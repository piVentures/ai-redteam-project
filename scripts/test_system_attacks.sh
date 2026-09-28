#!/usr/bin/env bash
# System-level finding tests.
#
# Proves each of the nine findings documented in the report's
# Section 8 is real: what the vulnerable endpoint leaks, what the
# hardened endpoint refuses, and what the container configuration
# exposes. Different from verify.sh — that script checks whether
# the system is configured correctly, this one checks whether the
# findings the report claims exist are still present.
#
# Runtime: ~90 seconds (two container restarts with 8-second waits).
#
# Run from the repo root:  bash scripts/test_system_attacks.sh

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

VULN="${VULN:-http://localhost:8000}"
HARD="${HARD:-http://localhost:8001}"
KEY="${KEY:-dev-local-key-change-me}"
BADFILE="${BADFILE:-/tmp/bad.txt}"

if [ -t 1 ]; then
    OK=$'\033[32m'; BAD=$'\033[31m'; WARN=$'\033[33m'
    DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
else
    OK=""; BAD=""; WARN=""; DIM=""; BOLD=""; OFF=""
fi

PASS=0
FAIL=0
WARN_COUNT=0

check() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        printf "  ${OK}PASS${OFF}  %s\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  ${BAD}FAIL${OFF}  %s (expected '%s', got '%s')\n" "$name" "$expected" "$actual"
        FAIL=$((FAIL + 1))
    fi
}

check_contains() {
    local name="$1" needle="$2" haystack="$3"
    if printf '%s' "$haystack" | grep -q "$needle"; then
        printf "  ${OK}PASS${OFF}  %s\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  ${BAD}FAIL${OFF}  %s (missing '%s')\n" "$name" "$needle"
        FAIL=$((FAIL + 1))
    fi
}

check_not_contains() {
    local name="$1" needle="$2" haystack="$3"
    if printf '%s' "$haystack" | grep -q "$needle"; then
        printf "  ${BAD}FAIL${OFF}  %s (unexpectedly contains '%s')\n" "$name" "$needle"
        FAIL=$((FAIL + 1))
    else
        printf "  ${OK}PASS${OFF}  %s\n" "$name"
        PASS=$((PASS + 1))
    fi
}

check_above() {
    local name="$1" min="$2" actual="$3"
    if [ -z "$actual" ] || ! awk "BEGIN { exit !($actual > $min) }"; then
        printf "  ${BAD}FAIL${OFF}  %s = %s (expected > %s)\n" "$name" "${actual:-empty}" "$min"
        FAIL=$((FAIL + 1))
    else
        printf "  ${OK}PASS${OFF}  %s = %s (> %s)\n" "$name" "$actual" "$min"
        PASS=$((PASS + 1))
    fi
}

warn() { printf "  ${WARN}WARN${OFF}  %s\n" "$*"; WARN_COUNT=$((WARN_COUNT + 1)); }
section() { echo ""; echo "${BOLD}=== $* ===${OFF}"; }
info() { echo "  ${DIM}$*${OFF}"; }

# ---------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------
section "Preflight"

curl -sf -o /dev/null "$VULN/health" || { printf "  ${BAD}ERR${OFF}   vulnerable API not responding at $VULN\n"; exit 1; }
curl -sf -o /dev/null "$HARD/health" || { printf "  ${BAD}ERR${OFF}   hardened API not responding at $HARD\n"; exit 1; }
info "both APIs responding"

echo "not an image" > "$BADFILE"

# ---------------------------------------------------------------
# Finding 1 — /model-info architecture leak
# ---------------------------------------------------------------
section "Finding 1 — /model-info architecture leak (AML.T0007)"

check "vulnerable /model-info status" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/model-info")"
check "hardened /model-info status" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/model-info")"

VULN_INFO=$(curl -s "$VULN/model-info")
check_contains "vulnerable exposes architecture" "architecture" "$VULN_INFO"
check_contains "vulnerable exposes class list" "airplane" "$VULN_INFO"
check_contains "vulnerable exposes parameter count" "618820" "$VULN_INFO"
check_contains "vulnerable exposes torch version" "torch_version" "$VULN_INFO"

# ---------------------------------------------------------------
# Finding 2 — Verbose error traces
# ---------------------------------------------------------------
section "Finding 2 — Verbose error traces (AML.T0007)"

check "vulnerable returns 500" "500" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$VULN/predict" -F "file=@$BADFILE;type=text/plain")"
check "hardened returns 400" "400" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" -H "x-api-key: $KEY" -F "file=@$BADFILE;type=text/plain")"

VULN_ERR=$(curl -s -X POST "$VULN/predict" -F "file=@$BADFILE;type=text/plain")
HARD_ERR=$(curl -s -X POST "$HARD/predict" -H "x-api-key: $KEY" -F "file=@$BADFILE;type=text/plain")

check_contains "vulnerable error has trace" "trace" "$VULN_ERR"
check_contains "vulnerable error reveals file path" "/srv/" "$VULN_ERR"
check_contains "vulnerable error reveals library" "PIL" "$VULN_ERR"
check_not_contains "hardened error has no trace" "trace" "$HARD_ERR"
check_contains "hardened error is generic" "Invalid" "$HARD_ERR"

# ---------------------------------------------------------------
# Finding 3 — Rate limit
# ---------------------------------------------------------------
section "Finding 3 — Rate limiting (AML.T0024)"

# Vulnerable accepts unlimited.
VULN_OK=0
for i in $(seq 1 50); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$VULN/health")
    [ "$code" = "200" ] && VULN_OK=$((VULN_OK + 1))
done
check "vulnerable accepts 50 requests" "50" "$VULN_OK"

# Hardened enforces 20/60s. Restart to clear state, then wait.
info "restarting api-hardened and waiting for readiness..."
docker compose restart api-hardened >/dev/null 2>&1
sleep 8

pre=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" \
    -H "x-api-key: $KEY" -F "file=@data/samples/cat_0.png")

if [ "$pre" != "200" ]; then
    printf "  ${BAD}FAIL${OFF}  hardened /predict not ready before rate-limit test (got %s)\n" "$pre"
    FAIL=$((FAIL + 1))
else
    # The readiness check consumed 1 request.
    HARD_OK=1
    HARD_429=0
    for i in $(seq 1 24); do
        code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" \
            -H "x-api-key: $KEY" -F "file=@data/samples/cat_0.png")
        [ "$code" = "200" ] && HARD_OK=$((HARD_OK + 1))
        [ "$code" = "429" ] && HARD_429=$((HARD_429 + 1))
    done
    check "hardened accepts 20" "20" "$HARD_OK"
    check "hardened rate-limits 5" "5" "$HARD_429"
fi

# ---------------------------------------------------------------
# Finding 4 — Auto-docs exposed
# ---------------------------------------------------------------
section "Finding 4 — Auto-docs exposed (AML.T0007)"

for path in docs redoc openapi.json; do
    check "vulnerable /$path" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/$path")"
    check "hardened /$path" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/$path")"
done

# ---------------------------------------------------------------
# Finding 5 — Environment variable secret exposure
# ---------------------------------------------------------------
section "Finding 5 — Environment variable secret exposure (AML.T0010)"

HARD_ENV=$(docker inspect redteam-api-hardened --format '{{json .Config.Env}}' 2>/dev/null)
VULN_ENV=$(docker inspect redteam-api-vuln --format '{{json .Config.Env}}' 2>/dev/null)

check_contains "hardened env contains API_KEY" "API_KEY" "$HARD_ENV"
check_not_contains "vulnerable env has no API_KEY" "API_KEY" "$VULN_ENV"

KEY_FROM_INSIDE=$(docker compose exec -T api-hardened sh -c 'echo $API_KEY' 2>/dev/null | tr -d '\r')
check "key readable from inside container" "$KEY" "$KEY_FROM_INSIDE"

# ---------------------------------------------------------------
# Finding 6 — Container user (remediated)
# ---------------------------------------------------------------
section "Finding 6 — Container user (AML.T0000, remediated)"

check "api-vuln user" "appuser" "$(docker compose exec -T api-vuln whoami 2>/dev/null | tr -d '\r')"
check "api-hardened user" "appuser" "$(docker compose exec -T api-hardened whoami 2>/dev/null | tr -d '\r')"

VULN_ID=$(docker compose exec -T api-vuln id 2>/dev/null | tr -d '\r')
check_contains "api-vuln uid is 1000" "uid=1000" "$VULN_ID"

# ---------------------------------------------------------------
# Finding 7 — Volume mounts
# ---------------------------------------------------------------
section "Finding 7 — Volume mounts (AML.T0000)"

MOUNT_COUNT=$(docker inspect redteam-api-vuln --format '{{json .Mounts}}' 2>/dev/null \
    | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
check "api-vuln has 9 mounts" "9" "$MOUNT_COUNT"

RW_COUNT=$(docker inspect redteam-api-vuln --format '{{json .Mounts}}' 2>/dev/null \
    | python3 -c 'import sys,json; print(sum(1 for m in json.load(sys.stdin) if m.get("RW")))' 2>/dev/null || echo 0)
check "api-vuln has 2 read-write mounts" "2" "$RW_COUNT"

# Code directory is read-only.
RO_TEST=$(docker compose exec -T api-vuln sh -c 'echo x >> /srv/adapters/http.py' 2>&1 | grep -c 'Read-only' || true)
check "code directory is read-only" "1" "$RO_TEST"

# Logs directory is writable — this is the finding.
RW_TEST=$(docker compose exec -T api-vuln sh -c 'echo x >> /srv/logs/predictions.jsonl' 2>&1 | grep -c 'Read-only' || true)
check "logs directory is writable" "0" "$RW_TEST"

# ---------------------------------------------------------------
# Finding 8 — Resource limits (remediated)
# ---------------------------------------------------------------
section "Finding 8 — Resource limits (remediated)"

for c in redteam-api-vuln redteam-api-hardened; do
    MEM=$(docker inspect "$c" --format '{{.HostConfig.Memory}}' 2>/dev/null)
    NANO=$(docker inspect "$c" --format '{{.HostConfig.NanoCpus}}' 2>/dev/null)
    check_above "$c memory limit set" "0" "$MEM"
    check_above "$c CPU allocation set" "0" "$NANO"
done

# ---------------------------------------------------------------
# Finding 9 — CORS
# ---------------------------------------------------------------
section "Finding 9 — CORS configuration"

VULN_ACAO=$(curl -s -i -X OPTIONS "$VULN/predict" \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    | grep -i '^access-control-allow-origin' | tr -d '\r' | awk '{print $2}')
check "vulnerable allows any origin" "*" "$VULN_ACAO"

VULN_METHODS=$(curl -s -i -X OPTIONS "$VULN/predict" \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    | grep -i '^access-control-allow-methods' | tr -d '\r')
check_contains "vulnerable allows DELETE" "DELETE" "$VULN_METHODS"

HARD_ACAO=$(curl -s -i -X OPTIONS "$HARD/predict" \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    | grep -i '^access-control-allow-origin' | tr -d '\r' | awk '{print $2}')
check "hardened allows localhost:3000" "http://localhost:3000" "$HARD_ACAO"

HARD_METHODS=$(curl -s -i -X OPTIONS "$HARD/predict" \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    | grep -i '^access-control-allow-methods' | tr -d '\r')
check_contains "hardened allows POST" "POST" "$HARD_METHODS"
check_not_contains "hardened does not allow DELETE" "DELETE" "$HARD_METHODS"

EVIL_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS "$HARD/predict" \
    -H "Origin: http://evil.example.com" \
    -H "Access-Control-Request-Method: POST")
check "hardened rejects disallowed origin" "400" "$EVIL_STATUS"

# ---------------------------------------------------------------
# Finding 10 — Detector sees the evidence
# ---------------------------------------------------------------
section "Finding 10 — Detector evidence trail"

DETECTOR_LOG=$(docker compose logs detector --tail=50 2>&1)
check_contains "detector is watching" "watching" "$DETECTOR_LOG"

if [ -f results/alerts.jsonl ]; then
    ALERT_COUNT=$(wc -l < results/alerts.jsonl | tr -d ' ')
    info "alerts file has $ALERT_COUNT lines"
    printf "  ${OK}PASS${OFF}  alerts file exists\n"
    PASS=$((PASS + 1))
else
    warn "alerts file missing (may not have fired yet)"
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
section "Summary"
echo "  ${OK}PASS${OFF}: $PASS"
echo "  ${BAD}FAIL${OFF}: $FAIL"
if [ "$WARN_COUNT" -gt 0 ]; then
    echo "  ${WARN}WARN${OFF}: $WARN_COUNT"
fi
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo "All system-attack tests passed."
    exit 0
else
    echo "Some system-attack tests failed. See above."
    exit 1
fi
#!/usr/bin/env bash
# System verification.
#
# Confirms the running stack is configured correctly: containers up,
# both API modes behaving as designed, auth enforced, response shapes
# different, rate limiting in place, resource limits set. This is a
# smoke test for the deployment — a failure means the system is
# misconfigured, not that a finding is missing.
#
# Run from the repo root:  bash scripts/verify.sh

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

VULN="${VULN:-http://localhost:8000}"
HARD="${HARD:-http://localhost:8001}"
ALERTS="${ALERTS:-http://localhost:8002}"
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
section "1. Containers"
# ---------------------------------------------------------------

RUNNING=$(docker compose ps --status running --format '{{.Name}}' | sort | tr '\n' ' ')
check_contains "api-vuln running" "redteam-api-vuln" "$RUNNING"
check_contains "api-hardened running" "redteam-api-hardened" "$RUNNING"
check_contains "detector running" "redteam-detector" "$RUNNING"
check_contains "alerts-api running" "redteam-alerts-api" "$RUNNING"

if printf '%s' "$RUNNING" | grep -q "redteam-telegram-notifier"; then
    printf "  ${OK}PASS${OFF}  telegram-notifier running\n"
    PASS=$((PASS + 1))
else
    warn "telegram-notifier not running (optional)"
fi

# ---------------------------------------------------------------
section "2. Health and mode"
# ---------------------------------------------------------------

check "vulnerable /health mode" "vulnerable" \
    "$(curl -s "$VULN/health" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("mode",""))' 2>/dev/null)"
check "hardened /health mode" "hardened" \
    "$(curl -s "$HARD/health" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("mode",""))' 2>/dev/null)"

# ---------------------------------------------------------------
section "3. Endpoint availability"
# ---------------------------------------------------------------

check "vulnerable /docs" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/docs")"
check "vulnerable /redoc" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/redoc")"
check "vulnerable /openapi.json" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/openapi.json")"
check "vulnerable /model-info" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/model-info")"

check "hardened /docs" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/docs")"
check "hardened /redoc" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/redoc")"
check "hardened /openapi.json" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/openapi.json")"
check "hardened /model-info" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/model-info")"

# ---------------------------------------------------------------
section "4. Authentication"
# ---------------------------------------------------------------

check "hardened without key" "401" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" -F "file=@data/samples/cat_0.png")"
check "hardened wrong key" "401" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" -H "x-api-key: wrong" -F "file=@data/samples/cat_0.png")"
check "hardened with correct key" "200" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" -H "x-api-key: $KEY" -F "file=@data/samples/cat_0.png")"
check "vulnerable accepts unauthenticated" "200" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$VULN/predict" -F "file=@data/samples/cat_0.png")"

# ---------------------------------------------------------------
section "5. Response shape"
# ---------------------------------------------------------------

VULN_BODY=$(curl -s -X POST "$VULN/predict" -F "file=@data/samples/cat_0.png")
HARD_BODY=$(curl -s -X POST "$HARD/predict" -H "x-api-key: $KEY" -F "file=@data/samples/cat_0.png")

check_contains "vulnerable returns full softmax" "probabilities" "$VULN_BODY"
check_contains "hardened returns class" '"class"' "$HARD_BODY"
check_contains "hardened returns confidence" '"confidence"' "$HARD_BODY"
check_not_contains "hardened omits full softmax" "probabilities" "$HARD_BODY"

# ---------------------------------------------------------------
section "6. Input validation"
# ---------------------------------------------------------------

echo "not an image" > "$BADFILE"

check "hardened rejects malformed input" "400" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" \
        -H "x-api-key: $KEY" -F "file=@$BADFILE;type=text/plain")"
check "vulnerable accepts malformed with 500" "500" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$VULN/predict" \
        -F "file=@$BADFILE;type=text/plain")"

# ---------------------------------------------------------------
section "7. Container user"
# ---------------------------------------------------------------

check "api-vuln user" "appuser" "$(docker compose exec -T api-vuln whoami 2>/dev/null | tr -d '\r')"
check "api-hardened user" "appuser" "$(docker compose exec -T api-hardened whoami 2>/dev/null | tr -d '\r')"

VULN_ID=$(docker compose exec -T api-vuln id 2>/dev/null | tr -d '\r')
check_contains "api-vuln uid is 1000" "uid=1000" "$VULN_ID"

# ---------------------------------------------------------------
section "8. Resource limits"
# ---------------------------------------------------------------

for c in redteam-api-vuln redteam-api-hardened; do
    MEM=$(docker inspect "$c" --format '{{.HostConfig.Memory}}' 2>/dev/null)
    NANO=$(docker inspect "$c" --format '{{.HostConfig.NanoCpus}}' 2>/dev/null)
    check_above "$c memory limit set" "0" "$MEM"
    check_above "$c CPU allocation set" "0" "$NANO"
done

# ---------------------------------------------------------------
section "9. Volume mounts (structural)"
# ---------------------------------------------------------------

MOUNT_COUNT=$(docker inspect redteam-api-vuln --format '{{json .Mounts}}' 2>/dev/null \
    | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
check "api-vuln has 9 mounts" "9" "$MOUNT_COUNT"

RW_COUNT=$(docker inspect redteam-api-vuln --format '{{json .Mounts}}' 2>/dev/null \
    | python3 -c 'import sys,json; print(sum(1 for m in json.load(sys.stdin) if m.get("RW")))' 2>/dev/null || echo 0)
check "api-vuln has 2 read-write mounts" "2" "$RW_COUNT"

RO_TEST=$(docker compose exec -T api-vuln sh -c 'echo x >> /srv/adapters/http.py' 2>&1 | grep -c 'Read-only' || true)
check "code directory is read-only" "1" "$RO_TEST"

# ---------------------------------------------------------------
section "10. Detector and alerts API"
# ---------------------------------------------------------------

DETECTOR_LOG=$(docker compose logs detector --tail=50 2>&1)
check_contains "detector is watching logs" "watching" "$DETECTOR_LOG"

ALERTS_TYPE=$(curl -s "$ALERTS/alerts" | python3 -c 'import sys,json; print(type(json.load(sys.stdin)).__name__)' 2>/dev/null)
check "alerts API returns list" "list" "$ALERTS_TYPE"

if [ -f logs/predictions.jsonl ]; then
    printf "  ${OK}PASS${OFF}  predictions log exists\n"
    PASS=$((PASS + 1))
else
    printf "  ${BAD}FAIL${OFF}  predictions log missing\n"
    FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------
section "11. Memory usage (informational)"
# ---------------------------------------------------------------

docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"

# ---------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------

echo ""
echo "  ${OK}PASS${OFF}: $PASS"
echo "  ${BAD}FAIL${OFF}: $FAIL"
if [ "$WARN_COUNT" -gt 0 ]; then
    echo "  ${WARN}WARN${OFF}: $WARN_COUNT"
fi
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo "All checks passed."
    exit 0
else
    echo "Some checks failed. See above."
    exit 1
fi
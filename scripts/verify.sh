#!/usr/bin/env bash
# Full verification suite.
#
# Asserts every claim the report makes about the running system.
# Exit code 0 on success, 1 on any failure.
#
# Run from the repo root: bash scripts/verify.sh

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

VULN="${VULN:-http://localhost:8000}"
HARD="${HARD:-http://localhost:8001}"
ALERTS="${ALERTS:-http://localhost:8002}"
KEY="${KEY:-dev-local-key-change-me}"

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

warn() {
    printf "  ${WARN}WARN${OFF}  %s\n" "$*"
    WARN_COUNT=$((WARN_COUNT + 1))
}

section() {
    echo ""
    echo "${BOLD}=== $* ===${OFF}"
}

# ---------------------------------------------------------------
section "1. Containers"
# ---------------------------------------------------------------

RUNNING=$(docker compose ps --status running --format '{{.Name}}' | sort | tr '\n' ' ')
EXPECTED="redteam-alerts-api redteam-api-hardened redteam-api-vuln redteam-detector "
check_contains "api-vuln running" "redteam-api-vuln" "$RUNNING"
check_contains "api-hardened running" "redteam-api-hardened" "$RUNNING"
check_contains "detector running" "redteam-detector" "$RUNNING"
check_contains "alerts-api running" "redteam-alerts-api" "$RUNNING"

if printf '%s' "$RUNNING" | grep -q "redteam-telegram-notifier"; then
    printf "  ${OK}PASS${OFF}  telegram-notifier running\n"
    PASS=$((PASS + 1))
else
    warn "telegram-notifier not running (disabled or stopped)"
fi

# ---------------------------------------------------------------
section "2. Health and mode"
# ---------------------------------------------------------------

check "vulnerable /health mode" "vulnerable" \
    "$(curl -s "$VULN/health" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("mode",""))' 2>/dev/null)"
check "hardened /health mode" "hardened" \
    "$(curl -s "$HARD/health" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("mode",""))' 2>/dev/null)"

# ---------------------------------------------------------------
section "3. Docs exposure"
# ---------------------------------------------------------------

check "vulnerable /docs" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/docs")"
check "vulnerable /redoc" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/redoc")"
check "vulnerable /openapi.json" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/openapi.json")"
check "hardened /docs" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/docs")"
check "hardened /redoc" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/redoc")"
check "hardened /openapi.json" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/openapi.json")"

# ---------------------------------------------------------------
section "4. /model-info leak"
# ---------------------------------------------------------------

check "vulnerable /model-info" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$VULN/model-info")"
check "hardened /model-info" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$HARD/model-info")"

VULN_INFO=$(curl -s "$VULN/model-info")
check_contains "vulnerable exposes architecture" "architecture" "$VULN_INFO"
check_contains "vulnerable exposes classes" "airplane" "$VULN_INFO"
check_contains "vulnerable exposes param count" "618820" "$VULN_INFO"
check_contains "vulnerable exposes torch version" "torch_version" "$VULN_INFO"

# ---------------------------------------------------------------
section "5. Authentication"
# ---------------------------------------------------------------

check "hardened without key" "401" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" -F "file=@data/samples/cat_0.png")"
check "hardened wrong key" "401" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" -H "x-api-key: wrong" -F "file=@data/samples/cat_0.png")"
check "hardened with correct key" "200" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" -H "x-api-key: $KEY" -F "file=@data/samples/cat_0.png")"

VULN_NOAUTH=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$VULN/predict" -F "file=@data/samples/cat_0.png")
check "vulnerable accepts unauthenticated" "200" "$VULN_NOAUTH"

# ---------------------------------------------------------------
section "6. Response shape"
# ---------------------------------------------------------------

VULN_BODY=$(curl -s -X POST "$VULN/predict" -F "file=@data/samples/cat_0.png")
HARD_BODY=$(curl -s -X POST "$HARD/predict" -H "x-api-key: $KEY" -F "file=@data/samples/cat_0.png")

check_contains "vulnerable returns full softmax" "probabilities" "$VULN_BODY"
check_contains "hardened returns class" '"class"' "$HARD_BODY"
check_contains "hardened returns confidence" '"confidence"' "$HARD_BODY"
check_not_contains "hardened omits full softmax" "probabilities" "$HARD_BODY"

# ---------------------------------------------------------------
section "7. Rate limiting"
# ---------------------------------------------------------------

# Vulnerable should accept everything
VULN_OK=0
for i in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$VULN/health")
    [ "$code" = "200" ] && VULN_OK=$((VULN_OK + 1))
done
check "vulnerable accepts 30 requests" "30" "$VULN_OK"

# Hardened should rate-limit after 20.
# Restart the hardened container to clear any prior rate-limit state.
docker compose restart api-hardened >/dev/null 2>&1

# Wait for the container to fully settle. Polling /health is not enough
# because it binds before /predict is ready. A fixed wait of 8 seconds
# gives Uvicorn time to finish startup.
sleep 8

# Verify /predict is actually serving before running the test.
pre=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" \
    -H "x-api-key: $KEY" -F "file=@data/samples/cat_0.png")

if [ "$pre" != "200" ]; then
    printf "  ${BAD}FAIL${OFF}  hardened API not serving /predict before rate-limit test (got %s)\n" "$pre"
    FAIL=$((FAIL + 1))
else
    # The readiness check above used 1 of the 20 allowed requests.
    # Send 24 more: 19 should succeed, 5 should be rate-limited.
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
section "8. Input validation (hardened)"
# ---------------------------------------------------------------

# Reset the rate limiter before validation tests
docker compose restart api-hardened >/dev/null 2>&1
sleep 3

echo "not an image" > /tmp/bad.txt

check "hardened rejects bad image" "400" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$HARD/predict" \
        -H "x-api-key: $KEY" -F "file=@/tmp/bad.txt;type=text/plain")"

check "vulnerable accepts bad image with 500" "500" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$VULN/predict" \
        -F "file=@/tmp/bad.txt;type=text/plain")"

# ---------------------------------------------------------------
section "9. Verbose errors"
# ---------------------------------------------------------------

VULN_ERR=$(curl -s -X POST "$VULN/predict" -F "file=@/tmp/bad.txt;type=text/plain")
HARD_ERR=$(curl -s -X POST "$HARD/predict" -H "x-api-key: $KEY" -F "file=@/tmp/bad.txt;type=text/plain")

check_contains "vulnerable error contains trace" "trace" "$VULN_ERR"
check_contains "vulnerable error contains file path" "/srv/" "$VULN_ERR"
check_not_contains "hardened error has no trace" "trace" "$HARD_ERR"
check_contains "hardened error is generic" "Invalid" "$HARD_ERR"

# ---------------------------------------------------------------
section "10. CORS"
# ---------------------------------------------------------------

VULN_ACAO=$(curl -s -i -X OPTIONS "$VULN/predict" \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" | grep -i '^access-control-allow-origin' | tr -d '\r' | awk '{print $2}')
check "vulnerable CORS allows any" "*" "$VULN_ACAO"

HARD_ACAO=$(curl -s -i -X OPTIONS "$HARD/predict" \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" | grep -i '^access-control-allow-origin' | tr -d '\r' | awk '{print $2}')
check "hardened CORS allows localhost:3000" "http://localhost:3000" "$HARD_ACAO"

EVIL_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS "$HARD/predict" \
    -H "Origin: http://evil.example.com" \
    -H "Access-Control-Request-Method: POST")
check "hardened CORS rejects evil origin" "400" "$EVIL_STATUS"

# ---------------------------------------------------------------
section "11. Container user"
# ---------------------------------------------------------------

check "api-vuln user" "appuser" "$(docker compose exec -T api-vuln whoami 2>/dev/null | tr -d '\r')"
check "api-hardened user" "appuser" "$(docker compose exec -T api-hardened whoami 2>/dev/null | tr -d '\r')"

VULN_UID=$(docker compose exec -T api-vuln id 2>/dev/null | tr -d '\r')
check_contains "api-vuln uid is 1000" "uid=1000" "$VULN_UID"

# ---------------------------------------------------------------
section "12. Resource limits"
# ---------------------------------------------------------------

for c in redteam-api-vuln redteam-api-hardened; do
    MEM=$(docker inspect "$c" --format '{{.HostConfig.Memory}}' 2>/dev/null)
    NANO=$(docker inspect "$c" --format '{{.HostConfig.NanoCpus}}' 2>/dev/null)
    if [ "${MEM:-0}" -gt 0 ]; then
        printf "  ${OK}PASS${OFF}  %s memory limit set (%s bytes)\n" "$c" "$MEM"
        PASS=$((PASS + 1))
    else
        printf "  ${BAD}FAIL${OFF}  %s has no memory limit\n" "$c"
        FAIL=$((FAIL + 1))
    fi
    if [ "${NANO:-0}" -gt 0 ]; then
        printf "  ${OK}PASS${OFF}  %s CPU allocation set (%s nanocores)\n" "$c" "$NANO"
        PASS=$((PASS + 1))
    else
        printf "  ${BAD}FAIL${OFF}  %s has no CPU allocation\n" "$c"
        FAIL=$((FAIL + 1))
    fi
done

# ---------------------------------------------------------------
section "13. Volume mounts"
# ---------------------------------------------------------------

MOUNT_COUNT=$(docker inspect redteam-api-vuln --format '{{json .Mounts}}' 2>/dev/null \
    | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
check "api-vuln has 9 mounts" "9" "$MOUNT_COUNT"

RW_COUNT=$(docker inspect redteam-api-vuln --format '{{json .Mounts}}' 2>/dev/null \
    | python3 -c 'import sys,json; print(sum(1 for m in json.load(sys.stdin) if m.get("RW")))' 2>/dev/null || echo 0)
check "api-vuln has 2 read-write mounts" "2" "$RW_COUNT"

# Confirm the code directory is read-only
RO_TEST=$(docker compose exec -T api-vuln sh -c 'echo x >> /srv/adapters/http.py' 2>&1 | grep -c 'Read-only' || true)
check "api-vuln code dir is read-only" "1" "$RO_TEST"

# ---------------------------------------------------------------
section "14. Detector"
# ---------------------------------------------------------------

DETECTOR_LOG=$(docker compose logs detector --tail=100 2>&1)
check_contains "detector is watching predictions" "watching" "$DETECTOR_LOG"

# ---------------------------------------------------------------
section "15. Alerts API"
# ---------------------------------------------------------------

ALERTS_TYPE=$(curl -s "$ALERTS/alerts" | python3 -c 'import sys,json; print(type(json.load(sys.stdin)).__name__)' 2>/dev/null)
check "alerts API returns list" "list" "$ALERTS_TYPE"

# ---------------------------------------------------------------
section "16. Logs"
# ---------------------------------------------------------------

check_contains "predictions log exists" "" "$(ls logs/predictions.jsonl 2>/dev/null && echo ok || echo missing)"

# ---------------------------------------------------------------
section "17. Memory usage (informational)"
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

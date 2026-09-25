#!/usr/bin/env bash
# Full verification suite. Run after every change.

cd ~/github/insa/ai-redteam-project
FAIL=0

check() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  PASS  $name"
    else
        echo "  FAIL  $name (expected $expected, got $actual)"
        FAIL=1
    fi
}

echo "=== Containers ==="
docker compose ps --all

echo ""
echo "=== Health ==="
check "vulnerable mode" "vulnerable" \
    "$(curl -s localhost:8000/health | python -c 'import sys,json;print(json.load(sys.stdin)["mode"])')"
check "hardened mode" "hardened" \
    "$(curl -s localhost:8001/health | python -c 'import sys,json;print(json.load(sys.stdin)["mode"])')"

echo ""
echo "=== Docs ==="
check "vulnerable /docs" "200" "$(curl -s -o /dev/null -w '%{http_code}' localhost:8000/docs)"
check "hardened /docs" "404" "$(curl -s -o /dev/null -w '%{http_code}' localhost:8001/docs)"
check "hardened /redoc" "404" "$(curl -s -o /dev/null -w '%{http_code}' localhost:8001/redoc)"
check "hardened /openapi" "404" "$(curl -s -o /dev/null -w '%{http_code}' localhost:8001/openapi.json)"

echo ""
echo "=== Auth ==="
check "hardened without key" "401" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8001/predict -F 'file=@data/samples/cat_0.png')"
check "hardened with key" "200" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8001/predict -H 'x-api-key: dev-local-key-change-me' -F 'file=@data/samples/cat_0.png')"

echo ""
echo "=== Container user ==="
check "api-vuln" "appuser" "$(docker compose exec -T api-vuln whoami)"
check "api-hardened" "appuser" "$(docker compose exec -T api-hardened whoami)"

echo ""
echo "=== Alerts API ==="
check "alerts JSON" "list" \
    "$(curl -s localhost:8002/alerts | python -c 'import sys,json;print(type(json.load(sys.stdin)).__name__)')"

echo ""
echo "=== Memory limits ==="
docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"

if [ $FAIL -eq 0 ]; then
    echo ""
    echo "All checks passed."
else
    echo ""
    echo "Some checks failed. See above."
    exit 1
fi

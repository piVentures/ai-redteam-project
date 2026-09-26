#!/usr/bin/env bash
# Run an attack and deliver the Telegram notification.
#
# Nothing persists in the repo after the run:
#   - attack artifacts go to /tmp/redteam-scratch
#   - results/alerts.jsonl is truncated after delivery
#   - logs/predictions.jsonl is truncated and the detector is restarted
#
# Usage:
#   bash scripts/notify_only.sh evasion
#   bash scripts/notify_only.sh extraction
#   bash scripts/notify_only.sh mia
#
# The notifier is not modified and remains a read-only relay.

set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

WHICH="${1:-extraction}"
SCRATCH="/tmp/redteam-scratch"
WAIT=45
ALERTS="results/alerts.jsonl"
PREDICTIONS="logs/predictions.jsonl"

if [ -t 1 ]; then
    OK=$'\033[32m'; BAD=$'\033[31m'; DIM=$'\033[2m'
    BOLD=$'\033[1m'; OFF=$'\033[0m'
else
    OK=""; BAD=""; DIM=""; BOLD=""; OFF=""
fi

say()  { echo "${DIM}  $*${OFF}"; }
pass() { echo "${OK}  OK${OFF}    $*"; }
fail() { echo "${BAD}  ERR${OFF}   $*"; }
title(){ echo; echo "${BOLD}== $* ==${OFF}"; }

# ---------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------
title "Preflight"

if ! docker compose ps --status running --format '{{.Name}}' | grep -q telegram-notifier; then
    fail "telegram-notifier container is not running"
    echo "       start with: docker compose up -d telegram-notifier"
    exit 1
fi
say "notifier up"

if ! docker compose ps --status running --format '{{.Name}}' | grep -q redteam-detector; then
    fail "detector container is not running"
    exit 1
fi
say "detector up"

if ! curl -sf -o /dev/null http://localhost:8000/health; then
    fail "vulnerable API not responding on :8000"
    exit 1
fi
say "vulnerable API up"

if [ -d venv ] && [ -f venv/bin/activate ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
    say "venv active"
else
    fail "venv missing"
    exit 1
fi

mkdir -p "$SCRATCH"

# ---------------------------------------------------------------
# Reset so the run is clean
# ---------------------------------------------------------------
title "Reset"

: > "$ALERTS"
: > "$PREDICTIONS"
docker compose restart detector telegram-notifier >/dev/null 2>&1
sleep 3
say "alerts + predictions truncated, detector and notifier restarted"

# ---------------------------------------------------------------
# Run the attack
# ---------------------------------------------------------------
title "Attack: $WHICH"

case "$WHICH" in
    evasion)
        say "running evasion (FGSM + PGD) ..."
        python -m attacks.evasion_fgsm_pgd \
            --target http://localhost:8000 \
            --output-dir "$SCRATCH/evasion" >/dev/null 2>&1 || true
        ;;
    extraction)
        say "running model extraction (200 queries) ..."
        python -m attacks.extraction \
            --target http://localhost:8000 \
            --queries 200 \
            --output-dir "$SCRATCH/extraction" >/dev/null 2>&1 || true
        ;;
    mia)
        say "running membership inference (100/class) ..."
        python -m attacks.membership_inference \
            --target http://localhost:8000 \
            --samples-per-class 100 \
            --output-dir "$SCRATCH/mia" >/dev/null 2>&1 || true
        ;;
    *)
        fail "unknown attack: $WHICH"
        echo "       usage: $0 [evasion|extraction|mia]"
        exit 1
        ;;
esac

# ---------------------------------------------------------------
# Wait for the notifier to flush
# ---------------------------------------------------------------
title "Delivery"

alerts=$(wc -l < "$ALERTS" | tr -d ' ')
say "alerts written: ${alerts}"

if [ "$alerts" -eq 0 ]; then
    fail "attack produced no detector alerts"
    echo "       (this is expected for evasion with only 3 samples)"
    exit 2
fi

say "waiting up to ${WAIT}s for Telegram batch ..."
deadline=$(( $(date +%s) + WAIT ))
delivered=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    if docker compose logs --since "${WAIT}s" telegram-notifier 2>&1 \
        | grep -q '\[notifier\] sent batch'; then
        delivered=1
        break
    fi
    sleep 3
done

if [ "$delivered" -eq 1 ]; then
    line=$(docker compose logs --since "${WAIT}s" telegram-notifier 2>&1 \
        | grep '\[notifier\] sent batch' | tail -1)
    pass "Telegram notified"
    echo "       ${line#*| }"
else
    fail "no Telegram batch within ${WAIT}s"
    docker compose logs --tail=5 telegram-notifier 2>&1 | sed 's/^/       /'
    # fall through to cleanup anyway
fi

# ---------------------------------------------------------------
# Cleanup so nothing persists in the repo
# ---------------------------------------------------------------
title "Cleanup"

: > "$ALERTS"
: > "$PREDICTIONS"
docker compose restart detector >/dev/null 2>&1
say "alerts + predictions cleared, detector restarted"

if [ "$delivered" -eq 1 ]; then
    pass "done — repo state clean, notification delivered"
    exit 0
else
    fail "done — repo state clean, but delivery failed (see above)"
    exit 1
fi

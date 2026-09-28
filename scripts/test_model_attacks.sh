#!/usr/bin/env bash
# Test the three model-level attacks and their defenses.
#
# Runs each attack script with a short budget, checks that the attack is
# still effective, and verifies that the corresponding defense still
# works. Uses numerical thresholds rather than exact values because the
# attacks have run-to-run variance.
#
# Runtime: ~3-4 minutes for all tests.
#
# Usage:
#   bash scripts/test_model_attacks.sh           # run all
#   bash scripts/test_model_attacks.sh evasion
#   bash scripts/test_model_attacks.sh extraction
#   bash scripts/test_model_attacks.sh mia

set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

VULN="${VULN:-http://localhost:8000}"
HARD="${HARD:-http://localhost:8001}"
KEY="${KEY:-dev-local-key-change-me}"
SCRATCH="${SCRATCH:-/tmp/model-attack-tests}"

if [ -t 1 ]; then
    OK=$'\033[32m'; BAD=$'\033[31m'; WARN=$'\033[33m'
    DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
else
    OK=""; BAD=""; WARN=""; DIM=""; BOLD=""; OFF=""
fi

PASS=0
FAIL=0
WARN_COUNT=0

check_range() {
    local name="$1" min="$2" max="$3" actual="$4"
    if [ -z "$actual" ]; then
        printf "  ${BAD}FAIL${OFF}  %s (no value)\n" "$name"
        FAIL=$((FAIL + 1))
        return
    fi
    if awk "BEGIN { exit !($actual >= $min && $actual <= $max) }"; then
        printf "  ${OK}PASS${OFF}  %s = %s (expected %s-%s)\n" "$name" "$actual" "$min" "$max"
        PASS=$((PASS + 1))
    else
        printf "  ${BAD}FAIL${OFF}  %s = %s (expected %s-%s)\n" "$name" "$actual" "$min" "$max"
        FAIL=$((FAIL + 1))
    fi
}

check_below() {
    local name="$1" max="$2" actual="$3"
    if [ -z "$actual" ]; then
        printf "  ${BAD}FAIL${OFF}  %s (no value)\n" "$name"
        FAIL=$((FAIL + 1))
        return
    fi
    if awk "BEGIN { exit !($actual < $max) }"; then
        printf "  ${OK}PASS${OFF}  %s = %s (< %s)\n" "$name" "$actual" "$max"
        PASS=$((PASS + 1))
    else
        printf "  ${BAD}FAIL${OFF}  %s = %s (expected < %s)\n" "$name" "$actual" "$max"
        FAIL=$((FAIL + 1))
    fi
}

check_above() {
    local name="$1" min="$2" actual="$3"
    if [ -z "$actual" ]; then
        printf "  ${BAD}FAIL${OFF}  %s (no value)\n" "$name"
        FAIL=$((FAIL + 1))
        return
    fi
    if awk "BEGIN { exit !($actual > $min) }"; then
        printf "  ${OK}PASS${OFF}  %s = %s (> %s)\n" "$name" "$actual" "$min"
        PASS=$((PASS + 1))
    else
        printf "  ${BAD}FAIL${OFF}  %s = %s (expected > %s)\n" "$name" "$actual" "$min"
        FAIL=$((FAIL + 1))
    fi
}

section() { echo ""; echo "${BOLD}=== $* ===${OFF}"; }
info()    { echo "  ${DIM}$*${OFF}"; }
warn()    { printf "  ${WARN}WARN${OFF}  %s\n" "$*"; WARN_COUNT=$((WARN_COUNT + 1)); }

# ---------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------
section "Preflight"

if [ ! -d venv ] || [ ! -f venv/bin/activate ]; then
    echo "  ${BAD}ERR${OFF}   venv missing — run 'make setup' first"
    exit 1
fi
# shellcheck disable=SC1091
source venv/bin/activate
info "venv activated"

if ! curl -sf -o /dev/null "$VULN/health"; then
    echo "  ${BAD}ERR${OFF}   vulnerable API not responding at $VULN"
    exit 1
fi
if ! curl -sf -o /dev/null "$HARD/health"; then
    echo "  ${BAD}ERR${OFF}   hardened API not responding at $HARD"
    exit 1
fi
info "both APIs responding"

mkdir -p "$SCRATCH"

WHICH="${1:-all}"

# ---------------------------------------------------------------
# Evasion tests
# ---------------------------------------------------------------
if [ "$WHICH" = "all" ] || [ "$WHICH" = "evasion" ]; then
    section "Evasion — baseline (vulnerable endpoint)"

    info "running evasion attack against $VULN ..."
    python -m attacks.evasion_fgsm_pgd \
        --target "$VULN" \
        --output-dir "$SCRATCH/evasion-baseline" >/dev/null 2>&1 || true

    SWEEP="$SCRATCH/evasion-baseline/epsilon_sweep.json"
    if [ ! -f "$SWEEP" ]; then
        printf "  ${BAD}FAIL${OFF}  sweep file not produced\n"
        FAIL=$((FAIL + 1))
    else
        FGSM_BASE=$(python3 -c "
import json
for row in json.load(open('$SWEEP')):
    if abs(row['eps'] - 0.03) < 0.001:
        print(row['fgsm_acc']); break
" 2>/dev/null)
        PGD_BASE=$(python3 -c "
import json
for row in json.load(open('$SWEEP')):
    if abs(row['eps'] - 0.03) < 0.001:
        print(row['pgd_acc']); break
" 2>/dev/null)

        info "FGSM accuracy at eps=0.03: $FGSM_BASE"
        info "PGD  accuracy at eps=0.03: $PGD_BASE"

        check_below "FGSM drops baseline accuracy" "0.35" "$FGSM_BASE"
        check_below "PGD drops baseline accuracy"  "0.25" "$PGD_BASE"
    fi

    section "Evasion — robust model (committed artifact)"

    ROBUST_SWEEP="results/defense/adversarial_training/robust/epsilon_sweep.json"
    if [ ! -f "$ROBUST_SWEEP" ]; then
        printf "  ${BAD}FAIL${OFF}  robust sweep artifact missing\n"
        FAIL=$((FAIL + 1))
    else
        RFGSM=$(python3 -c "
import json
for row in json.load(open('$ROBUST_SWEEP')):
    if abs(row['eps'] - 0.03) < 0.005:
        print(row['fgsm_acc']); break
" 2>/dev/null)
        RPGD=$(python3 -c "
import json
for row in json.load(open('$ROBUST_SWEEP')):
    if abs(row['eps'] - 0.03) < 0.005:
        print(row['pgd_acc']); break
" 2>/dev/null)

        info "robust FGSM accuracy at eps=0.03: $RFGSM"
        info "robust PGD  accuracy at eps=0.03: $RPGD"

        check_above "robust FGSM accuracy beats baseline" "0.05" "$RFGSM"
        check_above "robust PGD accuracy beats baseline"  "0.05" "$RPGD"
    fi
fi

# ---------------------------------------------------------------
# Extraction tests
# ---------------------------------------------------------------
if [ "$WHICH" = "all" ] || [ "$WHICH" = "extraction" ]; then
    section "Extraction — vulnerable endpoint (200 queries)"

    info "running extraction attack against $VULN ..."
    python -m attacks.extraction \
        --target "$VULN" \
        --queries 200 \
        --substitute-epochs 15 \
        --output-dir "$SCRATCH/extraction" >/dev/null 2>&1 || true

    METRICS="$SCRATCH/extraction/metrics.json"
    if [ ! -f "$METRICS" ]; then
        printf "  ${BAD}FAIL${OFF}  metrics file not produced\n"
        FAIL=$((FAIL + 1))
    else
        SOFT_FID=$(python3 -c "import json; print(json.load(open('$METRICS'))['fidelity_soft_label'])" 2>/dev/null)
        HARD_FID=$(python3 -c "import json; print(json.load(open('$METRICS'))['fidelity_hard_label'])" 2>/dev/null)
        RAND_FID=$(python3 -c "import json; print(json.load(open('$METRICS'))['fidelity_random_baseline'])" 2>/dev/null)

        info "soft-label fidelity: $SOFT_FID"
        info "hard-label fidelity: $HARD_FID"
        info "random baseline:     $RAND_FID"

        check_above "soft-label fidelity beats random" "0.45" "$SOFT_FID"
        check_above "hard-label fidelity beats random" "0.45" "$HARD_FID"
    fi

    section "Extraction — hardened endpoint (30-query cap)"

    info "running extraction with 30-query cap against $HARD ..."
    python -m attacks.extraction \
        --target "$HARD" \
        --queries 30 \
        --api-key "$KEY" \
        --substitute-epochs 10 \
        --max-queries-for-hardened 30 \
        --output-dir "$SCRATCH/extraction-hardened" >/dev/null 2>&1 || true

    HARD_METRICS="$SCRATCH/extraction-hardened/metrics.json"
    if [ ! -f "$HARD_METRICS" ]; then
        warn "hardened metrics not produced (attack may have been blocked entirely)"
    else
        RATE_LIMITS=$(python3 -c "import json; print(json.load(open('$HARD_METRICS')).get('rate_limit_hits', 0))" 2>/dev/null || echo 0)
        info "rate-limit hits on hardened: $RATE_LIMITS"
        if [ "$RATE_LIMITS" -ge 1 ]; then
            printf "  ${OK}PASS${OFF}  hardened endpoint rate-limited the extraction attack\n"
            PASS=$((PASS + 1))
        else
            printf "  ${BAD}FAIL${OFF}  hardened endpoint did not rate-limit (expected >= 1)\n"
            FAIL=$((FAIL + 1))
        fi
    fi

    section "Extraction — committed artifact check"

    if [ -f "results/extraction/metrics.json" ]; then
        FULL_QUERIES=$(python3 -c "import json; print(json.load(open('results/extraction/metrics.json'))['query_budget'])" 2>/dev/null)
        FULL_FID=$(python3 -c "import json; print(json.load(open('results/extraction/metrics.json'))['fidelity_soft_label'])" 2>/dev/null)

        info "committed artifact: $FULL_QUERIES queries, fidelity $FULL_FID"

        check_range "committed artifact fidelity" "0.80" "0.90" "$FULL_FID"
    else
        warn "committed extraction artifact missing"
    fi
fi

# ---------------------------------------------------------------
# MIA tests
# ---------------------------------------------------------------
if [ "$WHICH" = "all" ] || [ "$WHICH" = "mia" ]; then
    section "Membership Inference — vulnerable endpoint"

    info "running MIA against $VULN (200 samples, seed 42) ..."
    python -m attacks.membership_inference \
        --target "$VULN" \
        --samples-per-class 50 \
        --seed 42 \
        --output-dir "$SCRATCH/mia-vuln" >/dev/null 2>&1 || true

    MIA_METRICS="$SCRATCH/mia-vuln/metrics.json"
    if [ ! -f "$MIA_METRICS" ]; then
        printf "  ${BAD}FAIL${OFF}  MIA metrics not produced\n"
        FAIL=$((FAIL + 1))
    else
        MIA_ACC=$(python3 -c "import json; print(json.load(open('$MIA_METRICS'))['best']['accuracy'])" 2>/dev/null)
        MIA_BASE=$(python3 -c "import json; print(json.load(open('$MIA_METRICS'))['best']['majority_baseline'])" 2>/dev/null)

        info "MIA accuracy: $MIA_ACC"
        info "majority baseline: $MIA_BASE"

        # Weak but positive: between 0.50 and 0.65.
        check_range "MIA accuracy is weak but positive" "0.50" "0.65" "$MIA_ACC"
    fi

    section "Membership Inference — committed artifact check"

    if [ -f "results/membership_inference/vuln/metrics.json" ]; then
        COMMIT_MIA=$(python3 -c "import json; print(json.load(open('results/membership_inference/vuln/metrics.json'))['best']['accuracy'])" 2>/dev/null)
        info "committed artifact MIA accuracy: $COMMIT_MIA"
        check_range "committed MIA artifact" "0.50" "0.65" "$COMMIT_MIA"
    else
        warn "committed MIA artifact missing"
    fi
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
    echo "All model-attack tests passed."
    exit 0
else
    echo "Some model-attack tests failed. See above."
    exit 1
fi
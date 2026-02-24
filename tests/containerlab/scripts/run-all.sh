#!/bin/bash
# run-all.sh — Execute containerlab E2E test scenarios
#
# Runs each test script and collects results into a summary.
# Exits with non-zero if any test scenario failed.
#
# Environment variables:
#   E2E_SUITES      — Comma-separated list of suites to run.
#                     Available: l2, l3, nat, fw
#                     Default: all suites (l2,l3,nat,fw)
#   CLAB_TOPO_NAME  — Containerlab topology name override.
#                     Default: ruster-e2e (from topology.yml)
#
# Examples:
#   bash run-all.sh                       # Run all suites
#   E2E_SUITES=l2,l3 bash run-all.sh      # v0.1 gate (L2 + L3 only)
#   E2E_SUITES=nat,fw bash run-all.sh     # NAT/FW strict tests only

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
RESULTS=""

E2E_SUITES="${E2E_SUITES:-l2,l3,nat,fw}"

# ── Known suites ──────────────────────────────────────
KNOWN_SUITES=("l2" "l3" "nat" "fw")

# ── Helpers ───────────────────────────────────────────

suite_enabled() {
    echo ",$E2E_SUITES," | grep -q ",$1,"
}

# ── Validate E2E_SUITES ──────────────────────────────
# Check that at least one known suite is requested.
# This prevents typos like E2E_SUITES=l2,l33 from silently
# running 0 suites and exiting 0.
VALID_COUNT=0
INVALID_NAMES=()
IFS=',' read -ra REQUESTED_SUITES <<< "$E2E_SUITES"
for s in "${REQUESTED_SUITES[@]}"; do
    is_known=false
    for k in "${KNOWN_SUITES[@]}"; do
        if [ "$s" = "$k" ]; then
            is_known=true
            VALID_COUNT=$((VALID_COUNT + 1))
            break
        fi
    done
    if [ "$is_known" = false ] && [ -n "$s" ]; then
        INVALID_NAMES+=("$s")
    fi
done

if [ "${#INVALID_NAMES[@]}" -gt 0 ]; then
    echo "WARNING: Unknown suite(s) in E2E_SUITES: ${INVALID_NAMES[*]}"
    echo "         Known suites: ${KNOWN_SUITES[*]}"
fi

if [ "$VALID_COUNT" -eq 0 ]; then
    echo ""
    echo "ERROR: E2E_SUITES='${E2E_SUITES}' contains no valid suite names."
    echo "       Known suites: ${KNOWN_SUITES[*]}"
    echo "       At least one valid suite must be specified."
    exit 1
fi

run_suite() {
    local name="$1"
    local script="$2"
    echo ""
    echo "================================================================"
    echo "  Running: ${name}"
    echo "================================================================"
    echo ""

    if bash "${SCRIPT_DIR}/${script}"; then
        RESULTS="${RESULTS}  [PASS] ${name}\n"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        RESULTS="${RESULTS}  [FAIL] ${name}\n"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
}

# ── Wait for topology to settle ──────────────────────

echo "Waiting for topology to settle (5s)..."
sleep 5

# ── Pre-flight: verify ruster is running ─────────────

echo ""
echo "================================================================"
echo "  Pre-flight: checking ruster process"
echo "================================================================"
echo ""

if ! bash "${SCRIPT_DIR}/check-ruster.sh"; then
    echo ""
    echo "FATAL: ruster process is not running. Cannot proceed with E2E tests."
    echo "       Tests would pass using kernel routing alone, masking real failures."
    echo "       See diagnostic output above for details."
    exit 1
fi

echo ""
echo "Suites to run: ${E2E_SUITES}"

# ── Run selected suites ──────────────────────────────

suite_enabled "l2"  && run_suite "L2 (ARP / MAC Learning)"   "test-l2.sh"
suite_enabled "l3"  && run_suite "L3 (Routing)"              "test-l3.sh"
suite_enabled "nat" && run_suite "NAT (NAPT44)"              "test-nat.sh"
suite_enabled "fw"  && run_suite "Firewall"                  "test-fw.sh"

# ── Summary ───────────────────────────────────────────

TOTAL_RAN=$((TOTAL_PASS + TOTAL_FAIL))
TOTAL_SKIP=$((VALID_COUNT - TOTAL_RAN))

echo ""
echo "================================================================"
echo "  E2E Test Summary"
echo "================================================================"
echo ""
echo -e "$RESULTS"
echo "Suites: ${TOTAL_RAN} ran (${TOTAL_PASS} passed, ${TOTAL_FAIL} failed), ${TOTAL_SKIP} skipped"
echo ""

if [ "$TOTAL_RAN" -eq 0 ]; then
    echo "ERROR: No test suites were executed. This should not happen"
    echo "       after validation. Check suite scripts exist."
    echo "RESULT: FAIL"
    exit 1
elif [ "$TOTAL_FAIL" -gt 0 ]; then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi

#!/bin/bash
# run-all.sh — Execute all containerlab E2E test scenarios
#
# Runs each test script and collects results into a summary.
# Exits with non-zero if any test scenario failed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOTAL_PASS=0
TOTAL_FAIL=0
RESULTS=""

# ── Helpers ───────────────────────────────────────────

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

# ── Run all suites ────────────────────────────────────

run_suite "L2 (ARP / MAC Learning)"   "test-l2.sh"
run_suite "L3 (Routing)"              "test-l3.sh"
run_suite "NAT (NAPT44)"              "test-nat.sh"
run_suite "Firewall"                  "test-fw.sh"

# ── Summary ───────────────────────────────────────────

TOTAL=$((TOTAL_PASS + TOTAL_FAIL))

echo ""
echo "================================================================"
echo "  E2E Test Summary"
echo "================================================================"
echo ""
echo -e "$RESULTS"
echo "Total: ${TOTAL} suites, ${TOTAL_PASS} passed, ${TOTAL_FAIL} failed"
echo ""

if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi

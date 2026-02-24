#!/bin/bash
# test-e2e-suites-guard.sh — Unit test for E2E_SUITES validation in run-all.sh
#
# Tests the upfront validation logic that rejects invalid suite names.
# This script extracts and tests the validation portion of run-all.sh
# without requiring containerlab infrastructure.
#
# Usage:
#   bash tests/containerlab/scripts/test-e2e-suites-guard.sh

set -uo pipefail

PASS=0
FAIL=0

# ── Test helper ──────────────────────────────────────

assert_exit_code() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [ "$expected" -eq "$actual" ]; then
        echo "  [PASS] ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] ${desc} (expected exit ${expected}, got ${actual})"
        FAIL=$((FAIL + 1))
    fi
}

assert_output_contains() {
    local desc="$1"
    local expected_text="$2"
    local actual_output="$3"
    if echo "$actual_output" | grep -qF "$expected_text"; then
        echo "  [PASS] ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] ${desc} (expected output to contain: '${expected_text}')"
        FAIL=$((FAIL + 1))
    fi
}

# ── Inline validation function (mirrors run-all.sh logic) ──

validate_e2e_suites() {
    local E2E_SUITES="$1"
    local KNOWN_SUITES=("l2" "l3" "nat" "fw")
    local VALID_COUNT=0
    local INVALID_NAMES=()
    local output=""

    IFS=',' read -ra REQUESTED_SUITES <<< "$E2E_SUITES"
    for s in "${REQUESTED_SUITES[@]}"; do
        local is_known=false
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
        output="WARNING: Unknown suite(s) in E2E_SUITES: ${INVALID_NAMES[*]}"
    fi

    if [ "$VALID_COUNT" -eq 0 ]; then
        echo "${output}"
        echo "ERROR: E2E_SUITES='${E2E_SUITES}' contains no valid suite names."
        return 1
    fi

    echo "${output}"
    return 0
}

# ── Tests ────────────────────────────────────────────

echo ""
echo "================================================================"
echo "  E2E_SUITES Validation Guard — Unit Tests"
echo "================================================================"
echo ""

# Test 1: All defaults (should pass)
echo "--- Test group: valid suites ---"
output=$(validate_e2e_suites "l2,l3,nat,fw" 2>&1); rc=$?
assert_exit_code "All four suites (l2,l3,nat,fw) -> exit 0" 0 "$rc"

# Test 2: Single valid suite
output=$(validate_e2e_suites "l2" 2>&1); rc=$?
assert_exit_code "Single suite (l2) -> exit 0" 0 "$rc"

# Test 3: Two valid suites
output=$(validate_e2e_suites "nat,fw" 2>&1); rc=$?
assert_exit_code "Two suites (nat,fw) -> exit 0" 0 "$rc"

# Test 4: All invalid suites (should fail)
echo ""
echo "--- Test group: invalid suites ---"
output=$(validate_e2e_suites "l33,natt" 2>&1); rc=$?
assert_exit_code "All invalid (l33,natt) -> exit 1" 1 "$rc"
assert_output_contains "Error message mentions no valid suite names" "contains no valid suite names" "$output"

# Test 5: Single invalid suite
output=$(validate_e2e_suites "typo" 2>&1); rc=$?
assert_exit_code "Single invalid (typo) -> exit 1" 1 "$rc"

# Test 6: Empty string
output=$(validate_e2e_suites "" 2>&1); rc=$?
assert_exit_code "Empty string -> exit 1" 1 "$rc"

# Test 7: Mixed valid + invalid (should pass with warning)
echo ""
echo "--- Test group: mixed valid/invalid ---"
output=$(validate_e2e_suites "l2,l33" 2>&1); rc=$?
assert_exit_code "Mixed (l2,l33) -> exit 0 (l2 is valid)" 0 "$rc"
assert_output_contains "Warning about unknown suite" "WARNING: Unknown suite(s)" "$output"

# Test 8: Valid with trailing comma
output=$(validate_e2e_suites "l2,l3," 2>&1); rc=$?
assert_exit_code "Trailing comma (l2,l3,) -> exit 0" 0 "$rc"

# Test 9: Case sensitivity (uppercase should fail)
output=$(validate_e2e_suites "L2,L3" 2>&1); rc=$?
assert_exit_code "Uppercase (L2,L3) -> exit 1 (case sensitive)" 1 "$rc"

# ── Summary ──────────────────────────────────────────

TOTAL=$((PASS + FAIL))
echo ""
echo "================================================================"
echo "  Results: ${TOTAL} tests, ${PASS} passed, ${FAIL} failed"
echo "================================================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi

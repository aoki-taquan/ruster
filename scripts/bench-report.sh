#!/usr/bin/env bash
# bench-report.sh — Run criterion benchmarks and check against targets.
#
# Usage:
#   ./scripts/bench-report.sh [--ci]
#
# Options:
#   --ci    Run in CI mode: fail on regression or below-target performance.
#
# Exit codes:
#   0  All benchmarks pass
#   1  Regression detected or below-target performance
#
# Requires: cargo, jq (optional, for JSON parsing)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGETS_FILE="$PROJECT_ROOT/tests/perf/targets.toml"
CI_MODE=false

for arg in "$@"; do
    case "$arg" in
        --ci) CI_MODE=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ── Parse targets from TOML (simple key = value parser) ──────────────

parse_toml_value() {
    local file="$1" key="$2"
    # Match lines like: key = 1_000_000
    # Strip underscores from numeric values for arithmetic.
    grep -E "^${key}\s*=" "$file" \
        | head -1 \
        | sed 's/.*=\s*//' \
        | tr -d ' _'
}

L2_TARGET=$(parse_toml_value "$TARGETS_FILE" "l2_bridge_pps")
L3_TARGET=$(parse_toml_value "$TARGETS_FILE" "l3_forward_pps")
NAT_TARGET=$(parse_toml_value "$TARGETS_FILE" "l3_nat_pps")
FW_TARGET=$(parse_toml_value "$TARGETS_FILE" "firewall_pps")
CT_TARGET=$(parse_toml_value "$TARGETS_FILE" "conntrack_lookup_pps")
PIPELINE_TARGET=$(parse_toml_value "$TARGETS_FILE" "full_pipeline_pps")
PARSE_TARGET=$(parse_toml_value "$TARGETS_FILE" "packet_parse_pps")

echo "=== ruster Benchmark Report ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""
echo "--- Targets (from targets.toml) ---"
echo "  L2 bridge:       ${L2_TARGET} pps"
echo "  L3 forward:      ${L3_TARGET} pps"
echo "  NAT:             ${NAT_TARGET} pps"
echo "  Firewall:        ${FW_TARGET} pps"
echo "  Conntrack:       ${CT_TARGET} pps"
echo "  Full pipeline:   ${PIPELINE_TARGET} pps"
echo "  Packet parse:    ${PARSE_TARGET} pps"
echo "  Regression:      criterion built-in statistical comparison"
echo ""

# ── Run benchmarks ───────────────────────────────────────────────────

echo "--- Running criterion benchmarks (--release) ---"
echo ""

BENCH_OUTPUT_DIR="$PROJECT_ROOT/target/criterion"

# Run criterion and capture output.
# Use --message-format=human for readable output.
cd "$PROJECT_ROOT"
BENCH_OUTPUT=$(cargo bench -p ruster-dataplane 2>&1) || {
    echo "ERROR: cargo bench failed:"
    echo "$BENCH_OUTPUT"
    exit 1
}

echo "$BENCH_OUTPUT"
echo ""

# ── Parse results ────────────────────────────────────────────────────

# Extract ns/iter values from criterion output.
# Criterion format: "bench_name  time:   [low est high]"
# We look for the "time:" line and extract the estimate (middle value).

parse_ns_per_iter() {
    local bench_name="$1"
    # Match the benchmark group/function pattern in criterion output.
    # Criterion outputs lines like:
    #   l2_bridge/fdb_hit   time:   [45.123 ns 46.456 ns 47.789 ns]
    echo "$BENCH_OUTPUT" \
        | grep -E "${bench_name}.*time:" \
        | head -1 \
        | sed -E 's/.*time:\s*\[([0-9.]+)\s*(ns|µs|us|ms|s)\s+([0-9.]+)\s*(ns|µs|us|ms|s)\s+([0-9.]+)\s*(ns|µs|us|ms|s)\]/\3 \4/' \
        | awk '{
            val=$1; unit=$2;
            if (unit == "ns") print val;
            else if (unit == "µs" || unit == "us") print val * 1000;
            else if (unit == "ms") print val * 1000000;
            else if (unit == "s") print val * 1000000000;
        }'
}

ns_to_pps() {
    local ns="$1"
    if [ -z "$ns" ] || [ "$ns" = "0" ]; then
        echo "0"
        return
    fi
    # pps = 1e9 / ns_per_packet
    awk "BEGIN { printf \"%.0f\", 1000000000 / $ns }"
}

# ── Check results against targets ────────────────────────────────────

echo "--- Results vs Targets ---"
echo ""

FAIL=0

check_target() {
    local name="$1" bench_pattern="$2" target="$3"
    local ns pps

    ns=$(parse_ns_per_iter "$bench_pattern")
    if [ -z "$ns" ]; then
        echo "  SKIP  $name (benchmark output not found)"
        return
    fi

    pps=$(ns_to_pps "$ns")
    local status="PASS"

    if ! [[ "$pps" =~ ^[0-9]+$ ]]; then
        echo "  ERROR $name: non-numeric pps value '$pps'"
        FAIL=1
        return
    fi

    if [[ "$pps" =~ ^[0-9]+$ ]] && [ "$pps" -lt "$target" ]; then
        status="FAIL"
        FAIL=1
    fi

    printf "  %-6s %-20s %10s pps  (target: %s pps, %.1f ns/pkt)\n" \
        "$status" "$name" "$pps" "$target" "$ns"
}

check_target "L2 bridge"     "l2_bridge/fdb_hit"          "$L2_TARGET"
check_target "L3 forward"    "l3_forward/default_route"   "$L3_TARGET"
check_target "NAT"           "nat/outbound_existing"      "$NAT_TARGET"
check_target "Firewall"      "firewall/accept"            "$FW_TARGET"
check_target "Conntrack"     "conntrack/lookup_hit"       "$CT_TARGET"
check_target "Full pipeline" "full_pipeline/l3_fw_nat"    "$PIPELINE_TARGET"
check_target "Packet parse"  "packet_parse/tcp_ipv4/1500" "$PARSE_TARGET"

echo ""

# ── Check for regressions ────────────────────────────────────────────
#
# Regression detection uses criterion's built-in statistical comparison
# rather than a custom percentage threshold. Criterion uses confidence
# intervals to determine whether a benchmark has regressed, which is more
# robust against measurement noise than a fixed percentage cutoff.

echo "--- Regression Check ---"
echo ""

# Criterion reports regressions in its output with "regressed" keyword.
REGRESSIONS=$(echo "$BENCH_OUTPUT" | grep -ci "regressed" || true)

if [ "$REGRESSIONS" -gt 0 ]; then
    echo "  WARNING: $REGRESSIONS benchmark(s) show regression from previous run."
    echo ""
    echo "$BENCH_OUTPUT" | grep -i "regressed" || true
    echo ""
    if [ "$CI_MODE" = true ]; then
        FAIL=1
    fi
else
    echo "  No regressions detected."
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────

if [ "$FAIL" -ne 0 ]; then
    echo "=== RESULT: FAIL ==="
    echo "One or more benchmarks failed to meet targets or showed regression."
    if [ "$CI_MODE" = true ]; then
        exit 1
    fi
else
    echo "=== RESULT: PASS ==="
    echo "All benchmarks within acceptable ranges."
fi

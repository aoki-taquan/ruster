#!/bin/bash
# soak-report.sh — Generate soak test report from collected metrics
#
# Reads metrics and packet stats from the latest soak run, computes
# summary statistics, checks against thresholds (both thresholds.toml
# and soak-config.toml), and produces a markdown report.
#
# This script is designed to run after soak-run.sh completes. It reads
# from tests/soak/results/latest/ and writes the report there.
#
# Environment variables:
#   CLAB_TOPO_NAME  — Used for topology info in the report (optional)
#
# Usage:
#   bash soak-report.sh
#
# Exit code:
#   0 — All thresholds passed
#   1 — One or more threshold violations detected

set -uo pipefail

# ── Configuration ─────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results/latest"

METRICS_FILE="${RESULTS_DIR}/metrics.tsv"
PACKET_STATS_FILE="${RESULTS_DIR}/packet-stats.tsv"
PING_LOG="${RESULTS_DIR}/ping-results.log"
REPORT_FILE="${RESULTS_DIR}/report.md"

THRESHOLDS_FILE="${SCRIPT_DIR}/thresholds.toml"
CONFIG_FILE="${SCRIPT_DIR}/soak-config.toml"

CLAB_TOPO_NAME="${CLAB_TOPO_NAME:-unknown}"

# ── Logging ───────────────────────────────────────────
log() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [soak-report] $*"
}

log_error() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [soak-report] ERROR: $*" >&2
}

# ── Pre-flight ────────────────────────────────────────
if [ ! -d "$RESULTS_DIR" ]; then
    log_error "Results directory not found: $RESULTS_DIR"
    log_error "Run soak-run.sh first"
    exit 1
fi

if [ ! -f "$METRICS_FILE" ]; then
    log_error "Metrics file not found: $METRICS_FILE"
    exit 1
fi

# ── Parse thresholds ─────────────────────────────────
parse_toml_value() {
    local file="$1" key="$2"
    local val
    val=$(awk -v k="$key" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            split($0, parts, "=")
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", parts[1])
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", parts[2])
            if (parts[1] == k) {
                print parts[2]
                exit
            }
        }
    ' "$file" 2>/dev/null)
    echo "$val"
}

# Load thresholds from thresholds.toml (primary)
MAX_RSS_GROWTH_MB=$(parse_toml_value "$THRESHOLDS_FILE" "max_rss_growth_mb")
MAX_RSS_ABSOLUTE_MB=$(parse_toml_value "$THRESHOLDS_FILE" "max_rss_absolute_mb")
MUST_BE_ALIVE=$(parse_toml_value "$THRESHOLDS_FILE" "must_be_alive")
MAX_CPU_PERCENT=$(parse_toml_value "$THRESHOLDS_FILE" "max_cpu_percent")
MAX_RESTARTS=$(parse_toml_value "$THRESHOLDS_FILE" "max_restarts")
MIN_UPTIME_FRACTION=$(parse_toml_value "$THRESHOLDS_FILE" "min_uptime_fraction")

# Load additional thresholds from soak-config.toml
MAX_LOSS_RATE=$(parse_toml_value "$CONFIG_FILE" "max_loss_rate")
MAX_ERROR_INCREMENTS=$(parse_toml_value "$CONFIG_FILE" "max_error_increments")
MAX_AVG_RTT_MS=$(parse_toml_value "$CONFIG_FILE" "max_avg_rtt_ms")
MAX_P99_RTT_MS=$(parse_toml_value "$CONFIG_FILE" "max_p99_rtt_ms")

# Defaults
MAX_RSS_GROWTH_MB="${MAX_RSS_GROWTH_MB:-50}"
MAX_RSS_ABSOLUTE_MB="${MAX_RSS_ABSOLUTE_MB:-256}"
MUST_BE_ALIVE="${MUST_BE_ALIVE:-true}"
MAX_CPU_PERCENT="${MAX_CPU_PERCENT:-80}"
MAX_RESTARTS="${MAX_RESTARTS:-0}"
MIN_UPTIME_FRACTION="${MIN_UPTIME_FRACTION:-0.99}"
MAX_LOSS_RATE="${MAX_LOSS_RATE:-0.01}"
MAX_ERROR_INCREMENTS="${MAX_ERROR_INCREMENTS:-10}"
MAX_AVG_RTT_MS="${MAX_AVG_RTT_MS:-50}"
MAX_P99_RTT_MS="${MAX_P99_RTT_MS:-200}"

# ── Parse health metrics TSV ─────────────────────────
log "Parsing health metrics..."

SAMPLE_COUNT=0
RSS_MIN=999999999
RSS_MAX=0
RSS_SUM=0
RSS_FIRST=0
RSS_LAST=0
CPU_MIN=999999
CPU_MAX=0
CPU_SUM=0
FD_MIN=999999
FD_MAX=0
FD_SUM=0
ALIVE_COUNT=0
DEAD_COUNT=0
DEATH_TIMESTAMPS=""
FIRST_TIMESTAMP=""
LAST_TIMESTAMP=""

while IFS=$'\t' read -r timestamp pid_alive rss_kb cpu_pct open_fds uptime_s; do
    # Skip empty/comment lines
    [ -z "$timestamp" ] && continue
    echo "$timestamp" | grep -q '^#' && continue

    SAMPLE_COUNT=$((SAMPLE_COUNT + 1))

    if [ -z "$FIRST_TIMESTAMP" ]; then
        FIRST_TIMESTAMP="$timestamp"
    fi
    LAST_TIMESTAMP="$timestamp"

    # PID alive
    if [ "${pid_alive:-0}" -eq 1 ] 2>/dev/null; then
        ALIVE_COUNT=$((ALIVE_COUNT + 1))
    else
        DEAD_COUNT=$((DEAD_COUNT + 1))
        DEATH_TIMESTAMPS="${DEATH_TIMESTAMPS}  - ${timestamp}\n"
    fi

    # RSS
    rss_int=$(echo "${rss_kb:-0}" | cut -d'.' -f1)
    rss_int="${rss_int:-0}"
    if [ "$SAMPLE_COUNT" -eq 1 ]; then
        RSS_FIRST="$rss_int"
    fi
    RSS_LAST="$rss_int"
    RSS_SUM=$((RSS_SUM + rss_int))
    [ "$rss_int" -lt "$RSS_MIN" ] 2>/dev/null && RSS_MIN="$rss_int"
    [ "$rss_int" -gt "$RSS_MAX" ] 2>/dev/null && RSS_MAX="$rss_int"

    # CPU
    cpu_val="${cpu_pct:-0}"
    CPU_SUM=$(awk "BEGIN { printf \"%.1f\", $CPU_SUM + $cpu_val }")
    awk "BEGIN { exit !($cpu_val < $CPU_MIN) }" && CPU_MIN="$cpu_val"
    awk "BEGIN { exit !($cpu_val > $CPU_MAX) }" && CPU_MAX="$cpu_val"

    # FDs
    fd_int=$(echo "${open_fds:-0}" | cut -d'.' -f1)
    fd_int="${fd_int:-0}"
    FD_SUM=$((FD_SUM + fd_int))
    [ "$fd_int" -lt "$FD_MIN" ] 2>/dev/null && FD_MIN="$fd_int"
    [ "$fd_int" -gt "$FD_MAX" ] 2>/dev/null && FD_MAX="$fd_int"

done < "$METRICS_FILE"

if [ "$SAMPLE_COUNT" -eq 0 ]; then
    log_error "No metric samples found in $METRICS_FILE"
    exit 1
fi

# ── Compute summary statistics ────────────────────────
RSS_AVG=$((RSS_SUM / SAMPLE_COUNT))
RSS_GROWTH_KB=$((RSS_LAST - RSS_FIRST))
RSS_GROWTH_MB=$(awk "BEGIN { printf \"%.1f\", $RSS_GROWTH_KB / 1024.0 }")
RSS_MAX_MB=$(awk "BEGIN { printf \"%.1f\", $RSS_MAX / 1024.0 }")
RSS_MIN_MB=$(awk "BEGIN { printf \"%.1f\", $RSS_MIN / 1024.0 }")
RSS_AVG_MB=$(awk "BEGIN { printf \"%.1f\", $RSS_AVG / 1024.0 }")
RSS_FIRST_MB=$(awk "BEGIN { printf \"%.1f\", $RSS_FIRST / 1024.0 }")
RSS_LAST_MB=$(awk "BEGIN { printf \"%.1f\", $RSS_LAST / 1024.0 }")
CPU_AVG=$(awk "BEGIN { printf \"%.1f\", $CPU_SUM / $SAMPLE_COUNT }")
FD_AVG=$((FD_SUM / SAMPLE_COUNT))
ALIVE_FRACTION=$(awk "BEGIN { printf \"%.4f\", $ALIVE_COUNT / $SAMPLE_COUNT }")

# ── Parse packet stats ───────────────────────────────
log "Parsing packet statistics..."

PKT_TX_FIRST=0 PKT_RX_FIRST=0 ERR_TX_FIRST=0 ERR_RX_FIRST=0 DROP_TX_FIRST=0 DROP_RX_FIRST=0
PKT_TX_LAST=0 PKT_RX_LAST=0 ERR_TX_LAST=0 ERR_RX_LAST=0 DROP_TX_LAST=0 DROP_RX_LAST=0
PKT_SAMPLE=0

if [ -f "$PACKET_STATS_FILE" ]; then
    while IFS=$'\t' read -r ts tx_p rx_p tx_e rx_e tx_d rx_d; do
        [ -z "$ts" ] && continue
        echo "$ts" | grep -q '^#' && continue

        PKT_SAMPLE=$((PKT_SAMPLE + 1))
        if [ "$PKT_SAMPLE" -eq 1 ]; then
            PKT_TX_FIRST="${tx_p:-0}"
            PKT_RX_FIRST="${rx_p:-0}"
            ERR_TX_FIRST="${tx_e:-0}"
            ERR_RX_FIRST="${rx_e:-0}"
            DROP_TX_FIRST="${tx_d:-0}"
            DROP_RX_FIRST="${rx_d:-0}"
        fi
        PKT_TX_LAST="${tx_p:-0}"
        PKT_RX_LAST="${rx_p:-0}"
        ERR_TX_LAST="${tx_e:-0}"
        ERR_RX_LAST="${rx_e:-0}"
        DROP_TX_LAST="${tx_d:-0}"
        DROP_RX_LAST="${rx_d:-0}"
    done < "$PACKET_STATS_FILE"
fi

# Compute deltas
PKT_TX_DELTA=$((PKT_TX_LAST - PKT_TX_FIRST))
PKT_RX_DELTA=$((PKT_RX_LAST - PKT_RX_FIRST))
ERR_TX_DELTA=$((ERR_TX_LAST - ERR_TX_FIRST))
ERR_RX_DELTA=$((ERR_RX_LAST - ERR_RX_FIRST))
DROP_TX_DELTA=$((DROP_TX_LAST - DROP_TX_FIRST))
DROP_RX_DELTA=$((DROP_RX_LAST - DROP_RX_FIRST))
TOTAL_ERRORS=$((ERR_TX_DELTA + ERR_RX_DELTA + DROP_TX_DELTA + DROP_RX_DELTA))

# ── Parse ping results ───────────────────────────────
log "Parsing ping results..."

PING_TX=0
PING_RX=0
PING_LOSS_PCT="0"
PING_AVG_RTT="0"
PING_MAX_RTT="0"

if [ -f "$PING_LOG" ] && [ -s "$PING_LOG" ]; then
    # Parse aggregate ping stats from all streams
    # Format: X packets transmitted, Y received, Z% packet loss, time NNNms
    PING_TX=$(awk '/packets transmitted/ { sum += $1 } END { print sum+0 }' "$PING_LOG")
    PING_RX=$(awk '/packets transmitted/ { gsub(/,/, "", $4); sum += $4 } END { print sum+0 }' "$PING_LOG")

    if [ "$PING_TX" -gt 0 ]; then
        PING_LOSS_PCT=$(awk "BEGIN { printf \"%.2f\", (1.0 - ${PING_RX} / ${PING_TX}) * 100.0 }")
    fi

    # RTT stats: rtt min/avg/max/mdev = A/B/C/D ms
    PING_AVG_RTT=$(awk -F'/' '/rtt min\/avg\/max/ { sum += $5; count++ } END { if (count>0) printf "%.2f", sum/count; else print "0" }' "$PING_LOG")
    PING_MAX_RTT=$(awk -F'/' '/rtt min\/avg\/max/ { if ($6+0 > max) max = $6+0 } END { printf "%.2f", max+0 }' "$PING_LOG")
fi

PING_LOSS_RATE="0"
if [ "$PING_TX" -gt 0 ]; then
    PING_LOSS_RATE=$(awk "BEGIN { printf \"%.6f\", 1.0 - ${PING_RX} / ${PING_TX} }")
fi

# ── Threshold checks ─────────────────────────────────
log "Checking thresholds..."

VIOLATIONS=0
VERDICT_LINES=""

check_threshold() {
    local name="$1" actual="$2" limit="$3" op="$4" unit="${5:-}"

    local passed=0
    case "$op" in
        le) awk "BEGIN { exit !($actual <= $limit) }" && passed=1 ;;
        ge) awk "BEGIN { exit !($actual >= $limit) }" && passed=1 ;;
        eq) [ "$actual" = "$limit" ] && passed=1 ;;
    esac

    if [ "$passed" -eq 1 ]; then
        VERDICT_LINES="${VERDICT_LINES}| ${name} | ${actual}${unit} | ${op} ${limit}${unit} | PASS |\n"
    else
        VERDICT_LINES="${VERDICT_LINES}| ${name} | ${actual}${unit} | ${op} ${limit}${unit} | **FAIL** |\n"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
}

# Memory checks
check_threshold "RSS growth" "$RSS_GROWTH_MB" "$MAX_RSS_GROWTH_MB" "le" " MB"
check_threshold "RSS max" "$RSS_MAX_MB" "$MAX_RSS_ABSOLUTE_MB" "le" " MB"

# Process alive (final)
if [ "$MUST_BE_ALIVE" = "true" ]; then
    last_alive=$(tail -1 "$METRICS_FILE" | grep -v '^#' | cut -f2)
    if [ "${last_alive:-0}" -eq 1 ] 2>/dev/null; then
        VERDICT_LINES="${VERDICT_LINES}| Process alive (final) | yes | must be alive | PASS |\n"
    else
        VERDICT_LINES="${VERDICT_LINES}| Process alive (final) | no | must be alive | **FAIL** |\n"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

# CPU check
check_threshold "CPU avg" "$CPU_AVG" "$MAX_CPU_PERCENT" "le" "%"

# Stability checks
check_threshold "Restart count" "$DEAD_COUNT" "$MAX_RESTARTS" "le" ""
check_threshold "Uptime fraction" "$ALIVE_FRACTION" "$MIN_UPTIME_FRACTION" "ge" ""

# Packet loss check
check_threshold "Packet loss rate" "$PING_LOSS_RATE" "$MAX_LOSS_RATE" "le" ""

# Error counter check
check_threshold "Error increments" "$TOTAL_ERRORS" "$MAX_ERROR_INCREMENTS" "le" ""

# Latency checks (only if we have ping data)
if [ "$PING_TX" -gt 0 ]; then
    check_threshold "Avg RTT" "$PING_AVG_RTT" "$MAX_AVG_RTT_MS" "le" " ms"
    # Use max RTT as a proxy for p99 (conservative; actual p99 would need sorted data)
    check_threshold "Max RTT (p99 proxy)" "$PING_MAX_RTT" "$MAX_P99_RTT_MS" "le" " ms"
fi

# Overall verdict
if [ "$VIOLATIONS" -eq 0 ]; then
    OVERALL="PASS"
else
    OVERALL="FAIL (${VIOLATIONS} violation(s))"
fi

# ── Compute soak duration from timestamps ─────────────
SOAK_DURATION_DISPLAY="unknown"
if [ -n "$FIRST_TIMESTAMP" ] && [ -n "$LAST_TIMESTAMP" ]; then
    first_epoch=$(date -d "$FIRST_TIMESTAMP" +%s 2>/dev/null || echo 0)
    last_epoch=$(date -d "$LAST_TIMESTAMP" +%s 2>/dev/null || echo 0)
    if [ "$first_epoch" -gt 0 ] && [ "$last_epoch" -gt 0 ]; then
        duration_sec=$((last_epoch - first_epoch))
        duration_min=$(awk "BEGIN { printf \"%.1f\", $duration_sec / 60.0 }")
        SOAK_DURATION_DISPLAY="${duration_sec}s (${duration_min} min)"
    fi
fi

# ── Generate markdown report ─────────────────────────
log "Generating report: $REPORT_FILE"

cat > "$REPORT_FILE" << REPORT_EOF
# Soak Test Report (Strict Dataplane)

**Generated**: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Hostname**: $(hostname)
**Platform**: $(uname -s) $(uname -m)
**Topology**: ${CLAB_TOPO_NAME}
**Verdict**: **${OVERALL}**

## Test Parameters

| Parameter | Value |
|-----------|-------|
| Soak duration | ${SOAK_DURATION_DISPLAY} |
| Metric samples | ${SAMPLE_COUNT} |
| Packet stat samples | ${PKT_SAMPLE} |
| First sample | ${FIRST_TIMESTAMP} |
| Last sample | ${LAST_TIMESTAMP} |

## Memory (RSS)

| Metric | Value |
|--------|-------|
| Baseline (first) | ${RSS_FIRST_MB} MB |
| Final (last) | ${RSS_LAST_MB} MB |
| Growth | ${RSS_GROWTH_MB} MB |
| Min | ${RSS_MIN_MB} MB |
| Max | ${RSS_MAX_MB} MB |
| Average | ${RSS_AVG_MB} MB |

## CPU

| Metric | Value |
|--------|-------|
| Min | ${CPU_MIN}% |
| Max | ${CPU_MAX}% |
| Average | ${CPU_AVG}% |

## File Descriptors

| Metric | Value |
|--------|-------|
| Min | ${FD_MIN} |
| Max | ${FD_MAX} |
| Average | ${FD_AVG} |

## Process Stability

| Metric | Value |
|--------|-------|
| Samples alive | ${ALIVE_COUNT} / ${SAMPLE_COUNT} |
| Samples dead | ${DEAD_COUNT} |
| Uptime fraction | ${ALIVE_FRACTION} |

REPORT_EOF

if [ "$DEAD_COUNT" -gt 0 ]; then
    cat >> "$REPORT_FILE" << DEATH_EOF
### Process Death Events

$(printf '%b' "$DEATH_TIMESTAMPS")

DEATH_EOF
fi

cat >> "$REPORT_FILE" << PKT_EOF
## Packet Statistics (interface counters)

| Metric | Delta (soak period) |
|--------|---------------------|
| TX packets | ${PKT_TX_DELTA} |
| RX packets | ${PKT_RX_DELTA} |
| TX errors | ${ERR_TX_DELTA} |
| RX errors | ${ERR_RX_DELTA} |
| TX dropped | ${DROP_TX_DELTA} |
| RX dropped | ${DROP_RX_DELTA} |
| Total errors | ${TOTAL_ERRORS} |

## Ping Statistics (end-to-end)

| Metric | Value |
|--------|-------|
| Packets transmitted | ${PING_TX} |
| Packets received | ${PING_RX} |
| Loss rate | ${PING_LOSS_PCT}% (${PING_LOSS_RATE}) |
| Average RTT | ${PING_AVG_RTT} ms |
| Max RTT | ${PING_MAX_RTT} ms |

PKT_EOF

cat >> "$REPORT_FILE" << THRESHOLD_EOF
## Threshold Checks

| Check | Actual | Threshold | Result |
|-------|--------|-----------|--------|
$(printf '%b' "$VERDICT_LINES")

## Overall Verdict

**${OVERALL}**

THRESHOLD_EOF

# ── Output summary to stdout ─────────────────────────
echo ""
echo "================================================================"
echo "  Soak Test Report Summary (Strict Dataplane)"
echo "================================================================"
echo ""
echo "  Duration:       ${SOAK_DURATION_DISPLAY}"
echo "  Samples:        ${SAMPLE_COUNT}"
echo "  RSS baseline:   ${RSS_FIRST_MB} MB"
echo "  RSS final:      ${RSS_LAST_MB} MB"
echo "  RSS growth:     ${RSS_GROWTH_MB} MB"
echo "  RSS max:        ${RSS_MAX_MB} MB"
echo "  CPU avg:        ${CPU_AVG}%"
echo "  Alive:          ${ALIVE_COUNT} / ${SAMPLE_COUNT}"
echo "  Ping loss:      ${PING_LOSS_PCT}%"
echo "  Avg RTT:        ${PING_AVG_RTT} ms"
echo "  Error counters: ${TOTAL_ERRORS}"
echo "  Violations:     ${VIOLATIONS}"
echo ""
echo "  VERDICT:        ${OVERALL}"
echo ""
echo "  Full report:    ${REPORT_FILE}"
echo ""

# ── Exit ──────────────────────────────────────────────
if [ "$VIOLATIONS" -gt 0 ]; then
    exit 1
else
    exit 0
fi

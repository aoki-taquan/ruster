#!/bin/bash
# report.sh — Generate soak test report and check thresholds
#
# Reads collected metrics from the health check TSV file, computes
# summary statistics, checks against thresholds, and produces a
# markdown report.
#
# Usage: bash report.sh <metrics_file> <thresholds_file> <report_file> [soak_duration_sec]
#
# Exit code:
#   0 — All thresholds passed
#   1 — One or more threshold violations detected

set -uo pipefail

METRICS_FILE="${1:-}"
THRESHOLDS_FILE="${2:-}"
REPORT_FILE="${3:-}"
SOAK_DURATION_SEC="${4:-1800}"

if [ -z "$METRICS_FILE" ] || [ -z "$THRESHOLDS_FILE" ] || [ -z "$REPORT_FILE" ]; then
    echo "ERROR: Missing required arguments" >&2
    echo "Usage: $0 <metrics_file> <thresholds_file> <report_file> [soak_duration_sec]" >&2
    exit 1
fi

if [ ! -f "$METRICS_FILE" ]; then
    echo "ERROR: Metrics file not found: $METRICS_FILE" >&2
    exit 1
fi

if [ ! -f "$THRESHOLDS_FILE" ]; then
    echo "ERROR: Thresholds file not found: $THRESHOLDS_FILE" >&2
    exit 1
fi

# ── Parse thresholds from TOML ──────────────────────────
# Simple TOML parser for our flat structure (no nested tables beyond one level)
parse_toml_value() {
    local file="$1"
    local key="$2"
    # Match lines like: key = value (ignoring comments and whitespace)
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
    ' "$file")
    echo "$val"
}

MAX_RSS_GROWTH_MB=$(parse_toml_value "$THRESHOLDS_FILE" "max_rss_growth_mb")
MAX_RSS_ABSOLUTE_MB=$(parse_toml_value "$THRESHOLDS_FILE" "max_rss_absolute_mb")
MUST_BE_ALIVE=$(parse_toml_value "$THRESHOLDS_FILE" "must_be_alive")
MAX_CPU_PERCENT=$(parse_toml_value "$THRESHOLDS_FILE" "max_cpu_percent")
MAX_RESTARTS=$(parse_toml_value "$THRESHOLDS_FILE" "max_restarts")
MIN_UPTIME_FRACTION=$(parse_toml_value "$THRESHOLDS_FILE" "min_uptime_fraction")

# Defaults if parsing fails
MAX_RSS_GROWTH_MB="${MAX_RSS_GROWTH_MB:-50}"
MAX_RSS_ABSOLUTE_MB="${MAX_RSS_ABSOLUTE_MB:-256}"
MUST_BE_ALIVE="${MUST_BE_ALIVE:-true}"
MAX_CPU_PERCENT="${MAX_CPU_PERCENT:-80}"
MAX_RESTARTS="${MAX_RESTARTS:-0}"
MIN_UPTIME_FRACTION="${MIN_UPTIME_FRACTION:-0.99}"

# ── Parse metrics TSV ───────────────────────────────────
# Columns: timestamp  pid_alive  rss_kb  cpu_percent  open_fds  uptime_sec

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
    # Skip empty lines or header-like lines
    [ -z "$timestamp" ] && continue
    echo "$timestamp" | grep -q '^#' && continue

    SAMPLE_COUNT=$((SAMPLE_COUNT + 1))

    # Track timestamps
    if [ -z "$FIRST_TIMESTAMP" ]; then
        FIRST_TIMESTAMP="$timestamp"
    fi
    LAST_TIMESTAMP="$timestamp"

    # PID alive tracking
    if [ "$pid_alive" -eq 1 ] 2>/dev/null; then
        ALIVE_COUNT=$((ALIVE_COUNT + 1))
    else
        DEAD_COUNT=$((DEAD_COUNT + 1))
        DEATH_TIMESTAMPS="${DEATH_TIMESTAMPS}  - ${timestamp}\n"
    fi

    # RSS (convert to integer for comparison)
    rss_int=$(echo "$rss_kb" | cut -d'.' -f1)
    rss_int="${rss_int:-0}"
    if [ "$SAMPLE_COUNT" -eq 1 ]; then
        RSS_FIRST="$rss_int"
    fi
    RSS_LAST="$rss_int"
    RSS_SUM=$((RSS_SUM + rss_int))
    if [ "$rss_int" -lt "$RSS_MIN" ] 2>/dev/null; then
        RSS_MIN="$rss_int"
    fi
    if [ "$rss_int" -gt "$RSS_MAX" ] 2>/dev/null; then
        RSS_MAX="$rss_int"
    fi

    # CPU (use awk for float comparison)
    cpu_val="${cpu_pct:-0}"
    CPU_SUM=$(awk "BEGIN { printf \"%.1f\", $CPU_SUM + $cpu_val }")
    if awk "BEGIN { exit !($cpu_val < $CPU_MIN) }"; then
        CPU_MIN="$cpu_val"
    fi
    if awk "BEGIN { exit !($cpu_val > $CPU_MAX) }"; then
        CPU_MAX="$cpu_val"
    fi

    # File descriptors
    fd_int=$(echo "$open_fds" | cut -d'.' -f1)
    fd_int="${fd_int:-0}"
    FD_SUM=$((FD_SUM + fd_int))
    if [ "$fd_int" -lt "$FD_MIN" ] 2>/dev/null; then
        FD_MIN="$fd_int"
    fi
    if [ "$fd_int" -gt "$FD_MAX" ] 2>/dev/null; then
        FD_MAX="$fd_int"
    fi

done < "$METRICS_FILE"

# ── Compute summary statistics ──────────────────────────

if [ "$SAMPLE_COUNT" -eq 0 ]; then
    echo "ERROR: No metric samples found in $METRICS_FILE" >&2
    exit 1
fi

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

# Alive fraction
if [ "$SAMPLE_COUNT" -gt 0 ]; then
    ALIVE_FRACTION=$(awk "BEGIN { printf \"%.4f\", $ALIVE_COUNT / $SAMPLE_COUNT }")
else
    ALIVE_FRACTION="0.0000"
fi

# Restart count: number of times process was found dead
RESTART_COUNT="$DEAD_COUNT"

# ── Threshold checks ────────────────────────────────────
VIOLATIONS=0
VERDICT_LINES=""

check_threshold() {
    local name="$1"
    local actual="$2"
    local limit="$3"
    local op="$4"  # "le" (<=), "ge" (>=), "eq"
    local unit="${5:-}"

    local passed=0
    case "$op" in
        le)
            if awk "BEGIN { exit !($actual <= $limit) }"; then
                passed=1
            fi
            ;;
        ge)
            if awk "BEGIN { exit !($actual >= $limit) }"; then
                passed=1
            fi
            ;;
        eq)
            if [ "$actual" = "$limit" ]; then
                passed=1
            fi
            ;;
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

# Process alive (final check: must be alive at end)
if [ "$MUST_BE_ALIVE" = "true" ]; then
    # Check last sample
    last_alive=$(tail -1 "$METRICS_FILE" | cut -f2)
    if [ "${last_alive:-0}" -eq 1 ]; then
        VERDICT_LINES="${VERDICT_LINES}| Process alive (final) | yes | must be alive | PASS |\n"
    else
        VERDICT_LINES="${VERDICT_LINES}| Process alive (final) | no | must be alive | **FAIL** |\n"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

# CPU check
check_threshold "CPU avg" "$CPU_AVG" "$MAX_CPU_PERCENT" "le" "%"

# Stability checks
check_threshold "Restart count" "$RESTART_COUNT" "$MAX_RESTARTS" "le" ""
check_threshold "Uptime fraction" "$ALIVE_FRACTION" "$MIN_UPTIME_FRACTION" "ge" ""

# ── Overall verdict ─────────────────────────────────────
if [ "$VIOLATIONS" -eq 0 ]; then
    OVERALL="PASS"
else
    OVERALL="FAIL (${VIOLATIONS} violation(s))"
fi

# ── Generate markdown report ───────────────────────────

cat > "$REPORT_FILE" << REPORT_EOF
# Soak Test Report

**Generated**: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Hostname**: $(hostname)
**Platform**: $(uname -s) $(uname -m)

## Test Parameters

| Parameter | Value |
|-----------|-------|
| Soak duration | ${SOAK_DURATION_SEC}s ($(awk "BEGIN { printf \"%.1f\", $SOAK_DURATION_SEC / 60.0 }") min) |
| Metric samples | ${SAMPLE_COUNT} |
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

# Add death timestamps if any
if [ "$DEAD_COUNT" -gt 0 ]; then
    cat >> "$REPORT_FILE" << DEATH_EOF
### Process Death Events

$(printf '%b' "$DEATH_TIMESTAMPS")

DEATH_EOF
fi

cat >> "$REPORT_FILE" << THRESHOLD_EOF
## Threshold Checks

| Check | Actual | Threshold | Result |
|-------|--------|-----------|--------|
$(printf '%b' "$VERDICT_LINES")

## Overall Verdict

**${OVERALL}**

THRESHOLD_EOF

# ── Output summary to stdout ───────────────────────────
echo ""
echo "================================================================"
echo "  Soak Test Report Summary"
echo "================================================================"
echo ""
echo "  Duration:      ${SOAK_DURATION_SEC}s ($(awk "BEGIN { printf \"%.1f\", $SOAK_DURATION_SEC / 60.0 }") min)"
echo "  Samples:       ${SAMPLE_COUNT}"
echo "  RSS baseline:  ${RSS_FIRST_MB} MB"
echo "  RSS final:     ${RSS_LAST_MB} MB"
echo "  RSS growth:    ${RSS_GROWTH_MB} MB"
echo "  RSS max:       ${RSS_MAX_MB} MB"
echo "  CPU avg:       ${CPU_AVG}%"
echo "  Alive:         ${ALIVE_COUNT} / ${SAMPLE_COUNT}"
echo "  Violations:    ${VIOLATIONS}"
echo ""
echo "  VERDICT:       ${OVERALL}"
echo ""
echo "  Full report:   ${REPORT_FILE}"
echo ""

# ── Exit with appropriate code ──────────────────────────
if [ "$VIOLATIONS" -gt 0 ]; then
    exit 1
else
    exit 0
fi

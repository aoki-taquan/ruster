#!/bin/bash
# check-health.sh — Collect health metrics from a running ruster process
#
# Outputs a single TSV line with timestamp and metrics.
# Designed to be called periodically by soak-test.sh.
#
# Usage: bash check-health.sh <PID> [output_file]
#
# Output columns (TSV):
#   timestamp  pid_alive  rss_kb  cpu_percent  open_fds  uptime_sec

set -uo pipefail

PID="${1:-}"
OUTPUT_FILE="${2:-}"

if [ -z "$PID" ]; then
    echo "ERROR: PID argument required" >&2
    echo "Usage: $0 <PID> [output_file]" >&2
    exit 1
fi

# ── Helper: parse elapsed time from ps -o etime ────────
# Format: [[DD-]HH:]MM:SS
parse_etime() {
    local etime="$1"
    local days=0 hours=0 mins=0 secs=0

    # Remove leading/trailing whitespace
    etime=$(echo "$etime" | xargs)

    if echo "$etime" | grep -q '-'; then
        days=$(echo "$etime" | cut -d'-' -f1)
        etime=$(echo "$etime" | cut -d'-' -f2)
    fi

    local parts
    IFS=':' read -ra parts <<< "$etime"
    local count=${#parts[@]}

    if [ "$count" -eq 3 ]; then
        hours=${parts[0]}
        mins=${parts[1]}
        secs=${parts[2]}
    elif [ "$count" -eq 2 ]; then
        mins=${parts[0]}
        secs=${parts[1]}
    elif [ "$count" -eq 1 ]; then
        secs=${parts[0]}
    fi

    echo $(( days * 86400 + hours * 3600 + mins * 60 + secs ))
}

# ── Collect timestamp ──────────────────────────────────
TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ── Check if process is alive ───────────────────────────
pid_alive=0
if kill -0 "$PID" 2>/dev/null; then
    pid_alive=1
fi

# ── Collect metrics (platform-aware) ────────────────────
rss_kb=0
cpu_percent=0
open_fds=0
uptime_sec=0

if [ "$pid_alive" -eq 1 ]; then
    # Detect platform
    case "$(uname -s)" in
        Linux)
            # RSS from /proc (most accurate)
            if [ -f "/proc/${PID}/status" ]; then
                rss_kb=$(awk '/^VmRSS:/ { print $2 }' "/proc/${PID}/status" 2>/dev/null || echo 0)
            else
                rss_kb=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ' || echo 0)
            fi

            # CPU usage (snapshot from ps)
            cpu_percent=$(ps -o %cpu= -p "$PID" 2>/dev/null | tr -d ' ' || echo 0)

            # Open file descriptors from /proc
            if [ -d "/proc/${PID}/fd" ]; then
                open_fds=$(ls "/proc/${PID}/fd" 2>/dev/null | wc -l | tr -d ' ')
            else
                open_fds=0
            fi

            # Process uptime from /proc/stat
            if [ -f "/proc/${PID}/stat" ]; then
                proc_start_ticks=$(awk '{ print $22 }' "/proc/${PID}/stat" 2>/dev/null || echo 0)
                clk_tck=$(getconf CLK_TCK 2>/dev/null || echo 100)
                boot_time=$(awk '/^btime/ { print $2 }' /proc/stat 2>/dev/null || echo 0)
                if [ "$proc_start_ticks" -gt 0 ] && [ "$clk_tck" -gt 0 ] && [ "$boot_time" -gt 0 ]; then
                    proc_start_sec=$((boot_time + proc_start_ticks / clk_tck))
                    now_sec=$(date +%s)
                    uptime_sec=$((now_sec - proc_start_sec))
                fi
            fi
            ;;

        Darwin)
            # RSS from ps (in KB)
            rss_kb=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ' || echo 0)

            # CPU usage from ps
            cpu_percent=$(ps -o %cpu= -p "$PID" 2>/dev/null | tr -d ' ' || echo 0)

            # Open file descriptors via lsof
            open_fds=$(lsof -p "$PID" 2>/dev/null | wc -l | tr -d ' ' || echo 0)

            # Process uptime: ps -o etime gives elapsed time
            etime=$(ps -o etime= -p "$PID" 2>/dev/null | tr -d ' ' || echo "0")
            uptime_sec=$(parse_etime "$etime" 2>/dev/null || echo 0)
            ;;

        *)
            # Fallback: use ps
            rss_kb=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ' || echo 0)
            cpu_percent=$(ps -o %cpu= -p "$PID" 2>/dev/null | tr -d ' ' || echo 0)
            open_fds=0
            uptime_sec=0
            ;;
    esac
fi

# Ensure numeric values (strip any non-numeric characters except dot)
rss_kb=$(echo "$rss_kb" | sed 's/[^0-9]//g')
cpu_percent=$(echo "$cpu_percent" | sed 's/[^0-9.]//g')
open_fds=$(echo "$open_fds" | sed 's/[^0-9]//g')
uptime_sec=$(echo "$uptime_sec" | sed 's/[^0-9]//g')

# Default empty values to 0
rss_kb="${rss_kb:-0}"
cpu_percent="${cpu_percent:-0}"
open_fds="${open_fds:-0}"
uptime_sec="${uptime_sec:-0}"

# ── Output ──────────────────────────────────────────────
LINE="${TIMESTAMP}\t${pid_alive}\t${rss_kb}\t${cpu_percent}\t${open_fds}\t${uptime_sec}"

if [ -n "$OUTPUT_FILE" ]; then
    printf '%b\n' "$LINE" >> "$OUTPUT_FILE"
fi

printf '%b\n' "$LINE"

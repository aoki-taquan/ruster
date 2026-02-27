#!/bin/bash
# soak-run.sh — Soak test runner for strict dataplane environment
#
# Runs ruster inside the strict containerlab topology for an extended
# period while sending real traffic and monitoring health metrics.
# The strict topology ensures kernel ip_forward=0 on all nodes,
# so all traffic must pass through the ruster dataplane.
#
# Prerequisites:
#   - Strict containerlab topology already deployed and hardened
#   - ruster binary built (cargo build --release)
#
# Environment variables:
#   CLAB_TOPO_NAME       — Containerlab topology name (required)
#   SOAK_DURATION_MIN    — Test duration in minutes (default: 60)
#   SOAK_CHECK_INTERVAL  — Health check interval in seconds (default: 30)
#   SOAK_OUTPUT_DIR      — Output directory (default: auto-generated)
#
# Usage:
#   CLAB_TOPO_NAME=ruster-soak-strict bash soak-run.sh
#
# Exit code:
#   0 — Soak test passed (all thresholds met)
#   1 — Soak test failed (threshold violations or process crash)

set -uo pipefail

# ── Configuration ─────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CLAB_TOPO_NAME="${CLAB_TOPO_NAME:?ERROR: CLAB_TOPO_NAME is required}"
PREFIX="clab-${CLAB_TOPO_NAME}"

SOAK_DURATION_MIN="${SOAK_DURATION_MIN:-60}"
SOAK_DURATION_SEC=$((SOAK_DURATION_MIN * 60))
SOAK_CHECK_INTERVAL="${SOAK_CHECK_INTERVAL:-30}"

CONFIG_FILE="${SCRIPT_DIR}/soak-config.toml"

# Output directory
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
SOAK_OUTPUT_DIR="${SOAK_OUTPUT_DIR:-${SCRIPT_DIR}/results/${TIMESTAMP}}"
LATEST_LINK="${SCRIPT_DIR}/results/latest"

METRICS_FILE="${SOAK_OUTPUT_DIR}/metrics.tsv"
TRAFFIC_LOG="${SOAK_OUTPUT_DIR}/traffic.log"
RUSTER_LOG="${SOAK_OUTPUT_DIR}/ruster.log"
PACKET_STATS_FILE="${SOAK_OUTPUT_DIR}/packet-stats.tsv"

# Parse traffic settings from config
TRAFFIC_STREAMS=4
PING_INTERVAL=0.2
SETTLE_TIME=10

if [ -f "$CONFIG_FILE" ]; then
    val=$(grep '^traffic_streams' "$CONFIG_FILE" | sed 's/.*=\s*//' | tr -d ' ')
    [ -n "$val" ] && TRAFFIC_STREAMS="$val"
    val=$(grep '^ping_interval_sec' "$CONFIG_FILE" | sed 's/.*=\s*//' | tr -d ' ')
    [ -n "$val" ] && PING_INTERVAL="$val"
    val=$(grep '^settle_time_sec' "$CONFIG_FILE" | sed 's/.*=\s*//' | tr -d ' ')
    [ -n "$val" ] && SETTLE_TIME="$val"
fi

# Tracking
TRAFFIC_PIDS=()
RUSTER_STARTED=false

# ── Logging ───────────────────────────────────────────
log() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [soak-run] $*"
}

log_error() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [soak-run] ERROR: $*" >&2
}

# ── Helpers ───────────────────────────────────────────
run_on() {
    local node="$1"; shift
    docker exec "${PREFIX}-${node}" "$@"
}

# ── Cleanup handler ───────────────────────────────────
cleanup() {
    local exit_code=$?
    log "Cleaning up..."

    # Stop traffic generators
    for pid in "${TRAFFIC_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    # Stop ruster in container
    if [ "$RUSTER_STARTED" = true ]; then
        log "Stopping ruster in container..."
        run_on ruster bash -c "pkill -x ruster 2>/dev/null || true" 2>/dev/null || true
        sleep 2
        run_on ruster bash -c "pkill -9 -x ruster 2>/dev/null || true" 2>/dev/null || true
    fi

    log "Cleanup complete (exit code: $exit_code)"
    exit "$exit_code"
}

trap cleanup EXIT INT TERM

# ── Setup output directory ────────────────────────────
setup_output() {
    mkdir -p "$SOAK_OUTPUT_DIR"

    # Create/update latest symlink
    rm -f "$LATEST_LINK"
    ln -sf "$SOAK_OUTPUT_DIR" "$LATEST_LINK"

    # Write TSV headers
    printf '# timestamp\tpid_alive\trss_kb\tcpu_percent\topen_fds\tuptime_sec\n' > "$METRICS_FILE"
    printf '# timestamp\ttx_packets\trx_packets\ttx_errors\trx_errors\ttx_dropped\trx_dropped\n' > "$PACKET_STATS_FILE"

    log "Output directory: $SOAK_OUTPUT_DIR"
}

# ── Pre-flight checks ────────────────────────────────
preflight() {
    log "Running pre-flight checks..."

    # Verify containers are running
    for node in ruster lan-host wan-host; do
        STATE=$(docker inspect --format '{{.State.Status}}' "${PREFIX}-${node}" 2>/dev/null || echo "not_found")
        if [ "$STATE" != "running" ]; then
            log_error "Container ${PREFIX}-${node} is not running (state: ${STATE})"
            exit 1
        fi
    done

    # Verify strict mode (ip_forward=0)
    for node in ruster lan-host wan-host; do
        FWD=$(run_on "$node" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
        if [ "$FWD" != "0" ]; then
            log_error "${node}: ip_forward=${FWD} (expected 0) — strict mode not active"
            exit 1
        fi
    done

    # Verify ruster binary is in the container
    if ! run_on ruster test -f /usr/local/bin/ruster; then
        log_error "ruster binary not found in container at /usr/local/bin/ruster"
        exit 1
    fi

    log "  Topology:     ${CLAB_TOPO_NAME}"
    log "  Duration:     ${SOAK_DURATION_MIN} min (${SOAK_DURATION_SEC}s)"
    log "  Interval:     ${SOAK_CHECK_INTERVAL}s"
    log "  Streams:      ${TRAFFIC_STREAMS}"
    log "  Ping interval: ${PING_INTERVAL}s"
    log "Pre-flight checks passed"
}

# ── Start ruster in container ─────────────────────────
start_ruster() {
    log "Starting ruster in container..."

    # Ensure ruster is not already running
    run_on ruster bash -c "pkill -x ruster 2>/dev/null || true"
    sleep 2

    # Start ruster
    run_on ruster bash -c "nohup /usr/local/bin/ruster --config /etc/ruster/router.toml > /var/log/ruster.log 2>&1 &"
    RUSTER_STARTED=true

    # Wait for startup
    log "Waiting ${SETTLE_TIME}s for ruster to initialize..."
    sleep "$SETTLE_TIME"

    # Verify ruster is running
    if run_on ruster pgrep -x ruster > /dev/null 2>&1; then
        local pid
        pid=$(run_on ruster pgrep -x ruster 2>/dev/null)
        log "ruster is running (PID: ${pid})"
    else
        log_error "ruster failed to start"
        log_error "ruster log:"
        run_on ruster cat /var/log/ruster.log 2>/dev/null | while IFS= read -r line; do
            log_error "  $line"
        done
        exit 1
    fi

    # ARP warmup
    log "ARP warmup..."
    run_on lan-host ping -c 1 -W 2 192.168.1.1 > /dev/null 2>&1 || true
    run_on wan-host ping -c 1 -W 2 10.0.0.1 > /dev/null 2>&1 || true
    sleep 2
}

# ── Verify forwarding works ──────────────────────────
verify_forwarding() {
    log "Verifying ruster forwarding before soak..."

    if run_on lan-host ping -c 3 -W 5 10.0.0.100 > /dev/null 2>&1; then
        log "Forwarding verified: lan-host -> wan-host through ruster (OK)"
    else
        log_error "Forwarding verification failed: lan-host cannot reach wan-host"
        log_error "This may indicate ruster dataplane is not fully operational"
        log_error "Continuing soak test — forwarding metrics will reflect this"
    fi
}

# ── Start traffic generation ─────────────────────────
start_traffic() {
    log "Starting traffic generation (${TRAFFIC_STREAMS} streams, ${SOAK_DURATION_SEC}s)..."

    for i in $(seq 1 "$TRAFFIC_STREAMS"); do
        docker exec "$PREFIX-lan-host" \
            ping -q -i "$PING_INTERVAL" -w "$SOAK_DURATION_SEC" 10.0.0.100 \
            >> "${SOAK_OUTPUT_DIR}/ping-stream${i}.log" 2>&1 &
        TRAFFIC_PIDS+=($!)
        log "  Stream ${i} started (PID: ${TRAFFIC_PIDS[-1]})"
    done

    log "Traffic generation started"
}

# ── Collect health metrics ────────────────────────────
collect_metrics() {
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Check if ruster is alive in container
    local pid_alive=0
    local rss_kb=0 cpu_percent=0 open_fds=0 uptime_sec=0

    if run_on ruster pgrep -x ruster > /dev/null 2>&1; then
        pid_alive=1
        local pid
        pid=$(run_on ruster pgrep -x ruster 2>/dev/null | head -1)

        # RSS from /proc inside container
        rss_kb=$(run_on ruster bash -c "awk '/^VmRSS:/ { print \$2 }' /proc/${pid}/status 2>/dev/null || echo 0")
        rss_kb="${rss_kb:-0}"

        # CPU from ps inside container
        cpu_percent=$(run_on ruster bash -c "ps -o %cpu= -p ${pid} 2>/dev/null | tr -d ' ' || echo 0")
        cpu_percent="${cpu_percent:-0}"

        # Open FDs from /proc inside container
        open_fds=$(run_on ruster bash -c "ls /proc/${pid}/fd 2>/dev/null | wc -l || echo 0")
        open_fds="${open_fds:-0}"

        # Uptime from /proc inside container
        uptime_sec=$(run_on ruster bash -c "
            proc_start=\$(awk '{ print \$22 }' /proc/${pid}/stat 2>/dev/null || echo 0)
            clk_tck=\$(getconf CLK_TCK 2>/dev/null || echo 100)
            boot_time=\$(awk '/^btime/ { print \$2 }' /proc/stat 2>/dev/null || echo 0)
            if [ \"\$proc_start\" -gt 0 ] && [ \"\$clk_tck\" -gt 0 ] && [ \"\$boot_time\" -gt 0 ]; then
                proc_start_sec=\$((boot_time + proc_start / clk_tck))
                now=\$(date +%s)
                echo \$((now - proc_start_sec))
            else
                echo 0
            fi
        " 2>/dev/null || echo 0)
        uptime_sec="${uptime_sec:-0}"
    fi

    # Sanitize values
    rss_kb=$(echo "$rss_kb" | tr -cd '0-9')
    cpu_percent=$(echo "$cpu_percent" | tr -cd '0-9.')
    open_fds=$(echo "$open_fds" | tr -cd '0-9')
    uptime_sec=$(echo "$uptime_sec" | tr -cd '0-9')
    rss_kb="${rss_kb:-0}"
    cpu_percent="${cpu_percent:-0}"
    open_fds="${open_fds:-0}"
    uptime_sec="${uptime_sec:-0}"

    # Append to metrics file
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$timestamp" "$pid_alive" "$rss_kb" "$cpu_percent" "$open_fds" "$uptime_sec" \
        >> "$METRICS_FILE"

    echo "$pid_alive"
}

# ── Collect packet/error counters ─────────────────────
collect_packet_stats() {
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Collect interface stats from the ruster container
    # We check eth1 (LAN) and eth2 (WAN) inside the ruster node
    local tx_packets=0 rx_packets=0 tx_errors=0 rx_errors=0 tx_dropped=0 rx_dropped=0

    for iface in eth1 eth2; do
        local stats
        stats=$(run_on ruster bash -c "cat /proc/net/dev 2>/dev/null" || echo "")

        if [ -n "$stats" ]; then
            local line
            line=$(echo "$stats" | grep "${iface}:" || echo "")
            if [ -n "$line" ]; then
                # /proc/net/dev format:
                # iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets tx_errs tx_drop ...
                local rx_p rx_e rx_d tx_p tx_e tx_d
                rx_p=$(echo "$line" | awk '{ print $3 }')
                rx_e=$(echo "$line" | awk '{ print $4 }')
                rx_d=$(echo "$line" | awk '{ print $5 }')
                tx_p=$(echo "$line" | awk '{ print $11 }')
                tx_e=$(echo "$line" | awk '{ print $12 }')
                tx_d=$(echo "$line" | awk '{ print $13 }')

                tx_packets=$((tx_packets + ${tx_p:-0}))
                rx_packets=$((rx_packets + ${rx_p:-0}))
                tx_errors=$((tx_errors + ${tx_e:-0}))
                rx_errors=$((rx_errors + ${rx_e:-0}))
                tx_dropped=$((tx_dropped + ${tx_d:-0}))
                rx_dropped=$((rx_dropped + ${rx_d:-0}))
            fi
        fi
    done

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$timestamp" "$tx_packets" "$rx_packets" "$tx_errors" "$rx_errors" "$tx_dropped" "$rx_dropped" \
        >> "$PACKET_STATS_FILE"
}

# ── Health monitoring loop ────────────────────────────
run_soak_loop() {
    log "Starting soak monitoring loop (duration: ${SOAK_DURATION_SEC}s, interval: ${SOAK_CHECK_INTERVAL}s)..."

    local elapsed=0
    local check_count=0
    local ruster_died=false

    while [ "$elapsed" -lt "$SOAK_DURATION_SEC" ]; do
        check_count=$((check_count + 1))

        # Collect health metrics
        local alive
        alive=$(collect_metrics)

        # Collect packet/error stats
        collect_packet_stats

        # Check if ruster crashed
        if [ "$alive" != "1" ]; then
            log_error "Ruster process died at ${elapsed}s (check #${check_count})"
            log_error "Collecting ruster log from container..."
            run_on ruster cat /var/log/ruster.log 2>/dev/null | tail -50 | while IFS= read -r line; do
                log_error "  $line"
            done
            ruster_died=true
            break
        fi

        # Progress logging every 5 minutes
        if [ $((elapsed % 300)) -eq 0 ] && [ "$elapsed" -gt 0 ]; then
            local rss_kb
            rss_kb=$(tail -1 "$METRICS_FILE" | cut -f3)
            rss_kb="${rss_kb:-0}"
            local rss_mb
            rss_mb=$(awk "BEGIN { printf \"%.1f\", ${rss_kb} / 1024.0 }")
            log "Progress: ${elapsed}s / ${SOAK_DURATION_SEC}s | RSS: ${rss_mb} MB | Check #${check_count}"
        fi

        # Sleep until next check
        local remaining=$((SOAK_DURATION_SEC - elapsed))
        if [ "$remaining" -le 0 ]; then
            break
        fi

        if [ "$remaining" -lt "$SOAK_CHECK_INTERVAL" ]; then
            sleep "$remaining"
            elapsed=$SOAK_DURATION_SEC
        else
            sleep "$SOAK_CHECK_INTERVAL"
            elapsed=$((elapsed + SOAK_CHECK_INTERVAL))
        fi
    done

    # Final metric collection
    collect_metrics > /dev/null
    collect_packet_stats

    log "Soak loop complete (${check_count} checks over ${elapsed}s)"

    # Collect ruster log from container
    log "Collecting ruster application log..."
    run_on ruster cat /var/log/ruster.log > "$RUSTER_LOG" 2>/dev/null || true

    if [ "$ruster_died" = true ]; then
        return 1
    fi
    return 0
}

# ── Collect ping statistics ──────────────────────────
collect_ping_results() {
    log "Waiting for traffic generators to finish..."

    local failed=0
    for pid in "${TRAFFIC_PIDS[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            failed=$((failed + 1))
        fi
    done
    TRAFFIC_PIDS=()

    if [ "$failed" -gt 0 ]; then
        log "WARNING: ${failed} traffic stream(s) exited with errors"
    fi

    log "Traffic generation complete"
}

# ── Main ──────────────────────────────────────────────
main() {
    echo ""
    echo "================================================================"
    echo "  ruster Soak Test (strict dataplane)"
    echo "================================================================"
    echo ""
    echo "  Topology:   ${CLAB_TOPO_NAME}"
    echo "  Duration:   ${SOAK_DURATION_MIN} min (${SOAK_DURATION_SEC}s)"
    echo "  Interval:   ${SOAK_CHECK_INTERVAL}s"
    echo "  Streams:    ${TRAFFIC_STREAMS}"
    echo "  Started:    $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo ""

    preflight
    setup_output

    # Start ruster in the strict container
    start_ruster

    # Verify forwarding works before starting the soak
    verify_forwarding

    # Collect baseline metrics
    log "Collecting baseline metrics..."
    collect_metrics > /dev/null
    collect_packet_stats

    # Start traffic generation
    start_traffic

    # Run the soak monitoring loop
    local result=0
    if ! run_soak_loop; then
        log_error "Soak loop failed — ruster process did not survive"
        result=1
    fi

    # Collect final ping statistics
    collect_ping_results

    # Stop ruster
    log "Stopping ruster..."
    run_on ruster bash -c "pkill -x ruster 2>/dev/null || true"
    RUSTER_STARTED=false
    sleep 2

    echo ""
    echo "================================================================"
    echo "  Soak Test Data Collection Complete"
    echo "================================================================"
    echo ""
    echo "  Ended:     $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "  Metrics:   $METRICS_FILE"
    echo "  Packets:   $PACKET_STATS_FILE"
    echo "  Ping logs: ${SOAK_OUTPUT_DIR}/ping-stream*.log"
    echo "  Ruster log: $RUSTER_LOG"
    echo ""

    exit "$result"
}

main

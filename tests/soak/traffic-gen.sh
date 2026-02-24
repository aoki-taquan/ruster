#!/bin/bash
# traffic-gen.sh — Traffic generation for soak tests
#
# Operates in two modes:
#   standalone  — No real packets (v0.1 has no DPDK I/O); keeps process alive
#   containerlab — Sends real traffic via ping/iperf between clab nodes
#
# Usage:
#   bash traffic-gen.sh <mode> <duration_sec>
#
# Modes:
#   standalone    — Sleep-based, no real traffic (default for v0.1)
#   containerlab  — Real traffic via containerlab nodes
#
# Environment variables (containerlab mode):
#   CLAB_TOPO_NAME  — Containerlab topology name (default: ruster-e2e)
#   CLAB_LAN_HOST   — Container name for lan-host (default: clab-${CLAB_TOPO_NAME}-lan-host)
#   CLAB_WAN_HOST   — Container name for wan-host (default: clab-${CLAB_TOPO_NAME}-wan-host)
#   TRAFFIC_STREAMS — Number of parallel ping streams (default: 4)

set -uo pipefail

MODE="${1:-standalone}"
DURATION_SEC="${2:-1800}"

CLAB_TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e}"
CLAB_LAN_HOST="${CLAB_LAN_HOST:-clab-${CLAB_TOPO_NAME}-lan-host}"
CLAB_WAN_HOST="${CLAB_WAN_HOST:-clab-${CLAB_TOPO_NAME}-wan-host}"
TRAFFIC_STREAMS="${TRAFFIC_STREAMS:-4}"

log() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [traffic-gen] $*"
}

# ── Standalone mode ─────────────────────────────────────
# v0.1 has no real packet I/O via DPDK, so standalone mode
# simply keeps the test running for the specified duration.
# This exercises process stability and memory behavior over time.
run_standalone() {
    log "Standalone mode: no real traffic (v0.1 DPDK I/O not active)"
    log "Duration: ${DURATION_SEC}s — monitoring process stability"

    local elapsed=0
    local interval=10

    while [ "$elapsed" -lt "$DURATION_SEC" ]; do
        remaining=$((DURATION_SEC - elapsed))
        if [ "$remaining" -lt "$interval" ]; then
            sleep "$remaining"
            elapsed=$DURATION_SEC
        else
            sleep "$interval"
            elapsed=$((elapsed + interval))
        fi

        # Progress log every 60 seconds
        if [ $((elapsed % 60)) -eq 0 ]; then
            log "Progress: ${elapsed}s / ${DURATION_SEC}s elapsed"
        fi
    done

    log "Standalone traffic generation complete (${DURATION_SEC}s)"
}

# ── Containerlab mode ───────────────────────────────────
# Sends real traffic between lan-host and wan-host via the
# ruster node. Uses parallel ping streams and optionally iperf3.
run_containerlab() {
    log "Containerlab mode: sending real traffic"
    log "Duration: ${DURATION_SEC}s, Streams: ${TRAFFIC_STREAMS}"
    log "LAN host: ${CLAB_LAN_HOST}, WAN host: ${CLAB_WAN_HOST}"

    local pids=()

    # Start parallel ping streams (lan -> wan)
    for i in $(seq 1 "$TRAFFIC_STREAMS"); do
        docker exec "$CLAB_LAN_HOST" \
            ping -q -i 0.1 -w "$DURATION_SEC" 10.0.0.100 \
            > /dev/null 2>&1 &
        pids+=($!)
        log "Started ping stream ${i} (PID: ${pids[-1]})"
    done

    # Optionally run iperf3 if available in containers
    if docker exec "$CLAB_WAN_HOST" which iperf3 > /dev/null 2>&1; then
        log "iperf3 available — starting bandwidth test"

        # Start iperf3 server on wan-host
        docker exec -d "$CLAB_WAN_HOST" iperf3 -s -1

        # Give server time to start
        sleep 2

        # Start iperf3 client on lan-host
        docker exec "$CLAB_LAN_HOST" \
            iperf3 -c 10.0.0.100 -t "$DURATION_SEC" -P 2 \
            > /dev/null 2>&1 &
        pids+=($!)
        log "Started iperf3 client (PID: ${pids[-1]})"
    else
        log "iperf3 not available in containers — using ping only"
    fi

    # Wait for all traffic generators to finish
    local failed=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            failed=$((failed + 1))
        fi
    done

    if [ "$failed" -gt 0 ]; then
        log "WARNING: ${failed} traffic stream(s) exited with errors"
    fi

    log "Containerlab traffic generation complete (${DURATION_SEC}s)"
}

# ── Main ────────────────────────────────────────────────
case "$MODE" in
    standalone)
        run_standalone
        ;;
    containerlab)
        run_containerlab
        ;;
    *)
        echo "ERROR: Unknown mode '${MODE}'" >&2
        echo "Usage: $0 <standalone|containerlab> <duration_sec>" >&2
        exit 1
        ;;
esac

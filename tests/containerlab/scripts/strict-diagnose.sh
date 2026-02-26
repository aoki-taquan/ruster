#!/bin/bash
# strict-diagnose.sh — Collect diagnostic logs from all strict topology nodes
#
# Gathers networking state, ruster logs, and process information from all
# nodes in the strict topology. Output is saved to a timestamped directory.
#
# Environment variables:
#   CLAB_TOPO_NAME  — Containerlab topology name (default: ruster-e2e-strict)
#   STRICT_LOG_DIR  — Override output directory (default: /tmp/ruster-strict-diag-<timestamp>)
#
# Usage:
#   bash scripts/strict-diagnose.sh
#
# Output:
#   Diagnostic files are saved to $STRICT_LOG_DIR/ with one file per node
#   plus a summary file.

set -uo pipefail

TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e-strict}"
PREFIX="clab-${TOPO_NAME}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_DIR="${STRICT_LOG_DIR:-/tmp/ruster-strict-diag-${TIMESTAMP}}"

# ── Helpers ───────────────────────────────────────────

info()  { echo "[strict-diagnose] $*"; }
error() { echo "[strict-diagnose] ERROR: $*" >&2; }

run_on() {
    local node="$1"; shift
    docker exec "${PREFIX}-${node}" "$@" 2>&1 || echo "(command failed)"
}

# ── Create output directory ──────────────────────────

mkdir -p "$LOG_DIR"
info "Collecting diagnostics to: ${LOG_DIR}"

# ── Collect from each node ───────────────────────────

NODES=("ruster" "lan-host" "wan-host")

for node in "${NODES[@]}"; do
    NODE_LOG="${LOG_DIR}/${node}.log"
    info "Collecting from ${node}..."

    {
        echo "========================================"
        echo "  Diagnostics: ${node}"
        echo "  Timestamp: $(date -Iseconds)"
        echo "  Container: ${PREFIX}-${node}"
        echo "========================================"
        echo ""

        echo "--- Container state ---"
        docker inspect --format '{{.State.Status}}' "${PREFIX}-${node}" 2>&1 || echo "(not found)"
        echo ""

        echo "--- sysctl net.ipv4.ip_forward ---"
        run_on "$node" cat /proc/sys/net/ipv4/ip_forward
        echo ""

        echo "--- ip addr show ---"
        run_on "$node" ip addr show
        echo ""

        echo "--- ip route show ---"
        run_on "$node" ip route show
        echo ""

        echo "--- ip neigh show (ARP table) ---"
        run_on "$node" ip neigh show
        echo ""

        echo "--- iptables -L -n -v ---"
        run_on "$node" iptables -L -n -v
        echo ""

        echo "--- iptables -t nat -L -n -v ---"
        run_on "$node" iptables -t nat -L -n -v
        echo ""

        echo "--- Process list ---"
        run_on "$node" ps aux
        echo ""

    } > "$NODE_LOG" 2>&1

    info "  Saved: ${NODE_LOG}"
done

# ── Collect ruster-specific logs ─────────────────────

RUSTER_LOG="${LOG_DIR}/ruster-app.log"
info "Collecting ruster application log..."

{
    echo "========================================"
    echo "  ruster application log"
    echo "  Timestamp: $(date -Iseconds)"
    echo "========================================"
    echo ""
    run_on ruster cat /var/log/ruster.log
} > "$RUSTER_LOG" 2>&1

info "  Saved: ${RUSTER_LOG}"

# ── Collect docker logs ──────────────────────────────

for node in "${NODES[@]}"; do
    DOCKER_LOG="${LOG_DIR}/${node}-docker.log"
    docker logs "${PREFIX}-${node}" > "$DOCKER_LOG" 2>&1 || true
    info "  Docker logs: ${DOCKER_LOG}"
done

# ── Collect docker ps ────────────────────────────────

DOCKER_PS="${LOG_DIR}/docker-ps.txt"
docker ps -a > "$DOCKER_PS" 2>&1 || true
info "  Docker ps: ${DOCKER_PS}"

# ── Summary ──────────────────────────────────────────

SUMMARY="${LOG_DIR}/summary.txt"
{
    echo "========================================"
    echo "  Strict Diagnostic Summary"
    echo "  Timestamp: $(date -Iseconds)"
    echo "  Topology: ${TOPO_NAME}"
    echo "========================================"
    echo ""

    echo "--- ip_forward status ---"
    for node in "${NODES[@]}"; do
        fwd=$(run_on "$node" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
        echo "  ${node}: ip_forward=${fwd}"
    done
    echo ""

    echo "--- ruster process ---"
    if docker exec "${PREFIX}-ruster" pgrep -x ruster > /dev/null 2>&1; then
        pid=$(docker exec "${PREFIX}-ruster" pgrep -x ruster 2>/dev/null)
        echo "  ruster is running (PID: ${pid})"
    else
        echo "  ruster is NOT running"
    fi
    echo ""

    echo "--- Routing tables ---"
    for node in "${NODES[@]}"; do
        echo "  [${node}]"
        run_on "$node" ip route show 2>/dev/null | sed 's/^/    /'
        echo ""
    done

    echo "--- ARP tables ---"
    for node in "${NODES[@]}"; do
        echo "  [${node}]"
        run_on "$node" ip neigh show 2>/dev/null | sed 's/^/    /'
        echo ""
    done

} > "$SUMMARY" 2>&1

info "  Summary: ${SUMMARY}"
info ""
info "Diagnostic collection complete."
info "Files saved to: ${LOG_DIR}"
ls -la "$LOG_DIR" | sed 's/^/  /'

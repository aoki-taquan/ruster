#!/bin/bash
# check-ruster.sh — Pre-flight check: verify ruster process is running
#
# Validates that:
#   1. The ruster container accepts exec commands (readiness)
#   2. The ruster process is alive
#   3. The ruster log shows successful startup messages
#   4. Kernel ip_forward=0
#   5. ARP warmup completes (lan-host and wan-host can reach ruster)
#
# Exit codes:
#   0 — ruster is running and healthy
#   1 — ruster is NOT running or failed to start

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e}"
PREFIX="clab-${TOPO_NAME}"
CONTAINER="${PREFIX}-ruster"
MAX_RETRIES="${CHECK_RUSTER_RETRIES:-20}"
RETRY_INTERVAL="${CHECK_RUSTER_INTERVAL:-2}"

# ── Helpers ───────────────────────────────────────────

info()  { echo "[check-ruster] $*"; }
error() { echo "[check-ruster] ERROR: $*" >&2; }

dump_diagnostics() {
    echo ""
    error "=== Diagnostic information ==="
    echo ""

    echo "--- Container status ---"
    docker inspect --format '{{.State.Status}}' "${CONTAINER}" 2>&1 || true
    echo ""

    echo "--- Process list inside container ---"
    docker exec "${CONTAINER}" ps aux 2>&1 || true
    echo ""

    echo "--- ruster log (/var/log/ruster.log) ---"
    docker exec "${CONTAINER}" cat /var/log/ruster.log 2>&1 || echo "(log file not found or empty)"
    echo ""

    echo "--- Container stdout/stderr (docker logs) ---"
    docker logs "${CONTAINER}" 2>&1 | tail -50 || true
    echo ""
}

# ── Step 1: Wait for containers to be ready ──────────

info "Waiting for all containers to accept exec commands..."
if ! wait_all_containers_ready "$PREFIX" ruster lan-host wan-host; then
    error "FAILED: containers did not become ready"
    exit 1
fi

# ── Step 2: Wait for ruster process ──────────────────

info "Checking ruster process in container: ${CONTAINER}"
info "Will retry up to ${MAX_RETRIES} times (interval: ${RETRY_INTERVAL}s)"

RUSTER_FOUND=false
for attempt in $(seq 1 "${MAX_RETRIES}"); do
    info "Attempt ${attempt}/${MAX_RETRIES}: checking ruster process..."

    if docker exec "${CONTAINER}" pgrep -x ruster > /dev/null 2>&1; then
        RUSTER_PID=$(docker exec "${CONTAINER}" pgrep -x ruster 2>/dev/null)
        info "ruster process found (PID: ${RUSTER_PID})"
        RUSTER_FOUND=true
        break
    fi

    info "ruster process not found yet (waiting...)"
    sleep "${RETRY_INTERVAL}"
done

if [ "$RUSTER_FOUND" = false ]; then
    error "FAILED: ruster process is NOT running after ${MAX_RETRIES} attempts"
    dump_diagnostics
    exit 1
fi

# ── Step 3: Verify startup log messages ──────────────

info "Verifying ruster startup log..."

LOG_READY=false
for attempt in $(seq 1 10); do
    if docker exec "${CONTAINER}" test -f /var/log/ruster.log 2>/dev/null; then
        LOG_CONTENT=$(docker exec "${CONTAINER}" cat /var/log/ruster.log 2>/dev/null || echo "")
        if echo "${LOG_CONTENT}" | grep -q "running"; then
            info "Run-loop confirmation found in log"
            LOG_READY=true
            break
        fi
    fi
    info "Waiting for ruster run-loop to start (attempt ${attempt}/10)..."
    sleep 1
done

if [ "$LOG_READY" = false ]; then
    error "ruster run-loop not confirmed after 10s — process may be stuck"
    dump_diagnostics
    exit 1
fi

# ── Step 4: Verify kernel forwarding is disabled ─────

KERNEL_FWD=$(docker exec "${CONTAINER}" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
if [ "${KERNEL_FWD}" = "0" ]; then
    info "Kernel ip_forward=0 (ruster handles forwarding)"
else
    error "kernel ip_forward=${KERNEL_FWD} — expected 0; E2E tests may be invalid"
    exit 1
fi

# ── Step 5: ARP warmup ──────────────────────────────

arp_warmup "$PREFIX"

echo ""
info "PASSED: ruster is running in ${CONTAINER} with kernel forwarding disabled"
exit 0

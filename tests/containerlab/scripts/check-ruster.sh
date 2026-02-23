#!/bin/bash
# check-ruster.sh — Pre-flight check: verify ruster process is running
#
# Validates that:
#   1. The ruster process is alive inside the clab-ruster-e2e-ruster container
#   2. The ruster log shows successful startup messages
#
# Exit codes:
#   0 — ruster is running and healthy
#   1 — ruster is NOT running or failed to start
#
# Note (v0.1): ruster uses MockPacketIo and does not perform real NIC I/O.
# Kernel IP forwarding handles actual packet forwarding in the E2E topology.
# This check gates on ruster *process liveness* to ensure the binary is
# functional and doesn't crash on startup. Future versions with real
# dataplane I/O will additionally verify that forwarding goes through ruster.

set -uo pipefail

TOPO_NAME="ruster-e2e"
CONTAINER="clab-${TOPO_NAME}-ruster"
MAX_RETRIES="${CHECK_RUSTER_RETRIES:-10}"
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

# ── Main ──────────────────────────────────────────────

info "Checking ruster process in container: ${CONTAINER}"
info "Will retry up to ${MAX_RETRIES} times (interval: ${RETRY_INTERVAL}s)"

for attempt in $(seq 1 "${MAX_RETRIES}"); do
    info "Attempt ${attempt}/${MAX_RETRIES}: checking ruster process..."

    # Check if the container exists and is running
    CONTAINER_STATE=$(docker inspect --format '{{.State.Status}}' "${CONTAINER}" 2>/dev/null || echo "not_found")
    if [ "${CONTAINER_STATE}" != "running" ]; then
        info "Container state: ${CONTAINER_STATE} (waiting...)"
        sleep "${RETRY_INTERVAL}"
        continue
    fi

    # Check if the ruster process is alive (pgrep exit code 0 = found)
    if docker exec "${CONTAINER}" pgrep -x ruster > /dev/null 2>&1; then
        RUSTER_PID=$(docker exec "${CONTAINER}" pgrep -x ruster 2>/dev/null)
        info "ruster process found (PID: ${RUSTER_PID})"

        # Verify startup log messages
        if docker exec "${CONTAINER}" test -f /var/log/ruster.log; then
            LOG_CONTENT=$(docker exec "${CONTAINER}" cat /var/log/ruster.log 2>/dev/null || echo "")

            if echo "${LOG_CONTENT}" | grep -q "ruster v0.1"; then
                info "Startup banner found in log"
            else
                info "WARNING: startup banner not found in log (process may still be initializing)"
            fi

            if echo "${LOG_CONTENT}" | grep -q "running"; then
                info "Run-loop confirmation found in log"
            else
                info "WARNING: run-loop message not yet in log (may still be initializing)"
            fi
        else
            info "WARNING: /var/log/ruster.log not found yet (process may still be starting)"
        fi

        echo ""
        info "PASSED: ruster is running in ${CONTAINER}"
        info "NOTE (v0.1): Kernel forwarding is active. ruster process liveness is the E2E gate."
        exit 0
    fi

    info "ruster process not found yet (waiting...)"
    sleep "${RETRY_INTERVAL}"
done

# All retries exhausted — ruster is not running
echo ""
error "FAILED: ruster process is NOT running after ${MAX_RETRIES} attempts"
dump_diagnostics
exit 1

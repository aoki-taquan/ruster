#!/bin/bash
# strict-test.sh — Strict E2E test: verify ruster is the sole forwarding entity
#
# Three-phase test:
#   Phase 1: WITHOUT ruster running -> ping MUST FAIL (proves no kernel bypass)
#   Phase 2: START ruster           -> ping MUST SUCCEED (ruster forwarding works)
#   Phase 3: STOP ruster            -> ping MUST FAIL (proves ruster was forwarding)
#
# Each phase with clear pass/fail output.
# On failure: calls strict-diagnose.sh to collect diagnostic logs.
#
# Environment variables:
#   CLAB_TOPO_NAME  — Containerlab topology name (default: ruster-e2e-strict)
#   STRICT_PING_COUNT   — Number of pings per test (default: 3)
#   STRICT_PING_TIMEOUT — Ping timeout in seconds (default: 3)
#   STRICT_SETTLE_TIME  — Seconds to wait after starting/stopping ruster (default: 5)
#
# Usage:
#   bash scripts/strict-test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/e2e-helpers.sh"

TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e-strict}"
PREFIX="clab-${TOPO_NAME}"
PING_COUNT="${STRICT_PING_COUNT:-3}"
PING_TIMEOUT="${STRICT_PING_TIMEOUT:-3}"
SETTLE_TIME="${STRICT_SETTLE_TIME:-5}"

PASS=0
FAIL=0
ERRORS=""

# ── Helpers ───────────────────────────────────────────

info()  { echo "[strict-test] $*"; }
error() { echo "[strict-test] ERROR: $*" >&2; }

run_on() {
    local node="$1"; shift
    docker exec "${PREFIX}-${node}" "$@"
}

report() {
    local name="$1" result="$2"
    if [ "$result" = "PASS" ]; then
        PASS=$((PASS + 1))
        echo "  [PASS] ${name}"
    else
        FAIL=$((FAIL + 1))
        ERRORS="${ERRORS}  - ${name}\n"
        echo "  [FAIL] ${name}"
    fi
}

collect_diagnostics() {
    info "Collecting diagnostics..."
    if [ -f "${SCRIPT_DIR}/strict-diagnose.sh" ]; then
        bash "${SCRIPT_DIR}/strict-diagnose.sh" || true
    else
        error "strict-diagnose.sh not found; skipping diagnostics"
    fi
}

# Ping from lan-host to wan-host (cross-subnet, requires forwarding)
ping_through_ruster() {
    run_on lan-host ping -c "$PING_COUNT" -W "$PING_TIMEOUT" 10.0.0.100 > /dev/null 2>&1
}

# ── Pre-flight checks ────────────────────────────────

info "================================================================"
info "  Strict E2E Test"
info "  Topology: ${TOPO_NAME}"
info "================================================================"
info ""

# Wait for all containers to be ready (accept exec commands)
if ! wait_all_containers_ready "$PREFIX" ruster lan-host wan-host; then
    error "Containers failed readiness check. Cannot proceed."
    exit 1
fi

# Run strict setup to harden the topology
info "Running strict setup..."
if ! bash "${SCRIPT_DIR}/strict-setup.sh"; then
    error "Strict setup failed. Cannot proceed."
    collect_diagnostics
    exit 1
fi

# ── Phase 1: WITHOUT ruster — ping MUST FAIL ────────

info ""
info "================================================================"
info "  Phase 1: Ruster NOT running — ping MUST FAIL"
info "================================================================"
info ""

# Ensure ruster is NOT running
run_on ruster bash -c "pkill -x ruster 2>/dev/null || true"

# Wait for ruster to stop with retry loop
RUSTER_STOPPED=false
for i in $(seq 1 10); do
    if ! run_on ruster pgrep -x ruster > /dev/null 2>&1; then
        RUSTER_STOPPED=true
        break
    fi
    if [ "$i" -eq 8 ]; then
        info "SIGTERM not effective, sending SIGKILL..."
        run_on ruster bash -c "pkill -9 -x ruster 2>/dev/null || true"
    fi
    sleep 0.5
done

if [ "$RUSTER_STOPPED" = true ]; then
    report "phase1-ruster-stopped" "PASS"
else
    error "ruster is still running after pkill + SIGKILL — cannot validate strict mode"
    report "phase1-ruster-stopped" "FAIL"
    collect_diagnostics
fi

# Verify kernel forwarding is disabled
KERNEL_FWD=$(run_on ruster cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
if [ "$KERNEL_FWD" = "0" ]; then
    report "phase1-kernel-fwd-disabled" "PASS"
else
    error "kernel ip_forward=${KERNEL_FWD} (expected 0)"
    report "phase1-kernel-fwd-disabled" "FAIL"
fi

# Ping MUST fail (no forwarding path exists)
info "Testing cross-subnet ping (should FAIL)..."
if ping_through_ruster; then
    error "Ping SUCCEEDED without ruster — kernel bypass detected!"
    report "phase1-no-bypass" "FAIL"
    collect_diagnostics
else
    info "Ping failed as expected (no forwarding path)."
    report "phase1-no-bypass" "PASS"
fi

# ── Phase 2: START ruster — ping MUST SUCCEED ───────

info ""
info "================================================================"
info "  Phase 2: Start ruster — ping MUST SUCCEED"
info "================================================================"
info ""

# Start ruster in background
info "Starting ruster..."
run_on ruster bash -c "nohup /usr/local/bin/ruster --config /etc/ruster/router.toml > /var/log/ruster.log 2>&1 &"

# Wait for ruster to initialize — check process + run-loop log
RUSTER_STARTED=false
for i in $(seq 1 20); do
    if run_on ruster pgrep -x ruster > /dev/null 2>&1; then
        LOG=$(run_on ruster cat /var/log/ruster.log 2>/dev/null || echo "")
        if echo "$LOG" | grep -q "running"; then
            RUSTER_PID=$(run_on ruster pgrep -x ruster 2>/dev/null)
            info "ruster is running (PID: ${RUSTER_PID}), run-loop confirmed"
            RUSTER_STARTED=true
            break
        fi
    fi
    sleep 1
done

if [ "$RUSTER_STARTED" = true ]; then
    report "phase2-ruster-started" "PASS"
else
    error "ruster failed to start or run-loop not confirmed after 20s"
    info "ruster log:"
    run_on ruster cat /var/log/ruster.log 2>/dev/null | sed 's/^/    /' || true
    report "phase2-ruster-started" "FAIL"
    collect_diagnostics
fi

# ARP warmup: resolve ruster's MAC on client/server
arp_warmup "$PREFIX"

# Ping MUST succeed (ruster is forwarding)
info "Testing cross-subnet ping (should SUCCEED)..."
if ping_through_ruster; then
    info "Ping succeeded — ruster is forwarding traffic."
    report "phase2-forwarding-works" "PASS"
else
    error "Ping FAILED with ruster running"
    info "Diagnostic: ping verbose output:"
    run_on lan-host ping -c "$PING_COUNT" -W "$PING_TIMEOUT" 10.0.0.100 2>&1 | sed 's/^/    /' || true
    report "phase2-forwarding-works" "FAIL"
    collect_diagnostics
fi

# Verify kernel forwarding is still disabled (ruster does forwarding, not kernel)
KERNEL_FWD=$(run_on ruster cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
if [ "$KERNEL_FWD" = "0" ]; then
    report "phase2-kernel-fwd-still-disabled" "PASS"
else
    error "kernel ip_forward=${KERNEL_FWD} — ruster may have enabled kernel forwarding"
    report "phase2-kernel-fwd-still-disabled" "FAIL"
fi

# ── Phase 3: STOP ruster — ping MUST FAIL ───────────

info ""
info "================================================================"
info "  Phase 3: Stop ruster — ping MUST FAIL"
info "================================================================"
info ""

# Stop ruster
info "Stopping ruster..."
run_on ruster bash -c "pkill -x ruster 2>/dev/null || true"

# Wait for ruster to stop with retry loop
PHASE3_STOPPED=false
for i in $(seq 1 10); do
    if ! run_on ruster pgrep -x ruster > /dev/null 2>&1; then
        PHASE3_STOPPED=true
        break
    fi
    if [ "$i" -eq 8 ]; then
        info "SIGTERM not effective, sending SIGKILL..."
        run_on ruster bash -c "pkill -9 -x ruster 2>/dev/null || true"
    fi
    sleep 0.5
done

if [ "$PHASE3_STOPPED" = true ]; then
    info "ruster stopped successfully."
    report "phase3-ruster-stopped" "PASS"
else
    error "ruster is still running after pkill + SIGKILL"
    report "phase3-ruster-stopped" "FAIL"
fi

# Ping MUST fail again (no forwarding path exists)
info "Testing cross-subnet ping (should FAIL)..."
if ping_through_ruster; then
    error "Ping SUCCEEDED without ruster — indicates kernel bypass or stale state!"
    report "phase3-no-bypass" "FAIL"
    collect_diagnostics
else
    info "Ping failed as expected (forwarding stopped with ruster)."
    report "phase3-no-bypass" "PASS"
fi

# ── Summary ──────────────────────────────────────────

TOTAL=$((PASS + FAIL))

info ""
info "================================================================"
info "  Strict E2E Test Summary"
info "================================================================"
info ""
echo "  Phase 1 (no ruster):   ping must fail   — validates no kernel bypass"
echo "  Phase 2 (ruster up):   ping must succeed — validates ruster forwarding"
echo "  Phase 3 (ruster down): ping must fail   — validates ruster was forwarding"
echo ""
echo "  Tests: ${TOTAL} ran, ${PASS} passed, ${FAIL} failed"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "  Failed tests:"
    echo -e "$ERRORS"
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi

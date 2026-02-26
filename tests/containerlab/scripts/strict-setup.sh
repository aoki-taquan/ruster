#!/bin/bash
# strict-setup.sh — Post-deploy hardening for the strict E2E topology
#
# Ensures that kernel IP forwarding is disabled on all nodes and that
# no bypass routes exist. This script is idempotent and can be run
# multiple times safely.
#
# Environment variables:
#   CLAB_TOPO_NAME  — Containerlab topology name (default: ruster-e2e-strict)
#
# Usage:
#   bash scripts/strict-setup.sh

set -euo pipefail

TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e-strict}"
PREFIX="clab-${TOPO_NAME}"

# ── Helpers ───────────────────────────────────────────

info()  { echo "[strict-setup] $*"; }
error() { echo "[strict-setup] ERROR: $*" >&2; }

run_on() {
    local node="$1"; shift
    docker exec "${PREFIX}-${node}" "$@"
}

# ── Step 1: Disable kernel forwarding on all nodes ───

info "Disabling kernel ip_forward on all nodes..."

for node in ruster lan-host wan-host; do
    current=$(run_on "$node" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
    if [ "$current" = "0" ]; then
        info "  ${node}: ip_forward already 0"
    else
        run_on "$node" sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1
        info "  ${node}: ip_forward set to 0 (was ${current})"
    fi
done

# ── Step 2: Flush kernel bypass routes on ruster ─────

info "Flushing kernel bypass routes on ruster..."

# Remove any default routes on ruster that the kernel might use
run_on ruster bash -c "ip route del default 2>/dev/null || true"
# Flush boot/static protocol routes (keep connected subnets)
run_on ruster bash -c "ip route flush proto boot 2>/dev/null || true"
run_on ruster bash -c "ip route flush proto static 2>/dev/null || true"

info "  ruster routes after flush:"
run_on ruster ip route show 2>/dev/null | sed 's/^/    /'

# ── Step 3: Verify client/server routing ─────────────

info "Verifying client/server routes point to ruster as gateway..."

# lan-host should only have: 192.168.1.0/24 dev eth1 + default via 192.168.1.1
LAN_DEFAULT=$(run_on lan-host ip route show default 2>/dev/null || echo "")
if echo "$LAN_DEFAULT" | grep -q "192.168.1.1"; then
    info "  lan-host: default via 192.168.1.1 (OK)"
else
    info "  lan-host: setting default route via 192.168.1.1"
    run_on lan-host bash -c "ip route del default 2>/dev/null || true"
    run_on lan-host ip route add default via 192.168.1.1
fi

# wan-host should only have: 10.0.0.0/24 dev eth1 + default via 10.0.0.1
WAN_DEFAULT=$(run_on wan-host ip route show default 2>/dev/null || echo "")
if echo "$WAN_DEFAULT" | grep -q "10.0.0.1"; then
    info "  wan-host: default via 10.0.0.1 (OK)"
else
    info "  wan-host: setting default route via 10.0.0.1"
    run_on wan-host bash -c "ip route del default 2>/dev/null || true"
    run_on wan-host ip route add default via 10.0.0.1
fi

# ── Step 4: Verify no bypass paths ──────────────────

info "Verifying no bypass paths exist..."

BYPASS_FOUND=false

# Check that ruster has no default route (it should only forward via dataplane)
if run_on ruster ip route show default 2>/dev/null | grep -q "default"; then
    error "ruster has a kernel default route — this is a bypass path!"
    run_on ruster ip route show default 2>/dev/null | sed 's/^/    /'
    BYPASS_FOUND=true
fi

# Check kernel forwarding is truly disabled
for node in ruster lan-host wan-host; do
    fwd=$(run_on "$node" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
    if [ "$fwd" != "0" ]; then
        error "${node}: ip_forward=${fwd} (expected 0) — bypass risk!"
        BYPASS_FOUND=true
    fi
done

if [ "$BYPASS_FOUND" = true ]; then
    error "Bypass paths detected. Strict mode is not properly configured."
    exit 1
fi

info ""
info "Strict setup complete. All bypass paths eliminated."
info "  - ip_forward=0 on all nodes"
info "  - No kernel default route on ruster"
info "  - Client/server routes point to ruster as gateway"
exit 0

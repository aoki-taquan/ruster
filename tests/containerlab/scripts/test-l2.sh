#!/bin/bash
# test-l2.sh — L2 bridging / ARP resolution tests
#
# Verifies:
#   1. ARP resolution between lan-host and ruster
#   2. MAC address learning (ARP table populated)

set -euo pipefail

TOPO_NAME="ruster-e2e"
PREFIX="clab-${TOPO_NAME}"
PASS=0
FAIL=0
ERRORS=""

# ── Helpers ───────────────────────────────────────────

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

# ── Tests ─────────────────────────────────────────────

echo "=== L2 Tests ==="

# Test 1: ARP resolution — lan-host can resolve ruster (192.168.1.1)
echo ""
echo "-- Test 1: ARP resolution (lan-host -> ruster) --"
if run_on lan-host ping -c 2 -W 3 192.168.1.1 > /dev/null 2>&1; then
    # Check ARP table for ruster's IP
    if run_on lan-host ip neigh show 192.168.1.1 2>/dev/null | grep -q REACHABLE\\\|STALE\\\|DELAY; then
        report "arp-lan-to-ruster" "PASS"
    else
        echo "  Diagnostic: ARP table on lan-host:"
        run_on lan-host ip neigh show 2>/dev/null || true
        report "arp-lan-to-ruster" "FAIL"
    fi
else
    echo "  Diagnostic: ping to 192.168.1.1 failed"
    echo "  Diagnostic: interfaces on lan-host:"
    run_on lan-host ip addr show 2>/dev/null || true
    echo "  Diagnostic: routes on lan-host:"
    run_on lan-host ip route show 2>/dev/null || true
    report "arp-lan-to-ruster" "FAIL"
fi

# Test 2: ARP resolution — ruster can resolve lan-host (192.168.1.100)
echo ""
echo "-- Test 2: ARP resolution (ruster -> lan-host) --"
if run_on ruster ping -c 2 -W 3 192.168.1.100 > /dev/null 2>&1; then
    if run_on ruster ip neigh show 192.168.1.100 2>/dev/null | grep -q REACHABLE\\\|STALE\\\|DELAY; then
        report "arp-ruster-to-lan" "PASS"
    else
        echo "  Diagnostic: ARP table on ruster:"
        run_on ruster ip neigh show 2>/dev/null || true
        report "arp-ruster-to-lan" "FAIL"
    fi
else
    echo "  Diagnostic: ping to 192.168.1.100 failed"
    run_on ruster ip addr show 2>/dev/null || true
    report "arp-ruster-to-lan" "FAIL"
fi

# Test 3: ARP resolution — ruster can resolve wan-host (10.0.0.100)
echo ""
echo "-- Test 3: ARP resolution (ruster -> wan-host) --"
if run_on ruster ping -c 2 -W 3 10.0.0.100 > /dev/null 2>&1; then
    if run_on ruster ip neigh show 10.0.0.100 2>/dev/null | grep -q REACHABLE\\\|STALE\\\|DELAY; then
        report "arp-ruster-to-wan" "PASS"
    else
        echo "  Diagnostic: ARP table on ruster:"
        run_on ruster ip neigh show 2>/dev/null || true
        report "arp-ruster-to-wan" "FAIL"
    fi
else
    echo "  Diagnostic: ping to 10.0.0.100 failed"
    run_on ruster ip addr show 2>/dev/null || true
    report "arp-ruster-to-wan" "FAIL"
fi

# Test 4: MAC address learning — verify ARP table entries have MAC addresses
echo ""
echo "-- Test 4: MAC address learning verification --"
MAC_ENTRY=$(run_on lan-host ip neigh show 192.168.1.1 2>/dev/null || true)
if echo "$MAC_ENTRY" | grep -qE '([0-9a-f]{2}:){5}[0-9a-f]{2}'; then
    report "mac-learning" "PASS"
else
    echo "  Diagnostic: no MAC in ARP entry:"
    echo "  ${MAC_ENTRY}"
    report "mac-learning" "FAIL"
fi

# ── Summary ───────────────────────────────────────────

echo ""
echo "--- L2 Summary: ${PASS} passed, ${FAIL} failed ---"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed tests:"
    echo -e "$ERRORS"
    exit 1
fi
exit 0

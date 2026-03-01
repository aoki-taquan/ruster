#!/bin/bash
# test-fw.sh — Firewall tests
#
# Verifies:
#   1. Allowed traffic: LAN -> WAN forward is permitted
#   2. Allowed traffic: LAN -> ruster ICMP input is permitted
#   3. Blocked traffic: WAN -> ruster new connections are dropped
#   4. Blocked traffic: WAN -> LAN unsolicited forward is dropped
#
# Quality gate: tests that cannot verify expected behavior report FAIL,
# never silently PASS. See issue #134.

set -euo pipefail

TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e}"
PREFIX="clab-${TOPO_NAME}"
PASS=0
FAIL=0
SKIP=0
ERRORS=""

# -- Helpers ---------------------------------------------------

run_on() {
    local node="$1"; shift
    docker exec "${PREFIX}-${node}" "$@"
}

report() {
    local name="$1" result="$2"
    case "$result" in
        PASS)
            PASS=$((PASS + 1))
            echo "  [PASS] ${name}"
            ;;
        FAIL)
            FAIL=$((FAIL + 1))
            ERRORS="${ERRORS}  - ${name}\n"
            echo "  [FAIL] ${name}"
            ;;
        SKIP)
            SKIP=$((SKIP + 1))
            echo "  [SKIP] ${name}"
            ;;
        *)
            echo "  [ERROR] unknown result '${result}' for ${name}"
            FAIL=$((FAIL + 1))
            ERRORS="${ERRORS}  - ${name} (bad result)\n"
            ;;
    esac
}

# -- Tests -----------------------------------------------------

echo "=== Firewall Tests ==="

# Test 1: Allowed -- LAN to WAN forwarding (should pass per rule allow-lan-to-wan)
echo ""
echo "-- Test 1: Allowed (lan-host -> wan-host forward) --"
if run_on lan-host ping -c 3 -W 5 10.0.0.100 > /dev/null 2>&1; then
    report "fw-allow-lan-to-wan" "PASS"
else
    echo "  Diagnostic: ping output:"
    run_on lan-host ping -c 3 -W 5 10.0.0.100 2>&1 || true
    echo "  Diagnostic: iptables FORWARD on ruster:"
    run_on ruster iptables -L FORWARD -n -v 2>/dev/null || true
    report "fw-allow-lan-to-wan" "FAIL"
fi

# Test 2: Allowed -- LAN ICMP to ruster input (should pass per rule allow-lan-input-icmp)
echo ""
echo "-- Test 2: Allowed (lan-host -> ruster ICMP input) --"
if run_on lan-host ping -c 3 -W 3 192.168.1.1 > /dev/null 2>&1; then
    report "fw-allow-lan-icmp-input" "PASS"
else
    echo "  Diagnostic: ping output:"
    run_on lan-host ping -c 3 -W 3 192.168.1.1 2>&1 || true
    echo "  Diagnostic: iptables INPUT on ruster:"
    run_on ruster iptables -L INPUT -n -v 2>/dev/null || true
    report "fw-allow-lan-icmp-input" "FAIL"
fi

# Test 3: Blocked -- WAN new connections to ruster input (should be dropped)
#   When the firewall is active, ping from wan-host to ruster's WAN interface
#   should be DROPPED. A dropped ping means the firewall is working correctly.
#
#   AF_PACKET backend cannot intercept packets destined to the kernel's own
#   IP stack, so iptables INPUT DROP on eth2 mirrors ruster's firewall policy
#   at the kernel level. See topology.yml exec section.
echo ""
echo "-- Test 3: Blocked (wan-host -> ruster new input) --"

if run_on wan-host ping -c 2 -W 3 10.0.0.1 > /dev/null 2>&1; then
    echo "  Ping from WAN to ruster succeeded -- firewall is NOT blocking."
    echo "  Expected: ping should be dropped by rule 'block-wan-input'."
    report "fw-block-wan-input" "FAIL"
else
    echo "  Ping from WAN to ruster timed out/refused -- firewall is blocking."
    report "fw-block-wan-input" "PASS"
fi

# Test 4: Blocked -- WAN unsolicited forward to LAN (should be dropped)
#   With the firewall active, unsolicited packets from WAN to LAN should be
#   dropped (default_forward=drop). The allow-wan-to-lan-reply rule only
#   permits established/related traffic, not new connections.
echo ""
echo "-- Test 4: Blocked (wan-host -> lan-host unsolicited forward) --"

# Verify the route exists so we know the test is meaningful.
# Accept either an explicit route to 192.168.1.0/24 or a default route via ruster.
WAN_ROUTES=$(run_on wan-host ip route show 2>/dev/null || true)
if ! echo "$WAN_ROUTES" | grep -qE "192.168.1.0/24|default via 10.0.0.1"; then
    echo "  Diagnostic: no route to 192.168.1.0/24 on wan-host."
    echo "  Cannot test WAN->LAN forwarding without a route."
    echo "  Routes:"
    echo "$WAN_ROUTES" | sed 's/^/    /'
    report "fw-block-wan-to-lan" "FAIL"
else
    echo "  Route to LAN exists on wan-host: OK"
    if run_on wan-host ping -c 2 -W 3 192.168.1.100 > /dev/null 2>&1; then
        echo "  Ping from WAN to LAN succeeded -- firewall is NOT blocking."
        echo "  Expected: forward should be dropped by default_forward=drop."
        report "fw-block-wan-to-lan" "FAIL"
    else
        echo "  Ping from WAN to LAN timed out/refused -- firewall is blocking."
        report "fw-block-wan-to-lan" "PASS"
    fi
fi

# -- Summary ---------------------------------------------------

echo ""
echo "--- Firewall Summary: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ---"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed tests:"
    echo -e "$ERRORS"
    exit 1
fi
exit 0

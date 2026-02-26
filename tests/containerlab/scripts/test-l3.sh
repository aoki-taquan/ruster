#!/bin/bash
# test-l3.sh — L3 routing tests
#
# Verifies:
#   1. Local delivery: lan-host can ping ruster (192.168.1.1)
#   2. Routing: lan-host can ping wan-host (10.0.0.100) through ruster
#   3. Routing: wan-host can ping lan-host (192.168.1.100) through ruster
#   4. Traceroute shows ruster as intermediate hop

set -euo pipefail

TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e}"
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

echo "=== L3 Tests ==="

# Test 1: Local delivery — lan-host -> ruster LAN interface
echo ""
echo "-- Test 1: Local delivery (lan-host -> ruster 192.168.1.1) --"
if run_on lan-host ping -c 3 -W 3 192.168.1.1 > /dev/null 2>&1; then
    report "local-delivery-lan" "PASS"
else
    echo "  Diagnostic: ping output:"
    run_on lan-host ping -c 3 -W 3 192.168.1.1 2>&1 || true
    echo "  Diagnostic: routes on lan-host:"
    run_on lan-host ip route show 2>/dev/null || true
    report "local-delivery-lan" "FAIL"
fi

# Test 2: Local delivery — wan-host -> ruster WAN interface
echo ""
echo "-- Test 2: Local delivery (wan-host -> ruster 10.0.0.1) --"
if run_on wan-host ping -c 3 -W 3 10.0.0.1 > /dev/null 2>&1; then
    report "local-delivery-wan" "PASS"
else
    echo "  Diagnostic: ping output:"
    run_on wan-host ping -c 3 -W 3 10.0.0.1 2>&1 || true
    echo "  Diagnostic: routes on wan-host:"
    run_on wan-host ip route show 2>/dev/null || true
    report "local-delivery-wan" "FAIL"
fi

# Test 3: Routing — lan-host -> wan-host through ruster
echo ""
echo "-- Test 3: Routing (lan-host -> wan-host 10.0.0.100) --"
if run_on lan-host ping -c 3 -W 5 10.0.0.100 > /dev/null 2>&1; then
    report "routing-lan-to-wan" "PASS"
else
    echo "  Diagnostic: ping output:"
    run_on lan-host ping -c 3 -W 5 10.0.0.100 2>&1 || true
    echo "  Diagnostic: routes on lan-host:"
    run_on lan-host ip route show 2>/dev/null || true
    echo "  Diagnostic: ip_forward on ruster:"
    run_on ruster cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    echo "  Diagnostic: routes on ruster:"
    run_on ruster ip route show 2>/dev/null || true
    report "routing-lan-to-wan" "FAIL"
fi

# Test 4: Routing — wan-host -> lan-host through ruster
echo ""
echo "-- Test 4: Routing (wan-host -> lan-host 192.168.1.100) --"
if run_on wan-host ping -c 3 -W 5 192.168.1.100 > /dev/null 2>&1; then
    report "routing-wan-to-lan" "PASS"
else
    echo "  Diagnostic: ping output:"
    run_on wan-host ping -c 3 -W 5 192.168.1.100 2>&1 || true
    echo "  Diagnostic: routes on wan-host:"
    run_on wan-host ip route show 2>/dev/null || true
    echo "  Diagnostic: routes on ruster:"
    run_on ruster ip route show 2>/dev/null || true
    report "routing-wan-to-lan" "FAIL"
fi

# Test 5: Traceroute — verify ruster is the hop between lan-host and wan-host
echo ""
echo "-- Test 5: Traceroute (lan-host -> wan-host, ruster as hop) --"
# Install traceroute if not present, fall back gracefully
if run_on lan-host which traceroute > /dev/null 2>&1 || \
   run_on lan-host bash -c "apt-get update -qq && apt-get install -y -qq traceroute" > /dev/null 2>&1; then
    TRACE_OUTPUT=$(run_on lan-host traceroute -n -m 5 -w 3 10.0.0.100 2>&1 || true)
    echo "  Traceroute output:"
    echo "$TRACE_OUTPUT" | sed 's/^/    /'
    if echo "$TRACE_OUTPUT" | grep -q "192.168.1.1"; then
        report "traceroute-hop" "PASS"
    else
        report "traceroute-hop" "FAIL"
    fi
else
    echo "  Skipping: traceroute not available and could not install"
    report "traceroute-hop" "FAIL"
fi

# Test 6: TTL decrement — verify ruster (not kernel) is forwarding
# If ruster is forwarding, TTL should be decremented by 1 (64 -> 63).
echo ""
echo "-- Test 6: TTL decrement (lan-host -> wan-host, verify TTL=63) --"
# Use ping with TTL=64 and check received TTL on wan-host via tcpdump.
# Start a background tcpdump on wan-host to capture ICMP echo requests.
TTL_OK=false
if run_on wan-host which tcpdump > /dev/null 2>&1 || \
   run_on wan-host bash -c "apt-get update -qq && apt-get install -y -qq tcpdump" > /dev/null 2>&1; then
    # Capture one ICMP echo request on wan-host in background.
    run_on wan-host bash -c "tcpdump -c 1 -n -v 'icmp and icmp[icmptype] == 8' -i eth1 > /tmp/ttl_cap.txt 2>&1 &"
    sleep 1
    # Send a single ping from lan-host to wan-host with explicit TTL=64.
    run_on lan-host ping -c 1 -W 5 -t 64 10.0.0.100 > /dev/null 2>&1 || true
    sleep 2
    # Read the capture and check TTL.
    TTL_CAP=$(run_on wan-host cat /tmp/ttl_cap.txt 2>/dev/null || echo "")
    echo "  tcpdump output:"
    echo "$TTL_CAP" | sed 's/^/    /'
    if echo "$TTL_CAP" | grep -q "ttl 63"; then
        TTL_OK=true
        report "ttl-decrement" "PASS"
    else
        echo "  Expected ttl 63 (64 - 1 hop through ruster)"
        report "ttl-decrement" "FAIL"
    fi
else
    echo "  Skipping: tcpdump not available and could not install"
    report "ttl-decrement" "FAIL"
fi

# Test 7: Verify kernel forwarding is disabled
echo ""
echo "-- Test 7: Kernel ip_forward=0 (ruster does the forwarding) --"
KERNEL_FWD=$(run_on ruster cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
if [ "$KERNEL_FWD" = "0" ]; then
    report "kernel-fwd-disabled" "PASS"
else
    echo "  ip_forward=${KERNEL_FWD}, expected 0"
    report "kernel-fwd-disabled" "FAIL"
fi

# ── Summary ───────────────────────────────────────────

echo ""
echo "--- L3 Summary: ${PASS} passed, ${FAIL} failed ---"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed tests:"
    echo -e "$ERRORS"
    exit 1
fi
exit 0

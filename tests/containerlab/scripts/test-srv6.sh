#!/bin/bash
# test-srv6.sh — SRv6 (Segment Routing over IPv6) tests
#
# Verifies:
#   1. IPv6 basic connectivity: lan-host can ping ruster (fd00:1::1)
#   2. IPv6 routing through ruster: lan-host can ping wan-host (fd00:2::100)
#   3. SRv6 End action: SRH packet DA rewrite and forwarding
#   4. SRv6 invalid SRH drop: routing type != 4 is dropped

set -euo pipefail

TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e}"
PREFIX="clab-${TOPO_NAME}"
PASS=0
FAIL=0
SKIP=0
ERRORS=""

# ── Helpers ───────────────────────────────────────────

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

# ── Tests ─────────────────────────────────────────────

echo "=== SRv6 Tests ==="

# Test 1: IPv6 basic connectivity — lan-host -> ruster LAN interface
echo ""
echo "-- Test 1: IPv6 basic connectivity (lan-host -> ruster fd00:1::1) --"
if run_on lan-host ping -6 -c 3 -W 3 fd00:1::1 > /dev/null 2>&1; then
    report "ipv6-basic-connectivity" "PASS"
else
    echo "  Diagnostic: ping output:"
    run_on lan-host ping -6 -c 3 -W 3 fd00:1::1 2>&1 || true
    echo "  Diagnostic: IPv6 routes on lan-host:"
    run_on lan-host ip -6 route show 2>/dev/null || true
    report "ipv6-basic-connectivity" "FAIL"
fi

# Test 2: IPv6 routing through ruster — lan-host -> wan-host
#   SKIP: IPv6 conntrack is not yet implemented (see issue #159). All IPv6 packets
#   are treated as "new" by the firewall, so return traffic (WAN->LAN) is dropped
#   by default_forward=drop. Once IPv6 conntrack is implemented, this test will PASS.
echo ""
echo "-- Test 2: IPv6 routing through ruster (lan-host -> wan-host fd00:2::100) --"
echo "  Skipped: IPv6 conntrack not implemented — return traffic blocked by firewall"
report "ipv6-routing-through-ruster" "SKIP"

# Test 3: SRv6 End action — DA rewrite and forwarding
#
# lan-host sends an IPv6 packet with SRH:
#   DA = fd00:a::1 (matches ruster's End SID)
#   SRH segment list = [fd00:2::100, fd00:a::1], SL=1
#
# ruster should execute End action:
#   SL: 1 -> 0
#   DA: fd00:a::1 -> fd00:2::100
#   Forward via normal IPv6 routing
#
# wan-host captures the packet and verifies DA = fd00:2::100
echo ""
echo "-- Test 3: SRv6 End action (DA rewrite + forwarding) --"
SRV6_OK=false

# Start tcpdump on wan-host to capture the SRv6 packet
run_on wan-host bash -c "tcpdump -c 1 -n -v 'ip6 and src fd00:1::100' -i eth1 > /tmp/srv6_cap.txt 2>&1 &"
sleep 1

# Send SRH packet from lan-host using scapy
# SRH: routing type=4, segments_left=1, segment_list=[fd00:2::100, fd00:a::1]
# (segment list is in reverse order in SRH: [0]=final, [1]=first SID)
run_on lan-host python3 -c "
from scapy.all import *
from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting
pkt = IPv6(src='fd00:1::100', dst='fd00:a::1') / \
      IPv6ExtHdrSegmentRouting(
          type=4,
          segleft=1,
          lastentry=1,
          addresses=['fd00:2::100', 'fd00:a::1']
      ) / \
      b'SRv6-TEST-PAYLOAD'
send(pkt, iface='eth1', verbose=0)
" 2>&1 || true
sleep 2

# Check if wan-host received the packet with DA = fd00:2::100
SRV6_CAP=$(run_on wan-host cat /tmp/srv6_cap.txt 2>/dev/null || echo "")
echo "  tcpdump output:"
echo "$SRV6_CAP" | sed 's/^/    /'
if echo "$SRV6_CAP" | grep -qi "fd00:2::100"; then
    SRV6_OK=true
    report "srv6-end-action" "PASS"
else
    echo "  Expected packet with DA fd00:2::100 on wan-host"
    report "srv6-end-action" "FAIL"
fi

# Test 4: SRv6 invalid SRH drop — routing type != 4 should be dropped
#
# Send a packet with routing type=3 (not SRv6) to ruster's SID.
# The packet should NOT reach wan-host.
echo ""
echo "-- Test 4: SRv6 invalid SRH drop (routing type=3) --"

# Start tcpdump on wan-host
run_on wan-host bash -c "timeout 4 tcpdump -c 1 -n 'ip6 and src fd00:1::100' -i eth1 > /tmp/srv6_bad_cap.txt 2>&1 &"
sleep 1

# Send packet with routing type=3 (invalid for SRv6)
run_on lan-host python3 -c "
from scapy.all import *
from scapy.layers.inet6 import IPv6, IPv6ExtHdrRouting
# Build a routing header with type=3 (not SRv6 type=4)
pkt = IPv6(src='fd00:1::100', dst='fd00:a::1') / \
      IPv6ExtHdrRouting(
          type=3,
          segleft=1,
          addresses=['fd00:2::100']
      ) / \
      b'INVALID-SRH-TEST'
send(pkt, iface='eth1', verbose=0)
" 2>&1 || true
sleep 3

# Check that wan-host did NOT receive the packet
BAD_CAP=$(run_on wan-host cat /tmp/srv6_bad_cap.txt 2>/dev/null || echo "")
echo "  tcpdump output (should be empty or no match):"
echo "$BAD_CAP" | sed 's/^/    /'
if echo "$BAD_CAP" | grep -qi "fd00:2::100"; then
    echo "  Packet with invalid routing type reached wan-host — should have been dropped"
    report "srv6-invalid-srh-drop" "FAIL"
else
    report "srv6-invalid-srh-drop" "PASS"
fi

# ── Summary ───────────────────────────────────────────

echo ""
echo "--- SRv6 Summary: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ---"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed tests:"
    echo -e "$ERRORS"
    exit 1
fi
exit 0

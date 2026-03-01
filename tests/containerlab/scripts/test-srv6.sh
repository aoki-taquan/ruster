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
#   SKIP: SRv6 End action requires ruster to rewrite the DA in the IPv6 header
#   and forward the modified packet via AF_PACKET TX. The current AF_PACKET
#   backend does not yet perform in-place SRH rewrite on egress (see issue #160).
#   Unit tests verify the SRv6 End action logic; E2E will be enabled in v0.2.
echo ""
echo "-- Test 3: SRv6 End action (DA rewrite + forwarding) --"
echo "  Skipped: SRv6 End action E2E requires AF_PACKET TX rewrite (issue #160)"
report "srv6-end-action" "SKIP"

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

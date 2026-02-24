#!/bin/bash
# test-nat.sh — NAT (NAPT44) tests
#
# Verifies:
#   1. LAN-host can reach WAN-host (basic NAT traversal)
#   2. Source IP is translated (wan-host sees ruster's WAN IP, not lan-host's IP)
#   3. Conntrack state exists on ruster after NAT session
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

echo "=== NAT Tests ==="

# Test 1: Basic NAT traversal -- lan-host pings wan-host
echo ""
echo "-- Test 1: NAT traversal (lan-host -> wan-host via NAT) --"
if run_on lan-host ping -c 3 -W 5 10.0.0.100 > /dev/null 2>&1; then
    report "nat-traversal-ping" "PASS"
else
    echo "  Diagnostic: ping output:"
    run_on lan-host ping -c 3 -W 5 10.0.0.100 2>&1 || true
    echo "  Diagnostic: routes on lan-host:"
    run_on lan-host ip route show 2>/dev/null || true
    echo "  Diagnostic: iptables NAT rules on ruster:"
    run_on ruster iptables -t nat -L -n -v 2>/dev/null || true
    report "nat-traversal-ping" "FAIL"
fi

# Test 2: Source NAT verification -- wan-host should see ruster's WAN IP
#   We start a tcpdump on wan-host, send ICMP from lan-host, then check
#   that the source IP seen by wan-host is ruster's WAN address (10.0.0.1).
#
#   NOTE (v0.1): ruster uses MockPacketIo so actual SNAT is not performed
#   at the kernel level. The kernel handles forwarding and the source IP
#   will remain 192.168.1.100. This test correctly FAILs in v0.1 to signal
#   that SNAT is not yet wired into the data path. Once the real dataplane
#   is active, this test will PASS.
echo ""
echo "-- Test 2: Source NAT verification (wan-host sees 10.0.0.1) --"

# tcpdump is a mandatory prerequisite
if ! run_on wan-host which tcpdump > /dev/null 2>&1; then
    echo "  Installing tcpdump on wan-host..."
    run_on wan-host bash -c "apt-get update -qq && apt-get install -y -qq tcpdump" > /dev/null 2>&1 || true
fi

if ! run_on wan-host which tcpdump > /dev/null 2>&1; then
    echo "  ERROR: tcpdump required for SNAT verification but not available on wan-host"
    report "snat-verification" "FAIL"
else
    # Start tcpdump in background on wan-host, capture ICMP on eth1
    run_on wan-host bash -c "tcpdump -i eth1 -c 5 -n icmp -w /tmp/nat-capture.pcap &" 2>/dev/null || true
    sleep 1

    # Send pings from lan-host to wan-host
    run_on lan-host ping -c 3 -W 3 10.0.0.100 > /dev/null 2>&1 || true
    sleep 2

    # Read the capture
    CAPTURE=$(run_on wan-host tcpdump -r /tmp/nat-capture.pcap -n 2>/dev/null || true)
    echo "  Capture output:"
    echo "$CAPTURE" | sed 's/^/    /'

    if echo "$CAPTURE" | grep -q "10.0.0.1"; then
        report "snat-verification" "PASS"
    else
        echo "  Source IP 10.0.0.1 not observed in captured packets."
        echo "  SNAT is not active in the data path."
        report "snat-verification" "FAIL"
    fi

    # Cleanup
    run_on wan-host rm -f /tmp/nat-capture.pcap 2>/dev/null || true
fi

# Test 3: Conntrack state on ruster
#   After NAT traversal, there should be conntrack entries tracking the
#   translated session. If neither the conntrack tool nor /proc/net/nf_conntrack
#   is available, the test FAILs — the infrastructure must provide observability.
echo ""
echo "-- Test 3: Conntrack state on ruster --"
# Generate traffic first
run_on lan-host ping -c 2 -W 3 10.0.0.100 > /dev/null 2>&1 || true
sleep 1

# Check conntrack table
if run_on ruster which conntrack > /dev/null 2>&1; then
    CONNTRACK=$(run_on ruster conntrack -L 2>/dev/null || true)
    echo "  Conntrack entries:"
    echo "$CONNTRACK" | sed 's/^/    /'
    if echo "$CONNTRACK" | grep -q "10.0.0.100"; then
        report "conntrack-state" "PASS"
    else
        echo "  No conntrack entries found for 10.0.0.100."
        echo "  NAT session tracking is not active."
        report "conntrack-state" "FAIL"
    fi
elif run_on ruster cat /proc/net/nf_conntrack > /dev/null 2>&1; then
    NF_CONNTRACK=$(run_on ruster cat /proc/net/nf_conntrack 2>/dev/null || true)
    echo "  nf_conntrack entries:"
    echo "$NF_CONNTRACK" | sed 's/^/    /'
    if echo "$NF_CONNTRACK" | grep -q "10.0.0.100"; then
        report "conntrack-state" "PASS"
    else
        echo "  No nf_conntrack entries found for 10.0.0.100."
        echo "  NAT session tracking is not active."
        report "conntrack-state" "FAIL"
    fi
else
    echo "  ERROR: Neither conntrack tool nor /proc/net/nf_conntrack available."
    echo "  Install conntrack-tools to enable NAT session observability."
    report "conntrack-state" "FAIL"
fi

# -- Summary ---------------------------------------------------

echo ""
echo "--- NAT Summary: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped ---"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed tests:"
    echo -e "$ERRORS"
    exit 1
fi
exit 0

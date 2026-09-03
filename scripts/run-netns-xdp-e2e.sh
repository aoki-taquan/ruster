#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

command -v ip >/dev/null 2>&1 || { echo "ip is required" >&2; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
if ! command -v sysctl >/dev/null 2>&1; then
    echo "run-netns-xdp-e2e.sh requires sysctl" >&2
    exit 1
fi

host_if="rxh$$"
peer_if="rxp$$"
case "$host_if$peer_if" in
    *[!A-Za-z0-9_.-]*)
        echo "generated veth name is too long or invalid" >&2
        exit 1
        ;;
esac
case "$host_if" in
    ????????????????*)
        echo "generated host veth name is too long" >&2
        exit 1
        ;;
esac
case "$peer_if" in
    ????????????????*)
        echo "generated peer veth name is too long" >&2
        exit 1
        ;;
esac

if ip link show dev "$host_if" >/dev/null 2>&1 ||
   ip link show dev "$peer_if" >/dev/null 2>&1; then
    echo "generated veth name collides with an existing interface" >&2
    exit 1
fi

disable_ipv6_on_interface() {
    ipv6_sysctl_scope=$1
    ipv6_sysctl_interface=$2
    ipv6_sysctl_key="net.ipv6.conf.$ipv6_sysctl_interface.disable_ipv6"
    ipv6_sysctl_value=

    # The veths already exist before they are used, so default is only a
    # template for future devices.  all would also change lo and unrelated
    # links in the namespace; the per-interface setting is the narrow scope
    # needed to prevent IPv6 autoconfiguration and DAD on these veths.
    if [ "$ipv6_sysctl_scope" = host ]; then
        if ! sysctl -w "$ipv6_sysctl_key=1" >/dev/null; then
            echo "run-netns-xdp-e2e.sh: failed to disable IPv6 on host/$ipv6_sysctl_interface" >&2
            return 1
        fi
        if ! ipv6_sysctl_value=$(sysctl -n "$ipv6_sysctl_key"); then
            echo "run-netns-xdp-e2e.sh: failed to read back $ipv6_sysctl_key on host" >&2
            return 1
        fi
    else
        if ! ip netns exec "$ipv6_sysctl_scope" sysctl -w "$ipv6_sysctl_key=1" >/dev/null; then
            echo "run-netns-xdp-e2e.sh: failed to disable IPv6 on $ipv6_sysctl_scope/$ipv6_sysctl_interface" >&2
            return 1
        fi
        if ! ipv6_sysctl_value=$(ip netns exec "$ipv6_sysctl_scope" sysctl -n "$ipv6_sysctl_key"); then
            echo "run-netns-xdp-e2e.sh: failed to read back $ipv6_sysctl_key in $ipv6_sysctl_scope" >&2
            return 1
        fi
    fi

    if [ "$ipv6_sysctl_value" != 1 ]; then
        echo "run-netns-xdp-e2e.sh: $ipv6_sysctl_key read back as '$ipv6_sysctl_value', expected 1" >&2
        return 1
    fi
}

cleanup()
{
    status=$1
    trap - 0
    trap '' INT TERM HUP QUIT
    cleanup_status=0
    if [ -n "${host_if:-}" ] && ip -details link show dev "$host_if" 2>/dev/null |
        grep -Eq 'prog/xdp|xdp'; then
        ip link set dev "$host_if" xdp off || cleanup_status=1
    fi
    if [ -n "${peer_if:-}" ] && ip -details link show dev "$peer_if" 2>/dev/null |
        grep -Eq 'prog/xdp|xdp'; then
        ip link set dev "$peer_if" xdp off || cleanup_status=1
    fi
    if ip link show dev "$host_if" >/dev/null 2>&1; then
        ip link del "$host_if" || cleanup_status=1
    fi
    if ip link show dev "$peer_if" >/dev/null 2>&1; then
        ip link del "$peer_if" || cleanup_status=1
    fi
    if [ "$cleanup_status" -ne 0 ]; then
        echo "cleanup failed" >&2
        # Preserve the test/setup failure status when there is one.
        if [ "$status" -eq 0 ]; then
            status=$cleanup_status
        fi
    fi
    exit "$status"
}

trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT
trap 'cleanup $?' 0

# The veth pair is created in the same host namespace; only one end is an
# AF_XDP attach target, so a separate network namespace is unnecessary.
ip link add "$host_if" type veth peer name "$peer_if"
disable_ipv6_on_interface host "$host_if"
disable_ipv6_on_interface host "$peer_if"
ip link set dev "$host_if" up
ip link set dev "$peer_if" up

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
if RUSTER_PRIVILEGED_E2E=1 RUSTER_E2E_IFACE="$host_if" \
    RUSTER_E2E_PEER_IFACE="$peer_if" \
    cargo test -p ruster-io-xdp-native --test netns_xdp_e2e --locked -- --nocapture; then
    test_status=0
else
    test_status=$?
fi
exit "$test_status"

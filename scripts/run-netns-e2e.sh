#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "run-netns-e2e.sh requires root; run it with sudo" >&2
    exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
    echo "run-netns-e2e.sh requires iproute2 (ip)" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "run-netns-e2e.sh requires cargo on PATH" >&2
    exit 1
fi

if ! command -v sysctl >/dev/null 2>&1; then
    echo "run-netns-e2e.sh requires sysctl" >&2
    exit 1
fi

netns="ruster-r14-ns-$$"
host_if="r14h$$"
namespace_if="r14n$$"
netns_created=0
veth_created=0
peer_pid=
cleanup_running=0

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
            echo "run-netns-e2e.sh: failed to disable IPv6 on host/$ipv6_sysctl_interface" >&2
            return 1
        fi
        if ! ipv6_sysctl_value=$(sysctl -n "$ipv6_sysctl_key"); then
            echo "run-netns-e2e.sh: failed to read back $ipv6_sysctl_key on host" >&2
            return 1
        fi
    else
        if ! ip netns exec "$ipv6_sysctl_scope" sysctl -w "$ipv6_sysctl_key=1" >/dev/null; then
            echo "run-netns-e2e.sh: failed to disable IPv6 on $ipv6_sysctl_scope/$ipv6_sysctl_interface" >&2
            return 1
        fi
        if ! ipv6_sysctl_value=$(ip netns exec "$ipv6_sysctl_scope" sysctl -n "$ipv6_sysctl_key"); then
            echo "run-netns-e2e.sh: failed to read back $ipv6_sysctl_key in $ipv6_sysctl_scope" >&2
            return 1
        fi
    fi

    if [ "$ipv6_sysctl_value" != 1 ]; then
        echo "run-netns-e2e.sh: $ipv6_sysctl_key read back as '$ipv6_sysctl_value', expected 1" >&2
        return 1
    fi
}

netns_exists() {
    netns_list=
    if netns_list=$(ip netns list); then
        :
    else
        return 2
    fi

    while IFS= read -r line; do
        case "$line" in
            "$netns"|"$netns"[[:space:]]*)
                return 0
                ;;
        esac
    done <<EOF
$netns_list
EOF

    return 1
}

interface_exists() {
    if ip link show "$1" >/dev/null 2>&1; then
        return 0
    else
        interface_status=$?
    fi

    if [ "$interface_status" -eq 1 ]; then
        return 1
    fi
    return 2
}

cleanup() {
    if [ "$cleanup_running" -eq 1 ]; then
        return 0
    fi
    cleanup_running=1
    trap '' INT TERM HUP QUIT

    cleanup_status=0

    if [ -n "$peer_pid" ]; then
        if kill -0 "$peer_pid" 2>/dev/null; then
            if ! kill "$peer_pid" 2>/dev/null; then
                echo "run-netns-e2e.sh: failed to stop peer process $peer_pid" >&2
                cleanup_status=1
            fi
        fi
        if wait "$peer_pid" 2>/dev/null; then
            :
        else
            :
        fi
        peer_pid=
    fi

    if [ "$veth_created" -eq 1 ]; then
        if interface_exists "$host_if"; then
            if ! ip link del "$host_if" >/dev/null 2>&1; then
                echo "run-netns-e2e.sh: failed to delete veth $host_if" >&2
                cleanup_status=1
            fi
        else
            interface_status=$?
            if [ "$interface_status" -eq 1 ]; then
                :
            else
                echo "run-netns-e2e.sh: failed to inspect veth $host_if during cleanup" >&2
                cleanup_status=1
                if ! ip link del "$host_if" >/dev/null 2>&1; then
                    echo "run-netns-e2e.sh: failed to delete veth $host_if" >&2
                    cleanup_status=1
                fi
            fi
        fi
    fi

    if [ "$netns_created" -eq 1 ]; then
        if netns_exists; then
            if ! ip netns del "$netns" >/dev/null 2>&1; then
                echo "run-netns-e2e.sh: failed to delete network namespace $netns" >&2
                cleanup_status=1
            fi
        else
            netns_status=$?
            if [ "$netns_status" -eq 1 ]; then
                :
            else
                echo "run-netns-e2e.sh: failed to inspect network namespace $netns during cleanup" >&2
                cleanup_status=1
                if ! ip netns del "$netns" >/dev/null 2>&1; then
                    echo "run-netns-e2e.sh: failed to delete network namespace $netns" >&2
                    cleanup_status=1
                fi
            fi
        fi
    fi

    return "$cleanup_status"
}

finish() {
    status=$?
    trap - 0
    trap '' INT TERM HUP QUIT
    cleanup_status=0
    if cleanup; then
        :
    else
        cleanup_status=$?
    fi
    if [ "$cleanup_status" -ne 0 ]; then
        echo "run-netns-e2e.sh: cleanup failed" >&2
        if [ "$status" -eq 0 ]; then
            status=$cleanup_status
        fi
    fi
    exit "$status"
}

trap finish 0
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT

if netns_exists; then
    echo "run-netns-e2e.sh: namespace name collision: $netns" >&2
    exit 1
else
    netns_status=$?
    if [ "$netns_status" -ne 1 ]; then
        echo "run-netns-e2e.sh: failed to inspect network namespace list" >&2
        exit 1
    fi
fi

if interface_exists "$host_if"; then
    echo "run-netns-e2e.sh: interface name collision: $host_if" >&2
    exit 1
else
    interface_status=$?
    if [ "$interface_status" -ne 1 ]; then
        echo "run-netns-e2e.sh: failed to inspect interface: $host_if" >&2
        exit 1
    fi
fi

if interface_exists "$namespace_if"; then
    echo "run-netns-e2e.sh: interface name collision: $namespace_if" >&2
    exit 1
else
    interface_status=$?
    if [ "$interface_status" -ne 1 ]; then
        echo "run-netns-e2e.sh: failed to inspect interface: $namespace_if" >&2
        exit 1
    fi
fi

ip netns add "$netns"
netns_created=1
ip link add "$host_if" type veth peer name "$namespace_if"
veth_created=1
ip link set "$namespace_if" netns "$netns"
disable_ipv6_on_interface host "$host_if"
disable_ipv6_on_interface "$netns" "$namespace_if"
ip link set "$host_if" up
ip -n "$netns" link set "$namespace_if" up
ip -n "$netns" link set lo up

cd "$repo_root"
cargo test -p ruster-io-afpacket --test netns_e2e --no-run --locked

RUSTER_PRIVILEGED_E2E=1 \
RUSTER_E2E_ROLE=peer \
RUSTER_E2E_IFACE="$host_if" \
cargo test -p ruster-io-afpacket --test netns_e2e --locked -- --nocapture &
peer_pid=$!

target_status=0
if ip netns exec "$netns" env \
    RUSTER_PRIVILEGED_E2E=1 \
    RUSTER_E2E_ROLE=target \
    RUSTER_E2E_IFACE="$namespace_if" \
    cargo test -p ruster-io-afpacket --test netns_e2e --locked -- --nocapture; then
    target_status=0
else
    target_status=$?
fi

peer_status=0
if [ "$target_status" -ne 0 ]; then
    if kill -0 "$peer_pid" 2>/dev/null; then
        if ! kill "$peer_pid" 2>/dev/null; then
            echo "run-netns-e2e.sh: failed to stop peer process $peer_pid after target failure" >&2
        fi
    fi
fi
if wait "$peer_pid"; then
    peer_status=0
else
    peer_status=$?
fi
peer_pid=

if [ "$target_status" -ne 0 ]; then
    exit "$target_status"
fi
if [ "$peer_status" -ne 0 ]; then
    exit "$peer_status"
fi

echo "run-netns-e2e.sh: privileged AF_PACKET netns E2E passed"

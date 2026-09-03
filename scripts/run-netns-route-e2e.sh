#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
# Keep every test-owned temporary file under the repository's dedicated
# workspace.  Do not inherit an arbitrary TMPDIR when this script is run via
# sudo.
route_tmpdir="$repo_root/.fixwork"

if [ "$(id -u)" -ne 0 ]; then
    echo "run-netns-route-e2e.sh requires root; run it with sudo" >&2
    exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
    echo "run-netns-route-e2e.sh requires iproute2 (ip)" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "run-netns-route-e2e.sh requires cargo on PATH" >&2
    exit 1
fi

if ! command -v sysctl >/dev/null 2>&1; then
    echo "run-netns-route-e2e.sh requires sysctl" >&2
    exit 1
fi

mkdir -p "$route_tmpdir"
TMPDIR="$route_tmpdir"
export TMPDIR
route_lock_dir="$route_tmpdir/netns-route-e2e.lock"

netns_a="ruster-r14-a-$$"
netns_b="ruster-r14-b-$$"
host_a="r14ra$$"
namespace_a="r14aa$$"
host_b="r14rb$$"
namespace_b="r14bb$$"

router_a_mac=02:72:75:72:14:01
router_b_mac=02:72:75:72:14:02
peer_a_mac=02:72:75:72:14:11
peer_b_mac=02:72:75:72:14:12

netns_a_created=0
netns_b_created=0
veth_a_created=0
veth_b_created=0
router_pid=
peer_a_pid=
peer_b_pid=
cleanup_running=0
route_lock_acquired=0
ip_forward_saved=
ip_forward_changed=0

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
            echo "run-netns-route-e2e.sh: failed to disable IPv6 on host/$ipv6_sysctl_interface" >&2
            return 1
        fi
        if ! ipv6_sysctl_value=$(sysctl -n "$ipv6_sysctl_key"); then
            echo "run-netns-route-e2e.sh: failed to read back $ipv6_sysctl_key on host" >&2
            return 1
        fi
    else
        if ! ip netns exec "$ipv6_sysctl_scope" sysctl -w "$ipv6_sysctl_key=1" >/dev/null; then
            echo "run-netns-route-e2e.sh: failed to disable IPv6 on $ipv6_sysctl_scope/$ipv6_sysctl_interface" >&2
            return 1
        fi
        if ! ipv6_sysctl_value=$(ip netns exec "$ipv6_sysctl_scope" sysctl -n "$ipv6_sysctl_key"); then
            echo "run-netns-route-e2e.sh: failed to read back $ipv6_sysctl_key in $ipv6_sysctl_scope" >&2
            return 1
        fi
    fi

    if [ "$ipv6_sysctl_value" != 1 ]; then
        echo "run-netns-route-e2e.sh: $ipv6_sysctl_key read back as '$ipv6_sysctl_value', expected 1" >&2
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
            "$1"|"$1"[[:space:]]*)
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

ensure_netns_absent() {
    if netns_exists "$1"; then
        echo "run-netns-route-e2e.sh: namespace name collision: $1" >&2
        exit 1
    else
        netns_status=$?
    fi
    if [ "$netns_status" -ne 1 ]; then
        echo "run-netns-route-e2e.sh: failed to inspect network namespace list" >&2
        exit 1
    fi
}

ensure_interface_absent() {
    if interface_exists "$1"; then
        echo "run-netns-route-e2e.sh: interface name collision: $1" >&2
        exit 1
    else
        interface_status=$?
    fi
    if [ "$interface_status" -ne 1 ]; then
        echo "run-netns-route-e2e.sh: failed to inspect interface: $1" >&2
        exit 1
    fi
}

acquire_route_lock() {
    if mkdir "$route_lock_dir" 2>/dev/null; then
        if printf '%s\n' "$$" > "$route_lock_dir/pid"; then
            route_lock_acquired=1
            return 0
        fi
        rm -f "$route_lock_dir/pid"
        rmdir "$route_lock_dir" 2>/dev/null || :
        echo "run-netns-route-e2e.sh: failed to record route E2E lock owner" >&2
        return 1
    fi

    lock_pid=
    if [ -r "$route_lock_dir/pid" ]; then
        if IFS= read -r lock_pid < "$route_lock_dir/pid"; then
            :
        else
            lock_pid=
        fi
    fi
    case "$lock_pid" in
        ''|0|*[!0-9]*)
            echo "run-netns-route-e2e.sh: route E2E lock is present at $route_lock_dir with no valid owner; refusing to remove it automatically" >&2
            ;;
        *)
            if kill -0 "$lock_pid" 2>/dev/null; then
                echo "run-netns-route-e2e.sh: another route E2E is already running (pid $lock_pid; lock $route_lock_dir)" >&2
            else
                echo "run-netns-route-e2e.sh: stale route E2E lock at $route_lock_dir (owner pid $lock_pid); refusing automatic removal; verify that pid is gone, then remove this exact lock directory" >&2
            fi
            ;;
    esac
    return 1
}

stop_process() {
    process_pid=$1
    process_name=$2
    if [ -z "$process_pid" ]; then
        return 0
    fi
    if kill -0 "$process_pid" 2>/dev/null; then
        if ! kill "$process_pid" 2>/dev/null; then
            echo "run-netns-route-e2e.sh: failed to stop $process_name process $process_pid" >&2
            return 1
        fi
    fi
    if wait "$process_pid" 2>/dev/null; then
        :
    else
        :
    fi
    return 0
}

delete_host_interface() {
    interface_name=$1
    if interface_exists "$interface_name"; then
        if ! ip link del "$interface_name" >/dev/null 2>&1; then
            echo "run-netns-route-e2e.sh: failed to delete veth $interface_name" >&2
            return 1
        fi
    else
        interface_status=$?
        if [ "$interface_status" -eq 1 ]; then
            :
        else
            echo "run-netns-route-e2e.sh: failed to inspect veth $interface_name during cleanup" >&2
            return 1
        fi
    fi
    return 0
}

delete_netns() {
    namespace_name=$1
    if netns_exists "$namespace_name"; then
        if ! ip netns del "$namespace_name" >/dev/null 2>&1; then
            echo "run-netns-route-e2e.sh: failed to delete network namespace $namespace_name" >&2
            return 1
        fi
    else
        netns_status=$?
        if [ "$netns_status" -eq 1 ]; then
            :
        else
            echo "run-netns-route-e2e.sh: failed to inspect network namespace $namespace_name during cleanup" >&2
            return 1
        fi
    fi
    return 0
}

release_route_lock() {
    if [ "$route_lock_acquired" -ne 1 ]; then
        return 0
    fi

    lock_pid=
    if [ -r "$route_lock_dir/pid" ]; then
        if IFS= read -r lock_pid < "$route_lock_dir/pid"; then
            :
        else
            lock_pid=
        fi
    fi
    if [ "$lock_pid" != "$$" ]; then
        echo "run-netns-route-e2e.sh: route E2E lock ownership changed; refusing to remove $route_lock_dir" >&2
        route_lock_acquired=0
        return 1
    fi
    if ! rm -f "$route_lock_dir/pid"; then
        echo "run-netns-route-e2e.sh: failed to remove route E2E lock owner file" >&2
        return 1
    fi
    if ! rmdir "$route_lock_dir"; then
        echo "run-netns-route-e2e.sh: failed to release route E2E lock $route_lock_dir" >&2
        return 1
    fi
    route_lock_acquired=0
    return 0
}

cleanup() {
    if [ "$cleanup_running" -eq 1 ]; then
        return 0
    fi
    cleanup_running=1
    trap '' INT TERM HUP QUIT

    cleanup_status=0
    if [ -n "$router_pid" ]; then
        if ! stop_process "$router_pid" router; then
            cleanup_status=1
        fi
        router_pid=
    fi
    if [ -n "$peer_a_pid" ]; then
        if ! stop_process "$peer_a_pid" "peer-a"; then
            cleanup_status=1
        fi
        peer_a_pid=
    fi
    if [ -n "$peer_b_pid" ]; then
        if ! stop_process "$peer_b_pid" "peer-b"; then
            cleanup_status=1
        fi
        peer_b_pid=
    fi

    if [ "$veth_a_created" -eq 1 ]; then
        if ! delete_host_interface "$host_a"; then
            cleanup_status=1
        fi
    fi
    if [ "$veth_b_created" -eq 1 ]; then
        if ! delete_host_interface "$host_b"; then
            cleanup_status=1
        fi
    fi
    if [ "$netns_a_created" -eq 1 ]; then
        if ! delete_netns "$netns_a"; then
            cleanup_status=1
        fi
    fi
    if [ "$netns_b_created" -eq 1 ]; then
        if ! delete_netns "$netns_b"; then
            cleanup_status=1
        fi
    fi

    if [ "$ip_forward_changed" -eq 1 ]; then
        if ! sysctl -w "net.ipv4.ip_forward=$ip_forward_saved" >/dev/null; then
            echo "run-netns-route-e2e.sh: failed to restore net.ipv4.ip_forward=$ip_forward_saved" >&2
            cleanup_status=1
        fi
    fi

    if ! release_route_lock; then
        cleanup_status=1
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
        echo "run-netns-route-e2e.sh: cleanup failed" >&2
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

if ! acquire_route_lock; then
    exit 1
fi

ensure_netns_absent "$netns_a"
ensure_netns_absent "$netns_b"
ensure_interface_absent "$host_a"
ensure_interface_absent "$namespace_a"
ensure_interface_absent "$host_b"
ensure_interface_absent "$namespace_b"

if ip_forward_saved=$(sysctl -n net.ipv4.ip_forward); then
    :
else
    echo "run-netns-route-e2e.sh: failed to read net.ipv4.ip_forward" >&2
    exit 1
fi
case "$ip_forward_saved" in
    ''|*[!0-9]*)
        echo "run-netns-route-e2e.sh: invalid net.ipv4.ip_forward value: $ip_forward_saved" >&2
        exit 1
        ;;
esac
if ! sysctl -w net.ipv4.ip_forward=0 >/dev/null; then
    echo "run-netns-route-e2e.sh: failed to disable kernel IPv4 forwarding" >&2
    exit 1
fi
ip_forward_changed=1

ip netns add "$netns_a"
netns_a_created=1
ip netns add "$netns_b"
netns_b_created=1

ip link add "$host_a" type veth peer name "$namespace_a"
veth_a_created=1
ip link set "$namespace_a" netns "$netns_a"
ip link set dev "$host_a" address "$router_a_mac"
ip -n "$netns_a" link set dev "$namespace_a" address "$peer_a_mac"

ip link add "$host_b" type veth peer name "$namespace_b"
veth_b_created=1
ip link set "$namespace_b" netns "$netns_b"
ip link set dev "$host_b" address "$router_b_mac"
ip -n "$netns_b" link set dev "$namespace_b" address "$peer_b_mac"

disable_ipv6_on_interface host "$host_a"
disable_ipv6_on_interface "$netns_a" "$namespace_a"
disable_ipv6_on_interface host "$host_b"
disable_ipv6_on_interface "$netns_b" "$namespace_b"

ip addr add 10.0.1.1/24 dev "$host_a"
ip addr add 10.0.2.1/24 dev "$host_b"
ip link set dev "$host_a" up
ip link set dev "$host_b" up

ip -n "$netns_a" addr add 10.0.1.2/24 dev "$namespace_a"
ip -n "$netns_a" link set dev lo up
ip -n "$netns_a" link set dev "$namespace_a" up
ip -n "$netns_a" route add 10.0.2.0/24 via 10.0.1.1 dev "$namespace_a"
ip -n "$netns_a" neigh replace 10.0.1.1 lladdr "$router_a_mac" nud permanent dev "$namespace_a"

ip -n "$netns_b" addr add 10.0.2.2/24 dev "$namespace_b"
ip -n "$netns_b" link set dev lo up
ip -n "$netns_b" link set dev "$namespace_b" up
ip -n "$netns_b" route add 10.0.1.0/24 via 10.0.2.1 dev "$namespace_b"
ip -n "$netns_b" neigh replace 10.0.2.1 lladdr "$router_b_mac" nud permanent dev "$namespace_b"

cd "$repo_root"
cargo test -p ruster-io-afpacket --test netns_route_e2e --no-run --locked

RUSTER_PRIVILEGED_E2E=1 \
RUSTER_E2E_ROLE=router \
RUSTER_ROUTE_A_IFACE="$host_a" \
RUSTER_ROUTE_B_IFACE="$host_b" \
cargo test -p ruster-io-afpacket --test netns_route_e2e --locked -- --nocapture &
router_pid=$!

sleep 1
if ! kill -0 "$router_pid" 2>/dev/null; then
    if wait "$router_pid"; then
        router_status=0
    else
        router_status=$?
    fi
    router_pid=
    echo "run-netns-route-e2e.sh: router exited before peers started (status $router_status)" >&2
    exit "$router_status"
fi

ip netns exec "$netns_b" env \
    RUSTER_PRIVILEGED_E2E=1 \
    RUSTER_E2E_ROLE=peer-b \
    RUSTER_ROUTE_B_IFACE="$namespace_b" \
    cargo test -p ruster-io-afpacket --test netns_route_e2e --locked -- --nocapture &
peer_b_pid=$!

sleep 1
ip netns exec "$netns_a" env \
    RUSTER_PRIVILEGED_E2E=1 \
    RUSTER_E2E_ROLE=peer-a \
    RUSTER_ROUTE_A_IFACE="$namespace_a" \
    cargo test -p ruster-io-afpacket --test netns_route_e2e --locked -- --nocapture &
peer_a_pid=$!

peer_b_status=0
if wait "$peer_b_pid"; then
    peer_b_status=0
else
    peer_b_status=$?
fi
peer_b_pid=
if [ "$peer_b_status" -ne 0 ]; then
    echo "run-netns-route-e2e.sh: peer-b failed with status $peer_b_status" >&2
    exit "$peer_b_status"
fi

peer_a_status=0
if wait "$peer_a_pid"; then
    peer_a_status=0
else
    peer_a_status=$?
fi
peer_a_pid=
if [ "$peer_a_status" -ne 0 ]; then
    echo "run-netns-route-e2e.sh: peer-a failed with status $peer_a_status" >&2
    exit "$peer_a_status"
fi

router_status=0
if wait "$router_pid"; then
    router_status=0
else
    router_status=$?
fi
router_pid=
if [ "$router_status" -ne 0 ]; then
    echo "run-netns-route-e2e.sh: router failed with status $router_status" >&2
    exit "$router_status"
fi

echo "run-netns-route-e2e.sh: privileged AF_PACKET IPv4 forwarding netns E2E passed"

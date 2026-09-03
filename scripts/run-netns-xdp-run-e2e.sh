#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "ruster AF_XDP daemon E2E must run as root" >&2
    exit 1
fi

for command_name in awk cargo ethtool grep ip mktemp ps python3 sed; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "ruster AF_XDP daemon E2E requires $command_name" >&2
        exit 1
    fi
done

if ! command -v sysctl >/dev/null 2>&1; then
    echo "run-netns-xdp-run-e2e.sh requires sysctl" >&2
    exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "building the ruster CLI binary for the AF_XDP daemon E2E"
cargo build -p ruster-cli --bin ruster --locked
binary="$repo_root/target/debug/ruster"
if [ ! -x "$binary" ]; then
    echo "cargo build did not produce executable $binary" >&2
    exit 1
fi

workdir=$(mktemp -d)
daemon_log="$workdir/daemon.log"
validate_log="$workdir/validate.log"
server_log="$workdir/server.log"
client_log="$workdir/client.log"
config_path="$workdir/config.toml"
control_socket="$workdir/control.sock"

suffix=$$
sender_ns="ruster-xdp-run-s-$suffix"
daemon_ns="ruster-xdp-run-d-$suffix"
receiver_ns="ruster-xdp-run-r-$suffix"
sender_if="rxds$suffix"
lan_if="rxdl$suffix"
wan_if="rxdw$suffix"
receiver_if="rxdr$suffix"

lan_mac="02:00:00:00:00:01"
wan_mac="02:00:00:00:00:02"
receiver_mac="02:00:00:00:00:03"
sender_mac="02:00:00:00:00:04"

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
            echo "run-netns-xdp-run-e2e.sh: failed to disable IPv6 on host/$ipv6_sysctl_interface" >&2
            return 1
        fi
        if ! ipv6_sysctl_value=$(sysctl -n "$ipv6_sysctl_key"); then
            echo "run-netns-xdp-run-e2e.sh: failed to read back $ipv6_sysctl_key on host" >&2
            return 1
        fi
    else
        if ! ip netns exec "$ipv6_sysctl_scope" sysctl -w "$ipv6_sysctl_key=1" >/dev/null; then
            echo "run-netns-xdp-run-e2e.sh: failed to disable IPv6 on $ipv6_sysctl_scope/$ipv6_sysctl_interface" >&2
            return 1
        fi
        if ! ipv6_sysctl_value=$(ip netns exec "$ipv6_sysctl_scope" sysctl -n "$ipv6_sysctl_key"); then
            echo "run-netns-xdp-run-e2e.sh: failed to read back $ipv6_sysctl_key in $ipv6_sysctl_scope" >&2
            return 1
        fi
    fi

    if [ "$ipv6_sysctl_value" != 1 ]; then
        echo "run-netns-xdp-run-e2e.sh: $ipv6_sysctl_key read back as '$ipv6_sysctl_value', expected 1" >&2
        return 1
    fi
}

daemon_pid=""
server_pid=""

ns_exists()
{
    ip netns list | awk '{print $1}' | grep -Fqx "$1"
}

dump_logs()
{
    log_path=$1
    label=$2
    if [ -f "$log_path" ]; then
        echo "--- $label ($log_path) ---" >&2
        sed -n '1,260p' "$log_path" >&2 || true
    fi
}

cleanup()
{
    status=$?
    cleanup_status=0
    process_state=""
    details=""
    trap - 0 2 3 1 15
    trap '' 2 3 1 15

    for process in "$server_pid" "$daemon_pid"; do
        if [ -z "$process" ]; then
            continue
        fi
        if kill -0 "$process" >/dev/null 2>&1; then
            if ! kill -TERM "$process" >/dev/null 2>&1; then
                echo "cleanup: failed to send SIGTERM to process $process" >&2
                cleanup_status=1
            fi
            wait_loops=0
            while kill -0 "$process" >/dev/null 2>&1; do
                process_state=$(ps -o stat= -p "$process" 2>/dev/null || true)
                case "$process_state" in
                    Z*) break ;;
                esac
                if [ "$wait_loops" -ge 15 ]; then
                    break
                fi
                sleep 1
                wait_loops=$((wait_loops + 1))
            done
            if kill -0 "$process" >/dev/null 2>&1 &&
                case "$process_state" in Z*) false ;; *) true ;; esac
            then
                echo "cleanup: process $process did not stop after SIGTERM; sending SIGKILL" >&2
                if ! kill -KILL "$process" >/dev/null 2>&1; then
                    cleanup_status=1
                fi
                cleanup_status=1
            fi
        fi
        if ! wait "$process" >/dev/null 2>&1; then
            :
        fi
    done

    if ns_exists "$daemon_ns"; then
        for interface in "$lan_if" "$wan_if"; do
            if details=$(ip -n "$daemon_ns" -details link show dev "$interface" 2>&1); then
                if printf '%s\n' "$details" |
                    grep -Eq '(^|[[:space:]])prog/xdp([[:space:]]|$)'; then
                    echo "cleanup: XDP program remains on $daemon_ns/$interface" >&2
                    if ! ip -n "$daemon_ns" link set dev "$interface" xdp off >/dev/null 2>&1; then
                        echo "cleanup: failed to detach XDP from $daemon_ns/$interface" >&2
                        cleanup_status=1
                    fi
                    if details=$(ip -n "$daemon_ns" -details link show dev "$interface" 2>&1) &&
                        printf '%s\n' "$details" |
                        grep -Eq '(^|[[:space:]])prog/xdp([[:space:]]|$)'; then
                        echo "cleanup: XDP program is still present on $daemon_ns/$interface" >&2
                        cleanup_status=1
                    fi
                fi
            fi
        done
    fi

    for namespace in "$receiver_ns" "$daemon_ns" "$sender_ns"; do
        if ns_exists "$namespace"; then
            if ! ip netns del "$namespace"; then
                echo "cleanup: failed to delete network namespace $namespace" >&2
                cleanup_status=1
            fi
        fi
    done

    if [ "$status" -ne 0 ]; then
        dump_logs "$validate_log" "configuration validation log"
        dump_logs "$client_log" "sender client log"
        dump_logs "$server_log" "receiver server log"
        dump_logs "$daemon_log" "ruster daemon log"
    fi

    if ! rm -rf "$workdir"; then
        echo "cleanup: failed to remove temporary directory $workdir" >&2
        cleanup_status=1
    fi

    if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
        status=$cleanup_status
    fi
    exit "$status"
}

trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT
trap cleanup EXIT

for namespace in "$sender_ns" "$daemon_ns" "$receiver_ns"; do
    if ns_exists "$namespace"; then
        echo "generated namespace already exists: $namespace" >&2
        exit 1
    fi
done

for interface in "$sender_if" "$lan_if" "$wan_if" "$receiver_if"; do
    case "$interface" in
        *[!A-Za-z0-9_.-]*|????????????????*)
            echo "generated interface name is invalid or longer than 15 bytes: $interface" >&2
            exit 1
            ;;
    esac
    if ip link show dev "$interface" >/dev/null 2>&1; then
        echo "generated interface name collides with an existing link: $interface" >&2
        exit 1
    fi
done

cp "$repo_root/crates/control/tests/full-service.toml" "$config_path"
sed -i \
    -e "s/device = \"eth1\"/device = \"$wan_if\"/" \
    -e "s/device = \"eth0\"/device = \"$lan_if\"/" \
    "$config_path"
cat >>"$config_path" <<EOF

[backend]
kind = "af-xdp"
xskmap-max-entries = 1
bind-flags = 10
attach-mode = "skb"

[backend.umem]
frame-count = 4
frame-size = 2048
headroom = 0
rx-frames = 1
generated-frames = 3
raw-flags = 0

[backend.rings]
fill = 2
rx = 2
tx = 2
completion = 2

[[backend.resources]]
interface = "wan"
queue-id = 0

[[backend.resources]]
interface = "lan"
queue-id = 0
EOF

ip netns add "$sender_ns"
ip netns add "$daemon_ns"
ip netns add "$receiver_ns"

ip link add "$sender_if" type veth peer name "$lan_if"
ip link set dev "$sender_if" netns "$sender_ns"
ip link set dev "$lan_if" netns "$daemon_ns"
ip link add "$wan_if" type veth peer name "$receiver_if"
ip link set dev "$wan_if" netns "$daemon_ns"
ip link set dev "$receiver_if" netns "$receiver_ns"

disable_ipv6_on_interface "$sender_ns" "$sender_if"
disable_ipv6_on_interface "$daemon_ns" "$lan_if"
disable_ipv6_on_interface "$daemon_ns" "$wan_if"
disable_ipv6_on_interface "$receiver_ns" "$receiver_if"

ip -n "$sender_ns" link set dev lo up
ip -n "$daemon_ns" link set dev lo up
ip -n "$receiver_ns" link set dev lo up

ip -n "$sender_ns" link set dev "$sender_if" address "$sender_mac"
ip -n "$daemon_ns" link set dev "$lan_if" address "$lan_mac"
ip -n "$daemon_ns" link set dev "$wan_if" address "$wan_mac"
ip -n "$receiver_ns" link set dev "$receiver_if" address "$receiver_mac"

ip -n "$sender_ns" addr add 192.0.2.20/24 dev "$sender_if"
ip -n "$daemon_ns" addr add 192.0.2.1/24 dev "$lan_if"
ip -n "$daemon_ns" addr add 198.51.100.10/24 dev "$wan_if"
ip -n "$receiver_ns" addr add 198.51.100.1/24 dev "$receiver_if"

ip -n "$sender_ns" link set dev "$sender_if" up
ip -n "$daemon_ns" link set dev "$lan_if" up
ip -n "$daemon_ns" link set dev "$wan_if" up
ip -n "$receiver_ns" link set dev "$receiver_if" up

# Generic XDP receives the skb before the kernel's transmit checksum helper
# materializes a TCP checksum in the packet bytes.  Linux's v6.8
# tools/testing/selftests/bpf/test_xdp_features.sh disables tx-checksumming on
# both ends of its veth/XDP fixture for the same reason.  The four links here
# are the two endpoint TX paths and the two AF_XDP-facing links; keeping all of
# them off makes both request and response bytes wire-valid at the XDP hook.
ip netns exec "$sender_ns" ethtool -K "$sender_if" tx-checksumming off
ip netns exec "$daemon_ns" ethtool -K "$lan_if" tx-checksumming off
ip netns exec "$daemon_ns" ethtool -K "$wan_if" tx-checksumming off
ip netns exec "$receiver_ns" ethtool -K "$receiver_if" tx-checksumming off

ip -n "$sender_ns" route add default via 192.0.2.1 dev "$sender_if"
ip -n "$sender_ns" neigh replace 192.0.2.1 lladdr "$lan_mac" nud permanent dev "$sender_if"
ip -n "$receiver_ns" neigh replace 198.51.100.10 lladdr "$wan_mac" nud permanent dev "$receiver_if"

if ! ip netns exec "$daemon_ns" "$binary" validate "$config_path" >"$validate_log" 2>&1; then
    echo "ruster validate rejected the AF_XDP E2E configuration" >&2
    exit 1
fi

assert_no_xdp()
{
    interface=$1
    details=
    if ! details=$(ip -n "$daemon_ns" -details link show dev "$interface" 2>&1); then
        echo "cannot inspect $daemon_ns/$interface with ip link" >&2
        printf '%s\n' "$details" >&2
        return 1
    fi
    if printf '%s\n' "$details" |
        grep -Eq '(^|[[:space:]])prog/xdp([[:space:]]|$)'; then
        echo "an XDP program is already attached to $daemon_ns/$interface" >&2
        printf '%s\n' "$details" >&2
        return 1
    fi
}

assert_has_xdp()
{
    interface=$1
    details=
    if ! details=$(ip -n "$daemon_ns" -details link show dev "$interface" 2>&1); then
        echo "cannot inspect $daemon_ns/$interface with ip link" >&2
        printf '%s\n' "$details" >&2
        return 1
    fi
    if ! printf '%s\n' "$details" |
        grep -Eq '(^|[[:space:]])prog/xdp([[:space:]]|$)'; then
        echo "ruster did not attach an XDP program to $daemon_ns/$interface" >&2
        printf '%s\n' "$details" >&2
        return 1
    fi
}

assert_no_xdp "$lan_if"
assert_no_xdp "$wan_if"

ip netns exec "$daemon_ns" env \
    RUSTER_CONTROL_SOCKET="$control_socket" \
    RUSTER_OBSERVABILITY_INTERVAL_SECS=1 \
    "$binary" run "$config_path" >"$daemon_log" 2>&1 &
daemon_pid=$!

daemon_ready=0
wait_loops=1
while [ "$wait_loops" -le 300 ]; do
    if ! kill -0 "$daemon_pid" >/dev/null 2>&1; then
        daemon_status=0
        wait "$daemon_pid" || daemon_status=$?
        daemon_pid=""
        echo "ruster daemon exited before AF_XDP readiness (status=$daemon_status)" >&2
        exit 1
    fi
    if grep -Fq "bound interface name=lan device=$lan_if" "$daemon_log" &&
        grep -Fq "bound interface name=wan device=$wan_if" "$daemon_log"; then
        daemon_ready=1
        break
    fi
    sleep 0.1
    wait_loops=$((wait_loops + 1))
done
if [ "$daemon_ready" -ne 1 ]; then
    echo "ruster daemon did not report both bound AF_XDP interfaces" >&2
    exit 1
fi

assert_has_xdp "$lan_if"
assert_has_xdp "$wan_if"

ip netns exec "$receiver_ns" python3 -u -c '
import socket
import sys

expected = b"ruster-af-xdp-run-e2e"
response = b"ruster-af-xdp-run-e2e-ok"
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("198.51.100.1", 443))
listener.listen(1)
print("READY", flush=True)
connection, peer = listener.accept()
with connection:
    data = b""
    while len(data) < len(expected):
        chunk = connection.recv(len(expected) - len(data))
        if not chunk:
            print("short request from %r: %r" % (peer, data), file=sys.stderr)
            sys.exit(1)
        data += chunk
    if data != expected:
        print("unexpected request: %r" % (data,), file=sys.stderr)
        sys.exit(1)
    connection.sendall(response)
print("RECEIVED", flush=True)
listener.close()
' >"$server_log" 2>&1 &
server_pid=$!

server_ready=0
wait_loops=1
while [ "$wait_loops" -le 100 ]; do
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
        server_status=0
        wait "$server_pid" || server_status=$?
        server_pid=""
        echo "receiver TCP server exited before readiness (status=$server_status)" >&2
        exit 1
    fi
    if grep -Fq READY "$server_log"; then
        server_ready=1
        break
    fi
    sleep 0.1
    wait_loops=$((wait_loops + 1))
done
if [ "$server_ready" -ne 1 ]; then
    echo "receiver TCP server did not become ready" >&2
    exit 1
fi

if ! ip netns exec "$sender_ns" python3 -u -c '
import socket
import sys
import time

expected = b"ruster-af-xdp-run-e2e"
response = b"ruster-af-xdp-run-e2e-ok"
last_error = None
for attempt in range(240):
    connection = None
    try:
        connection = socket.create_connection(("198.51.100.1", 443), timeout=0.5)
        connection.settimeout(2.0)
        connection.sendall(expected)
        data = b""
        while len(data) < len(response):
            chunk = connection.recv(len(response) - len(data))
            if not chunk:
                raise RuntimeError("receiver closed before the complete response")
            data += chunk
        if data != response:
            raise RuntimeError("unexpected response: %r" % (data,))
        print("FORWARDED", flush=True)
        sys.exit(0)
    except (OSError, RuntimeError) as error:
        last_error = error
        time.sleep(0.1)
    finally:
        if connection is not None:
            connection.close()
print("TCP packet did not traverse the ruster daemon: %r" % (last_error,), file=sys.stderr)
sys.exit(1)
' >"$client_log" 2>&1; then
    echo "sender TCP traffic was not forwarded through ruster AF_XDP" >&2
    exit 1
fi
grep -Fq FORWARDED "$client_log"

server_status=0
wait "$server_pid" || server_status=$?
if [ "$server_status" -ne 0 ]; then
    server_pid=""
    echo "receiver TCP server failed after the forwarded packet (status=$server_status)" >&2
    exit 1
fi
server_pid=""

if ! kill -TERM "$daemon_pid"; then
    echo "failed to deliver SIGTERM to ruster daemon" >&2
    exit 1
fi
daemon_status=0
wait "$daemon_pid" || daemon_status=$?
daemon_pid=""
if [ "$daemon_status" -ne 0 ]; then
    echo "ruster daemon did not shut down successfully after SIGTERM (status=$daemon_status)" >&2
    exit 1
fi

grep -Fq "shutdown complete" "$daemon_log"
grep -Fq "backend_mode=af_xdp" "$daemon_log"
if ! grep -Eq 'forwarded=[1-9][0-9]*' "$daemon_log"; then
    echo "ruster observability did not record a forwarded packet" >&2
    exit 1
fi

assert_no_xdp "$lan_if"
assert_no_xdp "$wan_if"
echo "ruster AF_XDP daemon netns E2E forwarded a TCP packet and detached both XDP programs"
exit 0

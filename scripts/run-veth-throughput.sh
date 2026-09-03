#!/bin/sh

# This harness owns the veth lifecycle. The Rust integration tests own the
# packet sockets, data-path resources, and their sender threads.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
bench_tmpdir=

backend=af_packet
frame_size=60
duration_ms=3000
warmup_ms=100
window_ms=250
sender_threads=3
send_batch_size=8
cpu=

usage() {
    printf '%s\n' \
        "usage: $0 [--backend af_packet|af_xdp|both] [--frame-size N]" \
        "          [--duration-ms N] [--warmup-ms N] [--window-ms N]" \
        "          [--sender-threads N] [--send-batch-size N] [--cpu N]" \
        "" \
        "The result is veth_functional data and is not physical-NIC acceptance." \
        "Default sender config: sender_threads=3 send_batch_size=8."
}

fail() {
    printf 'run-veth-throughput.sh: %s\n' "$1" >&2
    exit 1
}

unsigned_integer() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

take_option_value() {
    option=$1
    if [ "$#" -lt 2 ]; then
        fail "$option requires a value"
    fi
    option_value=$2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --backend)
            take_option_value "$@"
            backend=$option_value
            shift 2
            ;;
        --backend=*)
            backend=${1#--backend=}
            shift
            ;;
        --frame-size)
            take_option_value "$@"
            frame_size=$option_value
            shift 2
            ;;
        --frame-size=*)
            frame_size=${1#--frame-size=}
            shift
            ;;
        --duration-ms)
            take_option_value "$@"
            duration_ms=$option_value
            shift 2
            ;;
        --duration-ms=*)
            duration_ms=${1#--duration-ms=}
            shift
            ;;
        --warmup-ms)
            take_option_value "$@"
            warmup_ms=$option_value
            shift 2
            ;;
        --warmup-ms=*)
            warmup_ms=${1#--warmup-ms=}
            shift
            ;;
        --window-ms)
            take_option_value "$@"
            window_ms=$option_value
            shift 2
            ;;
        --window-ms=*)
            window_ms=${1#--window-ms=}
            shift
            ;;
        --sender-threads)
            take_option_value "$@"
            sender_threads=$option_value
            shift 2
            ;;
        --sender-threads=*)
            sender_threads=${1#--sender-threads=}
            shift
            ;;
        --send-batch-size)
            take_option_value "$@"
            send_batch_size=$option_value
            shift 2
            ;;
        --send-batch-size=*)
            send_batch_size=${1#--send-batch-size=}
            shift
            ;;
        --cpu)
            take_option_value "$@"
            cpu=$option_value
            shift 2
            ;;
        --cpu=*)
            cpu=${1#--cpu=}
            shift
            ;;
        *)
            fail "unknown option: $1 (use --help)"
            ;;
    esac
done

case "$backend" in
    af_packet|af_xdp|both) ;;
    *) fail "backend must be af_packet, af_xdp, or both" ;;
esac

for numeric_option in frame_size duration_ms warmup_ms window_ms sender_threads send_batch_size; do
    case "$numeric_option" in
        frame_size) numeric_value=$frame_size ;;
        duration_ms) numeric_value=$duration_ms ;;
        warmup_ms) numeric_value=$warmup_ms ;;
        window_ms) numeric_value=$window_ms ;;
        sender_threads) numeric_value=$sender_threads ;;
        send_batch_size) numeric_value=$send_batch_size ;;
    esac
    if ! unsigned_integer "$numeric_value"; then
        fail "$numeric_option must be an unsigned integer"
    fi
done

if [ "$frame_size" -lt 60 ] || [ "$frame_size" -gt 1514 ]; then
    fail "frame size must be between 60 and 1514 bytes"
fi
if [ "$duration_ms" -eq 0 ]; then
    fail "duration must be greater than zero"
fi
if [ "$warmup_ms" -lt 20 ]; then
    fail "warmup must be at least 20 ms"
fi
if [ "$window_ms" -eq 0 ]; then
    fail "window must be greater than zero"
fi
if [ "$sender_threads" -lt 1 ] || [ "$sender_threads" -gt 16 ]; then
    fail "sender threads must be between 1 and 16"
fi
if [ "$send_batch_size" -lt 1 ] || [ "$send_batch_size" -gt 32 ]; then
    fail "send batch size must be between 1 and 32"
fi
if [ -n "$cpu" ] && ! unsigned_integer "$cpu"; then
    fail "cpu must be an unsigned integer"
fi

if [ "$(id -u)" -ne 0 ]; then
    fail "root is required; run it with sudo"
fi
command -v ip >/dev/null 2>&1 || fail "iproute2 (ip) is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"

case "${RUSTER_PRIVILEGED_E2E-}" in
    ''|1) ;;
    *) fail "RUSTER_PRIVILEGED_E2E must be 1 when set" ;;
esac

rx_interface="rvethr$$"
tx_interface="rvetht$$"
case "$rx_interface$tx_interface" in
    *[!A-Za-z0-9_.-]*) fail "generated veth name contains an invalid character" ;;
esac
case "$rx_interface" in
    ????????????????*) fail "generated receiver veth name is too long" ;;
esac
case "$tx_interface" in
    ????????????????*) fail "generated sender veth name is too long" ;;
esac

if ip link show dev "$rx_interface" >/dev/null 2>&1 ||
   ip link show dev "$tx_interface" >/dev/null 2>&1; then
    fail "generated veth name collides with an existing interface"
fi

veth_created=0
test_pid=
cleanup_running=0

detach_xdp() {
    interface=$1
    details=
    if details=$(ip -details link show dev "$interface" 2>/dev/null); then
        case "$details" in
            *prog/xdp*|*xdp*)
                if ! ip link set dev "$interface" xdp off; then
                    printf 'run-veth-throughput.sh: failed to detach XDP from %s\n' "$interface" >&2
                    return 1
                fi
                ;;
        esac
    else
        inspect_status=$?
        if [ "$inspect_status" -ne 1 ]; then
            printf 'run-veth-throughput.sh: failed to inspect %s for XDP cleanup\n' "$interface" >&2
            return 1
        fi
    fi
    return 0
}

delete_interface() {
    interface=$1
    if ip link show dev "$interface" >/dev/null 2>&1; then
        if ! ip link del "$interface"; then
            printf 'run-veth-throughput.sh: failed to delete veth %s\n' "$interface" >&2
            return 1
        fi
    else
        inspect_status=$?
        if [ "$inspect_status" -ne 1 ]; then
            printf 'run-veth-throughput.sh: failed to inspect veth %s during cleanup\n' "$interface" >&2
            return 1
        fi
    fi
    return 0
}

cleanup() {
    status=$1
    if [ "$cleanup_running" -eq 1 ]; then
        exit "$status"
    fi
    cleanup_running=1
    trap - 0
    trap '' INT TERM HUP QUIT
    cleanup_status=0

    if [ -n "$test_pid" ]; then
        if kill -0 "$test_pid" 2>/dev/null; then
            if ! kill "$test_pid" 2>/dev/null; then
                printf 'run-veth-throughput.sh: failed to stop test process %s\n' "$test_pid" >&2
                cleanup_status=1
            fi
        fi
        if wait "$test_pid" 2>/dev/null; then
            :
        else
            :
        fi
        test_pid=
    fi

    if [ "$veth_created" -eq 1 ]; then
        if ! detach_xdp "$rx_interface"; then
            cleanup_status=1
        fi
        if ! detach_xdp "$tx_interface"; then
            cleanup_status=1
        fi
        if ! delete_interface "$rx_interface"; then
            cleanup_status=1
        fi
        if ! delete_interface "$tx_interface"; then
            cleanup_status=1
        fi
    fi

    if [ -n "$bench_tmpdir" ]; then
        case "$bench_tmpdir" in
            /tmp/ruster-veth-throughput.*)
                if ! rm -rf -- "$bench_tmpdir"; then
                    printf 'run-veth-throughput.sh: failed to remove temporary directory %s\n' "$bench_tmpdir" >&2
                    cleanup_status=1
                fi
                ;;
            *)
                printf 'run-veth-throughput.sh: refusing to remove unexpected temporary path %s\n' "$bench_tmpdir" >&2
                cleanup_status=1
                ;;
        esac
        bench_tmpdir=
    fi

    if [ "$cleanup_status" -ne 0 ]; then
        printf 'run-veth-throughput.sh: cleanup failed\n' >&2
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

bench_tmpdir=$(mktemp -d /tmp/ruster-veth-throughput.XXXXXX)
case "$bench_tmpdir" in
    /tmp/ruster-veth-throughput.*) ;;
    *) fail "mktemp returned an unexpected path: $bench_tmpdir" ;;
esac
export TMPDIR="$bench_tmpdir"
if [ -n "$cpu" ]; then
    export RUSTER_THROUGHPUT_CPU="$cpu"
fi
CDPATH= cd -- "$repo_root"

ip link add "$rx_interface" type veth peer name "$tx_interface"
veth_created=1
ip link set dev "$rx_interface" up
ip link set dev "$tx_interface" up

run_backend_test() {
    selected_backend=$1
    package=$2
    test_name=$3
    RUSTER_PRIVILEGED_E2E=1 \
    RUSTER_VETH_RX_IFACE="$rx_interface" \
    RUSTER_VETH_TX_IFACE="$tx_interface" \
    RUSTER_THROUGHPUT_BACKEND="$selected_backend" \
    RUSTER_THROUGHPUT_FRAME_SIZE="$frame_size" \
    RUSTER_THROUGHPUT_DURATION_MS="$duration_ms" \
    RUSTER_THROUGHPUT_WARMUP_MS="$warmup_ms" \
    RUSTER_THROUGHPUT_WINDOW_MS="$window_ms" \
    RUSTER_THROUGHPUT_SENDER_THREADS="$sender_threads" \
    RUSTER_THROUGHPUT_SEND_BATCH_SIZE="$send_batch_size" \
    cargo test --release -p "$package" --test "$test_name" --locked -- --ignored --nocapture &
    test_pid=$!
    if wait "$test_pid"; then
        test_status=0
    else
        test_status=$?
    fi
    test_pid=
    return "$test_status"
}

overall_status=0
case "$backend" in
    af_packet)
        if run_backend_test af_packet ruster-io-afpacket veth_throughput; then
            :
        else
            overall_status=$?
        fi
        ;;
    af_xdp)
        if run_backend_test af_xdp ruster-io-xdp-native veth_throughput; then
            :
        else
            overall_status=$?
        fi
        ;;
    both)
        if run_backend_test af_packet ruster-io-afpacket veth_throughput; then
            if run_backend_test af_xdp ruster-io-xdp-native veth_throughput; then
                :
            else
                overall_status=$?
            fi
        else
            overall_status=$?
        fi
        ;;
esac

exit "$overall_status"

#!/bin/sh

# Run the physical-NIC acceptance test against one explicitly named
# interface.  This script is deliberately read-only with respect to NIC
# configuration: it never creates a link and never writes IRQ/RSS settings.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

interface=${RUSTER_NIC_ACCEPTANCE_IFACE-}
cpu=
frame_size=60
duration_ms=3000
warmup_ms=100

usage() {
    printf '%s\n' \
        "usage: $0 --interface IFACE [--cpu N] [--frame-size N]" \
        "          [--duration-ms N] [--warmup-ms N]" \
        "" \
        "The interface is explicit; this entry point never creates a veth pair." \
        "IRQ affinity and RSS configuration are read and verified, never written."
}

fail() {
    printf 'run-nic-acceptance.sh: %s\n' "$1" >&2
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
        --interface)
            take_option_value "$@"
            interface=$option_value
            shift 2
            ;;
        --interface=*)
            interface=${1#--interface=}
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
        *)
            fail "unknown option: $1 (use --help)"
            ;;
    esac
done

if [ -z "$interface" ]; then
    fail "an explicit interface is required; pass --interface IFACE or set RUSTER_NIC_ACCEPTANCE_IFACE"
fi
case "$interface" in
    *[!A-Za-z0-9_.-]*) fail "interface name contains an unsafe character: $interface" ;;
esac
if [ "${#interface}" -gt 15 ]; then
    fail "interface name is longer than Linux IFNAMSIZ-1: $interface"
fi
for numeric_option in frame_size duration_ms warmup_ms; do
    case "$numeric_option" in
        frame_size) numeric_value=$frame_size ;;
        duration_ms) numeric_value=$duration_ms ;;
        warmup_ms) numeric_value=$warmup_ms ;;
    esac
    if ! unsigned_integer "$numeric_value"; then
        fail "$numeric_option must be an unsigned integer"
    fi
done
if [ -n "$cpu" ] && ! unsigned_integer "$cpu"; then
    fail "cpu must be an unsigned integer"
fi
if [ "$frame_size" -lt 60 ] || [ "$frame_size" -gt 1514 ]; then
    fail "frame size must be between 60 and 1514 bytes"
fi
if [ "$duration_ms" -eq 0 ]; then
    fail "duration must be greater than zero"
fi
if [ "$warmup_ms" -lt 20 ]; then
    fail "warmup must be at least 20 ms"
fi

if [ "$(id -u)" -ne 0 ]; then
    fail "root (uid 0) and CAP_NET_RAW are required; rerun with sudo"
fi
command -v cargo >/dev/null 2>&1 || fail "cargo is required"

if [ -n "$cpu" ]; then
    export RUSTER_THROUGHPUT_CPU=$cpu
else
    unset RUSTER_THROUGHPUT_CPU
fi
export RUSTER_NIC_ACCEPTANCE_IFACE=$interface
export RUSTER_NIC_ACCEPTANCE_FRAME_SIZE=$frame_size
export RUSTER_NIC_ACCEPTANCE_DURATION_MS=$duration_ms
export RUSTER_NIC_ACCEPTANCE_WARMUP_MS=$warmup_ms
export RUSTER_NIC_ACCEPTANCE_GENERATE_TRAFFIC=1
export RUSTER_PRIVILEGED_E2E=1

CDPATH= cd -- "$repo_root"
exec cargo test --release -p ruster-io-afpacket --test nic_acceptance --locked -- --ignored --nocapture

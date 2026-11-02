#!/bin/sh
# Environment probe for the privileged AF_XDP smokes (M2 S11, `XDP veth`
# CI job). It proves that this host can really run them, and FAILS (exit 1
# with one typed `code=`) instead of letting a later step skip or pass
# vacuously:
#
#   PROBE_TOOL_MISSING    ip, python3, od, ethtool, ps, sudo, uname, sysctl
#   PROBE_SUDO            passwordless `sudo -n` is unavailable
#   PROBE_KERNEL_TOO_OLD  kernel older than 5.9 (XDP bpf_link)
#   PROBE_CAPABILITIES    root under sudo lacks CAP_NET_ADMIN, CAP_NET_RAW,
#                         CAP_IPC_LOCK, or CAP_BPF+CAP_PERFMON/CAP_SYS_ADMIN
#   PROBE_IPROUTE_LIBBPF  iproute2 without libbpf (cannot load an object)
#   PROBE_NETNS           `ip netns add`/`exec` does not work
#   PROBE_VETH            a veth pair cannot be created inside the netns
#   PROBE_SYSCTL          net.ipv4.ip_forward or conf/<dev>/forwarding
#                         cannot be read and written inside the netns
#   PROBE_AF_XDP_SOCKET   socket(AF_XDP, SOCK_RAW) fails inside the netns
#   PROBE_XDP_GENERIC     a generic (skb) XDP program cannot be attached
#   PROBE_XDP_NATIVE      a native (driver) XDP program cannot be attached
#                         to the veth
#   PROBE_CLEANUP         the throwaway netns survived its deletion
#
# Same discipline as the smokes: everything happens inside one throwaway
# namespace `ruster-probe-<pid>-<random>` (the veth pair is created with
# `ip -n`, so it never exists in the initial namespace) that is always
# deleted. No host interface, host-wide sysctl, or bpftool is touched.
set -eu

fail() {
    code=$1
    shift
    echo "priv-xdp-probe: FAIL code=$code: $*" >&2
    if [ -n "${GITHUB_ACTIONS-}" ]; then
        echo "::error title=XDP veth probe::code=$code: $*"
    fi
    exit 1
}

for tool in ip python3 od ethtool ps sudo uname sysctl; do
    command -v "$tool" >/dev/null 2>&1 || fail PROBE_TOOL_MISSING "missing $tool"
done
sudo -n true 2>/dev/null || fail PROBE_SUDO "passwordless sudo -n is required"
here=$(cd "$(dirname "$0")" && pwd)

release=$(uname -r)
major=${release%%.*}
rest=${release#*.}
minor=${rest%%[!0-9]*}
case $major$minor in
'' | *[!0-9]*) fail PROBE_KERNEL_TOO_OLD "cannot parse kernel release $release" ;;
esac
if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 9 ]; }; then
    fail PROBE_KERNEL_TOO_OLD "kernel $release is older than 5.9"
fi

# Effective capabilities of a root process under sudo.
caps=$(sudo -n sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)
python3 -I -c '
import sys
eff = int(sys.argv[1], 16)
has = lambda bit: eff >> bit & 1
# CAP_NET_ADMIN 12, CAP_NET_RAW 13, CAP_IPC_LOCK 14, CAP_SYS_ADMIN 21,
# CAP_PERFMON 38, CAP_BPF 39
ok = has(12) and has(13) and has(14) and (has(21) or (has(38) and has(39)))
sys.exit(0 if ok else 1)
' "$caps" || fail PROBE_CAPABILITIES "CapEff=$caps under sudo"

ip -V | grep -q libbpf || fail PROBE_IPROUTE_LIBBPF "$(ip -V)"

suffix=$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')
netns="ruster-probe-$$-$suffix"
created=
work=

cleanup() {
    if [ -n "$created" ]; then
        sudo -n ip netns del "$netns" 2>/dev/null || true
        created=
    fi
    if [ -n "$work" ]; then
        rm -rf "$work"
    fi
}
# The trap is in place before anything is created.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
work=$(mktemp -d "${TMPDIR:-/tmp}/ruster-priv-probe.XXXXXX")

# A pre-existing namespace of this name is never adopted or deleted.
sudo -n ip netns add "$netns" 2>"$work/err" ||
    fail PROBE_NETNS "ip netns add: $(cat "$work/err")"
created=1
in_netns() {
    sudo -n ip netns exec "$netns" "$@"
}
in_netns true 2>"$work/err" || fail PROBE_NETNS "ip netns exec: $(cat "$work/err")"
# Both links must be real namespace ids (`net:[<inode>]`) before they are
# compared, so a failed readlink cannot pass as "different".
initial_ns=$(sudo -n readlink /proc/1/ns/net) || initial_ns=
probe_ns=$(in_netns readlink /proc/self/ns/net) || probe_ns=
for id in "$initial_ns" "$probe_ns"; do
    case $id in
    net:\[[0-9]*\]) ;;
    *) fail PROBE_NETNS "unexpected namespace id '$id'" ;;
    esac
done
[ "$initial_ns" != "$probe_ns" ] ||
    fail PROBE_NETNS "ip netns exec stayed in the initial namespace ($probe_ns)"

sudo -n ip -n "$netns" link add rprobe0 numtxqueues 1 numrxqueues 1 type veth \
    peer name rprobe1 numtxqueues 1 numrxqueues 1 2>"$work/err" ||
    fail PROBE_VETH "ip link add type veth: $(cat "$work/err")"
for dev in rprobe0 rprobe1; do
    sudo -n ip -n "$netns" link set "$dev" up 2>"$work/err" ||
        fail PROBE_VETH "ip link set $dev up: $(cat "$work/err")"
done
if ip link show dev rprobe0 >/dev/null 2>&1; then
    fail PROBE_VETH "rprobe0 is visible in the initial namespace"
fi

for key in net.ipv4.ip_forward net.ipv4.conf.rprobe0.forwarding; do
    in_netns sysctl -qw "$key=1" 2>"$work/err" ||
        fail PROBE_SYSCTL "write $key: $(cat "$work/err")"
    [ "$(in_netns sysctl -n "$key")" = 1 ] || fail PROBE_SYSCTL "$key did not read back 1"
    in_netns sysctl -qw "$key=0" 2>"$work/err" ||
        fail PROBE_SYSCTL "write $key: $(cat "$work/err")"
done

# AF_XDP is address family 44 (Linux UAPI). Creating the socket proves the
# kernel has AF_XDP (CONFIG_XDP_SOCKETS) and that root inside the netns may
# open one; binding it to a queue is left to the smokes.
in_netns python3 -I -c '
import socket
socket.socket(44, socket.SOCK_RAW, 0).close()
' 2>"$work/err" || fail PROBE_AF_XDP_SOCKET "$(tail -n 1 "$work/err")"

python3 -I "$here/priv-xdp-foreign-elf.py" "$work/pass.o"
xdp_attached() {
    sudo -n ip -n "$netns" -details link show dev rprobe0 | grep -q 'prog/xdp'
}
for mode in xdpgeneric xdpdrv; do
    case $mode in
    xdpgeneric) code=PROBE_XDP_GENERIC ;;
    *) code=PROBE_XDP_NATIVE ;;
    esac
    sudo -n ip -n "$netns" link set dev rprobe0 "$mode" obj "$work/pass.o" sec xdp \
        2>"$work/err" || fail "$code" "attach: $(tail -n 3 "$work/err" | tr '\n' ' ')"
    xdp_attached || fail "$code" "no program attached after $mode"
    sudo -n ip -n "$netns" link set dev rprobe0 "$mode" off 2>"$work/err" ||
        fail "$code" "detach: $(cat "$work/err")"
    ! xdp_attached || fail "$code" "program left attached after $mode off"
done

cleanup
trap - EXIT
if sudo -n ip netns list | grep -qx "$netns\( .*\)\{0,1\}"; then
    fail PROBE_CLEANUP "namespace $netns survived cleanup"
fi
echo "priv-xdp-probe: ok kernel=$release netns veth sysctl af_xdp xdpgeneric xdpdrv" \
    "(namespace $netns removed)"

#!/bin/sh
# Privileged AF_XDP smoke: native session (M2 S1, X00C), XDP program /
# bpf_link lifecycle (M2 S2, X00D), the RX/Fill engine (M2 S3, X01), and
# same-frame TX/Completion with shutdown drain (M2 S4, X02).
#
# Builds the test binary as the invoking user, then with `sudo -n` creates a
# dedicated network namespace holding its own two-queue veth pair, runs the
# prebuilt test inside that namespace phase by phase with RUSTER_PRIV_XDP=1,
# and always deletes the namespace (which destroys both veth ends and
# detaches every XDP program on them). No command touches an interface
# outside the namespace: the veth pair is created with `ip -n`, so it never
# exists in the initial namespace, and every `ip` call below is `ip -n` or
# runs under `ip netns exec`. Any missing privilege or tool fails.
#
# Phases:
#   session  copy/auto session, EBUSY/EINVAL/ENODEV (X00C)
#   attach   native attach, peer frame reaches the RX ring, second attach
#            refused with ExistingProgram, detach, generic attach, close
#   engine   RX/Fill engine over the live mappings: peer frames pass
#            descriptor validation and are lent, recycled, and refilled (X01)
#   tx       the peer's ARP request is rewritten in place into a reply,
#            transmitted from the same UMEM frame out the same veth, learned
#            by the peer (ip neigh), completed, and drained on close (X02)
#   foreign  a netlink-attached xdpgeneric program loaded with `ip` is
#            refused in both modes and left untouched (same program id)
#   holder   attach in a separate process, SIGKILL it, link auto-detaches
set -eu

for tool in cargo ip sudo python3 od; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "priv-xdp-smoke: missing $tool" >&2
        exit 1
    }
done
sudo -n true || {
    echo "priv-xdp-smoke: passwordless sudo is required" >&2
    exit 1
}
here=$(cd "$(dirname "$0")" && pwd)

binary=$(cargo test --locked -p ruster-io-xdp-native --test priv_xdp_session --no-run \
    --message-format=json |
    sed -n 's/.*"executable":"\([^"]*priv_xdp_session[^"]*\)".*/\1/p' | tail -n 1)
test -x "$binary" || {
    echo "priv-xdp-smoke: test binary not found" >&2
    exit 1
}

# A pid plus 32 random bits names the namespace uniquely. A pre-existing
# namespace of that name is never adopted or deleted: `ip netns add` fails
# first, before the cleanup trap that owns the namespace is installed.
suffix=$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')
netns="ruster-x00c-$$-$suffix"
device=rx00c0
peer=rx00c1
work=$(mktemp -d "${TMPDIR:-/tmp}/ruster-priv-xdp.XXXXXX")
binary_path=$(readlink -f "$binary")
holder_pid=
launcher=

# True only if `$1` is a live process running the prebuilt test binary.
is_holder() {
    [ -n "$1" ] && [ "$(sudo -n readlink "/proc/$1/exe" 2>/dev/null)" = "$binary_path" ]
}

ready="$work/holder.pid"

cleanup() {
    if [ -n "$launcher" ] && [ -z "$holder_pid" ] && [ -s "$ready" ]; then
        # A holder that published its pid after a failed check or timeout.
        holder_pid=$(tr -cd '0-9' <"$ready")
    fi
    # Re-verify right before the kill: never signal a pid that is not the
    # test binary (it may have exited and the number been reused).
    if is_holder "$holder_pid"; then
        sudo -n kill -KILL "$holder_pid" 2>/dev/null || true
    fi
    holder_pid=
    if [ -n "$launcher" ]; then
        # Reap the launcher so no holder outlives the script. A holder that
        # never published a pid exits by itself within 30 seconds.
        wait "$launcher" 2>/dev/null || true
        launcher=
    fi
    sudo -n ip netns del "$netns" 2>/dev/null || true
    rm -rf "$work"
}

if ! sudo -n ip netns add "$netns"; then
    echo "priv-xdp-smoke: cannot create $netns (already exists?); not touching it" >&2
    rm -rf "$work"
    exit 1
fi
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

in_netns() {
    sudo -n ip netns exec "$netns" "$@"
}

# Two queues per end: native veth XDP needs RX queues >= the peer's TX
# queues, and a second socket on queue 1 exercises a second attach.
sudo -n ip -n "$netns" link add "$device" numtxqueues 2 numrxqueues 2 type veth \
    peer name "$peer" numtxqueues 2 numrxqueues 2
sudo -n ip -n "$netns" link set "$device" up
sudo -n ip -n "$netns" link set "$peer" up
# TEST-NET-1 source for frames sent from the peer end; the device itself
# has no address, so ARP requests go unanswered and repeat.
sudo -n ip -n "$netns" address add 192.0.2.2/24 dev "$peer"

run_phase() {
    phase=$1
    marker=$2
    shift 2
    log="$work/$phase.log"
    status=0
    in_netns env \
        RUSTER_PRIV_XDP=1 \
        RUSTER_PRIV_XDP_PHASE="$phase" \
        RUSTER_PRIV_XDP_NETNS="$netns" \
        RUSTER_PRIV_XDP_DEVICE="$device" \
        RUSTER_PRIV_XDP_PEER="$peer" \
        "$binary" --exact "$@" --nocapture --test-threads=1 >"$log" 2>&1 || status=$?
    cat "$log"
    test "$status" -eq 0 || {
        echo "priv-xdp-smoke: phase $phase failed with status $status" >&2
        exit 1
    }
    grep -q "$marker: .* verified$" "$log" || {
        echo "priv-xdp-smoke: phase $phase did not report $marker" >&2
        exit 1
    }
}

xdp_prog() {
    # Prints "<mode> <id>" of the program attached to the device, or nothing.
    # The link line names the mode (xdp, xdpgeneric); the details line is
    # "prog/xdp id N ..." in either mode.
    sudo -n ip -n "$netns" -details link show dev "$device" | awk '
        NR == 1 { for (i = 1; i <= NF; i++) if ($i ~ /^xdp(generic|offload|multi)?$/) mode = $i }
        { for (i = 1; i < NF; i++) if ($i ~ /^prog\/xdp/ && $(i + 1) == "id") id = $(i + 2) }
        END { if (id != "") print mode " " id }'
}

run_phase session priv_xdp_session priv_xdp_session_opens_copy_mode_on_netns_veth
run_phase attach priv_xdp_attach \
    priv_xdp_attach_redirects_refuses_second_and_detaches_on_netns_veth
test -z "$(xdp_prog)" || {
    echo "priv-xdp-smoke: program left attached after the attach phase" >&2
    exit 1
}
run_phase engine priv_xdp_engine priv_xdp_engine_validates_and_recycles_peer_frames
test -z "$(xdp_prog)" || {
    echo "priv-xdp-smoke: program left attached after the engine phase" >&2
    exit 1
}
run_phase tx priv_xdp_tx \
    priv_xdp_tx_reflects_peer_frame_completes_and_drains_on_netns_veth
test -z "$(xdp_prog)" || {
    echo "priv-xdp-smoke: program left attached after the tx phase" >&2
    exit 1
}

# Foreign program: a compiler-free XDP_PASS object attached through netlink.
python3 -I "$here/priv-xdp-foreign-elf.py" "$work/foreign.o"
sudo -n ip -n "$netns" link set dev "$device" xdpgeneric obj "$work/foreign.o" sec xdp
foreign=$(xdp_prog)
case $foreign in
xdpgeneric\ [0-9]*) ;;
*)
    echo "priv-xdp-smoke: foreign program did not attach" >&2
    exit 1
    ;;
esac
run_phase foreign priv_xdp_foreign \
    priv_xdp_attach_refuses_foreign_program_and_leaves_it_untouched
test "$(xdp_prog)" = "$foreign" || {
    echo "priv-xdp-smoke: foreign program changed" >&2
    exit 1
}
if command -v bpftool >/dev/null 2>&1; then
    in_netns bpftool net show dev "$device"
fi
sudo -n ip -n "$netns" link set dev "$device" xdpgeneric off
test -z "$(xdp_prog)" || {
    echo "priv-xdp-smoke: cannot remove the foreign program" >&2
    exit 1
}

# Holder: attach in a separate process, then SIGKILL it.
in_netns env \
    RUSTER_PRIV_XDP=1 \
    RUSTER_PRIV_XDP_PHASE=holder \
    RUSTER_PRIV_XDP_NETNS="$netns" \
    RUSTER_PRIV_XDP_DEVICE="$device" \
    RUSTER_PRIV_XDP_READY="$ready" \
    "$binary" --exact priv_xdp_attach_holder_waits_for_sigkill \
    --nocapture --test-threads=1 >"$work/holder.log" 2>&1 &
launcher=$!
tries=0
# The holder publishes the file by rename, so it is complete once present.
while [ ! -s "$ready" ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 200 ]; then
        cat "$work/holder.log" >&2
        echo "priv-xdp-smoke: holder did not attach within 10 seconds" >&2
        exit 1
    fi
    sleep 0.05
done
candidate=$(tr -cd '0-9' <"$ready")
# Adopt the pid only once it is proven to be the prebuilt test binary.
is_holder "$candidate" || {
    echo "priv-xdp-smoke: holder pid does not belong to the test binary" >&2
    exit 1
}
holder_pid=$candidate
case $(xdp_prog) in
xdp\ [0-9]*) ;;
*)
    echo "priv-xdp-smoke: holder link not attached" >&2
    exit 1
    ;;
esac
if command -v bpftool >/dev/null 2>&1; then
    # Netlink query of this namespace's device only.
    in_netns bpftool net show dev "$device"
fi
is_holder "$holder_pid" || {
    echo "priv-xdp-smoke: holder exited before SIGKILL" >&2
    exit 1
}
sudo -n kill -KILL "$holder_pid"
holder_pid=
wait "$launcher" 2>/dev/null || true
launcher=
tries=0
while [ -n "$(xdp_prog)" ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ]; then
        echo "priv-xdp-smoke: link survived SIGKILL of its owner" >&2
        exit 1
    fi
    sleep 0.02
done
echo "priv_xdp_holder: link auto-detached after SIGKILL verified"

cleanup
trap - EXIT
if sudo -n ip netns list | grep -qx "$netns\( .*\)\{0,1\}"; then
    echo "priv-xdp-smoke: namespace $netns survived cleanup" >&2
    exit 1
fi
echo "priv-xdp-smoke: ok (namespace $netns removed)"

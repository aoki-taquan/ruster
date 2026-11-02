#!/bin/sh
# Privileged AF_PACKET smoke (AP3): the live `AfPacketIo` adapter on two
# veth ports forwards a frame through core, completes a generated burst,
# recovers from a link flap through the owed kick, releases a failed open,
# drains, and closes.
#
# Builds the test binary as the invoking user, then with `sudo -n` creates a
# dedicated network namespace holding its own two veth pairs, runs the
# prebuilt test inside that namespace with RUSTER_PRIV_AFPACKET=1, and
# always deletes the namespace (which destroys every veth end). No command
# touches an interface outside the namespace: the veth pairs are created
# with `ip -n`, so they never exist in the initial namespace, and every other
# command runs under `ip -n` or `ip netns exec`. Any missing privilege or
# tool fails; nothing skips.
set -eu

# RUSTER_REQUIRE_PRIV=1 (the `XDP veth` CI job) is passed to the privileged
# test, which then fails instead of skipping. Empty counts as unset.
case ${RUSTER_REQUIRE_PRIV-} in
"" | 1) ;;
*)
    echo "priv-afpacket-smoke: RUSTER_REQUIRE_PRIV must be 1 or unset" >&2
    exit 1
    ;;
esac

for tool in cargo ip sudo python3 od; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "priv-afpacket-smoke: missing $tool" >&2
        exit 1
    }
done
sudo -n true || {
    echo "priv-afpacket-smoke: passwordless sudo is required" >&2
    exit 1
}

binary=$(cargo test --locked -p ruster-io-afpacket --test priv_afpacket --no-run \
    --message-format=json |
    sed -n 's/.*"executable":"\([^"]*priv_afpacket[^"]*\)".*/\1/p' | tail -n 1)
test -x "$binary" || {
    echo "priv-afpacket-smoke: test binary not found" >&2
    exit 1
}

# Every privileged test must be wired here: a new `priv_afpacket_*` test
# that is not listed fails the smoke instead of never running.
wired='priv_afpacket_forwards_between_two_veth_ports_through_core_and_drains
priv_afpacket_gate_fails_instead_of_skipping_when_required'
listed=$("$binary" --list --format=terse | sed -n 's/^\(priv_afpacket_[a-z0-9_]*\): test$/\1/p' | LC_ALL=C sort)
[ "$listed" = "$(printf '%s\n' "$wired" | LC_ALL=C sort)" ] || {
    echo "priv-afpacket-smoke: privileged tests differ from the wired list" >&2
    printf 'listed:\n%s\nwired:\n%s\n' "$listed" "$wired" >&2
    exit 1
}

suffix=$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')
netns="ruster-ap3-$$-$suffix"
fwd_a=rap3a0
fwd_a_peer=rap3a1
fwd_b=rap3b0
fwd_b_peer=rap3b1
work=$(mktemp -d "${TMPDIR:-/tmp}/ruster-priv-afpacket.XXXXXX")

cleanup() {
    sudo -n ip netns del "$netns" 2>/dev/null || true
    rm -rf "$work"
}

# A pre-existing namespace of that name is never adopted or deleted:
# `ip netns add` fails first, before the cleanup trap is installed.
if ! sudo -n ip netns add "$netns"; then
    echo "priv-afpacket-smoke: cannot create $netns (already exists?); not touching it" >&2
    rm -rf "$work"
    exit 1
fi
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

in_netns() {
    sudo -n ip netns exec "$netns" "$@"
}

# IPv6 off inside the namespace only, so the peers' ND/MLD chatter does not
# end the idle wait; the router ports carry no kernel address at all.
in_netns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
for pair in "$fwd_a $fwd_a_peer" "$fwd_b $fwd_b_peer"; do
    set -- $pair
    sudo -n ip -n "$netns" link add "$1" type veth peer name "$2"
    sudo -n ip -n "$netns" link set "$1" up
    sudo -n ip -n "$netns" link set "$2" up
done
# The kernel must not route between the router ports itself: AF_PACKET
# only copies frames, the kernel stack still sees them. A new namespace may
# inherit forwarding from the initial one (devconf_inherit_init_net, e.g. on
# hosts running Docker), so switch it off here (namespace-scoped) and check.
in_netns sysctl -q -w net.ipv4.ip_forward=0
test "$(in_netns sysctl -n net.ipv4.ip_forward)" = 0 || {
    echo "priv-afpacket-smoke: cannot turn IPv4 forwarding off in the namespace" >&2
    exit 1
}

log="$work/adapter.log"
status=0
in_netns env \
    ${RUSTER_REQUIRE_PRIV:+"RUSTER_REQUIRE_PRIV=$RUSTER_REQUIRE_PRIV"} \
    RUSTER_PRIV_AFPACKET=1 \
    RUSTER_PRIV_AFPACKET_NETNS="$netns" \
    RUSTER_PRIV_AFPACKET_FWD_A="$fwd_a" \
    RUSTER_PRIV_AFPACKET_FWD_A_PEER="$fwd_a_peer" \
    RUSTER_PRIV_AFPACKET_FWD_B="$fwd_b" \
    RUSTER_PRIV_AFPACKET_FWD_B_PEER="$fwd_b_peer" \
    "$binary" --exact priv_afpacket_forwards_between_two_veth_ports_through_core_and_drains \
    --nocapture --test-threads=1 >"$log" 2>&1 || status=$?
cat "$log"
test "$status" -eq 0 || {
    echo "priv-afpacket-smoke: adapter phase failed with status $status" >&2
    exit 1
}
grep -q '^test result: ok\. 1 passed;' "$log" || {
    echo "priv-afpacket-smoke: the adapter test did not run exactly once" >&2
    exit 1
}
for marker in priv_afpacket_idle_wait priv_afpacket_adapter; do
    grep -q "$marker: .*" "$log" || {
        echo "priv-afpacket-smoke: missing $marker" >&2
        exit 1
    }
done
grep -q "priv_afpacket_adapter: .* verified$" "$log" || {
    echo "priv-afpacket-smoke: adapter phase did not report verified" >&2
    exit 1
}
echo "priv-afpacket-smoke: ok"

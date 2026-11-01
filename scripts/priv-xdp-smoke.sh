#!/bin/sh
# Privileged AF_XDP native-session smoke (M2 S1, X00C).
#
# Builds the test binary as the invoking user, then with `sudo -n` creates a
# dedicated network namespace holding its own veth pair, runs the prebuilt
# test inside that namespace with RUSTER_PRIV_XDP=1, and always deletes the
# namespace (which destroys both veth ends). No command touches an interface
# outside the namespace: the veth pair is created with `ip -n`, so it never
# exists in the initial namespace. Any missing privilege or tool fails.
set -eu

for tool in cargo ip sudo; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "priv-xdp-smoke: missing $tool" >&2
        exit 1
    }
done
sudo -n true || {
    echo "priv-xdp-smoke: passwordless sudo is required" >&2
    exit 1
}

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

cleanup() {
    sudo -n ip netns del "$netns" 2>/dev/null || true
}

if ! sudo -n ip netns add "$netns"; then
    echo "priv-xdp-smoke: cannot create $netns (already exists?); not touching it" >&2
    exit 1
fi
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

sudo -n ip -n "$netns" link add "$device" type veth peer name "$peer"
sudo -n ip -n "$netns" link set "$device" up
sudo -n ip -n "$netns" link set "$peer" up

sudo -n ip netns exec "$netns" env \
    RUSTER_PRIV_XDP=1 \
    RUSTER_PRIV_XDP_NETNS="$netns" \
    RUSTER_PRIV_XDP_DEVICE="$device" \
    "$binary" --exact priv_xdp_session_opens_copy_mode_on_netns_veth \
    --nocapture --test-threads=1

cleanup
trap - EXIT
if sudo -n ip netns list | grep -qx "$netns\( .*\)\{0,1\}"; then
    echo "priv-xdp-smoke: namespace $netns survived cleanup" >&2
    exit 1
fi
echo "priv-xdp-smoke: ok (namespace $netns removed)"

#!/usr/bin/env bash
# BGP through bird-rs: the router's bird-rs, set up by ruster-bird from confd's bird
# part (routing-daemon = "bird-rs"), learns prefixes from a neighbouring bird-rs on
# the WAN and gives them to ribd itself (protocol ruster, source bird); ribd puts
# them in the FE, and a LAN host reaches a host behind the neighbour over IPv4 and
# IPv6. The router announces the LAN's prefixes back, the IPv6 one with the FE
# port's link-local next hop. A configuration bird-rs cannot read is refused, and
# a withdrawn prefix leaves the FE.
#
#   lan (192.0.2.10) -- [r-lan | router | r-wan 198.51.100.1] -- peer (198.51.100.10,
#     AS 65002, bird-rs) -- far (203.0.113.10, 2001:db8:203::10)
#
# Needs bird-rs and birdc-rs: BIRD_RS is the directory that holds them (exit 77,
# skipped, without). Run as root, after `cargo build`:
#   sudo BIRD_RS=<dir> scripts/netns-bird-bgp.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
bird=${BIRD_RS:-}
if [[ -z "$bird" || ! -x "$bird/bird-rs" || ! -x "$bird/birdc-rs" ]]; then
  echo "SKIP: give BIRD_RS, the directory of bird-rs and birdc-rs" >&2
  exit 77
fi
bird=$(realpath "$bird")

tag=rbb$$
lan=$tag-lan peer=$tag-peer far=$tag-far router=$tag-r
work=$(mktemp -d)
chmod 0755 "$work"
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$peer" "$far" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do [[ -e "$log" ]] && { echo "== $log"; tail -n 40 "$log"; }; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$lan" "$peer" "$far" "$router"; do ip netns add "$ns"; done
link() { # host-ns router-dev router-mac host-ip/len host-ip6/len
  ip link add h0 netns "$1" type veth peer name "$2" netns "$router"
  nsx "$router" sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
  nsx "$router" ethtool -K "$2" gro off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$2" address "$3" up
  nsx "$1" ethtool -K h0 tx off >/dev/null
  nsx "$1" sysctl -qw net.ipv6.conf.h0.accept_ra=0
  nsx "$1" ip link set h0 up
  nsx "$1" ip link set lo up
  nsx "$1" ip addr add "$4" dev h0
  nsx "$1" ip addr add "$5" dev h0 nodad
}
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
link "$lan" r-lan 02:00:00:00:00:01 192.0.2.10/24 2001:db8:1::10/64
link "$peer" r-wan 02:00:00:00:00:02 198.51.100.10/24 2001:db8:100::10/64
nsx "$lan" ip route add default via 192.0.2.1
nsx "$lan" ip -6 route add default via 2001:db8:1::1
ip link add h1 netns "$peer" type veth peer name h0 netns "$far"
nsx "$peer" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
nsx "$peer" ip link set h1 up
nsx "$peer" ip addr add 203.0.113.1/24 dev h1
nsx "$peer" ip addr add 2001:db8:203::1/64 dev h1 nodad
nsx "$far" ip link set h0 up
nsx "$far" ip addr add 203.0.113.10/24 dev h0
nsx "$far" ip addr add 2001:db8:203::10/64 dev h0 nodad
nsx "$far" ip route add default via 203.0.113.1
nsx "$far" ip -6 route add default via 2001:db8:203::1
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports

# The peer's bird-rs: it announces the far prefixes, takes everything and puts
# what it learns in its kernel.
cat >"$work/peer.conf" <<'CONF'
router id 198.51.100.10;
protocol device {}
protocol kernel { ipv4 { import none; export where source = RTS_BGP; }; }
protocol kernel { ipv6 { import none; export where source = RTS_BGP; }; }
protocol static far4 { ipv4; route 203.0.113.0/24 via "h1"; }
protocol static far6 { ipv6; route 2001:db8:203::/64 via "h1"; }
protocol bgp v4 {
  local as 65002; neighbor 198.51.100.1 as 65001; connect retry time 1;
  ipv4 { import all; export where proto = "far4"; };
}
protocol bgp v6 {
  local as 65002; neighbor 2001:db8:100::1 as 65001; connect retry time 1;
  ipv6 { import all; export where proto = "far6"; };
}
CONF
ip netns exec "$peer" "$bird/bird-rs" -f -c "$work/peer.conf" -s "$work/peer.ctl" >>"$work/peer-bird.log" 2>&1 &
pids+=("$!")
peerc() { nsx "$peer" "$bird/birdc-rs" -s "$work/peer.ctl" "$@"; }

cat >"$work/router.toml" <<'TOML'
routing-daemon = "bird-rs"

[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
ipv6 = ["2001:db8:100::1/64"]

[bgp]
as = 65001
networks = ["192.0.2.0/24", "2001:db8:1::/64"]
include = "WORK/include.conf"

[[bgp.neighbor]]
address = "198.51.100.10"
remote-as = 65002
description = "the peer"

[[bgp.neighbor]]
address = "2001:db8:100::10"
remote-as = 65002
TOML
sed -i "s|WORK|$work|" "$work/router.toml"
# The operator's own bird-rs settings: a quicker reconnection for the test.
cat >"$work/include.conf" <<'CONF'
template bgp quick { connect retry time 1; }
CONF

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" r-lan r-wan
start ruster-ribd confd:1 bird:20:65000
start ruster-neighd
start ruster-confd --kernel "$work/router.toml"
for _ in $(seq 1 50); do nsx "$router" ip link show rt-default >/dev/null 2>&1 && break; sleep 0.1; done
# bird-rs starts on a file of its own until ruster-bird writes one.
echo "protocol device {}" >"$work/bird.conf"
ip netns exec "$router" "$bird/bird-rs" -f -c "$work/bird.conf" -s "$work/router.ctl" >>"$work/router-bird.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 50); do [[ -S "$work/router.ctl" ]] && break; sleep 0.1; done
start ruster-bird --birdc "$bird/birdc-rs -s $work/router.ctl" "$work/bird.conf"
routerc() { nsx "$router" "$bird/birdc-rs" -s "$work/router.ctl" "$@"; }

ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
routes() { ruster show 2>/dev/null | grep "^route " || true; }
wait_route() { # pattern, present (1) or gone (0)
  for _ in $(seq 1 300); do
    if routes | grep -q "$1"; then [[ $2 == 1 ]] && return 0; else [[ $2 == 0 ]] && return 0; fi
    sleep 0.1
  done
  return 1
}
wait_route "203.0.113.0/24" 1 || fail "the FE has no route to 203.0.113.0/24: $(routes); $(routerc show protocols 2>&1)"
wait_route "2001:db8:203::/64" 1 || fail "the FE has no route to 2001:db8:203::/64: $(routes)"
echo "ok: the router's bird-rs learns the peer's prefixes, and ribd puts them in the FE"
echo "    $(routes | grep -E '203.0.113.0/24|2001:db8:203::/64' | tr '\n' ' ')"
grep -q 'description "the peer";' "$work/bird.conf" || fail "ruster-bird's file: $(cat "$work/bird.conf")"

reach() { # ns address
  for _ in $(seq 1 20); do nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1 && return 0; done
  return 1
}
reach "$lan" 203.0.113.10 || fail "the LAN host does not reach 203.0.113.10: $(nsx "$peer" ip route)"
reach "$lan" 2001:db8:203::10 || fail "the LAN host does not reach 2001:db8:203::10: $(nsx "$peer" ip -6 route)"
echo "ok: the LAN host reaches the host behind the peer, over IPv4 and IPv6"
nsx "$peer" ip route show 192.0.2.0/24 | grep -q "via 198.51.100.1" ||
  fail "the peer has no route to the LAN: $(nsx "$peer" ip route)"
learned=$(peerc show route for 2001:db8:1::/64 all 2>&1)
grep -q "bgp_next_hop: 2001:db8:100::1 fe80::ff:fe00:2" <<<"$learned" ||
  fail "the peer's IPv6 route to the LAN has not the FE port's link-local: $learned"
echo "ok: the peer learns the LAN's prefixes, the IPv6 one with the FE port's link-local next hop"

# A configuration bird-rs cannot read is refused, and the one before stays.
before=$(cat "$work/bird.conf")
# The part changes (another description), and its include is not bird-rs's syntax.
echo "this is not bird-rs's syntax" >"$work/include.conf"
sed 's/description = "the peer"/description = "the other peer"/' "$work/router.toml" >"$work/broken.toml"
out=$(ruster apply "$work/broken.toml" 2>&1) && fail "ruster apply took it: $out"
grep -q "refused" <<<"$out" || fail "ruster apply said: $out"
[[ "$(cat "$work/bird.conf")" == "$before" ]] || fail "bird-rs's file changed"
echo "template bgp quick { connect retry time 1; }" >"$work/include.conf"
echo "ok: a configuration bird-rs cannot read is refused, and the one before stays"

# The peer withdraws the IPv4 prefix: the route leaves the FE.
sed -i '/protocol static far4/d; s/export where proto = "far4"/export none/' "$work/peer.conf"
peerc configure "\"$work/peer.conf\"" >/dev/null || fail "the peer's bird-rs does not take the change"
wait_route "203.0.113.0/24" 0 || fail "the withdrawn route stays: $(routes)"
routes | grep -q "2001:db8:203::/64" || fail "the IPv6 route went too"
echo "ok: when the peer withdraws the prefix, the route leaves the FE"
echo "PASS ($backend)"

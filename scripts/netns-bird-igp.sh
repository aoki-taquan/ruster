#!/usr/bin/env bash
# IS-IS and OSPF through bird-rs: the router's bird-rs, set up by ruster-bird from
# confd's bird part (routing-daemon = "bird-rs"), runs IS-IS and OSPFv2 on the TAP
# device of r-wan (rp-r-wan) with a neighbouring bird-rs, and gives ribd the routes
# itself (protocol ruster, source bird). The neighbour announces one prefix by
# IS-IS and another by OSPF; ribd puts them in the FE, and a LAN host reaches both.
# The router announces the LAN's prefix from its passive r-lan.
#
#   lan (192.0.2.10) -- [r-lan | router | r-wan 10.0.1.1] -- peer (10.0.1.2, bird-rs:
#     203.0.113.1 by IS-IS, 198.18.0.1 by OSPF)
#
# Needs bird-rs and birdc-rs: BIRD_RS is the directory that holds them (exit 77,
# skipped, without). Run as root, after `cargo build`:
#   sudo BIRD_RS=<dir> scripts/netns-bird-igp.sh [target/debug]
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

tag=rbi$$
lan=$tag-lan peer=$tag-peer router=$tag-r
work=$(mktemp -d)
chmod 0755 "$work"
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$peer" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do [[ -e "$log" ]] && { echo "== $log"; tail -n 40 "$log"; }; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$lan" "$peer" "$router"; do ip netns add "$ns"; done
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
link "$peer" r-wan 02:00:00:00:00:02 10.0.1.2/24 2001:db8:100::10/64
nsx "$lan" ip route add default via 192.0.2.1
nsx "$lan" ip -6 route add default via 2001:db8:1::1
for d in d1:203.0.113.1 d2:198.18.0.1; do
  nsx "$peer" ip link add "${d%%:*}" type dummy
  nsx "$peer" ip link set "${d%%:*}" up
  nsx "$peer" ip addr add "${d#*:}/24" dev "${d%%:*}"
done
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports

# The peer's bird-rs: IS-IS and OSPFv2 on h0, its prefixes from passive dummies,
# and what it learns in its kernel.
cat >"$work/peer.conf" <<'CONF'
router id 10.0.1.2;
protocol device { scan time 1; }
protocol kernel { ipv4 { import none; export where source ~ [RTS_ISIS, RTS_OSPF]; }; }
protocol isis {
  net 49.0001.0000.0000.0002.00;
  level 2;
  ipv4 { import all; export none; };
  interface "h0" { hello 1; };
  interface "d1" { passive; };
}
protocol ospf v2 {
  ipv4 { import all; export none; };
  area 0 {
    interface "h0" { type ptp; };
    interface "d2" { stub; };
  };
}
CONF
ip netns exec "$peer" "$bird/bird-rs" -f -c "$work/peer.conf" -s "$work/peer.ctl" >>"$work/peer-bird.log" 2>&1 &
pids+=("$!")

cat >"$work/router.toml" <<'TOML'
routing-daemon = "bird-rs"

[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4 = "10.0.1.1/24"

[isis]
net = "49.0001.0000.0000.0001.00"
level = "level-2"

[[isis.interface]]
name = "r-wan"

[[isis.interface]]
name = "r-lan"
passive = true

[ospf]
router-id = "10.0.1.1"

[[ospf.interface]]
name = "r-wan"
network = "point-to-point"

[[ospf.interface]]
name = "r-lan"
passive = true
TOML

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
for _ in $(seq 1 50); do nsx "$router" ip link show rp-r-wan >/dev/null 2>&1 && break; sleep 0.1; done
echo "protocol device {}" >"$work/bird.conf"
ip netns exec "$router" "$bird/bird-rs" -f -c "$work/bird.conf" -s "$work/router.ctl" >>"$work/router-bird.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 50); do [[ -S "$work/router.ctl" ]] && break; sleep 0.1; done
start ruster-bird --birdc "$bird/birdc-rs -s $work/router.ctl" "$work/bird.conf"
routerc() { nsx "$router" "$bird/birdc-rs" -s "$work/router.ctl" "$@"; }

ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
routes() { ruster show 2>/dev/null | grep "^route " || true; }
wait_route() { # pattern
  for _ in $(seq 1 600); do routes | grep -q "$1" && return 0; sleep 0.1; done
  return 1
}
wait_route "203.0.113.0/24 via 10.0.1.2 dev r-wan" ||
  fail "the FE has no IS-IS route to 203.0.113.0/24: $(routes); $(routerc show protocols 2>&1)"
wait_route "198.18.0.0/24 via 10.0.1.2 dev r-wan" ||
  fail "the FE has no OSPF route to 198.18.0.0/24: $(routes); $(routerc show protocols 2>&1)"
grep -q 'interface "rp-r-wan"' "$work/bird.conf" || fail "ruster-bird's file: $(cat "$work/bird.conf")"
echo "ok: the router's bird-rs learns the peer's prefixes by IS-IS and OSPF on rp-r-wan, and ribd puts them in the FE"
echo "    $(routes | grep -E '203.0.113.0/24|198.18.0.0/24' | tr '\n' ' ')"

reach() { # ns address
  for _ in $(seq 1 30); do nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1 && return 0; done
  return 1
}
reach "$lan" 203.0.113.1 || fail "the LAN host does not reach 203.0.113.1: $(nsx "$peer" ip route)"
reach "$lan" 198.18.0.1 || fail "the LAN host does not reach 198.18.0.1: $(nsx "$peer" ip route)"
echo "ok: the LAN host reaches both, and the peer learned the LAN's prefix from the passive r-lan"
echo "PASS ($backend)"

#!/usr/bin/env bash
# VLAN sub-interfaces on real Linux: one router port carries VLANs 10 and 20, another
# is an untagged uplink.
#
#   a (10.10.0.10, VLAN 10) --\                  /-- [rb] -- c (198.51.100.10)
#                              trunk -- [ra: ra.10, ra.20]
#   b (10.20.0.10, VLAN 20) --/
#
# a to b goes in and out of the same port with the tag changed; a to c loses its tag;
# c to b gets one. Run as root after `cargo build`:
#   sudo scripts/netns-vlan.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default); there
# the kernel takes the tag off and the backend puts it back.
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rsl$$
a=$tag-a b=$tag-b c=$tag-c router=$tag-r
work=$(mktemp -d)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$a" "$b" "$c" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
for ns in "$a" "$b" "$c" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up

# The trunk: its VLAN 10 device stays in a, its VLAN 20 device moves to b.
ip link add trunk netns "$a" type veth peer name ra netns "$router"
ip link add c0 netns "$c" type veth peer name rb netns "$router"
for dev in ra rb; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off rxvlan off txvlan off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$dev" master vrf-ports
done
nsx "$router" ip link set ra address 02:00:00:00:00:01 up
nsx "$router" ip link set rb address 02:00:00:00:00:02 up
nsx "$a" ethtool -K trunk tx off rxvlan off txvlan off >/dev/null 2>&1 || true
nsx "$a" ip link set trunk up
nsx "$a" ip link add link trunk name v10 type vlan id 10
nsx "$a" ip link add link trunk name v20 type vlan id 20
nsx "$a" ip link set v20 netns "$b"
nsx "$a" ip link set v10 up
nsx "$a" ip addr add 10.10.0.10/24 dev v10
nsx "$a" ip route add default via 10.10.0.1
nsx "$b" ip link set v20 up
nsx "$b" ip addr add 10.20.0.10/24 dev v20
nsx "$b" ip route add default via 10.20.0.1
nsx "$c" ethtool -K c0 tx off >/dev/null 2>&1 || true
nsx "$c" ip link set c0 up
nsx "$c" ip addr add 198.51.100.10/24 dev c0
nsx "$c" ip route add default via 198.51.100.1

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "ra"
mac = "02:00:00:00:00:01"

[[interface]]
name = "ra.10"
parent = "ra"
vlan = 10
ipv4 = "10.10.0.1/24"

[[interface]]
name = "ra.20"
parent = "ra"
vlan = 20
ipv4 = "10.20.0.1/24"

[[interface]]
name = "rb"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" ra rb
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"

pings() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
ok=0
for _ in $(seq 1 20); do
  if pings "$a" 10.20.0.10; then ok=1; break; fi
done
(( ok == 1 )) || fail "VLAN 10 does not reach VLAN 20"
nsx "$a" ping -c 3 -i 0.2 -W 1 10.20.0.10 >/dev/null || fail "VLAN 10 to VLAN 20"
echo "ok: VLAN 10 reaches VLAN 20 through the same port"
nsx "$a" ping -c 3 -i 0.2 -W 1 198.51.100.10 >/dev/null || fail "VLAN 10 to the uplink"
nsx "$c" ping -c 3 -i 0.2 -W 1 10.20.0.10 >/dev/null || fail "the uplink to VLAN 20"
echo "ok: tags come off toward the uplink and go on toward a VLAN"
# An expiring packet from a VLAN: its ICMP error would leave a sub-interface, which is
# not sent yet; the FE must go on forwarding.
nsx "$a" ping -c 3 -i 0.2 -W 1 -t 1 198.51.100.10 >/dev/null 2>&1 || true
nsx "$a" ping -c 3 -i 0.2 -W 1 10.20.0.10 >/dev/null || fail "forwarding stopped after expiring packets"
echo "ok: expiring packets from a VLAN do not stop forwarding"
out=$(nsx "$c" ping -c 1 -W 1 -t 1 10.20.0.10 2>&1 || true)
grep -qi "time to live exceeded" <<<"$out" || fail "no ICMP Time Exceeded on the uplink afterwards: $out"
echo "ok: ICMP errors still go out of ports afterwards"
echo "PASS ($backend)"

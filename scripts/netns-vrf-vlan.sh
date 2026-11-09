#!/usr/bin/env bash
# VRFs on VLANs on real Linux: two customers with the same addresses, each on its
# own VLAN of one router port and in its own VRF, and a shared host in the default
# VRF that only one of them may reach.
#
#   red  (10.0.0.10, VLAN 10) --\                         /-- [r-up default]
#                                trunk -- [ra: ra.10 red, ra.20 blue]   -- shared
#   blue (10.0.0.10, VLAN 20) --/                                  (198.51.100.10)
#
# red looks 198.51.100.0/24 up in the default VRF, and the default VRF sends
# 10.0.0.0/24 back out of ra.10. blue has no way out. Run as root after `cargo build`:
#   sudo scripts/netns-vrf-vlan.sh [target/debug]  (FE_BACKEND=af-packet for AF_PACKET)
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rsw$$
red=$tag-red blue=$tag-blue shared=$tag-up router=$tag-r
work=$(mktemp -d)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$red" "$blue" "$shared" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$red" "$blue" "$shared" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
ip link add trunk netns "$red" type veth peer name ra netns "$router"
ip link add h0 netns "$shared" type veth peer name r-up netns "$router"
for dev in ra r-up; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off rxvlan off txvlan off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$dev" master vrf-ports
done
nsx "$router" ip link set ra address 02:00:00:00:00:01 up
nsx "$router" ip link set r-up address 02:00:00:00:00:03 up
nsx "$red" ethtool -K trunk tx off rxvlan off txvlan off >/dev/null 2>&1 || true
nsx "$red" ip link set trunk up
nsx "$red" ip link add link trunk name v10 type vlan id 10
nsx "$red" ip link add link trunk name v20 type vlan id 20
nsx "$red" ip link set v20 netns "$blue"
nsx "$red" ip link set v10 up
nsx "$red" ip addr add 10.0.0.10/24 dev v10
nsx "$red" ip route add default via 10.0.0.1
nsx "$blue" ip link set v20 up
nsx "$blue" ip addr add 10.0.0.10/24 dev v20
nsx "$blue" ip route add default via 10.0.0.1
nsx "$shared" ethtool -K h0 tx off >/dev/null
nsx "$shared" ip link set h0 up
nsx "$shared" ip addr add 198.51.100.10/24 dev h0
nsx "$shared" ip route add default via 198.51.100.1

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "ra"
mac = "02:00:00:00:00:01"

[[interface]]
name = "ra.10"
parent = "ra"
vlan = 10
ipv4 = "10.0.0.1/24"
vrf = "red"

[[interface]]
name = "ra.20"
parent = "ra"
vlan = 20
ipv4 = "10.0.0.1/24"
vrf = "blue"

[[interface]]
name = "r-up"
mac = "02:00:00:00:00:03"
ipv4 = "198.51.100.1/24"

[[route]]
vrf = "red"
prefix = "198.51.100.0/24"
lookup-vrf = "default"

[[route]]
prefix = "10.0.0.0/24"
interface = "ra.10"
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" ra r-up
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"

pings() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
ok=0
for _ in $(seq 1 20); do
  if pings "$red" 198.51.100.10; then ok=1; break; fi
done
(( ok == 1 )) || fail "red does not reach the shared host"
nsx "$red" ping -c 3 -i 0.2 -W 1 198.51.100.10 >/dev/null || fail "red to shared"
echo "ok: red reaches the shared host through the default VRF"

# The shared host's 10.0.0.10 is red's host, not blue's (the same address).
nsx "$shared" ping -c 3 -i 0.2 -W 1 10.0.0.10 >/dev/null || fail "shared to red"
# Only red's VLAN carries the shared host's packets for 10.0.0.10.
nsx "$blue" ip -s link show v20 | awk '/RX:/{getline; print $2}' >"$work/blue-before"
nsx "$shared" ping -c 3 -i 0.2 -W 1 10.0.0.10 >/dev/null || fail "shared to red again"
nsx "$blue" ip -s link show v20 | awk '/RX:/{getline; print $2}' >"$work/blue-after"
(( $(cat "$work/blue-after") - $(cat "$work/blue-before") < 3 )) \
  || fail "the shared host's packets reached blue's VLAN"
echo "ok: the shared host reaches red's 10.0.0.10 on VLAN 10, not blue's on VLAN 20"

if pings "$blue" 198.51.100.10; then fail "blue reaches the shared host"; fi
echo "ok: blue cannot reach the shared host"

echo "PASS ($backend)"

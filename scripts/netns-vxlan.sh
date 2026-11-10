#!/usr/bin/env bash
# VXLAN between ruster and a Linux vxlan device: ruster bridges its port p1 with
# VXLAN interface vx0 (VNI 100); on the other side Linux bridges its vxlan device
# with host b. The outer packets cross the routed link wan, in IPv4 and then IPv6.
#
#   a (192.0.2.10) -- p1 [ruster br0: p1, vx0] wan 10.0.0.1 ==== 10.0.0.2 [Linux brl: vxl, b-side] -- b (192.0.2.20)
#                                                  2001:db8::1     2001:db8::2
#
# a and b reach each other at L2 (TTL unchanged), and a frame too long for the link
# once wrapped is dropped and counted. Run as root after `cargo build`:
#   sudo scripts/netns-vxlan.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rsx$$
a=$tag-a b=$tag-b router=$tag-r linux=$tag-l
work=$(mktemp -d)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$a" "$b" "$router" "$linux"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
for ns in "$a" "$b" "$router" "$linux"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
ip link add p1 netns "$router" type veth peer name a0 netns "$a"
ip link add wan netns "$router" type veth peer name wan netns "$linux"
ip link add b0 netns "$b" type veth peer name bside netns "$linux"
for port in p1:02:00:00:00:01:01 wan:02:00:00:00:01:02; do
  name=${port%%:*} mac=${port#*:}
  nsx "$router" sysctl -qw "net.ipv6.conf.$name.disable_ipv6=1"
  nsx "$router" ethtool -K "$name" gro off rxvlan off txvlan off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$name" master vrf-ports
  nsx "$router" ip link set "$name" address "$mac" up
done
for h in "$a:a0:192.0.2.10" "$b:b0:192.0.2.20"; do
  IFS=: read -r ns dev address <<<"$h"
  nsx "$ns" ethtool -K "$dev" tx off >/dev/null 2>&1 || true
  nsx "$ns" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$ns" ip addr add "$address/24" dev "$dev"
  nsx "$ns" ip link set "$dev" up
done
# The Linux side: its end of wan, and a bridge for b.
nsx "$linux" ethtool -K wan tx off >/dev/null 2>&1 || true
nsx "$linux" ip addr add 10.0.0.2/24 dev wan
nsx "$linux" ip addr add 2001:db8::2/64 dev wan nodad
nsx "$linux" ip link set wan up
nsx "$linux" ip link add brl type bridge
nsx "$linux" ip link set brl up
nsx "$linux" ip link set bside master brl
nsx "$linux" ip link set bside up

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
stop() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  pids=()
}
pings() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
counter() { { grep -o "$1: [0-9]*" "$work/ruster-fe.log" || true; } | tail -1 | awk '{print $2}'; }

for outer in 4 6; do
  if [[ $outer == 4 ]]; then l=10.0.0.1 r=10.0.0.2 mtu=1450; else l=2001:db8::1 r=2001:db8::2 mtu=1430; fi
  nsx "$linux" ip link del vxl 2>/dev/null || true
  # Linux checks the UDP checksum over IPv6 (ruster computes it) and sends none
  # over IPv4 (ruster takes 0).
  nsx "$linux" ip link add vxl type vxlan id 100 local "$r" remote "$l" dstport 4789 dev wan
  nsx "$linux" ip link set vxl master brl
  nsx "$linux" ip link set vxl up
  cat > "$work/router.toml" <<TOML
[[interface]]
name = "p1"
mac = "02:00:00:00:01:01"

[[interface]]
name = "wan"
mac = "02:00:00:00:01:02"
ipv4 = "10.0.0.1/24"
ipv6 = ["2001:db8::1/64"]

[[interface]]
name = "vx0"
vxlan = { vni = 100, local = "$l", remote = ["$r"] }

[[interface]]
name = "br0"
bridge = { members = ["p1", "vx0"] }
TOML
  rm -f "$work"/*.log
  start ruster-fe --backend "$backend" p1 wan
  start ruster-ribd
  start ruster-neighd
  start ruster-confd "$work/router.toml"
  ok=0
  for _ in $(seq 1 20); do
    if pings "$a" 192.0.2.20; then ok=1; break; fi
  done
  (( ok == 1 )) || fail "a does not reach b over VXLAN in IPv$outer"
  out=$(nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20) || fail "a to b in IPv$outer: $out"
  grep -q "ttl=64" <<<"$out" || fail "a to b was not bridged (TTL changed): $out"
  nsx "$b" ping -c 2 -i 0.2 -W 1 192.0.2.10 >/dev/null || fail "b to a in IPv$outer"
  echo "ok: a and b reach each other at L2 over VXLAN in IPv$outer"

  # The largest frame that fits: the VXLAN interface's MTU is the inner IP
  # packet, 28 of which are IPv4 and ICMP.
  nsx "$a" ping -c 2 -i 0.2 -W 1 -M do -s $((mtu - 28)) 192.0.2.20 >/dev/null ||
    fail "a frame that fits once wrapped did not cross in IPv$outer"
  if nsx "$a" ping -c 2 -i 0.2 -W 1 -M do -s $((mtu - 27)) 192.0.2.20 >/dev/null 2>&1; then
    fail "a frame too long once wrapped crossed in IPv$outer"
  fi
  # The FE reports its counters every 5 seconds when they change.
  seen=0
  for _ in $(seq 1 8); do
    n=$(counter overlay_too_big)
    if [[ -n "$n" ]] && (( n >= 2 )); then seen=1; break; fi
    sleep 1
  done
  (( seen == 1 )) || fail "the FE did not count the frames too long in IPv$outer"
  echo "ok: frames too long once wrapped are dropped and counted (IPv$outer)"
  stop
done
echo "PASS ($backend)"

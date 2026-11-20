#!/usr/bin/env bash
# EVPN's L2 forwarding with what a routing daemon gives, written with `ruster evpn`
# as the ribd source "evpn": ruster's VXLAN interface vx0 (VNI 100) lists no VTEP
# in the configuration; Linux bridges its vxlan device with host b.
#
#   a (192.0.2.10, 2001:db8:100::10) -- p1 [ruster br0: p1, vx0] wan 10.0.0.1 ==== 10.0.0.2 [Linux brl: vxl, b-side] -- b (192.0.2.20)
#
# a reaches b only once the Linux VTEP takes VNI 100's floods; frames to b's MAC go
# to its VTEP; ARP and ND for a remote host are answered by ruster (RFC 9161).
# Run as root after `cargo build`:
#   sudo scripts/netns-evpn.sh [target/debug]
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

nsx "$a" ip addr add 2001:db8:100::10/64 dev a0 nodad
nsx "$linux" ip link add vxl type vxlan id 100 local 10.0.0.2 remote 10.0.0.1 dstport 4789 dev wan
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

[[interface]]
name = "vx0"
vxlan = { vni = 100, local = "10.0.0.1" }

[[interface]]
name = "br0"
bridge = { members = ["p1", "vx0"] }
TOML
start ruster-fe --backend "$backend" p1 wan
start ruster-ribd confd:1 evpn:20
start ruster-neighd
start ruster-confd "$work/router.toml"
evpn() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" evpn "$@" --source evpn; }
for _ in $(seq 1 50); do
  [[ -S "$run_dir/ribd/source/evpn/source.sock" ]] && nsx "$router" "$bin/ruster" --run-dir "$run_dir" show >/dev/null 2>&1 && break
  sleep 0.2
done

# No VTEP yet: nothing crosses.
if pings "$a" 192.0.2.20; then fail "a reached b with no VTEP"; fi
echo "ok: with no VTEP given, a does not reach b"

evpn add flood 100 10.0.0.2 || fail "evpn add flood"
ok=0
for _ in $(seq 1 20); do
  if pings "$a" 192.0.2.20; then ok=1; break; fi
done
(( ok == 1 )) || fail "a does not reach b once the VTEP takes VNI 100's floods"
out=$(nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20) || fail "a to b: $out"
grep -q "ttl=64" <<<"$out" || fail "a to b was not bridged (TTL changed): $out"
echo "ok: a reaches b once the VTEP takes VNI 100's floods"

# b's MAC behind the VTEP: shown, and frames to b still go there.
b_mac=$(nsx "$b" cat /sys/class/net/b0/address)
evpn add mac 100 "$b_mac" vtep 10.0.0.2 || fail "evpn add mac"
shown=""
for _ in $(seq 1 20); do
  shown=$(nsx "$router" "$bin/ruster" --run-dir "$run_dir" show 2>/dev/null | grep "^evpn-mac vni 100 $b_mac vtep 10.0.0.2" || true)
  [[ -n "$shown" ]] && break
  sleep 0.2
done
[[ -n "$shown" ]] || fail "ruster show has no EVPN MAC"
nsx "$a" ping -c 2 -i 0.2 -W 1 192.0.2.20 >/dev/null || fail "a to b with b's MAC behind its VTEP"
echo "ok: b's MAC is behind its VTEP and a still reaches b"

# Hosts no one has: only ruster's answers give a their MAC addresses.
evpn add neighbor 100 192.0.2.99 02:00:00:00:00:99 || fail "evpn add neighbor (IPv4)"
evpn add neighbor 100 2001:db8:100::99 02:00:00:00:00:98 router || fail "evpn add neighbor (IPv6)"
got=""
for _ in $(seq 1 20); do
  nsx "$a" ping -c 1 -W 1 192.0.2.99 >/dev/null 2>&1 || true
  got=$(nsx "$a" ip neigh show 192.0.2.99 dev a0 | grep -o 'lladdr [0-9a-f:]*' || true)
  [[ "$got" == "lladdr 02:00:00:00:00:99" ]] && break
done
[[ "$got" == "lladdr 02:00:00:00:00:99" ]] || fail "a has no answer to its ARP request for 192.0.2.99: $got"
echo "ok: ruster answers ARP for a remote host"
got=""
for _ in $(seq 1 20); do
  nsx "$a" ping -6 -c 1 -W 1 2001:db8:100::99 >/dev/null 2>&1 || true
  got=$(nsx "$a" ip -6 neigh show 2001:db8:100::99 dev a0 || true)
  grep -q 'lladdr 02:00:00:00:00:98 router' <<<"$got" && break
done
grep -q 'lladdr 02:00:00:00:00:98 router' <<<"$got" || fail "a has no answer to its NS for 2001:db8:100::99: $got"
echo "ok: ruster answers ND for a remote host (a router)"

# The VTEP goes: so do the floods to it.
evpn del flood 100 10.0.0.2 || fail "evpn del flood"
evpn del mac 100 "$b_mac" || fail "evpn del mac"
gone=0
for _ in $(seq 1 20); do
  nsx "$a" ip neigh flush dev a0
  if ! pings "$a" 192.0.2.20; then gone=1; break; fi
done
(( gone == 1 )) || fail "a still reaches b after the VTEP went"
echo "ok: once the VTEP goes, a no longer reaches b"
echo "PASS ($backend)"

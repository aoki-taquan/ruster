#!/usr/bin/env bash
# MAP-E on real Linux: the router is the CE of RFC 7597 Appendix A example 1. It
# NATs the LAN to 192.0.2.18 with PSID 0x34's ports and sends it inside IPv6
# from 2001:db8:12:3400:0:c000:212:34 to the BR, here a Linux ip6tnl in its own
# namespace that routes it on to an IPv4 host.
#
#   lan (192.168.0.10) -- [r-lan | router (CE) | r-wan 2001:db8:ffff:1::2]
#       -- [2001:db8:ffff:1::1 br ip6tnl 2001:db8:ffff::1 | 198.51.100.1] -- net
#
# Run as root, after `cargo build`:  sudo scripts/netns-map-e.sh [target/debug]
# AF_XDP only: AF_PACKET has no room in front of a frame for the IPv6 header.
set -euo pipefail
bin=$(realpath "${1:-target/debug}")

tag=rsm$$
lan=$tag-lan br=$tag-br net=$tag-net router=$tag-r
work=$(mktemp -d)
pids=()
ce=2001:db8:12:3400:0:c000:212:34

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$br" "$net" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$lan" "$br" "$net" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
for ns in "$lan" "$br" "$net"; do nsx "$ns" ip link set lo up; done

ip link add h0 netns "$lan" type veth peer name r-lan netns "$router"
nsx "$lan" ethtool -K h0 tx off >/dev/null
nsx "$lan" ip link set h0 up
nsx "$lan" ip addr add 192.168.0.10/24 dev h0
nsx "$lan" ip route add default via 192.168.0.1

ip link add b0 netns "$br" type veth peer name r-wan netns "$router"
for dev in r-lan r-wan; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off >/dev/null 2>&1 || true
done
nsx "$router" ip link set r-lan address 02:00:00:00:00:01 up
nsx "$router" ip link set r-wan address 02:00:00:00:00:02 up
nsx "$br" sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
nsx "$br" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
nsx "$br" ethtool -K b0 tx off >/dev/null
nsx "$br" ip link set b0 up
nsx "$br" ip addr add 2001:db8:ffff:1::1/64 dev b0 nodad
# The delegated prefix is routed to the CE.
nsx "$br" ip -6 route add 2001:db8:12:3400::/56 via 2001:db8:ffff:1::2
nsx "$br" ip addr add 2001:db8:ffff::1/128 dev lo
nsx "$br" ip -6 tunnel add mp mode ipip6 local 2001:db8:ffff::1 remote "$ce"
nsx "$br" ip link set mp up
nsx "$br" ip route add 192.0.2.18/32 dev mp

ip link add n0 netns "$net" type veth peer name i0 netns "$br"
nsx "$net" ethtool -K n0 tx off >/dev/null
nsx "$br" ethtool -K i0 tx off >/dev/null
nsx "$net" ip link set n0 up
nsx "$net" ip addr add 198.51.100.10/24 dev n0
nsx "$net" ip route add 192.0.2.0/24 via 198.51.100.1
nsx "$br" ip link set i0 up
nsx "$br" ip addr add 198.51.100.1/24 dev i0

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv6 = ["2001:db8:ffff:1::2/64"]

[map-e]
interface = "map"
inside = "r-lan"
prefix = "2001:db8:12:3400::/56"
rule-ipv6 = "2001:db8::/40"
rule-ipv4 = "192.0.2.0/24"
ea-length = 16
br = "2001:db8:ffff::1"

[[route]]
prefix = "2001:db8:ffff::/64"
interface = "r-wan"
via = "2001:db8:ffff:1::1"
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend af-xdp r-lan r-wan
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.10 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN does not reach the IPv4 host through MAP-E"
echo "ok: the LAN pings an IPv4 host through MAP-E"

nsx "$net" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.10", 8080)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(b"%s %d" % (peer[0].encode(), peer[1])); c.close()
' >/dev/null 2>"$work/server.log" &
pids+=("$!")
for _ in $(seq 1 50); do
  nsx "$net" ss -Hltn "sport = :8080" | grep -q . && break
  sleep 0.1
done
seen=$(nsx "$lan" python3 -c '
import socket
s = socket.create_connection(("198.51.100.10", 8080), timeout=5)
print(s.recv(100).decode())
') || fail "TCP through MAP-E"
read -r address port <<<"$seen"
[[ "$address" == 192.0.2.18 ]] || fail "the IPv4 host saw $address"
# PSID 0x34 with offset 6 and 8 PSID bits: bits 2..9 of the port.
(( ((port >> 2) & 0xff) == 0x34 && (port >> 10) != 0 )) || fail "port $port is not PSID 0x34's"
echo "ok: TCP arrives from 192.0.2.18 port $port, one of PSID 0x34's"

echo "PASS (af-xdp)"

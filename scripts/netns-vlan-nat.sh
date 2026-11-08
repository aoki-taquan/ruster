#!/usr/bin/env bash
# VLAN, NAT and the firewall together on real Linux: the LAN is VLAN 10 of one port,
# the WAN an untagged port with the default route, NAPT from the VLAN to the WAN,
# and firewall rules for what leaves the LAN.
#
#   lan (10.10.0.10, VLAN 10) -- [ra: ra.10 | router | rb 198.51.100.1]
#       -- wan (198.51.100.10, .11)
#
# Run as root after `cargo build`:  sudo scripts/netns-vlan-nat.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rsc$$
lan=$tag-lan wan=$tag-wan router=$tag-r
work=$(mktemp -d)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$wan" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
listening() {
  for _ in $(seq 1 50); do
    nsx "$1" ss -Hln"$2" "sport = :$3" | grep -q . && return 0
    sleep 0.1
  done
  fail "nothing listens on $3 in $1"
}

for ns in "$lan" "$wan" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
ip link add trunk netns "$lan" type veth peer name ra netns "$router"
ip link add w0 netns "$wan" type veth peer name rb netns "$router"
for dev in ra rb; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off rxvlan off txvlan off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$dev" master vrf-ports
done
nsx "$router" ip link set ra address 02:00:00:00:00:01 up
nsx "$router" ip link set rb address 02:00:00:00:00:02 up
nsx "$lan" ethtool -K trunk tx off rxvlan off txvlan off >/dev/null 2>&1 || true
nsx "$lan" ip link set trunk up
nsx "$lan" ip link set lo up
nsx "$lan" ip link add link trunk name v10 type vlan id 10
nsx "$lan" ip link set v10 up
nsx "$lan" ip addr add 10.10.0.10/24 dev v10
nsx "$lan" ip route add default via 10.10.0.1
nsx "$wan" ethtool -K w0 tx off >/dev/null 2>&1 || true
nsx "$wan" ip link set w0 up
nsx "$wan" ip link set lo up
nsx "$wan" ip addr add 198.51.100.10/24 dev w0
nsx "$wan" ip addr add 198.51.100.11/24 dev w0

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
name = "rb"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"

[[route]]
prefix = "0.0.0.0/0"
interface = "rb"
via = "198.51.100.10"

[nat]
inside = "ra.10"
outside = "rb"
ports = "20000-20999"

[[firewall]]
action = "accept"
protocol = "icmp"
ingress = "ra.10"

[[firewall]]
action = "accept"
protocol = "tcp"
ingress = "ra.10"

[[firewall]]
action = "accept"
protocol = "udp"
ingress = "ra.10"
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

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.10 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the VLAN does not reach the WAN host"
echo "ok: the LAN on VLAN 10 pings the WAN host through NAT"

# TCP: the WAN host sees the public address and a port of the pool.
nsx "$wan" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.10", 8080)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(b"%s %d\n" % (peer[0].encode(), peer[1])); c.close()
' >/dev/null 2>"$work/server.log" &
pids+=("$!")
listening "$wan" t 8080
seen=$(nsx "$lan" python3 -c '
import socket
s = socket.create_connection(("198.51.100.10", 8080), timeout=5)
print(s.recv(100).decode().strip())
') || fail "TCP from the VLAN"
read -r address port <<<"$seen"
[[ "$address" == 198.51.100.1 ]] || fail "the WAN host saw $address"
(( port >= 20000 && port <= 20999 )) || fail "the WAN host saw port $port"
echo "ok: TCP from the VLAN arrives from $address port $port"

# UDP: the reply comes back, and with endpoint-independent filtering (the default
# of NAT and the firewall) another outside address reaches the mapping too.
nsx "$lan" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.10.0.10", 5000)); s.settimeout(5)
s.sendto(b"hello", ("198.51.100.10", 3478))
got = []
while len(got) < 2:
    data, peer = s.recvfrom(100); got.append(peer[0])
print(" ".join(sorted(got)))
' >"$work/udp.txt" 2>"$work/udp-client.log" &
client=$!
nsx "$wan" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.51.100.10", 3478)); s.settimeout(5)
data, peer = s.recvfrom(100)
s.sendto(b"reply", peer)
o = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
o.bind(("198.51.100.11", 3479))
o.sendto(b"other", peer)
' 2>"$work/udp-server.log" || fail "the WAN host got no UDP: $(cat "$work/udp-server.log")"
wait "$client" || fail "the LAN host did not get both: $(cat "$work/udp-client.log")"
[[ "$(cat "$work/udp.txt")" == "198.51.100.10 198.51.100.11" ]] \
  || fail "the LAN host got UDP from $(cat "$work/udp.txt")"
echo "ok: the UDP reply and another outside endpoint reach the LAN host"

# Nothing from outside opens a flow into the LAN on its own.
nsx "$lan" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.10.0.10", 2222)); s.listen(4); s.settimeout(15)
while True: s.accept()[0].close()
' >/dev/null 2>"$work/lan-server.log" &
pids+=("$!")
listening "$lan" t 2222
if nsx "$wan" timeout 2 bash -c 'exec 3<>/dev/tcp/198.51.100.1/2222' 2>/dev/null; then
  fail "the WAN host opens TCP to the LAN"
fi
echo "ok: the WAN host cannot open TCP into the LAN"

# An expiring packet from the VLAN gets Time Exceeded back on the VLAN.
out=$(nsx "$lan" ping -c 1 -W 1 -t 1 198.51.100.10 2>&1 || true)
grep -qi "time to live exceeded" <<<"$out" || fail "no Time Exceeded on the VLAN: $out"
echo "ok: Time Exceeded comes back tagged on the VLAN"

echo "PASS ($backend)"

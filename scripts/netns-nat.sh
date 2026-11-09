#!/usr/bin/env bash
# NAPT and the firewall on real Linux. The router translates the LAN to its WAN
# address; its firewall lets ICMP and TCP from the LAN out (and their replies in),
# and drops the rest, such as UDP.
#
#   lan (192.0.2.10) -- [r-lan | router | r-wan 198.51.100.1] -- wan (198.51.100.10)
#
# The WAN host has a route back to the LAN; NAT, not routing, keeps it out.
# Run as root, after `cargo build`:  sudo scripts/netns-nat.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsn$$
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
# Waits until something in namespace $1 listens on $2 port $3 (ss -ltn or -lun).
listening() {
  for _ in $(seq 1 50); do
    nsx "$1" ss -Hln"$2" "sport = :$3" | grep -q . && return 0
    sleep 0.1
  done
  fail "nothing listens on $3 in $1"
}

for ns in "$lan" "$wan" "$router"; do ip netns add "$ns"; done
link() { # host-ns router-dev router-mac host-ip/len gateway
  ip link add h0 netns "$1" type veth peer name "$2" netns "$router"
  nsx "$router" sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
  nsx "$router" ethtool -K "$2" gro off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$2" address "$3" up
  nsx "$1" ethtool -K h0 tx off >/dev/null
  nsx "$1" ip link set h0 up
  nsx "$1" ip link set lo up
  nsx "$1" ip addr add "$4" dev h0
  nsx "$1" ip route add "$5" via "${4%.*}.1"
}
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
link "$lan" r-lan 02:00:00:00:00:01 192.0.2.10/24 default
link "$wan" r-wan 02:00:00:00:00:02 198.51.100.10/24 192.0.2.0/24
# The ports sit in a VRF with no addresses; the router's kernel has its addresses
# on the TUN device confd makes.
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"

[nat]
inside = "r-lan"
outside = "r-wan"
ports = "20000-20999"

[[firewall]]
action = "accept"
protocol = "icmp"
ingress = "r-lan"

[[firewall]]
action = "accept"
protocol = "tcp"
ingress = "r-lan"

# The router's own pings and TCP, as a LAN host's.
[[firewall]]
action = "accept"
protocol = "icmp"
ingress = "rt-default"

[[firewall]]
action = "accept"
protocol = "tcp"
ingress = "rt-default"
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" r-lan r-wan
start ruster-ribd
start ruster-neighd
start ruster-confd --kernel "$work/router.toml"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.10 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN does not reach the WAN host"
echo "ok: the LAN pings the WAN host"

# The router itself reaches a host on the WAN's subnet through NAT, as a LAN host
# does (from its inside address), with fragments too.
for size in 56 3000; do
  nsx "$router" ping -c 1 -W 2 -s "$size" 198.51.100.10 >/dev/null 2>&1 ||
    fail "the router pings the WAN host ($size bytes)"
done
echo "ok: the router pings the WAN host, fragmented too"

# The WAN host sees the router's address and a port of the range.
nsx "$wan" python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.10", 8080)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(b"%s %d\n" % (peer[0].encode(), peer[1])); c.close()
' >"$work/peer.txt" 2>"$work/server.log" &
pids+=("$!")
listening "$wan" t 8080
seen=$(nsx "$lan" python3 -c '
import socket
s = socket.create_connection(("198.51.100.10", 8080), timeout=5)
print(s.recv(100).decode().strip())
') || fail "TCP from the LAN"
read -r address port <<<"$seen"
[[ "$address" == 198.51.100.1 ]] || fail "the WAN host saw $address"
(( port >= 20000 && port <= 20999 )) || fail "the WAN host saw port $port"
echo "ok: TCP from the LAN arrives from $address port $port"

# The router itself, too, is translated to its address and a port of the range.
nsx "$wan" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.10", 8081)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(b"%s %d\n" % (peer[0].encode(), peer[1])); c.close()
' >"$work/peer-router.txt" 2>"$work/server-router.log" &
pids+=("$!")
listening "$wan" t 8081
seen=$(nsx "$router" python3 -c '
import socket
s = socket.create_connection(("198.51.100.10", 8081), timeout=5)
print(s.recv(100).decode().strip())
') || fail "TCP from the router"
read -r address port <<<"$seen"
[[ "$address" == 198.51.100.1 ]] || fail "the WAN host saw the router as $address"
(( port >= 20000 && port <= 20999 )) || fail "the WAN host saw the router's port $port"
echo "ok: TCP from the router arrives from $address port $port"

if nsx "$wan" ping -c 2 -i 0.2 -W 1 192.0.2.10 >/dev/null 2>&1; then
  fail "the WAN host pings into the LAN"
fi
# A listener in the LAN, so a refused connection means the firewall.
nsx "$lan" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.0.2.10", 2222)); s.listen(4); s.settimeout(15)
while True: s.accept()[0].close()
' >/dev/null 2>"$work/lan-server.log" &
pids+=("$!")
listening "$lan" t 2222
nsx "$lan" timeout 2 bash -c 'exec 3<>/dev/tcp/192.0.2.10/2222' || fail "the LAN listener"
if nsx "$wan" timeout 2 bash -c 'exec 3<>/dev/tcp/192.0.2.10/2222' 2>/dev/null; then
  fail "the WAN host opens TCP into the LAN"
fi
echo "ok: the WAN host cannot reach into the LAN"

# No rule accepts UDP: the firewall drops it, though NAT would translate it.
nsx "$wan" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("198.51.100.10", 9999))
s.settimeout(3)
try:
    s.recvfrom(100); print("got")
except socket.timeout:
    print("none")
' >"$work/udp.txt" 2>"$work/udp-server.log" &
udp_server=$!
pids+=("$udp_server")
listening "$wan" u 9999
for _ in 1 2 3; do
  nsx "$lan" python3 -c '
import socket
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("198.51.100.10", 9999))'
done
wait "$udp_server" || true
[[ "$(cat "$work/udp.txt")" == none ]] || fail "UDP from the LAN passed the firewall"
echo "ok: the firewall drops LAN UDP, which no rule accepts"

echo "PASS ($backend)"

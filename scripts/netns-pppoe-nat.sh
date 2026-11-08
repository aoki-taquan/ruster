#!/usr/bin/env bash
# PPPoE, NAT and the firewall together on real Linux: the router's default route is
# a PPPoE session (RFC 2516) whose address is the NAT's public one, and firewall
# rules say what leaves the LAN. scripts/pppoe-ac.py plays the access
# concentrator's data plane; the AC's kernel (198.51.100.1) knows only the router's
# public address, not the LAN.
#
#   lan (192.168.0.10) -- [r-lan | router 198.51.100.2 | r-wan, session 0x1234]
#       -- [a0 ac 198.51.100.1]
#
# Run as root, after `cargo build`:  sudo scripts/netns-pppoe-nat.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
here=$(dirname "$(realpath "$0")")

tag=rsy$$
lan=$tag-lan ac=$tag-ac router=$tag-r
work=$(mktemp -d)
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$ac" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$lan" "$ac" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
for ns in "$lan" "$ac"; do nsx "$ns" ip link set lo up; done

ip link add h0 netns "$lan" type veth peer name r-lan netns "$router"
nsx "$lan" ethtool -K h0 tx off >/dev/null
nsx "$lan" ip link set h0 up
nsx "$lan" ip addr add 192.168.0.10/24 dev h0
nsx "$lan" ip route add default via 192.168.0.1

ip link add a0 netns "$ac" type veth peer name r-wan netns "$router"
for dev in r-lan r-wan; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off >/dev/null 2>&1 || true
done
nsx "$router" ip link set r-lan address 02:00:00:00:00:01 up
nsx "$router" ip link set r-wan address 02:00:00:00:00:02 up
nsx "$ac" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
nsx "$ac" ethtool -K a0 tx off >/dev/null
nsx "$ac" ip link set a0 address 02:00:00:00:00:ac up
nsx "$ac" python3 "$here/pppoe-ac.py" a0 ac0 0x1234 02:00:00:00:00:02 >"$work/ac.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 50); do grep -q ready "$work/ac.log" 2>/dev/null && break; sleep 0.1; done
nsx "$ac" ip link set ac0 up
nsx "$ac" ip addr add 198.51.100.1/32 dev ac0
nsx "$ac" ip route add 198.51.100.2/32 dev ac0

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"

[[interface]]
name = "ppp"
pppoe = { parent = "r-wan", session = 4660, peer = "02:00:00:00:00:ac" }
ipv4 = "198.51.100.2/32"

[[route]]
prefix = "0.0.0.0/0"
interface = "ppp"

[nat]
inside = "r-lan"
outside = "ppp"
ports = "20000-20999"

[[firewall]]
action = "accept"
protocol = "icmp"
ingress = "r-lan"

[[firewall]]
action = "accept"
protocol = "tcp"
ingress = "r-lan"

[[firewall]]
action = "accept"
protocol = "udp"
ingress = "r-lan"
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
start ruster-confd "$work/router.toml"
listening() {
  for _ in $(seq 1 50); do
    nsx "$1" ss -Hln"$2" "sport = :$3" | grep -q . && return 0
    sleep 0.1
  done
  fail "nothing listens on $3 in $1"
}

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.1 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN does not reach the AC through NAT and the session"
echo "ok: the LAN pings the AC through NAT and the PPPoE session"

nsx "$ac" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.1", 8080)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(b"%s %d" % (peer[0].encode(), peer[1])); c.close()
' >/dev/null 2>"$work/server.log" &
pids+=("$!")
listening "$ac" t 8080
seen=$(nsx "$lan" python3 -c '
import socket
s = socket.create_connection(("198.51.100.1", 8080), timeout=5)
print(s.recv(100).decode())
') || fail "TCP through NAT and the session"
read -r address port <<<"$seen"
[[ "$address" == 198.51.100.2 ]] || fail "the AC saw $address"
(( port >= 20000 && port <= 20999 )) || fail "the AC saw port $port"
echo "ok: TCP arrives from the session's address 198.51.100.2 port $port"

# A 1500-byte datagram with DF clear: fragments in the session, put together at
# the AC (RFC 1812 4.2.2.7).
nsx "$ac" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.51.100.1", 9999)); s.settimeout(5)
data, peer = s.recvfrom(4000); print(len(data))
' >"$work/big.out" 2>"$work/big.log" &
receiver=$!
listening "$ac" u 9999
nsx "$lan" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER = IP_PMTUDISC_DONT
s.sendto(b"x" * 1472, ("198.51.100.1", 9999))
'
wait "$receiver" || fail "the big datagram did not arrive: $(cat "$work/big.log")"
[[ "$(cat "$work/big.out")" == 1472 ]] || fail "the AC got $(cat "$work/big.out") bytes"
echo "ok: a datagram too big for the session arrives in fragments"

# Nothing from outside reaches into the LAN.
nsx "$lan" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.168.0.10", 2222)); s.listen(4); s.settimeout(15)
while True: s.accept()[0].close()
' >/dev/null 2>"$work/lan-server.log" &
pids+=("$!")
listening "$lan" t 2222
if nsx "$ac" timeout 2 bash -c 'exec 3<>/dev/tcp/198.51.100.2/2222' 2>/dev/null; then
  fail "the AC opens TCP into the LAN"
fi
echo "ok: the outside cannot open TCP into the LAN"

echo "PASS ($backend)"

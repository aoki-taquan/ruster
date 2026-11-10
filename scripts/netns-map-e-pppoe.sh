#!/usr/bin/env bash
# MAP-E over PPPoE on real Linux: the router's IPv6 is a PPPoE session (RFC 2516) on
# its WAN port, and its IPv4 goes to the BR in MAP-E (RFC 7597) inside that IPv6.
# One namespace is both the access concentrator (scripts/pppoe-ac.py hands the
# session's IPv6 to a TUN device) and the BR (a Linux ip6tnl).
#
#   lan (192.168.0.10) -- [r-lan | router CE | r-wan, session 0x1234]
#       -- [a0 ac+br ac0 2001:db8:ffff:1::1, mp | 198.51.100.1] -- net (198.51.100.10)
#
# Run as root, after `cargo build`:  sudo scripts/netns-map-e-pppoe.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
here=$(dirname "$(realpath "$0")")

tag=rsq$$
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

ip link add a0 netns "$br" type veth peer name r-wan netns "$router"
for dev in r-lan r-wan; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off >/dev/null 2>&1 || true
done
nsx "$router" ip link set r-lan address 02:00:00:00:00:01 up
nsx "$router" ip link set r-wan address 02:00:00:00:00:02 up

# The access concentrator's data plane, then the BR on its side of the session.
nsx "$br" sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
nsx "$br" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
nsx "$br" ethtool -K a0 tx off >/dev/null
nsx "$br" ip link set a0 address 02:00:00:00:00:ac up
nsx "$br" python3 "$here/pppoe-ac.py" a0 ac0 0x1234 02:00:00:00:00:02 >"$work/ac.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 50); do grep -q ready "$work/ac.log" 2>/dev/null && break; sleep 0.1; done
nsx "$br" ip link set ac0 mtu 1492 up
nsx "$br" ip addr add 2001:db8:ffff:1::1/64 dev ac0 nodad
nsx "$br" ip -6 route add 2001:db8:12:3400::/56 dev ac0
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
[[source]]
name = "pppoe-wan"
kind = "pppoe"

[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"

[[interface]]
name = "ppp"
pppoe = { parent = "r-wan", source = "pppoe-wan" }
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
interface = "ppp"
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
# The session is fixed (the AC stand-in has no Discovery or PPP control): it is
# handed to confd by hand, as ruster-pppoed would.
fed=0
for _ in $(seq 1 50); do
  if nsx "$router" "$bin/ruster" --run-dir "$run_dir" source pppoe-wan pppoe 4660 02:00:00:00:00:ac 1492 2>>"$work/source.log"; then fed=1; break; fi
  sleep 0.1
done
(( fed == 1 )) || fail "confd took no values for the session"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.10 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN does not reach the IPv4 host through MAP-E over PPPoE"
echo "ok: the LAN pings an IPv4 host through MAP-E over PPPoE"

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
') || fail "TCP through MAP-E over PPPoE"
read -r address port <<<"$seen"
[[ "$address" == 192.0.2.18 ]] || fail "the IPv4 host saw $address"
(( ((port >> 2) & 0xff) == 0x34 && (port >> 10) != 0 )) || fail "port $port is not PSID 0x34's"
echo "ok: TCP arrives from 192.0.2.18 port $port, one of PSID 0x34's"

# The session carries 1492 bytes, so MAP-E carries 1452 of IPv4: 1452 with DF set
# passes, 1460 gets Fragmentation Needed with 1452 (RFC 2473 6.7, RFC 1191).
nsx "$lan" ping -c 1 -W 2 -M do -s 1424 198.51.100.10 >/dev/null || fail "a 1452-byte ping"
out=$(nsx "$lan" ping -c 1 -W 2 -M do -s 1432 198.51.100.10 2>&1 || true)
grep -q "mtu = 1452\|mtu=1452" <<<"$out" || fail "no Fragmentation Needed with 1452: $out"
echo "ok: the tunnel carries what the session carries less 40 and says so"

echo "PASS ($backend)"

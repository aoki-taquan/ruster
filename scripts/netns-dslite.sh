#!/usr/bin/env bash
# DS-Lite on real Linux: the router is the B4 and sends the LAN's IPv4 inside IPv6
# to an AFTR, here a Linux ip6tnl (ipip6) in its own namespace that routes it on to
# an IPv4 host.
#
#   lan (192.168.0.10) -- [r-lan | router (B4) | r-wan 2001:db8:1::2]
#       -- [2001:db8:1::1 aftr ip6tnl 2001:db8:ff::1 | 198.51.100.1] -- net (198.51.100.10)
#
# Run as root, after `cargo build`:  sudo scripts/netns-dslite.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsd$$
lan=$tag-lan aftr=$tag-aftr net=$tag-net router=$tag-r
work=$(mktemp -d)
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$aftr" "$net" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$lan" "$aftr" "$net" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
for ns in "$lan" "$aftr" "$net"; do nsx "$ns" ip link set lo up; done

# LAN host.
ip link add h0 netns "$lan" type veth peer name r-lan netns "$router"
nsx "$lan" ethtool -K h0 tx off >/dev/null
nsx "$lan" ip link set h0 up
nsx "$lan" ip addr add 192.168.0.10/24 dev h0
nsx "$lan" ip route add default via 192.168.0.1

# The router's WAN link to the AFTR.
ip link add a0 netns "$aftr" type veth peer name r-wan netns "$router"
for dev in r-lan r-wan; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off >/dev/null 2>&1 || true
done
nsx "$router" ip link set r-lan address 02:00:00:00:00:01 up
nsx "$router" ip link set r-wan address 02:00:00:00:00:02 up
nsx "$aftr" sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
nsx "$aftr" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
nsx "$aftr" ethtool -K a0 tx off >/dev/null
nsx "$aftr" ip link set a0 up
nsx "$aftr" ip addr add 2001:db8:1::1/64 dev a0 nodad
# The AFTR's tunnel end and the softwire.
nsx "$aftr" ip addr add 2001:db8:ff::1/128 dev lo
nsx "$aftr" ip -6 tunnel add sw mode ipip6 local 2001:db8:ff::1 remote 2001:db8:1::2
nsx "$aftr" ip link set sw up
nsx "$aftr" ip addr add 192.0.0.1/29 dev sw
nsx "$aftr" ip route add 192.168.0.0/24 dev sw

# The IPv4 host behind the AFTR.
ip link add n0 netns "$net" type veth peer name i0 netns "$aftr"
nsx "$net" ethtool -K n0 tx off >/dev/null
nsx "$aftr" ethtool -K i0 tx off >/dev/null
nsx "$net" ip link set n0 up
nsx "$net" ip addr add 198.51.100.10/24 dev n0
nsx "$net" ip route add 192.168.0.0/24 via 198.51.100.1
nsx "$aftr" ip link set i0 up
nsx "$aftr" ip addr add 198.51.100.1/24 dev i0

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv6 = ["2001:db8:1::2/64"]

[[interface]]
name = "dslite"
tunnel = { local = "2001:db8:1::2", remote = "2001:db8:ff::1" }
ipv4 = "192.0.0.2/29"

[[route]]
prefix = "2001:db8:ff::/64"
interface = "r-wan"
via = "2001:db8:1::1"

[[route]]
prefix = "0.0.0.0/0"
interface = "dslite"
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

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.10 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN does not reach the IPv4 host through the softwire"
nsx "$lan" ping -c 3 -i 0.2 -W 1 198.51.100.10 >/dev/null || fail "ping through the softwire"
echo "ok: the LAN pings an IPv4 host through the DS-Lite softwire"

# The AFTR saw the LAN's address inside IPv6 (it does no NAT here).
nsx "$aftr" ip -s link show sw | grep -A1 "RX:" | tail -1 | awk '{exit !($2 > 0)}' \
  || fail "the AFTR's tunnel received nothing"
echo "ok: the packets arrived inside IPv6 at the AFTR"

nsx "$net" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.10", 8080)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(peer[0].encode()); c.close()
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
') || fail "TCP through the softwire"
[[ "$seen" == 192.168.0.10 ]] || fail "the IPv4 host saw $seen"
echo "ok: TCP through the softwire arrives from the LAN host"

# An AFTR may fragment the IPv6 packet a big datagram goes in (Linux's ip6tnl does
# not, so the fragments are sent by hand); the router puts it back together
# (RFC 6333 5.3).
nsx "$lan" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("192.168.0.10", 9999)); s.settimeout(5)
data, peer = s.recvfrom(4000); print(len(data))
' >"$work/big.out" 2>"$work/big.log" &
receiver=$!
sleep 0.5
nsx "$aftr" python3 -c '
import socket, struct
def checksum(b):
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
payload = b"x" * 1450
udp = struct.pack("!HHHH", 5000, 9999, 8 + len(payload), 0) + payload
ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 63, 17, 0,
    socket.inet_aton("198.51.100.10"), socket.inet_aton("192.168.0.10")))
ip[10:12] = struct.pack("!H", checksum(bytes(ip)))
inner = bytes(ip) + udp
src = socket.inet_pton(socket.AF_INET6, "2001:db8:ff::1")
dst = socket.inet_pton(socket.AF_INET6, "2001:db8:1::2")
mac = bytes.fromhex(open("/sys/class/net/a0/address").read().strip().replace(":", ""))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("a0", 0))
for offset, more, part in ((0, 1, inner[:1000]), (1000, 0, inner[1000:])):
    frag = struct.pack("!BBHI", 4, 0, (offset // 8) << 3 | more, 0x5eed)
    ip6 = struct.pack("!IHBB", 0x60000000, 8 + len(part), 44, 64) + src + dst
    s.send(bytes.fromhex("020000000002") + mac + b"\x86\xdd" + ip6 + frag + part)
'
wait "$receiver" || fail "the big datagram did not arrive: $(cat "$work/big.log")"
[[ "$(cat "$work/big.out")" == 1450 ]] || fail "the LAN host got $(cat "$work/big.out") bytes"
echo "ok: a datagram the AFTR sent in IPv6 fragments arrives whole"

echo "PASS ($backend)"

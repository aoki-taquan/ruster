#!/usr/bin/env bash
# WireGuard on real Linux: a LAN host reaches a peer behind the router's WireGuard
# interface (10.9.0.0/16); scripts/wg-peer.py plays the peer's data plane with the
# session keys the router's file gives (no handshake: the key exchange is a daemon's
# job, which ruster does not have yet).
#
#   lan (192.168.0.10) -- [r-lan | router | r-wan 198.51.100.2] -- [a0 peer 198.51.100.1, 10.9.0.9]
#
# Run as root, after `cargo build`:  sudo scripts/netns-wireguard.sh [target/debug]
# The peer needs python3's cryptography module.
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
here=$(dirname "$(realpath "$0")")

tag=rsw$$
lan=$tag-lan peer=$tag-peer router=$tag-r
work=$(mktemp -d)
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$peer" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$lan" "$peer" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
for ns in "$lan" "$peer"; do nsx "$ns" ip link set lo up; done

ip link add h0 netns "$lan" type veth peer name r-lan netns "$router"
nsx "$lan" ethtool -K h0 tx off >/dev/null
nsx "$lan" ip link set h0 up
nsx "$lan" ip addr add 192.168.0.10/24 dev h0
nsx "$lan" ip route add default via 192.168.0.1

ip link add a0 netns "$peer" type veth peer name r-wan netns "$router"
for dev in r-lan r-wan; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off >/dev/null 2>&1 || true
done
nsx "$router" ip link set r-lan address 02:00:00:00:00:01 up
nsx "$router" ip link set r-wan address 02:00:00:00:00:02 up
nsx "$peer" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
nsx "$peer" ethtool -K a0 tx off >/dev/null
nsx "$peer" ip link set a0 address 02:00:00:00:00:ac up
nsx "$peer" ip addr add 198.51.100.1/24 dev a0
# Strict reverse path: a packet for 10.9.0.9 that arrives on a0, not sealed through
# wg0, is dropped instead of answered.
nsx "$peer" sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.a0.rp_filter=1

send=0202020202020202020202020202020202020202020202020202020202020202   # the router receives with this
receive=0101010101010101010101010101010101010101010101010101010101010101 # the router sends with this
# Started directly (not through nsx), so that the pid is python's and cleanup stops it.
ip netns exec "$peer" python3 "$here/wg-peer.py" 198.51.100.1 51821 198.51.100.2 51820 wg0 \
  "$send" "$receive" 11 22 1420 >"$work/peer.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 50); do grep -q ready "$work/peer.log" 2>/dev/null && break; sleep 0.1; done
grep -q ready "$work/peer.log" || fail "the peer did not start"
nsx "$peer" ip link set wg0 mtu 1420 up
nsx "$peer" ip addr add 10.9.0.9/32 dev wg0
nsx "$peer" ip route add 192.168.0.0/24 dev wg0

cat > "$work/router.toml" <<TOML
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.2/24"

[[interface]]
name = "wg0"
wireguard = { listen-port = 51820, local = "198.51.100.2" }

[[wireguard-peer]]
interface = "wg0"
name = "branch"
endpoint = "198.51.100.1:51821"
allowed = ["10.9.0.0/16"]
session = { send = "$receive", receive = "$send", peer-index = 22, local-index = 11 }

[[route]]
prefix = "10.9.0.0/16"
interface = "wg0"
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
  if nsx "$lan" ping -c 1 -W 1 10.9.0.9 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN does not reach the peer through the WireGuard interface"
# With -w, ping fails unless every one of the -c pings is answered.
nsx "$lan" ping -c 5 -i 0.2 -w 5 -s 1000 10.9.0.9 >/dev/null || fail "1028-byte pings"
# 1420 bytes, the MTU: the peer sends it unpadded (1420 is no multiple of 16).
nsx "$lan" ping -c 3 -i 0.2 -w 5 -s 1392 10.9.0.9 >/dev/null || fail "1420-byte pings"
echo "ok: the LAN pings the peer through the WireGuard interface (up to its 1420-byte MTU)"

ip netns exec "$peer" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.9.0.9", 8080)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(peer[0].encode()); c.close()
' >/dev/null 2>"$work/server.log" &
pids+=("$!")
for _ in $(seq 1 50); do
  nsx "$peer" ss -Hltn "sport = :8080" | grep -q . && break
  sleep 0.1
done
seen=$(nsx "$lan" python3 -c '
import socket
s = socket.create_connection(("10.9.0.9", 8080), timeout=5)
print(s.recv(100).decode())
') || fail "TCP through the WireGuard interface"
[[ "$seen" == 192.168.0.10 ]] || fail "the peer saw $seen"
echo "ok: TCP through the WireGuard interface arrives from the LAN host"

grep -q "^drop" "$work/peer.log" && fail "the peer refused what the router sent"
opened=$(grep -c "^opened" "$work/peer.log")
(( opened >= 9 )) || fail "the peer opened only $opened messages"
echo "PASS ($backend)"

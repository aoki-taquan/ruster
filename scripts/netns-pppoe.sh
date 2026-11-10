#!/usr/bin/env bash
# PPPoE on real Linux: the router's default route is a PPPoE session (RFC 2516)
# on its WAN port, with a fixed session ID; scripts/pppoe-ac.py plays the access
# concentrator's data plane and hands the session's IPv4 to its namespace's
# kernel (198.51.100.1).
#
#   lan (192.168.0.10) -- [r-lan | router | r-wan, session 0x1234] -- [a0 ac 198.51.100.1]
#
# Run as root, after `cargo build`:  sudo scripts/netns-pppoe.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
here=$(dirname "$(realpath "$0")")

tag=rsp$$
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
# The ports sit in a VRF with no addresses; the router's kernel has its addresses
# on the TUN device confd makes.
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports
nsx "$ac" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
nsx "$ac" ethtool -K a0 tx off >/dev/null
nsx "$ac" ip link set a0 address 02:00:00:00:00:ac up
nsx "$ac" python3 "$here/pppoe-ac.py" a0 ac0 0x1234 02:00:00:00:00:02 >"$work/ac.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 50); do grep -q ready "$work/ac.log" 2>/dev/null && break; sleep 0.1; done
# The session carries 1492 bytes: the AC's kernel fragments what is larger.
nsx "$ac" ip link set ac0 mtu 1492 up
nsx "$ac" ip addr add 198.51.100.1/32 dev ac0
nsx "$ac" ip route add 192.168.0.0/24 dev ac0
nsx "$ac" ip route add 198.51.100.2/32 dev ac0

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

[[route]]
prefix = "0.0.0.0/0"
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
start ruster-confd --kernel "$work/router.toml"
# The session is fixed (the AC stand-in has no Discovery or PPP control): it is
# handed to confd by hand, as ruster-pppoed would.
fed=0
for _ in $(seq 1 50); do
  if nsx "$router" "$bin/ruster" --run-dir "$run_dir" source pppoe-wan pppoe 4660 02:00:00:00:00:ac 1492 ipv4 198.51.100.2/32 2>>"$work/source.log"; then fed=1; break; fi
  sleep 0.1
done
(( fed == 1 )) || fail "confd took no values for the session"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.1 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN does not reach the AC through the PPPoE session"
nsx "$lan" ping -c 3 -i 0.2 -W 1 -s 1400 198.51.100.1 >/dev/null || fail "1428-byte pings"
echo "ok: the LAN pings through the PPPoE session (up to the 1492-byte MTU)"

# confd puts the session's address on the router's kernel side once it has it.
for _ in $(seq 1 50); do
  nsx "$router" ip -4 addr show dev rt-default | grep -q "198.51.100.2/32" && break
  sleep 0.1
done
nsx "$router" ip -4 addr show dev rt-default | grep -q "198.51.100.2/32" ||
  fail "the kernel side has no 198.51.100.2"
sleep 0.5
# The router itself too, with a datagram too big for the session: the FE cuts it.
for size in 56 3000; do
  nsx "$router" ping -c 1 -W 2 -M dont -s "$size" 198.51.100.1 >/dev/null ||
    fail "the router pings the AC ($size bytes)"
done
echo "ok: the router pings through the session, fragmented too"

nsx "$ac" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.1", 8080)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(peer[0].encode()); c.close()
' >/dev/null 2>"$work/server.log" &
pids+=("$!")
for _ in $(seq 1 50); do
  nsx "$ac" ss -Hltn "sport = :8080" | grep -q . && break
  sleep 0.1
done
seen=$(nsx "$lan" python3 -c '
import socket
s = socket.create_connection(("198.51.100.1", 8080), timeout=5)
print(s.recv(100).decode())
') || fail "TCP through the PPPoE session"
[[ "$seen" == 192.168.0.10 ]] || fail "the AC saw $seen"
echo "ok: TCP through the PPPoE session arrives from the LAN host"

echo "PASS ($backend)"

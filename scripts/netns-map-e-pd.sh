#!/usr/bin/env bash
# MAP-E with the end-user prefix from DHCPv6 prefix delegation: as netns-map-e.sh,
# but the router learns 2001:db8:12:3400::/56 from Kea (kea-dhcp6) in the BR's
# namespace through ruster-dhcpc, and confd makes the CE of RFC 7597 Appendix A
# example 1 from it ([map-e] prefix-from). The LAN also takes subnet 1 of the
# prefix (ipv6-from).
#
#   lan (192.168.0.10) -- [r-lan | router (CE) | r-wan 2001:db8:ffff:1::2]
#       -- [2001:db8:ffff:1::1 br ip6tnl 2001:db8:ffff::1 | 198.51.100.1] -- net
#
# Needs kea-dhcp6-server; its service must not be running. Run as root, after
# `cargo build`:  sudo scripts/netns-map-e-pd.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rmp$$
lan=$tag-lan br=$tag-br net=$tag-net router=$tag-r
work=$(mktemp -d)
kdir=/etc/kea/$tag
pids=()
ce=2001:db8:12:3400:0:c000:212:34

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  pkill -f "kea-dhcp6 -c $kdir/" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$kdir"
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

command -v kea-dhcp6 >/dev/null || fail "kea-dhcp6 is not installed"
id _kea >/dev/null 2>&1 || fail "there is no _kea user"
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
# confd --kernel gives the router's kernel its addresses on a TUN; the FE's ports sit
# in a VRF with no addresses, so the kernel leaves their frames to the FE.
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports
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
[[source]]
name = "dhcp6-wan"
kind = "dhcpv6-client"

[[dhcp-client]]
interface = "r-wan"
ipv6-source = "dhcp6-wan"
default-route = false

[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"
ipv6-from = { source = "dhcp6-wan", subnet = 1 }

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv6 = ["2001:db8:ffff:1::2/64"]

[map-e]
interface = "map"
inside = "r-lan"
prefix-from = "dhcp6-wan"
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
# Kea delegates the /56 of the example, and only it.
for _ in $(seq 1 50); do
  nsx "$br" ip -6 addr show dev b0 tentative | grep -q inet6 || break
  sleep 0.1
done
mkdir -p "$kdir"
cat >"$kdir/kea-dhcp6.conf" <<CONF
{ "Dhcp6": {
  "interfaces-config": { "interfaces": [ "b0" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "subnet6": [ { "id": 1, "subnet": "2001:db8:ffff:1::/64", "interface": "b0",
    "pd-pools": [ { "prefix": "2001:db8:12:3400::", "prefix-len": 56, "delegated-len": 56 } ] } ],
  "loggers": [ { "name": "kea-dhcp6", "output-options": [ { "output": "stdout" } ], "severity": "INFO" } ]
} }
CONF
(nsx "$br" env KEA_LOCKFILE_DIR=none setpriv --reuid=_kea --regid=_kea --init-groups \
  --inh-caps=+net_bind_service,+net_raw --ambient-caps=+net_bind_service,+net_raw \
  kea-dhcp6 -c "$kdir/kea-dhcp6.conf" 2>&1 | cat >>"$work/kea6.log") &
pids+=("$!")
for _ in $(seq 1 100); do grep -q DHCP6_STARTED "$work/kea6.log" && break; sleep 0.1; done
grep -q DHCP6_STARTED "$work/kea6.log" || fail "Kea did not start"

start ruster-fe --backend "$backend" r-lan r-wan
start ruster-ribd confd:1 dhcpc:5
start ruster-neighd
start ruster-confd --kernel "$work/router.toml"
start ruster-dhcpc

for _ in $(seq 1 300); do grep -q "^bound6 r-wan prefix=2001:db8:12:3400::/56" "$work/ruster-dhcpc.log" && break; sleep 0.1; done
grep -q "^bound6 r-wan prefix=2001:db8:12:3400::/56" "$work/ruster-dhcpc.log" || fail "no delegated prefix"
echo "ok: ruster-dhcpc got 2001:db8:12:3400::/56"
show=""
for _ in $(seq 1 50); do
  show=$(nsx "$router" "$bin/ruster" --run-dir "$run_dir" show)
  grep -q "address map 192.0.2.18/32" <<<"$show" && break
  sleep 0.1
done
grep -q "address map 192.0.2.18/32" <<<"$show" || fail "no CE address from the prefix: $show"
grep -q "address r-lan 2001:db8:12:3401::1/64" <<<"$show" || fail "the LAN has not subnet 1: $show"
echo "ok: confd made the CE (192.0.2.18) and the LAN's 2001:db8:12:3401::1/64 from it"

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

echo "PASS ($backend)"

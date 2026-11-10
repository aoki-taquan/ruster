#!/usr/bin/env bash
# OSPFv2 and OSPFv3 through FRR on a TAP device per port (docs/design/overlay.md
# section 6). The router has two ports with a neighbouring FRR on each: on p1 the
# link is point-to-point, on p2 broadcast (a DR is elected, and Database
# Description packets go to the neighbour's own address: IPv4 through the FE's
# routes, IPv6 to its link-local address). Each neighbour announces a prefix behind
# it; the router learns each on its own port, and a LAN host reaches both. A
# single TUN could not do this: the Hellos to 224.0.0.5 and ff02::5 must leave the
# right port, and OSPFv3 tells interfaces apart by their link-local addresses.
# When p1's link goes down, its TAP device's carrier follows and the adjacency drops
# at once, not after RouterDeadInterval (40 s).
#
#   lan (192.0.2.10) -- [r-lan | router | r-p1 10.0.1.1, r-p2 10.0.2.1]
#     r-p1 -- peer1 (10.0.1.2, point-to-point) -- 203.0.113.0/24, 2001:db8:203::/64
#     r-p2 -- peer2 (10.0.2.2, broadcast)      -- 198.18.0.0/24, 2001:db8:218::/64
#
# Needs FRR (apt-get install frr). OSPF's default timers make this take about a
# minute (the broadcast link waits RouterDeadInterval, 40 s, before electing a DR).
# Run as root, after `cargo build`:
#   sudo scripts/netns-ospf.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rso$$
lan=$tag-lan peer1=$tag-p1 peer2=$tag-p2 router=$tag-r
work=$(mktemp -d)
chmod 0755 "$work"
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for side in router peer1 peer2; do
    for pid in $(cat "$work/$side"/run/*.pid 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  done
  wait 2>/dev/null || true
  for ns in "$lan" "$peer1" "$peer2" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log "$work"/*/log/*.log; do
    [[ -e "$log" ]] && { echo "== $log"; tail -n 40 "$log"; }
  done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
[[ -x /usr/lib/frr/ospfd && -x /usr/lib/frr/ospf6d ]] || fail "FRR is not installed"

# Runs a command in namespace $1 with FRR instance $2's directories (their own
# mount namespace: Ubuntu's AppArmor profiles allow FRR only its usual paths).
frr() {
  local ns=$1 side=$2; shift 2
  nsx "$ns" unshare -m sh -c "mount --bind '$work/$side/etc' /etc/frr &&
    mount --bind '$work/$side/run' /run/frr && mount --bind '$work/$side/log' /var/log/frr &&
    exec \"\$@\"" sh "$@"
}
frr_start() { # ns side zebra-options...
  local ns=$1 side=$2; shift 2
  frr "$ns" "$side" /usr/lib/frr/mgmtd -d --log file:/var/log/frr/mgmtd.log >/dev/null 2>&1
  frr "$ns" "$side" /usr/lib/frr/zebra -d "$@" --log file:/var/log/frr/zebra.log >/dev/null 2>&1
  frr "$ns" "$side" /usr/lib/frr/ospfd -d --log file:/var/log/frr/ospfd.log >/dev/null 2>&1
  frr "$ns" "$side" /usr/lib/frr/ospf6d -d --log file:/var/log/frr/ospf6d.log >/dev/null 2>&1
}
for side in router peer1 peer2; do
  mkdir -p "$work/$side/etc" "$work/$side/run" "$work/$side/log"
  touch "$work/$side/etc/vtysh.conf"
  chown -R frr:frr "$work/$side"
done

for ns in "$lan" "$peer1" "$peer2" "$router"; do ip netns add "$ns"; done
link() { # host-ns router-dev router-mac host-ip/len host-ip6/len
  ip link add h0 netns "$1" type veth peer name "$2" netns "$router"
  nsx "$router" sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
  nsx "$router" ethtool -K "$2" gro off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$2" address "$3" up
  nsx "$1" ethtool -K h0 tx off >/dev/null
  nsx "$1" sysctl -qw net.ipv6.conf.h0.accept_ra=0
  nsx "$1" ip link set h0 up
  nsx "$1" ip link set lo up
  nsx "$1" ip addr add "$4" dev h0
  nsx "$1" ip addr add "$5" dev h0 nodad
}
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
link "$lan" r-lan 02:00:00:00:00:01 192.0.2.10/24 2001:db8:1::10/64
link "$peer1" r-p1 02:00:00:00:00:02 10.0.1.2/24 2001:db8:101::2/64
link "$peer2" r-p2 02:00:00:00:00:03 10.0.2.2/24 2001:db8:102::2/64
nsx "$lan" ip route add default via 192.0.2.1
nsx "$lan" ip -6 route add default via 2001:db8:1::1
# What each neighbour announces: a dummy link with an address in it.
for at in 1 2; do
  ns=$peer1 v4=203.0.113.1/24 v6=2001:db8:203::1/64
  [[ $at == 2 ]] && ns=$peer2 v4=198.18.0.1/24 v6=2001:db8:218::1/64
  nsx "$ns" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
  nsx "$ns" ip link add far type dummy
  nsx "$ns" ip link set far up
  nsx "$ns" ip addr add "$v4" dev far
  nsx "$ns" ip addr add "$v6" dev far nodad
done
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
for port in r-lan r-p1 r-p2; do nsx "$router" ip link set "$port" master vrf-ports; done

peer_conf() { # side router-id network
  cat >"$work/$1/etc/frr.conf" <<CONF
interface h0
 ip ospf area 0.0.0.0
 ip ospf network $3
 ipv6 ospf6 area 0.0.0.0
 ipv6 ospf6 network $3
exit
interface far
 ip ospf area 0.0.0.0
 ip ospf passive
 ipv6 ospf6 area 0.0.0.0
 ipv6 ospf6 passive
exit
router ospf
 ospf router-id $2
exit
router ospf6
 ospf6 router-id $2
exit
CONF
  chown frr:frr "$work/$1/etc/frr.conf"
}
peer_conf peer1 10.0.0.1 point-to-point
peer_conf peer2 10.0.0.2 broadcast
frr_start "$peer1" peer1
frr "$peer1" peer1 vtysh -b >"$work/peer1-boot.log" 2>&1 || fail "peer1's FRR does not take its configuration"
frr_start "$peer2" peer2
frr "$peer2" peer2 vtysh -b >"$work/peer2-boot.log" 2>&1 || fail "peer2's FRR does not take its configuration"

cat >"$work/router.toml" <<'TOML'
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "r-p1"
mac = "02:00:00:00:00:02"
ipv4 = "10.0.1.1/24"
ipv6 = ["2001:db8:101::1/64"]

[[interface]]
name = "r-p2"
mac = "02:00:00:00:00:03"
ipv4 = "10.0.2.1/24"
ipv6 = ["2001:db8:102::1/64"]

[ospf]

[[ospf.interface]]
name = "r-p1"
network = "point-to-point"

[[ospf.interface]]
name = "r-p2"

[[ospf.interface]]
name = "r-lan"
passive = true

[ospf6]

[[ospf6.interface]]
name = "r-p1"
network = "point-to-point"

[[ospf6.interface]]
name = "r-p2"

[[ospf6.interface]]
name = "r-lan"
passive = true
TOML
cat >"$work/reload" <<SH
#!/usr/bin/env bash
exec ip netns exec "$router" unshare -m sh -c "mount --bind '$work/router/etc' /etc/frr &&
  mount --bind '$work/router/run' /run/frr && mount --bind '$work/router/log' /var/log/frr &&
  /usr/lib/frr/frr-reload.py --reload --stdout /etc/frr/frr.conf" >>"$work/reload.log" 2>&1
SH
chmod 0755 "$work/reload"

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" r-lan r-p1 r-p2
start ruster-ribd confd:1 frr:20:65000
start ruster-neighd
start ruster-confd --kernel "$work/router.toml"
for _ in $(seq 1 50); do
  nsx "$router" ip link show rp-r-p2 2>/dev/null | grep -q LOWER_UP && break
  sleep 0.1
done
for tap in rp-r-lan rp-r-p1 rp-r-p2; do
  nsx "$router" ip link show "$tap" 2>/dev/null | grep -q LOWER_UP || fail "$tap is not there or not held open"
done
echo "ok: confd makes a TAP for each of the three ports, and the FE holds them open"

frr_start "$router" router -M dplane_fpm_nl
start ruster-frr --reload "$work/reload" --fpm-owner "$(id -u frr)" "$work/router/etc/frr.conf"

ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
routes() { ruster show 2>/dev/null | grep "^route " || true; }
wait_route() { # pattern
  for _ in $(seq 1 900); do routes | grep -q "$1" && return 0; sleep 0.1; done
  return 1
}
state() {
  frr "$router" router vtysh -c 'show ip ospf neighbor' -c 'show ipv6 ospf6 neighbor' \
    -c 'show ip route' -c 'show ipv6 route' 2>&1
}
wait_route "203.0.113.0/24 via 10.0.1.2 dev r-p1" ||
  fail "no OSPFv2 route out of r-p1: $(routes)
$(state)"
wait_route "198.18.0.0/24 via 10.0.2.2 dev r-p2" ||
  fail "no OSPFv2 route out of r-p2 (broadcast): $(routes)
$(state)"
echo "ok: OSPFv2 forms an adjacency on each port, point-to-point and broadcast, and"
echo "    each prefix goes out of its own port"
echo "    $(routes | grep -E '203.0.113.0/24|198.18.0.0/24' | tr '\n' ' ')"
wait_route "2001:db8:203::/64 via fe80::.* dev r-p1" ||
  fail "no OSPFv3 route out of r-p1: $(routes)
$(state)"
wait_route "2001:db8:218::/64 via fe80::.* dev r-p2" ||
  fail "no OSPFv3 route out of r-p2 (broadcast): $(routes)
$(state)"
echo "ok: OSPFv3 does the same, each next hop the neighbour's link-local address on its port"
echo "    $(routes | grep -E '2001:db8:203::/64|2001:db8:218::/64' | tr '\n' ' ')"
frr "$router" router vtysh -c 'show ip ospf neighbor' | grep -q "10.0.0.2 .*Full/\(DR\|Backup\)" ||
  fail "no DR election on r-p2: $(state)"
echo "ok: on the broadcast port the routers elect a DR and reach Full"

reach() { # ns address
  for _ in $(seq 1 20); do nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1 && return 0; done
  return 1
}
for _ in $(seq 1 200); do
  frr "$peer2" peer2 vtysh -c "show ipv6 route 2001:db8:1::/64" 2>/dev/null | grep -q ospf && break
  sleep 0.1
done
for address in 203.0.113.1 198.18.0.1 2001:db8:203::1 2001:db8:218::1; do
  reach "$lan" "$address" || fail "the LAN host does not reach $address"
done
echo "ok: the LAN host reaches both neighbours' prefixes over IPv4 and IPv6; they learn"
echo "    the LAN's from the router's passive interface"

# p1's link goes down (the neighbour's end of the veth): the FE takes the carrier
# of rp-r-p1 down, and ospfd drops the neighbour well before RouterDeadInterval.
frr "$router" router vtysh -c 'show ip ospf neighbor' | grep -q "^10.0.0.1 " ||
  fail "no adjacency on r-p1 before its link goes down: $(state)"
nsx "$peer1" ip link set h0 down
started=$SECONDS
for _ in $(seq 1 50); do
  frr "$router" router vtysh -c 'show ip ospf neighbor' 2>/dev/null | grep -q "^10.0.0.1 " || break
  sleep 0.1
done
nsx "$router" ip link show rp-r-p1 | grep -q LOWER_UP && fail "rp-r-p1 keeps its carrier with r-p1 down"
frr "$router" router vtysh -c 'show ip ospf neighbor' | grep -q "^10.0.0.1 " &&
  fail "the adjacency on r-p1 stays up with its link down: $(state)"
echo "ok: with r-p1's link down, rp-r-p1 goes down and the adjacency drops in $((SECONDS - started)) s"
nsx "$peer1" ip link set h0 up
for _ in $(seq 1 50); do
  nsx "$router" ip link show rp-r-p1 | grep -q LOWER_UP && break
  sleep 0.1
done
nsx "$router" ip link show rp-r-p1 | grep -q LOWER_UP || fail "rp-r-p1 does not come back up"
echo "ok: rp-r-p1 comes back up with r-p1's link"

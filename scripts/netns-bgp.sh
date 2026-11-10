#!/usr/bin/env bash
# BGP through FRR: the router's FRR, set up by ruster-frr from confd's frr part,
# learns a prefix from a neighbouring FRR on the WAN and hands it to ruster-frr over
# FPM; ribd puts it in the FE, and a LAN host reaches a host behind the neighbour.
# The router announces the LAN's prefixes back. Withdrawing the prefix removes the
# route. A second neighbor, mh, is two hops away behind the peer and reached by a
# static route (eBGP multihop): its prefix's next hop is on none of the router's
# links, and ribd resolves it through the static route. No internet is needed.
#
#   lan (192.0.2.10) -- [r-lan | router | r-wan 198.51.100.1] -- peer (198.51.100.10,
#     AS 65002, FRR) -- far (203.0.113.10, 2001:db8:203::10)
#                                                                 \- mh (10.0.2.2, AS 65003,
#                                                                   FRR, 100.64.0.10)
#
# Needs FRR (apt-get install frr; the distribution's frr service is not used). Each
# FRR instance runs in its own mount namespace with its own /etc/frr, /run/frr and
# /var/log/frr bound from a work directory: Ubuntu's AppArmor profile for bgpd allows
# only those paths, so the two instances cannot be told apart by path. Run as root,
# after `cargo build`:
#   sudo scripts/netns-bgp.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsb$$
lan=$tag-lan peer=$tag-peer far=$tag-far mh=$tag-mh router=$tag-r
work=$(mktemp -d)
chmod 0755 "$work"
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for side in router peer mh; do
    for pid in $(cat "$work/$side"/run/*.pid 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  done
  wait 2>/dev/null || true
  for ns in "$lan" "$peer" "$far" "$mh" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
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
[[ -x /usr/lib/frr/bgpd ]] || fail "FRR is not installed"

# Runs a command in namespace $1 with FRR instance $2's directories.
frr() {
  local ns=$1 side=$2; shift 2
  nsx "$ns" unshare -m sh -c "mount --bind '$work/$side/etc' /etc/frr &&
    mount --bind '$work/$side/run' /run/frr && mount --bind '$work/$side/log' /var/log/frr &&
    exec \"\$@\"" sh "$@"
}
frr_start() { # ns side [zebra options]
  local ns=$1 side=$2; shift 2
  frr "$ns" "$side" /usr/lib/frr/mgmtd -d --log file:/var/log/frr/mgmtd.log >/dev/null 2>&1
  frr "$ns" "$side" /usr/lib/frr/zebra -d "$@" --log file:/var/log/frr/zebra.log >/dev/null 2>&1
  frr "$ns" "$side" /usr/lib/frr/bgpd -d --log file:/var/log/frr/bgpd.log >/dev/null 2>&1
}
for side in router peer mh; do
  mkdir -p "$work/$side/etc" "$work/$side/run" "$work/$side/log"
  chown -R frr:frr "$work/$side"
done

for ns in "$lan" "$peer" "$far" "$mh" "$router"; do ip netns add "$ns"; done
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
link "$peer" r-wan 02:00:00:00:00:02 198.51.100.10/24 2001:db8:100::10/64
nsx "$lan" ip route add default via 192.0.2.1
nsx "$lan" ip -6 route add default via 2001:db8:1::1
# The host behind the peer, which routes for it.
ip link add h1 netns "$peer" type veth peer name h0 netns "$far"
nsx "$peer" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
nsx "$peer" ip link set h1 up
nsx "$peer" ip addr add 203.0.113.1/24 dev h1
nsx "$peer" ip addr add 2001:db8:203::1/64 dev h1 nodad
nsx "$far" ip link set h0 up
nsx "$far" ip addr add 203.0.113.10/24 dev h0
nsx "$far" ip addr add 2001:db8:203::10/64 dev h0 nodad
nsx "$far" ip route add default via 203.0.113.1
nsx "$far" ip -6 route add default via 2001:db8:203::1
# The multihop neighbor behind the peer, and the prefix behind it.
ip link add h2 netns "$peer" type veth peer name h0 netns "$mh"
nsx "$peer" ip link set h2 up
nsx "$peer" ip addr add 10.0.2.1/24 dev h2
nsx "$mh" ip link set lo up
nsx "$mh" ip link set h0 up
nsx "$mh" ip addr add 10.0.2.2/24 dev h0
nsx "$mh" ip route add default via 10.0.2.1
nsx "$mh" ip link add mh0 type dummy
nsx "$mh" ip link set mh0 up
nsx "$mh" ip addr add 100.64.0.10/24 dev mh0
nsx "$peer" ip route add 100.64.0.0/24 via 10.0.2.2
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports

# The peer's FRR: it announces the far prefixes and takes everything.
cat >"$work/peer/etc/frr.conf" <<'CONF'
route-map all permit 10
exit
router bgp 65002
 bgp router-id 198.51.100.10
 no bgp default ipv4-unicast
 neighbor 198.51.100.1 remote-as 65001
 neighbor 2001:db8:100::1 remote-as 65001
 address-family ipv4 unicast
  network 203.0.113.0/24
  neighbor 198.51.100.1 activate
  neighbor 198.51.100.1 route-map all in
  neighbor 198.51.100.1 route-map all out
 exit-address-family
 address-family ipv6 unicast
  network 2001:db8:203::/64
  neighbor 2001:db8:100::1 activate
  neighbor 2001:db8:100::1 route-map all in
  neighbor 2001:db8:100::1 route-map all out
 exit-address-family
exit
CONF
# The multihop neighbor's FRR: two hops from the router, announcing 100.64.0.0/24
# with its own address as the next hop.
cat >"$work/mh/etc/frr.conf" <<'CONF'
route-map all permit 10
exit
router bgp 65003
 bgp router-id 10.0.2.2
 no bgp default ipv4-unicast
 neighbor 198.51.100.1 remote-as 65001
 neighbor 198.51.100.1 ebgp-multihop 2
 neighbor 198.51.100.1 update-source 10.0.2.2
 neighbor 198.51.100.1 timers connect 1
 address-family ipv4 unicast
  network 100.64.0.0/24
  neighbor 198.51.100.1 activate
  neighbor 198.51.100.1 route-map all in
  neighbor 198.51.100.1 route-map all out
 exit-address-family
exit
CONF
touch "$work/peer/etc/vtysh.conf" "$work/router/etc/vtysh.conf" "$work/mh/etc/vtysh.conf"
chown frr:frr "$work"/*/etc/*
frr_start "$peer" peer
frr "$peer" peer vtysh -b >"$work/peer-boot.log" 2>&1 || fail "the peer's FRR does not take its configuration"
frr_start "$mh" mh
frr "$mh" mh vtysh -b >"$work/mh-boot.log" 2>&1 || fail "mh's FRR does not take its configuration"

cat >"$work/router.toml" <<'TOML'
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
ipv6 = ["2001:db8:100::1/64"]

[[route]]
prefix = "10.0.2.0/24"
interface = "r-wan"
via = "198.51.100.10"

[bgp]
as = 65001
networks = ["192.0.2.0/24", "2001:db8:1::/64"]
include = "WORK/include.conf"

[[bgp.neighbor]]
address = "198.51.100.10"
remote-as = 65002
description = "the peer"

[[bgp.neighbor]]
address = "2001:db8:100::10"
remote-as = 65002

[[bgp.neighbor]]
address = "10.0.2.2"
remote-as = 65003
TOML
sed -i "s|WORK|$work|" "$work/router.toml"
# The operator's own FRR settings: a quicker session for the test, and what the
# multihop neighbor needs. zebra sees only the kernel's routes, where everything
# not on a link goes to the TUN by the default route; it is let to resolve mh's
# next hop through it, and ribd resolves it for the FE through the static route.
cat >"$work/include.conf" <<'CONF'
ip nht resolve-via-default
router bgp 65001
 neighbor 198.51.100.10 timers connect 1
 neighbor 2001:db8:100::10 timers connect 1
 neighbor 10.0.2.2 ebgp-multihop 2
 neighbor 10.0.2.2 update-source 198.51.100.1
 neighbor 10.0.2.2 timers connect 1
exit
CONF
# frr-reload.py, run in the router's FRR's mount namespace, where the file
# ruster-frr writes is /etc/frr/frr.conf. It fails while $work/broken exists.
cat >"$work/reload" <<SH
#!/usr/bin/env bash
[[ ! -e "$work/broken" ]] || { echo "broken on purpose" >&2; exit 1; }
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
start ruster-fe --backend "$backend" r-lan r-wan
start ruster-ribd confd:1 frr:20:65000
start ruster-neighd
start ruster-confd --kernel "$work/router.toml"
for _ in $(seq 1 50); do nsx "$router" ip link show rt-default >/dev/null 2>&1 && break; sleep 0.1; done
frr_start "$router" router -M dplane_fpm_nl
frr_owner=$(id -u frr)
start ruster-frr --reload "$work/reload" --fpm-owner "$frr_owner" "$work/router/etc/frr.conf"

ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
routes() { ruster show 2>/dev/null | grep "^route " || true; }
wait_route() { # pattern, present (1) or gone (0)
  for _ in $(seq 1 300); do
    if routes | grep -q "$1"; then [[ $2 == 1 ]] && return 0; else [[ $2 == 0 ]] && return 0; fi
    sleep 0.1
  done
  return 1
}
wait_route "203.0.113.0/24" 1 || fail "the FE has no route to 203.0.113.0/24: $(routes)"
wait_route "2001:db8:203::/64" 1 || fail "the FE has no route to 2001:db8:203::/64: $(routes)"
echo "ok: the router's FRR learns the peer's prefixes, and ribd puts them in the FE"
echo "    $(routes | grep -E '203.0.113.0/24|2001:db8:203::/64' | tr '\n' ' ')"
grep -q "neighbor 198.51.100.10 description the peer" "$work/router/etc/frr.conf" ||
  fail "ruster-frr's file: $(cat "$work/router/etc/frr.conf")"

reach() { # ns address
  for _ in $(seq 1 20); do nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1 && return 0; done
  return 1
}
reach "$lan" 203.0.113.10 || fail "the LAN host does not reach 203.0.113.10"
reach "$lan" 2001:db8:203::10 || fail "the LAN host does not reach 2001:db8:203::10"
echo "ok: the LAN host reaches the host behind the peer, over IPv4 and IPv6"
frr "$peer" peer vtysh -c "show ip route bgp" | grep -q "192.0.2.0/24 .* via 198.51.100.1" ||
  fail "the peer has no route to the LAN: $(frr "$peer" peer vtysh -c 'show ip route')"
frr "$peer" peer vtysh -c "show ipv6 route bgp" | grep -q "2001:db8:1::/64 .* via fe80::ff:fe00:2" ||
  fail "the peer's IPv6 route to the LAN: $(frr "$peer" peer vtysh -c 'show ipv6 route')"
echo "ok: the peer learns the LAN's prefixes from the router, the IPv6 one via the FE port's link-local"

# The multihop neighbor: its next hop 10.0.2.2 is resolved through the static route.
wait_route "100.64.0.0/24 via 198.51.100.10 dev r-wan" 1 ||
  fail "the FE has no resolved route to 100.64.0.0/24: $(routes)"
reach "$lan" 100.64.0.10 || fail "the LAN host does not reach 100.64.0.10"
echo "ok: a prefix from a neighbor two hops away goes to the FE through the static route"
echo "    $(routes | grep '100.64.0.0/24')"
# Without the static route the next hop cannot be resolved, and the route leaves
# the FE; with it back, the route comes back.
sed '/^\[\[route\]\]/,/^via/d' "$work/router.toml" >"$work/no-static.toml"
ruster apply "$work/no-static.toml" >/dev/null || fail "ruster apply without the static route"
wait_route "100.64.0.0/24" 0 || fail "the route stays without the static route: $(routes)"
ruster apply "$work/router.toml" >/dev/null || fail "ruster apply with the static route"
wait_route "100.64.0.0/24 via 198.51.100.10 dev r-wan" 1 ||
  fail "the route does not come back with the static route: $(routes)"
reach "$lan" 100.64.0.10 || fail "100.64.0.10 after the static route came back"
echo "ok: the route follows the static route it is resolved through"

# ruster-frr starts again: the routes stay, and come back from zebra.
kill "${pids[4]}"; wait "${pids[4]}" 2>/dev/null || true
routes | grep -q "203.0.113.0/24" || fail "the route went when ruster-frr stopped"
start ruster-frr --reload "$work/reload" --fpm-owner "$frr_owner" "$work/router/etc/frr.conf"
for _ in $(seq 1 100); do grep -q "giving them to ribd" "$work/ruster-frr.log" && break; sleep 0.1; done
for _ in $(seq 1 100); do
  (( $(grep -c "giving them to ribd" "$work/ruster-frr.log") == 2 )) && break
  sleep 0.1
done
(( $(grep -c "giving them to ribd" "$work/ruster-frr.log") == 2 )) || fail "ruster-frr did not take zebra's routes again"
routes | grep -q "203.0.113.0/24" || fail "the route is gone after ruster-frr started again"
reach "$lan" 203.0.113.10 || fail "after ruster-frr started again"
echo "ok: ruster-frr starts again and takes zebra's routes again; forwarding goes on"

# A configuration FRR cannot apply is refused, and the one before stays.
touch "$work/broken"
sed 's/remote-as = 65002/remote-as = 65003/' "$work/router.toml" >"$work/other-as.toml"
before=$(cat "$work/router/etc/frr.conf")
out=$(ruster apply "$work/other-as.toml" 2>&1) && fail "ruster apply took it: $out"
grep -q "refused" <<<"$out" || fail "ruster apply said: $out"
[[ "$(cat "$work/router/etc/frr.conf")" == "$before" ]] || fail "FRR's file changed"
rm "$work/broken"
echo "ok: a configuration FRR cannot apply is refused, and the one before stays"

# The peer withdraws the prefix: the route leaves the FE.
frr "$peer" peer vtysh -c "configure terminal" -c "router bgp 65002" \
  -c "address-family ipv4 unicast" -c "no network 203.0.113.0/24" >/dev/null
wait_route "203.0.113.0/24" 0 || fail "the withdrawn route stays: $(routes)"
nsx "$lan" ping -c 1 -W 1 203.0.113.10 >/dev/null 2>&1 && fail "203.0.113.10 is still reached"
routes | grep -q "2001:db8:203::/64" || fail "the IPv6 route went too"
echo "ok: when the peer withdraws the prefix, the route leaves the FE"

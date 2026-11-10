#!/usr/bin/env bash
# IS-IS through FRR on a TAP device (docs/design/overlay.md section 6): confd makes
# rp-r-wan and rp-r-lan in the router's namespace, the FE hands them the IS-IS PDUs
# of their ports and sends out what isisd writes there. The router's isisd forms an
# adjacency with a neighbouring FRR over a plain veth and learns its prefixes, IPv4
# and IPv6 (the IPv6 next hop is the neighbour's link-local address, through the
# TAP); ruster-frr gives them to ribd on the FE's port. A LAN host reaches a host
# behind the neighbour, and the neighbour learns the LAN's prefixes from the router.
#
#   lan (192.0.2.10) -- [r-lan | router | r-wan 198.51.100.1] -- peer (198.51.100.10,
#     FRR isisd) -- far (203.0.113.10, 2001:db8:203::10)
#
# Needs FRR (apt-get install frr). Run as root, after `cargo build`:
#   sudo scripts/netns-isis.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsi$$
lan=$tag-lan peer=$tag-peer far=$tag-far router=$tag-r
work=$(mktemp -d)
chmod 0755 "$work"
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for side in router peer; do
    for pid in $(cat "$work/$side"/run/*.pid 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  done
  wait 2>/dev/null || true
  for ns in "$lan" "$peer" "$far" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
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
[[ -x /usr/lib/frr/isisd ]] || fail "FRR is not installed"

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
  frr "$ns" "$side" /usr/lib/frr/isisd -d --log file:/var/log/frr/isisd.log >/dev/null 2>&1
}
for side in router peer; do
  mkdir -p "$work/$side/etc" "$work/$side/run" "$work/$side/log"
  touch "$work/$side/etc/vtysh.conf"
  chown -R frr:frr "$work/$side"
done

for ns in "$lan" "$peer" "$far" "$router"; do ip netns add "$ns"; done
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
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports

# The peer's isisd: on the router's link, and announcing the far link (passive).
cat >"$work/peer/etc/frr.conf" <<'CONF'
interface h0
 ip router isis peer
 ipv6 router isis peer
 isis hello-interval 1
exit
interface h1
 ip router isis peer
 ipv6 router isis peer
 isis passive
exit
router isis peer
 net 49.0001.1921.6800.2010.00
 is-type level-2-only
 metric-style wide
exit
CONF
chown frr:frr "$work/peer/etc/frr.conf"
frr_start "$peer" peer
frr "$peer" peer vtysh -b >"$work/peer-boot.log" 2>&1 || fail "the peer's FRR does not take its configuration"

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

[isis]
net = "49.0001.1921.6800.1001.00"
level = "level-2"

[[isis.interface]]
name = "r-wan"

[[isis.interface]]
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
start ruster-fe --backend "$backend" r-lan r-wan
start ruster-ribd confd:1 frr:20:65000
start ruster-neighd
start ruster-confd --kernel "$work/router.toml"
for _ in $(seq 1 50); do nsx "$router" ip link show rp-r-wan >/dev/null 2>&1 && break; sleep 0.1; done
nsx "$router" ip link show rp-r-wan >/dev/null 2>&1 || fail "confd made no TAP device"
for _ in $(seq 1 50); do
  nsx "$router" ip link show rp-r-wan | grep -q LOWER_UP && break
  sleep 0.1
done
nsx "$router" ip link show rp-r-wan | grep -q LOWER_UP || fail "the FE does not hold the TAP open"
nsx "$router" ip -4 address show dev rp-r-wan | grep -q "198.51.100.1/24" ||
  fail "the TAP has not the port's address: $(nsx "$router" ip address show rp-r-wan)"
nsx "$router" ip -4 address show dev rt-default | grep -q "198.51.100.1" &&
  fail "the TUN still has the port's address"
echo "ok: confd makes rp-r-wan and rp-r-lan with the ports' addresses, and the FE holds them open"

frr_start "$router" router -M dplane_fpm_nl
start ruster-frr --reload "$work/reload" --fpm-owner "$(id -u frr)" "$work/router/etc/frr.conf"

ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
routes() { ruster show 2>/dev/null | grep "^route " || true; }
wait_route() { # pattern
  for _ in $(seq 1 600); do routes | grep -q "$1" && return 0; sleep 0.1; done
  return 1
}
wait_route "203.0.113.0/24 via 198.51.100.10 dev r-wan" ||
  fail "the FE has no IS-IS route to 203.0.113.0/24: $(routes)
$(frr "$router" router vtysh -c 'show isis neighbor' -c 'show ip route' 2>&1)"
echo "ok: the router's isisd forms an adjacency through the TAP and learns 203.0.113.0/24 for r-wan"
echo "    $(routes | grep '203.0.113.0/24')"
wait_route "2001:db8:203::/64 via fe80::.* dev r-wan" ||
  fail "the FE has no IPv6 IS-IS route through the link-local next hop: $(routes)"
echo "ok: the IPv6 route's next hop is the peer's link-local address on r-wan"
echo "    $(routes | grep '2001:db8:203::/64')"

reach() { # ns address
  for _ in $(seq 1 20); do nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1 && return 0; done
  return 1
}
for _ in $(seq 1 100); do
  frr "$peer" peer vtysh -c "show ip route 192.0.2.0/24" 2>/dev/null | grep -q isis && break
  sleep 0.1
done
reach "$lan" 203.0.113.10 || fail "the LAN host does not reach 203.0.113.10"
reach "$lan" 2001:db8:203::10 || fail "the LAN host does not reach 2001:db8:203::10"
echo "ok: the LAN host reaches the host behind the peer over IPv4 and IPv6, and the peer"
echo "    learns the LAN's prefixes from the router's passive interface"

# The router's own traffic to the peer leaves through the TAP and the FE.
nsx "$router" ping -c 1 -W 2 198.51.100.10 >/dev/null || fail "the router does not reach the peer"
echo "ok: the router's own packets to the peer's subnet go out through the TAP"

# Taking IS-IS off r-lan removes its TAP and puts its address back on the TUN.
sed '/^\[\[isis.interface\]\]/{N;/r-lan/{N;d}}' "$work/router.toml" >"$work/wan-only.toml"
ruster apply "$work/wan-only.toml" >/dev/null || fail "ruster apply without r-lan in isis"
nsx "$router" ip link show rp-r-lan >/dev/null 2>&1 && fail "rp-r-lan stays"
nsx "$router" ip -4 address show dev rt-default | grep -q "192.0.2.1/24" ||
  fail "r-lan's address is not back on the TUN"
reach "$lan" 192.0.2.1 || fail "the LAN host does not reach the router"
echo "ok: without IS-IS on r-lan its TAP goes and its address is back on the TUN"

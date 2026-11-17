#!/usr/bin/env bash
# BGP through the systemd units in contrib/systemd: ruster-frr.service writes FRR's
# configuration from confd's frr part, the distribution's frr.service runs FRR in the
# router's namespace through the drop-in of contrib/systemd, and FRR learns a prefix
# from a neighbouring FRR and hands it to ruster-frr over FPM. ribd puts it in the
# FE, and the LAN host reaches a host behind the neighbour. When ruster-frr is
# killed, systemd starts it again and the route stays.
#
#   lan (192.0.2.10) -- [r-lan | router | r-wan 198.51.100.1] -- peer (198.51.100.10,
#     AS 65002, FRR) -- far (203.0.113.10)
#
# The units and drop-ins go to /run/systemd/system (gone at reboot) and are removed
# at the end. A second drop-in here binds this test's directories over /etc/frr,
# /run/frr and /var/log/frr for frr.service and ruster-frr.service, so the host's
# own FRR files are not touched. Needs systemd as process 1, no ruster units
# installed, and frr installed but not running. Run as root, after `cargo build`:
#   sudo scripts/netns-systemd-frr.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}

bin=$(realpath "${1:-target/debug}")
here=$(dirname "$(realpath "$0")")
units_dir=$(realpath "$here/../contrib/systemd")
for name in ruster-fe ruster-ribd ruster-neighd ruster-confd ruster-frr ruster; do
  [[ -x "$bin/$name" ]] || { echo "missing $bin/$name (run cargo build)" >&2; exit 2; }
done
[[ "$(ps -p 1 -o comm=)" == systemd ]] || { echo "systemd is not process 1" >&2; exit 2; }
[[ -x /usr/lib/frr/bgpd ]] || { echo "FRR is not installed" >&2; exit 2; }
units=(ruster.target ruster-netns.service ruster-fe.service ruster-ribd.service
  ruster-neighd.service ruster-confd.service ruster-frr.service)
for unit in "${units[@]}"; do
  if systemctl cat "$unit" >/dev/null 2>&1; then
    echo "$unit is installed already; this test would replace it" >&2
    exit 2
  fi
done
systemctl cat frr.service >/dev/null 2>&1 || { echo "frr.service is not installed" >&2; exit 2; }
if systemctl -q is-active frr.service; then echo "frr.service runs; stop it first" >&2; exit 2; fi
if [[ -e /run/systemd/system/frr.service.d ]]; then echo "/run/systemd/system/frr.service.d exists" >&2; exit 2; fi
for dev in r-lan r-wan; do
  if ip link show "$dev" >/dev/null 2>&1; then echo "device $dev exists already" >&2; exit 2; fi
done

tag=rsf$$
lan=$tag-lan peer=$tag-peer far=$tag-far router=$tag-r
work=$(mktemp -d)
chmod 0755 "$work"
started=$(date +%s)

cleanup() {
  systemctl stop frr.service 2>/dev/null || true
  systemctl stop ruster.target "${units[@]}" 2>/dev/null || true
  for unit in "${units[@]}"; do rm -f "/run/systemd/system/$unit"; done
  rm -rf /run/systemd/system/frr.service.d /run/systemd/system/ruster-frr.service.d
  systemctl daemon-reload
  systemctl reset-failed "${units[@]}" frr.service 2>/dev/null || true
  for pid in $(cat "$work"/peer/run/*.pid 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  for ns in "$lan" "$peer" "$far" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  ip link del r-lan 2>/dev/null || true
  ip link del r-wan 2>/dev/null || true
  rm -rf /run/ruster
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  systemctl status --no-pager "${units[@]}" frr.service >&2 || true
  journalctl -q --no-pager -u 'ruster*' -u frr --since "@$started" >&2 || true
  for log in "$work"/*/log/*.log; do [[ -e "$log" ]] && { echo "== $log"; tail -n 40 "$log"; }; done >&2
  exit 1
}

# The units as shipped, with the paths of this checkout and this test.
mkdir -p "$work/etc" "$work/state"
ship() { # source destination
  sed -e "s|/usr/local/bin/|$bin/|g" \
    -e "s|/usr/local/lib/ruster/|$units_dir/|g" \
    -e "s|/etc/ruster/|$work/etc/|g" \
    -e "s|/run/netns/ruster|/run/netns/$router|g" \
    -e "s#ruster-netns \(up\|down\) ruster #ruster-netns \1 $router #g" \
    -e "s|/var/lib/ruster/confd|$work/state/confd|g" \
    -e "/^StateDirectory/d" \
    "$1" >"$2"
}
for unit in "${units[@]}"; do ship "$units_dir/$unit" "/run/systemd/system/$unit"; done
mkdir -p /run/systemd/system/frr.service.d /run/systemd/system/ruster-frr.service.d
ship "$units_dir/frr.service.d/ruster.conf" /run/systemd/system/frr.service.d/ruster.conf
# The router's FRR directories, for FRR and for ruster-frr (which writes frr.conf
# and runs frr-reload.py, which talks to FRR in /run/frr).
for side in router peer; do
  mkdir -p "$work/$side/etc" "$work/$side/run" "$work/$side/log"
done
for unit in frr.service ruster-frr.service; do
  cat >"/run/systemd/system/$unit.d/test.conf" <<EOF
[Service]
BindPaths=$work/router/etc:/etc/frr $work/router/run:/run/frr $work/router/log:/var/log/frr
EOF
done
# systemd reads frr.service's PID file outside the bound directories.
echo "PIDFile=$work/router/run/watchfrr.pid" >>/run/systemd/system/frr.service.d/test.conf
systemctl daemon-reload

cat >"$work/etc/ruster.env" <<EOF
RUSTER_PORTS="r-lan r-wan"
RUSTER_FE_OPTIONS="--backend $backend"
RUSTER_RIBD_SOURCES="confd:1 frr:20:65000"
EOF
cat >"$work/etc/router.toml" <<TOML
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"

[bgp]
as = 65001
networks = ["192.0.2.0/24"]
include = "$work/include.conf"

[[bgp.neighbor]]
address = "198.51.100.10"
remote-as = 65002
TOML
cat >"$work/include.conf" <<'CONF'
router bgp 65001
 neighbor 198.51.100.10 timers connect 1
exit
CONF
# The router's FRR, as the operator sets it up: bgpd, and zebra with FPM.
cat >"$work/router/etc/daemons" <<'EOF'
bgpd=yes
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000 -M dplane_fpm_nl"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
EOF
touch "$work/router/etc/vtysh.conf" "$work/router/etc/frr.conf" "$work/peer/etc/vtysh.conf"
# The peer's FRR, run here without systemd: it announces the far prefix.
cat >"$work/peer/etc/frr.conf" <<'CONF'
route-map all permit 10
exit
router bgp 65002
 bgp router-id 198.51.100.10
 no bgp default ipv4-unicast
 neighbor 198.51.100.1 remote-as 65001
 neighbor 198.51.100.1 timers connect 1
 address-family ipv4 unicast
  network 203.0.113.0/24
  neighbor 198.51.100.1 activate
  neighbor 198.51.100.1 route-map all in
  neighbor 198.51.100.1 route-map all out
 exit-address-family
exit
CONF
chown -R frr:frr "$work/router" "$work/peer"

nsx() { ip netns exec "$@"; }
# Runs a command in namespace $1 with the peer's FRR directories.
peer_frr() {
  nsx "$peer" unshare -m sh -c "mount --bind '$work/peer/etc' /etc/frr &&
    mount --bind '$work/peer/run' /run/frr && mount --bind '$work/peer/log' /var/log/frr &&
    exec \"\$@\"" sh "$@"
}
for ns in "$lan" "$peer" "$far"; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
# The router's ends start in the host's namespace, as a real NIC would.
ip link add h0 netns "$lan" type veth peer name r-lan
ip link add h0 netns "$peer" type veth peer name r-wan
ip link set r-lan address 02:00:00:00:00:01
ip link set r-wan address 02:00:00:00:00:02
for dev in r-lan r-wan; do ethtool -K "$dev" gro off >/dev/null 2>&1 || true; done
for ns in "$lan" "$peer"; do
  nsx "$ns" ethtool -K h0 tx off >/dev/null
  nsx "$ns" sysctl -qw net.ipv6.conf.h0.disable_ipv6=1
  nsx "$ns" ip link set h0 up
done
nsx "$lan" ip addr add 192.0.2.10/24 dev h0
nsx "$lan" ip route add default via 192.0.2.1
nsx "$peer" ip addr add 198.51.100.10/24 dev h0
ip link add h1 netns "$peer" type veth peer name h0 netns "$far"
nsx "$peer" sysctl -qw net.ipv4.ip_forward=1
nsx "$peer" ethtool -K h1 tx off >/dev/null
nsx "$peer" ip link set h1 up
nsx "$peer" ip addr add 203.0.113.1/24 dev h1
nsx "$far" ethtool -K h0 tx off >/dev/null
nsx "$far" ip link set h0 up
nsx "$far" ip addr add 203.0.113.10/24 dev h0
nsx "$far" ip route add default via 203.0.113.1
peer_frr /usr/lib/frr/mgmtd -d --log file:/var/log/frr/mgmtd.log >/dev/null 2>&1
peer_frr /usr/lib/frr/zebra -d --log file:/var/log/frr/zebra.log >/dev/null 2>&1
peer_frr /usr/lib/frr/bgpd -d --log file:/var/log/frr/bgpd.log >/dev/null 2>&1
peer_frr vtysh -b >"$work/peer-boot.log" 2>&1 || fail "the peer's FRR does not take its configuration"

systemctl start ruster.target ruster-frr.service || fail "the ruster units did not start"
systemctl start frr.service || fail "frr.service did not start"
for unit in "${units[@]}" frr.service; do systemctl -q is-active "$unit" || fail "$unit is not active"; done
zebra=$(cat "$work/router/run/zebra.pid")
[[ "$(ip netns identify "$zebra")" == "$router" ]] || fail "zebra does not run in the router's namespace"
grep -q "neighbor 198.51.100.10 remote-as 65002" "$work/router/etc/frr.conf" ||
  fail "ruster-frr's file: $(cat "$work/router/etc/frr.conf")"
echo "ok: the units start the router and ruster-frr, and frr.service runs FRR in its namespace"

routes() { nsx "$router" "$bin/ruster" show 2>/dev/null | grep "^route " || true; }
wait_route() {
  for _ in $(seq 1 600); do routes | grep -q "$1" && return 0; sleep 0.1; done
  return 1
}
reach() {
  for _ in $(seq 1 20); do nsx "$lan" ping -c 1 -W 1 203.0.113.10 >/dev/null 2>&1 && return 0; done
  return 1
}
wait_route "203.0.113.0/24 via 198.51.100.10 dev r-wan" || fail "the FE has no route to 203.0.113.0/24: $(routes)"
reach || fail "the LAN host does not reach 203.0.113.10"
echo "ok: FRR learns the peer's prefix, ribd puts it in the FE, and the LAN host reaches the far host"

# Killed, ruster-frr is started again by systemd; the route stays meanwhile.
systemctl kill -s KILL ruster-frr.service
for _ in $(seq 1 50); do systemctl -q is-active ruster-frr.service && break; sleep 0.1; done
systemctl -q is-active ruster-frr.service || fail "ruster-frr did not come back"
routes | grep -q "203.0.113.0/24" || fail "the route went when ruster-frr was killed"
reach || fail "no forwarding after ruster-frr was killed"
echo "ok: ruster-frr killed with SIGKILL comes back, and the route stays"

# Stopping the router stops FRR with it: it is bound to the router's namespace.
systemctl stop ruster.target
for unit in "${units[@]}" frr.service; do
  for _ in $(seq 1 100); do systemctl -q is-active "$unit" || break; sleep 0.1; done
  if systemctl -q is-active "$unit"; then fail "$unit is still active after stop"; fi
done
echo "ok: stopping ruster.target stops ruster-frr and FRR"

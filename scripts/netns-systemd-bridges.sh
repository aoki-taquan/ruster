#!/usr/bin/env bash
# A home router started by the systemd units in contrib/systemd, with the bridges:
# ruster-dhcpc takes the WAN address from the ISP's DHCP server, ruster-kea and the
# distribution's Kea service hand the LAN host an address, and ruster-unbound and
# the distribution's Unbound service answer its names. Kea and Unbound run in the
# router's namespace through the drop-ins of contrib/systemd. The LAN host then
# reaches the ISP side through NAT. No internet is needed.
#
#   lan (DHCP) -- [r-lan 192.168.0.1 | router | r-wan: DHCP] -- isp (198.51.100.1: udhcpd, Unbound)
#
# The units and drop-ins go to /run/systemd/system (gone at reboot) and are
# removed at the end; each drop-in gets a second one here that points Kea and
# Unbound at this test's files. Needs systemd as process 1, no ruster units
# installed, the services kea-dhcp4-server and unbound installed but not running,
# and busybox, udhcpc and dig. Run as root, after `cargo build`:
#   sudo scripts/netns-systemd-bridges.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}

bin=$(realpath "${1:-target/debug}")
here=$(dirname "$(realpath "$0")")
units_dir=$(realpath "$here/../contrib/systemd")
for name in ruster-fe ruster-ribd ruster-neighd ruster-confd ruster-dhcpc ruster-kea ruster-unbound ruster; do
  [[ -x "$bin/$name" ]] || { echo "missing $bin/$name (run cargo build)" >&2; exit 2; }
done
[[ "$(ps -p 1 -o comm=)" == systemd ]] || { echo "systemd is not process 1" >&2; exit 2; }
for program in kea-dhcp4 unbound busybox udhcpc dig; do
  command -v "$program" >/dev/null || { echo "$program is not installed" >&2; exit 2; }
done
units=(ruster.target ruster-netns.service ruster-fe.service ruster-ribd.service
  ruster-neighd.service ruster-confd.service ruster-dhcpc.service ruster-kea.service
  ruster-unbound.service)
others=(kea-dhcp4-server.service unbound.service)
for unit in "${units[@]}"; do
  if systemctl cat "$unit" >/dev/null 2>&1; then
    echo "$unit is installed already; this test would replace it" >&2
    exit 2
  fi
done
for unit in "${others[@]}"; do
  systemctl cat "$unit" >/dev/null 2>&1 || { echo "$unit is not installed" >&2; exit 2; }
  if systemctl -q is-active "$unit"; then echo "$unit runs; stop it first" >&2; exit 2; fi
  if [[ -e "/run/systemd/system/$unit.d" ]]; then echo "/run/systemd/system/$unit.d exists" >&2; exit 2; fi
done
for dev in r-lan r-wan; do
  if ip link show "$dev" >/dev/null 2>&1; then echo "device $dev exists already" >&2; exit 2; fi
done

tag=rsb$$
lan=$tag-lan isp=$tag-isp router=$tag-r
work=$(mktemp -d)
# Ubuntu's AppArmor profiles let Kea read only below /etc/kea, and Unbound below
# /etc/unbound and /var/lib/unbound.
kdir=/etc/kea/$tag
udir=/var/lib/unbound/$tag
started=$(date +%s)
pids=()

cleanup() {
  systemctl stop "${others[@]}" 2>/dev/null || true
  systemctl stop ruster.target "${units[@]}" 2>/dev/null || true
  journalctl -q --no-pager -u 'ruster*' -u kea-dhcp4-server -u unbound --since "@$started" \
    >"$work/journal.log" 2>&1 || true
  for unit in "${units[@]}"; do rm -f "/run/systemd/system/$unit"; done
  for unit in "${others[@]}"; do rm -rf "/run/systemd/system/$unit.d"; done
  systemctl daemon-reload
  systemctl reset-failed "${units[@]}" "${others[@]}" 2>/dev/null || true
  for pid in ${pids[@]+"${pids[@]}"} $(cat "$udir"/up/unbound.pid 2>/dev/null); do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  for ns in "$lan" "$isp" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  ip link del r-lan 2>/dev/null || true
  ip link del r-wan 2>/dev/null || true
  rm -rf /run/ruster "$kdir" "$udir"
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  systemctl status --no-pager "${units[@]}" "${others[@]}" >&2 || true
  journalctl -q --no-pager -u 'ruster*' -u kea-dhcp4-server -u unbound --since "@$started" >&2 || true
  for log in "$work"/*.log "$udir"/unbound.log "$udir"/up/unbound.log; do
    [[ -e "$log" ]] && { echo "== $log"; cat "$log"; }
  done >&2
  exit 1
}

# The units as shipped, with the paths of this checkout and this test.
mkdir -p "$work/etc" "$work/state" "$kdir" "$udir/up"
ship() { # source destination
  sed -e "s|/usr/local/bin/|$bin/|g" \
    -e "s|/usr/local/lib/ruster/|$units_dir/|g" \
    -e "s|/etc/ruster/|$work/etc/|g" \
    -e "s|/run/netns/ruster|/run/netns/$router|g" \
    -e "s#ruster-netns \(up\|down\) ruster #ruster-netns \1 $router #g" \
    -e "s|/var/lib/ruster/confd|$work/state/confd|g" \
    -e "s|/etc/kea/ruster-dhcp4.json|$kdir/ruster-dhcp4.json|g" \
    -e "s|/etc/unbound/unbound.conf.d/ruster.conf|$udir/ruster.conf|g" \
    -e "/^StateDirectory/d" \
    "$1" >"$2"
}
for unit in "${units[@]}"; do ship "$units_dir/$unit" "/run/systemd/system/$unit"; done
for unit in "${others[@]}"; do
  mkdir -p "/run/systemd/system/$unit.d"
  ship "$units_dir/$unit.d/ruster.conf" "/run/systemd/system/$unit.d/ruster.conf"
done
# This test's configuration files instead of the distribution's.
cat >/run/systemd/system/kea-dhcp4-server.service.d/test.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/sbin/kea-dhcp4 -c $kdir/kea-dhcp4.conf
EOF
cat >/run/systemd/system/unbound.service.d/test.conf <<EOF
[Service]
ExecStartPre=
ExecStart=
ExecStart=/usr/sbin/unbound -d -p -c $udir/unbound.conf
EOF
systemctl daemon-reload

cat >"$work/etc/ruster.env" <<EOF
RUSTER_PORTS="r-lan r-wan"
RUSTER_FE_OPTIONS="--backend $backend"
RUSTER_RIBD_SOURCES="confd:1 dhcpc:5"
RUSTER_KEA_OPTIONS=""
EOF
cat >"$work/etc/router.toml" <<'TOML'
[[source]]
name = "dhcp-wan"
kind = "dhcp-client"

[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4-from = "dhcp-wan"

[[dhcp-client]]
interface = "r-wan"

[nat]
inside = "r-lan"
outside = "r-wan"
ports = "20000-20999"

[[dhcp]]
interface = "r-lan"
pool = "192.168.0.100-192.168.0.120"
lease-time = 600
dns = ["192.168.0.1"]

[dns]
upstream = ["198.51.100.1"]
TOML

# The operator's kea-dhcp4.conf: everything but what ruster-kea writes.
cat >"$kdir/kea-dhcp4.conf" <<CONF
{ "Dhcp4": {
<?include "$kdir/ruster-dhcp4.json"?>,
"lease-database": { "type": "memfile", "persist": false },
"control-socket": { "socket-type": "unix", "socket-name": "kea4-ctrl-socket" },
"loggers": [ { "name": "kea-dhcp4", "output-options": [ { "output": "stdout" } ], "severity": "INFO" } ]
} }
CONF
# The ISP's DHCP server is busybox's udhcpd: AppArmor lets only one Kea write its
# PID file.
cat >"$work/udhcpd.conf" <<CONF
start 198.51.100.100
end 198.51.100.110
interface h0
lease_file $work/udhcpd.leases
pidfile $work/udhcpd.pid
opt router 198.51.100.1
opt dns 198.51.100.1
opt lease 600
CONF
touch "$work/udhcpd.leases"
chown -R _kea "$kdir"
unbound_common() { # directory
  cat <<CONF
server:
    username: ""
    chroot: ""
    directory: "$1"
    pidfile: "$1/unbound.pid"
    use-syslog: no
    logfile: "$1/unbound.log"
    do-ip6: no
CONF
}
{
  unbound_common "$udir"
  cat <<CONF
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-use-cert: no
include-toplevel: "$udir/ruster.conf"
CONF
} >"$udir/unbound.conf"
{
  unbound_common "$udir/up"
  cat <<CONF
    interface: 198.51.100.1
    access-control: 198.51.100.0/24 allow
    local-zone: "up.example." static
    local-data: "www.up.example. A 203.0.113.80"
CONF
} >"$udir/up/unbound.conf"

nsx() { ip netns exec "$@"; }
for ns in "$lan" "$isp"; do ip netns add "$ns"; done
# The router's ends start in the host's namespace, as a real NIC would.
ip link add h0 netns "$lan" type veth peer name r-lan
ip link add h0 netns "$isp" type veth peer name r-wan
ip link set r-lan address 02:00:00:00:00:01
ip link set r-wan address 02:00:00:00:00:02
for dev in r-lan r-wan; do ethtool -K "$dev" gro off >/dev/null 2>&1 || true; done
for ns in "$lan" "$isp"; do
  # veth leaves checksums to the receiver; the FE forwards frames as they are.
  nsx "$ns" ethtool -K h0 tx off >/dev/null
  nsx "$ns" sysctl -qw net.ipv6.conf.h0.disable_ipv6=1
  nsx "$ns" ip link set h0 up
  nsx "$ns" ip link set lo up
done
nsx "$isp" ip addr add 198.51.100.1/24 dev h0

nsx "$isp" busybox udhcpd -f "$work/udhcpd.conf" >>"$work/udhcpd.log" 2>&1 &
pids+=("$!")
nsx "$isp" unbound -c "$udir/up/unbound.conf" || fail "the ISP's Unbound does not start"

systemctl start ruster.target ruster-dhcpc.service ruster-kea.service ruster-unbound.service ||
  fail "the ruster units did not start"
systemctl start kea-dhcp4-server.service unbound.service || fail "Kea or Unbound did not start"
for unit in "${units[@]}" "${others[@]}"; do
  systemctl -q is-active "$unit" || fail "$unit is not active"
done
[[ "$(ip netns identify "$(systemctl show -P MainPID kea-dhcp4-server)")" == "$router" ]] ||
  fail "Kea does not run in the router's namespace"
[[ "$(ip netns identify "$(systemctl show -P MainPID unbound)")" == "$router" ]] ||
  fail "Unbound does not run in the router's namespace"
echo "ok: the units start the router, the bridges, and Kea and Unbound in its namespace"

show() { nsx "$router" "$bin/ruster" show; }
for _ in $(seq 1 200); do show | grep -q "route default 0.0.0.0/0 via 198.51.100.1 dev r-wan" && break; sleep 0.1; done
out=$(show)
grep -Eq "address r-wan 198\.51\.100\.1(0[0-9]|10)/24" <<<"$out" || fail "r-wan has no leased address: $out"
grep -q "route default 0.0.0.0/0 via 198.51.100.1 dev r-wan" <<<"$out" || fail "no default route: $out"
echo "ok: ruster-dhcpc took the WAN address and the default route from the ISP"

cat >"$work/udhcpc.sh" <<SH
#!/bin/sh
case "\$1" in
  deconfig) ip addr flush dev "\$interface" ;;
  bound|renew)
    ip addr replace "\$ip/\$mask" dev "\$interface"
    ip route replace default via "\$router" dev "\$interface"
    echo "\$1 ip=\$ip router=\$router dns=\$dns" >>"$work/lease" ;;
esac
SH
chmod 0755 "$work/udhcpc.sh"
nsx "$lan" udhcpc -i h0 -s "$work/udhcpc.sh" -f -t 20 -T 1 -A 1 >>"$work/udhcpc.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 250); do [[ -s "$work/lease" ]] && break; sleep 0.1; done
[[ -s "$work/lease" ]] || fail "the LAN host got no lease"
lease=$(head -1 "$work/lease")
grep -Eq "^bound ip=192\.168\.0\.1([01][0-9]|20) router=192\.168\.0\.1 dns=192\.168\.0\.1$" <<<"$lease" ||
  fail "the lease: $lease"
echo "ok: the LAN host got its address from Kea: $lease"

answer=""
for _ in $(seq 1 20); do
  answer=$(nsx "$lan" dig +tries=1 +time=1 +short @192.168.0.1 www.up.example A 2>/dev/null || true)
  [[ "$answer" == 203.0.113.80 ]] && break
  sleep 0.5
done
[[ "$answer" == 203.0.113.80 ]] || fail "the router's Unbound did not answer: $answer"
echo "ok: the router's Unbound answers the LAN host through the ISP's"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.1 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN host does not reach the ISP through NAT"
echo "ok: the LAN host reaches the ISP side through NAT"

# Stopping the router stops Kea and Unbound with it: they are bound to its namespace.
systemctl stop ruster.target
for unit in "${units[@]}" "${others[@]}"; do
  for _ in $(seq 1 100); do systemctl -q is-active "$unit" || break; sleep 0.1; done
  if systemctl -q is-active "$unit"; then fail "$unit is still active after stop"; fi
done
ip link show r-wan >/dev/null 2>&1 || fail "r-wan did not come back to the host's namespace"
echo "ok: stopping ruster.target stops the bridges, Kea and Unbound, and gives the devices back"

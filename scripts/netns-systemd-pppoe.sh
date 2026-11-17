#!/usr/bin/env bash
# PPPoE through the systemd units in contrib/systemd: ruster-pppoed.service sets up
# a session with an access concentrator (rp-pppoe's pppoe-server with pppd), confd
# makes the session interface from what pppoed sends it, ribd takes its default
# route, and the LAN host reaches a host behind the AC through NAT. When pppoed is
# killed, systemd starts it again and the session comes back.
#
#   lan (192.168.0.10) -- [r-lan | router | r-wan]
#       -- [a0 ac: pppoe-server, ppp0 198.51.100.1 | i0] -- net (203.0.113.10)
#
# The units go to /run/systemd/system (gone at reboot) and are removed at the end.
# Needs systemd as process 1, no ruster units installed, and the pppoe and ppp
# packages. Run as root, after `cargo build`:
#   sudo scripts/netns-systemd-pppoe.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}

bin=$(realpath "${1:-target/debug}")
here=$(dirname "$(realpath "$0")")
units_dir=$(realpath "$here/../contrib/systemd")
for name in ruster-fe ruster-ribd ruster-neighd ruster-confd ruster-pppoed ruster; do
  [[ -x "$bin/$name" ]] || { echo "missing $bin/$name (run cargo build)" >&2; exit 2; }
done
[[ "$(ps -p 1 -o comm=)" == systemd ]] || { echo "systemd is not process 1" >&2; exit 2; }
command -v pppoe-server >/dev/null || { echo "pppoe-server is not installed" >&2; exit 2; }
command -v pppd >/dev/null || [[ -x /usr/sbin/pppd ]] || { echo "pppd is not installed" >&2; exit 2; }
modprobe ppp_generic 2>/dev/null || true
units=(ruster.target ruster-netns.service ruster-fe.service ruster-ribd.service
  ruster-neighd.service ruster-confd.service ruster-pppoed.service)
for unit in "${units[@]}"; do
  if systemctl cat "$unit" >/dev/null 2>&1; then
    echo "$unit is installed already; this test would replace it" >&2
    exit 2
  fi
done
for dev in r-lan r-wan; do
  if ip link show "$dev" >/dev/null 2>&1; then echo "device $dev exists already" >&2; exit 2; fi
done

tag=rsp$$
lan=$tag-lan ac=$tag-ac net=$tag-net router=$tag-r
work=$(mktemp -d)
started=$(date +%s)
pids=()

cleanup() {
  systemctl stop ruster.target "${units[@]}" 2>/dev/null || true
  for unit in "${units[@]}"; do rm -f "/run/systemd/system/$unit"; done
  systemctl daemon-reload
  systemctl reset-failed "${units[@]}" 2>/dev/null || true
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  # pppoe-server's children (pppd) are in the namespace too.
  ip netns pids "$ac" 2>/dev/null | xargs -r kill 2>/dev/null || true
  wait 2>/dev/null || true
  for ns in "$lan" "$ac" "$net" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  ip link del r-lan 2>/dev/null || true
  ip link del r-wan 2>/dev/null || true
  rm -rf /run/ruster
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  systemctl status --no-pager "${units[@]}" >&2 || true
  journalctl -q --no-pager -u 'ruster*' --since "@$started" >&2 || true
  for log in "$work"/*.log; do [[ -e "$log" ]] && { echo "== $log"; cat "$log"; }; done >&2
  exit 1
}

# The units as shipped, with the paths of this checkout and this test.
mkdir -p "$work/etc" "$work/state"
for unit in "${units[@]}"; do
  sed -e "s|/usr/local/bin/|$bin/|g" \
    -e "s|/usr/local/lib/ruster/|$units_dir/|g" \
    -e "s|/etc/ruster/|$work/etc/|g" \
    -e "s|/run/netns/ruster|/run/netns/$router|g" \
    -e "s#ruster-netns \(up\|down\) ruster #ruster-netns \1 $router #g" \
    -e "s|/var/lib/ruster/confd|$work/state/confd|g" \
    -e "/^StateDirectory/d" \
    "$units_dir/$unit" >"/run/systemd/system/$unit"
done
systemctl daemon-reload

cat >"$work/etc/ruster.env" <<EOF
RUSTER_PORTS="r-lan r-wan"
RUSTER_FE_OPTIONS="--backend $backend"
RUSTER_RIBD_SOURCES="confd:1 pppoed:5"
EOF
cat >"$work/etc/router.toml" <<'TOML'
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

[[pppoe]]
source = "pppoe-wan"
user = "user@isp"
password = "secret"
service = "inet"
ac-name = "isp-ac"
ipv6 = false
echo-interval = 2
default-route = true

[nat]
inside = "r-lan"
outside = "ppp"
ports = "20000-20999"
TOML

nsx() { ip netns exec "$@"; }
for ns in "$lan" "$ac" "$net"; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
# The router's ends start in the host's namespace, as a real NIC would.
ip link add h0 netns "$lan" type veth peer name r-lan
ip link add a0 netns "$ac" type veth peer name r-wan
ip link set r-lan address 02:00:00:00:00:01
ip link set r-wan address 02:00:00:00:00:02
for dev in r-lan r-wan; do ethtool -K "$dev" gro off >/dev/null 2>&1 || true; done
nsx "$lan" ethtool -K h0 tx off >/dev/null
nsx "$lan" ip link set h0 up
nsx "$lan" ip addr add 192.168.0.10/24 dev h0
nsx "$lan" ip route add default via 192.168.0.1
nsx "$ac" sysctl -qw net.ipv4.ip_forward=1
nsx "$ac" ethtool -K a0 tx off >/dev/null
nsx "$ac" ip link set a0 address 02:00:00:00:00:ac up
ip link add n0 netns "$net" type veth peer name i0 netns "$ac"
nsx "$net" ethtool -K n0 tx off >/dev/null
nsx "$ac" ethtool -K i0 tx off >/dev/null
nsx "$net" ip link set n0 up
nsx "$net" ip addr add 203.0.113.10/24 dev n0
nsx "$net" ip route add default via 203.0.113.1
nsx "$ac" ip link set i0 up
nsx "$ac" ip addr add 203.0.113.1/24 dev i0

# The AC's secrets, bound over /etc/ppp's only inside its `ip netns exec` (which
# has its own mount namespace).
printf '"user@isp" * "secret" *\n' >"$work/secrets"
chmod 600 "$work/secrets"
cat >"$work/pppd-options" <<EOF
require-chap
ms-dns 192.0.2.53
lcp-echo-interval 2
lcp-echo-failure 3
logfile $work/pppd.log
EOF
ip netns exec "$ac" sh -c "mount --bind '$work/secrets' /etc/ppp/chap-secrets &&
  exec pppoe-server -F -I a0 -C isp-ac -S inet -L 198.51.100.1 -R 198.51.100.2 -N 4 -O '$work/pppd-options'" \
  >>"$work/ac.log" 2>&1 &
pids+=("$!")

systemctl start ruster.target ruster-pppoed.service || fail "the ruster units did not start"
for unit in "${units[@]}"; do systemctl -q is-active "$unit" || fail "$unit is not active"; done

# pppoed's lines go to the journal. How many sessions came up since $1:
sessions_up() {
  journalctl -q --no-pager -o cat -u ruster-pppoed --since "@$1" |
    grep -cE '^up pppoe-wan session=[0-9]+ ac=02:00:00:00:00:ac mtu=1492 ipv4=198\.51\.100\.[0-9]+ ' || true
}
wait_up() {
  for _ in $(seq 1 200); do (( $(sessions_up "$1") > 0 )) && return 0; sleep 0.1; done
  return 1
}
reach() {
  for _ in $(seq 1 30); do
    nsx "$lan" ping -c 1 -W 1 203.0.113.10 >/dev/null 2>&1 && return 0
  done
  return 1
}
wait_up "$started" || fail "no session"
reach || fail "the LAN does not reach the host behind the AC through NAT and the session"
show=$(nsx "$router" "$bin/ruster" show)
grep -q "interface ppp up mac 02:00:00:00:00:02 mtu 1492 vrf default pppoe session [0-9]* on r-wan to 02:00:00:00:00:ac" <<<"$show" ||
  fail "the FE has no session interface: $show"
grep -q "route default 0.0.0.0/0 dev ppp" <<<"$show" || fail "no default route out of the session: $show"
echo "ok: ruster-pppoed.service brings the session up, and the LAN reaches the host behind the AC"

# Killed, pppoed is started again by systemd and sets up a new session. The AC
# keeps the old one until its echoes go unanswered, so the new one may get
# another address.
sleep 1
again=$(date +%s)
systemctl kill -s KILL ruster-pppoed.service
wait_up "$again" || fail "no new session after pppoed was killed"
reach || fail "no forwarding through the new session"
echo "ok: pppoed killed with SIGKILL comes back with a new session, and forwarding with it"

#!/usr/bin/env bash
# Kea as the LAN's DHCP server, set up by ruster-kea from confd's dhcp part, with
# ruster-kea relaying between the FE and Kea. The LAN host gets an address from the
# pool with udhcpc, reaches the WAN host through NAT, and renews its lease.
# No internet is needed.
#
#   lan (udhcpc) -- [r-lan 192.0.2.1 | router: Kea on lo | r-wan 198.51.100.1] -- wan (198.51.100.10)
#
# Needs kea-dhcp4-server and udhcpc (apt-get install kea-dhcp4-server udhcpc); the
# distribution's Kea service must not be running (systemctl disable --now
# kea-dhcp4-server). Run as root, after `cargo build`:
#   sudo scripts/netns-dhcp.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsk$$
lan=$tag-lan wan=$tag-wan router=$tag-r
work=$(mktemp -d)
# Kea's files: Ubuntu's AppArmor profile lets Kea read only below /etc/kea, and
# write its pid file and control socket only in /run/kea, which belongs to _kea.
kdir=/etc/kea/$tag
control=/run/kea/kea4-ctrl-socket
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  pkill -f "kea-dhcp4 -c $kdir/" 2>/dev/null || true
  wait 2>/dev/null || true
  for ns in "$lan" "$wan" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -rf "$kdir"
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do
    [[ -e "$log" ]] && { echo "== $log"; cat "$log"; }
  done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
command -v kea-dhcp4 >/dev/null || fail "kea-dhcp4 is not installed"
command -v udhcpc >/dev/null || fail "udhcpc is not installed"
id _kea >/dev/null 2>&1 || fail "there is no _kea user (kea-dhcp4-server makes it)"
if pgrep -x kea-dhcp4 >/dev/null; then fail "another kea-dhcp4 runs; stop it first"; fi

for ns in "$lan" "$wan" "$router"; do ip netns add "$ns"; done
veth() { # host-ns router-dev router-mac
  ip link add h0 netns "$1" type veth peer name "$2" netns "$router"
  nsx "$router" sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
  nsx "$router" ethtool -K "$2" gro off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$2" address "$3" up
  nsx "$1" ethtool -K h0 tx off >/dev/null
  nsx "$1" ip link set h0 up
  nsx "$1" ip link set lo up
}
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
veth "$lan" r-lan 02:00:00:00:00:01
veth "$wan" r-wan 02:00:00:00:00:02
nsx "$lan" sysctl -qw net.ipv6.conf.h0.disable_ipv6=1
nsx "$wan" ip addr add 198.51.100.10/24 dev h0
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"

[nat]
inside = "r-lan"
outside = "r-wan"
ports = "20000-20999"
TOML
cp "$work/router.toml" "$work/with-dhcp.toml"
printf '\n[[dhcp]]\ninterface = "r-lan"\npool = "192.0.2.100-192.0.2.120"\nlease-time = 600\ndns = ["192.0.2.53"]\n' >>"$work/with-dhcp.toml"
sed 's/192.0.2.100-192.0.2.120/192.0.2.200-192.0.2.220/' "$work/with-dhcp.toml" >"$work/other-pool.toml"

# The operator's kea-dhcp4.conf: everything but what ruster-kea writes, which it
# includes in the Dhcp4 map.
mkdir -p "$kdir"
cat >"$kdir/kea-dhcp4.conf" <<CONF
{ "Dhcp4": {
<?include "$kdir/ruster-dhcp4.json"?>,
"lease-database": { "type": "memfile", "persist": false },
"control-socket": { "socket-type": "unix", "socket-name": "kea4-ctrl-socket" },
"loggers": [ { "name": "kea-dhcp4", "output-options": [ { "output": "stdout" } ], "severity": "INFO" } ]
} }
CONF

# udhcpc's script: puts the lease on h0 and writes what it got.
cat >"$work/udhcpc.sh" <<SH
#!/bin/sh
case "\$1" in
  deconfig) ip addr flush dev "\$interface" ;;
  bound|renew)
    ip addr replace "\$ip/\$mask" dev "\$interface"
    ip route replace default via "\$router" dev "\$interface"
    echo "\$1 ip=\$ip router=\$router dns=\$dns lease=\$lease" >>"$work/lease" ;;
esac
SH
chmod 0755 "$work/udhcpc.sh"

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
start ruster-confd --kernel "$work/with-dhcp.toml"
# Kea is not running yet: ruster-kea writes the file and takes the part.
start ruster-kea --control "$control" "$kdir/ruster-dhcp4.json"
for _ in $(seq 1 100); do grep -q "took a part" "$work/ruster-kea.log" 2>/dev/null && break; sleep 0.1; done
grep -q "192.0.2.100 - 192.0.2.120" "$kdir/ruster-dhcp4.json" 2>/dev/null ||
  fail "ruster-kea did not write the subnets"
# Kea runs as _kea, as its systemd unit does: AppArmor gives root's Kea no
# CAP_DAC_OVERRIDE, and /etc/kea and /run/kea belong to _kea.
kea_as() {
  nsx "$router" env KEA_LOCKFILE_DIR=none setpriv --reuid=_kea --regid=_kea --init-groups \
    --inh-caps=+net_bind_service --ambient-caps=+net_bind_service kea-dhcp4 "$@"
}
kea_as -t "$kdir/kea-dhcp4.conf" >"$work/kea-check.log" 2>&1 ||
  fail "Kea does not take the file"
(kea_as -c "$kdir/kea-dhcp4.conf" 2>&1 | cat >>"$work/kea.log") &
pids+=("$!")
for _ in $(seq 1 100); do [[ -S "$control" ]] && grep -q DHCP4_STARTED "$work/kea.log" && break; sleep 0.1; done
grep -q DHCP4_STARTED "$work/kea.log" || fail "Kea did not start"
for _ in $(seq 1 100); do grep -q "relaying for r-lan" "$work/ruster-kea.log" && break; sleep 0.1; done
grep -q "relaying for r-lan" "$work/ruster-kea.log" || fail "ruster-kea did not bind 192.0.2.1:67"

# udhcpc gets a lease, through the FE, ruster-kea and Kea.
nsx "$lan" udhcpc -i h0 -s "$work/udhcpc.sh" -f -t 10 -T 1 -A 1 -p "$work/udhcpc.pid" >>"$work/udhcpc.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 150); do [[ -s "$work/lease" ]] && break; sleep 0.1; done
[[ -s "$work/lease" ]] || fail "udhcpc got no lease"
lease=$(head -1 "$work/lease")
grep -Eq "^bound ip=192\.0\.2\.1(0[0-9]|1[0-9]|20) router=192\.0\.2\.1 dns=192\.0\.2\.53 lease=600$" <<<"$lease" ||
  fail "the lease: $lease"
echo "ok: the LAN host got a lease from the pool: $lease"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.10 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN host does not reach the WAN host"
echo "ok: with that lease the LAN host reaches the WAN through NAT"

# Renewing goes to the router's address (the server identifier), not broadcast.
kill -USR1 "$(cat "$work/udhcpc.pid")"
for _ in $(seq 1 50); do grep -q "^renew" "$work/lease" && break; sleep 0.1; done
grep -q "^renew" "$work/lease" || fail "the renewal was not answered: $(cat "$work/lease")"
grep -q "DHCPREQUEST.*from 192.0.2.1 to 127.0.0.1" "$work/kea.log" || fail "Kea did not see a relayed request"
echo "ok: the lease is renewed through the relay"

ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
out=$(ruster apply "$work/other-pool.toml") || fail "ruster apply: $out"
grep -q "applied" <<<"$out" || fail "ruster apply said: $out"
grep -q "192.0.2.200 - 192.0.2.220" "$kdir/ruster-dhcp4.json" || fail "the new pool is not written"
kea_as -t "$kdir/kea-dhcp4.conf" >/dev/null 2>&1 || fail "Kea does not take the new file"
echo "ok: ruster apply changes Kea's pool"

out=$(ruster apply "$work/router.toml") || fail "ruster apply without dhcp: $out"
grep -q "applied" <<<"$out" || fail "ruster apply said: $out"
grep -q '"subnet4": \[\]' "$kdir/ruster-dhcp4.json" || fail "subnets after removing dhcp: $(cat "$kdir/ruster-dhcp4.json")"
echo "ok: removing dhcp removes Kea's subnets"

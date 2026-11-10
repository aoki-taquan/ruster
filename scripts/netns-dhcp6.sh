#!/usr/bin/env bash
# Kea's DHCPv6 as the LAN's server, set up by ruster-kea from confd's dhcp part,
# with ruster-kea relaying between the FE and Kea (RFC 8415 Relay-forward and
# Relay-reply). neighd's Router Advertisements set M and O, so the LAN host runs a
# DHCPv6 client (busybox udhcpc6), gets an address from the pool and the DNS
# server, reaches the WAN host from it, and renews it. No internet is needed.
#
#   lan (udhcpc6) -- [r-lan 2001:db8:1::1 | router: Kea on lo/::1 | r-wan 2001:db8:2::1] -- wan (2001:db8:2::10)
#
# Needs kea-dhcp6-server and busybox (apt-get install kea-dhcp6-server busybox);
# the distribution's Kea DHCPv6 service must not be running (systemctl disable
# --now kea-dhcp6-server). Run as root, after `cargo build`:
#   sudo scripts/netns-dhcp6.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsk6$$
lan=$tag-lan wan=$tag-wan router=$tag-r
work=$(mktemp -d)
# Kea's files: Ubuntu's AppArmor profile lets Kea read only below /etc/kea, and
# make its control socket only in /run/kea, which belongs to _kea.
kdir=/etc/kea/$tag
control=/run/kea/kea6-ctrl-socket
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  pkill -f "kea-dhcp6 -c $kdir/" 2>/dev/null || true
  wait 2>/dev/null || true
  for ns in "$lan" "$wan" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -rf "$kdir"
  [[ -n "${ours:-}" ]] && rm -f "$control" "$control.lock"
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
command -v kea-dhcp6 >/dev/null || fail "kea-dhcp6 is not installed"
command -v busybox >/dev/null || fail "busybox is not installed"
id _kea >/dev/null 2>&1 || fail "there is no _kea user (kea-dhcp6-server makes it)"
if pgrep -x kea-dhcp6 >/dev/null; then fail "another kea-dhcp6 runs; stop it first"; fi

for ns in "$lan" "$wan" "$router"; do ip netns add "$ns"; done
veth() { # host-ns router-dev router-mac
  ip link add h0 netns "$1" type veth peer name "$2" netns "$router"
  nsx "$router" sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
  nsx "$router" ethtool -K "$2" gro off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$2" address "$3" up
  nsx "$1" ethtool -K h0 tx off >/dev/null
  nsx "$1" ip link set lo up
}
veth "$lan" r-lan 02:00:00:00:00:01
veth "$wan" r-wan 02:00:00:00:00:02
# The LAN host takes Router Advertisements (for its default route), but makes no
# address from them: its address comes from DHCPv6.
nsx "$lan" sysctl -qw net.ipv6.conf.all.forwarding=0
nsx "$lan" sysctl -qw net.ipv6.conf.h0.accept_ra=1
nsx "$lan" sysctl -qw net.ipv6.conf.h0.autoconf=0
nsx "$lan" ip link set h0 up
nsx "$wan" sysctl -qw net.ipv6.conf.h0.accept_ra=0
nsx "$wan" ip link set h0 up
nsx "$wan" ip addr add 2001:db8:2::10/64 dev h0 nodad
nsx "$wan" ip route add 2001:db8:1::/64 via 2001:db8:2::1
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
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv6 = ["2001:db8:2::1/64"]

[[ra]]
interface = "r-lan"
managed = true
other = true
TOML
cp "$work/router.toml" "$work/with-dhcp6.toml"
printf '\n[[dhcp6]]\ninterface = "r-lan"\npool = "2001:db8:1::1000-2001:db8:1::1fff"\npreferred-lifetime = 300\nvalid-lifetime = 600\ndns = ["2001:db8:1::53"]\n' >>"$work/with-dhcp6.toml"
sed 's/2001:db8:1::1000-2001:db8:1::1fff/2001:db8:1::2000-2001:db8:1::2fff/' "$work/with-dhcp6.toml" >"$work/other-pool.toml"

# The operator's kea-dhcp6.conf: everything but what ruster-kea writes, which it
# includes in the Dhcp6 map.
mkdir -p "$kdir"
cat >"$kdir/kea-dhcp6.conf" <<CONF
{ "Dhcp6": {
<?include "$kdir/ruster-dhcp6.json"?>,
"server-id": { "type": "LL", "htype": 1, "identifier": "020000000001", "persist": false },
"lease-database": { "type": "memfile", "persist": false },
"control-socket": { "socket-type": "unix", "socket-name": "kea6-ctrl-socket" },
"loggers": [ { "name": "kea-dhcp6", "output-options": [ { "output": "stdout" } ], "severity": "INFO" } ]
} }
CONF
# ruster-kea's DHCPv4 file: no [[dhcp]] here, so it holds no subnets.
dhcp4=$work/ruster-dhcp4.json

# udhcpc6's script: puts the leased address on h0 and writes what it got.
cat >"$work/udhcpc6.sh" <<SH
#!/bin/sh
case "\$1" in
  bound|renew)
    ip -6 addr replace "\$ipv6/128" dev "\$interface" nodad
    echo "\$1 ipv6=\$ipv6 dns=\$dns" >>"$work/lease" ;;
esac
SH
chmod 0755 "$work/udhcpc6.sh"

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
start ruster-confd --kernel "$work/with-dhcp6.toml"
# Kea is not running yet: ruster-kea writes the files and takes the part.
start ruster-kea --control "" --dhcp6 "$kdir/ruster-dhcp6.json" --control6 "$control" "$dhcp4"
for _ in $(seq 1 100); do grep -q "took a part" "$work/ruster-kea.log" 2>/dev/null && break; sleep 0.1; done
grep -q "2001:db8:1::1000 - 2001:db8:1::1fff" "$kdir/ruster-dhcp6.json" 2>/dev/null ||
  fail "ruster-kea did not write the subnets"
# Kea runs as _kea, as its systemd unit does (AppArmor; see netns-dhcp.sh).
kea_as() {
  nsx "$router" env KEA_LOCKFILE_DIR=none setpriv --reuid=_kea --regid=_kea --init-groups \
    --inh-caps=+net_bind_service --ambient-caps=+net_bind_service kea-dhcp6 "$@"
}
kea_as -t "$kdir/kea-dhcp6.conf" >"$work/kea-check.log" 2>&1 ||
  fail "Kea does not take the file"
ours=1
(kea_as -c "$kdir/kea-dhcp6.conf" 2>&1 | cat >>"$work/kea.log") &
pids+=("$!")
for _ in $(seq 1 100); do [[ -S "$control" ]] && grep -q DHCP6_STARTED "$work/kea.log" && break; sleep 0.1; done
grep -q DHCP6_STARTED "$work/kea.log" || fail "Kea did not start"
for _ in $(seq 1 100); do grep -q "relaying for r-lan from \[2001:db8:1::1\]:547" "$work/ruster-kea.log" && break; sleep 0.1; done
grep -q "relaying for r-lan from \[2001:db8:1::1\]:547" "$work/ruster-kea.log" ||
  fail "ruster-kea did not bind [2001:db8:1::1]:547"

# The host learns of the router (M and O set) and its default route.
for _ in $(seq 1 100); do
  nsx "$lan" ip -6 route show default | grep -q "via fe80::ff:fe00:1" && break
  sleep 0.1
done
nsx "$lan" ip -6 route show default | grep -q "via fe80::ff:fe00:1" ||
  fail "no default route from the Router Advertisement"
# udhcpc6 gets an address, through the FE, ruster-kea and Kea.
nsx "$lan" busybox udhcpc6 -i h0 -s "$work/udhcpc6.sh" -f -t 10 -T 1 -A 1 -p "$work/udhcpc6.pid" >>"$work/udhcpc6.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 150); do [[ -s "$work/lease" ]] && break; sleep 0.1; done
[[ -s "$work/lease" ]] || fail "udhcpc6 got no lease"
lease=$(head -1 "$work/lease")
# udhcpc6 writes addresses in full.
grep -Eq "^bound ipv6=2001:0db8:0001:0000:0000:0000:0000:1[0-9a-f]{3} dns=2001:0db8:0001:0000:0000:0000:0000:0053" <<<"$lease" ||
  fail "the lease: $lease"
address=$(sed -E 's/^bound ipv6=([^ ]+).*/\1/' <<<"$lease")
echo "ok: the LAN host got $address from the pool and the DNS server: $lease"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -6 -c 1 -W 1 -I "$address" 2001:db8:2::10 >/dev/null 2>&1; then ok=1; break; fi
  sleep 0.5
done
(( ok == 1 )) || fail "the LAN host does not reach the WAN host from $address"
echo "ok: from that address the LAN host reaches the WAN host"

kill -USR1 "$(cat "$work/udhcpc6.pid")"
for _ in $(seq 1 50); do grep -q "^renew" "$work/lease" && break; sleep 0.1; done
grep -q "^renew ipv6=$address" "$work/lease" || fail "the renewal was not answered: $(cat "$work/lease")"
echo "ok: the lease is renewed through the relay"

ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
out=$(ruster apply "$work/other-pool.toml") || fail "ruster apply: $out"
grep -q "applied" <<<"$out" || fail "ruster apply said: $out"
grep -q "2001:db8:1::2000 - 2001:db8:1::2fff" "$kdir/ruster-dhcp6.json" || fail "the new pool is not written"
kea_as -t "$kdir/kea-dhcp6.conf" >/dev/null 2>&1 || fail "Kea does not take the new file"
echo "ok: ruster apply writes the new pool, and Kea reads it"

out=$(ruster apply "$work/router.toml") || fail "ruster apply without dhcp6: $out"
grep -q "applied" <<<"$out" || fail "ruster apply said: $out"
grep -q '"subnet6": \[\]' "$kdir/ruster-dhcp6.json" || fail "subnets after removing dhcp6: $(cat "$kdir/ruster-dhcp6.json")"
echo "ok: removing dhcp6 removes Kea's subnets"

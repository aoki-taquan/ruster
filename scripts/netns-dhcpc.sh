#!/usr/bin/env bash
# ruster-dhcpc as the WAN side's DHCP client: Kea in the ISP's netns leases the
# router's WAN an IPv4 address (DHCPv4) and delegates it an IPv6 prefix (DHCPv6-PD).
# The address goes on r-wan through confd, the default route through ribd, and the
# LAN host reaches the ISP side through NAT. Both leases are short, so they are
# renewed while the test runs. No internet is needed.
#
#   lan (192.168.0.10) -- [r-lan 192.168.0.1 | router | r-wan: DHCP] -- isp (198.51.100.1, Kea)
#
# Needs kea-dhcp4-server and kea-dhcp6-server; the distribution's Kea services must
# not be running. Run as root, after `cargo build`:
#   sudo scripts/netns-dhcpc.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rdc$$
lan=$tag-lan isp=$tag-isp router=$tag-r
work=$(mktemp -d)
# Ubuntu's AppArmor profiles let Kea read only below /etc/kea and write only in
# /run/kea, which belongs to _kea.
kdir=/etc/kea/$tag
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  pkill -f "kea-dhcp[46] -c $kdir/" 2>/dev/null || true
  wait 2>/dev/null || true
  for ns in "$lan" "$isp" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -rf "$kdir"
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  [[ -n "${hold:-}" ]] && sleep "$hold"
  echo "FAIL: $*" >&2
  for log in "$work"/*.log "$work"/*.out; do
    [[ -e "$log" ]] && { echo "== $log"; cat "$log"; }
  done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
command -v kea-dhcp4 >/dev/null || fail "kea-dhcp4 is not installed"
command -v kea-dhcp6 >/dev/null || fail "kea-dhcp6 is not installed"
id _kea >/dev/null 2>&1 || fail "there is no _kea user"

for ns in "$lan" "$isp" "$router"; do ip netns add "$ns"; done
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
veth "$isp" r-wan 02:00:00:00:00:02
nsx "$lan" sysctl -qw net.ipv6.conf.h0.disable_ipv6=1
nsx "$lan" ip addr add 192.168.0.10/24 dev h0
nsx "$lan" ip route add default via 192.168.0.1
nsx "$isp" ip addr add 198.51.100.1/24 dev h0
nsx "$isp" ip -6 addr add 2001:db8:ff::1/64 dev h0 nodad
nsx "$router" ip link set lo up
# Kea's DHCPv6 sockets need the link-local address out of DAD.
for _ in $(seq 1 50); do
  nsx "$isp" ip -6 addr show dev h0 tentative | grep -q inet6 || break
  sleep 0.1
done

cat >"$work/router.toml" <<'TOML'
[[source]]
name = "dhcp-wan"
kind = "dhcp-client"

[[source]]
name = "dhcp6-wan"
kind = "dhcpv6-client"

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
ipv6-source = "dhcp6-wan"

[nat]
inside = "r-lan"
outside = "r-wan"
ports = "20000-20999"

[[firewall]]
action = "accept"
protocol = "icmp"
ingress = "r-lan"
TOML

# Kea as the ISP's servers: short leases, so that they are renewed during the test.
mkdir -p "$kdir"
cat >"$kdir/kea-dhcp4.conf" <<CONF
{ "Dhcp4": {
  "interfaces-config": { "interfaces": [ "h0" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "valid-lifetime": 30, "renew-timer": 10, "rebind-timer": 20,
  "subnet4": [ { "id": 1, "subnet": "198.51.100.0/24", "interface": "h0",
    "pools": [ { "pool": "198.51.100.100 - 198.51.100.110" } ],
    "option-data": [ { "name": "routers", "data": "198.51.100.1" },
                     { "name": "domain-name-servers", "data": "198.51.100.53" } ] } ],
  "loggers": [ { "name": "kea-dhcp4", "output-options": [ { "output": "stdout" } ], "severity": "INFO" } ]
} }
CONF
cat >"$kdir/kea-dhcp6.conf" <<CONF
{ "Dhcp6": {
  "interfaces-config": { "interfaces": [ "h0" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "preferred-lifetime": 30, "valid-lifetime": 60, "renew-timer": 10, "rebind-timer": 20,
  "subnet6": [ { "id": 1, "subnet": "2001:db8:ff::/64", "interface": "h0",
    "pd-pools": [ { "prefix": "2001:db8:100::", "prefix-len": 40, "delegated-len": 56 } ],
    "option-data": [ { "name": "dns-servers", "data": "2001:db8::53" } ] } ],
  "loggers": [ { "name": "kea-dhcp6", "output-options": [ { "output": "stdout" } ], "severity": "INFO" } ]
} }
CONF
chown -R _kea "$kdir" 2>/dev/null || true
kea_as() { # program args...
  local program=$1; shift
  nsx "$isp" env KEA_LOCKFILE_DIR=none setpriv --reuid=_kea --regid=_kea --init-groups \
    --inh-caps=+net_bind_service,+net_raw --ambient-caps=+net_bind_service,+net_raw "$program" "$@"
}
for v in 4 6; do
  kea_as kea-dhcp$v -t "$kdir/kea-dhcp$v.conf" >"$work/kea$v-check.log" 2>&1 || fail "Kea $v does not take its file"
  (kea_as kea-dhcp$v -c "$kdir/kea-dhcp$v.conf" 2>&1 | cat >>"$work/kea$v.log") &
  pids+=("$!")
done
for v in 4 6; do
  for _ in $(seq 1 100); do grep -q "DHCP${v}_STARTED" "$work/kea$v.log" && break; sleep 0.1; done
  grep -q "DHCP${v}_STARTED" "$work/kea$v.log" || fail "Kea $v did not start"
done

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" r-lan r-wan
start ruster-ribd confd:1 dhcpc:5
start ruster-neighd
start ruster-confd --kernel "$work/router.toml"
ip netns exec "$router" "$bin/ruster-dhcpc" --run-dir "$run_dir" \
  >>"$work/dhcpc.out" 2>"$work/dhcpc.log" &
pids+=("$!")

wait_line() { # pattern count
  for _ in $(seq 1 400); do
    (( $(grep -cE "$1" "$work/dhcpc.out" 2>/dev/null || true) >= ${2:-1} )) && return 0
    sleep 0.1
  done
  return 1
}
wait_line '^bound4 r-wan address=198\.51\.100\.1(0[0-9]|10)/24 router=198\.51\.100\.1 dns=198\.51\.100\.53 lease=30$' ||
  fail "no DHCPv4 lease"
echo "ok: DHCPv4: $(grep '^bound4' "$work/dhcpc.out" | head -1)"
wait_line '^bound6 r-wan prefix=2001:db8:1[0-9a-f]{2}(:[0-9a-f]{1,2}00)?::/56 address=- dns=2001:db8::53 via=fe80::' ||
  fail "no delegated prefix"
echo "ok: DHCPv6-PD: $(grep '^bound6' "$work/dhcpc.out" | head -1)"

show() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" show; }
address=$(grep '^bound4' "$work/dhcpc.out" | head -1 | sed -E 's/.*address=([0-9.]+)\/.*/\1/')
for _ in $(seq 1 50); do show | grep -q "address r-wan $address/24" && break; sleep 0.1; done
out=$(show)
grep -q "address r-wan $address/24" <<<"$out" || fail "r-wan has not the leased address: $out"
grep -q "route default 0.0.0.0/0 via 198.51.100.1 dev r-wan" <<<"$out" || fail "no IPv4 default route: $out"
grep -q "route default ::/0 via fe80::.* dev r-wan" <<<"$out" || fail "no IPv6 default route: $out"
echo "ok: the FE has the leased address and both default routes"

reach() {
  for _ in $(seq 1 30); do
    nsx "$lan" ping -c 1 -W 1 198.51.100.1 >/dev/null 2>&1 && return 0
  done
  return 1
}
reach || fail "the LAN does not reach the ISP through NAT"
echo "ok: the LAN host reaches the ISP side through NAT"

# The leases are renewed (DHCPv4 at 10 s to the server, DHCPv6 at 10 s).
wait_line '^bound4 ' 2 || fail "the DHCPv4 lease was not renewed"
wait_line '^bound6 ' 2 || fail "the DHCPv6 lease was not renewed"
grep -q "^lost" "$work/dhcpc.out" && fail "a lease was lost: $(cat "$work/dhcpc.out")"
echo "ok: both leases are renewed"

# Removing the client ends both leases: their values and routes go. The client
# sends DHCPRELEASE and Release too, but the FE may have dropped its punt classes
# by then, so Kea is not asked whether they came.
sed '/^\[\[dhcp-client\]\]/,/^$/d' "$work/router.toml" >"$work/without.toml"
out=$(nsx "$router" "$bin/ruster" --run-dir "$run_dir" apply "$work/without.toml" 2>&1) ||
  fail "ruster apply: $out"
wait_line '^lost4 r-wan' 1 || fail "the DHCPv4 lease did not end"
wait_line '^lost6 r-wan' 1 || fail "the DHCPv6 lease did not end"
for _ in $(seq 1 50); do show | grep -q "address r-wan $address/24\|route default 0.0.0.0/0\|route default ::/0" || break; sleep 0.1; done
out=$(show)
grep -q "address r-wan $address/24" <<<"$out" && fail "r-wan keeps the address: $out"
grep -q "route default 0.0.0.0/0\|route default ::/0" <<<"$out" && fail "a default route is left: $out"
echo "ok: removing the client ends both leases, and their address and routes go"

#!/usr/bin/env bash
# Router Advertisements from neighd, set by confd's [[ra]]. The LAN host's kernel
# takes them: it makes a SLAAC address from the advertised prefix, and a default
# route through the router's link-local address, which it reaches the WAN host by.
# When [[ra]] is removed, neighd's final advertisements (router lifetime 0) take
# the default route away again.
#
#   lan (SLAAC) -- [r-lan 2001:db8:1::1 | router | r-wan 2001:db8:2::1] -- wan (2001:db8:2::10)
#
# Run as root, after `cargo build`:  sudo scripts/netns-ra.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsr$$
lan=$tag-lan wan=$tag-wan router=$tag-r
work=$(mktemp -d)
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$wan" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
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
# The LAN host is a host: it takes Router Advertisements and makes addresses.
nsx "$lan" sysctl -qw net.ipv6.conf.all.forwarding=0
nsx "$lan" sysctl -qw net.ipv6.conf.h0.accept_ra=1
nsx "$lan" sysctl -qw net.ipv6.conf.h0.autoconf=1
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
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv6 = ["2001:db8:2::1/64"]
TOML
cp "$work/router.toml" "$work/with-ra.toml"
printf '\n[[ra]]\ninterface = "r-lan"\n' >>"$work/with-ra.toml"

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
start ruster-confd "$work/with-ra.toml"
for _ in $(seq 1 100); do grep -q "took the ra part" "$work/ruster-neighd.log" 2>/dev/null && break; sleep 0.1; done
grep -q "took the ra part" "$work/ruster-neighd.log" || fail "neighd did not take the ra part"

# The host's kernel makes 2001:db8:1::/64 + its interface identifier, and a
# default route to the router's link-local address (from 02:00:00:00:00:01).
router_ll=fe80::ff:fe00:1
ok=0
for _ in $(seq 1 100); do
  # Past duplicate address detection: not tentative any more.
  if nsx "$lan" ip -6 addr show dev h0 scope global -tentative | grep -q "inet6 2001:db8:1:0:.*/64 .*dynamic" &&
    nsx "$lan" ip -6 route show default | grep -q "via $router_ll dev h0"; then
    ok=1
    break
  fi
  sleep 0.1
done
(( ok == 1 )) || fail "no SLAAC address or default route: $(nsx "$lan" ip -6 addr show dev h0) $(nsx "$lan" ip -6 route)"
echo "ok: the LAN host has a SLAAC address and a default route through $router_ll"
echo "    $(nsx "$lan" ip -6 addr show dev h0 scope global | grep inet6)"
echo "    $(nsx "$lan" ip -6 route show default)"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -6 -c 1 -W 1 2001:db8:2::10 >/dev/null 2>&1; then ok=1; break; fi
  sleep 0.5
done
(( ok == 1 )) || fail "the LAN host does not reach the WAN host"
echo "ok: by that route the LAN host reaches the WAN host"

# A Router Solicitation is answered: the host asks again by bringing h0 down and up.
nsx "$lan" ip link set h0 down
nsx "$lan" ip link set h0 up
for _ in $(seq 1 100); do
  nsx "$lan" ip -6 route show default | grep -q "via $router_ll" && break
  sleep 0.1
done
nsx "$lan" ip -6 route show default | grep -q "via $router_ll" ||
  fail "no default route after the host solicited"
# neighd writes its counts every 5 s.
for _ in $(seq 1 70); do
  grep -Eq "router_solicitations: [1-9]" "$work/ruster-neighd.log" && break
  sleep 0.1
done
grep -Eq "router_solicitations: [1-9]" "$work/ruster-neighd.log" || fail "neighd took no Router Solicitation"
echo "ok: neighd answers the host's Router Solicitations, and the host has the default route back"

ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
out=$(ruster apply "$work/router.toml") || fail "ruster apply without ra: $out"
grep -q "applied" <<<"$out" || fail "ruster apply said: $out"
for _ in $(seq 1 100); do
  [[ -z "$(nsx "$lan" ip -6 route show default)" ]] && break
  sleep 0.1
done
[[ -z "$(nsx "$lan" ip -6 route show default)" ]] ||
  fail "the default route stays after the final advertisement: $(nsx "$lan" ip -6 route show default)"
echo "ok: removing [[ra]] takes the default route away (router lifetime 0)"

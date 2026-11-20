#!/usr/bin/env bash
# EVPN over SRv6 (End.DT2U and End.DT2M) between two ruster routers: each bridges
# its port p1 with an SRv6 EVPN interface se0 (VNI 100). What a routing daemon
# would give (the far End.DT2M SID to flood to, b's MAC behind the far End.DT2U
# SID, a remote host's address) is written with `ruster evpn` as the ribd source
# "evpn".
#
#   a (192.0.2.10) -- p1 [r1 br0: p1, se0] wan 2001:db8::1 ===== 2001:db8::2 wan [r2 br0: p1, se0] p1 -- b (192.0.2.20)
#                        SIDs fc00:1::/48                           SIDs fc00:2::/48
#
# a and b reach each other at L2 only once each floods to the other's End.DT2M
# SID; frames to b then go to r2's End.DT2U SID; r1 answers ARP for a remote host.
# Run as root after `cargo build`:
#   sudo scripts/netns-srv6-evpn.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rse$$
a=$tag-a b=$tag-b r1=$tag-r1 r2=$tag-r2
work=$(mktemp -d)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$a" "$b" "$r1" "$r2"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
for ns in "$a" "$b" "$r1" "$r2"; do ip netns add "$ns"; done
for r in "$r1" "$r2"; do
  nsx "$r" sysctl -qw net.ipv4.ip_forward=0
  nsx "$r" ip link add vrf-ports type vrf table 999
  nsx "$r" ip link set vrf-ports up
done
port() { # router, its port, the port's MAC
  nsx "$1" sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
  nsx "$1" ethtool -K "$2" gro off rxvlan off txvlan off >/dev/null 2>&1 || true
  nsx "$1" ip link set "$2" master vrf-ports
  nsx "$1" ip link set "$2" address "$3" up
}
ip link add p1 netns "$r1" type veth peer name a0 netns "$a"
ip link add p1 netns "$r2" type veth peer name b0 netns "$b"
ip link add wan netns "$r1" type veth peer name wan netns "$r2"
port "$r1" p1 02:00:00:00:01:01
port "$r1" wan 02:00:00:00:01:02
port "$r2" p1 02:00:00:00:02:01
port "$r2" wan 02:00:00:00:02:02
for h in "$a:a0:192.0.2.10" "$b:b0:192.0.2.20"; do
  IFS=: read -r ns dev address <<<"$h"
  nsx "$ns" ethtool -K "$dev" tx off >/dev/null 2>&1 || true
  nsx "$ns" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$ns" ip addr add "$address/24" dev "$dev"
  nsx "$ns" ip link set "$dev" up
done

config() { # router dir, p1's MAC, wan's MAC, wan address, own SIDs, far SIDs, far wan
  mkdir -p "$work/$1/run"
  chmod 0700 "$work/$1/run"
  cat > "$work/$1/router.toml" <<TOML
[[interface]]
name = "p1"
mac = "$2"

[[interface]]
name = "wan"
mac = "$3"
ipv6 = ["$4/64"]

[[interface]]
name = "se0"
srv6-evpn = { vni = 100, unicast-sid = "$5::e", multicast-sid = "$5::f" }

[[interface]]
name = "br0"
bridge = { members = ["p1", "se0"] }

[[route]]
prefix = "$6::/48"
interface = "wan"
via = "$7"

[srv6]
locator = "$5::/48"
source = "$4"

[[srv6.sid]]
sid = "$5::1"
behavior = "End"
TOML
}

start() { # router dir, namespace
  local dir=$work/$1
  for name in ruster-fe ruster-ribd ruster-neighd; do
    local args=()
    [[ $name == ruster-fe ]] && args=(--backend "$backend" p1 wan)
    [[ $name == ruster-ribd ]] && args=(confd:1 evpn:20)
    ip netns exec "$2" "$bin/$name" --run-dir "$dir/run" "${args[@]}" >>"$dir/$name.log" 2>&1 &
    pids+=("$!")
  done
  ip netns exec "$2" "$bin/ruster-confd" --run-dir "$dir/run" "$dir/router.toml" >>"$dir/ruster-confd.log" 2>&1 &
  pids+=("$!")
}
evpn() { # router dir, namespace, words
  local dir=$work/$1 ns=$2
  shift 2
  nsx "$ns" "$bin/ruster" --run-dir "$dir/run" evpn "$@" --source evpn
}
pings() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
show() { nsx "$2" "$bin/ruster" --run-dir "$work/$1/run" show 2>/dev/null; }

config r1 02:00:00:00:01:01 02:00:00:00:01:02 2001:db8::1 fc00:1 fc00:2 2001:db8::2
config r2 02:00:00:00:02:01 02:00:00:00:02:02 2001:db8::2 fc00:2 fc00:1 2001:db8::1
start r1 "$r1"
start r2 "$r2"
for r in "r1:$r1" "r2:$r2"; do
  for _ in $(seq 1 50); do
    [[ -S "$work/${r%%:*}/run/ribd/source/evpn/source.sock" ]] && show "${r%%:*}" "${r#*:}" | grep -q '^srv6-evpn se0' && break
    sleep 0.2
  done
done
show r1 "$r1" | grep -q '^srv6-evpn se0 vni 100 dt2u fc00:1::e dt2m fc00:1::f from 2001:db8::1' ||
  fail "r1 has no SRv6 EVPN interface: $(show r1 "$r1")"

# No remote end given: nothing crosses.
if pings "$a" 192.0.2.20; then fail "a reached b with no remote end"; fi
echo "ok: with no remote end given, a does not reach b"

evpn r1 "$r1" add flood 100 fc00:2::f || fail "r1: evpn add flood"
evpn r2 "$r2" add flood 100 fc00:1::f || fail "r2: evpn add flood"
ok=0
for _ in $(seq 1 20); do
  if pings "$a" 192.0.2.20; then ok=1; break; fi
done
(( ok == 1 )) || fail "a does not reach b once each floods to the other's End.DT2M SID"
out=$(nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20) || fail "a to b: $out"
grep -q "ttl=64" <<<"$out" || fail "a to b was not bridged (TTL changed): $out"
nsx "$b" ping -c 2 -i 0.2 -W 1 192.0.2.10 >/dev/null || fail "b to a"
echo "ok: a and b reach each other at L2 over SRv6 EVPN (End.DT2M)"

# The MAC addresses behind the far End.DT2U SIDs: unicast goes there.
a_mac=$(nsx "$a" cat /sys/class/net/a0/address)
b_mac=$(nsx "$b" cat /sys/class/net/b0/address)
evpn r1 "$r1" add mac 100 "$b_mac" vtep fc00:2::e || fail "r1: evpn add mac"
evpn r2 "$r2" add mac 100 "$a_mac" vtep fc00:1::e || fail "r2: evpn add mac"
nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20 >/dev/null || fail "a to b with the MACs behind End.DT2U SIDs"
nsx "$b" ping -c 2 -i 0.2 -W 1 192.0.2.10 >/dev/null || fail "b to a with the MACs behind End.DT2U SIDs"
echo "ok: a and b reach each other with their MACs behind the End.DT2U SIDs"

# Without the floods, unicast to the known MACs still crosses (End.DT2U).
evpn r1 "$r1" del flood 100 fc00:2::f || fail "r1: evpn del flood"
evpn r2 "$r2" del flood 100 fc00:1::f || fail "r2: evpn del flood"
sleep 0.5
nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20 >/dev/null || fail "a to b over End.DT2U only"
echo "ok: with no flooding, a and b still reach each other over End.DT2U"

# r1 answers ARP for a remote host no one has.
evpn r1 "$r1" add neighbor 100 192.0.2.99 02:00:00:00:00:99 || fail "r1: evpn add neighbor"
got=""
for _ in $(seq 1 20); do
  nsx "$a" ping -c 1 -W 1 192.0.2.99 >/dev/null 2>&1 || true
  got=$(nsx "$a" ip neigh show 192.0.2.99 dev a0 | grep -o 'lladdr [0-9a-f:]*' || true)
  [[ "$got" == "lladdr 02:00:00:00:00:99" ]] && break
done
[[ "$got" == "lladdr 02:00:00:00:00:99" ]] || fail "a has no answer to its ARP request for 192.0.2.99: $got"
echo "ok: r1 answers ARP for a remote host"
echo "PASS ($backend)"

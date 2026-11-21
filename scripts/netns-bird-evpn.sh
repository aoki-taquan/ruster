#!/usr/bin/env bash
# EVPN through bird-rs: two ruster routers, each with bird-rs set up by ruster-bird
# from confd's bird part (routing-daemon = "bird-rs", a neighbor with evpn = true),
# bridge their port p1 with a VXLAN interface (VNI 100) that lists no VTEP. Over
# the IBGP EVPN session between them each learns the other's VTEP (type 3) and the
# MAC addresses the other's FE learned (type 2), which bird-rs gives ribd.
#
#   a (192.0.2.10) -- p1 [r1 br0: p1, vx0] wan 10.0.0.1 ===== 10.0.0.2 wan [r2 br0: p1, vx0] p1 -- b (192.0.2.20)
#
# a and b reach each other at L2; each ribd has the other's flood VTEP and host MAC;
# when r2's bird-rs stops, r1's entries go. Needs bird-rs and birdc-rs: BIRD_RS is
# the directory that holds them (exit 77, skipped, without). Run as root after
# `cargo build`:
#   sudo BIRD_RS=<dir> scripts/netns-bird-evpn.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
bird=${BIRD_RS:-}
if [[ -z "$bird" || ! -x "$bird/bird-rs" || ! -x "$bird/birdc-rs" ]]; then
  echo "SKIP: give BIRD_RS, the directory of bird-rs and birdc-rs" >&2
  exit 77
fi
bird=$(realpath "$bird")
tag=rbe$$
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

config() { # router dir, p1's MAC, wan's MAC, wan address, far wan
  mkdir -p "$work/$1/run"
  chmod 0700 "$work/$1/run"
  cat > "$work/$1/router.toml" <<TOML
routing-daemon = "bird-rs"

[[interface]]
name = "p1"
mac = "$2"

[[interface]]
name = "wan"
mac = "$3"
ipv4 = "$4/24"

[[interface]]
name = "vx0"
vxlan = { vni = 100, local = "$4" }

[[interface]]
name = "br0"
bridge = { members = ["p1", "vx0"] }

[bgp]
as = 65000
include = "$work/$1/include.conf"

[[bgp.neighbor]]
address = "$5"
remote-as = 65000
evpn = true
TOML
  # The operator's own bird-rs settings: a quicker reconnection for the test.
  echo "template bgp quick { connect retry time 1; }" >"$work/$1/include.conf"
  echo "protocol device {}" >"$work/$1/bird.conf"
}

start() { # router dir, namespace
  local dir=$work/$1
  for name in ruster-fe ruster-ribd ruster-neighd; do
    local args=()
    [[ $name == ruster-fe ]] && args=(--backend "$backend" p1 wan)
    [[ $name == ruster-ribd ]] && args=(confd:1 bird:20:65000)
    ip netns exec "$2" "$bin/$name" --run-dir "$dir/run" "${args[@]}" >>"$dir/$name.log" 2>&1 &
    pids+=("$!")
  done
  ip netns exec "$2" "$bin/ruster-confd" --run-dir "$dir/run" --kernel "$dir/router.toml" >>"$dir/ruster-confd.log" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 50); do nsx "$2" ip link show rt-default >/dev/null 2>&1 && break; sleep 0.1; done
  ip netns exec "$2" "$bird/bird-rs" -f -c "$dir/bird.conf" -s "$dir/bird.ctl" >>"$dir/bird-rs.log" 2>&1 &
  pids+=("$!")
  eval "bird_$1=$!"
  for _ in $(seq 1 50); do [[ -S "$dir/bird.ctl" ]] && break; sleep 0.1; done
  ip netns exec "$2" "$bin/ruster-bird" --run-dir "$dir/run" --birdc "$bird/birdc-rs -s $dir/bird.ctl" "$dir/bird.conf" >>"$dir/ruster-bird.log" 2>&1 &
  pids+=("$!")
}
show() { nsx "$2" "$bin/ruster" --run-dir "$work/$1/run" show 2>/dev/null || true; }
wait_show() { # router dir, namespace, pattern, present (1) or gone (0)
  for _ in $(seq 1 300); do
    if show "$1" "$2" | grep -q "$3"; then [[ $4 == 1 ]] && return 0; else [[ $4 == 0 ]] && return 0; fi
    sleep 0.1
  done
  return 1
}
pings() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }

config r1 02:00:00:00:01:01 02:00:00:00:01:02 10.0.0.1 10.0.0.2
config r2 02:00:00:00:02:01 02:00:00:00:02:02 10.0.0.2 10.0.0.1
start r1 "$r1"
start r2 "$r2"

wait_show r1 "$r1" "^evpn-flood vni 100 vtep 10.0.0.2" 1 ||
  fail "r1's ribd has no flood to r2: $(show r1 "$r1" | grep evpn); $(nsx "$r1" "$bird/birdc-rs" -s "$work/r1/bird.ctl" show protocols 2>&1)"
wait_show r2 "$r2" "^evpn-flood vni 100 vtep 10.0.0.1" 1 || fail "r2's ribd has no flood to r1"
grep -q "protocol evpn ruster_evpn_100" "$work/r1/bird.conf" || fail "ruster-bird's file: $(cat "$work/r1/bird.conf")"
echo "ok: each router's bird-rs learns the other's VTEP (type 3), and ribd has it"

ok=0
for _ in $(seq 1 20); do
  if pings "$a" 192.0.2.20; then ok=1; break; fi
done
(( ok == 1 )) || fail "a does not reach b over EVPN"
out=$(nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20) || fail "a to b: $out"
grep -q "ttl=64" <<<"$out" || fail "a to b was not bridged (TTL changed): $out"
echo "ok: a and b reach each other at L2 over VXLAN, with the VTEPs from EVPN"

a_mac=$(nsx "$a" cat /sys/class/net/a0/address)
b_mac=$(nsx "$b" cat /sys/class/net/b0/address)
wait_show r2 "$r2" "^evpn-mac vni 100 $a_mac vtep 10.0.0.1" 1 ||
  fail "r2's ribd has no MAC of a: $(show r2 "$r2" | grep evpn)"
wait_show r1 "$r1" "^evpn-mac vni 100 $b_mac vtep 10.0.0.2" 1 || fail "r1's ribd has no MAC of b"
echo "ok: the MAC addresses each FE learned reach the other's ribd (type 2)"

kill "$bird_r2"
wait_show r1 "$r1" "^evpn-flood vni 100 vtep 10.0.0.2" 0 ||
  fail "r1's ribd keeps the flood to r2: $(nsx "$r1" "$bird/birdc-rs" -s "$work/r1/bird.ctl" show protocols 2>&1); $(ps -p "$bird_r2" -o pid,stat,cmd 2>&1)"
wait_show r1 "$r1" "^evpn-mac vni 100 $b_mac" 0 || fail "r1's ribd keeps b's MAC"
echo "ok: when r2's bird-rs stops, r1's EVPN entries go"
echo "PASS ($backend)"

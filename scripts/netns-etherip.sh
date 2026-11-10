#!/usr/bin/env bash
# EtherIP between two ruster routers: each bridges its port p1 with an EtherIP
# interface to the other, over the routed link wan (IPv4 outer, then IPv6 outer).
#
#   a (192.0.2.10) -- p1 [r1 br0: p1, eip0] wan 10.0.0.1 ===== 10.0.0.2 wan [r2 br0: p1, eip0] p1 -- b (192.0.2.20)
#                                              2001:db8::1     2001:db8::2
#
# a and b reach each other at L2 (TTL unchanged), and a frame too long for the link
# once wrapped is dropped and counted. Linux has no EtherIP device, so the far end is
# a second ruster. Run as root after `cargo build`:
#   sudo scripts/netns-etherip.sh [target/debug]
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

config() { # router dir, its wan addresses, local, remote
  mkdir -p "$work/$1/run"
  chmod 0700 "$work/$1/run"
  cat > "$work/$1/router.toml" <<TOML
[[interface]]
name = "p1"
mac = "$2"

[[interface]]
name = "wan"
mac = "$3"
ipv4 = "$4/24"
ipv6 = ["$5/64"]

[[interface]]
name = "eip0"
etherip = { local = "$6", remote = "$7" }

[[interface]]
name = "br0"
bridge = { members = ["p1", "eip0"] }
TOML
}

declare -A fe_pid
start() { # router dir, namespace
  local dir=$work/$1
  for name in ruster-fe ruster-ribd ruster-neighd; do
    local args=()
    [[ $name == ruster-fe ]] && args=(--backend "$backend" p1 wan)
    ip netns exec "$2" "$bin/$name" --run-dir "$dir/run" "${args[@]}" >>"$dir/$name.log" 2>&1 &
    pids+=("$!")
  done
  ip netns exec "$2" "$bin/ruster-confd" --run-dir "$dir/run" "$dir/router.toml" >>"$dir/ruster-confd.log" 2>&1 &
  pids+=("$!")
}
stop() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  pids=()
}

pings() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
counter() { { grep -o "$2: [0-9]*" "$work/$1/ruster-fe.log" || true; } | tail -1 | awk '{print $2}'; }

for outer in 4 6; do
  if [[ $outer == 4 ]]; then l=10.0.0.1 r=10.0.0.2; else l=2001:db8::1 r=2001:db8::2; fi
  config r1 02:00:00:00:01:01 02:00:00:00:01:02 10.0.0.1 2001:db8::1 "$l" "$r"
  config r2 02:00:00:00:02:01 02:00:00:00:02:02 10.0.0.2 2001:db8::2 "$r" "$l"
  rm -f "$work"/r?/*.log
  start r1 "$r1"
  start r2 "$r2"
  ok=0
  for _ in $(seq 1 20); do
    if pings "$a" 192.0.2.20; then ok=1; break; fi
  done
  (( ok == 1 )) || fail "a does not reach b over EtherIP in IPv$outer"
  out=$(nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20) || fail "a to b in IPv$outer: $out"
  grep -q "ttl=64" <<<"$out" || fail "a to b was not bridged (TTL changed): $out"
  nsx "$b" ping -c 2 -i 0.2 -W 1 192.0.2.10 >/dev/null || fail "b to a in IPv$outer"
  echo "ok: a and b reach each other at L2 over EtherIP in IPv$outer"

  # The largest frame that fits: 1500 less the outer headers (36 or 56) is the
  # inner IP packet, 28 of which are IPv4 and ICMP.
  if [[ $outer == 4 ]]; then fits=$((1464 - 28)); else fits=$((1444 - 28)); fi
  nsx "$a" ping -c 2 -i 0.2 -W 1 -M do -s "$fits" 192.0.2.20 >/dev/null ||
    fail "a frame that fits once wrapped did not cross in IPv$outer"
  if nsx "$a" ping -c 2 -i 0.2 -W 1 -M do -s $((fits + 1)) 192.0.2.20 >/dev/null 2>&1; then
    fail "a frame too long once wrapped crossed in IPv$outer"
  fi
  # The FE reports its counters every 5 seconds when they change.
  seen=0
  for _ in $(seq 1 8); do
    n=$(counter r1 overlay_too_big)
    if [[ -n "$n" ]] && (( n >= 2 )); then seen=1; break; fi
    sleep 1
  done
  (( seen == 1 )) || fail "r1 did not count the frames too long in IPv$outer"
  echo "ok: frames too long once wrapped are dropped and counted (IPv$outer)"
  stop
done
echo "PASS ($backend)"

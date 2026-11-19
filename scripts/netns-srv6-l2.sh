#!/usr/bin/env bash
# SRv6 L2 (H.Encaps.L2 and End.DX2) between two ruster routers: each bridges its
# port p1 with an SRv6 L2 interface to the other, over the routed link wan.
#
#   a (192.0.2.10) -- p1 [r1 br0: p1, sr0] wan 2001:db8::1 ===== 2001:db8::2 wan [r2 br0: p1, sr0] p1 -- b (192.0.2.20)
#                        SIDs fc00:1::/48                           SIDs fc00:2::/48
#
# a and b reach each other at L2 (TTL unchanged): with one segment (the far End.DX2
# SID), then through the far router's End first (a Segment Routing Header), then
# the same with H.Encaps.L2.Red. A frame too long for the link once wrapped is
# dropped and counted. The far end is a second ruster, so that both directions are
# ruster's. Run as root after `cargo build`:
#   sudo scripts/netns-srv6-l2.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rsl$$
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

config() { # router dir, p1's MAC, wan's MAC, wan address, own SIDs, far SIDs, far wan, srv6-l2 extra
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
name = "sr0"
srv6-l2 = { sid = "$5::d2", $8 }

[[interface]]
name = "br0"
bridge = { members = ["p1", "sr0"] }

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

for form in one two reduced; do
  case $form in
    one) far1='segments = ["fc00:2::d2"]' far2='segments = ["fc00:1::d2"]' over=54 ;;
    two) far1='segments = ["fc00:2::1", "fc00:2::d2"]' far2='segments = ["fc00:1::1", "fc00:1::d2"]' over=94 ;;
    reduced) far1='segments = ["fc00:2::1", "fc00:2::d2"], reduced = true' far2='segments = ["fc00:1::1", "fc00:1::d2"], reduced = true' over=78 ;;
  esac
  config r1 02:00:00:00:01:01 02:00:00:00:01:02 2001:db8::1 fc00:1 fc00:2 2001:db8::2 "$far1"
  config r2 02:00:00:00:02:01 02:00:00:00:02:02 2001:db8::2 fc00:2 fc00:1 2001:db8::1 "$far2"
  rm -f "$work"/r?/*.log
  start r1 "$r1"
  start r2 "$r2"
  ok=0
  for _ in $(seq 1 20); do
    if pings "$a" 192.0.2.20; then ok=1; break; fi
  done
  (( ok == 1 )) || fail "a does not reach b over SRv6 L2 ($form)"
  out=$(nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20) || fail "a to b ($form): $out"
  grep -q "ttl=64" <<<"$out" || fail "a to b was not bridged (TTL changed, $form): $out"
  nsx "$b" ping -c 2 -i 0.2 -W 1 192.0.2.10 >/dev/null || fail "b to a ($form)"
  echo "ok: a and b reach each other at L2 over SRv6 ($form)"

  # The largest frame that fits: 1500 less the outer headers is the inner IP
  # packet, 28 of which are IPv4 and ICMP.
  fits=$((1500 - over - 28))
  nsx "$a" ping -c 2 -i 0.2 -W 1 -M do -s "$fits" 192.0.2.20 >/dev/null ||
    fail "a frame that fits once wrapped did not cross ($form)"
  if nsx "$a" ping -c 2 -i 0.2 -W 1 -M do -s $((fits + 1)) 192.0.2.20 >/dev/null 2>&1; then
    fail "a frame too long once wrapped crossed ($form)"
  fi
  seen=0
  for _ in $(seq 1 8); do
    n=$(counter r1 overlay_too_big)
    if [[ -n "$n" ]] && (( n >= 2 )); then seen=1; break; fi
    sleep 1
  done
  (( seen == 1 )) || fail "r1 did not count the frames too long ($form)"
  echo "ok: frames too long once wrapped are dropped and counted ($form)"
  stop
done
echo "PASS ($backend)"

#!/usr/bin/env bash
# A bridge on real Linux: ports p1, p2 and p4 are members of br0, whose own interface
# (IRB) routes to p3.
#
#   a (192.0.2.10) -- p1 --\
#   b (192.0.2.20) -- p2 ---[br0 192.0.2.1]--- routed --- p3 -- c (198.51.100.10)
#   d (b's MAC and address later) -- p4 --/
#
# a and b reach each other at L2 (TTL unchanged), c reaches both through the IRB, b's
# MAC moves to p4 and the FE follows, and learned addresses age out. The members are
# in promiscuous mode while the FE runs, and not after it stops. Run as root
# after `cargo build`:
#   sudo scripts/netns-bridge.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rsb$$
a=$tag-a b=$tag-b c=$tag-c d=$tag-d router=$tag-r
work=$(mktemp -d)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$a" "$b" "$c" "$d" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
for ns in "$a" "$b" "$c" "$d" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up

b_mac=02:00:00:00:0b:0b
host() { # namespace, its device, the router's port, the port's MAC
  ip link add "$2" netns "$1" type veth peer name "$3" netns "$router"
  nsx "$router" sysctl -qw "net.ipv6.conf.$3.disable_ipv6=1"
  nsx "$router" ethtool -K "$3" gro off rxvlan off txvlan off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$3" master vrf-ports
  nsx "$router" ip link set "$3" address "$4" up
  nsx "$1" ethtool -K "$2" tx off >/dev/null 2>&1 || true
  # No IPv6 on the hosts: its unasked frames would teach the bridge b's MAC on p4
  # before the move.
  nsx "$1" sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
  nsx "$1" ip link set "$2" up
}
host "$a" a0 p1 02:00:00:00:00:01
host "$b" b0 p2 02:00:00:00:00:02
host "$c" c0 p3 02:00:00:00:00:03
host "$d" d0 p4 02:00:00:00:00:04
nsx "$a" ip addr add 192.0.2.10/24 dev a0
nsx "$a" ip route add default via 192.0.2.1
nsx "$b" ip link set b0 address "$b_mac"
nsx "$b" ip addr add 192.0.2.20/24 dev b0
nsx "$b" ip route add default via 192.0.2.1
nsx "$d" ip link set d0 down
nsx "$d" ip link set d0 address "$b_mac"
nsx "$c" ip addr add 198.51.100.10/24 dev c0
nsx "$c" ip route add default via 198.51.100.1

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "p1"
mac = "02:00:00:00:00:01"

[[interface]]
name = "p2"
mac = "02:00:00:00:00:02"

[[interface]]
name = "p4"
mac = "02:00:00:00:00:04"

[[interface]]
name = "p3"
mac = "02:00:00:00:00:03"
ipv4 = "198.51.100.1/24"

[[interface]]
name = "br0"
mac = "02:00:00:00:00:10"
bridge = { members = ["p1", "p2", "p4"], aging-time = 10 }
ipv4 = "192.0.2.1/24"
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" p1 p2 p3 p4
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"

pings() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
ok=0
for _ in $(seq 1 20); do
  if pings "$a" 192.0.2.20; then ok=1; break; fi
done
(( ok == 1 )) || fail "a does not reach b in the bridge"
out=$(nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20) || fail "a to b: $out"
grep -q "ttl=64" <<<"$out" || fail "a to b was not bridged (TTL changed): $out"
echo "ok: a and b reach each other at L2"

promiscuity() { nsx "$router" ip -d link show "$1" | grep -o 'promiscuity [0-9]*' | awk '{print $2}'; }
for port in p1 p2 p4; do
  [[ $(promiscuity "$port") == 1 ]] || fail "member $port is not promiscuous: $(promiscuity "$port")"
done
[[ $(promiscuity p3) == 0 ]] || fail "p3, not a member, is promiscuous"
echo "ok: the members are promiscuous"

for target in 192.0.2.10 192.0.2.20; do
  ok=0
  for _ in $(seq 1 10); do
    if pings "$c" "$target"; then ok=1; break; fi
  done
  (( ok == 1 )) || fail "c does not reach $target through the IRB"
  out=$(nsx "$c" ping -c 3 -i 0.2 -W 1 "$target") || fail "c to $target: $out"
  grep -q "ttl=63" <<<"$out" || fail "c to $target was not routed: $out"
done
nsx "$a" ping -c 2 -i 0.2 -W 1 198.51.100.10 >/dev/null || fail "a to c through the IRB"
echo "ok: c reaches a and b through the IRB, and a reaches c"

# The FE reports its counters every 5 seconds when they change.
counter() { grep -o "$1: [0-9]*" "$work/ruster-fe.log" | tail -1 | awk '{print $2}'; }
wait_counter() { # name, at least, seconds
  for _ in $(seq 1 "$3"); do
    local n; n=$(counter "$1")
    if [[ -n "$n" ]] && (( n >= $2 )); then return 0; fi
    sleep 1
  done
  return 1
}

# b moves to p4: d takes its MAC and address and speaks first.
nsx "$b" ip link set b0 down
nsx "$d" ip link set d0 up
nsx "$d" ip addr add 192.0.2.20/24 dev d0
nsx "$d" ip route add default via 192.0.2.1
nsx "$d" ping -c 2 -i 0.2 -W 1 192.0.2.10 >/dev/null || fail "d (b's MAC on p4) does not reach a"
nsx "$a" ping -c 3 -i 0.2 -W 1 192.0.2.20 >/dev/null || fail "a does not reach b's address after it moved to p4"
nsx "$c" ping -c 3 -i 0.2 -W 1 192.0.2.20 >/dev/null || fail "c does not reach b's address after it moved to p4"
wait_counter bridge_moved 1 8 || fail "the FE did not count b's MAC moving"
echo "ok: b's MAC moved from p2 to p4 and traffic followed"

# Quiet for longer than the ageing time (10 s): the learned addresses age out.
aged=$(counter bridge_aged); aged=${aged:-0}
sleep 13
wait_counter bridge_aged $((aged + 1)) 8 || fail "no learned address aged out"
nsx "$a" ping -c 2 -i 0.2 -W 1 192.0.2.20 >/dev/null || fail "a to b's address after ageing"
echo "ok: learned addresses age out and are learned again"

kill "${pids[0]}"
wait "${pids[0]}" || true
for port in p1 p2 p4; do
  [[ $(promiscuity "$port") == 0 ]] || fail "$port is still promiscuous after the FE stopped"
done
echo "ok: the FE stopped and the members are not promiscuous"
echo "PASS ($backend)"

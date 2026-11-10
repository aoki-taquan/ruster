#!/usr/bin/env bash
# SRv6 between ruster and Linux's seg6: VRF red on both sides, joined over the
# IPv6 link wan. ruster wraps red's traffic to b (H.Encaps) toward Linux's
# End.DT4 and End.DT6 SIDs, and Linux wraps the replies toward ruster's.
#
#   a 192.168.1.10 -- p1 [ruster, p1 in red] wan 2001:db8::1 ==== 2001:db8::2 [Linux, bside in vrf-red] -- b 10.2.0.7
#     fd00:a::10                                SIDs fc00:1::/48     SIDs fc00:2::/48                    fd00:b::7
#
# Checks: IPv4 and IPv6 both ways; Linux's packets through ruster's End and End.X
# with a two-segment SRH; ruster's two-segment policy through Linux's End; and a
# Parameter Problem for a packet to an End.DT4 SID with segments left. Run as root
# after `cargo build`:
#   sudo scripts/netns-srv6.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rs6$$
a=$tag-a b=$tag-b router=$tag-r linux=$tag-l
work=$(mktemp -d)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$a" "$b" "$router" "$linux"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
for ns in "$a" "$b" "$router" "$linux"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
ip link add p1 netns "$router" type veth peer name a0 netns "$a"
ip link add wan netns "$router" type veth peer name wan netns "$linux"
ip link add b0 netns "$b" type veth peer name bside netns "$linux"
for port in p1:02:00:00:00:01:01 wan:02:00:00:00:01:02; do
  name=${port%%:*} mac=${port#*:}
  nsx "$router" sysctl -qw "net.ipv6.conf.$name.disable_ipv6=1"
  nsx "$router" ethtool -K "$name" gro off rxvlan off txvlan off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$name" master vrf-ports
  nsx "$router" ip link set "$name" address "$mac" up
done
# The hosts.
nsx "$a" ethtool -K a0 tx off >/dev/null 2>&1 || true
nsx "$a" ip addr add 192.168.1.10/24 dev a0
nsx "$a" ip addr add fd00:a::10/64 dev a0 nodad
nsx "$a" ip link set a0 up
nsx "$a" ip route add default via 192.168.1.1
nsx "$a" ip -6 route add default via fd00:a::1
nsx "$b" ethtool -K b0 tx off >/dev/null 2>&1 || true
nsx "$b" ip addr add 10.2.0.7/24 dev b0
nsx "$b" ip addr add fd00:b::7/64 dev b0 nodad
nsx "$b" ip link set b0 up
nsx "$b" ip route add default via 10.2.0.1
nsx "$b" ip -6 route add default via fd00:b::1

# Linux: its SIDs fc00:2::/48, and red as the VRF vrf-red (table 10).
nsx "$linux" sysctl -qw net.ipv4.ip_forward=1
nsx "$linux" sysctl -qw net.ipv6.conf.all.forwarding=1
nsx "$linux" sysctl -qw net.ipv6.conf.all.seg6_enabled=1
nsx "$linux" sysctl -qw net.vrf.strict_mode=1
# End.DT4 checks the inner source in vrf-red, whose way back leaves through wan
# outside the VRF: the reverse path filter would drop it.
nsx "$linux" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
nsx "$linux" sysctl -qw net.ipv4.conf.wan.rp_filter=0 net.ipv4.conf.bside.rp_filter=0
nsx "$linux" ethtool -K wan tx off >/dev/null 2>&1 || true
nsx "$linux" ip link set wan up
nsx "$linux" sysctl -qw net.ipv6.conf.wan.seg6_enabled=1
nsx "$linux" ip -6 addr add 2001:db8::2/64 dev wan nodad
nsx "$linux" ip -6 addr add fe80::2/64 dev wan nodad
nsx "$linux" ip link add vrf-red type vrf table 10
nsx "$linux" sysctl -qw net.ipv4.conf.vrf-red.rp_filter=0
nsx "$linux" ip link set vrf-red up
nsx "$linux" ip link set bside master vrf-red
nsx "$linux" ip addr add 10.2.0.1/24 dev bside
nsx "$linux" ip addr add fd00:b::1/64 dev bside nodad
nsx "$linux" ip link set bside up
nsx "$linux" ip sr tunsrc set 2001:db8::2
nsx "$linux" ip -6 route add fc00:1::/48 via 2001:db8::1 dev wan
nsx "$linux" ip -6 route add fc00:2::1/128 encap seg6local action End dev wan
nsx "$linux" ip -6 route add fc00:2::4/128 encap seg6local action End.DT4 vrftable 10 dev vrf-red
nsx "$linux" ip -6 route add fc00:2::6/128 encap seg6local action End.DT6 vrftable 10 dev vrf-red
# red's way back to a: to ruster's End.DT4 and End.DT6 SIDs.
back4() { nsx "$linux" ip route replace 192.168.1.0/24 vrf vrf-red encap seg6 mode encap segs "$1" dev wan; }
back4 fc00:1::4
nsx "$linux" ip -6 route add fd00:a::/64 vrf vrf-red encap seg6 mode encap segs fc00:1::6 dev wan

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
pings() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "wan"
mac = "02:00:00:00:01:02"
ipv6 = ["2001:db8::1/64"]

[[interface]]
name = "p1"
mac = "02:00:00:00:01:01"
vrf = "red"
ipv4 = "192.168.1.1/24"
ipv6 = ["fd00:a::1/64"]

[[route]]
prefix = "fc00:2::/48"
interface = "wan"
via = "2001:db8::2"

[srv6]
locator = "fc00:1::/48"
source = "2001:db8::1"

[[srv6.sid]]
sid = "fc00:1::1"
behavior = "End"

[[srv6.sid]]
sid = "fc00:1::2"
behavior = "End.X"
interface = "wan"
next-hop = "fe80::2"

[[srv6.sid]]
sid = "fc00:1::4"
behavior = "End.DT4"
vrf = "red"

[[srv6.sid]]
sid = "fc00:1::6"
behavior = "End.DT6"
vrf = "red"

[[srv6.policy]]
prefix = "10.2.0.0/24"
vrf = "red"
segments = ["fc00:2::4"]

[[srv6.policy]]
prefix = "fd00:b::/64"
vrf = "red"
segments = ["fc00:2::1", "fc00:2::6"]
TOML
start ruster-fe --backend "$backend" p1 wan
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"

ok=0
for _ in $(seq 1 20); do
  if pings "$a" 10.2.0.7; then ok=1; break; fi
done
(( ok == 1 )) || fail "a does not reach b over SRv6 (IPv4)"
out=$(nsx "$a" ping -c 3 -i 0.2 -W 1 10.2.0.7) || fail "a to b: $out"
# The reply's TTL is decremented once, by ruster after its End.DT4 (Linux wraps
# it on input, before forwarding would decrement it).
grep -q "ttl=63" <<<"$out" || fail "a to b: unexpected TTL: $out"
echo "ok: ruster's H.Encaps to Linux's End.DT4, and Linux's encap to ruster's End.DT4"

ok=0
for _ in $(seq 1 10); do
  if pings "$a" fd00:b::7; then ok=1; break; fi
done
(( ok == 1 )) || fail "a does not reach b over SRv6 (IPv6)"
echo "ok: ruster's two-segment policy through Linux's End to End.DT6, and Linux's encap to ruster's End.DT6"

# Linux's packets to a through ruster's End.X, out to Linux and back, then End.DT4:
# Linux sees ruster send it the packet to fc00:1::4 (End.X's next hop is Linux).
back4 fc00:1::2,fc00:1::4
nsx "$linux" timeout 8 tcpdump -n -i wan -c 1 -w "$work/endx.pcap" \
  'ether src 02:00:00:00:01:02 and ip6 dst fc00:1::4' >/dev/null 2>&1 &
dump=$!
sleep 1
ok=0
for _ in $(seq 1 10); do
  if pings "$b" 192.168.1.10; then ok=1; break; fi
done
(( ok == 1 )) || fail "b does not reach a through ruster's End.X"
wait "$dump" || fail "ruster's End.X did not send the packet to its next hop"
echo "ok: a two-segment SRH through ruster's End.X"
# And through ruster's End, then its End.DT4.
back4 fc00:1::1,fc00:1::4
pings "$b" 192.168.1.10 || pings "$b" 192.168.1.10 || fail "b does not reach a through ruster's End"
echo "ok: a two-segment SRH through ruster's End"

# To ruster's End.DT4 SID with a segment left: Parameter Problem, code 0, pointing
# at Segments Left (40 + 3), back to Linux.
back4 fc00:1::4,fc00:2::4
nsx "$linux" timeout 5 tcpdump -n -i wan -c 1 -w "$work/pp.pcap" \
  'icmp6 and ip6[40] == 4 and ip6[41] == 0 and ip6[44:4] == 43' >/dev/null 2>&1 &
dump=$!
sleep 1
pings "$b" 192.168.1.10 || true
wait "$dump" || fail "no Parameter Problem (code 0, pointer 43) for a packet to End.DT4 with segments left"
echo "ok: Parameter Problem for End.DT4 with segments left"
echo "PASS ($backend)"

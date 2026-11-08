#!/usr/bin/env bash
# The forward firewall on IPv6, on real Linux: the LAN host may open TCP and ping out;
# only the replies come back, and nothing the outside opens gets in. UDP, which no
# rule accepts, does not leave.
#
#   host-a (2001:db8:1::10) -- [ra | router | rb] -- host-b (2001:db8:2::10)
#
# Run as root, after `cargo build`:  sudo scripts/netns-firewall6.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsf$$
host_a=$tag-a host_b=$tag-b router=$tag-r
work=$(mktemp -d)
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$host_a" "$host_b" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$host_a" "$host_b" "$router"; do ip netns add "$ns"; done
ip link add a0 netns "$host_a" type veth peer name ra netns "$router"
ip link add b0 netns "$host_b" type veth peer name rb netns "$router"
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
for dev in ra rb; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off >/dev/null 2>&1 || true
done
nsx "$router" ip link set ra address 02:00:00:00:00:01 up
nsx "$router" ip link set rb address 02:00:00:00:00:02 up
for ns in "$host_a" "$host_b"; do
  nsx "$ns" sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
  nsx "$ns" ip link set lo up
done
nsx "$host_a" ethtool -K a0 tx off >/dev/null
nsx "$host_b" ethtool -K b0 tx off >/dev/null
nsx "$host_a" ip link set a0 up
nsx "$host_a" ip addr add 2001:db8:1::10/64 dev a0 nodad
nsx "$host_a" ip -6 route add default via fe80::ff:fe00:1 dev a0
nsx "$host_b" ip link set b0 up
nsx "$host_b" ip addr add 2001:db8:2::10/64 dev b0 nodad
nsx "$host_b" ip -6 route add default via fe80::ff:fe00:2 dev b0

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "ra"
mac = "02:00:00:00:00:01"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "rb"
mac = "02:00:00:00:00:02"
ipv6 = ["2001:db8:2::1/64"]

[[firewall]]
action = "accept"
protocol = "tcp"
ingress = "ra"

[[firewall]]
action = "accept"
protocol = "icmpv6"
ingress = "ra"
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" ra rb
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"

ok=0
for _ in $(seq 1 20); do
  if nsx "$host_a" ping -6 -c 1 -W 1 2001:db8:2::10 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "host-a does not ping out"
nsx "$host_a" ping -6 -c 5 -i 0.2 -w 5 2001:db8:2::10 >/dev/null || fail "host-a's pings and their replies"
echo "ok: the LAN pings out and the replies come back"
if nsx "$host_b" ping -6 -c 2 -i 0.2 -W 1 2001:db8:1::10 >/dev/null 2>&1; then
  fail "host-b's ping got in"
fi
echo "ok: a ping from outside does not get in"

serve() { # namespace address port
  ip netns exec "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(1); s.settimeout(8)
c, peer = s.accept(); c.sendall(peer[0].encode()); c.close()
' "$2" "$3" >/dev/null 2>"$work/server-$3.log" &
  pids+=("$!")
  listening "$1" t "$3"
}
listening() { # namespace t|u port
  for _ in $(seq 1 50); do
    nsx "$1" ss -Hln"$2" "sport = :$3" | grep -q . && return 0
    sleep 0.1
  done
  fail "nothing listens on $3 in $1"
}
connect() { # namespace address port; exits 2 when the attempt times out (dropped)
  nsx "$1" python3 -c '
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
except socket.timeout:
    sys.exit(2)
print(s.recv(100).decode())
' "$2" "$3"
}
serve "$host_b" 2001:db8:2::10 8080
seen=$(connect "$host_a" 2001:db8:2::10 8080) || fail "TCP from the LAN out"
[[ "$seen" == 2001:db8:1::10 ]] || fail "host-b saw $seen"
echo "ok: TCP from the LAN goes out"
serve "$host_a" 2001:db8:1::10 8081
# A server listens, so only the firewall can make the attempt time out (a refusal
# would mean the SYN got in).
status=0
connect "$host_b" 2001:db8:1::10 8081 >/dev/null 2>&1 || status=$?
(( status == 2 )) || fail "TCP from outside was not dropped (exit $status)"

echo "ok: TCP from outside does not get in"

# UDP: no rule accepts it.
ip netns exec "$host_b" python3 -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.bind(("2001:db8:2::10", 5353)); s.settimeout(3)
try:
    s.recvfrom(100); print("got")
except socket.timeout:
    print("none")
' >"$work/udp.out" 2>&1 &
pids+=("$!")
listening "$host_b" u 5353
nsx "$host_a" python3 -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
for _ in range(3): s.sendto(b"x", ("2001:db8:2::10", 5353))
'
for _ in $(seq 1 40); do [[ -s "$work/udp.out" ]] && break; sleep 0.1; done
[[ "$(cat "$work/udp.out")" == none ]] || fail "UDP, which no rule accepts, left"
echo "ok: UDP, which no rule accepts, does not leave"

echo "PASS ($backend)"

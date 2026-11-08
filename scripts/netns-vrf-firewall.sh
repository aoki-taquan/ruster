#!/usr/bin/env bash
# VRFs and the firewall together on real Linux: two customers with the same
# addresses in their own VRFs, a shared host in the default VRF, and the default
# VRF's firewall, whose rules name only the default VRF's interfaces. With the
# firewall on, IPv4 that red looks up in the default VRF is dropped rather than let
# past the default VRF's firewall unchecked (fail closed); the default VRF's own
# traffic is judged by the rules, and the VRFs stay apart.
#
#   red  (10.0.0.10) -- [r-red  vrf red ]
#   blue (10.0.0.10) -- [r-blue vrf blue]  router  [r-up default] -- shared (198.51.100.10)
#
# red looks 198.51.100.0/24 up in the default VRF, and the default VRF sends
# 10.0.0.0/24 back out of r-red. blue has no way out. Run as root after `cargo build`:
#   sudo scripts/netns-vrf-firewall.sh [target/debug]  (FE_BACKEND=af-packet for AF_PACKET)
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
tag=rsz$$
red=$tag-red blue=$tag-blue shared=$tag-up router=$tag-r
work=$(mktemp -d)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$red" "$blue" "$shared" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }

for ns in "$red" "$blue" "$shared" "$router"; do ip netns add "$ns"; done
link() { # host-ns host-dev router-dev router-mac host-ip/len gateway
  ip link add "$2" netns "$1" type veth peer name "$3" netns "$router"
  nsx "$router" sysctl -qw "net.ipv6.conf.$3.disable_ipv6=1"
  nsx "$router" ethtool -K "$3" gro off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$3" address "$4" up
  nsx "$1" ethtool -K "$2" tx off >/dev/null
  nsx "$1" ip link set "$2" up
  nsx "$1" ip addr add "$5" dev "$2"
  nsx "$1" ip route add default via "$6"
}
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
link "$red" h0 r-red 02:00:00:00:00:01 10.0.0.10/24 10.0.0.1
link "$blue" h0 r-blue 02:00:00:00:00:02 10.0.0.10/24 10.0.0.1
link "$shared" h0 r-up 02:00:00:00:00:03 198.51.100.10/24 198.51.100.1

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "r-red"
mac = "02:00:00:00:00:01"
ipv4 = "10.0.0.1/24"
vrf = "red"

[[interface]]
name = "r-blue"
mac = "02:00:00:00:00:02"
ipv4 = "10.0.0.1/24"
vrf = "blue"

[[interface]]
name = "r-up"
mac = "02:00:00:00:00:03"
ipv4 = "198.51.100.1/24"

# red reaches the shared host through the default VRF.
[[route]]
vrf = "red"
prefix = "198.51.100.0/24"
lookup-vrf = "default"

# The default VRF sends red's addresses back to red.
[[route]]
prefix = "10.0.0.0/24"
interface = "r-red"

# Rules are the default VRF's: the shared host may ping the router.
[[firewall]]
action = "accept"
protocol = "icmp"
ingress = "r-up"
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" r-red r-blue r-up
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"

listening() {
  for _ in $(seq 1 50); do
    nsx "$1" ss -Hltn "sport = :$2" | grep -q . && return 0
    sleep 0.1
  done
  fail "nothing listens on $2 in $1"
}
nsx "$shared" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.10", 8080)); s.listen(8); s.settimeout(30)
while True:
    c, peer = s.accept(); c.sendall(peer[0].encode()); c.close()
' >/dev/null 2>"$work/server.log" &
pids+=("$!")
listening "$shared" 8080
connect() { nsx "$1" timeout 2 python3 -c '
import socket
s = socket.create_connection(("198.51.100.10", 8080), timeout=1)
print(s.recv(100).decode())' 2>/dev/null; }
ok=0
for _ in $(seq 1 20); do
  if nsx "$shared" ping -c 1 -W 1 198.51.100.1 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the shared host's ping, which a rule accepts, does not reach the router"
echo "ok: the default VRF's rule lets the shared host ping the router"

if connect "$red" >/dev/null; then fail "red's leak passed the default VRF's firewall"; fi
if nsx "$red" ping -c 2 -i 0.2 -W 1 198.51.100.10 >/dev/null 2>&1; then
  fail "red's ping passed the default VRF's firewall"
fi
echo "ok: red's IPv4 looked up in the default VRF does not pass its firewall unchecked"

if connect "$blue" >/dev/null; then fail "blue reaches the shared host"; fi
echo "ok: blue cannot reach the shared host"

echo "PASS ($backend)"

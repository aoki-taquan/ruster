#!/usr/bin/env bash
# PPPoE end to end on real Linux: ruster-pppoed sets up a session with an access
# concentrator (rp-pppoe's pppoe-server with pppd), confd makes the session
# interface from what pppoed sends it, pppoed gives ribd the default route, and a
# LAN host reaches a host behind the AC through NAT and the session. The AC and the
# host behind it know only the router's public address (from IPCP), not the LAN.
#
#   lan (192.168.0.10) -- [r-lan | router: FE, confd, ribd, neighd, pppoed | r-wan]
#       -- [a0 ac: pppoe-server, ppp0 198.51.100.1 | i0 203.0.113.1] -- net (203.0.113.10)
#
# Needs the pppoe and ppp packages (sudo apt-get install -y pppoe ppp). Run as
# root, after `cargo build`:  sudo scripts/netns-pppoe-nat.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
command -v pppoe-server >/dev/null || { echo "SKIP: pppoe-server is not installed"; exit 0; }
command -v pppd >/dev/null || [[ -x /usr/sbin/pppd ]] || { echo "SKIP: pppd is not installed"; exit 0; }
modprobe ppp_generic 2>/dev/null || true

tag=rsy$$
lan=$tag-lan ac=$tag-ac net=$tag-net router=$tag-r
work=$(mktemp -d)
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for ns in "$ac" "$router"; do ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$ac" "$net" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log "$work"/*.out; do [[ -f $log ]] && { echo "== $log"; cat "$log"; }; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
ns_kill() {
  local pid
  for pid in $(ip netns pids "$1" 2>/dev/null); do
    [[ "$(cat "/proc/$pid/comm" 2>/dev/null)" == "$2" ]] && kill "-$3" "$pid" 2>/dev/null || true
  done
  return 0
}
listening() {
  for _ in $(seq 1 50); do
    nsx "$1" ss -Hln"$2" "sport = :$3" | grep -q . && return 0
    sleep 0.1
  done
  fail "nothing listens on $3 in $1"
}

for ns in "$lan" "$ac" "$net" "$router"; do ip netns add "$ns"; done
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
for ns in "$lan" "$ac" "$net"; do nsx "$ns" ip link set lo up; done

ip link add h0 netns "$lan" type veth peer name r-lan netns "$router"
nsx "$lan" ethtool -K h0 tx off >/dev/null
nsx "$lan" ip link set h0 up
nsx "$lan" ip addr add 192.168.0.10/24 dev h0
nsx "$lan" ip route add default via 192.168.0.1

ip link add a0 netns "$ac" type veth peer name r-wan netns "$router"
for dev in r-lan r-wan; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off >/dev/null 2>&1 || true
done
nsx "$router" ip link set r-lan address 02:00:00:00:00:01 up
nsx "$router" ip link set r-wan address 02:00:00:00:00:02 up
nsx "$ac" sysctl -qw net.ipv4.ip_forward=1
nsx "$ac" ethtool -K a0 tx off >/dev/null
nsx "$ac" ip link set a0 address 02:00:00:00:00:ac up

ip link add n0 netns "$net" type veth peer name i0 netns "$ac"
nsx "$net" ethtool -K n0 tx off >/dev/null
nsx "$ac" ethtool -K i0 tx off >/dev/null
nsx "$net" ip link set n0 up
nsx "$net" ip addr add 203.0.113.10/24 dev n0
nsx "$net" ip route add default via 203.0.113.1
nsx "$ac" ip link set i0 up
nsx "$ac" ip addr add 203.0.113.1/24 dev i0

# The AC's secrets, bound over /etc/ppp's only inside its `ip netns exec` (which
# has its own mount namespace).
printf '"user@isp" * "secret" *\n' >"$work/secrets"
chmod 600 "$work/secrets"
cat >"$work/pppd-options" <<EOF
require-chap
ms-dns 192.0.2.53
lcp-echo-interval 2
lcp-echo-failure 3
logfile $work/pppd.log
EOF
start_ac() {
  ip netns exec "$ac" sh -c "mount --bind '$work/secrets' /etc/ppp/chap-secrets &&
    exec pppoe-server -F -I a0 -C isp-ac -S inet -L 198.51.100.1 -R 198.51.100.2 -N 4 -O '$work/pppd-options'" \
    >>"$work/ac.log" 2>&1 &
  ac_pid=$!
  pids+=("$ac_pid")
}
start_ac

cat > "$work/router.toml" <<'TOML'
[[source]]
name = "pppoe-wan"
kind = "pppoe"

[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"

[[interface]]
name = "ppp"
pppoe = { parent = "r-wan", source = "pppoe-wan" }

[[pppoe]]
source = "pppoe-wan"
user = "user@isp"
password = "secret"
service = "inet"
ac-name = "isp-ac"
ipv6 = false
echo-interval = 2
default-route = true

[nat]
inside = "r-lan"
outside = "ppp"
ports = "20000-20999"

[[firewall]]
action = "accept"
protocol = "icmp"
ingress = "r-lan"

[[firewall]]
action = "accept"
protocol = "tcp"
ingress = "r-lan"

[[firewall]]
action = "accept"
protocol = "udp"
ingress = "r-lan"
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" r-lan r-wan
start ruster-ribd confd:1 pppoed:5
start ruster-neighd
start ruster-confd "$work/router.toml"
ip netns exec "$router" "$bin/ruster-pppoed" --run-dir "$run_dir" \
  >>"$work/pppoed.out" 2>"$work/pppoed.log" &
pids+=("$!")

wait_line() {
  for _ in $(seq 1 200); do
    grep -qE "$1" "$work/pppoed.out" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}
wait_line '^up pppoe-wan session=[0-9]+ ac=02:00:00:00:00:ac mtu=1492 ipv4=198.51.100.2 ' ||
  fail "no session"
echo "ok: pppoed's session is up: $(grep '^up' "$work/pppoed.out" | tail -1)"

reach() {
  for _ in $(seq 1 30); do
    nsx "$lan" ping -c 1 -W 1 203.0.113.10 >/dev/null 2>&1 && return 0
  done
  return 1
}
reach || fail "the LAN does not reach the host behind the AC through NAT and the session"
show=$(nsx "$router" "$bin/ruster" --run-dir "$run_dir" show)
grep -q "interface ppp up mac 02:00:00:00:00:02 mtu 1492 vrf default pppoe session [0-9]* on r-wan to 02:00:00:00:00:ac" <<<"$show" ||
  fail "the FE has no session interface: $show"
grep -q "route default 0.0.0.0/0 dev ppp" <<<"$show" || fail "no default route out of the session: $show"
echo "ok: the LAN pings the host behind the AC through NAT and the session"

nsx "$net" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("203.0.113.10", 8080)); s.listen(1); s.settimeout(10)
c, peer = s.accept(); c.sendall(b"%s %d" % (peer[0].encode(), peer[1])); c.close()
' >/dev/null 2>"$work/server.log" &
pids+=("$!")
listening "$net" t 8080
seen=$(nsx "$lan" python3 -c '
import socket
s = socket.create_connection(("203.0.113.10", 8080), timeout=5)
print(s.recv(100).decode())
') || fail "TCP through NAT and the session"
read -r address port <<<"$seen"
[[ "$address" == 198.51.100.2 ]] || fail "the host saw $address"
(( port >= 20000 && port <= 20999 )) || fail "the host saw port $port"
echo "ok: TCP arrives from the session's address 198.51.100.2 port $port"

# A 1500-byte datagram with DF clear: fragments in the session.
nsx "$net" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("203.0.113.10", 9999)); s.settimeout(5)
data, peer = s.recvfrom(4000); print(len(data))
' >"$work/big.out" 2>"$work/big.log" &
receiver=$!
listening "$net" u 9999
nsx "$lan" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER = IP_PMTUDISC_DONT
s.sendto(b"x" * 1472, ("203.0.113.10", 9999))
'
wait "$receiver" || fail "the big datagram did not arrive: $(cat "$work/big.log")"
[[ "$(cat "$work/big.out")" == 1472 ]] || fail "the host got $(cat "$work/big.out") bytes"
echo "ok: a datagram too big for the session arrives in fragments"

# Nothing from outside reaches into the LAN.
nsx "$lan" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.168.0.10", 2222)); s.listen(4); s.settimeout(15)
while True: s.accept()[0].close()
' >/dev/null 2>"$work/lan-server.log" &
pids+=("$!")
listening "$lan" t 2222
if nsx "$net" timeout 2 bash -c 'exec 3<>/dev/tcp/198.51.100.2/2222' 2>/dev/null; then
  fail "the outside opens TCP into the LAN"
fi
echo "ok: the outside cannot open TCP into the LAN"

# The AC ends the session: the session interface and its route go; a new session
# comes up and the LAN gets through again.
ns_kill "$ac" pppd TERM
wait_line '^down pppoe-wan reason=(peer-terminated|ac-terminated)$' || fail "no down line"
: >"$work/pppoed.out"
gone=0
for _ in $(seq 1 50); do
  if ! nsx "$router" "$bin/ruster" --run-dir "$run_dir" show | grep -q "^interface ppp "; then gone=1; break; fi
  sleep 0.1
done
(( gone == 1 )) || fail "the session interface stays after the session went down"
echo "ok: the session interface goes with the session"
wait_line '^up pppoe-wan ' || fail "no new session"
reach || fail "the LAN does not get through the new session"
echo "ok: a new session comes up and the LAN gets through again"

echo "PASS ($backend)"

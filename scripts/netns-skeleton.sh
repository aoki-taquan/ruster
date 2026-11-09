#!/usr/bin/env bash
# The skeleton on real Linux: two hosts in their own network namespaces, a router
# namespace between them, joined by veth pairs. The router runs ruster-fe,
# ruster-ribd, ruster-neighd and ruster-confd as separate processes; confd reads a
# configuration file. The test passes when each host can ping the other through it.
#
#   host-a (192.0.2.10) -- [ra | router | rb] -- host-b (198.51.100.10)
#
# Run as root, after `cargo build`:  sudo scripts/netns-skeleton.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}

bin=$(realpath "${1:-target/debug}")
for name in ruster-fe ruster-ribd ruster-neighd ruster-confd ruster; do
  [[ -x "$bin/$name" ]] || { echo "missing $bin/$name (run cargo build)" >&2; exit 2; }
done

tag=rst$$
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

for ns in "$host_a" "$host_b" "$router"; do ip netns add "$ns"; done
nsx() { ip netns exec "$@"; }
# Waits until something in namespace $1 listens on $2 port $3 (ss -ltn or -lun).
listening() {
  for _ in $(seq 1 50); do
    nsx "$1" ss -Hln"$2" "sport = :$3" | grep -q . && return 0
    sleep 0.1
  done
  fail "nothing listens on $3 in $1"
}

# The router's devices carry no kernel address: the kernel must leave them to the FE.
ip link add a0 netns "$host_a" type veth peer name ra netns "$router"
ip link add b0 netns "$host_b" type veth peer name rb netns "$router"
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
for dev in ra rb; do
  nsx "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  nsx "$router" ethtool -K "$dev" gro off >/dev/null 2>&1 || true
done
nsx "$router" ip link set ra address 02:00:00:00:00:01 up
nsx "$router" ip link set rb address 02:00:00:00:00:02 up
nsx "$router" ip link set lo up
# The FE's ports sit in a VRF with no addresses, so the kernel never takes their
# frames (AF_PACKET gives it copies) as its own; it sees the router's addresses only
# on the TUN devices confd makes.
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set ra master vrf-ports
nsx "$router" ip link set rb master vrf-ports

# veth leaves checksums to the receiver; the FE forwards frames as they are, so the
# hosts compute their own.
nsx "$host_a" ethtool -K a0 tx off >/dev/null
nsx "$host_b" ethtool -K b0 tx off >/dev/null
# No duplicate address detection on the hosts, so their IPv6 addresses work at once.
nsx "$host_a" sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
nsx "$host_b" sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
nsx "$host_a" ip link set a0 up
nsx "$host_a" ip addr add 192.0.2.10/24 dev a0
nsx "$host_a" ip route add default via 192.0.2.1
nsx "$host_a" ip addr add 2001:db8:1::10/64 dev a0 nodad
# The router's link-local addresses come from its MAC addresses (modified EUI-64).
nsx "$host_a" ip -6 route add default via fe80::ff:fe00:1 dev a0
nsx "$host_b" ip link set b0 up
nsx "$host_b" ip addr add 198.51.100.10/24 dev b0
nsx "$host_b" ip route add default via 198.51.100.1
nsx "$host_b" ip addr add 2001:db8:2::10/64 dev b0 nodad
nsx "$host_b" ip -6 route add default via fe80::ff:fe00:2 dev b0
# A network behind host-b that only an outside route source knows.
nsx "$host_b" ip addr add 203.0.113.10/32 dev lo
nsx "$host_b" ip link set lo up

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "ra"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "rb"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
ipv6 = ["2001:db8:2::1/64"]
TOML

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
declare -A pid_of
start() {
  local name=$1; shift
  # Not through nsx: a function would run in a subshell, and $! would not be the process.
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
  pid_of[$name]=$!
}
args_of() {
  case $1 in
    ruster-fe) echo "--backend $backend ra rb" ;;
    ruster-confd) echo "--kernel $work/router.toml" ;;
    ruster-ribd) echo "confd:1 routed:20" ;;
    *) echo "" ;;
  esac
}
start_named() { local name=$1; # shellcheck disable=SC2046
  start "$name" $(args_of "$name"); }
stop_named() { kill -9 "${pid_of[$1]}"; wait "${pid_of[$1]}" 2>/dev/null || true; }

fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
}
ping_ok() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
# Each host pings the other a few times; every reply must come back.
both_ways() {
  nsx "$host_a" ping -c 3 -i 0.2 -W 1 198.51.100.10 >/dev/null \
    && nsx "$host_b" ping -c 3 -i 0.2 -W 1 192.0.2.10 >/dev/null \
    && nsx "$host_a" ping -6 -c 3 -i 0.2 -W 1 2001:db8:2::10 >/dev/null \
    && nsx "$host_b" ping -6 -c 3 -i 0.2 -W 1 2001:db8:1::10 >/dev/null
}
# Waits up to 20 seconds for forwarding, then checks both ways.
comes_up() {
  for _ in $(seq 1 20); do
    if ping_ok "$host_a" 198.51.100.10 && ping_ok "$host_a" 2001:db8:2::10; then
      both_ways
      return
    fi
  done
  return 1
}
all_running() {
  local name
  for name in "${!pid_of[@]}"; do kill -0 "${pid_of[$name]}" 2>/dev/null || return 1; done
}

for name in ruster-fe ruster-ribd ruster-neighd ruster-confd; do start_named "$name"; done
comes_up || fail "IPv4 does not cross the router"
all_running || fail "a router process exited"
echo "ok: IPv4 and IPv6 cross the router both ways (four separate processes)"

# TCP and UDP cross it too, over IPv4 and IPv6: their checksums arrive right.
for dst in 198.51.100.10 2001:db8:2::10; do
  family=-4
  [[ "$dst" == *:* ]] && family=-6
  nsx "$host_b" timeout 5 nc "$family" -l 8081 >"$work/tcp-through.out" &
  listening "$host_b" t 8081
  echo hello-through | nsx "$host_a" timeout 5 nc -N "$dst" 8081 || fail "TCP to $dst"
  wait $! 2>/dev/null || true
  grep -q hello-through "$work/tcp-through.out" || fail "TCP data to $dst"
  nsx "$host_b" timeout 3 nc "$family" -u -l 8082 >"$work/udp-through.out" &
  listening "$host_b" u 8082
  echo hello-udp | nsx "$host_a" timeout 1 nc -u -q 0 "$dst" 8082 || true
  wait $! 2>/dev/null || true
  grep -q hello-udp "$work/udp-through.out" || fail "UDP to $dst"
done
echo "ok: TCP and UDP cross the router (IPv4 and IPv6)"

# A packet that would expire at the router gets a time exceeded error from it.
out=$(nsx "$host_a" ping -c 1 -W 1 -t 1 198.51.100.10 2>&1 || true)
grep -qi "time to live exceeded" <<<"$out" || fail "no ICMP Time Exceeded from the router: $out"
out=$(nsx "$host_a" ping -6 -c 1 -W 1 -t 1 2001:db8:2::10 2>&1 || true)
grep -qi "time exceeded" <<<"$out" || fail "no ICMPv6 Time Exceeded from the router: $out"
echo "ok: the router answers expiring packets with ICMP and ICMPv6 Time Exceeded"

# Traffic addressed to the router reaches its kernel through the TUN devices.
nsx "$host_a" ping -c 3 -i 0.2 -W 1 192.0.2.1 >/dev/null || fail "no answer to ping 192.0.2.1"
nsx "$host_a" ping -6 -c 3 -i 0.2 -W 1 2001:db8:1::1 >/dev/null \
  || fail "no answer to ping 2001:db8:1::1"
nsx "$host_b" ping -c 3 -i 0.2 -W 1 198.51.100.1 >/dev/null || fail "no answer to ping 198.51.100.1"
# A router address on the far side is the router's too (RFC 1812 5.2.3).
nsx "$host_a" ping -c 3 -i 0.2 -W 1 198.51.100.1 >/dev/null \
  || fail "no answer from host-a to the router's other address 198.51.100.1"
nsx "$router" timeout 5 nc -l 8080 >"$work/tcp.out" &
pids+=("$!")
sleep 0.5
echo hello-router | nsx "$host_a" timeout 5 nc -N 192.0.2.1 8080 || fail "no TCP to the router"
sleep 0.2
grep -q hello-router "$work/tcp.out" || fail "the router's kernel did not get the TCP data"
echo "ok: ping and TCP to the router reach its kernel (IPv4 and IPv6)"

# A route from an outside source (as a routing daemon would write it to ribd).
ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
ping_ok "$host_a" 203.0.113.10 && fail "203.0.113.10 is reachable before the route"
ruster route add --source routed 203.0.113.0/24 dev rb via 198.51.100.10 \
  || fail "ruster route add"
sleep 0.5
nsx "$host_a" ping -c 3 -i 0.2 -W 1 203.0.113.10 >/dev/null || fail "the outside route is not used"
ruster show | grep -q "route default 203.0.113.0/24 via 198.51.100.10 dev rb" \
  || fail "ruster show does not list the route: $(ruster show)"
ruster route del --source routed 203.0.113.0/24 || fail "ruster route del"
sleep 0.5
ping_ok "$host_a" 203.0.113.10 && fail "203.0.113.10 is still reachable after the route went"
echo "ok: a route from an outside source is used, shown, and withdrawn"

# A new configuration file through `ruster apply`: a static route comes and goes.
{ cat "$work/router.toml"; cat <<'TOML'

[[route]]
prefix = "203.0.113.0/24"
interface = "rb"
via = "198.51.100.10"
TOML
} >"$work/with-route.toml"
out=$(ruster apply "$work/with-route.toml") || fail "ruster apply: $out"
grep -q "applied" <<<"$out" || fail "ruster apply said: $out"
nsx "$host_a" ping -c 3 -i 0.2 -W 1 203.0.113.10 >/dev/null || fail "the applied route is not used"
printf '[[route]]\nprefix = "203.0.113.0/24"\ninterface = "nowhere"\n' >>"$work/with-route.toml"
ruster apply "$work/with-route.toml" >/dev/null 2>&1 && fail "ruster apply took a broken file"
ping_ok "$host_a" 203.0.113.10 || fail "a broken file changed the configuration"
out=$(ruster apply "$work/router.toml") || fail "ruster apply back: $out"
sleep 0.5
ping_ok "$host_a" 203.0.113.10 && fail "203.0.113.10 is still reachable after the file without it"
both_ways || fail "forwarding stopped after ruster apply"
echo "ok: ruster apply changes the running configuration and refuses a broken file"

# The kernel's TUN device is made again (deleted, then made by the next apply): the FE
# lets go of the old one and attaches to the new one.
nsx "$router" ip link del rt-default
out=$(ruster apply "$work/router.toml") || fail "ruster apply after deleting rt-default: $out"
for _ in $(seq 1 30); do ping_ok "$host_a" 192.0.2.1 && break; sleep 0.2; done
ping_ok "$host_a" 192.0.2.1 || fail "the router's kernel is not reached through the new rt-default"
echo "ok: a TUN device made again is attached again"

# A control process that dies does not stop forwarding, and comes back by itself.
# Counts the lines of a log that say a connection was made again.
again() { grep -c "again" "$work/$1.log" || true; }
for name in ruster-ribd ruster-neighd ruster-confd; do
  before_confd=$(again ruster-confd)
  stop_named "$name"
  both_ways || fail "forwarding stopped while $name was down"
  start_named "$name"
  # Longer than ribd's 5 s wait for its sources, so a ribd that never got confd's
  # routes back would have deleted them by now.
  sleep 6
  both_ways || fail "forwarding stopped after $name restarted"
  all_running || fail "a router process exited after $name restarted"
  case $name in
    ruster-ribd | ruster-neighd)
      (( $(again ruster-confd) > before_confd )) || fail "confd did not connect to $name again" ;;
    ruster-confd)
      grep -q "sent $work/router.toml" <(tail -n 3 "$work/ruster-confd.log") \
        || fail "the restarted confd did not send its configuration" ;;
  esac
  echo "ok: $name restarted without stopping forwarding"
done

# A restarted FE starts empty; the control processes connect again and fill it.
stop_named ruster-fe
start_named ruster-fe
comes_up || fail "forwarding did not come back after the FE restarted"
for name in ruster-ribd ruster-neighd; do
  grep -q "connected to the FE again" "$work/$name.log" || fail "$name did not connect to the FE again"
done
all_running || fail "a router process exited after the FE restarted"
echo "ok: the control processes refilled a restarted FE"

# SIGTERM stops the FE: it drains and exits by itself.
kill -TERM "${pid_of[ruster-fe]}"
status=0
for _ in $(seq 1 30); do
  kill -0 "${pid_of[ruster-fe]}" 2>/dev/null || break
  sleep 0.1
done
kill -0 "${pid_of[ruster-fe]}" 2>/dev/null && fail "the FE did not stop on SIGTERM"
wait "${pid_of[ruster-fe]}" || status=$?
(( status == 0 )) || fail "the FE exited with $status on SIGTERM"
grep -q "ruster-fe: stopped" "$work/ruster-fe.log" || fail "the FE did not report stopping"
echo "ok: SIGTERM stops the FE"

echo "PASS ($backend)"

#!/usr/bin/env bash
# The skeleton on real Linux: two hosts in their own network namespaces, a router
# namespace between them, joined by veth pairs. The router runs ruster-fe,
# ruster-ribd, ruster-neighd and ruster-confd as separate processes; confd reads a
# configuration file. The test passes when each host can ping the other through it.
#
#   host-a (192.0.2.10) -- [ra | router | rb] -- host-b (198.51.100.10)
#
# Run as root, after `cargo build`:  sudo scripts/netns-skeleton.sh [target/debug]
set -euo pipefail

bin=$(realpath "${1:-target/debug}")
for name in ruster-fe ruster-ribd ruster-neighd ruster-confd; do
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

# veth leaves checksums to the receiver; the FE forwards frames as they are, so the
# hosts compute their own.
nsx "$host_a" ethtool -K a0 tx off >/dev/null
nsx "$host_b" ethtool -K b0 tx off >/dev/null
nsx "$host_a" ip link set a0 up
nsx "$host_a" ip addr add 192.0.2.10/24 dev a0
nsx "$host_a" ip route add default via 192.0.2.1
nsx "$host_b" ip link set b0 up
nsx "$host_b" ip addr add 198.51.100.10/24 dev b0
nsx "$host_b" ip route add default via 198.51.100.1

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "ra"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "rb"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
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
    ruster-fe) echo "ra rb" ;;
    ruster-confd) echo "$work/router.toml" ;;
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
    && nsx "$host_b" ping -c 3 -i 0.2 -W 1 192.0.2.10 >/dev/null
}
# Waits up to 20 seconds for forwarding, then checks both ways.
comes_up() {
  for _ in $(seq 1 20); do
    if ping_ok "$host_a" 198.51.100.10; then both_ways; return; fi
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
echo "ok: IPv4 crosses the router both ways (four separate processes)"

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

echo "PASS"

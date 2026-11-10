#!/usr/bin/env bash
# confd's versions and the confirmed commit on real Linux. confd runs with
# --state-dir: an applied configuration (a static route to 203.0.113.0/24) outlives a
# confd restart, `ruster diff` shows a change without making it, and a configuration
# applied with --confirm-within goes back to the version before when no
# `ruster confirm` comes, even with confd started again during the wait.
#
#   host-a (192.0.2.10) -- [ra | router | rb] -- host-b (198.51.100.10, 203.0.113.10)
#
# Run as root, after `cargo build`:  sudo scripts/netns-commit.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}

bin=$(realpath "${1:-target/debug}")
for name in ruster-fe ruster-ribd ruster-neighd ruster-confd ruster; do
  [[ -x "$bin/$name" ]] || { echo "missing $bin/$name (run cargo build)" >&2; exit 2; }
done

tag=rsc$$
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

for ns in "$host_a" "$host_b" "$router"; do ip netns add "$ns"; done
nsx() { ip netns exec "$@"; }

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
# The FE's ports sit in a VRF with no addresses, so the kernel never takes their frames.
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set ra master vrf-ports
nsx "$router" ip link set rb master vrf-ports

nsx "$host_a" ethtool -K a0 tx off >/dev/null
nsx "$host_b" ethtool -K b0 tx off >/dev/null
nsx "$host_a" ip link set a0 up
nsx "$host_a" ip addr add 192.0.2.10/24 dev a0
nsx "$host_a" ip route add default via 192.0.2.1
nsx "$host_b" ip link set b0 up
nsx "$host_b" ip addr add 198.51.100.10/24 dev b0
nsx "$host_b" ip route add default via 198.51.100.1
# A network behind host-b that only the static route reaches.
nsx "$host_b" ip addr add 203.0.113.10/32 dev lo
nsx "$host_b" ip link set lo up

cat >"$work/router.toml" <<'TOML'
[[interface]]
name = "ra"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "rb"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
TOML
{ cat "$work/router.toml"; cat <<'TOML'

[[route]]
prefix = "203.0.113.0/24"
interface = "rb"
via = "198.51.100.10"
TOML
} >"$work/with-route.toml"

run_dir="$work/run" state="$work/state"
mkdir -m 0700 "$run_dir"
declare -A pid_of
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
  pid_of[$name]=$!
}
start_confd() { start ruster-confd --state-dir "$state" "$work/router.toml"; }
stop_confd() { kill -9 "${pid_of[ruster-confd]}"; wait "${pid_of[ruster-confd]}" 2>/dev/null || true; }
ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }
ping_ok() { nsx "$host_a" ping -c 1 -W 1 "$1" >/dev/null 2>&1; }
# Waits up to $2 seconds for 203.0.113.10 to be reachable (yes) or not (no).
route_is() {
  for _ in $(seq 1 "$2"); do
    if ping_ok 203.0.113.10; then [[ $1 == yes ]] && return 0
    else [[ $1 == no ]] && return 0; fi
    sleep 1
  done
  return 1
}

start ruster-fe --backend "$backend" ra rb
start ruster-ribd confd:1
start ruster-neighd
start_confd
for _ in $(seq 1 20); do ping_ok 198.51.100.10 && break; done
ping_ok 198.51.100.10 || fail "IPv4 does not cross the router"
route_is no 1 || fail "203.0.113.10 is reachable before the route"
ruster versions | grep -q "^     1  .*start-up file $work/router.toml" \
  || fail "the start-up file is not version 1: $(ruster versions)"
echo "ok: the start-up file is version 1"

# A diff changes nothing.
out=$(ruster diff "$work/with-route.toml") || fail "ruster diff: $out"
grep -q '^+prefix = "203.0.113.0/24"' <<<"$out" || fail "ruster diff does not show the route: $out"
grep -q "^+ route default 203.0.113.0/24 via 198.51.100.10 dev rb" <<<"$out" \
  || fail "ruster diff does not show the route offered to ribd: $out"
route_is no 1 || fail "ruster diff applied the route"
echo "ok: ruster diff shows the change and makes none"

# An applied version outlives confd.
out=$(ruster apply "$work/with-route.toml") || fail "ruster apply: $out"
grep -q "kept as version 2" <<<"$out" || fail "ruster apply said: $out"
route_is yes 5 || fail "the applied route is not used"
stop_confd
start_confd
# Longer than ribd's 5 s wait, so a confd that came back without the route would
# have let it go by now.
sleep 6
grep -q "sent version 2" "$work/ruster-confd.log" || fail "the restarted confd did not send version 2"
route_is yes 3 || fail "the route went with the confd restart"
echo "ok: an applied version outlives a confd restart"

# Without `ruster confirm`, confd goes back, even when started again during the wait.
out=$(ruster apply --confirm-within 1 "$work/router.toml") || fail "ruster apply --confirm-within: $out"
grep -q "kept as version 3 (apply); it goes back to version 2 at" <<<"$out" \
  || fail "ruster apply --confirm-within said: $out"
route_is no 5 || fail "the confirmed apply did not take the route away"
ruster apply "$work/with-route.toml" >/dev/null 2>&1 && fail "an apply went through while version 3 waits"
stop_confd
# A minute is the shortest wait; bring the deadline near while confd is down.
sed -i "s/^deadline = .*/deadline = $(( $(date +%s) + 5 ))/" "$state/versions/confirm.toml"
start_confd
for _ in $(seq 1 20); do ruster versions >/dev/null 2>&1 && break; sleep 0.2; done
ruster versions | grep -q "waits for .ruster confirm.; goes back to version 2" \
  || fail "the restarted confd does not wait: $(ruster versions)"
route_is yes 15 || fail "confd did not go back to version 2"
ruster versions | grep -q "^     4  .*back to 2: version 3 was not confirmed" \
  || fail "going back is not version 4: $(ruster versions)"
[[ ! -e "$state/versions/confirm.toml" ]] || fail "confirm.toml is still there"
echo "ok: a version not confirmed goes back, across a confd restart"

# With `ruster confirm`, it stays.
ruster apply --confirm-within 1 "$work/router.toml" >/dev/null || fail "ruster apply --confirm-within"
route_is no 5 || fail "the second confirmed apply did not take the route away"
out=$(ruster confirm) || fail "ruster confirm: $out"
grep -q "version 5 confirmed" <<<"$out" || fail "ruster confirm said: $out"
[[ ! -e "$state/versions/confirm.toml" ]] || fail "confirm.toml is still there after confirm"
ruster versions | grep -q "waits for" && fail "a version still waits: $(ruster versions)"
echo "ok: a confirmed version stays"

# A rollback goes back to version 2 as version 6.
out=$(ruster rollback 2) || fail "ruster rollback 2: $out"
grep -q "kept as version 6 (rollback to 2)" <<<"$out" || fail "ruster rollback said: $out"
route_is yes 5 || fail "ruster rollback 2 did not bring the route back"
echo "ok: ruster rollback puts an old version back as a new one"

for name in "${!pid_of[@]}"; do kill -0 "${pid_of[$name]}" 2>/dev/null || fail "$name exited"; done
echo "PASS ($backend)"

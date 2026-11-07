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
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
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
start() {
  local name=$1; shift
  nsx "$router" "$bin/$name" --run-dir "$run_dir" "$@" >"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe ra rb
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"

ping_ok() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }

ok=0
for _ in $(seq 1 20); do
  if ping_ok "$host_a" 198.51.100.10; then ok=1; break; fi
done
if [[ $ok == 1 ]] && nsx "$host_a" ping -c 5 -i 0.2 -W 1 198.51.100.10 >/dev/null \
  && nsx "$host_b" ping -c 5 -i 0.2 -W 1 192.0.2.10 >/dev/null; then
  for pid in "${pids[@]}"; do
    kill -0 "$pid" || { echo "FAIL: a router process exited" >&2; ok=0; }
  done
else
  ok=0
fi

if [[ $ok == 1 ]]; then
  echo "PASS: IPv4 crosses the router both ways (fe, ribd, neighd, confd as separate processes)"
else
  echo "FAIL" >&2
  for log in "$work"/*.log; do echo "== $log"; cat "$log"; done >&2
  exit 1
fi

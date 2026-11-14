#!/usr/bin/env bash
# The router started by the systemd units in contrib/systemd: two hosts in their own
# network namespaces, joined by veth pairs to the router's devices, which
# ruster-netns.service moves into the router's namespace. The test passes when the
# hosts reach each other through the router, a process killed with SIGKILL comes
# back by itself, and the router stops and starts again with ruster.target.
#
#   host-a (192.0.2.10) -- [ra | router | rb] -- host-b (198.51.100.10)
#
# The units go to /run/systemd/system (gone at reboot) and are removed at the end.
# Needs systemd as process 1, and no ruster units installed on the host.
#
# Run as root, after `cargo build`:  sudo scripts/netns-systemd.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}

bin=$(realpath "${1:-target/debug}")
here=$(dirname "$(realpath "$0")")
units_dir=$(realpath "$here/../contrib/systemd")
for name in ruster-fe ruster-ribd ruster-neighd ruster-confd ruster; do
  [[ -x "$bin/$name" ]] || { echo "missing $bin/$name (run cargo build)" >&2; exit 2; }
done
[[ "$(ps -p 1 -o comm=)" == systemd ]] || { echo "systemd is not process 1" >&2; exit 2; }
units=(ruster.target ruster-netns.service ruster-fe.service ruster-ribd.service
  ruster-neighd.service ruster-confd.service)
for unit in "${units[@]}"; do
  if systemctl cat "$unit" >/dev/null 2>&1; then
    echo "$unit is installed already; this test would replace it" >&2
    exit 2
  fi
done
for dev in ra rb; do
  if ip link show "$dev" >/dev/null 2>&1; then echo "device $dev exists already" >&2; exit 2; fi
done

tag=rst$$
host_a=$tag-a host_b=$tag-b router=$tag-r
work=$(mktemp -d)
installed=()

cleanup() {
  systemctl stop ruster.target "${units[@]}" 2>/dev/null || true
  journalctl -q --no-pager -u 'ruster*' --since "@$started" >"$work/journal.log" 2>&1 || true
  for unit in ${installed[@]+"${installed[@]}"}; do rm -f "/run/systemd/system/$unit"; done
  systemctl daemon-reload
  systemctl reset-failed "${units[@]}" 2>/dev/null || true
  for ns in "$host_a" "$host_b" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  ip link del ra 2>/dev/null || true
  ip link del rb 2>/dev/null || true
  rm -rf /run/ruster
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
started=$(date +%s)
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  systemctl status --no-pager "${units[@]}" >&2 || true
  journalctl -q --no-pager -u 'ruster*' --since "@$started" >&2 || true
  exit 1
}

# The units as shipped, with the paths of this checkout and this test.
mkdir -p "$work/etc" "$work/state"
for unit in "${units[@]}"; do
  sed -e "s|/usr/local/bin/|$bin/|g" \
    -e "s|/usr/local/lib/ruster/|$units_dir/|g" \
    -e "s|/etc/ruster/|$work/etc/|g" \
    -e "s|/run/netns/ruster|/run/netns/$router|g" \
    -e "s#ruster-netns \(up\|down\) ruster #ruster-netns \1 $router #g" \
    -e "s|/var/lib/ruster/confd|$work/state/confd|g" \
    -e "/^StateDirectory/d" \
    "$units_dir/$unit" >"/run/systemd/system/$unit"
  installed+=("$unit")
done
systemctl daemon-reload
grep -q "netns up $router " "/run/systemd/system/ruster-netns.service" \
  || fail "the namespace name in ruster-netns.service was not replaced"

cat >"$work/etc/ruster.env" <<EOF
RUSTER_PORTS="ra rb"
RUSTER_FE_OPTIONS="--backend $backend"
RUSTER_RIBD_SOURCES=""
EOF
cat >"$work/etc/router.toml" <<'TOML'
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

nsx() { ip netns exec "$@"; }
for ns in "$host_a" "$host_b"; do ip netns add "$ns"; done
# The router's ends start in the host's namespace, as a real NIC would.
ip link add a0 netns "$host_a" type veth peer name ra
ip link add b0 netns "$host_b" type veth peer name rb
ip link set ra address 02:00:00:00:00:01
ip link set rb address 02:00:00:00:00:02
for dev in ra rb; do ethtool -K "$dev" gro off >/dev/null 2>&1 || true; done
# veth leaves checksums to the receiver; the FE forwards frames as they are.
nsx "$host_a" ethtool -K a0 tx off >/dev/null
nsx "$host_b" ethtool -K b0 tx off >/dev/null
for ns in "$host_a" "$host_b"; do
  nsx "$ns" sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
done
nsx "$host_a" ip link set a0 up
nsx "$host_a" ip addr add 192.0.2.10/24 dev a0
nsx "$host_a" ip route add default via 192.0.2.1
nsx "$host_a" ip addr add 2001:db8:1::10/64 dev a0 nodad
nsx "$host_a" ip -6 route add default via fe80::ff:fe00:1 dev a0
nsx "$host_b" ip link set b0 up
nsx "$host_b" ip addr add 198.51.100.10/24 dev b0
nsx "$host_b" ip route add default via 198.51.100.1
nsx "$host_b" ip addr add 2001:db8:2::10/64 dev b0 nodad
nsx "$host_b" ip -6 route add default via fe80::ff:fe00:2 dev b0

ping_ok() { nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
both_ways() {
  nsx "$host_a" ping -c 3 -i 0.2 -W 1 198.51.100.10 >/dev/null \
    && nsx "$host_b" ping -c 3 -i 0.2 -W 1 192.0.2.10 >/dev/null \
    && nsx "$host_a" ping -6 -c 3 -i 0.2 -W 1 2001:db8:2::10 >/dev/null \
    && nsx "$host_b" ping -6 -c 3 -i 0.2 -W 1 2001:db8:1::10 >/dev/null
}
comes_up() {
  for _ in $(seq 1 20); do
    if ping_ok "$host_a" 198.51.100.10 && ping_ok "$host_a" 2001:db8:2::10; then
      both_ways
      return
    fi
  done
  return 1
}
all_active() {
  local unit
  for unit in "${units[@]}"; do systemctl -q is-active "$unit" || return 1; done
}

systemctl start ruster.target || fail "ruster.target did not start"
all_active || fail "a unit is not active after start"
[[ -e "/run/netns/$router" ]] || fail "no router namespace"
if ip link show ra >/dev/null 2>&1; then fail "ra is still in the host's namespace"; fi
comes_up || fail "IPv4 and IPv6 do not cross the router"
nsx "$host_a" ping -c 3 -i 0.2 -W 1 192.0.2.1 >/dev/null || fail "no answer from the router's kernel"
echo "ok: ruster.target starts the router, which forwards both ways and answers ping"

# A process killed with SIGKILL is started again by systemd; the FE keeps
# forwarding meanwhile.
for unit in ruster-ribd.service ruster-neighd.service ruster-confd.service ruster-fe.service; do
  before=$(systemctl show -P MainPID "$unit")
  systemctl kill -s KILL "$unit"
  for _ in $(seq 1 50); do
    now=$(systemctl show -P MainPID "$unit")
    [[ "$now" != 0 && "$now" != "$before" ]] && systemctl -q is-active "$unit" && break
    sleep 0.1
  done
  systemctl -q is-active "$unit" || fail "$unit did not come back after SIGKILL"
  comes_up || fail "no forwarding after $unit was killed"
done
echo "ok: each process killed with SIGKILL comes back, and forwarding with it"

# Stopping gives the devices back to the host; starting again moves them in again.
# systemctl waits for the target only; the units it takes down follow.
systemctl stop ruster.target
for unit in "${units[@]}"; do
  for _ in $(seq 1 100); do systemctl -q is-active "$unit" || break; sleep 0.1; done
  if systemctl -q is-active "$unit"; then fail "$unit is still active after stop"; fi
done
if [[ -e "/run/netns/$router" ]]; then fail "the router namespace is left after stop"; fi
ip link show ra >/dev/null 2>&1 || fail "ra did not come back to the host's namespace"
systemctl start ruster.target || fail "ruster.target did not start again"
all_active || fail "a unit is not active after the second start"
comes_up || fail "no forwarding after the second start"
# confd kept the version it started with in its state directory.
[[ -n "$(ls -A "$work/state/confd")" ]] || fail "confd kept no version"
echo "ok: ruster.target stops and starts again, giving the devices back in between"

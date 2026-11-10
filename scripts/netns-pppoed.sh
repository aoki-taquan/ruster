#!/usr/bin/env bash
# ruster-pppoed against a real access concentrator: rp-pppoe's pppoe-server with
# pppd, in a neighbouring namespace. pppoed takes its settings from confd, and the
# FE hands it the PPPoE frames. The session comes up with CHAP and then with PAP,
# gets its IPv4 address, the DNS servers and the IPv6 interface identifiers, and
# goes down when the AC ends it; a wrong password from `ruster apply` fails.
# Data through the session is netns-pppoe-nat.sh's.
#
#   [router: FE, confd, ribd, neighd, pppoed, r-wan] -- [ac: pppoe-server, a0]
#
# Needs the pppoe and ppp packages (sudo apt-get install -y pppoe ppp). Run as
# root, after `cargo build`:  sudo scripts/netns-pppoed.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")
command -v pppoe-server >/dev/null || { echo "SKIP: pppoe-server is not installed"; exit 0; }
command -v pppd >/dev/null || [[ -x /usr/sbin/pppd ]] || { echo "SKIP: pppd is not installed"; exit 0; }
modprobe ppp_generic 2>/dev/null || true

tag=rsd$$
ac=$tag-ac router=$tag-r
work=$(mktemp -d)
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done
  # pppoe-server's children (pppd) are in the namespace too.
  for ns in "$ac" "$router"; do ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$ac" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log "$work"/*.out; do [[ -f $log ]] && { echo "== $log"; cat "$log"; }; done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
# Sends signal $3 to the processes named $2 in namespace $1 (pkill is not
# limited to a namespace).
ns_kill() {
  local pid
  for pid in $(ip netns pids "$1" 2>/dev/null); do
    [[ "$(cat "/proc/$pid/comm" 2>/dev/null)" == "$2" ]] && kill "-$3" "$pid" 2>/dev/null
  done
  return 0
}

for ns in "$ac" "$router"; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
ip link add a0 netns "$ac" type veth peer name r-wan netns "$router"
nsx "$ac" ip link set a0 address 02:00:00:00:00:ac up
nsx "$router" ip link set r-wan address 02:00:00:00:00:02 up
nsx "$router" sysctl -qw net.ipv6.conf.r-wan.disable_ipv6=1

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
nsx "$router" ethtool -K r-wan gro off >/dev/null 2>&1 || true

# The AC's secrets, bound over /etc/ppp's only inside its `ip netns exec` (which
# has its own mount namespace).
printf '"user@isp" * "secret" *\n' >"$work/secrets"
chmod 600 "$work/secrets"

# Starts the AC requiring `$1` (chap or pap).
start_ac() {
  cat >"$work/pppd-options" <<EOF
require-$1
ms-dns 192.0.2.53
ms-dns 192.0.2.54
+ipv6
lcp-echo-interval 2
lcp-echo-failure 3
debug
logfile $work/pppd.log
EOF
  ip netns exec "$ac" sh -c "mount --bind '$work/secrets' /etc/ppp/chap-secrets &&
    mount --bind '$work/secrets' /etc/ppp/pap-secrets &&
    exec pppoe-server -F -I a0 -C isp-ac -S inet -L 198.51.100.1 -R 198.51.100.2 -N 4 -O '$work/pppd-options'" \
    >"$work/ac.log" 2>&1 &
  ac_pid=$!
  pids+=("$ac_pid")
}

config() {
  cat <<TOML
[[source]]
name = "wan"
kind = "pppoe"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"

[[interface]]
name = "ppp"
pppoe = { parent = "r-wan", source = "wan" }

[[pppoe]]
source = "wan"
user = "user@isp"
password = "$1"
service = "inet"
ac-name = "isp-ac"
echo-interval = 2
TOML
}
config secret >"$work/router.toml"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" r-wan
start ruster-ribd
start ruster-neighd
start ruster-confd "$work/router.toml"
ip netns exec "$router" "$bin/ruster-pppoed" --run-dir "$run_dir" \
  >>"$work/pppoed.out" 2>"$work/pppoed.log" &
pids+=("$!")

# Waits for an output line matching $1.
wait_line() {
  for _ in $(seq 1 150); do
    grep -qE "$1" "$work/pppoed.out" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

up='^up wan session=[0-9]+ ac=02:00:00:00:00:ac mtu=1492 ipv4=198.51.100.2 peer-ipv4=198.51.100.1 dns=192.0.2.53,192.0.2.54 ipv6-id=[0-9a-f:]{19} peer-ipv6-id=[0-9a-f:]{19}$'

for auth in chap pap; do
  : >"$work/pppoed.out"
  start_ac "$auth"
  wait_line "$up" || fail "$auth: no full up line"
  # The AC's side agrees.
  for _ in $(seq 1 30); do
    nsx "$ac" ip -4 addr show 2>/dev/null | grep -q "198.51.100.1 peer 198.51.100.2" && break
    sleep 0.1
  done
  nsx "$ac" ip -4 addr show | grep -q "198.51.100.1 peer 198.51.100.2" ||
    fail "$auth: the AC has no ppp interface with the addresses"
  # The AC's echoes are answered for a while.
  sleep 7
  grep -q '^down' "$work/pppoed.out" && fail "$auth: the session went down"
  echo "ok: $auth session up: $(grep '^up' "$work/pppoed.out" | tail -1)"

  # The AC ends it: pppd sends Terminate-Request and pppoe a PADT.
  ns_kill "$ac" pppd TERM
  wait_line '^down wan reason=(peer-terminated|ac-terminated)$' || fail "$auth: no down line"
  echo "ok: $auth session down: $(grep '^down' "$work/pppoed.out" | tail -1)"
  kill "$ac_pid" 2>/dev/null || true
  wait "$ac_pid" 2>/dev/null || true
  ns_kill "$ac" pppd KILL
  sleep 0.5
done

# A wrong password from a new configuration: the session starts again and fails.
config wrong >"$work/router.toml"
: >"$work/pppoed.out"
start_ac chap
nsx "$router" "$bin/ruster" --run-dir "$run_dir" apply "$work/router.toml" >/dev/null ||
  fail "ruster apply"
wait_line '^failed wan reason=auth-failed$' || fail "no failed line for a wrong password"
echo "ok: a wrong password fails"

echo "PASS ($backend)"

#!/usr/bin/env bash
# Unbound as the LAN's DNS server, set up by ruster-unbound from confd's dns part.
# The router's Unbound answers a name of its own (local-data in the operator's
# unbound.conf) and forwards the rest to an upstream Unbound on the WAN, through NAT.
# No internet is needed.
#
#   lan (192.0.2.10) -- [r-lan | router | r-wan 198.51.100.1] -- wan (198.51.100.10, Unbound)
#
# Needs unbound and dig (apt-get install unbound bind9-dnsutils); the distribution's
# unbound service is not used. Run as root, after `cargo build`:
#   sudo scripts/netns-dns.sh [target/debug]
# FE_BACKEND=af-packet selects the FE's AF_PACKET backend (af-xdp by default).
set -euo pipefail
backend=${FE_BACKEND:-af-xdp}
bin=$(realpath "${1:-target/debug}")

tag=rsd$$
lan=$tag-lan wan=$tag-wan router=$tag-r
work=$(mktemp -d)
# Unbound's files: Ubuntu's AppArmor profile lets Unbound read only below
# /etc/unbound and /var/lib/unbound.
udir=/var/lib/unbound/$tag
pids=()

cleanup() {
  for pid in ${pids[@]+"${pids[@]}"} $(cat "$udir"/unbound.pid "$udir"/up/unbound.pid 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$lan" "$wan" "$router"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -rf "$udir"
  if [[ "${keep_logs:-}" == 1 ]]; then echo "logs in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for log in "$work"/*.log "$udir"/unbound.log "$udir"/up/unbound.log; do
    [[ -e "$log" ]] && { echo "== $log"; cat "$log"; }
  done >&2
  exit 1
}
nsx() { ip netns exec "$@"; }
command -v unbound >/dev/null || fail "unbound is not installed"
command -v dig >/dev/null || fail "dig is not installed"

for ns in "$lan" "$wan" "$router"; do ip netns add "$ns"; done
link() { # host-ns router-dev router-mac host-ip/len gateway
  ip link add h0 netns "$1" type veth peer name "$2" netns "$router"
  nsx "$router" sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
  nsx "$router" ethtool -K "$2" gro off >/dev/null 2>&1 || true
  nsx "$router" ip link set "$2" address "$3" up
  nsx "$1" ethtool -K h0 tx off >/dev/null
  nsx "$1" ip link set h0 up
  nsx "$1" ip link set lo up
  nsx "$1" ip addr add "$4" dev h0
  nsx "$1" ip route add "$5" via "${4%.*}.1"
}
nsx "$router" sysctl -qw net.ipv4.ip_forward=0
link "$lan" r-lan 02:00:00:00:00:01 192.0.2.10/24 default
link "$wan" r-wan 02:00:00:00:00:02 198.51.100.10/24 192.0.2.0/24
nsx "$router" ip link set lo up
nsx "$router" ip link add vrf-ports type vrf table 999
nsx "$router" ip link set vrf-ports up
nsx "$router" ip link set r-lan master vrf-ports
nsx "$router" ip link set r-wan master vrf-ports

cat > "$work/router.toml" <<'TOML'
[[interface]]
name = "r-lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "r-wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"

[nat]
inside = "r-lan"
outside = "r-wan"
ports = "20000-20999"
TOML
# The same with DNS for the LAN (NAT's inside), forwarding to the WAN's Unbound.
cp "$work/router.toml" "$work/with-dns.toml"
printf '\n[dns]\nupstream = ["198.51.100.10"]\n' >>"$work/with-dns.toml"
sed 's/198.51.100.10"/198.51.100.11"/' "$work/with-dns.toml" >"$work/other-upstream.toml"

mkdir -p "$udir/up"
# The operator's unbound.conf for the router: everything but what ruster-unbound
# writes, which it includes.
unbound_common() { # directory
  cat <<CONF
server:
    username: ""
    chroot: ""
    directory: "$1"
    pidfile: "$1/unbound.pid"
    use-syslog: no
    logfile: "$1/unbound.log"
    do-ip6: no
CONF
}
{
  unbound_common "$udir"
  cat <<CONF
    local-zone: "router.example." static
    local-data: "host.router.example. A 192.0.2.99"
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-use-cert: no
include-toplevel: "$udir/ruster.conf"
CONF
} >"$udir/unbound.conf"
# The upstream on the WAN, with a name of its own.
{
  unbound_common "$udir/up"
  cat <<CONF
    interface: 198.51.100.10
    access-control: 198.51.100.0/24 allow
    local-zone: "up.example." static
    local-data: "www.up.example. A 203.0.113.80"
CONF
} >"$udir/up/unbound.conf"
# What `systemctl restart unbound` does on a router: stops the router's Unbound and
# starts it again. It fails while $udir/broken exists.
cat >"$work/restart-unbound" <<SH
#!/usr/bin/env bash
set -eu
[[ ! -e "$udir/broken" ]] || { echo "broken on purpose" >&2; exit 1; }
if [[ -s "$udir/unbound.pid" ]]; then
  pid=\$(cat "$udir/unbound.pid")
  kill "\$pid" 2>/dev/null || true
  for _ in \$(seq 1 50); do kill -0 "\$pid" 2>/dev/null || break; sleep 0.1; done
fi
unbound -c "$udir/unbound.conf"
for _ in \$(seq 1 50); do
  unbound-control -c "$udir/unbound.conf" status >/dev/null 2>&1 && exit 0
  sleep 0.1
done
echo "Unbound did not start" >&2
exit 1
SH
chmod 0755 "$work/restart-unbound"

run_dir="$work/run"
mkdir -m 0700 "$run_dir"
start() {
  local name=$1; shift
  ip netns exec "$router" "$bin/$name" --run-dir "$run_dir" "$@" >>"$work/$name.log" 2>&1 &
  pids+=("$!")
}
start ruster-fe --backend "$backend" r-lan r-wan
start ruster-ribd
start ruster-neighd
start ruster-confd --kernel "$work/router.toml"
# Without Unbound running, the first part's restart starts it.
start ruster-unbound --reload "$work/restart-unbound" "$udir/ruster.conf"
for _ in $(seq 1 50); do [[ -s "$udir/unbound.pid" ]] && break; sleep 0.1; done
[[ -s "$udir/ruster.conf" ]] || fail "ruster-unbound wrote no settings"
grep -q interface: "$udir/ruster.conf" && fail "settings without [dns]: $(cat "$udir/ruster.conf")"
nsx "$router" unbound-control -c "$udir/unbound.conf" status >/dev/null 2>&1 ||
  fail "the router's Unbound does not run"
nsx "$wan" unbound -c "$udir/up/unbound.conf" || fail "the upstream Unbound does not start"

ok=0
for _ in $(seq 1 20); do
  if nsx "$lan" ping -c 1 -W 1 198.51.100.10 >/dev/null 2>&1; then ok=1; break; fi
done
(( ok == 1 )) || fail "the LAN does not reach the WAN host"

# Asks $2 from namespace $1 for an A record of $3; prints the answer and the status.
ask() { nsx "$1" dig +tries=1 +time=2 @"$2" "$3" A +noall +answer +comments 2>&1 || true; }
ruster() { nsx "$router" "$bin/ruster" --run-dir "$run_dir" "$@"; }

ask "$lan" 192.0.2.1 host.router.example | grep -q "192.0.2.99" &&
  fail "Unbound answers the LAN before the configuration has dns"
echo "ok: without dns, Unbound does not answer the LAN"

out=$(ruster apply "$work/with-dns.toml") || fail "ruster apply: $out"
grep -q "applied" <<<"$out" || fail "ruster apply said: $out"
grep -q "interface: 192.0.2.1" "$udir/ruster.conf" || fail "settings: $(cat "$udir/ruster.conf")"
answer=$(ask "$lan" 192.0.2.1 host.router.example)
grep -q "192.0.2.99" <<<"$answer" || fail "the router's own name: $answer"
echo "ok: after ruster apply, Unbound answers the LAN on the router's LAN address"
answer=$(ask "$lan" 192.0.2.1 www.up.example)
grep -q "203.0.113.80" <<<"$answer" || fail "a forwarded name: $answer"
echo "ok: Unbound forwards the rest to the upstream on the WAN, through NAT"

# The WAN host is not among the allowed clients (Unbound refuses it, and NAT does
# not let the refusal back out), and nothing answers on the WAN address.
for address in 192.0.2.1 198.51.100.1; do
  answer=$(ask "$wan" "$address" host.router.example)
  grep -q "192.0.2.99" <<<"$answer" && fail "the WAN host got an answer from $address: $answer"
done
echo "ok: the WAN host gets no answer"

# Unbound cannot restart: ruster-unbound refuses the new part and confd goes back.
touch "$udir/broken"
before=$(cat "$udir/ruster.conf")
out=$(ruster apply "$work/other-upstream.toml" 2>&1) && fail "ruster apply took it: $out"
grep -q "refused" <<<"$out" || fail "ruster apply said: $out"
[[ "$(cat "$udir/ruster.conf")" == "$before" ]] || fail "the settings changed: $(cat "$udir/ruster.conf")"
rm "$udir/broken"
answer=$(ask "$lan" 192.0.2.1 www.up.example)
grep -q "203.0.113.80" <<<"$answer" || fail "after the refusal: $answer"
echo "ok: a failed reload is refused, and the configuration before stays"

# ruster-unbound starts again and takes the part again without changing anything.
kill "${pids[4]}"; wait "${pids[4]}" 2>/dev/null || true
start ruster-unbound --reload "$work/restart-unbound" "$udir/ruster.conf"
sleep 1
[[ "$(cat "$udir/ruster.conf")" == "$before" ]] || fail "the settings changed after a restart"
out=$(ruster apply "$work/router.toml") || fail "ruster apply without dns: $out"
grep -q interface: "$udir/ruster.conf" && fail "settings after removing dns: $(cat "$udir/ruster.conf")"
ask "$lan" 192.0.2.1 host.router.example | grep -q "192.0.2.99" &&
  fail "Unbound still answers the LAN after dns was removed"
echo "ok: ruster-unbound starts again, and removing dns stops the answers"

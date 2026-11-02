#!/bin/sh
# Privileged end-to-end smoke of `ruster run` (M2 S10a, X04b first half).
#
# Builds the `ruster` binary as the invoking user, then with `sudo -n`
# creates three dedicated network namespaces: a router namespace holding
# the router's veth ends, and one host namespace per LAN/WAN peer. Every
# veth pair is created with `ip -n <router>` and its peer end is moved
# straight into a host namespace, so no interface ever exists in the
# initial namespace; every other `ip` call is `ip -n` or runs under
# `ip netns exec`. The namespaces are always deleted (which destroys every
# veth and detaches every XDP program on them). Any missing privilege or
# tool fails; nothing is skipped.
#
# Topology (router-v1 fixture with devices ra/rb and an AF_XDP backend):
#
#   host A (192.168.1.10/24, gw .1) pa ── ra  [ruster run]  rb ── pb host B (203.0.113.1/24)
#
# Phases:
#   forward   start `ruster run`; a UDP datagram from host A to host B
#             crosses the router (ARP reply from the router to A, ARP
#             request from the router to B, NAT44 to 203.0.113.2, stateful
#             firewall); SIGTERM; exit 0, no XDP left on ra/rb, final stats
#   ops       (M2 S10b) on one running router: SIGHUP reload that turns the
#             LAN->WAN UDP rule into deny (the datagram stops arriving) and
#             back (it arrives again), generations 2 and 3, no restart; a
#             restart-required reload (UMEM shape) refused while traffic
#             keeps flowing; `ip link set ra down/up` inside the router
#             namespace warns and recovers with forwarding; then rb's MTU
#             raised beyond the 2048-byte frame bound: exit 1 after drain,
#             nothing left attached
#   forwarding  ip_forward=1 in the router namespace is refused at startup
#             (KERNEL_FORWARDING_ENABLED), accepted with a warning under
#             --allow-kernel-forwarding, and only warned while running;
#             then conf/ra/forwarding=1 with ip_forward=0: refused at
#             startup with scope=device, warned on if1 (only) while
#             running and recovered when cleared (M2 S11)
#   removal   (last) `ip link del ra` inside the router namespace while
#             running: exit 1 (DEVICE_REMOVED), nothing left attached
#   rollback  a second port that fails to open (queue 1 of a one-queue
#             veth) or to attach (a foreign xdpgeneric program on rb):
#             exit 1 with the stage and port, nothing left attached on ra,
#             and the foreign program untouched
#   checks    a two-queue device and a kernel IPv4 address on the port are
#             refused before attach (XDP-063)
#   restart   SIGKILL a running router: the unpinned links auto-detach;
#             restart (bounded retry of the transient BIND/BUSY or
#             REGISTER_UMEM/MEMLOCK_LIMIT after teardown, XDP-045, in this
#             test only) and forward again, then SIGTERM, exit 0
#   stuck     stdout on a FIFO that is held open but never read: the stats
#             blocks fill it (checked: queued bytes at capacity and not
#             moving), yet SIGTERM still drains, detaches, and the process
#             exits within 10 seconds with status 0 (#301 LN1)
set -eu

# RUSTER_REQUIRE_PRIV=1 (the `XDP veth` CI job) is passed to the privileged
# tests, which then fail instead of skipping. Nothing here ever skips.
case ${RUSTER_REQUIRE_PRIV-} in
"" | 1) ;;
*)
    echo "priv-run-smoke: RUSTER_REQUIRE_PRIV must be 1 or unset" >&2
    exit 1
    ;;
esac

for tool in cargo ip sudo python3 od ethtool ps; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "priv-run-smoke: missing $tool" >&2
        exit 1
    }
done
sudo -n true || {
    echo "priv-run-smoke: passwordless sudo is required" >&2
    exit 1
}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

binary=$(cd "$root" && cargo build --locked -p ruster-cli --bin ruster --message-format=json |
    sed -n 's/.*"executable":"\([^"]*\/ruster\)".*/\1/p' | tail -n 1)
test -x "$binary" || {
    echo "priv-run-smoke: ruster binary not found" >&2
    exit 1
}
binary_path=$(readlink -f "$binary")

suffix=$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')
router="ruster-run-$$-$suffix"
host_a="$router-a"
host_b="$router-b"
work=$(mktemp -d "${TMPDIR:-/tmp}/ruster-priv-run.XXXXXX")
pidfile="$work/ruster.pid"
stopfile="$work/sender.stop"
created=
launcher=
ruster_pid=

# True only if `$1` is a live process running the built ruster binary.
is_ruster() {
    [ -n "$1" ] && [ "$(sudo -n readlink "/proc/$1/exe" 2>/dev/null)" = "$binary_path" ]
}

cleanup() {
    if [ -z "$ruster_pid" ] && [ -s "$pidfile" ]; then
        ruster_pid=$(tr -cd '0-9' <"$pidfile")
    fi
    if is_ruster "$ruster_pid"; then
        sudo -n kill -KILL "$ruster_pid" 2>/dev/null || true
    fi
    ruster_pid=
    if [ -n "$launcher" ]; then
        wait "$launcher" 2>/dev/null || true
        launcher=
    fi
    : >"$stopfile" 2>/dev/null || true
    for ns in $created; do
        sudo -n ip netns del "$ns" 2>/dev/null || true
    done
    created=
    rm -rf "$work"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT

# A pre-existing namespace of these names is never adopted or deleted.
for ns in "$router" "$host_a" "$host_b"; do
    if ! sudo -n ip netns add "$ns"; then
        echo "priv-run-smoke: cannot create $ns (already exists?); not touching it" >&2
        exit 1
    fi
    created="$ns $created"
done

in_ns() {
    ns=$1
    shift
    sudo -n ip netns exec "$ns" "$@"
}

fail() {
    echo "priv-run-smoke: $*" >&2
    for log in "$work"/*.err "$work"/*.out; do
        [ -f "$log" ] || continue
        echo "--- $log" >&2
        cat "$log" >&2
    done
    exit 1
}

# One-queue veth pairs whose peer ends live in the host namespaces.
sudo -n ip -n "$router" link add ra numtxqueues 1 numrxqueues 1 type veth \
    peer name pa netns "$host_a" numtxqueues 1 numrxqueues 1
sudo -n ip -n "$router" link add rb numtxqueues 1 numrxqueues 1 type veth \
    peer name pb netns "$host_b" numtxqueues 1 numrxqueues 1
# A two-queue pair entirely inside the router namespace (checks phase).
sudo -n ip -n "$router" link add rq numtxqueues 2 numrxqueues 2 type veth \
    peer name rqp numtxqueues 2 numrxqueues 2
sudo -n ip -n "$router" link set ra address 02:00:00:00:00:01
sudo -n ip -n "$router" link set rb address 02:00:00:00:00:02
for dev in ra rb rq rqp; do
    sudo -n ip -n "$router" link set "$dev" up
done
# Kernel IPv4 forwarding stays off in the router namespace (refused by
# `ruster run` unless --allow-kernel-forwarding; checks phase).
in_ns "$router" sysctl -qw net.ipv4.ip_forward=0
# Host A is the fixture's static LAN neighbor 192.168.1.10.
sudo -n ip -n "$host_a" link set pa address 02:00:00:00:00:10
sudo -n ip -n "$host_a" address add 192.168.1.10/24 dev pa
sudo -n ip -n "$host_a" link set pa up
sudo -n ip -n "$host_a" route add default via 192.168.1.1
# veth hands locally generated UDP over with a partial (offloaded)
# checksum that no NIC completes; the router's firewall rightly drops it
# (FIREWALL_UDP_CHECKSUM_INVALID). Make host A compute full checksums.
in_ns "$host_a" ethtool -K pa tx off >/dev/null
# Host B is resolved by the router's ARP (no static neighbor).
sudo -n ip -n "$host_b" address add 203.0.113.1/24 dev pb
sudo -n ip -n "$host_b" link set pb up

# The router-v1 fixture on ra/rb plus a copy-mode AF_XDP backend.
write_config() {
    # $1 output, $2 lan device, $3 wan queue
    sed -e 's/device = "sim0"/device = "'"$2"'"/' -e 's/device = "sim1"/device = "rb"/' \
        "$root/fixtures/m1/router-v1.toml" >"$1"
    cat >>"$1" <<EOF

[backend]
kind = "af-xdp"

[[backend.ports]]
interface = "lan"
queue = 0
mode = "copy"
xdp-attach = "native"
rings = { fill = 128, rx = 128, tx = 128, completion = 128 }
frame-size = 2048
frame-count = 512
generated-frames = 64

[[backend.ports]]
interface = "wan"
queue = $3
mode = "copy"
xdp-attach = "native"
rings = { fill = 128, rx = 128, tx = 128, completion = 128 }
frame-size = 2048
frame-count = 512
generated-frames = 64
EOF
}
write_config "$work/router.toml" ra 0
write_config "$work/bad-queue.toml" ra 1
write_config "$work/multi-queue.toml" rq 0

xdp_on() {
    # Prints "<mode> <id>" of the program attached to $1, or nothing.
    sudo -n ip -n "$router" -details link show dev "$1" | awk '
        NR == 1 { for (i = 1; i <= NF; i++) if ($i ~ /^xdp(generic|offload|multi)?$/) mode = $i }
        { for (i = 1; i < NF; i++) if ($i ~ /^prog\/xdp/ && $(i + 1) == "id") id = $(i + 2) }
        END { if (id != "") print mode " " id }'
}

assert_detached() {
    for dev in ra rb rq; do
        test -z "$(xdp_on "$dev")" || fail "XDP left attached on $dev after $1"
    done
}

# Starts `ruster run` in the router namespace; its stdout/stderr go to
# $work/$1.out and $work/$1.err. The pid is the ruster process itself
# (`sh` execs `ip netns exec`, which execs ruster). $3, if given, is one
# extra option without spaces.
start_ruster() {
    name=$1
    config=$2
    rm -f "$pidfile"
    sudo -n sh -c 'echo $$ >"$1"; shift; exec ip netns exec "$@"' sh "$pidfile" \
        "$router" "$binary_path" run --stats-interval 1 ${3:-} --config "$config" \
        >"$work/$name.out" 2>"$work/$name.err" &
    launcher=$!
    tries=0
    while [ ! -s "$pidfile" ]; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "ruster did not start within 10 seconds"
        sleep 0.05
    done
    candidate=$(tr -cd '0-9' <"$pidfile")
    ruster_pid=$candidate
}

# Waits for the launcher (sudo, which returns ruster's status) and sets
# `status`. Never used in a command substitution: `wait` needs this shell.
wait_ruster() {
    status=0
    wait "$launcher" || status=$?
    launcher=
    ruster_pid=
}

# Whether the launcher still runs (a reaped or zombie child does not).
launcher_alive() {
    case $(ps -o stat= -p "$launcher" 2>/dev/null) in
    "" | Z*) return 1 ;;
    *) return 0 ;;
    esac
}

# Waits until `ruster run` reports readiness; returns 1 if it exited first.
wait_ready() {
    name=$1
    tries=0
    while ! grep -q "running generation 1 on 2 port(s)" "$work/$name.err"; do
        if ! launcher_alive; then
            return 1
        fi
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "$name: not ready within 10 seconds"
        sleep 0.05
    done
    is_ruster "$ruster_pid" || fail "$name: pid does not belong to the ruster binary"
}

signal_ruster() {
    is_ruster "$ruster_pid" || fail "refusing to signal a pid that is not ruster"
    sudo -n kill "-$1" "$ruster_pid"
}

# Waits until $work/$1.err contains the fixed text $2 while ruster runs.
wait_line() {
    name=$1
    text=$2
    tries=0
    while ! grep -qF -- "$text" "$work/$name.err"; do
        launcher_alive || fail "$name: exited while waiting for: $text"
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "$name: no \"$text\" within 10 seconds"
        sleep 0.05
    done
}

# Waits for ruster to exit by itself within 10 seconds and sets `status`.
wait_exit() {
    name=$1
    tries=0
    while launcher_alive; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "$name: still running 10 seconds after the event"
        sleep 0.05
    done
    wait_ruster
}

RECEIVE='
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.settimeout(float(sys.argv[3]))
print("ready", flush=True)
while True:
    data, (host, port) = s.recvfrom(2048)
    if sys.argv[2].encode() in data:
        print(host, port, flush=True)
        sys.exit(0)
'
SEND='
import os, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(100):
    if os.path.exists(sys.argv[4]):
        break
    try:
        s.sendto(sys.argv[3].encode(), (sys.argv[1], int(sys.argv[2])))
    except OSError:
        pass
    time.sleep(0.1)
'

# Prints "<queued bytes> <capacity>" of the FIFO at argv[1] without reading
# from it (a second, non-blocking read end; FIONREAD and F_GETPIPE_SZ).
PIPE_FILL='
import array, fcntl, os, sys, termios
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NONBLOCK)
queued = array.array("i", [0])
fcntl.ioctl(fd, termios.FIONREAD, queued, True)
print(queued[0], fcntl.fcntl(fd, getattr(fcntl, "F_GETPIPE_SZ", 1032)))
'

# Host A -> host B through the router; checks NAT44 on arrival.
forward_once() {
    tag=$1
    marker="ruster-s10a-$tag-$suffix"
    rm -f "$stopfile" "$work/recv-$tag.out"
    in_ns "$host_b" python3 -I -c "$RECEIVE" 9000 "$marker" 10 >"$work/recv-$tag.out" 2>&1 &
    receiver=$!
    tries=0
    while ! grep -q ready "$work/recv-$tag.out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "$tag: receiver not ready"
        sleep 0.05
    done
    in_ns "$host_a" python3 -I -c "$SEND" 203.0.113.1 9000 "$marker" "$stopfile" &
    sender=$!
    status=0
    wait "$receiver" || status=$?
    : >"$stopfile"
    wait "$sender" || true
    [ "$status" -eq 0 ] || fail "$tag: host B never received the datagram"
    source=$(sed -n 2p "$work/recv-$tag.out")
    case $source in
    "203.0.113.2 400"[0-1][0-9]) ;;
    *) fail "$tag: datagram not translated by NAT44 (source $source)" ;;
    esac
    echo "priv_run_$tag: host A -> host B forwarded and translated ($source) verified"
}

# Host A -> host B must NOT arrive within 3 seconds (firewall deny).
forward_blocked() {
    tag=$1
    marker="ruster-s10b-$tag-$suffix"
    rm -f "$stopfile" "$work/recv-$tag.out"
    in_ns "$host_b" python3 -I -c "$RECEIVE" 9000 "$marker" 3 >"$work/recv-$tag.out" 2>&1 &
    receiver=$!
    tries=0
    while ! grep -q ready "$work/recv-$tag.out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "$tag: receiver not ready"
        sleep 0.05
    done
    in_ns "$host_a" python3 -I -c "$SEND" 203.0.113.1 9000 "$marker" "$stopfile" &
    sender=$!
    status=0
    wait "$receiver" || status=$?
    : >"$stopfile"
    wait "$sender" || true
    [ "$status" -ne 0 ] || fail "$tag: host B received a datagram the firewall denies"
    echo "priv_run_$tag: host A -> host B denied by the reloaded firewall verified"
}

# Replaces the running router's config atomically and sends SIGHUP.
reload_with() {
    cp "$1" "$work/ops.next"
    mv "$work/ops.next" "$work/ops.toml"
    signal_ruster HUP
}

# forward: cold start, forward, SIGTERM.
start_ruster forward "$work/router.toml"
wait_ready forward || fail "forward: ruster exited during startup"
case $(xdp_on ra) in xdp\ [0-9]*) ;; *) fail "forward: no native XDP on ra" ;; esac
case $(xdp_on rb) in xdp\ [0-9]*) ;; *) fail "forward: no native XDP on rb" ;; esac
forward_once forward
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "forward: exit status $status after SIGTERM"
assert_detached "SIGTERM"
grep -q "^ruster-run-stats kind=final" "$work/forward.out" || fail "forward: no final stats"
grep -q "^af_xdp.ports=2$" "$work/forward.out" || fail "forward: no backend stats"
received=$(sed -n 's/^rx.received=//p' "$work/forward.out" | tail -n 1)
[ "${received:-0}" -ge 1 ] || fail "forward: final rx.received is ${received:-missing}"
grep -q "stopped by signal; .* tx-in-flight=0 .*detached and closed 2 port(s)" \
    "$work/forward.err" || fail "forward: no shutdown summary"
cat "$work/forward.err"
echo "priv_run_shutdown: SIGTERM exit 0, XDP detached, final counters (rx.received=$received) verified"

# ops: SIGHUP reload, a refused restart-required reload, and link down/up,
# all on one running router (M2 S10b).
cp "$work/router.toml" "$work/ops.toml"
# Rule 20 (LAN -> WAN UDP) denies instead of allowing.
sed '/protocol = "udp"/{n;s/action = "allow-stateful"/action = "deny"/;}' \
    "$work/router.toml" >"$work/deny.toml"
grep -q 'action = "deny"' "$work/deny.toml" || fail "ops: deny config not written"
# A different UMEM shape for lan: restart-required (BACKEND).
sed '0,/frame-count = 512/s//frame-count = 1024/' "$work/router.toml" >"$work/reshape.toml"
start_ruster ops "$work/ops.toml"
wait_ready ops || fail "ops: ruster exited during startup"
forward_once ops-before
reload_with "$work/deny.toml"
wait_line ops "reload applied: generation=2 previous=1"
forward_blocked ops-denied
reload_with "$work/router.toml"
wait_line ops "reload applied: generation=3 previous=2"
forward_once ops-allowed
echo "priv_run_reload: SIGHUP changed the firewall outcome twice without a restart verified"
reload_with "$work/reshape.toml"
wait_line ops "reload refused: code=RESTART_REQUIRED reasons=BACKEND; generation 3 keeps running"
forward_once ops-refused
reload_with "$work/router.toml"
wait_line ops "reload applied: generation=5 previous=3"
echo "priv_run_reload_refused: restart-required reload refused while traffic kept flowing verified"
sudo -n ip -n "$router" link set ra down
wait_line ops "warning: port=if1 health=LINK_DOWN"
sudo -n ip -n "$router" link set ra up
wait_line ops "recovered: port=if1 health=LINK_DOWN"
forward_once ops-link-up
echo "priv_run_link: link down/up on ra kept the router running and forwarding recovered verified"
# An MTU above what a 2048-byte frame holds (1778): fail closed, exit 1.
sudo -n ip -n "$router" link set rb mtu 3000
wait_exit ops
[ "$status" -eq 1 ] || fail "ops: exit status $status after the MTU change"
grep -q "fatal: port=if2 health=MTU_ABOVE_FRAME" "$work/ops.err" ||
    fail "ops: no MTU_ABOVE_FRAME"
grep -q "stopped after a fatal health event port=if2 code=MTU_ABOVE_FRAME; .*detached and closed 2 port(s)" \
    "$work/ops.err" || fail "ops: no fatal summary"
sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/ops.out" >"$work/ops.final"
grep -q "^reload.applied=3$" "$work/ops.final" || fail "ops: final reload.applied"
grep -q "^reload.refused=1$" "$work/ops.final" || fail "ops: final reload.refused"
grep -q "^reload.requested=4$" "$work/ops.final" || fail "ops: final reload.requested"
grep -q "^if1.watch.link_down_events=1$" "$work/ops.final" || fail "ops: final link counters"
assert_detached "the MTU fail-closed exit"
sudo -n ip -n "$router" link set rb mtu 1500
cat "$work/ops.err"
echo "priv_run_mtu: MTU above the frame bound failed closed with exit 1 and detached verified"

# rollback: the second port fails after the first one attached.
start_ruster bad-queue "$work/bad-queue.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "bad-queue: exit status $status"
grep -q "startup failed: stage=open port=if2 code=TX_QUEUE_CHECK/NO_TX_QUEUE" \
    "$work/bad-queue.err" || fail "bad-queue: wrong failure"
assert_detached "a failed open of the second port"
echo "priv_run_rollback: second-port open failure detached the first port verified"

python3 -I "$here/priv-xdp-foreign-elf.py" "$work/foreign.o"
sudo -n ip -n "$router" link set dev rb xdpgeneric obj "$work/foreign.o" sec xdp
foreign=$(xdp_on rb)
case $foreign in xdpgeneric\ [0-9]*) ;; *) fail "foreign program did not attach" ;; esac
start_ruster foreign "$work/router.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "foreign: exit status $status"
grep -q "startup failed: stage=attach port=if2 code=CREATE_LINK/EXISTING_PROGRAM" \
    "$work/foreign.err" || fail "foreign: wrong failure"
test -z "$(xdp_on ra)" || fail "foreign: XDP left attached on ra"
test "$(xdp_on rb)" = "$foreign" || fail "foreign: the foreign program changed"
sudo -n ip -n "$router" link set dev rb xdpgeneric off
assert_detached "removing the foreign program"
echo "priv_run_rollback: existing program refused, first port detached, foreign untouched verified"

# checks: XDP-063 refusals before attach.
start_ruster multi-queue "$work/multi-queue.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "multi-queue: exit status $status"
grep -q "startup failed: stage=checks port=if1 code=MULTI_QUEUE_DEVICE rx-queues=2" \
    "$work/multi-queue.err" || fail "multi-queue: wrong failure"
assert_detached "the multi-queue refusal"
sudo -n ip -n "$router" address add 10.99.0.1/24 dev ra
start_ruster kernel-ipv4 "$work/router.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "kernel-ipv4: exit status $status"
grep -q "startup failed: stage=checks port=if1 code=KERNEL_IPV4_ADDRESSES count=1" \
    "$work/kernel-ipv4.err" || fail "kernel-ipv4: wrong failure"
assert_detached "the kernel IPv4 refusal"
sudo -n ip -n "$router" address del 10.99.0.1/24 dev ra
sudo -n ip -n "$router" route add 10.98.0.0/16 dev ra
start_ruster kernel-route "$work/router.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "kernel-route: exit status $status"
grep -q "startup failed: stage=checks port=if1 code=KERNEL_IPV4_ROUTES count=1" \
    "$work/kernel-route.err" || fail "kernel-route: wrong failure"
assert_detached "the kernel route refusal"
sudo -n ip -n "$router" route del 10.98.0.0/16 dev ra
echo "priv_run_checks: multi-queue device, kernel IPv4 address, and kernel route refused before attach verified"
# Kernel forwarding in the router namespace: refused by default, warned
# and accepted with --allow-kernel-forwarding.
in_ns "$router" sysctl -qw net.ipv4.ip_forward=1
start_ruster forwarding "$work/router.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "forwarding: exit status $status"
grep -q "startup failed: stage=checks port=if1 code=KERNEL_FORWARDING_ENABLED scope=global" \
    "$work/forwarding.err" || fail "forwarding: wrong failure"
assert_detached "the kernel forwarding refusal"
start_ruster forwarding-allowed "$work/router.toml" --allow-kernel-forwarding
wait_ready forwarding-allowed || fail "forwarding-allowed: ruster exited during startup"
grep -q "warning: port=if1 IPV4_FORWARDING_ENABLED scope=global" "$work/forwarding-allowed.err" ||
    fail "forwarding-allowed: no warning"
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "forwarding-allowed: exit status $status"
assert_detached "the forwarding override run"
in_ns "$router" sysctl -qw net.ipv4.ip_forward=0
# Turned on while running: XDP still takes every frame, so a warning, no
# exit (an exit would detach and expose the ports); recovered when off;
# an exit while it is on warns about the detached ports.
start_ruster forwarding-runtime "$work/router.toml"
wait_ready forwarding-runtime || fail "forwarding-runtime: ruster exited during startup"
in_ns "$router" sysctl -qw net.ipv4.ip_forward=1
wait_line forwarding-runtime "warning: port=if1 health=KERNEL_FORWARDING_ENABLED"
forward_once forwarding-runtime-on
in_ns "$router" sysctl -qw net.ipv4.ip_forward=0
wait_line forwarding-runtime "recovered: port=if1 health=KERNEL_FORWARDING_ENABLED"
in_ns "$router" sysctl -qw net.ipv4.ip_forward=1
tries=0
while [ "$(grep -c "warning: port=if1 health=KERNEL_FORWARDING_ENABLED" "$work/forwarding-runtime.err")" -lt 2 ]; do
    launcher_alive || fail "forwarding-runtime: exited while forwarding was on"
    tries=$((tries + 1))
    [ "$tries" -le 200 ] || fail "forwarding-runtime: no second warning"
    sleep 0.05
done
signal_ruster TERM
wait_ruster
in_ns "$router" sysctl -qw net.ipv4.ip_forward=0
[ "$status" -eq 0 ] || fail "forwarding-runtime: exit status $status"
grep -q "warning: kernel forwarding is enabled; detached ports may be forwarded by the kernel" \
    "$work/forwarding-runtime.err" || fail "forwarding-runtime: no exit warning"
if grep -q "fatal:" "$work/forwarding-runtime.err"; then
    fail "forwarding-runtime: a fatal event"
fi
assert_detached "the run-time forwarding run"
echo "priv_run_forwarding: kernel forwarding refused at startup, accepted with the override, and only warned (forwarding kept, recovered, exit warning) when turned on while running verified"
# Per-port forwarding (conf/ra/forwarding) with the global switch off: the
# startup check and the run-time watch read the port's own sysctl, not
# only ip_forward (refused with scope=device; warned and recovered).
in_ns "$router" sysctl -qw net.ipv4.conf.ra.forwarding=1
[ "$(in_ns "$router" sysctl -n net.ipv4.ip_forward)" = 0 ] ||
    fail "forwarding-device: ip_forward is not 0"
start_ruster forwarding-device "$work/router.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "forwarding-device: exit status $status"
grep -q "startup failed: stage=checks port=if1 code=KERNEL_FORWARDING_ENABLED scope=device" \
    "$work/forwarding-device.err" || fail "forwarding-device: wrong failure"
assert_detached "the per-port forwarding refusal"
in_ns "$router" sysctl -qw net.ipv4.conf.ra.forwarding=0
start_ruster forwarding-device-runtime "$work/router.toml"
wait_ready forwarding-device-runtime || fail "forwarding-device-runtime: ruster exited during startup"
in_ns "$router" sysctl -qw net.ipv4.conf.ra.forwarding=1
[ "$(in_ns "$router" sysctl -n net.ipv4.ip_forward)" = 0 ] ||
    fail "forwarding-device-runtime: ip_forward is not 0"
wait_line forwarding-device-runtime "warning: port=if1 health=KERNEL_FORWARDING_ENABLED"
forward_once forwarding-device-on
in_ns "$router" sysctl -qw net.ipv4.conf.ra.forwarding=0
wait_line forwarding-device-runtime "recovered: port=if1 health=KERNEL_FORWARDING_ENABLED"
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "forwarding-device-runtime: exit status $status"
if grep -q "port=if2 health=KERNEL_FORWARDING_ENABLED" "$work/forwarding-device-runtime.err"; then
    fail "forwarding-device-runtime: rb warned for ra's sysctl"
fi
if grep -q "fatal:" "$work/forwarding-device-runtime.err"; then
    fail "forwarding-device-runtime: a fatal event"
fi
assert_detached "the run-time per-port forwarding run"
echo "priv_run_forwarding_device: conf/ra/forwarding=1 with ip_forward=0 refused at startup (scope=device), warned on if1 only and recovered while running verified"

# stuck: an undrained stdout must not keep the process alive.
mkfifo "$work/stuck.fifo"
# Open read-write so the FIFO has a reader that never reads.
exec 3<>"$work/stuck.fifo"
rm -f "$pidfile"
sudo -n sh -c 'echo $$ >"$1"; shift; exec ip netns exec "$@"' sh "$pidfile" \
    "$router" "$binary_path" run --stats-interval 1 --config "$work/router.toml" \
    >"$work/stuck.fifo" 2>"$work/stuck.err" &
launcher=$!
tries=0
while [ ! -s "$pidfile" ]; do
    tries=$((tries + 1))
    [ "$tries" -le 200 ] || fail "stuck: ruster did not start within 10 seconds"
    sleep 0.05
done
ruster_pid=$(tr -cd '0-9' <"$pidfile")
wait_ready stuck || fail "stuck: ruster exited during startup"
# About one stats block (>10 KiB) per second fills the 64 KiB pipe.
sleep 8
# Prove the pipe is really full (the writer thread is blocked, so the
# phase is not vacuous): queued bytes within one page of the capacity, and
# unchanged 1.5 s later while ruster keeps producing stats.
first=$(python3 -I -c "$PIPE_FILL" "$work/stuck.fifo") || fail "stuck: cannot read the FIFO fill"
sleep 1.5
second=$(python3 -I -c "$PIPE_FILL" "$work/stuck.fifo") || fail "stuck: cannot read the FIFO fill"
queued=${first% *}
capacity=${first#* }
[ "$queued" -gt 0 ] && [ $((queued + 4096)) -gt "$capacity" ] ||
    fail "stuck: stdout pipe not full ($queued of $capacity bytes queued)"
[ "$first" = "$second" ] || fail "stuck: stdout pipe still moving ($first, then $second)"
launcher_alive || fail "stuck: exited before SIGTERM"
echo "priv_run_stuck: stdout pipe full ($queued of $capacity bytes) and not draining"
signal_ruster TERM
tries=0
while launcher_alive; do
    tries=$((tries + 1))
    [ "$tries" -le 200 ] || fail "stuck: no exit within 10 seconds of SIGTERM"
    sleep 0.05
done
wait_ruster
exec 3<&-
[ "$status" -eq 0 ] || fail "stuck: exit status $status after SIGTERM"
assert_detached "SIGTERM with an undrained stdout"
echo "priv_run_stuck: undrained stdout, SIGTERM drained, detached, and exited in bounded time verified"

# restart: SIGKILL, auto-detach, bounded restart retry, forward again.
start_ruster killed "$work/router.toml"
wait_ready killed || fail "killed: ruster exited during startup"
signal_ruster KILL
wait_ruster
tries=0
while [ -n "$(xdp_on ra)$(xdp_on rb)" ]; do
    tries=$((tries + 1))
    [ "$tries" -le 100 ] || fail "links survived SIGKILL of their owner"
    sleep 0.02
done
echo "priv_run_kill: links auto-detached after SIGKILL verified"
attempt=0
while :; do
    attempt=$((attempt + 1))
    start_ruster restart "$work/router.toml"
    if wait_ready restart; then
        break
    fi
    wait_ruster
    # Only the transient deferred-release failures are retried, boundedly.
    if [ "$attempt" -lt 20 ] && [ "$status" -eq 1 ] &&
        grep -Eq "code=(BIND/BUSY|REGISTER_UMEM/MEMLOCK_LIMIT)" "$work/restart.err"; then
        assert_detached "a transient restart failure"
        sleep 0.1
        continue
    fi
    fail "restart: exit status $status on attempt $attempt"
done
forward_once restart
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "restart: exit status $status after SIGTERM"
assert_detached "the restarted router's SIGTERM"
grep -q "^ruster-run-stats kind=final" "$work/restart.out" || fail "restart: no final stats"
echo "priv_run_restart: restart after SIGKILL (attempts $attempt) forwarded and shut down verified"

# removal (last: it destroys ra/pa): deleting a port's veth inside the
# router namespace fails closed with exit 1 and leaves nothing attached.
attempt=0
while :; do
    attempt=$((attempt + 1))
    start_ruster removal "$work/router.toml"
    if wait_ready removal; then
        break
    fi
    wait_ruster
    [ "$attempt" -lt 20 ] || fail "removal: did not start"
    sleep 0.1
done
forward_once removal-before
sudo -n ip -n "$router" link del ra
wait_exit removal
[ "$status" -eq 1 ] || fail "removal: exit status $status after deleting ra"
grep -q "fatal: port=if1 health=DEVICE_REMOVED" "$work/removal.err" ||
    fail "removal: no DEVICE_REMOVED"
grep -q "stopped after a fatal health event port=if1 code=DEVICE_REMOVED; .*detached and closed 2 port(s)" \
    "$work/removal.err" || fail "removal: no fatal summary"
test -z "$(xdp_on rb)" || fail "removal: XDP left attached on rb"
if sudo -n ip -n "$router" link show dev ra >/dev/null 2>&1; then
    fail "removal: ra still exists"
fi
cat "$work/removal.err"
echo "priv_run_removal: deleted port device failed closed with exit 1, nothing left attached verified"

cleanup
trap - EXIT
for ns in "$router" "$host_a" "$host_b"; do
    if sudo -n ip netns list | grep -qx "$ns\( .*\)\{0,1\}"; then
        echo "priv-run-smoke: namespace $ns survived cleanup" >&2
        exit 1
    fi
done
echo "priv-run-smoke: ok (namespaces $router{,-a,-b} removed)"

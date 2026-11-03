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
#             firewall); SIGTERM; exit 0, no XDP left on ra/rb, final stats.
#             (H6) Every phase runs with the default privilege drop: here
#             every thread of the running router (/proc/<pid>/task/*/status)
#             shows CapInh/CapPrm/CapEff/CapAmb/CapBnd 0 and NoNewPrivs 1,
#             and the startup line and stats say privileges dropped.
#             (H8) Every phase also runs under the default seccomp filter
#             (--seccomp kill): wherever the threads are checked, every
#             thread shows Seccomp 2 and one filter more than this shell
#             (Seccomp_filters 1 on an unconfined host), and the startup
#             line and stats say seccomp mode=kill. (H11) And under the
#             default filesystem confinement (--fs-confine landlock): the
#             startup line says filesystem confined ... threads=5 and the
#             stats fs.confine=landlock fs.threads=5
#   fs        (H11, after privileges) the reload is the probe of what the
#             router can open (no test hook): with --user/--group, the
#             config atomically replaced by a symlink to a readable file
#             outside its directory fails with stage=read
#             code=PERMISSION_DENIED while forwarding goes on, and the same
#             file installed in the directory applies; as uid 0 (which owns
#             /etc/shadow) symlinks to /etc/shadow, /etc/passwd,
#             /proc/1/status, and /proc/<pid>/root/etc/shadow all fail with
#             PERMISSION_DENIED; with --fs-confine off the same reload
#             through /etc/passwd gets past the read (the control)
#   limits   (H3) a config with every runtime table at its production
#             limit (failure holds and ICMPv4 error actions 4096, every
#             other table 65536, NAT44 pool 1-65535, 63.94 MiB of storage) is
#             accepted by `validate`; one more failure hold (4097) is
#             refused by `validate` and `ruster run` (exit 2) although the
#             simulator's limits accept it as a sim document; `ruster run`
#             starts the maximal config, forwards and translates, and exits
#             0 on SIGTERM
#   ops       (M2 S10b) on one running router, started with --user/--group
#             as the invoking user (H6: every thread switched to that uid
#             and gid with no supplementary group and no capability, so the
#             reloads below read the config as that user): SIGHUP reload that turns the
#             LAN->WAN UDP rule into deny (the datagram stops arriving) and
#             back (it arrives again), generations 2 and 3, no restart; a
#             restart-required reload (UMEM shape) refused while traffic
#             keeps flowing; `ip link set ra down/up` inside the router
#             namespace warns and recovers with forwarding; then rb's MTU
#             raised beyond the 2048-byte frame bound: exit 1 after drain,
#             nothing left attached
#   privileges  (H6) the recommended config layout (runbook section 5):
#             a root-owned directory /run/ruster-smoke.XXXXXX (root:<gid>
#             0750, removed on every exit; a plain directory, nothing
#             network-related in the initial namespace) with the config
#             root:<gid> 0640. With the default drop as root (no --user),
#             again with --strict-config-perms, and with --user/--group
#             plus --strict-config-perms, a SIGHUP reload that swaps the
#             file in that directory applies (generation 2) and the
#             firewall then denies. After the drop root keeps uid 0 but no
#             capability: the smoke's own work directory (0700, owned by
#             the invoking user) is read at startup (still privileged) but
#             a SIGHUP reload from it fails with stage=read
#             code=PERMISSION_DENIED while forwarding goes on (no
#             CAP_DAC_OVERRIDE); with --keep-privileges every thread keeps
#             CAP_NET_ADMIN (NoNewPrivs 1: the seccomp filter sets it),
#             the same reload applies, and
#             the stats say privileges.state=kept; all exit 0 on SIGTERM
#             with nothing attached
#   validate  (gap fill) `ruster validate` on every config the smoke runs
#             (exit 0, af-xdp backend with 2 ports) and on an invalid one
#             (exit 2); `ruster plan` between the configs the smoke reloads
#             (reloadable vs restart-required BACKEND). The ops and icmp
#             phases then require the running router to do what plan said:
#             a reloadable plan is applied, a restart-required plan is
#             refused with the plan's reasons, and the invalid config is
#             refused on SIGHUP with the validate diagnostic (and by `run`)
#   icmp      (gap fill) router-generated ICMPv4 over AF_XDP, captured on
#             host A with a raw socket: Echo Reply from 192.168.1.1; Time
#             Exceeded (TTL 1), Destination Unreachable Port (ICMP-ERR: UDP
#             to the router's own 192.168.1.1, no port open), Destination
#             Unreachable Host (an on-link WAN
#             address that never answers ARP); a route miss is silent under
#             router-v1 (FIREWALL_ROUTE_UNAVAILABLE) and, after a SIGHUP
#             reload to router-v2 (rule 40, no egress), Destination
#             Unreachable Network (RFC 1812 5.2.7.1). Every error is checked
#             for type/code, outer source/TTL/TOS/checksums, and a quote that
#             is the whole original datagram with a valid header checksum
#   pmtu      (MTU1, RFC 1812 4.2.2.7/5.2.7.1, RFC 1191) rb and pb at MTU
#             1400: the default config (wan mtu 1500) is refused before
#             attach (MTU_BELOW_CONFIG mtu=1400 config=1500); with
#             `mtu = 1400` on both interfaces (warning MTU_BELOW_DEVICE for
#             ra at 1500 only) a 1500-byte DF UDP datagram from host A
#             (IP_PMTUDISC_DO) is answered with Fragmentation Needed (3/4,
#             Next-Hop MTU 1400, from 192.168.1.1, quoting 548 bytes of the
#             untranslated datagram), host A's kernel learns PMTU 1400 and
#             refuses the next 1500-byte send (EMSGSIZE), a 1400-byte DF
#             datagram reaches host B, and tracepath from host A discovers
#             pmtu 1400; the final counters show the drops and errors
#   df_clear  (MTU2 part A, NAT44-008, RFC 6864 5.3.1) host A sends, from a
#             raw socket, two DF-clear UDP datagrams with the same IPv4 ID
#             and one with DF set to host B through the NAT: host B's raw
#             socket sees all three translated (source 203.0.113.2), the
#             DF-clear ones still without DF and with consecutive generated
#             IDs, the DF one with the ID host A sent; every checksum valid
#   urpf      (URPF, RFC 1812 5.3.8, RFC 3704) `source-validation =
#             "strict"` on lan and wan: host A -> host B still forwards and
#             translates, host B's Echo Request to 203.0.113.2 is answered,
#             the same Echo from host B claiming the inside source
#             192.168.1.99 is silently dropped
#             (drop.IPV4_SOURCE_VALIDATION_FAILED, no reply); a SIGHUP
#             reload to `off` (generation 2) answers it again; exit 0
#   frag      (MTU2 part B, RFC 791 3.2, RFC 1812 4.2.2.7) rb and pb at
#             1400 and wan `mtu = 1400`: a 1500-byte DF-clear UDP datagram
#             from host A (IP_PMTUDISC_DONT) reaches host B as exactly two
#             fragments from 203.0.113.2 seen on pb with AF_PACKET (total
#             lengths 1396+124, offsets 0/172, MF 1/0, one ID, DF clear,
#             TTL 63, valid checksums) and is reassembled to the exact
#             payload; with `[fragmentation] enabled = false` it does not
#             arrive (drop.IPV4_FRAGMENTATION_REQUIRED). Then lan
#             `mtu = 1280` (MTU_BELOW_DEVICE for if1, ra at 1500): host
#             B's 1400-byte DF-clear reply to host A's NAT mapping
#             reaches host A as two fragments 203.0.113.1 -> 192.168.1.10
#             (1276+144, offsets 0/157) and is reassembled. The final
#             counters show fragmentation.fragmented =
#             consume.IPV4_FRAGMENTED, fragments = generated_fragments
#             tx_accepted, nothing dropped or incomplete
#   natfrag   (NAT-FRAG, RFC 4787 REQ-14) every device at 1500, firewall
#             on, default `[fragment-tracking]`: host B's 3000-byte DF-clear
#             UDP answer to host A's NAT mapping, fragmented by host B's
#             kernel, reaches host A translated (one inbound generated ID,
#             RFC 791 layout, TTL 63) and is reassembled to the exact
#             payload; host A's own fragments from a raw socket, sent last
#             first, are held and released by the router and reassembled by
#             host B (source 203.0.113.2, valid UDP checksum). Final counters:
#             fragment_tracking.held = consume.IPV4_FRAGMENT_HELD, released,
#             nothing refused. With `[fragment-tracking] mode = "refuse"` the
#             same fragments never arrive (drop.FIREWALL_FRAGMENT_UNSUPPORTED)
#   arphold   (ARP-HOLD, RFC 1122 2.3.2.2, RFC 1812 3.3.2) every neighbour
#             cache empty (a fresh router, host caches flushed): `ping -c1`
#             from host A to host B succeeds on the first try (the first
#             Echo Request is held while the router resolves host B and sent
#             on its ARP reply), and on another fresh router the first TCP
#             SYN to host B gets through with no retransmission (connect in
#             well under the 1 s initial RTO, tcpi_total_retrans 0); final
#             counters arp_hold.held = replayed = replay_sent = 1, no
#             NEIGHBOR_UNRESOLVED. With `[resolution.hold] enabled = false`
#             the single ping is lost (drop.NEIGHBOR_UNRESOLVED=1)
#   reload_carry  (RELOAD-CARRY, AF_XDP and again inside the afpacket phase
#             over AF_PACKET) a long-lived TCP connection and a UDP flow (a
#             fixed source port) from host A to host B through NAT44 keep
#             working, on the same socket and from the same public port,
#             across an applied SIGHUP reload that adds an unrelated firewall
#             rule (the reload line shows every family carried and no flow
#             revoked; `ruster plan` predicted carry with re-evaluation);
#             a second reload whose rules deny both revokes the two flows
#             (firewall-revoked=2) and neither passes afterwards
#   unsolicited_syn  (B3, RFC 5382 REQ-4) with a firewall rule that admits
#             new WAN -> LAN TCP flows to every destination, host B sends a
#             TCP SYN to a public port without a mapping: nothing for 6 s,
#             then exactly one ICMP Destination Unreachable Port Unreachable
#             (3/3) from 203.0.113.2 quoting the SYN; after a reloadable
#             SIGHUP to `unsolicited-syn-icmp = false`, nothing within 9 s;
#             after one back to router-v1's default-deny firewall (switch
#             on), nothing within 9 s either (REQ-4 a, counted as
#             unsolicited_syn_firewall_denied). Run with --user/--group so
#             the reloads can read the work files
#   exit_protection  (OPS-EXIT, after txfull) `[exit-protection]`: each
#             key is refused under the default drop (exit 2,
#             EXIT_FORWARDING_NEEDS_PRIVILEGES / EXIT_LINK_DOWN_NEEDS_PRIVILEGES);
#             with --keep-privileges (seccomp kill, Landlock) ra/rb
#             forwarding set to 1 (accepted with --allow-kernel-forwarding)
#             reads 0 after SIGTERM, and link-down sets ra and rb down at
#             exit (set up again after); exit 0.
#             Only the router namespace's links and sysctls are touched
#   txfull    (gap fill; run with --user/--group so its reload can read
#             the work file) the WAN TX ring (128 entries; 256 generated frames
#             so the ring, not the copy pool, is the bound) driven full:
#             `ip link set rb down` in the router namespace makes every TX
#             kick fail ENETDOWN, so the kernel consumes nothing; a burst
#             from host A fills the ring (tx_inflight=128, tx_ring_full and
#             tx_blocked counted, core tx_rejected). Held past
#             --tx-stall-fatal-secs 2 and --kick-errors-fatal-secs 2 with no
#             fatal (a down link holds TX by design and is LINK_DOWN, not
#             TX_STALL or KICK_ERRORS); observer.state=healthy and
#             watch.state=warning while held. `ip link set rb up`: the 128
#             held datagrams reach host B, forwarding recovers, and the final
#             counters add up (rx, TX submitted = completed, nothing in
#             flight, observer.state=healthy, watch.state=ok)
#   forwarding  ip_forward=1 in the router namespace is refused at startup
#             (KERNEL_FORWARDING_ENABLED), accepted with a warning under
#             --allow-kernel-forwarding, and only warned while running;
#             then conf/ra/forwarding=1 with ip_forward=0: refused at
#             startup with scope=device, warned on if1 (only) while
#             running and recovered when cleared (M2 S11)
#   afpacket  (AFPKT-015, after removal, which it follows by recreating
#             ra/pa) `ruster run` with `backend.kind = "af-packet"` (MTU2
#             part B: first the inbound run of the frag phase over
#             AF_PACKET, lan `mtu = 1280`, fragments in the lan TX ring): GRO on
#             ra, rb MTU 1400 (below the configured MTU), a kernel address
#             on rb, and a VLAN on ra are refused
#             (exit 1, no packet socket left); one router forwards with
#             NAT44, answers ICMP Echo, applies two reloads and refuses a
#             restart-required one, survives a carrier loss on rb and an
#             administrative down/up of ra (its pending socket error is
#             cleared: the idle wait keeps blocking instead of sleeping),
#             transmits every frame on ra/rb itself (none by the kernel),
#             and drains on SIGTERM (exit 0, both packet sockets closed);
#             enslaving rb to a bridge ends a second router with
#             KERNEL_UPPER_DEVICE, deleting rb a third with DEVICE_REMOVED
#             (exit 1 each), no packet socket left. Default drop, Landlock, seccomp kill.
#   removal   (last) `ip link del ra` inside the router namespace while
#             running: exit 1 (DEVICE_REMOVED), nothing left attached
#   rollback  a second port that fails to open (queue 1 of a one-queue
#             veth) or to attach (a foreign xdpgeneric program on rb):
#             exit 1 with the stage and port, nothing left attached on ra,
#             and the foreign program untouched
#   checks    a two-queue device, a kernel IPv4 address on the port, a
#             main-table route, a route in a policy-routing table (100),
#             and a multipath route with one nexthop on the port (table
#             101) are refused before attach (XDP-063)
#   ipv6      (H2) every phase runs with disable_ipv6=1 on ra/rb (the
#             recommended setup) except these. IPv6 on ra with only
#             link-local is refused (KERNEL_IPV6_ENABLED) and accepted with
#             warnings under --allow-kernel-ipv6; a global IPv6 address is
#             refused (KERNEL_IPV6_ADDRESSES, also under
#             --allow-kernel-forwarding) and accepted with warnings under
#             --allow-kernel-ipv6 (traffic forwarded, exit warning); an IPv6
#             route out of rb in table 200 is refused (KERNEL_IPV6_ROUTES,
#             port if2); net.ipv6.conf.all.forwarding=1 is refused
#             (KERNEL_IPV6_FORWARDING_ENABLED scope=global) but accepted
#             without a word with disable_ipv6=1 on both ports;
#             conf/ra/force_forwarding=1 is refused (scope=force; the step
#             says SKIPPED when the sysctl is absent, before Linux 6.17).
#             While running: disable_ipv6 flipped to 0, a global IPv6
#             address, force_forwarding, an IPv4 route in table 300, and
#             IPv6 forwarding each warn and recover (disable_ipv6=1 on ra
#             recovers if1 only), no fatal, exit warnings for rb
#   weakhost  an effective rp_filter=0 (the setup sets all.rp_filter=1),
#             also with arp_ignore=1, is refused at startup
#             (KERNEL_IPV4_WEAK_HOST, per port; CLI-079), accepted with the
#             warning IPV4_WEAK_HOST_EXPOSURE under --allow-ipv4-weak-host;
#             while running it only warns (with or without the override)
#             and recovers with rp_filter 2 or 1
#   mc_forwarding  an IPv4 multicast routing socket (MRT_INIT) makes
#             all/mc_forwarding=1: refused (scope=multicast), accepted with
#             --allow-kernel-forwarding, warned and recovered (SKIPPED with
#             the reason when MRT_INIT fails)
#   seccomp   (H8) --seccomp log: every thread filtered (Seccomp 2), the
#             log-mode warning, forwarding, an applied SIGHUP reload, a
#             link down/up, SIGTERM exit 0, and no seccomp record of the
#             ruster binary in the kernel log (dmesg; best effort: with
#             auditd running the records go to its log instead).
#             --seccomp off: no thread filtered (Seccomp 0), the warning,
#             seccomp.mode=off, forwarding, exit 0. A kill by the filter
#             cannot be provoked from outside (nothing reachable makes a
#             denied syscall, and there is no test hook in the binary;
#             the Rust test seccomp::tests::live kills a filtered child):
#             a SIGSYS sent to the running router stands in for it (the
#             kernel's seccomp kill is the same group exit by SIGSYS):
#             it dies by that signal and both links detach. At the end,
#             no seccomp kill of the ruster binary was logged during the
#             whole smoke (same best effort)
#   systemd   (H10) NOTIFY_SOCKET names a datagram socket in the work
#             directory (a python receiver stands in for systemd) and
#             WATCHDOG_USEC=400000; run as the invoking user under the
#             default --seccomp kill: READY=1 is the first notification,
#             after readiness; WATCHDOG=1 every 200 ms (6 to 14 in 2 s);
#             a reloadable SIGHUP sends RELOADING=1 with MONOTONIC_USEC
#             and then READY=1 with generation 2; SIGUSR1 prints a
#             kind=on-demand stats block (notify.* fields); SIGTERM sends
#             STOPPING=1 last; notify.sent equals the datagrams received
#   rename    (H10) `ip link set ra down` and `name rx` while running:
#             exit 1 (DEVICE_RENAMED), nothing left attached; renamed back
#   log_json  (OPS-LOG) `--log-format json` as the invoking user: forward,
#             a SIGHUP reload whose [health]/[watch] keys change the
#             thresholds and intervals (watch settings applied, generation
#             2), a reload whose merged thresholds disagree (fatal below
#             warning: reload failed stage=health, generation 2 keeps
#             running), forward again, SIGUSR1, SIGTERM (exit 0, detached);
#             python3 -I parses every stderr and stdout line as one JSON
#             object of schema ruster-run-log/v1 (pure ASCII, the keys in
#             order, a known event code, every stdout line a STATS object)
#   restart   SIGKILL a running router: the unpinned links auto-detach;
#             restart (bounded retry of the transient BIND/BUSY or
#             REGISTER_UMEM/MEMLOCK_LIMIT after teardown, XDP-045, in this
#             test only) and forward again, then SIGTERM, exit 0
#   workers   (H7) the link watcher and the reload worker are threads of
#             their own (ruster-watch, ruster-reload; every thread dropped
#             and switched to the invoking user,
#             threads=5). A ~0.9 MiB config (4000 routes, 2400 firewall
#             rules, a changed UMEM: restart-required) takes the reload
#             worker hundreds of milliseconds to read, validate, and plan in
#             this debug build; three SIGHUPs during a 500 pps ping flood
#             from host A to the router coalesce into two refused reloads
#             (reload.requested=2), and the flood loses no Echo and its
#             longest round trip stays far below the preparation time (before
#             H7 RX stopped for the whole preparation: a 128-entry RX ring
#             overflows within 0.3 s at that rate). Link rounds keep coming
#             (watch.link_rounds, no stale round); SIGTERM exits 0 with no
#             abandoned worker and nothing attached
#   announce  (ARP-033..ARP-039) RFC 5227 announcements, captured on pb
#             with an AF_PACKET (ETH_P_ARP) socket in host B: at startup
#             exactly 2 ARP Requests with sender = target = 203.0.113.2 from
#             02:00:00:00:00:02, broadcast, about 2 s apart; after rb
#             down/up (LINK_DOWN warned and recovered) 2 more; a conflicting
#             ARP Reply from host B claiming 203.0.113.2 warns
#             ARP_ADDRESS_CONFLICT (no address or MAC in the log), counts
#             arp_announce.conflicts=1 and if2.watch.arp_address_conflicts=1,
#             and is defended by exactly one announcement; with `[arp]
#             announce = false` nothing is announced; exit 0 each
#   idle      (H9) an idle router blocks in poll() on its port sockets: over
#             3 s without traffic the router thread (the main thread) wakes
#             at most 400 times per second (voluntary context switches;
#             about 100 at the default --idle-wait-ms 10, about 1000 before
#             H9 with its 1 ms sleeps) and ticks at most 400 times per
#             second (tick.ticks), most waits time out (idle.timed_out) and
#             none fails (idle.errors=0); then 5 single pings to the router,
#             each after 2 s of idle, are answered with a median round trip
#             of at most 1 ms (the pre-H9 worst-case wait alone; a router
#             whose wait a frame does not end answers after half of the
#             10 ms wait on average) and none above 10 ms, the router
#             receives them (rx.received grows by at least 5), and most
#             woke the wait (idle.woken grows by at least 3: a frame that
#             lands while the thread is between waits, in a tick or a stats
#             block, is taken by the next tick without a wake, which a
#             1500-ping run measured at about 0.2% of frames); exit 0
#   stuck     stdout on a FIFO that is held open but never read: the stats
#             blocks fill it (checked: queued bytes at capacity and not
#             moving), yet SIGTERM still drains, detaches, and the process
#             exits within 10 seconds with status 0 (#301 LN1)
set -eu

# RUSTER_REQUIRE_PRIV must be 1 or unset (empty counts as unset), as in
# priv-xdp-smoke.sh; this script has no skip path either way.
case ${RUSTER_REQUIRE_PRIV-} in
"" | 1) ;;
*)
    echo "priv-run-smoke: RUSTER_REQUIRE_PRIV must be 1 or unset" >&2
    exit 1
    ;;
esac

for tool in cargo ip sudo python3 od ethtool ps ping date; do
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
ruster_env=
launcher=
ruster_pid=
mroute=
etcdir=

# True only if `$1` is a live process running the built ruster binary.
is_ruster() {
    [ -n "$1" ] && [ "$(sudo -n readlink "/proc/$1/exe" 2>/dev/null)" = "$binary_path" ]
}

cleanup() {
    if [ -n "$mroute" ]; then
        kill "$mroute" 2>/dev/null || true
        wait "$mroute" 2>/dev/null || true
        mroute=
    fi
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
    case $etcdir in
    /run/ruster-smoke.*) sudo -n rm -rf -- "$etcdir" 2>/dev/null || true ;;
    esac
    etcdir=
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
# The recommended router namespace (runbook section 2): kernel IPv4
# forwarding off (refused by `ruster run` unless --allow-kernel-forwarding),
# IPv6 off on every port device (refused unless --allow-kernel-ipv6; the
# ipv6 phase turns it on where it tests that), IPv6 forwarding off, and
# all.rp_filter=1 (otherwise refused with KERNEL_IPV4_WEAK_HOST unless
# --allow-ipv4-weak-host; the weakhost phase tests that) and all.arp_ignore=1 (advice: no ARP replies
# for addresses the port does not hold).
in_ns "$router" sysctl -qw net.ipv4.ip_forward=0
in_ns "$router" sysctl -qw net.ipv6.conf.all.forwarding=0
in_ns "$router" sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.arp_ignore=1
for dev in ra rb rq rqp; do
    in_ns "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
done
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
    # $1 output, $2 lan device, $3 wan queue, $4 fixture (router-v1; a
    # name in fixtures/m1 or an absolute path), $5 wan generated frames (64)
    case ${4:-router-v1} in
    /*) fixture=$4 ;;
    *) fixture="$root/fixtures/m1/${4:-router-v1}.toml" ;;
    esac
    sed -e 's/device = "sim0"/device = "'"$2"'"/' -e 's/device = "sim1"/device = "rb"/' \
        "$fixture" >"$1"
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
generated-frames = ${5:-64}
EOF
}
write_config "$work/router.toml" ra 0
write_config "$work/bad-queue.toml" ra 1
write_config "$work/multi-queue.toml" rq 0
# router-v2: adds rule 40 (LAN UDP to any egress), so a UDP route miss
# yields Destination Unreachable (Network); reloadable from router-v1.
write_config "$work/router-v2.toml" ra 0 router-v2
# 256 WAN generated frames (frame-count 512 = fill 128 + tx 128 + 256):
# a cross-port forward is copied into an egress generated frame, so with
# more of those than TX entries the 128-entry TX ring is what fills.
write_config "$work/txfull.toml" ra 0 router-v1 256
# H3: every runtime table at its production limit (63.94 MiB of storage),
# without the fixture's own backend; and one more failure hold (above the
# production 4096, within the simulator's 65536), as af-xdp and as sim.
sed -e '/^\[backend\]$/,$d' -e 's/device = "rusternodev0"/device = "sim0"/' \
    -e 's/device = "rusternodev1"/device = "sim1"/' \
    "$root/fixtures/limits/router-production-max.toml" >"$work/max-base.toml"
write_config "$work/production-max.toml" ra 0 "$work/max-base.toml"
sed 's/^failure-holds = 4096$/failure-holds = 4097/' "$work/production-max.toml" \
    >"$work/production-above.toml"
sed '/^\[backend\]$/,$d' "$work/production-above.toml" >"$work/sim-above.toml"
# Invalid: a frame size AF_XDP does not support (validate exit 2).
sed 's/frame-size = 2048/frame-size = 1000/' "$work/router.toml" >"$work/invalid.toml"

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
# (`sh` execs `ip netns exec`, which execs ruster). Arguments after $2 are
# extra options.
start_ruster() {
    name=$1
    config=$2
    shift 2
    rm -f "$pidfile"
    # shellcheck disable=SC2086 # $ruster_env is a list of NAME=value words.
    sudo -n env $ruster_env sh -c 'echo $$ >"$1"; shift; exec ip netns exec "$@"' sh "$pidfile" \
        "$router" "$binary_path" run --stats-interval 1 "$@" --config "$config" \
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
    # $2: the translated source ("address port") pattern; default the
    # fixture's pool 40000-40015.
    pattern=${2:-"203.0.113.2 400[0-1][0-9]"}
    # shellcheck disable=SC2254 # $pattern is a pattern on purpose.
    case $source in
    $pattern) ;;
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

# Replaces the running router's config ($2, default ops.toml) atomically
# with $1 and sends SIGHUP.
reload_with() {
    target=${2:-$work/ops.toml}
    cp "$1" "$target.next"
    mv "$target.next" "$target"
    signal_ruster HUP
}

# Writes the last complete stats block of $work/$1.out to $work/$1.block.
latest_block() {
    awk '/^ruster-run-stats /{cur=""} {cur=cur $0 "\n"} /^end$/{last=cur} END{printf "%s", last}' \
        "$work/$1.out" >"$work/$1.block"
}

# Prints the value of the stats key $2 in the block file $1.
stat_in() {
    sed -n "s/^$2=//p" "$1" | tail -n 1
}

# Waits (10 s) until the latest complete stats block of $1 has the line $2.
wait_block() {
    tries=0
    while :; do
        latest_block "$1"
        grep -qxF -- "$2" "$work/$1.block" && return 0
        launcher_alive || fail "$1: exited while waiting for a block with $2"
        tries=$((tries + 1))
        [ "$tries" -le 100 ] || fail "$1: no stats block with $2 within 10 seconds"
        sleep 0.1
    done
}

# Waits (10 s) until the stats key $2 of $1's latest block is at least $3.
wait_stat_ge() {
    tries=0
    while :; do
        latest_block "$1"
        value=$(stat_in "$work/$1.block" "$2")
        [ "${value:-0}" -ge "$3" ] && return 0
        launcher_alive || fail "$1: exited while waiting for $2 >= $3"
        tries=$((tries + 1))
        [ "$tries" -le 100 ] || fail "$1: $2 is ${value:-missing}, not >= $3, after 10 seconds"
        sleep 0.1
    done
}

# Fails unless the block file $1 has every line given after it.
block_has() {
    file=$1
    shift
    for line in "$@"; do
        grep -qxF -- "$line" "$file" || fail "$file: no line $line"
    done
}

# The invoking user's ids: the identity the ops and icmp phases switch to
# (--user/--group), which can read the smoke's work files on reload.
smoke_uid=$(id -u)
smoke_gid=$(id -g)
[ "$smoke_uid" -ne 0 ] && [ "$smoke_gid" -ne 0 ] ||
    fail "run the smoke as a regular user (it uses sudo -n itself)"

# Prints the value of the row $2 of the status file text in $1, its
# fields separated by single spaces.
status_row() {
    printf '%s\n' "$1" | sed -n "s/^$2:[[:space:]]*//p" | tr -s '[:space:]' ' ' | sed 's/ $//'
}

# H7: the threads of the running ruster ($ruster_pid) are at least the
# router, the two output threads, the link watcher (ruster-watch), and the
# reload worker (ruster-reload). $1 names the phase, $2 the count.
assert_workers() {
    [ "$2" -ge 5 ] || fail "$1: only $2 thread(s)"
    for want in ruster-watch ruster-reload ruster-stdout ruster-stderr; do
        found=
        for task in $(sudo -n ls "/proc/$ruster_pid/task"); do
            [ "$(sudo -n cat "/proc/$ruster_pid/task/$task/comm")" = "$want" ] && found=1
        done
        [ -n "$found" ] || fail "$1: no thread $want"
    done
}

# H6: every thread of the running ruster ($ruster_pid) holds no
# capability (inheritable, permitted, effective, ambient, bounding) and
# has NoNewPrivs 1; with $2 = "<uid> <gid>" also that uid/gid in every
# field and no supplementary group. Sets `threads`. Covers the H7 worker
# threads (assert_workers) and (H8) the seccomp filter on every thread
# (assert_confined) unless $3 is "unconfined" (--seccomp off).
assert_dropped() {
    name=$1
    ids=${2-}
    filtered=${3-filtered}
    threads=0
    for task in $(sudo -n ls "/proc/$ruster_pid/task"); do
        st=$(sudo -n cat "/proc/$ruster_pid/task/$task/status") ||
            fail "$name: cannot read task $task"
        comm=$(status_row "$st" Name)
        for key in CapInh CapPrm CapEff CapAmb CapBnd; do
            value=$(status_row "$st" "$key")
            [ "$value" = 0000000000000000 ] ||
                fail "$name: thread $comm ($task) $key=$value after the drop"
        done
        [ "$(status_row "$st" NoNewPrivs)" = 1 ] ||
            fail "$name: thread $comm ($task) NoNewPrivs is not 1"
        if [ -n "$ids" ]; then
            set -- $ids
            uids=$(status_row "$st" Uid)
            gids=$(status_row "$st" Gid)
            [ "$uids" = "$1 $1 $1 $1" ] || fail "$name: thread $comm ($task) Uid $uids"
            [ "$gids" = "$2 $2 $2 $2" ] || fail "$name: thread $comm ($task) Gid $gids"
            [ -z "$(status_row "$st" Groups)" ] ||
                fail "$name: thread $comm ($task) kept supplementary groups"
        else
            [ "$(status_row "$st" Uid)" = "0 0 0 0" ] ||
                fail "$name: thread $comm ($task) changed uid without --user"
        fi
        threads=$((threads + 1))
    done
    assert_workers "$name" "$threads"
    [ "$filtered" = unconfined ] || assert_confined "$name"
}

# H8: every thread of the running ruster ($ruster_pid) runs under the
# seccomp filter ($2 = 1, the default) or under none ($2 = 0, --seccomp
# off): Seccomp 2 and one filter more than this shell, or this shell's
# Seccomp mode and filter count.
assert_confined() {
    name=$1
    want=${2:-1}
    count=0
    for task in $(sudo -n ls "/proc/$ruster_pid/task"); do
        st=$(sudo -n cat "/proc/$ruster_pid/task/$task/status") ||
            fail "$name: cannot read task $task"
        comm=$(status_row "$st" Name)
        mode=$(status_row "$st" Seccomp)
        filters=$(status_row "$st" Seccomp_filters)
        if [ "$want" = 1 ]; then
            [ "$mode" = 2 ] || fail "$name: thread $comm ($task) Seccomp=$mode, not 2"
            [ "$filters" = $((seccomp_base + 1)) ] ||
                fail "$name: thread $comm ($task) Seccomp_filters=$filters, not $((seccomp_base + 1))"
        else
            [ "$mode" = "$seccomp_mode_base" ] ||
                fail "$name: thread $comm ($task) Seccomp=$mode under --seccomp off"
            [ "$filters" = "$seccomp_base" ] ||
                fail "$name: thread $comm ($task) Seccomp_filters=$filters under --seccomp off"
        fi
        count=$((count + 1))
    done
    [ "$count" -ge 5 ] || fail "$name: only $count thread(s)"
}

# Number of seccomp records (`type=1326`) of the ruster binary in the
# kernel log so far; empty if the kernel log cannot be read.
seccomp_records() {
    log=$(sudo -n dmesg 2>/dev/null) || return 0
    printf '%s\n' "$log" | grep -F "type=1326" | grep -cF "exe=\"$binary_path\"" || true
}

# H6 --keep-privileges: every thread still has CAP_NET_ADMIN (bit 12)
# effective; NoNewPrivs is 1 (set for the seccomp filter, which also runs
# with --keep-privileges).
assert_kept() {
    name=$1
    threads=0
    for task in $(sudo -n ls "/proc/$ruster_pid/task"); do
        st=$(sudo -n cat "/proc/$ruster_pid/task/$task/status") ||
            fail "$name: cannot read task $task"
        eff=$(status_row "$st" CapEff)
        [ $((0x$eff >> 12 & 1)) -eq 1 ] || fail "$name: task $task CapEff=$eff without CAP_NET_ADMIN"
        [ "$(status_row "$st" NoNewPrivs)" = 1 ] || fail "$name: task $task NoNewPrivs not set"
        threads=$((threads + 1))
    done
    assert_workers "$name" "$threads"
    assert_confined "$name"
}

# The config of the workers phase (argv: base config, routes, rules): the
# base with that many extra routes (10.x.y.0/24 via the WAN gateway) and
# UDP deny rules, appended as further array-of-tables entries.
BIG_CONFIG='
import sys
out = [open(sys.argv[1]).read()]
for i in range(int(sys.argv[2])):
    out.append("[[routes]]\nprefix = \"10.%d.%d.0/24\"\negress = \"wan\"\nvia = \"203.0.113.1\"\n" % (i // 250, i % 250))
for i in range(int(sys.argv[3])):
    out.append(
        "[[firewall.rules]]\nid = %d\ningress = \"lan\"\negress = \"wan\"\n"
        "source = \"192.168.1.0/24\"\ndestination = \"10.%d.%d.1/32\"\n"
        "protocol = \"udp\"\naction = \"deny\"\n"
        "[firewall.rules.source-ports]\nfirst = 1\nlast = 65535\n"
        "[firewall.rules.destination-ports]\nfirst = 9\nlast = 9\n" % (1000 + i, i // 250, i % 250))
sys.stdout.write("\n".join(out))
'

# workers (H7): a large reload is prepared off the router thread while a
# ping flood is answered without loss, and SIGHUPs coalesce.
phase_workers() {
    # A changed LAN UMEM (frame-count) makes it restart-required: refused
    # only after the whole preparation, with no quiescence hold.
    sed '0,/frame-count = 512/s//frame-count = 1024/' "$work/router.toml" >"$work/big-base.toml"
    python3 -I -c "$BIG_CONFIG" "$work/big-base.toml" 4000 2400 >"$work/big.toml"
    big_bytes=$(wc -c <"$work/big.toml")
    [ "$big_bytes" -le 1048576 ] || fail "workers: the big config has $big_bytes bytes"
    status=0
    "$binary_path" validate "$work/big.toml" >"$work/validate-big.txt" 2>&1 || status=$?
    [ "$status" -eq 0 ] || fail "workers: validate exit status $status: $(cat "$work/validate-big.txt")"
    grep -q " routes=4003 .* firewall-rules=2403 " "$work/validate-big.txt" ||
        fail "workers: validate: $(cat "$work/validate-big.txt")"
    cp "$work/router.toml" "$work/workers.toml"
    # As the invoking user, who can read the work directory on reload.
    start_ruster workers "$work/workers.toml" --user "$smoke_uid" --group "$smoke_gid"
    wait_ready workers || fail "workers: ruster exited during startup"
    assert_dropped workers "$smoke_uid $smoke_gid"
    grep -qxF "ruster run: privileges dropped: threads=5 capabilities=none bounding-set=cleared no-new-privs=1 identity=switched" \
        "$work/workers.err" || fail "workers: no privilege drop line for 5 threads"
    # ARP and the echo path first.
    in_ns "$host_a" ping -n -q -c 3 -i 0.2 -W 2 192.168.1.1 >"$work/workers-warm.txt" 2>&1 ||
        fail "workers: the router does not answer ping: $(cat "$work/workers-warm.txt")"
    in_ns "$host_a" ping -n -q -c 3000 -i 0.002 -W 2 192.168.1.1 >"$work/workers-ping.txt" 2>&1 &
    pinger=$!
    sleep 0.5
    cp "$work/big.toml" "$work/workers.toml.next"
    mv "$work/workers.toml.next" "$work/workers.toml"
    started=$(date +%s%N)
    signal_ruster HUP
    # Two more while the first is prepared: they coalesce into one.
    wait_line workers "reload requested (generation 1)"
    grep -qF "reload refused" "$work/workers.err" &&
        fail "workers: the reload ended before the coalescing SIGHUPs"
    signal_ruster HUP
    signal_ruster HUP
    refused="reload refused: code=RESTART_REQUIRED reasons=BACKEND; generation 1 keeps running"
    wait_line workers "$refused"
    prepared_ms=$((($(date +%s%N) - started) / 1000000))
    kill -0 "$pinger" 2>/dev/null || fail "workers: the ping flood ended before the reload was prepared"
    tries=0
    while [ "$(grep -cF -- "$refused" "$work/workers.err")" -lt 2 ]; do
        launcher_alive || fail "workers: exited while waiting for the second reload"
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "workers: the coalesced reload never ended"
        sleep 0.05
    done
    kill -0 "$pinger" 2>/dev/null || fail "workers: the ping flood ended before the second reload"
    status=0
    wait "$pinger" || status=$?
    summary=$(cat "$work/workers-ping.txt")
    sent=$(printf '%s\n' "$summary" | sed -n 's/^\([0-9]*\) packets transmitted, \([0-9]*\) received.*/\1/p')
    got=$(printf '%s\n' "$summary" | sed -n 's/^\([0-9]*\) packets transmitted, \([0-9]*\) received.*/\2/p')
    # Whole milliseconds of the longest round trip (the integer part, so no
    # leading-zero arithmetic such as 0907).
    max_ms=$(printf '%s\n' "$summary" | sed -n 's|^rtt min/avg/max/mdev = [0-9.]*/[0-9.]*/\([0-9]*\)\.[0-9]*/.*|\1|p')
    [ -n "$sent" ] && [ -n "$got" ] && [ -n "$max_ms" ] || fail "workers: ping summary: $summary"
    [ "$prepared_ms" -ge 200 ] ||
        fail "workers: the reload was prepared in $prepared_ms ms; too fast to show a stall"
    [ "$got" -eq "$sent" ] || fail "workers: $got of $sent echoes answered during the reloads"
    [ "$max_ms" -lt 100 ] && [ "$max_ms" -lt $((prepared_ms / 4)) ] ||
        fail "workers: longest round trip $max_ms ms during a $prepared_ms ms preparation"
    wait_block workers watch.link_rounds_stale=0
    rounds=$(stat_in "$work/workers.block" watch.link_rounds)
    [ "${rounds:-0}" -ge 2 ] || fail "workers: watch.link_rounds=${rounds:-missing}"
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "workers: exit status $status after SIGTERM"
    assert_detached "the workers phase"
    ! grep -q "did not end within" "$work/workers.err" || fail "workers: a worker was abandoned"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/workers.out" >"$work/workers.final"
    block_has "$work/workers.final" reload.requested=2 reload.refused=2 reload.applied=0 \
        reload.failed=0 watch.link_rounds_stale=0 watch.state=ok privileges.threads=5
    echo "priv_run_workers: threads ruster-watch and ruster-reload present and dropped (threads=5); a $big_bytes-byte reload prepared for $prepared_ms ms off the router thread while $got of $sent pings (500 pps) were answered, longest round trip $max_ms ms; three SIGHUPs coalesced into two refused reloads; $rounds link rounds, none stale; exit 0, detached verified"
}

# Prints "<voluntary context switches> <utime+stime clock ticks>" of the
# router thread (the main thread: task id = pid) of the running ruster.
router_thread_usage() {
    st=$(sudo -n cat "/proc/$ruster_pid/task/$ruster_pid/status") ||
        fail "idle: cannot read the router thread status"
    switches=$(status_row "$st" voluntary_ctxt_switches)
    # Fields 14 and 15 of stat (after the parenthesized comm, which has no
    # space here: the router thread is named ruster).
    ticks=$(sudo -n cat "/proc/$ruster_pid/task/$ruster_pid/stat" | sed 's/^.*) //' |
        awk '{ print $12 + $13 }')
    echo "$switches $ticks"
}

phase_idle() {
    start_ruster idle "$work/router.toml"
    wait_ready idle || fail "idle: ruster exited during startup"
    [ "$(sudo -n cat "/proc/$ruster_pid/task/$ruster_pid/comm")" = ruster ] ||
        fail "idle: the main thread is not the router thread"
    in_ns "$host_a" ping -n -q -c 3 -i 0.2 -W 2 192.168.1.1 >"$work/idle-warm.txt" 2>&1 ||
        fail "idle: the router does not answer ping: $(cat "$work/idle-warm.txt")"
    # Settle, then 3 s without traffic between two stats blocks.
    sleep 1.5
    latest_block idle
    cp "$work/idle.block" "$work/idle-a.block"
    set -- $(router_thread_usage)
    switches_a=$1
    cpu_a=$2
    started=$(date +%s%N)
    sleep 3
    set -- $(router_thread_usage)
    switches_b=$1
    cpu_b=$2
    elapsed_ms=$((($(date +%s%N) - started) / 1000000))
    sleep 1.2
    latest_block idle
    cp "$work/idle.block" "$work/idle-b.block"
    uptime_a=$(sed -n 's/^ruster-run-stats kind=periodic uptime-ms=//p' "$work/idle-a.block")
    uptime_b=$(sed -n 's/^ruster-run-stats kind=periodic uptime-ms=//p' "$work/idle-b.block")
    [ -n "$uptime_a" ] && [ -n "$uptime_b" ] && [ "$uptime_b" -gt "$uptime_a" ] ||
        fail "idle: no two periodic blocks ($uptime_a, $uptime_b)"
    span=$((uptime_b - uptime_a))
    ticks=$(($(stat_in "$work/idle-b.block" tick.ticks) - $(stat_in "$work/idle-a.block" tick.ticks)))
    waits=$(($(stat_in "$work/idle-b.block" idle.waits) - $(stat_in "$work/idle-a.block" idle.waits)))
    timed_out=$(($(stat_in "$work/idle-b.block" idle.timed_out) - $(stat_in "$work/idle-a.block" idle.timed_out)))
    tick_rate=$((ticks * 1000 / span))
    wake_rate=$(((switches_b - switches_a) * 1000 / elapsed_ms))
    hz=$(getconf CLK_TCK)
    cpu_pct_x10=$(((cpu_b - cpu_a) * 1000 * 10 / hz / elapsed_ms))
    [ "$wake_rate" -le 400 ] ||
        fail "idle: the router thread woke $wake_rate times per second while idle"
    [ "$tick_rate" -le 400 ] || fail "idle: $tick_rate ticks per second while idle"
    [ "$waits" -ge $((span / 20)) ] || fail "idle: only $waits idle waits in $span ms"
    [ "$timed_out" -ge $((waits / 2)) ] || fail "idle: only $timed_out of $waits waits timed out"
    block_has "$work/idle-b.block" idle.max_wait_ms=10 idle.errors=0
    # First packet after idle: single pings, each after 2 s without
    # traffic, answered at once.
    woken_before=$(stat_in "$work/idle-b.block" idle.woken)
    received_before=$(stat_in "$work/idle-b.block" rx.received)
    rtts=
    for n in 1 2 3 4 5; do
        sleep 2
        in_ns "$host_a" ping -n -c 1 -W 2 192.168.1.1 >"$work/idle-ping-$n.txt" 2>&1 ||
            fail "idle: ping $n unanswered: $(cat "$work/idle-ping-$n.txt")"
        rtt=$(sed -n 's/.* time=\([0-9.]*\) ms.*/\1/p' "$work/idle-ping-$n.txt")
        [ -n "$rtt" ] || fail "idle: ping $n: $(cat "$work/idle-ping-$n.txt")"
        rtts="$rtts $rtt"
    done
    sorted=$(printf '%s\n' $rtts | sort -n)
    median=$(printf '%s\n' "$sorted" | sed -n 3p)
    max=$(printf '%s\n' "$sorted" | tail -n 1)
    awk -v m="$median" -v x="$max" 'BEGIN { exit !(m <= 1.0 && x < 10.0) }' ||
        fail "idle: round trips after 2 s idle:$rtts ms (median $median, max $max)"
    sleep 1.2
    latest_block idle
    woken_after=$(stat_in "$work/idle.block" idle.woken)
    received_after=$(stat_in "$work/idle.block" rx.received)
    # Each Echo Request reaches the router (more frames, such as host A's
    # ARP probes, may come too). Not each needs to end a wait: one that
    # arrives while the thread is between waits is taken by the next tick
    # without a wake. The round trips above are the property (a frame that
    # did not end the wait would wait out up to 10 ms); a majority of
    # wakes shows the frames, not the timeouts, ended the waits.
    [ "$received_after" -ge $((received_before + 5)) ] ||
        fail "idle: rx.received $received_before -> $received_after over 5 pings"
    woken=$((woken_after - woken_before))
    [ "$woken" -ge 3 ] ||
        fail "idle: idle.woken $woken_before -> $woken_after over 5 pings (rx.received $received_before -> $received_after)"
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "idle: exit status $status after SIGTERM"
    assert_detached "the idle phase"
    echo "priv_run_idle: idle for ${elapsed_ms} ms the router thread woke $wake_rate times/s (cpu $((cpu_pct_x10 / 10)).$((cpu_pct_x10 % 10))%), ticked $tick_rate times/s, $waits waits ($timed_out timed out) in $span ms; single pings after 2 s idle round trip$rtts ms (median $median); the waits woke $woken times (rx.received +$((received_after - received_before))); exit 0, detached verified"
}

# Host A's view of router-generated ICMPv4 (argv: mode target ttl marker
# deadline-seconds). Repeats the probe (an Echo Request on a raw socket, or
# a UDP datagram to port 9 with the given TTL) every 0.3 s and reads every
# ICMPv4 message host A receives on a raw socket, until one answers this
# probe (or, for `absent`, until the deadline, failing if one does). An
# error must come from the router's LAN address with
# ipv4-origin.default-ttl 64, TOS 0xc0 (RFC 1812 4.3.2.5), valid IPv4 and
# ICMP checksums, a zero unused field, and quote the whole datagram as sent
# (it is shorter than the 576-byte bound of RFC 1812 4.3.2.3).
ICMP_PROBE='
import os, socket, struct, sys, time

def fold(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total

def check(ok, what):
    if not ok:
        sys.exit("icmp probe %s: %s" % (mode, what))

mode, target, ttl, marker = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4].encode()
deadline = time.monotonic() + float(sys.argv[5])
router, host = socket.inet_aton("192.168.1.1"), socket.inet_aton("192.168.1.10")
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
raw.settimeout(0.1)
ident = os.getpid() & 0xFFFF
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
udp.bind(("0.0.0.0", 0))
sport = udp.getsockname()[1]

def send():
    if mode == "echo":
        body = struct.pack("!BBHHH", 8, 0, 0, ident, 1) + marker
        body = body[:2] + struct.pack("!H", 0xFFFF - fold(body)) + body[4:]
        raw.sendto(body, (target, 0))
    else:
        udp.sendto(marker, (target, 9))

def answer(pkt):
    icmp = pkt[(pkt[0] & 15) * 4:]
    if mode == "echo":
        if len(icmp) >= 8 and icmp[0] == 0 and struct.unpack("!H", icmp[4:6])[0] == ident:
            return icmp
        return None
    if len(icmp) < 36 or icmp[0] not in (3, 11):
        return None
    quote = icmp[8:]
    qihl = (quote[0] & 15) * 4
    if len(quote) < qihl + 4 or quote[16:20] != socket.inet_aton(target):
        return None
    if struct.unpack("!H", quote[qihl:qihl + 2])[0] != sport:
        return None
    return icmp

found = None
while found is None and time.monotonic() < deadline:
    send()
    end = time.monotonic() + 0.3
    while found is None and time.monotonic() < end:
        try:
            pkt = raw.recv(4096)
        except socket.timeout:
            continue
        icmp = answer(pkt)
        if icmp is not None:
            found = (pkt, icmp)
if mode == "absent":
    check(found is None, "an ICMPv4 error answered a datagram the router must drop silently")
    print("no ICMPv4 error for %s within %s s" % (target, sys.argv[5]))
    sys.exit(0)
check(found is not None, "no answer within %s s" % sys.argv[5])
pkt, icmp = found
ihl = (pkt[0] & 15) * 4
check(pkt[12:16] == router and pkt[16:20] == host, "outer addresses")
check(pkt[9] == 1 and fold(pkt[:ihl]) == 0xFFFF, "outer protocol or header checksum")
check(fold(icmp) == 0xFFFF, "ICMP checksum")
if mode == "echo":
    check(icmp[1] == 0 and icmp[6:8] == b"\0\x01" and icmp[8:] == marker, "echo code/sequence/payload")
    print("echo-reply type=0 code=0 from 192.168.1.1, identifier, sequence, and payload echoed")
    sys.exit(0)
want = {"time-exceeded": (11, 0), "net-unreachable": (3, 0), "host-unreachable": (3, 1),
        "port-unreachable": (3, 3)}[mode]
check((icmp[0], icmp[1]) == want, "type/code %d/%d" % (icmp[0], icmp[1]))
check(pkt[8] == 64, "outer TTL %d" % pkt[8])
check(pkt[1] == 0xC0, "outer TOS 0x%02x" % pkt[1])
check(icmp[4:8] == b"\0\0\0\0", "unused field")
quote = icmp[8:]
check(quote[0] == 0x45 and quote[12:16] == host and quote[9] == 17, "quoted IPv4 header")
check(quote[8] == ttl and fold(quote[:20]) == 0xFFFF, "quoted TTL or header checksum")
check(struct.unpack("!HH", quote[20:24]) == (sport, 9), "quoted UDP ports")
check(struct.unpack("!H", quote[2:4])[0] == 28 + len(marker) == len(quote), "quote length")
check(quote[28:] == marker, "quoted payload")
print("type=%d code=%d from 192.168.1.1 ttl=64 tos=0xc0, quoting the whole %d-byte datagram 192.168.1.10:%d -> %s:9 ttl=%d" % (icmp[0], icmp[1], len(quote), sport, target, ttl))
'

# Host A -> argv[1]:argv[2]: argv[3] datagrams "argv[4]-<n>", 2 ms apart.
BURST='
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for n in range(int(sys.argv[3])):
    s.sendto(("%s-%d" % (sys.argv[4], n)).encode(), (sys.argv[1], int(sys.argv[2])))
    time.sleep(0.002)
'

# Counts the distinct "argv[2]-<n>" datagrams on UDP port argv[1] until
# none arrives for argv[3] seconds.
COUNT='
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.settimeout(float(sys.argv[3]))
print("ready", flush=True)
seen = set()
try:
    while True:
        text = s.recv(2048).decode(errors="replace")
        if text.startswith(sys.argv[2] + "-"):
            seen.add(int(text.rsplit("-", 1)[1]))
except socket.timeout:
    pass
print(len(seen), flush=True)
'

# Runs one ICMP_PROBE from host A (mode, target, TTL, deadline seconds).
icmp_probe() {
    in_ns "$host_a" python3 -I -c "$ICMP_PROBE" "$1" "$2" "$3" "ruster-icmp-$1-$suffix" "$4" \
        >"$work/icmp-$1.txt" 2>&1 || fail "icmp: $(cat "$work/icmp-$1.txt")"
}

# Requires `ruster plan $work/$1.toml $work/$2.toml` to exit 0 with the
# verdict $3 and the restart-required reasons $4.
expect_plan() {
    out="$work/plan-$1-$2.txt"
    "$binary_path" plan "$work/$1.toml" "$work/$2.toml" >"$out" 2>&1 ||
        fail "plan: $1 -> $2 exit status $?: $(cat "$out")"
    grep -qx "plan: $3" "$out" || fail "plan: $1 -> $2 is not $3: $(cat "$out")"
    grep -qx "restart-required: $4" "$out" ||
        fail "plan: $1 -> $2 restart-required is not $4: $(cat "$out")"
}

# validate/plan: what the offline commands say about the smoke's configs.
# The ops and icmp phases then require the running router to agree.
# Rule 20 (LAN -> WAN UDP) denies instead of allowing.
sed '/protocol = "udp"/{n;s/action = "allow-stateful"/action = "deny"/;}' \
    "$work/router.toml" >"$work/deny.toml"
grep -q 'action = "deny"' "$work/deny.toml" || fail "validate: deny config not written"
# A different UMEM shape for lan: restart-required (BACKEND).
sed '0,/frame-count = 512/s//frame-count = 1024/' "$work/router.toml" >"$work/reshape.toml"
for config in router deny reshape router-v2 txfull bad-queue multi-queue; do
    status=0
    "$binary_path" validate "$work/$config.toml" >"$work/validate-$config.txt" 2>&1 || status=$?
    [ "$status" -eq 0 ] || fail "validate: $config.toml exit status $status: $(cat "$work/validate-$config.txt")"
    grep -q '^valid: schema-version=1 interfaces=2 .* backend=af-xdp ports=2 umem-bytes=[0-9]*$' \
        "$work/validate-$config.txt" || fail "validate: $config.toml: $(cat "$work/validate-$config.txt")"
done
grep -q " routes=4 .* firewall-rules=4 " "$work/validate-router-v2.txt" ||
    fail "validate: router-v2 counts: $(cat "$work/validate-router-v2.txt")"
status=0
"$binary_path" validate "$work/invalid.toml" >"$work/validate-invalid.txt" 2>&1 || status=$?
[ "$status" -eq 2 ] || fail "validate: invalid.toml exit status $status"
invalid_detail=$(sed -n 's/^ruster: invalid config: //p' "$work/validate-invalid.txt")
[ "$invalid_detail" = "stage=validate code=BACKEND_FRAME_SIZE_UNSUPPORTED path=backend.ports[0].frame-size" ] ||
    fail "validate: invalid.toml: $(cat "$work/validate-invalid.txt")"
# `ruster run` refuses the same config with the same diagnostic, before
# touching any port.
start_ruster invalid "$work/invalid.toml"
wait_ruster
[ "$status" -eq 2 ] || fail "invalid: run exit status $status"
grep -qxF "ruster: invalid config: $invalid_detail" "$work/invalid.err" ||
    fail "invalid: run diagnostic differs from validate"
assert_detached "the invalid config"
echo "priv_run_validate: 7 smoke configs valid (af-xdp, 2 ports), invalid frame size exit 2 from validate and run with the same diagnostic verified"
expect_plan router router reloadable none
grep -qx "changes: 0" "$work/plan-router-router.txt" || fail "plan: router -> router has changes"
expect_plan router deny reloadable none
expect_plan deny router reloadable none
expect_plan router reshape restart-required BACKEND
expect_plan reshape router restart-required BACKEND
expect_plan router router-v2 reloadable none
expect_plan router txfull restart-required BACKEND
status=0
"$binary_path" plan "$work/router.toml" "$work/invalid.toml" >"$work/plan-router-invalid.txt" 2>&1 ||
    status=$?
[ "$status" -eq 2 ] || fail "plan: router -> invalid exit status $status"
grep -qxF "ruster: invalid next config: $invalid_detail" "$work/plan-router-invalid.txt" ||
    fail "plan: router -> invalid: $(cat "$work/plan-router-invalid.txt")"
reshape_reasons=$(sed -n 's/^restart-required: //p' "$work/plan-router-reshape.txt")
echo "priv_run_plan: deny and router-v2 reloadable, reshape and txfull restart-required BACKEND, invalid next exit 2 verified"

# H8: the seccomp state this shell passes on to ruster (on an unconfined
# host Seccomp 0 with 0 filters; under a supervisor's filter ruster adds
# one on top).
seccomp_base=$(sed -n 's/^Seccomp_filters:[[:space:]]*//p' /proc/self/status)
seccomp_mode_base=$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/self/status)
case $seccomp_base in
"" | *[!0-9]*) fail "no Seccomp_filters row in /proc/self/status (Linux 5.9 or newer needed)" ;;
esac
seccomp_records_start=$(seccomp_records)

# forward: cold start, forward, SIGTERM.
start_ruster forward "$work/router.toml"
wait_ready forward || fail "forward: ruster exited during startup"
case $(xdp_on ra) in xdp\ [0-9]*) ;; *) fail "forward: no native XDP on ra" ;; esac
case $(xdp_on rb) in xdp\ [0-9]*) ;; *) fail "forward: no native XDP on rb" ;; esac
assert_dropped forward
grep -qxF "ruster run: privileges dropped: threads=5 capabilities=none bounding-set=cleared no-new-privs=1 identity=unchanged" \
    "$work/forward.err" || fail "forward: no privilege drop line"
grep -Eqx "ruster run: seccomp filter installed: mode=kill threads=5 syscalls=[0-9]+ arch=x86_64" \
    "$work/forward.err" || fail "forward: no seccomp line"
grep -Eqx "ruster run: filesystem confined: mode=landlock abi=[0-9]+ rules=4 threads=5" \
    "$work/forward.err" || fail "forward: no filesystem confinement line"
forward_once forward
echo "priv_run_seccomp_kill: all $threads threads Seccomp=2 Seccomp_filters=$((seccomp_base + 1)) under the default kill filter, forwarding verified"
echo "priv_run_privileges_dropped: all $threads threads CapInh/CapPrm/CapEff/CapAmb/CapBnd=0 NoNewPrivs=1 uid 0, forwarding after the drop verified"
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "forward: exit status $status after SIGTERM"
assert_detached "SIGTERM"
grep -q "^ruster-run-stats kind=final" "$work/forward.out" || fail "forward: no final stats"
grep -q "^af_xdp.ports=2$" "$work/forward.out" || fail "forward: no backend stats"
sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/forward.out" >"$work/forward.final"
block_has "$work/forward.final" observer.state=healthy observer.generation=1 watch.state=ok \
    resolution_index.state_probe_exhausted=0 resolution_index.index_corrupt=0 \
    privileges.state=dropped privileges.bounding_set=cleared privileges.identity=unchanged \
    privileges.threads=5 seccomp.mode=kill seccomp.threads=5 fs.confine=landlock fs.threads=5
received=$(sed -n 's/^rx.received=//p' "$work/forward.out" | tail -n 1)
[ "${received:-0}" -ge 1 ] || fail "forward: final rx.received is ${received:-missing}"
grep -q "stopped by signal; .* tx-in-flight=0 .*detached and closed 2 port(s)" \
    "$work/forward.err" || fail "forward: no shutdown summary"
cat "$work/forward.err"
echo "priv_run_shutdown: SIGTERM exit 0, XDP detached, final counters (rx.received=$received) verified"

phase_workers
phase_idle

# limits (H3): every table at its production limit runs; one slot above a
# quote table is refused by validate and run, not by the sim limits.
status=0
"$binary_path" validate "$work/production-max.toml" >"$work/validate-production-max.txt" 2>&1 || status=$?
[ "$status" -eq 0 ] || fail "limits: validate exit status $status: $(cat "$work/validate-production-max.txt")"
grep -q " storage-bytes=67050272 backend=af-xdp ports=2 " "$work/validate-production-max.txt" ||
    fail "limits: validate: $(cat "$work/validate-production-max.txt")"
above_detail="stage=validate code=CAPACITY_LIMIT_EXCEEDED path=resolution.capacity.failure-holds limit=4096 actual=4097"
status=0
"$binary_path" validate "$work/production-above.toml" >"$work/validate-production-above.txt" 2>&1 || status=$?
[ "$status" -eq 2 ] || fail "limits: validate of 4097 failure holds exit status $status"
grep -qxF "ruster: invalid config: $above_detail" "$work/validate-production-above.txt" ||
    fail "limits: validate: $(cat "$work/validate-production-above.txt")"
start_ruster limits-above "$work/production-above.toml"
wait_ruster
[ "$status" -eq 2 ] || fail "limits: run of 4097 failure holds exit status $status"
grep -qxF "ruster: invalid config: $above_detail" "$work/limits-above.err" ||
    fail "limits: run diagnostic: $(cat "$work/limits-above.err")"
assert_detached "the refused limits config"
status=0
"$binary_path" validate "$work/sim-above.toml" >"$work/validate-sim-above.txt" 2>&1 || status=$?
[ "$status" -eq 0 ] || fail "limits: sim validate exit status $status: $(cat "$work/validate-sim-above.txt")"
start_ruster limits "$work/production-max.toml"
wait_ready limits || fail "limits: ruster exited during startup: $(cat "$work/limits.err")"
forward_once limits "203.0.113.2 [1-9]*"
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "limits: exit status $status after SIGTERM"
assert_detached "the limits phase"
echo "priv_run_limits: every table at its production limit (storage 67050272 bytes) started, forwarded, and stopped with exit 0; 4097 failure holds refused by validate and run (exit 2, limit=4096), accepted as sim verified"

# ops: SIGHUP reload, a refused restart-required reload, and link down/up,
# all on one running router (M2 S10b).
# Each reload is the one `ruster plan` judged above: router -> deny and
# deny -> router reloadable (applied), router -> reshape restart-required
# with $reshape_reasons (refused with exactly those reasons).
cp "$work/router.toml" "$work/ops.toml"
start_ruster ops "$work/ops.toml" --user "$smoke_uid" --group "$smoke_gid"
wait_ready ops || fail "ops: ruster exited during startup"
assert_dropped ops "$smoke_uid $smoke_gid"
grep -qxF "ruster run: privileges dropped: threads=5 capabilities=none bounding-set=cleared no-new-privs=1 identity=switched" \
    "$work/ops.err" || fail "ops: no identity switch line"
echo "priv_run_privileges_identity: all $threads threads switched to the invoking uid/gid (real, effective, saved, fs) with no supplementary group, no capability, NoNewPrivs=1 verified"
forward_once ops-before
reload_with "$work/deny.toml"
wait_line ops "reload applied: generation=2 previous=1"
forward_blocked ops-denied
reload_with "$work/router.toml"
wait_line ops "reload applied: generation=3 previous=2"
forward_once ops-allowed
echo "priv_run_reload: SIGHUP changed the firewall outcome twice without a restart verified"
reload_with "$work/reshape.toml"
wait_line ops "reload refused: code=RESTART_REQUIRED reasons=$reshape_reasons; generation 3 keeps running"
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
block_has "$work/ops.final" privileges.state=dropped privileges.identity=switched
assert_detached "the MTU fail-closed exit"
sudo -n ip -n "$router" link set rb mtu 1500
cat "$work/ops.err"
echo "priv_run_mtu: MTU above the frame bound failed closed with exit 1 and detached verified"
echo "priv_run_privileges_runtime: after the drop and identity switch, three SIGHUP reloads applied and one refused, link down/up warned and recovered, the MTU event failed closed, drain and detach completed verified"

# privileges (H6): the recommended layout reloads under every drop mode.
etcdir=$(sudo -n mktemp -d /run/ruster-smoke.XXXXXX)
case $etcdir in
/run/ruster-smoke.*) ;;
*) fail "privileges: unexpected directory $etcdir" ;;
esac
sudo -n chown "root:$smoke_gid" "$etcdir"
sudo -n chmod 0750 "$etcdir"
# Installs $1 as $etcdir/router.toml (root:<gid> 0640) by an atomic swap.
install_etc() {
    sudo -n install -m 0640 -o root -g "$smoke_gid" "$1" "$etcdir/router.toml.next"
    sudo -n mv -f "$etcdir/router.toml.next" "$etcdir/router.toml"
}
for mode in default strict user-strict; do
    case $mode in
    default) set -- ;;
    strict) set -- --strict-config-perms ;;
    user-strict) set -- --strict-config-perms --user "$smoke_uid" --group "$smoke_gid" ;;
    esac
    name="etc-$mode"
    install_etc "$work/router.toml"
    start_ruster "$name" "$etcdir/router.toml" "$@"
    wait_ready "$name" || fail "$name: ruster exited during startup"
    if [ "$mode" = user-strict ]; then
        assert_dropped "$name" "$smoke_uid $smoke_gid"
        # Not dumpable after the switch: procfs reports root as the owner.
        [ "$(sudo -n stat -c %u "/proc/$ruster_pid/status")" = 0 ] ||
            fail "$name: the switched process is dumpable"
    else
        assert_dropped "$name"
    fi
    forward_once "$name-before"
    install_etc "$work/deny.toml"
    signal_ruster HUP
    wait_line "$name" "reload applied: generation=2 previous=1"
    forward_blocked "$name-denied"
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "$name: exit status $status after SIGTERM"
    assert_detached "the $name run"
done
set --
sudo -n rm -rf -- "$etcdir"
etcdir=
echo "priv_run_privileges_reload_dropped: a config root:<gid> 0640 in a root:<gid> 0750 directory reloaded (generation 2, firewall then denied) after the default drop as root, with --strict-config-perms, and with --user/--group plus --strict-config-perms (process not dumpable), exit 0, detached verified"
# What the drop takes from root: the work directory is 0700 and owned by
# the invoking user, so uid 0 without CAP_DAC_OVERRIDE cannot read it.
start_ruster drop-root "$work/router.toml"
wait_ready drop-root || fail "drop-root: ruster exited during startup"
assert_dropped drop-root
signal_ruster HUP
wait_line drop-root "reload failed: stage=read code=PERMISSION_DENIED; generation 1 keeps running"
forward_once drop-root
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "drop-root: exit status $status after SIGTERM"
assert_detached "the drop-root run"
echo "priv_run_privileges_no_dac_override: after the drop uid 0 could not reload a config in the 0700 work directory of another user (PERMISSION_DENIED, generation 1 kept, forwarding kept), exit 0, detached verified"
start_ruster keep "$work/router.toml" --keep-privileges
wait_ready keep || fail "keep: ruster exited during startup"
grep -qxF "ruster run: warning: privileges kept (--keep-privileges): every capability stays for the whole run" \
    "$work/keep.err" || fail "keep: no warning"
grep -q "privileges dropped" "$work/keep.err" && fail "keep: dropped anyway"
assert_kept keep
signal_ruster HUP
wait_line keep "reload applied: generation=2 previous=1"
forward_once keep
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "keep: exit status $status after SIGTERM"
assert_detached "the --keep-privileges run"
sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/keep.out" >"$work/keep.final"
block_has "$work/keep.final" privileges.state=kept privileges.threads=0
echo "priv_run_privileges_kept: --keep-privileges kept CAP_NET_ADMIN in all $threads threads (NoNewPrivs=1, Seccomp=2: the filter still applies), the same reload applied, privileges.state=kept, exit 0, detached verified"

# fs (H11): the Landlock view. Nothing in the binary reports what it can
# open (no test hook), so the SIGHUP reload, which opens the config path
# again on the reload worker thread, is the probe: the config is replaced
# (atomically) by a symlink to a file outside its directory that the
# router's user can read; a refused open is `stage=read
# code=PERMISSION_DENIED`, an allowed one gets past the read.
# Line number of the first line of $work/$1.err containing $2 (0: none).
line_of() {
    grep -nF -- "$2" "$work/$1.err" | head -n 1 | cut -d: -f1 | grep . || echo 0
}
# Waits (10 s) until $work/$1.err has more than $2 lines containing $3.
wait_count_above() {
    tries=0
    while [ "$(grep -cF -- "$3" "$work/$1.err" || true)" -le "$2" ]; do
        launcher_alive || fail "$1: exited while waiting for: $3"
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "$1: no new \"$3\" within 10 seconds"
        sleep 0.05
    done
}
phase_fs_confine() {
    # As the invoking user (who can read the work files): a symlink to the
    # readable $work/deny.toml next to the config directory is refused,
    # forwarding goes on; the same file copied into the directory (a new
    # inode, as an editor or installer writes it) applies.
    mkdir -p "$work/fsconf"
    cp "$work/router.toml" "$work/fsconf/router.toml"
    start_ruster fs-user "$work/fsconf/router.toml" --user "$smoke_uid" --group "$smoke_gid"
    wait_ready fs-user || fail "fs-user: ruster exited during startup"
    grep -Eqx "ruster run: filesystem confined: mode=landlock abi=[0-9]+ rules=4 threads=5" \
        "$work/fs-user.err" || fail "fs-user: no filesystem confinement line"
    fs_abi=$(sed -n 's/^ruster run: filesystem confined: mode=landlock abi=\([0-9]*\) .*/\1/p' "$work/fs-user.err")
    # The startup order: drop, filesystem, filter, readiness.
    at_drop=$(line_of fs-user "privileges dropped")
    at_fs=$(line_of fs-user "filesystem confined")
    at_filter=$(line_of fs-user "seccomp filter installed")
    at_ready=$(line_of fs-user "running generation")
    [ "$at_drop" -gt 0 ] && [ "$at_drop" -lt "$at_fs" ] && [ "$at_fs" -lt "$at_filter" ] &&
        [ "$at_filter" -lt "$at_ready" ] || fail "fs-user: startup lines out of order"
    ln -s "$work/deny.toml" "$work/fsconf/router.toml.next"
    mv -f "$work/fsconf/router.toml.next" "$work/fsconf/router.toml"
    signal_ruster HUP
    wait_line fs-user "reload failed: stage=read code=PERMISSION_DENIED; generation 1 keeps running"
    forward_once fs-user-outside
    reload_with "$work/deny.toml" "$work/fsconf/router.toml"
    wait_line fs-user "reload applied: generation=2 previous=1"
    forward_blocked fs-user-inside
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "fs-user: exit status $status after SIGTERM"
    assert_detached "the fs-user run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/fs-user.out" >"$work/fs-user.final"
    block_has "$work/fs-user.final" fs.confine=landlock "fs.abi=$fs_abi" fs.rules=4 fs.threads=5 \
        reload.applied=1 reload.failed=1
    echo "priv_run_fs_confine_user: Landlock ABI $fs_abi, all 5 threads confined (drop, filesystem, filter, readiness in that order); a SIGHUP through a symlink to a readable file outside the config directory failed with PERMISSION_DENIED while forwarding went on, the same file installed in the directory applied (generation 2); exit 0, detached verified"

    # As root (no --user): uid 0 owns /etc/shadow, which the drop alone
    # leaves readable. A root-owned config directory as in section 5.
    etcdir=$(sudo -n mktemp -d /run/ruster-smoke.XXXXXX)
    case $etcdir in
    /run/ruster-smoke.*) ;;
    *) fail "fs: unexpected directory $etcdir" ;;
    esac
    sudo -n chown "root:$smoke_gid" "$etcdir"
    sudo -n chmod 0750 "$etcdir"
    sudo -n test -r /etc/shadow || fail "fs: no /etc/shadow on this host"
    install_etc "$work/router.toml"
    start_ruster fs-root "$etcdir/router.toml"
    wait_ready fs-root || fail "fs-root: ruster exited during startup"
    assert_dropped fs-root
    grep -Eqx "ruster run: filesystem confined: mode=landlock abi=[0-9]+ rules=4 threads=5" \
        "$work/fs-root.err" || fail "fs-root: no filesystem confinement line"
    denied_line="reload failed: stage=read code=PERMISSION_DENIED; generation 1 keeps running"
    for secret in /etc/shadow /etc/passwd /proc/1/status "/proc/$ruster_pid/root/etc/shadow"; do
        before=$(grep -cF -- "$denied_line" "$work/fs-root.err" || true)
        # $etcdir/router.toml becomes a symlink to $secret (atomic swap).
        sudo -n ln -sfn "$secret" "$etcdir/router.toml.next"
        sudo -n mv -f "$etcdir/router.toml.next" "$etcdir/router.toml"
        signal_ruster HUP
        wait_count_above fs-root "$before" "$denied_line"
    done
    install_etc "$work/deny.toml"
    signal_ruster HUP
    wait_line fs-root "reload applied: generation=2 previous=1"
    forward_blocked fs-root-inside
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "fs-root: exit status $status after SIGTERM"
    assert_detached "the fs-root run"
    [ "$(grep -c "reload failed: " "$work/fs-root.err")" = 4 ] ||
        fail "fs-root: a reload through a refused file failed otherwise"
    echo "priv_run_fs_confine_root: as uid 0 without capabilities, SIGHUP reloads through symlinks to /etc/shadow, /etc/passwd, /proc/1/status, and /proc/<pid>/root/etc/shadow all failed with PERMISSION_DENIED, then a config in the directory applied (generation 2); exit 0, detached verified"

    # The control: --fs-confine off reads the same world-readable file
    # (/etc/passwd gets past the read and fails as a config).
    install_etc "$work/router.toml"
    start_ruster fs-off "$etcdir/router.toml" --fs-confine off
    wait_ready fs-off || fail "fs-off: ruster exited during startup"
    grep -qxF "ruster run: warning: fs-confine=off (--fs-confine off): no filesystem confinement; every file the process's user may read stays readable" \
        "$work/fs-off.err" || fail "fs-off: no warning"
    grep -q "filesystem confined" "$work/fs-off.err" && fail "fs-off: confined anyway"
    sudo -n ln -sfn /etc/passwd "$etcdir/router.toml.next"
    sudo -n mv -f "$etcdir/router.toml.next" "$etcdir/router.toml"
    signal_ruster HUP
    wait_line fs-off "reload failed: stage="
    grep -q "reload failed: stage=read" "$work/fs-off.err" &&
        fail "fs-off: /etc/passwd was not read without the confinement"
    forward_once fs-off
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "fs-off: exit status $status after SIGTERM"
    assert_detached "the fs-off run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/fs-off.out" >"$work/fs-off.final"
    block_has "$work/fs-off.final" fs.confine=off fs.abi=0 fs.rules=0 fs.threads=0
    sudo -n rm -rf -- "$etcdir"
    etcdir=
    passwd_stage=$(sed -n 's/.*reload failed: \(stage=[a-z-]*\).*/\1/p' "$work/fs-off.err" | head -n 1)
    echo "priv_run_fs_confine_off: --fs-confine off warned, confined nothing (fs.confine=off), and the same reload through a symlink to /etc/passwd got past the read ($passwd_stage); exit 0, detached verified"
}
phase_fs_confine

# icmp: router-generated ICMPv4 on the wire over AF_XDP, seen by host A.
cp "$work/router.toml" "$work/icmp.toml"
start_ruster icmp "$work/icmp.toml" --user "$smoke_uid" --group "$smoke_gid"
wait_ready icmp || fail "icmp: ruster exited during startup"
icmp_probe echo 192.168.1.1 64 10
echo "priv_run_icmp_echo: $(cat "$work/icmp-echo.txt") verified"
# ICMP-ERR: UDP to the router's own address (no UDP port is open) gets
# Port Unreachable (RFC 1812 5.2.7.1, RFC 1122 4.1.3.1).
icmp_probe port-unreachable 192.168.1.1 64 10
wait_stat_ge icmp drop.IPV4_LOCAL_UDP_PORT_UNREACHABLE 1
echo "priv_run_icmp_port_unreachable: $(cat "$work/icmp-port-unreachable.txt") verified"
icmp_probe time-exceeded 203.0.113.1 1 10
echo "priv_run_icmp_time_exceeded: $(cat "$work/icmp-time-exceeded.txt") verified"
# 203.0.113.99 is on-link on the WAN and never answers the router's ARP
# (3 attempts 1 s apart): the held datagram's Host Unreachable.
icmp_probe host-unreachable 203.0.113.99 64 15
echo "priv_run_icmp_host_unreachable: $(cat "$work/icmp-host-unreachable.txt") verified"
# No route to 10.255.0.1: router-v1's rules all name the egress "wan", so a
# route miss has no permitting rule and is dropped silently.
icmp_probe absent 10.255.0.1 64 2
wait_stat_ge icmp drop.FIREWALL_ROUTE_UNAVAILABLE 1
# SIGHUP with the invalid config: refused with validate's diagnostic.
reload_with "$work/invalid.toml" "$work/icmp.toml"
wait_line icmp "reload failed: $invalid_detail; generation 1 keeps running"
echo "priv_run_reload_invalid: SIGHUP with the config validate rejects failed with the same diagnostic, generation 1 kept verified"
# router-v2 (plan: reloadable): rule 40 permits the route miss, which now
# yields Destination Unreachable (Network).
reload_with "$work/router-v2.toml" "$work/icmp.toml"
wait_line icmp "reload applied: generation=2 previous=1; interfaces=2 addresses=2 routes=4 neighbors=1 firewall-rules=4 "
icmp_probe net-unreachable 10.255.0.1 64 10
echo "priv_run_icmp_net_unreachable: route miss silent under router-v1 (FIREWALL_ROUTE_UNAVAILABLE), then after the reloadable router-v2 reload $(cat "$work/icmp-net-unreachable.txt") verified"
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "icmp: exit status $status after SIGTERM"
assert_detached "the icmp run"
sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/icmp.out" >"$work/icmp.final"
block_has "$work/icmp.final" observer.state=healthy observer.generation=2 \
    generated_icmpv4.tx_rejected=0 if1.af_xdp_port.generated_inflight=0 \
    if1.af_xdp_port.tx_inflight=0
accepted=$(stat_in "$work/icmp.final" generated_icmpv4.tx_accepted)
[ "${accepted:-0}" -ge 3 ] || fail "icmp: generated_icmpv4.tx_accepted is ${accepted:-missing}"
committed=$(stat_in "$work/icmp.final" if1.af_xdp_port.generated_committed)
completed=$(stat_in "$work/icmp.final" if1.af_xdp_port.generated_completed)
[ "${committed:-x}" = "${completed:-y}" ] ||
    fail "icmp: if1 generated committed $committed, completed $completed"
cat "$work/icmp.err"
echo "priv_run_icmp: generated_icmpv4.tx_accepted=$accepted, if1 generated committed=completed=$completed, exit 0 verified"

# pmtu (MTU1): RFC 1812 4.2.2.7/5.2.7.1 and RFC 1191 Path MTU Discovery
# through the router over AF_XDP. The WAN link carries 1400 (rb, pb, and
# `mtu = 1400` of the wan interface). Host A sends DF UDP (IP_PMTUDISC_DO)
# to host B. argv: target, port, marker of the datagram that must fit,
# deadline seconds. The 1500-byte datagram must be answered by exactly
# the RFC layout: Destination Unreachable, Fragmentation Needed (3/4) from
# 192.168.1.1, TTL 64, TOS 0xc0, valid checksums, unused 16 bits zero and
# Next-Hop MTU 1400 (RFC 1191 4), quoting the first 548 bytes of the
# datagram as sent (before NAT; 576 bytes in all, RFC 1812 4.3.2.3); the
# kernel of host A must then hold PMTU 1400 for host B (IP_MTU of the
# connected socket) and refuse the 1500-byte send locally (EMSGSIZE); a
# 1400-byte DF datagram (exactly the MTU) is sent for host B to receive.
PMTU_PROBE='
import errno, socket, struct, sys, time

def fold(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total

def check(ok, what):
    if not ok:
        sys.exit("pmtu probe: %s" % what)

IP_MTU_DISCOVER, IP_PMTUDISC_DO, IP_MTU = 10, 2, 14
target, port, fit_marker = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
deadline = time.monotonic() + float(sys.argv[4])
router, host = socket.inet_aton("192.168.1.1"), socket.inet_aton("192.168.1.10")
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
raw.settimeout(0.1)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
udp.connect((target, port))
sport = udp.getsockname()[1]
check(udp.getsockopt(socket.IPPROTO_IP, IP_MTU) == 1500, "PMTU cache not flushed")
big = bytes((i * 7) & 0xFF for i in range(1472))
found = None
while found is None and time.monotonic() < deadline:
    try:
        udp.send(big)
    except OSError as error:
        check(error.errno == errno.EMSGSIZE, "send: %s" % error)
    end = time.monotonic() + 0.3
    while found is None and time.monotonic() < end:
        try:
            pkt = raw.recv(4096)
        except socket.timeout:
            continue
        icmp = pkt[(pkt[0] & 15) * 4:]
        if len(icmp) < 36 or (icmp[0], icmp[1]) != (3, 4):
            continue
        quote = icmp[8:]
        if quote[16:20] == socket.inet_aton(target) and struct.unpack("!H", quote[20:22])[0] == sport:
            found = (pkt, icmp)
check(found is not None, "no Fragmentation Needed within %s s" % sys.argv[4])
pkt, icmp = found
ihl = (pkt[0] & 15) * 4
check(pkt[12:16] == router and pkt[16:20] == host, "outer addresses")
check(pkt[9] == 1 and fold(pkt[:ihl]) == 0xFFFF, "outer protocol or header checksum")
check(pkt[8] == 64 and pkt[1] == 0xC0, "outer TTL %d or TOS 0x%02x" % (pkt[8], pkt[1]))
check(struct.unpack("!H", pkt[2:4])[0] == 576 == len(pkt), "outer length %d" % len(pkt))
check(fold(icmp) == 0xFFFF, "ICMP checksum")
check(icmp[4:6] == b"\0\0", "unused bits")
mtu = struct.unpack("!H", icmp[6:8])[0]
check(mtu == 1400, "Next-Hop MTU %d" % mtu)
quote = icmp[8:]
check(len(quote) == 548, "quote length %d" % len(quote))
check(quote[0] == 0x45 and quote[9] == 17 and quote[12:16] == host, "quoted IPv4 header")
check(struct.unpack("!H", quote[2:4])[0] == 1500, "quoted total length")
check(struct.unpack("!H", quote[6:8])[0] & 0x4000, "quoted DF")
check(fold(quote[:20]) == 0xFFFF, "quoted header checksum")
check(struct.unpack("!HH", quote[20:24]) == (sport, port), "quoted UDP ports (untranslated)")
check(quote[28:] == big[:520], "quoted payload")
learned = udp.getsockopt(socket.IPPROTO_IP, IP_MTU)
check(learned == 1400, "host A learned PMTU %d" % learned)
# Each Fragmentation Needed also leaves EMSGSIZE pending on the connected
# socket (reported by the next call); clear it so that the refusal below
# is the local PMTU check.
time.sleep(0.3)
udp.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
try:
    udp.send(big)
    check(False, "a 1500-byte DF send passed after PMTU 1400 was learned")
except OSError as error:
    check(error.errno == errno.EMSGSIZE, "send after PMTUD: %s" % error)
fit = fit_marker + bytes(1372 - len(fit_marker))
for _ in range(20):
    udp.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    udp.send(fit)
    time.sleep(0.05)
print("type=3 code=4 from 192.168.1.1 ttl=64 tos=0xc0 next-hop-mtu=1400, quoting 548 bytes of the 1500-byte DF datagram 192.168.1.10:%d -> %s:%d as sent (576 bytes in all); host A learned PMTU 1400 and refused a 1500-byte send (EMSGSIZE)" % (sport, target, port))
'

phase_pmtu() {
    sudo -n ip -n "$router" link set rb mtu 1400
    sudo -n ip -n "$host_b" link set pb mtu 1400
    # The configured MTU (1500 by default) above the device's: refused
    # before attach.
    start_ruster pmtu-refused "$work/router.toml"
    wait_ruster
    [ "$status" -eq 1 ] || fail "pmtu-refused: exit status $status"
    grep -q "startup failed: stage=checks port=if2 code=MTU_BELOW_CONFIG mtu=1400 config=1500" \
        "$work/pmtu-refused.err" || fail "pmtu-refused: wrong failure"
    assert_detached "the MTU_BELOW_CONFIG refusal"
    echo "priv_run_pmtu_refused: wan mtu 1500 (default) on a 1400-byte rb refused before attach (MTU_BELOW_CONFIG mtu=1400 config=1500), exit 1, detached verified"

    # wan at the link's 1400; lan at 1400 too, below ra's 1500: started
    # with the MTU_BELOW_DEVICE warning for if1 only.
    sed -e '/^mac = "02:00:00:00:00:02"$/a mtu = 1400' \
        -e '/^mac = "02:00:00:00:00:01"$/a mtu = 1400' "$work/router.toml" >"$work/pmtu.toml"
    [ "$(grep -cx "mtu = 1400" "$work/pmtu.toml")" -eq 2 ] || fail "pmtu: config edit"
    start_ruster pmtu "$work/pmtu.toml"
    wait_ready pmtu || fail "pmtu: ruster exited during startup"
    grep -q "warning: port=if1 MTU_BELOW_DEVICE mtu=1500 config=1400" "$work/pmtu.err" ||
        fail "pmtu: no MTU_BELOW_DEVICE warning for if1"
    ! grep -q "port=if2 MTU_BELOW_DEVICE" "$work/pmtu.err" ||
        fail "pmtu: MTU_BELOW_DEVICE warning for if2 at equal MTUs"
    in_ns "$host_a" ip route flush cache
    marker="ruster-pmtu-fit-$suffix"
    rm -f "$work/recv-pmtu.out"
    in_ns "$host_b" python3 -I -c "$RECEIVE" 9002 "$marker" 15 >"$work/recv-pmtu.out" 2>&1 &
    receiver=$!
    tries=0
    while ! grep -q ready "$work/recv-pmtu.out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "pmtu: receiver not ready"
        sleep 0.05
    done
    in_ns "$host_a" python3 -I -c "$PMTU_PROBE" 203.0.113.1 9002 "$marker" 10 \
        >"$work/pmtu-probe.txt" 2>&1 || fail "pmtu: $(cat "$work/pmtu-probe.txt")"
    status=0
    wait "$receiver" || status=$?
    [ "$status" -eq 0 ] || fail "pmtu: host B never received the 1400-byte DF datagram"
    echo "priv_run_pmtu_frag_needed: $(cat "$work/pmtu-probe.txt"); the 1400-byte DF datagram reached host B verified"

    # tracepath discovers the path MTU from scratch (cache flushed).
    in_ns "$host_a" ip route flush cache
    in_ns "$host_a" tracepath -n -m 4 -p 33500 203.0.113.1 >"$work/tracepath.txt" 2>&1 || true
    grep -q "pmtu 1400" "$work/tracepath.txt" ||
        fail "pmtu: tracepath did not discover PMTU 1400: $(cat "$work/tracepath.txt")"
    resume=$(grep "Resume:" "$work/tracepath.txt" || true)
    echo "priv_run_pmtu_tracepath: tracepath from host A discovered pmtu 1400 at 192.168.1.1 (${resume:-no resume line}) verified"

    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "pmtu: exit status $status after SIGTERM"
    assert_detached "the pmtu run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/pmtu.out" >"$work/pmtu.final"
    block_has "$work/pmtu.final" drop.IPV4_FRAGMENTATION_REQUIRED=0 \
        icmpv4_errors.disabled_fragmentation_needed=0 generated_icmpv4.tx_rejected=0
    # The first DF datagram is held while the router resolves host B (ARP-HOLD)
    # and refused for its MTU at replay: counted by the hold
    # (arp_hold.replay_dropped), not again under drop.*.
    needed=$(($(stat_in "$work/pmtu.final" drop.IPV4_FRAGMENTATION_NEEDED) + \
        $(stat_in "$work/pmtu.final" arp_hold.replay_dropped)))
    queued=$(stat_in "$work/pmtu.final" icmpv4_errors.queued_fragmentation_needed)
    sent=$(stat_in "$work/pmtu.final" icmpv4_errors.dequeued_fragmentation_needed)
    [ "${needed:-0}" -ge 2 ] || fail "pmtu: drop.IPV4_FRAGMENTATION_NEEDED + arp_hold.replay_dropped is ${needed:-missing}"
    [ "${queued:-0}" -ge 2 ] && [ "${queued:-0}" = "${sent:-x}" ] ||
        fail "pmtu: queued_fragmentation_needed $queued, dequeued $sent"
    sudo -n ip -n "$router" link set rb mtu 1500
    sudo -n ip -n "$host_b" link set pb mtu 1500
    echo "priv_run_pmtu: MTU_BELOW_DEVICE warned for if1 (ra 1500, config 1400) only; drop.IPV4_FRAGMENTATION_NEEDED + arp_hold.replay_dropped=$needed, queued_fragmentation_needed=dequeued=$queued, exit 0, detached verified"
}
phase_pmtu

# df_clear (MTU2 part A): NAT44 translates whole DF-clear datagrams
# (Windows sends unfragmented UDP without DF) and generates their IPv4 ID
# (RFC 6864 5.3.1). DF_CLEAR_SEND (host A, raw IP_HDRINCL socket) sends
# argv[3] copies of a DF-clear UDP datagram with ID 0x4242 and one with DF
# and ID 0x4343, source port argv[2], to host B port argv[1]. DF_CLEAR_RECV
# (host B, raw UDP socket, plus a bound UDP socket so that the kernel sends
# no Port Unreachable) checks the first two DF-clear arrivals and the DF
# one: source 203.0.113.2, valid IPv4 and UDP checksums, the payload as
# sent, DF clear with IDs n and n+1 (one translated tuple), and DF with ID
# 0x4343 (atomic: the ID is kept).
DF_CLEAR_SEND='
import socket, struct, sys

def fold(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total

dport, sport, copies = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
src, dst = socket.inet_aton("192.168.1.10"), socket.inet_aton("203.0.113.1")
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

def datagram(ident, flags, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = 0xFFFF - fold(src + dst + struct.pack("!BBH", 0, 17, len(udp)) + udp)
    udp = udp[:6] + struct.pack("!H", csum or 0xFFFF) + udp[8:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, flags, 64, 17, 0, src, dst)
    header = header[:10] + struct.pack("!H", 0xFFFF - fold(header)) + header[12:]
    return header + udp

for n in range(copies):
    raw.sendto(datagram(0x4242, 0, b"ruster-df-clear-%d" % n), ("203.0.113.1", 0))
raw.sendto(datagram(0x4343, 0x4000, b"ruster-df-set"), ("203.0.113.1", 0))
'
DF_CLEAR_RECV='
import socket, struct, sys, time

def fold(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total

def check(ok, what):
    if not ok:
        sys.exit("df_clear: %s" % what)

dport, deadline = int(sys.argv[1]), time.monotonic() + float(sys.argv[2])
public, me = socket.inet_aton("203.0.113.2"), socket.inet_aton("203.0.113.1")
sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sink.bind(("0.0.0.0", dport))
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
raw.settimeout(0.1)
print("ready", flush=True)
clear, kept = {}, None
while (len(clear) < 2 or kept is None) and time.monotonic() < deadline:
    try:
        pkt = raw.recv(4096)
    except socket.timeout:
        continue
    ihl = (pkt[0] & 15) * 4
    udp = pkt[ihl:]
    if len(udp) < 8 or struct.unpack("!H", udp[2:4])[0] != dport:
        continue
    check(pkt[12:16] == public and pkt[16:20] == me, "addresses %s" % pkt[12:20].hex())
    check(fold(pkt[:ihl]) == 0xFFFF, "IPv4 header checksum")
    check(fold(public + me + struct.pack("!BBH", 0, 17, len(udp)) + udp) == 0xFFFF, "UDP checksum")
    ident, flags = struct.unpack("!HH", pkt[4:8])
    payload = udp[8:]
    if payload == b"ruster-df-set":
        check(flags == 0x4000 and ident == 0x4343, "DF datagram flags 0x%04x id 0x%04x" % (flags, ident))
        kept = ident
    elif payload.startswith(b"ruster-df-clear-"):
        check(flags == 0, "DF-clear datagram arrived with flags 0x%04x" % flags)
        clear[int(payload[16:])] = ident
check(0 in clear and 1 in clear and kept is not None, "arrived: %s, DF one %s" % (clear, kept))
check(clear[1] == (clear[0] + 1) & 0xFFFF, "IDs 0x%04x, 0x%04x not consecutive" % (clear[0], clear[1]))
print("DF-clear UDP 192.168.1.10 -> 203.0.113.1:%d (host ID 0x4242 twice) arrived from 203.0.113.2 without DF with generated IDs 0x%04x, 0x%04x; the DF one kept ID 0x4343" % (dport, clear[0], clear[1]))
'

phase_df_clear() {
    start_ruster dfclear "$work/router.toml"
    wait_ready dfclear || fail "df_clear: ruster exited during startup"
    forward_once dfclear_resolve
    rm -f "$work/df-clear-recv.out"
    in_ns "$host_b" python3 -I -c "$DF_CLEAR_RECV" 9003 10 >"$work/df-clear-recv.out" 2>&1 &
    receiver=$!
    tries=0
    while ! grep -q ready "$work/df-clear-recv.out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "df_clear: receiver not ready"
        sleep 0.05
    done
    in_ns "$host_a" python3 -I -c "$DF_CLEAR_SEND" 9003 33200 2 >"$work/df-clear-send.out" 2>&1 ||
        fail "df_clear: send: $(cat "$work/df-clear-send.out")"
    status=0
    wait "$receiver" || status=$?
    [ "$status" -eq 0 ] || fail "$(cat "$work/df-clear-recv.out")"
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "df_clear: exit status $status after SIGTERM"
    assert_detached "the df_clear run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/dfclear.out" >"$work/dfclear.final"
    block_has "$work/dfclear.final" drop.NAT44_UDP_NON_ATOMIC_IPV4_UNSUPPORTED=0 \
        drop.FIREWALL_FRAGMENT_UNSUPPORTED=0
    echo "priv_run_df_clear: $(sed -n 2p "$work/df-clear-recv.out"), exit 0 verified"
}
phase_df_clear

# urpf (URPF): strict source validation on both ports. Host B gets the
# inside address 192.168.1.99/32 as a second source; its Echo Requests to
# the router's WAN address from that source arrive on the WAN with a
# source whose route leaves through the LAN.
phase_urpf() {
    sed '/^device = "r[ab]"$/a source-validation = "strict"' "$work/router.toml" \
        >"$work/urpf-strict.toml"
    [ "$(grep -c '^source-validation = "strict"$' "$work/urpf-strict.toml")" -eq 2 ] ||
        fail "urpf: strict config not written"
    expect_plan router urpf-strict reloadable none
    cp "$work/urpf-strict.toml" "$work/urpf.toml"
    sudo -n ip -n "$host_b" addr add 192.168.1.99/32 dev pb
    # As the invoking user, so the reload can read the work directory.
    start_ruster urpf "$work/urpf.toml" --user "$smoke_uid" --group "$smoke_gid"
    wait_ready urpf || fail "urpf: ruster exited during startup"
    forward_once urpf
    in_ns "$host_b" ping -c 1 -W 2 203.0.113.2 >"$work/urpf-ping.txt" 2>&1 ||
        fail "urpf: host B's own Echo was not answered: $(cat "$work/urpf-ping.txt")"
    if in_ns "$host_b" ping -c 2 -W 1 -I 192.168.1.99 203.0.113.2 >"$work/urpf-spoof.txt" 2>&1; then
        fail "urpf: an Echo from a spoofed inside source was answered"
    fi
    wait_stat_ge urpf drop.IPV4_SOURCE_VALIDATION_FAILED 2
    reload_with "$work/router.toml" "$work/urpf.toml"
    wait_line urpf "reload applied: generation=2 previous=1"
    in_ns "$host_b" ping -c 1 -W 2 -I 192.168.1.99 203.0.113.2 >"$work/urpf-off.txt" 2>&1 ||
        fail "urpf: with source-validation off the Echo was not answered: $(cat "$work/urpf-off.txt")"
    signal_ruster TERM
    wait_ruster
    sudo -n ip -n "$host_b" addr del 192.168.1.99/32 dev pb
    [ "$status" -eq 0 ] || fail "urpf: exit status $status after SIGTERM"
    assert_detached "the urpf run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/urpf.out" >"$work/urpf.final"
    dropped=$(stat_in "$work/urpf.final" drop.IPV4_SOURCE_VALIDATION_FAILED)
    [ "${dropped:-0}" -ge 2 ] || fail "urpf: final drop.IPV4_SOURCE_VALIDATION_FAILED=${dropped:-missing}"
    echo "priv_run_urpf: strict lan/wan forwards, answers host B, drops $dropped spoofed inside-source Echo(s) silently, reload to off answers them, exit 0 verified"
}
phase_urpf

# reload_carry (RELOAD-CARRY): a long-lived TCP connection and a UDP flow
# from host A to host B through the NAT survive an applied SIGHUP reload
# that adds an unrelated firewall rule (both on the same socket, the UDP
# flow from the same public port), and an applied reload whose rules deny
# both kills them (the carry revokes the two flows). Host A's clients do one
# exchange per step file $work/$name-step-<n>; host B echoes.
# The servers (argv: port, stop file) echo until the stop file exists. Both
# TCP ends close with SO_LINGER 0: one RST, no FIN retransmitted into later
# phases (the revoked flow cannot carry a FIN through the router).
CARRY_TCP_SERVER='
import os, socket, struct, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
s.settimeout(30)
print("ready", flush=True)
conn, peer = s.accept()
print(peer[0], peer[1], flush=True)
conn.settimeout(0.2)
while not os.path.exists(sys.argv[2]):
    try:
        data = conn.recv(4096)
        if not data:
            break
        conn.sendall(data)
    except socket.timeout:
        continue
    except OSError:
        break
conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
conn.close()
'
CARRY_UDP_SERVER='
import os, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.settimeout(0.2)
print("ready", flush=True)
while not os.path.exists(sys.argv[2]):
    try:
        data, peer = s.recvfrom(2048)
    except socket.timeout:
        continue
    print(peer[0], peer[1], flush=True)
    s.sendto(data, peer)
'
# argv: tcp|udp, server address, server port, step file prefix, steps.
# Prints "connected" (TCP) and then "ok <n>" or "fail <n>" per step; a
# failed step is not retried on the TCP connection (its data stays queued).
CARRY_CLIENT='
import os, socket, struct, sys, time
kind, address, port, prefix, steps = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
if kind == "tcp":
    s = socket.create_connection((address, port), timeout=10)
    print("connected", flush=True)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 5300))
for step in range(1, steps + 1):
    deadline = time.monotonic() + 60
    while not os.path.exists(prefix + str(step)):
        if time.monotonic() > deadline:
            print("timeout", step, flush=True)
            sys.exit(1)
        time.sleep(0.05)
    message = ("%s-%d" % (kind, step)).encode()
    ok = False
    if kind == "tcp":
        s.settimeout(3)
        try:
            s.sendall(message)
            got = b""
            while len(got) < len(message):
                chunk = s.recv(len(message) - len(got))
                if not chunk:
                    break
                got += chunk
            ok = got == message
        except OSError:
            ok = False
    else:
        s.settimeout(0.5)
        for _ in range(6):
            s.sendto(message, (address, port))
            try:
                data, _ = s.recvfrom(2048)
                if data == message:
                    ok = True
                    break
            except OSError:
                pass
    print("ok" if ok else "fail", step, flush=True)
if kind == "tcp":
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()
'

# Waits (15 s) until $1 has the exact line $2.
wait_file_line() {
    tries=0
    while ! grep -qxF -- "$2" "$1" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 300 ] || fail "no \"$2\" in $1: $(cat "$1" 2>/dev/null)"
        sleep 0.05
    done
}

# $1: phase name, $2: base config (the router-v1 fixture with a backend).
phase_reload_carry() {
    name=$1
    base=$2
    # The unrelated rule (TCP/25 deny) and the deny of both flows (TCP/9100
    # and UDP/9200), each inserted ahead of the UDP allow (rule 20).
    python3 -I -c '
import sys
base, out, rules = sys.argv[1], sys.argv[2], sys.argv[3:]
text = open(base).read()
anchor = "[[firewall.rules]]\nid = 20\n"
assert text.count(anchor) == 1
block = ""
for rule in rules:
    rule_id, protocol, port = rule.split(":")
    block += ("[[firewall.rules]]\nid = %s\ningress = \"lan\"\negress = \"wan\"\n"
              "source = \"192.168.1.0/24\"\ndestination = \"0.0.0.0/0\"\n"
              "protocol = \"%s\"\naction = \"deny\"\n\n"
              "[firewall.rules.source-ports]\nfirst = 0\nlast = 65535\n\n"
              "[firewall.rules.destination-ports]\nfirst = %s\nlast = %s\n\n"
              % (rule_id, protocol, port, port))
open(out, "w").write(text.replace(anchor, block + anchor))
' "$base" "$work/$name-rule.toml" 15:tcp:25 || fail "$name: rule config"
    python3 -I -c '
import sys
text = open(sys.argv[1]).read()
anchor = "[[firewall.rules]]\nid = 20\n"
deny = "".join(
    "[[firewall.rules]]\nid = %d\ningress = \"lan\"\negress = \"wan\"\n"
    "source = \"192.168.1.0/24\"\ndestination = \"0.0.0.0/0\"\n"
    "protocol = \"%s\"\naction = \"deny\"\n\n"
    "[firewall.rules.source-ports]\nfirst = 0\nlast = 65535\n\n"
    "[firewall.rules.destination-ports]\nfirst = %d\nlast = %d\n\n" % (i, p, port, port)
    for i, p, port in ((16, "tcp", 9100), (17, "udp", 9200)))
open(sys.argv[2], "w").write(text.replace(anchor, deny + anchor))
' "$work/$name-rule.toml" "$work/$name-deny.toml" || fail "$name: deny config"
    for config in rule deny; do
        status=0
        "$binary_path" validate "$work/$name-$config.toml" >"$work/$name-validate-$config.txt" 2>&1 ||
            status=$?
        [ "$status" -eq 0 ] || fail "$name: validate $config: $(cat "$work/$name-validate-$config.txt")"
    done
    status=0
    "$binary_path" plan "$base" "$work/$name-rule.toml" >"$work/$name-plan.txt" 2>&1 || status=$?
    [ "$status" -eq 0 ] || fail "$name: plan: $(cat "$work/$name-plan.txt")"
    for line in "state: carry" "  nat44-udp carried" "  nat44-tcp carried" \
        "  firewall carried reevaluate"; do
        grep -qxF -- "$line" "$work/$name-plan.txt" || fail "$name: plan lacks \"$line\": $(cat "$work/$name-plan.txt")"
    done

    # Host B answers this time (TCP and UDP from its own stack): full
    # checksums there too, as on host A (a veth leaves them partial).
    in_ns "$host_b" ethtool -K pb tx off >/dev/null
    cp "$base" "$work/$name-ops.toml"
    start_ruster "$name" "$work/$name-ops.toml" --user "$smoke_uid" --group "$smoke_gid"
    wait_ready "$name" || fail "$name: ruster exited during startup: $(cat "$work/$name.err")"
    rm -f "$work/$name"-step-* "$work/$name"-tcp-*.out "$work/$name"-udp-*.out "$work/$name-stop"
    in_ns "$host_b" python3 -I -c "$CARRY_TCP_SERVER" 9100 "$work/$name-stop" \
        >"$work/$name-tcp-server.out" 2>&1 &
    tcp_server=$!
    in_ns "$host_b" python3 -I -c "$CARRY_UDP_SERVER" 9200 "$work/$name-stop" \
        >"$work/$name-udp-server.out" 2>&1 &
    udp_server=$!
    wait_file_line "$work/$name-tcp-server.out" ready
    wait_file_line "$work/$name-udp-server.out" ready
    in_ns "$host_a" python3 -I -c "$CARRY_CLIENT" tcp 203.0.113.1 9100 "$work/$name-step-" 3 \
        >"$work/$name-tcp-client.out" 2>&1 &
    tcp_client=$!
    in_ns "$host_a" python3 -I -c "$CARRY_CLIENT" udp 203.0.113.1 9200 "$work/$name-step-" 3 \
        >"$work/$name-udp-client.out" 2>&1 &
    udp_client=$!
    wait_file_line "$work/$name-tcp-client.out" connected
    : >"$work/$name-step-1"
    wait_file_line "$work/$name-tcp-client.out" "ok 1"
    wait_file_line "$work/$name-udp-client.out" "ok 1"
    tcp_peer=$(sed -n 2p "$work/$name-tcp-server.out")
    case $tcp_peer in
    "203.0.113.2 "*) ;;
    *) fail "$name: TCP connection not translated by NAT44 (peer $tcp_peer)" ;;
    esac
    udp_peer=$(sed -n 2p "$work/$name-udp-server.out")
    case $udp_peer in
    "203.0.113.2 "*) ;;
    *) fail "$name: UDP flow not translated by NAT44 (peer $udp_peer)" ;;
    esac

    # An unrelated rule: every flow is re-evaluated and carried.
    reload_with "$work/$name-rule.toml" "$work/$name-ops.toml"
    wait_line "$name" "reload applied: generation=2 previous=1"
    applied=$(grep -F "reload applied: generation=2 previous=1" "$work/$name.err")
    for part in "nat44-udp-mappings=1 nat44-tcp-sessions=1 nat44-icmp-mappings=0 firewall-flows=2 firewall-revoked=0;" \
        "state arp=carried nat44-udp=carried nat44-tcp=carried nat44-icmp=none firewall=carried" \
        "flushed dynamic-neighbors=0 resolution-states=" \
        " nat44-udp-mappings=0 nat44-tcp-sessions=0 firewall-flows=0; carried dynamic-neighbors=1 "; do
        case $applied in
        *"$part"*) ;;
        *) fail "$name: reload line lacks \"$part\": $applied" ;;
        esac
    done
    : >"$work/$name-step-2"
    wait_file_line "$work/$name-tcp-client.out" "ok 2"
    wait_file_line "$work/$name-udp-client.out" "ok 2"
    [ "$(sed -n 2p "$work/$name-tcp-server.out")" = "$tcp_peer" ] || fail "$name: TCP peer changed"
    [ "$(tail -n 1 "$work/$name-udp-server.out")" = "$udp_peer" ] ||
        fail "$name: the UDP flow's public port changed: $udp_peer -> $(tail -n 1 "$work/$name-udp-server.out")"
    echo "priv_run_${name}_unrelated: the TCP connection ($tcp_peer) and the UDP flow ($udp_peer) survived a reload adding an unrelated firewall rule (generation 2, every family carried, no flow revoked) verified"

    # Rules that deny both flows: the carry revokes them at the apply.
    reload_with "$work/$name-deny.toml" "$work/$name-ops.toml"
    wait_line "$name" "reload applied: generation=3 previous=2"
    applied=$(grep -F "reload applied: generation=3 previous=2" "$work/$name.err")
    case $applied in
    *"firewall-flows=0 firewall-revoked=2; state arp=carried nat44-udp=carried nat44-tcp=carried nat44-icmp=none firewall=carried"*) ;;
    *) fail "$name: deny reload did not revoke both flows: $applied" ;;
    esac
    : >"$work/$name-step-3"
    wait_file_line "$work/$name-tcp-client.out" "fail 3"
    wait_file_line "$work/$name-udp-client.out" "fail 3"
    status=0
    wait "$tcp_client" || status=$?
    [ "$status" -eq 0 ] || fail "$name: TCP client: $(cat "$work/$name-tcp-client.out")"
    wait "$udp_client" || status=$?
    [ "$status" -eq 0 ] || fail "$name: UDP client: $(cat "$work/$name-udp-client.out")"
    : >"$work/$name-stop"
    status=0
    wait "$tcp_server" || status=$?
    [ "$status" -eq 0 ] || fail "$name: TCP server: $(cat "$work/$name-tcp-server.out")"
    wait "$udp_server" || status=$?
    [ "$status" -eq 0 ] || fail "$name: UDP server: $(cat "$work/$name-udp-server.out")"

    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "$name: exit status $status after SIGTERM: $(cat "$work/$name.err")"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/$name.out" >"$work/$name.final"
    block_has "$work/$name.final" observer.generation=3 firewall.states_revoked=2 \
        carried.firewall_flows_revoked=2 apply.state.firewall=carried
    echo "priv_run_${name}_deny: a reload denying both flows revoked them (generation 3, firewall-revoked=2) and neither the TCP connection nor the UDP flow passed afterwards, exit 0 verified"
}
phase_reload_carry carry "$work/router.toml"

# frag (MTU2 part B, RFC 791 3.2, RFC 1812 4.2.2.7): the router fragments
# forwarded DF-clear IPv4 datagrams above the egress MTU (after NAT44, so
# every fragment carries the one generated ID). Separate runs: outbound
# with the WAN at 1400 (rb, pb, wan `mtu = 1400`), the same with
# `[fragmentation] enabled = false`, and inbound with lan `mtu = 1280`
# (ra stays 1500: MTU_BELOW_DEVICE for if1). Separate runs keep each
# direction's MTUs simple; a slot holds max(largest interface MTU, 3826)
# bytes, so a 1500-byte datagram received above every configured MTU is
# fragmented too (crates/io-sim/tests/ipv4_fragmentation_tick.rs).
# FRAG_RECV: argv mode (expect|absent),
# capture interface, bound UDP port, IPv4 source and destination of the
# fragments, UDP source port range (first-last), egress MTU, payload
# length, marker, deadline seconds, and optionally a poke target address,
# port, and marker. It binds the UDP port, opens an AF_PACKET (ETH_P_IP)
# socket on the interface, prints ready, and pokes the target from the
# bound port every 0.2 s (creating the NAT mapping and firewall state).
# For `expect`, the UDP socket must receive exactly the payload
# (frag_payload of the marker and length), and every complete fragment
# set seen on the wire must be exactly the RFC 791 layout for the MTU
# (data per fragment the largest multiple of 8 that fits, MF on all but
# the last, offsets in 8-byte units), one ID, DF clear, TTL 63, valid
# header checksums, total lengths as on the wire, and the reassembled UDP
# datagram must carry the ports and a valid checksum. For `absent`,
# neither the payload nor any fragment may arrive before the deadline.
# FRAG_SEND: argv target, port, payload length, marker, stop file, and an
# optional reply marker; sends the payload DF-clear (IP_MTU_DISCOVER =
# IP_PMTUDISC_DONT) every 0.1 s (10 s at most) until the stop file
# exists, to the target, or (reply marker given) from the bound port to
# the source of the first datagram carrying the reply marker.
FRAG_PAYLOAD='
def frag_payload(marker, length):
    return marker + bytes((i * 7 + 3) & 0xFF for i in range(length - len(marker)))
'
FRAG_RECV="$FRAG_PAYLOAD"'
import socket, struct, sys, time

def fold(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total

def check(ok, what):
    if not ok:
        sys.exit("frag %s: %s" % (mode, what))

mode, iface, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
src, dst = socket.inet_aton(sys.argv[4]), socket.inet_aton(sys.argv[5])
sport_first, sport_last = (int(p) for p in sys.argv[6].split("-"))
mtu, length, marker = int(sys.argv[7]), int(sys.argv[8]), sys.argv[9].encode()
deadline = time.monotonic() + float(sys.argv[10])
poke = (sys.argv[11], int(sys.argv[12]), sys.argv[13].encode()) if len(sys.argv) > 13 else None
expected = frag_payload(marker, length)
per = (mtu - 20) // 8 * 8
layout, offset = [], 0
while offset < 8 + length:
    size = min(per, 8 + length - offset)
    layout.append((offset // 8, offset + size < 8 + length, size))
    offset += size
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("0.0.0.0", port))
udp.setblocking(False)
cap = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
cap.bind((iface, 0x0800))
cap.settimeout(0.05)
print("ready", flush=True)
sets, done, received, next_poke = {}, [], False, 0.0
while time.monotonic() < deadline and not (mode == "expect" and received and done):
    if poke is not None and time.monotonic() >= next_poke:
        udp.sendto(poke[2], poke[:2])
        next_poke = time.monotonic() + 0.2
    try:
        data = udp.recv(4096)
        check(mode == "expect", "the %d-byte payload arrived with fragmentation off" % len(data))
        if marker in data:
            check(data == expected, "reassembled payload differs (%d bytes)" % len(data))
            received = True
    except BlockingIOError:
        pass
    try:
        pkt, addr = cap.recvfrom(65535)
    except socket.timeout:
        continue
    if addr[2] == socket.PACKET_OUTGOING or len(pkt) < 20 or pkt[9] != 17:
        continue
    if pkt[12:16] != src or pkt[16:20] != dst:
        continue
    ident, flags = struct.unpack("!HH", pkt[4:8])
    if not flags & 0x3FFF:
        continue
    check(mode == "expect", "a fragment arrived with fragmentation off")
    check(pkt[0] == 0x45, "fragment version/IHL 0x%02x" % pkt[0])
    check(fold(pkt[:20]) == 0xFFFF, "fragment header checksum (id 0x%04x)" % ident)
    check(not flags & 0xC000, "fragment flags 0x%04x (reserved or DF set)" % flags)
    check(pkt[8] == 63, "fragment TTL %d" % pkt[8])
    total = struct.unpack("!H", pkt[2:4])[0]
    check(total == len(pkt), "fragment total length %d on a %d-byte packet" % (total, len(pkt)))
    frags = sets.setdefault(ident, {})
    frags[flags & 0x1FFF] = (bool(flags & 0x2000), pkt[20:])
    if len(frags) < len(layout) or ident in [d[0] for d in done]:
        continue
    seen = sorted((off, mf, len(body)) for off, (mf, body) in frags.items())
    check(seen == layout, "fragments of id 0x%04x %s, not %s" % (ident, seen, layout))
    whole = b"".join(frags[off][1] for off, _, _ in layout)
    sp, dp, ulen = struct.unpack("!HHH", whole[:6])
    check(sport_first <= sp <= sport_last and dp == port, "UDP ports %d -> %d" % (sp, dp))
    check(ulen == 8 + length and whole[8:] == expected, "reassembled UDP datagram")
    check(fold(src + dst + struct.pack("!BBH", 0, 17, ulen) + whole) == 0xFFFF, "UDP checksum")
    done.append((ident, sp, [20 + size for _, _, size in layout]))
if mode == "absent":
    print("neither the %d-byte DF-clear datagram nor a fragment of it reached %s within %s s" % (20 + 8 + length, sys.argv[5], sys.argv[10]))
    sys.exit(0)
check(received, "the %d-byte payload never arrived" % length)
check(done, "no complete fragment set on %s" % iface)
ident, sp, totals = done[0]
print("%d-byte DF-clear UDP %s:%d -> %s:%d arrived as %d fragments (id 0x%04x, total lengths %s, data %s, offsets %s, MF %s, DF clear, TTL 63, checksums valid; %d complete set(s), one ID each) and reassembled to the exact %d-byte payload" % (
    20 + 8 + length, sys.argv[4], sp, sys.argv[5], port, len(layout), ident,
    "+".join(map(str, totals)), "+".join(str(s) for _, _, s in layout),
    ",".join(str(o) for o, _, _ in layout), ",".join(str(int(m)) for _, m, _ in layout),
    len(done), length))
'
FRAG_SEND="$FRAG_PAYLOAD"'
import os, socket, sys, time
target, port, length = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
marker, stop = sys.argv[4].encode(), sys.argv[5]
reply = sys.argv[6].encode() if len(sys.argv) > 6 else None
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER = IP_PMTUDISC_DONT
s.settimeout(0.1)
if reply is not None:
    s.bind(("0.0.0.0", port))
print("ready", flush=True)
peer = None if reply is not None else (target, port)
deadline = time.monotonic() + 10
while time.monotonic() < deadline and not os.path.exists(stop):
    if peer is None:
        try:
            data, source = s.recvfrom(4096)
        except socket.timeout:
            continue
        if reply in data:
            peer = source
        continue
    s.sendto(frag_payload(marker, length), peer)
    time.sleep(0.1)
'

# Starts FRAG_RECV (output file $work/$1, then its argv) in the namespace
# $frag_ns and waits until it is ready; sets `frag_receiver`.
frag_receiver_start() {
    out="$work/$1"
    shift
    : >"$out"
    in_ns "$frag_ns" python3 -I -c "$FRAG_RECV" "$@" >"$out" 2>&1 &
    frag_receiver=$!
    tries=0
    while ! grep -q ready "$out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "frag: $out not ready: $(cat "$out")"
        sleep 0.05
    done
}

# Host A -> host B: the 1500-byte DF-clear datagram (1472-byte payload)
# to port 9004, captured on pb. $1 tag, $2 mode (expect|absent), $3
# deadline seconds.
frag_outbound() {
    rm -f "$stopfile"
    frag_ns=$host_b
    frag_receiver_start "frag-$1.out" "$2" pb 9004 203.0.113.2 203.0.113.1 40000-40015 \
        1400 1472 "ruster-frag-$1-$suffix" "$3"
    in_ns "$host_a" python3 -I -c "$FRAG_SEND" 203.0.113.1 9004 1472 \
        "ruster-frag-$1-$suffix" "$stopfile" >"$work/frag-send-$1.out" 2>&1 &
    sender=$!
    status=0
    wait "$frag_receiver" || status=$?
    : >"$stopfile"
    wait "$sender" || true
    [ "$status" -eq 0 ] || fail "$1: $(cat "$work/frag-$1.out")"
}

# Stops the run $1 with SIGTERM (exit 0, nothing attached), writes its
# final stats block to $work/$1.final, and checks the fragmentation
# counters: at least $2 datagrams fragmented into two fragments each,
# every one consumed as IPV4_FRAGMENTED and accepted by TX, nothing
# dropped, rejected, or left incomplete, and no fragment from a host
# (FIREWALL_FRAGMENT_UNSUPPORTED: the hosts send whole datagrams).
frag_stop() {
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "$1: exit status $status after SIGTERM"
    assert_detached "the $1 run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/$1.out" >"$work/$1.final"
    block_has "$work/$1.final" drop.IPV4_FRAGMENTATION_REQUIRED=0 \
        fragmentation.dropped_unavailable=0 fragmentation.dropped_frame_too_large=0 \
        fragmentation.incomplete=0 generated_fragments.tx_rejected=0 \
        drop.FIREWALL_FRAGMENT_UNSUPPORTED=0 drop.IPV4_FRAGMENTATION_DATAGRAM_TOO_LARGE=0
    fragmented=$(stat_in "$work/$1.final" fragmentation.fragmented)
    fragments=$(stat_in "$work/$1.final" fragmentation.fragments)
    consumed=$(stat_in "$work/$1.final" consume.IPV4_FRAGMENTED)
    accepted=$(stat_in "$work/$1.final" generated_fragments.tx_accepted)
    # Frames sent whole through the fragmentation slots (a datagram held for
    # ARP and replayed, ARP-HOLD) are generated fragment frames too.
    whole=$(stat_in "$work/$1.final" fragmentation.whole)
    [ "${fragmented:-0}" -ge "$2" ] ||
        fail "$1: fragmentation.fragmented is ${fragmented:-missing}"
    [ "${consumed:-x}" = "$fragmented" ] ||
        fail "$1: consume.IPV4_FRAGMENTED ${consumed:-missing}, fragmented $fragmented"
    [ "${fragments:-0}" -eq $((fragmented * 2)) ] && [ "${accepted:-x}" = $((fragments + ${whole:-0})) ] ||
        fail "$1: fragments ${fragments:-missing}, tx_accepted ${accepted:-missing}, whole ${whole:-missing}, fragmented $fragmented"
}

# Host B -> host A through the NAT toward lan `mtu = 1280`: host B answers
# a poke from host A port 33300 (NAT mapping and firewall state) with a
# 1400-byte DF-clear datagram (1372-byte payload) from port 9005; the
# router translates it back and fragments it; captured on pa. $1 tag.
frag_inbound() {
    # As for host A (setup): full UDP checksums from host B's socket, or
    # the router drops the reply (FIREWALL_UDP_CHECKSUM_INVALID).
    in_ns "$host_b" ethtool -K pb tx off >/dev/null
    rm -f "$stopfile"
    in_ns "$host_b" python3 -I -c "$FRAG_SEND" 0.0.0.0 9005 1372 \
        "ruster-$1-$suffix" "$stopfile" "ruster-$1-poke-$suffix" \
        >"$work/frag-send-$1.out" 2>&1 &
    sender=$!
    tries=0
    while ! grep -q ready "$work/frag-send-$1.out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "$1: host B replier not ready"
        sleep 0.05
    done
    frag_ns=$host_a
    frag_receiver_start "frag-recv-$1.out" expect pa 33300 203.0.113.1 192.168.1.10 9005-9005 \
        1280 1372 "ruster-$1-$suffix" 10 203.0.113.1 9005 "ruster-$1-poke-$suffix"
    status=0
    wait "$frag_receiver" || status=$?
    : >"$stopfile"
    wait "$sender" || true
    in_ns "$host_b" ethtool -K pb tx on >/dev/null
    [ "$status" -eq 0 ] || fail "$1: $(cat "$work/frag-recv-$1.out")"
}

phase_frag() {
    # Outbound: the WAN at 1400 (rb, pb, wan `mtu = 1400`), lan at its
    # default 1500.
    sudo -n ip -n "$router" link set rb mtu 1400
    sudo -n ip -n "$host_b" link set pb mtu 1400
    sed -e '/^mac = "02:00:00:00:00:02"$/a mtu = 1400' "$work/router.toml" >"$work/frag-out.toml"
    [ "$(grep -cx "mtu = 1400" "$work/frag-out.toml")" -eq 1 ] || fail "frag: config edit"
    printf '\n[fragmentation]\nenabled = false\n' |
        cat "$work/frag-out.toml" - >"$work/frag-off.toml"
    sed -e '/^mac = "02:00:00:00:00:01"$/a mtu = 1280' "$work/router.toml" >"$work/frag-in.toml"
    [ "$(grep -cx "mtu = 1280" "$work/frag-in.toml")" -eq 1 ] || fail "frag: config edit"
    # The pmtu phase left host A with a learned PMTU 1400 for host B, by
    # which its kernel would fragment the DF-clear datagram itself (the
    # router would then associate the fragments, NAT-FRAG, instead of
    # fragmenting). The hosts send whole datagrams at their device MTUs.
    in_ns "$host_a" ip route flush cache
    in_ns "$host_b" ip route flush cache
    start_ruster frag-out "$work/frag-out.toml"
    wait_ready frag-out || fail "frag-out: ruster exited during startup"
    ! grep -q "MTU_BELOW_DEVICE" "$work/frag-out.err" ||
        fail "frag-out: MTU_BELOW_DEVICE warning at equal MTUs"
    forward_once frag_out_resolve
    frag_outbound frag_out expect 10
    echo "priv_run_frag_outbound: $(sed -n 2p "$work/frag-frag_out.out") verified"
    frag_stop frag-out 1
    echo "priv_run_frag_outbound_stats: fragmentation.fragmented=consume.IPV4_FRAGMENTED=$fragmented, fragments=generated_fragments.tx_accepted=$fragments, nothing dropped or incomplete, exit 0, detached verified"

    # The off switch: the same outbound datagram is dropped
    # (IPV4_FRAGMENTATION_REQUIRED, the MTU1 behaviour).
    start_ruster frag-off "$work/frag-off.toml"
    wait_ready frag-off || fail "frag-off: ruster exited during startup"
    forward_once frag_off_resolve
    frag_outbound frag_off absent 3
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "frag-off: exit status $status after SIGTERM"
    assert_detached "the frag-off run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/frag-off.out" >"$work/frag-off.final"
    block_has "$work/frag-off.final" fragmentation.fragmented=0 consume.IPV4_FRAGMENTED=0 \
        drop.FIREWALL_FRAGMENT_UNSUPPORTED=0
    required=$(stat_in "$work/frag-off.final" drop.IPV4_FRAGMENTATION_REQUIRED)
    [ "${required:-0}" -ge 1 ] ||
        fail "frag-off: drop.IPV4_FRAGMENTATION_REQUIRED is ${required:-missing}"
    echo "priv_run_frag_off: with [fragmentation] enabled = false $(sed -n 2p "$work/frag-frag_off.out"); drop.IPV4_FRAGMENTATION_REQUIRED=$required, fragmentation.fragmented=0, exit 0, detached verified"
    sudo -n ip -n "$router" link set rb mtu 1500
    sudo -n ip -n "$host_b" link set pb mtu 1500

    # Inbound: lan `mtu = 1280` (ra stays 1500: MTU_BELOW_DEVICE for
    # if1), the WAN at 1500. Host B answers a poke from host A port 33300
    # (NAT mapping and firewall state) with a 1400-byte DF-clear datagram
    # (1372-byte payload) from port 9005; the router translates it back
    # and fragments it for lan's 1280; captured on pa.
    start_ruster frag-in "$work/frag-in.toml"
    wait_ready frag-in || fail "frag-in: ruster exited during startup"
    grep -q "warning: port=if1 MTU_BELOW_DEVICE mtu=1500 config=1280" "$work/frag-in.err" ||
        fail "frag-in: no MTU_BELOW_DEVICE warning for if1"
    forward_once frag_in_resolve
    frag_inbound frag-in
    echo "priv_run_frag_inbound: $(sed -n 2p "$work/frag-recv-frag-in.out") verified"
    frag_stop frag-in 1
    echo "priv_run_frag: MTU_BELOW_DEVICE warned for if1 (ra 1500, config 1280); inbound fragmentation.fragmented=consume.IPV4_FRAGMENTED=$fragmented, fragments=generated_fragments.tx_accepted=$fragments, nothing dropped or incomplete, drop.IPV4_FRAGMENTATION_REQUIRED=0, exit 0, detached verified"
}
phase_frag

# natfrag (NAT-FRAG, RFC 4787 REQ-14, RFC 1858): fragments of one datagram
# through the stateful firewall and the NAT, every device at 1500 and the
# fixture's default `[fragment-tracking]` (associate). Inbound: host B's
# 3000-byte DF-clear UDP answer to host A's NAT mapping is fragmented by
# host B's kernel (1480 + 1480 + 48 data bytes), each fragment follows the
# first fragment's translation, and host A's kernel reassembles the exact
# payload. Outbound out of order: host A sends its own fragments from a raw
# socket (IP_HDRINCL; no netem, nothing outside the namespaces), the last
# first and the first last, so the router holds two fragments per datagram
# until the first one decides; host B reassembles the exact payload.
# A separate run with `[fragment-tracking] mode = "refuse"` (the hardening
# switch) drops every fragment (FIREWALL_FRAGMENT_UNSUPPORTED).
# NATFRAG_RAW: argv source, destination, source port, destination port,
# payload length, marker, stop file, fragment order (e.g. 2,1,0); sends the
# UDP datagram (frag_payload, valid UDP checksum) as 1480-byte RFC 791
# fragments in that order, a new ID every 0.2 s (10 s at most) until the
# stop file exists.
NATFRAG_RAW="$FRAG_PAYLOAD"'
import os, socket, struct, sys, time

def fold(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total

src, dst = socket.inet_aton(sys.argv[1]), socket.inet_aton(sys.argv[2])
sport, dport, length = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
marker, stop = sys.argv[6].encode(), sys.argv[7]
order = [int(i) for i in sys.argv[8].split(",")]
ulen = 8 + length
udp = struct.pack("!HHHH", sport, dport, ulen, 0) + frag_payload(marker, length)
check = (~fold(src + dst + struct.pack("!BBH", 0, 17, ulen) + udp)) & 0xFFFF or 0xFFFF
udp = udp[:6] + struct.pack("!H", check) + udp[8:]
pieces, offset = [], 0
while offset < ulen:
    size = min(1480, ulen - offset)
    pieces.append((offset, offset + size < ulen, udp[offset:offset + size]))
    offset += size
assert sorted(order) == list(range(len(pieces)))
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
print("ready", flush=True)
ident = 0x5100
deadline = time.monotonic() + 10
while time.monotonic() < deadline and not os.path.exists(stop):
    ident += 1
    for index in order:
        off, more, body = pieces[index]
        word = (0x2000 if more else 0) | off // 8
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, word, 64, 17, 0, src, dst)
        header = header[:10] + struct.pack("!H", (~fold(header)) & 0xFFFF) + header[12:]
        s.sendto(header + body, (sys.argv[2], 0))
    time.sleep(0.2)
'

# Stops the run $1 (exit 0, nothing attached) and writes its final stats
# block to $work/$1.final.
natfrag_stop() {
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "$1: exit status $status after SIGTERM"
    assert_detached "the $1 run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/$1.out" >"$work/$1.final"
}

phase_natfrag() {
    printf '\n[fragment-tracking]\nmode = "refuse"\n' |
        cat "$work/router.toml" - >"$work/natfrag-refuse.toml"
    # Hosts send at their device MTUs (1500); no learned PMTU from the
    # earlier phases.
    in_ns "$host_a" ip route flush cache
    in_ns "$host_b" ip route flush cache
    start_ruster natfrag "$work/router.toml"
    wait_ready natfrag || fail "natfrag: ruster exited during startup"
    forward_once natfrag_resolve

    # Inbound, fragmented by host B's kernel (IP_PMTUDISC_DONT, 3008-byte
    # UDP datagram over pb's 1500): host A pokes from port 33310 (NAT
    # mapping and firewall state), host B answers from port 9006.
    in_ns "$host_b" ethtool -K pb tx off >/dev/null
    rm -f "$stopfile"
    in_ns "$host_b" python3 -I -c "$FRAG_SEND" 0.0.0.0 9006 2972 \
        "ruster-natfrag-in-$suffix" "$stopfile" "ruster-natfrag-poke-$suffix" \
        >"$work/natfrag-send-in.out" 2>&1 &
    sender=$!
    tries=0
    while ! grep -q ready "$work/natfrag-send-in.out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "natfrag: host B replier not ready"
        sleep 0.05
    done
    frag_ns=$host_a
    frag_receiver_start "natfrag-in.out" expect pa 33310 203.0.113.1 192.168.1.10 9006-9006 \
        1500 2972 "ruster-natfrag-in-$suffix" 10 203.0.113.1 9006 "ruster-natfrag-poke-$suffix"
    status=0
    wait "$frag_receiver" || status=$?
    : >"$stopfile"
    wait "$sender" || true
    in_ns "$host_b" ethtool -K pb tx on >/dev/null
    [ "$status" -eq 0 ] || fail "natfrag inbound: $(cat "$work/natfrag-in.out")"
    echo "priv_run_natfrag_inbound: host B's kernel fragments, translated by the NAT: $(sed -n 2p "$work/natfrag-in.out") verified"

    # Outbound out of order from host A's raw socket: last, middle, first.
    rm -f "$stopfile"
    frag_ns=$host_b
    frag_receiver_start "natfrag-out.out" expect pb 9007 203.0.113.2 203.0.113.1 40000-40015 \
        1500 2972 "ruster-natfrag-out-$suffix" 10
    in_ns "$host_a" python3 -I -c "$NATFRAG_RAW" 192.168.1.10 203.0.113.1 33311 9007 2972 \
        "ruster-natfrag-out-$suffix" "$stopfile" 2,1,0 >"$work/natfrag-raw.out" 2>&1 &
    sender=$!
    status=0
    wait "$frag_receiver" || status=$?
    : >"$stopfile"
    wait "$sender" || true
    [ "$status" -eq 0 ] || fail "natfrag outbound: $(cat "$work/natfrag-out.out") $(cat "$work/natfrag-raw.out")"
    echo "priv_run_natfrag_outbound: host A's raw fragments sent last first, held and released by the router: $(sed -n 2p "$work/natfrag-out.out") verified"
    natfrag_stop natfrag
    block_has "$work/natfrag.final" drop.FIREWALL_FRAGMENT_UNSUPPORTED=0 \
        drop.NAT44_UDP_NON_ATOMIC_IPV4_UNSUPPORTED=0 drop.IPV4_FRAGMENT_TABLE_FULL=0 \
        drop.IPV4_FRAGMENT_HOST_LIMIT=0 drop.IPV4_FRAGMENT_HOLD_FULL=0 \
        drop.IPV4_FRAGMENT_HOST_HOLD_LIMIT=0 drop.IPV4_FRAGMENT_TRANSPORT_HEADER_OVERLAP=0 \
        drop.IPV4_FRAGMENT_MALFORMED=0 fragment_tracking.release_dropped=0 \
        fragmentation.dropped_unavailable=0 fragmentation.incomplete=0
    allowed=$(stat_in "$work/natfrag.final" fragment_tracking.first_allowed)
    followed=$(stat_in "$work/natfrag.final" fragment_tracking.followed)
    held=$(stat_in "$work/natfrag.final" fragment_tracking.held)
    released=$(stat_in "$work/natfrag.final" fragment_tracking.released)
    consumed=$(stat_in "$work/natfrag.final" consume.IPV4_FRAGMENT_HELD)
    whole=$(stat_in "$work/natfrag.final" fragmentation.whole)
    [ "${allowed:-0}" -ge 2 ] && [ "${followed:-0}" -ge 2 ] ||
        fail "natfrag: first_allowed ${allowed:-missing}, followed ${followed:-missing}"
    [ "${held:-0}" -ge 2 ] && [ "${consumed:-x}" = "$held" ] ||
        fail "natfrag: held ${held:-missing}, consume.IPV4_FRAGMENT_HELD ${consumed:-missing}"
    [ "${released:-0}" -ge 2 ] && [ "${whole:-x}" -ge "$released" ] ||
        fail "natfrag: released ${released:-missing}, fragmentation.whole ${whole:-missing}"
    echo "priv_run_natfrag: firewall on; fragment_tracking.first_allowed=$allowed followed=$followed held=consume.IPV4_FRAGMENT_HELD=$held released=$released (fragmentation.whole=$whole), no fragment refused, exit 0, detached verified"

    # The hardening switch: the same out-of-order fragments are refused.
    start_ruster natfrag-refuse "$work/natfrag-refuse.toml"
    wait_ready natfrag-refuse || fail "natfrag-refuse: ruster exited during startup"
    forward_once natfrag_refuse_resolve
    rm -f "$stopfile"
    frag_ns=$host_b
    frag_receiver_start "natfrag-refuse.recv" absent pb 9007 203.0.113.2 203.0.113.1 40000-40015 \
        1500 2972 "ruster-natfrag-refuse-$suffix" 3
    in_ns "$host_a" python3 -I -c "$NATFRAG_RAW" 192.168.1.10 203.0.113.1 33312 9007 2972 \
        "ruster-natfrag-refuse-$suffix" "$stopfile" 2,1,0 >"$work/natfrag-raw-refuse.out" 2>&1 &
    sender=$!
    status=0
    wait "$frag_receiver" || status=$?
    : >"$stopfile"
    wait "$sender" || true
    [ "$status" -eq 0 ] || fail "natfrag refuse: $(cat "$work/natfrag-refuse.recv")"
    natfrag_stop natfrag-refuse
    refused=$(stat_in "$work/natfrag-refuse.final" drop.FIREWALL_FRAGMENT_UNSUPPORTED)
    [ "${refused:-0}" -ge 3 ] ||
        fail "natfrag-refuse: drop.FIREWALL_FRAGMENT_UNSUPPORTED is ${refused:-missing}"
    block_has "$work/natfrag-refuse.final" fragment_tracking.first_allowed=0 \
        fragment_tracking.held=0 consume.IPV4_FRAGMENT_HELD=0
    echo "priv_run_natfrag_refuse: with [fragment-tracking] mode = \"refuse\" $(sed -n 2p "$work/natfrag-refuse.recv"); drop.FIREWALL_FRAGMENT_UNSUPPORTED=$refused, exit 0, detached verified"
}
phase_natfrag

# unsolicited_syn (B3): host B's raw-socket view of the RFC 5382 REQ-4
# delayed ICMP Port Unreachable. argv: mode (icmp|absent), public port,
# source port, deadline seconds. Sends one SYN 203.0.113.1 -> 203.0.113.2
# and reads every ICMPv4 message on a raw socket until the deadline. For
# `icmp`, exactly one Type 3 Code 3 from 203.0.113.2 must quote the SYN as
# sent (IPv4 addresses, TCP ports, sequence number), with valid checksums,
# TTL 64 and TOS 0xc0, and arrive no earlier than 6 s after the SYN: the
# delay is measured from the latest send-side reading (after sendto
# returned, when the router has surely been handed the SYN), so it never
# overstates the hold; the router keeps a 2 ms clock margin
# (NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS) on top of the 6 s. Residual
# risk on a heavily loaded host: if the router took the SYN from its RX ring
# while this process was still descheduled inside sendto, a correct router
# can be measured a little under 6 s here. The error is in the safe
# direction (the check only ever fails, never passes, wrongly); a failure
# also prints the delay from before the send for the diagnosis.
UNSOLICITED_SYN='
import os, socket, struct, sys, time

def fold(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total

def check(ok, what):
    if not ok:
        sys.exit("unsolicited syn %s: %s" % (mode, what))

mode, dport, sport, wait = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
me, router = socket.inet_aton("203.0.113.1"), socket.inet_aton("203.0.113.2")
seq = int.from_bytes(os.urandom(4), "big")
tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 8192, 0, 0)
pseudo = me + router + struct.pack("!BBH", 0, 6, len(tcp))
tcp = tcp[:16] + struct.pack("!H", 0xFFFF - fold(pseudo + tcp)) + tcp[18:]
icmp_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_raw.settimeout(0.1)
syn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# Both readings bracket the send; the strict check uses the later one
# (sent), the earlier one (before) only bounds the listening window.
before = time.monotonic()
syn.sendto(tcp, ("203.0.113.2", 0))
sent = time.monotonic()
answers = []
while time.monotonic() - before < wait:
    try:
        pkt = icmp_raw.recv(4096)
    except socket.timeout:
        continue
    ihl = (pkt[0] & 15) * 4
    icmp = pkt[ihl:]
    if len(icmp) < 36 or icmp[0] != 3:
        continue
    quote = icmp[8:]
    qihl = (quote[0] & 15) * 4
    if quote[9] != 6 or quote[12:16] != me or len(quote) < qihl + 8:
        continue
    if struct.unpack("!HHI", quote[qihl:qihl + 8]) != (sport, dport, seq):
        continue
    answers.append((time.monotonic() - sent, pkt, icmp, quote, qihl))
if mode == "absent":
    check(not answers, "an ICMPv4 error answered the SYN with the switch off")
    print("no ICMPv4 error for the unsolicited SYN to 203.0.113.2:%d within %s s" % (dport, sys.argv[4]))
    sys.exit(0)
check(len(answers) == 1, "%d answers within %s s" % (len(answers), sys.argv[4]))
delay, pkt, icmp, quote, qihl = answers[0]
ihl = (pkt[0] & 15) * 4
check(delay >= 6.0, "answered %.4f s after sendto returned (%.4f s after the send started), before the 6 s hold" % (delay, delay + (sent - before)))
check((icmp[0], icmp[1]) == (3, 3), "type/code %d/%d" % (icmp[0], icmp[1]))
check(pkt[12:16] == router and pkt[16:20] == me, "outer addresses")
check(pkt[9] == 1 and fold(pkt[:ihl]) == 0xFFFF, "outer protocol or header checksum")
check(pkt[8] == 64 and pkt[1] == 0xC0, "outer TTL %d TOS 0x%02x" % (pkt[8], pkt[1]))
check(fold(icmp) == 0xFFFF and icmp[4:8] == b"\0\0\0\0", "ICMP checksum or unused field")
check(quote[16:20] == router and fold(quote[:qihl]) == 0xFFFF, "quoted IPv4 header")
check(quote[qihl:qihl + 20] == tcp, "quoted TCP header differs from the SYN sent")
print("type=3 code=3 from 203.0.113.2 ttl=64 tos=0xc0 %.4f s after sendto returned (>= 6 s), quoting the SYN 203.0.113.1:%d -> 203.0.113.2:%d seq=%d" % (delay, sport, dport, seq))
'

unsolicited_syn_probe() {
    in_ns "$host_b" python3 -I -c "$UNSOLICITED_SYN" "$1" "$2" "$3" "$4" \
        >"$work/unsolicited-syn-$1.txt" 2>&1 ||
        fail "unsolicited_syn: $(cat "$work/unsolicited-syn-$1.txt")"
}

phase_unsolicited_syn() {
    # router-v1 keeps the default unsolicited-syn-icmp = true (64 holds)
    # but its firewall denies every new WAN -> LAN flow, so REQ-4 a keeps
    # unsolicited SYNs silent there (syn-deny). syn-on adds rule 90, which
    # admits new WAN -> LAN TCP flows to every inside destination; the off
    # copy of it only flips the reloadable switch.
    cp "$work/router.toml" "$work/syn-deny.toml"
    cp "$work/router.toml" "$work/syn-on.toml"
    cat >>"$work/syn-on.toml" <<'EOF'

[[firewall.rules]]
id = 90
ingress = "wan"
egress = "lan"
source = "0.0.0.0/0"
destination = "0.0.0.0/0"
protocol = "tcp"
action = "allow-stateful"

[firewall.rules.source-ports]
first = 1
last = 65535

[firewall.rules.destination-ports]
first = 1
last = 65535
EOF
    "$binary_path" validate "$work/syn-on.toml" >"$work/validate-syn-on.txt" 2>&1 ||
        fail "unsolicited_syn: syn-on.toml invalid: $(cat "$work/validate-syn-on.txt")"
    awk '{print} /^\[nat44\.tcp\]$/{print "unsolicited-syn-icmp = false"}' \
        "$work/syn-on.toml" >"$work/syn-off.toml"
    grep -q '^unsolicited-syn-icmp = false$' "$work/syn-off.toml" ||
        fail "unsolicited_syn: off config not written"
    cp "$work/syn-on.toml" "$work/syn.toml"
    expect_plan syn-on syn-off reloadable none
    expect_plan syn-off syn-deny reloadable none
    grep -qxF '  nat44-tcp unsolicited-syn-icmp ~ on -> off' "$work/plan-syn-on-syn-off.txt" ||
        fail "unsolicited_syn: plan does not show the switch: $(cat "$work/plan-syn-on-syn-off.txt")"
    start_ruster syn "$work/syn.toml" --user "$smoke_uid" --group "$smoke_gid"
    wait_ready syn || fail "unsolicited_syn: ruster exited during startup"
    # Resolves host B on the router (the ICMP's reverse neighbor) and
    # creates the only TCP-free UDP mapping; 40003 has no TCP mapping.
    forward_once syn_resolve
    unsolicited_syn_probe icmp 40003 33001 12
    wait_stat_ge syn nat44_tcp.unsolicited_syn_icmp_queued 1
    latest_block syn
    block_has "$work/syn.block" nat44_tcp.unsolicited_syn_held=1 \
        icmpv4_errors.dequeued_port_unreachable=1 drop.NAT44_TCP_MAPPING_MISS=1
    echo "priv_run_unsolicited_syn: $(cat "$work/unsolicited-syn-icmp.txt") verified"
    reload_with "$work/syn-off.toml" "$work/syn.toml"
    wait_line syn "reload applied: generation=2 previous=1;"
    unsolicited_syn_probe absent 40004 33002 9
    wait_stat_ge syn drop.NAT44_TCP_MAPPING_MISS 2
    latest_block syn
    block_has "$work/syn.block" nat44_tcp.unsolicited_syn_held=1 \
        icmpv4_errors.dequeued_port_unreachable=1
    echo "priv_run_unsolicited_syn_off: after the reloadable SIGHUP to unsolicited-syn-icmp = false, $(cat "$work/unsolicited-syn-absent.txt") (REQ-4 a silent drop) verified"
    reload_with "$work/syn-deny.toml" "$work/syn.toml"
    wait_line syn "reload applied: generation=3 previous=2;"
    unsolicited_syn_probe absent 40005 33003 9
    wait_stat_ge syn nat44_tcp.unsolicited_syn_firewall_denied 1
    latest_block syn
    block_has "$work/syn.block" nat44_tcp.unsolicited_syn_held=1 \
        icmpv4_errors.dequeued_port_unreachable=1
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "unsolicited_syn: exit status $status after SIGTERM"
    assert_detached "the unsolicited_syn run"
    echo "priv_run_unsolicited_syn_firewall: after the reloadable SIGHUP to router-v1's default-deny firewall (switch on), $(cat "$work/unsolicited-syn-absent.txt") (REQ-4 a, unsolicited_syn_firewall_denied counted), exit 0 verified"
}
phase_unsolicited_syn

# icmp_query (N5, RFC 5508 §3): router-v1 has no [nat44.icmp], so a ping
# from host A to host B is dropped there (ICMP queries crossing the NAT fail
# closed). icmp-query adds [nat44.icmp] and an `icmp` firewall rule (a
# storage-shape change, restart-required): host A's pings to host B then
# succeed. Host B has no route to 192.168.1.0/24, so a reply reaches host A
# only if the router translated the request's source to 203.0.113.2 and the
# reply's destination back. Host A pinging 203.0.113.2 is answered by the
# router itself. ping runs with its defaults: the request has DF set, and
# host B's kernel sends the Echo Reply with DF clear, which the NAT
# translates as long as it is unfragmented (NAT44-116).
phase_icmp_query() {
    cp "$work/router.toml" "$work/icmp-query.toml"
    cat >>"$work/icmp-query.toml" <<'EOF'

[nat44.icmp]
idle-ttl-ms = 60000

[nat44.icmp.capacity]
mappings = 8
peers = 16

[[firewall.rules]]
id = 95
ingress = "lan"
egress = "wan"
source = "192.168.1.0/24"
destination = "0.0.0.0/0"
protocol = "icmp"
action = "allow-stateful"
EOF
    "$binary_path" validate "$work/icmp-query.toml" >"$work/validate-icmp-query.txt" 2>&1 ||
        fail "icmp_query: icmp-query.toml invalid: $(cat "$work/validate-icmp-query.txt")"
    grep -q " services=resolution,icmpv4-errors,nat44-udp,nat44-tcp,nat44-icmp,firewall " \
        "$work/validate-icmp-query.txt" ||
        fail "icmp_query: validate does not list nat44-icmp: $(cat "$work/validate-icmp-query.txt")"
    expect_plan router icmp-query restart-required STORAGE_SHAPE
    grep -qxF '  nat44-icmp ~ off -> on' "$work/plan-router-icmp-query.txt" ||
        fail "icmp_query: plan does not show the service: $(cat "$work/plan-router-icmp-query.txt")"

    cp "$work/router.toml" "$work/icmp.toml"
    start_ruster icmpq "$work/icmp.toml" --user "$smoke_uid" --group "$smoke_gid"
    wait_ready icmpq || fail "icmp_query: ruster exited during startup"
    forward_once icmpq_resolve
    if in_ns "$host_a" ping -n -q -c 2 -i 0.2 -W 1 203.0.113.1 >"$work/ping-off.txt" 2>&1; then
        fail "icmp_query: a ping crossed the NAT without [nat44.icmp]: $(cat "$work/ping-off.txt")"
    fi
    wait_stat_ge icmpq drop.NAT44_UDP_UNSUPPORTED_TRANSPORT 2
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "icmp_query: exit status $status after SIGTERM (off)"
    assert_detached "the icmp_query off run"
    echo "priv_run_icmp_query_off: without [nat44.icmp] host A's pings to host B are dropped (NAT44_UDP_UNSUPPORTED_TRANSPORT) verified"

    start_ruster icmpq "$work/icmp-query.toml" --user "$smoke_uid" --group "$smoke_gid"
    wait_ready icmpq || fail "icmp_query: ruster exited during startup"
    forward_once icmpq_resolve_on
    in_ns "$host_a" ping -n -c 3 -i 0.2 -W 2 203.0.113.1 >"$work/ping-on.txt" 2>&1 ||
        fail "icmp_query: ping host A -> host B failed: $(cat "$work/ping-on.txt")"
    grep -q "3 received" "$work/ping-on.txt" ||
        fail "icmp_query: not every reply came back: $(cat "$work/ping-on.txt")"
    in_ns "$host_a" ping -n -c 2 -i 0.2 -W 2 203.0.113.2 >"$work/ping-public.txt" 2>&1 ||
        fail "icmp_query: ping of the public address failed: $(cat "$work/ping-public.txt")"
    wait_stat_ge icmpq nat44_icmp.inbound_translated 3
    latest_block icmpq
    block_has "$work/icmpq.block" nat44_icmp.outbound_translated=3 \
        nat44_icmp.inbound_translated=3 nat44_icmp.mappings_created=1 \
        occupancy.nat44_icmp_mappings.occupied=1
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "icmp_query: exit status $status after SIGTERM"
    assert_detached "the icmp_query run"
    echo "priv_run_icmp_query: with [nat44.icmp] host A -> host B ping (3/3 replies translated back, one mapping) and host A -> public address (answered by the router), exit 0 verified"
}
phase_icmp_query

# arphold (ARP-HOLD, RFC 1122 2.3.2.2, RFC 1812 3.3.2): every neighbour
# cache empty (a fresh router; host A's and host B's caches flushed), the
# first datagram of a new flow is held while the router resolves host B and
# sent when host B answers. `ping -c1` from host A to host B succeeds on the
# first try (the icmp-query config: ICMP query NAT and an icmp rule), and on
# a second fresh router the first TCP SYN of a connection to host B gets
# through without its 1 s retransmission: the connection completes well
# under the initial RTO. The final counters show arp_hold.held = replayed =
# replay_sent and no NEIGHBOR_UNRESOLVED drop. With `[resolution.hold]
# enabled = false` the same single ping is lost (drop.NEIGHBOR_UNRESOLVED).
TCP_LISTEN='
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
s.settimeout(float(sys.argv[2]))
print("ready", flush=True)
c, (host, port) = s.accept()
print(host, port, flush=True)
c.close()
'
TCP_CONNECT='
import socket, sys, time
start = time.monotonic()
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5)
elapsed = time.monotonic() - start
# struct tcp_info: tcpi_total_retrans is the u32 at byte offset 100.
info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
retrans = int.from_bytes(info[100:104], sys.byteorder)
s.close()
print("%.3f %d" % (elapsed, retrans), flush=True)
'

arphold_fresh_caches() {
    in_ns "$host_a" ip neigh flush all
    in_ns "$host_b" ip neigh flush all
}

phase_arphold() {
    # The icmp_query phase wrote icmp-query.toml (router-v1 with [nat44.icmp]
    # and an icmp rule); the hold is the default.
    cp "$work/icmp-query.toml" "$work/arphold.toml"
    grep -q '^\[resolution.hold\]' "$work/arphold.toml" &&
        fail "arphold: the base config already sets [resolution.hold]"

    arphold_fresh_caches
    start_ruster arphold "$work/arphold.toml"
    wait_ready arphold || fail "arphold: ruster exited during startup"
    in_ns "$host_a" ping -n -c 1 -W 3 203.0.113.1 >"$work/arphold-ping.txt" 2>&1 ||
        fail "arphold: the first ping was lost: $(cat "$work/arphold-ping.txt")"
    grep -q "1 packets transmitted, 1 received" "$work/arphold-ping.txt" ||
        fail "arphold: ping -c1: $(cat "$work/arphold-ping.txt")"
    natfrag_stop arphold
    block_has "$work/arphold.final" arp_hold.held=1 arp_hold.replayed=1 \
        arp_hold.replay_sent=1 consume.ARP_HELD=1 drop.NEIGHBOR_UNRESOLVED=0 \
        nat44_icmp.outbound_translated=1 nat44_icmp.inbound_translated=1
    echo "priv_run_arphold_ping: $(sed -n '/transmitted/p' "$work/arphold-ping.txt") on the first try with every neighbour cache empty; arp_hold.held=replayed=replay_sent=1, drop.NEIGHBOR_UNRESOLVED=0, exit 0, detached verified"

    # Host B answers from its own TCP stack: full checksums (a veth leaves
    # them partial, which the router's firewall rightly drops).
    in_ns "$host_b" ethtool -K pb tx off >/dev/null
    arphold_fresh_caches
    start_ruster arphold-tcp "$work/arphold.toml"
    wait_ready arphold-tcp || fail "arphold: ruster exited during startup (tcp)"
    in_ns "$host_b" python3 -I -c "$TCP_LISTEN" 9100 10 >"$work/arphold-listen.out" 2>&1 &
    listener=$!
    tries=0
    while ! grep -q ready "$work/arphold-listen.out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "arphold: host B listener not ready"
        sleep 0.05
    done
    in_ns "$host_a" python3 -I -c "$TCP_CONNECT" 203.0.113.1 9100 >"$work/arphold-connect.out" 2>&1 ||
        fail "arphold: TCP connect failed: $(cat "$work/arphold-connect.out")"
    status=0
    wait "$listener" || status=$?
    [ "$status" -eq 0 ] || fail "arphold: host B accepted nothing: $(cat "$work/arphold-listen.out")"
    read -r elapsed retrans <"$work/arphold-connect.out"
    # The first SYN went through: no retransmission, and the handshake took
    # far less than Linux's 1 s initial RTO.
    [ "$retrans" -eq 0 ] || fail "arphold: the SYN was retransmitted ($retrans): $elapsed s"
    awk -v t="$elapsed" 'BEGIN { exit !(t < 0.5) }' ||
        fail "arphold: the handshake took $elapsed s"
    natfrag_stop arphold-tcp
    in_ns "$host_b" ethtool -K pb tx on >/dev/null
    block_has "$work/arphold-tcp.final" arp_hold.held=1 arp_hold.replayed=1 \
        arp_hold.replay_sent=1 drop.NEIGHBOR_UNRESOLVED=0 nat44_tcp.sessions_created=1
    echo "priv_run_arphold_tcp: with every neighbour cache empty the first SYN was held and sent (connect ${elapsed} s, tcpi_total_retrans=$retrans), host B accepted from $(sed -n 2p "$work/arphold-listen.out"), exit 0 verified"

    # The switch: without the hold the first ping is lost.
    sed 's/^\[nat44.icmp\]$/[resolution.hold]\nenabled = false\n\n[nat44.icmp]/' \
        "$work/arphold.toml" >"$work/arphold-off.toml"
    grep -q '^enabled = false$' "$work/arphold-off.toml" || fail "arphold: no off config"
    arphold_fresh_caches
    start_ruster arphold-off "$work/arphold-off.toml"
    wait_ready arphold-off || fail "arphold: ruster exited during startup (off)"
    if in_ns "$host_a" ping -n -c 1 -W 2 203.0.113.1 >"$work/arphold-off-ping.txt" 2>&1; then
        fail "arphold: the first ping crossed without the hold: $(cat "$work/arphold-off-ping.txt")"
    fi
    natfrag_stop arphold-off
    block_has "$work/arphold-off.final" drop.NEIGHBOR_UNRESOLVED=1 consume.ARP_HELD=0 \
        arp_hold.held=0
    echo "priv_run_arphold_off: with [resolution.hold] enabled = false the first ping is lost (drop.NEIGHBOR_UNRESOLVED=1) verified"
}
phase_arphold

# announce: RFC 5227 ARP Announcements of the router's own addresses
# (ARP-033..ARP-039). Host B captures every ARP frame on pb with an
# AF_PACKET (ETH_P_ARP) socket and prints "<seconds> <op> <sha> <spa> <tpa>"
# per frame, from the time it prints "ready" until the stop file appears.
ARP_CAPTURE='
import os, socket, sys, time
iface, stopfile, deadline = sys.argv[1], sys.argv[2], time.monotonic() + float(sys.argv[3])
cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
cap.bind((iface, 0x0806))
cap.settimeout(0.05)
start = time.monotonic()
print("ready", flush=True)
while time.monotonic() < deadline and not os.path.exists(stopfile):
    try:
        frame, addr = cap.recvfrom(65535)
    except socket.timeout:
        continue
    if addr[2] == socket.PACKET_OUTGOING or len(frame) < 42:
        continue
    op = int.from_bytes(frame[20:22], "big")
    sha = frame[22:28].hex(":")
    spa = ".".join(str(b) for b in frame[28:32])
    tpa = ".".join(str(b) for b in frame[38:42])
    dst = frame[0:6].hex(":")
    print("%.3f %d %s %s %s %s" % (time.monotonic() - start, op, sha, spa, tpa, dst), flush=True)
'
# Host B claims an address of the router: one ARP Reply from pb's own MAC
# with sender IP $2, broadcast (a conflicting ARP packet, RFC 5227 §2.4).
ARP_CLAIM='
import socket, sys
iface, claimed = sys.argv[1], bytes(int(x) for x in sys.argv[2].split("."))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
s.bind((iface, 0x0806))
mac = s.getsockname()[4][:6]
body = bytes([0, 1, 8, 0, 6, 4, 0, 2]) + mac + claimed + mac + bytes([203, 0, 113, 1])
s.send(b"\xff" * 6 + mac + b"\x08\x06" + body + bytes(60 - 14 - len(body)))
'
# The announcements of 203.0.113.2 (sender = target, broadcast, from the
# router's wan MAC) in capture file $1, one start time per line.
announcements() {
    awk '$2 == 1 && $3 == "02:00:00:00:00:02" && $4 == "203.0.113.2" &&
        $5 == "203.0.113.2" && $6 == "ff:ff:ff:ff:ff:ff" { print $1 }' "$1"
}
phase_announce() {
    # A 2 s minimum interval (one sequence) so the link-up below, more
    # than 2 s after startup, announces again at once.
    printf '\n[arp]\nannounce-min-interval-ms = 2000\n' |
        cat "$work/router.toml" - >"$work/announce.toml"
    capture="$work/announce-capture.txt"
    rm -f "$stopfile"
    in_ns "$host_b" python3 -I -c "$ARP_CAPTURE" pb "$stopfile" 30 >"$capture" 2>&1 &
    capturer=$!
    tries=0
    while ! grep -q ready "$capture" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "announce: capture not ready"
        sleep 0.05
    done
    start_ruster announce "$work/announce.toml"
    wait_ready announce || fail "announce: ruster exited during startup"
    # Startup: ANNOUNCE_NUM (2) Announcements ANNOUNCE_INTERVAL (2 s) apart.
    sleep 3
    [ "$(announcements "$capture" | wc -l)" -eq 2 ] ||
        fail "announce: startup did not send exactly 2 announcements: $(cat "$capture")"
    gap=$(announcements "$capture" | awk 'NR == 1 { a = $1 } NR == 2 { print $1 - a }')
    awk -v g="$gap" 'BEGIN { exit !(g >= 1.9 && g <= 3.0) }' ||
        fail "announce: startup announcements $gap s apart"
    echo "priv_run_announce_startup: 2 RFC 5227 announcements of 203.0.113.2 from 02:00:00:00:00:02 on pb, $gap s apart verified"

    # Link-up: one more sequence on that port.
    sudo -n ip -n "$router" link set rb down
    wait_line announce "warning: port=if2 health=LINK_DOWN"
    sudo -n ip -n "$router" link set rb up
    wait_line announce "recovered: port=if2 health=LINK_DOWN"
    sleep 3
    [ "$(announcements "$capture" | wc -l)" -eq 4 ] ||
        fail "announce: link-up did not send 2 more announcements: $(cat "$capture")"
    echo "priv_run_announce_link_up: link down/up on rb sent 2 more announcements verified"

    # A conflicting ARP packet: counted, logged value-free, and defended by
    # one announcement (RFC 5227 §2.4 (c)).
    in_ns "$host_b" python3 -I -c "$ARP_CLAIM" pb 203.0.113.2 ||
        fail "announce: could not send the conflicting ARP packet"
    wait_line announce "warning: port=if2 health=ARP_ADDRESS_CONFLICT"
    sleep 1
    [ "$(announcements "$capture" | wc -l)" -eq 5 ] ||
        fail "announce: the conflict was not defended once: $(cat "$capture")"
    touch "$stopfile"
    wait "$capturer" || fail "announce: capture failed: $(cat "$capture")"
    natfrag_stop announce
    block_has "$work/announce.final" arp_announce.conflicts=1 arp_announce.defended=1 \
        if2.watch.arp_address_conflicts=1
    if grep -q '02:00:00:00:00:66\|203\.0\.113\.2' "$work/announce.err"; then
        fail "announce: the conflict log line carries a value"
    fi
    echo "priv_run_announce_conflict: a conflicting ARP Reply was counted (arp_announce.conflicts=1, if2.watch.arp_address_conflicts=1), logged as ARP_ADDRESS_CONFLICT, and defended by one announcement verified"

    # The switch: no announcement at startup.
    printf '\n[arp]\nannounce = false\n' |
        cat "$work/router.toml" - >"$work/announce-off.toml"
    rm -f "$stopfile"
    in_ns "$host_b" python3 -I -c "$ARP_CAPTURE" pb "$stopfile" 30 >"$capture" 2>&1 &
    capturer=$!
    tries=0
    while ! grep -q ready "$capture" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "announce: capture not ready (off)"
        sleep 0.05
    done
    start_ruster announce-off "$work/announce-off.toml"
    wait_ready announce-off || fail "announce: ruster exited during startup (off)"
    sleep 3
    touch "$stopfile"
    wait "$capturer" || fail "announce: capture failed (off): $(cat "$capture")"
    natfrag_stop announce-off
    [ "$(announcements "$capture" | wc -l)" -eq 0 ] ||
        fail "announce: announced with announce = false: $(cat "$capture")"
    block_has "$work/announce-off.final" arp_announce.committed=0
    echo "priv_run_announce_off: with [arp] announce = false nothing was announced verified"
}
phase_announce

# exit_protection: OPS-EXIT `[exit-protection]` on ra/rb of the router
# namespace only (every sysctl and link here is in that namespace).
fwd_of() {
    sudo -n ip netns exec "$router" cat "/proc/sys/net/ipv4/conf/$1/forwarding"
}
phase_exit_protection() {
    # Every exit action needs CAP_NET_ADMIN at exit (Linux checks it at
    # every sysctl write and link change): refused under the default drop
    # before any resource (exit 2), applied with --keep-privileges, where
    # both ports' forwarding was 1 (accepted with --allow-kernel-forwarding)
    # and is 0 after the exit.
    cp "$work/router.toml" "$work/exit-forwarding.toml"
    printf '\n[exit-protection]\nipv4-forwarding-off = true\n' >>"$work/exit-forwarding.toml"
    start_ruster exit-forwarding-refused "$work/exit-forwarding.toml"
    wait_ruster
    [ "$status" -eq 2 ] || fail "exit: forwarding-off without --keep-privileges exit status $status"
    grep -q "invalid config: stage=exit-protection code=EXIT_FORWARDING_NEEDS_PRIVILEGES" \
        "$work/exit-forwarding-refused.err" || fail "exit: forwarding-off refusal: $(cat "$work/exit-forwarding-refused.err")"
    assert_detached "the forwarding-off refusal"
    for device in ra rb; do
        sudo -n ip netns exec "$router" sh -c \
            "echo 1 >/proc/sys/net/ipv4/conf/$device/forwarding"
    done
    [ "$(fwd_of ra)$(fwd_of rb)" = 11 ] || fail "exit: forwarding not set up"
    start_ruster exit-forwarding "$work/exit-forwarding.toml" --allow-kernel-forwarding --keep-privileges
    wait_ready exit-forwarding || fail "exit: forwarding-off run exited during startup: $(cat "$work/exit-forwarding.err")"
    grep -q "exit protection armed: ipv4-forwarding-off=true link-down=false ports=2" \
        "$work/exit-forwarding.err" || fail "exit: not armed"
    grep -q "seccomp filter installed: mode=kill" "$work/exit-forwarding.err" ||
        fail "exit: forwarding-off run without the syscall filter"
    grep -q "filesystem confined: mode=landlock" "$work/exit-forwarding.err" ||
        fail "exit: forwarding-off run without Landlock"
    forward_once exit-forwarding
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "exit: forwarding-off exit status $status"
    grep -q "exit protection applied: ipv4-forwarding-off=2 link-down=0 failed=0" \
        "$work/exit-forwarding.err" || fail "exit: forwarding-off not applied: $(cat "$work/exit-forwarding.err")"
    [ "$(fwd_of ra)$(fwd_of rb)" = 00 ] || fail "exit: forwarding is $(fwd_of ra)/$(fwd_of rb) after the exit"
    assert_detached "the forwarding-off exit"
    echo "priv_run_exit_forwarding: ipv4-forwarding-off refused under the default drop (exit 2, EXIT_FORWARDING_NEEDS_PRIVILEGES); with --keep-privileges under seccomp kill and Landlock ra and rb forwarding 1 -> 0 at exit, exit 0 verified"

    # link-down needs CAP_NET_ADMIN at exit: refused under the default
    # drop before any resource, applied with --keep-privileges.
    cp "$work/router.toml" "$work/exit-link.toml"
    printf '\n[exit-protection]\nlink-down = true\n' >>"$work/exit-link.toml"
    start_ruster exit-link-refused "$work/exit-link.toml"
    wait_ruster
    [ "$status" -eq 2 ] || fail "exit: link-down without --keep-privileges exit status $status"
    grep -q "invalid config: stage=exit-protection code=EXIT_LINK_DOWN_NEEDS_PRIVILEGES" \
        "$work/exit-link-refused.err" || fail "exit: link-down refusal: $(cat "$work/exit-link-refused.err")"
    assert_detached "the link-down refusal"
    start_ruster exit-link "$work/exit-link.toml" --keep-privileges
    wait_ready exit-link || fail "exit: link-down run exited during startup: $(cat "$work/exit-link.err")"
    forward_once exit-link
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "exit: link-down exit status $status"
    grep -q "exit protection applied: ipv4-forwarding-off=0 link-down=2 failed=0" \
        "$work/exit-link.err" || fail "exit: link-down not applied: $(cat "$work/exit-link.err")"
    for device in ra rb; do
        if sudo -n ip -n "$router" -o link show dev "$device" | grep -q "[<,]UP[,>]"; then
            fail "exit: $device is still up after the exit"
        fi
    done
    assert_detached "the link-down exit"
    sudo -n ip -n "$router" link set ra up
    sudo -n ip -n "$router" link set rb up
    echo "priv_run_exit_link: link-down refused without --keep-privileges (exit 2, EXIT_LINK_DOWN_NEEDS_PRIVILEGES); with it ra and rb set down at exit, exit 0, then set up again verified"
}

# txfull: the WAN TX ring driven full and recovered.
# --user/--group: the reload while held reads the work file as that user.
start_ruster txfull "$work/txfull.toml" --tx-stall-warn-secs 1 --tx-stall-fatal-secs 2 \
    --kick-errors-fatal-secs 2 --user "$smoke_uid" --group "$smoke_gid"
wait_ready txfull || fail "txfull: ruster exited during startup"
forward_once txfull-before
# rb administratively down inside the router namespace: every TX kick
# fails ENETDOWN and the kernel consumes no TX descriptor. (A peer that
# is down only drops carrier; the kernel then consumes and drops the
# frames, so the ring never fills.)
down_at=$(date +%s%N)
sudo -n ip -n "$router" link set rb down
wait_line txfull "warning: port=if2 health=LINK_DOWN"
in_ns "$host_a" python3 -I -c "$BURST" 203.0.113.1 9001 300 "ruster-txfull-$suffix"
wait_block txfull if2.af_xdp_port.tx_inflight=128
# Held past both fatal thresholds (2 s): a down link holds its TX by
# design, so neither TX_STALL nor KICK_ERRORS may fire.
sleep 4
launcher_alive || fail "txfull: exited while the TX ring was full"
latest_block txfull
held_ms=$((($(date +%s%N) - down_at) / 1000000))
cp "$work/txfull.block" "$work/txfull.held"
block_has "$work/txfull.held" observer.state=healthy watch.state=warning \
    if2.af_xdp_port.link_down=true if2.af_xdp_port.tx_inflight=128 \
    if2.af_xdp_port.tx_ring_unconsumed=128 if2.af_xdp_port.tx_inflight_highwater=128 \
    if2.watch.link_up=false if2.watch.tx_stall=false if2.watch.kick_errors_persistent=false \
    if1.af_xdp_port.tx_blocked=0
ring_full=$(stat_in "$work/txfull.held" if2.af_xdp_port.tx_ring_full)
blocked=$(stat_in "$work/txfull.held" if2.af_xdp_port.tx_blocked)
# A router frame (the second startup ARP Announcement, ARP-033, 2 s after
# startup) can meet the full ring too: it counts as generated_tx_blocked.
generated_blocked=$(stat_in "$work/txfull.held" if2.af_xdp_port.generated_tx_blocked)
link_down_kicks=$(stat_in "$work/txfull.held" if2.af_xdp_port.kicks_link_down)
[ "${ring_full:-0}" -ge 1 ] && [ "${generated_blocked:-x}" -le 2 ] &&
    [ "$ring_full" -eq $((blocked + generated_blocked)) ] ||
    fail "txfull: tx_ring_full ${ring_full:-missing}, tx_blocked ${blocked:-missing}, generated_tx_blocked ${generated_blocked:-missing}"
[ "${link_down_kicks:-0}" -ge 1 ] || fail "txfull: no ENETDOWN kick while held"
# The adapter retries a down link's owed kick at most every 1 ms doubling
# to 64 ms: at most 7 + held_ms / 64 ENETDOWN kicks since rb went down
# (the block predates held_ms, so this over-counts the time). Allow 4x;
# a retry at every settle was about 10k per second.
kick_bound=$((4 * (7 + held_ms / 64)))
[ "$link_down_kicks" -le "$kick_bound" ] ||
    fail "txfull: $link_down_kicks ENETDOWN kicks in ${held_ms} ms, above $kick_bound"
suppressed=$(stat_in "$work/txfull.held" if2.af_xdp_port.kick_retries_suppressed)
[ "${suppressed:-0}" -ge 1 ] || fail "txfull: no suppressed kick retry while held"
if grep -Eq "fatal:|health=(TX_STALL|KICK_ERRORS)" "$work/txfull.err"; then
    fail "txfull: a TX_STALL/KICK_ERRORS event or a fatal while the link was down"
fi
echo "priv_run_txfull: rb down, TX ring full (tx_inflight=128 of 128, tx_ring_full=$ring_full=tx_blocked $blocked + generated_tx_blocked $generated_blocked, $link_down_kicks ENETDOWN kicks in ${held_ms} ms, at most $kick_bound, $suppressed retries suppressed), held 4 s past --tx-stall-fatal-secs 2 and --kick-errors-fatal-secs 2 without a fatal, observer.state=healthy watch.state=warning verified"
# OPS-EXIT item 2: a reload while rb is admin-down with its TX ring full
# applies at once; the held TX does not block the quiescence (before, it
# failed with stage=quiesce code=TIMEOUT) and stays in flight.
reload_with "$work/txfull.toml" "$work/txfull.toml"
wait_line txfull "reload applied: generation=2 previous=1"
if grep -q "stage=quiesce" "$work/txfull.err"; then
    fail "txfull: the reload waited for the down link's TX"
fi
grep -q "reload applied: generation=2 previous=1; .*; held-tx-on-down-links=128" \
    "$work/txfull.err" || fail "txfull: the reload line does not count the 128 held frames"
wait_block txfull observer.generation=2
block_has "$work/txfull.block" if2.af_xdp_port.tx_inflight=128 \
    if2.af_xdp_port.tx_held_on_down_link=128
# The strict `[reload] down-link-tx = "refuse"` refuses the same reload
# while the frames are held; generation 2 keeps running.
cp "$work/txfull.toml" "$work/txfull-strict.toml"
printf '\n[reload]\ndown-link-tx = "refuse"\n' >>"$work/txfull-strict.toml"
cp "$work/txfull.toml" "$work/txfull-default.toml"
reload_with "$work/txfull-strict.toml" "$work/txfull.toml"
wait_line txfull "stage=quiesce code=DOWN_LINK_TX_HELD; generation 2 keeps running"
reload_with "$work/txfull-default.toml" "$work/txfull.toml"
wait_line txfull "reload applied: generation=4 previous=2"
echo "priv_run_txfull_reload: SIGHUP while rb was down with 128 frames held applied generation 2 without waiting (held-tx-on-down-links=128, gauge tx_held_on_down_link=128, the frames still in flight); with [reload] down-link-tx = \"refuse\" the next reload was refused (DOWN_LINK_TX_HELD), the default applied again verified"
rm -f "$work/recv-txfull-backlog.out"
in_ns "$host_b" python3 -I -c "$COUNT" 9001 "ruster-txfull-$suffix" 3 \
    >"$work/recv-txfull-backlog.out" 2>&1 &
receiver=$!
tries=0
while ! grep -q ready "$work/recv-txfull-backlog.out" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -le 200 ] || fail "txfull: receiver not ready"
    sleep 0.05
done
sudo -n ip -n "$router" link set rb up
wait "$receiver" || fail "txfull: backlog receiver failed"
backlog=$(sed -n 2p "$work/recv-txfull-backlog.out")
[ "$backlog" = 128 ] || fail "txfull: host B got ${backlog:-no} held datagrams, not 128"
wait_line txfull "recovered: port=if2 health=LINK_DOWN"
forward_once txfull-after
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "txfull: exit status $status after SIGTERM"
assert_detached "the txfull run"
grep -q "stopped by signal; .* tx-in-flight=0 .*detached and closed 2 port(s)" \
    "$work/txfull.err" || fail "txfull: no shutdown summary"
if grep -Eq "fatal:|health=(TX_STALL|KICK_ERRORS)" "$work/txfull.err"; then
    fail "txfull: a TX_STALL/KICK_ERRORS event or a fatal"
fi
sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/txfull.out" >"$work/txfull.final"
block_has "$work/txfull.final" observer.state=healthy watch.state=ok \
    if2.af_xdp_port.tx_inflight=0 if2.af_xdp_port.generated_inflight=0 \
    if2.watch.link_down_events=1 if2.watch.link_up_events=1 rx.accounting_violations=0 \
    "if2.af_xdp_port.tx_blocked=$blocked" "rx.tx_rejected=$blocked"
final() {
    stat_in "$work/txfull.final" "$1"
}
[ "$(final if2.af_xdp_port.tx_submitted)" = "$(final if2.af_xdp_port.tx_completed)" ] ||
    fail "txfull: if2 TX submitted != completed"
[ "$(final if2.af_xdp_port.generated_committed)" = "$(final if2.af_xdp_port.generated_completed)" ] ||
    fail "txfull: if2 generated committed != completed"
[ "$(final rx.tx_requested)" -eq $(($(final rx.tx_accepted) + $(final rx.tx_rejected))) ] ||
    fail "txfull: rx.tx_requested != tx_accepted + tx_rejected"
[ "$(final rx.received)" -eq $(($(final rx.tx_requested) + $(final rx.dropped) + $(final rx.consumed))) ] ||
    fail "txfull: rx.received != tx_requested + dropped + consumed"
cat "$work/txfull.err"
phase_exit_protection
echo "priv_run_txfull: rb up, the 128 held datagrams reached host B, forwarding recovered, exit 0; final rx.received=$(final rx.received) = tx_requested + dropped + consumed, tx_requested = tx_accepted + tx_rejected ($(final rx.tx_rejected) = if2 tx_blocked), if2 TX submitted = completed = $(final if2.af_xdp_port.tx_completed), nothing in flight, observer.state=healthy watch.state=ok verified"

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
# Policy routing: a route out of the port in a table other than main
# (rtnetlink RTM_GETROUTE of every table), and a multipath route of which
# one nexthop leaves through the port.
sudo -n ip -n "$router" route add 10.97.0.0/16 dev ra table 100
start_ruster kernel-route-table "$work/router.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "kernel-route-table: exit status $status"
grep -q "startup failed: stage=checks port=if1 code=KERNEL_IPV4_ROUTES count=1" \
    "$work/kernel-route-table.err" || fail "kernel-route-table: wrong failure"
assert_detached "the policy-table route refusal"
sudo -n ip -n "$router" route del 10.97.0.0/16 dev ra table 100
sudo -n ip -n "$router" route add 10.96.0.0/16 table 101 nexthop dev rq nexthop dev rb
start_ruster kernel-route-multipath "$work/router.toml"
wait_ruster
[ "$status" -eq 1 ] || fail "kernel-route-multipath: exit status $status"
grep -q "startup failed: stage=checks port=if2 code=KERNEL_IPV4_ROUTES count=1" \
    "$work/kernel-route-multipath.err" || fail "kernel-route-multipath: wrong failure"
assert_detached "the multipath route refusal"
sudo -n ip -n "$router" route del 10.96.0.0/16 table 101
echo "priv_run_checks: multi-queue device, kernel IPv4 address, and kernel routes (main, policy table 100, multipath nexthop in table 101) refused before attach verified"
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
echo "priv_run_forwarding_device: conf/ra/forwarding=1 with ip_forward=0 refused at startup" \
    "(scope=device), warned on if1 only and recovered while running verified"

# ipv6: every phase so far ran with disable_ipv6=1 on the ports (the
# recommended setup, set before the first phase). IPv6 enabled on a port
# is refused unless --allow-kernel-ipv6; the more specific codes come
# first, so each is asserted on its own.
set_ipv6() {
    # $1 ra|rb, $2 on|off
    case $2 in on) value=0 ;; *) value=1 ;; esac
    in_ns "$router" sysctl -qw "net.ipv6.conf.$1.disable_ipv6=$value"
}
# Waits (10 s) until $work/$1.err holds the fixed text $2 at least $3 times.
wait_count() {
    tries=0
    while [ "$(grep -cF -- "$2" "$work/$1.err")" -lt "$3" ]; do
        launcher_alive || fail "$1: exited while waiting for $3 x: $2"
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "$1: fewer than $3 \"$2\" within 10 seconds"
        sleep 0.05
    done
}
refused_with() {
    # $1 name, $2 expected failure text, extra args: options
    name=$1
    text=$2
    shift 2
    start_ruster "$name" "$work/router.toml" "$@"
    wait_ruster
    [ "$status" -eq 1 ] || fail "$name: exit status $status"
    grep -qF "startup failed: stage=checks $text" "$work/$name.err" ||
        fail "$name: wrong failure (want $text)"
    assert_detached "the $name refusal"
}
set_ipv6 ra on
refused_with ipv6-enabled "port=if1 code=KERNEL_IPV6_ENABLED"
start_ruster ipv6-enabled-allowed "$work/router.toml" --allow-kernel-ipv6
wait_ready ipv6-enabled-allowed || fail "ipv6-enabled-allowed: ruster exited during startup"
grep -q "warning: port=if1 IPV6_ENABLED_ALLOWED" "$work/ipv6-enabled-allowed.err" ||
    fail "ipv6-enabled-allowed: no startup warning"
if grep -q "port=if2 IPV6" "$work/ipv6-enabled-allowed.err"; then
    fail "ipv6-enabled-allowed: rb (IPv6 off) warned"
fi
wait_line ipv6-enabled-allowed "warning: port=if1 health=KERNEL_IPV6_ENABLED"
forward_once ipv6-enabled-allowed
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "ipv6-enabled-allowed: exit status $status"
grep -q "warning: kernel IPv6 is enabled on a port; detached ports may be answered by the kernel's IPv6 stack" \
    "$work/ipv6-enabled-allowed.err" || fail "ipv6-enabled-allowed: no exit warning"
assert_detached "the IPv6-enabled override run"
echo "priv_run_ipv6_enabled: IPv6 on ra with only link-local refused (KERNEL_IPV6_ENABLED), accepted with warnings under --allow-kernel-ipv6 (forwarded, exit warning) verified"
sudo -n ip -n "$router" -6 address add 2001:db8:1::1/64 dev ra nodad
refused_with ipv6-address "port=if1 code=KERNEL_IPV6_ADDRESSES count=1"
# --allow-kernel-forwarding is IPv4 only; --allow-kernel-ipv6 accepts it.
refused_with ipv6-address-ipv4-override "port=if1 code=KERNEL_IPV6_ADDRESSES count=1" \
    --allow-kernel-forwarding
start_ruster ipv6-allowed "$work/router.toml" --allow-kernel-ipv6
wait_ready ipv6-allowed || fail "ipv6-allowed: ruster exited during startup"
for line in "IPV6_ENABLED_ALLOWED" "IPV6_ADDRESSES_ALLOWED count=1" "IPV6_ROUTES_ALLOWED count="; do
    grep -qF "warning: port=if1 $line" "$work/ipv6-allowed.err" ||
        fail "ipv6-allowed: no $line warning"
done
forward_once ipv6-allowed
wait_line ipv6-allowed "warning: port=if1 health=KERNEL_IPV6_ADDRESSES"
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "ipv6-allowed: exit status $status"
grep -q "warning: kernel IPv6 addresses are on a port; detached ports may be answered and routed by the kernel" \
    "$work/ipv6-allowed.err" || fail "ipv6-allowed: no exit warning"
assert_detached "the IPv6 override run"
sudo -n ip -n "$router" -6 address del 2001:db8:1::1/64 dev ra
echo "priv_run_ipv6_address: a global IPv6 address on ra refused (also under --allow-kernel-forwarding), accepted with warnings under --allow-kernel-ipv6 (forwarded, exit warning) verified"
set_ipv6 ra off
set_ipv6 rb on
sudo -n ip -n "$router" -6 route add 2001:db8:99::/48 dev rb table 200
refused_with ipv6-route "port=if2 code=KERNEL_IPV6_ROUTES count=1"
sudo -n ip -n "$router" -6 route del 2001:db8:99::/48 dev rb table 200
set_ipv6 rb off
echo "priv_run_ipv6_route: an IPv6 route out of rb in table 200 refused verified"
set_ipv6 ra on
in_ns "$router" sysctl -qw net.ipv6.conf.all.forwarding=1
refused_with ipv6-forwarding "port=if1 code=KERNEL_IPV6_FORWARDING_ENABLED scope=global"
# disable_ipv6 on both ports: the kernel drops every IPv6 frame there, so
# IPv6 forwarding no longer matters and the run starts without a word.
set_ipv6 ra off
start_ruster ipv6-disabled "$work/router.toml"
wait_ready ipv6-disabled || fail "ipv6-disabled: ruster exited during startup"
forward_once ipv6-disabled
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "ipv6-disabled: exit status $status"
if grep -q "IPV6" "$work/ipv6-disabled.err"; then
    fail "ipv6-disabled: an IPv6 warning with IPv6 disabled on the ports"
fi
assert_detached "the disabled-IPv6 run"
in_ns "$router" sysctl -qw net.ipv6.conf.all.forwarding=0
for dev in ra rb; do
    [ "$(in_ns "$router" sysctl -n "net.ipv6.conf.$dev.forwarding")" = 0 ] ||
        fail "ipv6: $dev forwarding is still on"
done
echo "priv_run_ipv6_forwarding: net.ipv6.conf.all.forwarding=1 refused (scope=global), accepted silently with disable_ipv6=1 on both ports verified"
# force_forwarding (Linux 6.17+): forwards on the ingress device even with
# conf/all/forwarding 0. Only an absent sysctl skips, and says so.
if in_ns "$router" test -e /proc/sys/net/ipv6/conf/ra/force_forwarding; then
    force_forwarding=yes
    set_ipv6 ra on
    in_ns "$router" sysctl -qw net.ipv6.conf.ra.force_forwarding=1
    [ "$(in_ns "$router" sysctl -n net.ipv6.conf.ra.forwarding)" = 0 ] ||
        fail "ipv6-force: conf/ra/forwarding is on"
    refused_with ipv6-force "port=if1 code=KERNEL_IPV6_FORWARDING_ENABLED scope=force"
    in_ns "$router" sysctl -qw net.ipv6.conf.ra.force_forwarding=0
    set_ipv6 ra off
    echo "priv_run_ipv6_force_forwarding: net.ipv6.conf.ra.force_forwarding=1 with all.forwarding=0 refused (scope=force) verified"
else
    force_forwarding=
    echo "priv_run_ipv6_force_forwarding: SKIPPED (no net.ipv6.conf.ra.force_forwarding on this kernel; Linux 6.17+)"
fi
# While running (no override; both ports start with IPv6 off): each kind
# warns and recovers, the router keeps forwarding, and nothing is fatal
# (a fatal exit would detach).
start_ruster ipv6-runtime "$work/router.toml"
wait_ready ipv6-runtime || fail "ipv6-runtime: ruster exited during startup"
set_ipv6 ra on
wait_line ipv6-runtime "warning: port=if1 health=KERNEL_IPV6_ENABLED"
sudo -n ip -n "$router" -6 address add 2001:db8:2::1/64 dev ra nodad
wait_line ipv6-runtime "warning: port=if1 health=KERNEL_IPV6_ADDRESSES"
wait_line ipv6-runtime "warning: port=if1 health=KERNEL_IPV6_ROUTES"
forward_once ipv6-runtime-address
sudo -n ip -n "$router" -6 address del 2001:db8:2::1/64 dev ra
wait_line ipv6-runtime "recovered: port=if1 health=KERNEL_IPV6_ADDRESSES"
wait_line ipv6-runtime "recovered: port=if1 health=KERNEL_IPV6_ROUTES"
forwarding_warnings=0
if [ -n "$force_forwarding" ]; then
    in_ns "$router" sysctl -qw net.ipv6.conf.ra.force_forwarding=1
    wait_count ipv6-runtime "warning: port=if1 health=KERNEL_IPV6_FORWARDING_ENABLED" 1
    in_ns "$router" sysctl -qw net.ipv6.conf.ra.force_forwarding=0
    wait_count ipv6-runtime "recovered: port=if1 health=KERNEL_IPV6_FORWARDING_ENABLED" 1
    forwarding_warnings=1
fi
sudo -n ip -n "$router" route add 10.95.0.0/16 dev rb table 300
wait_line ipv6-runtime "warning: port=if2 health=KERNEL_IPV4_ROUTES"
sudo -n ip -n "$router" route del 10.95.0.0/16 dev rb table 300
wait_line ipv6-runtime "recovered: port=if2 health=KERNEL_IPV4_ROUTES"
in_ns "$router" sysctl -qw net.ipv6.conf.all.forwarding=1
wait_count ipv6-runtime "warning: port=if1 health=KERNEL_IPV6_FORWARDING_ENABLED" $((forwarding_warnings + 1))
forward_once ipv6-runtime-forwarding
set_ipv6 ra off
wait_line ipv6-runtime "recovered: port=if1 health=KERNEL_IPV6_ENABLED"
wait_count ipv6-runtime "recovered: port=if1 health=KERNEL_IPV6_FORWARDING_ENABLED" $((forwarding_warnings + 1))
set_ipv6 rb on
wait_line ipv6-runtime "warning: port=if2 health=KERNEL_IPV6_ENABLED"
wait_line ipv6-runtime "warning: port=if2 health=KERNEL_IPV6_FORWARDING_ENABLED"
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "ipv6-runtime: exit status $status"
if grep -q "fatal:" "$work/ipv6-runtime.err"; then
    fail "ipv6-runtime: a fatal event"
fi
if grep -q "recovered: port=if2 health=KERNEL_IPV6" "$work/ipv6-runtime.err"; then
    fail "ipv6-runtime: rb recovered although its IPv6 stayed on"
fi
for line in "kernel IPv6 forwarding is enabled for a port; detached ports may be forwarded by the kernel" \
    "kernel IPv6 is enabled on a port; detached ports may be answered by the kernel's IPv6 stack"; do
    grep -qF "warning: $line" "$work/ipv6-runtime.err" || fail "ipv6-runtime: no exit warning: $line"
done
if grep -q "warning: kernel IPv4 routes lead out of a port" "$work/ipv6-runtime.err"; then
    fail "ipv6-runtime: an exit warning for a route that was removed"
fi
assert_detached "the run-time IPv6 run"
in_ns "$router" sysctl -qw net.ipv6.conf.all.forwarding=0
# Back to the recommended setup for the remaining phases.
set_ipv6 rb off
echo "priv_run_ipv6_runtime: disable_ipv6 flipped to 0, a global IPv6 address and its route, force_forwarding (${force_forwarding:-skipped}), an IPv4 route in table 300, and IPv6 forwarding warned and recovered while forwarding (disable_ipv6 on ra recovered if1 only), no fatal, exit warnings for rb verified"

# weakhost: an effective rp_filter (the larger of all and the device) of 0
# on an address-less port is refused at startup (KERNEL_IPV4_WEAK_HOST,
# owner decision 2026-11-02, CLI-079), also with arp_ignore=1 (which stops
# ARP replies only: a frame sent to the port's MAC for any host address is
# still delivered). --allow-ipv4-weak-host accepts it with the warning.
# While running it is only ever a warning (a fatal exit would detach XDP),
# with or without the override; strict (1) or loose (2) recovers. The
# setup's all.rp_filter=1 avoids it.
for dev in all ra rb; do
    in_ns "$router" sysctl -qw "net.ipv4.conf.$dev.rp_filter=0"
done
[ "$(in_ns "$router" sysctl -n net.ipv4.conf.all.arp_ignore)" = 1 ] ||
    fail "weakhost: all.arp_ignore is not 1"
refused_with weakhost-refused "port=if1 code=KERNEL_IPV4_WEAK_HOST"
# The other overrides do not accept it.
refused_with weakhost-other-overrides "port=if1 code=KERNEL_IPV4_WEAK_HOST" \
    --allow-kernel-forwarding --allow-kernel-ipv6 --allow-multi-queue
# The effective value is per port: rp_filter=1 on ra alone leaves rb at 0.
in_ns "$router" sysctl -qw net.ipv4.conf.ra.rp_filter=1
refused_with weakhost-device "port=if2 code=KERNEL_IPV4_WEAK_HOST"
in_ns "$router" sysctl -qw net.ipv4.conf.ra.rp_filter=0
start_ruster weakhost "$work/router.toml" --allow-ipv4-weak-host
wait_ready weakhost || fail "weakhost: ruster exited during startup"
grep -q "warning: port=if1 IPV4_WEAK_HOST_EXPOSURE" "$work/weakhost.err" ||
    fail "weakhost: no startup warning with arp_ignore=1"
wait_line weakhost "warning: port=if2 health=IPV4_WEAK_HOST_EXPOSURE"
in_ns "$router" sysctl -qw net.ipv4.conf.all.rp_filter=2
wait_line weakhost "recovered: port=if2 health=IPV4_WEAK_HOST_EXPOSURE"
forward_once weakhost
in_ns "$router" sysctl -qw net.ipv4.conf.all.rp_filter=0
wait_count weakhost "warning: port=if2 health=IPV4_WEAK_HOST_EXPOSURE" 2
in_ns "$router" sysctl -qw net.ipv4.conf.all.rp_filter=1
wait_count weakhost "recovered: port=if2 health=IPV4_WEAK_HOST_EXPOSURE" 2
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "weakhost: exit status $status"
if grep -q "fatal:" "$work/weakhost.err"; then
    fail "weakhost: a fatal event"
fi
assert_detached "the weak-host run"
# Without the override: loose rp_filter (2) starts without a weak-host
# warning; flipping it to 0 while running warns (no fatal) and 1 recovers.
in_ns "$router" sysctl -qw net.ipv4.conf.all.rp_filter=2
start_ruster weakhost-loose "$work/router.toml"
wait_ready weakhost-loose || fail "weakhost-loose: ruster exited during startup"
if grep -q "IPV4_WEAK_HOST" "$work/weakhost-loose.err"; then
    fail "weakhost-loose: warned with rp_filter=2"
fi
forward_once weakhost-loose
in_ns "$router" sysctl -qw net.ipv4.conf.all.rp_filter=0
wait_line weakhost-loose "warning: port=if2 health=IPV4_WEAK_HOST_EXPOSURE"
in_ns "$router" sysctl -qw net.ipv4.conf.all.rp_filter=1
wait_line weakhost-loose "recovered: port=if2 health=IPV4_WEAK_HOST_EXPOSURE"
forward_once weakhost-loose
signal_ruster TERM
wait_ruster
[ "$status" -eq 0 ] || fail "weakhost-loose: exit status $status"
if grep -q "fatal:" "$work/weakhost-loose.err"; then
    fail "weakhost-loose: a fatal event"
fi
assert_detached "the loose rp_filter run"
echo "priv_run_weak_host: effective rp_filter=0 refused at startup (KERNEL_IPV4_WEAK_HOST, per port, not by the other overrides) although arp_ignore=1, accepted and warned under --allow-ipv4-weak-host, recovered with rp_filter=2 and with 1; without the override rp_filter=2 started clean and a run-time flip to 0 only warned and recovered with 1 verified"

# mc_forwarding: a multicast routing socket (MRT_INIT) sets IPv4
# conf/all/mc_forwarding=1 while it is open: refused (scope=multicast)
# unless --allow-kernel-forwarding. Without kernel multicast routing the
# step says it is skipped.
mroute_stop="$work/mroute.stop"
rm -f "$work/mroute.ready" "$mroute_stop"
in_ns "$router" python3 -I -c '
import os, socket, sys, time
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
    s.setsockopt(socket.IPPROTO_IP, 200, (1).to_bytes(4, "little"))  # MRT_INIT
except OSError as error:
    open(sys.argv[1], "w").write("skip %d\n" % error.errno)
    sys.exit(0)
open(sys.argv[1], "w").write("ready\n")
deadline = time.monotonic() + 120
while not os.path.exists(sys.argv[2]) and time.monotonic() < deadline:
    time.sleep(0.05)
' "$work/mroute.ready" "$mroute_stop" &
mroute=$!
tries=0
while [ ! -s "$work/mroute.ready" ]; do
    tries=$((tries + 1))
    [ "$tries" -le 200 ] || fail "mroute: holder not ready"
    sleep 0.05
done
if grep -q ready "$work/mroute.ready"; then
    [ "$(in_ns "$router" sysctl -n net.ipv4.conf.all.mc_forwarding)" = 1 ] ||
        fail "mroute: mc_forwarding is not 1"
    refused_with mc-forwarding "port=if1 code=KERNEL_FORWARDING_ENABLED scope=multicast"
    start_ruster mc-forwarding-allowed "$work/router.toml" --allow-kernel-forwarding
    wait_ready mc-forwarding-allowed || fail "mc-forwarding-allowed: ruster exited during startup"
    grep -q "warning: port=if1 IPV4_FORWARDING_ENABLED scope=multicast" "$work/mc-forwarding-allowed.err" ||
        fail "mc-forwarding-allowed: no warning"
    wait_line mc-forwarding-allowed "warning: port=if1 health=KERNEL_FORWARDING_ENABLED"
    : >"$mroute_stop"
    wait "$mroute" || true
    mroute=
    wait_line mc-forwarding-allowed "recovered: port=if1 health=KERNEL_FORWARDING_ENABLED"
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "mc-forwarding-allowed: exit status $status"
    assert_detached "the mc_forwarding override run"
    echo "priv_run_mc_forwarding: an IPv4 multicast routing socket (all/mc_forwarding=1) refused (scope=multicast), accepted with --allow-kernel-forwarding, warned and recovered while running verified"
else
    : >"$mroute_stop"
    wait "$mroute" || true
    mroute=
    echo "priv_run_mc_forwarding: SKIPPED (MRT_INIT failed: $(cat "$work/mroute.ready"))"
fi
rm -f "$mroute_stop"

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
# phase is not vacuous). "Full" is mainly "not moving": the queued byte
# count is unchanged 1.5 s later although ruster emits a stats block every
# second. The byte count itself is only checked against a loose floor of
# half the capacity, because the kernel merges small writes into a pipe
# page only while the whole write fits, so a full pipe holds somewhat less
# than its capacity (a few unused bytes per page).
first=$(python3 -I -c "$PIPE_FILL" "$work/stuck.fifo") ||
    fail "stuck: cannot read the FIFO fill"
sleep 1.5
second=$(python3 -I -c "$PIPE_FILL" "$work/stuck.fifo") ||
    fail "stuck: cannot read the FIFO fill"
queued=${first% *}
capacity=${first#* }
[ "$first" = "$second" ] || fail "stuck: stdout pipe still moving ($first, then $second)"
[ "$queued" -gt 0 ] && [ $((queued * 2)) -ge "$capacity" ] ||
    fail "stuck: stdout pipe not full ($queued of $capacity bytes queued)"
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

# seccomp (H8): the log and off modes, and a SIGSYS kill detaches.
phase_seccomp() {
    before=$(seccomp_records)
    start_ruster seccomp-log "$work/router.toml" --seccomp log \
        --user "$smoke_uid" --group "$smoke_gid"
    wait_ready seccomp-log || fail "seccomp-log: ruster exited during startup"
    assert_dropped seccomp-log "$smoke_uid $smoke_gid"
    grep -Eqx "ruster run: seccomp filter installed: mode=log threads=5 syscalls=[0-9]+ arch=x86_64" \
        "$work/seccomp-log.err" || fail "seccomp-log: no seccomp line"
    grep -qxF "ruster run: warning: seccomp=log (--seccomp log): a syscall outside the allowlist is logged by the kernel and allowed" \
        "$work/seccomp-log.err" || fail "seccomp-log: no warning"
    forward_once seccomp-log
    signal_ruster HUP
    wait_line seccomp-log "reload applied: generation=2 previous=1"
    sudo -n ip -n "$router" link set ra down
    wait_line seccomp-log "warning: port=if1 health=LINK_DOWN"
    sudo -n ip -n "$router" link set ra up
    wait_line seccomp-log "recovered: port=if1 health=LINK_DOWN"
    forward_once seccomp-log-after
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "seccomp-log: exit status $status after SIGTERM"
    assert_detached "the --seccomp log run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/seccomp-log.out" >"$work/seccomp-log.final"
    block_has "$work/seccomp-log.final" seccomp.mode=log seccomp.threads=5
    after=$(seccomp_records)
    [ "${after:-0}" -le "${before:-0}" ] ||
        fail "seccomp-log: the kernel logged $((after - before)) seccomp record(s) of the ruster binary"
    echo "priv_run_seccomp_log: --seccomp log filtered all 5 threads, forwarded, reloaded (generation 2), survived a link down/up, exit 0, detached, no seccomp record in the kernel log (${after:-unreadable} in all) verified"

    start_ruster seccomp-off "$work/router.toml" --seccomp=off
    wait_ready seccomp-off || fail "seccomp-off: ruster exited during startup"
    assert_dropped seccomp-off "" unconfined
    assert_confined seccomp-off 0
    grep -qxF "ruster run: warning: seccomp=off (--seccomp off): no syscall filter" \
        "$work/seccomp-off.err" || fail "seccomp-off: no warning"
    forward_once seccomp-off
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "seccomp-off: exit status $status after SIGTERM"
    assert_detached "the --seccomp off run"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/seccomp-off.out" >"$work/seccomp-off.final"
    block_has "$work/seccomp-off.final" seccomp.mode=off seccomp.threads=0 seccomp.syscalls=0
    echo "priv_run_seccomp_off: --seccomp off left every thread unfiltered (Seccomp=$seccomp_mode_base), forwarded, exit 0, detached verified"

    start_ruster seccomp-sigsys "$work/router.toml"
    wait_ready seccomp-sigsys || fail "seccomp-sigsys: ruster exited during startup"
    assert_confined seccomp-sigsys
    signal_ruster SYS
    wait_ruster
    [ "$status" -ne 0 ] || fail "seccomp-sigsys: exit status 0 after SIGSYS"
    tries=0
    while [ -n "$(xdp_on ra)$(xdp_on rb)" ]; do
        tries=$((tries + 1))
        [ "$tries" -le 100 ] || fail "links survived SIGSYS of their owner"
        sleep 0.02
    done
    grep -q "stopped by signal" "$work/seccomp-sigsys.err" && fail "seccomp-sigsys: ran an ordered shutdown"
    echo "priv_run_seccomp_sigsys: a SIGSYS group exit (what the kill filter does) ended the router with status $status and both links auto-detached verified"
}

phase_seccomp

# H10 systemd: a path datagram socket in the work directory stands in for
# systemd's notify socket (no systemd needed). Every datagram is appended
# to the log file as one line, its newlines written as '|'.
NOTIFY_RECEIVER='
import os, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o600)
out = open(sys.argv[2], "a")
print("ready", flush=True)
while True:
    data = s.recv(4096)
    out.write(data.decode().replace("\n", "|") + "\n")
    out.flush()
'

# Waits (10 s) until the notification log has the line $1 (regex, whole
# line) at least $2 (default 1) times.
wait_notify() {
    tries=0
    while [ "$(grep -cx -- "$1" "$work/notify.log")" -lt "${2:-1}" ]; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "systemd: no notification $1 (x${2:-1}): $(cat "$work/notify.log")"
        sleep 0.05
    done
}

# systemd (H10): sd_notify over NOTIFY_SOCKET, the watchdog, SIGUSR1 stats,
# all under the default privilege drop (switched to the invoking user, who
# owns the socket) and the default --seccomp kill filter.
phase_systemd() {
    rm -f "$work/notify.sock"
    : >"$work/notify.log"
    python3 -I -c "$NOTIFY_RECEIVER" "$work/notify.sock" "$work/notify.log" \
        >"$work/notify-receiver.out" 2>&1 &
    notify_receiver=$!
    tries=0
    while ! grep -q ready "$work/notify-receiver.out" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "systemd: notify receiver not ready"
        sleep 0.05
    done
    cp "$work/router.toml" "$work/systemd.toml"
    # WATCHDOG_USEC 0.4 s: a ping every 200 ms.
    ruster_env="NOTIFY_SOCKET=$work/notify.sock WATCHDOG_USEC=400000"
    start_ruster systemd "$work/systemd.toml" --user "$smoke_uid" --group "$smoke_gid"
    ruster_env=
    wait_ready systemd || fail "systemd: ruster exited during startup"
    assert_dropped systemd "$smoke_uid $smoke_gid"
    wait_notify "READY=1|STATUS=running generation 1|"
    [ "$(sed -n 1p "$work/notify.log")" = "READY=1|STATUS=running generation 1|" ] ||
        fail "systemd: the first notification is not READY=1: $(cat "$work/notify.log")"
    forward_once systemd
    pings_a=$(grep -cx "WATCHDOG=1|" "$work/notify.log")
    sleep 2
    pings_b=$(grep -cx "WATCHDOG=1|" "$work/notify.log")
    [ $((pings_b - pings_a)) -ge 6 ] && [ $((pings_b - pings_a)) -le 14 ] ||
        fail "systemd: $((pings_b - pings_a)) watchdog pings in 2 s (interval 200 ms)"
    # A reloadable change (router-v2): RELOADING=1 with MONOTONIC_USEC,
    # then READY=1 with the new generation.
    reload_with "$work/router-v2.toml" "$work/systemd.toml"
    wait_line systemd "reload applied: generation=2 previous=1"
    wait_notify "RELOADING=1|MONOTONIC_USEC=[1-9][0-9]*|STATUS=reloading (generation 1)|"
    wait_notify "READY=1|STATUS=running generation 2|"
    # SIGUSR1: one on-demand block, two coalesced or not, never an exit.
    signal_ruster USR1
    tries=0
    while ! grep -q "^ruster-run-stats kind=on-demand " "$work/systemd.out"; do
        launcher_alive || fail "systemd: exited after SIGUSR1"
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "systemd: no on-demand stats block within 10 s"
        sleep 0.05
    done
    sleep 0.3
    awk '/^ruster-run-stats kind=on-demand /{on=1} on{print} on&&/^end$/{exit}' \
        "$work/systemd.out" >"$work/systemd.ondemand"
    block_has "$work/systemd.ondemand" observer.generation=2 notify.enabled=true \
        notify.watchdog_interval_ms=200 notify.failed=0 seccomp.mode=kill
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "systemd: exit status $status after SIGTERM"
    assert_detached "the systemd phase"
    sleep 0.2
    [ "$(tail -n 1 "$work/notify.log")" = "STOPPING=1|STATUS=stopping: stop requested|" ] ||
        fail "systemd: the last notification is not STOPPING=1: $(tail -n 3 "$work/notify.log")"
    kill "$notify_receiver" 2>/dev/null || true
    wait "$notify_receiver" 2>/dev/null || true
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/systemd.out" >"$work/systemd.final"
    block_has "$work/systemd.final" notify.enabled=true notify.failed=0
    sent=$(stat_in "$work/systemd.final" notify.sent)
    lines=$(wc -l <"$work/notify.log")
    # The final block is captured after STOPPING=1, so it counts it.
    [ "$sent" -eq "$lines" ] || fail "systemd: notify.sent=$sent but $lines datagrams received"
    echo "priv_run_systemd: READY=1 after readiness, $((pings_b - pings_a)) watchdog pings in 2 s, RELOADING=1 with MONOTONIC_USEC and READY=1 generation 2 around a reload, a SIGUSR1 on-demand stats block, STOPPING=1 last ($lines datagrams, all counted), under --seccomp kill as the invoking user; exit 0, detached verified"
}

# rename (H10): renaming a port while the router runs (taken down first,
# which every kernel accepts; 6.2 and newer also rename an up device) is
# fatal DEVICE_RENAMED: its sysctl paths would name
# whatever device takes the old name. Exit 1, nothing left attached; the
# device gets its name back for the later phases.
phase_rename() {
    start_ruster rename "$work/router.toml"
    wait_ready rename || fail "rename: ruster exited during startup"
    forward_once rename-before
    sudo -n ip -n "$router" link set ra down
    sudo -n ip -n "$router" link set ra name rx
    wait_exit rename
    [ "$status" -eq 1 ] || fail "rename: exit status $status after renaming ra"
    grep -q "fatal: port=if1 health=DEVICE_RENAMED" "$work/rename.err" ||
        fail "rename: no DEVICE_RENAMED"
    grep -q "stopped after a fatal health event port=if1 code=DEVICE_RENAMED; .*detached and closed 2 port(s)" \
        "$work/rename.err" || fail "rename: no fatal summary"
    test -z "$(xdp_on rx)$(xdp_on rb)" || fail "rename: XDP left attached"
    sudo -n ip -n "$router" link set rx name ra
    sudo -n ip -n "$router" link set ra up
    assert_detached "the rename phase"
    echo "priv_run_rename: a port renamed while running failed closed with DEVICE_RENAMED, exit 1, nothing left attached verified"
}

# log_json (OPS-LOG): every line of a `--log-format json` run is one JSON
# object (validated by python3 -I), and a SIGHUP changes the health
# thresholds and watch intervals from the config.
LOG_JSON_CHECK='
import json, sys
schema = "ruster-run-log/v1"
head = ["schema", "ts", "level", "event", "msg", "fields"]
def objects(path):
    data = open(path, "rb").read()
    if not data.isascii():
        sys.exit(path + ": non-ASCII output")
    if data and not data.endswith(b"\n"):
        sys.exit(path + ": unterminated last line")
    out = []
    for number, line in enumerate(data.decode().splitlines(), 1):
        def unique(pairs):
            keys = [key for key, _ in pairs]
            if len(keys) != len(set(keys)):
                sys.exit("%s:%d: duplicate key" % (path, number))
            return dict(pairs)
        try:
            item = json.loads(line, object_pairs_hook=unique)
        except ValueError as error:
            sys.exit("%s:%d: not JSON (%s): %s" % (path, number, error, line))
        if list(item)[:6] != head or item["schema"] != schema:
            sys.exit("%s:%d: bad head: %s" % (path, number, line))
        if item["level"] not in ("info", "warn", "error"):
            sys.exit("%s:%d: bad level: %s" % (path, number, line))
        if item["event"] == "UNCLASSIFIED" or not isinstance(item["fields"], dict):
            sys.exit("%s:%d: unclassified: %s" % (path, number, line))
        if len(item["ts"]) != 24 or not item["ts"].endswith("Z"):
            sys.exit("%s:%d: bad ts: %s" % (path, number, line))
        out.append(item)
    return out
events = objects(sys.argv[1])
stats = objects(sys.argv[2])
codes = [item["event"] for item in events]
for code in sys.argv[3:]:
    if code not in codes:
        sys.exit("missing event " + code + " in " + " ".join(codes))
if not stats or any(item["event"] != "STATS" or not isinstance(item.get("stats"), dict) for item in stats):
    sys.exit("stdout: a line that is not a STATS object")
final = stats[-1]
if final["fields"].get("kind") != "final" or final["stats"].get("observer.generation") != 2:
    sys.exit("stdout: last block is not the final one of generation 2")
for kind in ("periodic", "on-demand"):
    if not any(item["fields"].get("kind") == kind for item in stats):
        sys.exit("stdout: no " + kind + " block")
print("%d events and %d stats objects" % (len(events), len(stats)))
'

phase_log_json() {
    cp "$work/router.toml" "$work/log.toml"
    # Lower thresholds and other intervals; reloadable (no plan aspect).
    cp "$work/router.toml" "$work/log-health.toml"
    cat >>"$work/log-health.toml" <<EOF

[health]
tx-stall-warn-ms = 2000
tx-stall-fatal-ms = 20000
frames-quarantined-fatal = 1
tx-invalid-descs-fatal = 1

[watch]
health-interval-ms = 250
link-interval-ms = 500
link-stale-ms = 8000
EOF
    # A warning above the (flag default) fatal bound: refused after the merge.
    cp "$work/router.toml" "$work/log-bad.toml"
    printf '\n[health]\ntx-stall-warn-ms = 30000\n' >>"$work/log-bad.toml"
    "$binary" validate "$work/log-health.toml" >/dev/null ||
        fail "log_json: the [health]/[watch] config does not validate"
    start_ruster log_json "$work/log.toml" --log-format json \
        --user "$smoke_uid" --group "$smoke_gid"
    wait_ready log_json || fail "log_json: ruster exited during startup"
    forward_once log_json-before
    reload_with "$work/log-health.toml" "$work/log.toml"
    wait_line log_json "reload applied: generation=2 previous=1"
    wait_line log_json "watch settings applied: tx-stall-warn-ms=2000 tx-stall-fatal-ms=20000 kick-errors-fatal-ms=5000 fill-starved-warn-ms=1000 link-probe-failures-fatal=3 link-dump-interrupted-fatal=10 frames-quarantined-fatal=1 tx-invalid-descs-fatal=1 health-interval-ms=250 link-interval-ms=500 link-stale-ms=8000"
    reload_with "$work/log-bad.toml" "$work/log.toml"
    wait_line log_json "reload failed: stage=health code=HEALTH_FATAL_BELOW_WARNING path=health.tx-stall-fatal-ms limit=30000 actual=10000; generation 2 keeps running"
    forward_once log_json-after
    # At least one periodic block (--stats-interval 1) before the on-demand one.
    sleep 1.2
    signal_ruster USR1
    tries=0
    while ! grep -q '"kind":"on-demand"' "$work/log_json.out"; do
        launcher_alive || fail "log_json: exited after SIGUSR1"
        tries=$((tries + 1))
        [ "$tries" -le 200 ] || fail "log_json: no on-demand stats object within 10 s"
        sleep 0.05
    done
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "log_json: exit status $status after SIGTERM"
    assert_detached "the log_json phase"
    if grep -q '^ruster' "$work/log_json.err" "$work/log_json.out"; then
        fail "log_json: a text line in JSON mode"
    fi
    counts=$(python3 -I -c "$LOG_JSON_CHECK" "$work/log_json.err" "$work/log_json.out" \
        PRIVILEGES_DROPPED FS_CONFINED SECCOMP_INSTALLED READY RELOAD_REQUESTED \
        RELOAD_CHECKED RELOAD_APPLIED WATCH_SETTINGS_APPLIED RELOAD_FAILED \
        SHUTDOWN_DRAINING SHUTDOWN_SUMMARY) ||
        fail "log_json: JSON lines check failed"
    echo "priv_run_log_json: --log-format json wrote $counts, all valid ruster-run-log/v1 objects (python3 -I json, no UNCLASSIFIED); a SIGHUP applied [health]/[watch] (watch settings applied, generation 2) and a disagreeing merge was refused (stage=health, generation 2 kept); forwarding before and after; exit 0, detached verified"
}

phase_systemd
phase_rename
phase_log_json

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

# afpacket (AFPKT-015): `ruster run` with `backend.kind = "af-packet"` in the
# same topology (after the AF_XDP removal phase, which deleted ra: it is
# recreated first). Startup refusals open nothing; one router forwards
# with NAT, answers ICMP Echo, applies and refuses reloads, survives a
# carrier loss and an administrative down/up of a port (whose pending
# socket error it clears, so the idle wait keeps blocking), adds no
# kernel frame of its own, and drains on SIGTERM; deleting a port's
# device ends a second router with DEVICE_REMOVED, leaving no packet
# socket behind. Every run: default privilege drop, Landlock, and the
# kill seccomp filter (the final no-violation check covers them).
PACKET_BACKEND='
[backend]
kind = "af-packet"

[backend.af-packet]
max-frame-len = 1514

[[backend.af-packet.ports]]
interface = "lan"
rx = { block-size = 65536, block-count = 4, retire-timeout-ms = 2 }
tx = { block-size = 65536, block-count = 2 }

[[backend.af-packet.ports]]
interface = "wan"
rx = { block-size = 65536, block-count = 4, retire-timeout-ms = 2 }
tx = { block-size = 65536, block-count = 2 }
'

# The packet sockets of the router namespace (`/proc/net/packet` rows).
packet_sockets() {
    in_ns "$router" cat /proc/net/packet | sed 1d | grep -c . || true
}

# Transmitted frames of the router's device $1.
tx_packets() {
    in_ns "$router" cat "/sys/class/net/$1/statistics/tx_packets"
}

# Starts the AF_PACKET config $2 as phase $1 and expects the startup
# refusal line $3 (exit 1), with no packet socket left.
packet_refused() {
    start_ruster "$1" "$2"
    wait_ruster
    [ "$status" -eq 1 ] || fail "$1: exit status $status: $(cat "$work/$1.err")"
    grep -qxF "ruster run: startup failed: $3" "$work/$1.err" ||
        fail "$1: no refusal \"$3\": $(cat "$work/$1.err")"
    [ "$(packet_sockets)" -eq 0 ] || fail "$1: a packet socket was left open"
}

phase_afpacket() {
    # ra/pa again, as the setup made them (IPv6 off before the link is up,
    # so the kernel never sends a frame of its own on it).
    sudo -n ip -n "$router" link add ra numtxqueues 1 numrxqueues 1 type veth \
        peer name pa netns "$host_a" numtxqueues 1 numrxqueues 1
    sudo -n ip -n "$router" link set ra address 02:00:00:00:00:01
    for dev in ra rb; do
        in_ns "$router" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
        sudo -n ip -n "$router" link set "$dev" mtu 1500
        sudo -n ip -n "$router" link set "$dev" up
    done
    sudo -n ip -n "$host_a" link set pa address 02:00:00:00:00:10
    sudo -n ip -n "$host_a" address add 192.168.1.10/24 dev pa
    sudo -n ip -n "$host_a" link set pa up
    sudo -n ip -n "$host_a" route add default via 192.168.1.1
    in_ns "$host_a" ethtool -K pa tx off >/dev/null
    # The AF_PACKET requirement (runbook): no merging receive offload. veth
    # starts with GRO off on current kernels; say so explicitly anyway.
    for dev in ra rb; do
        in_ns "$router" ethtool -K "$dev" gro off
    done
    for name in router deny; do
        sed '/^\[backend\]$/,$d' "$work/$name.toml" >"$work/packet-$name-base.toml"
        printf '%s' "$PACKET_BACKEND" | cat "$work/packet-$name-base.toml" - >"$work/packet-$name.toml"
    done
    sed 's/retire-timeout-ms = 2/retire-timeout-ms = 3/' "$work/packet-router.toml" \
        >"$work/packet-reshape.toml"
    for config in packet-router packet-deny packet-reshape; do
        status=0
        "$binary_path" validate "$work/$config.toml" >"$work/validate-$config.txt" 2>&1 || status=$?
        [ "$status" -eq 0 ] || fail "afpacket: validate $config: $(cat "$work/validate-$config.txt")"
        grep -q ' backend=af-packet ports=2 max-frame-len=1514 ring-bytes=786432$' \
            "$work/validate-$config.txt" || fail "afpacket: validate $config: $(cat "$work/validate-$config.txt")"
    done
    expect_plan packet-router packet-deny reloadable none
    expect_plan packet-router packet-reshape restart-required BACKEND
    expect_plan router packet-router restart-required BACKEND
    echo "priv_run_afpacket_config: af-packet configs valid (2 ports, 786432 ring bytes), firewall change reloadable, ring change and af-xdp -> af-packet restart-required BACKEND verified"

    # MTU2 part B over AF_PACKET: the inbound run of the frag phase (lan
    # `mtu = 1280`, every device at 1500) with the AF_PACKET backend: the
    # fragments are generated frames written into the lan port's TX ring.
    sed -e '/^mac = "02:00:00:00:00:01"$/a mtu = 1280' "$work/packet-router.toml" \
        >"$work/packet-frag-in.toml"
    [ "$(grep -cx "mtu = 1280" "$work/packet-frag-in.toml")" -eq 1 ] ||
        fail "afpacket-frag: config edit"
    in_ns "$host_a" ip route flush cache
    in_ns "$host_b" ip route flush cache
    start_ruster afpacket-frag "$work/packet-frag-in.toml"
    wait_ready afpacket-frag || fail "afpacket-frag: ruster exited during startup"
    forward_once afpacket_frag_resolve
    frag_inbound afpacket-frag
    frag_stop afpacket-frag 1
    echo "priv_run_afpacket_frag: over AF_PACKET $(sed -n 2p "$work/frag-recv-afpacket-frag.out"); fragmentation.fragmented=consume.IPV4_FRAGMENTED=$fragmented, fragments=generated_fragments.tx_accepted=$fragments, nothing dropped or incomplete, exit 0 verified"

    # Refusals: GRO on a port, a port MTU below max-frame-len - 14, a
    # kernel IPv4 address on a port. Each opens no socket.
    in_ns "$router" ethtool -K ra gro on
    packet_refused afpacket-gro "$work/packet-router.toml" \
        "stage=checks port=if1 code=RECEIVE_OFFLOAD feature=rx-gro"
    in_ns "$router" ethtool -K ra gro off
    # A device MTU below max-frame-len - 14 passes the frame bound, but the
    # configured interface MTU (1500) must fit it (MTU1).
    sudo -n ip -n "$router" link set rb mtu 1400
    packet_refused afpacket-mtu "$work/packet-router.toml" \
        "stage=checks port=if2 code=MTU_BELOW_CONFIG mtu=1400 config=1500"
    sudo -n ip -n "$router" link set rb mtu 1500
    # A VLAN stacked on ra (in the router namespace).
    sudo -n ip -n "$router" link add link ra name ra.10 type vlan id 10
    packet_refused afpacket-vlan "$work/packet-router.toml" \
        "stage=checks port=if1 code=KERNEL_UPPER_DEVICE"
    sudo -n ip -n "$router" link del ra.10
    sudo -n ip -n "$router" address add 198.51.100.7/32 dev rb
    packet_refused afpacket-address "$work/packet-router.toml" \
        "stage=checks port=if2 code=KERNEL_IPV4_ADDRESSES count=1"
    sudo -n ip -n "$router" address del 198.51.100.7/32 dev rb
    echo "priv_run_afpacket_refusals: GRO on ra (RECEIVE_OFFLOAD), rb MTU 1400 (MTU_BELOW_CONFIG), a kernel address on rb, a VLAN on ra (KERNEL_UPPER_DEVICE) refused with exit 1 and no packet socket left verified"

    ra_tx=$(tx_packets ra)
    rb_tx=$(tx_packets rb)
    cp "$work/packet-router.toml" "$work/packet-ops.toml"
    # As the invoking user (who can read the work directory on reload).
    start_ruster afpacket "$work/packet-ops.toml" --user "$smoke_uid" --group "$smoke_gid"
    wait_ready afpacket || fail "afpacket: ruster exited during startup: $(cat "$work/afpacket.err")"
    assert_dropped afpacket "$smoke_uid $smoke_gid"
    grep -Eqx "ruster run: seccomp filter installed: mode=kill threads=5 syscalls=[0-9]+ arch=x86_64" \
        "$work/afpacket.err" || fail "afpacket: no seccomp line"
    grep -Eqx "ruster run: filesystem confined: mode=landlock abi=[0-9]+ rules=4 threads=5" \
        "$work/afpacket.err" || fail "afpacket: no filesystem confinement line"
    [ "$(packet_sockets)" -eq 2 ] || fail "afpacket: not two packet sockets"
    forward_once afpacket-forward
    in_ns "$host_a" ping -c 3 -i 0.2 -W 2 -q 192.168.1.1 >"$work/afpacket-ping.txt" 2>&1 ||
        fail "afpacket: no Echo Reply from the router: $(cat "$work/afpacket-ping.txt")"
    grep -q "3 packets transmitted, 3 received" "$work/afpacket-ping.txt" ||
        fail "afpacket: ping: $(cat "$work/afpacket-ping.txt")"
    echo "priv_run_afpacket_forward: UDP host A -> host B through AF_PACKET with NAT44, ICMP Echo from the router, $threads threads dropped and switched to the invoking uid/gid, seccomp kill, Landlock verified"
    reload_with "$work/packet-deny.toml" "$work/packet-ops.toml"
    wait_line afpacket "reload applied: generation=2 previous=1"
    forward_blocked afpacket-denied
    reload_with "$work/packet-router.toml" "$work/packet-ops.toml"
    wait_line afpacket "reload applied: generation=3 previous=2"
    forward_once afpacket-allowed
    reload_with "$work/packet-reshape.toml" "$work/packet-ops.toml"
    wait_line afpacket "reload refused: code=RESTART_REQUIRED reasons=BACKEND; generation 3 keeps running"
    forward_once afpacket-refused
    echo "priv_run_afpacket_reload: two applied reloads changed the firewall outcome, a ring change refused as RESTART_REQUIRED while forwarding verified"
    # Carrier loss on rb (its peer down), then rb's own administrative
    # down: the kernel sets the bound socket's error, which the idle wait
    # must read and clear.
    sudo -n ip -n "$host_b" link set pb down
    wait_line afpacket "warning: port=if2 health=LINK_DOWN"
    sudo -n ip -n "$host_b" link set pb up
    wait_line afpacket "recovered: port=if2 health=LINK_DOWN"
    forward_once afpacket-carrier
    sudo -n ip -n "$router" link set ra down
    sudo -n ip -n "$router" link set ra up
    wait_stat_ge afpacket if1.af_packet_port.socket_errors 1
    latest_block afpacket
    sleeps=$(stat_in "$work/afpacket.block" idle.sleeps)
    waits=$(stat_in "$work/afpacket.block" idle.waits)
    sleep 1.5
    latest_block afpacket
    sleeps_after=$(stat_in "$work/afpacket.block" idle.sleeps)
    waits_after=$(stat_in "$work/afpacket.block" idle.waits)
    [ $((sleeps_after - sleeps)) -le 20 ] ||
        fail "afpacket: idle wait degraded to sleeps after the socket error ($sleeps -> $sleeps_after)"
    [ $((waits_after - waits)) -ge 20 ] ||
        fail "afpacket: idle waits stopped ($waits -> $waits_after)"
    forward_once afpacket-admin
    echo "priv_run_afpacket_link: carrier loss on rb warned and recovered, ra down/up socket error cleared (socket_errors>=1, idle waits $waits -> $waits_after, sleeps $sleeps -> $sleeps_after), forwarding recovered verified"
    signal_ruster TERM
    wait_ruster
    [ "$status" -eq 0 ] || fail "afpacket: exit status $status after SIGTERM: $(cat "$work/afpacket.err")"
    grep -q "stopped by signal; .* tx-in-flight=0 .*; closed 2 port(s)$" "$work/afpacket.err" ||
        fail "afpacket: no shutdown summary: $(cat "$work/afpacket.err")"
    [ "$(packet_sockets)" -eq 0 ] || fail "afpacket: a packet socket survived the shutdown"
    sed -n "/^ruster-run-stats kind=final/,/^end$/p" "$work/afpacket.out" >"$work/afpacket.final"
    block_has "$work/afpacket.final" af_packet.ports=2 af_packet.mode=copy af_packet.stopped=true \
        af_packet.unbound_ports=0 observer.generation=3 watch.state=ok \
        privileges.state=dropped privileges.identity=switched seccomp.mode=kill fs.confine=landlock
    for port in 1:ra:"$ra_tx" 2:rb:"$rb_tx"; do
        id=${port%%:*}
        rest=${port#*:}
        dev=${rest%%:*}
        before=${rest#*:}
        sent=$(stat_in "$work/afpacket.final" "if$id.af_packet_port.tx_completed")
        kernel=$(stat_in "$work/afpacket.final" "if$id.af_packet_port.kernel_packets")
        delta=$(($(tx_packets "$dev") - before))
        [ "${sent:-0}" -ge 1 ] || fail "afpacket: if$id sent nothing"
        [ "$delta" -le "$sent" ] ||
            fail "afpacket: $dev transmitted $delta frames, the router only $sent: the kernel sent its own"
        [ "${kernel:-0}" -ge 1 ] || fail "afpacket: if$id kernel_packets ${kernel:-missing}"
    done
    echo "priv_run_afpacket_shutdown: SIGTERM exit 0 with nothing in flight, both packet sockets closed, every frame on ra/rb sent by the router (none by the kernel), PACKET_STATISTICS folded in verified"
    # RELOAD-CARRY over AF_PACKET: the same flows survive an unrelated
    # reload and die with a denying one.
    phase_reload_carry afpacket-carry "$work/packet-router.toml"
    [ "$(packet_sockets)" -eq 0 ] || fail "afpacket-carry: a packet socket survived the shutdown"

    # upper: rb enslaved to a bridge while running ends the router with
    # KERNEL_UPPER_DEVICE (exit 1). The bridge (down, in the router
    # namespace only) is deleted again, which releases rb.
    start_ruster afpacket-upper "$work/packet-router.toml"
    wait_ready afpacket-upper || fail "afpacket-upper: ruster exited during startup"
    sudo -n ip -n "$router" link add rbr type bridge
    sudo -n ip -n "$router" link set rb master rbr
    wait_exit afpacket-upper
    [ "$status" -eq 1 ] || fail "afpacket-upper: exit status $status after enslaving rb"
    grep -q "fatal: port=if2 health=KERNEL_UPPER_DEVICE" "$work/afpacket-upper.err" ||
        fail "afpacket-upper: no KERNEL_UPPER_DEVICE: $(cat "$work/afpacket-upper.err")"
    grep -q "stopped after a fatal health event port=if2 code=KERNEL_UPPER_DEVICE; .*; closed 2 port(s)$" \
        "$work/afpacket-upper.err" || fail "afpacket-upper: no fatal summary"
    [ "$(packet_sockets)" -eq 0 ] || fail "afpacket-upper: a packet socket was left open"
    sudo -n ip -n "$router" link del rbr
    sudo -n ip -n "$router" link set rb up
    echo "priv_run_afpacket_upper: rb enslaved to a bridge while running failed closed with exit 1 (KERNEL_UPPER_DEVICE), no packet socket left verified"

    # removal: deleting rb ends the router with DEVICE_REMOVED (exit 1).
    start_ruster afpacket-removal "$work/packet-router.toml"
    wait_ready afpacket-removal || fail "afpacket-removal: ruster exited during startup"
    forward_once afpacket-removal-before
    sudo -n ip -n "$router" link del rb
    wait_exit afpacket-removal
    [ "$status" -eq 1 ] || fail "afpacket-removal: exit status $status after deleting rb"
    grep -q "fatal: port=if2 health=DEVICE_REMOVED" "$work/afpacket-removal.err" ||
        fail "afpacket-removal: no DEVICE_REMOVED: $(cat "$work/afpacket-removal.err")"
    grep -q "stopped after a fatal health event port=if2 code=DEVICE_REMOVED; .*; closed 2 port(s)$" \
        "$work/afpacket-removal.err" || fail "afpacket-removal: no fatal summary"
    [ "$(packet_sockets)" -eq 0 ] || fail "afpacket-removal: a packet socket was left open"
    echo "priv_run_afpacket_removal: deleted port device failed closed with exit 1 (DEVICE_REMOVED), no packet socket left verified"
}

phase_afpacket

# H8: no seccomp kill (or log record) of the ruster binary in the whole
# smoke: every syscall the phases above made was on the allowlist.
seccomp_records_end=$(seccomp_records)
[ "${seccomp_records_end:-0}" -le "${seccomp_records_start:-0}" ] ||
    fail "the kernel logged $((seccomp_records_end - seccomp_records_start)) seccomp record(s) of the ruster binary"
echo "priv_run_seccomp_no_violation: no seccomp record of the ruster binary in the kernel log during the smoke (${seccomp_records_end:-unreadable} in all) verified"

cleanup
trap - EXIT
for ns in "$router" "$host_a" "$host_b"; do
    if sudo -n ip netns list | grep -qx "$ns\( .*\)\{0,1\}"; then
        echo "priv-run-smoke: namespace $ns survived cleanup" >&2
        exit 1
    fi
done
echo "priv-run-smoke: ok (namespaces $router{,-a,-b} removed)"

# M2 operator runbook (`ruster run`, AF_XDP)

Status: final for M2a (M2 S13). It covers what `main` implements after
M2 S10a, S10b and S11 (#301, #302, #303): one copy-mode AF_XDP socket per
port and one RX/TX queue per port, under `ruster run`. Multi-queue,
zero-copy NICs and the X05 hardware lab are not covered (M2b, pending owner
decisions; see [`release-evidence/m2.md`](release-evidence/m2.md)).

Every flag, code and default below was checked against `crates/cli/src/args.rs`
and `crates/cli/src/run/*` at `a51d7de`. If this file and the code
disagree, the code is right; please report the drift.

All commands assume a dedicated router host or network namespace. Replace
`lan0`/`wan0` with the devices of your `[[interfaces]]` entries.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Install and run](#2-install-and-run)
3. [Command line](#3-command-line)
4. [Exit status](#4-exit-status)
5. [Cold start](#5-cold-start)
6. [Config reload (SIGHUP)](#6-config-reload-sighup)
7. [Health and stall signals](#7-health-and-stall-signals)
8. [Link and device events](#8-link-and-device-events)
9. [Graceful shutdown and drain](#9-graceful-shutdown-and-drain)
10. [Forced termination and restart](#10-forced-termination-and-restart)
11. [Stats](#11-stats)
12. [Known limits](#12-known-limits)
13. [CI and E2E](#13-ci-and-e2e)
14. [Troubleshooting](#14-troubleshooting)

## 1. Prerequisites

- **Kernel**: x86_64 Linux 5.9 or newer (XDP `bpf_link`). On any other
  platform `ruster run` exits 1 with `unsupported platform: the AF_XDP
  backend needs x86_64 Linux`. Only the kernel of the CI runner and of the
  development host have been tested; 5.9 to 6.x are not verified (XDP-062).
- **Config**: a file that `ruster validate` accepts, with `[backend] kind =
  "af-xdp"` and one `[[backend.ports]]` entry per interface (README "packet
  backend"). `rings`, `frame-size`, `frame-count`, `generated-frames`,
  `mode` and `xdp-attach` have no defaults; `need-wakeup` defaults to `true`
  (the only value) and `headroom` to `0`. Use `mode = "copy"`: zero-copy is
  not verified on any NIC.
- **Privileges**: run as root, or give the process the effective
  capabilities `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `CAP_BPF` + `CAP_PERFMON`
  (or `CAP_SYS_ADMIN` instead of both). Checked before any resource is
  taken; missing ones exit 4 (`privileges code=MISSING_CAPABILITIES
  missing=...`). `ruster run` does not drop privileges after startup
  (deferred, CLI-034).
- **Memlock**: without `CAP_IPC_LOCK`, the soft `RLIMIT_MEMLOCK` must be at
  least the sum over ports of `frame-count x frame-size` (rounded up to
  4 KiB pages; twice that for `mode = "auto"`) plus 64 KiB per port for the
  BPF objects. Otherwise exit 4 (`privileges code=MEMLOCK_LIMIT
  limit-bytes=L required-bytes=R`). Root has `CAP_IPC_LOCK`. The estimate is
  a lower bound (section 12).
- **Dedicated network namespace (recommended)**: run the router in its own
  namespace (`ip netns exec <ns> ruster run ...`) that holds only the port
  devices. Then no other interface needs kernel forwarding, the per-second
  address dump stays small, and `ip netns exec` remounts `/sys` for the
  namespace, which the session's sysfs reads need (section 12).
- **Kernel IPv4 forwarding off** in the router's namespace:
  `sysctl -w net.ipv4.ip_forward=0` and
  `sysctl -w net.ipv4.conf.<port>.forwarding=0`. Startup refuses otherwise
  (`checks code=KERNEL_FORWARDING_ENABLED scope=global|device`; unreadable:
  `UNVERIFIABLE probe=forwarding`). Why: whenever the router is not
  attached (before it starts, after any exit, after a crash or SIGKILL,
  when the unpinned XDP links detach by themselves) frames on the ports
  reach the kernel stack, and kernel forwarding would carry them between
  the ports around the firewall and NAT. With forwarding off and no kernel
  L3 on the ports the fallback is "no traffic", not "traffic without the
  firewall". If other interfaces of the namespace need forwarding, start
  with `--allow-kernel-forwarding` (the check only warns); prefer a
  dedicated namespace instead.
- **IPv6 off on the ports (required unless `--allow-kernel-ipv6`)**: the
  router is IPv4 only, so while it is detached the kernel's IPv6 stack is
  the only one on the ports. Set `sysctl -w
  net.ipv6.conf.<port>.disable_ipv6=1` for every port (persist it in
  `/etc/sysctl.d/` or in the namespace setup; it must be set again after
  the device is re-created). Then the kernel drops every IPv6 frame
  received on or sent through the port, removes its IPv6 addresses and
  routes, and refuses new ones, and the IPv6 checks pass without reading
  anything else. A kernel without IPv6 counts as disabled: no
  `/proc/sys/net/ipv6` while `/proc/sys/net/ipv4` exists (for example
  `ipv6.disable=1`); anything else that leaves the flag unreadable is
  `UNVERIFIABLE probe=ipv6-disabled`.

  With IPv6 on (`disable_ipv6=0`, the default of every new device and
  namespace) startup is refused, even with only the kernel's link-local
  address. What is reachable through such a port while the router is
  detached: Linux implements the weak host model and IPv6 has no
  `rp_filter`, so a frame arriving on the port for *any* local IPv6
  address of the host (a global address on another interface, for
  example) is delivered to local sockets, and services listening on
  `[::]` (sshd, tunnels, DNS, ...) answer through the port; the port's own
  link-local address answers Neighbor Discovery and ICMPv6 on the segment.
  Link-local alone does not let the kernel *forward* between the ports (a
  link-local source or destination is never forwarded, RFC 4291 2.5.6),
  but host services are exposed. The specific findings are reported first
  (each refused on its own code), then the general one:
  - an IPv6 fact that cannot be read (`UNVERIFIABLE
    probe=ipv6-disabled|ipv6-addresses|ipv6-routes|ipv6-forwarding`);
  - an IPv6 address outside `fe80::/10` on the port
    (`checks code=KERNEL_IPV6_ADDRESSES count=N`), for example from SLAAC
    (`accept_ra`) or DHCPv6;
  - an IPv6 route out of the port in any table other than the kernel's
    automatic `fe80::/64`, link-local `local`/`anycast` and
    `multicast ff00::/8` routes (`KERNEL_IPV6_ROUTES count=N`), for
    example a default route learnt from a Router Advertisement;
  - IPv6 forwarding (`KERNEL_IPV6_FORWARDING_ENABLED scope=...`):
    `net.ipv6.conf.all.forwarding=1` (`scope=global`, what `ip6_forward()`
    reads), `conf/<port>/forwarding=1` (`scope=device`; on its own it does
    *not* enable IPv6 forwarding, it switches the device to router
    behaviour for Neighbor Discovery and Router Advertisements, but it is
    checked anyway), `conf/<port>/force_forwarding=1` or
    `conf/all/force_forwarding=1` (`scope=force`, Linux 6.17+: forwards
    what arrives on that device even with `all.forwarding=0`; an absent
    file is off), and `conf/<port>/mc_forwarding` or
    `conf/all/mc_forwarding` (`scope=multicast`, set while an IPv6
    multicast routing daemon runs; absent is off);
  - otherwise `KERNEL_IPV6_ENABLED`.

  `--allow-kernel-ipv6` accepts all of the above with warnings
  (`IPV6_ENABLED_ALLOWED` and the codes of section 3); `disable_ipv6=1` is
  the fix.
- **IPv4 weak host (warning only)**: an address-less port still receives,
  while detached, frames for any local IPv4 address of the host, and with
  `arp_ignore=0` answers ARP for them. When the effective `rp_filter` (the
  larger of `conf/all` and `conf/<port>`) and the effective `arp_ignore`
  are both 0, or cannot be read, startup warns `IPV4_WEAK_HOST_EXPOSURE`
  and the watch warns `health=IPV4_WEAK_HOST_EXPOSURE` (recovered when
  fixed). It is never refused (whether it should be is an open owner
  question, CLI-034). Set `net.ipv4.conf.all.arp_ignore=1` and
  `net.ipv4.conf.all.rp_filter=1` (or 2) in the router namespace.
- **Port devices** (each checked at startup, refused otherwise):
  - exactly one RX queue: `ethtool -l lan0`, then `ethtool -L lan0 combined 1`
    (or `rx 1`). The count is rtnetlink's `IFLA_NUM_RX_QUEUES`, the number
    the driver *allocated*: a NIC that allocates several queues but runs one
    after `ethtool -L ... combined 1` still counts as multi-queue. If the NIC
    must keep several queues, steer every frame to the bound queue with
    RSS/ntuple (`ethtool -X`, `ethtool -N`), confirm with `ethtool -l`, and
    start with `--allow-multi-queue` (warning `MULTI_QUEUE_ALLOWED
    rx-queues=N`). Frames on other queues are dropped by the XDP program.
    The steering is not verified by `ruster run`.
  - a TX queue with the bound queue number (else `open
    code=TX_QUEUE_CHECK/NO_TX_QUEUE`).
  - an MTU whose frames fit a UMEM frame: `mtu + 14 <= frame-size - 256 -
    headroom` (1778 for 2048-byte frames, 3826 for 4096 with `headroom =
    0`). Otherwise `checks code=MTU_ABOVE_FRAME mtu=M limit=L`.
  - no kernel IPv4 address and no kernel IPv4 route out of the port in any
    table (main, local, and every policy-routing table; a multipath route
    with one nexthop on the port counts): `ip -4 addr flush dev lan0`;
    `ip -4 route show table all dev lan0` must be empty, and so must
    `ip -4 route show table all | grep -w lan0` for multipath routes.
    Leave the device up (`ip link set lan0 up`). The route check reads
    rtnetlink `RTM_GETROUTE` of every table with the kernel's own device
    filter (`NETLINK_GET_STRICT_CHK` and `RTA_OIF`, which matches every
    nexthop, multipath and `ip nexthop` objects included) and matches
    again in userspace. A route the kernel returns that names only a
    nexthop object (`net.ipv4.nexthop_compat_mode=0`) is counted (fail
    closed: the kernel's filter said one of its nexthops uses the port).
  - IPv4 `mc_forwarding` off: `conf/all/mc_forwarding` and
    `conf/<port>/mc_forwarding` are 1 while a multicast routing daemon
    (`smcroute`, `pimd`) runs; refused as `KERNEL_FORWARDING_ENABLED
    scope=multicast` unless `--allow-kernel-forwarding`.
  - no other XDP program: `ip -details link show dev lan0` must not show
    `prog/xdp`. `ruster run` never replaces or detaches a program it did
    not attach.
  - IPv6 off (see above), unless `--allow-kernel-ipv6`.
- **Config file permissions (optional)**: `--strict-config-perms` (section 3).

## 2. Install and run

Build and install the binary (no external libraries; libbpf is not used):

```bash
cargo build --release --locked -p ruster-cli
sudo install -m 0755 target/release/ruster /usr/local/bin/ruster
ruster --version
```

Recommended namespace setup (the ports moved into a dedicated namespace,
kernel L3 off on them; `lan0`/`wan0` stand for the port devices):

```bash
sudo ip netns add router
for dev in lan0 wan0; do
    sudo ip link set "$dev" netns router
    sudo ip netns exec router sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"   # required
    sudo ip netns exec router sysctl -qw "net.ipv4.conf.$dev.forwarding=0"
    sudo ip -n router -4 addr flush dev "$dev"
    sudo ip -n router link set "$dev" up
done
sudo ip netns exec router sysctl -qw net.ipv4.ip_forward=0
sudo ip netns exec router sysctl -qw net.ipv6.conf.all.forwarding=0
sudo ip netns exec router sysctl -qw net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.rp_filter=1
sudo ip -n router route show table all   # nothing may name lan0 or wan0
```

Check the config, then start in the foreground:

```bash
ruster validate /etc/ruster/router.toml   # exit 0; summary ends with backend=af-xdp ports=N umem-bytes=B
sudo ip netns exec router ruster run --config /etc/ruster/router.toml
```

systemd example (the unit must run inside the router's namespace, for
example with `NetworkNamespacePath=/run/netns/router`):

```ini
[Service]
NetworkNamespacePath=/run/netns/router
ExecStart=/usr/local/bin/ruster run --config /etc/ruster/router.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=1
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON
LimitMEMLOCK=infinity
KillSignal=SIGTERM
TimeoutStopSec=10
```

`Restart=on-failure` restarts after exit 1, 3 and 4 and after a crash;
exit 2 (usage or invalid config) also restarts under this setting, so fix
the config first. `TimeoutStopSec` must exceed the 2 s drain plus the 1 s
output wait (section 9).

## 3. Command line

```text
ruster run [--allow-multi-queue] [--allow-kernel-forwarding]
           [--allow-kernel-ipv6]
           [--strict-config-perms] [--stats-interval <seconds>]
           [--startup-attempts <n>] [--tx-stall-warn-secs <s>]
           [--tx-stall-fatal-secs <s>] [--kick-errors-fatal-secs <s>]
           --config <config.toml>
ruster run [options] -- <config.toml>
```

| flag | default | accepted | effect |
|---|---|---|---|
| `--config <path>` (or `--config=<path>`, or `-- <path>`) | required | a regular file | the config read at startup and on every reload |
| `--allow-multi-queue` | off | flag | accept a port with more than one RX queue (warned, section 1) |
| `--allow-kernel-forwarding` | off | flag | warn instead of refusing kernel IPv4 forwarding at startup (`IPV4_FORWARDING_ENABLED scope=global\|device`, `IPV4_FORWARDING_UNVERIFIABLE`); at run time an unreadable forwarding sysctl then warns `FORWARDING_UNVERIFIABLE` instead of counting as a failed query |
| `--allow-kernel-ipv6` | off | flag | warn instead of refusing IPv6 enabled on a port and everything found with it (section 1): `IPV6_ENABLED_ALLOWED`, `IPV6_ADDRESSES_ALLOWED count=N`, `IPV6_ROUTES_ALLOWED count=N`, `IPV6_FORWARDING_ENABLED scope=global\|device\|force\|multicast`, `IPV6_UNVERIFIABLE probe=ipv6-*` at startup; at run time an unreadable IPv6 fact then warns `IPV6_UNVERIFIABLE` instead of counting as a failed query (the exposure warnings, `KERNEL_IPV6_ENABLED` included, are given either way). Risk: while the router is detached (before start, after any exit, after a crash) the kernel's IPv6 stack receives on the ports: every local IPv6 address of the host and the services bound to `[::]` are reachable through them (weak host model), and with IPv6 forwarding on the kernel forwards IPv6 between the ports or to its other interfaces without the router's firewall. One flag for the whole IPv6 stack, because the router does not handle IPv6 and the safe setting is `disable_ipv6=1`; it does not touch any IPv4 refusal, and `--allow-kernel-forwarding` does not cover IPv6 |
| `--strict-config-perms` | off | flag | refuse a config (startup and reload) that group/other may write (`WRITABLE_BY_OTHERS`), owned by neither root nor the effective user (`UNTRUSTED_OWNER`), with a symbolic link in its path (`SYMLINK_IN_PATH`), or in a directory up to `/` that is not owned by root/the user (`UNTRUSTED_DIRECTORY`) or is group/other writable (`WRITABLE_DIRECTORY`; a root-owned sticky directory such as `/tmp` is allowed); any error checking it is `OWNER_UNVERIFIABLE` |
| `--stats-interval <s>` | 60 | 0 to 86400 | seconds between periodic stats blocks on stdout; 0 disables them (the final block is always printed) |
| `--startup-attempts <n>` | 3 | 1 to 10 | whole startups tried on a transient open failure (section 5); 1 disables the retry |
| `--tx-stall-warn-secs <s>` | 1 | 1 to 3600 | `TX_STALL` warning delay |
| `--tx-stall-fatal-secs <s>` | 10 | 0 to 3600 | `TX_STALL` fatal exit; 0 never; otherwise at least `--tx-stall-warn-secs` |
| `--kick-errors-fatal-secs <s>` | 5 | 0 to 3600 | `KICK_ERRORS` fatal exit; 0 never |

Numbers are decimal digits only (at most 6, no sign). Every option may be
given once; `-h`/`--help` prints the usage. The thresholds and intervals
are set at start and are not reloadable. The config file is always opened
`O_NONBLOCK | O_NOCTTY` and must be a regular file (a FIFO or device is
`NOT_A_FILE`).

Signals: SIGINT/SIGTERM stop (a second one forces the drain to end),
SIGHUP reloads the config. SIGHUP never ends `ruster run`, also not when
its terminal hangs up or under `nohup`.

## 4. Exit status

| status | meaning |
|---|---|
| 0 | ordered shutdown after SIGINT/SIGTERM with no TX frame left in the kernel; also a signal during startup or during a retry pause, after a clean rollback |
| 1 | runtime failure: unreadable or refused config file; a startup failure at any stage after the config (open, checks, attach, watch, datapath, engine, adapter, activate, storage, key source; a transient open failure after the last attempt); a backend fault, a fatal health or device event, or an invariant violation during the run; a drain failure; a stranded TX handoff; a close error; signal handler or output thread setup failure; unsupported platform |
| 2 | usage error, or invalid config (`parse`, `version`, `validate`, the `sim` backend, or `candidate code=MISSING_SERVICE_*`) |
| 3 | the shutdown drain deadline (or a second signal) left TX frames with the kernel; everything was still detached and closed |
| 4 | missing capability, too small `RLIMIT_MEMLOCK`, or unreadable `/proc/self/status`/`/proc/self/limits`; nothing was acquired |
| 101 | a panic (section 9) |

A refused or failed reload never ends the run.

## 5. Cold start

1. `ruster validate router.toml`, then `ruster run --config router.toml`.
2. Startup order: read and validate the config (no service bridge yet),
   signal handlers, `/dev/urandom` key source, output threads,
   generation-1 candidate, runtime storage, privilege and memlock
   preflight, then per port in interface-id order: open the session (TX
   queue and MTU read from sysfs), device checks (rtnetlink, procfs), XDP
   attach; then the link-watch socket, every datapath, every engine, the
   adapter, and activation of generation 1.
3. Ready when stderr shows
   `ruster run: running generation 1 on N port(s); send SIGINT or SIGTERM to
   stop, SIGHUP to reload`.
   `ip -details link show dev lan0` then lists `prog/xdp id <n>` (`xdp`, or
   `xdpgeneric` with `xdp-attach = "generic"`).
4. Warnings (`ruster run: warning: port=if<id> <CODE>`) do not stop startup:
   `MULTI_QUEUE_ALLOWED rx-queues=N` (with `--allow-multi-queue`), with
   `--allow-kernel-forwarding` `IPV4_FORWARDING_ENABLED scope=global|device`
   and `IPV4_FORWARDING_UNVERIFIABLE`, and with `--allow-kernel-ipv6`
   `IPV6_ENABLED_ALLOWED`, `IPV6_UNVERIFIABLE probe=...`, `IPV6_ADDRESSES_ALLOWED count=N`,
   `IPV6_ROUTES_ALLOWED count=N`, and `IPV6_FORWARDING_ENABLED
   scope=global|device|force|multicast`; always (never refused)
   `IPV4_WEAK_HOST_EXPOSURE`.

### Startup refusals

A failure after the config is loaded rolls back completely (every opened
port closed, last first, XDP detached) and prints
`ruster run: startup failed: stage=<stage> [port=if<id>] code=<code>`. Config
problems print `ruster: cannot read config: <CODE>`, `ruster: refused config:
stage=permissions code=<CODE>`, or `ruster: invalid config: stage=<stage>
code=<CODE> [path=<schema path>] [limit=L actual=A]`; the `sim` backend
prints `ruster run: invalid config: stage=backend code=SIM_BACKEND`. Verify
with `ip -details link show` that no `prog/xdp` is left, fix, and start
again. Session and attach codes are `<STEP>/<FAILURE>` tokens of the native
error (`BIND/BUSY`, `CREATE_LINK/EXISTING_PROGRAM`, `ERRNO_<n>` for another
errno). The table of all of them with actions is section 14.

### Startup retry (XDP-045)

Right after a previous run (or a crash) the kernel releases the old
sockets' queue registration and UMEM accounting from deferred work, so a
port open can fail transiently. `ruster run` retries the whole port
startup on exactly these failures: `open code=BIND/BUSY`,
`open code=REGISTER_UMEM/MEMLOCK_LIMIT` or `REGISTER_UMEM/OUT_OF_MEMORY`, and
any `.../ERRNO_11` (`EAGAIN`). Before each retry every opened port is
rolled back, and stderr shows

```text
ruster run: startup attempt 1 of 3 failed: stage=open port=if2 code=BIND/BUSY; rolled back 1 port(s), retrying in 250 ms
```

The pause starts at 250 ms and doubles up to 2 s; `--startup-attempts`
bounds the attempts. The candidate, storage and privilege preflight are not
repeated. Every other failure is final at once. A signal during the pause
cancels (`startup cancelled by signal; rolled back N port(s)`, exit 0).

### Output never blocks the router

stdout and stderr are written by separate output threads. The router
thread only queues complete lines and stats blocks with a bounded,
non-blocking hand-off (64 messages per stream). When the pipe behind a
stream is full or nobody reads it (a stuck log collector, `ruster run |
less` left alone), further messages are dropped and counted in
`output.dropped` of the next stats block that gets through. Ticks, the
stop flag, the drain and the detach never wait for output. At exit the
process waits at most 1 s for queued output, then exits anyway; the final
stats block and summary can then be lost (the teardown itself completed).

## 6. Config reload (SIGHUP)

1. Write the new config to a new file and `mv` it over the file given to
   `--config` (a reload never reads a half-written file). Check it first:
   `ruster validate new.toml` and `ruster plan current.toml new.toml`.
2. `kill -HUP <pid>` (`systemctl reload`). The router takes the request
   between two ticks and prints `reload requested (generation G)`. SIGHUPs
   that arrive while one reload is pending are coalesced into one more.
3. The file is read and validated like at startup (same limits, regular
   file only, `--strict-config-perms` applies), a successor generation is
   built with fresh keys, and the plan is checked against the running
   generation. One line reports the outcome:

   | line | meaning |
   |---|---|
   | `reload applied: generation=N previous=P; interfaces=.. addresses=.. routes=.. neighbors=.. firewall-rules=.. nat44-ports=..; flushed dynamic-neighbors=.. resolution-states=.. nat44-udp-mappings=.. nat44-tcp-sessions=.. firewall-flows=..` | active from this tick on. Compare the counts with what you meant to load (a truncated file that still validates shows fewer rules or routes; `routes` includes connected routes) |
   | `reload refused: code=RESTART_REQUIRED reasons=<R>[,<R>...]; generation P keeps running` | the change needs a restart; nothing changed |
   | `reload failed: stage=<stage> code=<code>[ path=...]; generation P keeps running` | nothing changed. Stages: `read`, `permissions`, `parse`, `version`, `validate`, `candidate`, `plan`, `dry-run`, `apply`, `quiesce` (`code=TIMEOUT`: not quiescent within 200 ms; `code=STOPPED`: the run stopped while the reload waited) |

4. Restart-required reasons (`R`): `BACKEND` (anything in `[backend]`:
   device, queue, mode, attach, rings, UMEM; also an interface `device`
   change, because the port binds the device), `INTERFACES` (interface ids
   or MACs), `STORAGE_SHAPE` (a capacity, including the NAT port pool
   size), `RESOLUTION_POLICY`, `ICMPV4_ERROR_POLICY`. Routes, neighbors,
   addresses, firewall rules and policy, NAT realm, port range shift,
   filtering and hairpinning, `[ipv4-origin]` and `[tick]` budgets reload in
   place (`ruster plan` shows which).
5. State: an applied reload flushes ARP learning, pending resolution and
   ICMPv4 errors, and every NAT44 mapping and firewall flow (their hash
   keys rotate with each generation; established TCP through NAT must
   reconnect). Cumulative counters are kept. Every reload request consumes
   a generation number, so after a refusal or failure the next applied
   generation skips one.
6. Timing: the switch happens at a tick boundary once the backend is
   quiescent (no TX frame of the old generation in flight). While it waits
   the router reads no RX for at most 200 ms; parsing and planning also
   run on the router thread (a few milliseconds). Reload when traffic is
   low: a busy port's RX ring (`rings.rx` entries) can overflow, which shows
   as rising `if<id>.af_xdp_port.kernel_rx_ring_full` and
   `kernel_rx_dropped`.
7. Counters: `reload.requested`, `reload.applied`, `reload.refused`,
   `reload.failed`; in the final block `requested = applied + refused +
   failed`. If the backend reports a commit without its report
   (`previous=unknown`, `code=APPLY_REPORT_MISSING`) the publication contract
   is broken: the run ends (`stopped after an invariant violation
   code=APPLY_REPORT_MISSING`) and exits 1.

## 7. Health and stall signals

The router samples every port's backend counters every 500 ms (cold path)
and prints a value-free line when a condition starts or ends:
`ruster run: warning: port=if<id> health=<CODE>` and
`ruster run: recovered: port=if<id> health=<CODE>`. A fatal condition prints
`ruster run: fatal: port=if<id> health=<CODE>`, then the shutdown of
section 9 runs and exits 1. `watch.state` is `warning` while any condition
holds.

| code | condition | warning | fatal (exit 1) |
|---|---|---|---|
| `TX_STALL` | TX is in flight and the oldest in-flight frame has not completed, while the link is up | after `--tx-stall-warn-secs` (1) | after `--tx-stall-fatal-secs` (10; 0 never) |
| `FILL_STARVED` | no Fill frame with the kernel, no RX, and the free list was empty when refilling | after 1 s (fixed) | never (the frames are held by TX, which `TX_STALL` covers) |
| `KICK_ERRORS` | kick failures other than `ENETDOWN` grew in every sample | at the first growth | after `--kick-errors-fatal-secs` (5; 0 never) of growth in every sample |

A busy healthy link never trips these: completions retire the oldest
frame, RX keeps arriving, kicks succeed. A link that is down holds its TX
by design, so `TX_STALL` is not timed while it is down.

A TX stall can be caused from the wire: a host on a port's segment that
floods 802.3x PAUSE frames stops a NIC with flow control from
transmitting, and with the default fatal exit can make the router exit
(and restart in a loop under `Restart=on-failure`). The default stays fatal
because the router then fails closed (no kernel forwarding, no kernel L3 on
the ports) and a stuck TX queue usually needs the restart. If availability
under a hostile segment matters more, disable flow control
(`ethtool -A <dev> rx off tx off`) and/or run with `--tx-stall-fatal-secs 0`.

Separately, if the adapter's I/O stays non-reentrant for 1024 ticks in a row
(about a second, the wedged-adapter watchdog), or the adapter stops itself
after a ring fault, the run ends with `stopped after a backend fault` and
exit 1.

## 8. Link and device events

Every second the router queries each port's interface index over
rtnetlink (`RTM_GETLINK`, namespace correct), dumps the namespace's IPv4
addresses (`RTM_GETADDR`) and IPv4 routes of every table
(`RTM_GETROUTE`), reads the IPv4 forwarding sysctls (`mc_forwarding`
included) and `rp_filter`/`arp_ignore` (procfs), and then the port's
`disable_ipv6`; unless it is 1 it also reads the IPv6 forwarding sysctls
(`force_forwarding` and `mc_forwarding` included) and dumps the IPv6
addresses and routes. The dumps are filtered by the kernel to the port
(strict checking). A failed query replaces the socket, so an aborted dump
cannot leave the next query facing `EBUSY`. All of it runs on the
router thread, on one reused socket and buffer, without allocation:

| event | outcome |
|---|---|
| link down (`ip link set lan0 down`, cable out: `IFF_UP` or `IFF_LOWER_UP` clear) | warning `LINK_DOWN`, `if<id>.watch.link_down_events` +1; keeps running; owed TX is kicked again when the link returns (recovered `LINK_DOWN`, `link_up_events` +1) |
| device removed (`ip link del`, driver unbind, moved to another namespace) | fatal `DEVICE_REMOVED` |
| MTU below the startup MTU | fatal `MTU_DECREASED` (TX is bounded by the startup MTU; longer frames could be stranded in the kernel) |
| MTU above what a frame holds (`frame-size - 256 - headroom - 14`) | fatal `MTU_ABOVE_FRAME` |
| MTU raised within that bound | warning `MTU_RAISED`, recovered when it returns; TX stays bounded by the startup MTU until a restart |
| a query fails | warning `LINK_PROBE`; fatal `LINK_UNVERIFIABLE` after 3 failures in a row. The link query, each dump (IPv4 addresses, IPv4 routes, IPv6 addresses, IPv6 routes) and the procfs reads (IPv4 forwarding; `disable_ipv6` with the IPv6 forwarding sysctls) each count their own failures |
| a kernel IPv4 address appears on a port | warning `KERNEL_IPV4_ADDRESSES` (`if<id>.watch.kernel_ipv4_addresses`), recovered when gone; keeps running |
| a kernel IPv4 route out of a port appears in any table (policy routing and multipath nexthops included) | warning `KERNEL_IPV4_ROUTES` (`if<id>.watch.kernel_ipv4_routes`), recovered when gone; keeps running |
| `net.ipv4.ip_forward`, `conf/<port>/forwarding`, or an IPv4 `mc_forwarding` turns on | warning `KERNEL_FORWARDING_ENABLED` (`if<id>.watch.kernel_forwarding`), recovered when off; keeps running |
| effective `rp_filter` and `arp_ignore` both 0 (or unreadable) | warning `IPV4_WEAK_HOST_EXPOSURE` (`if<id>.watch.ipv4_weak_host`), recovered when either is set; never fatal, never a failed query |
| `disable_ipv6` flips to 0 on the port | warning `KERNEL_IPV6_ENABLED` (`if<id>.watch.kernel_ipv6_enabled`), recovered when it is 1 again; keeps running |
| a forwarding sysctl becomes unreadable (for example the device renamed) | a failed query; with `--allow-kernel-forwarding` a warning `FORWARDING_UNVERIFIABLE` instead |
| with IPv6 on for the port: an IPv6 address outside `fe80::/10` appears | warning `KERNEL_IPV6_ADDRESSES` (`if<id>.watch.kernel_ipv6_addresses`), recovered when gone; keeps running |
| ... an IPv6 route out of the port beyond the automatic link-local and multicast ones | warning `KERNEL_IPV6_ROUTES` (`if<id>.watch.kernel_ipv6_routes`), recovered when gone; keeps running |
| ... `net.ipv6.conf.all.forwarding`, `conf/<port>/forwarding`, a `force_forwarding`, or an IPv6 `mc_forwarding` turns on | warning `KERNEL_IPV6_FORWARDING_ENABLED` (`if<id>.watch.kernel_ipv6_forwarding`), recovered when off; keeps running |
| `disable_ipv6=1` set on the port | every IPv6 warning of the port recovers (nothing IPv6 is exposed) |
| an IPv6 fact becomes unreadable | a failed query of its kind; with `--allow-kernel-ipv6` a warning `IPV6_UNVERIFIABLE` instead, recovered when every IPv6 fact reads again |

Why forwarding, addresses and routes only warn while running: while XDP
is attached the kernel never sees a frame from a port, so they change
nothing. A fatal exit would detach XDP, which is exactly what would let the
kernel forward around the firewall and NAT, and a supervised restart would
then be refused at startup. Fix the namespace while it runs (`sysctl -w
net.ipv4.ip_forward=0`, `ip addr flush dev <port>`, `ip route del ...
table <id>`, `sysctl -w net.ipv6.conf.<port>.disable_ipv6=1`). For each kind
the last round still saw when `ruster run` exits, the exit prints one
line: `warning: kernel forwarding is enabled; detached ports may be
forwarded by the kernel`, `warning: kernel IPv4 addresses are on a port;
detached ports may be answered and routed by the kernel`, `warning: kernel
IPv4 routes lead out of a port; detached ports may be routed by the
kernel`, `warning: kernel IPv6 forwarding is enabled for a port; detached
ports may be forwarded by the kernel`, `warning: kernel IPv6 is enabled on
a port; detached ports may be answered by the kernel's IPv6 stack`,
`warning: kernel IPv6 addresses are
on a port; detached ports may be answered and routed by the kernel`, and
`warning: kernel IPv6 routes lead out of a port; detached ports may be
routed by the kernel`.

TX while a port is down: with the port administratively down (`IFF_UP`
clear), every TX kick fails `ENETDOWN`, the kernel consumes no TX
descriptor, and forwards to the port fill its TX ring
(`if<id>.af_xdp_port.tx_inflight` reaches the ring size, then
`tx_ring_full`/`tx_blocked` and `rx.tx_rejected` count the frames that no
longer fit; they are dropped). A
port that is down is `LINK_DOWN` only: neither `TX_STALL` nor
`KICK_ERRORS` is timed, whatever the thresholds (an `ENETDOWN` from the
shutdown drain's kick or from a Fill kick is counted in `kick_errors` but
not in `kicks_link_down`; the drain runs after the watch stops, and a Fill
`poll` kick failing `ENETDOWN` is theoretical). While the port is down
the owed TX kick is retried with a backoff, not at every settle: the
first `ENETDOWN` is immediate, the next retry comes 1 ms later, and each
further wait doubles up to 64 ms, so a port that stays down costs about
16 `sendto` calls per second (`if<id>.af_xdp_port.kicks_link_down`); a
settle before the retry is due only reaps and counts
`kick_retries_suppressed`. When the link returns, the held frames are
transmitted at the next retry, within about 64 ms (plus up to one 1 ms
idle pause) and without new
traffic (they may be stale by then), and the ring drains; the backoff
starts again at 1 ms on the next down period. With only carrier lost (`IFF_LOWER_UP` clear, for example the
peer down), the kernel consumes and drops the frames instead, so the ring
does not fill. A cross-port forward also needs a free generated frame of
the egress port, so with `generated-frames` below the TX ring size the
copy pool runs out first (`cross_port_copy_unavailable`). The XDP veth
smoke runs this case (release evidence, criterion 5).

After a fatal device event the summary starts with `stopped after a fatal
health event port=if<id> code=<CODE>` and the exit status is 1, so
`Restart=on-failure` restarts with the new device state (after a removal
the device must exist again, or startup fails at `open`).

## 9. Graceful shutdown and drain

1. Send SIGTERM (or SIGINT): `kill -TERM <pid>` / `systemctl stop`. stderr
   shows `ruster run: stop requested; draining`.
2. The router stops ticking (no RX, no TX), drains every port for at most
   2 s (leases and staged handoffs reclaimed, completions reaped, owed TX
   kicked), prints the final stats block on stdout, detaches XDP by closing
   each link, closes every socket and UMEM, and prints on stderr:

   ```text
   ruster run: stopped by signal; drain calls=C completed=K rx-released=R tx-in-flight=T tx-handoffs=H fill-in-kernel=F forced=false timed-out=false last-kick-error=none; detached and closed N port(s)
   ```

   | field | meaning |
   |---|---|
   | `calls` | drain calls made |
   | `completed` | TX completions reaped during the drain |
   | `rx-released` | received frames that were never lent and were returned |
   | `tx-in-flight` | TX frames still owned by the kernel at the end (released by the socket close) |
   | `tx-handoffs` | staged TX handoffs no code path could cancel; above 0 is an internal fault (exit 1; the frames were never in the kernel) |
   | `fill-in-kernel` | Fill frames with the kernel; always released by the close, normal |
   | `forced` | a second signal cut the drain short |
   | `timed-out` | the 2 s deadline passed |
   | `last-kick-error` | `none`, or the last kick failure the drain saw as `if<id>:<TOKEN>` (for example `if2:NETWORK_DOWN`) |

3. Exit 0 means no TX frame was left with the kernel; exit 3 means
   `tx-in-flight` was above 0 (deadline or second signal). Nothing stays
   attached in either case.
4. If a close failed, stderr shows `close failed: port=if<id> code=<STEP>[
   errno=<n>]` and the tail reads `detached and closed K of N port(s); see
   close failed`; exit 1.
5. Confirm: `ip -details link show dev lan0` shows no `prog/xdp`.

The summary starts with `stopped after a backend fault`, `stopped after a
fatal health event port=if<id> code=<CODE>`, or `stopped after an invariant
violation code=APPLY_REPORT_MISSING` when the run ended for those reasons
(exit 1), and `drain failed: code=<CODE>` precedes it when the drain itself
failed (exit 1). Every port is still closed.

### Panics

`ruster run` keeps Rust's default `panic = "unwind"`. A panic on the router
thread unwinds through the run: the adapter and engines are dropped and the
startup guard closes every opened session, last first, which detaches XDP;
the process exits with status 101 and the panic message on stderr, with no
summary or final stats. A panic during that unwinding aborts the process
(SIGABRT); the kernel then closes every fd and the unpinned links detach as
after SIGKILL.

## 10. Forced termination and restart

1. `kill -KILL <pid>` (or a crash, OOM kill): no drain, no final stats. The
   kernel closes every fd; the XDP links are unpinned, so the programs
   detach by themselves within milliseconds. Confirm with
   `ip -details link show dev lan0` (no `prog/xdp`). While detached, frames
   reach the kernel stack: keep the ports free of kernel L3 and forwarding
   off (section 1).
2. Restart with the same command. The first attempt can fail transiently
   with `open code=BIND/BUSY` or `REGISTER_UMEM/MEMLOCK_LIMIT`; `ruster run`
   rolls back and retries (section 5). If every attempt fails it exits 1
   fully rolled back, and systemd `Restart=on-failure` starts it again.
3. A restarted process begins at generation 1 with fresh keys; no state
   (NAT mappings, firewall flows, dynamic neighbors) survives.

## 11. Stats

Every `--stats-interval` seconds stdout carries one block, and the final
block is printed at shutdown. Only counters, gauges, flags, fixed labels,
generations and interface ids appear: no key, address, MAC, device name,
packet byte, fd or pointer.

```text
ruster-run-stats kind=periodic|final uptime-ms=<ms>
<section>.<key>=<value>
...
output.dropped=<n>
end
```

Sections, in this order:

| prefix | content |
|---|---|
| `observer.*`, `tick.*`, `rx.*`, `generated_arp.*`, `generated_icmpv4.*`, `phase_skip.*`, `drop.<REASON>`, `consume.<REASON>`, `apply.*`, `flushed.*`, `occupancy.*` | worker observability: health state (`observer.state`: `healthy`, `degraded`, `stale`, `stopped`, `not_started`), active generation, tick totals, RX totals (`rx.received`, `rx.tx_accepted`, `rx.tx_rejected`, `rx.dropped`, `rx.consumed`, ...), drop/consume reason counts, last apply outcome and flush counts, NAT/FW/ICMP limiter occupancy and high-water |
| `resolution.*`, `icmpv4_errors.*`, `nat44_udp.*`, `nat44_tcp.*`, `firewall.*` | the five service runtimes' cumulative counters |
| `af_xdp.*` | all ports: `mode` (`copy`, `zero_copy`, `mixed`), `ports`, `copy_ports`, `zero_copy_ports`, `fill_need_wakeup_ports`, `tx_need_wakeup_ports`, `link_down_ports`, `kick_owed_ports`, `kernel_stats_ports`, `generated_unknown_egress`, `stopped`, and the summed port counters |
| `if<id>.af_xdp_port.*` | per port: `interface`, `queue`, `mode`, `mtu`, `max_frame`, need-wakeup now, `draining`, `link_down`, `kick_owed`, `copy_reserve`, ring gauges (`fill_ring_occupancy`, `rx_ring_occupancy`, `tx_ring_unconsumed`), `fill_starved`, invalid RX descriptors and quarantines, TX (`tx_completed`, `tx_inflight`, `tx_inflight_highwater`, `tx_blocked`, `tx_over_mtu`, `tx_invalid_completions`), kicks (`tx_kicks`, `fill_kicks`, `kicks_deferred`, `kick_errors`, `kicks_link_down`, `kick_retries_suppressed`; `kick_errors` counts every failed kick and so includes `kicks_link_down`, while the `KICK_ERRORS` health code times `kick_errors - kicks_link_down` only; `kick_retries_suppressed` counts settles on a down port that skipped a retry not yet due, which made no syscall), generated frames, `cross_port_copies`, and the kernel `XDP_STATISTICS` (`kernel_rx_dropped`, `kernel_rx_invalid_descs`, `kernel_tx_invalid_descs`, `kernel_rx_ring_full`, `kernel_rx_fill_ring_empty_descs`, `kernel_tx_ring_empty_descs`) |
| `reload.*` | `requested`, `applied`, `refused`, `failed` |
| `watch.*` | `state` (`ok`/`warning`), `warnings` (all ports) |
| `if<id>.watch.*` | `tx_stall`, `tx_stall_ms`, `fill_starved`, `kick_errors_persistent`, `link_up`, `link_down_events`, `link_up_events`, `mtu`, `link_probe_errors`, `kernel_ipv4_addresses`, `kernel_forwarding`, `kernel_ipv4_routes`, `kernel_ipv6_addresses`, `kernel_ipv6_routes`, `kernel_ipv6_forwarding`, `kernel_ipv6_enabled`, `ipv4_weak_host`, `warnings` |
| `output.dropped` | output messages dropped because a stream could not keep up |

What to watch in operation: `observer.state=healthy`, `watch.state=ok`,
`rx.received` growing, `drop.<REASON>`, `af_xdp.mode=copy`,
`if<id>.af_xdp_port.fill_starved`, `kernel_rx_dropped`,
`kernel_rx_ring_full`, `kernel_rx_fill_ring_empty_descs`, `tx_inflight` near
`rings.tx`, and `kernel_tx_invalid_descs` (not a health condition yet,
CLI-034).

## 12. Known limits

- One AF_XDP socket and one RX/TX queue per port; no multi-queue or worker
  sharding (M2b, owner decision 2a open). With `--allow-multi-queue` the
  steering is the operator's responsibility.
- Zero-copy (`mode = "zero-copy"` or `"auto"` on a zero-copy NIC) is not
  verified on any hardware. Port-to-port forwarding copies each frame once
  into the egress port's UMEM (shared UMEM is deferred, XDP-136).
- The RX queue count and the MTU checks use rtnetlink (`IFLA_NUM_RX_QUEUES`
  is the allocated count; section 1). The session itself still reads the
  TX queue and the MTU from sysfs after proving the sysfs `ifindex`; the
  startup check refuses (`UNVERIFIABLE probe=mtu`) when that MTU differs
  from rtnetlink's, which catches a foreign sysfs view with another MTU but
  not one with the same MTU. Run `ruster run` under `ip netns exec <ns>`,
  which remounts `/sys`.
- The link watch and the reload's parse and plan run synchronously on the
  router thread: one link query and up to four dumps (IPv4 addresses and
  routes, and with IPv6 on the port IPv6 addresses and routes) per second
  per port (the `send` blocks while another process holds the kernel's
  RTNL lock), and a reload for a few milliseconds; RX queues in the ring
  meanwhile and can overflow under load. The reload's quiescence wait holds
  RX back for at most 200 ms. Each dump lists the whole namespace (the
  route dumps every table), so its cost grows with every address and route
  the namespace holds: keep the router in a dedicated namespace with a
  small routing table, and set `disable_ipv6=1` on the ports, which skips
  both IPv6 dumps.
- A port that is administratively down with TX queued holds those frames
  in the kernel's ring, so a reload while it is down fails with
  `stage=quiesce code=TIMEOUT`; bring the link up first.
- Every reload rotates the NAT44 and firewall hash keys and flushes their
  state (PUB-006): reloading during busy NAT traffic drops established TCP
  sessions through NAT.
- The `FILL_STARVED` delay (1 s), the 3 failed queries, and the watch
  intervals (500 ms health, 1 s link) are fixed; the TX stall and kick
  error thresholds are flags (section 3), not reloadable.
- Kernel routes are attributed to a port by the kernel's device filter and
  then by `RTA_OIF` and `RTA_MULTIPATH` nexthops in userspace. With
  `net.ipv4.nexthop_compat_mode=0` (shared by IPv6) a route through a
  nexthop object carries only `RTA_NH_ID`; it is counted whenever the
  kernel's filter returns it (so a nexthop object used by another
  interface does not affect the router, and one used by a port refuses
  startup or warns at run time). Resolving the ids through
  `RTM_GETNEXTHOP` to confirm the device in userspace is a follow-up.
  `ip rule` policy itself is not inspected: a route out of a port counts
  in whatever table it is, used by a rule or not.
- The sysctl paths name the port device. If a port is renamed while the
  router runs, its sysctls become unreadable (a failed query,
  `LINK_UNVERIFIABLE` after three rounds); if another device then takes
  the old name, that device's sysctls are read until the next restart. Do
  not rename ports while the router runs.
- IPv4 weak host (`IPV4_WEAK_HOST_EXPOSURE`) only warns (section 1).
- The config is validated with the same limits as `run-sim`
  (`SIM_VALIDATION_LIMITS`); production limits are not decided yet.
- Capability diagnostics read `CapEff` in the caller's user namespace; in a
  non-initial user namespace the bits can look sufficient while BPF still
  needs init-namespace capabilities, so the failure appears later as
  `attach code=.../PERMISSION_DENIED`.
- Under `sudo` from an interactive terminal, Ctrl-C reaches `ruster run`
  both from the terminal's process group and relayed by sudo, so one key
  press can count as two signals and force the drain (`forced=true`). Use
  `kill -TERM <pid>` (or systemd) for a full drain; not verified on every
  setup.
- The memlock estimate adds 64 KiB per port for BPF objects (charged to
  `RLIMIT_MEMLOCK` before Linux 5.11) and is a lower bound: other processes
  of the same user, and a run that just exited, also hold locked memory.
- `/dev/urandom` is read with `read(2)`: before Linux 5.18 it can return
  output of an unseeded CRNG very early at boot (PUB-010); start the router
  after the system's entropy is initialized.
- Not implemented (CLI-034): `poll`-based waiting on the socket fds (the
  loop spins 64 ticks, then sleeps 50 µs doubling to 1 ms when idle),
  privilege drop, SIGUSR1 stats, structured logs, systemd notify, opt-in
  "link down / forwarding 0 at exit", state carried across a reload.
- While a port is down with TX held, its owed kick is retried about 16
  times per second (1 ms doubling to 64 ms, §8), so held TX resumes within about
  64 ms (plus up to one 1 ms idle pause) after the link returns; the run loop's link watch (1 s) does not
  shortcut the retry.
- Verified kernels: the development host and the CI runner only
  (XDP-062). A TX stall with the link up (`TX_STALL`) cannot be produced
  on veth and is tested only against a scripted kernel (CLI-050).

## 13. CI and E2E

The `XDP veth` job (`.github/workflows/xdp-veth.yml`, M2 S11) runs on every
pull request and push to `main`, on an `ubuntu-24.04` hosted runner with
passwordless sudo, with a 30-minute limit. It is not a required check
(owner decision 2e, 2026-11-02: 「当面は任意のまま」, optional for now).

What it proves, on the runner's kernel only:

- The environment can do AF_XDP at all. `scripts/priv-xdp-probe.sh` runs
  first and fails the job with one typed code instead of letting a later
  step skip: `PROBE_TOOL_MISSING`, `PROBE_SUDO`, `PROBE_KERNEL_TOO_OLD`
  (< 5.9), `PROBE_CAPABILITIES` (root's `CapEff` lacks NET_ADMIN, NET_RAW,
  IPC_LOCK, or BPF+PERFMON/SYS_ADMIN), `PROBE_IPROUTE_LIBBPF`,
  `PROBE_NETNS`, `PROBE_VETH`, `PROBE_SYSCTL`, `PROBE_AF_XDP_SOCKET`,
  `PROBE_XDP_GENERIC`, `PROBE_XDP_NATIVE`, `PROBE_CLEANUP`. Everything it
  does happens in a throwaway `ruster-probe-<pid>-<random>` namespace that
  it always deletes.
- The native layer on a real kernel: `scripts/priv-xdp-smoke.sh` (the
  `priv_xdp_*` phases: session, attach, engine, tx, generated, adapter,
  foreign program, SIGKILL holder).
- The operator flows of sections 5 to 10 end to end:
  `scripts/priv-run-smoke.sh`, in three dedicated namespaces with copy mode
  and native XDP on veth: forwarding with ARP, NAT44 and the firewall;
  SIGTERM with final stats; a SIGHUP reload that denies and then allows the
  forwarded UDP without a restart; a refused restart-required reload while
  traffic keeps flowing; link down/up with recovered forwarding; an MTU
  above the frame bound and a deleted port device, both exit 1 with
  nothing attached; rollback after a second-port failure and after a
  foreign program; the device checks; kernel forwarding refused by default,
  accepted with `--allow-kernel-forwarding`, and only warned while running;
  per-port `conf/<dev>/forwarding` refused (`scope=device`) and warned; an
  undrained stdout FIFO proven full before SIGTERM; SIGKILL and restart.
  Added by H2 (the router namespace is set up as recommended:
  `disable_ipv6=1` on every port, `all.arp_ignore=1`, `all.rp_filter=1`):
  IPv4 routes in a policy-routing table and a multipath route with one
  nexthop on a port refused; IPv6 enabled with only link-local refused
  (`KERNEL_IPV6_ENABLED`) and accepted with warnings under
  `--allow-kernel-ipv6`; a global IPv6 address refused (also with only
  `--allow-kernel-forwarding`) and accepted with warnings under the
  override; an IPv6 route in table 200, `all.forwarding=1`, and
  `conf/ra/force_forwarding=1` (printed as SKIPPED where the sysctl does
  not exist) refused; at run time `disable_ipv6` flipped to 0, a global
  address and its route, `force_forwarding`, an IPv4 route in table 300,
  and IPv6 forwarding warned and recovered with traffic forwarded and no
  fatal, exit warnings for what was still on; `rp_filter=0` with
  `arp_ignore=0` only warned; an IPv4 multicast routing socket
  (`mc_forwarding=1`) refused and accepted with `--allow-kernel-forwarding`
  (markers `priv_run_ipv6_enabled`, `priv_run_ipv6_address`,
  `priv_run_ipv6_route`, `priv_run_ipv6_forwarding`,
  `priv_run_ipv6_force_forwarding`, `priv_run_ipv6_runtime`,
  `priv_run_weak_host`, `priv_run_mc_forwarding`, and the extended
  `priv_run_checks`).
  Added by #305 (CI-005 to CI-007): `ruster validate` on every smoke config
  and an invalid one (exit 2, refused by `run` and by a SIGHUP reload with
  the same diagnostic), `ruster plan` verdicts that the running router then
  follows (reloadable applied, restart-required refused with the plan's
  reasons); router-generated ICMPv4 captured on host A (Echo Reply, Time
  Exceeded, Destination Unreachable Host, and Network after a reload that
  permits route misses), checked for type/code, TTL, TOS, checksums and
  the quote; a full WAN TX ring (port down, 128 of 128 in flight) held past
  tight fatal thresholds without a fatal and recovered with the held
  frames delivered and the counters adding up; `observer.state` and
  `watch.state` in the stats blocks.
- Nothing is left behind: a final step fails if any `ruster-*` namespace
  survives. Smoke logs are uploaded as an artifact when the job fails.

Both smokes run with `RUSTER_REQUIRE_PRIV=1`: the privileged tests then
fail (`PRIV_REQUIRED: ...`) rather than skip when `RUSTER_PRIV_XDP` is
missing or their phase is not selected, and the scripts refuse any value
but `1` (an empty value counts as unset). Without the variable a plain
`cargo test` keeps skipping them. `priv-xdp-smoke.sh` also fails when the
test binary's `priv_xdp_*` tests differ from the phases it runs.

Not covered: zero-copy NICs, kernels other than the runner's (5.9 to 6.x,
XDP-062), multi-queue, a TX stall with the link up (`TX_STALL`; veth
cannot produce one, CLI-050 uses a scripted kernel), `observer.state`
`degraded`/`stale` (unit tests only), and performance (X05).

To run the same sequence locally (Linux 5.9+, passwordless `sudo -n`,
iproute2 with libbpf, `python3`, `ethtool`):

```bash
scripts/priv-xdp-probe.sh
RUSTER_REQUIRE_PRIV=1 scripts/priv-xdp-smoke.sh
RUSTER_REQUIRE_PRIV=1 scripts/priv-run-smoke.sh
```

Set `TMPDIR` to a roomy directory if `/tmp` is small. The scripts create
their veth pairs only inside their own namespaces and delete them on exit;
they never touch interfaces outside them.

## 14. Troubleshooting

Startup codes are printed as `stage=<stage> [port=if<id>] code=<code>`
(section 5); run-time codes as `health=<CODE>` (sections 7 and 8).

| code | exit | meaning | action |
|---|---|---|---|
| `ruster: cannot read config: NOT_FOUND\|PERMISSION_DENIED\|IS_A_DIRECTORY\|NOT_A_FILE\|...` | 1 | the config path cannot be read, or is not a regular file | fix the path or permissions |
| `refused config: stage=permissions code=WRITABLE_BY_OTHERS\|UNTRUSTED_OWNER\|SYMLINK_IN_PATH\|UNTRUSTED_DIRECTORY\|WRITABLE_DIRECTORY\|OWNER_UNVERIFIABLE` | 1 | `--strict-config-perms` refused the file | `chmod go-w`, `chown root` (or the service user), remove symlinks from the path |
| `invalid config: stage=parse\|version\|validate code=...` | 2 | the config is invalid | `ruster validate`; the code and schema path name the problem |
| `stage=backend code=SIM_BACKEND` | 2 | `kind = "sim"` (or no `[backend]`) | use `ruster run-sim`, or set `kind = "af-xdp"` |
| `stage=candidate code=MISSING_SERVICE_*` | 2 | a required service (NAT44 UDP/TCP, firewall, ...) is missing | add it (`ruster validate` reports the same) |
| `stage=key-source code=KEY_SOURCE`, `stage=candidate code=KEY_SOURCE` | 1 | `/dev/urandom` cannot be opened or read, or is not the kernel CSPRNG | check `/dev/urandom` (character device 1:9; 1:8 `/dev/random` is also accepted) in the namespace/container |
| `stage=storage code=ALLOCATION.<SERVICE>` | 1 | runtime storage could not be allocated | lower the capacities or give the process more memory |
| `stage=privileges code=MISSING_CAPABILITIES missing=...` | 4 | effective capabilities missing | run as root or grant the listed capabilities |
| `stage=privileges code=MEMLOCK_LIMIT limit-bytes=L required-bytes=R` | 4 | soft memlock limit below the UMEM estimate | raise `ulimit -l`/`LimitMEMLOCK` to at least R, or grant `CAP_IPC_LOCK` |
| `stage=privileges code=UNREADABLE source=/proc/self/status\|/proc/self/limits` | 4 | procfs not readable | mount procfs in the namespace/container |
| `stage=open code=INTERFACE_LOOKUP/NO_SUCH_DEVICE` | 1 | the `device` does not exist in this namespace | fix `device`, or run in the right namespace |
| `stage=open code=TX_QUEUE_CHECK/NO_TX_QUEUE`, `BIND/INVALID_ARGUMENT` | 1 | `queue` is not a queue of the device | use queue 0, or a queue that has RX and TX |
| `stage=open code=BIND/BUSY` | 1 | another AF_XDP socket owns the queue (retried first) | stop the other user; after a crash, wait and start again |
| `stage=open code=REGISTER_UMEM/MEMLOCK_LIMIT\|OUT_OF_MEMORY` | 1 | UMEM could not be pinned (retried first) | raise memlock or grant `CAP_IPC_LOCK`; `auto` needs twice the UMEM |
| `stage=open code=BIND/ZERO_COPY_UNSUPPORTED` | 1 | `mode = "zero-copy"` on a device without zero-copy | use `mode = "copy"` |
| `stage=open code=OPEN_SOCKET/UNSUPPORTED` | 1 | kernel without `CONFIG_XDP_SOCKETS` | use a kernel with AF_XDP |
| `stage=open code=.../PERMISSION_DENIED` | 1 | capability or LSM policy denied a syscall | check capabilities, user namespace, SELinux/AppArmor |
| `stage=open code=.../ERRNO_<n>` | 1 | another errno at that step (`ERRNO_11` is retried) | look the errno up; report it if unexpected |
| `stage=checks code=MULTI_QUEUE_DEVICE rx-queues=N` | 1 | more than one allocated RX queue | `ethtool -L <dev> combined 1`, or steer and use `--allow-multi-queue` |
| `stage=checks code=KERNEL_IPV4_ADDRESSES count=N` / `KERNEL_IPV4_ROUTES count=N` | 1 | kernel L3 config on the port; routes count in every table (`ip -4 route show table all`), multipath nexthops included | `ip -4 addr flush dev <dev>`, delete the routes (`ip route del ... table <id>`) |
| `stage=checks code=KERNEL_IPV6_ADDRESSES count=N` / `KERNEL_IPV6_ROUTES count=N` | 1 | IPv6 on the port with a global/ULA address (SLAAC, DHCPv6, manual) or a route beyond link-local/multicast (for example an RA default route) | `sysctl -w net.ipv6.conf.<dev>.disable_ipv6=1` (recommended), or knowingly `--allow-kernel-ipv6` |
| `stage=checks code=KERNEL_IPV6_ENABLED` | 1 | IPv6 on for the port (`disable_ipv6=0`, the default of a new device or namespace), even with only link-local | `sysctl -w net.ipv6.conf.<dev>.disable_ipv6=1`, or knowingly `--allow-kernel-ipv6` |
| `stage=checks code=KERNEL_IPV6_FORWARDING_ENABLED scope=global\|device\|force\|multicast` | 1 | `net.ipv6.conf.all.forwarding`, `conf/<dev>/forwarding`, a `force_forwarding`, or an IPv6 `mc_forwarding` on with IPv6 on the port | `disable_ipv6=1` on the port, or `sysctl -w net.ipv6.conf.all.forwarding=0`, or knowingly `--allow-kernel-ipv6` |
| `stage=checks code=KERNEL_FORWARDING_ENABLED scope=global\|device\|multicast` | 1 | kernel IPv4 forwarding on (`multicast`: a multicast routing daemon set `mc_forwarding`) | `sysctl -w net.ipv4.ip_forward=0` and `net.ipv4.conf.<dev>.forwarding=0`, or knowingly `--allow-kernel-forwarding` |
| `stage=checks code=MTU_ABOVE_FRAME mtu=M limit=L` | 1 | frames would not fit a UMEM frame | lower the MTU to at most L, or `frame-size = 4096` |
| `stage=checks code=UNVERIFIABLE probe=link\|rx-queues\|mtu\|ipv4-addresses\|ipv4-routes\|forwarding\|ipv6-disabled\|ipv6-addresses\|ipv6-routes\|ipv6-forwarding` | 1 | a device fact could not be read (`mtu`: sysfs and rtnetlink disagree or the MTU changed during startup) | run under `ip netns exec <ns>`; check rtnetlink and procfs |
| `stage=attach code=CREATE_LINK/EXISTING_PROGRAM` | 1 | another XDP program is attached | remove it deliberately (`ip link set dev <dev> xdp off`) or use another device |
| `stage=attach code=CREATE_LINK/NATIVE_XDP_UNSUPPORTED` | 1 | driver lacks native XDP | `xdp-attach = "generic"` with `mode = "copy"` |
| `stage=attach code=LOAD_PROGRAM/VERIFIER_REJECTED verifier-log-bytes=B truncated=T` | 1 | the kernel verifier refused the redirect program | report it with the kernel version |
| `stage=attach code=.../PERMISSION_DENIED` | 1 | BPF denied (often a non-initial user namespace) | run with init-namespace `CAP_BPF`/`CAP_PERFMON` or `CAP_SYS_ADMIN` |
| `stage=watch code=...` | 1 | the link watch's rtnetlink socket could not be opened | check netlink access in the namespace |
| `stage=datapath\|engine\|adapter\|activate code=...` | 1 | internal setup fault after attach (everything was rolled back) | report it with the line |
| `cannot install <signal> handler`, `cannot start the output thread` | 1 | process setup failed | report it |
| `health=TX_STALL` | 1 if fatal | oldest TX frame not completing while the link is up | check PAUSE frames/flow control, driver state; restart; `--tx-stall-fatal-secs 0` to warn only |
| `health=FILL_STARVED` | — | no free frame to give the kernel for RX | usually follows a TX stall; check `tx_inflight` and `TX_STALL` |
| `health=KICK_ERRORS` | 1 if fatal | kicks keep failing (not `ENETDOWN`) | check the device; `last-kick-error=` in the summary names the errno token |
| `health=LINK_DOWN` | — | carrier or admin down | fix the link; forwarding resumes by itself |
| `health=DEVICE_REMOVED` | 1 | the port device is gone | restore the device, then restart |
| `health=MTU_DECREASED` / `MTU_ABOVE_FRAME` | 1 | MTU changed below the startup MTU / above the frame bound | restore the MTU, then restart |
| `health=MTU_RAISED` | — | MTU raised within the frame bound; TX still bounded by the old MTU | restart to use the new MTU |
| `health=LINK_PROBE` / `LINK_UNVERIFIABLE` | 1 if `LINK_UNVERIFIABLE` | rtnetlink/procfs queries failing (3 in a row is fatal) | check the namespace; a renamed device makes its forwarding sysctl unreadable |
| `health=KERNEL_IPV4_ADDRESSES` / `KERNEL_IPV4_ROUTES` / `KERNEL_FORWARDING_ENABLED` / `FORWARDING_UNVERIFIABLE` | — | kernel L3 or forwarding appeared while attached | remove it while the router runs (section 8) |
| `IPV4_WEAK_HOST_EXPOSURE` (startup or `health=`) | — | `rp_filter` and `arp_ignore` both 0 | `sysctl -w net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.rp_filter=1` |
| `health=KERNEL_IPV6_ENABLED` / `KERNEL_IPV6_ADDRESSES` / `KERNEL_IPV6_ROUTES` / `KERNEL_IPV6_FORWARDING_ENABLED` / `IPV6_UNVERIFIABLE` | — | kernel IPv6 on a port with IPv6 on, while attached | `sysctl -w net.ipv6.conf.<dev>.disable_ipv6=1` while the router runs (section 8) |
| `reload refused: code=RESTART_REQUIRED reasons=...` | — | the change needs a restart | restart in a quiet period |
| `reload failed: stage=quiesce code=TIMEOUT` | — | TX did not settle within 200 ms (often a port down with TX queued) | bring the link up, send SIGHUP again |
| `reload failed: stage=apply code=RESTART_REQUIRED.<R>\|NOT_QUIESCENT\|...` | — | the live apply refused | nothing changed; check the plan |
| `stopped after a backend fault` | 1 | ring fault or wedged adapter | collect the final stats; restart |
| `stopped after an invariant violation code=APPLY_REPORT_MISSING` | 1 | publication contract broken | report it |
| `drain failed: code=...` | 1 | the drain itself failed | ports are still closed; report it |
| `tx-in-flight=T` (T > 0) | 3 | the kernel still held TX at the deadline | normal after a forced stop; the close released them |
| `tx-handoffs=H` (H > 0) | 1 | stranded TX handoff, internal fault | report it |
| `close failed: port=if<id> code=<STEP>` | 1 | a socket, ring, UMEM or link close failed | check `ip -details link show`; detach by hand if a program stayed |
| exit 101 | 101 | panic | report the message; XDP was detached by the unwind or the kernel |

# M2 operator runbook (`ruster run`, AF_XDP)

Status: M2 S10a and S10b (X04b). Covers cold start (with the bounded
startup retry), config reload (SIGHUP), health and stall signals, link and
device events, graceful shutdown, and forced termination with restart.

All commands assume a dedicated router host or network namespace. Replace
`lan0`/`wan0` with the devices of your `[[interfaces]]` entries.

## 1. Prerequisites

- x86_64 Linux 5.9 or newer (XDP `bpf_link`). The privileged E2E runs on the
  test host's kernel only; older kernels are not verified (XDP-062).
- A config that `ruster validate` accepts, with `[backend] kind = "af-xdp"` and
  one `[[backend.ports]]` entry per interface (README "packet backend").
- Privileges: run as root, or grant `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF`,
  and `CAP_PERFMON` (or `CAP_SYS_ADMIN`). Without `CAP_IPC_LOCK` the soft
  `RLIMIT_MEMLOCK` must cover every port's UMEM (`frame-count x frame-size`,
  rounded up to pages), twice for `mode = "auto"`. Root has `CAP_IPC_LOCK`.
  systemd example:

  ```ini
  [Service]
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

  `ruster run` does not drop these privileges after startup (deferred).
- Port devices (checked at startup, refused otherwise):
  - exactly one RX queue: `ethtool -l lan0`, then `ethtool -L lan0 combined 1`
    (or `rx 1`). If the NIC must keep several queues, steer every frame to the
    bound queue with RSS/ntuple (`ethtool -X`, `ethtool -N`) and start with
    `--allow-multi-queue`; frames on other queues are dropped by the XDP
    program. The count is rtnetlink's `IFLA_NUM_RX_QUEUES` (namespace
    correct), which is the number of queues the driver *allocated*: a NIC
    that allocates several queues but runs one after `ethtool -L ... combined
    1` still counts as multi-queue. Confirm with `ethtool -l` that only one
    is active, then start with `--allow-multi-queue` (the warning
    `MULTI_QUEUE_ALLOWED rx-queues=N` names the allocated count).
  - an MTU whose frames fit a UMEM frame: `mtu + 14 <= frame-size - 256 -
    headroom` (1778 for 2048-byte frames, 3826 for 4096). A larger MTU is
    refused (`MTU_ABOVE_FRAME mtu=M limit=L`); lower the MTU or use 4096-byte
    frames.
  - no kernel IPv4 address and no kernel IPv4 route out of the port:
    `ip -4 addr flush dev lan0`, and `ip -4 route show dev lan0` must be empty.
    Leave the devices up (`ip link set lan0 up`).
  - no other XDP program: `ip -details link show dev lan0` must not show
    `prog/xdp`. `ruster run` never replaces or detaches a program it did not
    attach.
- Kernel IPv4 forwarding off: `sysctl -w net.ipv4.ip_forward=0` (and
  `net.ipv4.conf.<port>.forwarding=0`) in the router's namespace. `ruster
  run` refuses to start otherwise (`checks code=KERNEL_FORWARDING_ENABLED
  scope=global|device`; an unreadable sysctl is `UNVERIFIABLE
  probe=forwarding`). Why: whenever the router is not attached — before it
  starts, after any exit (including a fatal health event, section 3), and
  after a crash or SIGKILL, when the unpinned XDP links detach by themselves
  — frames on the ports reach the kernel stack, and kernel forwarding is
  what would carry them between the ports around the firewall and NAT. With
  forwarding off and no kernel L3 on the ports (below) the fallback is "no
  traffic", not "traffic without the firewall". If other interfaces of the
  namespace need forwarding (containers, VPN), start with
  `--allow-kernel-forwarding`: the check then only warns
  (`IPV4_FORWARDING_ENABLED ...`) and the address/route refusals are what
  keep the kernel without a route through the ports; prefer a dedicated
  router namespace instead.
- Optional: `--strict-config-perms` refuses a config file (at startup and on
  every reload) that group or other may write (`stage=permissions
  code=WRITABLE_BY_OTHERS`) or that is owned by neither root nor the user
  `ruster run` runs as (`code=UNTRUSTED_OWNER`). Off by default; it is a
  flag, not a config key, because it guards the file itself. The config is
  always opened `O_NONBLOCK | O_NOCTTY` and must be a regular file.

## 2. Cold start

1. Check the config: `ruster validate router.toml` (exit 0, summary ends with
   `backend=af-xdp ports=N umem-bytes=B`).
2. Start: `ruster run --config router.toml`. Startup order: config, signal
   handlers, `/dev/urandom` key source, generation-1 candidate, privilege and
   memlock preflight, then per port in interface-id order open, device checks,
   XDP attach, then engines, adapter, and activation.
3. Ready when stderr shows
   `ruster run: running generation 1 on N port(s); send SIGINT or SIGTERM to
   stop, SIGHUP to reload`.
   Each port then shows native or generic XDP:
   `ip -details link show dev lan0` lists `prog/xdp id <n>` (`xdp` or
   `xdpgeneric`).
4. Warnings (`ruster run: warning: port=if<id> ...`) do not stop startup:
   `MULTI_QUEUE_ALLOWED` (with `--allow-multi-queue`), and only with
   `--allow-kernel-forwarding`: `IPV4_FORWARDING_ENABLED scope=global|device`,
   `IPV4_FORWARDING_UNVERIFIABLE`.
5. Health and counters: every `--stats-interval` seconds (default 60, 0 to
   disable) stdout carries a `ruster-run-stats kind=periodic` block ending in
   `end`. Look at `observer.state` (`healthy`), `rx.received`, `rx.dropped`,
   `drop.<REASON>`, `af_xdp.mode`, `if<id>.af_xdp_port.fill_starved`,
   `if<id>.af_xdp_port.kernel_rx_dropped`, `...kernel_rx_fill_ring_empty_descs`,
   and the run-time sections `reload.*`, `watch.state` (`ok`/`warning`),
   `watch.warnings`, and `if<id>.watch.*` (section 3).

### Startup failures

Every failure rolls back completely (all opened ports closed, last first, XDP
detached) and prints one line `ruster run: startup failed: stage=<stage>
[port=if<id>] code=<code>`. Verify with `ip -details link show` that no
`prog/xdp` is left, then fix and start again.

| exit | stage / code | action |
|---|---|---|
| 2 | `backend code=SIM_BACKEND` | use `ruster run-sim`, or set `kind = "af-xdp"` |
| 2 | `parse`/`validate`/`candidate code=MISSING_SERVICE_*` | fix the config (`ruster validate`) |
| 4 | `privileges code=MISSING_CAPABILITIES missing=...` | run as root or grant the listed capabilities |
| 4 | `privileges code=MEMLOCK_LIMIT limit-bytes=L required-bytes=R` | raise `ulimit -l`/`LimitMEMLOCK` to at least R, or grant `CAP_IPC_LOCK` |
| 1 | `open code=INTERFACE_LOOKUP/NO_SUCH_DEVICE` | wrong `device` or wrong network namespace |
| 1 | `open code=TX_QUEUE_CHECK/NO_TX_QUEUE` or `BIND/INVALID_ARGUMENT` | `queue` is not a queue of the device |
| 1 | `open code=BIND/BUSY` | retried automatically (below); after the last attempt: another AF_XDP socket owns the queue |
| 1 | `open code=REGISTER_UMEM/MEMLOCK_LIMIT` | retried automatically (below); after the last attempt: memlock too small |
| 1 | `checks code=MULTI_QUEUE_DEVICE rx-queues=N` | reduce to one queue or steer and use `--allow-multi-queue` |
| 1 | `checks code=KERNEL_IPV4_ADDRESSES` / `KERNEL_IPV4_ROUTES` | remove kernel L3 config from the port |
| 1 | `checks code=KERNEL_FORWARDING_ENABLED scope=global\|device` / `UNVERIFIABLE probe=forwarding` | turn kernel IPv4 forwarding off in the namespace, or knowingly use `--allow-kernel-forwarding` (section 1) |
| 1 | `stage=permissions code=WRITABLE_BY_OTHERS\|UNTRUSTED_OWNER\|OWNER_UNVERIFIABLE` (`refused config:`) | with `--strict-config-perms`: `chmod go-w`, `chown root` (or the service user) |
| 1 | `checks code=MTU_ABOVE_FRAME mtu=M limit=L` | lower the MTU to at most L or use `frame-size = 4096` |
| 1 | `checks code=UNVERIFIABLE probe=link\|rx-queues\|mtu\|ipv4-addresses\|ipv4-routes` | rtnetlink or procfs not answering in this namespace; `mtu`: the MTU changed during startup, or sysfs (read by the session) is not this namespace's (run under `ip netns exec`) |
| 1 | `watch code=...` | the rtnetlink socket of the link watch could not be opened |
| 1 | `attach code=CREATE_LINK/EXISTING_PROGRAM` | another XDP program is attached; remove it deliberately or use another device |
| 1 | `attach code=CREATE_LINK/NATIVE_XDP_UNSUPPORTED` | driver lacks native XDP: use `xdp-attach = "generic"` with `mode = "copy"` |
| 1 | `key-source` / `candidate code=KEY_SOURCE` | `/dev/urandom` unreadable |

A SIGINT/SIGTERM during startup rolls back the same way and exits 0
(`startup cancelled by signal; rolled back N port(s)`).

### Startup retry (XDP-045)

Right after a previous run (or a crash), the kernel releases the old
sockets' queue registration and UMEM accounting from deferred work, so a
port open can fail transiently. `ruster run` retries the whole port
startup on exactly these failures: `open code=BIND/BUSY`,
`open code=REGISTER_UMEM/MEMLOCK_LIMIT` or `REGISTER_UMEM/OUT_OF_MEMORY`,
and any `.../ERRNO_11` (`EAGAIN`). Before each retry every opened port is
rolled back (closed, XDP detached), and stderr shows

```text
ruster run: startup attempt 1 of 3 failed: stage=open port=if2 code=BIND/BUSY; rolled back 1 port(s), retrying in 250 ms
```

The pause starts at 250 ms and doubles up to 2 s. `--startup-attempts N`
(1 to 10, default 3) bounds the attempts; `1` disables the retry. Every
other failure (wrong device, missing privilege, checks, attach) fails at
once. A signal during the pause cancels (exit 0).

### Output never blocks the router

stdout and stderr are written by a separate output thread. The router
thread only queues complete lines and stats blocks with a bounded,
non-blocking hand-off (64 messages per stream; stdout and stderr have
separate threads and queues, so a stuck stdout never holds back stderr);
when the pipe behind stdout/stderr is full or nobody reads it (a stuck log collector, `ruster run | less` left
alone), further blocks and lines are dropped and counted in
`output.dropped` of the next stats block that gets through. Ticks, the
stop flag, the drain, and the detach never wait for output. The threads
write to duplicated fds, not through Rust's stdout/stderr locks, and `main`
does not flush stdout after `run`, so nothing waits on a blocked writer. At
exit the process waits at most 1 s for queued output, then exits anyway:
if a stream is still blocked then, its final stats block and summary line
can be lost (they were teardown's last output; the teardown itself has
completed).

## 3. While running: reload, health, and link events

### Config reload (SIGHUP)

1. Edit the config file given to `--config` (write a new file and `mv` it
   into place so a reload never reads a half-written file), check it with
   `ruster validate` and `ruster plan old.toml new.toml`.
2. `kill -HUP <pid>` (`systemctl reload`, with `ExecReload=/bin/kill -HUP
   $MAINPID`). The handler only sets a flag; the router takes it between
   two ticks and prints `reload requested (generation G)`. SIGHUP never
   ends `ruster run`, also not a foreground run whose terminal hangs up
   (and also under `nohup`): stop it with SIGINT/SIGTERM.
3. The file is read and validated exactly like at startup (same limits; a
   path that is not a regular file is refused, so a FIFO cannot block the
   router), a successor generation is built with fresh keys, and the
   control-plane plan is checked against the running generation. One line
   reports the outcome:

   | line | meaning |
   |---|---|
   | `reload applied: generation=N previous=P; interfaces=.. addresses=.. routes=.. neighbors=.. firewall-rules=.. nat44-ports=..; flushed dynamic-neighbors=.. resolution-states=.. nat44-udp-mappings=.. nat44-tcp-sessions=.. firewall-flows=..` | the new generation is active from this tick on; compare the document counts with what you meant to load (a truncated file that still validates shows fewer rules or routes; `routes` includes the connected routes) |
   | `reload refused: code=RESTART_REQUIRED reasons=BACKEND,...; generation P keeps running` | the change needs a restart (below); nothing changed |
   | `reload failed: stage=<stage> code=<code>[ path=...]; generation P keeps running` | read/permissions/parse/validate/candidate/plan/dry-run/apply/quiesce failure; nothing changed. `stage=quiesce code=STOPPED`: the run stopped while the reload waited |

   Counters: `reload.requested`, `reload.applied`, `reload.refused`,
   `reload.failed` in every stats block; in the final block `requested`
   always equals `applied + refused + failed`. If the backend reports a
   commit without its report (`previous=unknown; ... code=APPLY_REPORT_MISSING`)
   the publication contract is broken: the new document is current, the run
   ends (`stopped after an invariant violation`) and exits 1.
4. Restart-required (refused) changes: anything in `[backend]` (device,
   queue, mode, attach, rings, UMEM: `BACKEND`), interface ids or MACs
   (`INTERFACES`), a storage capacity (`STORAGE_SHAPE`), the resolution or
   ICMPv4 error policy. Routes, neighbors, addresses, firewall rules and
   policy, NAT realm/filtering/hairpinning, `[ipv4-origin]`, and `[tick]`
   budgets reload in place (`ruster plan` shows which).
5. State: an applied reload flushes ARP learning, pending resolution and
   ICMPv4 errors, and every NAT44 mapping and firewall flow (their hash
   keys rotate with each generation; established TCP through NAT must
   reconnect), and keeps cumulative counters. A refused or failed reload
   changes no state. Every reload consumes a generation number, so after a
   refusal the next applied generation skips one.
6. Timing: the switch happens at a tick boundary once the backend is
   quiescent (no TX frame of the old generation still in flight). While it
   waits, the router holds RX back (frames queue in the RX ring) for at most
   200 ms; if the backend does not settle in time (for example a port whose
   link is down still holds TX), the reload fails with
   `stage=quiesce code=TIMEOUT`; send SIGHUP again later. Parsing and
   planning run synchronously on the router thread too (typically a few
   milliseconds, more for a large config). SIGHUPs while one reload is
   pending are coalesced into one more reload.
7. Under load, reload when traffic is low: during the parse/plan and the
   quiescence hold the router reads no RX, so a busy port's RX ring (2048
   entries by default) can overflow and the kernel drops frames. That shows
   as `if<id>.af_xdp_port.kernel_rx_ring_full` and `kernel_rx_dropped`
   rising in the next stats block.

### Health and stall signals (OBS-018)

The router samples every port's backend counters every 500 ms (cold path)
and prints a value-free line when a condition starts or ends:
`ruster run: warning: port=if<id> health=<CODE>` and
`ruster run: recovered: port=if<id> health=<CODE>`. `watch.state` in the
stats is `warning` while any condition holds.

| code | condition | warning | fatal (exit 1) |
|---|---|---|---|
| `TX_STALL` | the oldest TX frame in flight has not completed while the link is up (kicks issued or not) | after `--tx-stall-warn-secs` (default 1) | after `--tx-stall-fatal-secs` (default 10; `0`: never) |
| `FILL_STARVED` | no Fill frame with the kernel, no RX, and no free frame to refill | after 1 s | never (its frames are held by TX, which `TX_STALL` covers) |
| `KICK_ERRORS` | kick failures other than `ENETDOWN` in every sample | at once | after `--kick-errors-fatal-secs` (default 5; `0`: never) without a clean sample |

The thresholds are seconds from 1 (warning) or 0 (fatal) to 3600, and a
nonzero `--tx-stall-fatal-secs` must be at least `--tx-stall-warn-secs`.
They are command-line options (set at start, not reloadable).

A TX stall can be caused from the wire: a host on a port's segment that
floods 802.3x PAUSE frames stops a NIC with flow control from
transmitting. With the default fatal exit such a host can therefore make
the router exit (and, under `Restart=on-failure`, restart in a loop). The
default stays fatal because the router then fails closed: kernel
forwarding is refused and the ports carry no kernel L3 (section 1), so
nothing is forwarded around the firewall while it is down, and a stuck TX
queue usually needs the restart to recover. If availability under a
hostile segment matters more, disable flow control on the port
(`ethtool -A <dev> rx off tx off`) and/or run with
`--tx-stall-fatal-secs 0` (warn only; the stall stays visible in
`watch.state` and `if<id>.watch.tx_stall_ms`).

A busy link never trips these: completions keep retiring the oldest frame,
RX keeps arriving, and kicks succeed. Per port: `if<id>.watch.tx_stall`,
`tx_stall_ms`, `fill_starved`, `kick_errors_persistent`, `warnings`. The
wedged-adapter watchdog of section 4 stays.

### Link and device events

Every second the router asks rtnetlink for each port's interface index
(namespace correct, cold path):

| event | outcome |
|---|---|
| link down (`ip link set lan0 down`, cable out: `IFF_UP` or `IFF_LOWER_UP` clear) | warning `LINK_DOWN`, `if<id>.watch.link_down_events` +1; keeps running; owed TX is kicked again when the link returns (recovered `LINK_DOWN`, `link_up_events` +1) |
| device removed (`ip link del`, driver unbind, moved to another namespace) | fatal `DEVICE_REMOVED`: drain, detach, close, exit 1 |
| MTU below the startup MTU | fatal `MTU_DECREASED` (TX is bounded by the startup MTU; longer frames could be stranded in the kernel) |
| MTU above what a frame holds (`frame-size - 256 - headroom - 14`) | fatal `MTU_ABOVE_FRAME` |
| MTU raised within that bound | warning `MTU_RAISED`; TX stays bounded by the startup MTU until a restart |
| the rtnetlink query fails | warning `LINK_PROBE`; fatal `LINK_UNVERIFIABLE` after 3 failures in a row |
| a kernel IPv4 address appears on a port (`ip addr add ... dev lan0`; one `RTM_GETADDR` dump in the same round) | fatal `KERNEL_IPV4_ADDRESSES` (`if<id>.watch.kernel_ipv4_addresses`), like the startup refusal; a failed dump counts as a failed query |

Kernel routes and forwarding sysctls are checked at startup only.

A fatal event prints `fatal: port=if<id> health=<CODE>`, then the shutdown
of section 4 runs and the summary starts with `stopped after a fatal health
event port=if<id> code=<CODE>`; the exit status is 1, so `systemd`
`Restart=on-failure` restarts the router with the new device state (after a
removal, the device must exist again or startup fails at `open`).

## 4. Graceful shutdown

1. Send SIGTERM (or SIGINT): `kill -TERM <pid>` / `systemctl stop`.
2. The router stops ticking (no more RX or TX), drains every port for at most
   2 s (completions reaped, owed TX kicked), prints the final stats block on
   stdout, detaches XDP by closing each link, closes every socket and UMEM,
   and prints on stderr:
   `ruster run: stopped by signal; drain calls=C completed=K rx-released=R
   tx-in-flight=T tx-handoffs=0 fill-in-kernel=F forced=false timed-out=false
   last-kick-error=none; detached and closed N port(s)`. If a close failed the
   tail reads `detached and closed K of N port(s); see close failed` after a
   `close failed: port=if<id> code=...` line, and `last-kick-error=` names the
   last kick failure the drain saw (for example `if2:NETWORK_DOWN`).
3. Exit status 0 means no TX frame was left with the kernel. Exit 3 means the
   deadline (or a second signal) left `tx-in-flight=T` frames with the kernel;
   they were released by the socket close, nothing stays attached.
   `fill-in-kernel` frames are always released by the close and are normal.
4. A second SIGTERM/SIGINT during the drain cuts it short (`forced=true`).
5. Confirm: `ip -details link show dev lan0` shows no `prog/xdp`.

Exit 1 after a run means a backend fault (`stopped after a backend fault`:
the adapter stopped itself, or its I/O stayed non-reentrant for 1024 ticks in
a row, about a second: the wedged-adapter watchdog), a fatal health or
device event (`stopped after a fatal health event port=if<id> code=...`,
section 3), a drain failure (`drain failed: code=...`), a TX handoff that no
code path could cancel (`tx-handoffs=` above 0: an internal fault; the frames
were never in the kernel and the close released them), or a close error
(`close failed: port=...`, and the summary then says `detached and closed K
of N port(s)`). Every port was still closed. `last-kick-error=` names the
last kick failure the drain saw (`none`, or `if<id>:NETWORK_DOWN`, ...).

### Panics

`ruster run` keeps Rust's default `panic = "unwind"`. A panic on the router
thread unwinds through the run: the adapter and engines are dropped and the
startup guard closes every opened session, last first, which detaches XDP;
then the process exits with status 101 and the panic message on stderr, and
no summary or final stats. A panic during that unwinding aborts the process
(SIGABRT); the kernel then closes every fd and the unpinned links detach as
after SIGKILL (section 5). There is no custom panic hook: the unwind already
tears down in order, and 101 stays distinct from the documented statuses.

## 5. Forced termination and restart

1. `kill -KILL <pid>` (or a crash, OOM kill): no drain, no final stats. The
   kernel closes every fd of the process; the XDP links are unpinned, so the
   programs detach by themselves within milliseconds. Confirm with
   `ip -details link show dev lan0` (no `prog/xdp`). While detached, frames on
   the ports reach the kernel stack: keep the ports free of kernel L3 config
   and forwarding off (section 1).
2. Restart with the same command. Right after a teardown the kernel releases
   the old sockets' queue registration and UMEM accounting from deferred
   work, so the first attempt can fail with `open code=BIND/BUSY` or
   `open code=REGISTER_UMEM/MEMLOCK_LIMIT`; `ruster run` rolls back and
   retries by itself (section 2, "Startup retry"). If every attempt fails it
   exits 1 fully rolled back; under systemd `Restart=on-failure` with
   `RestartSec=1` then starts it again.
3. A restarted process begins again at generation 1 with fresh keys; no
   state (NAT mappings, firewall flows, dynamic neighbors) survives.

## 6. Known limits (M2 S10b)

- The RX queue count and the MTU checks use rtnetlink (`RTM_GETLINK` of the
  session's interface index, always this namespace). The count is the
  allocated one (`IFLA_NUM_RX_QUEUES`); see section 1 for NICs that allocate
  more queues than they run. The session itself (native crate) still reads
  the TX queue and the MTU from sysfs after proving the sysfs `ifindex`;
  the startup check now refuses (`UNVERIFIABLE probe=mtu`) when that MTU
  differs from rtnetlink's, which catches a foreign sysfs view with another
  MTU but not one with the same MTU. Keep running `ruster run` under
  `ip netns exec <ns>`, which remounts `/sys`.
- The link watch and the reload's parse and plan run synchronously on the
  router thread: a link query and an address dump once per second per port
  (the `send` blocks while another process holds the kernel's RTNL lock),
  and a reload for a few milliseconds; RX queues in the ring meanwhile and
  can overflow under load (section 3). The quiescence wait of a reload
  holds RX back for at most 200 ms.
- A port that is administratively down with TX queued holds those frames
  in the kernel's ring, so a reload while it is down fails with
  `stage=quiesce code=TIMEOUT`; bring the link up first.
- Every reload rotates the NAT44 and firewall hash keys and so flushes
  their state (PUB-006): reload during busy NAT traffic drops established
  TCP sessions through NAT.
- The `FILL_STARVED` warning delay (1 s), the 3 failed link queries, and
  the watch intervals are fixed; the TX stall and kick error thresholds
  are options (section 3) but not reloadable.
- Only the main routing table is checked for kernel routes out of a port;
  policy-routing tables (`ip rule`, other tables) are not (deferred:
  `RTM_GETROUTE` over all tables).
- IPv6 is not checked at all: link-local and other IPv6 addresses, IPv6
  routes, and `net.ipv6.conf.*.forwarding` on the ports. While XDP is
  detached the kernel can still forward IPv6 between the ports; disable it
  on the ports yourself (`sysctl net.ipv6.conf.<dev>.disable_ipv6=1`) if
  that matters.
- The config is validated with the same limits as `run-sim`
  (`SIM_VALIDATION_LIMITS`); production limits are not decided yet.
- Capability diagnostics read `CapEff` in the caller's user namespace; in a
  non-initial user namespace the bits can look sufficient while BPF still
  needs init-namespace capabilities, so the failure appears later as
  `attach code=.../PERMISSION_DENIED`.
- Under `sudo` from an interactive terminal, Ctrl-C reaches `ruster run`
  both from the terminal's process group and relayed by sudo, so one key
  press can count as two signals and force the drain (`forced=true`). Use
  `kill -TERM <pid>` (or systemd) for a full drain; check this manually on
  your setup.
- The memlock estimate adds 64 KiB per port for BPF objects (charged to
  `RLIMIT_MEMLOCK` before Linux 5.11) and is a lower bound: other processes
  of the same user, and a run that just exited, also hold locked memory.

## 7. Verification

`scripts/priv-run-smoke.sh` exercises sections 2–5 in three dedicated
network namespaces (forwarding with ARP, NAT44, and the firewall; SIGTERM;
a SIGHUP reload that denies and then allows the forwarded UDP again without
a restart; a refused restart-required reload while traffic keeps flowing;
link down/up on the router's port with recovered forwarding; an MTU above
the frame bound and a deleted port device, both exit 1 with nothing
attached; rollback after a second-port failure; the device checks; kernel
forwarding refused by default and accepted with `--allow-kernel-forwarding`;
SIGKILL
and restart). It never touches interfaces outside its namespaces.

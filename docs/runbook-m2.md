# M2 operator runbook (`ruster run`, AF_XDP)

Status: started in M2 S10a (X04b first half). Covers cold start, graceful
shutdown, and forced termination with restart. Config reload (SIGHUP), link
down/up, TX ring full, and health/stall handling arrive with M2 S10b and are
not covered yet.

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
    program.
  - no kernel IPv4 address and no kernel IPv4 route out of the port:
    `ip -4 addr flush dev lan0`, and `ip -4 route show dev lan0` must be empty.
    Leave the devices up (`ip link set lan0 up`).
  - no other XDP program: `ip -details link show dev lan0` must not show
    `prog/xdp`. `ruster run` never replaces or detaches a program it did not
    attach.
- Recommended: `net.ipv4.ip_forward = 0` in the router's namespace. `ruster
  run` only warns when it is on, but with forwarding on and kernel addresses on
  the ports the kernel would route around the router while it is not running.

## 2. Cold start

1. Check the config: `ruster validate router.toml` (exit 0, summary ends with
   `backend=af-xdp ports=N umem-bytes=B`).
2. Start: `ruster run --config router.toml`. Startup order: config, signal
   handlers, `/dev/urandom` key source, generation-1 candidate, privilege and
   memlock preflight, then per port in interface-id order open, device checks,
   XDP attach, then engines, adapter, and activation.
3. Ready when stderr shows
   `ruster run: running generation 1 on N port(s); send SIGINT or SIGTERM to stop`.
   Each port then shows native or generic XDP:
   `ip -details link show dev lan0` lists `prog/xdp id <n>` (`xdp` or
   `xdpgeneric`).
4. Warnings (`ruster run: warning: port=if<id> ...`) do not stop startup:
   `MULTI_QUEUE_ALLOWED` (with `--allow-multi-queue`),
   `IPV4_FORWARDING_ENABLED scope=global|device`, `IPV4_FORWARDING_UNVERIFIABLE`.
5. Health and counters: every `--stats-interval` seconds (default 60, 0 to
   disable) stdout carries a `ruster-run-stats kind=periodic` block ending in
   `end`. Look at `observer.state` (`healthy`), `rx.received`, `rx.dropped`,
   `drop.<REASON>`, `af_xdp.mode`, `if<id>.af_xdp_port.fill_starved`,
   `if<id>.af_xdp_port.kernel_rx_dropped`, `...kernel_rx_fill_ring_empty_descs`.

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
| 1 | `open code=BIND/BUSY` | another AF_XDP socket owns the queue, or a previous run is still being released (retry after a second) |
| 1 | `open code=REGISTER_UMEM/MEMLOCK_LIMIT` | memlock too small, or a previous run's UMEM accounting is still being released |
| 1 | `checks code=MULTI_QUEUE_DEVICE rx-queues=N` | reduce to one queue or steer and use `--allow-multi-queue` |
| 1 | `checks code=KERNEL_IPV4_ADDRESSES` / `KERNEL_IPV4_ROUTES` | remove kernel L3 config from the port |
| 1 | `checks code=UNVERIFIABLE probe=...` | sysfs/procfs/netlink not readable in this namespace (run under `ip netns exec` so `/sys` matches) |
| 1 | `attach code=CREATE_LINK/EXISTING_PROGRAM` | another XDP program is attached; remove it deliberately or use another device |
| 1 | `attach code=CREATE_LINK/NATIVE_XDP_UNSUPPORTED` | driver lacks native XDP: use `xdp-attach = "generic"` with `mode = "copy"` |
| 1 | `key-source` / `candidate code=KEY_SOURCE` | `/dev/urandom` unreadable |

A SIGINT/SIGTERM during startup rolls back the same way and exits 0
(`startup cancelled by signal; rolled back N port(s)`).

### Output never blocks the router

stdout and stderr are written by a separate output thread. The router
thread only queues complete lines and stats blocks with a bounded,
non-blocking hand-off (64 messages); when the pipe behind stdout/stderr is
full or nobody reads it (a stuck log collector, `ruster run | less` left
alone), further blocks and lines are dropped and counted in
`output.dropped` of the next stats block that gets through. Ticks, the
stop flag, the drain, and the detach never wait for output. At exit the
process waits at most 1 s for queued output, then exits anyway.

## 3. Graceful shutdown

1. Send SIGTERM (or SIGINT): `kill -TERM <pid>` / `systemctl stop`.
2. The router stops ticking (no more RX or TX), drains every port for at most
   2 s (completions reaped, owed TX kicked), prints the final stats block on
   stdout, detaches XDP by closing each link, closes every socket and UMEM,
   and prints on stderr:
   `ruster run: stopped by signal; drain calls=C completed=K rx-released=R
   tx-in-flight=T fill-in-kernel=F forced=false timed-out=false; detached and
   closed N port(s)`.
3. Exit status 0 means no TX frame was left with the kernel. Exit 3 means the
   deadline (or a second signal) left `tx-in-flight=T` frames with the kernel;
   they were released by the socket close, nothing stays attached.
   `fill-in-kernel` frames are always released by the close and are normal.
4. A second SIGTERM/SIGINT during the drain cuts it short (`forced=true`).
5. Confirm: `ip -details link show dev lan0` shows no `prog/xdp`.

Exit 1 after a run means a backend fault (`stopped after a backend fault`:
the adapter stopped itself, or its I/O stayed non-reentrant for 1024 ticks in
a row, about a second), a drain failure (`drain failed: code=...`), or a close
error (`close failed: port=...`, and the summary then says `detached and
closed K of N port(s)`). Every port was still closed. `last-kick-error=` names
the last kick failure the drain saw (`none`, or `if<id>:NETWORK_DOWN`, ...).

### Panics

`ruster run` keeps Rust's default `panic = "unwind"`. A panic on the router
thread unwinds through the run: the adapter and engines are dropped and the
startup guard closes every opened session, last first, which detaches XDP;
then the process exits with status 101 and the panic message on stderr, and
no summary or final stats. A panic during that unwinding aborts the process
(SIGABRT); the kernel then closes every fd and the unpinned links detach as
after SIGKILL (section 4). There is no custom panic hook: the unwind already
tears down in order, and 101 stays distinct from the documented statuses.

## 4. Forced termination and restart

1. `kill -KILL <pid>` (or a crash, OOM kill): no drain, no final stats. The
   kernel closes every fd of the process; the XDP links are unpinned, so the
   programs detach by themselves within milliseconds. Confirm with
   `ip -details link show dev lan0` (no `prog/xdp`). While detached, frames on
   the ports reach the kernel stack: keep the ports free of kernel L3 config
   and forwarding off (section 1).
2. Restart with the same command. Right after a teardown the kernel releases
   the old sockets' queue registration and UMEM accounting from deferred
   work, so the first restart can fail with `open code=BIND/BUSY` or
   `open code=REGISTER_UMEM/MEMLOCK_LIMIT` (exit 1, fully rolled back). Retry
   after about a second; under systemd `Restart=on-failure` with
   `RestartSec=1` covers it. `ruster run` itself does not retry yet (S10b).
3. A restarted process begins again at generation 1 with fresh keys; no
   state (NAT mappings, firewall flows, dynamic neighbors) survives.

## 5. Known limits (M2 S10a)

- RX queue count comes from sysfs (`/sys/class/net/<dev>/queues`). The check
  proves only that the sysfs `ifindex` equals the session's, not that this
  sysfs view belongs to the same network namespace (an unrelated device in
  another namespace can share the ifindex). Run `ruster run` in the router's
  namespace with `ip netns exec <ns>`, which remounts `/sys` for it. Moving
  the count to rtnetlink `RTM_GETLINK` `IFLA_NUM_RX_QUEUES` is deferred.
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

## 6. Verification

`scripts/priv-run-smoke.sh` exercises sections 2–4 in three dedicated
network namespaces (forwarding with ARP, NAT44, and the firewall; SIGTERM;
rollback after a second-port failure; the device checks; SIGKILL and
restart). It never touches interfaces outside its namespaces.

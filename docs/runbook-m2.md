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
| 1 | `open code=InterfaceLookup/NoSuchDevice` | wrong `device` or wrong network namespace |
| 1 | `open code=TxQueueCheck/NoTxQueue` or `Bind/InvalidArgument` | `queue` is not a queue of the device |
| 1 | `open code=Bind/Busy` | another AF_XDP socket owns the queue, or a previous run is still being released (retry after a second) |
| 1 | `open code=RegisterUmem/MemlockLimit` | memlock too small, or a previous run's UMEM accounting is still being released |
| 1 | `checks code=MULTI_QUEUE_DEVICE rx-queues=N` | reduce to one queue or steer and use `--allow-multi-queue` |
| 1 | `checks code=KERNEL_IPV4_ADDRESSES` / `KERNEL_IPV4_ROUTES` | remove kernel L3 config from the port |
| 1 | `checks code=UNVERIFIABLE probe=...` | sysfs/procfs/netlink not readable in this namespace (run under `ip netns exec` so `/sys` matches) |
| 1 | `attach code=CreateLink/ExistingProgram` | another XDP program is attached; remove it deliberately or use another device |
| 1 | `attach code=CreateLink/NativeXdpUnsupported` | driver lacks native XDP: use `xdp-attach = "generic"` with `mode = "copy"` |
| 1 | `key-source` / `candidate code=KEY_SOURCE` | `/dev/urandom` unreadable |

A SIGINT/SIGTERM during startup rolls back the same way and exits 0
(`startup cancelled by signal; rolled back N port(s)`).

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

Exit 1 after a run means a backend fault (`stopped after a backend fault`), a
drain failure (`drain failed: ...`), or a close error (`close failed: port=...`);
the ports were still closed.

## 4. Forced termination and restart

1. `kill -KILL <pid>` (or a crash, OOM kill): no drain, no final stats. The
   kernel closes every fd of the process; the XDP links are unpinned, so the
   programs detach by themselves within milliseconds. Confirm with
   `ip -details link show dev lan0` (no `prog/xdp`). While detached, frames on
   the ports reach the kernel stack: keep the ports free of kernel L3 config
   and forwarding off (section 1).
2. Restart with the same command. Right after a teardown the kernel releases
   the old sockets' queue registration and UMEM accounting from deferred
   work, so the first restart can fail with `open code=Bind/Busy` or
   `open code=RegisterUmem/MemlockLimit` (exit 1, fully rolled back). Retry
   after about a second; under systemd `Restart=on-failure` with
   `RestartSec=1` covers it. `ruster run` itself does not retry yet (S10b).
3. A restarted process begins again at generation 1 with fresh keys; no
   state (NAT mappings, firewall flows, dynamic neighbors) survives.

## 5. Verification

`scripts/priv-run-smoke.sh` exercises sections 2–4 in three dedicated
network namespaces (forwarding with ARP, NAT44, and the firewall; SIGTERM;
rollback after a second-port failure; the device checks; SIGKILL and
restart). It never touches interfaces outside its namespaces.

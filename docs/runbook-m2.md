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
  missing=...`). These are needed only for startup: once generation 1 is
  active, `ruster run` drops every capability of every thread (and, with
  `--user`/`--group`, switches to that uid/gid) before the first tick
  (section 5, "Privilege drop"); `--keep-privileges` opts out. The default
  drop needs Linux 6.5 or newer, or `kernel.unprivileged_bpf_disabled=0`
  (exit 4 `privileges code=TEARDOWN_NEEDS_CAPABILITIES` otherwise);
  `--user`/`--group` also need `CAP_SETUID` and `CAP_SETGID`.
- **Memlock**: without `CAP_IPC_LOCK`, the soft `RLIMIT_MEMLOCK` must be at
  least the sum over ports of `frame-count x frame-size` (rounded up to
  4 KiB pages; twice that for `mode = "auto"`) plus 64 KiB per port for the
  BPF objects. Otherwise exit 4 (`privileges code=MEMLOCK_LIMIT
  limit-bytes=L required-bytes=R`). Root has `CAP_IPC_LOCK`. The estimate is
  a lower bound (section 12).
- **Memory (RAM)**: the runtime tables are ordinary heap, not memlocked;
  63.94 MiB for the largest config `ruster run` accepts (64 MiB bound),
  plus the UMEM (see "Validation limits and memory" below).
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
- **IPv4 weak host (required unless `--allow-ipv4-weak-host`)**: an
  address-less port still receives,
  while detached, frames sent to its MAC for any local IPv4 address of the
  host: with the effective `rp_filter` (the larger of `conf/all` and
  `conf/<port>`) 0, the source check of a device without addresses passes
  them (`__fib_validate_source`, the no-address path) and they reach local
  sockets. `arp_ignore` only stops the ARP replies that would reveal those
  addresses, so it does not change this. Since H5 (owner decision
  2026-11-02, CLI-079) startup refuses an effective `rp_filter` of 0 on any
  port (`KERNEL_IPV4_WEAK_HOST`; unreadable: `UNVERIFIABLE
  probe=rp-filter`). `--allow-ipv4-weak-host` accepts it with the old
  warning `IPV4_WEAK_HOST_EXPOSURE`. While running it stays a warning
  either way: the watch warns `health=IPV4_WEAK_HOST_EXPOSURE` (recovered
  when it is 1 or 2), because a fatal exit would detach XDP and open the
  very exposure. Set `net.ipv4.conf.all.rp_filter=1` (strict) or `2`
  (loose) in the router namespace, and `net.ipv4.conf.all.arp_ignore=1` as
  advice (no ARP replies for addresses the port does not hold).
  **Behaviour change**: a fresh network namespace starts with
  `rp_filter=0` (`all` and every device), which earlier versions only
  warned about and which is now refused; set `all.rp_filter` before
  starting (the recommended setup in section 2 does).
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

### Validation limits and memory

`ruster run` validates the config, at startup and on every SIGHUP reload,
with the production limits (`PRODUCTION_VALIDATION_LIMITS`, H3).
`ruster validate` and `ruster plan` choose limits from the document's
own `backend.kind`, so they predict exactly what the command that drives
that backend will accept. `af-xdp` gets the production limits, which is
what `run` accepts. `sim`, or no `[backend]`, gets the simulator's limits
(`SIM_VALIDATION_LIMITS`), which is what `run-sim` accepts; `run-sim`
itself is unchanged. `plan` checks each side with the limits of its own
backend. A refusal exits 2 with a value-free line such as `stage=validate
code=CAPACITY_LIMIT_EXCEEDED path=resolution.capacity.failure-holds
limit=4096 actual=4097`, or with `stage=validate
code=RUNTIME_STORAGE_BYTES_EXCEEDED limit=... actual=...` for the
whole-document storage, which has no path.

| Limit | `run-sim` (and `validate` of `sim`) | `ruster run` (and `validate` of `af-xdp`) | Why |
|---|---|---|---|
| quote tables (`max_quote_slots_per_table`): `resolution.capacity.failure-holds`, `icmpv4-errors.capacity.actions`, `nat44.tcp.capacity.unsolicited-syn-holds` | 65536 | 4096 | each slot holds a quoted datagram (656, 592, and 592 bytes), so the bound is memory: at 65536 these three alone would need 115.0 MiB. Until H4b this limit (then `max_scanned_slots_per_table`) covered every resolution and ICMPv4 error table because their packet paths scanned |
| other tables (`max_slots_per_table`): `resolution.capacity.{states,actions,dynamic-neighbors}`, `icmpv4-errors.capacity.states`, `nat44.{udp,tcp}.capacity.*`, `firewall.capacity.states`, each NAT44 directory (next power of two), the NAT44 port owner table (pool size) | 65536 | 65536 | no packet path scans them (table below); home NAT needs many sessions; also the largest port pool (1-65535) |
| runtime storage bytes (`max_runtime_bytes`) | 64 MiB | 64 MiB | every table at its production limit needs 63.94 MiB (with `[fragmentation] datagrams = 1024`, MTU2 part B, `[fragment-tracking] entries = 16384, held-fragments = 512`, NAT-FRAG, and `[resolution.hold] packets = 64`, ARP-HOLD; 64.00 MiB with `mappings-per-host` set on both NAT44 protocols, only 12 fragmentation slots, `[fragment-tracking] mode = "refuse"`, and `[resolution.hold] enabled = false`, N3, and 63.97 MiB with only `sessions-per-host`, `mode = "refuse"`, and the hold off, N6), so the per-table limits bind; all four per-host limits at the maximal tables need 69.70 MiB and fail closed here (size a table down); otherwise the byte limit fails closed only if a slot type grows |
| config file | 1 MiB | 1 MiB | parse stage, every backend (CONFIG-001) |
| `[[interfaces]]` / `[[backend.ports]]` | 256 / 256 | 256 / 256 | parse stage |
| `[[addresses]]` | 1024 | 1024 | parse stage |
| `[[routes]]` / `[[neighbors]]` / `[[firewall.rules]]` | 4096 each | 4096 each | parse stage |
| UMEM per port / all ports | (not used) | 256 MiB / 1 GiB | CONFIG-005 |

All production values are coordinator defaults, not owner decisions.

**Per-packet cost.** No runtime table is searched linearly on the
packet path any more (PERF-001: NAT44 since H4a, resolution and ICMPv4
errors since H4b). Before H4b a dynamic-neighbor miss, resolution
scheduling, an ARP learn, and failure capture scanned their whole table:
75 to 940 µs per packet at 65536 slots in a release build, 4.5 to 72 µs
at the old 4096 cap. Since H4c the configured lists do not scale the
per-packet cost either (PERF-002): the router builds lookup indexes once
when it validates a config (startup and every reload) and every packet
does a bounded binary search instead of walking a list. A route lookup
(longest prefix match) takes at most 14 comparisons at 4096 routes, a
static-neighbor, local-address, or interface lookup at most 13. In a
release build with 4096 `/24` routes one route lookup went from about
8.8 µs (about 10.9 µs in the review that found it, at least 22 µs per
forwarded packet, about 45 kpps per queue) to about 49 ns, and a
static-neighbor plus local-address lookup takes about 67 ns. The indexes
are snapshot memory, not runtime storage (not in `storage-bytes`): at
most about 392 KiB (the worst shape is 4096 non-adjacent direct routes
plus 4096 neighbors, about 262 KiB, plus 256 input firewall rules in the
shape with the longest per-ingress lists, about 130 KiB), about 784 KiB
while a reload holds the old and the new config. Building them is a sort, O(n log n), on the
reload path.

| Table | Packet path, and what drives it | Work per packet | Release time per packet at 65536 (before H4b) | Recommended size |
|---|---|---|---|---|
| `dynamic-neighbors` (64 B) | lookup on forwarding to a non-static next hop, ARP merge: a LAN host flooding ARP from many senders, or WAN packets to unused LAN addresses where routed inbound traffic is allowed | one keyed chain of at most 16 slots (`RESOLUTION_INDEX_CHAIN_LIMIT`; secret per-publication SipHash key, one bucket per slot), plus for a new entry the lowest free or expired slot from a bitmap (at most 17 words at 65536) and the head of the refresh-order list; expired entries are taken off that list lazily, amortized O(1) per learned entry | miss 0.28 µs (74 µs); ARP flood into a full cache 0.31 µs (148 µs) | on-link hosts of the largest LAN plus headroom |
| resolution `states` (96 B) | `schedule` on a dynamic miss, failure capture, ARP learn (cancels the key's state) | one keyed chain of at most 16 slots, plus for a new key the lowest free or elapsed-cooldown slot (bitmap) and the head of the request-order list (amortized O(1) per committed request) | new target with the table full 0.34 µs (250 µs); ARP update of a pending target 0.78 µs (943 µs) | the number of next hops being resolved at once |
| resolution `failure-holds` (656 B) | capture on a miss, promotion and expiry of a failed resolution, ARP learn | the forward chain of the key (at most 16 holds) and, for holds waiting on a reverse resolution, the reverse chain, which carries one leader per distinct waiting token (the other holds of a token hang off its leader, so thousands of holds behind one spoofed source cost other tokens nothing); clearing a token's holds visits each once, and each was captured once (amortized O(1)) | — | a few times `states` |
| resolution `actions` (56 B) | FIFO list; a state removes its own queued action in O(1) | O(1) | — | like `states` |
| ICMPv4 error `states` (24 B) | every generated error (TTL expiry, unreachable) | only the occupied states, which are a prefix of the table and at most two per egress interface in use (one per limiter class: Port Unreachable has its own) | — | at least the number of interfaces plus one (the WAN's Port Unreachable class; `validate` requires it while delayed Port Unreachable is on) |
| ICMPv4 error `actions` (592 B) | O(1) ring; one per state | O(1) | — | like `states` (one queued error per state; fewer only means `action_full` refusals while the queue is full) |
| NAT44 `mappings`/`peers`/`sessions` (UDP 64/48 B, TCP 80/64 B + directories; with `mappings-per-host` or `peers-per-host` also 76/76 B per mapping slot of per-host storage, with `sessions-per-host` 92 B per TCP session slot) | none since H4a: lookups are keyed; a reusable mapping, peer, or session is the head of an activity-ordered list (one list per TTL, so its head is the first to expire; TCP since N1 has one session list per phase and two mapping lists) or the next never-used slot, and a free public port comes from a free-port bitmap (at most 34 words read at the widest pool), so a new flow does O(1) work however full the tables are. An external inbound SYN keeps its 16-probe window | O(1): under 1 µs per new flow in a release build with 64500 of 65536 slots live (was about 430 µs per TCP SYN and 350 µs per UDP flow before H4a) | same (65536) | the expected concurrent flows; leave headroom |
| `nat44.icmp.capacity` `mappings`/`peers` (64/48 B + directories), `nat44.icmp.identifiers` (32 B per identifier plus the free bitmap) | the same O(1) mapping engine as UDP (N5) on its own tables and key | O(1) per query; a full table refuses without eviction (`NAT44_ICMP_MAPPING_TABLE_FULL`) | same (65536) | one mapping per running ping per host and one peer per pinged remote; the pool defaults to the realm port numbers |
| `nat44.tcp.capacity.unsolicited-syn-holds` (592 B) | an unsolicited inbound TCP SYN (no mapping for its public port, or refused by the filtering) is held for the RFC 5382 REQ-4 delayed ICMP Port Unreachable; a translated outbound SYN cancels the hold of its connection | one keyed chain of at most 16 holds (`NAT44_TCP_SYN_HOLD_CHAIN_LIMIT`, secret NAT key) plus O(1) list heads; a full table or chain drops silently. Matured holds are taken in deadline order by the failure-dispatch phase, at most `tick.failure-dispatch-scans` per tick (the same budget value as the resolution failure dispatch, applied separately, so the phase does up to twice that), never scanning unmatured ones; each matured hold walks the firewall rules once. An inconsistent table is flushed (`unsolicited_syn_index_corrupt`) | — | default 64. The Port Unreachable limiter sends at most 1 per second per egress by default, so a bigger table does not send more ICMP; it only holds more SYNs that the limiter will refuse. 0 frees the 37 KiB when the switch is off |
| `firewall.capacity.states` (56 B) | keyed SipHash probe with occupancy capped near 75% (`usable_state_capacity`), so a full table cannot occur; only the amortized expiry sweep (`reclaim_one_expired`) is linear | — (amortized) | — | the expected concurrent flows |

The per-packet work on the runtime tables no longer depends on their
capacity (the configured lists above still do), but two tick-budgeted
round-robin scans do: the resolution timer visits `tick.resolution-timer-scans`
state slots per tick and the failure dispatch `tick.failure-dispatch-scans`
hold slots, so an ARP retry, timeout, or Host Unreachable can wait up to
`ceil(capacity / scans)` ticks for its slot to come round (with 65536 states
and 16 scans, 4096 ticks, about 4 s at the idle tick cadence of about 1 ms,
which the idle wait keeps while any resolution state or hold is pending;
section 7, "Idle wait"). Size `states` for the expected traffic and raise the scan budgets
with it. `ruster validate` (of an af-xdp document) and `ruster run` (at
startup and after each applied reload) print a value-free warning when a
sweep takes more than 1000 ticks (about 1 s at the 1 ms idle cadence):
`ruster: warning: RESOLUTION_SWEEP_SLOW table=states ticks=4096` (or
`table=failure-holds`, `ticks=never` for a zero budget). The maximal
fixture uses 128 timer scans (512 ticks for 65536 states) and 16 dispatch
scans (256 ticks for 4096 holds). An insert whose key chain already holds
16 entries fails closed like a full table (`StateFull`, `CacheFull`,
`CapacityFull`) and is counted as `resolution_index.*_probe_exhausted`; an
index inconsistency met on the packet path fails closed and is counted as
`resolution_index.index_corrupt`. Both appear in every `ruster run` stats
block (not in `run-sim` output, whose schema is pinned) and should stay 0:
with the secret key a chain that long does not happen by chance, and
cannot be aimed at as long as the key stays secret (it is drawn from the
OS CSPRNG per publication and never printed).

Expired dynamic neighbors and elapsed cooldowns are taken off their
time-ordered lists lazily. Each timer tick drains up to its scan budget
of them, and the next insert takes off whatever is left, so that insert
can pay once for many entries that expired together: in a release build
about 0.8 ms when all 65536 dynamic neighbors expired at the same moment
and no tick ran since (85 µs at 4096). It cannot be bounded per insert
without changing which slot is reused (the lowest reusable one), and an
attacker must first fill the table, one packet per entry.

**Memory per slot.** These are the x86_64 slot types that
`FullServiceStorage` allocates; the total is pinned by
`the_maximal_production_config_allocates_within_the_documented_bound`.

| Table (config key) | Bytes per slot | At the production limit |
|---|---|---|
| `resolution.capacity.states` | 96 | 6 MiB (65536) |
| `resolution.capacity.actions` | 56 | 3.5 MiB (65536) |
| `resolution.capacity.dynamic-neighbors` | 64 | 4 MiB (65536) |
| `resolution.capacity.failure-holds` (holds a quoted datagram) | 656 | 2.56 MiB (4096) |
| `icmpv4-errors.capacity.states` | 24 | 1.5 MiB (65536) |
| `icmpv4-errors.capacity.actions` (holds a quoted datagram) | 592 | 2.31 MiB (4096) |
| `nat44.udp.capacity.mappings` | 64 + 28 directory | 5.75 MiB (65536) |
| `nat44.udp.capacity.peers` | 48 + 28 directory | 4.75 MiB (65536) |
| `nat44.tcp.capacity.mappings` | 80 + 28 directory | 6.75 MiB (65536) |
| `nat44.tcp.capacity.sessions` | 64 + 2 x 28 directories | 7.5 MiB (65536) |
| `nat44.tcp.capacity.unsolicited-syn-holds` (holds a quoted datagram) | 592 | 2.31 MiB (4096) |
| NAT44 port owners (`nat44.realm.ports`, per pool port, UDP and TCP each) | 32, plus a free-port bitmap of 8 bytes per 64 ports and per 4096 ports | 2 MiB + 8320 bytes per protocol |
| `firewall.capacity.states` | 56 | 3.5 MiB (65536) |

A directory has one 4-byte bucket per slot, rounded up to a power of two,
and one 24-byte node per slot (exact for the powers of two above). `ruster
validate` prints the total as `storage-bytes=`. The largest config that
`run` accepts (`fixtures/limits/router-production-max.toml`) needs
67050272 bytes (63.94 MiB). GARP (ARP-033) added one 48-byte announcement
slot per interface (96 bytes for its two interfaces; 67050176 bytes
before; at most 12 KiB with 256 interfaces). ARP-HOLD added the largest hold table (64
slots of 40 + 3840 bytes: 248320 bytes; 66801856 bytes, 63.71 MiB,
before). NAT-FRAG added the largest fragment association
table (16384 entries of an entry, a host slot, and two directory buckets
and nodes, and 512 held fragments of 8 + 3840 bytes: 5.49 MiB; 61042880
bytes, 58.22 MiB, before; its follow-ups grew the host slot by 8 bytes,
128 KiB at the limit, kept the entry at 136 bytes, and added one tombstone
slot, bucket, and node per sixteen entries, 52 KiB at the limit). MTU2 part B added 1024 fragmentation slots
of 12 + 3840 bytes (3.76 MiB; 57098432 bytes, 54.45 MiB, before). MTU1 grew the ICMPv4 error action slot from 584
to 592 bytes (the Next-Hop MTU of Fragmentation Needed, 32 KiB at the limit;
57065664 bytes, 54.42 MiB, before). N1 grew the TCP NAT mapping slot from 64 to 80
bytes (established-session count and expiry, 1 MiB at the limit; 56017088
bytes, 53.42 MiB, before). B3 added the 4096 unsolicited-SYN holds
(2.31 MiB; 53592256 bytes, 51.11 MiB, before). H4a added 16 bytes per NAT44 mapping and
session slot (reuse-list links, 48 to 64 bytes with the 16-byte alignment)
and the free-port bitmaps: 3 MiB more at the limits. H4b added the
resolution indexes inside the slots (state 56 to 96 bytes, action 32 to
56, dynamic neighbor 24 to 64, failure hold 608 to 656 with the reverse-group links; the chain heads
and bitmap words live in the slots, so there is no other storage) and
raised states, actions, dynamic neighbors, and ICMPv4 error states to
65536: 14.7 MiB more.

Worst-case resident memory of `ruster run`:

- Runtime storage: at most 64 MiB (63.94 MiB with today's slot sizes).
  It is allocated once at startup, before the privilege preflight, and
  filled, so it is resident from the start. If the allocation fails,
  startup reports `stage=storage code=ALLOCATION.<service>` and exits 1.
  It is ordinary heap: it does not count against `RLIMIT_MEMLOCK`, and a
  reload reuses it (a different size is restart-required).
- UMEM: the sum of `frame-count x frame-size` over the ports, at most
  1 GiB, memlocked (see Memlock above). It is twice that, up to 2 GiB,
  while an `auto` port falls back to copy mode.
- Config documents: at most 1 MiB of text each, plus their parsed form.
  A reload holds the running document and the new one at the same time.
- Everything else (binary, stacks, rings, and the forwarding snapshot of
  at most 4096 routes and 4096 neighbors) is a few MiB.

So a maximal config with 1 GiB of UMEM needs about 1.1 GiB of RAM, or
about 2.1 GiB during an `auto` fallback. The smoke configs (2 ports with
1 MiB of UMEM each, small tables) need a few MiB.

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
example with `NetworkNamespacePath=/run/netns/router`). `ruster run`
speaks the `sd_notify` protocol (H10, section 5 "Service notification"):
with `Type=notify-reload` (systemd 253 or newer) systemd itself sends
SIGHUP for `systemctl reload` and waits for the reload to end:

```ini
[Service]
Type=notify-reload
NetworkNamespacePath=/run/netns/router
ExecStart=/usr/local/bin/ruster run --user 990 --group 990 --config /etc/ruster/router.toml
WatchdogSec=20
Restart=on-failure
RestartSec=1
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON CAP_SETUID CAP_SETGID CAP_SETPCAP
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON CAP_SETUID CAP_SETGID CAP_SETPCAP
LimitMEMLOCK=infinity
KillSignal=SIGTERM
TimeoutStopSec=10
```

On systemd older than 253 use `Type=notify` and add
`ExecReload=/bin/kill -HUP $MAINPID` (systemd then reports the reload done
when the signal is sent, not when it is applied; the outcome is still in
the log). Without notification support at all, `Type=simple` with that
`ExecReload=` works as before (and no `WatchdogSec=`). `WatchdogSec=` is
optional: the router thread pings every half of it between ticks, so a
router that stops ticking is killed (`WatchdogSignal=`, SIGABRT by default:
the process dies, the links detach as after SIGKILL) and restarted by
`Restart=on-failure`. Keep it well above a second (20 s here): it bounds
how long a wedged router keeps the ports attached, and too small a value
restarts a router that is only briefly descheduled. The notification
socket (`/run/systemd/notify`, mode 0777) must be writable by the
`--user` the router switches to, which systemd's default is.

`990` stands for a dedicated system account with no login and no other
use (`useradd --system --no-create-home --shell /usr/sbin/nologin ruster`,
which also creates its group). Recommended config layout, readable by the
router in every mode of section 5 ("Privilege drop") and accepted by
`--strict-config-perms`:

```bash
sudo install -d -o root -g ruster -m 0750 /etc/ruster
sudo install -o root -g ruster -m 0640 router.toml /etc/ruster/router.toml
```

Root reads it as the owner (also after the drop, without
`CAP_DAC_OVERRIDE`), the switched user through `--group`, and nobody else
can read or change it. Replace it on reload with the same owner and mode
(`install ... router.toml.next` and `mv`). Without
`--user`/`--group` drop `CAP_SETUID CAP_SETGID` from both lines; without
`CAP_SETPCAP` the bounding set cannot be cleared and the drop reports
`bounding-set=kept` (harmless: no capability can come back, see section 5).
Do not use `NoNewPrivileges=yes` with `ExecStartPre=` helpers that need it
off; `ruster run` sets no_new_privs itself after startup.

Upgrade note (H6, behaviour change): the drop is on by default. On a kernel
older than 6.5 with `kernel.unprivileged_bpf_disabled` nonzero (the default
of, for example, Ubuntu 22.04 and RHEL 9 kernels) an unchanged unit now
exits 4 at startup with `stage=privileges code=TEARDOWN_NEEDS_CAPABILITIES`
before touching any port, and `Restart=on-failure` restarts it in a loop.
There, add `--keep-privileges` (and accept its risk, section 3) or move to
Linux 6.5 or newer. The check reads the kernel version only: a vendor
kernel that backported the 6.5 change under an older version is not
detected and is refused too (fail closed). `--keep-privileges` is needed
only in that case, or to diagnose a drop failure.

Upgrade note (H11, behaviour change): the filesystem confinement is on by
default (section 5, "Filesystem confinement"). A kernel without Landlock
(before 5.13, or `landlock` not in `/sys/kernel/security/lsm`) now exits 1
at startup with `stage=fs-confine code=LANDLOCK_UNSUPPORTED` or
`LANDLOCK_DISABLED` before touching any port; enable Landlock or add
`--fs-confine off` (and accept its risk, section 3). A config kept in a
shared directory such as `/etc` keeps that whole directory readable to the
router: move it into `/etc/ruster/` as above. A config symlinked to
another directory keeps working (both directories are granted), but
retargeting the symlink to a third directory after startup makes the
reload fail with `PERMISSION_DENIED` until a restart.
`Restart=on-failure` restarts after exit 1, 3 and 4 and after a crash;
exit 2 (usage or invalid config) also restarts under this setting, so fix
the config first. `TimeoutStopSec` must exceed the 2 s drain plus the 1 s
output wait (section 9).

## 3. Command line

```text
ruster run [--allow-multi-queue] [--allow-kernel-forwarding]
           [--allow-kernel-ipv6] [--allow-ipv4-weak-host]
           [--strict-config-perms] [--stats-interval <seconds>]
           [--startup-attempts <n>] [--tx-stall-warn-secs <s>]
           [--tx-stall-fatal-secs <s>] [--kick-errors-fatal-secs <s>]
           [--link-stale-secs <s>] [--idle-wait-ms <ms>]
           [--keep-privileges | --user <uid> --group <gid>]
           [--seccomp kill|log|off] [--fs-confine landlock|off]
           [--log-format text|json] --config <config.toml>
ruster run [options] -- <config.toml>
```

| flag | default | accepted | effect |
|---|---|---|---|
| `--config <path>` (or `--config=<path>`, or `-- <path>`) | required | a regular file | the config read at startup and on every reload |
| `--allow-multi-queue` | off | flag | accept a port with more than one RX queue (warned, section 1) |
| `--allow-kernel-forwarding` | off | flag | warn instead of refusing kernel IPv4 forwarding at startup (`IPV4_FORWARDING_ENABLED scope=global\|device`, `IPV4_FORWARDING_UNVERIFIABLE`); at run time an unreadable forwarding sysctl then warns `FORWARDING_UNVERIFIABLE` instead of counting as a failed query |
| `--allow-kernel-ipv6` | off | flag | warn instead of refusing IPv6 enabled on a port and everything found with it (section 1): `IPV6_ENABLED_ALLOWED`, `IPV6_ADDRESSES_ALLOWED count=N`, `IPV6_ROUTES_ALLOWED count=N`, `IPV6_FORWARDING_ENABLED scope=global\|device\|force\|multicast`, `IPV6_UNVERIFIABLE probe=ipv6-*` at startup; at run time an unreadable IPv6 fact then warns `IPV6_UNVERIFIABLE` instead of counting as a failed query (the exposure warnings, `KERNEL_IPV6_ENABLED` included, are given either way). Risk: while the router is detached (before start, after any exit, after a crash) the kernel's IPv6 stack receives on the ports: every local IPv6 address of the host and the services bound to `[::]` are reachable through them (weak host model), and with IPv6 forwarding on the kernel forwards IPv6 between the ports or to its other interfaces without the router's firewall. One flag for the whole IPv6 stack, because the router does not handle IPv6 and the safe setting is `disable_ipv6=1`; it does not touch any IPv4 refusal, and `--allow-kernel-forwarding` does not cover IPv6 |
| `--allow-ipv4-weak-host` | off | flag | warn (`IPV4_WEAK_HOST_EXPOSURE`) instead of refusing (`KERNEL_IPV4_WEAK_HOST`, `UNVERIFIABLE probe=rp-filter`) a port whose effective IPv4 `rp_filter` (the larger of `all` and the device) is 0 or unreadable (section 1). Risk: while the router is detached (before start, after any exit, after a crash) a frame sent to the port's MAC for any local IPv4 address of the host reaches the host's local sockets, so every IPv4 service of the host (also those bound to other interfaces' addresses) is reachable through the port. It does not change the run-time behaviour (a warning either way) and no other override covers it |
| `--strict-config-perms` | off | flag | refuse a config (startup and reload) that group/other may write (`WRITABLE_BY_OTHERS`), owned by neither root nor the effective user (`UNTRUSTED_OWNER`), with a symbolic link in its path (`SYMLINK_IN_PATH`), or in a directory up to `/` that is not owned by root/the user (`UNTRUSTED_DIRECTORY`) or is group/other writable (`WRITABLE_DIRECTORY`; a root-owned sticky directory such as `/tmp` is allowed); any error checking it is `OWNER_UNVERIFIABLE` |
| `--stats-interval <s>` | 60 | 0 to 86400 | seconds between periodic stats blocks on stdout; 0 disables them (the final block is always printed) |
| `--startup-attempts <n>` | 3 | 1 to 10 | whole startups tried on a transient open failure (section 5); 1 disables the retry |
| `--log-format text\|json` (or `--log-format=<format>`) | `text` | one of the two | the output format (section 11, "JSON log format", OPS-LOG). `text`: the human-readable lines, unchanged. `json`: every line on stderr and every stats block on stdout is one JSON object (`ruster-run-log/v1`), also the refusals before startup (a config that does not load). Fixed for the process (not a config key: it applies before the config is read, and the output threads own it) |
| `--tx-stall-warn-secs <s>` | 1 | 1 to 3600 | deprecated (OPS-LOG): the fallback of `[health] tx-stall-warn-ms` (section 7, "Thresholds and intervals"); `TX_STALL` warning delay |
| `--tx-stall-fatal-secs <s>` | 10 | 0 to 3600 | deprecated: the fallback of `[health] tx-stall-fatal-ms`; `TX_STALL` fatal exit; 0 never; otherwise at least `--tx-stall-warn-secs` |
| `--kick-errors-fatal-secs <s>` | 5 | 0 to 3600 | deprecated: the fallback of `[health] kick-errors-fatal-ms`; `KICK_ERRORS` fatal exit; 0 never |
| `--link-stale-secs <s>` | 5 | 1 to 3600 | deprecated: the fallback of `[watch] link-stale-ms`; age of a link watcher round still running (a `send` waiting for the kernel's RTNL lock) from which every further due round counts as a failed link query on every port (`LINK_WATCH_STALE`, `LINK_PROBE`; `LINK_UNVERIFIABLE` at the third, so about `s + 2` seconds after the stuck round started; section 8). No 0: losing observability of the ports always ends the run eventually. Raise it on hosts where driver resets hold RTNL longer |
| `--idle-wait-ms <ms>` | 10 | 1 to 100 | longest idle wait (section 7, "Idle wait"): an idle router blocks in `poll()` on its port sockets for at most this long, or at most 1 ms while timers, TX, or a reload are pending; an arriving frame ends the wait at once. Larger: fewer idle wake-ups and less CPU, but a signal delivered to another thread, a worker's answer, and anything the router only notices at a tick are seen up to this much later. 1 keeps the pre-H9 idle cadence (about 1000 wake-ups per second) |
| `--keep-privileges` | off | flag | do not drop privileges after startup (section 5, "Privilege drop"): the process keeps every capability it started with for its whole life (`warning: privileges kept (--keep-privileges)`, `privileges.state=kept`). Risk: a memory-safety bug or a logic flaw reachable from packets or the config then runs with `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF`/`CAP_SYS_ADMIN` (as root: every capability), so it can reconfigure every interface and route of the namespace, sniff and inject on any device, load BPF programs, and (as root) read and write any file. Use it only to diagnose a drop problem, on a kernel before 6.5 with `kernel.unprivileged_bpf_disabled` set (where the drop is refused), or for `[exit-protection]` (section 9), which needs it and then also requires the syscall filter and Landlock (they keep the reach to rtnetlink changes and the open descriptors) |
| `--seccomp kill\|log\|off` (or `--seccomp=<mode>`) | `kill` | one of the three | the syscall filter after startup (section 5, "Syscall filter"). `kill`: a syscall outside the allowlist kills the whole process at once (`SECCOMP_RET_KILL_PROCESS`; the XDP links detach as after SIGKILL). `log`: the kernel logs it and lets it run (`SECCOMP_RET_LOG`; `warning: seccomp=log`), for finding a missing entry without an outage. `off`: no filter (`warning: seccomp=off`, `seccomp.mode=off`). Risk of `log` and `off`: a compromised router can then make every syscall an unprivileged process (after the drop) or a privileged one (with `--keep-privileges`) can: open inet sockets and connect out, write any file its user may write, start programs, `ptrace` its own user's processes, load BPF programs where unprivileged BPF is allowed, and probe kernel interfaces that the filter keeps out of reach. Use `log` to diagnose a kill, `off` only on a platform where the filter cannot be installed. On a kernel before Landlock ABI 3 (Linux 6.2) the filter is also what keeps a writable file from being truncated by path (the `O_TRUNC` rule, no `truncate`), so `log`/`off` there loses that too; before ABI 4 (Linux 6.7) it is also the only limit on TCP sockets. An i386 or x32 syscall kills in every mode but `off`. Independent of `--keep-privileges` and `--user`/`--group` |
| `--fs-confine landlock\|off` (or `--fs-confine=<mode>`) | `landlock` | one of the two | the filesystem confinement after startup (section 5, "Filesystem confinement", H11). `landlock`: every thread can open only the files the run reads (the config's directory, its own `/proc/<pid>`, `/proc/sys/net`, its binary; read-only; a config directory of `/` is refused), and startup fails without Landlock (`stage=fs-confine code=LANDLOCK_UNSUPPORTED\|LANDLOCK_DISABLED\|LANDLOCK_BLOCKED`). `off`: no confinement (`warning: fs-confine=off`, `fs.confine=off`). Risk of `off`: a compromised router can then read every file its user may read, which without `--user`/`--group` is every root-readable file (`/etc/shadow`, private keys, other services' configs), and send it out over the ports or its output. Use `off` only on a kernel without Landlock (before 5.13, or `landlock` missing from the boot `lsm=` list). Independent of `--keep-privileges`, `--user`/`--group`, and `--seccomp` |
| `--user <uid>` `--group <gid>` | none | numeric ids 1 to 4294967294, both or neither, not with `--keep-privileges` | with the drop, also switch every thread's real, effective, saved and filesystem uid and gid to these ids and clear the supplementary groups. Names are not resolved. Needs `CAP_SETUID` and `CAP_SETGID` at startup (exit 4 otherwise, checked before anything is opened). The config must then be readable by that user for reloads |

Numbers are decimal digits only (at most 6, no sign; ids at most 10).
`--idle-wait-ms` is in milliseconds, the other numeric options in seconds
(`--startup-attempts` a count).
Every option may be given once; `-h`/`--help` prints the usage. The
health thresholds and watch intervals are config keys since OPS-LOG
(`[health]`, `[watch]`, section 7) and reload with the config; the four
threshold flags above only set what a key the config does not set falls
back to. `--stats-interval`, `--idle-wait-ms`, `--startup-attempts` and
`--log-format` are set at start and need a restart. The config file is always opened
`O_NONBLOCK | O_NOCTTY` and must be a regular file (a FIFO or device is
`NOT_A_FILE`).

Signals: SIGINT/SIGTERM stop (a second one forces the drain to end),
SIGHUP reloads the config, SIGUSR1 prints one stats block at once
(`kind=on-demand`, section 11; at most one per 100 ms: further SIGUSR1s
within that make one more block when it has passed, and the periodic
blocks keep their schedule). SIGHUP never ends `ruster run`, also not when
its terminal hangs up or under `nohup`.

## 4. Exit status

| status | meaning |
|---|---|
| 0 | ordered shutdown after SIGINT/SIGTERM with no TX frame left in the kernel; also a signal during startup or during a retry pause, after a clean rollback |
| 1 | runtime failure: unreadable or refused config file; a startup failure at any stage after the config (notify, fs-confine, open, checks, attach, watch, datapath, engine, adapter, activate, exit-protection, privilege-drop, seccomp, storage, key source; a transient open failure after the last attempt); a backend fault, a fatal health or device event, or an invariant violation during the run; a drain failure; a stranded TX handoff; a close error; a failed exit action (`exit protection failed:`); signal handler or output thread setup failure; unsupported platform |
| 2 | usage error, or invalid config (`parse`, `version`, `validate`, the `sim` backend, `candidate code=MISSING_SERVICE_*`, or `stage=exit-protection` with a privilege policy that would defeat it) |
| 3 | the shutdown drain deadline (or a second signal) left TX frames with the kernel; everything was still detached and closed |
| 4 | missing capability (also `CAP_SETUID`/`CAP_SETGID` for `--user`/`--group`), too small `RLIMIT_MEMLOCK`, a kernel whose teardown would need `CAP_BPF` after the drop (`TEARDOWN_NEEDS_CAPABILITIES`), or unreadable `/proc/self/status`/`/proc/self/limits`/`/proc/sys/kernel/osrelease`/`/proc/sys/kernel/unprivileged_bpf_disabled`; nothing was acquired |
| 101 | a panic (section 9) |
| killed by SIGSYS (a shell shows 159, systemd `status=31/SYS`) | the seccomp filter killed the process: it made a syscall outside the allowlist (section 5, "Syscall filter"); every fd was closed by the kernel and the links detached |

A refused or failed reload never ends the run.

## 5. Cold start

1. `ruster validate router.toml`, then `ruster run --config router.toml`.
2. Startup order: read and validate the config (no service bridge yet),
   the service notification environment and socket (H10, below),
   signal handlers, `/dev/urandom` key source, the filesystem ruleset
   (H11, below), output threads,
   generation-1 candidate, runtime storage, privilege and memlock
   preflight, then per port in interface-id order: open the session (TX
   queue and MTU read from sysfs), device checks (rtnetlink, procfs), XDP
   attach; then the link-watch socket, every datapath, every engine, the
   adapter, activation of generation 1, the workers, the privilege drop
   (`ruster run: privileges dropped: threads=5 capabilities=none
   bounding-set=cleared|kept no-new-privs=1 identity=unchanged|switched`),
   the filesystem confinement (`ruster run: filesystem confined:
   mode=landlock abi=N rules=N threads=5`), and the syscall filter.
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
   scope=global|device|force|multicast`, and with `--allow-ipv4-weak-host`
   `IPV4_WEAK_HOST_EXPOSURE`.

### Service notification (systemd, H10)

Only when the service manager sets `NOTIFY_SOCKET`. First thing after the
config is read, while the process has one thread, `ruster run` reads
`NOTIFY_SOCKET`, `WATCHDOG_USEC` and `WATCHDOG_PID`, removes them from its
environment, and opens one non-blocking `AF_UNIX` datagram socket; every
notification afterwards is one `sendto` on it (already on the syscall
allowlist below: no new socket is created after startup, and the
allowlist is unchanged). A notification never blocks the router: when the
manager's queue is full or nobody listens it is dropped and counted
(`notify.failed`).

Use a path socket (systemd's `/run/systemd/notify` is one). An abstract
`@name` socket is scoped to a network namespace: with
`NetworkNamespacePath=` (or under `ip netns exec`) the router would look
it up in the router's namespace, not the manager's, and every
notification would fail (`notify.failed`), so `Type=notify` would time
out.

| when | message |
|---|---|
| ready (the stderr line `running generation 1 on N port(s)`, after the privilege drop and the syscall filter) | `READY=1`, `STATUS=running generation 1` |
| SIGHUP reload starts | `RELOADING=1`, `MONOTONIC_USEC=<CLOCK_MONOTONIC in µs>` (omitted if the clock cannot be read), `STATUS=reloading (generation N)` |
| the reload ended (applied, refused, failed, or abandoned) | `READY=1`, `STATUS=running generation N` (the new one if applied) |
| the run loop ends (signal, fatal event, backend fault), before the drain | `STOPPING=1`, `STATUS=stopping: stop requested` or `stopping: fatal health event port=if<id> code=<CODE>` |
| `WATCHDOG_USEC` set, and `WATCHDOG_PID` unset or this process | `WATCHDOG=1` every half of `WATCHDOG_USEC` (at least 1 ms), from the router thread between ticks |

A startup failure sends nothing (systemd sees the exit). Accepted values:
`NOTIFY_SOCKET` an absolute path or `@name` (abstract) of at most 107
bytes, `WATCHDOG_USEC`/`WATCHDOG_PID` positive decimals. Anything else
(empty, relative, `vsock:`, a malformed number) is refused before anything
else: `startup failed: stage=notify code=NOTIFY_SOCKET_INVALID`,
`WATCHDOG_USEC_INVALID` or `WATCHDOG_PID_INVALID` (exit 1), rather than
silently not notifying. `NOTIFY_SOCKET_OPEN` means the socket could not be
created.

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

### Interface MTU and Path MTU Discovery (MTU1)

Each `[[interfaces]]` entry has an IPv4 `mtu` (default 1500, 68 to 65535;
the largest IPv4 datagram the router sends out of it, without the Ethernet
header). Set it to the MTU of the link: the device MTU, or less when a
smaller link sits behind the device (a PPPoE or tunnel hop the next router
does not report). After the device checks and before attach, `ruster run`
refuses a port whose device MTU is below the configured one
(`stage=checks port=if<id> code=MTU_BELOW_CONFIG mtu=<device>
config=<config>`): the router would forward datagrams the device cannot
send, and the AF_XDP TX would refuse them silently (`tx_over_mtu`) instead
of the sender learning the path MTU. A device MTU above the configured one
is allowed and warned (`warning: port=if<id> MTU_BELOW_DEVICE mtu=<device>
config=<config>`): a jumbo device left at the default `mtu` forwards only
1500-byte datagrams. The link watch keeps the device MTU at or above the startup MTU
(`MTU_DECREASED` is fatal), so the relation holds for the whole run. An MTU
change in the config is restart-required (`INTERFACES`).

A forwarded datagram longer than the egress MTU is dropped:

- DF set (every PMTUD sender, every TCP stack by default):
  `IPV4_FRAGMENTATION_NEEDED`, and the sender gets ICMP Destination
  Unreachable, Fragmentation Needed and DF Set (Type 3, Code 4) with the
  egress MTU as Next-Hop MTU, from the router's address on the interface
  toward the sender, quoting its datagram as it sent it (before NAT). The
  sender lowers its path MTU and retries (`ip route get <dst>` shows
  `mtu`; `tracepath <dst>` reports `pmtu`). The error has its own limiter
  per egress toward the senders (`[icmpv4-errors.policy]
  fragmentation-needed-interval-ms`, default 10 ms, at least 1), so a flood
  of other errors (a TTL sweep) never uses it up. It is per egress, not per
  sender: one host sending oversized DF datagrams continuously can still
  delay the error to other hosts behind the same interface
  (`icmpv4_errors.rate_limited`); TCP retransmits until one arrives.
  Mitigate with MSS clamping on the senders (or their gateway) and, if
  needed, a shorter interval. Fragmentation Needed needs its own limiter
  state on every interface: `icmpv4-errors.capacity.states` must be at
  least twice the number of interfaces (plus one with delayed Port
  Unreachable), or validation fails with
  `ICMPV4_ERROR_STATES_TOO_FEW_FOR_FRAGMENTATION_NEEDED`.
- DF clear: fragmented (RFC 1812 4.2.2.7, RFC 791 3.2; since MTU2 part B,
  see "Fragmentation" below), also through the NAT, which translates whole
  DF-clear datagrams (see "DF-clear datagrams through the NAT" below).
  With `[fragmentation] enabled = false`: `IPV4_FRAGMENTATION_REQUIRED`, no
  error, and the NAT commits no mapping or state for such a drop.
- The firewall decides first: a datagram it refuses is dropped with the
  firewall's reason and never answered, so the error reveals nothing about
  traffic the policy does not admit. To an admitted peer the error does
  reveal the MTU of the router's link toward the destination (the inside
  link MTU, for an outside sender): that is what RFC 1191 asks of a router.
- A frame whose Ethernet payload is longer than the egress MTU although
  its datagram fits (bytes after the IPv4 Total Length) is
  `IPV4_FRAME_EXCEEDS_MTU`, without an error: the backend sends whole
  frames. Ethernet minimum padding never trips it.
- An ICMP error the router translates (NAT44) that is itself longer than
  the egress MTU with DF is counted as `IPV4_FRAGMENTATION_NEEDED` but
  answered with nothing (no error about an error, RFC 1812 4.3.2.7).
- An unresolved next hop comes first: the first oversized datagram to a
  neighbor not yet resolved is `NEIGHBOR_UNRESOLVED` (ARP starts, and a
  fruitless ARP yields Host Unreachable); once the neighbor answers, the
  next one gets Fragmentation Needed.

`[icmpv4-errors.generate] fragmentation-needed = false` turns the error off
(`icmpv4_errors.disabled_fragmentation_needed`). That black-holes PMTUD
through the router: TCP connections whose segments exceed the MTU stall
after the handshake. Leave it on unless every sender behind the router
clamps its MSS. Every router-generated error is cut to fit the MTU of the
interface it leaves (at most 576 bytes of IPv4 as before).

### Errors about datagrams for the router and bad headers (ICMP-ERR)

The router answers datagrams addressed to its own interface addresses (on
the interface they arrive on) and datagrams with headers it cannot process
the way RFC 1812 asks, each with a switch in `[icmpv4-errors.generate]`:

| datagram | drop | error | switch (default) |
|---|---|---|---|
| UDP to a router address (no UDP port is open on the router) | `IPV4_LOCAL_UDP_PORT_UNREACHABLE` | Destination Unreachable, Port Unreachable (3/3) | `udp-port-unreachable` (`true`) |
| UDP to a router address with a short header, a bad UDP length, or a bad nonzero checksum | `IPV4_LOCAL_UDP_INVALID` | none (RFC 1122 4.1.3.4) | — |
| TCP to a router address | `IPV4_LOCAL_TCP_UNSUPPORTED` | none: a closed TCP port answers with a RST, which the router does not send | — |
| any other protocol (GRE, SCTP, ...) to a router address | `IPV4_LOCAL_PROTOCOL_UNREACHABLE` | Destination Unreachable, Protocol Unreachable (3/2) | `protocol-unreachable` (`true`) |
| a fragment of a non-ICMP datagram to a router address | consumed as `IPV4_LOCAL_UNSUPPORTED` (no reassembly) | none | — |
| a datagram whose Total Length is longer than the frame (link truncation), valid header checksum | `IPV4_TOTAL_LENGTH_EXCEEDS_PACKET` | Parameter Problem (12/0), pointer 2 | `parameter-problem` (`true`) |
| malformed IPv4 options, a second source route, or a strict source route not for the router | `IPV4_OPTIONS_UNSUPPORTED` | Parameter Problem, pointer at the offending octet (16 for the strict source route) | `parameter-problem` |
| a forwarded datagram the firewall denies by rule or by default | `FIREWALL_RULE_DENIED` / `FIREWALL_DEFAULT_DENIED` | Destination Unreachable, Communication Administratively Prohibited (3/13) | `admin-prohibited` (**`false`**) |

```toml
[icmpv4-errors.generate]
protocol-unreachable = true   # 3/2 for protocols the router does not implement
udp-port-unreachable = true   # 3/3 for UDP to a router address
parameter-problem = true      # 12/0 for truncated datagrams and bad options
admin-prohibited = false      # 3/13 for firewall denies (off: silent drop)
```

- **The forward firewall does not cover router addresses; the input
  firewall does.** Datagrams addressed to the router (Echo, and these
  errors) are never evaluated by the forward rules `[[firewall.rules]]`,
  which judge forwarded traffic only. They are judged by the input
  firewall `[firewall.input]` (INPUT-FW, "Input firewall" below), whose
  default is `accept`: without the table a default-deny forward firewall
  still lets the WAN address answer every UDP port with Port Unreachable
  (so a scanner learns that all are closed and that the router is there)
  and every unimplemented protocol with Protocol Unreachable (a working
  protocol scan). For a WAN address silent at L3 use the recommended WAN
  stealth policy (input `default-action = "deny"` with an `accept` rule
  for the LAN, and optionally Echo from a management prefix): it is per
  interface and leaves the LAN answered. The router-wide switches
  (`protocol-unreachable = false`, `udp-port-unreachable = false`,
  `parameter-problem = false`, `[ipv4-origin] echo-reply = false`) still
  work but silence every interface. Neither covers the NAT: with the
  public address = WAN address, TCP to the public address is NAT traffic,
  so also set `[nat44.tcp] unsolicited-syn-icmp = false` (the TCP NAT's
  delayed Port Unreachable to unsolicited SYNs) unless the forward
  firewall already keeps it silent.
- UDP and TCP to the NAT public address are not "for the router": they go
  to the NAT as before (no mapping: `NAT44_UDP_MAPPING_MISS`; for TCP see
  `unsolicited-syn-icmp`). `udp-port-unreachable` does not touch the TCP
  NAT's Port Unreachable either (that one is `[nat44.tcp]
  unsolicited-syn-icmp`, counted as `queued_port_unreachable`).
- Every error goes through the same limiter as Time Exceeded and Network/Host
  Unreachable (`interval-ms`, default 100 ms, one per egress at a time):
  they add no limiter state, so `icmpv4-errors.capacity.states` needs no
  change. A UDP flood to a router address therefore also delays Time
  Exceeded toward the same interface (`icmpv4_errors.rate_limited`,
  `pending`); turn `udp-port-unreachable` off if that matters more than
  answering UDP probes. Sources are not authenticated: with the default
  `source-validation = "off"`, UDP to a router address with a spoofed
  inside source uses up the limiter of the inside interface and delays
  errors to the real inside hosts. `source-validation = "strict"` on the
  WAN drops such datagrams silently before any error is considered (see
  "Source address validation (URPF)" below).
- With `udp-port-unreachable = false` the UDP checksum of router-addressed
  datagrams is not read (a flood costs no payload pass); such datagrams
  are all `IPV4_LOCAL_UDP_PORT_UNREACHABLE`, a broken header still
  `IPV4_LOCAL_UDP_INVALID`. `icmpv4_errors.disabled_udp_port_unreachable`
  therefore also counts UDP with a bad checksum while the switch is off.
- With a firewall configured, every truncated datagram to the NAT public
  address is silent (whatever its protocol): it would be a NAT inbound
  candidate that the firewall judges.
- TCP to the router is a deliberate silent drop (no RST). The option check
  comes first, so TCP with malformed IPv4 options still gets a Parameter
  Problem. Router addresses are ingress-scoped: UDP to the address of
  another interface is not answered with Port Unreachable.
- Never answered (RFC 1812 4.3.2.7): ICMP errors, non-initial fragments,
  broadcast/multicast destinations or link frames, non-host sources.
  Parameter Problem about a datagram not for the router is sent only when
  the router has a route for it, the NAT would not refuse it as an
  outside-to-inside crossing, and there is no forward firewall (the
  firewall refuses option-bearing datagrams first,
  `FIREWALL_IPV4_OPTIONS_UNSUPPORTED`). Bad header checksums are always
  silent.
- `admin-prohibited` is off by default: a deny stays a silent drop, the
  usual firewall behaviour, and RFC 1812 5.2.7.1 allows the option not to
  send Code 13. Turning it on makes denied senders fail fast (on Linux
  `connect` fails with `EHOSTUNREACH` instead of timing out) at the cost of
  telling them the firewall exists. It answers only denies of the plain
  forward plan, which includes inside-to-outside NAT traffic (judged
  before translation; the inside host gets its own datagram back); denies
  on the NAT inbound, hairpin, and ICMP query paths stay silent. With it off, `icmpv4_errors.disabled_admin_prohibited` counts the
  denies that would have been answered.
- Errors are about the datagram as received and go back to its sender on
  the side it came from, so nothing needs NAT translation: an inside host
  sees its own datagram, an outside host the one it sent.
- Counters: `icmpv4_errors.queued_*`/`dequeued_*`/`disabled_*` with
  `protocol_unreachable`, `udp_port_unreachable`, `parameter_problem`,
  `admin_prohibited`. All four switches are part of the ICMPv4 error policy:
  changing one is restart-required (`plan` says `ICMPV4_ERROR_POLICY`).

Upgrade note (ICMP-ERR, behaviour change): UDP and other non-TCP, non-ICMP
datagrams to a router address used to be consumed silently
(`consume.IPV4_LOCAL_UNSUPPORTED`); they are now dropped with the reasons
above and answered with Port or Protocol Unreachable, and truncated
datagrams and bad options get Parameter Problem. New drop codes 205
`IPV4_LOCAL_PROTOCOL_UNREACHABLE`, 206 `IPV4_LOCAL_UDP_PORT_UNREACHABLE`,
207 `IPV4_LOCAL_UDP_INVALID`, 208 `IPV4_LOCAL_TCP_UNSUPPORTED`; twelve new
`icmpv4_errors.*` counters. To keep the old silence set
`protocol-unreachable = false`, `udp-port-unreachable = false`, and
`parameter-problem = false` (the drops keep their new reasons). Router
addresses are not protected by `[firewall]` (see above): with these on,
a default-deny router answers UDP and protocol probes on its WAN address.
Monitoring: router-addressed UDP now counts in `drop.*` (and the
`rx.dropped` total), no longer in `consume.*`, so a drop-rate alert can
fire on ordinary UDP probes of the router; alert on the forwarding drop
reasons instead, or exclude the four new codes. The twelve new
`icmpv4_errors.*` counters are appended after the existing ones, so the
order of the earlier fields in stats and JSONL is unchanged. Storage is
unchanged (67050176 bytes for the maximal production config at the time;
67050272 since GARP).

### Source address validation (URPF)

Each `[[interfaces]]` entry can check the source address of the IPv4
datagrams it receives against the forwarding table (RFC 1812 §5.3.8,
RFC 3704, BCP 38/RFC 2827):

```toml
[[interfaces]]
id = 2
name = "wan"
device = "wan0"
mac = "02:00:00:00:00:02"
source-validation = "strict"            # "off" (default) | "loose" | "strict"
# source-validation-allow-default = true  # only with "loose"
```

| mode | passes when the longest matching route for the source ... | RFC |
|---|---|---|
| `off` (default) | (no check) | RFC 1812 §5.3.8 "MUST be disabled by default" |
| `strict` | exists and leaves through this interface; a default route counts | RFC 1812 §5.3.8, RFC 3704 §2.2 |
| `loose` | exists and is not a `/0`, out of any interface | RFC 3704 §2.5 |
| `loose` + `source-validation-allow-default = true` | exists, a default route included | RFC 3704 §2.4 |

`strict` here is the RFC 1812 §5.3.8 rule taken literally: the route a
reply would take, a default route included. Cisco `ip verify unicast source
reachable-via rx` and Juniper `rpf-check` strict do not count a default
route unless told to (`allow-default`), so their strict on a default-only
WAN drops every Internet source and ours does not. Our
`source-validation-allow-default` therefore means something else: it only
exists for `loose` and switches it from RFC 3704 §2.5 (ignore the default
route) to §2.4 (count it).

Recommended home/NAT edge (the coordinator's default, pending owner
objection; the built-in default and the generic fixtures stay `off`):

```toml
[[interfaces]]
name = "lan"
# ...
# Optional BCP 38 hardening of the inside network: only sources routed out
# of the LAN may enter. Leave it off if anything behind the LAN can send
# with a source routed elsewhere (asymmetric routing, a second router).
# source-validation = "strict"

[[interfaces]]
name = "wan"
# ...
source-validation = "strict"   # the NAT outside, default route out of it
```

With more than one upstream (two WANs, each with its own routes) use
`loose` with `source-validation-allow-default = true` on the upstreams
instead: a reply may legitimately arrive on the upstream that its route
does not use, which `strict` drops.

- A failing datagram is silently discarded (RFC 1812 §5.3.8 "MUST silently
  discard"): `drop.IPV4_SOURCE_VALIDATION_FAILED` (code 209), the trace
  event `Ipv4SourceValidationFailed{ingress, source, mode}`, and no ICMP
  error of any kind (no Echo Reply, Port/Protocol Unreachable, Time
  Exceeded, or Parameter Problem). The counter is router-wide; the
  `Dropped` trace carries the ingress interface.
- Which mode where. On the WAN (NAT outside) use `strict`: the Internet's
  default route leaves through the WAN, so every Internet source passes
  and NAT answers to the public address are translated as usual, while a
  datagram claiming an inside (or any LAN-routed) source arriving on the
  WAN is dropped. That protects the *inside* egress's class 0 limiter
  (ICMP4-023: spoofed inside sources making the router queue errors toward
  the inside hosts) and the ARP resolution those errors would start on
  the LAN. It does not protect the WAN egress: a spoofed Internet source,
  or one on the WAN's own subnet, passes `strict` on the WAN, so a flood
  of them can still use up the WAN egress's class 0 and make the router
  resolve on-link WAN addresses by ARP. Do not use plain `loose` on a WAN
  whose only route back is the default route: it ignores default routes
  and drops all Internet traffic (`validate` warns, below).
  On the LAN, `strict` is BCP 38 filtering of the inside network: hosts on
  the connected prefixes (and prefixes routed via a LAN gateway) pass,
  spoofed Internet sources never reach the NAT or the firewall.
- Asymmetric routing: if traffic from a prefix can arrive on an interface
  other than the one its route leaves through, `strict` drops it; use
  `loose` there.
- Feasible-path uRPF (RFC 3704 §2.3, RFC 8704) is not offered: the
  forwarding table has one path per prefix, so it would equal `strict`.
- The check runs in the IPv4 ingress validation after the martian source
  and destination checks (they keep their own reasons) and before local
  delivery, NAT, the firewall, the fragment association table, and ARP
  holds, for transit and router-addressed datagrams alike. It reuses the
  source route lookup those checks already make; with every interface
  `off` it costs one branch. ARP and the router's own generated frames are
  not checked. A held datagram is decided again at replay against the same
  publication (an apply drops every hold), so it gets the same answer.
- Warnings (value-free, never a refusal), printed by `validate`, at
  startup, and after every applied reload:
  `warning: SOURCE_VALIDATION_DEFAULT_IGNORED interface=if<id>` when an
  interface is `loose` without allow-default and is the egress of a `/0`
  route (Internet sources whose only route is that default will be
  dropped), and `warning: SOURCE_VALIDATION_NO_ROUTE interface=if<id>` when
  an interface is `strict` and no route leaves through it (everything it
  receives is dropped). JSON log event `SOURCE_VALIDATION_WARNING`.
- Reload: changing either key is reloadable (`ruster plan` shows
  `source-validation + if2 strict`, `~ if2 strict -> if2 loose`, or `-`);
  no state is flushed for it. `source-validation-allow-default` without
  `loose` is refused by `validate` with
  `SOURCE_VALIDATION_ALLOW_DEFAULT_NOT_LOOSE`; an unknown mode is
  `INVALID_TYPE`.
- Storage is unchanged (67050176 bytes for the maximal production config):
  the modes live in the forwarding snapshot, not in runtime storage.
- Upgrade note: the new drop code 209 `IPV4_SOURCE_VALIDATION_FAILED` is
  appended after 208, so stats and JSONL gain one `drop.*` field at the
  end (0 while every interface is `off`); nothing else changes for a
  config without the keys.

### Input firewall (INPUT-FW)

`[firewall.input]` is a stateless first-match policy for datagrams
addressed to one of the router's own addresses (the ingress interface's
address, ICMP4-001): Echo, the ICMP-ERR answers above, ICMP messages the
router consumes, and anything else for the router. The default is
`default-action = "accept"`, the RFC behavior, so a config without the
table behaves exactly as before.

```toml
[firewall.input]
default-action = "deny"          # absent: "accept"

[[firewall.input.rules]]         # first match wins, document order
id = 10                          # nonzero, unique among input rules
ingress = "lan"                  # every selector is optional ("any")
action = "accept"

[[firewall.input.rules]]
id = 20
ingress = "wan"
source = "198.51.100.0/24"       # a management prefix
protocol = "icmp"                # "icmp", "tcp", "udp"; absent: any protocol
icmp-type = 8                    # Echo; only with protocol = "icmp"
action = "accept"

# For a future local service: destination-ports only with tcp/udp.
# [[firewall.input.rules]]
# id = 30
# ingress = "lan"
# protocol = "udp"
# destination-ports = { first = 53, last = 53 }
# destination = "192.168.1.1/32"
# action = "accept"
```

That is the recommended WAN stealth policy: the LAN is answered as
before (Echo, Port/Protocol Unreachable, Parameter Problem), the WAN
answers Echo from the management prefix only, and the WAN is silent at L3
for datagrams to the router's addresses. Drop rule 20 for a WAN that
answers no datagram to the router at all. The built-in default and the
fixtures stay `accept` (owner policy: RFC by default, hardening
configurable).

What stays visible from the WAN under it (the input firewall judges only
datagrams addressed to the router):

- ARP: replies for the WAN address and the RFC 5227 announcements (GARP)
  of `[arp]`, which every on-link host sees.
- Errors about transit datagrams, sent from the WAN address: Time
  Exceeded, Fragmentation Needed, Network/Host Unreachable for datagrams
  the router forwards (`[icmpv4-errors.generate]`), including Time Exceeded
  for traffic with a live NAT mapping, and Communication Administratively
  Prohibited (3/13) when `admin-prohibited = true`.
- The TCP NAT's delayed Port Unreachable to unsolicited SYNs
  (`[nat44.tcp] unsolicited-syn-icmp`) when the forward firewall admits
  them (B3): TCP to the public address is NAT traffic, not local delivery.
- Replies to NAT mappings (they are what the NAT is for).
- With rule 20: Echo Replies to any source inside the management prefix.
  Source addresses are not authenticated, so anyone who can spoof a source
  in that prefix gets one Echo Reply per Echo Request sent to that source
  (a 1:1 reflector toward the prefix, rate-limited by nothing but the
  sender); keep the prefix small, and use `source-validation = "strict"`
  where a spoofed source would arrive on the wrong interface.

- A denied datagram is silently discarded before any local decision:
  `drop.IPV4_INPUT_FIREWALL_RULE_DENIED` (code 210) for a `deny` rule,
  `drop.IPV4_INPUT_FIREWALL_DEFAULT_DENIED` (code 211) for the `deny`
  default, trace event `Ipv4InputFirewallDenied{ingress, source, rule,
  transport_header}` (`transport_header = false`: the deny was decided
  without the ICMP type or port, see fragments below).
  No Echo Reply and no ICMP error of any kind (Port/Protocol Unreachable,
  Parameter Problem). Input deny wins: the `[icmpv4-errors.generate]`
  switches and `[ipv4-origin] echo-reply` are never reached, so their
  `disabled_*` counters and `ICMPV4_ECHO_DISABLED` do not count denied
  datagrams. An accepted datagram is decided as without the table, the
  switches included.
- Selectors: `ingress` (interface name), `source` and `destination`
  (CIDR), `protocol` (`icmp`, `tcp`, `udp`), `icmp-type` (0-255, ICMP
  only), and `destination-ports` (TCP/UDP only). Validation codes:
  `FIREWALL_INPUT_ICMP_TYPE_NOT_ICMP`, `FIREWALL_INPUT_PORTS_NOT_TCP_UDP`,
  `FIREWALL_INPUT_RULES` (zero or repeated id), and the forward rules'
  `UNKNOWN_INTERFACE`, `FIREWALL_PREFIX`, `FIREWALL_PORT_RANGE`. At most
  256 rules (`LIST_TOO_LONG path=firewall.input.rules limit=256`; the core
  refuses more as `InputFirewallError::TooManyRules`). Input and forward
  rule ids are separate.
- `destination` only ever sees the address of the datagram's ingress
  interface (local delivery is ingress-scoped, ICMP4-001), or the NAT
  public address for an inside host's Echo/Timestamp with `[nat44.icmp]`.
  A rule whose destination covers neither can never match; `validate`
  warns `INPUT_FIREWALL_DESTINATION_NOT_LOCAL rule=<id>` (value-free, not
  refused).
- Stateless on purpose: the router originates no TCP or UDP session and
  no ICMP query, so nothing addressed to it is a reply to something it
  started; its own ICMP errors are never answered, and replies to NAT
  traffic take the NAT path. A flow table would hold nothing a rule cannot
  say. There is no `allow-stateful`.
- NAT traffic is not local delivery and stays with the NAT and the
  forward firewall, even when the public address is the WAN address: UDP
  and TCP to the public address, Echo Replies and ICMP errors for NAT
  mappings, and fragments to the public address (NAT-FRAG). A deny-all WAN
  input policy does not break NAT. Echo Requests and other protocols to
  the public address are for the router and are judged here.
- Order: the L2 checks, the martian source/destination checks, and URPF
  run first and keep their reasons; then the input firewall; then the
  local decision and its errors. Transit pays nothing (the check is on the
  local path only); without rules and with `accept` the local path pays
  one branch.
- Cost per datagram for the router (any host that can reach an address
  causes it): at publication the rules are split into lists per ingress
  interface and per protocol class (ICMP, TCP, UDP, other), each in
  first-match order, a rule without `ingress` or `protocol` in every list
  it can match. A datagram walks only its own list: a binary search over
  the interfaces the rules name, then at most 256 rule tests (about 6 ns
  each on the development host, the forward rule test measurement), so at
  worst about 1.5 µs; the stealth policy tests one rule for a WAN Echo and
  none for other WAN traffic. `firewall.input_rule_evaluations` counts the
  tests (like `firewall.rule_evaluations`): divide by the local datagrams
  to see the average walk, and shorten or reorder the rules if it grows.
  The lists are snapshot memory (at most about 130 KiB for 256 rules),
  not runtime storage. No allocation on the packet path.
- Fragments for the router (consumed without reassembly, ICMP4-006) are
  judged one by one. A first fragment carries its transport header; a
  later fragment does not, and neither does a datagram the link truncated.
  Without a transport header a rule with `icmp-type` or a partial
  `destination-ports` range matches only if it denies (fail closed): an
  Echo `accept` rule never admits an unknown type, a `deny` rule for a port
  refuses it. Such a deny is attributed to the first deny rule (in
  first-match order) that needs a header, even if the real type or port
  would not have matched it; the trace says `transport_header = false`. A
  truncated datagram denied this way gets no Parameter Problem and keeps
  its drop `IPV4_TOTAL_LENGTH_EXCEEDS_PACKET`; it is counted as
  `firewall.input_truncated_denied` (and not in the 210/211 drops).
- The address of another interface (for example the LAN address arriving
  on the WAN) is not local delivery (ICMP4-001): it is transit, judged by
  the NAT and the forward firewall. Limited and directed broadcasts are
  refused as martians before this point and never reach it. ARP is not
  covered.
- Reload: every change is reloadable (`ruster plan` shows
  `firewall-input-rule + id 20 icmp type 8 if2 198.51.100.0/24 ->
  0.0.0.0/0 accept`, `firewall-input-rule-order ~ changed`, and
  `firewall-input-default ~ accept -> deny`); no state is flushed or
  re-evaluated for it (the forward flows carry as before).
- Storage is unchanged (67050272 bytes for the maximal production config,
  67106224 with the per-host limits): the rules live in the forwarding
  snapshot like the forward rules, not in runtime storage.
- Upgrade note: drop codes 210 `IPV4_INPUT_FIREWALL_RULE_DENIED` and 211
  `IPV4_INPUT_FIREWALL_DEFAULT_DENIED` are appended after 209, and the
  firewall counters `input_rule_evaluations` and `input_truncated_denied`
  after `states_revoked`, so stats and JSONL gain two `drop.*` and two
  `firewall.*` fields (0 without the table).

### DF-clear datagrams through the NAT (MTU2 part A)

NAT44 translates every whole datagram (More Fragments clear, fragment
offset 0) whether Don't Fragment is set or not: UDP, TCP, ICMP queries,
and the ICMPv4 errors it translates, in both directions and hairpinned
(NAT44-008). Windows and other hosts send unfragmented UDP (DNS, games,
VPNs) without DF; before MTU2 the NAT dropped all of it as
`drop.NAT44_UDP_NON_ATOMIC_IPV4_UNSUPPORTED` (TCP:
`NAT44_TCP_NON_ATOMIC_IPV4_UNSUPPORTED`).

- IPv4 ID: a translated DF-clear datagram leaves with a new IPv4
  Identification (RFC 6864 5.3.1: a NAT that shares one public address
  must generate the ID, not copy it, or two inside hosts sending the same
  ID to one server could have their fragments mixed if a later link
  fragments them). Each translated (source, destination, protocol) gets
  consecutive IDs from a keyed counter; the start is secret. A datagram
  with DF set keeps its ID (it can never be fragmented, RFC 6864 4.1).
  There is no switch: copying the ID is not allowed by RFC 6864. Packet
  captures on both sides of the router therefore show different IDs for
  DF-clear datagrams; match them by addresses, ports and payload. An ICMP
  error about such a datagram quotes the generated ID in either direction
  (an outside router's error about an outbound datagram, or an inside
  host's error about an inbound one); the router translates the quoted
  addresses and ports back but not the ID (hosts match errors by addresses
  and ports). Outbound and inbound datagrams count in separate sequences,
  so outside traffic cannot advance the sequence of outbound traffic. All
  inside hosts share the outbound sequence of one (public address,
  destination, protocol): one host sending about 2.2 kpps of DF-clear
  datagrams to one destination makes that sequence wrap within 30 s; there
  is no per-host rate limit yet.
- Fragments (MF set or a nonzero offset) are translated through the
  fragment association table (NAT-FRAG, "Fragments through the firewall and
  the NAT" below). With `[fragment-tracking] mode = "refuse"` they are
  dropped as before: `drop.NAT44_UDP_NON_ATOMIC_IPV4_UNSUPPORTED`,
  `drop.NAT44_TCP_NON_ATOMIC_IPV4_UNSUPPORTED`,
  `drop.NAT44_ICMP_FRAGMENT_UNSUPPORTED`,
  `drop.NAT44_ICMPV4_QUOTED_FRAGMENT_UNSUPPORTED`, or, with the firewall,
  `drop.FIREWALL_FRAGMENT_UNSUPPORTED` first (`*_NON_ATOMIC_IPV4_*` counts
  only fragments).
- A DF-clear datagram larger than the egress MTU is fragmented after the
  translation (MTU2 part B, below); every fragment carries the generated
  ID.

Upgrade note (MTU2 part A, behaviour change): traffic that was dropped as
`*_NON_ATOMIC_IPV4_UNSUPPORTED` now passes the NAT and the firewall's rules
like any other datagram, creating mappings and firewall state. Review the
firewall rules if you relied on that drop. Expect those counters to fall to
the rate of real fragments, and new mappings for the hosts concerned. No
config key changes; nothing to migrate.

### Fragmentation (MTU2 part B)

A forwarded datagram without DF that is longer than the MTU of the
interface it leaves is cut into fragments (RFC 791 3.2, RFC 1812 4.2.2.7
MUST): plain routing, NAT44 outbound and inbound (toward a smaller LAN
MTU), hairpin, and translated ICMP errors. The router never fragments its
own datagrams (Echo Replies, ICMP errors fit the MTU) or a datagram with
DF (that gets Fragmentation Needed, above).

- Order: every decision comes first (TTL, firewall, NAT plan), then the
  fragmentation bound and slot are checked, and only then does anything
  commit. A refused datagram is dropped whole, byte-unchanged, without an
  error, and takes no NAT mapping, firewall state, or IPv4 ID (except the
  outbound half of a hairpinned datagram, which commits before the MTU
  check, as for every hairpin refusal). The
  datagram is then rewritten as usual (MACs, TTL, NAT translation and
  generated ID), copied into a fragmentation slot, and the received frame
  goes back to the backend (`consume.IPV4_FRAGMENTED`).
- As the last phase of the same tick, after the router's own ARP requests
  and ICMP errors, it sends each slot as fragments on its egress, through
  the same backend-owned generated-frame path (`generated_fragments.*`, the
  frames show as `origin=generated`), at most `[tick]
  generated-fragments` frames per tick (default 64, 1 to 65536; a set that
  does not fit what is left is dropped whole, `fragmentation.dropped_budget`;
  a datagram needing more fragments than the whole budget can never be sent
  and is refused before any commit as
  `drop.IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS`). The budget is one FIFO
  pool per tick shared by every source and egress, with no per-source
  fairness: one heavy sender can use it up (residual). A set that the
  backend then refuses for room still used its share of the budget.
  It first asks the backend for room for the whole set, leaving a router
  reserve free for single router frames (ARP, ICMP errors): AF_XDP keeps
  `max(2, generated-frames / 8)` generated frames and as many TX ring
  slots, AF_PACKET `max(2, TX ring frames / 8)` TX frames. Without room it
  sends nothing (`fragmentation.dropped_unavailable`): the router never
  sends a partial fragment set for lack of room. What is guaranteed: in a
  tick the router's own ARP requests and ICMP errors go first, and
  fragments in flight never take the reserve, so the next tick's router
  frames find at least the reserve; beyond it, size the TX ring for
  `rx` + `generated-arp` + `generated-icmpv4` + `generated-fragments` plus
  headroom for completions that lag. The
  NAT and firewall state of such a datagram stays committed, as for a
  forwarded frame the backend refuses.
- Layout: every fragment but the last carries the largest multiple of 8
  data bytes that fits the MTU after the 20-byte header (1376 at 1400, 1256
  at 1280, 552 at 576), the last carries the rest. All carry the same ID,
  DF clear, MF on all but the last (the last keeps the datagram's own MF),
  and the offset of their data; the header checksum is computed for each.
  Bytes after the IPv4 Total Length (link padding) are not sent.
- Received fragments that the fragment association table forwards (NAT-FRAG,
  below) are fragmented again when they are above the egress MTU (offsets
  and MF kept); IPv4 options are refused as before
  (`IPV4_OPTIONS_UNSUPPORTED`).
- Cost: the fast path is unchanged (one compare against the MTU). A
  fragmented datagram is copied twice (into its slot, then into its
  fragments) and needs as many generated frames as fragments; on AF_XDP
  they come from the `generated-frames` pool and the TX ring of the egress
  port, shared with ARP and ICMP errors. Size `generated-frames` for a full
  RX batch of fragmented datagrams if that is your traffic (a 1500-byte
  datagram over a 1280 or 1400 link needs 2 frames, over 576 3). The
  fragments one datagram can actually get are at most
  min(`max-fragments-per-datagram`, ceil((slot - 34) / block), the room
  the egress offers a set, `[tick] generated-fragments`). The room is, on
  AF_XDP, min(free generated frames, TX submit room) minus the router
  reserve `max(2, generated-frames / 8)`, and on AF_PACKET the free TX
  frames from the producer head minus `max(2, TX ring frames / 8)`. A set
  larger than that room is counted `fragmentation.dropped_unavailable`
  (its state already committed). A port that could never offer room for
  even two fragments (fewer than 4 `generated-frames` on AF_XDP, fewer
  than 4 TX ring frames on AF_PACKET, for example `block-size = 4096,
  block-count = 1`) is refused while fragmentation is on:
  `stage=validate code=FRAGMENTATION_BACKEND_ROOM_TOO_SMALL
  path=backend.ports[i].generated-frames` (AF_XDP) or
  `path=backend.af-packet.ports[i].tx` (AF_PACKET).

```toml
[fragmentation]
enabled = true                      # default; false = hardening (RFC 1812 MUST off)
max-fragments-per-datagram = 1365   # default 1365, 2..=1365
datagrams = 64                      # default 64, 1..=1024; slots per tick
```

- `enabled = false` turns fragmentation off: DF-clear datagrams above the
  egress MTU are `drop.IPV4_FRAGMENTATION_REQUIRED` as in MTU1, and no slot
  storage is allocated. Senders without PMTUD (most UDP from Windows, many
  VPN and game clients) then lose every datagram above the path MTU.
- `max-fragments-per-datagram` bounds the fragments of one datagram
  (`drop.IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS` above it). The default
  1365 is the most any IPv4 datagram can need (65535 bytes at the minimum
  MTU 68). The real ceiling per datagram is min(this, `[tick]
  generated-fragments` (default 64), the slot, the egress room): with the
  defaults a datagram needing more than 64 fragments (9000 → 140 or less,
  for example) is refused, and raising `generated-fragments` raises it.
  Real links need far fewer: 1500 → 1280 or 1400 needs 2, 1500 → 576 3,
  9000 → 1500 7. Lower it to bound the packet amplification of an
  unusually small egress MTU.
- `datagrams` is the number of datagrams one tick can fragment
  (`drop.IPV4_FRAGMENTATION_QUEUE_FULL` beyond). Keep it at least `[tick]
  rx`, and `[tick] generated-fragments` at least `rx` × the fragments per
  datagram of your links (2 for 1500 over 1280 or 1400), if most of your
  traffic needs fragmentation (a PPPoE or tunnel WAN
  link below 1500 with senders that do not use PMTUD). Each slot holds the
  longest datagram the router can receive: the largest of the largest
  interface `mtu`, 3826 bytes (the most a 4096-byte AF_XDP frame
  carries), and, on AF_PACKET, `max-frame-len` - 14 (up to 9216). The
  interface `mtu` is not enforced on received frames (a
  device above it only warns `MTU_BELOW_DEVICE`), so a 1500-byte datagram
  arriving on a device configured at 1280 is still fragmented, never
  dropped for its size. 64 × (12 + 14 + 3826) = 246528 bytes by default,
  3.76 MiB at 1024 slots, 8.81 MiB at 1024 slots and a 9000-byte MTU. The
  storage counts in `storage-bytes` and the production byte limit.
- Every `[fragmentation]` change is restart-required (`STORAGE_SHAPE`):
  the policy and slots are part of the storage shape. So is an interface
  MTU change above 3826 that changes the largest MTU (the slot size),
  besides `INTERFACES`, and an AF_PACKET `max-frame-len` above 3840 (a
  `[backend]` change is restart-required anyway).
- IPv4 ID of inbound fragments: the NAT generates the ID of an inbound
  DF-clear datagram from the inbound sequence of (remote, inside host,
  protocol) (NAT44-126) and fragments it with that ID. The inbound
  sequences are shared by every outside sender (4096 counters): an outside
  sender with enough volume could make another remote's sequence repeat
  within the inside host's reassembly time (about 2.7e8 datagrams, about
  9 Mpps over Linux's 30 s), which could make the inside host misassemble
  two datagrams (RFC 4963). That volume is far above what one worker
  forwards; UDP and TCP checksums also catch most misassembly. It is a
  documented residual (NAT44-126 (7)).

Counters (`ruster-run-stats`): `fragmentation.queued` (staged),
`fragmentation.fragmented` (every fragment committed), `fragmentation.fragments`,
`fragmentation.dropped_unavailable` (no TX room for the set),
`fragmentation.dropped_frame_too_large` (the backend refused the fragment
length), `fragmentation.dropped_budget` (over the tick's fragment frame
budget), `fragmentation.incomplete` (a backend fault after the room check
cut a set short), `fragmentation.flushed` (the tick's fragment phase did
not run after a backend failure), and `generated_fragments.*` (sessions,
allocations, TX accepted/rejected).

Upgrade note (MTU2 part B, behaviour change): fragmentation is on by
default, also for configs without `[fragmentation]`. DF-clear datagrams
above an egress MTU, so far `drop.IPV4_FRAGMENTATION_REQUIRED`, are now
fragmented and create NAT mappings and firewall state like any forwarded
datagram; expect that counter to fall to 0 and `consume.IPV4_FRAGMENTED`
and `generated_fragments.*` to grow. The default slots add 246528 bytes of
runtime storage (`storage-bytes`; the maximal production config with
`datagrams = 1024` was 61042880 bytes before NAT-FRAG). A config with every table at its
production limit and `mappings-per-host` on both NAT44 protocols now needs
67306432 bytes with the default 64 slots and fails with
`RUNTIME_STORAGE_BYTES_EXCEEDED` (64 MiB); set `[fragmentation] datagrams`
to at most 12, or size a table down. New `[tick] generated-fragments`
(default 64). New drop codes: 186
`IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS`, 187
`IPV4_FRAGMENTATION_QUEUE_FULL`, 188
`IPV4_FRAGMENTATION_DATAGRAM_TOO_LARGE`, 189
`IPV4_FRAGMENTATION_OFFSET_OVERFLOW`; new consume code `IPV4_FRAGMENTED`;
new stats sections `fragmentation.*` and `generated_fragments.*`. To keep
the MTU1 behaviour set `[fragmentation] enabled = false` (restart). Since
#335, while fragmentation is enabled, a config whose AF_XDP
`generated-frames` or AF_PACKET TX ring is under 4 frames fails validation
with `FRAGMENTATION_BACKEND_ROOM_TOO_SMALL`.

### Fragments through the firewall and the NAT (NAT-FRAG)

Only the first fragment of an IPv4 datagram (offset 0) carries the UDP,
TCP, or ICMP header, so the firewall and the NAT can only decide on it.
With the default `[fragment-tracking] mode = "associate"` the router keeps
a bounded association table (RFC 4787 REQ-14: a NAT must receive in-order
and out-of-order fragments):

- The first fragment gets the normal firewall rules and NAT translation on
  its header (the header must be whole in that fragment; the transport
  checksum covers the whole datagram and is left to the receiver). The
  table records how it left: egress, MACs, translated addresses, and the
  IPv4 ID the NAT generated for the datagram (once; every fragment of one
  datagram carries it).
- Every later fragment of the same datagram (same ingress, source,
  destination, protocol, and ID) is forwarded with that rewrite (TTL - 1);
  if the first fragment was refused, so is the rest
  (`drop.IPV4_FRAGMENT_FIRST_DENIED`). Fragments of plain routed traffic
  (no NAT) keep their addresses and ID.
- A later fragment that arrives before the first one is copied into a held
  slot and the frame is returned (`consume.IPV4_FRAGMENT_HELD`). When the
  first fragment is allowed, the held ones are rewritten and sent in the
  same tick through the fragmentation slots (`fragmentation.whole`, or cut
  again when above the egress MTU); when it is refused or does not come
  within `timeout-ms`, they are discarded (`fragment_tracking.held_denied`,
  `fragment_tracking.held_expired`).
- A forwarded fragment above the egress MTU is fragmented again like any
  DF-clear datagram (`fragmentation.*`), with the same generated ID.
- Refused as attacks on the transport header (RFC 1858, RFC 3128): a first
  fragment too short for its header (the usual
  `drop.FIREWALL_*_HEADER_TRUNCATED`, then the rest is
  `IPV4_FRAGMENT_FIRST_DENIED`), a later fragment that starts inside the
  header (`drop.IPV4_FRAGMENT_TRANSPORT_HEADER_OVERLAP`; for TCP offsets 8
  and 16 always), a second first fragment of a decided datagram
  (`drop.IPV4_FRAGMENT_DUPLICATE_FIRST`), and fragments that break RFC 791
  (`drop.IPV4_FRAGMENT_MALFORMED`: no data, MF with data not a multiple of
  8, data past 65515 bytes, or an end that contradicts the datagram's).
- Two datagrams with one key: the key has no ports, so an ID reused after
  a lost fragment, or a server answering two inside hosts with the same ID,
  share it. A second first fragment that is not a byte-identical duplicate
  (same length and a fingerprint of all its data) poisons the association: every
  remaining fragment of both datagrams is refused
  (`fragment_tracking.poisoned`, `drop.IPV4_FRAGMENT_FIRST_DENIED`), so a
  receiver never gets one datagram's fragments under the other's
  translation or ID. A byte-identical duplicate is dropped alone
  (`fragment_tracking.duplicate_first`). A fragment that contradicts the
  datagram's end (fixed by its first fragment with MF clear) poisons it too.
- An association is freed early once every data byte from 0 to the end was
  seen (duplicates and overlaps count once; a datagram in more than four
  separate pieces at a time waits for the timeout).
- Fragments addressed to the router's own addresses (other than the NAT
  public address) are not associated: the router does not reassemble
  (ICMP4-006, `drop.ICMPV4_FRAGMENT_UNSUPPORTED` for a fragmented ping).
  Fragmented ICMP errors through the NAT stay refused.

```toml
[fragment-tracking]
mode = "associate"     # default; "refuse" = hardening (every fragment dropped)
entries = 256          # default 256, 1..=16384; datagrams associated at once
entries-per-host = 32  # default 32, >= 1; per source address
held-fragments = 64    # default 64, 0..=512; fragments held before their first
held-per-host = 16     # default 16; per source address (0 = hold none)
timeout-ms = 5000      # default 5000, 100..=60000; from the first fragment seen
ingress-share-percent = 50  # default 50, 1..=100; most of the table one interface takes
```

The table is swept each tick (at most four expired associations), so the
occupancy and the expiry counters stay current without traffic.

Tuning:

- `entries` bounds the datagrams in flight at once; an entry is freed as
  soon as every byte up to the last fragment has passed, otherwise after
  `timeout-ms`. One ingress interface may take at most
  `ingress-share-percent` of the table (default 50): a flood arriving on
  the WAN cannot take the entries of LAN-originated datagrams
  (`drop.IPV4_FRAGMENT_INGRESS_LIMIT`). The share is a cap, not a
  reservation: one ingress takes at most floor(`entries` × share / 100)
  entries (at least one), so the last of n interfaces keeps room only while
  that times n − 1 stays below `entries`; use 100/n or less for equal
  parts. The held slots are shared the same way (floor(`held-fragments` ×
  share / 100) each, at least one). `ruster validate`, `ruster run`, and an
  applied reload warn with `FRAGMENT_INGRESS_SHARE_OVERCOMMITTED
  share-percent=P interfaces=N entries=E held=H` (event
  `FRAGMENT_SHARE_OVERCOMMITTED`) when, for the entries or the held slots,
  floor(size × share / 100) × (n − 1) ≥ size (on a small table the
  rounding can warn below 100/n too). With the default 50 the warning is
  expected on three or more interfaces: lower the share if one interface
  must keep room while the others are flooded.
  When the table, an ingress's share, or one (ingress, source)'s
  `entries-per-host` is full, an old association of that scope is evicted
  (`fragment_tracking.entries_evicted`, `held_evicted`): a pending or
  refused one first, else one that allows a datagram that has made no
  progress (no fragment) for a fifth of `timeout-ms` (1 s by default; a
  datagram's fragments arrive within milliseconds; a duplicate fragment is
  not progress). Finding the victim is O(1) whatever the scope holds, and
  victims are evicted only when the whole admission succeeds (a fragment
  refused for a limit evicts nothing). An evicted association that
  allowed its datagram (still allowing, or poisoned since) is remembered
  for `timeout-ms` (one tombstone per sixteen
  entries, at least 16; `fragment_tracking.tombstones_overwritten` counts
  the ones overwritten early): its late fragments and a new first fragment
  with its key are refused (`IPV4_FRAGMENT_FIRST_DENIED`,
  `IPV4_FRAGMENT_DUPLICATE_FIRST`, counted in `poisoned`). Only then is a
  new one refused
  (`drop.IPV4_FRAGMENT_TABLE_FULL`, `IPV4_FRAGMENT_INGRESS_LIMIT`,
  `IPV4_FRAGMENT_HOST_LIMIT`). Sizing: one entry per fragmented datagram in
  flight, plus one for every datagram that lost a fragment, for
  `timeout-ms`; a busy NAT with fragmented traffic and some loss (for
  example 50 lossy datagrams per second) needs `entries` of at least
  rate × timeout / share (here 50 × 5 / 0.5 = 500): raise `entries` above
  the default 256, or lower `timeout-ms`.
  A refused first fragment is refused before any NAT or firewall state is
  created.
- `held-fragments` bounds out-of-order fragments (`drop.IPV4_FRAGMENT_HOLD_FULL`,
  `drop.IPV4_FRAGMENT_HOST_HOLD_LIMIT`). Each holds one datagram of a
  fragmentation slot's size (3840 bytes by default). Without fragmentation
  (`[fragmentation] enabled = false`) nothing can be held and every
  fragment that arrives first is `IPV4_FRAGMENT_HOLD_FULL`. Released
  fragments use fragmentation slots (`[fragmentation] datagrams`) and the
  tick's fragment budget (`[tick] generated-fragments`).
- `timeout-ms` is not refreshed; fragments of one datagram normally arrive
  within milliseconds. Shorter frees the table sooner after a loss.
- The per-host limits count (ingress, source address): fragments from the
  WAN that claim an inside host's address use their own quota. A source
  can still be spoofed: a flood of forged fragments stays within its
  ingress's share, and its entries are evictable, but on that ingress it
  can evict other hosts' pending out-of-order datagrams, and about 13 forged
  later fragments per second compete with them for that ingress's part of
  the 64 default held slots. Held slots follow `ingress-share-percent` too:
  a full slot table makes an interface at its share of the held slots
  displace its own oldest held datagram, and one below it displace the
  oldest of an interface over its share, so a WAN flood cannot displace
  the LAN's out-of-order fragments (one datagram holds at most 16
  fragments, `drop.IPV4_FRAGMENT_DATAGRAM_HOLD_LIMIT`).
  Whole datagrams and in-order fragments are not affected. Whoever guesses a
  datagram's ID can poison its association and lose that one datagram
  (fail closed); a poisoned key refuses new datagrams for `timeout-ms`
  (residual FRAG-012).
- An allowing association lives until its datagram is complete or
  `timeout-ms`: the rest of a datagram still follows it for up to that long
  after its firewall state closed or its neighbor's MAC changed (a reload
  flushes it).
- Storage: `entries` × (entry + host slot + 2 directory nodes) +
  next_power_of_two(`entries`) × 2 directory buckets + max(16,
  `entries` / 16) × (tombstone + directory node and bucket) +
  `held-fragments` × (record + slot): 305472 bytes by default, counted in
  `storage-bytes`.
  Every `[fragment-tracking]` change is restart-required (`STORAGE_SHAPE`).
- A reload (SIGHUP apply) discards every association and held fragment
  (`fragment_tracking.entries_flushed`, `held_flushed`): a datagram in
  flight across a reload loses its later fragments (its receiver times
  out). The next datagram is associated normally.

Counters (`ruster-run-stats`): `fragment_tracking.first_allowed`,
`first_denied`, `followed` (later fragments forwarded), `followed_denied`,
`held`, `released` (held fragments staged in the fragmentation slots, not
yet sent: `fragmentation.whole` and `generated_fragments.*` report what
left), `release_dropped` (a held fragment that could not be staged: TTL,
overlap, DF above the MTU, or no fragmentation slot), `held_denied` (with a
refused first fragment or a poisoned association), `held_expired`,
`entries_expired`, `entries_completed` (every byte decided, before the
backend took the last fragments), `entries_evicted`, `held_evicted`,
`poisoned`, `duplicate_first`, `entries_flushed`, `held_flushed`; `consume.IPV4_FRAGMENT_HELD`
(= `held`); `fragmentation.whole` (released fragments sent unchanged).

Troubleshooting:

| Symptom | Counter | What to do |
|---|---|---|
| fragmented datagrams of one host stop | `drop.IPV4_FRAGMENT_HOST_LIMIT` | that source has `entries-per-host` datagrams in flight, all allowed: raise it, look for a host sending many fragmented datagrams |
| fragmented datagrams of every host stop | `drop.IPV4_FRAGMENT_TABLE_FULL` | every entry allows a datagram: raise `entries` |
| reordered fragments lost under load | `fragment_tracking.entries_evicted`, `held_evicted` | pending associations were evicted for new datagrams: raise `entries`; check for a flood of fragments (spoofed sources) |
| a fragmented flow stops after one datagram | `fragment_tracking.poisoned`, `drop.IPV4_FRAGMENT_DUPLICATE_FIRST` | two datagrams shared a key (a sender reusing IDs fast, or a server answering two inside hosts with one ID): both were refused |
| reordered fragments lost | `drop.IPV4_FRAGMENT_HOLD_FULL`, `HOST_HOLD_LIMIT`, `fragment_tracking.held_expired` | raise `held-fragments`/`held-per-host`; `held_expired` alone means the first fragment never came (lost upstream or refused before the table) |
| held fragments not sent | `fragment_tracking.release_dropped`, `drop.IPV4_FRAGMENTATION_QUEUE_FULL` | raise `[fragmentation] datagrams` and `[tick] generated-fragments` |
| a fragment flow refused as a whole | `fragment_tracking.first_denied`, `drop.IPV4_FRAGMENT_FIRST_DENIED` | the first fragment was refused: see its own drop reason (firewall rule, NAT mapping) |
| fragments refused everywhere | `drop.FIREWALL_FRAGMENT_UNSUPPORTED` | `[fragment-tracking] mode = "refuse"` is set |

Upgrade note (NAT-FRAG, behaviour change): fragment association is on by
default, also for configs without `[fragment-tracking]`. Fragments that
were dropped as `drop.FIREWALL_FRAGMENT_UNSUPPORTED` (and, without the
firewall, `NAT44_*_NON_ATOMIC_IPV4_UNSUPPORTED`/`NAT44_ICMP_FRAGMENT_UNSUPPORTED`)
now pass the firewall's rules and the NAT on their first fragment, creating
mappings and firewall state; review the rules if you relied on that drop,
and expect those counters to fall to 0. The default table adds 305472
bytes of storage (the maximal production config, with `entries = 16384` and
`held-fragments = 512`, was 67050176 bytes; 67050272 since GARP). A config with every table at
its production limit and per-host NAT44 limits that just fitted 64 MiB may
now fail with `RUNTIME_STORAGE_BYTES_EXCEEDED`: lower `[fragment-tracking]
entries`/`held-fragments` or `[fragmentation] datagrams`, size a table
down, or (hardening) set `mode = "refuse"`. New drop codes 190
`IPV4_FRAGMENT_FIRST_DENIED`, 191 `IPV4_FRAGMENT_DUPLICATE_FIRST`, 192
`IPV4_FRAGMENT_TRANSPORT_HEADER_OVERLAP`, 193 `IPV4_FRAGMENT_MALFORMED`, 194
`IPV4_FRAGMENT_TABLE_FULL`, 195 `IPV4_FRAGMENT_HOST_LIMIT`, 196
`IPV4_FRAGMENT_HOLD_FULL`, 197 `IPV4_FRAGMENT_HOST_HOLD_LIMIT`, 198
`IPV4_FRAGMENT_HOLD_TOO_LARGE`, 199 `IPV4_FRAGMENT_INGRESS_LIMIT`, 200
`IPV4_FRAGMENT_DATAGRAM_HOLD_LIMIT`; new consume code `IPV4_FRAGMENT_HELD`; new
stats section `fragment_tracking.*` and `fragmentation.whole`; new
validation codes `FRAGMENT_TRACKING_POLICY` and
`FRAGMENT_TRACKING_ENTRIES_ZERO`. To keep the old behaviour set
`[fragment-tracking] mode = "refuse"` (restart).

### First datagrams to an unresolved neighbour (ARP-HOLD)

RFC 1122 §2.3.2.2 and RFC 1812 §3.3.2: the router should save at least the
latest datagram to an address it is still resolving by ARP and send it when
the address resolves. With the default `[resolution.hold]` it does:

- A forwarded datagram whose next hop (the gateway, or the destination on
  a connected network, on either side of the NAT) has no static or live
  dynamic neighbour, and for which an ARP request is queued, retried, or
  already pending, is copied into a hold slot and the frame is returned
  (`consume.ARP_HELD`). Nothing is committed for it yet: no NAT mapping,
  no firewall state, no TTL decrement. The firewall's rules still apply
  first: a denied datagram is never held.
- After every RX batch the held datagrams whose next hop is now known are
  forwarded again from scratch (route, TTL, firewall, NAT, MTU, and
  fragmentation decided then) and sent at the end of the same tick, after
  the router's own ARP requests and ICMP errors, within `[tick]
  generated-fragments`, through the fragmentation slots (`[fragmentation]
  datagrams` bounds how many one tick replays; the rest go next tick,
  `arp_hold.deferred`). A DF-clear datagram above the egress MTU is
  fragmented then; a DF-set one gets Fragmentation Needed.
- So `ping -c1` through the router succeeds on the first try with an empty
  neighbour cache, the first TCP SYN goes out without waiting for its
  retransmission, and a DNS query is not retried.
- When the resolution fails (three requests one second apart by default),
  the held datagrams are discarded (`arp_hold.failed` or `expired`); the
  sender gets the same single Destination Unreachable (Host) as before for
  a directly connected destination.
- Every applied reload (SIGHUP) discards the held datagrams
  (`arp_hold.flushed`), whatever `[reload] state` carries.

```toml
[resolution.hold]      # optional; absent = these defaults; restart-required
enabled = true         # false: drop as NEIGHBOR_UNRESOLVED (the behaviour before ARP-HOLD)
per-neighbor = 3       # 1..=64 per (egress, next hop); a new one replaces the oldest
per-host = 16          # 1..=packets per (ingress, source); beyond: drop.ARP_HOLD_HOST_LIMIT
per-ingress = 32       # 1..=packets per ingress interface; beyond: drop.ARP_HOLD_INGRESS_LIMIT
                       # (default: half of packets; = packets does not partition)
packets = 64           # 1..=64 in all; beyond: drop.ARP_HOLD_FULL
```

Each slot is a fragmentation slot's size (14 + the longest datagram a
port can receive, 3840 bytes with AF_XDP frames) plus a 40-byte record:
the default table is 248320 bytes. Nothing is held with `[fragmentation]
enabled = false` (the replay leaves through its slots). The maximum of 64
is what the 64 MiB storage bound leaves when every other table is at its
production limit.

Tuning: `per-neighbor` is how many first datagrams of new flows to one
next hop survive (a host opening a few connections at once to a new
gateway); raising it costs nothing until used. Lower `packets` (or turn
the hold off) to bound the copy work a flood of datagrams to unresolvable
addresses on a connected network can cause: each such datagram is copied
once (cold path) and costs a walk of at most `packets` records.

Counters (`ruster-run-stats`): `arp_hold.held` (= `consume.ARP_HELD`),
`replaced`, `refused_full`/`refused_host_limit`/`refused_ingress_limit`/`refused_too_large`
(= `drop.ARP_HOLD_FULL`/`ARP_HOLD_HOST_LIMIT`/`ARP_HOLD_INGRESS_LIMIT`/`ARP_HOLD_TOO_LARGE`),
`replayed` (decided again), of which `replay_sent` (staged whole),
`replay_fragmented`, `replay_parked` (held by the fragment association
table instead of decided; not expected), `replay_dropped` (for example a NAT mapping that
expired meanwhile; a replay's drops are not counted again under `drop.*`:
the frame was already counted as `consume.ARP_HELD`), `replay_unstaged`
(committed but no fragmentation slot left; a first fragment reserves room
for up to 16 fragments its datagram may hold in the association table, so
this stays 0),
`deferred`, `failed` (the resolution failed), `cancelled` (cancelled, or the
learned neighbour expired while the replay waited for room), `expired`, and
`flushed`. Every bound is checked also with `enabled = false`; a bound
above `packets` is `ARP_HOLD_BOUND_ABOVE_PACKETS` (the defaults are capped
at `packets`), and `enabled = true` written with `[fragmentation] enabled =
false` is `ARP_HOLD_WITHOUT_FRAGMENTATION`.

| Symptom | Counters | Meaning / action |
|---|---|---|
| first datagrams of new flows still lost | `drop.NEIGHBOR_UNRESOLVED` | the hold is off, there is no fragmentation, or the resolution could not start (`resolution.state_full`/`action_full`, a Failed hold-down) |
| first datagrams lost under load | `drop.ARP_HOLD_FULL`, `drop.ARP_HOLD_HOST_LIMIT`, `drop.ARP_HOLD_INGRESS_LIMIT` | many unresolved next hops at once (a scan of a connected network, or a flood from one interface?): raise `packets`/`per-host`/`per-ingress` or find the source |
| only the last few of a burst arrive | `arp_hold.replaced` | `per-neighbor` datagrams per next hop are kept: raise it |
| held datagrams sent late | `arp_hold.deferred` | not enough free fragmentation slots per tick: raise `[fragmentation] datagrams` |
| held datagrams never sent | `arp_hold.failed`, `expired`, `resolution.timed_out` | the neighbour never answered ARP |

Upgrade note (ARP-HOLD, behaviour change): the hold is on by default, also
for configs without `[resolution.hold]`. Datagrams that were dropped as
`drop.NEIGHBOR_UNRESOLVED` are now held and sent, so that counter falls to
(near) 0 and `consume.ARP_HELD` rises; firewall and NAT state for them is
created when they are sent, not dropped. The default table adds 248320
bytes of storage (the maximal production config was 67050176 bytes;
67050272 since GARP). **A
config that just fitted 64 MiB fails after the upgrade with no change of
its own**: `stage=validate code=RUNTIME_STORAGE_BYTES_EXCEEDED
path=resolution.hold.packets` (the path is set when the document fits
without the hold). Lower `[resolution.hold] packets` (each slot is about
3.8 KiB) or set `enabled = false`, before upgrading a router whose
`ruster validate` shows `storage-bytes=` above 66860000.
New drop codes 201 `ARP_HOLD_FULL`, 202 `ARP_HOLD_HOST_LIMIT`, 203
`ARP_HOLD_TOO_LARGE`, 204 `ARP_HOLD_INGRESS_LIMIT`; new consume code
`ARP_HELD`; new stats section `arp_hold.*`; new validation codes
`ARP_HOLD_POLICY`, `ARP_HOLD_PACKETS_ZERO`, `ARP_HOLD_BOUND_ABOVE_PACKETS`,
and `ARP_HOLD_WITHOUT_FRAGMENTATION`. To keep the old behaviour set
`[resolution.hold] enabled = false` (restart).

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

### Privilege drop

Before startup completes the process needs the capabilities of section 1.
After it, nothing does, so the process gives them up for good:

| | before the drop (startup) | after the drop (the whole run) |
|---|---|---|
| capabilities (`CapInh`, `CapPrm`, `CapEff`, `CapAmb`) | as started (root: all) | none, in every thread |
| bounding set (`CapBnd`) | as started | empty if `CAP_SETPCAP` was effective, otherwise unchanged (`bounding-set=kept`) |
| `no_new_privs` | as started | 1: no `execve` can grant anything (setuid binaries, file capabilities) |
| uid/gid | as started | unchanged, or with `--user`/`--group` those ids (real, effective, saved, filesystem) and no supplementary group |

When: after every port is open, checked and attached, the datapath and
adapter are built and generation 1 is active, and before the first tick.
Linux credentials are per thread. The two output threads (`ruster-stdout`,
`ruster-stderr`) are started before startup and drop their own privileges
(the same steps, the same identity) before they write anything; the link
watcher (`ruster-watch`) and the reload worker (`ruster-reload`) are
started after activation and drop their own before they take any request
(section 7, "Threads"); the router thread drops its own last. Each uses raw per-thread syscalls
(not the C library's process-wide `setuid`, which would also drop the
router thread too early). Steps per thread: `PR_SET_DUMPABLE` 0 (a flag
of the whole process, set before the first identity change, set again
right after `setresuid` because an euid change resets it to
`fs.suid_dumpable`, and read back at the end); `PR_SET_KEEPCAPS` 0; with
`CAP_SETPCAP`, `PR_CAPBSET_DROP` of every capability; `PR_CAP_AMBIENT`
clear; with `--user`/`--group` `setgroups(0)`, `setresgid`, `setresuid`;
`capset` with empty sets; `PR_SET_NO_NEW_PRIVS` 1. Each thread then checks
its own `/proc/thread-self/status`, and the router thread finally reads
`/proc/self/task/*/status` and requires every thread of the process to show
the dropped state, the two workers included. The line reports how many
threads were checked (`threads=5`).

What still works without any capability (verified by the privileged smoke,
section 13): AF_XDP RX/TX on the open sockets (ring and UMEM memory, the
`sendto`/`poll` kicks), `XDP_STATISTICS` (`getsockopt` on an owned
socket), the link watch (new `NETLINK_ROUTE` sockets and `GETLINK`,
`GETADDR`, `GETROUTE` dumps are open to every user, also when the socket is
recreated after a failure; the sysctls it reads are world-readable), SIGHUP
reload (it never opens a socket or attaches a program: backend changes are
restart-required and refused), the health watch and its fatal exits, the
drain, and the teardown (closing the XDP link fd detaches; the XSKMAP entry
delete runs on a map fd the process holds, which Linux 6.5 and newer allow
without a capability; earlier kernels refuse every `bpf(2)` call without
`CAP_BPF` while `kernel.unprivileged_bpf_disabled` is set, so the drop is
refused there at startup with `TEARDOWN_NEEDS_CAPABILITIES`).

What changes:

- Root without capabilities has no `CAP_DAC_OVERRIDE`: a reload reads the
  config with plain file permissions. A config in another user's private
  directory fails with `reload failed: stage=read code=PERMISSION_DENIED`
  (startup still read it). With `--user`/`--group` the config and every
  directory above it must be readable by that user, and
  `--strict-config-perms` then accepts files owned by root or by that user.
  The layout of section 2 (`/etc/ruster` `root:<group> 0750`, the config
  `root:<group> 0640`) works in every mode: root reads it as the owner,
  the switched user through its group, and `--strict-config-perms` accepts
  it (the privileged smoke reloads exactly this layout).
- uid 0 without capabilities still owns every root-owned file. Use
  `--user`/`--group` with a dedicated account to take that away too.
- The process is not dumpable from the drop on: no core dumps, and
  `ptrace` or `/proc/<pid>/mem` of it needs `CAP_SYS_PTRACE`, also for the
  switched user. Its `/proc/<pid>` entries are owned by root.
- With `--user`/`--group` that user can signal the router (SIGHUP reload,
  SIGTERM stop: the kernel lets a user signal a process whose real or
  saved uid is theirs) and owns its locked memory accounting from then on.
  The output threads switch at spawn, before startup, so during startup
  (usually under a second, longer with startup retries) that user can already send them signals,
  which are delivered to the process like any other: SIGHUP and SIGTERM
  are only flags read by the router thread (a stop during startup rolls
  back and exits 0), and SIGKILL or SIGSTOP end or pause the process like
  a crash (the unpinned links detach). The user cannot `ptrace` or read
  the still privileged router thread: the process is made not dumpable
  before any thread switches. What remains: with `fs.suid_dumpable=1` (not
  a default) the kernel makes the process dumpable again inside each
  thread's `setresuid` until the very next `PR_SET_DUMPABLE` call, a
  window of one syscall per thread; keep `fs.suid_dumpable` at 0 or 2.
- Nothing can bring a capability back: restart the router to change
  anything restart-required, as before.

Failure: any failed step aborts startup with the full rollback of section 5
(`startup failed: stage=privilege-drop code=<STEP>/ERRNO_<n>`,
`code=NOT_DROPPED/<WHAT>` when a thread still holds something, or
`code=STATUS_UNREADABLE`; exit 1). A worker thread that cannot drop fails startup
the same way after activation (`stage=privilege-drop code=...`), before the
router thread's own drop; a worker that cannot be spawned at all is
`stage=workers code=THREAD_SPAWN`. An output thread that cannot drop fails
before anything is opened (`stage=privilege-drop code=... thread=output`,
exit 1). The router never runs half-dropped.

### Filesystem confinement (Landlock)

The drop leaves the process able to open, read-only, every file its user
may read, and without `--user`/`--group` that user is uid 0, the owner of
every root file (`/etc/shadow`, keys). Right after the drop and before the
syscall filter, every thread is confined to the files the run reads, with
one Landlock ruleset (H11, CLI-122 to CLI-127; `--fs-confine landlock`,
the default; `off` opts out):

| readable after startup | why |
|---|---|
| files beneath the config file's directory (as the path names it, and the directory of the file it resolves to if that is another one); not listable | the SIGHUP reload, also after an atomic replace (a new file renamed into place) |
| `/proc/<pid>` of the router itself (files, and listing) | the drop and filter verifications (`/proc/self/task/*/status`), `/proc/self/status` (the effective uid of `--strict-config-perms`) |
| files beneath `/proc/sys/net` | the link watch's forwarding, `rp_filter`, and IPv6 sysctls |
| the `ruster` binary | symbolizing a panic backtrace (`RUST_BACKTRACE=1`) |

Everything else is refused (`EACCES`): opening, listing, executing,
writing, creating, removing, linking, and renaming by path, including
`/etc`, `/dev`, `/sys`, other processes' `/proc/<pid>`, and the rest of
`/proc/sys`. Truncating by path is a Landlock right only from ABI 3
(Linux 6.2); before that it is kept out by the syscall filter alone (its
`openat` rule refuses `O_TRUNC`, and `truncate`/`ftruncate` are not on the
allowlist), so on such a kernel `--seccomp log|off` lets a compromised
router truncate a file its user may write. On ABI 4 (Linux 6.7) and newer
TCP `bind` and `connect` are refused too (no rule grants a port; the run
uses AF_XDP, rtnetlink, and a Unix datagram socket, never TCP): defence in
depth for `--seccomp log|off`, under which `socket` is not limited. Landlock checks where an open resolves to, so
`/proc/<pid>/root/...`, `/proc/self/cwd/...`, and a symlink from the
config directory to a file outside it are refused too. What stays: the fds
opened before (port sockets, netlink and notification sockets,
`/dev/urandom`, stdout/stderr), and metadata (`stat`, `readlink`: the
`--strict-config-perms` walk up to `/` and its `/proc/self/fd/N` link
work). The confinement is independent of the drop: with
`--keep-privileges` the kept capabilities do not bypass it (Landlock
applies to root and `CAP_DAC_OVERRIDE` alike), and with `--user`/`--group`
the plain file permissions still apply on top.

Keep the config in a directory of its own (`/etc/ruster/`, section 2):
every file the router's user may read beneath that directory stays
readable. A config whose directory (as named, or as resolved through a
symlink) is `/` is refused at startup (`stage=fs-confine
code=CONFIG_DIRECTORY_ROOT`, exit 1: it would grant reading the whole
filesystem). One directly in `/etc`, `/home`, `/root`, `/usr`, or `/var`
starts with the warning `warning: fs-confine
code=CONFIG_DIRECTORY_BROAD directory=/etc: ...`: in `/etc` it keeps
`/etc/shadow` readable to uid 0. A reload through a symlink that now points outside the granted
directories fails with `reload failed: stage=read code=PERMISSION_DENIED`
(generation N keeps running); restart to make a new location readable.

When: the ruleset is built first thing (before any thread exists, from the
`--config` path); each thread confines itself after its own privilege
drop: the two output threads at spawn, the link watcher and the reload
worker at spawn after activation, and the router thread right after its
drop. Each thread then checks itself (listing `/` must fail with
`EACCES`) and records its thread id, and the router thread requires the
recorded ids to be exactly those `/proc/self/task` lists (`threads=5`).
On Landlock ABI 7 (Linux 6.15) and newer with audit enabled, that
self-check makes the kernel log one Landlock denial record per thread at
startup (`type=1423`, `AUDIT_LANDLOCK_ACCESS`, five in all): expected, not
a fault. `PR_SET_NO_NEW_PRIVS` is set on each
thread first (Landlock needs it without `CAP_SYS_ADMIN`; the drop and the
filter set it anyway). The `landlock_*` and `prctl` calls all happen
before the syscall filter, which allows none of them: nothing is added to
the allowlist. The rules hold the `O_PATH` fds of their directories for
the whole run (a procfs directory gets a new inode once its cache entry is
reclaimed; a held one is never reclaimed).

Kernel: Landlock ABI 1 (Linux 5.13) or newer, enabled (`landlock` in
`cat /sys/kernel/security/lsm`; Ubuntu 22.04 and newer, Debian 12, Fedora
enable it; otherwise add it to the boot `lsm=` list). The ruleset handles
every filesystem right of the running ABI up to ABI 5 (refer from ABI 2,
truncate from 3, device ioctl from 5) and never a right a later kernel
defines, so a newer kernel restricts nothing new. The startup line and the
stats report the ABI (`fs.abi`). Without Landlock startup fails before
anything is opened (`stage=fs-confine code=LANDLOCK_UNSUPPORTED` before
5.13 or built without it, `LANDLOCK_DISABLED` when not enabled at boot,
`LANDLOCK_BLOCKED` when a supervisor's syscall filter refuses the
`landlock_*` calls with `EPERM`; exit 1); `--fs-confine off` runs without
it (`warning: fs-confine=off`).

Failure: any other failed step aborts startup with the full rollback
(`stage=fs-confine code=...`, exit 1, section 14): before any thread
(the ruleset: `ABI`, `RULESET`, `OPEN.<GRANT>`, `ADD_RULE.<GRANT>`), in an
output thread (`thread=output`) or a worker's prologue, or on the router
thread (`NOT_CONFINED/PROBE\|THREADS`, `NOT_PREPARED`, `STATUS_UNREADABLE`).

### Syscall filter (seccomp)

Right after the privilege drop (also with `--keep-privileges`), before the
first tick, the router thread confines every thread of the process to the
syscalls the run needs, with one classic BPF program installed by
`seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC)` (H8,
CLI-102 to CLI-109). TSYNC attaches the same filter to all five threads at
once (or to none when a thread has a filter of its own that is not an
ancestor of the router thread's: `TSYNC_CONFLICT`); no thread is started
after it, and a thread could not be: `clone` is not allowed. The kernel needs
`no_new_privs` on the installing thread: the drop has set it; with
`--keep-privileges` it is set here (no capability is lost; it only stops an
`execve` from granting any, and ruster executes nothing), and TSYNC sets
it on every thread. The router thread then requires every thread
(`/proc/self/task/*/status`) to show `Seccomp: 2`, `NoNewPrivs: 1`, and
one filter more than before (`Seccomp_filters`, Linux 5.9). A supervisor's
own filter (systemd `SystemCallFilter=`, a container runtime) stays
underneath; the stricter result applies, and that filter must allow
`seccomp` and `prctl` at startup, and with the default `--fs-confine
landlock` also `landlock_create_ruleset`, `landlock_add_rule`, and
`landlock_restrict_self` (systemd's `@sandbox` group has them). The line
`ruster run: seccomp filter installed: mode=kill threads=5 syscalls=N
arch=x86_64` follows the drop line; the stats show `seccomp.*`
(section 11).

The program, in order:

1. `seccomp_data.arch` must be `AUDIT_ARCH_X86_64` and the number must not
   carry the x32 bit (`0x40000000`): otherwise the process is killed, in
   `log` mode too (the allowlist is in x86_64 numbers; ruster never makes
   an i386 or x32 call).
2. An allowlisted syscall runs if its argument conditions hold. Conditions
   compare the low 32 bits of a C `int` argument, which is all the kernel
   reads of it.
3. Anything else gets the `--seccomp` action: `kill`
   (`SECCOMP_RET_KILL_PROCESS`, the default: every thread dies at once, the
   kernel closes every fd and the unpinned XDP links detach within
   milliseconds as after SIGKILL, section 10; no drain, no final stats; not
   dumpable, so no core file) or `log` (`SECCOMP_RET_LOG`: logged, then
   run).

The allowlist (x86_64 numbers; derived by reading every thread's code after
the drop and checked against `strace -f` of the whole privileged smoke
attached to the running router; the Rust test
`seccomp::tests::live` runs the same work in a filtered child):

| syscall | condition | who needs it after startup |
|---|---|---|
| `sendto` (44) | — | router: AF_XDP TX kick and the systemd notifications (H10, on the socket opened before the filter); link watcher: netlink requests (`send`) |
| `poll` (7) | — | router: the idle wait on every port socket (section 7, H9) and the Fill-ring wakeup of the need-wakeup profile; glibc's `poll()` is this syscall on x86_64, never `ppoll` |
| `getsockopt` (55) | (level, option) one of `(SOL_XDP, XDP_STATISTICS)`, `(SOL_PACKET, PACKET_STATISTICS)`, `(SOL_SOCKET, SO_ERROR)` | router: AF_XDP `XDP_STATISTICS` per stats sample; AF_PACKET `PACKET_STATISTICS` per health sample and `SO_ERROR` after a `POLLERR` (AFPKT-015) |
| `clock_nanosleep` (230), `nanosleep` (35), `restart_syscall` (219) | — | the 1 ms fallback sleep of the idle wait, the reload quiescence pause, the drain, and every `thread::sleep` (`nanosleep` where the C library's sleep uses it: older glibc, musl); resuming one a signal interrupted |
| `clock_gettime` (228) | — | the monotonic clock (normally a vDSO call; this syscall without a vDSO) |
| `futex` (202), `sched_yield` (24) | — | channels between the threads; std's channels back off with `yield_now` in disconnect and preemption races (dropping the worker and output channels) |
| `write` (1) | — | output threads (stdout, stderr), a panic message |
| `read` (0) | — | config, sysctls, `/proc`, `/dev/urandom` keys of a reload |
| `recvfrom` (45), `getsockname` (51) | — | link watcher: netlink answers and the socket's port id |
| `openat` (257) | flags without `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC` | read-only opens: config, sysctls, `/proc` (no file is ever created, truncated, or opened for writing) |
| `close` (3) | — | every fd closed: files, replaced netlink sockets, teardown |
| `statx` (332), `fstat` (5), `newfstatat` (262) | — | std file metadata (reload, `--strict-config-perms`); glibc `opendir` checks its fd with `fstat`, which is the `fstat` syscall before glibc 2.33 and from 2.39 on, and `newfstatat(fd, "", AT_EMPTY_PATH)` in glibc 2.33 to 2.38 (Ubuntu 22.04, Debian 12, RHEL 9); std falls back to `fstat64`/`stat64`/`lstat64` (`newfstatat`) when a supervisor refuses `statx`. Read-only metadata either way |
| `readlink` (89) | — | `--strict-config-perms`: the path of the opened config (`/proc/self/fd/N`) |
| `getdents64` (217) | — | listing `/proc/self/task` (the verification after the install) |
| `fcntl` (72) | `F_GETFD` only | debug builds of std check an fd before closing it |
| `mmap` (9), `mprotect` (10) | protection without `PROT_EXEC` | allocation (glibc malloc and its per-thread arenas); never executable memory |
| `munmap` (11), `mremap` (25), `brk` (12), `madvise` (28) | — | allocation, freeing, a thread's stack at exit |
| `getrandom` (318) | — | std's per-thread hash keys, drawn on a thread's first `HashMap` |
| `socket` (41) | `AF_NETLINK` and `NETLINK_ROUTE` | link watcher: a replacement rtnetlink socket after a failed query |
| `setsockopt` (54) | `SOL_NETLINK` and `NETLINK_GET_STRICT_CHK` | strict checking on that socket |
| `connect` (42) | — | connecting that socket to the kernel |
| `bpf` (321) | `BPF_MAP_DELETE_ELEM` only | teardown: the XSKMAP entry delete on the map fd the process holds |
| `rt_sigreturn` (15) | — | return from the SIGINT/SIGTERM/SIGHUP handlers |
| `exit` (60), `exit_group` (231), `sigaltstack` (131), `rt_sigprocmask` (14) | — | thread and process exit (glibc blocks signals and frees the thread's stacks) |
| `getpid` (39), `gettid` (186), `tgkill` (234) | `tgkill`: this process only | `abort` (a panic while panicking) raises SIGABRT at itself; a panic message names the thread id |
| `getcwd` (79), `lseek` (8) | — | a panic backtrace under `RUST_BACKTRACE=1` shortens paths against the working directory and reads the binary's debug info |
| `rt_sigaction` (13) | — | std's SIGSEGV/SIGBUS handler restores the default action before re-raising, so a crash keeps its own signal |

What the filter does not take away: everything the allowed calls can do
on what the process may reach. Its read-only `openat` reaches only the
files of the filesystem confinement above (with `--fs-confine off`, and
without `--user`/`--group`, every root-readable file: keys,
`/etc/shadow`); an open alone can also have a side effect on some
devices (a `/dev/watchdog`-style device arms on open). Use `--user`/
`--group` with a dedicated account for the full benefit. Under
`--keep-privileges` the filter does not narrow what the kept capabilities
allow through the calls it permits: an rtnetlink request on the link
watcher's socket can change links, addresses and routes (`CAP_NET_ADMIN`),
and `bpf(BPF_MAP_DELETE_ELEM)` works on every map fd the process holds.

Not on it (a selection): `open`, `ioctl`, `execve`, `clone`/`clone3`/
`fork`, `kill`, `ptrace`, `prctl`, `setuid` and the other credential calls,
`mount`, `bind`/`listen`/`accept`, `sendmsg`/`recvmsg`, `unlink`/`rename`/
`mkdir`, `memfd_create`, `io_uring_*`, `perf_event_open`, `seccomp`, every
`bpf` command but the delete, and executable mappings. The kernel caches
the result of an unconditional allow per syscall number (Linux 5.11), so the
hot-path calls (`sendto`, `poll`, `getsockopt`, `clock_nanosleep`, `futex`)
skip the program; the hot path is listed first for older kernels.

Failure: anything that keeps the filter from being installed or verified
aborts startup with the full rollback of this section
(`startup failed: stage=seccomp code=...`, exit 1, section 14), after the
privilege drop line and before the readiness line.

Diagnosing a kill (`killed by SIGSYS`, or systemd `status=31/SYS`): the
kernel logs every seccomp kill (and every `log` hit) as an audit record:

```bash
journalctl -k | grep 'type=1326'        # or: dmesg | grep type=1326
ausearch -m SECCOMP -ts recent          # where auditd runs (records go there)
```

`syscall=N` is the x86_64 number (`ausyscall N`, or
`/usr/include/x86_64-linux-gnu/asm/unistd_64.h`), `comm=` the thread
(`ruster`, `ruster-watch`, `ruster-reload`, `ruster-stdout`,
`ruster-stderr`), `code=0x80000000` a kill and `0x7ffc0000` a logged run.
Restart with `--seccomp log` to keep running while collecting every
missing entry, and report the records (they hold no packet or config data).
The kernel rate-limits these messages without auditd. Use `--seccomp off`
only if the filter itself cannot be installed (for example a
supervisor's filter that refuses `seccomp`).

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

### JSON log format (`--log-format json`, OPS-LOG)

With `--log-format json` every line `ruster run` writes is one JSON object
on its own line (JSON Lines, RFC 8259), on the same stream as in text:
events on stderr, stats blocks on stdout. The router thread still queues
the same text; each output thread translates what it writes, so the
bounded queues, `output.dropped`, and the bounded exit wait above are the
same in both formats, and the router does no extra work per line. Lines
written before the output threads start (a config that does not load, a
failed early startup step) are translated on the main thread. Usage
errors (bad flags) are text: the format is not known yet. Under systemd
each stderr line becomes one journal entry (`journalctl -u ruster -o cat |
jq`); the `sd_notify` messages (section 5) do not change.

Schema `ruster-run-log/v1`, keys in this order:

| key | type | content |
|---|---|---|
| `schema` | string | `ruster-run-log/v1` |
| `ts` | string | UTC wall clock when the output thread wrote the line, RFC 3339 with milliseconds (`2026-11-03T12:14:56.789Z`); for ordering within the run use `uptime-ms` of the stats and the line order |
| `level` | string | `info`, `warn`, or `error` |
| `event` | string | stable event code (below) |
| `msg` | string | the text line without the `ruster run: ` (or `ruster: `) prefix, so every text match still works on `msg` |
| `fields` | object | every `key=value` token of `msg`: whole numbers as numbers, `true`/`false` as booleans, the rest as strings. In a `;`-separated clause that starts with one bare word the keys get that word as prefix (`flushed.dynamic-neighbors`, `carried.firewall-flows`, `state.arp`, `drain.calls`); of two equal keys the first wins. Health and startup check lines also get `code` (the condition, `TX_STALL`, `MULTI_QUEUE_ALLOWED`, ...) |
| `truncated` | boolean | only when `msg` was cut at 16 KiB or a stats block at 65536 lines |
| `stats` | object | `STATS` only: each `section.key=value` line of the block under its text key (`"if1.watch.link_up": true`, `"observer.generation": 2`, `"observer.last_apply": null` for `none`, labels as strings); `fields` holds `kind` and `uptime-ms` |

Strings are escaped per RFC 8259 and the output is pure ASCII (`"`, `\`,
control characters, DEL and every non-ASCII character as `\uXXXX`), so a
value can never end the line or add a key or an event. The messages are
value-free by design anyway (interface ids, codes, counts, fixed names; no
device name, address, or path from the config or the command line: the
`directory=` of `FS_CONFINE_WARNING` is one of the fixed broad directories
such as `/etc`, never the `--config` path). Numbers are exact unsigned
64-bit values; a consumer that reads JSON numbers as doubles (JavaScript,
`jq` before 1.7) loses precision above 2^53.

Event codes (one per message form; a renamed code is a breaking change,
so new messages get new codes):

| event | level | text line |
|---|---|---|
| `READY` | info | `running generation N on M port(s); ...` |
| `RELOAD_REQUESTED`, `RELOAD_CHECKED`, `RELOAD_APPLIED` | info | `reload requested`, `reload checked:`, `reload applied:` (section 6) |
| `RELOAD_REFUSED`, `RELOAD_FAILED` | warn | `reload refused:`, `reload failed:` |
| `WATCH_SETTINGS_APPLIED` | info | `watch settings applied:` (section 7) |
| `HEALTH_WARNING`, `HEALTH_RECOVERED`, `HEALTH_FATAL` | warn, info, error | `warning:`, `recovered:`, `fatal: port=if<id> health=<CODE>` (sections 7 and 8) |
| `CHECK_WARNING` | warn | `warning: port=if<id> <CODE> ...` (startup device check accepted by an override, `MTU_BELOW_DEVICE`) |
| `SWEEP_SLOW` | warn | `warning: RESOLUTION_SWEEP_SLOW ...` |
| `FRAGMENT_SHARE_OVERCOMMITTED` | warn | `warning: FRAGMENT_INGRESS_SHARE_OVERCOMMITTED ...` |
| `SOURCE_VALIDATION_WARNING` | warn | `warning: SOURCE_VALIDATION_DEFAULT_IGNORED interface=if<id>`, `warning: SOURCE_VALIDATION_NO_ROUTE interface=if<id>` (URPF) |
| `RELOAD_PREPARE_SLOW`, `IDLE_POLL_FAILED`, `WORKER_ABANDONED`, `KERNEL_EXPOSURE_AT_EXIT` | warn | `warning: reload preparation running ...`, `warning: idle poll failed ...`, `warning: the <thread> thread did not end ...`, `warning: kernel ...` (exit) |
| `PRIVILEGES_DROPPED`, `FS_CONFINED`, `SECCOMP_INSTALLED` | info | the hardening lines of section 5 |
| `PRIVILEGES_KEPT`, `FS_CONFINE_OFF`, `FS_CONFINE_WARNING`, `SECCOMP_LOG`, `SECCOMP_OFF` | warn | their opt-out and broad-directory warnings |
| `FLAG_OVERRIDDEN` | warn | `warning: --<flag> is overridden by ...` |
| `STARTUP_RETRY` | warn | `startup attempt N of M failed: ...` |
| `STARTUP_CANCELLED` | info | `startup cancelled by signal; ...` |
| `STARTUP_FAILED` | error | `startup failed: ...` |
| `STARTUP_HINT` | info | the advice lines after a startup failure (`run as root or grant ...`, Landlock hints) |
| `SIGNAL_INSTALL_FAILED`, `OUTPUT_THREAD_FAILED`, `UNSUPPORTED_PLATFORM` | error | `cannot install ...`, `cannot start the output thread`, `unsupported platform` |
| `CONFIG_INVALID`, `CONFIG_UNREADABLE`, `CONFIG_REFUSED` | error | `invalid config:`, `cannot read config:`, `refused config:` |
| `SHUTDOWN_DRAINING` | info after a signal, else error | `<why>; draining` |
| `DRAIN_FAILED`, `CLOSE_FAILED` | error | `drain failed:`, `close failed:` |
| `SHUTDOWN_SUMMARY` | info after a signal, else error | `stopped ...; drain calls=...; ...` |
| `WARNING` | warn | any other `warning:` line |
| `STATS` | info | a stats block (stdout) |
| `UNCLASSIFIED` | info | a line no rule matches: a bug, please report it |

Example:

```json
{"schema":"ruster-run-log/v1","ts":"2026-11-03T12:14:56.789Z","level":"warn","event":"HEALTH_WARNING","msg":"warning: port=if2 health=TX_STALL","fields":{"code":"TX_STALL","port":"if2","health":"TX_STALL"}}
{"schema":"ruster-run-log/v1","ts":"2026-11-03T12:15:00.001Z","level":"info","event":"STATS","msg":"ruster-run-stats kind=periodic uptime-ms=60000","fields":{"kind":"periodic","uptime-ms":60000},"stats":{"observer.taken_at":60000,"observer.state":"healthy","...":0,"output.dropped":0}}
```

Migration from text: keep `text` (the default) where scripts parse the
lines; they do not change. For a collector, switch to `json` and match on
`event` (and `fields.code`) instead of line prefixes; `msg` carries the old
line. Stats consumers read `stats` of the `STATS` objects instead of the
`ruster-run-stats` ... `end` blocks (same keys). `jq` example:
`journalctl -u ruster -o cat | jq -c 'select(.level != "info")'`.

## 6. Config reload (SIGHUP)

1. Write the new config to a new file and `mv` it over the file given to
   `--config` (a reload never reads a half-written file). Check it first:
   `ruster validate new.toml` and `ruster plan current.toml new.toml`.
2. `kill -HUP <pid>` (`systemctl reload`). The router takes the request
   between two ticks and prints `reload requested (generation G)`. SIGHUPs
   that arrive while one reload is pending are coalesced into one more.
3. The file is read and validated like at startup (same limits, regular
   file only, `--strict-config-perms` applies; after the privilege drop with
   plain file permissions, section 5), a successor generation is
   built with fresh keys, and the plan is checked against the running
   generation. One line reports the outcome:

   | line | meaning |
   |---|---|
   | `reload applied: generation=N previous=P; interfaces=.. addresses=.. routes=.. neighbors=.. firewall-rules=.. nat44-ports=..; flushed dynamic-neighbors=.. resolution-states=.. nat44-udp-mappings=.. nat44-tcp-sessions=.. firewall-flows=..; carried dynamic-neighbors=.. nat44-udp-mappings=.. nat44-tcp-sessions=.. nat44-icmp-mappings=.. firewall-flows=.. firewall-revoked=..; state arp=.. nat44-udp=.. nat44-tcp=.. nat44-icmp=.. firewall=..` | active from this tick on. Compare the counts with what you meant to load (a truncated file that still validates shows fewer rules or routes; `routes` includes connected routes). `state` says per family what happened to its state (item 5): `carried`, `flushed` (`[reload] state = "flush"`), or `flushed:<reason>`; `nat44-icmp=none` without `[nat44.icmp]` |
   | `reload refused: code=RESTART_REQUIRED reasons=<R>[,<R>...]; generation P keeps running` | the change needs a restart; nothing changed |
   | `reload failed: stage=<stage> code=<code>[ path=...]; generation P keeps running` | nothing changed. Stages: `read`, `permissions`, `parse`, `version`, `validate`, `candidate`, `plan`, `health` (the `[health]` keys and the threshold flags disagree after the merge, section 7), `dry-run`, `apply`, `quiesce` (`code=TIMEOUT`: not quiescent within 200 ms; `code=STOPPED`: the run stopped while the reload waited) |
   | `watch settings applied: tx-stall-warn-ms=.. ... link-stale-ms=..` | after `reload applied`, only when the applied document's `[health]`/`[watch]` settings differ from the running ones; they apply from the next health sample and link round (section 7) |

4. Restart-required reasons (`R`): `BACKEND` (anything in `[backend]`:
   device, queue, mode, attach, rings, UMEM; also an interface `device`
   change, because the port binds the device), `INTERFACES` (interface ids
   or MACs), `STORAGE_SHAPE` (a capacity, including the NAT port pool
   size), `RESOLUTION_POLICY`, `ICMPV4_ERROR_POLICY`. Routes, neighbors,
   addresses, firewall rules and policy, NAT realm, port range shift,
   filtering and hairpinning, `[ipv4-origin]` and `[tick]` budgets reload in
   place (`ruster plan` shows which).
5. State (RELOAD-CARRY): what an applied reload does with runtime state is
   set by `[reload] state` in the **new** document:

   ```toml
   [reload]
   state = "carry"   # default; "flush": flush everything, as before
   ```

   Every reload flushes pending ARP resolution, failure holds, queued
   ICMPv4 errors and their rate limiter, TCP unsolicited-SYN holds, and
   datagrams held for ARP (ARP-HOLD) (all short-lived and bound to the old tables). With `carry` (the default)
   it keeps, per family, the state the new document does not invalidate,
   with its hash key, so established connections through the NAT continue:

   | family | carried when | otherwise (`state` value) |
   |---|---|---|
   | NAT44 UDP, TCP, ICMP query mappings, peers, sessions | same inside/outside interface, public address, port (identifier) pool, and filtering mode; the UDP/ICMP `idle-ttl-ms` not longer; no lowered or new per-host limit; for TCP also the same `idle-ttl-ms`, `opening-idle-ttl-ms`, `closing-idle-ttl-ms` | that family is flushed: `flushed:interfaces`, `flushed:public-address`, `flushed:port-range` (also a same-size shift), `flushed:filtering`, `flushed:timers`, `flushed:quota` |
   | firewall flows | no firewall idle timeout is longer. Flows already expired are dropped; when routes changed, a flow whose route (to either end) now leaves through another interface, or no longer exists, is revoked; when the rules changed, every remaining flow is re-evaluated as if its first packet arrived now, and the flows the new rules deny are revoked (`firewall-revoked`): nothing of them passes after the reload | `flushed:timers` for a longer timeout; `flushed:reevaluation-budget` when `live flows x (rules + 4 route lookups x 16)` exceeds 4194304 rule-test units (a count, not a time: 20-48 ms for a full table on the development host, depending on load): the firewall table is flushed instead of stalling the router |
   | learned ARP neighbors | the interface's own IPv4 address is unchanged, no new static neighbor replaces it, and, with `[arp] require-on-link-sender = true`, it is on-link | that entry is dropped (`flushed dynamic-neighbors`) and learned again on demand |

   State that expired under the old settings never becomes live again: a
   longer UDP/ICMP NAT or firewall idle timeout flushes that family, and a
   shorter one applies to carried state from its last activity (it can
   expire it at once). A lowered or new per-host limit flushes that NAT
   family so it applies at once; a raised or removed one carries. A NAT
   mapping whose firewall flow was revoked passes nothing but stays until
   it times out and counts toward its host's limit. Use `ruster plan current.toml
   new.toml` before the reload: its `state:` block names each family's
   expected outcome (`firewall carried reevaluate` when rules change). With
   `state = "flush"` every family is flushed and every hash key rotates
   (established TCP through the NAT must reconnect); a restart always
   flushes. Cumulative counters are kept. Every reload request consumes a
   generation number, so after a refusal or failure the next applied
   generation skips one.

   Upgrade note: before RELOAD-CARRY every applied reload flushed all of
   this state. A config without `[reload]` now carries it; add
   `[reload] state = "flush"` to keep the old behavior. Under `carry` the
   NAT44, firewall, and resolution hash keys live as long as the process;
   a `state = "flush"` reload or a restart rotates them, and also clears
   learned ARP entries (including any an attacker poisoned) and every
   NAT/firewall state. Do that periodically, or after a suspected attack.

   The live dry run before the switch does not re-evaluate firewall flows
   (`ruster plan` and the dry run show `invalidated`); only the switch
   itself does, once. After the dry run the router prints `reload checked:
   generation P keeps running until the switch; would carry ...
   firewall-flows<=N` (`<=`: the switch may still revoke some of them;
   `=` when neither rules nor routes changed).
6. Timing: reading, validating, building the candidate (fresh keys from
   the production sequencer) and planning run on the reload worker thread
   (`ruster-reload`, section 7), while the router keeps forwarding; a large
   config costs no RX time. Only the live dry run (a few comparisons) and
   the switch run on the router thread. The switch happens at a tick
   boundary once the backend is quiescent (no TX frame of the old
   generation in flight); while it waits the router reads no RX for at most
   200 ms. Reload when traffic is low: during that wait a busy port's RX
   ring (`rings.rx` entries) can overflow, which shows as rising
   `if<id>.af_xdp_port.kernel_rx_ring_full` and `kernel_rx_dropped`. One
   reload is in flight at a time: SIGHUPs that arrive while one is
   prepared or pending coalesce into one reload after it. A preparation has
   no time limit of its own; if the run stops during it, it fails as
   `reload failed: stage=prepare code=STOPPED`.
7. Counters: `reload.requested`, `reload.applied`, `reload.refused`,
   `reload.failed`; in the final block `requested = applied + refused +
   failed`. If the backend reports a commit without its report
   (`previous=unknown`, `code=APPLY_REPORT_MISSING`) the publication contract
   is broken: the run ends (`stopped after an invariant violation
   code=APPLY_REPORT_MISSING`) and exits 1.

## 7. Health and stall signals

### Threads

| thread (`comm`) | does |
|---|---|
| `ruster` | the router: ticks (RX, forwarding, TX), the health samples below, every watch decision (warnings, fatal exits), and the reload switch |
| `ruster-watch` | the link round of section 8 (rtnetlink queries and sysctl reads), one per request of the router |
| `ruster-reload` | the reload preparation of section 6 (read, validate, candidate with fresh keys, plan); owns the production key sequencer for the whole run |
| `ruster-stdout`, `ruster-stderr` | the output lines (section 5) |

The router never waits for a worker: it hands a request over and takes the
answer at a later tick boundary with non-blocking channel operations, and
nothing on its side allocates or takes an application lock. Every thread
holds no capability after startup (section 5, `threads=5`). At shutdown the
workers are told to stop when the loop ends and are waited for at most
500 ms (overlapping the drain); a worker still busy then (a watcher stuck
on the RTNL lock, a reload still reading) is abandoned with `warning: the
link watcher thread did not end within 500 ms after the loop; abandoned`
(or `reload worker`) and dies with the process. A busy worker therefore
delays the detach and the exit by at most 500 ms after the loop. The XDP
detach itself (closing each link) also takes the kernel's RTNL lock: while
another process holds it, the exit waits for the kernel whatever the
workers do (the same before H7).

Scheduling: the workers inherit the router's CPU affinity and scheduling
policy. Do not run `ruster run` under `SCHED_FIFO`/`SCHED_RR` pinned to a
single CPU: a busy router then never yields to the link watcher, whose
round goes stale and ends the run with `LINK_UNVERIFIABLE` after about
7 s (section 8). Keep at least one CPU in the affinity mask where the
workers can run (or leave the default `SCHED_OTHER`).

A reload preparation that runs for 10 s (for example a config read stuck on
a hung file system) prints once `warning: reload preparation running for N
s; later SIGHUPs are held`; `reload.preparing_ms` in the stats shows how
long the current one has run (0 when none).

The router samples every port's backend counters every 500 ms (cold path)
and prints a value-free line when a condition starts or ends:
`ruster run: warning: port=if<id> health=<CODE>` and
`ruster run: recovered: port=if<id> health=<CODE>`. A fatal condition prints
`ruster run: fatal: port=if<id> health=<CODE>`, then the shutdown of
section 9 runs and exits 1. `watch.state` is `warning` while any condition
holds.

| code | condition | warning | fatal (exit 1) |
|---|---|---|---|
| `TX_STALL` | TX is in flight and the oldest in-flight frame has not completed, while the link is up | after `tx-stall-warn-ms` (1000) | after `tx-stall-fatal-ms` (10000; 0 never) |
| `FILL_STARVED` | no Fill frame with the kernel, no RX, and the free list was empty when refilling | after `fill-starved-warn-ms` (1000) | never (the frames are held by TX, which `TX_STALL` covers) |
| `KICK_ERRORS` | kick failures other than `ENETDOWN` grew in every sample | at the first growth | after `kick-errors-fatal-ms` (5000; 0 never) of growth in every sample |
| `FRAMES_QUARANTINED` | AF_XDP: the port quarantined frames since the last sample (a kernel descriptor broke the frame ownership contract: a completion at another address, an RX descriptor with options, inside the headroom, or past its frame; the frame never returns to the pool, so the UMEM shrinks by one each time) | at the first growth of an episode (recovered after 10 s without growth) | when the port's count since startup reaches `frames-quarantined-fatal` (64; 0 never) |
| `TX_INVALID_DESCS` | AF_XDP: the kernel's `XDP_STATISTICS` `tx_invalid_descs` of the port grew (it consumed a TX descriptor without sending or completing it; that frame stays in flight for good, so `TX_STALL` follows within `tx-stall-fatal-ms` unless the fatal stall is off) | at the first growth of an episode (recovered after 10 s without growth) | when the count since startup reaches `tx-invalid-descs-fatal` (64; 0 never) |
| `ARP_ADDRESS_CONFLICT` | another host's ARP packet claimed the port's IPv4 address with another MAC since the last sample (RFC 5227 §2.4; `ifN.watch.arp_address_conflicts`, ARP-039) | at the first growth of an episode (recovered after 10 s without growth) | never |

The names in the table are the `[health]` keys below (defaults in
parentheses). Neither integrity condition exists on AF_PACKET (no frame
ownership ledger, no `XDP_STATISTICS`). Both should never happen: each
one is a broken kernel-trust assumption (`if<id>.af_xdp_port.frames_quarantined`
and `kernel_tx_invalid_descs` count them). Lower the fatal threshold to 1
to stop at the first one, or set 0 to keep running on a degrading port
with warnings only.

### Thresholds and intervals (`[health]`, `[watch]`, OPS-LOG)

Every health threshold and watch interval is a config key. The run reads
them from the `--config` file at startup and from the new document at
every reload; validation bounds each key and fails closed (exit 2 at
startup, `reload failed: stage=validate` at a reload, the same in `ruster
validate`):

```toml
[health]
tx-stall-warn-ms = 1000             # 100 to 3600000
tx-stall-fatal-ms = 10000           # 0 (never) or tx-stall-warn-ms to 3600000
kick-errors-fatal-ms = 5000         # 0 (never) or 100 to 3600000
fill-starved-warn-ms = 1000         # 100 to 3600000
link-probe-failures-fatal = 3       # 1 to 100 failed link queries of one kind in a row
link-dump-interrupted-fatal = 10    # 1 to 1000 (AF_PACKET stacked-device dump)
frames-quarantined-fatal = 64       # 0 (never) to 1000000, per port since startup
tx-invalid-descs-fatal = 64         # 0 (never) to 1000000, per port since startup

[watch]
health-interval-ms = 500            # 100 to 60000: backend health sample
link-interval-ms = 1000             # 100 to 60000: link round (link, addresses,
                                    # routes, forwarding, IPv6, rp_filter: every
                                    # kernel exposure probe of section 8)
link-stale-ms = 5000                # 1000 to 3600000 (section 8, stale rounds)
```

The values shown are the defaults. For the keys that existed as fixed
values or flags before OPS-LOG they are those values. Behaviour change on
upgrade: `FRAMES_QUARANTINED` and `TX_INVALID_DESCS` are new, so a config
without the tables now also warns on those counters and ends the run when a
port reaches 64 of either (set `frames-quarantined-fatal = 0` and
`tx-invalid-descs-fatal = 0` to keep the old never-fatal behaviour). The
kernel's `tx_invalid_descs` also counts TX descriptors it dropped in copy
(generic) mode because it could not build the packet (for example
`-EOVERFLOW`), not only malformed ones; a port that sees those regularly
needs a higher threshold or 0.

`health-interval-ms` is coupled to the conditions it samples:
`KICK_ERRORS` needs growth in every sample and `FILL_STARVED` a sample
without RX, so a shorter interval sees fewer of them (a sample can fall
between two kick retries or two arrivals) and a longer one reacts later.
The minimum is 100 ms for that reason; the time thresholds are in
milliseconds but act at sample granularity (a 1000 ms warning fires at the
first sample at or after 1 s). Errors: `HEALTH_VALUE_OUT_OF_RANGE` or `WATCH_INTERVAL_OUT_OF_RANGE`
with `path=health.<key>` (or `watch.<key>`), `limit=` the bound crossed and
`actual=` the value; `HEALTH_FATAL_BELOW_WARNING` when both TX stall keys
are set and the fatal one (not 0) is below the warning.

Precedence, per key: the config key, else its flag (`--tx-stall-warn-secs`,
`--tx-stall-fatal-secs`, `--kick-errors-fatal-secs`, `--link-stale-secs`,
in seconds; deprecated and kept for compatibility), else the default. The
flag thus stays the fallback at every reload of a config without the key.
A flag given with a value other than its default under a config that sets
its key is overridden, with one startup warning: `warning:
--tx-stall-warn-secs is overridden by [health] tx-stall-warn-ms of the
config`. The override warning is given at startup only (a reload applies
the key without repeating it). After the merge the fatal TX stall bound (when not 0) must still
be at least the warning: a config `tx-stall-warn-ms = 20000` without
`tx-stall-fatal-ms` under the default flag (10 s) is refused at startup
(`invalid config: stage=health code=HEALTH_FATAL_BELOW_WARNING
path=health.tx-stall-fatal-ms limit=20000 actual=10000`, exit 2) and fails a
reload (`stage=health`, the running settings stay). Set both keys.

Migration: move each threshold flag of the unit file into the config
(`--tx-stall-fatal-secs 0` becomes `tx-stall-fatal-ms = 0`, seconds become
milliseconds) and drop the flag; until then the flag keeps working.

Reload class: every key is reloadable, none is restart-required. The
watch only decides on cold samples between ticks, so an applied reload
switches the thresholds and intervals at once, from the next sample and
round, and prints `watch settings applied: ...` with every effective
value (0 for a disabled fatal exit). A condition being timed keeps its
start: a lowered fatal bound it has already passed ends the run at the
next sample; a raised one gives it more time. Lowering
`link-probe-failures-fatal` below a port's current failure count makes
its next failed query fatal. `ruster plan` does not list `[health]` or
`[watch]` changes (they are no publication state); a reload that changes
only them still publishes a new generation, so its state follows `[reload]
state` of the new document like every reload (section 6): carried by
default, but under `state = "flush"` a reload made only to change a
threshold also flushes every NAT44 mapping and session, firewall flow, and
learned ARP neighbor. Keep `state = "carry"` (the default) when tuning
thresholds on a busy router. (Applying watch-only changes without a
publication would be a second reload path with its own failure and
counter semantics; one atomic path is simpler to reason about, so it is
not done.)

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
(`ethtool -A <dev> rx off tx off`) and/or set `[health] tx-stall-fatal-ms = 0`.

Separately, if the adapter's I/O stays non-reentrant for 1 s on the loop's
clock with no other tick in between (and at least 16 such ticks, so the
bound is `max(1 s, 16 × --idle-wait-ms)`; the
wedged-adapter watchdog, time-based since H9 because the idle tick rate
depends on the idle wait), or the adapter stops itself after a ring fault,
the run ends with `stopped after a backend fault` and exit 1.

### Idle wait

Under load the router thread never waits. A tick that received no frame
and generated no TX is idle; after 64 idle ticks in a row (a few
microseconds) each further idle tick is followed by one blocking `poll()`
with `POLLIN` on the AF_XDP sockets of every port (one preallocated
`pollfd` array, H9). It returns:

- at once, without a syscall, while a port has a descriptor in its RX ring
  or a frame left over from the previous tick;
- as soon as the kernel puts a frame on any port's RX ring (the socket
  wakes the thread; the first frame after an idle period is processed
  within the kernel's wake-up latency, typically tens of microseconds,
  instead of up to 1 ms before H9);
- when a signal handler runs on the router thread (SIGTERM, SIGINT,
  SIGHUP: `poll` is never restarted after a handler, so the flags are read
  at once; the kernel prefers the main thread, which is the router, for
  process-directed signals);
- at its timeout: `--idle-wait-ms` (10), but at most 1 ms while
  time-driven work is pending, and never past the next periodic stats
  block, health sample (500 ms), or link round (1 s).

The router's timers advance only at ticks, so these keep the wait at 1 ms
(the pre-H9 idle cadence, so every bound stated in terms of ticks still
holds, such as the resolution sweep warning `RESOLUTION_SWEEP_SLOW` at
1000 ticks, about 1 s): a resolution state, failure hold or queued ARP
request; a queued ICMPv4 error; an unsolicited-SYN hold (B3: its 6 s Port
Unreachable is sent within about a millisecond of the deadline); TX in
flight or an owed kick in the adapter (completions do not end an RX wait;
the link-down kick retry of section 8 keeps its 1 ms first step); and a
reload request out on the reload worker (its answer is picked up within
about 1 ms). NAT44 and firewall state expiry is lazy and needs no tick.
These caps last as long as their cause: while TX is held on a down link
(section 8), while resolution states sit in `Failed` (the hold-down),
or while unsolicited-SYN holds exist, every idle wait stays at 1 ms for
that whole period, about 1000 wake-ups per second as before H9
(`idle.short` grows). Before blocking, the wait also puts frames that the
last tick reaped from TX completions back on Fill, so a port whose Fill ran
dry can receive the frame that wakes it. What the 10 ms costs: a signal that the kernel delivers to another thread
(or that arrives between the router's flag check and its `poll`), and a
link round coming back, are noticed up to one wait later.

A wait that reported a ready socket must be followed by a tick that
receives something; if it is not (readiness RX cannot consume), the next
idle wait is a plain sleep of at most 1 ms, so a socket that stays ready
never turns into a busy spin. If `poll` fails (it should not), the router
warns once (`warning: idle poll failed code=ERRNO_<n>; sleeping at most
1 ms between idle ticks instead`) and sleeps 1 ms instead of every wait,
the pre-H9 behaviour.

CPU and wake-ups: an idle router thread wakes about 100 times per second
at the default (plus the stats, health and link deadlines), against about
1000 before H9; with timers pending it is back to about 1000. The
`idle.*` stats (section 11) count the waits (`waits`, `woken`,
`timed_out`, `interrupted`, `short`: waits the pending cap made shorter
than the configured wait and the next deadline would have,
`sleeps`, `errors`, and the configured `max_wait_ms`); `tick.ticks` grows
by about the wait count while idle.

## 8. Link and device events

Every second the router queries each port's interface index over
rtnetlink (`RTM_GETLINK`, namespace correct), dumps the namespace's IPv4
addresses (`RTM_GETADDR`) and IPv4 routes of every table
(`RTM_GETROUTE`), reads the IPv4 forwarding sysctls (`mc_forwarding`
included) and `rp_filter` (procfs), and then the port's
`disable_ipv6`; unless it is 1 it also reads the IPv6 forwarding sysctls
(`force_forwarding` and `mc_forwarding` included) and dumps the IPv6
addresses and routes. The dumps are filtered by the kernel to the port
(strict checking). A failed query replaces the socket, so an aborted dump
cannot leave the next query facing `EBUSY`. All of it runs on the link
watcher thread (`ruster-watch`, section 7), on one reused socket and
buffer, without allocation; the router requests a round every second and
judges the results when the round comes back, so a `send` that waits while
another process holds the kernel's RTNL lock (seconds during a driver
reset) stalls the watcher, not forwarding. At most one round is
outstanding:

| event | outcome |
|---|---|
| link down (`ip link set lan0 down`, cable out: `IFF_UP` or `IFF_LOWER_UP` clear) | warning `LINK_DOWN`, `if<id>.watch.link_down_events` +1; keeps running; owed TX is kicked again when the link returns (recovered `LINK_DOWN`, `link_up_events` +1) |
| device removed (`ip link del`, driver unbind, moved to another namespace) | fatal `DEVICE_REMOVED` |
| device renamed (`ip link set lan0 name x`; Linux 6.2 and newer also rename a device that is up; H10) | fatal `DEVICE_RENAMED` within one link round (about 1 s; until then the port keeps forwarding, since XDP follows the interface index, and its sysctls are read by the old name): the per-port sysctls are read by name, so they would describe whatever device takes the old name. The rest of that port's round is ignored (also for `DEVICE_REMOVED`). Rename it back (or fix the config) and restart. Startup refuses a port whose interface index does not carry the configured name (`checks code=UNVERIFIABLE probe=name`) |
| MTU below the startup MTU | fatal `MTU_DECREASED` (TX is bounded by the startup MTU; longer frames could be stranded in the kernel) |
| MTU above what a frame holds (`frame-size - 256 - headroom - 14`) | fatal `MTU_ABOVE_FRAME` |
| MTU raised within that bound | warning `MTU_RAISED`, recovered when it returns; TX stays bounded by the startup MTU until a restart |
| a round is still running when the next is due (watcher stuck, usually on the RTNL lock) | `watch.link_rounds_late` +1, nothing else while the round is younger than `--link-stale-secs` (5). Rounds that are persistently slow but never stale (each finishing within the threshold, yet after the next was due) show up only in `watch.link_rounds_late` growing, with no warning: watch it, as it means the namespace's dumps or RTNL contention take longer than the 1 s interval |
| ... the running round is older than `--link-stale-secs` | each due round: warning `LINK_WATCH_STALE` (once, every port) and a failed link query on every port (`watch.link_rounds_stale` +1, warning `LINK_PROBE`, fatal `LINK_UNVERIFIABLE` at the third in a row: with the defaults about 7 s after the stuck round started). When the round comes back its results count as usual and `LINK_WATCH_STALE` recovers |
| a query fails | warning `LINK_PROBE`; fatal `LINK_UNVERIFIABLE` after 3 failures in a row. The link query, each dump (IPv4 addresses, IPv4 routes, IPv6 addresses, IPv6 routes) and the procfs reads (IPv4 forwarding; `disable_ipv6` with the IPv6 forwarding sysctls) each count their own failures |
| a kernel IPv4 address appears on a port | warning `KERNEL_IPV4_ADDRESSES` (`if<id>.watch.kernel_ipv4_addresses`), recovered when gone; keeps running |
| a kernel IPv4 route out of a port appears in any table (policy routing and multipath nexthops included) | warning `KERNEL_IPV4_ROUTES` (`if<id>.watch.kernel_ipv4_routes`), recovered when gone; keeps running |
| `net.ipv4.ip_forward`, `conf/<port>/forwarding`, or an IPv4 `mc_forwarding` turns on | warning `KERNEL_FORWARDING_ENABLED` (`if<id>.watch.kernel_forwarding`), recovered when off; keeps running |
| effective `rp_filter` 0 (or unreadable) | warning `IPV4_WEAK_HOST_EXPOSURE` (`if<id>.watch.ipv4_weak_host`), recovered when it is 1 or 2; never fatal, never a failed query, with or without `--allow-ipv4-weak-host` (the next startup refuses it without the flag) |
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
idle wait: TX held in flight keeps the idle wait at 1 ms) and without new
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

### Exit protection (`[exit-protection]`, OPS-EXIT)

Detaching hands the ports back to the kernel. The startup checks refuse a
kernel that would forward, answer, or route their frames, but nothing
stops an operator or a tool from turning kernel forwarding on while the
router runs (the link watch only warns, section 8), and
`--allow-kernel-forwarding` runs with it on. Two opt-in exit actions close
that gap; both rewrite operator and kernel state, so both are off by
default:

```toml
[exit-protection]          # optional; every key false when absent. Restart-required
ipv4-forwarding-off = false # write 0 to net.ipv4.conf.<device>.forwarding of every port
link-down = false           # set every port's link administratively down (IFF_UP off)
```

- **When.** The actions are armed at readiness (`exit protection armed:
  ipv4-forwarding-off=<bool> link-down=<bool> ports=N`, before the
  `running generation 1` line) and run once after the drain (which needs
  the links up) and before the ports are detached: on a stop signal, a
  fatal health or device event, a backend fault, an invariant violation,
  and a panic (unreported). A startup that fails or is cancelled never
  arms them, so ports the router never served keep the operator's state.
  `exit protection applied: ipv4-forwarding-off=N link-down=N failed=N`
  reports the outcome; each failure is `exit protection failed:
  port=if<id> action=<action> code=<code>` and makes the exit status 1
  (the ports are still detached and closed).
- **Privileges.** Both actions need `CAP_NET_ADMIN` over the ports'
  network namespace at the moment they run: Linux checks it at every
  sysctl write (even on a file opened before the drop, and even for uid
  0 without capabilities: `EPERM`, seen on Linux 7.0) and at every link
  change (rtnetlink, `SIOCSIFFLAGS`, and sysfs all check the calling
  thread). No thread keeps a capability after the default privilege drop,
  so either key is refused at startup unless `--keep-privileges`
  (`EXIT_FORWARDING_NEEDS_PRIVILEGES`, `EXIT_LINK_DOWN_NEEDS_PRIVILEGES`,
  exit 2 before anything). The files and the rtnetlink socket are opened
  before Landlock and the syscall filter, which allow the later `write`
  and `sendto`/`recvfrom`; until the owner decides on a privileged helper
  process (architecture document), `[exit-protection]` is refused with
  `--seccomp off` or `log` (log lets every syscall run; `EXIT_PROTECTION_NEEDS_SECCOMP`) or `--fs-confine off`
  (`EXIT_PROTECTION_NEEDS_FS_CONFINE`), exit 2. With the default drop, use
  the supervisor's post-stop hook below instead.
- **What `--keep-privileges` costs.** It keeps every capability the
  process started with (as root: all of them, `CAP_SYS_ADMIN`,
  `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_SYS_PTRACE` included) on every thread
  for the whole run. Code that gained control of the router (a parser or
  datapath bug) could then change every link, address, route, and
  neighbor of the namespace over rtnetlink (with `CAP_NET_ADMIN`; the
  only socket the syscall filter lets it open is `NETLINK_ROUTE`), and
  write through the descriptors it holds open. The syscall filter (which
  must stay on) still blocks `execve`, `ptrace`, `mount`, BPF loads, other
  sockets, and writable opens, and Landlock limits reads to the confined
  files; without those filters the kept capabilities would be the whole
  machine. The default drop removes all of that; prefer it with the
  post-stop hook unless the exit actions must also run on an exit the
  supervisor does not see.
- **Reload.** A change of either key is refused as restart-required
  (`reload refused: code=RESTART_REQUIRED reasons=EXIT_PROTECTION`; `ruster plan` says
  the same).
- **Not covered.** A process killed outright (`SIGKILL`, a seccomp kill,
  the OOM killer, a panic while unwinding) runs nothing. Cover those, and
  both actions under the default drop, with the supervisor's post-stop
  hook:

  ```ini
  [Service]
  # "+": full privileges even with User=/CapabilityBoundingSet= set for the
  # unit; "-": a failing line (a device already gone) does not fail the
  # others or the unit's stop.
  ExecStopPost=-+/usr/sbin/sysctl -q -w net.ipv4.conf.lan0.forwarding=0
  ExecStopPost=-+/usr/sbin/sysctl -q -w net.ipv4.conf.wan0.forwarding=0
  ExecStopPost=-+/usr/sbin/ip link set dev lan0 down
  ExecStopPost=-+/usr/sbin/ip link set dev wan0 down
  ```

  Notes: the hook runs in the unit's network namespace (with
  `NetworkNamespacePath=` that namespace, otherwise the host's), so the
  device names must be the router's; it also runs after a startup that
  failed (the ports then keep the state of the hook, not the operator's);
  it covers IPv4 forwarding only (IPv6 forwarding,
  `net.ipv6.conf.<device>.forwarding`, needs its own line, or keep IPv6
  disabled on the ports, section 1). Bring the links up again in
  `ExecStartPre=-+/usr/sbin/ip link set dev lan0 up` (and wan0): until
  the router attaches, the startup forwarding check
  (`KERNEL_FORWARDING`) is what keeps the kernel from forwarding the
  port's traffic, so keep the forwarding sysctls at 0 rather than relying
  on the link state alone.

- **Interaction with the startup checks.** `ipv4-forwarding-off` writes
  only the ports' per-device `forwarding`. The next startup's forwarding
  check (`KERNEL_FORWARDING`, section 1) still reads `net.ipv4.ip_forward`
  too; Linux copies a write of `net.ipv4.ip_forward` or
  `conf.all.forwarding` to every device, so turning global forwarding on
  later re-enables the ports as well. Neither action changes `rp_filter`,
  so the weak-host check (`KERNEL_IPV4_WEAK_HOST`) reads the same after an
  exit. `link-down` makes the kernel drop the IPv4 routes through the
  port (the startup refuses those anyway, `KERNEL_IPV4_ROUTES`) and its
  non-permanent IPv6 addresses. `ruster run` never sets a link up: bring
  the ports up before the next start (`ip link set dev <device> up`, or
  `ExecStartPre=`); a port that is still down starts with the
  `LINK_DOWN` warning and forwards nothing until it is up (section 8).
- **AF_PACKET.** The same keys work over AF_PACKET; there the kernel saw
  every frame all along (its exposure is fatal while running), so the
  actions only keep it from forwarding after the router stops.

### Panics

`ruster run` keeps Rust's default `panic = "unwind"`. Under the
filesystem confinement a `RUST_BACKTRACE=1` backtrace still has symbols
(the binary is readable); separate debug-info files (`/usr/lib/debug`) are
not, and a binary replaced on disk since startup is a new file the
confinement does not cover: the backtrace then shows addresses only. A panic on the router
thread unwinds through the run: the adapter and engines are dropped and the
startup guard closes every opened session, last first, which detaches XDP;
the process exits with status 101 and the panic message on stderr, with no
summary or final stats. A panic during that unwinding aborts the process
(SIGABRT); the kernel then closes every fd and the unpinned links detach as
after SIGKILL.

## 10. Forced termination and restart

1. `kill -KILL <pid>` (or a crash, OOM kill, a seccomp kill): no drain, no final stats. The
   kernel closes every fd; the XDP links are unpinned, so the programs
   detach by themselves within milliseconds. Confirm with
   `ip -details link show dev lan0` (no `prog/xdp`). While detached, frames
   reach the kernel stack: keep the ports free of kernel L3 and forwarding
   off (section 1). `[exit-protection]` (section 9) does not run here; the
   supervisor's `ExecStopPost=` does.
2. Restart with the same command. The first attempt can fail transiently
   with `open code=BIND/BUSY` or `REGISTER_UMEM/MEMLOCK_LIMIT`; `ruster run`
   rolls back and retries (section 5). If every attempt fails it exits 1
   fully rolled back, and systemd `Restart=on-failure` starts it again.
3. A restarted process begins at generation 1 with fresh keys; no state
   (NAT mappings, firewall flows, dynamic neighbors) survives.

## 11. Stats

Every `--stats-interval` seconds stdout carries one block, SIGUSR1 adds one
(`kind=on-demand`, at the next point between ticks: at once if the signal
reaches the router thread, else within `--idle-wait-ms`; at most one per
100 ms, the requests in between coalesced into one block once it has
passed, so a SIGUSR1 flood cannot keep the router formatting stats), and the final
block is printed at shutdown. Only counters, gauges, flags, fixed labels,
generations and interface ids appear: no key, address, MAC, device name,
packet byte, fd or pointer.

```text
ruster-run-stats kind=periodic|on-demand|final uptime-ms=<ms>
<section>.<key>=<value>
...
output.dropped=<n>
end
```

Sections, in this order:

| prefix | content |
|---|---|
| `observer.*`, `tick.*`, `rx.*`, `generated_arp.*`, `generated_icmpv4.*`, `phase_skip.*`, `drop.<REASON>`, `consume.<REASON>`, `apply.*`, `flushed.*`, `carried.*`, `occupancy.*` | worker observability: health state (`observer.state`: `healthy`, `degraded`, `stale`, `stopped`, `not_started`), active generation, tick totals, RX totals (`rx.received`, `rx.tx_accepted`, `rx.tx_rejected`, `rx.dropped`, `rx.consumed`, ...), drop/consume reason counts, last apply outcome, its flush counts (`apply.flush.*`), carry counts (`apply.carry.*`, including `firewall_flows_revoked`) and per-family outcome (`apply.state.<family>`: `carried`, `flushed`, `flushed:<reason>`, RELOAD-CARRY), cumulative `flushed.*` and `carried.*`, NAT/FW/ICMP limiter occupancy and high-water (OBS-015), and the resolution, generated action, hold, and fragment occupancy (OBS-017, below). `firewall.states_revoked` counts the flows reloads revoked |
| `resolution.*`, `icmpv4_errors.*`, `nat44_udp.*`, `nat44_tcp.*`, `nat44_icmp.*`, `firewall.*` | the service runtimes' cumulative counters (`nat44_icmp.*` is all zero without `[nat44.icmp]`) |
| `af_xdp.*` | all ports: `mode` (`copy`, `zero_copy`, `mixed`), `ports`, `copy_ports`, `zero_copy_ports`, `fill_need_wakeup_ports`, `tx_need_wakeup_ports`, `link_down_ports`, `kick_owed_ports`, `kernel_stats_ports`, `generated_unknown_egress`, `stopped`, and the summed port counters |
| `if<id>.af_xdp_port.*` | per port: `interface`, `queue`, `mode`, `mtu`, `max_frame`, need-wakeup now, `draining`, `link_down`, `kick_owed`, `copy_reserve`, ring gauges (`fill_ring_occupancy`, `rx_ring_occupancy`, `tx_ring_unconsumed`), `fill_starved`, invalid RX descriptors and quarantines, TX (`tx_completed`, `tx_inflight`, `tx_inflight_highwater`, `tx_blocked`, `tx_over_mtu`, `tx_invalid_completions`), kicks (`tx_kicks`, `fill_kicks`, `kicks_deferred`, `kick_errors`, `kicks_link_down`, `kick_retries_suppressed`; `kick_errors` counts every failed kick and so includes `kicks_link_down`, while the `KICK_ERRORS` health code times `kick_errors - kicks_link_down` only; `kick_retries_suppressed` counts settles on a down port that skipped a retry not yet due, which made no syscall; the gauge `tx_held_on_down_link` is the TX held while the link is last seen down, which a reload does not wait for, OPS-EXIT), generated frames, `cross_port_copies`, and the kernel `XDP_STATISTICS` (`kernel_rx_dropped`, `kernel_rx_invalid_descs`, `kernel_tx_invalid_descs`, `kernel_rx_ring_full`, `kernel_rx_fill_ring_empty_descs`, `kernel_tx_ring_empty_descs`) |
| `reload.*` | `requested`, `applied`, `refused`, `failed`, `preparing_ms` (how long the reload being prepared on the worker has run; 0 when none) |
| `idle.*` | the idle wait (section 7): `max_wait_ms` (`--idle-wait-ms`), `waits` (blocking `poll`s), `woken` (ended by a frame on a port), `timed_out`, `interrupted` (a signal handler ran), `short` (waits the 1 ms pending cap made shorter than `--idle-wait-ms` and the next deadline would have; it grows about 1000 per second for as long as TX is held on a down link, resolution states are `Failed`, or unsolicited-SYN holds exist, as before H9), `sleeps` (plain sleeps of at most 1 ms after a ready socket that no tick used, or because `poll` failed), `errors` (failed `poll`s; warned once) |
| `notify.*` | systemd notification (section 5, H10): `enabled` (`NOTIFY_SOCKET` was set), `watchdog_interval_ms` (half of `WATCHDOG_USEC`; 0 without a watchdog), `sent`, `watchdog_pings` (of them), `failed` (not delivered: nobody listening, or the manager's queue full) |
| `watch.*` | `state` (`ok`/`warning`), `warnings` (all ports), `link_rounds` (link rounds that came back from the watcher), `link_rounds_late` (due rounds skipped because one still ran), `link_rounds_stale` (late rounds past `--link-stale-secs`, each a failed link query) |
| `if<id>.watch.*` | `tx_stall`, `tx_stall_ms`, `fill_starved`, `kick_errors_persistent`, `link_up`, `link_down_events`, `link_up_events`, `mtu`, `link_probe_errors`, `kernel_ipv4_addresses`, `kernel_forwarding`, `kernel_ipv4_routes`, `kernel_ipv6_addresses`, `kernel_ipv6_routes`, `kernel_ipv6_forwarding`, `kernel_ipv6_enabled`, `ipv4_weak_host`, `warnings`, `frames_quarantined` and `tx_invalid_descs` (AF_XDP, since startup, as of the last health sample; 0 on AF_PACKET; OPS-LOG) |
| `privileges.*` | `state` (`dropped`, or `kept` under `--keep-privileges`), `bounding_set` (`cleared`/`kept`), `identity` (`switched`/`unchanged`), `threads` (threads verified by the drop; 0 when kept) |
| `fs.*` | `confine` (`landlock`, `off`), `abi` (the kernel's Landlock ABI; 0 when off), `rules` (rules of the ruleset; 0 when off), `threads` (threads confined; 0 when off) |
| `seccomp.*` | `mode` (`kill`, `log`, `off`), `threads` (threads verified with the filter; 0 when off), `syscalls` (allowlist entries; 0 when off) |
| `output.dropped` | output messages dropped because a stream could not keep up |

Occupancy (`occupancy.<table>.<field>`). Every table has four fields:
`occupied` (in use now, at the last sample after a tick), `high_water`
(the most in use since startup or the last apply that flushed the table),
`capacity` (its configured slots), and `peak` (the largest `high_water`
of any sample, so it survives reloads). `occupancy.samples` counts the
samples (one after each tick). The OBS-015 tables are the NAT44, firewall
state, and ICMPv4 limiter state tables; like them, an apply that keeps a
table's state (`[reload] state` carrying) keeps its `high_water`. OBS-017
adds:

| table | counts | capacity from | `high_water` restarts |
|---|---|---|---|
| `resolution_states` | state slots a new resolution cannot take: queued, waiting for a reply, failed hold-downs, and cooldowns whose request interval has not elapsed yet (an answered resolution leaves one) | `resolution.capacity.states` | at every apply |
| `resolution_actions` | the generated ARP request queue | `resolution.capacity.actions` | at every apply |
| `resolution_dynamic_neighbors` | learned neighbors (expired ones until their slot is reused) | `resolution.capacity.dynamic-neighbors` | at an apply that flushes them; kept when they are carried |
| `resolution_failure_holds` | datagrams kept for a Host Unreachable | `resolution.capacity.failure-holds` | at every apply |
| `icmpv4_error_actions` | the generated ICMPv4 error queue (pending errors) | `icmpv4-errors.capacity.actions` | at every apply |
| `arp_hold_packets` | datagrams held for ARP (ARP-HOLD) | `resolution.hold.packets` | at every apply |
| `fragment_tracking_entries`, `fragment_tracking_held` | fragment associations and held later fragments (NAT-FRAG) | `fragment-tracking.entries`, `fragment-tracking.held-fragments` | at every apply |
| `fragmentation_slots` | staged fragmentation slots (MTU2) | `fragmentation.datagrams` | never: nothing staged outlives a tick, so `occupied` is 0 between ticks and `high_water` is the fullest a tick's queue got |

An optional table that is not configured shows `capacity=0`. A `peak` at
or near `capacity` means that table has been full: check the matching
full counter (`resolution.state_full`, `resolution.action_full`,
`icmpv4_errors.action_full`, `arp_hold.refused_full`,
`fragment_tracking.entries_evicted`/`held_evicted`,
`drop.IPV4_FRAGMENTATION_QUEUE_FULL`) and size the table up. The
exception is `resolution_dynamic_neighbors`: expired neighbors count
until a new one reuses their slot, so after enough churn (many hosts
over time, an ARP scan) `occupied` and `peak` sit at `capacity` while
the router works normally. There is no separate counter for a
learned-neighbor cache that refused a new entry; only a full key chain
is counted (`resolution_index.dynamic_probe_exhausted`). No occupancy
value is a health condition (OBS-030).

What to watch in operation: `observer.state=healthy`, `watch.state=ok`,
`rx.received` growing, `drop.<REASON>`, `af_xdp.mode=copy`,
`if<id>.af_xdp_port.fill_starved`, `kernel_rx_dropped`,
`kernel_rx_ring_full`, `kernel_rx_fill_ring_empty_descs`, `tx_inflight` near
`rings.tx`, and `kernel_tx_invalid_descs` (not a health condition yet,
CLI-034).

Unsolicited inbound TCP SYNs (B3, RFC 5382 REQ-4). A SYN from the WAN to a
public port with no mapping (or one the NAT filtering refuses) is still
dropped silently at once (`drop.NAT44_TCP_MAPPING_MISS` /
`drop.NAT44_TCP_SESSION_MISS`). By default (`[nat44.tcp]
unsolicited-syn-icmp = true`) the router also holds a copy for 6 s (plus a
2 ms clock margin, `NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS`, so the
millisecond loop clock never shortens the RFC minimum) and then
sends one ICMP Port Unreachable (Type 3, Code 3) to the sender, unless an
inside host opened the same connection in the meantime.

The firewall decides first (RFC 5382 REQ-4 a: no answer the security policy
would not allow). The SYN is held, and answered when the hold ends, only if
the firewall would admit it as a new connection to *every* inside
destination. The address and port it would be translated to are unknown, so
the router walks the rules in order using only what it knows: ingress (the
WAN), egress (the LAN), source address and port, protocol TCP.

- A matching `allow-stateful` rule decides only if its destination is
  `0.0.0.0/0` with ports 1-65535. Egress `any` counts.
- An allow rule with a narrower destination is skipped.
- A matching `deny` rule silences the SYN, whatever its destination.
- If no rule decides, the default deny applies.

With the usual firewall that admits no new WAN -> LAN flows, unsolicited SYNs
therefore stay silent. The answer does not depend on whether a mapping exists.
The check runs again when the hold ends, so a rule change during the 6 s is
honoured.

Watch these counters:

- `nat44_tcp.unsolicited_syn_held`, `_icmp_queued`, `_cancelled`
  (simultaneous opens), `_superseded`
- `_firewall_denied`: the firewall would not admit the SYN
- `_icmp_suppressed`: refused by the Port Unreachable rate limiter, which
  points to a SYN flood or a scan
- `_hold_full`: the table `[nat44.tcp.capacity] unsolicited-syn-holds`
  (default 64) was full, so those SYNs were only dropped
- `_ineligible`
- `_index_corrupt`: the hold table was inconsistent and was flushed. This
  should stay 0.
- `occupancy.nat44_tcp_unsolicited_syn_holds`

Port Unreachable has its own rate limiter per egress, separate from the
other ICMPv4 errors: `[icmpv4-errors.policy]
port-unreachable-interval-ms`, default 1000, a restart-required
`ICMPV4_ERROR_POLICY` change. A SYN flood therefore never delays a Time
Exceeded or a Net/Host Unreachable. It uses one more limiter state on the
WAN egress, so `validate` (and `run`, `plan`, and every reload) refuses
`icmpv4-errors.capacity.states` below the number of interfaces plus one
(twice the number of interfaces plus one while Fragmentation Needed is
generated, MTU1: it has a limiter state of its own on every egress)
while `unsolicited-syn-icmp` is on and `unsolicited-syn-holds` is above 0:
`stage=validate code=ICMPV4_ERROR_STATES_TOO_FEW_FOR_PORT_UNREACHABLE
path=icmpv4-errors.capacity.states`. With fewer states, a SYN flood could
keep the WAN Port Unreachable state busy (a state is reclaimed only after
`state-ttl-ms` idle) and leave another egress `StateFull`, which silently
suppresses its Time Exceeded and Net/Host Unreachable. Each state can have
one error queued, so size `icmpv4-errors.capacity.actions` the same way:
with fewer actions than states in use, a full queue refuses the extra
errors as `action_full` until the generated phase drains it (within the
same tick at the default budgets). The queue is shared by every class, so
with `actions` below the state bound (2 x interfaces, plus 1 with delayed
Port Unreachable, while Fragmentation Needed is on) a burst of one class
(a TTL sweep, a SYN flood) can hold every action and make another class,
Fragmentation Needed included, `action_full` until the next execution.
Set `actions` at least to the state bound; validation does not enforce
it.

Turning the switch off is a reloadable change (`plan` shows `nat44-tcp
unsolicited-syn-icmp ~ on -> off`). Changing the capacity is
`STORAGE_SHAPE`; with the switch off, `unsolicited-syn-holds = 0` frees the
table's roughly 37 KiB.

Hardening: with a rule that admits new inbound TCP to every destination and
`endpoint-independent` filtering, a SYN to a mapped public port is forwarded
while one to an unmapped port gets Port Unreachable. Port scans can then
tell which public ports are in use about as well as forwarding already
shows. If scans should see only silence, set `unsolicited-syn-icmp = false`,
which removes this remaining oracle.

TCP NAT session timers (N1, RFC 5382 REQ-5, RFC 7857 section 2). Each TCP
session follows the SYN, ACK, FIN, and RST flags it translates and uses the
idle timeout of its phase:

| phase | when | timeout (key, default) |
|---|---|---|
| opening | a SYN, but ACK not yet seen in both directions (also an external SYN the remote never ACKs) | `[nat44.tcp] opening-idle-ttl-ms`, 240000 (4 min) |
| established | ACK seen both ways after a SYN (RFC 5382 section 5); a FIN in one direction keeps it here | `[nat44.tcp] idle-ttl-ms`, 7440000 (2 h 4 min) |
| closing | FIN seen both ways, or the last segment was a RST | `[nat44.tcp] closing-idle-ttl-ms`, 240000 (4 min) |

Every translated segment, a repeated RST included, restarts the timer of
the session's phase. A RST never removes a session: it is translated and
the session moves to the closing timeout; any later non-RST segment, a SYN
included, moves it back (RFC 7857 section 2.2). An injected RST therefore
cannot end a session sooner than the closing timeout, and live traffic
undoes it. Only the inside host restarts a connection closed by FIN in
both directions as a new one: with a new SYN, or with a SYN-ACK to the
remote's new SYN (that reconnect then gets the established timeout). The
router does not
track TCP sequence numbers, so it accepts any RST or FIN that matches the
exact connection (address and port pair). A mapping, with its public port,
lives as long as its latest session: the established timeout while it has
an established session (also one that has expired but whose slot has not
been reused yet; such a mapping can be live with no session left and then
answers inbound segments with `drop.NAT44_TCP_SESSION_MISS`), otherwise
the longer transitory timeout after its last segment. After a clean close
the port and the session slot are therefore free again after 4 minutes
instead of 2 h 4 min.

Spoofed inbound segments (`[nat44.tcp] inbound-rst`). With the default
`"closing"` (RFC 7857 section 2.2), an off-path attacker who guesses a
connection's addresses and ports can move it to the closing timeout with a
RST or a FIN, so it ends after 4 minutes idle, and can make a spoofed SYN
look established by following it with blind ACKs, so that session holds a
slot for 2 h 4 min. `inbound-rst = "corroborate"` (reloadable, `plan`
shows `nat44-tcp inbound-rst ~ closing -> corroborate`) ignores inbound RSTs
for the phase, closes on an inbound FIN only
after an outbound FIN or RST, and counts a connection as established only
after the inside host sent an ACK without SYN. Its cost: a connection the
inside host closes first keeps the established timeout, and an inbound
connection on which the inside host sends nothing after its SYN-ACK keeps
the opening timeout. No setting stops an attacker who keeps refreshing a
session with spoofed segments.

`validate` refuses an opening or closing timeout below 240000 (the RFC
floor) or above `idle-ttl-ms` as `stage=validate code=NAT44_TCP_POLICY
path=nat44.tcp.opening-idle-ttl-ms` (or `closing-idle-ttl-ms`). Like
`idle-ttl-ms`, a change is reloadable (`plan` shows `nat44-tcp policy ~
changed`). TCP mappings keep their expiry as absolute deadlines, so a
changed TCP timeout cannot carry: the apply flushes the TCP NAT state
(`state ... nat44-tcp=flushed:timers`) and established TCP through the NAT
breaks at that reload; UDP and ICMP keep theirs.

Watch `nat44_tcp.sessions_established`, `sessions_closed` (FIN both ways),
`sessions_reset` (RSTs that moved a session to the closing timeout), and
`sessions_expired_opening`, `_established`, `_closing` (expired sessions
reclaimed, by the timeout that ended them; they sum to `sessions_expired`).
Many `sessions_expired_opening` with few `sessions_established` point to
SYNs nobody completes, such as a scan or a spoofed SYN flood.

Translated ICMPv4 errors (N4, NAT44-065). An ICMPv4 error from outside
about an inside host's flow (Destination Unreachable, Time Exceeded,
Parameter Problem; RFC 5508 REQ-4) is translated and forwarded to that host.
Each path, that is each pair of inside host and quoted remote address, may
receive at most `burst` of them at once and `rate-per-second` sustained:

```toml
[icmpv4-errors.translated]   # optional; these are the defaults
rate-per-second = 100
burst = 100
```

The budgets live in 4096 fixed buckets (32 KiB) chosen by a keyed hash of
the pair, with the secret key of the current publication (it changes on
every applied reload, which also empties the buckets). So a port sweep or
a flood of forged errors that names remote R spends only the budget of the
inside host's flows to R: the same host's Path MTU Discovery and traceroute
toward other remotes, and every other host, keep theirs (two pairs share a
bucket only by a 1-in-4096 chance that nobody without the key can aim at).
The defaults never limit a traceroute (90 Time Exceeded at once), an mtr,
or Path MTU Discovery. An error over the limit is dropped unchanged as
`drop.NAT44_ICMPV4_TRANSLATED_RATE_LIMITED`; only errors that passed every
other check (mapping, session, firewall, route) count, and a limited error
never starts ARP. With the firewall on, such an error was already recorded
in the audit as an allowed RELATED packet, like other drops after the
firewall (an unresolved neighbor, for example). Both keys accept 1 to
1000000; 0 or a larger value is refused as
`stage=validate code=ICMPV4_ERROR_POLICY path=icmpv4-errors.translated`.
There is no unlimited setting; `rate-per-second = 1000000` with
`burst = 1000000` is effectively off. Errors that share one clock reading
pass at most `burst` at a time, so keep `burst` at least
`rate-per-second / 1000`. The table is part of the ICMPv4 error policy, so
a change is `restart-required: ICMPV4_ERROR_POLICY`. Errors from inside
hosts toward the outside (REQ-5) are not limited.

A Fragmentation Needed whose Next-Hop MTU is 1 to 67 (below the IPv4
minimum of 68, so no router sends it) is dropped in both directions as
`drop.NAT44_ICMPV4_FRAG_NEEDED_MTU_INVALID` (NAT44-098). MTU 0, from routers
older than RFC 1191, still passes.

A rising `drop.NAT44_ICMPV4_TRANSLATED_RATE_LIMITED` means one inside host
receives many errors from outside about one remote: a sweep or flood of
forged errors, a peer that sends errors on every packet, or a very busy
traceroute. Raise the limit only if a legitimate tool is being cut off.

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
- The link watch (one link query and up to four dumps per second per port:
  IPv4 addresses and routes, and with IPv6 on the port IPv6 addresses and
  routes) and the reload's read, parse and plan run on worker threads
  (section 7), so neither an RTNL hold nor a large config stops RX. A
  watcher stuck for longer than `--link-stale-secs` plus two rounds ends
  the run (`LINK_UNVERIFIABLE`, fail closed); an RTNL hold longer than that
  (rare, some driver resets) therefore restarts the router. The reload's
  quiescence wait still holds RX back for at most 200 ms. Each dump lists
  the whole namespace (the route dumps every table), so its cost grows
  with every address and route the namespace holds: keep the router in a
  dedicated namespace with a small routing table, and set `disable_ipv6=1`
  on the ports, which skips both IPv6 dumps.
- A reload preparation cannot be interrupted: one stuck reading the config
  (for example on a hung network file system) keeps further SIGHUPs
  waiting until the run stops (`stage=prepare code=STOPPED`). Keep the
  config on a local file system.
- A port that is administratively down with TX queued holds those frames
  in the kernel's ring until the link returns (AF_XDP has no way to take a
  published TX descriptor back). Since OPS-EXIT a reload does not wait for
  them: they already left every decision of the old generation, and they
  leave the port when the link comes back up, possibly after the new
  generation is active (like frames in a NIC queue at any reload). The
  check confirms the link is down with one fresh kick (only `ENETDOWN`
  confirms; any other outcome makes the frames block as before). The
  `reload applied` line ends with `held-tx-on-down-links=N`, and the gauge
  `if<id>.af_xdp_port.tx_held_on_down_link` (AF_PACKET:
  `if<id>.af_packet_port.tx_held_on_down_link`, `af_packet.tx_held_on_down_link`)
  shows them. The hardening `[reload] down-link-tx = "refuse"` (read from
  the document being applied, default `"send"`) refuses such a reload
  instead (`reload failed: stage=quiesce code=DOWN_LINK_TX_HELD`; bring the
  link up or restart). TX queued on a port whose link is up still has to
  complete first (`stage=quiesce code=TIMEOUT` after 200 ms).
- With the default `[reload] state = "carry"` a reload keeps NAT44,
  firewall, and ARP state the new document does not invalidate, with its
  hash keys (section 6). The keys rotate only when a family is flushed
  (`state = "flush"`, an incompatible change, the firewall re-evaluation
  budget) or on restart; there is no periodic rotation while state is
  carried (RELOAD-016); rotate them with a `state = "flush"` reload or a
  restart. A NAT realm, pool, or filtering change, a TCP timeout change, a
  longer UDP/ICMP or firewall timeout, a lowered or new per-host limit, and
  `state = "flush"` still drop established connections of that family. The
  firewall re-evaluation of changed rules or routes runs on the router
  thread at the switch (bounded at 4194304 rule tests and route lookups, a
  count: 20-48 ms for a full table on the development host); above the
  bound it flushes the firewall flows instead. A route change revokes the
  flows whose route moved to another interface or disappeared.
- The health thresholds and watch intervals are reloadable config keys
  (section 7, OPS-LOG); the 500 ms worker stop bound, `--stats-interval`,
  and `--idle-wait-ms` are fixed for the run.
- Kernel routes are attributed to a port by the kernel's device filter and
  then by `RTA_OIF` and `RTA_MULTIPATH` nexthops in userspace. With
  `net.ipv4.nexthop_compat_mode=0` (shared by IPv6) a route through a
  nexthop object carries only `RTA_NH_ID`; it is counted whenever the
  kernel's filter returns it (so a nexthop object used by another
  interface does not affect the router, and one used by a port refuses
  startup or warns at run time). Resolving the ids through
  `RTM_GETNEXTHOP` to confirm the device in userspace is a follow-up
  (left out by H10: the kernel's filter, confirmed by
  `NLM_F_DUMP_FILTERED`, already matches nexthop objects against the
  device, so a counted route really uses the port and nothing is refused
  wrongly; resolving would add a second request per id after the dump and
  validation of nexthop groups for defense in depth only).
  `ip rule` policy itself is not inspected: a route out of a port counts
  in whatever table it is, used by a rule or not.
- The sysctl paths name the port device. A port renamed while the router
  runs ends the run within one link round (`DEVICE_RENAMED`, section 8,
  H10; Linux 6.2 and newer rename an up device too, so up to about 1 s of
  forwarding and of sysctl reads through the old name can happen first); a rename that lands between a round's link query and its sysctl
  reads is caught one round (1 s) later, and the reads in between can only
  warn or recover. Do not rename ports while the router runs.
- IPv4 weak host: refused at startup (`KERNEL_IPV4_WEAK_HOST`) unless
  `--allow-ipv4-weak-host`, but only warned while running
  (`IPV4_WEAK_HOST_EXPOSURE`, section 1); like the other kernel exposures
  it is only enforced while the router is not yet attached.
- The kernel's dump filter is trusted only when the dump confirms it
  (`NLM_F_DUMP_FILTERED` on `NLMSG_DONE`); a dump without it fails closed
  as an unverifiable query. The strict route dumps list FIB entries only,
  so IPv6 cached exceptions (PMTU and redirect clones) are not listed;
  harmless, because each hangs off a FIB route through the same device,
  which is listed.
- The config is validated with the production limits (section 1,
  "Validation limits and memory").
- Per-packet linear scans of runtime tables are gone (PERF-001: NAT44 in
  H4a, resolution and ICMPv4 errors in H4b). What the resolution runtime
  still does in more than constant time: the reverse failure-hold chain
  is not capped, but it holds one leader per distinct waiting token, so a
  walk is expected O(1) under the secret key however many holds wait on
  one token, and clearing a token visits each of its holds once; taking
  expired dynamic neighbors and elapsed cooldowns off their time-ordered
  lists is amortized (drained a scan budget per tick in the background;
  the insert after a burst of simultaneous expiries can still take up to
  0.8 ms once at 65536, section 1); the publication preflight validates
  every index (O(capacity), control path); and the timer and
  failure-dispatch scans are tick-budgeted round robins
  (`RESOLUTION_SWEEP_SLOW`, section 1). An insert into a key chain that
  already holds 16 entries fails closed (`resolution_index.*_probe_exhausted`).
- ARP from a sender that is not on the link of the ingress interface
  (outside every connected or other direct route of that interface and
  not one of its gateways) is learned and answered by default, as RFC 826
  specifies (the merge and reply algorithm places no condition on the
  sender's address; ARP-032). H4c (#311) dropped it unconditionally; since
  H5 that is the opt-in `[arp] require-on-link-sender = true` (owner
  decision 2026-11-02 「rfc準きょで」: RFC behaviour by default, hardening
  opt-in; this reading is the coordinator's). With the option such a
  packet is dropped (`drop.ARP_SENDER_NOT_ON_LINK`, ARP-031), neither
  learned nor answered, even a Request for the router's own address.
  Trade-off: on, a host on the LAN cannot fill the dynamic-neighbor cache
  with off-link addresses, and a rising counter usually means a host with
  a wrong prefix or address on that LAN; but a host of another prefix that
  really shares the link (a secondary subnet) is not resolved until you
  add a direct `[[routes]]` entry without `via` for that prefix (out of
  that interface). Off (default), such hosts are learned and answered as
  before H4c; the counter stays 0. The option is reloadable (`ruster plan`
  shows `arp ~ changed`).
- **ARP Announcements (GARP, ARP-033..ARP-039).** The router announces
  each interface address with RFC 5227 ARP Announcements (an ARP Request,
  broadcast, sender IP = target IP = the address, target MAC zero): at
  startup once the ports are open, after a port's link comes back up
  (the `recovered: ... health=LINK_DOWN` line), and after a reload that
  adds or changes the interface's address (an unchanged address is not
  announced). Each is `announce-count` frames (default 2, RFC 5227
  ANNOUNCE_NUM) `announce-interval-ms` apart (default 2000,
  ANNOUNCE_INTERVAL), the first at once. Two sequences on one port start
  at least `announce-min-interval-ms` apart (default 10000): triggers in
  between are folded into one later sequence (`arp_announce.coalesced`,
  `arp_announce.rate_limited`), so a flapping link costs at most
  `announce-count` frames per minimum interval. They use the generated
  ARP frame budget (`[tick] generated-arp`): the first frame of each tick
  goes to a due Announcement or defense, the rest to resolution requests
  and then the other Announcements. `[tick] generated-arp = 0` with
  announcements or defense on is refused
  (`ARP_ANNOUNCE_WITHOUT_GENERATED_ARP`). A port whose generated frame
  cannot be allocated (pool empty, AF_PACKET TX ring full on an admin-down
  port) retries after 10 ms, doubling up to 1 s while it keeps failing
  (`arp_announce.unavailable`), without holding the other ports back; a
  fresh trigger or a new defense starts again at 10 ms. A document
  without `[tick]` (every budget 0) never sends them: startup and link-up
  do not request them, and the run loop does not wait for the ones a
  reload or a conflict still marks (they stay in `arp_announce.requested`
  and `defended` unsent). `arp_announce.committed` counts frames handed
  to the backend, `accepted` and `rejected` what it did with them (a
  rejected one is not resent). `[arp] announce = false` turns them off
  (reloadable; a sequence already running stops at once). Link-up is seen
  by the link watch round (the `[watch]` link interval, about 1 s), from
  the link's admin and carrier state: a flap that goes down and up
  between two rounds is not seen and announces nothing. The router does
  not send RFC 5227 Probes before using its static addresses (ARP-036):
  it could not pick another address anyway.
- **Address conflicts (ARP-038, ARP-039).** An ARP Request or Reply on a
  port whose sender IP is the port's address and whose sender MAC is not
  the port's MAC is a conflict: another host uses the router's address.
  It is counted (`arp_announce.conflicts`, `ifN.watch.arp_address_conflicts`)
  and reported once per episode as `warning: port=ifN
  health=ARP_ADDRESS_CONFLICT` (no address or MAC in the line; find the
  host with a capture on the link), recovered after 10 s without one; it
  never stops the router. With `[arp] conflict-defense = true` (default,
  RFC 5227 §2.4 (c)) the router answers with one Announcement, at most
  one per 10 s (DEFEND_INTERVAL) per port (`arp_announce.defended`,
  `arp_announce.defense_suppressed`); the defense is one extra frame and
  does not shorten a running announcement sequence. `false` only counts
  and reports, which RFC 5227 §2.4 does not allow a host that keeps its
  address (an operator-selected deviation). Neither puts the other host
  into the neighbour cache. `watch.state` stays `ok` during a conflict
  episode (any host on the link can send one; automation keyed on
  `watch.state` cannot be driven by a spoofer): alert on
  `ifN.watch.arp_address_conflict` (the open episode) or the log line.
- NAT44 slot reuse and port selection
  are O(1) per new flow since H4a (NAT44-035). What NAT44 still does in
  more than constant time: a keyed directory lookup walks its hash chain
  (secret per-publication SipHash key and at most one slot per bucket on
  average, so chains stay short and cannot be aimed at; it is exact, since
  a bounded lookup that missed an existing key would break
  endpoint-independent mapping), and a reconcile flush clears the tables
  (control path). An external inbound SYN still probes 16 keyed slots and
  can report the session table full while a reusable slot exists elsewhere
  (NAT44-037). Port choice (NAT44-068, N2 NAT44-089 to 091): a new
  endpoint keeps its internal port if `port-preservation` is on (the
  default) and the port is free; otherwise it takes the first *unowned*
  port from a start keyed by the secret per-publication NAT hash key
  (RFC 6056 Algorithm 3 without the remote endpoint, so the mapping stays
  endpoint-independent), even when a port of an expired mapping comes
  first (a returning endpoint still gets its own old port back). With
  every pool port owned it probes 8 keyed pool ports for an expired owner
  before falling back to the longest-idle expired mapping (with a fraction
  f of owners expired, the fallback happens with probability about
  (1-f)^8; duplicate probes make it slightly higher). It takes the first
  expired owner it probes, not the oldest of them. The trade-off: a
  mapping that expired a moment ago can lose its port before older
  expired ones, so its returning endpoint (which would otherwise get the
  same port back) gets a new one sooner; preferring the oldest probed
  owner would pull the choice back toward the predictable expiry order.
  Ports are therefore not predictable without the key, which every
  reconcile (every applied reload) rotates and the sequencer never issues
  twice; `allocator-seed` is only a non-secret salt.
- Port preservation (`[nat44.udp]`/`[nat44.tcp]` `port-preservation`,
  default `true`, reloadable; `ruster plan` shows
  `nat44-udp port-preservation ~ on -> off`). On, the public port of a
  host whose source port is in the pool and free is that source port, so
  it is exactly as predictable as the host's own choice (RFC 6056 §4 and
  RFC 7857 §9 allow this: obfuscate only when the port must change). If
  inside hosts use predictable source ports (old stacks, embedded
  devices), set it to `false`: every new mapping then gets a keyed port,
  which hides the host's choice. It does not make the public port of an
  endpoint with a fixed source port change between flows: the keyed
  start is fixed per endpoint for one key generation, and a returning
  endpoint keeps its own port, so a resolver must still randomize its
  own source ports (RFC 5452). Also choose `false` when inside hosts are
  not trusted: with preservation on, an inside host can learn whether a
  public port is in use (its own source port comes back unchanged only if
  the port was free), and a new mapping takes its internal port even
  when it belongs to another host's just-expired mapping, so an inside
  host can claim a victim's port the moment it expires (and receive what
  remotes still send to it). With `false`, the port comes from the
  victim-independent keyed search, and an expired port is reused only by
  its own returning endpoint or by a keyed takeover when the pool is
  full. The switch is reloadable and carries the NAT state (port
  preservation only affects new mappings).
- Translated ICMPv4 errors (NAT44-065, NAT44-099). The per-path limit
  bounds how many forged errors reach an inside host about one remote
  (a host with flows to many remotes can receive that many budgets); it
  does not slow a
  sweep looking for live ports, and one forged Fragmentation Needed with a
  plausible MTU (68 or more) that hits a live flow still reaches the host,
  which decides whether to lower its path MTU (modern stacks check it,
  RFC 5927). The router does not track TCP sequence numbers, so it cannot
  check that a quoted TCP segment is in the window. A flood naming one of a
  host's flows also uses up that path's budget, so legitimate errors about
  the same remote can be dropped for the duration. There is no separate
  budget for Fragmentation Needed: a forged Fragmentation Needed is exactly
  what a sweep sends, so a priority lane would hand the attack its own
  budget. If inside hosts do not need PMTUD or
  traceroute through the NAT, `icmpv4-errors = "external-only"` or
  `"disabled"` (per protocol) remain the stricter options.
- ICMP query NAT (`[nat44.icmp]`, N5, NAT44-100..118). Without the
  section, `ping` from the LAN to the Internet does not work through the
  router: ICMP queries crossing the NAT are dropped as
  `NAT44_UDP_UNSUPPORTED_TRANSPORT` (`NAT44_TCP_UNSUPPORTED_TRANSPORT` when
  only TCP NAT is configured). Add the section (and, with the
  firewall, an `icmp` rule such as `ingress = "lan"`, `egress = "wan"`,
  `protocol = "icmp"`, `action = "allow-stateful"`, without port ranges)
  to translate Echo and Timestamp requests from inside hosts and their
  replies. Adding or removing the section changes the storage shape, so it
  needs a restart (`ruster plan` shows `nat44-icmp ~ off -> on` and
  `STORAGE_SHAPE`); its other keys are reloadable. Sizing: one mapping per
  (inside host, ping identifier), usually one per running `ping`, and one
  peer per remote it pings; `capacity.mappings = 256`, `peers = 1024` serve
  a home LAN. The identifier pool (`[nat44.icmp.identifiers]`, default the
  realm port numbers) costs 32 bytes per identifier, so the full
  1..65535 range is about 2 MiB. Limits:
  - Queries are translated whether DF is set or not (Linux sends Echo
    Replies, and Windows Echo Requests, with DF clear), but never as
    fragments (`NAT44_ICMP_FRAGMENT_UNSUPPORTED`, NAT44-116): a ping larger
    than the path MTU fails. A DF-clear query gets a generated IPv4 ID
    (NAT44-126, below).
  - The idle timeout is 60 s by default (RFC 5508 REQ-2 floor); a ping
    with an interval above it gets a new mapping (and possibly a new public
    identifier) per request.
  - Pinging the router's public address from the LAN is answered by the
    router itself; there is no inbound or static query mapping, so an
    outside host cannot ping an inside host.
  - Information and Address Mask messages (RFC 6918) are never
    translated (`NAT44_ICMP_TYPE_UNSUPPORTED`).
  - Errors quoting a query (for example Time Exceeded for `traceroute -I`)
    are translated under `[nat44.icmp] icmpv4-errors` and share the
    translated-error limit of NAT44-065.
  - The firewall's ICMP flows use `udp-idle-ttl-ms` (at least 120 s,
    default 300 s), independent of the NAT's `idle-ttl-ms`; replies stop
    when the shorter of the two runs out.
  - With the firewall, an `icmp` rule cannot say "replies only" or "Echo
    only": an outside-to-inside allow rule admits every Echo and Timestamp
    request it covers. Replies to inside pings need no such rule. A reply
    never opens a flow (`FIREWALL_ICMP_REPLY_WITHOUT_REQUEST`).
  - Also with the firewall, routed Echo/Timestamp packets that do not cross
    the NAT (for example between two inside interfaces) are now evaluated
    against the rules; without an `icmp` rule they drop as
    `FIREWALL_DEFAULT_DENIED` instead of `FIREWALL_UNSUPPORTED_PROTOCOL`
    (still default deny, only the reason changed).
  - With `[nat44.icmp]`, Echo Replies to the public address take the NAT
    path, so a ping sent by the router itself from its public address would
    lose its replies (`NAT44_ICMP_MAPPING_MISS`); ruster never sends one.
  - Multi-host LANs: like UDP, one inside host can fill the query mapping
    and peer tables (one mapping per identifier, one peer per pinged
    address; a ping sweep makes many peers). Set a nonzero
    `mappings-per-host` (for example `capacity.mappings / expected hosts`)
    and size `peers` for sweeps; `peers-per-host` (N6) limits the pinged
    addresses per host as for UDP.
  - Counters: `nat44_icmp.*` (for example `outbound_translated`,
    `inbound_translated`, `mapping_misses`, `filter_denied`,
    `identifier_exhausted`, `host_quota_exceeded`,
    `host_peer_quota_exceeded`) and
    `occupancy.nat44_icmp_{mappings,peers}`; drop reasons
    `NAT44_ICMP_*` and `FIREWALL_ICMP_QUERY_INVALID`.
- Per-host mapping quota (`[nat44.udp]`/`[nat44.tcp]` `mappings-per-host`,
  N3, NAT44-092; default `0`, no limit). Without it an inside host can
  fill the pool (it opens mappings from many source ports) and so steer
  other hosts into takeovers of expired ports or into `PORT_EXHAUSTED`.
  With a limit, a host that already holds that many live mappings of the
  protocol gets its next new mapping dropped as
  `NAT44_UDP_HOST_QUOTA_EXCEEDED` / `NAT44_TCP_HOST_QUOTA_EXCEEDED`
  (counters `nat44_udp.host_quota_exceeded`,
  `nat44_tcp.host_quota_exceeded`); nothing is evicted, and its existing
  mappings, their new peers or sessions, and inbound traffic are
  unaffected. For TCP, "live" here means kept alive by the host itself:
  only segments the host sends on connections it opened, or on
  established connections, refresh a mapping for the quota (with the same
  phase TTLs as the mapping), and never a segment that leaves the
  connection closing (any RST, or an ACK from TIME-WAIT, which the host's
  stack sends in answer to whatever a remote sends on an old 4-tuple). So
  neither a remote that keeps sending SYNs to the host's public ports nor
  the remote of a closed connection that keeps poking it can keep the host
  at its limit. It recovers by
  itself: once one of its mappings has expired (UDP idle TTL; TCP the
  phase TTL of the host's last segment, 4 minutes for a closed or
  half-open connection), the next new mapping takes over that mapping's
  slot, never another host's slot, and gets its public port by the normal
  selection (preservation, keyed start, keyed takeover). A TCP mapping
  that only remotes kept alive ends with its sessions when it is taken
  over; an inside server that answers its inbound connections keeps its
  mapping. Sizing: decide up front, because switching between `0` and a
  limit needs a restart (it adds or drops per-host storage), while
  changing one limit to another is a reload. The limit counts public
  ports per host, so `pool size / expected inside hosts` keeps every host
  able to get a port (for example 65535 / 64 hosts is about 1024); a limit
  of a few hundred to a few thousand still serves browsers, games, and P2P
  clients, while a host that opens tens of thousands of flows is the one
  refused. If unsure, enable it with a generous value (for example 4096)
  and lower it by reload. Watch the counters: a steadily rising count on a
  well-behaved host means the limit is too low. Enabling it allocates
  per-host storage sized from `capacity.mappings` (76 bytes per UDP
  mapping slot, including the N6 peer counters, and 76 per TCP slot at a
  power-of-two capacity, 9961472 bytes for both at 65536 slots; it still
  fits the 64 MiB production bound), so changing between `0` and a limit is restart-required
  (`STORAGE_SHAPE`); changing one limit to another is reloadable (`ruster
  plan` shows `nat44-udp mappings-per-host ~ 64 -> 128`; the apply carries
  the NAT state: a host already above a lowered limit keeps its live
  mappings and gets no new one until it is below it). Limits:
  - The quota covers mappings (public ports) only. One host can still
    fill the `peers` or `sessions` table with many remotes on its few
    mappings unless the per-host peer and session limits below are set.
  - The limit is per inside IPv4 address. The router's reverse-path check
    accepts an inside source only if its address routes back out of the
    inside interface, so spoofing is bounded to the inside-routed
    prefixes, but there is no ARP or MAC binding: a LAN host can still use
    any address in those prefixes and get a quota per address. Keep the
    inside routes tight (the connected LAN prefix rather than a broad
    route). A LAN host spoofing a chosen victim's address can also use up
    that victim's quota and lock it out, which is the same residual.
  - Narrow TCP residual: a returning endpoint whose own mapping was
    already taken over (retired) is refused while the host is at its
    limit and every one of its mappings past the host-driven expiry is
    still kept live by a remote's inbound segments (a mapping is never
    retired while live). Retired slots are the first reused, so the window
    is short, and other source ports of the host are not affected.
  - No ICMP is sent for a refusal, and there is no per-host usage report
    (NAT44-096).
- Per-host peer and session limits (`[nat44.udp]`/`[nat44.icmp]`
  `peers-per-host`, `[nat44.tcp]` `sessions-per-host`, N6, NAT44-119;
  default `0`, no limit; RFC 6888 REQ-5 SHOULD). Without them one inside
  host can fill the shared `peers` or `sessions` table by talking to many
  remotes from a few mappings, and every other host then gets
  `PEER_TABLE_FULL` / `SESSION_TABLE_FULL`. With a limit, a host's next new
  UDP or ICMP query filter peer (a remote address, or address and port under
  address-and-port-dependent filtering) or its next new outbound TCP
  connection is dropped as `NAT44_UDP_HOST_PEER_QUOTA_EXCEEDED` /
  `NAT44_ICMP_HOST_PEER_QUOTA_EXCEEDED` /
  `NAT44_TCP_HOST_SESSION_QUOTA_EXCEEDED` (counters
  `nat44_{udp,icmp}.host_peer_quota_exceeded`,
  `nat44_tcp.host_session_quota_exceeded`) while it holds that many; nothing
  is evicted and existing flows and inbound traffic are unaffected. What
  counts:
  - UDP/ICMP: the peers of the host's live mappings. Peers live as long as
    their mapping, which only the host's outbound packets refresh, so a
    host recovers one idle TTL after it stops using a mapping. Every peer
    the host's own packets create counts, including its answers to
    remotes that reached it first. Under `filtering =
    "endpoint-independent"` any remote (or spoofed source) can reach a
    host's mapped port, so a host that runs a UDP responder (a game or SIP
    server, a P2P node) can have its whole budget spent by the remotes it
    answers, after which its own new peers (its DNS client too) are
    refused while it keeps answering. Do not combine endpoint-independent
    filtering with `peers-per-host` for hosts that run UDP services; under
    the default address-dependent filtering such packets are filtered
    before the host sees them (NAT44-125).
  - TCP: only sessions the host opened with an outbound SYN (the outbound
    half of a hairpin too). Connections remotes open to the host (inbound
    SYNs, the inbound half of a hairpin) never count, so an attacker cannot
    spend a victim's budget; bound those with `inbound-sessions-per-remote`
    and filtering. A counted session counts while the host keeps it alive
    by the same rule as the mapping quota above (its own segments, never a
    RST or an ACK from TIME-WAIT, and only the 4-minute transitory timeout
    once the host has sent its FIN), so a closed connection stops counting
    4 minutes after the host's last segment (an opening one after the
    opening timeout, an idle established one after the established
    timeout) even if the remote keeps it alive; it is then left to the
    remote and is no longer counted. If the host resumes such a session,
    its next segment counts it again within the limit like a new session
    (dropped as `NAT44_TCP_HOST_SESSION_QUOTA_EXCEEDED` while every counted
    session is still driven), so letting sessions lapse and resuming them
    cannot exceed the limit. A connection the remote reopens after a FIN
    close (the host answers its SYN) is remote-opened and stops counting;
    one the host reopens with its own SYN counts. A host at
    `sessions-per-host` that resumes a connection after more than its idle
    timeout of its own silence may see that connection's segments dropped
    as `NAT44_TCP_HOST_SESSION_QUOTA_EXCEEDED` until one of its other
    sessions goes idle. Size the limit with headroom above the host's
    normal number of concurrent connections.
  - Sizing: like the mapping quota, `capacity.peers` or `capacity.sessions`
    divided by the expected inside hosts keeps every host able to work
    (for example 65536 sessions / 64 hosts = 1024). Browsers open tens to a
    few hundred connections; P2P clients and scanners thousands. Start
    generous (for example 2048) and lower by reload while watching the
    counters.
  - Storage and classification: a UDP or ICMP `peers-per-host` uses the
    same per-host storage as `mappings-per-host` (76 bytes per mapping
    slot), so it is a storage change only when neither was set before; a
    TCP `sessions-per-host` adds 92 bytes per session slot (6029312 bytes
    at 65536). Switching storage on or off is restart-required
    (`STORAGE_SHAPE`), changing one nonzero limit to another reloadable
    (`ruster plan` shows `nat44-tcp sessions-per-host ~ 32 -> 64`; the apply
    carries the NAT state, and a lowered limit refuses new state without
    evicting live state). At the production maximum (every table at
    65536 slots, with the 1024 fragmentation slots of MTU2 part B)
    `sessions-per-host` alone fits the 64 MiB bound (67072192 bytes), both
    mapping limits fit only with at most 12 fragmentation slots (67106128
    bytes at 12; the default 64 slots exceed the bound), and all four
    per-host limits together do not: validation fails closed with
    `RUNTIME_STORAGE_BYTES_EXCEEDED`; lower a capacity (for example
    `capacity.sessions = 32768`) instead.
  - Limits: no rate limit on state creation (REQ-5 b), no ICMP or
    notification for a refusal, a host colluding with a remote can still
    add inbound-created TCP sessions, and the endpoint-independent UDP
    responder case above (NAT44-125).
- Debug builds validate every NAT44 index after each UDP commit (O(M+P)
  and more per packet). Use only release builds (`cargo build --release`)
  in production.
- Capability diagnostics read `CapEff` in the caller's user namespace; in a
  non-initial user namespace the bits can look sufficient while BPF still
  needs init-namespace capabilities, so the failure appears later as
  `attach code=.../PERMISSION_DENIED`. The startup warns once
  (`warning: user namespace: code=USER_NAMESPACE_NOT_INITIAL ...`, log
  event `USER_NAMESPACE_NOT_INITIAL`) when `/proc/self/uid_map` is not the
  initial namespace's identity map (or cannot be read); it does not stop
  the start.
- `[exit-protection]` (section 9) cannot run when the process is killed
  outright (`SIGKILL`, a seccomp kill, the OOM killer) or panics while
  unwinding; both keys need `--keep-privileges`. Use the supervisor's
  post-stop hook for those cases.
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
- Idle wait (H9, section 7): a signal the kernel delivers to a thread
  other than the router, a link round, and anything not on the "pending"
  list of section 7 are seen up to `--idle-wait-ms` (10 ms) later while
  idle. The wait is level-triggered on RX only.
- Not implemented (CLI-034): opt-in "link down / forwarding 0 at exit".
  (Structured logs, `[health]`/`[watch]`, and the integrity conditions are
  OPS-LOG; state carried across a reload is RELOAD-CARRY.)
  (SIGUSR1 stats and systemd notification are H10.)
- systemd notification (H10): the watchdog is pinged by the router
  thread only, so a stuck worker thread does not stop it (the link
  watcher's own stale rule ends the run then, section 8); the pings pause
  for up to 200 ms while a reload waits for quiescence. `MONOTONIC_USEC`
  comes from `CLOCK_MONOTONIC` as systemd expects; `vsock:` notification
  addresses (systemd in a VM) are refused, not supported.
- Privilege drop limits (CLI-089 to CLI-095): the filesystem
  confinement (H11, section 5) limits file reads to the config's
  directory, the router's own `/proc/<pid>`, `/proc/sys/net`, and its
  binary, but a compromised process can still open rtnetlink sockets and
  dump the namespace's links, addresses and routes, and write to its own
  open fds; numeric `--user`/`--group` only, and the drop needs
  Linux 6.5 or newer unless `kernel.unprivileged_bpf_disabled=0`. Without
  `--user`/`--group` the process stays uid 0 (owner of every root file).
- While a port is down with TX held, its owed kick is retried about 16
  times per second (1 ms doubling to 64 ms, §8), so held TX resumes within about
  64 ms (plus up to one 1 ms idle wait) after the link returns; the run loop's link watch (1 s) does not
  shortcut the retry.
- Syscall filter limits (CLI-102 to CLI-109): x86_64 only (the platform of
  `ruster run`). The allowlist is for glibc builds only. It covers glibc
  2.31 and newer as far as the calls were checked: verified at run time on
  the development host and the CI runner (glibc 2.39), and by reading the
  glibc wrappers that changed in that range (`fstat` through `newfstatat`
  in 2.33 to 2.38, `nanosleep` before `clock_nanosleep`). A musl build
  (compile-only in CI) is not verified at run time and needs more (musl's
  `open` uses the `open` syscall, for one; `nanosleep` and `newfstatat` are
  already covered), so run a musl build with `--seccomp log` first. A
  future change that makes a new syscall after startup (a new thread, a
  new file or socket) must extend the allowlist, or the default kills the
  router. Known calls that are denied and not reachable after startup
  today: `fs::canonicalize` (`realpath`), glibc malloc's
  `sched_getaffinity` (glibc sizes its arena limit once, when the first
  extra arena is made; every thread has allocated before the install), `writev` (no vectored write is
  used), `clone`/`clone3` (no thread after startup). Argument filters cover the
  calls listed in section 5; `write`, `read`, `sendto`, `connect` and the
  others work on any fd the process holds.
- Verified kernels: the development host and the CI runner only
  (XDP-062). A TX stall with the link up (`TX_STALL`) cannot be produced
  on veth and is tested only against a scripted kernel (CLI-050).

### AF_PACKET backend (AFPKT-015)

`ruster run` drives either backend; `backend.kind` selects it. AF_XDP stays
the primary backend. AF_PACKET (`ruster-io-afpacket::AfPacketIo`, AP3) is
the debug/fallback backend: it needs no XDP program, no `CAP_BPF`, no
`RLIMIT_MEMLOCK`, and no single-queue or RSS steering, only `CAP_NET_RAW`,
so it runs where XDP attach is impossible (a driver or kernel without XDP,
a device that already carries a foreign XDP program, a container without
BPF privileges).

**Selecting it.** Replace the `[backend]` section:

```toml
[backend]
kind = "af-packet"

[backend.af-packet]
max-frame-len = 1514            # optional, default 1514; every port's device MTU must be at most this - 14

[[backend.af-packet.ports]]     # one per [[interfaces]] entry
interface = "lan"
rx = { block-size = 65536, block-count = 8, retire-timeout-ms = 2 }
tx = { block-size = 65536, block-count = 4 }

[[backend.af-packet.ports]]
interface = "wan"
rx = { block-size = 65536, block-count = 8, retire-timeout-ms = 2 }
tx = { block-size = 65536, block-count = 4 }
```

- `block-size` is a power of two from 4096 to 4 MiB (and a multiple of the
  page size, checked when the socket opens), `block-count` 1 to 65536,
  `retire-timeout-ms` 1 to 1000; `max-frame-len` 590 to 9230. The frame
  slot is derived (the smallest power of two that holds the kernel's
  per-frame header and `max-frame-len`: 2048 for 1514), so the TX ring holds
  `block-size / slot * block-count` frames (128 in the example) and an RX
  block at least one frame. One port's rings are at most 256 MiB, all
  ports' at most 1 GiB (`ruster validate` prints `ring-bytes=`).
- Every backend change (kind, `max-frame-len`, any ring value) is
  restart-required (`ruster plan` shows `backend ~ ...`,
  `backend af-packet max-frame-len ~ ...`, `backend-af-packet-port ...`;
  `restart-required: BACKEND`); a SIGHUP reload refuses it.
- `ruster run` startup line, stats, reload, drop, Landlock, seccomp, and
  the exit statuses are those of AF_XDP. The shutdown summary ends in
  `closed N port(s)` (there is nothing to detach). Exit 4 without
  `CAP_NET_RAW` prints `run as root or grant CAP_NET_RAW`.

**Exposure model.** An AF_XDP port's frames are redirected away from the
kernel stack. An AF_PACKET socket only receives a *copy*: the kernel stack
keeps processing every frame of the port while the router runs, as well
as before and after it. So the kernel must have nothing to act on:

- Startup refuses, per port, exactly what it refuses for AF_XDP (section
  5): kernel IPv4 addresses or routes, IPv4 forwarding (`ip_forward`, the
  device's `forwarding`, `mc_forwarding`), the weak host (`rp_filter` 0),
  and IPv6 enabled on the port, with the same overrides
  (`--allow-kernel-forwarding`, `--allow-ipv4-weak-host`,
  `--allow-kernel-ipv6`). The RX queue count does not matter (a packet
  socket receives from every queue; no `--allow-multi-queue` needed).
- In addition: the device MTU must be at most `max-frame-len - 14`
  (`MTU_ABOVE_FRAME mtu= limit=`: longer frames would be truncated by the
  RX ring and dropped; a raise above it while running is fatal too). A
  smaller device MTU is fine: the router never sends a frame above an
  interface's configured `mtu` (MTU1: Fragmentation Needed instead), which
  may not exceed the device MTU, and a decrease while running is fatal
  (`MTU_DECREASED`). So mixed MTUs share one `max-frame-len`, the largest
  port's MTU plus 14: a 9000-byte LAN and a 1500-byte WAN run with
  `max-frame-len = 9014` (the rings then hold 9014-byte frames for both).
  The port must not be enslaved to a bridge, bond, team, or VRF, and no
  device of the router's namespace may be stacked on it: a VLAN, macvlan,
  ipvlan, or MACsec device on the port, or the port's veth peer in the
  same namespace (`KERNEL_UPPER_DEVICE`: a bridge forwards every frame
  around the router, a macvlan delivers frames to its own stack). Devices
  stacked on the port are found with one link dump of the namespace
  (`IFLA_LINK` is the port and no `IFLA_LINK_NETNSID`; a failed dump is
  `UNVERIFIABLE probe=upper-devices`), at startup and at every link round
  while running (one dump per round for all AF_PACKET ports together),
  where one is fatal (`fatal: port=ifN
  health=KERNEL_UPPER_DEVICE`), as is the port becoming enslaved. A device
  stacked on the port *from another namespace* (a macvlan or ipvlan created
  in, or moved to, a container's namespace) carries `IFLA_LINK_NETNSID`
  and is not in this namespace's dump: the router cannot see it, so keeping
  the ports free of such devices is the operator's responsibility. Finally,
  no merging receive offload may be active
  (`RECEIVE_OFFLOAD feature=rx-gro|rx-lro|rx-gro-hw`; a packet socket sees
  frames after GRO, so merged super-frames would be truncated and dropped;
  `UNVERIFIABLE probe=offloads` if the features cannot be read). Fix:
  `ethtool -K <dev> gro off lro off`, and set the MTU. The configured
  `[[interfaces]] mtu` (MTU1) is checked as for AF_XDP: above the device
  MTU refused (`MTU_BELOW_CONFIG`), below it warned (`MTU_BELOW_DEVICE`).
- While running, the link watch's kernel exposure conditions are **fatal**
  for AF_PACKET (under AF_XDP they only warn): a kernel address or route
  appearing on a port, forwarding turning on, `rp_filter` dropping to 0,
  IPv6 turning on (or an IPv6 address, route, or forwarding with it) print
  the warning and then `fatal: port=ifN health=<same code>`; the router
  drains and exits 1, and the next start refuses until it is fixed.
  Stopping does not reduce the kernel's exposure (it was already acting on
  every frame), but it makes the misconfiguration visible at once instead
  of letting the kernel answer, deliver, or forward in parallel. What an
  override accepted at startup stays a warning. A GRO toggle or a new
  upper device at run time is fatal (above). Receive offloads are not
  watched while running (the probe is an ioctl the syscall filter does not
  allow): turning GRO or LRO back on shows as growing
  `ifN.af_packet_port.rx_packet_faults` (merged super-frames truncated and
  dropped) and TCP through the router stalling under load; turn it off
  again (`ethtool -K <dev> gro off lro off`), and the next start refuses it
  anyway.
- The kernel sends nothing of its own on a correctly configured port: no
  IPv4 address means no ARP and no IGMP report source, `disable_ipv6=1`
  means no neighbor discovery or MLD, and forwarding off with `rp_filter`
  1 means a received IP frame is dropped (`ip_error` sends no ICMP while
  forwarding is off). The privileged smoke checks that every frame the
  router's devices transmitted during a run was one the router sent. A
  local socket that joins a multicast group on a port would make the
  kernel send IGMP reports; do not run other services on the ports.
- The socket sets `PACKET_IGNORE_OUTGOING` (the router never receives its
  own TX) and requests no promiscuous mode: the port receives frames for
  its own MAC plus broadcast and multicast, as with AF_XDP.

**Performance (not measured).** Every forwarded frame is copied once into a
TX frame (router-generated ARP/ICMP is written into the TX ring directly),
the kernel stack processes each received frame a second time, and TX goes
through the device qdisc. Expect throughput well below AF_XDP copy mode;
no number is claimed. TPACKET_V3 hands an RX block to the router when it
is full or its retire timer fires, so an idle port delivers a lone frame
up to `retire-timeout-ms` late; 1 to 2 ms suits a router (the timer runs in
the kernel, not in the router thread). A growing `kernel_drops` means the
RX ring is too small (more or larger blocks) or the router thread too slow.

**Link dump cost and churn.** The dump reads every link of the router's
namespace once per link round (every second), whatever the port count,
into the watcher's reused 32 KiB buffer. On a namespace with thousands of
links (a Kubernetes node with about 2000 veths) that is a few MB of
rtnetlink replies per second and an RTNL hold per round: run the router in
its own namespace with only its ports, as recommended. A dump that link
changes interrupt (`NLM_F_DUMP_INTR`) is retried within the round; a
device any attempt listed is still reported (fatal `KERNEL_UPPER_DEVICE`:
it existed then), so churn cannot hide one; a round whose every attempt
was interrupted without listing one is a failed query counted apart, and
only 10 such rounds in a row (`LINK_DUMP_INTERRUPTED_FATAL`) end the run
with `LINK_UNVERIFIABLE`; other dump failures are fatal after 3, as for
the other queries.

**Kernel memory.** The TPACKET rings are kernel pages allocated when the
sockets open: up to 256 MiB per port and 1 GiB in all (the validation
bounds, `ring-bytes=` in `ruster validate`). They are not charged to
`RLIMIT_MEMLOCK` and, as `packet_mmap` ring pages, not to the memory cgroup
of the service either, so a container or systemd `MemoryMax=` does not
bound them: size the rings for the host, not for the cgroup.

**Stats.** `af_packet.*` (sum) and `ifN.af_packet_port.*` (per port,
OBS-028): RX packets and faults, TX published/copies/completed/ring full/
oversize, kicks (deferred, link down, unbound, errors, retries,
suppressed), generated frames, `socket_errors` (a pending socket error the
idle wait read and cleared after the port went down or away), and the
kernel's `tp_packets`/`tp_drops`/`tp_freeze_q_cnt` as `kernel_packets`/
`kernel_drops`/`kernel_freeze_q`, folded in at every health sample (every
500 ms; the kernel keeps them in 32-bit counters that reset on read).

**Troubleshooting.**

| Symptom | Cause and fix |
|---|---|
| `stage=checks port=ifN code=RECEIVE_OFFLOAD feature=rx-gro` | GRO (or LRO, hardware GRO) on: `ethtool -K <dev> gro off lro off` |
| `code=MTU_ABOVE_FRAME mtu=M limit=L` | lower the port MTU to at most `max-frame-len - 14`, or raise `max-frame-len` (restart-required) |
| `code=MTU_BELOW_CONFIG mtu=M config=C` | the interface's configured `mtu` is above the device MTU: raise the device MTU or lower `mtu` (MTU1) |
| `code=KERNEL_UPPER_DEVICE` (startup or `fatal: ... health=KERNEL_UPPER_DEVICE`) | remove the port from its bridge/bond/team/VRF, and delete the VLAN/macvlan/ipvlan/MACsec devices on it (`ip -d link show` lists `@<port>`); a veth pair needs its peer in another namespace |
| `code=UNVERIFIABLE probe=upper-devices` | the namespace's link dump failed (rtnetlink); retry, check the kernel log |
| `af_packet_port.rx_packet_faults` grows, TCP stalls under load | GRO or LRO was turned on while running (not watched): `ethtool -K <dev> gro off lro off`; the next start refuses it |
| `code=UNVERIFIABLE probe=link` at startup | the configured device does not exist in the router's network namespace |
| `stage=open code=CONFIG.RING...` | the ring geometry does not fit this system's page size (a 16 or 64 KiB page needs blocks of at least that size) |
| `stage=open code=SOCKET/ERRNO_1` | no `CAP_NET_RAW` in the namespace that opens the socket |
| `fatal: port=ifN health=KERNEL_...` while running | a kernel address, route, forwarding, weak host, or IPv6 appeared on the port; remove it, then restart |
| `fatal: port=ifN health=DEVICE_REMOVED` | the port's device was deleted (rtnetlink `ENODEV`, or a TX kick found it gone with `ENXIO`, which also strands its in-flight TX); restart with the device back |
| `warning: port=ifN health=LINK_DOWN` | carrier lost or the port set down: frames queue in the TX ring and the owed kick is retried at most about 16 times a second until the link is back; a reload waits for those frames (publication quiescence) and is abandoned after the quiesce timeout |
| `kernel_drops` grows | RX ring too small or router overloaded |

**Notes.** A down egress with queued TX keeps those frames in flight, and a
SIGHUP reload during such an outage is held back until the link returns or
the reload quiesce timeout passes. AF_PACKET runs are x86_64 Linux only
(as `ruster run`), 64-bit, and verified on veth in the privileged smoke
only; no real NIC has been tried.

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
- The AF_PACKET live adapter on a real kernel (AP3, library level):
  `scripts/priv-afpacket-smoke.sh` (`priv_afpacket_*`):
  idle poll, core forwarding between two veth ports, a generated burst,
  a link flap, a failed open that releases its first port, drain and close.
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
  Added by B3, with a rule that admits new WAN -> LAN TCP flows to every
  destination: a raw TCP SYN from host B to an unmapped public port gets
  exactly one ICMP Port Unreachable from 203.0.113.2, no earlier than 6 s
  after the SYN (measured from after `sendto` returned, the latest
  send-side reading), quoting it. After a reloadable SIGHUP to
  `unsolicited-syn-icmp = false`, nothing arrives within 9 s. After a SIGHUP
  back to router-v1's default-deny firewall (switch on), nothing arrives
  within 9 s either (`unsolicited_syn_firewall_denied`).
  Added by N5: without `[nat44.icmp]` (router-v1), `ping` from host
  A to host B is dropped (`NAT44_UDP_UNSUPPORTED_TRANSPORT`); with the
  section and an `icmp` firewall rule (a restart, `nat44-icmp ~ off -> on`
  in the plan), 3 of 3 pings get their replies (host B has no route to the
  LAN, so a reply proves both translations), a ping of 203.0.113.2 is
  answered by the router, and the stats show 3 outbound and 3 inbound
  translations on one mapping.
  Added by MTU2 part A (`priv_run_df_clear`): host A sends, from a raw
  socket, two DF-clear UDP datagrams with the same IPv4 ID and one with DF
  to host B; host B sees all three from 203.0.113.2 with valid checksums,
  the DF-clear ones still without DF and with consecutive generated IDs,
  the DF one with the ID host A sent; no fragment drop is counted.
  Added by URPF (`priv_run_urpf`): with `source-validation = "strict"` on
  both ports, host A -> host B is still forwarded and translated and host
  B's Echo Request to 203.0.113.2 is answered, while the same Echo sent
  from host B's extra inside address 192.168.1.99/32 gets no reply and
  counts `drop.IPV4_SOURCE_VALIDATION_FAILED`; a SIGHUP reload to `off`
  (generation 2) answers it again; exit 0, nothing attached.
  Added by INPUT-FW (`priv_run_inputfw`): with `[firewall.input]
  default-action = "deny"` and one rule accepting the LAN, host A -> host
  B is still forwarded and translated and host A's Echo to 192.168.1.1 is
  answered, while host B's Echo to 203.0.113.2 gets no reply and counts
  `drop.IPV4_INPUT_FIREWALL_DEFAULT_DENIED`; a SIGHUP reload adding a rule
  for Echo from 203.0.113.1/32 on the WAN (generation 2) answers it; exit
  0, nothing attached.
  Added by MTU2 part B (`priv_run_frag*`): with the WAN link (rb, pb, and
  the wan `mtu`) at 1400, a DF-clear 1500-byte UDP datagram from host A
  arrives at host B's pb as exactly the RFC 791 pair of fragments from
  203.0.113.2 (1376 + 104 data bytes, one generated ID) and is reassembled
  by host B's kernel with the payload as sent; with `[fragmentation]
  enabled = false` it does not arrive (`drop.IPV4_FRAGMENTATION_REQUIRED`);
  with the LAN `mtu` at 1280,
  host B's DF-clear 1400-byte answer arrives at host A as two fragments
  (1256 + 124) and is reassembled; the final counters show the fragmented
  datagrams and no drop, no flush, no TX rejection. The afpacket phase
  repeats the inbound run with `backend.kind = "af-packet"`
  (`priv_run_afpacket_frag`).
  Added by NAT-FRAG (`priv_run_natfrag*`): every device at 1500, the
  firewall on, the default `[fragment-tracking]`: host B's 3000-byte
  DF-clear UDP answer to host A's NAT mapping, fragmented by host B's
  kernel (1480 + 1480 + 20 data bytes), arrives at host A translated (one
  inbound generated ID, TTL 63) and is reassembled; host A's own fragments
  from a raw socket, sent last first, are held and released by the router
  and reassembled by host B with the payload as sent (source 203.0.113.2);
  the final counters show `fragment_tracking.held` =
  `consume.IPV4_FRAGMENT_HELD`, released, and no fragment refused. With
  `[fragment-tracking] mode = "refuse"` the same fragments never arrive
  (`drop.FIREWALL_FRAGMENT_UNSUPPORTED`).
  Added by ARP-HOLD (`priv_run_arphold*`): with every neighbour cache empty
  (a fresh router, host A's and host B's caches flushed), `ping -c1` from
  host A to host B succeeds on the first try, and on another fresh router
  the first TCP SYN to host B gets through without a retransmission
  (`tcpi_total_retrans` 0, connect well under the 1 s initial RTO); the
  final counters show `arp_hold.held` = `replayed` = `replay_sent` = 1 and
  no `NEIGHBOR_UNRESOLVED`. With `[resolution.hold] enabled = false` the
  same single ping is lost (`drop.NEIGHBOR_UNRESOLVED=1`). Not repeated over
  AF_PACKET (the hold is in the core, the same for both backends).
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
  fatal, exit warnings for what was still on; an effective `rp_filter=0`
  refused at startup (`KERNEL_IPV4_WEAK_HOST`, per port, also with
  `arp_ignore=1` and the other overrides), accepted and warned under
  `--allow-ipv4-weak-host`, recovered with 2 and 1, and without the flag
  `rp_filter=2` started clean and a run-time flip to 0 only warned (H5); an IPv4 multicast routing socket
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
  Added by H3 (marker `priv_run_limits`): a config with every runtime
  table at its production limit (51.11 MiB of storage since H4b)
  accepted by `validate`; `ruster run` starts it, forwards and
  translates, and exits 0 on SIGTERM; one more failure hold (4097, a
  quote table) refused by `validate` and `run` (exit 2) although
  accepted as a sim document.
  Added by H6: every phase runs with the default privilege drop. Markers
  `priv_run_privileges_dropped` (every thread of the running router has
  `CapInh`, `CapPrm`, `CapEff`, `CapAmb` and `CapBnd` 0 and `NoNewPrivs` 1
  in `/proc/<pid>/task/*/status`, forwarding works),
  `priv_run_privileges_identity` (the ops and icmp phases run with
  `--user`/`--group` as the invoking user: every uid/gid field switched, no
  supplementary group), `priv_run_privileges_runtime` (after the drop:
  reloads applied and refused, link down/up, the MTU fatal exit, drain and
  detach), `priv_run_privileges_reload_dropped` (the recommended layout in
  a root-owned `/run/ruster-smoke.XXXXXX` directory, `root:<gid> 0750` with
  the config `root:<gid> 0640`, removed on every exit: a SIGHUP reload that
  swaps the file applies, generation 2, and the firewall then denies,
  after the default drop as root, with `--strict-config-perms`, and with
  `--user`/`--group` plus `--strict-config-perms`, where `/proc/<pid>` is
  also owned by root because the process is not dumpable),
  `priv_run_privileges_no_dac_override` (uid 0 after the drop cannot
  reload a config from the smoke's 0700 work directory owned by the
  invoking user, generation 1 and forwarding kept) and
  `priv_run_privileges_kept` (`--keep-privileges`:
  `CAP_NET_ADMIN` in every thread, the same reload applies,
  `privileges.state=kept`).
  Added by H8: every phase runs under the default seccomp filter
  (`--seccomp kill`), and wherever the smoke checks the threads it also
  requires `Seccomp: 2`, `NoNewPrivs: 1`, and one filter more than its own
  shell in every thread. Markers `priv_run_seccomp_kill` (every thread
  filtered, the startup line, `seccomp.mode=kill`, forwarding),
  `priv_run_seccomp_log` (`--seccomp log` with `--user`/`--group`: the
  warning, forwarding, an applied reload, link down/up, exit 0, detached,
  no seccomp record in `dmesg`), `priv_run_seccomp_off` (`--seccomp off`:
  no thread filtered, `seccomp.mode=off`, exit 0), `priv_run_seccomp_sigsys`
  (a SIGSYS sent to the router, the same group exit as the filter's kill:
  it dies and both links detach; the smoke has no way to make the binary
  itself call a denied syscall, which the Rust test `seccomp::tests::live`
  does in a child process), and `priv_run_seccomp_no_violation` (no seccomp
  record of the ruster binary in `dmesg` over the whole smoke; best effort:
  with auditd running the records go to its log instead, and the kernel
  rate-limits them). `--keep-privileges` now shows `NoNewPrivs: 1` (the
  filter sets it).
  Added by H11: every phase runs under the default filesystem
  confinement; the forward phase requires the line `filesystem confined:
  mode=landlock abi=N rules=4 threads=5` and `fs.confine=landlock
  fs.threads=5`. There is no test hook that reports what the binary can
  open, so the SIGHUP reload (which opens the config path again on the
  reload worker) is the probe, with the config atomically replaced by a
  symlink: `priv_run_fs_confine_user` (as the invoking user: a symlink to
  the readable `deny.toml` outside the config directory fails with
  `stage=read code=PERMISSION_DENIED` while forwarding goes on, the same
  file installed in the directory applies; startup lines in the order drop,
  filesystem, filter, readiness; `fs.*` in the final stats),
  `priv_run_fs_confine_root` (as uid 0 without capabilities, which owns
  `/etc/shadow`: symlinks to `/etc/shadow`, `/etc/passwd`, `/proc/1/status`,
  and `/proc/<pid>/root/etc/shadow` all fail with `PERMISSION_DENIED`, then
  a config in the directory applies), and `priv_run_fs_confine_off` (the
  control: `--fs-confine off` warns, reports `fs.confine=off`, and the same
  reload through `/etc/passwd` gets past the read and fails as a config).
  The Rust tests `fs_confine::tests::live` confine spawned test threads
  (no privilege needed) and check every path class.
  Added by H9: marker `priv_run_idle` (the idle wait of section 7: over 3 s
  without traffic the router thread wakes at most 400 times per second,
  measured as its voluntary context switches, and ticks at most 400 times
  per second, `idle.errors=0`; single pings after 2 s idle have a median
  round trip of at most 1 ms and none above 10 ms, all 5 reach the router
  (`rx.received`) and at least 3 end the wait (`idle.woken`; a frame that
  lands while the thread is between waits is taken by the next tick
  without a wake); the line reports the measured rates, CPU, and round trips), and in
  `priv-xdp-smoke.sh` the line `priv_xdp_idle_wait` (on two live veth
  ports a 30 ms `poll` times out after at least 30 ms, and a frame sent
  0.3 s into a 10 s `poll` ends it).
  Added by H10: markers `priv_run_systemd` (a python datagram receiver in
  the work directory stands in for systemd: with `NOTIFY_SOCKET` and
  `WATCHDOG_USEC=400000`, as the invoking user under `--seccomp kill`,
  `READY=1` comes first and after readiness, 6 to 14 `WATCHDOG=1` in 2 s,
  a reload sends `RELOADING=1` with `MONOTONIC_USEC` and then `READY=1`
  with generation 2, SIGUSR1 prints a `kind=on-demand` block, `STOPPING=1`
  is last, and `notify.sent` equals the datagrams received) and
  `priv_run_rename` (`ip link set ra down` and `name rx` while running:
  exit 1 `DEVICE_RENAMED`, nothing attached).
  Added by AFPKT-015 (last, after the AF_XDP removal, recreating ra/pa):
  `ruster run` with `backend.kind = "af-packet"` (the AF_PACKET backend
  section above). Markers `priv_run_afpacket_config` (the af-packet
  configs validate with `ring-bytes=786432`; a firewall change plans
  reloadable, a ring change and af-xdp -> af-packet restart-required
  `BACKEND`), `priv_run_afpacket_refusals` (GRO on ra
  `RECEIVE_OFFLOAD feature=rx-gro`, rb MTU 1400 `MTU_BELOW_CONFIG`, a kernel
  address on rb `KERNEL_IPV4_ADDRESSES`, a VLAN on ra
  `KERNEL_UPPER_DEVICE`: exit 1, no packet socket in the
  namespace's `/proc/net/packet`), `priv_run_afpacket_forward` (UDP with
  NAT44 to host B, 3 of 3 pings of 192.168.1.1 answered, every thread
  dropped and under the kill filter, Landlock, two packet sockets open),
  `priv_run_afpacket_reload` (deny applied, allow applied, a ring change
  refused `RESTART_REQUIRED reasons=BACKEND` while forwarding),
  `priv_run_afpacket_link` (pb down/up: `LINK_DOWN` warned and recovered;
  ra down/up: `if1.af_packet_port.socket_errors >= 1` and over the next
  1.5 s the idle wait keeps blocking (at most 20 more sleeps, at least 20
  more waits); forwarding after each), `priv_run_afpacket_shutdown`
  (SIGTERM exit 0 with nothing in flight and `closed 2 port(s)`, no packet
  socket left, final `af_packet.*`, and on ra and rb no more frames
  transmitted than the router completed: the kernel sent none of its own)
  `priv_run_afpacket_upper` (a bridge in the router namespace enslaving
  rb while running: exit 1 `KERNEL_UPPER_DEVICE`, no packet socket left)
  and `priv_run_afpacket_removal` (`ip link del rb` while running: exit 1
  `DEVICE_REMOVED`, no packet socket left).
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
| `stage=privileges code=UNREADABLE source=/proc/self/status\|/proc/self/limits\|/proc/sys/kernel/osrelease\|/proc/sys/kernel/unprivileged_bpf_disabled` | 4 | procfs not readable | mount procfs in the namespace/container |
| `stage=privileges code=MISSING_CAPABILITIES missing=CAP_SETGID,CAP_SETUID` | 4 | `--user`/`--group` without the capabilities to switch | grant `CAP_SETUID` and `CAP_SETGID` (systemd: add them to `AmbientCapabilities`/`CapabilityBoundingSet`), or drop `--user`/`--group` |
| `stage=privileges code=TEARDOWN_NEEDS_CAPABILITIES` | 4 | kernel before 6.5 with `kernel.unprivileged_bpf_disabled` set (Ubuntu 22.04, RHEL 9 defaults; vendor backports are not detected): the teardown after the drop would fail | use Linux 6.5 or newer, or knowingly `--keep-privileges` (section 2, upgrade note); with `Restart=on-failure` the unit otherwise restarts in a loop |
| `stage=privilege-drop code=<STEP>/ERRNO_<n>` (`DUMPABLE`, `KEEPCAPS`, `BOUNDING`, `AMBIENT`, `GROUPS`, `GID`, `UID`, `CAPSET`, `NO_NEW_PRIVS`), `code=NOT_DROPPED/CAPABILITIES\|BOUNDING\|NO_NEW_PRIVS\|IDENTITY\|GROUPS\|DUMPABLE`, `code=STATUS_UNREADABLE` [`thread=output`] | 1 | the privilege drop failed (everything was rolled back) | check seccomp/LSM policy on `prctl`/`capset`/set-id calls and procfs; `NOT_DROPPED` names what a thread kept: report it |
| `stage=fs-confine code=LANDLOCK_UNSUPPORTED\|LANDLOCK_DISABLED\|LANDLOCK_BLOCKED` | 1 | the kernel has no Landlock (before 5.13, or built without it), it is not enabled (`landlock` missing from `/sys/kernel/security/lsm`), or a supervisor's syscall filter refuses the `landlock_*` calls (`EPERM`); nothing was opened | enable Landlock (boot `lsm=` list), use a newer kernel, allow `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self` in the supervisor's filter, or knowingly `--fs-confine off` (section 3) |
| `stage=fs-confine code=CONFIG_DIRECTORY_ROOT` | 1 | the config's directory, as named or resolved through a symlink, is `/`: granting it would leave every file readable; nothing was opened | move the config into a directory of its own (`/etc/ruster`), or knowingly `--fs-confine off` |
| `warning: fs-confine code=CONFIG_DIRECTORY_BROAD directory=/etc\|/home\|/root\|/usr\|/var` | — | the config's directory is a broad shared one: everything the router's user may read beneath it stays readable | move the config into a directory of its own (`/etc/ruster`) |
| `stage=fs-confine code=OPEN.CONFIG_DIRECTORY\|CONFIG_TARGET\|PROCESS\|NET_SYSCTLS/ERRNO_<n>`, `code=ABI\|RULESET\|ADD_RULE.<GRANT>\|NO_NEW_PRIVS\|RESTRICT\|PROBE/ERRNO_<n>`, `code=NOT_CONFINED/PROBE\|THREADS`, `code=NOT_PREPARED`, `code=STATUS_UNREADABLE` [`thread=output`] | 1 | the filesystem confinement could not be built or verified (everything was rolled back): `OPEN.*` a granted directory cannot be opened (no procfs, a missing config directory), `RESTRICT/ERRNO_1` no `no_new_privs`, `NOT_CONFINED` a thread could still list `/` or not every thread confined itself | mount procfs in the namespace/container; report `NOT_CONFINED`; knowingly `--fs-confine off` |
| `reload failed: stage=read code=PERMISSION_DENIED` under the default confinement | — | the config path now resolves outside the directories granted at startup (a symlink retargeted elsewhere), or plain file permissions refuse it (section 5, "Privilege drop") | keep the config (and what its path resolves to) in the directory it was started from, or restart |
| `stage=seccomp code=NO_NEW_PRIVS\|ACTION_AVAIL\|INSTALL/ERRNO_<n>`, `code=ACTION_UNAVAILABLE`, `code=TSYNC_CONFLICT`, `code=PROGRAM_TOO_LONG`, `code=STATUS_UNREADABLE`, `code=NOT_CONFINED/MODE\|FILTERS\|NO_NEW_PRIVS` | 1 | the syscall filter could not be installed or verified (everything was rolled back): `INSTALL/ERRNO_13` no `no_new_privs`, `INSTALL/ERRNO_22` a kernel without seccomp filters, `INSTALL/ERRNO_1` a supervisor's filter refused `seccomp`, `TSYNC_CONFLICT` a thread with a filter of its own, `ACTION_UNAVAILABLE` a kernel before 4.14, `STATUS_UNREADABLE` no procfs or no `Seccomp_filters` row (before 5.9) | allow `seccomp` and `prctl` in the supervisor's filter, use Linux 5.9 or newer, or knowingly `--seccomp off` (section 3) |
| the process died with SIGSYS (shell status 159, systemd `status=31/SYS`) | — | the seccomp filter killed it for a syscall outside the allowlist; the links detached | `journalctl -k \| grep type=1326` names the syscall and thread; run with `--seccomp log` meanwhile and report it (section 5, "Syscall filter") |
| `reload failed: stage=read code=PERMISSION_DENIED` after a clean start | — | after the drop the config is read without `CAP_DAC_OVERRIDE` (section 5) | make the config and its directories readable by the process's user (root: a root-owned path such as `/etc/ruster`) |
| `reload applied: ... state ... nat44-udp=flushed:<reason>` (or `nat44-tcp`, `nat44-icmp`) | — | the new document changed what that NAT state means (interfaces, public address, pool, filtering, a TCP timeout or a longer UDP/ICMP timeout, a lowered or new per-host limit), so that family was flushed with a fresh key and its connections must reconnect (RELOAD-CARRY) | expected for such a change; make it when the NAT is quiet, or keep those settings and change the rest |
| `reload applied: ... firewall-revoked=N` with N > 0 | — | the new firewall rules deny N live flows, or their routes moved to another interface or disappeared; they were revoked at the switch and pass nothing more | intended when the rules were tightened; otherwise check `ruster plan` (`firewall carried reevaluate`) and the rule order |
| `reload applied: ... state ... firewall=flushed:reevaluation-budget` | — | re-evaluating every live flow against the changed rules or routes would take more than 4194304 rule tests and route lookups, so all firewall flows were flushed instead of stalling the router | reload when fewer flows are live, or with fewer rules (`live flows x (rules + 4 x 16 for changed routes)` is the cost) |
| `reload applied: ... state ... firewall=flushed:timers` | — | a firewall idle timeout grew: a longer timeout would reopen flows that already expired, so the flows were flushed | expected; shorten timeouts freely, lengthen them when the firewall is quiet |
| established TCP through the NAT drops at every reload | — | `[reload] state = "flush"` in the new document (`state ... =flushed` for every family), or a TCP timeout or NAT realm/pool/filtering change | remove `state = "flush"` (the default carries) or leave those settings unchanged |
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
| `stage=checks code=KERNEL_IPV4_WEAK_HOST` | 1 | effective IPv4 `rp_filter` 0 on the port (the larger of `conf/all` and `conf/<dev>`; a new namespace defaults to 0; `arp_ignore` does not matter) | `sysctl -w net.ipv4.conf.all.rp_filter=1` (or 2), or knowingly `--allow-ipv4-weak-host` |
| `stage=checks code=MTU_ABOVE_FRAME mtu=M limit=L` | 1 | frames would not fit a UMEM frame | lower the MTU to at most L, or `frame-size = 4096` |
| `stage=checks code=UNVERIFIABLE probe=link\|rx-queues\|mtu\|ipv4-addresses\|ipv4-routes\|forwarding\|ipv6-disabled\|ipv6-addresses\|ipv6-routes\|ipv6-forwarding\|rp-filter` | 1 | a device fact could not be read (`mtu`: sysfs and rtnetlink disagree or the MTU changed during startup) | run under `ip netns exec <ns>`; check rtnetlink and procfs |
| `stage=attach code=CREATE_LINK/EXISTING_PROGRAM` | 1 | another XDP program is attached | remove it deliberately (`ip link set dev <dev> xdp off`) or use another device |
| `stage=attach code=CREATE_LINK/NATIVE_XDP_UNSUPPORTED` | 1 | driver lacks native XDP | `xdp-attach = "generic"` with `mode = "copy"` |
| `stage=attach code=LOAD_PROGRAM/VERIFIER_REJECTED verifier-log-bytes=B truncated=T` | 1 | the kernel verifier refused the redirect program | report it with the kernel version |
| `stage=attach code=.../PERMISSION_DENIED` | 1 | BPF denied (often a non-initial user namespace) | run with init-namespace `CAP_BPF`/`CAP_PERFMON` or `CAP_SYS_ADMIN` |
| `stage=watch code=...` | 1 | the link watch's rtnetlink socket could not be opened | check netlink access in the namespace |
| `stage=datapath\|engine\|adapter\|activate code=...` | 1 | internal setup fault after attach (everything was rolled back) | report it with the line |
| `cannot install <signal> handler`, `cannot start the output thread` | 1 | process setup failed | report it |
| `health=TX_STALL` | 1 if fatal | oldest TX frame not completing while the link is up | check PAUSE frames/flow control, driver state; restart; `[health] tx-stall-fatal-ms = 0` to warn only |
| `health=FILL_STARVED` | — | no free frame to give the kernel for RX | usually follows a TX stall; check `tx_inflight` and `TX_STALL` |
| `health=KICK_ERRORS` | 1 if fatal | kicks keep failing (not `ENETDOWN`) | check the device; `last-kick-error=` in the summary names the errno token |
| `health=FRAMES_QUARANTINED` | 1 at `frames-quarantined-fatal` | the kernel handed back a descriptor that breaks the frame ownership contract; the frame is withheld for good | a kernel or driver bug (or memory corruption): note the kernel version and driver, `if<id>.af_xdp_port.frames_quarantined` and the RX invalid reasons; restart; report it |
| `health=TX_INVALID_DESCS` | 1 at `tx-invalid-descs-fatal` | the kernel refused TX descriptors (`kernel_tx_invalid_descs`); those frames never complete | a geometry mismatch between the router and the kernel (UMEM, headroom, MTU) or a kernel bug: compare the device MTU and `max_frame`, restart; `TX_STALL` usually follows |
| `reload failed: stage=health code=HEALTH_FATAL_BELOW_WARNING` | — | the reloaded `[health]` keys and the threshold flags disagree (fatal TX stall below the warning) | set both `tx-stall-warn-ms` and `tx-stall-fatal-ms` in the config, or drop the flag (section 7) |
| `health=LINK_DOWN` | — | carrier or admin down | fix the link; forwarding resumes by itself |
| `health=ARP_ADDRESS_CONFLICT` | — | another host on that link uses the router's address (a conflicting ARP packet, RFC 5227 §2.4); with `conflict-defense` the router re-announces at most every 10 s | find the host (`tcpdump -e arp` on the link shows its MAC; the log line carries none) and fix its address |
| `health=DEVICE_REMOVED` | 1 | the port device is gone | restore the device, then restart |
| `health=DEVICE_RENAMED`, `checks code=UNVERIFIABLE probe=name` | 1 | the port's interface index carries another name than the config's `device` | rename it back or fix the config, then restart |
| `stage=notify code=NOTIFY_SOCKET_INVALID\|WATCHDOG_USEC_INVALID\|WATCHDOG_PID_INVALID\|NOTIFY_SOCKET_OPEN` | 1 | the service manager's notification environment is not usable (section 5, "Service notification") | fix the unit's environment (`NOTIFY_SOCKET` must be an absolute path or `@name`) |
| `health=MTU_DECREASED` / `MTU_ABOVE_FRAME` | 1 | MTU changed below the startup MTU / above the frame bound | restore the MTU, then restart |
| `health=MTU_RAISED` | — | MTU raised within the frame bound; TX still bounded by the old MTU | restart to use the new MTU |
| `warning: port=if<id> MTU_BELOW_DEVICE mtu=M config=C` | — | the device carries M but forwarding is limited to the interface's `mtu` C (default 1500) | set `mtu = M` if the link carries it (restart) |
| `stage=validate code=ICMPV4_ERROR_STATES_TOO_FEW_FOR_FRAGMENTATION_NEEDED path=icmpv4-errors.capacity.states` | 2 | fewer than two ICMPv4 error limiter states per interface while Fragmentation Needed is on | raise `states` to at least 2 × interfaces (+1 with delayed Port Unreachable) |
| `drop.IPV4_FRAME_EXCEEDS_MTU` | — | frames carry bytes after the IPv4 datagram beyond the egress MTU | find the sender appending trailers; the datagrams themselves fit |
| `stage=checks code=MTU_BELOW_CONFIG mtu=M config=C` | 1 | the device MTU M is below the interface's configured `mtu` C (default 1500) | set the interface `mtu` to the link's MTU (at most M), or raise the device MTU (section 5, "Interface MTU") |
| `drop.IPV4_LOCAL_UDP_PORT_UNREACHABLE` / `IPV4_LOCAL_PROTOCOL_UNREACHABLE` growing | — | UDP or another protocol sent to a router address (scans, misconfigured clients, a service expected on the router) | normal at a low rate; `udp-port-unreachable = false` / `protocol-unreachable = false` to stop answering (ICMP-ERR) |
| `drop.IPV4_INPUT_FIREWALL_DEFAULT_DENIED` / `IPV4_INPUT_FIREWALL_RULE_DENIED` growing | — | datagrams for a router address refused by `[firewall.input]` (scans of the WAN address, or a host whose traffic to the router you meant to allow) | normal for a stealth WAN; otherwise add an `accept` rule before the deny (first match) and reload (INPUT-FW) |
| `drop.IPV4_LOCAL_TCP_UNSUPPORTED` growing | — | TCP to a router address (scans, a client expecting a service on the router); not answered | nothing runs on the router; point clients at the right host |
| `icmpv4_errors.queued_parameter_problem` growing | — | truncated datagrams (a link or device shortening frames) or malformed IP options from a sender | find the link or sender; `parameter-problem = false` to stop answering |
| `drop.IPV4_FRAGMENTATION_NEEDED` growing | — | DF datagrams above an egress MTU; senders get Fragmentation Needed | normal for PMTUD; persistent growth from one sender means it ignores the error (check `icmpv4_errors.rate_limited`, firewalls in front of the sender) |
| `drop.IPV4_FRAGMENTATION_REQUIRED` | — | DF-clear datagrams above an egress MTU with `[fragmentation] enabled = false` | turn fragmentation on (the default), raise the egress MTU, or have the senders use PMTUD (DF) or a smaller MTU |
| `drop.IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS` | — | a DF-clear datagram would need more fragments than `max-fragments-per-datagram` | raise the bound (default 1365), or raise the egress MTU |
| `drop.IPV4_FRAGMENTATION_QUEUE_FULL` | — | more DF-clear datagrams above an egress MTU in one tick than `[fragmentation] datagrams` | raise `datagrams` to at least `[tick] rx` (restart) |
| `drop.IPV4_FRAGMENTATION_DATAGRAM_TOO_LARGE` | — | a DF-clear datagram longer than a fragmentation slot (the largest of the interface `mtu`s, 3826, and the AF_PACKET `max-frame-len` - 14); no production port delivers one, so only the simulator can | none on AF_XDP or AF_PACKET; in a scenario, keep injected datagrams within the slot |
| `stage=validate code=FRAGMENTATION_BACKEND_ROOM_TOO_SMALL` | 2 | fragmentation is on and a port has fewer than 4 AF_XDP `generated-frames` or AF_PACKET TX ring frames, so it could never send a fragment set (two fragments plus the router reserve of two) | raise that port's `generated-frames` (and `frame-count`) or TX ring, or set `[fragmentation] enabled = false` |
| `fragmentation.dropped_budget` growing | — | more fragment frames per tick than `[tick] generated-fragments` | raise `generated-fragments` (and the egress `generated-frames` / TX ring with it) if the link carries much fragmented traffic |
| `drop.IPV4_FRAGMENTATION_OFFSET_OVERFLOW` | — | a fragment whose offset plus data run past 65535 bytes (malformed, ping-of-death shape) | nothing to fix on the router; find the sender (the firewall normally refuses fragments first) |
| `fragmentation.dropped_unavailable` growing | — | no generated-frame or TX room on the egress for a whole fragment set | raise `generated-frames` (AF_XDP) or the TX ring; check `tx_ring_full` and completion lag |
| `fragmentation.incomplete` / `fragmentation.flushed` growing | — | backend faults during the fragment phase (an allocation failed after the room check, or a finish error) | check the backend stats and health lines of that tick; these are backend faults, not configuration |
| `drop.NAT44_UDP_NON_ATOMIC_IPV4_UNSUPPORTED` / `drop.NAT44_TCP_NON_ATOMIC_IPV4_UNSUPPORTED` growing | — | IPv4 fragments (MF or an offset) through the NAT; whole DF-clear datagrams are translated since MTU2 (section 5, "DF-clear datagrams through the NAT") | find the sender that fragments (a datagram above its link MTU); have it use PMTUD (DF) or a smaller MTU. Fragment translation is not implemented (NAT44-018) |
| DF-clear datagram has a different IPv4 ID after the router | — | the NAT generates the ID of every translated DF-clear datagram (RFC 6864 5.3.1, NAT44-126) | expected; match captures by addresses, ports and payload |
| `health=LINK_PROBE` / `LINK_UNVERIFIABLE` | 1 if `LINK_UNVERIFIABLE` | rtnetlink/procfs queries failing (3 in a row is fatal) | check the namespace |
| `health=KERNEL_IPV4_ADDRESSES` / `KERNEL_IPV4_ROUTES` / `KERNEL_FORWARDING_ENABLED` / `FORWARDING_UNVERIFIABLE` | — | kernel L3 or forwarding appeared while attached | remove it while the router runs (section 8) |
| `IPV4_WEAK_HOST_EXPOSURE` (startup under `--allow-ipv4-weak-host`, or `health=`) | — | effective `rp_filter` 0 (`arp_ignore` does not matter) | `sysctl -w net.ipv4.conf.all.rp_filter=1` (or 2); `arp_ignore=1` as well; without the flag the next start is refused |
| `health=KERNEL_IPV6_ENABLED` / `KERNEL_IPV6_ADDRESSES` / `KERNEL_IPV6_ROUTES` / `KERNEL_IPV6_FORWARDING_ENABLED` / `IPV6_UNVERIFIABLE` | — | kernel IPv6 on a port with IPv6 on, while attached | `sysctl -w net.ipv6.conf.<dev>.disable_ipv6=1` while the router runs (section 8) |
| `reload refused: code=RESTART_REQUIRED reasons=...` | — | the change needs a restart | restart in a quiet period |
| `reload failed: stage=quiesce code=TIMEOUT` | — | TX on a port whose link is up did not complete within 200 ms (a port that is down no longer blocks, section 12) | check the port's TX (`tx_inflight`, `TX_STALL`), send SIGHUP again |
| `invalid config: stage=exit-protection code=EXIT_LINK_DOWN_NEEDS_PRIVILEGES` | 2 | `link-down = true` under the privilege drop: no thread holds `CAP_NET_ADMIN` at exit | run with `--keep-privileges` (every capability stays, section 9), or set the link down in `ExecStopPost=` |
| `invalid config: stage=exit-protection code=EXIT_PROTECTION_NEEDS_SECCOMP` / `EXIT_PROTECTION_NEEDS_FS_CONFINE` | 2 | `[exit-protection]` (which needs `--keep-privileges`) with `--seccomp off` or `log` / `--fs-confine off` | keep the syscall filter and Landlock on, or use `ExecStopPost=` |
| `startup failed: stage=open code=TX_QUEUE_CHECK/TX_QUEUE_UNVERIFIABLE` | 1 | the device has more than one allocated TX queue and no sysfs view corroborates it (the view's `ifindex` and `address` must both equal rtnetlink's; another namespace's sysfs, or a device without a 6-byte address, does not), so the active TX queue count cannot be checked | use a device with one allocated TX queue (for veth: `ip link add ... numtxqueues 1`), or run where sysfs is the router namespace's (`ip netns exec` remounts it) |
| `reload failed: stage=quiesce code=DOWN_LINK_TX_HELD` | — | `[reload] down-link-tx = "refuse"` and a port whose link is down holds TX | bring the link up and reload again, or restart (which discards the held frames) |
| `invalid config: stage=exit-protection code=EXIT_FORWARDING_NEEDS_PRIVILEGES` | 2 | `ipv4-forwarding-off = true` under the privilege drop: the sysctl write needs `CAP_NET_ADMIN` at exit | run with `--keep-privileges`, or write the sysctl in `ExecStopPost=` (section 9) |
| `startup failed: stage=exit-protection port=if<id> code=ERRNO_<n>` (or `code=RENAMED`) | 1 | a port's forwarding sysctl could not be opened (no such device, read-only `/proc/sys`) or the rtnetlink socket failed; `RENAMED`: after the open, the port's name no longer resolves to its interface index (a rename or replacement since the startup checks) | check `/proc/sys/net/ipv4/conf/<device>/forwarding` in the router's namespace and that the device keeps its name; restart |
| `exit protection failed: port=if<id> action=<action> code=<code>` | 1 | an exit action failed (`KERNEL_1`: `EPERM`; `ERRNO_2`: the sysctl entry is gone, e.g. the device was renamed or removed) | apply it by hand: `sysctl -w net.ipv4.conf.<device>.forwarding=0`, `ip link set dev <device> down` |
| `reload failed: stage=apply code=RESTART_REQUIRED.<R>\|NOT_QUIESCENT\|...` | — | the live apply refused | nothing changed; check the plan |
| `stopped after a backend fault` | 1 | ring fault or wedged adapter | collect the final stats; restart |
| `stopped after an invariant violation code=APPLY_REPORT_MISSING` | 1 | publication contract broken | report it |
| `drain failed: code=...` | 1 | the drain itself failed | ports are still closed; report it |
| `tx-in-flight=T` (T > 0) | 3 | the kernel still held TX at the deadline | normal after a forced stop; the close released them |
| `tx-handoffs=H` (H > 0) | 1 | stranded TX handoff, internal fault | report it |
| `close failed: port=if<id> code=<STEP>` | 1 | a socket, ring, UMEM or link close failed | check `ip -details link show`; detach by hand if a program stayed |
| exit 101 | 101 | panic | report the message; XDP was detached by the unwind or the kernel |

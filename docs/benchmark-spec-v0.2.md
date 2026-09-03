# R17 benchmark specification v0.2

This document is the normative source for the R17 benchmark specification.
The bytes of this file, rather than a rendered copy or a Git object ID, are
the specification identity used by benchmark software and CI.

## Canonical byte contract

The canonical path is `docs/benchmark-spec-v0.2.md`. A consumer MUST hash the
complete raw file at that path. It MUST NOT hash a parsed Markdown tree,
trimmed text, a checkout-relative path, or a rendered document.

The canonical byte sequence has these mechanically checkable properties:

1. It is valid UTF-8.
2. It does not begin with the three-byte UTF-8 BOM `EF BB BF`.
3. Every line ending is exactly one byte `0A` (LF). The byte `0D` (CR) is not
   permitted anywhere.
4. The file is non-empty and ends in exactly one LF byte. Therefore the final
   two bytes MUST NOT be `0A 0A`.
5. The SHA-256 input is the complete sequence, including that final LF.
6. The document MUST NOT contain its own SHA-256 value. The compiled value is
   a derived identity held in the benchmark crate.

The repository verifier first takes one bounded private snapshot of each input
using the R17 benchmark helper. On supported POSIX targets the helper opens
with `O_NOFOLLOW|O_NONBLOCK`, rejects symlinks, FIFOs, devices, directories,
and other non-regular handles before reading, and checks the handle metadata
before and after the read. Unsupported targets fail closed. The verifier then
applies the following algorithm to the unchanged specification snapshot:
validate UTF-8; reject the BOM, CR, and trailing whitespace; require a final LF
and reject a second final LF; compute SHA-256 over the unchanged bytes; extract
the one lowercase 64-hex `R17_BENCHMARK_SPEC_SHA256_HEX` value and the typed
32-byte value from `crates/bench/src/spec.rs`; and fail unless the file hash,
hex value, and typed bytes all agree. The verifier selects `sha256sum`, then
`shasum -a 256`, then `openssl dgst -sha256` as available. A verifier failure
is a build failure, not a request to rewrite the compiled value.

`spec_git_sha` identifies the Git commit from which a specification was
selected. `source_git_sha` identifies the source commit that produced a
benchmark binary. Neither is a substitute for this content SHA, and the two
Git IDs MUST remain separate in any hardware artifact.

The identity consumer uses a strict lexical declaration parser. It recognizes
normal strings and characters, raw strings and raw byte strings with their
exact hash delimiters, escaped forms, line comments, and nested block
comments. An opened string, character, raw literal, or block comment without
its terminating delimiter is a parse failure; parser diagnostics are
value-free and do not echo source contents.

## R17 deterministic smoke boundary

R17 deterministic smoke is the ordinary-CI contract. It exercises the
allocation-free `ruster-core` forwarding matrix with the preallocated
`ruster-bench` backend, a single `wire64` frame, batch size `1`, seed
`0x5eed020000000001` (`6840125608068907009` in the canonical decimal artifact),
and logical time `1000` milliseconds. It performs one measured forwarding pass
per case, after any state-establishing setup passes. It does not read Git or
this file at runtime, spawn a process, or use wall-clock time. It does not
compute a cryptographic packet/spec hash at runtime; stateful firewall
forwarding does perform its configured SipHash of the flow tuple.

The setup and state contract is part of this specification. Plain control
cases have one measured pass and no setup pass. UDP NAT cases have one UDP
setup pass followed by the measured pass; TCP NAT cases have three setup
passes (`SYN`, `SYN-ACK`, `ACK`) followed by the measured pass. Firewall-only
cases use one UDP setup pass or three TCP setup passes, according to transport.
Combined NAT/firewall cases use the same transport-specific setup sequence.
Setup is outside the measured pass. Each stateful case must finish with one
occupied mapping/peer or mapping/session as applicable when it uses NAT; each
firewall-only case must finish with one occupied firewall state, and each
combined case must finish with both the NAT state and one occupied firewall
state. The forwarding oracle also requires one transmitted packet, zero drops,
and zero timed allocations.

The case vocabulary and order are frozen from the existing matrix test in
`crates/bench/src/matrix.rs`. The exact 24 cases are:

```text
ctl-udp0-out
nat-udp0-out-est
fw-udp0-out-est
both-udp0-out-est
ctl-udp0-in
nat-udp0-in-est
fw-udp0-in-est
both-udp0-in-est
ctl-udpc-out
nat-udpc-out-est
fw-udpc-out-est
both-udpc-out-est
ctl-udpc-in
nat-udpc-in-est
fw-udpc-in-est
both-udpc-in-est
ctl-tcp-out
nat-tcp-out-est
fw-tcp-out-est
both-tcp-out-est
ctl-tcp-in
nat-tcp-in-est
fw-tcp-in-est
both-tcp-in-est
```

The deterministic artifact is UTF-8 JSON Lines with no blank line and exactly
one final LF. JSON object member order is part of the byte contract; no spaces
are allowed outside JSON strings. The canonical CLI invocation is
`--suite deterministic-smoke --format jsonl`; other output formats are
rejected for this suite. The first line is the header:

```text
{"artifact_schema":"ruster.benchmark-smoke/v1","case_count":24,"kind":"deterministic-smoke","logical_time_ms":1000,"seed":6840125608068907009,"spec_sha256":"<lowercase-64-hex>","workload_fingerprint":"<lowercase-16-hex>"}
```

The next 24 lines are case records in the order above. The header and case
objects have an exact member order and exact allowlist; these are not minimum
field sets. The header has exactly these seven keys, in this order:
`artifact_schema`, `case_count`, `kind`, `logical_time_ms`, `seed`,
`spec_sha256`, `workload_fingerprint`. Each case has exactly these 19 keys, in
this order: `artifact_schema`, `case`, `checksum_passes`, `completion`,
`counter_allocations`, `counter_consumed`, `counter_dropped`,
`counter_received`, `counter_recycled`, `counter_tx_accepted`,
`counter_tx_rejected`, `counter_tx_requested`, `egress`, `frame`,
`logical_time_ms`, `oracle`, `ordinal`, `seed`, `spec_sha256`.

```text
{"artifact_schema":"ruster.benchmark-smoke/v1","case":"<case>","checksum_passes":<u8-decimal>,"completion":"transmitted","counter_allocations":0,"counter_consumed":0,"counter_dropped":0,"counter_received":1,"counter_recycled":0,"counter_tx_accepted":1,"counter_tx_rejected":0,"counter_tx_requested":1,"egress":"<lan-or-wan>","frame":"wire64","logical_time_ms":1000,"oracle":"forwarded-wire-exact","ordinal":<0..23>,"seed":6840125608068907009,"spec_sha256":"<lowercase-64-hex>"}
```

`spec_sha256`, `seed`, and `logical_time_ms` in every case record MUST equal
the header values. The validator MUST reject a missing, duplicate, reordered,
or unexpected case, a missing/duplicate/reordered/unknown field, a
non-canonical line, a wrong ordinal, a wrong counter or completion value, and
any spec SHA other than the compiled R17 identity. A replay is byte-identical
only when the complete artifact, including the header and final LF, compares
equal. Wall-clock latency, throughput, host names, addresses, MACs, serials,
CPU identifiers, hardware-only measurements, and other privacy-sensitive or
host-dependent values are absent from this artifact; they MUST NOT be
represented as fabricated zeroes or added under an unreviewed key.

The canonical artifact accepts only the fixed R17 seed, and writes it as the
canonical decimal `6840125608068907009`; leading zeroes, alternate numeric
spellings, and another seed are invalid. The logical time in the artifact and
the logical time passed to every deterministic state machine are the same
compiled R17 constant. The header also carries the lowercase, non-secret
`workload_fingerprint` for the complete deterministic workload. It binds the
live topology, endpoint tuples, packet fixture bytes and shape for every
measured/setup case, NAT/firewall policies, setup/state semantics, and
flow-hash algorithm without publishing hash keys or raw packets. The setup
boundary additionally has an independent fixed answer for its safe output
digests, lengths, event order, and protocol markers; the hash-role boundary
has an independent safe mapping digest; and the actual runtime constructors
have an independent semantic-probe answer for UDP mapping/peer, TCP
mapping/session, and firewall stateful-flow wiring, including constructor
argument order. Artifact validation recomputes this identity from the live
benchmark ingredients before accepting the header.

The following block is the unique machine-readable R17 binding. Its keys and
values are parsed as a complete set by the benchmark crate's specification
test; the prose below explains the same hardware boundary for readers.

```ruster-r17-binding-v1
deterministic_workload_fingerprint=0x6920d8872e7e5c38
deterministic_topology=lan-if1/mac-020000000001;wan-if2/mac-020000000002;route-10.0.0.0/24-lan;route-0.0.0.0/0-wan-via-203.0.113.1;neighbor-lan-10.0.0.10-02000000000a;neighbor-wan-203.0.113.1-020000000014;binding-lan-10.0.0.1;binding-wan-203.0.113.10
deterministic_flow_tuples=out-10.0.0.10:40000-198.51.100.20:443;in-198.51.100.20:443-10.0.0.10:40000
deterministic_packet_fixture=wire64/backend60/ipv4-total46/ethernet14/ttl64/payload-xorshift64-shift13-7-17/all-case-and-setup-bytes-bound
deterministic_nat_policy=udp-inside-lan-outside-wan-public-203.0.113.10-ports-40000-40000-idle-300000;tcp-inside-lan-outside-wan-public-203.0.113.10-ports-40000-40000-idle-7440000
deterministic_firewall_policy=lan-to-wan-source-10.0.0.0/24-destination-any-udp-tcp-ports-any-allow-stateful-generation1-idle-300000-240000-7440000
deterministic_setup=plain-measured-only;udp-udp-setup-then-measured;tcp-syn-syn-ack-ack-then-measured;event-order-udp-setup|tcp-syn|tcp-syn-ack|tcp-ack
deterministic_setup_known_answer=fnv1a64/outputs-30/bytes-1800/output-68e9f945eb0b4571/order-ae892a47c58cc77a/semantic-markers-48fcc51ed2254b9c
deterministic_state=nat-one-mapping-one-peer-or-session;firewall-one-state;combined-both;forward-one-tx-zero-drop-zero-timed-allocation
deterministic_flow_hash=siphash-2-4-flow-tuple-domain-separated-key-not-emitted
deterministic_hash_role_mapping=fnv1a64/2b07c91e57d31ca7/nat-udp-mapping-peer>nat-tcp-mapping-session>firewall-stateful-flow
deterministic_hash_constructor_binding=actual-runtime-probe-v1/udp-nat44-mapping-peer/4-peers/Nat44UdpHashKey-new(mapping,peer)/74c7bdf39f779845|tcp-nat44-mapping-session/4-sessions/Nat44TcpHashKey-new(mapping,session)/ce7d6c21d5464308|firewall-stateful-flow/3-states/FirewallHashKey-new(flow)/a2b007540a6ff5cd|aggregate/8ee009f1015aef75
hardware_plan_version=1
hardware_plan_fingerprint=0x7508ce5cf2cb672e
hardware_normative_descriptor_fingerprint=0xaa9bad5f9e6d8be7
hardware_primary_case_count=90
hardware_control_case_count=147
hardware_total_case_count=237
hardware_primary_product=frame>direction>service>transport
hardware_primary_settings=mode-zero-copy|queue-4|batch-64|flow-4096
hardware_primary_frames=eth64|eth128|eth512|ip-mtu1500|ruster-imix-v1
hardware_primary_directions=outbound|inbound|bidirectional
hardware_primary_services=plain|nat44|nat44-firewall
hardware_primary_transports=udp-checksum|tcp-checksum
hardware_control_frames=eth64|eth512|ip-mtu1500
hardware_control_slice_order=flow-one|flow64-imix|single-queue|copy-mode|standalone-firewall|udp-zero|batch-sweep
hardware_control_nesting=flow-one:frame>direction>service|flow64-imix:direction>service|single-queue:frame>direction>service|copy-mode:frame>direction>service|standalone-firewall:frame>direction>transport|udp-zero:profile>frame>direction|batch-sweep:value
hardware_udp_zero_profiles=zero-copy/q4/f1|zero-copy/q4/f64|zero-copy/q1/f4096|copy/q4/f4096
hardware_batch_sweep_values=1|32|256
hardware_control_counts=27|9|27|27|18|36|3
hardware_imix_cycle=eth64|eth64|eth64|eth64|eth64|eth64|eth64|eth512|eth512|eth512|eth512|ip-mtu1500
hardware_imix_counts=7|4|1
hardware_imix_cycle_l1_bytes=4254
hardware_fixed_backend_bytes=60|124|508|1514
hardware_fixed_ethernet_bytes_including_fcs=64|128|512|1518
hardware_fixed_l1_bytes_with_preamble_ifg=84|148|532|1538
hardware_reference_line_rate_bps=10000000000
hardware_rate_formulas=fixed-bps/(l1-bytes*8)|imix-bps*cycle-packets/(cycle-l1-bytes*8)
```

## Frozen hardware plan binding

The separate hardware qualification boundary is bound to the current
`hardware_plan_v1` source and its existing regression tests. The binding is
not satisfied by the word “frozen” or by the total count alone. It requires
plan version `1`, exactly `90` primary cases plus `147` control cases (`237`
total), and the existing non-cryptographic regression fingerprint
`0x7508ce5cf2cb672e`. The fingerprint covers the typed normative descriptor
(including all axis/value-set orders, settings, control slices and counts,
fixed-frame backend/Ethernet/L1 sizes, IMIX counts and cycle L1 size, rate
formula and reference rate, and setup/hash semantics) and all case ordinal,
seed, class, case fields, and canonical case-ID bytes.

The primary axes and their canonical nested order are:

```text
frame     = [eth64, eth128, eth512, ip-mtu1500, ruster-imix-v1]
direction = [outbound, inbound, bidirectional]
service   = [plain, nat44, nat44-firewall]
transport = [udp-checksum, tcp-checksum]
```

The primary product is `frame × direction × service × transport` (`5 × 3 × 3
× 2 = 90`) with mode `zero-copy`, queue `4`, batch `64`, and flow `4096`.
The control frame axis is exactly `[eth64, eth512, ip-mtu1500]`. Control slices
are emitted in this order: `flow-one`, `flow64-imix`, `single-queue`,
`copy-mode`, `standalone-firewall`, `udp-zero`, `batch-sweep`. `flow-one`,
`single-queue`, and `copy-mode` nest frame, direction, service in that order;
`flow64-imix` fixes `ruster-imix-v1` and nests direction, service. Standalone
firewall nests frame, direction, transport. UDP-zero nests the four profiles
`[zero-copy/q4/f1, zero-copy/q4/f64, zero-copy/q1/f4096, copy/q4/f4096]`
before frame and direction; batch-sweep uses `[1, 32, 256]` in that order.
The resulting control counts are `27 + 9 + 27 + 27 + 18 + 36 + 3 = 147`.

The ordered `ruster-imix-v1` cycle is exactly seven `eth64`, four `eth512`,
then one `ip-mtu1500` packet, with cycle L1 size `4254` bytes. The benchmark
crate's typed descriptor also fixes the fixed-frame backend/Ethernet/L1 tuples
to `(60,64,84)`, `(124,128,148)`, `(508,512,532)`, and
`(1514,1518,1538)`, and fixes the reference rate to `10000000000` bits per
second. At 10GbE, the IMIX packet-rate fraction is exactly
`2500000000/709`, whose floor is `3526093`. The crate's spec tests mechanically
check these binding literals and the independent descriptor known answer
against the current hardware-plan regression contract.

## Hardware qualification boundary

Deterministic smoke proves schema, case vocabulary/order, fixed-seed logical
execution, completion counters, forwarding oracles, and replay stability. It
does not measure elapsed time and MUST NOT gate on packets per second,
throughput, latency, loss thresholds, or a host-specific performance value.

Hardware qualification is a separate activity using the frozen
`hardware_plan_v1` matrix and the `ruster.hardware-bench/v1` measurement
protocol. That plan currently contains 237 ordered cases (90 primary and 147
controls), explicit frame/L1 arithmetic, lifecycle evidence, and separate
`spec_git_sha`, content SHA, and `source_git_sha` fields. A hardware runner
may add bounded hardware counters and latency evidence only under that
protocol. Ordinary CI in this repository performs the deterministic smoke and
schema/replay checks; it does not claim hardware throughput qualification.

The smoke artifact is therefore evidence of a reproducible software/schema
contract, not a benchmark result or a hardware baseline.

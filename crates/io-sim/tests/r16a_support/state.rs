//! R16 `state` target: NAT44 UDP/TCP and firewall state transactions.
//!
//! A bounded random program of LAN->WAN and WAN->LAN UDP/TCP packets, denied
//! and corrupted packets, time advances, and tick boundaries runs through the
//! public full-service composition (`ActivePublication` + `run_tick` on
//! `SimIo`) of a small-capacity router. An independent black-box flow model
//! checks, packet by packet and in batch order:
//!
//! - translation: outbound frames leave with the public address, a port in
//!   the configured range, endpoint-independent mapping reuse, no public port
//!   shared by two live internal endpoints, and byte-exact headers/checksums;
//! - inverse: an inbound reply to a live flow is de-translated to exactly the
//!   original internal endpoint, including when the reply shares the batch
//!   that created the state (same-batch visibility of committed state);
//! - filtering: replies without exact live state, denied and corrupted
//!   packets, and non-SYN TCP without a session are never forwarded;
//! - capacity: a fresh flow on an empty router always succeeds, live flows
//!   are never evicted by later pressure, and while no state can have expired
//!   a tick that forwarded nothing leaves every NAT/firewall slot unchanged;
//! - no panic and exact RX accounting in every tick.

use ruster_control::{
    ActivePublication, FullServiceStorage, PublicationSequencer, SimDeterministicKeySource,
};
use ruster_core::{IfId, Ipv4Address, MonotonicMillis};
use ruster_io_sim::{FrameOrigin, SimIo};
use ruster_runtime::{run_tick, RxPhaseReport, TickBudgets, TickObserver};

use super::envelope::{CaseEnvelope, Expected, InvariantFlags, Target};
use super::packets::{
    corrupt, identification, source_port, Corruption, Proto, Segment, ACK, RST_ACK, SYN, SYN_ACK,
};
use super::router::{
    host, host_mac, remote, RouterParams, GATEWAY_MAC, HOSTS, LAN_MAC, PORT_FIRST, PUBLIC, REMOTES,
    TCP_DENIED_PORT, UDP_DENIED_PORT, WAN_MAC,
};
use super::targets::{CaseFailure, V1Rng};

pub const HEADER_LEN: usize = 8;
pub const OP_LEN: usize = 4;
pub const MAX_OPS: usize = 96;
pub const MAX_BATCH: usize = 8;
pub const START_MS: u64 = 1_000;
/// Every flow refreshed by a forwarded outbound packet within this window
/// is live in every service (the shortest idle lifetime is TCP Opening,
/// 240 s).
pub const LIVE_WINDOW_MS: u64 = 230_000;
/// No state survives this long without activity (the longest idle lifetime
/// is TCP Active/NAT TCP, 2 h 4 min).
pub const DEAD_AFTER_MS: u64 = 7_500_000;
pub const BIG_JUMP_MS: u64 = 10_000_000;
pub const MAX_ADVANCE_MS: u64 = 4_000;

/// Start times above this could overflow the bounded time advances.
pub const MAX_START_MS: u64 = 1 << 40;
const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const INTERNAL_PORTS: [u16; 3] = [5_000, 5_001, 5_002];
const UDP_REMOTE_PORTS: [u16; 2] = [53, 123];
const TCP_REMOTE_PORTS: [u16; 2] = [80, 443];

mod op {
    pub const UDP_OUT: u8 = 0;
    pub const UDP_IN: u8 = 1;
    pub const TCP_SYN: u8 = 2;
    pub const TCP_OUT_ACK: u8 = 3;
    pub const TCP_IN: u8 = 4;
    pub const DENY: u8 = 5;
    pub const CORRUPT: u8 = 6;
    pub const ADVANCE: u8 = 7;
    pub const BIG_JUMP: u8 = 8;
    pub const FLUSH: u8 = 9;
    pub const PAIR_UDP: u8 = 10;
    pub const PAIR_TCP: u8 = 11;
    pub const COUNT: u8 = 12;
}

pub fn generate(seed: u64, case_index: u64) -> Result<Vec<u8>, CaseFailure> {
    let mut rng = V1Rng::for_case(Target::State, seed, case_index);
    let mut payload = vec![
        1 + u8::try_from(rng.below(4)).unwrap(),
        1 + u8::try_from(rng.below(6)).unwrap(),
        1 + u8::try_from(rng.below(4)).unwrap(),
        1 + u8::try_from(rng.below(6)).unwrap(),
        4 + u8::try_from(rng.below(5)).unwrap(),
        1 + u8::try_from(rng.below(4)).unwrap(),
        0,
        0,
    ];
    let ops = 8 + rng.below(MAX_OPS - 7);
    payload[6] = u8::try_from(ops).unwrap();
    for _ in 0..ops {
        // Weighted: traffic dominates, big jumps are rare.
        let kind = match rng.below(64) {
            0..=9 => op::UDP_OUT,
            10..=19 => op::UDP_IN,
            20..=27 => op::TCP_SYN,
            28..=31 => op::TCP_OUT_ACK,
            32..=39 => op::TCP_IN,
            40..=42 => op::DENY,
            43..=45 => op::CORRUPT,
            46..=50 => op::ADVANCE,
            51 if rng.below(4) == 0 => op::BIG_JUMP,
            51 => op::ADVANCE,
            52..=55 => op::FLUSH,
            56..=59 => op::PAIR_UDP,
            _ => op::PAIR_TCP,
        };
        payload.extend_from_slice(&[kind, rng.byte(), rng.byte(), rng.byte()]);
    }
    CaseEnvelope {
        target: Target::State,
        seed,
        case_index,
        now: START_MS,
        ingress: 0,
        expected: Expected::Invariants(InvariantFlags::default()),
        payload: &payload,
    }
    .encode()
    .map_err(|error| CaseFailure::new(format!("encode state case: {error}")))
}

struct Program<'a> {
    params: RouterParams,
    ops: &'a [u8],
}

fn decode(payload: &[u8]) -> Result<Program<'_>, CaseFailure> {
    if payload.len() < HEADER_LEN || payload[7] != 0 {
        return Err(CaseFailure::new("state payload header is malformed"));
    }
    let in_range = |value: u8, low: u8, high: u8| (low..=high).contains(&value);
    if !(in_range(payload[0], 1, 4)
        && in_range(payload[1], 1, 6)
        && in_range(payload[2], 1, 4)
        && in_range(payload[3], 1, 6)
        && in_range(payload[4], 4, 8)
        && in_range(payload[5], 1, 4))
    {
        return Err(CaseFailure::new("state capacity header is out of range"));
    }
    let ops = usize::from(payload[6]);
    if ops > MAX_OPS || payload.len() != HEADER_LEN + ops * OP_LEN {
        return Err(CaseFailure::new("state op count does not match payload"));
    }
    let ops_bytes = &payload[HEADER_LEN..];
    if ops_bytes
        .chunks_exact(OP_LEN)
        .any(|chunk| chunk[0] >= op::COUNT)
    {
        return Err(CaseFailure::new("state op kind is unknown"));
    }
    Ok(Program {
        params: RouterParams {
            udp_mappings: u32::from(payload[0]),
            udp_peers: u32::from(payload[1]),
            tcp_mappings: u32::from(payload[2]),
            tcp_sessions: u32::from(payload[3]),
            firewall_states: u32::from(payload[4]),
            ports: u16::from(payload[5]),
            ..RouterParams::BASE
        },
        ops: ops_bytes,
    })
}

#[derive(Clone, Copy, Debug)]
struct Flow {
    proto: Proto,
    host: usize,
    internal_port: u16,
    remote: Ipv4Address,
    remote_port: u16,
    public_port: u16,
    last_out: u64,
    last_any: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Liveness {
    Live,
    Unknown,
    Dead,
}

impl Flow {
    fn liveness(&self, now: u64) -> Liveness {
        if now - self.last_out < LIVE_WINDOW_MS {
            Liveness::Live
        } else if now - self.last_any > DEAD_AFTER_MS {
            Liveness::Dead
        } else {
            Liveness::Unknown
        }
    }

    fn same_endpoint(&self, proto: Proto, host: usize, port: u16) -> bool {
        self.proto == proto && self.host == host && self.internal_port == port
    }

    fn same_tuple(&self, out: &Outbound) -> bool {
        self.same_endpoint(out.proto, out.host, out.internal_port)
            && self.remote == out.remote
            && self.remote_port == out.remote_port
    }
}

#[derive(Clone, Copy, Debug)]
struct Outbound {
    proto: Proto,
    host: usize,
    internal_port: u16,
    remote: Ipv4Address,
    remote_port: u16,
    /// Initial SYN (TCP) or any UDP datagram: may create state.
    creates: bool,
}

#[derive(Clone, Copy, Debug)]
struct Inbound {
    proto: Proto,
    remote: Ipv4Address,
    remote_port: u16,
    public_port: u16,
    flags: ruster_sim_scenario::TcpFlags,
}

#[derive(Clone, Copy, Debug)]
enum Expect {
    Out(Outbound),
    In(Inbound),
    Dropped,
}

struct Pending {
    id: u16,
    expect: Expect,
    /// A reply injected in the same batch as the packet creating its state.
    same_batch: bool,
}

struct Model {
    params: RouterParams,
    flows: Vec<Flow>,
    now: u64,
    /// Set once any recorded state may have expired; exact slot equality
    /// and no-eviction checks are then no longer decidable by the model.
    stale_possible: bool,
    firewall_usable: usize,
}

impl Model {
    fn live_endpoint_port(&self, proto: Proto, host: usize, port: u16) -> Option<u16> {
        self.flows
            .iter()
            .filter(|flow| flow.same_endpoint(proto, host, port))
            .find(|flow| flow.liveness(self.now) == Liveness::Live)
            .map(|flow| flow.public_port)
    }

    fn refresh_staleness(&mut self) {
        if self
            .flows
            .iter()
            .any(|flow| flow.liveness(self.now) != Liveness::Live)
        {
            self.stale_possible = true;
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Slots {
    udp_mappings: Vec<ruster_core::Nat44UdpMappingSlot>,
    udp_peers: Vec<ruster_core::Nat44UdpPeerSlot>,
    tcp_mappings: Vec<ruster_core::Nat44TcpMappingSlot>,
    tcp_sessions: Vec<ruster_core::Nat44TcpSessionSlot>,
    firewall: Vec<ruster_core::FirewallStateSlot>,
}

impl Slots {
    fn capture(active: &ActivePublication<'_, SimIo>) -> Self {
        Self {
            udp_mappings: active.nat44_udp().mappings().to_vec(),
            udp_peers: active.nat44_udp().peers().to_vec(),
            tcp_mappings: active.nat44_tcp().mappings().to_vec(),
            tcp_sessions: active.nat44_tcp().sessions().to_vec(),
            firewall: active.firewall().states().to_vec(),
        }
    }

    fn udp_identities(&self) -> Vec<(Ipv4Address, u16, u16)> {
        self.udp_mappings
            .iter()
            .filter(|slot| slot.is_occupied())
            .map(|slot| {
                (
                    slot.internal_address(),
                    slot.internal_port(),
                    slot.public_port(),
                )
            })
            .collect()
    }

    fn tcp_identities(&self) -> Vec<(Ipv4Address, u16, u16)> {
        self.tcp_mappings
            .iter()
            .filter(|slot| slot.is_occupied())
            .map(|slot| {
                (
                    slot.internal_address(),
                    slot.internal_port(),
                    slot.public_port(),
                )
            })
            .collect()
    }

    fn counts(&self) -> [usize; 3] {
        [
            self.udp_peers
                .iter()
                .filter(|slot| slot.is_occupied())
                .count(),
            self.tcp_sessions
                .iter()
                .filter(|slot| slot.is_occupied())
                .count(),
            self.firewall
                .iter()
                .filter(|slot| slot.is_occupied())
                .count(),
        ]
    }
}

/// How often each checked property was actually exercised.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateCoverage {
    pub translated_out: u64,
    pub translated_in: u64,
    pub same_batch_replies: u64,
    pub replies_refused: u64,
    pub outbound_refused: u64,
    pub filtered: u64,
    pub unchanged_ticks: u64,
    pub big_jumps: u64,
}

impl StateCoverage {
    pub fn add(&mut self, other: Self) {
        self.translated_out += other.translated_out;
        self.translated_in += other.translated_in;
        self.same_batch_replies += other.same_batch_replies;
        self.replies_refused += other.replies_refused;
        self.outbound_refused += other.outbound_refused;
        self.filtered += other.filtered;
        self.unchanged_ticks += other.unchanged_ticks;
        self.big_jumps += other.big_jumps;
    }
}

pub fn run(case: &CaseEnvelope<'_>) -> Result<(), CaseFailure> {
    run_with_coverage(case).map(|_| ())
}

pub fn run_with_coverage(case: &CaseEnvelope<'_>) -> Result<StateCoverage, CaseFailure> {
    if case.now > MAX_START_MS {
        return Err(CaseFailure::new("state start time is out of range"));
    }
    let Expected::Invariants(flags) = case.expected else {
        return Err(CaseFailure::new(
            "state target has a non-invariant expected value",
        ));
    };
    if flags.bits() != 0 {
        return Err(CaseFailure::new("state target accepts no invariant flags"));
    }
    let program = decode(case.payload)?;
    let config = program.params.validated()?;
    let tick = config.tick();
    let budgets = TickBudgets {
        rx: usize::try_from(tick.rx).unwrap(),
        resolution_timer_scans: usize::try_from(tick.resolution_timer_scans).unwrap(),
        failure_dispatch_scans: usize::try_from(tick.failure_dispatch_scans).unwrap(),
        generated_arp: usize::try_from(tick.generated_arp).unwrap(),
        generated_icmpv4: usize::try_from(tick.generated_icmpv4).unwrap(),
    };
    let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(case.seed));
    let candidate = sequencer
        .candidate(&config)
        .map_err(|error| CaseFailure::new(format!("state candidate: {error:?}")))?;
    let mut storage = FullServiceStorage::new(candidate.storage_shape())
        .map_err(|error| CaseFailure::new(format!("state storage: {error:?}")))?;
    let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate)
        .map_err(|error| CaseFailure::new(format!("state activation: {error:?}")))?;
    let mut harness = Harness {
        model: Model {
            params: program.params,
            flows: Vec::new(),
            now: case.now,
            stale_possible: false,
            firewall_usable: 0,
        },
        io: SimIo::new(),
        observer: TickObserver::default(),
        budgets,
        batch: Vec::new(),
        next_id: 1,
        ticks: 0,
        coverage: StateCoverage::default(),
    };
    harness.model.firewall_usable = active.firewall().usable_capacity();
    for (index, chunk) in program.ops.chunks_exact(OP_LEN).enumerate() {
        harness
            .op(&mut active, [chunk[0], chunk[1], chunk[2], chunk[3]])
            .map_err(|failure| {
                CaseFailure::new(format!("op={index} kind={} {}", chunk[0], failure.detail))
            })?;
    }
    harness.flush(&mut active)?;
    Ok(harness.coverage)
}

struct Harness {
    model: Model,
    io: SimIo,
    observer: TickObserver,
    budgets: TickBudgets,
    batch: Vec<Pending>,
    next_id: u16,
    ticks: u32,
    coverage: StateCoverage,
}

impl Harness {
    fn op(
        &mut self,
        active: &mut ActivePublication<'_, SimIo>,
        [kind, a, b, c]: [u8; 4],
    ) -> Result<(), CaseFailure> {
        let host_index = usize::from(a) % HOSTS;
        let internal_port = INTERNAL_PORTS[usize::from(b) % INTERNAL_PORTS.len()];
        let remote_ip = remote(usize::from(c) % REMOTES, false);
        let udp_port = UDP_REMOTE_PORTS[usize::from(c >> 2) % 2];
        let tcp_port = TCP_REMOTE_PORTS[usize::from(c >> 2) % 2];
        match kind {
            op::UDP_OUT | op::TCP_SYN | op::TCP_OUT_ACK => {
                let (proto, remote_port) = if kind == op::UDP_OUT {
                    (Proto::Udp, udp_port)
                } else {
                    (Proto::Tcp, tcp_port)
                };
                self.outbound(Outbound {
                    proto,
                    host: host_index,
                    internal_port,
                    remote: remote_ip,
                    remote_port,
                    creates: kind != op::TCP_OUT_ACK,
                })?;
            }
            op::UDP_IN | op::TCP_IN => {
                let proto = if kind == op::UDP_IN {
                    Proto::Udp
                } else {
                    Proto::Tcp
                };
                let flags = [SYN_ACK, ACK, RST_ACK][usize::from(c) % 3];
                let known: Vec<Flow> = self
                    .model
                    .flows
                    .iter()
                    .copied()
                    .filter(|flow| flow.proto == proto)
                    .collect();
                let mut inbound = if known.is_empty() {
                    Inbound {
                        proto,
                        remote: remote_ip,
                        remote_port: if proto == Proto::Udp {
                            udp_port
                        } else {
                            tcp_port
                        },
                        public_port: PORT_FIRST + u16::from(b) % 8,
                        flags,
                    }
                } else {
                    let flow = known[usize::from(a) % known.len()];
                    Inbound {
                        proto,
                        remote: flow.remote,
                        remote_port: flow.remote_port,
                        public_port: flow.public_port,
                        flags,
                    }
                };
                match b % 6 {
                    3 => inbound.remote_port = inbound.remote_port.wrapping_add(1),
                    4 => inbound.remote = remote(usize::from(c) + 1, false),
                    5 => inbound.public_port = PORT_FIRST + u16::from(c) % 8,
                    _ => {}
                }
                self.inbound(inbound)?;
            }
            op::DENY => {
                let (proto, port) = if a & 1 == 0 {
                    (Proto::Udp, UDP_DENIED_PORT)
                } else {
                    (Proto::Tcp, TCP_DENIED_PORT)
                };
                let id = self.id();
                let bytes = outbound_segment(
                    proto,
                    usize::from(b),
                    internal_port,
                    remote_ip,
                    port,
                    SYN,
                    id,
                )
                .build()?;
                self.push(LAN, bytes, id, Expect::Dropped)?;
            }
            op::CORRUPT => {
                let (proto, corruption) = match a % 3 {
                    0 => (Proto::Udp, Corruption::TransportChecksum),
                    1 => (Proto::Udp, Corruption::Ipv4HeaderChecksum),
                    _ => (Proto::Tcp, Corruption::TransportChecksum),
                };
                let port = if proto == Proto::Udp {
                    udp_port
                } else {
                    tcp_port
                };
                let id = self.id();
                let mut bytes = outbound_segment(
                    proto,
                    usize::from(b),
                    internal_port,
                    remote_ip,
                    port,
                    SYN,
                    id,
                )
                .build()?;
                corrupt(&mut bytes, corruption);
                self.push(LAN, bytes, id, Expect::Dropped)?;
            }
            op::ADVANCE => {
                self.flush(active)?;
                self.model.now += 1 + u64::from(u16::from_le_bytes([a, b])) % MAX_ADVANCE_MS;
            }
            op::BIG_JUMP => {
                self.flush(active)?;
                self.coverage.big_jumps += 1;
                self.model.now += BIG_JUMP_MS;
            }
            op::FLUSH => self.flush(active)?,
            op::PAIR_UDP | op::PAIR_TCP => {
                let (proto, remote_port) = if kind == op::PAIR_UDP {
                    (Proto::Udp, udp_port)
                } else {
                    (Proto::Tcp, tcp_port)
                };
                // The reply must reach the router in the same batch as the
                // packet that creates its state, so its public port has to
                // be known before that packet runs: an existing live mapping
                // of the internal endpoint (endpoint-independent mapping) or
                // the only port of a one-port range.
                if self.batch.len() + 2 > MAX_BATCH {
                    self.flush(active)?;
                }
                let predicted = self
                    .model
                    .live_endpoint_port(proto, host_index, internal_port)
                    .or((self.model.params.ports == 1).then_some(PORT_FIRST));
                let out = Outbound {
                    proto,
                    host: host_index,
                    internal_port,
                    remote: remote_ip,
                    remote_port,
                    creates: true,
                };
                // Counted as same-batch only when no earlier tick created
                // this exact flow.
                let fresh = !self.model.flows.iter().any(|flow| flow.same_tuple(&out));
                self.outbound(out)?;
                if let Some(public_port) = predicted {
                    self.inbound(Inbound {
                        proto,
                        remote: remote_ip,
                        remote_port,
                        public_port,
                        flags: SYN_ACK,
                    })?;
                    if let Some(last) = self.batch.last_mut() {
                        last.same_batch = fresh;
                    }
                }
            }
            _ => return Err(CaseFailure::new("unknown state op")),
        }
        if self.batch.len() >= MAX_BATCH {
            self.flush(active)?;
        }
        Ok(())
    }

    fn id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn outbound(&mut self, out: Outbound) -> Result<(), CaseFailure> {
        let id = self.id();
        let flags = if out.creates { SYN } else { ACK };
        let bytes = outbound_segment(
            out.proto,
            out.host,
            out.internal_port,
            out.remote,
            out.remote_port,
            flags,
            id,
        )
        .build()?;
        self.push(LAN, bytes, id, Expect::Out(out))
    }

    fn inbound(&mut self, inbound: Inbound) -> Result<(), CaseFailure> {
        let id = self.id();
        let bytes = Segment {
            proto: inbound.proto,
            eth_source: GATEWAY_MAC,
            eth_destination: WAN_MAC,
            source: inbound.remote,
            destination: PUBLIC,
            source_port: inbound.remote_port,
            destination_port: inbound.public_port,
            identification: id,
            ttl: 64,
            flags: inbound.flags,
        }
        .build()?;
        self.push(WAN, bytes, id, Expect::In(inbound))
    }

    fn push(
        &mut self,
        ingress: IfId,
        bytes: Vec<u8>,
        id: u16,
        expect: Expect,
    ) -> Result<(), CaseFailure> {
        self.io.inject(ingress, bytes);
        self.batch.push(Pending {
            id,
            expect,
            same_batch: false,
        });
        Ok(())
    }

    fn flush(&mut self, active: &mut ActivePublication<'_, SimIo>) -> Result<(), CaseFailure> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let batch = std::mem::take(&mut self.batch);
        self.ticks += 1;
        self.model.refresh_staleness();
        let stale_before = self.model.stale_possible;
        let before = Slots::capture(active);
        let report = run_tick(
            active,
            None,
            &mut self.io,
            MonotonicMillis(self.model.now),
            self.budgets,
            &mut self.observer,
        );
        let tick = self.ticks;
        match &report.rx {
            RxPhaseReport::Completed(rx) => {
                if rx.received != batch.len()
                    || rx.tx_requested + rx.dropped + rx.consumed != rx.received
                {
                    return Err(CaseFailure::new(format!(
                        "tick={tick} rx accounting received={} tx={} dropped={} consumed={} injected={}",
                        rx.received,
                        rx.tx_requested,
                        rx.dropped,
                        rx.consumed,
                        batch.len()
                    )));
                }
            }
            other => {
                return Err(CaseFailure::new(format!(
                    "tick={tick} rx phase did not complete: {other:?}"
                )))
            }
        }
        let mut forwarded: Vec<(u16, IfId, Vec<u8>)> = Vec::new();
        while let Some(frame) = self.io.pop_tx() {
            if frame.origin == FrameOrigin::Generated {
                continue;
            }
            let Some(id) = identification(&frame.bytes) else {
                return Err(CaseFailure::new(format!(
                    "tick={tick} forwarded a non-IPv4 frame"
                )));
            };
            if forwarded.iter().any(|(seen, _, _)| *seen == id) {
                return Err(CaseFailure::new(format!(
                    "tick={tick} id={id} forwarded twice"
                )));
            }
            forwarded.push((id, frame.egress, frame.bytes));
        }
        let mut recycled = Vec::new();
        while let Some(frame) = self.io.pop_recycled() {
            if let Some(id) = identification(&frame.bytes) {
                recycled.push((id, frame.cause));
            }
        }
        while self.io.pop_generated_recycled().is_some() {}
        for (id, _, _) in &forwarded {
            if !batch.iter().any(|pending| pending.id == *id) {
                return Err(CaseFailure::new(format!(
                    "tick={tick} id={id} forwarded but never injected"
                )));
            }
        }

        for pending in &batch {
            let tx = forwarded
                .iter()
                .find(|(id, _, _)| *id == pending.id)
                .map(|(_, egress, bytes)| (*egress, bytes.as_slice()));
            self.evaluate(pending, tx).map_err(|failure| {
                let cause = recycled
                    .iter()
                    .find(|(id, _)| *id == pending.id)
                    .map(|(_, cause)| *cause);
                CaseFailure::new(format!(
                    "tick={tick} now={} id={} {} recycle={cause:?}",
                    self.model.now, pending.id, failure.detail
                ))
            })?;
        }

        let after = Slots::capture(active);
        if !stale_before {
            if forwarded.is_empty() {
                if before != after {
                    return Err(CaseFailure::new(format!(
                        "tick={tick} forwarded nothing but NAT/firewall slots changed"
                    )));
                }
                self.coverage.unchanged_ticks += 1;
            }
            for (label, old, new) in [
                ("udp", before.udp_identities(), after.udp_identities()),
                ("tcp", before.tcp_identities(), after.tcp_identities()),
            ] {
                if let Some(lost) = old.iter().find(|identity| !new.contains(identity)) {
                    return Err(CaseFailure::new(format!(
                        "tick={tick} live {label} mapping evicted: {lost:?}"
                    )));
                }
            }
            let (old, new) = (before.counts(), after.counts());
            if old.iter().zip(new).any(|(old, new)| new < *old) {
                return Err(CaseFailure::new(format!(
                    "tick={tick} live peer/session/firewall state evicted: {old:?} -> {new:?}"
                )));
            }
        }
        // Every model-live flow must still own its mapping.
        let (udp, tcp) = (after.udp_identities(), after.tcp_identities());
        for flow in &self.model.flows {
            if flow.liveness(self.model.now) != Liveness::Live {
                continue;
            }
            let identity = (host(flow.host), flow.internal_port, flow.public_port);
            let owned = match flow.proto {
                Proto::Udp => udp.contains(&identity),
                Proto::Tcp => tcp.contains(&identity),
            };
            if !owned {
                return Err(CaseFailure::new(format!(
                    "tick={tick} live flow lost its mapping: {flow:?}"
                )));
            }
        }
        Ok(())
    }

    fn evaluate(
        &mut self,
        pending: &Pending,
        tx: Option<(IfId, &[u8])>,
    ) -> Result<(), CaseFailure> {
        let now = self.model.now;
        match pending.expect {
            Expect::Dropped => {
                if tx.is_some() {
                    return Err(CaseFailure::new("denied or corrupted packet was forwarded"));
                }
                self.coverage.filtered += 1;
            }
            Expect::Out(out) => {
                let existing = self
                    .model
                    .flows
                    .iter()
                    .position(|flow| flow.same_tuple(&out));
                let existing_live = existing
                    .is_some_and(|index| self.model.flows[index].liveness(now) == Liveness::Live);
                let existing_dead_or_none = existing
                    .is_none_or(|index| self.model.flows[index].liveness(now) == Liveness::Dead);
                let Some((egress, bytes)) = tx else {
                    if existing_live {
                        return Err(CaseFailure::new(format!(
                            "outbound on a live flow was dropped: {out:?}"
                        )));
                    }
                    // Expired state is reclaimed only by bounded probe-path
                    // cleanup, so it may still occupy capacity; a fresh flow
                    // is owed only while nothing can have expired.
                    if out.creates
                        && !self.model.stale_possible
                        && self.model.flows.len() < self.model.firewall_usable
                        && !self.model.flows.iter().any(|flow| flow.proto == out.proto)
                    {
                        return Err(CaseFailure::new(format!(
                            "fresh flow without same-protocol state and with firewall room was dropped: {out:?}"
                        )));
                    }
                    self.coverage.outbound_refused += 1;
                    return Ok(());
                };
                if !out.creates && existing_dead_or_none {
                    return Err(CaseFailure::new(format!(
                        "non-SYN TCP without a session was forwarded: {out:?}"
                    )));
                }
                if egress != WAN {
                    return Err(CaseFailure::new(format!("outbound egress {egress:?}")));
                }
                let public_port = source_port(bytes)
                    .ok_or_else(|| CaseFailure::new("outbound frame too short"))?;
                if !(PORT_FIRST..=self.model.params.port_last()).contains(&public_port) {
                    return Err(CaseFailure::new(format!(
                        "public port {public_port} outside the configured range"
                    )));
                }
                let flags = if out.creates { SYN } else { ACK };
                let expected = Segment {
                    proto: out.proto,
                    eth_source: WAN_MAC,
                    eth_destination: GATEWAY_MAC,
                    source: PUBLIC,
                    destination: out.remote,
                    source_port: public_port,
                    destination_port: out.remote_port,
                    identification: pending.id,
                    ttl: 63,
                    flags,
                }
                .build()?;
                if bytes != expected.as_slice() {
                    return Err(CaseFailure::new(format!(
                        "outbound translation is not byte-exact: {out:?}"
                    )));
                }
                if let Some(mapped) =
                    self.model
                        .live_endpoint_port(out.proto, out.host, out.internal_port)
                {
                    if mapped != public_port {
                        return Err(CaseFailure::new(format!(
                            "endpoint-independent mapping changed {mapped} -> {public_port}"
                        )));
                    }
                }
                if let Some(other) = self.model.flows.iter().find(|flow| {
                    flow.proto == out.proto
                        && flow.public_port == public_port
                        && !flow.same_endpoint(out.proto, out.host, out.internal_port)
                        && flow.liveness(now) == Liveness::Live
                }) {
                    return Err(CaseFailure::new(format!(
                        "public port {public_port} shared with live endpoint {other:?}"
                    )));
                }
                self.coverage.translated_out += 1;
                match existing {
                    Some(index) => {
                        let flow = &mut self.model.flows[index];
                        if flow.liveness(now) == Liveness::Live && flow.public_port != public_port {
                            return Err(CaseFailure::new("live flow changed its public port"));
                        }
                        flow.public_port = public_port;
                        flow.last_out = now;
                        flow.last_any = now;
                    }
                    None => self.model.flows.push(Flow {
                        proto: out.proto,
                        host: out.host,
                        internal_port: out.internal_port,
                        remote: out.remote,
                        remote_port: out.remote_port,
                        public_port,
                        last_out: now,
                        last_any: now,
                    }),
                }
            }
            Expect::In(inbound) => {
                let matches: Vec<usize> = self
                    .model
                    .flows
                    .iter()
                    .enumerate()
                    .filter(|(_, flow)| {
                        flow.proto == inbound.proto
                            && flow.remote == inbound.remote
                            && flow.remote_port == inbound.remote_port
                            && flow.public_port == inbound.public_port
                    })
                    .map(|(index, _)| index)
                    .collect();
                let live: Vec<usize> = matches
                    .iter()
                    .copied()
                    .filter(|index| self.model.flows[*index].liveness(now) == Liveness::Live)
                    .collect();
                let possible: Vec<usize> = matches
                    .iter()
                    .copied()
                    .filter(|index| self.model.flows[*index].liveness(now) != Liveness::Dead)
                    .collect();
                if live.len() > 1 {
                    return Err(CaseFailure::new("two live flows share one reply tuple"));
                }
                let Some((egress, bytes)) = tx else {
                    if !live.is_empty() {
                        return Err(CaseFailure::new(format!(
                            "reply to a live flow was dropped: {inbound:?}"
                        )));
                    }
                    self.coverage.replies_refused += 1;
                    return Ok(());
                };
                if possible.is_empty() {
                    return Err(CaseFailure::new(format!(
                        "reply without exact live state was forwarded: {inbound:?}"
                    )));
                }
                if egress != LAN {
                    return Err(CaseFailure::new(format!("inbound egress {egress:?}")));
                }
                let candidates = if live.is_empty() { possible } else { live };
                let mut matched = None;
                for index in candidates {
                    let flow = self.model.flows[index];
                    let expected = Segment {
                        proto: inbound.proto,
                        eth_source: LAN_MAC,
                        eth_destination: host_mac(flow.host),
                        source: inbound.remote,
                        destination: host(flow.host),
                        source_port: inbound.remote_port,
                        destination_port: flow.internal_port,
                        identification: pending.id,
                        ttl: 63,
                        flags: inbound.flags,
                    }
                    .build()?;
                    if bytes == expected.as_slice() {
                        matched = Some(index);
                        break;
                    }
                }
                let Some(index) = matched else {
                    return Err(CaseFailure::new(format!(
                        "reply de-translation is not the inverse of the translation: {inbound:?}"
                    )));
                };
                self.model.flows[index].last_any = now;
                self.coverage.translated_in += 1;
                if pending.same_batch {
                    self.coverage.same_batch_replies += 1;
                }
            }
        }
        Ok(())
    }
}

fn outbound_segment(
    proto: Proto,
    host_index: usize,
    internal_port: u16,
    remote: Ipv4Address,
    remote_port: u16,
    flags: ruster_sim_scenario::TcpFlags,
    id: u16,
) -> Segment {
    Segment {
        proto,
        eth_source: host_mac(host_index),
        eth_destination: LAN_MAC,
        source: host(host_index),
        destination: remote,
        source_port: internal_port,
        destination_port: remote_port,
        identification: id,
        ttl: 64,
        flags,
    }
}

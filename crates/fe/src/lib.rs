#![forbid(unsafe_code)]
//! The forwarding element (FE): it holds the tables and forwards packets by them.
//!
//! See `docs/design/fe-internals.md`. This is the skeleton: one worker, IPv4 only,
//! one VRF (`default`), one next hop per route. The tables arrive over the table
//! server ([`ruster_proto::session`]); every accepted change rebuilds the core's
//! [`ValidatedForwardingOwner`] and the worker uses the new one from its next batch.
//!
//! ARP goes to the neighbor process: core hands each ARP packet over
//! ([`ForwardingSnapshot::with_arp_to_control`](ruster_core::ForwardingSnapshot::with_arp_to_control)) and the FE sends it on the punt
//! socket. A packet whose next hop is not in the neighbor table is dropped and turned
//! into a resolve request notification, at most one per next hop per second.
//! Frames the neighbor process sends back go out through the backend's generated
//! frames.
//!
//! # Standards
//!
//! - Forwarding decisions are `ruster-core`'s (RFC 1812 sections 5.2.2 and 5.3.1:
//!   header checks and the TTL).
//! - RFC 1122 section 2.3.2.1: at most one resolve request per second per next hop.
//!
//! Deviations: ARP is not answered in the FE; every ARP packet goes to the neighbor
//! process.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::PathBuf;

use ruster_core::{
    execute_one_icmpv4_error, forward_batch_with_control, ArpOpcode, ControlQueue,
    GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink, GeneratedPacketBatch, GeneratedPacketIo,
    Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId,
    MonotonicMillis, PacketIo, TraceEvent, TraceSink,
};
use ruster_proto::cbor::Encoder;
use ruster_proto::punt::{self, Direction, Punt};
use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::ResolveRequest;
use ruster_proto::task::{Progress, Task};

mod build;

/// The tables each kind of writer may change (one writer per table).
pub mod writers {
    use ruster_proto::sid;

    pub const CONFIG: &[u64] = &[sid::INTERFACE, sid::ADDRESS];
    pub const ROUTE: &[u64] = &[sid::ROUTE];
    pub const NEIGHBOR: &[u64] = &[sid::NEIGHBOR];
    pub const READ_ONLY: &[u64] = &[];
}

/// The only VRF of the skeleton.
pub const DEFAULT_VRF: &str = ruster_proto::table::DEFAULT_VRF;

/// Packets taken from the backend in one step.
const RX_BUDGET: usize = 64;
/// ARP packets and resolve requests remembered per batch; more are dropped and counted.
const EVENTS_PER_BATCH: usize = 64;
/// Frames read from the punt socket per step.
const INJECT_PER_STEP: usize = 64;
/// One resolve request per next hop per this many milliseconds.
const RESOLVE_INTERVAL_MS: u64 = 1_000;
/// Next hops remembered for the rate limit. Older ones are forgotten first; when all
/// are recent, further requests wait (and are counted).
const RESOLVE_REMEMBERED: usize = 1_024;
/// The largest frame accepted from the punt socket (Ethernet with a 1500-byte payload
/// and a VLAN tag, plus the punt header).
const PUNT_MAX: usize = 1_522 + 300;
const ETHERNET_HEADER: usize = 14;
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ETHERTYPE_IPV6: [u8; 2] = [0x86, 0xdd];

/// Counters for things the FE dropped on its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeCounters {
    pub batches: u64,
    pub forwarded: u64,
    pub dropped: u64,
    pub arp_to_control: u64,
    pub arp_to_control_dropped: u64,
    pub resolve_requests: u64,
    pub resolve_requests_dropped: u64,
    pub injected: u64,
    pub inject_dropped: u64,
    /// ICMP errors generated (rate limited per egress interface).
    pub icmp_errors_sent: u64,
}

pub struct Fe<B> {
    io: B,
    builder: Builder,
    /// Core's tables per VRF, the default VRF first.
    vrfs: Vec<build::Vrf>,
    /// For each port, the index in `vrfs` of its VRF.
    by_ingress: Vec<u16>,
    /// The interfaces enabled in the current tables.
    active: Vec<IfId>,
    server: Server,
    punt: Option<UnixDatagram>,
    /// Where ARP goes when the punt socket is not connected to one peer.
    punt_peer: Option<PathBuf>,
    last_resolve: BTreeMap<(IfId, IpAddr), u64>,
    /// Neighbor Discovery frames core copied out of the last batch.
    control: ControlQueue,
    /// ICMPv4 errors core queued in the last batch, and their rate limits.
    icmpv4_errors: Icmpv4ErrorRuntime<'static>,
    counters: FeCounters,
}

impl<B> std::fmt::Debug for Fe<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fe")
            .field("ports", &self.builder.ports)
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl<B> Fe<B>
where
    B: PacketIo + GeneratedPacketIo,
{
    /// `ports` names the backend's ports; port `i` is `IfId(i)`. The tables start empty,
    /// so nothing is forwarded until a writer adds interfaces and routes.
    pub fn new(io: B, ports: Vec<String>) -> Self {
        let builder = Builder { ports, built: None };
        let built = build::build(&builder.ports, &Store::default()).expect("empty tables build");
        Self {
            io,
            builder,
            vrfs: built.vrfs,
            by_ingress: built.by_ingress,
            active: built.active,
            server: Server::new(),
            punt: None,
            punt_peer: None,
            last_resolve: BTreeMap::new(),
            control: ControlQueue::new(EVENTS_PER_BATCH).with_icmpv6_errors(EVENTS_PER_BATCH),
            icmpv4_errors: icmpv4_error_runtime(),
            counters: FeCounters::default(),
        }
    }

    /// Accepts a table connection that may write `writes` (see [`writers`]).
    pub fn attach(&mut self, stream: UnixStream, writes: &[u64]) -> io::Result<()> {
        self.server.attach(stream, writes)
    }

    /// Uses `socket` to pass ARP to the neighbor process and to take frames back.
    /// It replaces an earlier one, for when the neighbor process restarts.
    pub fn attach_punt(&mut self, socket: UnixDatagram) -> io::Result<()> {
        socket.set_nonblocking(true)?;
        self.punt = Some(socket);
        self.punt_peer = None;
        Ok(())
    }

    /// Like [`Fe::attach_punt`] for a socket bound at a fixed path that is not
    /// connected: ARP is sent to the socket at `peer`, and frames are taken from
    /// whoever sends them. A neighbor process that restarts binds the same path again.
    pub fn attach_punt_to(&mut self, socket: UnixDatagram, peer: PathBuf) -> io::Result<()> {
        socket.set_nonblocking(true)?;
        self.punt = Some(socket);
        self.punt_peer = Some(peer);
        Ok(())
    }

    pub fn io_mut(&mut self) -> &mut B {
        &mut self.io
    }

    pub fn counters(&self) -> FeCounters {
        self.counters
    }

    /// The current tables.
    pub fn store(&self) -> &Store {
        self.server.store()
    }

    fn worker(&mut self, now_ms: u64) -> bool {
        let mut trace = FeTrace::default();
        // One snapshot per VRF; each packet uses its ingress interface's.
        let snapshots: Vec<_> = self
            .vrfs
            .iter()
            .map(|vrf| {
                vrf.owner
                    .snapshot()
                    .with_arp_to_control(true)
                    .with_ipv6(&vrf.ipv6)
            })
            .collect();
        let snapshot = snapshots[0].with_vrfs(&snapshots, &self.by_ingress);
        let Ok(batch) = self.io.receive(RX_BUDGET) else {
            return false;
        };
        self.control.clear();
        let now = MonotonicMillis(now_ms);
        self.control.set_clock(now);
        let report = forward_batch_with_control(
            batch,
            &snapshot,
            &mut self.control,
            Some((&mut self.icmpv4_errors, now)),
            &mut trace,
        );
        if report.received == 0 {
            return false;
        }
        self.counters.batches += 1;
        self.counters.forwarded += report.tx_requested as u64;
        self.counters.dropped += report.dropped as u64;
        self.counters.arp_to_control_dropped += trace.overflow;

        while let Ok(Some(_)) =
            execute_one_icmpv4_error(&mut self.io, &mut self.icmpv4_errors, now, &mut NoTrace)
        {
            self.counters.icmp_errors_sent += 1;
        }
        for arp in &trace.arp {
            self.punt_arp(arp);
        }
        for index in 0..self.control.errors().len() {
            let error = &self.control.errors()[index];
            let (egress, bytes) = (error.ingress, error.bytes().to_vec());
            if self.send_generated(egress, &bytes) {
                self.counters.icmp_errors_sent += 1;
            }
        }
        for index in 0..self.control.frames().len() {
            let frame = &self.control.frames()[index];
            let (ingress, bytes) = (frame.ingress, frame.bytes().to_vec());
            self.punt_frame(ingress, punt::reason::ND, &bytes);
        }
        for &(egress, target) in &trace.misses {
            self.resolve_request(egress, target, now_ms);
        }
        true
    }

    fn punt_arp(&mut self, arp: &ArpEvent) {
        let body = arp.body();
        self.punt_frame(arp.ingress, punt::reason::ARP, &body);
    }

    /// Sends `frame` to the neighbor process; counted with the ARP counters.
    fn punt_frame(&mut self, ingress: IfId, reason: u16, frame: &[u8]) {
        let Some(name) = self.builder.ports.get(usize::from(ingress.0)) else {
            return;
        };
        let Some(socket) = &self.punt else {
            self.counters.arp_to_control_dropped += 1;
            return;
        };
        let mut message = Vec::with_capacity(frame.len() + 64);
        Punt {
            direction: Direction::ToControl,
            reason,
            interface: name,
            frame,
        }
        .encode(&mut message)
        .expect("port names are short and non-empty");
        let sent = match &self.punt_peer {
            Some(peer) => socket.send_to(&message, peer),
            None => socket.send(&message),
        };
        match sent {
            Ok(_) => self.counters.arp_to_control += 1,
            Err(_) => self.counters.arp_to_control_dropped += 1,
        }
    }

    fn resolve_request(&mut self, egress: IfId, address: IpAddr, now_ms: u64) {
        let last = self.last_resolve.get(&(egress, address)).copied();
        if last.is_some_and(|at| now_ms.saturating_sub(at) < RESOLVE_INTERVAL_MS) {
            return;
        }
        let Some(name) = self.builder.ports.get(usize::from(egress.0)) else {
            return;
        };
        if self.last_resolve.len() >= RESOLVE_REMEMBERED {
            self.last_resolve
                .retain(|_, at| now_ms.saturating_sub(*at) < RESOLVE_INTERVAL_MS);
            if self.last_resolve.len() >= RESOLVE_REMEMBERED {
                self.counters.resolve_requests_dropped += 1;
                return;
            }
        }
        self.last_resolve.insert((egress, address), now_ms);
        let mut payload = Vec::new();
        ResolveRequest {
            interface: name.clone(),
            address,
        }
        .encode(&mut Encoder::new(&mut payload));
        self.server.notify(&payload);
        self.counters.resolve_requests += 1;
    }

    /// Sends the frames the neighbor process gave back.
    fn inject(&mut self) -> bool {
        let Some(socket) = &self.punt else {
            return false;
        };
        // One byte more than accepted, to see a datagram that was cut short.
        let mut buf = vec![0_u8; PUNT_MAX + 1];
        let mut frames = Vec::new();
        for _ in 0..INJECT_PER_STEP {
            match socket.recv_from(&mut buf) {
                // With a fixed peer path, only frames from that path are taken.
                Ok((_, from))
                    if self
                        .punt_peer
                        .as_deref()
                        .is_some_and(|peer| from.as_pathname() != Some(peer)) =>
                {
                    self.counters.inject_dropped += 1;
                }
                Ok((n, _)) if n <= PUNT_MAX => frames.push(buf[..n].to_vec()),
                Ok(_) => self.counters.inject_dropped += 1,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        let busy = !frames.is_empty();
        for message in &frames {
            let Ok(punt) = Punt::decode(message) else {
                self.counters.inject_dropped += 1;
                continue;
            };
            // Only out of an interface the current tables have enabled.
            let egress = self
                .builder
                .port(punt.interface)
                .filter(|id| self.active.contains(id));
            match (punt.direction, punt.reason, egress) {
                (Direction::FromControl, reason, Some(egress))
                    if punt.frame.len() >= ETHERNET_HEADER
                        && ((reason == punt::reason::ARP
                            && punt.frame[12..14] == ETHERTYPE_ARP)
                            || (reason == punt::reason::ND
                                && punt.frame[12..14] == ETHERTYPE_IPV6)) =>
                {
                    if self.send_generated(egress, punt.frame) {
                        self.counters.injected += 1;
                    } else {
                        self.counters.inject_dropped += 1;
                    }
                }
                _ => self.counters.inject_dropped += 1,
            }
        }
        busy
    }

    fn send_generated(&mut self, egress: IfId, frame: &[u8]) -> bool {
        let mut batch = self.io.begin_generated(egress);
        let sent = match batch.allocate(frame.len()) {
            Ok(mut lease) => {
                lease.bytes_mut().copy_from_slice(frame);
                lease.commit();
                true
            }
            Err(_) => false,
        };
        let completion = batch.finish();
        sent && completion.error.is_none()
    }
}

impl<B> Task for Fe<B>
where
    B: PacketIo + GeneratedPacketIo,
{
    fn step(&mut self, now_ms: u64) -> Progress {
        let control = self.server.step(&mut self.builder);
        if let Some(built) = self.builder.built.take() {
            self.vrfs = built.vrfs;
            self.by_ingress = built.by_ingress;
            self.active = built.active;
        }
        let worked = self.worker(now_ms);
        let injected = self.inject();
        // Notifications queued by the worker go out now.
        let flushed = self.server.step(&mut self.builder);
        control.and(flushed).and(Progress::busy(worked || injected))
    }
}

/// ICMPv4 error slots: limiter states and queued errors, enough for one batch.
const ICMPV4_ERROR_SLOTS: usize = 64;

/// The ICMPv4 error runtime with the default policy (RFC 1812 section 4.3.2.8 rate
/// limits). Its slots are allocated once for the life of the process.
fn icmpv4_error_runtime() -> Icmpv4ErrorRuntime<'static> {
    let states =
        Box::leak(vec![Icmpv4ErrorStateSlot::EMPTY; ICMPV4_ERROR_SLOTS].into_boxed_slice());
    let actions =
        Box::leak(vec![Icmpv4ErrorActionSlot::EMPTY; ICMPV4_ERROR_SLOTS].into_boxed_slice());
    Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), states, actions)
}

/// Generated ICMPv4 frames are counted, not traced.
struct NoTrace;

impl GeneratedIcmpv4TraceSink for NoTrace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

/// Turns the tables into core's tables.
struct Builder {
    ports: Vec<String>,
    /// The tables built for the last accepted store, until the FE takes them.
    built: Option<build::Built>,
}

impl Builder {
    fn port(&self, name: &str) -> Option<IfId> {
        let index = self.ports.iter().position(|port| port == name)?;
        u16::try_from(index).ok().map(IfId)
    }
}

impl Hook for Builder {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        self.built = Some(build::build(&self.ports, next)?);
        Ok(())
    }

    fn committed(&mut self, _store: &Store) {}
}

#[derive(Clone, Copy)]
struct ArpEvent {
    ingress: IfId,
    opcode: ArpOpcode,
    sender_hardware: [u8; 6],
    sender_protocol: [u8; 4],
    target_protocol: [u8; 4],
}

impl ArpEvent {
    /// The 28-byte Ethernet/IPv4 ARP body. The target hardware address is zero.
    fn body(&self) -> [u8; 28] {
        let mut body = [0_u8; 28];
        body[0..2].copy_from_slice(&1_u16.to_be_bytes());
        body[2..4].copy_from_slice(&0x0800_u16.to_be_bytes());
        body[4] = 6;
        body[5] = 4;
        let opcode: u16 = match self.opcode {
            ArpOpcode::Request => 1,
            ArpOpcode::Reply => 2,
        };
        body[6..8].copy_from_slice(&opcode.to_be_bytes());
        body[8..14].copy_from_slice(&self.sender_hardware);
        body[14..18].copy_from_slice(&self.sender_protocol);
        body[24..28].copy_from_slice(&self.target_protocol);
        body
    }
}

/// Collects what the FE acts on after a batch: ARP for the control side and next hops
/// that missed the neighbor table.
#[derive(Default)]
struct FeTrace {
    arp: Vec<ArpEvent>,
    misses: Vec<(IfId, IpAddr)>,
    overflow: u64,
}

impl TraceSink for FeTrace {
    fn record(&mut self, event: TraceEvent) {
        match event {
            TraceEvent::ArpToControl {
                ingress,
                opcode,
                sender_hardware,
                sender_protocol,
                target_protocol,
            } => {
                if self.arp.len() < EVENTS_PER_BATCH {
                    self.arp.push(ArpEvent {
                        ingress,
                        opcode,
                        sender_hardware: sender_hardware.0,
                        sender_protocol: sender_protocol.octets(),
                        target_protocol: target_protocol.octets(),
                    });
                } else {
                    self.overflow += 1;
                }
            }
            TraceEvent::NeighborMissing { egress, target } => {
                self.miss(egress, IpAddr::V4(target.octets().into()));
            }
            TraceEvent::Ipv6NeighborMissing { egress, target } => {
                self.miss(egress, IpAddr::V6(target.into()));
            }
            _ => {}
        }
    }
}

impl FeTrace {
    fn miss(&mut self, egress: IfId, target: IpAddr) {
        let miss = (egress, target);
        if self.misses.len() < EVENTS_PER_BATCH && !self.misses.contains(&miss) {
            self.misses.push(miss);
        }
    }
}

/// The SIDs a neighbor process writes, for callers that build their own writer sets.
pub const NEIGHBOR_TABLE: u64 = sid::NEIGHBOR;

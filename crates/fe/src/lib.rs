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
    execute_one_icmpv4_error, execute_one_ipv4_fragmentation, forward_batch_with_control,
    ArpOpcode, ControlKind, ControlQueue, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
    GeneratedPacketBatch, GeneratedPacketIo, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, MonotonicMillis, PacketIo, Services,
    TraceEvent, TraceSink, VlanBinding,
};
use ruster_proto::cbor::Encoder;
use ruster_proto::punt::{self, Direction, Punt};
use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::ResolveRequest;
use ruster_proto::task::{Progress, Task};

mod build;
mod firewall;
mod fragments;
mod kernel;
mod local;
mod nat;
mod reassembly;
mod wireguard;

pub use local::LocalPipe;

/// The tables each kind of writer may change (one writer per table).
pub mod writers {
    use ruster_proto::sid;

    pub const CONFIG: &[u64] = &[
        sid::INTERFACE,
        sid::ADDRESS,
        sid::NAT,
        sid::FIREWALL_RULE,
        sid::WIREGUARD,
        sid::WIREGUARD_PEER,
        sid::WIREGUARD_SESSION,
    ];
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
/// Neighbors marked used at most between two reads of the marks.
const USED_MAX: usize = 8_192;
/// Frames read from the punt socket per step.
const INJECT_PER_STEP: usize = 64;
/// One resolve request per next hop per this many milliseconds.
const RESOLVE_INTERVAL_MS: u64 = 1_000;
/// A peer's key exchange is asked for again after this long (WireGuard's handshake
/// retry is 5 seconds, whitepaper section 6.4).
const KEY_REQUEST_INTERVAL_MS: u64 = 5_000;
const KEY_REQUESTS_REMEMBERED: usize = 256;
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
    /// Key exchange notifications sent for WireGuard peers that had a packet and no
    /// session.
    pub key_exchange_requests: u64,
    pub injected: u64,
    pub inject_dropped: u64,
    /// ICMP errors generated (rate limited per egress interface).
    pub icmp_errors_sent: u64,
    /// Packets addressed to the router written to the kernel, and those dropped
    /// (rate limit, no pipe for the VRF, or the pipe full).
    pub to_kernel: u64,
    pub to_kernel_dropped: u64,
    /// Packets from the kernel sent out, and those dropped (no route, no neighbor
    /// yet, or no room).
    pub from_kernel: u64,
    pub from_kernel_dropped: u64,
    /// Tunnels' IPv6 packets put back together from their fragments.
    pub tunnel_reassembled: u64,
    /// Fragments sent for datagrams longer than the egress MTU, and datagrams whose
    /// fragments could not be sent.
    pub fragments_sent: u64,
    pub fragmentation_dropped: u64,
    /// WireGuard packets sealed and sent, and sealed ones that could not be sent.
    pub wireguard_sent: u64,
    pub wireguard_send_dropped: u64,
}

pub struct Fe<B> {
    io: B,
    builder: Builder,
    /// Core's tables per VRF, the default VRF first.
    vrfs: Vec<build::Vrf>,
    /// For each port, the index in `vrfs` of its VRF.
    by_ingress: Vec<u16>,
    /// The VRF names, in the order of `vrfs`.
    names: Vec<String>,
    /// Every interface's name by id: the ports, then VLAN sub-interfaces.
    interface_names: Vec<String>,
    vlans: Vec<VlanBinding>,
    tunnels: Vec<ruster_core::Ipv4InIpv6Tunnel>,
    pppoe: Vec<ruster_core::PppoeSession>,
    wireguard: wireguard::Wireguard,
    /// Each VRF's kernel interface, in the order of `vrfs`.
    kernel: Vec<IfId>,
    /// Each VRF's pipe to the kernel, for traffic addressed to the router.
    local: BTreeMap<String, Box<dyn LocalPipe>>,
    limiter: local::Limiter,
    /// The interfaces enabled in the current tables.
    active: Vec<IfId>,
    server: Server,
    punt: Option<UnixDatagram>,
    /// Where ARP goes when the punt socket is not connected to one peer.
    punt_peer: Option<PathBuf>,
    last_resolve: BTreeMap<(IfId, IpAddr), u64>,
    last_key_request: BTreeMap<(String, String), u64>,
    /// Neighbor Discovery frames core copied out of the last batch.
    control: ControlQueue,
    /// ICMPv4 errors core queued in the last batch, and their rate limits.
    icmpv4_errors: Icmpv4ErrorRuntime<'static>,
    /// The default VRF's forward firewall, once a rule has arrived.
    firewall: Option<firewall::Firewall>,
    /// The default VRF's NAPT, once the tables have had one.
    nat: Option<nat::Nat>,
    fragmentation: ruster_core::Ipv4FragmentationRuntime<'static>,
    /// Tunnels' fragmented IPv6 packets being put back together, and those put
    /// together, for the next batch.
    reassembly: reassembly::Reassembly,
    reassembled: Vec<kernel::Frame>,
    /// The neighbors packets went to since the neighbor process last read them.
    used: std::collections::HashSet<(u16, IpAddr)>,
    fragment_tracking: ruster_core::Ipv4FragmentTracker<'static>,
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
        let mut builder = Builder {
            ports,
            built: None,
            generation: 0,
        };
        builder
            .check(&Store::default())
            .expect("empty tables build");
        let (built, _, _) = builder.built.take().expect("built");
        Self {
            io,
            builder,
            vrfs: built.vrfs,
            by_ingress: built.by_ingress,
            names: built.names,
            interface_names: built.interface_names,
            vlans: built.vlans,
            tunnels: built.tunnels,
            pppoe: built.pppoe,
            wireguard: {
                let mut wireguard = wireguard::Wireguard::new();
                wireguard.publish(built.wireguard);
                wireguard
            },
            kernel: built.kernel,
            local: BTreeMap::new(),
            limiter: local::Limiter::default(),
            active: built.active,
            server: Server::new(),
            punt: None,
            punt_peer: None,
            last_resolve: BTreeMap::new(),
            last_key_request: BTreeMap::new(),
            control: ControlQueue::new(EVENTS_PER_BATCH).with_icmpv6_errors(EVENTS_PER_BATCH),
            icmpv4_errors: icmpv4_error_runtime(),
            firewall: None,
            nat: None,
            fragmentation: fragments::fragmentation(),
            reassembly: reassembly::Reassembly::default(),
            reassembled: Vec::new(),
            used: std::collections::HashSet::new(),
            fragment_tracking: fragments::tracker(),
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

    /// Uses `pipe` to hand the traffic addressed to the router in `vrf` to the kernel,
    /// and to send the kernel's packets out. Without a pipe, core answers Echo
    /// Requests itself and drops the rest.
    pub fn attach_local(&mut self, vrf: &str, pipe: Box<dyn LocalPipe>) {
        self.local.insert(vrf.to_owned(), pipe);
    }

    /// The VRFs of the current tables, the default VRF first.
    pub fn vrfs(&self) -> &[String] {
        &self.names
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
        // Core's views of the WireGuard interfaces: made for each batch, and only
        // when there is one.
        let wireguard_on = !self.wireguard.is_empty();
        let wg_peers = wireguard::peer_configs(&self.wireguard.config);
        let wg_views = wireguard::interfaces(&self.wireguard.config, &wg_peers);
        // The kernel's packets join the ports' in one batch, after them.
        let mut kernel_frames = self.read_kernel();
        kernel_frames.append(&mut self.reassembled);
        // One snapshot per VRF; each packet uses its ingress interface's.
        let snapshots: Vec<_> = self
            .vrfs
            .iter()
            .zip(&self.names)
            .map(|(vrf, name)| {
                vrf.owner
                    .snapshot()
                    .with_arp_to_control(true)
                    .with_ipv6(&vrf.ipv6)
                    .with_local_to_control(self.local.contains_key(name))
                    .with_kernel_ingress(&self.kernel)
                    .with_vlans(&self.vlans)
                    .with_tunnels(&self.tunnels)
                    .with_pppoe(&self.pppoe)
                    .with_wireguard(&wg_views)
            })
            .collect();
        let mut firewall = self.firewall.as_mut().and_then(firewall::Firewall::service);
        // IPv6 goes through the firewall too; should its runtime be missing, IPv6 is
        // not forwarded through the default VRF rather than forwarded unchecked.
        let snapshot = snapshots[0]
            .with_now(MonotonicMillis(now_ms))
            .with_vrfs(&snapshots, &self.by_ingress)
            .with_vlans(&self.vlans)
            .with_tunnels(&self.tunnels)
            .with_pppoe(&self.pppoe)
            .with_wireguard(&wg_views)
            .with_kernel_ingress(&self.kernel)
            .with_ipv6_forwarding_blocked(firewall.is_some());
        let Ok(ports) = self.io.receive(RX_BUDGET) else {
            self.counters.from_kernel_dropped += kernel_frames.len() as u64;
            return false;
        };
        let mut from_kernel = kernel::Outcome::default();
        let batch = kernel::Joined {
            ports,
            kernel_ids: &self.kernel,
            kernel: kernel_frames.into_iter(),
            outcome: &mut from_kernel,
            kernel_done: 0,
        };
        self.control.clear();
        let now = MonotonicMillis(now_ms);
        self.control.set_clock(now);
        let mut services = Services {
            icmpv4_errors: Some(&mut self.icmpv4_errors),
            firewall: firewall
                .as_mut()
                .map(|(config, runtime)| (&*config, &mut **runtime)),
            fragmentation: Some(&mut self.fragmentation),
            fragment_tracking: Some(&mut self.fragment_tracking),
            wireguard: wireguard_on.then_some(&mut self.wireguard.states[..]),
            wireguard_send: wireguard_on.then_some(&mut self.wireguard.send),
            ..Services::default()
        };
        if let Some(nat) = self.nat.as_mut() {
            nat.services(&mut services);
        }
        let report =
            forward_batch_with_control(batch, &snapshot, &mut self.control, services, &mut trace);
        if report.received == 0 {
            return false;
        }
        self.counters.batches += 1;
        self.counters.forwarded += report.tx_requested as u64;
        self.counters.dropped += report.dropped as u64;
        self.counters.arp_to_control_dropped += trace.overflow;
        self.counters.from_kernel_dropped += from_kernel.dropped;
        for (egress, frame) in from_kernel.to_kernel {
            let packet = frame.get(ETHERNET_HEADER..).unwrap_or_default();
            let admitted = self.limiter.take(local::class(packet), now_ms);
            if admitted && self.write_kernel(egress, &frame) {
                self.counters.to_kernel += 1;
            } else {
                self.counters.to_kernel_dropped += 1;
            }
        }
        for (egress, frame) in from_kernel.sent {
            let sent = if self.kernel.contains(&egress) {
                self.write_kernel(egress, frame.bytes())
            } else {
                self.send_port(egress, None, frame.bytes())
            };
            if sent {
                self.counters.from_kernel += 1;
            } else {
                self.counters.from_kernel_dropped += 1;
            }
        }

        // Until one cannot be built or allocated (it stays queued for the next batch).
        // Those for an interface that is not a port (the kernel's, a VLAN
        // sub-interface, a PPPoE session, a tunnel) are caught and sent after.
        let ports = self.builder.ports.len();
        let mut caught = Vec::new();
        while let Ok(Some(report)) = execute_one_icmpv4_error(
            &mut kernel::WithKernel {
                io: &mut self.io,
                ports,
                caught: &mut caught,
            },
            &mut self.icmpv4_errors,
            now,
            &mut NoTrace,
        ) {
            if report.allocation_error.is_some() || report.build_error.is_some() {
                // One for an egress the backend does not have would stay at the front
                // and block every later error: drop it. Others wait for the next batch.
                let unknown = usize::from(report.action.egress.0) >= self.builder.ports.len();
                if unknown {
                    self.icmpv4_errors.discard_front();
                    continue;
                }
                break;
            }
            self.counters.icmp_errors_sent += 1;
        }
        let mut wireguard_budget = wireguard::FRAMES_PER_BATCH;
        while let Some(report) = ruster_core::wireguard::execute_one_wireguard_send(
            &mut self.io,
            &mut self.wireguard.send,
            &mut wireguard_budget,
        ) {
            if report.sent {
                self.counters.wireguard_sent += 1;
            } else {
                self.counters.wireguard_send_dropped += 1;
            }
        }
        let mut budget = fragments::FRAMES_PER_BATCH;
        while let Some(report) = execute_one_ipv4_fragmentation(
            &mut kernel::WithKernel {
                io: &mut self.io,
                ports,
                caught: &mut caught,
            },
            &mut self.fragmentation,
            &mut budget,
        ) {
            if matches!(report.outcome, ruster_core::Ipv4FragmentOutcome::Sent) {
                self.counters.fragments_sent += u64::from(report.fragments);
            } else {
                self.counters.fragmentation_dropped += 1;
            }
        }
        for (egress, frame) in caught {
            self.send_generated(egress, &frame);
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
            let (kind, ingress, bytes) = (frame.kind, frame.ingress, frame.bytes().to_vec());
            match kind {
                ControlKind::Neighbor => self.punt_frame(ingress, punt::reason::ND, &bytes),
                ControlKind::Local => {
                    self.send_to_kernel(ingress, &bytes[ETHERNET_HEADER..], now_ms)
                }
                ControlKind::TunnelFragment => {
                    if let Some(whole) = self.reassembly.add(ingress, &bytes, now_ms) {
                        self.counters.tunnel_reassembled += 1;
                        self.reassembled
                            .push(kernel::Frame::from_ethernet(ingress, &whole));
                    }
                }
            }
        }
        if self.used.len() < USED_MAX {
            self.used.extend(trace.used.drain());
        }
        for &(egress, target) in &trace.misses {
            self.resolve_request(egress, target, now_ms);
        }
        for &(interface, peer) in &trace.key_requests {
            self.key_exchange_request(interface, peer, now_ms);
        }
        true
    }

    fn punt_arp(&mut self, arp: &ArpEvent) {
        let body = arp.body();
        self.punt_frame(arp.ingress, punt::reason::ARP, &body);
    }

    /// Sends `frame` to the neighbor process; counted with the ARP counters.
    fn punt_frame(&mut self, ingress: IfId, reason: u16, frame: &[u8]) {
        let Some(name) = self.interface_names.get(usize::from(ingress.0)) else {
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
        let Some(name) = self.interface_names.get(usize::from(egress.0)) else {
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

    /// Tells the observers that the key exchange with a peer is due, at most once
    /// in [`KEY_REQUEST_INTERVAL_MS`] for each peer.
    fn key_exchange_request(&mut self, interface: IfId, peer: usize, now_ms: u64) {
        let Some(built) = self
            .wireguard
            .config
            .iter()
            .find(|i| i.interface == interface)
        else {
            return;
        };
        let Some(peer) = built.peers.get(peer) else {
            return;
        };
        let key = (built.name.clone(), peer.name.clone());
        let last = self.last_key_request.get(&key).copied();
        if last.is_some_and(|at| now_ms.saturating_sub(at) < KEY_REQUEST_INTERVAL_MS) {
            return;
        }
        if self.last_key_request.len() >= KEY_REQUESTS_REMEMBERED {
            self.last_key_request
                .retain(|_, at| now_ms.saturating_sub(*at) < KEY_REQUEST_INTERVAL_MS);
            if self.last_key_request.len() >= KEY_REQUESTS_REMEMBERED {
                return;
            }
        }
        let mut payload = Vec::new();
        ruster_proto::table::KeyExchangeRequest {
            interface: key.0.clone(),
            peer: key.1.clone(),
        }
        .encode(&mut Encoder::new(&mut payload));
        self.last_key_request.insert(key, now_ms);
        self.server.notify(&payload);
        self.counters.key_exchange_requests += 1;
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
            let egress = interface_id(&self.interface_names, punt.interface)
                .filter(|id| self.active.contains(id));
            match (punt.direction, punt.reason, egress) {
                // The neighbor process reads the "used" marks, which are then cleared.
                (Direction::FromControl, punt::reason::NEIGHBOR_USED, _) => {
                    let used: Vec<_> = self.used.drain().collect();
                    for (interface, address) in used {
                        let bytes = match address {
                            IpAddr::V4(a) => a.octets().to_vec(),
                            IpAddr::V6(a) => a.octets().to_vec(),
                        };
                        self.punt_frame(IfId(interface), punt::reason::NEIGHBOR_USED, &bytes);
                    }
                }
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

    /// Writes a packet addressed to the router to its VRF's kernel pipe.
    fn send_to_kernel(&mut self, ingress: IfId, packet: &[u8], now_ms: u64) {
        let vrf = self
            .by_ingress
            .get(usize::from(ingress.0))
            .and_then(|&at| self.names.get(usize::from(at)));
        let pipe = vrf.and_then(|name| self.local.get(name));
        let admitted = self.limiter.take(local::class(packet), now_ms);
        match pipe {
            Some(pipe) if admitted && pipe.send(packet).is_ok() => self.counters.to_kernel += 1,
            _ => self.counters.to_kernel_dropped += 1,
        }
    }

    /// The packets the kernel wrote to each VRF's pipe, as frames from its kernel
    /// interface.
    fn read_kernel(&self) -> Vec<kernel::Frame> {
        let mut buf = vec![0_u8; PUNT_MAX];
        let mut frames = Vec::new();
        for (at, name) in self.names.iter().enumerate() {
            let (Some(pipe), Some(&ingress)) = (self.local.get(name), self.kernel.get(at)) else {
                continue;
            };
            for _ in 0..INJECT_PER_STEP {
                match pipe.recv(&mut buf) {
                    Ok(n) if n > 0 => frames.push(kernel::Frame::new(ingress, at, &buf[..n])),
                    _ => break,
                }
            }
        }
        frames
    }

    /// Writes `frame` (Ethernet) for kernel interface `egress` to its VRF's pipe,
    /// without the Ethernet header.
    fn write_kernel(&mut self, egress: IfId, frame: &[u8]) -> bool {
        let pipe = self
            .kernel
            .iter()
            .position(|&id| id == egress)
            .and_then(|at| self.names.get(at))
            .and_then(|name| self.local.get(name));
        match (pipe, frame.get(ETHERNET_HEADER..)) {
            (Some(pipe), Some(packet)) => pipe.send(packet).is_ok(),
            _ => false,
        }
    }

    /// Sends `frame` out of `egress`; out of a VLAN sub-interface's parent, tagged,
    /// for a sub-interface.
    fn send_generated(&mut self, egress: IfId, frame: &[u8]) -> bool {
        if self.kernel.contains(&egress) {
            return self.write_kernel(egress, frame);
        }
        // Into a tunnel or a PPPoE session, then out of the interface below it.
        let outer = self.vrfs[0]
            .owner
            .snapshot()
            .with_ipv6(&self.vrfs[0].ipv6)
            .with_tunnels(&self.tunnels)
            .with_pppoe(&self.pppoe);
        match outer.tunnel_frame(egress, frame) {
            Some(Ok((below, wrapped))) => return self.send_generated(below, &wrapped),
            Some(Err(_)) => return false,
            None => {}
        }
        match outer.pppoe_frame(egress, frame) {
            Some(Ok((parent, wrapped))) => return self.send_generated(parent, &wrapped),
            Some(Err(_)) => return false,
            None => {}
        }
        let vlan = self.vlans.iter().find(|b| b.sub == egress).copied();
        let (port, tag) = match vlan {
            Some(binding) => (binding.parent, Some(binding.vid)),
            None => (egress, None),
        };
        self.send_port(port, tag, frame)
    }

    /// Sends `frame` out of port `port` as it is, with VLAN tag `tag` put in.
    fn send_port(&mut self, port: IfId, tag: Option<u16>, frame: &[u8]) -> bool {
        // An all-zero destination is what core puts on a frame to be wrapped (a
        // tunnel's, a session's): one that was not wrapped never leaves a port.
        if frame.len() < ETHERNET_HEADER || frame[..6] == [0; 6] {
            return false;
        }
        let extra = if tag.is_some() { 4 } else { 0 };
        let mut batch = self.io.begin_generated(port);
        let sent = match batch.allocate(frame.len() + extra) {
            Ok(mut lease) => {
                let bytes = lease.bytes_mut();
                match tag {
                    Some(vid) => {
                        bytes[..12].copy_from_slice(&frame[..12]);
                        bytes[12..14].copy_from_slice(&[0x81, 0x00]);
                        bytes[14..16].copy_from_slice(&(vid & 0x0fff).to_be_bytes());
                        bytes[16..].copy_from_slice(&frame[12..]);
                    }
                    None => bytes.copy_from_slice(frame),
                }
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
        if let Some((built, publication, nat)) = self.builder.built.take() {
            // The tracker's entries name the old tables' egress, neighbors and
            // translations: later fragments of those datagrams are dropped.
            self.fragment_tracking.flush_with_key(fragments::key());
            // As for the firewall: a NAT that cannot move stays bound to the old
            // tables, and core drops what it would have translated.
            if let Err(error) = nat::Nat::publish(&mut self.nat, nat) {
                eprintln!("ruster-fe: {error}");
            }
            // Until a move succeeds the old firewall stays, bound to the old tables:
            // core then drops what it would have checked.
            if let Err(error) = firewall::Firewall::publish(
                &mut self.firewall,
                publication,
                // With the IPv6 tables, so that IPv6 flows whose route moved go.
                self.vrfs[0].owner.snapshot().with_ipv6(&self.vrfs[0].ipv6),
                built.vrfs[0]
                    .owner
                    .snapshot()
                    .with_ipv6(&built.vrfs[0].ipv6),
            ) {
                eprintln!("ruster-fe: {error}");
            }
            self.vrfs = built.vrfs;
            self.by_ingress = built.by_ingress;
            self.names = built.names;
            self.interface_names = built.interface_names;
            self.vlans = built.vlans;
            self.tunnels = built.tunnels;
            self.pppoe = built.pppoe;
            self.wireguard.publish(built.wireguard);
            self.kernel = built.kernel;
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
    // A secret key for the limiter of NAT-translated errors, so no one outside can
    // aim at its buckets.
    let key = loop {
        let (a, b) = nat::words();
        if let Ok(key) = ruster_core::ResolutionHashKey::new(a, b) {
            break key;
        }
    };
    Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), states, actions)
        .with_translated_limit_key(key)
}

/// Generated ICMPv4 frames are counted, not traced.
struct NoTrace;

impl GeneratedIcmpv4TraceSink for NoTrace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

/// Turns the tables into core's tables.
struct Builder {
    ports: Vec<String>,
    /// The tables built for the last accepted store and their firewall, until the
    /// FE takes them.
    built: Option<(
        build::Built,
        firewall::Publication,
        Option<nat::Publication>,
    )>,
    /// Of the last firewall publication.
    generation: u64,
}

/// The id of the interface `name` (a port or a VLAN sub-interface) in `names`.
fn interface_id(names: &[String], name: &str) -> Option<IfId> {
    let index = names.iter().position(|n| n == name)?;
    u16::try_from(index).ok().map(IfId)
}

impl Hook for Builder {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        let built = build::build(&self.ports, next)?;
        self.generation += 1;
        let default = built.vrfs.first().ok_or("no default VRF")?;
        let publication = firewall::Publication::new(
            &default.owner.snapshot(),
            &built.firewall,
            built.firewall_on,
            self.generation,
        )?;
        let nat = built
            .nat
            .map(|nat| nat::Publication::new(&default.owner.snapshot(), nat))
            .transpose()?;
        self.built = Some((built, publication, nat));
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
    /// Next hops packets went to in this batch (the neighbors' "used" marks).
    used: std::collections::HashSet<(u16, IpAddr)>,
    /// WireGuard peers (interface, index among its peers) that had a packet and no
    /// session.
    key_requests: Vec<(IfId, usize)>,
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
            TraceEvent::Routed {
                egress,
                neighbor_target,
            } => {
                self.used
                    .insert((egress.0, IpAddr::V4(neighbor_target.octets().into())));
            }
            TraceEvent::Ipv6Routed { egress, next_hop } => {
                self.used.insert((egress.0, IpAddr::V6(next_hop.into())));
            }
            TraceEvent::NeighborMissing { egress, target } => {
                self.miss(egress, IpAddr::V4(target.octets().into()));
            }
            TraceEvent::Ipv6NeighborMissing { egress, target } => {
                self.miss(egress, IpAddr::V6(target.into()));
            }
            TraceEvent::WireguardNoSession { interface, peer } => {
                let request = (interface, peer);
                if self.key_requests.len() < EVENTS_PER_BATCH
                    && !self.key_requests.contains(&request)
                {
                    self.key_requests.push(request);
                }
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

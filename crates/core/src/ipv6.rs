//! IPv6 forwarding.
//!
//! [`Ipv6Fib`] holds the IPv6 routes, neighbors and the router's own addresses; a
//! [`ForwardingSnapshot`](crate::ForwardingSnapshot) carries it after
//! [`with_ipv6`](crate::ForwardingSnapshot::with_ipv6). Each IPv6 frame of a batch is
//! then forwarded, dropped, or copied into a caller's [`ControlQueue`] for the
//! neighbor process (Neighbor Discovery) and consumed.
//!
//! # Standards
//!
//! - RFC 8200 section 3: the header fields read and the Hop Limit decrement; a packet
//!   whose Hop Limit would reach 0 is not forwarded.
//! - RFC 4291 section 2.5.6: link-local addresses, as source or destination, are not
//!   forwarded. Section 2.7: a multicast source is invalid.
//! - RFC 4861 section 4: Router and Neighbor Solicitation and Advertisement and
//!   Redirect (ICMPv6 types 133 to 137) addressed to the router or to a multicast
//!   group go to the control side unchanged; neighd checks the rest of RFC 4861.
//! - RFC 2464 section 7: IPv6 multicast is sent to 33:33 Ethernet addresses.
//!
//! - RFC 4443 section 3: Destination Unreachable (no route), Packet Too Big (with the
//!   egress MTU) and Time Exceeded (Hop Limit), built into a [`ControlQueue`] made
//!   [`with_icmpv6_errors`](ControlQueue::with_icmpv6_errors). Section 2.4: no error
//!   about an ICMPv6 error, about multicast (except Packet Too Big), or to a source
//!   that is not one host; at most 1280 bytes; a token bucket limits the rate (a
//!   burst of 10, then one per 10 ms); the source is a global address of the router,
//!   one on the interface toward the source when there is one.
//!
//! Deviations: no Destination Unreachable for an unresolvable neighbor (address
//! unreachable) or for traffic to the router, no extension headers before an ND
//! message, and other traffic addressed to the router is dropped until it is passed
//! to the kernel. Routes are searched linearly, longest prefix first.

use crate::{IfId, MacAddress, TraceEvent, TraceSink};

/// The Ethernet type of IPv6 (RFC 2464).
pub const IPV6_ETHERTYPE: u16 = 0x86dd;

const ETHERNET_HEADER: usize = 14;
const IPV6_HEADER: usize = 40;
const ICMPV6: u8 = 58;
const DESTINATION_UNREACHABLE: u8 = 1;
const PACKET_TOO_BIG: u8 = 2;
const TIME_EXCEEDED: u8 = 3;
/// The largest ICMPv6 error, so that it fits the IPv6 minimum MTU (RFC 4443 2.4 (c)).
const ERROR_MAX: usize = 1_280;
/// The largest frame a [`ControlQueue`] slot holds: Ethernet with a 1500-byte payload.
pub const CONTROL_FRAME_MAX: usize = ETHERNET_HEADER + 1_500;

/// One IPv6 route: packets to `prefix/len` leave through `egress`, to `next_hop` or,
/// when it is `None`, to their destination on the link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Route {
    prefix: [u8; 16],
    len: u8,
    egress: IfId,
    next_hop: Option<[u8; 16]>,
}

/// Why an IPv6 route or table was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6FibError {
    PrefixLengthTooLong,
    HostBitsSet,
    /// Two routes for the same prefix.
    DuplicateRoute,
    /// Two neighbors for the same interface and address.
    DuplicateNeighbor,
}

impl Ipv6Route {
    pub fn new(
        prefix: [u8; 16],
        len: u8,
        egress: IfId,
        next_hop: Option<[u8; 16]>,
    ) -> Result<Self, Ipv6FibError> {
        if len > 128 {
            return Err(Ipv6FibError::PrefixLengthTooLong);
        }
        if masked(prefix, len) != prefix {
            return Err(Ipv6FibError::HostBitsSet);
        }
        Ok(Self {
            prefix,
            len,
            egress,
            next_hop,
        })
    }

    fn contains(&self, address: [u8; 16]) -> bool {
        masked(address, self.len) == self.prefix
    }
}

/// The link-layer address of an IPv6 neighbor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Neighbor {
    pub interface: IfId,
    pub target: [u8; 16],
    pub mac: MacAddress,
}

/// One of the router's own IPv6 addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Local {
    pub interface: IfId,
    pub address: [u8; 16],
}

/// The IPv6 tables of one snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ipv6Fib {
    /// Longest prefix first.
    routes: Box<[Ipv6Route]>,
    neighbors: Box<[Ipv6Neighbor]>,
    local: Box<[Ipv6Local]>,
}

impl Ipv6Fib {
    pub fn new(
        mut routes: Vec<Ipv6Route>,
        neighbors: Vec<Ipv6Neighbor>,
        local: Vec<Ipv6Local>,
    ) -> Result<Self, Ipv6FibError> {
        routes.sort_by(|a, b| b.len.cmp(&a.len).then(a.prefix.cmp(&b.prefix)));
        if routes
            .windows(2)
            .any(|w| w[0].len == w[1].len && w[0].prefix == w[1].prefix)
        {
            return Err(Ipv6FibError::DuplicateRoute);
        }
        let mut seen: Vec<(IfId, [u8; 16])> =
            neighbors.iter().map(|n| (n.interface, n.target)).collect();
        seen.sort_unstable();
        if seen.windows(2).any(|w| w[0] == w[1]) {
            return Err(Ipv6FibError::DuplicateNeighbor);
        }
        Ok(Self {
            routes: routes.into(),
            neighbors: neighbors.into(),
            local: local.into(),
        })
    }

    fn route(&self, destination: [u8; 16]) -> Option<&Ipv6Route> {
        self.routes.iter().find(|route| route.contains(destination))
    }

    fn neighbor(&self, interface: IfId, target: [u8; 16]) -> Option<MacAddress> {
        self.neighbors
            .iter()
            .find(|n| n.interface == interface && n.target == target)
            .map(|n| n.mac)
    }

    fn is_local(&self, address: [u8; 16]) -> bool {
        self.local.iter().any(|l| l.address == address)
    }
}

fn masked(address: [u8; 16], len: u8) -> [u8; 16] {
    let bits = u128::from_be_bytes(address);
    let mask = u128::MAX
        .checked_shl(128 - u32::from(len.min(128)))
        .unwrap_or(0);
    (bits & mask).to_be_bytes()
}

fn is_multicast(address: [u8; 16]) -> bool {
    address[0] == 0xff
}

fn is_link_local(address: [u8; 16]) -> bool {
    address[0] == 0xfe && address[1] & 0xc0 == 0x80
}

fn is_unspecified_or_loopback(address: [u8; 16]) -> bool {
    let bits = u128::from_be_bytes(address);
    bits == 0 || bits == 1
}

/// Frames copied for the control side, in fixed slots allocated once.
#[derive(Debug)]
pub struct ControlQueue {
    slots: Box<[ControlFrame]>,
    len: usize,
    /// ICMPv6 errors built in the last batch, ready to send.
    errors: Box<[ControlFrame]>,
    errors_len: usize,
    limiter: ErrorLimiter,
}

/// A token bucket for ICMPv6 errors (RFC 4443 section 2.4 (f)): a burst of
/// [`ERROR_BURST`], refilled at one error per [`ERROR_INTERVAL_MS`].
#[derive(Clone, Copy, Debug)]
struct ErrorLimiter {
    tokens: u32,
    refilled_at: u64,
    now: u64,
}

/// Errors that may be sent at once.
pub const ERROR_BURST: u32 = 10;
/// One more error may be sent after this many milliseconds.
pub const ERROR_INTERVAL_MS: u64 = 10;

impl ErrorLimiter {
    fn take(&mut self) -> bool {
        let earned = self.now.saturating_sub(self.refilled_at) / ERROR_INTERVAL_MS;
        if earned > 0 {
            let earned = u32::try_from(earned).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(earned).min(ERROR_BURST);
            self.refilled_at = self.now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

/// What a control frame is for.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ControlKind {
    /// Neighbor Discovery, for the neighbor process.
    #[default]
    Neighbor,
    /// A packet addressed to the router, for the kernel.
    Local,
}

/// One frame for the control side, or one ICMPv6 error to send.
#[derive(Clone, Debug)]
pub struct ControlFrame {
    pub kind: ControlKind,
    /// The interface the frame came in on; for an error, the one to send it out of.
    pub ingress: IfId,
    bytes: Box<[u8; CONTROL_FRAME_MAX]>,
    len: usize,
}

impl ControlFrame {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl ControlQueue {
    /// A queue of `capacity` slots; a full queue drops further frames.
    pub fn new(capacity: usize) -> Self {
        let slot = ControlFrame {
            kind: ControlKind::Neighbor,
            ingress: IfId(0),
            bytes: Box::new([0; CONTROL_FRAME_MAX]),
            len: 0,
        };
        Self {
            slots: vec![slot.clone(); capacity].into(),
            len: 0,
            errors: Box::new([]),
            errors_len: 0,
            limiter: ErrorLimiter {
                tokens: ERROR_BURST,
                refilled_at: 0,
                now: 0,
            },
        }
    }

    /// Also builds up to `capacity` ICMPv6 errors per batch.
    #[must_use]
    pub fn with_icmpv6_errors(mut self, capacity: usize) -> Self {
        let slot = ControlFrame {
            kind: ControlKind::Neighbor,
            ingress: IfId(0),
            bytes: Box::new([0; CONTROL_FRAME_MAX]),
            len: 0,
        };
        self.errors = vec![slot; capacity].into();
        self
    }

    /// The time the error limiter counts by; call before each batch.
    pub fn set_clock(&mut self, now: crate::MonotonicMillis) {
        self.limiter.now = now.0;
    }

    /// The ICMPv6 errors built since the last [`ControlQueue::clear`].
    pub fn errors(&self) -> &[ControlFrame] {
        &self.errors[..self.errors_len]
    }

    /// Queues a packet addressed to the router; a full queue drops it.
    pub(crate) fn push_local(&mut self, ingress: IfId, frame: &[u8]) -> bool {
        let pushed = self.push(ingress, frame);
        if pushed {
            self.slots[self.len - 1].kind = ControlKind::Local;
        }
        pushed
    }

    fn push(&mut self, ingress: IfId, frame: &[u8]) -> bool {
        let Some(slot) = self.slots.get_mut(self.len) else {
            return false;
        };
        if frame.len() > CONTROL_FRAME_MAX {
            return false;
        }
        slot.kind = ControlKind::Neighbor;
        slot.ingress = ingress;
        slot.bytes[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len();
        self.len += 1;
        true
    }

    /// The frames queued since the last [`ControlQueue::clear`].
    pub fn frames(&self) -> &[ControlFrame] {
        &self.slots[..self.len]
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.errors_len = 0;
    }

    /// Builds an ICMPv6 error about `invoking` toward its source, if RFC 4443 allows
    /// one, there is room and the limiter has a token.
    fn error(
        &mut self,
        invoking: &[u8],
        snapshot: &crate::ForwardingSnapshot<'_>,
        fib: &Ipv6Fib,
        (kind, code, parameter): (u8, u8, u32),
    ) {
        if self.errors_len >= self.errors.len() {
            return;
        }
        let Some((egress, frame_len)) = build_error(
            &mut self.errors[self.errors_len].bytes,
            invoking,
            snapshot,
            fib,
            (kind, code, parameter),
        ) else {
            return;
        };
        if !self.limiter.take() {
            return;
        }
        let slot = &mut self.errors[self.errors_len];
        slot.ingress = egress;
        slot.len = frame_len;
        self.errors_len += 1;
    }
}

/// What to do with one IPv6 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// Rewritten in place; send it out of the interface.
    Transmit(IfId),
    Drop(crate::DropReason),
    /// Dropped, and worth an ICMPv6 error (RFC 4443) of this type, code and parameter.
    Error(crate::DropReason, u8, u8, u32),
    /// Copy it to the control side and consume it.
    Control,
    /// Addressed to the router: copy it to the control side for the kernel.
    Local,
}

fn address(frame: &[u8], at: usize) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(&frame[at..at + 16]);
    out
}

/// Decides one IPv6 frame and, for [`Outcome::Transmit`], rewrites it: Ethernet
/// addresses for the next hop and the Hop Limit.
pub(crate) fn decide<T: TraceSink>(
    frame: &mut [u8],
    snapshot: &crate::ForwardingSnapshot<'_>,
    fib: &Ipv6Fib,
    ingress: IfId,
    trace: &mut T,
) -> Outcome {
    use crate::DropReason::*;
    let ip = ETHERNET_HEADER;
    if frame.len() < ip + IPV6_HEADER {
        return Outcome::Drop(Ipv6HeaderTruncated);
    }
    if frame[ip] >> 4 != 6 {
        return Outcome::Drop(Ipv6VersionUnsupported);
    }
    let payload_len = usize::from(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]));
    if ip + IPV6_HEADER + payload_len > frame.len() {
        return Outcome::Drop(Ipv6PayloadLengthExceedsPacket);
    }
    let Some(interface) = snapshot.interface(ingress) else {
        return Outcome::Drop(Ipv6IngressInterfaceUnknown);
    };
    let destination_mac = &frame[0..6];
    let source_mac = &frame[6..12];
    if source_mac[0] & 1 != 0 || source_mac == [0; 6] {
        return Outcome::Drop(Ipv6EthernetAddressInvalid);
    }
    let to_us_or_group = destination_mac == interface.mac.0
        || (destination_mac[0] == 0x33 && destination_mac[1] == 0x33);
    if !to_us_or_group {
        return Outcome::Drop(Ipv6EthernetAddressInvalid);
    }
    let next_header = frame[ip + 6];
    let hop_limit = frame[ip + 7];
    let source = address(frame, ip + 8);
    let destination = address(frame, ip + 24);
    if is_multicast(source) {
        return Outcome::Drop(Ipv6SourceInvalid);
    }
    let neighbor_discovery =
        next_header == ICMPV6 && payload_len >= 1 && (133..=137).contains(&frame[ip + IPV6_HEADER]);
    if is_multicast(destination) || fib.is_local(destination) {
        return if neighbor_discovery {
            trace.record(TraceEvent::Ipv6ToControl { ingress });
            Outcome::Control
        } else if is_multicast(destination) {
            Outcome::Drop(Ipv6DestinationNotForwarded)
        } else if snapshot.local_to_control {
            Outcome::Local
        } else {
            Outcome::Drop(Ipv6LocalUnsupported)
        };
    }
    if is_link_local(destination) || is_unspecified_or_loopback(destination) {
        return Outcome::Drop(Ipv6DestinationNotForwarded);
    }
    if is_link_local(source) || is_unspecified_or_loopback(source) {
        return Outcome::Drop(Ipv6SourceInvalid);
    }
    if hop_limit <= 1 {
        return Outcome::Error(Ipv6HopLimitExpired, TIME_EXCEEDED, 0, 0);
    }
    let Some(route) = fib.route(destination) else {
        return Outcome::Error(RouteMiss, DESTINATION_UNREACHABLE, 0, 0);
    };
    let Some(egress) = snapshot.interface(route.egress) else {
        return Outcome::Drop(InterfaceMiss);
    };
    if IPV6_HEADER + payload_len > usize::from(egress.mtu) {
        return Outcome::Error(Ipv6PacketTooBig, PACKET_TOO_BIG, 0, u32::from(egress.mtu));
    }
    let next_hop = route.next_hop.unwrap_or(destination);
    let Some(mac) = fib.neighbor(egress.id, next_hop) else {
        trace.record(TraceEvent::Ipv6NeighborMissing {
            egress: egress.id,
            target: next_hop,
        });
        return Outcome::Drop(NeighborUnresolved);
    };
    frame[0..6].copy_from_slice(&mac.0);
    frame[6..12].copy_from_slice(&egress.mac.0);
    frame[ip + 7] = hop_limit - 1;
    Outcome::Transmit(egress.id)
}

/// Handles an IPv6 frame in the batch loop: decides it and completes its lease.
/// Returns how it ended, for the batch counters.
pub(crate) fn complete<S: crate::PacketSlot, T: TraceSink>(
    mut packet: crate::PacketLease<S>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    fib: &Ipv6Fib,
    control: Option<&mut ControlQueue>,
    trace: &mut T,
) -> Completed {
    let ingress = packet.ingress();
    match decide(packet.bytes_mut(), snapshot, fib, ingress, trace) {
        Outcome::Transmit(egress) => {
            packet.commit(egress);
            Completed::Transmitted
        }
        Outcome::Drop(reason) => {
            packet.recycle(reason);
            trace.record(TraceEvent::Dropped { ingress, reason });
            Completed::Dropped
        }
        Outcome::Error(reason, kind, code, parameter) => {
            if let Some(queue) = control {
                queue.error(packet.bytes_mut(), snapshot, fib, (kind, code, parameter));
            }
            packet.recycle(reason);
            trace.record(TraceEvent::Dropped { ingress, reason });
            Completed::Dropped
        }
        Outcome::Local => {
            if let Some(queue) = control {
                queue.push_local(ingress, packet.bytes_mut());
            }
            packet.consume(crate::ConsumeReason::LocalToControl);
            Completed::Consumed
        }
        Outcome::Control => {
            let queued = control.is_some_and(|queue| queue.push(ingress, packet.bytes_mut()));
            if queued {
                packet.consume(crate::ConsumeReason::Ipv6Control);
                Completed::Consumed
            } else {
                let reason = crate::DropReason::Ipv6ControlQueueFull;
                packet.recycle(reason);
                trace.record(TraceEvent::Dropped { ingress, reason });
                Completed::Dropped
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Completed {
    Transmitted,
    Dropped,
    Consumed,
}

/// The ICMPv6 checksum of `icmp` between `source` and `destination` (RFC 4443 2.3).
fn icmpv6_checksum(source: [u8; 16], destination: [u8; 16], icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for pair in bytes.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
    };
    add(&source);
    add(&destination);
    add(&u32::try_from(icmp.len()).unwrap_or(0).to_be_bytes());
    add(&[0, 0, 0, ICMPV6]);
    add(icmp);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Writes into `out` the Ethernet frame of an ICMPv6 error about `invoking` and returns
/// the interface to send it out of and its length. `None` when RFC 4443 section 2.4 (e)
/// forbids one, or there is no route, neighbor or router address to send it with.
fn build_error(
    out: &mut [u8; CONTROL_FRAME_MAX],
    invoking: &[u8],
    snapshot: &crate::ForwardingSnapshot<'_>,
    fib: &Ipv6Fib,
    (kind, code, parameter): (u8, u8, u32),
) -> Option<(IfId, usize)> {
    let ip = ETHERNET_HEADER;
    let source = address(invoking, ip + 8);
    let destination = address(invoking, ip + 24);
    // (e.1) no error about an ICMPv6 error; (e.2, e.3) none about multicast, except
    // Packet Too Big; (e.5) none to a source that is not one host.
    let is_error =
        invoking[ip + 6] == ICMPV6 && invoking.get(ip + IPV6_HEADER).is_some_and(|&t| t < 128);
    let multicast = is_multicast(destination) || invoking[0] & 1 != 0;
    if is_error
        || (multicast && kind != PACKET_TOO_BIG)
        || is_multicast(source)
        || is_unspecified_or_loopback(source)
    {
        return None;
    }
    let route = fib.route(source)?;
    let egress = snapshot.interface(route.egress)?;
    let mac = fib.neighbor(egress.id, route.next_hop.unwrap_or(source))?;
    // An address of the router: on the egress interface if it has a global one.
    let from = fib
        .local
        .iter()
        .filter(|l| !is_link_local(l.address))
        .min_by_key(|l| l.interface != egress.id)?
        .address;
    let limit = ERROR_MAX.min(usize::from(egress.mtu));
    let quoted = (invoking.len() - ip).min(limit - IPV6_HEADER - 8);
    let icmp_len = 8 + quoted;
    let frame_len = ip + IPV6_HEADER + icmp_len;
    out[0..6].copy_from_slice(&mac.0);
    out[6..12].copy_from_slice(&egress.mac.0);
    out[12..14].copy_from_slice(&IPV6_ETHERTYPE.to_be_bytes());
    out[ip..ip + 4].copy_from_slice(&[0x60, 0, 0, 0]);
    out[ip + 4..ip + 6].copy_from_slice(&u16::try_from(icmp_len).ok()?.to_be_bytes());
    out[ip + 6] = ICMPV6;
    out[ip + 7] = 64;
    out[ip + 8..ip + 24].copy_from_slice(&from);
    out[ip + 24..ip + 40].copy_from_slice(&source);
    let icmp = ip + IPV6_HEADER;
    out[icmp] = kind;
    out[icmp + 1] = code;
    out[icmp + 2..icmp + 4].copy_from_slice(&[0, 0]);
    out[icmp + 4..icmp + 8].copy_from_slice(&parameter.to_be_bytes());
    out[icmp + 8..icmp + 8 + quoted].copy_from_slice(&invoking[ip..ip + quoted]);
    let sum = icmpv6_checksum(from, source, &out[icmp..frame_len]);
    out[icmp + 2..icmp + 4].copy_from_slice(&sum.to_be_bytes());
    Some((egress.id, frame_len))
}

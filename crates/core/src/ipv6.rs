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
//!   forwarded; a link-local source toward another link gets Destination
//!   Unreachable code 2 back on its link (RFC 4443 section 3.1). Section 2.7: a
//!   multicast source is invalid. A packet from outside with one of the router's
//!   addresses as its source is dropped.
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
//! - RFC 8200 section 3: the Hop Limit is decremented when a packet is forwarded. A
//!   packet from the kernel's interface ([`with_kernel_ingress`]) is the router's own,
//!   so its Hop Limit stays.
//!
//! Deviations: the subnet-router anycast address of a connected prefix (RFC 4291
//! section 2.6.1) is not the router's; extension headers are stepped over only to tell whether a packet is itself an
//! ICMPv6 error (RFC 4443 2.4(e.1)); one ICMPv6 error limiter for every source,
//! with one for Packet Too Big and one for the others;
//! Address Unreachable (RFC 4443 3.1 code 3) only for a next hop the neighbor
//! process gave up on, none for traffic to the router; no extension headers before an ND
//! message, and other traffic addressed to the router is dropped until it is passed
//! to the kernel. Routes are searched linearly, longest prefix first.
//! An ICMPv6 error about a packet from the kernel's interface has the packet's
//! destination as its source, not an address of the router (RFC 4443 section 2.2),
//! because the kernel discards a packet from one of its own addresses.
//! No source address validation of forwarded IPv6 (RFC 1812 section 5.3.8's check is
//! for IPv4; RFC 3704's for IPv6 is not built).
//!
//! [`with_kernel_ingress`]: crate::ForwardingSnapshot::with_kernel_ingress

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
    /// Next hops the control side could not resolve: Address Unreachable.
    unreachable: Box<[(IfId, [u8; 16])]>,
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
            unreachable: Box::new([]),
        })
    }

    /// The interface and the address of the next hop toward `destination`.
    /// The egress, next hop and (when known) next hop MAC for a packet the router
    /// sends to `destination`.
    pub(crate) fn origin(
        &self,
        destination: [u8; 16],
    ) -> Option<(IfId, [u8; 16], Option<MacAddress>)> {
        let route = self.route(destination)?;
        let hop = route.next_hop.unwrap_or(destination);
        Some((route.egress, hop, self.neighbor(route.egress, hop)))
    }

    pub(crate) fn next_hop(&self, destination: [u8; 16]) -> Option<(IfId, [u8; 16])> {
        self.route(destination)
            .map(|route| (route.egress, route.next_hop.unwrap_or(destination)))
    }

    pub(crate) fn route(&self, destination: [u8; 16]) -> Option<&Ipv6Route> {
        self.routes.iter().find(|route| route.contains(destination))
    }

    /// The same table with `unreachable` as the next hops the control side could
    /// not resolve.
    #[must_use]
    pub fn with_unreachable(mut self, unreachable: Vec<(IfId, [u8; 16])>) -> Self {
        self.unreachable = unreachable.into();
        self
    }

    pub(crate) fn neighbor(&self, interface: IfId, target: [u8; 16]) -> Option<MacAddress> {
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
    /// Packet Too Big has its own bucket, so that other errors cannot use up what
    /// path MTU discovery needs.
    too_big_limiter: ErrorLimiter,
}

/// A token bucket for ICMPv6 errors (RFC 4443 section 2.4 (f)): a burst of
/// [`ERROR_BURST`], refilled at one error per [`ERROR_INTERVAL_MS`].
#[derive(Clone, Copy, Debug)]
struct ErrorLimiter {
    tokens: u32,
    refilled_at: u64,
    now: u64,
    burst: u32,
    interval_ms: u64,
}

/// Errors that may be sent at once.
pub const ERROR_BURST: u32 = 10;
/// One more error may be sent after this many milliseconds.
pub const ERROR_INTERVAL_MS: u64 = 10;

impl ErrorLimiter {
    fn take(&mut self) -> bool {
        let earned = self.now.saturating_sub(self.refilled_at) / self.interval_ms;
        if earned > 0 {
            let earned = u32::try_from(earned).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(earned).min(self.burst);
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
    /// A fragment of a tunnel's IPv6 packet, for the FE to put back together.
    TunnelFragment,
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
                burst: ERROR_BURST,
                interval_ms: ERROR_INTERVAL_MS,
            },
            too_big_limiter: ErrorLimiter {
                tokens: ERROR_BURST,
                refilled_at: 0,
                now: 0,
                burst: ERROR_BURST,
                interval_ms: ERROR_INTERVAL_MS,
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

    /// Limits ICMPv6 errors to `burst` at once and one more every `interval_ms`
    /// (RFC 4443 2.4(f): the parameters are configurable), for Packet Too Big and
    /// for the other errors each. `interval_ms` is at least 1.
    pub fn set_error_limit(&mut self, burst: u32, interval_ms: u64) {
        for limiter in [&mut self.limiter, &mut self.too_big_limiter] {
            limiter.burst = burst;
            limiter.interval_ms = interval_ms.max(1);
            limiter.tokens = limiter.tokens.min(burst);
        }
    }

    /// The time the error limiter counts by; call before each batch.
    pub fn set_clock(&mut self, now: crate::MonotonicMillis) {
        self.limiter.now = now.0;
        self.too_big_limiter.now = now.0;
    }

    /// The ICMPv6 errors built since the last [`ControlQueue::clear`].
    pub fn errors(&self) -> &[ControlFrame] {
        &self.errors[..self.errors_len]
    }

    /// Queues a fragment of a tunnel's IPv6 packet; a full queue drops it.
    pub(crate) fn push_tunnel_fragment(&mut self, ingress: IfId, frame: &[u8]) -> bool {
        let pushed = self.push(ingress, frame);
        if pushed {
            self.slots[self.len - 1].kind = ControlKind::TunnelFragment;
        }
        pushed
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
        ingress: IfId,
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
            ingress,
            (kind, code, parameter),
        ) else {
            return;
        };
        let limiter = if kind == PACKET_TOO_BIG {
            &mut self.too_big_limiter
        } else {
            &mut self.limiter
        };
        if !limiter.take() {
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
///
/// `admit` is the forward firewall: it sees a packet to be forwarded right after its
/// route is found, before anything else is decided for it, so that a packet it drops
/// makes no ICMPv6 error and no neighbor resolution. With `silent_route_miss`, a
/// packet with no route is dropped without an error (the firewall guards it, and
/// cannot say whether it would have let it through).
pub(crate) fn decide<T: TraceSink, A>(
    frame: &mut [u8],
    snapshot: &crate::ForwardingSnapshot<'_>,
    fib: &Ipv6Fib,
    ingress: IfId,
    admit: &mut A,
    silent_route_miss: bool,
    trace: &mut T,
) -> Outcome
where
    A: FnMut(&[u8], IfId) -> Result<(), crate::DropReason>,
{
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
    // A unicast packet for someone else in an Ethernet multicast frame is not
    // forwarded (every router on the link would).
    if destination_mac[0] == 0x33 && destination_mac[1] == 0x33 {
        return Outcome::Drop(Ipv6EthernetAddressInvalid);
    }
    if is_link_local(destination) || is_unspecified_or_loopback(destination) {
        return Outcome::Drop(Ipv6DestinationNotForwarded);
    }
    if is_unspecified_or_loopback(source) {
        return Outcome::Drop(Ipv6SourceInvalid);
    }
    // The router's own address as the source of a packet from outside is forged.
    if fib.is_local(source) && !snapshot.is_kernel_ingress(ingress) {
        return Outcome::Drop(Ipv6SourceInvalid);
    }
    // A link-local source cannot leave its link: Destination Unreachable code 2,
    // beyond scope of source address (RFC 4443 3.1).
    if is_link_local(source) {
        return Outcome::Error(Ipv6SourceInvalid, DESTINATION_UNREACHABLE, 2, 0);
    }
    let Some(route) = fib.route(destination) else {
        if silent_route_miss {
            return Outcome::Drop(FirewallDefaultDenied);
        }
        return Outcome::Error(RouteMiss, DESTINATION_UNREACHABLE, 0, 0);
    };
    if route.egress == IfId::DISCARD {
        return Outcome::Drop(crate::DropReason::RouteDiscard);
    }
    if route.egress == IfId::REJECT {
        if silent_route_miss {
            return Outcome::Drop(FirewallDefaultDenied);
        }
        // RFC 4443 3.1 code 6: reject route to destination.
        return Outcome::Error(RouteMiss, DESTINATION_UNREACHABLE, 6, 0);
    }
    let Some(egress) = snapshot.interface(route.egress) else {
        return Outcome::Drop(InterfaceMiss);
    };
    if let Err(reason) = admit(frame, egress.id) {
        return Outcome::Drop(reason);
    }
    // The router's own packets are not forwarded: their Hop Limit stays.
    let hop = u8::from(!snapshot.is_kernel_ingress(ingress));
    if hop_limit <= hop {
        return Outcome::Error(Ipv6HopLimitExpired, TIME_EXCEEDED, 0, 0);
    }
    if IPV6_HEADER + payload_len > usize::from(egress.mtu) {
        return Outcome::Error(Ipv6PacketTooBig, PACKET_TOO_BIG, 0, u32::from(egress.mtu));
    }
    let next_hop = route.next_hop.unwrap_or(destination);
    let session = crate::pppoe::of(snapshot.pppoe, egress.id).is_some();
    let Some(mac) = fib
        .neighbor(egress.id, next_hop)
        .or(session.then_some(MacAddress([0; 6])))
    else {
        // The control side gave up resolving it: Address Unreachable (RFC 4443 3.1
        // code 3), and no new request until it tries again.
        if fib.unreachable.contains(&(egress.id, next_hop)) {
            return Outcome::Error(NeighborUnresolved, DESTINATION_UNREACHABLE, 3, 0);
        }
        trace.record(TraceEvent::Ipv6NeighborMissing {
            egress: egress.id,
            target: next_hop,
        });
        return Outcome::Drop(NeighborUnresolved);
    };
    trace.record(TraceEvent::Ipv6Routed {
        egress: egress.id,
        next_hop,
    });
    frame[0..6].copy_from_slice(&mac.0);
    frame[6..12].copy_from_slice(&egress.mac.0);
    frame[ip + 7] = hop_limit - hop;
    Outcome::Transmit(egress.id)
}

/// The forward firewall, for the IPv6 packets it guards.
pub(crate) struct FirewallService<'f, 'a, 'c, 'r, 's, 'b, 't> {
    /// The snapshot the firewall's configuration is bound to (the default VRF's).
    pub(crate) outer: &'f crate::ForwardingSnapshot<'a>,
    pub(crate) config: Option<&'f crate::FirewallConfig<'c>>,
    pub(crate) runtime: &'f mut Option<&'s mut crate::FirewallRuntime<'r>>,
    pub(crate) audit: &'f mut Option<&'t mut crate::FirewallAuditBuffer<'b>>,
    /// Without a firewall, whether the guarded packets are dropped anyway (the
    /// firewall has rules but no runtime here).
    pub(crate) blocked: bool,
}

/// Handles an IPv6 frame in the batch loop: decides it and completes its lease.
/// A packet `guarded` says the forward firewall guards goes through `firewall`.
/// Returns how it ended, for the batch counters.
#[allow(clippy::too_many_arguments)]
pub(crate) fn complete<S: crate::PacketSlot, T: TraceSink>(
    mut packet: crate::PacketLease<S>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    fib: &Ipv6Fib,
    guarded: impl Fn(IfId) -> bool,
    firewall: FirewallService<'_, '_, '_, '_, '_, '_, '_>,
    control: Option<&mut ControlQueue>,
    vlans: &[crate::VlanBinding],
    trace: &mut T,
) -> Completed {
    let ingress = packet.ingress();
    // Decided in another VRF: the firewall's rules are the default VRF's, so such a
    // packet does not go through them (as for IPv4).
    let foreign = snapshot.authority() != firewall.outer.authority();
    let FirewallService {
        outer,
        config,
        runtime,
        audit,
        blocked,
    } = firewall;
    let mut admit = |frame: &[u8], egress: IfId| -> Result<(), crate::DropReason> {
        if !guarded(egress) {
            return Ok(());
        }
        match config {
            // Into the default VRF's interfaces from another VRF while the default
            // VRF has a firewall: dropped rather than let past it.
            Some(_) if foreign => Err(crate::DropReason::VrfLeakIntoServices),
            Some(config) => crate::forwarding::require_firewall_runtime(outer, config, runtime)
                .and_then(|runtime| {
                    crate::firewall6::check(
                        frame,
                        ingress,
                        egress,
                        config,
                        runtime,
                        audit,
                        outer.now.0,
                    )
                }),
            None if blocked => Err(crate::DropReason::Ipv6ForwardingBlocked),
            None => Ok(()),
        }
    };
    let silent_route_miss = config.is_some() && !foreign;
    let outcome = decide(
        packet.bytes_mut(),
        snapshot,
        fib,
        ingress,
        &mut admit,
        silent_route_miss,
        trace,
    );
    match outcome {
        Outcome::Transmit(egress) => match crate::pppoe::of(snapshot.pppoe, egress)
            .map_or(Ok(egress), |session| {
                crate::pppoe::transmit(&mut packet, session, snapshot)
            })
            .and_then(|egress| crate::vlan::transmit(&mut packet, egress, vlans))
        {
            Ok(port) => {
                packet.commit(port);
                Completed::Transmitted
            }
            Err(reason) => {
                packet.recycle(reason);
                trace.record(TraceEvent::Dropped { ingress, reason });
                Completed::Dropped
            }
        },
        Outcome::Drop(reason) => {
            packet.recycle(reason);
            trace.record(TraceEvent::Dropped { ingress, reason });
            Completed::Dropped
        }
        Outcome::Error(reason, kind, code, parameter) => {
            if let Some(queue) = control {
                queue.error(
                    packet.bytes_mut(),
                    snapshot,
                    fib,
                    ingress,
                    (kind, code, parameter),
                );
            }
            packet.recycle(reason);
            trace.record(TraceEvent::Dropped { ingress, reason });
            Completed::Dropped
        }
        Outcome::Local => {
            // To the kernel, the router's host, as to a host behind a port: through
            // the forward firewall, out of the VRF's kernel interface.
            let admitted = match outer.kernel_interface_of(snapshot) {
                Some(kernel) => admit(packet.bytes_mut(), kernel),
                None => Ok(()),
            };
            if let Err(reason) = admitted {
                packet.recycle(reason);
                trace.record(TraceEvent::Dropped { ingress, reason });
                return Completed::Dropped;
            }
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
/// The upper-layer header of the IPv6 packet in `frame` (Ethernet): its type and
/// where it starts, past at most eight Hop-by-Hop, Routing, Destination Options and
/// (first-fragment) Fragment headers.
fn upper_layer(frame: &[u8]) -> Option<(u8, usize)> {
    let ip = ETHERNET_HEADER;
    let mut next = *frame.get(ip + 6)?;
    let mut at = ip + IPV6_HEADER;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let header = frame.get(at..at + 2)?;
                next = header[0];
                at += (usize::from(header[1]) + 1) * 8;
            }
            44 => {
                let header = frame.get(at..at + 8)?;
                if u16::from_be_bytes([header[2], header[3]]) >> 3 != 0 {
                    return None;
                }
                next = header[0];
                at += 8;
            }
            _ => return Some((next, at)),
        }
    }
    None
}

fn build_error(
    out: &mut [u8; CONTROL_FRAME_MAX],
    invoking: &[u8],
    snapshot: &crate::ForwardingSnapshot<'_>,
    fib: &Ipv6Fib,
    ingress: IfId,
    (kind, code, parameter): (u8, u8, u32),
) -> Option<(IfId, usize)> {
    let ip = ETHERNET_HEADER;
    let source = address(invoking, ip + 8);
    let destination = address(invoking, ip + 24);
    // (e.1) no error about an ICMPv6 error; (e.2, e.3) none about multicast, except
    // Packet Too Big; (e.5) none to a source that is not one host.
    let is_error = upper_layer(invoking)
        .is_some_and(|(next, at)| next == ICMPV6 && invoking.get(at).is_some_and(|&t| t < 128));
    let multicast = is_multicast(destination) || invoking[0] & 1 != 0;
    if is_error
        || (multicast && kind != PACKET_TOO_BIG)
        || is_multicast(source)
        || is_unspecified_or_loopback(source)
    {
        return None;
    }
    let (egress, mac, from) = if is_link_local(source) && !snapshot.is_kernel_ingress(ingress) {
        // Back on its link, to the sender's MAC, from the router's link-local address
        // there.
        let egress = snapshot.interface(ingress)?;
        let mut mac = [0; 6];
        mac.copy_from_slice(&invoking[6..12]);
        let from = fib
            .local
            .iter()
            .find(|l| l.interface == ingress && is_link_local(l.address))?
            .address;
        (egress, MacAddress(mac), from)
    } else if snapshot.is_kernel_ingress(ingress) {
        // About the router's own packet: back through the kernel's interface, from
        // the packet's destination (every router address is the kernel's own).
        let mut mac = [0; 6];
        mac.copy_from_slice(&invoking[6..12]);
        (snapshot.interface(ingress)?, MacAddress(mac), destination)
    } else {
        let route = fib.route(source)?;
        let egress = snapshot.interface(route.egress)?;
        let mac = fib
            .neighbor(egress.id, route.next_hop.unwrap_or(source))
            .or(crate::pppoe::of(snapshot.pppoe, egress.id).map(|_| MacAddress([0; 6])))?;
        // An address of the router: on the egress interface if it has a global one.
        let from = fib
            .local
            .iter()
            .filter(|l| !is_link_local(l.address))
            .min_by_key(|l| l.interface != egress.id)?
            .address;
        (egress, mac, from)
    };
    let limit = ERROR_MAX.min(usize::from(egress.mtu));
    // The invoking packet itself: up to its Payload Length, not the frame's padding.
    let payload_len = usize::from(u16::from_be_bytes([invoking[ip + 4], invoking[ip + 5]]));
    let quoted = (invoking.len() - ip)
        .min(IPV6_HEADER + payload_len)
        .min(limit - IPV6_HEADER - 8);
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

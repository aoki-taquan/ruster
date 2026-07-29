use crate::nat44::{Nat44UdpInboundPlan, Nat44UdpOutboundPlan, Nat44UdpPlanError};
use crate::resolution::DynamicLookup;
use crate::{
    packet, rfc1624_update, route, validate_arp, validate_ipv4_frame, ArpOpcode, ArpRequestAction,
    BatchCompletion, ConsumeReason, ControlDisposition, Icmpv4ErrorAction, Icmpv4ErrorDisposition,
    Icmpv4ErrorKind, Icmpv4ErrorRuntime, Icmpv4TimeExceededDisposition, IfId, Interface,
    LocalIpv4Binding, MonotonicMillis, Nat44UdpConfig, Nat44UdpDisposition, Nat44UdpRuntime,
    Neighbor, PacketBatch, ResolutionResult, ResolutionRuntime, Route, ARP_ETHERTYPE,
    IPV4_ETHERTYPE,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum DropReason {
    EthernetHeaderTruncated = 1,
    UnsupportedEtherType = 2,
    Ipv4HeaderTruncated = 3,
    Ipv4VersionUnsupported = 4,
    Ipv4IhlTooSmall = 5,
    Ipv4HeaderLengthExceedsPacket = 6,
    Ipv4TotalLengthTooSmall = 7,
    Ipv4TotalLengthExceedsPacket = 8,
    Ipv4HeaderChecksumInvalid = 9,
    Ipv4OptionsUnsupported = 10,
    Ipv4TtlExpired = 11,
    RouteMiss = 12,
    NeighborUnresolved = 13,
    InterfaceMiss = 14,
    ArpPacketTruncated = 15,
    ArpHardwareTypeUnsupported = 16,
    ArpProtocolTypeUnsupported = 17,
    ArpHardwareLengthUnsupported = 18,
    ArpProtocolLengthUnsupported = 19,
    ArpReplyUnsupported = 20,
    ArpOpcodeUnsupported = 21,
    ArpTargetNotLocal = 22,
    ArpSenderHardwareZero = 23,
    ArpSenderHardwareBroadcast = 24,
    ArpSenderHardwareMulticast = 25,
    Icmpv4HeaderTruncated = 26,
    Icmpv4EchoHeaderTruncated = 27,
    Icmpv4ChecksumInvalid = 28,
    Icmpv4EchoCodeInvalid = 29,
    Icmpv4FragmentUnsupported = 30,
    Icmpv4SourceNotUnicast = 31,
    Icmpv4EthernetSourceInvalid = 32,
    Icmpv4EthernetDestinationNotLocal = 33,
    Nat44UdpRuntimeUnavailable = 34,
    Nat44UdpConfigMismatch = 35,
    Nat44UdpUnsupportedTransport = 36,
    Nat44UdpHairpinUnsupported = 37,
    Nat44UdpNonAtomicIpv4Unsupported = 38,
    Nat44UdpHeaderTruncated = 39,
    Nat44UdpLengthTooSmall = 40,
    Nat44UdpLengthExceedsIpv4Payload = 41,
    Nat44UdpSourcePortZero = 42,
    Nat44UdpSourceForbidden = 43,
    Nat44UdpReverseAuthorityMismatch = 44,
    Nat44UdpMappingMiss = 45,
    Nat44UdpFilterDenied = 46,
    Nat44UdpMappingTableFull = 47,
    Nat44UdpPeerTableFull = 48,
    Nat44UdpPortExhausted = 49,
    Nat44UdpClockRegression = 50,
    Nat44UdpWrongIngress = 51,
    Nat44UdpWrongEgress = 52,
    Nat44ExternalToInternalBypass = 53,
}

use DropReason::*;

impl DropReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            EthernetHeaderTruncated => "ETHERNET_HEADER_TRUNCATED",
            UnsupportedEtherType => "UNSUPPORTED_ETHERTYPE",
            Ipv4HeaderTruncated => "IPV4_HEADER_TRUNCATED",
            Ipv4VersionUnsupported => "IPV4_VERSION_UNSUPPORTED",
            Ipv4IhlTooSmall => "IPV4_IHL_TOO_SMALL",
            Ipv4HeaderLengthExceedsPacket => "IPV4_HEADER_LENGTH_EXCEEDS_PACKET",
            Ipv4TotalLengthTooSmall => "IPV4_TOTAL_LENGTH_TOO_SMALL",
            Ipv4TotalLengthExceedsPacket => "IPV4_TOTAL_LENGTH_EXCEEDS_PACKET",
            Ipv4HeaderChecksumInvalid => "IPV4_HEADER_CHECKSUM_INVALID",
            Ipv4OptionsUnsupported => "IPV4_OPTIONS_UNSUPPORTED",
            Ipv4TtlExpired => "IPV4_TTL_EXPIRED",
            RouteMiss => "ROUTE_MISS",
            NeighborUnresolved => "NEIGHBOR_UNRESOLVED",
            InterfaceMiss => "INTERFACE_MISS",
            ArpPacketTruncated => "ARP_PACKET_TRUNCATED",
            ArpHardwareTypeUnsupported => "ARP_HARDWARE_TYPE_UNSUPPORTED",
            ArpProtocolTypeUnsupported => "ARP_PROTOCOL_TYPE_UNSUPPORTED",
            ArpHardwareLengthUnsupported => "ARP_HARDWARE_LENGTH_UNSUPPORTED",
            ArpProtocolLengthUnsupported => "ARP_PROTOCOL_LENGTH_UNSUPPORTED",
            ArpReplyUnsupported => "ARP_REPLY_UNSUPPORTED",
            ArpOpcodeUnsupported => "ARP_OPCODE_UNSUPPORTED",
            ArpTargetNotLocal => "ARP_TARGET_NOT_LOCAL",
            ArpSenderHardwareZero => "ARP_SENDER_HARDWARE_ZERO",
            ArpSenderHardwareBroadcast => "ARP_SENDER_HARDWARE_BROADCAST",
            ArpSenderHardwareMulticast => "ARP_SENDER_HARDWARE_MULTICAST",
            Icmpv4HeaderTruncated => "ICMPV4_HEADER_TRUNCATED",
            Icmpv4EchoHeaderTruncated => "ICMPV4_ECHO_HEADER_TRUNCATED",
            Icmpv4ChecksumInvalid => "ICMPV4_CHECKSUM_INVALID",
            Icmpv4EchoCodeInvalid => "ICMPV4_ECHO_CODE_INVALID",
            Icmpv4FragmentUnsupported => "ICMPV4_FRAGMENT_UNSUPPORTED",
            Icmpv4SourceNotUnicast => "ICMPV4_SOURCE_NOT_UNICAST",
            Icmpv4EthernetSourceInvalid => "ICMPV4_ETHERNET_SOURCE_INVALID",
            Icmpv4EthernetDestinationNotLocal => "ICMPV4_ETHERNET_DESTINATION_NOT_LOCAL",
            Nat44UdpRuntimeUnavailable => "NAT44_UDP_RUNTIME_UNAVAILABLE",
            Nat44UdpConfigMismatch => "NAT44_UDP_CONFIG_MISMATCH",
            Nat44UdpUnsupportedTransport => "NAT44_UDP_UNSUPPORTED_TRANSPORT",
            Nat44UdpHairpinUnsupported => "NAT44_UDP_HAIRPIN_UNSUPPORTED",
            Nat44UdpNonAtomicIpv4Unsupported => "NAT44_UDP_NON_ATOMIC_IPV4_UNSUPPORTED",
            Nat44UdpHeaderTruncated => "NAT44_UDP_HEADER_TRUNCATED",
            Nat44UdpLengthTooSmall => "NAT44_UDP_LENGTH_TOO_SMALL",
            Nat44UdpLengthExceedsIpv4Payload => "NAT44_UDP_LENGTH_EXCEEDS_IPV4_PAYLOAD",
            Nat44UdpSourcePortZero => "NAT44_UDP_SOURCE_PORT_ZERO",
            Nat44UdpSourceForbidden => "NAT44_UDP_SOURCE_FORBIDDEN",
            Nat44UdpReverseAuthorityMismatch => "NAT44_UDP_REVERSE_AUTHORITY_MISMATCH",
            Nat44UdpMappingMiss => "NAT44_UDP_MAPPING_MISS",
            Nat44UdpFilterDenied => "NAT44_UDP_FILTER_DENIED",
            Nat44UdpMappingTableFull => "NAT44_UDP_MAPPING_TABLE_FULL",
            Nat44UdpPeerTableFull => "NAT44_UDP_PEER_TABLE_FULL",
            Nat44UdpPortExhausted => "NAT44_UDP_PORT_EXHAUSTED",
            Nat44UdpClockRegression => "NAT44_UDP_CLOCK_REGRESSION",
            Nat44UdpWrongIngress => "NAT44_UDP_WRONG_INGRESS",
            Nat44UdpWrongEgress => "NAT44_UDP_WRONG_EGRESS",
            Nat44ExternalToInternalBypass => "NAT44_EXTERNAL_TO_INTERNAL_BYPASS",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    DuplicateRoute,
    DuplicateInterface,
    DuplicateNeighbor,
    RouteUnknownInterface,
    NeighborUnknownInterface,
    DuplicateLocalIpv4Binding,
    LocalIpv4BindingUnknownInterface,
    LocalIpv4BindingUnspecified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4OriginPolicy {
    default_ttl: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ipv4OriginPolicyError {
    DefaultTtlZero,
}

impl Ipv4OriginPolicy {
    pub const fn new(default_ttl: u8) -> Result<Self, Ipv4OriginPolicyError> {
        if default_ttl == 0 {
            return Err(Ipv4OriginPolicyError::DefaultTtlZero);
        }
        Ok(Self { default_ttl })
    }

    #[must_use]
    pub const fn default_ttl(self) -> u8 {
        self.default_ttl
    }
}

impl Default for Ipv4OriginPolicy {
    fn default() -> Self {
        Self { default_ttl: 64 }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ForwardingSnapshot<'a> {
    pub(crate) routes: &'a [Route],
    pub(crate) interfaces: &'a [Interface],
    pub(crate) neighbors: &'a [Neighbor],
    pub(crate) local_ipv4: &'a [LocalIpv4Binding],
    pub(crate) ipv4_origin: Ipv4OriginPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResolutionActionAuthority {
    Valid,
    StaticResolved,
    Invalid,
}

impl<'a> ForwardingSnapshot<'a> {
    pub fn new(
        routes: &'a [Route],
        interfaces: &'a [Interface],
        neighbors: &'a [Neighbor],
        local_ipv4: &'a [LocalIpv4Binding],
    ) -> Result<Self, SnapshotError> {
        Self::with_ipv4_origin_policy(
            routes,
            interfaces,
            neighbors,
            local_ipv4,
            Ipv4OriginPolicy::default(),
        )
    }

    pub fn with_ipv4_origin_policy(
        routes: &'a [Route],
        interfaces: &'a [Interface],
        neighbors: &'a [Neighbor],
        local_ipv4: &'a [LocalIpv4Binding],
        ipv4_origin: Ipv4OriginPolicy,
    ) -> Result<Self, SnapshotError> {
        for (index, route) in routes.iter().enumerate() {
            if routes[..index].iter().any(|candidate| {
                candidate.prefix() == route.prefix() && candidate.prefix_len() == route.prefix_len()
            }) {
                return Err(SnapshotError::DuplicateRoute);
            }
            if !interfaces
                .iter()
                .any(|interface| interface.id == route.egress())
            {
                return Err(SnapshotError::RouteUnknownInterface);
            }
        }
        for (index, interface) in interfaces.iter().enumerate() {
            if interfaces[..index]
                .iter()
                .any(|candidate| candidate.id == interface.id)
            {
                return Err(SnapshotError::DuplicateInterface);
            }
        }
        for (index, neighbor) in neighbors.iter().enumerate() {
            if neighbors[..index].iter().any(|candidate| {
                candidate.interface == neighbor.interface && candidate.target == neighbor.target
            }) {
                return Err(SnapshotError::DuplicateNeighbor);
            }
            if !interfaces
                .iter()
                .any(|interface| interface.id == neighbor.interface)
            {
                return Err(SnapshotError::NeighborUnknownInterface);
            }
        }
        for (index, binding) in local_ipv4.iter().enumerate() {
            if binding.address.is_unspecified() {
                return Err(SnapshotError::LocalIpv4BindingUnspecified);
            }
            if local_ipv4[..index].iter().any(|candidate| {
                candidate.interface == binding.interface || candidate.address == binding.address
            }) {
                return Err(SnapshotError::DuplicateLocalIpv4Binding);
            }
            if !interfaces
                .iter()
                .any(|interface| interface.id == binding.interface)
            {
                return Err(SnapshotError::LocalIpv4BindingUnknownInterface);
            }
        }
        Ok(Self {
            routes,
            interfaces,
            neighbors,
            local_ipv4,
            ipv4_origin,
        })
    }

    pub(crate) fn resolution_action_authority(
        &self,
        action: ArpRequestAction,
    ) -> ResolutionActionAuthority {
        if self.neighbors.iter().any(|neighbor| {
            neighbor.interface == action.egress && neighbor.target == action.target_ip
        }) {
            return ResolutionActionAuthority::StaticResolved;
        }
        if !self
            .interfaces
            .iter()
            .any(|interface| interface.id == action.egress && interface.mac == action.source_mac)
            || !self.local_ipv4.iter().any(|binding| {
                binding.interface == action.egress && binding.address == action.source_ip
            })
        {
            return ResolutionActionAuthority::Invalid;
        }
        let target = action.target_ip;
        let octets = target.octets();
        if target == action.source_ip
            || octets[0] == 0
            || octets[0] == 127
            || octets[0] >= 224
            || octets == [255; 4]
            || self
                .local_ipv4
                .iter()
                .any(|binding| binding.address == target)
            || self.routes.iter().any(|route| {
                route.egress() == action.egress
                    && (route.is_connected_network_address(target)
                        || route.is_connected_directed_broadcast(target))
            })
        {
            return ResolutionActionAuthority::Invalid;
        }
        let route_still_authorizes = self
            .routes
            .iter()
            .any(|route| route.egress() == action.egress && route.next_hop() == Some(target))
            || route::lookup(self.routes, target)
                .is_some_and(|route| route.egress() == action.egress && route.next_hop().is_none());
        if route_still_authorizes {
            ResolutionActionAuthority::Valid
        } else {
            ResolutionActionAuthority::Invalid
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TraceEvent {
    Ipv4Validated {
        ingress: IfId,
        destination: crate::Ipv4Address,
    },
    Icmpv4EchoRequestValidated {
        ingress: IfId,
        source: crate::Ipv4Address,
        destination: crate::Ipv4Address,
    },
    Icmpv4TimeExceededDisposition {
        ingress: IfId,
        disposition: Icmpv4ErrorDisposition,
    },
    Icmpv4DestinationUnreachableDisposition {
        ingress: IfId,
        disposition: Icmpv4ErrorDisposition,
    },
    ArpRequestValidated {
        ingress: IfId,
        sender_protocol: crate::Ipv4Address,
        target_protocol: crate::Ipv4Address,
    },
    ArpReplyValidated {
        ingress: IfId,
        sender_protocol: crate::Ipv4Address,
        target_protocol: crate::Ipv4Address,
    },
    ArpControl {
        ingress: IfId,
        disposition: ControlDisposition,
    },
    Routed {
        egress: IfId,
        neighbor_target: crate::Ipv4Address,
    },
    NeighborResolution {
        egress: IfId,
        target: crate::Ipv4Address,
        result: ResolutionResult,
    },
    /// The packet was handed to the backend, not necessarily accepted by TX.
    TxRequested {
        egress: IfId,
    },
    ArpReplyRequested {
        egress: IfId,
        target_protocol: crate::Ipv4Address,
    },
    Icmpv4EchoReplyRequested {
        egress: IfId,
        source: crate::Ipv4Address,
        destination: crate::Ipv4Address,
    },
    Nat44Udp {
        ingress: IfId,
        disposition: Nat44UdpDisposition,
    },
    Dropped {
        ingress: IfId,
        reason: DropReason,
    },
    Consumed {
        ingress: IfId,
        reason: ConsumeReason,
        disposition: ControlDisposition,
    },
    Ipv4LocalConsumed {
        ingress: IfId,
        reason: ConsumeReason,
    },
    BatchCompleted {
        tx_accepted: usize,
        tx_rejected: usize,
    },
}

/// A trace sink must not panic. A panic is a contract violation; RAII still
/// recycles an outstanding lease, but tracing must never disrupt forwarding.
pub trait TraceSink {
    fn record(&mut self, event: TraceEvent);
}

#[derive(Default)]
pub struct NoTrace;

impl TraceSink for NoTrace {
    #[inline]
    fn record(&mut self, _event: TraceEvent) {}
}

#[derive(Debug, Eq, PartialEq)]
pub struct BatchReport<E> {
    pub received: usize,
    /// Packets requested for TX; this does not mean backend or wire acceptance.
    pub tx_requested: usize,
    pub dropped: usize,
    pub consumed: usize,
    pub completion: BatchCompletion<E>,
}

#[derive(Clone, Copy)]
struct Ipv4RewriteDecision {
    egress: IfId,
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    ttl_offset: usize,
    checksum_offset: usize,
    checksum_end: usize,
    old_ttl_protocol: u16,
    new_ttl_protocol: u16,
    old_checksum: u16,
}

#[derive(Clone, Copy)]
struct ArpReplyDecision {
    egress: IfId,
    local_mac: [u8; 6],
    requester_mac: [u8; 6],
    requester_protocol: [u8; 4],
    local_protocol: [u8; 4],
}

#[derive(Clone, Copy)]
struct Icmpv4EchoReplyDecision {
    egress: IfId,
    local_mac: [u8; 6],
    requester_mac: [u8; 6],
    local_ip: [u8; 4],
    requester_ip: [u8; 4],
    ipv4_checksum: u16,
    icmp_checksum: u16,
    reply_ttl: u8,
    icmp_offset: usize,
    icmp_end: usize,
}

#[derive(Clone, Copy)]
enum Nat44UdpTransition {
    Outbound(Nat44UdpOutboundPlan),
    Inbound(Nat44UdpInboundPlan),
}

#[derive(Clone, Copy)]
struct Nat44UdpRewriteDecision {
    forwarding: Ipv4RewriteDecision,
    address_offset: usize,
    address_end: usize,
    new_address: [u8; 4],
    port_offset: usize,
    port_end: usize,
    new_port: u16,
    udp_checksum_offset: usize,
    udp_checksum_end: usize,
    ipv4_checksum: u16,
    udp_checksum: u16,
    transition: Nat44UdpTransition,
    disposition: Nat44UdpDisposition,
}

#[derive(Clone, Copy)]
enum PacketDecision {
    Ipv4(Ipv4RewriteDecision),
    Nat44Udp(Nat44UdpRewriteDecision),
    ArpReply(ArpReplyDecision),
    Icmpv4EchoReply(Icmpv4EchoReplyDecision),
    ConsumeArp(ControlDisposition),
    ConsumeIpv4Local,
}

impl PacketDecision {
    fn egress(self) -> IfId {
        match self {
            Self::Ipv4(decision) => decision.egress,
            Self::Nat44Udp(decision) => decision.forwarding.egress,
            Self::ArpReply(decision) => decision.egress,
            Self::Icmpv4EchoReply(decision) => decision.egress,
            Self::ConsumeArp(_) | Self::ConsumeIpv4Local => {
                unreachable!("consumed controls have no egress")
            }
        }
    }
}

pub fn forward_batch<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    forward_batch_inner(batch, snapshot, None, None, None, None, trace)
}

/// Forwards RX packets and queues resolution actions without allocating TX
/// frames. Generated execution must start only after this function returns.
pub fn forward_batch_with_resolution<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    forward_batch_inner(
        batch,
        snapshot,
        Some((runtime, now)),
        None,
        None,
        None,
        trace,
    )
}

/// Forwards RX packets while queueing ARP resolution and eligible ICMPv4 error
/// actions into separate caller-backed worker-local runtimes.
///
/// Generated packet execution must happen after this function returns.
pub fn forward_batch_with_resolution_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    forward_batch_inner(
        batch,
        snapshot,
        Some((resolution, now)),
        Some((icmpv4_errors, now)),
        None,
        None,
        trace,
    )
}

/// Runs the forwarding, ARP resolution, and one configured UDP NAPT domain as
/// one ordered worker-local service.
///
/// Passing `None` for `nat44_udp` deliberately fails closed for packets that
/// cross the configured inside/outside boundary. This lets a control plane
/// publish configuration before runtime storage without leaking private
/// addresses. Generated ARP execution remains a separate post-RX phase.
pub fn forward_batch_with_nat44_udp<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    forward_batch_inner(
        batch,
        snapshot,
        Some((resolution, now)),
        None,
        Some(config),
        nat44_udp,
        trace,
    )
}

/// Runs the complete ARP-resolution, generated-ICMPv4-error, and UDP NAPT
/// service composition in one ordered RX phase.
///
/// TTL expiry, route miss, and direct ARP failure capture happen before NAT
/// mutation and therefore quote the original datagram. Generated packet
/// execution still starts only after this RX function returns.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    forward_batch_inner(
        batch,
        snapshot,
        Some((resolution, now)),
        Some((icmpv4_errors, now)),
        Some(config),
        nat44_udp,
        trace,
    )
}

fn forward_batch_inner<B, T>(
    mut batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    mut resolution: Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    mut icmpv4_errors: Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    mut nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    let mut received = 0;
    let mut tx_requested = 0;
    let mut dropped = 0;
    let mut consumed = 0;
    while let Some(mut packet) = batch.next_packet() {
        received += 1;
        let ingress = packet.ingress();
        let nat_now_ms = resolution.as_ref().map_or(0, |(_, now)| now.0);
        let result = {
            let frame = packet.bytes_mut();
            decide(
                &*frame,
                snapshot,
                ingress,
                &mut resolution,
                &mut icmpv4_errors,
                nat44_udp_config,
                &mut nat44_udp,
                trace,
            )
            .and_then(|decision| {
                if matches!(
                    decision,
                    PacketDecision::ConsumeArp(_) | PacketDecision::ConsumeIpv4Local
                ) {
                    Ok(decision)
                } else {
                    apply_decision(frame, decision).map(|()| decision)
                }
            })
        };
        match result {
            Ok(PacketDecision::ConsumeArp(disposition)) => {
                packet.consume(ConsumeReason::ArpControl);
                consumed += 1;
                trace.record(TraceEvent::Consumed {
                    ingress,
                    reason: ConsumeReason::ArpControl,
                    disposition,
                });
            }
            Ok(PacketDecision::ConsumeIpv4Local) => {
                packet.consume(ConsumeReason::Ipv4LocalUnsupported);
                consumed += 1;
                trace.record(TraceEvent::Ipv4LocalConsumed {
                    ingress,
                    reason: ConsumeReason::Ipv4LocalUnsupported,
                });
            }
            Ok(decision) => {
                let egress = decision.egress();
                if let PacketDecision::Nat44Udp(nat) = decision {
                    let runtime = nat44_udp
                        .as_deref_mut()
                        .expect("NAT decision requires a bound runtime");
                    match nat.transition {
                        Nat44UdpTransition::Outbound(plan) => {
                            runtime.commit_outbound(plan, nat_now_ms);
                        }
                        Nat44UdpTransition::Inbound(plan) => {
                            runtime.commit_inbound(plan, nat_now_ms);
                        }
                    }
                    trace.record(TraceEvent::Nat44Udp {
                        ingress,
                        disposition: nat.disposition,
                    });
                }
                packet.commit(egress);
                tx_requested += 1;
                if let PacketDecision::ArpReply(arp) = decision {
                    trace.record(TraceEvent::ArpReplyRequested {
                        egress,
                        target_protocol: crate::Ipv4Address::from_octets(arp.requester_protocol),
                    });
                }
                if let PacketDecision::Icmpv4EchoReply(icmp) = decision {
                    trace.record(TraceEvent::Icmpv4EchoReplyRequested {
                        egress,
                        source: crate::Ipv4Address::from_octets(icmp.local_ip),
                        destination: crate::Ipv4Address::from_octets(icmp.requester_ip),
                    });
                }
                trace.record(TraceEvent::TxRequested { egress });
            }
            Err(reason) => {
                packet.recycle(reason);
                dropped += 1;
                trace.record(TraceEvent::Dropped { ingress, reason });
            }
        }
    }
    let completion = batch.finish();
    debug_assert_eq!(received, tx_requested + dropped + consumed);
    trace.record(TraceEvent::BatchCompleted {
        tx_accepted: completion.tx_accepted,
        tx_rejected: completion.tx_rejected,
    });
    BatchReport {
        received,
        tx_requested,
        dropped,
        consumed,
        completion,
    }
}

#[allow(clippy::too_many_arguments)]
fn decide<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let ether_type = packet::read_u16(frame, 12).ok_or(EthernetHeaderTruncated)?;
    match ether_type {
        IPV4_ETHERTYPE => decide_ipv4(
            frame,
            snapshot,
            ingress,
            resolution,
            icmpv4_errors,
            nat44_udp_config,
            nat44_udp,
            trace,
        ),
        ARP_ETHERTYPE => decide_arp(frame, snapshot, ingress, resolution, trace),
        _ => Err(UnsupportedEtherType),
    }
}

#[allow(clippy::too_many_arguments)]
fn decide_ipv4<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let ipv4 = validate_ipv4_frame(frame)?;
    trace.record(TraceEvent::Ipv4Validated {
        ingress,
        destination: ipv4.destination,
    });
    if let Some(config) = nat44_udp_config {
        if ingress == config.inside() && ipv4.destination == config.public_address() {
            observe_nat_candidate_if_present(
                snapshot,
                config,
                nat44_udp,
                resolution
                    .as_ref()
                    .map_or(MonotonicMillis(0), |(_, now)| *now),
                ingress,
                trace,
            )?;
            return nat44_udp_drop(ingress, Nat44UdpHairpinUnsupported, trace);
        }
        if ipv4.destination == config.public_address() && ipv4.protocol == 17 {
            if ingress != config.outside() {
                observe_nat_candidate_if_present(
                    snapshot,
                    config,
                    nat44_udp,
                    resolution
                        .as_ref()
                        .map_or(MonotonicMillis(0), |(_, now)| *now),
                    ingress,
                    trace,
                )?;
                return nat44_udp_drop(ingress, Nat44UdpWrongIngress, trace);
            }
            return decide_nat44_udp_inbound(
                frame, snapshot, ingress, ipv4, resolution, config, nat44_udp, trace,
            );
        }
    }
    let local = snapshot
        .local_ipv4
        .iter()
        .any(|binding| binding.interface == ingress && binding.address == ipv4.destination);
    if local {
        return decide_local_ipv4(frame, snapshot, ingress, ipv4, trace);
    }
    if ipv4.header_len > 20 {
        return Err(Ipv4OptionsUnsupported);
    }
    let route = route::lookup(snapshot.routes, ipv4.destination);
    let Some(route) = route else {
        if let Some((runtime, now)) = icmpv4_errors.as_mut() {
            let disposition = decide_icmpv4_error(
                frame,
                snapshot,
                ipv4,
                None,
                Icmpv4ErrorKind::DestinationUnreachableNetwork,
                resolution,
                runtime,
                *now,
                trace,
            );
            trace.record(TraceEvent::Icmpv4DestinationUnreachableDisposition {
                ingress,
                disposition,
            });
        }
        return Err(RouteMiss);
    };
    if nat44_udp_config
        .is_some_and(|config| ingress == config.outside() && route.egress() == config.inside())
    {
        return nat44_udp_drop(ingress, Nat44ExternalToInternalBypass, trace);
    }
    if ipv4.ttl <= 1 {
        if let Some((runtime, now)) = icmpv4_errors.as_mut() {
            let disposition = decide_icmpv4_error(
                frame,
                snapshot,
                ipv4,
                Some(route),
                Icmpv4ErrorKind::TimeExceededTtl,
                resolution,
                runtime,
                *now,
                trace,
            );
            trace.record(TraceEvent::Icmpv4TimeExceededDisposition {
                ingress,
                disposition,
            });
        }
        return Err(Ipv4TtlExpired);
    }
    let target = route.next_hop().unwrap_or(ipv4.destination);
    let interface = snapshot
        .interfaces
        .iter()
        .find(|item| item.id == route.egress())
        .ok_or(InterfaceMiss)?;
    let static_neighbor = snapshot
        .neighbors
        .iter()
        .find(|item| item.interface == route.egress() && item.target == target);
    let destination_mac = if let Some(neighbor) = static_neighbor {
        neighbor.mac
    } else if let Some((runtime, now)) = resolution.as_mut() {
        match runtime.lookup_dynamic(route.egress(), target, *now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                trace.record(TraceEvent::NeighborResolution {
                    egress: route.egress(),
                    target,
                    result: ResolutionResult::ClockRegression,
                });
                return Err(NeighborUnresolved);
            }
            DynamicLookup::Miss => {
                if let Some(binding) = snapshot
                    .local_ipv4
                    .iter()
                    .find(|binding| binding.interface == route.egress())
                {
                    let result = runtime.schedule(
                        ArpRequestAction {
                            egress: route.egress(),
                            source_mac: interface.mac,
                            source_ip: binding.address,
                            target_ip: target,
                        },
                        *now,
                        snapshot
                            .local_ipv4
                            .iter()
                            .any(|binding| binding.address == target)
                            || snapshot.routes.iter().any(|candidate| {
                                candidate.egress() == route.egress()
                                    && (candidate.is_connected_directed_broadcast(target)
                                        || candidate.is_connected_network_address(target))
                            }),
                    );
                    trace.record(TraceEvent::NeighborResolution {
                        egress: route.egress(),
                        target,
                        result,
                    });
                    if route.next_hop().is_none()
                        && target == ipv4.destination
                        && icmp_error_candidate_eligible(frame, snapshot, ipv4, Some(route))
                    {
                        let quote_end = ipv4.header_offset + ipv4.total_len;
                        let _ = runtime.capture_failure_candidate(
                            route.egress(),
                            target,
                            ipv4.source,
                            ipv4.destination,
                            interface.mac,
                            binding.address,
                            route.prefix(),
                            route.prefix_len(),
                            frame[ipv4.header_offset + 1],
                            &frame[ipv4.header_offset..quote_end],
                        );
                    }
                }
                return Err(NeighborUnresolved);
            }
        }
    } else {
        return Err(NeighborUnresolved);
    };
    let ttl_offset = ipv4
        .header_offset
        .checked_add(8)
        .ok_or(Ipv4HeaderLengthExceedsPacket)?;
    let checksum_offset = ipv4
        .header_offset
        .checked_add(10)
        .ok_or(Ipv4HeaderLengthExceedsPacket)?;
    let checksum_end = checksum_offset
        .checked_add(2)
        .ok_or(Ipv4HeaderLengthExceedsPacket)?;
    trace.record(TraceEvent::Routed {
        egress: route.egress(),
        neighbor_target: target,
    });
    let forwarding = Ipv4RewriteDecision {
        egress: route.egress(),
        source_mac: interface.mac.0,
        destination_mac: destination_mac.0,
        ttl_offset,
        checksum_offset,
        checksum_end,
        old_ttl_protocol: u16::from_be_bytes([ipv4.ttl, ipv4.protocol]),
        new_ttl_protocol: u16::from_be_bytes([ipv4.ttl - 1, ipv4.protocol]),
        old_checksum: ipv4.checksum,
    };
    if let Some(config) = nat44_udp_config {
        if ingress == config.inside() && route.egress() == config.outside() {
            return decide_nat44_udp_outbound(
                frame,
                snapshot,
                ingress,
                ipv4,
                forwarding,
                config,
                nat44_udp,
                resolution
                    .as_ref()
                    .map_or(MonotonicMillis(0), |(_, now)| *now),
                trace,
            );
        }
    }
    Ok(PacketDecision::Ipv4(forwarding))
}

#[allow(clippy::too_many_arguments)]
fn decide_nat44_udp_outbound<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    forwarding: Ipv4RewriteDecision,
    config: &Nat44UdpConfig,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let runtime = require_nat44_udp_runtime(snapshot, config, nat44_udp, ingress, trace)?;
    if let Err(error) = runtime.observe_now(now.0) {
        let (reason, disposition) = nat44_udp_plan_error(error);
        trace.record(TraceEvent::Nat44Udp {
            ingress,
            disposition,
        });
        return Err(reason);
    }
    if ipv4.header_len > 20 {
        return nat44_udp_drop(ingress, Ipv4OptionsUnsupported, trace);
    }
    if ipv4.protocol != 17 {
        return nat44_udp_drop(ingress, Nat44UdpUnsupportedTransport, trace);
    }
    if let Err(reason) = validate_nat44_atomic(frame, ipv4) {
        return nat44_udp_drop(ingress, reason, trace);
    }
    let udp = match validate_nat44_udp(frame, ipv4) {
        Ok(udp) => udp,
        Err(reason) => return nat44_udp_drop(ingress, reason, trace),
    };
    if udp.source_port == 0 {
        return nat44_udp_drop(ingress, Nat44UdpSourcePortZero, trace);
    }
    if !icmp_error_source_is_host(snapshot, ipv4.source)
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == ipv4.source)
        || ipv4.source == config.public_address()
    {
        return nat44_udp_drop(ingress, Nat44UdpSourceForbidden, trace);
    }
    if route::lookup(snapshot.routes, ipv4.source)
        .is_none_or(|reverse| reverse.egress() != config.inside())
    {
        return nat44_udp_drop(ingress, Nat44UdpReverseAuthorityMismatch, trace);
    }
    let plan = match runtime.plan_outbound(ipv4.source, udp.source_port, ipv4.destination, now.0) {
        Ok(plan) => plan,
        Err(error) => {
            runtime.record_plan_error(error);
            let (reason, disposition) = nat44_udp_plan_error(error);
            trace.record(TraceEvent::Nat44Udp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    };
    build_nat44_udp_rewrite(
        ipv4,
        udp,
        forwarding,
        ipv4.source,
        config.public_address(),
        udp.source_port,
        plan.public_port(),
        Nat44UdpTransition::Outbound(plan),
        plan.disposition(),
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_nat44_udp_inbound<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    config: &Nat44UdpConfig,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let now = resolution
        .as_ref()
        .map_or(MonotonicMillis(0), |(_, now)| *now);
    let runtime = require_nat44_udp_runtime(snapshot, config, nat44_udp, ingress, trace)?;
    if let Err(error) = runtime.observe_now(now.0) {
        let (reason, disposition) = nat44_udp_plan_error(error);
        trace.record(TraceEvent::Nat44Udp {
            ingress,
            disposition,
        });
        return Err(reason);
    }
    if ipv4.header_len > 20 {
        return nat44_udp_drop(ingress, Ipv4OptionsUnsupported, trace);
    }
    if let Err(reason) = validate_nat44_atomic(frame, ipv4) {
        return nat44_udp_drop(ingress, reason, trace);
    }
    let udp = match validate_nat44_udp(frame, ipv4) {
        Ok(udp) => udp,
        Err(reason) => return nat44_udp_drop(ingress, reason, trace),
    };
    if ipv4.ttl <= 1 {
        return nat44_udp_drop(ingress, Ipv4TtlExpired, trace);
    }
    if !icmp_error_source_is_host(snapshot, ipv4.source)
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == ipv4.source)
    {
        return nat44_udp_drop(ingress, Nat44UdpSourceForbidden, trace);
    }
    let plan = match runtime.plan_inbound(udp.destination_port, ipv4.source, now.0) {
        Ok(plan) => plan,
        Err(error) => {
            runtime.record_plan_error(error);
            let (reason, disposition) = nat44_udp_plan_error(error);
            trace.record(TraceEvent::Nat44Udp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    };
    let internal_address = plan.internal_address();
    let Some(reverse_route) = route::lookup(snapshot.routes, internal_address) else {
        return nat44_udp_drop(ingress, Nat44UdpReverseAuthorityMismatch, trace);
    };
    if reverse_route.egress() != config.inside() {
        return nat44_udp_drop(ingress, Nat44UdpWrongEgress, trace);
    }
    let target = reverse_route.next_hop().unwrap_or(internal_address);
    let interface = snapshot
        .interfaces
        .iter()
        .find(|interface| interface.id == reverse_route.egress())
        .ok_or(InterfaceMiss)?;
    let destination_mac = if let Some(neighbor) = snapshot
        .neighbors
        .iter()
        .find(|neighbor| neighbor.interface == reverse_route.egress() && neighbor.target == target)
    {
        neighbor.mac
    } else if let Some((resolution_runtime, resolution_now)) = resolution.as_mut() {
        match resolution_runtime.lookup_dynamic(reverse_route.egress(), target, *resolution_now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                return nat44_udp_drop(ingress, NeighborUnresolved, trace);
            }
            DynamicLookup::Miss => {
                if let Some(binding) = snapshot
                    .local_ipv4
                    .iter()
                    .find(|binding| binding.interface == reverse_route.egress())
                {
                    let result = resolution_runtime.schedule(
                        ArpRequestAction {
                            egress: reverse_route.egress(),
                            source_mac: interface.mac,
                            source_ip: binding.address,
                            target_ip: target,
                        },
                        *resolution_now,
                        false,
                    );
                    trace.record(TraceEvent::NeighborResolution {
                        egress: reverse_route.egress(),
                        target,
                        result,
                    });
                }
                return nat44_udp_drop(ingress, NeighborUnresolved, trace);
            }
        }
    } else {
        return nat44_udp_drop(ingress, NeighborUnresolved, trace);
    };
    let ttl_offset = ipv4.header_offset + 8;
    let checksum_offset = ipv4.header_offset + 10;
    let forwarding = Ipv4RewriteDecision {
        egress: reverse_route.egress(),
        source_mac: interface.mac.0,
        destination_mac: destination_mac.0,
        ttl_offset,
        checksum_offset,
        checksum_end: checksum_offset + 2,
        old_ttl_protocol: u16::from_be_bytes([ipv4.ttl, ipv4.protocol]),
        new_ttl_protocol: u16::from_be_bytes([ipv4.ttl - 1, ipv4.protocol]),
        old_checksum: ipv4.checksum,
    };
    trace.record(TraceEvent::Routed {
        egress: reverse_route.egress(),
        neighbor_target: target,
    });
    build_nat44_udp_rewrite(
        ipv4,
        udp,
        forwarding,
        ipv4.destination,
        internal_address,
        udp.destination_port,
        plan.internal_port(),
        Nat44UdpTransition::Inbound(plan),
        plan.disposition(),
    )
}

#[derive(Clone, Copy)]
struct ValidatedNat44Udp {
    offset: usize,
    source_port: u16,
    destination_port: u16,
    checksum: u16,
}

fn validate_nat44_atomic(frame: &[u8], ipv4: packet::ValidatedIpv4) -> Result<(), DropReason> {
    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(Ipv4HeaderLengthExceedsPacket)?;
    if flags_fragment != 0x4000 {
        return Err(Nat44UdpNonAtomicIpv4Unsupported);
    }
    Ok(())
}

fn validate_nat44_udp(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Result<ValidatedNat44Udp, DropReason> {
    let offset = ipv4
        .header_offset
        .checked_add(ipv4.header_len)
        .ok_or(Nat44UdpHeaderTruncated)?;
    let ipv4_end = ipv4
        .header_offset
        .checked_add(ipv4.total_len)
        .ok_or(Nat44UdpHeaderTruncated)?;
    let header_end = offset.checked_add(8).ok_or(Nat44UdpHeaderTruncated)?;
    if header_end > ipv4_end || frame.get(offset..header_end).is_none() {
        return Err(Nat44UdpHeaderTruncated);
    }
    let length = usize::from(packet::read_u16(frame, offset + 4).ok_or(Nat44UdpHeaderTruncated)?);
    if length < 8 {
        return Err(Nat44UdpLengthTooSmall);
    }
    let payload_len = ipv4.total_len - ipv4.header_len;
    if length > payload_len {
        return Err(Nat44UdpLengthExceedsIpv4Payload);
    }
    Ok(ValidatedNat44Udp {
        offset,
        source_port: packet::read_u16(frame, offset).ok_or(Nat44UdpHeaderTruncated)?,
        destination_port: packet::read_u16(frame, offset + 2).ok_or(Nat44UdpHeaderTruncated)?,
        checksum: packet::read_u16(frame, offset + 6).ok_or(Nat44UdpHeaderTruncated)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_nat44_udp_rewrite(
    ipv4: packet::ValidatedIpv4,
    udp: ValidatedNat44Udp,
    forwarding: Ipv4RewriteDecision,
    old_address: crate::Ipv4Address,
    new_address: crate::Ipv4Address,
    old_port: u16,
    new_port: u16,
    transition: Nat44UdpTransition,
    disposition: Nat44UdpDisposition,
) -> Result<PacketDecision, DropReason> {
    let outbound = matches!(transition, Nat44UdpTransition::Outbound(_));
    let address_offset = ipv4
        .header_offset
        .checked_add(if outbound { 12 } else { 16 })
        .ok_or(Ipv4HeaderLengthExceedsPacket)?;
    let address_end = address_offset
        .checked_add(4)
        .ok_or(Ipv4HeaderLengthExceedsPacket)?;
    let port_offset = udp
        .offset
        .checked_add(if outbound { 0 } else { 2 })
        .ok_or(Nat44UdpHeaderTruncated)?;
    let port_end = port_offset.checked_add(2).ok_or(Nat44UdpHeaderTruncated)?;
    let udp_checksum_offset = udp.offset.checked_add(6).ok_or(Nat44UdpHeaderTruncated)?;
    let udp_checksum_end = udp_checksum_offset
        .checked_add(2)
        .ok_or(Nat44UdpHeaderTruncated)?;
    let old_octets = old_address.octets();
    let new_octets = new_address.octets();
    let old_high = u16::from_be_bytes([old_octets[0], old_octets[1]]);
    let old_low = u16::from_be_bytes([old_octets[2], old_octets[3]]);
    let new_high = u16::from_be_bytes([new_octets[0], new_octets[1]]);
    let new_low = u16::from_be_bytes([new_octets[2], new_octets[3]]);
    let ipv4_checksum = rfc1624_update(
        rfc1624_update(
            rfc1624_update(
                forwarding.old_checksum,
                forwarding.old_ttl_protocol,
                forwarding.new_ttl_protocol,
            ),
            old_high,
            new_high,
        ),
        old_low,
        new_low,
    );
    let udp_checksum = if udp.checksum == 0 {
        0
    } else {
        let updated = rfc1624_update(
            rfc1624_update(
                rfc1624_update(udp.checksum, old_high, new_high),
                old_low,
                new_low,
            ),
            old_port,
            new_port,
        );
        if updated == 0 {
            0xffff
        } else {
            updated
        }
    };
    Ok(PacketDecision::Nat44Udp(Nat44UdpRewriteDecision {
        forwarding,
        address_offset,
        address_end,
        new_address: new_octets,
        port_offset,
        port_end,
        new_port,
        udp_checksum_offset,
        udp_checksum_end,
        ipv4_checksum,
        udp_checksum,
        transition,
        disposition,
    }))
}

fn nat44_udp_plan_error(error: Nat44UdpPlanError) -> (DropReason, Nat44UdpDisposition) {
    match error {
        Nat44UdpPlanError::MappingMiss => (Nat44UdpMappingMiss, Nat44UdpDisposition::MappingMiss),
        Nat44UdpPlanError::FilterDenied => {
            (Nat44UdpFilterDenied, Nat44UdpDisposition::FilterDenied)
        }
        Nat44UdpPlanError::MappingFull => {
            (Nat44UdpMappingTableFull, Nat44UdpDisposition::MappingFull)
        }
        Nat44UdpPlanError::PeerFull => (Nat44UdpPeerTableFull, Nat44UdpDisposition::PeerFull),
        Nat44UdpPlanError::PortExhausted => {
            (Nat44UdpPortExhausted, Nat44UdpDisposition::PortExhausted)
        }
        Nat44UdpPlanError::ClockRegression => (
            Nat44UdpClockRegression,
            Nat44UdpDisposition::ClockRegression,
        ),
    }
}

fn nat44_udp_drop<T: TraceSink>(
    ingress: IfId,
    reason: DropReason,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    trace.record(TraceEvent::Nat44Udp {
        ingress,
        disposition: Nat44UdpDisposition::Rejected { reason },
    });
    Err(reason)
}

fn require_nat44_udp_runtime<'runtime, 'storage, T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    config: &Nat44UdpConfig,
    runtime: &'runtime mut Option<&mut Nat44UdpRuntime<'storage>>,
    ingress: IfId,
    trace: &mut T,
) -> Result<&'runtime mut Nat44UdpRuntime<'storage>, DropReason> {
    if !config.authority_matches(snapshot) {
        if let Some(runtime) = runtime.as_deref_mut() {
            runtime.record_config_mismatch();
        }
        trace.record(TraceEvent::Nat44Udp {
            ingress,
            disposition: Nat44UdpDisposition::ConfigMismatch,
        });
        return Err(Nat44UdpConfigMismatch);
    }
    let Some(runtime) = runtime.as_deref_mut() else {
        trace.record(TraceEvent::Nat44Udp {
            ingress,
            disposition: Nat44UdpDisposition::Rejected {
                reason: Nat44UdpRuntimeUnavailable,
            },
        });
        return Err(Nat44UdpRuntimeUnavailable);
    };
    if runtime.config() != *config {
        runtime.record_config_mismatch();
        trace.record(TraceEvent::Nat44Udp {
            ingress,
            disposition: Nat44UdpDisposition::ConfigMismatch,
        });
        return Err(Nat44UdpConfigMismatch);
    }
    Ok(runtime)
}

fn observe_nat_candidate_if_present<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    config: &Nat44UdpConfig,
    runtime: &mut Option<&mut Nat44UdpRuntime<'_>>,
    now: MonotonicMillis,
    ingress: IfId,
    trace: &mut T,
) -> Result<(), DropReason> {
    if runtime.is_none() {
        return Ok(());
    }
    let runtime = require_nat44_udp_runtime(snapshot, config, runtime, ingress, trace)?;
    if let Err(error) = runtime.observe_now(now.0) {
        let (reason, disposition) = nat44_udp_plan_error(error);
        trace.record(TraceEvent::Nat44Udp {
            ingress,
            disposition,
        });
        return Err(reason);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decide_icmpv4_error<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ipv4: packet::ValidatedIpv4,
    selected_destination_route: Option<Route>,
    kind: Icmpv4ErrorKind,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Icmpv4ErrorDisposition {
    if !runtime.observe_decision(now) {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ClockRegression);
    }
    if !icmp_error_source_is_host(snapshot, ipv4.source) {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::SourceNotUnicast);
    }
    if snapshot
        .local_ipv4
        .iter()
        .any(|binding| binding.address == ipv4.source)
    {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::SourceIsLocal);
    }

    let destination_octets = ipv4.destination.octets();
    if (destination_octets[0] & 0xf0) == 0xe0 {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::DestinationMulticast);
    }
    if destination_octets == [255; 4] {
        return runtime
            .record_suppression(Icmpv4TimeExceededDisposition::DestinationLimitedBroadcast);
    }
    if let Some(selected) = selected_destination_route {
        if selected.is_prefix_network_address(ipv4.destination) {
            return runtime
                .record_suppression(Icmpv4TimeExceededDisposition::DestinationNetworkAddress);
        }
        if selected.is_prefix_directed_broadcast(ipv4.destination) {
            return runtime
                .record_suppression(Icmpv4TimeExceededDisposition::DestinationDirectedBroadcast);
        }
    }
    if frame.first().is_some_and(|first| first & 1 != 0) {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::EthernetDestinationGroup);
    }

    let flags_fragment = match packet::read_u16(frame, ipv4.header_offset + 6) {
        Some(value) => value,
        None => {
            return runtime.record_suppression(Icmpv4TimeExceededDisposition::NonInitialFragment);
        }
    };
    if flags_fragment & 0x1fff != 0 {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::NonInitialFragment);
    }
    if ipv4.protocol == 1 {
        let type_offset = ipv4.header_offset + ipv4.header_len;
        let Some(icmp_type) = frame.get(type_offset).copied() else {
            return runtime.record_suppression(Icmpv4TimeExceededDisposition::IcmpTypeMissing);
        };
        if matches!(icmp_type, 3 | 4 | 5 | 11 | 12) {
            return runtime.record_suppression(Icmpv4TimeExceededDisposition::IcmpErrorMessage);
        }
    }

    let Some(reverse_route) = route::lookup(snapshot.routes, ipv4.source) else {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ReverseRouteMiss);
    };
    let reverse_egress = reverse_route.egress();
    let Some(interface) = snapshot
        .interfaces
        .iter()
        .find(|interface| interface.id == reverse_egress)
    else {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ReverseInterfaceMiss {
            egress: reverse_egress,
        });
    };
    let Some(binding) = snapshot
        .local_ipv4
        .iter()
        .find(|binding| binding.interface == reverse_egress)
    else {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ReverseBindingMiss {
            egress: reverse_egress,
        });
    };
    let target = reverse_route.next_hop().unwrap_or(ipv4.source);
    if reverse_target_forbidden(snapshot, reverse_egress, target, binding.address) {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ReverseTargetForbidden {
            egress: reverse_egress,
            target,
        });
    }

    let static_neighbor = snapshot
        .neighbors
        .iter()
        .find(|neighbor| neighbor.interface == reverse_egress && neighbor.target == target);
    let destination_mac = if let Some(neighbor) = static_neighbor {
        neighbor.mac
    } else if let Some((resolution_runtime, resolution_now)) = resolution.as_mut() {
        match resolution_runtime.lookup_dynamic(reverse_egress, target, *resolution_now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                trace.record(TraceEvent::NeighborResolution {
                    egress: reverse_egress,
                    target,
                    result: ResolutionResult::ClockRegression,
                });
                return runtime.record_suppression(
                    Icmpv4TimeExceededDisposition::ReverseNeighborUnresolved {
                        egress: reverse_egress,
                        target,
                        resolution: ResolutionResult::ClockRegression,
                    },
                );
            }
            DynamicLookup::Miss => {
                let result = resolution_runtime.schedule(
                    ArpRequestAction {
                        egress: reverse_egress,
                        source_mac: interface.mac,
                        source_ip: binding.address,
                        target_ip: target,
                    },
                    *resolution_now,
                    snapshot
                        .local_ipv4
                        .iter()
                        .any(|binding| binding.address == target)
                        || snapshot.routes.iter().any(|candidate| {
                            candidate.egress() == reverse_egress
                                && (candidate.is_connected_directed_broadcast(target)
                                    || candidate.is_connected_network_address(target))
                        }),
                );
                trace.record(TraceEvent::NeighborResolution {
                    egress: reverse_egress,
                    target,
                    result,
                });
                return runtime.record_suppression(
                    Icmpv4TimeExceededDisposition::ReverseNeighborUnresolved {
                        egress: reverse_egress,
                        target,
                        resolution: result,
                    },
                );
            }
        }
    } else {
        return runtime.record_suppression(
            Icmpv4TimeExceededDisposition::ReverseNeighborUnresolved {
                egress: reverse_egress,
                target,
                resolution: ResolutionResult::StateFull,
            },
        );
    };

    let quote_end = ipv4.header_offset + ipv4.total_len;
    let original_ipv4 = &frame[ipv4.header_offset..quote_end];
    runtime.schedule(
        Icmpv4ErrorAction::new_with_kind(
            kind,
            reverse_egress,
            interface.mac,
            destination_mac,
            binding.address,
            ipv4.source,
            frame[ipv4.header_offset + 1],
            snapshot.ipv4_origin.default_ttl(),
            original_ipv4,
        ),
        now,
    )
}

fn icmp_error_source_is_host(
    snapshot: &ForwardingSnapshot<'_>,
    source: crate::Ipv4Address,
) -> bool {
    let octets = source.octets();
    octets[0] != 0
        && octets[0] != 127
        && octets[0] < 224
        && !route::lookup(snapshot.routes, source).is_some_and(|selected| {
            selected.is_prefix_network_address(source)
                || selected.is_prefix_directed_broadcast(source)
        })
}

fn icmp_error_candidate_eligible(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ipv4: packet::ValidatedIpv4,
    selected_destination_route: Option<Route>,
) -> bool {
    if !icmp_error_source_is_host(snapshot, ipv4.source)
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == ipv4.source)
    {
        return false;
    }
    let destination = ipv4.destination.octets();
    if (destination[0] & 0xf0) == 0xe0 || destination == [255; 4] {
        return false;
    }
    if selected_destination_route.is_some_and(|route| {
        route.is_prefix_network_address(ipv4.destination)
            || route.is_prefix_directed_broadcast(ipv4.destination)
    }) || frame.first().is_some_and(|first| first & 1 != 0)
    {
        return false;
    }
    let Some(flags_fragment) = packet::read_u16(frame, ipv4.header_offset + 6) else {
        return false;
    };
    if flags_fragment & 0x1fff != 0 {
        return false;
    }
    if ipv4.protocol == 1 {
        let Some(icmp_type) = frame.get(ipv4.header_offset + ipv4.header_len).copied() else {
            return false;
        };
        if matches!(icmp_type, 3 | 4 | 5 | 11 | 12) {
            return false;
        }
    }
    true
}

fn reverse_target_forbidden(
    snapshot: &ForwardingSnapshot<'_>,
    egress: IfId,
    target: crate::Ipv4Address,
    local: crate::Ipv4Address,
) -> bool {
    let octets = target.octets();
    octets[0] == 0
        || octets[0] == 127
        || octets[0] >= 224
        || octets == [255; 4]
        || target == local
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == target)
        || snapshot.routes.iter().any(|route| {
            route.egress() == egress
                && (route.is_connected_directed_broadcast(target)
                    || route.is_connected_network_address(target))
        })
}

fn decide_local_ipv4<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    if ipv4.header_len > 20 {
        return Err(Ipv4OptionsUnsupported);
    }
    if ipv4.protocol != 1 {
        return Ok(PacketDecision::ConsumeIpv4Local);
    }

    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(Ipv4HeaderLengthExceedsPacket)?;
    if flags_fragment & 0x3fff != 0 {
        return Err(Icmpv4FragmentUnsupported);
    }

    let icmp_offset = ipv4
        .header_offset
        .checked_add(ipv4.header_len)
        .ok_or(Ipv4TotalLengthExceedsPacket)?;
    let icmp_end = ipv4
        .header_offset
        .checked_add(ipv4.total_len)
        .ok_or(Ipv4TotalLengthExceedsPacket)?;
    let icmp = frame
        .get(icmp_offset..icmp_end)
        .ok_or(Ipv4TotalLengthExceedsPacket)?;
    if icmp.len() < 4 {
        return Err(Icmpv4HeaderTruncated);
    }
    if icmp[0] != 8 {
        if crate::internet_checksum(icmp) != 0 {
            return Err(Icmpv4ChecksumInvalid);
        }
        return Ok(PacketDecision::ConsumeIpv4Local);
    }
    if icmp[1] != 0 {
        return Err(Icmpv4EchoCodeInvalid);
    }
    if icmp.len() < 8 {
        return Err(Icmpv4EchoHeaderTruncated);
    }
    if crate::internet_checksum(icmp) != 0 {
        return Err(Icmpv4ChecksumInvalid);
    }

    let interface = snapshot
        .interfaces
        .iter()
        .find(|item| item.id == ingress)
        .ok_or(InterfaceMiss)?;
    if !sender_is_host(snapshot, ingress, ipv4.source)
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.interface == ingress && binding.address == ipv4.source)
    {
        return Err(Icmpv4SourceNotUnicast);
    }
    let requester_mac: [u8; 6] = frame
        .get(6..12)
        .ok_or(EthernetHeaderTruncated)?
        .try_into()
        .map_err(|_| EthernetHeaderTruncated)?;
    if requester_mac == [0; 6] || requester_mac[0] & 1 != 0 {
        return Err(Icmpv4EthernetSourceInvalid);
    }
    if frame.get(0..6) != Some(interface.mac.0.as_slice()) {
        return Err(Icmpv4EthernetDestinationNotLocal);
    }
    let old_icmp_checksum =
        packet::read_u16(frame, icmp_offset + 2).ok_or(Icmpv4HeaderTruncated)?;
    let ipv4_id =
        packet::read_u16(frame, ipv4.header_offset + 4).ok_or(Ipv4HeaderLengthExceedsPacket)?;
    let ipv4_checksum = rfc1624_update(
        ipv4.checksum,
        u16::from_be_bytes([ipv4.ttl, ipv4.protocol]),
        u16::from_be_bytes([snapshot.ipv4_origin.default_ttl(), ipv4.protocol]),
    );
    let ipv4_checksum = rfc1624_update(ipv4_checksum, ipv4_id, 0);
    let ipv4_checksum = rfc1624_update(ipv4_checksum, flags_fragment, 0x4000);
    let icmp_checksum = rfc1624_update(old_icmp_checksum, 0x0800, 0x0000);
    trace.record(TraceEvent::Icmpv4EchoRequestValidated {
        ingress,
        source: ipv4.source,
        destination: ipv4.destination,
    });
    Ok(PacketDecision::Icmpv4EchoReply(Icmpv4EchoReplyDecision {
        egress: ingress,
        local_mac: interface.mac.0,
        requester_mac,
        local_ip: ipv4.destination.octets(),
        requester_ip: ipv4.source.octets(),
        ipv4_checksum,
        icmp_checksum,
        reply_ttl: snapshot.ipv4_origin.default_ttl(),
        icmp_offset,
        icmp_end,
    }))
}

fn decide_arp<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let arp = validate_arp(frame)?;
    match arp.opcode {
        ArpOpcode::Request => trace.record(TraceEvent::ArpRequestValidated {
            ingress,
            sender_protocol: arp.sender_protocol,
            target_protocol: arp.target_protocol,
        }),
        ArpOpcode::Reply => trace.record(TraceEvent::ArpReplyValidated {
            ingress,
            sender_protocol: arp.sender_protocol,
            target_protocol: arp.target_protocol,
        }),
    }
    let sha = arp.sender_hardware.0;
    if sha == [0; 6] {
        return Err(ArpSenderHardwareZero);
    }
    if sha == [0xff; 6] {
        return Err(ArpSenderHardwareBroadcast);
    }
    if sha[0] & 1 != 0 {
        return Err(ArpSenderHardwareMulticast);
    }
    let target_local = snapshot
        .local_ipv4
        .iter()
        .any(|binding| binding.interface == ingress && binding.address == arp.target_protocol);
    let sender_local = snapshot
        .local_ipv4
        .iter()
        .any(|binding| binding.interface == ingress && binding.address == arp.sender_protocol);
    let sender_host = sender_is_host(snapshot, ingress, arp.sender_protocol);
    let static_key = snapshot
        .neighbors
        .iter()
        .any(|neighbor| neighbor.interface == ingress && neighbor.target == arp.sender_protocol);
    let has_runtime = resolution.is_some();
    let disposition = if let Some((runtime, now)) = resolution.as_mut() {
        if static_key {
            runtime.merge_dynamic(
                ingress,
                arp.sender_protocol,
                arp.sender_hardware,
                target_local,
                true,
                *now,
            )
        } else if arp.sender_protocol.is_unspecified() {
            if runtime.observe_control(*now) {
                ControlDisposition::Probe
            } else {
                ControlDisposition::ClockRegression
            }
        } else if sender_local {
            if runtime.observe_control(*now) {
                ControlDisposition::LocalAddressPreserved
            } else {
                ControlDisposition::ClockRegression
            }
        } else if !sender_host {
            if runtime.observe_control(*now) {
                ControlDisposition::SenderNotHost
            } else {
                ControlDisposition::ClockRegression
            }
        } else {
            runtime.merge_dynamic(
                ingress,
                arp.sender_protocol,
                arp.sender_hardware,
                target_local,
                false,
                *now,
            )
        }
    } else if static_key {
        ControlDisposition::StaticPreserved
    } else {
        ControlDisposition::Ignored
    };
    if has_runtime {
        trace.record(TraceEvent::ArpControl {
            ingress,
            disposition,
        });
    }
    if arp.opcode == ArpOpcode::Reply || !target_local {
        return Ok(PacketDecision::ConsumeArp(disposition));
    }
    let interface = snapshot
        .interfaces
        .iter()
        .find(|item| item.id == ingress)
        .ok_or(InterfaceMiss)?;
    if frame.get(0..packet::ARP_FRAME_LEN).is_none() {
        return Err(ArpPacketTruncated);
    }
    Ok(PacketDecision::ArpReply(ArpReplyDecision {
        egress: ingress,
        local_mac: interface.mac.0,
        requester_mac: arp.sender_hardware.0,
        requester_protocol: arp.sender_protocol.octets(),
        local_protocol: arp.target_protocol.octets(),
    }))
}

fn sender_is_host(
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    sender: crate::Ipv4Address,
) -> bool {
    let octets = sender.octets();
    octets[0] != 0
        && octets[0] != 127
        && octets[0] < 224
        && !snapshot.routes.iter().any(|route| {
            route.egress() == ingress
                && (route.is_connected_directed_broadcast(sender)
                    || route.is_connected_network_address(sender))
        })
}

fn apply_decision(frame: &mut [u8], decision: PacketDecision) -> Result<(), DropReason> {
    match decision {
        PacketDecision::Ipv4(ipv4) => apply_ipv4_rewrite(frame, ipv4),
        PacketDecision::Nat44Udp(nat) => apply_nat44_udp_rewrite(frame, nat),
        PacketDecision::ArpReply(arp) => apply_arp_reply(frame, arp),
        PacketDecision::Icmpv4EchoReply(icmp) => apply_icmpv4_echo_reply(frame, icmp),
        PacketDecision::ConsumeArp(_) | PacketDecision::ConsumeIpv4Local => {
            unreachable!("consume decisions are never rewritten")
        }
    }
}

fn apply_nat44_udp_rewrite(
    frame: &mut [u8],
    decision: Nat44UdpRewriteDecision,
) -> Result<(), DropReason> {
    if frame.get(0..12).is_none()
        || frame.get(decision.forwarding.ttl_offset).is_none()
        || frame
            .get(decision.forwarding.checksum_offset..decision.forwarding.checksum_end)
            .is_none()
        || frame
            .get(decision.address_offset..decision.address_end)
            .is_none()
        || frame.get(decision.port_offset..decision.port_end).is_none()
        || frame
            .get(decision.udp_checksum_offset..decision.udp_checksum_end)
            .is_none()
    {
        return Err(Nat44UdpHeaderTruncated);
    }
    frame[0..6].copy_from_slice(&decision.forwarding.destination_mac);
    frame[6..12].copy_from_slice(&decision.forwarding.source_mac);
    frame[decision.forwarding.ttl_offset] -= 1;
    frame[decision.forwarding.checksum_offset..decision.forwarding.checksum_end]
        .copy_from_slice(&decision.ipv4_checksum.to_be_bytes());
    frame[decision.address_offset..decision.address_end].copy_from_slice(&decision.new_address);
    frame[decision.port_offset..decision.port_end]
        .copy_from_slice(&decision.new_port.to_be_bytes());
    frame[decision.udp_checksum_offset..decision.udp_checksum_end]
        .copy_from_slice(&decision.udp_checksum.to_be_bytes());
    Ok(())
}

fn apply_ipv4_rewrite(frame: &mut [u8], decision: Ipv4RewriteDecision) -> Result<(), DropReason> {
    if frame.get(0..6).is_none()
        || frame.get(6..12).is_none()
        || frame.get(decision.ttl_offset).is_none()
        || frame
            .get(decision.checksum_offset..decision.checksum_end)
            .is_none()
    {
        return Err(Ipv4HeaderLengthExceedsPacket);
    }
    frame[0..6].copy_from_slice(&decision.destination_mac);
    frame[6..12].copy_from_slice(&decision.source_mac);
    frame[decision.ttl_offset] -= 1;
    let checksum = rfc1624_update(
        decision.old_checksum,
        decision.old_ttl_protocol,
        decision.new_ttl_protocol,
    );
    frame[decision.checksum_offset..decision.checksum_end].copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn apply_arp_reply(frame: &mut [u8], decision: ArpReplyDecision) -> Result<(), DropReason> {
    if frame.get(0..packet::ARP_FRAME_LEN).is_none() {
        return Err(ArpPacketTruncated);
    }
    frame[0..6].copy_from_slice(&decision.requester_mac);
    frame[6..12].copy_from_slice(&decision.local_mac);
    frame[20..22].copy_from_slice(&2_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&decision.local_mac);
    frame[28..32].copy_from_slice(&decision.local_protocol);
    frame[32..38].copy_from_slice(&decision.requester_mac);
    frame[38..42].copy_from_slice(&decision.requester_protocol);
    Ok(())
}

fn apply_icmpv4_echo_reply(
    frame: &mut [u8],
    decision: Icmpv4EchoReplyDecision,
) -> Result<(), DropReason> {
    if frame.get(0..12).is_none()
        || frame.get(14..34).is_none()
        || frame.get(decision.icmp_offset..decision.icmp_end).is_none()
        || frame
            .get(decision.icmp_offset..decision.icmp_offset + 4)
            .is_none()
    {
        return Err(Ipv4TotalLengthExceedsPacket);
    }

    frame[0..6].copy_from_slice(&decision.requester_mac);
    frame[6..12].copy_from_slice(&decision.local_mac);
    frame[18..20].copy_from_slice(&0_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = decision.reply_ttl;
    frame[24..26].copy_from_slice(&decision.ipv4_checksum.to_be_bytes());
    frame[26..30].copy_from_slice(&decision.local_ip);
    frame[30..34].copy_from_slice(&decision.requester_ip);
    frame[decision.icmp_offset] = 0;
    frame[decision.icmp_offset + 2..decision.icmp_offset + 4]
        .copy_from_slice(&decision.icmp_checksum.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DropReason;

    #[test]
    fn drop_reason_discriminants_and_codes_are_stable_and_unique() {
        let expected = [
            (1, "ETHERNET_HEADER_TRUNCATED"),
            (2, "UNSUPPORTED_ETHERTYPE"),
            (3, "IPV4_HEADER_TRUNCATED"),
            (4, "IPV4_VERSION_UNSUPPORTED"),
            (5, "IPV4_IHL_TOO_SMALL"),
            (6, "IPV4_HEADER_LENGTH_EXCEEDS_PACKET"),
            (7, "IPV4_TOTAL_LENGTH_TOO_SMALL"),
            (8, "IPV4_TOTAL_LENGTH_EXCEEDS_PACKET"),
            (9, "IPV4_HEADER_CHECKSUM_INVALID"),
            (10, "IPV4_OPTIONS_UNSUPPORTED"),
            (11, "IPV4_TTL_EXPIRED"),
            (12, "ROUTE_MISS"),
            (13, "NEIGHBOR_UNRESOLVED"),
            (14, "INTERFACE_MISS"),
            (15, "ARP_PACKET_TRUNCATED"),
            (16, "ARP_HARDWARE_TYPE_UNSUPPORTED"),
            (17, "ARP_PROTOCOL_TYPE_UNSUPPORTED"),
            (18, "ARP_HARDWARE_LENGTH_UNSUPPORTED"),
            (19, "ARP_PROTOCOL_LENGTH_UNSUPPORTED"),
            (20, "ARP_REPLY_UNSUPPORTED"),
            (21, "ARP_OPCODE_UNSUPPORTED"),
            (22, "ARP_TARGET_NOT_LOCAL"),
            (23, "ARP_SENDER_HARDWARE_ZERO"),
            (24, "ARP_SENDER_HARDWARE_BROADCAST"),
            (25, "ARP_SENDER_HARDWARE_MULTICAST"),
            (26, "ICMPV4_HEADER_TRUNCATED"),
            (27, "ICMPV4_ECHO_HEADER_TRUNCATED"),
            (28, "ICMPV4_CHECKSUM_INVALID"),
            (29, "ICMPV4_ECHO_CODE_INVALID"),
            (30, "ICMPV4_FRAGMENT_UNSUPPORTED"),
            (31, "ICMPV4_SOURCE_NOT_UNICAST"),
            (32, "ICMPV4_ETHERNET_SOURCE_INVALID"),
            (33, "ICMPV4_ETHERNET_DESTINATION_NOT_LOCAL"),
            (34, "NAT44_UDP_RUNTIME_UNAVAILABLE"),
            (35, "NAT44_UDP_CONFIG_MISMATCH"),
            (36, "NAT44_UDP_UNSUPPORTED_TRANSPORT"),
            (37, "NAT44_UDP_HAIRPIN_UNSUPPORTED"),
            (38, "NAT44_UDP_NON_ATOMIC_IPV4_UNSUPPORTED"),
            (39, "NAT44_UDP_HEADER_TRUNCATED"),
            (40, "NAT44_UDP_LENGTH_TOO_SMALL"),
            (41, "NAT44_UDP_LENGTH_EXCEEDS_IPV4_PAYLOAD"),
            (42, "NAT44_UDP_SOURCE_PORT_ZERO"),
            (43, "NAT44_UDP_SOURCE_FORBIDDEN"),
            (44, "NAT44_UDP_REVERSE_AUTHORITY_MISMATCH"),
            (45, "NAT44_UDP_MAPPING_MISS"),
            (46, "NAT44_UDP_FILTER_DENIED"),
            (47, "NAT44_UDP_MAPPING_TABLE_FULL"),
            (48, "NAT44_UDP_PEER_TABLE_FULL"),
            (49, "NAT44_UDP_PORT_EXHAUSTED"),
            (50, "NAT44_UDP_CLOCK_REGRESSION"),
            (51, "NAT44_UDP_WRONG_INGRESS"),
            (52, "NAT44_UDP_WRONG_EGRESS"),
            (53, "NAT44_EXTERNAL_TO_INTERNAL_BYPASS"),
        ];
        let actual = [
            DropReason::EthernetHeaderTruncated,
            DropReason::UnsupportedEtherType,
            DropReason::Ipv4HeaderTruncated,
            DropReason::Ipv4VersionUnsupported,
            DropReason::Ipv4IhlTooSmall,
            DropReason::Ipv4HeaderLengthExceedsPacket,
            DropReason::Ipv4TotalLengthTooSmall,
            DropReason::Ipv4TotalLengthExceedsPacket,
            DropReason::Ipv4HeaderChecksumInvalid,
            DropReason::Ipv4OptionsUnsupported,
            DropReason::Ipv4TtlExpired,
            DropReason::RouteMiss,
            DropReason::NeighborUnresolved,
            DropReason::InterfaceMiss,
            DropReason::ArpPacketTruncated,
            DropReason::ArpHardwareTypeUnsupported,
            DropReason::ArpProtocolTypeUnsupported,
            DropReason::ArpHardwareLengthUnsupported,
            DropReason::ArpProtocolLengthUnsupported,
            DropReason::ArpReplyUnsupported,
            DropReason::ArpOpcodeUnsupported,
            DropReason::ArpTargetNotLocal,
            DropReason::ArpSenderHardwareZero,
            DropReason::ArpSenderHardwareBroadcast,
            DropReason::ArpSenderHardwareMulticast,
            DropReason::Icmpv4HeaderTruncated,
            DropReason::Icmpv4EchoHeaderTruncated,
            DropReason::Icmpv4ChecksumInvalid,
            DropReason::Icmpv4EchoCodeInvalid,
            DropReason::Icmpv4FragmentUnsupported,
            DropReason::Icmpv4SourceNotUnicast,
            DropReason::Icmpv4EthernetSourceInvalid,
            DropReason::Icmpv4EthernetDestinationNotLocal,
            DropReason::Nat44UdpRuntimeUnavailable,
            DropReason::Nat44UdpConfigMismatch,
            DropReason::Nat44UdpUnsupportedTransport,
            DropReason::Nat44UdpHairpinUnsupported,
            DropReason::Nat44UdpNonAtomicIpv4Unsupported,
            DropReason::Nat44UdpHeaderTruncated,
            DropReason::Nat44UdpLengthTooSmall,
            DropReason::Nat44UdpLengthExceedsIpv4Payload,
            DropReason::Nat44UdpSourcePortZero,
            DropReason::Nat44UdpSourceForbidden,
            DropReason::Nat44UdpReverseAuthorityMismatch,
            DropReason::Nat44UdpMappingMiss,
            DropReason::Nat44UdpFilterDenied,
            DropReason::Nat44UdpMappingTableFull,
            DropReason::Nat44UdpPeerTableFull,
            DropReason::Nat44UdpPortExhausted,
            DropReason::Nat44UdpClockRegression,
            DropReason::Nat44UdpWrongIngress,
            DropReason::Nat44UdpWrongEgress,
            DropReason::Nat44ExternalToInternalBypass,
        ];
        assert_eq!(actual.len(), expected.len());
        for (reason, &(discriminant, code)) in actual.iter().zip(&expected) {
            assert_eq!(*reason as u16, discriminant);
            assert_eq!(reason.code(), code);
        }
    }
}

use crate::resolution::DynamicLookup;
use crate::{
    packet, rfc1624_update, route, validate_arp, validate_ipv4_frame, ArpOpcode, ArpRequestAction,
    BatchCompletion, ConsumeReason, ControlDisposition, Icmpv4ErrorRuntime,
    Icmpv4TimeExceededAction, Icmpv4TimeExceededDisposition, IfId, Interface, LocalIpv4Binding,
    MonotonicMillis, Neighbor, PacketBatch, ResolutionResult, ResolutionRuntime, Route,
    ARP_ETHERTYPE, IPV4_ETHERTYPE,
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
    routes: &'a [Route],
    interfaces: &'a [Interface],
    neighbors: &'a [Neighbor],
    local_ipv4: &'a [LocalIpv4Binding],
    ipv4_origin: Ipv4OriginPolicy,
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
        disposition: Icmpv4TimeExceededDisposition,
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
enum PacketDecision {
    Ipv4(Ipv4RewriteDecision),
    ArpReply(ArpReplyDecision),
    Icmpv4EchoReply(Icmpv4EchoReplyDecision),
    ConsumeArp(ControlDisposition),
    ConsumeIpv4Local,
}

impl PacketDecision {
    fn egress(self) -> IfId {
        match self {
            Self::Ipv4(decision) => decision.egress,
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
    forward_batch_inner(batch, snapshot, None, None, trace)
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
    forward_batch_inner(batch, snapshot, Some((runtime, now)), None, trace)
}

/// Forwards RX packets while queueing ARP resolution and eligible ICMPv4 Time
/// Exceeded actions into separate caller-backed worker-local runtimes.
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
        trace,
    )
}

fn forward_batch_inner<B, T>(
    mut batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    mut resolution: Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    mut icmpv4_errors: Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
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
        let result = {
            let frame = packet.bytes_mut();
            decide(
                &*frame,
                snapshot,
                ingress,
                &mut resolution,
                &mut icmpv4_errors,
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

fn decide<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let ether_type = packet::read_u16(frame, 12).ok_or(EthernetHeaderTruncated)?;
    match ether_type {
        IPV4_ETHERTYPE => decide_ipv4(frame, snapshot, ingress, resolution, icmpv4_errors, trace),
        ARP_ETHERTYPE => decide_arp(frame, snapshot, ingress, resolution, trace),
        _ => Err(UnsupportedEtherType),
    }
}

fn decide_ipv4<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let ipv4 = validate_ipv4_frame(frame)?;
    trace.record(TraceEvent::Ipv4Validated {
        ingress,
        destination: ipv4.destination,
    });
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
    if ipv4.ttl <= 1 {
        if let Some((runtime, now)) = icmpv4_errors.as_mut() {
            let disposition = decide_icmpv4_time_exceeded(
                frame, snapshot, ipv4, resolution, runtime, *now, trace,
            );
            trace.record(TraceEvent::Icmpv4TimeExceededDisposition {
                ingress,
                disposition,
            });
        }
        return Err(Ipv4TtlExpired);
    }
    let route = route::lookup(snapshot.routes, ipv4.destination).ok_or(RouteMiss)?;
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
                        snapshot.routes.iter().any(|candidate| {
                            candidate.egress() == route.egress()
                                && candidate.is_connected_directed_broadcast(target)
                        }),
                    );
                    trace.record(TraceEvent::NeighborResolution {
                        egress: route.egress(),
                        target,
                        result,
                    });
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
    Ok(PacketDecision::Ipv4(Ipv4RewriteDecision {
        egress: route.egress(),
        source_mac: interface.mac.0,
        destination_mac: destination_mac.0,
        ttl_offset,
        checksum_offset,
        checksum_end,
        old_ttl_protocol: u16::from_be_bytes([ipv4.ttl, ipv4.protocol]),
        new_ttl_protocol: u16::from_be_bytes([ipv4.ttl - 1, ipv4.protocol]),
        old_checksum: ipv4.checksum,
    }))
}

fn decide_icmpv4_time_exceeded<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ipv4: packet::ValidatedIpv4,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Icmpv4TimeExceededDisposition {
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
    if route::lookup(snapshot.routes, ipv4.destination)
        .is_some_and(|selected| selected.is_prefix_directed_broadcast(ipv4.destination))
    {
        return runtime
            .record_suppression(Icmpv4TimeExceededDisposition::DestinationDirectedBroadcast);
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
                    snapshot.routes.iter().any(|candidate| {
                        candidate.egress() == reverse_egress
                            && candidate.is_connected_directed_broadcast(target)
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
        Icmpv4TimeExceededAction::new(
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
        PacketDecision::ArpReply(arp) => apply_arp_reply(frame, arp),
        PacketDecision::Icmpv4EchoReply(icmp) => apply_icmpv4_echo_reply(frame, icmp),
        PacketDecision::ConsumeArp(_) | PacketDecision::ConsumeIpv4Local => {
            unreachable!("consume decisions are never rewritten")
        }
    }
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
        ];
        for (reason, &(discriminant, code)) in actual.iter().zip(&expected) {
            assert_eq!(*reason as u16, discriminant);
            assert_eq!(reason.code(), code);
        }
    }
}

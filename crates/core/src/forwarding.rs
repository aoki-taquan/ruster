use crate::firewall::{FirewallPacket, FirewallPlan, FirewallPlanError};
use crate::nat44::{
    Nat44TcpInboundPlan, Nat44TcpOutboundPlan, Nat44TcpPlanError, Nat44UdpInboundPlan,
    Nat44UdpOutboundPlan, Nat44UdpPlanError,
};
use crate::resolution::DynamicLookup;
use crate::{
    packet, rfc1624_update, route, validate_arp, validate_ipv4_frame, ArpOpcode, ArpRequestAction,
    BatchCompletion, ConsumeReason, ControlDisposition, FirewallAction, FirewallAuditBuffer,
    FirewallConfig, FirewallConnectionClass, FirewallDisposition, FirewallFailure,
    FirewallPolicySource, FirewallProtocol, FirewallRelatedIcmpv4Error, FirewallRelatedIcmpv4Flow,
    FirewallRuntime, FirewallVerdict, Icmpv4ErrorAction, Icmpv4ErrorDisposition, Icmpv4ErrorKind,
    Icmpv4ErrorRuntime, Icmpv4TimeExceededDisposition, IfId, Interface, LocalIpv4Binding,
    MonotonicMillis, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig, Nat44TcpDisposition, Nat44TcpRuntime,
    Nat44UdpConfig, Nat44UdpDisposition, Nat44UdpRuntime, Neighbor, PacketBatch, ResolutionResult,
    ResolutionRuntime, Route, ARP_ETHERTYPE, IPV4_ETHERTYPE,
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
    Nat44TcpRuntimeUnavailable = 54,
    Nat44TcpConfigMismatch = 55,
    Nat44TcpUnsupportedTransport = 56,
    Nat44TcpHairpinUnsupported = 57,
    Nat44TcpNonAtomicIpv4Unsupported = 58,
    Nat44TcpHeaderTruncated = 59,
    Nat44TcpDataOffsetTooSmall = 60,
    Nat44TcpDataOffsetExceedsIpv4Payload = 61,
    Nat44TcpChecksumInvalid = 62,
    Nat44TcpSourcePortZero = 63,
    Nat44TcpSourceForbidden = 64,
    Nat44TcpReverseAuthorityMismatch = 65,
    Nat44TcpMappingMiss = 66,
    Nat44TcpSessionMiss = 67,
    Nat44TcpInvalidInitialFlags = 68,
    Nat44TcpMappingTableFull = 69,
    Nat44TcpSessionTableFull = 70,
    Nat44TcpPortExhausted = 71,
    Nat44TcpClockRegression = 72,
    Nat44TcpWrongIngress = 73,
    Nat44TcpWrongEgress = 74,
    Nat44CombinedRealmMismatch = 75,
    Nat44Icmpv4WrongIngress = 76,
    Nat44Icmpv4OuterOptionsUnsupported = 77,
    Nat44Icmpv4OuterFragmentUnsupported = 78,
    Nat44Icmpv4OuterTtlExpired = 79,
    Nat44Icmpv4HeaderTruncated = 80,
    Nat44Icmpv4ChecksumInvalid = 81,
    Nat44Icmpv4QuoteTruncated = 82,
    Nat44Icmpv4QuotedVersionUnsupported = 83,
    Nat44Icmpv4QuotedIhlTooSmall = 84,
    Nat44Icmpv4QuotedHeaderTruncated = 85,
    Nat44Icmpv4QuotedTotalLengthTooSmall = 86,
    Nat44Icmpv4QuotedChecksumInvalid = 87,
    Nat44Icmpv4QuotedFragmentUnsupported = 88,
    Nat44Icmpv4QuotedProtocolUnsupported = 89,
    Nat44Icmpv4QuotedPublicSourceMismatch = 90,
    Nat44Icmpv4TcpChecksumPartial = 91,
    Nat44Icmpv4WrongEgress = 92,
    Nat44Icmpv4SourceForbidden = 93,
    FirewallRuntimeUnavailable = 94,
    FirewallConfigMismatch = 95,
    FirewallUnsupportedProtocol = 96,
    FirewallIpv4OptionsUnsupported = 97,
    FirewallFragmentUnsupported = 98,
    FirewallTcpHeaderTruncated = 99,
    FirewallTcpDataOffsetTooSmall = 100,
    FirewallTcpDataOffsetExceedsIpv4Payload = 101,
    FirewallTcpChecksumInvalid = 102,
    FirewallTcpPortZero = 103,
    FirewallUdpHeaderTruncated = 104,
    FirewallUdpLengthTooSmall = 105,
    FirewallUdpLengthExceedsIpv4Payload = 106,
    FirewallUdpChecksumInvalid = 107,
    FirewallUdpDestinationPortZero = 108,
    FirewallRuleDenied = 109,
    FirewallDefaultDenied = 110,
    FirewallTcpInvalidInitialFlags = 111,
    FirewallStateTableFull = 112,
    FirewallClockRegression = 113,
    FirewallRelatedIcmpv4Unsupported = 114,
    FirewallRouteUnavailable = 115,
    FirewallRelatedIcmpv4StateMiss = 116,
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
            Nat44TcpRuntimeUnavailable => "NAT44_TCP_RUNTIME_UNAVAILABLE",
            Nat44TcpConfigMismatch => "NAT44_TCP_CONFIG_MISMATCH",
            Nat44TcpUnsupportedTransport => "NAT44_TCP_UNSUPPORTED_TRANSPORT",
            Nat44TcpHairpinUnsupported => "NAT44_TCP_HAIRPIN_UNSUPPORTED",
            Nat44TcpNonAtomicIpv4Unsupported => "NAT44_TCP_NON_ATOMIC_IPV4_UNSUPPORTED",
            Nat44TcpHeaderTruncated => "NAT44_TCP_HEADER_TRUNCATED",
            Nat44TcpDataOffsetTooSmall => "NAT44_TCP_DATA_OFFSET_TOO_SMALL",
            Nat44TcpDataOffsetExceedsIpv4Payload => "NAT44_TCP_DATA_OFFSET_EXCEEDS_IPV4_PAYLOAD",
            Nat44TcpChecksumInvalid => "NAT44_TCP_CHECKSUM_INVALID",
            Nat44TcpSourcePortZero => "NAT44_TCP_SOURCE_PORT_ZERO",
            Nat44TcpSourceForbidden => "NAT44_TCP_SOURCE_FORBIDDEN",
            Nat44TcpReverseAuthorityMismatch => "NAT44_TCP_REVERSE_AUTHORITY_MISMATCH",
            Nat44TcpMappingMiss => "NAT44_TCP_MAPPING_MISS",
            Nat44TcpSessionMiss => "NAT44_TCP_SESSION_MISS",
            Nat44TcpInvalidInitialFlags => "NAT44_TCP_INVALID_INITIAL_FLAGS",
            Nat44TcpMappingTableFull => "NAT44_TCP_MAPPING_TABLE_FULL",
            Nat44TcpSessionTableFull => "NAT44_TCP_SESSION_TABLE_FULL",
            Nat44TcpPortExhausted => "NAT44_TCP_PORT_EXHAUSTED",
            Nat44TcpClockRegression => "NAT44_TCP_CLOCK_REGRESSION",
            Nat44TcpWrongIngress => "NAT44_TCP_WRONG_INGRESS",
            Nat44TcpWrongEgress => "NAT44_TCP_WRONG_EGRESS",
            Nat44CombinedRealmMismatch => "NAT44_COMBINED_REALM_MISMATCH",
            Nat44Icmpv4WrongIngress => "NAT44_ICMPV4_WRONG_INGRESS",
            Nat44Icmpv4OuterOptionsUnsupported => "NAT44_ICMPV4_OUTER_OPTIONS_UNSUPPORTED",
            Nat44Icmpv4OuterFragmentUnsupported => "NAT44_ICMPV4_OUTER_FRAGMENT_UNSUPPORTED",
            Nat44Icmpv4OuterTtlExpired => "NAT44_ICMPV4_OUTER_TTL_EXPIRED",
            Nat44Icmpv4HeaderTruncated => "NAT44_ICMPV4_HEADER_TRUNCATED",
            Nat44Icmpv4ChecksumInvalid => "NAT44_ICMPV4_CHECKSUM_INVALID",
            Nat44Icmpv4QuoteTruncated => "NAT44_ICMPV4_QUOTE_TRUNCATED",
            Nat44Icmpv4QuotedVersionUnsupported => "NAT44_ICMPV4_QUOTED_VERSION_UNSUPPORTED",
            Nat44Icmpv4QuotedIhlTooSmall => "NAT44_ICMPV4_QUOTED_IHL_TOO_SMALL",
            Nat44Icmpv4QuotedHeaderTruncated => "NAT44_ICMPV4_QUOTED_HEADER_TRUNCATED",
            Nat44Icmpv4QuotedTotalLengthTooSmall => "NAT44_ICMPV4_QUOTED_TOTAL_LENGTH_TOO_SMALL",
            Nat44Icmpv4QuotedChecksumInvalid => "NAT44_ICMPV4_QUOTED_CHECKSUM_INVALID",
            Nat44Icmpv4QuotedFragmentUnsupported => "NAT44_ICMPV4_QUOTED_FRAGMENT_UNSUPPORTED",
            Nat44Icmpv4QuotedProtocolUnsupported => "NAT44_ICMPV4_QUOTED_PROTOCOL_UNSUPPORTED",
            Nat44Icmpv4QuotedPublicSourceMismatch => "NAT44_ICMPV4_QUOTED_PUBLIC_SOURCE_MISMATCH",
            Nat44Icmpv4TcpChecksumPartial => "NAT44_ICMPV4_TCP_CHECKSUM_PARTIAL",
            Nat44Icmpv4WrongEgress => "NAT44_ICMPV4_WRONG_EGRESS",
            Nat44Icmpv4SourceForbidden => "NAT44_ICMPV4_SOURCE_FORBIDDEN",
            FirewallRuntimeUnavailable => "FIREWALL_RUNTIME_UNAVAILABLE",
            FirewallConfigMismatch => "FIREWALL_CONFIG_MISMATCH",
            FirewallUnsupportedProtocol => "FIREWALL_UNSUPPORTED_PROTOCOL",
            FirewallIpv4OptionsUnsupported => "FIREWALL_IPV4_OPTIONS_UNSUPPORTED",
            FirewallFragmentUnsupported => "FIREWALL_FRAGMENT_UNSUPPORTED",
            FirewallTcpHeaderTruncated => "FIREWALL_TCP_HEADER_TRUNCATED",
            FirewallTcpDataOffsetTooSmall => "FIREWALL_TCP_DATA_OFFSET_TOO_SMALL",
            FirewallTcpDataOffsetExceedsIpv4Payload => {
                "FIREWALL_TCP_DATA_OFFSET_EXCEEDS_IPV4_PAYLOAD"
            }
            FirewallTcpChecksumInvalid => "FIREWALL_TCP_CHECKSUM_INVALID",
            FirewallTcpPortZero => "FIREWALL_TCP_PORT_ZERO",
            FirewallUdpHeaderTruncated => "FIREWALL_UDP_HEADER_TRUNCATED",
            FirewallUdpLengthTooSmall => "FIREWALL_UDP_LENGTH_TOO_SMALL",
            FirewallUdpLengthExceedsIpv4Payload => "FIREWALL_UDP_LENGTH_EXCEEDS_IPV4_PAYLOAD",
            FirewallUdpChecksumInvalid => "FIREWALL_UDP_CHECKSUM_INVALID",
            FirewallUdpDestinationPortZero => "FIREWALL_UDP_DESTINATION_PORT_ZERO",
            FirewallRuleDenied => "FIREWALL_RULE_DENIED",
            FirewallDefaultDenied => "FIREWALL_DEFAULT_DENIED",
            FirewallTcpInvalidInitialFlags => "FIREWALL_TCP_INVALID_INITIAL_FLAGS",
            FirewallStateTableFull => "FIREWALL_STATE_TABLE_FULL",
            FirewallClockRegression => "FIREWALL_CLOCK_REGRESSION",
            FirewallRelatedIcmpv4Unsupported => "FIREWALL_RELATED_ICMPV4_UNSUPPORTED",
            FirewallRouteUnavailable => "FIREWALL_ROUTE_UNAVAILABLE",
            FirewallRelatedIcmpv4StateMiss => "FIREWALL_RELATED_ICMPV4_STATE_MISS",
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
    authority: u64,
    identity: [usize; 8],
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
            authority: calculate_snapshot_authority(
                routes,
                interfaces,
                neighbors,
                local_ipv4,
                ipv4_origin,
            ),
            identity: [
                routes.as_ptr() as usize,
                routes.len(),
                interfaces.as_ptr() as usize,
                interfaces.len(),
                neighbors.as_ptr() as usize,
                neighbors.len(),
                local_ipv4.as_ptr() as usize,
                local_ipv4.len(),
            ],
        })
    }

    pub(crate) const fn authority(&self) -> u64 {
        self.authority
    }

    pub(crate) const fn identity(&self) -> [usize; 8] {
        self.identity
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

fn calculate_snapshot_authority(
    routes: &[Route],
    interfaces: &[Interface],
    neighbors: &[Neighbor],
    local_ipv4: &[LocalIpv4Binding],
    ipv4_origin: Ipv4OriginPolicy,
) -> u64 {
    fn mix(hash: u64, value: u64) -> u64 {
        (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
    }

    let mut hash = 0xcbf2_9ce4_8422_2325;
    for interface in interfaces {
        hash = mix(hash, u64::from(interface.id.0));
        for octet in interface.mac.0 {
            hash = mix(hash, u64::from(octet));
        }
    }
    hash = mix(hash, 0xff);
    for binding in local_ipv4 {
        hash = mix(hash, u64::from(binding.interface.0));
        hash = mix(
            hash,
            u64::from(u32::from_be_bytes(binding.address.octets())),
        );
    }
    hash = mix(hash, 0xfe);
    for route in routes {
        hash = mix(hash, u64::from(u32::from_be_bytes(route.prefix().octets())));
        hash = mix(hash, u64::from(route.prefix_len()));
        hash = mix(hash, u64::from(route.egress().0));
        hash = mix(
            hash,
            route.next_hop().map_or(u64::MAX, |next| {
                u64::from(u32::from_be_bytes(next.octets()))
            }),
        );
    }
    hash = mix(hash, 0xfd);
    for neighbor in neighbors {
        hash = mix(hash, u64::from(neighbor.interface.0));
        hash = mix(
            hash,
            u64::from(u32::from_be_bytes(neighbor.target.octets())),
        );
        for octet in neighbor.mac.0 {
            hash = mix(hash, u64::from(octet));
        }
    }
    mix(hash, u64::from(ipv4_origin.default_ttl()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44Icmpv4Disposition {
    Translated {
        quoted_protocol: u8,
        internal_address: crate::Ipv4Address,
        internal_port: u16,
    },
    Rejected {
        reason: DropReason,
    },
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
    Nat44Tcp {
        ingress: IfId,
        disposition: Nat44TcpDisposition,
    },
    Nat44Icmpv4 {
        ingress: IfId,
        disposition: Nat44Icmpv4Disposition,
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
    /// RX slots leased from the backend and terminally handled by the core.
    pub received: usize,
    /// Packets requested for TX; this does not mean backend or wire acceptance.
    pub tx_requested: usize,
    /// RX slots completed with a forwarding [`DropReason`].
    pub dropped: usize,
    /// RX slots completed with a typed [`ConsumeReason`].
    pub consumed: usize,
    /// Backend completion for the same batch.
    pub completion: BatchCompletion<E>,
}

impl<E> BatchReport<E> {
    /// Returns whether core terminal outcomes and backend accounting agree.
    ///
    /// A valid report satisfies all of the following:
    ///
    /// - every received slot is requested for TX, dropped, or consumed;
    /// - the core and backend report the same number of TX requests;
    /// - backend `recycled` is exactly core drops plus consumes; and
    /// - [`BatchCompletion::invariants_hold`] is true.
    ///
    /// A returned report cannot contain an abandoned lease: abandonment is
    /// the RAII fallback for an interrupted packet path, while normal
    /// forwarding explicitly drops or consumes every non-TX packet.
    #[must_use]
    pub const fn invariants_hold(&self) -> bool {
        let Some(core_terminal) = self.tx_requested.checked_add(self.dropped) else {
            return false;
        };
        let Some(core_terminal) = core_terminal.checked_add(self.consumed) else {
            return false;
        };
        let Some(core_recycled) = self.dropped.checked_add(self.consumed) else {
            return false;
        };
        core_terminal == self.received
            && self.tx_requested == self.completion.tx_requested
            && core_recycled == self.completion.recycled
            && self.completion.invariants_hold()
    }
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
enum Nat44TcpTransition {
    Outbound(Nat44TcpOutboundPlan),
    Inbound(Nat44TcpInboundPlan),
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
struct Nat44TcpRewriteDecision {
    forwarding: Ipv4RewriteDecision,
    address_offset: usize,
    address_end: usize,
    new_address: [u8; 4],
    port_offset: usize,
    port_end: usize,
    new_port: u16,
    tcp_checksum_offset: usize,
    tcp_checksum_end: usize,
    ipv4_checksum: u16,
    tcp_checksum: u16,
    transition: Nat44TcpTransition,
    disposition: Nat44TcpDisposition,
}

#[derive(Clone, Copy)]
struct Nat44Icmpv4RewriteDecision {
    egress: IfId,
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    outer_ttl_offset: usize,
    outer_checksum_offset: usize,
    outer_destination_offset: usize,
    inner_checksum_offset: usize,
    inner_source_offset: usize,
    inner_port_offset: usize,
    transport_checksum_offset: Option<usize>,
    icmp_checksum_offset: usize,
    internal_address: [u8; 4],
    internal_port: u16,
    outer_checksum: u16,
    inner_checksum: u16,
    transport_checksum: Option<u16>,
    icmp_checksum: u16,
    disposition: Nat44Icmpv4Disposition,
}

#[derive(Clone, Copy)]
enum PacketDecision {
    Ipv4(Ipv4RewriteDecision),
    Nat44Udp(Nat44UdpRewriteDecision),
    Nat44Tcp(Nat44TcpRewriteDecision),
    Nat44Icmpv4(Nat44Icmpv4RewriteDecision),
    ArpReply(ArpReplyDecision),
    Icmpv4EchoReply(Icmpv4EchoReplyDecision),
    ConsumeArp(ControlDisposition),
    ConsumeIpv4Local,
}

#[derive(Clone, Copy)]
struct PlannedPacket {
    decision: PacketDecision,
    firewall: Option<FirewallPlan>,
}

impl PacketDecision {
    fn egress(self) -> IfId {
        match self {
            Self::Ipv4(decision) => decision.egress,
            Self::Nat44Udp(decision) => decision.forwarding.egress,
            Self::Nat44Tcp(decision) => decision.forwarding.egress,
            Self::Nat44Icmpv4(decision) => decision.egress,
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
    forward_batch_inner(
        batch, snapshot, None, None, None, None, None, None, None, None, None, trace,
    )
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
        None,
        None,
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
        None,
        None,
        None,
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
        None,
        None,
        None,
        None,
        None,
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
        None,
        None,
        None,
        None,
        None,
        trace,
    )
}

/// Runs one outbound-initiated TCP NAPT domain with ARP resolution.
pub fn forward_batch_with_nat44_tcp<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
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
        None,
        None,
        Some(config),
        nat44_tcp,
        None,
        None,
        None,
        trace,
    )
}

/// Composes TCP NAPT with generated ICMPv4 errors in one RX phase.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_tcp_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
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
        Some(config),
        nat44_tcp,
        None,
        None,
        None,
        trace,
    )
}

/// Runs independent UDP and TCP NAPT state for one matching address realm.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
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
        Some(udp_config),
        nat44_udp,
        Some(tcp_config),
        nat44_tcp,
        None,
        None,
        None,
        trace,
    )
}

/// Full UDP/TCP NAPT and generated ICMPv4-error composition.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
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
        Some(udp_config),
        nat44_udp,
        Some(tcp_config),
        nat44_tcp,
        None,
        None,
        None,
        trace,
    )
}

/// Runs an opt-in stateful firewall for forwarded unfragmented IPv4 UDP/TCP.
///
/// ARP, router-local traffic, and router-originated generated packets remain
/// outside this service. A missing or mismatched runtime fails closed.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_firewall<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_, '_>>,
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
        None,
        None,
        None,
        None,
        Some(config),
        firewall,
        None,
        trace,
    )
}

/// Runs the opt-in stateful firewall and appends one typed policy record for
/// every packet that reaches rule or established-flow evaluation.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_firewall_audited<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_, '_>>,
    audit: &mut FirewallAuditBuffer<'_>,
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
        None,
        None,
        None,
        None,
        Some(config),
        firewall,
        Some(audit),
        trace,
    )
}

/// Composes the stateful firewall with the existing generated ICMPv4 error
/// capture path. Firewall authorization precedes TTL error capture.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_firewall_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_, '_>>,
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
        None,
        None,
        Some(config),
        firewall,
        None,
        trace,
    )
}

/// Audited variant of [`forward_batch_with_firewall_and_icmpv4_errors`].
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_firewall_and_icmpv4_errors_audited<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_, '_>>,
    audit: &mut FirewallAuditBuffer<'_>,
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
        None,
        None,
        Some(config),
        firewall,
        Some(audit),
        trace,
    )
}

/// Composes independent UDP/TCP NAPT with one canonical-tuple firewall.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_firewall<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_, '_>>,
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
        Some(udp_config),
        nat44_udp,
        Some(tcp_config),
        nat44_tcp,
        Some(firewall_config),
        firewall,
        None,
        trace,
    )
}

/// Audited variant of
/// [`forward_batch_with_nat44_udp_and_tcp_and_firewall`].
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_firewall_audited<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_, '_>>,
    audit: &mut FirewallAuditBuffer<'_>,
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
        Some(udp_config),
        nat44_udp,
        Some(tcp_config),
        nat44_tcp,
        Some(firewall_config),
        firewall,
        Some(audit),
        trace,
    )
}

#[allow(clippy::too_many_arguments)]
fn forward_batch_inner<B, T>(
    mut batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    mut resolution: Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    mut icmpv4_errors: Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    mut nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    mut nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    mut firewall: Option<&mut FirewallRuntime<'_, '_>>,
    mut firewall_audit: Option<&mut FirewallAuditBuffer<'_>>,
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
        let mut firewall_plan = None;
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
                nat44_tcp_config,
                &mut nat44_tcp,
                firewall_config,
                &mut firewall,
                &mut firewall_audit,
                &mut firewall_plan,
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
            .map(|decision| PlannedPacket {
                decision,
                firewall: firewall_plan,
            })
        };
        match result {
            Ok(PlannedPacket {
                decision: PacketDecision::ConsumeArp(disposition),
                ..
            }) => {
                packet.consume(ConsumeReason::ArpControl);
                consumed += 1;
                trace.record(TraceEvent::Consumed {
                    ingress,
                    reason: ConsumeReason::ArpControl,
                    disposition,
                });
            }
            Ok(PlannedPacket {
                decision: PacketDecision::ConsumeIpv4Local,
                ..
            }) => {
                packet.consume(ConsumeReason::Ipv4LocalUnsupported);
                consumed += 1;
                trace.record(TraceEvent::Ipv4LocalConsumed {
                    ingress,
                    reason: ConsumeReason::Ipv4LocalUnsupported,
                });
            }
            Ok(planned) => {
                let decision = planned.decision;
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
                if let PacketDecision::Nat44Tcp(nat) = decision {
                    let runtime = nat44_tcp
                        .as_deref_mut()
                        .expect("TCP NAT decision requires a bound runtime");
                    match nat.transition {
                        Nat44TcpTransition::Outbound(plan) => {
                            runtime.commit_outbound(plan, nat_now_ms);
                        }
                        Nat44TcpTransition::Inbound(plan) => {
                            runtime.commit_inbound(plan, nat_now_ms);
                        }
                    }
                    trace.record(TraceEvent::Nat44Tcp {
                        ingress,
                        disposition: nat.disposition,
                    });
                }
                if let PacketDecision::Nat44Icmpv4(nat) = decision {
                    trace.record(TraceEvent::Nat44Icmpv4 {
                        ingress,
                        disposition: nat.disposition,
                    });
                }
                if let Some(plan) = planned.firewall {
                    firewall
                        .as_deref_mut()
                        .expect("firewall plan requires a bound runtime")
                        .commit(plan)
                        .expect("sequential packet path keeps firewall plan authority stable");
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
    trace.record(TraceEvent::BatchCompleted {
        tx_accepted: completion.tx_accepted,
        tx_rejected: completion.tx_rejected,
    });
    let report = BatchReport {
        received,
        tx_requested,
        dropped,
        consumed,
        completion,
    };
    debug_assert!(report.invariants_hold());
    report
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
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_, '_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_plan: &mut Option<FirewallPlan>,
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
            nat44_tcp_config,
            nat44_tcp,
            firewall_config,
            firewall,
            firewall_audit,
            firewall_plan,
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
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_, '_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_plan: &mut Option<FirewallPlan>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let ipv4 = validate_ipv4_frame(frame)?;
    trace.record(TraceEvent::Ipv4Validated {
        ingress,
        destination: ipv4.destination,
    });
    let nat_now = resolution
        .as_ref()
        .map_or(MonotonicMillis(0), |(_, now)| *now);
    let combined_realm_mismatch = matches!((nat44_udp_config, nat44_tcp_config), (Some(udp), Some(tcp)) if !tcp.realm_matches_udp(*udp));
    if is_nat44_icmpv4_candidate(frame, ipv4, nat44_udp_config, nat44_tcp_config) {
        let related_firewall = firewall_config
            .map(|config| require_firewall_runtime(snapshot, config, firewall))
            .transpose()?;
        return decide_nat44_icmpv4_frag_needed(
            frame,
            snapshot,
            ingress,
            ipv4,
            resolution,
            nat44_udp_config,
            nat44_udp,
            nat44_tcp_config,
            nat44_tcp,
            nat_now,
            combined_realm_mismatch,
            related_firewall,
            firewall_audit,
            trace,
        );
    }
    let local = snapshot
        .local_ipv4
        .iter()
        .any(|binding| binding.interface == ingress && binding.address == ipv4.destination);
    let nat_inbound_candidate = nat44_udp_config
        .is_some_and(|config| ipv4.destination == config.public_address() && ipv4.protocol == 17)
        || nat44_tcp_config.is_some_and(|config| {
            ipv4.destination == config.public_address() && ipv4.protocol == 6
        });
    let mut firewall_validated = None;
    if let Some(config) = firewall_config {
        if !local || nat_inbound_candidate {
            let runtime = require_firewall_runtime(snapshot, config, firewall)?;
            let validated = match validate_firewall_transport(frame, ipv4) {
                Ok(validated) => validated,
                Err(reason) => {
                    runtime.record_invalid_packet();
                    return Err(reason);
                }
            };
            if let Err(error) = runtime.observe_attempt(nat_now.0) {
                return Err(match error {
                    FirewallPlanError::ClockRegression => FirewallClockRegression,
                    FirewallPlanError::RuleDenied(_)
                    | FirewallPlanError::DefaultDenied
                    | FirewallPlanError::InvalidInitialTcp(_)
                    | FirewallPlanError::StateFull(_) => {
                        unreachable!("clock observation only reports regression")
                    }
                });
            }
            observe_combined_nat_security_time(
                snapshot,
                ingress,
                ipv4,
                validated,
                nat44_udp_config,
                nat44_udp,
                nat44_tcp_config,
                nat44_tcp,
                nat_now,
                trace,
            )?;
            firewall_validated = Some(validated);
        }
    }
    if combined_realm_mismatch
        && matches!(ipv4.protocol, 6 | 17)
        && (nat44_udp_config.is_some_and(|config| ipv4.destination == config.public_address())
            || nat44_tcp_config.is_some_and(|config| ipv4.destination == config.public_address()))
    {
        return reject_combined_realm_mismatch(ingress, nat44_udp, nat44_tcp, trace);
    }
    if let Some(config) = nat44_tcp_config {
        if ipv4.protocol == 6
            && (ingress == config.inside() || ipv4.destination == config.public_address())
            && !combined_realm_mismatch
            && firewall_config.is_none()
        {
            observe_nat44_tcp_candidate_if_present(
                snapshot, config, nat44_tcp, nat_now, ingress, trace,
            )?;
        }
    }
    if let Some(config) = nat44_udp_config {
        if ingress == config.inside()
            && ipv4.destination == config.public_address()
            && (ipv4.protocol == 17 || (ipv4.protocol == 6 && nat44_tcp_config.is_none()))
        {
            observe_nat_candidate_if_present(snapshot, config, nat44_udp, nat_now, ingress, trace)?;
            return nat44_udp_drop(ingress, Nat44UdpHairpinUnsupported, trace);
        }
        if ipv4.destination == config.public_address() && ipv4.protocol == 17 {
            if ingress != config.outside() {
                observe_nat_candidate_if_present(
                    snapshot, config, nat44_udp, nat_now, ingress, trace,
                )?;
                return nat44_udp_drop(ingress, Nat44UdpWrongIngress, trace);
            }
            return decide_nat44_udp_inbound(
                frame,
                snapshot,
                ingress,
                ipv4,
                resolution,
                config,
                nat44_udp,
                firewall_config,
                firewall,
                firewall_audit,
                firewall_validated,
                firewall_plan,
                trace,
            );
        }
    }
    if let Some(config) = nat44_tcp_config {
        if ingress == config.inside()
            && ipv4.destination == config.public_address()
            && (ipv4.protocol == 6 || (ipv4.protocol == 17 && nat44_udp_config.is_none()))
        {
            observe_nat44_tcp_candidate_if_present(
                snapshot, config, nat44_tcp, nat_now, ingress, trace,
            )?;
            return nat44_tcp_drop(ingress, Nat44TcpHairpinUnsupported, trace);
        }
        if ipv4.destination == config.public_address() && ipv4.protocol == 6 {
            if ingress != config.outside() {
                observe_nat44_tcp_candidate_if_present(
                    snapshot, config, nat44_tcp, nat_now, ingress, trace,
                )?;
                return nat44_tcp_drop(ingress, Nat44TcpWrongIngress, trace);
            }
            return decide_nat44_tcp_inbound(
                frame,
                snapshot,
                ingress,
                ipv4,
                resolution,
                config,
                nat44_tcp,
                firewall_config,
                firewall,
                firewall_audit,
                firewall_validated,
                firewall_plan,
                trace,
            );
        }
    }
    if local {
        return decide_local_ipv4(frame, snapshot, ingress, ipv4, trace);
    }
    if ipv4.header_len > 20 {
        return Err(Ipv4OptionsUnsupported);
    }
    let route = route::lookup(snapshot.routes, ipv4.destination);
    let Some(route) = route else {
        if firewall_config.is_some() {
            return Err(FirewallRouteUnavailable);
        }
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
    if combined_realm_mismatch && matches!(ipv4.protocol, 6 | 17) {
        let crosses_mismatched_realm = nat44_udp_config.is_some_and(|config| {
            (ingress == config.inside() && route.egress() == config.outside())
                || (ingress == config.outside() && route.egress() == config.inside())
        }) || nat44_tcp_config.is_some_and(|config| {
            (ingress == config.inside() && route.egress() == config.outside())
                || (ingress == config.outside() && route.egress() == config.inside())
        });
        if crosses_mismatched_realm {
            return reject_combined_realm_mismatch(ingress, nat44_udp, nat44_tcp, trace);
        }
    }
    let crosses_external_to_internal = nat44_udp_config
        .is_some_and(|config| ingress == config.outside() && route.egress() == config.inside())
        || nat44_tcp_config
            .is_some_and(|config| ingress == config.outside() && route.egress() == config.inside());
    if crosses_external_to_internal {
        return Err(Nat44ExternalToInternalBypass);
    }
    let crosses_internal_to_external = nat44_udp_config
        .is_some_and(|config| ingress == config.inside() && route.egress() == config.outside())
        || nat44_tcp_config
            .is_some_and(|config| ingress == config.inside() && route.egress() == config.outside());
    if crosses_internal_to_external && !matches!(ipv4.protocol, 6 | 17) {
        return Err(if nat44_udp_config.is_some() {
            Nat44UdpUnsupportedTransport
        } else {
            Nat44TcpUnsupportedTransport
        });
    }
    if let Some(config) = firewall_config {
        if let Some(udp_config) = nat44_udp_config {
            if ingress == udp_config.inside()
                && route.egress() == udp_config.outside()
                && ipv4.protocol == 17
            {
                let _ = require_nat44_udp_runtime(snapshot, udp_config, nat44_udp, ingress, trace)?;
            }
        }
        if let Some(tcp_config) = nat44_tcp_config {
            if ingress == tcp_config.inside()
                && route.egress() == tcp_config.outside()
                && ipv4.protocol == 6
            {
                let _ = require_nat44_tcp_runtime(snapshot, tcp_config, nat44_tcp, ingress, trace)?;
            }
        }
        let runtime = require_firewall_runtime(snapshot, config, firewall)?;
        *firewall_plan = Some(plan_firewall(
            ingress,
            route.egress(),
            ipv4,
            firewall_validated.expect("forward firewall packet was preflight validated"),
            None,
            runtime,
            firewall_audit,
            nat_now.0,
        )?);
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
        if ingress == config.inside()
            && route.egress() == config.outside()
            && (ipv4.protocol == 17 || (ipv4.protocol == 6 && nat44_tcp_config.is_none()))
        {
            return decide_nat44_udp_outbound(
                frame,
                snapshot,
                ingress,
                ipv4,
                forwarding,
                config,
                nat44_udp,
                firewall_config.is_some(),
                resolution
                    .as_ref()
                    .map_or(MonotonicMillis(0), |(_, now)| *now),
                trace,
            );
        }
    }
    if let Some(config) = nat44_tcp_config {
        if ingress == config.inside()
            && route.egress() == config.outside()
            && (ipv4.protocol == 6 || (ipv4.protocol == 17 && nat44_udp_config.is_none()))
        {
            return decide_nat44_tcp_outbound(
                frame,
                snapshot,
                ingress,
                ipv4,
                forwarding,
                config,
                nat44_tcp,
                firewall_config.is_some(),
                nat_now,
                trace,
            );
        }
    }
    let crosses_udp_only = nat44_tcp_config.is_none()
        && ipv4.protocol == 6
        && nat44_udp_config
            .is_some_and(|config| ingress == config.inside() && route.egress() == config.outside());
    let crosses_tcp_only = nat44_udp_config.is_none()
        && ipv4.protocol == 17
        && nat44_tcp_config
            .is_some_and(|config| ingress == config.inside() && route.egress() == config.outside());
    if crosses_tcp_only {
        return nat44_tcp_drop(ingress, Nat44TcpUnsupportedTransport, trace);
    }
    if crosses_udp_only {
        return nat44_udp_drop(ingress, Nat44UdpUnsupportedTransport, trace);
    }
    Ok(PacketDecision::Ipv4(forwarding))
}

fn is_nat44_icmpv4_candidate(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
) -> bool {
    if ipv4.protocol != 1 {
        return false;
    }
    let Some(ipv4_end) = ipv4.header_offset.checked_add(ipv4.total_len) else {
        return false;
    };
    let Some(icmp_offset) = ipv4.header_offset.checked_add(ipv4.header_len) else {
        return false;
    };
    let Some(type_code_end) = icmp_offset.checked_add(2) else {
        return false;
    };
    if type_code_end > ipv4_end || frame.get(icmp_offset..type_code_end) != Some([3, 4].as_slice())
    {
        return false;
    }

    let udp_enabled = nat44_udp_config.is_some_and(|config| {
        config.policy().icmpv4_errors() == Nat44Icmpv4ErrorPolicy::ExternalOnly
            && ipv4.destination == config.public_address()
    });
    let tcp_enabled = nat44_tcp_config.is_some_and(|config| {
        config.policy().icmpv4_errors() == Nat44Icmpv4ErrorPolicy::ExternalOnly
            && ipv4.destination == config.public_address()
    });
    let quoted_protocol = icmp_offset
        .checked_add(8 + 9)
        .filter(|offset| *offset < ipv4_end)
        .and_then(|offset| frame.get(offset))
        .copied();
    match quoted_protocol {
        Some(17) => udp_enabled,
        Some(6) => tcp_enabled,
        Some(_) | None => udp_enabled || tcp_enabled,
    }
}

#[derive(Clone, Copy)]
struct ParsedNat44Icmpv4Quote {
    protocol: u8,
    public_address: crate::Ipv4Address,
    public_port: u16,
    remote_address: crate::Ipv4Address,
    remote_port: u16,
    inner_checksum_offset: usize,
    inner_checksum: u16,
    inner_source_offset: usize,
    inner_port_offset: usize,
    transport_checksum_offset: Option<usize>,
    transport_checksum: Option<u16>,
    icmp_checksum_offset: usize,
    icmp_checksum: u16,
}

#[allow(clippy::too_many_arguments)]
fn decide_nat44_icmpv4_frag_needed<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    outer: packet::ValidatedIpv4,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    now: MonotonicMillis,
    combined_realm_mismatch: bool,
    related_firewall: Option<&mut FirewallRuntime<'_, '_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let quote = parse_nat44_icmpv4_frag_needed(frame, outer)
        .map_err(|reason| trace_nat44_icmpv4_drop(ingress, reason, trace))?;
    if !icmp_error_source_is_host(snapshot, outer.source)
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == outer.source)
    {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4SourceForbidden, trace);
    }

    let (inside, internal_address, internal_port) = match quote.protocol {
        17 => {
            let Some(config) = nat44_udp_config else {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
            };
            if config.policy().icmpv4_errors() != Nat44Icmpv4ErrorPolicy::ExternalOnly
                || outer.destination != config.public_address()
                || quote.public_address != config.public_address()
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedPublicSourceMismatch, trace);
            }
            if combined_realm_mismatch {
                return nat44_icmpv4_drop(ingress, Nat44CombinedRealmMismatch, trace);
            }
            if ingress != config.outside() {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongIngress, trace);
            }
            if route::lookup(snapshot.routes, outer.source)
                .is_none_or(|reverse| reverse.egress() != config.outside())
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4SourceForbidden, trace);
            }
            if !config.authority_matches(snapshot) {
                return nat44_icmpv4_drop(ingress, Nat44UdpConfigMismatch, trace);
            }
            let Some(runtime) = nat44_udp.as_deref() else {
                return nat44_icmpv4_drop(ingress, Nat44UdpRuntimeUnavailable, trace);
            };
            if runtime.config() != *config {
                return nat44_icmpv4_drop(ingress, Nat44UdpConfigMismatch, trace);
            }
            let lookup = runtime
                .inspect_icmpv4(quote.public_port, quote.remote_address, now.0)
                .map_err(|error| {
                    let reason = match error {
                        Nat44UdpPlanError::MappingMiss => Nat44UdpMappingMiss,
                        Nat44UdpPlanError::FilterDenied => Nat44UdpFilterDenied,
                        Nat44UdpPlanError::ClockRegression => Nat44UdpClockRegression,
                        Nat44UdpPlanError::MappingFull
                        | Nat44UdpPlanError::PeerFull
                        | Nat44UdpPlanError::PortExhausted => {
                            unreachable!("read-only ICMP lookup cannot exhaust state")
                        }
                    };
                    trace_nat44_icmpv4_drop(ingress, reason, trace)
                })?;
            (
                config.inside(),
                lookup.internal_address(),
                lookup.internal_port(),
            )
        }
        6 => {
            let Some(config) = nat44_tcp_config else {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
            };
            if config.policy().icmpv4_errors() != Nat44Icmpv4ErrorPolicy::ExternalOnly
                || outer.destination != config.public_address()
                || quote.public_address != config.public_address()
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedPublicSourceMismatch, trace);
            }
            if combined_realm_mismatch {
                return nat44_icmpv4_drop(ingress, Nat44CombinedRealmMismatch, trace);
            }
            if ingress != config.outside() {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongIngress, trace);
            }
            if route::lookup(snapshot.routes, outer.source)
                .is_none_or(|reverse| reverse.egress() != config.outside())
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4SourceForbidden, trace);
            }
            if !config.authority_matches(snapshot) {
                return nat44_icmpv4_drop(ingress, Nat44TcpConfigMismatch, trace);
            }
            let Some(runtime) = nat44_tcp.as_deref() else {
                return nat44_icmpv4_drop(ingress, Nat44TcpRuntimeUnavailable, trace);
            };
            if runtime.config() != *config {
                return nat44_icmpv4_drop(ingress, Nat44TcpConfigMismatch, trace);
            }
            let lookup = runtime
                .inspect_icmpv4(
                    quote.public_port,
                    quote.remote_address,
                    quote.remote_port,
                    now.0,
                )
                .map_err(|error| {
                    let reason = match error {
                        Nat44TcpPlanError::MappingMiss => Nat44TcpMappingMiss,
                        Nat44TcpPlanError::SessionMiss => Nat44TcpSessionMiss,
                        Nat44TcpPlanError::ClockRegression => Nat44TcpClockRegression,
                        Nat44TcpPlanError::InvalidInitialFlags
                        | Nat44TcpPlanError::MappingFull
                        | Nat44TcpPlanError::SessionFull
                        | Nat44TcpPlanError::PortExhausted => {
                            unreachable!("read-only ICMP lookup cannot create state")
                        }
                    };
                    trace_nat44_icmpv4_drop(ingress, reason, trace)
                })?;
            (
                config.inside(),
                lookup.internal_address(),
                lookup.internal_port(),
            )
        }
        _ => {
            return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
        }
    };

    if let Some(runtime) = related_firewall.as_deref() {
        let protocol = FirewallProtocol::from_ipv4(quote.protocol)
            .expect("the NAT ICMPv4 parser accepts only UDP and TCP quotes");
        let packet = FirewallPacket {
            ingress: inside,
            egress: match quote.protocol {
                17 => nat44_udp_config
                    .expect("UDP quote was accepted only with UDP configuration")
                    .outside(),
                6 => nat44_tcp_config
                    .expect("TCP quote was accepted only with TCP configuration")
                    .outside(),
                _ => unreachable!("the NAT ICMPv4 parser accepts only UDP and TCP quotes"),
            },
            source: internal_address,
            destination: quote.remote_address,
            protocol,
            source_port: internal_port,
            destination_port: quote.remote_port,
            tcp_flags: 0,
        };
        let flow = FirewallRelatedIcmpv4Flow::new(
            packet.ingress,
            packet.egress,
            packet.source,
            packet.destination,
            packet.protocol,
            packet.source_port,
            packet.destination_port,
        );
        match runtime.inspect_related_icmpv4(flow, now.0) {
            Ok(rule_id) => {
                if let Some(audit) = firewall_audit.as_deref_mut() {
                    audit.record(
                        packet,
                        FirewallDisposition {
                            verdict: FirewallVerdict::Allow,
                            class: FirewallConnectionClass::Related,
                            source: FirewallPolicySource::Rule(rule_id),
                            matched_action: Some(FirewallAction::AllowStateful),
                            failure: None,
                        },
                    );
                }
            }
            Err(FirewallRelatedIcmpv4Error::StateMiss) => {
                if let Some(audit) = firewall_audit.as_deref_mut() {
                    audit.record(
                        packet,
                        FirewallDisposition {
                            verdict: FirewallVerdict::Drop,
                            class: FirewallConnectionClass::Related,
                            source: FirewallPolicySource::Default,
                            matched_action: None,
                            failure: None,
                        },
                    );
                }
                return nat44_icmpv4_drop(ingress, FirewallRelatedIcmpv4StateMiss, trace);
            }
            Err(FirewallRelatedIcmpv4Error::ClockRegression) => {
                return nat44_icmpv4_drop(ingress, FirewallClockRegression, trace);
            }
        }
    }

    let route = route::lookup(snapshot.routes, internal_address).ok_or(RouteMiss)?;
    if route.egress() != inside {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongEgress, trace);
    }
    let interface = snapshot
        .interfaces
        .iter()
        .find(|interface| interface.id == inside)
        .ok_or(InterfaceMiss)?;
    let target = route.next_hop().unwrap_or(internal_address);
    let destination_mac = if let Some(neighbor) = snapshot
        .neighbors
        .iter()
        .find(|neighbor| neighbor.interface == inside && neighbor.target == target)
    {
        neighbor.mac
    } else if let Some((runtime, resolution_now)) = resolution.as_mut() {
        match runtime.lookup_dynamic(inside, target, *resolution_now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                trace.record(TraceEvent::NeighborResolution {
                    egress: inside,
                    target,
                    result: ResolutionResult::ClockRegression,
                });
                return Err(NeighborUnresolved);
            }
            DynamicLookup::Miss => {
                if let Some(binding) = snapshot
                    .local_ipv4
                    .iter()
                    .find(|binding| binding.interface == inside)
                {
                    let result = runtime.schedule(
                        ArpRequestAction {
                            egress: inside,
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
                                candidate.egress() == inside
                                    && (candidate.is_connected_directed_broadcast(target)
                                        || candidate.is_connected_network_address(target))
                            }),
                    );
                    trace.record(TraceEvent::NeighborResolution {
                        egress: inside,
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

    trace.record(TraceEvent::Routed {
        egress: inside,
        neighbor_target: target,
    });
    build_nat44_icmpv4_rewrite(
        outer,
        quote,
        inside,
        interface.mac.0,
        destination_mac.0,
        internal_address,
        internal_port,
    )
}

fn parse_nat44_icmpv4_frag_needed(
    frame: &[u8],
    outer: packet::ValidatedIpv4,
) -> Result<ParsedNat44Icmpv4Quote, DropReason> {
    if outer.header_len != 20 {
        return Err(Nat44Icmpv4OuterOptionsUnsupported);
    }
    let outer_flags =
        packet::read_u16(frame, outer.header_offset + 6).ok_or(Nat44Icmpv4HeaderTruncated)?;
    if outer_flags & 0x3fff != 0 {
        return Err(Nat44Icmpv4OuterFragmentUnsupported);
    }
    if outer.ttl <= 1 {
        return Err(Nat44Icmpv4OuterTtlExpired);
    }
    let icmp_offset = outer.header_offset + outer.header_len;
    let icmp_end = outer.header_offset + outer.total_len;
    let icmp = frame
        .get(icmp_offset..icmp_end)
        .ok_or(Nat44Icmpv4HeaderTruncated)?;
    if icmp.len() < 8 {
        return Err(Nat44Icmpv4HeaderTruncated);
    }
    if crate::internet_checksum(icmp) != 0 {
        return Err(Nat44Icmpv4ChecksumInvalid);
    }
    let quote_offset = icmp_offset + 8;
    let quote = frame
        .get(quote_offset..icmp_end)
        .ok_or(Nat44Icmpv4QuoteTruncated)?;
    let Some(&version_ihl) = quote.first() else {
        return Err(Nat44Icmpv4QuoteTruncated);
    };
    if version_ihl >> 4 != 4 {
        return Err(Nat44Icmpv4QuotedVersionUnsupported);
    }
    let ihl_words = version_ihl & 0x0f;
    if ihl_words < 5 {
        return Err(Nat44Icmpv4QuotedIhlTooSmall);
    }
    let inner_header_len = usize::from(ihl_words) * 4;
    let inner_header = quote
        .get(..inner_header_len)
        .ok_or(Nat44Icmpv4QuotedHeaderTruncated)?;
    let inner_total_len =
        usize::from(packet::read_u16(inner_header, 2).ok_or(Nat44Icmpv4QuotedHeaderTruncated)?);
    if inner_total_len < inner_header_len + 8 {
        return Err(Nat44Icmpv4QuotedTotalLengthTooSmall);
    }
    if crate::internet_checksum(inner_header) != 0 {
        return Err(Nat44Icmpv4QuotedChecksumInvalid);
    }
    let inner_flags = packet::read_u16(inner_header, 6).ok_or(Nat44Icmpv4QuotedHeaderTruncated)?;
    if inner_flags != 0x4000 {
        return Err(Nat44Icmpv4QuotedFragmentUnsupported);
    }
    let protocol = *inner_header
        .get(9)
        .ok_or(Nat44Icmpv4QuotedHeaderTruncated)?;
    if !matches!(protocol, 6 | 17) {
        return Err(Nat44Icmpv4QuotedProtocolUnsupported);
    }
    let public_address = crate::Ipv4Address::from_octets(
        inner_header[12..16]
            .try_into()
            .expect("validated IPv4 header contains the source address"),
    );
    let remote_address = crate::Ipv4Address::from_octets(
        inner_header[16..20]
            .try_into()
            .expect("validated IPv4 header contains the destination address"),
    );
    let transport_offset = quote_offset + inner_header_len;
    let quoted_datagram_end = quote_offset + inner_total_len.min(quote.len());
    let transport_available = quoted_datagram_end - transport_offset;
    if transport_available < 8 {
        return Err(Nat44Icmpv4QuoteTruncated);
    }
    let public_port = packet::read_u16(frame, transport_offset).ok_or(Nat44Icmpv4QuoteTruncated)?;
    let remote_port =
        packet::read_u16(frame, transport_offset + 2).ok_or(Nat44Icmpv4QuoteTruncated)?;
    let (transport_checksum_offset, transport_checksum) = if protocol == 17 {
        (
            Some(transport_offset + 6),
            Some(packet::read_u16(frame, transport_offset + 6).ok_or(Nat44Icmpv4QuoteTruncated)?),
        )
    } else if transport_available == 17 {
        return Err(Nat44Icmpv4TcpChecksumPartial);
    } else if transport_available >= 18 {
        (
            Some(transport_offset + 16),
            Some(
                packet::read_u16(frame, transport_offset + 16)
                    .ok_or(Nat44Icmpv4TcpChecksumPartial)?,
            ),
        )
    } else {
        (None, None)
    };
    Ok(ParsedNat44Icmpv4Quote {
        protocol,
        public_address,
        public_port,
        remote_address,
        remote_port,
        inner_checksum_offset: quote_offset + 10,
        inner_checksum: packet::read_u16(frame, quote_offset + 10)
            .ok_or(Nat44Icmpv4QuotedHeaderTruncated)?,
        inner_source_offset: quote_offset + 12,
        inner_port_offset: transport_offset,
        transport_checksum_offset,
        transport_checksum,
        icmp_checksum_offset: icmp_offset + 2,
        icmp_checksum: packet::read_u16(frame, icmp_offset + 2)
            .ok_or(Nat44Icmpv4HeaderTruncated)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_nat44_icmpv4_rewrite(
    outer: packet::ValidatedIpv4,
    quote: ParsedNat44Icmpv4Quote,
    egress: IfId,
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    internal_address: crate::Ipv4Address,
    internal_port: u16,
) -> Result<PacketDecision, DropReason> {
    let old_octets = quote.public_address.octets();
    let new_octets = internal_address.octets();
    let old_high = u16::from_be_bytes([old_octets[0], old_octets[1]]);
    let old_low = u16::from_be_bytes([old_octets[2], old_octets[3]]);
    let new_high = u16::from_be_bytes([new_octets[0], new_octets[1]]);
    let new_low = u16::from_be_bytes([new_octets[2], new_octets[3]]);

    let inner_checksum = rfc1624_update(
        rfc1624_update(quote.inner_checksum, old_high, new_high),
        old_low,
        new_low,
    );
    let transport_checksum = quote.transport_checksum.map(|checksum| {
        if quote.protocol == 17 && checksum == 0 {
            return 0;
        }
        let updated = rfc1624_update(
            rfc1624_update(
                rfc1624_update(checksum, old_high, new_high),
                old_low,
                new_low,
            ),
            quote.public_port,
            internal_port,
        );
        if quote.protocol == 17 && updated == 0 {
            0xffff
        } else {
            updated
        }
    });
    let mut icmp_checksum =
        rfc1624_update(quote.icmp_checksum, quote.inner_checksum, inner_checksum);
    icmp_checksum = rfc1624_update(icmp_checksum, old_high, new_high);
    icmp_checksum = rfc1624_update(icmp_checksum, old_low, new_low);
    icmp_checksum = rfc1624_update(icmp_checksum, quote.public_port, internal_port);
    if let (Some(old), Some(new)) = (quote.transport_checksum, transport_checksum) {
        icmp_checksum = rfc1624_update(icmp_checksum, old, new);
    }

    let outer_destination_offset = outer.header_offset + 16;
    let outer_destination = outer.destination.octets();
    let outer_old_high = u16::from_be_bytes([outer_destination[0], outer_destination[1]]);
    let outer_old_low = u16::from_be_bytes([outer_destination[2], outer_destination[3]]);
    let outer_checksum = rfc1624_update(
        rfc1624_update(
            rfc1624_update(
                outer.checksum,
                u16::from_be_bytes([outer.ttl, outer.protocol]),
                u16::from_be_bytes([outer.ttl - 1, outer.protocol]),
            ),
            outer_old_high,
            new_high,
        ),
        outer_old_low,
        new_low,
    );
    let disposition = Nat44Icmpv4Disposition::Translated {
        quoted_protocol: quote.protocol,
        internal_address,
        internal_port,
    };
    Ok(PacketDecision::Nat44Icmpv4(Nat44Icmpv4RewriteDecision {
        egress,
        source_mac,
        destination_mac,
        outer_ttl_offset: outer.header_offset + 8,
        outer_checksum_offset: outer.header_offset + 10,
        outer_destination_offset,
        inner_checksum_offset: quote.inner_checksum_offset,
        inner_source_offset: quote.inner_source_offset,
        inner_port_offset: quote.inner_port_offset,
        transport_checksum_offset: quote.transport_checksum_offset,
        icmp_checksum_offset: quote.icmp_checksum_offset,
        internal_address: new_octets,
        internal_port,
        outer_checksum,
        inner_checksum,
        transport_checksum,
        icmp_checksum,
        disposition,
    }))
}

fn trace_nat44_icmpv4_drop<T: TraceSink>(
    ingress: IfId,
    reason: DropReason,
    trace: &mut T,
) -> DropReason {
    trace.record(TraceEvent::Nat44Icmpv4 {
        ingress,
        disposition: Nat44Icmpv4Disposition::Rejected { reason },
    });
    reason
}

#[allow(clippy::too_many_arguments)]
fn observe_combined_nat_security_time<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    validated: ValidatedFirewallTransport,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<(), DropReason> {
    match validated.protocol {
        FirewallProtocol::Udp => {
            let Some(config) = nat44_udp_config else {
                return Ok(());
            };
            if ingress != config.inside() && ipv4.destination != config.public_address() {
                return Ok(());
            }
            let runtime = require_nat44_udp_runtime(snapshot, config, nat44_udp, ingress, trace)?;
            if let Err(error) = runtime.observe_now(now.0) {
                let (reason, disposition) = nat44_udp_plan_error(error);
                trace.record(TraceEvent::Nat44Udp {
                    ingress,
                    disposition,
                });
                return Err(reason);
            }
        }
        FirewallProtocol::Tcp => {
            let Some(config) = nat44_tcp_config else {
                return Ok(());
            };
            if ingress != config.inside() && ipv4.destination != config.public_address() {
                return Ok(());
            }
            let runtime = require_nat44_tcp_runtime(snapshot, config, nat44_tcp, ingress, trace)?;
            if let Err(error) = runtime.observe_now(now.0) {
                let (reason, disposition) = nat44_tcp_plan_error(error);
                trace.record(TraceEvent::Nat44Tcp {
                    ingress,
                    disposition,
                });
                return Err(reason);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn plan_firewall(
    ingress: IfId,
    egress: IfId,
    ipv4: packet::ValidatedIpv4,
    validated: ValidatedFirewallTransport,
    canonical: Option<FirewallPacket>,
    runtime: &mut FirewallRuntime<'_, '_>,
    audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    now_ms: u64,
) -> Result<FirewallPlan, DropReason> {
    let packet = firewall_packet(ingress, egress, ipv4, validated, canonical);
    match runtime.plan_packet(packet, now_ms) {
        Ok(plan) => {
            if let Some(audit) = audit.as_deref_mut() {
                audit.record(packet, plan.disposition());
            }
            Ok(plan)
        }
        Err(error) => {
            runtime.record_plan_error(error);
            let disposition = match error {
                FirewallPlanError::RuleDenied(rule_id) => FirewallDisposition {
                    verdict: FirewallVerdict::Drop,
                    class: FirewallConnectionClass::New,
                    source: FirewallPolicySource::Rule(rule_id),
                    matched_action: Some(FirewallAction::Deny),
                    failure: None,
                },
                FirewallPlanError::DefaultDenied => FirewallDisposition {
                    verdict: FirewallVerdict::Drop,
                    class: FirewallConnectionClass::New,
                    source: FirewallPolicySource::Default,
                    matched_action: None,
                    failure: None,
                },
                FirewallPlanError::InvalidInitialTcp(rule_id) => FirewallDisposition {
                    verdict: FirewallVerdict::Drop,
                    class: FirewallConnectionClass::New,
                    source: FirewallPolicySource::Rule(rule_id),
                    matched_action: Some(FirewallAction::AllowStateful),
                    failure: Some(FirewallFailure::InvalidInitialTcp),
                },
                FirewallPlanError::StateFull(rule_id) => FirewallDisposition {
                    verdict: FirewallVerdict::Drop,
                    class: FirewallConnectionClass::New,
                    source: FirewallPolicySource::Rule(rule_id),
                    matched_action: Some(FirewallAction::AllowStateful),
                    failure: Some(FirewallFailure::StateTableFull),
                },
                FirewallPlanError::ClockRegression => {
                    return Err(match error {
                        FirewallPlanError::ClockRegression => FirewallClockRegression,
                        FirewallPlanError::RuleDenied(_)
                        | FirewallPlanError::DefaultDenied
                        | FirewallPlanError::InvalidInitialTcp(_)
                        | FirewallPlanError::StateFull(_) => {
                            unreachable!("policy errors were handled above")
                        }
                    });
                }
            };
            if let Some(audit) = audit.as_deref_mut() {
                audit.record(packet, disposition);
            }
            Err(match error {
                FirewallPlanError::RuleDenied(_) => FirewallRuleDenied,
                FirewallPlanError::DefaultDenied => FirewallDefaultDenied,
                FirewallPlanError::InvalidInitialTcp(_) => FirewallTcpInvalidInitialFlags,
                FirewallPlanError::StateFull(_) => FirewallStateTableFull,
                FirewallPlanError::ClockRegression => FirewallClockRegression,
            })
        }
    }
}

fn require_firewall_runtime<'runtime, 'rules, 'state>(
    snapshot: &ForwardingSnapshot<'_>,
    config: &FirewallConfig<'_>,
    runtime: &'runtime mut Option<&mut FirewallRuntime<'rules, 'state>>,
) -> Result<&'runtime mut FirewallRuntime<'rules, 'state>, DropReason> {
    if !config.authority_matches(snapshot) {
        if let Some(runtime) = runtime.as_deref_mut() {
            runtime.record_config_mismatch();
        }
        return Err(FirewallConfigMismatch);
    }
    let Some(runtime) = runtime.as_deref_mut() else {
        return Err(FirewallRuntimeUnavailable);
    };
    if !runtime.config().identity_matches(*config) {
        runtime.record_config_mismatch();
        return Err(FirewallConfigMismatch);
    }
    Ok(runtime)
}

#[derive(Clone, Copy)]
struct ValidatedFirewallTransport {
    protocol: FirewallProtocol,
    source_port: u16,
    destination_port: u16,
    tcp_flags: u8,
}

fn validate_firewall_transport(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Result<ValidatedFirewallTransport, DropReason> {
    if ipv4.header_len != 20 {
        return Err(FirewallIpv4OptionsUnsupported);
    }
    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(FirewallFragmentUnsupported)?;
    if !matches!(flags_fragment, 0 | 0x4000) {
        return Err(FirewallFragmentUnsupported);
    }
    let protocol = FirewallProtocol::from_ipv4(ipv4.protocol).ok_or(FirewallUnsupportedProtocol)?;
    let packet = match protocol {
        FirewallProtocol::Tcp => {
            let tcp = validate_nat44_tcp(frame, ipv4).map_err(|reason| match reason {
                Nat44TcpHeaderTruncated => FirewallTcpHeaderTruncated,
                Nat44TcpDataOffsetTooSmall => FirewallTcpDataOffsetTooSmall,
                Nat44TcpDataOffsetExceedsIpv4Payload => FirewallTcpDataOffsetExceedsIpv4Payload,
                Nat44TcpChecksumInvalid => FirewallTcpChecksumInvalid,
                _ => FirewallTcpHeaderTruncated,
            })?;
            if tcp.source_port == 0 || tcp.destination_port == 0 {
                return Err(FirewallTcpPortZero);
            }
            ValidatedFirewallTransport {
                protocol,
                source_port: tcp.source_port,
                destination_port: tcp.destination_port,
                tcp_flags: tcp.flags,
            }
        }
        FirewallProtocol::Udp => {
            let udp = validate_nat44_udp(frame, ipv4).map_err(|reason| match reason {
                Nat44UdpHeaderTruncated => FirewallUdpHeaderTruncated,
                Nat44UdpLengthTooSmall => FirewallUdpLengthTooSmall,
                Nat44UdpLengthExceedsIpv4Payload => FirewallUdpLengthExceedsIpv4Payload,
                _ => FirewallUdpHeaderTruncated,
            })?;
            if udp.destination_port == 0 {
                return Err(FirewallUdpDestinationPortZero);
            }
            if udp.checksum != 0 && !udp_checksum_valid(frame, ipv4, udp.offset) {
                return Err(FirewallUdpChecksumInvalid);
            }
            ValidatedFirewallTransport {
                protocol,
                source_port: udp.source_port,
                destination_port: udp.destination_port,
                tcp_flags: 0,
            }
        }
    };
    Ok(packet)
}

fn firewall_packet(
    ingress: IfId,
    egress: IfId,
    ipv4: packet::ValidatedIpv4,
    validated: ValidatedFirewallTransport,
    canonical: Option<FirewallPacket>,
) -> FirewallPacket {
    canonical.unwrap_or(FirewallPacket {
        ingress,
        egress,
        source: ipv4.source,
        destination: ipv4.destination,
        protocol: validated.protocol,
        source_port: validated.source_port,
        destination_port: validated.destination_port,
        tcp_flags: validated.tcp_flags,
    })
}

fn udp_checksum_valid(frame: &[u8], ipv4: packet::ValidatedIpv4, udp_offset: usize) -> bool {
    let Some(length) = packet::read_u16(frame, udp_offset + 4) else {
        return false;
    };
    let length_usize = usize::from(length);
    let Some(end) = udp_offset.checked_add(length_usize) else {
        return false;
    };
    let Some(segment) = frame.get(udp_offset..end) else {
        return false;
    };
    transport_checksum_valid(ipv4.source, ipv4.destination, 17, length, segment)
}

fn transport_checksum_valid(
    source: crate::Ipv4Address,
    destination: crate::Ipv4Address,
    protocol: u8,
    length: u16,
    segment: &[u8],
) -> bool {
    let source = source.octets();
    let destination = destination.octets();
    let mut sum = u32::from(u16::from_be_bytes([source[0], source[1]]))
        + u32::from(u16::from_be_bytes([source[2], source[3]]))
        + u32::from(u16::from_be_bytes([destination[0], destination[1]]))
        + u32::from(u16::from_be_bytes([destination[2], destination[3]]))
        + u32::from(protocol)
        + u32::from(length);
    let mut chunks = segment.chunks_exact(2);
    for word in chunks.by_ref() {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if let Some(last) = chunks.remainder().first() {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

fn nat44_icmpv4_drop<T: TraceSink>(
    ingress: IfId,
    reason: DropReason,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    Err(trace_nat44_icmpv4_drop(ingress, reason, trace))
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
    read_only_plan: bool,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let runtime = require_nat44_udp_runtime(snapshot, config, nat44_udp, ingress, trace)?;
    if !read_only_plan {
        if let Err(error) = runtime.observe_now(now.0) {
            let (reason, disposition) = nat44_udp_plan_error(error);
            trace.record(TraceEvent::Nat44Udp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
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
    let planned = if read_only_plan {
        runtime.plan_outbound_read_only(ipv4.source, udp.source_port, ipv4.destination, now.0)
    } else {
        runtime.plan_outbound(ipv4.source, udp.source_port, ipv4.destination, now.0)
    };
    let plan = match planned {
        Ok(plan) => plan,
        Err(error) => {
            if read_only_plan {
                runtime.record_read_only_plan_error(error);
            } else {
                runtime.record_plan_error(error);
            }
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
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_, '_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_validated: Option<ValidatedFirewallTransport>,
    firewall_plan: &mut Option<FirewallPlan>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let now = resolution
        .as_ref()
        .map_or(MonotonicMillis(0), |(_, now)| *now);
    let runtime = require_nat44_udp_runtime(snapshot, config, nat44_udp, ingress, trace)?;
    if firewall_config.is_none() {
        if let Err(error) = runtime.observe_now(now.0) {
            let (reason, disposition) = nat44_udp_plan_error(error);
            trace.record(TraceEvent::Nat44Udp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
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
    if !icmp_error_source_is_host(snapshot, ipv4.source)
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == ipv4.source)
    {
        return nat44_udp_drop(ingress, Nat44UdpSourceForbidden, trace);
    }
    let planned = if firewall_config.is_some() {
        runtime.plan_inbound_read_only(udp.destination_port, ipv4.source, now.0)
    } else {
        runtime.plan_inbound(udp.destination_port, ipv4.source, now.0)
    };
    let plan = match planned {
        Ok(plan) => plan,
        Err(error) => {
            if firewall_config.is_some() {
                runtime.record_read_only_plan_error(error);
            } else {
                runtime.record_plan_error(error);
            }
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
    if let Some(firewall_config) = firewall_config {
        let firewall_packet = FirewallPacket {
            ingress,
            egress: reverse_route.egress(),
            source: ipv4.source,
            destination: internal_address,
            protocol: FirewallProtocol::Udp,
            source_port: udp.source_port,
            destination_port: plan.internal_port(),
            tcp_flags: 0,
        };
        let firewall_runtime = require_firewall_runtime(snapshot, firewall_config, firewall)?;
        *firewall_plan = Some(plan_firewall(
            ingress,
            reverse_route.egress(),
            ipv4,
            firewall_validated.expect("inbound firewall packet was preflight validated"),
            Some(firewall_packet),
            firewall_runtime,
            firewall_audit,
            now.0,
        )?);
    }
    if ipv4.ttl <= 1 {
        return nat44_udp_drop(ingress, Ipv4TtlExpired, trace);
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

#[allow(clippy::too_many_arguments)]
fn decide_nat44_tcp_outbound<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    forwarding: Ipv4RewriteDecision,
    config: &Nat44TcpConfig,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    read_only_plan: bool,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let runtime = require_nat44_tcp_runtime(snapshot, config, nat44_tcp, ingress, trace)?;
    if !read_only_plan {
        if let Err(error) = runtime.observe_now(now.0) {
            let (reason, disposition) = nat44_tcp_plan_error(error);
            trace.record(TraceEvent::Nat44Tcp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    }
    if ipv4.header_len > 20 {
        return nat44_tcp_drop(ingress, Ipv4OptionsUnsupported, trace);
    }
    if ipv4.protocol != 6 {
        return nat44_tcp_drop(ingress, Nat44TcpUnsupportedTransport, trace);
    }
    if let Err(reason) = validate_nat44_tcp_atomic(frame, ipv4) {
        return nat44_tcp_drop(ingress, reason, trace);
    }
    let tcp = match validate_nat44_tcp(frame, ipv4) {
        Ok(tcp) => tcp,
        Err(reason) => return nat44_tcp_drop(ingress, reason, trace),
    };
    if tcp.source_port == 0 {
        return nat44_tcp_drop(ingress, Nat44TcpSourcePortZero, trace);
    }
    if !icmp_error_source_is_host(snapshot, ipv4.source)
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == ipv4.source)
        || ipv4.source == config.public_address()
    {
        return nat44_tcp_drop(ingress, Nat44TcpSourceForbidden, trace);
    }
    if route::lookup(snapshot.routes, ipv4.source)
        .is_none_or(|reverse| reverse.egress() != config.inside())
    {
        return nat44_tcp_drop(ingress, Nat44TcpReverseAuthorityMismatch, trace);
    }
    let initial_syn = tcp.flags & 0x17 == 0x02;
    let planned = if read_only_plan {
        runtime.plan_outbound_read_only(
            ipv4.source,
            tcp.source_port,
            ipv4.destination,
            tcp.destination_port,
            initial_syn,
            now.0,
        )
    } else {
        runtime.plan_outbound(
            ipv4.source,
            tcp.source_port,
            ipv4.destination,
            tcp.destination_port,
            initial_syn,
            now.0,
        )
    };
    let plan = match planned {
        Ok(plan) => plan,
        Err(error) => {
            if read_only_plan {
                runtime.record_read_only_plan_error(error);
            } else {
                runtime.record_plan_error(error);
            }
            let (reason, disposition) = nat44_tcp_plan_error(error);
            trace.record(TraceEvent::Nat44Tcp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    };
    build_nat44_tcp_rewrite(
        ipv4,
        tcp,
        forwarding,
        ipv4.source,
        config.public_address(),
        tcp.source_port,
        plan.public_port(),
        Nat44TcpTransition::Outbound(plan),
        plan.disposition(),
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_nat44_tcp_inbound<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    config: &Nat44TcpConfig,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_, '_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_validated: Option<ValidatedFirewallTransport>,
    firewall_plan: &mut Option<FirewallPlan>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let now = resolution
        .as_ref()
        .map_or(MonotonicMillis(0), |(_, now)| *now);
    let runtime = require_nat44_tcp_runtime(snapshot, config, nat44_tcp, ingress, trace)?;
    if firewall_config.is_none() {
        if let Err(error) = runtime.observe_now(now.0) {
            let (reason, disposition) = nat44_tcp_plan_error(error);
            trace.record(TraceEvent::Nat44Tcp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    }
    if ipv4.header_len > 20 {
        return nat44_tcp_drop(ingress, Ipv4OptionsUnsupported, trace);
    }
    if let Err(reason) = validate_nat44_tcp_atomic(frame, ipv4) {
        return nat44_tcp_drop(ingress, reason, trace);
    }
    let tcp = match validate_nat44_tcp(frame, ipv4) {
        Ok(tcp) => tcp,
        Err(reason) => return nat44_tcp_drop(ingress, reason, trace),
    };
    if tcp.source_port == 0 {
        return nat44_tcp_drop(ingress, Nat44TcpSourcePortZero, trace);
    }
    if !icmp_error_source_is_host(snapshot, ipv4.source)
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == ipv4.source)
    {
        return nat44_tcp_drop(ingress, Nat44TcpSourceForbidden, trace);
    }
    let planned = if firewall_config.is_some() {
        runtime.plan_inbound_read_only(tcp.destination_port, ipv4.source, tcp.source_port, now.0)
    } else {
        runtime.plan_inbound(tcp.destination_port, ipv4.source, tcp.source_port, now.0)
    };
    let plan = match planned {
        Ok(plan) => plan,
        Err(error) => {
            if firewall_config.is_some() {
                runtime.record_read_only_plan_error(error);
            } else {
                runtime.record_plan_error(error);
            }
            let (reason, disposition) = nat44_tcp_plan_error(error);
            trace.record(TraceEvent::Nat44Tcp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    };
    let internal_address = plan.internal_address();
    let Some(reverse_route) = route::lookup(snapshot.routes, internal_address) else {
        return nat44_tcp_drop(ingress, Nat44TcpReverseAuthorityMismatch, trace);
    };
    if reverse_route.egress() != config.inside() {
        return nat44_tcp_drop(ingress, Nat44TcpWrongEgress, trace);
    }
    if let Some(firewall_config) = firewall_config {
        let firewall_packet = FirewallPacket {
            ingress,
            egress: reverse_route.egress(),
            source: ipv4.source,
            destination: internal_address,
            protocol: FirewallProtocol::Tcp,
            source_port: tcp.source_port,
            destination_port: plan.internal_port(),
            tcp_flags: tcp.flags,
        };
        let firewall_runtime = require_firewall_runtime(snapshot, firewall_config, firewall)?;
        *firewall_plan = Some(plan_firewall(
            ingress,
            reverse_route.egress(),
            ipv4,
            firewall_validated.expect("inbound firewall packet was preflight validated"),
            Some(firewall_packet),
            firewall_runtime,
            firewall_audit,
            now.0,
        )?);
    }
    if ipv4.ttl <= 1 {
        return nat44_tcp_drop(ingress, Ipv4TtlExpired, trace);
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
                return nat44_tcp_drop(ingress, NeighborUnresolved, trace);
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
                return nat44_tcp_drop(ingress, NeighborUnresolved, trace);
            }
        }
    } else {
        return nat44_tcp_drop(ingress, NeighborUnresolved, trace);
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
    build_nat44_tcp_rewrite(
        ipv4,
        tcp,
        forwarding,
        ipv4.destination,
        internal_address,
        tcp.destination_port,
        plan.internal_port(),
        Nat44TcpTransition::Inbound(plan),
        plan.disposition(),
    )
}

#[derive(Clone, Copy)]
struct ValidatedNat44Tcp {
    offset: usize,
    source_port: u16,
    destination_port: u16,
    checksum: u16,
    flags: u8,
}

fn validate_nat44_tcp_atomic(frame: &[u8], ipv4: packet::ValidatedIpv4) -> Result<(), DropReason> {
    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(Ipv4HeaderLengthExceedsPacket)?;
    if flags_fragment != 0x4000 {
        return Err(Nat44TcpNonAtomicIpv4Unsupported);
    }
    Ok(())
}

fn validate_nat44_tcp(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Result<ValidatedNat44Tcp, DropReason> {
    let offset = ipv4
        .header_offset
        .checked_add(ipv4.header_len)
        .ok_or(Nat44TcpHeaderTruncated)?;
    let ipv4_end = ipv4
        .header_offset
        .checked_add(ipv4.total_len)
        .ok_or(Nat44TcpHeaderTruncated)?;
    let minimum_end = offset.checked_add(20).ok_or(Nat44TcpHeaderTruncated)?;
    if minimum_end > ipv4_end || frame.get(offset..minimum_end).is_none() {
        return Err(Nat44TcpHeaderTruncated);
    }
    let data_offset_words = frame[offset + 12] >> 4;
    if data_offset_words < 5 {
        return Err(Nat44TcpDataOffsetTooSmall);
    }
    let header_len = usize::from(data_offset_words) * 4;
    if offset
        .checked_add(header_len)
        .is_none_or(|header_end| header_end > ipv4_end)
    {
        return Err(Nat44TcpDataOffsetExceedsIpv4Payload);
    }
    let segment = frame.get(offset..ipv4_end).ok_or(Nat44TcpHeaderTruncated)?;
    if !tcp_checksum_valid(ipv4.source, ipv4.destination, segment) {
        return Err(Nat44TcpChecksumInvalid);
    }
    Ok(ValidatedNat44Tcp {
        offset,
        source_port: packet::read_u16(frame, offset).ok_or(Nat44TcpHeaderTruncated)?,
        destination_port: packet::read_u16(frame, offset + 2).ok_or(Nat44TcpHeaderTruncated)?,
        checksum: packet::read_u16(frame, offset + 16).ok_or(Nat44TcpHeaderTruncated)?,
        flags: frame[offset + 13],
    })
}

fn tcp_checksum_valid(
    source: crate::Ipv4Address,
    destination: crate::Ipv4Address,
    segment: &[u8],
) -> bool {
    let source = source.octets();
    let destination = destination.octets();
    let Ok(length) = u16::try_from(segment.len()) else {
        return false;
    };
    let mut sum = u32::from(u16::from_be_bytes([source[0], source[1]]))
        + u32::from(u16::from_be_bytes([source[2], source[3]]))
        + u32::from(u16::from_be_bytes([destination[0], destination[1]]))
        + u32::from(u16::from_be_bytes([destination[2], destination[3]]))
        + 6
        + u32::from(length);
    let mut chunks = segment.chunks_exact(2);
    for word in chunks.by_ref() {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if let Some(last) = chunks.remainder().first() {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

#[allow(clippy::too_many_arguments)]
fn build_nat44_tcp_rewrite(
    ipv4: packet::ValidatedIpv4,
    tcp: ValidatedNat44Tcp,
    forwarding: Ipv4RewriteDecision,
    old_address: crate::Ipv4Address,
    new_address: crate::Ipv4Address,
    old_port: u16,
    new_port: u16,
    transition: Nat44TcpTransition,
    disposition: Nat44TcpDisposition,
) -> Result<PacketDecision, DropReason> {
    let outbound = matches!(transition, Nat44TcpTransition::Outbound(_));
    let address_offset = ipv4
        .header_offset
        .checked_add(if outbound { 12 } else { 16 })
        .ok_or(Ipv4HeaderLengthExceedsPacket)?;
    let address_end = address_offset
        .checked_add(4)
        .ok_or(Ipv4HeaderLengthExceedsPacket)?;
    let port_offset = tcp
        .offset
        .checked_add(if outbound { 0 } else { 2 })
        .ok_or(Nat44TcpHeaderTruncated)?;
    let port_end = port_offset.checked_add(2).ok_or(Nat44TcpHeaderTruncated)?;
    let tcp_checksum_offset = tcp.offset.checked_add(16).ok_or(Nat44TcpHeaderTruncated)?;
    let tcp_checksum_end = tcp_checksum_offset
        .checked_add(2)
        .ok_or(Nat44TcpHeaderTruncated)?;
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
    let tcp_checksum = rfc1624_update(
        rfc1624_update(
            rfc1624_update(tcp.checksum, old_high, new_high),
            old_low,
            new_low,
        ),
        old_port,
        new_port,
    );
    Ok(PacketDecision::Nat44Tcp(Nat44TcpRewriteDecision {
        forwarding,
        address_offset,
        address_end,
        new_address: new_octets,
        port_offset,
        port_end,
        new_port,
        tcp_checksum_offset,
        tcp_checksum_end,
        ipv4_checksum,
        tcp_checksum,
        transition,
        disposition,
    }))
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

fn reject_combined_realm_mismatch<T: TraceSink>(
    ingress: IfId,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    if let Some(runtime) = nat44_udp.as_deref_mut() {
        runtime.record_config_mismatch();
    }
    if let Some(runtime) = nat44_tcp.as_deref_mut() {
        runtime.record_config_mismatch();
    }
    trace.record(TraceEvent::Nat44Udp {
        ingress,
        disposition: Nat44UdpDisposition::ConfigMismatch,
    });
    trace.record(TraceEvent::Nat44Tcp {
        ingress,
        disposition: Nat44TcpDisposition::ConfigMismatch,
    });
    Err(Nat44CombinedRealmMismatch)
}

fn nat44_tcp_plan_error(error: Nat44TcpPlanError) -> (DropReason, Nat44TcpDisposition) {
    match error {
        Nat44TcpPlanError::MappingMiss => (Nat44TcpMappingMiss, Nat44TcpDisposition::MappingMiss),
        Nat44TcpPlanError::SessionMiss => (Nat44TcpSessionMiss, Nat44TcpDisposition::SessionMiss),
        Nat44TcpPlanError::InvalidInitialFlags => (
            Nat44TcpInvalidInitialFlags,
            Nat44TcpDisposition::InvalidInitialFlags,
        ),
        Nat44TcpPlanError::MappingFull => {
            (Nat44TcpMappingTableFull, Nat44TcpDisposition::MappingFull)
        }
        Nat44TcpPlanError::SessionFull => {
            (Nat44TcpSessionTableFull, Nat44TcpDisposition::SessionFull)
        }
        Nat44TcpPlanError::PortExhausted => {
            (Nat44TcpPortExhausted, Nat44TcpDisposition::PortExhausted)
        }
        Nat44TcpPlanError::ClockRegression => (
            Nat44TcpClockRegression,
            Nat44TcpDisposition::ClockRegression,
        ),
    }
}

fn nat44_tcp_drop<T: TraceSink>(
    ingress: IfId,
    reason: DropReason,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    trace.record(TraceEvent::Nat44Tcp {
        ingress,
        disposition: Nat44TcpDisposition::Rejected { reason },
    });
    Err(reason)
}

fn require_nat44_tcp_runtime<'runtime, 'storage, T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    config: &Nat44TcpConfig,
    runtime: &'runtime mut Option<&mut Nat44TcpRuntime<'storage>>,
    ingress: IfId,
    trace: &mut T,
) -> Result<&'runtime mut Nat44TcpRuntime<'storage>, DropReason> {
    if !config.authority_matches(snapshot) {
        if let Some(runtime) = runtime.as_deref_mut() {
            runtime.record_config_mismatch();
        }
        trace.record(TraceEvent::Nat44Tcp {
            ingress,
            disposition: Nat44TcpDisposition::ConfigMismatch,
        });
        return Err(Nat44TcpConfigMismatch);
    }
    let Some(runtime) = runtime.as_deref_mut() else {
        trace.record(TraceEvent::Nat44Tcp {
            ingress,
            disposition: Nat44TcpDisposition::Rejected {
                reason: Nat44TcpRuntimeUnavailable,
            },
        });
        return Err(Nat44TcpRuntimeUnavailable);
    };
    if runtime.config() != *config {
        runtime.record_config_mismatch();
        trace.record(TraceEvent::Nat44Tcp {
            ingress,
            disposition: Nat44TcpDisposition::ConfigMismatch,
        });
        return Err(Nat44TcpConfigMismatch);
    }
    Ok(runtime)
}

fn observe_nat44_tcp_candidate_if_present<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    config: &Nat44TcpConfig,
    runtime: &mut Option<&mut Nat44TcpRuntime<'_>>,
    now: MonotonicMillis,
    ingress: IfId,
    trace: &mut T,
) -> Result<(), DropReason> {
    if runtime.is_none() {
        return Ok(());
    }
    let runtime = require_nat44_tcp_runtime(snapshot, config, runtime, ingress, trace)?;
    if let Err(error) = runtime.observe_now(now.0) {
        let (reason, disposition) = nat44_tcp_plan_error(error);
        trace.record(TraceEvent::Nat44Tcp {
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
        PacketDecision::Nat44Tcp(nat) => apply_nat44_tcp_rewrite(frame, nat),
        PacketDecision::Nat44Icmpv4(nat) => apply_nat44_icmpv4_rewrite(frame, nat),
        PacketDecision::ArpReply(arp) => apply_arp_reply(frame, arp),
        PacketDecision::Icmpv4EchoReply(icmp) => apply_icmpv4_echo_reply(frame, icmp),
        PacketDecision::ConsumeArp(_) | PacketDecision::ConsumeIpv4Local => {
            unreachable!("consume decisions are never rewritten")
        }
    }
}

fn apply_nat44_icmpv4_rewrite(
    frame: &mut [u8],
    decision: Nat44Icmpv4RewriteDecision,
) -> Result<(), DropReason> {
    let required = [
        (decision.outer_checksum_offset, 2),
        (decision.outer_destination_offset, 4),
        (decision.inner_checksum_offset, 2),
        (decision.inner_source_offset, 4),
        (decision.inner_port_offset, 2),
        (decision.icmp_checksum_offset, 2),
    ];
    if frame.get(0..12).is_none()
        || frame.get(decision.outer_ttl_offset).is_none()
        || required
            .iter()
            .any(|(offset, len)| frame.get(*offset..*offset + *len).is_none())
        || decision
            .transport_checksum_offset
            .is_some_and(|offset| frame.get(offset..offset + 2).is_none())
    {
        return Err(Nat44Icmpv4QuoteTruncated);
    }
    frame[0..6].copy_from_slice(&decision.destination_mac);
    frame[6..12].copy_from_slice(&decision.source_mac);
    frame[decision.outer_ttl_offset] -= 1;
    frame[decision.outer_checksum_offset..decision.outer_checksum_offset + 2]
        .copy_from_slice(&decision.outer_checksum.to_be_bytes());
    frame[decision.outer_destination_offset..decision.outer_destination_offset + 4]
        .copy_from_slice(&decision.internal_address);
    frame[decision.inner_checksum_offset..decision.inner_checksum_offset + 2]
        .copy_from_slice(&decision.inner_checksum.to_be_bytes());
    frame[decision.inner_source_offset..decision.inner_source_offset + 4]
        .copy_from_slice(&decision.internal_address);
    frame[decision.inner_port_offset..decision.inner_port_offset + 2]
        .copy_from_slice(&decision.internal_port.to_be_bytes());
    if let (Some(offset), Some(checksum)) = (
        decision.transport_checksum_offset,
        decision.transport_checksum,
    ) {
        frame[offset..offset + 2].copy_from_slice(&checksum.to_be_bytes());
    }
    frame[decision.icmp_checksum_offset..decision.icmp_checksum_offset + 2]
        .copy_from_slice(&decision.icmp_checksum.to_be_bytes());
    Ok(())
}

fn apply_nat44_tcp_rewrite(
    frame: &mut [u8],
    decision: Nat44TcpRewriteDecision,
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
            .get(decision.tcp_checksum_offset..decision.tcp_checksum_end)
            .is_none()
    {
        return Err(Nat44TcpHeaderTruncated);
    }
    frame[0..6].copy_from_slice(&decision.forwarding.destination_mac);
    frame[6..12].copy_from_slice(&decision.forwarding.source_mac);
    frame[decision.forwarding.ttl_offset] -= 1;
    frame[decision.forwarding.checksum_offset..decision.forwarding.checksum_end]
        .copy_from_slice(&decision.ipv4_checksum.to_be_bytes());
    frame[decision.address_offset..decision.address_end].copy_from_slice(&decision.new_address);
    frame[decision.port_offset..decision.port_end]
        .copy_from_slice(&decision.new_port.to_be_bytes());
    frame[decision.tcp_checksum_offset..decision.tcp_checksum_end]
        .copy_from_slice(&decision.tcp_checksum.to_be_bytes());
    Ok(())
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
    use super::{decide_ipv4, BatchReport, DropReason};
    use crate::{
        ipv4_header_checksum, BatchCompletion, ForwardingSnapshot, IfId, Interface, Ipv4Address,
        LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44Icmpv4ErrorPolicy, Nat44UdpConfig,
        Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, NoTrace,
        ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
    };

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const INTERNAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
    const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
    const ROUTER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);

    fn report(
        core: (usize, usize, usize, usize),
        backend: (usize, usize, usize, usize),
    ) -> BatchReport<()> {
        let (received, tx_requested, dropped, consumed) = core;
        let (completion_tx_requested, tx_accepted, tx_rejected, recycled) = backend;
        BatchReport {
            received,
            tx_requested,
            dropped,
            consumed,
            completion: BatchCompletion {
                tx_requested: completion_tx_requested,
                tx_accepted,
                tx_rejected,
                recycled,
                error: None,
            },
        }
    }

    #[test]
    fn batch_report_invariants_cover_core_and_backend_accounting() {
        assert!(report((5, 2, 2, 1), (2, 1, 1, 3)).invariants_hold());
        assert!(!report((6, 2, 2, 1), (2, 1, 1, 3)).invariants_hold());
        assert!(!report((5, 2, 2, 1), (1, 1, 0, 3)).invariants_hold());
        assert!(!report((5, 2, 2, 1), (2, 2, 1, 3)).invariants_hold());
        assert!(!report((5, 2, 2, 1), (2, 1, 1, 2)).invariants_hold());
    }

    #[test]
    fn batch_report_invariants_reject_counter_overflow() {
        assert!(!report(
            (usize::MAX, usize::MAX, 1, 0),
            (usize::MAX, usize::MAX, 0, 1),
        )
        .invariants_hold());
    }

    fn frag_needed_frame() -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 20 + 8 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&56_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 1;
        frame[26..30].copy_from_slice(&ROUTER.octets());
        frame[30..34].copy_from_slice(&PUBLIC.octets());
        frame[34..36].copy_from_slice(&[3, 4]);
        frame[40..42].copy_from_slice(&1500_u16.to_be_bytes());
        frame[42] = 0x45;
        frame[44..46].copy_from_slice(&28_u16.to_be_bytes());
        frame[48..50].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[50] = 64;
        frame[51] = 17;
        frame[54..58].copy_from_slice(&PUBLIC.octets());
        frame[58..62].copy_from_slice(&REMOTE.octets());
        frame[62..64].copy_from_slice(&40_000_u16.to_be_bytes());
        frame[64..66].copy_from_slice(&53_u16.to_be_bytes());
        frame[66..68].copy_from_slice(&8_u16.to_be_bytes());
        let inner_checksum = ipv4_header_checksum(&frame[42..62]);
        frame[52..54].copy_from_slice(&inner_checksum.to_be_bytes());
        let icmp_checksum = crate::internet_checksum(&frame[34..70]);
        frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
        let outer_checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&outer_checksum.to_be_bytes());
        frame
    }

    fn assert_icmp_routing_defense(routes: &[Route], expected: DropReason) {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let snapshot = ForwardingSnapshot::new(routes, &interfaces, &[], &bindings).unwrap();
        let config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
        )
        .unwrap();
        let mut mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut peers = [Nat44UdpPeerSlot::default(); 1];
        let mut nat = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
        let plan = nat.plan_outbound(INTERNAL, 12_345, REMOTE, 0).unwrap();
        nat.commit_outbound(plan, 0);
        let before_mapping = nat.mappings()[0];
        let before_peer = nat.peers()[0];
        let before_counters = nat.counters();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut states,
            &mut actions,
        );
        let mut resolution = Some((&mut resolution, MonotonicMillis(0)));
        let mut generated_errors = None;
        let mut udp = Some(&mut nat);
        let mut tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let result = decide_ipv4(
            &frag_needed_frame(),
            &snapshot,
            WAN,
            &mut resolution,
            &mut generated_errors,
            Some(&config),
            &mut udp,
            None,
            &mut tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            &mut NoTrace,
        );
        assert!(matches!(result, Err(reason) if reason == expected));
        assert_eq!(nat.mappings()[0], before_mapping);
        assert_eq!(nat.peers()[0], before_peer);
        assert_eq!(nat.counters(), before_counters);
    }

    #[test]
    fn icmp_translation_route_miss_and_wrong_egress_are_defensive_and_read_only() {
        let route_to_router = Route::new(ROUTER, 32, WAN, None).expect("host route is canonical");
        assert_icmp_routing_defense(&[route_to_router], DropReason::RouteMiss);
        let default = Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, None).unwrap();
        assert_icmp_routing_defense(&[default], DropReason::Nat44Icmpv4WrongEgress);
    }

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
            (54, "NAT44_TCP_RUNTIME_UNAVAILABLE"),
            (55, "NAT44_TCP_CONFIG_MISMATCH"),
            (56, "NAT44_TCP_UNSUPPORTED_TRANSPORT"),
            (57, "NAT44_TCP_HAIRPIN_UNSUPPORTED"),
            (58, "NAT44_TCP_NON_ATOMIC_IPV4_UNSUPPORTED"),
            (59, "NAT44_TCP_HEADER_TRUNCATED"),
            (60, "NAT44_TCP_DATA_OFFSET_TOO_SMALL"),
            (61, "NAT44_TCP_DATA_OFFSET_EXCEEDS_IPV4_PAYLOAD"),
            (62, "NAT44_TCP_CHECKSUM_INVALID"),
            (63, "NAT44_TCP_SOURCE_PORT_ZERO"),
            (64, "NAT44_TCP_SOURCE_FORBIDDEN"),
            (65, "NAT44_TCP_REVERSE_AUTHORITY_MISMATCH"),
            (66, "NAT44_TCP_MAPPING_MISS"),
            (67, "NAT44_TCP_SESSION_MISS"),
            (68, "NAT44_TCP_INVALID_INITIAL_FLAGS"),
            (69, "NAT44_TCP_MAPPING_TABLE_FULL"),
            (70, "NAT44_TCP_SESSION_TABLE_FULL"),
            (71, "NAT44_TCP_PORT_EXHAUSTED"),
            (72, "NAT44_TCP_CLOCK_REGRESSION"),
            (73, "NAT44_TCP_WRONG_INGRESS"),
            (74, "NAT44_TCP_WRONG_EGRESS"),
            (75, "NAT44_COMBINED_REALM_MISMATCH"),
            (76, "NAT44_ICMPV4_WRONG_INGRESS"),
            (77, "NAT44_ICMPV4_OUTER_OPTIONS_UNSUPPORTED"),
            (78, "NAT44_ICMPV4_OUTER_FRAGMENT_UNSUPPORTED"),
            (79, "NAT44_ICMPV4_OUTER_TTL_EXPIRED"),
            (80, "NAT44_ICMPV4_HEADER_TRUNCATED"),
            (81, "NAT44_ICMPV4_CHECKSUM_INVALID"),
            (82, "NAT44_ICMPV4_QUOTE_TRUNCATED"),
            (83, "NAT44_ICMPV4_QUOTED_VERSION_UNSUPPORTED"),
            (84, "NAT44_ICMPV4_QUOTED_IHL_TOO_SMALL"),
            (85, "NAT44_ICMPV4_QUOTED_HEADER_TRUNCATED"),
            (86, "NAT44_ICMPV4_QUOTED_TOTAL_LENGTH_TOO_SMALL"),
            (87, "NAT44_ICMPV4_QUOTED_CHECKSUM_INVALID"),
            (88, "NAT44_ICMPV4_QUOTED_FRAGMENT_UNSUPPORTED"),
            (89, "NAT44_ICMPV4_QUOTED_PROTOCOL_UNSUPPORTED"),
            (90, "NAT44_ICMPV4_QUOTED_PUBLIC_SOURCE_MISMATCH"),
            (91, "NAT44_ICMPV4_TCP_CHECKSUM_PARTIAL"),
            (92, "NAT44_ICMPV4_WRONG_EGRESS"),
            (93, "NAT44_ICMPV4_SOURCE_FORBIDDEN"),
            (94, "FIREWALL_RUNTIME_UNAVAILABLE"),
            (95, "FIREWALL_CONFIG_MISMATCH"),
            (96, "FIREWALL_UNSUPPORTED_PROTOCOL"),
            (97, "FIREWALL_IPV4_OPTIONS_UNSUPPORTED"),
            (98, "FIREWALL_FRAGMENT_UNSUPPORTED"),
            (99, "FIREWALL_TCP_HEADER_TRUNCATED"),
            (100, "FIREWALL_TCP_DATA_OFFSET_TOO_SMALL"),
            (101, "FIREWALL_TCP_DATA_OFFSET_EXCEEDS_IPV4_PAYLOAD"),
            (102, "FIREWALL_TCP_CHECKSUM_INVALID"),
            (103, "FIREWALL_TCP_PORT_ZERO"),
            (104, "FIREWALL_UDP_HEADER_TRUNCATED"),
            (105, "FIREWALL_UDP_LENGTH_TOO_SMALL"),
            (106, "FIREWALL_UDP_LENGTH_EXCEEDS_IPV4_PAYLOAD"),
            (107, "FIREWALL_UDP_CHECKSUM_INVALID"),
            (108, "FIREWALL_UDP_DESTINATION_PORT_ZERO"),
            (109, "FIREWALL_RULE_DENIED"),
            (110, "FIREWALL_DEFAULT_DENIED"),
            (111, "FIREWALL_TCP_INVALID_INITIAL_FLAGS"),
            (112, "FIREWALL_STATE_TABLE_FULL"),
            (113, "FIREWALL_CLOCK_REGRESSION"),
            (114, "FIREWALL_RELATED_ICMPV4_UNSUPPORTED"),
            (115, "FIREWALL_ROUTE_UNAVAILABLE"),
            (116, "FIREWALL_RELATED_ICMPV4_STATE_MISS"),
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
            DropReason::Nat44TcpRuntimeUnavailable,
            DropReason::Nat44TcpConfigMismatch,
            DropReason::Nat44TcpUnsupportedTransport,
            DropReason::Nat44TcpHairpinUnsupported,
            DropReason::Nat44TcpNonAtomicIpv4Unsupported,
            DropReason::Nat44TcpHeaderTruncated,
            DropReason::Nat44TcpDataOffsetTooSmall,
            DropReason::Nat44TcpDataOffsetExceedsIpv4Payload,
            DropReason::Nat44TcpChecksumInvalid,
            DropReason::Nat44TcpSourcePortZero,
            DropReason::Nat44TcpSourceForbidden,
            DropReason::Nat44TcpReverseAuthorityMismatch,
            DropReason::Nat44TcpMappingMiss,
            DropReason::Nat44TcpSessionMiss,
            DropReason::Nat44TcpInvalidInitialFlags,
            DropReason::Nat44TcpMappingTableFull,
            DropReason::Nat44TcpSessionTableFull,
            DropReason::Nat44TcpPortExhausted,
            DropReason::Nat44TcpClockRegression,
            DropReason::Nat44TcpWrongIngress,
            DropReason::Nat44TcpWrongEgress,
            DropReason::Nat44CombinedRealmMismatch,
            DropReason::Nat44Icmpv4WrongIngress,
            DropReason::Nat44Icmpv4OuterOptionsUnsupported,
            DropReason::Nat44Icmpv4OuterFragmentUnsupported,
            DropReason::Nat44Icmpv4OuterTtlExpired,
            DropReason::Nat44Icmpv4HeaderTruncated,
            DropReason::Nat44Icmpv4ChecksumInvalid,
            DropReason::Nat44Icmpv4QuoteTruncated,
            DropReason::Nat44Icmpv4QuotedVersionUnsupported,
            DropReason::Nat44Icmpv4QuotedIhlTooSmall,
            DropReason::Nat44Icmpv4QuotedHeaderTruncated,
            DropReason::Nat44Icmpv4QuotedTotalLengthTooSmall,
            DropReason::Nat44Icmpv4QuotedChecksumInvalid,
            DropReason::Nat44Icmpv4QuotedFragmentUnsupported,
            DropReason::Nat44Icmpv4QuotedProtocolUnsupported,
            DropReason::Nat44Icmpv4QuotedPublicSourceMismatch,
            DropReason::Nat44Icmpv4TcpChecksumPartial,
            DropReason::Nat44Icmpv4WrongEgress,
            DropReason::Nat44Icmpv4SourceForbidden,
            DropReason::FirewallRuntimeUnavailable,
            DropReason::FirewallConfigMismatch,
            DropReason::FirewallUnsupportedProtocol,
            DropReason::FirewallIpv4OptionsUnsupported,
            DropReason::FirewallFragmentUnsupported,
            DropReason::FirewallTcpHeaderTruncated,
            DropReason::FirewallTcpDataOffsetTooSmall,
            DropReason::FirewallTcpDataOffsetExceedsIpv4Payload,
            DropReason::FirewallTcpChecksumInvalid,
            DropReason::FirewallTcpPortZero,
            DropReason::FirewallUdpHeaderTruncated,
            DropReason::FirewallUdpLengthTooSmall,
            DropReason::FirewallUdpLengthExceedsIpv4Payload,
            DropReason::FirewallUdpChecksumInvalid,
            DropReason::FirewallUdpDestinationPortZero,
            DropReason::FirewallRuleDenied,
            DropReason::FirewallDefaultDenied,
            DropReason::FirewallTcpInvalidInitialFlags,
            DropReason::FirewallStateTableFull,
            DropReason::FirewallClockRegression,
            DropReason::FirewallRelatedIcmpv4Unsupported,
            DropReason::FirewallRouteUnavailable,
            DropReason::FirewallRelatedIcmpv4StateMiss,
        ];
        assert_eq!(actual.len(), expected.len());
        for (reason, &(discriminant, code)) in actual.iter().zip(&expected) {
            assert_eq!(*reason as u16, discriminant);
            assert_eq!(reason.code(), code);
        }
    }
}

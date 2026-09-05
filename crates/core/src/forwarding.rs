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
    MacAddress, MonotonicMillis, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig, Nat44TcpDisposition,
    Nat44TcpRuntime, Nat44UdpConfig, Nat44UdpDisposition, Nat44UdpRuntime, Neighbor, PacketBatch,
    ResolutionHoldDisposition, ResolutionResult, ResolutionRuntime, Route, ARP_ETHERTYPE,
    IPV4_ETHERTYPE, RESOLUTION_HOLD_MAX_FRAME_LEN,
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
    Ipv4IngressInterfaceUnknown = 117,
    Ipv4EthernetSourceZero = 118,
    Ipv4EthernetSourceBroadcast = 119,
    Ipv4EthernetSourceMulticast = 120,
    Ipv4EthernetDestinationZero = 121,
    Ipv4EthernetDestinationBroadcast = 122,
    Ipv4EthernetDestinationMulticast = 123,
    Ipv4SourceUnspecifiedNetwork = 124,
    Ipv4SourceLoopback = 125,
    Ipv4SourceMulticast = 126,
    Ipv4SourceLimitedBroadcast = 127,
    Ipv4SourceClassE = 128,
    Ipv4SourceNetworkAddress = 129,
    Ipv4SourceDirectedBroadcast = 130,
    Ipv4DestinationUnspecifiedNetwork = 131,
    Ipv4DestinationLoopback = 132,
    Ipv4DestinationMulticast = 133,
    Ipv4DestinationLimitedBroadcast = 134,
    Ipv4DestinationClassE = 135,
    Ipv4DestinationNetworkAddress = 136,
    Ipv4DestinationDirectedBroadcast = 137,
    EthernetDestinationNotLocal = 138,
    ArpIngressInterfaceUnknown = 139,
    ArpEthernetSourceZero = 140,
    ArpEthernetSourceBroadcast = 141,
    ArpEthernetSourceMulticast = 142,
    ArpEthernetDestinationZero = 143,
    ArpEthernetDestinationMulticast = 144,
    Ipv4SourceLocalAddress = 145,
    Ipv4FragmentationNeeded = 146,
    Ipv4FragmentationRequired = 147,
    Ipv4SourceRouteUnsupported = 148,
    Ipv4OptionsMalformed = 149,
    Icmpv4ProtocolUnreachable = 150,
    Icmpv4PortUnreachable = 151,
    Icmpv4TimestampCodeInvalid = 152,
    Icmpv4TimestampHeaderTruncated = 153,
    FirewallRuleRejected = 154,
}

/// The IPv4 Don't Fragment flag inside the flags-and-offset field (RFC 791).
const IPV4_DONT_FRAGMENT_FLAG: u16 = 0x4000;

use DropReason::*;

impl DropReason {
    /// The largest discriminant this enum assigns.
    ///
    /// Anything serialising a reason by number needs this bound, and deriving
    /// it here keeps such a check from going stale when a reason is added.
    pub const LARGEST_CODE: u16 = Self::FirewallRuleRejected as u16;

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
            Ipv4IngressInterfaceUnknown => "IPV4_INGRESS_INTERFACE_UNKNOWN",
            Ipv4EthernetSourceZero => "IPV4_ETHERNET_SOURCE_ZERO",
            Ipv4EthernetSourceBroadcast => "IPV4_ETHERNET_SOURCE_BROADCAST",
            Ipv4EthernetSourceMulticast => "IPV4_ETHERNET_SOURCE_MULTICAST",
            Ipv4EthernetDestinationZero => "IPV4_ETHERNET_DESTINATION_ZERO",
            Ipv4EthernetDestinationBroadcast => "IPV4_ETHERNET_DESTINATION_BROADCAST",
            Ipv4EthernetDestinationMulticast => "IPV4_ETHERNET_DESTINATION_MULTICAST",
            Ipv4SourceUnspecifiedNetwork => "IPV4_SOURCE_UNSPECIFIED_NETWORK",
            Ipv4SourceLoopback => "IPV4_SOURCE_LOOPBACK",
            Ipv4SourceMulticast => "IPV4_SOURCE_MULTICAST",
            Ipv4SourceLimitedBroadcast => "IPV4_SOURCE_LIMITED_BROADCAST",
            Ipv4SourceClassE => "IPV4_SOURCE_CLASS_E",
            Ipv4SourceNetworkAddress => "IPV4_SOURCE_NETWORK_ADDRESS",
            Ipv4SourceDirectedBroadcast => "IPV4_SOURCE_DIRECTED_BROADCAST",
            Ipv4DestinationUnspecifiedNetwork => "IPV4_DESTINATION_UNSPECIFIED_NETWORK",
            Ipv4DestinationLoopback => "IPV4_DESTINATION_LOOPBACK",
            Ipv4DestinationMulticast => "IPV4_DESTINATION_MULTICAST",
            Ipv4DestinationLimitedBroadcast => "IPV4_DESTINATION_LIMITED_BROADCAST",
            Ipv4DestinationClassE => "IPV4_DESTINATION_CLASS_E",
            Ipv4DestinationNetworkAddress => "IPV4_DESTINATION_NETWORK_ADDRESS",
            Ipv4DestinationDirectedBroadcast => "IPV4_DESTINATION_DIRECTED_BROADCAST",
            EthernetDestinationNotLocal => "ETHERNET_DESTINATION_NOT_LOCAL",
            ArpIngressInterfaceUnknown => "ARP_INGRESS_INTERFACE_UNKNOWN",
            ArpEthernetSourceZero => "ARP_ETHERNET_SOURCE_ZERO",
            ArpEthernetSourceBroadcast => "ARP_ETHERNET_SOURCE_BROADCAST",
            ArpEthernetSourceMulticast => "ARP_ETHERNET_SOURCE_MULTICAST",
            ArpEthernetDestinationZero => "ARP_ETHERNET_DESTINATION_ZERO",
            ArpEthernetDestinationMulticast => "ARP_ETHERNET_DESTINATION_MULTICAST",
            Ipv4SourceLocalAddress => "IPV4_SOURCE_LOCAL_ADDRESS",
            Ipv4FragmentationNeeded => "IPV4_FRAGMENTATION_NEEDED",
            Ipv4FragmentationRequired => "IPV4_FRAGMENTATION_REQUIRED",
            Ipv4SourceRouteUnsupported => "IPV4_SOURCE_ROUTE_UNSUPPORTED",
            Ipv4OptionsMalformed => "IPV4_OPTIONS_MALFORMED",
            Icmpv4ProtocolUnreachable => "ICMPV4_PROTOCOL_UNREACHABLE",
            Icmpv4PortUnreachable => "ICMPV4_PORT_UNREACHABLE",
            Icmpv4TimestampCodeInvalid => "ICMPV4_TIMESTAMP_CODE_INVALID",
            Icmpv4TimestampHeaderTruncated => "ICMPV4_TIMESTAMP_HEADER_TRUNCATED",
            FirewallRuleRejected => "FIREWALL_RULE_REJECTED",
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

#[derive(Clone, Copy)]
pub struct ForwardingSnapshot<'a> {
    pub(crate) routes: &'a [Route],
    pub(crate) interfaces: &'a [Interface],
    pub(crate) neighbors: &'a [Neighbor],
    pub(crate) local_ipv4: &'a [LocalIpv4Binding],
    pub(crate) ipv4_origin: Ipv4OriginPolicy,
    authority: u64,
    identity: [usize; 8],
}

const VALIDATED_OWNER_AUTHORITY_BIT: u64 = 1 << 63;

impl std::fmt::Debug for ForwardingSnapshot<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForwardingSnapshot")
            .field("routes_len", &self.routes.len())
            .field("interfaces_len", &self.interfaces.len())
            .field("neighbors_len", &self.neighbors.len())
            .field("local_ipv4_len", &self.local_ipv4.len())
            .field("ipv4_origin", &self.ipv4_origin)
            .finish_non_exhaustive()
    }
}

/// Immutable validated forwarding tables owned by the cold publication path.
///
/// Construction consumes caller-allocated boxes and validates them once.
/// [`Self::snapshot`] is then an infallible O(1) borrow scoped to this owner.
///
/// ```compile_fail
/// use ruster_core::{ForwardingSnapshot, ValidatedForwardingOwner};
///
/// fn escape(owner: &ValidatedForwardingOwner) -> ForwardingSnapshot<'static> {
///     owner.snapshot()
/// }
/// ```
pub struct ValidatedForwardingOwner {
    routes: Box<[Route]>,
    interfaces: Box<[Interface]>,
    neighbors: Box<[Neighbor]>,
    local_ipv4: Box<[LocalIpv4Binding]>,
    ipv4_origin: Ipv4OriginPolicy,
    authority: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidatedForwardingOwnerError {
    Snapshot(SnapshotError),
    PublicationNonceExhausted,
}

impl std::fmt::Debug for ValidatedForwardingOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedForwardingOwner")
            .field("routes_len", &self.routes.len())
            .field("interfaces_len", &self.interfaces.len())
            .field("neighbors_len", &self.neighbors.len())
            .field("local_ipv4_len", &self.local_ipv4.len())
            .field("ipv4_origin", &self.ipv4_origin)
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "validation-test-hooks"))]
std::thread_local! {
    static FULL_FORWARDING_VALIDATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Returns and resets the current thread's full forwarding validation count.
#[cfg(feature = "validation-test-hooks")]
#[doc(hidden)]
pub fn take_full_forwarding_validation_count() -> usize {
    FULL_FORWARDING_VALIDATIONS.with(|count| count.replace(0))
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
        #[cfg(any(test, feature = "validation-test-hooks"))]
        FULL_FORWARDING_VALIDATIONS.with(|count| count.set(count.get().saturating_add(1)));
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

    /// Borrows the route table in the order supplied to the constructor.
    ///
    /// [`ForwardingSnapshot::new`] validates but does not sort its input. The
    /// config-origin path canonicalizes routes before constructing a validated
    /// publication owner; callers using this general constructor must not infer
    /// canonical order from this accessor. Publication authority, snapshot
    /// identity, and allocation addresses are not part of this view.
    #[must_use]
    pub const fn routes(&self) -> &'a [Route] {
        self.routes
    }

    /// Borrows the static-neighbor table in the order supplied to the constructor.
    ///
    /// The general snapshot constructor validates but does not sort this slice.
    /// Config-origin validated candidates retain their separate canonicalization
    /// contract.
    #[must_use]
    pub const fn neighbors(&self) -> &'a [Neighbor] {
        self.neighbors
    }

    /// Borrows the local IPv4 bindings in the order supplied to the constructor.
    ///
    /// The general snapshot constructor validates but does not sort this slice.
    /// Config-origin validated candidates retain their separate canonicalization
    /// contract.
    #[must_use]
    pub const fn local_ipv4(&self) -> &'a [LocalIpv4Binding] {
        self.local_ipv4
    }

    /// Returns the IPv4 origin policy without exposing publication identity.
    #[must_use]
    pub const fn ipv4_origin_policy(&self) -> Ipv4OriginPolicy {
        self.ipv4_origin
    }

    pub(crate) const fn publication_nonce(&self) -> u64 {
        if self.authority & VALIDATED_OWNER_AUTHORITY_BIT == 0 {
            0
        } else {
            self.authority
        }
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

impl ValidatedForwardingOwner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        routes: Box<[Route]>,
        interfaces: Box<[Interface]>,
        neighbors: Box<[Neighbor]>,
        local_ipv4: Box<[LocalIpv4Binding]>,
        ipv4_origin: Ipv4OriginPolicy,
    ) -> Result<Self, ValidatedForwardingOwnerError> {
        ForwardingSnapshot::with_ipv4_origin_policy(
            &routes,
            &interfaces,
            &neighbors,
            &local_ipv4,
            ipv4_origin,
        )
        .map_err(ValidatedForwardingOwnerError::Snapshot)?;
        let authority = next_publication_nonce()
            .ok_or(ValidatedForwardingOwnerError::PublicationNonceExhausted)?;
        Ok(Self {
            routes,
            interfaces,
            neighbors,
            local_ipv4,
            ipv4_origin,
            authority,
        })
    }

    /// Borrows a coherent snapshot without validation, hashing, or allocation.
    #[must_use]
    pub fn snapshot(&self) -> ForwardingSnapshot<'_> {
        let identity = [
            self.routes.as_ptr() as usize,
            self.routes.len(),
            self.interfaces.as_ptr() as usize,
            self.interfaces.len(),
            self.neighbors.as_ptr() as usize,
            self.neighbors.len(),
            self.local_ipv4.as_ptr() as usize,
            self.local_ipv4.len(),
        ];
        ForwardingSnapshot {
            routes: &self.routes,
            interfaces: &self.interfaces,
            neighbors: &self.neighbors,
            local_ipv4: &self.local_ipv4,
            ipv4_origin: self.ipv4_origin,
            authority: self.authority,
            identity,
        }
    }

    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    #[must_use]
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    #[must_use]
    pub fn neighbors(&self) -> &[Neighbor] {
        &self.neighbors
    }

    #[must_use]
    pub fn local_ipv4(&self) -> &[LocalIpv4Binding] {
        &self.local_ipv4
    }
}

fn next_publication_nonce() -> Option<u64> {
    use std::sync::atomic::AtomicU64;

    static NEXT_PUBLICATION_NONCE: AtomicU64 = AtomicU64::new(VALIDATED_OWNER_AUTHORITY_BIT | 1);
    next_publication_nonce_from(&NEXT_PUBLICATION_NONCE)
}

fn next_publication_nonce_from(counter: &std::sync::atomic::AtomicU64) -> Option<u64> {
    use std::sync::atomic::Ordering;

    counter
        .fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| match current {
                0 => None,
                u64::MAX => Some(0),
                _ => current.checked_add(1),
            },
        )
        .ok()
        .filter(|nonce| *nonce != 0)
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
    mix(hash, u64::from(ipv4_origin.default_ttl())) & !VALIDATED_OWNER_AUTHORITY_BIT
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
    Icmpv4TimestampRequestValidated {
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
    Icmpv4TimestampReplyRequested {
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

/// Milliseconds since UTC midnight, per RFC 792's Timestamp message fields.
///
/// The datapath never reads a clock itself; the caller supplies this value
/// the same way it supplies [`MonotonicMillis`] elsewhere, which keeps replay
/// deterministic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4TimestampClock(pub u32);

#[derive(Clone, Copy)]
struct Icmpv4TimestampReplyDecision {
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
    /// The receive and transmit timestamp this reply carries in both fields,
    /// since the reply is built and sent in the same step.
    clock_word: u32,
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
    Icmpv4TimestampReply(Icmpv4TimestampReplyDecision),
    ConsumeArp(ControlDisposition),
    ConsumeIpv4Local,
    /// The datagram was copied into the hold queue to be split (RFC 791 §3.2)
    /// and will leave as several frames from the generated path.
    ConsumeIpv4ForFragmentation,
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
            Self::Icmpv4TimestampReply(decision) => decision.egress,
            Self::ConsumeArp(_) | Self::ConsumeIpv4Local | Self::ConsumeIpv4ForFragmentation => {
                unreachable!("consumed controls have no egress")
            }
        }
    }
}

/// Forwards every packet offered by one fresh backend batch.
///
/// # Fresh-batch precondition
///
/// `batch` must be passed directly from [`crate::PacketIo::receive`]:
/// [`PacketBatch::next_packet`] must not have been called and no lifecycle
/// completion or accounting may predate this invocation. [`BatchCompletion`]
/// reports whole-batch totals, so these forwarding APIs deliberately do not
/// accept partially processed or pre-accounted batches.
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
        batch, snapshot, None, None, None, None, None, None, None, None, None, None, trace,
    )
}

/// Forwards RX packets, additionally answering an ICMPv4 Timestamp request
/// addressed to one of this router's own addresses (RFC 792, RFC 1812
/// §4.3.2.9). `clock` is milliseconds since UTC midnight; the caller supplies
/// it the same way it supplies [`MonotonicMillis`] to the other variants.
///
/// The [`forward_batch`] fresh-batch precondition applies.
pub fn forward_batch_with_icmpv4_timestamp<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    clock: Icmpv4TimestampClock,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    forward_batch_inner(
        batch,
        snapshot,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(clock),
        trace,
    )
}

/// Forwards RX packets and queues resolution actions without allocating TX
/// frames. Generated execution must start only after this function returns.
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
        None,
        trace,
    )
}

/// Forwards RX packets while queueing ARP resolution and eligible ICMPv4 error
/// actions into separate caller-backed worker-local runtimes.
///
/// Generated packet execution must happen after this function returns.
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
        None,
        trace,
    )
}

/// Runs one outbound-initiated TCP NAPT domain with ARP resolution.
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
        None,
        trace,
    )
}

/// Composes TCP NAPT with generated ICMPv4 errors in one RX phase.
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
        None,
        trace,
    )
}

/// Runs independent UDP and TCP NAPT state for one matching address realm.
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
        None,
        trace,
    )
}

/// Full UDP/TCP NAPT and generated ICMPv4-error composition.
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
        None,
        trace,
    )
}

/// Runs an opt-in stateful firewall for forwarded unfragmented IPv4 UDP/TCP.
///
/// ARP, router-local traffic, and router-originated generated packets remain
/// outside this service. A missing or mismatched runtime fails closed.
///
/// The [`forward_batch`] fresh-batch precondition applies.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_firewall<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
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
        None,
        trace,
    )
}

/// Runs the opt-in stateful firewall and appends one typed policy record for
/// every packet that reaches rule or established-flow evaluation.
///
/// The [`forward_batch`] fresh-batch precondition applies.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_firewall_audited<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
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
        None,
        trace,
    )
}

/// Composes the stateful firewall with the existing generated ICMPv4 error
/// capture path. Firewall authorization precedes TTL error capture.
///
/// The [`forward_batch`] fresh-batch precondition applies.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_firewall_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
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
        None,
        trace,
    )
}

/// Audited variant of [`forward_batch_with_firewall_and_icmpv4_errors`].
///
/// The [`forward_batch`] fresh-batch precondition applies.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_firewall_and_icmpv4_errors_audited<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
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
        None,
        trace,
    )
}

/// Composes independent UDP/TCP NAPT with one canonical-tuple firewall.
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
    firewall: Option<&mut FirewallRuntime<'_>>,
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
        None,
        trace,
    )
}

/// Audited variant of
/// [`forward_batch_with_nat44_udp_and_tcp_and_firewall`].
///
/// The [`forward_batch`] fresh-batch precondition applies.
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
    firewall: Option<&mut FirewallRuntime<'_>>,
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
        None,
        trace,
    )
}

/// Composes independent UDP/TCP NAPT, one canonical-tuple firewall, and
/// generated ICMPv4 error capture in one ordered RX phase.
///
/// Firewall authorization precedes TTL error capture. Generated execution
/// remains a separate post-RX phase.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
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
        Some(firewall_config),
        firewall,
        None,
        None,
        trace,
    )
}

/// [`forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors`],
/// additionally answering an ICMPv4 Timestamp request addressed to one of
/// this router's own addresses (RFC 792, RFC 1812 §4.3.2.9). `clock` is
/// milliseconds since UTC midnight; the caller supplies it the same way it
/// supplies `now` to every other variant, since the datapath never reads a
/// clock of its own.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_and_timestamp<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
    now: MonotonicMillis,
    clock: Icmpv4TimestampClock,
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
        Some(firewall_config),
        firewall,
        None,
        Some(clock),
        trace,
    )
}

/// Audited variant of
/// [`forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors`].
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_audited<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
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
        Some(udp_config),
        nat44_udp,
        Some(tcp_config),
        nat44_tcp,
        Some(firewall_config),
        firewall,
        Some(audit),
        None,
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
    mut firewall: Option<&mut FirewallRuntime<'_>>,
    mut firewall_audit: Option<&mut FirewallAuditBuffer<'_>>,
    timestamp_clock: Option<Icmpv4TimestampClock>,
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
                timestamp_clock,
                trace,
            )
            .and_then(|decision| {
                if let PacketDecision::Nat44Tcp(nat) = decision {
                    let runtime = nat44_tcp
                        .as_deref()
                        .ok_or(DropReason::Nat44TcpRuntimeUnavailable)?;
                    match nat.transition {
                        Nat44TcpTransition::Outbound(plan) => runtime
                            .prevalidate_outbound_commit(plan, nat_now_ms)
                            .map_err(|_| DropReason::Nat44TcpConfigMismatch)?,
                        Nat44TcpTransition::Inbound(plan) => runtime
                            .prevalidate_inbound_commit(plan, nat_now_ms)
                            .map_err(|_| DropReason::Nat44TcpConfigMismatch)?,
                    }
                }
                if matches!(
                    decision,
                    PacketDecision::ConsumeArp(_)
                        | PacketDecision::ConsumeIpv4Local
                        | PacketDecision::ConsumeIpv4ForFragmentation
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
                decision: PacketDecision::ConsumeIpv4ForFragmentation,
                ..
            }) => {
                packet.consume(ConsumeReason::Ipv4Fragmented);
                consumed += 1;
                trace.record(TraceEvent::Ipv4LocalConsumed {
                    ingress,
                    reason: ConsumeReason::Ipv4Fragmented,
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
                            runtime
                                .commit_outbound(plan, nat_now_ms)
                                .expect("sequential packet path keeps UDP NAT plan current");
                        }
                        Nat44UdpTransition::Inbound(plan) => {
                            runtime
                                .commit_inbound(plan, nat_now_ms)
                                .expect("sequential packet path keeps UDP NAT plan current");
                        }
                    }
                    trace.record(TraceEvent::Nat44Udp {
                        ingress,
                        disposition: nat.disposition,
                    });
                }
                if let PacketDecision::Nat44Tcp(nat) = decision {
                    if let Some(runtime) = nat44_tcp.as_deref_mut() {
                        match nat.transition {
                            Nat44TcpTransition::Outbound(plan) => {
                                runtime.commit_prevalidated_outbound(plan, nat_now_ms);
                            }
                            Nat44TcpTransition::Inbound(plan) => {
                                runtime.commit_prevalidated_inbound(plan, nat_now_ms);
                            }
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
                if let PacketDecision::Icmpv4TimestampReply(icmp) = decision {
                    trace.record(TraceEvent::Icmpv4TimestampReplyRequested {
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
    let report = BatchReport {
        received,
        tx_requested,
        dropped,
        consumed,
        completion,
    };
    let invariants_hold = report.invariants_hold();
    debug_assert!(
        invariants_hold,
        "backend batch accounting violates the forwarding contract"
    );
    if invariants_hold {
        trace.record(TraceEvent::BatchCompleted {
            tx_accepted: report.completion.tx_accepted,
            tx_rejected: report.completion.tx_rejected,
        });
    }
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
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_plan: &mut Option<FirewallPlan>,
    timestamp_clock: Option<Icmpv4TimestampClock>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let ether_type = packet::read_u16(frame, 12).ok_or(EthernetHeaderTruncated)?;
    validate_ethernet_ingress(frame, snapshot, ingress, ether_type)?;
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
            timestamp_clock,
            trace,
        ),
        ARP_ETHERTYPE => decide_arp(frame, snapshot, ingress, resolution, trace),
        _ => Err(UnsupportedEtherType),
    }
}

fn validate_ethernet_ingress(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ether_type: u16,
) -> Result<(), DropReason> {
    if !matches!(ether_type, IPV4_ETHERTYPE | ARP_ETHERTYPE) {
        return Ok(());
    }
    let interface = snapshot
        .interfaces
        .iter()
        .find(|interface| interface.id == ingress)
        .ok_or(if ether_type == IPV4_ETHERTYPE {
            Ipv4IngressInterfaceUnknown
        } else {
            ArpIngressInterfaceUnknown
        })?;
    let destination_mac = frame.get(0..6).ok_or(EthernetHeaderTruncated)?;
    let source_mac = frame.get(6..12).ok_or(EthernetHeaderTruncated)?;
    if ether_type == IPV4_ETHERTYPE {
        if source_mac == [0; 6] {
            return Err(Ipv4EthernetSourceZero);
        }
        if source_mac == [0xff; 6] {
            return Err(Ipv4EthernetSourceBroadcast);
        }
        if source_mac[0] & 1 != 0 {
            return Err(Ipv4EthernetSourceMulticast);
        }
        if destination_mac == [0; 6] {
            return Err(Ipv4EthernetDestinationZero);
        }
        if destination_mac == [0xff; 6] {
            return Err(Ipv4EthernetDestinationBroadcast);
        }
        if destination_mac[0] & 1 != 0 {
            return Err(Ipv4EthernetDestinationMulticast);
        }
    } else {
        if source_mac == [0; 6] {
            return Err(ArpEthernetSourceZero);
        }
        if source_mac == [0xff; 6] {
            return Err(ArpEthernetSourceBroadcast);
        }
        if source_mac[0] & 1 != 0 {
            return Err(ArpEthernetSourceMulticast);
        }
        if destination_mac == [0; 6] {
            return Err(ArpEthernetDestinationZero);
        }
        if destination_mac == [0xff; 6] {
            return Ok(());
        }
        if destination_mac[0] & 1 != 0 {
            return Err(ArpEthernetDestinationMulticast);
        }
    }
    if destination_mac != interface.mac.0 {
        return Err(EthernetDestinationNotLocal);
    }
    Ok(())
}

fn validate_ipv4_ingress(
    snapshot: &ForwardingSnapshot<'_>,
    ipv4: packet::ValidatedIpv4,
) -> Result<(), DropReason> {
    let source = ipv4.source.octets();
    if source == [255; 4] {
        return Err(Ipv4SourceLimitedBroadcast);
    }
    match source[0] {
        0 => return Err(Ipv4SourceUnspecifiedNetwork),
        127 => return Err(Ipv4SourceLoopback),
        224..=239 => return Err(Ipv4SourceMulticast),
        240..=255 => return Err(Ipv4SourceClassE),
        _ => {}
    }
    if snapshot
        .local_ipv4
        .iter()
        .any(|binding| binding.address == ipv4.source)
    {
        return Err(Ipv4SourceLocalAddress);
    }
    if let Some(selected) = route::lookup(snapshot.routes, ipv4.source) {
        if selected.is_prefix_network_address(ipv4.source) {
            return Err(Ipv4SourceNetworkAddress);
        }
        if selected.is_prefix_directed_broadcast(ipv4.source) {
            return Err(Ipv4SourceDirectedBroadcast);
        }
    }

    let destination = ipv4.destination.octets();
    if destination == [255; 4] {
        return Err(Ipv4DestinationLimitedBroadcast);
    }
    match destination[0] {
        0 => Err(Ipv4DestinationUnspecifiedNetwork),
        127 => Err(Ipv4DestinationLoopback),
        224..=239 => Err(Ipv4DestinationMulticast),
        240..=255 => Err(Ipv4DestinationClassE),
        _ => Ok(()),
    }
}

fn validate_ipv4_forward_destination(
    ipv4: packet::ValidatedIpv4,
    selected_route: Option<Route>,
) -> Result<(), DropReason> {
    if let Some(selected) = selected_route {
        if selected.is_prefix_network_address(ipv4.destination) {
            return Err(Ipv4DestinationNetworkAddress);
        }
        if selected.is_prefix_directed_broadcast(ipv4.destination) {
            return Err(Ipv4DestinationDirectedBroadcast);
        }
    }
    Ok(())
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
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_plan: &mut Option<FirewallPlan>,
    timestamp_clock: Option<Icmpv4TimestampClock>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let ipv4 = validate_ipv4_frame(frame)?;
    trace.record(TraceEvent::Ipv4Validated {
        ingress,
        destination: ipv4.destination,
    });
    validate_ipv4_ingress(snapshot, ipv4)?;
    let local = snapshot
        .local_ipv4
        .iter()
        .any(|binding| binding.interface == ingress && binding.address == ipv4.destination);
    let selected_route = if local {
        None
    } else {
        route::lookup(snapshot.routes, ipv4.destination)
    };
    if !local {
        validate_ipv4_forward_destination(ipv4, selected_route)?;
    }
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
                    | FirewallPlanError::RuleRejected(_)
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
                selected_route,
                resolution,
                icmpv4_errors,
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
                selected_route,
                resolution,
                icmpv4_errors,
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
        let decision = decide_local_ipv4(frame, snapshot, ingress, ipv4, timestamp_clock, trace);
        // RFC 1812 §4.3.3.3: a router without a service for the addressed
        // transport or UDP port reports so, the same as any other host.
        if let Err(reason @ (Icmpv4ProtocolUnreachable | Icmpv4PortUnreachable)) = decision {
            if let Some((runtime, now)) = icmpv4_errors.as_mut() {
                let kind = if reason == Icmpv4PortUnreachable {
                    Icmpv4ErrorKind::DestinationUnreachablePort
                } else {
                    Icmpv4ErrorKind::DestinationUnreachableProtocol
                };
                let disposition = decide_icmpv4_error(
                    frame, snapshot, ipv4, None, kind, resolution, runtime, *now, trace,
                );
                trace.record(TraceEvent::Icmpv4DestinationUnreachableDisposition {
                    ingress,
                    disposition,
                });
            }
        }
        return decision;
    }
    if let Err(refusal) = validate_ipv4_options(frame, ipv4) {
        // RFC 1812 §4.3.2 asks a router to say why it refused a header rather
        // than dropping it silently: a bad option gets Parameter Problem with
        // the pointer, and a refused source route gets Source Route Failed.
        if let Some((runtime, now)) = icmpv4_errors.as_mut() {
            let kind = if refusal.reason == Ipv4SourceRouteUnsupported {
                Icmpv4ErrorKind::DestinationUnreachableSourceRouteFailed
            } else {
                Icmpv4ErrorKind::ParameterProblem {
                    pointer: refusal.pointer,
                }
            };
            let disposition = decide_icmpv4_error(
                frame,
                snapshot,
                ipv4,
                selected_route,
                kind,
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
        return Err(refusal.reason);
    }
    let Some(route) = selected_route else {
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
        match plan_firewall(
            ingress,
            route.egress(),
            ipv4,
            firewall_validated.expect("forward firewall packet was preflight validated"),
            None,
            config,
            runtime,
            firewall_audit,
            nat_now.0,
        ) {
            Ok(plan) => *firewall_plan = Some(plan),
            // A plain deny is reported silently: RFC 1812 §4.3.3.9 makes
            // Communication Administratively Prohibited optional exactly so
            // a filter is not forced into confirming its own rules to
            // whoever it is filtering (see the
            // `never_queues_icmp_or_arp_on_failures` firewall contract). A
            // rule whose action is explicitly `reject` asks for that report.
            Err(reason @ FirewallRuleRejected) => {
                if let Some((runtime, now)) = icmpv4_errors.as_mut() {
                    let disposition = decide_icmpv4_error(
                        frame,
                        snapshot,
                        ipv4,
                        Some(route),
                        Icmpv4ErrorKind::DestinationUnreachableCommAdminProhibited,
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
                return Err(reason);
            }
            Err(reason) => return Err(reason),
        }
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
    // RFC 1812 §5.2.7.2: tell the sender a better first hop exists when this
    // datagram leaves by the same interface it arrived on, toward a next hop
    // on the same subnet as the sender itself. The datagram is still
    // forwarded normally; a Redirect is advisory, not a substitute. A
    // datagram carrying a source route never reaches here: it was already
    // refused above by `validate_ipv4_options`.
    if route.egress() == ingress
        && !snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == target)
    {
        let connected_subnet = snapshot.routes.iter().find(|candidate| {
            candidate.egress() == route.egress()
                && candidate.next_hop().is_none()
                && candidate.matches(target)
        });
        if connected_subnet.is_some_and(|connected| connected.matches(ipv4.source)) {
            if let Some((runtime, now)) = icmpv4_errors.as_mut() {
                let disposition = decide_icmpv4_error(
                    frame,
                    snapshot,
                    ipv4,
                    Some(route),
                    Icmpv4ErrorKind::Redirect { gateway: target },
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
        }
    }
    // RFC 1812 §4.2.2.7: a datagram larger than the egress MTU must not be
    // put on the link. Before this check the oversized frame was handed to
    // the backend unchanged, which a real driver rejects.
    let mut split_to = None;
    if ipv4.total_len > interface.mtu.as_len() {
        let dont_fragment = packet::read_u16(frame, ipv4.header_offset + 6)
            .ok_or(Ipv4HeaderTruncated)?
            & IPV4_DONT_FRAGMENT_FLAG
            != 0;
        if !dont_fragment {
            // RFC 1812 §5.2.7: split it, once the next hop is known. Splitting
            // a header that carries options needs the copied-bit rule and a
            // per-fragment header length, which is not implemented, so that
            // combination is still refused rather than emitted at a length the
            // link cannot carry.
            if ipv4.header_len != 20 || resolution.is_none() {
                return Err(Ipv4FragmentationRequired);
            }
            let mtu = interface.mtu.bytes();
            // The same arithmetic the splitter uses: fragment offsets count
            // eight-octet units, so every fragment but the last carries a
            // payload that is a multiple of eight.
            let per_fragment = ((usize::from(mtu) - 20) / 8) * 8;
            let payload_len = ipv4.total_len.saturating_sub(ipv4.header_len);
            if per_fragment == 0
                || payload_len.div_ceil(per_fragment)
                    > crate::resolution::MAX_FRAGMENTS_PER_DATAGRAM
            {
                return Err(Ipv4FragmentationRequired);
            }
            split_to = Some(mtu);
        } else {
            if let Some((runtime, now)) = icmpv4_errors.as_mut() {
                let disposition = decide_icmpv4_error(
                    frame,
                    snapshot,
                    ipv4,
                    Some(route),
                    Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded {
                        next_hop_mtu: interface.mtu.bytes(),
                    },
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
            return Err(Ipv4FragmentationNeeded);
        }
    }
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
                    // RFC 1122 §2.3.2.2: save the datagram that triggered this
                    // resolution rather than discarding it. A runtime built
                    // without hold slots refuses, which is the old behaviour.
                    if matches!(
                        result,
                        ResolutionResult::Queued
                            | ResolutionResult::RetryQueued
                            | ResolutionResult::Suppressed
                    ) {
                        let _ = hold_unresolved_datagram(
                            frame,
                            ipv4,
                            route.egress(),
                            target,
                            interface.mac,
                            split_to,
                            runtime,
                            *now,
                        );
                    }
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
    if let Some(mtu) = split_to {
        let Some((runtime, now)) = resolution.as_mut() else {
            return Err(Ipv4FragmentationRequired);
        };
        let held = hold_datagram_for_split(
            frame,
            ipv4,
            route.egress(),
            target,
            interface.mac,
            destination_mac,
            mtu,
            runtime,
            *now,
        );
        if !matches!(
            held,
            ResolutionHoldDisposition::Held { .. } | ResolutionHoldDisposition::Replaced { .. }
        ) {
            return Err(Ipv4FragmentationRequired);
        }
        trace.record(TraceEvent::Routed {
            egress: route.egress(),
            neighbor_target: target,
        });
        return Ok(PacketDecision::ConsumeIpv4ForFragmentation);
    }
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

/// Whether a NAT should carry this ICMP error across the boundary.
///
/// RFC 5508 REQ-3 asks a NAT to translate an ICMP error whose embedded packet
/// matches one of its mappings, so the sender learns what happened to its own
/// datagram. Only these three types report something about a datagram this
/// router forwarded:
///
///   3   Destination Unreachable, all codes
///   11  Time Exceeded
///   12  Parameter Problem
///
/// Redirect is deliberately absent. It names a better first hop on the link
/// it arrived from, which means nothing to a host on the other side of a NAT,
/// and forwarding one would let an outside station steer an inside host's
/// routing. Source Quench is absent because RFC 6633 deprecated it.
const fn nat44_translatable_icmpv4_error(icmp_type: u8) -> bool {
    matches!(icmp_type, 3 | 11 | 12)
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
    if type_code_end > ipv4_end {
        return false;
    }
    let Some(type_code) = frame.get(icmp_offset..type_code_end) else {
        return false;
    };
    if !nat44_translatable_icmpv4_error(type_code[0]) {
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
    related_firewall: Option<&mut FirewallRuntime<'_>>,
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
                        | Nat44UdpPlanError::PortExhausted
                        | Nat44UdpPlanError::GenerationExhausted
                        | Nat44UdpPlanError::StateRevisionExhausted => {
                            unreachable!("read-only ICMP lookup cannot exhaust state")
                        }
                        Nat44UdpPlanError::IndexCorrupt => Nat44UdpConfigMismatch,
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
                        Nat44TcpPlanError::IndexCorrupt
                        | Nat44TcpPlanError::GenerationExhausted
                        | Nat44TcpPlanError::StateRevisionExhausted => Nat44TcpConfigMismatch,
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
    if inner_flags & 0x7fff != 0x4000 {
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
    let icmp_checksum = if icmp_checksum == 0 {
        // RFC 1624 returns +0 for this mathematical-zero update. ICMP stores
        // the equivalent one's-complement -0 as 0xffff on the wire.
        0xffff
    } else {
        icmp_checksum
    };

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
    config: &FirewallConfig<'_>,
    runtime: &mut FirewallRuntime<'_>,
    audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    now_ms: u64,
) -> Result<FirewallPlan, DropReason> {
    let packet = firewall_packet(ingress, egress, ipv4, validated, canonical);
    match runtime.plan_packet(config, packet, now_ms) {
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
                FirewallPlanError::RuleRejected(rule_id) => FirewallDisposition {
                    verdict: FirewallVerdict::Drop,
                    class: FirewallConnectionClass::New,
                    source: FirewallPolicySource::Rule(rule_id),
                    matched_action: Some(FirewallAction::Reject),
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
                        | FirewallPlanError::RuleRejected(_)
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
                FirewallPlanError::RuleRejected(_) => FirewallRuleRejected,
                FirewallPlanError::DefaultDenied => FirewallDefaultDenied,
                FirewallPlanError::InvalidInitialTcp(_) => FirewallTcpInvalidInitialFlags,
                FirewallPlanError::StateFull(_) => FirewallStateTableFull,
                FirewallPlanError::ClockRegression => FirewallClockRegression,
            })
        }
    }
}

fn require_firewall_runtime<'runtime, 'state>(
    snapshot: &ForwardingSnapshot<'_>,
    config: &FirewallConfig<'_>,
    runtime: &'runtime mut Option<&mut FirewallRuntime<'state>>,
) -> Result<&'runtime mut FirewallRuntime<'state>, DropReason> {
    if !config.authority_matches(snapshot) {
        if let Some(runtime) = runtime.as_deref_mut() {
            runtime.record_config_mismatch();
        }
        return Err(FirewallConfigMismatch);
    }
    let Some(runtime) = runtime.as_deref_mut() else {
        return Err(FirewallRuntimeUnavailable);
    };
    if !runtime.config_matches(config) {
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
    // The transport validators below already locate the header at
    // `header_offset + header_len`, so options only need to be well formed and
    // free of source routing — the same test the forwarding decision applies.
    validate_ipv4_options(frame, ipv4).map_err(|refusal| match refusal.reason {
        Ipv4OptionsMalformed | Ipv4SourceRouteUnsupported => refusal.reason,
        _ => FirewallIpv4OptionsUnsupported,
    })?;
    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(FirewallFragmentUnsupported)?;
    if !matches!(flags_fragment & 0x7fff, 0 | 0x4000) {
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
    let sum = u32::from(u16::from_be_bytes([source[0], source[1]]))
        + u32::from(u16::from_be_bytes([source[2], source[3]]))
        + u32::from(u16::from_be_bytes([destination[0], destination[1]]))
        + u32::from(u16::from_be_bytes([destination[2], destination[3]]))
        + u32::from(protocol)
        + u32::from(length);
    // The segment is summed with the shared wide accumulator rather than a
    // local per-word fold: this validation runs over the whole payload for
    // every UDP and TCP packet, and the per-word carry made it the dominant
    // cost of a full-MTU forward.
    let sum = u64::from(sum) + crate::checksum::wide_sum(segment);
    crate::checksum::fold_u64(sum) == 0xffff
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
    selected_destination_route: Option<Route>,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    config: &Nat44UdpConfig,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
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
            firewall_config,
            firewall_runtime,
            firewall_audit,
            now.0,
        )?);
    }
    if ipv4.ttl <= 1 {
        if let Some((runtime, now)) = icmpv4_errors.as_mut() {
            let disposition = decide_icmpv4_error(
                frame,
                snapshot,
                ipv4,
                selected_destination_route,
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
    selected_destination_route: Option<Route>,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    config: &Nat44TcpConfig,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
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
            firewall_config,
            firewall_runtime,
            firewall_audit,
            now.0,
        )?);
    }
    if ipv4.ttl <= 1 {
        if let Some((runtime, now)) = icmpv4_errors.as_mut() {
            let disposition = decide_icmpv4_error(
                frame,
                snapshot,
                ipv4,
                selected_destination_route,
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
    if flags_fragment & 0x7fff != 0x4000 {
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
    let sum = u32::from(u16::from_be_bytes([source[0], source[1]]))
        + u32::from(u16::from_be_bytes([source[2], source[3]]))
        + u32::from(u16::from_be_bytes([destination[0], destination[1]]))
        + u32::from(u16::from_be_bytes([destination[2], destination[3]]))
        + 6
        + u32::from(length);
    // Same reasoning as `transport_checksum_valid`: the shared wide
    // accumulator defers the end-around carry to a single fold instead of
    // serialising one per 16-bit word of the segment.
    let sum = u64::from(sum) + crate::checksum::wide_sum(segment);
    crate::checksum::fold_u64(sum) == 0xffff
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
    if flags_fragment & 0x7fff != 0x4000 {
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
        Nat44UdpPlanError::IndexCorrupt
        | Nat44UdpPlanError::GenerationExhausted
        | Nat44UdpPlanError::StateRevisionExhausted => {
            (Nat44UdpConfigMismatch, Nat44UdpDisposition::ConfigMismatch)
        }
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
        Nat44TcpPlanError::IndexCorrupt
        | Nat44TcpPlanError::GenerationExhausted
        | Nat44TcpPlanError::StateRevisionExhausted => {
            (Nat44TcpConfigMismatch, Nat44TcpDisposition::ConfigMismatch)
        }
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
        let Some(icmp_type) = icmpv4_type_within_total_length(frame, ipv4) else {
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
        let Some(icmp_type) = icmpv4_type_within_total_length(frame, ipv4) else {
            return false;
        };
        if matches!(icmp_type, 3 | 4 | 5 | 11 | 12) {
            return false;
        }
    }
    true
}

fn icmpv4_type_within_total_length(frame: &[u8], ipv4: packet::ValidatedIpv4) -> Option<u8> {
    let icmp_offset = ipv4.header_offset.checked_add(ipv4.header_len)?;
    let ipv4_end = ipv4.header_offset.checked_add(ipv4.total_len)?;
    (icmp_offset < ipv4_end)
        .then(|| frame.get(icmp_offset))
        .flatten()
        .copied()
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
    timestamp_clock: Option<Icmpv4TimestampClock>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    if ipv4.header_len > 20 {
        return Err(Ipv4OptionsUnsupported);
    }
    if ipv4.protocol != 1 {
        // RFC 1812 §4.3.3.3: a router is a host for traffic addressed to
        // itself, and answers a transport it has no service for the same way
        // any host would. TCP is the one exception: a closed TCP port
        // answers with RST at the transport layer, never with ICMP.
        return match ipv4.protocol {
            6 => Ok(PacketDecision::ConsumeIpv4Local),
            17 => Err(Icmpv4PortUnreachable),
            _ => Err(Icmpv4ProtocolUnreachable),
        };
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
    if icmp[0] == 13 {
        return decide_local_icmpv4_timestamp(
            frame,
            snapshot,
            ingress,
            ipv4,
            flags_fragment,
            icmp_offset,
            icmp_end,
            icmp,
            timestamp_clock,
            trace,
        );
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
    let icmp_checksum = if icmp_checksum == 0 {
        // RFC 1624 returns +0 for this mathematical-zero update. ICMP stores
        // the equivalent one's-complement -0 as 0xffff on the wire.
        0xffff
    } else {
        icmp_checksum
    };
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

/// RFC 792 / RFC 1812 §4.3.2.9: answer a Timestamp request addressed to one
/// of this router's own addresses with a Timestamp Reply. `timestamp_clock`
/// is `None` when the caller has no wall clock to offer; the datapath never
/// reads one itself, so the request is simply consumed unanswered rather
/// than reported as invalid.
#[allow(clippy::too_many_arguments)]
fn decide_local_icmpv4_timestamp<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    flags_fragment: u16,
    icmp_offset: usize,
    icmp_end: usize,
    icmp: &[u8],
    timestamp_clock: Option<Icmpv4TimestampClock>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    if icmp[1] != 0 {
        return Err(Icmpv4TimestampCodeInvalid);
    }
    if icmp.len() < 20 {
        return Err(Icmpv4TimestampHeaderTruncated);
    }
    if crate::internet_checksum(icmp) != 0 {
        return Err(Icmpv4ChecksumInvalid);
    }
    let Some(clock) = timestamp_clock else {
        return Ok(PacketDecision::ConsumeIpv4Local);
    };

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

    let old_receive = packet::read_u16(frame, icmp_offset + 12).ok_or(Icmpv4HeaderTruncated)?;
    let old_receive_low = packet::read_u16(frame, icmp_offset + 14).ok_or(Icmpv4HeaderTruncated)?;
    let old_transmit = packet::read_u16(frame, icmp_offset + 16).ok_or(Icmpv4HeaderTruncated)?;
    let old_transmit_low =
        packet::read_u16(frame, icmp_offset + 18).ok_or(Icmpv4HeaderTruncated)?;
    let clock_word = clock.0;
    let new_high = (clock_word >> 16) as u16;
    let new_low = (clock_word & 0xffff) as u16;
    let icmp_checksum = rfc1624_update(old_icmp_checksum, 0x0d00, 0x0e00);
    let icmp_checksum = rfc1624_update(icmp_checksum, old_receive, new_high);
    let icmp_checksum = rfc1624_update(icmp_checksum, old_receive_low, new_low);
    let icmp_checksum = rfc1624_update(icmp_checksum, old_transmit, new_high);
    let icmp_checksum = rfc1624_update(icmp_checksum, old_transmit_low, new_low);
    let icmp_checksum = if icmp_checksum == 0 {
        // RFC 1624 returns +0 for this mathematical-zero update. ICMP stores
        // the equivalent one's-complement -0 as 0xffff on the wire.
        0xffff
    } else {
        icmp_checksum
    };
    trace.record(TraceEvent::Icmpv4TimestampRequestValidated {
        ingress,
        source: ipv4.source,
        destination: ipv4.destination,
    });
    Ok(PacketDecision::Icmpv4TimestampReply(
        Icmpv4TimestampReplyDecision {
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
            clock_word,
        },
    ))
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
        PacketDecision::Icmpv4TimestampReply(icmp) => apply_icmpv4_timestamp_reply(frame, icmp),
        PacketDecision::ConsumeArp(_)
        | PacketDecision::ConsumeIpv4Local
        | PacketDecision::ConsumeIpv4ForFragmentation => {
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

/// The IPv4 option types this router refuses to carry.
///
/// Loose and strict source routing ask a router to forward along a path the
/// sender chose. RFC 1812 §4.2.2.11 lets a router refuse them, and refusing is
/// what a router on an untrusted network should do: honouring them lets a
/// sender steer traffic past filtering that assumes the routing table decides
/// the path. This router also has no source-route reversal, so it could not
/// answer such a datagram correctly even if it carried it.
const IPV4_OPTION_LOOSE_SOURCE_ROUTE: u8 = 131;
const IPV4_OPTION_STRICT_SOURCE_ROUTE: u8 = 137;
const IPV4_OPTION_END_OF_LIST: u8 = 0;
const IPV4_OPTION_NO_OPERATION: u8 = 1;

/// Why this router refused a header, and the octet that caused it.
///
/// RFC 792 reports a bad header field with a pointer to its first octet,
/// counted from the start of the IPv4 header, so the refusal carries one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ipv4OptionRefusal {
    reason: DropReason,
    pointer: u8,
}

/// Checks the option area of a header this router is about to forward.
///
/// RFC 1812 §5.2.5 requires a router to forward a datagram whose options it
/// does not recognise, passing them through unchanged, so anything well formed
/// and not a source route is accepted here and copied by the ordinary forward.
/// Record Route and Timestamp are carried without being filled in, which is
/// the same treatment an unrecognised option gets.
fn validate_ipv4_options(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Result<(), Ipv4OptionRefusal> {
    let refuse = |reason, offset: usize| Ipv4OptionRefusal {
        reason,
        // The pointer counts from the start of the IPv4 header, and the
        // option area begins twenty octets in.
        pointer: u8::try_from(20 + offset).unwrap_or(u8::MAX),
    };
    let start = ipv4
        .header_offset
        .checked_add(20)
        .ok_or(refuse(Ipv4HeaderLengthExceedsPacket, 0))?;
    let end = ipv4
        .header_offset
        .checked_add(ipv4.header_len)
        .ok_or(refuse(Ipv4HeaderLengthExceedsPacket, 0))?;
    let options = frame
        .get(start..end)
        .ok_or(refuse(Ipv4HeaderLengthExceedsPacket, 0))?;

    let mut offset = 0;
    while offset < options.len() {
        let option_type = options[offset];
        if option_type == IPV4_OPTION_END_OF_LIST {
            // Everything after the end of the list is padding.
            return Ok(());
        }
        if option_type == IPV4_OPTION_NO_OPERATION {
            offset += 1;
            continue;
        }
        // Every other option carries its own length, which must cover at
        // least the type and length octets and must not run past the header.
        let Some(&length) = options.get(offset + 1) else {
            return Err(refuse(Ipv4OptionsMalformed, offset));
        };
        let length = usize::from(length);
        if length < 2 {
            return Err(refuse(Ipv4OptionsMalformed, offset + 1));
        }
        let Some(next) = offset.checked_add(length) else {
            return Err(refuse(Ipv4OptionsMalformed, offset + 1));
        };
        if next > options.len() {
            return Err(refuse(Ipv4OptionsMalformed, offset + 1));
        }
        if matches!(
            option_type,
            IPV4_OPTION_LOOSE_SOURCE_ROUTE | IPV4_OPTION_STRICT_SOURCE_ROUTE
        ) {
            return Err(refuse(Ipv4SourceRouteUnsupported, offset));
        }
        offset = next;
    }
    Ok(())
}

/// Copies a datagram that must be split into the hold queue.
///
/// Like the unresolved-hop hold, the copy carries the forwarding rewrite with
/// the TTL already decremented, so every fragment leaves with the TTL an
/// immediate forward would have used. The destination MAC is filled in when
/// known and left for the resolution to supply when it is not, which is what
/// keeps an oversized datagram from being replayed whole later.
#[allow(clippy::too_many_arguments)]
fn hold_datagram_for_split(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
    egress: IfId,
    target: crate::Ipv4Address,
    source_mac: MacAddress,
    destination_mac: MacAddress,
    mtu: u16,
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
) -> ResolutionHoldDisposition {
    let mut staged = [0_u8; RESOLUTION_HOLD_MAX_FRAME_LEN];
    let len = frame.len();
    if len > RESOLUTION_HOLD_MAX_FRAME_LEN {
        return ResolutionHoldDisposition::FrameTooLong { len };
    }
    staged[..len].copy_from_slice(frame);
    staged[0..6].fill(0);
    if let Some(slot) = staged.get_mut(6..12) {
        slot.copy_from_slice(&source_mac.0);
    }
    let Some(ttl_offset) = ipv4.header_offset.checked_add(8) else {
        return ResolutionHoldDisposition::FrameTooLong { len };
    };
    let Some(checksum_offset) = ipv4.header_offset.checked_add(10) else {
        return ResolutionHoldDisposition::FrameTooLong { len };
    };
    if ipv4.ttl == 0 || ttl_offset >= len || checksum_offset + 2 > len {
        return ResolutionHoldDisposition::FrameTooLong { len };
    }
    staged[ttl_offset] = ipv4.ttl - 1;
    // Every fragment recomputes its own header checksum, so the copy only
    // needs a consistent TTL here.
    runtime.hold_datagram_for_fragmentation(
        egress,
        target,
        destination_mac,
        mtu,
        &staged[..len],
        now,
    )
}

/// Copies a datagram whose next hop is unresolved into the hold queue.
///
/// The copy carries the forwarding rewrite already applied — TTL decremented
/// once, header checksum updated, source MAC set — with the destination MAC
/// left zero, so releasing it later sends exactly what an immediate forward
/// would have sent. Nothing here holds an RX lease: the caller recycles the
/// received frame as usual.
#[allow(clippy::too_many_arguments)]
fn hold_unresolved_datagram(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
    egress: IfId,
    target: crate::Ipv4Address,
    source_mac: MacAddress,
    split_to: Option<u16>,
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
) -> ResolutionHoldDisposition {
    if frame.len() > RESOLUTION_HOLD_MAX_FRAME_LEN {
        // Offered as-is so the refusal, and its counter, name the real length.
        return runtime.hold_datagram(egress, target, frame, now);
    }
    let mut staged = [0_u8; RESOLUTION_HOLD_MAX_FRAME_LEN];
    let len = frame.len();
    staged[..len].copy_from_slice(frame);
    // The destination MAC is the one field the hold cannot know yet.
    staged[0..6].fill(0);
    if let Some(slot) = staged.get_mut(6..12) {
        slot.copy_from_slice(&source_mac.0);
    }
    let Some(ttl_offset) = ipv4.header_offset.checked_add(8) else {
        return ResolutionHoldDisposition::FrameTooLong { len };
    };
    let Some(checksum_offset) = ipv4.header_offset.checked_add(10) else {
        return ResolutionHoldDisposition::FrameTooLong { len };
    };
    if ipv4.ttl == 0 || ttl_offset >= len || checksum_offset + 2 > len {
        return ResolutionHoldDisposition::FrameTooLong { len };
    }
    staged[ttl_offset] = ipv4.ttl - 1;
    let checksum = rfc1624_update(
        ipv4.checksum,
        u16::from_be_bytes([ipv4.ttl, ipv4.protocol]),
        u16::from_be_bytes([ipv4.ttl - 1, ipv4.protocol]),
    );
    staged[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
    match split_to {
        // An oversized datagram must still be split when its hop resolves;
        // replaying it whole would put a frame on the link that cannot carry
        // it.
        Some(mtu) => {
            runtime.hold_datagram_awaiting_fragmentation(egress, target, mtu, &staged[..len], now)
        }
        None => runtime.hold_datagram(egress, target, &staged[..len], now),
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

fn apply_icmpv4_timestamp_reply(
    frame: &mut [u8],
    decision: Icmpv4TimestampReplyDecision,
) -> Result<(), DropReason> {
    if frame.get(0..12).is_none()
        || frame.get(14..34).is_none()
        || frame.get(decision.icmp_offset..decision.icmp_end).is_none()
        || frame
            .get(decision.icmp_offset..decision.icmp_offset + 20)
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
    frame[decision.icmp_offset] = 14;
    frame[decision.icmp_offset + 2..decision.icmp_offset + 4]
        .copy_from_slice(&decision.icmp_checksum.to_be_bytes());
    frame[decision.icmp_offset + 12..decision.icmp_offset + 16]
        .copy_from_slice(&decision.clock_word.to_be_bytes());
    frame[decision.icmp_offset + 16..decision.icmp_offset + 20]
        .copy_from_slice(&decision.clock_word.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DropReason::*;
    use super::{
        decide_ipv4, forward_batch, forward_batch_with_nat44_udp_and_tcp_and_firewall,
        forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_audited,
        next_publication_nonce_from, validate_ethernet_ingress, BatchReport, DropReason,
        FirewallPacket, Ipv4OriginPolicy, ResolutionActionAuthority, ValidatedForwardingOwner,
        FULL_FORWARDING_VALIDATIONS, VALIDATED_OWNER_AUTHORITY_BIT,
    };
    use crate::{
        internet_checksum, ipv4_header_checksum, ArpRequestAction, BatchCompletion,
        DirectoryBucket, DirectoryNode, FirewallAction, FirewallAuditBuffer, FirewallAuditRecord,
        FirewallConfig, FirewallHashKey, FirewallInterface, FirewallIpv4Prefix, FirewallPolicy,
        FirewallPortRange, FirewallProtocol, FirewallRule, FirewallRuleId, FirewallRuntime,
        FirewallStateSlot, FirewallVerdict, ForwardingSnapshot, Icmpv4ErrorActionSlot,
        Icmpv4ErrorDisposition, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId,
        Interface, Ipv4Address, Ipv4Mtu, LocalIpv4Binding, MacAddress, MonotonicMillis,
        Nat44Icmpv4ErrorPolicy, Nat44TcpConfig, Nat44TcpHashKey, Nat44TcpIndexStorage,
        Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig,
        Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Neighbor, NoTrace, PacketBatch,
        PacketLease, PacketSlot, PortOwnerSlot, ResolutionActionSlot, ResolutionFailureHoldSlot,
        ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route, SlotCompletion,
        TraceEvent, TraceSink, ARP_ETHERTYPE, IPV4_ETHERTYPE,
    };
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
    };

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const PUBLIC2: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 11]);
    const INTERNAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
    const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
    const ROUTER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
    const DMZ: IfId = IfId(3);

    fn empty_validated_owner() -> ValidatedForwardingOwner {
        ValidatedForwardingOwner::new(
            Vec::new().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
            Ipv4OriginPolicy::default(),
        )
        .unwrap()
    }

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
    fn a_held_datagram_carries_no_destination_mac_and_one_ttl_decrement() {
        // The hold is a copy of the frame with everything the forward already
        //decided applied. Its destination MAC is the single unknown, and it is
        // cleared rather than left carrying the previous hop's address: the
        // slot is public through `frame()`, so what it holds is observable.
        use super::hold_unresolved_datagram;
        use crate::{
            DynamicNeighborSlot, ResolutionDatagramHoldSlot, ResolutionFailureHoldSlot,
            ResolutionPolicy,
        };

        let mut frame = vec![0_u8; 14 + 20 + 8];
        frame[0..6].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xaa]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&28_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let ipv4 = crate::packet::ValidatedIpv4 {
            header_offset: 14,
            header_len: 20,
            total_len: 28,
            ttl: 64,
            protocol: 17,
            source: crate::Ipv4Address::from_octets([192, 0, 2, 50]),
            destination: crate::Ipv4Address::from_octets([198, 51, 100, 9]),
            checksum,
        };

        let mut states = [crate::ResolutionStateSlot::EMPTY; 1];
        let mut actions = [crate::ResolutionActionSlot::EMPTY; 1];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut holds = [ResolutionDatagramHoldSlot::EMPTY; 1];
        let egress_mac = crate::MacAddress([0x02, 0, 0, 0, 0, 0x02]);
        {
            let mut runtime =
                ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
                    ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 60_000, 60_000).unwrap(),
                    &mut states,
                    &mut actions,
                    &mut dynamic,
                    &mut failure_holds,
                    &mut holds,
                );
            let disposition = hold_unresolved_datagram(
                &frame,
                ipv4,
                IfId(2),
                ipv4.destination,
                egress_mac,
                None,
                &mut runtime,
                MonotonicMillis(0),
            );
            assert!(matches!(
                disposition,
                crate::ResolutionHoldDisposition::Held { .. }
            ));
        }

        let held = holds[0].frame();
        assert_eq!(&held[0..6], &[0; 6], "the destination MAC is not yet known");
        assert_eq!(&held[6..12], &egress_mac.0, "the egress interface is set");
        assert_eq!(held[22], 63, "the TTL is decremented exactly once");
        assert_eq!(
            ipv4_header_checksum(&held[14..34]),
            0,
            "the header checksum matches the decremented TTL"
        );
        assert_eq!(&held[34..], &frame[34..], "the payload is unchanged");
    }

    #[test]
    fn validated_owner_snapshot_is_o1_lifetime_bound_and_move_stable() {
        FULL_FORWARDING_VALIDATIONS.with(|count| count.set(0));
        let owner = empty_validated_owner();
        assert_eq!(FULL_FORWARDING_VALIDATIONS.with(std::cell::Cell::get), 1);
        let first = owner.snapshot();
        let identity = first.identity();
        let publication_nonce = first.publication_nonce();
        for _ in 0..1_024 {
            let snapshot = owner.snapshot();
            assert_eq!(snapshot.identity(), identity);
            assert_eq!(snapshot.publication_nonce(), publication_nonce);
        }
        assert_eq!(FULL_FORWARDING_VALIDATIONS.with(std::cell::Cell::get), 1);

        let moved = owner;
        let moved_snapshot = moved.snapshot();
        assert_eq!(moved_snapshot.identity(), identity);
        assert_eq!(moved_snapshot.publication_nonce(), publication_nonce);
    }

    #[test]
    fn validated_owner_nonce_distinguishes_equal_empty_storage_without_identity_leak() {
        let first = empty_validated_owner();
        let second = empty_validated_owner();
        let first_snapshot = first.snapshot();
        let second_snapshot = second.snapshot();
        assert!(first_snapshot.routes.as_ptr() == second_snapshot.routes.as_ptr());
        assert!(first_snapshot.interfaces.as_ptr() == second_snapshot.interfaces.as_ptr());
        assert!(first_snapshot.neighbors.as_ptr() == second_snapshot.neighbors.as_ptr());
        assert!(first_snapshot.local_ipv4.as_ptr() == second_snapshot.local_ipv4.as_ptr());
        assert_eq!(first_snapshot.identity(), second_snapshot.identity());
        assert_ne!(
            first_snapshot.publication_nonce(),
            second_snapshot.publication_nonce()
        );
        assert_ne!(
            first_snapshot.publication_nonce() & VALIDATED_OWNER_AUTHORITY_BIT,
            0
        );
        assert_eq!(
            format!("{first_snapshot:?}"),
            "ForwardingSnapshot { routes_len: 0, interfaces_len: 0, neighbors_len: 0, \
             local_ipv4_len: 0, ipv4_origin: Ipv4OriginPolicy { default_ttl: 64 }, .. }"
        );
        assert_eq!(
            format!("{first:?}"),
            "ValidatedForwardingOwner { routes_len: 0, interfaces_len: 0, neighbors_len: 0, \
             local_ipv4_len: 0, ipv4_origin: Ipv4OriginPolicy { default_ttl: 64 }, .. }"
        );
    }

    #[test]
    fn publication_nonce_is_monotonic_and_never_wraps() {
        use std::sync::atomic::AtomicU64;

        let counter = AtomicU64::new(1);
        assert_eq!(next_publication_nonce_from(&counter), Some(1));
        assert_eq!(next_publication_nonce_from(&counter), Some(2));

        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_publication_nonce_from(&counter), Some(u64::MAX - 1));
        assert_eq!(next_publication_nonce_from(&counter), Some(u64::MAX));
        assert_eq!(next_publication_nonce_from(&counter), None);
        assert_eq!(next_publication_nonce_from(&counter), None);
    }

    #[test]
    fn legacy_snapshot_identity_keeps_all_pointer_and_length_facts() {
        let interfaces = [Interface {
            id: LAN,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let neighbors = [crate::Neighbor {
            interface: LAN,
            target: Ipv4Address::from_octets([10, 0, 0, 2]),
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
        }];
        let bindings = [LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        }];
        let empty =
            ForwardingSnapshot::new(&[], &interfaces, &neighbors[..0], &bindings[..0]).unwrap();
        let populated = ForwardingSnapshot::new(&[], &interfaces, &neighbors, &bindings).unwrap();
        assert!(empty.neighbors.as_ptr() == populated.neighbors.as_ptr());
        assert!(empty.local_ipv4.as_ptr() == populated.local_ipv4.as_ptr());
        assert_ne!(empty.identity(), populated.identity());
        assert_eq!(empty.publication_nonce(), 0);
        assert_eq!(populated.publication_nonce(), 0);
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

    struct NeverLeasedSlot;

    impl PacketSlot for NeverLeasedSlot {
        fn ingress(&self) -> IfId {
            unreachable!("accounting-only batch never leases a slot")
        }

        fn bytes_mut(&mut self) -> &mut [u8] {
            unreachable!("accounting-only batch never leases a slot")
        }

        fn complete(self, _completion: SlotCompletion) {
            unreachable!("accounting-only batch never leases a slot")
        }
    }

    struct AccountingOnlyBatch {
        completion: BatchCompletion<()>,
    }

    impl PacketBatch for AccountingOnlyBatch {
        type Error = ();
        type Slot<'a> = NeverLeasedSlot;

        fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
            None
        }

        fn finish(self) -> BatchCompletion<Self::Error> {
            self.completion
        }
    }

    struct OnePacketSlot<'a> {
        ingress: IfId,
        frame: &'a mut [u8],
        completion: &'a Cell<Option<SlotCompletion>>,
    }

    impl PacketSlot for OnePacketSlot<'_> {
        fn ingress(&self) -> IfId {
            self.ingress
        }

        fn bytes_mut(&mut self) -> &mut [u8] {
            self.frame
        }

        fn complete(self, completion: SlotCompletion) {
            assert_eq!(self.completion.replace(Some(completion)), None);
        }
    }

    struct OnePacketBatch<'a> {
        ingress: IfId,
        frame: Option<&'a mut [u8]>,
        completion: &'a Cell<Option<SlotCompletion>>,
    }

    impl PacketBatch for OnePacketBatch<'_> {
        type Error = ();
        type Slot<'a>
            = OnePacketSlot<'a>
        where
            Self: 'a;

        fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
            self.frame.take().map(|frame| {
                PacketLease::new(OnePacketSlot {
                    ingress: self.ingress,
                    frame,
                    completion: self.completion,
                })
            })
        }

        fn finish(self) -> BatchCompletion<Self::Error> {
            let completion = self
                .completion
                .get()
                .expect("one packet must complete exactly once");
            match completion {
                SlotCompletion::Transmit(_) => BatchCompletion {
                    tx_requested: 1,
                    tx_accepted: 1,
                    tx_rejected: 0,
                    recycled: 0,
                    error: None,
                },
                SlotCompletion::Recycle(_)
                | SlotCompletion::Consume(_)
                | SlotCompletion::LeaseAbandoned => BatchCompletion {
                    tx_requested: 0,
                    tx_accepted: 0,
                    tx_rejected: 0,
                    recycled: 1,
                    error: None,
                },
            }
        }
    }

    #[derive(Default)]
    struct RecordingTrace {
        events: Vec<TraceEvent>,
    }

    impl TraceSink for RecordingTrace {
        fn record(&mut self, event: TraceEvent) {
            self.events.push(event);
        }
    }

    fn assert_invalid_batch_has_no_terminal_trace(completion: BatchCompletion<()>) {
        let snapshot = ForwardingSnapshot::new(&[], &[], &[], &[]).unwrap();
        let mut trace = RecordingTrace::default();
        let result = catch_unwind(AssertUnwindSafe(|| {
            forward_batch(AccountingOnlyBatch { completion }, &snapshot, &mut trace)
        }));
        if cfg!(debug_assertions) {
            assert!(result.is_err(), "debug builds reject invalid accounting");
        } else {
            assert!(result.is_ok(), "release builds return the invalid report");
        }
        assert!(
            !trace
                .events
                .iter()
                .any(|event| matches!(event, TraceEvent::BatchCompleted { .. })),
            "invalid accounting must not publish a terminal batch trace"
        );
    }

    #[test]
    fn preaccounted_batch_violates_fresh_batch_precondition_before_terminal_trace() {
        assert_invalid_batch_has_no_terminal_trace(BatchCompletion {
            tx_requested: 1,
            tx_accepted: 1,
            tx_rejected: 0,
            recycled: 0,
            error: None,
        });
    }

    #[test]
    fn malformed_backend_completion_is_rejected_before_terminal_trace() {
        assert_invalid_batch_has_no_terminal_trace(BatchCompletion {
            tx_requested: 0,
            tx_accepted: 1,
            tx_rejected: 0,
            recycled: 0,
            error: Some(()),
        });
    }

    fn tcp_syn_frame() -> Vec<u8> {
        let mut frame = vec![0_u8; 60];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 10]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&INTERNAL.octets());
        frame[30..34].copy_from_slice(&REMOTE.octets());
        frame[34..36].copy_from_slice(&12_345_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&443_u16.to_be_bytes());
        frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
        frame[46] = 5 << 4;
        frame[47] = 0x02;
        frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
        let mut pseudo = Vec::with_capacity(32);
        pseudo.extend_from_slice(&INTERNAL.octets());
        pseudo.extend_from_slice(&REMOTE.octets());
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&20_u16.to_be_bytes());
        pseudo.extend_from_slice(&frame[34..54]);
        let tcp_checksum = internet_checksum(&pseudo);
        frame[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());
        let ipv4_checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&ipv4_checksum.to_be_bytes());
        frame
    }

    fn empty_ipv4_icmp_frame(ttl: u8, destination: Ipv4Address) -> Vec<u8> {
        let mut frame = vec![0_u8; 60];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 30]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&20_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = ttl;
        frame[23] = 1;
        frame[26..30].copy_from_slice(&REMOTE.octets());
        frame[30..34].copy_from_slice(&destination.octets());
        frame[34] = 0x08;
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn zero_identifier_echo_request() -> Vec<u8> {
        let mut frame = vec![0_u8; 60];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 30]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&28_u16.to_be_bytes());
        frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 1;
        frame[26..30].copy_from_slice(&REMOTE.octets());
        frame[30..34].copy_from_slice(&INTERNAL.octets());
        frame[34..42].copy_from_slice(&[0x08, 0x00, 0xf7, 0xff, 0, 0, 0, 0]);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    #[test]
    fn local_echo_reply_encodes_mathematical_zero_as_icmp_negative_zero() {
        let interfaces = [Interface {
            id: LAN,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let bindings = [LocalIpv4Binding {
            interface: LAN,
            address: INTERNAL,
        }];
        let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &bindings).unwrap();
        let mut frame = zero_identifier_echo_request();
        let ipv4 = crate::validate_ipv4_frame(&frame).unwrap();
        let mut trace = RecordingTrace::default();

        let decision =
            super::decide_local_ipv4(&frame, &snapshot, LAN, ipv4, None, &mut trace).unwrap();
        super::apply_decision(&mut frame, decision).unwrap();

        assert_eq!(
            u16::from_be_bytes(frame[36..38].try_into().unwrap()),
            0xffff
        );
        assert_eq!(internet_checksum(&frame[34..42]), 0);
    }

    fn nat_inbound_ttl_frame(protocol: FirewallProtocol) -> Vec<u8> {
        let (ipv4_total_len, transport_len) = match protocol {
            FirewallProtocol::Udp => (28_u16, 8_usize),
            FirewallProtocol::Tcp => (40_u16, 20_usize),
        };
        let mut frame = vec![0_u8; 60];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 30]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&ipv4_total_len.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 1;
        frame[23] = match protocol {
            FirewallProtocol::Udp => 17,
            FirewallProtocol::Tcp => 6,
        };
        frame[26..30].copy_from_slice(&REMOTE.octets());
        frame[30..34].copy_from_slice(&PUBLIC.octets());
        match protocol {
            FirewallProtocol::Udp => {
                frame[34..36].copy_from_slice(&53_u16.to_be_bytes());
                frame[36..38].copy_from_slice(&40_000_u16.to_be_bytes());
                frame[38..40].copy_from_slice(&8_u16.to_be_bytes());
                let mut pseudo = Vec::with_capacity(12 + transport_len);
                pseudo.extend_from_slice(&REMOTE.octets());
                pseudo.extend_from_slice(&PUBLIC.octets());
                pseudo.extend_from_slice(&[0, 17]);
                pseudo.extend_from_slice(&(transport_len as u16).to_be_bytes());
                pseudo.extend_from_slice(&frame[34..42]);
                let checksum = internet_checksum(&pseudo);
                frame[40..42].copy_from_slice(&checksum.to_be_bytes());
            }
            FirewallProtocol::Tcp => {
                frame[34..36].copy_from_slice(&443_u16.to_be_bytes());
                frame[36..38].copy_from_slice(&40_000_u16.to_be_bytes());
                frame[38..42].copy_from_slice(&2_u32.to_be_bytes());
                frame[42..46].copy_from_slice(&1_u32.to_be_bytes());
                frame[46] = 5 << 4;
                frame[47] = 0x12;
                frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
                let mut pseudo = Vec::with_capacity(12 + transport_len);
                pseudo.extend_from_slice(&REMOTE.octets());
                pseudo.extend_from_slice(&PUBLIC.octets());
                pseudo.extend_from_slice(&[0, 6]);
                pseudo.extend_from_slice(&(transport_len as u16).to_be_bytes());
                pseudo.extend_from_slice(&frame[34..54]);
                let checksum = internet_checksum(&pseudo);
                frame[50..52].copy_from_slice(&checksum.to_be_bytes());
            }
        }
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn assert_nat_inbound_ttl_error_is_captured_after_firewall(protocol: FirewallProtocol) {
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(ROUTER)).unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let neighbors = [
            crate::Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 10]),
            },
            crate::Neighbor {
                interface: WAN,
                target: ROUTER,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
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
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let inside_prefix =
            FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24).unwrap();
        let any_prefix = FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap();
        let any_ports = FirewallPortRange::new(1, u16::MAX).unwrap();
        let rules = [
            FirewallRule::new(
                FirewallRuleId(1),
                FirewallInterface::Interface(LAN),
                FirewallInterface::Interface(WAN),
                inside_prefix,
                any_prefix,
                FirewallProtocol::Udp,
                any_ports,
                any_ports,
                FirewallAction::AllowStateful,
            ),
            FirewallRule::new(
                FirewallRuleId(2),
                FirewallInterface::Interface(WAN),
                FirewallInterface::Interface(LAN),
                any_prefix,
                inside_prefix,
                FirewallProtocol::Udp,
                any_ports,
                any_ports,
                FirewallAction::AllowStateful,
            ),
            FirewallRule::new(
                FirewallRuleId(3),
                FirewallInterface::Interface(LAN),
                FirewallInterface::Interface(WAN),
                inside_prefix,
                any_prefix,
                FirewallProtocol::Tcp,
                any_ports,
                any_ports,
                FirewallAction::AllowStateful,
            ),
            FirewallRule::new(
                FirewallRuleId(4),
                FirewallInterface::Interface(WAN),
                FirewallInterface::Interface(LAN),
                any_prefix,
                inside_prefix,
                FirewallProtocol::Tcp,
                any_ports,
                any_ports,
                FirewallAction::AllowStateful,
            ),
        ];
        let firewall_config = FirewallConfig::new(
            &snapshot,
            &rules,
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
        )
        .unwrap();

        let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
        let mut udp_indexes =
            crate::nat44::TestNat44UdpIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
        let mut udp = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
        let udp_seed = udp.plan_outbound(INTERNAL, 12_345, REMOTE, 0).unwrap();
        assert_eq!(udp_seed.public_port(), 40_000);
        udp.commit_outbound(udp_seed, 0).unwrap();
        let before_udp_mappings = udp.mappings().to_vec();
        let before_udp_peers = udp.peers().to_vec();
        let before_udp_counters = udp.counters();

        let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut tcp_mapping_buckets = [DirectoryBucket::default(); 1];
        let mut tcp_mapping_nodes = [DirectoryNode::default(); 1];
        let mut tcp_session_buckets = [DirectoryBucket::default(); 1];
        let mut tcp_session_nodes = [DirectoryNode::default(); 1];
        let mut tcp_owners = [PortOwnerSlot::default(); 1];
        let mut tcp = Nat44TcpRuntime::new(
            tcp_config,
            &mut tcp_mappings,
            &mut tcp_sessions,
            Nat44TcpIndexStorage::new(
                &mut tcp_mapping_buckets,
                &mut tcp_mapping_nodes,
                &mut tcp_session_buckets,
                &mut tcp_session_nodes,
                &mut tcp_owners,
            ),
            Nat44TcpHashKey::new(0xc001_d00d_f00d_beef, 0x1234_5678_9abc_def0).unwrap(),
        )
        .unwrap();
        let tcp_seed = tcp
            .plan_outbound(INTERNAL, 12_346, REMOTE, 443, true, 0)
            .unwrap();
        assert_eq!(tcp_seed.public_port(), 40_000);
        tcp.commit_outbound(tcp_seed, 0).unwrap();
        let before_tcp_mappings = tcp.mappings().to_vec();
        let before_tcp_sessions = tcp.sessions().to_vec();
        let before_tcp_counters = tcp.counters();

        let mut firewall_states = [FirewallStateSlot::default(); 2];
        let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_states);
        let udp_firewall_seed = FirewallPacket {
            ingress: LAN,
            egress: WAN,
            source: INTERNAL,
            destination: REMOTE,
            protocol: FirewallProtocol::Udp,
            source_port: 12_345,
            destination_port: 53,
            tcp_flags: 0,
        };
        let udp_firewall_plan = firewall
            .plan_packet(&firewall_config, udp_firewall_seed, 0)
            .unwrap();
        firewall.commit(udp_firewall_plan).unwrap();
        let tcp_firewall_seed = FirewallPacket {
            ingress: LAN,
            egress: WAN,
            source: INTERNAL,
            destination: REMOTE,
            protocol: FirewallProtocol::Tcp,
            source_port: 12_346,
            destination_port: 443,
            tcp_flags: 0x02,
        };
        let tcp_firewall_plan = firewall
            .plan_packet(&firewall_config, tcp_firewall_seed, 0)
            .unwrap();
        firewall.commit(tcp_firewall_plan).unwrap();
        let before_firewall_states = firewall.states().to_vec();

        let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
        let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut resolution_states,
            &mut resolution_actions,
        );
        let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            &mut error_states,
            &mut error_actions,
        );
        let mut audit_storage = [FirewallAuditRecord::default(); 1];
        let mut audit = FirewallAuditBuffer::new(&mut audit_storage);
        let mut trace = RecordingTrace::default();
        let mut frame = nat_inbound_ttl_frame(protocol);
        let original = frame.clone();
        let completion = Cell::new(None);
        let report = forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_audited(
            OnePacketBatch {
                ingress: WAN,
                frame: Some(&mut frame),
                completion: &completion,
            },
            &snapshot,
            &mut resolution,
            &mut errors,
            &udp_config,
            Some(&mut udp),
            &tcp_config,
            Some(&mut tcp),
            &firewall_config,
            Some(&mut firewall),
            &mut audit,
            MonotonicMillis(0),
            &mut trace,
        );
        let disposition = trace.events.iter().find_map(|event| match event {
            TraceEvent::Icmpv4TimeExceededDisposition { disposition, .. } => Some(*disposition),
            _ => None,
        });
        let has_icmp_trace = disposition.is_some();
        eprintln!(
            "defect3 {protocol:?} inbound ttl=1: expected=drop/Ipv4TtlExpired pending=1 \
             queued_time_exceeded=1 icmp_trace=true actual=completion={:?} pending={} \
             queued_time_exceeded={} icmp_trace={has_icmp_trace}",
            completion.get(),
            errors.pending_actions(),
            errors.counters().queued_time_exceeded,
        );
        assert_eq!(
            (report.received, report.tx_requested, report.dropped),
            (1, 0, 1)
        );
        assert_eq!(report.completion.recycled, 1);
        assert_eq!(
            completion.get(),
            Some(SlotCompletion::Recycle(DropReason::Ipv4TtlExpired))
        );
        assert_eq!(
            disposition,
            Some(Icmpv4ErrorDisposition::Queued {
                egress: WAN,
                quote_len: match protocol {
                    FirewallProtocol::Udp => 28,
                    FirewallProtocol::Tcp => 40,
                },
            })
        );
        assert_eq!(errors.pending_actions(), 1);
        assert_eq!(errors.counters().queued_time_exceeded, 1);
        assert_eq!(errors.counters().queued, 1);
        assert_eq!(frame, original);
        assert_eq!(udp.mappings(), before_udp_mappings.as_slice());
        assert_eq!(udp.peers(), before_udp_peers.as_slice());
        assert_eq!(udp.counters(), before_udp_counters);
        assert_eq!(tcp.mappings(), before_tcp_mappings.as_slice());
        assert_eq!(tcp.sessions(), before_tcp_sessions.as_slice());
        assert_eq!(tcp.counters(), before_tcp_counters);
        assert_eq!(firewall.states(), before_firewall_states.as_slice());
        assert_eq!(audit.records().len(), 1);
        assert_eq!(audit.records()[0].ingress, WAN);
        assert_eq!(audit.records()[0].egress, LAN);
        assert_eq!(
            audit.records()[0].disposition.verdict,
            FirewallVerdict::Allow
        );
        assert_eq!(
            audit.records()[0].disposition.matched_action,
            Some(FirewallAction::AllowStateful)
        );
    }

    #[test]
    fn nat_inbound_udp_ttl_expiry_captures_generic_icmp_after_firewall() {
        assert_nat_inbound_ttl_error_is_captured_after_firewall(FirewallProtocol::Udp);
    }

    #[test]
    fn nat_inbound_tcp_ttl_expiry_captures_generic_icmp_after_firewall() {
        assert_nat_inbound_ttl_error_is_captured_after_firewall(FirewallProtocol::Tcp);
    }

    #[test]
    fn icmp_error_type_read_is_limited_to_ipv4_total_length_for_ttl_expiry() {
        let routes = [Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(ROUTER)).unwrap()];
        let interfaces = [Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let neighbors = [crate::Neighbor {
            interface: WAN,
            target: ROUTER,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            &mut error_states,
            &mut error_actions,
        );
        let mut icmpv4_errors = Some((&mut errors, MonotonicMillis(0)));
        let mut resolution = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let mut trace = RecordingTrace::default();
        let result = decide_ipv4(
            &empty_ipv4_icmp_frame(1, Ipv4Address::from_octets([192, 0, 2, 99])),
            &snapshot,
            WAN,
            &mut resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut trace,
        );
        let disposition = trace.events.iter().find_map(|event| match event {
            TraceEvent::Icmpv4TimeExceededDisposition { disposition, .. } => Some(*disposition),
            _ => None,
        });
        eprintln!(
            "defect2 ttl=1 missing-payload ICMP type: expected=IcmpTypeMissing/pending=0 \
             actual={disposition:?}/pending={}",
            errors.pending_actions()
        );
        assert!(matches!(result, Err(DropReason::Ipv4TtlExpired)));
        assert_eq!(disposition, Some(Icmpv4ErrorDisposition::IcmpTypeMissing));
        assert_eq!(errors.pending_actions(), 0);
    }

    #[test]
    fn icmp_failure_candidate_ignores_ethernet_padding_after_ipv4_total_length() {
        let direct =
            Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap();
        let default = Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(ROUTER)).unwrap();
        let routes = [direct, default];
        let interfaces = [Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        }];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
        let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut dynamic_neighbors = [crate::DynamicNeighborSlot::EMPTY; 0];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut resolution_states,
            &mut resolution_actions,
            &mut dynamic_neighbors,
            &mut failure_holds,
        );
        let mut no_icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let mut trace = RecordingTrace::default();
        let destination = Ipv4Address::from_octets([198, 51, 100, 99]);
        let result = decide_ipv4(
            &empty_ipv4_icmp_frame(64, destination),
            &snapshot,
            WAN,
            &mut Some((&mut resolution, MonotonicMillis(0))),
            &mut no_icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut trace,
        );
        eprintln!(
            "defect2 direct-neighbor-miss missing-payload candidate: \
             expected=captured=0/pending_hold=0 actual=captured={}/pending_hold={}",
            resolution.failure_counters().captured,
            resolution.pending_failure_holds()
        );
        assert!(matches!(result, Err(DropReason::NeighborUnresolved)));
        assert_eq!(resolution.failure_counters().captured, 0);
        assert_eq!(resolution.pending_failure_holds(), 0);
    }

    #[test]
    fn exhausted_tcp_revision_in_firewall_composition_is_typed_and_byte_atomic() {
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(
                Ipv4Address::from_octets([0; 4]),
                0,
                WAN,
                Some(Ipv4Address::from_octets([203, 0, 113, 1])),
            )
            .unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let neighbors = [
            crate::Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 10]),
            },
            crate::Neighbor {
                interface: WAN,
                target: Ipv4Address::from_octets([203, 0, 113, 1]),
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
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
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let rules = [FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24).unwrap(),
            FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap(),
            FirewallProtocol::Tcp,
            FirewallPortRange::new(1, u16::MAX).unwrap(),
            FirewallPortRange::new(1, u16::MAX).unwrap(),
            FirewallAction::AllowStateful,
        )];
        let firewall_config = FirewallConfig::new(
            &snapshot,
            &rules,
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
        )
        .unwrap();

        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut mapping_buckets = [DirectoryBucket::default(); 1];
        let mut mapping_nodes = [DirectoryNode::default(); 1];
        let mut session_buckets = [DirectoryBucket::default(); 1];
        let mut session_nodes = [DirectoryNode::default(); 1];
        let mut owners = [PortOwnerSlot::default(); 1];
        let mut firewall_states = [FirewallStateSlot::default(); 1];
        let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
        let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
        let before_mappings = mappings;
        let before_sessions = sessions;
        let before_mapping_buckets = mapping_buckets;
        let before_mapping_nodes = mapping_nodes;
        let before_session_buckets = session_buckets;
        let before_session_nodes = session_nodes;
        let before_owners = owners;
        let before_firewall_states = firewall_states;
        let before_resolution_states = resolution_states;
        let before_resolution_actions = resolution_actions;
        let mut frame = tcp_syn_frame();
        let original = frame.clone();
        let completion = Cell::new(None);

        {
            let mut tcp = Nat44TcpRuntime::new(
                tcp_config,
                &mut mappings,
                &mut sessions,
                Nat44TcpIndexStorage::new(
                    &mut mapping_buckets,
                    &mut mapping_nodes,
                    &mut session_buckets,
                    &mut session_nodes,
                    &mut owners,
                ),
                Nat44TcpHashKey::new(0xc001_d00d_f00d_beef, 0x1234_5678_9abc_def0).unwrap(),
            )
            .unwrap();
            tcp.exhaust_state_revision_at_for_test(0);
            let before_tcp_counters = tcp.counters();
            let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_states);
            let before_firewall_counters = firewall.counters();
            let mut resolution = ResolutionRuntime::new(
                ResolutionPolicy::new(1_000, 2_000).unwrap(),
                &mut resolution_states,
                &mut resolution_actions,
            );
            let report = forward_batch_with_nat44_udp_and_tcp_and_firewall(
                OnePacketBatch {
                    ingress: LAN,
                    frame: Some(&mut frame),
                    completion: &completion,
                },
                &snapshot,
                &mut resolution,
                &udp_config,
                None,
                &tcp_config,
                Some(&mut tcp),
                &firewall_config,
                Some(&mut firewall),
                MonotonicMillis(0),
                &mut NoTrace,
            );
            assert_eq!(
                (report.received, report.tx_requested, report.dropped),
                (1, 0, 1)
            );
            assert_eq!(report.completion.recycled, 1);
            let mut expected_tcp_counters = before_tcp_counters;
            expected_tcp_counters.config_mismatches += 1;
            assert_eq!(tcp.counters(), expected_tcp_counters);
            assert_eq!(tcp.mappings(), &before_mappings);
            assert_eq!(tcp.sessions(), &before_sessions);
            let mut expected_firewall_counters = before_firewall_counters;
            expected_firewall_counters.state_probes += 1;
            expected_firewall_counters.rule_evaluations += 1;
            assert_eq!(firewall.counters(), expected_firewall_counters);
            assert_eq!(firewall.states(), &before_firewall_states);
        }

        assert_eq!(
            completion.get(),
            Some(SlotCompletion::Recycle(DropReason::Nat44TcpConfigMismatch))
        );
        assert_eq!(frame, original);
        assert_eq!(mappings, before_mappings);
        assert_eq!(sessions, before_sessions);
        assert_eq!(mapping_buckets, before_mapping_buckets);
        assert_eq!(mapping_nodes, before_mapping_nodes);
        assert_eq!(session_buckets, before_session_buckets);
        assert_eq!(session_nodes, before_session_nodes);
        assert_eq!(owners, before_owners);
        assert_eq!(firewall_states, before_firewall_states);
        assert_eq!(resolution_states, before_resolution_states);
        assert_eq!(resolution_actions, before_resolution_actions);
    }

    fn frag_needed_frame() -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 20 + 8 + 20 + 8];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 3]);
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
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
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
        let mut nat_indexes =
            crate::nat44::TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
        let plan = nat.plan_outbound(INTERNAL, 12_345, REMOTE, 0).unwrap();
        nat.commit_outbound(plan, 0).unwrap();
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
            None,
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
            (117, "IPV4_INGRESS_INTERFACE_UNKNOWN"),
            (118, "IPV4_ETHERNET_SOURCE_ZERO"),
            (119, "IPV4_ETHERNET_SOURCE_BROADCAST"),
            (120, "IPV4_ETHERNET_SOURCE_MULTICAST"),
            (121, "IPV4_ETHERNET_DESTINATION_ZERO"),
            (122, "IPV4_ETHERNET_DESTINATION_BROADCAST"),
            (123, "IPV4_ETHERNET_DESTINATION_MULTICAST"),
            (124, "IPV4_SOURCE_UNSPECIFIED_NETWORK"),
            (125, "IPV4_SOURCE_LOOPBACK"),
            (126, "IPV4_SOURCE_MULTICAST"),
            (127, "IPV4_SOURCE_LIMITED_BROADCAST"),
            (128, "IPV4_SOURCE_CLASS_E"),
            (129, "IPV4_SOURCE_NETWORK_ADDRESS"),
            (130, "IPV4_SOURCE_DIRECTED_BROADCAST"),
            (131, "IPV4_DESTINATION_UNSPECIFIED_NETWORK"),
            (132, "IPV4_DESTINATION_LOOPBACK"),
            (133, "IPV4_DESTINATION_MULTICAST"),
            (134, "IPV4_DESTINATION_LIMITED_BROADCAST"),
            (135, "IPV4_DESTINATION_CLASS_E"),
            (136, "IPV4_DESTINATION_NETWORK_ADDRESS"),
            (137, "IPV4_DESTINATION_DIRECTED_BROADCAST"),
            (138, "ETHERNET_DESTINATION_NOT_LOCAL"),
            (139, "ARP_INGRESS_INTERFACE_UNKNOWN"),
            (140, "ARP_ETHERNET_SOURCE_ZERO"),
            (141, "ARP_ETHERNET_SOURCE_BROADCAST"),
            (142, "ARP_ETHERNET_SOURCE_MULTICAST"),
            (143, "ARP_ETHERNET_DESTINATION_ZERO"),
            (144, "ARP_ETHERNET_DESTINATION_MULTICAST"),
            (145, "IPV4_SOURCE_LOCAL_ADDRESS"),
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
            DropReason::Ipv4IngressInterfaceUnknown,
            DropReason::Ipv4EthernetSourceZero,
            DropReason::Ipv4EthernetSourceBroadcast,
            DropReason::Ipv4EthernetSourceMulticast,
            DropReason::Ipv4EthernetDestinationZero,
            DropReason::Ipv4EthernetDestinationBroadcast,
            DropReason::Ipv4EthernetDestinationMulticast,
            DropReason::Ipv4SourceUnspecifiedNetwork,
            DropReason::Ipv4SourceLoopback,
            DropReason::Ipv4SourceMulticast,
            DropReason::Ipv4SourceLimitedBroadcast,
            DropReason::Ipv4SourceClassE,
            DropReason::Ipv4SourceNetworkAddress,
            DropReason::Ipv4SourceDirectedBroadcast,
            DropReason::Ipv4DestinationUnspecifiedNetwork,
            DropReason::Ipv4DestinationLoopback,
            DropReason::Ipv4DestinationMulticast,
            DropReason::Ipv4DestinationLimitedBroadcast,
            DropReason::Ipv4DestinationClassE,
            DropReason::Ipv4DestinationNetworkAddress,
            DropReason::Ipv4DestinationDirectedBroadcast,
            DropReason::EthernetDestinationNotLocal,
            DropReason::ArpIngressInterfaceUnknown,
            DropReason::ArpEthernetSourceZero,
            DropReason::ArpEthernetSourceBroadcast,
            DropReason::ArpEthernetSourceMulticast,
            DropReason::ArpEthernetDestinationZero,
            DropReason::ArpEthernetDestinationMulticast,
            DropReason::Ipv4SourceLocalAddress,
        ];
        assert_eq!(actual.len(), expected.len());
        for (reason, &(discriminant, code)) in actual.iter().zip(&expected) {
            assert_eq!(*reason as u16, discriminant);
            assert_eq!(reason.code(), code);
        }
    }

    // Contract: a snapshot accepts only unique route keys, known egress
    // interfaces, and at most one local address per interface or address.
    #[test]
    fn snapshot_validation_rejects_forwarding_table_key_collisions() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let route = Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap();
        assert!(matches!(
            ForwardingSnapshot::with_ipv4_origin_policy(
                &[route, route],
                &interfaces,
                &[],
                &[],
                Ipv4OriginPolicy::default(),
            ),
            Err(crate::SnapshotError::DuplicateRoute)
        ));

        let same_prefix_different_lengths = [
            Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 25, WAN, None).unwrap(),
        ];
        // Contract: route identity includes both the prefix and prefix length;
        // equal prefixes with different lengths are distinct routes.
        assert!(ForwardingSnapshot::with_ipv4_origin_policy(
            &same_prefix_different_lengths,
            &interfaces,
            &[],
            &[],
            Ipv4OriginPolicy::default(),
        )
        .is_ok());

        let unknown_interface_route =
            Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, IfId(99), None).unwrap();
        assert!(matches!(
            ForwardingSnapshot::with_ipv4_origin_policy(
                &[unknown_interface_route],
                &interfaces,
                &[],
                &[],
                Ipv4OriginPolicy::default(),
            ),
            Err(crate::SnapshotError::RouteUnknownInterface)
        ));

        let duplicate_neighbors = [
            crate::Neighbor {
                interface: WAN,
                target: REMOTE,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            },
            crate::Neighbor {
                interface: WAN,
                target: REMOTE,
                mac: MacAddress([2, 0, 0, 0, 0, 21]),
            },
        ];
        // Contract: a neighbor key is the exact (interface, target) pair,
        // regardless of the MAC stored for that key.
        assert!(matches!(
            ForwardingSnapshot::with_ipv4_origin_policy(
                &[],
                &interfaces,
                &duplicate_neighbors,
                &[],
                Ipv4OriginPolicy::default(),
            ),
            Err(crate::SnapshotError::DuplicateNeighbor)
        ));

        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
            },
            LocalIpv4Binding {
                interface: LAN,
                address: Ipv4Address::from_octets([10, 0, 0, 2]),
            },
        ];
        assert!(matches!(
            ForwardingSnapshot::with_ipv4_origin_policy(
                &[],
                &interfaces,
                &[],
                &bindings,
                Ipv4OriginPolicy::default(),
            ),
            Err(crate::SnapshotError::DuplicateLocalIpv4Binding)
        ));

        let same_address_different_interfaces = [
            LocalIpv4Binding {
                interface: LAN,
                address: Ipv4Address::from_octets([10, 0, 0, 9]),
            },
            LocalIpv4Binding {
                interface: WAN,
                address: Ipv4Address::from_octets([10, 0, 0, 9]),
            },
        ];
        // Contract: an IPv4 address can have only one owning interface, even
        // when the two conflicting bindings use different interfaces.
        assert!(matches!(
            ForwardingSnapshot::with_ipv4_origin_policy(
                &[],
                &interfaces,
                &[],
                &same_address_different_interfaces,
                Ipv4OriginPolicy::default(),
            ),
            Err(crate::SnapshotError::DuplicateLocalIpv4Binding)
        ));

        let policy = Ipv4OriginPolicy::new(37).unwrap();
        let snapshot =
            ForwardingSnapshot::with_ipv4_origin_policy(&[], &interfaces, &[], &[], policy)
                .unwrap();
        assert_eq!(snapshot.ipv4_origin_policy(), policy);
    }

    // Contract: ARP resolution authority must reject an action whose source
    // interface/MAC or source IPv4 binding is not an exact local pair.
    #[test]
    fn resolution_authority_requires_exact_local_source_identity() {
        let interfaces = [Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        }];
        let routes =
            [Route::new(Ipv4Address::from_octets([0, 0, 0, 0]), 0, WAN, Some(REMOTE)).unwrap()];

        let wrong_mac = ArpRequestAction {
            egress: WAN,
            source_mac: MacAddress([2, 0, 0, 0, 0, 3]),
            source_ip: PUBLIC,
            target_ip: REMOTE,
        };
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        assert_eq!(
            snapshot.resolution_action_authority(wrong_mac),
            ResolutionActionAuthority::Invalid
        );

        let wrong_source_ip = ArpRequestAction {
            egress: WAN,
            source_mac: interfaces[0].mac,
            source_ip: Ipv4Address::from_octets([203, 0, 113, 11]),
            target_ip: REMOTE,
        };
        assert_eq!(
            snapshot.resolution_action_authority(wrong_source_ip),
            ResolutionActionAuthority::Invalid
        );
    }

    // Contract: resolution may never authorize ARP for special, local,
    // connected-network, or connected-directed-broadcast targets.
    #[test]
    fn resolution_authority_rejects_every_forbidden_target_class() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let target_zero = Ipv4Address::from_octets([0, 1, 2, 3]);
        let target_loopback = Ipv4Address::from_octets([127, 0, 0, 1]);
        let target_multicast = Ipv4Address::from_octets([224, 0, 0, 1]);
        let target_broadcast = Ipv4Address::from_octets([255, 255, 255, 255]);
        let target_network = Ipv4Address::from_octets([198, 51, 100, 0]);
        let target_directed_broadcast = Ipv4Address::from_octets([198, 51, 100, 255]);
        let routes = [
            Route::new(target_zero, 32, WAN, Some(target_zero)).unwrap(),
            Route::new(target_loopback, 32, WAN, Some(target_loopback)).unwrap(),
            Route::new(target_multicast, 32, WAN, Some(target_multicast)).unwrap(),
            Route::new(target_broadcast, 32, WAN, Some(target_broadcast)).unwrap(),
            Route::new(INTERNAL, 32, WAN, Some(INTERNAL)).unwrap(),
            Route::new(target_network, 24, WAN, None).unwrap(),
        ];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let action = |target_ip| ArpRequestAction {
            egress: WAN,
            source_mac: interfaces[1].mac,
            source_ip: PUBLIC,
            target_ip,
        };

        for target in [
            target_zero,
            target_loopback,
            target_multicast,
            target_broadcast,
            INTERNAL,
            target_network,
            target_directed_broadcast,
        ] {
            assert_eq!(
                snapshot.resolution_action_authority(action(target)),
                ResolutionActionAuthority::Invalid,
                "forbidden target {target:?} must not be authorized",
            );
        }
    }

    // Contract: route authorization requires the exact egress/next-hop pair,
    // while a connected host route authorizes only its ordinary host target.
    #[test]
    fn resolution_authority_requires_exact_route_evidence() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        }];
        let action = |target_ip| ArpRequestAction {
            egress: WAN,
            source_mac: interfaces[1].mac,
            source_ip: PUBLIC,
            target_ip,
        };

        let target = REMOTE;
        let wrong_egress = [Route::new(target, 32, LAN, Some(target)).unwrap()];
        let snapshot = ForwardingSnapshot::new(&wrong_egress, &interfaces, &[], &bindings).unwrap();
        assert_eq!(
            snapshot.resolution_action_authority(action(target)),
            ResolutionActionAuthority::Invalid
        );

        let exact_next_hop = [Route::new(target, 32, WAN, Some(target)).unwrap()];
        let snapshot =
            ForwardingSnapshot::new(&exact_next_hop, &interfaces, &[], &bindings).unwrap();
        assert_eq!(
            snapshot.resolution_action_authority(action(target)),
            ResolutionActionAuthority::Valid
        );

        let different_next_hop = [Route::new(target, 32, WAN, Some(ROUTER)).unwrap()];
        let snapshot =
            ForwardingSnapshot::new(&different_next_hop, &interfaces, &[], &bindings).unwrap();
        assert_eq!(
            snapshot.resolution_action_authority(action(target)),
            ResolutionActionAuthority::Invalid
        );

        let connected_host = [Route::new(target, 32, WAN, None).unwrap()];
        let snapshot =
            ForwardingSnapshot::new(&connected_host, &interfaces, &[], &bindings).unwrap();
        assert_eq!(
            snapshot.resolution_action_authority(action(target)),
            ResolutionActionAuthority::Valid
        );
    }

    // Contract: IPv4 accepts only a local ingress interface, unicast source,
    // and either a local unicast destination or a valid Ethernet destination;
    // ARP additionally permits an Ethernet broadcast destination.
    #[test]
    fn ethernet_ingress_distinguishes_ipv4_and_arp_mac_contracts() {
        let interface = Interface {
            id: LAN,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: Ipv4Mtu::ETHERNET,
        };
        let interfaces = [interface];
        let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &[]).unwrap();
        let normal_source = [2, 0, 0, 0, 0, 9];
        let normal_destination = interface.mac.0;
        let frame = |destination: [u8; 6], source: [u8; 6]| {
            let mut frame = vec![0_u8; 14];
            frame[0..6].copy_from_slice(&destination);
            frame[6..12].copy_from_slice(&source);
            frame
        };

        assert_eq!(
            validate_ethernet_ingress(
                &frame(normal_destination, normal_source),
                &snapshot,
                WAN,
                IPV4_ETHERTYPE
            ),
            Err(Ipv4IngressInterfaceUnknown)
        );
        assert_eq!(
            validate_ethernet_ingress(
                &frame([0xff; 6], normal_source),
                &snapshot,
                LAN,
                ARP_ETHERTYPE
            ),
            Ok(())
        );

        for source in [[0; 6], [0xff; 6], [1, 0, 0, 0, 0, 9]] {
            let expected = if source == [0; 6] {
                ArpEthernetSourceZero
            } else if source == [0xff; 6] {
                ArpEthernetSourceBroadcast
            } else {
                ArpEthernetSourceMulticast
            };
            assert_eq!(
                validate_ethernet_ingress(
                    &frame(normal_destination, source),
                    &snapshot,
                    LAN,
                    ARP_ETHERTYPE,
                ),
                Err(expected)
            );
        }

        for destination in [[0; 6], [1, 0, 0, 0, 0, 9]] {
            let expected = if destination == [0; 6] {
                ArpEthernetDestinationZero
            } else {
                ArpEthernetDestinationMulticast
            };
            assert_eq!(
                validate_ethernet_ingress(
                    &frame(destination, normal_source),
                    &snapshot,
                    LAN,
                    ARP_ETHERTYPE,
                ),
                Err(expected)
            );
        }
        assert_eq!(
            validate_ethernet_ingress(
                &frame([0xff; 6], normal_source),
                &snapshot,
                LAN,
                ARP_ETHERTYPE
            ),
            Ok(())
        );
    }

    fn ipv4_decision_frame(
        source: Ipv4Address,
        destination: Ipv4Address,
        protocol: u8,
        ttl: u8,
        ihl_words: u8,
    ) -> Vec<u8> {
        let header_len = usize::from(ihl_words) * 4;
        let mut frame = vec![0_u8; 14 + header_len];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
        frame[12..14].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        frame[14] = 0x40 | ihl_words;
        frame[16..18].copy_from_slice(&(header_len as u16).to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = ttl;
        frame[23] = protocol;
        frame[26..30].copy_from_slice(&source.octets());
        frame[30..34].copy_from_slice(&destination.octets());
        let checksum = ipv4_header_checksum(&frame[14..14 + header_len]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn decide_ipv4_without_services(
        frame: &[u8],
        snapshot: &ForwardingSnapshot<'_>,
        ingress: IfId,
    ) -> Result<super::PacketDecision, DropReason> {
        let mut resolution = None;
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        decide_ipv4(
            frame,
            snapshot,
            ingress,
            &mut resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        )
    }

    fn decide_ipv4_with_services(
        frame: &[u8],
        snapshot: &ForwardingSnapshot<'_>,
        ingress: IfId,
        udp_config: Option<&Nat44UdpConfig>,
        tcp_config: Option<&Nat44TcpConfig>,
        firewall_config: Option<&FirewallConfig<'_>>,
    ) -> Result<super::PacketDecision, DropReason> {
        let mut resolution = None;
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        decide_ipv4(
            frame,
            snapshot,
            ingress,
            &mut resolution,
            &mut icmpv4_errors,
            udp_config,
            &mut nat44_udp,
            tcp_config,
            &mut nat44_tcp,
            firewall_config,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        )
    }

    fn decide_ipv4_with_mismatched_tcp_runtime(
        frame: &[u8],
        snapshot: &ForwardingSnapshot<'_>,
        ingress: IfId,
        udp_config: Option<&Nat44UdpConfig>,
        tcp_config: &Nat44TcpConfig,
        runtime_config: Nat44TcpConfig,
    ) -> Result<super::PacketDecision, DropReason> {
        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut mapping_buckets = [DirectoryBucket::default(); 1];
        let mut mapping_nodes = [DirectoryNode::default(); 1];
        let mut session_buckets = [DirectoryBucket::default(); 1];
        let mut session_nodes = [DirectoryNode::default(); 1];
        let mut owners = [PortOwnerSlot::default(); 1];
        let mut runtime = Nat44TcpRuntime::new(
            runtime_config,
            &mut mappings,
            &mut sessions,
            Nat44TcpIndexStorage::new(
                &mut mapping_buckets,
                &mut mapping_nodes,
                &mut session_buckets,
                &mut session_nodes,
                &mut owners,
            ),
            Nat44TcpHashKey::new(0xc001_d00d_f00d_beef, 0x1234_5678_9abc_def0).unwrap(),
        )
        .unwrap();
        let mut resolution = None;
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = Some(&mut runtime);
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        decide_ipv4(
            frame,
            snapshot,
            ingress,
            &mut resolution,
            &mut icmpv4_errors,
            udp_config,
            &mut nat44_udp,
            Some(tcp_config),
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        )
    }

    // Contract: a local IPv4 address is local only on the interface owning
    // that address; a same-address binding on another interface must route.
    #[test]
    fn decide_ipv4_binds_local_delivery_to_the_ingress_interface() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(PUBLIC, 32, WAN, None).unwrap()];
        let neighbors = [crate::Neighbor {
            interface: WAN,
            target: PUBLIC,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let frame = ipv4_decision_frame(REMOTE, PUBLIC, 6, 64, 5);
        let decision = decide_ipv4_without_services(&frame, &snapshot, LAN).unwrap();
        assert!(matches!(decision, super::PacketDecision::Ipv4(_)));
    }

    // Contract: RFC 1812 §5.2.5 requires a router to forward a datagram whose
    // options it does not recognise, passing them through unchanged. Source
    // routing is refused instead — RFC 1812 §4.2.2.11 allows that, this router
    // has no source-route reversal, and honouring it would let a sender steer
    // traffic past filtering that assumes the routing table decides the path.
    #[test]
    fn forwarded_ipv4_options_are_carried_unless_they_route_or_are_malformed() {
        let interfaces = [Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let neighbors = [crate::Neighbor {
            interface: WAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();

        let carried: [(&str, [u8; 8]); 4] = [
            ("end of list then padding", [0, 0, 0, 0, 0, 0, 0, 0]),
            ("no-operation padding", [1, 1, 1, 1, 1, 1, 1, 0]),
            // Record Route, type 7, length 7: carried without being filled in.
            ("record route", [7, 7, 4, 0, 0, 0, 0, 0]),
            // An option this router does not know, which must still be carried.
            ("unrecognised option", [222, 4, 0, 0, 0, 0, 0, 0]),
        ];
        for (label, options) in carried {
            let mut frame = ipv4_decision_frame(INTERNAL, REMOTE, 6, 64, 7);
            frame[34..42].copy_from_slice(&options);
            frame[24..26].fill(0);
            let checksum = ipv4_header_checksum(&frame[14..42]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            let outcome = decide_ipv4_without_services(&frame, &snapshot, WAN);
            assert!(
                matches!(outcome, Ok(super::PacketDecision::Ipv4(_))),
                "{label} must be forwarded, got {:?}",
                outcome.err()
            );
        }

        let refused: [(&str, [u8; 8], DropReason); 5] = [
            // Loose source route, type 131.
            (
                "loose source route",
                [131, 7, 4, 0, 0, 0, 0, 0],
                Ipv4SourceRouteUnsupported,
            ),
            // Strict source route, type 137.
            (
                "strict source route",
                [137, 7, 4, 0, 0, 0, 0, 0],
                Ipv4SourceRouteUnsupported,
            ),
            // A source route reached only after skipping a no-operation.
            (
                "source route behind padding",
                [1, 131, 7, 4, 0, 0, 0, 0],
                Ipv4SourceRouteUnsupported,
            ),
            // A length that cannot cover its own two octets.
            (
                "length below two",
                [7, 1, 0, 0, 0, 0, 0, 0],
                Ipv4OptionsMalformed,
            ),
            // A length that runs past the end of the header.
            (
                "length past the header",
                [7, 9, 0, 0, 0, 0, 0, 0],
                Ipv4OptionsMalformed,
            ),
        ];
        for (label, options, expected) in refused {
            let mut frame = ipv4_decision_frame(INTERNAL, REMOTE, 6, 64, 7);
            frame[34..42].copy_from_slice(&options);
            frame[24..26].fill(0);
            let checksum = ipv4_header_checksum(&frame[14..42]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            assert_eq!(
                decide_ipv4_without_services(&frame, &snapshot, WAN).err(),
                Some(expected),
                "{label}"
            );
        }
    }

    // Contract: a static neighbor is usable only when both its interface and
    // target match the selected route.
    #[test]
    fn decide_ipv4_requires_static_neighbor_interface_and_target() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let neighbors = [Neighbor {
            interface: LAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
        let frame = ipv4_decision_frame(INTERNAL, REMOTE, 6, 64, 5);

        assert!(matches!(
            decide_ipv4_without_services(&frame, &snapshot, WAN),
            Err(NeighborUnresolved)
        ));
    }

    // Contract: a dynamic ARP request needs a local source binding on the
    // selected egress, and a normal target must be queued for resolution.
    #[test]
    fn decide_ipv4_schedules_dynamic_resolution_from_selected_egress() {
        let interfaces = [Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        }];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut states,
            &mut actions,
        );
        let frame = ipv4_decision_frame(INTERNAL, REMOTE, 6, 64, 5);
        let mut resolution = Some((&mut runtime, MonotonicMillis(0)));
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let result = decide_ipv4(
            &frame,
            &snapshot,
            WAN,
            &mut resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        );

        assert!(matches!(result, Err(NeighborUnresolved)));
        assert_eq!(runtime.pending_actions(), 1);
        assert_eq!(runtime.queued_action(0).unwrap().0.target_ip, REMOTE);
        assert_eq!(runtime.queued_action(0).unwrap().0.source_ip, PUBLIC);
    }

    // Contract: a target already owned by any local binding is forbidden for
    // dynamic resolution even when the selected route itself is a host route.
    #[test]
    fn decide_ipv4_does_not_schedule_a_local_target() {
        let target = Ipv4Address::from_octets([192, 0, 2, 99]);
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let routes = [Route::new(target, 32, WAN, None).unwrap()];
        let bindings = [
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
            LocalIpv4Binding {
                interface: LAN,
                address: target,
            },
        ];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut states,
            &mut actions,
        );
        let frame = ipv4_decision_frame(INTERNAL, target, 6, 64, 5);
        let mut resolution = Some((&mut runtime, MonotonicMillis(0)));
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let result = decide_ipv4(
            &frame,
            &snapshot,
            WAN,
            &mut resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        );

        assert!(matches!(result, Err(NeighborUnresolved)));
        assert_eq!(runtime.pending_actions(), 0);
    }

    // Contract: connected-network and directed-broadcast evidence forbids a
    // request only when it belongs to the selected route's egress interface.
    #[test]
    fn decide_ipv4_resolution_checks_connected_route_evidence_exactly() {
        let directed_broadcast = Ipv4Address::from_octets([198, 51, 100, 255]);
        let directed_interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let directed_routes = [
            Route::new(directed_broadcast, 32, WAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, LAN, None).unwrap(),
        ];
        let directed_bindings = [LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        }];
        let directed_snapshot = ForwardingSnapshot::new(
            &directed_routes,
            &directed_interfaces,
            &[],
            &directed_bindings,
        )
        .unwrap();
        let mut directed_states = [ResolutionStateSlot::EMPTY; 1];
        let mut directed_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut directed_runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut directed_states,
            &mut directed_actions,
        );
        let directed_frame = ipv4_decision_frame(INTERNAL, directed_broadcast, 6, 64, 5);
        let mut directed_resolution = Some((&mut directed_runtime, MonotonicMillis(0)));
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let directed_result = decide_ipv4(
            &directed_frame,
            &directed_snapshot,
            WAN,
            &mut directed_resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        );
        assert!(matches!(directed_result, Err(NeighborUnresolved)));
        assert_eq!(directed_runtime.pending_actions(), 1);

        let network = Ipv4Address::from_octets([198, 51, 101, 0]);
        let network_routes = [
            Route::new(network, 32, WAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([198, 51, 101, 0]), 24, WAN, None).unwrap(),
        ];
        let network_snapshot = ForwardingSnapshot::new(
            &network_routes,
            &directed_interfaces,
            &[],
            &directed_bindings,
        )
        .unwrap();
        let mut network_states = [ResolutionStateSlot::EMPTY; 1];
        let mut network_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut network_runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut network_states,
            &mut network_actions,
        );
        let network_frame = ipv4_decision_frame(INTERNAL, network, 6, 64, 5);
        let mut network_resolution = Some((&mut network_runtime, MonotonicMillis(0)));
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let network_result = decide_ipv4(
            &network_frame,
            &network_snapshot,
            WAN,
            &mut network_resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        );
        assert!(matches!(network_result, Err(NeighborUnresolved)));
        assert_eq!(network_runtime.pending_actions(), 0);
    }

    // Contract: a direct-route neighbor miss captures an eligible ICMP error
    // candidate only when its resolution target is the packet destination.
    #[test]
    fn decide_ipv4_captures_direct_route_failure_candidate() {
        let target = Ipv4Address::from_octets([192, 0, 2, 99]);
        let interfaces = [Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let routes = [Route::new(target, 32, WAN, None).unwrap()];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        }];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        let mut frame = zero_identifier_echo_request();
        frame[30..34].copy_from_slice(&target.octets());
        frame[24..26].fill(0);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let mut resolution_option = Some((&mut resolution, MonotonicMillis(0)));
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let result = decide_ipv4(
            &frame,
            &snapshot,
            WAN,
            &mut resolution_option,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        );

        assert_eq!(result.err(), Some(NeighborUnresolved));
        assert_eq!(resolution.failure_counters().captured, 1);
        assert_eq!(resolution.pending_failure_holds(), 1);
    }

    // Contract: a firewall must be preflighted for an inbound NAT candidate
    // only when the destination and transport protocol match that NAT.
    #[test]
    fn decide_ipv4_nat_candidate_requires_matching_transport_protocol() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: DMZ,
                mac: MacAddress([2, 0, 0, 0, 0, 3]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
            LocalIpv4Binding {
                interface: DMZ,
                address: PUBLIC2,
            },
        ];
        let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            DMZ,
            PUBLIC2,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let firewall_config = FirewallConfig::new(
            &snapshot,
            &[],
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(1, 2).unwrap(),
        )
        .unwrap();

        let udp_destination_with_tcp = ipv4_decision_frame(REMOTE, PUBLIC, 6, 64, 5);
        assert!(matches!(
            decide_ipv4_with_services(
                &udp_destination_with_tcp,
                &snapshot,
                WAN,
                Some(&udp_config),
                None,
                Some(&firewall_config),
            ),
            Ok(super::PacketDecision::ConsumeIpv4Local)
        ));

        // Contract: a UDP packet that misses every NAT candidacy check falls
        // to local delivery, which now answers a locally-addressed UDP
        // packet with Port Unreachable (RFC 1812 §4.3.3.3) rather than
        // silently consuming it.
        let tcp_destination_with_udp = ipv4_decision_frame(REMOTE, PUBLIC2, 17, 64, 5);
        assert!(matches!(
            decide_ipv4_with_services(
                &tcp_destination_with_udp,
                &snapshot,
                DMZ,
                None,
                Some(&tcp_config),
                Some(&firewall_config),
            ),
            Err(super::DropReason::Icmpv4PortUnreachable)
        ));
    }

    // Contract: combined NAT realm mismatch is rejected only for a TCP/UDP
    // packet addressed to either configured public address.
    #[test]
    fn decide_ipv4_rejects_combined_nat_realm_mismatch_for_either_public_address() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: DMZ,
                mac: MacAddress([2, 0, 0, 0, 0, 3]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
            LocalIpv4Binding {
                interface: DMZ,
                address: PUBLIC2,
            },
        ];
        let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            DMZ,
            PUBLIC2,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();

        for (destination, protocol) in [(PUBLIC, 17), (PUBLIC2, 6)] {
            let frame = ipv4_decision_frame(REMOTE, destination, protocol, 64, 5);
            assert!(matches!(
                decide_ipv4_with_services(
                    &frame,
                    &snapshot,
                    LAN,
                    Some(&udp_config),
                    Some(&tcp_config),
                    None,
                ),
                Err(Nat44CombinedRealmMismatch)
            ));
        }
    }

    // Contract: combined NAT realms reject exactly the configured forward or
    // reverse crossing, while partial matches remain ordinary forwarding.
    #[test]
    fn decide_ipv4_combined_realm_crossing_guards_are_directional() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: DMZ,
                mac: MacAddress([2, 0, 0, 0, 0, 3]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
            LocalIpv4Binding {
                interface: DMZ,
                address: PUBLIC2,
            },
        ];
        let targets = [
            Ipv4Address::from_octets([192, 0, 2, 101]),
            Ipv4Address::from_octets([192, 0, 2, 102]),
            Ipv4Address::from_octets([192, 0, 2, 103]),
            Ipv4Address::from_octets([192, 0, 2, 104]),
            Ipv4Address::from_octets([192, 0, 2, 105]),
            Ipv4Address::from_octets([192, 0, 2, 106]),
            Ipv4Address::from_octets([192, 0, 2, 107]),
            Ipv4Address::from_octets([192, 0, 2, 108]),
            Ipv4Address::from_octets([192, 0, 2, 109]),
            Ipv4Address::from_octets([192, 0, 2, 110]),
            Ipv4Address::from_octets([192, 0, 2, 111]),
            Ipv4Address::from_octets([192, 0, 2, 112]),
            Ipv4Address::from_octets([192, 0, 2, 113]),
            Ipv4Address::from_octets([192, 0, 2, 114]),
            Ipv4Address::from_octets([192, 0, 2, 115]),
        ];
        let egresses = [
            WAN, LAN, LAN, DMZ, DMZ, DMZ, LAN, DMZ, LAN, DMZ, WAN, LAN, DMZ, LAN, LAN,
        ];
        let routes: Vec<_> = targets
            .iter()
            .zip(egresses)
            .map(|(&target, egress)| Route::new(target, 32, egress, None).unwrap())
            .collect();
        let neighbors: Vec<_> = targets
            .iter()
            .zip(egresses)
            .map(|(&target, interface)| Neighbor {
                interface,
                target,
                mac: MacAddress([2, 0, 0, 0, 1, interface.0 as u8]),
            })
            .collect();
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            DMZ,
            PUBLIC2,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let run = |target, ingress, protocol| {
            let frame = ipv4_decision_frame(REMOTE, target, protocol, 64, 5);
            decide_ipv4_with_services(
                &frame,
                &snapshot,
                ingress,
                Some(&udp_config),
                Some(&tcp_config),
                None,
            )
        };

        assert!(matches!(
            run(targets[0], LAN, 17),
            Err(Nat44CombinedRealmMismatch)
        ));
        assert!(matches!(
            run(targets[1], WAN, 17),
            Err(Nat44CombinedRealmMismatch)
        ));
        assert!(matches!(
            run(targets[2], LAN, 17),
            Ok(super::PacketDecision::Ipv4(_))
        ));
        assert!(matches!(
            run(targets[3], LAN, 6),
            Err(Nat44CombinedRealmMismatch)
        ));
        assert!(matches!(
            run(targets[4], WAN, 17),
            Ok(super::PacketDecision::Ipv4(_))
        ));
        assert!(matches!(
            run(targets[5], DMZ, 6),
            Ok(super::PacketDecision::Ipv4(_))
        ));
        assert!(matches!(
            run(targets[14], DMZ, 6),
            Err(Nat44CombinedRealmMismatch)
        ));

        assert!(matches!(
            run(targets[6], WAN, 1),
            Err(Nat44ExternalToInternalBypass)
        ));
        assert!(matches!(
            run(targets[7], WAN, 1),
            Ok(super::PacketDecision::Ipv4(_))
        ));
        assert!(matches!(
            run(targets[8], DMZ, 1),
            Err(Nat44ExternalToInternalBypass)
        ));
        assert!(matches!(
            run(targets[9], DMZ, 1),
            Ok(super::PacketDecision::Ipv4(_))
        ));

        assert!(matches!(
            run(targets[10], LAN, 1),
            Err(Nat44UdpUnsupportedTransport)
        ));
        assert!(matches!(
            run(targets[11], LAN, 1),
            Ok(super::PacketDecision::Ipv4(_))
        ));
        assert!(matches!(
            run(targets[12], LAN, 1),
            Err(Nat44UdpUnsupportedTransport)
        ));
        assert!(matches!(
            run(targets[13], LAN, 1),
            Ok(super::PacketDecision::Ipv4(_))
        ));
    }

    // Contract: the TCP candidate observer runs exactly for an eligible TCP
    // packet, an inside ingress or public destination, a matching realm, and
    // a path without firewall preflight.
    #[test]
    fn decide_ipv4_tcp_candidate_observation_preserves_all_four_guards() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: DMZ,
                mac: MacAddress([2, 0, 0, 0, 0, 3]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
            LocalIpv4Binding {
                interface: DMZ,
                address: PUBLIC2,
            },
        ];
        let routes = [Route::new(REMOTE, 32, LAN, None).unwrap()];
        let neighbors = [crate::Neighbor {
            interface: LAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let mismatched_runtime_config = Nat44TcpConfig::new(
            &snapshot,
            DMZ,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();

        let inside_tcp = ipv4_decision_frame(REMOTE, REMOTE, 6, 64, 5);
        assert!(matches!(
            decide_ipv4_with_mismatched_tcp_runtime(
                &inside_tcp,
                &snapshot,
                LAN,
                None,
                &tcp_config,
                mismatched_runtime_config,
            ),
            Err(Nat44TcpConfigMismatch)
        ));

        // Contract: a TCP candidate requires either inside ingress or the
        // configured public destination; a wrong-ingress private destination
        // must not trigger candidate observation.
        assert!(matches!(
            decide_ipv4_with_mismatched_tcp_runtime(
                &inside_tcp,
                &snapshot,
                DMZ,
                None,
                &tcp_config,
                mismatched_runtime_config,
            ),
            Ok(super::PacketDecision::Ipv4(_))
        ));

        let public_route = [Route::new(PUBLIC, 32, LAN, None).unwrap()];
        let public_neighbor = [crate::Neighbor {
            interface: LAN,
            target: PUBLIC,
            mac: MacAddress([2, 0, 0, 0, 0, 21]),
        }];
        let public_snapshot =
            ForwardingSnapshot::new(&public_route, &interfaces, &public_neighbor, &bindings)
                .unwrap();
        let public_tcp = ipv4_decision_frame(REMOTE, PUBLIC, 6, 64, 5);
        assert!(matches!(
            decide_ipv4_with_mismatched_tcp_runtime(
                &public_tcp,
                &public_snapshot,
                DMZ,
                None,
                &tcp_config,
                mismatched_runtime_config,
            ),
            Err(Nat44TcpConfigMismatch)
        ));

        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            DMZ,
            PUBLIC2,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        assert!(matches!(
            decide_ipv4_with_mismatched_tcp_runtime(
                &inside_tcp,
                &snapshot,
                LAN,
                Some(&udp_config),
                &tcp_config,
                mismatched_runtime_config,
            ),
            Ok(super::PacketDecision::Ipv4(_))
        ));

        let udp_frame = ipv4_decision_frame(REMOTE, REMOTE, 17, 64, 5);
        assert!(matches!(
            decide_ipv4_with_mismatched_tcp_runtime(
                &udp_frame,
                &snapshot,
                LAN,
                None,
                &tcp_config,
                mismatched_runtime_config,
            ),
            Ok(super::PacketDecision::Ipv4(_))
        ));
    }

    // Contract: NAT hairpin detection distinguishes each supported transport
    // and never changes a wrong-ingress, unsupported, or runtime outcome.
    #[test]
    fn decide_ipv4_nat_hairpin_guards_distinguish_transport_and_configuration() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(PUBLIC, 32, WAN, None).unwrap()];
        let neighbors = [crate::Neighbor {
            interface: WAN,
            target: PUBLIC,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();

        let udp_frame = ipv4_decision_frame(REMOTE, PUBLIC, 17, 64, 5);
        assert!(matches!(
            decide_ipv4_with_services(&udp_frame, &snapshot, LAN, Some(&udp_config), None, None,),
            Err(Nat44UdpHairpinUnsupported)
        ));

        let tcp_frame = ipv4_decision_frame(REMOTE, PUBLIC, 6, 64, 5);
        assert!(matches!(
            decide_ipv4_with_services(
                &tcp_frame,
                &snapshot,
                LAN,
                Some(&udp_config),
                Some(&tcp_config),
                None,
            ),
            Err(Nat44TcpHairpinUnsupported)
        ));
        assert!(matches!(
            decide_ipv4_with_services(&tcp_frame, &snapshot, LAN, Some(&udp_config), None, None,),
            Err(Nat44UdpHairpinUnsupported)
        ));

        let unsupported_frame = ipv4_decision_frame(REMOTE, PUBLIC, 1, 64, 5);
        assert!(matches!(
            decide_ipv4_with_services(
                &unsupported_frame,
                &snapshot,
                LAN,
                None,
                Some(&tcp_config),
                None,
            ),
            Err(Nat44TcpUnsupportedTransport)
        ));
    }

    // Contract: with only TCP NAT configured, an inside UDP packet targeting
    // the TCP public address is rejected as an unsupported TCP hairpin before
    // the absent TCP runtime is required.
    #[test]
    fn decide_ipv4_tcp_hairpin_udp_without_udp_config_is_unsupported() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(PUBLIC, 32, WAN, None).unwrap()];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let frame = ipv4_decision_frame(REMOTE, PUBLIC, 17, 64, 5);

        assert!(matches!(
            decide_ipv4_with_services(&frame, &snapshot, LAN, None, Some(&tcp_config), None,),
            Err(Nat44TcpHairpinUnsupported)
        ));
    }

    // Contract: a connected route is resolution evidence only on the route's
    // selected egress; an otherwise identical route on another interface is
    // not sufficient authority.
    #[test]
    fn resolution_authority_rejects_connected_route_on_wrong_egress() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        }];
        let target = Ipv4Address::from_octets([198, 51, 100, 42]);
        let route = Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, LAN, None).unwrap();
        let routes = [route];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let action = ArpRequestAction {
            egress: WAN,
            source_mac: interfaces[1].mac,
            source_ip: PUBLIC,
            target_ip: target,
        };
        assert_eq!(
            snapshot.resolution_action_authority(action),
            ResolutionActionAuthority::Invalid
        );
    }

    // Contract: an address bound on the ingress interface is delivered
    // locally even when a route also contains the same address.
    #[test]
    fn decide_ipv4_local_target_requires_only_the_matching_local_binding() {
        let interfaces = [Interface {
            id: LAN,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let bindings = [LocalIpv4Binding {
            interface: LAN,
            address: REMOTE,
        }];
        let routes = [Route::new(REMOTE, 32, LAN, None).unwrap()];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let frame = ipv4_decision_frame(INTERNAL, REMOTE, 6, 64, 5);
        assert!(matches!(
            decide_ipv4_without_services(&frame, &snapshot, LAN),
            Ok(super::PacketDecision::ConsumeIpv4Local)
        ));
    }

    // Contract: NAT outbound selection requires the configured inside ingress,
    // configured outside egress, and the configured transport protocol.
    #[test]
    fn decide_ipv4_nat_outbound_guards_reject_wrong_path_and_protocol() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let route_on_lan = [Route::new(REMOTE, 32, LAN, None).unwrap()];
        let lan_neighbor = [Neighbor {
            interface: LAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&route_on_lan, &interfaces, &lan_neighbor, &bindings).unwrap();
        let udp = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();

        // Wrong UDP egress must remain ordinary forwarding.
        let udp_frame = ipv4_decision_frame(ROUTER, REMOTE, 17, 64, 5);
        let outbound_result =
            decide_ipv4_with_services(&udp_frame, &snapshot, LAN, Some(&udp), None, None);
        assert!(matches!(
            outbound_result,
            Ok(super::PacketDecision::Ipv4(_))
        ));

        // A TCP configuration must not claim a UDP packet through its
        // protocol fallback when the UDP service is absent.
        assert!(matches!(
            decide_ipv4_with_services(&udp_frame, &snapshot, LAN, None, Some(&tcp), None),
            Ok(super::PacketDecision::Ipv4(_))
        ));

        // Contract: a TCP packet crossing the UDP-only NAT realm is rejected
        // only when both the protocol and the configured path match.
        let tcp_crossing_frame = ipv4_decision_frame(ROUTER, REMOTE, 6, 64, 5);
        assert!(matches!(
            decide_ipv4_with_services(&tcp_crossing_frame, &snapshot, LAN, Some(&udp), None, None),
            Ok(super::PacketDecision::Ipv4(_))
        ));

        // Contract: a UDP packet crossing the TCP-only NAT realm is likewise
        // ordinary forwarding when the selected route is not the outside.
        let udp_crossing_frame = ipv4_decision_frame(ROUTER, REMOTE, 17, 64, 5);
        assert!(matches!(
            decide_ipv4_with_services(&udp_crossing_frame, &snapshot, LAN, None, Some(&tcp), None),
            Ok(super::PacketDecision::Ipv4(_))
        ));

        let route_on_wan = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let wan_neighbor = [Neighbor {
            interface: WAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 21]),
        }];
        let wan_snapshot =
            ForwardingSnapshot::new(&route_on_wan, &interfaces, &wan_neighbor, &bindings).unwrap();
        let tcp_wan = Nat44TcpConfig::new(
            &wan_snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let tcp_frame = ipv4_decision_frame(REMOTE, REMOTE, 6, 64, 5);

        // Wrong TCP ingress must not select outbound NAT.
        assert!(matches!(
            decide_ipv4_with_services(&tcp_frame, &wan_snapshot, WAN, None, Some(&tcp_wan), None),
            Ok(super::PacketDecision::Ipv4(_))
        ));

        // A matching TCP outbound path must require a runtime; changing the
        // protocol equality would incorrectly bypass this NAT decision.
        let outbound_frame = ipv4_decision_frame(ROUTER, REMOTE, 6, 64, 5);
        assert!(matches!(
            decide_ipv4_with_services(
                &outbound_frame,
                &wan_snapshot,
                LAN,
                None,
                Some(&tcp_wan),
                None,
            ),
            Err(Nat44TcpRuntimeUnavailable)
        ));
    }

    // Contract: on the exact inside-to-outside path, a TCP packet with only
    // UDP NAT configured must take the UDP fallback and report its missing
    // runtime, rather than being classified as unsupported crossing traffic.
    #[test]
    fn decide_ipv4_udp_nat_fallback_claims_tcp_on_exact_outbound_path() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let neighbors = [Neighbor {
            interface: WAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let frame = ipv4_decision_frame(ROUTER, REMOTE, 6, 64, 5);

        assert!(matches!(
            decide_ipv4_with_services(&frame, &snapshot, LAN, Some(&udp_config), None, None),
            Err(Nat44UdpRuntimeUnavailable)
        ));
    }

    // Contract: the UDP-only crossing guard requires the packet to enter on
    // the configured inside interface; an outside-ingress packet using the
    // outside egress remains ordinary forwarding.
    #[test]
    fn decide_ipv4_udp_only_crossing_requires_inside_ingress() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let neighbors = [Neighbor {
            interface: WAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let frame = ipv4_decision_frame(ROUTER, REMOTE, 6, 64, 5);

        assert!(matches!(
            decide_ipv4_with_services(&frame, &snapshot, WAN, Some(&udp_config), None, None),
            Ok(super::PacketDecision::Ipv4(_))
        ));
    }

    // Contract: the TCP-only crossing guard requires the packet to enter on
    // the configured inside interface; an outside-ingress UDP packet using
    // the outside egress remains ordinary forwarding.
    #[test]
    fn decide_ipv4_tcp_only_crossing_requires_inside_ingress() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let neighbors = [Neighbor {
            interface: WAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let frame = ipv4_decision_frame(ROUTER, REMOTE, 17, 64, 5);

        assert!(matches!(
            decide_ipv4_with_services(&frame, &snapshot, WAN, None, Some(&tcp_config), None),
            Ok(super::PacketDecision::Ipv4(_))
        ));
    }

    // Contract: a target owned by another interface is still local for ARP
    // scheduling; resolution must not enqueue a request for it.
    #[test]
    fn decide_ipv4_does_not_schedule_target_owned_on_egress_only() {
        let target = Ipv4Address::from_octets([192, 0, 2, 99]);
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: target,
        }];
        let routes = [Route::new(target, 32, WAN, None).unwrap()];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut states,
            &mut actions,
        );
        let frame = ipv4_decision_frame(INTERNAL, target, 6, 64, 5);
        let mut resolution = Some((&mut runtime, MonotonicMillis(0)));
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = None;
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let result = decide_ipv4(
            &frame,
            &snapshot,
            LAN,
            &mut resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            None,
            &mut nat44_tcp,
            None,
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        );
        assert!(matches!(result, Err(NeighborUnresolved)));
        assert_eq!(runtime.pending_actions(), 0);
    }

    // Contract: a configured firewall suppresses the TCP candidate observer
    // when no firewall runtime is supplied; the firewall guard is decisive.
    #[test]
    fn decide_ipv4_firewall_guard_precedes_tcp_candidate_observation() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: DMZ,
                mac: MacAddress([2, 0, 0, 0, 0, 3]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(REMOTE, 32, LAN, None).unwrap()];
        let neighbors = [Neighbor {
            interface: LAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let any_prefix = FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap();
        let any_ports = FirewallPortRange::new(1, u16::MAX).unwrap();
        let rules = [FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(LAN),
            any_prefix,
            any_prefix,
            FirewallProtocol::Tcp,
            any_ports,
            any_ports,
            FirewallAction::AllowStateful,
        )];
        let firewall_config = FirewallConfig::new(
            &snapshot,
            &rules,
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(1, 2).unwrap(),
        )
        .unwrap();
        let mut firewall_states = [FirewallStateSlot::default(); 1];
        let mut firewall_runtime = FirewallRuntime::new(firewall_config, &mut firewall_states);
        let runtime_config = Nat44TcpConfig::new(
            &snapshot,
            DMZ,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut mapping_buckets = [DirectoryBucket::default(); 1];
        let mut mapping_nodes = [DirectoryNode::default(); 1];
        let mut session_buckets = [DirectoryBucket::default(); 1];
        let mut session_nodes = [DirectoryNode::default(); 1];
        let mut owners = [PortOwnerSlot::default(); 1];
        let mut tcp_runtime = Nat44TcpRuntime::new(
            runtime_config,
            &mut mappings,
            &mut sessions,
            Nat44TcpIndexStorage::new(
                &mut mapping_buckets,
                &mut mapping_nodes,
                &mut session_buckets,
                &mut session_nodes,
                &mut owners,
            ),
            Nat44TcpHashKey::new(3, 4).unwrap(),
        )
        .unwrap();
        // The local destination bypasses firewall preflight, leaving the
        // TCP-candidate guard itself observable.
        let frame = ipv4_decision_frame(REMOTE, INTERNAL, 6, 64, 5);
        let mut resolution = None;
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = Some(&mut tcp_runtime);
        let mut firewall = Some(&mut firewall_runtime);
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let result = decide_ipv4(
            &frame,
            &snapshot,
            LAN,
            &mut resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            Some(&tcp_config),
            &mut nat44_tcp,
            Some(&firewall_config),
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        );
        assert!(matches!(
            result,
            Ok(super::PacketDecision::ConsumeIpv4Local)
        ));
    }

    fn decide_with_firewall_runtime(
        frame: &[u8],
        snapshot: &ForwardingSnapshot<'_>,
        ingress: IfId,
        udp_config: Option<&Nat44UdpConfig>,
        tcp_config: Option<&Nat44TcpConfig>,
        firewall_config: FirewallConfig<'_>,
    ) -> Result<super::PacketDecision, DropReason> {
        let mut states = [FirewallStateSlot::default(); 1];
        let mut runtime = FirewallRuntime::new(firewall_config, &mut states);
        let mut resolution = None;
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = Some(&mut runtime);
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        decide_ipv4(
            frame,
            snapshot,
            ingress,
            &mut resolution,
            &mut icmpv4_errors,
            udp_config,
            &mut nat44_udp,
            tcp_config,
            &mut nat44_tcp,
            Some(&firewall_config),
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        )
    }

    // Contract: firewall preflight must not turn a false NAT path guard into
    // a NAT runtime lookup; with TTL one, the original path reaches expiry.
    #[test]
    fn decide_ipv4_firewall_precheck_guards_ingress_and_tcp_path() {
        let any = FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap();
        let ports = FirewallPortRange::new(1, u16::MAX).unwrap();

        // UDP: ingress differs from inside (line 2321).
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let neighbor = [Neighbor {
            interface: WAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbor, &bindings).unwrap();
        let udp = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let udp_rule = [FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(WAN),
            FirewallInterface::Interface(WAN),
            any,
            any,
            FirewallProtocol::Udp,
            ports,
            ports,
            FirewallAction::AllowStateful,
        )];
        let firewall = FirewallConfig::new(
            &snapshot,
            &udp_rule,
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(5, 6).unwrap(),
        )
        .unwrap();
        let mut udp_frame = nat_inbound_ttl_frame(FirewallProtocol::Udp);
        udp_frame[26..30].copy_from_slice(&ROUTER.octets());
        udp_frame[30..34].copy_from_slice(&REMOTE.octets());
        udp_frame[40..42].fill(0);
        udp_frame[24..26].fill(0);
        let checksum = ipv4_header_checksum(&udp_frame[14..34]);
        udp_frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let precheck_result =
            decide_with_firewall_runtime(&udp_frame, &snapshot, WAN, Some(&udp), None, firewall);
        assert!(matches!(precheck_result, Err(Ipv4TtlExpired)));

        // TCP: the && guard must require both ingress and egress matches (line 2330).
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let neighbor = [Neighbor {
            interface: WAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbor, &bindings).unwrap();
        let tcp = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let tcp_rule = [FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(WAN),
            FirewallInterface::Interface(WAN),
            any,
            any,
            FirewallProtocol::Tcp,
            ports,
            ports,
            FirewallAction::AllowStateful,
        )];
        let firewall = FirewallConfig::new(
            &snapshot,
            &tcp_rule,
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(9, 10).unwrap(),
        )
        .unwrap();
        let mut tcp_frame = tcp_syn_frame();
        tcp_frame[26..30].copy_from_slice(&ROUTER.octets());
        tcp_frame[50..52].fill(0);
        let mut pseudo = Vec::with_capacity(32);
        pseudo.extend_from_slice(&ROUTER.octets());
        pseudo.extend_from_slice(&REMOTE.octets());
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&20_u16.to_be_bytes());
        pseudo.extend_from_slice(&tcp_frame[34..54]);
        let tcp_checksum = internet_checksum(&pseudo);
        tcp_frame[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());
        tcp_frame[22] = 1;
        tcp_frame[24..26].fill(0);
        let checksum = ipv4_header_checksum(&tcp_frame[14..34]);
        tcp_frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        assert!(matches!(
            decide_with_firewall_runtime(&tcp_frame, &snapshot, WAN, None, Some(&tcp), firewall),
            Err(Ipv4TtlExpired)
        ));
    }

    // Contract: a TCP-only firewall precheck is protocol-specific; a valid
    // UDP packet must reach the final TCP fallback after firewall planning.
    #[test]
    fn decide_ipv4_firewall_plan_precedes_tcp_udp_fallback_runtime_check() {
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let routes = [Route::new(REMOTE, 32, WAN, None).unwrap()];
        let neighbors = [Neighbor {
            interface: WAN,
            target: REMOTE,
            mac: MacAddress([2, 0, 0, 0, 0, 20]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let tcp = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            40_000,
            40_000,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let any_prefix = FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap();
        let any_ports = FirewallPortRange::new(1, u16::MAX).unwrap();
        let rules = [FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            any_prefix,
            any_prefix,
            FirewallProtocol::Udp,
            any_ports,
            any_ports,
            FirewallAction::AllowStateful,
        )];
        let firewall_config = FirewallConfig::new(
            &snapshot,
            &rules,
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(11, 12).unwrap(),
        )
        .unwrap();
        let mut firewall_states = [FirewallStateSlot::default(); 1];
        let mut firewall_runtime = FirewallRuntime::new(firewall_config, &mut firewall_states);
        let mut frame = nat_inbound_ttl_frame(FirewallProtocol::Udp);
        frame[26..30].copy_from_slice(&ROUTER.octets());
        frame[30..34].copy_from_slice(&REMOTE.octets());
        frame[40..42].fill(0);
        frame[22] = 64;
        frame[24..26].fill(0);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());

        let mut resolution = None;
        let mut icmpv4_errors = None;
        let mut nat44_udp = None;
        let mut nat44_tcp = None;
        let mut firewall = Some(&mut firewall_runtime);
        let mut firewall_audit = None;
        let mut firewall_plan = None;
        let result = decide_ipv4(
            &frame,
            &snapshot,
            LAN,
            &mut resolution,
            &mut icmpv4_errors,
            None,
            &mut nat44_udp,
            Some(&tcp),
            &mut nat44_tcp,
            Some(&firewall_config),
            &mut firewall,
            &mut firewall_audit,
            &mut firewall_plan,
            None,
            &mut NoTrace,
        );
        assert!(matches!(result, Err(Nat44TcpRuntimeUnavailable)));
        assert!(firewall_plan.is_some());
    }

    // The remaining mutation tests are kept in a child module so their
    // fixtures cannot accidentally become part of the production surface.
    mod rest_mutation_tests {
        use super::*;
        use crate::nat44::TestNat44UdpIndexes;
        use crate::{
            validate_ipv4_frame, ArpOpcode, ControlDisposition, Nat44TcpPolicy, Nat44UdpPolicy,
            Nat44UdpRuntime,
        };

        // These parser result types intentionally have no production-facing
        // Debug/PartialEq implementations.  The test-only adapters let the
        // assertions below compare their error sides without widening the
        // product API.
        impl std::fmt::Debug for super::super::ParsedNat44Icmpv4Quote {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("ParsedNat44Icmpv4Quote")
            }
        }

        impl PartialEq for super::super::ParsedNat44Icmpv4Quote {
            fn eq(&self, other: &Self) -> bool {
                self.protocol == other.protocol
                    && self.public_address == other.public_address
                    && self.public_port == other.public_port
                    && self.remote_address == other.remote_address
                    && self.remote_port == other.remote_port
                    && self.inner_checksum_offset == other.inner_checksum_offset
                    && self.inner_checksum == other.inner_checksum
                    && self.inner_source_offset == other.inner_source_offset
                    && self.inner_port_offset == other.inner_port_offset
                    && self.transport_checksum_offset == other.transport_checksum_offset
                    && self.transport_checksum == other.transport_checksum
                    && self.icmp_checksum_offset == other.icmp_checksum_offset
                    && self.icmp_checksum == other.icmp_checksum
            }
        }

        impl Eq for super::super::ParsedNat44Icmpv4Quote {}

        impl std::fmt::Debug for super::super::ValidatedFirewallTransport {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("ValidatedFirewallTransport")
            }
        }

        impl PartialEq for super::super::ValidatedFirewallTransport {
            fn eq(&self, other: &Self) -> bool {
                self.protocol == other.protocol
                    && self.source_port == other.source_port
                    && self.destination_port == other.destination_port
                    && self.tcp_flags == other.tcp_flags
            }
        }

        impl Eq for super::super::ValidatedFirewallTransport {}

        impl std::fmt::Debug for super::super::ValidatedNat44Udp {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("ValidatedNat44Udp")
            }
        }

        impl PartialEq for super::super::ValidatedNat44Udp {
            fn eq(&self, other: &Self) -> bool {
                self.offset == other.offset
                    && self.source_port == other.source_port
                    && self.destination_port == other.destination_port
                    && self.checksum == other.checksum
            }
        }

        impl Eq for super::super::ValidatedNat44Udp {}

        impl std::fmt::Debug for super::super::ValidatedNat44Tcp {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("ValidatedNat44Tcp")
            }
        }

        impl PartialEq for super::super::ValidatedNat44Tcp {
            fn eq(&self, other: &Self) -> bool {
                self.offset == other.offset
                    && self.source_port == other.source_port
                    && self.destination_port == other.destination_port
                    && self.checksum == other.checksum
                    && self.flags == other.flags
            }
        }

        impl Eq for super::super::ValidatedNat44Tcp {}

        fn synthetic_ipv4(
            protocol: u8,
            source: Ipv4Address,
            destination: Ipv4Address,
            total_len: usize,
        ) -> crate::packet::ValidatedIpv4 {
            crate::packet::ValidatedIpv4 {
                header_offset: 14,
                header_len: 20,
                total_len,
                ttl: 64,
                protocol,
                source,
                destination,
                checksum: 0x2345,
            }
        }

        fn forwarding_decision() -> super::super::Ipv4RewriteDecision {
            super::super::Ipv4RewriteDecision {
                egress: WAN,
                source_mac: [2, 0, 0, 0, 0, 2],
                destination_mac: [2, 0, 0, 0, 0, 20],
                ttl_offset: 22,
                checksum_offset: 24,
                checksum_end: 26,
                old_ttl_protocol: u16::from_be_bytes([64, 17]),
                new_ttl_protocol: u16::from_be_bytes([63, 17]),
                old_checksum: 0x1234,
            }
        }

        fn udp_frame_with_checksum(
            source: Ipv4Address,
            destination: Ipv4Address,
            source_port: u16,
            destination_port: u16,
            ip_total_len: usize,
            udp_len: usize,
            checksum: u16,
        ) -> Vec<u8> {
            let mut frame = vec![0_u8; (14 + ip_total_len).max(60)];
            frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
            frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 30]);
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
            frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
            frame[22] = 64;
            frame[23] = 17;
            frame[26..30].copy_from_slice(&source.octets());
            frame[30..34].copy_from_slice(&destination.octets());
            frame[34..36].copy_from_slice(&source_port.to_be_bytes());
            frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
            frame[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
            frame[40..42].copy_from_slice(&checksum.to_be_bytes());
            let checksum = ipv4_header_checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            frame
        }

        fn valid_udp_frame(
            source: Ipv4Address,
            destination: Ipv4Address,
            source_port: u16,
            destination_port: u16,
        ) -> Vec<u8> {
            let mut frame = udp_frame_with_checksum(
                source,
                destination,
                source_port,
                destination_port,
                28,
                8,
                0,
            );
            let mut pseudo = Vec::with_capacity(20);
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&8_u16.to_be_bytes());
            pseudo.extend_from_slice(&frame[34..42]);
            let checksum = internet_checksum(&pseudo);
            frame[40..42].copy_from_slice(&checksum.to_be_bytes());
            frame
        }

        fn tcp_frame_with_checksum(
            source: Ipv4Address,
            destination: Ipv4Address,
            source_port: u16,
            destination_port: u16,
            ip_total_len: usize,
            data_offset_words: u8,
            checksum_override: Option<u16>,
        ) -> Vec<u8> {
            let mut frame = vec![0_u8; (14 + ip_total_len).max(60)];
            frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
            frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 30]);
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
            frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
            frame[22] = 64;
            frame[23] = 6;
            frame[26..30].copy_from_slice(&source.octets());
            frame[30..34].copy_from_slice(&destination.octets());
            frame[34..36].copy_from_slice(&source_port.to_be_bytes());
            frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
            frame[46] = data_offset_words << 4;
            frame[47] = 0x02;
            frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
            let segment_len = ip_total_len.saturating_sub(20);
            let checksum = checksum_override.unwrap_or_else(|| {
                let mut pseudo = Vec::with_capacity(12 + segment_len);
                pseudo.extend_from_slice(&source.octets());
                pseudo.extend_from_slice(&destination.octets());
                pseudo.extend_from_slice(&[0, 6]);
                pseudo.extend_from_slice(&(segment_len as u16).to_be_bytes());
                pseudo.extend_from_slice(&frame[34..34 + segment_len]);
                internet_checksum(&pseudo)
            });
            frame[50..52].copy_from_slice(&checksum.to_be_bytes());
            let checksum = ipv4_header_checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            frame
        }

        fn frag_needed_frame_with_quote(
            protocol: u8,
            inner_ihl_words: u8,
            inner_total_len: usize,
        ) -> Vec<u8> {
            let outer_total_len = 20 + 8 + inner_total_len;
            let mut frame = vec![0_u8; 14 + outer_total_len];
            frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
            frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 3]);
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&(outer_total_len as u16).to_be_bytes());
            frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
            frame[22] = 64;
            frame[23] = 1;
            frame[26..30].copy_from_slice(&ROUTER.octets());
            frame[30..34].copy_from_slice(&PUBLIC.octets());
            frame[34..36].copy_from_slice(&[3, 4]);
            let quote_offset = 42;
            let inner_header_len = usize::from(inner_ihl_words) * 4;
            frame[quote_offset] = (4 << 4) | inner_ihl_words;
            frame[quote_offset + 2..quote_offset + 4]
                .copy_from_slice(&(inner_total_len as u16).to_be_bytes());
            frame[quote_offset + 6..quote_offset + 8].copy_from_slice(&0x4000_u16.to_be_bytes());
            frame[quote_offset + 8] = 64;
            frame[quote_offset + 9] = protocol;
            if inner_header_len >= 20 {
                frame[quote_offset + 12..quote_offset + 16].copy_from_slice(&PUBLIC.octets());
                frame[quote_offset + 16..quote_offset + 20].copy_from_slice(&REMOTE.octets());
                let checksum =
                    ipv4_header_checksum(&frame[quote_offset..quote_offset + inner_header_len]);
                frame[quote_offset + 10..quote_offset + 12]
                    .copy_from_slice(&checksum.to_be_bytes());
            }
            let transport_offset = quote_offset + inner_header_len;
            frame[transport_offset..transport_offset + 2]
                .copy_from_slice(&40_000_u16.to_be_bytes());
            frame[transport_offset + 2..transport_offset + 4]
                .copy_from_slice(&53_u16.to_be_bytes());
            if protocol == 17 && inner_total_len >= inner_header_len + 8 {
                frame[transport_offset + 4..transport_offset + 6]
                    .copy_from_slice(&8_u16.to_be_bytes());
                frame[transport_offset + 6..transport_offset + 8]
                    .copy_from_slice(&0x1111_u16.to_be_bytes());
            } else if protocol == 6 && inner_total_len >= inner_header_len + 18 {
                frame[transport_offset + 16..transport_offset + 18]
                    .copy_from_slice(&0x2222_u16.to_be_bytes());
            }
            let checksum = internet_checksum(&frame[34..14 + outer_total_len]);
            frame[36..38].copy_from_slice(&checksum.to_be_bytes());
            let checksum = ipv4_header_checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            frame
        }

        fn parsed_quote(
            protocol: u8,
            transport_checksum: Option<u16>,
        ) -> super::super::ParsedNat44Icmpv4Quote {
            super::super::ParsedNat44Icmpv4Quote {
                protocol,
                public_address: PUBLIC,
                public_port: 40_000,
                remote_address: REMOTE,
                remote_port: 53,
                inner_checksum_offset: 52,
                inner_checksum: 0x1111,
                inner_source_offset: 54,
                inner_port_offset: 62,
                transport_checksum_offset: transport_checksum.map(|_| 68),
                transport_checksum,
                icmp_checksum_offset: 36,
                icmp_checksum: 0x3333,
            }
        }

        fn with_nat_configs<T>(
            test: impl FnOnce(&ForwardingSnapshot<'_>, Nat44UdpConfig, Nat44TcpConfig) -> T,
        ) -> T {
            let routes = [
                Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
                Route::new(ROUTER, 32, WAN, None).unwrap(),
            ];
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [
                LocalIpv4Binding {
                    interface: LAN,
                    address: INTERNAL,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: PUBLIC,
                },
            ];
            let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
            let udp = Nat44UdpConfig::new(
                &snapshot,
                LAN,
                WAN,
                PUBLIC,
                40_000,
                40_001,
                Nat44UdpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
            )
            .unwrap();
            let tcp = Nat44TcpConfig::new(
                &snapshot,
                LAN,
                WAN,
                PUBLIC,
                40_000,
                40_001,
                Nat44TcpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
            )
            .unwrap();
            test(&snapshot, udp, tcp)
        }

        fn with_udp_runtime<T>(
            test: impl FnOnce(&ForwardingSnapshot<'_>, Nat44UdpConfig, &mut Nat44UdpRuntime<'_>) -> T,
        ) -> T {
            let routes = [
                Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
                Route::new(ROUTER, 32, WAN, None).unwrap(),
            ];
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [
                LocalIpv4Binding {
                    interface: LAN,
                    address: INTERNAL,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: PUBLIC,
                },
            ];
            let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
            let config = Nat44UdpConfig::new(
                &snapshot,
                LAN,
                WAN,
                PUBLIC,
                40_000,
                40_001,
                Nat44UdpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
            )
            .unwrap();
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut indexes = TestNat44UdpIndexes::new(config, 1, 1);
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            test(&snapshot, config, &mut runtime)
        }

        fn with_tcp_runtime<T>(
            test: impl FnOnce(&ForwardingSnapshot<'_>, Nat44TcpConfig, &mut Nat44TcpRuntime<'_>) -> T,
        ) -> T {
            let routes = [
                Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
                Route::new(ROUTER, 32, WAN, None).unwrap(),
            ];
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [
                LocalIpv4Binding {
                    interface: LAN,
                    address: INTERNAL,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: PUBLIC,
                },
            ];
            let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
            let config = Nat44TcpConfig::new(
                &snapshot,
                LAN,
                WAN,
                PUBLIC,
                40_000,
                40_001,
                Nat44TcpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
            )
            .unwrap();
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut mapping_buckets = [DirectoryBucket::default(); 1];
            let mut mapping_nodes = [DirectoryNode::default(); 1];
            let mut session_buckets = [DirectoryBucket::default(); 1];
            let mut session_nodes = [DirectoryNode::default(); 1];
            let mut owners = [PortOwnerSlot::default(); 2];
            let indexes = Nat44TcpIndexStorage::new(
                &mut mapping_buckets,
                &mut mapping_nodes,
                &mut session_buckets,
                &mut session_nodes,
                &mut owners,
            );
            let mut runtime = Nat44TcpRuntime::new(
                config,
                &mut mappings,
                &mut sessions,
                indexes,
                Nat44TcpHashKey::new(1, 2).unwrap(),
            )
            .unwrap();
            test(&snapshot, config, &mut runtime)
        }

        fn standard_nat_routes() -> [Route; 2] {
            [
                Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
                Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(ROUTER)).unwrap(),
            ]
        }

        fn with_udp_runtime_on<T>(
            routes: &[Route],
            neighbors: &[Neighbor],
            test: impl FnOnce(&ForwardingSnapshot<'_>, Nat44UdpConfig, &mut Nat44UdpRuntime<'_>) -> T,
        ) -> T {
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [
                LocalIpv4Binding {
                    interface: LAN,
                    address: INTERNAL,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: PUBLIC,
                },
            ];
            let snapshot =
                ForwardingSnapshot::new(routes, &interfaces, neighbors, &bindings).unwrap();
            let config = Nat44UdpConfig::new(
                &snapshot,
                LAN,
                WAN,
                PUBLIC,
                40_000,
                40_001,
                Nat44UdpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
            )
            .unwrap();
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut indexes = TestNat44UdpIndexes::new(config, 1, 1);
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            test(&snapshot, config, &mut runtime)
        }

        fn with_tcp_runtime_on<T>(
            routes: &[Route],
            neighbors: &[Neighbor],
            test: impl FnOnce(&ForwardingSnapshot<'_>, Nat44TcpConfig, &mut Nat44TcpRuntime<'_>) -> T,
        ) -> T {
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [
                LocalIpv4Binding {
                    interface: LAN,
                    address: INTERNAL,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: PUBLIC,
                },
            ];
            let snapshot =
                ForwardingSnapshot::new(routes, &interfaces, neighbors, &bindings).unwrap();
            let config = Nat44TcpConfig::new(
                &snapshot,
                LAN,
                WAN,
                PUBLIC,
                40_000,
                40_001,
                Nat44TcpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
            )
            .unwrap();
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut mapping_buckets = [DirectoryBucket::default(); 1];
            let mut mapping_nodes = [DirectoryNode::default(); 1];
            let mut session_buckets = [DirectoryBucket::default(); 1];
            let mut session_nodes = [DirectoryNode::default(); 1];
            let mut owners = [PortOwnerSlot::default(); 2];
            let indexes = Nat44TcpIndexStorage::new(
                &mut mapping_buckets,
                &mut mapping_nodes,
                &mut session_buckets,
                &mut session_nodes,
                &mut owners,
            );
            let mut runtime = Nat44TcpRuntime::new(
                config,
                &mut mappings,
                &mut sessions,
                indexes,
                Nat44TcpHashKey::new(1, 2).unwrap(),
            )
            .unwrap();
            test(&snapshot, config, &mut runtime)
        }

        fn seed_udp_mapping(
            runtime: &mut Nat44UdpRuntime<'_>,
            internal_address: Ipv4Address,
            remote_address: Ipv4Address,
        ) {
            let plan = runtime
                .plan_outbound(internal_address, 12_345, remote_address, 0)
                .unwrap();
            assert_eq!(plan.public_port(), 40_000);
            runtime.commit_outbound(plan, 0).unwrap();
        }

        fn seed_tcp_mapping(
            runtime: &mut Nat44TcpRuntime<'_>,
            internal_address: Ipv4Address,
            remote_address: Ipv4Address,
            remote_port: u16,
        ) {
            let plan = runtime
                .plan_outbound(
                    internal_address,
                    12_345,
                    remote_address,
                    remote_port,
                    true,
                    0,
                )
                .unwrap();
            assert_eq!(plan.public_port(), 40_000);
            runtime.commit_outbound(plan, 0).unwrap();
        }

        fn decide_frag_udp(
            frame: &[u8],
            snapshot: &ForwardingSnapshot<'_>,
            config: &Nat44UdpConfig,
            runtime: &mut Nat44UdpRuntime<'_>,
            outer: crate::packet::ValidatedIpv4,
            resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
        ) -> Result<super::super::PacketDecision, DropReason> {
            let mut nat44_udp = Some(runtime);
            let mut nat44_tcp = None;
            let mut firewall_audit = None;
            super::super::decide_nat44_icmpv4_frag_needed(
                frame,
                snapshot,
                WAN,
                outer,
                resolution,
                Some(config),
                &mut nat44_udp,
                None,
                &mut nat44_tcp,
                MonotonicMillis(0),
                false,
                None,
                &mut firewall_audit,
                &mut NoTrace,
            )
        }

        fn decide_frag_tcp(
            frame: &[u8],
            snapshot: &ForwardingSnapshot<'_>,
            config: &Nat44TcpConfig,
            runtime: &mut Nat44TcpRuntime<'_>,
            outer: crate::packet::ValidatedIpv4,
            resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
        ) -> Result<super::super::PacketDecision, DropReason> {
            let mut nat44_udp = None;
            let mut nat44_tcp = Some(runtime);
            let mut firewall_audit = None;
            super::super::decide_nat44_icmpv4_frag_needed(
                frame,
                snapshot,
                WAN,
                outer,
                resolution,
                None,
                &mut nat44_udp,
                Some(config),
                &mut nat44_tcp,
                MonotonicMillis(0),
                false,
                None,
                &mut firewall_audit,
                &mut NoTrace,
            )
        }

        fn decide_udp_outbound(
            frame: &[u8],
            snapshot: &ForwardingSnapshot<'_>,
            config: &Nat44UdpConfig,
            runtime: &mut Nat44UdpRuntime<'_>,
            ipv4: crate::packet::ValidatedIpv4,
        ) -> Result<super::super::PacketDecision, DropReason> {
            let mut nat44_udp = Some(runtime);
            super::super::decide_nat44_udp_outbound(
                frame,
                snapshot,
                LAN,
                ipv4,
                forwarding_decision(),
                config,
                &mut nat44_udp,
                false,
                MonotonicMillis(0),
                &mut NoTrace,
            )
        }

        fn tcp_forwarding_decision() -> super::super::Ipv4RewriteDecision {
            super::super::Ipv4RewriteDecision {
                old_ttl_protocol: u16::from_be_bytes([64, 6]),
                new_ttl_protocol: u16::from_be_bytes([63, 6]),
                ..forwarding_decision()
            }
        }

        fn decide_tcp_outbound(
            frame: &[u8],
            snapshot: &ForwardingSnapshot<'_>,
            config: &Nat44TcpConfig,
            runtime: &mut Nat44TcpRuntime<'_>,
            ipv4: crate::packet::ValidatedIpv4,
        ) -> Result<super::super::PacketDecision, DropReason> {
            let mut nat44_tcp = Some(runtime);
            super::super::decide_nat44_tcp_outbound(
                frame,
                snapshot,
                LAN,
                ipv4,
                tcp_forwarding_decision(),
                config,
                &mut nat44_tcp,
                false,
                MonotonicMillis(0),
                &mut NoTrace,
            )
        }

        fn decide_udp_inbound(
            frame: &[u8],
            snapshot: &ForwardingSnapshot<'_>,
            config: &Nat44UdpConfig,
            runtime: &mut Nat44UdpRuntime<'_>,
            ipv4: crate::packet::ValidatedIpv4,
            resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
        ) -> Result<super::super::PacketDecision, DropReason> {
            let mut icmpv4_errors = None;
            let mut nat44_udp = Some(runtime);
            let mut firewall = None;
            let mut firewall_audit = None;
            let mut firewall_plan = None;
            super::super::decide_nat44_udp_inbound(
                frame,
                snapshot,
                WAN,
                ipv4,
                None,
                resolution,
                &mut icmpv4_errors,
                config,
                &mut nat44_udp,
                None,
                &mut firewall,
                &mut firewall_audit,
                None,
                &mut firewall_plan,
                &mut NoTrace,
            )
        }

        fn decide_tcp_inbound(
            frame: &[u8],
            snapshot: &ForwardingSnapshot<'_>,
            config: &Nat44TcpConfig,
            runtime: &mut Nat44TcpRuntime<'_>,
            ipv4: crate::packet::ValidatedIpv4,
            resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
        ) -> Result<super::super::PacketDecision, DropReason> {
            let mut icmpv4_errors = None;
            let mut nat44_tcp = Some(runtime);
            let mut firewall = None;
            let mut firewall_audit = None;
            let mut firewall_plan = None;
            super::super::decide_nat44_tcp_inbound(
                frame,
                snapshot,
                WAN,
                ipv4,
                None,
                resolution,
                &mut icmpv4_errors,
                config,
                &mut nat44_tcp,
                None,
                &mut firewall,
                &mut firewall_audit,
                None,
                &mut firewall_plan,
                &mut NoTrace,
            )
        }

        fn set_outer_source(frame: &mut [u8], source: Ipv4Address) {
            frame[26..30].copy_from_slice(&source.octets());
            frame[24..26].fill(0);
            let checksum = ipv4_header_checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        }

        fn set_quoted_source(frame: &mut [u8], source: Ipv4Address) {
            frame[54..58].copy_from_slice(&source.octets());
            frame[52..54].fill(0);
            let inner_checksum = ipv4_header_checksum(&frame[42..62]);
            frame[52..54].copy_from_slice(&inner_checksum.to_be_bytes());
            frame[36..38].fill(0);
            let icmp_end = usize::from(u16::from_be_bytes([frame[16], frame[17]])) + 14;
            let icmp_checksum = internet_checksum(&frame[34..icmp_end]);
            frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
        }

        fn with_snapshot<T>(
            routes: &[Route],
            interfaces: &[Interface],
            neighbors: &[Neighbor],
            bindings: &[LocalIpv4Binding],
            test: impl FnOnce(&ForwardingSnapshot<'_>) -> T,
        ) -> T {
            let snapshot =
                ForwardingSnapshot::new(routes, interfaces, neighbors, bindings).unwrap();
            test(&snapshot)
        }

        fn with_icmp_error_runtime<T>(test: impl FnOnce(&mut Icmpv4ErrorRuntime<'_>) -> T) -> T {
            let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
            let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
            let mut runtime =
                Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
            test(&mut runtime)
        }

        fn with_resolution_runtime<T>(test: impl FnOnce(&mut ResolutionRuntime<'_>) -> T) -> T {
            let mut states = [ResolutionStateSlot::EMPTY; 1];
            let mut actions = [ResolutionActionSlot::EMPTY; 1];
            let mut runtime = ResolutionRuntime::new(
                ResolutionPolicy::new(1_000, 2_000).unwrap(),
                &mut states,
                &mut actions,
            );
            test(&mut runtime)
        }

        fn generic_error_frame(
            source: Ipv4Address,
            destination: Ipv4Address,
            protocol: u8,
        ) -> Vec<u8> {
            let mut frame = empty_ipv4_icmp_frame(64, destination);
            frame[23] = protocol;
            frame[26..30].copy_from_slice(&source.octets());
            frame[24..26].fill(0);
            let checksum = ipv4_header_checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            frame
        }

        fn echo_request_frame(source: Ipv4Address, destination: Ipv4Address) -> Vec<u8> {
            let mut frame = zero_identifier_echo_request();
            frame[26..30].copy_from_slice(&source.octets());
            frame[30..34].copy_from_slice(&destination.octets());
            frame[24..26].fill(0);
            let checksum = ipv4_header_checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            frame
        }

        fn candidate_eligible(
            frame: &[u8],
            snapshot: &ForwardingSnapshot<'_>,
            selected_destination_route: Option<Route>,
        ) -> bool {
            let ipv4 = validate_ipv4_frame(frame).unwrap();
            super::super::icmp_error_candidate_eligible(
                frame,
                snapshot,
                ipv4,
                selected_destination_route,
            )
        }

        fn arp_frame(
            opcode: ArpOpcode,
            sender_hardware: [u8; 6],
            sender_protocol: Ipv4Address,
            target_protocol: Ipv4Address,
        ) -> Vec<u8> {
            let mut frame = vec![0_u8; 60];
            frame[0..6].copy_from_slice(&[0xff; 6]);
            frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
            frame[12..14].copy_from_slice(&ARP_ETHERTYPE.to_be_bytes());
            frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
            frame[16..18].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
            frame[18] = 6;
            frame[19] = 4;
            frame[20..22].copy_from_slice(
                &(match opcode {
                    ArpOpcode::Request => 1_u16,
                    ArpOpcode::Reply => 2_u16,
                })
                .to_be_bytes(),
            );
            frame[22..28].copy_from_slice(&sender_hardware);
            frame[28..32].copy_from_slice(&sender_protocol.octets());
            frame[32..38].fill(0);
            frame[38..42].copy_from_slice(&target_protocol.octets());
            frame
        }

        fn decide_arp_without_runtime(
            frame: &[u8],
            snapshot: &ForwardingSnapshot<'_>,
            ingress: IfId,
        ) -> Result<super::super::PacketDecision, DropReason> {
            let mut resolution = None;
            let mut trace = NoTrace;
            super::super::decide_arp(frame, snapshot, ingress, &mut resolution, &mut trace)
        }

        fn arp_disposition(
            result: Result<super::super::PacketDecision, DropReason>,
        ) -> ControlDisposition {
            match result {
                Ok(super::super::PacketDecision::ConsumeArp(disposition)) => disposition,
                _ => panic!("expected a consumed ARP decision"),
            }
        }

        #[test]
        fn rest_is_nat44_icmpv4_candidate_guards_type_policy_and_quote_bounds() {
            with_nat_configs(|_snapshot, udp, tcp| {
                let frame = frag_needed_frame_with_quote(17, 5, 28);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                // Contract: RFC 5508 REQ-3 carries an ICMP error whose quoted
                // packet matches a mapping. Destination Unreachable of any
                // code, Time Exceeded and Parameter Problem all report on a
                // datagram this router forwarded, so all three reach NAT error
                // translation.
                for (icmp_type, code) in [(3_u8, 0_u8), (3, 1), (3, 3), (11, 0), (12, 0)] {
                    let mut carried = frame.clone();
                    carried[34] = icmp_type;
                    carried[35] = code;
                    assert!(
                        super::super::is_nat44_icmpv4_candidate(
                            &carried,
                            ipv4,
                            Some(&udp),
                            Some(&tcp),
                        ),
                        "type {icmp_type} code {code} must reach NAT translation"
                    );
                }
                // Redirect names a better first hop on the link it arrived
                // from, which means nothing across a NAT and would let an
                // outside station steer an inside host. Source Quench is
                // deprecated by RFC 6633. Echo is not an error at all.
                for icmp_type in [0_u8, 4, 5, 8, 13] {
                    let mut refused = frame.clone();
                    refused[34] = icmp_type;
                    refused[35] = 0;
                    assert!(
                        !super::super::is_nat44_icmpv4_candidate(
                            &refused,
                            ipv4,
                            Some(&udp),
                            Some(&tcp),
                        ),
                        "type {icmp_type} must not reach NAT translation"
                    );
                }
                // Contract: ExternalOnly and the configured public address are
                // both required independently for UDP and TCP (2554/2558).
                let disabled = Nat44UdpConfig::new(
                    _snapshot,
                    LAN,
                    WAN,
                    PUBLIC,
                    40_000,
                    40_001,
                    Nat44UdpPolicy::default(),
                )
                .unwrap();
                assert!(!super::super::is_nat44_icmpv4_candidate(
                    &frame,
                    ipv4,
                    Some(&disabled),
                    None,
                ));
                let wrong_destination = synthetic_ipv4(1, ROUTER, PUBLIC2, ipv4.total_len);
                assert!(!super::super::is_nat44_icmpv4_candidate(
                    &frame,
                    wrong_destination,
                    Some(&udp),
                    None,
                ));
                // Contract: a quoted UDP/TCP protocol selects only its matching
                // enabled translator; an unknown quote uses either translator.
                let tcp_quote = frag_needed_frame_with_quote(6, 5, 40);
                let tcp_ipv4 = validate_ipv4_frame(&tcp_quote).unwrap();
                assert!(!super::super::is_nat44_icmpv4_candidate(
                    &tcp_quote,
                    tcp_ipv4,
                    Some(&udp),
                    None,
                ));
                let mut unknown = frame.clone();
                unknown[51] = 99;
                assert!(super::super::is_nat44_icmpv4_candidate(
                    &unknown,
                    ipv4,
                    Some(&udp),
                    None,
                ));
                // Contract: a quote protocol exactly at IPv4 end is absent,
                // even when Ethernet padding contains a plausible byte (2562).
                let mut at_end = frame.clone();
                at_end[16..18].copy_from_slice(&37_u16.to_be_bytes());
                at_end[51] = 17;
                at_end[24..26].fill(0);
                let checksum = ipv4_header_checksum(&at_end[14..34]);
                at_end[24..26].copy_from_slice(&checksum.to_be_bytes());
                let at_end_ipv4 = validate_ipv4_frame(&at_end[..51]).unwrap();
                assert!(super::super::is_nat44_icmpv4_candidate(
                    &at_end,
                    at_end_ipv4,
                    None,
                    Some(&tcp),
                ));
            });
        }

        #[test]
        fn rest_is_nat44_icmpv4_candidate_requires_tcp_policy_and_public_destination() {
            with_nat_configs(|snapshot, _udp, enabled_tcp| {
                let tcp_frame = frag_needed_frame_with_quote(6, 5, 40);
                let tcp_ipv4 = validate_ipv4_frame(&tcp_frame).unwrap();
                let disabled_tcp = Nat44TcpConfig::new(
                    snapshot,
                    LAN,
                    WAN,
                    PUBLIC,
                    40_000,
                    40_001,
                    Nat44TcpPolicy::default(),
                )
                .unwrap();

                // Contract: a TCP ICMP candidate needs ExternalOnly even when
                // the outer destination is PUBLIC (mutant #5, policy `&&`).
                assert!(!super::super::is_nat44_icmpv4_candidate(
                    &tcp_frame,
                    tcp_ipv4,
                    None,
                    Some(&disabled_tcp),
                ));

                let mut nonpublic_frame = tcp_frame;
                nonpublic_frame[30..34].copy_from_slice(&PUBLIC2.octets());
                nonpublic_frame[24..26].fill(0);
                let checksum = ipv4_header_checksum(&nonpublic_frame[14..34]);
                nonpublic_frame[24..26].copy_from_slice(&checksum.to_be_bytes());
                let nonpublic_ipv4 = validate_ipv4_frame(&nonpublic_frame).unwrap();

                // Contract: ExternalOnly is insufficient when the outer
                // destination is not the configured PUBLIC address (mutant
                // #5, destination `&&`).
                assert!(!super::super::is_nat44_icmpv4_candidate(
                    &nonpublic_frame,
                    nonpublic_ipv4,
                    None,
                    Some(&enabled_tcp),
                ));
            });
        }

        #[test]
        fn rest_is_nat44_icmpv4_candidate_accepts_type_code_at_ipv4_end() {
            with_nat_configs(|_snapshot, udp, _tcp| {
                let mut frame = vec![0_u8; 60];
                // Contract: the Fragmentation Needed type/code may end
                // exactly at IPv4 Total Length; Ethernet padding must not
                // turn this valid boundary into a rejection (2547 `>`,
                // mutant 2).
                frame[34..36].copy_from_slice(&[3, 4]);
                let ipv4 = synthetic_ipv4(1, REMOTE, PUBLIC, 22);
                assert!(super::super::is_nat44_icmpv4_candidate(
                    &frame,
                    ipv4,
                    Some(&udp),
                    None,
                ));
            });
        }

        #[test]
        fn rest_is_nat44_icmpv4_candidate_accepts_explicit_equal_type_code_end() {
            with_nat_configs(|_snapshot, udp, _tcp| {
                let ipv4 = synthetic_ipv4(1, REMOTE, PUBLIC, 22);
                let icmp_offset = ipv4.header_offset + ipv4.header_len;
                let ipv4_end = ipv4.header_offset + ipv4.total_len;
                let type_code_end = icmp_offset + 2;
                let mut frame = vec![0_u8; 60];
                frame[icmp_offset..type_code_end].copy_from_slice(&[3, 4]);

                // Contract: this fixture places the type/code end exactly at
                // IPv4 Total Length while retaining Ethernet padding, so the
                // strict `>` guard must accept it (2547, mutant 3).
                assert_eq!(type_code_end, ipv4_end);
                assert!(frame.len() > ipv4_end);
                assert!(super::super::is_nat44_icmpv4_candidate(
                    &frame,
                    ipv4,
                    Some(&udp),
                    None,
                ));
            });
        }

        #[test]
        fn rest_parse_nat44_icmpv4_frag_needed_checks_exact_lengths_and_protocols() {
            // Contract: an exactly eight-byte ICMP header is valid enough to
            // reach quote parsing, and is not itself header-truncated (2902).
            let mut exact = vec![0_u8; 42];
            exact[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            exact[14] = 0x45;
            exact[16..18].copy_from_slice(&28_u16.to_be_bytes());
            exact[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
            exact[22] = 64;
            exact[23] = 1;
            exact[26..30].copy_from_slice(&ROUTER.octets());
            exact[30..34].copy_from_slice(&PUBLIC.octets());
            exact[34..36].copy_from_slice(&[3, 4]);
            let icmp_checksum = internet_checksum(&exact[34..42]);
            exact[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
            let outer_checksum = ipv4_header_checksum(&exact[14..34]);
            exact[24..26].copy_from_slice(&outer_checksum.to_be_bytes());
            let outer = validate_ipv4_frame(&exact).unwrap();
            assert_eq!(
                super::super::parse_nat44_icmpv4_frag_needed(&exact, outer),
                Err(Nat44Icmpv4QuoteTruncated)
            );

            // Contract: an IPv4 quote must have IHL >= 5 (2919).
            let bad_ihl = frag_needed_frame_with_quote(17, 4, 24);
            let bad_ihl_outer = validate_ipv4_frame(&bad_ihl).unwrap();
            assert_eq!(
                super::super::parse_nat44_icmpv4_frag_needed(&bad_ihl, bad_ihl_outer),
                Err(Nat44Icmpv4QuotedIhlTooSmall)
            );

            // Contract: UDP quotes retain their checksum field, while a full
            // TCP quote retains its checksum and a 17-byte TCP quote is partial
            // (2963/2970).
            let udp = frag_needed_frame_with_quote(17, 5, 28);
            let udp_outer = validate_ipv4_frame(&udp).unwrap();
            let parsed = super::super::parse_nat44_icmpv4_frag_needed(&udp, udp_outer).unwrap();
            assert_eq!(parsed.transport_checksum, Some(0x1111));
            let tcp = frag_needed_frame_with_quote(6, 5, 40);
            let tcp_outer = validate_ipv4_frame(&tcp).unwrap();
            let parsed = super::super::parse_nat44_icmpv4_frag_needed(&tcp, tcp_outer).unwrap();
            assert_eq!(parsed.transport_checksum, Some(0x2222));
            let partial = frag_needed_frame_with_quote(6, 5, 37);
            let partial_outer = validate_ipv4_frame(&partial).unwrap();
            assert_eq!(
                super::super::parse_nat44_icmpv4_frag_needed(&partial, partial_outer),
                Err(Nat44Icmpv4TcpChecksumPartial)
            );
        }

        #[test]
        fn rest_build_nat44_icmpv4_rewrite_preserves_checksum_zero_rules() {
            let outer = synthetic_ipv4(1, ROUTER, PUBLIC, 56);
            let tcp_zero = parsed_quote(6, Some(0));
            // Contract: TCP checksum zero is still updated; only UDP's zero
            // checksum is exempt from address/port rewriting (3023).
            let decision = super::super::build_nat44_icmpv4_rewrite(
                outer,
                tcp_zero,
                LAN,
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 10],
                INTERNAL,
                12_345,
            )
            .unwrap();
            let super::super::PacketDecision::Nat44Icmpv4(decision) = decision else {
                panic!("expected ICMP NAT rewrite");
            };
            let expected_transport = crate::rfc1624_update(
                crate::rfc1624_update(crate::rfc1624_update(0, 0xcb00, 0x0a00), 0x710a, 0x000a),
                40_000,
                12_345,
            );
            assert_eq!(decision.transport_checksum, Some(expected_transport));
            assert_ne!(expected_transport, 0);

            let udp_normal = parsed_quote(17, Some(0x1234));
            // Contract: UDP's normal checksum update returns the computed
            // value unless it is mathematical zero (3035).
            let decision = super::super::build_nat44_icmpv4_rewrite(
                outer,
                udp_normal,
                LAN,
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 10],
                INTERNAL,
                12_345,
            )
            .unwrap();
            let super::super::PacketDecision::Nat44Icmpv4(decision) = decision else {
                panic!("expected ICMP NAT rewrite");
            };
            let expected_transport = crate::rfc1624_update(
                crate::rfc1624_update(
                    crate::rfc1624_update(0x1234, 0xcb00, 0x0a00),
                    0x710a,
                    0x000a,
                ),
                40_000,
                12_345,
            );
            assert_eq!(decision.transport_checksum, Some(expected_transport));
            assert_ne!(expected_transport, 0);

            let mut udp_zero = parsed_quote(17, Some(0xffff));
            udp_zero.public_address = PUBLIC;
            udp_zero.public_port = 40_000;
            // Contract: an updated UDP checksum of mathematical zero is sent
            // as one's-complement negative zero (3035 equality mutant).
            let decision = super::super::build_nat44_icmpv4_rewrite(
                outer,
                udp_zero,
                LAN,
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 10],
                PUBLIC,
                40_000,
            )
            .unwrap();
            let super::super::PacketDecision::Nat44Icmpv4(decision) = decision else {
                panic!("expected ICMP NAT rewrite");
            };
            assert_eq!(decision.transport_checksum, Some(0xffff));
            // Contract: ICMP also maps mathematical zero to wire negative
            // zero (3049).
            assert_ne!(decision.icmp_checksum, 0);
        }

        #[test]
        fn rest_build_nat44_icmpv4_rewrite_maps_udp_and_icmp_math_zero() {
            let outer = synthetic_ipv4(1, ROUTER, PUBLIC, 56);

            let mut transport_zero = parsed_quote(17, Some(0xffff));
            transport_zero.public_address = PUBLIC;
            transport_zero.public_port = 40_000;
            let decision = super::super::build_nat44_icmpv4_rewrite(
                outer,
                transport_zero,
                LAN,
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 10],
                PUBLIC,
                40_000,
            )
            .unwrap();
            let super::super::PacketDecision::Nat44Icmpv4(decision) = decision else {
                panic!("expected ICMP NAT rewrite");
            };
            // Contract: a UDP checksum update that is mathematical zero is
            // encoded as wire negative zero (3035, mutant 33).
            assert_eq!(decision.transport_checksum, Some(0xffff));

            let mut icmp_zero = parsed_quote(17, Some(0xffff));
            icmp_zero.public_address = PUBLIC;
            icmp_zero.public_port = 40_000;
            icmp_zero.icmp_checksum = 0;
            let decision = super::super::build_nat44_icmpv4_rewrite(
                outer,
                icmp_zero,
                LAN,
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 10],
                PUBLIC,
                40_000,
            )
            .unwrap();
            let super::super::PacketDecision::Nat44Icmpv4(decision) = decision else {
                panic!("expected ICMP NAT rewrite");
            };
            // Contract: the same UDP zero mapping remains explicit in the
            // ICMP-zero case, so the two zero encodings are independent.
            assert_eq!(decision.transport_checksum, Some(0xffff));
            // Contract: a final mathematical ICMP checksum zero is also
            // encoded as wire negative zero (3049, mutant 34).
            assert_eq!(decision.icmp_checksum, 0xffff);
        }

        #[test]
        fn rest_checksums_and_firewall_transport_reject_invalid_content() {
            let valid_udp = valid_udp_frame(REMOTE, PUBLIC, 53, 40_000);
            let ipv4 = validate_ipv4_frame(&valid_udp).unwrap();
            // Contract: UDP checksum validation must inspect the packet and
            // transport pseudo-header (3347/3367), including end-around carry.
            assert!(super::super::udp_checksum_valid(&valid_udp, ipv4, 34));
            let mut invalid_udp = valid_udp.clone();
            invalid_udp[40] ^= 1;
            assert!(!super::super::udp_checksum_valid(&invalid_udp, ipv4, 34));
            assert!(super::super::transport_checksum_valid(
                REMOTE,
                PUBLIC,
                17,
                8,
                &valid_udp[34..42],
            ));
            assert!(!super::super::transport_checksum_valid(
                REMOTE,
                PUBLIC,
                17,
                8,
                &invalid_udp[34..42],
            ));

            // Contract: firewall TCP requires both ports to be nonzero; UDP
            // checksum zero is the protocol's checksum-disabled form
            // (3293/3313).
            let tcp = tcp_frame_with_checksum(INTERNAL, REMOTE, 0, 443, 40, 5, None);
            let tcp_ipv4 = validate_ipv4_frame(&tcp).unwrap();
            assert_eq!(
                super::super::validate_firewall_transport(&tcp, tcp_ipv4),
                Err(FirewallTcpPortZero)
            );
            let udp_zero = udp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 28, 8, 0);
            let udp_zero_ipv4 = validate_ipv4_frame(&udp_zero).unwrap();
            assert!(super::super::validate_firewall_transport(&udp_zero, udp_zero_ipv4).is_ok());
            let udp_bad = udp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 28, 8, 0x1234);
            let udp_bad_ipv4 = validate_ipv4_frame(&udp_bad).unwrap();
            assert_eq!(
                super::super::validate_firewall_transport(&udp_bad, udp_bad_ipv4),
                Err(FirewallUdpChecksumInvalid)
            );
        }

        #[test]
        fn rest_nat44_udp_and_tcp_validators_preserve_length_and_checksum_guards() {
            // Contract: UDP header and declared payload lengths are checked
            // against the IPv4 payload (4179/4187).
            let short_payload = udp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 28, 16, 0);
            let short_ipv4 = validate_ipv4_frame(&short_payload).unwrap();
            assert_eq!(
                super::super::validate_nat44_udp(&short_payload, short_ipv4),
                Err(Nat44UdpLengthExceedsIpv4Payload)
            );
            let tcp = tcp_frame_with_checksum(INTERNAL, REMOTE, 12_345, 443, 40, 5, None);
            let tcp_ipv4 = validate_ipv4_frame(&tcp).unwrap();
            // Contract: a valid TCP data offset and folded checksum are
            // accepted, while an offset beyond IPv4 payload is rejected
            // (4018/4022/4028/4050/4069).
            assert!(super::super::validate_nat44_tcp(&tcp, tcp_ipv4).is_ok());
            let too_small = tcp_frame_with_checksum(INTERNAL, REMOTE, 12_345, 443, 40, 4, None);
            let too_small_ipv4 = validate_ipv4_frame(&too_small).unwrap();
            assert_eq!(
                super::super::validate_nat44_tcp(&too_small, too_small_ipv4),
                Err(Nat44TcpDataOffsetTooSmall)
            );
            let too_long = tcp_frame_with_checksum(INTERNAL, REMOTE, 12_345, 443, 40, 6, None);
            let too_long_ipv4 = validate_ipv4_frame(&too_long).unwrap();
            assert_eq!(
                super::super::validate_nat44_tcp(&too_long, too_long_ipv4),
                Err(Nat44TcpDataOffsetExceedsIpv4Payload)
            );
            let invalid_checksum =
                tcp_frame_with_checksum(INTERNAL, REMOTE, 12_345, 443, 40, 5, Some(0x1234));
            let invalid_ipv4 = validate_ipv4_frame(&invalid_checksum).unwrap();
            assert_eq!(
                super::super::validate_nat44_tcp(&invalid_checksum, invalid_ipv4),
                Err(Nat44TcpChecksumInvalid)
            );

            // Contract: UDP's zero checksum rewrite remains zero, and a
            // nonzero checksum update is preserved (4246/4258).
            let udp = super::super::ValidatedNat44Udp {
                offset: 34,
                source_port: 1000,
                destination_port: 2000,
                checksum: 0,
            };
            let decision = super::super::build_nat44_udp_rewrite(
                synthetic_ipv4(17, INTERNAL, REMOTE, 28),
                udp,
                forwarding_decision(),
                INTERNAL,
                PUBLIC,
                1000,
                40_000,
                super::super::Nat44UdpTransition::Outbound(
                    // This plan is never inspected by the builder; obtain a
                    // real one to keep the transition contract honest.
                    with_udp_runtime(|_, _, runtime| {
                        runtime.plan_outbound(INTERNAL, 1000, REMOTE, 0).unwrap()
                    }),
                ),
                super::super::Nat44UdpDisposition::OutboundTranslated {
                    public_port: 40_000,
                    mapping_created: true,
                    peer_created: true,
                },
            )
            .unwrap();
            let super::super::PacketDecision::Nat44Udp(decision) = decision else {
                panic!("expected UDP NAT rewrite");
            };
            assert_eq!(decision.udp_checksum, 0);
        }

        #[test]
        fn rest_validate_nat44_udp_accepts_length_within_ipv4_payload() {
            let frame = udp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 30, 8, 0);
            let ipv4 = validate_ipv4_frame(&frame).unwrap();

            // Contract: an eight-byte UDP datagram is valid when the IPv4
            // payload is ten bytes, regardless of Ethernet padding; reversing
            // the `>` length guard would reject this independent case (4187,
            // mutant 73).
            assert!(super::super::validate_nat44_udp(&frame, ipv4).is_ok());
        }

        #[test]
        fn rest_combined_nat_security_time_requires_relevant_ingress_and_destination() {
            with_udp_runtime(|snapshot, config, runtime| {
                runtime.observe_now(100).unwrap();
                let mut runtime = Some(runtime);
                let validated = super::super::ValidatedFirewallTransport {
                    protocol: FirewallProtocol::Udp,
                    source_port: 53,
                    destination_port: 40_000,
                    tcp_flags: 0,
                };
                let ipv4 = synthetic_ipv4(17, REMOTE, REMOTE, 28);
                // Contract: inside ingress is relevant even for a non-public
                // destination; the guard must not skip clock validation
                // (3131's && and first != mutant).
                assert_eq!(
                    super::super::observe_combined_nat_security_time(
                        snapshot,
                        LAN,
                        ipv4,
                        validated,
                        Some(&config),
                        &mut runtime,
                        None,
                        &mut None,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    ),
                    Err(Nat44UdpClockRegression)
                );
            });
            with_udp_runtime(|snapshot, config, runtime| {
                runtime.observe_now(100).unwrap();
                let mut runtime = Some(runtime);
                let validated = super::super::ValidatedFirewallTransport {
                    protocol: FirewallProtocol::Udp,
                    source_port: 53,
                    destination_port: 40_000,
                    tcp_flags: 0,
                };
                // Contract: outside ingress to the public address is relevant;
                // changing the second != must not turn it into a skip.
                let ipv4 = synthetic_ipv4(17, REMOTE, PUBLIC, 28);
                assert_eq!(
                    super::super::observe_combined_nat_security_time(
                        snapshot,
                        WAN,
                        ipv4,
                        validated,
                        Some(&config),
                        &mut runtime,
                        None,
                        &mut None,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    ),
                    Err(Nat44UdpClockRegression)
                );
            });
        }

        #[test]
        fn rest_combined_nat_security_time_checks_tcp_inside_nonpublic_regression() {
            with_tcp_runtime(|snapshot, config, runtime| {
                runtime.observe_now(100).unwrap();
                let mut tcp_runtime = Some(runtime);
                let validated = super::super::ValidatedFirewallTransport {
                    protocol: FirewallProtocol::Tcp,
                    source_port: 53,
                    destination_port: 40_000,
                    tcp_flags: 0,
                };
                let ipv4 = synthetic_ipv4(6, REMOTE, REMOTE, 40);
                // Contract: TCP traffic arriving on the inside interface is
                // relevant even when its destination is not public; a clock
                // regression must reach the TCP runtime (3148 `&&`, mutant
                // 38).
                assert_eq!(
                    super::super::observe_combined_nat_security_time(
                        snapshot,
                        LAN,
                        ipv4,
                        validated,
                        None,
                        &mut None,
                        Some(&config),
                        &mut tcp_runtime,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    ),
                    Err(Nat44TcpClockRegression)
                );
            });
        }

        #[test]
        fn rest_combined_nat_security_time_skips_tcp_outside_nonpublic_destination() {
            with_tcp_runtime(|snapshot, config, runtime| {
                runtime.observe_now(100).unwrap();
                let mut tcp_runtime = Some(runtime);
                let validated = super::super::ValidatedFirewallTransport {
                    protocol: FirewallProtocol::Tcp,
                    source_port: 53,
                    destination_port: 40_000,
                    tcp_flags: 0,
                };
                let ipv4 = synthetic_ipv4(6, REMOTE, REMOTE, 40);
                // Contract: TCP traffic from the outside to a non-public
                // destination is irrelevant and must skip without touching
                // the runtime; changing the second `!=` to `==` would enter
                // the regressing runtime instead (3148, mutant 39).
                assert_eq!(
                    super::super::observe_combined_nat_security_time(
                        snapshot,
                        WAN,
                        ipv4,
                        validated,
                        None,
                        &mut None,
                        Some(&config),
                        &mut tcp_runtime,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    ),
                    Ok(())
                );
            });
        }

        #[test]
        fn rest_apply_rewriters_reject_each_independent_truncation_guard() {
            // Contract: every required ICMP NAT field, including an optional
            // present checksum field, is bounds-checked before any write
            // (5038/5039/5042).
            let icmp_decision = || super::super::Nat44Icmpv4RewriteDecision {
                egress: LAN,
                source_mac: [1; 6],
                destination_mac: [2; 6],
                outer_ttl_offset: 20,
                outer_checksum_offset: 22,
                outer_destination_offset: 24,
                inner_checksum_offset: 28,
                inner_source_offset: 30,
                inner_port_offset: 34,
                transport_checksum_offset: Some(38),
                icmp_checksum_offset: 40,
                internal_address: INTERNAL.octets(),
                internal_port: 1234,
                outer_checksum: 1,
                inner_checksum: 2,
                transport_checksum: Some(3),
                icmp_checksum: 4,
                disposition: super::super::Nat44Icmpv4Disposition::Rejected {
                    reason: Nat44Icmpv4QuoteTruncated,
                },
            };
            let cases = [
                ("ethernet", vec![0_u8; 11], icmp_decision()),
                ("outer ttl", vec![0_u8; 37], icmp_decision()),
                ("required", vec![0_u8; 39], icmp_decision()),
                (
                    "optional transport checksum",
                    vec![0_u8; 40],
                    icmp_decision(),
                ),
            ];
            for (label, mut frame, decision) in cases {
                assert_eq!(
                    super::super::apply_nat44_icmpv4_rewrite(&mut frame, decision),
                    Err(Nat44Icmpv4QuoteTruncated),
                    "{label} must be rejected before mutation"
                );
            }

            // Contract: TCP and UDP NAT rewrites validate Ethernet, IPv4,
            // address, port, and transport checksum ranges independently
            // (5077/5078/5081/5084/5085 and 5109/5110/5113/5116/5117).
            let tcp_guard = || super::super::Nat44TcpRewriteDecision {
                forwarding: super::super::Ipv4RewriteDecision {
                    ttl_offset: 12,
                    checksum_offset: 14,
                    checksum_end: 16,
                    ..forwarding_decision()
                },
                address_offset: 16,
                address_end: 20,
                new_address: INTERNAL.octets(),
                port_offset: 20,
                port_end: 22,
                new_port: 1234,
                tcp_checksum_offset: 22,
                tcp_checksum_end: 24,
                ipv4_checksum: 1,
                tcp_checksum: 2,
                transition: super::super::Nat44TcpTransition::Outbound(with_tcp_runtime(
                    |_, _, runtime| {
                        runtime
                            .plan_outbound(INTERNAL, 1000, REMOTE, 2000, true, 0)
                            .unwrap()
                    },
                )),
                disposition: super::super::Nat44TcpDisposition::OutboundTranslated {
                    public_port: 40_000,
                    mapping_created: true,
                    session_created: true,
                },
            };
            let tcp_cases = [
                ("ethernet", 11, 0),
                ("ttl", 24, 12),
                ("ipv4 checksum", 24, 40),
                ("address", 24, 40),
                ("port", 24, 40),
                ("tcp checksum", 24, 40),
            ];
            for (label, len, _unused) in tcp_cases {
                let mut frame = vec![0_u8; len];
                let mut decision = tcp_guard();
                if label == "ttl" {
                    decision.forwarding.ttl_offset = 100;
                }
                if label == "ipv4 checksum" {
                    decision.forwarding.checksum_offset = 100;
                    decision.forwarding.checksum_end = 102;
                }
                if label == "address" {
                    decision.address_offset = 100;
                    decision.address_end = 104;
                }
                if label == "port" {
                    decision.port_offset = 100;
                    decision.port_end = 102;
                }
                if label == "tcp checksum" {
                    decision.tcp_checksum_offset = 100;
                    decision.tcp_checksum_end = 102;
                }
                assert_eq!(
                    super::super::apply_nat44_tcp_rewrite(&mut frame, decision),
                    Err(Nat44TcpHeaderTruncated),
                    "{label} must be rejected"
                );
            }
            let udp_guard = || super::super::Nat44UdpRewriteDecision {
                forwarding: super::super::Ipv4RewriteDecision {
                    ttl_offset: 12,
                    checksum_offset: 14,
                    checksum_end: 16,
                    ..forwarding_decision()
                },
                address_offset: 16,
                address_end: 20,
                new_address: INTERNAL.octets(),
                port_offset: 20,
                port_end: 22,
                new_port: 1234,
                udp_checksum_offset: 22,
                udp_checksum_end: 24,
                ipv4_checksum: 1,
                udp_checksum: 2,
                transition: super::super::Nat44UdpTransition::Outbound(with_udp_runtime(
                    |_, _, runtime| runtime.plan_outbound(INTERNAL, 1000, REMOTE, 0).unwrap(),
                )),
                disposition: super::super::Nat44UdpDisposition::OutboundTranslated {
                    public_port: 40_000,
                    mapping_created: true,
                    peer_created: true,
                },
            };
            for (label, len, field) in [
                ("ethernet", 11, 0),
                ("ttl", 24, 1),
                ("ipv4 checksum", 24, 2),
                ("address", 24, 3),
                ("port", 24, 4),
                ("udp checksum", 24, 5),
            ] {
                let mut frame = vec![0_u8; len];
                let mut decision = udp_guard();
                match field {
                    1 => decision.forwarding.ttl_offset = 100,
                    2 => {
                        decision.forwarding.checksum_offset = 100;
                        decision.forwarding.checksum_end = 102;
                    }
                    3 => {
                        decision.address_offset = 100;
                        decision.address_end = 104;
                    }
                    4 => {
                        decision.port_offset = 100;
                        decision.port_end = 102;
                    }
                    5 => {
                        decision.udp_checksum_offset = 100;
                        decision.udp_checksum_end = 102;
                    }
                    _ => {}
                }
                assert_eq!(
                    super::super::apply_nat44_udp_rewrite(&mut frame, decision),
                    Err(Nat44UdpHeaderTruncated),
                    "{label} must be rejected"
                );
            }

            // Contract: ordinary IPv4 forwarding and ICMP echo replies have
            // the same fail-before-write guarantee (5138/5139/5140/5177/5178/5179).
            for (label, len, field) in [
                ("ipv4 ethernet", 10, 0),
                ("ipv4 ttl", 12, 1),
                ("ipv4 checksum", 12, 2),
            ] {
                let mut frame = vec![0_u8; len];
                let mut decision = forwarding_decision();
                match field {
                    1 => decision.ttl_offset = 100,
                    2 => {
                        decision.checksum_offset = 100;
                        decision.checksum_end = 102;
                    }
                    _ => {}
                }
                assert_eq!(
                    super::super::apply_ipv4_rewrite(&mut frame, decision),
                    Err(Ipv4HeaderLengthExceedsPacket),
                    "{label} must be rejected"
                );
            }
            let echo = || super::super::Icmpv4EchoReplyDecision {
                egress: LAN,
                local_mac: [1; 6],
                requester_mac: [2; 6],
                local_ip: INTERNAL.octets(),
                requester_ip: REMOTE.octets(),
                ipv4_checksum: 1,
                icmp_checksum: 2,
                reply_ttl: 64,
                icmp_offset: 20,
                icmp_end: 24,
            };
            for (label, len, field) in [
                ("echo ethernet", 11, 0),
                ("echo IPv4", 20, 1),
                ("echo ICMP range", 34, 2),
                ("echo ICMP header", 42, 3),
            ] {
                let mut frame = vec![0_u8; len];
                let mut decision = echo();
                match field {
                    1 => decision.icmp_offset = 40,
                    2 => {
                        decision.icmp_offset = 20;
                        decision.icmp_end = 40;
                    }
                    3 => {
                        decision.icmp_offset = 40;
                        decision.icmp_end = 42;
                    }
                    _ => {}
                }
                assert_eq!(
                    super::super::apply_icmpv4_echo_reply(&mut frame, decision),
                    Err(Ipv4TotalLengthExceedsPacket),
                    "{label} must be rejected"
                );
            }
        }

        #[test]
        fn rest_apply_ipv4_rewrite_checks_ttl_and_checksum_ranges_independently() {
            let mut ttl_frame = vec![0_u8; 20];
            let mut ttl_decision = forwarding_decision();
            ttl_decision.ttl_offset = 100;
            ttl_decision.checksum_offset = 14;
            ttl_decision.checksum_end = 16;
            // Contract: with both Ethernet ranges and the checksum range
            // valid, an out-of-range TTL is still rejected; changing either
            // relevant `||` to `&&` must not permit the write (5139/5140,
            // mutants 155/154).
            assert_eq!(
                super::super::apply_ipv4_rewrite(&mut ttl_frame, ttl_decision),
                Err(Ipv4HeaderLengthExceedsPacket)
            );

            let mut checksum_frame = vec![0_u8; 20];
            let mut checksum_decision = forwarding_decision();
            checksum_decision.ttl_offset = 12;
            checksum_decision.checksum_offset = 100;
            checksum_decision.checksum_end = 102;
            // Contract: with Ethernet and TTL ranges valid, an out-of-range
            // checksum range is independently rejected (5140, mutant 154).
            assert_eq!(
                super::super::apply_ipv4_rewrite(&mut checksum_frame, checksum_decision),
                Err(Ipv4HeaderLengthExceedsPacket)
            );
        }

        #[test]
        fn rest_apply_rewriters_checks_leading_frame_ranges_independently() {
            let mut icmp_frame = vec![0_u8; 11];
            let icmp_decision = super::super::Nat44Icmpv4RewriteDecision {
                egress: LAN,
                source_mac: [1; 6],
                destination_mac: [2; 6],
                outer_ttl_offset: 0,
                outer_checksum_offset: 0,
                outer_destination_offset: 2,
                inner_checksum_offset: 0,
                inner_source_offset: 2,
                inner_port_offset: 6,
                transport_checksum_offset: None,
                icmp_checksum_offset: 8,
                internal_address: INTERNAL.octets(),
                internal_port: 1234,
                outer_checksum: 1,
                inner_checksum: 2,
                transport_checksum: None,
                icmp_checksum: 4,
                disposition: super::super::Nat44Icmpv4Disposition::Rejected {
                    reason: Nat44Icmpv4QuoteTruncated,
                },
            };
            // Contract: the complete Ethernet header is required even when
            // every other ICMP NAT field range fits in an 11-byte frame and
            // no optional transport checksum is present (5037, mutant 143).
            assert_eq!(
                super::super::apply_nat44_icmpv4_rewrite(&mut icmp_frame, icmp_decision),
                Err(Nat44Icmpv4QuoteTruncated)
            );

            let mut ipv4_frame = vec![0_u8; 10];
            let mut ipv4_decision = forwarding_decision();
            ipv4_decision.ttl_offset = 0;
            ipv4_decision.checksum_offset = 0;
            ipv4_decision.checksum_end = 2;
            // Contract: an IPv4 rewrite must reject a missing second
            // Ethernet range even when the first Ethernet range, TTL, and
            // checksum ranges are valid (5138, mutant 156).
            assert_eq!(
                super::super::apply_ipv4_rewrite(&mut ipv4_frame, ipv4_decision),
                Err(Ipv4HeaderLengthExceedsPacket)
            );

            let mut echo_frame = vec![0_u8; 20];
            let echo_decision = super::super::Icmpv4EchoReplyDecision {
                egress: LAN,
                local_mac: [1; 6],
                requester_mac: [2; 6],
                local_ip: INTERNAL.octets(),
                requester_ip: REMOTE.octets(),
                ipv4_checksum: 1,
                icmp_checksum: 2,
                reply_ttl: 64,
                icmp_offset: 0,
                icmp_end: 4,
            };
            // Contract: an ICMP echo reply must reject a missing IPv4 range
            // even when the Ethernet range and both ICMP ranges fit
            // (5177, mutant 159).
            assert_eq!(
                super::super::apply_icmpv4_echo_reply(&mut echo_frame, echo_decision),
                Err(Ipv4TotalLengthExceedsPacket)
            );
        }

        #[test]
        fn rest_decide_frag_needed_rejects_non_host_outer_source() {
            let routes = [
                Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
                Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap(),
            ];
            let neighbors = [Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_udp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_udp_mapping(runtime, INTERNAL, REMOTE);
                let mut frame = frag_needed_frame_with_quote(17, 5, 28);
                set_outer_source(&mut frame, Ipv4Address::from_octets([198, 51, 100, 0]));
                let outer = validate_ipv4_frame(&frame).unwrap();
                let mut resolution = None;

                // Contract: a network-address ICMP source is rejected before
                // NAT lookup, even when it is not also a local binding (2609).
                assert!(matches!(
                    decide_frag_udp(&frame, snapshot, &config, runtime, outer, &mut resolution,),
                    Err(Nat44Icmpv4SourceForbidden)
                ));
            });
        }

        #[test]
        fn rest_decide_frag_needed_udp_public_source_guards_are_independent() {
            let routes = standard_nat_routes();
            let neighbors = [Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_udp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_udp_mapping(runtime, INTERNAL, REMOTE);
                let frame = frag_needed_frame_with_quote(17, 5, 28);
                let outer = validate_ipv4_frame(&frame).unwrap();
                let disabled = Nat44UdpConfig::new(
                    snapshot,
                    LAN,
                    WAN,
                    PUBLIC,
                    40_000,
                    40_001,
                    Nat44UdpPolicy::default(),
                )
                .unwrap();
                let mut resolution = None;

                // Contract: UDP ICMP translation requires ExternalOnly even
                // when both public-address comparisons succeed (2623).
                assert!(matches!(
                    decide_frag_udp(&frame, snapshot, &disabled, runtime, outer, &mut resolution,),
                    Err(Nat44Icmpv4QuotedPublicSourceMismatch)
                ));

                let mut wrong_quote_source = frame.clone();
                set_quoted_source(&mut wrong_quote_source, PUBLIC2);
                let wrong_outer = validate_ipv4_frame(&wrong_quote_source).unwrap();
                let mut resolution = None;

                // Contract: the quoted source must equal the configured public
                // address even when policy and outer destination are valid
                // (2624).
                assert!(matches!(
                    decide_frag_udp(
                        &wrong_quote_source,
                        snapshot,
                        &config,
                        runtime,
                        wrong_outer,
                        &mut resolution,
                    ),
                    Err(Nat44Icmpv4QuotedPublicSourceMismatch)
                ));
            });
        }

        #[test]
        fn rest_decide_frag_needed_tcp_public_source_guards_are_independent() {
            let routes = standard_nat_routes();
            let neighbors = [Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_tcp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_tcp_mapping(runtime, INTERNAL, REMOTE, 53);
                let frame = frag_needed_frame_with_quote(6, 5, 40);
                let outer = validate_ipv4_frame(&frame).unwrap();
                let disabled = Nat44TcpConfig::new(
                    snapshot,
                    LAN,
                    WAN,
                    PUBLIC,
                    40_000,
                    40_001,
                    Nat44TcpPolicy::default(),
                )
                .unwrap();
                let mut resolution = None;

                // Contract: TCP ICMP translation requires ExternalOnly even
                // when both public-address comparisons succeed (2677).
                assert!(matches!(
                    decide_frag_tcp(&frame, snapshot, &disabled, runtime, outer, &mut resolution,),
                    Err(Nat44Icmpv4QuotedPublicSourceMismatch)
                ));

                let mut wrong_quote_source = frame.clone();
                set_quoted_source(&mut wrong_quote_source, PUBLIC2);
                let wrong_outer = validate_ipv4_frame(&wrong_quote_source).unwrap();
                let mut resolution = None;

                // Contract: the quoted TCP source must equal the configured
                // public address when policy and outer destination are valid
                // (2678).
                assert!(matches!(
                    decide_frag_tcp(
                        &wrong_quote_source,
                        snapshot,
                        &config,
                        runtime,
                        wrong_outer,
                        &mut resolution,
                    ),
                    Err(Nat44Icmpv4QuotedPublicSourceMismatch)
                ));
            });
        }

        #[test]
        fn rest_decide_frag_needed_uses_matching_interface_and_static_neighbor() {
            let routes = standard_nat_routes();
            let neighbors = [Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_udp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_udp_mapping(runtime, INTERNAL, REMOTE);
                let frame = frag_needed_frame_with_quote(17, 5, 28);
                let outer = validate_ipv4_frame(&frame).unwrap();
                let mut resolution = None;
                let decision =
                    decide_frag_udp(&frame, snapshot, &config, runtime, outer, &mut resolution)
                        .unwrap();
                let super::super::PacketDecision::Nat44Icmpv4(decision) = decision else {
                    panic!("expected ICMPv4 NAT rewrite");
                };

                // Contract: the rewrite uses the selected inside interface,
                // not an unrelated interface that happens to be present
                // (2810).
                assert_eq!(decision.egress, LAN);
                assert_eq!(decision.source_mac, [2, 0, 0, 0, 0, 1]);
                // Contract: a static neighbor is selected by the complete
                // (interface, target) key (2816 is covered by the next test).
                assert_eq!(decision.destination_mac, [2, 0, 0, 0, 0, 20]);
            });
        }

        #[test]
        fn rest_decide_frag_needed_does_not_use_neighbor_on_wrong_interface() {
            let routes = standard_nat_routes();
            let neighbors = [Neighbor {
                interface: WAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 21]),
            }];
            with_udp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_udp_mapping(runtime, INTERNAL, REMOTE);
                let frame = frag_needed_frame_with_quote(17, 5, 28);
                let outer = validate_ipv4_frame(&frame).unwrap();
                let mut resolution = None;

                // Contract: a neighbor on another interface cannot satisfy
                // resolution for the selected inside egress (2816).
                assert!(matches!(
                    decide_frag_udp(&frame, snapshot, &config, runtime, outer, &mut resolution,),
                    Err(NeighborUnresolved)
                ));
            });
        }

        #[test]
        fn rest_decide_frag_needed_preserves_arp_binding_and_target_authority() {
            let target = Ipv4Address::from_octets([10, 0, 0, 20]);
            let routes = standard_nat_routes();
            with_udp_runtime_on(&routes, &[], |snapshot, config, runtime| {
                seed_udp_mapping(runtime, target, REMOTE);
                let frame = frag_needed_frame_with_quote(17, 5, 28);
                let outer = validate_ipv4_frame(&frame).unwrap();
                let mut states = [ResolutionStateSlot::EMPTY; 1];
                let mut actions = [ResolutionActionSlot::EMPTY; 1];
                let mut resolution_runtime = ResolutionRuntime::new(
                    ResolutionPolicy::new(1_000, 2_000).unwrap(),
                    &mut states,
                    &mut actions,
                );
                let mut resolution = Some((&mut resolution_runtime, MonotonicMillis(0)));

                let result =
                    decide_frag_udp(&frame, snapshot, &config, runtime, outer, &mut resolution);

                // Contract: a normal target queues ARP using the local binding
                // on the selected interface, and does not mistake another
                // binding for the target (2834/2847).
                assert!(matches!(result, Err(NeighborUnresolved)));
                let (action, _) = resolution_runtime.queued_action(0).unwrap();
                assert_eq!(action.egress, LAN);
                assert_eq!(action.source_ip, INTERNAL);
                assert_eq!(action.target_ip, target);
            });
        }

        #[test]
        fn rest_decide_frag_needed_combines_local_target_and_route_evidence() {
            let routes = [
                Route::new(PUBLIC, 32, LAN, None).unwrap(),
                Route::new(ROUTER, 32, WAN, None).unwrap(),
            ];
            with_udp_runtime_on(&routes, &[], |snapshot, config, runtime| {
                seed_udp_mapping(runtime, PUBLIC, REMOTE);
                let frame = frag_needed_frame_with_quote(17, 5, 28);
                let outer = validate_ipv4_frame(&frame).unwrap();
                let mut states = [ResolutionStateSlot::EMPTY; 1];
                let mut actions = [ResolutionActionSlot::EMPTY; 1];
                let mut resolution_runtime = ResolutionRuntime::new(
                    ResolutionPolicy::new(1_000, 2_000).unwrap(),
                    &mut states,
                    &mut actions,
                );
                let mut resolution = Some((&mut resolution_runtime, MonotonicMillis(0)));

                // Contract: a local target remains forbidden even if no
                // connected-route evidence also matches it (2848).
                assert!(matches!(
                    decide_frag_udp(&frame, snapshot, &config, runtime, outer, &mut resolution,),
                    Err(NeighborUnresolved)
                ));
                assert_eq!(resolution_runtime.pending_actions(), 0);
            });
        }

        #[test]
        fn rest_decide_frag_needed_rejects_connected_network_target_on_selected_egress() {
            let target = Ipv4Address::from_octets([10, 0, 0, 0]);
            let routes = [
                Route::new(target, 24, LAN, None).unwrap(),
                Route::new(ROUTER, 32, WAN, None).unwrap(),
            ];
            with_udp_runtime_on(&routes, &[], |snapshot, config, runtime| {
                seed_udp_mapping(runtime, target, REMOTE);
                let frame = frag_needed_frame_with_quote(17, 5, 28);
                let outer = validate_ipv4_frame(&frame).unwrap();
                let mut states = [ResolutionStateSlot::EMPTY; 1];
                let mut actions = [ResolutionActionSlot::EMPTY; 1];
                let mut resolution_runtime = ResolutionRuntime::new(
                    ResolutionPolicy::new(1_000, 2_000).unwrap(),
                    &mut states,
                    &mut actions,
                );
                let mut resolution = Some((&mut resolution_runtime, MonotonicMillis(0)));

                // Contract: connected network evidence on the selected egress
                // forbids an ARP request; the egress test and the two route
                // boundary tests must all participate (2849/2851).
                assert!(matches!(
                    decide_frag_udp(&frame, snapshot, &config, runtime, outer, &mut resolution,),
                    Err(NeighborUnresolved)
                ));
                assert_eq!(resolution_runtime.pending_actions(), 0);
            });
        }

        #[test]
        fn rest_decide_frag_needed_ignores_connected_evidence_on_wrong_egress() {
            let target = Ipv4Address::from_octets([10, 0, 0, 0]);
            let routes = [
                Route::new(target, 32, LAN, None).unwrap(),
                Route::new(target, 24, WAN, None).unwrap(),
                Route::new(ROUTER, 32, WAN, None).unwrap(),
            ];
            with_udp_runtime_on(&routes, &[], |snapshot, config, runtime| {
                seed_udp_mapping(runtime, target, REMOTE);
                let frame = frag_needed_frame_with_quote(17, 5, 28);
                let outer = validate_ipv4_frame(&frame).unwrap();
                let mut states = [ResolutionStateSlot::EMPTY; 1];
                let mut actions = [ResolutionActionSlot::EMPTY; 1];
                let mut resolution_runtime = ResolutionRuntime::new(
                    ResolutionPolicy::new(1_000, 2_000).unwrap(),
                    &mut states,
                    &mut actions,
                );
                let mut resolution = Some((&mut resolution_runtime, MonotonicMillis(0)));

                // Contract: a connected-network route on another interface is
                // not evidence for the selected inside egress (2850).
                assert!(matches!(
                    decide_frag_udp(&frame, snapshot, &config, runtime, outer, &mut resolution,),
                    Err(NeighborUnresolved)
                ));
                assert_eq!(resolution_runtime.pending_actions(), 1);
                assert_eq!(
                    resolution_runtime.queued_action(0).unwrap().0.target_ip,
                    target
                );
            });
        }

        #[test]
        // Contract: outbound NAT must reject IPv4 options and each independent
        // source-forbidden condition before it can create a mapping (3421,
        // 3438, 3442).
        fn rest_decide_nat44_udp_outbound_guards_are_independent() {
            with_udp_runtime(|snapshot, config, runtime| {
                let frame = valid_udp_frame(INTERNAL, REMOTE, 12_345, 53);
                let mut ipv4 = validate_ipv4_frame(&frame).unwrap();
                ipv4.header_len = 24;
                assert!(matches!(
                    decide_udp_outbound(&frame, snapshot, &config, runtime, ipv4),
                    Err(Ipv4OptionsUnsupported)
                ));
            });

            with_udp_runtime(|snapshot, config, runtime| {
                let source = Ipv4Address::from_octets([10, 0, 0, 0]);
                let frame = valid_udp_frame(source, REMOTE, 12_345, 53);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                assert!(matches!(
                    decide_udp_outbound(&frame, snapshot, &config, runtime, ipv4),
                    Err(Nat44UdpSourceForbidden)
                ));
            });

            with_udp_runtime(|snapshot, config, runtime| {
                let frame = valid_udp_frame(INTERNAL, REMOTE, 12_345, 53);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                assert!(matches!(
                    decide_udp_outbound(&frame, snapshot, &config, runtime, ipv4),
                    Err(Nat44UdpSourceForbidden)
                ));
            });
        }

        #[test]
        fn rest_decide_udp_outbound_rejects_options_and_forbidden_sources() {
            // Contract: outbound NAT rejects IPv4 options before transport
            // parsing (3421), rejects a non-host source independently of local
            // binding evidence (3438), and rejects a locally bound source
            // independently of public-address evidence (3442).  The three
            // subcases kill the corresponding `>`/`<` and `||`/`&&` mutants.
            with_udp_runtime(|snapshot, config, runtime| {
                let frame = valid_udp_frame(INTERNAL, REMOTE, 12_345, 53);
                let mut ipv4 = validate_ipv4_frame(&frame).unwrap();
                ipv4.header_len = 24;
                assert!(matches!(
                    decide_udp_outbound(&frame, snapshot, &config, runtime, ipv4),
                    Err(Ipv4OptionsUnsupported)
                ));
            });

            with_udp_runtime(|snapshot, config, runtime| {
                let source = Ipv4Address::from_octets([224, 0, 0, 1]);
                let frame = valid_udp_frame(source, REMOTE, 12_345, 53);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                assert!(matches!(
                    decide_udp_outbound(&frame, snapshot, &config, runtime, ipv4),
                    Err(Nat44UdpSourceForbidden)
                ));
            });

            with_udp_runtime(|snapshot, config, runtime| {
                let frame = valid_udp_frame(INTERNAL, REMOTE, 12_345, 53);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                assert!(matches!(
                    decide_udp_outbound(&frame, snapshot, &config, runtime, ipv4),
                    Err(Nat44UdpSourceForbidden)
                ));
            });
        }

        #[test]
        fn rest_decide_nat44_udp_inbound_rejects_options_and_source_forbidden_cases() {
            let routes = standard_nat_routes();
            let neighbors = [Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];

            with_udp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_udp_mapping(runtime, INTERNAL, REMOTE);
                let frame = valid_udp_frame(REMOTE, PUBLIC, 53, 40_000);
                let mut ipv4 = validate_ipv4_frame(&frame).unwrap();
                ipv4.header_len = 24;
                let mut resolution = None;

                // Contract: inbound NAT rejects IPv4 options before using a
                // valid mapping or forwarding metadata (3517).
                assert!(matches!(
                    decide_udp_inbound(&frame, snapshot, &config, runtime, ipv4, &mut resolution,),
                    Err(Ipv4OptionsUnsupported)
                ));
            });

            with_udp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                let source = Ipv4Address::from_octets([224, 0, 0, 1]);
                seed_udp_mapping(runtime, INTERNAL, source);
                let frame = valid_udp_frame(source, PUBLIC, 53, 40_000);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let mut resolution = None;

                // Contract: a non-host source is forbidden even when it is
                // not a local binding (3528).
                assert!(matches!(
                    decide_udp_inbound(&frame, snapshot, &config, runtime, ipv4, &mut resolution,),
                    Err(Nat44UdpSourceForbidden)
                ));
            });

            with_udp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_udp_mapping(runtime, INTERNAL, INTERNAL);
                let frame = valid_udp_frame(INTERNAL, PUBLIC, 53, 40_000);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let mut resolution = None;

                // Contract: a host source is still forbidden when it belongs
                // to a local IPv4 binding (3528).
                assert!(matches!(
                    decide_udp_inbound(&frame, snapshot, &config, runtime, ipv4, &mut resolution,),
                    Err(Nat44UdpSourceForbidden)
                ));
            });
        }

        #[test]
        fn rest_decide_nat44_udp_inbound_requires_exact_interface_and_neighbor_key() {
            let routes = standard_nat_routes();

            with_udp_runtime_on(
                &routes,
                &[Neighbor {
                    interface: LAN,
                    target: INTERNAL,
                    mac: MacAddress([2, 0, 0, 0, 0, 20]),
                }],
                |snapshot, config, runtime| {
                    seed_udp_mapping(runtime, INTERNAL, REMOTE);
                    let frame = valid_udp_frame(REMOTE, PUBLIC, 53, 40_000);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;
                    let decision = decide_udp_inbound(
                        &frame,
                        snapshot,
                        &config,
                        runtime,
                        ipv4,
                        &mut resolution,
                    )
                    .unwrap();
                    let super::super::PacketDecision::Nat44Udp(rewrite) = decision else {
                        panic!("expected inbound UDP NAT rewrite");
                    };

                    // Contract: the selected reverse route's egress must pick
                    // its matching interface, not the other interface (3611).
                    assert_eq!(rewrite.forwarding.egress, LAN);
                    assert_eq!(rewrite.forwarding.source_mac, [2, 0, 0, 0, 0, 1]);
                    // Contract: a static neighbor is valid only when both its
                    // interface and target match the reverse route (3616).
                    assert_eq!(rewrite.forwarding.destination_mac, [2, 0, 0, 0, 0, 20]);
                },
            );

            with_udp_runtime_on(
                &routes,
                &[Neighbor {
                    interface: WAN,
                    target: INTERNAL,
                    mac: MacAddress([2, 0, 0, 0, 0, 21]),
                }],
                |snapshot, config, runtime| {
                    seed_udp_mapping(runtime, INTERNAL, REMOTE);
                    let frame = valid_udp_frame(REMOTE, PUBLIC, 53, 40_000);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;

                    // Contract: a neighbor with the right target but the
                    // wrong interface cannot satisfy inbound resolution
                    // (3616's && and interface equality).
                    assert!(matches!(
                        decide_udp_inbound(
                            &frame,
                            snapshot,
                            &config,
                            runtime,
                            ipv4,
                            &mut resolution,
                        ),
                        Err(NeighborUnresolved)
                    ));
                },
            );

            with_udp_runtime_on(
                &routes,
                &[Neighbor {
                    interface: LAN,
                    target: Ipv4Address::from_octets([10, 0, 0, 11]),
                    mac: MacAddress([2, 0, 0, 0, 0, 22]),
                }],
                |snapshot, config, runtime| {
                    seed_udp_mapping(runtime, INTERNAL, REMOTE);
                    let frame = valid_udp_frame(REMOTE, PUBLIC, 53, 40_000);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;

                    // Contract: a neighbor with the right interface but the
                    // wrong target cannot satisfy inbound resolution (3616's
                    // && and target equality).
                    assert!(matches!(
                        decide_udp_inbound(
                            &frame,
                            snapshot,
                            &config,
                            runtime,
                            ipv4,
                            &mut resolution,
                        ),
                        Err(NeighborUnresolved)
                    ));
                },
            );
        }

        #[test]
        fn rest_decide_nat44_udp_inbound_queues_arp_from_selected_binding() {
            let routes = standard_nat_routes();
            with_udp_runtime_on(&routes, &[], |snapshot, config, runtime| {
                let target = Ipv4Address::from_octets([10, 0, 0, 20]);
                seed_udp_mapping(runtime, target, REMOTE);
                let frame = valid_udp_frame(REMOTE, PUBLIC, 53, 40_000);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let mut states = [ResolutionStateSlot::EMPTY; 1];
                let mut actions = [ResolutionActionSlot::EMPTY; 1];
                let mut resolution_runtime = ResolutionRuntime::new(
                    ResolutionPolicy::new(1_000, 2_000).unwrap(),
                    &mut states,
                    &mut actions,
                );
                let mut resolution = Some((&mut resolution_runtime, MonotonicMillis(0)));

                // Contract: a dynamic miss queues ARP using the local binding
                // on the selected reverse-route interface (3629).
                assert!(matches!(
                    decide_udp_inbound(&frame, snapshot, &config, runtime, ipv4, &mut resolution,),
                    Err(NeighborUnresolved)
                ));
                let (action, _) = resolution_runtime.queued_action(0).unwrap();
                assert_eq!(action.egress, LAN);
                assert_eq!(action.source_mac, MacAddress([2, 0, 0, 0, 0, 1]));
                assert_eq!(action.source_ip, INTERNAL);
                assert_eq!(action.target_ip, target);
            });
        }

        #[test]
        fn rest_decide_nat44_tcp_outbound_rejects_ipv4_options() {
            with_tcp_runtime(|snapshot, config, runtime| {
                let source = Ipv4Address::from_octets([10, 0, 0, 20]);
                let base = tcp_frame_with_checksum(source, REMOTE, 12_345, 443, 40, 5, None);
                let mut frame = vec![0_u8; base.len() + 4];
                frame[..34].copy_from_slice(&base[..34]);
                frame[38..].copy_from_slice(&base[34..]);
                frame[14] = 0x46;
                frame[16..18].copy_from_slice(&44_u16.to_be_bytes());
                frame[24..26].fill(0);
                let checksum = ipv4_header_checksum(&frame[14..38]);
                frame[24..26].copy_from_slice(&checksum.to_be_bytes());
                let ipv4 = validate_ipv4_frame(&frame).unwrap();

                // Contract: TCP outbound rejects a syntactically valid IPv4
                // options header before transport planning (3707).
                assert!(matches!(
                    decide_tcp_outbound(&frame, snapshot, &config, runtime, ipv4),
                    Err(Ipv4OptionsUnsupported)
                ));
            });
        }

        #[test]
        fn rest_decide_nat44_tcp_outbound_rejects_each_source_forbidden_guard() {
            with_tcp_runtime(|snapshot, config, runtime| {
                let frame = tcp_frame_with_checksum(INTERNAL, REMOTE, 12_345, 443, 40, 5, None);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();

                // Contract: a locally bound source is rejected even when the
                // non-host and public-address conditions are false.  This
                // single-true-condition input guards both independent ORs
                // (3724/3728).
                assert!(matches!(
                    decide_tcp_outbound(&frame, snapshot, &config, runtime, ipv4),
                    Err(Nat44TcpSourceForbidden)
                ));
            });
        }

        #[test]
        fn rest_decide_nat44_tcp_inbound_rejects_ipv4_options() {
            let routes = standard_nat_routes();
            let neighbors = [Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_tcp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_tcp_mapping(runtime, INTERNAL, REMOTE, 53);
                let base = tcp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 40, 5, None);
                let mut frame = vec![0_u8; base.len() + 4];
                frame[..34].copy_from_slice(&base[..34]);
                frame[38..].copy_from_slice(&base[34..]);
                frame[14] = 0x46;
                frame[16..18].copy_from_slice(&44_u16.to_be_bytes());
                frame[24..26].fill(0);
                let checksum = ipv4_header_checksum(&frame[14..38]);
                frame[24..26].copy_from_slice(&checksum.to_be_bytes());
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let mut resolution = None;

                // Contract: TCP inbound rejects a syntactically valid IPv4
                // options header before mapping and forwarding (3818).
                assert!(matches!(
                    decide_tcp_inbound(&frame, snapshot, &config, runtime, ipv4, &mut resolution,),
                    Err(Ipv4OptionsUnsupported)
                ));
            });
        }

        #[test]
        fn rest_decide_nat44_tcp_inbound_rejects_locally_bound_source() {
            let routes = standard_nat_routes();
            let neighbors = [Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_tcp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_tcp_mapping(runtime, INTERNAL, INTERNAL, 53);
                let frame = tcp_frame_with_checksum(INTERNAL, PUBLIC, 53, 40_000, 40, 5, None);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let mut resolution = None;

                // Contract: a locally bound host source is rejected even when
                // the non-host condition is false (3832).
                assert!(matches!(
                    decide_tcp_inbound(&frame, snapshot, &config, runtime, ipv4, &mut resolution,),
                    Err(Nat44TcpSourceForbidden)
                ));
            });
        }

        #[test]
        fn rest_decide_nat44_tcp_inbound_uses_selected_reverse_interface() {
            let routes = standard_nat_routes();
            let neighbors = [Neighbor {
                interface: LAN,
                target: INTERNAL,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_tcp_runtime_on(&routes, &neighbors, |snapshot, config, runtime| {
                seed_tcp_mapping(runtime, INTERNAL, REMOTE, 53);
                let frame = tcp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 40, 5, None);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let mut resolution = None;
                let decision =
                    decide_tcp_inbound(&frame, snapshot, &config, runtime, ipv4, &mut resolution)
                        .unwrap();
                let super::super::PacketDecision::Nat44Tcp(rewrite) = decision else {
                    panic!("expected inbound TCP NAT rewrite");
                };

                // Contract: reverse-route forwarding uses the interface that
                // owns the inside egress rather than an unrelated interface
                // (3915).
                assert_eq!(rewrite.forwarding.egress, LAN);
                assert_eq!(rewrite.forwarding.source_mac, [2, 0, 0, 0, 0, 1]);
                assert_eq!(rewrite.forwarding.destination_mac, [2, 0, 0, 0, 0, 20]);
            });
        }

        #[test]
        fn rest_decide_nat44_tcp_inbound_requires_exact_static_neighbor_pair() {
            let routes = standard_nat_routes();

            with_tcp_runtime_on(
                &routes,
                &[Neighbor {
                    interface: LAN,
                    target: INTERNAL,
                    mac: MacAddress([2, 0, 0, 0, 0, 20]),
                }],
                |snapshot, config, runtime| {
                    seed_tcp_mapping(runtime, INTERNAL, REMOTE, 53);
                    let frame = tcp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 40, 5, None);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;

                    // Contract: an exact (interface, target) neighbor is
                    // accepted; changing either equality must not reject it
                    // (3920's two equality mutants).
                    assert!(matches!(
                        decide_tcp_inbound(
                            &frame,
                            snapshot,
                            &config,
                            runtime,
                            ipv4,
                            &mut resolution,
                        ),
                        Ok(super::super::PacketDecision::Nat44Tcp(_))
                    ));
                },
            );

            with_tcp_runtime_on(
                &routes,
                &[Neighbor {
                    interface: WAN,
                    target: INTERNAL,
                    mac: MacAddress([2, 0, 0, 0, 0, 21]),
                }],
                |snapshot, config, runtime| {
                    seed_tcp_mapping(runtime, INTERNAL, REMOTE, 53);
                    let frame = tcp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 40, 5, None);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;

                    // Contract: matching only the target is insufficient;
                    // the neighbor interface must be the reverse egress
                    // (3920's && mutant).
                    assert!(matches!(
                        decide_tcp_inbound(
                            &frame,
                            snapshot,
                            &config,
                            runtime,
                            ipv4,
                            &mut resolution,
                        ),
                        Err(NeighborUnresolved)
                    ));
                },
            );

            with_tcp_runtime_on(
                &routes,
                &[Neighbor {
                    interface: LAN,
                    target: Ipv4Address::from_octets([10, 0, 0, 11]),
                    mac: MacAddress([2, 0, 0, 0, 0, 22]),
                }],
                |snapshot, config, runtime| {
                    seed_tcp_mapping(runtime, INTERNAL, REMOTE, 53);
                    let frame = tcp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 40, 5, None);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;

                    // Contract: matching only the interface is insufficient;
                    // the neighbor target must equal the reverse target
                    // (3920's target equality mutant).
                    assert!(matches!(
                        decide_tcp_inbound(
                            &frame,
                            snapshot,
                            &config,
                            runtime,
                            ipv4,
                            &mut resolution,
                        ),
                        Err(NeighborUnresolved)
                    ));
                },
            );
        }

        #[test]
        fn rest_decide_nat44_tcp_inbound_queues_arp_from_reverse_binding() {
            let target = Ipv4Address::from_octets([10, 0, 0, 20]);
            let routes = standard_nat_routes();
            with_tcp_runtime_on(&routes, &[], |snapshot, config, runtime| {
                seed_tcp_mapping(runtime, target, REMOTE, 53);
                let frame = tcp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 40, 5, None);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let mut states = [ResolutionStateSlot::EMPTY; 1];
                let mut actions = [ResolutionActionSlot::EMPTY; 1];
                let mut resolution_runtime = ResolutionRuntime::new(
                    ResolutionPolicy::new(1_000, 2_000).unwrap(),
                    &mut states,
                    &mut actions,
                );
                let mut resolution = Some((&mut resolution_runtime, MonotonicMillis(0)));

                // Contract: a dynamic inbound miss queues ARP from the local
                // binding belonging to the selected reverse interface (3933).
                assert!(matches!(
                    decide_tcp_inbound(&frame, snapshot, &config, runtime, ipv4, &mut resolution,),
                    Err(NeighborUnresolved)
                ));
                let (action, _) = resolution_runtime.queued_action(0).unwrap();
                assert_eq!(action.egress, LAN);
                assert_eq!(action.source_mac, MacAddress([2, 0, 0, 0, 0, 1]));
                assert_eq!(action.source_ip, INTERNAL);
                assert_eq!(action.target_ip, target);
            });
        }

        #[test]
        fn rest_validate_nat44_tcp_rejects_short_ipv4_payload_with_frame_padding() {
            let frame = tcp_frame_with_checksum(INTERNAL, REMOTE, 12_345, 443, 30, 5, None);
            let ipv4 = validate_ipv4_frame(&frame).unwrap();

            // Contract: the minimum TCP header must fit inside the declared
            // IPv4 payload even when Ethernet padding supplies those bytes
            // in the frame (4018's `||` and `>` mutants, missed 66/67).
            assert_eq!(
                super::super::validate_nat44_tcp(&frame, ipv4),
                Err(Nat44TcpHeaderTruncated)
            );
        }

        #[test]
        fn rest_tcp_checksum_valid_requires_the_final_end_around_carry() {
            // Contract: checksum validation must reject arbitrary invalid
            // content; replacing the helper's result with `true` (4050)
            // must fail this assertion.
            assert!(!super::super::tcp_checksum_valid(REMOTE, PUBLIC, &[0]));

            let source = Ipv4Address::from_octets([255, 255, 0, 0]);
            let destination = Ipv4Address::from_octets([0, 248, 0, 0]);
            // Contract: a valid odd-length checksum whose pseudo-header and
            // final byte leave a carry must be folded before comparison
            // (4069, missed 71).
            assert!(super::super::tcp_checksum_valid(
                source,
                destination,
                &[0xff]
            ));
        }

        #[test]
        fn rest_validate_nat44_udp_separates_ipv4_length_from_frame_padding() {
            let frame = udp_frame_with_checksum(REMOTE, PUBLIC, 53, 40_000, 26, 8, 0);
            let ipv4 = validate_ipv4_frame(&frame).unwrap();

            // Contract: the complete UDP header must fit inside IPv4's
            // declared payload, not merely inside Ethernet padding (4179's
            // `||` mutant, missed 72).
            assert_eq!(
                super::super::validate_nat44_udp(&frame, ipv4),
                Err(Nat44UdpHeaderTruncated)
            );
        }

        #[test]
        fn rest_build_nat44_udp_maps_updated_mathematical_zero_to_wire_zero() {
            with_udp_runtime(|_, _, runtime| {
                let transition = runtime.plan_outbound(INTERNAL, 1_000, REMOTE, 0).unwrap();
                let udp = super::super::ValidatedNat44Udp {
                    offset: 34,
                    source_port: 0,
                    destination_port: u16::MAX,
                    checksum: 0xffff,
                };
                let decision = super::super::build_nat44_udp_rewrite(
                    synthetic_ipv4(17, INTERNAL, REMOTE, 28),
                    udp,
                    forwarding_decision(),
                    INTERNAL,
                    INTERNAL,
                    0,
                    u16::MAX,
                    super::super::Nat44UdpTransition::Outbound(transition),
                    super::super::Nat44UdpDisposition::OutboundTranslated {
                        public_port: u16::MAX,
                        mapping_created: true,
                        peer_created: true,
                    },
                )
                .unwrap();
                let super::super::PacketDecision::Nat44Udp(decision) = decision else {
                    panic!("expected UDP NAT rewrite");
                };

                // Contract: mathematical checksum zero is emitted as
                // one's-complement negative zero (4258's `==` mutant,
                // missed 75).
                assert_eq!(decision.udp_checksum, 0xffff);
            });
        }

        #[test]
        fn rest_decide_icmpv4_error_checks_each_reverse_delivery_guard() {
            let destination = Ipv4Address::from_octets([198, 51, 100, 99]);

            let routes = standard_nat_routes();
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [
                LocalIpv4Binding {
                    interface: LAN,
                    address: INTERNAL,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: PUBLIC,
                },
            ];
            with_snapshot(&routes, &interfaces, &[], &bindings, |snapshot| {
                with_icmp_error_runtime(|errors| {
                    let frame = generic_error_frame(
                        Ipv4Address::from_octets([0, 0, 0, 1]),
                        destination,
                        17,
                    );
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;
                    let disposition = super::super::decide_icmpv4_error(
                        &frame,
                        snapshot,
                        ipv4,
                        None,
                        crate::Icmpv4ErrorKind::TimeExceededTtl,
                        &mut resolution,
                        errors,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    );

                    // Contract: a non-unicast source is suppressed before
                    // any reverse lookup (4517, source guard).
                    assert_eq!(disposition, Icmpv4ErrorDisposition::SourceNotUnicast);
                });
            });

            with_snapshot(&[], &[], &[], &[], |snapshot| {
                with_icmp_error_runtime(|errors| {
                    let frame = generic_error_frame(REMOTE, destination, 17);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;
                    let disposition = super::super::decide_icmpv4_error(
                        &frame,
                        snapshot,
                        ipv4,
                        None,
                        crate::Icmpv4ErrorKind::TimeExceededTtl,
                        &mut resolution,
                        errors,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    );

                    // Contract: an absent route for the original source
                    // suppresses ICMP generation (4568, reverse route guard).
                    assert_eq!(disposition, Icmpv4ErrorDisposition::ReverseRouteMiss);
                });
            });

            let routes = standard_nat_routes();
            let bindings = [LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            }];
            with_snapshot(&routes, &interfaces, &[], &bindings, |snapshot| {
                with_icmp_error_runtime(|errors| {
                    with_resolution_runtime(|resolution_runtime| {
                        let frame = generic_error_frame(REMOTE, destination, 17);
                        let ipv4 = validate_ipv4_frame(&frame).unwrap();
                        let disposition = {
                            let mut resolution =
                                Some((&mut *resolution_runtime, MonotonicMillis(0)));
                            super::super::decide_icmpv4_error(
                                &frame,
                                snapshot,
                                ipv4,
                                None,
                                crate::Icmpv4ErrorKind::TimeExceededTtl,
                                &mut resolution,
                                errors,
                                MonotonicMillis(0),
                                &mut NoTrace,
                            )
                        };

                        // Contract: the reverse-route egress must select its
                        // matching interface (4575, interface equality).
                        assert_eq!(
                            disposition,
                            Icmpv4ErrorDisposition::ReverseNeighborUnresolved {
                                egress: WAN,
                                target: ROUTER,
                                resolution: crate::ResolutionResult::Queued,
                            }
                        );
                        let (action, _) = resolution_runtime.queued_action(0).unwrap();
                        assert_eq!(action.source_mac, MacAddress([2, 0, 0, 0, 0, 2]));
                    })
                })
            });

            with_snapshot(&routes, &interfaces, &[], &bindings, |snapshot| {
                with_icmp_error_runtime(|errors| {
                    with_resolution_runtime(|resolution_runtime| {
                        let frame = generic_error_frame(REMOTE, destination, 17);
                        let ipv4 = validate_ipv4_frame(&frame).unwrap();
                        let disposition = {
                            let mut resolution =
                                Some((&mut *resolution_runtime, MonotonicMillis(0)));
                            super::super::decide_icmpv4_error(
                                &frame,
                                snapshot,
                                ipv4,
                                None,
                                crate::Icmpv4ErrorKind::TimeExceededTtl,
                                &mut resolution,
                                errors,
                                MonotonicMillis(0),
                                &mut NoTrace,
                            )
                        };

                        // Contract: the reverse egress must have a local
                        // IPv4 binding (4584, binding equality).
                        assert_eq!(
                            disposition,
                            Icmpv4ErrorDisposition::ReverseNeighborUnresolved {
                                egress: WAN,
                                target: ROUTER,
                                resolution: crate::ResolutionResult::Queued,
                            }
                        );
                        let (action, _) = resolution_runtime.queued_action(0).unwrap();
                        assert_eq!(action.source_ip, PUBLIC);
                    })
                })
            });

            let target_binding = [LocalIpv4Binding {
                interface: WAN,
                address: ROUTER,
            }];
            with_snapshot(&routes, &interfaces, &[], &target_binding, |snapshot| {
                with_icmp_error_runtime(|errors| {
                    let frame = generic_error_frame(REMOTE, destination, 17);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;
                    let disposition = super::super::decide_icmpv4_error(
                        &frame,
                        snapshot,
                        ipv4,
                        None,
                        crate::Icmpv4ErrorKind::TimeExceededTtl,
                        &mut resolution,
                        errors,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    );

                    // Contract: a reverse target that is locally bound is
                    // forbidden before neighbor resolution (4591, target guard).
                    assert_eq!(
                        disposition,
                        Icmpv4ErrorDisposition::ReverseTargetForbidden {
                            egress: WAN,
                            target: ROUTER,
                        }
                    );
                });
            });

            let wrong_neighbor = [Neighbor {
                interface: WAN,
                target: PUBLIC2,
                mac: MacAddress([2, 0, 0, 0, 0, 99]),
            }];
            with_snapshot(
                &routes,
                &interfaces,
                &wrong_neighbor,
                &bindings,
                |snapshot| {
                    with_icmp_error_runtime(|errors| {
                        with_resolution_runtime(|resolution_runtime| {
                            let frame = generic_error_frame(REMOTE, destination, 17);
                            let ipv4 = validate_ipv4_frame(&frame).unwrap();
                            let disposition = {
                                let mut resolution =
                                    Some((&mut *resolution_runtime, MonotonicMillis(0)));
                                super::super::decide_icmpv4_error(
                                    &frame,
                                    snapshot,
                                    ipv4,
                                    None,
                                    crate::Icmpv4ErrorKind::TimeExceededTtl,
                                    &mut resolution,
                                    errors,
                                    MonotonicMillis(0),
                                    &mut NoTrace,
                                )
                            };

                            // Contract: a static neighbor is usable only when
                            // both interface and target match (4601, neighbor
                            // pair guard).
                            assert_eq!(
                                disposition,
                                Icmpv4ErrorDisposition::ReverseNeighborUnresolved {
                                    egress: WAN,
                                    target: ROUTER,
                                    resolution: crate::ResolutionResult::Queued,
                                }
                            );
                            assert_eq!(resolution_runtime.pending_actions(), 1);
                        })
                    })
                },
            );
        }

        #[test]
        fn rest_decide_icmpv4_error_rejects_ethernet_fragment_and_icmp_error_inputs() {
            let routes = standard_nat_routes();
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [
                LocalIpv4Binding {
                    interface: LAN,
                    address: INTERNAL,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: PUBLIC,
                },
            ];
            let destination = Ipv4Address::from_octets([198, 51, 100, 99]);

            with_snapshot(&routes, &interfaces, &[], &bindings, |snapshot| {
                with_icmp_error_runtime(|errors| {
                    let mut frame = generic_error_frame(REMOTE, destination, 17);
                    frame[0] = 1;
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;
                    let disposition = super::super::decide_icmpv4_error(
                        &frame,
                        snapshot,
                        ipv4,
                        None,
                        crate::Icmpv4ErrorKind::TimeExceededTtl,
                        &mut resolution,
                        errors,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    );

                    // Contract: an Ethernet group destination is rejected
                    // before reverse route resolution (4546).
                    assert_eq!(
                        disposition,
                        Icmpv4ErrorDisposition::EthernetDestinationGroup
                    );
                });

                with_icmp_error_runtime(|errors| {
                    let mut frame = generic_error_frame(REMOTE, destination, 17);
                    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
                    frame[24..26].fill(0);
                    let checksum = ipv4_header_checksum(&frame[14..34]);
                    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;
                    let disposition = super::super::decide_icmpv4_error(
                        &frame,
                        snapshot,
                        ipv4,
                        None,
                        crate::Icmpv4ErrorKind::TimeExceededTtl,
                        &mut resolution,
                        errors,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    );

                    // Contract: a non-initial IPv4 fragment cannot generate
                    // an ICMP error (4556).
                    assert_eq!(disposition, Icmpv4ErrorDisposition::NonInitialFragment);
                });

                with_icmp_error_runtime(|errors| {
                    let frame = generic_error_frame(REMOTE, destination, 1);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;
                    let disposition = super::super::decide_icmpv4_error(
                        &frame,
                        snapshot,
                        ipv4,
                        None,
                        crate::Icmpv4ErrorKind::TimeExceededTtl,
                        &mut resolution,
                        errors,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    );

                    // Contract: an ICMP packet whose type byte is outside
                    // IPv4 Total Length is not eligible for error generation
                    // (4560/4741).
                    assert_eq!(disposition, Icmpv4ErrorDisposition::IcmpTypeMissing);
                });

                with_icmp_error_runtime(|errors| {
                    let mut frame = generic_error_frame(REMOTE, destination, 1);
                    frame[16..18].copy_from_slice(&21_u16.to_be_bytes());
                    frame[34] = 3;
                    frame[24..26].fill(0);
                    let checksum = ipv4_header_checksum(&frame[14..34]);
                    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    let mut resolution = None;
                    let disposition = super::super::decide_icmpv4_error(
                        &frame,
                        snapshot,
                        ipv4,
                        None,
                        crate::Icmpv4ErrorKind::TimeExceededTtl,
                        &mut resolution,
                        errors,
                        MonotonicMillis(0),
                        &mut NoTrace,
                    );

                    // Contract: ICMP error messages are not allowed to
                    // recursively trigger another error (4563).
                    assert_eq!(disposition, Icmpv4ErrorDisposition::IcmpErrorMessage);
                });
            });
        }

        #[test]
        fn rest_decide_icmpv4_error_rejects_destination_and_reverse_target_classes() {
            let routes = standard_nat_routes();
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [
                LocalIpv4Binding {
                    interface: LAN,
                    address: INTERNAL,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: PUBLIC,
                },
            ];
            let destination = Ipv4Address::from_octets([198, 51, 100, 99]);

            with_snapshot(&routes, &interfaces, &[], &bindings, |snapshot| {
                for (destination, expected) in [
                    (
                        Ipv4Address::from_octets([224, 0, 0, 1]),
                        Icmpv4ErrorDisposition::DestinationMulticast,
                    ),
                    (
                        Ipv4Address::from_octets([255; 4]),
                        Icmpv4ErrorDisposition::DestinationLimitedBroadcast,
                    ),
                ] {
                    with_icmp_error_runtime(|errors| {
                        let frame = generic_error_frame(REMOTE, destination, 17);
                        let ipv4 = validate_ipv4_frame(&frame).unwrap();
                        let mut resolution = None;
                        let disposition = super::super::decide_icmpv4_error(
                            &frame,
                            snapshot,
                            ipv4,
                            None,
                            crate::Icmpv4ErrorKind::TimeExceededTtl,
                            &mut resolution,
                            errors,
                            MonotonicMillis(0),
                            &mut NoTrace,
                        );

                        // Contract: multicast and limited-broadcast IPv4
                        // destinations are independently suppressed (4528-4534).
                        assert_eq!(disposition, expected);
                    });
                }

                let selected_route =
                    Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap();
                for (destination, expected) in [
                    (
                        Ipv4Address::from_octets([198, 51, 100, 0]),
                        Icmpv4ErrorDisposition::DestinationNetworkAddress,
                    ),
                    (
                        Ipv4Address::from_octets([198, 51, 100, 255]),
                        Icmpv4ErrorDisposition::DestinationDirectedBroadcast,
                    ),
                ] {
                    with_icmp_error_runtime(|errors| {
                        let frame = generic_error_frame(REMOTE, destination, 17);
                        let ipv4 = validate_ipv4_frame(&frame).unwrap();
                        let mut resolution = None;
                        let disposition = super::super::decide_icmpv4_error(
                            &frame,
                            snapshot,
                            ipv4,
                            Some(selected_route),
                            crate::Icmpv4ErrorKind::TimeExceededTtl,
                            &mut resolution,
                            errors,
                            MonotonicMillis(0),
                            &mut NoTrace,
                        );

                        // Contract: the selected destination route's network
                        // and directed-broadcast addresses are suppressed
                        // (4537-4544).
                        assert_eq!(disposition, expected);
                    });
                }
            });

            // Mutants 79-83 change only the resolution authority boolean,
            // but reverse_target_forbidden below returns before that boolean
            // can be evaluated.  The coherent snapshot invariant makes these
            // substitutions equivalent and intentionally leaves no test here
            // that pretends the unreachable branch is observable.
            let network = Ipv4Address::from_octets([198, 51, 100, 0]);
            let network_routes = [
                Route::new(network, 24, WAN, None).unwrap(),
                Route::new(REMOTE, 32, WAN, Some(network)).unwrap(),
            ];
            let wan_interfaces = [Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            let wan_binding = [LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            }];
            with_snapshot(
                &network_routes,
                &wan_interfaces,
                &[],
                &wan_binding,
                |snapshot| {
                    with_icmp_error_runtime(|errors| {
                        let frame = generic_error_frame(REMOTE, destination, 17);
                        let ipv4 = validate_ipv4_frame(&frame).unwrap();
                        let mut resolution = None;
                        let disposition = super::super::decide_icmpv4_error(
                            &frame,
                            snapshot,
                            ipv4,
                            None,
                            crate::Icmpv4ErrorKind::TimeExceededTtl,
                            &mut resolution,
                            errors,
                            MonotonicMillis(0),
                            &mut NoTrace,
                        );

                        // Contract: a connected reverse network address is
                        // forbidden before ARP scheduling (4591/4765-4766).
                        assert_eq!(
                            disposition,
                            Icmpv4ErrorDisposition::ReverseTargetForbidden {
                                egress: WAN,
                                target: network,
                            }
                        );
                    });
                },
            );

            let directed_broadcast = Ipv4Address::from_octets([198, 51, 100, 255]);
            let broadcast_routes = [
                Route::new(network, 24, WAN, None).unwrap(),
                Route::new(REMOTE, 32, WAN, Some(directed_broadcast)).unwrap(),
            ];
            with_snapshot(
                &broadcast_routes,
                &wan_interfaces,
                &[],
                &wan_binding,
                |snapshot| {
                    with_icmp_error_runtime(|errors| {
                        let frame = generic_error_frame(REMOTE, destination, 17);
                        let ipv4 = validate_ipv4_frame(&frame).unwrap();
                        let mut resolution = None;
                        let disposition = super::super::decide_icmpv4_error(
                            &frame,
                            snapshot,
                            ipv4,
                            None,
                            crate::Icmpv4ErrorKind::TimeExceededTtl,
                            &mut resolution,
                            errors,
                            MonotonicMillis(0),
                            &mut NoTrace,
                        );

                        // Contract: a connected reverse directed-broadcast
                        // address is forbidden before ARP scheduling (4591/4765).
                        assert_eq!(
                            disposition,
                            Icmpv4ErrorDisposition::ReverseTargetForbidden {
                                egress: WAN,
                                target: directed_broadcast,
                            }
                        );
                    });
                },
            );
        }

        #[test]
        fn rest_icmp_error_source_host_checks_boundaries_and_route_addresses() {
            let routes =
                [Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap()];
            let interfaces = [Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            with_snapshot(&routes, &interfaces, &[], &[], |snapshot| {
                for (octets, expected) in [
                    ([0, 0, 0, 1], false),
                    ([127, 0, 0, 1], false),
                    ([223, 0, 0, 1], true),
                    ([224, 0, 0, 1], false),
                    ([198, 51, 100, 0], false),
                    ([198, 51, 100, 255], false),
                    ([198, 51, 100, 1], true),
                ] {
                    // Contract: source classification rejects 0/127/224
                    // boundaries and connected network/broadcast addresses,
                    // while accepting ordinary unicast hosts (4686-4693,
                    // mutants 84-89).
                    assert_eq!(
                        super::super::icmp_error_source_is_host(
                            snapshot,
                            Ipv4Address::from_octets(octets),
                        ),
                        expected,
                        "source {octets:?}"
                    );
                }
            });
        }

        #[test]
        fn rest_icmp_error_candidate_eligibility_checks_all_mutated_guards() {
            let normal_destination = Ipv4Address::from_octets([198, 51, 100, 99]);
            with_snapshot(&[], &[], &[], &[], |snapshot| {
                let frame = generic_error_frame(REMOTE, normal_destination, 17);

                // Contract: an ordinary host packet passes every candidate
                // prerequisite (mutant 90).
                assert!(candidate_eligible(&frame, snapshot, None));
            });

            let local_interface = [Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            let local_source = [LocalIpv4Binding {
                interface: LAN,
                address: REMOTE,
            }];
            with_snapshot(&[], &local_interface, &[], &local_source, |snapshot| {
                let frame = generic_error_frame(REMOTE, normal_destination, 17);

                // Contract: a locally bound source is ineligible even when
                // all other candidate conditions pass (mutants 91/92).
                assert!(!candidate_eligible(&frame, snapshot, None));
            });

            with_snapshot(&[], &[], &[], &[], |snapshot| {
                let multicast =
                    generic_error_frame(REMOTE, Ipv4Address::from_octets([224, 0, 0, 1]), 17);
                // Contract: multicast destinations are excluded (mutants 93/94).
                assert!(!candidate_eligible(&multicast, snapshot, None));

                let limited_broadcast =
                    generic_error_frame(REMOTE, Ipv4Address::from_octets([255; 4]), 17);
                // Contract: limited broadcast is excluded independently of
                // multicast detection (mutant 95).
                assert!(!candidate_eligible(&limited_broadcast, snapshot, None));
            });

            let selected_route =
                Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap();
            let selected_interface = [Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            with_snapshot(
                std::slice::from_ref(&selected_route),
                &selected_interface,
                &[],
                &[],
                |snapshot| {
                    let network = generic_error_frame(
                        REMOTE,
                        Ipv4Address::from_octets([198, 51, 100, 0]),
                        17,
                    );
                    // Contract: selected-route network addresses are excluded
                    // even with a unicast Ethernet destination (mutants 96/97).
                    assert!(!candidate_eligible(
                        &network,
                        snapshot,
                        Some(selected_route)
                    ));

                    let directed_broadcast = generic_error_frame(
                        REMOTE,
                        Ipv4Address::from_octets([198, 51, 100, 255]),
                        17,
                    );
                    // Contract: selected-route directed broadcasts are also
                    // excluded by the same route guard.
                    assert!(!candidate_eligible(
                        &directed_broadcast,
                        snapshot,
                        Some(selected_route)
                    ));
                },
            );

            with_snapshot(&[], &[], &[], &[], |snapshot| {
                let mut ethernet_group = generic_error_frame(REMOTE, normal_destination, 17);
                ethernet_group[0] = 1;
                // Contract: an Ethernet group destination is ineligible even
                // for an ordinary IPv4 host destination (mutant 98).
                assert!(!candidate_eligible(&ethernet_group, snapshot, None));

                let mut noninitial_fragment = generic_error_frame(REMOTE, normal_destination, 17);
                noninitial_fragment[20..22].copy_from_slice(&1_u16.to_be_bytes());
                noninitial_fragment[24..26].fill(0);
                let checksum = ipv4_header_checksum(&noninitial_fragment[14..34]);
                noninitial_fragment[24..26].copy_from_slice(&checksum.to_be_bytes());
                // Contract: a non-initial fragment is ineligible (mutant 99).
                assert!(!candidate_eligible(&noninitial_fragment, snapshot, None));
            });

            with_snapshot(&[], &[], &[], &[], |snapshot| {
                let missing_type = generic_error_frame(REMOTE, normal_destination, 1);
                // Contract: an ICMP packet without an in-bounds type byte is
                // ineligible, even when padding contains bytes (4728-4729).
                assert!(!candidate_eligible(&missing_type, snapshot, None));

                let mut error_message = generic_error_frame(REMOTE, normal_destination, 1);
                error_message[16..18].copy_from_slice(&21_u16.to_be_bytes());
                error_message[34] = 3;
                error_message[24..26].fill(0);
                let checksum = ipv4_header_checksum(&error_message[14..34]);
                error_message[24..26].copy_from_slice(&checksum.to_be_bytes());
                // Contract: ICMP error messages cannot recursively generate
                // another error (4731-4732).
                assert!(!candidate_eligible(&error_message, snapshot, None));
            });
        }

        #[test]
        fn rest_icmpv4_type_within_total_length_reads_only_an_in_bounds_type() {
            let destination = Ipv4Address::from_octets([198, 51, 100, 99]);
            let mut frame = generic_error_frame(REMOTE, destination, 1);
            frame[16..18].copy_from_slice(&21_u16.to_be_bytes());
            frame[34] = 8;
            frame[24..26].fill(0);
            let checksum = ipv4_header_checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            let ipv4 = validate_ipv4_frame(&frame).unwrap();

            // Contract: the type byte is returned when its offset is strictly
            // inside IPv4 Total Length (4741 `<`, mutant 100).
            assert_eq!(
                super::super::icmpv4_type_within_total_length(&frame, ipv4),
                Some(8)
            );
        }

        #[test]
        fn rest_reverse_target_forbidden_checks_special_and_snapshot_evidence() {
            let ordinary = Ipv4Address::from_octets([198, 51, 100, 9]);
            with_snapshot(&[], &[], &[], &[], |snapshot| {
                for target in [
                    Ipv4Address::from_octets([0, 0, 0, 1]),
                    Ipv4Address::from_octets([127, 0, 0, 1]),
                    Ipv4Address::from_octets([224, 0, 0, 1]),
                    Ipv4Address::from_octets([255; 4]),
                ] {
                    // Contract: unspecified, loopback, class-D, and limited
                    // broadcast targets are always forbidden (4753-4757,
                    // mutants 101/105-107).
                    assert!(super::super::reverse_target_forbidden(
                        snapshot, WAN, target, PUBLIC
                    ));
                }

                // Contract: an ordinary host target is allowed when no local
                // or connected-route evidence applies (4753-4767).
                assert!(!super::super::reverse_target_forbidden(
                    snapshot, WAN, ordinary, PUBLIC
                ));

                // Contract: the selected local source itself cannot also be
                // the reverse target (4758 `||`, mutant 103).
                assert!(super::super::reverse_target_forbidden(
                    snapshot, WAN, ordinary, ordinary
                ));
            });

            let local_interface = [Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            let target_binding = [LocalIpv4Binding {
                interface: LAN,
                address: ordinary,
            }];
            with_snapshot(&[], &local_interface, &[], &target_binding, |snapshot| {
                // Contract: any local binding for the target forbids it,
                // even when the supplied local source differs (4759,
                // mutant 104).
                assert!(super::super::reverse_target_forbidden(
                    snapshot, WAN, ordinary, PUBLIC,
                ));
            });

            let connected_network = Ipv4Address::from_octets([198, 51, 100, 0]);
            let connected_route = [Route::new(connected_network, 24, LAN, None).unwrap()];
            with_snapshot(&connected_route, &local_interface, &[], &[], |snapshot| {
                // Contract: connected network evidence forbids a target
                // on the same egress (4763-4767, mutant 109).
                assert!(super::super::reverse_target_forbidden(
                    snapshot,
                    LAN,
                    connected_network,
                    PUBLIC,
                ));

                // Contract: the same connected route must not authorize
                // a target on a different egress (4764 equality, mutant
                // 108).
                assert!(!super::super::reverse_target_forbidden(
                    snapshot,
                    WAN,
                    connected_network,
                    PUBLIC,
                ));
            });

            let connected_broadcast = Ipv4Address::from_octets([198, 51, 100, 255]);
            with_snapshot(&connected_route, &local_interface, &[], &[], |snapshot| {
                // Contract: connected directed-broadcast evidence is
                // also forbidden on the matching egress (4765-4766,
                // mutant 109).
                assert!(super::super::reverse_target_forbidden(
                    snapshot,
                    LAN,
                    connected_broadcast,
                    PUBLIC,
                ));
            });
        }

        #[test]
        fn rest_decide_local_ipv4_checks_all_echo_request_guards() {
            let destination = INTERNAL;
            let empty_interfaces: [Interface; 0] = [];
            let empty_bindings: [LocalIpv4Binding; 0] = [];
            with_snapshot(&[], &empty_interfaces, &[], &empty_bindings, |snapshot| {
                let frame = vec![0_u8; 60];
                let ipv4 = synthetic_ipv4(1, REMOTE, destination, 28);
                let mut trace = NoTrace;
                let mut options_ipv4 = ipv4;
                options_ipv4.header_len = 24;

                // Contract: IPv4 options are not accepted by the local
                // ICMP path (4777 `>`, mutant 110).
                assert!(matches!(
                    super::super::decide_local_ipv4(
                        &frame,
                        snapshot,
                        LAN,
                        options_ipv4,
                        None,
                        &mut trace,
                    ),
                    Err(Ipv4OptionsUnsupported)
                ));

                let short_icmp = vec![0_u8; 37];
                let short_ipv4 = synthetic_ipv4(1, REMOTE, destination, 23);
                // Contract: an ICMP header shorter than four bytes is
                // truncated, including a three-byte range (4801 `<`,
                // mutant 111).
                assert!(matches!(
                    super::super::decide_local_ipv4(
                        &short_icmp,
                        snapshot,
                        LAN,
                        short_ipv4,
                        None,
                        &mut trace,
                    ),
                    Err(Icmpv4HeaderTruncated)
                ));

                let mut exact_icmp = vec![0_u8; 38];
                exact_icmp[36..38].copy_from_slice(&0xffff_u16.to_be_bytes());
                let exact_ipv4 = synthetic_ipv4(1, REMOTE, destination, 24);
                // Contract: exactly four ICMP bytes are sufficient for a
                // non-echo local consume (4801 `<=`, mutant 112).
                assert!(matches!(
                    super::super::decide_local_ipv4(
                        &exact_icmp,
                        snapshot,
                        LAN,
                        exact_ipv4,
                        None,
                        &mut trace,
                    ),
                    Ok(super::super::PacketDecision::ConsumeIpv4Local)
                ));

                let mut invalid_non_echo = vec![0_u8; 38];
                invalid_non_echo[34] = 3;
                let invalid_non_echo_ipv4 = synthetic_ipv4(1, REMOTE, destination, 24);
                // Contract: a non-echo ICMP message still requires a
                // valid checksum (4805 `!=`, mutant 113).
                assert!(matches!(
                    super::super::decide_local_ipv4(
                        &invalid_non_echo,
                        snapshot,
                        LAN,
                        invalid_non_echo_ipv4,
                        None,
                        &mut trace,
                    ),
                    Err(Icmpv4ChecksumInvalid)
                ));

                let mut short_echo = vec![0_u8; 40];
                short_echo[34] = 8;
                short_echo[35] = 0;
                let short_echo_ipv4 = synthetic_ipv4(1, REMOTE, destination, 26);
                // Contract: an echo request must include its complete
                // eight-byte header (4813 `<`, mutant 114).
                assert!(matches!(
                    super::super::decide_local_ipv4(
                        &short_echo,
                        snapshot,
                        LAN,
                        short_echo_ipv4,
                        None,
                        &mut trace,
                    ),
                    Err(Icmpv4EchoHeaderTruncated)
                ));
            });

            let interface = [Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            let destination_binding = [LocalIpv4Binding {
                interface: LAN,
                address: destination,
            }];
            with_snapshot(&[], &interface, &[], &destination_binding, |snapshot| {
                let mut frame =
                    echo_request_frame(Ipv4Address::from_octets([0, 0, 0, 1]), destination);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let mut trace = NoTrace;
                // Contract: a source rejected by sender_is_host is not
                // accepted merely because no local binding matches it
                // (4825 `||`, mutant 115).
                assert!(matches!(
                    super::super::decide_local_ipv4(&frame, snapshot, LAN, ipv4, None, &mut trace,),
                    Err(Icmpv4SourceNotUnicast)
                ));

                frame = echo_request_frame(REMOTE, destination);
                let ipv4 = validate_ipv4_frame(&frame).unwrap();
                let local_source = [LocalIpv4Binding {
                    interface: LAN,
                    address: REMOTE,
                }];
                with_snapshot(&[], &interface, &[], &local_source, |snapshot| {
                    // Contract: a source bound on the ingress interface is
                    // rejected (4829 equality, mutant 116).
                    assert!(matches!(
                        super::super::decide_local_ipv4(
                            &frame, snapshot, LAN, ipv4, None, &mut trace,
                        ),
                        Err(Icmpv4SourceNotUnicast)
                    ));
                });

                let mut zero_requester = echo_request_frame(REMOTE, destination);
                zero_requester[6..12].fill(0);
                let ipv4 = validate_ipv4_frame(&zero_requester).unwrap();
                let mut trace = NoTrace;
                // Contract: an all-zero requester hardware address is
                // rejected independently of multicast detection (4838 `||`,
                // mutant 117).
                assert!(matches!(
                    super::super::decide_local_ipv4(
                        &zero_requester,
                        snapshot,
                        LAN,
                        ipv4,
                        None,
                        &mut trace,
                    ),
                    Err(Icmpv4EthernetSourceInvalid)
                ));

                let mut wrong_destination = echo_request_frame(REMOTE, destination);
                wrong_destination[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
                let ipv4 = validate_ipv4_frame(&wrong_destination).unwrap();
                // Contract: an echo request addressed to another interface
                // is not handled as local traffic (4841).
                assert!(matches!(
                    super::super::decide_local_ipv4(
                        &wrong_destination,
                        snapshot,
                        LAN,
                        ipv4,
                        None,
                        &mut trace,
                    ),
                    Err(Icmpv4EthernetDestinationNotLocal)
                ));
            });
        }

        #[test]
        fn rest_decide_local_ipv4_checks_the_timestamp_request_source_guard() {
            // Contract: a Timestamp request shares the same unicast-source
            // guard an Echo request already enforces (RFC 1812 §4.3.2.9).
            let destination = INTERNAL;
            let interface = [Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            let destination_binding = [LocalIpv4Binding {
                interface: LAN,
                address: destination,
            }];
            with_snapshot(&[], &interface, &[], &destination_binding, |snapshot| {
                let mut frame = vec![0_u8; 54];
                frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
                frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
                frame[34] = 13;
                let checksum = internet_checksum(&frame[34..54]);
                frame[36..38].copy_from_slice(&checksum.to_be_bytes());
                let ipv4 =
                    synthetic_ipv4(1, Ipv4Address::from_octets([0, 0, 0, 1]), destination, 40);
                let mut trace = NoTrace;
                assert!(matches!(
                    super::super::decide_local_ipv4(
                        &frame,
                        snapshot,
                        LAN,
                        ipv4,
                        Some(super::super::Icmpv4TimestampClock(0)),
                        &mut trace,
                    ),
                    Err(Icmpv4SourceNotUnicast)
                ));
            });
        }

        #[test]
        fn rest_decide_arp_rejects_each_sender_hardware_class() {
            let interfaces = [Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            with_snapshot(&[], &interfaces, &[], &[], |snapshot| {
                // Contract: an all-zero ARP sender hardware address is
                // rejected before any address or resolution decision (4903,
                // mutant 118).
                assert!(matches!(
                    decide_arp_without_runtime(
                        &arp_frame(ArpOpcode::Request, [0; 6], REMOTE, PUBLIC),
                        snapshot,
                        LAN,
                    ),
                    Err(ArpSenderHardwareZero)
                ));

                // Contract: the Ethernet broadcast value is not a usable ARP
                // sender hardware address (4906, mutant 119).
                assert!(matches!(
                    decide_arp_without_runtime(
                        &arp_frame(ArpOpcode::Request, [0xff; 6], REMOTE, PUBLIC),
                        snapshot,
                        LAN,
                    ),
                    Err(ArpSenderHardwareBroadcast)
                ));

                // Contract: any multicast-bit sender hardware address is
                // rejected independently of the all-broadcast case (4909,
                // mutant 120).
                assert!(matches!(
                    decide_arp_without_runtime(
                        &arp_frame(ArpOpcode::Request, [1, 0, 0, 0, 0, 9], REMOTE, PUBLIC,),
                        snapshot,
                        LAN,
                    ),
                    Err(ArpSenderHardwareMulticast)
                ));
            });
        }

        #[test]
        fn rest_decide_arp_requires_exact_binding_opcode_interface_and_length() {
            let interface = Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            };
            let binding = [LocalIpv4Binding {
                interface: LAN,
                address: INTERNAL,
            }];
            with_snapshot(&[], &[interface], &[], &binding, |snapshot| {
                let request = arp_frame(ArpOpcode::Request, [2, 0, 0, 0, 0, 9], REMOTE, INTERNAL);
                let result = decide_arp_without_runtime(&request, snapshot, LAN);
                let super::super::PacketDecision::ArpReply(reply) = result.unwrap() else {
                    panic!("a request for the exact local binding must be answered");
                };
                // Contract: target-local is true only for the same ingress
                // interface and exact target address (4915, mutants 121-123).
                assert_eq!(reply.egress, LAN);
                assert_eq!(reply.local_mac, interface.mac.0);
                assert_eq!(reply.requester_mac, [2, 0, 0, 0, 0, 9]);
                assert_eq!(reply.requester_protocol, REMOTE.octets());
                assert_eq!(reply.local_protocol, INTERNAL.octets());

                // Contract: a request for a local address reaches the ARP
                // reply path (4975 opcode equality, mutant 131).
                assert!(matches!(
                    decide_arp_without_runtime(&request, snapshot, LAN),
                    Ok(super::super::PacketDecision::ArpReply(_))
                ));

                let reply = arp_frame(ArpOpcode::Reply, [2, 0, 0, 0, 0, 9], REMOTE, INTERNAL);
                // Contract: an ARP Reply is consumed even when its target is
                // local; it must not enter the reply-builder branch (4975
                // `||`, mutant 130).
                assert_eq!(
                    arp_disposition(decide_arp_without_runtime(&reply, snapshot, LAN)),
                    ControlDisposition::Ignored
                );

                let truncated = request[..41].to_vec();
                // Contract: a frame shorter than the complete ARP packet is
                // rejected before decision logic (validate_arp truncation
                // boundary).
                assert!(matches!(
                    decide_arp_without_runtime(&truncated, snapshot, LAN),
                    Err(ArpPacketTruncated)
                ));
            });

            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let target = arp_frame(ArpOpcode::Request, [2, 0, 0, 0, 0, 9], REMOTE, INTERNAL);
            let other_interface_binding = [LocalIpv4Binding {
                interface: WAN,
                address: INTERNAL,
            }];
            with_snapshot(
                &[],
                &interfaces,
                &[],
                &other_interface_binding,
                |snapshot| {
                    // Contract: matching the address on another interface
                    // does not make the ARP target local (4915 `&&`, mutant
                    // 121).
                    assert_eq!(
                        arp_disposition(decide_arp_without_runtime(&target, snapshot, LAN)),
                        ControlDisposition::Ignored
                    );
                },
            );

            let other_address_binding = [LocalIpv4Binding {
                interface: LAN,
                address: PUBLIC,
            }];
            with_snapshot(&[], &interfaces, &[], &other_address_binding, |snapshot| {
                // Contract: matching the ingress interface without matching
                // the ARP target does not make it local (4915 `&&`, mutant
                // 121).
                assert_eq!(
                    arp_disposition(decide_arp_without_runtime(&target, snapshot, LAN)),
                    ControlDisposition::Ignored
                );
            });

            let interfaces_without_ingress = [Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            }];
            let binding_without_ingress = [LocalIpv4Binding {
                interface: WAN,
                address: INTERNAL,
            }];
            with_snapshot(
                &[],
                &interfaces_without_ingress,
                &[],
                &binding_without_ingress,
                |snapshot| {
                    // Contract: an unknown ingress is consumed before a
                    // reply can be built, preserving the exact interface
                    // lookup boundary (4981).
                    assert_eq!(
                        arp_disposition(decide_arp_without_runtime(&target, snapshot, LAN)),
                        ControlDisposition::Ignored
                    );
                },
            );
        }

        #[test]
        fn rest_decide_arp_selects_exact_static_key_and_runtime_branches() {
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let frame = arp_frame(ArpOpcode::Request, [2, 0, 0, 0, 0, 9], REMOTE, PUBLIC);

            let exact_static = [Neighbor {
                interface: LAN,
                target: REMOTE,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_snapshot(&[], &interfaces, &exact_static, &[], |snapshot| {
                // Contract: a static neighbor is selected by the complete
                // ingress-interface and sender-address key (4921/4964,
                // mutants 127-129).
                assert_eq!(
                    arp_disposition(decide_arp_without_runtime(&frame, snapshot, LAN)),
                    ControlDisposition::StaticPreserved
                );
            });

            let wrong_interface_static = [Neighbor {
                interface: WAN,
                target: REMOTE,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_snapshot(&[], &interfaces, &wrong_interface_static, &[], |snapshot| {
                // Contract: a static key on another interface is not
                // usable for this ingress (4921 `&&`, mutant 127).
                assert_eq!(
                    arp_disposition(decide_arp_without_runtime(&frame, snapshot, LAN)),
                    ControlDisposition::Ignored
                );
            });

            let wrong_target_static = [Neighbor {
                interface: LAN,
                target: PUBLIC,
                mac: MacAddress([2, 0, 0, 0, 0, 20]),
            }];
            with_snapshot(&[], &interfaces, &wrong_target_static, &[], |snapshot| {
                // Contract: a static neighbor for a different protocol
                // address does not authorize the ARP sender (4921 `&&`,
                // mutant 127).
                assert_eq!(
                    arp_disposition(decide_arp_without_runtime(&frame, snapshot, LAN)),
                    ControlDisposition::Ignored
                );
            });

            let unspecified = Ipv4Address::from_octets([0, 0, 0, 0]);
            with_snapshot(&[], &interfaces, &[], &[], |snapshot| {
                with_resolution_runtime(|runtime| {
                    let mut resolution = Some((runtime, MonotonicMillis(0)));
                    let mut trace = NoTrace;
                    // Contract: an unspecified ARP sender is a probe control
                    // path, before the generic non-host path (4936).
                    assert_eq!(
                        arp_disposition(super::super::decide_arp(
                            &arp_frame(ArpOpcode::Request, [2, 0, 0, 0, 0, 9], unspecified, PUBLIC,),
                            snapshot,
                            LAN,
                            &mut resolution,
                            &mut trace,
                        )),
                        ControlDisposition::Probe
                    );
                });
            });

            let network = Ipv4Address::from_octets([198, 51, 100, 0]);
            let connected = [Route::new(network, 24, LAN, None).unwrap()];
            with_snapshot(&connected, &interfaces, &[], &[], |snapshot| {
                with_resolution_runtime(|runtime| {
                    let mut resolution = Some((runtime, MonotonicMillis(0)));
                    let mut trace = NoTrace;
                    // Contract: a connected network address is reported as a
                    // non-host sender after the unspecified/local checks
                    // (4949).
                    assert_eq!(
                        arp_disposition(super::super::decide_arp(
                            &arp_frame(ArpOpcode::Request, [2, 0, 0, 0, 0, 9], network, PUBLIC,),
                            snapshot,
                            LAN,
                            &mut resolution,
                            &mut trace,
                        )),
                        ControlDisposition::SenderNotHost
                    );
                });
            });

            let local_sender = [LocalIpv4Binding {
                interface: LAN,
                address: REMOTE,
            }];
            with_snapshot(&[], &interfaces, &[], &local_sender, |snapshot| {
                with_resolution_runtime(|runtime| {
                    let mut resolution = Some((runtime, MonotonicMillis(0)));
                    let mut trace = NoTrace;
                    // Contract: a sender equal to an ingress local binding is
                    // preserved instead of entering host learning (4943).
                    assert_eq!(
                        arp_disposition(super::super::decide_arp(
                            &frame,
                            snapshot,
                            LAN,
                            &mut resolution,
                            &mut trace,
                        )),
                        ControlDisposition::LocalAddressPreserved
                    );
                });
            });

            with_snapshot(&[], &interfaces, &[], &[], |snapshot| {
                with_resolution_runtime(|runtime| {
                    let mut resolution = Some((runtime, MonotonicMillis(0)));
                    let mut trace = NoTrace;
                    // Contract: an ordinary host sender follows the dynamic
                    // merge path; with no dynamic slots and a nonlocal target
                    // that path returns Ignored (4955).
                    assert_eq!(
                        arp_disposition(super::super::decide_arp(
                            &frame,
                            snapshot,
                            LAN,
                            &mut resolution,
                            &mut trace,
                        )),
                        ControlDisposition::Ignored
                    );
                });
            });
        }

        #[test]
        fn rest_sender_is_host_checks_special_boundaries_and_connected_egress() {
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            with_snapshot(&[], &interfaces, &[], &[], |snapshot| {
                // Contract: the unspecified source range is never a host
                // address (5001, mutant 136).
                assert!(!super::super::sender_is_host(
                    snapshot,
                    LAN,
                    Ipv4Address::from_octets([0, 0, 0, 0]),
                ));

                // Contract: the loopback first-octet boundary is rejected
                // independently of the unspecified boundary (5002, mutant
                // 135).
                assert!(!super::super::sender_is_host(
                    snapshot,
                    LAN,
                    Ipv4Address::from_octets([127, 0, 0, 1]),
                ));

                // Contract: 224 is the first multicast/class-D octet and is
                // not included by the strict host range (5003 `<`, mutant
                // 137).
                assert!(!super::super::sender_is_host(
                    snapshot,
                    LAN,
                    Ipv4Address::from_octets([224, 0, 0, 1]),
                ));

                // Contract: an ordinary unicast address with no connected
                // network evidence is a host address (5000, mutant 133).
                assert!(super::super::sender_is_host(snapshot, LAN, REMOTE));
            });

            let network = Ipv4Address::from_octets([198, 51, 100, 0]);
            let broadcast = Ipv4Address::from_octets([198, 51, 100, 255]);
            let connected_on_lan = [Route::new(network, 24, LAN, None).unwrap()];
            with_snapshot(&connected_on_lan, &interfaces, &[], &[], |snapshot| {
                // Contract: a connected network address on the ingress is
                // not a host address (5004 `&&`, mutant 134; 5005 `==`,
                // mutant 139).
                assert!(!super::super::sender_is_host(snapshot, LAN, network));

                // Contract: a connected directed broadcast on the same
                // egress is also forbidden (5007 `||`, mutant 140).
                assert!(!super::super::sender_is_host(snapshot, LAN, broadcast));
            });

            let connected_on_wan = [Route::new(network, 24, WAN, None).unwrap()];
            with_snapshot(&connected_on_wan, &interfaces, &[], &[], |snapshot| {
                // Contract: connected-address evidence from another egress
                // must not affect the ingress decision (5004 route `&&`,
                // mutant 138).
                assert!(super::super::sender_is_host(snapshot, LAN, network));
            });
        }

        #[test]
        fn rest_decide_arp_requires_sender_local_interface_and_address_pair() {
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let target = Ipv4Address::from_octets([198, 51, 100, 21]);
            let frame = arp_frame(ArpOpcode::Request, [2, 0, 0, 0, 0, 9], REMOTE, target);

            let binding_on_ingress_only = [LocalIpv4Binding {
                interface: LAN,
                address: PUBLIC,
            }];
            with_snapshot(
                &[],
                &interfaces,
                &[],
                &binding_on_ingress_only,
                |snapshot| {
                    with_resolution_runtime(|runtime| {
                        let mut resolution = Some((runtime, MonotonicMillis(0)));
                        let mut trace = NoTrace;
                        // Contract: sender_local requires the same interface
                        // and sender address; an interface-only match must
                        // remain ordinary host handling (4919 `&&`, mutant
                        // 124).
                        assert_eq!(
                            arp_disposition(super::super::decide_arp(
                                &frame,
                                snapshot,
                                LAN,
                                &mut resolution,
                                &mut trace,
                            )),
                            ControlDisposition::Ignored
                        );
                    });
                },
            );

            let binding_on_other_interface = [LocalIpv4Binding {
                interface: WAN,
                address: REMOTE,
            }];
            with_snapshot(
                &[],
                &interfaces,
                &[],
                &binding_on_other_interface,
                |snapshot| {
                    with_resolution_runtime(|runtime| {
                        let mut resolution = Some((runtime, MonotonicMillis(0)));
                        let mut trace = NoTrace;
                        // Contract: an address-only match on another
                        // interface is also not sender_local (4919 `&&`,
                        // mutant 124).
                        assert_eq!(
                            arp_disposition(super::super::decide_arp(
                                &frame,
                                snapshot,
                                LAN,
                                &mut resolution,
                                &mut trace,
                            )),
                            ControlDisposition::Ignored
                        );
                    });
                },
            );
        }

        #[test]
        fn rest_decide_icmpv4_error_keeps_cross_egress_connected_targets_unforbidden() {
            let network = Ipv4Address::from_octets([192, 0, 2, 0]);
            let directed_broadcast = Ipv4Address::from_octets([192, 0, 2, 255]);
            let interfaces = [
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: Ipv4Mtu::ETHERNET,
                },
            ];
            let bindings = [LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            }];

            for target in [network, directed_broadcast] {
                let routes = [
                    Route::new(REMOTE, 32, WAN, Some(target)).unwrap(),
                    Route::new(network, 24, LAN, None).unwrap(),
                ];
                with_snapshot(&routes, &interfaces, &[], &bindings, |snapshot| {
                    with_icmp_error_runtime(|errors| {
                        with_resolution_runtime(|resolution_runtime| {
                            let frame = generic_error_frame(REMOTE, PUBLIC, 17);
                            let ipv4 = validate_ipv4_frame(&frame).unwrap();
                            let mut resolution =
                                Some((&mut *resolution_runtime, MonotonicMillis(0)));
                            let disposition = super::super::decide_icmpv4_error(
                                &frame,
                                snapshot,
                                ipv4,
                                None,
                                crate::Icmpv4ErrorKind::TimeExceededTtl,
                                &mut resolution,
                                errors,
                                MonotonicMillis(0),
                                &mut NoTrace,
                            );

                            // Contract: connected network/broadcast evidence
                            // on another egress does not authorize or forbid
                            // the reverse ARP target; authority stays false,
                            // so scheduling is Queued (4635 `==`, mutant 82).
                            assert_eq!(
                                disposition,
                                Icmpv4ErrorDisposition::ReverseNeighborUnresolved {
                                    egress: WAN,
                                    target,
                                    resolution: crate::ResolutionResult::Queued,
                                }
                            );
                            assert_eq!(resolution_runtime.pending_actions(), 1);
                        });
                    });
                });
            }
        }
    }
}

use crate::firewall::{FirewallPacket, FirewallPlan, FirewallPlanError, FirewallRouteMissPacket};
use crate::ipv4_fragment_tracking::{
    parse_fragment, Ipv4FragmentFirstTicket, Ipv4FragmentFollow, Ipv4FragmentInfo,
    Ipv4FragmentTemplate,
};
use crate::ipv4_fragmentation::Ipv4FragmentPlan;
use crate::nat44::{
    Nat44TcpInboundPlan, Nat44TcpOutboundPlan, Nat44TcpPlanError, Nat44UdpInboundPlan,
    Nat44UdpOutboundPlan, Nat44UdpPlanError,
};
use crate::resolution::DynamicLookup;
use crate::{
    packet, rfc1624_update, validate_arp, validate_ipv4_frame, ArpOpcode, ArpRequestAction,
    BatchCompletion, ConsumeReason, ControlDisposition, FirewallAction, FirewallAuditBuffer,
    FirewallConfig, FirewallConnectionClass, FirewallDisposition, FirewallFailure,
    FirewallPolicySource, FirewallProtocol, FirewallRelatedIcmpv4Error, FirewallRelatedIcmpv4Flow,
    FirewallRuntime, FirewallVerdict, Icmpv4ErrorAction, Icmpv4ErrorDisposition, Icmpv4ErrorKind,
    Icmpv4ErrorRuntime, Icmpv4TimeExceededDisposition, IfId, Interface, Ipv4FragmentTracker,
    Ipv4FragmentationRuntime, LocalIpv4Binding, MonotonicMillis, Nat44IcmpConfig,
    Nat44IcmpDisposition, Nat44IcmpRuntime, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig,
    Nat44TcpDisposition, Nat44TcpRuntime, Nat44UdpConfig, Nat44UdpDisposition, Nat44UdpRuntime,
    Neighbor, PacketBatch, ResolutionResult, ResolutionRuntime, Route, ARP_ETHERTYPE,
    IPV4_ETHERTYPE,
};
use hairpin::{decide_nat44_tcp_hairpin, decide_nat44_udp_hairpin, Nat44HairpinDestinationRewrite};
use lookup::{linear, ForwardingIndex};
use nat44_icmp_query::{
    apply_nat44_icmp_rewrite, decide_nat44_icmp_inbound, decide_nat44_icmp_outbound,
    is_query_reply, is_query_request, nat44_icmp_drop, observe_nat44_icmp_security_time,
    peek_icmp_type, require_nat44_icmp_runtime, validate_firewall_icmp_query,
    Nat44IcmpRewriteDecision, Nat44IcmpTransition,
};
use nat44_icmpv4_inside::{decide_nat44_icmpv4_inside_error, is_nat44_icmpv4_inside_candidate};
use unsolicited_syn::hold_unsolicited_syn;
pub use unsolicited_syn::{
    dispatch_nat44_tcp_unsolicited_syns, Nat44TcpUnsolicitedSynDispatchError,
    Nat44TcpUnsolicitedSynDispatchReport, Nat44TcpUnsolicitedSynDisposition,
};

mod hairpin;
mod lookup;
#[cfg(test)]
mod lookup_tests;
mod nat44_icmp_query;
mod nat44_icmpv4_inside;
mod unsolicited_syn;

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
    Nat44UdpHairpinDisabled = 37,
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
    Nat44TcpHairpinDisabled = 57,
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
    Icmpv4EchoDisabled = 146,
    Nat44UdpHairpinFiltered = 147,
    Nat44TcpHairpinFiltered = 148,
    Nat44Icmpv4QuotedRemoteLocal = 149,
    Nat44TcpInboundRemoteQuotaExceeded = 150,
    /// An inside-originated ICMPv4 error is not addressed to the source of
    /// the packet it quotes (RFC 5508 REQ-5).
    Nat44Icmpv4OuterDestinationMismatch = 151,
    /// An inside-originated ICMPv4 error comes from neither the quoted
    /// internal destination nor the router's inside next hop toward it.
    Nat44Icmpv4InsideSourceMismatch = 152,
    /// An external Protocol or Port Unreachable (Type 3, Code 2 or 3) does
    /// not come from the quoted destination host, the only node that
    /// generates it.
    Nat44Icmpv4EndHostSourceMismatch = 153,
    /// An ARP packet's sender protocol address is not on the link of the
    /// ingress interface: outside every direct route out of it and not one
    /// of its configured gateways (ARP-031). Only with the opt-in
    /// [`ArpPolicy::with_require_on_link_sender`]; the RFC 826 default
    /// learns and answers such a sender. Nothing is learned or answered.
    ArpSenderNotOnLink = 154,
    /// A new UDP mapping's internal address already holds the per-host
    /// limit of live mappings (N3, NAT44-092). Nothing was created or
    /// evicted.
    Nat44UdpHostQuotaExceeded = 155,
    /// A new TCP mapping's internal address already holds the per-host
    /// limit of live mappings (N3, NAT44-092). Nothing was created or
    /// evicted.
    Nat44TcpHostQuotaExceeded = 156,
    /// An external ICMPv4 error that NAT44 would translate toward an inside
    /// host exceeds that host's translated-error rate limit (RFC 5508
    /// REQ-10 f, RFC 1812 §4.3.2.8; NAT44-065).
    Nat44Icmpv4TranslatedRateLimited = 157,
    /// A Fragmentation Needed (Type 3, Code 4) error advertises a Next-Hop
    /// MTU of 1 to 67, below the IPv4 minimum of 68 (RFC 791, RFC 1191 §3).
    /// Zero (a router predating RFC 1191) stays valid.
    Nat44Icmpv4FragNeededMtuInvalid = 158,
    /// ICMP query NAT is configured but the tick has no ICMP query runtime.
    Nat44IcmpRuntimeUnavailable = 159,
    /// The ICMP query NAT config or runtime does not match the snapshot, or the runtime's state
    /// failed a commit check.
    Nat44IcmpConfigMismatch = 160,
    /// An ICMPv4 message crossing the NAT from the inside is neither an Echo or Timestamp
    /// request (translated, RFC 5508 REQ-10) nor a translated error, or an inbound message to
    /// the public address is a query reply from the wrong realm. Information and Address Mask
    /// messages (RFC 6918) and inside-originated replies are never translated.
    Nat44IcmpTypeUnsupported = 161,
    /// An ICMP query to translate is a fragment (MF set or a nonzero offset). Unfragmented
    /// queries are translated with DF set or clear (NAT44-116).
    Nat44IcmpFragmentUnsupported = 162,
    /// An ICMP query to translate is shorter than its 8-byte header (20 bytes for Timestamp).
    Nat44IcmpHeaderTruncated = 163,
    /// An ICMP query to translate has a nonzero code (RFC 792).
    Nat44IcmpCodeInvalid = 164,
    /// An ICMP query to translate fails the ICMP checksum.
    Nat44IcmpChecksumInvalid = 165,
    /// An ICMP query's source is not an admissible host (a router or the public address, or not
    /// host-unicast).
    Nat44IcmpSourceForbidden = 166,
    /// An outbound ICMP query's source is not routed back through the inside interface, or an
    /// inbound reply's internal destination has no route.
    Nat44IcmpReverseAuthorityMismatch = 167,
    /// An inbound ICMP query reply names no live query mapping.
    Nat44IcmpMappingMiss = 168,
    /// An inbound ICMP query reply comes from a remote address the mapping has not queried
    /// (address-dependent filtering).
    Nat44IcmpFilterDenied = 169,
    /// A new ICMP query mapping found no free or expired slot. Nothing was evicted.
    Nat44IcmpMappingTableFull = 170,
    /// A new ICMP query filter peer found no free or reusable slot. Nothing was evicted.
    Nat44IcmpPeerTableFull = 171,
    /// Every public ICMP query identifier has a live owner.
    Nat44IcmpIdentifierExhausted = 172,
    /// A new ICMP query mapping's internal address already holds the per-host limit of live
    /// query mappings (N3 applied to queries). Nothing was created or evicted.
    Nat44IcmpHostQuotaExceeded = 173,
    /// The ICMP query NAT runtime observed time going backwards.
    Nat44IcmpClockRegression = 174,
    /// A query reply addressed to the public address arrived on another interface than the
    /// outside (no inbound query session exists to reach from the inside).
    Nat44IcmpWrongIngress = 175,
    /// An inbound query reply's internal destination is not routed through the inside
    /// interface.
    Nat44IcmpWrongEgress = 176,
    /// An ICMP Echo or Timestamp message evaluated by the firewall is truncated, has a nonzero
    /// code, or fails the ICMP checksum.
    FirewallIcmpQueryInvalid = 177,
    /// An ICMP Echo/Timestamp reply without a firewall flow matched an
    /// allow-stateful rule: only a request opens an ICMP flow (N5).
    FirewallIcmpReplyWithoutRequest = 178,
    /// A new UDP filter peer (or the new mapping that would carry it) for an internal address
    /// that already holds the per-host limit of peers on live mappings (N6, RFC 6888 REQ-5).
    /// Nothing was created or evicted.
    Nat44UdpHostPeerQuotaExceeded = 179,
    /// A new host-initiated TCP session (or the new mapping that would carry it) for an
    /// internal address that already holds the per-host limit of sessions it keeps alive (N6,
    /// RFC 6888 REQ-5). Nothing was created or evicted.
    Nat44TcpHostSessionQuotaExceeded = 180,
    /// A new ICMP query filter peer (or the new query mapping that would carry it) for an
    /// internal address that already holds the per-host limit of peers on live query mappings
    /// (N6). Nothing was created or evicted.
    Nat44IcmpHostPeerQuotaExceeded = 181,
    /// A forwarded IPv4 datagram with Don't Fragment set is longer than the
    /// MTU of its egress interface (RFC 1812 §§4.2.2.7, 5.2.7.1). It is
    /// discarded and, unless suppressed, ICMP Destination Unreachable,
    /// Fragmentation Needed and DF Set (Type 3, Code 4) carrying the egress
    /// MTU as Next-Hop MTU (RFC 1191 §4) is queued to its source (MTU1).
    Ipv4FragmentationNeeded = 182,
    /// A forwarded IPv4 datagram without Don't Fragment is longer than the
    /// MTU of its egress interface and fragmentation is off
    /// (`[fragmentation] enabled = false`, a hardening option against RFC
    /// 1812 §4.2.2.7) or not part of the composition. It is discarded
    /// without an ICMP error (Code 4 means DF set). With fragmentation on
    /// (the default, MTU2 part B) such a datagram is fragmented instead.
    Ipv4FragmentationRequired = 183,
    /// The local Echo Reply to a valid Echo Request would be longer than the
    /// MTU of its egress interface (the request arrived over a device MTU
    /// above the configured interface MTU). It is not sent; the router does
    /// not fragment its own datagrams.
    Icmpv4EchoReplyExceedsMtu = 184,
    /// A datagram within the egress MTU arrived in a frame whose Ethernet
    /// payload (the datagram plus bytes after its Total Length) is longer
    /// than that MTU. The backend sends the whole frame, so it would exceed
    /// the link MTU; it is discarded without an ICMP error (the datagram
    /// itself fits). Minimum Ethernet padding (to 60 bytes) never trips it,
    /// since every MTU is at least 68 (MTU1 review).
    Ipv4FrameExceedsMtu = 185,
    /// A DF-clear datagram above the egress MTU would need more fragments
    /// than `[fragmentation] max-fragments-per-datagram`. The whole
    /// datagram is discarded before any NAT, firewall, or ID state commits;
    /// no fragment is sent (MTU2 part B).
    Ipv4FragmentationTooManyFragments = 186,
    /// A DF-clear datagram above the egress MTU found every fragmentation
    /// slot of this tick taken (`[fragmentation] datagrams`). The whole
    /// datagram is discarded before any state commits (MTU2 part B).
    Ipv4FragmentationQueueFull = 187,
    /// A DF-clear datagram above the egress MTU is longer than a
    /// fragmentation slot. The config sizes slots for the largest of the
    /// interface MTUs, the longest AF_XDP datagram (3826 bytes), and the
    /// AF_PACKET `max-frame-len` minus 14, so no production port delivers a
    /// longer one; only a simulated frame can be. The whole
    /// datagram is discarded before any state commits (MTU2 part B).
    Ipv4FragmentationDatagramTooLarge = 188,
    /// A DF-clear fragment above the egress MTU whose data, at its Fragment
    /// Offset, ends past the largest IPv4 datagram (RFC 791: 65535 bytes,
    /// so `offset * 8 + data > 65515`): malformed, not cut further. The
    /// whole fragment is discarded before any state commits (MTU2 part B).
    /// Not reached in production: the fragment association table (NAT-FRAG)
    /// refuses such a fragment first (`IPV4_FRAGMENT_MALFORMED`), and without
    /// the table the firewall refuses every received fragment.
    Ipv4FragmentationOffsetOverflow = 189,
    /// A later fragment (Fragment Offset not 0) of a datagram whose first
    /// fragment the router refused (firewall, NAT, or any forwarding drop):
    /// the fragment association entry refuses the rest of the datagram
    /// (NAT-FRAG).
    Ipv4FragmentFirstDenied = 190,
    /// A first fragment (MF set, offset 0) for a datagram whose first
    /// fragment was already decided: a second transport header could differ
    /// from the one the decision was made on (RFC 1858 §4 overlap), so it
    /// is refused (NAT-FRAG).
    Ipv4FragmentDuplicateFirst = 191,
    /// A later fragment that starts inside its first fragment's transport
    /// header (or, before the first fragment is seen, inside the smallest
    /// header of its protocol: 20 bytes for TCP, RFC 1858 §3.2's offset 1
    /// rule) could rewrite the ports or TCP flags the decision was made on
    /// (RFC 1858, RFC 3128). Refused (NAT-FRAG).
    Ipv4FragmentTransportHeaderOverlap = 192,
    /// A fragment that breaks RFC 791's structure: no data, a fragment
    /// with MF set whose data is not a multiple of 8 bytes, or data ending
    /// past the largest datagram (65515 data bytes). Refused (NAT-FRAG).
    Ipv4FragmentMalformed = 193,
    /// No free fragment association entry (`[fragment-tracking] entries`)
    /// for a new datagram, after expiring the oldest. A first fragment is
    /// refused before its decision, so no NAT or firewall state commits
    /// (NAT-FRAG).
    Ipv4FragmentTableFull = 194,
    /// The datagram's source already has `[fragment-tracking]
    /// entries-per-host` association entries (NAT-FRAG).
    Ipv4FragmentHostLimit = 195,
    /// A later fragment arrived before its first fragment and no held slot
    /// is free (`[fragment-tracking] held-fragments`, none without
    /// fragmentation), after expiring the oldest entry (NAT-FRAG).
    Ipv4FragmentHoldFull = 196,
    /// A later fragment arrived before its first fragment and its source
    /// already has `[fragment-tracking] held-per-host` held fragments
    /// (NAT-FRAG).
    Ipv4FragmentHostHoldLimit = 197,
    /// A later fragment arrived before its first fragment and is longer
    /// than a held slot (sized like a fragmentation slot, so only a
    /// simulated frame can be) (NAT-FRAG).
    Ipv4FragmentHoldTooLarge = 198,
}

use DropReason::*;

impl DropReason {
    /// Every reason in ascending stable code order. Codes are contiguous
    /// from 1, so `ALL[code - 1]` is the reason with that code.
    pub const ALL: [Self; 198] = [
        EthernetHeaderTruncated,
        UnsupportedEtherType,
        Ipv4HeaderTruncated,
        Ipv4VersionUnsupported,
        Ipv4IhlTooSmall,
        Ipv4HeaderLengthExceedsPacket,
        Ipv4TotalLengthTooSmall,
        Ipv4TotalLengthExceedsPacket,
        Ipv4HeaderChecksumInvalid,
        Ipv4OptionsUnsupported,
        Ipv4TtlExpired,
        RouteMiss,
        NeighborUnresolved,
        InterfaceMiss,
        ArpPacketTruncated,
        ArpHardwareTypeUnsupported,
        ArpProtocolTypeUnsupported,
        ArpHardwareLengthUnsupported,
        ArpProtocolLengthUnsupported,
        ArpReplyUnsupported,
        ArpOpcodeUnsupported,
        ArpTargetNotLocal,
        ArpSenderHardwareZero,
        ArpSenderHardwareBroadcast,
        ArpSenderHardwareMulticast,
        Icmpv4HeaderTruncated,
        Icmpv4EchoHeaderTruncated,
        Icmpv4ChecksumInvalid,
        Icmpv4EchoCodeInvalid,
        Icmpv4FragmentUnsupported,
        Icmpv4SourceNotUnicast,
        Icmpv4EthernetSourceInvalid,
        Icmpv4EthernetDestinationNotLocal,
        Nat44UdpRuntimeUnavailable,
        Nat44UdpConfigMismatch,
        Nat44UdpUnsupportedTransport,
        Nat44UdpHairpinDisabled,
        Nat44UdpNonAtomicIpv4Unsupported,
        Nat44UdpHeaderTruncated,
        Nat44UdpLengthTooSmall,
        Nat44UdpLengthExceedsIpv4Payload,
        Nat44UdpSourcePortZero,
        Nat44UdpSourceForbidden,
        Nat44UdpReverseAuthorityMismatch,
        Nat44UdpMappingMiss,
        Nat44UdpFilterDenied,
        Nat44UdpMappingTableFull,
        Nat44UdpPeerTableFull,
        Nat44UdpPortExhausted,
        Nat44UdpClockRegression,
        Nat44UdpWrongIngress,
        Nat44UdpWrongEgress,
        Nat44ExternalToInternalBypass,
        Nat44TcpRuntimeUnavailable,
        Nat44TcpConfigMismatch,
        Nat44TcpUnsupportedTransport,
        Nat44TcpHairpinDisabled,
        Nat44TcpNonAtomicIpv4Unsupported,
        Nat44TcpHeaderTruncated,
        Nat44TcpDataOffsetTooSmall,
        Nat44TcpDataOffsetExceedsIpv4Payload,
        Nat44TcpChecksumInvalid,
        Nat44TcpSourcePortZero,
        Nat44TcpSourceForbidden,
        Nat44TcpReverseAuthorityMismatch,
        Nat44TcpMappingMiss,
        Nat44TcpSessionMiss,
        Nat44TcpInvalidInitialFlags,
        Nat44TcpMappingTableFull,
        Nat44TcpSessionTableFull,
        Nat44TcpPortExhausted,
        Nat44TcpClockRegression,
        Nat44TcpWrongIngress,
        Nat44TcpWrongEgress,
        Nat44CombinedRealmMismatch,
        Nat44Icmpv4WrongIngress,
        Nat44Icmpv4OuterOptionsUnsupported,
        Nat44Icmpv4OuterFragmentUnsupported,
        Nat44Icmpv4OuterTtlExpired,
        Nat44Icmpv4HeaderTruncated,
        Nat44Icmpv4ChecksumInvalid,
        Nat44Icmpv4QuoteTruncated,
        Nat44Icmpv4QuotedVersionUnsupported,
        Nat44Icmpv4QuotedIhlTooSmall,
        Nat44Icmpv4QuotedHeaderTruncated,
        Nat44Icmpv4QuotedTotalLengthTooSmall,
        Nat44Icmpv4QuotedChecksumInvalid,
        Nat44Icmpv4QuotedFragmentUnsupported,
        Nat44Icmpv4QuotedProtocolUnsupported,
        Nat44Icmpv4QuotedPublicSourceMismatch,
        Nat44Icmpv4TcpChecksumPartial,
        Nat44Icmpv4WrongEgress,
        Nat44Icmpv4SourceForbidden,
        FirewallRuntimeUnavailable,
        FirewallConfigMismatch,
        FirewallUnsupportedProtocol,
        FirewallIpv4OptionsUnsupported,
        FirewallFragmentUnsupported,
        FirewallTcpHeaderTruncated,
        FirewallTcpDataOffsetTooSmall,
        FirewallTcpDataOffsetExceedsIpv4Payload,
        FirewallTcpChecksumInvalid,
        FirewallTcpPortZero,
        FirewallUdpHeaderTruncated,
        FirewallUdpLengthTooSmall,
        FirewallUdpLengthExceedsIpv4Payload,
        FirewallUdpChecksumInvalid,
        FirewallUdpDestinationPortZero,
        FirewallRuleDenied,
        FirewallDefaultDenied,
        FirewallTcpInvalidInitialFlags,
        FirewallStateTableFull,
        FirewallClockRegression,
        FirewallRelatedIcmpv4Unsupported,
        FirewallRouteUnavailable,
        FirewallRelatedIcmpv4StateMiss,
        Ipv4IngressInterfaceUnknown,
        Ipv4EthernetSourceZero,
        Ipv4EthernetSourceBroadcast,
        Ipv4EthernetSourceMulticast,
        Ipv4EthernetDestinationZero,
        Ipv4EthernetDestinationBroadcast,
        Ipv4EthernetDestinationMulticast,
        Ipv4SourceUnspecifiedNetwork,
        Ipv4SourceLoopback,
        Ipv4SourceMulticast,
        Ipv4SourceLimitedBroadcast,
        Ipv4SourceClassE,
        Ipv4SourceNetworkAddress,
        Ipv4SourceDirectedBroadcast,
        Ipv4DestinationUnspecifiedNetwork,
        Ipv4DestinationLoopback,
        Ipv4DestinationMulticast,
        Ipv4DestinationLimitedBroadcast,
        Ipv4DestinationClassE,
        Ipv4DestinationNetworkAddress,
        Ipv4DestinationDirectedBroadcast,
        EthernetDestinationNotLocal,
        ArpIngressInterfaceUnknown,
        ArpEthernetSourceZero,
        ArpEthernetSourceBroadcast,
        ArpEthernetSourceMulticast,
        ArpEthernetDestinationZero,
        ArpEthernetDestinationMulticast,
        Ipv4SourceLocalAddress,
        Icmpv4EchoDisabled,
        Nat44UdpHairpinFiltered,
        Nat44TcpHairpinFiltered,
        Nat44Icmpv4QuotedRemoteLocal,
        Nat44TcpInboundRemoteQuotaExceeded,
        Nat44Icmpv4OuterDestinationMismatch,
        Nat44Icmpv4InsideSourceMismatch,
        Nat44Icmpv4EndHostSourceMismatch,
        ArpSenderNotOnLink,
        Nat44UdpHostQuotaExceeded,
        Nat44TcpHostQuotaExceeded,
        Nat44Icmpv4TranslatedRateLimited,
        Nat44Icmpv4FragNeededMtuInvalid,
        Nat44IcmpRuntimeUnavailable,
        Nat44IcmpConfigMismatch,
        Nat44IcmpTypeUnsupported,
        Nat44IcmpFragmentUnsupported,
        Nat44IcmpHeaderTruncated,
        Nat44IcmpCodeInvalid,
        Nat44IcmpChecksumInvalid,
        Nat44IcmpSourceForbidden,
        Nat44IcmpReverseAuthorityMismatch,
        Nat44IcmpMappingMiss,
        Nat44IcmpFilterDenied,
        Nat44IcmpMappingTableFull,
        Nat44IcmpPeerTableFull,
        Nat44IcmpIdentifierExhausted,
        Nat44IcmpHostQuotaExceeded,
        Nat44IcmpClockRegression,
        Nat44IcmpWrongIngress,
        Nat44IcmpWrongEgress,
        FirewallIcmpQueryInvalid,
        FirewallIcmpReplyWithoutRequest,
        Nat44UdpHostPeerQuotaExceeded,
        Nat44TcpHostSessionQuotaExceeded,
        Nat44IcmpHostPeerQuotaExceeded,
        Ipv4FragmentationNeeded,
        Ipv4FragmentationRequired,
        Icmpv4EchoReplyExceedsMtu,
        Ipv4FrameExceedsMtu,
        Ipv4FragmentationTooManyFragments,
        Ipv4FragmentationQueueFull,
        Ipv4FragmentationDatagramTooLarge,
        Ipv4FragmentationOffsetOverflow,
        Ipv4FragmentFirstDenied,
        Ipv4FragmentDuplicateFirst,
        Ipv4FragmentTransportHeaderOverlap,
        Ipv4FragmentMalformed,
        Ipv4FragmentTableFull,
        Ipv4FragmentHostLimit,
        Ipv4FragmentHoldFull,
        Ipv4FragmentHostHoldLimit,
        Ipv4FragmentHoldTooLarge,
    ];

    /// The reason with stable discriminant `code`, if any.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        let index = code as usize;
        if index == 0 || index > Self::ALL.len() {
            return None;
        }
        Some(Self::ALL[index - 1])
    }

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
            Nat44UdpHairpinDisabled => "NAT44_UDP_HAIRPIN_DISABLED",
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
            Nat44TcpHairpinDisabled => "NAT44_TCP_HAIRPIN_DISABLED",
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
            Icmpv4EchoDisabled => "ICMPV4_ECHO_DISABLED",
            Nat44UdpHairpinFiltered => "NAT44_UDP_HAIRPIN_FILTERED",
            Nat44TcpHairpinFiltered => "NAT44_TCP_HAIRPIN_FILTERED",
            Nat44Icmpv4QuotedRemoteLocal => "NAT44_ICMPV4_QUOTED_REMOTE_LOCAL",
            Nat44TcpInboundRemoteQuotaExceeded => "NAT44_TCP_INBOUND_REMOTE_QUOTA_EXCEEDED",
            Nat44Icmpv4OuterDestinationMismatch => "NAT44_ICMPV4_OUTER_DESTINATION_MISMATCH",
            Nat44Icmpv4InsideSourceMismatch => "NAT44_ICMPV4_INSIDE_SOURCE_MISMATCH",
            Nat44Icmpv4EndHostSourceMismatch => "NAT44_ICMPV4_END_HOST_SOURCE_MISMATCH",
            ArpSenderNotOnLink => "ARP_SENDER_NOT_ON_LINK",
            Nat44UdpHostQuotaExceeded => "NAT44_UDP_HOST_QUOTA_EXCEEDED",
            Nat44TcpHostQuotaExceeded => "NAT44_TCP_HOST_QUOTA_EXCEEDED",
            Nat44Icmpv4TranslatedRateLimited => "NAT44_ICMPV4_TRANSLATED_RATE_LIMITED",
            Nat44Icmpv4FragNeededMtuInvalid => "NAT44_ICMPV4_FRAG_NEEDED_MTU_INVALID",
            Nat44IcmpRuntimeUnavailable => "NAT44_ICMP_RUNTIME_UNAVAILABLE",
            Nat44IcmpConfigMismatch => "NAT44_ICMP_CONFIG_MISMATCH",
            Nat44IcmpTypeUnsupported => "NAT44_ICMP_TYPE_UNSUPPORTED",
            Nat44IcmpFragmentUnsupported => "NAT44_ICMP_FRAGMENT_UNSUPPORTED",
            Nat44IcmpHeaderTruncated => "NAT44_ICMP_HEADER_TRUNCATED",
            Nat44IcmpCodeInvalid => "NAT44_ICMP_CODE_INVALID",
            Nat44IcmpChecksumInvalid => "NAT44_ICMP_CHECKSUM_INVALID",
            Nat44IcmpSourceForbidden => "NAT44_ICMP_SOURCE_FORBIDDEN",
            Nat44IcmpReverseAuthorityMismatch => "NAT44_ICMP_REVERSE_AUTHORITY_MISMATCH",
            Nat44IcmpMappingMiss => "NAT44_ICMP_MAPPING_MISS",
            Nat44IcmpFilterDenied => "NAT44_ICMP_FILTER_DENIED",
            Nat44IcmpMappingTableFull => "NAT44_ICMP_MAPPING_TABLE_FULL",
            Nat44IcmpPeerTableFull => "NAT44_ICMP_PEER_TABLE_FULL",
            Nat44IcmpIdentifierExhausted => "NAT44_ICMP_IDENTIFIER_EXHAUSTED",
            Nat44IcmpHostQuotaExceeded => "NAT44_ICMP_HOST_QUOTA_EXCEEDED",
            Nat44IcmpClockRegression => "NAT44_ICMP_CLOCK_REGRESSION",
            Nat44IcmpWrongIngress => "NAT44_ICMP_WRONG_INGRESS",
            Nat44IcmpWrongEgress => "NAT44_ICMP_WRONG_EGRESS",
            FirewallIcmpQueryInvalid => "FIREWALL_ICMP_QUERY_INVALID",
            FirewallIcmpReplyWithoutRequest => "FIREWALL_ICMP_REPLY_WITHOUT_REQUEST",
            Nat44UdpHostPeerQuotaExceeded => "NAT44_UDP_HOST_PEER_QUOTA_EXCEEDED",
            Nat44TcpHostSessionQuotaExceeded => "NAT44_TCP_HOST_SESSION_QUOTA_EXCEEDED",
            Nat44IcmpHostPeerQuotaExceeded => "NAT44_ICMP_HOST_PEER_QUOTA_EXCEEDED",
            Ipv4FragmentationNeeded => "IPV4_FRAGMENTATION_NEEDED",
            Ipv4FragmentationRequired => "IPV4_FRAGMENTATION_REQUIRED",
            Icmpv4EchoReplyExceedsMtu => "ICMPV4_ECHO_REPLY_EXCEEDS_MTU",
            Ipv4FrameExceedsMtu => "IPV4_FRAME_EXCEEDS_MTU",
            Ipv4FragmentationTooManyFragments => "IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS",
            Ipv4FragmentationQueueFull => "IPV4_FRAGMENTATION_QUEUE_FULL",
            Ipv4FragmentationDatagramTooLarge => "IPV4_FRAGMENTATION_DATAGRAM_TOO_LARGE",
            Ipv4FragmentationOffsetOverflow => "IPV4_FRAGMENTATION_OFFSET_OVERFLOW",
            Ipv4FragmentFirstDenied => "IPV4_FRAGMENT_FIRST_DENIED",
            Ipv4FragmentDuplicateFirst => "IPV4_FRAGMENT_DUPLICATE_FIRST",
            Ipv4FragmentTransportHeaderOverlap => "IPV4_FRAGMENT_TRANSPORT_HEADER_OVERLAP",
            Ipv4FragmentMalformed => "IPV4_FRAGMENT_MALFORMED",
            Ipv4FragmentTableFull => "IPV4_FRAGMENT_TABLE_FULL",
            Ipv4FragmentHostLimit => "IPV4_FRAGMENT_HOST_LIMIT",
            Ipv4FragmentHoldFull => "IPV4_FRAGMENT_HOLD_FULL",
            Ipv4FragmentHostHoldLimit => "IPV4_FRAGMENT_HOST_HOLD_LIMIT",
            Ipv4FragmentHoldTooLarge => "IPV4_FRAGMENT_HOLD_TOO_LARGE",
        }
    }
}

// `ALL` is contiguous from code 1; a gap or reordering fails to compile.
const _: () = {
    let mut index = 0;
    while index < DropReason::ALL.len() {
        assert!(DropReason::ALL[index] as usize == index + 1);
        index += 1;
    }
};

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
    /// An interface MTU is below [`crate::IPV4_MIN_MTU`] (RFC 791).
    InterfaceMtuBelowMinimum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4OriginPolicy {
    default_ttl: u8,
    echo_reply: bool,
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
        Ok(Self {
            default_ttl,
            echo_reply: true,
        })
    }

    #[must_use]
    pub const fn default_ttl(self) -> u8 {
        self.default_ttl
    }

    /// Returns this policy with the local Echo responder enabled or disabled.
    ///
    /// RFC 1812 §4.3.3.6 asks for an option to silently ignore all Echo
    /// Requests that defaults to answering them. When disabled, a valid Echo
    /// Request to a router address is dropped as
    /// [`DropReason::Icmpv4EchoDisabled`] without any reply.
    #[must_use]
    pub const fn with_echo_reply(self, enabled: bool) -> Self {
        Self {
            echo_reply: enabled,
            ..self
        }
    }

    /// Whether valid Echo Requests to a router address are answered.
    #[must_use]
    pub const fn echo_reply(self) -> bool {
        self.echo_reply
    }
}

impl Default for Ipv4OriginPolicy {
    fn default() -> Self {
        Self {
            default_ttl: 64,
            echo_reply: true,
        }
    }
}

/// ARP receive policy of the forwarding snapshot.
///
/// The default is RFC 826 behavior: the merge and reply algorithm places no
/// condition on the sender's protocol address, so every valid ARP packet
/// from a host sender is merged or learned and, if it targets a router
/// address on the ingress, answered. ARP-031 on-link sender hardening is an
/// opt-in (owner decision 2026-11-02 「rfc準きょで」; the reading "RFC default,
/// hardening opt-in" is the coordinator's).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArpPolicy {
    require_on_link_sender: bool,
}

impl ArpPolicy {
    /// RFC 826: no condition on the sender's protocol address.
    pub const RFC826: Self = Self {
        require_on_link_sender: false,
    };

    /// Returns this policy with the ARP-031 on-link sender rule enabled or
    /// disabled.
    ///
    /// When enabled, an ARP Request or Reply (gratuitous included) whose
    /// sender is a host outside every direct route out of the ingress and
    /// not one of its gateways is dropped as
    /// [`DropReason::ArpSenderNotOnLink`] without learning, merging,
    /// replying, or moving the resolution clock. Static neighbors, the
    /// router's own address, and non-host senders (the RFC 5227 probe
    /// sender 0.0.0.0, connected network or broadcast addresses) keep their
    /// dispositions either way.
    #[must_use]
    pub const fn with_require_on_link_sender(self, enabled: bool) -> Self {
        Self {
            require_on_link_sender: enabled,
        }
    }

    /// Whether ARP from off-link senders is dropped (ARP-031 hardening).
    #[must_use]
    pub const fn require_on_link_sender(self) -> bool {
        self.require_on_link_sender
    }
}

#[derive(Clone, Copy)]
pub struct ForwardingSnapshot<'a> {
    pub(crate) routes: &'a [Route],
    pub(crate) interfaces: &'a [Interface],
    pub(crate) neighbors: &'a [Neighbor],
    pub(crate) local_ipv4: &'a [LocalIpv4Binding],
    pub(crate) ipv4_origin: Ipv4OriginPolicy,
    pub(crate) arp: ArpPolicy,
    /// Publication-time lookup indexes over exactly these slices, present
    /// only for snapshots borrowed from a [`ValidatedForwardingOwner`].
    /// Without it every lookup uses the linear reference (PERF-002).
    index: Option<&'a ForwardingIndex>,
    authority: u64,
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
            .field("arp", &self.arp)
            .finish_non_exhaustive()
    }
}

/// Immutable validated forwarding tables owned by the cold publication path.
///
/// Construction consumes caller-allocated boxes, validates them once, and
/// builds the lookup indexes every packet path search uses (route LPM,
/// interface, local address, static neighbor, connected boundary, gateway,
/// and on-link sender; PERF-002). The indexes are snapshot memory owned
/// here ([`Self::index_heap_bytes`]). [`Self::snapshot`] is then an
/// infallible O(1) borrow scoped to this owner.
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
    arp: ArpPolicy,
    index: ForwardingIndex,
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
            .field("arp", &self.arp)
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
            if interface.mtu < crate::IPV4_MIN_MTU {
                return Err(SnapshotError::InterfaceMtuBelowMinimum);
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
            arp: ArpPolicy::RFC826,
            index: None,
            authority: calculate_snapshot_authority(
                routes,
                interfaces,
                neighbors,
                local_ipv4,
                ipv4_origin,
                ArpPolicy::RFC826,
            ),
        })
    }

    /// Returns this snapshot with `arp` as its ARP receive policy (default
    /// [`ArpPolicy::RFC826`]). A snapshot not borrowed from a
    /// [`ValidatedForwardingOwner`] recomputes its authority, so two
    /// snapshots of the same tables with different ARP policies are never
    /// the same authority.
    ///
    /// For tests and benches that borrow tables directly. Production code
    /// sets the policy on the owner
    /// ([`ValidatedForwardingOwner::with_arp_policy`], from the validated
    /// `[arp]` config through the publication plan), whose snapshots carry
    /// it.
    #[must_use]
    pub fn with_arp_policy(self, arp: ArpPolicy) -> Self {
        let authority = if self.authority & VALIDATED_OWNER_AUTHORITY_BIT == 0 {
            calculate_snapshot_authority(
                self.routes,
                self.interfaces,
                self.neighbors,
                self.local_ipv4,
                self.ipv4_origin,
                arp,
            )
        } else {
            self.authority
        };
        Self {
            arp,
            authority,
            ..self
        }
    }

    /// The ARP receive policy.
    #[must_use]
    pub const fn arp_policy(&self) -> ArpPolicy {
        self.arp
    }

    pub(crate) const fn authority(&self) -> u64 {
        self.authority
    }

    /// The pointer and length of every table, read from the borrowed
    /// slices themselves (O(1); not stored, which keeps the by-value
    /// snapshot small enough for the index reference, RT-002).
    pub(crate) fn identity(&self) -> [usize; 8] {
        [
            self.routes.as_ptr() as usize,
            self.routes.len(),
            self.interfaces.as_ptr() as usize,
            self.interfaces.len(),
            self.neighbors.as_ptr() as usize,
            self.neighbors.len(),
            self.local_ipv4.as_ptr() as usize,
            self.local_ipv4.len(),
        ]
    }

    pub(crate) const fn publication_nonce(&self) -> u64 {
        if self.authority & VALIDATED_OWNER_AUTHORITY_BIT == 0 {
            0
        } else {
            self.authority
        }
    }

    /// Longest-prefix route for `destination` (bounded binary search over
    /// the owner index; linear reference without one).
    #[inline]
    pub(crate) fn route_lookup(&self, destination: crate::Ipv4Address) -> Option<Route> {
        match self.index {
            Some(index) => index.route(destination).0.map(|slot| self.routes[slot]),
            None => linear::route(self.routes, destination),
        }
    }

    /// The interface with `id` (ids are unique after validation).
    #[inline]
    pub(crate) fn interface(&self, id: IfId) -> Option<&'a Interface> {
        match self.index {
            Some(index) => index.interface(id).0.map(|slot| &self.interfaces[slot]),
            None => linear::interface(self.interfaces, id),
        }
    }

    /// The local IPv4 binding of `interface` (at most one per interface).
    #[inline]
    pub(crate) fn local_binding_on(&self, interface: IfId) -> Option<&'a LocalIpv4Binding> {
        match self.index {
            Some(index) => index
                .local_by_interface(interface)
                .0
                .map(|slot| &self.local_ipv4[slot]),
            None => linear::local_by_interface(self.local_ipv4, interface),
        }
    }

    /// The local IPv4 binding owning `address` on any interface (addresses
    /// are unique after validation).
    #[inline]
    pub(crate) fn local_binding_for(
        &self,
        address: crate::Ipv4Address,
    ) -> Option<&'a LocalIpv4Binding> {
        match self.index {
            Some(index) => index
                .local_by_address(address)
                .0
                .map(|slot| &self.local_ipv4[slot]),
            None => linear::local_by_address(self.local_ipv4, address),
        }
    }

    /// Whether `address` is one of the router's own IPv4 addresses.
    #[inline]
    pub(crate) fn is_local_ipv4(&self, address: crate::Ipv4Address) -> bool {
        self.local_binding_for(address).is_some()
    }

    /// Whether `address` is the local binding of `interface` itself.
    #[inline]
    pub(crate) fn is_local_ipv4_on(&self, interface: IfId, address: crate::Ipv4Address) -> bool {
        self.local_binding_on(interface)
            .is_some_and(|binding| binding.address == address)
    }

    /// The static neighbor for `(interface, target)`.
    #[inline]
    pub(crate) fn static_neighbor(
        &self,
        interface: IfId,
        target: crate::Ipv4Address,
    ) -> Option<&'a Neighbor> {
        match self.index {
            Some(index) => index
                .static_neighbor(interface, target)
                .0
                .map(|slot| &self.neighbors[slot]),
            None => linear::static_neighbor(self.neighbors, interface, target),
        }
    }

    /// Whether `address` is the network or directed-broadcast address of
    /// any connected route out of `interface` (not only the selected one).
    #[inline]
    pub(crate) fn is_connected_boundary(
        &self,
        interface: IfId,
        address: crate::Ipv4Address,
    ) -> bool {
        match self.index {
            Some(index) => index.connected_boundary(interface, address).0,
            None => linear::connected_boundary(self.routes, interface, address),
        }
    }

    /// Whether some route out of `interface` names `next_hop` as gateway.
    #[inline]
    pub(crate) fn is_gateway(&self, interface: IfId, next_hop: crate::Ipv4Address) -> bool {
        match self.index {
            Some(index) => index.gateway(interface, next_hop).0,
            None => linear::gateway(self.routes, interface, next_hop),
        }
    }

    /// Whether `sender` is on the link of `interface`: inside a direct
    /// (no next hop) route out of it, or a configured gateway out of it.
    /// This set contains every target the router itself may resolve on that
    /// interface (ARP-031).
    #[inline]
    pub(crate) fn sender_on_link(&self, interface: IfId, sender: crate::Ipv4Address) -> bool {
        match self.index {
            Some(index) => index.sender_on_link(interface, sender).0,
            None => linear::sender_on_link(self.routes, interface, sender),
        }
    }

    pub(crate) fn resolution_action_authority(
        &self,
        action: ArpRequestAction,
    ) -> ResolutionActionAuthority {
        if self
            .static_neighbor(action.egress, action.target_ip)
            .is_some()
        {
            return ResolutionActionAuthority::StaticResolved;
        }
        if !self
            .interface(action.egress)
            .is_some_and(|interface| interface.mac == action.source_mac)
            || !self.is_local_ipv4_on(action.egress, action.source_ip)
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
            || self.is_local_ipv4(target)
            || self.is_connected_boundary(action.egress, target)
        {
            return ResolutionActionAuthority::Invalid;
        }
        let route_still_authorizes = self.is_gateway(action.egress, target)
            || self
                .route_lookup(target)
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
        let index = ForwardingIndex::build(&routes, &interfaces, &neighbors, &local_ipv4);
        Ok(Self {
            routes,
            interfaces,
            neighbors,
            local_ipv4,
            ipv4_origin,
            arp: ArpPolicy::RFC826,
            index,
            authority,
        })
    }

    /// Returns this owner with `arp` as the ARP receive policy of every
    /// snapshot it lends (default [`ArpPolicy::RFC826`]). The policy is
    /// not a table, so nothing is revalidated or reindexed.
    #[must_use]
    pub fn with_arp_policy(mut self, arp: ArpPolicy) -> Self {
        self.arp = arp;
        self
    }

    /// Borrows a coherent snapshot without validation, hashing, or allocation.
    #[must_use]
    pub fn snapshot(&self) -> ForwardingSnapshot<'_> {
        ForwardingSnapshot {
            routes: &self.routes,
            interfaces: &self.interfaces,
            neighbors: &self.neighbors,
            local_ipv4: &self.local_ipv4,
            ipv4_origin: self.ipv4_origin,
            arp: self.arp,
            index: Some(&self.index),
            authority: self.authority,
        }
    }

    /// Heap bytes of the publication-time lookup indexes (snapshot memory,
    /// not runtime storage; freed with the owner). Bounded by the config
    /// limits: the worst shape (4096 non-adjacent direct routes, 4096
    /// neighbors, 256 interfaces with one address each) is about 262 KiB,
    /// about 524 KiB while a reload holds the old and the new owner.
    #[must_use]
    pub fn index_heap_bytes(&self) -> usize {
        self.index.heap_bytes()
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
    arp: ArpPolicy,
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
        // Mixed only when non-default so existing publications keep their
        // authority values.
        if interface.mtu != crate::ETHERNET_DEFAULT_MTU {
            hash = mix(hash, 0x1_0000 | u64::from(interface.mtu));
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
    hash = mix(hash, u64::from(ipv4_origin.default_ttl()));
    // Mixed only when non-default so existing publications keep their
    // authority values.
    if !ipv4_origin.echo_reply() {
        hash = mix(hash, 0xec);
    }
    if arp.require_on_link_sender() {
        hash = mix(hash, 0xa7);
    }
    hash & !VALIDATED_OWNER_AUTHORITY_BIT
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44Icmpv4Disposition {
    /// An external-realm error translated toward the inside endpoint
    /// `internal_address:internal_port` (RFC 5508 REQ-4).
    Translated {
        quoted_protocol: u8,
        internal_address: crate::Ipv4Address,
        internal_port: u16,
    },
    /// A private-realm error about a packet the inside endpoint
    /// `internal_address:internal_port` received, translated toward the
    /// external realm with that endpoint's `public_port` (RFC 5508 REQ-5).
    TranslatedFromInside {
        quoted_protocol: u8,
        internal_address: crate::Ipv4Address,
        internal_port: u16,
        public_port: u16,
    },
    /// A hairpinned error translated back to the hairpin sender
    /// `internal_address:internal_port` (RFC 5508 REQ-7).
    TranslatedHairpin {
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
    /// The disposition of the Fragmentation Needed error (Type 3, Code 4)
    /// about a DF datagram longer than its egress MTU (MTU1).
    Icmpv4FragmentationNeededDisposition {
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
    /// ICMP query translation (Echo, Timestamp; RFC 5508 §3, N5).
    Nat44Icmp {
        ingress: IfId,
        disposition: Nat44IcmpDisposition,
    },
    /// An unsolicited inbound TCP SYN was offered to the hold table, or a
    /// matured hold was resolved (RFC 5382 REQ-4).
    Nat44TcpUnsolicitedSyn {
        disposition: Nat44TcpUnsolicitedSynDisposition,
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
    /// A DF-clear datagram above the egress MTU was staged for
    /// fragmentation into `fragments` fragments toward `egress`; the
    /// received frame was consumed as `reason`
    /// ([`ConsumeReason::Ipv4Fragmented`]).
    Ipv4FragmentationQueued {
        ingress: IfId,
        egress: IfId,
        fragments: u16,
        reason: ConsumeReason,
    },
    /// A later fragment that arrived before its first fragment was held in
    /// the fragment association table; the received frame was consumed as
    /// `reason` ([`ConsumeReason::Ipv4FragmentHeld`], NAT-FRAG).
    Ipv4FragmentHeld {
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
    /// Inbound half of a hairpinned packet; its outbound half has committed.
    Hairpin(Nat44UdpInboundPlan),
}

#[derive(Clone, Copy)]
enum Nat44TcpTransition {
    Outbound(Nat44TcpOutboundPlan),
    Inbound(Nat44TcpInboundPlan),
    /// Inbound half of a hairpinned segment; its outbound half has committed.
    Hairpin(Nat44TcpInboundPlan),
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
    hairpin_destination: Option<Nat44HairpinDestinationRewrite>,
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
    hairpin_destination: Option<Nat44HairpinDestinationRewrite>,
}

/// In-place rewrite of a translated ICMPv4 error. The outer addresses are
/// 8 bytes from `outer_source_offset`, the quoted addresses 8 bytes from
/// `inner_source_offset`, and the quoted ports 4 bytes from
/// `inner_port_offset`; unchanged fields are written back with their
/// received value.
#[derive(Clone, Copy)]
struct Nat44Icmpv4RewriteDecision {
    egress: IfId,
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    outer_ttl_offset: usize,
    outer_checksum_offset: usize,
    outer_source_offset: usize,
    inner_checksum_offset: usize,
    inner_source_offset: usize,
    inner_port_offset: usize,
    transport_checksum_offset: Option<usize>,
    icmp_checksum_offset: usize,
    outer_source: [u8; 4],
    outer_destination: [u8; 4],
    inner_source: [u8; 4],
    inner_destination: [u8; 4],
    inner_source_port: u16,
    inner_destination_port: u16,
    /// A quoted ICMP query (N5): only the 2-byte identifier at
    /// `inner_port_offset` is written (`inner_source_port`).
    inner_identifier_only: bool,
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
    Nat44Icmp(Nat44IcmpRewriteDecision),
    ArpReply(ArpReplyDecision),
    Icmpv4EchoReply(Icmpv4EchoReplyDecision),
    /// A later fragment that follows its first fragment's forwarding
    /// (NAT-FRAG).
    FragmentFollow(FragmentFollowDecision),
    ConsumeArp(ControlDisposition),
    ConsumeIpv4Local,
    /// A later fragment held until its first fragment decides (NAT-FRAG).
    ConsumeFragmentHeld,
}

/// A later fragment rewritten with its first fragment's template.
#[derive(Clone, Copy)]
struct FragmentFollowDecision {
    entry: u32,
    template: Ipv4FragmentTemplate,
    info: Ipv4FragmentInfo,
}

#[derive(Clone, Copy)]
struct PlannedPacket {
    decision: PacketDecision,
    firewall: Option<FirewallPlan>,
    /// Fragments of a datagram staged for fragmentation; the received
    /// frame is consumed instead of committed.
    fragments: Option<u16>,
}

impl PacketDecision {
    fn egress(self) -> IfId {
        match self {
            Self::Ipv4(decision) => decision.egress,
            Self::Nat44Udp(decision) => decision.forwarding.egress,
            Self::Nat44Tcp(decision) => decision.forwarding.egress,
            Self::Nat44Icmpv4(decision) => decision.egress,
            Self::Nat44Icmp(decision) => decision.forwarding.egress,
            Self::ArpReply(decision) => decision.egress,
            Self::Icmpv4EchoReply(decision) => decision.egress,
            Self::FragmentFollow(decision) => decision.template.egress,
            Self::ConsumeArp(_) | Self::ConsumeIpv4Local | Self::ConsumeFragmentHeld => {
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
        batch, snapshot, None, None, None, None, None, None, None, None, None, None, None, None,
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
        None,
        None,
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
        None,
        None,
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
        None,
        None,
        Some(firewall_config),
        firewall,
        None,
        None,
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
        None,
        None,
        Some(firewall_config),
        firewall,
        Some(audit),
        None,
        trace,
    )
}

/// Full UDP/TCP NAPT, ICMP query NAT (RFC 5508 §3, N5), and generated
/// ICMPv4-error composition, without a firewall.
///
/// The ICMP query runtime shares the UDP/TCP realm (a mismatch fails
/// closed). An absent ICMP runtime fails ICMP queries closed; UDP and TCP
/// are unaffected. The [`forward_batch`] fresh-batch precondition applies.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_icmp_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    icmp_config: &Nat44IcmpConfig,
    nat44_icmp: Option<&mut Nat44IcmpRuntime<'_>>,
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
        Some(icmp_config),
        nat44_icmp,
        None,
        None,
        None,
        None,
        trace,
    )
}

/// [`forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors`]
/// with ICMP query NAT (RFC 5508 §3, N5).
///
/// `icmp` is `None` when ICMP query NAT is not configured: ICMP queries
/// crossing the NAT then fail closed exactly as in the UDP/TCP composition.
/// With a config, queries are translated and the firewall evaluates them as
/// [`FirewallProtocol::Icmp`] flows. The [`forward_batch`] fresh-batch
/// precondition applies.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    icmp: Option<(&Nat44IcmpConfig, Option<&mut Nat44IcmpRuntime<'_>>)>,
    firewall_config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
    audit: Option<&mut FirewallAuditBuffer<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    let (icmp_config, nat44_icmp) = match icmp {
        Some((config, runtime)) => (Some(config), runtime),
        None => (None, None),
    };
    forward_batch_inner(
        batch,
        snapshot,
        Some((resolution, now)),
        Some((icmpv4_errors, now)),
        Some(udp_config),
        nat44_udp,
        Some(tcp_config),
        nat44_tcp,
        icmp_config,
        nat44_icmp,
        Some(firewall_config),
        firewall,
        audit,
        None,
        trace,
    )
}

/// [`forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors`]
/// with IPv4 fragmentation (MTU2 part B, RFC 791 §3.2, RFC 1812
/// §4.2.2.7): a DF-clear datagram above its egress MTU is, after every
/// decision and before any commit, admitted by `fragmentation`'s policy and
/// slot table (or dropped whole with a typed reason), rewritten, staged in
/// a slot, and its received frame consumed as
/// [`ConsumeReason::Ipv4Fragmented`]. The caller then sends the staged
/// datagrams with [`crate::execute_one_ipv4_fragmentation`] in the same
/// tick. Without a runtime such a datagram is
/// [`DropReason::Ipv4FragmentationRequired`], as in the compositions
/// without fragmentation. The [`forward_batch`] fresh-batch precondition
/// applies.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragmentation<
    B,
    T,
>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    icmp: Option<(&Nat44IcmpConfig, Option<&mut Nat44IcmpRuntime<'_>>)>,
    firewall_config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
    audit: Option<&mut FirewallAuditBuffer<'_>>,
    fragmentation: Option<&mut Ipv4FragmentationRuntime<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    let (icmp_config, nat44_icmp) = match icmp {
        Some((config, runtime)) => (Some(config), runtime),
        None => (None, None),
    };
    forward_batch_inner(
        batch,
        snapshot,
        Some((resolution, now)),
        Some((icmpv4_errors, now)),
        Some(udp_config),
        nat44_udp,
        Some(tcp_config),
        nat44_tcp,
        icmp_config,
        nat44_icmp,
        Some(firewall_config),
        firewall,
        audit,
        fragmentation,
        trace,
    )
}

/// [`forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragmentation`]
/// with IPv4 fragment association (NAT-FRAG, RFC 4787 REQ-14): with
/// `fragment_tracking` bound, a first fragment (MF set, offset 0) is decided
/// by the firewall and the NAT on its transport header like a whole
/// datagram, and every later fragment of its datagram follows that decision
/// (the same translation and generated IPv4 ID, or the same refusal); a later
/// fragment that arrives first is held until its first fragment decides.
/// See [`Ipv4FragmentTracker`]. Without it, fragments keep their typed
/// drops (`FIREWALL_FRAGMENT_UNSUPPORTED` first).
///
/// The [`forward_batch`] fresh-batch precondition applies.
#[allow(clippy::too_many_arguments)]
pub fn forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragment_tracking<
    B,
    T,
>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    tcp_config: &Nat44TcpConfig,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    icmp: Option<(&Nat44IcmpConfig, Option<&mut Nat44IcmpRuntime<'_>>)>,
    firewall_config: &FirewallConfig<'_>,
    firewall: Option<&mut FirewallRuntime<'_>>,
    audit: Option<&mut FirewallAuditBuffer<'_>>,
    fragmentation: Option<&mut Ipv4FragmentationRuntime<'_>>,
    fragment_tracking: Option<&mut Ipv4FragmentTracker<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    let (icmp_config, nat44_icmp) = match icmp {
        Some((config, runtime)) => (Some(config), runtime),
        None => (None, None),
    };
    forward_batch_tracked(
        batch,
        snapshot,
        Some((resolution, now)),
        Some((icmpv4_errors, now)),
        Some(udp_config),
        nat44_udp,
        Some(tcp_config),
        nat44_tcp,
        icmp_config,
        nat44_icmp,
        Some(firewall_config),
        firewall,
        audit,
        fragmentation,
        fragment_tracking,
        trace,
    )
}

#[allow(clippy::too_many_arguments)]
fn forward_batch_inner<B, T>(
    batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
    nat44_icmp: Option<&mut Nat44IcmpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: Option<&mut FirewallRuntime<'_>>,
    firewall_audit: Option<&mut FirewallAuditBuffer<'_>>,
    fragmentation: Option<&mut Ipv4FragmentationRuntime<'_>>,
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    forward_batch_tracked(
        batch,
        snapshot,
        resolution,
        icmpv4_errors,
        nat44_udp_config,
        nat44_udp,
        nat44_tcp_config,
        nat44_tcp,
        nat44_icmp_config,
        nat44_icmp,
        firewall_config,
        firewall,
        firewall_audit,
        fragmentation,
        None,
        trace,
    )
}

#[allow(clippy::too_many_arguments)]
fn forward_batch_tracked<B, T>(
    mut batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    mut resolution: Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    mut icmpv4_errors: Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    mut nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    mut nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
    mut nat44_icmp: Option<&mut Nat44IcmpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    mut firewall: Option<&mut FirewallRuntime<'_>>,
    mut firewall_audit: Option<&mut FirewallAuditBuffer<'_>>,
    mut fragmentation: Option<&mut Ipv4FragmentationRuntime<'_>>,
    mut fragment_tracking: Option<&mut Ipv4FragmentTracker<'_>>,
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
        // NAT-FRAG: a first fragment admitted by the association table
        // before its decision, and the rewrite it left with.
        let mut first_fragment: Option<Ipv4FragmentFirstTicket> = None;
        let mut first_template: Option<Ipv4FragmentTemplate> = None;
        let result = {
            let frame = packet.bytes_mut();
            // One read of the flags word for a frame that is not a fragment.
            let fragment = match fragment_tracking.as_deref_mut() {
                Some(tracker) if is_ipv4_fragment(frame) => tracked_fragment(
                    &*frame,
                    snapshot,
                    ingress,
                    nat44_udp_config,
                    nat44_tcp_config,
                    nat44_icmp_config,
                )
                .map(|(ipv4, info)| (tracker, ipv4, info)),
                _ => None,
            };
            let decided = match fragment {
                Some((tracker, ipv4, info)) if !info.is_first() => decide_later_fragment(
                    &*frame, snapshot, ingress, ipv4, info, tracker, nat_now_ms,
                ),
                Some((tracker, ipv4, info)) => admit_first_fragment(
                    &*frame, snapshot, ingress, ipv4, info, tracker, nat_now_ms,
                )
                .and_then(|ticket| {
                    first_fragment = Some(ticket);
                    decide(
                        &*frame,
                        snapshot,
                        ingress,
                        true,
                        &mut resolution,
                        &mut icmpv4_errors,
                        nat44_udp_config,
                        &mut nat44_udp,
                        nat44_tcp_config,
                        &mut nat44_tcp,
                        nat44_icmp_config,
                        &mut nat44_icmp,
                        firewall_config,
                        &mut firewall,
                        &mut firewall_audit,
                        &mut firewall_plan,
                        trace,
                    )
                }),
                None => decide(
                    &*frame,
                    snapshot,
                    ingress,
                    false,
                    &mut resolution,
                    &mut icmpv4_errors,
                    nat44_udp_config,
                    &mut nat44_udp,
                    nat44_tcp_config,
                    &mut nat44_tcp,
                    nat44_icmp_config,
                    &mut nat44_icmp,
                    firewall_config,
                    &mut firewall,
                    &mut firewall_audit,
                    &mut firewall_plan,
                    trace,
                ),
            };
            decided
                .and_then(|decision| {
                    // Every NAT commit is checked before the packet is
                    // rewritten, so a plan the runtime would refuse (stale or
                    // corrupt reuse lists or indexes) is a counted drop, never
                    // a worker panic.
                    if let PacketDecision::Nat44Udp(nat) = decision {
                        let runtime = nat44_udp
                            .as_deref()
                            .ok_or(DropReason::Nat44UdpRuntimeUnavailable)?;
                        match nat.transition {
                            Nat44UdpTransition::Outbound(plan) => runtime
                                .prevalidate_outbound_commit(plan, nat_now_ms)
                                .map_err(|_| DropReason::Nat44UdpConfigMismatch)?,
                            Nat44UdpTransition::Inbound(plan)
                            | Nat44UdpTransition::Hairpin(plan) => {
                                runtime
                                    .prevalidate_inbound_commit(plan, nat_now_ms)
                                    .map_err(|_| DropReason::Nat44UdpConfigMismatch)?;
                            }
                        }
                    }
                    if let PacketDecision::Nat44Tcp(nat) = decision {
                        let runtime = nat44_tcp
                            .as_deref()
                            .ok_or(DropReason::Nat44TcpRuntimeUnavailable)?;
                        match nat.transition {
                            Nat44TcpTransition::Outbound(plan) => runtime
                                .prevalidate_outbound_commit(plan, nat_now_ms)
                                .map_err(|_| DropReason::Nat44TcpConfigMismatch)?,
                            Nat44TcpTransition::Inbound(plan)
                            | Nat44TcpTransition::Hairpin(plan) => {
                                runtime
                                    .prevalidate_inbound_commit(plan, nat_now_ms)
                                    .map_err(|_| DropReason::Nat44TcpConfigMismatch)?;
                            }
                        }
                    }
                    if let PacketDecision::Nat44Icmp(nat) = decision {
                        let runtime = nat44_icmp
                            .as_deref()
                            .ok_or(DropReason::Nat44IcmpRuntimeUnavailable)?;
                        match nat.transition {
                            Nat44IcmpTransition::Outbound(plan) => runtime
                                .prevalidate_outbound_commit(plan, nat_now_ms)
                                .map_err(|_| DropReason::Nat44IcmpConfigMismatch)?,
                            Nat44IcmpTransition::Inbound(plan) => runtime
                                .prevalidate_inbound_commit(plan, nat_now_ms)
                                .map_err(|_| DropReason::Nat44IcmpConfigMismatch)?,
                        }
                    }
                    if matches!(
                        decision,
                        PacketDecision::ConsumeArp(_)
                            | PacketDecision::ConsumeIpv4Local
                            | PacketDecision::ConsumeFragmentHeld
                    ) {
                        Ok((decision, None))
                    } else {
                        // After every plan is known to commit and before the
                        // frame is rewritten, so the error quotes the datagram
                        // as received and no NAT or firewall state is created
                        // for a datagram that is not sent. A DF-clear datagram
                        // that is fragmented is admitted here too (bound and
                        // slot checked), so a refused one commits nothing.
                        let fragment = check_egress_mtu(
                            &*frame,
                            snapshot,
                            ingress,
                            decision,
                            &mut resolution,
                            &mut icmpv4_errors,
                            fragmentation.as_deref(),
                            trace,
                        )?;
                        apply_decision(frame, decision)?;
                        // Only for a datagram the core commits for TX: a plan,
                        // MTU, or firewall drop consumes no ID (a later backend
                        // TX rejection does not return it). A fragmented
                        // datagram takes its ID here, so every fragment carries
                        // the generated ID.
                        rewrite_translated_non_atomic_id(
                            frame,
                            decision,
                            &mut nat44_udp,
                            &mut nat44_tcp,
                            &mut nat44_icmp,
                        )?;
                        // NAT-FRAG: the first fragment as it leaves (addresses,
                        // MACs, and the ID generated above) is what every later
                        // fragment of its datagram gets.
                        if first_fragment.is_some() {
                            first_template =
                                Ipv4FragmentTemplate::capture(frame, decision.egress());
                        }
                        // The last fallible step is above: staging cannot fail
                        // for a plan admitted by check_egress_mtu.
                        if let Some(plan) = fragment {
                            fragmentation
                                .as_deref_mut()
                                .expect("an admitted fragment plan has a runtime")
                                .stage(frame, plan, decision.egress());
                        }
                        Ok((decision, fragment.map(Ipv4FragmentPlan::fragments)))
                    }
                })
                .map(|(decision, fragments)| PlannedPacket {
                    decision,
                    firewall: firewall_plan,
                    fragments,
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
                decision: PacketDecision::ConsumeFragmentHeld,
                ..
            }) => {
                packet.consume(ConsumeReason::Ipv4FragmentHeld);
                consumed += 1;
                trace.record(TraceEvent::Ipv4FragmentHeld {
                    ingress,
                    reason: ConsumeReason::Ipv4FragmentHeld,
                });
            }
            Ok(PlannedPacket {
                decision: PacketDecision::ConsumeIpv4Local,
                ..
            }) => {
                if let Some(ticket) = first_fragment {
                    if let Some(tracker) = fragment_tracking.as_deref_mut() {
                        tracker.commit_deny(ticket, nat_now_ms);
                    }
                }
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
                        Nat44UdpTransition::Hairpin(plan) => {
                            runtime
                                .commit_hairpin_inbound(plan, nat_now_ms)
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
                            Nat44TcpTransition::Hairpin(plan) => {
                                runtime.commit_prevalidated_hairpin_inbound(plan, nat_now_ms);
                            }
                        }
                    }
                    trace.record(TraceEvent::Nat44Tcp {
                        ingress,
                        disposition: nat.disposition,
                    });
                }
                if let PacketDecision::Nat44Icmp(nat) = decision {
                    let runtime = nat44_icmp
                        .as_deref_mut()
                        .expect("ICMP query NAT decision requires a bound runtime");
                    match nat.transition {
                        Nat44IcmpTransition::Outbound(plan) => runtime
                            .commit_outbound(plan, nat_now_ms)
                            .expect("sequential packet path keeps ICMP query NAT plan current"),
                        Nat44IcmpTransition::Inbound(plan) => runtime
                            .commit_inbound(plan, nat_now_ms)
                            .expect("sequential packet path keeps ICMP query NAT plan current"),
                    }
                    trace.record(TraceEvent::Nat44Icmp {
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
                if let Some(tracker) = fragment_tracking.as_deref_mut() {
                    if let Some(ticket) = first_fragment {
                        // After the first fragment's own staging, so its
                        // pieces go first; the held fragments follow.
                        match first_template {
                            Some(template) => tracker.commit_allow(
                                ticket,
                                template,
                                snapshot,
                                fragmentation.as_deref_mut(),
                                nat_now_ms,
                            ),
                            None => tracker.commit_deny(ticket, nat_now_ms),
                        }
                    }
                    if let PacketDecision::FragmentFollow(follow) = decision {
                        tracker.followed(follow.entry, follow.info);
                    }
                }
                if let Some(fragments) = planned.fragments {
                    // The datagram lives on in its fragmentation slot; the
                    // received frame goes back to the backend.
                    packet.consume(ConsumeReason::Ipv4Fragmented);
                    consumed += 1;
                    trace.record(TraceEvent::Ipv4FragmentationQueued {
                        ingress,
                        egress,
                        fragments,
                        reason: ConsumeReason::Ipv4Fragmented,
                    });
                    continue;
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
                if let Some(ticket) = first_fragment {
                    if let Some(tracker) = fragment_tracking.as_deref_mut() {
                        tracker.commit_deny(ticket, nat_now_ms);
                    }
                }
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

/// The egress MTU rule of RFC 1812 §4.2.2.7 for every IPv4 decision that
/// sends the received frame (forwarded, NAT-translated, hairpinned,
/// translated ICMP error, local Echo Reply).
///
/// NAT never changes the datagram length, so the received Total Length is
/// the length on the egress link. A datagram of at most the egress MTU
/// passes (one indexed interface lookup and one compare). A longer one is
/// discarded:
///
/// - DF set: [`DropReason::Ipv4FragmentationNeeded`], and an ICMP
///   Destination Unreachable, Fragmentation Needed and DF Set (Type 3,
///   Code 4) whose Next-Hop MTU is the egress MTU (RFC 1191 §4) goes to the
///   datagram's source (RFC 1812 §5.2.7.1) through the generated-ICMPv4
///   path: RFC 1812 §4.3.2.7 suppression (no error about an ICMP error, a
///   non-initial fragment, or a non-unicast source or destination), the
///   reverse route and its interface address as source (§4.3.2.4), the
///   reverse neighbor, the per-kind switch, and the limiter (§4.3.2.8).
///   The quote is the datagram as received, before any translation, so an
///   inside host behind the NAT sees its own datagram and an outside host
///   the one it sent to the public address.
/// - DF clear: fragmented (RFC 1812 §4.2.2.7, RFC 791 §3.2, MTU2 part B)
///   when a fragmentation runtime is bound and its policy is on: the
///   returned plan has passed the per-datagram bound and found a free slot
///   (otherwise a typed drop of the whole datagram, see
///   [`crate::Ipv4FragmentationRuntime`]). Without a runtime, or with
///   `enabled = false`, [`DropReason::Ipv4FragmentationRequired`] without
///   an error (Code 4 means DF set).
/// - A local Echo Reply: [`DropReason::Icmpv4EchoReplyExceedsMtu`]; the
///   router does not fragment its own datagrams.
///
/// A datagram within the MTU in a frame that carries bytes after its Total
/// Length beyond the MTU is [`DropReason::Ipv4FrameExceedsMtu`]: the
/// backend sends the whole frame, which must fit the link.
#[allow(clippy::too_many_arguments)]
fn check_egress_mtu<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    decision: PacketDecision,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    fragmentation: Option<&Ipv4FragmentationRuntime<'_>>,
    trace: &mut T,
) -> Result<Option<Ipv4FragmentPlan>, DropReason> {
    if matches!(
        decision,
        PacketDecision::ArpReply(_)
            | PacketDecision::ConsumeArp(_)
            | PacketDecision::ConsumeIpv4Local
            | PacketDecision::ConsumeFragmentHeld
    ) {
        return Ok(None);
    }
    let mtu = snapshot
        .interface(decision.egress())
        .ok_or(InterfaceMiss)?
        .mtu;
    let total_len =
        packet::read_u16(frame, packet::ETHERNET_HEADER_LEN + 2).ok_or(Ipv4HeaderTruncated)?;
    // The backend sends the whole frame: bytes after Total Length count too.
    let payload_len = frame.len() - packet::ETHERNET_HEADER_LEN;
    if total_len <= mtu {
        if payload_len > usize::from(mtu) {
            return Err(Ipv4FrameExceedsMtu);
        }
        return Ok(None);
    }
    exceeds_egress_mtu(
        frame,
        snapshot,
        ingress,
        decision,
        mtu,
        resolution,
        icmpv4_errors,
        fragmentation,
        trace,
    )
    .map(Some)
}

/// The cold half of [`check_egress_mtu`]: the datagram is longer than
/// `mtu`.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn exceeds_egress_mtu<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    decision: PacketDecision,
    mtu: u16,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    fragmentation: Option<&Ipv4FragmentationRuntime<'_>>,
    trace: &mut T,
) -> Result<Ipv4FragmentPlan, DropReason> {
    if matches!(decision, PacketDecision::Icmpv4EchoReply(_)) {
        return Err(Icmpv4EchoReplyExceedsMtu);
    }
    let ipv4 = validate_ipv4_frame(frame)?;
    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(Ipv4HeaderTruncated)?;
    if flags_fragment & 0x4000 == 0 {
        return fragmentation.map_or(Err(Ipv4FragmentationRequired), |runtime| {
            runtime.plan(frame, mtu)
        });
    }
    if let Some((runtime, now)) = icmpv4_errors.as_mut() {
        let disposition = decide_icmpv4_error(
            frame,
            snapshot,
            ipv4,
            snapshot.route_lookup(ipv4.destination),
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded,
            mtu,
            resolution,
            runtime,
            *now,
            trace,
        );
        trace.record(TraceEvent::Icmpv4FragmentationNeededDisposition {
            ingress,
            disposition,
        });
    }
    Err(Ipv4FragmentationNeeded)
}

/// Whether `frame` is an IPv4 fragment (MF set or a Fragment Offset): the
/// one read the fast path pays for fragment association (NAT-FRAG).
#[inline]
fn is_ipv4_fragment(frame: &[u8]) -> bool {
    matches!(
        frame.get(12..packet::ETHERNET_HEADER_LEN + 8),
        Some([0x08, 0x00, _, _, _, _, _, _, flags, offset])
            if u16::from_be_bytes([*flags, *offset]) & 0x3fff != 0
    )
}

/// A valid IPv4 fragment the association table handles (NAT-FRAG): every
/// fragment the router forwards or translates. A fragment for one of the
/// router's own addresses on its ingress that is not a NAT public address
/// keeps the local path (no reassembly, ICMP4-006). `None` also for an
/// invalid IPv4 header, which the normal decision refuses.
#[cold]
#[inline(never)]
fn tracked_fragment(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
) -> Option<(packet::ValidatedIpv4, Ipv4FragmentInfo)> {
    let ipv4 = validate_ipv4_frame(frame).ok()?;
    let public = nat44_udp_config.is_some_and(|config| config.public_address() == ipv4.destination)
        || nat44_tcp_config.is_some_and(|config| config.public_address() == ipv4.destination)
        || nat44_icmp_config.is_some_and(|config| config.public_address() == ipv4.destination);
    if !public && snapshot.is_local_ipv4_on(ingress, ipv4.destination) {
        return None;
    }
    parse_fragment(frame, ipv4, ingress).map(|info| (ipv4, info))
}

/// Admits a first fragment before its decision (NAT-FRAG): the same L2 and
/// IPv4 ingress checks as the decision (so a frame the decision would refuse
/// for them leaves no entry), RFC 791 structure, and room in the table.
#[cold]
#[inline(never)]
fn admit_first_fragment(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    info: Ipv4FragmentInfo,
    tracker: &mut Ipv4FragmentTracker<'_>,
    now_ms: u64,
) -> Result<Ipv4FragmentFirstTicket, DropReason> {
    validate_ethernet_ingress(frame, snapshot, ingress, IPV4_ETHERTYPE)?;
    validate_ipv4_ingress(snapshot, ipv4)?;
    info.check_structure()?;
    tracker.admit_first(info, now_ms)
}

/// Decides a later fragment (Fragment Offset not 0, NAT-FRAG) without a
/// transport header: the L2 and IPv4 ingress checks, no options, RFC 791
/// structure, no overlap with the transport header (RFC 1858, RFC 3128),
/// then its first fragment's decision through the association table:
/// forwarded with the first fragment's rewrite, refused, or held until the
/// first fragment arrives. A TTL that expires drops it without an ICMP
/// error (RFC 1812 §4.3.2.7: none about a non-initial fragment).
#[cold]
#[inline(never)]
fn decide_later_fragment(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    info: Ipv4FragmentInfo,
    tracker: &mut Ipv4FragmentTracker<'_>,
    now_ms: u64,
) -> Result<PacketDecision, DropReason> {
    validate_ethernet_ingress(frame, snapshot, ingress, IPV4_ETHERTYPE)?;
    validate_ipv4_ingress(snapshot, ipv4)?;
    if ipv4.header_len != 20 {
        return Err(Ipv4OptionsUnsupported);
    }
    info.check_structure()?;
    info.check_static_overlap()?;
    let frame_len = ipv4.header_offset + ipv4.total_len;
    match tracker.follow(info, frame, frame_len, now_ms)? {
        Ipv4FragmentFollow::Allow { entry, template } => {
            if ipv4.ttl <= 1 {
                return Err(Ipv4TtlExpired);
            }
            Ok(PacketDecision::FragmentFollow(FragmentFollowDecision {
                entry,
                template,
                info,
            }))
        }
        Ipv4FragmentFollow::Deny => Err(Ipv4FragmentFirstDenied),
        Ipv4FragmentFollow::Held => Ok(PacketDecision::ConsumeFragmentHeld),
    }
}

#[allow(clippy::too_many_arguments)]
fn decide<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    first_fragment: bool,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_plan: &mut Option<FirewallPlan>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let ether_type = packet::read_u16(frame, 12).ok_or(EthernetHeaderTruncated)?;
    validate_ethernet_ingress(frame, snapshot, ingress, ether_type)?;
    match ether_type {
        IPV4_ETHERTYPE => decide_ipv4(
            frame,
            snapshot,
            ingress,
            first_fragment,
            resolution,
            icmpv4_errors,
            nat44_udp_config,
            nat44_udp,
            nat44_tcp_config,
            nat44_tcp,
            nat44_icmp_config,
            nat44_icmp,
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
        .interface(ingress)
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
    if snapshot.is_local_ipv4(ipv4.source) {
        return Err(Ipv4SourceLocalAddress);
    }
    if let Some(selected) = snapshot.route_lookup(ipv4.source) {
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
    first_fragment: bool,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_plan: &mut Option<FirewallPlan>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let mut ipv4 = validate_ipv4_frame(frame)?;
    // Only the fragment association table admits a first fragment
    // (NAT-FRAG); the validators then check its transport header only.
    ipv4.first_fragment = first_fragment;
    trace.record(TraceEvent::Ipv4Validated {
        ingress,
        destination: ipv4.destination,
    });
    validate_ipv4_ingress(snapshot, ipv4)?;
    let local = snapshot.is_local_ipv4_on(ingress, ipv4.destination);
    let selected_route = if local {
        None
    } else {
        snapshot.route_lookup(ipv4.destination)
    };
    if !local {
        validate_ipv4_forward_destination(ipv4, selected_route)?;
    }
    let nat_now = resolution
        .as_ref()
        .map_or(MonotonicMillis(0), |(_, now)| *now);
    let combined_realm_mismatch = matches!((nat44_udp_config, nat44_tcp_config), (Some(udp), Some(tcp)) if !tcp.realm_matches_udp(*udp))
        || nat44_icmp_config.is_some_and(|icmp| {
            nat44_udp_config.is_some_and(|udp| {
                !icmp.realm_matches(udp.inside(), udp.outside(), udp.public_address())
            }) || nat44_tcp_config.is_some_and(|tcp| {
                !icmp.realm_matches(tcp.inside(), tcp.outside(), tcp.public_address())
            })
        });
    // Inside-realm errors (RFC 5508 REQ-5, REQ-7) before the external
    // candidate, which would otherwise claim an inside error addressed to
    // the public address as a wrong-ingress external error.
    if is_nat44_icmpv4_inside_candidate(
        frame,
        ingress,
        ipv4,
        local,
        selected_route,
        nat44_udp_config,
        nat44_tcp_config,
        nat44_icmp_config,
    ) {
        let related_firewall = firewall_config
            .map(|config| require_firewall_runtime(snapshot, config, firewall))
            .transpose()?;
        return decide_nat44_icmpv4_inside_error(
            frame,
            snapshot,
            ingress,
            ipv4,
            selected_route,
            resolution,
            nat44_udp_config,
            nat44_udp,
            nat44_tcp_config,
            nat44_tcp,
            nat44_icmp_config,
            nat44_icmp,
            nat_now,
            combined_realm_mismatch,
            related_firewall,
            firewall_audit,
            trace,
        );
    }
    if is_nat44_icmpv4_candidate(
        frame,
        ipv4,
        nat44_udp_config,
        nat44_tcp_config,
        nat44_icmp_config,
    ) {
        let related_firewall = firewall_config
            .map(|config| require_firewall_runtime(snapshot, config, firewall))
            .transpose()?;
        return decide_nat44_icmpv4_frag_needed(
            frame,
            snapshot,
            ingress,
            ipv4,
            resolution,
            icmpv4_errors,
            nat44_udp_config,
            nat44_udp,
            nat44_tcp_config,
            nat44_tcp,
            nat44_icmp_config,
            nat44_icmp,
            nat_now,
            combined_realm_mismatch,
            related_firewall,
            firewall_audit,
            trace,
        );
    }
    // ICMP queries addressed to the public address (N5). A request is for
    // the router, which owns that address, from either realm; only a reply
    // arriving from the outside can name a query mapping.
    let icmp_reply_to_public = nat44_icmp_config.is_some_and(|config| {
        ipv4.destination == config.public_address()
            && peek_icmp_type(frame, ipv4).is_some_and(is_query_reply)
    });
    if let Some(config) = nat44_icmp_config {
        if ipv4.destination == config.public_address() {
            if ingress == config.inside()
                && peek_icmp_type(frame, ipv4).is_some_and(is_query_request)
            {
                return decide_local_ipv4(frame, snapshot, ingress, ipv4, trace);
            }
            if icmp_reply_to_public && ingress != config.outside() {
                return nat44_icmp_drop(ingress, Nat44IcmpWrongIngress, trace);
            }
        }
    }
    let nat_inbound_candidate = nat44_udp_config
        .is_some_and(|config| ipv4.destination == config.public_address() && ipv4.protocol == 17)
        || nat44_tcp_config.is_some_and(|config| {
            ipv4.destination == config.public_address() && ipv4.protocol == 6
        })
        || icmp_reply_to_public;
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
                    | FirewallPlanError::InvalidInitialIcmp(_)
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
                nat44_icmp_config,
                nat44_icmp,
                nat_now,
                trace,
            )?;
            firewall_validated = Some(validated);
        }
    }
    if combined_realm_mismatch
        && (matches!(ipv4.protocol, 6 | 17) || icmp_reply_to_public)
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
            && ipv4.protocol == 17
        {
            return decide_nat44_udp_hairpin(
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
        if ingress == config.inside()
            && ipv4.destination == config.public_address()
            && ipv4.protocol == 6
            && nat44_tcp_config.is_none()
        {
            observe_nat_candidate_if_present(snapshot, config, nat44_udp, nat_now, ingress, trace)?;
            return nat44_udp_drop(ingress, Nat44UdpUnsupportedTransport, trace);
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
            && ipv4.protocol == 6
        {
            return decide_nat44_tcp_hairpin(
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
        if ingress == config.inside()
            && ipv4.destination == config.public_address()
            && ipv4.protocol == 17
            && nat44_udp_config.is_none()
        {
            observe_nat44_tcp_candidate_if_present(
                snapshot, config, nat44_tcp, nat_now, ingress, trace,
            )?;
            return nat44_tcp_drop(ingress, Nat44TcpUnsupportedTransport, trace);
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
    if let Some(config) = nat44_icmp_config {
        if icmp_reply_to_public {
            return decide_nat44_icmp_inbound(
                frame,
                snapshot,
                ingress,
                ipv4,
                resolution,
                config,
                nat44_icmp,
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
    let Some(route) = selected_route else {
        if let Some(config) = firewall_config {
            // RFC 1812 §5.2.7.1 requires Destination Unreachable (Network),
            // but only for packets the policy would admit toward every
            // possible egress; anything else stays a silent drop so the error
            // never becomes a route oracle.
            let runtime = require_firewall_runtime(snapshot, config, firewall)?;
            if route_miss_may_hit_nat_reject(
                snapshot,
                ingress,
                ipv4.protocol,
                combined_realm_mismatch,
                nat44_udp_config,
                nat44_udp,
                nat44_tcp_config,
                nat44_tcp,
                nat44_icmp_config,
                nat44_icmp,
            ) {
                return Err(FirewallRouteUnavailable);
            }
            let validated =
                firewall_validated.expect("forward firewall packet was preflight validated");
            let packet = FirewallRouteMissPacket {
                ingress,
                source: ipv4.source,
                destination: ipv4.destination,
                protocol: validated.protocol,
                source_port: validated.source_port,
                destination_port: validated.destination_port,
                tcp_flags: validated.tcp_flags,
            };
            if runtime.permits_route_miss(config, packet).is_none() {
                return Err(FirewallRouteUnavailable);
            }
        }
        if let Some((runtime, now)) = icmpv4_errors.as_mut() {
            let disposition = decide_icmpv4_error(
                frame,
                snapshot,
                ipv4,
                None,
                Icmpv4ErrorKind::DestinationUnreachableNetwork,
                0,
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
    let icmp_nat = nat44_icmp_config.is_some() && ipv4.protocol == 1;
    if combined_realm_mismatch && (matches!(ipv4.protocol, 6 | 17) || icmp_nat) {
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
    if crosses_internal_to_external && !matches!(ipv4.protocol, 6 | 17) && !icmp_nat {
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
        if let Some(icmp_config) = nat44_icmp_config {
            if ingress == icmp_config.inside()
                && route.egress() == icmp_config.outside()
                && ipv4.protocol == 1
            {
                let _ =
                    require_nat44_icmp_runtime(snapshot, icmp_config, nat44_icmp, ingress, trace)?;
            }
        }
        let runtime = require_firewall_runtime(snapshot, config, firewall)?;
        *firewall_plan = Some(plan_firewall(
            ingress,
            route.egress(),
            ipv4,
            firewall_validated.expect("forward firewall packet was preflight validated"),
            None,
            config,
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
                0,
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
    let interface = snapshot.interface(route.egress()).ok_or(InterfaceMiss)?;
    let static_neighbor = snapshot.static_neighbor(route.egress(), target);
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
                if let Some(binding) = snapshot.local_binding_on(route.egress()) {
                    let result = runtime.schedule(
                        ArpRequestAction {
                            egress: route.egress(),
                            source_mac: interface.mac,
                            source_ip: binding.address,
                            target_ip: target,
                        },
                        *now,
                        snapshot.is_local_ipv4(target)
                            || snapshot.is_connected_boundary(route.egress(), target),
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
    if let Some(config) = nat44_icmp_config {
        if ingress == config.inside() && route.egress() == config.outside() && ipv4.protocol == 1 {
            return decide_nat44_icmp_outbound(
                frame,
                snapshot,
                ingress,
                ipv4,
                forwarding,
                config,
                nat44_icmp,
                firewall_config.is_some(),
                nat_now,
                trace,
            );
        }
    }
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

/// ICMPv4 error messages NAT44 translates (RFC 5508 REQ-10; RFC 792 and
/// RFC 1812 §§4.3.2, 5.2.7 for the codes).
///
/// - Destination Unreachable (Type 3, REQ-10 a.1): codes 0–4, 6, 7, and
///   9–15. Code 5 (Source Route Failed) is excluded because NAT44 translates
///   only packets without IPv4 options, so no translated packet can carry a
///   source route. Code 8 (Source Host Isolated) is obsolete (RFC 1812
///   §5.2.7.1: routers SHOULD NOT generate it).
/// - Time Exceeded (Type 11, REQ-10 a.2): code 0 only. Code 1 (Fragment
///   Reassembly) needs a fragment, and NAT44 translates only atomic
///   datagrams (the quote must be DF=1/MF=0/offset=0).
/// - Parameter Problem (Type 12, REQ-10 b.5, MAY): codes 0–2. The pointer is
///   an offset into the quoted packet, which translation never moves.
///
/// Source Quench (Type 4) is excluded (REQ-10 c.1 SHOULD NOT; deprecated by
/// RFC 6633), and Redirect (Type 5, REQ-10 b.1 MAY) is excluded because a
/// redirect is link-local advice that must never cross the NAT.
pub(crate) const fn nat44_icmpv4_error_supported(icmp_type: u8, code: u8) -> bool {
    match icmp_type {
        3 => matches!(code, 0..=4 | 6 | 7 | 9..=15),
        11 => code == 0,
        12 => code <= 2,
        _ => false,
    }
}

/// Whether only the quoted destination host itself generates this error:
/// Protocol Unreachable and Port Unreachable (RFC 1812 §5.2.7.1, RFC 792)
/// report the absence of a transport or port at the destination host,
/// never a condition on the path.
///
/// As a local policy ("unless explicitly overridden by local policy", RFC
/// 5508 REQ-4 and REQ-5), NAT44 translates these only when the outer source
/// is that host. Otherwise an off-path sender using its own, unspoofed
/// address could sweep public ports and tear down inside UDP flows with a
/// hard error.
pub(crate) const fn nat44_icmpv4_error_end_host_only(icmp_type: u8, code: u8) -> bool {
    icmp_type == 3 && matches!(code, 2 | 3)
}

/// Type, code, and quoted protocol of an ICMPv4 message, peeked within the
/// outer IPv4 Total Length only (link padding is never a candidate byte).
fn peek_nat44_icmpv4_error(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Option<(u8, u8, Option<u8>)> {
    if ipv4.protocol != 1 {
        return None;
    }
    let ipv4_end = ipv4.header_offset.checked_add(ipv4.total_len)?;
    let icmp_offset = ipv4.header_offset.checked_add(ipv4.header_len)?;
    let type_code_end = icmp_offset.checked_add(2)?;
    if type_code_end > ipv4_end {
        return None;
    }
    let type_code = frame.get(icmp_offset..type_code_end)?;
    let quoted_protocol = icmp_offset
        .checked_add(8 + 9)
        .filter(|offset| *offset < ipv4_end)
        .and_then(|offset| frame.get(offset))
        .copied();
    Some((type_code[0], type_code[1], quoted_protocol))
}

fn is_nat44_icmpv4_candidate(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
) -> bool {
    let Some((icmp_type, code, quoted_protocol)) = peek_nat44_icmpv4_error(frame, ipv4) else {
        return false;
    };
    if !nat44_icmpv4_error_supported(icmp_type, code) {
        return false;
    }

    let udp_enabled = nat44_udp_config.is_some_and(|config| {
        config.policy().icmpv4_errors().translates_external()
            && ipv4.destination == config.public_address()
    });
    let tcp_enabled = nat44_tcp_config.is_some_and(|config| {
        config.policy().icmpv4_errors().translates_external()
            && ipv4.destination == config.public_address()
    });
    let icmp_enabled = nat44_icmp_config.is_some_and(|config| {
        config.policy().icmpv4_errors().translates_external()
            && ipv4.destination == config.public_address()
    });
    match quoted_protocol {
        Some(17) => udp_enabled,
        Some(6) => tcp_enabled,
        Some(1) if nat44_icmp_config.is_some() => icmp_enabled,
        Some(_) | None => udp_enabled || tcp_enabled || icmp_enabled,
    }
}

#[derive(Clone, Copy)]
struct ParsedNat44Icmpv4Quote {
    icmp_type: u8,
    icmp_code: u8,
    protocol: u8,
    source_address: crate::Ipv4Address,
    source_port: u16,
    destination_address: crate::Ipv4Address,
    destination_port: u16,
    inner_checksum_offset: usize,
    inner_checksum: u16,
    inner_source_offset: usize,
    inner_port_offset: usize,
    transport_checksum_offset: Option<usize>,
    transport_checksum: Option<u16>,
    icmp_checksum_offset: usize,
    icmp_checksum: u16,
    /// ICMP type of a quoted ICMP query (N5); `None` for UDP and TCP. A
    /// quoted query's identifier is both `source_port` and
    /// `destination_port`, at `inner_port_offset`, and its ICMP checksum is
    /// the transport checksum (no pseudo-header).
    query_type: Option<u8>,
}

impl ParsedNat44Icmpv4Quote {
    /// Firewall pseudo-ports of the quoted packet with the identifier (or
    /// ports) replaced by `source_port` and `destination_port`.
    fn firewall_ports(self, source_port: u16, destination_port: u16) -> (u16, u16) {
        match self.query_type {
            Some(query_type) => {
                let identifier = if nat44_icmp_query::is_query_request(query_type) {
                    source_port
                } else {
                    destination_port
                };
                nat44_icmp_query::firewall_ports(query_type, identifier)
                    .expect("only quoted queries are translated")
            }
            None => (source_port, destination_port),
        }
    }
}

/// Whether a quoted remote names one of the router's own IPv4 addresses,
/// including the NAT public address. Only hairpinned packets create NAT
/// state with such a remote.
fn quoted_remote_is_local(snapshot: &ForwardingSnapshot<'_>, remote: crate::Ipv4Address) -> bool {
    snapshot.is_local_ipv4(remote)
}

fn nat44_udp_icmpv4_lookup_reason(error: Nat44UdpPlanError) -> DropReason {
    match error {
        Nat44UdpPlanError::MappingMiss => Nat44UdpMappingMiss,
        Nat44UdpPlanError::FilterDenied => Nat44UdpFilterDenied,
        Nat44UdpPlanError::ClockRegression => Nat44UdpClockRegression,
        Nat44UdpPlanError::MappingFull
        | Nat44UdpPlanError::PeerFull
        | Nat44UdpPlanError::PortExhausted
        | Nat44UdpPlanError::HostQuotaExceeded
        | Nat44UdpPlanError::HostPeerQuotaExceeded
        | Nat44UdpPlanError::GenerationExhausted
        | Nat44UdpPlanError::StateRevisionExhausted => {
            unreachable!("read-only ICMP lookup cannot exhaust state")
        }
        Nat44UdpPlanError::IndexCorrupt => Nat44UdpConfigMismatch,
    }
}

fn nat44_tcp_icmpv4_lookup_reason(error: Nat44TcpPlanError) -> DropReason {
    match error {
        Nat44TcpPlanError::MappingMiss => Nat44TcpMappingMiss,
        Nat44TcpPlanError::SessionMiss => Nat44TcpSessionMiss,
        Nat44TcpPlanError::ClockRegression => Nat44TcpClockRegression,
        Nat44TcpPlanError::InvalidInitialFlags
        | Nat44TcpPlanError::MappingFull
        | Nat44TcpPlanError::SessionFull
        | Nat44TcpPlanError::PortExhausted
        | Nat44TcpPlanError::InboundRemoteQuotaExceeded
        | Nat44TcpPlanError::HostQuotaExceeded
        | Nat44TcpPlanError::HostSessionQuotaExceeded => {
            unreachable!("read-only ICMP lookup cannot create state")
        }
        Nat44TcpPlanError::IndexCorrupt
        | Nat44TcpPlanError::GenerationExhausted
        | Nat44TcpPlanError::StateRevisionExhausted => Nat44TcpConfigMismatch,
    }
}

/// Read-only firewall RELATED check of one quoted flow, with audit.
///
/// `either_direction` selects
/// [`FirewallRuntime::inspect_related_icmpv4_either_direction`] (the quoted
/// packet was received by the error's sender) instead of the direct-only
/// [`FirewallRuntime::inspect_related_icmpv4`] (the quoted packet was sent
/// by the inside host the error is delivered to).
fn inspect_nat44_icmpv4_related<T: TraceSink>(
    runtime: &FirewallRuntime<'_>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    packet: FirewallPacket,
    either_direction: bool,
    ingress: IfId,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<(), DropReason> {
    let flow = FirewallRelatedIcmpv4Flow::new(
        packet.ingress,
        packet.egress,
        packet.source,
        packet.destination,
        packet.protocol,
        packet.source_port,
        packet.destination_port,
    );
    // A quoted ICMP query reply is RELATED only as the reverse of a flow.
    let flow = if packet.protocol == FirewallProtocol::Icmp
        && packet.tcp_flags & crate::firewall::FIREWALL_ICMP_REPLY != 0
    {
        flow.with_icmp_query_reply()
    } else {
        flow
    };
    let result = if either_direction {
        runtime.inspect_related_icmpv4_either_direction(flow, now.0)
    } else {
        runtime.inspect_related_icmpv4(flow, now.0)
    };
    match result {
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
            Ok(())
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
            Err(trace_nat44_icmpv4_drop(
                ingress,
                FirewallRelatedIcmpv4StateMiss,
                trace,
            ))
        }
        Err(FirewallRelatedIcmpv4Error::ClockRegression) => Err(trace_nat44_icmpv4_drop(
            ingress,
            FirewallClockRegression,
            trace,
        )),
    }
}

/// Static or fresh dynamic neighbor toward `target` on `egress`. A miss
/// schedules ARP like an ordinary forwarded packet and reports
/// `NeighborUnresolved`.
fn resolve_nat44_icmpv4_next_hop<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    egress: IfId,
    target: crate::Ipv4Address,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    trace: &mut T,
) -> Result<(Interface, crate::MacAddress), DropReason> {
    let interface = *snapshot.interface(egress).ok_or(InterfaceMiss)?;
    let destination_mac = if let Some(neighbor) = snapshot.static_neighbor(egress, target) {
        neighbor.mac
    } else if let Some((runtime, resolution_now)) = resolution.as_mut() {
        match runtime.lookup_dynamic(egress, target, *resolution_now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                trace.record(TraceEvent::NeighborResolution {
                    egress,
                    target,
                    result: ResolutionResult::ClockRegression,
                });
                return Err(NeighborUnresolved);
            }
            DynamicLookup::Miss => {
                if let Some(binding) = snapshot.local_binding_on(egress) {
                    let result = runtime.schedule(
                        ArpRequestAction {
                            egress,
                            source_mac: interface.mac,
                            source_ip: binding.address,
                            target_ip: target,
                        },
                        *resolution_now,
                        snapshot.is_local_ipv4(target)
                            || snapshot.is_connected_boundary(egress, target),
                    );
                    trace.record(TraceEvent::NeighborResolution {
                        egress,
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
        egress,
        neighbor_target: target,
    });
    Ok((interface, destination_mac))
}

#[allow(clippy::too_many_arguments)]
fn decide_nat44_icmpv4_frag_needed<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    outer: packet::ValidatedIpv4,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
    now: MonotonicMillis,
    combined_realm_mismatch: bool,
    related_firewall: Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let quote = parse_nat44_icmpv4_error(frame, outer)
        .map_err(|reason| trace_nat44_icmpv4_drop(ingress, reason, trace))?;
    if !icmp_error_source_is_host(snapshot, outer.source) || snapshot.is_local_ipv4(outer.source) {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4SourceForbidden, trace);
    }
    if nat44_icmpv4_error_end_host_only(quote.icmp_type, quote.icmp_code)
        && outer.source != quote.destination_address
    {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4EndHostSourceMismatch, trace);
    }

    let (inside, outside, internal_address, internal_port) = match quote.protocol {
        17 => {
            let Some(config) = nat44_udp_config else {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
            };
            if !config.policy().icmpv4_errors().translates_external()
                || outer.destination != config.public_address()
                || quote.source_address != config.public_address()
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedPublicSourceMismatch, trace);
            }
            // A quoted remote naming a router address can only match state
            // the hairpin outbound half created (remote = the public
            // address). An outside error must never reach it.
            if quoted_remote_is_local(snapshot, quote.destination_address) {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedRemoteLocal, trace);
            }
            if combined_realm_mismatch {
                return nat44_icmpv4_drop(ingress, Nat44CombinedRealmMismatch, trace);
            }
            if ingress != config.outside() {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongIngress, trace);
            }
            if snapshot
                .route_lookup(outer.source)
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
                .inspect_icmpv4(
                    quote.source_port,
                    quote.destination_address,
                    quote.destination_port,
                    now.0,
                )
                .map_err(|error| {
                    trace_nat44_icmpv4_drop(ingress, nat44_udp_icmpv4_lookup_reason(error), trace)
                })?;
            (
                config.inside(),
                config.outside(),
                lookup.internal_address(),
                lookup.internal_port(),
            )
        }
        6 => {
            let Some(config) = nat44_tcp_config else {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
            };
            if !config.policy().icmpv4_errors().translates_external()
                || outer.destination != config.public_address()
                || quote.source_address != config.public_address()
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedPublicSourceMismatch, trace);
            }
            // A quoted remote naming a router address can only match state
            // the hairpin outbound half created (remote = the public
            // address). An outside error must never reach it.
            if quoted_remote_is_local(snapshot, quote.destination_address) {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedRemoteLocal, trace);
            }
            if combined_realm_mismatch {
                return nat44_icmpv4_drop(ingress, Nat44CombinedRealmMismatch, trace);
            }
            if ingress != config.outside() {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongIngress, trace);
            }
            if snapshot
                .route_lookup(outer.source)
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
                    quote.source_port,
                    quote.destination_address,
                    quote.destination_port,
                    now.0,
                )
                .map_err(|error| {
                    trace_nat44_icmpv4_drop(ingress, nat44_tcp_icmpv4_lookup_reason(error), trace)
                })?;
            (
                config.inside(),
                config.outside(),
                lookup.internal_address(),
                lookup.internal_port(),
            )
        }
        // A quoted ICMP query (N5): the request the NAT sent from the public
        // address with a public identifier (RFC 5508 REQ-4 with the query
        // identifier as the "port", §3.1).
        1 => {
            let Some(config) = nat44_icmp_config else {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
            };
            if !quote
                .query_type
                .is_some_and(nat44_icmp_query::is_query_request)
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
            }
            if !config.policy().icmpv4_errors().translates_external()
                || outer.destination != config.public_address()
                || quote.source_address != config.public_address()
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedPublicSourceMismatch, trace);
            }
            if quoted_remote_is_local(snapshot, quote.destination_address) {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedRemoteLocal, trace);
            }
            if combined_realm_mismatch {
                return nat44_icmpv4_drop(ingress, Nat44CombinedRealmMismatch, trace);
            }
            if ingress != config.outside() {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongIngress, trace);
            }
            if snapshot
                .route_lookup(outer.source)
                .is_none_or(|reverse| reverse.egress() != config.outside())
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4SourceForbidden, trace);
            }
            if !config.authority_matches(snapshot) {
                return nat44_icmpv4_drop(ingress, Nat44IcmpConfigMismatch, trace);
            }
            let Some(runtime) = nat44_icmp.as_deref() else {
                return nat44_icmpv4_drop(ingress, Nat44IcmpRuntimeUnavailable, trace);
            };
            if runtime.config() != *config {
                return nat44_icmpv4_drop(ingress, Nat44IcmpConfigMismatch, trace);
            }
            let lookup = runtime
                .inspect_error_quote(quote.source_port, quote.destination_address, now.0)
                .map_err(|error| {
                    trace_nat44_icmpv4_drop(
                        ingress,
                        nat44_icmp_query::nat44_icmp_error_lookup_reason(error),
                        trace,
                    )
                })?;
            (
                config.inside(),
                config.outside(),
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
            .expect("the NAT ICMPv4 parser accepts only ICMP, UDP, and TCP quotes");
        let (source_port, destination_port) =
            quote.firewall_ports(internal_port, quote.destination_port);
        let packet = FirewallPacket {
            ingress: inside,
            egress: outside,
            source: internal_address,
            destination: quote.destination_address,
            protocol,
            source_port,
            destination_port,
            tcp_flags: 0,
        };
        inspect_nat44_icmpv4_related(runtime, firewall_audit, packet, false, ingress, now, trace)?;
    }

    let route = snapshot.route_lookup(internal_address).ok_or(RouteMiss)?;
    if route.egress() != inside {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongEgress, trace);
    }
    // NAT44-065: the per-inside-host limit is the last gate, after every
    // read-only authority check and before the only side effect (neighbor
    // resolution may schedule ARP), so an error that would be refused
    // anyway never spends the budget and a limited one never starts ARP.
    if let Some((runtime, errors_now)) = icmpv4_errors.as_mut() {
        if !runtime.admit_translated(internal_address, quote.destination_address, *errors_now) {
            return nat44_icmpv4_drop(ingress, Nat44Icmpv4TranslatedRateLimited, trace);
        }
    }
    let target = route.next_hop().unwrap_or(internal_address);
    let (interface, destination_mac) =
        resolve_nat44_icmpv4_next_hop(snapshot, inside, target, resolution, trace)?;
    Ok(build_nat44_icmpv4_rewrite(
        outer,
        quote,
        inside,
        interface.mac.0,
        destination_mac.0,
        Nat44Icmpv4Rewrite {
            outer_source: None,
            outer_destination: Some(internal_address),
            quoted_source: Some((internal_address, internal_port)),
            quoted_destination: None,
        },
        Nat44Icmpv4Disposition::Translated {
            quoted_protocol: quote.protocol,
            internal_address,
            internal_port,
        },
    ))
}

/// Parses and validates a candidate ICMPv4 error and its quote (RFC 5508
/// REQ-3): outer IHL 5, nonfragment, TTL > 1, valid ICMP checksum, a
/// Fragmentation Needed Next-Hop MTU of 0 or at least 68; a quoted
/// IPv4 header with a valid checksum (options skipped by IHL), reserved flag
/// and DF ignored, MF=0/offset=0, UDP, TCP or an ICMP query, and the first
/// 8 transport bytes.
/// The embedded transport checksum is located but not validated.
fn parse_nat44_icmpv4_error(
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
    // A Next-Hop MTU of 1..=67 is below the IPv4 minimum every link carries
    // (RFC 791: 68 octets), so no router can report it (RFC 1191 §4: the
    // MTU of the next-hop network). Zero is a router predating RFC 1191
    // (§5, the host estimates a plateau) and stays valid.
    if icmp[0] == 3 && icmp[1] == 4 {
        let mtu = u16::from_be_bytes([icmp[6], icmp[7]]);
        if (1..68).contains(&mtu) {
            return Err(Nat44Icmpv4FragNeededMtuInvalid);
        }
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
    let protocol = *inner_header
        .get(9)
        .ok_or(Nat44Icmpv4QuotedHeaderTruncated)?;
    // The quoted datagram must be whole, as every translated datagram
    // (NAT44-008, NAT44-116): MF clear and offset 0, DF either way (MTU2).
    if inner_flags & 0x3fff != 0 {
        return Err(Nat44Icmpv4QuotedFragmentUnsupported);
    }
    if !matches!(protocol, 1 | 6 | 17) {
        return Err(Nat44Icmpv4QuotedProtocolUnsupported);
    }
    let source_address = crate::Ipv4Address::from_octets(
        inner_header[12..16]
            .try_into()
            .expect("validated IPv4 header contains the source address"),
    );
    let destination_address = crate::Ipv4Address::from_octets(
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
    if protocol == 1 {
        // A quoted ICMP query: type, code, checksum, identifier, sequence.
        // RFC 792 guarantees these 8 bytes; the checksum is updated
        // incrementally, so a truncated quote is still corrected exactly.
        let query_type = *frame
            .get(transport_offset)
            .ok_or(Nat44Icmpv4QuoteTruncated)?;
        let identifier =
            packet::read_u16(frame, transport_offset + 4).ok_or(Nat44Icmpv4QuoteTruncated)?;
        return Ok(ParsedNat44Icmpv4Quote {
            icmp_type: icmp[0],
            icmp_code: icmp[1],
            protocol,
            source_address,
            source_port: identifier,
            destination_address,
            destination_port: identifier,
            inner_checksum_offset: quote_offset + 10,
            inner_checksum: packet::read_u16(frame, quote_offset + 10)
                .ok_or(Nat44Icmpv4QuotedHeaderTruncated)?,
            inner_source_offset: quote_offset + 12,
            inner_port_offset: transport_offset + 4,
            transport_checksum_offset: Some(transport_offset + 2),
            transport_checksum: Some(
                packet::read_u16(frame, transport_offset + 2).ok_or(Nat44Icmpv4QuoteTruncated)?,
            ),
            icmp_checksum_offset: icmp_offset + 2,
            icmp_checksum: packet::read_u16(frame, icmp_offset + 2)
                .ok_or(Nat44Icmpv4HeaderTruncated)?,
            query_type: Some(query_type),
        });
    }
    let source_port = packet::read_u16(frame, transport_offset).ok_or(Nat44Icmpv4QuoteTruncated)?;
    let destination_port =
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
        icmp_type: icmp[0],
        icmp_code: icmp[1],
        protocol,
        source_address,
        source_port,
        destination_address,
        destination_port,
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
        query_type: None,
    })
}

/// Address/port replacements of one ICMPv4 error translation; `None` keeps
/// the received value.
#[derive(Clone, Copy)]
struct Nat44Icmpv4Rewrite {
    outer_source: Option<crate::Ipv4Address>,
    outer_destination: Option<crate::Ipv4Address>,
    quoted_source: Option<(crate::Ipv4Address, u16)>,
    quoted_destination: Option<(crate::Ipv4Address, u16)>,
}

fn address_words(address: crate::Ipv4Address) -> [u16; 2] {
    let octets = address.octets();
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
    ]
}

/// RFC 1624 update of `checksum` for one replaced IPv4 address.
fn rfc1624_update_address(checksum: u16, old: crate::Ipv4Address, new: crate::Ipv4Address) -> u16 {
    let [old_high, old_low] = address_words(old);
    let [new_high, new_low] = address_words(new);
    rfc1624_update(
        rfc1624_update(checksum, old_high, new_high),
        old_low,
        new_low,
    )
}

/// Builds the in-place rewrite of a validated ICMPv4 error: Ethernet, outer
/// TTL decrement and addresses, quoted addresses and ports, and the outer
/// IPv4, quoted IPv4, quoted transport (within the quoted Total Length only,
/// UDP zero preserved), and ICMP checksums, all by RFC 1624 incremental
/// update. The work is a fixed number of word updates (NAT44-019C).
fn build_nat44_icmpv4_rewrite(
    outer: packet::ValidatedIpv4,
    quote: ParsedNat44Icmpv4Quote,
    egress: IfId,
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    rewrite: Nat44Icmpv4Rewrite,
    disposition: Nat44Icmpv4Disposition,
) -> PacketDecision {
    let outer_source = rewrite.outer_source.unwrap_or(outer.source);
    let outer_destination = rewrite.outer_destination.unwrap_or(outer.destination);
    let (quoted_source, quoted_source_port) = rewrite
        .quoted_source
        .unwrap_or((quote.source_address, quote.source_port));
    let (quoted_destination, quoted_destination_port) = rewrite
        .quoted_destination
        .unwrap_or((quote.destination_address, quote.destination_port));
    let source_changed = rewrite.quoted_source.is_some();
    let destination_changed = rewrite.quoted_destination.is_some();
    // A quoted ICMP query has one identifier field, rewritten from the
    // changed side's "port".
    let icmp_query = quote.query_type.is_some();
    let new_identifier = if source_changed {
        quoted_source_port
    } else if destination_changed {
        quoted_destination_port
    } else {
        quote.source_port
    };

    let mut inner_checksum = quote.inner_checksum;
    if source_changed {
        inner_checksum =
            rfc1624_update_address(inner_checksum, quote.source_address, quoted_source);
    }
    if destination_changed {
        inner_checksum = rfc1624_update_address(
            inner_checksum,
            quote.destination_address,
            quoted_destination,
        );
    }
    let transport_checksum = quote.transport_checksum.map(|checksum| {
        if icmp_query {
            // ICMP has no pseudo-header: only the identifier is covered.
            return rfc1624_update(checksum, quote.source_port, new_identifier);
        }
        if quote.protocol == 17 && checksum == 0 {
            return 0;
        }
        let mut updated = checksum;
        if source_changed {
            updated = rfc1624_update_address(updated, quote.source_address, quoted_source);
            updated = rfc1624_update(updated, quote.source_port, quoted_source_port);
        }
        if destination_changed {
            updated =
                rfc1624_update_address(updated, quote.destination_address, quoted_destination);
            updated = rfc1624_update(updated, quote.destination_port, quoted_destination_port);
        }
        if quote.protocol == 17 && updated == 0 {
            0xffff
        } else {
            updated
        }
    });
    let mut icmp_checksum =
        rfc1624_update(quote.icmp_checksum, quote.inner_checksum, inner_checksum);
    if source_changed {
        icmp_checksum = rfc1624_update_address(icmp_checksum, quote.source_address, quoted_source);
        if !icmp_query {
            icmp_checksum = rfc1624_update(icmp_checksum, quote.source_port, quoted_source_port);
        }
    }
    if destination_changed {
        icmp_checksum =
            rfc1624_update_address(icmp_checksum, quote.destination_address, quoted_destination);
        if !icmp_query {
            icmp_checksum = rfc1624_update(
                icmp_checksum,
                quote.destination_port,
                quoted_destination_port,
            );
        }
    }
    if icmp_query {
        icmp_checksum = rfc1624_update(icmp_checksum, quote.source_port, new_identifier);
    }
    if let (Some(old), Some(new)) = (quote.transport_checksum, transport_checksum) {
        icmp_checksum = rfc1624_update(icmp_checksum, old, new);
    }

    let mut outer_checksum = rfc1624_update(
        outer.checksum,
        u16::from_be_bytes([outer.ttl, outer.protocol]),
        u16::from_be_bytes([outer.ttl - 1, outer.protocol]),
    );
    if rewrite.outer_source.is_some() {
        outer_checksum = rfc1624_update_address(outer_checksum, outer.source, outer_source);
    }
    if rewrite.outer_destination.is_some() {
        outer_checksum =
            rfc1624_update_address(outer_checksum, outer.destination, outer_destination);
    }
    PacketDecision::Nat44Icmpv4(Nat44Icmpv4RewriteDecision {
        egress,
        source_mac,
        destination_mac,
        outer_ttl_offset: outer.header_offset + 8,
        outer_checksum_offset: outer.header_offset + 10,
        outer_source_offset: outer.header_offset + 12,
        inner_checksum_offset: quote.inner_checksum_offset,
        inner_source_offset: quote.inner_source_offset,
        inner_port_offset: quote.inner_port_offset,
        transport_checksum_offset: quote.transport_checksum_offset,
        icmp_checksum_offset: quote.icmp_checksum_offset,
        outer_source: outer_source.octets(),
        outer_destination: outer_destination.octets(),
        inner_source: quoted_source.octets(),
        inner_destination: quoted_destination.octets(),
        inner_source_port: if icmp_query {
            new_identifier
        } else {
            quoted_source_port
        },
        inner_destination_port: quoted_destination_port,
        inner_identifier_only: icmp_query,
        outer_checksum,
        inner_checksum,
        transport_checksum,
        icmp_checksum,
        disposition,
    })
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
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<(), DropReason> {
    match validated.protocol {
        FirewallProtocol::Icmp => {
            let Some(config) = nat44_icmp_config else {
                return Ok(());
            };
            if ingress != config.inside() && ipv4.destination != config.public_address() {
                return Ok(());
            }
            observe_nat44_icmp_security_time(snapshot, config, nat44_icmp, ingress, now, trace)?;
        }
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
                FirewallPlanError::InvalidInitialIcmp(rule_id) => FirewallDisposition {
                    verdict: FirewallVerdict::Drop,
                    class: FirewallConnectionClass::New,
                    source: FirewallPolicySource::Rule(rule_id),
                    matched_action: Some(FirewallAction::AllowStateful),
                    failure: Some(FirewallFailure::InvalidInitialIcmp),
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
                        | FirewallPlanError::InvalidInitialIcmp(_)
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
                FirewallPlanError::InvalidInitialIcmp(_) => FirewallIcmpReplyWithoutRequest,
                FirewallPlanError::StateFull(_) => FirewallStateTableFull,
                FirewallPlanError::ClockRegression => FirewallClockRegression,
            })
        }
    }
}

/// Read-only check whether a route-missing packet would be silently dropped by
/// an egress-dependent NAT gate for *some* egress if it had a route.
///
/// A route hit runs these gates before the firewall plan: the
/// external-to-internal bypass reject (any NAT config whose outside is the
/// ingress), the combined realm-mismatch crossing reject, and the inside to
/// outside NAT runtime/authority requirement. Answering such a route miss
/// with ICMP while the route hit stays silent would let the sender learn which
/// destinations are routed toward the guarded realm, so the route miss stays
/// silent instead. Nothing (counters, traces, state) is mutated.
#[allow(clippy::too_many_arguments)]
fn route_miss_may_hit_nat_reject(
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    protocol: u8,
    combined_realm_mismatch: bool,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_udp: &Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_tcp: &Option<&mut Nat44TcpRuntime<'_>>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
    nat44_icmp: &Option<&mut Nat44IcmpRuntime<'_>>,
) -> bool {
    let udp_outside = nat44_udp_config.is_some_and(|config| ingress == config.outside());
    let tcp_outside = nat44_tcp_config.is_some_and(|config| ingress == config.outside());
    if udp_outside || tcp_outside {
        return true;
    }
    let udp_inside = nat44_udp_config.is_some_and(|config| ingress == config.inside());
    let tcp_inside = nat44_tcp_config.is_some_and(|config| ingress == config.inside());
    let icmp_nat = nat44_icmp_config.is_some() && protocol == 1;
    if combined_realm_mismatch
        && (matches!(protocol, 6 | 17) || icmp_nat)
        && (udp_inside || tcp_inside)
    {
        return true;
    }
    if let Some(config) = nat44_icmp_config.filter(|config| icmp_nat && ingress == config.inside())
    {
        let usable = config.authority_matches(snapshot)
            && nat44_icmp
                .as_deref()
                .is_some_and(|runtime| runtime.config() == *config);
        if !usable {
            return true;
        }
    }
    if let Some(config) = nat44_udp_config.filter(|_| udp_inside && protocol == 17) {
        let usable = config.authority_matches(snapshot)
            && nat44_udp
                .as_deref()
                .is_some_and(|runtime| runtime.config() == *config);
        if !usable {
            return true;
        }
    }
    if let Some(config) = nat44_tcp_config.filter(|_| tcp_inside && protocol == 6) {
        let usable = config.authority_matches(snapshot)
            && nat44_tcp
                .as_deref()
                .is_some_and(|runtime| runtime.config() == *config);
        if !usable {
            return true;
        }
    }
    false
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
    if ipv4.header_len != 20 {
        return Err(FirewallIpv4OptionsUnsupported);
    }
    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(FirewallFragmentUnsupported)?;
    // A whole datagram, or a first fragment the fragment association table
    // admitted (NAT-FRAG: its decision covers the later fragments). Any
    // other fragment never reaches a decision with the table bound, and is
    // refused without it (the `refuse` mode).
    if !matches!(flags_fragment & 0x7fff, 0 | 0x4000) && !first_fragment(ipv4, flags_fragment) {
        return Err(FirewallFragmentUnsupported);
    }
    let protocol = FirewallProtocol::from_ipv4(ipv4.protocol).ok_or(FirewallUnsupportedProtocol)?;
    let packet = match protocol {
        FirewallProtocol::Icmp => {
            let (source_port, destination_port, tcp_flags) =
                validate_firewall_icmp_query(frame, ipv4)?;
            ValidatedFirewallTransport {
                protocol,
                source_port,
                destination_port,
                tcp_flags,
            }
        }
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
            // The checksum of a first fragment covers data still to come:
            // the receiver checks it after reassembly.
            if udp.checksum != 0
                && !ipv4.first_fragment
                && !udp_checksum_valid(frame, ipv4, udp.offset)
            {
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
    if let Err(reason) = validate_nat44_unfragmented(frame, ipv4) {
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
        || snapshot.is_local_ipv4(ipv4.source)
        || ipv4.source == config.public_address()
    {
        return nat44_udp_drop(ingress, Nat44UdpSourceForbidden, trace);
    }
    if snapshot
        .route_lookup(ipv4.source)
        .is_none_or(|reverse| reverse.egress() != config.inside())
    {
        return nat44_udp_drop(ingress, Nat44UdpReverseAuthorityMismatch, trace);
    }
    let planned = if read_only_plan {
        runtime.plan_outbound_read_only(
            ipv4.source,
            udp.source_port,
            ipv4.destination,
            udp.destination_port,
            now.0,
        )
    } else {
        runtime.plan_outbound(
            ipv4.source,
            udp.source_port,
            ipv4.destination,
            udp.destination_port,
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
    if let Err(reason) = validate_nat44_unfragmented(frame, ipv4) {
        return nat44_udp_drop(ingress, reason, trace);
    }
    let udp = match validate_nat44_udp(frame, ipv4) {
        Ok(udp) => udp,
        Err(reason) => return nat44_udp_drop(ingress, reason, trace),
    };
    if !icmp_error_source_is_host(snapshot, ipv4.source) || snapshot.is_local_ipv4(ipv4.source) {
        return nat44_udp_drop(ingress, Nat44UdpSourceForbidden, trace);
    }
    let planned = if firewall_config.is_some() {
        runtime.plan_inbound_read_only(udp.destination_port, ipv4.source, udp.source_port, now.0)
    } else {
        runtime.plan_inbound(udp.destination_port, ipv4.source, udp.source_port, now.0)
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
    let Some(reverse_route) = snapshot.route_lookup(internal_address) else {
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
        return nat44_udp_drop(ingress, Ipv4TtlExpired, trace);
    }
    let target = reverse_route.next_hop().unwrap_or(internal_address);
    let interface = snapshot
        .interface(reverse_route.egress())
        .ok_or(InterfaceMiss)?;
    let destination_mac = if let Some(neighbor) =
        snapshot.static_neighbor(reverse_route.egress(), target)
    {
        neighbor.mac
    } else if let Some((resolution_runtime, resolution_now)) = resolution.as_mut() {
        match resolution_runtime.lookup_dynamic(reverse_route.egress(), target, *resolution_now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                return nat44_udp_drop(ingress, NeighborUnresolved, trace);
            }
            DynamicLookup::Miss => {
                if let Some(binding) = snapshot.local_binding_on(reverse_route.egress()) {
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
    if let Err(reason) = validate_nat44_tcp_unfragmented(frame, ipv4) {
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
        || snapshot.is_local_ipv4(ipv4.source)
        || ipv4.source == config.public_address()
    {
        return nat44_tcp_drop(ingress, Nat44TcpSourceForbidden, trace);
    }
    if snapshot
        .route_lookup(ipv4.source)
        .is_none_or(|reverse| reverse.egress() != config.inside())
    {
        return nat44_tcp_drop(ingress, Nat44TcpReverseAuthorityMismatch, trace);
    }
    let segment = crate::nat44_tcp_state::Nat44TcpSegment::from_flags(tcp.flags);
    let planned = if read_only_plan {
        runtime.plan_outbound_read_only(
            ipv4.source,
            tcp.source_port,
            ipv4.destination,
            tcp.destination_port,
            segment,
            now.0,
        )
    } else {
        runtime.plan_outbound(
            ipv4.source,
            tcp.source_port,
            ipv4.destination,
            tcp.destination_port,
            segment,
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
    if let Err(reason) = validate_nat44_tcp_unfragmented(frame, ipv4) {
        return nat44_tcp_drop(ingress, reason, trace);
    }
    let tcp = match validate_nat44_tcp(frame, ipv4) {
        Ok(tcp) => tcp,
        Err(reason) => return nat44_tcp_drop(ingress, reason, trace),
    };
    if tcp.source_port == 0 {
        return nat44_tcp_drop(ingress, Nat44TcpSourcePortZero, trace);
    }
    if !icmp_error_source_is_host(snapshot, ipv4.source) || snapshot.is_local_ipv4(ipv4.source) {
        return nat44_tcp_drop(ingress, Nat44TcpSourceForbidden, trace);
    }
    // Same initial-SYN predicate as outbound: SYN=1 with ACK/RST/FIN=0.
    // Only such a packet may initiate a session through the NAT filter; a
    // bound firewall still plans the translated packet below.
    let segment = crate::nat44_tcp_state::Nat44TcpSegment::from_flags(tcp.flags);
    let planned = if firewall_config.is_some() {
        runtime.plan_inbound_read_only(
            tcp.destination_port,
            ipv4.source,
            tcp.source_port,
            segment,
            now.0,
        )
    } else {
        runtime.plan_inbound(
            tcp.destination_port,
            ipv4.source,
            tcp.source_port,
            segment,
            now.0,
        )
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
            // RFC 5382 REQ-4: the unsolicited SYN is dropped silently now;
            // a copy may be held for a delayed ICMP Port Unreachable. Only a
            // worker with a clock (a resolution runtime) can time a hold.
            if segment.is_initial_syn()
                && resolution.is_some()
                && matches!(
                    error,
                    Nat44TcpPlanError::MappingMiss | Nat44TcpPlanError::SessionMiss
                )
            {
                hold_unsolicited_syn(
                    frame,
                    snapshot,
                    ipv4,
                    tcp.destination_port,
                    tcp.source_port,
                    config,
                    runtime,
                    firewall_config,
                    firewall.as_deref_mut(),
                    now,
                    trace,
                );
            }
            return Err(reason);
        }
    };
    let internal_address = plan.internal_address();
    let Some(reverse_route) = snapshot.route_lookup(internal_address) else {
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
        return nat44_tcp_drop(ingress, Ipv4TtlExpired, trace);
    }
    let target = reverse_route.next_hop().unwrap_or(internal_address);
    let interface = snapshot
        .interface(reverse_route.egress())
        .ok_or(InterfaceMiss)?;
    let destination_mac = if let Some(neighbor) =
        snapshot.static_neighbor(reverse_route.egress(), target)
    {
        neighbor.mac
    } else if let Some((resolution_runtime, resolution_now)) = resolution.as_mut() {
        match resolution_runtime.lookup_dynamic(reverse_route.egress(), target, *resolution_now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                return nat44_tcp_drop(ingress, NeighborUnresolved, trace);
            }
            DynamicLookup::Miss => {
                if let Some(binding) = snapshot.local_binding_on(reverse_route.egress()) {
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

/// NAT44 translates whole datagrams (MTU2, NAT44-008: MF clear and offset
/// 0; DF and the reserved flag are ignored and preserved; a DF-clear
/// datagram gets a new ID after translation,
/// [`rewrite_translated_non_atomic_id`]) and first fragments the fragment
/// association table admitted (NAT-FRAG, RFC 4787 REQ-14), whose later
/// fragments follow their translation. Any other fragment is refused as
/// [`DropReason::Nat44TcpNonAtomicIpv4Unsupported`].
fn validate_nat44_tcp_unfragmented(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Result<(), DropReason> {
    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(Ipv4HeaderLengthExceedsPacket)?;
    if flags_fragment & 0x3fff != 0 && !first_fragment(ipv4, flags_fragment) {
        return Err(Nat44TcpNonAtomicIpv4Unsupported);
    }
    Ok(())
}

/// Whether `ipv4` is a first fragment (MF set, offset 0, reserved flag
/// clear; DF may be set) that the fragment association table admitted
/// (NAT-FRAG). The NAT and the firewall decide on it like a whole datagram,
/// checking its transport header but not the transport checksum or the UDP
/// length, which cover the whole datagram.
fn first_fragment(ipv4: packet::ValidatedIpv4, flags_fragment: u16) -> bool {
    ipv4.first_fragment && flags_fragment & 0xbfff == 0x2000
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
    // A first fragment holds the whole header (checked above, RFC 1858's
    // tiny fragment) but not the whole segment its checksum covers.
    if !ipv4.first_fragment && !tcp_checksum_valid(ipv4.source, ipv4.destination, segment) {
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
        hairpin_destination: None,
    }))
}

#[derive(Clone, Copy)]
struct ValidatedNat44Udp {
    offset: usize,
    source_port: u16,
    destination_port: u16,
    checksum: u16,
}

/// The UDP form of [`validate_nat44_tcp_unfragmented`]: a fragment is
/// [`DropReason::Nat44UdpNonAtomicIpv4Unsupported`].
fn validate_nat44_unfragmented(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Result<(), DropReason> {
    let flags_fragment =
        packet::read_u16(frame, ipv4.header_offset + 6).ok_or(Ipv4HeaderLengthExceedsPacket)?;
    if flags_fragment & 0x3fff != 0 && !first_fragment(ipv4, flags_fragment) {
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
    if ipv4.first_fragment {
        // The UDP length covers the whole datagram, of which a first
        // fragment carries only a part: it must be longer than this part.
        if length <= payload_len {
            return Err(Nat44UdpLengthTooSmall);
        }
    } else if length > payload_len {
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
        hairpin_destination: None,
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
        Nat44UdpPlanError::HostQuotaExceeded => (
            Nat44UdpHostQuotaExceeded,
            Nat44UdpDisposition::HostQuotaExceeded,
        ),
        Nat44UdpPlanError::HostPeerQuotaExceeded => (
            Nat44UdpHostPeerQuotaExceeded,
            Nat44UdpDisposition::HostPeerQuotaExceeded,
        ),
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
        Nat44TcpPlanError::InboundRemoteQuotaExceeded => (
            Nat44TcpInboundRemoteQuotaExceeded,
            Nat44TcpDisposition::InboundRemoteQuotaExceeded,
        ),
        Nat44TcpPlanError::HostQuotaExceeded => (
            Nat44TcpHostQuotaExceeded,
            Nat44TcpDisposition::HostQuotaExceeded,
        ),
        Nat44TcpPlanError::HostSessionQuotaExceeded => (
            Nat44TcpHostSessionQuotaExceeded,
            Nat44TcpDisposition::HostSessionQuotaExceeded,
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
    next_hop_mtu: u16,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Icmpv4ErrorDisposition {
    if !runtime.policy().generates(kind) {
        return runtime.record_suppression(Icmpv4ErrorDisposition::GenerationDisabled { kind });
    }
    if !runtime.observe_decision(now) {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ClockRegression);
    }
    if !icmp_error_source_is_host(snapshot, ipv4.source) {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::SourceNotUnicast);
    }
    if snapshot.is_local_ipv4(ipv4.source) {
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

    let quote_end = ipv4.header_offset + ipv4.total_len;
    schedule_reverse_icmpv4_error(
        snapshot,
        ipv4.source,
        frame[ipv4.header_offset + 1],
        &frame[ipv4.header_offset..quote_end],
        kind,
        next_hop_mtu,
        resolution,
        runtime,
        now,
        trace,
    )
}

/// Routes an ICMPv4 error of `kind` about `original_ipv4` back to its
/// `original_source` and queues it: the reverse route, the egress binding,
/// the reverse neighbor (static, then fresh dynamic; a miss queues only an
/// ARP Request), then the generated-ICMPv4 limiter. The caller has already
/// applied the RFC 1812 §4.3.2.7 suppression rules. `next_hop_mtu` is the
/// Next-Hop MTU of a Fragmentation Needed error (ignored for other kinds).
/// The quote is cut so the error fits the MTU of the reverse egress.
#[allow(clippy::too_many_arguments)]
pub(crate) fn schedule_reverse_icmpv4_error<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    original_source: crate::Ipv4Address,
    original_tos: u8,
    original_ipv4: &[u8],
    kind: Icmpv4ErrorKind,
    next_hop_mtu: u16,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Icmpv4ErrorDisposition {
    let Some(reverse_route) = snapshot.route_lookup(original_source) else {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ReverseRouteMiss);
    };
    let reverse_egress = reverse_route.egress();
    let Some(interface) = snapshot.interface(reverse_egress) else {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ReverseInterfaceMiss {
            egress: reverse_egress,
        });
    };
    let Some(binding) = snapshot.local_binding_on(reverse_egress) else {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ReverseBindingMiss {
            egress: reverse_egress,
        });
    };
    let target = reverse_route.next_hop().unwrap_or(original_source);
    if reverse_target_forbidden(snapshot, reverse_egress, target, binding.address) {
        return runtime.record_suppression(Icmpv4TimeExceededDisposition::ReverseTargetForbidden {
            egress: reverse_egress,
            target,
        });
    }

    let static_neighbor = snapshot.static_neighbor(reverse_egress, target);
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
                    snapshot.is_local_ipv4(target)
                        || snapshot.is_connected_boundary(reverse_egress, target),
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

    runtime.schedule(
        Icmpv4ErrorAction::new_with_kind(
            kind,
            reverse_egress,
            interface.mac,
            destination_mac,
            binding.address,
            original_source,
            original_tos,
            snapshot.ipv4_origin.default_ttl(),
            original_ipv4,
        )
        .with_next_hop_mtu(next_hop_mtu)
        .fit_egress_mtu(interface.mtu),
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
        && !snapshot.route_lookup(source).is_some_and(|selected| {
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
    if !icmp_error_source_is_host(snapshot, ipv4.source) || snapshot.is_local_ipv4(ipv4.source) {
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
        || snapshot.is_local_ipv4(target)
        || snapshot.is_connected_boundary(egress, target)
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

    let interface = snapshot.interface(ingress).ok_or(InterfaceMiss)?;
    if !sender_is_host(snapshot, ingress, ipv4.source)
        || snapshot.is_local_ipv4_on(ingress, ipv4.source)
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
    if !snapshot.ipv4_origin.echo_reply() {
        // RFC 1812 §4.3.3.6 operator option: silently ignore Echo Requests.
        return Err(Icmpv4EchoDisabled);
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
    let target_local = snapshot.is_local_ipv4_on(ingress, arp.target_protocol);
    let sender_local = snapshot.is_local_ipv4_on(ingress, arp.sender_protocol);
    let sender_host = sender_is_host(snapshot, ingress, arp.sender_protocol);
    let static_key = snapshot
        .static_neighbor(ingress, arp.sender_protocol)
        .is_some();
    // ARP-031 (opt-in hardening; RFC 826 places no condition on the
    // sender, so the default learns and answers it): a sender the router
    // could never resolve on this interface (outside every direct route out
    // of it and not one of its gateways) is not a neighbor on this link.
    // When enabled, it is dropped before any state, clock, or reply. A
    // configured static neighbor, our own address (a conflict), and the
    // non-host senders (`sender_is_host` is false for the RFC 5227 probe
    // sender 0.0.0.0 and for connected network or broadcast addresses)
    // keep their dispositions either way.
    if snapshot.arp.require_on_link_sender()
        && !static_key
        && !sender_local
        && sender_host
        && !snapshot.sender_on_link(ingress, arp.sender_protocol)
    {
        return Err(ArpSenderNotOnLink);
    }
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
    let interface = snapshot.interface(ingress).ok_or(InterfaceMiss)?;
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
        && !snapshot.is_connected_boundary(ingress, sender)
}

/// RFC 6864 §5.3.1 (NAT44-126): an address-sharing device generates the
/// IPv4 ID of the non-atomic datagrams it translates instead of copying it,
/// so the IDs of inside hosts sharing the public address stay unique per
/// (source, destination, protocol) if a datagram is fragmented downstream.
///
/// Runs on the translated frame. A datagram with DF set (atomic, RFC 6864
/// §4.1: its ID has no meaning) keeps its ID, which costs one header read
/// on the fast path; so does any non-NAT decision. A whole DF-clear
/// datagram (the NAT translates no fragment) gets the next ID of its
/// translated tuple from the generator of its protocol: UDP from the UDP
/// runtime, TCP from the TCP runtime, and ICMP (queries and translated
/// errors share protocol 1, so one sequence) from the ICMP query runtime,
/// else the UDP, else the TCP runtime. Each generator counts tuples whose
/// source is the public address (outbound, hairpin) apart from the others
/// (inbound), so outside traffic cannot advance an outbound sequence. The
/// header checksum is updated incrementally (RFC 1624).
///
/// The ID is taken when the core commits the frame for TX, before the
/// backend accepts it: a backend TX rejection does not return it. A plan,
/// MTU, or firewall drop happens earlier and takes none.
fn rewrite_translated_non_atomic_id(
    frame: &mut [u8],
    decision: PacketDecision,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
) -> Result<(), DropReason> {
    if !matches!(
        decision,
        PacketDecision::Nat44Udp(_)
            | PacketDecision::Nat44Tcp(_)
            | PacketDecision::Nat44Icmp(_)
            | PacketDecision::Nat44Icmpv4(_)
    ) {
        return Ok(());
    }
    let header = packet::ETHERNET_HEADER_LEN;
    let flags_fragment = packet::read_u16(frame, header + 6).ok_or(Ipv4HeaderTruncated)?;
    // Atomic (RFC 6864 §4.1: DF set, MF clear, offset 0): the ID is kept.
    // Every other datagram is non-atomic: a whole DF-clear datagram, or a
    // first fragment the association table admitted (NAT-FRAG), whose
    // generated ID the table gives every later fragment of the datagram.
    if flags_fragment & 0x7fff == 0x4000 {
        return Ok(());
    }
    // The NAT translates only IHL=5 datagrams (options are refused before
    // any NAT decision, `Ipv4OptionsUnsupported`), so the IPv4 header is at
    // the fixed offsets after the Ethernet header: ID at 4, flags at 6,
    // protocol at 9, checksum at 10, addresses at 12..20.
    let old_id = packet::read_u16(frame, header + 4).ok_or(Ipv4HeaderTruncated)?;
    let checksum = packet::read_u16(frame, header + 10).ok_or(Ipv4HeaderTruncated)?;
    let addresses: [u8; 8] = frame
        .get(header + 12..header + 20)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Ipv4HeaderTruncated)?;
    let protocol = frame[header + 9];
    let source = [addresses[0], addresses[1], addresses[2], addresses[3]];
    let destination = [addresses[4], addresses[5], addresses[6], addresses[7]];
    let id = match decision {
        PacketDecision::Nat44Udp(_) => nat44_udp
            .as_deref_mut()
            .ok_or(Nat44UdpRuntimeUnavailable)?
            .next_ipv4_id(source, destination, protocol),
        PacketDecision::Nat44Tcp(_) => nat44_tcp
            .as_deref_mut()
            .ok_or(Nat44TcpRuntimeUnavailable)?
            .next_ipv4_id(source, destination, protocol),
        _ => {
            if let Some(runtime) = nat44_icmp.as_deref_mut() {
                runtime.next_ipv4_id(source, destination, protocol)
            } else if let Some(runtime) = nat44_udp.as_deref_mut() {
                runtime.next_ipv4_id(source, destination, protocol)
            } else {
                nat44_tcp
                    .as_deref_mut()
                    .ok_or(Nat44IcmpRuntimeUnavailable)?
                    .next_ipv4_id(source, destination, protocol)
            }
        }
    };
    frame[header + 4..header + 6].copy_from_slice(&id.to_be_bytes());
    frame[header + 10..header + 12]
        .copy_from_slice(&rfc1624_update(checksum, old_id, id).to_be_bytes());
    Ok(())
}

fn apply_decision(frame: &mut [u8], decision: PacketDecision) -> Result<(), DropReason> {
    match decision {
        PacketDecision::Ipv4(ipv4) => apply_ipv4_rewrite(frame, ipv4),
        PacketDecision::Nat44Udp(nat) => apply_nat44_udp_rewrite(frame, nat),
        PacketDecision::Nat44Tcp(nat) => apply_nat44_tcp_rewrite(frame, nat),
        PacketDecision::Nat44Icmpv4(nat) => apply_nat44_icmpv4_rewrite(frame, nat),
        PacketDecision::Nat44Icmp(nat) => apply_nat44_icmp_rewrite(frame, nat),
        PacketDecision::ArpReply(arp) => apply_arp_reply(frame, arp),
        PacketDecision::Icmpv4EchoReply(icmp) => apply_icmpv4_echo_reply(frame, icmp),
        PacketDecision::FragmentFollow(follow) => follow.template.apply(frame),
        PacketDecision::ConsumeArp(_)
        | PacketDecision::ConsumeIpv4Local
        | PacketDecision::ConsumeFragmentHeld => {
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
        (decision.outer_source_offset, 8),
        (decision.inner_checksum_offset, 2),
        (decision.inner_source_offset, 8),
        (decision.inner_port_offset, 4),
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
    let outer = decision.outer_source_offset;
    frame[outer..outer + 4].copy_from_slice(&decision.outer_source);
    frame[outer + 4..outer + 8].copy_from_slice(&decision.outer_destination);
    frame[decision.inner_checksum_offset..decision.inner_checksum_offset + 2]
        .copy_from_slice(&decision.inner_checksum.to_be_bytes());
    let inner = decision.inner_source_offset;
    frame[inner..inner + 4].copy_from_slice(&decision.inner_source);
    frame[inner + 4..inner + 8].copy_from_slice(&decision.inner_destination);
    let ports = decision.inner_port_offset;
    frame[ports..ports + 2].copy_from_slice(&decision.inner_source_port.to_be_bytes());
    if !decision.inner_identifier_only {
        frame[ports + 2..ports + 4].copy_from_slice(&decision.inner_destination_port.to_be_bytes());
    }
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
        || decision
            .hairpin_destination
            .is_some_and(|rewrite| !rewrite.fits(frame))
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
    if let Some(rewrite) = decision.hairpin_destination {
        rewrite.apply(frame);
    }
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
        || decision
            .hairpin_destination
            .is_some_and(|rewrite| !rewrite.fits(frame))
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
    if let Some(rewrite) = decision.hairpin_destination {
        rewrite.apply(frame);
    }
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
    use super::{
        decide_ipv4, forward_batch, forward_batch_with_nat44_udp_and_tcp_and_firewall,
        next_publication_nonce_from, ArpPolicy, BatchReport, DropReason, Ipv4OriginPolicy,
        ValidatedForwardingOwner, FULL_FORWARDING_VALIDATIONS, VALIDATED_OWNER_AUTHORITY_BIT,
    };
    use crate::{
        internet_checksum, ipv4_header_checksum, BatchCompletion, DirectoryBucket, DirectoryNode,
        FirewallAction, FirewallConfig, FirewallHashKey, FirewallInterface, FirewallIpv4Prefix,
        FirewallPolicy, FirewallPortRange, FirewallProtocol, FirewallRule, FirewallRuleId,
        FirewallRuntime, FirewallStateSlot, ForwardingSnapshot, IfId, Interface, Ipv4Address,
        LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig,
        Nat44TcpHashKey, Nat44TcpIndexStorage, Nat44TcpMappingSlot, Nat44TcpPolicy,
        Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpMappingSlot,
        Nat44UdpPeerSlot, Nat44UdpPolicy, NoTrace, PacketBatch, PacketLease, PacketSlot,
        PortOwnerSlot, ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime,
        ResolutionStateSlot, Route, SlotCompletion, TraceEvent, TraceSink,
    };
    use std::{
        cell::Cell,
        panic::{catch_unwind, AssertUnwindSafe},
    };

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const INTERNAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
    const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
    const ROUTER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);

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

    /// The ARP policy is RFC 826 by default; opting into ARP-031 changes
    /// the authority of a borrowed snapshot (mixed only when non-default,
    /// so existing authorities are unchanged) and keeps the nonce of an
    /// owner snapshot.
    #[test]
    fn arp_policy_defaults_to_rfc826_and_is_part_of_borrowed_authority() {
        let required = ArpPolicy::RFC826.with_require_on_link_sender(true);
        assert_eq!(ArpPolicy::default(), ArpPolicy::RFC826);
        assert!(!ArpPolicy::RFC826.require_on_link_sender());
        assert!(required.require_on_link_sender());
        let borrowed = ForwardingSnapshot::new(&[], &[], &[], &[]).unwrap();
        assert_eq!(borrowed.arp_policy(), ArpPolicy::RFC826);
        let hardened = borrowed.with_arp_policy(required);
        assert_eq!(hardened.arp_policy(), required);
        assert_ne!(hardened.authority(), borrowed.authority());
        assert_eq!(hardened.publication_nonce(), 0);
        assert_eq!(
            hardened.with_arp_policy(ArpPolicy::RFC826).authority(),
            borrowed.authority()
        );
        let owner = empty_validated_owner();
        assert_eq!(owner.snapshot().arp_policy(), ArpPolicy::RFC826);
        let nonce = owner.snapshot().publication_nonce();
        let owner = owner.with_arp_policy(required);
        assert_eq!(owner.snapshot().arp_policy(), required);
        assert_eq!(owner.snapshot().publication_nonce(), nonce);
        assert_eq!(
            owner
                .snapshot()
                .with_arp_policy(ArpPolicy::RFC826)
                .authority(),
            nonce
        );
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
             local_ipv4_len: 0, ipv4_origin: Ipv4OriginPolicy { default_ttl: 64, echo_reply: true }, \
             arp: ArpPolicy { require_on_link_sender: false }, .. }"
        );
        assert_eq!(
            format!("{first:?}"),
            "ValidatedForwardingOwner { routes_len: 0, interfaces_len: 0, neighbors_len: 0, \
             local_ipv4_len: 0, ipv4_origin: Ipv4OriginPolicy { default_ttl: 64, echo_reply: true }, \
             arp: ArpPolicy { require_on_link_sender: false }, .. }"
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
            mtu: 1500,
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

    /// RFC 5382 REQ-4 hold timing needs a clock: a worker without a
    /// resolution runtime (its `now` would be 0) never holds an unsolicited
    /// SYN; with one it does.
    #[test]
    fn unsolicited_syns_are_held_only_with_a_worker_clock() {
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
                mtu: 1500,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: 1500,
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
        // REMOTE:443 -> PUBLIC:40000, an initial SYN arriving on WAN.
        let mut frame = tcp_syn_frame();
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 20]);
        frame[26..30].copy_from_slice(&REMOTE.octets());
        frame[30..34].copy_from_slice(&PUBLIC.octets());
        frame[34..36].copy_from_slice(&443_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&40_000_u16.to_be_bytes());
        frame[24..26].copy_from_slice(&[0, 0]);
        frame[50..52].copy_from_slice(&[0, 0]);
        let mut pseudo = Vec::with_capacity(32);
        pseudo.extend_from_slice(&REMOTE.octets());
        pseudo.extend_from_slice(&PUBLIC.octets());
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&20_u16.to_be_bytes());
        pseudo.extend_from_slice(&frame[34..54]);
        let tcp_checksum = internet_checksum(&pseudo);
        frame[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());
        let ipv4_checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&ipv4_checksum.to_be_bytes());

        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut mapping_buckets = [DirectoryBucket::default(); 1];
        let mut mapping_nodes = [DirectoryNode::default(); 1];
        let mut session_buckets = [DirectoryBucket::default(); 1];
        let mut session_nodes = [DirectoryNode::default(); 1];
        let mut session_address_buckets = session_buckets;
        let mut session_address_nodes = session_nodes;
        let mut owners = [PortOwnerSlot::default(); 1];
        let mut owner_bits = vec![0_u64; crate::port_free_bitmap_words(1)];
        let mut holds = [crate::Nat44TcpSynHoldSlot::EMPTY; 2];
        let mut tcp = Nat44TcpRuntime::new(
            tcp_config,
            &mut mappings,
            &mut sessions,
            Nat44TcpIndexStorage::new(
                &mut mapping_buckets,
                &mut mapping_nodes,
                &mut session_buckets,
                &mut session_nodes,
                &mut session_address_buckets,
                &mut session_address_nodes,
                &mut owners,
                &mut owner_bits,
                crate::nat44_host_quota::leaked_host_storage(1),
            ),
            Nat44TcpHashKey::new(0xc001_d00d_f00d_beef, 0x1234_5678_9abc_def0).unwrap(),
        )
        .unwrap()
        .with_unsolicited_syn_holds(&mut holds)
        .unwrap();
        let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
        let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution_runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut resolution_states,
            &mut resolution_actions,
        );
        for with_clock in [false, true] {
            let mut resolution =
                with_clock.then_some((&mut resolution_runtime, MonotonicMillis(5)));
            let decision = crate::forwarding::decide(
                &frame,
                &snapshot,
                WAN,
                false,
                &mut resolution,
                &mut None,
                None,
                &mut None,
                Some(&tcp_config),
                &mut Some(&mut tcp),
                None,
                &mut None,
                None,
                &mut None,
                &mut None,
                &mut None,
                &mut NoTrace,
            );
            assert_eq!(decision.err(), Some(DropReason::Nat44TcpMappingMiss));
            assert_eq!(tcp.unsolicited_syn_holds(), usize::from(with_clock));
        }
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
                mtu: 1500,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: 1500,
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
        let mut session_address_buckets = session_buckets;
        let mut session_address_nodes = session_nodes;
        let mut owners = [PortOwnerSlot::default(); 1];
        let mut owner_bits = vec![0_u64; crate::port_free_bitmap_words(1)];
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
                    &mut session_address_buckets,
                    &mut session_address_nodes,
                    &mut owners,
                    &mut owner_bits,
                    crate::nat44_host_quota::leaked_host_storage(1),
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
                mtu: 1500,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: 1500,
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
        let plan = nat.plan_outbound(INTERNAL, 12_345, REMOTE, 53, 0).unwrap();
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
            false,
            &mut resolution,
            &mut generated_errors,
            Some(&config),
            &mut udp,
            None,
            &mut tcp,
            None,
            &mut None,
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
            (37, "NAT44_UDP_HAIRPIN_DISABLED"),
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
            (57, "NAT44_TCP_HAIRPIN_DISABLED"),
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
            (146, "ICMPV4_ECHO_DISABLED"),
            (147, "NAT44_UDP_HAIRPIN_FILTERED"),
            (148, "NAT44_TCP_HAIRPIN_FILTERED"),
            (149, "NAT44_ICMPV4_QUOTED_REMOTE_LOCAL"),
            (150, "NAT44_TCP_INBOUND_REMOTE_QUOTA_EXCEEDED"),
            (151, "NAT44_ICMPV4_OUTER_DESTINATION_MISMATCH"),
            (152, "NAT44_ICMPV4_INSIDE_SOURCE_MISMATCH"),
            (153, "NAT44_ICMPV4_END_HOST_SOURCE_MISMATCH"),
            (154, "ARP_SENDER_NOT_ON_LINK"),
            (155, "NAT44_UDP_HOST_QUOTA_EXCEEDED"),
            (156, "NAT44_TCP_HOST_QUOTA_EXCEEDED"),
            (157, "NAT44_ICMPV4_TRANSLATED_RATE_LIMITED"),
            (158, "NAT44_ICMPV4_FRAG_NEEDED_MTU_INVALID"),
            (159, "NAT44_ICMP_RUNTIME_UNAVAILABLE"),
            (160, "NAT44_ICMP_CONFIG_MISMATCH"),
            (161, "NAT44_ICMP_TYPE_UNSUPPORTED"),
            (162, "NAT44_ICMP_FRAGMENT_UNSUPPORTED"),
            (163, "NAT44_ICMP_HEADER_TRUNCATED"),
            (164, "NAT44_ICMP_CODE_INVALID"),
            (165, "NAT44_ICMP_CHECKSUM_INVALID"),
            (166, "NAT44_ICMP_SOURCE_FORBIDDEN"),
            (167, "NAT44_ICMP_REVERSE_AUTHORITY_MISMATCH"),
            (168, "NAT44_ICMP_MAPPING_MISS"),
            (169, "NAT44_ICMP_FILTER_DENIED"),
            (170, "NAT44_ICMP_MAPPING_TABLE_FULL"),
            (171, "NAT44_ICMP_PEER_TABLE_FULL"),
            (172, "NAT44_ICMP_IDENTIFIER_EXHAUSTED"),
            (173, "NAT44_ICMP_HOST_QUOTA_EXCEEDED"),
            (174, "NAT44_ICMP_CLOCK_REGRESSION"),
            (175, "NAT44_ICMP_WRONG_INGRESS"),
            (176, "NAT44_ICMP_WRONG_EGRESS"),
            (177, "FIREWALL_ICMP_QUERY_INVALID"),
            (178, "FIREWALL_ICMP_REPLY_WITHOUT_REQUEST"),
            (179, "NAT44_UDP_HOST_PEER_QUOTA_EXCEEDED"),
            (180, "NAT44_TCP_HOST_SESSION_QUOTA_EXCEEDED"),
            (181, "NAT44_ICMP_HOST_PEER_QUOTA_EXCEEDED"),
            (182, "IPV4_FRAGMENTATION_NEEDED"),
            (183, "IPV4_FRAGMENTATION_REQUIRED"),
            (184, "ICMPV4_ECHO_REPLY_EXCEEDS_MTU"),
            (185, "IPV4_FRAME_EXCEEDS_MTU"),
            (186, "IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS"),
            (187, "IPV4_FRAGMENTATION_QUEUE_FULL"),
            (188, "IPV4_FRAGMENTATION_DATAGRAM_TOO_LARGE"),
            (189, "IPV4_FRAGMENTATION_OFFSET_OVERFLOW"),
            (190, "IPV4_FRAGMENT_FIRST_DENIED"),
            (191, "IPV4_FRAGMENT_DUPLICATE_FIRST"),
            (192, "IPV4_FRAGMENT_TRANSPORT_HEADER_OVERLAP"),
            (193, "IPV4_FRAGMENT_MALFORMED"),
            (194, "IPV4_FRAGMENT_TABLE_FULL"),
            (195, "IPV4_FRAGMENT_HOST_LIMIT"),
            (196, "IPV4_FRAGMENT_HOLD_FULL"),
            (197, "IPV4_FRAGMENT_HOST_HOLD_LIMIT"),
            (198, "IPV4_FRAGMENT_HOLD_TOO_LARGE"),
        ];
        let actual = DropReason::ALL;
        assert_eq!(actual.len(), expected.len());
        for (reason, &(discriminant, code)) in actual.iter().zip(&expected) {
            assert_eq!(*reason as u16, discriminant);
            assert_eq!(reason.code(), code);
            assert_eq!(DropReason::from_code(discriminant), Some(*reason));
        }
        assert_eq!(DropReason::from_code(0), None);
        assert_eq!(DropReason::from_code(199), None);
    }

    /// `DropReason::ALL` lists every declared variant: a new variant fails
    /// this test until it is appended to `ALL` (and to the code table above).
    #[test]
    fn drop_reason_all_lists_every_declared_variant_in_order() {
        let source = include_str!("forwarding.rs");
        let body = source
            .split_once("pub enum DropReason {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let declared: Vec<String> = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .map(|line| line.split_once(" = ").unwrap().0.to_owned())
            .collect();
        let listed: Vec<String> = DropReason::ALL.iter().map(|r| format!("{r:?}")).collect();
        assert_eq!(declared, listed);
    }
}

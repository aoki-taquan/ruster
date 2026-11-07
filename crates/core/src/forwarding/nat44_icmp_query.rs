//! NAT44 translation of ICMP queries on the packet path (RFC 5508 §3, N5).
//!
//! **Which messages.** Echo Request/Reply (types 8/0, RFC 5508 REQ-10 a.3,
//! MUST) and Timestamp/Timestamp Reply (13/14, REQ-10 b, MAY) are
//! translated. Information Request/Reply (15/16, REQ-10 c, SHOULD NOT) and
//! Address Mask Request/Reply (17/18, REQ-10 b, MAY) are not: both were
//! deprecated by RFC 6918. Any other non-error ICMP message crossing the NAT
//! is dropped (REQ-11 allows dropping non-query/error messages).
//!
//! **Direction.** Only an inside host's request creates or refreshes a
//! mapping (REQ-1: queries initiated from the private realm). A reply from
//! the external realm to the public address is translated back when it
//! names a live mapping and, under address-dependent filtering, comes from a
//! remote address the mapping has queried. A request from either realm to
//! the public address is for the router, which owns that address: the local
//! Echo responder answers it (an inside host pinging the public address is
//! answered by the router, not hairpinned, because a NAPT has no inbound
//! query session to hairpin to; RFC 5508 REQ-7 is a Basic NAT requirement
//! and RFC 7857 §12 ties query hairpinning to external-to-internal mappings
//! that this NAT does not create).
//!
//! **Rewrite.** Outbound: IPv4 source to the public address and the
//! identifier to the public identifier. Inbound: IPv4 destination to the
//! internal address and the identifier back. The ICMP checksum covers the
//! identifier but no pseudo-header, so only the identifier change updates it
//! (RFC 1624); the IPv4 header checksum covers the TTL and the address.
//!
//! **State order.** The ICMP checksum and that the query is unfragmented
//! (DF may be clear, unlike UDP/TCP; NAT44-116) are validated before any NAT
//! state changes, and every commit is prevalidated
//! before the frame is rewritten, exactly as for UDP.

use super::*;

const ECHO_REPLY: u8 = 0;
const ECHO_REQUEST: u8 = 8;
const TIMESTAMP_REQUEST: u8 = 13;
const TIMESTAMP_REPLY: u8 = 14;

/// Whether `icmp_type` is a translated query request (Echo, Timestamp).
pub(super) const fn is_query_request(icmp_type: u8) -> bool {
    matches!(icmp_type, ECHO_REQUEST | TIMESTAMP_REQUEST)
}

/// Whether `icmp_type` is a translated query reply (Echo, Timestamp).
pub(super) const fn is_query_reply(icmp_type: u8) -> bool {
    matches!(icmp_type, ECHO_REPLY | TIMESTAMP_REPLY)
}

/// Firewall pseudo-ports of a translated query (see
/// [`FirewallProtocol::Icmp`]): a request is `(identifier, type)` and its
/// reply `(request type, identifier)`, so the reply is the exact reverse
/// tuple of its request.
pub(super) const fn firewall_ports(icmp_type: u8, identifier: u16) -> Option<(u16, u16)> {
    match icmp_type {
        ECHO_REQUEST | TIMESTAMP_REQUEST => Some((identifier, icmp_type as u16)),
        ECHO_REPLY => Some((ECHO_REQUEST as u16, identifier)),
        TIMESTAMP_REPLY => Some((TIMESTAMP_REQUEST as u16, identifier)),
        _ => None,
    }
}

/// The ICMP type of an IPv4 packet's first payload byte within its Total
/// Length, if any.
pub(super) fn peek_icmp_type(frame: &[u8], ipv4: packet::ValidatedIpv4) -> Option<u8> {
    if ipv4.protocol != 1 || ipv4.total_len <= ipv4.header_len {
        return None;
    }
    frame
        .get(ipv4.header_offset.checked_add(ipv4.header_len)?)
        .copied()
}

#[derive(Clone, Copy)]
pub(super) struct ValidatedIcmpQuery {
    pub(super) offset: usize,
    pub(super) icmp_type: u8,
    pub(super) identifier: u16,
    pub(super) checksum: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IcmpQueryError {
    NotQuery,
    Truncated,
    CodeInvalid,
    ChecksumInvalid,
}

/// Validates a translated ICMP query: an Echo or Timestamp message with
/// its full header (8 bytes; 20 for Timestamp, RFC 792), code 0, and a
/// valid checksum over the whole message within the IPv4 Total Length
/// (link padding excluded).
pub(super) fn validate_icmp_query(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Result<ValidatedIcmpQuery, IcmpQueryError> {
    let offset = ipv4
        .header_offset
        .checked_add(ipv4.header_len)
        .ok_or(IcmpQueryError::Truncated)?;
    let end = ipv4
        .header_offset
        .checked_add(ipv4.total_len)
        .ok_or(IcmpQueryError::Truncated)?;
    let icmp = frame.get(offset..end).ok_or(IcmpQueryError::Truncated)?;
    let &icmp_type = icmp.first().ok_or(IcmpQueryError::Truncated)?;
    if !is_query_request(icmp_type) && !is_query_reply(icmp_type) {
        return Err(IcmpQueryError::NotQuery);
    }
    let minimum = if matches!(icmp_type, TIMESTAMP_REQUEST | TIMESTAMP_REPLY) {
        20
    } else {
        8
    };
    if icmp.len() < minimum {
        return Err(IcmpQueryError::Truncated);
    }
    if icmp[1] != 0 {
        return Err(IcmpQueryError::CodeInvalid);
    }
    // A first fragment admitted by the association table (NAT-FRAG) holds
    // the header but not the whole message the checksum covers.
    if !ipv4.first_fragment && crate::internet_checksum(icmp) != 0 {
        return Err(IcmpQueryError::ChecksumInvalid);
    }
    Ok(ValidatedIcmpQuery {
        offset,
        icmp_type,
        identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
        checksum: u16::from_be_bytes([icmp[2], icmp[3]]),
    })
}

/// Whether a query is a whole datagram (MF clear, offset 0). As for UDP and
/// TCP (NAT44-008), DF may be clear: Linux sends Echo Replies and Windows
/// sends Echo Requests with DF clear (NAT44-116). The reserved flag is
/// ignored and preserved; a DF-clear query gets a generated IPv4 ID after
/// translation (NAT44-126), a DF-set one keeps its ID.
///
/// A first fragment the association table admitted (NAT-FRAG) is translated
/// too: its later fragments follow its translation.
fn unfragmented(frame: &[u8], ipv4: packet::ValidatedIpv4) -> bool {
    packet::read_u16(frame, ipv4.header_offset + 6).is_some_and(|flags| {
        flags & 0x3fff == 0 || (ipv4.first_fragment && flags & 0xbfff == 0x2000)
    })
}

const fn nat_reason(error: IcmpQueryError) -> DropReason {
    match error {
        IcmpQueryError::NotQuery => Nat44IcmpTypeUnsupported,
        IcmpQueryError::Truncated => Nat44IcmpHeaderTruncated,
        IcmpQueryError::CodeInvalid => Nat44IcmpCodeInvalid,
        IcmpQueryError::ChecksumInvalid => Nat44IcmpChecksumInvalid,
    }
}

#[derive(Clone, Copy)]
pub(super) enum Nat44IcmpTransition {
    Outbound(Nat44UdpOutboundPlan),
    Inbound(Nat44UdpInboundPlan),
}

/// In-place rewrite of a translated ICMP query: Ethernet, TTL, one IPv4
/// address, the identifier, and both checksums.
#[derive(Clone, Copy)]
pub(super) struct Nat44IcmpRewriteDecision {
    pub(super) forwarding: Ipv4RewriteDecision,
    address_offset: usize,
    new_address: [u8; 4],
    identifier_offset: usize,
    new_identifier: u16,
    icmp_checksum_offset: usize,
    ipv4_checksum: u16,
    icmp_checksum: u16,
    pub(super) transition: Nat44IcmpTransition,
    pub(super) disposition: Nat44IcmpDisposition,
}

pub(super) fn nat44_icmp_drop<T: TraceSink>(
    ingress: IfId,
    reason: DropReason,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    trace.record(TraceEvent::Nat44Icmp {
        ingress,
        disposition: Nat44IcmpDisposition::Rejected { reason },
    });
    Err(reason)
}

pub(super) fn nat44_icmp_plan_error(
    error: Nat44UdpPlanError,
) -> (DropReason, Nat44IcmpDisposition) {
    match error {
        Nat44UdpPlanError::MappingMiss => (Nat44IcmpMappingMiss, Nat44IcmpDisposition::MappingMiss),
        Nat44UdpPlanError::FilterDenied => {
            (Nat44IcmpFilterDenied, Nat44IcmpDisposition::FilterDenied)
        }
        Nat44UdpPlanError::MappingFull => {
            (Nat44IcmpMappingTableFull, Nat44IcmpDisposition::MappingFull)
        }
        Nat44UdpPlanError::PeerFull => (Nat44IcmpPeerTableFull, Nat44IcmpDisposition::PeerFull),
        Nat44UdpPlanError::PortExhausted => (
            Nat44IcmpIdentifierExhausted,
            Nat44IcmpDisposition::IdentifierExhausted,
        ),
        Nat44UdpPlanError::HostQuotaExceeded => (
            Nat44IcmpHostQuotaExceeded,
            Nat44IcmpDisposition::HostQuotaExceeded,
        ),
        Nat44UdpPlanError::HostPeerQuotaExceeded => (
            Nat44IcmpHostPeerQuotaExceeded,
            Nat44IcmpDisposition::HostPeerQuotaExceeded,
        ),
        Nat44UdpPlanError::ClockRegression => (
            Nat44IcmpClockRegression,
            Nat44IcmpDisposition::ClockRegression,
        ),
        Nat44UdpPlanError::IndexCorrupt
        | Nat44UdpPlanError::GenerationExhausted
        | Nat44UdpPlanError::StateRevisionExhausted => (
            Nat44IcmpConfigMismatch,
            Nat44IcmpDisposition::ConfigMismatch,
        ),
    }
}

/// Reason for a read-only ICMP query lookup made for a translated error.
pub(super) fn nat44_icmp_error_lookup_reason(error: Nat44UdpPlanError) -> DropReason {
    match error {
        Nat44UdpPlanError::MappingMiss => Nat44IcmpMappingMiss,
        Nat44UdpPlanError::FilterDenied => Nat44IcmpFilterDenied,
        Nat44UdpPlanError::ClockRegression => Nat44IcmpClockRegression,
        Nat44UdpPlanError::MappingFull
        | Nat44UdpPlanError::PeerFull
        | Nat44UdpPlanError::PortExhausted
        | Nat44UdpPlanError::HostQuotaExceeded
        | Nat44UdpPlanError::HostPeerQuotaExceeded
        | Nat44UdpPlanError::GenerationExhausted
        | Nat44UdpPlanError::StateRevisionExhausted => {
            unreachable!("read-only ICMP lookup cannot exhaust state")
        }
        Nat44UdpPlanError::IndexCorrupt => Nat44IcmpConfigMismatch,
    }
}

pub(super) fn require_nat44_icmp_runtime<'runtime, 'storage, T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    config: &Nat44IcmpConfig,
    runtime: &'runtime mut Option<&mut Nat44IcmpRuntime<'storage>>,
    ingress: IfId,
    trace: &mut T,
) -> Result<&'runtime mut Nat44IcmpRuntime<'storage>, DropReason> {
    if !config.authority_matches(snapshot) {
        if let Some(runtime) = runtime.as_deref_mut() {
            runtime.record_config_mismatch();
        }
        trace.record(TraceEvent::Nat44Icmp {
            ingress,
            disposition: Nat44IcmpDisposition::ConfigMismatch,
        });
        return Err(Nat44IcmpConfigMismatch);
    }
    let Some(runtime) = runtime.as_deref_mut() else {
        trace.record(TraceEvent::Nat44Icmp {
            ingress,
            disposition: Nat44IcmpDisposition::Rejected {
                reason: Nat44IcmpRuntimeUnavailable,
            },
        });
        return Err(Nat44IcmpRuntimeUnavailable);
    };
    if runtime.config() != *config {
        runtime.record_config_mismatch();
        trace.record(TraceEvent::Nat44Icmp {
            ingress,
            disposition: Nat44IcmpDisposition::ConfigMismatch,
        });
        return Err(Nat44IcmpConfigMismatch);
    }
    Ok(runtime)
}

fn observe<T: TraceSink>(
    runtime: &mut Nat44IcmpRuntime<'_>,
    ingress: IfId,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<(), DropReason> {
    runtime.observe_now(now.0).map_err(|error| {
        let (reason, disposition) = nat44_icmp_plan_error(error);
        trace.record(TraceEvent::Nat44Icmp {
            ingress,
            disposition,
        });
        reason
    })
}

/// Observes the ICMP query runtime clock for a firewall-preflighted packet
/// (the combined composition observes NAT time before the firewall plan).
pub(super) fn observe_nat44_icmp_security_time<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    config: &Nat44IcmpConfig,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
    ingress: IfId,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<(), DropReason> {
    let runtime = require_nat44_icmp_runtime(snapshot, config, nat44_icmp, ingress, trace)?;
    observe(runtime, ingress, now, trace)
}

/// An inside host's query toward the outside: maps `internal:identifier`
/// (creating or refreshing the endpoint-independent mapping and the peer)
/// and rewrites the source address and identifier.
#[allow(clippy::too_many_arguments)]
pub(super) fn decide_nat44_icmp_outbound<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    forwarding: Ipv4RewriteDecision,
    config: &Nat44IcmpConfig,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
    read_only_plan: bool,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let runtime = require_nat44_icmp_runtime(snapshot, config, nat44_icmp, ingress, trace)?;
    if !read_only_plan {
        observe(runtime, ingress, now, trace)?;
    }
    if ipv4.header_len > 20 {
        return nat44_icmp_drop(ingress, Ipv4OptionsUnsupported, trace);
    }
    if !unfragmented(frame, ipv4) {
        return nat44_icmp_drop(ingress, Nat44IcmpFragmentUnsupported, trace);
    }
    let query = match validate_icmp_query(frame, ipv4) {
        Ok(query) if is_query_request(query.icmp_type) => query,
        // A reply from the inside answers a request no inbound session
        // could have delivered.
        Ok(_) => return nat44_icmp_drop(ingress, Nat44IcmpTypeUnsupported, trace),
        Err(error) => return nat44_icmp_drop(ingress, nat_reason(error), trace),
    };
    if !icmp_error_source_is_host(snapshot, ipv4.source)
        || snapshot.is_local_ipv4(ipv4.source)
        || ipv4.source == config.public_address()
    {
        return nat44_icmp_drop(ingress, Nat44IcmpSourceForbidden, trace);
    }
    if snapshot
        .route_lookup(ipv4.source)
        .is_none_or(|reverse| reverse.egress() != config.inside())
    {
        return nat44_icmp_drop(ingress, Nat44IcmpReverseAuthorityMismatch, trace);
    }
    let planned = if read_only_plan {
        runtime.plan_outbound_read_only(ipv4.source, query.identifier, ipv4.destination, now.0)
    } else {
        runtime.plan_outbound(ipv4.source, query.identifier, ipv4.destination, now.0)
    };
    let plan = match planned {
        Ok(plan) => plan,
        Err(error) => {
            if read_only_plan {
                runtime.record_read_only_plan_error(error);
            } else {
                runtime.record_plan_error(error);
            }
            let (reason, disposition) = nat44_icmp_plan_error(error);
            trace.record(TraceEvent::Nat44Icmp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    };
    Ok(build_nat44_icmp_rewrite(
        ipv4,
        query,
        forwarding,
        ipv4.source,
        config.public_address(),
        plan.public_port(),
        Nat44IcmpTransition::Outbound(plan),
        Nat44IcmpDisposition::from_engine(plan.disposition()),
    ))
}

/// A query reply from the outside to the public address: translated back to
/// the mapping's internal address and identifier (reply filtering per
/// policy), then authorized by a bound firewall on the translated tuple.
#[allow(clippy::too_many_arguments)]
pub(super) fn decide_nat44_icmp_inbound<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    config: &Nat44IcmpConfig,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_validated: Option<ValidatedFirewallTransport>,
    firewall_plan: &mut Option<FirewallPlan>,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let now = resolution.as_ref().map_or(snapshot.now, |(_, now)| *now);
    let runtime = require_nat44_icmp_runtime(snapshot, config, nat44_icmp, ingress, trace)?;
    if firewall_config.is_none() {
        observe(runtime, ingress, now, trace)?;
    }
    if ipv4.header_len > 20 {
        return nat44_icmp_drop(ingress, Ipv4OptionsUnsupported, trace);
    }
    if !unfragmented(frame, ipv4) {
        return nat44_icmp_drop(ingress, Nat44IcmpFragmentUnsupported, trace);
    }
    let query = match validate_icmp_query(frame, ipv4) {
        Ok(query) if is_query_reply(query.icmp_type) => query,
        Ok(_) => return nat44_icmp_drop(ingress, Nat44IcmpTypeUnsupported, trace),
        Err(error) => return nat44_icmp_drop(ingress, nat_reason(error), trace),
    };
    if !icmp_error_source_is_host(snapshot, ipv4.source) || snapshot.is_local_ipv4(ipv4.source) {
        return nat44_icmp_drop(ingress, Nat44IcmpSourceForbidden, trace);
    }
    let planned = if firewall_config.is_some() {
        runtime.plan_inbound_read_only(query.identifier, ipv4.source, now.0)
    } else {
        runtime.plan_inbound(query.identifier, ipv4.source, now.0)
    };
    let plan = match planned {
        Ok(plan) => plan,
        Err(error) => {
            if firewall_config.is_some() {
                runtime.record_read_only_plan_error(error);
            } else {
                runtime.record_plan_error(error);
            }
            let (reason, disposition) = nat44_icmp_plan_error(error);
            trace.record(TraceEvent::Nat44Icmp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    };
    let internal_address = plan.internal_address();
    let Some(reverse_route) = snapshot.route_lookup(internal_address) else {
        return nat44_icmp_drop(ingress, Nat44IcmpReverseAuthorityMismatch, trace);
    };
    if reverse_route.egress() != config.inside() {
        return nat44_icmp_drop(ingress, Nat44IcmpWrongEgress, trace);
    }
    if let Some(firewall_config) = firewall_config {
        let (source_port, destination_port) = firewall_ports(query.icmp_type, plan.internal_port())
            .expect("a validated query reply has firewall pseudo-ports");
        let canonical = FirewallPacket {
            ingress,
            egress: reverse_route.egress(),
            source: ipv4.source,
            destination: internal_address,
            protocol: FirewallProtocol::Icmp,
            source_port,
            destination_port,
            tcp_flags: crate::firewall::FIREWALL_ICMP_REPLY,
        };
        let firewall_runtime = require_firewall_runtime(snapshot, firewall_config, firewall)?;
        *firewall_plan = Some(plan_firewall(
            ingress,
            reverse_route.egress(),
            ipv4,
            firewall_validated.expect("inbound firewall packet was preflight validated"),
            Some(canonical),
            firewall_config,
            firewall_runtime,
            firewall_audit,
            now.0,
        )?);
    }
    if ipv4.ttl <= 1 {
        return nat44_icmp_drop(ingress, Ipv4TtlExpired, trace);
    }
    let target = reverse_route.next_hop().unwrap_or(internal_address);
    let (interface, destination_mac) = match resolve_nat44_icmpv4_next_hop(
        snapshot,
        reverse_route.egress(),
        target,
        resolution,
        trace,
    ) {
        Ok(resolved) => resolved,
        Err(reason) => return nat44_icmp_drop(ingress, reason, trace),
    };
    let checksum_offset = ipv4.header_offset + 10;
    let forwarding = Ipv4RewriteDecision {
        egress: reverse_route.egress(),
        source_mac: interface.mac.0,
        destination_mac: destination_mac.0,
        ttl_offset: ipv4.header_offset + 8,
        checksum_offset,
        checksum_end: checksum_offset + 2,
        old_ttl_protocol: u16::from_be_bytes([ipv4.ttl, ipv4.protocol]),
        new_ttl_protocol: u16::from_be_bytes([ipv4.ttl - 1, ipv4.protocol]),
        old_checksum: ipv4.checksum,
    };
    Ok(build_nat44_icmp_rewrite(
        ipv4,
        query,
        forwarding,
        ipv4.destination,
        internal_address,
        plan.internal_port(),
        Nat44IcmpTransition::Inbound(plan),
        Nat44IcmpDisposition::from_engine(plan.disposition()),
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_nat44_icmp_rewrite(
    ipv4: packet::ValidatedIpv4,
    query: ValidatedIcmpQuery,
    forwarding: Ipv4RewriteDecision,
    old_address: crate::Ipv4Address,
    new_address: crate::Ipv4Address,
    new_identifier: u16,
    transition: Nat44IcmpTransition,
    disposition: Nat44IcmpDisposition,
) -> PacketDecision {
    let outbound = matches!(transition, Nat44IcmpTransition::Outbound(_));
    let ipv4_checksum = rfc1624_update_address(
        rfc1624_update(
            forwarding.old_checksum,
            forwarding.old_ttl_protocol,
            forwarding.new_ttl_protocol,
        ),
        old_address,
        new_address,
    );
    // No pseudo-header: the address change does not touch the ICMP checksum.
    let icmp_checksum = rfc1624_update(query.checksum, query.identifier, new_identifier);
    PacketDecision::Nat44Icmp(Nat44IcmpRewriteDecision {
        forwarding,
        address_offset: ipv4.header_offset + if outbound { 12 } else { 16 },
        new_address: new_address.octets(),
        identifier_offset: query.offset + 4,
        new_identifier,
        icmp_checksum_offset: query.offset + 2,
        ipv4_checksum,
        icmp_checksum,
        transition,
        disposition,
    })
}

pub(super) fn apply_nat44_icmp_rewrite(
    frame: &mut [u8],
    decision: Nat44IcmpRewriteDecision,
) -> Result<(), DropReason> {
    if frame.get(0..12).is_none()
        || frame.get(decision.forwarding.ttl_offset).is_none()
        || frame
            .get(decision.forwarding.checksum_offset..decision.forwarding.checksum_end)
            .is_none()
        || frame
            .get(decision.address_offset..decision.address_offset + 4)
            .is_none()
        || frame
            .get(decision.identifier_offset..decision.identifier_offset + 2)
            .is_none()
        || frame
            .get(decision.icmp_checksum_offset..decision.icmp_checksum_offset + 2)
            .is_none()
    {
        return Err(Nat44IcmpHeaderTruncated);
    }
    frame[0..6].copy_from_slice(&decision.forwarding.destination_mac);
    frame[6..12].copy_from_slice(&decision.forwarding.source_mac);
    frame[decision.forwarding.ttl_offset] -= 1;
    frame[decision.forwarding.checksum_offset..decision.forwarding.checksum_end]
        .copy_from_slice(&decision.ipv4_checksum.to_be_bytes());
    frame[decision.address_offset..decision.address_offset + 4]
        .copy_from_slice(&decision.new_address);
    frame[decision.identifier_offset..decision.identifier_offset + 2]
        .copy_from_slice(&decision.new_identifier.to_be_bytes());
    frame[decision.icmp_checksum_offset..decision.icmp_checksum_offset + 2]
        .copy_from_slice(&decision.icmp_checksum.to_be_bytes());
    Ok(())
}

/// Firewall flags of a query: the reply flag for a reply (see
/// [`FirewallProtocol::Icmp`]).
pub(super) const fn firewall_flags(icmp_type: u8) -> u8 {
    if is_query_reply(icmp_type) {
        crate::firewall::FIREWALL_ICMP_REPLY
    } else {
        0
    }
}

/// Firewall view of an ICMP query (see [`FirewallProtocol::Icmp`]):
/// pseudo-ports and direction flags.
pub(super) fn validate_firewall_icmp_query(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
) -> Result<(u16, u16, u8), DropReason> {
    match validate_icmp_query(frame, ipv4) {
        Ok(query) => {
            let (source_port, destination_port) = firewall_ports(query.icmp_type, query.identifier)
                .expect("a validated query has firewall pseudo-ports");
            Ok((
                source_port,
                destination_port,
                firewall_flags(query.icmp_type),
            ))
        }
        Err(IcmpQueryError::NotQuery) => Err(FirewallUnsupportedProtocol),
        Err(_) => Err(FirewallIcmpQueryInvalid),
    }
}

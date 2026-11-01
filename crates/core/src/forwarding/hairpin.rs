//! NAT44 hairpinning (RFC 4787 §6 REQ-9, REQ-9 a; RFC 5382 §7.2 REQ-8).
//!
//! An inside host X1:x1 that addresses the public address and port P:x2' of
//! a live mapping of inside host X2:x2 (X2 may be X1) is translated back into
//! the inside realm as P:x1' -> X2:x2, where P:x1' is X1's own external
//! mapping ("External source IP address and port", REQ-9 a).
//!
//! The packet is treated as two NAT traversals, each committed atomically:
//!
//! 1. **Outbound half**: exactly the NAT outbound plan an ordinary outbound
//!    packet X1:x1 -> P:x2' would make (mapping, filter peer or TCP session),
//!    and, with a bound firewall, exactly the plan an ordinary outbound packet
//!    with ingress inside and egress outside would make. It commits only when
//!    every outbound-half check passes and the destination port is a live
//!    mapping; it never creates more state than the sender could create by
//!    sending an ordinary outbound packet. Because the remote it records is
//!    the router's own public address, which common admission refuses as an
//!    external source, that state only ever admits hairpinned packets.
//! 2. **Inbound half**: planned against the state after the outbound half,
//!    exactly like an ordinary inbound packet from the external endpoint
//!    P:x1' to P:x2' (destination mapping filtering, then the firewall with
//!    ingress outside, egress inside, and the post-DNAT tuple P:x1' -> X2:x2,
//!    then inside route/neighbor). It commits only with the TX request.
//!
//! If the inbound half is refused, the outbound half stays committed, as for
//! an outbound packet the remote NAT drops, which is what hole punching
//! between two hosts behind the same NAT relies on (RFC 5128 §3.3.2 for UDP,
//! §3.4 for TCP simultaneous open).
//! Hairpinning disabled, malformed packets, an unknown destination mapping,
//! and any failure of the outbound half commit nothing.

use super::*;

/// Destination address/port rewrite of a hairpinned packet, applied together
/// with the source rewrite of the enclosing NAT decision.
#[derive(Clone, Copy)]
pub(super) struct Nat44HairpinDestinationRewrite {
    pub(super) address_offset: usize,
    pub(super) new_address: [u8; 4],
    pub(super) port_offset: usize,
    pub(super) new_port: u16,
}

impl Nat44HairpinDestinationRewrite {
    pub(super) fn fits(self, frame: &[u8]) -> bool {
        self.address_offset
            .checked_add(4)
            .is_some_and(|end| frame.get(self.address_offset..end).is_some())
            && self
                .port_offset
                .checked_add(2)
                .is_some_and(|end| frame.get(self.port_offset..end).is_some())
    }

    pub(super) fn apply(self, frame: &mut [u8]) {
        frame[self.address_offset..self.address_offset + 4].copy_from_slice(&self.new_address);
        frame[self.port_offset..self.port_offset + 2].copy_from_slice(&self.new_port.to_be_bytes());
    }
}

fn address_words(address: crate::Ipv4Address) -> [u16; 2] {
    let octets = address.octets();
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
    ]
}

/// RFC 1624 update of a checksum over both IPv4 addresses.
fn update_addresses(
    checksum: u16,
    old_source: crate::Ipv4Address,
    new_source: crate::Ipv4Address,
    old_destination: crate::Ipv4Address,
    new_destination: crate::Ipv4Address,
) -> u16 {
    let [old_source_high, old_source_low] = address_words(old_source);
    let [new_source_high, new_source_low] = address_words(new_source);
    let [old_destination_high, old_destination_low] = address_words(old_destination);
    let [new_destination_high, new_destination_low] = address_words(new_destination);
    let checksum = rfc1624_update(checksum, old_source_high, new_source_high);
    let checksum = rfc1624_update(checksum, old_source_low, new_source_low);
    let checksum = rfc1624_update(checksum, old_destination_high, new_destination_high);
    rfc1624_update(checksum, old_destination_low, new_destination_low)
}

/// Both rewritten tuples of one hairpinned packet.
#[derive(Clone, Copy)]
struct HairpinTuples {
    public_address: crate::Ipv4Address,
    sender_public_port: u16,
    internal_address: crate::Ipv4Address,
    internal_port: u16,
}

/// Inside-realm forwarding toward the translated destination: TTL, Ethernet
/// rewrite, and static or fresh dynamic neighbor. A miss schedules ARP like
/// an ordinary inbound packet and is reported as `NeighborUnresolved`.
fn inside_forwarding<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    ipv4: packet::ValidatedIpv4,
    route: Route,
    internal_address: crate::Ipv4Address,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    trace: &mut T,
) -> Result<Ipv4RewriteDecision, DropReason> {
    let target = route.next_hop().unwrap_or(internal_address);
    let interface = snapshot
        .interfaces
        .iter()
        .find(|interface| interface.id == route.egress())
        .ok_or(InterfaceMiss)?;
    let destination_mac = if let Some(neighbor) = snapshot
        .neighbors
        .iter()
        .find(|neighbor| neighbor.interface == route.egress() && neighbor.target == target)
    {
        neighbor.mac
    } else if let Some((resolution_runtime, resolution_now)) = resolution.as_mut() {
        match resolution_runtime.lookup_dynamic(route.egress(), target, *resolution_now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => return Err(NeighborUnresolved),
            DynamicLookup::Miss => {
                if let Some(binding) = snapshot
                    .local_ipv4
                    .iter()
                    .find(|binding| binding.interface == route.egress())
                {
                    let result = resolution_runtime.schedule(
                        ArpRequestAction {
                            egress: route.egress(),
                            source_mac: interface.mac,
                            source_ip: binding.address,
                            target_ip: target,
                        },
                        *resolution_now,
                        false,
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
    let ttl_offset = ipv4.header_offset + 8;
    let checksum_offset = ipv4.header_offset + 10;
    trace.record(TraceEvent::Routed {
        egress: route.egress(),
        neighbor_target: target,
    });
    Ok(Ipv4RewriteDecision {
        egress: route.egress(),
        source_mac: interface.mac.0,
        destination_mac: destination_mac.0,
        ttl_offset,
        checksum_offset,
        checksum_end: checksum_offset + 2,
        old_ttl_protocol: u16::from_be_bytes([ipv4.ttl, ipv4.protocol]),
        new_ttl_protocol: u16::from_be_bytes([ipv4.ttl - 1, ipv4.protocol]),
        old_checksum: ipv4.checksum,
    })
}

/// Shared outbound-half source admission: the same checks as an ordinary
/// outbound packet (host-unicast, not a router or public address, and the
/// source reverse-LPM selects the inside interface).
fn sender_is_authorized(
    snapshot: &ForwardingSnapshot<'_>,
    source: crate::Ipv4Address,
    public_address: crate::Ipv4Address,
) -> bool {
    icmp_error_source_is_host(snapshot, source)
        && !snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == source)
        && source != public_address
}

fn reverse_is_inside(
    snapshot: &ForwardingSnapshot<'_>,
    source: crate::Ipv4Address,
    inside: IfId,
) -> bool {
    route::lookup(snapshot.routes, source).is_some_and(|reverse| reverse.egress() == inside)
}

/// Plans the firewall for one hairpin half with an explicit canonical
/// packet. The audit buffer records each half as its own entry.
#[allow(clippy::too_many_arguments)]
fn plan_half_firewall(
    snapshot: &ForwardingSnapshot<'_>,
    ipv4: packet::ValidatedIpv4,
    packet: FirewallPacket,
    config: &FirewallConfig<'_>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    validated: Option<ValidatedFirewallTransport>,
    now: MonotonicMillis,
) -> Result<FirewallPlan, DropReason> {
    let runtime = require_firewall_runtime(snapshot, config, firewall)?;
    plan_firewall(
        packet.ingress,
        packet.egress,
        ipv4,
        validated.expect("hairpin firewall packet was preflight validated"),
        Some(packet),
        config,
        runtime,
        firewall_audit,
        now.0,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decide_nat44_udp_hairpin<T: TraceSink>(
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
    // With a bound firewall the combined preflight already observed time.
    let read_only = firewall_config.is_some();
    let runtime = require_nat44_udp_runtime(snapshot, config, nat44_udp, ingress, trace)?;
    if !read_only {
        if let Err(error) = runtime.observe_now(now.0) {
            let (reason, disposition) = nat44_udp_plan_error(error);
            trace.record(TraceEvent::Nat44Udp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    }
    if !config.policy().hairpinning() {
        runtime.record_hairpin_disabled();
        return nat44_udp_drop(ingress, Nat44UdpHairpinDisabled, trace);
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
    if udp.source_port == 0 {
        return nat44_udp_drop(ingress, Nat44UdpSourcePortZero, trace);
    }
    if !sender_is_authorized(snapshot, ipv4.source, config.public_address()) {
        return nat44_udp_drop(ingress, Nat44UdpSourceForbidden, trace);
    }
    if !reverse_is_inside(snapshot, ipv4.source, config.inside()) {
        return nat44_udp_drop(ingress, Nat44UdpReverseAuthorityMismatch, trace);
    }
    if ipv4.ttl <= 1 {
        return nat44_udp_drop(ingress, Ipv4TtlExpired, trace);
    }
    let record_error = |runtime: &mut Nat44UdpRuntime<'_>, error| {
        if read_only {
            runtime.record_read_only_plan_error(error);
        } else {
            runtime.record_plan_error(error);
        }
    };
    let fail = |runtime: &mut Nat44UdpRuntime<'_>, error, trace: &mut T| {
        record_error(runtime, error);
        let (reason, disposition) = nat44_udp_plan_error(error);
        trace.record(TraceEvent::Nat44Udp {
            ingress,
            disposition,
        });
        Err(reason)
    };
    match runtime.hairpin_destination_is_live(udp.destination_port, now.0) {
        Ok(true) => {}
        Ok(false) => return fail(runtime, Nat44UdpPlanError::MappingMiss, trace),
        Err(error) => return fail(runtime, error, trace),
    }

    // Outbound half: X1:x1 -> P:x2' as an ordinary outbound packet.
    let planned = if read_only {
        runtime.plan_outbound_read_only(
            ipv4.source,
            udp.source_port,
            config.public_address(),
            udp.destination_port,
            now.0,
        )
    } else {
        runtime.plan_outbound(
            ipv4.source,
            udp.source_port,
            config.public_address(),
            udp.destination_port,
            now.0,
        )
    };
    let outbound = match planned {
        Ok(plan) => plan,
        Err(error) => return fail(runtime, error, trace),
    };
    let outbound_firewall = match firewall_config {
        Some(firewall_config) => Some(plan_half_firewall(
            snapshot,
            ipv4,
            FirewallPacket {
                ingress,
                egress: config.outside(),
                source: ipv4.source,
                destination: config.public_address(),
                protocol: FirewallProtocol::Udp,
                source_port: udp.source_port,
                destination_port: udp.destination_port,
                tcp_flags: 0,
            },
            firewall_config,
            firewall,
            firewall_audit,
            firewall_validated,
            now,
        )?),
        None => None,
    };
    if let Some(plan) = outbound_firewall {
        firewall
            .as_deref_mut()
            .expect("firewall plan requires a bound runtime")
            .commit(plan)
            .expect("sequential packet path keeps firewall plan authority stable");
    }
    runtime
        .commit_hairpin_outbound(outbound, now.0)
        .expect("sequential packet path keeps UDP NAT plan current");
    trace.record(TraceEvent::Nat44Udp {
        ingress,
        disposition: outbound.hairpin_disposition(),
    });

    // Inbound half: P:x1' -> P:x2' as an ordinary inbound packet.
    let tuples = HairpinTuples {
        public_address: config.public_address(),
        sender_public_port: outbound.public_port(),
        internal_address: config.public_address(),
        internal_port: 0,
    };
    let result = udp_hairpin_inbound_half(
        snapshot,
        ingress,
        ipv4,
        udp,
        resolution,
        config,
        runtime,
        read_only,
        firewall_config,
        firewall,
        firewall_audit,
        firewall_validated,
        firewall_plan,
        tuples,
        now,
        trace,
    );
    if result.is_err() {
        runtime.record_hairpin_inbound_refused();
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn udp_hairpin_inbound_half<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    udp: ValidatedNat44Udp,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    config: &Nat44UdpConfig,
    runtime: &mut Nat44UdpRuntime<'_>,
    read_only: bool,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_validated: Option<ValidatedFirewallTransport>,
    firewall_plan: &mut Option<FirewallPlan>,
    mut tuples: HairpinTuples,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let planned = if read_only {
        runtime.plan_inbound_read_only(
            udp.destination_port,
            tuples.public_address,
            tuples.sender_public_port,
            now.0,
        )
    } else {
        runtime.plan_inbound(
            udp.destination_port,
            tuples.public_address,
            tuples.sender_public_port,
            now.0,
        )
    };
    let inbound = match planned {
        Ok(plan) => plan,
        Err(Nat44UdpPlanError::FilterDenied) => {
            return nat44_udp_drop(ingress, Nat44UdpHairpinFiltered, trace);
        }
        Err(error) => {
            if read_only {
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
    tuples.internal_address = inbound.internal_address();
    tuples.internal_port = inbound.internal_port();
    let Some(route) = route::lookup(snapshot.routes, tuples.internal_address) else {
        return nat44_udp_drop(ingress, Nat44UdpReverseAuthorityMismatch, trace);
    };
    if route.egress() != config.inside() {
        return nat44_udp_drop(ingress, Nat44UdpWrongEgress, trace);
    }
    if let Some(firewall_config) = firewall_config {
        *firewall_plan = Some(plan_half_firewall(
            snapshot,
            ipv4,
            FirewallPacket {
                ingress: config.outside(),
                egress: route.egress(),
                source: tuples.public_address,
                destination: tuples.internal_address,
                protocol: FirewallProtocol::Udp,
                source_port: tuples.sender_public_port,
                destination_port: tuples.internal_port,
                tcp_flags: 0,
            },
            firewall_config,
            firewall,
            firewall_audit,
            firewall_validated,
            now,
        )?);
    }
    let forwarding = match inside_forwarding(
        snapshot,
        ipv4,
        route,
        tuples.internal_address,
        resolution,
        trace,
    ) {
        Ok(forwarding) => forwarding,
        Err(reason) => return nat44_udp_drop(ingress, reason, trace),
    };
    build_udp_rewrite(ipv4, udp, forwarding, tuples, inbound)
}

fn build_udp_rewrite(
    ipv4: packet::ValidatedIpv4,
    udp: ValidatedNat44Udp,
    forwarding: Ipv4RewriteDecision,
    tuples: HairpinTuples,
    plan: Nat44UdpInboundPlan,
) -> Result<PacketDecision, DropReason> {
    let ipv4_checksum = update_addresses(
        rfc1624_update(
            forwarding.old_checksum,
            forwarding.old_ttl_protocol,
            forwarding.new_ttl_protocol,
        ),
        ipv4.source,
        tuples.public_address,
        ipv4.destination,
        tuples.internal_address,
    );
    let udp_checksum = if udp.checksum == 0 {
        0
    } else {
        let updated = rfc1624_update(
            rfc1624_update(
                update_addresses(
                    udp.checksum,
                    ipv4.source,
                    tuples.public_address,
                    ipv4.destination,
                    tuples.internal_address,
                ),
                udp.source_port,
                tuples.sender_public_port,
            ),
            udp.destination_port,
            tuples.internal_port,
        );
        if updated == 0 {
            0xffff
        } else {
            updated
        }
    };
    let address_offset = ipv4.header_offset + 12;
    let udp_checksum_offset = udp.offset + 6;
    Ok(PacketDecision::Nat44Udp(Nat44UdpRewriteDecision {
        forwarding,
        address_offset,
        address_end: address_offset + 4,
        new_address: tuples.public_address.octets(),
        port_offset: udp.offset,
        port_end: udp.offset + 2,
        new_port: tuples.sender_public_port,
        udp_checksum_offset,
        udp_checksum_end: udp_checksum_offset + 2,
        ipv4_checksum,
        udp_checksum,
        transition: Nat44UdpTransition::Hairpin(plan),
        disposition: Nat44UdpDisposition::HairpinTranslated {
            public_port: tuples.sender_public_port,
            internal_address: tuples.internal_address,
            internal_port: tuples.internal_port,
        },
        hairpin_destination: Some(Nat44HairpinDestinationRewrite {
            address_offset: ipv4.header_offset + 16,
            new_address: tuples.internal_address.octets(),
            port_offset: udp.offset + 2,
            new_port: tuples.internal_port,
        }),
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decide_nat44_tcp_hairpin<T: TraceSink>(
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
    let read_only = firewall_config.is_some();
    let runtime = require_nat44_tcp_runtime(snapshot, config, nat44_tcp, ingress, trace)?;
    if !read_only {
        if let Err(error) = runtime.observe_now(now.0) {
            let (reason, disposition) = nat44_tcp_plan_error(error);
            trace.record(TraceEvent::Nat44Tcp {
                ingress,
                disposition,
            });
            return Err(reason);
        }
    }
    if !config.policy().hairpinning() {
        runtime.record_hairpin_disabled();
        return nat44_tcp_drop(ingress, Nat44TcpHairpinDisabled, trace);
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
    if !sender_is_authorized(snapshot, ipv4.source, config.public_address()) {
        return nat44_tcp_drop(ingress, Nat44TcpSourceForbidden, trace);
    }
    if !reverse_is_inside(snapshot, ipv4.source, config.inside()) {
        return nat44_tcp_drop(ingress, Nat44TcpReverseAuthorityMismatch, trace);
    }
    if ipv4.ttl <= 1 {
        return nat44_tcp_drop(ingress, Ipv4TtlExpired, trace);
    }
    let fail = |runtime: &mut Nat44TcpRuntime<'_>, error, trace: &mut T| {
        if read_only {
            runtime.record_read_only_plan_error(error);
        } else {
            runtime.record_plan_error(error);
        }
        let (reason, disposition) = nat44_tcp_plan_error(error);
        trace.record(TraceEvent::Nat44Tcp {
            ingress,
            disposition,
        });
        Err(reason)
    };
    match runtime.hairpin_destination_is_live(tcp.destination_port, now.0) {
        Ok(true) => {}
        Ok(false) => return fail(runtime, Nat44TcpPlanError::MappingMiss, trace),
        Err(error) => return fail(runtime, error, trace),
    }

    // Outbound half: X1:x1 -> P:x2' as an ordinary outbound segment.
    let initial_syn = tcp.flags & 0x17 == 0x02;
    let planned = if read_only {
        runtime.plan_outbound_read_only(
            ipv4.source,
            tcp.source_port,
            config.public_address(),
            tcp.destination_port,
            initial_syn,
            now.0,
        )
    } else {
        runtime.plan_outbound(
            ipv4.source,
            tcp.source_port,
            config.public_address(),
            tcp.destination_port,
            initial_syn,
            now.0,
        )
    };
    let outbound = match planned {
        Ok(plan) => plan,
        Err(error) => return fail(runtime, error, trace),
    };
    let outbound_firewall = match firewall_config {
        Some(firewall_config) => Some(plan_half_firewall(
            snapshot,
            ipv4,
            FirewallPacket {
                ingress,
                egress: config.outside(),
                source: ipv4.source,
                destination: config.public_address(),
                protocol: FirewallProtocol::Tcp,
                source_port: tcp.source_port,
                destination_port: tcp.destination_port,
                tcp_flags: tcp.flags,
            },
            firewall_config,
            firewall,
            firewall_audit,
            firewall_validated,
            now,
        )?),
        None => None,
    };
    if runtime
        .prevalidate_outbound_commit(outbound, now.0)
        .is_err()
    {
        return nat44_tcp_drop(ingress, Nat44TcpConfigMismatch, trace);
    }
    if let Some(plan) = outbound_firewall {
        firewall
            .as_deref_mut()
            .expect("firewall plan requires a bound runtime")
            .commit(plan)
            .expect("sequential packet path keeps firewall plan authority stable");
    }
    runtime.commit_prevalidated_hairpin_outbound(outbound, now.0);
    trace.record(TraceEvent::Nat44Tcp {
        ingress,
        disposition: outbound.hairpin_disposition(),
    });

    // Inbound half: P:x1' -> P:x2' as an ordinary inbound segment.
    let tuples = HairpinTuples {
        public_address: config.public_address(),
        sender_public_port: outbound.public_port(),
        internal_address: config.public_address(),
        internal_port: 0,
    };
    let result = tcp_hairpin_inbound_half(
        snapshot,
        ingress,
        ipv4,
        tcp,
        initial_syn,
        resolution,
        config,
        runtime,
        read_only,
        firewall_config,
        firewall,
        firewall_audit,
        firewall_validated,
        firewall_plan,
        tuples,
        now,
        trace,
    );
    if result.is_err() {
        runtime.record_hairpin_inbound_refused();
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn tcp_hairpin_inbound_half<T: TraceSink>(
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    tcp: ValidatedNat44Tcp,
    initial_syn: bool,
    resolution: &mut Option<(&mut ResolutionRuntime<'_>, MonotonicMillis)>,
    config: &Nat44TcpConfig,
    runtime: &mut Nat44TcpRuntime<'_>,
    read_only: bool,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    firewall_audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    firewall_validated: Option<ValidatedFirewallTransport>,
    firewall_plan: &mut Option<FirewallPlan>,
    mut tuples: HairpinTuples,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<PacketDecision, DropReason> {
    let planned = if read_only {
        runtime.plan_inbound_read_only(
            tcp.destination_port,
            tuples.public_address,
            tuples.sender_public_port,
            initial_syn,
            now.0,
        )
    } else {
        runtime.plan_inbound(
            tcp.destination_port,
            tuples.public_address,
            tuples.sender_public_port,
            initial_syn,
            now.0,
        )
    };
    let inbound = match planned {
        Ok(plan) => plan,
        Err(Nat44TcpPlanError::SessionMiss) => {
            return nat44_tcp_drop(ingress, Nat44TcpHairpinFiltered, trace);
        }
        Err(error) => {
            if read_only {
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
    tuples.internal_address = inbound.internal_address();
    tuples.internal_port = inbound.internal_port();
    let Some(route) = route::lookup(snapshot.routes, tuples.internal_address) else {
        return nat44_tcp_drop(ingress, Nat44TcpReverseAuthorityMismatch, trace);
    };
    if route.egress() != config.inside() {
        return nat44_tcp_drop(ingress, Nat44TcpWrongEgress, trace);
    }
    if let Some(firewall_config) = firewall_config {
        *firewall_plan = Some(plan_half_firewall(
            snapshot,
            ipv4,
            FirewallPacket {
                ingress: config.outside(),
                egress: route.egress(),
                source: tuples.public_address,
                destination: tuples.internal_address,
                protocol: FirewallProtocol::Tcp,
                source_port: tuples.sender_public_port,
                destination_port: tuples.internal_port,
                tcp_flags: tcp.flags,
            },
            firewall_config,
            firewall,
            firewall_audit,
            firewall_validated,
            now,
        )?);
    }
    let forwarding = match inside_forwarding(
        snapshot,
        ipv4,
        route,
        tuples.internal_address,
        resolution,
        trace,
    ) {
        Ok(forwarding) => forwarding,
        Err(reason) => return nat44_tcp_drop(ingress, reason, trace),
    };
    build_tcp_rewrite(ipv4, tcp, forwarding, tuples, inbound)
}

fn build_tcp_rewrite(
    ipv4: packet::ValidatedIpv4,
    tcp: ValidatedNat44Tcp,
    forwarding: Ipv4RewriteDecision,
    tuples: HairpinTuples,
    plan: Nat44TcpInboundPlan,
) -> Result<PacketDecision, DropReason> {
    let ipv4_checksum = update_addresses(
        rfc1624_update(
            forwarding.old_checksum,
            forwarding.old_ttl_protocol,
            forwarding.new_ttl_protocol,
        ),
        ipv4.source,
        tuples.public_address,
        ipv4.destination,
        tuples.internal_address,
    );
    // TCP keeps a mathematical zero on the wire (no UDP-style encoding).
    let tcp_checksum = rfc1624_update(
        rfc1624_update(
            update_addresses(
                tcp.checksum,
                ipv4.source,
                tuples.public_address,
                ipv4.destination,
                tuples.internal_address,
            ),
            tcp.source_port,
            tuples.sender_public_port,
        ),
        tcp.destination_port,
        tuples.internal_port,
    );
    let address_offset = ipv4.header_offset + 12;
    let tcp_checksum_offset = tcp.offset.checked_add(16).ok_or(Nat44TcpHeaderTruncated)?;
    Ok(PacketDecision::Nat44Tcp(Nat44TcpRewriteDecision {
        forwarding,
        address_offset,
        address_end: address_offset + 4,
        new_address: tuples.public_address.octets(),
        port_offset: tcp.offset,
        port_end: tcp.offset + 2,
        new_port: tuples.sender_public_port,
        tcp_checksum_offset,
        tcp_checksum_end: tcp_checksum_offset + 2,
        ipv4_checksum,
        tcp_checksum,
        transition: Nat44TcpTransition::Hairpin(plan),
        disposition: Nat44TcpDisposition::HairpinTranslated {
            public_port: tuples.sender_public_port,
            internal_address: tuples.internal_address,
            internal_port: tuples.internal_port,
        },
        hairpin_destination: Some(Nat44HairpinDestinationRewrite {
            address_offset: ipv4.header_offset + 16,
            new_address: tuples.internal_address.octets(),
            port_offset: tcp.offset + 2,
            new_port: tuples.internal_port,
        }),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ipv4Address, MacAddress};

    /// Sender admission of the outbound half. On the wire, common IPv4
    /// admission already refuses router-local and network/broadcast
    /// sources, so the call site is defense in depth that mirrors the
    /// ordinary outbound check; this pins the helpers themselves.
    #[test]
    fn hairpin_sender_admission_requires_an_inside_host_that_is_not_the_router() {
        let lan = IfId(1);
        let wan = IfId(2);
        let public = Ipv4Address::from_octets([203, 0, 113, 10]);
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, lan, None).unwrap(),
            Route::new(
                Ipv4Address::from_octets([0; 4]),
                0,
                wan,
                Some(Ipv4Address::from_octets([203, 0, 113, 1])),
            )
            .unwrap(),
        ];
        let interfaces = [
            Interface {
                id: lan,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
            },
            Interface {
                id: wan,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: lan,
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
            },
            LocalIpv4Binding {
                interface: wan,
                address: public,
            },
        ];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let host = Ipv4Address::from_octets([10, 0, 0, 10]);
        assert!(sender_is_authorized(&snapshot, host, public));
        for forbidden in [
            public,
            Ipv4Address::from_octets([10, 0, 0, 1]),
            Ipv4Address::from_octets([10, 0, 0, 0]),
            Ipv4Address::from_octets([10, 0, 0, 255]),
            Ipv4Address::from_octets([127, 0, 0, 1]),
            Ipv4Address::from_octets([0, 0, 0, 1]),
            Ipv4Address::from_octets([224, 0, 0, 1]),
        ] {
            assert!(
                !sender_is_authorized(&snapshot, forbidden, public),
                "{forbidden:?}"
            );
        }
        assert!(reverse_is_inside(&snapshot, host, lan));
        assert!(!reverse_is_inside(
            &snapshot,
            Ipv4Address::from_octets([198, 51, 100, 7]),
            lan
        ));
    }
}

//! The short way through for the most common packet: an IPv4 datagram that is
//! only forwarded, with no NAT to consult.
//!
//! [`decide`] makes the same checks as the full decision (`decide_ipv4`,
//! `check_egress_mtu`) for that case, in the same functions, and answers only
//! when every one passes and nothing else could happen to the packet. Anything
//! else (a drop, an ICMP error, a Redirect, a fragment, options, a packet for
//! the router, a wrapped or bridged egress, a resolve request) gets `None`, and
//! the packet goes the full way, which then does exactly what it did before.
//! [`decide`] neither writes the frame nor records a trace event, so a `None`
//! leaves no mark.
//!
//! With a forward firewall, a datagram [`decide`] answered for is then judged
//! by it ([`plan_firewall`]) with the full decision's own functions. Every
//! other check has passed by then, so the firewall's answer is the packet's:
//! sent, or dropped as the full way drops it.
//!
//! The answer, once sent ([`send`]), leaves the frame, the trace and the
//! firewall as the full way would: `plain_ipv4_tests` compares both on random
//! tables, rules and frames.

use super::*;
use crate::{PacketLease, PacketSlot};

/// A datagram [`decide`] found plain: where it goes and what to write.
#[derive(Clone, Copy)]
pub(super) struct Plain {
    rewrite: Ipv4RewriteDecision,
    ipv4: packet::ValidatedIpv4,
    route: Route,
    target: crate::Ipv4Address,
}

impl Plain {
    pub(super) fn egress(&self) -> IfId {
        self.rewrite.egress
    }
}

#[cfg(test)]
thread_local! {
    /// Set by tests to send every packet the full way.
    pub(super) static OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the short way is tried at all (always, except in tests that turn
/// it off to compare).
#[inline]
pub(super) fn enabled() -> bool {
    #[cfg(test)]
    {
        !OFF.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        true
    }
}

/// `frame`, received on `ingress` and decided in `snapshot` (its VRF's),
/// when it is a plain forward; `outer` is the batch's snapshot, whose
/// tunnels, PPPoE sessions and SR policies wrap what leaves. With
/// `firewall` (the forward firewall is on), an ICMPv4 error, which the
/// firewall judges by the flow it quotes, is not.
#[inline]
pub(super) fn decide(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    outer: &ForwardingSnapshot<'_>,
    ingress: IfId,
    bridges: Option<&crate::Bridges>,
    firewall: bool,
) -> Option<Plain> {
    if packet::read_u16(frame, 12)? != IPV4_ETHERTYPE || is_ipv4_fragment(frame) {
        return None;
    }
    validate_ethernet_ingress(frame, snapshot, ingress, IPV4_ETHERTYPE).ok()?;
    let ipv4 = validate_ipv4_frame(frame).ok()?;
    if ipv4.header_len != 20 || (firewall && is_related_icmpv4_error_candidate(frame, ipv4)) {
        return None;
    }
    validate_ipv4_ingress(snapshot, ingress, ipv4).ok()?;
    if snapshot.is_ipv4_for_router(ingress, ipv4.destination, false) {
        return None;
    }
    let route = snapshot.route_lookup(ipv4.destination)?;
    let egress = route.egress();
    // Out of its ingress interface it may get a Redirect.
    if egress == IfId::DISCARD || egress == IfId::REJECT || egress == ingress {
        return None;
    }
    validate_ipv4_forward_destination(ipv4, Some(route)).ok()?;
    // The router's own packets keep their TTL.
    if ipv4.ttl <= 1 || snapshot.is_kernel_ingress(ingress) {
        return None;
    }
    let target = route.next_hop().unwrap_or(ipv4.destination);
    let interface = snapshot.interface(egress)?;
    let neighbor = snapshot.static_neighbor(egress, target)?;
    // Sent as it is: no tunnel, SR policy, PPPoE session or bridge on the way.
    if outer.wraps_frames(egress) || bridges.is_some_and(|bridges| bridges.irb_of(egress).is_some())
    {
        return None;
    }
    let mtu = usize::from(outer.carried_mtu(egress, interface.mtu));
    if ipv4.total_len > mtu || frame.len() - packet::ETHERNET_HEADER_LEN > mtu {
        return None;
    }
    let offset = ipv4.header_offset;
    Some(Plain {
        rewrite: Ipv4RewriteDecision {
            egress,
            source_mac: interface.mac.0,
            destination_mac: neighbor.mac.0,
            ttl_offset: offset + 8,
            checksum_offset: offset + 10,
            checksum_end: offset + 12,
            old_ttl_protocol: u16::from_be_bytes([ipv4.ttl, ipv4.protocol]),
            new_ttl_protocol: u16::from_be_bytes([ipv4.ttl - 1, ipv4.protocol]),
            old_checksum: ipv4.checksum,
        },
        ipv4,
        route,
        target,
    })
}

/// Judges `plain` with the forward firewall, as the full way does for a
/// forwarded datagram: `snapshot` is the default VRF's, on the batch's clock.
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_firewall<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    plain: &Plain,
    config: &FirewallConfig<'_>,
    firewall: &mut Option<&mut FirewallRuntime<'_>>,
    audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    icmpv4_errors: &mut Option<(&mut Icmpv4ErrorRuntime<'_>, MonotonicMillis)>,
    trace: &mut T,
) -> Result<FirewallPlan, DropReason> {
    let now = snapshot.now;
    let runtime = require_firewall_runtime(snapshot, config, firewall)?;
    let validated = observe_forward_firewall(frame, plain.ipv4, runtime, now)?;
    // Without NAT there is no NAT clock to observe.
    plan_forward_firewall(
        frame,
        snapshot,
        ingress,
        plain.ipv4,
        plain.route,
        validated,
        config,
        runtime,
        audit,
        icmpv4_errors,
        now,
        trace,
    )
}

/// What the full way records first for a datagram [`decide`] answered for.
#[inline]
pub(super) fn validated<T: TraceSink>(plain: &Plain, ingress: IfId, trace: &mut T) {
    trace.record(TraceEvent::Ipv4Validated {
        ingress,
        destination: plain.ipv4.destination,
    });
}

/// Rewrites the frame [`decide`] answered for, commits the firewall's plan
/// for it, and readies it to leave: the port to commit it to, or why it is
/// dropped. Records what the full way records from the route to the commit.
#[inline]
pub(super) fn send<S: PacketSlot, T: TraceSink>(
    packet: &mut PacketLease<S>,
    plain: Plain,
    firewall: Option<(FirewallPlan, &mut FirewallRuntime<'_>)>,
    outer: &ForwardingSnapshot<'_>,
    bridges: Option<&crate::Bridges>,
    trace: &mut T,
) -> Result<IfId, DropReason> {
    let egress = plain.egress();
    trace.record(TraceEvent::Routed {
        egress,
        neighbor_target: plain.target,
    });
    apply_ipv4_rewrite(packet.bytes_mut(), plain.rewrite)?;
    if let Some((plan, runtime)) = firewall {
        runtime
            .commit(plan)
            .expect("sequential packet path keeps firewall plan authority stable");
    }
    let irb = |id: IfId| bridges.is_some_and(|bridges| bridges.irb_of(id).is_some());
    crate::overlay::transmit_member(packet, egress, None, outer, irb, trace)
}

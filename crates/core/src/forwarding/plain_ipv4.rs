//! The short way through for the most common packet: an IPv4 datagram that is
//! only forwarded, perhaps judged by the forward firewall or translated from
//! the inside out by NAT.
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
//! sent, or dropped as the full way drops it. With NAT (and no firewall), a
//! UDP or TCP datagram that NAT leaves alone is forwarded the same way, and
//! one from the inside out is translated ([`translate`], [`send_translated`])
//! with the full decision's own functions; a datagram to the public address,
//! ICMP, and configurations whose realms disagree go the full way.
//!
//! The answer, once sent ([`send`], [`send_translated`]), leaves the frame,
//! the trace, the firewall and NAT as the full way would: `plain_ipv4_tests`
//! compares both on random tables, rules, NAT configurations and frames.

use super::*;
use crate::{ConsumeReason, PacketBatch, PacketLease, PacketSlot};

/// A datagram [`decide`] found plain: where it goes and what to write.
#[derive(Clone, Copy)]
pub(super) struct Plain {
    rewrite: Ipv4RewriteDecision,
    ipv4: packet::ValidatedIpv4,
    route: Route,
    target: crate::Ipv4Address,
    through: Through,
    /// Whether TCP NAT observes its clock first (a TCP segment from its
    /// inside).
    observe_tcp: bool,
}

/// What NAT does with a datagram [`decide`] answered for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Through {
    /// Nothing: it is forwarded as it is.
    Forward,
    /// UDP NAT translates it out (or refuses a TCP segment without TCP NAT).
    Udp,
    /// TCP NAT translates it out (or refuses a UDP datagram without UDP NAT).
    Tcp,
}

/// The NAT configurations of a batch.
#[derive(Clone, Copy)]
pub(super) struct Nat<'c> {
    pub(super) udp: Option<&'c Nat44UdpConfig>,
    pub(super) tcp: Option<&'c Nat44TcpConfig>,
    pub(super) icmp: Option<&'c Nat44IcmpConfig>,
}

impl Nat<'_> {
    pub(super) fn any(&self) -> bool {
        self.udp.is_some() || self.tcp.is_some() || self.icmp.is_some()
    }

    /// Whether `address` is a public address of NAT.
    fn is_public(&self, address: crate::Ipv4Address) -> bool {
        self.udp.is_some_and(|c| c.public_address() == address)
            || self.tcp.is_some_and(|c| c.public_address() == address)
            || self.icmp.is_some_and(|c| c.public_address() == address)
    }
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
/// firewall judges by the flow it quotes, is not. With `nat`, what NAT does
/// with it is in the answer, for [`translate`].
#[inline]
pub(super) fn decide(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    outer: &ForwardingSnapshot<'_>,
    ingress: IfId,
    bridges: Option<&crate::Bridges>,
    firewall: bool,
    nat: Nat<'_>,
) -> Option<Plain> {
    if packet::read_u16(frame, 12)? != IPV4_ETHERTYPE || is_ipv4_fragment(frame) {
        return None;
    }
    // What NAT translates in, and ICMP, go the full way: found first, from
    // the bytes, so that they pay for nothing else here.
    if nat.any() {
        let header = frame.get(packet::ETHERNET_HEADER_LEN..packet::ETHERNET_HEADER_LEN + 20)?;
        let destination =
            crate::Ipv4Address::from_octets([header[16], header[17], header[18], header[19]]);
        if !matches!(header[9], 6 | 17) || nat.is_public(destination) {
            return None;
        }
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
    let (through, observe_tcp) = if nat.any() {
        nat_way(snapshot, ingress, ipv4, egress, nat)?
    } else {
        (Through::Forward, false)
    };
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
        through,
        observe_tcp,
    })
}

/// What NAT does with a UDP or TCP datagram from `ingress` out of `egress`,
/// in the order the full decision (`decide_ipv4`) asks, when it is not one
/// the full way handles otherwise: ICMP, one to a public address, one in
/// from the outside to the inside, or any with realms that disagree.
fn nat_way(
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    egress: IfId,
    nat: Nat<'_>,
) -> Option<(Through, bool)> {
    let protocol = ipv4.protocol;
    if !matches!(protocol, 6 | 17)
        || nat.is_public(ipv4.destination)
        || combined_realm_mismatch(nat.udp, nat.tcp, nat.icmp)
    {
        return None;
    }
    if nat
        .udp
        .is_some_and(|c| ingress == c.outside() && egress == c.inside())
        || nat
            .tcp
            .is_some_and(|c| ingress == c.outside() && egress == c.inside())
    {
        return None;
    }
    let inside = |inside: IfId| nat_inside(snapshot, ingress, ipv4.source, inside);
    let through = if nat.udp.is_some_and(|c| {
        inside(c.inside())
            && egress == c.outside()
            && (protocol == 17 || (protocol == 6 && nat.tcp.is_none()))
    }) {
        Through::Udp
    } else if nat.tcp.is_some_and(|c| {
        inside(c.inside())
            && egress == c.outside()
            && (protocol == 6 || (protocol == 17 && nat.udp.is_none()))
    }) {
        Through::Tcp
    } else {
        Through::Forward
    };
    let observe_tcp = protocol == 6 && nat.tcp.is_some_and(|c| inside(c.inside()));
    Some((through, observe_tcp))
}

/// NAT's part for `plain`, as the full way does it: TCP NAT's clock, the
/// route, then the translation out. `None` for one NAT leaves alone.
/// `snapshot` is the default VRF's, on the batch's clock.
#[allow(clippy::too_many_arguments)]
pub(super) fn translate<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    plain: &Plain,
    nat: Nat<'_>,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    trace: &mut T,
) -> Result<Option<PacketDecision>, DropReason> {
    let now = snapshot.now;
    if plain.observe_tcp {
        let config = nat.tcp.expect("a TCP segment from the inside with TCP NAT");
        observe_nat44_tcp_candidate_if_present(snapshot, config, nat44_tcp, now, ingress, trace)?;
    }
    routed(plain, trace);
    match plain.through {
        Through::Forward => Ok(None),
        Through::Udp => decide_nat44_udp_outbound(
            frame,
            snapshot,
            ingress,
            plain.ipv4,
            plain.rewrite,
            nat.udp.expect("UDP NAT"),
            nat44_udp,
            false,
            now,
            trace,
        )
        .map(Some),
        Through::Tcp => decide_nat44_tcp_outbound(
            frame,
            snapshot,
            ingress,
            plain.ipv4,
            plain.rewrite,
            nat.tcp.expect("TCP NAT"),
            nat44_tcp,
            false,
            now,
            trace,
        )
        .map(Some),
    }
}

/// Sends a datagram [`translate`] translated, as the full way does: the
/// runtime's check of the plan, the rewrite, a new IPv4 ID when the policy
/// asks, the commit, then out.
#[allow(clippy::too_many_arguments)]
pub(super) fn send_translated<S: PacketSlot, T: TraceSink>(
    packet: &mut PacketLease<S>,
    decision: PacketDecision,
    ingress: IfId,
    nat44_udp: &mut Option<&mut Nat44UdpRuntime<'_>>,
    nat44_tcp: &mut Option<&mut Nat44TcpRuntime<'_>>,
    nat44_icmp: &mut Option<&mut Nat44IcmpRuntime<'_>>,
    outer: &ForwardingSnapshot<'_>,
    bridges: Option<&crate::Bridges>,
    trace: &mut T,
) -> Result<IfId, DropReason> {
    let now_ms = outer.now.0;
    prevalidate_nat(
        decision,
        nat44_udp.as_deref(),
        nat44_tcp.as_deref(),
        nat44_icmp.as_deref(),
        now_ms,
    )?;
    let frame = packet.bytes_mut();
    apply_decision(frame, decision)?;
    rewrite_translated_non_atomic_id(frame, decision, nat44_udp, nat44_tcp, nat44_icmp, now_ms)?;
    commit_nat(
        decision, nat44_udp, nat44_tcp, nat44_icmp, now_ms, ingress, trace,
    );
    let irb = |id: IfId| bridges.is_some_and(|bridges| bridges.irb_of(id).is_some());
    crate::overlay::transmit_member(packet, decision.egress(), None, outer, irb, trace)
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

/// What the full way records once the route of a datagram [`decide`]
/// answered for is settled.
#[inline]
pub(super) fn routed<T: TraceSink>(plain: &Plain, trace: &mut T) {
    trace.record(TraceEvent::Routed {
        egress: plain.egress(),
        neighbor_target: plain.target,
    });
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
/// dropped. Records what the full way records after the route.
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
    apply_ipv4_rewrite(packet.bytes_mut(), plain.rewrite)?;
    if let Some((plan, runtime)) = firewall {
        runtime
            .commit(plan)
            .expect("sequential packet path keeps firewall plan authority stable");
    }
    let irb = |id: IfId| bridges.is_some_and(|bridges| bridges.irb_of(id).is_some());
    crate::overlay::transmit_member(packet, egress, None, outer, irb, trace)
}

/// What [`forward_batch_stateless`] must leave to the worker that owns the
/// state: the NAT configurations it tells NAT's packets by, and whether a
/// forward firewall is on or the bridges are not empty (then every packet is
/// handed over).
#[derive(Clone, Copy, Default)]
pub struct Stateful<'c> {
    pub nat44_udp: Option<&'c Nat44UdpConfig>,
    pub nat44_tcp: Option<&'c Nat44TcpConfig>,
    pub nat44_icmp: Option<&'c Nat44IcmpConfig>,
    pub firewall: bool,
    pub bridges: bool,
}

/// Forwards the packets of `batch` that need no state, and hands every other
/// one to `hand` (its ingress and its frame, both as received) for the worker
/// that owns the state, which forwards it as if it had received it
/// ([`crate::forward_batch_with_control`]). A packet is forwarded here only when
/// it is a plain forward that NAT leaves alone, with no firewall and no bridge
/// and not for the control side: the short way's own answer. It then ends, frame
/// and trace, as the full way would end it. With VLAN sub-interfaces, a tagged
/// frame is handed over as it is.
pub fn forward_batch_stateless<B, T>(
    mut batch: B,
    snapshot: &ForwardingSnapshot<'_>,
    stateful: Stateful<'_>,
    mut hand: impl FnMut(IfId, &[u8]),
    trace: &mut T,
) -> BatchReport<B::Error>
where
    B: PacketBatch,
    T: TraceSink,
{
    let all_vrfs = snapshot;
    let nat = Nat {
        udp: stateful.nat44_udp,
        tcp: stateful.nat44_tcp,
        icmp: stateful.nat44_icmp,
    };
    let everything = stateful.firewall || stateful.bridges;
    let (mut received, mut tx_requested, mut dropped, mut consumed) = (0, 0, 0, 0);
    while let Some(mut packet) = batch.next_packet() {
        received += 1;
        let ingress = packet.ingress();
        let tagged = !all_vrfs.vlans.is_empty()
            && packet.bytes_mut().get(12..14) == Some(&crate::vlan::TPID[..]);
        let decided = if everything
            || tagged
            || (!all_vrfs.punt.is_empty()
                && crate::punt::select(packet.bytes_mut(), ingress, all_vrfs.punt).is_some())
        {
            None
        } else {
            let snapshot = all_vrfs.for_ingress(ingress);
            (!nat.any() || snapshot.authority() == all_vrfs.authority())
                .then(|| {
                    decide(
                        packet.bytes_mut(),
                        snapshot,
                        all_vrfs,
                        ingress,
                        None,
                        false,
                        nat,
                    )
                })
                .flatten()
                .filter(|plain| plain.through == Through::Forward && !plain.observe_tcp)
        };
        let Some(plain) = decided else {
            hand(ingress, packet.bytes_mut());
            packet.consume(ConsumeReason::HandedToOwner);
            consumed += 1;
            continue;
        };
        validated(&plain, ingress, trace);
        routed(&plain, trace);
        match send(&mut packet, plain, None, all_vrfs, None, trace) {
            Ok(port) => {
                packet.commit(port);
                tx_requested += 1;
                trace.record(TraceEvent::TxRequested {
                    egress: plain.egress(),
                });
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

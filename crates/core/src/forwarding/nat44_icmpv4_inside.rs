//! NAT44 translation of ICMPv4 errors that arrive from the inside realm, and
//! of hairpinned errors (REQ-5 and REQ-7, see # Standards).
//!
//! **REQ-5.** An inside host X (or an inside router on the path to X)
//! reports an error about an inbound packet `R:r -> X:x` that the NAT
//! delivered. The error is addressed to R. The NAT reverts the quoted
//! packet to its external view `R:r -> P:x'` and sets the outer source to
//! its own public address P (REQ-5 c for NAPT), keeping type and code.
//!
//! **REQ-7.** For a hairpinned packet `X1:x1 -> P:x2'`, delivered to X2 as
//! `P:x1' -> X2:x2`, X2 (or an inside router toward X2) addresses its error
//! to P. Both halves are reverted. The quote becomes `X1:x1 -> P:x2'`,
//! which is what X1 sent. The outer destination becomes X1 (REQ-7 a), and
//! the outer source becomes P (REQ-5 c, which REQ-7 applies in full).
//!
//! Authority is strict and read-only. Nothing here creates, refreshes, or
//! deletes NAT or firewall state, or changes a NAT counter.
//!
//! - The outer source must be an inside host-unicast address whose reverse
//!   route uses the inside interface. It must also be the quoted internal
//!   destination itself or the next hop of the router's route toward it.
//!   This stops an inside host from reporting errors about another host's
//!   flows. An error from a router further along an inside path is
//!   refused: that is a local-policy override that REQ-5 permits.
//! - The quoted internal endpoint must own a live mapping that still owns
//!   its public port. The quoted remote must be a recorded peer (UDP, at
//!   the runtime's peer key granularity, address-granular even under
//!   endpoint-independent filtering) or an exact live session (TCP). An
//!   inside host therefore cannot use an error to reach an external host
//!   its mapping has never exchanged traffic with.
//! - REQ-5: the outer destination must equal the quoted source, so the
//!   error goes only to the sender of the quoted packet. The quoted remote
//!   must not be a router address (`quoted_remote_is_local`). Hairpin
//!   state, whose remote is P, is reachable only by the REQ-7 path.
//! - REQ-7: hairpinning must be enabled. The quoted source must be P. Both
//!   X2's view (mapping of X2:x2 with peer or session P:x1') and X1's
//!   outbound half (mapping P:x1' with peer or session P:x2') must be live.
//! - With a bound firewall, every quoted flow must belong to a live
//!   firewall state in either direction (RELATED): the REQ-5 quote as the
//!   inbound packet `R:r -> X:x` (ingress outside, egress inside). For
//!   REQ-7, both the inbound half `P:x1' -> X2:x2` and the outbound half
//!   `X1:x1 -> P:x2'` must match. No rule is scanned.
//!
//! # Standards
//!
//! - RFC 5508 section 4.2.2 (REQ-5): the quoted packet is reverted, type and
//!   code are kept, and the outer source becomes the public address (REQ-5 c
//!   for NAPT). The quote is checked as RFC 5508 section 4.1 (REQ-3) asks,
//!   before this module (`parse_nat44_icmpv4_error`).
//! - RFC 5508 section 5 (REQ-7, REQ-7 a): hairpinned errors are translated and
//!   sent to the sender of the quoted packet.
//! - RFC 5508 section 4.3 (REQ-6): no NAT state is refreshed or deleted.
//!
//! Deviations, as the local policy REQ-5 allows: an error is translated only
//! from the quoted host or the router's next hop toward it, and Port
//! Unreachable, Protocol Unreachable and Time Exceeded code 1 only from the
//! quoted host; with a bound firewall the quoted flow must also be live in it.
//! An error quoting an ICMP query is not hairpinned, since no hairpinned query
//! session exists. An error with IPv4 options in its outer header, or a
//! fragment of one, is dropped.

use super::*;

/// Whether an inside-ingress ICMPv4 message is a REQ-5/REQ-7 candidate: a
/// supported error from the inside interface (or, from one of the router's own
/// addresses that route to the inside, the kernel's interface) of a protocol whose policy
/// translates inside errors, addressed to the public address (hairpin) or
/// routed toward the outside.
#[allow(clippy::too_many_arguments)]
pub(super) fn is_nat44_icmpv4_inside_candidate(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    ipv4: packet::ValidatedIpv4,
    local: bool,
    selected_route: Option<Route>,
    nat44_udp_config: Option<&Nat44UdpConfig>,
    nat44_tcp_config: Option<&Nat44TcpConfig>,
    nat44_icmp_config: Option<&Nat44IcmpConfig>,
) -> bool {
    if local {
        return false;
    }
    let Some((icmp_type, code, quoted_protocol)) = peek_nat44_icmpv4_error(frame, ipv4) else {
        return false;
    };
    if !nat44_icmpv4_error_supported(icmp_type, code) {
        return false;
    }
    let enabled = |policy: Nat44Icmpv4ErrorPolicy, inside: IfId, outside: IfId, public| {
        policy.translates_internal()
            && nat_inside(snapshot, ingress, ipv4.source, inside)
            && (ipv4.destination == public
                || selected_route.is_some_and(|route| route.egress() == outside))
    };
    let udp_enabled = nat44_udp_config.is_some_and(|config| {
        enabled(
            config.policy().icmpv4_errors(),
            config.inside(),
            config.outside(),
            config.public_address(),
        )
    });
    let tcp_enabled = nat44_tcp_config.is_some_and(|config| {
        enabled(
            config.policy().icmpv4_errors(),
            config.inside(),
            config.outside(),
            config.public_address(),
        )
    });
    let icmp_enabled = nat44_icmp_config.is_some_and(|config| {
        enabled(
            config.policy().icmpv4_errors(),
            config.inside(),
            config.outside(),
            config.public_address(),
        )
    });
    match quoted_protocol {
        Some(17) => udp_enabled,
        Some(6) => tcp_enabled,
        Some(1) if nat44_icmp_config.is_some() => icmp_enabled,
        Some(_) | None => udp_enabled || tcp_enabled || icmp_enabled,
    }
}

/// Protocol-independent view of the NAT configuration that owns a quote.
#[derive(Clone, Copy)]
struct OwnerConfig {
    inside: IfId,
    outside: IfId,
    public_address: crate::Ipv4Address,
    policy: Nat44Icmpv4ErrorPolicy,
    hairpinning: bool,
    hairpin_disabled: DropReason,
}

/// Result of the read-only NAT lookups.
#[derive(Clone, Copy)]
struct InsideErrorAuthority {
    /// Public port of the quoted internal destination's mapping.
    public_port: u16,
    /// Hairpin sender X1:x1 (REQ-7 only).
    sender: Option<(crate::Ipv4Address, u16)>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decide_nat44_icmpv4_inside_error<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ingress: IfId,
    outer: packet::ValidatedIpv4,
    selected_route: Option<Route>,
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
    // Forwarded out, it goes one hop on; the router's own (from the kernel's
    // interface) keeps its TTL.
    if outer.ttl <= 1 && !snapshot.is_kernel_ingress(ingress) {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4OuterTtlExpired, trace);
    }
    // A router address as the sender is forged, unless the router itself sent it
    // (from the kernel's interface).
    if !icmp_error_source_is_host(snapshot, outer.source)
        || (quoted_remote_is_local(snapshot, outer.source) && !snapshot.is_kernel_ingress(ingress))
    {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4SourceForbidden, trace);
    }
    let owner = match quote.protocol {
        17 => nat44_udp_config.map(|config| OwnerConfig {
            inside: config.inside(),
            outside: config.outside(),
            public_address: config.public_address(),
            policy: config.policy().icmpv4_errors(),
            hairpinning: config.policy().hairpinning(),
            hairpin_disabled: Nat44UdpHairpinDisabled,
        }),
        6 => nat44_tcp_config.map(|config| OwnerConfig {
            inside: config.inside(),
            outside: config.outside(),
            public_address: config.public_address(),
            policy: config.policy().icmpv4_errors(),
            hairpinning: config.policy().hairpinning(),
            hairpin_disabled: Nat44TcpHairpinDisabled,
        }),
        // A quoted ICMP query reply the inside host received (N5). No
        // hairpinned query session exists (see `nat44_icmp_query`), so an
        // error toward the public address quoting a query is refused.
        1 => nat44_icmp_config.map(|config| OwnerConfig {
            inside: config.inside(),
            outside: config.outside(),
            public_address: config.public_address(),
            policy: config.policy().icmpv4_errors(),
            hairpinning: false,
            hairpin_disabled: Nat44Icmpv4QuotedProtocolUnsupported,
        }),
        _ => None,
    };
    // The quoted protocol, not the peeked one, owns the decision; a quote
    // of a protocol whose policy keeps inside errors off is not translated.
    let Some(owner) = owner.filter(|owner| owner.policy.translates_internal()) else {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
    };
    if combined_realm_mismatch {
        return nat44_icmpv4_drop(ingress, Nat44CombinedRealmMismatch, trace);
    }
    // From the inside, or from the router itself (from one of its own addresses)
    // about its own translated flow.
    let kernel = snapshot.is_kernel_ingress(ingress);
    if !nat_inside(snapshot, ingress, outer.source, owner.inside)
        || (kernel && !snapshot.is_local_ipv4(outer.source))
    {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongIngress, trace);
    }
    // The interface the flow's inside end is on: the inside, or the kernel's.
    let inside_end = ingress;
    // Local strict uRPF: the reporting host is reached through the inside.
    if snapshot
        .route_lookup(outer.source)
        .is_none_or(|reverse| reverse.egress() != owner.inside)
    {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4SourceForbidden, trace);
    }

    let hairpin = outer.destination == owner.public_address;
    // The router's own packets are never hairpinned (a router address is no
    // hairpin sender), so no error of its is about one.
    if hairpin && kernel {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongIngress, trace);
    }
    let egress_route = if hairpin {
        if !owner.hairpinning {
            return nat44_icmpv4_drop(ingress, owner.hairpin_disabled, trace);
        }
        if quote.source_address != owner.public_address {
            return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedPublicSourceMismatch, trace);
        }
        None
    } else {
        // REQ-5: an error goes to the sender of the packet it quotes.
        if outer.destination != quote.source_address {
            return nat44_icmpv4_drop(ingress, Nat44Icmpv4OuterDestinationMismatch, trace);
        }
        if quoted_remote_is_local(snapshot, quote.source_address) {
            return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedRemoteLocal, trace);
        }
        let Some(route) = selected_route.filter(|route| route.egress() == owner.outside) else {
            return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongEgress, trace);
        };
        Some(route)
    };

    // Source authority: the quoted internal destination itself, or the
    // router's inside next hop toward it. Protocol and Port Unreachable, and
    // reassembly Time Exceeded, come only from the host itself.
    let internal = quote.destination_address;
    let on_path = outer.source == internal
        || (!nat44_icmpv4_error_end_host_only(quote.icmp_type, quote.icmp_code)
            && snapshot.route_lookup(internal).is_some_and(|route| {
                route.egress() == owner.inside && route.next_hop() == Some(outer.source)
            }));
    if !on_path {
        return nat44_icmpv4_drop(ingress, Nat44Icmpv4InsideSourceMismatch, trace);
    }

    let authority = match quote.protocol {
        17 => {
            let config = nat44_udp_config.expect("UDP owner has a UDP configuration");
            if !config.authority_matches(snapshot) {
                return nat44_icmpv4_drop(ingress, Nat44UdpConfigMismatch, trace);
            }
            let Some(runtime) = nat44_udp.as_deref() else {
                return nat44_icmpv4_drop(ingress, Nat44UdpRuntimeUnavailable, trace);
            };
            if runtime.config() != *config {
                return nat44_icmpv4_drop(ingress, Nat44UdpConfigMismatch, trace);
            }
            let reason = |error| nat44_udp_icmpv4_lookup_reason(error);
            let public_port = runtime
                .inspect_icmpv4_inbound_quote(
                    internal,
                    quote.destination_port,
                    quote.source_address,
                    quote.source_port,
                    now.0,
                )
                .map_err(|error| trace_nat44_icmpv4_drop(ingress, reason(error), trace))?;
            let sender = if hairpin {
                let lookup = runtime
                    .inspect_icmpv4(quote.source_port, owner.public_address, public_port, now.0)
                    .map_err(|error| trace_nat44_icmpv4_drop(ingress, reason(error), trace))?;
                Some((lookup.internal_address(), lookup.internal_port()))
            } else {
                None
            };
            InsideErrorAuthority {
                public_port,
                sender,
            }
        }
        6 => {
            let config = nat44_tcp_config.expect("TCP owner has a TCP configuration");
            if !config.authority_matches(snapshot) {
                return nat44_icmpv4_drop(ingress, Nat44TcpConfigMismatch, trace);
            }
            let Some(runtime) = nat44_tcp.as_deref() else {
                return nat44_icmpv4_drop(ingress, Nat44TcpRuntimeUnavailable, trace);
            };
            if runtime.config() != *config {
                return nat44_icmpv4_drop(ingress, Nat44TcpConfigMismatch, trace);
            }
            let reason = |error| nat44_tcp_icmpv4_lookup_reason(error);
            let public_port = runtime
                .inspect_icmpv4_inbound_quote(
                    internal,
                    quote.destination_port,
                    quote.source_address,
                    quote.source_port,
                    now.0,
                )
                .map_err(|error| trace_nat44_icmpv4_drop(ingress, reason(error), trace))?;
            let sender = if hairpin {
                let lookup = runtime
                    .inspect_icmpv4(quote.source_port, owner.public_address, public_port, now.0)
                    .map_err(|error| trace_nat44_icmpv4_drop(ingress, reason(error), trace))?;
                Some((lookup.internal_address(), lookup.internal_port()))
            } else {
                None
            };
            InsideErrorAuthority {
                public_port,
                sender,
            }
        }
        1 => {
            // Only a reply can have reached an inside host through the NAT.
            if !quote
                .query_type
                .is_some_and(super::nat44_icmp_query::is_query_reply)
            {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4QuotedProtocolUnsupported, trace);
            }
            let config = nat44_icmp_config.expect("ICMP owner has an ICMP configuration");
            if !config.authority_matches(snapshot) {
                return nat44_icmpv4_drop(ingress, Nat44IcmpConfigMismatch, trace);
            }
            let Some(runtime) = nat44_icmp.as_deref() else {
                return nat44_icmpv4_drop(ingress, Nat44IcmpRuntimeUnavailable, trace);
            };
            if runtime.config() != *config {
                return nat44_icmpv4_drop(ingress, Nat44IcmpConfigMismatch, trace);
            }
            let public_port = runtime
                .inspect_inbound_quote(
                    internal,
                    quote.destination_port,
                    quote.source_address,
                    now.0,
                )
                .map_err(|error| {
                    trace_nat44_icmpv4_drop(
                        ingress,
                        super::nat44_icmp_query::nat44_icmp_error_lookup_reason(error),
                        trace,
                    )
                })?;
            InsideErrorAuthority {
                public_port,
                sender: None,
            }
        }
        _ => unreachable!("the NAT ICMPv4 parser accepts only ICMP, UDP, and TCP quotes"),
    };

    if let Some(runtime) = related_firewall.as_deref() {
        let protocol = FirewallProtocol::from_ipv4(quote.protocol)
            .expect("the NAT ICMPv4 parser accepts only ICMP, UDP, and TCP quotes");
        let (source_port, destination_port) =
            quote.firewall_ports(quote.source_port, quote.destination_port);
        // The quoted packet as the error's sender received it: post-DNAT,
        // ingress outside, egress inside.
        let received = FirewallPacket {
            ingress: owner.outside,
            egress: inside_end,
            source: quote.source_address.into(),
            destination: internal.into(),
            protocol,
            source_port,
            destination_port,
            // A quoted query is a reply here (checked above).
            tcp_flags: quote
                .query_type
                .map_or(0, super::nat44_icmp_query::firewall_flags),
        };
        inspect_nat44_icmpv4_related(runtime, firewall_audit, received, true, ingress, now, trace)?;
        if let Some((sender_address, sender_port)) = authority.sender {
            // The hairpin's outbound half as X1 sent it: pre-SNAT, ingress
            // inside, egress outside.
            let sent = FirewallPacket {
                ingress: owner.inside,
                egress: owner.outside,
                source: sender_address.into(),
                destination: owner.public_address.into(),
                protocol,
                source_port: sender_port,
                destination_port: authority.public_port,
                tcp_flags: 0,
            };
            inspect_nat44_icmpv4_related(runtime, firewall_audit, sent, true, ingress, now, trace)?;
        }
    }

    let (egress, target, rewrite, disposition) = match (egress_route, authority.sender) {
        (Some(route), None) => (
            owner.outside,
            route.next_hop().unwrap_or(outer.destination),
            Nat44Icmpv4Rewrite {
                outer_source: Some(owner.public_address),
                outer_destination: None,
                quoted_source: None,
                quoted_destination: Some((owner.public_address, authority.public_port)),
            },
            Nat44Icmpv4Disposition::TranslatedFromInside {
                quoted_protocol: quote.protocol,
                internal_address: internal,
                internal_port: quote.destination_port,
                public_port: authority.public_port,
            },
        ),
        (None, Some((sender_address, sender_port))) => {
            let route = snapshot.route_lookup(sender_address).ok_or(RouteMiss)?;
            if route.egress() != owner.inside {
                return nat44_icmpv4_drop(ingress, Nat44Icmpv4WrongEgress, trace);
            }
            (
                owner.inside,
                route.next_hop().unwrap_or(sender_address),
                Nat44Icmpv4Rewrite {
                    outer_source: Some(owner.public_address),
                    outer_destination: Some(sender_address),
                    quoted_source: Some((sender_address, sender_port)),
                    quoted_destination: Some((owner.public_address, authority.public_port)),
                },
                Nat44Icmpv4Disposition::TranslatedHairpin {
                    quoted_protocol: quote.protocol,
                    internal_address: sender_address,
                    internal_port: sender_port,
                },
            )
        }
        _ => unreachable!("a hairpin error has a sender and an external one a route"),
    };
    let (interface, destination_mac) =
        resolve_nat44_icmpv4_next_hop(snapshot, egress, target, trace)?;
    Ok(build_nat44_icmpv4_rewrite(
        outer,
        quote,
        egress,
        interface.mac.0,
        destination_mac.0,
        rewrite,
        disposition,
    ))
}

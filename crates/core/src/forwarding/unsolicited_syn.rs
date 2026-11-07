//! RFC 5382 REQ-4: delayed ICMP Port Unreachable for unsolicited inbound
//! TCP SYNs.
//!
//! The packet path drops every unsolicited inbound initial SYN (no live
//! mapping for its public port, or a filtering refusal) silently, as before,
//! and may copy it into the TCP NAT runtime's bounded hold table
//! ([`hold_unsolicited_syn`]). A translated outbound SYN for the same
//! connection cancels the hold inside the NAT commit. The tick loop calls
//! [`dispatch_nat44_tcp_unsolicited_syns`] after the resolution failure
//! dispatch: each hold whose 6 s have passed is removed and answered at most
//! once with a Port Unreachable through the generated-ICMPv4 queue and the
//! Port Unreachable limiter class, unless the NAT would now admit a
//! retransmission.
//!
//! When a firewall is bound, a SYN is held, and a matured hold answered,
//! only if the firewall would admit the SYN as a new connection to every
//! inside destination (`FirewallRuntime::permits_unsolicited_syn`): RFC 5382
//! REQ-4 a forbids a response that the security policy would not allow.

use super::*;
use crate::firewall::FirewallUnsolicitedSynPacket;
use crate::nat44_syn_hold::unsolicited_syn_deadline_ms;

/// What happened to one unsolicited inbound SYN or one matured hold
/// (RFC 5382 REQ-4). Cancellation by a translated outbound SYN is counted in
/// [`crate::Nat44TcpCounters::unsolicited_syn_cancelled`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpUnsolicitedSynDisposition {
    /// The SYN was held until at least `deadline_ms`.
    Held { public_port: u16, deadline_ms: u64 },
    /// A retransmission of a held connection restarted its hold.
    Refreshed { public_port: u16, deadline_ms: u64 },
    /// The hold table (or the connection's keyed chain) was full or
    /// inconsistent: the SYN is only dropped silently.
    HoldFull { public_port: u16 },
    /// No ICMP error may answer this SYN (source not a unicast host or not
    /// routed back through the outside interface, or a link-layer group
    /// destination): the SYN is only dropped silently.
    Ineligible { public_port: u16 },
    /// A matured hold whose connection the NAT would now admit: dropped
    /// silently.
    Superseded { public_port: u16 },
    /// The bound firewall would not admit the SYN as a new connection to
    /// every inside destination: the SYN was not held, or the matured hold
    /// was dropped silently (RFC 5382 REQ-4 a).
    FirewallDenied { public_port: u16 },
    /// A matured hold was answered with a queued ICMP Port Unreachable.
    IcmpQueued { public_port: u16, egress: IfId },
    /// A matured hold queued no ICMP; `icmpv4` is the generated-ICMPv4
    /// refusal when the queue or a reverse lookup refused it.
    IcmpSuppressed {
        public_port: u16,
        icmpv4: Option<Icmpv4ErrorDisposition>,
    },
}

/// Counts of one [`dispatch_nat44_tcp_unsolicited_syns`] call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44TcpUnsolicitedSynDispatchReport {
    /// Holds removed because their hold time had passed.
    pub matured: usize,
    pub superseded: usize,
    /// Matured holds dropped silently because the bound firewall would not
    /// admit the SYN (RFC 5382 REQ-4 a).
    pub firewall_denied: usize,
    pub queued: usize,
    pub suppressed: usize,
    /// Holds still in the table after the call.
    pub pending: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpUnsolicitedSynDispatchError {
    /// `now` is before the TCP NAT runtime's clock watermark.
    ClockRegression,
    /// The runtime's config does not belong to `snapshot`.
    ConfigMismatch,
    /// The hold table or the runtime state is inconsistent; nothing more was
    /// dispatched. An inconsistent hold table has been flushed (fail closed,
    /// counted in [`crate::Nat44TcpCounters::unsolicited_syn_index_corrupt`]).
    Inconsistent,
}

/// Packet path: offers an unsolicited inbound initial SYN that the TCP NAT
/// just refused (mapping miss or filtering refusal) to the hold table. The
/// caller drops the SYN in every case. The hold is timed by the batch's
/// clock (`ForwardingSnapshot::with_now`).
#[allow(clippy::too_many_arguments)]
pub(super) fn hold_unsolicited_syn<T: TraceSink>(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    ipv4: packet::ValidatedIpv4,
    public_port: u16,
    remote_port: u16,
    config: &Nat44TcpConfig,
    runtime: &mut Nat44TcpRuntime<'_>,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: Option<&mut FirewallRuntime<'_>>,
    now: MonotonicMillis,
    trace: &mut T,
) {
    if !runtime.holds_unsolicited_syns() {
        return;
    }
    // RFC 1812 §4.3.2.7 suppression, as for every generated error, plus a
    // reverse-path check: the remote must be routed back out of the outside
    // interface, so a spoofed inside or unrouted source never turns the
    // hold into an ICMP toward the inside realm or nowhere.
    if !icmp_error_candidate_eligible(frame, snapshot, ipv4, None)
        || !remote_routes_outside(snapshot, config, ipv4.source)
    {
        runtime.record_unsolicited_syn_ineligible();
        trace.record(TraceEvent::Nat44TcpUnsolicitedSyn {
            disposition: Nat44TcpUnsolicitedSynDisposition::Ineligible { public_port },
        });
        return;
    }
    if !firewall_permits_unsolicited_syn(
        snapshot,
        config,
        firewall_config,
        firewall,
        ipv4.source,
        remote_port,
    ) {
        runtime.record_unsolicited_syn_firewall_denied();
        trace.record(TraceEvent::Nat44TcpUnsolicitedSyn {
            disposition: Nat44TcpUnsolicitedSynDisposition::FirewallDenied { public_port },
        });
        return;
    }
    let quote_end = ipv4.header_offset + ipv4.total_len;
    let deadline_ms = unsolicited_syn_deadline_ms(now.0);
    let Some(outcome) = runtime.hold_unsolicited_syn(
        public_port,
        ipv4.source,
        remote_port,
        frame[ipv4.header_offset + 1],
        &frame[ipv4.header_offset..quote_end],
        now.0,
    ) else {
        return;
    };
    let disposition = match outcome {
        crate::nat44_syn_hold::SynHoldInsert::Held => Nat44TcpUnsolicitedSynDisposition::Held {
            public_port,
            deadline_ms,
        },
        crate::nat44_syn_hold::SynHoldInsert::Refreshed => {
            Nat44TcpUnsolicitedSynDisposition::Refreshed {
                public_port,
                deadline_ms,
            }
        }
        crate::nat44_syn_hold::SynHoldInsert::Full
        // An inconsistent table was flushed (fail closed) and the SYN was
        // not held.
        | crate::nat44_syn_hold::SynHoldInsert::IndexCorrupt => {
            Nat44TcpUnsolicitedSynDisposition::HoldFull { public_port }
        }
    };
    trace.record(TraceEvent::Nat44TcpUnsolicitedSyn { disposition });
}

/// Whether the bound firewall, if any, would admit an unsolicited SYN from
/// `remote:remote_port` as a new connection to every inside destination.
/// Without a firewall the NAT alone decides (true). A firewall whose config
/// or runtime does not belong to this publication fails closed (false).
fn firewall_permits_unsolicited_syn(
    snapshot: &ForwardingSnapshot<'_>,
    config: &Nat44TcpConfig,
    firewall_config: Option<&FirewallConfig<'_>>,
    firewall: Option<&mut FirewallRuntime<'_>>,
    remote: crate::Ipv4Address,
    remote_port: u16,
) -> bool {
    let Some(firewall_config) = firewall_config else {
        return true;
    };
    if !firewall_config.authority_matches(snapshot) {
        return false;
    }
    let Some(firewall) = firewall else {
        return false;
    };
    if !firewall.config_matches(firewall_config) {
        return false;
    }
    firewall
        .permits_unsolicited_syn(
            firewall_config,
            FirewallUnsolicitedSynPacket {
                ingress: config.outside(),
                egress: config.inside(),
                source: remote,
                source_port: remote_port,
            },
        )
        .is_some()
}

fn remote_routes_outside(
    snapshot: &ForwardingSnapshot<'_>,
    config: &Nat44TcpConfig,
    remote: crate::Ipv4Address,
) -> bool {
    snapshot
        .route_lookup(remote)
        .is_some_and(|route| route.egress() == config.outside())
}

/// Tick loop: resolves at most `budget` unsolicited-SYN holds whose hold
/// time ([`crate::NAT44_TCP_UNSOLICITED_SYN_HOLD_MS`] plus
/// [`crate::NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS`]) has passed at `now`, oldest
/// first. Each matured hold is removed and yields at most one ICMP
/// Destination Unreachable, Port Unreachable (Type 3, Code 3) quoting the
/// held SYN (RFC 5382 REQ-4), queued through `icmpv4_errors` and its Port
/// Unreachable limiter class. It is dropped silently instead when the NAT
/// would now admit a retransmission of the SYN (an outbound SYN for the
/// connection was translated, or the filtering now admits the remote), when
/// the remote is no longer an eligible, outside-routed unicast host, when
/// the bound firewall (`firewall_config`, re-checked now so a firewall
/// change during the hold is honoured) would not admit the SYN as a new
/// connection to every inside destination, or when the limiter, the action
/// queue, the reverse route, or the reverse neighbor refuses (an unresolved
/// reverse neighbor queues only an ARP Request). A refused hold is not
/// retried, so a hold never produces a second ICMP.
///
/// Work is O(`budget`) plus, per matured hold, one firewall rule walk:
/// holds are kept in deadline order, so this never scans holds that have
/// not matured. A runtime without held SYNs returns at once without
/// touching its clock. The tick loop passes the failure-dispatch budget
/// value, applied separately from the resolution failure dispatch, so the
/// phase does at most twice that much work per tick.
///
/// # Errors
///
/// [`Nat44TcpUnsolicitedSynDispatchError::ClockRegression`] when `now` is
/// before the NAT runtime's watermark,
/// [`Nat44TcpUnsolicitedSynDispatchError::ConfigMismatch`] when the runtime
/// does not belong to `snapshot`, and
/// [`Nat44TcpUnsolicitedSynDispatchError::Inconsistent`] when the hold
/// table or NAT state is inconsistent.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_nat44_tcp_unsolicited_syns<T: TraceSink>(
    nat44_tcp: &mut Nat44TcpRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    snapshot: &ForwardingSnapshot<'_>,
    firewall_config: Option<&FirewallConfig<'_>>,
    mut firewall: Option<&mut FirewallRuntime<'_>>,
    now: MonotonicMillis,
    budget: usize,
    trace: &mut T,
) -> Result<Nat44TcpUnsolicitedSynDispatchReport, Nat44TcpUnsolicitedSynDispatchError> {
    let mut report = Nat44TcpUnsolicitedSynDispatchReport {
        pending: nat44_tcp.unsolicited_syn_holds(),
        ..Nat44TcpUnsolicitedSynDispatchReport::default()
    };
    if report.pending == 0 || budget == 0 {
        return Ok(report);
    }
    let config = nat44_tcp.config();
    if !config.authority_matches(snapshot) {
        nat44_tcp.record_config_mismatch();
        return Err(Nat44TcpUnsolicitedSynDispatchError::ConfigMismatch);
    }
    match nat44_tcp.observe_now(now.0) {
        Ok(()) => {}
        Err(Nat44TcpPlanError::ClockRegression) => {
            return Err(Nat44TcpUnsolicitedSynDispatchError::ClockRegression);
        }
        Err(_) => return Err(Nat44TcpUnsolicitedSynDispatchError::Inconsistent),
    }
    for _ in 0..budget {
        let hold = match nat44_tcp.pop_matured_unsolicited_syn(now.0) {
            Ok(Some(hold)) => hold,
            Ok(None) => break,
            // The runtime flushed the inconsistent table and counted it.
            Err(_) => return Err(Nat44TcpUnsolicitedSynDispatchError::Inconsistent),
        };
        report.matured += 1;
        let public_port = hold.key.public_port;
        let disposition = match nat44_tcp.plan_inbound_read_only(
            public_port,
            hold.key.remote_address,
            hold.key.remote_port,
            crate::nat44_tcp_state::Nat44TcpSegment::INITIAL_SYN,
            now.0,
        ) {
            Ok(_) => {
                nat44_tcp.record_unsolicited_syn_superseded();
                report.superseded += 1;
                Nat44TcpUnsolicitedSynDisposition::Superseded { public_port }
            }
            Err(Nat44TcpPlanError::MappingMiss | Nat44TcpPlanError::SessionMiss) => {
                let remote = hold.key.remote_address;
                let eligible = icmp_error_source_is_host(snapshot, remote)
                    && !snapshot.is_local_ipv4(remote)
                    && remote_routes_outside(snapshot, &config, remote);
                if eligible
                    && !firewall_permits_unsolicited_syn(
                        snapshot,
                        &config,
                        firewall_config,
                        firewall.as_deref_mut(),
                        remote,
                        hold.key.remote_port,
                    )
                {
                    nat44_tcp.record_unsolicited_syn_firewall_denied();
                    report.firewall_denied += 1;
                    trace.record(TraceEvent::Nat44TcpUnsolicitedSyn {
                        disposition: Nat44TcpUnsolicitedSynDisposition::FirewallDenied {
                            public_port,
                        },
                    });
                    continue;
                }
                let icmpv4 = if !eligible {
                    None
                } else {
                    Some(schedule_reverse_icmpv4_error(
                        snapshot,
                        remote,
                        hold.original_tos,
                        hold.quote(),
                        Icmpv4ErrorKind::DestinationUnreachablePort,
                        0,
                        icmpv4_errors,
                        now,
                        trace,
                    ))
                };
                match icmpv4 {
                    Some(Icmpv4ErrorDisposition::PortUnreachableQueued { egress, .. }) => {
                        nat44_tcp.record_unsolicited_syn_icmp(true);
                        report.queued += 1;
                        Nat44TcpUnsolicitedSynDisposition::IcmpQueued {
                            public_port,
                            egress,
                        }
                    }
                    icmpv4 => {
                        nat44_tcp.record_unsolicited_syn_icmp(false);
                        report.suppressed += 1;
                        Nat44TcpUnsolicitedSynDisposition::IcmpSuppressed {
                            public_port,
                            icmpv4,
                        }
                    }
                }
            }
            Err(_) => {
                nat44_tcp.record_unsolicited_syn_icmp(false);
                report.suppressed += 1;
                Nat44TcpUnsolicitedSynDisposition::IcmpSuppressed {
                    public_port,
                    icmpv4: None,
                }
            }
        };
        trace.record(TraceEvent::Nat44TcpUnsolicitedSyn { disposition });
    }
    report.pending = nat44_tcp.unsolicited_syn_holds();
    Ok(report)
}

use super::*;
use crate::{GeneratedArpFailure, GeneratedPhaseReport};
use ruster_core::{
    BatchCompletion, BatchReport, ResolutionFailureDispatchReport, ResolutionTimerError,
    ResolutionTimerReport,
};

const ALL_DROP_REASONS: [DropReason; 145] = [
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

const ALL_CONSUME_REASONS: [ConsumeReason; 2] = [
    ConsumeReason::ArpControl,
    ConsumeReason::Ipv4LocalUnsupported,
];

/// `(name, explicit discriminant)` of every variant of `enum_name` in a core
/// source file, so a variant added to core fails these tests until the
/// runtime tables and the lists above are updated.
fn scan_enum(source: &str, enum_name: &str) -> Vec<(String, Option<u16>)> {
    let header = format!("pub enum {enum_name} {{");
    let body = source
        .split_once(&header)
        .expect("enum present in core source")
        .1;
    let body = &body[..body.find("\n}").expect("enum end")];
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|line| {
            let line = line.trim_end_matches(',');
            match line.split_once(" = ") {
                Some((name, code)) => (name.to_owned(), Some(code.parse().expect("u16 code"))),
                None => (line.to_owned(), None),
            }
        })
        .collect()
}

#[derive(Default)]
struct Collect(Vec<(&'static str, &'static str, FieldValue)>);

impl FieldVisitor for Collect {
    fn field(&mut self, section: &'static str, key: &'static str, value: FieldValue) {
        self.0.push((section, key, value));
    }
}

#[test]
fn drop_reason_counters_index_every_stable_core_reason() {
    let scanned = scan_enum(
        include_str!("../../../core/src/forwarding.rs"),
        "DropReason",
    );
    let listed: Vec<(String, Option<u16>)> = ALL_DROP_REASONS
        .iter()
        .map(|reason| (format!("{reason:?}"), Some(*reason as u16)))
        .collect();
    assert_eq!(
        scanned, listed,
        "every core DropReason is listed in code order"
    );
    let max = ALL_DROP_REASONS.iter().map(|r| *r as u16).max().unwrap();
    assert_eq!(usize::from(max) + 1, DROP_REASON_CODE_LIMIT);

    let mut counters = DropReasonCounters::default();
    for reason in ALL_DROP_REASONS {
        for _ in 0..(reason as u16) {
            counters.record(reason);
        }
    }
    for reason in ALL_DROP_REASONS {
        assert_eq!(
            counters.count(reason),
            u64::from(reason as u16),
            "{reason:?}"
        );
    }
    assert_eq!(counters.unclassified(), 0);
    assert_eq!(counters.total(), (1..=u64::from(max)).sum::<u64>());

    let mut visited = Collect::default();
    counters.visit_fields(&mut visited);
    let expected: Vec<_> = ALL_DROP_REASONS
        .iter()
        .map(|r| ("drop", r.code(), FieldValue::Count(u64::from(*r as u16))))
        .chain([("drop", "UNCLASSIFIED", FieldValue::Count(0))])
        .collect();
    assert_eq!(visited.0, expected, "ascending stable code order");
}

#[test]
fn consume_reason_counters_cover_every_core_reason() {
    let scanned = scan_enum(include_str!("../../../core/src/io.rs"), "ConsumeReason");
    let listed: Vec<(String, Option<u16>)> = ALL_CONSUME_REASONS
        .iter()
        .map(|reason| (format!("{reason:?}"), None))
        .collect();
    assert_eq!(scanned, listed, "every core ConsumeReason is listed");

    let mut counters = ConsumeReasonCounters::default();
    for (index, reason) in ALL_CONSUME_REASONS.into_iter().enumerate() {
        for _ in 0..=index {
            counters.record(reason);
        }
    }
    assert_eq!(counters.count(ConsumeReason::ArpControl), 1);
    assert_eq!(counters.count(ConsumeReason::Ipv4LocalUnsupported), 2);
    assert_eq!((counters.unclassified, counters.total()), (0, 3));
}

#[test]
fn phase_skip_counters_cover_every_skip_reason() {
    let mut observer = TickObserver::default();
    let mut slots = Vec::new();
    let mut labels = Vec::new();
    for (index, reason) in TICK_PHASE_SKIPS.into_iter().enumerate() {
        let (slot, label) = phase_skip_slot(reason);
        slots.push(slot);
        labels.push(label);
        for _ in 0..=index {
            observer.record_tick_phase(TickPhaseTrace::PhaseSkipped {
                phase: crate::TickPhase::Rx,
                reason,
            });
        }
    }
    assert_eq!(slots, (0..PHASE_SKIP_KINDS).collect::<Vec<_>>());
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), PHASE_SKIP_KINDS);
    let skips = observer.snapshot(MonotonicMillis(0)).phase_skips;
    for (index, reason) in TICK_PHASE_SKIPS.into_iter().enumerate() {
        assert_eq!(skips.count(reason), index as u64 + 1);
    }
}

#[test]
fn observability_counters_saturate_instead_of_wrapping() {
    let mut drops = DropReasonCounters::default();
    drops.counts[usize::from(DropReason::RouteMiss as u16)] = u64::MAX - 1;
    drops.unclassified = u64::MAX;
    drops.record(DropReason::RouteMiss);
    drops.record(DropReason::RouteMiss);
    assert_eq!(drops.count(DropReason::RouteMiss), u64::MAX);
    assert_eq!(drops.total(), u64::MAX);

    let mut consumes = ConsumeReasonCounters {
        arp_control: u64::MAX,
        ipv4_local_unsupported: u64::MAX,
        unclassified: 0,
    };
    consumes.record(ConsumeReason::ArpControl);
    assert_eq!(
        (consumes.arp_control, consumes.total()),
        (u64::MAX, u64::MAX)
    );

    let mut generated = GeneratedTotals {
        sessions: u64::MAX - 1,
        ..GeneratedTotals::default()
    };
    generated.add(&GeneratedAccounting {
        sessions: usize::MAX,
        tx_accepted: usize::MAX,
        ..GeneratedAccounting::default()
    });
    assert_eq!(
        (generated.sessions, generated.tx_accepted),
        (u64::MAX, u64::MAX)
    );

    let mut flushed = ApplyFlushCounts {
        firewall_flows: u64::MAX,
        ..ApplyFlushCounts::default()
    };
    flushed.accumulate(&ApplyFlushCounts {
        firewall_flows: 7,
        nat44_udp_peers: 3,
        ..ApplyFlushCounts::default()
    });
    assert_eq!(
        (flushed.firewall_flows, flushed.nat44_udp_peers),
        (u64::MAX, 3)
    );

    let mut observer = TickObserver::default();
    observer.totals.ticks = u64::MAX;
    observer.totals.rx.received = u64::MAX - 1;
    observer.health.consecutive_backend_io_failures = u64::MAX;
    observer.observe_tick(
        MonotonicMillis(1),
        None,
        &rx_report(batch(usize::MAX, None)),
    );
    let snapshot = observer.snapshot(MonotonicMillis(1));
    assert_eq!(snapshot.totals.ticks, u64::MAX);
    assert_eq!(snapshot.totals.rx.received, u64::MAX);
    assert_eq!(snapshot.health.consecutive_backend_io_failures, 0);
    observer.health.consecutive_backend_io_failures = u64::MAX;
    observer.observe_tick(
        MonotonicMillis(2),
        None,
        &rx_report(RxPhaseReport::ReceiveFailed(())),
    );
    let snapshot = observer.snapshot(MonotonicMillis(2));
    assert_eq!(snapshot.health.consecutive_backend_io_failures, u64::MAX);
}

type Report = TickReport<&'static str, &'static str, (), ()>;

fn batch(received: usize, error: Option<()>) -> RxPhaseReport<()> {
    RxPhaseReport::Completed(BatchReport {
        received,
        tx_requested: received,
        dropped: 0,
        consumed: 0,
        completion: BatchCompletion {
            tx_requested: received,
            tx_accepted: received,
            tx_rejected: 0,
            recycled: 0,
            error,
        },
    })
}

fn generated<S>(stop: S) -> PhaseReport<GeneratedPhaseReport<S>, core::convert::Infallible> {
    PhaseReport::Completed(GeneratedPhaseReport {
        accounting: GeneratedAccounting::default(),
        stop,
    })
}

fn rx_report(rx: RxPhaseReport<()>) -> Report {
    TickReport {
        publication: PublicationOutcome::Unchanged,
        active: true,
        rx,
        resolution_timers: PhaseReport::Completed(ResolutionTimerReport::default()),
        failure_dispatch: PhaseReport::Completed(ResolutionFailureDispatchReport::default()),
        generated_arp: generated(GeneratedArpStop::QueueEmpty),
        generated_icmpv4: generated(GeneratedIcmpv4Stop::QueueEmpty),
    }
}

fn healthy() -> Report {
    rx_report(batch(0, None))
}

fn state(observer: &TickObserver, now: u64) -> HealthState {
    observer.snapshot(MonotonicMillis(now)).state
}

#[test]
fn health_transitions_follow_tick_outcomes_and_injected_time() {
    let policy = HealthPolicy {
        stale_after_ms: 100,
    };
    let mut observer = TickObserver::new(policy);
    assert_eq!(state(&observer, 0), HealthState::NotStarted);
    assert!(!observer
        .snapshot(MonotonicMillis(0))
        .health
        .alive(MonotonicMillis(0), policy));

    observer.observe_tick(MonotonicMillis(10), None, &rx_report(batch(2, None)));
    let snapshot = observer.snapshot(MonotonicMillis(10));
    assert_eq!(snapshot.state, HealthState::Healthy);
    assert_eq!(
        snapshot.health.last_successful_tick,
        Some(MonotonicMillis(10))
    );
    assert_eq!(snapshot.health.last_rx_progress, Some(MonotonicMillis(10)));
    assert_eq!(snapshot.health.last_tx_progress, Some(MonotonicMillis(10)));
    assert_eq!(state(&observer, 110), HealthState::Healthy);
    assert_eq!(state(&observer, 111), HealthState::Stale);
    assert!(snapshot.health.alive(MonotonicMillis(110), policy));
    assert!(!snapshot.health.alive(MonotonicMillis(111), policy));

    // An idle successful tick keeps health but not RX/TX progress.
    observer.observe_tick(MonotonicMillis(20), None, &healthy());
    let snapshot = observer.snapshot(MonotonicMillis(20));
    assert_eq!(snapshot.health.last_rx_progress, Some(MonotonicMillis(10)));
    assert_eq!(
        snapshot.health.last_successful_tick,
        Some(MonotonicMillis(20))
    );

    // Consecutive backend I/O failures degrade until an attempted I/O
    // tick succeeds.
    observer.observe_tick(
        MonotonicMillis(30),
        None,
        &rx_report(RxPhaseReport::ReceiveFailed(())),
    );
    observer.observe_tick(MonotonicMillis(31), None, &rx_report(batch(1, Some(()))));
    let snapshot = observer.snapshot(MonotonicMillis(31));
    assert_eq!(snapshot.state, HealthState::Degraded);
    assert_eq!(snapshot.health.consecutive_backend_io_failures, 2);
    assert_eq!(snapshot.health.backend_io_failures, 2);
    assert_eq!(snapshot.totals.rx.receive_failures, 1);
    assert_eq!(snapshot.totals.rx.finish_errors, 1);
    assert_eq!(
        snapshot.health.last_successful_tick,
        Some(MonotonicMillis(20))
    );
    observer.observe_tick(MonotonicMillis(32), None, &healthy());
    let snapshot = observer.snapshot(MonotonicMillis(32));
    assert_eq!(snapshot.state, HealthState::Healthy);
    assert_eq!(snapshot.health.consecutive_backend_io_failures, 0);

    // Generated allocation backpressure is not a failure; a build error is.
    let mut backpressure = healthy();
    backpressure.generated_arp = generated(GeneratedArpStop::Failed(GeneratedArpFailure {
        allocation: Some(GeneratedAllocationError::Unavailable),
        build: None,
        finish: None,
    }));
    observer.observe_tick(MonotonicMillis(33), None, &backpressure);
    assert_eq!(state(&observer, 33), HealthState::Healthy);
    let mut build = healthy();
    build.generated_arp = generated(GeneratedArpStop::Failed(GeneratedArpFailure {
        allocation: None,
        build: Some(ruster_core::ArpRequestBuildError::ExactLengthRequired),
        finish: None,
    }));
    observer.observe_tick(MonotonicMillis(34), None, &build);
    assert_eq!(state(&observer, 34), HealthState::Degraded);
    assert_eq!(
        observer
            .snapshot(MonotonicMillis(34))
            .totals
            .generated_arp
            .failures,
        2
    );

    // No active publication degrades.
    let mut inactive = healthy();
    inactive.active = false;
    observer.observe_tick(MonotonicMillis(35), None, &inactive);
    assert_eq!(state(&observer, 35), HealthState::Degraded);

    // Quiescence deferrals count consecutively; `Stop` is terminal.
    let deferred = |disposition| Report {
        publication: PublicationOutcome::Deferred {
            error: "busy",
            disposition,
        },
        ..healthy()
    };
    observer.observe_tick(
        MonotonicMillis(36),
        None,
        &deferred(PublicationQuiescenceDisposition::ContinueOldIo),
    );
    assert_eq!(state(&observer, 36), HealthState::Healthy);
    observer.observe_tick(
        MonotonicMillis(37),
        None,
        &deferred(PublicationQuiescenceDisposition::Stop),
    );
    let snapshot = observer.snapshot(MonotonicMillis(37));
    assert_eq!(snapshot.health.quiescence_deferrals, 2);
    assert_eq!(snapshot.health.consecutive_quiescence_deferrals, 2);
    assert_eq!(snapshot.totals.publications_deferred, 2);
    assert_eq!(
        snapshot.last_apply.map(|last| last.outcome),
        Some(ApplyOutcomeKind::Deferred)
    );
    assert_eq!(snapshot.state, HealthState::Stopped);
    observer.observe_tick(MonotonicMillis(38), None, &healthy());
    assert_eq!(state(&observer, 38), HealthState::Stopped, "stop is sticky");
}

#[test]
fn clock_regression_is_flagged_without_moving_health_time_backwards() {
    let mut observer = TickObserver::default();
    observer.observe_tick(MonotonicMillis(100), None, &healthy());
    observer.observe_tick(MonotonicMillis(40), None, &healthy());
    let snapshot = observer.snapshot(MonotonicMillis(100));
    assert_eq!(snapshot.health.clock_regressions, 1);
    assert_eq!(snapshot.health.last_tick, Some(MonotonicMillis(100)));
    assert_eq!(
        snapshot.health.last_successful_tick,
        Some(MonotonicMillis(100))
    );
    assert_eq!(snapshot.state, HealthState::Degraded);

    // Equal time is not a regression and recovers.
    observer.observe_tick(MonotonicMillis(100), None, &healthy());
    assert_eq!(state(&observer, 100), HealthState::Healthy);

    // A runtime-reported regression (timer phase) is counted separately.
    let mut runtime = healthy();
    runtime.resolution_timers = PhaseReport::Failed(ResolutionTimerError::ClockRegression);
    runtime.failure_dispatch = PhaseReport::Skipped(TickPhaseSkip::ClockRegression);
    observer.observe_tick(MonotonicMillis(101), None, &runtime);
    let snapshot = observer.snapshot(MonotonicMillis(101));
    assert_eq!(snapshot.health.clock_regressions, 1);
    assert_eq!(snapshot.health.runtime_clock_regressions, 1);
    assert_eq!(snapshot.state, HealthState::Degraded);
}

#[test]
fn generation_and_apply_outcome_are_reflected_once() {
    let one = NonZeroU64::MIN;
    let two = NonZeroU64::new(2).unwrap();
    let mut observer = TickObserver::default();
    observer.observe_tick(MonotonicMillis(1), Some(one), &healthy());
    let snapshot = observer.snapshot(MonotonicMillis(1));
    assert_eq!(
        (snapshot.generation, snapshot.generation_changes),
        (Some(one), 0)
    );
    assert_eq!(snapshot.last_apply, None);

    let flush = ApplyFlushCounts::from_reports(
        ResolutionPublicationReport {
            states_flushed: 1,
            actions_flushed: 2,
            dynamic_neighbors_flushed: 3,
            failure_holds_flushed: 4,
        },
        Icmpv4ErrorPublicationReport {
            states_flushed: 5,
            actions_flushed: 6,
        },
        Nat44UdpReconcileReport {
            mappings_flushed: 7,
            peers_flushed: 8,
        },
        Nat44TcpReconcileReport {
            mappings_flushed: 9,
            sessions_flushed: 10,
        },
        FirewallReconcileReport { states_flushed: 11 },
    );
    assert_eq!(
        flush,
        ApplyFlushCounts {
            resolution_states: 1,
            resolution_actions: 2,
            dynamic_neighbors: 3,
            failure_holds: 4,
            icmpv4_error_states: 5,
            icmpv4_error_actions: 6,
            nat44_udp_mappings: 7,
            nat44_udp_peers: 8,
            nat44_tcp_mappings: 9,
            nat44_tcp_sessions: 10,
            firewall_flows: 11,
        }
    );
    assert!(
        !observer.record_apply_flush(one, flush),
        "no apply observed yet"
    );

    let applied = Report {
        publication: PublicationOutcome::Applied,
        ..healthy()
    };
    observer.observe_tick(MonotonicMillis(2), Some(two), &applied);
    assert!(!observer.record_apply_flush(one, flush), "wrong generation");
    assert!(observer.record_apply_flush(two, flush));
    assert!(!observer.record_apply_flush(two, flush), "no double count");
    let snapshot = observer.snapshot(MonotonicMillis(2));
    assert_eq!(
        (snapshot.generation, snapshot.generation_changes),
        (Some(two), 1)
    );
    assert_eq!(
        snapshot.last_apply,
        Some(LastApply {
            outcome: ApplyOutcomeKind::Applied,
            at: MonotonicMillis(2),
            generation: Some(two),
            flush: Some(flush),
        })
    );
    assert_eq!(snapshot.flushed, flush);
    assert_eq!(snapshot.totals.publications_applied, 1);

    let rejected = Report {
        publication: PublicationOutcome::Rejected("stale"),
        ..healthy()
    };
    observer.observe_tick(MonotonicMillis(3), Some(two), &rejected);
    assert!(
        !observer.record_apply_flush(two, flush),
        "rejected apply flushes nothing"
    );
    let snapshot = observer.snapshot(MonotonicMillis(3));
    assert_eq!(
        snapshot.last_apply.map(|last| last.outcome),
        Some(ApplyOutcomeKind::Rejected)
    );
    assert_eq!(snapshot.last_apply.and_then(|last| last.flush), None);
    assert_eq!((snapshot.generation_changes, snapshot.flushed), (1, flush));
    assert_eq!(snapshot.totals.publications_rejected, 1);
    assert_eq!(
        snapshot.state,
        HealthState::Healthy,
        "old generation continues"
    );
}

#[test]
fn snapshot_rendering_is_stable_and_ordered() {
    let mut observer = TickObserver::default();
    observer.drops.record(DropReason::RouteMiss);
    observer.drops.record(DropReason::EthernetHeaderTruncated);
    observer.observe_tick(MonotonicMillis(5), Some(NonZeroU64::MIN), &healthy());
    let snapshot = observer.snapshot(MonotonicMillis(5));
    let text = FieldsDisplay(&snapshot).to_string();
    assert_eq!(text, FieldsDisplay(&snapshot).to_string());
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        &lines[..4],
        [
            "observer.taken_at=5",
            "observer.state=healthy",
            "observer.generation=1",
            "observer.generation_changes=0",
        ]
    );
    let truncated = lines
        .iter()
        .position(|line| *line == "drop.ETHERNET_HEADER_TRUNCATED=1")
        .unwrap();
    assert_eq!(lines[truncated + 1], "drop.ROUTE_MISS=1");
    assert_eq!(lines[truncated + 2], "drop.UNCLASSIFIED=0");
    assert!(lines.contains(&"apply.outcome=none"));
    assert!(lines.contains(&"health.last_rx_progress=none"));
    assert_eq!(lines.last(), Some(&"flushed.firewall_flows=0"));
    let mut keys: Vec<&str> = lines.iter().map(|l| l.split_once('=').unwrap().0).collect();
    let count = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), count, "keys are unique");
}

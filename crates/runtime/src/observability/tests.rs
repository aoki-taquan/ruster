use super::*;
use crate::{GeneratedArpFailure, GeneratedPhaseReport};
use ruster_core::{
    BatchCompletion, BatchReport, ResolutionFailureDispatchReport, ResolutionTimerError,
    ResolutionTimerReport,
};

#[derive(Default)]
struct Collect(Vec<(&'static str, &'static str, FieldValue)>);

impl FieldVisitor for Collect {
    fn field(&mut self, section: &'static str, key: &'static str, value: FieldValue) {
        self.0.push((section, key, value));
    }
}

/// Completeness of `DropReason::ALL` against the declaration is enforced in
/// core (`drop_reason_all_lists_every_declared_variant_in_order` and a const
/// contiguity check); this test proves the runtime table indexes all of it.
#[test]
fn drop_reason_counters_index_every_stable_core_reason() {
    assert_eq!(DROP_REASON_CODE_LIMIT, DropReason::ALL.len() + 1);
    let mut counters = DropReasonCounters::default();
    for reason in DropReason::ALL {
        for _ in 0..(reason as u16) {
            counters.record(reason);
        }
    }
    for reason in DropReason::ALL {
        assert_eq!(
            counters.count(reason),
            u64::from(reason as u16),
            "{reason:?}"
        );
    }
    assert_eq!(counters.unclassified(), 0);
    let max = DropReason::ALL.len() as u64;
    assert_eq!(counters.total(), (1..=max).sum::<u64>());

    let mut visited = Collect::default();
    counters.visit_fields(&mut visited);
    let expected: Vec<_> = DropReason::ALL
        .iter()
        .map(|r| ("drop", r.code(), FieldValue::Count(u64::from(*r as u16))))
        .chain([("drop", "UNCLASSIFIED", FieldValue::Count(0))])
        .collect();
    assert_eq!(visited.0, expected, "ascending stable code order");

    // Zero counts are rendered too, so the shape is traffic independent.
    let mut empty = Collect::default();
    DropReasonCounters::default().visit_fields(&mut empty);
    let keys = |c: &Collect| c.0.iter().map(|(_, key, _)| *key).collect::<Vec<_>>();
    assert_eq!(keys(&empty), keys(&visited));
}

#[test]
fn consume_reason_counters_cover_every_core_reason() {
    let mut counters = ConsumeReasonCounters::default();
    for reason in ConsumeReason::ALL {
        for _ in 0..=reason.index() {
            counters.record(reason);
        }
    }
    assert_eq!(counters.count(ConsumeReason::ArpControl), 1);
    assert_eq!(counters.count(ConsumeReason::Ipv4LocalUnsupported), 2);
    assert_eq!(counters.total(), 3);
    let mut visited = Collect::default();
    ConsumeReasonCounters::default().visit_fields(&mut visited);
    let expected: Vec<_> = ConsumeReason::ALL
        .iter()
        .map(|r| ("consume", r.code(), FieldValue::Count(0)))
        .chain([("consume", "UNCLASSIFIED", FieldValue::Count(0))])
        .collect();
    assert_eq!(visited.0, expected);
    assert_eq!(counters.unclassified(), 0);
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
        counts: [u64::MAX; ConsumeReason::ALL.len()],
        unclassified: 0,
    };
    consumes.record(ConsumeReason::ArpControl);
    assert_eq!(
        (consumes.count(ConsumeReason::ArpControl), consumes.total()),
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

    // A worker that stops ticking after a failed tick reads Stale, not
    // Degraded, once the policy window elapses.
    assert_eq!(state(&observer, 134), HealthState::Degraded);
    assert_eq!(state(&observer, 135), HealthState::Stale);

    // No active publication (pre-activation) degrades: alive, not started.
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
    // Candidate-free ticks between attempts neither count nor reset.
    observer.observe_tick(MonotonicMillis(37), None, &healthy());
    let snapshot = observer.snapshot(MonotonicMillis(37));
    assert_eq!(snapshot.health.consecutive_quiescence_deferrals, 2);
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
            active_generation: Some(two),
            flush: Some(flush),
        })
    );
    assert_eq!(snapshot.flushed, flush);
    assert_eq!(snapshot.totals.publications_applied, 1);
    assert_eq!(snapshot.totals.apply_flushes_recorded, 1);

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
        snapshot.last_apply.and_then(|last| last.active_generation),
        Some(two),
        "a rejected attempt reports the still-active generation"
    );
    assert_eq!(
        snapshot.state,
        HealthState::Healthy,
        "old generation continues"
    );
}

#[test]
fn missed_apply_flush_is_exposed_by_recorded_counter() {
    let three = NonZeroU64::new(3).unwrap();
    let four = NonZeroU64::new(4).unwrap();
    let applied = || Report {
        publication: PublicationOutcome::Applied,
        ..healthy()
    };
    let mut observer = TickObserver::default();
    // Back-to-back applies without recording the first flush in between.
    observer.observe_tick(MonotonicMillis(1), Some(three), &applied());
    observer.observe_tick(MonotonicMillis(2), Some(four), &applied());
    let flush = ApplyFlushCounts {
        firewall_flows: 1,
        ..ApplyFlushCounts::default()
    };
    assert!(!observer.record_apply_flush(three, flush), "too late");
    assert!(observer.record_apply_flush(four, flush));
    let totals = observer.snapshot(MonotonicMillis(2)).totals;
    assert_eq!(
        (totals.publications_applied, totals.apply_flushes_recorded),
        (2, 1)
    );
    assert_eq!(
        totals.publications_applied - totals.apply_flushes_recorded,
        1,
        "the lost flush is visible, not silent"
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
    assert_eq!(lines[truncated + 1], "drop.UNSUPPORTED_ETHERTYPE=0");
    let unclassified = truncated + DropReason::ALL.len();
    assert_eq!(lines[unclassified], "drop.UNCLASSIFIED=0");
    assert!(lines.contains(&"drop.ROUTE_MISS=1"));
    assert!(lines.contains(&"apply.outcome=none"));
    assert!(lines.contains(&"apply.flush_recorded=false"));
    assert!(lines.contains(&"apply.flush.firewall_flows=0"));
    assert!(lines.contains(&"health.last_rx_progress=none"));
    assert_eq!(lines.last(), Some(&"flushed.firewall_flows=0"));
    let keys = |text: &str| -> Vec<String> {
        text.lines()
            .map(|l| l.split_once('=').unwrap().0.to_owned())
            .collect()
    };
    let mut unique = keys(&text);
    let count = unique.len();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), count, "keys are unique");

    // The key sequence is fixed: an idle observer and one after an applied,
    // flush-recorded tick render exactly the same keys in the same order.
    let idle = FieldsDisplay(&TickObserver::default().snapshot(MonotonicMillis(0))).to_string();
    let two = NonZeroU64::new(2).unwrap();
    let applied = Report {
        publication: PublicationOutcome::Applied,
        ..healthy()
    };
    observer.observe_tick(MonotonicMillis(6), Some(two), &applied);
    assert!(observer.record_apply_flush(two, ApplyFlushCounts::default()));
    let busy = FieldsDisplay(&observer.snapshot(MonotonicMillis(6))).to_string();
    assert!(busy.contains("apply.flush_recorded=true\n"));
    assert_eq!(keys(&idle), keys(&busy));
    assert_eq!(keys(&idle), keys(&text));
}

/// io-sim implements the core-defined trait, so a runtime unit test sees the
/// same `BackendStats` (no dev-dependency cycle duplicating this crate).
#[test]
fn sim_io_satisfies_backend_stats_in_runtime_unit_tests() {
    fn stats<T: crate::BackendStats>(backend: &T) -> T::Stats {
        backend.backend_stats()
    }
    assert_eq!(stats(&ruster_io_sim::SimIo::new()).injected, 0);
}

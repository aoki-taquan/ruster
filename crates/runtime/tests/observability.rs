mod observability_support;

use std::{collections::BTreeMap, num::NonZeroU64};

use observability_support::*;
use ruster_core::{
    ConsumeReason, DirectoryBucket, DropReason, FirewallRuntime, FirewallStateSlot,
    ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime,
    Icmpv4ErrorStateSlot, MonotonicMillis, Nat44TcpHashKey, Nat44TcpIndexStorage, Nat44TcpRuntime,
    Nat44UdpHashKey, Nat44UdpIndexStorage, Nat44UdpRuntime, PortOwnerSlot,
    PublicationQuiescenceDisposition, ResolutionActionSlot, ResolutionFailureHoldSlot,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot,
};
use ruster_io_sim::{RecycleCause, SimIo, SimIoStats};
use ruster_runtime::{
    run_tick, ApplyOutcomeKind, BackendMode, BackendStats, FieldsDisplay, HealthState,
    PublicationOutcome, ServiceCounters, ServiceOccupancy, TickBudgets, TickObserver,
};

const BUDGETS: TickBudgets = TickBudgets {
    rx: 16,
    resolution_timer_scans: 4,
    failure_dispatch_scans: 4,
    generated_arp: 4,
    generated_icmpv4: 4,
};

#[test]
fn sim_tick_observer_counts_match_backend_recycle_causes() {
    let routes = routes();
    let snapshot = ForwardingSnapshot::new(&routes, &INTERFACES, &[], &BINDINGS).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut states,
        &mut actions,
        &mut [],
        &mut holds,
    );
    let mut icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 2];
    let mut icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
    let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut icmp_states,
        &mut icmp_actions,
    );
    let mut publication = Publication {
        generation: NonZeroU64::MIN,
        snapshot: &snapshot,
        resolution: &mut resolution,
        icmpv4_errors: &mut icmpv4_errors,
        udp_config: udp_config(&snapshot),
        tcp_config: tcp_config(&snapshot),
        firewall_config: firewall_config(&snapshot),
    };
    let mut io = SimIo::new();
    let mut observer = TickObserver::default();
    for frame in [
        truncated_ethernet(),
        unsupported_ethertype(),
        unsupported_ethertype(),
        bad_ipv4_checksum(),
        local_udp(),
        local_udp(),
        local_udp(),
        echo_request(),
    ] {
        io.inject(LAN, frame);
    }
    assert_eq!(
        io.backend_stats(),
        SimIoStats {
            injected: 8,
            pending_rx: 8,
            rx_high_watermark: 8,
            ..SimIoStats::default()
        }
    );

    let now = MonotonicMillis(10);
    let report = run_tick(&mut publication, None, &mut io, now, BUDGETS, &mut observer);
    observer.observe_tick(now, Some(publication.generation), &report);
    let snapshot = observer.snapshot(now);
    assert_eq!(
        io.backend_stats(),
        SimIoStats {
            injected: 8,
            pending_tx: 1,
            pending_recycled: 7,
            rx_high_watermark: 8,
            tx_high_watermark: 1,
            ..SimIoStats::default()
        }
    );

    let mut drops = BTreeMap::new();
    let mut consumes = BTreeMap::new();
    while let Some(frame) = io.pop_recycled() {
        match frame.cause {
            RecycleCause::Forwarding(reason) => *drops.entry(reason as u16).or_insert(0) += 1,
            RecycleCause::Consumed(reason) => {
                *consumes.entry(format!("{reason:?}")).or_insert(0) += 1
            }
            cause => panic!("unexpected recycle cause {cause:?}"),
        }
    }
    assert_eq!(
        drops,
        BTreeMap::from([
            (DropReason::EthernetHeaderTruncated as u16, 1),
            (DropReason::UnsupportedEtherType as u16, 2),
            (DropReason::Ipv4HeaderChecksumInvalid as u16, 1),
        ])
    );
    assert_eq!(
        consumes,
        BTreeMap::from([("Ipv4LocalUnsupported".to_owned(), 3)])
    );
    for reason in [
        DropReason::EthernetHeaderTruncated,
        DropReason::UnsupportedEtherType,
        DropReason::Ipv4HeaderChecksumInvalid,
    ] {
        assert_eq!(snapshot.drops.count(reason), drops[&(reason as u16)]);
    }
    assert_eq!(snapshot.drops.total(), 4);
    assert_eq!(
        snapshot.consumes.count(ConsumeReason::Ipv4LocalUnsupported),
        3
    );
    assert_eq!(snapshot.consumes.total(), 3);

    let rx = snapshot.totals.rx;
    assert_eq!((rx.received, rx.dropped, rx.consumed), (8, 4, 3));
    assert_eq!((rx.tx_requested, rx.tx_accepted, rx.recycled), (1, 1, 7));
    assert_eq!(snapshot.state, HealthState::Healthy);
    assert_eq!(snapshot.health.last_rx_progress, Some(now));
    assert_eq!(snapshot.health.last_tx_progress, Some(now));
    assert_eq!(snapshot.generation, Some(NonZeroU64::MIN));

    // The echo reply is still awaiting TX completion, so a candidate is
    // deferred while the old publication continues.
    let two = NonZeroU64::new(2).unwrap();
    let later = MonotonicMillis(11);
    let report = run_tick(
        &mut publication,
        Some(two),
        &mut io,
        later,
        BUDGETS,
        &mut observer,
    );
    observer.observe_tick(later, Some(publication.generation), &report);
    let deferred = observer.snapshot(later);
    assert!(matches!(
        report.publication,
        PublicationOutcome::Deferred {
            disposition: PublicationQuiescenceDisposition::ContinueOldIo,
            ..
        }
    ));
    assert_eq!(deferred.health.quiescence_deferrals, 1);
    assert_eq!(
        deferred.last_apply.map(|l| l.outcome),
        Some(ApplyOutcomeKind::Deferred)
    );
    assert_eq!(deferred.generation, Some(NonZeroU64::MIN));

    // Once TX completes, the candidate applies; a stale one is rejected.
    assert!(io.pop_tx().is_some());
    let drained = io.backend_stats();
    assert_eq!((drained.pending_tx, drained.tx_high_watermark), (0, 1));
    assert_eq!((drained.pending_rx, drained.rx_high_watermark), (0, 8));
    let apply = MonotonicMillis(12);
    let report = run_tick(
        &mut publication,
        Some(two),
        &mut io,
        apply,
        BUDGETS,
        &mut observer,
    );
    observer.observe_tick(apply, Some(publication.generation), &report);
    let reject = MonotonicMillis(13);
    let report = run_tick(
        &mut publication,
        Some(two),
        &mut io,
        reject,
        BUDGETS,
        &mut observer,
    );
    assert_eq!(
        report.publication,
        PublicationOutcome::Rejected("generation not increasing")
    );
    let after_apply = observer.snapshot(apply);
    observer.observe_tick(reject, Some(publication.generation), &report);
    let after_reject = observer.snapshot(reject);
    assert_eq!(
        after_apply.last_apply.map(|l| l.outcome),
        Some(ApplyOutcomeKind::Applied)
    );
    assert_eq!(after_apply.generation, Some(two));
    assert_eq!(after_apply.health.consecutive_quiescence_deferrals, 0);
    assert_eq!(
        after_reject.last_apply.map(|l| l.outcome),
        Some(ApplyOutcomeKind::Rejected)
    );
    assert_eq!(
        (after_reject.generation, after_reject.generation_changes),
        (Some(two), 1)
    );
    let totals = after_reject.totals;
    assert_eq!(
        (
            totals.publications_applied,
            totals.publications_rejected,
            totals.publications_deferred,
        ),
        (1, 1, 1)
    );
    assert_eq!((totals.ticks, totals.successful_ticks), (4, 4));
}

#[test]
fn sim_io_backend_stats_expose_fixed_occupancy() {
    assert_eq!(<SimIo as BackendStats>::NAME, "sim");
    assert_eq!(<SimIo as BackendStats>::MODE, BackendMode::Simulated);
    assert_eq!(BackendMode::Simulated.label(), "simulated");

    let mut io = SimIo::new();
    io.inject(LAN, truncated_ethernet());
    io.inject(LAN, truncated_ethernet());
    io.inject(LAN, truncated_ethernet());
    let stats = io.backend_stats();
    assert_eq!(
        stats,
        SimIoStats {
            injected: 3,
            pending_rx: 3,
            rx_high_watermark: 3,
            ..SimIoStats::default()
        }
    );
    assert_eq!(
        FieldsDisplay(&stats).to_string(),
        "backend.sim.injected=3\n\
         backend.sim.pending_rx=3\n\
         backend.sim.pending_tx=0\n\
         backend.sim.pending_recycled=0\n\
         backend.sim.pending_generated_recycled=0\n\
         backend.sim.rx_leases_live=0\n\
         backend.sim.generated_leases_live=0\n\
         backend.sim.rx_high_watermark=3\n\
         backend.sim.tx_high_watermark=0\n\
         backend.sim.batch_open=false\n"
    );
}

/// Runs `test` with one runtime of every service over empty or one-slot
/// storage.
fn with_service_runtimes(
    test: impl FnOnce(
        &ResolutionRuntime<'_>,
        &Icmpv4ErrorRuntime<'_>,
        &Nat44UdpRuntime<'_>,
        &Nat44TcpRuntime<'_>,
        &FirewallRuntime<'_>,
    ),
) {
    let routes = routes();
    let snapshot = ForwardingSnapshot::new(&routes, &INTERFACES, &[], &BINDINGS).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut states,
        &mut actions,
        &mut [],
        &mut [],
    );
    let mut icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let icmpv4_errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut icmp_states,
        &mut icmp_actions,
    );
    let mut udp_owner = [PortOwnerSlot::default(); 1];
    let mut tcp_owner = [PortOwnerSlot::default(); 1];
    let no_buckets: &mut [DirectoryBucket] = &mut [];
    let nat44_udp = Nat44UdpRuntime::new(
        udp_config(&snapshot),
        &mut [],
        &mut [],
        Nat44UdpIndexStorage::new(no_buckets, &mut [], &mut [], &mut [], &mut udp_owner),
        Nat44UdpHashKey::new(3, 4).unwrap(),
    )
    .unwrap();
    let nat44_tcp = Nat44TcpRuntime::new(
        tcp_config(&snapshot),
        &mut [],
        &mut [],
        Nat44TcpIndexStorage::new(
            &mut [],
            &mut [],
            &mut [],
            &mut [],
            &mut [],
            &mut [],
            &mut tcp_owner,
        ),
        Nat44TcpHashKey::new(5, 6).unwrap(),
    )
    .unwrap();
    let mut firewall_states = [FirewallStateSlot::default(); 4];
    let firewall = FirewallRuntime::new(firewall_config(&snapshot), &mut firewall_states);
    test(
        &resolution,
        &icmpv4_errors,
        &nat44_udp,
        &nat44_tcp,
        &firewall,
    );
}

#[test]
fn service_occupancy_capture_copies_every_runtime_accessor() {
    with_service_runtimes(|_, icmpv4_errors, nat44_udp, nat44_tcp, firewall| {
        let occupancy = ServiceOccupancy::capture(icmpv4_errors, nat44_udp, nat44_tcp, firewall);
        let udp = nat44_udp.occupancy();
        let tcp = nat44_tcp.occupancy();
        assert_eq!(
            occupancy,
            ServiceOccupancy {
                nat44_udp_mappings: udp.mappings,
                nat44_udp_peers: udp.peers,
                nat44_tcp_mappings: tcp.mappings,
                nat44_tcp_sessions: tcp.sessions,
                nat44_tcp_external_inbound_sessions: tcp.external_inbound_sessions,
                firewall_states: firewall.occupancy(),
                icmpv4_error_states: icmpv4_errors.state_occupancy(),
            }
        );
        // Capacities come from each runtime's own storage shape.
        assert_eq!(occupancy.icmpv4_error_states.capacity(), 1);
        assert_eq!(
            occupancy.firewall_states.capacity(),
            firewall.usable_capacity()
        );
        assert_eq!(occupancy.firewall_states.capacity(), 3);
        assert_eq!(occupancy.nat44_udp_mappings.capacity(), 0);
        let mut observer = TickObserver::default();
        observer.record_occupancy(occupancy);
        let observed = observer.snapshot(MonotonicMillis(0)).occupancy;
        assert_eq!(observed.samples, 1);
        assert_eq!(observed.firewall_states.capacity, 3);
        assert_eq!(observed.icmpv4_error_states.capacity, 1);
    });
}

#[test]
fn service_counters_capture_every_runtime_counter_in_fixed_order() {
    with_service_runtimes(service_counters_render_in_fixed_order);
}

fn service_counters_render_in_fixed_order(
    resolution: &ResolutionRuntime<'_>,
    icmpv4_errors: &Icmpv4ErrorRuntime<'_>,
    nat44_udp: &Nat44UdpRuntime<'_>,
    nat44_tcp: &Nat44TcpRuntime<'_>,
    firewall: &FirewallRuntime<'_>,
) {
    let counters =
        ServiceCounters::capture(resolution, icmpv4_errors, nat44_udp, nat44_tcp, firewall);
    assert_eq!(counters.resolution, resolution.counters());
    assert_eq!(counters.icmpv4_errors, icmpv4_errors.counters());
    assert_eq!(counters.nat44_udp, nat44_udp.counters());
    assert_eq!(counters.nat44_tcp, nat44_tcp.counters());
    assert_eq!(counters.firewall, firewall.counters());

    let text = FieldsDisplay(&counters).to_string();
    let keys: Vec<&str> = text.lines().map(|l| l.split_once('=').unwrap().0).collect();
    let sections: Vec<&str> = keys.iter().map(|k| k.split_once('.').unwrap().0).collect();
    let mut order = sections.clone();
    order.dedup();
    assert_eq!(
        order,
        [
            "resolution",
            "icmpv4_errors",
            "nat44_udp",
            "nat44_tcp",
            "firewall"
        ]
    );
    for (section, fields) in [
        ("resolution", 13),
        ("icmpv4_errors", 31),
        ("nat44_udp", 17),
        ("nat44_tcp", 22),
        ("firewall", 13),
    ] {
        assert_eq!(sections.iter().filter(|s| **s == section).count(), fields);
    }
    let mut unique = keys.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), keys.len());
}

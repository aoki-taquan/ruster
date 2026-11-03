//! Thresholds and outcomes of the health and link watch.

use super::*;
use crate::run::engine::LinkMonitor;
use crate::run::workers::{probe_round, LinkRound, PortRound};

const PORT: IfId = IfId(1);
// The default thresholds.
const TX_STALL_WARN_MS: u64 = 1_000;
const TX_STALL_FATAL_MS: u64 = 10_000;
const KICK_ERRORS_FATAL_MS: u64 = 5_000;
const TARGET: LinkTarget = LinkTarget {
    watch_uppers: false,
    interface: PORT,
    ifindex: 7,
    name: IfName::literal(b"ra"),
    mtu: 1500,
    frame_capacity: 1792,
};

fn watch() -> Watch {
    Watch::new(&[TARGET], Thresholds::default())
}

fn run(watch: &mut Watch, at: u64, sample: PortSample) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    watch.on_sample(MonotonicMillis(at), sample, &mut |event| events.push(event));
    events
}

fn link(watch: &mut Watch, result: Result<LinkFacts, NetlinkError>) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    watch.on_link(0, result, &mut |event| events.push(event));
    events
}

fn sample() -> PortSample {
    PortSample {
        interface: PORT,
        polls: 0,
        tx_inflight: 0,
        oldest_age_polls: 0,
        kick_errors: 0,
        kick_link_down: false,
        fill_starved: 0,
        fill_ring_occupancy: 64,
        rx_packets: 0,
        device_gone: false,
    }
}

fn up(mtu: u32) -> Result<LinkFacts, NetlinkError> {
    Ok(LinkFacts {
        name: TARGET.name,
        mtu,
        rx_queues: Some(1),
        admin_up: true,
        lower_up: true,
        master: None,
    })
}

const fn warning(condition: Condition) -> WatchEvent {
    WatchEvent::Warning {
        port: PORT,
        condition,
    }
}

const fn recovered(condition: Condition) -> WatchEvent {
    WatchEvent::Recovered {
        port: PORT,
        condition,
    }
}

const fn fatal(cause: Fatal) -> WatchEvent {
    WatchEvent::Fatal { port: PORT, cause }
}

/// A saturated but healthy link: TX always in flight, the oldest frame
/// retired between samples, RX arriving, Fill sometimes empty and the
/// free list sometimes dry, no kick error. Nothing trips, for a long time.
#[test]
fn a_busy_healthy_link_never_trips_the_thresholds() {
    let mut watch = fresh();
    let mut current = sample();
    for step in 0..1_000_u64 {
        current.polls += 5_000;
        current.tx_inflight = 2_048;
        // The oldest frame is always younger than the poll delta.
        current.oldest_age_polls = 100 + step % 7;
        current.rx_packets += 10_000;
        current.fill_starved += 3;
        current.fill_ring_occupancy = step % 2;
        let events = run(&mut watch, step * HEALTH_INTERVAL_MS, current);
        assert!(events.is_empty(), "step {step}: {events:?}");
    }
    assert!(!watch.warning());
    let (_, health) = watch.health().next().expect("port");
    assert!(!health.tx_stall && !health.fill_starved && !health.kick_errors_persistent);
}

#[test]
fn a_tx_stall_warns_then_is_fatal_and_recovers_on_progress() {
    let mut watch = fresh();
    let mut stalled = PortSample {
        tx_inflight: 3,
        ..sample()
    };
    // The oldest frame was submitted at poll 100 and never completes.
    let mut at = 0;
    let mut events = Vec::new();
    while at < TX_STALL_WARN_MS {
        stalled.polls = 100 + at;
        stalled.oldest_age_polls = at;
        events.extend(run(&mut watch, at, stalled));
        at += HEALTH_INTERVAL_MS;
    }
    assert!(events.is_empty(), "{events:?}");
    stalled.polls = 100 + at;
    stalled.oldest_age_polls = at;
    assert_eq!(run(&mut watch, at, stalled), [warning(Condition::TxStall)]);
    assert!(watch.warning());
    let (_, health) = watch.health().next().expect("port");
    assert!(health.tx_stall);
    assert_eq!(health.tx_stall_ms, TX_STALL_WARN_MS);
    // The oldest frame completes: recovered.
    stalled.polls += 10;
    stalled.oldest_age_polls = 1;
    assert_eq!(
        run(&mut watch, at + 1, stalled),
        [recovered(Condition::TxStall)]
    );
    assert!(!watch.warning());
    // Unchanged again for the fatal bound.
    let start = at + 1;
    let mut fatal_seen = Vec::new();
    let mut t = start;
    while fatal_seen.is_empty() {
        t += HEALTH_INTERVAL_MS;
        stalled.polls += 10;
        stalled.oldest_age_polls += 10;
        fatal_seen = run(&mut watch, t, stalled)
            .into_iter()
            .filter(|event| matches!(event, WatchEvent::Fatal { .. }))
            .collect();
    }
    assert_eq!(fatal_seen, [fatal(Fatal::TxStall)]);
    assert_eq!(t - start, TX_STALL_FATAL_MS);
}

#[test]
fn a_down_link_holds_tx_without_a_stall() {
    let mut watch = fresh();
    let held = PortSample {
        tx_inflight: 1,
        polls: 50,
        oldest_age_polls: 10,
        kick_link_down: true,
        ..sample()
    };
    for step in 0..100 {
        let mut current = held;
        current.polls += step;
        current.oldest_age_polls += step;
        assert!(run(&mut watch, step * 1_000, current).is_empty());
    }
    // rtnetlink says down too: a warning for the link, not a stall.
    let down = Ok(LinkFacts {
        lower_up: false,
        ..up(1500).expect("facts")
    });
    assert_eq!(link(&mut watch, down), [warning(Condition::LinkDown)]);
    let mut current = PortSample {
        kick_link_down: false,
        ..held
    };
    for step in 100..200 {
        current.polls = 50 + step;
        current.oldest_age_polls = 10 + step;
        assert!(run(&mut watch, step * 1_000, current).is_empty());
    }
    // Back up: the stall clock starts from the link's return.
    assert_eq!(link(&mut watch, up(1500)), [recovered(Condition::LinkDown)]);
    let (_, health) = watch.health().next().expect("port");
    assert_eq!((health.link_down_events, health.link_up_events), (1, 1));
    for (at, expected) in [
        (200_000, None),
        (200_000 + TX_STALL_WARN_MS - 1, None),
        (
            200_000 + TX_STALL_WARN_MS,
            Some(warning(Condition::TxStall)),
        ),
    ] {
        current.polls += 1;
        current.oldest_age_polls += 1;
        assert_eq!(run(&mut watch, at, current), Vec::from_iter(expected));
    }
}

#[test]
fn fill_starvation_warns_and_recovers() {
    let mut watch = fresh();
    let mut starving = PortSample {
        fill_ring_occupancy: 0,
        ..sample()
    };
    assert!(run(&mut watch, 0, starving).is_empty(), "first sample");
    let mut events = Vec::new();
    for step in 1..=3 {
        starving.fill_starved += 1;
        events.extend(run(&mut watch, step * HEALTH_INTERVAL_MS, starving));
    }
    assert_eq!(events, [warning(Condition::FillStarved)]);
    // RX resumes: recovered.
    starving.rx_packets += 1;
    starving.fill_starved += 1;
    assert_eq!(
        run(&mut watch, 4 * HEALTH_INTERVAL_MS, starving),
        [recovered(Condition::FillStarved)]
    );
    // A dry free list while Fill still holds frames is not starvation.
    let mut events = Vec::new();
    for step in 5..20 {
        starving.fill_starved += 1;
        starving.fill_ring_occupancy = 1;
        events.extend(run(&mut watch, step * HEALTH_INTERVAL_MS, starving));
    }
    assert!(events.is_empty(), "{events:?}");
}

#[test]
fn persistent_kick_errors_warn_then_are_fatal() {
    let mut watch = fresh();
    let mut failing = sample();
    assert!(run(&mut watch, 0, failing).is_empty());
    failing.kick_errors = 1;
    assert_eq!(
        run(&mut watch, 500, failing),
        [warning(Condition::KickErrors)]
    );
    // A sample without a new error resets the clock.
    assert_eq!(
        run(&mut watch, 1_000, failing),
        [recovered(Condition::KickErrors)]
    );
    let mut events = Vec::new();
    let mut at = 1_000;
    while !events
        .iter()
        .any(|event| matches!(event, WatchEvent::Fatal { .. }))
    {
        at += 500;
        failing.kick_errors += 1;
        events.extend(run(&mut watch, at, failing));
    }
    assert_eq!(
        events,
        [warning(Condition::KickErrors), fatal(Fatal::KickErrors)]
    );
    assert_eq!(at - 1_500, KICK_ERRORS_FATAL_MS);
}

#[test]
fn device_events_have_their_documented_outcomes() {
    assert_eq!(
        link(&mut watch(), Err(NetlinkError::Kernel(-19))),
        [fatal(Fatal::DeviceRemoved)]
    );
    assert_eq!(link(&mut watch(), up(1499)), [fatal(Fatal::MtuDecreased)]);
    assert_eq!(
        link(&mut watch(), up(mtu_limit(1792) + 1)),
        [fatal(Fatal::MtuAboveFrame)]
    );
    // Raised within the bound: one warning per new value, recovered when
    // it returns.
    let mut raised = watch();
    assert!(link(&mut raised, up(1500)).is_empty());
    assert_eq!(link(&mut raised, up(1600)), [warning(Condition::MtuRaised)]);
    assert!(link(&mut raised, up(1600)).is_empty());
    assert_eq!(
        link(&mut raised, up(mtu_limit(1792))),
        [warning(Condition::MtuRaised)]
    );
    assert_eq!(
        link(&mut raised, up(1500)),
        [recovered(Condition::MtuRaised)]
    );
    let (_, health) = raised.health().next().expect("port");
    assert_eq!(health.mtu, 1500);
    // Admin down and carrier loss are both down; counted per change.
    let mut flapping = watch();
    for _ in 0..3 {
        let down = Ok(LinkFacts {
            admin_up: false,
            ..up(1500).expect("facts")
        });
        assert_eq!(link(&mut flapping, down), [warning(Condition::LinkDown)]);
        assert!(link(&mut flapping, down).is_empty());
        assert_eq!(
            link(&mut flapping, up(1500)),
            [recovered(Condition::LinkDown)]
        );
    }
    let (_, health) = flapping.health().next().expect("port");
    assert_eq!((health.link_down_events, health.link_up_events), (3, 3));
    assert!(health.link_up);
}

#[test]
fn link_query_failures_warn_then_are_fatal_in_a_row() {
    let mut watch = fresh();
    let failure = Err(NetlinkError::Errno(11));
    assert_eq!(link(&mut watch, failure), [warning(Condition::LinkProbe)]);
    assert!(link(&mut watch, failure).is_empty());
    assert_eq!(
        link(&mut watch, up(1500)),
        [recovered(Condition::LinkProbe)]
    );
    // A success resets the count: the next failures start from one.
    for _ in 1..LINK_PROBE_FAILURES_FATAL {
        let events = link(&mut watch, failure);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, WatchEvent::Fatal { .. })),
            "{events:?}"
        );
    }
    assert_eq!(link(&mut watch, failure), [fatal(Fatal::LinkUnverifiable)]);
    let (_, health) = watch.health().next().expect("port");
    assert_eq!(
        health.link_probe_errors,
        2 + u64::from(LINK_PROBE_FAILURES_FATAL)
    );
}

/// Holds the oldest frame for `duration` ms, sampling every 500 ms, and
/// returns every event.
fn stall_for(watch: &mut Watch, duration: u64) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    let mut at = 0;
    while at <= duration {
        let stalled = PortSample {
            tx_inflight: 1,
            polls: 100 + at,
            oldest_age_polls: at,
            ..sample()
        };
        events.extend(run(watch, at, stalled));
        at += HEALTH_INTERVAL_MS;
    }
    events
}

#[test]
fn health_thresholds_are_configurable_and_fatal_can_be_off() {
    // Warn only: a stall of an hour never ends the run.
    let warn_only = Thresholds::from_secs(1, 0, 0);
    assert_eq!(
        warn_only,
        Thresholds {
            tx_stall_warn_ms: 1_000,
            tx_stall_fatal_ms: None,
            kick_errors_fatal_ms: None,
        }
    );
    let mut watch = Watch::new(&[TARGET], warn_only);
    assert_eq!(
        stall_for(&mut watch, 3_600_000),
        [warning(Condition::TxStall)]
    );
    // Custom bounds: 3 s warning, 4 s fatal.
    let mut watch = Watch::new(&[TARGET], Thresholds::from_secs(3, 4, 5));
    let events = stall_for(&mut watch, 4_000);
    assert_eq!(events, [warning(Condition::TxStall), fatal(Fatal::TxStall)]);
    let mut watch = Watch::new(&[TARGET], Thresholds::from_secs(3, 4, 5));
    assert_eq!(stall_for(&mut watch, 2_500), []);
    assert_eq!(Thresholds::default(), Thresholds::from_secs(1, 10, 5));
    // Kick errors: warn only never ends the run either.
    let mut watch = Watch::new(&[TARGET], warn_only);
    let mut failing = sample();
    let mut events = run(&mut watch, 0, failing);
    for step in 1..100 {
        failing.kick_errors += 1;
        events.extend(run(&mut watch, step * 1_000, failing));
    }
    assert_eq!(events, [warning(Condition::KickErrors)]);
}

/// One link round as the loop runs it: the link query, then (if it
/// succeeded) the address dump, then the forwarding read.
fn round(
    watch: &mut Watch,
    link_result: Result<LinkFacts, NetlinkError>,
    addresses: Result<u32, NetlinkError>,
    forwarding: Result<Forwarding, ()>,
) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    let linked = link_result.is_ok();
    watch.on_link(0, link_result, &mut |event| events.push(event));
    if linked {
        watch.on_addresses(0, addresses, &mut |event| events.push(event));
    }
    watch.on_forwarding(0, forwarding, &mut |event| events.push(event));
    events
}

const OFF: Result<Forwarding, ()> = Ok(Forwarding {
    global: false,
    device: false,
    force: false,
    multicast: false,
});

/// While attached, a kernel address on a port changes nothing (XDP takes
/// every frame), so it warns, is counted, and recovers; exiting would be
/// what exposes it.
#[test]
fn kernel_addresses_on_a_port_warn_while_attached() {
    let mut watch = fresh();
    assert!(round(&mut watch, up(1500), Ok(0), OFF).is_empty());
    assert_eq!(
        round(&mut watch, up(1500), Ok(2), OFF),
        [warning(Condition::KernelIpv4Addresses)]
    );
    assert!(round(&mut watch, up(1500), Ok(2), OFF).is_empty(), "once");
    assert!(watch.warning());
    assert_eq!(
        watch.kernel_exposure(),
        KernelExposure {
            addresses: true,
            ..KernelExposure::default()
        }
    );
    let (_, health) = watch.health().next().expect("port");
    assert_eq!(health.kernel_ipv4_addresses, 2);
    assert_eq!(health.warnings, 1);
    assert_eq!(
        round(&mut watch, up(1500), Ok(0), OFF),
        [recovered(Condition::KernelIpv4Addresses)]
    );
    assert!(!watch.warning());
    assert_eq!(watch.kernel_exposure(), KernelExposure::default());
}

/// A link query that succeeds every round must not reset the failure
/// count of an address dump that fails every round (fail open otherwise).
#[test]
fn an_address_dump_failing_every_round_is_fatal_despite_link_success() {
    let mut watch = fresh();
    let failure = Err(NetlinkError::Errno(11));
    let mut events = Vec::new();
    for _ in 0..LINK_PROBE_FAILURES_FATAL {
        events.extend(round(&mut watch, up(1500), failure, OFF));
    }
    assert_eq!(
        events,
        [
            warning(Condition::LinkProbe),
            fatal(Fatal::LinkUnverifiable)
        ]
    );
    // The same for an unreadable forwarding sysctl.
    let mut watch = fresh();
    let mut events = Vec::new();
    for _ in 0..LINK_PROBE_FAILURES_FATAL {
        events.extend(round(&mut watch, up(1500), Ok(0), Err(())));
    }
    assert_eq!(
        events,
        [
            warning(Condition::LinkProbe),
            fatal(Fatal::LinkUnverifiable)
        ]
    );
    // Recovery needs every query kind healthy again.
    let mut watch = fresh();
    assert_eq!(
        round(&mut watch, up(1500), failure, Err(())),
        [warning(Condition::LinkProbe)]
    );
    assert!(round(&mut watch, up(1500), Ok(0), Err(())).is_empty());
    assert_eq!(
        round(&mut watch, up(1500), Ok(0), OFF),
        [recovered(Condition::LinkProbe)]
    );
}

/// Forwarding turned on while attached warns (with or without the
/// override) and recovers; an unreadable sysctl is a failed query without
/// the override and only a warning with it.
#[test]
fn kernel_forwarding_at_run_time_warns_while_attached() {
    for (global, device) in [(true, false), (false, true), (true, true)] {
        let on = Ok(Forwarding {
            global,
            device,
            force: false,
            multicast: false,
        });
        for mut watch in [fresh(), watch_allowing()] {
            assert_eq!(
                round(&mut watch, up(1500), Ok(0), on),
                [warning(Condition::KernelForwardingEnabled)]
            );
            assert!(round(&mut watch, up(1500), Ok(0), on).is_empty());
            assert!(watch.warning());
            assert_eq!(
                watch.kernel_exposure(),
                KernelExposure {
                    forwarding: true,
                    ..KernelExposure::default()
                }
            );
            let (_, health) = watch.health().next().expect("port");
            assert!(health.kernel_forwarding);
            assert_eq!(
                round(&mut watch, up(1500), Ok(0), OFF),
                [recovered(Condition::KernelForwardingEnabled)]
            );
            assert!(!watch.warning());
        }
    }
    let mut allowed = watch_allowing();
    let mut events = Vec::new();
    for _ in 0..10 {
        events.extend(round(&mut allowed, up(1500), Ok(0), Err(())));
    }
    assert_eq!(events, [warning(Condition::ForwardingUnverifiable)]);
    assert_eq!(
        round(&mut allowed, up(1500), Ok(0), OFF),
        [recovered(Condition::ForwardingUnverifiable)]
    );
}

fn fresh() -> Watch {
    Watch::new(&[TARGET], Thresholds::default())
}

fn watch_allowing() -> Watch {
    Watch::new(&[TARGET], Thresholds::default()).allowing_kernel_forwarding(true)
}

#[test]
fn intervals_and_lines_are_stable() {
    let mut watch = fresh();
    assert!(watch.health_due(MonotonicMillis(5), 500), "first is due");
    assert!(!watch.health_due(MonotonicMillis(504), 500));
    assert!(watch.health_due(MonotonicMillis(505), 500));
    assert!(watch.link_due(MonotonicMillis(0), 1_000));
    assert!(!watch.link_due(MonotonicMillis(999), 1_000));
    assert_eq!(
        warning(Condition::TxStall).to_string(),
        "warning: port=if1 health=TX_STALL"
    );
    assert_eq!(
        recovered(Condition::LinkDown).to_string(),
        "recovered: port=if1 health=LINK_DOWN"
    );
    assert_eq!(
        fatal(Fatal::DeviceRemoved).to_string(),
        "fatal: port=if1 health=DEVICE_REMOVED"
    );
    // Samples of an unknown port and results of an unknown index are
    // ignored.
    let unknown = PortSample {
        interface: IfId(9),
        ..sample()
    };
    assert!(run(&mut watch, 0, unknown).is_empty());
    let mut events = Vec::new();
    watch.on_link(5, Err(NetlinkError::Kernel(-19)), &mut |event| {
        events.push(event)
    });
    assert!(events.is_empty());
}

/// One round with the link up and only the IPv4 route dump or the IPv6
/// sample varied.
fn exposure_round(
    watch: &mut Watch,
    routes: Result<u32, NetlinkError>,
    ipv6: Ipv6Sample,
) -> Vec<WatchEvent> {
    let mut events = round(watch, up(1500), Ok(0), OFF);
    watch.on_ipv4_routes(0, routes, &mut |event| events.push(event));
    watch.on_ipv6(0, ipv6, &mut |event| events.push(event));
    events
}

const IPV6_CLEAN: Ipv6Sample = Ipv6Sample {
    disabled: Ok(false),
    addresses: Ok(0),
    routes: Ok(0),
    forwarding: Ok(Forwarding {
        global: false,
        device: false,
        force: false,
        multicast: false,
    }),
};

/// A kernel route out of a port (any table) while attached warns, is
/// counted and reported for the exit, and recovers; a dump failing every
/// round is fatal like the others.
#[test]
fn kernel_routes_on_a_port_warn_while_attached() {
    let mut watch = fresh();
    assert!(exposure_round(&mut watch, Ok(0), Ipv6Sample::DISABLED).is_empty());
    assert_eq!(
        exposure_round(&mut watch, Ok(2), Ipv6Sample::DISABLED),
        [warning(Condition::KernelIpv4Routes)]
    );
    assert!(
        exposure_round(&mut watch, Ok(3), Ipv6Sample::DISABLED).is_empty(),
        "once"
    );
    assert!(watch.warning());
    assert_eq!(
        watch.kernel_exposure(),
        KernelExposure {
            routes: true,
            ..KernelExposure::default()
        }
    );
    let (_, health) = watch.health().next().expect("port");
    assert_eq!((health.kernel_ipv4_routes, health.warnings), (3, 1));
    assert_eq!(
        exposure_round(&mut watch, Ok(0), Ipv6Sample::DISABLED),
        [recovered(Condition::KernelIpv4Routes)]
    );
    assert!(!watch.warning());
    assert_eq!(watch.kernel_exposure(), KernelExposure::default());
    // A failing route dump is a failed query of its own kind, even under
    // both overrides.
    let mut watch = watch_allowing().allowing_kernel_ipv6(true);
    let mut events = Vec::new();
    for _ in 0..LINK_PROBE_FAILURES_FATAL {
        events.extend(exposure_round(
            &mut watch,
            Err(NetlinkError::Truncated),
            Ipv6Sample::DISABLED,
        ));
    }
    assert_eq!(
        events,
        [
            warning(Condition::LinkProbe),
            fatal(Fatal::LinkUnverifiable)
        ]
    );
}

/// Kernel IPv6 on a port warns: IPv6 enabled at all (`disable_ipv6`
/// flipped to 0 while running), and each exposure kind; each recovers, and
/// `disable_ipv6` turning on clears every kind at once.
#[test]
fn kernel_ipv6_at_run_time_warns_unless_disabled() {
    let exposed = Ipv6Sample {
        disabled: Ok(false),
        addresses: Ok(1),
        routes: Ok(2),
        forwarding: Ok(Forwarding {
            global: false,
            device: true,
            force: false,
            multicast: false,
        }),
    };
    for mut watch in [fresh(), fresh().allowing_kernel_ipv6(true)] {
        assert_eq!(
            exposure_round(&mut watch, Ok(0), exposed),
            [
                warning(Condition::KernelIpv6Enabled),
                warning(Condition::KernelIpv6Addresses),
                warning(Condition::KernelIpv6Routes),
                warning(Condition::KernelIpv6ForwardingEnabled),
            ]
        );
        assert!(
            exposure_round(&mut watch, Ok(0), exposed).is_empty(),
            "once"
        );
        assert!(watch.warning());
        assert_eq!(
            watch.kernel_exposure(),
            KernelExposure {
                ipv6_forwarding: true,
                ipv6_addresses: true,
                ipv6_routes: true,
                ipv6_enabled: true,
                ..KernelExposure::default()
            }
        );
        let (_, health) = watch.health().next().expect("port");
        assert_eq!(
            (
                health.kernel_ipv6_enabled,
                health.kernel_ipv6_addresses,
                health.kernel_ipv6_routes,
                health.kernel_ipv6_forwarding,
                health.warnings
            ),
            (true, 1, 2, true, 4)
        );
        // disable_ipv6 = 1: whatever else the sample says, nothing is
        // exposed.
        let disabled = Ipv6Sample {
            disabled: Ok(true),
            addresses: Err(NetlinkError::Errno(1)),
            ..exposed
        };
        assert_eq!(
            exposure_round(&mut watch, Ok(0), disabled),
            [
                recovered(Condition::KernelIpv6Enabled),
                recovered(Condition::KernelIpv6Addresses),
                recovered(Condition::KernelIpv6Routes),
                recovered(Condition::KernelIpv6ForwardingEnabled),
            ]
        );
        assert!(!watch.warning());
        assert_eq!(watch.kernel_exposure(), KernelExposure::default());
        // One kind at a time.
        let routes_only = Ipv6Sample {
            routes: Ok(1),
            ..IPV6_CLEAN
        };
        assert_eq!(
            exposure_round(&mut watch, Ok(0), routes_only),
            [
                warning(Condition::KernelIpv6Enabled),
                warning(Condition::KernelIpv6Routes)
            ]
        );
        assert_eq!(
            exposure_round(&mut watch, Ok(0), IPV6_CLEAN),
            [recovered(Condition::KernelIpv6Routes)]
        );
        // Link-local only, enabled: still a warning until disabled.
        assert!(watch.warning());
        assert_eq!(
            exposure_round(&mut watch, Ok(0), Ipv6Sample::DISABLED),
            [recovered(Condition::KernelIpv6Enabled)]
        );
        assert!(!watch.warning());
    }
}

/// An unreadable IPv6 fact is a failed query of its kind (fatal after
/// three rounds in a row) unless `--allow-kernel-ipv6`, which warns
/// `IPV6_UNVERIFIABLE` once and recovers when every IPv6 fact reads
/// again.
#[test]
fn unreadable_ipv6_facts_are_failed_queries_unless_allowed() {
    let failing = [
        Ipv6Sample {
            disabled: Err(()),
            ..IPV6_CLEAN
        },
        Ipv6Sample {
            forwarding: Err(()),
            ..IPV6_CLEAN
        },
        Ipv6Sample {
            addresses: Err(NetlinkError::Truncated),
            ..IPV6_CLEAN
        },
        Ipv6Sample {
            routes: Err(NetlinkError::Interrupted),
            ..IPV6_CLEAN
        },
    ];
    // `KERNEL_IPV6_ENABLED` (the samples with a readable flag say 0) is
    // covered above; here only the query outcome matters.
    let enabled = warning(Condition::KernelIpv6Enabled);
    let without_enabled = |mut events: Vec<WatchEvent>| {
        events
            .retain(|event| *event != enabled && *event != recovered(Condition::KernelIpv6Enabled));
        events
    };
    for sample in failing {
        let mut watch = fresh();
        let mut events = Vec::new();
        for _ in 0..LINK_PROBE_FAILURES_FATAL {
            events.extend(exposure_round(&mut watch, Ok(0), sample));
        }
        assert_eq!(
            without_enabled(events),
            [
                warning(Condition::LinkProbe),
                fatal(Fatal::LinkUnverifiable)
            ],
            "{sample:?}"
        );
        // --allow-kernel-forwarding does not cover IPv6.
        let mut ipv4_only = watch_allowing();
        let mut events = Vec::new();
        for _ in 0..LINK_PROBE_FAILURES_FATAL {
            events.extend(exposure_round(&mut ipv4_only, Ok(0), sample));
        }
        assert!(
            events.contains(&fatal(Fatal::LinkUnverifiable)),
            "{sample:?}"
        );
        let mut allowed = fresh().allowing_kernel_ipv6(true);
        let mut events = Vec::new();
        for _ in 0..10 {
            events.extend(exposure_round(&mut allowed, Ok(0), sample));
        }
        assert_eq!(
            without_enabled(events),
            [warning(Condition::Ipv6Unverifiable)],
            "{sample:?}"
        );
        assert!(allowed.warning());
        assert_eq!(
            without_enabled(exposure_round(&mut allowed, Ok(0), IPV6_CLEAN)),
            [recovered(Condition::Ipv6Unverifiable)]
        );
        assert!(
            without_enabled(exposure_round(&mut allowed, Ok(0), Ipv6Sample::DISABLED)).is_empty()
        );
        assert!(!allowed.warning());
    }
    let mut allowed = fresh().allowing_kernel_ipv6(true);
    assert!(exposure_round(&mut allowed, Ok(0), Ipv6Sample::DISABLED).is_empty());
    for (condition, code) in [
        (
            Condition::KernelIpv6ForwardingEnabled,
            "KERNEL_IPV6_FORWARDING_ENABLED",
        ),
        (Condition::KernelIpv6Addresses, "KERNEL_IPV6_ADDRESSES"),
        (Condition::KernelIpv6Routes, "KERNEL_IPV6_ROUTES"),
        (Condition::Ipv6Unverifiable, "IPV6_UNVERIFIABLE"),
        (Condition::KernelIpv4Routes, "KERNEL_IPV4_ROUTES"),
        (Condition::KernelIpv6Enabled, "KERNEL_IPV6_ENABLED"),
        (Condition::Ipv4WeakHost, "IPV4_WEAK_HOST_EXPOSURE"),
    ] {
        assert_eq!(condition.code(), code);
    }
}

/// The IPv4 weak-host advice warns (also when unreadable), recovers, and
/// is never fatal; IPv4 multicast forwarding is forwarding.
#[test]
fn weak_host_warns_and_multicast_forwarding_is_forwarding() {
    let mut watch = fresh();
    let mut events = Vec::new();
    for exposed in [Some(true), Some(true), None, Some(false), None] {
        watch.on_weak_host(0, exposed, &mut |event| events.push(event));
    }
    assert_eq!(
        events,
        [
            warning(Condition::Ipv4WeakHost),
            recovered(Condition::Ipv4WeakHost),
            warning(Condition::Ipv4WeakHost),
        ]
    );
    let (_, health) = watch.health().next().expect("port");
    assert!(health.ipv4_weak_host);
    assert!(watch.warning());
    let multicast = Ok(Forwarding {
        multicast: true,
        ..Forwarding::default()
    });
    assert_eq!(
        round(&mut fresh(), up(1500), Ok(0), multicast),
        [warning(Condition::KernelForwardingEnabled)]
    );
    let force = Ipv6Sample {
        forwarding: Ok(Forwarding {
            force: true,
            ..Forwarding::default()
        }),
        ..IPV6_CLEAN
    };
    let mut watch = fresh();
    assert!(exposure_round(&mut watch, Ok(0), force)
        .contains(&warning(Condition::KernelIpv6ForwardingEnabled)));
}

fn late(watch: &mut Watch, now: u64, since: u64) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    watch.on_late_round(MonotonicMillis(now), MonotonicMillis(since), &mut |event| {
        events.push(event)
    });
    events
}

/// A monitor that answers with one fixed port round.
struct Scripted(PortRound);

impl LinkMonitor for Scripted {
    fn stacked_links(&mut self, _: &[u32], counts: &mut [u32]) -> Result<(), NetlinkError> {
        let count = self.0.uppers.unwrap_or(Ok(0))?;
        counts.iter_mut().for_each(|slot| *slot = count);
        Ok(())
    }

    fn query(&mut self, _: &LinkTarget) -> Result<LinkFacts, NetlinkError> {
        self.0.link
    }
    fn ipv4_addresses(&mut self, _: &LinkTarget) -> Result<u32, NetlinkError> {
        self.0.addresses.unwrap_or(Ok(0))
    }
    fn ipv4_routes(&mut self, _: &LinkTarget) -> Result<u32, NetlinkError> {
        self.0.routes.unwrap_or(Ok(0))
    }
    fn ipv6(&mut self, _: &LinkTarget) -> Ipv6Sample {
        self.0.ipv6.unwrap_or(Ipv6Sample::DISABLED)
    }
    fn forwarding(&mut self, _: &LinkTarget) -> Result<Forwarding, ()> {
        self.0.forwarding
    }
    fn ipv4_weak_host(&mut self, _: &LinkTarget) -> Option<bool> {
        self.0.weak_host
    }
}

fn round_of(port: PortRound) -> LinkRound {
    let mut round = LinkRound::new(1);
    probe_round(&mut Scripted(port), &[TARGET], &mut round);
    round
}

fn port_round(link: Result<LinkFacts, NetlinkError>, addresses: u32, routes: u32) -> PortRound {
    let linked = link.is_ok();
    PortRound {
        link,
        addresses: linked.then_some(Ok(addresses)),
        routes: linked.then_some(Ok(routes)),
        forwarding: Ok(Forwarding::default()),
        weak_host: Some(false),
        ipv6: linked.then_some(Ipv6Sample::DISABLED),
        uppers: None,
    }
}

fn fold(watch: &mut Watch, round: &LinkRound) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    watch.on_round(round, &mut |event| events.push(event));
    events
}

/// The staleness rule (H7): a round still outstanding when the next is
/// due is late only; from the stale threshold on each due round is a
/// failed link query of every port (`LINK_PROBE`, then
/// `LINK_UNVERIFIABLE` at the third in a row) and `LINK_WATCH_STALE`.
#[test]
fn a_stuck_link_round_is_late_then_stale_then_fatal() {
    let mut watch = watch().with_link_stale_ms(5_000);
    // Requested at 1 s; due again every second.
    for now in [2_000, 3_000, 4_000, 5_000] {
        assert_eq!(late(&mut watch, now, 1_000), [], "{now}");
    }
    assert!(
        !watch.warning(),
        "a brief hold costs nothing but late rounds"
    );
    assert_eq!(
        late(&mut watch, 6_000, 1_000),
        [
            warning(Condition::LinkWatchStale),
            warning(Condition::LinkProbe)
        ]
    );
    assert_eq!(late(&mut watch, 7_000, 1_000), []);
    assert_eq!(
        late(&mut watch, 8_000, 1_000),
        [fatal(Fatal::LinkUnverifiable)]
    );
    let rounds = watch.rounds();
    assert_eq!((rounds.completed, rounds.late, rounds.stale), (0, 7, 3));
    let mut text = String::new();
    crate::run::stats::write_fields(&mut text, None, &watch);
    assert!(text.contains("watch.state=warning\n"), "{text}");
    assert!(
        text.contains("watch.link_rounds=0\nwatch.link_rounds_late=7\nwatch.link_rounds_stale=3\n"),
        "{text}"
    );
}

/// A stuck round that comes back before the third stale round recovers
/// everything: its link query succeeds, the failure count restarts, and
/// the next stale episode starts from zero.
#[test]
fn a_returning_round_recovers_the_stale_warning() {
    let mut watch = watch().with_link_stale_ms(2_000);
    assert_eq!(late(&mut watch, 2_000, 1_000), []);
    assert_eq!(
        late(&mut watch, 3_000, 1_000),
        [
            warning(Condition::LinkWatchStale),
            warning(Condition::LinkProbe)
        ]
    );
    assert_eq!(late(&mut watch, 4_000, 1_000), []);
    assert_eq!(
        fold(&mut watch, &round_of(port_round(up(1500), 0, 0))),
        [
            recovered(Condition::LinkWatchStale),
            recovered(Condition::LinkProbe)
        ]
    );
    assert!(!watch.warning());
    // Two more stale rounds are not fatal: the count restarted.
    assert_eq!(
        late(&mut watch, 7_000, 5_000),
        [
            warning(Condition::LinkWatchStale),
            warning(Condition::LinkProbe)
        ]
    );
    assert_eq!(late(&mut watch, 8_000, 5_000), []);
    assert_eq!(watch.rounds().completed, 1);
}

/// A folded round reports what the pre-H7 synchronous round reported for
/// the same results.
#[test]
fn a_folded_round_has_the_synchronous_outcomes() {
    let mut watch = watch();
    assert_eq!(
        fold(&mut watch, &round_of(port_round(up(1500), 1, 2))),
        [
            warning(Condition::KernelIpv4Addresses),
            warning(Condition::KernelIpv4Routes)
        ]
    );
    let removed = Err(NetlinkError::Kernel(crate::run::netlink::KERNEL_ENODEV));
    assert_eq!(
        fold(&mut watch, &round_of(port_round(removed, 0, 0))),
        [fatal(Fatal::DeviceRemoved)]
    );
}

/// H10: the index carrying another name than the configured device is
/// fatal `DEVICE_RENAMED`, and nothing else of that port's round is
/// folded in (its sysctl paths may name another device now), also for a
/// removed device; the same name keeps the round as before.
#[test]
fn a_renamed_port_is_fatal_and_its_round_is_not_read() {
    let renamed = || {
        Ok(LinkFacts {
            name: IfName::literal(b"rx"),
            ..up(1500).expect("facts")
        })
    };
    assert_eq!(link(&mut watch(), renamed()), [fatal(Fatal::DeviceRenamed)]);
    assert_eq!(Fatal::DeviceRenamed.code(), "DEVICE_RENAMED");
    // A prefix or an extension of the name is another name.
    for name in [&b"r"[..], b"ra0", b"RA"] {
        let other = Ok(LinkFacts {
            name: IfName::literal(name),
            ..up(1500).expect("facts")
        });
        assert_eq!(link(&mut watch(), other), [fatal(Fatal::DeviceRenamed)]);
    }
    // Kernel forwarding, an address, a route, and weak-host exposure in
    // the same round (read through the old name) are not reported.
    let exposed = |link| PortRound {
        forwarding: Ok(Forwarding {
            global: true,
            ..Forwarding::default()
        }),
        weak_host: Some(true),
        ..port_round(link, 1, 1)
    };
    let mut watched = watch();
    assert_eq!(
        fold(&mut watched, &round_of(exposed(renamed()))),
        [fatal(Fatal::DeviceRenamed)]
    );
    assert!(!watched.kernel_exposure().forwarding);
    let removed = Err(NetlinkError::Kernel(crate::run::netlink::KERNEL_ENODEV));
    assert_eq!(
        fold(&mut watch(), &round_of(exposed(removed))),
        [fatal(Fatal::DeviceRemoved)]
    );
    // The configured name: every finding is read.
    assert_eq!(
        fold(&mut watch(), &round_of(exposed(up(1500)))).len(),
        4,
        "addresses, routes, forwarding, weak host"
    );
}

/// AFPKT-015: on an AF_PACKET port a kernel exposure condition found at
/// run time is fatal under its own code, unless the startup accepted it
/// through an override; the device found gone by the backend is
/// `DEVICE_REMOVED`; AF_XDP keeps warning only.
#[test]
fn af_packet_kernel_exposure_is_fatal_unless_overridden() {
    let strict = ExposurePolicy::default();
    let mut packet = watch().failing_on_kernel_exposure(strict);
    let mut events = Vec::new();
    packet.on_addresses(0, Ok(1), &mut |event| events.push(event));
    assert_eq!(
        events,
        [
            warning(Condition::KernelIpv4Addresses),
            fatal(Fatal::KernelExposure(Condition::KernelIpv4Addresses)),
        ]
    );
    assert_eq!(
        Fatal::KernelExposure(Condition::KernelIpv4Addresses).code(),
        "KERNEL_IPV4_ADDRESSES"
    );
    for (condition, fatal_by_default) in [
        (Condition::KernelIpv4Addresses, true),
        (Condition::KernelIpv4Routes, true),
        (Condition::KernelForwardingEnabled, true),
        (Condition::Ipv4WeakHost, true),
        (Condition::KernelIpv6Enabled, true),
        (Condition::KernelIpv6Addresses, true),
        (Condition::KernelIpv6Routes, true),
        (Condition::KernelIpv6ForwardingEnabled, true),
        (Condition::TxStall, false),
        (Condition::LinkDown, false),
        (Condition::LinkProbe, false),
        (Condition::ForwardingUnverifiable, false),
        (Condition::Ipv6Unverifiable, false),
        (Condition::LinkWatchStale, false),
        (Condition::MtuRaised, false),
        (Condition::KickErrors, false),
        (Condition::FillStarved, false),
    ] {
        assert_eq!(
            strict.is_fatal(condition),
            fatal_by_default,
            "{condition:?}"
        );
    }
    let allowed = ExposurePolicy {
        allow_kernel_forwarding: true,
        allow_kernel_ipv6: true,
        allow_ipv4_weak_host: true,
    };
    for condition in [
        Condition::KernelForwardingEnabled,
        Condition::Ipv4WeakHost,
        Condition::KernelIpv6Enabled,
        Condition::KernelIpv6Addresses,
        Condition::KernelIpv6Routes,
        Condition::KernelIpv6ForwardingEnabled,
    ] {
        assert!(!allowed.is_fatal(condition), "{condition:?}");
    }
    assert!(allowed.is_fatal(Condition::KernelIpv4Addresses));
    assert!(allowed.is_fatal(Condition::KernelIpv4Routes));
    // The weak host with its override: a warning only.
    let mut packet = watch().failing_on_kernel_exposure(allowed);
    let mut events = Vec::new();
    packet.on_weak_host(0, Some(true), &mut |event| events.push(event));
    assert_eq!(events, [warning(Condition::Ipv4WeakHost)]);
    // AF_XDP: an address only warns.
    let mut xdp = watch();
    let mut events = Vec::new();
    xdp.on_addresses(0, Ok(1), &mut |event| events.push(event));
    assert_eq!(events, [warning(Condition::KernelIpv4Addresses)]);
    // The backend's unbound port.
    let mut packet = watch().failing_on_kernel_exposure(strict);
    assert_eq!(
        run(
            &mut packet,
            10,
            PortSample {
                device_gone: true,
                ..sample()
            }
        ),
        [fatal(Fatal::DeviceRemoved)]
    );
}

/// AF_PACKET: an upper device appearing at run time (the port enslaved,
/// `IFLA_MASTER` in the link query; or a device stacked on it, the link
/// dump) is fatal `KERNEL_UPPER_DEVICE`; a failing dump counts as a failed
/// query; an AF_XDP port is not asked.
#[test]
fn an_upper_device_at_run_time_ends_an_af_packet_run() {
    let mut packet = watch().failing_on_kernel_exposure(ExposurePolicy::default());
    let mut events = Vec::new();
    packet.on_uppers(0, false, Ok(0), &mut |event| events.push(event));
    assert!(events.is_empty());
    for (master, stacked) in [(true, 0), (false, 1), (true, 2)] {
        let mut packet = watch().failing_on_kernel_exposure(ExposurePolicy::default());
        let mut events = Vec::new();
        packet.on_uppers(0, master, Ok(stacked), &mut |event| events.push(event));
        assert_eq!(
            events,
            [
                warning(Condition::KernelUpperDevice),
                fatal(Fatal::KernelExposure(Condition::KernelUpperDevice)),
            ],
            "{master} {stacked}"
        );
        assert_eq!(
            Fatal::KernelExposure(Condition::KernelUpperDevice).code(),
            "KERNEL_UPPER_DEVICE"
        );
    }
    // Even with every override: no override accepts an upper device.
    let all = ExposurePolicy {
        allow_kernel_forwarding: true,
        allow_kernel_ipv6: true,
        allow_ipv4_weak_host: true,
    };
    assert!(all.is_fatal(Condition::KernelUpperDevice));
    // A failing dump is a failed query (fatal LINK_UNVERIFIABLE after three).
    let mut packet = watch().failing_on_kernel_exposure(ExposurePolicy::default());
    let mut events = Vec::new();
    for _ in 0..LINK_PROBE_FAILURES_FATAL {
        packet.on_uppers(0, false, Err(NetlinkError::EndOfStream), &mut |event| {
            events.push(event);
        });
    }
    assert_eq!(
        events,
        [
            warning(Condition::LinkProbe),
            fatal(Fatal::LinkUnverifiable)
        ]
    );
    // Through a whole round: the link query's master is used, and the
    // dump only for a port that watches its uppers.
    let enslaved = Ok(LinkFacts {
        master: Some(9),
        ..up(1500).expect("facts")
    });
    let packet_target = LinkTarget {
        watch_uppers: true,
        ..TARGET
    };
    let mut round = LinkRound::new(1);
    probe_round(
        &mut Scripted(port_round(enslaved, 0, 0)),
        &[packet_target],
        &mut round,
    );
    let mut packet = Watch::new(&[packet_target], Thresholds::default())
        .failing_on_kernel_exposure(ExposurePolicy::default());
    assert_eq!(
        fold(&mut packet, &round),
        [
            warning(Condition::KernelUpperDevice),
            fatal(Fatal::KernelExposure(Condition::KernelUpperDevice)),
        ]
    );
    // A stacked device found by the dump of the same round.
    let mut round = LinkRound::new(1);
    probe_round(
        &mut Scripted(PortRound {
            uppers: Some(Ok(1)),
            ..port_round(up(1500), 0, 0)
        }),
        &[packet_target],
        &mut round,
    );
    assert_eq!(round.ports()[0].uppers, Some(Ok(1)));
    let mut packet = Watch::new(&[packet_target], Thresholds::default())
        .failing_on_kernel_exposure(ExposurePolicy::default());
    assert_eq!(
        fold(&mut packet, &round),
        [
            warning(Condition::KernelUpperDevice),
            fatal(Fatal::KernelExposure(Condition::KernelUpperDevice)),
        ]
    );
    // AF_XDP ports are not asked.
    let round = round_of(PortRound {
        uppers: Some(Ok(1)),
        ..port_round(up(1500), 0, 0)
    });
    assert_eq!(round.ports()[0].uppers, None, "not asked for AF_XDP");
}

/// A stacked-device dump that link churn interrupts in every attempt is
/// counted apart, with its own higher threshold (still fail closed); a
/// completed dump resets it; another failure keeps the usual threshold.
#[test]
fn an_interrupted_upper_device_dump_fails_closed_only_after_its_own_threshold() {
    let mut packet = watch().failing_on_kernel_exposure(ExposurePolicy::default());
    let mut events = Vec::new();
    for _ in 1..LINK_DUMP_INTERRUPTED_FATAL {
        packet.on_uppers(0, false, Err(NetlinkError::Interrupted), &mut |event| {
            events.push(event);
        });
    }
    assert_eq!(
        events,
        [warning(Condition::LinkProbe)],
        "below the threshold"
    );
    // A completed dump resets the count and recovers.
    let mut events = Vec::new();
    packet.on_uppers(0, false, Ok(0), &mut |event| events.push(event));
    assert_eq!(events, [recovered(Condition::LinkProbe)]);
    let mut events = Vec::new();
    for _ in 0..LINK_DUMP_INTERRUPTED_FATAL {
        packet.on_uppers(0, false, Err(NetlinkError::Interrupted), &mut |event| {
            events.push(event);
        });
    }
    assert_eq!(
        events,
        [
            warning(Condition::LinkProbe),
            fatal(Fatal::LinkUnverifiable)
        ],
        "fatal at the threshold"
    );
    const { assert!(LINK_DUMP_INTERRUPTED_FATAL > LINK_PROBE_FAILURES_FATAL) };
    // Any other dump failure: the usual threshold.
    let mut packet = watch().failing_on_kernel_exposure(ExposurePolicy::default());
    let mut events = Vec::new();
    for _ in 0..LINK_PROBE_FAILURES_FATAL {
        packet.on_uppers(0, false, Err(NetlinkError::Truncated), &mut |event| {
            events.push(event);
        });
    }
    assert_eq!(
        events,
        [
            warning(Condition::LinkProbe),
            fatal(Fatal::LinkUnverifiable)
        ]
    );
}

fn integrity(watch: &mut Watch, at: u64, frames: u64, descs: u64) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    watch.on_integrity(
        MonotonicMillis(at),
        IntegritySample {
            interface: PORT,
            frames_quarantined: frames,
            tx_invalid_descs: descs,
        },
        &mut |event| events.push(event),
    );
    events
}

/// OPS-LOG: growth of the quarantine or the kernel's invalid TX
/// descriptors warns once per episode, the episode recovers after
/// `INTEGRITY_QUIET_MS` without growth, the count since startup at the
/// threshold is fatal, `None` never is, and a reading that went back (an
/// unreadable `XDP_STATISTICS`) is not growth afterwards.
#[test]
fn integrity_counters_warn_recover_and_become_fatal_at_the_threshold() {
    let mut watch = watch().with_limits(Limits {
        frames_quarantined_fatal: Some(3),
        tx_invalid_descs_fatal: None,
        ..Limits::default()
    });
    assert_eq!(integrity(&mut watch, 0, 0, 0), []);
    assert_eq!(
        integrity(&mut watch, 500, 1, 0),
        [warning(Condition::FramesQuarantined)]
    );
    assert!(watch.warning());
    assert_eq!(integrity(&mut watch, 1_000, 2, 0), []);
    // Quiet for less than INTEGRITY_QUIET_MS: still the same episode.
    assert_eq!(integrity(&mut watch, 10_999, 2, 0), []);
    assert!(watch.warning());
    assert_eq!(
        integrity(&mut watch, 11_000, 2, 0),
        [recovered(Condition::FramesQuarantined)]
    );
    assert!(!watch.warning());
    // TX descriptors: warning only (no threshold), however many.
    assert_eq!(
        integrity(&mut watch, 11_500, 2, 1_000_000),
        [warning(Condition::TxInvalidDescs)]
    );
    // The kernel statistics unreadable (0), then back: no new growth.
    assert_eq!(integrity(&mut watch, 12_000, 2, 0), []);
    assert_eq!(
        integrity(&mut watch, 21_500, 2, 1_000_000),
        [recovered(Condition::TxInvalidDescs)]
    );
    assert_eq!(
        integrity(&mut watch, 22_000, 3, 1_000_000),
        [
            warning(Condition::FramesQuarantined),
            fatal(Fatal::FramesQuarantined)
        ]
    );
    let (_, health) = watch.health().next().expect("port");
    assert_eq!(
        (health.frames_quarantined, health.tx_invalid_descs),
        (3, 1_000_000)
    );
    // Another port's sample changes nothing.
    let mut events = Vec::new();
    watch.on_integrity(
        MonotonicMillis(30_000),
        IntegritySample {
            interface: IfId(9),
            frames_quarantined: 99,
            tx_invalid_descs: 99,
        },
        &mut |event| events.push(event),
    );
    assert!(events.is_empty());
    // Defaults: 64 each, the first growth warns.
    let mut watch = Watch::new(&[TARGET], Thresholds::default());
    assert_eq!(
        integrity(&mut watch, 0, 0, 63),
        [warning(Condition::TxInvalidDescs)]
    );
    assert_eq!(
        integrity(&mut watch, 500, 0, 64),
        [fatal(Fatal::TxInvalidDescs)]
    );
    // A slow trickle under a disabled fatal exit (one frame every 3 s for a
    // minute) is one episode: one warning, no recovered/warning flapping.
    let mut watch = Watch::new(&[TARGET], Thresholds::default()).with_limits(Limits {
        frames_quarantined_fatal: None,
        ..Limits::default()
    });
    let mut events = Vec::new();
    for step in 0..=120_u64 {
        events.extend(integrity(&mut watch, step * 500, step / 6, 0));
    }
    assert_eq!(events, [warning(Condition::FramesQuarantined)]);
    assert_eq!(Condition::FramesQuarantined.code(), "FRAMES_QUARANTINED");
    assert_eq!(Fatal::TxInvalidDescs.code(), "TX_INVALID_DESCS");
    // Never fatal by kernel exposure policy (AF_PACKET has no such
    // counters anyway).
    let policy = ExposurePolicy::default();
    assert!(!policy.is_fatal(Condition::FramesQuarantined));
    assert!(!policy.is_fatal(Condition::TxInvalidDescs));
}

fn conflicts(watch: &mut Watch, at: u64, count: u64) -> Vec<WatchEvent> {
    let mut events = Vec::new();
    watch.on_arp_conflicts(MonotonicMillis(at), PORT, count, &mut |event| {
        events.push(event);
    });
    events
}

/// ARP-039: conflicting ARP packets for a port's address (RFC 5227 §2.4)
/// warn `ARP_ADDRESS_CONFLICT` once per episode however many arrive (the
/// §2.4 (c) rate-controlled notification), recover after
/// `INTEGRITY_QUIET_MS` without one, are never fatal, and show in the
/// port's health fields.
#[test]
fn arp_address_conflicts_warn_once_per_episode_and_never_end_the_run() {
    let mut watch = watch();
    assert_eq!(conflicts(&mut watch, 0, 0), []);
    assert_eq!(
        conflicts(&mut watch, 500, 1),
        [warning(Condition::ArpAddressConflict)]
    );
    assert_eq!(conflicts(&mut watch, 1_000, 1_000), []);
    assert_eq!(conflicts(&mut watch, 10_999, 1_000), []);
    assert_eq!(
        conflicts(&mut watch, 11_000, 1_000),
        [recovered(Condition::ArpAddressConflict)]
    );
    assert_eq!(
        conflicts(&mut watch, 12_000, 1_001),
        [warning(Condition::ArpAddressConflict)]
    );
    let (_, health) = watch.health().next().expect("port");
    assert_eq!(health.arp_address_conflicts, 1_001);
    assert_eq!(Condition::ArpAddressConflict.code(), "ARP_ADDRESS_CONFLICT");
    assert!(!ExposurePolicy::default().is_fatal(Condition::ArpAddressConflict));
}

/// OPS-LOG: new thresholds take over from the next sample; conditions
/// being timed keep their start, so a lowered fatal bound already passed
/// acts at once, and the limits reach every port.
#[test]
fn replaced_thresholds_apply_from_the_next_sample() {
    let mut watch = Watch::new(&[TARGET], Thresholds::from_secs(1, 0, 0));
    let mut stalled = PortSample {
        tx_inflight: 1,
        ..sample()
    };
    let mut events = Vec::new();
    for step in 0..=20_u64 {
        stalled.polls = step;
        stalled.oldest_age_polls = step;
        events.extend(run(&mut watch, step * HEALTH_INTERVAL_MS, stalled));
    }
    assert_eq!(events, [warning(Condition::TxStall)]);
    let limits = Limits {
        fill_starved_warn_ms: 200,
        link_probe_failures_fatal: 1,
        ..Limits::default()
    };
    watch.set_thresholds(Thresholds::from_secs(1, 5, 0), limits, 1_234);
    assert_eq!(
        watch.thresholds(),
        (Thresholds::from_secs(1, 5, 0), Some(limits), 1_234)
    );
    stalled.polls = 21;
    stalled.oldest_age_polls = 21;
    assert_eq!(
        run(&mut watch, 21 * HEALTH_INTERVAL_MS, stalled),
        [fatal(Fatal::TxStall)]
    );
    // One failed link query is now fatal.
    assert_eq!(
        link(&mut watch, Err(NetlinkError::Truncated)),
        [fatal(Fatal::LinkUnverifiable)]
    );
}

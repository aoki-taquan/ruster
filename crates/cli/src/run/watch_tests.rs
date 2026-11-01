//! Thresholds and outcomes of the health and link watch.

use super::*;

const PORT: IfId = IfId(1);
const TARGET: LinkTarget = LinkTarget {
    interface: PORT,
    ifindex: 7,
    mtu: 1500,
    frame_capacity: 1792,
};

fn watch() -> Watch {
    Watch::new(&[TARGET])
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
    }
}

fn up(mtu: u32) -> Result<LinkFacts, NetlinkError> {
    Ok(LinkFacts {
        mtu,
        rx_queues: Some(1),
        admin_up: true,
        lower_up: true,
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
    let mut watch = watch();
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
    let mut watch = watch();
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
    let mut watch = watch();
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
    let mut watch = watch();
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
    let mut watch = watch();
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
    let mut watch = watch();
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

#[test]
fn intervals_and_lines_are_stable() {
    let mut watch = watch();
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

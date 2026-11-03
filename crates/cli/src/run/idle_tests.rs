//! H9: the idle wait. After the spin ticks the loop blocks in the
//! datapath's RX wait (a `poll` on every port's socket in production),
//! here simulated on a clock bound to the fake host: a wait advances the
//! clock by its timeout, or to the arrival of a frame, which ends it.

use super::ops::line_value;
use super::reclock::{document, hold_pending, unsolicited_syn};
use super::*;
use crate::run::engine::{idle_timeout_ms, Pending};

const MS: u64 = 1_000;

/// Stops once the bound clock reached `until_us`, or when a simulated
/// signal handler ran.
struct ClockStop {
    state: Rc<State>,
    until_us: u64,
}

impl StopSignal for ClockStop {
    fn stop(&self) -> bool {
        self.state.signal.get() || self.state.clock_seen_us.get() >= self.until_us
    }

    fn force(&self) -> bool {
        false
    }
}

/// A host whose datapath waits (simulated).
fn waiting_host() -> FakeHost {
    let host = FakeHost::default();
    host.state.waits.set(true);
    host
}

/// Runs `config` with `settings` on a clock bound to the host (10 µs per
/// reading) until the clock reaches `until_us`.
fn run_until(
    host: &FakeHost,
    config: ValidatedConfigV1,
    settings: Settings,
    until_us: u64,
) -> (Outcome, FakeClock) {
    let stop = ClockStop {
        state: Rc::clone(&host.state),
        until_us,
    };
    let mut clock = FakeClock {
        step_us: 10,
        state: Some(Rc::clone(&host.state)),
        ..FakeClock::default()
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = execute_with(
        host,
        config,
        FakeSource::default(),
        settings,
        &mut clock,
        &stop,
        &mut out,
        &mut err,
    );
    let outcome = Outcome {
        status,
        out: String::from_utf8(out).expect("utf-8"),
        err: String::from_utf8(err).expect("utf-8"),
    };
    (outcome, clock)
}

fn stat(out: &str, key: &str) -> u64 {
    line_value(out, key)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("{key} in {out}"))
}

fn timeouts(state: &State) -> Vec<u32> {
    state
        .wait_log
        .borrow()
        .iter()
        .map(|(_, timeout)| *timeout)
        .collect()
}

#[test]
fn the_timeout_is_the_cap_shortened_by_pending_work_and_the_next_deadline() {
    let at = MonotonicMillis;
    let none = Pending::default();
    assert_eq!(idle_timeout_ms(at(100), 10, none, None), 10);
    assert_eq!(idle_timeout_ms(at(100), 100, none, None), 100);
    assert_eq!(idle_timeout_ms(at(100), 1, none, None), 1);
    // Never past the next deadline; a due or overdue one waits not at all.
    assert_eq!(idle_timeout_ms(at(100), 10, none, Some(at(104))), 4);
    assert_eq!(idle_timeout_ms(at(100), 10, none, Some(at(110))), 10);
    assert_eq!(idle_timeout_ms(at(100), 10, none, Some(at(5_000))), 10);
    assert_eq!(idle_timeout_ms(at(100), 10, none, Some(at(100))), 0);
    assert_eq!(idle_timeout_ms(at(100), 10, none, Some(at(40))), 0);
    // Each kind of pending work alone caps the wait at the short wait.
    for pending in [
        Pending {
            resolution: true,
            ..none
        },
        Pending {
            icmpv4: true,
            ..none
        },
        Pending { tx: true, ..none },
        Pending {
            reload: true,
            ..none
        },
    ] {
        assert!(pending.any());
        assert_eq!(idle_timeout_ms(at(100), 10, pending, None), SHORT_WAIT_MS);
        assert_eq!(idle_timeout_ms(at(100), 100, pending, None), SHORT_WAIT_MS);
        assert_eq!(idle_timeout_ms(at(100), 10, pending, Some(at(100))), 0);
    }
    assert!(!none.any());
}

#[test]
fn the_watch_deadline_is_the_earlier_due_round() {
    use crate::run::watch::{Thresholds, Watch};

    let at = MonotonicMillis;
    let targets = [LAN, WAN].map(|id| LinkTarget {
        watch_uppers: false,
        interface: IfId(id),
        ifindex: u32::from(id) + 10,
        name: crate::run::netlink::IfName::literal(b"sim0"),
        mtu: 1500,
        frame_capacity: 1792,
    });
    let mut watch = Watch::new(&targets, Thresholds::default());
    // Never taken: due at once; an interval of 0 (every tick) sets none.
    assert_eq!(watch.next_due(500, 1_000), Some(at(0)));
    assert_eq!(watch.next_due(0, 0), None);
    assert!(watch.health_due(at(100), 500));
    assert_eq!(watch.next_due(500, 1_000), Some(at(0)), "link never taken");
    assert!(watch.link_due(at(300), 1_000));
    assert_eq!(watch.next_due(500, 1_000), Some(at(600)));
    assert_eq!(watch.next_due(500, 100), Some(at(400)));
    assert_eq!(watch.next_due(0, 1_000), Some(at(1_300)));
    assert_eq!(watch.next_due(500, 0), Some(at(600)));
    assert_eq!(watch.next_due(u64::MAX, u64::MAX), Some(at(u64::MAX)));
}

/// An idle router ticks about once per idle wait (10 ms) instead of once
/// per millisecond, and a frame arriving during a wait is served by the
/// very next tick, with no added delay.
#[test]
fn an_idle_loop_blocks_in_the_wait_and_wakes_on_a_frame() {
    let host = waiting_host();
    let arrival = 1_500 * MS + 123;
    host.state
        .arrivals
        .borrow_mut()
        .push_back((arrival, IfId(LAN), arp_request()));
    let (outcome, clock) = run_until(
        &host,
        config(),
        settings(CheckPolicy::default(), 0),
        3_000 * MS,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    // 3 s of simulated time: three spin phases of 64 ticks (start with the
    // first RFC 5227 announcements, the second announcements at 2 s,
    // ARP-033, and after the frame) and about 300 waits of 10 ms; the
    // pre-H9 1 ms sleep made about 3000 ticks.
    let ticks = host.state.io_calls.get();
    let waits = host.state.wait_log.borrow().len();
    assert!((290..=305).contains(&waits), "{waits} waits");
    assert!(
        ticks <= 3 * SPIN_TICKS + 310,
        "{ticks} ticks in 3 simulated seconds"
    );
    // Every wait is the configured one, except the one the second
    // announcement's deadline (2 s) cut short.
    let timeouts = timeouts(&host.state);
    assert!(
        timeouts
            .iter()
            .all(|timeout| u64::from(*timeout) <= crate::args::DEFAULT_IDLE_WAIT_MS),
        "{timeouts:?}"
    );
    assert!(
        timeouts
            .iter()
            .filter(|timeout| u64::from(**timeout) != crate::args::DEFAULT_IDLE_WAIT_MS)
            .count()
            <= 1,
        "{timeouts:?}"
    );
    assert_eq!(clock.pauses, 0, "no sleep: every wait could block");
    // Served by the first tick after the wait ended at the arrival (one
    // clock step later).
    assert_eq!(host.state.arrived_us.get(), Some(arrival));
    let served = host.state.served_us.get().expect("served");
    assert!(
        served - arrival <= 20,
        "served {} µs late",
        served - arrival
    );
    let out = &outcome.out;
    assert_eq!(stat(out, "rx.received"), 1, "{out}");
    assert_eq!(stat(out, "rx.tx_accepted"), 1, "{out}");
    assert_eq!(stat(out, "idle.max_wait_ms"), 10, "{out}");
    assert_eq!(stat(out, "idle.waits"), waits as u64, "{out}");
    assert_eq!(stat(out, "idle.woken"), 1, "{out}");
    assert_eq!(stat(out, "idle.timed_out"), waits as u64 - 1, "{out}");
    assert_eq!(stat(out, "idle.interrupted"), 0, "{out}");
    assert_eq!(stat(out, "idle.short"), 0, "{out}");
    assert_eq!(stat(out, "idle.sleeps"), 0, "{out}");
    assert_eq!(stat(out, "idle.errors"), 0, "{out}");
    host.assert_released();
}

/// A signal handler interrupting the wait (EINTR) ends the loop before
/// another tick: the stop flag is read at once.
#[test]
fn a_signal_interrupts_the_wait_and_stops_before_another_tick() {
    let host = waiting_host();
    host.state.interrupt_at.set(Some(5));
    let (outcome, _) = run_until(
        &host,
        config(),
        settings(CheckPolicy::default(), 0),
        u64::MAX,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome.err.contains("stopped by signal"), "{}", outcome.err);
    let log = host.state.wait_log.borrow();
    assert_eq!(log.len(), 5);
    assert_eq!(
        log.last().map(|(ticks, _)| *ticks),
        Some(host.state.io_calls.get())
    );
    assert_eq!(stat(&outcome.out, "idle.interrupted"), 1, "{}", outcome.out);
    host.assert_released();
}

/// TX in flight in the backend keeps every wait short: reaps and kick
/// retries keep their pre-H9 cadence.
#[test]
fn outstanding_tx_keeps_the_waits_short() {
    let host = waiting_host();
    host.state.tx_outstanding.set(true);
    let (outcome, _) = run_until(
        &host,
        config(),
        settings(CheckPolicy::default(), 0),
        300 * MS,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let timeouts = timeouts(&host.state);
    assert!(timeouts.len() >= 200, "{} waits", timeouts.len());
    assert!(
        timeouts
            .iter()
            .all(|timeout| u64::from(*timeout) == SHORT_WAIT_MS),
        "{timeouts:?}"
    );
    let out = &outcome.out;
    assert_eq!(stat(out, "idle.short"), stat(out, "idle.waits"), "{out}");
}

/// The periodic stats never come late by more than a clock step: the wait
/// before them ends at their deadline.
#[test]
fn waits_end_at_the_next_stats_deadline() {
    let host = waiting_host();
    let mut settings = settings(CheckPolicy::default(), 25);
    settings.idle_wait_ms = 10;
    let (outcome, _) = run_until(&host, config(), settings, 500 * MS);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let uptimes: Vec<u64> = outcome
        .out
        .lines()
        .filter_map(|line| line.strip_prefix("ruster-run-stats kind=periodic uptime-ms="))
        .map(|value| value.parse().expect("uptime"))
        .collect();
    assert!(uptimes.len() >= 18, "{uptimes:?}");
    for pair in uptimes.windows(2) {
        assert!(
            (25..=26).contains(&(pair[1] - pair[0])),
            "stats at {uptimes:?}"
        );
    }
    // Waits of 10, 10, and the 5 ms left to the deadline.
    let timeouts = timeouts(&host.state);
    assert!(timeouts.iter().all(|timeout| *timeout <= 10));
    assert!(timeouts.iter().any(|timeout| *timeout < 10), "{timeouts:?}");
}

/// With stats, health, and link deadlines all set, the earliest one ends
/// the wait: here the 25 ms health sample, with the stats at 1 s and the
/// link round at 1 s.
#[test]
fn waits_end_at_the_earliest_of_the_loop_deadlines() {
    let host = waiting_host();
    let rounds = (0..100_u64).map(|step| {
        vec![PortSample {
            interface: IfId(WAN),
            polls: step,
            tx_inflight: 0,
            oldest_age_polls: 0,
            kick_errors: 0,
            kick_link_down: false,
            fill_starved: 0,
            fill_ring_occupancy: 8,
            rx_packets: step,
            device_gone: false,
        }]
    });
    host.state.samples.borrow_mut().extend(rounds);
    let mut settings = settings(CheckPolicy::default(), 1_000);
    settings.health_interval_ms = 25;
    settings.link_interval_ms = 1_000;
    let (outcome, _) = run_until(&host, config(), settings, 600 * MS);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let timeouts = timeouts(&host.state);
    assert!(timeouts.len() >= 40, "{timeouts:?}");
    assert!(
        timeouts.iter().all(|timeout| *timeout <= 10),
        "{timeouts:?}"
    );
    // 25 ms = 10 + 10 + 5: every third wait ends at a health sample.
    let short = timeouts.iter().filter(|timeout| **timeout < 10).count();
    assert!(short >= timeouts.len() / 4, "{timeouts:?}");
    // Every sample round was taken on time: about 600 / 25.
    let taken = 100 - host.state.samples.borrow().len();
    assert!((23..=25).contains(&taken), "{taken} health samples");
}

/// Readiness that the next tick does not consume makes the next wait a
/// short sleep, never a spin.
#[test]
fn unconsumed_readiness_sleeps_instead_of_spinning() {
    let host = waiting_host();
    host.state.spurious_ready.set(3);
    let (outcome, clock) = run_until(
        &host,
        config(),
        settings(CheckPolicy::default(), 0),
        200 * MS,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(clock.pauses, 3);
    assert_eq!(clock.longest, Duration::from_millis(SHORT_WAIT_MS));
    let out = &outcome.out;
    assert_eq!(stat(out, "idle.woken"), 3, "{out}");
    assert_eq!(stat(out, "idle.sleeps"), 3, "{out}");
}

/// B3: while an unsolicited SYN is held, the waits stay short, so the
/// hold is released within about a millisecond of its 6 s deadline (the
/// failure dispatch runs at ticks), as before H9; afterwards the waits go
/// back to the full idle wait.
#[test]
fn a_held_unsolicited_syn_keeps_the_waits_short_and_is_released_on_time() {
    let arrival = 100 * MS;
    // The SYN's tick reads the clock right after the arrival, so the hold
    // matures 6 s plus the 2 ms margin later.
    for (until_ms, pending) in [(6_101, true), (6_105, false)] {
        let host = waiting_host();
        host.state
            .arrivals
            .borrow_mut()
            .push_back((arrival, IfId(WAN), unsolicited_syn()));
        let mut settings = settings(CheckPolicy::default(), 0);
        settings.health_interval_ms = 1_000;
        settings.link_interval_ms = 1_000;
        let (outcome, _) = run_until(&host, document(|text| text), settings, until_ms * MS);
        assert_eq!(outcome.status, 0, "{}", outcome.err);
        assert_eq!(
            hold_pending(&outcome.out),
            pending,
            "{until_ms}: {}",
            outcome.out
        );
        // Full waits until the SYN arrived, then short ones while it was
        // held (the frame's own tick and the spin ticks after it first).
        let log = host.state.wait_log.borrow();
        let before: Vec<u32> = log
            .iter()
            .take_while(|(ticks, _)| *ticks <= SPIN_TICKS + 12)
            .map(|(_, timeout)| *timeout)
            .collect();
        assert!(before.len() >= 9, "{before:?}");
        assert!(before.iter().all(|timeout| *timeout == 10), "{before:?}");
        let held: Vec<u32> = log
            .iter()
            .filter(|(ticks, _)| *ticks > 2 * SPIN_TICKS + 12)
            .map(|(_, timeout)| *timeout)
            .take(5_900)
            .collect();
        assert_eq!(held.len(), 5_900, "short waits while held");
        assert!(
            held.iter()
                .all(|timeout| u64::from(*timeout) == SHORT_WAIT_MS),
            "{:?}",
            held.iter()
                .filter(|timeout| u64::from(**timeout) != SHORT_WAIT_MS)
                .count()
        );
    }
}

/// A UDP datagram from the LAN host to host B (203.0.113.1, on the WAN
/// link, not a static neighbor): its forward needs ARP.
fn udp_to_unresolved_wan_host() -> Vec<u8> {
    let mut ip = vec![0x45, 0, 0, 36, 0, 7, 0x40, 0, 64, 17, 0, 0];
    ip.extend_from_slice(&[192, 168, 1, 10, 203, 0, 113, 1]);
    let sum = super::reclock::fold(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    // UDP 5000 -> 9000, 8 bytes of payload, checksum 0 (none).
    let mut udp = vec![0x13, 0x88, 0x23, 0x28, 0, 16, 0, 0];
    udp.extend_from_slice(b"ruster!!");
    let mut frame = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x10, 0x08, 0x00];
    frame.extend(ip);
    frame.extend(udp);
    frame.resize(60, 0);
    frame
}

/// A next hop being resolved (ARP request and its 1 s retries, nobody
/// answers) keeps the waits short, so the resolution timer sweeps at the
/// pre-H9 cadence; before the frame the waits are full.
#[test]
fn a_pending_resolution_keeps_the_waits_short() {
    let host = waiting_host();
    host.state
        .arrivals
        .borrow_mut()
        .push_back((100 * MS, IfId(LAN), udp_to_unresolved_wan_host()));
    let (outcome, _) = run_until(
        &host,
        config(),
        settings(CheckPolicy::default(), 0),
        2_500 * MS,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let out = &outcome.out;
    assert_eq!(stat(out, "rx.received"), 1, "{out}");
    // The first request and at least one retry went out.
    assert!(stat(out, "generated_arp.tx_accepted") >= 2, "{out}");
    let log = host.state.wait_log.borrow();
    let before: Vec<u32> = log
        .iter()
        .take_while(|(ticks, _)| *ticks <= SPIN_TICKS + 8)
        .map(|(_, timeout)| *timeout)
        .collect();
    assert!(before.len() >= 5, "{before:?}");
    assert!(before.iter().all(|timeout| *timeout == 10), "{before:?}");
    let resolving: Vec<u32> = log
        .iter()
        .filter(|(ticks, _)| *ticks > 2 * SPIN_TICKS + 12)
        .map(|(_, timeout)| *timeout)
        .take(2_000)
        .collect();
    assert_eq!(resolving.len(), 2_000, "short waits while resolving");
    assert!(
        resolving
            .iter()
            .all(|timeout| u64::from(*timeout) == SHORT_WAIT_MS),
        "{} full waits",
        resolving
            .iter()
            .filter(|timeout| u64::from(**timeout) != SHORT_WAIT_MS)
            .count()
    );
}

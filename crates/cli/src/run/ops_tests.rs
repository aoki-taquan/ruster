//! Run-time operations of `ruster run` (M2 S10b) over the scripted host:
//! SIGHUP reload, health and device events, and the startup retry.

use super::*;

use crate::config_cmd::Rejection;

use super::super::startup::transient_open;
const TX_STALL_WARN_MS: u64 = 1_000;
const TX_STALL_FATAL_MS: u64 = 10_000;
use super::super::{retry_pause_ms, STARTUP_RETRY_PAUSE_MAX_MS};
use ruster_io_xdp_native::{SessionFailure, SessionStage};

/// Stops once the datapath served `ticks` ticks.
struct StopAfterTicks {
    state: Rc<State>,
    ticks: u32,
    reloads: RefCell<VecDeque<u32>>,
}

impl StopAfterTicks {
    fn new(host: &FakeHost, ticks: u32, reloads: &[u32]) -> Self {
        Self {
            state: Rc::clone(&host.state),
            ticks,
            reloads: RefCell::new(reloads.iter().copied().collect()),
        }
    }
}

impl StopSignal for StopAfterTicks {
    fn stop(&self) -> bool {
        self.state.io_calls.get() >= self.ticks
    }

    fn force(&self) -> bool {
        false
    }

    /// A reload request once the datapath served that many ticks.
    fn take_reload(&self) -> bool {
        let mut reloads = self.reloads.borrow_mut();
        if reloads
            .front()
            .is_some_and(|at| self.state.io_calls.get() >= *at)
        {
            reloads.pop_front();
            return true;
        }
        false
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An ICMPv4 Echo Request from the LAN host to the router's LAN address.
fn echo_request(sequence: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34];
    icmp.extend_from_slice(&sequence.to_be_bytes());
    icmp.extend_from_slice(b"ruster!!");
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let total = u16::try_from(20 + icmp.len()).expect("short");
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 1, 0, 0]);
    ip.extend_from_slice(&[192, 168, 1, 10, 192, 168, 1, 1]);
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    let mut frame = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x10, 0x08, 0x00];
    frame.extend(ip);
    frame.extend(icmp);
    frame.resize(frame.len().max(60), 0);
    frame
}

/// The test config with `edit` applied to its text.
fn edited(edit: impl Fn(String) -> String) -> ValidatedConfigV1 {
    let base = include_str!("../../../../fixtures/m1/router-v1.toml");
    let text = edit(format!("{base}\n{BACKEND}"));
    let parsed = parse(text.as_bytes()).expect("parse");
    match validate(parsed, SIM_VALIDATION_LIMITS) {
        Ok(ValidatedConfig::V1(config)) => config,
        _ => panic!("valid edited config"),
    }
}

fn echo_off() -> ValidatedConfigV1 {
    edited(|text| text.replace("echo-reply = true", "echo-reply = false"))
}

fn ops(host: &FakeHost, source: FakeSource, stop: &impl StopSignal) -> Outcome {
    run_full(
        host,
        settings(CheckPolicy::default(), 0),
        source,
        stop,
        &mut FakeClock {
            step_us: 1_000,
            ..FakeClock::default()
        },
    )
}

fn line_value<'a>(out: &'a str, key: &str) -> Option<&'a str> {
    out.lines()
        .rev()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
}

#[test]
fn a_reload_applies_at_a_tick_boundary_and_changes_the_traffic_outcome() {
    let host = FakeHost::default();
    host.state.inject_at.borrow_mut().extend([
        (1, IfId(LAN), echo_request(1)),
        (20, IfId(LAN), echo_request(2)),
    ]);
    let source = FakeSource::with([Ok(echo_off())]);
    let outcome = ops(
        &host,
        source.clone(),
        &StopAfterTicks::new(&host, 40, &[10]),
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(source.loads.get(), 1);
    assert!(
        outcome
            .err
            .contains("ruster run: reload requested (generation 1)"),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains(
            "ruster run: reload applied: generation=2 previous=1; interfaces=2 addresses=2 \
                 routes=3 neighbors=1 firewall-rules=3 nat44-ports=16; flushed "
        ),
        "{}",
        outcome.err
    );
    // The first echo was answered under generation 1, the second dropped
    // under generation 2 without a restart.
    let out = &outcome.out;
    assert_eq!(line_value(out, "rx.received"), Some("2"), "{out}");
    assert_eq!(line_value(out, "rx.tx_accepted"), Some("1"), "{out}");
    assert!(out.contains("ICMPV4_ECHO_DISABLED=1\n"), "{out}");
    assert_eq!(line_value(out, "observer.generation"), Some("2"), "{out}");
    assert_eq!(line_value(out, "reload.requested"), Some("1"));
    assert_eq!(line_value(out, "reload.applied"), Some("1"));
    assert_eq!(line_value(out, "reload.refused"), Some("0"));
    assert_eq!(line_value(out, "reload.failed"), Some("0"));
    // The same ports kept running: no reopen, one close each.
    let opens = host
        .events()
        .iter()
        .filter(|event| matches!(event, Event::Open(_)))
        .count();
    assert_eq!(opens, 2);
    host.assert_released();
}

#[test]
fn a_restart_required_reload_is_refused_and_traffic_keeps_flowing() {
    let host = FakeHost::default();
    host.state.inject_at.borrow_mut().extend([
        (1, IfId(LAN), echo_request(1)),
        (20, IfId(LAN), echo_request(2)),
        (30, IfId(LAN), echo_request(3)),
    ]);
    let frames = edited(|text| text.replacen("frame-count = 256", "frame-count = 512", 1));
    let mac = edited(|text| text.replacen("02:00:00:00:00:01", "02:00:00:00:00:31", 1));
    let source = FakeSource::with([Ok(frames), Ok(mac)]);
    let outcome = ops(&host, source, &StopAfterTicks::new(&host, 40, &[10, 25]));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(
        outcome.err.contains(
            "ruster run: reload refused: code=RESTART_REQUIRED reasons=BACKEND; \
             generation 1 keeps running"
        ),
        "{}",
        outcome.err
    );
    assert!(
        outcome
            .err
            .contains("reload refused: code=RESTART_REQUIRED reasons=INTERFACES;"),
        "{}",
        outcome.err
    );
    let out = &outcome.out;
    assert_eq!(line_value(out, "rx.tx_accepted"), Some("3"), "{out}");
    assert_eq!(line_value(out, "observer.generation"), Some("1"), "{out}");
    assert_eq!(line_value(out, "reload.refused"), Some("2"));
    assert_eq!(line_value(out, "reload.applied"), Some("0"));
    host.assert_released();
}

#[test]
fn a_failed_reload_keeps_the_old_generation_running() {
    let host = FakeHost::default();
    host.state.inject_at.borrow_mut().extend([
        (1, IfId(LAN), echo_request(1)),
        (30, IfId(LAN), echo_request(2)),
    ]);
    let rejected = LoadError::Rejected(Rejection {
        stage: "validate",
        code: "UNKNOWN_FIELD",
        path: Some("tick.rxx".to_owned()),
        bounds: None,
    });
    // Unreadable, rejected, then (the source is exhausted) unreadable.
    let source = FakeSource::with([
        Err(LoadError::Read(std::io::ErrorKind::PermissionDenied)),
        Err(rejected),
        Err(LoadError::NotAFile),
    ]);
    let outcome = ops(&host, source, &StopAfterTicks::new(&host, 40, &[5, 10, 15]));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    for line in [
        "ruster run: reload failed: stage=read code=PERMISSION_DENIED; generation 1 keeps running",
        "ruster run: reload failed: stage=validate code=UNKNOWN_FIELD path=tick.rxx; \
         generation 1 keeps running",
        "ruster run: reload failed: stage=read code=NOT_A_FILE; generation 1 keeps running",
    ] {
        assert!(outcome.err.contains(line), "{line}\n{}", outcome.err);
    }
    let out = &outcome.out;
    // Echo is still answered by generation 1 after every failure.
    assert_eq!(line_value(out, "rx.tx_accepted"), Some("2"), "{out}");
    assert_eq!(line_value(out, "observer.generation"), Some("1"));
    assert_eq!(line_value(out, "reload.failed"), Some("3"));
    host.assert_released();
}

/// While the backend is not quiescent (TX in flight), a pending reload
/// holds RX back and waits; it applies once the backend settles, and
/// fails without a change after the quiescence bound.
#[test]
fn a_pending_reload_waits_for_quiescence_or_fails_after_the_bound() {
    let host = FakeHost::default();
    host.state.quiesce_blocks.set(5);
    let source = FakeSource::with([Ok(echo_off())]);
    let mut clock = FakeClock {
        step_us: 1_000,
        ..FakeClock::default()
    };
    let outcome = run_full(
        &host,
        settings(CheckPolicy::default(), 0),
        source,
        &StopAfterTicks::new(&host, 20, &[5]),
        &mut clock,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome.err.contains("reload applied: generation=2"));
    assert_eq!(
        host.state.quiesce_probes.get(),
        6,
        "five refusals, then one"
    );
    assert!(clock.pauses >= 5, "RX held back between probes");

    let host = FakeHost::default();
    host.state.quiesce_blocks.set(u32::MAX);
    host.state
        .inject_at
        .borrow_mut()
        .push_back((30, IfId(LAN), echo_request(1)));
    let source = FakeSource::with([Ok(echo_off())]);
    let outcome = ops(&host, source, &StopAfterTicks::new(&host, 40, &[5]));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("reload failed: stage=quiesce code=TIMEOUT; generation 1 keeps running"),
        "{}",
        outcome.err
    );
    assert_eq!(line_value(&outcome.out, "rx.tx_accepted"), Some("1"));
    assert_eq!(line_value(&outcome.out, "observer.generation"), Some("1"));
    // Bounded by RELOAD_QUIESCE_MS of fake time (about 1 ms per probe).
    let probes = host.state.quiesce_probes.get();
    assert!(
        (150..=super::super::reload::RELOAD_QUIESCE_MS as u32 + 5).contains(&probes),
        "{probes}"
    );
}

/// The applied document becomes the current one: its tick budgets apply
/// from the next tick (and the next reload plans against it).
#[test]
fn an_applied_reload_takes_the_new_tick_budgets() {
    let received_in_last_tick = |reload: bool| {
        let host = FakeHost::default();
        // Three requests arrive together in the last tick (30).
        host.state
            .inject_at
            .borrow_mut()
            .extend((1..=3).map(|sequence| (30, IfId(LAN), echo_request(sequence))));
        let one_rx = edited(|text| text.replace("[tick]\nrx = 32", "[tick]\nrx = 1"));
        let source = FakeSource::with([Ok(one_rx)]);
        let reloads: &[u32] = if reload { &[5] } else { &[] };
        let outcome = ops(&host, source, &StopAfterTicks::new(&host, 30, reloads));
        assert_eq!(outcome.status, 0, "{}", outcome.err);
        line_value(&outcome.out, "rx.received").map(str::to_owned)
    };
    assert_eq!(received_in_last_tick(false).as_deref(), Some("3"));
    assert_eq!(received_in_last_tick(true).as_deref(), Some("1"));
}

/// A run that stops while a reload waits ends that reload as failed, so
/// the counters always add up.
#[test]
fn a_reload_pending_at_the_stop_is_reported_failed() {
    let host = FakeHost::default();
    host.state.quiesce_blocks.set(u32::MAX);
    let source = FakeSource::with([Ok(echo_off())]);
    // The stop check comes while the reload waits (well within 200 ms).
    let stop = FakeStop::after(FIRST_LOOP_CHECK + 20);
    let stop = ReloadAt {
        inner: stop,
        at: FIRST_LOOP_CHECK + 3,
    };
    let outcome = ops(&host, source, &stop);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("reload failed: stage=quiesce code=STOPPED; generation 1 keeps running"),
        "{}",
        outcome.err
    );
    let out = &outcome.out;
    assert_eq!(line_value(out, "reload.requested"), Some("1"));
    assert_eq!(line_value(out, "reload.failed"), Some("1"));
    assert_eq!(line_value(out, "reload.applied"), Some("0"));
}

/// Wraps a [`FakeStop`] with one reload request at its `at`-th stop check.
struct ReloadAt {
    inner: FakeStop,
    at: u32,
}

impl StopSignal for ReloadAt {
    fn stop(&self) -> bool {
        self.inner.stop()
    }

    fn force(&self) -> bool {
        self.inner.force()
    }

    fn take_reload(&self) -> bool {
        self.inner.calls.get() == self.at
    }
}

/// `PublicationOutcome::Applied` is authoritative: without a matching
/// commit report the document still becomes current and the outcome says
/// so (the loop then ends as an invariant violation, exit 1).
#[test]
fn an_applied_reload_without_its_report_is_not_kept_running() {
    use super::super::reload::{Reloader, TickApply};
    let sequencer = ProductionSequencer::new(OsRandomKeySource::open().expect("urandom"));
    let mut reloader = Reloader::new(sequencer, config(), FakeSource::default());
    let one_rx = edited(|text| text.replace("[tick]\nrx = 32", "[tick]\nrx = 1"));
    reloader.set_pending_for_test(one_rx);
    let generation = std::num::NonZeroU64::new(2).expect("nonzero");
    let outcome = reloader
        .finish(generation, TickApply::Applied(None))
        .expect("pending");
    let text = outcome.to_string();
    assert!(
        text.starts_with("reload applied: generation=2 previous=unknown;"),
        "{text}"
    );
    assert!(text.ends_with("code=APPLY_REPORT_MISSING"), "{text}");
    assert!(!text.contains("keeps running"));
    assert_eq!(reloader.budgets().rx, 1, "the applied document is current");
    assert_eq!(reloader.counters().applied, 1);
    assert!(reloader.finish(generation, TickApply::NotApplied).is_none());
    let ran = super::super::Ran {
        end: super::super::LoopEnd::Invariant,
        shutdown: super::super::ShutdownReport::default(),
        final_block: String::new(),
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(
        super::super::finished(&ran, 2, &[], &mut out, &mut err),
        EXIT_RUNTIME
    );
    assert!(String::from_utf8(err)
        .expect("utf-8")
        .contains("stopped after an invariant violation code=APPLY_REPORT_MISSING"));
}

/// The loop itself ends a run whose reload tick reports `Applied` without
/// a matching commit report (exit 1), instead of continuing.
#[test]
fn the_loop_ends_on_an_applied_reload_without_its_report() {
    let host = FakeHost::default();
    super::DROP_APPLY_REPORT.with(|flag| flag.set(true));
    let source = FakeSource::with([Ok(echo_off())]);
    let outcome = ops(&host, source, &StopAfterTicks::new(&host, 40, &[5]));
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("reload applied: generation=2 previous=unknown;"),
        "{}",
        outcome.err
    );
    assert!(
        outcome
            .err
            .contains("stopped after an invariant violation code=APPLY_REPORT_MISSING"),
        "{}",
        outcome.err
    );
    assert!(host.state.io_calls.get() < 40, "the loop ended early");
    host.assert_released();
}

/// Kernel forwarding or a port address appearing while attached warns and
/// keeps forwarding through the router (a fatal exit would be what
/// detaches XDP); an exit while it is still seen prints a warning line.
#[test]
fn kernel_exposure_while_running_warns_and_is_reported_at_exit() {
    let on = Forwarding {
        global: true,
        device: false,
    };
    for forwarding in [true, false] {
        let host = FakeHost::default();
        // Seen in every round until the stop.
        for _ in 0..1_000 {
            if forwarding {
                host.state
                    .forwarding
                    .borrow_mut()
                    .push_back((IfId(WAN), Ok(on)));
            } else {
                host.state
                    .addresses
                    .borrow_mut()
                    .push_back((IfId(WAN), Ok(1)));
            }
        }
        host.state
            .inject_at
            .borrow_mut()
            .push_back((10, IfId(LAN), echo_request(1)));
        let outcome = fatal_run(&host, 20);
        assert_eq!(outcome.status, 0, "{}", outcome.err);
        let (code, field, exit_line) = if forwarding {
            (
                "KERNEL_FORWARDING_ENABLED",
                "if2.watch.kernel_forwarding",
                "warning: kernel forwarding is enabled; detached ports may be forwarded by the kernel",
            )
        } else {
            (
                "KERNEL_IPV4_ADDRESSES",
                "if2.watch.kernel_ipv4_addresses",
                "warning: kernel IPv4 addresses are on a port",
            )
        };
        for line in [
            format!("warning: port=if2 health={code}"),
            exit_line.to_owned(),
        ] {
            assert!(outcome.err.contains(&line), "{line}\n{}", outcome.err);
        }
        assert!(!outcome.err.contains("fatal:"), "{}", outcome.err);
        assert!(outcome.err.contains("stopped by signal"));
        let out = &outcome.out;
        assert_eq!(line_value(out, "rx.tx_accepted"), Some("1"), "kept routing");
        assert_eq!(line_value(out, "watch.state"), Some("warning"));
        assert!(
            matches!(line_value(out, field), Some("true" | "1")),
            "{out}"
        );
        host.assert_released();
    }
    // Cleared before the stop: recovered, no exit warning.
    let host = FakeHost::default();
    host.state
        .forwarding
        .borrow_mut()
        .push_back((IfId(WAN), Ok(on)));
    let outcome = fatal_run(&host, 20);
    assert_eq!(outcome.status, 0);
    assert!(outcome
        .err
        .contains("recovered: port=if2 health=KERNEL_FORWARDING_ENABLED"));
    assert!(!outcome.err.contains("kernel forwarding is enabled"));
}

#[test]
fn kernel_forwarding_is_refused_at_startup_unless_allowed() {
    let host = FakeHost {
        forwarding_on: true,
        ..FakeHost::default()
    };
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome.err.contains(
            "startup failed: stage=checks port=if1 code=KERNEL_FORWARDING_ENABLED scope=global"
        ),
        "{}",
        outcome.err
    );
    assert!(!host
        .events()
        .iter()
        .any(|event| matches!(event, Event::Attach(..))));
    host.assert_released();

    let host = FakeHost {
        forwarding_on: true,
        ..FakeHost::default()
    };
    let outcome = run_with(
        &host,
        CheckPolicy {
            allow_kernel_forwarding: true,
            ..CheckPolicy::default()
        },
        &FakeStop::after(FIRST_LOOP_CHECK + 1),
        &mut FakeClock::default(),
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome
        .err
        .contains("warning: port=if1 IPV4_FORWARDING_ENABLED scope=global"));
    host.assert_released();
}

/// A SIGHUP that arrives while a reload is pending is not lost: it is
/// taken after the first one ended.
#[test]
fn reload_requests_are_taken_one_at_a_time() {
    let host = FakeHost::default();
    host.state.quiesce_blocks.set(3);
    let source = FakeSource::with([Ok(echo_off()), Ok(config())]);
    let outcome = ops(
        &host,
        source.clone(),
        &StopAfterTicks::new(&host, 40, &[5, 5]),
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(source.loads.get(), 2);
    assert!(outcome
        .err
        .contains("reload applied: generation=2 previous=1"));
    assert!(outcome
        .err
        .contains("reload applied: generation=3 previous=2"));
}

fn fatal_run(host: &FakeHost, ticks: u32) -> Outcome {
    ops(
        host,
        FakeSource::default(),
        &StopAfterTicks::new(host, ticks, &[]),
    )
}

fn assert_fatal(outcome: &Outcome, host: &FakeHost, code: &str) {
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains(&format!("ruster run: fatal: port=if2 health={code}")),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains(&format!(
            "stopped after a fatal health event port=if2 code={code}; drain calls=1"
        )),
        "{}",
        outcome.err
    );
    assert!(host
        .events()
        .iter()
        .any(|event| matches!(event, Event::Drain(_))));
    host.assert_released();
    assert!(outcome.out.contains("ruster-run-stats kind=final"));
}

#[test]
fn device_removal_and_mtu_violations_fail_closed_with_exit_1() {
    let facts = |mtu| {
        Ok(LinkFacts {
            mtu,
            rx_queues: Some(1),
            admin_up: true,
            lower_up: true,
        })
    };
    for (result, code) in [
        (Err(NetlinkError::Kernel(-19)), "DEVICE_REMOVED"),
        (facts(9_000), "MTU_ABOVE_FRAME"),
        (facts(1_400), "MTU_DECREASED"),
    ] {
        let host = FakeHost::default();
        host.state.links.borrow_mut().push_back((IfId(WAN), result));
        let outcome = fatal_run(&host, 1_000);
        assert_fatal(&outcome, &host, code);
        assert!(host.state.io_calls.get() < 5, "{code}: ended at once");
    }
}

#[test]
fn a_link_down_and_up_keeps_running_and_is_counted() {
    let host = FakeHost::default();
    let down = Ok(LinkFacts {
        mtu: 1500,
        rx_queues: Some(1),
        admin_up: false,
        lower_up: false,
    });
    {
        let mut links = host.state.links.borrow_mut();
        links.push_back((IfId(LAN), down));
        links.push_back((IfId(LAN), down));
    }
    // A raised MTU within the frame bound only warns.
    let raised = Ok(LinkFacts {
        mtu: 1600,
        rx_queues: Some(1),
        admin_up: true,
        lower_up: true,
    });
    host.state.links.borrow_mut().push_back((IfId(WAN), raised));
    host.state
        .inject_at
        .borrow_mut()
        .push_back((10, IfId(LAN), echo_request(1)));
    let outcome = fatal_run(&host, 20);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    for line in [
        "ruster run: warning: port=if1 health=LINK_DOWN",
        "ruster run: recovered: port=if1 health=LINK_DOWN",
        "ruster run: warning: port=if2 health=MTU_RAISED",
        "ruster run: recovered: port=if2 health=MTU_RAISED",
    ] {
        assert!(outcome.err.contains(line), "{line}\n{}", outcome.err);
    }
    let out = &outcome.out;
    assert_eq!(line_value(out, "if1.watch.link_down_events"), Some("1"));
    assert_eq!(line_value(out, "if1.watch.link_up_events"), Some("1"));
    assert_eq!(line_value(out, "if1.watch.link_up"), Some("true"));
    assert_eq!(line_value(out, "if2.watch.mtu"), Some("1500"));
    assert_eq!(line_value(out, "if2.watch.warnings"), Some("1"));
    assert_eq!(line_value(out, "watch.state"), Some("ok"));
    assert_eq!(line_value(out, "watch.warnings"), Some("2"));
    assert_eq!(line_value(out, "rx.tx_accepted"), Some("1"), "recovered");
    host.assert_released();
}

#[test]
fn a_persistent_tx_stall_fails_closed_with_exit_1() {
    let host = FakeHost::default();
    // The same oldest frame in flight on every sample (stamp 0).
    let rounds = (1..=200_u64).map(|polls| {
        vec![PortSample {
            interface: IfId(WAN),
            polls,
            tx_inflight: 1,
            oldest_age_polls: polls,
            kick_errors: 0,
            kick_link_down: false,
            fill_starved: 0,
            fill_ring_occupancy: 8,
            rx_packets: 0,
        }]
    });
    host.state.samples.borrow_mut().extend(rounds);
    let outcome = run_full(
        &host,
        settings(CheckPolicy::default(), 0),
        FakeSource::default(),
        &StopAfterTicks::new(&host, 1_000, &[]),
        &mut FakeClock {
            step_us: 100_000,
            ..FakeClock::default()
        },
    );
    assert!(outcome
        .err
        .contains("ruster run: warning: port=if2 health=TX_STALL"));
    assert_fatal(&outcome, &host, "TX_STALL");
    // Roughly the fatal bound of fake time, at 100 ms per clock reading.
    let ticks = u64::from(host.state.io_calls.get());
    assert!(
        ticks * 100 >= TX_STALL_FATAL_MS - TX_STALL_WARN_MS,
        "{ticks}"
    );
}

/// A TX handoff the drain could not cancel is reported and makes the run
/// unclean (exit 1) even though nothing is left in the kernel.
#[test]
fn a_stranded_tx_handoff_after_the_drain_exits_1() {
    let host = FakeHost::default();
    host.script_drains([Ok(DrainProgress {
        tx_handoffs: 2,
        ..DrainProgress::default()
    })]);
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("stopped by signal; drain calls=1 completed=0 rx-released=0 tx-in-flight=0 tx-handoffs=2 "),
        "{}",
        outcome.err
    );
    host.assert_released();
}

#[test]
fn transient_open_failures_retry_after_a_full_rollback() {
    let host = FakeHost::default();
    host.state.transient_open.set(Some((WAN, 2)));
    let mut clock = FakeClock {
        step_us: 1_000,
        ..FakeClock::default()
    };
    let outcome = run_full(
        &host,
        settings(CheckPolicy::default(), 0),
        FakeSource::default(),
        &StopAfterTicks::new(&host, 3, &[]),
        &mut clock,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    for line in [
        "ruster run: startup attempt 1 of 3 failed: stage=open port=if2 \
         code=INJECTED_TRANSIENT; rolled back 1 port(s), retrying in 250 ms",
        "ruster run: startup attempt 2 of 3 failed: stage=open port=if2 \
         code=INJECTED_TRANSIENT; rolled back 1 port(s), retrying in 500 ms",
    ] {
        assert!(outcome.err.contains(line), "{line}\n{}", outcome.err);
    }
    assert!(outcome.err.contains(READY));
    // Each failed attempt closed the attached LAN port before the next.
    let events = host.events();
    let attempt = [
        Event::Open(LAN),
        Event::Inspect(LAN),
        Event::Attach(LAN, GENERIC),
        Event::Open(WAN),
        Event::Close {
            port: LAN,
            attached: true,
        },
    ];
    assert_eq!(&events[1..6], &attempt);
    assert_eq!(&events[6..11], &attempt);
    assert_eq!(events[11], Event::Open(LAN));
    host.assert_released();

    // Exhausted: the last failure is reported, fully rolled back.
    let host = FakeHost::default();
    host.state.transient_open.set(Some((WAN, u32::MAX)));
    let outcome = run(&host, &FakeStop::after(u32::MAX));
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(outcome
        .err
        .contains("startup failed: stage=open port=if2 code=INJECTED_TRANSIENT"));
    let opens = host
        .events()
        .iter()
        .filter(|event| **event == Event::Open(WAN))
        .count();
    assert_eq!(opens, 3, "default attempts");
    host.assert_released();
}

#[test]
fn non_transient_failures_and_a_single_attempt_never_retry() {
    let host = FakeHost::failing(Stage::Open, Some(WAN));
    let outcome = run(&host, &FakeStop::after(u32::MAX));
    assert_eq!(outcome.status, EXIT_RUNTIME);
    assert!(!outcome.err.contains("startup attempt"));
    let count = |host: &FakeHost| {
        host.events()
            .iter()
            .filter(|event| **event == Event::Open(WAN))
            .count()
    };
    assert_eq!(count(&host), 1);

    let host = FakeHost::default();
    host.state.transient_open.set(Some((WAN, 1)));
    let outcome = run_full(
        &host,
        Settings {
            startup_attempts: 1,
            ..settings(CheckPolicy::default(), 0)
        },
        FakeSource::default(),
        &FakeStop::after(u32::MAX),
        &mut FakeClock::default(),
    );
    assert_eq!(outcome.status, EXIT_RUNTIME);
    assert_eq!(count(&host), 1);
    host.assert_released();
}

#[test]
fn a_signal_during_the_retry_pause_cancels_after_the_rollback() {
    let host = FakeHost::default();
    host.state.transient_open.set(Some((WAN, u32::MAX)));
    // Calls 1-3 are the open checks of attempt 1 (LAN, LAN, WAN); the
    // pause's first check stops.
    let outcome = run(&host, &FakeStop::after(4));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome
        .err
        .contains("startup cancelled by signal; rolled back 1 port(s)"));
    host.assert_released();
}

#[test]
fn only_deferred_release_failures_are_transient() {
    use SessionFailure as F;
    use SessionStage as S;
    assert!(transient_open(S::Bind, F::Busy));
    assert!(transient_open(S::RegisterUmem, F::MemlockLimit));
    assert!(transient_open(S::RegisterUmem, F::OutOfMemory));
    assert!(transient_open(S::OpenSocket, F::Errno(11)));
    for (stage, failure) in [
        (S::Bind, F::InvalidArgument),
        (S::Bind, F::PermissionDenied),
        (S::Bind, F::MemlockLimit),
        (S::RegisterUmem, F::Busy),
        (S::InterfaceLookup, F::NoSuchDevice),
        (S::TxQueueCheck, F::NoTxQueue),
        (S::OpenSocket, F::Unsupported),
        (S::Bind, F::Errno(105)),
        (S::MapUmem, F::OutOfMemory),
    ] {
        assert!(!transient_open(stage, failure), "{stage:?} {failure:?}");
    }
    assert!(!Failure::Injected.is_transient());
    assert!(Failure::InjectedTransient.is_transient());
    assert_eq!(retry_pause_ms(2), 250);
    assert_eq!(retry_pause_ms(3), 500);
    assert_eq!(retry_pause_ms(4), 1_000);
    assert_eq!(retry_pause_ms(5), STARTUP_RETRY_PAUSE_MAX_MS);
    assert_eq!(retry_pause_ms(10), STARTUP_RETRY_PAUSE_MAX_MS);
    assert_eq!(retry_pause_ms(u32::MAX), STARTUP_RETRY_PAUSE_MAX_MS);
}

/// Kernel IPv6 on a port and an IPv4 route in any table are refused
/// before attach with every port rolled back; `--allow-kernel-ipv6`
/// starts with warnings (and does not cover the IPv4 route).
#[test]
fn kernel_ipv6_and_routes_are_refused_at_startup_unless_allowed() {
    let exposed = Ipv6Facts {
        addresses: Some(1),
        forwarding_global: Some(true),
        ..Ipv6Facts::CLEAN
    };
    let cases = [
        (
            FakeHost {
                ipv6: Some(exposed),
                ..FakeHost::default()
            },
            "code=KERNEL_IPV6_ADDRESSES count=1",
        ),
        (
            FakeHost {
                ipv6: Some(Ipv6Facts {
                    routes: Some(2),
                    ..Ipv6Facts::CLEAN
                }),
                ..FakeHost::default()
            },
            "code=KERNEL_IPV6_ROUTES count=2",
        ),
        (
            FakeHost {
                ipv6: Some(Ipv6Facts {
                    forwarding_device: Some(true),
                    ..Ipv6Facts::CLEAN
                }),
                ..FakeHost::default()
            },
            "code=KERNEL_IPV6_FORWARDING_ENABLED scope=device",
        ),
        (
            FakeHost {
                ipv6: Some(Ipv6Facts {
                    routes: None,
                    ..Ipv6Facts::CLEAN
                }),
                ..FakeHost::default()
            },
            "code=UNVERIFIABLE probe=ipv6-routes",
        ),
        (
            FakeHost {
                ipv4_routes: 1,
                ..FakeHost::default()
            },
            "code=KERNEL_IPV4_ROUTES count=1",
        ),
    ];
    for (host, code) in &cases {
        let outcome = run(host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
        assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
        let line = format!("startup failed: stage=checks port=if1 {code}");
        assert!(outcome.err.contains(&line), "{line}\n{}", outcome.err);
        assert!(!host
            .events()
            .iter()
            .any(|event| matches!(event, Event::Attach(..))));
        host.assert_released();
    }
    // Disabled on the ports: the same exposure does not matter.
    let host = FakeHost {
        ipv6: Some(Ipv6Facts {
            disabled: Some(true),
            ..exposed
        }),
        ..FakeHost::default()
    };
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(!outcome.err.contains("IPV6"), "{}", outcome.err);
    host.assert_released();
    // The override.
    let allowed = CheckPolicy {
        allow_kernel_ipv6: true,
        ..CheckPolicy::default()
    };
    let host = FakeHost {
        ipv6: Some(exposed),
        ..FakeHost::default()
    };
    let outcome = run_with(
        &host,
        allowed,
        &FakeStop::after(FIRST_LOOP_CHECK + 1),
        &mut FakeClock::default(),
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    for line in [
        "warning: port=if1 IPV6_ADDRESSES_ALLOWED count=1",
        "warning: port=if1 IPV6_FORWARDING_ENABLED scope=global",
        "warning: port=if2 IPV6_ADDRESSES_ALLOWED count=1",
    ] {
        assert!(outcome.err.contains(line), "{line}\n{}", outcome.err);
    }
    host.assert_released();
    let host = FakeHost {
        ipv4_routes: 1,
        ..FakeHost::default()
    };
    let outcome = run_with(
        &host,
        CheckPolicy {
            allow_kernel_forwarding: true,
            allow_multi_queue: true,
            ..allowed
        },
        &FakeStop::after(FIRST_LOOP_CHECK + 1),
        &mut FakeClock::default(),
    );
    assert_eq!(outcome.status, EXIT_RUNTIME, "no override for IPv4 routes");
    host.assert_released();
}

/// IPv4 routes and kernel IPv6 appearing while attached warn, keep the
/// router forwarding, show in the stats, and print one exit line per
/// kind still seen at the stop.
#[test]
fn kernel_routes_and_ipv6_while_running_warn_and_are_reported_at_exit() {
    let exposed = Ipv6Sample {
        disabled: Ok(false),
        addresses: Ok(1),
        routes: Ok(1),
        forwarding: Ok(Forwarding {
            global: true,
            device: false,
        }),
    };
    let host = FakeHost::default();
    for _ in 0..1_000 {
        host.state.routes.borrow_mut().push_back((IfId(WAN), Ok(2)));
        host.state.ipv6.borrow_mut().push_back((IfId(WAN), exposed));
    }
    host.state
        .inject_at
        .borrow_mut()
        .push_back((10, IfId(LAN), echo_request(1)));
    let outcome = fatal_run(&host, 20);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    for line in [
        "warning: port=if2 health=KERNEL_IPV4_ROUTES",
        "warning: port=if2 health=KERNEL_IPV6_ADDRESSES",
        "warning: port=if2 health=KERNEL_IPV6_ROUTES",
        "warning: port=if2 health=KERNEL_IPV6_FORWARDING_ENABLED",
        "warning: kernel IPv4 routes lead out of a port; detached ports may be routed by the kernel",
        "warning: kernel IPv6 forwarding is enabled for a port; detached ports may be forwarded by the kernel",
        "warning: kernel IPv6 addresses are on a port; detached ports may be answered and routed by the kernel",
        "warning: kernel IPv6 routes lead out of a port; detached ports may be routed by the kernel",
    ] {
        assert!(outcome.err.contains(line), "{line}\n{}", outcome.err);
    }
    assert!(!outcome.err.contains("fatal:"), "{}", outcome.err);
    assert!(!outcome.err.contains("kernel forwarding is enabled"));
    assert!(!outcome.err.contains("port=if1 health=KERNEL"));
    let out = &outcome.out;
    assert_eq!(line_value(out, "rx.tx_accepted"), Some("1"), "kept routing");
    assert_eq!(line_value(out, "watch.state"), Some("warning"));
    for (field, value) in [
        ("if2.watch.kernel_ipv4_routes", "2"),
        ("if2.watch.kernel_ipv6_addresses", "1"),
        ("if2.watch.kernel_ipv6_routes", "1"),
        ("if2.watch.kernel_ipv6_forwarding", "true"),
        ("if1.watch.kernel_ipv6_forwarding", "false"),
    ] {
        assert_eq!(line_value(out, field), Some(value), "{field}\n{out}");
    }
    host.assert_released();
    // Disabled on the port before the stop: recovered, no exit line.
    let host = FakeHost::default();
    host.state.ipv6.borrow_mut().push_back((IfId(WAN), exposed));
    for _ in 0..1_000 {
        host.state
            .ipv6
            .borrow_mut()
            .push_back((IfId(WAN), Ipv6Sample::DISABLED));
    }
    let outcome = fatal_run(&host, 20);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome
        .err
        .contains("recovered: port=if2 health=KERNEL_IPV6_ADDRESSES"));
    assert!(!outcome.err.contains("kernel IPv6"), "{}", outcome.err);
}

/// An IPv6 fact that stays unreadable while running ends the run with
/// `LINK_UNVERIFIABLE` (lost observability fails closed), unless the run
/// was started with `--allow-kernel-ipv6`, which only warns.
#[test]
fn unreadable_ipv6_while_running_is_fatal_unless_allowed() {
    let unreadable = Ipv6Sample {
        disabled: Err(()),
        addresses: Ok(0),
        routes: Ok(0),
        forwarding: Ok(Forwarding::default()),
    };
    let script = |host: &FakeHost| {
        for _ in 0..1_000 {
            host.state
                .ipv6
                .borrow_mut()
                .push_back((IfId(WAN), unreadable));
        }
    };
    let host = FakeHost::default();
    script(&host);
    let outcome = fatal_run(&host, 20);
    assert_fatal(&outcome, &host, "LINK_UNVERIFIABLE");

    let host = FakeHost::default();
    script(&host);
    let outcome = run_full(
        &host,
        settings(
            CheckPolicy {
                allow_kernel_ipv6: true,
                ..CheckPolicy::default()
            },
            0,
        ),
        FakeSource::default(),
        &StopAfterTicks::new(&host, 20, &[]),
        &mut FakeClock {
            step_us: 1_000,
            ..FakeClock::default()
        },
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome
        .err
        .contains("warning: port=if2 health=IPV6_UNVERIFIABLE"));
    assert!(!outcome.err.contains("fatal:"), "{}", outcome.err);
    host.assert_released();
}

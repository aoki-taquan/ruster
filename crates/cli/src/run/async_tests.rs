//! `ruster run` with its worker threads running asynchronously, as in
//! production (H7): the router keeps ticking while a reload is prepared
//! or a link round is stuck.

use std::io::Write;
use std::time::Instant;

use super::ops::{echo_off, echo_request, line_value};
use super::*;

/// stderr shared between the run and its stop signal.
#[derive(Clone, Default)]
struct SharedText(Arc<Mutex<Vec<u8>>>);

impl SharedText {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8")
    }
}

impl Write for SharedText {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `execute` with asynchronous workers.
fn run_async(
    host: &FakeHost,
    source: FakeSource,
    settings: Settings,
    stop: &impl StopSignal,
    err: &mut SharedText,
) -> (u8, String) {
    ASYNC_WORKERS.with(|flag| flag.set(true));
    let mut out = Vec::new();
    let status = execute_with(
        host,
        config(),
        source,
        settings,
        &mut FakeClock {
            step_us: 1_000,
            ..FakeClock::default()
        },
        stop,
        &mut out,
        err,
    );
    (status, String::from_utf8(out).expect("utf-8"))
}

/// Settings with link rounds every tick that never go stale (the stale
/// rule has its own tests; here fake time runs far ahead of the
/// watcher's real time).
fn never_stale() -> Settings {
    Settings {
        link_stale_ms: u64::MAX / 2,
        ..settings(CheckPolicy::default(), 0)
    }
}

/// Fails the test instead of hanging when an expected event never comes.
fn within(started: Instant, what: &str) {
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "timed out waiting for {what}"
    );
}

/// The reload's read (and parse) blocks on the worker; meanwhile the
/// router thread keeps ticking and answering traffic under generation 1.
/// Released, the prepared candidate is applied at a tick boundary and
/// changes the traffic outcome.
struct HeldReload {
    state: Rc<State>,
    source: FakeSource,
    err: SharedText,
    started: Instant,
    held_until_tick: u32,
    /// Ticks served when the hold was released, and when the reload was
    /// seen applied.
    released_at: Cell<Option<u32>>,
    applied_at: Cell<Option<u32>>,
}

impl StopSignal for HeldReload {
    fn stop(&self) -> bool {
        within(self.started, "the reload");
        let ticks = self.state.io_calls.get();
        if self.released_at.get().is_none() && ticks >= self.held_until_tick {
            // The worker took the request and is still held.
            while self.source.loads.load(Ordering::SeqCst) == 0 {
                within(self.started, "the worker's load");
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(self.source.loads.load(Ordering::SeqCst), 1);
            assert!(!self.err.text().contains("reload applied"));
            self.released_at.set(Some(ticks));
            self.source.hold.store(false, Ordering::SeqCst);
        }
        if self.applied_at.get().is_none() && self.err.text().contains("reload applied") {
            self.applied_at.set(Some(ticks));
        }
        self.applied_at.get().is_some_and(|at| ticks >= at + 40)
    }

    fn force(&self) -> bool {
        false
    }

    fn take_reload(&self) -> bool {
        self.state.io_calls.get() == 5
    }
}

#[test]
fn traffic_flows_while_a_reload_is_prepared_and_it_applies_at_a_boundary() {
    let host = FakeHost::default();
    host.state
        .inject_at
        .borrow_mut()
        .extend((0..1_000_u32).map(|i| {
            (
                1 + i * 10,
                IfId(LAN),
                echo_request(u16::try_from(i).unwrap()),
            )
        }));
    let source = FakeSource::with([Ok(echo_off())]);
    source.hold.store(true, Ordering::SeqCst);
    let mut err = SharedText::default();
    let stop = HeldReload {
        state: Rc::clone(&host.state),
        source: source.clone(),
        err: err.clone(),
        started: Instant::now(),
        held_until_tick: 200,
        released_at: Cell::new(None),
        applied_at: Cell::new(None),
    };
    let (status, out) = run_async(&host, source.clone(), never_stale(), &stop, &mut err);
    let text = err.text();
    assert_eq!(status, 0, "{text}");
    assert!(
        text.contains("ruster run: reload applied: generation=2 previous=1;"),
        "{text}"
    );
    // 200 ticks ran while the worker held the read; the 20 echoes injected
    // meanwhile were all answered by generation 1.
    assert_eq!(stop.released_at.get(), Some(200));
    let accepted: u64 = line_value(&out, "rx.tx_accepted")
        .and_then(|value| value.parse().ok())
        .expect("rx.tx_accepted");
    assert!(accepted >= 20, "{out}");
    // After the switch the echoes are dropped (echo off).
    assert!(out.contains("ICMPV4_ECHO_DISABLED="), "{out}");
    assert_eq!(line_value(&out, "observer.generation"), Some("2"));
    assert_eq!(line_value(&out, "reload.requested"), Some("1"));
    assert_eq!(line_value(&out, "reload.applied"), Some("1"));
    host.assert_released();
}

/// A reload still preparing when the run stops fails as `STOPPED` (the
/// counters add up), and the held worker does not hold the exit: it is
/// abandoned after the bound.
#[test]
fn a_reload_preparing_at_the_stop_is_stopped_and_the_worker_abandoned() {
    struct StopWhileHeld {
        state: Rc<State>,
        source: FakeSource,
        started: Instant,
    }
    impl StopSignal for StopWhileHeld {
        fn stop(&self) -> bool {
            within(self.started, "the held load");
            self.state.io_calls.get() >= 50 && self.source.loads.load(Ordering::SeqCst) == 1
        }
        fn force(&self) -> bool {
            false
        }
        fn take_reload(&self) -> bool {
            self.state.io_calls.get() == 5
        }
    }
    let host = FakeHost::default();
    let source = FakeSource::with([Ok(echo_off())]);
    source.hold.store(true, Ordering::SeqCst);
    let stop = StopWhileHeld {
        state: Rc::clone(&host.state),
        source: source.clone(),
        started: Instant::now(),
    };
    let mut err = SharedText::default();
    let started = Instant::now();
    let (status, out) = run_async(&host, source.clone(), never_stale(), &stop, &mut err);
    let elapsed = started.elapsed();
    source.hold.store(false, Ordering::SeqCst);
    let text = err.text();
    assert_eq!(status, 0, "{text}");
    assert!(
        text.contains("reload failed: stage=prepare code=STOPPED; generation 1 keeps running"),
        "{text}"
    );
    assert!(
        text.contains(
            "warning: the reload worker thread did not end within 500 ms after the loop; \
             abandoned"
        ),
        "{text}"
    );
    assert!(
        !text.contains("the link watcher thread did not end"),
        "{text}"
    );
    assert!(elapsed < Duration::from_secs(20), "{elapsed:?}");
    assert_eq!(line_value(&out, "reload.requested"), Some("1"));
    assert_eq!(line_value(&out, "reload.failed"), Some("1"));
    assert_eq!(line_value(&out, "reload.applied"), Some("0"));
    host.assert_released();
}

/// Stops after `ticks` ticks; at `open_at` opens the link gate and waits
/// until the stuck round's queries ran.
struct GateStop {
    state: Rc<State>,
    ticks: u32,
    open_at: Option<u32>,
    started: Instant,
}

impl StopSignal for GateStop {
    fn stop(&self) -> bool {
        within(self.started, "the run");
        let ticks = self.state.io_calls.get();
        if self.open_at == Some(ticks) {
            self.state.link_gate.borrow_mut().closed = false;
            while *self.state.link_queries.borrow_mut() < 2 {
                within(self.started, "the released round");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if ticks < self.ticks {
            return false;
        }
        // With the gate opened, run on until the watcher ran three rounds
        // (one outstanding at a time, so the router took back at least
        // two) before stopping.
        self.open_at.is_none() || *self.state.link_queries.borrow_mut() >= 6
    }

    fn force(&self) -> bool {
        false
    }
}

/// A link watcher stuck in a round (RTNL held) does not stop forwarding;
/// once the round is older than the stale threshold each due round is a
/// failed link query, and the third ends the run (fail closed) without
/// waiting for the stuck thread.
#[test]
fn a_stuck_link_watcher_goes_stale_and_fails_closed_while_traffic_flows() {
    let host = FakeHost::default();
    host.state.link_gate.borrow_mut().closed = true;
    host.state
        .inject_at
        .borrow_mut()
        .extend((0..100_u32).map(|i| {
            (
                1 + i * 2,
                IfId(LAN),
                echo_request(u16::try_from(i).unwrap()),
            )
        }));
    let settings = Settings {
        link_interval_ms: 10,
        link_stale_ms: 50,
        ..settings(CheckPolicy::default(), 0)
    };
    let stop = GateStop {
        state: Rc::clone(&host.state),
        ticks: 100_000,
        open_at: None,
        started: Instant::now(),
    };
    let mut err = SharedText::default();
    let started = Instant::now();
    let (status, out) = run_async(&host, FakeSource::default(), settings, &stop, &mut err);
    let elapsed = started.elapsed();
    host.state.link_gate.borrow_mut().closed = false;
    let text = err.text();
    assert_eq!(status, EXIT_RUNTIME, "{text}");
    for line in [
        "ruster run: warning: port=if1 health=LINK_WATCH_STALE",
        "ruster run: warning: port=if2 health=LINK_WATCH_STALE",
        "ruster run: warning: port=if1 health=LINK_PROBE",
        "ruster run: fatal: port=if1 health=LINK_UNVERIFIABLE",
        "stopped after a fatal health event port=if1 code=LINK_UNVERIFIABLE",
        "warning: the link watcher thread did not end within 500 ms after the loop; abandoned",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    assert!(elapsed < Duration::from_secs(20), "{elapsed:?}");
    assert_eq!(line_value(&out, "watch.link_rounds"), Some("0"), "{out}");
    assert_eq!(
        line_value(&out, "watch.link_rounds_stale"),
        Some("3"),
        "{out}"
    );
    // Fake time: stale from 50 ms, fatal at the third stale round, about
    // 70 ms after the stuck request; traffic was answered all along.
    let ticks = host.state.io_calls.get();
    assert!((40..1_000).contains(&ticks), "{ticks}");
    let accepted: u64 = line_value(&out, "rx.tx_accepted")
        .and_then(|value| value.parse().ok())
        .expect("rx.tx_accepted");
    assert!(accepted >= 15, "{out}");
    host.assert_released();
}

/// A watcher stall shorter than the stale threshold costs late rounds
/// only: no warning, no fatal, and the rounds resume.
#[test]
fn a_brief_link_watcher_stall_costs_only_late_rounds() {
    let host = FakeHost::default();
    host.state.link_gate.borrow_mut().closed = true;
    let settings = Settings {
        link_interval_ms: 10,
        ..never_stale()
    };
    let stop = GateStop {
        state: Rc::clone(&host.state),
        ticks: 400,
        open_at: Some(100),
        started: Instant::now(),
    };
    let mut err = SharedText::default();
    let (status, out) = run_async(&host, FakeSource::default(), settings, &stop, &mut err);
    let text = err.text();
    assert_eq!(status, 0, "{text}");
    assert!(!text.contains("LINK_WATCH_STALE"), "{text}");
    assert!(!text.contains("LINK_PROBE"), "{text}");
    let count = |key| -> u64 {
        line_value(&out, key)
            .and_then(|value| value.parse().ok())
            .expect(key)
    };
    assert!(count("watch.link_rounds_late") >= 5, "{out}");
    assert!(count("watch.link_rounds") >= 2, "{out}");
    assert_eq!(count("watch.link_rounds_stale"), 0);
    assert_eq!(line_value(&out, "watch.state"), Some("ok"));
    host.assert_released();
}

/// A worker thread whose privilege drop (prologue) fails fails startup
/// before the process-wide drop and before any tick, with a full
/// rollback.
#[test]
fn a_worker_whose_drop_fails_rolls_back_before_the_lockdown() {
    let host = FakeHost::failing(Stage::Workers, None);
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 3));
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("ruster run: startup failed: stage=privilege-drop code=INJECTED\n"),
        "{}",
        outcome.err
    );
    assert!(host.state.lockdowns.borrow().is_empty(), "no lockdown");
    assert_eq!(host.state.io_calls.get(), 0, "no tick");
    assert!(!outcome.err.contains(READY));
    host.assert_released();
}

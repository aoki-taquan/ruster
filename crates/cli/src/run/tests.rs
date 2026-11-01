//! `ruster run` startup, loop, and shutdown over a scripted host whose
//! datapath is `SimIo`, with a scripted clock and stop source.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use ruster_config::{
    parse, validate, ValidatedAfXdpPortV1, ValidatedAfXdpV1, ValidatedConfig, ValidatedConfigV1,
    XdpAttachModeV1,
};
use ruster_control::{OsRandomKeySource, ProductionSequencer};
use ruster_core::{IfId, MonotonicMillis};
use ruster_io_sim::SimIo;
use ruster_io_xdp_native::XdpIoError;
use ruster_sim_scenario::SIM_VALIDATION_LIMITS;

use ruster_core::PublicationQuiescenceDisposition;

use super::checks::{
    required_memlock, CheckFailure, CheckPolicy, DeviceFacts, PrivilegeFailure, Probe,
};
use super::engine::{
    Clock, Datapath, DrainProgress, IdleBackoff, LinkMonitor, StopSignal, DRAIN_DEADLINE_MS,
    DRAIN_ROUNDS, MAX_PAUSE, MIN_PAUSE, SPIN_TICKS,
};
use super::netlink::{LinkFacts, NetlinkError};
use super::reload::ConfigSource;
use super::startup::{CloseFailure, Failure, OpenPort, PortHost, Stage, StartupError};
use super::watch::{LinkTarget, PortSample};
use super::{execute, Settings, EXIT_DRAIN_INCOMPLETE, EXIT_PRIVILEGE, READY};
use crate::config_cmd::LoadError;
use crate::{EXIT_INVALID, EXIT_RUNTIME};

const LAN: u16 = 1;
const WAN: u16 = 2;

const BACKEND: &str = r#"
[backend]
kind = "af-xdp"

[[backend.ports]]
interface = "wan"
queue = 0
mode = "auto"
xdp-attach = "native"
rings = { fill = 64, rx = 64, tx = 64, completion = 64 }
frame-size = 2048
frame-count = 256
generated-frames = 64

[[backend.ports]]
interface = "lan"
queue = 0
mode = "copy"
xdp-attach = "generic"
rings = { fill = 64, rx = 64, tx = 64, completion = 64 }
frame-size = 2048
frame-count = 256
generated-frames = 64
"#;

fn config_with(extra: &str) -> ValidatedConfigV1 {
    let base = include_str!("../../../../fixtures/m1/router-v1.toml");
    let text = format!("{base}\n{extra}");
    let parsed = parse(text.as_bytes()).expect("parse");
    match validate(parsed, SIM_VALIDATION_LIMITS) {
        Ok(ValidatedConfig::V1(config)) => config,
        _ => panic!("valid config"),
    }
}

fn config() -> ValidatedConfigV1 {
    config_with(BACKEND)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Preflight,
    Open(u16),
    Inspect(u16),
    Attach(u16, XdpAttachModeV1),
    Datapath(u16),
    Engine(u16),
    Adapter,
    Drain(u32),
    Close { port: u16, attached: bool },
}

#[derive(Default)]
struct State {
    events: RefCell<Vec<Event>>,
    live: Cell<u32>,
    attached: Cell<u32>,
    drains: RefCell<VecDeque<Result<DrainProgress, XdpIoError>>>,
    inject: RefCell<Vec<(IfId, Vec<u8>)>>,
    /// Frames injected when the datapath's `io()` call number (1-based,
    /// one per tick) reaches the first field.
    inject_at: RefCell<VecDeque<(u32, IfId, Vec<u8>)>>,
    io_calls: Cell<u32>,
    /// Health sample rounds handed out by `sample_ports`, one per call.
    samples: RefCell<VecDeque<Vec<PortSample>>>,
    /// Link query results, consumed in order by the matching port.
    links: RefCell<VecDeque<(IfId, Result<LinkFacts, NetlinkError>)>>,
    link_queries: Cell<u32>,
    /// Quiescence probes refused before one succeeds.
    quiesce_blocks: Cell<u32>,
    quiesce_probes: Cell<u32>,
    /// Transient open failures still to inject for this port.
    transient_open: Cell<Option<(u16, u32)>>,
}

impl State {
    fn push(&self, event: Event) {
        self.events.borrow_mut().push(event);
    }
}

#[derive(Default)]
struct FakeHost {
    state: Rc<State>,
    fail: Option<(Stage, Option<u16>)>,
    multi_queue: Option<u16>,
    privilege: Option<PrivilegeFailure>,
    close_fails: Option<u16>,
    panic_in_build: bool,
}

impl FakeHost {
    fn failing(stage: Stage, port: Option<u16>) -> Self {
        Self {
            fail: Some((stage, port)),
            ..Self::default()
        }
    }

    fn fails(&self, stage: Stage, port: Option<u16>) -> bool {
        self.fail == Some((stage, port))
    }

    fn events(&self) -> Vec<Event> {
        self.state.events.borrow().clone()
    }

    fn script_drains(&self, drains: impl IntoIterator<Item = Result<DrainProgress, XdpIoError>>) {
        self.state.drains.borrow_mut().extend(drains);
    }

    /// Every opened session was closed and none is left attached.
    fn assert_released(&self) {
        assert_eq!(self.state.live.get(), 0, "sessions left open");
        assert_eq!(self.state.attached.get(), 0, "XDP left attached");
    }
}

struct FakeSession {
    interface: IfId,
    attached: bool,
}

struct FakeDatapath<'s> {
    ports: &'s mut [OpenPort<FakeSession>],
    state: Rc<State>,
    io: SimIo,
}

impl Datapath for FakeDatapath<'_> {
    type Io = SimIo;

    fn io(&mut self) -> &mut SimIo {
        let call = self.state.io_calls.get() + 1;
        self.state.io_calls.set(call);
        let mut scheduled = self.state.inject_at.borrow_mut();
        while scheduled.front().is_some_and(|(at, _, _)| *at <= call) {
            if let Some((_, ingress, bytes)) = scheduled.pop_front() {
                self.io.inject(ingress, bytes);
            }
        }
        &mut self.io
    }

    fn sample_ports(&self, visit: &mut impl FnMut(PortSample)) {
        let round = self.state.samples.borrow_mut().pop_front();
        for sample in round.into_iter().flatten() {
            visit(sample);
        }
    }

    /// Completes every queued TX frame (the fake kernel transmits at
    /// once), unless a refusal is scripted.
    fn probe_quiescence(&mut self) -> Result<(), PublicationQuiescenceDisposition> {
        use ruster_core::PublicationQuiescence as _;
        self.state
            .quiesce_probes
            .set(self.state.quiesce_probes.get() + 1);
        let blocks = self.state.quiesce_blocks.get();
        if blocks != 0 {
            self.state.quiesce_blocks.set(blocks - 1);
            return Err(PublicationQuiescenceDisposition::ContinueOldIo);
        }
        while self.io.pop_tx().is_some() {}
        while self.io.pop_recycled().is_some() {}
        while self.io.pop_generated_recycled().is_some() {}
        match self.io.try_publication_quiescence() {
            Ok(_) => Ok(()),
            Err(error) => Err(SimIo::quiescence_error_disposition(&error)),
        }
    }

    fn drain(&mut self, rounds: u32) -> Result<DrainProgress, XdpIoError> {
        self.state.push(Event::Drain(rounds));
        self.state
            .drains
            .borrow_mut()
            .pop_front()
            .unwrap_or(Ok(DrainProgress {
                fill_in_kernel: 64,
                ..DrainProgress::default()
            }))
    }

    fn write_stats(&self, out: &mut String) {
        out.push_str(&format!("fake.ports={}\n", self.ports.len()));
    }

    fn port_count(&self) -> usize {
        self.ports.len()
    }
}

struct FakeLinks {
    state: Rc<State>,
}

impl LinkMonitor for FakeLinks {
    fn query(&mut self, target: &LinkTarget) -> Result<LinkFacts, NetlinkError> {
        self.state
            .link_queries
            .set(self.state.link_queries.get() + 1);
        let mut links = self.state.links.borrow_mut();
        if links
            .front()
            .is_some_and(|(port, _)| *port == target.interface)
        {
            if let Some((_, result)) = links.pop_front() {
                return result;
            }
        }
        Ok(LinkFacts {
            mtu: target.mtu,
            rx_queues: Some(1),
            admin_up: true,
            lower_up: true,
        })
    }
}

/// Fake interface index of a port.
const fn fake_ifindex(id: u16) -> u32 {
    100 + id as u32
}

impl PortHost for FakeHost {
    type Session = FakeSession;
    type Datapath<'s> = FakeDatapath<'s>;
    type Links = FakeLinks;

    fn links(&self) -> Result<FakeLinks, Failure> {
        if self.fails(Stage::Watch, None) {
            return Err(Failure::Links(NetlinkError::Errno(24)));
        }
        Ok(FakeLinks {
            state: Rc::clone(&self.state),
        })
    }

    fn preflight(&self, _: &ValidatedAfXdpV1) -> Result<(), PrivilegeFailure> {
        self.state.push(Event::Preflight);
        self.privilege.map_or(Ok(()), Err)
    }

    fn open(&self, port: &ValidatedAfXdpPortV1) -> Result<FakeSession, Failure> {
        let id = port.interface().0;
        self.state.push(Event::Open(id));
        if self.fails(Stage::Open, Some(id)) {
            return Err(Failure::Injected);
        }
        if let Some((port, left)) = self.state.transient_open.get() {
            if port == id && left != 0 {
                self.state.transient_open.set(Some((port, left - 1)));
                return Err(Failure::InjectedTransient);
            }
        }
        self.state.live.set(self.state.live.get() + 1);
        Ok(FakeSession {
            interface: port.interface(),
            attached: false,
        })
    }

    fn inspect(
        &self,
        port: &ValidatedAfXdpPortV1,
        session: &FakeSession,
    ) -> Result<DeviceFacts, CheckFailure> {
        let id = port.interface().0;
        assert_eq!(session.interface, port.interface());
        self.state.push(Event::Inspect(id));
        if self.fails(Stage::Checks, Some(id)) {
            return Err(CheckFailure::Unverifiable(Probe::Link));
        }
        Ok(DeviceFacts {
            ifindex: fake_ifindex(id),
            rx_queues: if self.multi_queue == Some(id) { 4 } else { 1 },
            link_mtu: 1500,
            session_mtu: 1500,
            frame_capacity: port.umem().visible_capacity(),
            ipv4_addresses: 0,
            ipv4_routes: 0,
            forwarding_global: Some(false),
            forwarding_device: Some(false),
        })
    }

    fn attach(&self, session: &mut FakeSession, mode: XdpAttachModeV1) -> Result<(), Failure> {
        let id = session.interface.0;
        self.state.push(Event::Attach(id, mode));
        if self.fails(Stage::Attach, Some(id)) {
            return Err(Failure::Injected);
        }
        session.attached = true;
        self.state.attached.set(self.state.attached.get() + 1);
        Ok(())
    }

    fn build<'s>(
        &self,
        ports: &'s mut [OpenPort<FakeSession>],
    ) -> Result<FakeDatapath<'s>, StartupError>
    where
        Self: 's,
    {
        for port in ports.iter() {
            let id = port.interface.0;
            assert!(port.session.attached, "datapath only after attach");
            for (stage, event) in [
                (Stage::Datapath, Event::Datapath(id)),
                (Stage::Engine, Event::Engine(id)),
            ] {
                self.state.push(event);
                if self.fails(stage, Some(id)) {
                    return Err(StartupError::new(
                        stage,
                        Some(port.interface),
                        Failure::Injected,
                    ));
                }
            }
        }
        self.state.push(Event::Adapter);
        assert!(
            !self.panic_in_build,
            "injected panic while building the datapath"
        );
        if self.fails(Stage::Adapter, None) {
            return Err(StartupError::new(Stage::Adapter, None, Failure::Injected));
        }
        let mut io = SimIo::new();
        for (ingress, bytes) in self.state.inject.borrow_mut().drain(..) {
            io.inject(ingress, bytes);
        }
        Ok(FakeDatapath {
            ports,
            state: Rc::clone(&self.state),
            io,
        })
    }

    fn close(&self, session: FakeSession) -> Result<(), CloseFailure> {
        let id = session.interface.0;
        self.state.push(Event::Close {
            port: id,
            attached: session.attached,
        });
        // Close detaches first, then releases the session, also when a
        // step reports an error.
        if session.attached {
            self.state.attached.set(self.state.attached.get() - 1);
        }
        self.state.live.set(self.state.live.get() - 1);
        if self.close_fails == Some(id) {
            return Err(CloseFailure::Injected);
        }
        Ok(())
    }
}

/// Stops at the `stop_at`-th `stop()` call; `force` from the start.
struct FakeStop {
    calls: Cell<u32>,
    stop_at: u32,
    force: bool,
    /// Force from this `force()` call on (1-based).
    force_at: Option<u32>,
    force_calls: Cell<u32>,
}

impl FakeStop {
    fn after(stop_at: u32) -> Self {
        Self {
            calls: Cell::new(0),
            stop_at,
            force: false,
            force_at: None,
            force_calls: Cell::new(0),
        }
    }

    fn forcing(stop_at: u32) -> Self {
        Self {
            force: true,
            ..Self::after(stop_at)
        }
    }
}

impl StopSignal for FakeStop {
    fn stop(&self) -> bool {
        self.calls.set(self.calls.get() + 1);
        self.calls.get() >= self.stop_at
    }

    fn force(&self) -> bool {
        let call = self.force_calls.get() + 1;
        self.force_calls.set(call);
        self.force || self.force_at.is_some_and(|at| call >= at)
    }
}

/// Scripted reload documents, shared with the test.
#[derive(Clone, Default)]
struct FakeSource {
    documents: Rc<RefCell<VecDeque<Result<ValidatedConfigV1, LoadError>>>>,
    loads: Rc<Cell<u32>>,
}

impl FakeSource {
    fn with(documents: impl IntoIterator<Item = Result<ValidatedConfigV1, LoadError>>) -> Self {
        let source = Self::default();
        source.documents.borrow_mut().extend(documents);
        source
    }
}

impl ConfigSource for FakeSource {
    fn load(&mut self) -> Result<ValidatedConfigV1, LoadError> {
        self.loads.set(self.loads.get() + 1);
        self.documents
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(LoadError::Read(std::io::ErrorKind::NotFound)))
    }
}

/// Test settings: no periodic stats, health and link watch every tick.
fn settings(policy: CheckPolicy, stats_interval_ms: u64) -> Settings {
    Settings {
        policy,
        stats_interval_ms,
        drain_deadline_ms: DRAIN_DEADLINE_MS,
        startup_attempts: 3,
        health_interval_ms: 0,
        link_interval_ms: 0,
        reload_quiesce_ms: super::reload::RELOAD_QUIESCE_MS,
    }
}

/// `execute` over the default config with a production sequencer.
#[allow(clippy::too_many_arguments)]
fn execute_with<S: StopSignal, O: std::io::Write, E: std::io::Write>(
    host: &FakeHost,
    config: ValidatedConfigV1,
    source: FakeSource,
    settings: Settings,
    clock: &mut FakeClock,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> u8 {
    let sequencer = ProductionSequencer::new(OsRandomKeySource::open().expect("urandom"));
    execute(
        host, config, sequencer, source, settings, clock, stop, out, err,
    )
}

/// Microsecond clock advanced by `step_us` per reading and by every pause.
#[derive(Default)]
struct FakeClock {
    micros: u64,
    step_us: u64,
    pauses: u32,
    longest: Duration,
}

impl Clock for FakeClock {
    fn now(&mut self) -> MonotonicMillis {
        let now = MonotonicMillis(self.micros / 1_000);
        self.micros += self.step_us;
        now
    }

    fn pause(&mut self, duration: Duration) {
        self.micros += u64::try_from(duration.as_micros()).expect("short");
        self.pauses += 1;
        self.longest = self.longest.max(duration);
    }
}

struct Outcome {
    status: u8,
    out: String,
    err: String,
}

/// `open_ports` calls `stop()` twice per port and `run_ports` once before
/// activation, so the first loop check is call 6 with two ports.
const FIRST_LOOP_CHECK: u32 = 6;

fn run_with<S: StopSignal>(
    host: &FakeHost,
    policy: CheckPolicy,
    stop: &S,
    clock: &mut FakeClock,
) -> Outcome {
    run_full(
        host,
        settings(policy, 0),
        FakeSource::default(),
        stop,
        clock,
    )
}

fn run_full<S: StopSignal>(
    host: &FakeHost,
    settings: Settings,
    source: FakeSource,
    stop: &S,
    clock: &mut FakeClock,
) -> Outcome {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = execute_with(
        host,
        config(),
        source,
        settings,
        clock,
        stop,
        &mut out,
        &mut err,
    );
    Outcome {
        status,
        out: String::from_utf8(out).expect("utf-8"),
        err: String::from_utf8(err).expect("utf-8"),
    }
}

fn run(host: &FakeHost, stop: &FakeStop) -> Outcome {
    run_with(
        host,
        CheckPolicy::default(),
        stop,
        &mut FakeClock {
            step_us: 1_000,
            ..FakeClock::default()
        },
    )
}

const NATIVE: XdpAttachModeV1 = XdpAttachModeV1::Native;
const GENERIC: XdpAttachModeV1 = XdpAttachModeV1::Generic;

#[test]
fn startup_runs_in_ifid_order_and_shutdown_closes_in_reverse() {
    let host = FakeHost::default();
    host.script_drains([
        Ok(DrainProgress {
            completed: 2,
            rx_pending_released: 1,
            tx_in_flight: 3,
            fill_in_kernel: 64,
            tx_handoffs: 0,
            last_kick_error: None,
        }),
        Ok(DrainProgress {
            completed: 3,
            tx_in_flight: 0,
            fill_in_kernel: 64,
            ..DrainProgress::default()
        }),
    ]);
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 3));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(
        host.events(),
        [
            Event::Preflight,
            // lan (if1) first although the config lists wan first.
            Event::Open(LAN),
            Event::Inspect(LAN),
            Event::Attach(LAN, GENERIC),
            Event::Open(WAN),
            Event::Inspect(WAN),
            Event::Attach(WAN, NATIVE),
            Event::Datapath(LAN),
            Event::Engine(LAN),
            Event::Datapath(WAN),
            Event::Engine(WAN),
            Event::Adapter,
            Event::Drain(DRAIN_ROUNDS),
            Event::Drain(DRAIN_ROUNDS),
            Event::Close {
                port: WAN,
                attached: true
            },
            Event::Close {
                port: LAN,
                attached: true
            },
        ]
    );
    host.assert_released();
    assert!(
        outcome.err.contains(&format!("{READY} 1 on 2 port(s)")),
        "{}",
        outcome.err
    );
    assert!(outcome.err.contains("stopped by signal"), "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("completed=5 rx-released=1 tx-in-flight=0 tx-handoffs=0 fill-in-kernel=64"),
        "{}",
        outcome.err
    );
    assert!(outcome.err.contains("detached and closed 2 port(s)"));
    // Exactly one stats block, the final one, after the loop's three ticks.
    assert!(outcome
        .out
        .starts_with("ruster-run-stats kind=final uptime-ms="));
    assert_eq!(outcome.out.matches("ruster-run-stats").count(), 1);
    assert!(
        outcome.out.contains("\nobserver.generation=1\n"),
        "{}",
        outcome.out
    );
    assert!(outcome.out.contains("\ntick.ticks=3\n"), "{}", outcome.out);
    assert!(outcome.out.contains("\nfake.ports=2\n"));
    assert!(outcome.out.ends_with("end\n"));
}

#[test]
fn a_failure_at_every_stage_rolls_back_every_opened_port() {
    let cases = [
        (Stage::Open, Some(LAN), 0),
        (Stage::Checks, Some(LAN), 1),
        (Stage::Attach, Some(LAN), 1),
        (Stage::Open, Some(WAN), 1),
        (Stage::Checks, Some(WAN), 2),
        (Stage::Attach, Some(WAN), 2),
        (Stage::Datapath, Some(LAN), 2),
        (Stage::Engine, Some(LAN), 2),
        (Stage::Datapath, Some(WAN), 2),
        (Stage::Engine, Some(WAN), 2),
        (Stage::Watch, None, 2),
        (Stage::Adapter, None, 2),
    ];
    for (stage, port, opened) in cases {
        let host = FakeHost::failing(stage, port);
        let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
        let label = format!("{stage:?} {port:?}");
        assert_eq!(outcome.status, EXIT_RUNTIME, "{label}: {}", outcome.err);
        let expected = match port {
            Some(port) => format!(
                "startup failed: stage={} port=if{port} code=",
                stage.label()
            ),
            None => format!("startup failed: stage={} code=", stage.label()),
        };
        assert!(outcome.err.contains(&expected), "{label}: {}", outcome.err);
        assert!(!outcome.err.contains(READY), "{label}");
        assert!(
            outcome.out.is_empty(),
            "{label}: no stats before activation"
        );
        host.assert_released();
        let events = host.events();
        // Closed exactly the opened ports, last opened first, and nothing
        // was drained (no datapath ran).
        let opens: Vec<u16> = events
            .iter()
            .filter_map(|event| match event {
                Event::Open(id) => Some(*id),
                _ => None,
            })
            .collect();
        let closes: Vec<u16> = events
            .iter()
            .filter_map(|event| match event {
                Event::Close { port, .. } => Some(*port),
                _ => None,
            })
            .collect();
        let succeeded = if stage == Stage::Open {
            &opens[..opens.len() - 1]
        } else {
            &opens[..]
        };
        assert_eq!(succeeded.len(), opened, "{label}");
        let mut reversed = succeeded.to_vec();
        reversed.reverse();
        assert_eq!(closes, reversed, "{label}");
        assert!(
            !events.iter().any(|event| matches!(event, Event::Drain(_))),
            "{label}"
        );
        // Every close came after the failing step.
        let first_close = events
            .iter()
            .position(|event| matches!(event, Event::Close { .. }));
        if let Some(first_close) = first_close {
            assert!(
                events[first_close..]
                    .iter()
                    .all(|event| matches!(event, Event::Close { .. })),
                "{label}: {events:?}"
            );
        }
    }
}

#[test]
fn a_close_error_during_rollback_is_reported_and_the_rest_still_closes() {
    let host = FakeHost {
        close_fails: Some(WAN),
        ..FakeHost::failing(Stage::Adapter, None)
    };
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_RUNTIME);
    assert!(outcome.err.contains("close failed: port=if2 code=INJECTED"));
    host.assert_released();
    assert!(host.events().ends_with(&[
        Event::Close {
            port: WAN,
            attached: true
        },
        Event::Close {
            port: LAN,
            attached: true
        }
    ]));
}

#[test]
fn privilege_refusal_exits_4_before_any_port() {
    let host = FakeHost {
        privilege: Some(PrivilegeFailure::MissingCapabilities(1 << 39)),
        ..FakeHost::default()
    };
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_PRIVILEGE);
    assert!(
        outcome
            .err
            .contains("stage=privileges code=MISSING_CAPABILITIES missing=CAP_BPF"),
        "{}",
        outcome.err
    );
    assert_eq!(host.events(), [Event::Preflight]);
}

#[test]
fn multi_queue_device_is_refused_unless_allowed_with_a_warning() {
    let host = FakeHost {
        multi_queue: Some(WAN),
        ..FakeHost::default()
    };
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_RUNTIME);
    assert!(outcome
        .err
        .contains("stage=checks port=if2 code=MULTI_QUEUE_DEVICE rx-queues=4"));
    host.assert_released();
    assert!(!host
        .events()
        .iter()
        .any(|event| matches!(event, Event::Attach(WAN, _))));

    let host = FakeHost {
        multi_queue: Some(WAN),
        ..FakeHost::default()
    };
    let outcome = run_with(
        &host,
        CheckPolicy {
            allow_multi_queue: true,
        },
        &FakeStop::after(FIRST_LOOP_CHECK + 1),
        &mut FakeClock::default(),
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome
        .err
        .contains("warning: port=if2 MULTI_QUEUE_ALLOWED rx-queues=4"));
    host.assert_released();
}

#[test]
fn a_signal_during_startup_rolls_back_and_exits_zero() {
    // Call 3 is the check before opening wan: lan is open and attached.
    let host = FakeHost::default();
    let outcome = run(&host, &FakeStop::after(3));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome
        .err
        .contains("startup cancelled by signal; rolled back 1 port(s)"));
    assert_eq!(
        host.events(),
        [
            Event::Preflight,
            Event::Open(LAN),
            Event::Inspect(LAN),
            Event::Attach(LAN, GENERIC),
            Event::Close {
                port: LAN,
                attached: true
            },
        ]
    );
    host.assert_released();
    // Between the adapter and activation: the datapath is dropped, then
    // both ports close.
    let host = FakeHost::default();
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK - 1));
    assert_eq!(outcome.status, 0);
    assert!(outcome.err.contains("rolled back 2 port(s)"));
    assert!(!outcome.err.contains(READY));
    host.assert_released();
}

#[test]
fn drain_deadline_with_frames_in_flight_exits_3_and_still_closes() {
    let host = FakeHost::default();
    host.script_drains((0..10_000).map(|_| {
        Ok(DrainProgress {
            tx_in_flight: 2,
            fill_in_kernel: 64,
            ..DrainProgress::default()
        })
    }));
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_DRAIN_INCOMPLETE, "{}", outcome.err);
    assert!(outcome.err.contains("tx-in-flight=2"), "{}", outcome.err);
    assert!(outcome.err.contains("timed-out=true"));
    let drains = host
        .events()
        .iter()
        .filter(|event| matches!(event, Event::Drain(_)))
        .count();
    // 1 ms per clock reading plus a 1 ms pause per call: bounded by the
    // 2 s deadline, never unbounded.
    assert!((500..=2_001).contains(&drains), "{drains}");
    host.assert_released();
    assert!(outcome.out.contains("kind=final"));
}

#[test]
fn a_second_signal_forces_one_zero_round_drain() {
    for (in_flight, status) in [(5, EXIT_DRAIN_INCOMPLETE), (0, 0)] {
        let host = FakeHost::default();
        host.script_drains([Ok(DrainProgress {
            tx_in_flight: in_flight,
            ..DrainProgress::default()
        })]);
        let outcome = run(&host, &FakeStop::forcing(FIRST_LOOP_CHECK + 1));
        assert_eq!(outcome.status, status, "{}", outcome.err);
        let drains: Vec<Event> = host
            .events()
            .into_iter()
            .filter(|event| matches!(event, Event::Drain(_)))
            .collect();
        assert_eq!(drains, [Event::Drain(0)]);
        assert!(outcome.err.contains("forced=true"));
        host.assert_released();
    }
}

#[test]
fn a_drain_failure_exits_1_and_still_closes() {
    let host = FakeHost::default();
    host.script_drains([Err(XdpIoError::Stopped)]);
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_RUNTIME);
    assert!(
        outcome.err.contains("drain failed: code=STOPPED"),
        "{}",
        outcome.err
    );
    host.assert_released();
}

#[test]
fn a_close_error_after_the_run_exits_1() {
    let host = FakeHost {
        close_fails: Some(LAN),
        ..FakeHost::default()
    };
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_RUNTIME);
    assert!(outcome.err.contains("close failed: port=if1"));
    host.assert_released();
}

/// An ARP request for the router's LAN address from the LAN host.
fn arp_request() -> Vec<u8> {
    let mut frame = vec![0xff; 6];
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x10]);
    frame.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x10, 192, 168, 1, 10]);
    frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 192, 168, 1, 1]);
    frame.resize(60, 0);
    frame
}

#[test]
fn the_loop_forwards_and_sleeps_only_when_idle() {
    let host = FakeHost::default();
    host.state
        .inject
        .borrow_mut()
        .push((IfId(LAN), arp_request()));
    let mut clock = FakeClock {
        step_us: 10,
        ..FakeClock::default()
    };
    let ticks = SPIN_TICKS + 10;
    let outcome = run_with(
        &host,
        CheckPolicy::default(),
        &FakeStop::after(FIRST_LOOP_CHECK + ticks),
        &mut clock,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome.out.contains("\nrx.received=1\n"), "{}", outcome.out);
    assert!(
        outcome.out.contains("\nrx.tx_accepted=1\n"),
        "{}",
        outcome.out
    );
    // The busy first tick reset the backoff: SPIN_TICKS idle ticks spin,
    // the remaining ones sleep, doubling up to the cap.
    let idle_sleeps = ticks - 1 - SPIN_TICKS;
    assert_eq!(clock.pauses, idle_sleeps, "drain pauses are not reached");
    assert!(clock.longest <= MAX_PAUSE);
}

#[test]
fn idle_backoff_spins_then_doubles_to_the_cap() {
    let mut backoff = IdleBackoff::default();
    for _ in 0..SPIN_TICKS {
        assert_eq!(backoff.after_tick(false), None);
    }
    assert_eq!(backoff.after_tick(false), Some(MIN_PAUSE));
    assert_eq!(backoff.after_tick(false), Some(MIN_PAUSE * 2));
    let mut last = MIN_PAUSE * 2;
    for _ in 0..100 {
        let pause = backoff.after_tick(false).expect("sleeping");
        assert!(pause >= last && pause <= MAX_PAUSE);
        last = pause;
    }
    assert_eq!(last, MAX_PAUSE);
    assert_eq!(backoff.after_tick(true), None);
    assert_eq!(backoff.after_tick(false), None, "busy resets to spinning");
    // Saturation never panics or overflows.
    let mut long = IdleBackoff::default();
    for _ in 0..100_000 {
        let _ = long.after_tick(false);
    }
    assert_eq!(long.after_tick(false), Some(MAX_PAUSE));
}

#[test]
fn periodic_stats_follow_the_interval() {
    let host = FakeHost::default();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    // 1 ms per clock reading, 25 loop iterations, a block every 10 ms.
    let status = execute_with(
        &host,
        config(),
        FakeSource::default(),
        settings(CheckPolicy::default(), 10),
        &mut FakeClock {
            step_us: 1_000,
            ..FakeClock::default()
        },
        &FakeStop::after(FIRST_LOOP_CHECK + 25),
        &mut out,
        &mut err,
    );
    assert_eq!(status, 0);
    let out = String::from_utf8(out).expect("utf-8");
    assert_eq!(
        out.matches("ruster-run-stats kind=periodic").count(),
        2,
        "{out}"
    );
    assert_eq!(out.matches("ruster-run-stats kind=final").count(), 1);
    assert_eq!(
        out.matches("\nend\n").count() + usize::from(out.starts_with("end\n")),
        3
    );
}

#[test]
fn stats_never_carry_secrets_or_addresses() {
    let host = FakeHost::default();
    host.state
        .inject
        .borrow_mut()
        .push((IfId(LAN), arp_request()));
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 2));
    for forbidden in [
        "192.168",
        "203.0.113",
        "02:00",
        "allocator",
        "seed",
        "key",
        "sim0",
        "sim1",
        "lan",
        "wan",
    ] {
        assert!(
            !outcome.out.contains(forbidden),
            "{forbidden} in stats: {}",
            outcome.out
        );
        assert!(
            !outcome.err.contains(forbidden),
            "{forbidden}: {}",
            outcome.err
        );
    }
}

#[test]
fn memlock_requirement_doubles_auto_ports() {
    let config = config();
    let backend = config.backend().af_xdp().expect("af-xdp");
    // copy: 256 x 2048 bytes; auto: twice that (XDP-045); plus the BPF
    // object margin per port for kernels before 5.11.
    assert_eq!(
        required_memlock(backend),
        3 * 256 * 2_048 + 2 * super::checks::BPF_MEMLOCK_MARGIN_PER_PORT
    );
}

#[test]
fn bridge_rejection_is_an_invalid_config() {
    // The candidate stage maps a bridge error to exit 2 and a key-source
    // error to exit 1.
    let bridge = StartupError::new(
        Stage::Candidate,
        None,
        Failure::Sequencer(ruster_control::SequencerError::Bridge(
            ruster_control::ConfigBridgeError::MissingService(
                ruster_control::RuntimeService::Firewall,
            ),
        )),
    );
    assert_eq!(super::startup_status(&bridge), EXIT_INVALID);
    assert_eq!(
        bridge.to_string(),
        "stage=candidate code=MISSING_SERVICE_FIREWALL"
    );
    let keys = StartupError::new(
        Stage::Candidate,
        None,
        Failure::Sequencer(ruster_control::SequencerError::Bridge(
            ruster_control::ConfigBridgeError::KeySource(
                ruster_control::KeySourceError::EntropyEndOfFile,
            ),
        )),
    );
    assert_eq!(super::startup_status(&keys), EXIT_RUNTIME);
}

/// Counts this thread's allocations while armed (test binary only).
#[allow(unsafe_code)]
mod counting {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    struct Counting;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    fn note() {
        let armed = ARMED.try_with(Cell::get).unwrap_or(false);
        if armed {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
        }
    }

    // SAFETY: every call delegates the unchanged pointer and layout to the
    // system allocator; the const thread-local counters never allocate.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            note();
            // SAFETY: as for `alloc`.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: `pointer` came from `System` through this allocator.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            note();
            // SAFETY: as for `dealloc`, with the `realloc` contract.
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    pub fn arm(on: bool) {
        ARMED.with(|armed| armed.set(on));
    }

    pub fn count() -> u64 {
        COUNT.with(Cell::get)
    }
}

/// Arms the allocation counter at loop check `arm_at` and stops at
/// `stop_at`, so exactly the ticks in between are measured.
struct MeasuringStop {
    calls: Cell<u32>,
    arm_at: u32,
    stop_at: u32,
}

impl StopSignal for MeasuringStop {
    fn stop(&self) -> bool {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if call == self.arm_at {
            counting::arm(true);
        }
        if call >= self.stop_at {
            counting::arm(false);
            return true;
        }
        false
    }

    fn force(&self) -> bool {
        false
    }
}

#[test]
fn ticks_do_not_allocate() {
    let host = FakeHost::default();
    // The health and link watch run every tick here (test settings), with
    // healthy samples that change nothing, so their path is measured too.
    let rounds = (0..1_000_u64).map(|step| {
        vec![PortSample {
            interface: IfId(WAN),
            polls: step * 10,
            tx_inflight: 1,
            oldest_age_polls: 1,
            kick_errors: 0,
            kick_link_down: false,
            fill_starved: 0,
            fill_ring_occupancy: 8,
            rx_packets: step,
        }]
    });
    host.state.samples.borrow_mut().extend(rounds);
    // Warm up past the busy first ticks; then measure idle ticks that both
    // spin and sleep, plus the stop checks themselves.
    let arm_at = FIRST_LOOP_CHECK + 8;
    let measured = SPIN_TICKS + 200;
    let stop = MeasuringStop {
        calls: Cell::new(0),
        arm_at,
        stop_at: arm_at + measured,
    };
    let before = counting::count();
    let outcome = run_with(
        &host,
        CheckPolicy::default(),
        &stop,
        &mut FakeClock {
            step_us: 10,
            ..FakeClock::default()
        },
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(counting::count() - before, 0, "allocation in the tick loop");
}

#[test]
fn a_backend_stop_ends_the_run_with_exit_1() {
    use ruster_runtime::{
        PhaseReport, PublicationOutcome, RxPhaseReport, TickPhaseSkip, TickReport,
    };

    let stopped: TickReport<(), (), (), ()> = TickReport {
        publication: PublicationOutcome::Unchanged,
        active: true,
        rx: RxPhaseReport::Skipped(TickPhaseSkip::BackendStopped),
        resolution_timers: PhaseReport::Skipped(TickPhaseSkip::BackendStopped),
        failure_dispatch: PhaseReport::Skipped(TickPhaseSkip::BackendStopped),
        generated_arp: PhaseReport::Skipped(TickPhaseSkip::BackendStopped),
        generated_icmpv4: PhaseReport::Skipped(TickPhaseSkip::BackendStopped),
    };
    assert!(super::engine::backend_stopped(&stopped));
    assert!(!super::engine::tick_was_busy(&stopped));
    let failed = TickReport {
        rx: RxPhaseReport::Skipped(TickPhaseSkip::BackendIoFailure),
        ..stopped
    };
    assert!(
        !super::engine::backend_stopped(&failed),
        "transient, not terminal"
    );

    let ran = super::Ran {
        end: super::LoopEnd::BackendStopped,
        shutdown: super::ShutdownReport::default(),
        final_block: String::new(),
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(
        super::finished(&ran, 2, &[], &mut out, &mut err),
        EXIT_RUNTIME
    );
    let err = String::from_utf8(err).expect("utf-8");
    assert!(err.contains("stopped after a backend fault"), "{err}");
}

thread_local! {
    static FAIL_ACTIVATION: Cell<bool> = const { Cell::new(false) };
}

/// Consumed by `run_ports` right after `ActivePublication::new`.
pub(super) fn take_activation_failure() -> bool {
    FAIL_ACTIVATION.with(|flag| flag.replace(false))
}

#[test]
fn an_activation_failure_drops_the_datapath_and_rolls_back() {
    let host = FakeHost::default();
    FAIL_ACTIVATION.with(|flag| flag.set(true));
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("startup failed: stage=activate code=STORAGE_SHAPE_MISMATCH"),
        "{}",
        outcome.err
    );
    assert!(!outcome.err.contains(READY));
    assert!(outcome.out.is_empty());
    host.assert_released();
    assert!(host.events().ends_with(&[
        Event::Adapter,
        Event::Close {
            port: WAN,
            attached: true
        },
        Event::Close {
            port: LAN,
            attached: true
        }
    ]));
}

#[test]
fn force_after_a_non_forced_drain_call_stops_the_drain() {
    let host = FakeHost::default();
    host.script_drains([
        Ok(DrainProgress {
            tx_in_flight: 3,
            ..DrainProgress::default()
        }),
        Ok(DrainProgress {
            tx_in_flight: 2,
            ..DrainProgress::default()
        }),
    ]);
    let stop = FakeStop {
        force_at: Some(2),
        ..FakeStop::after(FIRST_LOOP_CHECK + 1)
    };
    let outcome = run(&host, &stop);
    assert_eq!(outcome.status, EXIT_DRAIN_INCOMPLETE, "{}", outcome.err);
    let drains: Vec<Event> = host
        .events()
        .into_iter()
        .filter(|event| matches!(event, Event::Drain(_)))
        .collect();
    assert_eq!(drains, [Event::Drain(DRAIN_ROUNDS), Event::Drain(0)]);
    assert!(outcome.err.contains("tx-in-flight=2"), "{}", outcome.err);
    assert!(outcome.err.contains("forced=true timed-out=false"));
    host.assert_released();
}

#[test]
fn a_panic_during_startup_closes_every_port_through_drop() {
    let host = FakeHost {
        panic_in_build: true,
        ..FakeHost::default()
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1))
    }));
    assert!(result.is_err(), "the injected panic propagates");
    host.assert_released();
    assert!(host.events().ends_with(&[
        Event::Close {
            port: WAN,
            attached: true
        },
        Event::Close {
            port: LAN,
            attached: true
        }
    ]));
}

#[test]
fn the_last_kick_error_reaches_the_summary_as_a_token() {
    let host = FakeHost::default();
    host.script_drains([
        Ok(DrainProgress {
            tx_in_flight: 1,
            last_kick_error: Some((IfId(WAN), ruster_io_xdp_native::KickError::NetworkDown)),
            ..DrainProgress::default()
        }),
        Ok(DrainProgress::default()),
    ]);
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(
        outcome.err.contains("last-kick-error=if2:NETWORK_DOWN;"),
        "{}",
        outcome.err
    );
    assert_eq!(
        super::engine::kick_error_token(ruster_io_xdp_native::KickError::Errno(22)),
        "ERRNO_22"
    );
    let clean = FakeHost::default();
    let outcome = run(&clean, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert!(
        outcome.err.contains("last-kick-error=none;"),
        "{}",
        outcome.err
    );
}

#[test]
fn a_wedged_backend_ends_the_loop_after_bounded_skips() {
    use super::engine::{BackendWatch, LoopEnd, WEDGED_TICKS};
    use ruster_runtime::{
        PhaseReport, PublicationOutcome, RxPhaseReport, TickPhaseSkip, TickReport,
    };

    let skipped = |reason| -> TickReport<(), (), (), ()> {
        TickReport {
            publication: PublicationOutcome::Unchanged,
            active: true,
            rx: RxPhaseReport::Skipped(reason),
            resolution_timers: PhaseReport::Skipped(reason),
            failure_dispatch: PhaseReport::Skipped(reason),
            generated_arp: PhaseReport::Skipped(reason),
            generated_icmpv4: PhaseReport::Skipped(reason),
        }
    };
    let wedged = skipped(TickPhaseSkip::BackendIoNotReentrant);
    let other = skipped(TickPhaseSkip::BackendIoFailure);
    let mut watch = BackendWatch::default();
    for _ in 0..WEDGED_TICKS - 1 {
        assert_eq!(watch.after_tick(&wedged), None);
    }
    // Any other tick resets the count.
    assert_eq!(watch.after_tick(&other), None);
    for _ in 0..WEDGED_TICKS - 1 {
        assert_eq!(watch.after_tick(&wedged), None);
    }
    assert_eq!(watch.after_tick(&wedged), Some(LoopEnd::BackendStopped));
    assert_eq!(
        BackendWatch::default().after_tick(&skipped(TickPhaseSkip::BackendStopped)),
        Some(LoopEnd::BackendStopped)
    );
}

#[test]
fn startup_codes_are_stable_tokens_without_struct_syntax() {
    use super::startup::token;
    use ruster_io_xdp_native::{RxFillSetupError, XdpPacketIoSetupError};

    assert_eq!(token(&Stage::Activate), "ACTIVATE");
    assert_eq!(
        token(&RxFillSetupError::FillBatchExceedsRing {
            fill_batch: 64,
            capacity: 32
        }),
        "FILL_BATCH_EXCEEDS_RING"
    );
    assert_eq!(
        token(&XdpPacketIoSetupError::GeneratedPoolTooSmall {
            interface: IfId(2),
            generated_frames: 1
        }),
        "GENERATED_POOL_TOO_SMALL"
    );
    assert_eq!(
        token(&XdpPacketIoSetupError::DuplicateInterface(IfId(2))),
        "DUPLICATE_INTERFACE"
    );
    assert_eq!(token(&XdpIoError::Stopped), "STOPPED");
    assert_eq!(
        token(&ruster_io_xdp_native::KickError::Errno(105)),
        "ERRNO_105"
    );
    assert_eq!(
        token(&ruster_control::ActivationError::GenerationNotAboveFloor),
        "GENERATION_NOT_ABOVE_FLOOR"
    );
}

/// A pipe nobody reads: once it and the output queue are full, every
/// further output message is dropped and counted, while the loop keeps
/// ticking and the stop is honoured (M1 of the #301 review).
#[test]
fn an_undrained_output_pipe_never_blocks_the_loop_or_the_stop() {
    use std::io::Write as _;

    use std::io::Read as _;

    use super::output::{dropped, ColdOutput, Stream, Watchdog};

    // A regression to a blocking write hangs `execute`; abort instead.
    let _watchdog = Watchdog::arm(Duration::from_secs(120), "undrained stdout run");
    let (reader, writer) = std::io::pipe().expect("pipe");
    let (mut err_reader, err_writer) = std::io::pipe().expect("pipe");
    let stderr_text = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err_reader.read_to_string(&mut text);
        text
    });
    let output = ColdOutput::spawn(writer, err_writer).expect("output threads");
    let mut out = output.writer(Stream::Out);
    let mut err = output.writer(Stream::Err);
    let host = FakeHost::default();
    let before = dropped();
    let ticks = 20_000;
    let stop = FakeStop::after(FIRST_LOOP_CHECK + ticks);
    let status = execute_with(
        &host,
        config(),
        FakeSource::default(),
        // A ~10 KiB block every 1 ms of fake time, 10 ticks apart.
        settings(CheckPolicy::default(), 1),
        &mut FakeClock {
            step_us: 100,
            ..FakeClock::default()
        },
        &stop,
        &mut out,
        &mut err,
    );
    assert_eq!(status, 0);
    // Every loop check ran: the stop came exactly when scheduled.
    assert_eq!(stop.calls.get(), FIRST_LOOP_CHECK + ticks);
    host.assert_released();
    assert!(dropped() > before, "a full pipe drops instead of blocking");
    let _ = out.flush();
    drop((out, err));
    // The stdout thread is still blocked on the full pipe; finishing is
    // bounded anyway.
    assert!(!output.finish(Duration::from_millis(500)));
    // stderr has its own lane: the readiness line and the summary arrived
    // although stdout never moved.
    let stderr = stderr_text.join().expect("stderr reader");
    assert!(stderr.contains(READY), "{stderr}");
    assert!(stderr.contains("stopped by signal"), "{stderr}");
    drop(reader);
}

/// Pins `token()` over representative variants of every error enum it
/// formats on the startup and shutdown paths, including nested and errno
/// shapes, so a rename or a format change is a visible diff.
#[test]
fn token_table_is_pinned() {
    use super::startup::token;
    use ruster_control::{ActivationError, SequencerError, StorageAllocationError};
    use ruster_io_xdp_native::{
        AttachFailure, AttachStage, CleanupStage, DatapathError, KickError, RxFillSetupError,
        SessionConfigError, SessionFailure, SessionStage, XdpPacketIoSetupError,
    };

    let table: Vec<(String, &str)> = vec![
        (token(&SessionStage::TxQueueCheck), "TX_QUEUE_CHECK"),
        (token(&SessionStage::RegisterUmem), "REGISTER_UMEM"),
        (token(&SessionFailure::MemlockLimit), "MEMLOCK_LIMIT"),
        (token(&SessionFailure::Errno(105)), "ERRNO_105"),
        (token(&AttachStage::CreateLink), "CREATE_LINK"),
        (token(&AttachFailure::ExistingProgram), "EXISTING_PROGRAM"),
        (token(&AttachFailure::Errno(95)), "ERRNO_95"),
        (token(&CleanupStage::CloseXdpLink), "CLOSE_XDP_LINK"),
        (
            token(&SessionConfigError::DeviceNameTooLong { len: 20 }),
            "DEVICE_NAME_TOO_LONG",
        ),
        (
            token(&SessionConfigError::QueueOutOfRange { queue: 9 }),
            "QUEUE_OUT_OF_RANGE",
        ),
        (token(&DatapathError::AlreadyTaken), "ALREADY_TAKEN"),
        (token(&RxFillSetupError::UmemTooShort), "UMEM_TOO_SHORT"),
        (
            token(&RxFillSetupError::TxRingNotEmpty),
            "TX_RING_NOT_EMPTY",
        ),
        (token(&XdpPacketIoSetupError::NoPorts), "NO_PORTS"),
        (token(&XdpPacketIoSetupError::ZeroMtu(IfId(1))), "ZERO_MTU"),
        (
            token(&ActivationError::StorageShapeMismatch),
            "STORAGE_SHAPE_MISMATCH",
        ),
        (
            token(&SequencerError::GenerationExhausted),
            "GENERATION_EXHAUSTED",
        ),
        (
            token(&SequencerError::HistoryAllocation),
            "HISTORY_ALLOCATION",
        ),
        (
            token(&SequencerError::KeyReused(
                ruster_control::RuntimeService::Firewall,
            )),
            "KEY_REUSED.FIREWALL",
        ),
        (token(&KickError::NotBound), "NOT_BOUND"),
        (
            token(&XdpIoError::Kick {
                interface: IfId(2),
                error: KickError::Errno(22),
            }),
            "KICK",
        ),
    ];
    for (got, want) in &table {
        assert_eq!(got, want);
    }
    // `StorageAllocationError` is a non-exhaustive struct: its code is
    // `ALLOCATION.<service>` from the service token.
    assert_eq!(
        token(&ruster_control::RuntimeService::Nat44Tcp),
        "NAT44_TCP"
    );
    let _: fn(&StorageAllocationError) -> String = |error| token(&error.service);
}

#[path = "ops_tests.rs"]
mod ops;

//! `ruster run --config <path>`: the AF_XDP static router (M2 S10a/S10b,
//! X04b). x86_64 Linux only.
//!
//! # Startup (failure atomic)
//!
//! 1. Load and validate the config without the service bridge. `[backend]`
//!    must be `kind = "af-xdp"`; `sim` is refused (`stage=backend
//!    code=SIM_BACKEND`, exit 2) and points to `ruster run-sim`.
//! 2. Install the SIGINT/SIGTERM and SIGHUP handlers, open `/dev/urandom` as the
//!    [`ruster_control::OsRandomKeySource`] and wrap it in a [`ProductionSequencer`]. The
//!    whole live path is generic over `K: ProductionKeySource`, a sealed
//!    trait that the simulation key source cannot implement, so a
//!    deterministic key source cannot reach this path by type.
//! 3. Build the generation-1 candidate (bridge and key draw) and allocate
//!    its runtime storage.
//! 4. Preflight privileges: effective `CAP_NET_ADMIN`, `CAP_NET_RAW`, and
//!    `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`), and, without
//!    `CAP_IPC_LOCK`, a soft `RLIMIT_MEMLOCK` of at least the pinned UMEM
//!    (twice for `auto`, XDP-045). Refusal is exit 4 before any resource.
//! 5. Per port in `IfId` order: open the session (its TX-queue and MTU
//!    checks included), run the XDP-063 device checks (see
//!    [`checks::evaluate_device`]), attach XDP with the configured mode
//!    (existing programs are refused, never replaced). Then take every
//!    datapath, build every engine, build the `XdpPacketIo` adapter, and
//!    activate generation 1 ([`startup`] explains why the datapath comes
//!    after all attaches).
//!
//! A failure at any stage closes every session opened so far, last first
//! (closing detaches XDP before releasing the socket, UMEM, and rings),
//! prints a value-free `stage=<stage> [port=if<id>] code=...` line, and
//! exits non-zero. A signal between stages rolls back the same way and
//! exits 0.
//!
//! A transient port open failure (XDP-045, [`Failure::is_transient`]:
//! `BIND/BUSY`, `REGISTER_UMEM/MEMLOCK_LIMIT` or `OUT_OF_MEMORY`, any
//! `ERRNO_11`) rolls back every opened port the same way and retries the
//! whole port startup after 250 ms, doubling up to 2 s, at most
//! `--startup-attempts` attempts in all (default 3, `1..=10`; 1 disables
//! the retry). Each retry prints `startup attempt N of M failed: ...;
//! rolled back K port(s), retrying in P ms`. Every other failure is
//! final at once. The candidate, storage, and privilege preflight are not
//! repeated.
//!
//! # Run loop
//!
//! See [`engine`]: `run_tick` with the configured budgets and an `Instant`
//! clock, spin-then-sleep idle backoff (at most 1 ms), no allocation per
//! tick, and a stats block on stdout every `--stats-interval` seconds.
//! Between ticks, on the cold path: the SIGHUP reload ([`reload`]), and
//! the health and link watch ([`watch`]), whose fatal events end the run
//! like a stop request, with drain and close, but exit 1.
//!
//! # Shutdown
//!
//! On SIGINT/SIGTERM the loop stops ticking (no RX, no generated or
//! forwarded TX), then [`engine::shutdown_drain`] drains every port in
//! bounded rounds for at most 2 s: RX and Fill stop, staged handoffs and
//! leaked leases are reclaimed, unlent RX frames return, owed TX is kicked
//! and reaped. A second signal cuts the drain short (one zero-round call to
//! stop the adapter and count what the kernel holds). The final stats are
//! captured, the adapter and engines are dropped, and every session is
//! closed last port first (link close detaches XDP). The final stats
//! block goes to stdout, the summary with the frames still held by the
//! kernel to stderr.
//!
//! # Exit status
//!
//! - 0: ordered shutdown with no TX frame left in the kernel (also a
//!   signal during startup, after a clean rollback).
//! - 1: startup failure (open, checks, attach, watch, datapath, engine,
//!   adapter, activation, key source; a transient open failure after the
//!   last attempt), a backend fault during the run, a fatal health or
//!   device event ([`watch`]: TX stall, persistent kick errors, device
//!   removed, MTU decreased or above the frame bound, link unverifiable),
//!   a drain failure, a stranded TX handoff after the drain, or a close
//!   error. A refused or failed reload never ends the run.
//! - 2: usage error or invalid configuration (including the `sim`
//!   backend).
//! - 3: shutdown deadline (or a second signal) with TX frames still owned
//!   by the kernel; everything was still detached and closed.
//! - 4: missing capability or too small `RLIMIT_MEMLOCK` (nothing was
//!   acquired).
//!
//! Privileges are not dropped after startup (deferred).

mod checks;
mod engine;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod linux;
#[cfg_attr(
    not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )),
    allow(dead_code)
)]
mod netlink;
mod output;
mod reload;
mod startup;
mod stats;
#[cfg(test)]
mod tests;
mod watch;

use std::io::Write;
use std::time::Duration;

use ruster_config::ValidatedConfigV1;
use ruster_control::{
    ActivePublication, ConfigBridgeError, FullServiceStorage, ProductionKeySource,
    ProductionSequencer, SequencerError, ValidatedCandidate,
};
use ruster_core::{IfId, MonotonicMillis};
use ruster_runtime::{HealthPolicy, ServiceCounters, TickBudgets, TickObserver};

use crate::args::RunArgs;
use crate::config_cmd;
use crate::{EXIT_INVALID, EXIT_RUNTIME};

use checks::{CheckPolicy, PrivilegeFailure};
use engine::{
    port_label, run_loop, shutdown_drain, Clock, Control, Datapath, LoopEnd, LoopSettings,
    RunStatus, ShutdownReport, StopSignal, DRAIN_DEADLINE_MS,
};
use reload::{ConfigSource, Reloader};
use startup::{
    open_ports, CloseFailure, Failure, Interrupt, OpenedPorts, PortHost, Stage, StartupError,
};
use stats::BlockKind;
use watch::{Thresholds, Watch, HEALTH_INTERVAL_MS, LINK_INTERVAL_MS};

/// Shutdown deadline passed with TX frames still owned by the kernel.
pub const EXIT_DRAIN_INCOMPLETE: u8 = 3;
/// Missing capability or too small `RLIMIT_MEMLOCK`.
pub const EXIT_PRIVILEGE: u8 = 4;

/// Readiness line prefix on stderr.
pub const READY: &str = "ruster run: running generation";

/// First pause between startup attempts; it doubles per attempt.
pub const STARTUP_RETRY_PAUSE_MS: u64 = 250;
/// Longest pause between startup attempts.
pub const STARTUP_RETRY_PAUSE_MAX_MS: u64 = 2_000;
/// Slice of the retry pause between stop-flag checks.
const RETRY_SLICE: Duration = Duration::from_millis(10);

/// Settings of one run.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub policy: CheckPolicy,
    pub stats_interval_ms: u64,
    pub drain_deadline_ms: u64,
    /// Whole startups tried on a transient port open failure.
    pub startup_attempts: u32,
    pub health_interval_ms: u64,
    pub link_interval_ms: u64,
    pub reload_quiesce_ms: u64,
    /// Health thresholds of the watch.
    pub thresholds: Thresholds,
}

impl Settings {
    fn from_args(args: &RunArgs) -> Self {
        Self {
            policy: CheckPolicy {
                allow_multi_queue: args.allow_multi_queue,
                allow_kernel_forwarding: args.allow_kernel_forwarding,
            },
            stats_interval_ms: args.stats_interval_secs.saturating_mul(1_000),
            drain_deadline_ms: DRAIN_DEADLINE_MS,
            startup_attempts: args.startup_attempts,
            health_interval_ms: HEALTH_INTERVAL_MS,
            link_interval_ms: LINK_INTERVAL_MS,
            reload_quiesce_ms: reload::RELOAD_QUIESCE_MS,
            thresholds: Thresholds::from_secs(
                args.tx_stall_warn_secs,
                args.tx_stall_fatal_secs,
                args.kick_errors_fatal_secs,
            ),
        }
    }
}

/// Pause before startup attempt `next` (2, 3, ...): 250 ms doubling, at
/// most 2 s.
pub fn retry_pause_ms(next: u32) -> u64 {
    let doublings = next.saturating_sub(2).min(8);
    (STARTUP_RETRY_PAUSE_MS << doublings).min(STARTUP_RETRY_PAUSE_MAX_MS)
}

/// Runs the command and returns the exit status.
pub fn run(args: &RunArgs, err: &mut impl Write) -> u8 {
    let config = match config_cmd::load_validated_regular(&args.config, args.strict_config_perms) {
        Ok(config) => config,
        Err(error) => return config_cmd::report_load(err, "", &error),
    };
    if config.backend().af_xdp().is_none() {
        let _ = writeln!(
            err,
            "ruster run: invalid config: stage=backend code=SIM_BACKEND \
             (backend kind \"sim\" runs only under `ruster run-sim`)"
        );
        return EXIT_INVALID;
    }
    live(args, config, err)
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
fn live(_: &RunArgs, _: ValidatedConfigV1, err: &mut impl Write) -> u8 {
    let _ = writeln!(
        err,
        "ruster run: unsupported platform: the AF_XDP backend needs x86_64 Linux"
    );
    EXIT_RUNTIME
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn live(args: &RunArgs, config: ValidatedConfigV1, err: &mut impl Write) -> u8 {
    use ruster_control::OsRandomKeySource;

    if let Err(name) = crate::signal::install().and_then(|()| crate::signal::install_reload()) {
        let _ = writeln!(err, "ruster run: cannot install {name} handler");
        return EXIT_RUNTIME;
    }
    let keys = match OsRandomKeySource::open() {
        Ok(keys) => keys,
        Err(error) => {
            let _ = writeln!(
                err,
                "ruster run: startup failed: stage=key-source code={}",
                ConfigBridgeError::KeySource(error).code()
            );
            return EXIT_RUNTIME;
        }
    };
    let settings = Settings::from_args(args);
    let host = linux::LinuxHost;
    // From here on nothing on this thread writes to a file descriptor: a
    // stalled stdout/stderr pipe cannot block the datapath or the shutdown.
    // The threads get dups of fd 1/2 as plain files: blocked writes hold
    // no std stdio lock that `main` or the exit path could wait on.
    let output = match output::ColdOutput::process() {
        Ok(output) => output,
        Err(_) => {
            let _ = writeln!(err, "ruster run: cannot start the output thread");
            return EXIT_RUNTIME;
        }
    };
    let mut out = output.writer(output::Stream::Out);
    let mut cold_err = output.writer(output::Stream::Err);
    let status = execute(
        &host,
        config,
        ProductionSequencer::new(keys),
        reload::ConfigFile {
            path: args.config.clone(),
            strict: args.strict_config_perms,
        },
        settings,
        &mut engine::SystemClock::new(),
        &engine::ProcessSignals,
        &mut out,
        &mut cold_err,
    );
    drop((out, cold_err));
    // Bounded: a reader that never drains cannot keep the process alive.
    // Teardown is complete here. If the output thread is still blocked (it
    // may hold the global stdout lock), exit at once: `process::exit`
    // runs no destructors, and std's exit-time stdout cleanup only
    // try-locks, so nothing can wait on that thread (#301 LN1).
    if !output.finish(OUTPUT_FLUSH_TIMEOUT) {
        std::process::exit(i32::from(status));
    }
    status
}

/// How long the exit waits for queued output.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const OUTPUT_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Tick budgets of the configuration.
fn budgets(config: &ValidatedConfigV1) -> TickBudgets {
    let tick = config.tick();
    let wide = |value: u32| usize::try_from(value).unwrap_or(usize::MAX);
    TickBudgets {
        rx: wide(tick.rx),
        resolution_timer_scans: wide(tick.resolution_timer_scans),
        failure_dispatch_scans: wide(tick.failure_dispatch_scans),
        generated_arp: wide(tick.generated_arp),
        generated_icmpv4: wide(tick.generated_icmpv4),
    }
}

/// How one startup attempt ended.
enum Attempt {
    /// Every port is open, checked, and attached.
    Started,
    /// Stopped early; `opened` still holds what was opened.
    Interrupted(Interrupt),
}

/// Startup, run, shutdown, and teardown over `host`.
///
/// A transient port open failure ([`Failure::is_transient`]) rolls back
/// every opened port (last first) and retries the whole startup after
/// [`retry_pause_ms`], at most `settings.startup_attempts` attempts in
/// all; a signal during the pause cancels like any startup signal.
#[allow(clippy::too_many_arguments)]
pub fn execute<H, K, R, C, S, O, E>(
    host: &H,
    config: ValidatedConfigV1,
    mut sequencer: ProductionSequencer<K>,
    source: R,
    settings: Settings,
    clock: &mut C,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> u8
where
    H: PortHost,
    K: ProductionKeySource,
    R: ConfigSource,
    C: Clock,
    S: StopSignal,
    O: Write,
    E: Write,
{
    let Some(ports) = config
        .backend()
        .af_xdp()
        .map(|backend| backend.ports().len())
    else {
        return EXIT_INVALID;
    };
    let candidate = match sequencer.candidate(&config) {
        Ok(candidate) => candidate,
        Err(error) => {
            let error = StartupError::new(Stage::Candidate, None, Failure::Sequencer(error));
            return startup_failed(err, error, &[]);
        }
    };
    let mut storage = match FullServiceStorage::new(candidate.storage_shape()) {
        Ok(storage) => storage,
        Err(error) => {
            let error = StartupError::new(Stage::Storage, None, Failure::Storage(error));
            return startup_failed(err, error, &[]);
        }
    };
    if let Some(backend) = config.backend().af_xdp() {
        if let Err(error) = host.preflight(backend) {
            let error = StartupError::new(Stage::Privileges, None, Failure::Privileges(error));
            return startup_failed(err, error, &[]);
        }
    }
    let attempts = settings.startup_attempts.max(1);
    let mut attempt = 1;
    let (mut opened, attempt_end) = loop {
        let mut opened = OpenedPorts::new(host, ports);
        let started = match config.backend().af_xdp() {
            Some(backend) => open_ports(
                &mut opened,
                backend,
                settings.policy,
                stop,
                |port, warnings| {
                    for code in warnings.codes() {
                        let _ =
                            writeln!(err, "ruster run: warning: port={} {code}", port_label(port));
                    }
                },
            ),
            None => Ok(()),
        };
        match started {
            Ok(()) => break (opened, Attempt::Started),
            Err(Interrupt::Failed(error)) if attempt < attempts && error.failure.is_transient() => {
                let rolled_back = opened.len();
                let cleanup = opened.close_all();
                if !cleanup.is_empty() {
                    return startup_failed(err, error, &cleanup);
                }
                let pause = retry_pause_ms(attempt + 1);
                let _ = writeln!(
                    err,
                    "ruster run: startup attempt {attempt} of {attempts} failed: {error}; \
                     rolled back {rolled_back} port(s), retrying in {pause} ms"
                );
                if !retry_pause(clock, stop, pause) {
                    let _ = writeln!(
                        err,
                        "ruster run: startup cancelled by signal; rolled back {rolled_back} port(s)"
                    );
                    return 0;
                }
                attempt += 1;
            }
            Err(interrupt) => break (opened, Attempt::Interrupted(interrupt)),
        }
    };
    let outcome = match attempt_end {
        Attempt::Started => run_ports(
            host,
            &mut opened,
            candidate,
            &mut storage,
            Reloader::new(sequencer, config, source),
            settings,
            clock,
            stop,
            out,
            err,
        ),
        Attempt::Interrupted(interrupt) => Err(interrupt),
    };
    let ports = opened.len();
    let cleanup = opened.close_all();
    match outcome {
        Err(Interrupt::Failed(error)) => startup_failed(err, error, &cleanup),
        Err(Interrupt::Signalled) => {
            report_cleanup(err, &cleanup);
            let _ = writeln!(
                err,
                "ruster run: startup cancelled by signal; rolled back {ports} port(s){}",
                if cleanup.is_empty() {
                    ""
                } else {
                    " (see close failed)"
                }
            );
            if cleanup.is_empty() {
                0
            } else {
                EXIT_RUNTIME
            }
        }
        Ok(ran) => finished(&ran, ports, &cleanup, out, err),
    }
}

/// Sleeps `pause_ms` in slices; `false` if a stop request arrived.
fn retry_pause<C: Clock, S: StopSignal>(clock: &mut C, stop: &S, pause_ms: u64) -> bool {
    let start = clock.now();
    loop {
        if stop.stop() {
            return false;
        }
        if clock.now().0.saturating_sub(start.0) >= pause_ms {
            return true;
        }
        clock.pause(RETRY_SLICE);
    }
}

/// What a completed run hands to teardown.
struct Ran {
    end: LoopEnd,
    shutdown: ShutdownReport,
    final_block: String,
}

#[allow(clippy::too_many_arguments)]
fn run_ports<'h, H, K, R, C, S, O, E>(
    host: &H,
    opened: &mut OpenedPorts<'h, H>,
    candidate: ValidatedCandidate,
    storage: &mut FullServiceStorage,
    reloader: Reloader<K, R>,
    settings: Settings,
    clock: &mut C,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> Result<Ran, Interrupt>
where
    H: PortHost,
    K: ProductionKeySource,
    R: ConfigSource,
    C: Clock,
    S: StopSignal,
    O: Write,
    E: Write,
{
    let links = host
        .links()
        .map_err(|failure| Interrupt::Failed(StartupError::new(Stage::Watch, None, failure)))?;
    let targets: Vec<_> = opened.ports_mut().iter().map(|port| port.link).collect();
    let mut datapath = host.build(opened.ports_mut()).map_err(Interrupt::Failed)?;
    if stop.stop() {
        return Err(Interrupt::Signalled);
    }
    let activated = ActivePublication::new(storage, candidate);
    // Activation is unreachable to fail in production (the storage was
    // built from this candidate's shape); tests inject it here.
    #[cfg(test)]
    let activated = activated.and_then(|active| {
        if tests::take_activation_failure() {
            drop(active);
            Err(ruster_control::ActivationError::StorageShapeMismatch)
        } else {
            Ok(active)
        }
    });
    let mut active = activated.map_err(|error| {
        Interrupt::Failed(StartupError::new(
            Stage::Activate,
            None,
            Failure::Activation(error),
        ))
    })?;
    let mut observer = TickObserver::new(HealthPolicy::default());
    let _ = writeln!(
        err,
        "{READY} {} on {} port(s); send SIGINT or SIGTERM to stop, SIGHUP to reload",
        active.generation(),
        datapath.port_count()
    );
    let _ = err.flush();
    let loop_settings = LoopSettings {
        stats_interval_ms: settings.stats_interval_ms,
        health_interval_ms: settings.health_interval_ms,
        link_interval_ms: settings.link_interval_ms,
        reload_quiesce_ms: settings.reload_quiesce_ms,
    };
    let mut control = Control {
        reloader,
        watch: Watch::new(&targets, settings.thresholds),
        links,
    };
    let end = run_loop(
        &mut active,
        &mut datapath,
        &mut observer,
        clock,
        stop,
        loop_settings,
        &mut control,
        err,
        |active, datapath, observer, status, now| {
            let text = render(BlockKind::Periodic, now, active, datapath, observer, status);
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
        },
    );
    // A reload still waiting for quiescence ends with the run.
    if let Some(outcome) = control.reloader.abandon("STOPPED", active.generation()) {
        let _ = writeln!(err, "ruster run: {outcome}");
    }
    let _ = writeln!(
        err,
        "ruster run: {}; draining",
        match end {
            LoopEnd::Signal => "stop requested".to_owned(),
            LoopEnd::BackendStopped => "backend stopped after a fault".to_owned(),
            LoopEnd::Invariant => "invariant violation code=APPLY_REPORT_MISSING".to_owned(),
            LoopEnd::Fatal { port, cause } => format!(
                "fatal health event port={} code={}",
                port_label(port),
                cause.code()
            ),
        }
    );
    let shutdown = shutdown_drain(&mut datapath, clock, stop, settings.drain_deadline_ms);
    let now = clock.now();
    let status = RunStatus {
        reload: control.reloader.counters(),
        watch: &control.watch,
    };
    let final_block = render(
        BlockKind::Final,
        now,
        &active,
        &datapath,
        &observer,
        &status,
    );
    drop(active);
    drop(datapath);
    Ok(Ran {
        end,
        shutdown,
        final_block,
    })
}

fn render<D: Datapath>(
    kind: BlockKind,
    now: MonotonicMillis,
    active: &ActivePublication<'_, D::Io>,
    datapath: &D,
    observer: &TickObserver,
    status: &RunStatus<'_>,
) -> String {
    let services = ServiceCounters::capture(
        active.resolution(),
        active.icmpv4_errors(),
        active.nat44_udp(),
        active.nat44_tcp(),
        active.firewall(),
    );
    stats::block(kind, now, &observer.snapshot(now), &services, |out| {
        datapath.write_stats(out);
        stats::write_fields(out, None, &status.reload);
        stats::write_fields(out, None, status.watch);
        for (interface, health) in status.watch.health() {
            stats::write_fields(out, Some(interface), &health);
        }
    })
}

fn report_cleanup(err: &mut impl Write, cleanup: &[(IfId, CloseFailure)]) {
    for (port, failure) in cleanup {
        let _ = writeln!(
            err,
            "ruster run: close failed: port={} {failure}",
            port_label(*port)
        );
    }
}

/// Exit status of a startup failure.
fn startup_status(error: &StartupError) -> u8 {
    match error.failure {
        Failure::Privileges(_) => EXIT_PRIVILEGE,
        Failure::Sequencer(SequencerError::Bridge(ConfigBridgeError::KeySource(_))) => EXIT_RUNTIME,
        Failure::Sequencer(SequencerError::Bridge(_)) => EXIT_INVALID,
        _ => EXIT_RUNTIME,
    }
}

fn startup_failed(
    err: &mut impl Write,
    error: StartupError,
    cleanup: &[(IfId, CloseFailure)],
) -> u8 {
    let _ = writeln!(err, "ruster run: startup failed: {error}");
    if let Failure::Privileges(PrivilegeFailure::MissingCapabilities(_)) = error.failure {
        let _ = writeln!(
            err,
            "ruster run: run as root or grant CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF, and CAP_PERFMON"
        );
    }
    report_cleanup(err, cleanup);
    startup_status(&error)
}

fn finished(
    ran: &Ran,
    ports: usize,
    cleanup: &[(IfId, CloseFailure)],
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
    let _ = out.write_all(ran.final_block.as_bytes());
    let _ = out.flush();
    report_cleanup(err, cleanup);
    let shutdown = &ran.shutdown;
    if let Some(fault) = shutdown.fault {
        let _ = writeln!(
            err,
            "ruster run: drain failed: code={}",
            startup::token(&fault)
        );
    }
    let closed = ports.saturating_sub(cleanup.len());
    let _ = writeln!(
        err,
        "ruster run: {}; drain calls={} completed={} rx-released={} tx-in-flight={} \
         tx-handoffs={} fill-in-kernel={} forced={} timed-out={} last-kick-error={}; {}",
        match ran.end {
            LoopEnd::Signal => "stopped by signal".to_owned(),
            LoopEnd::BackendStopped => "stopped after a backend fault".to_owned(),
            LoopEnd::Invariant => {
                "stopped after an invariant violation code=APPLY_REPORT_MISSING".to_owned()
            }
            LoopEnd::Fatal { port, cause } => format!(
                "stopped after a fatal health event port={} code={}",
                port_label(port),
                cause.code()
            ),
        },
        shutdown.calls,
        shutdown.completed,
        shutdown.rx_pending_released,
        shutdown.tx_in_flight,
        shutdown.tx_handoffs,
        shutdown.fill_in_kernel,
        shutdown.forced,
        shutdown.timed_out,
        engine::last_kick_label(shutdown.last_kick_error),
        if cleanup.is_empty() {
            format!("detached and closed {ports} port(s)")
        } else {
            format!("detached and closed {closed} of {ports} port(s); see close failed")
        },
    );
    if !cleanup.is_empty()
        || ran.end != LoopEnd::Signal
        || shutdown.fault.is_some()
        || shutdown.tx_handoffs != 0
    {
        EXIT_RUNTIME
    } else if shutdown.tx_in_flight != 0 {
        EXIT_DRAIN_INCOMPLETE
    } else {
        0
    }
}

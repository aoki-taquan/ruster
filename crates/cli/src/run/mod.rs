//! `ruster run --config <path>`: the AF_XDP static router (M2 S10a, the
//! first half of X04b). x86_64 Linux only.
//!
//! # Startup (failure atomic)
//!
//! 1. Load and validate the config without the service bridge. `[backend]`
//!    must be `kind = "af-xdp"`; `sim` is refused (`stage=backend
//!    code=SIM_BACKEND`, exit 2) and points to `ruster run-sim`.
//! 2. Install the SIGINT/SIGTERM handlers, open `/dev/urandom` as the
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
//! # Run loop
//!
//! See [`engine`]: `run_tick` with the configured budgets and an `Instant`
//! clock, spin-then-sleep idle backoff (at most 1 ms), no allocation per
//! tick, and a stats block on stdout every `--stats-interval` seconds.
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
//! - 1: startup failure (open, checks, attach, datapath, engine, adapter,
//!   activation, key source), a backend fault during the run, a drain
//!   failure, or a close error.
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
mod startup;
mod stats;
#[cfg(test)]
mod tests;

use std::io::Write;

use ruster_config::{ValidatedAfXdpV1, ValidatedConfigV1};
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
    port_label, run_loop, shutdown_drain, Clock, Datapath, LoopEnd, LoopSettings, ShutdownReport,
    StopSignal, DRAIN_DEADLINE_MS,
};
use startup::{
    open_ports, CloseFailure, Failure, Interrupt, OpenedPorts, PortHost, Stage, StartupError,
};
use stats::BlockKind;

/// Shutdown deadline passed with TX frames still owned by the kernel.
pub const EXIT_DRAIN_INCOMPLETE: u8 = 3;
/// Missing capability or too small `RLIMIT_MEMLOCK`.
pub const EXIT_PRIVILEGE: u8 = 4;

/// Readiness line prefix on stderr.
pub const READY: &str = "ruster run: running generation";

/// Settings of one run.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub policy: CheckPolicy,
    pub stats_interval_ms: u64,
    pub drain_deadline_ms: u64,
}

impl Settings {
    fn from_args(args: &RunArgs) -> Self {
        Self {
            policy: CheckPolicy {
                allow_multi_queue: args.allow_multi_queue,
            },
            stats_interval_ms: args.stats_interval_secs.saturating_mul(1_000),
            drain_deadline_ms: DRAIN_DEADLINE_MS,
        }
    }
}

/// Runs the command and returns the exit status.
pub fn run(args: &RunArgs, err: &mut impl Write) -> u8 {
    let config = match config_cmd::load_validated(&args.config) {
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
    live(args, &config, err)
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
fn live(_: &RunArgs, _: &ValidatedConfigV1, err: &mut impl Write) -> u8 {
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
fn live(args: &RunArgs, config: &ValidatedConfigV1, err: &mut impl Write) -> u8 {
    use ruster_control::OsRandomKeySource;

    let Some(backend) = config.backend().af_xdp() else {
        return EXIT_INVALID;
    };
    if let Err(name) = crate::signal::install() {
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
    let mut out = std::io::stdout().lock();
    execute(
        &host,
        config,
        backend,
        ProductionSequencer::new(keys),
        settings,
        &mut engine::SystemClock::new(),
        &engine::ProcessSignals,
        &mut out,
        err,
    )
}

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

/// Startup, run, shutdown, and teardown over `host`.
#[allow(clippy::too_many_arguments)]
pub fn execute<H, K, C, S, O, E>(
    host: &H,
    config: &ValidatedConfigV1,
    backend: &ValidatedAfXdpV1,
    mut sequencer: ProductionSequencer<K>,
    settings: Settings,
    clock: &mut C,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> u8
where
    H: PortHost,
    K: ProductionKeySource,
    C: Clock,
    S: StopSignal,
    O: Write,
    E: Write,
{
    let candidate = match sequencer.candidate(config) {
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
    if let Err(error) = host.preflight(backend) {
        let error = StartupError::new(Stage::Privileges, None, Failure::Privileges(error));
        return startup_failed(err, error, &[]);
    }
    let mut opened = OpenedPorts::new(host, backend.ports().len());
    let started = open_ports(
        &mut opened,
        backend,
        settings.policy,
        stop,
        |port, warnings| {
            for code in warnings.codes() {
                let _ = writeln!(err, "ruster run: warning: port={} {code}", port_label(port));
            }
        },
    );
    let outcome = match started {
        Ok(()) => run_ports(
            host,
            &mut opened,
            candidate,
            &mut storage,
            budgets(config),
            settings,
            clock,
            stop,
            out,
            err,
        ),
        Err(interrupt) => Err(interrupt),
    };
    let ports = opened.len();
    let cleanup = opened.close_all();
    match outcome {
        Err(Interrupt::Failed(error)) => startup_failed(err, error, &cleanup),
        Err(Interrupt::Signalled) => {
            report_cleanup(err, &cleanup);
            let _ = writeln!(
                err,
                "ruster run: startup cancelled by signal; rolled back {ports} port(s)"
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

/// What a completed run hands to teardown.
struct Ran {
    end: LoopEnd,
    shutdown: ShutdownReport,
    final_block: String,
}

#[allow(clippy::too_many_arguments)]
fn run_ports<'h, H, C, S, O, E>(
    host: &H,
    opened: &mut OpenedPorts<'h, H>,
    candidate: ValidatedCandidate,
    storage: &mut FullServiceStorage,
    budgets: TickBudgets,
    settings: Settings,
    clock: &mut C,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> Result<Ran, Interrupt>
where
    H: PortHost,
    C: Clock,
    S: StopSignal,
    O: Write,
    E: Write,
{
    let mut datapath = host.build(opened.ports_mut()).map_err(Interrupt::Failed)?;
    if stop.stop() {
        return Err(Interrupt::Signalled);
    }
    let mut active = ActivePublication::new(storage, candidate).map_err(|error| {
        Interrupt::Failed(StartupError::new(
            Stage::Activate,
            None,
            Failure::Activation(error),
        ))
    })?;
    let mut observer = TickObserver::new(HealthPolicy::default());
    let _ = writeln!(
        err,
        "{READY} {} on {} port(s); send SIGINT or SIGTERM to stop",
        active.generation(),
        datapath.port_count()
    );
    let _ = err.flush();
    let loop_settings = LoopSettings {
        budgets,
        stats_interval_ms: settings.stats_interval_ms,
    };
    let end = run_loop(
        &mut active,
        &mut datapath,
        &mut observer,
        clock,
        stop,
        loop_settings,
        |active, datapath, observer, now| {
            let text = render(BlockKind::Periodic, now, active, datapath, observer);
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
        },
    );
    let _ = writeln!(
        err,
        "ruster run: {}; draining",
        match end {
            LoopEnd::Signal => "stop requested",
            LoopEnd::BackendStopped => "backend stopped after a fault",
        }
    );
    let shutdown = shutdown_drain(&mut datapath, clock, stop, settings.drain_deadline_ms);
    let now = clock.now();
    let final_block = render(BlockKind::Final, now, &active, &datapath, &observer);
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
        let _ = writeln!(err, "ruster run: drain failed: {fault}");
    }
    let _ = writeln!(
        err,
        "ruster run: {}; drain calls={} completed={} rx-released={} tx-in-flight={} \
         fill-in-kernel={} forced={} timed-out={}; detached and closed {ports} port(s)",
        match ran.end {
            LoopEnd::Signal => "stopped by signal",
            LoopEnd::BackendStopped => "stopped after a backend fault",
        },
        shutdown.calls,
        shutdown.completed,
        shutdown.rx_pending_released,
        shutdown.tx_in_flight,
        shutdown.fill_in_kernel,
        shutdown.forced,
        shutdown.timed_out,
    );
    if !cleanup.is_empty() || ran.end == LoopEnd::BackendStopped || shutdown.fault.is_some() {
        EXIT_RUNTIME
    } else if shutdown.tx_in_flight != 0 {
        EXIT_DRAIN_INCOMPLETE
    } else {
        0
    }
}

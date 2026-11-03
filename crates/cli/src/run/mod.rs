//! `ruster run --config <path>`: the AF_XDP static router (M2 S10a/S10b,
//! X04b), or with `backend.kind = "af-packet"` the AF_PACKET one
//! (AFPKT-015, see below). x86_64 Linux only.
//!
//! # Startup (failure atomic)
//!
//! 1. Load and validate the config without the service bridge. `[backend]`
//!    must be `kind = "af-xdp"` or `"af-packet"`; `sim` is refused
//!    (`stage=backend code=SIM_BACKEND`, exit 2) and points to `ruster
//!    run-sim`.
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
//! 6. Start the link watcher and the reload worker threads ([`workers`],
//!    H7), each dropping its own privileges first, then drop every
//!    privilege of every thread, irreversibly, before the first tick
//!    ([`privileges`]; the output threads dropped their own at spawn).
//!    `--keep-privileges` skips it; `--user`/`--group` also switch
//!    to that uid and gid. A failed drop rolls back like any startup
//!    failure (`stage=privilege-drop`, exit 1).
//!    Each thread then confines its filesystem view to what the run reads
//!    with the Landlock ruleset built first thing at startup
//!    ([`fs_confine`], H11; `--fs-confine landlock`, the default, or
//!    `off`): the output threads and the workers in the same prologue, the
//!    router thread right after its drop, which then requires every thread
//!    to be confined (`stage=fs-confine`, exit 1).
//! 7. Confine every thread to the syscall allowlist with one TSYNC
//!    seccomp filter ([`seccomp`], H8; `--seccomp kill`, the default, or
//!    `log`; `off` skips it), also with `--keep-privileges`. A failed
//!    install rolls back the same way (`stage=seccomp`, exit 1).
//!
//! 8. Report readiness: the stderr line, and with `NOTIFY_SOCKET` (systemd
//!    `Type=notify`/`notify-reload`) `READY=1` ([`notify`], H10; the
//!    notification socket was opened first thing, before any thread, so
//!    the run only `sendto`s on it).
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
//! # AF_PACKET (AFPKT-015)
//!
//! With `backend.kind = "af-packet"` steps 4 and 5 differ
//! ([`startup::open_packet_ports`], `execute_packet`): the preflight needs
//! only `CAP_NET_RAW` (nothing is pinned, no BPF object is loaded); per
//! port in `IfId` order the device is resolved by name over rtnetlink and
//! checked ([`checks::evaluate_packet_device`]: every kernel exposure
//! refusal of AF_XDP, MTU at most `max-frame-len - 14`, no upper device,
//! no GRO/LRO/hardware GRO, [`offload`]); then every packet socket is
//! opened at once (`ruster-io-afpacket`, failure atomic). Steps 6 to 8 and
//! the run loop are the same code over the AF_PACKET datapath (static
//! dispatch, [`engine::Datapath`]). Differences while running: the kernel
//! exposure conditions of the link watch are fatal ([`watch::ExposurePolicy`]),
//! a port whose device the backend found gone is fatal `DEVICE_REMOVED`, and
//! the kernel's `PACKET_STATISTICS` are folded in at every health sample.
//! The shutdown drains, then drops the datapath, which closes the sockets
//! ("closed N port(s)"; nothing to detach).
//!
//! # Run loop
//!
//! See [`engine`]: `run_tick` with the configured budgets and an `Instant`
//! clock, spin-then-wait idle strategy (a `poll` on every port's socket
//! that a frame ends at once, at most `--idle-wait-ms`, default 10 ms, and
//! at most 1 ms while time-driven work is pending; H9), no allocation per
//! tick, and a stats block on stdout every `--stats-interval` seconds.
//! Between ticks, on the cold path: the SIGHUP reload ([`reload`],
//! prepared on the reload worker thread), and the health and link watch
//! ([`watch`], the link round on the link watcher thread), whose fatal
//! events end the run like a stop request, with drain and close, but with
//! exit status 1; the systemd watchdog ping when due, and a stats block
//! (`kind=on-demand`) after a SIGUSR1 (H10). The workers are stopped with the loop and waited for at
//! most 500 ms ([`workers::WORKER_STOP_MS`]), then abandoned.
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
//!   adapter, activation, privilege drop, seccomp, key source; a transient open
//!   failure after the last attempt), a backend fault during the run, a fatal health or
//!   device event ([`watch`]: TX stall, persistent kick errors, device
//!   removed, MTU decreased or above the frame bound, link unverifiable),
//!   a drain failure, a stranded TX handoff after the drain, or a close
//!   error. A refused or failed reload never ends the run.
//! - 2: usage error or invalid configuration (including the `sim`
//!   backend).
//! - 3: shutdown deadline (or a second signal) with TX frames still owned
//!   by the kernel; everything was still detached and closed.
//! - 4: missing capability or too small `RLIMIT_MEMLOCK`, or a privilege
//!   drop that cannot work (`CAP_SETUID`/`CAP_SETGID` missing for
//!   `--user`/`--group`, or a kernel whose teardown needs `CAP_BPF`);
//!   nothing was acquired.

mod checks;
mod engine;
mod fs_confine;
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
mod notify;
#[cfg_attr(
    not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )),
    allow(dead_code)
)]
mod offload;
mod output;
mod privileges;
mod reload;
mod seccomp;
mod startup;
mod stats;
#[cfg(test)]
mod tests;
mod watch;
mod workers;

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
use fs_confine::{FsConfineMode, FsState};
use notify::Notifier;
use privileges::{DropFailure, Identity, PrivilegePolicy, PrivilegeState};
use reload::{ConfigSource, Preparer, ReloadWorker, Reloader};
use ruster_config::BackendKindV1;
use seccomp::{SeccompMode, SeccompState};
use startup::{
    open_packet_ports, open_ports, CloseFailure, Failure, Interrupt, OpenedPorts, PortHost, Stage,
    StartupError,
};
use stats::BlockKind;
use watch::{ExposurePolicy, LinkTarget};
use watch::{Thresholds, Watch, HEALTH_INTERVAL_MS, LINK_INTERVAL_MS};
use workers::{LinkWatcher, Worker, WORKER_STOP_MS};

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
    /// Age of an outstanding link round from which due rounds are stale
    /// (`--link-stale-secs`, [`watch`]).
    pub link_stale_ms: u64,
    pub reload_quiesce_ms: u64,
    /// A reload preparation running this long is warned once.
    pub reload_prepare_warn_ms: u64,
    /// Health thresholds of the watch.
    pub thresholds: Thresholds,
    /// The privilege drop after startup.
    pub privileges: PrivilegePolicy,
    /// The syscall filter after the drop.
    pub seccomp: SeccompMode,
    /// The filesystem confinement after the drop (H11).
    pub fs_confine: FsConfineMode,
    /// The longest idle wait (`--idle-wait-ms`, H9).
    pub idle_wait_ms: u64,
}

impl Settings {
    fn from_args(args: &RunArgs) -> Self {
        Self {
            privileges: privilege_policy(args),
            seccomp: args.seccomp,
            fs_confine: args.fs_confine,
            idle_wait_ms: args.idle_wait_ms,
            policy: CheckPolicy {
                allow_multi_queue: args.allow_multi_queue,
                allow_kernel_forwarding: args.allow_kernel_forwarding,
                allow_kernel_ipv6: args.allow_kernel_ipv6,
                allow_ipv4_weak_host: args.allow_ipv4_weak_host,
            },
            stats_interval_ms: args.stats_interval_secs.saturating_mul(1_000),
            drain_deadline_ms: DRAIN_DEADLINE_MS,
            startup_attempts: args.startup_attempts,
            health_interval_ms: HEALTH_INTERVAL_MS,
            link_interval_ms: LINK_INTERVAL_MS,
            link_stale_ms: args.link_stale_secs.saturating_mul(1_000),
            reload_quiesce_ms: reload::RELOAD_QUIESCE_MS,
            reload_prepare_warn_ms: reload::RELOAD_PREPARE_WARN_MS,
            thresholds: Thresholds::from_secs(
                args.tx_stall_warn_secs,
                args.tx_stall_fatal_secs,
                args.kick_errors_fatal_secs,
            ),
        }
    }
}

/// The privilege policy of the arguments: drop unless
/// `--keep-privileges`; `--user` and `--group` (accepted only together and
/// never with `--keep-privileges`) add the identity switch.
fn privilege_policy(args: &RunArgs) -> PrivilegePolicy {
    if args.keep_privileges {
        return PrivilegePolicy::Keep;
    }
    PrivilegePolicy::Drop {
        identity: match (args.user, args.group) {
            (Some(uid), Some(gid)) => Some(Identity { uid, gid }),
            _ => None,
        },
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
    if config.backend().kind() == BackendKindV1::Sim {
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
        "ruster run: unsupported platform: `ruster run` needs x86_64 Linux"
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

    // First, while this is the only thread: the systemd notification
    // variables are read and removed from the environment, and the socket
    // is opened before the privilege drop and the syscall filter.
    let notify = match Notifier::from_process_env() {
        Ok(notify) => notify,
        Err(error) => {
            let _ = writeln!(
                err,
                "ruster run: startup failed: stage=notify code={}",
                error.code()
            );
            return EXIT_RUNTIME;
        }
    };
    if let Err(name) = crate::signal::install()
        .and_then(|()| crate::signal::install_reload())
        .and_then(|()| crate::signal::install_stats())
    {
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
    // The output threads drop their privileges (and switch identity) at
    // spawn, so what that needs is checked before they start.
    let policy = settings.privileges;
    if let Err(error) = checks::linux::check_identity_switch(policy, config.backend().kind()) {
        let error = StartupError::new(Stage::Privileges, None, Failure::Privileges(error));
        return startup_failed(err, error, &[]);
    }
    // The filesystem ruleset, while this is the only thread: every thread
    // confines itself with it after its drop (the output threads below at
    // spawn, before startup).
    if settings.fs_confine == FsConfineMode::Landlock {
        match fs_confine::linux::prepare_process(&args.config) {
            Ok(None) => {}
            Ok(Some(directory)) => {
                let _ = writeln!(err, "ruster run: {}", fs_confine::broad_warning(directory));
            }
            Err(failure) => {
                let _ = writeln!(
                    err,
                    "ruster run: startup failed: stage=fs-confine {failure}"
                );
                if let Some(hint) = failure.hint() {
                    let _ = writeln!(err, "ruster run: {hint}");
                }
                return EXIT_RUNTIME;
            }
        }
    }
    // From here on nothing on this thread writes to a file descriptor: a
    // stalled stdout/stderr pipe cannot block the datapath or the shutdown.
    // The threads get dups of fd 1/2 as plain files: blocked writes hold
    // no std stdio lock that `main` or the exit path could wait on.
    let output = match output::ColdOutput::process(move || linux::thread_lockdown(policy)) {
        Ok(output) => output,
        Err(output::SpawnError::Prologue(error)) => {
            let error = prologue_failed(error);
            let _ = writeln!(err, "ruster run: startup failed: {error} thread=output");
            return EXIT_RUNTIME;
        }
        Err(output::SpawnError::Io) => {
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
        notify,
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
    notify: Notifier,
    clock: &mut C,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> u8
where
    H: PortHost,
    K: ProductionKeySource + Send + 'static,
    R: ConfigSource + Send + 'static,
    C: Clock,
    S: StopSignal,
    O: Write,
    E: Write,
{
    if config.backend().kind() == BackendKindV1::Sim {
        return EXIT_INVALID;
    }
    for warning in crate::config_cmd::sweep_warnings(&config)
        .into_iter()
        .flatten()
    {
        let _ = writeln!(err, "ruster run: warning: {warning}");
    }
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
    if config.backend().af_packet().is_some() {
        return execute_packet(
            host,
            config,
            sequencer,
            source,
            candidate,
            &mut storage,
            settings,
            notify,
            clock,
            stop,
            out,
            err,
        );
    }
    let ports = config
        .backend()
        .af_xdp()
        .map_or(0, |backend| backend.ports().len());
    if let Some(backend) = config.backend().af_xdp() {
        if let Err(error) = host.preflight(backend, settings.privileges) {
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
                config.interfaces(),
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
            Preparer::new(sequencer, config, source),
            settings,
            notify,
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
        Ok(ran) => finished(&ran, ports, &cleanup, true, out, err),
    }
}

/// The AF_PACKET startup, run, shutdown, and teardown (AFPKT-015): the
/// preflight (`CAP_NET_RAW`), the per-port device checks
/// ([`open_packet_ports`]), one failure-atomic open of every packet
/// socket, then the same run as AF_XDP ([`serve`]). Dropping the datapath
/// after the drain closes every socket; there is no session to close or
/// detach, and no transient open failure to retry.
#[allow(clippy::too_many_arguments)]
fn execute_packet<H, K, R, C, S, O, E>(
    host: &H,
    config: ValidatedConfigV1,
    sequencer: ProductionSequencer<K>,
    source: R,
    candidate: ValidatedCandidate,
    storage: &mut FullServiceStorage,
    settings: Settings,
    notify: Notifier,
    clock: &mut C,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> u8
where
    H: PortHost,
    K: ProductionKeySource + Send + 'static,
    R: ConfigSource + Send + 'static,
    C: Clock,
    S: StopSignal,
    O: Write,
    E: Write,
{
    let Some(backend) = config.backend().af_packet() else {
        return EXIT_INVALID;
    };
    if let Err(error) = host.preflight_packet(settings.privileges) {
        let error = StartupError::new(Stage::Privileges, None, Failure::Privileges(error));
        return startup_failed(err, error, &[]);
    }
    let ports = backend.ports().len();
    let interfaces = config.interfaces();
    let targets = match open_packet_ports(
        host,
        backend,
        interfaces,
        settings.policy,
        stop,
        |port, warnings| {
            for code in warnings.codes() {
                let _ = writeln!(err, "ruster run: warning: port={} {code}", port_label(port));
            }
        },
    ) {
        Ok(targets) => targets,
        Err(Interrupt::Failed(error)) => return startup_failed(err, error, &[]),
        Err(Interrupt::Signalled) => {
            let _ = writeln!(
                err,
                "ruster run: startup cancelled by signal; rolled back 0 port(s)"
            );
            return 0;
        }
    };
    let devices: Vec<(IfId, &str)> = backend
        .ports()
        .iter()
        .map(|port| (port.interface(), port.device()))
        .collect();
    let links = match host.links(&devices) {
        Ok(links) => links,
        Err(failure) => {
            return startup_failed(err, StartupError::new(Stage::Watch, None, failure), &[]);
        }
    };
    if stop.stop() {
        let _ = writeln!(
            err,
            "ruster run: startup cancelled by signal; rolled back 0 port(s)"
        );
        return 0;
    }
    let datapath = match host.open_packet(backend, &targets) {
        Ok(datapath) => datapath,
        Err(failure) => {
            return startup_failed(err, StartupError::new(Stage::Open, None, failure), &[]);
        }
    };
    drop(devices);
    let exposure = ExposurePolicy {
        allow_kernel_forwarding: settings.policy.allow_kernel_forwarding,
        allow_kernel_ipv6: settings.policy.allow_kernel_ipv6,
        allow_ipv4_weak_host: settings.policy.allow_ipv4_weak_host,
    };
    let outcome = serve(
        host,
        datapath,
        links,
        &targets,
        Some(exposure),
        candidate,
        storage,
        Preparer::new(sequencer, config, source),
        settings,
        notify,
        clock,
        stop,
        out,
        err,
    );
    match outcome {
        Err(Interrupt::Failed(error)) => startup_failed(err, error, &[]),
        Err(Interrupt::Signalled) => {
            let _ = writeln!(
                err,
                "ruster run: startup cancelled by signal; rolled back {ports} port(s)"
            );
            0
        }
        Ok(ran) => finished(&ran, ports, &[], false, out, err),
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
    preparer: Preparer<K, R>,
    settings: Settings,
    notify: Notifier,
    clock: &mut C,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> Result<Ran, Interrupt>
where
    H: PortHost,
    K: ProductionKeySource + Send + 'static,
    R: ConfigSource + Send + 'static,
    C: Clock,
    S: StopSignal,
    O: Write,
    E: Write,
{
    let devices: Vec<(IfId, &str)> = preparer
        .current()
        .backend()
        .af_xdp()
        .map(|backend| {
            backend
                .ports()
                .iter()
                .map(|port| (port.interface(), port.device()))
                .collect()
        })
        .unwrap_or_default();
    let links = host
        .links(&devices)
        .map_err(|failure| Interrupt::Failed(StartupError::new(Stage::Watch, None, failure)))?;
    let targets: Vec<_> = opened.ports_mut().iter().map(|port| port.link).collect();
    let datapath = host.build(opened.ports_mut()).map_err(Interrupt::Failed)?;
    serve(
        host, datapath, links, &targets, None, candidate, storage, preparer, settings, notify,
        clock, stop, out, err,
    )
}

/// Activation, the workers, the privilege drop, the filesystem and syscall
/// confinement, readiness, the run loop, the shutdown drain, and the final
/// stats over a built `datapath` of either backend (static dispatch: one
/// instance per backend). `exposure` makes the link watch's kernel
/// exposure conditions fatal (AF_PACKET, [`ExposurePolicy`]). The
/// datapath is dropped before returning, after the drain.
#[allow(clippy::too_many_arguments)]
fn serve<H, D, K, R, C, S, O, E>(
    host: &H,
    mut datapath: D,
    links: H::Links,
    targets: &[LinkTarget],
    exposure: Option<ExposurePolicy>,
    candidate: ValidatedCandidate,
    storage: &mut FullServiceStorage,
    preparer: Preparer<K, R>,
    settings: Settings,
    mut notify: Notifier,
    clock: &mut C,
    stop: &S,
    out: &mut O,
    err: &mut E,
) -> Result<Ran, Interrupt>
where
    H: PortHost,
    D: Datapath,
    K: ProductionKeySource + Send + 'static,
    R: ConfigSource + Send + 'static,
    C: Clock,
    S: StopSignal,
    O: Write,
    E: Write,
{
    let budgets = budgets(preparer.current());
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
    // The cold-path workers (H7) start before the drop and drop their own
    // privileges first, so the process-wide check below covers them.
    let (links, reloads) = spawn_workers(host, links, targets, preparer, settings.privileges)
        .map_err(Interrupt::Failed)?;
    #[cfg(test)]
    let (links, reloads) = {
        let lockstep = !tests::take_async_workers();
        (links.lockstep(lockstep), reloads.lockstep(lockstep))
    };
    let reloader = Reloader::new(reloads, budgets);
    // Nothing after this point needs a privilege (see [`privileges`]) or a
    // syscall outside the allowlist (see [`seccomp`]).
    let privileges = match settings.privileges {
        PrivilegePolicy::Keep => PrivilegeState::Kept,
        PrivilegePolicy::Drop { identity } => {
            let report = host.lockdown(identity).map_err(|error| {
                Interrupt::Failed(StartupError::new(
                    Stage::PrivilegeDrop,
                    None,
                    Failure::PrivilegeDrop(error),
                ))
            })?;
            PrivilegeState::Dropped(report)
        }
    };
    let _ = writeln!(err, "ruster run: {}", privileges.line());
    // Every other thread confined itself in its prologue; the router
    // thread last, still before the filter (which allows no Landlock call).
    let fs = match settings.fs_confine {
        FsConfineMode::Off => FsState::Off,
        FsConfineMode::Landlock => FsState::Confined(host.fs_confine().map_err(|failure| {
            Interrupt::Failed(StartupError::new(
                Stage::FsConfine,
                None,
                Failure::FsConfine(failure),
            ))
        })?),
    };
    let _ = writeln!(err, "ruster run: {}", fs.line());
    // Every thread exists and has dropped: confine them all at once.
    let seccomp = match settings.seccomp {
        SeccompMode::Off => SeccompState::Off,
        mode => {
            let report = host.confine(mode).map_err(|error| {
                Interrupt::Failed(StartupError::new(
                    Stage::Seccomp,
                    None,
                    Failure::Seccomp(error),
                ))
            })?;
            SeccompState::Confined { mode, report }
        }
    };
    let _ = writeln!(err, "ruster run: {}", seccomp.line());
    let hardening = Hardening {
        privileges,
        fs,
        seccomp,
    };
    let mut observer = TickObserver::new(HealthPolicy::default());
    let _ = writeln!(
        err,
        "{READY} {} on {} port(s); send SIGINT or SIGTERM to stop, SIGHUP to reload",
        active.generation(),
        datapath.port_count()
    );
    let _ = err.flush();
    notify.ready(active.generation().get());
    let loop_settings = LoopSettings {
        stats_interval_ms: settings.stats_interval_ms,
        health_interval_ms: settings.health_interval_ms,
        link_interval_ms: settings.link_interval_ms,
        reload_quiesce_ms: settings.reload_quiesce_ms,
        reload_prepare_warn_ms: settings.reload_prepare_warn_ms,
        idle_wait_ms: settings.idle_wait_ms,
    };
    let mut watch = Watch::new(targets, settings.thresholds)
        .allowing_kernel_forwarding(settings.policy.allow_kernel_forwarding)
        .allowing_kernel_ipv6(settings.policy.allow_kernel_ipv6)
        .with_link_stale_ms(settings.link_stale_ms);
    if let Some(exposure) = exposure {
        watch = watch.failing_on_kernel_exposure(exposure);
    }
    let mut control = Control {
        reloader,
        watch,
        links,
        idle: engine::IdleCounters {
            max_wait_ms: settings.idle_wait_ms,
            ..engine::IdleCounters::default()
        },
        notify,
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
        |kind, active, datapath, observer, status, now| {
            let text = render(kind, now, active, datapath, observer, status, hardening);
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
        },
    );
    // A reload still waiting for quiescence ends with the run.
    if let Some(outcome) = control.reloader.abandon("STOPPED", active.generation()) {
        let _ = writeln!(err, "ruster run: {outcome}");
    }
    // The workers end once their current request returns; that is waited
    // for after the drain, bounded (see [`workers`]).
    control.notify.stopping(|text| match end {
        LoopEnd::Signal => text.write_all(b"stop requested"),
        LoopEnd::BackendStopped => text.write_all(b"backend stopped after a fault"),
        LoopEnd::Invariant => text.write_all(b"invariant violation code=APPLY_REPORT_MISSING"),
        LoopEnd::Fatal { port, cause } => write!(
            text,
            "fatal health event port=if{} code={}",
            port.0,
            cause.code()
        ),
    });
    let workers_deadline = std::time::Instant::now() + Duration::from_millis(WORKER_STOP_MS);
    let workers = [
        ("link watcher", control.links.stop()),
        ("reload worker", control.reloader.stop_worker()),
    ];
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
    // The final block shows the kernel counters as of the drain.
    datapath.refresh();
    finish_workers(workers, workers_deadline, err);
    // AF_XDP: the ports are about to be detached, so whatever the kernel
    // would do with their frames now matters. AF_PACKET: the kernel acted
    // on every frame all along and goes on after the router stops.
    let packet = exposure.is_some();
    let exposure = control.watch.kernel_exposure();
    for (seen, line) in [
        (
            exposure.forwarding,
            "kernel forwarding is enabled; detached ports may be forwarded by the kernel",
        ),
        (
            exposure.addresses,
            "kernel IPv4 addresses are on a port; detached ports may be answered and routed by the kernel",
        ),
        (
            exposure.routes,
            "kernel IPv4 routes lead out of a port; detached ports may be routed by the kernel",
        ),
        (
            exposure.ipv6_forwarding,
            "kernel IPv6 forwarding is enabled for a port; detached ports may be forwarded by the kernel",
        ),
        (
            exposure.ipv6_addresses,
            "kernel IPv6 addresses are on a port; detached ports may be answered and routed by the kernel",
        ),
        (
            exposure.ipv6_enabled,
            "kernel IPv6 is enabled on a port; detached ports may be answered by the kernel's IPv6 stack",
        ),
        (
            exposure.ipv6_routes,
            "kernel IPv6 routes lead out of a port; detached ports may be routed by the kernel",
        ),
    ] {
        if seen {
            if packet {
                let condition = line.split(';').next().unwrap_or(line);
                let _ = writeln!(
                    err,
                    "ruster run: warning: {condition}; the kernel acts on every frame of the \
                     AF_PACKET ports, also now that the router stops"
                );
            } else {
                let _ = writeln!(err, "ruster run: warning: {line}");
            }
        }
    }
    let now = clock.now();
    let status = RunStatus {
        reload: control.reloader.counters(),
        watch: &control.watch,
        idle: control.idle,
        notify: control.notify.counters(),
    };
    let final_block = render(
        BlockKind::Final,
        now,
        &active,
        &datapath,
        &observer,
        &status,
        hardening,
    );
    drop(active);
    drop(datapath);
    Ok(Ran {
        end,
        shutdown,
        final_block,
    })
}

/// Spawns the link watcher and the reload worker, each running the host's
/// per-thread privilege drop of `policy` first.
fn spawn_workers<H, K, R>(
    host: &H,
    links: H::Links,
    targets: &[watch::LinkTarget],
    preparer: Preparer<K, R>,
    policy: PrivilegePolicy,
) -> Result<(LinkWatcher, ReloadWorker), StartupError>
where
    H: PortHost,
    K: ProductionKeySource + Send + 'static,
    R: ConfigSource + Send + 'static,
{
    let prologue = host.thread_prologue();
    let failed = |error| match error {
        output::SpawnError::Prologue(error) => prologue_failed(error),
        output::SpawnError::Io => StartupError::new(Stage::Workers, None, Failure::Spawn),
    };
    let watcher = LinkWatcher::spawn(links, targets, move || prologue(policy)).map_err(failed)?;
    let reloads = ReloadWorker::spawn(preparer, move || prologue(policy)).map_err(failed)?;
    Ok((watcher, reloads))
}

/// The startup error of a failed thread prologue: its filesystem
/// confinement (`stage=fs-confine`) or its privilege drop.
fn prologue_failed(error: DropFailure) -> StartupError {
    match error {
        DropFailure::Filesystem(failure) => {
            StartupError::new(Stage::FsConfine, None, Failure::FsConfine(failure))
        }
        error => StartupError::new(Stage::PrivilegeDrop, None, Failure::PrivilegeDrop(error)),
    }
}

/// Waits for the stopped workers until `deadline` and abandons those still
/// running (a watcher blocked on the RTNL lock), with a warning each.
fn finish_workers(
    workers: [(&str, Option<Worker>); 2],
    deadline: std::time::Instant,
    err: &mut impl Write,
) {
    for (name, worker) in workers {
        if worker.is_some_and(|worker| !worker.finish(deadline)) {
            let _ = writeln!(
                err,
                "ruster run: warning: the {name} thread did not end within {WORKER_STOP_MS} ms \
                 after the loop; abandoned"
            );
        }
    }
}

/// The privilege and syscall-filter state of the run, for the stats
/// blocks.
#[derive(Clone, Copy)]
struct Hardening {
    privileges: PrivilegeState,
    fs: FsState,
    seccomp: SeccompState,
}

fn render<D: Datapath>(
    kind: BlockKind,
    now: MonotonicMillis,
    active: &ActivePublication<'_, D::Io>,
    datapath: &D,
    observer: &TickObserver,
    status: &RunStatus<'_>,
    hardening: Hardening,
) -> String {
    let services = ServiceCounters::capture(
        active.resolution(),
        active.icmpv4_errors(),
        active.nat44_udp(),
        active.nat44_tcp(),
        active.firewall(),
    )
    .with_nat44_icmp(active.nat44_icmp());
    let resolution_index = active.resolution().index_counters();
    stats::block(kind, now, &observer.snapshot(now), &services, |out| {
        // H4b fail-closed index outcomes (ruster run only; not in run-sim).
        stats::write_fields(out, None, &resolution_index);
        datapath.write_stats(out);
        stats::write_fields(out, None, &status.reload);
        stats::write_fields(out, None, &status.idle);
        stats::write_fields(out, None, &status.notify);
        stats::write_fields(out, None, status.watch);
        for (interface, health) in status.watch.health() {
            stats::write_fields(out, Some(interface), &health);
        }
        stats::write_fields(out, None, &hardening.privileges);
        stats::write_fields(out, None, &hardening.fs);
        stats::write_fields(out, None, &hardening.seccomp);
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
    match error.failure {
        Failure::Privileges(PrivilegeFailure::MissingCapabilities(missing)) => {
            let startup = missing & !checks::SWITCH_CAPABILITIES;
            if startup == 1 << checks::cap::NET_RAW {
                // All an AF_PACKET run needs (and all an AF_XDP run lacks).
                let _ = writeln!(err, "ruster run: run as root or grant CAP_NET_RAW");
            } else if startup != 0 {
                let _ = writeln!(
                    err,
                    "ruster run: run as root or grant CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF, and CAP_PERFMON"
                );
            }
            if missing & checks::SWITCH_CAPABILITIES != 0 {
                let _ = writeln!(
                    err,
                    "ruster run: --user/--group also need CAP_SETUID and CAP_SETGID at startup"
                );
            }
        }
        Failure::Privileges(PrivilegeFailure::TeardownNeedsCapabilities) => {
            let _ = writeln!(
                err,
                "ruster run: before Linux 6.5 with kernel.unprivileged_bpf_disabled set, \
                 detaching needs CAP_BPF; use Linux 6.5 or newer, or --keep-privileges"
            );
        }
        _ => {}
    }
    report_cleanup(err, cleanup);
    startup_status(&error)
}

/// The final stats block and summary line; `detached`: the ports were
/// AF_XDP sessions (detached and closed), not AF_PACKET sockets (closed).
fn finished(
    ran: &Ran,
    ports: usize,
    cleanup: &[(IfId, CloseFailure)],
    detached: bool,
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
    let closing = if detached {
        "detached and closed"
    } else {
        "closed"
    };
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
            format!("{closing} {ports} port(s)")
        } else {
            format!("{closing} {closed} of {ports} port(s); see close failed")
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

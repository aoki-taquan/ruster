//! The `ruster run` worker loop and its shutdown drain, generic over the
//! datapath so they run against scripted fakes in tests.
//!
//! # Run loop
//!
//! One thread drives [`run_tick`] with the configured budgets and a
//! monotonic wall clock ([`SystemClock`], `Instant` since start) until the
//! stop flag is set or the backend stops itself. Each iteration reads the
//! clock, runs one tick, folds the report into the [`TickObserver`], samples
//! the O(1) state-table occupancy, and asks [`IdleBackoff`] whether to
//! pause. Nothing on this path allocates, formats, or locks; the periodic
//! stats block is the only cold work and runs at most once per interval.
//!
//! Kicks and need-wakeup are the adapter's: every `receive` reaps
//! completions, refills Fill, answers a Fill need-wakeup with a
//! non-sleeping `poll` kick, and settles owed TX kicks; `finish` kicks the
//! ports it published to. The loop adds nothing on top.
//!
//! # Idle strategy
//!
//! A tick that received no frame and requested no generated TX is idle.
//! After [`SPIN_TICKS`] idle ticks in a row the loop sleeps, starting at
//! [`MIN_PAUSE`] and doubling per further idle tick up to [`MAX_PAUSE`]; any
//! busy tick resets it to spinning. Trade-off: an idle router costs about
//! one wake-up per millisecond instead of a full core, and the first frame
//! after an idle period waits at most [`MAX_PAUSE`] (plus timer slack,
//! about 50 µs by default) in the RX ring before it is processed; under
//! load the loop never sleeps. At 1 ms the default 2048-entry RX ring
//! absorbs a burst of up to about 2 Mpps without loss while the loop
//! wakes. A blocking `poll` on the socket fds would wake sooner but needs a
//! new multi-fd syscall in the native crate; that is deferred (S10b).

use std::thread;
use std::time::{Duration, Instant};

use ruster_control::ActivePublication;
use ruster_core::{GeneratedPacketIo, IfId, MonotonicMillis, PacketIo, PublicationQuiescence};
use ruster_io_xdp_native::{KickError, XdpIoError};
use ruster_runtime::{
    run_tick, PhaseReport, RxPhaseReport, ServiceOccupancy, TickBudgets, TickObserver,
    TickPhaseSkip, TickReport,
};

/// Idle ticks before the loop starts to sleep.
pub const SPIN_TICKS: u32 = 64;
/// First sleep after [`SPIN_TICKS`] idle ticks.
pub const MIN_PAUSE: Duration = Duration::from_micros(50);
/// Longest sleep between idle ticks.
pub const MAX_PAUSE: Duration = Duration::from_millis(1);
/// Kick-and-reap rounds per port per drain call.
pub const DRAIN_ROUNDS: u32 = 4;
/// Pause between drain calls.
pub const DRAIN_PAUSE: Duration = Duration::from_millis(1);
/// Wall-clock bound of the whole shutdown drain.
pub const DRAIN_DEADLINE_MS: u64 = 2_000;

/// A datapath the loop drives: the core-facing I/O plus the shutdown and
/// stats operations of the backend.
pub trait Datapath {
    type Io: PacketIo + GeneratedPacketIo + PublicationQuiescence;

    fn io(&mut self) -> &mut Self::Io;

    /// One bounded shutdown drain call over every port (see
    /// `XdpPacketIo::drain`): stops RX/Fill and new TX for good, reclaims
    /// leaked leases and staged handoffs, returns unlent RX frames, and
    /// kicks/reaps at most `rounds` times per port.
    fn drain(&mut self, rounds: u32) -> Result<DrainProgress, XdpIoError>;

    /// Appends the backend's stats lines (cold path).
    fn write_stats(&self, out: &mut String);

    /// Interfaces of the ports, in `IfId` order.
    fn port_count(&self) -> usize;
}

/// Summed result of one drain call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrainProgress {
    /// Completions reaped by this call.
    pub completed: u32,
    /// Validated, unlent RX frames returned to their pools.
    pub rx_pending_released: u32,
    /// Frames the kernel still holds for TX.
    pub tx_in_flight: u32,
    /// Frames the kernel still holds from Fill (released by socket close).
    pub fill_in_kernel: u32,
    /// The last failed kick of this call.
    pub last_kick_error: Option<(IfId, KickError)>,
}

/// Monotonic time and pausing.
pub trait Clock {
    fn now(&mut self) -> MonotonicMillis;
    fn pause(&mut self, duration: Duration);
}

/// `Instant`-based milliseconds since construction, and `thread::sleep`.
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&mut self) -> MonotonicMillis {
        MonotonicMillis(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    fn pause(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// The stop request: a first signal stops, a second forces.
pub trait StopSignal {
    fn stop(&self) -> bool;
    fn force(&self) -> bool;
}

/// The process signal flags of [`crate::signal`].
pub struct ProcessSignals;

impl StopSignal for ProcessSignals {
    fn stop(&self) -> bool {
        crate::signal::stop_requested()
    }

    fn force(&self) -> bool {
        crate::signal::force_requested()
    }
}

/// Spin-then-sleep idle policy (see the module documentation).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdleBackoff {
    idle: u32,
}

impl IdleBackoff {
    /// Records one tick and returns how long to pause after it.
    pub fn after_tick(&mut self, busy: bool) -> Option<Duration> {
        if busy {
            self.idle = 0;
            return None;
        }
        self.idle = self.idle.saturating_add(1);
        let beyond = self.idle.checked_sub(SPIN_TICKS + 1)?;
        let pause = MIN_PAUSE
            .checked_mul(1_u32.checked_shl(beyond.min(16)).unwrap_or(u32::MAX))
            .unwrap_or(MAX_PAUSE);
        Some(pause.min(MAX_PAUSE))
    }
}

/// Whether a tick did packet work: frames received or generated TX
/// requested.
pub fn tick_was_busy<P, Q, R, G>(report: &TickReport<P, Q, R, G>) -> bool {
    let received = match &report.rx {
        RxPhaseReport::Completed(batch) | RxPhaseReport::AccountingInvariantViolation(batch) => {
            batch.received
        }
        RxPhaseReport::Skipped(_) | RxPhaseReport::ReceiveFailed(_) => 0,
    };
    let generated = |requested: usize| requested != 0;
    let arp = match &report.generated_arp {
        PhaseReport::Completed(phase) => generated(phase.accounting.tx_requested),
        _ => false,
    };
    let icmp = match &report.generated_icmpv4 {
        PhaseReport::Completed(phase) => generated(phase.accounting.tx_requested),
        _ => false,
    };
    received != 0 || arp || icmp
}

/// Whether the backend reported a terminal stop: `run_tick` skips RX with
/// `BackendStopped` once the backend's disposition is `Stop` (a datapath
/// fault or a drain), which never recovers.
pub fn backend_stopped<P, Q, R, G>(report: &TickReport<P, Q, R, G>) -> bool {
    matches!(
        report.rx,
        RxPhaseReport::Skipped(TickPhaseSkip::BackendStopped)
    )
}

/// Consecutive ticks whose I/O was skipped as `BackendIoNotReentrant`
/// (the adapter's `SkipIo` disposition: an engine-level stranded lease or
/// handoff that never clears by itself) before the loop treats the backend
/// as stopped. About one second at the 1 ms idle sleep.
pub const WEDGED_TICKS: u32 = 1_024;

/// Ends the loop on a terminal backend stop, or on [`WEDGED_TICKS`]
/// consecutive non-reentrant skips; any other tick resets the count.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackendWatch {
    skipped: u32,
}

impl BackendWatch {
    pub fn after_tick<P, Q, R, G>(&mut self, report: &TickReport<P, Q, R, G>) -> Option<LoopEnd> {
        if backend_stopped(report) {
            return Some(LoopEnd::BackendStopped);
        }
        if matches!(
            report.rx,
            RxPhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
        ) {
            self.skipped = self.skipped.saturating_add(1);
            if self.skipped >= WEDGED_TICKS {
                return Some(LoopEnd::BackendStopped);
            }
        } else {
            self.skipped = 0;
        }
        None
    }
}

/// Why the run loop returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopEnd {
    /// SIGINT or SIGTERM.
    Signal,
    /// The backend reported a terminal stop (a datapath fault).
    BackendStopped,
}

/// Run-loop settings.
#[derive(Clone, Copy, Debug)]
pub struct LoopSettings {
    pub budgets: TickBudgets,
    /// Milliseconds between periodic stats; 0 disables them.
    pub stats_interval_ms: u64,
}

/// Runs ticks until a stop request or a backend stop. `periodic` is called
/// between ticks once per `stats_interval_ms` (cold path).
pub fn run_loop<'s, D, C, S, F>(
    active: &mut ActivePublication<'s, D::Io>,
    datapath: &mut D,
    observer: &mut TickObserver,
    clock: &mut C,
    stop: &S,
    settings: LoopSettings,
    mut periodic: F,
) -> LoopEnd
where
    D: Datapath,
    C: Clock,
    S: StopSignal,
    F: FnMut(&ActivePublication<'s, D::Io>, &D, &TickObserver, MonotonicMillis),
{
    let mut backoff = IdleBackoff::default();
    let mut watch = BackendWatch::default();
    let mut last_stats = clock.now();
    loop {
        if stop.stop() {
            return LoopEnd::Signal;
        }
        let now = clock.now();
        let report = run_tick(active, None, datapath.io(), now, settings.budgets, observer);
        observer.observe_tick(now, Some(active.generation()), &report);
        observer.record_occupancy(ServiceOccupancy::capture(
            active.icmpv4_errors(),
            active.nat44_udp(),
            active.nat44_tcp(),
            active.firewall(),
        ));
        if let Some(end) = watch.after_tick(&report) {
            return end;
        }
        let busy = tick_was_busy(&report);
        drop(report);
        if settings.stats_interval_ms != 0
            && now.0.saturating_sub(last_stats.0) >= settings.stats_interval_ms
        {
            last_stats = now;
            periodic(active, datapath, observer, now);
        }
        if let Some(pause) = backoff.after_tick(busy) {
            clock.pause(pause);
        }
    }
}

/// Outcome of [`shutdown_drain`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Drain calls made.
    pub calls: u32,
    /// Completions reaped over all calls.
    pub completed: u64,
    /// RX frames returned unlent.
    pub rx_pending_released: u64,
    /// Frames the kernel still held for TX after the last call.
    pub tx_in_flight: u32,
    /// Frames the kernel still held from Fill after the last call.
    pub fill_in_kernel: u32,
    /// A second signal cut the drain short.
    pub forced: bool,
    /// The deadline passed with TX still in flight.
    pub timed_out: bool,
    /// The first drain failure; the drain stopped there.
    pub fault: Option<XdpIoError>,
    /// The last kick failure any drain call reported.
    pub last_kick_error: Option<(IfId, KickError)>,
}

/// Stable value-free token of a kick failure.
pub fn kick_error_token(error: KickError) -> String {
    match error {
        KickError::NetworkDown => "NETWORK_DOWN".to_owned(),
        KickError::NotBound => "NOT_BOUND".to_owned(),
        KickError::Errno(errno) => format!("ERRNO_{errno}"),
        KickError::Rejected => "REJECTED".to_owned(),
    }
}

/// `none` or `if<id>:<token>`.
pub fn last_kick_label(last: Option<(IfId, KickError)>) -> String {
    match last {
        None => "none".to_owned(),
        Some((interface, error)) => {
            format!("{}:{}", port_label(interface), kick_error_token(error))
        }
    }
}

/// Shutdown drain: stop RX (the loop no longer ticks), then call
/// [`Datapath::drain`] until no TX is in flight, the deadline passes, or a
/// second signal forces teardown. The first call always runs (a forced
/// shutdown makes it with zero kick rounds), so RX, Fill, and new TX stop,
/// leases and staged handoffs are reclaimed, and the kernel-held frames are
/// counted, before the caller detaches and closes.
pub fn shutdown_drain<D: Datapath, C: Clock, S: StopSignal>(
    datapath: &mut D,
    clock: &mut C,
    stop: &S,
    deadline_ms: u64,
) -> ShutdownReport {
    let mut report = ShutdownReport::default();
    let start = clock.now();
    loop {
        let forced = stop.force();
        let rounds = if forced { 0 } else { DRAIN_ROUNDS };
        report.calls = report.calls.saturating_add(1);
        match datapath.drain(rounds) {
            Ok(progress) => {
                report.completed = report
                    .completed
                    .saturating_add(u64::from(progress.completed));
                report.rx_pending_released = report
                    .rx_pending_released
                    .saturating_add(u64::from(progress.rx_pending_released));
                report.tx_in_flight = progress.tx_in_flight;
                report.fill_in_kernel = progress.fill_in_kernel;
                if progress.last_kick_error.is_some() {
                    report.last_kick_error = progress.last_kick_error;
                }
            }
            Err(error) => {
                report.fault = Some(error);
                return report;
            }
        }
        report.forced |= forced;
        if report.tx_in_flight == 0 || forced {
            return report;
        }
        if clock.now().0.saturating_sub(start.0) >= deadline_ms {
            report.timed_out = true;
            return report;
        }
        clock.pause(DRAIN_PAUSE);
    }
}

/// `if<id>` label of an interface.
pub fn port_label(interface: IfId) -> String {
    format!("if{}", interface.0)
}

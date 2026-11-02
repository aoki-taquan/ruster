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
//! pause. Nothing on this path allocates, formats, or locks; the cold work
//! between ticks is the periodic stats block (at most once per interval),
//! a SIGHUP reload (only on request; see [`super::reload`]), and the health
//! sample and rtnetlink link query round of [`super::watch`] (at most every
//! 500 ms and 1 s; allocation-free unless an event line is printed).
//!
//! A pending reload holds RX back (no tick runs) until the backend is
//! quiescent or [`super::reload::RELOAD_QUIESCE_MS`] passed; its candidate
//! then rides the publication phase of the next tick, before RX, so no
//! batch or lease is open across the switch.
//!
//! Kicks and need-wakeup are the adapter's: every `receive` reaps
//! completions, refills Fill, answers a Fill need-wakeup with a
//! non-sleeping `poll` kick, and settles owed TX kicks; `finish` kicks the
//! ports it published to. The loop adds nothing on top but its clock
//! reading, handed to the backend once per iteration
//! ([`Datapath::set_clock`]) so a port whose link is down retries its owed
//! kick at most every 1 ms doubling to 64 ms instead of at every settle.
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
//! new multi-fd syscall in the native crate; that is deferred (CLI-034).

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use ruster_control::{ActivePublication, ProductionKeySource};
use ruster_core::{
    GeneratedPacketIo, IfId, MonotonicMillis, PacketIo, PublicationQuiescence,
    PublicationQuiescenceDisposition,
};
use ruster_io_xdp_native::{KickError, XdpIoError};
use ruster_runtime::{
    run_tick, ApplyFlushCounts, PhaseReport, PublicationOutcome, RxPhaseReport, ServiceOccupancy,
    TickObserver, TickPhaseSkip, TickReport,
};

use super::netlink::{LinkFacts, NetlinkError};
use super::reload::{ConfigSource, ReloadCounters, Reloader, TickApply};
use super::watch::{Fatal, Forwarding, LinkTarget, PortSample, Watch, WatchEvent};

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

/// Backend I/O that takes the loop's clock reading at a cold boundary.
/// The AF_XDP adapter rate-limits TX kick retries on a down link with it.
pub trait ClockedIo {
    /// Hands the backend the current clock reading (never per packet).
    fn set_clock(&mut self, now: MonotonicMillis);
}

/// A datapath the loop drives: the core-facing I/O plus the shutdown and
/// stats operations of the backend.
pub trait Datapath {
    type Io: PacketIo + GeneratedPacketIo + PublicationQuiescence + ClockedIo;

    fn io(&mut self) -> &mut Self::Io;

    /// Hands the backend the loop's clock reading (cold boundary: once per
    /// loop iteration, before any I/O of that iteration): forwards to
    /// [`ClockedIo::set_clock`] of the I/O.
    fn set_clock(&mut self, now: MonotonicMillis) {
        self.io().set_clock(now);
    }

    /// One bounded shutdown drain call over every port (see
    /// `XdpPacketIo::drain`): stops RX/Fill and new TX for good, reclaims
    /// leaked leases and staged handoffs, returns unlent RX frames, and
    /// kicks/reaps at most `rounds` times per port.
    fn drain(&mut self, rounds: u32) -> Result<DrainProgress, XdpIoError>;

    /// Appends the backend's stats lines (cold path).
    fn write_stats(&self, out: &mut String);

    /// Interfaces of the ports, in `IfId` order.
    fn port_count(&self) -> usize;

    /// Hands each port's health counters to `visit` (cold path, no
    /// allocation).
    fn sample_ports(&self, visit: &mut impl FnMut(PortSample));

    /// Whether a publication could be applied right now: the backend's
    /// own quiescence check (which reaps completions and kicks owed TX
    /// first), with the guard dropped at once. `Err` carries what the
    /// backend says about I/O meanwhile.
    fn probe_quiescence(&mut self) -> Result<(), PublicationQuiescenceDisposition> {
        match self.io().try_publication_quiescence() {
            Ok(guard) => {
                drop(guard);
                Ok(())
            }
            Err(error) => {
                Err(<Self::Io as PublicationQuiescence>::quiescence_error_disposition(&error))
            }
        }
    }
}

/// rtnetlink link queries of the ports (cold path).
pub trait LinkMonitor {
    /// Link facts of `target`'s interface index in the router's network
    /// namespace.
    fn query(&mut self, target: &LinkTarget) -> Result<LinkFacts, NetlinkError>;

    /// Kernel IPv4 addresses on `target`'s interface index.
    fn ipv4_addresses(&mut self, target: &LinkTarget) -> Result<u32, NetlinkError>;

    /// The kernel IPv4 forwarding sysctls (global and `target`'s device);
    /// `Err` if either is unreadable. Cold path, no allocation.
    fn forwarding(&mut self, target: &LinkTarget) -> Result<Forwarding, ()>;
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
    /// TX handoffs staged but neither submitted nor cancelled (none on
    /// any adapter path; only a leak can leave one). Not in the kernel:
    /// the socket close releases them, but the run was not clean.
    pub tx_handoffs: u32,
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

/// The stop request: a first signal stops, a second forces; and the
/// reload request (SIGHUP).
pub trait StopSignal {
    fn stop(&self) -> bool;
    fn force(&self) -> bool;
    /// Takes a pending reload request (once per request).
    fn take_reload(&self) -> bool {
        false
    }
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

    fn take_reload(&self) -> bool {
        crate::signal::take_reload_request()
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
    /// The health or link watch found a fatal condition on a port.
    Fatal { port: IfId, cause: Fatal },
    /// A reload was applied but the commit report did not match its
    /// generation (publication contract violated).
    Invariant,
}

/// Run-loop settings.
#[derive(Clone, Copy, Debug)]
pub struct LoopSettings {
    /// Milliseconds between periodic stats; 0 disables them.
    pub stats_interval_ms: u64,
    /// Milliseconds between backend health samples.
    pub health_interval_ms: u64,
    /// Milliseconds between rtnetlink link query rounds.
    pub link_interval_ms: u64,
    /// Longest wait of a pending reload for quiescence.
    pub reload_quiesce_ms: u64,
}

/// The cold-path control of the loop: reload, health, and link watch.
pub struct Control<K: ProductionKeySource, R, L> {
    pub reloader: Reloader<K, R>,
    pub watch: Watch,
    pub links: L,
}

/// What a periodic stats block reads besides the publication and backend.
pub struct RunStatus<'a> {
    pub reload: ReloadCounters,
    pub watch: &'a Watch,
}

/// Runs ticks until a stop request, a backend stop, or a fatal watch
/// event. Between ticks (cold path): a reload request is prepared and,
/// once the backend is quiescent, its candidate rides the next tick's
/// publication phase; the health and link watch sample at their
/// intervals; `periodic` is called once per `stats_interval_ms`. Lines go
/// to `err`.
#[allow(clippy::too_many_arguments)]
pub fn run_loop<'s, D, C, S, K, R, L, E, F>(
    active: &mut ActivePublication<'s, D::Io>,
    datapath: &mut D,
    observer: &mut TickObserver,
    clock: &mut C,
    stop: &S,
    settings: LoopSettings,
    control: &mut Control<K, R, L>,
    err: &mut E,
    mut periodic: F,
) -> LoopEnd
where
    D: Datapath,
    C: Clock,
    S: StopSignal,
    K: ProductionKeySource,
    R: ConfigSource,
    L: LinkMonitor,
    E: Write,
    F: FnMut(&ActivePublication<'s, D::Io>, &D, &TickObserver, &RunStatus<'_>, MonotonicMillis),
{
    let mut backoff = IdleBackoff::default();
    let mut wedge = BackendWatch::default();
    let mut last_stats = clock.now();
    let mut budgets = control.reloader.budgets();
    loop {
        if stop.stop() {
            return LoopEnd::Signal;
        }
        let now = clock.now();
        datapath.set_clock(now);
        let generation = active.generation();
        if control.reloader.pending_since().is_none() && stop.take_reload() {
            let _ = writeln!(
                err,
                "ruster run: reload requested (generation {generation})"
            );
            if let Some(outcome) = control.reloader.prepare(active, now) {
                let _ = writeln!(err, "ruster run: {outcome}");
            }
        }
        let mut candidate = None;
        if let Some(since) = control.reloader.pending_since() {
            match datapath.probe_quiescence() {
                Ok(()) => candidate = control.reloader.take_candidate(),
                Err(PublicationQuiescenceDisposition::Stop) => {
                    if let Some(outcome) = control.reloader.abandon("BACKEND_STOPPED", generation) {
                        let _ = writeln!(err, "ruster run: {outcome}");
                    }
                }
                Err(_) if now.0.saturating_sub(since.0) >= settings.reload_quiesce_ms => {
                    if let Some(outcome) = control.reloader.abandon("TIMEOUT", generation) {
                        let _ = writeln!(err, "ruster run: {outcome}");
                    }
                }
                Err(_) => {
                    // Hold RX back so in-flight TX can complete; the probe
                    // reaped and kicked.
                    clock.pause(MIN_PAUSE);
                    continue;
                }
            }
        }
        let reloading = candidate.is_some();
        let report = run_tick(active, candidate, datapath.io(), now, budgets, observer);
        let generation = active.generation();
        observer.observe_tick(now, Some(generation), &report);
        if reloading {
            let result = match &report.publication {
                PublicationOutcome::Applied => {
                    let applied = active
                        .last_apply()
                        .filter(|apply| apply.generation == generation)
                        .map(|apply| {
                            let flush = ApplyFlushCounts::from_reports(
                                apply.resolution,
                                apply.icmpv4_errors,
                                apply.nat44_udp,
                                apply.nat44_tcp,
                                apply.firewall,
                            );
                            (apply.previous_generation, flush)
                        });
                    // Tests drop the report here to reach the invariant path.
                    #[cfg(test)]
                    let applied = applied.filter(|_| !super::tests::take_apply_report_drop());
                    TickApply::Applied(applied)
                }
                PublicationOutcome::Rejected(error) => TickApply::Rejected(*error),
                PublicationOutcome::Unchanged | PublicationOutcome::Deferred { .. } => {
                    TickApply::NotApplied
                }
            };
            if let TickApply::Applied(Some((_, flush))) = result {
                observer.record_apply_flush(generation, flush);
            }
            if let Some(outcome) = control.reloader.finish(generation, result) {
                let _ = writeln!(err, "ruster run: {outcome}");
            }
            budgets = control.reloader.budgets();
            if matches!(result, TickApply::Applied(None)) {
                // Applied without a matching report: the publication
                // contract is broken; stop rather than guess.
                return LoopEnd::Invariant;
            }
        }
        observer.record_occupancy(ServiceOccupancy::capture(
            active.icmpv4_errors(),
            active.nat44_udp(),
            active.nat44_tcp(),
            active.firewall(),
        ));
        if let Some(end) = wedge.after_tick(&report) {
            return end;
        }
        let busy = tick_was_busy(&report);
        drop(report);
        if let Some(end) = watch_step(datapath, control, now, settings, err) {
            return end;
        }
        if settings.stats_interval_ms != 0
            && now.0.saturating_sub(last_stats.0) >= settings.stats_interval_ms
        {
            last_stats = now;
            let status = RunStatus {
                reload: control.reloader.counters(),
                watch: &control.watch,
            };
            periodic(active, datapath, observer, &status, now);
        }
        if let Some(pause) = backoff.after_tick(busy) {
            clock.pause(pause);
        }
    }
}

/// The health sample and link query round, when due. Returns the first
/// fatal event as the loop end.
fn watch_step<D, K, R, L, E>(
    datapath: &D,
    control: &mut Control<K, R, L>,
    now: MonotonicMillis,
    settings: LoopSettings,
    err: &mut E,
) -> Option<LoopEnd>
where
    D: Datapath,
    K: ProductionKeySource,
    L: LinkMonitor,
    E: Write,
{
    let mut end = None;
    let mut on_event = |event: WatchEvent| {
        if let WatchEvent::Fatal { port, cause } = event {
            if end.is_some() {
                return;
            }
            end = Some(LoopEnd::Fatal { port, cause });
        }
        let _ = writeln!(err, "ruster run: {event}");
    };
    let watch = &mut control.watch;
    if watch.health_due(now, settings.health_interval_ms) {
        datapath.sample_ports(&mut |sample| watch.on_sample(now, sample, &mut on_event));
    }
    if watch.link_due(now, settings.link_interval_ms) {
        for index in 0..watch.port_count() {
            let Some(target) = watch.target(index) else {
                break;
            };
            let result = control.links.query(&target);
            let linked = result.is_ok();
            watch.on_link(index, result, &mut on_event);
            if linked {
                let addresses = control.links.ipv4_addresses(&target);
                watch.on_addresses(index, addresses, &mut on_event);
            }
            let forwarding = control.links.forwarding(&target);
            watch.on_forwarding(index, forwarding, &mut on_event);
        }
    }
    end
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
    /// Stranded TX handoffs after the last call (exit 1 if nonzero).
    pub tx_handoffs: u32,
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
                report.tx_handoffs = progress.tx_handoffs;
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

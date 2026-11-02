//! The `ruster run` worker loop and its shutdown drain, generic over the
//! datapath so they run against scripted fakes in tests.
//!
//! # Run loop
//!
//! One thread drives [`run_tick_reclocked`] with the configured budgets and
//! a monotonic wall clock ([`SystemClock`], `Instant` since start) until
//! the stop flag is set or the backend stops itself. Each iteration reads
//! the clock (again after the publication phase of a tick that publishes a
//! reload candidate, before its RX), runs one tick, folds the report into
//! the [`TickObserver`], samples the O(1) state-table occupancy, and asks
//! [`IdleBackoff`] whether to pause. Nothing on this path allocates,
//! formats, or locks; the cold work between ticks is the periodic stats
//! block (at most once per interval), an on-demand stats block after a
//! SIGUSR1 (H10), the systemd watchdog ping when due ([`Notifier`]; a
//! stack-composed `sendto`, no allocation), a SIGHUP reload (only on request; see
//! [`super::reload`]), the health sample of [`super::watch`] (at most every
//! 500 ms), and the link round: requested from the link watcher thread at
//! most every 1 s and folded in when it came back ([`super::workers`], H7).
//! Allocation-free unless an event line is printed. Neither the link
//! round's rtnetlink and sysctl I/O nor the reload's read, parse,
//! validation, candidate, and plan run on this thread: it only hands
//! requests to the worker threads and takes their answers with non-blocking
//! `try_send`/`try_recv`.
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
//! Under load the loop never waits. After [`SPIN_TICKS`] idle ticks in a
//! row, each further idle tick is followed by one blocking wait
//! ([`Datapath::wait_rx`], H9): a `poll(2)` with `POLLIN` over the AF_XDP
//! sockets of every port, which returns as soon as the kernel puts an RX
//! descriptor on any port, when a signal handler runs on the router
//! thread (`EINTR`), or at the timeout of [`idle_timeout_ms`]:
//!
//! - at most `--idle-wait-ms` ([`crate::args::DEFAULT_IDLE_WAIT_MS`], 1 to
//!   [`crate::args::MAX_IDLE_WAIT_MS`]);
//! - at most [`SHORT_WAIT_MS`] while time-driven work is pending
//!   ([`Pending`]: a resolution state, failure hold, or queued ARP; a
//!   queued ICMPv4 error; an unsolicited-SYN hold, B3; TX in flight or an
//!   owed kick in the backend; a reload request out on the worker), so the
//!   tick cadence those depend on stays what it was before H9 (about one
//!   tick per millisecond when idle);
//! - never past the loop's own next deadline (periodic stats, health
//!   sample, link round, [`Watch::next_due`]; the systemd watchdog ping,
//!   [`Notifier::watchdog_due`]).
//!
//! A wait that reported RX readiness must be followed by a busy tick; if
//! the next tick is idle anyway (readiness that RX cannot consume), the
//! next wait is a plain sleep of at most [`SHORT_WAIT_MS`] instead, so a
//! socket that stays ready without work cannot turn the loop into a
//! busy spin. A wait that cannot block ([`WaitError`]) sleeps the same
//! way. Trade-off: an idle router wakes about 100 times per second (at
//! the 10 ms default) instead of about 1000, and the first frame after an
//! idle period is processed as soon as the kernel wakes the router thread
//! instead of up to 1 ms later; a signal delivered to another thread, a
//! worker's reply, and anything the runtime only notices at a tick are
//! seen at most one wait later. Every wait counts in the `idle.*` stats
//! ([`IdleCounters`]).

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use ruster_control::ActivePublication;
use ruster_core::{
    GeneratedPacketIo, IfId, MonotonicMillis, PacketIo, PublicationQuiescence,
    PublicationQuiescenceDisposition,
};
use ruster_io_xdp_native::{KickError, XdpIoError};
use ruster_runtime::{
    run_tick_reclocked, ApplyFlushCounts, PhaseReport, PublicationOutcome, RxPhaseReport,
    ServiceOccupancy, TickObserver, TickPhaseSkip, TickReport,
};

use super::netlink::{LinkFacts, NetlinkError};
use super::notify::{Notifier, NotifyCounters};
use super::reload::{ReloadCounters, Reloader, TickApply};
use super::stats::BlockKind;
use super::watch::{Fatal, Forwarding, Ipv6Sample, LinkTarget, PortSample, Watch, WatchEvent};
use super::workers::LinkWatcher;

/// Idle ticks before the loop starts to wait.
pub const SPIN_TICKS: u32 = 64;
/// Pause of a tick held back by a pending reload's quiescence.
pub const MIN_PAUSE: Duration = Duration::from_micros(50);
/// Longest idle wait while time-driven work is pending ([`Pending`]), and
/// the longest fallback sleep: the pre-H9 idle cadence.
pub const SHORT_WAIT_MS: u64 = 1;
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

    /// The idle wait (cold boundary, between ticks): returns at once while
    /// a port has RX work, otherwise blocks until RX work arrives, a signal
    /// handler runs, or `timeout_ms` passes. No allocation. The default
    /// cannot block.
    fn wait_rx(&mut self, timeout_ms: u32) -> Result<IdleWake, WaitError> {
        let _ = timeout_ms;
        Err(WaitError::Unsupported)
    }

    /// Whether the backend has TX in flight or owes a kick: work that only
    /// later ticks complete, which an RX wait does not notice.
    fn tx_outstanding(&self) -> bool {
        false
    }

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

/// rtnetlink link queries of the ports (cold path; the link watcher
/// thread's, [`super::workers::probe_round`]).
pub trait LinkMonitor {
    /// Link facts of `target`'s interface index in the router's network
    /// namespace.
    fn query(&mut self, target: &LinkTarget) -> Result<LinkFacts, NetlinkError>;

    /// Kernel IPv4 addresses on `target`'s interface index.
    fn ipv4_addresses(&mut self, target: &LinkTarget) -> Result<u32, NetlinkError>;

    /// Kernel IPv4 routes out of `target`'s interface index in every
    /// table.
    fn ipv4_routes(&mut self, target: &LinkTarget) -> Result<u32, NetlinkError>;

    /// The kernel IPv6 facts of `target`'s port ([`Ipv6Sample`]). Cold
    /// path, no allocation.
    fn ipv6(&mut self, target: &LinkTarget) -> Ipv6Sample;

    /// The kernel IPv4 forwarding sysctls (global and `target`'s device);
    /// `Err` if either is unreadable. Cold path, no allocation.
    fn forwarding(&mut self, target: &LinkTarget) -> Result<Forwarding, ()>;

    /// The IPv4 weak-host exposure of `target`'s port: `Some(true)` if the
    /// effective `rp_filter` is 0, `None` if
    /// unreadable. Cold path, no allocation.
    fn ipv4_weak_host(&mut self, target: &LinkTarget) -> Option<bool>;
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
    /// Takes a pending on-demand stats request (SIGUSR1, H10; once per
    /// request).
    fn take_stats(&self) -> bool {
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

    fn take_stats(&self) -> bool {
        crate::signal::take_stats_request()
    }
}

/// How an idle wait ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdleWake {
    /// A port has RX work (or a socket condition to look at).
    Ready,
    /// The timeout passed.
    TimedOut,
    /// A signal handler ran (`EINTR`).
    Interrupted,
}

/// Why an idle wait could not block; the loop sleeps instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitError {
    /// No blocking wait for this datapath (scripted tests).
    Unsupported,
    /// `poll` failed with this errno.
    Errno(u16),
}

/// Spin-then-wait idle policy (see the module documentation): whether a
/// tick is followed by a wait, and whether that wait must be a plain
/// sleep because the previous one reported readiness that no tick used.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdleBackoff {
    idle: u32,
    /// The last wait said `Ready` and no busy tick followed yet.
    unconsumed_ready: bool,
}

/// What the loop does after a tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdleAction {
    /// Run the next tick at once (busy, or still spinning).
    Spin,
    /// Block in the datapath's RX wait.
    Wait,
    /// Sleep (at most [`SHORT_WAIT_MS`]): the last wait's readiness was
    /// not consumed by the tick after it.
    Sleep,
}

impl IdleBackoff {
    /// Records one tick and returns what to do after it.
    pub fn after_tick(&mut self, busy: bool) -> IdleAction {
        if busy {
            self.idle = 0;
            self.unconsumed_ready = false;
            return IdleAction::Spin;
        }
        self.idle = self.idle.saturating_add(1);
        if self.idle <= SPIN_TICKS {
            return IdleAction::Spin;
        }
        if std::mem::take(&mut self.unconsumed_ready) {
            IdleAction::Sleep
        } else {
            IdleAction::Wait
        }
    }

    /// Records how the wait after the last tick ended.
    pub fn after_wait(&mut self, wake: IdleWake) {
        self.unconsumed_ready = wake == IdleWake::Ready;
    }
}

/// Time-driven work that progresses only at ticks (see the module
/// documentation): while any is pending, idle waits stay short.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Pending {
    /// Resolution states (retries, `Failed`), failure holds, or queued ARP
    /// requests: the resolution timer and failure dispatch sweep them a
    /// budget of slots per tick.
    pub resolution: bool,
    /// Queued ICMPv4 errors, or unsolicited-SYN holds (B3) whose 6 s
    /// deadline the failure dispatch releases.
    pub icmpv4: bool,
    /// TX in flight or an owed kick (reaps, rate-limited retries on a down
    /// link).
    pub tx: bool,
    /// A reload request out on the reload worker.
    pub reload: bool,
}

impl Pending {
    /// Whether anything is pending.
    pub const fn any(self) -> bool {
        self.resolution || self.icmpv4 || self.tx || self.reload
    }
}

/// The timeout of the idle wait after a tick at `now`: `max_wait_ms`, or
/// [`SHORT_WAIT_MS`] (never more than `max_wait_ms`) while work is
/// `pending`, and never past `next_deadline`. 0 means a deadline is due:
/// run the next tick without waiting.
pub fn idle_timeout_ms(
    now: MonotonicMillis,
    max_wait_ms: u64,
    pending: Pending,
    next_deadline: Option<MonotonicMillis>,
) -> u64 {
    let cap = if pending.any() {
        max_wait_ms.min(SHORT_WAIT_MS)
    } else {
        max_wait_ms
    };
    next_deadline.map_or(cap, |deadline| cap.min(deadline.0.saturating_sub(now.0)))
}

/// Counters of the idle waits (`idle.*` in the stats blocks).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdleCounters {
    /// The configured longest wait (`--idle-wait-ms`).
    pub max_wait_ms: u64,
    /// Blocking waits made.
    pub waits: u64,
    /// ... ended by RX work.
    pub woken: u64,
    /// ... that reached their timeout.
    pub timed_out: u64,
    /// ... ended by a signal handler.
    pub interrupted: u64,
    /// Waits that the pending cap ([`Pending`]) made shorter than the
    /// configured wait and the next deadline would have (not counted when
    /// a deadline was nearer anyway, or with `--idle-wait-ms 1`).
    pub short: u64,
    /// Plain sleeps instead of a wait: unconsumed readiness or a wait that
    /// could not block.
    pub sleeps: u64,
    /// Waits that failed (`poll` errno); each slept instead.
    pub errors: u64,
}

impl ruster_core::ObservableFields for IdleCounters {
    fn visit_fields<V: ruster_core::FieldVisitor>(&self, visitor: &mut V) {
        use ruster_core::FieldValue::Count;
        const SECTION: &str = "idle";
        visitor.field(SECTION, "max_wait_ms", Count(self.max_wait_ms));
        visitor.field(SECTION, "waits", Count(self.waits));
        visitor.field(SECTION, "woken", Count(self.woken));
        visitor.field(SECTION, "timed_out", Count(self.timed_out));
        visitor.field(SECTION, "interrupted", Count(self.interrupted));
        visitor.field(SECTION, "short", Count(self.short));
        visitor.field(SECTION, "sleeps", Count(self.sleeps));
        visitor.field(SECTION, "errors", Count(self.errors));
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

/// How long ticks may keep skipping their I/O as `BackendIoNotReentrant`
/// (the adapter's `SkipIo` disposition: an engine-level stranded lease or
/// handoff that never clears by itself), without a tick in between, before
/// the loop treats the backend as stopped. Measured on the loop clock
/// since H9 (the tick rate depends on the idle wait); before, 1024 ticks
/// made about one second at the 1 ms idle sleep. With [`WEDGED_MIN_TICKS`]
/// the bound is `max(1 s, 16 × --idle-wait-ms)` (at most 1.6 s at the
/// 100 ms maximum), plus one wait.
pub const WEDGED_MS: u64 = 1_000;
/// ... and at least this many such ticks, so a single tick after a long
/// stall (a stopped process) never ends the run alone.
pub const WEDGED_MIN_TICKS: u32 = 16;

/// Ends the loop on a terminal backend stop, or once non-reentrant skips
/// have lasted [`WEDGED_MS`] over at least [`WEDGED_MIN_TICKS`] ticks
/// (`max(1 s, 16 × --idle-wait-ms)`); any other tick resets it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackendWatch {
    skipped: u32,
    since: Option<MonotonicMillis>,
}

impl BackendWatch {
    pub fn after_tick<P, Q, R, G>(
        &mut self,
        now: MonotonicMillis,
        report: &TickReport<P, Q, R, G>,
    ) -> Option<LoopEnd> {
        if backend_stopped(report) {
            return Some(LoopEnd::BackendStopped);
        }
        if matches!(
            report.rx,
            RxPhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
        ) {
            self.skipped = self.skipped.saturating_add(1);
            let since = *self.since.get_or_insert(now);
            if self.skipped >= WEDGED_MIN_TICKS && now.0.saturating_sub(since.0) >= WEDGED_MS {
                return Some(LoopEnd::BackendStopped);
            }
        } else {
            self.skipped = 0;
            self.since = None;
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
    /// A reload preparation running this long is warned once.
    pub reload_prepare_warn_ms: u64,
    /// The longest idle wait (`--idle-wait-ms`, 1 to
    /// [`crate::args::MAX_IDLE_WAIT_MS`]).
    pub idle_wait_ms: u64,
}

/// The cold-path control of the loop: reload, health, and link watch,
/// the idle wait counters, and the service notifier (H10).
pub struct Control {
    pub reloader: Reloader,
    pub watch: Watch,
    pub links: LinkWatcher,
    pub idle: IdleCounters,
    pub notify: Notifier,
}

/// What a stats block reads besides the publication and backend.
pub struct RunStatus<'a> {
    pub reload: ReloadCounters,
    pub watch: &'a Watch,
    pub idle: IdleCounters,
    pub notify: NotifyCounters,
}

/// Runs ticks until a stop request, a backend stop, or a fatal watch
/// event. Between ticks (cold path): a reload request goes to the reload
/// worker; its prepared candidate, once dry-run and once the backend is
/// quiescent, rides the next tick's publication phase; the health watch
/// samples and the link watcher is asked for a round at their intervals;
/// the systemd watchdog is pinged when due ([`Notifier`], H10);
/// `stats` is called with [`BlockKind::Periodic`] once per
/// `stats_interval_ms` and with [`BlockKind::OnDemand`] after a SIGUSR1
/// ([`StopSignal::take_stats`]). Lines go to `err`.
#[allow(clippy::too_many_arguments)]
pub fn run_loop<'s, D, C, S, E, F>(
    active: &mut ActivePublication<'s, D::Io>,
    datapath: &mut D,
    observer: &mut TickObserver,
    clock: &mut C,
    stop: &S,
    settings: LoopSettings,
    control: &mut Control,
    err: &mut E,
    mut stats: F,
) -> LoopEnd
where
    D: Datapath,
    C: Clock,
    S: StopSignal,
    E: Write,
    F: FnMut(
        BlockKind,
        &ActivePublication<'s, D::Io>,
        &D,
        &TickObserver,
        &RunStatus<'_>,
        MonotonicMillis,
    ),
{
    let mut backoff = IdleBackoff::default();
    let mut wedge = BackendWatch::default();
    let mut last_stats = clock.now();
    let mut budgets = control.reloader.budgets();
    loop {
        if stop.stop() {
            return LoopEnd::Signal;
        }
        let mut now = clock.now();
        datapath.set_clock(now);
        let generation = active.generation();
        // Whether the work before this tick's RX may have taken a while: a
        // reload in flight (the worker's answer and the live dry run, a
        // warning, an abandon, each possibly writing to stderr) or a new
        // request (which writes). Only idle ticks skip it.
        let mut cold = control.reloader.busy();
        if !control.reloader.busy() && stop.take_reload() {
            cold = true;
            let _ = writeln!(
                err,
                "ruster run: reload requested (generation {generation})"
            );
            control.notify.reloading(generation.get());
            if let Some(outcome) = control.reloader.request(generation, now) {
                let _ = writeln!(err, "ruster run: {outcome}");
            }
        }
        if let Some(outcome) = control.reloader.poll(active, now) {
            let _ = writeln!(err, "ruster run: {outcome}");
        }
        if let Some(seconds) = control
            .reloader
            .observe_preparation(now, settings.reload_prepare_warn_ms)
        {
            let _ = writeln!(
                err,
                "ruster run: warning: reload preparation running for {seconds} s; \
                 later SIGHUPs are held"
            );
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
        // RX must not be stamped with a reading taken before slow work:
        // after cold pre-tick work, read the clock again right before the
        // tick; a tick that publishes a candidate reads it again after the
        // publication phase, before RX (`run_tick_reclocked`), since
        // applying a successor has no time bound. Idle ticks read the
        // clock once. Both readings only move `now` forward.
        if cold && !reloading {
            now = MonotonicMillis(now.0.max(clock.now().0));
            datapath.set_clock(now);
        }
        let mut reclocked = now;
        let report = run_tick_reclocked(
            active,
            candidate,
            datapath.io(),
            now,
            || {
                reclocked = clock.now();
                reclocked
            },
            budgets,
            observer,
        );
        let now = MonotonicMillis(now.0.max(reclocked.0));
        if reloading {
            // The backend paces its kick retries on the latest reading.
            datapath.set_clock(now);
        }
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
                if matches!(outcome, super::reload::ReloadOutcome::Applied { .. }) {
                    for warning in control.reloader.sweep().into_iter().flatten() {
                        let _ = writeln!(err, "ruster run: warning: {warning}");
                    }
                }
            }
            budgets = control.reloader.budgets();
            if matches!(result, TickApply::Applied(None)) {
                // Applied without a matching report: the publication
                // contract is broken; stop rather than guess.
                return LoopEnd::Invariant;
            }
        }
        // Every way a reload ends (applied, refused, failed, abandoned)
        // leaves the reloader idle by here.
        control
            .notify
            .reload_settled(control.reloader.busy(), generation.get());
        let occupancy = ServiceOccupancy::capture(
            active.icmpv4_errors(),
            active.nat44_udp(),
            active.nat44_tcp(),
            active.firewall(),
        );
        observer.record_occupancy(occupancy);
        if let Some(end) = wedge.after_tick(now, &report) {
            return end;
        }
        let busy = tick_was_busy(&report);
        drop(report);
        if let Some(end) = watch_step(datapath, control, now, settings, err) {
            return end;
        }
        // Here, between ticks, so a router stuck anywhere stops pinging.
        control.notify.watchdog(now);
        let periodic = settings.stats_interval_ms != 0
            && now.0.saturating_sub(last_stats.0) >= settings.stats_interval_ms;
        let on_demand = stop.take_stats();
        if periodic || on_demand {
            let status = RunStatus {
                reload: control.reloader.counters(),
                watch: &control.watch,
                idle: control.idle,
                notify: control.notify.counters(),
            };
            if periodic {
                last_stats = now;
                stats(
                    BlockKind::Periodic,
                    active,
                    datapath,
                    observer,
                    &status,
                    now,
                );
            }
            if on_demand {
                stats(
                    BlockKind::OnDemand,
                    active,
                    datapath,
                    observer,
                    &status,
                    now,
                );
            }
        }
        match backoff.after_tick(busy) {
            IdleAction::Spin => {}
            action => {
                let resolution = active.resolution();
                let pending = Pending {
                    resolution: resolution.pending_states() != 0
                        || resolution.pending_failure_holds() != 0
                        || resolution.pending_actions() != 0,
                    icmpv4: active.icmpv4_errors().pending_actions() != 0
                        || occupancy.nat44_tcp_unsolicited_syn_holds.occupied() != 0,
                    tx: datapath.tx_outstanding(),
                    reload: control.reloader.busy(),
                };
                let stats_due = (settings.stats_interval_ms != 0).then(|| {
                    MonotonicMillis(last_stats.0.saturating_add(settings.stats_interval_ms))
                });
                let watch_due = control
                    .watch
                    .next_due(settings.health_interval_ms, settings.link_interval_ms);
                let deadline = [stats_due, watch_due, control.notify.watchdog_due()]
                    .into_iter()
                    .flatten()
                    .min();
                let timeout = idle_timeout_ms(now, settings.idle_wait_ms, pending, deadline);
                // Shortened only if the pending cap, not a deadline or the
                // configured wait, set this timeout.
                let shortened = timeout
                    < idle_timeout_ms(now, settings.idle_wait_ms, Pending::default(), deadline);
                idle_wait(
                    datapath,
                    clock,
                    &mut backoff,
                    action,
                    timeout,
                    shortened,
                    &mut control.idle,
                    err,
                );
            }
        }
    }
}

/// One idle wait of `timeout_ms` (none at 0: a deadline is due): the
/// datapath's blocking RX wait, or a plain sleep of at most
/// [`SHORT_WAIT_MS`] after unconsumed readiness or when the wait cannot
/// block. The first `poll` failure is warned once.
#[allow(clippy::too_many_arguments)]
fn idle_wait<D, C, E>(
    datapath: &mut D,
    clock: &mut C,
    backoff: &mut IdleBackoff,
    action: IdleAction,
    timeout_ms: u64,
    shortened: bool,
    counters: &mut IdleCounters,
    err: &mut E,
) where
    D: Datapath,
    C: Clock,
    E: Write,
{
    if timeout_ms == 0 {
        return;
    }
    let sleep = Duration::from_millis(timeout_ms.min(SHORT_WAIT_MS));
    if action == IdleAction::Sleep {
        bump(&mut counters.sleeps);
        clock.pause(sleep);
        return;
    }
    let timeout = u32::try_from(timeout_ms).unwrap_or(u32::MAX);
    match datapath.wait_rx(timeout) {
        Ok(wake) => {
            bump(&mut counters.waits);
            if shortened {
                bump(&mut counters.short);
            }
            bump(match wake {
                IdleWake::Ready => &mut counters.woken,
                IdleWake::TimedOut => &mut counters.timed_out,
                IdleWake::Interrupted => &mut counters.interrupted,
            });
            backoff.after_wait(wake);
        }
        Err(error) => {
            if let WaitError::Errno(errno) = error {
                if counters.errors == 0 {
                    let _ = writeln!(
                        err,
                        "ruster run: warning: idle poll failed code=ERRNO_{errno}; \
                         sleeping at most {SHORT_WAIT_MS} ms between idle ticks instead"
                    );
                }
                bump(&mut counters.errors);
            }
            bump(&mut counters.sleeps);
            clock.pause(sleep);
        }
    }
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The health sample when due, and the link round: a finished round is
/// folded in, a due one is requested (or counted late, and stale past the
/// threshold, while the previous one still runs). Returns the first fatal
/// event as the loop end.
pub(super) fn watch_step<D, E>(
    datapath: &D,
    control: &mut Control,
    now: MonotonicMillis,
    settings: LoopSettings,
    err: &mut E,
) -> Option<LoopEnd>
where
    D: Datapath,
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
    if let Some(round) = control.links.poll() {
        watch.on_round(round, &mut on_event);
    }
    if watch.link_due(now, settings.link_interval_ms) {
        if !control.links.request(now) {
            if let Some(since) = control.links.running_since() {
                watch.on_late_round(now, since, &mut on_event);
            }
        }
        // A round that is already back (test lockstep, or a fast watcher)
        // is folded in at once.
        if let Some(round) = control.links.poll() {
            watch.on_round(round, &mut on_event);
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

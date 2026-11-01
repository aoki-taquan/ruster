//! Allocation-free, fixed-size worker observability (R15).
//!
//! A [`TickObserver`] is passed as the `trace` argument of
//! [`run_tick`](crate::run_tick). On the tick path it only increments
//! saturating fixed counters (one array index per dropped or consumed packet,
//! one per skipped phase); it never formats, allocates, or locks. After
//! `run_tick` returns, the cold side folds the returned [`TickReport`] into the
//! observer with [`TickObserver::observe_tick`] (O(1) per tick) and takes a
//! by-value [`ObservabilitySnapshot`] between ticks. The exclusive borrow taken
//! by `run_tick` makes a mid-tick snapshot impossible.
//!
//! Rendering is cold-side only. Every snapshot type implements
//! [`ObservableFields`], which visits `(section, key, value)` triples in a fixed
//! order without maps, so a caller can serialize deterministically;
//! [`FieldsDisplay`] renders the same triples as stable `section.key=value`
//! lines. The visiting vocabulary and [`BackendStats`](ruster_core::BackendStats)
//! live in `ruster-core` so packet backends need not depend on this crate.

use core::{convert::Infallible, fmt};
use std::num::NonZeroU64;

use ruster_core::{
    ConsumeReason, DropReason, FieldValue, FieldVisitor, FirewallCounters, FirewallReconcileReport,
    FirewallRuntime, GeneratedAllocationError, GeneratedArpTrace, GeneratedIcmpv4Trace,
    GeneratedIcmpv4TraceSink, GeneratedTraceSink, Icmpv4ErrorCounters,
    Icmpv4ErrorPublicationReport, Icmpv4ErrorRuntime, MonotonicMillis, Nat44TcpCounters,
    Nat44TcpReconcileReport, Nat44TcpRuntime, Nat44UdpCounters, Nat44UdpReconcileReport,
    Nat44UdpRuntime, ObservableFields, PublicationQuiescenceDisposition, ResolutionCounters,
    ResolutionFailureDispatchError, ResolutionFailureTrace, ResolutionFailureTraceSink,
    ResolutionPublicationReport, ResolutionRuntime, ResolutionTimerError, ResolutionTimerTrace,
    ResolutionTimerTraceSink, TraceEvent, TraceSink,
};

use crate::{
    GeneratedAccounting, GeneratedArpStop, GeneratedIcmpv4Stop, GeneratedPhaseReport, PhaseReport,
    PublicationOutcome, RxPhaseReport, TickPhaseSkip, TickPhaseTrace, TickPhaseTraceSink,
    TickReport,
};

/// One past the largest stable [`DropReason`] discriminant (OBS-001).
///
/// Code 0 is unused. A reason whose discriminant does not fit (a variant
/// added to core but not to `DropReason::ALL`) is counted as unclassified
/// instead of being lost.
pub const DROP_REASON_CODE_LIMIT: usize = DropReason::ALL.len() + 1;

/// Stable cold-side `section.key=value` rendering, one field per line.
pub struct FieldsDisplay<'a, T>(pub &'a T);

struct DisplayVisitor<'a, 'b> {
    formatter: &'a mut fmt::Formatter<'b>,
    result: fmt::Result,
}

impl FieldVisitor for DisplayVisitor<'_, '_> {
    fn field(&mut self, section: &'static str, key: &'static str, value: FieldValue) {
        if self.result.is_err() {
            return;
        }
        let f = &mut *self.formatter;
        self.result = match value {
            FieldValue::Count(value) => writeln!(f, "{section}.{key}={value}"),
            FieldValue::Flag(value) => writeln!(f, "{section}.{key}={value}"),
            FieldValue::Millis(Some(value)) => writeln!(f, "{section}.{key}={}", value.0),
            FieldValue::Generation(Some(value)) => writeln!(f, "{section}.{key}={value}"),
            FieldValue::Millis(None) | FieldValue::Generation(None) => {
                writeln!(f, "{section}.{key}=none")
            }
            FieldValue::Label(value) => writeln!(f, "{section}.{key}={value}"),
        };
    }
}

impl<T: ObservableFields> fmt::Display for FieldsDisplay<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut visitor = DisplayVisitor {
            formatter,
            result: Ok(()),
        };
        self.0.visit_fields(&mut visitor);
        visitor.result
    }
}

#[inline]
fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[inline]
fn bump(counter: &mut u64, by: usize) {
    *counter = counter.saturating_add(saturating_u64(by));
}

#[inline]
fn incr(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// A counter field widened to `u64` with saturation.
trait Count: Copy {
    fn count(self) -> u64;
}

impl Count for u64 {
    fn count(self) -> u64 {
        self
    }
}

impl Count for usize {
    fn count(self) -> u64 {
        saturating_u64(self)
    }
}

/// Visits the listed fields of `$value` as counts keyed by field name, in
/// listed order. Fields after `;` are destructured but not visited. The
/// pattern has no `..`, so a new struct field fails to compile until listed.
macro_rules! visit_counts {
    ($v:expr, $section:expr, $value:expr, $ty:ident {
        $($field:ident),+ $(,)? $(; $($skip:ident),+ $(,)?)?
    }) => {{
        let $ty { $($field,)+ $($($skip: _,)+)? } = $value;
        $($v.field($section, stringify!($field), FieldValue::Count(Count::count($field)));)+
    }};
}

/// Saturating-adds every listed field of `$value` into the same-named field
/// of `$total`. Exhaustive like [`visit_counts`].
macro_rules! add_counts {
    ($total:expr, $value:expr, $ty:ident { $($field:ident),+ $(,)? }) => {{
        let $ty { $($field),+ } = $value;
        $($total.$field = $total.$field.saturating_add(Count::count($field));)+
    }};
}

/// Saturating per-[`DropReason`] counters indexed by the stable discriminant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropReasonCounters {
    counts: [u64; DROP_REASON_CODE_LIMIT],
    unclassified: u64,
}

impl Default for DropReasonCounters {
    fn default() -> Self {
        Self {
            counts: [0; DROP_REASON_CODE_LIMIT],
            unclassified: 0,
        }
    }
}

impl DropReasonCounters {
    /// O(1): one bounds check and one saturating add.
    #[inline]
    pub(crate) fn record(&mut self, reason: DropReason) {
        let code = usize::from(reason as u16);
        match self.counts.get_mut(code) {
            Some(count) if code != 0 => incr(count),
            _ => incr(&mut self.unclassified),
        }
    }

    /// Count for `reason`; 0 for a reason outside the indexed code range,
    /// which is counted in [`Self::unclassified`] instead.
    #[must_use]
    pub fn count(&self, reason: DropReason) -> u64 {
        let code = usize::from(reason as u16);
        if code == 0 {
            return 0;
        }
        self.counts.get(code).copied().unwrap_or(0)
    }

    #[must_use]
    pub const fn unclassified(&self) -> u64 {
        self.unclassified
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.iter().fold(self.unclassified, |total, count| {
            total.saturating_add(*count)
        })
    }
}

impl ObservableFields for DropReasonCounters {
    /// Every reason (zeros included) in ascending stable code order, then
    /// `UNCLASSIFIED`, so the shape does not depend on traffic.
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        for reason in DropReason::ALL {
            let count = FieldValue::Count(self.count(reason));
            visitor.field("drop", reason.code(), count);
        }
        visitor.field("drop", "UNCLASSIFIED", FieldValue::Count(self.unclassified));
    }
}

/// Saturating per-[`ConsumeReason`] counters indexed by the exhaustive
/// core `ConsumeReason::index`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConsumeReasonCounters {
    counts: [u64; ConsumeReason::ALL.len()],
    /// A reason whose core index falls outside `ALL`; never panics or drops.
    unclassified: u64,
}

impl ConsumeReasonCounters {
    #[inline]
    pub(crate) fn record(&mut self, reason: ConsumeReason) {
        match self.counts.get_mut(reason.index()) {
            Some(count) => incr(count),
            None => incr(&mut self.unclassified),
        }
    }

    /// Count for `reason`; 0 for a reason outside the table, which is
    /// counted in [`Self::unclassified`] instead.
    #[must_use]
    pub fn count(&self, reason: ConsumeReason) -> u64 {
        self.counts.get(reason.index()).copied().unwrap_or(0)
    }

    #[must_use]
    pub const fn unclassified(&self) -> u64 {
        self.unclassified
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.iter().fold(self.unclassified, |total, count| {
            total.saturating_add(*count)
        })
    }
}

impl ObservableFields for ConsumeReasonCounters {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        for reason in ConsumeReason::ALL {
            let count = FieldValue::Count(self.count(reason));
            visitor.field("consume", reason.code(), count);
        }
        let unclassified = FieldValue::Count(self.unclassified);
        visitor.field("consume", "UNCLASSIFIED", unclassified);
    }
}

const PHASE_SKIP_KINDS: usize = 7;

/// Every [`TickPhaseSkip`] in counter order.
pub const TICK_PHASE_SKIPS: [TickPhaseSkip; PHASE_SKIP_KINDS] = [
    TickPhaseSkip::NoActivePublication,
    TickPhaseSkip::BackendIoNotReentrant,
    TickPhaseSkip::BackendStopped,
    TickPhaseSkip::BackendIoFailure,
    TickPhaseSkip::BackendContractViolation,
    TickPhaseSkip::ClockRegression,
    TickPhaseSkip::GeneratedArpFailure,
];

/// Exhaustive: a new skip reason fails to compile until it is counted.
const fn phase_skip_slot(reason: TickPhaseSkip) -> (usize, &'static str) {
    match reason {
        TickPhaseSkip::NoActivePublication => (0, "no_active_publication"),
        TickPhaseSkip::BackendIoNotReentrant => (1, "backend_io_not_reentrant"),
        TickPhaseSkip::BackendStopped => (2, "backend_stopped"),
        TickPhaseSkip::BackendIoFailure => (3, "backend_io_failure"),
        TickPhaseSkip::BackendContractViolation => (4, "backend_contract_violation"),
        TickPhaseSkip::ClockRegression => (5, "clock_regression"),
        TickPhaseSkip::GeneratedArpFailure => (6, "generated_arp_failure"),
    }
}

/// Saturating count of skipped phases per [`TickPhaseSkip`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PhaseSkipCounters {
    counts: [u64; PHASE_SKIP_KINDS],
}

impl PhaseSkipCounters {
    #[must_use]
    pub const fn count(&self, reason: TickPhaseSkip) -> u64 {
        self.counts[phase_skip_slot(reason).0]
    }
}

impl ObservableFields for PhaseSkipCounters {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        for reason in TICK_PHASE_SKIPS {
            let (slot, key) = phase_skip_slot(reason);
            visitor.field("phase_skip", key, FieldValue::Count(self.counts[slot]));
        }
    }
}

/// Aggregated RX phase outcomes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxTotals {
    pub batches: u64,
    pub received: u64,
    pub tx_requested: u64,
    /// Backend-accepted TX (descriptor publication, not wire delivery).
    pub tx_accepted: u64,
    pub tx_rejected: u64,
    pub dropped: u64,
    pub consumed: u64,
    pub recycled: u64,
    pub receive_failures: u64,
    pub finish_errors: u64,
    pub accounting_violations: u64,
}

/// Aggregated generated-session accounting for one generated phase.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GeneratedTotals {
    pub sessions: u64,
    pub allocation_attempts: u64,
    pub allocated: u64,
    pub allocation_failed: u64,
    pub tx_requested: u64,
    pub cancelled: u64,
    pub abandoned: u64,
    pub tx_accepted: u64,
    pub tx_rejected: u64,
    /// Phases stopped by an allocation, build, or finish failure.
    pub failures: u64,
    pub accounting_violations: u64,
}

impl GeneratedTotals {
    fn add(&mut self, accounting: &GeneratedAccounting) {
        add_counts! {self, *accounting, GeneratedAccounting {
            sessions, allocation_attempts, allocated, allocation_failed, tx_requested,
            cancelled, abandoned, tx_accepted, tx_rejected,
        }}
    }

    fn visit<V: FieldVisitor>(&self, section: &'static str, v: &mut V) {
        visit_counts! {v, section, *self, GeneratedTotals {
            sessions, allocation_attempts, allocated, allocation_failed, tx_requested,
            cancelled, abandoned, tx_accepted, tx_rejected, failures, accounting_violations,
        }}
    }
}

/// Aggregated [`TickReport`] totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TickTotals {
    pub ticks: u64,
    pub active_ticks: u64,
    pub successful_ticks: u64,
    pub publications_applied: u64,
    pub publications_rejected: u64,
    pub publications_deferred: u64,
    /// Applies whose flush counts were attached by
    /// [`TickObserver::record_apply_flush`]. `publications_applied` minus this
    /// exposes applies whose flush was never recorded.
    pub apply_flushes_recorded: u64,
    pub rx: RxTotals,
    pub resolution_timer_scanned: u64,
    pub resolution_retries_queued: u64,
    pub resolution_timed_out: u64,
    pub failure_dispatch_scanned: u64,
    pub failure_dispatch_queued: u64,
    pub generated_arp: GeneratedTotals,
    pub generated_icmpv4: GeneratedTotals,
}

/// Worker health derived from observed ticks and injected monotonic time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Health {
    /// Monotonic high-water mark of observed tick times; never moves back.
    pub last_tick: Option<MonotonicMillis>,
    pub last_successful_tick: Option<MonotonicMillis>,
    pub last_rx_progress: Option<MonotonicMillis>,
    pub last_tx_progress: Option<MonotonicMillis>,
    pub last_tick_successful: bool,
    /// Ticks whose injected time was below the previous high-water mark.
    pub clock_regressions: u64,
    /// Ticks in which a runtime phase reported a clock regression.
    pub runtime_clock_regressions: u64,
    pub backend_io_failures: u64,
    pub consecutive_backend_io_failures: u64,
    pub backend_contract_violations: u64,
    pub quiescence_deferrals: u64,
    /// Publication attempts deferred in a row. Ticks without a candidate
    /// (`Unchanged`) neither increment nor reset it; only an `Applied` or
    /// `Rejected` attempt resets it.
    pub consecutive_quiescence_deferrals: u64,
    /// Sticky once the backend classified itself as terminally stopped.
    pub backend_stopped: bool,
}

/// Coarse health classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthState {
    NotStarted,
    Healthy,
    /// No tick was observed within the policy window.
    Stale,
    /// The last observed tick did not complete every phase successfully.
    Degraded,
    Stopped,
}

impl HealthState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Healthy => "healthy",
            Self::Stale => "stale",
            Self::Degraded => "degraded",
            Self::Stopped => "stopped",
        }
    }
}

/// Cold-side health policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthPolicy {
    /// Maximum age of the last successful tick for [`HealthState::Healthy`].
    pub stale_after_ms: u64,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            stale_after_ms: 1_000,
        }
    }
}

impl Health {
    /// Classifies health at `now`. Precedence: stopped, not started, stale
    /// (no tick at all within the policy, even if the last one failed),
    /// degraded (the last tick failed), healthy. A `now` below the last tick
    /// is age 0.
    ///
    /// `NotStarted` means no tick was observed. A tick that ran without an
    /// active publication (before activation) reads `Degraded`: the worker
    /// is alive but forwards nothing.
    #[must_use]
    pub fn state(&self, now: MonotonicMillis, policy: HealthPolicy) -> HealthState {
        if self.backend_stopped {
            return HealthState::Stopped;
        }
        let Some(last) = self.last_tick else {
            return HealthState::NotStarted;
        };
        if now.0.saturating_sub(last.0) > policy.stale_after_ms {
            HealthState::Stale
        } else if self.last_tick_successful {
            HealthState::Healthy
        } else {
            HealthState::Degraded
        }
    }

    /// Whether the worker observed any tick within the policy window.
    #[must_use]
    pub fn alive(&self, now: MonotonicMillis, policy: HealthPolicy) -> bool {
        !self.backend_stopped
            && self
                .last_tick
                .is_some_and(|last| now.0.saturating_sub(last.0) <= policy.stale_after_ms)
    }
}

/// Typed outcome of the most recent publication attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcomeKind {
    Applied,
    Rejected,
    Deferred,
}

impl ApplyOutcomeKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
        }
    }
}

/// State flushed by one committed publication.
///
/// Built from the core per-runtime publication reports, so a control-plane
/// `ApplyReport` can be surfaced without this crate depending on control.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplyFlushCounts {
    pub resolution_states: u64,
    pub resolution_actions: u64,
    pub dynamic_neighbors: u64,
    pub failure_holds: u64,
    pub icmpv4_error_states: u64,
    pub icmpv4_error_actions: u64,
    pub nat44_udp_mappings: u64,
    pub nat44_udp_peers: u64,
    pub nat44_tcp_mappings: u64,
    pub nat44_tcp_sessions: u64,
    pub firewall_flows: u64,
}

impl ApplyFlushCounts {
    #[must_use]
    pub fn from_reports(
        resolution: ResolutionPublicationReport,
        icmpv4_errors: Icmpv4ErrorPublicationReport,
        nat44_udp: Nat44UdpReconcileReport,
        nat44_tcp: Nat44TcpReconcileReport,
        firewall: FirewallReconcileReport,
    ) -> Self {
        let s = saturating_u64;
        Self {
            resolution_states: s(resolution.states_flushed),
            resolution_actions: s(resolution.actions_flushed),
            dynamic_neighbors: s(resolution.dynamic_neighbors_flushed),
            failure_holds: s(resolution.failure_holds_flushed),
            icmpv4_error_states: s(icmpv4_errors.states_flushed),
            icmpv4_error_actions: s(icmpv4_errors.actions_flushed),
            nat44_udp_mappings: s(nat44_udp.mappings_flushed),
            nat44_udp_peers: s(nat44_udp.peers_flushed),
            nat44_tcp_mappings: s(nat44_tcp.mappings_flushed),
            nat44_tcp_sessions: s(nat44_tcp.sessions_flushed),
            firewall_flows: s(firewall.states_flushed),
        }
    }

    fn visit<V: FieldVisitor>(&self, section: &'static str, v: &mut V) {
        visit_counts! {v, section, *self, ApplyFlushCounts {
            resolution_states, resolution_actions, dynamic_neighbors, failure_holds,
            icmpv4_error_states, icmpv4_error_actions, nat44_udp_mappings, nat44_udp_peers,
            nat44_tcp_mappings, nat44_tcp_sessions, firewall_flows,
        }}
    }

    fn accumulate(&mut self, other: &Self) {
        add_counts! {self, *other, ApplyFlushCounts {
            resolution_states, resolution_actions, dynamic_neighbors, failure_holds,
            icmpv4_error_states, icmpv4_error_actions, nat44_udp_mappings, nat44_udp_peers,
            nat44_tcp_mappings, nat44_tcp_sessions, firewall_flows,
        }}
    }
}

/// The most recent publication attempt seen by the observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LastApply {
    pub outcome: ApplyOutcomeKind,
    /// Observed tick time (monotonic high-water mark) of the attempt.
    pub at: MonotonicMillis,
    /// Generation active after the attempt: the new one when `Applied`, the
    /// still-active previous one when `Rejected` or `Deferred`.
    pub active_generation: Option<NonZeroU64>,
    /// Flushed state, attached by [`TickObserver::record_apply_flush`].
    pub flush: Option<ApplyFlushCounts>,
}

/// By-value, fixed-size observability state taken at a tick boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservabilitySnapshot {
    pub taken_at: MonotonicMillis,
    pub state: HealthState,
    pub generation: Option<NonZeroU64>,
    pub generation_changes: u64,
    pub health: Health,
    pub totals: TickTotals,
    pub drops: DropReasonCounters,
    pub consumes: ConsumeReasonCounters,
    pub phase_skips: PhaseSkipCounters,
    pub last_apply: Option<LastApply>,
    /// Cumulative state flushed by every recorded apply.
    pub flushed: ApplyFlushCounts,
}

/// Worker-local observability sink and cold-side tick aggregator.
///
/// Pass `&mut observer` as `run_tick`'s `trace`, then call
/// [`Self::observe_tick`] with the returned report. Both are O(1),
/// allocation-free, and saturating.
#[derive(Clone, Debug, Default)]
pub struct TickObserver {
    policy: HealthPolicy,
    generation: Option<NonZeroU64>,
    generation_changes: u64,
    health: Health,
    totals: TickTotals,
    drops: DropReasonCounters,
    consumes: ConsumeReasonCounters,
    phase_skips: PhaseSkipCounters,
    last_apply: Option<LastApply>,
    flushed: ApplyFlushCounts,
}

#[derive(Default)]
struct TickFlags {
    clock_regression: bool,
    io_failure: bool,
    contract_violation: bool,
    phase_failure: bool,
    tx_progress: bool,
}

impl TickObserver {
    #[must_use]
    pub fn new(policy: HealthPolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    /// Folds one returned tick report into the totals and health.
    ///
    /// `now` is the same injected time passed to `run_tick`; `generation` is
    /// the active publication generation after the tick (`None` if none).
    /// A tick is successful when a publication was active, the injected time
    /// did not regress, and every phase completed without a clock
    /// regression, backend I/O failure, contract violation, or generated
    /// failure other than allocation backpressure (`Unavailable`).
    pub fn observe_tick<P, Q, R, G>(
        &mut self,
        now: MonotonicMillis,
        generation: Option<NonZeroU64>,
        report: &TickReport<P, Q, R, G>,
    ) {
        let input_regressed = self.health.last_tick.is_some_and(|last| now < last);
        let at = match self.health.last_tick {
            Some(last) if input_regressed => last,
            _ => now,
        };
        let health = &mut self.health;
        let totals = &mut self.totals;
        health.last_tick = Some(at);
        if input_regressed {
            incr(&mut health.clock_regressions);
        }
        incr(&mut totals.ticks);
        if report.active {
            incr(&mut totals.active_ticks);
        }
        let mut flags = TickFlags::default();

        let outcome = match &report.publication {
            PublicationOutcome::Unchanged => None,
            PublicationOutcome::Applied => {
                incr(&mut totals.publications_applied);
                Some(ApplyOutcomeKind::Applied)
            }
            PublicationOutcome::Rejected(_) => {
                incr(&mut totals.publications_rejected);
                Some(ApplyOutcomeKind::Rejected)
            }
            PublicationOutcome::Deferred { disposition, .. } => {
                incr(&mut totals.publications_deferred);
                incr(&mut health.quiescence_deferrals);
                incr(&mut health.consecutive_quiescence_deferrals);
                if *disposition == PublicationQuiescenceDisposition::Stop {
                    health.backend_stopped = true;
                }
                Some(ApplyOutcomeKind::Deferred)
            }
        };
        if let Some(outcome) = outcome {
            if outcome != ApplyOutcomeKind::Deferred {
                health.consecutive_quiescence_deferrals = 0;
            }
            self.last_apply = Some(LastApply {
                outcome,
                at,
                active_generation: generation,
                flush: None,
            });
        }

        let rx_attempted = !matches!(report.rx, RxPhaseReport::Skipped(_));
        match &report.rx {
            RxPhaseReport::Skipped(reason) => flags.skip(health, *reason),
            RxPhaseReport::ReceiveFailed(_) => {
                incr(&mut totals.rx.receive_failures);
                flags.io_failure = true;
            }
            RxPhaseReport::Completed(batch)
            | RxPhaseReport::AccountingInvariantViolation(batch) => {
                let rx = &mut totals.rx;
                incr(&mut rx.batches);
                bump(&mut rx.received, batch.received);
                bump(&mut rx.tx_requested, batch.tx_requested);
                bump(&mut rx.tx_accepted, batch.completion.tx_accepted);
                bump(&mut rx.tx_rejected, batch.completion.tx_rejected);
                bump(&mut rx.dropped, batch.dropped);
                bump(&mut rx.consumed, batch.consumed);
                bump(&mut rx.recycled, batch.completion.recycled);
                if batch.received != 0 {
                    health.last_rx_progress = Some(at);
                }
                flags.tx_progress |= batch.completion.tx_accepted != 0;
                if batch.completion.error.is_some() {
                    incr(&mut rx.finish_errors);
                    flags.io_failure = true;
                }
                if matches!(report.rx, RxPhaseReport::AccountingInvariantViolation(_)) {
                    incr(&mut rx.accounting_violations);
                    flags.contract_violation = true;
                }
            }
        }

        match &report.resolution_timers {
            PhaseReport::Skipped(reason) => flags.skip(health, *reason),
            PhaseReport::Completed(timers) => {
                bump(&mut totals.resolution_timer_scanned, timers.scanned);
                bump(&mut totals.resolution_retries_queued, timers.retries_queued);
                bump(&mut totals.resolution_timed_out, timers.timed_out);
            }
            PhaseReport::Failed(ResolutionTimerError::ClockRegression) => {
                flags.clock_regression = true;
            }
        }
        match &report.failure_dispatch {
            PhaseReport::Skipped(reason) => flags.skip(health, *reason),
            PhaseReport::Completed(dispatch) => {
                bump(&mut totals.failure_dispatch_scanned, dispatch.scanned);
                bump(&mut totals.failure_dispatch_queued, dispatch.queued);
            }
            PhaseReport::Failed(ResolutionFailureDispatchError::ClockRegression) => {
                flags.clock_regression = true;
            }
        }

        flags.generated(
            health,
            &mut totals.generated_arp,
            &report.generated_arp,
            |s| match s {
                GeneratedArpStop::QueueEmpty | GeneratedArpStop::BudgetExhausted { .. } => {
                    GeneratedEnd::Done
                }
                GeneratedArpStop::ClockRegression => GeneratedEnd::ClockRegression,
                GeneratedArpStop::Failed(f) => {
                    GeneratedEnd::failed(f.allocation, f.build.is_some(), f.finish.is_some())
                }
                GeneratedArpStop::AccountingInvariantViolation(_) => GeneratedEnd::Violation,
            },
        );
        let icmpv4 = &mut totals.generated_icmpv4;
        flags.generated(health, icmpv4, &report.generated_icmpv4, |s| match s {
            GeneratedIcmpv4Stop::QueueEmpty | GeneratedIcmpv4Stop::BudgetExhausted { .. } => {
                GeneratedEnd::Done
            }
            GeneratedIcmpv4Stop::ClockRegression => GeneratedEnd::ClockRegression,
            GeneratedIcmpv4Stop::Failed(f) => {
                GeneratedEnd::failed(f.allocation, f.build.is_some(), f.finish.is_some())
            }
            GeneratedIcmpv4Stop::AccountingInvariantViolation(_) => GeneratedEnd::Violation,
        });

        if flags.clock_regression {
            incr(&mut health.runtime_clock_regressions);
        }
        if flags.contract_violation {
            incr(&mut health.backend_contract_violations);
        }
        if flags.io_failure {
            incr(&mut health.backend_io_failures);
            incr(&mut health.consecutive_backend_io_failures);
        } else if rx_attempted {
            health.consecutive_backend_io_failures = 0;
        }
        if flags.tx_progress {
            health.last_tx_progress = Some(at);
        }
        let successful = report.active
            && !input_regressed
            && !flags.clock_regression
            && !flags.io_failure
            && !flags.contract_violation
            && !flags.phase_failure;
        health.last_tick_successful = successful;
        if successful {
            health.last_successful_tick = Some(at);
            incr(&mut totals.successful_ticks);
        }
        if generation != self.generation {
            if self.generation.is_some() {
                incr(&mut self.generation_changes);
            }
            self.generation = generation;
        }
    }

    /// Attaches the flush counts of the apply committed in the last observed
    /// tick. Returns `false` (and records nothing) unless the last attempt
    /// was `Applied` at `generation` and has no flush counts yet, so a
    /// duplicate call cannot double count.
    ///
    /// Contract: call this after every tick whose report was `Applied` and
    /// before observing the next tick that carries a publication outcome;
    /// otherwise that apply's flush is lost. A loss is never silent: it shows
    /// as `publications_applied > apply_flushes_recorded`.
    pub fn record_apply_flush(&mut self, generation: NonZeroU64, flush: ApplyFlushCounts) -> bool {
        match &mut self.last_apply {
            Some(last)
                if last.outcome == ApplyOutcomeKind::Applied
                    && last.active_generation == Some(generation)
                    && last.flush.is_none() =>
            {
                last.flush = Some(flush);
                self.flushed.accumulate(&flush);
                incr(&mut self.totals.apply_flushes_recorded);
                true
            }
            _ => false,
        }
    }

    /// Copies the current state. Call only between ticks.
    #[must_use]
    pub fn snapshot(&self, now: MonotonicMillis) -> ObservabilitySnapshot {
        ObservabilitySnapshot {
            taken_at: now,
            state: self.health.state(now, self.policy),
            generation: self.generation,
            generation_changes: self.generation_changes,
            health: self.health,
            totals: self.totals,
            drops: self.drops,
            consumes: self.consumes,
            phase_skips: self.phase_skips,
            last_apply: self.last_apply,
            flushed: self.flushed,
        }
    }
}

impl TickFlags {
    fn skip(&mut self, health: &mut Health, reason: TickPhaseSkip) {
        self.phase_failure = true;
        match reason {
            TickPhaseSkip::BackendStopped => health.backend_stopped = true,
            TickPhaseSkip::ClockRegression => self.clock_regression = true,
            TickPhaseSkip::NoActivePublication
            | TickPhaseSkip::BackendIoNotReentrant
            | TickPhaseSkip::BackendIoFailure
            | TickPhaseSkip::BackendContractViolation
            | TickPhaseSkip::GeneratedArpFailure => {}
        }
    }

    fn generated<S>(
        &mut self,
        health: &mut Health,
        totals: &mut GeneratedTotals,
        report: &PhaseReport<GeneratedPhaseReport<S>, Infallible>,
        end: impl FnOnce(&S) -> GeneratedEnd,
    ) {
        let phase = match report {
            PhaseReport::Skipped(reason) => return self.skip(health, *reason),
            PhaseReport::Failed(never) => match *never {},
            PhaseReport::Completed(phase) => phase,
        };
        totals.add(&phase.accounting);
        self.tx_progress |= phase.accounting.tx_accepted != 0;
        match end(&phase.stop) {
            GeneratedEnd::Done => {}
            GeneratedEnd::ClockRegression => self.clock_regression = true,
            GeneratedEnd::Failed { fatal, finish } => {
                incr(&mut totals.failures);
                self.io_failure |= finish;
                self.phase_failure |= fatal;
            }
            GeneratedEnd::Violation => {
                incr(&mut totals.accounting_violations);
                self.contract_violation = true;
            }
        }
    }
}

/// Phase-independent view of a generated phase's stop reason.
enum GeneratedEnd {
    Done,
    ClockRegression,
    /// `fatal` is false only for allocation backpressure (`Unavailable`).
    Failed {
        fatal: bool,
        finish: bool,
    },
    Violation,
}

impl GeneratedEnd {
    fn failed(allocation: Option<GeneratedAllocationError>, build: bool, finish: bool) -> Self {
        let backpressure = matches!(
            allocation,
            None | Some(GeneratedAllocationError::Unavailable)
        );
        Self::Failed {
            fatal: build || !backpressure,
            finish,
        }
    }
}

impl TickPhaseTraceSink for TickObserver {
    #[inline]
    fn record_tick_phase(&mut self, event: TickPhaseTrace) {
        if let TickPhaseTrace::PhaseSkipped { reason, .. } = event {
            incr(&mut self.phase_skips.counts[phase_skip_slot(reason).0]);
        }
    }
}

impl TraceSink for TickObserver {
    /// O(1): drop and consume events index a fixed array; all other events
    /// are ignored.
    #[inline]
    fn record(&mut self, event: TraceEvent) {
        match event {
            TraceEvent::Dropped { reason, .. } => self.drops.record(reason),
            TraceEvent::Consumed { reason, .. } | TraceEvent::Ipv4LocalConsumed { reason, .. } => {
                self.consumes.record(reason);
            }
            _ => {}
        }
    }
}

impl ResolutionTimerTraceSink for TickObserver {
    #[inline]
    fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
}

impl ResolutionFailureTraceSink for TickObserver {
    #[inline]
    fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
}

impl GeneratedTraceSink for TickObserver {
    #[inline]
    fn record_generated(&mut self, _event: GeneratedArpTrace) {}
}

impl GeneratedIcmpv4TraceSink for TickObserver {
    #[inline]
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

impl ObservableFields for ObservabilitySnapshot {
    fn visit_fields<V: FieldVisitor>(&self, v: &mut V) {
        v.field(
            "observer",
            "taken_at",
            FieldValue::Millis(Some(self.taken_at)),
        );
        v.field("observer", "state", FieldValue::Label(self.state.label()));
        v.field(
            "observer",
            "generation",
            FieldValue::Generation(self.generation),
        );
        let changes = FieldValue::Count(self.generation_changes);
        v.field("observer", "generation_changes", changes);

        let health = &self.health;
        for (key, value) in [
            ("last_tick", health.last_tick),
            ("last_successful_tick", health.last_successful_tick),
            ("last_rx_progress", health.last_rx_progress),
            ("last_tx_progress", health.last_tx_progress),
        ] {
            v.field("health", key, FieldValue::Millis(value));
        }
        let successful = FieldValue::Flag(health.last_tick_successful);
        v.field("health", "last_tick_successful", successful);
        v.field(
            "health",
            "backend_stopped",
            FieldValue::Flag(health.backend_stopped),
        );
        visit_counts! {v, "health", *health, Health {
            clock_regressions, runtime_clock_regressions, backend_io_failures,
            consecutive_backend_io_failures, backend_contract_violations, quiescence_deferrals,
            consecutive_quiescence_deferrals;
            last_tick, last_successful_tick, last_rx_progress, last_tx_progress,
            last_tick_successful, backend_stopped
        }}

        visit_counts! {v, "tick", self.totals, TickTotals {
            ticks, active_ticks, successful_ticks, publications_applied, publications_rejected,
            publications_deferred, apply_flushes_recorded, resolution_timer_scanned,
            resolution_retries_queued,
            resolution_timed_out, failure_dispatch_scanned, failure_dispatch_queued;
            rx, generated_arp, generated_icmpv4
        }}
        visit_counts! {v, "rx", self.totals.rx, RxTotals {
            batches, received, tx_requested, tx_accepted, tx_rejected, dropped, consumed,
            recycled, receive_failures, finish_errors, accounting_violations,
        }}
        self.totals.generated_arp.visit("generated_arp", v);
        self.totals.generated_icmpv4.visit("generated_icmpv4", v);
        self.phase_skips.visit_fields(v);
        self.drops.visit_fields(v);
        self.consumes.visit_fields(v);

        // Fixed shape: every field is emitted whether or not an apply happened.
        let last = self.last_apply;
        let outcome = last.map_or("none", |last| last.outcome.label());
        v.field("apply", "outcome", FieldValue::Label(outcome));
        v.field("apply", "at", FieldValue::Millis(last.map(|last| last.at)));
        let generation = last.and_then(|last| last.active_generation);
        v.field(
            "apply",
            "active_generation",
            FieldValue::Generation(generation),
        );
        let flush = last.and_then(|last| last.flush);
        v.field("apply", "flush_recorded", FieldValue::Flag(flush.is_some()));
        flush.unwrap_or_default().visit("apply.flush", v);
        self.flushed.visit("flushed", v);
    }
}

/// Copies of every runtime's cumulative core counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServiceCounters {
    pub resolution: ResolutionCounters,
    pub icmpv4_errors: Icmpv4ErrorCounters,
    pub nat44_udp: Nat44UdpCounters,
    pub nat44_tcp: Nat44TcpCounters,
    pub firewall: FirewallCounters,
}

impl ServiceCounters {
    /// Reads each runtime's `counters()` (O(1) copies). Cold side, between
    /// ticks, through the publication owner's read-only runtime accessors.
    #[must_use]
    pub fn capture(
        resolution: &ResolutionRuntime<'_>,
        icmpv4_errors: &Icmpv4ErrorRuntime<'_>,
        nat44_udp: &Nat44UdpRuntime<'_>,
        nat44_tcp: &Nat44TcpRuntime<'_>,
        firewall: &FirewallRuntime<'_>,
    ) -> Self {
        Self {
            resolution: resolution.counters(),
            icmpv4_errors: icmpv4_errors.counters(),
            nat44_udp: nat44_udp.counters(),
            nat44_tcp: nat44_tcp.counters(),
            firewall: firewall.counters(),
        }
    }
}

impl ObservableFields for ServiceCounters {
    /// Field names are the core counter field names. The destructuring is
    /// exhaustive, so a new core counter fails to compile until rendered.
    fn visit_fields<V: FieldVisitor>(&self, v: &mut V) {
        visit_counts! {v, "resolution", self.resolution, ResolutionCounters {
            queued, suppressed, state_full, action_full, clock_regressions, forbidden_target,
            dequeued, retry_queued, attempts_committed, attempts_accepted, timed_out,
            failed_hits, failures_expired,
        }}
        visit_counts! {v, "icmpv4_errors", self.icmpv4_errors, Icmpv4ErrorCounters {
            queued, queued_time_exceeded, queued_destination_unreachable,
            queued_host_unreachable, pending, rate_limited, disabled_time_exceeded,
            disabled_destination_unreachable, disabled_host_unreachable, state_full, action_full,
            clock_regressions, source_not_unicast, source_is_local, destination_multicast,
            destination_limited_broadcast, destination_network_address,
            destination_directed_broadcast, ethernet_destination_group, noninitial_fragment,
            icmp_error_message, icmp_type_missing, reverse_route_miss, reverse_interface_miss,
            reverse_binding_miss, reverse_target_forbidden, reverse_neighbor_unresolved,
            dequeued, dequeued_time_exceeded, dequeued_destination_unreachable,
            dequeued_host_unreachable,
        }}
        visit_counts! {v, "nat44_udp", self.nat44_udp, Nat44UdpCounters {
            mappings_created, mappings_reused, mappings_expired, peers_created,
            outbound_translated, inbound_translated, mapping_misses, filter_denied,
            mapping_full, peer_full, port_exhausted, clock_regressions, config_mismatches,
            reconciliations, hairpin_translated, hairpin_inbound_refused, hairpin_disabled,
        }}
        visit_counts! {v, "nat44_tcp", self.nat44_tcp, Nat44TcpCounters {
            mappings_created, mappings_reused, mappings_expired, sessions_created,
            inbound_sessions_created, sessions_reused, sessions_expired, outbound_translated,
            inbound_translated, mapping_misses, session_misses, invalid_initial_flags,
            mapping_full, session_full,
            port_exhausted, clock_regressions, config_mismatches, reconciliations,
            hairpin_translated, hairpin_inbound_refused, hairpin_disabled,
            inbound_remote_quota_exceeded,
        }}
        visit_counts! {v, "firewall", self.firewall, FirewallCounters {
            allowed_new, allowed_established, denied_by_rule, denied_default, invalid_packets,
            state_full, clock_regressions, config_mismatches, reconciliations, states_expired,
            state_probes, maintenance_steps, rule_evaluations,
        }}
    }
}

#[cfg(test)]
mod tests;

//! R15 observability: allocation-free, generation-tagged snapshots of tick
//! health, per-service activity, and backend statistics for cold consumers.
//!
//! Every type here is `Copy` and every counter update is saturating: taking
//! or updating a snapshot never allocates and never panics on overflow.
//! `Display`/`Debug` formatting is a cold-consumer concern only — nothing in
//! this module formats a string on the hot per-tick path.

use std::fmt;
use std::num::NonZeroU64;

use ruster_core::{BatchReport, DropReason, FirewallCounters, Nat44TcpCounters, Nat44UdpCounters};

use crate::ActivePublicationStatus;

/// A counter that accumulates by saturating addition and never panics or
/// wraps on overflow.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SaturatingCounter(u64);

impl SaturatingCounter {
    /// Returns a zeroed counter.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Adds `delta` to this counter, saturating at [`u64::MAX`].
    pub fn add(&mut self, delta: u64) {
        self.0 = self.0.saturating_add(delta);
    }

    /// Returns the current cumulative value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The largest value observed so far. Saturating and monotonically
/// non-decreasing: it never panics, wraps, or drops below a prior peak.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HighWatermark(u64);

impl HighWatermark {
    /// Returns a zeroed high watermark.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Raises this high watermark to `value` if `value` exceeds the current
    /// peak. Never lowers the peak and never panics or wraps.
    pub fn observe(&mut self, value: u64) {
        if value > self.0 {
            self.0 = value;
        }
    }

    /// Returns the highest value observed so far.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Number of slots reserved for the current stable `DropReason` discriminants.
///
/// `DropReason` is `repr(u16)` and currently occupies the contiguous range
/// `1..=145`. Keeping the counters in a fixed array makes recording a reason a
/// bounded, allocation-free operation. A future reason must remain within this
/// reserved range to be exported by this recorder.
pub const DROP_REASON_SLOTS: usize = 146;

/// Bounded per-reason forwarding drop counters.
///
/// The counter array is indexed by the stable `DropReason` discriminant. The
/// reason value is retained beside each populated slot so cold consumers can
/// use the existing stable [`DropReason::code`] spelling without maintaining a
/// second hand-written name table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropReasonCounts {
    counts: [SaturatingCounter; DROP_REASON_SLOTS],
    reasons: [Option<DropReason>; DROP_REASON_SLOTS],
}

impl Default for DropReasonCounts {
    fn default() -> Self {
        Self::zero()
    }
}

impl DropReasonCounts {
    /// Returns an empty bounded reason table.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            counts: [SaturatingCounter::zero(); DROP_REASON_SLOTS],
            reasons: [None; DROP_REASON_SLOTS],
        }
    }

    /// Adds one occurrence of `reason` without allocating or wrapping.
    pub fn record(&mut self, reason: DropReason) {
        let index = reason as usize;
        if index < DROP_REASON_SLOTS {
            self.reasons[index] = Some(reason);
            self.counts[index].add(1);
        }
    }

    /// Returns the cumulative count for `reason`.
    #[must_use]
    pub fn count(&self, reason: DropReason) -> u64 {
        let index = reason as usize;
        if index < DROP_REASON_SLOTS {
            self.counts[index].get()
        } else {
            0
        }
    }

    /// Returns one populated table entry for cold-consumer formatting.
    ///
    /// Entries that have never been recorded are omitted. The index is the
    /// stable `DropReason` discriminant, so a caller can scan
    /// `0..DROP_REASON_SLOTS` without a heap-backed map.
    #[must_use]
    pub fn entry(&self, index: usize) -> Option<(DropReason, u64)> {
        (index < DROP_REASON_SLOTS)
            .then(|| self.reasons[index].map(|reason| (reason, self.counts[index].get())))
            .flatten()
    }

    /// Returns the total of all populated reason counters.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .fold(0_u64, |total, counter| total.saturating_add(counter.get()))
    }
}

/// Coarse health of the active publication, derived from
/// [`ActivePublicationStatus`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    /// No publication has been activated yet.
    Cold,
    /// The active publication's backend I/O may continue.
    Ready,
    /// The active publication is invalid; backend I/O must stop.
    Degraded,
}

impl Readiness {
    /// Derives readiness from the current [`ActivePublicationStatus`].
    #[must_use]
    pub const fn from_active_status(status: ActivePublicationStatus) -> Self {
        match status {
            ActivePublicationStatus::Absent => Self::Cold,
            ActivePublicationStatus::ContinueOldIo => Self::Ready,
            ActivePublicationStatus::StopOldPublication => Self::Degraded,
        }
    }

    /// Reports whether this readiness allows continued backend I/O.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Extension point for backend-specific statistics contributed to an
/// [`ObservabilitySnapshot`].
///
/// Implementors must stay allocation-free and `Copy`; any `Display`/`Debug`
/// formatting must be a cold-consumer concern, never performed while
/// producing a snapshot.
pub trait BackendObservabilityStats: Copy + fmt::Debug {
    /// Returns a zeroed/default value for this backend's statistics.
    fn zero() -> Self;
}

/// No additional backend statistics.
impl BackendObservabilityStats for () {
    fn zero() -> Self {}
}

/// Cumulative saturating activity plus per-tick high watermarks for one core
/// service (firewall, UDP NAT44, or TCP NAT44).
///
/// `processed`/`denied` are cumulative saturating totals across every tick
/// this recorder has observed; `*_per_tick_high_watermark` is the largest
/// single-tick delta observed for that total.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServiceActivity {
    pub processed: SaturatingCounter,
    pub denied: SaturatingCounter,
    /// Whether the raw processed counter sum has ever reached `u64::MAX`.
    ///
    /// Once set, subsequent processed deltas and the corresponding
    /// high-watermark cannot be considered complete because the source
    /// counters no longer identify how much the sum grew.
    pub processed_counter_sum_saturated: bool,
    /// Whether the raw denied counter sum has ever reached `u64::MAX`.
    ///
    /// Once set, subsequent denied deltas and the corresponding
    /// high-watermark cannot be considered complete because the source
    /// counters no longer identify how much the sum grew.
    pub denied_counter_sum_saturated: bool,
    pub processed_per_tick_high_watermark: HighWatermark,
    pub denied_per_tick_high_watermark: HighWatermark,
}

impl ServiceActivity {
    /// Returns a zeroed activity record.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            processed: SaturatingCounter::zero(),
            denied: SaturatingCounter::zero(),
            processed_counter_sum_saturated: false,
            denied_counter_sum_saturated: false,
            processed_per_tick_high_watermark: HighWatermark::zero(),
            denied_per_tick_high_watermark: HighWatermark::zero(),
        }
    }

    /// Folds in one tick's processed/denied deltas: accumulates the totals
    /// and raises each per-tick high watermark.
    pub fn record_tick(&mut self, processed_delta: u64, denied_delta: u64) {
        self.processed.add(processed_delta);
        self.denied.add(denied_delta);
        self.processed_per_tick_high_watermark
            .observe(processed_delta);
        self.denied_per_tick_high_watermark.observe(denied_delta);
    }

    fn record_counter_sum_saturation(&mut self, processed: bool, denied: bool) {
        self.processed_counter_sum_saturated |= processed;
        self.denied_counter_sum_saturated |= denied;
    }
}

/// Aggregated per-service activity across the full composition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoreActivitySnapshot {
    pub firewall: ServiceActivity,
    pub nat44_udp: ServiceActivity,
    pub nat44_tcp: ServiceActivity,
}

impl CoreActivitySnapshot {
    /// Returns a zeroed snapshot.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            firewall: ServiceActivity::zero(),
            nat44_udp: ServiceActivity::zero(),
            nat44_tcp: ServiceActivity::zero(),
        }
    }
}

/// Cumulative daemon tick/report activity and bounded queue/capacity peaks.
///
/// The RX, resolution, failure, and generated queue values are only updated
/// from report fields that expose an actual pending/received count. Capacity
/// values are the configured per-tick budgets observed by the caller; they are
/// deliberately named separately from backend ring capacity, which an I/O
/// adapter may not expose.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservabilityActivitySnapshot {
    pub ticks: SaturatingCounter,
    pub active_ticks: SaturatingCounter,
    pub forwarded: SaturatingCounter,
    pub dropped: SaturatingCounter,
    pub consumed: SaturatingCounter,
    pub tx_accepted: SaturatingCounter,
    pub tx_rejected: SaturatingCounter,
    pub queue_high_watermark: HighWatermark,
    pub rx_batch_high_watermark: HighWatermark,
    pub resolution_queue_high_watermark: HighWatermark,
    pub failure_queue_high_watermark: HighWatermark,
    pub generated_arp_queue_high_watermark: HighWatermark,
    pub generated_icmpv4_queue_high_watermark: HighWatermark,
    pub capacity_high_watermark: HighWatermark,
    pub capacity_rx_high_watermark: HighWatermark,
    pub capacity_resolution_timer_high_watermark: HighWatermark,
    pub capacity_failure_dispatch_high_watermark: HighWatermark,
    pub capacity_generated_arp_high_watermark: HighWatermark,
    pub capacity_generated_icmpv4_high_watermark: HighWatermark,
    pub drop_reasons: DropReasonCounts,
}

impl ObservabilityActivitySnapshot {
    /// Returns an empty activity snapshot.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            ticks: SaturatingCounter::zero(),
            active_ticks: SaturatingCounter::zero(),
            forwarded: SaturatingCounter::zero(),
            dropped: SaturatingCounter::zero(),
            consumed: SaturatingCounter::zero(),
            tx_accepted: SaturatingCounter::zero(),
            tx_rejected: SaturatingCounter::zero(),
            queue_high_watermark: HighWatermark::zero(),
            rx_batch_high_watermark: HighWatermark::zero(),
            resolution_queue_high_watermark: HighWatermark::zero(),
            failure_queue_high_watermark: HighWatermark::zero(),
            generated_arp_queue_high_watermark: HighWatermark::zero(),
            generated_icmpv4_queue_high_watermark: HighWatermark::zero(),
            capacity_high_watermark: HighWatermark::zero(),
            capacity_rx_high_watermark: HighWatermark::zero(),
            capacity_resolution_timer_high_watermark: HighWatermark::zero(),
            capacity_failure_dispatch_high_watermark: HighWatermark::zero(),
            capacity_generated_arp_high_watermark: HighWatermark::zero(),
            capacity_generated_icmpv4_high_watermark: HighWatermark::zero(),
            drop_reasons: DropReasonCounts::zero(),
        }
    }
}

/// One allocation-free, generation-tagged observability snapshot.
///
/// `backend` carries backend-specific statistics through the
/// [`BackendObservabilityStats`] extension point; use `()` when a backend
/// contributes nothing beyond the core snapshot.
#[derive(Clone, Copy, Debug)]
pub struct ObservabilitySnapshot<Backend: BackendObservabilityStats = ()> {
    pub generation: NonZeroU64,
    pub readiness: Readiness,
    pub core: CoreActivitySnapshot,
    pub backend: Backend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SaturatingSum {
    value: u64,
    saturated: bool,
}

impl SaturatingSum {
    const ZERO: Self = Self {
        value: 0,
        saturated: false,
    };
}

/// Sums `values` by saturating addition, never panicking or wrapping on
/// overflow. `saturated` records whether the result reached `u64::MAX`, so a
/// cold consumer can tell that a later delta may be incomplete.
fn saturating_sum(values: &[u64]) -> SaturatingSum {
    values.iter().fold(SaturatingSum::ZERO, |sum, &value| {
        if sum.saturated {
            return sum;
        }

        match sum.value.checked_add(value) {
            Some(value) => SaturatingSum {
                value,
                saturated: value == u64::MAX,
            },
            None => SaturatingSum {
                value: u64::MAX,
                saturated: true,
            },
        }
    })
}

fn saturating_delta(previous: SaturatingSum, current: SaturatingSum) -> u64 {
    // A generation reset that lowers a cumulative counter reports a zero delta
    // rather than wrapping.
    current.value.saturating_sub(previous.value)
}

/// Accumulates [`ObservabilitySnapshot`]s across ticks.
///
/// Holds the last cumulative counters observed for each service so that
/// [`Self::record_tick`] can derive this tick's processed/denied deltas and
/// fold them into the running totals and high watermarks. Allocation-free
/// and `Copy`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ObservabilityRecorder<Backend: BackendObservabilityStats = ()> {
    core: CoreActivitySnapshot,
    activity: ObservabilityActivitySnapshot,
    last_firewall: FirewallCounters,
    last_nat44_udp: Nat44UdpCounters,
    last_nat44_tcp: Nat44TcpCounters,
    _backend: core::marker::PhantomData<Backend>,
}

impl<Backend: BackendObservabilityStats> ObservabilityRecorder<Backend> {
    /// Returns a fresh recorder with all counters and high watermarks
    /// zeroed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: CoreActivitySnapshot::zero(),
            activity: ObservabilityActivitySnapshot::zero(),
            last_firewall: FirewallCounters::default(),
            last_nat44_udp: Nat44UdpCounters::default(),
            last_nat44_tcp: Nat44TcpCounters::default(),
            _backend: core::marker::PhantomData,
        }
    }

    /// Records the report returned by one [`crate::run_tick`] invocation.
    ///
    /// Forwarding totals come from the RX [`BatchReport`], while generated TX
    /// totals come from the generated phase accounting in the tick report.
    /// Trace events are intentionally not used for these totals because the
    /// trace sink also receives the same batch lifecycle. This method is
    /// allocation-free and does not inspect or format any error value.
    pub fn record_tick_report<C, E, Q, R, G, A>(
        &mut self,
        report: &crate::TickReport<C, E, Q, R, G, A>,
    ) {
        self.activity.ticks.add(1);
        if report.active {
            self.activity.active_ticks.add(1);
        }

        match &report.rx {
            crate::RxPhaseReport::Completed(batch)
            | crate::RxPhaseReport::AccountingInvariantViolation(batch) => {
                self.record_batch_report(batch);
            }
            crate::RxPhaseReport::Skipped(_) | crate::RxPhaseReport::ReceiveFailed(_) => {}
        }

        if let crate::PhaseReport::Completed(timer) = &report.resolution_timers {
            observe_queue(
                &mut self.activity.resolution_queue_high_watermark,
                &mut self.activity.queue_high_watermark,
                timer.pending,
            );
        }
        if let crate::PhaseReport::Completed(dispatch) = &report.failure_dispatch {
            observe_queue(
                &mut self.activity.failure_queue_high_watermark,
                &mut self.activity.queue_high_watermark,
                dispatch.pending,
            );
        }
        if let crate::PhaseReport::Completed(generated) = &report.generated_arp {
            self.record_generated_accounting(&generated.accounting);
            if let crate::GeneratedArpStop::BudgetExhausted { pending } = &generated.stop {
                observe_queue(
                    &mut self.activity.generated_arp_queue_high_watermark,
                    &mut self.activity.queue_high_watermark,
                    *pending,
                );
            }
        }
        if let crate::PhaseReport::Completed(generated) = &report.generated_icmpv4 {
            self.record_generated_accounting(&generated.accounting);
            if let crate::GeneratedIcmpv4Stop::BudgetExhausted { pending } = &generated.stop {
                observe_queue(
                    &mut self.activity.generated_icmpv4_queue_high_watermark,
                    &mut self.activity.queue_high_watermark,
                    *pending,
                );
            }
        }
    }

    /// Records one forwarding trace drop reason.
    ///
    /// The daemon trace sink calls this for `TraceEvent::Dropped`; it is kept
    /// separate from report totals so a report and its trace cannot double
    /// count drops.
    pub fn record_drop_reason(&mut self, reason: DropReason) {
        self.activity.drop_reasons.record(reason);
    }

    /// Observes the generation's configured per-tick budgets as capacity
    /// high-watermarks. These are configuration limits, not AF_PACKET ring
    /// occupancy or wire-delivery measurements.
    pub fn observe_tick_budgets(&mut self, budgets: crate::TickBudgets) {
        observe_capacity(
            &mut self.activity.capacity_rx_high_watermark,
            &mut self.activity.capacity_high_watermark,
            budgets.rx,
        );
        observe_capacity(
            &mut self.activity.capacity_resolution_timer_high_watermark,
            &mut self.activity.capacity_high_watermark,
            budgets.resolution_timer_scans,
        );
        observe_capacity(
            &mut self.activity.capacity_failure_dispatch_high_watermark,
            &mut self.activity.capacity_high_watermark,
            budgets.failure_dispatch_scans,
        );
        observe_capacity(
            &mut self.activity.capacity_generated_arp_high_watermark,
            &mut self.activity.capacity_high_watermark,
            budgets.generated_arp,
        );
        observe_capacity(
            &mut self.activity.capacity_generated_icmpv4_high_watermark,
            &mut self.activity.capacity_high_watermark,
            budgets.generated_icmpv4,
        );
    }

    /// Returns the current daemon activity without allocating.
    #[must_use]
    pub const fn activity_snapshot(&self) -> ObservabilityActivitySnapshot {
        self.activity
    }

    fn record_batch_report<E>(&mut self, report: &BatchReport<E>) {
        add_usize(&mut self.activity.forwarded, report.tx_requested);
        add_usize(&mut self.activity.dropped, report.dropped);
        add_usize(&mut self.activity.consumed, report.consumed);
        add_usize(
            &mut self.activity.tx_accepted,
            report.completion.tx_accepted,
        );
        add_usize(
            &mut self.activity.tx_rejected,
            report.completion.tx_rejected,
        );
        observe_queue(
            &mut self.activity.rx_batch_high_watermark,
            &mut self.activity.queue_high_watermark,
            report.received,
        );
    }

    fn record_generated_accounting(&mut self, accounting: &crate::GeneratedAccounting) {
        add_usize(&mut self.activity.tx_accepted, accounting.tx_accepted);
        add_usize(&mut self.activity.tx_rejected, accounting.tx_rejected);
    }

    /// Folds in one tick's observed state and returns the resulting
    /// snapshot.
    ///
    /// `firewall`/`nat44_udp`/`nat44_tcp` are each `None` when the active
    /// view had no runtime state for that service this tick, in which case
    /// this service's activity contributes a zero delta for the tick.
    pub fn record_tick(
        &mut self,
        generation: NonZeroU64,
        active_status: ActivePublicationStatus,
        firewall: Option<FirewallCounters>,
        nat44_udp: Option<Nat44UdpCounters>,
        nat44_tcp: Option<Nat44TcpCounters>,
        backend: Backend,
    ) -> ObservabilitySnapshot<Backend> {
        if let Some(firewall) = firewall {
            let previous_processed = saturating_sum(&[
                self.last_firewall.allowed_new,
                self.last_firewall.allowed_established,
            ]);
            let current_processed =
                saturating_sum(&[firewall.allowed_new, firewall.allowed_established]);
            let processed = saturating_delta(previous_processed, current_processed);
            let previous_denied = saturating_sum(&[
                self.last_firewall.denied_by_rule,
                self.last_firewall.denied_default,
                self.last_firewall.invalid_packets,
                self.last_firewall.state_full,
            ]);
            let current_denied = saturating_sum(&[
                firewall.denied_by_rule,
                firewall.denied_default,
                firewall.invalid_packets,
                firewall.state_full,
            ]);
            let denied = saturating_delta(previous_denied, current_denied);
            self.core.firewall.record_tick(processed, denied);
            self.core.firewall.record_counter_sum_saturation(
                current_processed.saturated,
                current_denied.saturated,
            );
            self.last_firewall = firewall;
        }
        if let Some(nat44_udp) = nat44_udp {
            let previous_processed = saturating_sum(&[
                self.last_nat44_udp.outbound_translated,
                self.last_nat44_udp.inbound_translated,
            ]);
            let current_processed =
                saturating_sum(&[nat44_udp.outbound_translated, nat44_udp.inbound_translated]);
            let processed = saturating_delta(previous_processed, current_processed);
            let previous_denied = saturating_sum(&[
                self.last_nat44_udp.mapping_misses,
                self.last_nat44_udp.filter_denied,
                self.last_nat44_udp.mapping_full,
                self.last_nat44_udp.peer_full,
                self.last_nat44_udp.port_exhausted,
            ]);
            let current_denied = saturating_sum(&[
                nat44_udp.mapping_misses,
                nat44_udp.filter_denied,
                nat44_udp.mapping_full,
                nat44_udp.peer_full,
                nat44_udp.port_exhausted,
            ]);
            let denied = saturating_delta(previous_denied, current_denied);
            self.core.nat44_udp.record_tick(processed, denied);
            self.core.nat44_udp.record_counter_sum_saturation(
                current_processed.saturated,
                current_denied.saturated,
            );
            self.last_nat44_udp = nat44_udp;
        }
        if let Some(nat44_tcp) = nat44_tcp {
            let previous_processed = saturating_sum(&[
                self.last_nat44_tcp.outbound_translated,
                self.last_nat44_tcp.inbound_translated,
            ]);
            let current_processed =
                saturating_sum(&[nat44_tcp.outbound_translated, nat44_tcp.inbound_translated]);
            let processed = saturating_delta(previous_processed, current_processed);
            let previous_denied = saturating_sum(&[
                self.last_nat44_tcp.mapping_misses,
                self.last_nat44_tcp.session_misses,
                self.last_nat44_tcp.invalid_initial_flags,
                self.last_nat44_tcp.mapping_full,
                self.last_nat44_tcp.session_full,
                self.last_nat44_tcp.port_exhausted,
            ]);
            let current_denied = saturating_sum(&[
                nat44_tcp.mapping_misses,
                nat44_tcp.session_misses,
                nat44_tcp.invalid_initial_flags,
                nat44_tcp.mapping_full,
                nat44_tcp.session_full,
                nat44_tcp.port_exhausted,
            ]);
            let denied = saturating_delta(previous_denied, current_denied);
            self.core.nat44_tcp.record_tick(processed, denied);
            self.core.nat44_tcp.record_counter_sum_saturation(
                current_processed.saturated,
                current_denied.saturated,
            );
            self.last_nat44_tcp = nat44_tcp;
        }

        ObservabilitySnapshot {
            generation,
            readiness: Readiness::from_active_status(active_status),
            core: self.core,
            backend,
        }
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn add_usize(counter: &mut SaturatingCounter, value: usize) {
    counter.add(usize_to_u64(value));
}

fn observe_queue(high_watermark: &mut HighWatermark, aggregate: &mut HighWatermark, value: usize) {
    let value = usize_to_u64(value);
    high_watermark.observe(value);
    aggregate.observe(value);
}

fn observe_capacity(
    high_watermark: &mut HighWatermark,
    aggregate: &mut HighWatermark,
    value: usize,
) {
    let value = usize_to_u64(value);
    high_watermark.observe(value);
    aggregate.observe(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturating_counter_never_wraps_or_panics() {
        let mut counter = SaturatingCounter::zero();
        counter.add(u64::MAX);
        counter.add(1);
        assert_eq!(counter.get(), u64::MAX);
    }

    #[test]
    fn high_watermark_only_rises() {
        let mut watermark = HighWatermark::zero();
        watermark.observe(5);
        watermark.observe(3);
        watermark.observe(9);
        assert_eq!(watermark.get(), 9);
    }

    #[test]
    fn readiness_maps_from_active_status() {
        assert_eq!(
            Readiness::from_active_status(ActivePublicationStatus::Absent),
            Readiness::Cold
        );
        assert_eq!(
            Readiness::from_active_status(ActivePublicationStatus::ContinueOldIo),
            Readiness::Ready
        );
        assert_eq!(
            Readiness::from_active_status(ActivePublicationStatus::StopOldPublication),
            Readiness::Degraded
        );
        assert!(Readiness::Ready.is_ready());
        assert!(!Readiness::Degraded.is_ready());
        assert!(!Readiness::Cold.is_ready());
    }

    #[test]
    fn recorder_accumulates_deltas_and_high_watermarks() {
        let generation = NonZeroU64::new(1).unwrap();
        let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();

        let tick1_firewall = FirewallCounters {
            allowed_new: 3,
            denied_by_rule: 1,
            ..FirewallCounters::default()
        };
        let snapshot1 = recorder.record_tick(
            generation,
            ActivePublicationStatus::ContinueOldIo,
            Some(tick1_firewall),
            None,
            None,
            (),
        );
        assert_eq!(snapshot1.core.firewall.processed.get(), 3);
        assert_eq!(snapshot1.core.firewall.denied.get(), 1);
        assert_eq!(
            snapshot1
                .core
                .firewall
                .processed_per_tick_high_watermark
                .get(),
            3
        );

        let tick2_firewall = FirewallCounters {
            allowed_new: 10,
            denied_by_rule: 1,
            ..FirewallCounters::default()
        };
        let snapshot2 = recorder.record_tick(
            generation,
            ActivePublicationStatus::ContinueOldIo,
            Some(tick2_firewall),
            None,
            None,
            (),
        );
        // Cumulative total grew by 7 this tick; denials had zero delta.
        assert_eq!(snapshot2.core.firewall.processed.get(), 10);
        assert_eq!(snapshot2.core.firewall.denied.get(), 1);
        assert_eq!(
            snapshot2
                .core
                .firewall
                .processed_per_tick_high_watermark
                .get(),
            7
        );
        assert_eq!(
            snapshot2.core.firewall.denied_per_tick_high_watermark.get(),
            1
        );
    }

    #[test]
    fn record_tick_never_panics_when_summed_fields_would_overflow() {
        let generation = NonZeroU64::new(1).unwrap();
        let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();

        let near_max_firewall = FirewallCounters {
            allowed_new: u64::MAX,
            allowed_established: u64::MAX,
            denied_by_rule: u64::MAX,
            denied_default: u64::MAX,
            invalid_packets: u64::MAX,
            state_full: u64::MAX,
            ..FirewallCounters::default()
        };
        let snapshot = recorder.record_tick(
            generation,
            ActivePublicationStatus::ContinueOldIo,
            Some(near_max_firewall),
            None,
            None,
            (),
        );
        // Summing multiple u64::MAX fields would panic in debug builds (and
        // silently wrap in release) under plain `+`; saturating_sum keeps
        // this at u64::MAX instead.
        assert_eq!(snapshot.core.firewall.processed.get(), u64::MAX);
        assert_eq!(snapshot.core.firewall.denied.get(), u64::MAX);
    }

    #[test]
    fn record_tick_reports_saturation_and_latches_high_watermarks() {
        const NEAR_MAX: u64 = u64::MAX - 2;
        let generation = NonZeroU64::new(1).unwrap();
        let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();

        let tick1_firewall = FirewallCounters {
            allowed_new: NEAR_MAX,
            denied_by_rule: NEAR_MAX,
            ..FirewallCounters::default()
        };
        let tick1_udp = Nat44UdpCounters {
            outbound_translated: NEAR_MAX,
            mapping_misses: NEAR_MAX,
            ..Nat44UdpCounters::default()
        };
        let tick1_tcp = Nat44TcpCounters {
            outbound_translated: NEAR_MAX,
            mapping_misses: NEAR_MAX,
            ..Nat44TcpCounters::default()
        };
        let snapshot1 = recorder.record_tick(
            generation,
            ActivePublicationStatus::ContinueOldIo,
            Some(tick1_firewall),
            Some(tick1_udp),
            Some(tick1_tcp),
            (),
        );

        let tick1_firewall_processed_watermark = snapshot1
            .core
            .firewall
            .processed_per_tick_high_watermark
            .get();
        let tick1_udp_processed_watermark = snapshot1
            .core
            .nat44_udp
            .processed_per_tick_high_watermark
            .get();
        let tick1_tcp_processed_watermark = snapshot1
            .core
            .nat44_tcp
            .processed_per_tick_high_watermark
            .get();

        let tick2_firewall = FirewallCounters {
            allowed_new: NEAR_MAX,
            allowed_established: 4,
            denied_by_rule: NEAR_MAX,
            denied_default: 4,
            ..FirewallCounters::default()
        };
        let tick2_udp = Nat44UdpCounters {
            outbound_translated: NEAR_MAX,
            inbound_translated: 4,
            mapping_misses: NEAR_MAX,
            filter_denied: 4,
            ..Nat44UdpCounters::default()
        };
        let tick2_tcp = Nat44TcpCounters {
            outbound_translated: NEAR_MAX,
            inbound_translated: 4,
            mapping_misses: NEAR_MAX,
            session_misses: 4,
            ..Nat44TcpCounters::default()
        };
        let snapshot2 = recorder.record_tick(
            generation,
            ActivePublicationStatus::ContinueOldIo,
            Some(tick2_firewall),
            Some(tick2_udp),
            Some(tick2_tcp),
            (),
        );

        assert!(snapshot2.core.firewall.processed_counter_sum_saturated);
        assert!(snapshot2.core.firewall.denied_counter_sum_saturated);
        assert!(snapshot2.core.nat44_udp.processed_counter_sum_saturated);
        assert!(snapshot2.core.nat44_udp.denied_counter_sum_saturated);
        assert!(snapshot2.core.nat44_tcp.processed_counter_sum_saturated);
        assert!(snapshot2.core.nat44_tcp.denied_counter_sum_saturated);
        assert_eq!(
            snapshot2
                .core
                .firewall
                .processed_per_tick_high_watermark
                .get(),
            tick1_firewall_processed_watermark
        );
        assert_eq!(
            snapshot2
                .core
                .nat44_udp
                .processed_per_tick_high_watermark
                .get(),
            tick1_udp_processed_watermark
        );
        assert_eq!(
            snapshot2
                .core
                .nat44_tcp
                .processed_per_tick_high_watermark
                .get(),
            tick1_tcp_processed_watermark
        );

        let tick3_firewall = FirewallCounters {
            allowed_new: NEAR_MAX,
            allowed_established: 5,
            denied_by_rule: NEAR_MAX,
            denied_default: 5,
            ..FirewallCounters::default()
        };
        let tick3_udp = Nat44UdpCounters {
            outbound_translated: NEAR_MAX,
            inbound_translated: 5,
            mapping_misses: NEAR_MAX,
            filter_denied: 5,
            ..Nat44UdpCounters::default()
        };
        let tick3_tcp = Nat44TcpCounters {
            outbound_translated: NEAR_MAX,
            inbound_translated: 5,
            mapping_misses: NEAR_MAX,
            session_misses: 5,
            ..Nat44TcpCounters::default()
        };
        let snapshot3 = recorder.record_tick(
            generation,
            ActivePublicationStatus::ContinueOldIo,
            Some(tick3_firewall),
            Some(tick3_udp),
            Some(tick3_tcp),
            (),
        );

        // Once the source sum is saturated, its next increase produces a zero
        // delta, so the high-watermark remains unchanged and the saturation
        // flags tell cold consumers not to treat it as complete.
        assert_eq!(
            snapshot3
                .core
                .firewall
                .processed_per_tick_high_watermark
                .get(),
            tick1_firewall_processed_watermark
        );
        assert_eq!(
            snapshot3
                .core
                .nat44_udp
                .processed_per_tick_high_watermark
                .get(),
            tick1_udp_processed_watermark
        );
        assert_eq!(
            snapshot3
                .core
                .nat44_tcp
                .processed_per_tick_high_watermark
                .get(),
            tick1_tcp_processed_watermark
        );
        assert!(snapshot3.core.firewall.processed_counter_sum_saturated);
        assert!(snapshot3.core.nat44_udp.processed_counter_sum_saturated);
        assert!(snapshot3.core.nat44_tcp.processed_counter_sum_saturated);
    }

    #[test]
    fn missing_runtime_contributes_a_zero_delta() {
        let generation = NonZeroU64::new(1).unwrap();
        let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
        let snapshot = recorder.record_tick(
            generation,
            ActivePublicationStatus::ContinueOldIo,
            None,
            None,
            None,
            (),
        );
        assert_eq!(snapshot.core.firewall, ServiceActivity::zero());
        assert_eq!(snapshot.core.nat44_udp, ServiceActivity::zero());
        assert_eq!(snapshot.core.nat44_tcp, ServiceActivity::zero());
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct SimBackendObservabilityStats {
        pending_tx_high_watermark: u32,
    }

    impl BackendObservabilityStats for SimBackendObservabilityStats {
        fn zero() -> Self {
            Self::default()
        }
    }

    #[test]
    fn backend_extension_point_carries_arbitrary_copy_stats() {
        let generation = NonZeroU64::new(1).unwrap();
        let mut recorder: ObservabilityRecorder<SimBackendObservabilityStats> =
            ObservabilityRecorder::new();
        let snapshot = recorder.record_tick(
            generation,
            ActivePublicationStatus::ContinueOldIo,
            None,
            None,
            None,
            SimBackendObservabilityStats {
                pending_tx_high_watermark: 4,
            },
        );
        assert_eq!(snapshot.backend.pending_tx_high_watermark, 4);
    }

    #[test]
    fn recorder_accumulates_tick_report_accounting_and_watermarks() {
        let batch = BatchReport {
            received: 8,
            tx_requested: 3,
            dropped: 2,
            consumed: 3,
            completion: ruster_core::BatchCompletion {
                tx_requested: 3,
                tx_accepted: 2,
                tx_rejected: 1,
                recycled: 5,
                error: None::<()>,
            },
        };
        let report: crate::TickReport<(), (), (), (), (), ()> = crate::TickReport {
            publication: crate::PublicationOutcome::Unchanged,
            active: true,
            rx: crate::RxPhaseReport::Completed(batch),
            resolution_timers: crate::PhaseReport::Completed(ruster_core::ResolutionTimerReport {
                pending: 5,
                ..ruster_core::ResolutionTimerReport::default()
            }),
            failure_dispatch: crate::PhaseReport::Completed(
                ruster_core::ResolutionFailureDispatchReport {
                    pending: 4,
                    ..ruster_core::ResolutionFailureDispatchReport::default()
                },
            ),
            generated_arp: crate::PhaseReport::Completed(crate::GeneratedPhaseReport {
                accounting: crate::GeneratedAccounting {
                    tx_accepted: 2,
                    tx_rejected: 1,
                    ..crate::GeneratedAccounting::default()
                },
                stop: crate::GeneratedArpStop::BudgetExhausted { pending: 7 },
            }),
            generated_icmpv4: crate::PhaseReport::Completed(crate::GeneratedPhaseReport {
                accounting: crate::GeneratedAccounting::default(),
                stop: crate::GeneratedIcmpv4Stop::QueueEmpty,
            }),
        };

        let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
        recorder.observe_tick_budgets(crate::TickBudgets {
            rx: 9,
            resolution_timer_scans: 2,
            failure_dispatch_scans: 3,
            generated_arp: 4,
            generated_icmpv4: 1,
        });
        recorder.record_tick_report(&report);
        let activity = recorder.activity_snapshot();

        assert_eq!(activity.ticks.get(), 1);
        assert_eq!(activity.active_ticks.get(), 1);
        assert_eq!(activity.forwarded.get(), 3);
        assert_eq!(activity.dropped.get(), 2);
        assert_eq!(activity.consumed.get(), 3);
        assert_eq!(activity.tx_accepted.get(), 4);
        assert_eq!(activity.tx_rejected.get(), 2);
        assert_eq!(activity.rx_batch_high_watermark.get(), 8);
        assert_eq!(activity.resolution_queue_high_watermark.get(), 5);
        assert_eq!(activity.failure_queue_high_watermark.get(), 4);
        assert_eq!(activity.generated_arp_queue_high_watermark.get(), 7);
        assert_eq!(activity.queue_high_watermark.get(), 8);
        assert_eq!(activity.capacity_high_watermark.get(), 9);
        assert_eq!(activity.capacity_rx_high_watermark.get(), 9);
    }

    #[test]
    fn recorder_counts_drop_reasons_by_stable_code() {
        let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
        recorder.record_drop_reason(DropReason::Nat44ExternalToInternalBypass);
        recorder.record_drop_reason(DropReason::Nat44ExternalToInternalBypass);
        recorder.record_drop_reason(DropReason::UnsupportedEtherType);

        let activity = recorder.activity_snapshot();
        assert_eq!(
            activity
                .drop_reasons
                .count(DropReason::Nat44ExternalToInternalBypass),
            2
        );
        assert_eq!(
            activity
                .drop_reasons
                .count(DropReason::UnsupportedEtherType),
            1
        );
        assert_eq!(activity.drop_reasons.total(), 3);
        assert_eq!(
            activity
                .drop_reasons
                .entry(DropReason::Nat44ExternalToInternalBypass as usize),
            Some((DropReason::Nat44ExternalToInternalBypass, 2))
        );
    }
}

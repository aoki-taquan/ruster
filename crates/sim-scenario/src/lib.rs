#![deny(unsafe_code)]
//! Deterministic multi-tick router scenarios driven through the public full
//! composition API: config parse/validate, cold planning, initial
//! activation, and [`ruster_runtime::run_tick`] against [`SimIo`].
//!
//! Every scenario supplies its own logical clock ([`MonotonicMillis`])
//! rather than reading the wall clock, and every observed outcome is a typed
//! value from `ruster-core`/`ruster-runtime`/`ruster-io-sim` — packet paths
//! and results are never represented as strings.

use std::{fmt, num::NonZeroU64};

use ruster_config::{parse, validate, ValidatedConfig, ValidationLimits};
use ruster_control::{
    plan_full_service_v1, FullServiceCandidateV1, FullServicePlanInputs, SuccessorError,
};
pub use ruster_core::MonotonicMillis;
use ruster_core::{bind_publication_backend, PublicationQuiescenceDisposition};
use ruster_core::{
    FirewallHashKey, GeneratedArpTrace, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
    GeneratedTraceSink, Icmpv4TimestampClock, IfId, Nat44TcpHashKey, Nat44UdpHashKey,
    ResolutionFailureTrace, ResolutionFailureTraceSink, ResolutionTimerTrace,
    ResolutionTimerTraceSink, TraceEvent, TraceSink,
};
use ruster_integration::{
    activate_initial, FullServiceApplyReport, FullServicePublishError, FullServiceRestartRequired,
    FullServiceRuntimeStorage,
};
pub use ruster_io_sim::FrameOrigin;
use ruster_io_sim::{BoundSimIoControl, SimIo, SimPublicationQuiescenceError};
use ruster_runtime::{run_tick, PublicationOutcome, TickPhaseTrace, TickPhaseTraceSink};

mod catalog;
mod descriptor;

pub use catalog::{
    named_scenario, named_scenarios, run_named_scenario, NamedScenario, NAMED_SCENARIO_COUNT,
    NAMED_SCENARIO_NAMES,
};
pub use descriptor::{
    RunNamedScenarioError, ScenarioDescriptor, ScenarioDescriptorError, ScenarioLookupError,
    ScenarioPublicationEvent, ScenarioPublicationKind, MAX_SCENARIO_PUBLICATION_EVENTS,
    MAX_SCENARIO_TICKS,
};

/// Semantic validation/allocation limits shared by every scenario config.
pub const LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1_048_576,
    max_runtime_bytes: 1 << 30,
};

/// One ingress frame injected on a named interface at the start of a tick.
#[derive(Clone)]
pub struct ScenarioIngress {
    pub interface: IfId,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for ScenarioIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScenarioIngress")
            .field("interface", &self.interface)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

impl ScenarioIngress {
    #[must_use]
    pub const fn new(interface: IfId, bytes: Vec<u8>) -> Self {
        Self { interface, bytes }
    }
}

/// One completed transmitted frame observed by the R11 scenario driver.
///
/// The wire bytes remain available for deterministic equality and golden
/// assertions, but this R11-owned wrapper deliberately redacts them from
/// formatting. The underlying simulator frame is consumed without cloning.
#[derive(Eq, PartialEq)]
pub struct TxFrame {
    pub sequence: u64,
    pub ingress: IfId,
    pub egress: IfId,
    pub origin: FrameOrigin,
    pub bytes: Vec<u8>,
}

impl From<ruster_io_sim::TxFrame> for TxFrame {
    fn from(frame: ruster_io_sim::TxFrame) -> Self {
        Self {
            sequence: frame.sequence,
            ingress: frame.ingress,
            egress: frame.egress,
            origin: frame.origin,
            bytes: frame.bytes,
        }
    }
}

impl fmt::Debug for TxFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TxFrame")
            .field("sequence", &self.sequence)
            .field("ingress", &self.ingress)
            .field("egress", &self.egress)
            .field("origin", &self.origin)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

impl fmt::Display for TxFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "TxFrame(sequence={}, ingress={:?}, egress={:?}, origin={:?}, byte_len={})",
            self.sequence,
            self.ingress,
            self.egress,
            self.origin,
            self.bytes.len()
        )
    }
}

/// One deterministic tick: an explicit logical clock value and the frames
/// injected before the tick runs. `now` is caller-supplied and the driver
/// never reads the wall clock, so replaying the same [`Scenario`] is exact.
#[derive(Clone)]
pub struct ScenarioTick {
    pub now: MonotonicMillis,
    pub ingress: Vec<ScenarioIngress>,
}

impl fmt::Debug for ScenarioTick {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScenarioTick")
            .field("now", &self.now)
            .field("ingress_count", &self.ingress.len())
            .finish()
    }
}

/// A full deterministic scenario: one full-service config text, the
/// candidate identity inputs used to plan it, and an ordered sequence of
/// ticks driven against one cold-activated worker.
#[derive(Clone)]
pub struct Scenario {
    pub name: &'static str,
    pub config_toml: &'static str,
    pub generation: u64,
    pub seed: u64,
    pub ticks: Vec<ScenarioTick>,
}

impl fmt::Debug for Scenario {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ingress_count = self
            .ticks
            .iter()
            .map(|tick| tick.ingress.len())
            .sum::<usize>();
        formatter
            .debug_struct("Scenario")
            .field("name", &self.name)
            .field("generation", &self.generation)
            .field("tick_count", &self.ticks.len())
            .field("ingress_count", &ingress_count)
            .finish()
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Scenario(name={}, generation={}, ticks={})",
            self.name,
            self.generation,
            self.ticks.len()
        )
    }
}

/// A publication result reduced to plain, comparable data. This is not the
/// raw [`ruster_runtime::TickReport`] (whose generic error/report types make
/// it impractical to name in a public fixture API); every field remains a
/// typed value copied out of the real report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationSummary {
    Unchanged,
    Applied {
        previous_generation: NonZeroU64,
        generation: NonZeroU64,
    },
    BackendMismatch,
    Deferred,
    Rejected,
}

/// Value-only tick-budget metadata for an opaque materialized candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioTickBudgetSummary {
    rx: u32,
    resolution_timer_scans: u32,
    failure_dispatch_scans: u32,
    generated_arp: u32,
    generated_icmpv4: u32,
}

impl ScenarioTickBudgetSummary {
    #[must_use]
    pub const fn rx(self) -> u32 {
        self.rx
    }

    #[must_use]
    pub const fn resolution_timer_scans(self) -> u32 {
        self.resolution_timer_scans
    }

    #[must_use]
    pub const fn failure_dispatch_scans(self) -> u32 {
        self.failure_dispatch_scans
    }

    #[must_use]
    pub const fn generated_arp(self) -> u32 {
        self.generated_arp
    }

    #[must_use]
    pub const fn generated_icmpv4(self) -> u32 {
        self.generated_icmpv4
    }
}

/// Safe, value-only metadata for a candidate retained after publication failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioCandidateSummary {
    generation: NonZeroU64,
    tick: ScenarioTickBudgetSummary,
}

impl ScenarioCandidateSummary {
    #[must_use]
    pub const fn generation(self) -> NonZeroU64 {
        self.generation
    }

    #[must_use]
    pub const fn tick(self) -> ScenarioTickBudgetSummary {
        self.tick
    }
}

/// Publication disposition observed when the backend deferred a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioPublicationDisposition {
    ContinueOldIo,
    SkipIo,
    Stop,
}

/// R11-owned value-only classification of a failed publication attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioPublicationFailureKind {
    BackendMismatch,
    Deferred {
        disposition: ScenarioPublicationDisposition,
    },
    RestartRequired(ScenarioRestartReason),
    Rejected(ScenarioRejectReason),
    PublicationInvariant,
}

/// Value-only restart reason retained by a scenario failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioRestartReason {
    InterfaceBindingsChanged,
    RuntimeStorageShapeChanged,
    ResolutionPolicyChanged,
    Icmpv4ErrorPolicyChanged,
    Unsupported,
}

/// Value-only successor rejection reason retained by a scenario failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioRejectReason {
    GenerationExhausted,
    GenerationNotIncreasing,
    Nat44UdpHashKeyReused,
    Nat44TcpHashKeyReused,
    FirewallHashKeyReused,
    StorageShapeChanged,
    ResolutionPolicyChanged,
    Icmpv4ErrorPolicyChanged,
    Other,
}

/// Opaque ownership handle for an unconsumed materialized candidate.
///
/// It exposes only value-only metadata. The candidate authority, config, and
/// hash keys cannot be inspected, formatted, cloned, or extracted through the
/// R11 API. Call [`Self::discard`] when the caller has decided that this
/// candidate will not be retried; until then, this handle owns the exact value
/// returned by the publication layer.
///
/// ```compile_fail
/// use ruster_sim_scenario::ScenarioCandidateHandle;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<ScenarioCandidateHandle>();
/// ```
///
/// ```compile_fail
/// use ruster_sim_scenario::ScenarioCandidateHandle;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<ScenarioCandidateHandle>();
/// ```
///
/// R11SIM-019 also closes the former raw planning entry point:
///
/// ```compile_fail
/// fn main() {
///     let _ = ruster_sim_scenario::plan_candidate("config", 1, 1);
/// }
/// ```
#[must_use = "the opaque candidate must be retried or explicitly discarded"]
pub struct ScenarioCandidateHandle {
    summary: ScenarioCandidateSummary,
    candidate: FullServiceCandidateV1,
}

impl ScenarioCandidateHandle {
    #[must_use]
    pub const fn summary(&self) -> ScenarioCandidateSummary {
        self.summary
    }

    /// Explicitly releases the retained candidate authority.
    pub fn discard(self) {
        let Self { candidate, .. } = self;
        drop(candidate);
    }
}

/// A typed publication failure that retains the exact unconsumed candidate.
///
/// The active generation is captured before the attempt and the candidate
/// summary is captured from the returned candidate. The failure itself and its
/// nested handle intentionally have no `Debug`/`Clone` implementation that can
/// expose or duplicate candidate authority.
///
/// ```compile_fail
/// use ruster_sim_scenario::ScenarioPublicationFailure;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<ScenarioPublicationFailure>();
/// ```
#[must_use = "the publication failure retains an unconsumed candidate"]
pub struct ScenarioPublicationFailure {
    candidate: ScenarioCandidateHandle,
    active_generation: NonZeroU64,
    kind: ScenarioPublicationFailureKind,
}

impl ScenarioPublicationFailure {
    #[must_use]
    pub const fn kind(&self) -> ScenarioPublicationFailureKind {
        self.kind
    }

    /// Returns the active generation that remained in place after rejection.
    #[must_use]
    pub const fn active_generation(&self) -> NonZeroU64 {
        self.active_generation
    }

    /// Returns only the retained candidate's generation and tick metadata.
    #[must_use]
    pub const fn candidate_summary(&self) -> ScenarioCandidateSummary {
        self.candidate.summary()
    }

    /// Moves out the opaque handle without exposing the candidate authority.
    #[must_use = "the returned handle owns the candidate until discarded"]
    pub fn into_candidate(self) -> ScenarioCandidateHandle {
        self.candidate
    }

    /// Explicitly drops the exact retained candidate.
    pub fn discard_candidate(self) {
        drop(self);
    }
}

impl fmt::Debug for ScenarioPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScenarioPublicationFailure")
            .field("kind", &self.kind)
            .field("active_generation", &self.active_generation)
            .field("candidate_summary", &self.candidate.summary())
            .finish()
    }
}

impl fmt::Display for ScenarioPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "scenario publication failed (kind={:?}, active_generation={}, candidate_generation={})",
            self.kind,
            self.active_generation,
            self.candidate.summary().generation()
        )
    }
}

impl PartialEq for ScenarioPublicationFailure {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.active_generation == other.active_generation
            && self.candidate.summary() == other.candidate.summary()
    }
}

impl Eq for ScenarioPublicationFailure {}

fn candidate_summary(candidate: &FullServiceCandidateV1) -> ScenarioCandidateSummary {
    let tick = candidate.tick();
    ScenarioCandidateSummary {
        generation: candidate.generation(),
        tick: ScenarioTickBudgetSummary {
            rx: tick.rx,
            resolution_timer_scans: tick.resolution_timer_scans,
            failure_dispatch_scans: tick.failure_dispatch_scans,
            generated_arp: tick.generated_arp,
            generated_icmpv4: tick.generated_icmpv4,
        },
    }
}

fn retain_candidate(candidate: FullServiceCandidateV1) -> ScenarioCandidateHandle {
    let summary = candidate_summary(&candidate);
    ScenarioCandidateHandle { summary, candidate }
}

fn map_disposition(
    disposition: PublicationQuiescenceDisposition,
) -> ScenarioPublicationDisposition {
    match disposition {
        PublicationQuiescenceDisposition::ContinueOldIo => {
            ScenarioPublicationDisposition::ContinueOldIo
        }
        PublicationQuiescenceDisposition::SkipIo => ScenarioPublicationDisposition::SkipIo,
        PublicationQuiescenceDisposition::Stop => ScenarioPublicationDisposition::Stop,
    }
}

fn map_restart_reason(reason: FullServiceRestartRequired) -> ScenarioRestartReason {
    match reason {
        FullServiceRestartRequired::InterfaceBindingsChanged => {
            ScenarioRestartReason::InterfaceBindingsChanged
        }
        FullServiceRestartRequired::RuntimeStorageShapeChanged => {
            ScenarioRestartReason::RuntimeStorageShapeChanged
        }
        FullServiceRestartRequired::ResolutionPolicyChanged => {
            ScenarioRestartReason::ResolutionPolicyChanged
        }
        FullServiceRestartRequired::Icmpv4ErrorPolicyChanged => {
            ScenarioRestartReason::Icmpv4ErrorPolicyChanged
        }
        _ => ScenarioRestartReason::Unsupported,
    }
}

fn map_successor_reason(reason: SuccessorError) -> ScenarioRejectReason {
    match reason {
        SuccessorError::GenerationExhausted => ScenarioRejectReason::GenerationExhausted,
        SuccessorError::GenerationNotIncreasing => ScenarioRejectReason::GenerationNotIncreasing,
        SuccessorError::Nat44UdpHashKeyReused => ScenarioRejectReason::Nat44UdpHashKeyReused,
        SuccessorError::Nat44TcpHashKeyReused => ScenarioRejectReason::Nat44TcpHashKeyReused,
        SuccessorError::FirewallHashKeyReused => ScenarioRejectReason::FirewallHashKeyReused,
        SuccessorError::StorageShapeChanged => ScenarioRejectReason::StorageShapeChanged,
        SuccessorError::ResolutionPolicyChanged => ScenarioRejectReason::ResolutionPolicyChanged,
        SuccessorError::Icmpv4ErrorPolicyChanged => ScenarioRejectReason::Icmpv4ErrorPolicyChanged,
        _ => ScenarioRejectReason::Other,
    }
}

fn map_publication_error(error: FullServicePublishError) -> ScenarioPublicationFailureKind {
    match error {
        FullServicePublishError::InvalidSuccessor(reason) => {
            ScenarioPublicationFailureKind::Rejected(map_successor_reason(reason))
        }
        FullServicePublishError::RestartRequired(reason) => {
            ScenarioPublicationFailureKind::RestartRequired(map_restart_reason(reason))
        }
        _ => ScenarioPublicationFailureKind::PublicationInvariant,
    }
}

fn publication_failure_from_outcome(
    outcome: PublicationOutcome<
        FullServiceCandidateV1,
        FullServicePublishError,
        SimPublicationQuiescenceError,
        FullServiceApplyReport,
    >,
    active_generation: NonZeroU64,
) -> Option<ScenarioPublicationFailure> {
    let (candidate, kind) = match outcome {
        PublicationOutcome::BackendMismatch { candidate } => {
            (candidate?, ScenarioPublicationFailureKind::BackendMismatch)
        }
        PublicationOutcome::Deferred {
            candidate,
            disposition,
            ..
        } => (
            candidate,
            ScenarioPublicationFailureKind::Deferred {
                disposition: map_disposition(disposition),
            },
        ),
        PublicationOutcome::Rejected { rejection, .. } => {
            let (candidate, error) = rejection.into_parts();
            (candidate, map_publication_error(error))
        }
        PublicationOutcome::Unchanged | PublicationOutcome::Applied(_) => return None,
    };
    Some(ScenarioPublicationFailure {
        candidate: retain_candidate(candidate),
        active_generation,
        kind,
    })
}

/// What one driven tick actually produced: the reduced publication outcome,
/// whether a five-service active view was in effect, and the exact ordered
/// TX frames drained from the simulated backend after the tick.
#[derive(Eq, PartialEq)]
pub struct TickOutcome {
    pub now: MonotonicMillis,
    pub generation: NonZeroU64,
    pub publication: PublicationSummary,
    pub active: bool,
    pub tx: Vec<TxFrame>,
}

impl fmt::Debug for TickOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TickOutcome")
            .field("now", &self.now)
            .field("generation", &self.generation)
            .field("publication", &self.publication)
            .field("active", &self.active)
            .field("tx_count", &self.tx.len())
            .field("tx", &self.tx)
            .finish()
    }
}

impl fmt::Display for TickOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "TickOutcome(now={:?}, generation={}, publication={:?}, active={}, tx_count={})",
            self.now,
            self.generation,
            self.publication,
            self.active,
            self.tx.len()
        )
    }
}

/// Why a [`Scenario`] could not be driven to completion. Each variant names
/// the exact stage that failed; none of them stringify the underlying typed
/// error (callers that need it should drive the composition API directly).
#[derive(Debug, Eq, PartialEq)]
pub enum ScenarioError {
    Syntax,
    Semantic,
    UnexpectedSchema,
    Plan,
    Candidate,
    Storage,
    Activation,
    Binding,
    Descriptor(ScenarioDescriptorError),
    Publication(Box<ScenarioPublicationFailure>),
    UnexpectedPublication,
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Syntax => "scenario syntax validation failed",
            Self::Semantic => "scenario semantic validation failed",
            Self::UnexpectedSchema => "scenario schema is unsupported",
            Self::Plan => "scenario planning failed",
            Self::Candidate => "scenario candidate construction failed",
            Self::Storage => "scenario storage allocation failed",
            Self::Activation => "scenario activation failed",
            Self::Binding => "scenario backend binding failed",
            Self::Descriptor(_) => "scenario descriptor validation failed",
            Self::Publication(_) => "scenario publication failed with candidate retained",
            Self::UnexpectedPublication => "scenario publication result was not applied",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ScenarioError {}

#[derive(Default)]
struct NullTrace;

impl TickPhaseTraceSink for NullTrace {
    fn record_tick_phase(&mut self, _event: TickPhaseTrace) {}
}

impl TraceSink for NullTrace {
    fn record(&mut self, _event: TraceEvent) {}
}

impl ResolutionTimerTraceSink for NullTrace {
    fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
}

impl ResolutionFailureTraceSink for NullTrace {
    fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
}

impl GeneratedTraceSink for NullTrace {
    fn record_generated(&mut self, _event: GeneratedArpTrace) {}
}

impl GeneratedIcmpv4TraceSink for NullTrace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

#[cfg(test)]
pub(crate) mod test_observer {
    use std::{cell::RefCell, convert::Infallible, marker::PhantomData, num::NonZeroU64, rc::Rc};

    use ruster_core::{
        BatchReport, BoundPublicationBackend, GeneratedArpTrace, GeneratedIcmpv4Trace,
        GeneratedIcmpv4TraceSink, GeneratedTraceSink, IfId, MonotonicMillis,
        ResolutionFailureTrace, ResolutionFailureTraceSink, ResolutionTimerTrace,
        ResolutionTimerTraceSink, TraceEvent, TraceSink,
    };
    use ruster_io_sim::{BoundSimIoControl, RecycleCause, SimIo};
    use ruster_runtime::{RxPhaseReport, TickPhaseTrace, TickPhaseTraceSink};

    const MAX_CAPTURED_TICKS: usize = 16;
    const MAX_CAPTURED_INJECTIONS: usize = 64;
    const MAX_CAPTURED_RECYCLES: usize = 64;
    const MAX_CAPTURED_TRACE_EVENTS: usize = 64;
    const MAX_CAPTURED_PHASE_EVENTS: usize = 32;

    /// Test-only trace storage. Fixed capacity keeps the observer bounded and
    /// a full trace buffer remains non-panicking, as required of TraceSink.
    pub(super) struct TestTrace {
        events: [Option<TraceEvent>; MAX_CAPTURED_TRACE_EVENTS],
        event_len: usize,
        events_overflowed: bool,
        phases: [Option<TickPhaseTrace>; MAX_CAPTURED_PHASE_EVENTS],
        phase_len: usize,
        phases_overflowed: bool,
    }

    impl Default for TestTrace {
        fn default() -> Self {
            Self {
                events: [None; MAX_CAPTURED_TRACE_EVENTS],
                event_len: 0,
                events_overflowed: false,
                phases: [None; MAX_CAPTURED_PHASE_EVENTS],
                phase_len: 0,
                phases_overflowed: false,
            }
        }
    }

    impl TestTrace {
        fn trace_events(&self) -> impl Iterator<Item = TraceEvent> + '_ {
            self.events[..self.event_len].iter().copied().flatten()
        }

        fn phase_events(&self) -> impl Iterator<Item = TickPhaseTrace> + '_ {
            self.phases[..self.phase_len].iter().copied().flatten()
        }
    }

    impl TickPhaseTraceSink for TestTrace {
        fn record_tick_phase(&mut self, event: TickPhaseTrace) {
            if let Some(slot) = self.phases.get_mut(self.phase_len) {
                *slot = Some(event);
                self.phase_len += 1;
            } else {
                self.phases_overflowed = true;
            }
        }
    }

    impl TraceSink for TestTrace {
        fn record(&mut self, event: TraceEvent) {
            if let Some(slot) = self.events.get_mut(self.event_len) {
                *slot = Some(event);
                self.event_len += 1;
            } else {
                self.events_overflowed = true;
            }
        }
    }

    impl ResolutionTimerTraceSink for TestTrace {
        fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
    }

    impl ResolutionFailureTraceSink for TestTrace {
        fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
    }

    impl GeneratedTraceSink for TestTrace {
        fn record_generated(&mut self, _event: GeneratedArpTrace) {}
    }

    impl GeneratedIcmpv4TraceSink for TestTrace {
        fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct InjectionEvidence {
        pub(crate) now: MonotonicMillis,
        pub(crate) ingress: IfId,
        pub(crate) sequence: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct RecycleEvidence {
        pub(crate) sequence: u64,
        pub(crate) ingress: IfId,
        pub(crate) cause: RecycleCause,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct BatchEvidence {
        pub(crate) received: usize,
        pub(crate) tx_requested: usize,
        pub(crate) dropped: usize,
        pub(crate) consumed: usize,
        pub(crate) completion_tx_requested: usize,
        pub(crate) completion_tx_accepted: usize,
        pub(crate) completion_tx_rejected: usize,
        pub(crate) completion_recycled: usize,
        pub(crate) completion_error: bool,
        pub(crate) invariants_hold: bool,
    }

    impl BatchEvidence {
        fn from_report(report: &BatchReport<Infallible>) -> Self {
            Self {
                received: report.received,
                tx_requested: report.tx_requested,
                dropped: report.dropped,
                consumed: report.consumed,
                completion_tx_requested: report.completion.tx_requested,
                completion_tx_accepted: report.completion.tx_accepted,
                completion_tx_rejected: report.completion.tx_rejected,
                completion_recycled: report.completion.recycled,
                completion_error: report.completion.error.is_some(),
                invariants_hold: report.invariants_hold(),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum RxEvidence {
        Skipped(ruster_runtime::TickPhaseSkip),
        ReceiveFailed,
        Completed(BatchEvidence),
        AccountingInvariantViolation(BatchEvidence),
    }

    fn rx_evidence(rx: &RxPhaseReport<Infallible>) -> RxEvidence {
        match rx {
            RxPhaseReport::Skipped(reason) => RxEvidence::Skipped(*reason),
            RxPhaseReport::ReceiveFailed(_) => RxEvidence::ReceiveFailed,
            RxPhaseReport::Completed(report) => {
                RxEvidence::Completed(BatchEvidence::from_report(report))
            }
            RxPhaseReport::AccountingInvariantViolation(report) => {
                RxEvidence::AccountingInvariantViolation(BatchEvidence::from_report(report))
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct CapturedTick {
        now: MonotonicMillis,
        generation: NonZeroU64,
        active: bool,
        injections: [Option<InjectionEvidence>; MAX_CAPTURED_INJECTIONS],
        injection_len: usize,
        injection_overflowed: bool,
        rx: RxEvidence,
        recycled: [Option<RecycleEvidence>; MAX_CAPTURED_RECYCLES],
        recycled_len: usize,
        recycled_overflowed: bool,
        pending_rx: usize,
        pending_tx: usize,
        trace_events: [Option<TraceEvent>; MAX_CAPTURED_TRACE_EVENTS],
        trace_len: usize,
        trace_overflowed: bool,
        phase_events: [Option<TickPhaseTrace>; MAX_CAPTURED_PHASE_EVENTS],
        phase_len: usize,
        phase_overflowed: bool,
    }

    impl CapturedTick {
        pub(crate) fn now(self) -> MonotonicMillis {
            self.now
        }

        pub(crate) fn generation(self) -> NonZeroU64 {
            self.generation
        }

        pub(crate) fn active(self) -> bool {
            self.active
        }

        pub(crate) fn injections(&self) -> impl Iterator<Item = InjectionEvidence> + '_ {
            self.injections[..self.injection_len]
                .iter()
                .copied()
                .flatten()
        }

        pub(crate) fn rx(self) -> RxEvidence {
            self.rx
        }

        pub(crate) fn recycled(&self) -> impl Iterator<Item = RecycleEvidence> + '_ {
            self.recycled[..self.recycled_len].iter().copied().flatten()
        }

        pub(crate) fn pending_rx(self) -> usize {
            self.pending_rx
        }

        pub(crate) fn pending_tx(self) -> usize {
            self.pending_tx
        }

        pub(crate) fn trace_events(&self) -> impl Iterator<Item = TraceEvent> + '_ {
            self.trace_events[..self.trace_len]
                .iter()
                .copied()
                .flatten()
        }

        pub(crate) fn phase_events(&self) -> impl Iterator<Item = TickPhaseTrace> + '_ {
            self.phase_events[..self.phase_len]
                .iter()
                .copied()
                .flatten()
        }

        pub(crate) fn overflowed(self) -> bool {
            self.injection_overflowed
                || self.recycled_overflowed
                || self.trace_overflowed
                || self.phase_overflowed
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct CapturedEvidence {
        ticks: [Option<CapturedTick>; MAX_CAPTURED_TICKS],
        tick_len: usize,
        overflowed: bool,
    }

    impl Default for CapturedEvidence {
        fn default() -> Self {
            Self {
                ticks: [None; MAX_CAPTURED_TICKS],
                tick_len: 0,
                overflowed: false,
            }
        }
    }

    impl CapturedEvidence {
        pub(crate) fn tick_count(self) -> usize {
            self.tick_len
        }

        pub(crate) fn tick(&self, index: usize) -> Option<&CapturedTick> {
            self.ticks.get(index).and_then(Option::as_ref)
        }

        pub(crate) fn overflowed(self) -> bool {
            self.overflowed
        }
    }

    struct ObserverState {
        evidence: CapturedEvidence,
        pending_injections: [Option<InjectionEvidence>; MAX_CAPTURED_INJECTIONS],
        pending_injection_len: usize,
        pending_injection_overflowed: bool,
    }

    impl Default for ObserverState {
        fn default() -> Self {
            Self {
                evidence: CapturedEvidence::default(),
                pending_injections: [None; MAX_CAPTURED_INJECTIONS],
                pending_injection_len: 0,
                pending_injection_overflowed: false,
            }
        }
    }

    thread_local! {
        static ACTIVE: RefCell<Option<ObserverState>> = const { RefCell::new(None) };
    }

    pub(crate) struct ScopedObserver {
        previous: Option<ObserverState>,
        active: bool,
        _thread_owner: PhantomData<Rc<()>>,
    }

    pub(crate) fn scoped() -> ScopedObserver {
        let previous = ACTIVE.with(|cell| cell.replace(Some(ObserverState::default())));
        ScopedObserver {
            previous,
            active: true,
            _thread_owner: PhantomData,
        }
    }

    impl ScopedObserver {
        pub(crate) fn finish(mut self) -> CapturedEvidence {
            let current = self.restore();
            current.map_or_else(CapturedEvidence::default, |state| state.evidence)
        }

        fn restore(&mut self) -> Option<ObserverState> {
            if !self.active {
                return None;
            }
            self.active = false;
            let previous = self.previous.take();
            ACTIVE.with(|cell| cell.replace(previous))
        }
    }

    impl Drop for ScopedObserver {
        fn drop(&mut self) {
            let _restored_state = self.restore();
        }
    }

    pub(crate) fn is_clear() -> bool {
        ACTIVE.with(|cell| cell.borrow().is_none())
    }

    pub(super) fn record_injection(now: MonotonicMillis, ingress: IfId, sequence: u64) {
        ACTIVE.with(|cell| {
            let mut active = cell.borrow_mut();
            let Some(state) = active.as_mut() else {
                return;
            };
            if let Some(slot) = state
                .pending_injections
                .get_mut(state.pending_injection_len)
            {
                *slot = Some(InjectionEvidence {
                    now,
                    ingress,
                    sequence,
                });
                state.pending_injection_len += 1;
            } else {
                state.pending_injection_overflowed = true;
            }
        });
    }

    pub(super) fn record_tick(
        now: MonotonicMillis,
        generation: NonZeroU64,
        active: bool,
        rx: &RxPhaseReport<Infallible>,
        trace: &TestTrace,
        io: &mut BoundPublicationBackend<SimIo>,
    ) {
        let observer_active = ACTIVE.with(|cell| cell.borrow().is_some());
        if !observer_active {
            return;
        }

        let mut recycled = [None; MAX_CAPTURED_RECYCLES];
        let mut recycled_len = 0;
        let mut recycled_overflowed = false;
        while let Some(frame) = io.pop_recycled() {
            let ruster_io_sim::RecycledFrame {
                sequence,
                ingress,
                cause,
                bytes,
            } = frame;
            drop(bytes);
            if let Some(slot) = recycled.get_mut(recycled_len) {
                *slot = Some(RecycleEvidence {
                    sequence,
                    ingress,
                    cause,
                });
                recycled_len += 1;
            } else {
                recycled_overflowed = true;
            }
        }

        let mut captured = CapturedTick {
            now,
            generation,
            active,
            injections: [None; MAX_CAPTURED_INJECTIONS],
            injection_len: 0,
            injection_overflowed: false,
            rx: rx_evidence(rx),
            recycled,
            recycled_len,
            recycled_overflowed,
            pending_rx: io.pending_rx(),
            pending_tx: io.pending_tx(),
            trace_events: [None; MAX_CAPTURED_TRACE_EVENTS],
            trace_len: 0,
            trace_overflowed: trace.events_overflowed,
            phase_events: [None; MAX_CAPTURED_PHASE_EVENTS],
            phase_len: 0,
            phase_overflowed: trace.phases_overflowed,
        };

        ACTIVE.with(|cell| {
            let mut active = cell.borrow_mut();
            let Some(state) = active.as_mut() else {
                return;
            };

            std::mem::swap(&mut captured.injections, &mut state.pending_injections);
            captured.injection_len = state.pending_injection_len;
            captured.injection_overflowed = state.pending_injection_overflowed;
            state.pending_injection_len = 0;
            state.pending_injection_overflowed = false;

            for event in trace.trace_events() {
                if let Some(slot) = captured.trace_events.get_mut(captured.trace_len) {
                    *slot = Some(event);
                    captured.trace_len += 1;
                } else {
                    captured.trace_overflowed = true;
                }
            }
            for event in trace.phase_events() {
                if let Some(slot) = captured.phase_events.get_mut(captured.phase_len) {
                    *slot = Some(event);
                    captured.phase_len += 1;
                } else {
                    captured.phase_overflowed = true;
                }
            }

            if let Some(slot) = state.evidence.ticks.get_mut(state.evidence.tick_len) {
                *slot = Some(captured);
                state.evidence.tick_len += 1;
            } else {
                state.evidence.overflowed = true;
            }
        });
    }
}

/// Derives an ICMPv4 Timestamp clock from a scenario's own logical clock.
///
/// A scenario never reads the wall clock (module docs above), so replaying
/// the same scenario stays byte-for-byte exact; this keeps a Timestamp Reply
/// inside that same replay guarantee instead of reading `SystemTime::now()`.
fn deterministic_timestamp_clock(now: MonotonicMillis) -> Icmpv4TimestampClock {
    Icmpv4TimestampClock(u32::try_from(now.0 % 86_400_000).unwrap_or(0))
}

/// Plans a full-service candidate from scenario config text and identity
/// inputs, using the same public parse/validate/plan path as production.
fn plan_candidate(
    config_toml: &str,
    generation: u64,
    seed: u64,
) -> Result<FullServiceCandidateV1, ScenarioError> {
    let parsed = parse(config_toml.as_bytes()).map_err(|_| ScenarioError::Syntax)?;
    let validated = validate(parsed, LIMITS).map_err(|_| ScenarioError::Semantic)?;
    let config = match validated {
        ValidatedConfig::V1(config) => config,
        #[allow(unreachable_patterns)]
        _ => return Err(ScenarioError::UnexpectedSchema),
    };
    let generation = NonZeroU64::new(generation).ok_or(ScenarioError::Candidate)?;
    let inputs = FullServicePlanInputs::new(
        generation,
        Nat44UdpHashKey::new(seed, seed.wrapping_add(1)).map_err(|_| ScenarioError::Candidate)?,
        Nat44TcpHashKey::new(seed.wrapping_add(2), seed.wrapping_add(3))
            .map_err(|_| ScenarioError::Candidate)?,
        FirewallHashKey::new(seed.wrapping_add(4), seed.wrapping_add(5))
            .map_err(|_| ScenarioError::Candidate)?,
    );
    let plan = plan_full_service_v1(config, inputs).map_err(|_| ScenarioError::Plan)?;
    plan.into_candidate().map_err(|_| ScenarioError::Candidate)
}

/// Attempts one successor publication through the production full-service
/// composition seam.
///
/// Only the initial scenario's config, generation, and seed and the
/// successor scenario's corresponding fields are used. The successor is never
/// returned as a raw control-plane candidate. If the publication is deferred
/// or rejected, [`ScenarioError::Publication`] retains the exact candidate in
/// an opaque, value-only handle and records the active generation that was
/// left unchanged. The handle is intentionally the current R11 recovery/drop
/// boundary: callers may inspect its summary, pass the handle to a future
/// operator workflow, or explicitly discard it.
pub fn attempt_publication(
    initial: &Scenario,
    successor: &Scenario,
) -> Result<PublicationSummary, ScenarioError> {
    let descriptor =
        ScenarioDescriptor::new(initial.clone(), Vec::new()).map_err(ScenarioError::Descriptor)?;
    let initial = descriptor.initial_scenario();
    let candidate = plan_candidate(initial.config_toml, initial.generation, initial.seed)?;
    let mut storage = FullServiceRuntimeStorage::try_for_candidate(&candidate)
        .map_err(|_| ScenarioError::Storage)?;
    let publication =
        activate_initial(&mut storage, candidate).map_err(|_| ScenarioError::Activation)?;
    let (owner_binding, mut io) =
        bind_publication_backend(SimIo::new()).map_err(|_| ScenarioError::Binding)?;
    let mut publication = publication
        .bind_backend(owner_binding, &mut io)
        .map_err(|_| ScenarioError::Binding)?;

    let successor = plan_candidate(successor.config_toml, successor.generation, successor.seed)?;
    let active_generation = publication.generation();
    let mut trace = NullTrace;
    let report = run_tick(
        &mut publication,
        Some(successor),
        &mut io,
        MonotonicMillis(0),
        deterministic_timestamp_clock(MonotonicMillis(0)),
        &mut trace,
    );
    let publication_summary = summarize_outcome(&report.publication);
    if let Some(failure) = publication_failure_from_outcome(report.publication, active_generation) {
        return Err(ScenarioError::Publication(Box::new(failure)));
    }
    if matches!(publication_summary, PublicationSummary::Applied { .. }) {
        Ok(publication_summary)
    } else {
        Err(ScenarioError::UnexpectedPublication)
    }
}

fn summarize_outcome<C, E, Q, A>(outcome: &PublicationOutcome<C, E, Q, A>) -> PublicationSummary
where
    A: AppliedGenerations,
{
    match outcome {
        PublicationOutcome::Unchanged => PublicationSummary::Unchanged,
        PublicationOutcome::Applied(applied) => PublicationSummary::Applied {
            previous_generation: applied.previous_generation(),
            generation: applied.generation(),
        },
        PublicationOutcome::BackendMismatch { .. } => PublicationSummary::BackendMismatch,
        PublicationOutcome::Deferred { .. } => PublicationSummary::Deferred,
        PublicationOutcome::Rejected { .. } => PublicationSummary::Rejected,
    }
}

/// Narrow trait so the internal outcome summarizer can read generation
/// identity out of whatever concrete apply-report type the composition root
/// uses, without this crate needing to expose candidate state.
trait AppliedGenerations {
    fn previous_generation(&self) -> NonZeroU64;
    fn generation(&self) -> NonZeroU64;
}

impl AppliedGenerations for ruster_integration::FullServiceApplyReport {
    fn previous_generation(&self) -> NonZeroU64 {
        Self::previous_generation(self)
    }

    fn generation(&self) -> NonZeroU64 {
        Self::generation(self)
    }
}

/// Drives one [`Scenario`] to completion through a descriptor with no
/// publication events. The scenario is structurally validated before parsing,
/// planning, allocation, activation, or backend binding.
pub fn run_scenario(scenario: &Scenario) -> Result<Vec<TickOutcome>, ScenarioError> {
    let descriptor =
        ScenarioDescriptor::new(scenario.clone(), Vec::new()).map_err(ScenarioError::Descriptor)?;
    run_descriptor(&descriptor)
}

/// Drives a finite logical-time descriptor through a fresh full-service
/// runtime and simulated backend. Publication events are materialized only at
/// their tick boundary; [`ruster_runtime::run_tick`] publishes before it
/// receives that tick's ingress frames.
pub fn run_descriptor(descriptor: &ScenarioDescriptor) -> Result<Vec<TickOutcome>, ScenarioError> {
    let mut ignore_candidate = |_: &FullServiceCandidateV1| {};
    run_descriptor_inner(descriptor, &mut ignore_candidate)
}

fn run_descriptor_inner<F>(
    descriptor: &ScenarioDescriptor,
    observe_candidate: &mut F,
) -> Result<Vec<TickOutcome>, ScenarioError>
where
    F: FnMut(&FullServiceCandidateV1),
{
    descriptor.validate().map_err(ScenarioError::Descriptor)?;
    let scenario = descriptor.initial_scenario();
    let candidate = plan_candidate(scenario.config_toml, scenario.generation, scenario.seed)?;
    observe_candidate(&candidate);
    let mut storage = FullServiceRuntimeStorage::try_for_candidate(&candidate)
        .map_err(|_| ScenarioError::Storage)?;
    let publication =
        activate_initial(&mut storage, candidate).map_err(|_| ScenarioError::Activation)?;
    let (owner_binding, mut io) =
        bind_publication_backend(SimIo::new()).map_err(|_| ScenarioError::Binding)?;
    let mut publication = publication
        .bind_backend(owner_binding, &mut io)
        .map_err(|_| ScenarioError::Binding)?;

    let mut outcomes = Vec::with_capacity(scenario.ticks.len());
    let mut history = Vec::with_capacity(descriptor.publication_events().len() + 1);
    history.push(descriptor::ScenarioRevision {
        generation: NonZeroU64::new(scenario.generation).ok_or(ScenarioError::Descriptor(
            ScenarioDescriptorError::GenerationZero,
        ))?,
        config_toml: scenario.config_toml,
    });
    let mut next_event = 0_usize;
    for tick in &scenario.ticks {
        let event = descriptor
            .publication_events()
            .get(next_event)
            .filter(|event| event.at() == tick.now);
        let event_config = event.map(|event| {
            event
                .config_for_history(&history)
                .ok_or(ScenarioError::Descriptor(
                    ScenarioDescriptorError::RollbackSourceMissing,
                ))
        });
        let event_config = match event_config {
            Some(config) => Some(config?),
            None => None,
        };
        let event_candidate = match event {
            Some(event) => {
                let candidate = plan_candidate(
                    event_config.ok_or(ScenarioError::Descriptor(
                        ScenarioDescriptorError::RollbackSourceMissing,
                    ))?,
                    event.generation().get(),
                    event.seed(),
                )?;
                observe_candidate(&candidate);
                Some(candidate)
            }
            None => None,
        };
        for ingress in &tick.ingress {
            let sequence = io.inject(ingress.interface, ingress.bytes.clone());
            #[cfg(test)]
            test_observer::record_injection(tick.now, ingress.interface, sequence);
            let _ = sequence;
        }
        #[cfg(test)]
        let mut trace = test_observer::TestTrace::default();
        #[cfg(not(test))]
        let mut trace = NullTrace;
        let active_generation = publication.generation();
        let report = run_tick(
            &mut publication,
            event_candidate,
            &mut io,
            tick.now,
            deterministic_timestamp_clock(tick.now),
            &mut trace,
        );
        #[cfg(test)]
        test_observer::record_tick(
            tick.now,
            publication.generation(),
            report.active,
            &report.rx,
            &trace,
            &mut io,
        );
        let publication_summary = summarize_outcome(&report.publication);
        let active = report.active;
        if let Some(event) = event {
            let expected = PublicationSummary::Applied {
                previous_generation: history.last().map(|revision| revision.generation).ok_or(
                    ScenarioError::Descriptor(ScenarioDescriptorError::GenerationZero),
                )?,
                generation: event.generation(),
            };
            if publication_summary != expected {
                if let Some(failure) =
                    publication_failure_from_outcome(report.publication, active_generation)
                {
                    return Err(ScenarioError::Publication(Box::new(failure)));
                }
                return Err(ScenarioError::UnexpectedPublication);
            }
            history.push(descriptor::ScenarioRevision {
                generation: event.generation(),
                config_toml: event_config.ok_or(ScenarioError::Descriptor(
                    ScenarioDescriptorError::RollbackSourceMissing,
                ))?,
            });
            next_event += 1;
        }
        let mut tx = Vec::new();
        while let Some(frame) = io.pop_tx() {
            tx.push(frame.into());
        }
        outcomes.push(TickOutcome {
            now: tick.now,
            generation: publication.generation(),
            publication: publication_summary,
            active,
            tx,
        });
    }
    Ok(outcomes)
}

/// Alias using an explicit scenario-oriented name for descriptor consumers.
pub fn run_scenario_descriptor(
    descriptor: &ScenarioDescriptor,
) -> Result<Vec<TickOutcome>, ScenarioError> {
    run_descriptor(descriptor)
}

pub mod fixtures;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FULL_SERVICE: &str = include_str!("../tests/fixtures/full-service-golden.toml");
    const TEST_UDP_NAT: &str = include_str!("../tests/fixtures/udp-nat-golden.toml");

    fn independent_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in bytes.chunks(2) {
            let word =
                (u32::from(chunk[0]) << 8) | u32::from(chunk.get(1).copied().unwrap_or_default());
            sum += word;
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
        }
        (!sum) as u16
    }

    fn independent_udp_frame() -> Vec<u8> {
        let source = [192, 0, 2, 20];
        let destination = [203, 0, 113, 5];
        let mut ip = [0_u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&33_u16.to_be_bytes());
        ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&source);
        ip[16..20].copy_from_slice(&destination);
        let ip_checksum = independent_checksum(&ip);
        ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        let mut udp = [0_u8; 13];
        udp[0..2].copy_from_slice(&51_000_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53_u16.to_be_bytes());
        udp[4..6].copy_from_slice(&13_u16.to_be_bytes());
        udp[8..].copy_from_slice(b"query");
        let mut pseudo = Vec::with_capacity(12 + udp.len());
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&destination);
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&13_u16.to_be_bytes());
        pseudo.extend_from_slice(&udp);
        let udp_checksum = independent_checksum(&pseudo);
        udp[6..8].copy_from_slice(&udp_checksum.to_be_bytes());

        let mut frame = Vec::with_capacity(47);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 4]);
        frame.extend_from_slice(&0x0800_u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        frame
    }

    struct CandidateIdentityEvidence {
        udp: Nat44UdpHashKey,
        tcp: Nat44TcpHashKey,
        firewall: FirewallHashKey,
    }

    impl PartialEq for CandidateIdentityEvidence {
        fn eq(&self, other: &Self) -> bool {
            self.udp == other.udp && self.tcp == other.tcp && self.firewall == other.firewall
        }
    }

    fn identity(candidate: &FullServiceCandidateV1) -> CandidateIdentityEvidence {
        let authority = candidate.authority();
        CandidateIdentityEvidence {
            udp: authority.nat44_udp_hash_key(),
            tcp: authority.nat44_tcp_hash_key(),
            firewall: authority.firewall_config().hash_key(),
        }
    }

    #[test]
    fn r11sim_026_rollback_materializes_fresh_identity_across_all_history() {
        let ingress = || {
            // The input is assembled here from test-owned literals;
            // production fixture constructors are intentionally not part of
            // this identity oracle.
            ScenarioIngress::new(IfId(1), independent_udp_frame())
        };
        let initial = Scenario {
            name: "identity-history-test",
            config_toml: TEST_UDP_NAT,
            generation: 7,
            seed: 11,
            ticks: vec![
                ScenarioTick {
                    now: MonotonicMillis(0),
                    ingress: vec![ingress()],
                },
                ScenarioTick {
                    now: MonotonicMillis(1_000),
                    ingress: vec![ingress()],
                },
                ScenarioTick {
                    now: MonotonicMillis(2_000),
                    ingress: vec![ingress()],
                },
            ],
        };
        let reload =
            ScenarioPublicationEvent::reload(MonotonicMillis(1_000), 8, TEST_FULL_SERVICE, 111)
                .expect("reload event generation is valid");
        let rollback = ScenarioPublicationEvent::rollback(MonotonicMillis(2_000), 9, 7, 211)
            .expect("rollback event generation is valid");
        let descriptor = ScenarioDescriptor::new(initial, vec![reload, rollback])
            .expect("identity history descriptor is valid");

        assert_eq!(
            descriptor.publication_events()[1].kind(),
            ScenarioPublicationKind::Rollback {
                source_generation: NonZeroU64::new(7).expect("nonzero source")
            }
        );

        let mut generations = Vec::new();
        let mut identities = Vec::new();
        let mut observe = |candidate: &FullServiceCandidateV1| {
            generations.push(candidate.generation());
            identities.push(identity(candidate));
        };
        let outcomes = run_descriptor_inner(&descriptor, &mut observe)
            .expect("descriptor runner must materialize every candidate");

        assert_eq!(
            generations,
            [
                NonZeroU64::new(7).expect("nonzero initial generation"),
                NonZeroU64::new(8).expect("nonzero reload generation"),
                NonZeroU64::new(9).expect("nonzero rollback generation"),
            ]
        );
        assert_eq!(outcomes.len(), 3);
        assert_eq!(
            outcomes
                .iter()
                .map(|outcome| outcome.generation.get())
                .collect::<Vec<_>>(),
            [7, 8, 9]
        );
        assert_eq!(
            outcomes
                .iter()
                .map(|outcome| outcome.tx.len())
                .collect::<Vec<_>>(),
            [1, 0, 1]
        );
        assert_eq!(identities.len(), 3);
        assert!(identities[0] != identities[1]);
        assert!(identities[0] != identities[2]);
        assert!(identities[1] != identities[2]);
    }

    #[test]
    fn r11sim_027_deferred_failure_retains_candidate_and_disposition() {
        let candidate = plan_candidate(TEST_FULL_SERVICE, 8, 111).expect("candidate is valid");
        let outcome: PublicationOutcome<
            FullServiceCandidateV1,
            FullServicePublishError,
            SimPublicationQuiescenceError,
            FullServiceApplyReport,
        > = PublicationOutcome::Deferred {
            candidate,
            error: SimPublicationQuiescenceError::TxCompletionPending,
            disposition: PublicationQuiescenceDisposition::SkipIo,
        };
        let failure = publication_failure_from_outcome(
            outcome,
            NonZeroU64::new(7).expect("active generation is nonzero"),
        )
        .expect("deferred outcome retains its candidate");

        assert_eq!(
            failure.kind(),
            ScenarioPublicationFailureKind::Deferred {
                disposition: ScenarioPublicationDisposition::SkipIo,
            }
        );
        assert_eq!(failure.active_generation().get(), 7);
        assert_eq!(failure.candidate_summary().generation().get(), 8);
        failure.into_candidate().discard();
    }

    #[test]
    fn scoped_observer_restores_nested_and_panic_cleanup_on_same_thread() {
        assert!(test_observer::is_clear());
        let outer = test_observer::scoped();
        {
            let inner = test_observer::scoped();
            assert_eq!(inner.finish().tick_count(), 0);
            assert!(!test_observer::is_clear());
        }
        drop(outer);
        assert!(test_observer::is_clear());

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _observer = test_observer::scoped();
            panic!("same-thread observer cleanup probe");
        }));
        assert!(panic_result.is_err());
        assert!(test_observer::is_clear());
    }
}

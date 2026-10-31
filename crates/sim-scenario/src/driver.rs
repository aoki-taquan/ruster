//! Deterministic `ruster-scenario/v1` driver producing `ruster-run-sim/v1`.
//!
//! [`SimSession::load`] reads the scenario and its initial configuration,
//! validates the configuration, and builds generation 1 through the one
//! process-wide [`PublicationSequencer`] seeded from the scenario seed.
//! [`SimSession::start`] activates it on owned [`FullServiceStorage`] and
//! returns a [`SimRun`], which executes the scenario one unit at a time
//! ([`SimRun::step`]): one inject, one worker tick, one apply, or one expect.
//! A caller can therefore check a stop flag between any two ticks.
//!
//! Time is only the scenario's injected [`MonotonicMillis`]; nothing reads a
//! wall clock, iterates a hash map, or formats a hash key or seed.
//!
//! An `apply` step reads, parses, and validates the referenced file. A file
//! that fails parsing, validation, or the M1 service bridge is rejected as
//! `invalid` without a tick. Otherwise the sequencer builds the next
//! generation (consuming it even if the apply is later rejected) and the
//! driver runs one tick at the current injected time whose publication phase
//! carries the candidate; that tick's outcome is the apply outcome. Tick
//! budgets of the active configuration are used, so the apply tick still runs
//! with the old budgets. A restart-required change is reported as a rejection
//! and leaves the old generation active: M1 `run-sim` never re-creates
//! storage within one run.
//!
//! The driver drains every TX frame after every tick (completing it), so the
//! simulated backend is always quiescent at a tick boundary.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::path::Path;

use ruster_config::{
    parse, validate, Diagnostic, ValidatedConfig, ValidatedConfigV1, ValidationError,
    ValidationLimits, MAX_CONFIG_BYTES,
};
use ruster_control::{
    ActivationError, ActivePublication, ApplyError, ConfigBridgeError, FullServiceStorage,
    PublicationSequencer, RestartRequired, SequencerError, SimDeterministicKeySource,
    StorageAllocationError, ValidatedCandidate,
};
use ruster_core::{BackendStats, ConsumeReason, DropReason, IfId, MonotonicMillis};
use ruster_io_sim::{FrameOrigin, SimIo};
use ruster_runtime::{
    run_tick, ApplyFlushCounts, HealthPolicy, ObservabilitySnapshot, PhaseReport,
    PublicationOutcome, RxPhaseReport, ServiceCounters, TickBudgets, TickObserver,
};

use crate::output::{hex_string, Line};
use crate::{
    parse_scenario, ApplyOutcome, Expectation, RejectReason, Scenario, ScenarioError, ScenarioPath,
    Step, MAX_SCENARIO_BYTES,
};

/// Value of the `schema` field of the first output line.
pub const RUN_SIM_SCHEMA_V1: &str = "ruster-run-sim/v1";

/// Storage bounds the simulation driver passes to configuration validation.
pub const SIM_VALIDATION_LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1 << 16,
    max_runtime_bytes: 64 << 20,
};

type Sequencer = PublicationSequencer<SimDeterministicKeySource>;

/// Which input file a read failure refers to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRole {
    Scenario,
    Config,
}

/// Why a configuration document was rejected as invalid. Value-free.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigRejection {
    Parse(Diagnostic),
    Validate(ValidationError),
    /// A schema version this driver does not know.
    UnsupportedVersion,
    /// The M1 service bridge rejected the document (for example a missing
    /// NAT44 or firewall service).
    Bridge(ConfigBridgeError),
}

impl ConfigRejection {
    const fn stage(&self) -> &'static str {
        match self {
            Self::Parse(_) => "parse",
            Self::Validate(_) => "validate",
            Self::UnsupportedVersion => "version",
            Self::Bridge(_) => "bridge",
        }
    }

    fn code(&self) -> String {
        match self {
            Self::Parse(diagnostic) => format!("{:?}", diagnostic.code()),
            Self::Validate(error) => format!("{:?}", error.code()),
            Self::UnsupportedVersion => "UnsupportedVersion".to_owned(),
            Self::Bridge(error) => format!("{error:?}"),
        }
    }
}

/// Observed class of one apply, compared with [`ApplyOutcome`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyClass {
    Applied,
    RestartRequired,
    Invalid,
}

/// One transmitted frame: egress interface and exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxRecord {
    pub interface: IfId,
    pub bytes: Vec<u8>,
}

/// The first difference between an `expect` step and the observed run.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExpectMismatch {
    /// TX since the previous expect differs first at `index`. A missing side
    /// means that list is shorter.
    Tx {
        index: usize,
        expected_count: usize,
        actual_count: usize,
        expected: Option<TxRecord>,
        actual: Option<TxRecord>,
    },
    Drop {
        reason: DropReason,
        expected: u64,
        actual: u64,
    },
    Consume {
        reason: ConsumeReason,
        expected: u64,
        actual: u64,
    },
    Generation {
        expected: NonZeroU64,
        actual: NonZeroU64,
    },
}

impl ExpectMismatch {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Tx { .. } => "tx",
            Self::Drop { .. } => "drop",
            Self::Consume { .. } => "consume",
            Self::Generation { .. } => "generation",
        }
    }
}

impl fmt::Display for ExpectMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tx {
                index,
                expected_count,
                actual_count,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "tx[{index}] differs (expected {expected_count} frames, observed {actual_count})"
                )?;
                for (label, record) in [("expected", expected), ("observed", actual)] {
                    match record {
                        Some(record) => write!(
                            formatter,
                            "; {label} if{} {}",
                            record.interface.0,
                            hex_string(&record.bytes)
                        )?,
                        None => write!(formatter, "; {label} none")?,
                    }
                }
                if let (Some(expected), Some(actual)) = (expected, actual) {
                    let offset = expected
                        .bytes
                        .iter()
                        .zip(&actual.bytes)
                        .position(|(a, b)| a != b)
                        .unwrap_or_else(|| expected.bytes.len().min(actual.bytes.len()));
                    write!(formatter, "; first differing byte {offset}")?;
                }
                Ok(())
            }
            Self::Drop {
                reason,
                expected,
                actual,
            } => write!(
                formatter,
                "drop {} expected {expected}, observed {actual}",
                reason.code()
            ),
            Self::Consume {
                reason,
                expected,
                actual,
            } => write!(
                formatter,
                "consume {} expected {expected}, observed {actual}",
                reason.code()
            ),
            Self::Generation { expected, actual } => {
                write!(
                    formatter,
                    "generation expected {expected}, observed {actual}"
                )
            }
        }
    }
}

/// Typed driver failure. Never carries a hash key, seed, or file content.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DriverError {
    /// A file could not be opened or read. `step` is `None` for the
    /// scenario and the initial configuration.
    Read {
        file: FileRole,
        step: Option<usize>,
        kind: io::ErrorKind,
    },
    Scenario(ScenarioError),
    /// The scenario's initial configuration is invalid.
    InitialConfig(ConfigRejection),
    Sequencer {
        step: Option<usize>,
        error: SequencerError,
    },
    StorageAllocation(StorageAllocationError),
    Activation(ActivationError),
    /// A step names an interface absent from the active configuration.
    UnknownInterface {
        step: usize,
        name: String,
    },
    ApplyMismatch {
        step: usize,
        expected: ApplyOutcome,
        observed: ApplyClass,
    },
    /// The publication rejected a sequencer-built candidate for a reason
    /// that is neither restart-required nor configuration-invalid.
    UnexpectedApplyError {
        step: usize,
        error: ApplyError,
    },
    /// The backend was not quiescent at the apply tick boundary.
    ApplyDeferred {
        step: usize,
    },
    Expect {
        step: usize,
        mismatch: ExpectMismatch,
    },
    /// The output writer failed.
    Output(io::ErrorKind),
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { file, step, kind } => {
                write!(formatter, "cannot read {file:?} file")?;
                if let Some(step) = step {
                    write!(formatter, " of step[{step}]")?;
                }
                write!(formatter, ": {kind:?}")
            }
            Self::Scenario(error) => write!(formatter, "{error}"),
            Self::InitialConfig(rejection) => write!(
                formatter,
                "initial config rejected at {}: {}",
                rejection.stage(),
                rejection.code()
            ),
            Self::Sequencer { error, .. } => write!(formatter, "sequencer failed: {error:?}"),
            Self::StorageAllocation(error) => write!(formatter, "storage allocation: {error:?}"),
            Self::Activation(error) => write!(formatter, "activation failed: {error:?}"),
            Self::UnknownInterface { step, name } => {
                write!(formatter, "step[{step}]: unknown interface {name:?}")
            }
            Self::ApplyMismatch {
                step,
                expected,
                observed,
            } => write!(
                formatter,
                "step[{step}]: apply expected {expected:?}, observed {observed:?}"
            ),
            Self::UnexpectedApplyError { step, error } => {
                write!(formatter, "step[{step}]: unexpected apply error {error:?}")
            }
            Self::ApplyDeferred { step } => write!(formatter, "step[{step}]: apply deferred"),
            Self::Expect { step, mismatch } => write!(formatter, "step[{step}]: {mismatch}"),
            Self::Output(kind) => write!(formatter, "output failed: {kind:?}"),
        }
    }
}

impl std::error::Error for DriverError {}

/// What [`SimRun::step`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One unit of work ran; more remain.
    Running,
    /// The final `hold` marker was reached (CLI hold mode).
    Hold,
    /// Every step has run.
    Finished,
}

/// Result of a completed run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunSummary {
    pub generation: NonZeroU64,
    pub snapshot: ObservabilitySnapshot,
}

/// A loaded scenario with its validated initial configuration and storage.
pub struct SimSession {
    scenario: Scenario,
    sequencer: Sequencer,
    storage: FullServiceStorage,
    initial: Option<(ValidatedConfigV1, ValidatedCandidate)>,
}

impl SimSession {
    /// Reads the scenario at `path` (relative config paths resolve against its
    /// directory) and prepares the initial publication.
    pub fn load(path: &Path) -> Result<Self, DriverError> {
        let bytes = read_bounded(path, MAX_SCENARIO_BYTES, FileRole::Scenario, None)?;
        let base = path.parent().unwrap_or_else(|| Path::new(""));
        let scenario = parse_scenario(&bytes, base).map_err(DriverError::Scenario)?;
        Self::new(scenario)
    }

    /// Prepares the initial publication of an already parsed scenario.
    pub fn new(scenario: Scenario) -> Result<Self, DriverError> {
        let config = load_config(&scenario.config, None)?.map_err(DriverError::InitialConfig)?;
        let mut sequencer = Sequencer::new(SimDeterministicKeySource::new(scenario.seed.get()));
        let candidate = sequencer.candidate(&config).map_err(|error| match error {
            SequencerError::Bridge(error) => {
                DriverError::InitialConfig(ConfigRejection::Bridge(error))
            }
            error => DriverError::Sequencer { step: None, error },
        })?;
        let storage = FullServiceStorage::new(candidate.storage_shape())
            .map_err(DriverError::StorageAllocation)?;
        Ok(Self {
            scenario,
            sequencer,
            storage,
            initial: Some((config, candidate)),
        })
    }

    #[must_use]
    pub const fn scenario(&self) -> &Scenario {
        &self.scenario
    }

    /// Activates the initial generation and writes the `start` event.
    ///
    /// A session runs once; a second call fails with
    /// [`ActivationError::GenerationNotAboveFloor`].
    pub fn start<W: Write>(&mut self, out: &mut W) -> Result<SimRun<'_>, DriverError> {
        let (config, candidate) = self.initial.take().ok_or(DriverError::Activation(
            ActivationError::GenerationNotAboveFloor,
        ))?;
        let active = ActivePublication::new(&mut self.storage, candidate)
            .map_err(DriverError::Activation)?;
        let run = SimRun {
            scenario: &self.scenario,
            sequencer: &mut self.sequencer,
            active,
            budgets: budgets(&config),
            config,
            io: SimIo::new(),
            observer: TickObserver::new(HealthPolicy::default()),
            now: self.scenario.start_ms,
            cursor: 0,
            ticks_left: 0,
            tx: Vec::new(),
        };
        run.write_start(out)?;
        Ok(run)
    }
}

/// A running scenario. See the module documentation.
pub struct SimRun<'s> {
    scenario: &'s Scenario,
    sequencer: &'s mut Sequencer,
    active: ActivePublication<'s, SimIo>,
    config: ValidatedConfigV1,
    budgets: TickBudgets,
    io: SimIo,
    observer: TickObserver,
    now: u64,
    cursor: usize,
    /// Remaining ticks of the tick step at `cursor`, once started.
    ticks_left: u32,
    /// TX since the previous expect step.
    tx: Vec<TxRecord>,
}

enum TickPublication {
    Unchanged,
    Applied(ApplyFlushCounts),
    Rejected(ApplyError),
    Deferred,
}

impl SimRun<'_> {
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.active.generation()
    }

    /// Current injected time in milliseconds.
    #[must_use]
    pub const fn now_ms(&self) -> u64 {
        self.now
    }

    #[must_use]
    pub fn snapshot(&self) -> ObservabilitySnapshot {
        self.observer.snapshot(MonotonicMillis(self.now))
    }

    /// Runs one unit of work: an inject, one tick, an apply, or an expect.
    pub fn step<W: Write>(&mut self, out: &mut W) -> Result<Progress, DriverError> {
        let scenario = self.scenario;
        let Some(step) = scenario.steps.get(self.cursor) else {
            return Ok(Progress::Finished);
        };
        let index = self.cursor;
        match step {
            Step::Inject { interface, frame } => {
                let id = self.interface_id(index, interface.as_str())?;
                self.io.inject(id, frame.bytes().to_vec());
                let mut line = Line::event("inject");
                line.usize("step", index);
                line.str("interface", interface.as_str());
                line.usize("len", frame.bytes().len());
                line.hex("hex", frame.bytes());
                emit(out, line)?;
            }
            Step::Tick { at_ms, ticks } => {
                if self.ticks_left == 0 {
                    self.now = *at_ms;
                    self.ticks_left = *ticks;
                }
                self.ticks_left = self.ticks_left.saturating_sub(1);
                self.tick(index, None, out)?;
                if self.ticks_left != 0 {
                    return Ok(Progress::Running);
                }
            }
            Step::Apply { config, outcome } => self.apply(index, config, *outcome, out)?,
            Step::Expect(expectation) => self.expect(index, expectation, out)?,
            Step::Hold => {
                self.cursor += 1;
                return Ok(Progress::Hold);
            }
        }
        self.cursor += 1;
        Ok(if self.cursor == scenario.steps.len() {
            Progress::Finished
        } else {
            Progress::Running
        })
    }

    /// Runs every remaining step, stopping at `hold` or the end.
    pub fn run<W: Write>(&mut self, out: &mut W) -> Result<Progress, DriverError> {
        loop {
            match self.step(out)? {
                Progress::Running => {}
                done => return Ok(done),
            }
        }
    }

    /// Writes the `final` event with the observability snapshot, the
    /// per-service counters, and the backend stats.
    pub fn finish<W: Write>(&self, out: &mut W) -> Result<RunSummary, DriverError> {
        let snapshot = self.snapshot();
        let active = &self.active;
        let services = ServiceCounters::capture(
            active.resolution(),
            active.icmpv4_errors(),
            active.nat44_udp(),
            active.nat44_tcp(),
            active.firewall(),
        );
        let mut line = Line::event("final");
        line.u64("at_ms", self.now);
        line.u64("generation", self.generation().get());
        line.fields("observability", &snapshot);
        line.fields("services", &services);
        line.fields("backend", &self.io.backend_stats());
        emit(out, line)?;
        Ok(RunSummary {
            generation: self.generation(),
            snapshot,
        })
    }

    fn interface_id(&self, step: usize, name: &str) -> Result<IfId, DriverError> {
        self.config
            .interfaces()
            .iter()
            .find(|binding| binding.name() == name)
            .map(ruster_config::InterfaceBindingV1::id)
            .ok_or_else(|| DriverError::UnknownInterface {
                step,
                name: name.to_owned(),
            })
    }

    fn interface_name(&self, id: IfId) -> Option<&str> {
        self.config
            .interfaces()
            .iter()
            .find(|binding| binding.id() == id)
            .map(ruster_config::InterfaceBindingV1::name)
    }

    fn tick<W: Write>(
        &mut self,
        step: usize,
        candidate: Option<ValidatedCandidate>,
        out: &mut W,
    ) -> Result<TickPublication, DriverError> {
        let now = MonotonicMillis(self.now);
        let report = run_tick(
            &mut self.active,
            candidate,
            &mut self.io,
            now,
            self.budgets,
            &mut self.observer,
        );
        let generation = self.active.generation();
        self.observer.observe_tick(now, Some(generation), &report);
        let publication = match report.publication {
            PublicationOutcome::Unchanged => TickPublication::Unchanged,
            PublicationOutcome::Applied => {
                let flush = self.active.last_apply().map_or_else(Default::default, |r| {
                    ApplyFlushCounts::from_reports(
                        r.resolution,
                        r.icmpv4_errors,
                        r.nat44_udp,
                        r.nat44_tcp,
                        r.firewall,
                    )
                });
                self.observer.record_apply_flush(generation, flush);
                TickPublication::Applied(flush)
            }
            PublicationOutcome::Rejected(error) => TickPublication::Rejected(error),
            PublicationOutcome::Deferred { .. } => TickPublication::Deferred,
        };
        let (received, forwarded, dropped, consumed) = match &report.rx {
            RxPhaseReport::Completed(batch)
            | RxPhaseReport::AccountingInvariantViolation(batch) => (
                batch.received,
                batch.completion.tx_accepted,
                batch.dropped,
                batch.consumed,
            ),
            RxPhaseReport::Skipped(_) | RxPhaseReport::ReceiveFailed(_) => (0, 0, 0, 0),
        };
        let generated = |accepted: Option<usize>| accepted.unwrap_or(0);
        let generated_arp = generated(match &report.generated_arp {
            PhaseReport::Completed(phase) => Some(phase.accounting.tx_accepted),
            _ => None,
        });
        let generated_icmpv4 = generated(match &report.generated_icmpv4 {
            PhaseReport::Completed(phase) => Some(phase.accounting.tx_accepted),
            _ => None,
        });

        let mut line = Line::event("tick");
        line.usize("step", step);
        line.u64("at_ms", self.now);
        line.u64("generation", generation.get());
        line.str(
            "publication",
            match publication {
                TickPublication::Unchanged => "unchanged",
                TickPublication::Applied(_) => "applied",
                TickPublication::Rejected(_) => "rejected",
                TickPublication::Deferred => "deferred",
            },
        );
        line.bool("active", report.active);
        line.usize("received", received);
        line.usize("forwarded", forwarded);
        line.usize("dropped", dropped);
        line.usize("consumed", consumed);
        line.usize("generated_arp", generated_arp);
        line.usize("generated_icmpv4", generated_icmpv4);
        emit(out, line)?;

        // Completing every accepted TX keeps the backend quiescent.
        while let Some(frame) = self.io.pop_tx() {
            let mut line = Line::event("tx");
            line.usize("step", step);
            line.u64("at_ms", self.now);
            line.opt_str("interface", self.interface_name(frame.egress));
            line.str(
                "origin",
                match frame.origin {
                    FrameOrigin::Received { .. } => "forwarded",
                    FrameOrigin::Generated => "generated",
                },
            );
            line.usize("len", frame.bytes.len());
            line.hex("hex", &frame.bytes);
            emit(out, line)?;
            self.tx.push(TxRecord {
                interface: frame.egress,
                bytes: frame.bytes,
            });
        }
        while self.io.pop_recycled().is_some() {}
        while self.io.pop_generated_recycled().is_some() {}
        Ok(publication)
    }

    fn apply<W: Write>(
        &mut self,
        step: usize,
        path: &ScenarioPath,
        expected: ApplyOutcome,
        out: &mut W,
    ) -> Result<(), DriverError> {
        let mut candidate_generation = None;
        let mut flush = None;
        let (class, stage, code) = match load_config(path, Some(step))? {
            Err(rejection) => (ApplyClass::Invalid, rejection.stage(), rejection.code()),
            Ok(config) => match self.sequencer.candidate(&config) {
                Err(SequencerError::Bridge(error)) => {
                    candidate_generation = self.sequencer.last_issued();
                    let rejection = ConfigRejection::Bridge(error);
                    (ApplyClass::Invalid, rejection.stage(), rejection.code())
                }
                Err(error) => {
                    return Err(DriverError::Sequencer {
                        step: Some(step),
                        error,
                    })
                }
                Ok(candidate) => {
                    candidate_generation = Some(candidate.generation());
                    match self.tick(step, Some(candidate), out)? {
                        TickPublication::Applied(counts) => {
                            flush = Some(counts);
                            self.budgets = budgets(&config);
                            self.config = config;
                            (ApplyClass::Applied, "successor", String::new())
                        }
                        TickPublication::Rejected(ApplyError::RestartRequired(reason)) => (
                            ApplyClass::RestartRequired,
                            "successor",
                            restart_label(reason).to_owned(),
                        ),
                        TickPublication::Rejected(error) => {
                            return Err(DriverError::UnexpectedApplyError { step, error })
                        }
                        TickPublication::Deferred | TickPublication::Unchanged => {
                            return Err(DriverError::ApplyDeferred { step })
                        }
                    }
                }
            },
        };

        let mut line = Line::event("apply");
        line.usize("step", step);
        line.u64("at_ms", self.now);
        line.str("config", &path.relative().to_string_lossy());
        line.str(
            "outcome",
            if class == ApplyClass::Applied {
                "applied"
            } else {
                "rejected"
            },
        );
        line.opt_str(
            "reason",
            match class {
                ApplyClass::Applied => None,
                ApplyClass::RestartRequired => Some("restart-required"),
                ApplyClass::Invalid => Some("invalid"),
            },
        );
        line.str("stage", stage);
        line.opt_str("code", (!code.is_empty()).then_some(code.as_str()));
        line.opt_u64(
            "candidate_generation",
            candidate_generation.map(NonZeroU64::get),
        );
        line.u64("generation", self.generation().get());
        match flush {
            Some(flush) => write_flush(&mut line, flush),
            None => line.null("flush"),
        }
        emit(out, line)?;

        let matches = match (expected, class) {
            (ApplyOutcome::Applied, ApplyClass::Applied) => true,
            (ApplyOutcome::Rejected { reason }, ApplyClass::RestartRequired) => {
                matches!(reason, None | Some(RejectReason::RestartRequired))
            }
            (ApplyOutcome::Rejected { reason }, ApplyClass::Invalid) => {
                matches!(reason, None | Some(RejectReason::Invalid))
            }
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(DriverError::ApplyMismatch {
                step,
                expected,
                observed: class,
            })
        }
    }

    fn expect<W: Write>(
        &mut self,
        step: usize,
        expectation: &Expectation,
        out: &mut W,
    ) -> Result<(), DriverError> {
        let observed = std::mem::take(&mut self.tx);
        let result = self.evaluate(step, expectation, &observed);
        let mut line = Line::event("expect");
        line.usize("step", step);
        line.u64("at_ms", self.now);
        line.usize("tx_observed", observed.len());
        line.u64("generation", self.generation().get());
        match &result {
            Ok(()) => {
                line.str("result", "pass");
                line.null("mismatch");
            }
            Err(DriverError::Expect { mismatch, .. }) => {
                line.str("result", "fail");
                line.str("mismatch", mismatch.kind());
            }
            Err(_) => {
                line.str("result", "error");
                line.null("mismatch");
            }
        }
        emit(out, line)?;
        result
    }

    fn evaluate(
        &self,
        step: usize,
        expectation: &Expectation,
        observed: &[TxRecord],
    ) -> Result<(), DriverError> {
        let fail = |mismatch| Err(DriverError::Expect { step, mismatch });
        if let Some(expected) = &expectation.tx {
            let mut wanted = Vec::with_capacity(expected.len());
            for entry in expected {
                wanted.push(TxRecord {
                    interface: self.interface_id(step, entry.interface.as_str())?,
                    bytes: entry.frame.bytes().to_vec(),
                });
            }
            let length = wanted.len().max(observed.len());
            if let Some(index) = (0..length).find(|&i| wanted.get(i) != observed.get(i)) {
                return fail(ExpectMismatch::Tx {
                    index,
                    expected_count: wanted.len(),
                    actual_count: observed.len(),
                    expected: wanted.get(index).cloned(),
                    actual: observed.get(index).cloned(),
                });
            }
        }
        let snapshot = self.snapshot();
        for &(reason, expected) in &expectation.drops {
            let actual = snapshot.drops.count(reason);
            if actual != expected {
                return fail(ExpectMismatch::Drop {
                    reason,
                    expected,
                    actual,
                });
            }
        }
        for &(reason, expected) in &expectation.consumes {
            let actual = snapshot.consumes.count(reason);
            if actual != expected {
                return fail(ExpectMismatch::Consume {
                    reason,
                    expected,
                    actual,
                });
            }
        }
        if let Some(expected) = expectation.generation {
            let actual = self.generation();
            if actual != expected {
                return fail(ExpectMismatch::Generation { expected, actual });
            }
        }
        Ok(())
    }

    fn write_start<W: Write>(&self, out: &mut W) -> Result<(), DriverError> {
        let mut line = Line::event("start");
        line.str("schema", RUN_SIM_SCHEMA_V1);
        line.str("backend", SimIo::NAME);
        line.str("backend_mode", SimIo::MODE.label());
        line.str("config", &self.scenario.config.relative().to_string_lossy());
        line.u64("generation", self.generation().get());
        line.u64("start_ms", self.now);
        line.usize("steps", self.scenario.steps.len());
        line.open_array("interfaces");
        for binding in self.config.interfaces() {
            line.open_element();
            line.u64("id", u64::from(binding.id().0));
            line.str("name", binding.name());
            line.str("device", binding.device());
            line.mac("mac", binding.mac());
            line.close();
        }
        line.close_array();
        let shape = self.config.storage_shape();
        line.open("capacity");
        match shape.resolution {
            Some(r) => {
                line.open("resolution");
                line.u64("states", r.states.into());
                line.u64("actions", r.actions.into());
                line.u64("dynamic_neighbors", r.dynamic_neighbors.into());
                line.u64("failure_holds", r.failure_holds.into());
                line.close();
            }
            None => line.null("resolution"),
        }
        match shape.icmpv4_errors {
            Some(i) => {
                line.open("icmpv4_errors");
                line.u64("states", i.states.into());
                line.u64("actions", i.actions.into());
                line.close();
            }
            None => line.null("icmpv4_errors"),
        }
        match shape.nat44_udp {
            Some(u) => {
                line.open("nat44_udp");
                line.u64("mappings", u.mappings.into());
                line.u64("peers", u.peers.into());
                line.u64("port_owners", u.port_owners.into());
                line.close();
            }
            None => line.null("nat44_udp"),
        }
        match shape.nat44_tcp {
            Some(t) => {
                line.open("nat44_tcp");
                line.u64("mappings", t.mappings.into());
                line.u64("sessions", t.sessions.into());
                line.u64("port_owners", t.port_owners.into());
                line.close();
            }
            None => line.null("nat44_tcp"),
        }
        line.opt_u64("firewall_states", shape.firewall_states.map(u64::from));
        line.usize("required_bytes", shape.required_bytes);
        line.close();
        line.open("tick_budget");
        let TickBudgets {
            rx,
            resolution_timer_scans,
            failure_dispatch_scans,
            generated_arp,
            generated_icmpv4,
        } = self.budgets;
        line.usize("rx", rx);
        line.usize("resolution_timer_scans", resolution_timer_scans);
        line.usize("failure_dispatch_scans", failure_dispatch_scans);
        line.usize("generated_arp", generated_arp);
        line.usize("generated_icmpv4", generated_icmpv4);
        line.close();
        emit(out, line)
    }
}

/// Writes committed apply flush counts as an object named `flush`. The
/// destructuring has no `..`, so a new counter fails to compile until listed.
fn write_flush(line: &mut Line, flush: ApplyFlushCounts) {
    let ApplyFlushCounts {
        resolution_states,
        resolution_actions,
        dynamic_neighbors,
        failure_holds,
        icmpv4_error_states,
        icmpv4_error_actions,
        nat44_udp_mappings,
        nat44_udp_peers,
        nat44_tcp_mappings,
        nat44_tcp_sessions,
        firewall_flows,
    } = flush;
    line.open("flush");
    for (key, value) in [
        ("resolution_states", resolution_states),
        ("resolution_actions", resolution_actions),
        ("dynamic_neighbors", dynamic_neighbors),
        ("failure_holds", failure_holds),
        ("icmpv4_error_states", icmpv4_error_states),
        ("icmpv4_error_actions", icmpv4_error_actions),
        ("nat44_udp_mappings", nat44_udp_mappings),
        ("nat44_udp_peers", nat44_udp_peers),
        ("nat44_tcp_mappings", nat44_tcp_mappings),
        ("nat44_tcp_sessions", nat44_tcp_sessions),
        ("firewall_flows", firewall_flows),
    ] {
        line.u64(key, value);
    }
    line.close();
}

const fn restart_label(reason: RestartRequired) -> &'static str {
    match reason {
        RestartRequired::StorageShape => "storage_shape",
        RestartRequired::ResolutionPolicy => "resolution_policy",
        RestartRequired::Icmpv4ErrorPolicy => "icmpv4_error_policy",
        RestartRequired::Interfaces => "interfaces",
        _ => "other",
    }
}

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

fn emit<W: Write>(out: &mut W, line: Line) -> Result<(), DriverError> {
    out.write_all(line.finish().as_bytes())
        .map_err(|error| DriverError::Output(error.kind()))
}

/// Reads at most `limit + 1` bytes so oversized input reaches the parser's
/// own bound check instead of being read whole.
fn read_bounded(
    path: &Path,
    limit: usize,
    file: FileRole,
    step: Option<usize>,
) -> Result<Vec<u8>, DriverError> {
    let error = |error: io::Error| DriverError::Read {
        file,
        step,
        kind: error.kind(),
    };
    let mut bytes = Vec::new();
    let take = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    File::open(path)
        .map_err(error)?
        .take(take)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    Ok(bytes)
}

/// Reads, parses, and validates one configuration file. I/O failures are
/// driver errors; content failures are [`ConfigRejection`]s.
fn load_config(
    path: &ScenarioPath,
    step: Option<usize>,
) -> Result<Result<ValidatedConfigV1, ConfigRejection>, DriverError> {
    let bytes = read_bounded(path.resolved(), MAX_CONFIG_BYTES, FileRole::Config, step)?;
    let parsed = match parse(&bytes) {
        Ok(parsed) => parsed,
        Err(diagnostic) => return Ok(Err(ConfigRejection::Parse(diagnostic))),
    };
    Ok(match validate(parsed, SIM_VALIDATION_LIMITS) {
        Ok(ValidatedConfig::V1(config)) => Ok(config),
        Ok(_) => Err(ConfigRejection::UnsupportedVersion),
        Err(error) => Err(ConfigRejection::Validate(error)),
    })
}

/// Loads `scenario_path`, runs it to the end (or `hold`), and writes the
/// complete `ruster-run-sim/v1` output including the `final` event.
///
/// On a step failure the output written so far ends with the failing event;
/// no `final` event is written.
pub fn run_scenario_file<W: Write>(
    scenario_path: &Path,
    out: &mut W,
) -> Result<RunSummary, DriverError> {
    let mut session = SimSession::load(scenario_path)?;
    let mut run = session.start(out)?;
    run.run(out)?;
    run.finish(out)
}

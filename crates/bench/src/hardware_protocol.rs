//! Pure, NIC-free measurement protocol for the frozen hardware plan.
//!
//! This module validates measurement inputs and derives artifact records. It
//! does not execute a driver, access a filesystem, mutate Linux state, evaluate
//! thresholds, compare baselines, or make performance claims.

use std::collections::BTreeSet;
use std::fmt;

use crate::{
    validate_hardware_plan_v1, ArtifactHash, DirectionProfile, FrameHealth, HardwareCase,
    HardwareFrame, HardwarePlan, HardwarePlanError, HardwareRepeat, HardwareSummary,
    ImixAcceptedFrames, LifecycleOutcome, LifecyclePhase, LifecycleRecord, PlannedHardwareCase,
    SchemaError, HARDWARE_PLAN_VERSION, HARDWARE_TOTAL_CASE_COUNT, RUSTER_IMIX_V1_CYCLE,
};

pub const HARDWARE_MEASUREMENT_PROTOCOL_VERSION: u32 = 1;
pub const HARDWARE_PLAN_FINGERPRINT_V1: u64 = 0xf68c_80b7_2065_c023;
pub const MAX_HARDWARE_WARMUP_SECONDS: u32 = 600;
pub const MAX_HARDWARE_DURATION_SECONDS: u32 = 600;
pub const MAX_HARDWARE_REPEAT_COUNT: u16 = 31;
pub const MAX_HARDWARE_DRAIN_TIMEOUT_MS: u64 = 600_000;
pub const MAX_HARDWARE_CASE_TIMEOUT_MS: u64 = 21_600_000;
pub const MAX_HARDWARE_RUN_TIMEOUT_MS: u64 = 5_184_000_000;
pub const MAX_LATENCY_SAMPLE_EVERY_PACKETS: u32 = 1_000_000;

const PROFILE_ID_CAPACITY: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MeasurementProtocolError {
    InvalidGitCommit(&'static str),
    InvalidSha256(&'static str),
    InvalidProfileId,
    TimingOutOfRange(&'static str),
    RepeatCountMustBeOdd,
    TimeoutTooShort(&'static str),
    ArithmeticOverflow(&'static str),
    InvalidLatencyProfile(&'static str),
    InvalidPlan(HardwarePlanError),
    PlanFingerprintMismatch {
        expected: u64,
        actual: u64,
    },
    OrdinalOutOfRange(u16),
    RepeatIndexOutOfRange {
        actual: u16,
        maximum: u16,
    },
    DuplicatePackets(u64),
    UnexpectedPackets(u64),
    OracleFailures(u64),
    InactiveDirection(DirectionProfile),
    EmptyDirection(DirectionProfile),
    ReceivedExceedsOffered(DirectionProfile),
    AcceptedDoesNotMatchReceived(DirectionProfile),
    CounterOverflow(&'static str),
    MissingImixEvidence(DirectionProfile),
    UnexpectedImixEvidence(DirectionProfile),
    InvalidImixEvidence(DirectionProfile),
    InvalidLatency(&'static str),
    InvalidArtifact(SchemaError),
    RepeatSetLength {
        expected: usize,
        actual: usize,
    },
    SummarySetLength {
        expected: usize,
        actual: usize,
    },
    RepeatBindingMismatch,
    SummaryBindingMismatch,
    DuplicateRepeat {
        ordinal: u16,
        repeat_index: u16,
    },
    MissingRepeat {
        ordinal: u16,
        repeat_index: u16,
    },
    DuplicateSummary(u16),
    MissingSummary(u16),
    SummaryDerivationMismatch(u16),
    LifecycleSequence {
        expected: u64,
        actual: u64,
    },
    LifecycleTimeRegression {
        previous: u64,
        actual: u64,
    },
    LifecycleUnexpectedCode,
    LifecycleUnexpectedOutcome,
    LifecycleOpenEvent,
    LifecycleIncomplete,
    LifecycleFinished,
    LifecycleTimeout {
        scope: &'static str,
        limit_ms: u64,
        elapsed_ms: u64,
    },
}

impl fmt::Display for MeasurementProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGitCommit(field) => write!(formatter, "invalid git commit in {field}"),
            Self::InvalidSha256(field) => write!(formatter, "invalid SHA-256 in {field}"),
            Self::InvalidProfileId => formatter.write_str("invalid measurement profile id"),
            Self::TimingOutOfRange(field) => {
                write!(formatter, "measurement timing {field} is out of range")
            }
            Self::RepeatCountMustBeOdd => {
                formatter.write_str("measurement repeat count must be odd")
            }
            Self::TimeoutTooShort(field) => {
                write!(formatter, "measurement timeout {field} is too short")
            }
            Self::ArithmeticOverflow(field) => {
                write!(formatter, "measurement arithmetic overflow in {field}")
            }
            Self::InvalidLatencyProfile(reason) => {
                write!(formatter, "invalid latency profile: {reason}")
            }
            Self::InvalidPlan(error) => write!(formatter, "invalid hardware plan: {error}"),
            Self::PlanFingerprintMismatch { expected, actual } => write!(
                formatter,
                "hardware plan fingerprint mismatch: expected {expected:016x}, got {actual:016x}"
            ),
            Self::OrdinalOutOfRange(ordinal) => {
                write!(formatter, "hardware case ordinal {ordinal} is out of range")
            }
            Self::RepeatIndexOutOfRange { actual, maximum } => write!(
                formatter,
                "hardware repeat index {actual} is outside 1..={maximum}"
            ),
            Self::DuplicatePackets(count) => {
                write!(formatter, "measurement observed {count} duplicate packets")
            }
            Self::UnexpectedPackets(count) => {
                write!(formatter, "measurement observed {count} unexpected packets")
            }
            Self::OracleFailures(count) => {
                write!(
                    formatter,
                    "measurement observed {count} packet oracle failures"
                )
            }
            Self::InactiveDirection(direction) => {
                write!(
                    formatter,
                    "inactive {} direction has packet counters",
                    direction.label()
                )
            }
            Self::EmptyDirection(direction) => {
                write!(
                    formatter,
                    "active {} direction offered no packets",
                    direction.label()
                )
            }
            Self::ReceivedExceedsOffered(direction) => write!(
                formatter,
                "{} received packets exceed offered packets",
                direction.label()
            ),
            Self::AcceptedDoesNotMatchReceived(direction) => write!(
                formatter,
                "{} accepted packets do not match oracle-clean received packets",
                direction.label()
            ),
            Self::CounterOverflow(field) => {
                write!(formatter, "measurement counter overflow in {field}")
            }
            Self::MissingImixEvidence(direction) => {
                write!(formatter, "missing {} IMIX evidence", direction.label())
            }
            Self::UnexpectedImixEvidence(direction) => {
                write!(formatter, "unexpected {} IMIX evidence", direction.label())
            }
            Self::InvalidImixEvidence(direction) => {
                write!(formatter, "invalid {} IMIX evidence", direction.label())
            }
            Self::InvalidLatency(reason) => {
                write!(formatter, "invalid latency counters: {reason}")
            }
            Self::InvalidArtifact(error) => {
                write!(formatter, "invalid derived hardware artifact: {error}")
            }
            Self::RepeatSetLength { expected, actual } => {
                write!(
                    formatter,
                    "hardware repeat set length: expected {expected}, got {actual}"
                )
            }
            Self::SummarySetLength { expected, actual } => {
                write!(
                    formatter,
                    "hardware summary set length: expected {expected}, got {actual}"
                )
            }
            Self::RepeatBindingMismatch => {
                formatter.write_str("hardware repeat belongs to another measurement binding")
            }
            Self::SummaryBindingMismatch => {
                formatter.write_str("hardware summary belongs to another measurement binding")
            }
            Self::DuplicateRepeat {
                ordinal,
                repeat_index,
            } => write!(
                formatter,
                "duplicate hardware repeat at ordinal {ordinal}, repeat {repeat_index}"
            ),
            Self::MissingRepeat {
                ordinal,
                repeat_index,
            } => write!(
                formatter,
                "missing hardware repeat at ordinal {ordinal}, repeat {repeat_index}"
            ),
            Self::DuplicateSummary(ordinal) => {
                write!(formatter, "duplicate hardware summary at ordinal {ordinal}")
            }
            Self::MissingSummary(ordinal) => {
                write!(formatter, "missing hardware summary at ordinal {ordinal}")
            }
            Self::SummaryDerivationMismatch(ordinal) => {
                write!(
                    formatter,
                    "hardware summary at ordinal {ordinal} is not derived from the supplied repeats"
                )
            }
            Self::LifecycleSequence { expected, actual } => write!(
                formatter,
                "lifecycle sequence mismatch: expected {expected}, got {actual}"
            ),
            Self::LifecycleTimeRegression { previous, actual } => write!(
                formatter,
                "lifecycle time regressed from {previous} ms to {actual} ms"
            ),
            Self::LifecycleUnexpectedCode => {
                formatter.write_str("unexpected lifecycle code for current protocol state")
            }
            Self::LifecycleUnexpectedOutcome => {
                formatter.write_str("unexpected lifecycle outcome for current protocol state")
            }
            Self::LifecycleOpenEvent => {
                formatter.write_str("lifecycle sequence ended with an open event")
            }
            Self::LifecycleIncomplete => {
                formatter.write_str("lifecycle sequence did not reach cleanup")
            }
            Self::LifecycleFinished => formatter.write_str("lifecycle sequence already finished"),
            Self::LifecycleTimeout {
                scope,
                limit_ms,
                elapsed_ms,
            } => write!(
                formatter,
                "lifecycle {scope} exceeded {limit_ms} ms after {elapsed_ms} ms"
            ),
        }
    }
}

impl std::error::Error for MeasurementProtocolError {}

impl From<HardwarePlanError> for MeasurementProtocolError {
    fn from(error: HardwarePlanError) -> Self {
        Self::InvalidPlan(error)
    }
}

impl From<SchemaError> for MeasurementProtocolError {
    fn from(error: SchemaError) -> Self {
        Self::InvalidArtifact(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitCommitId([u8; 20]);

impl GitCommitId {
    pub fn parse(field: &'static str, value: &str) -> Result<Self, MeasurementProtocolError> {
        parse_lower_hex::<20>(value)
            .map(Self)
            .ok_or(MeasurementProtocolError::InvalidGitCommit(field))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn parse(field: &'static str, value: &str) -> Result<Self, MeasurementProtocolError> {
        parse_lower_hex::<32>(value)
            .map(Self)
            .ok_or(MeasurementProtocolError::InvalidSha256(field))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasurementProfileId {
    bytes: [u8; PROFILE_ID_CAPACITY],
    len: u8,
}

impl MeasurementProfileId {
    pub fn parse(value: &str) -> Result<Self, MeasurementProtocolError> {
        if value.is_empty()
            || value.len() > PROFILE_ID_CAPACITY
            || !value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            })
        {
            return Err(MeasurementProtocolError::InvalidProfileId);
        }
        let mut bytes = [0; PROFILE_ID_CAPACITY];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: u8::try_from(value.len())
                .map_err(|_| MeasurementProtocolError::InvalidProfileId)?,
        })
    }

    #[must_use]
    pub fn label(&self) -> &str {
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratorProfile {
    id: MeasurementProfileId,
    config_sha256: Sha256Digest,
}

impl GeneratorProfile {
    #[must_use]
    pub const fn new(id: MeasurementProfileId, config_sha256: Sha256Digest) -> Self {
        Self { id, config_sha256 }
    }

    #[must_use]
    pub const fn id(&self) -> MeasurementProfileId {
        self.id
    }

    #[must_use]
    pub const fn config_sha256(&self) -> Sha256Digest {
        self.config_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LatencyMode {
    Disabled,
    RoundTrip,
    OneWaySynchronized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencyProfile {
    mode: LatencyMode,
    sample_every_packets: u32,
    config_sha256: Sha256Digest,
    clock_evidence_sha256: Option<Sha256Digest>,
}

impl LatencyProfile {
    #[must_use]
    pub const fn disabled(config_sha256: Sha256Digest) -> Self {
        Self {
            mode: LatencyMode::Disabled,
            sample_every_packets: 0,
            config_sha256,
            clock_evidence_sha256: None,
        }
    }

    pub fn round_trip(
        sample_every_packets: u32,
        config_sha256: Sha256Digest,
    ) -> Result<Self, MeasurementProtocolError> {
        validate_sample_every(sample_every_packets)?;
        Ok(Self {
            mode: LatencyMode::RoundTrip,
            sample_every_packets,
            config_sha256,
            clock_evidence_sha256: None,
        })
    }

    pub fn one_way_synchronized(
        sample_every_packets: u32,
        config_sha256: Sha256Digest,
        clock_evidence_sha256: Sha256Digest,
    ) -> Result<Self, MeasurementProtocolError> {
        validate_sample_every(sample_every_packets)?;
        Ok(Self {
            mode: LatencyMode::OneWaySynchronized,
            sample_every_packets,
            config_sha256,
            clock_evidence_sha256: Some(clock_evidence_sha256),
        })
    }

    #[must_use]
    pub const fn mode(self) -> LatencyMode {
        self.mode
    }

    #[must_use]
    pub const fn sample_every_packets(self) -> Option<u32> {
        if self.sample_every_packets == 0 {
            None
        } else {
            Some(self.sample_every_packets)
        }
    }

    #[must_use]
    pub const fn config_sha256(self) -> Sha256Digest {
        self.config_sha256
    }

    #[must_use]
    pub const fn clock_evidence_sha256(self) -> Option<Sha256Digest> {
        self.clock_evidence_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasurementTiming {
    warmup_seconds: u32,
    duration_seconds: u32,
    repeat_count: u16,
    case_timeout_ms: u64,
    drain_timeout_ms: u64,
    run_timeout_ms: u64,
}

impl MeasurementTiming {
    pub fn new(
        warmup_seconds: u32,
        duration_seconds: u32,
        repeat_count: u16,
        case_timeout_ms: u64,
        drain_timeout_ms: u64,
        run_timeout_ms: u64,
    ) -> Result<Self, MeasurementProtocolError> {
        if warmup_seconds > MAX_HARDWARE_WARMUP_SECONDS {
            return Err(MeasurementProtocolError::TimingOutOfRange("warmup_seconds"));
        }
        if duration_seconds == 0 || duration_seconds > MAX_HARDWARE_DURATION_SECONDS {
            return Err(MeasurementProtocolError::TimingOutOfRange(
                "duration_seconds",
            ));
        }
        if repeat_count == 0 || repeat_count > MAX_HARDWARE_REPEAT_COUNT {
            return Err(MeasurementProtocolError::TimingOutOfRange("repeat_count"));
        }
        if repeat_count.is_multiple_of(2) {
            return Err(MeasurementProtocolError::RepeatCountMustBeOdd);
        }
        if drain_timeout_ms == 0 || drain_timeout_ms > MAX_HARDWARE_DRAIN_TIMEOUT_MS {
            return Err(MeasurementProtocolError::TimingOutOfRange(
                "drain_timeout_ms",
            ));
        }
        if case_timeout_ms == 0 || case_timeout_ms > MAX_HARDWARE_CASE_TIMEOUT_MS {
            return Err(MeasurementProtocolError::TimingOutOfRange(
                "case_timeout_ms",
            ));
        }
        if run_timeout_ms == 0 || run_timeout_ms > MAX_HARDWARE_RUN_TIMEOUT_MS {
            return Err(MeasurementProtocolError::TimingOutOfRange("run_timeout_ms"));
        }
        let measured_seconds = duration_seconds
            .checked_mul(u32::from(repeat_count))
            .and_then(|value| value.checked_add(warmup_seconds))
            .ok_or(MeasurementProtocolError::ArithmeticOverflow(
                "case measured seconds",
            ))?;
        let minimum_case_timeout = u64::from(measured_seconds)
            .checked_mul(1_000)
            .and_then(|value| value.checked_add(drain_timeout_ms))
            .ok_or(MeasurementProtocolError::ArithmeticOverflow(
                "minimum case timeout",
            ))?;
        if case_timeout_ms < minimum_case_timeout {
            return Err(MeasurementProtocolError::TimeoutTooShort("case_timeout_ms"));
        }
        let minimum_run_timeout =
            case_timeout_ms
                .checked_mul(u64::try_from(HARDWARE_TOTAL_CASE_COUNT).map_err(|_| {
                    MeasurementProtocolError::ArithmeticOverflow("hardware case count")
                })?)
                .ok_or(MeasurementProtocolError::ArithmeticOverflow(
                    "minimum run timeout",
                ))?;
        if run_timeout_ms < minimum_run_timeout {
            return Err(MeasurementProtocolError::TimeoutTooShort("run_timeout_ms"));
        }
        Ok(Self {
            warmup_seconds,
            duration_seconds,
            repeat_count,
            case_timeout_ms,
            drain_timeout_ms,
            run_timeout_ms,
        })
    }

    #[must_use]
    pub const fn warmup_seconds(self) -> u32 {
        self.warmup_seconds
    }

    #[must_use]
    pub const fn duration_seconds(self) -> u32 {
        self.duration_seconds
    }

    #[must_use]
    pub const fn repeat_count(self) -> u16 {
        self.repeat_count
    }

    #[must_use]
    pub const fn case_timeout_ms(self) -> u64 {
        self.case_timeout_ms
    }

    #[must_use]
    pub const fn drain_timeout_ms(self) -> u64 {
        self.drain_timeout_ms
    }

    #[must_use]
    pub const fn run_timeout_ms(self) -> u64 {
        self.run_timeout_ms
    }
}

/// Frozen, threshold-free protocol inputs for one hardware measurement run.
///
/// Its invariants cannot be bypassed with a public struct literal:
///
/// ```compile_fail
/// use ruster_bench::HardwareMeasurementProtocol;
///
/// let _invalid = HardwareMeasurementProtocol {
///     version: 2,
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareMeasurementProtocol {
    version: u32,
    spec_git_sha: GitCommitId,
    spec_sha256: Sha256Digest,
    source_git_sha: GitCommitId,
    plan_version: u32,
    plan_fingerprint: u64,
    timing: MeasurementTiming,
    generator: GeneratorProfile,
    latency: LatencyProfile,
}

impl HardwareMeasurementProtocol {
    #[must_use]
    pub const fn new_v1(
        spec_git_sha: GitCommitId,
        spec_sha256: Sha256Digest,
        source_git_sha: GitCommitId,
        timing: MeasurementTiming,
        generator: GeneratorProfile,
        latency: LatencyProfile,
    ) -> Self {
        Self {
            version: HARDWARE_MEASUREMENT_PROTOCOL_VERSION,
            spec_git_sha,
            spec_sha256,
            source_git_sha,
            plan_version: HARDWARE_PLAN_VERSION,
            plan_fingerprint: HARDWARE_PLAN_FINGERPRINT_V1,
            timing,
            generator,
            latency,
        }
    }

    #[must_use]
    pub const fn version(self) -> u32 {
        self.version
    }

    #[must_use]
    pub const fn spec_git_sha(self) -> GitCommitId {
        self.spec_git_sha
    }

    #[must_use]
    pub const fn spec_sha256(self) -> Sha256Digest {
        self.spec_sha256
    }

    #[must_use]
    pub const fn source_git_sha(self) -> GitCommitId {
        self.source_git_sha
    }

    #[must_use]
    pub const fn plan_version(self) -> u32 {
        self.plan_version
    }

    #[must_use]
    pub const fn plan_fingerprint(self) -> u64 {
        self.plan_fingerprint
    }

    #[must_use]
    pub const fn timing(self) -> MeasurementTiming {
        self.timing
    }

    #[must_use]
    pub const fn generator(self) -> GeneratorProfile {
        self.generator
    }

    #[must_use]
    pub const fn latency(self) -> LatencyProfile {
        self.latency
    }

    pub fn bind<'a>(
        self,
        plan: &'a HardwarePlan,
    ) -> Result<BoundHardwareMeasurement<'a>, MeasurementProtocolError> {
        validate_hardware_plan_v1(plan)?;
        let actual = hardware_plan_fingerprint(plan);
        if actual != self.plan_fingerprint {
            return Err(MeasurementProtocolError::PlanFingerprintMismatch {
                expected: self.plan_fingerprint,
                actual,
            });
        }
        Ok(BoundHardwareMeasurement {
            protocol: self,
            plan,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BoundHardwareMeasurement<'a> {
    protocol: HardwareMeasurementProtocol,
    plan: &'a HardwarePlan,
}

impl<'a> BoundHardwareMeasurement<'a> {
    #[must_use]
    pub const fn protocol(self) -> HardwareMeasurementProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn plan(self) -> &'a HardwarePlan {
        self.plan
    }

    pub fn case(self, ordinal: u16) -> Result<&'a PlannedHardwareCase, MeasurementProtocolError> {
        self.plan
            .cases
            .get(usize::from(ordinal))
            .ok_or(MeasurementProtocolError::OrdinalOutOfRange(ordinal))
    }

    #[must_use]
    pub fn completeness(self) -> CompletenessMetadata {
        let repeat_count = self.protocol.timing.repeat_count;
        CompletenessMetadata {
            plan_version: HARDWARE_PLAN_VERSION,
            plan_fingerprint: self.protocol.plan_fingerprint,
            case_count: 237,
            repeats_per_case: repeat_count,
            expected_repeat_records: 237_u32 * u32::from(repeat_count),
            expected_summary_records: 237,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletenessMetadata {
    plan_version: u32,
    plan_fingerprint: u64,
    case_count: u16,
    repeats_per_case: u16,
    expected_repeat_records: u32,
    expected_summary_records: u16,
}

impl CompletenessMetadata {
    #[must_use]
    pub const fn plan_version(self) -> u32 {
        self.plan_version
    }

    #[must_use]
    pub const fn plan_fingerprint(self) -> u64 {
        self.plan_fingerprint
    }

    #[must_use]
    pub const fn case_count(self) -> u16 {
        self.case_count
    }

    #[must_use]
    pub const fn repeats_per_case(self) -> u16 {
        self.repeats_per_case
    }

    #[must_use]
    pub const fn expected_repeat_records(self) -> u32 {
        self.expected_repeat_records
    }

    #[must_use]
    pub const fn expected_summary_records(self) -> u16 {
        self.expected_summary_records
    }
}

/// Untrusted integer packet counters for one traffic direction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectionPacketCounters {
    pub offered_packets: u64,
    pub received_packets: u64,
    pub accepted_packets: u64,
}

impl DirectionPacketCounters {
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.offered_packets == 0 && self.received_packets == 0 && self.accepted_packets == 0
    }
}

/// Untrusted integer observations from one measurement interval.
///
/// All fields are validated before a [`VerifiedRepeat`] can be produced.
#[derive(Clone, Debug, PartialEq)]
pub struct RawRepeatCounters {
    pub outbound: DirectionPacketCounters,
    pub inbound: DirectionPacketCounters,
    pub duplicate_packets: u64,
    pub unexpected_packets: u64,
    pub oracle_failures: u64,
    pub latency_samples: u64,
    pub p50_latency_ns: u64,
    pub p99_latency_ns: u64,
    pub outbound_imix: Option<ImixAcceptedFrames>,
    pub inbound_imix: Option<ImixAcceptedFrames>,
    pub frame_health_before: FrameHealth,
    pub frame_health_after: FrameHealth,
    pub artifact_hashes: Vec<ArtifactHash>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedRepeat {
    protocol: HardwareMeasurementProtocol,
    ordinal: u16,
    record: HardwareRepeat,
}

impl VerifiedRepeat {
    pub fn from_raw(
        binding: BoundHardwareMeasurement<'_>,
        ordinal: u16,
        repeat_index: u16,
        raw: RawRepeatCounters,
    ) -> Result<Self, MeasurementProtocolError> {
        let planned = binding.case(ordinal)?;
        let repeat_count = binding.protocol.timing.repeat_count;
        if repeat_index == 0 || repeat_index > repeat_count {
            return Err(MeasurementProtocolError::RepeatIndexOutOfRange {
                actual: repeat_index,
                maximum: repeat_count,
            });
        }
        if raw.duplicate_packets != 0 {
            return Err(MeasurementProtocolError::DuplicatePackets(
                raw.duplicate_packets,
            ));
        }
        if raw.unexpected_packets != 0 {
            return Err(MeasurementProtocolError::UnexpectedPackets(
                raw.unexpected_packets,
            ));
        }
        if raw.oracle_failures != 0 {
            return Err(MeasurementProtocolError::OracleFailures(
                raw.oracle_failures,
            ));
        }

        validate_direction(
            DirectionProfile::Outbound,
            planned.case.direction,
            raw.outbound,
        )?;
        validate_direction(
            DirectionProfile::Inbound,
            planned.case.direction,
            raw.inbound,
        )?;

        let offered_packets = checked_direction_sum(
            raw.outbound.offered_packets,
            raw.inbound.offered_packets,
            "offered_packets",
        )?;
        let received_packets = checked_direction_sum(
            raw.outbound.received_packets,
            raw.inbound.received_packets,
            "received_packets",
        )?;
        let accepted_packets = checked_direction_sum(
            raw.outbound.accepted_packets,
            raw.inbound.accepted_packets,
            "accepted_packets",
        )?;

        validate_latency(
            binding.protocol.latency,
            accepted_packets,
            raw.latency_samples,
            raw.p50_latency_ns,
            raw.p99_latency_ns,
        )?;
        let imix_accepted_frames = validate_imix(
            &planned.case,
            raw.outbound,
            raw.inbound,
            raw.outbound_imix,
            raw.inbound_imix,
        )?;
        let duration_seconds = binding.protocol.timing.duration_seconds;
        let loss_packets = offered_packets
            .checked_sub(received_packets)
            .ok_or(MeasurementProtocolError::CounterOverflow("loss_packets"))?;
        let l1_bit_count =
            l1_bit_count(planned.case.frame, accepted_packets, imix_accepted_frames)?;
        let record = HardwareRepeat {
            case_id: planned.case_id.clone(),
            case: planned.case.clone(),
            repeat_index,
            warmup_seconds: binding.protocol.timing.warmup_seconds,
            duration_seconds,
            offered_packets,
            received_packets,
            accepted_packets,
            loss_packets,
            accepted_pps: accepted_packets as f64 / f64::from(duration_seconds),
            l1_gbps: l1_bit_count as f64 / (f64::from(duration_seconds) * 1_000_000_000.0),
            loss_ratio: if offered_packets == 0 {
                0.0
            } else {
                loss_packets as f64 / offered_packets as f64
            },
            latency_samples: raw.latency_samples,
            p50_latency_ns: raw.p50_latency_ns as f64,
            p99_latency_ns: raw.p99_latency_ns as f64,
            imix_accepted_frames,
            frame_health_before: raw.frame_health_before,
            frame_health_after: raw.frame_health_after,
            artifact_hashes: raw.artifact_hashes,
        };
        record.validate()?;
        Ok(Self {
            protocol: binding.protocol,
            ordinal,
            record,
        })
    }

    #[must_use]
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    #[must_use]
    pub const fn protocol(&self) -> HardwareMeasurementProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn record(&self) -> &HardwareRepeat {
        &self.record
    }

    #[must_use]
    pub fn into_record(self) -> HardwareRepeat {
        self.record
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedSummary {
    protocol: HardwareMeasurementProtocol,
    ordinal: u16,
    record: HardwareSummary,
}

impl VerifiedSummary {
    pub fn derive(
        binding: BoundHardwareMeasurement<'_>,
        ordinal: u16,
        repeats: &[VerifiedRepeat],
        artifact_hashes: Vec<ArtifactHash>,
    ) -> Result<Self, MeasurementProtocolError> {
        let record = derive_summary_record(binding, ordinal, repeats, artifact_hashes)?;
        Ok(Self {
            protocol: binding.protocol,
            ordinal,
            record,
        })
    }

    #[must_use]
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    #[must_use]
    pub const fn protocol(&self) -> HardwareMeasurementProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn record(&self) -> &HardwareSummary {
        &self.record
    }

    #[must_use]
    pub fn into_record(self) -> HardwareSummary {
        self.record
    }
}

pub fn validate_complete_measurement(
    binding: BoundHardwareMeasurement<'_>,
    repeats: &[VerifiedRepeat],
    summaries: &[VerifiedSummary],
) -> Result<CompletenessMetadata, MeasurementProtocolError> {
    let metadata = binding.completeness();
    let expected_repeats = usize::try_from(metadata.expected_repeat_records)
        .map_err(|_| MeasurementProtocolError::ArithmeticOverflow("expected repeat records"))?;
    if repeats.len() != expected_repeats {
        return Err(MeasurementProtocolError::RepeatSetLength {
            expected: expected_repeats,
            actual: repeats.len(),
        });
    }
    let expected_summaries = usize::from(metadata.expected_summary_records);
    if summaries.len() != expected_summaries {
        return Err(MeasurementProtocolError::SummarySetLength {
            expected: expected_summaries,
            actual: summaries.len(),
        });
    }

    let mut repeat_keys = BTreeSet::new();
    for repeat in repeats {
        validate_repeat_binding(binding, repeat)?;
        let key = (repeat.ordinal, repeat.record.repeat_index);
        if !repeat_keys.insert(key) {
            return Err(MeasurementProtocolError::DuplicateRepeat {
                ordinal: key.0,
                repeat_index: key.1,
            });
        }
    }
    for ordinal in 0..metadata.case_count {
        for repeat_index in 1..=metadata.repeats_per_case {
            if !repeat_keys.contains(&(ordinal, repeat_index)) {
                return Err(MeasurementProtocolError::MissingRepeat {
                    ordinal,
                    repeat_index,
                });
            }
        }
    }

    let mut summary_ordinals = BTreeSet::new();
    for summary in summaries {
        validate_summary_binding(binding, summary)?;
        if !summary_ordinals.insert(summary.ordinal) {
            return Err(MeasurementProtocolError::DuplicateSummary(summary.ordinal));
        }
    }
    for ordinal in 0..metadata.case_count {
        if !summary_ordinals.contains(&ordinal) {
            return Err(MeasurementProtocolError::MissingSummary(ordinal));
        }
        let supplied = summaries
            .iter()
            .find(|summary| summary.ordinal == ordinal)
            .ok_or(MeasurementProtocolError::MissingSummary(ordinal))?;
        let case_repeats = repeats
            .iter()
            .filter(|repeat| repeat.ordinal == ordinal)
            .cloned()
            .collect::<Vec<_>>();
        let expected = derive_summary_record(
            binding,
            ordinal,
            &case_repeats,
            supplied.record.artifact_hashes.clone(),
        )?;
        if expected != supplied.record {
            return Err(MeasurementProtocolError::SummaryDerivationMismatch(ordinal));
        }
    }
    Ok(metadata)
}

fn derive_summary_record(
    binding: BoundHardwareMeasurement<'_>,
    ordinal: u16,
    repeats: &[VerifiedRepeat],
    artifact_hashes: Vec<ArtifactHash>,
) -> Result<HardwareSummary, MeasurementProtocolError> {
    let planned = binding.case(ordinal)?;
    let expected_len = usize::from(binding.protocol.timing.repeat_count);
    if repeats.len() != expected_len {
        return Err(MeasurementProtocolError::RepeatSetLength {
            expected: expected_len,
            actual: repeats.len(),
        });
    }
    let mut indices = BTreeSet::new();
    for repeat in repeats {
        validate_repeat_binding(binding, repeat)?;
        if repeat.ordinal != ordinal {
            return Err(MeasurementProtocolError::RepeatBindingMismatch);
        }
        if !indices.insert(repeat.record.repeat_index) {
            return Err(MeasurementProtocolError::DuplicateRepeat {
                ordinal,
                repeat_index: repeat.record.repeat_index,
            });
        }
    }
    for repeat_index in 1..=binding.protocol.timing.repeat_count {
        if !indices.contains(&repeat_index) {
            return Err(MeasurementProtocolError::MissingRepeat {
                ordinal,
                repeat_index,
            });
        }
    }

    let accepted_pps_median = median_metric(repeats, |record| record.accepted_pps)?;
    let l1_gbps_median = median_metric(repeats, |record| record.l1_gbps)?;
    let loss_ratio_worst = worst_metric(repeats, |record| record.loss_ratio)?;
    let p50_latency_ns_worst = worst_metric(repeats, |record| record.p50_latency_ns)?;
    let p99_latency_ns_worst = worst_metric(repeats, |record| record.p99_latency_ns)?;
    let record = HardwareSummary {
        case_id: planned.case_id.clone(),
        case: planned.case.clone(),
        repeat_count: binding.protocol.timing.repeat_count,
        accepted_pps_median,
        l1_gbps_median,
        loss_ratio_worst,
        p50_latency_ns_worst,
        p99_latency_ns_worst,
        artifact_hashes,
    };
    record.validate()?;
    Ok(record)
}

fn validate_repeat_binding(
    binding: BoundHardwareMeasurement<'_>,
    repeat: &VerifiedRepeat,
) -> Result<(), MeasurementProtocolError> {
    if repeat.protocol != binding.protocol {
        return Err(MeasurementProtocolError::RepeatBindingMismatch);
    }
    let planned = binding.case(repeat.ordinal)?;
    if repeat.record.case_id != planned.case_id
        || repeat.record.case != planned.case
        || repeat.record.warmup_seconds != binding.protocol.timing.warmup_seconds
        || repeat.record.duration_seconds != binding.protocol.timing.duration_seconds
        || repeat.record.repeat_index == 0
        || repeat.record.repeat_index > binding.protocol.timing.repeat_count
    {
        return Err(MeasurementProtocolError::RepeatBindingMismatch);
    }
    repeat.record.validate()?;
    Ok(())
}

fn validate_summary_binding(
    binding: BoundHardwareMeasurement<'_>,
    summary: &VerifiedSummary,
) -> Result<(), MeasurementProtocolError> {
    if summary.protocol != binding.protocol {
        return Err(MeasurementProtocolError::SummaryBindingMismatch);
    }
    let planned = binding.case(summary.ordinal)?;
    if summary.record.case_id != planned.case_id
        || summary.record.case != planned.case
        || summary.record.repeat_count != binding.protocol.timing.repeat_count
    {
        return Err(MeasurementProtocolError::SummaryBindingMismatch);
    }
    summary.record.validate()?;
    Ok(())
}

fn median_metric(
    repeats: &[VerifiedRepeat],
    metric: impl Fn(&HardwareRepeat) -> f64,
) -> Result<f64, MeasurementProtocolError> {
    let mut values = repeats
        .iter()
        .map(|repeat| metric(&repeat.record))
        .collect::<Vec<_>>();
    if values.is_empty() || values.len().is_multiple_of(2) {
        return Err(MeasurementProtocolError::RepeatCountMustBeOdd);
    }
    values.sort_by(f64::total_cmp);
    Ok(values[values.len() / 2])
}

fn worst_metric(
    repeats: &[VerifiedRepeat],
    metric: impl Fn(&HardwareRepeat) -> f64,
) -> Result<f64, MeasurementProtocolError> {
    repeats
        .iter()
        .map(|repeat| metric(&repeat.record))
        .max_by(f64::total_cmp)
        .ok_or(MeasurementProtocolError::RepeatSetLength {
            expected: 1,
            actual: 0,
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleScope {
    Run,
    Case { ordinal: u16 },
    Repeat { ordinal: u16, repeat_index: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasurementLifecycleCode {
    phase: LifecyclePhase,
    scope: LifecycleScope,
}

impl MeasurementLifecycleCode {
    #[must_use]
    pub const fn preflight() -> Self {
        Self {
            phase: LifecyclePhase::Preflight,
            scope: LifecycleScope::Run,
        }
    }

    #[must_use]
    pub const fn setup() -> Self {
        Self {
            phase: LifecyclePhase::Setup,
            scope: LifecycleScope::Run,
        }
    }

    pub fn case_warmup(
        binding: BoundHardwareMeasurement<'_>,
        ordinal: u16,
    ) -> Result<Self, MeasurementProtocolError> {
        binding.case(ordinal)?;
        Ok(Self {
            phase: LifecyclePhase::Warmup,
            scope: LifecycleScope::Case { ordinal },
        })
    }

    pub fn case_measurement(
        binding: BoundHardwareMeasurement<'_>,
        ordinal: u16,
        repeat_index: u16,
    ) -> Result<Self, MeasurementProtocolError> {
        binding.case(ordinal)?;
        if repeat_index == 0 || repeat_index > binding.protocol.timing.repeat_count {
            return Err(MeasurementProtocolError::RepeatIndexOutOfRange {
                actual: repeat_index,
                maximum: binding.protocol.timing.repeat_count,
            });
        }
        Ok(Self {
            phase: LifecyclePhase::Measurement,
            scope: LifecycleScope::Repeat {
                ordinal,
                repeat_index,
            },
        })
    }

    pub fn case_drain(
        binding: BoundHardwareMeasurement<'_>,
        ordinal: u16,
    ) -> Result<Self, MeasurementProtocolError> {
        binding.case(ordinal)?;
        Ok(Self {
            phase: LifecyclePhase::Drain,
            scope: LifecycleScope::Case { ordinal },
        })
    }

    #[must_use]
    pub const fn cleanup() -> Self {
        Self {
            phase: LifecyclePhase::Cleanup,
            scope: LifecycleScope::Run,
        }
    }

    #[must_use]
    pub const fn phase(self) -> LifecyclePhase {
        self.phase
    }

    #[must_use]
    pub fn label(self) -> String {
        match (self.phase, self.scope) {
            (LifecyclePhase::Preflight, LifecycleScope::Run) => "run.preflight".to_owned(),
            (LifecyclePhase::Setup, LifecycleScope::Run) => "run.setup".to_owned(),
            (LifecyclePhase::Cleanup, LifecycleScope::Run) => "run.cleanup".to_owned(),
            (LifecyclePhase::Warmup, LifecycleScope::Case { ordinal }) => {
                format!("case.{ordinal:03}.warmup")
            }
            (LifecyclePhase::Drain, LifecycleScope::Case { ordinal }) => {
                format!("case.{ordinal:03}.drain")
            }
            (
                LifecyclePhase::Measurement,
                LifecycleScope::Repeat {
                    ordinal,
                    repeat_index,
                },
            ) => format!("case.{ordinal:03}.repeat.{repeat_index:03}.measurement"),
            _ => "invalid.lifecycle.code".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MeasurementLifecycleEvent {
    code: MeasurementLifecycleCode,
    record: LifecycleRecord,
}

impl MeasurementLifecycleEvent {
    pub fn new(
        sequence: u64,
        monotonic_ms: u64,
        code: MeasurementLifecycleCode,
        outcome: LifecycleOutcome,
        frame_health: FrameHealth,
        artifact_hashes: Vec<ArtifactHash>,
    ) -> Result<Self, MeasurementProtocolError> {
        if sequence == 0 {
            return Err(MeasurementProtocolError::LifecycleSequence {
                expected: 1,
                actual: 0,
            });
        }
        let record = LifecycleRecord {
            sequence,
            monotonic_ms,
            phase: code.phase,
            outcome,
            code: code.label(),
            frame_health,
            artifact_hashes,
        };
        record.validate()?;
        Ok(Self { code, record })
    }

    #[must_use]
    pub const fn code(&self) -> MeasurementLifecycleCode {
        self.code
    }

    #[must_use]
    pub const fn record(&self) -> &LifecycleRecord {
        &self.record
    }

    #[must_use]
    pub fn into_record(self) -> LifecycleRecord {
        self.record
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeasurementRunOutcome {
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub struct LifecycleSequenceValidator<'a> {
    binding: BoundHardwareMeasurement<'a>,
    next_sequence: u64,
    last_monotonic_ms: Option<u64>,
    expected_code: Option<MeasurementLifecycleCode>,
    open_code: Option<MeasurementLifecycleCode>,
    open_started_ms: Option<u64>,
    run_started_ms: Option<u64>,
    case_started_ms: Option<u64>,
    aborting: bool,
    failed: bool,
    finished: bool,
}

impl<'a> LifecycleSequenceValidator<'a> {
    #[must_use]
    pub const fn new(binding: BoundHardwareMeasurement<'a>) -> Self {
        Self {
            binding,
            next_sequence: 1,
            last_monotonic_ms: None,
            expected_code: Some(MeasurementLifecycleCode::preflight()),
            open_code: None,
            open_started_ms: None,
            run_started_ms: None,
            case_started_ms: None,
            aborting: false,
            failed: false,
            finished: false,
        }
    }

    pub fn push(
        &mut self,
        event: &MeasurementLifecycleEvent,
    ) -> Result<(), MeasurementProtocolError> {
        let mut candidate = *self;
        candidate.push_inner(event)?;
        *self = candidate;
        Ok(())
    }

    fn push_inner(
        &mut self,
        event: &MeasurementLifecycleEvent,
    ) -> Result<(), MeasurementProtocolError> {
        if self.finished {
            return Err(MeasurementProtocolError::LifecycleFinished);
        }
        if event.record.sequence != self.next_sequence {
            return Err(MeasurementProtocolError::LifecycleSequence {
                expected: self.next_sequence,
                actual: event.record.sequence,
            });
        }
        if let Some(previous) = self.last_monotonic_ms {
            if event.record.monotonic_ms < previous {
                return Err(MeasurementProtocolError::LifecycleTimeRegression {
                    previous,
                    actual: event.record.monotonic_ms,
                });
            }
        }
        self.next_sequence = self.next_sequence.checked_add(1).ok_or(
            MeasurementProtocolError::ArithmeticOverflow("lifecycle sequence"),
        )?;
        self.last_monotonic_ms = Some(event.record.monotonic_ms);

        match self.open_code {
            None => {
                if Some(event.code) != self.expected_code {
                    return Err(MeasurementProtocolError::LifecycleUnexpectedCode);
                }
                if event.record.outcome != LifecycleOutcome::Started {
                    return Err(MeasurementProtocolError::LifecycleUnexpectedOutcome);
                }
                self.validate_deadlines(event.record.monotonic_ms, event.code)?;
                self.open_code = Some(event.code);
                self.open_started_ms = Some(event.record.monotonic_ms);
                if event.code == MeasurementLifecycleCode::preflight() {
                    self.run_started_ms = Some(event.record.monotonic_ms);
                }
                if event.code.phase == LifecyclePhase::Warmup {
                    self.case_started_ms = Some(event.record.monotonic_ms);
                }
            }
            Some(open) => {
                if event.code != open {
                    return Err(MeasurementProtocolError::LifecycleUnexpectedCode);
                }
                if event.record.outcome == LifecycleOutcome::Started {
                    return Err(MeasurementProtocolError::LifecycleUnexpectedOutcome);
                }
                self.validate_deadlines(event.record.monotonic_ms, event.code)?;
                self.open_code = None;
                self.open_started_ms = None;
                if event.record.outcome == LifecycleOutcome::Failed {
                    self.failed = true;
                    self.aborting = true;
                }
                self.advance(open)?;
                if open.phase == LifecyclePhase::Drain {
                    self.case_started_ms = None;
                }
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<MeasurementRunOutcome, MeasurementProtocolError> {
        if self.open_code.is_some() {
            return Err(MeasurementProtocolError::LifecycleOpenEvent);
        }
        if !self.finished {
            return Err(MeasurementProtocolError::LifecycleIncomplete);
        }
        Ok(if self.failed {
            MeasurementRunOutcome::Failed
        } else {
            MeasurementRunOutcome::Completed
        })
    }

    fn advance(
        &mut self,
        completed: MeasurementLifecycleCode,
    ) -> Result<(), MeasurementProtocolError> {
        if completed == MeasurementLifecycleCode::cleanup() {
            self.expected_code = None;
            self.finished = true;
            return Ok(());
        }
        if self.aborting {
            self.expected_code = match (completed.phase, completed.scope) {
                (
                    LifecyclePhase::Warmup | LifecyclePhase::Measurement,
                    LifecycleScope::Case { ordinal }
                    | LifecycleScope::Repeat {
                        ordinal,
                        repeat_index: _,
                    },
                ) => Some(MeasurementLifecycleCode::case_drain(self.binding, ordinal)?),
                _ => Some(MeasurementLifecycleCode::cleanup()),
            };
            return Ok(());
        }
        self.expected_code = Some(match (completed.phase, completed.scope) {
            (LifecyclePhase::Preflight, LifecycleScope::Run) => MeasurementLifecycleCode::setup(),
            (LifecyclePhase::Setup, LifecycleScope::Run) => {
                MeasurementLifecycleCode::case_warmup(self.binding, 0)?
            }
            (LifecyclePhase::Warmup, LifecycleScope::Case { ordinal }) => {
                MeasurementLifecycleCode::case_measurement(self.binding, ordinal, 1)?
            }
            (
                LifecyclePhase::Measurement,
                LifecycleScope::Repeat {
                    ordinal,
                    repeat_index,
                },
            ) => {
                if repeat_index < self.binding.protocol.timing.repeat_count {
                    MeasurementLifecycleCode::case_measurement(
                        self.binding,
                        ordinal,
                        repeat_index + 1,
                    )?
                } else {
                    MeasurementLifecycleCode::case_drain(self.binding, ordinal)?
                }
            }
            (LifecyclePhase::Drain, LifecycleScope::Case { ordinal }) => {
                let next_ordinal =
                    ordinal
                        .checked_add(1)
                        .ok_or(MeasurementProtocolError::ArithmeticOverflow(
                            "lifecycle case ordinal",
                        ))?;
                if usize::from(next_ordinal) < HARDWARE_TOTAL_CASE_COUNT {
                    MeasurementLifecycleCode::case_warmup(self.binding, next_ordinal)?
                } else {
                    MeasurementLifecycleCode::cleanup()
                }
            }
            _ => return Err(MeasurementProtocolError::LifecycleUnexpectedCode),
        });
        Ok(())
    }

    fn validate_deadlines(
        self,
        monotonic_ms: u64,
        code: MeasurementLifecycleCode,
    ) -> Result<(), MeasurementProtocolError> {
        let timing = self.binding.protocol.timing;
        if let Some(started_ms) = self.run_started_ms {
            validate_elapsed_timeout("run", started_ms, monotonic_ms, timing.run_timeout_ms)?;
        }
        if let Some(started_ms) = self.case_started_ms {
            validate_elapsed_timeout("case", started_ms, monotonic_ms, timing.case_timeout_ms)?;
        }
        if code.phase == LifecyclePhase::Drain {
            if let Some(started_ms) = self.open_started_ms {
                validate_elapsed_timeout(
                    "drain",
                    started_ms,
                    monotonic_ms,
                    timing.drain_timeout_ms,
                )?;
            }
        }
        Ok(())
    }
}

pub fn validate_lifecycle_sequence(
    binding: BoundHardwareMeasurement<'_>,
    events: &[MeasurementLifecycleEvent],
) -> Result<MeasurementRunOutcome, MeasurementProtocolError> {
    let mut validator = LifecycleSequenceValidator::new(binding);
    for event in events {
        validator.push(event)?;
    }
    validator.finish()
}

fn validate_elapsed_timeout(
    scope: &'static str,
    started_ms: u64,
    monotonic_ms: u64,
    limit_ms: u64,
) -> Result<(), MeasurementProtocolError> {
    let elapsed_ms = monotonic_ms.checked_sub(started_ms).ok_or(
        MeasurementProtocolError::LifecycleTimeRegression {
            previous: started_ms,
            actual: monotonic_ms,
        },
    )?;
    if elapsed_ms > limit_ms {
        return Err(MeasurementProtocolError::LifecycleTimeout {
            scope,
            limit_ms,
            elapsed_ms,
        });
    }
    Ok(())
}

fn validate_direction(
    actual: DirectionProfile,
    planned: DirectionProfile,
    counters: DirectionPacketCounters,
) -> Result<(), MeasurementProtocolError> {
    let active = planned == actual || planned == DirectionProfile::Bidirectional;
    if !active {
        if counters.is_zero() {
            return Ok(());
        }
        return Err(MeasurementProtocolError::InactiveDirection(actual));
    }
    if counters.offered_packets == 0 {
        return Err(MeasurementProtocolError::EmptyDirection(actual));
    }
    if counters.received_packets > counters.offered_packets {
        return Err(MeasurementProtocolError::ReceivedExceedsOffered(actual));
    }
    if counters.accepted_packets != counters.received_packets {
        return Err(MeasurementProtocolError::AcceptedDoesNotMatchReceived(
            actual,
        ));
    }
    Ok(())
}

fn checked_direction_sum(
    outbound: u64,
    inbound: u64,
    field: &'static str,
) -> Result<u64, MeasurementProtocolError> {
    outbound
        .checked_add(inbound)
        .ok_or(MeasurementProtocolError::CounterOverflow(field))
}

fn validate_latency(
    profile: LatencyProfile,
    accepted_packets: u64,
    latency_samples: u64,
    p50_latency_ns: u64,
    p99_latency_ns: u64,
) -> Result<(), MeasurementProtocolError> {
    match profile.mode {
        LatencyMode::Disabled => {
            if latency_samples != 0 || p50_latency_ns != 0 || p99_latency_ns != 0 {
                return Err(MeasurementProtocolError::InvalidLatency(
                    "disabled profile has observations",
                ));
            }
        }
        LatencyMode::RoundTrip | LatencyMode::OneWaySynchronized => {
            let sample_every = u64::from(profile.sample_every_packets);
            let expected_samples = accepted_packets.div_ceil(sample_every);
            if latency_samples != expected_samples {
                return Err(MeasurementProtocolError::InvalidLatency(
                    "sample count does not match sampling profile",
                ));
            }
            if latency_samples == 0 {
                if p50_latency_ns != 0 || p99_latency_ns != 0 {
                    return Err(MeasurementProtocolError::InvalidLatency(
                        "empty sample set has percentiles",
                    ));
                }
            } else if p50_latency_ns == 0 || p99_latency_ns == 0 || p99_latency_ns < p50_latency_ns
            {
                return Err(MeasurementProtocolError::InvalidLatency(
                    "percentiles are not ordered positive integers",
                ));
            }
        }
    }
    Ok(())
}

fn validate_imix(
    case: &HardwareCase,
    outbound: DirectionPacketCounters,
    inbound: DirectionPacketCounters,
    outbound_imix: Option<ImixAcceptedFrames>,
    inbound_imix: Option<ImixAcceptedFrames>,
) -> Result<Option<ImixAcceptedFrames>, MeasurementProtocolError> {
    if case.frame != HardwareFrame::RusterImixV1 {
        if outbound_imix.is_some() {
            return Err(MeasurementProtocolError::UnexpectedImixEvidence(
                DirectionProfile::Outbound,
            ));
        }
        if inbound_imix.is_some() {
            return Err(MeasurementProtocolError::UnexpectedImixEvidence(
                DirectionProfile::Inbound,
            ));
        }
        return Ok(None);
    }
    let outbound_active = matches!(
        case.direction,
        DirectionProfile::Outbound | DirectionProfile::Bidirectional
    );
    let inbound_active = matches!(
        case.direction,
        DirectionProfile::Inbound | DirectionProfile::Bidirectional
    );
    let outbound_evidence = validate_direction_imix(
        DirectionProfile::Outbound,
        outbound_active,
        outbound.accepted_packets,
        outbound_imix,
    )?;
    let inbound_evidence = validate_direction_imix(
        DirectionProfile::Inbound,
        inbound_active,
        inbound.accepted_packets,
        inbound_imix,
    )?;
    Ok(Some(ImixAcceptedFrames {
        eth64_packets: outbound_evidence
            .eth64_packets
            .checked_add(inbound_evidence.eth64_packets)
            .ok_or(MeasurementProtocolError::CounterOverflow(
                "IMIX eth64 packets",
            ))?,
        eth512_packets: outbound_evidence
            .eth512_packets
            .checked_add(inbound_evidence.eth512_packets)
            .ok_or(MeasurementProtocolError::CounterOverflow(
                "IMIX eth512 packets",
            ))?,
        ip_mtu1500_packets: outbound_evidence
            .ip_mtu1500_packets
            .checked_add(inbound_evidence.ip_mtu1500_packets)
            .ok_or(MeasurementProtocolError::CounterOverflow(
                "IMIX ip-mtu1500 packets",
            ))?,
    }))
}

fn validate_direction_imix(
    direction: DirectionProfile,
    active: bool,
    accepted_packets: u64,
    evidence: Option<ImixAcceptedFrames>,
) -> Result<ImixAcceptedFrames, MeasurementProtocolError> {
    if !active {
        if evidence.is_some() {
            return Err(MeasurementProtocolError::UnexpectedImixEvidence(direction));
        }
        return Ok(ImixAcceptedFrames {
            eth64_packets: 0,
            eth512_packets: 0,
            ip_mtu1500_packets: 0,
        });
    }
    let evidence = evidence.ok_or(MeasurementProtocolError::MissingImixEvidence(direction))?;
    let total = evidence
        .eth64_packets
        .checked_add(evidence.eth512_packets)
        .and_then(|value| value.checked_add(evidence.ip_mtu1500_packets))
        .ok_or(MeasurementProtocolError::CounterOverflow(
            "direction IMIX packets",
        ))?;
    if total != accepted_packets {
        return Err(MeasurementProtocolError::InvalidImixEvidence(direction));
    }
    Ok(evidence)
}

fn l1_bit_count(
    frame: HardwareFrame,
    accepted_packets: u64,
    imix: Option<ImixAcceptedFrames>,
) -> Result<u128, MeasurementProtocolError> {
    match (frame, imix) {
        (HardwareFrame::RusterImixV1, Some(evidence)) => {
            let bytes = u128::from(evidence.eth64_packets)
                .checked_mul(84)
                .and_then(|value| {
                    u128::from(evidence.eth512_packets)
                        .checked_mul(532)
                        .and_then(|part| value.checked_add(part))
                })
                .and_then(|value| {
                    u128::from(evidence.ip_mtu1500_packets)
                        .checked_mul(1_538)
                        .and_then(|part| value.checked_add(part))
                })
                .ok_or(MeasurementProtocolError::ArithmeticOverflow(
                    "IMIX L1 bytes",
                ))?;
            bytes
                .checked_mul(8)
                .ok_or(MeasurementProtocolError::ArithmeticOverflow("IMIX L1 bits"))
        }
        (HardwareFrame::RusterImixV1, None) => Err(MeasurementProtocolError::MissingImixEvidence(
            DirectionProfile::Bidirectional,
        )),
        (frame, None) => u128::from(accepted_packets)
            .checked_mul(u128::from(frame.l1_bytes_with_preamble_ifg().ok_or(
                MeasurementProtocolError::ArithmeticOverflow("fixed frame L1 bytes"),
            )?))
            .and_then(|value| value.checked_mul(8))
            .ok_or(MeasurementProtocolError::ArithmeticOverflow(
                "fixed frame L1 bits",
            )),
        (_, Some(_)) => Err(MeasurementProtocolError::UnexpectedImixEvidence(
            DirectionProfile::Bidirectional,
        )),
    }
}

fn hardware_plan_fingerprint(plan: &HardwarePlan) -> u64 {
    let mut fingerprint = 0xcbf2_9ce4_8422_2325_u64;
    for byte in plan.version.to_be_bytes().into_iter().chain(*b"\n") {
        fingerprint = fnv1a_byte(fingerprint, byte);
    }
    for frame in RUSTER_IMIX_V1_CYCLE {
        for byte in frame.label().bytes().chain(*b"\n") {
            fingerprint = fnv1a_byte(fingerprint, byte);
        }
    }
    for planned in &plan.cases {
        for byte in planned
            .ordinal
            .to_be_bytes()
            .into_iter()
            .chain(planned.seed.to_be_bytes())
            .chain([planned.class as u8])
            .chain(planned.case_id.bytes())
            .chain(*b"\n")
        {
            fingerprint = fnv1a_byte(fingerprint, byte);
        }
    }
    fingerprint
}

const fn fnv1a_byte(hash: u64, byte: u8) -> u64 {
    (hash ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3)
}

fn validate_sample_every(value: u32) -> Result<(), MeasurementProtocolError> {
    if value == 0 || value > MAX_LATENCY_SAMPLE_EVERY_PACKETS {
        Err(MeasurementProtocolError::InvalidLatencyProfile(
            "sample interval is out of range",
        ))
    } else {
        Ok(())
    }
}

fn parse_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.checked_mul(2)? {
        return None;
    }
    let mut output = [0; N];
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < N {
        let high = lower_hex_nibble(bytes[index * 2])?;
        let low = lower_hex_nibble(bytes[index * 2 + 1])?;
        output[index] = (high << 4) | low;
        index += 1;
    }
    Some(output)
}

const fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware_plan_v1;

    const GIT_A: &str = "0123456789abcdef0123456789abcdef01234567";
    const GIT_B: &str = "89abcdef0123456789abcdef0123456789abcdef";
    const SHA_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SHA_B: &str = "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::parse("test", value).unwrap()
    }

    fn protocol(repeat_count: u16, latency: LatencyProfile) -> HardwareMeasurementProtocol {
        let timing = MeasurementTiming::new(1, 1, repeat_count, 6_000, 1_000, 6_000 * 237).unwrap();
        HardwareMeasurementProtocol::new_v1(
            GitCommitId::parse("spec", GIT_A).unwrap(),
            digest(SHA_A),
            GitCommitId::parse("source", GIT_B).unwrap(),
            timing,
            GeneratorProfile::new(
                MeasurementProfileId::parse("generator-v1").unwrap(),
                digest(SHA_B),
            ),
            latency,
        )
    }

    fn no_latency() -> LatencyProfile {
        LatencyProfile::disabled(digest(SHA_A))
    }

    fn healthy_frames() -> FrameHealth {
        FrameHealth {
            total: 16,
            free: 16,
            fill: 0,
            rx_owned: 0,
            core_borrowed: 0,
            tx_owned: 0,
            completion: 0,
            invalid_descriptors: 0,
            double_owned: 0,
        }
    }

    fn direction_counters(active: bool, repeat_index: u16) -> DirectionPacketCounters {
        if active {
            let accepted_packets = 96 + u64::from(repeat_index) * 12;
            DirectionPacketCounters {
                offered_packets: accepted_packets + 12,
                received_packets: accepted_packets,
                accepted_packets,
            }
        } else {
            DirectionPacketCounters::default()
        }
    }

    fn imix_evidence(counters: DirectionPacketCounters) -> ImixAcceptedFrames {
        let cycles = counters.accepted_packets / 12;
        ImixAcceptedFrames {
            eth64_packets: cycles * 7,
            eth512_packets: cycles * 4,
            ip_mtu1500_packets: cycles,
        }
    }

    fn raw_for_case(case: &HardwareCase, repeat_index: u16) -> RawRepeatCounters {
        let outbound_active = matches!(
            case.direction,
            DirectionProfile::Outbound | DirectionProfile::Bidirectional
        );
        let inbound_active = matches!(
            case.direction,
            DirectionProfile::Inbound | DirectionProfile::Bidirectional
        );
        let outbound = direction_counters(outbound_active, repeat_index);
        let inbound = direction_counters(inbound_active, repeat_index);
        RawRepeatCounters {
            outbound,
            inbound,
            duplicate_packets: 0,
            unexpected_packets: 0,
            oracle_failures: 0,
            latency_samples: 0,
            p50_latency_ns: 0,
            p99_latency_ns: 0,
            outbound_imix: (case.frame == HardwareFrame::RusterImixV1 && outbound_active)
                .then(|| imix_evidence(outbound)),
            inbound_imix: (case.frame == HardwareFrame::RusterImixV1 && inbound_active)
                .then(|| imix_evidence(inbound)),
            frame_health_before: healthy_frames(),
            frame_health_after: healthy_frames(),
            artifact_hashes: Vec::new(),
        }
    }

    fn verified_repeats(
        binding: BoundHardwareMeasurement<'_>,
        ordinal: u16,
    ) -> Vec<VerifiedRepeat> {
        let case = &binding.case(ordinal).unwrap().case;
        (1..=binding.protocol().timing().repeat_count())
            .map(|repeat_index| {
                VerifiedRepeat::from_raw(
                    binding,
                    ordinal,
                    repeat_index,
                    raw_for_case(case, repeat_index),
                )
                .unwrap()
            })
            .collect()
    }

    fn lifecycle_event(
        sequence: u64,
        code: MeasurementLifecycleCode,
        outcome: LifecycleOutcome,
    ) -> MeasurementLifecycleEvent {
        lifecycle_event_at(sequence, sequence * 10, code, outcome)
    }

    fn lifecycle_event_at(
        sequence: u64,
        monotonic_ms: u64,
        code: MeasurementLifecycleCode,
        outcome: LifecycleOutcome,
    ) -> MeasurementLifecycleEvent {
        MeasurementLifecycleEvent::new(
            sequence,
            monotonic_ms,
            code,
            outcome,
            healthy_frames(),
            Vec::new(),
        )
        .unwrap()
    }

    fn push_pair(
        events: &mut Vec<MeasurementLifecycleEvent>,
        next_sequence: &mut u64,
        code: MeasurementLifecycleCode,
        terminal: LifecycleOutcome,
    ) {
        events.push(lifecycle_event(
            *next_sequence,
            code,
            LifecycleOutcome::Started,
        ));
        *next_sequence += 1;
        events.push(lifecycle_event(*next_sequence, code, terminal));
        *next_sequence += 1;
    }

    #[test]
    fn hardware_measurement_protocol_binds_exact_frozen_plan_and_completeness() {
        let plan = hardware_plan_v1().unwrap();
        let protocol = protocol(3, no_latency());
        let binding = protocol.bind(&plan).unwrap();
        let completeness = binding.completeness();

        assert_eq!(protocol.version(), HARDWARE_MEASUREMENT_PROTOCOL_VERSION);
        assert_eq!(protocol.plan_version(), HARDWARE_PLAN_VERSION);
        assert_eq!(protocol.plan_fingerprint(), HARDWARE_PLAN_FINGERPRINT_V1);
        assert_eq!(protocol.generator().id().label(), "generator-v1");
        assert_eq!(protocol.spec_git_sha().as_bytes()[0], 0x01);
        assert_eq!(protocol.spec_sha256().as_bytes()[0], 0x01);
        assert_eq!(protocol.source_git_sha().as_bytes()[0], 0x89);
        assert_eq!(completeness.case_count(), 237);
        assert_eq!(completeness.repeats_per_case(), 3);
        assert_eq!(completeness.expected_repeat_records(), 711);
        assert_eq!(completeness.expected_summary_records(), 237);

        let mut drifted = plan.clone();
        drifted.cases[0].seed ^= 1;
        assert!(matches!(
            protocol.bind(&drifted),
            Err(MeasurementProtocolError::InvalidPlan(_))
        ));
    }

    #[test]
    fn measurement_protocol_inputs_reject_noncanonical_and_unbounded_values() {
        assert!(GitCommitId::parse("git", "ABCDEF").is_err());
        assert!(GitCommitId::parse("git", &"a".repeat(39)).is_err());
        assert!(Sha256Digest::parse("sha", &"g".repeat(64)).is_err());
        assert!(MeasurementProfileId::parse("").is_err());
        assert!(MeasurementProfileId::parse("-leading").is_err());
        assert!(MeasurementProfileId::parse("has/slash").is_err());
        assert!(MeasurementProfileId::parse(&"a".repeat(65)).is_err());
        assert!(matches!(
            MeasurementTiming::new(0, 0, 1, 6_000, 1_000, 6_000 * 237),
            Err(MeasurementProtocolError::TimingOutOfRange(
                "duration_seconds"
            ))
        ));
        assert!(matches!(
            MeasurementTiming::new(1, 1, 2, 6_000, 1_000, 6_000 * 237),
            Err(MeasurementProtocolError::RepeatCountMustBeOdd)
        ));
        assert!(matches!(
            MeasurementTiming::new(1, 1, 3, 4_999, 1_000, 6_000 * 237),
            Err(MeasurementProtocolError::TimeoutTooShort("case_timeout_ms"))
        ));
        assert!(LatencyProfile::round_trip(0, digest(SHA_A)).is_err());
        assert!(
            LatencyProfile::round_trip(MAX_LATENCY_SAMPLE_EVERY_PACKETS + 1, digest(SHA_A))
                .is_err()
        );
    }

    #[test]
    fn raw_fixed_and_bidirectional_imix_counters_derive_exact_records() {
        let plan = hardware_plan_v1().unwrap();
        let binding = protocol(1, no_latency()).bind(&plan).unwrap();
        let fixed_ordinal = plan
            .cases
            .iter()
            .position(|planned| {
                planned.case.frame == HardwareFrame::Eth64
                    && planned.case.direction == DirectionProfile::Outbound
            })
            .unwrap() as u16;
        let fixed = VerifiedRepeat::from_raw(
            binding,
            fixed_ordinal,
            1,
            raw_for_case(&binding.case(fixed_ordinal).unwrap().case, 1),
        )
        .unwrap();
        assert_eq!(fixed.record().offered_packets, 120);
        assert_eq!(fixed.record().received_packets, 108);
        assert_eq!(fixed.record().accepted_packets, 108);
        assert_eq!(fixed.record().loss_packets, 12);
        assert_eq!(fixed.record().accepted_pps.to_bits(), 108_f64.to_bits());
        assert_eq!(
            fixed.record().l1_gbps.to_bits(),
            (108_f64 * 84.0 * 8.0 / 1_000_000_000.0).to_bits()
        );
        assert_eq!(fixed.record().loss_ratio.to_bits(), 0.1_f64.to_bits());

        let imix_ordinal = plan
            .cases
            .iter()
            .position(|planned| {
                planned.case.frame == HardwareFrame::RusterImixV1
                    && planned.case.direction == DirectionProfile::Bidirectional
            })
            .unwrap() as u16;
        let imix = VerifiedRepeat::from_raw(
            binding,
            imix_ordinal,
            1,
            raw_for_case(&binding.case(imix_ordinal).unwrap().case, 1),
        )
        .unwrap();
        assert_eq!(imix.record().accepted_packets, 216);
        assert_eq!(
            imix.record().imix_accepted_frames,
            Some(ImixAcceptedFrames {
                eth64_packets: 126,
                eth512_packets: 72,
                ip_mtu1500_packets: 18,
            })
        );
    }

    #[test]
    fn raw_counter_adversaries_fail_closed_before_artifact_creation() {
        let plan = hardware_plan_v1().unwrap();
        let binding = protocol(1, no_latency()).bind(&plan).unwrap();
        let fixed_ordinal = plan
            .cases
            .iter()
            .position(|planned| {
                planned.case.frame != HardwareFrame::RusterImixV1
                    && planned.case.direction == DirectionProfile::Outbound
            })
            .unwrap() as u16;
        let fixed_case = &binding.case(fixed_ordinal).unwrap().case;

        let mut duplicate = raw_for_case(fixed_case, 1);
        duplicate.duplicate_packets = 1;
        assert!(matches!(
            VerifiedRepeat::from_raw(binding, fixed_ordinal, 1, duplicate),
            Err(MeasurementProtocolError::DuplicatePackets(1))
        ));
        let mut inactive = raw_for_case(fixed_case, 1);
        inactive.inbound = DirectionPacketCounters {
            offered_packets: 1,
            received_packets: 1,
            accepted_packets: 1,
        };
        assert!(matches!(
            VerifiedRepeat::from_raw(binding, fixed_ordinal, 1, inactive),
            Err(MeasurementProtocolError::InactiveDirection(
                DirectionProfile::Inbound
            ))
        ));
        let mut oracle_mismatch = raw_for_case(fixed_case, 1);
        oracle_mismatch.outbound.accepted_packets -= 1;
        assert!(matches!(
            VerifiedRepeat::from_raw(binding, fixed_ordinal, 1, oracle_mismatch),
            Err(MeasurementProtocolError::AcceptedDoesNotMatchReceived(
                DirectionProfile::Outbound
            ))
        ));
        let mut unexpected_imix = raw_for_case(fixed_case, 1);
        unexpected_imix.outbound_imix = Some(imix_evidence(unexpected_imix.outbound));
        assert!(matches!(
            VerifiedRepeat::from_raw(binding, fixed_ordinal, 1, unexpected_imix),
            Err(MeasurementProtocolError::UnexpectedImixEvidence(
                DirectionProfile::Outbound
            ))
        ));

        let imix_ordinal = plan
            .cases
            .iter()
            .position(|planned| planned.case.frame == HardwareFrame::RusterImixV1)
            .unwrap() as u16;
        let imix_case = &binding.case(imix_ordinal).unwrap().case;
        let mut missing_imix = raw_for_case(imix_case, 1);
        match imix_case.direction {
            DirectionProfile::Outbound | DirectionProfile::Bidirectional => {
                missing_imix.outbound_imix = None;
            }
            DirectionProfile::Inbound => missing_imix.inbound_imix = None,
        }
        assert!(matches!(
            VerifiedRepeat::from_raw(binding, imix_ordinal, 1, missing_imix),
            Err(MeasurementProtocolError::MissingImixEvidence(_))
        ));
    }

    #[test]
    fn latency_sampling_is_exact_and_one_way_requires_typed_evidence() {
        let plan = hardware_plan_v1().unwrap();
        let profile = LatencyProfile::round_trip(12, digest(SHA_A)).unwrap();
        let binding = protocol(1, profile).bind(&plan).unwrap();
        let ordinal = plan
            .cases
            .iter()
            .position(|planned| planned.case.direction != DirectionProfile::Bidirectional)
            .unwrap() as u16;
        let case = &binding.case(ordinal).unwrap().case;
        let mut raw = raw_for_case(case, 1);
        raw.latency_samples = 9;
        raw.p50_latency_ns = 100;
        raw.p99_latency_ns = 200;
        VerifiedRepeat::from_raw(binding, ordinal, 1, raw.clone()).unwrap();
        raw.latency_samples = 8;
        assert!(matches!(
            VerifiedRepeat::from_raw(binding, ordinal, 1, raw),
            Err(MeasurementProtocolError::InvalidLatency(_))
        ));

        let one_way =
            LatencyProfile::one_way_synchronized(32, digest(SHA_A), digest(SHA_B)).unwrap();
        assert_eq!(one_way.mode(), LatencyMode::OneWaySynchronized);
        assert_eq!(one_way.sample_every_packets(), Some(32));
        assert_eq!(one_way.clock_evidence_sha256(), Some(digest(SHA_B)));
        assert_eq!(profile.clock_evidence_sha256(), None);
    }

    #[test]
    fn summary_and_complete_run_are_derived_from_exact_repeat_set() {
        let plan = hardware_plan_v1().unwrap();
        let binding = protocol(3, no_latency()).bind(&plan).unwrap();
        let first_repeats = verified_repeats(binding, 0);
        let first_summary =
            VerifiedSummary::derive(binding, 0, &first_repeats, Vec::new()).unwrap();
        assert_eq!(first_summary.record().accepted_pps_median, 120.0);
        assert_eq!(
            first_summary.record().loss_ratio_worst.to_bits(),
            0.1_f64.to_bits()
        );

        let mut repeats = Vec::with_capacity(711);
        let mut summaries = Vec::with_capacity(237);
        for ordinal in 0..237 {
            let case_repeats = verified_repeats(binding, ordinal);
            summaries.push(
                VerifiedSummary::derive(binding, ordinal, &case_repeats, Vec::new()).unwrap(),
            );
            repeats.extend(case_repeats);
        }
        let metadata = validate_complete_measurement(binding, &repeats, &summaries).unwrap();
        assert_eq!(metadata.expected_repeat_records(), 711);

        let mut duplicated = repeats.clone();
        duplicated[1] = duplicated[0].clone();
        assert!(matches!(
            validate_complete_measurement(binding, &duplicated, &summaries),
            Err(MeasurementProtocolError::DuplicateRepeat { .. })
                | Err(MeasurementProtocolError::MissingRepeat { .. })
        ));
        let mut forged_summaries = summaries.clone();
        forged_summaries[0].record.accepted_pps_median += 1.0;
        assert!(matches!(
            validate_complete_measurement(binding, &repeats, &forged_summaries),
            Err(MeasurementProtocolError::SummaryDerivationMismatch(0))
        ));
    }

    #[test]
    fn lifecycle_sequence_is_complete_ordered_monotonic_and_failure_aware() {
        let plan = hardware_plan_v1().unwrap();
        let binding = protocol(1, no_latency()).bind(&plan).unwrap();
        let mut events = Vec::new();
        let mut sequence = 1;
        push_pair(
            &mut events,
            &mut sequence,
            MeasurementLifecycleCode::preflight(),
            LifecycleOutcome::Completed,
        );
        push_pair(
            &mut events,
            &mut sequence,
            MeasurementLifecycleCode::setup(),
            LifecycleOutcome::Completed,
        );
        for ordinal in 0..237 {
            push_pair(
                &mut events,
                &mut sequence,
                MeasurementLifecycleCode::case_warmup(binding, ordinal).unwrap(),
                LifecycleOutcome::Completed,
            );
            push_pair(
                &mut events,
                &mut sequence,
                MeasurementLifecycleCode::case_measurement(binding, ordinal, 1).unwrap(),
                LifecycleOutcome::Completed,
            );
            push_pair(
                &mut events,
                &mut sequence,
                MeasurementLifecycleCode::case_drain(binding, ordinal).unwrap(),
                LifecycleOutcome::Completed,
            );
        }
        push_pair(
            &mut events,
            &mut sequence,
            MeasurementLifecycleCode::cleanup(),
            LifecycleOutcome::Completed,
        );
        assert_eq!(
            validate_lifecycle_sequence(binding, &events).unwrap(),
            MeasurementRunOutcome::Completed
        );
        assert_eq!(
            MeasurementLifecycleCode::case_measurement(binding, 7, 1)
                .unwrap()
                .label(),
            "case.007.repeat.001.measurement"
        );

        let mut failed = Vec::new();
        let mut failed_sequence = 1;
        push_pair(
            &mut failed,
            &mut failed_sequence,
            MeasurementLifecycleCode::preflight(),
            LifecycleOutcome::Completed,
        );
        push_pair(
            &mut failed,
            &mut failed_sequence,
            MeasurementLifecycleCode::setup(),
            LifecycleOutcome::Failed,
        );
        push_pair(
            &mut failed,
            &mut failed_sequence,
            MeasurementLifecycleCode::cleanup(),
            LifecycleOutcome::Completed,
        );
        assert_eq!(
            validate_lifecycle_sequence(binding, &failed).unwrap(),
            MeasurementRunOutcome::Failed
        );
    }

    #[test]
    fn lifecycle_sequence_rejects_gap_time_regression_and_phase_skip_atomically() {
        let plan = hardware_plan_v1().unwrap();
        let binding = protocol(1, no_latency()).bind(&plan).unwrap();
        let preflight = MeasurementLifecycleCode::preflight();
        let mut validator = LifecycleSequenceValidator::new(binding);
        let gap = lifecycle_event(2, preflight, LifecycleOutcome::Started);
        assert!(matches!(
            validator.push(&gap),
            Err(MeasurementProtocolError::LifecycleSequence {
                expected: 1,
                actual: 2
            })
        ));
        validator
            .push(&lifecycle_event(1, preflight, LifecycleOutcome::Started))
            .unwrap();
        validator
            .push(
                &MeasurementLifecycleEvent::new(
                    2,
                    10,
                    preflight,
                    LifecycleOutcome::Completed,
                    healthy_frames(),
                    Vec::new(),
                )
                .unwrap(),
            )
            .unwrap();
        let setup = MeasurementLifecycleCode::setup();
        validator
            .push(
                &MeasurementLifecycleEvent::new(
                    3,
                    20,
                    setup,
                    LifecycleOutcome::Started,
                    healthy_frames(),
                    Vec::new(),
                )
                .unwrap(),
            )
            .unwrap();
        let regressed = MeasurementLifecycleEvent::new(
            4,
            19,
            setup,
            LifecycleOutcome::Completed,
            healthy_frames(),
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            validator.push(&regressed),
            Err(MeasurementProtocolError::LifecycleTimeRegression {
                previous: 20,
                actual: 19
            })
        ));
        validator
            .push(
                &MeasurementLifecycleEvent::new(
                    4,
                    20,
                    setup,
                    LifecycleOutcome::Completed,
                    healthy_frames(),
                    Vec::new(),
                )
                .unwrap(),
            )
            .unwrap();
        let skipped = lifecycle_event(
            5,
            MeasurementLifecycleCode::case_measurement(binding, 0, 1).unwrap(),
            LifecycleOutcome::Started,
        );
        assert!(matches!(
            validator.push(&skipped),
            Err(MeasurementProtocolError::LifecycleUnexpectedCode)
        ));
        validator
            .push(
                &MeasurementLifecycleEvent::new(
                    5,
                    50,
                    MeasurementLifecycleCode::case_warmup(binding, 0).unwrap(),
                    LifecycleOutcome::Started,
                    healthy_frames(),
                    Vec::new(),
                )
                .unwrap(),
            )
            .unwrap();

        let mut timeout_validator = LifecycleSequenceValidator::new(binding);
        let timeout_codes = [
            MeasurementLifecycleCode::preflight(),
            MeasurementLifecycleCode::setup(),
            MeasurementLifecycleCode::case_warmup(binding, 0).unwrap(),
            MeasurementLifecycleCode::case_measurement(binding, 0, 1).unwrap(),
            MeasurementLifecycleCode::case_drain(binding, 0).unwrap(),
        ];
        let mut timeout_sequence = 1;
        for code in timeout_codes {
            timeout_validator
                .push(&lifecycle_event_at(
                    timeout_sequence,
                    0,
                    code,
                    LifecycleOutcome::Started,
                ))
                .unwrap();
            timeout_sequence += 1;
            let terminal_ms = if code.phase() == LifecyclePhase::Drain {
                1_001
            } else {
                0
            };
            let result = timeout_validator.push(&lifecycle_event_at(
                timeout_sequence,
                terminal_ms,
                code,
                LifecycleOutcome::Completed,
            ));
            timeout_sequence += 1;
            if code.phase() == LifecyclePhase::Drain {
                assert!(matches!(
                    result,
                    Err(MeasurementProtocolError::LifecycleTimeout {
                        scope: "drain",
                        limit_ms: 1_000,
                        elapsed_ms: 1_001
                    })
                ));
            } else {
                result.unwrap();
            }
        }
    }
}

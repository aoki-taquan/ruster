#![doc = "Dependency-free, NIC-free benchmark support for `ruster-core`."]

mod allocation;
mod backend;
mod deterministic;
mod fixture;
mod hardware_artifact;
mod hardware_plan;
mod hardware_protocol;
mod matrix;
mod output;
mod runner;
mod spec;
mod stats;

pub use allocation::{allocation_count, CountingAllocator};
pub use backend::{BenchBackend, BenchCompletion};
pub use deterministic::{
    deterministic_smoke, r17_deterministic_smoke, validate_deterministic_smoke_artifact,
    DeterministicSmokeError, R17_DETERMINISTIC_SMOKE_ARTIFACT_MAX_BYTES,
    R17_DETERMINISTIC_SMOKE_CASES, R17_DETERMINISTIC_SMOKE_CASE_COUNT,
    R17_DETERMINISTIC_SMOKE_CASE_FIELDS, R17_DETERMINISTIC_SMOKE_HEADER_FIELDS,
    R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS, R17_DETERMINISTIC_SMOKE_SCHEMA,
    R17_DETERMINISTIC_SMOKE_SCHEMA_ID, R17_DETERMINISTIC_SMOKE_SEED,
    R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT,
};
pub use fixture::{plain_ipv4_fixture, FrameSize};
pub use hardware_artifact::{
    redact_sensitive_json, AfxdpMode, ArtifactHash, DirectionProfile, FrameHealth,
    HardwareArtifactRecord, HardwareCase, HardwareFrame, HardwareManifest, HardwareRepeat,
    HardwareSummary, ImixAcceptedFrames, LifecycleOutcome, LifecyclePhase, LifecycleRecord,
    SchemaError, ServiceProfile, TransportProfile, HARDWARE_SCHEMA_ID, HARDWARE_SCHEMA_VERSION,
};
pub use hardware_plan::{
    frame_wire_model, hardware_plan_v1, line_rate_packet_rate, validate_hardware_plan_v1,
    ExactPacketRate, FixedFrameWireModel, FrameWireModel, HardwareCaseSettings,
    HardwareNormativeDescriptor, HardwarePlan, HardwarePlanClass, HardwarePlanError,
    HardwareRateFormula, HardwareWireModelDescriptor, ImixWireModel, PlannedHardwareCase,
    HARDWARE_CONTROL_CASE_COUNT, HARDWARE_NORMATIVE_DESCRIPTOR_V1, HARDWARE_PLAN_FINGERPRINT_V1,
    HARDWARE_PLAN_VERSION, HARDWARE_PRIMARY_CASE_COUNT, HARDWARE_TOTAL_CASE_COUNT,
    RUSTER_IMIX_V1_CYCLE,
};
pub use hardware_protocol::{
    validate_complete_measurement, validate_lifecycle_sequence, BoundHardwareMeasurement,
    CompletenessMetadata, DirectionPacketCounters, GeneratorProfile, GitCommitId,
    HardwareMeasurementProtocol, LatencyMode, LatencyProfile, LifecycleSequenceValidator,
    MeasurementLifecycleCode, MeasurementLifecycleEvent, MeasurementProfileId,
    MeasurementProtocolError, MeasurementRunOutcome, MeasurementTiming, RawRepeatCounters,
    Sha256Digest, VerifiedMeasurementInterval, VerifiedRepeat, VerifiedSummary,
    HARDWARE_MEASUREMENT_PROTOCOL_VERSION, MAX_HARDWARE_CASE_TIMEOUT_MS,
    MAX_HARDWARE_DRAIN_TIMEOUT_MS, MAX_HARDWARE_DURATION_SECONDS, MAX_HARDWARE_REPEAT_COUNT,
    MAX_HARDWARE_RUN_TIMEOUT_MS, MAX_HARDWARE_WARMUP_SECONDS, MAX_LATENCY_SAMPLE_EVERY_PACKETS,
    MAX_MEASUREMENT_ARTIFACT_HASHES, MAX_MEASUREMENT_ARTIFACT_PATH_BYTES,
};
pub use output::{OutputFormat, ResultRow};
pub use runner::{run, RunConfig, RunError, Suite};
pub use spec::{
    r17_benchmark_spec_sha256, R17_BENCHMARK_SPEC_SHA256, R17_BENCHMARK_SPEC_SHA256_HEX,
};
pub use stats::SampleStats;

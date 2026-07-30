#![doc = "Dependency-free, NIC-free benchmark support for `ruster-core`."]

mod allocation;
mod backend;
mod fixture;
mod hardware_artifact;
mod hardware_plan;
mod hardware_protocol;
mod matrix;
mod output;
mod runner;
mod stats;

pub use allocation::allocation_count;
pub use backend::{BenchBackend, BenchCompletion};
pub use fixture::{plain_ipv4_fixture, FrameSize};
pub use hardware_artifact::{
    redact_sensitive_json, AfxdpMode, ArtifactHash, DirectionProfile, FrameHealth,
    HardwareArtifactRecord, HardwareCase, HardwareFrame, HardwareManifest, HardwareRepeat,
    HardwareSummary, ImixAcceptedFrames, LifecycleOutcome, LifecyclePhase, LifecycleRecord,
    SchemaError, ServiceProfile, TransportProfile, HARDWARE_SCHEMA_ID, HARDWARE_SCHEMA_VERSION,
};
pub use hardware_plan::{
    frame_wire_model, hardware_plan_v1, line_rate_packet_rate, validate_hardware_plan_v1,
    ExactPacketRate, FixedFrameWireModel, FrameWireModel, HardwarePlan, HardwarePlanClass,
    HardwarePlanError, ImixWireModel, PlannedHardwareCase, HARDWARE_CONTROL_CASE_COUNT,
    HARDWARE_PLAN_VERSION, HARDWARE_PRIMARY_CASE_COUNT, HARDWARE_TOTAL_CASE_COUNT,
    RUSTER_IMIX_V1_CYCLE,
};
pub use hardware_protocol::{
    validate_complete_measurement, validate_lifecycle_sequence, BoundHardwareMeasurement,
    CompletenessMetadata, DirectionPacketCounters, GeneratorProfile, GitCommitId,
    HardwareMeasurementProtocol, LatencyMode, LatencyProfile, LifecycleSequenceValidator,
    MeasurementLifecycleCode, MeasurementLifecycleEvent, MeasurementProfileId,
    MeasurementProtocolError, MeasurementRunOutcome, MeasurementTiming, RawRepeatCounters,
    Sha256Digest, VerifiedRepeat, VerifiedSummary, HARDWARE_MEASUREMENT_PROTOCOL_VERSION,
    HARDWARE_PLAN_FINGERPRINT_V1, MAX_HARDWARE_CASE_TIMEOUT_MS, MAX_HARDWARE_DRAIN_TIMEOUT_MS,
    MAX_HARDWARE_DURATION_SECONDS, MAX_HARDWARE_REPEAT_COUNT, MAX_HARDWARE_RUN_TIMEOUT_MS,
    MAX_HARDWARE_WARMUP_SECONDS, MAX_LATENCY_SAMPLE_EVERY_PACKETS,
};
pub use output::{OutputFormat, ResultRow};
pub use runner::{run, RunConfig, RunError, Suite};
pub use stats::SampleStats;

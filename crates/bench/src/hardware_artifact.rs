//! Strict, dependency-free schema support for offline hardware benchmark artifacts.
//!
//! This module only validates, canonicalizes, and redacts records. It does not
//! execute traffic, access hardware, evaluate thresholds, or make performance
//! claims. The existing NIC-free result schema remains independent.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

pub const HARDWARE_SCHEMA_ID: &str = "ruster.hardware-bench/v1";
pub const HARDWARE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaError {
    InvalidJson(&'static str),
    TrailingJson,
    DuplicateKey(String),
    MissingField(&'static str),
    UnknownField(String),
    InvalidField(&'static str),
    UnsupportedSchemaId(String),
    UnsupportedVersion(u64),
    UnknownEnum { field: &'static str, value: String },
    CaseIdMismatch { expected: String, actual: String },
    DuplicateArtifactPath(String),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(reason) => write!(formatter, "invalid JSON: {reason}"),
            Self::TrailingJson => formatter.write_str("trailing data after JSON value"),
            Self::DuplicateKey(key) => write!(formatter, "duplicate JSON key {key:?}"),
            Self::MissingField(field) => write!(formatter, "missing required field {field:?}"),
            Self::UnknownField(field) => write!(formatter, "unknown field {field:?}"),
            Self::InvalidField(field) => write!(formatter, "invalid field {field:?}"),
            Self::UnsupportedSchemaId(value) => {
                write!(formatter, "unsupported hardware schema id {value:?}")
            }
            Self::UnsupportedVersion(value) => {
                write!(formatter, "unsupported hardware schema version {value}")
            }
            Self::UnknownEnum { field, value } => {
                write!(formatter, "unknown {field} enum value {value:?}")
            }
            Self::CaseIdMismatch { expected, actual } => write!(
                formatter,
                "case_id mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::DuplicateArtifactPath(path) => {
                write!(formatter, "duplicate artifact path {path:?}")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            #[must_use]
            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }

            fn parse(field: &'static str, value: String) -> Result<Self, SchemaError> {
                match value.as_str() {
                    $($label => Ok(Self::$variant),)+
                    _ => Err(SchemaError::UnknownEnum { field, value }),
                }
            }
        }
    };
}

string_enum!(AfxdpMode {
    Copy => "copy",
    ZeroCopy => "zero-copy",
});

string_enum!(DirectionProfile {
    Outbound => "outbound",
    Inbound => "inbound",
    Bidirectional => "bidirectional",
});

string_enum!(ServiceProfile {
    Plain => "plain",
    Nat44 => "nat44",
    Firewall => "firewall",
    Nat44Firewall => "nat44-firewall",
});

string_enum!(TransportProfile {
    UdpZero => "udp-zero",
    UdpChecksum => "udp-checksum",
    TcpChecksum => "tcp-checksum",
});

string_enum!(LifecyclePhase {
    Preflight => "preflight",
    Setup => "setup",
    Warmup => "warmup",
    Measurement => "measurement",
    Drain => "drain",
    Cleanup => "cleanup",
});

string_enum!(LifecycleOutcome {
    Started => "started",
    Completed => "completed",
    Failed => "failed",
});

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HardwareFrame {
    Eth64,
    Eth128,
    Eth512,
    Ipv4Mtu1500,
    RusterImixV1,
}

impl HardwareFrame {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Eth64 => "eth64",
            Self::Eth128 => "eth128",
            Self::Eth512 => "eth512",
            Self::Ipv4Mtu1500 => "ip-mtu1500",
            Self::RusterImixV1 => "ruster-imix-v1",
        }
    }

    #[must_use]
    pub const fn l1_bytes_with_preamble_ifg(self) -> Option<u16> {
        match self {
            Self::Eth64 => Some(84),
            Self::Eth128 => Some(148),
            Self::Eth512 => Some(532),
            Self::Ipv4Mtu1500 => Some(1_538),
            Self::RusterImixV1 => None,
        }
    }

    fn parse(value: String) -> Result<Self, SchemaError> {
        match value.as_str() {
            "eth64" => Ok(Self::Eth64),
            "eth128" => Ok(Self::Eth128),
            "eth512" => Ok(Self::Eth512),
            "ip-mtu1500" => Ok(Self::Ipv4Mtu1500),
            "ruster-imix-v1" => Ok(Self::RusterImixV1),
            _ => Err(SchemaError::UnknownEnum {
                field: "frame",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImixAcceptedFrames {
    pub eth64_packets: u64,
    pub eth512_packets: u64,
    pub ip_mtu1500_packets: u64,
}

impl ImixAcceptedFrames {
    fn validate_total(self, accepted_packets: u64) -> Result<(), SchemaError> {
        let total = self
            .eth64_packets
            .checked_add(self.eth512_packets)
            .and_then(|value| value.checked_add(self.ip_mtu1500_packets))
            .ok_or(SchemaError::InvalidField("imix_accepted_frames"))?;
        if total != accepted_packets {
            return Err(SchemaError::InvalidField("imix_accepted_frames"));
        }
        Ok(())
    }

    fn l1_bit_count(self) -> u128 {
        (u128::from(self.eth64_packets) * 84
            + u128::from(self.eth512_packets) * 532
            + u128::from(self.ip_mtu1500_packets) * 1_538)
            * 8
    }

    fn to_json(self) -> JsonValue {
        object([
            (
                "eth512_packets",
                JsonValue::Number(self.eth512_packets.to_string()),
            ),
            (
                "eth64_packets",
                JsonValue::Number(self.eth64_packets.to_string()),
            ),
            (
                "ip_mtu1500_packets",
                JsonValue::Number(self.ip_mtu1500_packets.to_string()),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactHash {
    pub path: String,
    pub sha256: String,
}

impl ArtifactHash {
    pub fn new(path: impl Into<String>, sha256: impl Into<String>) -> Result<Self, SchemaError> {
        let value = Self {
            path: path.into(),
            sha256: sha256.into(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), SchemaError> {
        if self.path.is_empty()
            || self.path.starts_with('/')
            || self.path.split('/').any(|component| {
                component.is_empty()
                    || component == "."
                    || component == ".."
                    || !component.bytes().all(is_safe_path_byte)
            })
        {
            return Err(SchemaError::InvalidField("artifact_hashes.path"));
        }
        if !is_lower_hex(&self.sha256, 64) {
            return Err(SchemaError::InvalidField("artifact_hashes.sha256"));
        }
        Ok(())
    }

    fn to_json(&self) -> JsonValue {
        object([
            ("path", JsonValue::String(self.path.clone())),
            ("sha256", JsonValue::String(self.sha256.clone())),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareCase {
    pub mode: AfxdpMode,
    pub queue_count: u16,
    pub batch_size: u16,
    pub frame: HardwareFrame,
    pub flow_count: u32,
    pub direction: DirectionProfile,
    pub service: ServiceProfile,
    pub transport: TransportProfile,
}

impl HardwareCase {
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.queue_count == 0 {
            return Err(SchemaError::InvalidField("queue_count"));
        }
        if self.batch_size == 0 {
            return Err(SchemaError::InvalidField("batch_size"));
        }
        if self.flow_count == 0 {
            return Err(SchemaError::InvalidField("flow_count"));
        }
        Ok(())
    }

    #[must_use]
    pub fn canonical_id(&self) -> String {
        format!(
            "v1:{}:q{}:b{}:{}:f{}:{}:{}:{}",
            self.mode.label(),
            self.queue_count,
            self.batch_size,
            self.frame.label(),
            self.flow_count,
            self.direction.label(),
            self.service.label(),
            self.transport.label(),
        )
    }

    fn to_fields(&self, fields: &mut BTreeMap<String, JsonValue>) {
        fields.insert(
            "batch_size".to_owned(),
            JsonValue::Number(self.batch_size.to_string()),
        );
        fields.insert(
            "direction".to_owned(),
            JsonValue::String(self.direction.label().to_owned()),
        );
        fields.insert(
            "flow_count".to_owned(),
            JsonValue::Number(self.flow_count.to_string()),
        );
        fields.insert(
            "frame".to_owned(),
            JsonValue::String(self.frame.label().to_owned()),
        );
        fields.insert(
            "mode".to_owned(),
            JsonValue::String(self.mode.label().to_owned()),
        );
        fields.insert(
            "queue_count".to_owned(),
            JsonValue::Number(self.queue_count.to_string()),
        );
        fields.insert(
            "service".to_owned(),
            JsonValue::String(self.service.label().to_owned()),
        );
        fields.insert(
            "transport".to_owned(),
            JsonValue::String(self.transport.label().to_owned()),
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHealth {
    pub total: u64,
    pub free: u64,
    pub fill: u64,
    pub rx_owned: u64,
    pub core_borrowed: u64,
    pub tx_owned: u64,
    pub completion: u64,
    pub invalid_descriptors: u64,
    pub double_owned: u64,
}

impl FrameHealth {
    pub fn validate(&self) -> Result<(), SchemaError> {
        let owned = [
            self.free,
            self.fill,
            self.rx_owned,
            self.core_borrowed,
            self.tx_owned,
            self.completion,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
        .ok_or(SchemaError::InvalidField("frame_health"))?;
        if owned != self.total {
            return Err(SchemaError::InvalidField("frame_health"));
        }
        Ok(())
    }

    fn to_json(self) -> JsonValue {
        object([
            ("completion", JsonValue::Number(self.completion.to_string())),
            (
                "core_borrowed",
                JsonValue::Number(self.core_borrowed.to_string()),
            ),
            (
                "double_owned",
                JsonValue::Number(self.double_owned.to_string()),
            ),
            ("fill", JsonValue::Number(self.fill.to_string())),
            ("free", JsonValue::Number(self.free.to_string())),
            (
                "invalid_descriptors",
                JsonValue::Number(self.invalid_descriptors.to_string()),
            ),
            ("rx_owned", JsonValue::Number(self.rx_owned.to_string())),
            ("total", JsonValue::Number(self.total.to_string())),
            ("tx_owned", JsonValue::Number(self.tx_owned.to_string())),
        ])
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HardwareManifest {
    pub run_id: String,
    pub spec_git_sha: String,
    pub spec_sha256: String,
    pub source_git_sha: String,
    pub source_dirty: bool,
    pub hardware_profile_id: String,
    pub build_profile: String,
    pub rustc: String,
    pub kernel_release: String,
    pub kernel_cmdline_sha256: String,
    pub cpu_model: String,
    pub cpu_microcode: String,
    pub worker_cpu_mask: String,
    pub irq_cpu_mask: String,
    pub housekeeping_cpu_mask: String,
    pub numa_node: u16,
    pub nic_pci_id: String,
    pub nic_driver: String,
    pub nic_firmware: String,
    pub xdp_program_sha256: String,
    pub offload_profile_id: String,
    pub rss_profile_id: String,
    pub generator_id: String,
    pub artifact_hashes: Vec<ArtifactHash>,
}

impl HardwareManifest {
    pub fn validate(&self) -> Result<(), SchemaError> {
        validate_public_id("run_id", &self.run_id)?;
        validate_git_sha("spec_git_sha", &self.spec_git_sha)?;
        validate_sha256("spec_sha256", &self.spec_sha256)?;
        validate_git_sha("source_git_sha", &self.source_git_sha)?;
        if self.source_dirty {
            return Err(SchemaError::InvalidField("source_dirty"));
        }
        for (field, value) in [
            ("hardware_profile_id", self.hardware_profile_id.as_str()),
            ("build_profile", self.build_profile.as_str()),
            ("rustc", self.rustc.as_str()),
            ("kernel_release", self.kernel_release.as_str()),
            ("cpu_model", self.cpu_model.as_str()),
            ("cpu_microcode", self.cpu_microcode.as_str()),
            ("worker_cpu_mask", self.worker_cpu_mask.as_str()),
            ("irq_cpu_mask", self.irq_cpu_mask.as_str()),
            ("housekeeping_cpu_mask", self.housekeeping_cpu_mask.as_str()),
            ("nic_pci_id", self.nic_pci_id.as_str()),
            ("nic_driver", self.nic_driver.as_str()),
            ("nic_firmware", self.nic_firmware.as_str()),
            ("offload_profile_id", self.offload_profile_id.as_str()),
            ("rss_profile_id", self.rss_profile_id.as_str()),
            ("generator_id", self.generator_id.as_str()),
        ] {
            validate_public_string(field, value)?;
        }
        validate_sha256("kernel_cmdline_sha256", &self.kernel_cmdline_sha256)?;
        validate_sha256("xdp_program_sha256", &self.xdp_program_sha256)?;
        validate_artifact_hashes(&self.artifact_hashes)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HardwareRepeat {
    pub case_id: String,
    pub case: HardwareCase,
    pub repeat_index: u16,
    pub warmup_seconds: u32,
    pub duration_seconds: u32,
    pub offered_packets: u64,
    pub received_packets: u64,
    pub accepted_packets: u64,
    pub loss_packets: u64,
    pub accepted_pps: f64,
    pub l1_gbps: f64,
    pub loss_ratio: f64,
    pub latency_samples: u64,
    pub p50_latency_ns: f64,
    pub p99_latency_ns: f64,
    pub imix_accepted_frames: Option<ImixAcceptedFrames>,
    pub frame_health_before: FrameHealth,
    pub frame_health_after: FrameHealth,
    pub artifact_hashes: Vec<ArtifactHash>,
}

impl HardwareRepeat {
    pub fn validate(&self) -> Result<(), SchemaError> {
        validate_case_id(&self.case_id, &self.case)?;
        if self.repeat_index == 0 {
            return Err(SchemaError::InvalidField("repeat_index"));
        }
        if self.duration_seconds == 0 {
            return Err(SchemaError::InvalidField("duration_seconds"));
        }
        if self.received_packets > self.offered_packets
            || self.accepted_packets > self.received_packets
            || self.loss_packets != self.offered_packets - self.received_packets
        {
            return Err(SchemaError::InvalidField("packet_counts"));
        }
        validate_metric("accepted_pps", self.accepted_pps)?;
        validate_metric("l1_gbps", self.l1_gbps)?;
        validate_ratio("loss_ratio", self.loss_ratio)?;
        validate_metric("p50_latency_ns", self.p50_latency_ns)?;
        validate_metric("p99_latency_ns", self.p99_latency_ns)?;
        let expected_accepted_pps = self.accepted_packets as f64 / f64::from(self.duration_seconds);
        if self.accepted_pps.to_bits() != expected_accepted_pps.to_bits() {
            return Err(SchemaError::InvalidField("accepted_pps"));
        }
        let l1_bit_count = match (self.case.frame, self.imix_accepted_frames) {
            (HardwareFrame::RusterImixV1, Some(evidence)) => {
                evidence.validate_total(self.accepted_packets)?;
                evidence.l1_bit_count()
            }
            (HardwareFrame::RusterImixV1, None) => {
                return Err(SchemaError::MissingField("imix_accepted_frames"));
            }
            (_, Some(_)) => {
                return Err(SchemaError::InvalidField("imix_accepted_frames"));
            }
            (frame, None) => {
                u128::from(self.accepted_packets)
                    * u128::from(
                        frame
                            .l1_bytes_with_preamble_ifg()
                            .expect("fixed frame has an L1 byte count"),
                    )
                    * 8
            }
        };
        let expected_l1_gbps =
            l1_bit_count as f64 / (f64::from(self.duration_seconds) * 1_000_000_000.0);
        if self.l1_gbps.to_bits() != expected_l1_gbps.to_bits() {
            return Err(SchemaError::InvalidField("l1_gbps"));
        }
        let expected_loss_ratio = if self.offered_packets == 0 {
            0.0
        } else {
            self.loss_packets as f64 / self.offered_packets as f64
        };
        if self.loss_ratio.to_bits() != expected_loss_ratio.to_bits() {
            return Err(SchemaError::InvalidField("loss_ratio"));
        }
        if self.latency_samples == 0 {
            if self.p50_latency_ns != 0.0 || self.p99_latency_ns != 0.0 {
                return Err(SchemaError::InvalidField("latency_percentiles"));
            }
        } else if self.p99_latency_ns < self.p50_latency_ns {
            return Err(SchemaError::InvalidField("p99_latency_ns"));
        }
        self.frame_health_before.validate()?;
        self.frame_health_after.validate()?;
        if self.frame_health_before.total != self.frame_health_after.total {
            return Err(SchemaError::InvalidField("frame_health_total_drift"));
        }
        validate_artifact_hashes(&self.artifact_hashes)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HardwareSummary {
    pub case_id: String,
    pub case: HardwareCase,
    pub repeat_count: u16,
    pub accepted_pps_median: f64,
    pub l1_gbps_median: f64,
    pub loss_ratio_worst: f64,
    pub p50_latency_ns_worst: f64,
    pub p99_latency_ns_worst: f64,
    pub artifact_hashes: Vec<ArtifactHash>,
}

impl HardwareSummary {
    pub fn validate(&self) -> Result<(), SchemaError> {
        validate_case_id(&self.case_id, &self.case)?;
        if self.repeat_count == 0 {
            return Err(SchemaError::InvalidField("repeat_count"));
        }
        validate_metric("accepted_pps_median", self.accepted_pps_median)?;
        validate_metric("l1_gbps_median", self.l1_gbps_median)?;
        validate_ratio("loss_ratio_worst", self.loss_ratio_worst)?;
        validate_metric("p50_latency_ns_worst", self.p50_latency_ns_worst)?;
        validate_metric("p99_latency_ns_worst", self.p99_latency_ns_worst)?;
        if self.p99_latency_ns_worst < self.p50_latency_ns_worst {
            return Err(SchemaError::InvalidField("p99_latency_ns_worst"));
        }
        validate_artifact_hashes(&self.artifact_hashes)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LifecycleRecord {
    pub sequence: u64,
    pub monotonic_ms: u64,
    pub phase: LifecyclePhase,
    pub outcome: LifecycleOutcome,
    pub code: String,
    pub frame_health: FrameHealth,
    pub artifact_hashes: Vec<ArtifactHash>,
}

impl LifecycleRecord {
    pub fn validate(&self) -> Result<(), SchemaError> {
        validate_public_id("code", &self.code)?;
        self.frame_health.validate()?;
        validate_artifact_hashes(&self.artifact_hashes)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum HardwareArtifactRecord {
    Manifest(Box<HardwareManifest>),
    Repeat(HardwareRepeat),
    Summary(HardwareSummary),
    Lifecycle(LifecycleRecord),
}

impl HardwareArtifactRecord {
    pub fn parse(input: &str) -> Result<Self, SchemaError> {
        let value = JsonParser::new(input).parse()?;
        let mut fields = ObjectReader::new(value)?;
        validate_envelope(&mut fields)?;
        let kind = fields.take_string("kind")?;
        let record = match kind.as_str() {
            "manifest" => Self::Manifest(Box::new(parse_manifest(&mut fields)?)),
            "repeat" => Self::Repeat(parse_repeat(&mut fields)?),
            "summary" => Self::Summary(parse_summary(&mut fields)?),
            "lifecycle" => Self::Lifecycle(parse_lifecycle(&mut fields)?),
            _ => {
                return Err(SchemaError::UnknownEnum {
                    field: "kind",
                    value: kind,
                })
            }
        };
        fields.finish()?;
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), SchemaError> {
        match self {
            Self::Manifest(record) => record.validate(),
            Self::Repeat(record) => record.validate(),
            Self::Summary(record) => record.validate(),
            Self::Lifecycle(record) => record.validate(),
        }
    }

    pub fn to_json_line(&self) -> Result<String, SchemaError> {
        self.validate()?;
        let mut fields = envelope(match self {
            Self::Manifest(_) => "manifest",
            Self::Repeat(_) => "repeat",
            Self::Summary(_) => "summary",
            Self::Lifecycle(_) => "lifecycle",
        });
        match self {
            Self::Manifest(record) => manifest_fields(record, &mut fields),
            Self::Repeat(record) => repeat_fields(record, &mut fields),
            Self::Summary(record) => summary_fields(record, &mut fields),
            Self::Lifecycle(record) => lifecycle_fields(record, &mut fields),
        }
        Ok(JsonValue::Object(fields).to_canonical_json())
    }
}

pub fn redact_sensitive_json(input: &str) -> Result<String, SchemaError> {
    let mut value = JsonParser::new(input).parse()?;
    redact_value(&mut value);
    Ok(value.to_canonical_json())
}

fn validate_envelope(fields: &mut ObjectReader) -> Result<(), SchemaError> {
    let schema_id = fields.take_string("schema_id")?;
    if schema_id != HARDWARE_SCHEMA_ID {
        return Err(SchemaError::UnsupportedSchemaId(schema_id));
    }
    let version = fields.take_u64("schema_version")?;
    if version != u64::from(HARDWARE_SCHEMA_VERSION) {
        return Err(SchemaError::UnsupportedVersion(version));
    }
    Ok(())
}

fn envelope(kind: &str) -> BTreeMap<String, JsonValue> {
    BTreeMap::from([
        ("kind".to_owned(), JsonValue::String(kind.to_owned())),
        (
            "schema_id".to_owned(),
            JsonValue::String(HARDWARE_SCHEMA_ID.to_owned()),
        ),
        (
            "schema_version".to_owned(),
            JsonValue::Number(HARDWARE_SCHEMA_VERSION.to_string()),
        ),
    ])
}

fn parse_manifest(fields: &mut ObjectReader) -> Result<HardwareManifest, SchemaError> {
    Ok(HardwareManifest {
        run_id: fields.take_string("run_id")?,
        spec_git_sha: fields.take_string("spec_git_sha")?,
        spec_sha256: fields.take_string("spec_sha256")?,
        source_git_sha: fields.take_string("source_git_sha")?,
        source_dirty: fields.take_bool("source_dirty")?,
        hardware_profile_id: fields.take_string("hardware_profile_id")?,
        build_profile: fields.take_string("build_profile")?,
        rustc: fields.take_string("rustc")?,
        kernel_release: fields.take_string("kernel_release")?,
        kernel_cmdline_sha256: fields.take_string("kernel_cmdline_sha256")?,
        cpu_model: fields.take_string("cpu_model")?,
        cpu_microcode: fields.take_string("cpu_microcode")?,
        worker_cpu_mask: fields.take_string("worker_cpu_mask")?,
        irq_cpu_mask: fields.take_string("irq_cpu_mask")?,
        housekeeping_cpu_mask: fields.take_string("housekeeping_cpu_mask")?,
        numa_node: fields.take_u16("numa_node")?,
        nic_pci_id: fields.take_string("nic_pci_id")?,
        nic_driver: fields.take_string("nic_driver")?,
        nic_firmware: fields.take_string("nic_firmware")?,
        xdp_program_sha256: fields.take_string("xdp_program_sha256")?,
        offload_profile_id: fields.take_string("offload_profile_id")?,
        rss_profile_id: fields.take_string("rss_profile_id")?,
        generator_id: fields.take_string("generator_id")?,
        artifact_hashes: fields.take_artifact_hashes("artifact_hashes")?,
    })
}

fn manifest_fields(record: &HardwareManifest, fields: &mut BTreeMap<String, JsonValue>) {
    for (name, value) in [
        ("build_profile", record.build_profile.as_str()),
        ("cpu_microcode", record.cpu_microcode.as_str()),
        ("cpu_model", record.cpu_model.as_str()),
        ("generator_id", record.generator_id.as_str()),
        ("hardware_profile_id", record.hardware_profile_id.as_str()),
        (
            "housekeeping_cpu_mask",
            record.housekeeping_cpu_mask.as_str(),
        ),
        ("irq_cpu_mask", record.irq_cpu_mask.as_str()),
        (
            "kernel_cmdline_sha256",
            record.kernel_cmdline_sha256.as_str(),
        ),
        ("kernel_release", record.kernel_release.as_str()),
        ("nic_driver", record.nic_driver.as_str()),
        ("nic_firmware", record.nic_firmware.as_str()),
        ("nic_pci_id", record.nic_pci_id.as_str()),
        ("offload_profile_id", record.offload_profile_id.as_str()),
        ("rss_profile_id", record.rss_profile_id.as_str()),
        ("run_id", record.run_id.as_str()),
        ("rustc", record.rustc.as_str()),
        ("source_git_sha", record.source_git_sha.as_str()),
        ("spec_git_sha", record.spec_git_sha.as_str()),
        ("spec_sha256", record.spec_sha256.as_str()),
        ("worker_cpu_mask", record.worker_cpu_mask.as_str()),
        ("xdp_program_sha256", record.xdp_program_sha256.as_str()),
    ] {
        fields.insert(name.to_owned(), JsonValue::String(value.to_owned()));
    }
    fields.insert(
        "artifact_hashes".to_owned(),
        artifact_hashes_json(&record.artifact_hashes),
    );
    fields.insert(
        "numa_node".to_owned(),
        JsonValue::Number(record.numa_node.to_string()),
    );
    fields.insert(
        "source_dirty".to_owned(),
        JsonValue::Bool(record.source_dirty),
    );
}

fn parse_case(fields: &mut ObjectReader) -> Result<(String, HardwareCase), SchemaError> {
    let case_id = fields.take_string("case_id")?;
    let case = HardwareCase {
        mode: AfxdpMode::parse("mode", fields.take_string("mode")?)?,
        queue_count: fields.take_u16("queue_count")?,
        batch_size: fields.take_u16("batch_size")?,
        frame: HardwareFrame::parse(fields.take_string("frame")?)?,
        flow_count: fields.take_u32("flow_count")?,
        direction: DirectionProfile::parse("direction", fields.take_string("direction")?)?,
        service: ServiceProfile::parse("service", fields.take_string("service")?)?,
        transport: TransportProfile::parse("transport", fields.take_string("transport")?)?,
    };
    Ok((case_id, case))
}

fn parse_repeat(fields: &mut ObjectReader) -> Result<HardwareRepeat, SchemaError> {
    let (case_id, case) = parse_case(fields)?;
    Ok(HardwareRepeat {
        case_id,
        case,
        repeat_index: fields.take_u16("repeat_index")?,
        warmup_seconds: fields.take_u32("warmup_seconds")?,
        duration_seconds: fields.take_u32("duration_seconds")?,
        offered_packets: fields.take_u64("offered_packets")?,
        received_packets: fields.take_u64("received_packets")?,
        accepted_packets: fields.take_u64("accepted_packets")?,
        loss_packets: fields.take_u64("loss_packets")?,
        accepted_pps: fields.take_metric("accepted_pps")?,
        l1_gbps: fields.take_metric("l1_gbps")?,
        loss_ratio: fields.take_metric("loss_ratio")?,
        latency_samples: fields.take_u64("latency_samples")?,
        p50_latency_ns: fields.take_metric("p50_latency_ns")?,
        p99_latency_ns: fields.take_metric("p99_latency_ns")?,
        imix_accepted_frames: fields.take_optional_imix_accepted_frames()?,
        frame_health_before: fields.take_frame_health("frame_health_before")?,
        frame_health_after: fields.take_frame_health("frame_health_after")?,
        artifact_hashes: fields.take_artifact_hashes("artifact_hashes")?,
    })
}

fn repeat_fields(record: &HardwareRepeat, fields: &mut BTreeMap<String, JsonValue>) {
    fields.insert(
        "accepted_packets".to_owned(),
        JsonValue::Number(record.accepted_packets.to_string()),
    );
    fields.insert("accepted_pps".to_owned(), metric_json(record.accepted_pps));
    fields.insert(
        "artifact_hashes".to_owned(),
        artifact_hashes_json(&record.artifact_hashes),
    );
    fields.insert(
        "case_id".to_owned(),
        JsonValue::String(record.case_id.clone()),
    );
    record.case.to_fields(fields);
    fields.insert(
        "duration_seconds".to_owned(),
        JsonValue::Number(record.duration_seconds.to_string()),
    );
    fields.insert(
        "frame_health_after".to_owned(),
        record.frame_health_after.to_json(),
    );
    fields.insert(
        "frame_health_before".to_owned(),
        record.frame_health_before.to_json(),
    );
    if let Some(evidence) = record.imix_accepted_frames {
        fields.insert("imix_accepted_frames".to_owned(), evidence.to_json());
    }
    fields.insert("l1_gbps".to_owned(), metric_json(record.l1_gbps));
    fields.insert(
        "latency_samples".to_owned(),
        JsonValue::Number(record.latency_samples.to_string()),
    );
    fields.insert(
        "loss_packets".to_owned(),
        JsonValue::Number(record.loss_packets.to_string()),
    );
    fields.insert("loss_ratio".to_owned(), metric_json(record.loss_ratio));
    fields.insert(
        "offered_packets".to_owned(),
        JsonValue::Number(record.offered_packets.to_string()),
    );
    fields.insert(
        "p50_latency_ns".to_owned(),
        metric_json(record.p50_latency_ns),
    );
    fields.insert(
        "p99_latency_ns".to_owned(),
        metric_json(record.p99_latency_ns),
    );
    fields.insert(
        "received_packets".to_owned(),
        JsonValue::Number(record.received_packets.to_string()),
    );
    fields.insert(
        "repeat_index".to_owned(),
        JsonValue::Number(record.repeat_index.to_string()),
    );
    fields.insert(
        "warmup_seconds".to_owned(),
        JsonValue::Number(record.warmup_seconds.to_string()),
    );
}

fn parse_summary(fields: &mut ObjectReader) -> Result<HardwareSummary, SchemaError> {
    let (case_id, case) = parse_case(fields)?;
    Ok(HardwareSummary {
        case_id,
        case,
        repeat_count: fields.take_u16("repeat_count")?,
        accepted_pps_median: fields.take_metric("accepted_pps_median")?,
        l1_gbps_median: fields.take_metric("l1_gbps_median")?,
        loss_ratio_worst: fields.take_metric("loss_ratio_worst")?,
        p50_latency_ns_worst: fields.take_metric("p50_latency_ns_worst")?,
        p99_latency_ns_worst: fields.take_metric("p99_latency_ns_worst")?,
        artifact_hashes: fields.take_artifact_hashes("artifact_hashes")?,
    })
}

fn summary_fields(record: &HardwareSummary, fields: &mut BTreeMap<String, JsonValue>) {
    fields.insert(
        "accepted_pps_median".to_owned(),
        metric_json(record.accepted_pps_median),
    );
    fields.insert(
        "artifact_hashes".to_owned(),
        artifact_hashes_json(&record.artifact_hashes),
    );
    fields.insert(
        "case_id".to_owned(),
        JsonValue::String(record.case_id.clone()),
    );
    record.case.to_fields(fields);
    fields.insert(
        "l1_gbps_median".to_owned(),
        metric_json(record.l1_gbps_median),
    );
    fields.insert(
        "loss_ratio_worst".to_owned(),
        metric_json(record.loss_ratio_worst),
    );
    fields.insert(
        "p50_latency_ns_worst".to_owned(),
        metric_json(record.p50_latency_ns_worst),
    );
    fields.insert(
        "p99_latency_ns_worst".to_owned(),
        metric_json(record.p99_latency_ns_worst),
    );
    fields.insert(
        "repeat_count".to_owned(),
        JsonValue::Number(record.repeat_count.to_string()),
    );
}

fn parse_lifecycle(fields: &mut ObjectReader) -> Result<LifecycleRecord, SchemaError> {
    Ok(LifecycleRecord {
        sequence: fields.take_u64("sequence")?,
        monotonic_ms: fields.take_u64("monotonic_ms")?,
        phase: LifecyclePhase::parse("phase", fields.take_string("phase")?)?,
        outcome: LifecycleOutcome::parse("outcome", fields.take_string("outcome")?)?,
        code: fields.take_string("code")?,
        frame_health: fields.take_frame_health("frame_health")?,
        artifact_hashes: fields.take_artifact_hashes("artifact_hashes")?,
    })
}

fn lifecycle_fields(record: &LifecycleRecord, fields: &mut BTreeMap<String, JsonValue>) {
    fields.insert(
        "artifact_hashes".to_owned(),
        artifact_hashes_json(&record.artifact_hashes),
    );
    fields.insert("code".to_owned(), JsonValue::String(record.code.clone()));
    fields.insert("frame_health".to_owned(), record.frame_health.to_json());
    fields.insert(
        "monotonic_ms".to_owned(),
        JsonValue::Number(record.monotonic_ms.to_string()),
    );
    fields.insert(
        "outcome".to_owned(),
        JsonValue::String(record.outcome.label().to_owned()),
    );
    fields.insert(
        "phase".to_owned(),
        JsonValue::String(record.phase.label().to_owned()),
    );
    fields.insert(
        "sequence".to_owned(),
        JsonValue::Number(record.sequence.to_string()),
    );
}

fn validate_case_id(case_id: &str, case: &HardwareCase) -> Result<(), SchemaError> {
    case.validate()?;
    let expected = case.canonical_id();
    if case_id != expected {
        return Err(SchemaError::CaseIdMismatch {
            expected,
            actual: case_id.to_owned(),
        });
    }
    Ok(())
}

fn validate_artifact_hashes(hashes: &[ArtifactHash]) -> Result<(), SchemaError> {
    let mut paths = BTreeSet::new();
    for hash in hashes {
        hash.validate()?;
        if !paths.insert(hash.path.as_str()) {
            return Err(SchemaError::DuplicateArtifactPath(hash.path.clone()));
        }
    }
    Ok(())
}

fn artifact_hashes_json(hashes: &[ArtifactHash]) -> JsonValue {
    let mut sorted = hashes.to_vec();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));
    JsonValue::Array(sorted.iter().map(ArtifactHash::to_json).collect())
}

fn validate_metric(field: &'static str, value: f64) -> Result<(), SchemaError> {
    if !value.is_finite() || value < 0.0 || (value == 0.0 && value.is_sign_negative()) {
        Err(SchemaError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_ratio(field: &'static str, value: f64) -> Result<(), SchemaError> {
    validate_metric(field, value)?;
    if value > 1.0 {
        Err(SchemaError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_git_sha(field: &'static str, value: &str) -> Result<(), SchemaError> {
    if is_lower_hex(value, 40) {
        Ok(())
    } else {
        Err(SchemaError::InvalidField(field))
    }
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), SchemaError> {
    if is_lower_hex(value, 64) {
        Ok(())
    } else {
        Err(SchemaError::InvalidField(field))
    }
}

fn validate_public_id(field: &'static str, value: &str) -> Result<(), SchemaError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        Err(SchemaError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_public_string(field: &'static str, value: &str) -> Result<(), SchemaError> {
    let lowercase = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || [
            "password=",
            "token=",
            "secret=",
            "authorization:",
            "private key",
        ]
        .iter()
        .any(|marker| lowercase.contains(marker))
    {
        Err(SchemaError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

const fn is_safe_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn metric_json(value: f64) -> JsonValue {
    JsonValue::Number(value.to_string())
}

fn parse_frame_health(value: JsonValue) -> Result<FrameHealth, SchemaError> {
    let mut fields = ObjectReader::new(value)?;
    let health = FrameHealth {
        total: fields.take_u64("total")?,
        free: fields.take_u64("free")?,
        fill: fields.take_u64("fill")?,
        rx_owned: fields.take_u64("rx_owned")?,
        core_borrowed: fields.take_u64("core_borrowed")?,
        tx_owned: fields.take_u64("tx_owned")?,
        completion: fields.take_u64("completion")?,
        invalid_descriptors: fields.take_u64("invalid_descriptors")?,
        double_owned: fields.take_u64("double_owned")?,
    };
    fields.finish()?;
    health.validate()?;
    Ok(health)
}

fn parse_imix_accepted_frames(value: JsonValue) -> Result<ImixAcceptedFrames, SchemaError> {
    let mut fields = ObjectReader::new(value)?;
    let evidence = ImixAcceptedFrames {
        eth64_packets: fields.take_u64("eth64_packets")?,
        eth512_packets: fields.take_u64("eth512_packets")?,
        ip_mtu1500_packets: fields.take_u64("ip_mtu1500_packets")?,
    };
    fields.finish()?;
    Ok(evidence)
}

fn parse_artifact_hashes(value: JsonValue) -> Result<Vec<ArtifactHash>, SchemaError> {
    let JsonValue::Array(values) = value else {
        return Err(SchemaError::InvalidField("artifact_hashes"));
    };
    let mut hashes = Vec::with_capacity(values.len());
    for value in values {
        let mut fields = ObjectReader::new(value)?;
        let hash = ArtifactHash::new(fields.take_string("path")?, fields.take_string("sha256")?)?;
        fields.finish()?;
        hashes.push(hash);
    }
    validate_artifact_hashes(&hashes)?;
    hashes.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(hashes)
}

struct ObjectReader {
    fields: BTreeMap<String, JsonValue>,
}

impl ObjectReader {
    fn new(value: JsonValue) -> Result<Self, SchemaError> {
        let JsonValue::Object(fields) = value else {
            return Err(SchemaError::InvalidJson("expected object"));
        };
        Ok(Self { fields })
    }

    fn take(&mut self, field: &'static str) -> Result<JsonValue, SchemaError> {
        self.fields
            .remove(field)
            .ok_or(SchemaError::MissingField(field))
    }

    fn take_string(&mut self, field: &'static str) -> Result<String, SchemaError> {
        let JsonValue::String(value) = self.take(field)? else {
            return Err(SchemaError::InvalidField(field));
        };
        Ok(value)
    }

    fn take_bool(&mut self, field: &'static str) -> Result<bool, SchemaError> {
        let JsonValue::Bool(value) = self.take(field)? else {
            return Err(SchemaError::InvalidField(field));
        };
        Ok(value)
    }

    fn take_u64(&mut self, field: &'static str) -> Result<u64, SchemaError> {
        let JsonValue::Number(value) = self.take(field)? else {
            return Err(SchemaError::InvalidField(field));
        };
        if value.starts_with('-')
            || value.contains(['.', 'e', 'E'])
            || value.starts_with('+')
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(SchemaError::InvalidField(field));
        }
        value.parse().map_err(|_| SchemaError::InvalidField(field))
    }

    fn take_u32(&mut self, field: &'static str) -> Result<u32, SchemaError> {
        self.take_u64(field)?
            .try_into()
            .map_err(|_| SchemaError::InvalidField(field))
    }

    fn take_u16(&mut self, field: &'static str) -> Result<u16, SchemaError> {
        self.take_u64(field)?
            .try_into()
            .map_err(|_| SchemaError::InvalidField(field))
    }

    fn take_metric(&mut self, field: &'static str) -> Result<f64, SchemaError> {
        let JsonValue::Number(value) = self.take(field)? else {
            return Err(SchemaError::InvalidField(field));
        };
        let metric = value
            .parse::<f64>()
            .map_err(|_| SchemaError::InvalidField(field))?;
        validate_metric(field, metric)?;
        Ok(metric)
    }

    fn take_frame_health(&mut self, field: &'static str) -> Result<FrameHealth, SchemaError> {
        parse_frame_health(self.take(field)?).map_err(|error| match error {
            SchemaError::MissingField(_) | SchemaError::UnknownField(_) => error,
            _ => SchemaError::InvalidField(field),
        })
    }

    fn take_artifact_hashes(
        &mut self,
        field: &'static str,
    ) -> Result<Vec<ArtifactHash>, SchemaError> {
        parse_artifact_hashes(self.take(field)?)
    }

    fn take_optional_imix_accepted_frames(
        &mut self,
    ) -> Result<Option<ImixAcceptedFrames>, SchemaError> {
        self.fields
            .remove("imix_accepted_frames")
            .map(parse_imix_accepted_frames)
            .transpose()
    }

    fn finish(self) -> Result<(), SchemaError> {
        if let Some(field) = self.fields.keys().next() {
            Err(SchemaError::UnknownField(field.clone()))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl JsonValue {
    fn to_canonical_json(&self) -> String {
        let mut output = String::new();
        self.write_json(&mut output);
        output
    }

    fn write_json(&self, output: &mut String) {
        match self {
            Self::Null => output.push_str("null"),
            Self::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) => output.push_str(value),
            Self::String(value) => write_json_string(output, value),
            Self::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    value.write_json(output);
                }
                output.push(']');
            }
            Self::Object(fields) => {
                output.push('{');
                for (index, (name, value)) in fields.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_json_string(output, name);
                    output.push(':');
                    value.write_json(output);
                }
                output.push('}');
            }
        }
    }
}

fn object<const N: usize>(fields: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn write_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => {
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("writing to String cannot fail");
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> JsonParser<'a> {
    const MAX_DEPTH: usize = 64;
    const MAX_INPUT_BYTES: usize = 1_048_576;

    const fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            cursor: 0,
        }
    }

    fn parse(mut self) -> Result<JsonValue, SchemaError> {
        if self.bytes.len() > Self::MAX_INPUT_BYTES {
            return Err(SchemaError::InvalidJson("input exceeds size limit"));
        }
        self.skip_whitespace();
        let value = self.parse_value(0)?;
        self.skip_whitespace();
        if self.cursor != self.bytes.len() {
            return Err(SchemaError::TrailingJson);
        }
        Ok(value)
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, SchemaError> {
        match self.peek() {
            Some(b'{' | b'[') if depth >= Self::MAX_DEPTH => {
                Err(SchemaError::InvalidJson("nesting exceeds depth limit"))
            }
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(JsonValue::Number),
            _ => Err(SchemaError::InvalidJson("expected value")),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, SchemaError> {
        self.expect(b'{')?;
        self.skip_whitespace();
        let mut fields = BTreeMap::new();
        if self.take_if(b'}') {
            return Ok(JsonValue::Object(fields));
        }
        loop {
            self.skip_whitespace();
            let name = self.parse_string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.parse_value(depth)?;
            if fields.insert(name.clone(), value).is_some() {
                return Err(SchemaError::DuplicateKey(name));
            }
            self.skip_whitespace();
            if self.take_if(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(JsonValue::Object(fields))
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, SchemaError> {
        self.expect(b'[')?;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.take_if(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            self.skip_whitespace();
            values.push(self.parse_value(depth)?);
            self.skip_whitespace();
            if self.take_if(b']') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(JsonValue::Array(values))
    }

    fn parse_string(&mut self) -> Result<String, SchemaError> {
        self.expect(b'"')?;
        let mut output = String::new();
        loop {
            let byte = self
                .next()
                .ok_or(SchemaError::InvalidJson("unterminated string"))?;
            match byte {
                b'"' => return Ok(output),
                b'\\' => self.parse_escape(&mut output)?,
                0x00..=0x1f => return Err(SchemaError::InvalidJson("control in string")),
                0x20..=0x7f => output.push(char::from(byte)),
                _ => {
                    let start = self.cursor - 1;
                    let remaining = std::str::from_utf8(&self.bytes[start..])
                        .map_err(|_| SchemaError::InvalidJson("invalid UTF-8"))?;
                    let character = remaining
                        .chars()
                        .next()
                        .ok_or(SchemaError::InvalidJson("invalid UTF-8"))?;
                    output.push(character);
                    self.cursor = start + character.len_utf8();
                }
            }
        }
    }

    fn parse_escape(&mut self, output: &mut String) -> Result<(), SchemaError> {
        match self
            .next()
            .ok_or(SchemaError::InvalidJson("unterminated escape"))?
        {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let first = self.parse_hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    self.expect(b'\\')?;
                    self.expect(b'u')?;
                    let second = self.parse_hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(SchemaError::InvalidJson("invalid surrogate pair"));
                    }
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(SchemaError::InvalidJson("unpaired low surrogate"));
                } else {
                    u32::from(first)
                };
                output.push(
                    char::from_u32(scalar)
                        .ok_or(SchemaError::InvalidJson("invalid Unicode scalar"))?,
                );
            }
            _ => return Err(SchemaError::InvalidJson("unknown escape")),
        }
        Ok(())
    }

    fn parse_hex_quad(&mut self) -> Result<u16, SchemaError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = self
                .next()
                .and_then(|byte| char::from(byte).to_digit(16))
                .ok_or(SchemaError::InvalidJson("invalid Unicode escape"))?;
            value = (value << 4) | u16::try_from(digit).expect("hex digit fits u16");
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<String, SchemaError> {
        let start = self.cursor;
        self.take_if(b'-');
        match self.peek() {
            Some(b'0') => {
                self.cursor += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(SchemaError::InvalidJson("leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                self.cursor += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.cursor += 1;
                }
            }
            _ => return Err(SchemaError::InvalidJson("invalid number")),
        }
        if self.take_if(b'.') {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(SchemaError::InvalidJson("empty fraction"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.cursor += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.cursor += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.cursor += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(SchemaError::InvalidJson("empty exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.cursor += 1;
            }
        }
        std::str::from_utf8(&self.bytes[start..self.cursor])
            .map(str::to_owned)
            .map_err(|_| SchemaError::InvalidJson("invalid number"))
    }

    fn consume_literal(&mut self, expected: &[u8]) -> Result<(), SchemaError> {
        if self.bytes.get(self.cursor..self.cursor + expected.len()) == Some(expected) {
            self.cursor += expected.len();
            Ok(())
        } else {
            Err(SchemaError::InvalidJson("invalid literal"))
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.cursor += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), SchemaError> {
        if self.take_if(expected) {
            Ok(())
        } else {
            Err(SchemaError::InvalidJson("unexpected token"))
        }
    }

    fn take_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.cursor += 1;
        Some(value)
    }
}

fn redact_value(value: &mut JsonValue) {
    match value {
        JsonValue::Array(values) => {
            for value in values {
                redact_value(value);
            }
        }
        JsonValue::Object(fields) => {
            fields.retain(|name, _| !sensitive_field_name(name));
            for value in fields.values_mut() {
                redact_value(value);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
    }
}

fn sensitive_field_name(name: &str) -> bool {
    let mut normalized = String::with_capacity(name.len());
    let mut separator = false;
    let mut previous_was_lowercase_or_digit = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase()
                && previous_was_lowercase_or_digit
                && !normalized.is_empty()
            {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            separator = false;
            previous_was_lowercase_or_digit =
                character.is_ascii_lowercase() || character.is_ascii_digit();
        } else if !separator && !normalized.is_empty() {
            normalized.push('_');
            separator = true;
            previous_was_lowercase_or_digit = false;
        }
    }
    if separator {
        normalized.pop();
    }
    let segments = normalized
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.iter().any(|segment| {
        matches!(
            *segment,
            "fqdn" | "token" | "secret" | "password" | "credential" | "topology"
        )
    }) {
        return true;
    }
    let has_pair = |left, right| segments.windows(2).any(|window| window == [left, right]);
    if has_pair("host", "name")
        || has_pair("management", "ip")
        || has_pair("management", "url")
        || has_pair("mac", "address")
        || has_pair("serial", "number")
        || has_pair("runner", "token")
        || has_pair("private", "key")
        || has_pair("ssh", "key")
    {
        return true;
    }
    let collapsed = normalized.replace('_', "");
    [
        "hostname",
        "managementip",
        "managementurl",
        "macaddress",
        "serialnumber",
        "runnertoken",
        "privatekey",
        "sshkey",
    ]
    .iter()
    .any(|denied| collapsed == *denied || collapsed.ends_with(denied))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = include_str!("../tests/fixtures/hardware-bench-v1/manifest.json");
    const REPEAT: &str = include_str!("../tests/fixtures/hardware-bench-v1/repeat.json");
    const SUMMARY: &str = include_str!("../tests/fixtures/hardware-bench-v1/summary.json");
    const LIFECYCLE: &str = include_str!("../tests/fixtures/hardware-bench-v1/lifecycle.json");

    fn is_exact_canonical_json_line(fixture: &str) -> bool {
        let Ok(record) = HardwareArtifactRecord::parse(fixture) else {
            return false;
        };
        let Ok(canonical) = record.to_json_line() else {
            return false;
        };
        fixture.strip_suffix('\n') == Some(canonical.as_str())
    }

    #[test]
    fn hardware_artifact_golden_records_are_canonical_and_stable() {
        for fixture in [MANIFEST, REPEAT, SUMMARY, LIFECYCLE] {
            let record = HardwareArtifactRecord::parse(fixture).unwrap();
            let canonical = record.to_json_line().unwrap();
            assert_eq!(fixture, format!("{canonical}\n"));
            assert!(is_exact_canonical_json_line(fixture));
            for noncanonical in [
                format!(" {canonical}\n"),
                format!("{canonical} \n"),
                format!("{canonical}\n\n"),
            ] {
                assert!(!is_exact_canonical_json_line(&noncanonical));
            }
            let reparsed = HardwareArtifactRecord::parse(&canonical).unwrap();
            assert_eq!(reparsed, record);
            assert_eq!(reparsed.to_json_line().unwrap(), canonical);
        }
    }

    #[test]
    fn hardware_artifact_schema_rejects_unknown_missing_duplicate_and_inconsistent_fields() {
        assert!(matches!(
            HardwareArtifactRecord::parse(&MANIFEST.replace("\"run_id\":\"run-2026-07-30\",", "")),
            Err(SchemaError::MissingField("run_id"))
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(&MANIFEST.replace(
                "\"run_id\":\"run-2026-07-30\",",
                "\"run_id\":\"run-2026-07-30\",\"surprise\":1,"
            )),
            Err(SchemaError::UnknownField(field)) if field == "surprise"
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(&MANIFEST.replace(
                "\"run_id\":\"run-2026-07-30\",",
                "\"run_id\":\"first\",\"run_id\":\"second\","
            )),
            Err(SchemaError::DuplicateKey(field)) if field == "run_id"
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(&REPEAT.replace(
                "v1:zero-copy:q4:b64:eth64:f4096:outbound:nat44-firewall:udp-checksum",
                "wrong"
            )),
            Err(SchemaError::CaseIdMismatch { .. })
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &MANIFEST.replace("\"schema_version\":1", "\"schema_version\":2")
            ),
            Err(SchemaError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn metrics_enums_health_and_hashes_fail_closed() {
        for replacement in ["-1", "-0", "1e999"] {
            let invalid = REPEAT.replace(
                "\"accepted_pps\":999900",
                &format!("\"accepted_pps\":{replacement}"),
            );
            assert!(matches!(
                HardwareArtifactRecord::parse(&invalid),
                Err(SchemaError::InvalidField("accepted_pps"))
            ));
        }
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &REPEAT.replace("\"mode\":\"zero-copy\"", "\"mode\":\"fallback\"")
            ),
            Err(SchemaError::UnknownEnum { field: "mode", .. })
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(&REPEAT.replace("\"free\":16384", "\"free\":16383")),
            Err(SchemaError::InvalidField("frame_health_before"))
        ));
        let duplicate_hash = MANIFEST.replace(
            "{\"path\":\"system/kernel.txt\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
            "{\"path\":\"system/kernel.txt\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},{\"path\":\"system/kernel.txt\",\"sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}",
        );
        assert!(matches!(
            HardwareArtifactRecord::parse(&duplicate_hash),
            Err(SchemaError::DuplicateArtifactPath(path)) if path == "system/kernel.txt"
        ));

        let mut drift = HardwareArtifactRecord::parse(REPEAT).unwrap();
        let HardwareArtifactRecord::Repeat(repeat) = &mut drift else {
            panic!("repeat fixture must parse as repeat");
        };
        repeat.frame_health_after.total = 32_768;
        repeat.frame_health_after.free = 32_768;
        assert!(matches!(
            drift.validate(),
            Err(SchemaError::InvalidField("frame_health_total_drift"))
        ));

        let overflowing_health = FrameHealth {
            total: u64::MAX,
            free: u64::MAX,
            fill: 1,
            rx_owned: 0,
            core_borrowed: 0,
            tx_owned: 0,
            completion: 0,
            invalid_descriptors: 0,
            double_owned: 0,
        };
        assert!(matches!(
            overflowing_health.validate(),
            Err(SchemaError::InvalidField("frame_health"))
        ));

        let mut constructed = HardwareArtifactRecord::parse(REPEAT).unwrap();
        let HardwareArtifactRecord::Repeat(repeat) = &mut constructed else {
            panic!("repeat fixture must parse as repeat");
        };
        repeat.accepted_pps = f64::NAN;
        assert!(matches!(
            constructed.to_json_line(),
            Err(SchemaError::InvalidField("accepted_pps"))
        ));
    }

    #[test]
    fn packet_loss_and_latency_samples_are_exactly_consistent() {
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &REPEAT.replace("\"loss_ratio\":0.0001", "\"loss_ratio\":0.0002")
            ),
            Err(SchemaError::InvalidField("loss_ratio"))
        ));

        let empty = REPEAT
            .replace("\"offered_packets\":60000000", "\"offered_packets\":0")
            .replace("\"received_packets\":59994000", "\"received_packets\":0")
            .replace("\"accepted_packets\":59994000", "\"accepted_packets\":0")
            .replace("\"accepted_pps\":999900", "\"accepted_pps\":0")
            .replace("\"l1_gbps\":0.6719328", "\"l1_gbps\":0")
            .replace("\"loss_packets\":6000", "\"loss_packets\":0")
            .replace("\"loss_ratio\":0.0001", "\"loss_ratio\":0")
            .replace("\"latency_samples\":600000", "\"latency_samples\":0")
            .replace("\"p50_latency_ns\":1200", "\"p50_latency_ns\":0")
            .replace("\"p99_latency_ns\":4200", "\"p99_latency_ns\":0");
        assert!(HardwareArtifactRecord::parse(&empty).is_ok());
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &empty.replace("\"p50_latency_ns\":0", "\"p50_latency_ns\":1")
            ),
            Err(SchemaError::InvalidField("latency_percentiles"))
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &REPEAT.replace("\"p99_latency_ns\":4200", "\"p99_latency_ns\":1199")
            ),
            Err(SchemaError::InvalidField("p99_latency_ns"))
        ));
    }

    #[test]
    fn repeat_rates_are_count_derived_and_imix_requires_typed_evidence() {
        assert_eq!(HardwareFrame::Eth64.l1_bytes_with_preamble_ifg(), Some(84));
        assert_eq!(
            HardwareFrame::Eth128.l1_bytes_with_preamble_ifg(),
            Some(148)
        );
        assert_eq!(
            HardwareFrame::Eth512.l1_bytes_with_preamble_ifg(),
            Some(532)
        );
        assert_eq!(
            HardwareFrame::Ipv4Mtu1500.l1_bytes_with_preamble_ifg(),
            Some(1_538)
        );
        assert_eq!(
            HardwareFrame::RusterImixV1.l1_bytes_with_preamble_ifg(),
            None
        );
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &REPEAT.replace("\"accepted_pps\":999900", "\"accepted_pps\":999901")
            ),
            Err(SchemaError::InvalidField("accepted_pps"))
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &REPEAT.replace("\"l1_gbps\":0.6719328", "\"l1_gbps\":0.672")
            ),
            Err(SchemaError::InvalidField("l1_gbps"))
        ));

        let mut grouped_regression = HardwareArtifactRecord::parse(REPEAT).unwrap();
        let HardwareArtifactRecord::Repeat(repeat) = &mut grouped_regression else {
            panic!("repeat fixture must parse as repeat");
        };
        repeat.case.frame = HardwareFrame::Eth128;
        repeat.case_id = repeat.case.canonical_id();
        repeat.duration_seconds = 3;
        repeat.offered_packets = 1;
        repeat.received_packets = 1;
        repeat.accepted_packets = 1;
        repeat.loss_packets = 0;
        repeat.accepted_pps = 1.0_f64 / 3.0;
        repeat.loss_ratio = 0.0;
        let grouped = 1_184.0_f64 / (3.0 * 1_000_000_000.0);
        let sequential = 1_184.0_f64 / 3.0 / 1_000_000_000.0;
        assert_ne!(grouped.to_bits(), sequential.to_bits());
        repeat.l1_gbps = grouped;
        assert!(grouped_regression.validate().is_ok());
        let HardwareArtifactRecord::Repeat(repeat) = &mut grouped_regression else {
            unreachable!("record remains a repeat");
        };
        repeat.l1_gbps = sequential;
        assert!(matches!(
            grouped_regression.validate(),
            Err(SchemaError::InvalidField("l1_gbps"))
        ));

        let evidence = "\"imix_accepted_frames\":{\"eth512_packets\":19998000,\"eth64_packets\":34996500,\"ip_mtu1500_packets\":4999500},";
        let imix = REPEAT
            .replace(
                "v1:zero-copy:q4:b64:eth64:f4096:outbound:nat44-firewall:udp-checksum",
                "v1:zero-copy:q4:b64:ruster-imix-v1:f4096:outbound:nat44-firewall:udp-checksum",
            )
            .replace("\"frame\":\"eth64\"", "\"frame\":\"ruster-imix-v1\"")
            .replace(
                "\"kind\":\"repeat\",",
                &format!("{evidence}\"kind\":\"repeat\","),
            )
            .replace("\"l1_gbps\":0.6719328", "\"l1_gbps\":2.8357164");
        let record = HardwareArtifactRecord::parse(&imix).unwrap();
        let canonical = record.to_json_line().unwrap();
        assert_eq!(HardwareArtifactRecord::parse(&canonical).unwrap(), record);
        assert!(matches!(
            HardwareArtifactRecord::parse(&imix.replace(evidence, "")),
            Err(SchemaError::MissingField("imix_accepted_frames"))
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &imix.replace("\"eth64_packets\":34996500", "\"eth64_packets\":34996499")
            ),
            Err(SchemaError::InvalidField("imix_accepted_frames"))
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(
                &imix.replace("\"l1_gbps\":2.8357164", "\"l1_gbps\":2.8")
            ),
            Err(SchemaError::InvalidField("l1_gbps"))
        ));
        assert!(matches!(
            HardwareArtifactRecord::parse(&REPEAT.replace(
                "\"kind\":\"repeat\",",
                &format!("{evidence}\"kind\":\"repeat\",")
            )),
            Err(SchemaError::InvalidField("imix_accepted_frames"))
        ));
    }

    #[test]
    fn secret_and_topology_redaction_is_recursive_and_deterministic() {
        let hostile = r#"{
            "safe":"kept",
            "hostname":"lab-secret",
            "backup_hostname":"lab-backup",
            "nested":{
                "runner-token":"abc",
                "backup--private key":"def",
                "token_value":"ghi",
                "topology_map":"jkl",
                "host-name":"lab",
                "macAddress":"00:11:22:33:44:55",
                "management_ip":"192.0.2.5",
                "items":[{"serial_number":"xyz","driver":"ixgbe"}]
            },
            "topology":{"cable":"rack-4"}
        }"#;
        let expected = r#"{"nested":{"items":[{"driver":"ixgbe"}]},"safe":"kept"}"#;
        assert_eq!(redact_sensitive_json(hostile).unwrap(), expected);
        assert_eq!(
            redact_sensitive_json(&redact_sensitive_json(hostile).unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn artifact_hash_serialization_is_sorted_and_path_safe() {
        let first = ArtifactHash::new(
            "z/raw.bin",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let second = ArtifactHash::new(
            "a/raw.bin",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        let json = artifact_hashes_json(&[first, second]).to_canonical_json();
        assert!(json.find("a/raw.bin").unwrap() < json.find("z/raw.bin").unwrap());
        assert!(matches!(
            ArtifactHash::new(
                "../secret",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            Err(SchemaError::InvalidField("artifact_hashes.path"))
        ));
    }

    #[test]
    fn json_depth_limit_has_an_exact_boundary() {
        let at_limit = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        assert!(redact_sensitive_json(&at_limit).is_ok());

        let beyond_limit = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        assert!(matches!(
            redact_sensitive_json(&beyond_limit),
            Err(SchemaError::InvalidJson("nesting exceeds depth limit"))
        ));
    }
}

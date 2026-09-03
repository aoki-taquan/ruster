//! Deterministic, NIC-free planning for the frozen hardware benchmark matrix.
//!
//! This module enumerates cases and performs exact wire-rate arithmetic. It
//! does not execute traffic, access hardware, evaluate thresholds, or make
//! performance claims.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::{
    AfxdpMode, DirectionProfile, HardwareCase, HardwareFrame, ImixAcceptedFrames, SchemaError,
    ServiceProfile, TransportProfile,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum HardwarePlanClass {
    Primary,
    FlowOne,
    Flow64Imix,
    SingleQueue,
    CopyMode,
    StandaloneFirewall,
    UdpZero,
    BatchSweep,
}

impl HardwarePlanClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::FlowOne => "flow-one",
            Self::Flow64Imix => "flow64-imix",
            Self::SingleQueue => "single-queue",
            Self::CopyMode => "copy-mode",
            Self::StandaloneFirewall => "standalone-firewall",
            Self::UdpZero => "udp-zero",
            Self::BatchSweep => "batch-sweep",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedHardwareCase {
    pub ordinal: u16,
    pub seed: u64,
    pub class: HardwarePlanClass,
    pub case_id: String,
    pub case: HardwareCase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwarePlan {
    pub version: u32,
    pub cases: Vec<PlannedHardwareCase>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedFrameWireModel {
    pub backend_bytes: u16,
    pub ethernet_bytes_including_fcs: u16,
    pub l1_bytes_with_preamble_ifg: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImixWireModel {
    pub cycle_packets: u16,
    pub eth64_packets: u16,
    pub eth512_packets: u16,
    pub ip_mtu1500_packets: u16,
    pub cycle_l1_bytes_with_preamble_ifg: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWireModel {
    Fixed(FixedFrameWireModel),
    RusterImixV1(ImixWireModel),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareCaseSettings {
    pub mode: AfxdpMode,
    pub queue_count: u16,
    pub batch_size: u16,
    pub flow_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareRateFormula {
    FixedBitsPerSecondOverL1BytesTimesEight,
    ImixBitsPerSecondTimesCyclePacketsOverCycleL1BytesTimesEight,
}

impl HardwareRateFormula {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FixedBitsPerSecondOverL1BytesTimesEight => {
                "bits-per-second/(l1-bytes*bits-per-byte)"
            }
            Self::ImixBitsPerSecondTimesCyclePacketsOverCycleL1BytesTimesEight => {
                "bits-per-second*cycle-packets/(cycle-l1-bytes*bits-per-byte)"
            }
        }
    }

    const fn bits_per_byte(self) -> u8 {
        match self {
            Self::FixedBitsPerSecondOverL1BytesTimesEight
            | Self::ImixBitsPerSecondTimesCyclePacketsOverCycleL1BytesTimesEight => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareWireModelDescriptor {
    pub fixed_eth64: FixedFrameWireModel,
    pub fixed_eth128: FixedFrameWireModel,
    pub fixed_eth512: FixedFrameWireModel,
    pub fixed_ip_mtu1500: FixedFrameWireModel,
    pub imix: ImixWireModel,
    pub imix_cycle: [HardwareFrame; 12],
    pub reference_line_rate_bps: u64,
    pub fixed_rate_formula: HardwareRateFormula,
    pub imix_rate_formula: HardwareRateFormula,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareNormativeDescriptor {
    pub version: u32,
    pub primary_case_count: usize,
    pub control_case_count: usize,
    pub total_case_count: usize,
    pub primary_frames: [HardwareFrame; 5],
    pub control_frames: [HardwareFrame; 3],
    pub directions: [DirectionProfile; 3],
    pub primary_services: [ServiceProfile; 3],
    pub primary_transports: [TransportProfile; 2],
    pub primary_settings: HardwareCaseSettings,
    pub flow_one_settings: HardwareCaseSettings,
    pub flow64_imix_settings: HardwareCaseSettings,
    pub single_queue_settings: HardwareCaseSettings,
    pub copy_mode_settings: HardwareCaseSettings,
    pub standalone_firewall_settings: HardwareCaseSettings,
    pub udp_zero_settings: [HardwareCaseSettings; 4],
    pub batch_sweep_settings: HardwareCaseSettings,
    pub batch_sweep_values: [u16; 3],
    pub control_slice_order: [HardwarePlanClass; 7],
    pub control_nesting: [&'static str; 7],
    pub control_counts: [usize; 7],
    pub wire: HardwareWireModelDescriptor,
    pub setup_semantics: &'static str,
    pub hash_role_semantics: &'static str,
}

pub const HARDWARE_NORMATIVE_DESCRIPTOR_V1: HardwareNormativeDescriptor =
    HardwareNormativeDescriptor {
        version: 1,
        primary_case_count: 5 * 3 * 3 * 2,
        control_case_count: 27 + 9 + 27 + 27 + 18 + 36 + 3,
        total_case_count: (5 * 3 * 3 * 2) + (27 + 9 + 27 + 27 + 18 + 36 + 3),
        primary_frames: [
            HardwareFrame::Eth64,
            HardwareFrame::Eth128,
            HardwareFrame::Eth512,
            HardwareFrame::Ipv4Mtu1500,
            HardwareFrame::RusterImixV1,
        ],
        control_frames: [
            HardwareFrame::Eth64,
            HardwareFrame::Eth512,
            HardwareFrame::Ipv4Mtu1500,
        ],
        directions: [
            DirectionProfile::Outbound,
            DirectionProfile::Inbound,
            DirectionProfile::Bidirectional,
        ],
        primary_services: [
            ServiceProfile::Plain,
            ServiceProfile::Nat44,
            ServiceProfile::Nat44Firewall,
        ],
        primary_transports: [TransportProfile::UdpChecksum, TransportProfile::TcpChecksum],
        primary_settings: HardwareCaseSettings {
            mode: AfxdpMode::ZeroCopy,
            queue_count: 4,
            batch_size: 64,
            flow_count: 4_096,
        },
        flow_one_settings: HardwareCaseSettings {
            mode: AfxdpMode::ZeroCopy,
            queue_count: 4,
            batch_size: 64,
            flow_count: 1,
        },
        flow64_imix_settings: HardwareCaseSettings {
            mode: AfxdpMode::ZeroCopy,
            queue_count: 4,
            batch_size: 64,
            flow_count: 64,
        },
        single_queue_settings: HardwareCaseSettings {
            mode: AfxdpMode::ZeroCopy,
            queue_count: 1,
            batch_size: 64,
            flow_count: 4_096,
        },
        copy_mode_settings: HardwareCaseSettings {
            mode: AfxdpMode::Copy,
            queue_count: 4,
            batch_size: 64,
            flow_count: 4_096,
        },
        standalone_firewall_settings: HardwareCaseSettings {
            mode: AfxdpMode::ZeroCopy,
            queue_count: 4,
            batch_size: 64,
            flow_count: 4_096,
        },
        udp_zero_settings: [
            HardwareCaseSettings {
                mode: AfxdpMode::ZeroCopy,
                queue_count: 4,
                batch_size: 64,
                flow_count: 1,
            },
            HardwareCaseSettings {
                mode: AfxdpMode::ZeroCopy,
                queue_count: 4,
                batch_size: 64,
                flow_count: 64,
            },
            HardwareCaseSettings {
                mode: AfxdpMode::ZeroCopy,
                queue_count: 1,
                batch_size: 64,
                flow_count: 4_096,
            },
            HardwareCaseSettings {
                mode: AfxdpMode::Copy,
                queue_count: 4,
                batch_size: 64,
                flow_count: 4_096,
            },
        ],
        batch_sweep_settings: HardwareCaseSettings {
            mode: AfxdpMode::ZeroCopy,
            queue_count: 4,
            batch_size: 64,
            flow_count: 4_096,
        },
        batch_sweep_values: [1, 32, 256],
        control_slice_order: [
            HardwarePlanClass::FlowOne,
            HardwarePlanClass::Flow64Imix,
            HardwarePlanClass::SingleQueue,
            HardwarePlanClass::CopyMode,
            HardwarePlanClass::StandaloneFirewall,
            HardwarePlanClass::UdpZero,
            HardwarePlanClass::BatchSweep,
        ],
        control_nesting: [
            "flow-one:frame>direction>service",
            "flow64-imix:direction>service",
            "single-queue:frame>direction>service",
            "copy-mode:frame>direction>service",
            "standalone-firewall:frame>direction>transport",
            "udp-zero:profile>frame>direction",
            "batch-sweep:value",
        ],
        control_counts: [27, 9, 27, 27, 18, 36, 3],
        wire: HardwareWireModelDescriptor {
            fixed_eth64: FixedFrameWireModel {
                backend_bytes: 60,
                ethernet_bytes_including_fcs: 64,
                l1_bytes_with_preamble_ifg: 84,
            },
            fixed_eth128: FixedFrameWireModel {
                backend_bytes: 124,
                ethernet_bytes_including_fcs: 128,
                l1_bytes_with_preamble_ifg: 148,
            },
            fixed_eth512: FixedFrameWireModel {
                backend_bytes: 508,
                ethernet_bytes_including_fcs: 512,
                l1_bytes_with_preamble_ifg: 532,
            },
            fixed_ip_mtu1500: FixedFrameWireModel {
                backend_bytes: 1_514,
                ethernet_bytes_including_fcs: 1_518,
                l1_bytes_with_preamble_ifg: 1_538,
            },
            imix: ImixWireModel {
                cycle_packets: 12,
                eth64_packets: 7,
                eth512_packets: 4,
                ip_mtu1500_packets: 1,
                cycle_l1_bytes_with_preamble_ifg: 4_254,
            },
            imix_cycle: [
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth512,
                HardwareFrame::Eth512,
                HardwareFrame::Eth512,
                HardwareFrame::Eth512,
                HardwareFrame::Ipv4Mtu1500,
            ],
            reference_line_rate_bps: 10_000_000_000,
            fixed_rate_formula: HardwareRateFormula::FixedBitsPerSecondOverL1BytesTimesEight,
            imix_rate_formula:
                HardwareRateFormula::ImixBitsPerSecondTimesCyclePacketsOverCycleL1BytesTimesEight,
        },
        setup_semantics: "setup-before-measurement;udp-one-step;tcp-syn-syn-ack-ack",
        hash_role_semantics:
            "siphash-2-4;nat-udp-mapping-peer;nat-tcp-mapping-session;firewall-stateful-flow",
    };

pub const HARDWARE_PLAN_VERSION: u32 = HARDWARE_NORMATIVE_DESCRIPTOR_V1.version;
pub const HARDWARE_PRIMARY_CASE_COUNT: usize = HARDWARE_NORMATIVE_DESCRIPTOR_V1.primary_case_count;
pub const HARDWARE_CONTROL_CASE_COUNT: usize = HARDWARE_NORMATIVE_DESCRIPTOR_V1.control_case_count;
pub const HARDWARE_TOTAL_CASE_COUNT: usize = HARDWARE_NORMATIVE_DESCRIPTOR_V1.total_case_count;
/// Known answer for the complete v1 hardware descriptor and ordered plan.
///
/// This value is deliberately kept separate from the serializer below. It is
/// the compatibility boundary used by the measurement protocol and its
/// independent regression tests.
pub const HARDWARE_PLAN_FINGERPRINT_V1: u64 = 0x7508_ce5c_f2cb_672e;

pub const RUSTER_IMIX_V1_CYCLE: [HardwareFrame; 12] =
    HARDWARE_NORMATIVE_DESCRIPTOR_V1.wire.imix_cycle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A reduced packet-rate fraction whose denominator is always nonzero.
///
/// The invariant is enforced at the public API boundary:
///
/// ```compile_fail
/// use ruster_bench::ExactPacketRate;
///
/// let _invalid = ExactPacketRate {
///     numerator: 1,
///     denominator: 0,
/// };
/// ```
pub struct ExactPacketRate {
    numerator: u128,
    denominator: u128,
}

impl ExactPacketRate {
    fn reduced(numerator: u128, denominator: u128) -> Self {
        let divisor = greatest_common_divisor(numerator, denominator);
        Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        }
    }

    #[must_use]
    pub const fn numerator(self) -> u128 {
        self.numerator
    }

    #[must_use]
    pub const fn denominator(self) -> u128 {
        self.denominator
    }

    #[must_use]
    pub const fn floor_pps(self) -> u128 {
        self.numerator / self.denominator
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HardwarePlanError {
    UnsupportedVersion {
        expected: u32,
        actual: u32,
    },
    ZeroBitRate,
    ArithmeticOverflow,
    InvalidCase {
        case_id: String,
        reason: String,
    },
    CaseIdMismatch {
        expected: String,
        actual: String,
    },
    DuplicateCase(String),
    MissingCase(String),
    UnexpectedCase(String),
    OrderMismatch {
        ordinal: u16,
        expected: String,
        actual: String,
    },
    OrdinalMismatch {
        expected: u16,
        actual: u16,
    },
    SeedMismatch {
        ordinal: u16,
        expected: u64,
        actual: u64,
    },
    ClassMismatch {
        ordinal: u16,
        expected: HardwarePlanClass,
        actual: HardwarePlanClass,
    },
}

impl fmt::Display for HardwarePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    formatter,
                    "unsupported hardware plan version: expected {expected}, got {actual}"
                )
            }
            Self::ZeroBitRate => formatter.write_str("line bit rate must be nonzero"),
            Self::ArithmeticOverflow => formatter.write_str("hardware plan arithmetic overflow"),
            Self::InvalidCase { case_id, reason } => {
                write!(formatter, "invalid hardware case {case_id:?}: {reason}")
            }
            Self::CaseIdMismatch { expected, actual } => {
                write!(
                    formatter,
                    "case id mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::DuplicateCase(case_id) => {
                write!(formatter, "duplicate hardware case {case_id:?}")
            }
            Self::MissingCase(case_id) => write!(formatter, "missing hardware case {case_id:?}"),
            Self::UnexpectedCase(case_id) => {
                write!(formatter, "unexpected hardware case {case_id:?}")
            }
            Self::OrderMismatch {
                ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "hardware case order mismatch at {ordinal}: expected {expected:?}, got {actual:?}"
            ),
            Self::OrdinalMismatch { expected, actual } => {
                write!(
                    formatter,
                    "hardware case ordinal mismatch: expected {expected}, got {actual}"
                )
            }
            Self::SeedMismatch {
                ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "hardware case seed mismatch at {ordinal}: expected {expected}, got {actual}"
            ),
            Self::ClassMismatch {
                ordinal,
                expected,
                actual,
            } => write!(
                formatter,
                "hardware case class mismatch at {ordinal}: expected {expected:?}, got {actual:?}"
            ),
        }
    }
}

impl std::error::Error for HardwarePlanError {}

#[must_use]
pub const fn frame_wire_model(frame: HardwareFrame) -> FrameWireModel {
    let wire = HARDWARE_NORMATIVE_DESCRIPTOR_V1.wire;
    match frame {
        HardwareFrame::Eth64 => FrameWireModel::Fixed(wire.fixed_eth64),
        HardwareFrame::Eth128 => FrameWireModel::Fixed(wire.fixed_eth128),
        HardwareFrame::Eth512 => FrameWireModel::Fixed(wire.fixed_eth512),
        HardwareFrame::Ipv4Mtu1500 => FrameWireModel::Fixed(wire.fixed_ip_mtu1500),
        HardwareFrame::RusterImixV1 => FrameWireModel::RusterImixV1(wire.imix),
    }
}

pub fn line_rate_packet_rate(
    frame: HardwareFrame,
    bits_per_second: u64,
) -> Result<ExactPacketRate, HardwarePlanError> {
    if bits_per_second == 0 {
        return Err(HardwarePlanError::ZeroBitRate);
    }
    let (numerator, denominator) = match frame_wire_model(frame) {
        FrameWireModel::Fixed(model) => (
            u128::from(bits_per_second),
            u128::from(model.l1_bytes_with_preamble_ifg)
                * u128::from(
                    HARDWARE_NORMATIVE_DESCRIPTOR_V1
                        .wire
                        .fixed_rate_formula
                        .bits_per_byte(),
                ),
        ),
        FrameWireModel::RusterImixV1(model) => (
            u128::from(bits_per_second)
                .checked_mul(u128::from(model.cycle_packets))
                .ok_or(HardwarePlanError::ArithmeticOverflow)?,
            u128::from(model.cycle_l1_bytes_with_preamble_ifg)
                * u128::from(
                    HARDWARE_NORMATIVE_DESCRIPTOR_V1
                        .wire
                        .imix_rate_formula
                        .bits_per_byte(),
                ),
        ),
    };
    Ok(ExactPacketRate::reduced(numerator, denominator))
}

pub(crate) fn fixed_l1_bit_count(
    frame: HardwareFrame,
    accepted_packets: u64,
) -> Result<u128, HardwarePlanError> {
    let FrameWireModel::Fixed(model) = frame_wire_model(frame) else {
        return Err(HardwarePlanError::ArithmeticOverflow);
    };
    u128::from(accepted_packets)
        .checked_mul(u128::from(model.l1_bytes_with_preamble_ifg))
        .and_then(|value| {
            value.checked_mul(u128::from(
                HARDWARE_NORMATIVE_DESCRIPTOR_V1
                    .wire
                    .fixed_rate_formula
                    .bits_per_byte(),
            ))
        })
        .ok_or(HardwarePlanError::ArithmeticOverflow)
}

pub(crate) fn imix_l1_bit_count(evidence: ImixAcceptedFrames) -> Result<u128, HardwarePlanError> {
    let wire = HARDWARE_NORMATIVE_DESCRIPTOR_V1.wire;
    let eth64 = u128::from(evidence.eth64_packets)
        .checked_mul(u128::from(wire.fixed_eth64.l1_bytes_with_preamble_ifg));
    let eth512 = u128::from(evidence.eth512_packets)
        .checked_mul(u128::from(wire.fixed_eth512.l1_bytes_with_preamble_ifg));
    let mtu = u128::from(evidence.ip_mtu1500_packets)
        .checked_mul(u128::from(wire.fixed_ip_mtu1500.l1_bytes_with_preamble_ifg));
    eth64
        .and_then(|value| eth512.and_then(|part| value.checked_add(part)))
        .and_then(|value| mtu.and_then(|part| value.checked_add(part)))
        .and_then(|value| value.checked_mul(u128::from(wire.imix_rate_formula.bits_per_byte())))
        .ok_or(HardwarePlanError::ArithmeticOverflow)
}

const FINGERPRINT_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FINGERPRINT_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fingerprint_byte(hash: u64, byte: u8) -> u64 {
    (hash ^ u64::from(byte)).wrapping_mul(FINGERPRINT_PRIME)
}

fn fingerprint_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash = fingerprint_byte(hash, byte);
    }
    hash
}

fn fingerprint_u16(hash: u64, value: u16) -> u64 {
    fingerprint_bytes(hash, &value.to_be_bytes())
}

fn fingerprint_u32(hash: u64, value: u32) -> u64 {
    fingerprint_bytes(hash, &value.to_be_bytes())
}

fn fingerprint_u64(hash: u64, value: u64) -> u64 {
    fingerprint_bytes(hash, &value.to_be_bytes())
}

fn fingerprint_usize(hash: u64, value: usize) -> u64 {
    fingerprint_u64(hash, value as u64)
}

fn fingerprint_string(mut hash: u64, value: &str) -> u64 {
    hash = fingerprint_usize(hash, value.len());
    fingerprint_bytes(hash, value.as_bytes())
}

fn fingerprint_frame(hash: u64, frame: HardwareFrame) -> u64 {
    fingerprint_string(hash, frame.label())
}

fn fingerprint_frame_sequence(mut hash: u64, frames: &[HardwareFrame]) -> u64 {
    hash = fingerprint_usize(hash, frames.len());
    for &frame in frames {
        hash = fingerprint_frame(hash, frame);
    }
    hash
}

fn fingerprint_settings(mut hash: u64, label: &str, settings: HardwareCaseSettings) -> u64 {
    hash = fingerprint_string(hash, label);
    hash = fingerprint_string(hash, settings.mode.label());
    hash = fingerprint_u16(hash, settings.queue_count);
    hash = fingerprint_u16(hash, settings.batch_size);
    fingerprint_u32(hash, settings.flow_count)
}

fn fingerprint_class_sequence(mut hash: u64, classes: &[HardwarePlanClass]) -> u64 {
    hash = fingerprint_usize(hash, classes.len());
    for &class in classes {
        hash = fingerprint_string(hash, class.label());
    }
    hash
}

fn fingerprint_fixed_wire_model(mut hash: u64, label: &str, model: FixedFrameWireModel) -> u64 {
    hash = fingerprint_string(hash, label);
    hash = fingerprint_u16(hash, model.backend_bytes);
    hash = fingerprint_u16(hash, model.ethernet_bytes_including_fcs);
    fingerprint_u16(hash, model.l1_bytes_with_preamble_ifg)
}

fn fingerprint_imix_wire_model(mut hash: u64, model: ImixWireModel) -> u64 {
    hash = fingerprint_string(hash, "imix");
    hash = fingerprint_u16(hash, model.cycle_packets);
    hash = fingerprint_u16(hash, model.eth64_packets);
    hash = fingerprint_u16(hash, model.eth512_packets);
    hash = fingerprint_u16(hash, model.ip_mtu1500_packets);
    fingerprint_u16(hash, model.cycle_l1_bytes_with_preamble_ifg)
}

fn fingerprint_wire_descriptor(mut hash: u64, wire: HardwareWireModelDescriptor) -> u64 {
    hash = fingerprint_string(hash, "wire/v1");
    hash = fingerprint_fixed_wire_model(hash, "eth64", wire.fixed_eth64);
    hash = fingerprint_fixed_wire_model(hash, "eth128", wire.fixed_eth128);
    hash = fingerprint_fixed_wire_model(hash, "eth512", wire.fixed_eth512);
    hash = fingerprint_fixed_wire_model(hash, "ip-mtu1500", wire.fixed_ip_mtu1500);
    hash = fingerprint_imix_wire_model(hash, wire.imix);
    hash = fingerprint_string(hash, "imix-cycle");
    hash = fingerprint_frame_sequence(hash, &wire.imix_cycle);
    hash = fingerprint_u64(hash, wire.reference_line_rate_bps);
    hash = fingerprint_string(hash, wire.fixed_rate_formula.label());
    hash = fingerprint_u8(hash, wire.fixed_rate_formula.bits_per_byte());
    hash = fingerprint_string(hash, wire.imix_rate_formula.label());
    fingerprint_u8(hash, wire.imix_rate_formula.bits_per_byte())
}

fn fingerprint_u8(hash: u64, value: u8) -> u64 {
    fingerprint_byte(hash, value)
}

/// Returns the safe, non-cryptographic identity of the complete normative
/// hardware descriptor. Every value and order that affects plan construction
/// or wire/rate arithmetic is included; no caller may substitute a case-only
/// fingerprint for this descriptor identity.
pub(crate) fn hardware_normative_descriptor_fingerprint(
    descriptor: &HardwareNormativeDescriptor,
) -> u64 {
    let mut hash = fingerprint_string(FINGERPRINT_OFFSET, "ruster.hardware.normative/v2");
    hash = fingerprint_u32(hash, descriptor.version);
    hash = fingerprint_usize(hash, descriptor.primary_case_count);
    hash = fingerprint_usize(hash, descriptor.control_case_count);
    hash = fingerprint_usize(hash, descriptor.total_case_count);

    hash = fingerprint_string(hash, "primary-frames");
    hash = fingerprint_frame_sequence(hash, &descriptor.primary_frames);
    hash = fingerprint_string(hash, "control-frames");
    hash = fingerprint_frame_sequence(hash, &descriptor.control_frames);
    hash = fingerprint_string(hash, "directions");
    hash = fingerprint_usize(hash, descriptor.directions.len());
    for direction in descriptor.directions {
        hash = fingerprint_string(hash, direction.label());
    }
    hash = fingerprint_string(hash, "primary-services");
    hash = fingerprint_usize(hash, descriptor.primary_services.len());
    for service in descriptor.primary_services {
        hash = fingerprint_string(hash, service.label());
    }
    hash = fingerprint_string(hash, "primary-transports");
    hash = fingerprint_usize(hash, descriptor.primary_transports.len());
    for transport in descriptor.primary_transports {
        hash = fingerprint_string(hash, transport.label());
    }

    hash = fingerprint_settings(hash, "primary-settings", descriptor.primary_settings);
    hash = fingerprint_settings(hash, "flow-one-settings", descriptor.flow_one_settings);
    hash = fingerprint_settings(
        hash,
        "flow64-imix-settings",
        descriptor.flow64_imix_settings,
    );
    hash = fingerprint_settings(
        hash,
        "single-queue-settings",
        descriptor.single_queue_settings,
    );
    hash = fingerprint_settings(hash, "copy-mode-settings", descriptor.copy_mode_settings);
    hash = fingerprint_settings(
        hash,
        "standalone-firewall-settings",
        descriptor.standalone_firewall_settings,
    );
    hash = fingerprint_string(hash, "udp-zero-settings");
    hash = fingerprint_usize(hash, descriptor.udp_zero_settings.len());
    for settings in descriptor.udp_zero_settings {
        hash = fingerprint_settings(hash, "profile", settings);
    }
    hash = fingerprint_settings(
        hash,
        "batch-sweep-settings",
        descriptor.batch_sweep_settings,
    );
    hash = fingerprint_string(hash, "batch-sweep-values");
    hash = fingerprint_usize(hash, descriptor.batch_sweep_values.len());
    for value in descriptor.batch_sweep_values {
        hash = fingerprint_u16(hash, value);
    }

    hash = fingerprint_string(hash, "control-slice-order");
    hash = fingerprint_class_sequence(hash, &descriptor.control_slice_order);
    hash = fingerprint_string(hash, "control-nesting");
    hash = fingerprint_usize(hash, descriptor.control_nesting.len());
    for nesting in descriptor.control_nesting {
        hash = fingerprint_string(hash, nesting);
    }
    hash = fingerprint_string(hash, "control-counts");
    hash = fingerprint_usize(hash, descriptor.control_counts.len());
    for count in descriptor.control_counts {
        hash = fingerprint_usize(hash, count);
    }

    hash = fingerprint_wire_descriptor(hash, descriptor.wire);
    hash = fingerprint_string(hash, "setup-semantics");
    hash = fingerprint_string(hash, descriptor.setup_semantics);
    hash = fingerprint_string(hash, "hash-role-semantics");
    fingerprint_string(hash, descriptor.hash_role_semantics)
}

fn fingerprint_case(mut hash: u64, planned: &PlannedHardwareCase) -> u64 {
    hash = fingerprint_u16(hash, planned.ordinal);
    hash = fingerprint_u64(hash, planned.seed);
    hash = fingerprint_string(hash, planned.class.label());
    hash = fingerprint_string(hash, &planned.case_id);
    hash = fingerprint_string(hash, planned.case.mode.label());
    hash = fingerprint_u16(hash, planned.case.queue_count);
    hash = fingerprint_u16(hash, planned.case.batch_size);
    hash = fingerprint_frame(hash, planned.case.frame);
    hash = fingerprint_u32(hash, planned.case.flow_count);
    hash = fingerprint_string(hash, planned.case.direction.label());
    hash = fingerprint_string(hash, planned.case.service.label());
    fingerprint_string(hash, planned.case.transport.label())
}

/// Computes the compatibility identity for the descriptor and the complete
/// ordered plan. This is the only plan fingerprint implementation used by
/// the measurement protocol.
pub(crate) fn hardware_plan_fingerprint(plan: &HardwarePlan) -> u64 {
    let mut hash = hardware_normative_descriptor_fingerprint(&HARDWARE_NORMATIVE_DESCRIPTOR_V1);
    hash = fingerprint_string(hash, "plan/v1");
    hash = fingerprint_u32(hash, plan.version);
    hash = fingerprint_usize(hash, plan.cases.len());
    for planned in &plan.cases {
        hash = fingerprint_case(hash, planned);
    }
    hash
}

pub fn hardware_plan_v1() -> Result<HardwarePlan, HardwarePlanError> {
    let plan = HardwarePlan {
        version: HARDWARE_PLAN_VERSION,
        cases: build_hardware_plan_v1(),
    };
    validate_hardware_plan_v1(&plan)?;
    Ok(plan)
}

pub fn validate_hardware_plan_v1(plan: &HardwarePlan) -> Result<(), HardwarePlanError> {
    if plan.version != HARDWARE_PLAN_VERSION {
        return Err(HardwarePlanError::UnsupportedVersion {
            expected: HARDWARE_PLAN_VERSION,
            actual: plan.version,
        });
    }
    let cases = &plan.cases;
    for planned in cases {
        planned
            .case
            .validate()
            .map_err(|error| invalid_case(&planned.case_id, error))?;
        let expected_id = planned.case.canonical_id();
        if planned.case_id != expected_id {
            return Err(HardwarePlanError::CaseIdMismatch {
                expected: expected_id,
                actual: planned.case_id.clone(),
            });
        }
    }

    let mut supplied_ids = BTreeSet::new();
    for planned in cases {
        if !supplied_ids.insert(planned.case_id.as_str()) {
            return Err(HardwarePlanError::DuplicateCase(planned.case_id.clone()));
        }
    }

    let expected = build_hardware_plan_v1();
    let expected_by_id = expected
        .iter()
        .map(|planned| (planned.case_id.as_str(), planned))
        .collect::<BTreeMap<_, _>>();
    for supplied in cases {
        if !expected_by_id.contains_key(supplied.case_id.as_str()) {
            return Err(HardwarePlanError::UnexpectedCase(supplied.case_id.clone()));
        }
    }
    for expected_case in &expected {
        if !supplied_ids.contains(expected_case.case_id.as_str()) {
            return Err(HardwarePlanError::MissingCase(
                expected_case.case_id.clone(),
            ));
        }
    }

    for (expected_case, actual) in expected.iter().zip(cases) {
        if actual.ordinal != expected_case.ordinal {
            return Err(HardwarePlanError::OrdinalMismatch {
                expected: expected_case.ordinal,
                actual: actual.ordinal,
            });
        }
        if actual.seed != expected_case.seed {
            return Err(HardwarePlanError::SeedMismatch {
                ordinal: expected_case.ordinal,
                expected: expected_case.seed,
                actual: actual.seed,
            });
        }
        if actual.class != expected_case.class {
            return Err(HardwarePlanError::ClassMismatch {
                ordinal: expected_case.ordinal,
                expected: expected_case.class,
                actual: actual.class,
            });
        }
        if actual.case_id != expected_case.case_id {
            return Err(HardwarePlanError::OrderMismatch {
                ordinal: expected_case.ordinal,
                expected: expected_case.case_id.clone(),
                actual: actual.case_id.clone(),
            });
        }
    }
    Ok(())
}

fn invalid_case(case_id: &str, error: SchemaError) -> HardwarePlanError {
    HardwarePlanError::InvalidCase {
        case_id: case_id.to_owned(),
        reason: error.to_string(),
    }
}

fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn build_hardware_plan_v1() -> Vec<PlannedHardwareCase> {
    let descriptor = HARDWARE_NORMATIVE_DESCRIPTOR_V1;
    let mut cases = Vec::with_capacity(HARDWARE_TOTAL_CASE_COUNT);
    for frame in descriptor.primary_frames {
        for direction in descriptor.directions {
            for service in descriptor.primary_services {
                for transport in descriptor.primary_transports {
                    push_case(
                        &mut cases,
                        HardwarePlanClass::Primary,
                        case_from_settings(
                            descriptor.primary_settings,
                            frame,
                            direction,
                            service,
                            transport,
                        ),
                    );
                }
            }
        }
    }

    for frame in descriptor.control_frames {
        for direction in descriptor.directions {
            for service in descriptor.primary_services {
                push_case(
                    &mut cases,
                    descriptor.control_slice_order[0],
                    case_from_settings(
                        descriptor.flow_one_settings,
                        frame,
                        direction,
                        service,
                        TransportProfile::UdpChecksum,
                    ),
                );
            }
        }
    }

    for direction in descriptor.directions {
        for service in descriptor.primary_services {
            push_case(
                &mut cases,
                descriptor.control_slice_order[1],
                case_from_settings(
                    descriptor.flow64_imix_settings,
                    HardwareFrame::RusterImixV1,
                    direction,
                    service,
                    TransportProfile::UdpChecksum,
                ),
            );
        }
    }

    for frame in descriptor.control_frames {
        for direction in descriptor.directions {
            for service in descriptor.primary_services {
                push_case(
                    &mut cases,
                    descriptor.control_slice_order[2],
                    case_from_settings(
                        descriptor.single_queue_settings,
                        frame,
                        direction,
                        service,
                        TransportProfile::UdpChecksum,
                    ),
                );
            }
        }
    }

    for frame in descriptor.control_frames {
        for direction in descriptor.directions {
            for service in descriptor.primary_services {
                push_case(
                    &mut cases,
                    descriptor.control_slice_order[3],
                    case_from_settings(
                        descriptor.copy_mode_settings,
                        frame,
                        direction,
                        service,
                        TransportProfile::UdpChecksum,
                    ),
                );
            }
        }
    }

    for frame in descriptor.control_frames {
        for direction in descriptor.directions {
            for transport in descriptor.primary_transports {
                push_case(
                    &mut cases,
                    descriptor.control_slice_order[4],
                    case_from_settings(
                        descriptor.standalone_firewall_settings,
                        frame,
                        direction,
                        ServiceProfile::Firewall,
                        transport,
                    ),
                );
            }
        }
    }

    for settings in descriptor.udp_zero_settings {
        for frame in descriptor.control_frames {
            for direction in descriptor.directions {
                push_case(
                    &mut cases,
                    descriptor.control_slice_order[5],
                    case_from_settings(
                        settings,
                        frame,
                        direction,
                        ServiceProfile::Plain,
                        TransportProfile::UdpZero,
                    ),
                );
            }
        }
    }

    for batch_size in descriptor.batch_sweep_values {
        let mut settings = descriptor.batch_sweep_settings;
        settings.batch_size = batch_size;
        push_case(
            &mut cases,
            descriptor.control_slice_order[6],
            case_from_settings(
                settings,
                HardwareFrame::RusterImixV1,
                DirectionProfile::Bidirectional,
                ServiceProfile::Nat44Firewall,
                TransportProfile::UdpChecksum,
            ),
        );
    }
    cases
}

const fn case_from_settings(
    settings: HardwareCaseSettings,
    frame: HardwareFrame,
    direction: DirectionProfile,
    service: ServiceProfile,
    transport: TransportProfile,
) -> HardwareCase {
    HardwareCase {
        mode: settings.mode,
        queue_count: settings.queue_count,
        batch_size: settings.batch_size,
        frame,
        flow_count: settings.flow_count,
        direction,
        service,
        transport,
    }
}

fn push_case(cases: &mut Vec<PlannedHardwareCase>, class: HardwarePlanClass, case: HardwareCase) {
    let ordinal = u16::try_from(cases.len()).expect("v1 case count fits u16");
    let case_id = case.canonical_id();
    cases.push(PlannedHardwareCase {
        ordinal,
        seed: u64::from(ordinal) + 1,
        class,
        case_id,
        case,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HardwareArtifactRecord, HardwareSummary};

    #[test]
    fn hardware_plan_has_exact_primary_control_counts_and_stable_order() {
        let first = hardware_plan_v1().unwrap();
        let second = hardware_plan_v1().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.version, HARDWARE_PLAN_VERSION);
        assert_eq!(first.cases.len(), HARDWARE_TOTAL_CASE_COUNT);

        let mut counts = BTreeMap::new();
        for planned in &first.cases {
            *counts.entry(planned.class).or_insert(0_usize) += 1;
        }
        assert_eq!(counts[&HardwarePlanClass::Primary], 90);
        assert_eq!(counts[&HardwarePlanClass::FlowOne], 27);
        assert_eq!(counts[&HardwarePlanClass::Flow64Imix], 9);
        assert_eq!(counts[&HardwarePlanClass::SingleQueue], 27);
        assert_eq!(counts[&HardwarePlanClass::CopyMode], 27);
        assert_eq!(counts[&HardwarePlanClass::StandaloneFirewall], 18);
        assert_eq!(counts[&HardwarePlanClass::UdpZero], 36);
        assert_eq!(counts[&HardwarePlanClass::BatchSweep], 3);

        assert_eq!(first.cases[0].ordinal, 0);
        assert_eq!(first.cases[0].seed, 1);
        assert_eq!(
            first.cases[0].case_id,
            "v1:zero-copy:q4:b64:eth64:f4096:outbound:plain:udp-checksum"
        );
        assert_eq!(first.cases[236].ordinal, 236);
        assert_eq!(first.cases[236].seed, 237);
        assert_eq!(
            first.cases[236].case_id,
            "v1:zero-copy:q4:b256:ruster-imix-v1:f4096:bidirectional:nat44-firewall:udp-checksum"
        );

        assert_eq!(hardware_plan_fingerprint(&first), 0x7508_ce5c_f2cb_672e);
    }

    #[test]
    fn hardware_plan_rejects_version_duplicate_missing_unexpected_order_and_metadata_drift() {
        let plan = hardware_plan_v1().unwrap();

        let mut wrong_version = plan.clone();
        wrong_version.version = 2;
        assert_eq!(
            validate_hardware_plan_v1(&wrong_version),
            Err(HardwarePlanError::UnsupportedVersion {
                expected: 1,
                actual: 2,
            })
        );

        let mut duplicate = plan.clone();
        duplicate.cases[1] = duplicate.cases[0].clone();
        assert!(matches!(
            validate_hardware_plan_v1(&duplicate),
            Err(HardwarePlanError::DuplicateCase(_))
        ));

        let mut missing = plan.clone();
        let missing_id = missing.cases.remove(17).case_id;
        assert_eq!(
            validate_hardware_plan_v1(&missing),
            Err(HardwarePlanError::MissingCase(missing_id))
        );

        let mut unexpected = plan.clone();
        unexpected.cases[0].case.flow_count = 9_999;
        unexpected.cases[0].case_id = unexpected.cases[0].case.canonical_id();
        assert!(matches!(
            validate_hardware_plan_v1(&unexpected),
            Err(HardwarePlanError::UnexpectedCase(_))
        ));

        let mut reordered = plan.clone();
        reordered.cases.swap(0, 1);
        assert!(matches!(
            validate_hardware_plan_v1(&reordered),
            Err(HardwarePlanError::OrdinalMismatch { .. })
        ));

        let mut seed_drift = plan;
        seed_drift.cases[3].seed += 1;
        assert!(matches!(
            validate_hardware_plan_v1(&seed_drift),
            Err(HardwarePlanError::SeedMismatch { ordinal: 3, .. })
        ));
    }

    #[test]
    fn every_planned_case_roundtrips_through_hardware_schema() {
        let plan = hardware_plan_v1().unwrap();
        for planned in plan.cases {
            let record = HardwareArtifactRecord::Summary(HardwareSummary {
                case_id: planned.case_id,
                case: planned.case,
                repeat_count: 1,
                accepted_pps_median: 0.0,
                l1_gbps_median: 0.0,
                loss_ratio_worst: 0.0,
                p50_latency_ns_worst: 0.0,
                p99_latency_ns_worst: 0.0,
                artifact_hashes: Vec::new(),
            });
            let json = record.to_json_line().unwrap();
            assert_eq!(HardwareArtifactRecord::parse(&json).unwrap(), record);
        }
    }

    #[test]
    fn frame_math_imix_and_ten_gigabit_rates_match_known_answers() {
        assert_eq!(
            frame_wire_model(HardwareFrame::Eth64),
            FrameWireModel::Fixed(FixedFrameWireModel {
                backend_bytes: 60,
                ethernet_bytes_including_fcs: 64,
                l1_bytes_with_preamble_ifg: 84,
            })
        );
        assert_eq!(
            frame_wire_model(HardwareFrame::Ipv4Mtu1500),
            FrameWireModel::Fixed(FixedFrameWireModel {
                backend_bytes: 1_514,
                ethernet_bytes_including_fcs: 1_518,
                l1_bytes_with_preamble_ifg: 1_538,
            })
        );
        for frame in [
            HardwareFrame::Eth64,
            HardwareFrame::Eth128,
            HardwareFrame::Eth512,
            HardwareFrame::Ipv4Mtu1500,
        ] {
            let FrameWireModel::Fixed(model) = frame_wire_model(frame) else {
                panic!("fixed frame must have a fixed wire model");
            };
            assert_eq!(
                frame.l1_bytes_with_preamble_ifg(),
                Some(model.l1_bytes_with_preamble_ifg)
            );
        }
        assert_eq!(
            frame_wire_model(HardwareFrame::RusterImixV1),
            FrameWireModel::RusterImixV1(ImixWireModel {
                cycle_packets: 12,
                eth64_packets: 7,
                eth512_packets: 4,
                ip_mtu1500_packets: 1,
                cycle_l1_bytes_with_preamble_ifg: 4_254,
            })
        );
        assert_eq!(
            RUSTER_IMIX_V1_CYCLE,
            [
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth64,
                HardwareFrame::Eth512,
                HardwareFrame::Eth512,
                HardwareFrame::Eth512,
                HardwareFrame::Eth512,
                HardwareFrame::Ipv4Mtu1500,
            ]
        );

        for (frame, numerator, denominator, floor) in [
            (HardwareFrame::Eth64, 312_500_000, 21, 14_880_952),
            (HardwareFrame::Eth128, 312_500_000, 37, 8_445_945),
            (HardwareFrame::Eth512, 312_500_000, 133, 2_349_624),
            (HardwareFrame::Ipv4Mtu1500, 625_000_000, 769, 812_743),
            (HardwareFrame::RusterImixV1, 2_500_000_000, 709, 3_526_093),
        ] {
            let rate = line_rate_packet_rate(frame, 10_000_000_000).unwrap();
            assert_eq!(rate.numerator(), numerator);
            assert_eq!(rate.denominator(), denominator);
            assert_ne!(rate.denominator(), 0);
            assert_eq!(rate.floor_pps(), floor);
        }
        assert_eq!(
            line_rate_packet_rate(HardwareFrame::Eth64, 0),
            Err(HardwarePlanError::ZeroBitRate)
        );
    }

    #[test]
    fn r17_f08_normative_wire_descriptor_has_known_answer_and_numeric_boundaries() {
        let descriptor = HARDWARE_NORMATIVE_DESCRIPTOR_V1;
        assert_eq!(
            hardware_normative_descriptor_fingerprint(&descriptor),
            0xaa9b_ad5f_9e6d_8be7
        );

        for mutate in [
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth64.backend_bytes += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth64.ethernet_bytes_including_fcs += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth64.l1_bytes_with_preamble_ifg += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth128.backend_bytes += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth128.ethernet_bytes_including_fcs += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth128.l1_bytes_with_preamble_ifg += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth512.backend_bytes += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth512.ethernet_bytes_including_fcs += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_eth512.l1_bytes_with_preamble_ifg += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_ip_mtu1500.backend_bytes += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor
                    .wire
                    .fixed_ip_mtu1500
                    .ethernet_bytes_including_fcs += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.fixed_ip_mtu1500.l1_bytes_with_preamble_ifg += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| descriptor.wire.imix.cycle_packets += 1,
            |descriptor: &mut HardwareNormativeDescriptor| descriptor.wire.imix.eth64_packets += 1,
            |descriptor: &mut HardwareNormativeDescriptor| descriptor.wire.imix.eth512_packets += 1,
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.imix.ip_mtu1500_packets += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.imix.cycle_l1_bytes_with_preamble_ifg += 1
            },
            |descriptor: &mut HardwareNormativeDescriptor| {
                descriptor.wire.reference_line_rate_bps += 1
            },
        ] {
            let mut mutated = descriptor;
            mutate(&mut mutated);
            assert_ne!(
                hardware_normative_descriptor_fingerprint(&mutated),
                hardware_normative_descriptor_fingerprint(&descriptor)
            );
        }

        let mut formula = descriptor;
        formula.wire.fixed_rate_formula =
            HardwareRateFormula::ImixBitsPerSecondTimesCyclePacketsOverCycleL1BytesTimesEight;
        assert_ne!(
            hardware_normative_descriptor_fingerprint(&formula),
            hardware_normative_descriptor_fingerprint(&descriptor)
        );
        let mut imix_formula = descriptor;
        imix_formula.wire.imix_rate_formula =
            HardwareRateFormula::FixedBitsPerSecondOverL1BytesTimesEight;
        assert_ne!(
            hardware_normative_descriptor_fingerprint(&imix_formula),
            hardware_normative_descriptor_fingerprint(&descriptor)
        );
    }
}

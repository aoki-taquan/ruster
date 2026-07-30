//! Deterministic, NIC-free planning for the frozen hardware benchmark matrix.
//!
//! This module enumerates cases and performs exact wire-rate arithmetic. It
//! does not execute traffic, access hardware, evaluate thresholds, or make
//! performance claims.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::{
    AfxdpMode, DirectionProfile, HardwareCase, HardwareFrame, SchemaError, ServiceProfile,
    TransportProfile,
};

pub const HARDWARE_PLAN_VERSION: u32 = 1;
pub const HARDWARE_PRIMARY_CASE_COUNT: usize = 90;
pub const HARDWARE_CONTROL_CASE_COUNT: usize = 147;
pub const HARDWARE_TOTAL_CASE_COUNT: usize =
    HARDWARE_PRIMARY_CASE_COUNT + HARDWARE_CONTROL_CASE_COUNT;

pub const RUSTER_IMIX_V1_CYCLE: [HardwareFrame; 12] = [
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
];

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
    match frame {
        HardwareFrame::Eth64 => FrameWireModel::Fixed(FixedFrameWireModel {
            backend_bytes: 60,
            ethernet_bytes_including_fcs: 64,
            l1_bytes_with_preamble_ifg: 84,
        }),
        HardwareFrame::Eth128 => FrameWireModel::Fixed(FixedFrameWireModel {
            backend_bytes: 124,
            ethernet_bytes_including_fcs: 128,
            l1_bytes_with_preamble_ifg: 148,
        }),
        HardwareFrame::Eth512 => FrameWireModel::Fixed(FixedFrameWireModel {
            backend_bytes: 508,
            ethernet_bytes_including_fcs: 512,
            l1_bytes_with_preamble_ifg: 532,
        }),
        HardwareFrame::Ipv4Mtu1500 => FrameWireModel::Fixed(FixedFrameWireModel {
            backend_bytes: 1_514,
            ethernet_bytes_including_fcs: 1_518,
            l1_bytes_with_preamble_ifg: 1_538,
        }),
        HardwareFrame::RusterImixV1 => FrameWireModel::RusterImixV1(ImixWireModel {
            cycle_packets: 12,
            eth64_packets: 7,
            eth512_packets: 4,
            ip_mtu1500_packets: 1,
            cycle_l1_bytes_with_preamble_ifg: 4_254,
        }),
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
            u128::from(model.l1_bytes_with_preamble_ifg) * 8,
        ),
        FrameWireModel::RusterImixV1(model) => (
            u128::from(bits_per_second)
                .checked_mul(u128::from(model.cycle_packets))
                .ok_or(HardwarePlanError::ArithmeticOverflow)?,
            u128::from(model.cycle_l1_bytes_with_preamble_ifg) * 8,
        ),
    };
    Ok(ExactPacketRate::reduced(numerator, denominator))
}

pub fn hardware_plan_v1() -> Result<HardwarePlan, HardwarePlanError> {
    let plan = HardwarePlan {
        version: 1,
        cases: build_hardware_plan_v1(),
    };
    validate_hardware_plan_v1(&plan)?;
    Ok(plan)
}

pub fn validate_hardware_plan_v1(plan: &HardwarePlan) -> Result<(), HardwarePlanError> {
    if plan.version != 1 {
        return Err(HardwarePlanError::UnsupportedVersion {
            expected: 1,
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
    const ALL_FRAMES: [HardwareFrame; 5] = [
        HardwareFrame::Eth64,
        HardwareFrame::Eth128,
        HardwareFrame::Eth512,
        HardwareFrame::Ipv4Mtu1500,
        HardwareFrame::RusterImixV1,
    ];
    const CONTROL_FRAMES: [HardwareFrame; 3] = [
        HardwareFrame::Eth64,
        HardwareFrame::Eth512,
        HardwareFrame::Ipv4Mtu1500,
    ];
    const DIRECTIONS: [DirectionProfile; 3] = [
        DirectionProfile::Outbound,
        DirectionProfile::Inbound,
        DirectionProfile::Bidirectional,
    ];
    const PRIMARY_SERVICES: [ServiceProfile; 3] = [
        ServiceProfile::Plain,
        ServiceProfile::Nat44,
        ServiceProfile::Nat44Firewall,
    ];
    const PRIMARY_TRANSPORTS: [TransportProfile; 2] =
        [TransportProfile::UdpChecksum, TransportProfile::TcpChecksum];

    let mut cases = Vec::with_capacity(HARDWARE_TOTAL_CASE_COUNT);
    for frame in ALL_FRAMES {
        for direction in DIRECTIONS {
            for service in PRIMARY_SERVICES {
                for transport in PRIMARY_TRANSPORTS {
                    push_case(
                        &mut cases,
                        HardwarePlanClass::Primary,
                        case(
                            AfxdpMode::ZeroCopy,
                            4,
                            64,
                            frame,
                            4_096,
                            direction,
                            service,
                            transport,
                        ),
                    );
                }
            }
        }
    }

    for frame in CONTROL_FRAMES {
        for direction in DIRECTIONS {
            for service in PRIMARY_SERVICES {
                push_case(
                    &mut cases,
                    HardwarePlanClass::FlowOne,
                    case(
                        AfxdpMode::ZeroCopy,
                        4,
                        64,
                        frame,
                        1,
                        direction,
                        service,
                        TransportProfile::UdpChecksum,
                    ),
                );
            }
        }
    }

    for direction in DIRECTIONS {
        for service in PRIMARY_SERVICES {
            push_case(
                &mut cases,
                HardwarePlanClass::Flow64Imix,
                case(
                    AfxdpMode::ZeroCopy,
                    4,
                    64,
                    HardwareFrame::RusterImixV1,
                    64,
                    direction,
                    service,
                    TransportProfile::UdpChecksum,
                ),
            );
        }
    }

    for frame in CONTROL_FRAMES {
        for direction in DIRECTIONS {
            for service in PRIMARY_SERVICES {
                push_case(
                    &mut cases,
                    HardwarePlanClass::SingleQueue,
                    case(
                        AfxdpMode::ZeroCopy,
                        1,
                        64,
                        frame,
                        4_096,
                        direction,
                        service,
                        TransportProfile::UdpChecksum,
                    ),
                );
            }
        }
    }

    for frame in CONTROL_FRAMES {
        for direction in DIRECTIONS {
            for service in PRIMARY_SERVICES {
                push_case(
                    &mut cases,
                    HardwarePlanClass::CopyMode,
                    case(
                        AfxdpMode::Copy,
                        4,
                        64,
                        frame,
                        4_096,
                        direction,
                        service,
                        TransportProfile::UdpChecksum,
                    ),
                );
            }
        }
    }

    for frame in CONTROL_FRAMES {
        for direction in DIRECTIONS {
            for transport in PRIMARY_TRANSPORTS {
                push_case(
                    &mut cases,
                    HardwarePlanClass::StandaloneFirewall,
                    case(
                        AfxdpMode::ZeroCopy,
                        4,
                        64,
                        frame,
                        4_096,
                        direction,
                        ServiceProfile::Firewall,
                        transport,
                    ),
                );
            }
        }
    }

    for (mode, queue_count, flow_count) in [
        (AfxdpMode::ZeroCopy, 4, 1),
        (AfxdpMode::ZeroCopy, 4, 64),
        (AfxdpMode::ZeroCopy, 1, 4_096),
        (AfxdpMode::Copy, 4, 4_096),
    ] {
        for frame in CONTROL_FRAMES {
            for direction in DIRECTIONS {
                push_case(
                    &mut cases,
                    HardwarePlanClass::UdpZero,
                    case(
                        mode,
                        queue_count,
                        64,
                        frame,
                        flow_count,
                        direction,
                        ServiceProfile::Plain,
                        TransportProfile::UdpZero,
                    ),
                );
            }
        }
    }

    for batch_size in [1, 32, 256] {
        push_case(
            &mut cases,
            HardwarePlanClass::BatchSweep,
            case(
                AfxdpMode::ZeroCopy,
                4,
                batch_size,
                HardwareFrame::RusterImixV1,
                4_096,
                DirectionProfile::Bidirectional,
                ServiceProfile::Nat44Firewall,
                TransportProfile::UdpChecksum,
            ),
        );
    }
    cases
}

#[allow(clippy::too_many_arguments)]
const fn case(
    mode: AfxdpMode,
    queue_count: u16,
    batch_size: u16,
    frame: HardwareFrame,
    flow_count: u32,
    direction: DirectionProfile,
    service: ServiceProfile,
    transport: TransportProfile,
) -> HardwareCase {
    HardwareCase {
        mode,
        queue_count,
        batch_size,
        frame,
        flow_count,
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

        let mut fingerprint = 0xcbf2_9ce4_8422_2325_u64;
        for byte in first.version.to_be_bytes().into_iter().chain(*b"\n") {
            fingerprint ^= u64::from(byte);
            fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
        }
        for frame in RUSTER_IMIX_V1_CYCLE {
            for byte in frame.label().bytes().chain(*b"\n") {
                fingerprint ^= u64::from(byte);
                fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        for planned in &first.cases {
            for byte in planned
                .ordinal
                .to_be_bytes()
                .into_iter()
                .chain(planned.seed.to_be_bytes())
                .chain([planned.class as u8])
                .chain(planned.case_id.bytes())
                .chain(*b"\n")
            {
                fingerprint ^= u64::from(byte);
                fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        assert_eq!(fingerprint, 0xf68c_80b7_2065_c023);
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
}

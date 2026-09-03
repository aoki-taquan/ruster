use ruster_core::{
    forward_batch_with_resolution, internet_checksum, validate_ipv4_frame, ArpRequestAction,
    DropReason, DynamicNeighborSlot, ForwardingSnapshot, IfId, Interface, Ipv4Address,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, NoTrace, PacketIo,
    ResolutionActionSlot, ResolutionCounters, ResolutionFailureCounters, ResolutionPhase,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, ResolutionStatus, Route,
    ETHERNET_HEADER_LEN,
};
use ruster_io_sim::{RecycleCause, SimIo};

use super::envelope::{
    parse, CaseEnvelope, DropCode, Expected, ParserAccept, ResolutionSummary, Target,
    MAX_CASES_PER_RUN,
};

pub const V1_SEEDS: [u64; 4] = [
    0x6a09_e667_f3bc_c909,
    0x243f_6a88_85a3_08d3,
    0x9e37_79b9_7f4a_7c15,
    0xd1b5_4a32_d192_ed03,
];

pub const SHORT_CASES: u64 = 32;
pub const PARSER_SMOKE_CASES: u64 = 4_096;
pub const CHECKSUM_SMOKE_CASES: u64 = 4_096;
pub const ADMISSION_SMOKE_CASES: u64 = 2_048;
pub const RESOLUTION_SMOKE_CASES: u64 = 2_048;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const UNKNOWN: IfId = IfId(99);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x10]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x20]);
const NEXT_HOP_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x30]);
const PEER_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x40]);
const ARP_SHA: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x41]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const LAN_PEER: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 10]);
const DESTINATION: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const RESOLUTION_LOCAL: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);

#[derive(Debug)]
pub struct CaseFailure {
    pub detail: String,
}

impl CaseFailure {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Copy)]
struct V1Rng(u64);

impl V1Rng {
    fn for_case(target: Target, seed: u64, case_index: u64) -> Self {
        let domain = match target {
            Target::Parser => 0x7061_7273_6572_0001,
            Target::Checksum => 0x6368_6563_6b73_0001,
            Target::Admission => 0x6164_6d69_7373_0001,
            Target::Resolution => 0x7265_736f_6c76_0001,
        };
        Self(seed ^ domain ^ case_index.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x7631_5f72_6e67_0001)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, exclusive_upper: usize) -> usize {
        assert!(exclusive_upper != 0);
        usize::try_from(self.next_u64() % u64::try_from(exclusive_upper).unwrap()).unwrap()
    }

    fn byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.byte();
        }
    }
}

pub fn smoke_budget(target: Target) -> u64 {
    match target {
        Target::Parser => PARSER_SMOKE_CASES,
        Target::Checksum => CHECKSUM_SMOKE_CASES,
        Target::Admission => ADMISSION_SMOKE_CASES,
        Target::Resolution => RESOLUTION_SMOKE_CASES,
    }
}

pub fn generate_encoded(
    target: Target,
    seed: u64,
    case_index: u64,
) -> Result<Vec<u8>, CaseFailure> {
    if case_index >= MAX_CASES_PER_RUN {
        return Err(CaseFailure::new(format!(
            "case index {case_index} exceeds v1 limit {MAX_CASES_PER_RUN}"
        )));
    }
    match target {
        Target::Parser => generate_parser(seed, case_index),
        Target::Checksum => generate_checksum(seed, case_index),
        Target::Admission => generate_admission(seed, case_index),
        Target::Resolution => generate_resolution(seed, case_index),
    }
}

pub fn run_encoded(encoded: &[u8]) -> Result<(), CaseFailure> {
    let case = parse(encoded)
        .map_err(|error| CaseFailure::new(format!("typed envelope parse failed: {error}")))?;
    match case.target {
        Target::Parser => run_parser(&case),
        Target::Checksum => run_checksum(&case),
        Target::Admission => run_admission(&case),
        Target::Resolution => run_resolution(&case),
    }
}

/// Replays the concrete target/FIFO regression from the R16 fixed corpus.
///
/// Keeping this selector separate makes the identity and invalid-future
/// contract runnable without relying on the surrounding matrix lane.
pub fn run_resolution_fixed_identity_fifo_regression() -> Result<(), CaseFailure> {
    let case = super::corpus::past_regressions()
        .into_iter()
        .find(|case| case.name == "resolution-cancel-reuse-and-invalid-future")
        .ok_or_else(|| CaseFailure::new("fixed resolution regression is missing"))?;
    run_encoded(&case.encoded)
}

fn generate_parser(seed: u64, case_index: u64) -> Result<Vec<u8>, CaseFailure> {
    let mut rng = V1Rng::for_case(Target::Parser, seed, case_index);
    let ihl_words = u8::try_from(5 + rng.below(11)).unwrap();
    let payload_len = rng.below(257);
    let padding_len = rng.below(33);
    let flags_offset = rng.next_u64().to_le_bytes()[0..2]
        .try_into()
        .map(u16::from_le_bytes)
        .unwrap();
    let ttl = rng.byte();
    let source = Ipv4Address::from_octets([192, 0, 2, 1 + (rng.byte() % 253)]);
    let destination = Ipv4Address::from_octets([198, 51, 100, 1 + (rng.byte() % 253)]);
    let mut frame = ipv4_frame(
        ihl_words,
        payload_len,
        padding_len,
        flags_offset,
        ttl,
        source,
        destination,
    );
    randomize_ipv4(&mut frame, &mut rng);
    mutate_parser_frame(&mut frame, &mut rng);
    let expected = match model_ipv4(&frame) {
        Ok(value) => Expected::ParserAccept(value),
        Err(reason) => Expected::Drop(
            DropCode::new(reason as u16)
                .map_err(|error| CaseFailure::new(format!("drop code: {error}")))?,
        ),
    };
    CaseEnvelope {
        target: Target::Parser,
        seed,
        case_index,
        now: 0,
        ingress: LAN.0,
        expected,
        payload: &frame,
    }
    .encode()
    .map_err(|error| CaseFailure::new(format!("encode parser case: {error}")))
}

fn generate_checksum(seed: u64, case_index: u64) -> Result<Vec<u8>, CaseFailure> {
    const BOUNDARIES: [usize; 24] = [
        0, 1, 2, 3, 4, 7, 8, 15, 16, 19, 20, 31, 32, 59, 60, 61, 255, 256, 257, 1_499, 1_500,
        1_501, 65_534, 65_535,
    ];
    let mut rng = V1Rng::for_case(Target::Checksum, seed, case_index);
    let length = if usize::try_from(case_index).unwrap() < BOUNDARIES.len() {
        BOUNDARIES[usize::try_from(case_index).unwrap()]
    } else {
        rng.below(4_097)
    };
    let mut payload = vec![0_u8; length];
    rng.fill(&mut payload);
    let expected = Expected::Checksum(oracle_checksum(&payload));
    CaseEnvelope {
        target: Target::Checksum,
        seed,
        case_index,
        now: 0,
        ingress: 0,
        expected,
        payload: &payload,
    }
    .encode()
    .map_err(|error| CaseFailure::new(format!("encode checksum case: {error}")))
}

fn generate_admission(seed: u64, case_index: u64) -> Result<Vec<u8>, CaseFailure> {
    let mut rng = V1Rng::for_case(Target::Admission, seed, case_index);
    let selector = rng.below(10);
    let mut ingress = LAN;
    let (frame, expected) = match selector {
        0 => {
            let mut frame = ipv4_frame(5, 8, 3, 0x4000, 64, LAN_PEER, DESTINATION);
            let mut foreign = [0_u8; 6];
            rng.fill(&mut foreign);
            foreign[0] &= 0xfe;
            if foreign == [0; 6] || foreign == LAN_MAC.0 {
                foreign[5] ^= 0x5a;
            }
            frame[0..6].copy_from_slice(&foreign);
            (
                frame,
                drop_expected(DropReason::EthernetDestinationNotLocal)?,
            )
        }
        1 => (
            ipv4_frame(5, 0, 0, 0x4000, 64, LAN_LOCAL, DESTINATION),
            drop_expected(DropReason::Ipv4SourceLocalAddress)?,
        ),
        2 => {
            let mut frame = ipv4_frame(5, 0, 0, 0x4000, 64, LAN_PEER, DESTINATION);
            frame[12..14].copy_from_slice(&[0x81, 0x00]);
            (frame, drop_expected(DropReason::UnsupportedEtherType)?)
        }
        3 => {
            let mut frame = ipv4_frame(5, 0, 0, 0x4000, 64, LAN_PEER, DESTINATION);
            frame[24] ^= 1;
            (frame, drop_expected(DropReason::Ipv4HeaderChecksumInvalid)?)
        }
        4 => (
            ipv4_frame(6, 0, 0, 0x4000, 64, LAN_PEER, DESTINATION),
            drop_expected(DropReason::Ipv4OptionsUnsupported)?,
        ),
        5 => (
            ipv4_frame(5, 0, 0, 0x4000, 1, LAN_PEER, DESTINATION),
            drop_expected(DropReason::Ipv4TtlExpired)?,
        ),
        6 => (
            arp_frame(MacAddress([0xff; 6]), LAN_PEER, LAN_LOCAL),
            Expected::AdmissionTx,
        ),
        7 => (
            ipv4_frame(
                5,
                11,
                7,
                0x8000 | u16::try_from(rng.below(0x2000)).unwrap(),
                2,
                LAN_PEER,
                DESTINATION,
            ),
            Expected::AdmissionTx,
        ),
        8 => {
            ingress = UNKNOWN;
            (
                ipv4_frame(5, 0, 0, 0x4000, 64, LAN_PEER, DESTINATION),
                drop_expected(DropReason::Ipv4IngressInterfaceUnknown)?,
            )
        }
        _ => (
            arp_frame(WAN_MAC, LAN_PEER, LAN_LOCAL),
            drop_expected(DropReason::EthernetDestinationNotLocal)?,
        ),
    };
    CaseEnvelope {
        target: Target::Admission,
        seed,
        case_index,
        now: 10_000 + case_index,
        ingress: ingress.0,
        expected,
        payload: &frame,
    }
    .encode()
    .map_err(|error| CaseFailure::new(format!("encode admission case: {error}")))
}

fn generate_resolution(seed: u64, case_index: u64) -> Result<Vec<u8>, CaseFailure> {
    let mut rng = V1Rng::for_case(Target::Resolution, seed, case_index);
    let state_capacity = u8::try_from(rng.below(5)).unwrap();
    let action_capacity = u8::try_from(rng.below(5)).unwrap();
    let dynamic_capacity = u8::try_from(rng.below(5)).unwrap();
    let operation_count = 1 + rng.below(32);
    let mut payload = Vec::with_capacity(4 + operation_count * 2);
    payload.extend_from_slice(&[
        state_capacity,
        action_capacity,
        dynamic_capacity,
        u8::try_from(operation_count).unwrap(),
    ]);
    for _ in 0..operation_count {
        payload.push(u8::try_from(rng.below(3)).unwrap());
        payload.push(u8::try_from(rng.below(8)).unwrap());
    }
    let summary = model_resolution(&payload)?;
    CaseEnvelope {
        target: Target::Resolution,
        seed,
        case_index,
        now: 100 + (case_index % 1_000),
        ingress: LAN.0,
        expected: Expected::Resolution(summary),
        payload: &payload,
    }
    .encode()
    .map_err(|error| CaseFailure::new(format!("encode resolution case: {error}")))
}

fn run_parser(case: &CaseEnvelope<'_>) -> Result<(), CaseFailure> {
    let before = case.payload.to_vec();
    let actual = validate_ipv4_frame(case.payload);
    match (case.expected, actual) {
        (Expected::ParserAccept(expected), Ok(actual)) => {
            let actual = ParserAccept {
                header_len: u8::try_from(actual.header_len)
                    .map_err(|_| CaseFailure::new("production header length overflow"))?,
                total_len: u16::try_from(actual.total_len)
                    .map_err(|_| CaseFailure::new("production total length overflow"))?,
                ttl: actual.ttl,
                protocol: actual.protocol,
                source: actual.source.octets(),
                destination: actual.destination.octets(),
                checksum: actual.checksum,
            };
            if actual != expected {
                return Err(CaseFailure::new(format!(
                    "parser accept mismatch expected={expected:?} actual={actual:?}"
                )));
            }
        }
        (Expected::Drop(expected), Err(actual)) if actual as u16 == expected.value() => {}
        (expected, actual) => {
            return Err(CaseFailure::new(format!(
                "parser disposition mismatch expected={expected:?} actual={actual:?}"
            )));
        }
    }
    if case.payload != before {
        return Err(CaseFailure::new("parser mutated input bytes"));
    }
    Ok(())
}

fn run_checksum(case: &CaseEnvelope<'_>) -> Result<(), CaseFailure> {
    let Expected::Checksum(expected) = case.expected else {
        return Err(CaseFailure::new(
            "checksum target has non-checksum expected value",
        ));
    };
    let before = case.payload.to_vec();
    let actual = internet_checksum(case.payload);
    if actual != expected {
        return Err(CaseFailure::new(format!(
            "checksum mismatch expected={expected:#06x} actual={actual:#06x} length={}",
            case.payload.len()
        )));
    }
    if case.payload != before {
        return Err(CaseFailure::new("checksum target mutated input bytes"));
    }
    Ok(())
}

fn run_admission(case: &CaseEnvelope<'_>) -> Result<(), CaseFailure> {
    let (routes, interfaces, neighbors, bindings) = admission_topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
    );
    let before = case.payload.to_vec();
    let before_counters = runtime.counters();
    let before_failure = runtime.failure_counters();
    let mut io = SimIo::new();
    io.inject(IfId(case.ingress), case.payload.to_vec());
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut runtime,
        MonotonicMillis(case.now),
        &mut NoTrace,
    );
    if !report.invariants_hold() {
        return Err(CaseFailure::new("admission report invariant failed"));
    }
    match case.expected {
        Expected::Drop(expected) => {
            if (report.tx_requested, report.dropped, report.consumed) != (0, 1, 0) {
                return Err(CaseFailure::new(format!(
                    "admission expected drop, report=({}, {}, {})",
                    report.tx_requested, report.dropped, report.consumed
                )));
            }
            let recycled = io
                .pop_recycled()
                .ok_or_else(|| CaseFailure::new("admission drop missing recycle"))?;
            match recycled.cause {
                RecycleCause::Forwarding(actual) if actual as u16 == expected.value() => {}
                actual => {
                    return Err(CaseFailure::new(format!(
                        "admission drop mismatch expected={} actual={actual:?}",
                        expected.value()
                    )));
                }
            }
            if recycled.bytes != before {
                return Err(CaseFailure::new("admission drop mutated packet bytes"));
            }
            if runtime.counters() != before_counters
                || runtime.failure_counters() != before_failure
                || runtime.pending_states() != 0
                || runtime.pending_actions() != 0
                || runtime.dynamic_neighbor_count() != 0
            {
                return Err(CaseFailure::new(
                    "admission drop mutated resolution state or counters",
                ));
            }
        }
        Expected::AdmissionTx => {
            if (report.tx_requested, report.dropped, report.consumed) != (1, 0, 0) {
                return Err(CaseFailure::new(format!(
                    "admission expected TX, report=({}, {}, {})",
                    report.tx_requested, report.dropped, report.consumed
                )));
            }
            let tx = io
                .pop_tx()
                .ok_or_else(|| CaseFailure::new("admission success missing TX frame"))?;
            if read_be_u16(&before, 12) == Some(0x0800) {
                let parsed = model_ipv4(&tx.bytes).map_err(|reason| {
                    CaseFailure::new(format!("transmitted IPv4 model failure: {reason:?}"))
                })?;
                if parsed.ttl != 1 {
                    return Err(CaseFailure::new("transmitted IPv4 TTL is not one"));
                }
            } else if tx.bytes.get(6..12) != Some(&LAN_MAC.0) {
                return Err(CaseFailure::new(
                    "ARP reply does not use ingress interface source MAC",
                ));
            }
        }
        expected => {
            return Err(CaseFailure::new(format!(
                "admission target expected type mismatch: {expected:?}"
            )));
        }
    }
    Ok(())
}

fn run_resolution(case: &CaseEnvelope<'_>) -> Result<(), CaseFailure> {
    let Expected::Resolution(expected) = case.expected else {
        return Err(CaseFailure::new(
            "resolution target has non-resolution expected value",
        ));
    };
    let operations = parse_resolution_payload(case.payload)?;
    let (routes, interfaces, bindings) = resolution_topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = vec![ResolutionStateSlot::EMPTY; usize::from(operations.state_capacity)];
    let mut actions = vec![ResolutionActionSlot::EMPTY; usize::from(operations.action_capacity)];
    let mut dynamic = vec![DynamicNeighborSlot::EMPTY; usize::from(operations.dynamic_capacity)];
    let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
        ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 2_000, 60_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
    );
    let model = ResolutionModel::run(&operations, case.now);

    for (step, operation) in operations.operations.iter().copied().enumerate() {
        let now = case
            .now
            .checked_add(u64::try_from(step).unwrap())
            .ok_or_else(|| CaseFailure::new("resolution operation time overflow"))?;
        match operation {
            ResolutionOperation::Miss(target) => {
                let packet = resolution_ipv4(target_address(target));
                let mut io = SimIo::new();
                io.inject(LAN, packet);
                let batch = io.receive(1).unwrap();
                let report = forward_batch_with_resolution(
                    batch,
                    &snapshot,
                    &mut runtime,
                    MonotonicMillis(now),
                    &mut NoTrace,
                );
                if !report.invariants_hold() {
                    return Err(CaseFailure::new(format!(
                        "resolution miss report invariant failed at step={step}"
                    )));
                }
            }
            ResolutionOperation::Learn(target) => {
                let packet = resolution_arp_reply(target_address(target));
                let mut io = SimIo::new();
                io.inject(WAN, packet);
                let batch = io.receive(1).unwrap();
                let report = forward_batch_with_resolution(
                    batch,
                    &snapshot,
                    &mut runtime,
                    MonotonicMillis(now),
                    &mut NoTrace,
                );
                if !report.invariants_hold() || report.consumed != 1 {
                    return Err(CaseFailure::new(format!(
                        "resolution learn disposition failed at step={step}"
                    )));
                }
            }
            ResolutionOperation::InvalidFuture => {
                let mut packet = resolution_ipv4(DESTINATION);
                packet[0..6].copy_from_slice(&[0x02, 9, 9, 9, 9, 9]);
                let original = packet.clone();
                let before_evidence = capture_resolution_evidence(&runtime);
                let mut io = SimIo::new();
                io.inject(LAN, packet);
                let batch = io.receive(1).unwrap();
                let report = forward_batch_with_resolution(
                    batch,
                    &snapshot,
                    &mut runtime,
                    MonotonicMillis(
                        now.checked_add(1_000_000)
                            .ok_or_else(|| CaseFailure::new("invalid future time overflow"))?,
                    ),
                    &mut NoTrace,
                );
                let recycled = io
                    .pop_recycled()
                    .ok_or_else(|| CaseFailure::new("invalid future packet missing recycle"))?;
                let after = capture_resolution_evidence(&runtime);
                if report.dropped != 1 || recycled.bytes != original {
                    return Err(CaseFailure::new(format!(
                        "invalid future packet mutated resolution state at step={step}"
                    )));
                }
                assert_resolution_invalid_future_preserves(&before_evidence, &after);
            }
        }
    }
    let actual = visible_resolution_summary(&runtime)?;
    if actual != expected {
        return Err(CaseFailure::new(format!(
            "resolution summary mismatch expected={expected:?} actual={actual:?}"
        )));
    }
    let actual_evidence = capture_resolution_evidence(&runtime);
    let expected_evidence = model.evidence();
    if actual_evidence != expected_evidence {
        return Err(CaseFailure::new(format!(
            "resolution typed evidence mismatch expected={expected_evidence:?} actual={actual_evidence:?}"
        )));
    }
    Ok(())
}

fn visible_resolution_summary(
    runtime: &ResolutionRuntime<'_>,
) -> Result<ResolutionSummary, CaseFailure> {
    let counters = runtime.counters();
    Ok(ResolutionSummary {
        pending_states: u16::try_from(runtime.pending_states())
            .map_err(|_| CaseFailure::new("pending state count overflow"))?,
        pending_actions: u16::try_from(runtime.pending_actions())
            .map_err(|_| CaseFailure::new("pending action count overflow"))?,
        dynamic_neighbors: u16::try_from(runtime.dynamic_neighbor_count())
            .map_err(|_| CaseFailure::new("dynamic neighbor count overflow"))?,
        queued: u32::try_from(counters.queued)
            .map_err(|_| CaseFailure::new("queued counter overflow"))?,
        suppressed: u32::try_from(counters.suppressed)
            .map_err(|_| CaseFailure::new("suppressed counter overflow"))?,
        state_full: u32::try_from(counters.state_full)
            .map_err(|_| CaseFailure::new("state_full counter overflow"))?,
        action_full: u32::try_from(counters.action_full)
            .map_err(|_| CaseFailure::new("action_full counter overflow"))?,
        clock_regressions: u32::try_from(counters.clock_regressions)
            .map_err(|_| CaseFailure::new("clock counter overflow"))?,
    })
}

#[derive(Clone, Copy)]
enum ResolutionOperation {
    Miss(u8),
    Learn(u8),
    InvalidFuture,
}

struct ResolutionOperations {
    state_capacity: u8,
    action_capacity: u8,
    dynamic_capacity: u8,
    operations: Vec<ResolutionOperation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolutionStateEvidence {
    occupied: bool,
    egress: IfId,
    target: Ipv4Address,
    action: ArpRequestAction,
    generation: u64,
    attempts: u16,
    accepted_attempts: u16,
    requested_at: MonotonicMillis,
    failed_at: MonotonicMillis,
    phase: ResolutionPhase,
    failure_notified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DynamicNeighborEvidence {
    occupied: bool,
    interface: IfId,
    target: Ipv4Address,
    mac: MacAddress,
    refreshed_at: MonotonicMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolutionEvidence {
    state_slots: Vec<ResolutionStateEvidence>,
    action_slots: Vec<Option<(ArpRequestAction, u64)>>,
    dynamic_slots: Vec<DynamicNeighborEvidence>,
    fifo_actions: Vec<(ArpRequestAction, u64)>,
    statuses: Vec<Option<ResolutionStatus>>,
    counters: ResolutionCounters,
    failure_counters: ResolutionFailureCounters,
    last_observed_at: Option<MonotonicMillis>,
    publication_epoch: u128,
}

fn empty_action() -> ArpRequestAction {
    ArpRequestAction {
        egress: IfId(0),
        source_mac: MacAddress([0; 6]),
        source_ip: Ipv4Address::from_octets([0; 4]),
        target_ip: Ipv4Address::from_octets([0; 4]),
    }
}

fn empty_state(generation: u64) -> ResolutionStateEvidence {
    ResolutionStateEvidence {
        occupied: false,
        egress: IfId(0),
        target: Ipv4Address::from_octets([0; 4]),
        action: empty_action(),
        generation,
        attempts: 0,
        accepted_attempts: 0,
        requested_at: MonotonicMillis(0),
        failed_at: MonotonicMillis(0),
        phase: ResolutionPhase::InitialQueued,
        failure_notified: false,
    }
}

fn state_evidence(slot: ResolutionStateSlot) -> ResolutionStateEvidence {
    ResolutionStateEvidence {
        occupied: slot.is_occupied(),
        egress: slot.egress(),
        target: slot.target(),
        action: slot.action(),
        generation: slot.generation(),
        attempts: slot.attempts(),
        accepted_attempts: slot.accepted_attempts(),
        requested_at: slot.requested_at(),
        failed_at: slot.failed_at(),
        phase: slot.phase(),
        failure_notified: slot.failure_notified(),
    }
}

fn dynamic_neighbor_evidence(slot: DynamicNeighborSlot) -> DynamicNeighborEvidence {
    DynamicNeighborEvidence {
        occupied: slot.is_occupied(),
        interface: slot.interface(),
        target: slot.target(),
        mac: slot.mac(),
        refreshed_at: slot.refreshed_at(),
    }
}

fn capture_resolution_evidence(runtime: &ResolutionRuntime<'_>) -> ResolutionEvidence {
    ResolutionEvidence {
        state_slots: runtime
            .state_slots()
            .iter()
            .copied()
            .map(state_evidence)
            .collect(),
        action_slots: runtime
            .action_slots()
            .iter()
            .copied()
            .map(ResolutionActionSlot::queued)
            .collect(),
        dynamic_slots: runtime
            .dynamic_neighbor_slots()
            .iter()
            .copied()
            .map(dynamic_neighbor_evidence)
            .collect(),
        fifo_actions: (0..runtime.pending_actions())
            .map(|position| {
                runtime
                    .queued_action(position)
                    .expect("resolution FIFO evidence is internally bounded")
            })
            .collect(),
        statuses: (0..8)
            .map(|index| runtime.status(WAN, target_address(index)))
            .collect(),
        counters: runtime.counters(),
        failure_counters: runtime.failure_counters(),
        last_observed_at: runtime.last_observed_at(),
        publication_epoch: runtime.publication_epoch(),
    }
}

struct ResolutionModel {
    states: Vec<ResolutionStateEvidence>,
    actions: Vec<Option<(ArpRequestAction, u64)>>,
    dynamic: Vec<DynamicNeighborEvidence>,
    counters: ResolutionCounters,
    failure_counters: ResolutionFailureCounters,
    last_observed_at: Option<MonotonicMillis>,
    publication_epoch: u128,
}

impl ResolutionModel {
    fn run(operations: &ResolutionOperations, start_now: u64) -> Self {
        let mut model = Self {
            states: vec![empty_state(0); usize::from(operations.state_capacity)],
            actions: vec![None; usize::from(operations.action_capacity)],
            dynamic: vec![
                DynamicNeighborEvidence {
                    occupied: false,
                    interface: IfId(0),
                    target: Ipv4Address::from_octets([0; 4]),
                    mac: MacAddress([0; 6]),
                    refreshed_at: MonotonicMillis(0),
                };
                usize::from(operations.dynamic_capacity)
            ],
            counters: ResolutionCounters::default(),
            failure_counters: ResolutionFailureCounters::default(),
            last_observed_at: None,
            publication_epoch: 1,
        };
        for (step, operation) in operations.operations.iter().copied().enumerate() {
            let now = MonotonicMillis(
                start_now
                    .checked_add(u64::try_from(step).expect("bounded resolution step fits u64"))
                    .expect("bounded resolution time fits u64"),
            );
            match operation {
                ResolutionOperation::Miss(target) => model.miss(target, now),
                ResolutionOperation::Learn(target) => model.learn(target, now),
                ResolutionOperation::InvalidFuture => {}
            }
        }
        model
    }

    fn observe(&mut self, now: MonotonicMillis) -> bool {
        if self.last_observed_at.is_some_and(|last| now < last) {
            self.counters.clock_regressions += 1;
            return false;
        }
        self.last_observed_at = Some(now);
        true
    }

    fn miss(&mut self, target_index: u8, now: MonotonicMillis) {
        let target = target_address(target_index);
        if !self.observe(now) {
            return;
        }
        if self
            .dynamic
            .iter()
            .any(|slot| slot.occupied && slot.interface == WAN && slot.target == target)
        {
            return;
        }
        if let Some(state) = self
            .states
            .iter()
            .find(|state| state.occupied && state.egress == WAN && state.target == target)
        {
            if matches!(
                state.phase,
                ResolutionPhase::InitialQueued | ResolutionPhase::RetryQueued
            ) {
                self.counters.suppressed += 1;
                self.failure_counters.capture_full += 1;
                return;
            }
        }
        let Some(index) = self.states.iter().position(|state| !state.occupied) else {
            self.counters.state_full += 1;
            return;
        };
        if self.actions.iter().all(Option::is_some) {
            self.counters.action_full += 1;
            return;
        }
        let action = ArpRequestAction {
            egress: WAN,
            source_mac: WAN_MAC,
            source_ip: RESOLUTION_LOCAL,
            target_ip: target,
        };
        let generation = self.states[index].generation.wrapping_add(1);
        self.states[index] = ResolutionStateEvidence {
            occupied: true,
            egress: WAN,
            target,
            action,
            generation,
            attempts: 0,
            accepted_attempts: 0,
            requested_at: MonotonicMillis(0),
            failed_at: MonotonicMillis(0),
            phase: ResolutionPhase::InitialQueued,
            failure_notified: false,
        };
        let queue_index = self
            .actions
            .iter()
            .position(Option::is_none)
            .expect("model action capacity was checked");
        self.actions[queue_index] = Some((action, generation));
        self.counters.queued += 1;
        if self.states.iter().any(|state| {
            state.occupied
                && state.egress == WAN
                && state.target == target
                && matches!(
                    state.phase,
                    ResolutionPhase::InitialQueued
                        | ResolutionPhase::Waiting
                        | ResolutionPhase::RetryQueued
                )
        }) {
            // The production resolution composition attempts to retain an
            // ICMP failure candidate after every eligible unresolved packet.
            // This model has no failure-hold backing by design, so the
            // bounded semantic result is a capture-full observation.
            self.failure_counters.capture_full += 1;
        }
    }

    fn learn(&mut self, target_index: u8, now: MonotonicMillis) {
        let target = target_address(target_index);
        if !self.observe(now) {
            return;
        }
        if let Some(index) = self
            .dynamic
            .iter()
            .position(|slot| slot.occupied && slot.interface == WAN && slot.target == target)
        {
            self.dynamic[index].mac = ARP_SHA;
            self.dynamic[index].refreshed_at = now;
            self.clear_resolution(target);
            return;
        }
        let Some(index) = self.dynamic.iter().position(|slot| !slot.occupied) else {
            return;
        };
        self.dynamic[index] = DynamicNeighborEvidence {
            occupied: true,
            interface: WAN,
            target,
            mac: ARP_SHA,
            refreshed_at: now,
        };
        self.clear_resolution(target);
    }

    fn clear_resolution(&mut self, target: Ipv4Address) {
        for state in &mut self.states {
            if state.occupied && state.egress == WAN && state.target == target {
                *state = empty_state(state.generation);
            }
        }
        let retained: Vec<_> = self
            .actions
            .iter()
            .copied()
            .flatten()
            .filter(|(action, _)| action.target_ip != target)
            .collect();
        self.actions.fill(None);
        for (index, action) in retained.into_iter().enumerate().take(self.actions.len()) {
            self.actions[index] = Some(action);
        }
    }

    fn status(&self, target: Ipv4Address) -> Option<ResolutionStatus> {
        self.states
            .iter()
            .find(|state| state.occupied && state.egress == WAN && state.target == target)
            .map(|state| ResolutionStatus {
                phase: state.phase,
                attempts: state.attempts,
                accepted_attempts: state.accepted_attempts,
                generation: state.generation,
                requested_at: (state.attempts != 0).then_some(state.requested_at),
                failed_at: (state.phase == ResolutionPhase::Failed).then_some(state.failed_at),
                terminal_notified: state.failure_notified,
            })
    }

    fn evidence(&self) -> ResolutionEvidence {
        ResolutionEvidence {
            state_slots: self.states.clone(),
            action_slots: self.actions.clone(),
            dynamic_slots: self.dynamic.clone(),
            fifo_actions: self.actions.iter().copied().flatten().collect(),
            statuses: (0..8)
                .map(|index| self.status(target_address(index)))
                .collect(),
            counters: self.counters,
            failure_counters: self.failure_counters,
            last_observed_at: self.last_observed_at,
            publication_epoch: self.publication_epoch,
        }
    }

    fn summary(&self) -> ResolutionSummary {
        ResolutionSummary {
            pending_states: u16::try_from(
                self.states.iter().filter(|state| state.occupied).count(),
            )
            .expect("bounded resolution state count fits u16"),
            pending_actions: u16::try_from(
                self.actions.iter().filter(|slot| slot.is_some()).count(),
            )
            .expect("bounded resolution action count fits u16"),
            dynamic_neighbors: u16::try_from(
                self.dynamic.iter().filter(|slot| slot.occupied).count(),
            )
            .expect("bounded dynamic neighbor count fits u16"),
            queued: u32::try_from(self.counters.queued).expect("bounded queued counter fits u32"),
            suppressed: u32::try_from(self.counters.suppressed)
                .expect("bounded suppressed counter fits u32"),
            state_full: u32::try_from(self.counters.state_full)
                .expect("bounded state-full counter fits u32"),
            action_full: u32::try_from(self.counters.action_full)
                .expect("bounded action-full counter fits u32"),
            clock_regressions: u32::try_from(self.counters.clock_regressions)
                .expect("bounded clock counter fits u32"),
        }
    }
}

fn assert_resolution_invalid_future_preserves(
    before: &ResolutionEvidence,
    after: &ResolutionEvidence,
) {
    assert_eq!(before.state_slots, after.state_slots);
    assert_eq!(before.action_slots, after.action_slots);
    assert_eq!(before.dynamic_slots, after.dynamic_slots);
    assert_eq!(before.fifo_actions, after.fifo_actions);
    assert_eq!(before.statuses, after.statuses);
    assert_eq!(before.failure_counters, after.failure_counters);
    assert_eq!(before.last_observed_at, after.last_observed_at);
    assert_eq!(before.publication_epoch, after.publication_epoch);
    assert!(
        after.counters.clock_regressions >= before.counters.clock_regressions,
        "clock-regression counter must not decrease"
    );
    let clock_delta = after.counters.clock_regressions - before.counters.clock_regressions;
    assert!(
        clock_delta <= 1,
        "only one clock-regression counter may change"
    );
    let mut before_without_clock = before.counters;
    let mut after_without_clock = after.counters;
    before_without_clock.clock_regressions = 0;
    after_without_clock.clock_regressions = 0;
    assert_eq!(before_without_clock, after_without_clock);
}

fn parse_resolution_payload(payload: &[u8]) -> Result<ResolutionOperations, CaseFailure> {
    let header = payload
        .get(0..4)
        .ok_or_else(|| CaseFailure::new("resolution operation header truncated"))?;
    let operation_count = usize::from(header[3]);
    if header[0] > 4 || header[1] > 4 || header[2] > 4 || operation_count > 64 {
        return Err(CaseFailure::new(
            "resolution capacity or operation count exceeds v1 bound",
        ));
    }
    if payload.len() != 4 + operation_count * 2 {
        return Err(CaseFailure::new(
            "resolution operation payload length mismatch",
        ));
    }
    let mut operations = Vec::with_capacity(operation_count);
    for operation in payload[4..].chunks_exact(2) {
        if operation[1] >= 8 {
            return Err(CaseFailure::new("resolution target index exceeds v1 bound"));
        }
        operations.push(match operation[0] {
            0 => ResolutionOperation::Miss(operation[1]),
            1 => ResolutionOperation::Learn(operation[1]),
            2 => ResolutionOperation::InvalidFuture,
            _ => return Err(CaseFailure::new("unknown resolution operation tag")),
        });
    }
    Ok(ResolutionOperations {
        state_capacity: header[0],
        action_capacity: header[1],
        dynamic_capacity: header[2],
        operations,
    })
}

fn model_resolution(payload: &[u8]) -> Result<ResolutionSummary, CaseFailure> {
    let operations = parse_resolution_payload(payload)?;
    Ok(ResolutionModel::run(&operations, 100).summary())
}

fn drop_expected(reason: DropReason) -> Result<Expected, CaseFailure> {
    DropCode::new(reason as u16)
        .map(Expected::Drop)
        .map_err(|error| CaseFailure::new(format!("drop expected: {error}")))
}

fn model_ipv4(frame: &[u8]) -> Result<ParserAccept, DropReason> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(DropReason::EthernetHeaderTruncated);
    }
    if read_be_u16(frame, 12) != Some(0x0800) {
        return Err(DropReason::UnsupportedEtherType);
    }
    let available = frame.len() - ETHERNET_HEADER_LEN;
    if available < 20 {
        return Err(DropReason::Ipv4HeaderTruncated);
    }
    let first = frame[ETHERNET_HEADER_LEN];
    if first >> 4 != 4 {
        return Err(DropReason::Ipv4VersionUnsupported);
    }
    let ihl_words = usize::from(first & 0x0f);
    if ihl_words < 5 {
        return Err(DropReason::Ipv4IhlTooSmall);
    }
    let header_len = ihl_words * 4;
    if header_len > available {
        return Err(DropReason::Ipv4HeaderLengthExceedsPacket);
    }
    let total_len = usize::from(read_be_u16(frame, 16).unwrap());
    if total_len < header_len {
        return Err(DropReason::Ipv4TotalLengthTooSmall);
    }
    if total_len > available {
        return Err(DropReason::Ipv4TotalLengthExceedsPacket);
    }
    if oracle_checksum(&frame[14..14 + header_len]) != 0 {
        return Err(DropReason::Ipv4HeaderChecksumInvalid);
    }
    Ok(ParserAccept {
        header_len: u8::try_from(header_len).unwrap(),
        total_len: u16::try_from(total_len).unwrap(),
        ttl: frame[22],
        protocol: frame[23],
        source: frame[26..30].try_into().unwrap(),
        destination: frame[30..34].try_into().unwrap(),
        checksum: read_be_u16(frame, 24).unwrap(),
    })
}

fn oracle_checksum(bytes: &[u8]) -> u16 {
    let mut high = 0_u64;
    let mut low = 0_u64;
    for (index, byte) in bytes.iter().enumerate() {
        if index & 1 == 0 {
            high += u64::from(*byte);
        } else {
            low += u64::from(*byte);
        }
    }
    let mut sum = (high << 8) + low;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn install_oracle_checksum(frame: &mut [u8]) {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    frame[24..26].fill(0);
    let checksum = oracle_checksum(&frame[14..14 + header_len]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

#[allow(clippy::too_many_arguments)]
fn ipv4_frame(
    ihl_words: u8,
    payload_len: usize,
    padding_len: usize,
    flags_offset: u16,
    ttl: u8,
    source: Ipv4Address,
    destination: Ipv4Address,
) -> Vec<u8> {
    let header_len = usize::from(ihl_words) * 4;
    let total_len = header_len + payload_len;
    let mut frame = vec![0_u8; ETHERNET_HEADER_LEN + total_len + padding_len];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&PEER_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x40 | ihl_words;
    frame[15] = 0x2e;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x6d5a_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
    frame[22] = ttl;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    for (index, byte) in frame[34..14 + header_len].iter_mut().enumerate() {
        *byte = u8::try_from((index * 29 + 7) & 0xff).unwrap();
    }
    for (index, byte) in frame[14 + header_len..14 + total_len]
        .iter_mut()
        .enumerate()
    {
        *byte = u8::try_from((index * 17 + 3) & 0xff).unwrap();
    }
    frame[14 + total_len..].fill(0xa5);
    install_oracle_checksum(&mut frame);
    frame
}

fn randomize_ipv4(frame: &mut [u8], rng: &mut V1Rng) {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    frame[15] = rng.byte();
    frame[18..20].copy_from_slice(&rng.next_u64().to_le_bytes()[0..2]);
    frame[23] = rng.byte();
    rng.fill(&mut frame[34..14 + header_len]);
    rng.fill(&mut frame[14 + header_len..]);
    install_oracle_checksum(frame);
}

fn mutate_parser_frame(frame: &mut Vec<u8>, rng: &mut V1Rng) {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    let total_len = usize::from(read_be_u16(frame, 16).unwrap());
    match rng.below(12) {
        0 => frame.truncate(rng.below(frame.len() + 1)),
        1 => {
            let ether_type = [0x0800_u16, 0x0806, 0x8100, 0x88a8, 0x86dd][rng.below(5)];
            frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
        }
        2 => frame[14] = rng.byte(),
        3 => frame[16..18].copy_from_slice(&rng.next_u64().to_le_bytes()[0..2]),
        4 => {
            let index = 14 + rng.below(header_len);
            frame[index] ^= 1 << rng.below(8);
        }
        5 if total_len > header_len => {
            let index = 14 + header_len + rng.below(total_len - header_len);
            frame[index] ^= rng.byte() | 1;
        }
        6 => frame[20..22].copy_from_slice(&rng.next_u64().to_le_bytes()[0..2]),
        7 => frame[22] = rng.byte(),
        8 => frame[24..26].copy_from_slice(&rng.next_u64().to_le_bytes()[0..2]),
        9 => frame.extend((0..rng.below(17)).map(|_| rng.byte())),
        10 if header_len > 20 => {
            let index = 34 + rng.below(header_len - 20);
            frame[index] ^= rng.byte() | 1;
        }
        _ => {}
    }
}

fn arp_frame(
    ethernet_destination: MacAddress,
    sender: Ipv4Address,
    target: Ipv4Address,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&ethernet_destination.0);
    frame[6..12].copy_from_slice(&PEER_MAC.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&ARP_SHA.0);
    frame[28..32].copy_from_slice(&sender.octets());
    frame[38..42].copy_from_slice(&target.octets());
    frame
}

fn resolution_arp_reply(sender: Ipv4Address) -> Vec<u8> {
    let mut frame = arp_frame(WAN_MAC, sender, RESOLUTION_LOCAL);
    frame[20..22].copy_from_slice(&2_u16.to_be_bytes());
    frame
}

fn resolution_ipv4(destination: Ipv4Address) -> Vec<u8> {
    ipv4_frame(5, 0, 0, 0x4000, 64, LAN_PEER, destination)
}

fn target_address(index: u8) -> Ipv4Address {
    Ipv4Address::from_octets([198, 51, 100, 10 + index])
}

fn admission_topology() -> (
    [Route; 1],
    [Interface; 2],
    [Neighbor; 1],
    [LocalIpv4Binding; 1],
) {
    (
        [Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GATEWAY)).unwrap()],
        [
            Interface {
                id: LAN,
                mac: LAN_MAC,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
            },
        ],
        [Neighbor {
            interface: WAN,
            target: GATEWAY,
            mac: NEXT_HOP_MAC,
        }],
        [LocalIpv4Binding {
            interface: LAN,
            address: LAN_LOCAL,
        }],
    )
}

fn resolution_topology() -> ([Route; 1], [Interface; 2], [LocalIpv4Binding; 2]) {
    (
        [Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap()],
        [
            Interface {
                id: LAN,
                mac: LAN_MAC,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
            },
        ],
        [
            LocalIpv4Binding {
                interface: LAN,
                address: LAN_LOCAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: RESOLUTION_LOCAL,
            },
        ],
    )
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let word = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes(word.try_into().unwrap()))
}

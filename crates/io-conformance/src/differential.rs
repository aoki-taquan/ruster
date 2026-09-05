//! Deterministic, unprivileged differential contract coverage.
//!
//! This module is the always-on model lane. One core contract execution is
//! normalized into a terminal observation, then each backend model applies its
//! own ownership/admission transition to that observation. The real `SimIo`
//! comparison lives in the `io-sim` integration target (the conformance crate
//! cannot depend on its own dev-dependency without creating a cycle). The
//! privileged live three-way lane is implemented separately in
//! [`crate::differential_live`] and owns the real native backend setup.

use ruster_core::{
    forward_batch, BatchCompletion, DropReason, ForwardingSnapshot, IfId, Interface, Ipv4Mtu, Ipv4Address,
    MacAddress, Neighbor, NoTrace, PacketBatch, PacketLease, PacketSlot,
    PublicationQuiescenceDisposition, Route, SlotCompletion,
};
use ruster_io_afpacket::{TxFrameModel, TxOwnership};
use ruster_io_xdp_native::{
    abi::{XdpDescriptor, XdpRingOffset},
    NativeRingError, RingEntries, RingName, TxProducer,
};
use std::{cell::RefCell, convert::Infallible};

const LAN: IfId = IfId(11);
const WAN: IfId = IfId(22);
const UNKNOWN: IfId = IfId(99);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 11]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 22]);
const UNKNOWN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 99]);
const NEXT_HOP_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 2, 2]);
const DESTINATION_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const DESTINATION_PREFIX: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 0]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DifferentialCase {
    pub seed: u64,
    pub iteration: u64,
    pub frame: Vec<u8>,
    pub ingress: u16,
    pub rx_budget: usize,
    pub tx_capacity: usize,
    pub state: u8,
    /// Number of RX slots injected for this case.  The same frame bytes are
    /// used for each slot so the case remains compact and reproducible.
    pub packet_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForwardingResult {
    Forwarded,
    Dropped(DropReason),
    Consumed(ruster_core::ConsumeReason),
    NoPacket,
}

/// Coarse, backend-independent category for an observable batch error.
///
/// The concrete AF_PACKET and AF_XDP error enums intentionally remain private
/// to their adapters.  Comparing this category still distinguishes RX, TX,
/// completion, and quiescence failures without comparing backend-only errno
/// details or allocating a packet-path string.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCategory {
    None,
    Receive,
    Transmit,
    Completion,
    Kick,
    Wait,
    Quiescence,
    Ring,
    Mapping,
    Ownership,
    Setup,
    Platform,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedObservation {
    pub received: usize,
    pub dropped: usize,
    pub consumed: usize,
    pub tx_requested: usize,
    pub tx_accepted: usize,
    pub tx_rejected: usize,
    pub recycled: usize,
    pub error_present: bool,
    pub batch_invariants: bool,
    pub completion_invariants: bool,
    pub forwarding: Vec<ForwardingResult>,
    pub error_category: ErrorCategory,
    /// The only safe native observation before `receive` borrows the backend.
    /// The live lane compares this pre-batch disposition with the post-batch
    /// disposition; it does not pretend that a hook can be called through an
    /// outstanding batch borrow.
    pub active_disposition: PublicationQuiescenceDisposition,
    pub disposition: PublicationQuiescenceDisposition,
}

/// A contract-level shadow of one backend's packet-batch boundary.
///
/// Implementations in this module are intentionally not backend instances.
/// Keeping that distinction explicit prevents this model lane from being
/// mistaken for coverage of AF_PACKET/AF_XDP kernel behavior. The
/// `io-sim` test target always compares its real `SimIo` result with
/// `SimModel`; AF_PACKET and AF_XDP are represented here only by their
/// independent ownership/admission transitions.
#[allow(dead_code)]
pub trait Model {
    fn observe(&self, case: &DifferentialCase) -> NormalizedObservation;

    fn observe_with_snapshot(
        &self,
        case: &DifferentialCase,
        snapshot: &ForwardingSnapshot<'_>,
    ) -> NormalizedObservation;
}

/// Contract shadow used as the SimIo reference shape.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SimModel;
/// Contract shadow used as the AF_PACKET reference shape.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AfPacketModel;
/// Contract shadow used as the AF_XDP reference shape.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpNativeModel;

impl Model for SimModel {
    fn observe(&self, case: &DifferentialCase) -> NormalizedObservation {
        let snapshot = snapshot();
        self.observe_with_snapshot(case, &snapshot)
    }

    fn observe_with_snapshot(
        &self,
        case: &DifferentialCase,
        snapshot: &ForwardingSnapshot<'_>,
    ) -> NormalizedObservation {
        observe_backend_case(case, SimQueueAccounting::new(case.tx_capacity), snapshot)
    }
}

impl Model for AfPacketModel {
    fn observe(&self, case: &DifferentialCase) -> NormalizedObservation {
        let snapshot = snapshot();
        self.observe_with_snapshot(case, &snapshot)
    }

    fn observe_with_snapshot(
        &self,
        case: &DifferentialCase,
        snapshot: &ForwardingSnapshot<'_>,
    ) -> NormalizedObservation {
        observe_backend_case(
            case,
            AfPacketBlockTxAdmission::new(case.tx_capacity),
            snapshot,
        )
    }
}

impl Model for XdpNativeModel {
    fn observe(&self, case: &DifferentialCase) -> NormalizedObservation {
        let snapshot = snapshot();
        self.observe_with_snapshot(case, &snapshot)
    }

    fn observe_with_snapshot(
        &self,
        case: &DifferentialCase,
        snapshot: &ForwardingSnapshot<'_>,
    ) -> NormalizedObservation {
        observe_backend_case(
            case,
            XdpProducerReservation::new(case.tx_capacity),
            snapshot,
        )
    }
}

pub fn compare_case(
    case: &DifferentialCase,
) -> (
    NormalizedObservation,
    NormalizedObservation,
    NormalizedObservation,
) {
    let snapshot = snapshot();
    compare_case_with_snapshot(case, &snapshot)
}

pub fn compare_case_with_snapshot(
    case: &DifferentialCase,
    snapshot: &ForwardingSnapshot<'_>,
) -> (
    NormalizedObservation,
    NormalizedObservation,
    NormalizedObservation,
) {
    // Run the core forwarding contract once. The three returned observations
    // then differ only through their independently implemented ownership
    // transitions below; this is not three copies of a hand-written
    // `forward_batch` shadow.
    let core = observe_core_contract(case, snapshot);
    let tx_requested = core.tx_requested;
    let recycled = core.recycled;
    let sim_completion = SimQueueAccounting::new(case.tx_capacity).finish(tx_requested, recycled);
    let af_packet_completion =
        AfPacketBlockTxAdmission::new(case.tx_capacity).finish(tx_requested, recycled);
    let xdp_completion =
        XdpProducerReservation::new(case.tx_capacity).finish(tx_requested, recycled);
    (
        core.clone().normalize(sim_completion),
        core.clone().normalize(af_packet_completion),
        core.normalize(xdp_completion),
    )
}

pub fn snapshot() -> ForwardingSnapshot<'static> {
    // These boxed values are test-only and live until process exit.  Keeping
    // the topology in the model makes every adapter observe the same policy.
    let routes = Box::leak(Box::new([
        Route::new(DESTINATION_PREFIX, 24, WAN, None).expect("route")
    ]));
    let interfaces = Box::leak(Box::new([
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        Interface {
            id: UNKNOWN,
            mac: UNKNOWN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
    ]));
    let neighbors = Box::leak(Box::new([Neighbor {
        interface: WAN,
        target: DESTINATION_IP,
        mac: NEXT_HOP_MAC,
    }]));
    let bindings: &'static [ruster_core::LocalIpv4Binding] = &[];
    ForwardingSnapshot::new(routes, interfaces, neighbors, bindings).expect("differential snapshot")
}

#[derive(Clone)]
struct CoreObservation {
    received: usize,
    dropped: usize,
    consumed: usize,
    tx_requested: usize,
    recycled: usize,
    batch_invariants: bool,
    forwarding: Vec<ForwardingResult>,
    active_disposition: PublicationQuiescenceDisposition,
    disposition: PublicationQuiescenceDisposition,
}

impl CoreObservation {
    fn normalize(self, completion: BatchCompletion<Infallible>) -> NormalizedObservation {
        NormalizedObservation {
            received: self.received,
            dropped: self.dropped,
            consumed: self.consumed,
            tx_requested: self.tx_requested,
            tx_accepted: completion.tx_accepted,
            tx_rejected: completion.tx_rejected,
            recycled: completion.recycled,
            error_present: completion.error.is_some(),
            batch_invariants: self.batch_invariants,
            completion_invariants: completion.invariants_hold(),
            forwarding: self.forwarding,
            error_category: ErrorCategory::None,
            active_disposition: self.active_disposition,
            disposition: self.disposition,
        }
    }
}

#[allow(dead_code)]
fn observe_backend_case<A>(
    case: &DifferentialCase,
    accounting: A,
    snapshot: &ForwardingSnapshot<'_>,
) -> NormalizedObservation
where
    A: ModelTxAdmission,
{
    let core = observe_core_contract(case, snapshot);
    let completion = accounting.finish(core.tx_requested, core.recycled);
    core.normalize(completion)
}

fn observe_core_contract(
    case: &DifferentialCase,
    snapshot: &ForwardingSnapshot<'_>,
) -> CoreObservation {
    let completions = RefCell::new(Vec::with_capacity(case.packet_count.min(4)));
    let lifecycle = RefCell::new(ModelLifecycle::Idle);
    let active_disposition = lifecycle.borrow().active_disposition();
    lifecycle.replace(ModelLifecycle::Active);
    let mut trace = NoTrace;
    let report = forward_batch(
        ModelBatch {
            ingress: IfId(case.ingress),
            frames: model_frames(case),
            next: 0,
            completions: &completions,
            lifecycle: &lifecycle,
            rx_budget: case.rx_budget,
            accounting: CoreContractAdmission,
        },
        snapshot,
        &mut trace,
    );
    let finished_disposition = lifecycle.borrow().active_disposition();
    CoreObservation {
        received: report.received,
        dropped: report.dropped,
        consumed: report.consumed,
        tx_requested: report.tx_requested,
        recycled: report.completion.recycled,
        batch_invariants: report.invariants_hold(),
        forwarding: forwarding_from_completions(&completions),
        active_disposition,
        disposition: finished_disposition,
    }
}

fn model_frames(case: &DifferentialCase) -> Vec<Vec<u8>> {
    (0..case.packet_count.min(4))
        .map(|_| case.frame.clone())
        .collect()
}

fn forwarding_from_completions(
    completions: &RefCell<Vec<SlotCompletion>>,
) -> Vec<ForwardingResult> {
    completions
        .borrow()
        .iter()
        .map(|outcome| match outcome {
            SlotCompletion::Transmit(_) => ForwardingResult::Forwarded,
            SlotCompletion::Recycle(reason) => ForwardingResult::Dropped(*reason),
            SlotCompletion::Consume(reason) => ForwardingResult::Consumed(*reason),
            SlotCompletion::LeaseAbandoned => ForwardingResult::NoPacket,
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelLifecycle {
    Idle,
    Active,
    Finished,
}

impl ModelLifecycle {
    fn active_disposition(self) -> PublicationQuiescenceDisposition {
        match self {
            Self::Idle | Self::Finished => PublicationQuiescenceDisposition::ContinueOldIo,
            Self::Active => PublicationQuiescenceDisposition::SkipIo,
        }
    }
}

struct ModelSlot<'a> {
    ingress: IfId,
    bytes: &'a mut [u8],
    completions: &'a RefCell<Vec<SlotCompletion>>,
}

impl PacketSlot for ModelSlot<'_> {
    fn ingress(&self) -> IfId {
        self.ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    fn complete(self, completion: SlotCompletion) {
        self.completions.borrow_mut().push(completion);
    }
}

/// Shared contract plumbing for the three shadows: it owns the test RX
/// buffers and records the core slot terminal event.  It deliberately does
/// not pretend to be a live backend; only the `ModelTxAdmission` value models
/// the backend-specific TX ownership boundary.
struct ModelBatch<'a, A> {
    ingress: IfId,
    frames: Vec<Vec<u8>>,
    next: usize,
    completions: &'a RefCell<Vec<SlotCompletion>>,
    lifecycle: &'a RefCell<ModelLifecycle>,
    rx_budget: usize,
    accounting: A,
}

impl<A: ModelTxAdmission> PacketBatch for ModelBatch<'_, A> {
    type Error = Infallible;
    type Slot<'a>
        = ModelSlot<'a>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        if self.next >= self.rx_budget {
            return None;
        }
        let frame = self.frames.get_mut(self.next)?;
        self.next += 1;
        Some(PacketLease::new(ModelSlot {
            ingress: self.ingress,
            bytes: frame.as_mut_slice(),
            completions: self.completions,
        }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        let (tx_requested, recycled) = {
            let outcomes = self.completions.borrow();
            (
                outcomes
                    .iter()
                    .filter(|outcome| matches!(outcome, SlotCompletion::Transmit(_)))
                    .count(),
                outcomes
                    .iter()
                    .filter(|outcome| !matches!(outcome, SlotCompletion::Transmit(_)))
                    .count(),
            )
        };
        let completion = self.accounting.finish(tx_requested, recycled);
        self.lifecycle.replace(ModelLifecycle::Finished);
        completion
    }
}

/// Backend-specific admission is kept separate even though these models
/// currently receive the same capacity from a generated case. This makes the
/// observable `tx_accepted`/`tx_rejected` result derive from the corresponding
/// ownership concept instead of three copies of one generic hand-written
/// batch.
trait ModelTxAdmission {
    fn finish(self, tx_requested: usize, recycled: usize) -> BatchCompletion<Infallible>;
}

/// The core contract batch reports all requested TX as accepted so its
/// terminal RX accounting can be captured once. Each backend model applies its
/// own admission transition only after this oracle returns.
#[derive(Clone, Copy, Debug, Default)]
struct CoreContractAdmission;

impl ModelTxAdmission for CoreContractAdmission {
    fn finish(self, tx_requested: usize, recycled: usize) -> BatchCompletion<Infallible> {
        BatchCompletion {
            tx_requested,
            tx_accepted: tx_requested,
            tx_rejected: 0,
            recycled,
            error: None,
        }
    }
}

/// SimIo's finite output queue admits received TX one frame at a time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SimQueueAccounting {
    capacity: usize,
    queued: usize,
}

impl SimQueueAccounting {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queued: 0,
        }
    }
}

impl ModelTxAdmission for SimQueueAccounting {
    fn finish(mut self, tx_requested: usize, recycled: usize) -> BatchCompletion<Infallible> {
        let available = self.capacity.saturating_sub(self.queued);
        let tx_accepted = tx_requested.min(available);
        self.queued += tx_accepted;
        BatchCompletion {
            tx_requested,
            tx_accepted,
            tx_rejected: tx_requested - tx_accepted,
            recycled,
            error: None,
        }
    }
}

/// AF_PACKET admits TX against the USER block's available TX frames when the
/// block is flushed. The model stores block admission independently from the
/// Sim queue and XDP producer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AfPacketBlockTxAdmission {
    block_capacity: usize,
}

impl AfPacketBlockTxAdmission {
    fn new(block_capacity: usize) -> Self {
        Self { block_capacity }
    }
}

impl ModelTxAdmission for AfPacketBlockTxAdmission {
    fn finish(self, tx_requested: usize, recycled: usize) -> BatchCompletion<Infallible> {
        let mut frames = vec![TxFrameModel::new(); self.block_capacity];
        let mut tx_accepted = 0;
        let mut tx_rejected = 0;
        for _ in 0..tx_requested {
            let Some(frame) = frames
                .iter_mut()
                .find(|frame| frame.owner() == TxOwnership::Available)
            else {
                tx_rejected += 1;
                continue;
            };
            if frame.prepare().and_then(|_| frame.publish()).is_ok() {
                tx_accepted += 1;
            } else {
                tx_rejected += 1;
            }
        }
        BatchCompletion {
            tx_requested,
            tx_accepted,
            tx_rejected,
            recycled,
            error: None,
        }
    }
}

/// AF_XDP reserves a contiguous range from the application TX producer before
/// publishing it. Rejected requests never become published descriptors and
/// therefore remain excluded from the completion `recycled` count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct XdpProducerReservation {
    capacity: usize,
}

impl XdpProducerReservation {
    fn new(capacity: usize) -> Self {
        Self { capacity }
    }
}

#[repr(align(64))]
struct XdpSyntheticMemory([u8; 256]);

impl ModelTxAdmission for XdpProducerReservation {
    fn finish(self, tx_requested: usize, recycled: usize) -> BatchCompletion<Infallible> {
        let mut tx_accepted = 0;
        let mut tx_rejected = 0;

        if self.capacity != 0 {
            let mut memory = XdpSyntheticMemory([0; 256]);
            let offsets = XdpRingOffset {
                producer: 0,
                consumer: 64,
                flags: 128,
                descriptors: 192,
            };
            let entries = RingEntries::new(RingName::Tx, 2).expect("synthetic TX ring entries");
            let mut producer =
                TxProducer::new(&mut memory.0, offsets, entries).expect("synthetic TX ring");
            let descriptor = XdpDescriptor {
                address: 0,
                len: 0,
                options: 0,
            };
            for _ in 0..tx_requested {
                match producer.reserve(1) {
                    Ok(mut reservation) => {
                        if reservation.write(descriptor).is_err() {
                            reservation.release_cancel();
                            tx_rejected += 1;
                        } else if reservation.release_submit().is_ok() {
                            tx_accepted += 1;
                        } else {
                            tx_rejected += 1;
                        }
                    }
                    Err(NativeRingError::RingFull) => {
                        tx_rejected += 1;
                    }
                    Err(_) => {
                        tx_rejected += 1;
                    }
                }
            }
        } else {
            tx_rejected = tx_requested;
        }
        BatchCompletion {
            tx_requested,
            tx_accepted,
            tx_rejected,
            recycled,
            error: None,
        }
    }
}

pub fn generate_case(seed: u64, iteration: u64, structured: bool) -> DifferentialCase {
    let mut state = seed ^ iteration.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    const BOUNDARY_LENGTHS: [usize; 22] = [
        0, 1, 13, 14, 15, 33, 34, 41, 42, 53, 54, 60, 64, 1_499, 1_500, 1_501, 1_513, 1_514, 1_515,
        8_999, 9_000, 9_001,
    ];
    let length = if iteration < BOUNDARY_LENGTHS.len() as u64 {
        BOUNDARY_LENGTHS[iteration as usize]
    } else {
        (next() as usize) % 1_516
    };
    let mut frame = vec![0; length];
    for byte in &mut frame {
        *byte = next() as u8;
    }
    if structured {
        apply_structured_mutation(&mut frame, iteration, &mut next);
    }
    DifferentialCase {
        seed,
        iteration,
        frame,
        ingress: match next() % 3 {
            0 => LAN.0,
            1 => WAN.0,
            _ => UNKNOWN.0,
        },
        rx_budget: (next() as usize) % 4,
        tx_capacity: if next() & 1 == 0 { 0 } else { 2 },
        state: next() as u8,
        packet_count: 1 + (next() as usize % 4),
    }
}

fn apply_structured_mutation(frame: &mut [u8], iteration: u64, next: &mut impl FnMut() -> u64) {
    if frame.len() < 14 {
        return;
    }
    let kind = iteration % 5;
    match kind {
        0 => {
            frame[12..14].copy_from_slice(&[0x08, 0x00]);
            if frame.len() >= 34 {
                frame[14] = 0x45 | ((next() as u8) & 0x0f);
                frame[23] = match next() % 3 {
                    0 => 1,
                    1 => 6,
                    _ => 17,
                };
                frame[26..30].copy_from_slice(&[192, 0, 2, (next() | 1) as u8]);
                frame[30..34].copy_from_slice(&DESTINATION_IP.octets());
            }
        }
        1 => {
            // ARP request/reply shape, including mutations of operation and
            // addresses; short cases remain deliberately malformed.
            frame[12..14].copy_from_slice(&[0x08, 0x06]);
            if frame.len() >= 42 {
                frame[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
                frame[20] = if next() & 1 == 0 { 0 } else { 0xff };
                frame[21] = if next() & 1 == 0 { 1 } else { 2 };
            }
        }
        2..=4 => {
            // ICMP error with an outer IPv4 header and quoted UDP/TCP/ICMP
            // header. This is intentionally byte-level: the model lane
            // compares backend accounting, while NAT runtime tests own NAT
            // state-machine assertions.
            frame[12..14].copy_from_slice(&[0x08, 0x00]);
            if frame.len() >= 34 {
                frame[14] = 0x45;
                frame[23] = if kind == 4 { 1 } else { 17 };
                if kind == 3 {
                    frame[23] = 6;
                }
                frame[26..30].copy_from_slice(&[203, 0, 113, 7]);
                frame[30..34].copy_from_slice(&DESTINATION_IP.octets());
            }
            if frame.len() >= 42 {
                frame[34] = 3;
                frame[35] = if next() & 1 == 0 { 1 } else { 3 };
                frame[36..38].copy_from_slice(&0u16.to_be_bytes());
                frame[38..42].copy_from_slice(&[0x45, 0, 0, 0]);
            }
            if frame.len() >= 62 {
                frame[50..54].copy_from_slice(&[192, 0, 2, 8]);
                frame[54..58].copy_from_slice(&DESTINATION_IP.octets());
                frame[58..60].copy_from_slice(&4000u16.to_be_bytes());
                frame[60..62].copy_from_slice(&80u16.to_be_bytes());
            }
        }
        _ => unreachable!(),
    }
}

#[allow(dead_code)]
pub fn assert_case(case: &DifferentialCase) {
    let snapshot = snapshot();
    assert_case_with_snapshot(case, &snapshot);
}

pub fn assert_case_with_snapshot(case: &DifferentialCase, snapshot: &ForwardingSnapshot<'_>) {
    assert!(case.packet_count > 0 && case.packet_count <= 4);
    assert!(case.rx_budget <= 3);
    assert!(matches!(case.tx_capacity, 0 | 2));

    let (sim, af_packet, xdp_native) = compare_case_with_snapshot(case, snapshot);
    assert_eq!(
        sim,
        af_packet,
        "differential model mismatch: sim vs af_packet seed=0x{:016x} iteration={} frame_hex={}",
        case.seed,
        case.iteration,
        hex(case.frame.as_slice()),
    );
    assert_eq!(
        sim,
        xdp_native,
        "differential model mismatch: sim vs xdp_native seed=0x{:016x} iteration={} frame_hex={}",
        case.seed,
        case.iteration,
        hex(case.frame.as_slice()),
    );
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        output.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn differential_iterations() -> usize {
    match std::env::var("RUSTER_BACKEND_DIFFERENTIAL_ITERATIONS") {
        Ok(value) => {
            let iterations = value.parse::<usize>().unwrap_or_else(|error| {
                panic!(
                    "RUSTER_BACKEND_DIFFERENTIAL_ITERATIONS must be an integer in 1..=4096: {error}"
                )
            });
            assert!(
                (1..=4096).contains(&iterations),
                "RUSTER_BACKEND_DIFFERENTIAL_ITERATIONS must be in 1..=4096 (got {iterations})"
            );
            iterations
        }
        Err(std::env::VarError::NotPresent) => 256,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("RUSTER_BACKEND_DIFFERENTIAL_ITERATIONS is not valid UTF-8")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_exercises_multiple_slots_and_boundaries() {
        let boundary = generate_case(1, 2, false);
        assert_eq!(boundary.frame.len(), 13);
        let case = generate_case(1, 100, false);
        assert!((1..=4).contains(&case.packet_count));
        let (a, b, c) = compare_case(&case);
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn model_lifecycle_is_observable_without_completion_error() {
        let case = generate_case(7, 0, true);
        let (sim, af_packet, xdp_native) = compare_case(&case);
        assert!(!sim.error_present);
        assert_eq!(
            sim.active_disposition,
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        assert_eq!(
            sim.disposition,
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        assert_eq!(sim, af_packet);
        assert_eq!(sim, xdp_native);
    }
}

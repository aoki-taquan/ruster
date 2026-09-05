//! Always-on core-only forwarding-contract oracle coverage.
//!
//! The three-way model lives in `io-sim/tests/backend_differential.rs`, where
//! `ruster-io-conformance` is a dev-dependency and can therefore use the real
//! AF_PACKET and AF_XDP public model APIs. This target deliberately stays
//! independent of those backend crates and verifies that the core operation
//! consumes one shared forwarding snapshot for every generated case. It is
//! intentionally not a three-way backend differential test.

use std::cell::RefCell;

use ruster_core::{
    forward_batch, ipv4_header_checksum, BatchCompletion, ForwardingSnapshot, IfId, Ipv4Address,
    Ipv4Mtu, MacAddress, NoTrace, PacketBatch, PacketLease, PacketSlot,
    PublicationQuiescenceDisposition,
    Route, SlotCompletion,
};

const LAN: IfId = IfId(11);
const WAN: IfId = IfId(22);
const UNKNOWN: IfId = IfId(99);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 11]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 22]);
const UNKNOWN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 99]);
const NEXT_HOP_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 2, 2]);
const DESTINATION_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const DESTINATION_PREFIX: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 0]);

const RANDOM_SEED: u64 = 0x6261_636b_656e_6401;
const STRUCTURED_SEED: u64 = 0x6261_636b_656e_6402;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoreCase {
    seed: u64,
    iteration: u64,
    frame: Vec<u8>,
    ingress: u16,
    rx_budget: usize,
    tx_capacity: usize,
    state: u8,
    packet_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ForwardingResult {
    Forwarded,
    Dropped(ruster_core::DropReason),
    Consumed(ruster_core::ConsumeReason),
    NoPacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoreObservation {
    received: usize,
    dropped: usize,
    consumed: usize,
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
    batch_invariants: bool,
    completion_invariants: bool,
    forwarding: Vec<ForwardingResult>,
    active_disposition: PublicationQuiescenceDisposition,
    disposition: PublicationQuiescenceDisposition,
}

#[derive(Clone, Copy)]
enum CoreLifecycle {
    RxBatch,
    TxInFlight,
    Idle,
}

impl CoreLifecycle {
    fn current_io_disposition(self) -> PublicationQuiescenceDisposition {
        match self {
            Self::RxBatch => PublicationQuiescenceDisposition::SkipIo,
            Self::TxInFlight | Self::Idle => PublicationQuiescenceDisposition::ContinueOldIo,
        }
    }
}

#[test]
fn core_forward_batch_oracle_random_lane() {
    run_core_contract_lane(RANDOM_SEED, false);
}

#[test]
fn core_forward_batch_oracle_structured_lane() {
    run_core_contract_lane(STRUCTURED_SEED, true);
}

fn run_core_contract_lane(seed: u64, structured: bool) {
    let snapshot = core_contract_snapshot();
    for iteration in 0..core_contract_iterations() {
        let case = generate_case(seed, iteration as u64, structured);
        let observation = observe_core(&case, &snapshot);
        assert_eq!(observation.received, case.packet_count.min(case.rx_budget));
        assert!(observation.batch_invariants);
        assert!(observation.completion_invariants);
        assert_eq!(
            observation.tx_requested,
            observation.tx_accepted + observation.tx_rejected
        );
        assert_eq!(observation.forwarding.len(), observation.received);
        assert_eq!(
            observation.active_disposition,
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        assert_eq!(
            observation.disposition,
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        let _ = (case.seed, case.iteration, case.state);
    }
}

#[test]
fn core_forward_batch_deterministic_accounting_and_drop_reason() {
    let snapshot = core_contract_snapshot();
    let case = CoreCase {
        seed: 0x6465_7465_726d_0001,
        iteration: 0,
        frame: vec![0; 13],
        ingress: LAN.0,
        rx_budget: 1,
        tx_capacity: 1,
        state: 0,
        packet_count: 1,
    };
    let observation = observe_core(&case, &snapshot);
    assert_eq!(observation.received, 1);
    assert_eq!(observation.dropped, 1);
    assert_eq!(observation.consumed, 0);
    assert_eq!(observation.tx_requested, 0);
    assert_eq!(observation.recycled, 1);
    assert_eq!(
        observation.forwarding,
        vec![ForwardingResult::Dropped(
            ruster_core::DropReason::EthernetHeaderTruncated
        )]
    );
    assert!(observation.batch_invariants);
    assert!(observation.completion_invariants);
}

#[test]
fn core_multiple_packets_expose_budget_and_tx_capacity() {
    let snapshot = core_contract_snapshot();
    let base = CoreCase {
        seed: 0x6d75_6c74_6900_0001,
        iteration: 0,
        frame: forwarded_ipv4_frame(),
        ingress: LAN.0,
        rx_budget: 3,
        tx_capacity: 3,
        state: 0,
        packet_count: 3,
    };
    let mut one = base.clone();
    one.rx_budget = 1;
    let mut two = base.clone();
    two.rx_budget = 2;
    assert_eq!(observe_core(&one, &snapshot).received, 1);
    assert_eq!(observe_core(&two, &snapshot).received, 2);

    let observations = [0, 1, 2].map(|tx_capacity| {
        let mut case = base.clone();
        case.tx_capacity = tx_capacity;
        observe_core(&case, &snapshot)
    });
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.tx_requested)
            .collect::<Vec<_>>(),
        [3, 3, 3]
    );
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.tx_accepted)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.tx_rejected)
            .collect::<Vec<_>>(),
        [3, 2, 1]
    );
    assert!(observations
        .iter()
        .all(|observation| observation.forwarding == vec![ForwardingResult::Forwarded; 3]));
}

fn core_contract_snapshot() -> ForwardingSnapshot<'static> {
    let routes = Box::leak(Box::new([
        Route::new(DESTINATION_PREFIX, 24, WAN, None).expect("route")
    ]));
    let interfaces = Box::leak(Box::new([
        ruster_core::Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        ruster_core::Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        ruster_core::Interface {
            id: UNKNOWN,
            mac: UNKNOWN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
    ]));
    let neighbors = Box::leak(Box::new([ruster_core::Neighbor {
        interface: WAN,
        target: DESTINATION_IP,
        mac: NEXT_HOP_MAC,
    }]));
    ForwardingSnapshot::new(routes, interfaces, neighbors, &[]).expect("core contract snapshot")
}

fn core_contract_iterations() -> usize {
    match std::env::var("RUSTER_BACKEND_DIFFERENTIAL_ITERATIONS") {
        Ok(value) => {
            let iterations = value
                .parse::<usize>()
                .expect("RUSTER_BACKEND_DIFFERENTIAL_ITERATIONS must be an integer");
            assert!((1..=4096).contains(&iterations));
            iterations
        }
        Err(std::env::VarError::NotPresent) => 256,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("RUSTER_BACKEND_DIFFERENTIAL_ITERATIONS is not valid UTF-8")
        }
    }
}

fn generate_case(seed: u64, iteration: u64, structured: bool) -> CoreCase {
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
    if structured && frame.len() >= 14 {
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        if frame.len() >= 34 {
            frame[14] = 0x45;
            frame[23] = 17;
            frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
            frame[30..34].copy_from_slice(&DESTINATION_IP.octets());
        }
    }
    CoreCase {
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

fn forwarded_ipv4_frame() -> Vec<u8> {
    let mut frame = vec![0; 60];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&LAN_MAC.0);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&20u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
    frame[30..34].copy_from_slice(&DESTINATION_IP.octets());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn observe_core(case: &CoreCase, snapshot: &ForwardingSnapshot<'_>) -> CoreObservation {
    let completion = RefCell::new(Vec::with_capacity(case.packet_count));
    let lifecycle = RefCell::new(CoreLifecycle::Idle);
    let active_disposition = lifecycle.borrow().current_io_disposition();
    lifecycle.replace(CoreLifecycle::RxBatch);
    let frames = (0..case.packet_count).map(|_| case.frame.clone()).collect();
    let mut trace = NoTrace;
    let report = forward_batch(
        CoreBatch {
            ingress: IfId(case.ingress),
            frames,
            next: 0,
            completion: &completion,
            tx_capacity: case.tx_capacity,
            rx_budget: case.rx_budget,
            lifecycle: &lifecycle,
        },
        snapshot,
        &mut trace,
    );
    let forwarding = completion
        .borrow()
        .iter()
        .map(|terminal| match terminal {
            SlotCompletion::Transmit(_) => ForwardingResult::Forwarded,
            SlotCompletion::Recycle(reason) => ForwardingResult::Dropped(*reason),
            SlotCompletion::Consume(reason) => ForwardingResult::Consumed(*reason),
            SlotCompletion::LeaseAbandoned => ForwardingResult::NoPacket,
        })
        .collect();
    let disposition = lifecycle.borrow().current_io_disposition();
    CoreObservation {
        received: report.received,
        dropped: report.dropped,
        consumed: report.consumed,
        tx_requested: report.tx_requested,
        tx_accepted: report.completion.tx_accepted,
        tx_rejected: report.completion.tx_rejected,
        recycled: report.completion.recycled,
        batch_invariants: report.invariants_hold(),
        completion_invariants: report.completion.invariants_hold(),
        forwarding,
        active_disposition,
        disposition,
    }
}

struct CoreSlot<'a> {
    ingress: IfId,
    bytes: &'a mut [u8],
    completion: &'a RefCell<Vec<SlotCompletion>>,
}

impl PacketSlot for CoreSlot<'_> {
    fn ingress(&self) -> IfId {
        self.ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    fn complete(self, completion: SlotCompletion) {
        self.completion.borrow_mut().push(completion);
    }
}

struct CoreBatch<'a> {
    ingress: IfId,
    frames: Vec<Vec<u8>>,
    next: usize,
    completion: &'a RefCell<Vec<SlotCompletion>>,
    tx_capacity: usize,
    rx_budget: usize,
    lifecycle: &'a RefCell<CoreLifecycle>,
}

impl PacketBatch for CoreBatch<'_> {
    type Error = ();
    type Slot<'a>
        = CoreSlot<'a>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        if self.next >= self.frames.len() || self.next >= self.rx_budget {
            return None;
        }
        let bytes = self.frames[self.next].as_mut_slice();
        self.next += 1;
        Some(PacketLease::new(CoreSlot {
            ingress: self.ingress,
            bytes,
            completion: self.completion,
        }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        let outcomes = self.completion.borrow();
        let tx_requested = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SlotCompletion::Transmit(_)))
            .count();
        let tx_accepted = tx_requested.min(self.tx_capacity);
        let completion = BatchCompletion {
            tx_requested,
            tx_accepted,
            tx_rejected: tx_requested - tx_accepted,
            recycled: outcomes
                .iter()
                .filter(|outcome| !matches!(outcome, SlotCompletion::Transmit(_)))
                .count(),
            error: None,
        };
        self.lifecycle.replace(if completion.tx_accepted != 0 {
            CoreLifecycle::TxInFlight
        } else {
            CoreLifecycle::Idle
        });
        completion
    }
}

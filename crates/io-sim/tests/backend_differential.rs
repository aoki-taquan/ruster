//! Always-on, unprivileged differential coverage for `SimIo`.
//!
//! This file exercises the real `SimIo` receive/finish path and the
//! always-on unprivileged contract lane. The privileged three-way live lane
//! is in `backend_differential_live.rs`.

use ruster_core::{
    forward_batch, ipv4_header_checksum, BatchCompletion, DropReason, ForwardingSnapshot, IfId,
    Ipv4Address, MacAddress, NoTrace, PacketBatch, PacketIo, PublicationQuiescenceBackend,
    PublicationQuiescenceDisposition,
};
use ruster_io_conformance::differential::{
    assert_case_with_snapshot, compare_case_with_snapshot, generate_case, snapshot,
    DifferentialCase, ErrorCategory, ForwardingResult, Model, NormalizedObservation, SimModel,
};
use ruster_io_sim::{FrameOrigin, RecycleCause, SimIo};

const LAN: IfId = IfId(11);
const WAN: IfId = IfId(22);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 11]);
const DESTINATION_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);

const RANDOM_SEED: u64 = 0x6261_636b_656e_6401;
const STRUCTURED_SEED: u64 = 0x6261_636b_656e_6402;

#[test]
fn sim_io_entrypoints_exercise_real_receive_and_completion_queues() {
    let mut io = SimIo::new();
    let idle_disposition = io.current_io_disposition();
    assert_eq!(
        idle_disposition,
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    io.inject(LAN, vec![0; 13]);
    let recycled_completion = {
        let mut batch = io.receive(1).expect("SimIo receive is infallible");
        let packet = batch.next_packet().expect("injected RX packet");
        packet.recycle(DropReason::EthernetHeaderTruncated);
        batch.finish()
    };
    assert_eq!(
        recycled_completion,
        BatchCompletion {
            tx_requested: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            recycled: 1,
            error: None,
        }
    );
    assert_eq!(
        io.pop_recycled().expect("recycle queue entry").cause,
        RecycleCause::Forwarding(DropReason::EthernetHeaderTruncated)
    );
    assert!(io.pop_tx().is_none());

    io.inject(LAN, vec![0; 60]);
    let transmitted_completion = {
        let mut batch = io.receive(1).expect("SimIo receive is infallible");
        let packet = batch.next_packet().expect("injected RX packet");
        packet.commit(WAN);
        batch.finish()
    };
    assert_eq!(transmitted_completion.tx_requested, 1);
    assert_eq!(transmitted_completion.tx_accepted, 1);
    assert_eq!(transmitted_completion.tx_rejected, 0);
    assert_eq!(transmitted_completion.recycled, 0);
    let transmitted = io.pop_tx().expect("TX queue entry");
    assert_eq!(transmitted.origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(transmitted.egress, WAN);
    assert!(io.pop_recycled().is_none());
}

#[test]
fn sim_io_differential_random_model_lane() {
    run_model_lane(RANDOM_SEED, false);
}

#[test]
fn sim_io_differential_structured_model_lane() {
    run_model_lane(STRUCTURED_SEED, true);
}

#[test]
fn sim_io_multiple_packets_expose_budget_and_tx_capacity() {
    let snapshot = differential_snapshot();
    let base = DifferentialCase {
        seed: 0x6d75_6c74_6900_0002,
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
    assert_eq!(run_sim_case(&one, &snapshot).received, 1);
    assert_eq!(run_sim_case(&two, &snapshot).received, 2);

    let observations = [0, 1, 2].map(|tx_capacity| {
        let mut case = base.clone();
        case.tx_capacity = tx_capacity;
        run_sim_case(&case, &snapshot)
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
}

fn differential_snapshot() -> ForwardingSnapshot<'static> {
    snapshot()
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

fn run_model_lane(seed: u64, structured: bool) {
    let snapshot = snapshot();

    for iteration in 0..ruster_io_conformance::differential::differential_iterations() {
        let case = generate_case(seed, iteration as u64, structured);
        assert_case_with_snapshot(&case, &snapshot);
        let (sim, af_packet, xdp_native) = compare_case_with_snapshot(&case, &snapshot);
        assert_eq!(sim, af_packet, "model pair mismatch before SimIo");
        assert_eq!(sim, xdp_native, "model pair mismatch before SimIo");
        let actual = run_sim_case(&case, &snapshot);
        assert_eq!(
            actual,
            SimModel.observe_with_snapshot(&case, &snapshot),
            "SimIo differential mismatch: strategy={} seed=0x{:016x} iteration={} frame_hex={}",
            if structured { "structured" } else { "random" },
            case.seed,
            case.iteration,
            hex(&case.frame),
        );
    }
}

fn run_sim_case(
    case: &DifferentialCase,
    snapshot: &ForwardingSnapshot<'_>,
) -> NormalizedObservation {
    let ingress = IfId(case.ingress);
    let mut io = SimIo::new();
    io.set_received_accept_budget(case.tx_capacity);
    for _ in 0..case.packet_count {
        io.inject(ingress, case.frame.clone());
    }
    let mut trace = NoTrace;
    let active_disposition = io.current_io_disposition();
    let batch = io
        .receive(case.rx_budget)
        .expect("SimIo forwarding is infallible");
    // `SimIo::receive` holds the mutable borrow that owns the active batch,
    // so Rust correctly prevents observing `io` until finish returns. The
    // direct post-finish observation below verifies the transition; the
    // model lane independently records the active `SkipIo` state.
    let report = forward_batch(batch, snapshot, &mut trace);
    assert!(report.invariants_hold());
    assert!(report.completion.invariants_hold());
    let disposition = io.current_io_disposition();
    if report.completion.tx_accepted != 0 {
        assert_eq!(disposition, PublicationQuiescenceDisposition::ContinueOldIo);
        assert!(
            io.check_publication_quiescence().is_err(),
            "accepted TX ownership must be visible to quiescence"
        );
    }

    let mut forwarding = Vec::with_capacity(report.received);
    for _ in 0..report.completion.tx_accepted {
        let transmitted = io.pop_tx().expect("accepted TX frame");
        assert_eq!(transmitted.ingress, ingress);
        assert_eq!(transmitted.origin, FrameOrigin::Received { ingress });
        assert_eq!(transmitted.egress, WAN);
        forwarding.push(ForwardingResult::Forwarded);
    }
    for _ in 0..report.completion.tx_rejected {
        let rejected = io.pop_recycled_capture().expect("rejected TX frame");
        assert_eq!(rejected.frame.ingress, ingress);
        assert_eq!(rejected.frame.cause, RecycleCause::TxRejected);
        assert_eq!(rejected.rejected_egress, Some(WAN));
        forwarding.push(ForwardingResult::Forwarded);
    }
    while let Some(recycled) = io.pop_recycled() {
        assert_eq!(recycled.ingress, ingress);
        match recycled.cause {
            RecycleCause::Forwarding(reason) => forwarding.push(ForwardingResult::Dropped(reason)),
            RecycleCause::Consumed(reason) => forwarding.push(ForwardingResult::Consumed(reason)),
            RecycleCause::TxRejected | RecycleCause::LeaseAbandoned => {
                panic!("unexpected non-forwarding SimIo recycle cause")
            }
        }
    }
    if report.received == 0 {
        assert!(forwarding.is_empty());
        assert_eq!(disposition, PublicationQuiescenceDisposition::ContinueOldIo);
    }
    if io.pending_rx() != 0 {
        io.retire_pending_rx().expect("unoffered RX is retired");
    }
    assert_eq!(io.pending_rx(), 0);
    assert_eq!(io.pending_tx(), 0);
    assert_eq!(io.pending_recycled(), 0);
    NormalizedObservation {
        received: report.received,
        dropped: report.dropped,
        consumed: report.consumed,
        tx_requested: report.tx_requested,
        tx_accepted: report.completion.tx_accepted,
        tx_rejected: report.completion.tx_rejected,
        recycled: report.completion.recycled,
        error_present: report.completion.error.is_some(),
        batch_invariants: report.invariants_hold(),
        completion_invariants: report.completion.invariants_hold(),
        forwarding,
        error_category: ErrorCategory::None,
        active_disposition,
        disposition,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        output.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    output
}

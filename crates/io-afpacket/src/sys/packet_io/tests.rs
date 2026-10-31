//! AF_PACKET-native PacketIo tests: hairpin copy, the finish-error and
//! partial-rejection mapping that the reserve-then-reject conformance cases
//! cannot express, fault errors, round-robin fairness, forgotten leases, and
//! steady allocation.

use ruster_core::{DropReason, PacketBatch, PacketIo};
use ruster_io_conformance::{
    rx_copy::{
        CopyErrno, CopyKickEvent, RxCopyCompletionHarness, RxCopyHarness, RxCopyKickErrorHarness,
    },
    CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_WAN, CONFORMANCE_WAN_ENDPOINT,
};

use super::{
    conformance::{DefaultHarness, OneFrameHarness, LAN_PORT, WAN_PORT},
    AfPacketIoError,
};
use crate::{
    sys::{rx::RxFault, TxSubmitError},
    Errno, PlatformError, SyscallStage, TP_STATUS_KERNEL, TP_STATUS_SEND_REQUEST, TP_STATUS_USER,
};

fn counts(
    completion: &ruster_core::BatchCompletion<AfPacketIoError>,
) -> (usize, usize, usize, usize) {
    (
        completion.tx_requested,
        completion.tx_accepted,
        completion.tx_rejected,
        completion.recycled,
    )
}

#[test]
fn af_packet_packet_io_hairpin_and_cross_port_copy_final_bytes_once() {
    let mut harness = DefaultHarness::new();
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![0x11; 60], vec![0x22; 61]]);
    let completion = {
        let engine = &mut harness.io.engine;
        let mut batch = engine.receive(2).expect("receive");
        let mut hairpin = batch.next_packet().expect("first packet");
        assert_eq!(hairpin.ingress(), CONFORMANCE_LAN);
        hairpin.bytes_mut()[0] = 0xa1;
        // Same-port commit: RX and TX extents of one mapping.
        hairpin.commit(CONFORMANCE_LAN);
        let mut cross = batch.next_packet().expect("second packet");
        cross.bytes_mut()[60] = 0xb2;
        cross.commit(CONFORMANCE_WAN);
        batch.finish()
    };
    assert_eq!(counts(&completion), (2, 2, 0, 0));
    assert!(completion.error.is_none());
    let lan = harness.view(LAN_PORT);
    let wan = harness.view(WAN_PORT);
    let mut expected = vec![0x11; 60];
    expected[0] = 0xa1;
    assert_eq!(lan.tx_status(0), TP_STATUS_SEND_REQUEST);
    assert_eq!(lan.tx_payload(0), expected);
    let mut expected = vec![0x22; 61];
    expected[60] = 0xb2;
    assert_eq!(wan.tx_status(0), TP_STATUS_SEND_REQUEST);
    assert_eq!(wan.tx_payload(0), expected);
    // The source block returned after its last packet became terminal, and
    // both copies were the only packet-byte copies.
    assert_eq!(lan.rx_status(), TP_STATUS_KERNEL);
    let counters = harness.copy_operation_counters();
    assert_eq!((counters.copy_invocations, counters.copied_bytes), (2, 121));
    let mut kicks = harness.drain_copy_tx_kicks();
    kicks.sort_by_key(|kick| kick.endpoint.interface);
    assert_eq!(
        kicks,
        [
            CopyKickEvent {
                endpoint: CONFORMANCE_LAN_ENDPOINT,
                result: Ok(()),
            },
            CopyKickEvent {
                endpoint: CONFORMANCE_WAN_ENDPOINT,
                result: Ok(()),
            },
        ]
    );
}

#[test]
fn af_packet_finish_error_preserves_partial_reject_accounting_and_single_kick() {
    // A one-frame TX ring makes the second and third commits find the
    // producer head still SEND_REQUEST: a routine ring-full rejection that
    // reserves and copies nothing. The injected kick errno is the finish
    // error.
    let mut harness = OneFrameHarness::new();
    harness.fail_next_copy_kick(CopyErrno(11));
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3]]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io.receive(3).expect("receive");
        while let Some(packet) = batch.next_packet() {
            packet.commit(CONFORMANCE_WAN);
        }
        batch.finish()
    };
    assert_eq!(counts(&completion), (3, 1, 2, 0));
    assert!(completion.invariants_hold());
    assert_eq!(
        completion.error,
        Some(AfPacketIoError::Kick {
            interface: CONFORMANCE_WAN,
            error: PlatformError::Syscall {
                stage: SyscallStage::Kick,
                errno: Errno::new(11),
            },
        })
    );
    assert_eq!(
        harness.drain_copy_tx_kicks(),
        [CopyKickEvent {
            endpoint: CONFORMANCE_WAN_ENDPOINT,
            result: Err(CopyErrno(11)),
        }]
    );
    let counters = harness.copy_operation_counters();
    assert_eq!((counters.copy_invocations, counters.copied_bytes), (1, 1));
    assert_eq!(counters.tx_submit_status_reads, 3);
    assert_eq!(harness.drain_copy_rx_block_returns().len(), 1);
    // The accepted frame stays in flight despite the kick error.
    assert_eq!(harness.inflight_copy_tx_frames(), 1);
    assert_eq!(harness.complete_copy_submissions().len(), 1);
    assert_eq!(harness.free_copy_tx_frames(), 1);
}

#[test]
fn af_packet_rx_halt_and_tx_fault_report_errors_with_exact_accounting() {
    let mut harness = DefaultHarness::new();
    // RX: a head status that is neither KERNEL nor USER halts that port.
    // The halt is edge-triggered: only the batch that first observes a halt
    // event reports it, so a persistently halted port does not turn every
    // later batch into a backend failure for the healthy ports.
    let halt = |status| AfPacketIoError::Rx {
        interface: CONFORMANCE_LAN,
        fault: RxFault::Status {
            block_index: 0,
            status,
        },
    };
    let run = |harness: &mut DefaultHarness| {
        let (io, _) = harness.io_and_observer();
        let mut batch = io.receive(4).expect("receive");
        let mut delivered = Vec::new();
        while let Some(packet) = batch.next_packet() {
            delivered.push(packet.ingress());
            packet.recycle(DropReason::RouteMiss);
        }
        (delivered, batch.finish())
    };
    harness.view(LAN_PORT).set_rx_status(2);
    let (delivered, first) = run(&mut harness);
    assert!(delivered.is_empty());
    assert_eq!(counts(&first), (0, 0, 0, 0));
    assert_eq!(first.error, Some(halt(2)));
    harness.trace().expected_stats[LAN_PORT].status_rejected = 1;
    // Same halt persists: no error, and the healthy WAN port is served.
    harness.inject_rx_block(CONFORMANCE_WAN, vec![vec![0x31]]);
    let (delivered, second) = run(&mut harness);
    assert_eq!(delivered, [CONFORMANCE_WAN]);
    assert_eq!(counts(&second), (0, 0, 0, 1));
    assert_eq!(second.error, None);
    assert_eq!(harness.drain_copy_rx_block_returns().len(), 1);
    // A distinct halt is a new event and is reported again, once.
    harness.view(LAN_PORT).set_rx_status(4);
    let (_, third) = run(&mut harness);
    assert_eq!(third.error, Some(halt(4)));
    let (_, fourth) = run(&mut harness);
    assert_eq!(fourth.error, None);
    // Each distinct halt event is counted once in BackendStats.
    harness.trace().expected_stats[LAN_PORT].status_rejected = 2;
    harness.view(LAN_PORT).set_rx_status(TP_STATUS_KERNEL);

    // TX: an unknown producer-head status is a fault-class rejection; the
    // source packet still completes and nothing is copied or kicked.
    harness.view(WAN_PORT).set_tx_status(0, 0x80);
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![0x42]]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io.receive(1).expect("receive");
        batch.next_packet().expect("packet").commit(CONFORMANCE_WAN);
        batch.finish()
    };
    assert_eq!(counts(&completion), (1, 0, 1, 0));
    assert_eq!(
        completion.error,
        Some(AfPacketIoError::Tx {
            egress: CONFORMANCE_WAN,
            error: TxSubmitError::InvalidStatus { status: 0x80 },
        })
    );
    assert_eq!(harness.drain_copy_rx_block_returns().len(), 1);
    assert!(harness.drain_copy_tx_kicks().is_empty());
    assert_eq!(harness.copy_operation_counters().copy_invocations, 0);
}

#[test]
fn af_packet_receive_round_robins_ports_under_packet_budget() {
    let mut harness = DefaultHarness::new();
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2]]);
    harness.inject_rx_block(CONFORMANCE_WAN, vec![vec![3], vec![4]]);
    let mut order = Vec::new();
    for _ in 0..4 {
        let (io, _) = harness.io_and_observer();
        let mut batch = io.receive(1).expect("receive");
        while let Some(mut packet) = batch.next_packet() {
            order.push((packet.ingress(), packet.bytes_mut()[0]));
            packet.recycle(DropReason::RouteMiss);
        }
        assert_eq!(batch.finish().recycled, 1);
    }
    assert_eq!(
        order,
        [
            (CONFORMANCE_LAN, 1),
            (CONFORMANCE_WAN, 3),
            (CONFORMANCE_LAN, 2),
            (CONFORMANCE_WAN, 4),
        ]
    );
    assert_eq!(harness.drain_copy_rx_block_returns().len(), 2);
}

#[test]
fn af_packet_round_robin_resumes_after_the_port_that_exhausted_the_budget() {
    // Batch one starts at LAN, drains its single packet, and exhausts the
    // packet budget on WAN. The next batch must start at the port after
    // WAN (LAN), not at the port after this batch's start (WAN).
    let mut harness = DefaultHarness::new();
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1]]);
    harness.inject_rx_block(CONFORMANCE_WAN, vec![vec![10], vec![11], vec![12]]);
    let drain = |harness: &mut DefaultHarness, budget| {
        let (io, _) = harness.io_and_observer();
        let mut batch = io.receive(budget).expect("receive");
        let mut order = Vec::new();
        while let Some(mut packet) = batch.next_packet() {
            order.push((packet.ingress(), packet.bytes_mut()[0]));
            packet.recycle(DropReason::RouteMiss);
        }
        assert!(batch.finish().error.is_none());
        order
    };
    assert_eq!(
        drain(&mut harness, 2),
        [(CONFORMANCE_LAN, 1), (CONFORMANCE_WAN, 10)]
    );
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![2]]);
    assert_eq!(drain(&mut harness, 1), [(CONFORMANCE_LAN, 2)]);
    assert_eq!(drain(&mut harness, 1), [(CONFORMANCE_WAN, 11)]);
}

#[test]
#[should_panic(expected = "changed without being published")]
fn af_packet_harness_detects_a_write_into_an_unpublished_tx_frame() {
    // Regression for a reviewed mutation that copied a rejected payload into
    // the in-flight head TX frame: the copy counter is the engine's own, so
    // the harness must catch such a write from ring bytes alone. A one-frame
    // WAN ring keeps its only frame in flight; overwriting its payload
    // between the snapshot and the check must be detected.
    let mut harness = OneFrameHarness::new();
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![0x55; 8]]);
    {
        let (io, _) = harness.io_and_observer();
        let mut batch = io.receive(1).expect("receive");
        batch.next_packet().expect("packet").commit(CONFORMANCE_WAN);
        assert_eq!(batch.finish().tx_accepted, 1);
    }
    let wan = harness.view(WAN_PORT);
    assert_eq!(wan.tx_status(0), TP_STATUS_SEND_REQUEST);
    let trace = harness.trace();
    let snapshot = trace.tx_snapshot();
    wan.overwrite_tx_payload_for_test(0, &[0xee; 8]);
    trace.assert_tx_unchanged_except(&snapshot, &[]);
}

#[test]
fn af_packet_forgotten_lease_is_finalized_once_by_a_later_batch() {
    let mut harness = DefaultHarness::new();
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![9]]);
    let lan = harness.view(LAN_PORT);
    {
        let engine = &mut harness.io.engine;
        let mut batch = engine.receive(1).expect("receive");
        let lease = batch.next_packet().expect("packet");
        std::mem::forget(lease);
        assert_eq!(counts(&batch.finish()), (0, 0, 0, 0));
    }
    assert_eq!(lan.rx_status(), TP_STATUS_USER);
    {
        let engine = &mut harness.io.engine;
        let mut batch = engine.receive(1).expect("receive");
        assert!(batch.next_packet().is_none());
        assert_eq!(batch.rx_report().abandoned_leaks, 1);
        assert_eq!(batch.rx_report().blocks_returned, 1);
        let completion = batch.finish();
        // Not a core completion of this batch, so not `recycled`.
        assert_eq!(counts(&completion), (0, 0, 0, 0));
        assert!(completion.error.is_none());
    }
    assert_eq!(lan.rx_status(), TP_STATUS_KERNEL);
}

#[test]
fn af_packet_packet_io_hot_path_has_zero_steady_allocations() {
    let mut harness = DefaultHarness::new();
    for round in 0_u8..64 {
        harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![round; 64], vec![round; 65]]);
        let completion = {
            let (io, _) = harness.io_and_observer();
            let mut batch = io.receive(2).expect("receive");
            let mut first = batch.next_packet().expect("first");
            first.bytes_mut()[0] ^= 0xff;
            first.commit(CONFORMANCE_LAN);
            batch.next_packet().expect("second").commit(CONFORMANCE_WAN);
            batch.finish()
        };
        assert_eq!(counts(&completion), (2, 2, 0, 0));
        assert_eq!(harness.complete_copy_submissions().len(), 2);
        harness.drain_copy_tx_kicks();
        harness.drain_copy_source_events();
        harness.drain_copy_tx_events();
        harness.drain_copy_rx_block_returns();
    }
    let counters = harness.copy_operation_counters();
    assert_eq!(counters.copy_invocations, 128);
    assert_eq!(counters.steady_allocations, 0);
}

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
    harness.view(LAN_PORT).set_rx_status(2);
    for _ in 0..2 {
        let completion = {
            let (io, _) = harness.io_and_observer();
            let mut batch = io.receive(4).expect("receive");
            assert!(batch.next_packet().is_none());
            batch.finish()
        };
        assert_eq!(counts(&completion), (0, 0, 0, 0));
        assert_eq!(
            completion.error,
            Some(AfPacketIoError::Rx {
                interface: CONFORMANCE_LAN,
                fault: RxFault::Status {
                    block_index: 0,
                    status: 2,
                },
            })
        );
    }
    // The persistent halt is counted once, not once per batch.
    harness.trace().expected_stats[LAN_PORT].status_rejected = 1;
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

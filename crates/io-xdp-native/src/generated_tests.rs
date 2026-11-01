//! Generated-frame tests over the scripted heap kernel (M2 S5, X03).

// `drop(batch)` marks where a batch borrow ends; it is deliberate.
#![allow(clippy::drop_non_drop)]

use std::collections::VecDeque;

use ruster_io_xdp::{FrameStateKind, LedgerError, RawDescriptor};

use crate::{
    abi::XdpDescriptor,
    native_unsafe::heap_kernel::{allocation_count, ScriptedKernel},
    tx_completion_tests::{
        cancel_all, deliver, engine, engine_with, frame_base, frame_of, kernel, mirror_fill,
        mirror_tx, model, model_token, snapshot, staged, state, Model, Rng, FRAMES, FRAME_SIZE,
        HEADROOM, RING, RX_FRAMES,
    },
    CompletionInvalidReason, DrainOutcome, GeneratedAccounting, GeneratedAllocError,
    GeneratedRejectReason, RxFillAuditError, RxFillEngine, RxFillError, RxInvalidReason, TxBlocked,
    TxHandoff, TxRejection, TxSubmitError,
};

const GENERATED: u32 = FRAMES - RX_FRAMES;
const MAX_LEN: usize = FRAME_SIZE as usize - HEADROOM as usize;
/// A 42-byte Ethernet ARP request, the length core generates.
const ARP_LEN: usize = 42;

/// The deep audit plus the exact partitions of both pools.
fn audit(engine: &RxFillEngine<'_>) {
    engine.audit().expect("engine audit");
    let rx = engine.frame_accounting();
    assert_eq!(rx.total(), RX_FRAMES, "{rx:?}");
    assert_eq!(rx.free, engine.free_frames());
    let generated = engine.generated_accounting();
    assert_eq!(generated.generated_frames, GENERATED);
    assert_eq!(generated.total(), GENERATED, "{generated:?}");
    assert_eq!(generated.free, engine.generated_free_frames());
    assert_eq!(generated.leased, 0);
    assert_eq!(
        rx.tx_handoffs + generated.tx_handoffs,
        engine.tx_handoffs_outstanding()
    );
    assert_eq!(
        rx.tx_in_flight + generated.tx_in_flight,
        engine.tx_inflight()
    );
    assert!(engine.tx_inflight() <= engine.tx_inflight_limit());
    // allocated == committed + cancelled + abandoned + handoffs + leased
    let counters = engine.generated_counters();
    assert_eq!(
        counters.generated_allocated,
        counters.generated_committed
            + counters.generated_cancelled
            + counters.generated_abandoned
            + u64::from(generated.tx_handoffs),
        "{counters:?}"
    );
    assert_eq!(counters.generated_inflight, generated.tx_in_flight);
}

/// Writes a broadcast ARP request header (truncated to the frame) and
/// `marker` into the last visible byte.
fn arp_request(bytes: &mut [u8], marker: u8) {
    let mut template = [0_u8; 22];
    template[..6].fill(0xff);
    template[6..12].copy_from_slice(&[2, 0, 0, 0, 0, marker]);
    template[12..14].copy_from_slice(&[0x08, 0x06]);
    template[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    let head = bytes.len().min(template.len());
    bytes[..head].copy_from_slice(&template[..head]);
    if let Some(last) = bytes.last_mut() {
        *last = marker;
    }
}

/// Kernel transmit of everything in TX, completing each in order.
fn transmit_all(kernel: &ScriptedKernel) -> Vec<XdpDescriptor> {
    let mut sent = Vec::new();
    while let Some(descriptor) = kernel.consume_tx() {
        assert!(kernel.produce_completion(descriptor.address));
        sent.push(descriptor);
    }
    sent
}

fn generated_handoff(engine: &mut RxFillEngine<'_>, len: usize, marker: u8) -> TxHandoff {
    let mut frame = engine.allocate_generated(len).expect("generated frame");
    arp_request(frame.bytes_mut(), marker);
    frame.stage_tx()
}

/// Every Fill entry the engine ever published names an RX-pool frame.
fn assert_fill_is_rx_only(kernel: &ScriptedKernel) {
    let consumer = kernel.fill_consumer();
    for logical in consumer..kernel.fill_producer() {
        assert!(frame_of(kernel.fill_entry(logical)) < RX_FRAMES);
    }
}

#[test]
fn generated_lends_exact_visible_length_and_commits_through_tx() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    audit(&engine);
    assert_eq!(engine.generated_frames(), GENERATED);
    assert_eq!(engine.generated_max_len() as usize, MAX_LEN);

    // A full-length frame of 0xaa, transmitted and completed.
    let first = {
        let mut frame = engine.allocate_generated(MAX_LEN).expect("full length");
        assert_eq!(frame.len() as usize, MAX_LEN);
        assert_eq!(frame.bytes().len(), MAX_LEN);
        assert!(frame.bytes().iter().all(|byte| *byte == 0), "zeroed");
        frame.bytes_mut().fill(0xaa);
        let id = frame.frame().index();
        assert!(id >= RX_FRAMES, "allocated from the generated pool");
        assert_eq!(frame.descriptor().data_offset() as u64, HEADROOM);
        let report = frame.commit().expect("committed");
        assert_eq!(report.submitted(), 1);
        id
    };
    assert_eq!(state(&engine, first), FrameStateKind::TxOwnedByKernel);
    assert_eq!(engine.generated_counters().generated_inflight, 1);
    audit(&engine);
    let sent = transmit_all(&kernel);
    assert_eq!(sent[0].address, frame_base(first) + HEADROOM);
    assert_eq!(sent[0].len as usize, MAX_LEN);
    let rx_free = engine.free_frames();
    let report = engine.reap_completions(RING).expect("reap");
    assert_eq!(report.reaped(), 1);
    assert_eq!(state(&engine, first), FrameStateKind::Free);
    assert_eq!(engine.free_frames(), rx_free, "not to the RX free list");
    assert_eq!(engine.generated_free_frames(), GENERATED);
    audit(&engine);

    // Cycle the FIFO back to the same frame with a short request: exactly
    // the requested bytes are visible, zeroed, and transmitted; the
    // earlier bytes beyond them are neither exposed nor rewritten.
    for _ in 1..GENERATED {
        engine.allocate_generated(ARP_LEN).expect("frame").cancel();
    }
    let mut frame = engine.allocate_generated(ARP_LEN).expect("same frame");
    assert_eq!(frame.frame().index(), first);
    assert_eq!(frame.bytes_mut().len(), ARP_LEN);
    assert!(frame.bytes().iter().all(|byte| *byte == 0), "re-zeroed");
    arp_request(frame.bytes_mut(), 7);
    let expected: Vec<u8> = frame.bytes().to_vec();
    let report = frame.commit().expect("committed");
    assert_eq!(report.submitted(), 1);
    let descriptor = kernel.consume_tx().expect("TX");
    assert_eq!(
        descriptor,
        XdpDescriptor {
            address: frame_base(first) + HEADROOM,
            len: ARP_LEN as u32,
            options: 0,
        }
    );
    let mut wire = vec![0_u8; MAX_LEN];
    kernel.read_umem(descriptor.address, &mut wire);
    assert_eq!(&wire[..ARP_LEN], &expected[..]);
    assert!(wire[ARP_LEN..].iter().all(|byte| *byte == 0xaa));
    assert!(kernel.produce_completion(descriptor.address));
    let batch = engine.poll(RING).expect("poll reaps first");
    assert_eq!(batch.completions().reaped(), 1);
    drop(batch);
    assert_fill_is_rx_only(&kernel);
    let counters = engine.generated_counters();
    assert_eq!(counters.generated_allocated, 1 + GENERATED as u64);
    assert_eq!(counters.generated_committed, 2);
    assert_eq!(counters.generated_completed, 2);
    assert_eq!(counters.generated_cancelled, u64::from(GENERATED - 1));
    assert_eq!(counters.generated_inflight, 0);
    assert_eq!(engine.tx_counters().tx_completed, 2);
    audit(&engine);
}

#[test]
fn generated_refusals_are_typed_counted_and_change_nothing() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let before = snapshot(engine.ledger());
    let cases = [
        (0, GeneratedRejectReason::ZeroLength),
        (1, GeneratedRejectReason::BelowMinimum),
        (13, GeneratedRejectReason::BelowMinimum),
        (MAX_LEN + 1, GeneratedRejectReason::TooLarge),
        (FRAME_SIZE as usize, GeneratedRejectReason::TooLarge),
        (usize::MAX, GeneratedRejectReason::TooLarge),
    ];
    for (len, reason) in cases {
        assert_eq!(
            engine.allocate_generated(len).map(|_| ()),
            Err(GeneratedAllocError::Rejected(reason)),
            "{len}"
        );
        assert_eq!(snapshot(engine.ledger()), before);
        assert_eq!(engine.generated_free_frames(), GENERATED);
    }
    // Both boundaries are accepted.
    engine.allocate_generated(14).expect("minimum").cancel();
    engine
        .allocate_generated(MAX_LEN)
        .expect("maximum")
        .cancel();

    // An empty pool is Unavailable at once, never blocking, and recovers.
    let mut held: Vec<TxHandoff> = (0..GENERATED)
        .map(|marker| generated_handoff(&mut engine, ARP_LEN, u8::try_from(marker).expect("u8")))
        .collect();
    let before = snapshot(engine.ledger());
    for _ in 0..3 {
        assert_eq!(
            engine.allocate_generated(ARP_LEN).map(|_| ()),
            Err(GeneratedAllocError::Unavailable)
        );
    }
    assert_eq!(snapshot(engine.ledger()), before);
    audit(&engine);
    cancel_all(&mut engine, held.pop());
    engine
        .allocate_generated(ARP_LEN)
        .expect("recovered")
        .cancel();

    // Draining refuses before looking at the length or the pool.
    cancel_all(&mut engine, held);
    let report = engine.drain(1).expect("drain");
    assert_eq!(report.outcome(), DrainOutcome::Drained);
    assert_eq!(report.generated_accounting().free, GENERATED);
    for len in [0, ARP_LEN] {
        assert_eq!(
            engine.allocate_generated(len).map(|_| ()),
            Err(GeneratedAllocError::Rejected(
                GeneratedRejectReason::Draining
            ))
        );
    }
    let counters = engine.generated_counters();
    assert_eq!(
        counters.generated_rejected(GeneratedRejectReason::ZeroLength),
        1
    );
    assert_eq!(
        counters.generated_rejected(GeneratedRejectReason::BelowMinimum),
        2
    );
    assert_eq!(
        counters.generated_rejected(GeneratedRejectReason::TooLarge),
        3
    );
    assert_eq!(
        counters.generated_rejected(GeneratedRejectReason::Draining),
        2
    );
    assert_eq!(counters.generated_rejected_total(), 8);
    assert_eq!(counters.generated_unavailable, 3);
    assert_eq!(counters.generated_allocated, 3 + u64::from(GENERATED));
    for (index, reason) in GeneratedRejectReason::ALL.into_iter().enumerate() {
        assert_eq!(reason.index(), index);
        assert!(!reason.code().is_empty());
    }
    audit(&engine);
}

#[test]
fn generated_cancel_abandon_and_handoff_cancel_return_to_the_generated_pool() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let rx_free = engine.free_frames();
    // Explicit cancel.
    let frame = engine.allocate_generated(ARP_LEN).expect("frame");
    let cancelled = frame.frame().index();
    let first_generation = frame.token().generation().get();
    frame.cancel();
    assert_eq!(state(&engine, cancelled), FrameStateKind::Free);
    // Abandon: drop without an end.
    {
        let mut frame = engine.allocate_generated(ARP_LEN).expect("frame");
        frame.bytes_mut()[0] = 1;
    }
    // Staged, then cancelled as a handoff.
    let handoff = generated_handoff(&mut engine, ARP_LEN, 3);
    let staged_frame = handoff.frame().index();
    assert_eq!(state(&engine, staged_frame), FrameStateKind::PendingTx);
    assert_eq!(engine.generated_accounting().tx_handoffs, 1);
    audit(&engine);
    cancel_all(&mut engine, [handoff]);
    assert_eq!(state(&engine, staged_frame), FrameStateKind::Free);
    assert_eq!(engine.free_frames(), rx_free, "RX pool untouched");
    assert_eq!(engine.generated_free_frames(), GENERATED);
    let counters = engine.generated_counters();
    assert_eq!(counters.generated_allocated, 3);
    assert_eq!(counters.generated_cancelled, 2);
    assert_eq!(counters.generated_abandoned, 1);
    assert_eq!(counters.generated_committed, 0);
    // A generated cancel is not an RX handoff cancel.
    assert_eq!(engine.counters().tx_handoffs_cancelled, 0);
    assert_eq!(engine.counters().rx_abandoned, 0);
    // The next cycle of the frame has the next generation.
    let mut next = None;
    for _ in 0..GENERATED {
        let frame = engine.allocate_generated(ARP_LEN).expect("frame");
        if frame.frame().index() == cancelled {
            next = Some(frame.token().generation().get());
        }
        frame.cancel();
    }
    assert_eq!(next, Some(first_generation + 1));
    assert_fill_is_rx_only(&kernel);
    audit(&engine);
}

#[test]
fn generated_commit_shares_the_tx_cap_and_back_pressure() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    // Forwarded frames fill the TX ring.
    let mut slots: Vec<Option<TxHandoff>> = staged(&kernel, &mut engine, RING as usize)
        .into_iter()
        .map(Some)
        .collect();
    let report = engine.submit_tx_batch(&mut slots).expect("batch");
    assert_eq!(report.submitted(), RING);
    // A generated commit meets the same full ring and comes back intact.
    let mut frame = engine.allocate_generated(ARP_LEN).expect("frame");
    arp_request(frame.bytes_mut(), 9);
    let rejected = frame.commit().expect_err("ring full");
    assert_eq!(rejected.reason(), TxRejection::Blocked(TxBlocked::RingFull));
    let handoff = rejected.into_handoff();
    let generated_frame = handoff.frame().index();
    assert_eq!(state(&engine, generated_frame), FrameStateKind::PendingTx);
    assert_eq!(engine.generated_counters().generated_committed, 0);
    audit(&engine);
    // The kernel consumes TX but completes nothing: the in-flight cap.
    let mut consumed = VecDeque::new();
    while let Some(descriptor) = kernel.consume_tx() {
        consumed.push_back(descriptor.address);
    }
    let rejected = engine.submit_tx(handoff).expect_err("in-flight cap");
    assert_eq!(
        rejected.reason(),
        TxRejection::Blocked(TxBlocked::InflightLimit)
    );
    let handoff = rejected.into_handoff();
    assert_eq!(engine.tx_inflight(), RING);
    // One completion makes room; the generated handoff goes next to the
    // forwarded frames in one batch.
    assert!(kernel.produce_completion(consumed.pop_front().expect("one")));
    assert_eq!(engine.reap_completions(RING).expect("reap").reaped(), 1);
    let mut slots = [Some(handoff)];
    let report = engine.submit_tx_batch(&mut slots).expect("batch");
    assert_eq!(report.submitted(), 1);
    assert_eq!(engine.tx_inflight(), RING);
    assert_eq!(engine.generated_counters().generated_inflight, 1);
    assert_eq!(engine.generated_accounting().tx_in_flight, 1);
    assert_eq!(engine.frame_accounting().tx_in_flight, RING - 1);
    audit(&engine);
    let counters = engine.tx_counters();
    assert_eq!(counters.tx_ring_full, 1);
    assert_eq!(counters.tx_inflight_limited, 1);
    // Drain returns both pools.
    for address in consumed {
        assert!(kernel.produce_completion(address));
    }
    transmit_all(&kernel);
    let report = engine.drain(4).expect("drain");
    assert_eq!(report.outcome(), DrainOutcome::Drained);
    assert_eq!(report.generated_accounting().free, GENERATED);
    assert_eq!(report.accounting().tx_in_flight, 0);
    assert_eq!(engine.generated_counters().generated_completed, 1);
    audit(&engine);
}

#[test]
fn generated_and_rx_completions_stay_in_their_pools() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let rx = staged(&kernel, &mut engine, 4);
    let rx_frames: Vec<u32> = rx.iter().map(|handoff| handoff.frame().index()).collect();
    let mut slots: Vec<Option<TxHandoff>> = Vec::new();
    for (index, handoff) in rx.into_iter().enumerate() {
        slots.push(Some(handoff));
        slots.push(Some(generated_handoff(
            &mut engine,
            ARP_LEN + index,
            u8::try_from(index).expect("u8"),
        )));
    }
    let report = engine.submit_tx_batch(&mut slots).expect("batch");
    assert_eq!(report.submitted(), 8);
    audit(&engine);
    let mut sent: Vec<XdpDescriptor> = Vec::new();
    while let Some(descriptor) = kernel.consume_tx() {
        sent.push(descriptor);
    }
    let rx_free = engine.free_frames();
    // Complete in reverse order, one at a time.
    for (completed, descriptor) in sent.iter().rev().enumerate() {
        assert!(kernel.produce_completion(descriptor.address));
        assert_eq!(engine.reap_completions(1).expect("reap").reaped(), 1);
        let frame = frame_of(descriptor.address);
        assert_eq!(state(&engine, frame), FrameStateKind::Free);
        let generated_done = sent
            .iter()
            .rev()
            .take(completed + 1)
            .filter(|descriptor| frame_of(descriptor.address) >= RX_FRAMES)
            .count();
        let rx_done = completed + 1 - generated_done;
        assert_eq!(engine.free_frames() as usize, rx_free as usize + rx_done);
        assert_eq!(engine.generated_free_frames() as usize, generated_done);
        audit(&engine);
    }
    assert!(engine.tx_counters().tx_completions_reordered > 0);
    // Refill republishes exactly the RX frames, never a generated one.
    let refill = engine.refill().expect("refill");
    assert_eq!(refill.published(), 0, "Fill is still full");
    for frame in &rx_frames {
        assert_eq!(state(&engine, *frame), FrameStateKind::Free);
    }
    for _ in 0..4 {
        deliver(&kernel, 60);
    }
    let mut batch = engine.poll(RING).expect("poll");
    while let Some(frame) = batch.next_frame() {
        assert!(frame.frame().index() < RX_FRAMES);
        frame.recycle();
    }
    drop(batch);
    assert_fill_is_rx_only(&kernel);
    assert_eq!(engine.generated_free_frames(), GENERATED);
    audit(&engine);
}

#[test]
fn kernel_returns_naming_the_other_pool_are_refused() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    // An RX descriptor naming a free generated frame: nothing mutated.
    let free_generated = RX_FRAMES;
    let before = snapshot(engine.ledger());
    assert!(kernel.produce_rx(XdpDescriptor {
        address: frame_base(free_generated) + HEADROOM,
        len: 60,
        options: 0,
    }));
    let batch = engine.poll(RING).expect("poll");
    assert_eq!(batch.remaining(), 0);
    drop(batch);
    assert_eq!(snapshot(engine.ledger()), before);
    assert_eq!(
        engine
            .counters()
            .rx_invalid(RxInvalidReason::NotKernelOwned),
        1
    );
    // A completion naming a free generated frame, and one naming a staged
    // generated frame: nothing mutated.
    let handoff = generated_handoff(&mut engine, ARP_LEN, 1);
    let staged_frame = handoff.frame().index();
    let before = snapshot(engine.ledger());
    assert!(kernel.produce_completion(frame_base(staged_frame) + HEADROOM));
    assert!(kernel.produce_completion(frame_base(free_generated + 2) + HEADROOM));
    let report = engine.reap_completions(RING).expect("reap");
    assert_eq!(report.invalid(), 2);
    assert_eq!(snapshot(engine.ledger()), before);
    // An RX descriptor naming an in-flight generated frame: nothing.
    let report = engine.submit_tx(handoff).expect("submitted");
    assert_eq!(report.submitted(), 1);
    let before = snapshot(engine.ledger());
    assert!(kernel.produce_rx(XdpDescriptor {
        address: frame_base(staged_frame) + HEADROOM,
        len: 60,
        options: 0,
    }));
    let batch = engine.poll(RING).expect("poll");
    assert_eq!(batch.remaining(), 0);
    drop(batch);
    assert_eq!(snapshot(engine.ledger()), before);
    // A generated completion at a different address than submitted is
    // quarantined in the generated pool.
    let descriptor = kernel.consume_tx().expect("TX");
    assert!(kernel.produce_completion(descriptor.address - HEADROOM));
    let report = engine.reap_completions(RING).expect("reap");
    assert_eq!(report.invalid(), 1);
    assert_eq!(state(&engine, staged_frame), FrameStateKind::Quarantined);
    let counters = engine.tx_counters();
    assert_eq!(
        counters.tx_invalid_completion(CompletionInvalidReason::NotInFlight),
        2
    );
    assert_eq!(
        counters.tx_invalid_completion(CompletionInvalidReason::AddressMismatch),
        1
    );
    let generated = engine.generated_accounting();
    assert_eq!(generated.quarantined, 1);
    assert_eq!(generated.free, GENERATED - 1);
    assert_eq!(engine.frame_accounting().quarantined, 0);
    assert_eq!(engine.counters().frames_quarantined, 1);
    assert_eq!(engine.generated_counters().generated_inflight, 0);
    let counters = engine.generated_counters();
    assert_eq!(counters.generated_quarantined_after_tx, 1);
    // committed == completed + inflight + quarantined after TX.
    assert_eq!(
        counters.generated_committed,
        counters.generated_completed
            + u64::from(counters.generated_inflight)
            + counters.generated_quarantined_after_tx
    );
    audit(&engine);
}

#[test]
fn generated_foreign_handoffs_are_refused_and_returned_intact() {
    // Distinct domains, and one `UmemDomainId` reused for both ledgers:
    // only the engine identity in the handoff tells them apart.
    for (mine_domain, other_domain) in [(0x5502, 0x5503), (0x5502, 0x5502)] {
        let first = kernel();
        let second = kernel();
        let mut mine = engine_with(&first, mine_domain);
        let mut other = engine_with(&second, other_domain);
        let foreign = generated_handoff(&mut other, ARP_LEN, 1);
        let own = generated_handoff(&mut mine, ARP_LEN, 2);
        if mine_domain == other_domain {
            assert_eq!(foreign.token(), own.token(), "same domain, same token");
        }
        let before = snapshot(mine.ledger());
        let counters = (mine.tx_counters(), mine.generated_counters());
        let token = foreign.token();

        let rejected = mine.submit_tx(foreign).expect_err("foreign");
        assert_eq!(
            rejected.reason(),
            TxRejection::Invalid(LedgerError::ForeignTokenDomain)
        );
        let foreign = rejected.into_handoff();
        assert_eq!(foreign.token(), token, "returned intact");
        // In a batch, the foreign slot refuses the whole call.
        let mut slots = [Some(own), Some(foreign)];
        assert_eq!(
            mine.submit_tx_batch(&mut slots),
            Err(TxSubmitError::Handoff {
                index: 1,
                error: LedgerError::ForeignTokenDomain,
            })
        );
        assert!(slots.iter().all(Option::is_some));
        assert_eq!(first.tx_pending(), 0, "nothing published");
        assert_eq!(snapshot(mine.ledger()), before);
        assert_eq!(
            (mine.tx_counters(), mine.generated_counters()),
            counters,
            "a refused submission counts nothing"
        );
        let [own, foreign] = slots;
        let (error, foreign) = mine
            .cancel_tx_handoff(foreign.expect("kept"))
            .expect_err("foreign cancel");
        assert_eq!(error, RxFillError::Ledger(LedgerError::ForeignTokenDomain));
        assert_eq!(snapshot(mine.ledger()), before);
        audit(&mine);
        cancel_all(&mut other, [foreign]);
        cancel_all(&mut mine, [own.expect("kept")]);
        audit(&mine);
        audit(&other);
        assert_eq!(mine.generated_free_frames(), GENERATED);
        assert_eq!(other.generated_free_frames(), GENERATED);
    }
}

#[test]
fn generated_duplicate_handoff_in_one_batch_is_refused_and_rolled_back() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let first = generated_handoff(&mut engine, ARP_LEN, 1);
    let second = generated_handoff(&mut engine, ARP_LEN, 2);
    let duplicate = first.forged_copy_for_test();
    let frame = first.frame().index();
    let before = snapshot(engine.ledger());
    let counters = engine.generated_counters();
    let mut slots = [Some(first), Some(second), Some(duplicate)];
    assert!(matches!(
        engine.submit_tx_batch(&mut slots),
        Err(TxSubmitError::Handoff {
            index: 2,
            error: LedgerError::WrongState {
                expected: FrameStateKind::PendingTx,
                actual: FrameStateKind::TxReserved,
                ..
            },
        })
    ));
    // Both reservations before the duplicate were rolled back.
    assert_eq!(snapshot(engine.ledger()), before);
    assert_eq!(state(&engine, frame), FrameStateKind::PendingTx);
    assert_eq!(engine.generated_counters(), counters);
    assert_eq!(engine.generated_accounting().tx_handoffs, 2);
    assert_eq!(kernel.tx_pending(), 0);
    let [first, second, duplicate] = slots;
    // The forged copy owns no frame of its own.
    std::mem::forget(duplicate);
    let report = engine
        .submit_tx_batch(&mut [first, second])
        .expect("the real handoffs still submit");
    assert_eq!(report.submitted(), 2);
    assert_eq!(engine.generated_counters().generated_committed, 2);
    audit(&engine);
}

#[test]
fn generated_generation_exhaustion_quarantines_and_moves_on() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    engine.exhaust_generated_generation_for_test(RX_FRAMES);
    let frame = engine.allocate_generated(ARP_LEN).expect("next frame");
    assert_eq!(frame.frame().index(), RX_FRAMES + 1);
    frame.cancel();
    assert_eq!(state(&engine, RX_FRAMES), FrameStateKind::Quarantined);
    assert_eq!(engine.generated_accounting().quarantined, 1);
    assert_eq!(engine.counters().frames_quarantined, 1);
    audit(&engine);
}

#[test]
fn generated_audit_detects_pool_divergence() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    audit(&engine);
    // A lost generated free-list entry.
    let lost = engine.drop_generated_free_entry_for_test().expect("entry");
    assert_eq!(
        engine.audit(),
        Err(RxFillAuditError::GeneratedCount {
            state: FrameStateKind::Free,
            recorded: GENERATED - 1,
            actual: GENERATED,
        })
    );
    assert!(engine.push_generated_free_entry_for_test(lost));
    audit(&engine);
    // An RX frame in the generated free list.
    let rx = engine.drop_free_entry_for_test().expect("RX entry");
    engine.drop_generated_free_entry_for_test().expect("room");
    assert!(engine.push_generated_free_entry_for_test(rx));
    assert_eq!(
        engine.audit(),
        Err(RxFillAuditError::GeneratedFreeListEntry { frame: rx })
    );
    let kernel = crate::tx_completion_tests::kernel();
    let mut engine = crate::tx_completion_tests::engine(&kernel);
    // A generated frame in the RX free list.
    engine.drop_generated_free_entry_for_test().expect("entry");
    assert!(engine.push_free_entry_for_test(RX_FRAMES));
    assert_eq!(
        engine.audit(),
        Err(RxFillAuditError::FreeListEntry { frame: RX_FRAMES })
    );
    let kernel = crate::tx_completion_tests::kernel();
    let mut engine = crate::tx_completion_tests::engine(&kernel);
    // A skewed handoff record.
    let handoff = generated_handoff(&mut engine, ARP_LEN, 1);
    audit(&engine);
    engine.skew_generated_handoffs_for_test(-1);
    assert!(matches!(
        engine.audit(),
        Err(RxFillAuditError::GeneratedCount {
            state: FrameStateKind::PendingTx,
            ..
        })
    ));
    engine.skew_generated_handoffs_for_test(1);
    cancel_all(&mut engine, [handoff]);
    audit(&engine);
}

#[test]
fn generated_steady_state_does_not_allocate() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let cycle = |engine: &mut RxFillEngine<'_>, round: u32| {
        let marker = u8::try_from(round % 251).expect("u8");
        // Refusals.
        let _ = engine.allocate_generated(0);
        let _ = engine.allocate_generated(MAX_LEN + 1);
        // Commit, stage + batch, cancel, abandon.
        let refused = match engine.allocate_generated(ARP_LEN) {
            Ok(mut frame) => {
                arp_request(frame.bytes_mut(), marker);
                frame.commit().err()
            }
            Err(_) => None,
        };
        if let Some(refused) = refused {
            let _ = engine.cancel_tx_handoff(refused.into_handoff());
        }
        let handoff = match engine.allocate_generated(60) {
            Ok(mut frame) => {
                arp_request(frame.bytes_mut(), marker);
                Some(frame.stage_tx())
            }
            Err(_) => None,
        };
        let mut slots = [handoff];
        let _ = engine.submit_tx_batch(&mut slots);
        if let Some(handoff) = slots[0].take() {
            let _ = engine.cancel_tx_handoff(handoff);
        }
        if let Ok(frame) = engine.allocate_generated(ARP_LEN) {
            frame.cancel();
        }
        if let Ok(mut frame) = engine.allocate_generated(ARP_LEN) {
            frame.bytes_mut()[0] = marker;
        }
        // Kernel transmit with one round of lag, then a poll that reaps.
        if round.is_multiple_of(2) {
            while let Some(descriptor) = kernel.consume_tx() {
                assert!(kernel.produce_completion(descriptor.address));
            }
        }
        drop(engine.poll(RING).expect("poll"));
        let _ = engine.generated_accounting();
        let _ = engine.frame_accounting();
    };
    for round in 0..4 {
        cycle(&mut engine, round);
    }
    let before = allocation_count();
    for round in 0..256 {
        cycle(&mut engine, round);
    }
    while let Some(descriptor) = kernel.consume_tx() {
        assert!(kernel.produce_completion(descriptor.address));
    }
    let report = engine.drain(4).expect("drain");
    assert_eq!(allocation_count(), before, "generated hot path allocated");
    assert_eq!(report.outcome(), DrainOutcome::Drained);
    let counters = engine.generated_counters();
    assert!(counters.generated_committed > 256, "{counters:?}");
    assert!(counters.generated_abandoned > 0, "{counters:?}");
    assert_eq!(counters.generated_completed, counters.generated_committed);
    audit(&engine);
}

/// Mirrors the semantics of `ruster-io-conformance`'s generated suite at
/// the engine layer (the suite itself needs a core `GeneratedPacketIo`,
/// which is X04): one session of allocation attempts, commits, cancels,
/// abandons, and rejects keeps core's three `GeneratedBatchCompletion`
/// invariants, binds only successful allocations, restores the physical
/// pool after rejected submissions with a new generation, and returns the
/// exact submitted frame on completion.
#[test]
fn generated_session_keeps_core_generated_batch_invariants() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    // Leave one TX slot, so the second commit is rejected (back-pressure).
    let mut slots: Vec<Option<TxHandoff>> = staged(&kernel, &mut engine, RING as usize - 1)
        .into_iter()
        .map(Some)
        .collect();
    let _ = engine.submit_tx_batch(&mut slots).expect("batch");
    let mut attempts = 0_usize;
    let mut failed = 0_usize;
    let (mut requested, mut accepted, mut rejected) = (0_usize, 0_usize, 0_usize);
    let mut submitted_frames = Vec::new();
    let mut rejected_frames = Vec::new();
    for len in [
        0,
        ARP_LEN,
        13,
        ARP_LEN,
        MAX_LEN + 1,
        ARP_LEN,
        ARP_LEN,
        64,
        60,
    ] {
        attempts += 1;
        let Ok(mut frame) = engine.allocate_generated(len) else {
            failed += 1;
            continue;
        };
        assert_eq!(frame.bytes_mut().len(), len, "exact visible length");
        arp_request(frame.bytes_mut(), u8::try_from(len).expect("u8"));
        match attempts % 3 {
            0 => frame.cancel(),
            1 => drop(frame),
            _ => {
                requested += 1;
                let id = frame.frame().index();
                let generation = frame.token().generation().get();
                match frame.commit() {
                    Ok(report) => {
                        assert_eq!(report.submitted(), 1);
                        accepted += 1;
                        submitted_frames.push(id);
                    }
                    Err(refused) => {
                        rejected += 1;
                        cancel_all(&mut engine, [refused.into_handoff()]);
                        rejected_frames.push((id, generation));
                    }
                }
            }
        }
    }
    let counters = engine.generated_counters();
    let allocated = usize::try_from(counters.generated_allocated).expect("small");
    let cancelled = usize::try_from(counters.generated_cancelled).expect("small") - rejected; // handoff cancels after a rejected commit
    let abandoned = usize::try_from(counters.generated_abandoned).expect("small");
    let failures = counters.generated_unavailable + counters.generated_rejected_total();
    assert_eq!(usize::try_from(failures).expect("small"), failed);
    assert_eq!(attempts, allocated + failed);
    assert_eq!(allocated, requested + cancelled + abandoned);
    assert_eq!(accepted + rejected, requested);
    assert_eq!(
        usize::try_from(counters.generated_committed).expect("small"),
        accepted
    );
    assert!(accepted > 0 && rejected > 0, "{accepted} {rejected}");
    // Rejected submissions are back in the physical pool; the next cycle of
    // the frame has a newer generation.
    for (frame, _) in &rejected_frames {
        assert_eq!(state(&engine, *frame), FrameStateKind::Free);
    }
    let mut cycled = Vec::new();
    while let Ok(frame) = engine.allocate_generated(ARP_LEN) {
        cycled.push(frame.stage_tx());
    }
    for (frame, generation) in &rejected_frames {
        let handoff = cycled
            .iter()
            .find(|handoff| handoff.frame().index() == *frame)
            .expect("the rejected frame is allocatable again");
        assert!(handoff.token().generation().get() > *generation);
    }
    cancel_all(&mut engine, cycled);
    // Completion returns the exact submitted generated frames.
    while let Some(descriptor) = kernel.consume_tx() {
        assert!(kernel.produce_completion(descriptor.address));
    }
    let _ = engine.reap_completions(RING).expect("reap");
    for frame in submitted_frames {
        assert_eq!(state(&engine, frame), FrameStateKind::Free);
    }
    assert_eq!(engine.generated_free_frames(), GENERATED);
    audit(&engine);
}

// Differential against the io-xdp FakeKernel generated lifecycle.

/// The ledger snapshot equals the model's, projected as in the TX
/// differential, and the generated accounting equals a scan of the model.
fn assert_same(engine: &RxFillEngine<'_>, model: &Model, step: usize) {
    let project = |(kind, generation): (FrameStateKind, Option<u64>)| match kind {
        FrameStateKind::RxAvailable => (FrameStateKind::FillOwnedByKernel, generation),
        FrameStateKind::CompletionAvailable => (FrameStateKind::TxOwnedByKernel, generation),
        _ => (kind, generation),
    };
    let model_view: Vec<_> = snapshot(model.ledger()).into_iter().map(project).collect();
    assert_eq!(snapshot(engine.ledger()), model_view, "step {step}");
    model.ledger().deep_audit().expect("model audit");
    engine
        .audit()
        .unwrap_or_else(|error| panic!("step {step}: {error:?}"));
    let count = |kind| {
        u32::try_from(
            model_view[RX_FRAMES as usize..]
                .iter()
                .filter(|(state, _)| *state == kind)
                .count(),
        )
        .expect("small")
    };
    let generated: GeneratedAccounting = engine.generated_accounting();
    assert_eq!(generated.free, count(FrameStateKind::Free), "step {step}");
    assert_eq!(generated.tx_handoffs, count(FrameStateKind::PendingTx));
    assert_eq!(
        generated.tx_in_flight,
        count(FrameStateKind::TxOwnedByKernel)
    );
    assert_eq!(generated.quarantined, count(FrameStateKind::Quarantined));
    assert_eq!(engine.frame_accounting().total(), RX_FRAMES);
    for (frame, (kind, _)) in model_view.iter().enumerate() {
        if frame >= RX_FRAMES as usize {
            assert!(
                !matches!(
                    kind,
                    FrameStateKind::FillOwnedByKernel | FrameStateKind::RxAvailable
                ),
                "step {step}: generated frame {frame} reached Fill/RX"
            );
        }
    }
}

#[test]
fn generated_differential_matches_fake_kernel_generated_lifecycle() {
    for seed in [
        0x6e6e_0001_u64,
        0xdead_beef_0bad_f00d,
        0x1234_5678_9abc_def0,
    ] {
        let kernel = kernel();
        let mut engine = engine(&kernel);
        let mut model = model();
        let mut mirrored = 0_u32;
        let mut rng = Rng(seed);
        let mut handoffs: Vec<TxHandoff> = Vec::new();
        let mut consumed: VecDeque<u64> = VecDeque::new();
        let mut lens = [0_u32; FRAMES as usize];
        mirror_fill(&kernel, &mut model, &mut mirrored);
        assert_same(&engine, &model, 0);
        let steps = if cfg!(miri) { 80 } else { 800 };
        for step in 1..=steps {
            match rng.below(7) {
                // Kernel receive.
                0 => {
                    for _ in 0..=rng.below(u64::from(RING)) {
                        let room = RING - kernel.rx_producer().wrapping_sub(kernel.rx_consumer());
                        if kernel.fill_pending() == 0 || room == 0 {
                            break;
                        }
                        let base = kernel.consume_fill().expect("Fill");
                        assert!(
                            frame_of(base) < RX_FRAMES,
                            "step {step}: Fill got generated"
                        );
                        let len = 14 + u32::try_from(rng.below(1_000)).expect("small");
                        lens[frame_of(base) as usize] = len;
                        assert!(kernel.produce_rx(XdpDescriptor {
                            address: base + HEADROOM,
                            len,
                            options: 0,
                        }));
                        model
                            .kernel_consume_fill()
                            .expect("model Fill")
                            .produce_rx(RawDescriptor {
                                addr: base + HEADROOM,
                                len,
                                options: 0,
                            })
                            .expect("model RX");
                    }
                }
                // Engine poll: reap, refill, lend; recycle or stage.
                1 => {
                    let completions = kernel.completion_producer() - kernel.completion_consumer();
                    let budget = u32::try_from(rng.below(u64::from(RING) + 1)).expect("small");
                    let mut batch = engine.poll(budget).expect("poll");
                    assert_eq!(batch.completions().reaped(), completions, "step {step}");
                    let consumed_rx = batch.remaining();
                    while let Some(frame) = batch.next_frame() {
                        if rng.below(3) == 0 {
                            frame.recycle();
                        } else {
                            handoffs.push(frame.stage_tx());
                        }
                    }
                    drop(batch);
                    if completions > 0 {
                        model
                            .acquire_completion(completions as usize)
                            .expect("model completion acquire")
                            .release_consume()
                            .expect("model completion consume");
                    }
                    if consumed_rx > 0 {
                        model
                            .acquire_rx(consumed_rx as usize)
                            .expect("model RX acquire")
                            .release_consume()
                            .expect("model RX consume");
                    }
                    for frame in 0..RX_FRAMES {
                        let engine_kind = state(&engine, frame);
                        let model_kind = model.ledger().state(frame).expect("frame").kind();
                        if model_kind == FrameStateKind::Leased {
                            let token = model_token(&model, frame);
                            match engine_kind {
                                FrameStateKind::PendingTx => {
                                    model.stage_tx(token).expect("model stage");
                                }
                                _ => model.recycle_lease(token).expect("model recycle"),
                            }
                        }
                    }
                    mirror_fill(&kernel, &mut model, &mut mirrored);
                }
                // Submit a random prefix of the held (mixed) handoffs.
                2 => {
                    let count = rng.below(handoffs.len() as u64 + 1) as usize;
                    let mut slots: Vec<Option<TxHandoff>> =
                        handoffs.drain(..count).map(Some).collect();
                    let report = engine.submit_tx_batch(&mut slots).expect("batch");
                    let submitted = slots.iter().filter(|slot| slot.is_none()).count();
                    handoffs.splice(0..0, slots.into_iter().flatten());
                    let submitted = u32::try_from(submitted).expect("small");
                    assert_eq!(report.submitted(), submitted, "step {step}");
                    mirror_tx(&kernel, &mut model, submitted, &lens);
                }
                // Kernel transmit: consume some TX, complete some with lag.
                3 => {
                    for _ in 0..rng.below(u64::from(RING)) {
                        if let Some(descriptor) = kernel.consume_tx() {
                            let frame = frame_of(descriptor.address);
                            assert_eq!(descriptor.address, frame_base(frame) + HEADROOM);
                            assert_eq!(descriptor.len, lens[frame as usize], "step {step}");
                            consumed.push_back(descriptor.address);
                        }
                    }
                    for _ in 0..rng.below(u64::from(RING)) {
                        let Some(address) = consumed.pop_front() else {
                            break;
                        };
                        assert!(kernel.produce_completion(address));
                        model
                            .kernel_consume_tx()
                            .expect("model TX")
                            .produce_completion()
                            .expect("model completion");
                    }
                }
                // Cancel a random handoff (either pool).
                4 => {
                    if !handoffs.is_empty() {
                        let pick = rng.below(handoffs.len() as u64) as usize;
                        let handoff = handoffs.swap_remove(pick);
                        let token = model_token(&model, handoff.frame().index());
                        cancel_all(&mut engine, [handoff]);
                        model.cancel_pending_tx(token).expect("model cancel");
                        model.recycle_lease(token).expect("model recycle");
                    }
                }
                // Generate: allocate (sometimes an invalid length), then
                // commit, stage, cancel, or abandon.
                5 => {
                    for _ in 0..=rng.below(u64::from(GENERATED) + 1) {
                        let len = match rng.below(8) {
                            0 => 0,
                            1 => 13,
                            2 => MAX_LEN + 1,
                            _ => 14 + rng.below(MAX_LEN as u64 - 13) as usize,
                        };
                        let free = engine.generated_free_frames();
                        let action = rng.below(6);
                        match engine.allocate_generated(len) {
                            Err(GeneratedAllocError::Rejected(_)) => {
                                assert!(!(14..=MAX_LEN).contains(&len), "step {step}");
                            }
                            Err(GeneratedAllocError::Unavailable) => {
                                assert_eq!(free, 0, "step {step}");
                            }
                            Err(error) => panic!("step {step}: {error:?}"),
                            Ok(mut frame) => {
                                assert!((14..=MAX_LEN).contains(&len), "step {step}");
                                assert_eq!(frame.bytes_mut().len(), len);
                                let id = frame.frame().index();
                                assert!(id >= RX_FRAMES, "step {step}");
                                lens[id as usize] = u32::try_from(len).expect("small");
                                arp_request(
                                    frame.bytes_mut(),
                                    u8::try_from(step % 251).expect("u8"),
                                );
                                let token = model.lease_generated(id).expect("model lease");
                                match action {
                                    0 | 1 => {
                                        let result = frame.commit();
                                        model.stage_tx(token).expect("model stage");
                                        match result {
                                            Ok(report) => {
                                                assert_eq!(report.submitted(), 1);
                                                mirror_tx(&kernel, &mut model, 1, &lens);
                                            }
                                            Err(refused) => handoffs.push(refused.into_handoff()),
                                        }
                                    }
                                    2 | 3 => {
                                        handoffs.push(frame.stage_tx());
                                        model.stage_tx(token).expect("model stage");
                                    }
                                    4 => {
                                        frame.cancel();
                                        model.recycle_lease(token).expect("model recycle");
                                    }
                                    _ => {
                                        drop(frame);
                                        model.recycle_lease(token).expect("model recycle");
                                    }
                                }
                            }
                        }
                    }
                }
                // Refill only.
                _ => {
                    let _ = engine.refill().expect("refill");
                    mirror_fill(&kernel, &mut model, &mut mirrored);
                }
            }
            assert_same(&engine, &model, step);
        }
        for handoff in handoffs.drain(..) {
            let token = model_token(&model, handoff.frame().index());
            cancel_all(&mut engine, [handoff]);
            model.cancel_pending_tx(token).expect("model cancel");
            model.recycle_lease(token).expect("model recycle");
        }
        while let Some(descriptor) = kernel.consume_tx() {
            consumed.push_back(descriptor.address);
        }
        while let Some(address) = consumed.pop_front() {
            assert!(kernel.produce_completion(address));
            model
                .kernel_consume_tx()
                .expect("model TX")
                .produce_completion()
                .expect("model completion");
        }
        let completions = kernel.completion_producer() - kernel.completion_consumer();
        let report = engine.drain(4).expect("drain");
        assert_eq!(report.outcome(), DrainOutcome::Drained);
        if completions > 0 {
            model
                .acquire_completion(completions as usize)
                .expect("model completion acquire")
                .release_consume()
                .expect("model completion consume");
        }
        assert_same(&engine, &model, usize::MAX);
        assert_eq!(report.generated_accounting().free, GENERATED);
        let counters = engine.generated_counters();
        assert_eq!(counters.generated_completed, counters.generated_committed);
        if !cfg!(miri) {
            assert!(counters.generated_committed > 20, "{counters:?}");
            assert!(counters.generated_cancelled > 0, "{counters:?}");
            assert!(counters.generated_abandoned > 0, "{counters:?}");
            assert!(counters.generated_unavailable > 0, "{counters:?}");
            assert!(counters.generated_rejected_total() > 0, "{counters:?}");
        }
    }
}

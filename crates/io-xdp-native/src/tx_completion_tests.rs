//! TX/Completion engine tests over the scripted heap kernel (M2 S4, X02).

// `drop(batch)` marks where a batch borrow ends; it is deliberate.
#![allow(clippy::drop_non_drop)]

use std::{
    collections::VecDeque,
    num::{NonZeroU128, NonZeroU32},
};

use ruster_io_xdp::{
    EndpointLocation, FakeEndpointId, FakeKernel, FrameLedger, FrameStateKind, RawDescriptor,
    UmemDomainId, UmemLayout,
};

use crate::{
    abi::{XdpDescriptor, XDP_RING_NEED_WAKEUP},
    native_unsafe::{
        heap_kernel::{allocation_count, ScriptedKernel},
        kick::KickRing,
    },
    CompletionInvalidReason, DrainOutcome, KickDeferral, KickError, KickOutcome, LedgerError,
    NativeRingError, NeedWakeup, RingEntries, RingName, RxFillAuditError, RxFillConfig,
    RxFillEngine, RxFillError, RxFillSetupError, RxInvalidReason, TxBlocked, TxHandoff,
    TxRejection, TxSubmitError, UmemConfig, XDP_PACKET_HEADROOM,
};

const FRAME_SIZE: u32 = 2_048;
const FRAMES: u32 = 16;
const RX_FRAMES: u32 = 12;
const RING: u32 = 8;
const HEADROOM: u64 = XDP_PACKET_HEADROOM as u64;
const UMEM_LEN: u64 = FRAMES as u64 * FRAME_SIZE as u64;

fn umem_config() -> UmemConfig {
    UmemConfig::new(FRAMES, FRAME_SIZE, 0, RX_FRAMES, FRAMES - RX_FRAMES, 0).expect("UMEM")
}

fn entries(ring: RingName, value: u32) -> RingEntries {
    RingEntries::new(ring, value).expect("ring entries")
}

fn kernel() -> ScriptedKernel {
    ScriptedKernel::new(
        entries(RingName::Fill, RING),
        entries(RingName::Rx, RING),
        umem_config(),
    )
}

fn domain(value: u128) -> UmemDomainId {
    UmemDomainId::new(NonZeroU128::new(value).expect("nonzero domain"))
}

fn engine_with(kernel: &ScriptedKernel, domain_value: u128) -> RxFillEngine<'_> {
    let datapath = kernel.take_datapath().expect("first take");
    RxFillEngine::new(
        datapath,
        domain(domain_value),
        RxFillConfig::new(NonZeroU32::new(RING).expect("nonzero")),
    )
    .expect("engine")
}

fn engine(kernel: &ScriptedKernel) -> RxFillEngine<'_> {
    engine_with(kernel, 0x5401)
}

fn frame_base(frame: u32) -> u64 {
    u64::from(frame) * u64::from(FRAME_SIZE)
}

fn frame_of(address: u64) -> u32 {
    u32::try_from(address / u64::from(FRAME_SIZE)).expect("frame")
}

fn state(engine: &RxFillEngine<'_>, frame: u32) -> FrameStateKind {
    engine.ledger().state(frame).expect("frame").kind()
}

fn snapshot(ledger: &FrameLedger) -> Vec<(FrameStateKind, Option<u64>)> {
    (0..u32::try_from(ledger.frame_count()).expect("u32 frames"))
        .map(|frame| {
            let view = ledger.state(frame).expect("frame");
            (
                view.kind(),
                view.token().map(|token| token.generation().get()),
            )
        })
        .collect()
}

/// The deep audit: ledger scan, every list, exact-once accounting.
fn audit(engine: &RxFillEngine<'_>) {
    engine.audit().expect("engine audit");
    let accounting = engine.frame_accounting();
    assert_eq!(accounting.total(), RX_FRAMES, "{accounting:?}");
    assert_eq!(accounting.free, engine.free_frames());
    assert_eq!(accounting.tx_in_flight, engine.tx_inflight());
    assert_eq!(accounting.tx_handoffs, engine.tx_handoffs_outstanding());
    assert!(engine.tx_inflight() <= engine.tx_inflight_limit());
}

/// Kernel receive of one frame with `len` bytes; returns the frame.
fn deliver(kernel: &ScriptedKernel, len: u32) -> u32 {
    let base = kernel.consume_fill().expect("a published Fill frame");
    let mut bytes = [0_u8; 64];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(offset).expect("small") ^ u8::try_from(frame_of(base)).expect("u8");
    }
    kernel.write_umem(base + HEADROOM, &bytes[..(len as usize).min(64)]);
    assert!(kernel.produce_rx(XdpDescriptor {
        address: base + HEADROOM,
        len,
        options: 0,
    }));
    frame_of(base)
}

/// Delivers `count` frames, lends them, swaps their MAC addresses in
/// place, and stages them for TX.
fn staged(kernel: &ScriptedKernel, engine: &mut RxFillEngine<'_>, count: usize) -> Vec<TxHandoff> {
    let mut handoffs = Vec::new();
    while handoffs.len() < count {
        let mut delivered = 0;
        while delivered < count - handoffs.len() && kernel.fill_pending() > 0 {
            deliver(kernel, 60);
            delivered += 1;
        }
        let mut batch = engine.poll(RING).expect("poll");
        while let Some(mut frame) = batch.next_frame() {
            swap_macs(frame.bytes_mut());
            handoffs.push(frame.stage_tx());
        }
    }
    handoffs
}

fn swap_macs(bytes: &mut [u8]) {
    let (destination, rest) = bytes.split_at_mut(6);
    destination.swap_with_slice(&mut rest[..6]);
}

/// Kernel transmit: consumes up to `count` TX descriptors and completes
/// them in order. Returns the descriptors.
fn transmit(kernel: &ScriptedKernel, count: usize) -> Vec<XdpDescriptor> {
    let mut sent = Vec::new();
    for _ in 0..count {
        let Some(descriptor) = kernel.consume_tx() else {
            break;
        };
        assert!(kernel.produce_completion(descriptor.address));
        sent.push(descriptor);
    }
    sent
}

fn cancel_all(engine: &mut RxFillEngine<'_>, handoffs: impl IntoIterator<Item = TxHandoff>) {
    for handoff in handoffs {
        engine
            .cancel_tx_handoff(handoff)
            .map_err(|(error, _)| error)
            .expect("cancel");
    }
}

#[test]
fn tx_forwards_the_same_frame_in_place_and_recycles_on_completion() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    audit(&engine);
    let frame = deliver(&kernel, 60);
    let (handoff, original) = {
        let mut batch = engine.poll(RING).expect("poll");
        let mut lent = batch.next_frame().expect("frame");
        assert_eq!(lent.frame().index(), frame);
        let original: Vec<u8> = lent.bytes().to_vec();
        swap_macs(lent.bytes_mut());
        (lent.stage_tx(), original)
    };
    let rx_descriptor = handoff.descriptor();
    assert_eq!(state(&engine, frame), FrameStateKind::PendingTx);
    audit(&engine);

    let report = engine.submit_tx(handoff).expect("submitted");
    assert_eq!(report.submitted(), 1);
    assert_eq!(report.blocked(), None);
    assert_eq!(report.need_wakeup(), Ok(NeedWakeup::NotRequired));
    assert_eq!(state(&engine, frame), FrameStateKind::TxOwnedByKernel);
    assert_eq!(engine.tx_inflight(), 1);
    assert_eq!(kernel.tx_pending(), 1);
    audit(&engine);

    // The kernel sees the RX geometry and the bytes rewritten in place.
    let descriptor = kernel.consume_tx().expect("TX descriptor");
    assert!(kernel.tx_holds(frame));
    assert_eq!(
        descriptor,
        XdpDescriptor {
            address: rx_descriptor.frame_base() + u64::from(rx_descriptor.data_offset()),
            len: rx_descriptor.len(),
            options: 0,
        }
    );
    assert_eq!(descriptor.address, frame_base(frame) + HEADROOM);
    let mut wire = vec![0_u8; 60];
    kernel.read_umem(descriptor.address, &mut wire);
    assert_eq!(&wire[..6], &original[6..12]);
    assert_eq!(&wire[6..12], &original[..6]);
    assert_eq!(&wire[12..], &original[12..]);
    // Consumed but not completed: still in flight.
    let reap = engine.reap_completions(RING).expect("reap");
    assert_eq!(reap.reaped(), 0);
    assert_eq!(state(&engine, frame), FrameStateKind::TxOwnedByKernel);
    audit(&engine);

    assert!(kernel.produce_completion(descriptor.address));
    let free = engine.free_frames();
    assert!(!kernel.tx_holds(frame));
    let batch = engine.poll(RING).expect("poll reaps first");
    assert_eq!(batch.completions().reaped(), 1);
    // Fill is full, so the completed frame waits in the free list.
    assert_eq!(batch.refill().published(), 0);
    drop(batch);
    assert_eq!(engine.free_frames(), free + 1);
    assert_eq!(state(&engine, frame), FrameStateKind::Free);
    let counters = engine.tx_counters();
    assert_eq!(counters.tx_submitted, 1);
    assert_eq!(counters.tx_completed, 1);
    assert_eq!(counters.tx_inflight, 0);
    assert_eq!(counters.tx_inflight_highwater, 1);
    assert_eq!(counters.tx_invalid_completion_total(), 0);
    audit(&engine);
}

#[test]
fn tx_full_and_partial_ring_block_recoverably() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let mut slots: Vec<Option<TxHandoff>> = staged(&kernel, &mut engine, 12)
        .into_iter()
        .map(Some)
        .collect();
    audit(&engine);

    // Twelve handoffs, eight TX slots: a partial submission.
    let report = engine.submit_tx_batch(&mut slots).expect("batch");
    assert_eq!(report.submitted(), RING);
    assert_eq!(report.blocked(), Some(TxBlocked::RingFull));
    assert!(slots[..8].iter().all(Option::is_none));
    assert!(slots[8..].iter().all(Option::is_some));
    assert_eq!(engine.tx_counters().tx_ring_full, 1);
    assert_eq!(engine.tx_handoffs_outstanding(), 4);
    audit(&engine);

    // A full ring refuses one handoff and hands it back unchanged.
    let handoff = slots[8].take().expect("left");
    let token = handoff.token();
    let rejected = engine.submit_tx(handoff).expect_err("ring full");
    assert_eq!(rejected.reason(), TxRejection::Blocked(TxBlocked::RingFull));
    let handoff = rejected.into_handoff();
    assert_eq!(handoff.token(), token);
    assert_eq!(
        state(&engine, token.frame().index()),
        FrameStateKind::PendingTx
    );
    slots[8] = Some(handoff);
    audit(&engine);

    // The kernel consumed three, completed none: TX ring room is back but
    // in-flight TX is at the limit (completion lag).
    for _ in 0..3 {
        kernel.consume_tx().expect("TX");
    }
    let report = engine.submit_tx_batch(&mut slots).expect("batch");
    assert_eq!(report.submitted(), 0);
    assert_eq!(report.blocked(), Some(TxBlocked::InflightLimit));
    assert_eq!(engine.tx_inflight(), RING);
    assert_eq!(engine.tx_counters().tx_inflight_limited, 1);
    audit(&engine);

    // Two completions make room for exactly two more.
    let mut done = 0;
    for _ in 0..2 {
        let descriptor = kernel.consume_tx().expect("TX");
        assert!(kernel.produce_completion(descriptor.address));
        done += 1;
    }
    assert_eq!(engine.reap_completions(RING).expect("reap").reaped(), done);
    let report = engine.submit_tx_batch(&mut slots).expect("batch");
    assert_eq!(report.submitted(), 2);
    assert_eq!(report.blocked(), Some(TxBlocked::InflightLimit));
    assert_eq!(engine.tx_inflight(), RING);
    assert_eq!(engine.tx_counters().tx_inflight_highwater, RING);
    audit(&engine);

    // Dropping the rest: cancel recycles them to the free list, and the
    // next refill republishes them to Fill.
    let rest: Vec<TxHandoff> = slots.iter_mut().filter_map(Option::take).collect();
    assert_eq!(rest.len(), 2);
    let free = engine.free_frames();
    cancel_all(&mut engine, rest);
    assert_eq!(engine.free_frames(), free + 2);
    assert_eq!(engine.tx_handoffs_outstanding(), 0);
    audit(&engine);
    let _ = engine.refill().expect("refill");
    audit(&engine);
}

#[test]
fn tx_inflight_is_capped_and_short_free_list_still_progresses() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    // Every RX-pool frame cycles through TX while the kernel lags.
    let mut handoffs: VecDeque<TxHandoff> = VecDeque::new();
    let mut lagging: VecDeque<u64> = VecDeque::new();
    for round in 0..200_u32 {
        // Kernel: receive whatever Fill holds.
        while kernel.fill_pending() > 0
            && kernel.rx_producer().wrapping_sub(kernel.rx_consumer()) < RING
        {
            deliver(&kernel, 60);
        }
        {
            let mut batch = engine.poll(RING).expect("poll");
            while let Some(frame) = batch.next_frame() {
                handoffs.push_back(frame.stage_tx());
            }
        }
        // Submit everything we hold; whatever is refused stays held.
        let mut slots: Vec<Option<TxHandoff>> = handoffs.drain(..).map(Some).collect();
        let _ = engine.submit_tx_batch(&mut slots).expect("batch");
        handoffs.extend(slots.into_iter().flatten());
        assert!(engine.tx_inflight() <= RING, "round {round}");
        audit(&engine);
        // Kernel: consume all TX, complete only some, with lag.
        while let Some(descriptor) = kernel.consume_tx() {
            lagging.push_back(descriptor.address);
        }
        for _ in 0..(round % 3) {
            if let Some(address) = lagging.pop_front() {
                assert!(kernel.produce_completion(address));
            }
        }
    }
    let counters = engine.tx_counters();
    assert!(counters.tx_inflight_limited > 0, "{counters:?}");
    assert_eq!(counters.tx_inflight_highwater, RING);
    // The free list ran dry (every frame was held by TX or the caller),
    // and the engine reported starvation instead of stalling.
    assert!(engine.counters().fill_starved > 0);

    // Recovery: the kernel completes everything; one poll reaps first and
    // refills from the completed frames in the same call.
    while let Some(address) = lagging.pop_front() {
        assert!(kernel.produce_completion(address));
    }
    let free_before = engine.free_frames();
    let batch = engine.poll(0).expect("poll");
    assert!(batch.completions().reaped() > 0);
    assert!(batch.refill().published() > 0 || free_before > 0);
    drop(batch);
    assert_eq!(engine.tx_inflight(), 0);
    let held: Vec<TxHandoff> = handoffs.drain(..).collect();
    cancel_all(&mut engine, held);
    let _ = engine.refill().expect("refill");
    audit(&engine);
}

#[test]
fn tx_completion_lag_and_reordering_are_tracked() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    assert_eq!(engine.completion_lag().oldest_age_polls(), None);
    let handoffs = staged(&kernel, &mut engine, 3);
    let polls_at_submit = engine.counters().polls;
    let mut slots: Vec<Option<TxHandoff>> = handoffs.into_iter().map(Some).collect();
    assert_eq!(
        engine
            .submit_tx_batch(&mut slots)
            .expect("batch")
            .submitted(),
        3
    );
    for _ in 0..4 {
        drop(engine.poll(0).expect("poll"));
    }
    let lag = engine.completion_lag();
    assert_eq!(lag.in_flight(), 3);
    assert_eq!(
        lag.oldest_age_polls(),
        Some(engine.counters().polls - polls_at_submit)
    );
    assert_eq!(lag.oldest_age_polls(), Some(4));

    let sent: Vec<XdpDescriptor> = (0..3).map(|_| kernel.consume_tx().expect("TX")).collect();
    // Out of submission order: second, third, first.
    for index in [1, 2, 0] {
        assert!(kernel.produce_completion(sent[index].address));
    }
    assert_eq!(engine.reap_completions(1).expect("reap").reaped(), 1);
    assert_eq!(engine.tx_counters().completion_backlogged, 1);
    assert_eq!(engine.completion_lag().in_flight(), 2);
    // The oldest (first) frame is still in flight.
    assert_eq!(engine.completion_lag().oldest_age_polls(), Some(4));
    audit(&engine);
    let report = engine.reap_completions(RING).expect("reap");
    assert_eq!(report.reaped(), 2);
    assert!(!report.backlogged());
    assert_eq!(engine.completion_lag().in_flight(), 0);
    assert_eq!(engine.completion_lag().oldest_age_polls(), None);
    // Second and third were completed while the first was older.
    assert_eq!(engine.tx_counters().tx_completions_reordered, 2);
    assert_eq!(engine.tx_counters().tx_completed, 3);
    audit(&engine);
}

#[test]
fn tx_invalid_completions_are_counted_and_fail_closed() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let handoffs = staged(&kernel, &mut engine, 3);
    let mut slots: Vec<Option<TxHandoff>> = handoffs.into_iter().map(Some).collect();
    let _ = engine.submit_tx_batch(&mut slots).expect("batch");
    let sent: Vec<XdpDescriptor> = (0..3).map(|_| kernel.consume_tx().expect("TX")).collect();
    audit(&engine);
    // A frame still published to Fill.
    let fill_frame = (0..RX_FRAMES)
        .find(|frame| state(&engine, *frame) == FrameStateKind::FillOwnedByKernel)
        .expect("a Fill frame");

    // Untouched refusals: outside UMEM, the generated pool, a Fill frame.
    let before = snapshot(engine.ledger());
    for address in [
        UMEM_LEN,
        u64::MAX,
        frame_base(RX_FRAMES) + HEADROOM,
        frame_base(fill_frame) + HEADROOM,
    ] {
        assert!(kernel.produce_completion(address));
    }
    let report = engine.reap_completions(RING).expect("reap");
    assert_eq!((report.reaped(), report.invalid()), (0, 4));
    assert_eq!(snapshot(engine.ledger()), before);
    let counters = engine.tx_counters();
    assert_eq!(
        counters.tx_invalid_completion(CompletionInvalidReason::AddressOutsideUmem),
        2
    );
    assert_eq!(
        counters.tx_invalid_completion(CompletionInvalidReason::NotInFlight),
        2
    );
    assert_eq!(engine.tx_inflight(), 3);
    audit(&engine);

    // A valid completion, then its duplicate: the duplicate frees nothing.
    assert!(kernel.produce_completion(sent[0].address));
    assert!(kernel.produce_completion(sent[0].address));
    let free = engine.free_frames();
    let report = engine.reap_completions(RING).expect("reap");
    assert_eq!((report.reaped(), report.invalid()), (1, 1));
    assert_eq!(engine.free_frames(), free + 1);
    assert_eq!(
        engine
            .tx_counters()
            .tx_invalid_completion(CompletionInvalidReason::NotInFlight),
        3
    );
    audit(&engine);

    // An in-flight frame completed at a different offset: quarantined.
    let mismatch_frame = frame_of(sent[1].address);
    let quarantined = engine.counters().frames_quarantined;
    assert!(kernel.produce_completion(frame_base(mismatch_frame)));
    let report = engine.reap_completions(RING).expect("reap");
    assert_eq!((report.reaped(), report.invalid()), (0, 1));
    assert_eq!(state(&engine, mismatch_frame), FrameStateKind::Quarantined);
    assert_eq!(engine.counters().frames_quarantined, quarantined + 1);
    assert_eq!(
        engine
            .tx_counters()
            .tx_invalid_completion(CompletionInvalidReason::AddressMismatch),
        1
    );
    assert_eq!(engine.frame_accounting().quarantined, 1);
    // A later exact completion for it is refused: it is no longer in flight.
    assert!(kernel.produce_completion(sent[1].address));
    assert!(kernel.produce_completion(sent[2].address));
    let report = engine.reap_completions(RING).expect("reap");
    assert_eq!((report.reaped(), report.invalid()), (1, 1));
    assert_eq!(state(&engine, mismatch_frame), FrameStateKind::Quarantined);
    assert_eq!(engine.tx_inflight(), 0);
    assert_eq!(engine.tx_counters().tx_invalid_completion_total(), 7);
    audit(&engine);
}

#[test]
fn tx_need_wakeup_is_observed_and_kicks_map_errno() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    assert_eq!(engine.tx_needs_wakeup(), Ok(NeedWakeup::NotRequired));
    kernel.set_tx_flags(XDP_RING_NEED_WAKEUP);
    assert_eq!(engine.tx_needs_wakeup(), Ok(NeedWakeup::Required));
    let handoff = staged(&kernel, &mut engine, 1).pop().expect("one");
    let report = engine.submit_tx(handoff).expect("submit");
    assert_eq!(report.need_wakeup(), Ok(NeedWakeup::Required));
    assert_eq!(engine.tx_counters().tx_need_wakeup, 1);
    kernel.set_tx_flags(XDP_RING_NEED_WAKEUP | 2);
    assert_eq!(
        engine.tx_needs_wakeup(),
        Err(NativeRingError::UnsupportedRingFlags(2))
    );
    let report = engine.submit_tx_batch(&mut []).expect("empty batch");
    assert_eq!(report.submitted(), 0);
    assert_eq!(engine.tx_counters().tx_flag_errors, 1);
    kernel.set_tx_flags(0);

    // Kicks reach the bundle's socket and map errno exactly.
    assert_eq!(engine.wake_tx(), Ok(KickOutcome::Woken));
    assert_eq!(engine.wake_fill(), Ok(KickOutcome::Woken));
    assert_eq!(kernel.kicks(KickRing::Tx), 1);
    assert_eq!(kernel.kicks(KickRing::Fill), 1);
    for (errno, expected) in [
        (
            Some(11),
            Ok(KickOutcome::Deferred(KickDeferral::WouldBlock)),
        ),
        (Some(16), Ok(KickOutcome::Deferred(KickDeferral::Busy))),
        (
            Some(105),
            Ok(KickOutcome::Deferred(KickDeferral::NoBuffers)),
        ),
        (Some(100), Err(KickError::NetworkDown)),
        (Some(6), Err(KickError::NotBound)),
        (Some(1), Err(KickError::Errno(1))),
        (None, Err(KickError::Rejected)),
    ] {
        kernel.fail_next_kick(errno);
        assert_eq!(engine.wake_tx(), expected, "{errno:?}");
    }
    kernel.fail_next_kick(Some(4));
    assert_eq!(
        engine.wake_fill(),
        Ok(KickOutcome::Deferred(KickDeferral::Interrupted))
    );
    let counters = engine.tx_counters();
    assert_eq!(counters.tx_kicks, 8);
    assert_eq!(counters.fill_kicks, 2);
    assert_eq!(counters.kicks_deferred, 4);
    assert_eq!(counters.kick_errors, 4);
    // A failed kick changes no frame: the descriptor stays published.
    assert_eq!(engine.tx_inflight(), 1);
    assert_eq!(kernel.tx_pending(), 1);
    audit(&engine);
}

#[test]
fn tx_drain_returns_every_frame_once_and_reports_kernel_held_frames() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let handoffs = staged(&kernel, &mut engine, 5);
    let mut slots: Vec<Option<TxHandoff>> = handoffs.into_iter().map(Some).collect();
    // Four in flight, one still held by the caller.
    let last = slots.pop().flatten().expect("fifth");
    assert_eq!(
        engine
            .submit_tx_batch(&mut slots)
            .expect("batch")
            .submitted(),
        4
    );
    // Validated RX frames that were never lent.
    deliver(&kernel, 60);
    deliver(&kernel, 60);
    drop(engine.poll(1).expect("poll"));
    drop(engine.poll(0).expect("poll"));
    assert_eq!(engine.pending_rx(), 1);
    // The kernel completes two, consumes a third, never sees the fourth.
    transmit(&kernel, 2);
    let held = kernel.consume_tx().expect("TX");
    audit(&engine);

    kernel.set_tx_flags(XDP_RING_NEED_WAKEUP);
    let report = engine.drain(3).expect("drain");
    assert_eq!(report.outcome(), DrainOutcome::TxInFlight { frames: 2 });
    assert_eq!(report.completed(), 2);
    assert_eq!(report.rounds(), 3);
    assert_eq!(report.rx_pending_released(), 1);
    // Each round kicked TX because the kernel asked.
    assert_eq!(kernel.kicks(KickRing::Tx), 3);
    let accounting = report.accounting();
    assert_eq!(accounting.tx_in_flight, 2);
    assert_eq!(accounting.tx_handoffs, 1);
    assert_eq!(accounting.rx_pending, 0);
    assert_eq!(accounting.total(), RX_FRAMES);
    assert!(engine.is_draining());
    audit(&engine);

    // No new TX, no new Fill publication.
    let rejected = engine.submit_tx(last).expect_err("draining");
    assert_eq!(rejected.reason(), TxRejection::Blocked(TxBlocked::Draining));
    cancel_all(&mut engine, [rejected.into_handoff()]);
    let report = engine.refill().expect("refill");
    assert_eq!(report.published(), 0);
    assert_eq!(engine.counters().fill_suppressed_draining, 1);
    audit(&engine);

    // The kernel finishes; the next drain returns the rest exactly once.
    assert!(kernel.produce_completion(held.address));
    let fourth = kernel.consume_tx().expect("TX");
    assert!(kernel.produce_completion(fourth.address));
    // A duplicate completion during drain frees nothing twice.
    assert!(kernel.produce_completion(fourth.address));
    kernel.set_tx_flags(0);
    let report = engine.drain(8).expect("drain");
    assert_eq!(report.outcome(), DrainOutcome::Drained);
    assert_eq!(report.completed(), 2);
    assert_eq!(report.rounds(), 1);
    let accounting = report.accounting();
    assert_eq!(accounting.tx_in_flight, 0);
    assert_eq!(accounting.tx_handoffs, 0);
    assert_eq!(accounting.free + accounting.fill_in_kernel, RX_FRAMES);
    // Fill entries plus the RX descriptor the engine has not read yet.
    assert_eq!(
        accounting.fill_in_kernel,
        kernel.fill_pending() + kernel.rx_producer().wrapping_sub(kernel.rx_consumer())
    );
    assert_eq!(engine.tx_counters().tx_completed, 4);
    assert_eq!(engine.tx_counters().drains, 2);
    audit(&engine);
    // Draining again is a no-op.
    let again = engine.drain(8).expect("drain");
    assert_eq!(again.outcome(), DrainOutcome::Drained);
    assert_eq!((again.rounds(), again.completed()), (0, 0));
    assert_eq!(again.accounting(), accounting);

    // RX still returns Fill frames after drain (the unread one and a new
    // one); they go to the free list and are not republished.
    deliver(&kernel, 60);
    drain_rx(&mut engine);
    let after = engine.frame_accounting();
    assert_eq!(after.fill_in_kernel, accounting.fill_in_kernel - 2);
    assert_eq!(after.fill_in_kernel, kernel.fill_pending());
    assert_eq!(after.free, accounting.free + 2);
    audit(&engine);
}

fn drain_rx(engine: &mut RxFillEngine<'_>) {
    let mut batch = engine.poll(RING).expect("poll");
    while let Some(frame) = batch.next_frame() {
        frame.recycle();
    }
}

#[test]
fn tx_foreign_handoffs_are_refused_and_returned_intact() {
    let first = kernel();
    let second = kernel();
    let mut mine = engine_with(&first, 0x5402);
    let mut other = engine_with(&second, 0x5403);
    let foreign = staged(&second, &mut other, 1).pop().expect("one");
    let own = staged(&first, &mut mine, 1).pop().expect("one");
    let before = snapshot(mine.ledger());
    let token = foreign.token();

    let rejected = mine.submit_tx(foreign).expect_err("foreign");
    assert_eq!(
        rejected.reason(),
        TxRejection::Invalid(LedgerError::ForeignTokenDomain)
    );
    let foreign = rejected.into_handoff();
    assert_eq!(foreign.token(), token);
    // In a batch, the foreign slot refuses the whole call, nothing moves.
    let mut slots = [Some(own), Some(foreign)];
    assert_eq!(
        mine.submit_tx_batch(&mut slots),
        Err(TxSubmitError::Handoff {
            index: 1,
            error: LedgerError::ForeignTokenDomain,
        })
    );
    assert!(slots.iter().all(Option::is_some));
    assert_eq!(first.tx_pending(), 0);
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
}

#[test]
fn tx_setup_rejects_small_completion_and_untracked_entries() {
    let small = ScriptedKernel::with_tx(
        entries(RingName::Fill, RING),
        entries(RingName::Rx, RING),
        entries(RingName::Tx, 16),
        entries(RingName::Completion, 8),
        umem_config(),
    );
    let config = RxFillConfig::new(NonZeroU32::new(RING).expect("nonzero"));
    let result = RxFillEngine::new(small.take_datapath().expect("take"), domain(1), config);
    assert_eq!(
        result.map(|_| ()).expect_err("small completion"),
        RxFillSetupError::CompletionSmallerThanTx {
            tx: 16,
            completion: 8,
        }
    );
    let stale_tx = kernel();
    stale_tx.set_tx_producer(2);
    let result = RxFillEngine::new(stale_tx.take_datapath().expect("take"), domain(1), config);
    assert_eq!(
        result.map(|_| ()).expect_err("stale TX"),
        RxFillSetupError::TxRingNotEmpty
    );
    let stale_completion = kernel();
    stale_completion.set_completion_producer(1);
    let result = RxFillEngine::new(
        stale_completion.take_datapath().expect("take"),
        domain(1),
        config,
    );
    assert_eq!(
        result.map(|_| ()).expect_err("stale Completion"),
        RxFillSetupError::CompletionRingNotEmpty
    );
    // A larger Completion ring is fine.
    let large = ScriptedKernel::with_tx(
        entries(RingName::Fill, RING),
        entries(RingName::Rx, RING),
        entries(RingName::Tx, 4),
        entries(RingName::Completion, 16),
        umem_config(),
    );
    let engine =
        RxFillEngine::new(large.take_datapath().expect("take"), domain(1), config).expect("engine");
    assert_eq!(engine.tx_inflight_limit(), 4);
}

#[test]
fn tx_corrupt_cursors_fail_closed_without_mutation() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let mut slots: Vec<Option<TxHandoff>> = staged(&kernel, &mut engine, 2)
        .into_iter()
        .map(Some)
        .collect();
    let before = snapshot(engine.ledger());
    kernel.set_tx_consumer(RING + 1);
    assert!(matches!(
        engine.submit_tx_batch(&mut slots),
        Err(TxSubmitError::Ring(NativeRingError::CorruptCursor { .. }))
    ));
    assert!(slots.iter().all(Option::is_some));
    assert_eq!(snapshot(engine.ledger()), before);
    kernel.set_tx_consumer(0);
    kernel.set_completion_producer(RING + 1);
    assert!(matches!(
        engine.reap_completions(RING),
        Err(RxFillError::Ring(NativeRingError::CorruptCursor { .. }))
    ));
    assert!(matches!(
        engine.poll(1),
        Err(RxFillError::Ring(NativeRingError::CorruptCursor { .. }))
    ));
    assert_eq!(snapshot(engine.ledger()), before);
    kernel.set_completion_producer(0);
    audit(&engine);
    cancel_all(&mut engine, slots.into_iter().flatten());
    audit(&engine);
}

#[test]
fn tx_audit_detects_inflight_divergence() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let handoff = staged(&kernel, &mut engine, 1).pop().expect("one");
    let _ = engine.submit_tx(handoff).expect("submit");
    audit(&engine);
    let lost = engine.drop_inflight_entry_for_test().expect("entry");
    assert!(matches!(
        engine.audit(),
        Err(RxFillAuditError::InflightCount {
            listed: 0,
            in_flight: 1
        })
    ));
    engine.push_inflight_entry_for_test(lost);
    audit(&engine);
    engine.push_inflight_entry_for_test(lost);
    assert!(matches!(
        engine.audit(),
        Err(RxFillAuditError::InflightEntry { .. })
    ));
}

#[test]
fn rx_chunk_overflow_is_quarantined_before_the_runt_check() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let base = kernel.consume_fill().expect("Fill");
    // Short (a runt) and crossing the chunk end: out-of-profile geometry.
    assert!(kernel.produce_rx(XdpDescriptor {
        address: base + u64::from(FRAME_SIZE) - 4,
        len: 8,
        options: 0,
    }));
    drop(engine.poll(RING).expect("poll"));
    assert_eq!(
        engine.counters().rx_invalid(RxInvalidReason::ExceedsFrame),
        1
    );
    assert_eq!(
        engine
            .counters()
            .rx_invalid(RxInvalidReason::ShorterThanEthernetHeader),
        0
    );
    assert_eq!(state(&engine, frame_of(base)), FrameStateKind::Quarantined);
    assert_eq!(engine.counters().rx_runts_recycled, 0);
    audit(&engine);
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "TxHandoff dropped without TX or cancel")]
fn tx_handoff_drop_without_an_engine_method_asserts_in_debug() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let handoff = staged(&kernel, &mut engine, 1).pop().expect("one");
    drop(handoff);
}

#[test]
fn tx_steady_state_does_not_allocate() {
    let kernel = kernel();
    let mut engine = engine(&kernel);
    let mut slots: [Option<TxHandoff>; RING as usize] = Default::default();
    let mut cycle = |engine: &mut RxFillEngine<'_>, round: u32| {
        for _ in 0..(round % RING + 1) {
            if kernel.fill_pending() == 0
                || kernel.rx_producer().wrapping_sub(kernel.rx_consumer()) == RING
            {
                break;
            }
            let base = kernel.consume_fill().expect("Fill");
            assert!(kernel.produce_rx(XdpDescriptor {
                address: base + HEADROOM,
                len: 60,
                options: 0,
            }));
        }
        {
            let mut batch = engine.poll(RING).expect("poll");
            let mut slot = 0;
            while let Some(mut frame) = batch.next_frame() {
                swap_macs(frame.bytes_mut());
                slots[slot] = Some(frame.stage_tx());
                slot += 1;
            }
        }
        let report = engine.submit_tx_batch(&mut slots).expect("batch");
        if report.need_wakeup() == Ok(NeedWakeup::Required) {
            let _ = engine.wake_tx();
        }
        for slot in &mut slots {
            if let Some(handoff) = slot.take() {
                engine
                    .cancel_tx_handoff(handoff)
                    .map_err(|(error, _)| error)
                    .expect("cancel");
            }
        }
        // Kernel: transmit and complete with one poll of lag.
        if round.is_multiple_of(2) {
            while let Some(descriptor) = kernel.consume_tx() {
                assert!(kernel.produce_completion(descriptor.address));
            }
        }
        let _ = engine.completion_lag();
        let _ = engine.frame_accounting();
    };
    for round in 0..4 {
        cycle(&mut engine, round);
    }
    kernel.set_tx_flags(XDP_RING_NEED_WAKEUP);
    let before = allocation_count();
    for round in 0..256 {
        cycle(&mut engine, round);
    }
    while let Some(descriptor) = kernel.consume_tx() {
        assert!(kernel.produce_completion(descriptor.address));
    }
    let report = engine.drain(4).expect("drain");
    assert_eq!(allocation_count(), before, "TX hot path allocated");
    assert_eq!(report.outcome(), DrainOutcome::Drained);
    assert!(engine.tx_counters().tx_submitted > 256);
    assert!(engine.tx_counters().tx_kicks > 0);
    audit(&engine);
}

// Differential against the io-xdp FakeKernel TX lifecycle.

/// Deterministic xorshift for the differential schedule.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

type Model = FakeKernel<{ RING as usize }, { FRAMES as usize }>;

fn model() -> Model {
    let layout = UmemLayout::new(domain(0x5404), FRAMES, FRAME_SIZE, XDP_PACKET_HEADROOM)
        .expect("model layout");
    FakeKernel::new(
        FakeEndpointId::new(NonZeroU128::new(0x5405).expect("nonzero")),
        EndpointLocation::new(1, 0),
        FrameLedger::new(layout).expect("model ledger"),
    )
    .expect("model")
}

fn model_token(model: &Model, frame: u32) -> ruster_io_xdp::FrameToken {
    model
        .ledger()
        .state(frame)
        .expect("frame")
        .token()
        .expect("token")
}

fn mirror_fill(kernel: &ScriptedKernel, model: &mut Model, mirrored: &mut u32) {
    while *mirrored != kernel.fill_producer() {
        let frame = frame_of(kernel.fill_entry(*mirrored));
        model
            .reserve_fill(frame)
            .expect("model reserve")
            .publish()
            .expect("model publish");
        *mirrored = mirrored.wrapping_add(1);
    }
}

/// Per-frame state and generation, projected onto what the native engine
/// can observe: the model records `RxAvailable` when its kernel produces
/// RX and `CompletionAvailable` when it produces a completion; the native
/// engine sees neither until it reads the ring, so both still count as
/// held by the kernel side (`FillOwnedByKernel`, `TxOwnedByKernel`).
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
    assert_eq!(engine.frame_accounting().total(), RX_FRAMES);
}

#[test]
fn tx_differential_matches_fake_kernel_tx_lifecycle() {
    for seed in [
        0x5eed_0001_u64,
        0xfeed_face_cafe_beef,
        0x0bad_c0de_1234_5678,
    ] {
        let kernel = kernel();
        let mut engine = engine(&kernel);
        let mut model = model();
        let mut mirrored = 0_u32;
        let mut rng = Rng(seed);
        let mut handoffs: Vec<TxHandoff> = Vec::new();
        // Consumed by the scripted kernel, not yet completed (lag).
        let mut consumed: VecDeque<u64> = VecDeque::new();
        let mut lens = [0_u32; FRAMES as usize];
        mirror_fill(&kernel, &mut model, &mut mirrored);
        assert_same(&engine, &model, 0);
        let steps = if cfg!(miri) { 80 } else { 800 };
        for step in 1..=steps {
            match rng.below(6) {
                // Kernel receive.
                0 => {
                    for _ in 0..=rng.below(u64::from(RING)) {
                        let room = RING - kernel.rx_producer().wrapping_sub(kernel.rx_consumer());
                        if kernel.fill_pending() == 0 || room == 0 {
                            break;
                        }
                        let base = kernel.consume_fill().expect("Fill");
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
                    // Apply the per-frame decisions to the model from the
                    // engine's ledger, which already moved.
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
                // Engine submit of a random prefix of the held handoffs.
                2 => {
                    let count = rng.below(handoffs.len() as u64 + 1) as usize;
                    let mut slots: Vec<Option<TxHandoff>> =
                        handoffs.drain(..count).map(Some).collect();
                    let report = engine.submit_tx_batch(&mut slots).expect("batch");
                    let submitted = slots.iter().filter(|slot| slot.is_none()).count();
                    // Refused handoffs go back, unchanged, in order.
                    handoffs.splice(0..0, slots.into_iter().flatten());
                    let submitted = u32::try_from(submitted).expect("small");
                    assert_eq!(report.submitted(), submitted, "step {step}");
                    // Mirror in submission order: the scripted TX ring.
                    mirror_tx(&kernel, &mut model, submitted, &lens);
                    assert!(engine.tx_inflight() <= RING, "step {step}");
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
                // Cancel a random handoff.
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
                // Refill only.
                _ => {
                    let _ = engine.refill().expect("refill");
                    mirror_fill(&kernel, &mut model, &mut mirrored);
                }
            }
            assert_same(&engine, &model, step);
        }
        // Shutdown: cancel what the caller holds, finish the kernel, drain.
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
        let counters = engine.tx_counters();
        assert_eq!(counters.tx_completed, counters.tx_submitted);
        assert_eq!(counters.tx_invalid_completion_total(), 0);
        // The full schedule exercises back-pressure and cancels; the short
        // Miri schedule checks the same invariants on fewer steps.
        if !cfg!(miri) {
            assert!(counters.tx_submitted > 50, "{counters:?}");
            assert!(counters.tx_ring_full + counters.tx_inflight_limited > 0);
            assert!(engine.counters().tx_handoffs_cancelled > 0);
        }
    }
}

/// Mirrors the last `submitted` TX ring entries into the model, in ring
/// order.
fn mirror_tx(kernel: &ScriptedKernel, model: &mut Model, submitted: u32, lens: &[u32]) {
    let producer = kernel.tx_producer();
    for logical in producer.wrapping_sub(submitted)..producer {
        let descriptor = kernel.tx_entry(logical);
        let frame = frame_of(descriptor.address);
        let token = model_token(model, frame);
        let packet = model
            .layout()
            .validate_descriptor(RawDescriptor {
                addr: descriptor.address,
                len: lens[frame as usize],
                options: 0,
            })
            .expect("model descriptor");
        model
            .reserve_tx(token)
            .expect("model reserve TX")
            .publish(packet)
            .expect("model publish TX");
    }
}

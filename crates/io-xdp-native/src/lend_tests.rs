//! A frame of one engine sent out through another socket of the same UMEM,
//! over two scripted heap kernels.

use ruster_io_xdp::{FrameStateKind, LedgerError};

use crate::{
    abi::XdpDescriptor,
    native_unsafe::heap_kernel::ScriptedKernel,
    tx_completion_tests::{
        cancel_all, engine_with, frame_base, kernel, staged, state, FRAMES, FRAME_SIZE, HEADROOM,
        RING, RX_FRAMES,
    },
    CompletionInvalidReason, DrainOutcome, RxFillEngine, TxBlocked, TxRejection,
};

/// Where the second socket's part starts.
const BASE: u64 = FRAMES as u64 * FRAME_SIZE as u64;

/// Two sockets of one UMEM: the first registered it, the second joined.
fn pair() -> (ScriptedKernel, ScriptedKernel) {
    let first = kernel();
    let second = kernel().sharing_umem_of(&first, BASE);
    (first, second)
}

fn audit(engine: &RxFillEngine<'_>) {
    engine.audit().expect("engine audit");
    assert_eq!(engine.frame_accounting().total(), RX_FRAMES);
}

/// Lends one staged frame of `home` to `out` and returns its TX descriptor
/// as `out`'s kernel consumed it.
fn lend(
    home: &mut RxFillEngine<'_>,
    home_kernel: &ScriptedKernel,
    out: &mut RxFillEngine<'_>,
    out_kernel: &ScriptedKernel,
) -> XdpDescriptor {
    let handoff = staged(home_kernel, home, 1).pop().expect("one handoff");
    let report = home.submit_tx_through(out, handoff).expect("lent");
    assert_eq!((report.submitted(), report.blocked()), (1, None));
    out_kernel.consume_tx().expect("TX descriptor")
}

#[test]
fn a_frame_goes_out_through_another_socket_and_returns_to_its_own_pool() {
    let (kernel_a, kernel_b) = pair();
    let mut a = engine_with(&kernel_a, 0x6001);
    let mut b = engine_with(&kernel_b, 0x6002);
    assert!(a.shares_umem_with(&b) && b.shares_umem_with(&a));

    // A's frame on B's TX ring: the address counts from the UMEM's start,
    // where A's part is.
    let handoff = staged(&kernel_a, &mut a, 1).pop().expect("one handoff");
    let frame = handoff.frame().index();
    let free = a.free_frames();
    let _ = a.submit_tx_through(&mut b, handoff).expect("lent");
    assert_eq!(state(&a, frame), FrameStateKind::TxOwnedByKernel);
    assert_eq!((a.tx_lent(), a.tx_inflight(), b.tx_inflight()), (1, 0, 1));
    assert_eq!(kernel_a.tx_pending(), 0);
    let descriptor = kernel_b.consume_tx().expect("TX descriptor");
    assert_eq!(descriptor.address, frame_base(frame) + HEADROOM);
    assert_eq!(descriptor.len, 60);
    audit(&a);
    audit(&b);

    // The frame is not A's to reuse until B hands the completion over.
    assert!(kernel_b.produce_completion(descriptor.address));
    assert_eq!(b.reap_completions(RING).expect("reap").reaped(), 1);
    assert_eq!((b.tx_inflight(), a.tx_lent()), (0, 1));
    assert_eq!(state(&a, frame), FrameStateKind::TxOwnedByKernel);
    let completion = b.take_lent_completion().expect("one completion");
    assert!(b.take_lent_completion().is_none());
    // B is not its home.
    let completion = b.complete_lent(completion).expect_err("A's frame");
    a.complete_lent(completion).expect("home");
    assert_eq!(state(&a, frame), FrameStateKind::Free);
    assert_eq!((a.tx_lent(), a.free_frames()), (0, free + 1));
    let counters = a.tx_counters();
    assert_eq!((counters.tx_lent, counters.tx_lent_completed), (1, 1));
    assert_eq!(b.tx_counters().tx_completed, 1);
    audit(&a);
    audit(&b);

    // The other direction: B's frame carries B's base on A's TX ring.
    let descriptor = lend(&mut b, &kernel_b, &mut a, &kernel_a);
    assert!((BASE..2 * BASE).contains(&descriptor.address));
    assert!(kernel_a.produce_completion(descriptor.address));
    assert_eq!(a.reap_completions(RING).expect("reap").reaped(), 1);
    let completion = a.take_lent_completion().expect("one completion");
    b.complete_lent(completion).expect("home");
    assert_eq!(b.tx_lent(), 0);
    audit(&a);
    audit(&b);
}

#[test]
fn own_and_lent_frames_share_one_tx_ring_and_complete_in_any_order() {
    let (kernel_a, kernel_b) = pair();
    let mut a = engine_with(&kernel_a, 0x6003);
    let mut b = engine_with(&kernel_b, 0x6004);
    let lent_first = lend(&mut a, &kernel_a, &mut b, &kernel_b);
    let own = staged(&kernel_b, &mut b, 1).pop().expect("one handoff");
    let own_frame = own.frame().index();
    let _ = b.submit_tx(own).expect("own frame");
    let own_descriptor = kernel_b.consume_tx().expect("TX descriptor");
    let lent_second = lend(&mut a, &kernel_a, &mut b, &kernel_b);
    assert_eq!((b.tx_inflight(), a.tx_lent()), (3, 2));
    audit(&a);
    audit(&b);

    // Newest first.
    for address in [
        lent_second.address,
        own_descriptor.address,
        lent_first.address,
    ] {
        assert!(kernel_b.produce_completion(address));
    }
    let report = b.reap_completions(RING).expect("reap");
    assert_eq!((report.reaped(), report.invalid()), (3, 0));
    assert_eq!(state(&b, own_frame), FrameStateKind::Free);
    assert_eq!(b.tx_inflight(), 0);
    while let Some(completion) = b.take_lent_completion() {
        a.complete_lent(completion).expect("home");
    }
    assert_eq!(a.tx_lent(), 0);
    audit(&a);
    audit(&b);
}

#[test]
fn completions_that_match_no_lent_frame_are_refused_untouched() {
    let (kernel_a, kernel_b) = pair();
    let mut a = engine_with(&kernel_a, 0x6005);
    let mut b = engine_with(&kernel_b, 0x6006);
    let descriptor = lend(&mut a, &kernel_a, &mut b, &kernel_b);

    // On B: another address of A's part, then the right one twice.
    for address in [
        descriptor.address + 1,
        descriptor.address,
        descriptor.address,
    ] {
        assert!(kernel_b.produce_completion(address));
    }
    let report = b.reap_completions(RING).expect("reap");
    assert_eq!((report.reaped(), report.invalid()), (1, 2));
    assert_eq!(
        b.tx_counters()
            .tx_invalid_completion(CompletionInvalidReason::AddressOutsideUmem),
        2
    );

    // On A's own Completion ring the lent frame is not in flight.
    assert!(kernel_a.produce_completion(descriptor.address));
    let report = a.reap_completions(RING).expect("reap");
    assert_eq!((report.reaped(), report.invalid()), (0, 1));
    assert_eq!(
        a.tx_counters()
            .tx_invalid_completion(CompletionInvalidReason::NotInFlight),
        1
    );
    assert_eq!(a.tx_lent(), 1);
    a.complete_lent(b.take_lent_completion().expect("one completion"))
        .expect("home");
    audit(&a);
    audit(&b);
}

#[test]
fn lending_is_refused_unchanged_outside_its_bounds() {
    let (kernel_a, kernel_b) = pair();
    let mut a = engine_with(&kernel_a, 0x6007);
    let mut b = engine_with(&kernel_b, 0x6008);

    // Another UMEM.
    let kernel_c = kernel();
    let mut c = engine_with(&kernel_c, 0x6009);
    assert!(!a.shares_umem_with(&c));
    let handoff = staged(&kernel_a, &mut a, 1).pop().expect("one handoff");
    let refused = a
        .submit_tx_through(&mut c, handoff)
        .expect_err("another UMEM");
    assert_eq!(
        refused.reason(),
        TxRejection::Invalid(LedgerError::ForeignDescriptorDomain)
    );
    cancel_all(&mut a, [refused.into_handoff()]);

    // A handoff of another engine, and a generated frame.
    let handoff = staged(&kernel_b, &mut b, 1).pop().expect("one handoff");
    let refused = a
        .submit_tx_through(&mut b, handoff)
        .expect_err("B's handoff");
    assert_eq!(
        refused.reason(),
        TxRejection::Invalid(LedgerError::ForeignTokenDomain)
    );
    cancel_all(&mut b, [refused.into_handoff()]);
    let handoff = a.allocate_generated(60).expect("generated").stage_tx();
    let refused = a.submit_tx_through(&mut b, handoff).expect_err("generated");
    assert!(matches!(refused.reason(), TxRejection::Invalid(_)));
    cancel_all(&mut a, [refused.into_handoff()]);
    assert_eq!((a.tx_lent(), b.tx_inflight(), c.tx_inflight()), (0, 0, 0));

    // The RX pool has 12 frames and Fill holds 8: at most 4 are lent.
    assert_eq!(a.tx_lent_limit(), RX_FRAMES - RING);
    for _ in 0..a.tx_lent_limit() {
        let _ = lend(&mut a, &kernel_a, &mut b, &kernel_b);
    }
    let handoff = staged(&kernel_a, &mut a, 1).pop().expect("one handoff");
    let refused = a.submit_tx_through(&mut b, handoff).expect_err("limit");
    assert_eq!(
        refused.reason(),
        TxRejection::Blocked(TxBlocked::InflightLimit)
    );
    assert_eq!(a.tx_counters().tx_lent_limited, 1);
    // The same frame still goes out through its own socket.
    let _ = a.submit_tx(refused.into_handoff()).expect("own TX ring");
    audit(&a);
    audit(&b);
}

#[test]
fn a_full_tx_ring_refuses_a_lent_frame() {
    let (kernel_a, kernel_b) = pair();
    let mut a = engine_with(&kernel_a, 0x600a);
    let mut b = engine_with(&kernel_b, 0x600b);
    // B's own frames fill its TX ring; the kernel consumed none.
    let mut slots: Vec<_> = staged(&kernel_b, &mut b, RING as usize)
        .into_iter()
        .map(Some)
        .collect();
    let _ = b.submit_tx_batch(&mut slots).expect("batch");
    let handoff = staged(&kernel_a, &mut a, 1).pop().expect("one handoff");
    let refused = a.submit_tx_through(&mut b, handoff).expect_err("ring full");
    assert_eq!(refused.reason(), TxRejection::Blocked(TxBlocked::RingFull));
    // Consumed but not completed: the in-flight bound.
    while kernel_b.consume_tx().is_some() {}
    let refused = a
        .submit_tx_through(&mut b, refused.into_handoff())
        .expect_err("in-flight bound");
    assert_eq!(
        refused.reason(),
        TxRejection::Blocked(TxBlocked::InflightLimit)
    );
    cancel_all(&mut a, [refused.into_handoff()]);
    audit(&a);
    audit(&b);
}

#[test]
fn a_drain_reaps_lent_frames_and_they_still_return_home() {
    let (kernel_a, kernel_b) = pair();
    let mut a = engine_with(&kernel_a, 0x600c);
    let mut b = engine_with(&kernel_b, 0x600d);
    let descriptor = lend(&mut a, &kernel_a, &mut b, &kernel_b);

    let report = b.drain(1).expect("drain");
    assert_eq!(report.outcome(), DrainOutcome::TxInFlight { frames: 1 });
    // Nothing new goes out through a draining socket, in either role.
    let handoff = staged(&kernel_a, &mut a, 1).pop().expect("one handoff");
    let refused = a.submit_tx_through(&mut b, handoff).expect_err("draining");
    assert_eq!(refused.reason(), TxRejection::Blocked(TxBlocked::Draining));
    cancel_all(&mut a, [refused.into_handoff()]);

    assert!(kernel_b.produce_completion(descriptor.address));
    let report = b.drain(1).expect("drain");
    assert_eq!(
        (report.outcome(), report.completed()),
        (DrainOutcome::Drained, 1)
    );
    // A is not drained while its frame is on the way back.
    assert_eq!(
        a.drain(1).expect("drain").outcome(),
        DrainOutcome::TxInFlight { frames: 1 }
    );
    a.complete_lent(b.take_lent_completion().expect("one completion"))
        .expect("home");
    assert_eq!(a.drain(1).expect("drain").outcome(), DrainOutcome::Drained);
    audit(&a);
    audit(&b);
}

//! RX/Fill engine tests over a scripted heap kernel (M2 S3, X01).

// `drop(batch)` marks where a batch borrow ends; it is deliberate.
#![allow(clippy::drop_non_drop)]

use std::num::{NonZeroU128, NonZeroU32};

use ruster_io_xdp::{
    EndpointLocation, FakeEndpointId, FakeKernel, FrameLedger, FrameStateKind, LedgerError,
    RawDescriptor, UmemDomainId, UmemLayout,
};

use crate::{
    abi::{XdpDescriptor, XDP_PKT_CONTD, XDP_RING_NEED_WAKEUP},
    native_unsafe::heap_kernel::{allocation_count, ScriptedKernel, HEAP_RING_OFFSETS},
    FillProducer, NativeRingError, NeedWakeup, RingEntries, RingName, RxConsumer, RxFillAuditError,
    RxFillConfig, RxFillEngine, RxFillError, RxFillSetupError, RxInvalidReason, TxHandoff,
    UmemConfig, UmemRegion, UmemRegionError, ETHERNET_HEADER_LEN, XDP_PACKET_HEADROOM,
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

fn entries(ring: RingName) -> RingEntries {
    RingEntries::new(ring, RING).expect("ring entries")
}

fn kernel() -> ScriptedKernel {
    ScriptedKernel::new(
        entries(RingName::Fill),
        entries(RingName::Rx),
        umem_config(),
    )
}

fn domain(value: u128) -> UmemDomainId {
    UmemDomainId::new(NonZeroU128::new(value).expect("nonzero domain"))
}

fn config(fill_batch: u32) -> RxFillConfig {
    RxFillConfig::new(NonZeroU32::new(fill_batch).expect("nonzero batch"))
}

fn engine(kernel: &ScriptedKernel, fill_batch: u32) -> RxFillEngine<'_> {
    let (fill, rx, umem) = kernel.views();
    RxFillEngine::new(fill, rx, umem, domain(0x5301), config(fill_batch)).expect("engine")
}

fn frame_base(frame: u32) -> u64 {
    u64::from(frame) * u64::from(FRAME_SIZE)
}

fn packet(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|offset| seed.wrapping_add(offset as u8))
        .collect()
}

/// Kernel side of one receive: consume a Fill frame, write the packet at
/// the kernel headroom, publish the RX descriptor. Returns the frame base.
fn deliver(kernel: &ScriptedKernel, bytes: &[u8]) -> u64 {
    let base = kernel.consume_fill().expect("a published Fill frame");
    kernel.write_umem(base + HEADROOM, bytes);
    assert!(kernel.produce_rx(XdpDescriptor {
        address: base + HEADROOM,
        len: u32::try_from(bytes.len()).expect("test length"),
        options: 0,
    }));
    base
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

fn audit(engine: &RxFillEngine<'_>) {
    engine.audit().expect("engine audit");
}

#[test]
fn rx_fill_engine_primes_validates_lends_and_recycles() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    // Start: one bounded refill publishes the first Fill-capacity frames.
    assert_eq!(kernel.fill_pending(), RING);
    assert_eq!(engine.counters().fill_published, u64::from(RING));
    assert_eq!(engine.free_frames(), RX_FRAMES - RING);
    assert_eq!(
        engine
            .ledger()
            .counts()
            .get(FrameStateKind::FillOwnedByKernel),
        RING as usize
    );
    for logical in 0..RING {
        assert_eq!(
            kernel.fill_entry(logical),
            frame_base(logical),
            "chunk base"
        );
    }
    // The generated pool is never published.
    for frame in RX_FRAMES..FRAMES {
        assert_eq!(state(&engine, frame), FrameStateKind::Free);
    }
    audit(&engine);

    let first = packet(1, 60);
    let second = packet(2, 1_514);
    let base_first = deliver(&kernel, &first);
    let base_second = deliver(&kernel, &second);
    {
        let mut batch = engine.poll(RING).expect("poll");
        assert_eq!(batch.remaining(), 2);
        // Kernel consumed two Fill entries; refill topped Fill up again.
        assert_eq!(batch.refill().published(), 2);
        let mut frame = batch.next_frame().expect("first frame");
        assert_eq!(frame.frame().index(), 0);
        assert_eq!(frame.len(), 60);
        assert!(!frame.is_empty());
        assert_eq!(frame.bytes(), first.as_slice());
        frame.bytes_mut()[0] = 0xee;
        frame.recycle();
        let frame = batch.next_frame().expect("second frame");
        assert_eq!(frame.bytes(), second.as_slice());
        assert_eq!(frame.descriptor().data_offset(), XDP_PACKET_HEADROOM);
        frame.recycle();
        assert!(batch.next_frame().is_none());
    }
    // The in-place rewrite reached UMEM.
    let mut byte = [0_u8; 1];
    kernel.read_umem(base_first + HEADROOM, &mut byte);
    assert_eq!(byte, [0xee]);
    assert_eq!(state(&engine, 0), FrameStateKind::Free);
    assert_eq!(state(&engine, 1), FrameStateKind::Free);
    let counters = engine.counters();
    assert_eq!(
        (
            counters.rx_packets,
            counters.rx_leased,
            counters.rx_recycled
        ),
        (2, 2, 2)
    );
    assert_eq!(counters.rx_invalid_total(), 0);
    audit(&engine);

    // Recycled frames are republished, behind the frames freed earlier.
    let report = engine.refill().expect("refill");
    assert_eq!(report.published(), 0, "Fill is already full");
    assert_eq!(engine.counters().fill_ring_full, 1);
    let next = deliver(&kernel, &packet(3, 64));
    assert_eq!(next, frame_base(2));
    let _ = base_second;
    let mut batch = engine.poll(RING).expect("poll");
    let frame = batch.next_frame().expect("frame");
    assert_eq!(frame.frame().index(), 2);
    drop(frame);
    drop(batch);
    assert_eq!(engine.counters().rx_abandoned, 1);
    assert_eq!(state(&engine, 2), FrameStateKind::Free);
    audit(&engine);
}

#[test]
fn rx_fill_rejects_every_invalid_descriptor_kind() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    // Frames 0..8 are kernel-owned. Consume them so the script owns their
    // addresses, as the real kernel would after taking them from Fill.
    let bases: Vec<u64> = (0..RING)
        .map(|_| kernel.consume_fill().expect("Fill"))
        .collect();
    // Publish the rest of the RX pool now, so the per-case polls below find
    // an empty free list and change nothing but the case's own frame.
    assert_eq!(
        engine.refill().expect("refill").published(),
        RX_FRAMES - RING
    );
    let valid = |base: u64| XdpDescriptor {
        address: base + HEADROOM,
        len: 64,
        options: 0,
    };
    // (descriptor, reason, quarantined frame)
    let cases = [
        (
            XdpDescriptor {
                address: UMEM_LEN,
                ..valid(0)
            },
            RxInvalidReason::AddressOutsideUmem,
            None,
        ),
        (
            XdpDescriptor {
                address: u64::MAX,
                ..valid(0)
            },
            RxInvalidReason::AddressOutsideUmem,
            None,
        ),
        (
            XdpDescriptor {
                options: XDP_PKT_CONTD,
                ..valid(bases[0])
            },
            RxInvalidReason::UnsupportedOptions,
            Some(0),
        ),
        // A generated-pool frame (never published) and the frame that the
        // previous case quarantined: nothing is mutated.
        (
            valid(frame_base(RX_FRAMES)),
            RxInvalidReason::NotKernelOwned,
            None,
        ),
        (valid(bases[0]), RxInvalidReason::NotKernelOwned, None),
        (
            XdpDescriptor {
                options: 1 << 31,
                ..valid(bases[1])
            },
            RxInvalidReason::UnsupportedOptions,
            Some(1),
        ),
        (
            XdpDescriptor {
                address: bases[2] + HEADROOM - 1,
                ..valid(bases[2])
            },
            RxInvalidReason::DataBeforeHeadroom,
            Some(2),
        ),
        (
            XdpDescriptor {
                address: bases[3],
                ..valid(bases[3])
            },
            RxInvalidReason::DataBeforeHeadroom,
            Some(3),
        ),
        (
            XdpDescriptor {
                len: ETHERNET_HEADER_LEN - 1,
                ..valid(bases[4])
            },
            RxInvalidReason::ShorterThanEthernetHeader,
            Some(4),
        ),
        (
            XdpDescriptor {
                len: 0,
                ..valid(bases[5])
            },
            RxInvalidReason::ShorterThanEthernetHeader,
            Some(5),
        ),
        (
            XdpDescriptor {
                len: FRAME_SIZE - XDP_PACKET_HEADROOM + 1,
                ..valid(bases[6])
            },
            RxInvalidReason::ExceedsFrame,
            Some(6),
        ),
        (
            XdpDescriptor {
                len: u32::MAX,
                ..valid(bases[7])
            },
            RxInvalidReason::ExceedsFrame,
            Some(7),
        ),
    ];
    for (descriptor, reason, quarantined) in cases {
        let before = snapshot(engine.ledger());
        assert!(kernel.produce_rx(descriptor));
        let counted = engine.counters().rx_invalid(reason);
        {
            let mut batch = engine.poll(1).expect("poll");
            assert_eq!(batch.remaining(), 0, "{reason:?} must never be lent");
            assert!(batch.next_frame().is_none());
        }
        assert_eq!(
            engine.counters().rx_invalid(reason),
            counted + 1,
            "{reason:?}"
        );
        let after = snapshot(engine.ledger());
        for (frame, (old, new)) in before.iter().zip(&after).enumerate() {
            if Some(frame as u32) == quarantined {
                assert_eq!(old.0, FrameStateKind::FillOwnedByKernel);
                assert_eq!(new.0, FrameStateKind::Quarantined, "{reason:?}");
                assert_eq!(old.1, new.1, "quarantine keeps the generation");
            } else {
                assert_eq!(old, new, "{reason:?} mutated frame {frame}");
            }
        }
        audit(&engine);
    }
    let counters = engine.counters();
    assert_eq!(counters.rx_packets, 0);
    assert_eq!(counters.rx_leased, 0);
    assert_eq!(counters.rx_invalid_total(), 12);
    assert_eq!(counters.frames_quarantined, 8);
    for reason in RxInvalidReason::ALL {
        assert_eq!(RxInvalidReason::ALL[reason.index()], reason);
        assert!(counters.rx_invalid(reason) >= 2, "{}", reason.code());
    }
    // Quarantined frames never return: only the four never-published
    // RX-pool frames remain usable and are now in Fill.
    assert_eq!(
        engine.ledger().counts().get(FrameStateKind::Quarantined),
        RING as usize
    );
    assert_eq!(kernel.fill_pending(), RX_FRAMES - RING);
}

#[test]
fn rx_fill_accepts_exact_descriptor_boundaries() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    let shortest = kernel.consume_fill().expect("Fill");
    let longest = kernel.consume_fill().expect("Fill");
    assert!(kernel.produce_rx(XdpDescriptor {
        address: shortest + HEADROOM,
        len: ETHERNET_HEADER_LEN,
        options: 0,
    }));
    // Headroom may be exceeded (a driver may place data later); the end
    // may touch the chunk end exactly.
    assert!(kernel.produce_rx(XdpDescriptor {
        address: longest + HEADROOM + 8,
        len: FRAME_SIZE - XDP_PACKET_HEADROOM - 8,
        options: 0,
    }));
    let mut batch = engine.poll(RING).expect("poll");
    let frame = batch.next_frame().expect("14-byte frame");
    assert_eq!(frame.len(), ETHERNET_HEADER_LEN);
    frame.recycle();
    let frame = batch.next_frame().expect("frame ending at the chunk end");
    assert_eq!(
        frame.bytes().len(),
        (FRAME_SIZE - XDP_PACKET_HEADROOM - 8) as usize
    );
    frame.recycle();
    drop(batch);
    assert_eq!(engine.counters().rx_invalid_total(), 0);
    audit(&engine);
}

#[test]
fn rx_fill_duplicate_descriptor_is_rejected_without_mutation() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    let base = deliver(&kernel, &packet(9, 64));
    // The same address again in the same poll.
    assert!(kernel.produce_rx(XdpDescriptor {
        address: base + HEADROOM,
        len: 64,
        options: 0,
    }));
    let handoff: TxHandoff;
    {
        let mut batch = engine.poll(RING).expect("poll");
        assert_eq!(batch.remaining(), 1, "only the first copy is valid");
        let frame = batch.next_frame().expect("frame");
        handoff = frame.stage_tx();
        assert!(batch.next_frame().is_none());
    }
    assert_eq!(
        engine
            .counters()
            .rx_invalid(RxInvalidReason::NotKernelOwned),
        1
    );
    assert_eq!(state(&engine, 0), FrameStateKind::PendingTx);
    audit(&engine);

    // Again while the frame is handed to TX, and while a second copy is
    // pending (validated, not yet lent).
    let pending = deliver(&kernel, &packet(10, 64));
    for address in [base, pending] {
        assert!(kernel.produce_rx(XdpDescriptor {
            address: address + HEADROOM,
            len: 64,
            options: 0,
        }));
    }
    // A budget of four reads all three descriptors but lends none: drop
    // the batch at once so the valid one stays pending.
    let before = snapshot(engine.ledger());
    drop(engine.poll(4).expect("poll"));
    let after = snapshot(engine.ledger());
    assert_eq!(
        engine
            .counters()
            .rx_invalid(RxInvalidReason::NotKernelOwned),
        3
    );
    assert_eq!(engine.pending_rx(), 1);
    assert_eq!(after[0], before[0], "handed-off frame untouched");
    assert_eq!(after[1].0, FrameStateKind::RxAvailable);
    audit(&engine);

    engine.cancel_tx_handoff(handoff).expect("cancel handoff");
    assert_eq!(state(&engine, 0), FrameStateKind::Free);
    audit(&engine);
}

#[test]
fn rx_fill_frame_cannot_be_recycled_twice_or_while_not_lent() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    deliver(&kernel, &packet(4, 64));
    deliver(&kernel, &packet(5, 64));
    let handoff = {
        let mut batch = engine.poll(1).expect("poll");
        batch.next_frame().expect("frame").stage_tx()
    };
    // A duplicate completion of the same cycle is refused by the ledger
    // and changes nothing.
    let duplicate = handoff.forged_copy_for_test();
    let token = handoff.token();
    engine.cancel_tx_handoff(handoff).expect("first cancel");
    let before = snapshot(engine.ledger());
    let free = engine.free_frames();
    assert!(matches!(
        engine.cancel_tx_handoff(duplicate),
        Err(RxFillError::Ledger(LedgerError::WrongState {
            expected: FrameStateKind::PendingTx,
            actual: FrameStateKind::Free,
            ..
        }))
    ));
    assert_eq!(engine.raw_recycle_for_test(token).map_err(|_| ()), Err(()));
    assert_eq!(snapshot(engine.ledger()), before);
    assert_eq!(engine.free_frames(), free);
    audit(&engine);

    // A frame that is pending (validated, not lent) or kernel-owned cannot
    // be recycled by any token: only a lent RxFrame holds `Leased`.
    drop(engine.poll(0).expect("refill only"));
    let pending = engine
        .ledger()
        .state(1)
        .expect("frame")
        .token()
        .expect("token");
    assert_eq!(state(&engine, 1), FrameStateKind::FillOwnedByKernel);
    assert!(matches!(
        engine.raw_recycle_for_test(pending),
        Err(LedgerError::WrongState {
            actual: FrameStateKind::FillOwnedByKernel,
            ..
        })
    ));
    // Consuming frame 1's descriptor without lending it leaves it pending.
    drop(engine.poll(1).expect("poll"));
    let pending = engine.ledger().state(1).expect("frame");
    assert_eq!(pending.kind(), FrameStateKind::RxAvailable);
    assert!(matches!(
        engine.raw_recycle_for_test(pending.token().expect("token")),
        Err(LedgerError::WrongState {
            actual: FrameStateKind::RxAvailable,
            ..
        })
    ));
    audit(&engine);
}

#[test]
fn rx_fill_starvation_is_counted_without_stall_and_recovers() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    assert_eq!(engine.counters().fill_starved, 0);
    // The kernel takes every Fill frame and receives into all of them.
    let mut handoffs = Vec::new();
    for round in 0..2 {
        while kernel.fill_pending() > 0 {
            deliver(&kernel, &packet(round, 64));
        }
        let mut batch = engine.poll(RING).expect("poll");
        while let Some(frame) = batch.next_frame() {
            handoffs.push(frame.stage_tx());
        }
    }
    // All 12 RX-pool frames are now handed to TX: the free list is empty
    // while Fill is empty too.
    assert_eq!(handoffs.len(), RX_FRAMES as usize);
    assert_eq!(engine.free_frames(), 0);
    assert_eq!(kernel.fill_pending(), 0);
    let starved = engine.counters().fill_starved;
    assert!(starved >= 1, "the second round already found no free frame");
    for poll in 1..=3_u64 {
        let batch = engine.poll(RING).expect("a starved poll still completes");
        assert!(batch.refill().starved());
        assert_eq!(batch.refill().published(), 0);
        assert_eq!(batch.remaining(), 0);
        drop(batch);
        assert_eq!(engine.counters().fill_starved, starved + poll);
        audit(&engine);
    }
    // RX keeps working during starvation: a descriptor the kernel already
    // holds is still validated (here: refused, as nothing is kernel-owned).
    assert!(kernel.produce_rx(XdpDescriptor {
        address: frame_base(0) + HEADROOM,
        len: 64,
        options: 0,
    }));
    drop(engine.poll(RING).expect("poll"));
    assert_eq!(
        engine
            .counters()
            .rx_invalid(RxInvalidReason::NotKernelOwned),
        1
    );

    // Recovery: returning frames ends starvation on the next refill.
    let starved = engine.counters().fill_starved;
    for handoff in handoffs.drain(..3) {
        engine.cancel_tx_handoff(handoff).expect("cancel");
    }
    let batch = engine.poll(RING).expect("poll");
    assert!(!batch.refill().starved());
    assert_eq!(batch.refill().published(), 3);
    drop(batch);
    assert_eq!(engine.counters().fill_starved, starved);
    assert_eq!(kernel.fill_pending(), 3);
    for handoff in handoffs {
        engine.cancel_tx_handoff(handoff).expect("cancel");
    }
    drop(engine.poll(0).expect("refill"));
    assert_eq!(kernel.fill_pending(), RING);
    assert_eq!(engine.free_frames(), RX_FRAMES - RING);
    audit(&engine);
}

#[test]
fn rx_fill_partial_free_list_fills_partially_and_batch_bounds_refill() {
    let kernel = kernel();
    // A batch of 3 bounds the first refill and every later one.
    let mut engine = engine(&kernel, 3);
    assert_eq!(kernel.fill_pending(), 3);
    assert_eq!(engine.refill().expect("refill").published(), 3);
    assert_eq!(engine.refill().expect("refill").published(), 2, "Fill room");
    assert_eq!(kernel.fill_pending(), RING);
    assert_eq!(engine.counters().fill_published, u64::from(RING));
    assert_eq!(engine.free_frames(), RX_FRAMES - RING);
    // Fill full with free frames is a ring-full condition, not starvation.
    let _ = engine.refill().expect("refill");
    assert_eq!(engine.counters().fill_ring_full, 1);
    assert_eq!(engine.counters().fill_starved, 0);
    // The kernel frees six slots; only four free frames exist: partial
    // Fill, then starvation on the next refill.
    for _ in 0..6 {
        deliver(&kernel, &packet(7, 64));
    }
    assert_eq!(engine.refill().expect("refill").published(), 3);
    assert_eq!(engine.refill().expect("refill").published(), 1);
    let report = engine.refill().expect("refill");
    assert!(report.starved());
    assert_eq!(engine.counters().fill_starved, 1);
    audit(&engine);
}

#[test]
fn rx_fill_poll_budget_bounds_descriptor_work() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    for seed in 0..RING {
        deliver(&kernel, &packet(seed as u8, 64));
    }
    // Budget zero refills only and never observes RX.
    drop(engine.poll(0).expect("poll"));
    assert_eq!(kernel.rx_consumer(), 0);
    assert_eq!(engine.counters().rx_ring_empty, 0);

    // Budget three consumes exactly three descriptors.
    {
        let mut batch = engine.poll(3).expect("poll");
        assert_eq!(kernel.rx_consumer(), 3);
        assert_eq!(batch.remaining(), 3);
        batch.next_frame().expect("frame").recycle();
    }
    assert_eq!(engine.counters().rx_backlogged, 1);
    assert_eq!(engine.pending_rx(), 2, "unlent frames stay pending");
    audit(&engine);

    // The next poll lends the two pending frames first and consumes only
    // one more descriptor.
    {
        let mut batch = engine.poll(3).expect("poll");
        assert_eq!(kernel.rx_consumer(), 4);
        let mut lent = Vec::new();
        while let Some(frame) = batch.next_frame() {
            lent.push(frame.frame().index());
            frame.recycle();
        }
        assert_eq!(lent, [1, 2, 3], "FIFO order across polls");
    }
    // Invalid descriptors spend budget too.
    for _ in 0..3 {
        assert!(kernel.produce_rx(XdpDescriptor {
            address: UMEM_LEN,
            len: 64,
            options: 0,
        }));
    }
    {
        let mut batch = engine.poll(2).expect("poll");
        assert_eq!(kernel.rx_consumer(), 6);
        let mut lent = 0;
        while let Some(frame) = batch.next_frame() {
            lent += 1;
            frame.recycle();
        }
        assert_eq!(lent, 2);
    }
    {
        let mut batch = engine.poll(8).expect("poll");
        let mut lent = 0;
        while let Some(frame) = batch.next_frame() {
            lent += 1;
            frame.recycle();
        }
        assert_eq!(lent, 2);
    }
    assert_eq!(kernel.rx_consumer(), kernel.rx_producer());
    assert_eq!(
        engine
            .counters()
            .rx_invalid(RxInvalidReason::AddressOutsideUmem),
        3
    );
    drop(engine.poll(4).expect("poll"));
    assert_eq!(engine.counters().rx_ring_empty, 1);
    audit(&engine);
}

#[test]
fn rx_fill_need_wakeup_and_unknown_flags_are_counted_after_publication() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    assert_eq!(engine.counters().fill_need_wakeup, 0);
    kernel.set_fill_flags(XDP_RING_NEED_WAKEUP);
    deliver(&kernel, &packet(1, 64));
    let report = engine.refill().expect("refill");
    assert_eq!(report.published(), 1);
    assert_eq!(report.need_wakeup(), Some(Ok(NeedWakeup::Required)));
    assert_eq!(engine.counters().fill_need_wakeup, 1);

    kernel.set_fill_flags(XDP_RING_NEED_WAKEUP | 4);
    deliver(&kernel, &packet(2, 64));
    let report = engine.refill().expect("publication still succeeds");
    assert_eq!(report.published(), 1);
    assert_eq!(
        report.need_wakeup(),
        Some(Err(NativeRingError::UnsupportedRingFlags(4)))
    );
    assert_eq!(engine.counters().fill_flag_errors, 1);
    assert_eq!(kernel.fill_pending(), RING);
    audit(&engine);
}

#[test]
fn rx_fill_corrupt_kernel_cursors_fail_closed_without_mutation() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    deliver(&kernel, &packet(1, 64));
    // Poll refills before it reads RX; refill first so the snapshot covers
    // only the failing RX step.
    assert_eq!(engine.refill().expect("refill").published(), 1);
    let before = snapshot(engine.ledger());
    kernel.set_rx_producer(RING + 1);
    assert!(matches!(
        engine.poll(RING),
        Err(RxFillError::Ring(NativeRingError::CorruptCursor { .. }))
    ));
    assert_eq!(snapshot(engine.ledger()), before);
    kernel.set_rx_producer(1);

    kernel.set_fill_consumer(RING.wrapping_neg().wrapping_sub(1));
    assert!(matches!(
        engine.refill(),
        Err(RxFillError::Ring(NativeRingError::CorruptCursor { .. }))
    ));
    assert_eq!(snapshot(engine.ledger()), before);
    audit(&engine);
}

#[test]
fn rx_fill_setup_rejects_untracked_ring_entries_and_bad_geometry() {
    let entries_error = |kernel: &ScriptedKernel, batch: u32| {
        let (fill, rx, umem) = kernel.views();
        RxFillEngine::new(fill, rx, umem, domain(7), config(batch)).map(|_| ())
    };
    let kernel = kernel();
    assert_eq!(
        entries_error(&kernel, RING + 1),
        Err(RxFillSetupError::FillBatchExceedsRing {
            fill_batch: RING + 1,
            capacity: RING,
        })
    );
    // An engine already published to this Fill ring; a second, untracked
    // ledger must refuse it.
    {
        let _first = engine(&kernel, 2);
    }
    assert_eq!(
        entries_error(&kernel, RING),
        Err(RxFillSetupError::FillRingNotEmpty)
    );
    let kernel = self::kernel();
    assert!(kernel.produce_rx(XdpDescriptor {
        address: HEADROOM,
        len: 64,
        options: 0,
    }));
    assert_eq!(
        entries_error(&kernel, RING),
        Err(RxFillSetupError::RxRingNotEmpty)
    );

    let mut short = vec![0_u8; UMEM_LEN as usize - 1];
    assert_eq!(
        UmemRegion::from_slice(&mut short, umem_config()).map(|_| ()),
        Err(UmemRegionError::TooShort {
            required: UMEM_LEN,
            actual: UMEM_LEN as usize - 1,
        })
    );
}

#[repr(align(64))]
struct AlignedRing([u8; 512]);

#[test]
fn rx_fill_engine_runs_over_caller_owned_heap_memory() {
    let mut fill_memory = Box::new(AlignedRing([0; 512]));
    let mut rx_memory = Box::new(AlignedRing([0; 512]));
    let mut umem_memory = vec![0_u8; UMEM_LEN as usize];
    let fill = FillProducer::new(
        &mut fill_memory.0,
        HEAP_RING_OFFSETS,
        entries(RingName::Fill),
    )
    .expect("Fill view");
    let rx = RxConsumer::new(&mut rx_memory.0, HEAP_RING_OFFSETS, entries(RingName::Rx))
        .expect("RX view");
    let umem = UmemRegion::from_slice(&mut umem_memory, umem_config()).expect("UMEM");
    assert_eq!(umem.byte_len(), UMEM_LEN);
    let mut engine =
        RxFillEngine::new(fill, rx, umem, domain(11), config(RING)).expect("heap engine");
    assert_eq!(engine.counters().fill_published, u64::from(RING));
    let batch = engine.poll(RING).expect("poll");
    assert_eq!(batch.remaining(), 0);
    drop(batch);
    assert_eq!(engine.counters().rx_ring_empty, 1);
    assert!(format!("{engine:?}").contains("<redacted>"));
    audit(&engine);
    drop(engine);
    // Producer cursor 8 is visible in the caller's memory after the borrow.
    assert_eq!(
        u32::from_ne_bytes(fill_memory.0[0..4].try_into().expect("u32")),
        RING
    );
}

#[test]
fn rx_fill_audit_detects_free_list_divergence() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    audit(&engine);
    // A lost free-list entry: the Free frame is no longer listed.
    let lost = engine.drop_free_entry_for_test().expect("free entry");
    assert_eq!(
        engine.audit(),
        Err(RxFillAuditError::FreeListCount {
            listed: RX_FRAMES - RING - 1,
            free: RX_FRAMES - RING,
        })
    );
    assert!(engine.push_free_entry_for_test(lost));
    audit(&engine);
    // A duplicated entry, and an entry naming a kernel-owned frame.
    assert!(engine.push_free_entry_for_test(lost));
    assert_eq!(
        engine.audit(),
        Err(RxFillAuditError::FreeListEntry { frame: lost })
    );
    let fresh = self::kernel();
    let mut engine = self::engine(&fresh, RING);
    assert_eq!(state(&engine, 0), FrameStateKind::FillOwnedByKernel);
    assert!(engine.push_free_entry_for_test(0));
    assert_eq!(
        engine.audit(),
        Err(RxFillAuditError::FreeListEntry { frame: 0 })
    );
}

#[test]
fn rx_fill_steady_state_does_not_allocate() {
    let kernel = kernel();
    let mut engine = engine(&kernel, RING);
    let payload = packet(3, 128);
    // Warm up once, then measure many full cycles.
    for _ in 0..2 {
        deliver(&kernel, &payload);
        let mut batch = engine.poll(RING).expect("poll");
        while let Some(frame) = batch.next_frame() {
            frame.recycle();
        }
    }
    let before = allocation_count();
    for round in 0..256_u32 {
        for _ in 0..(round % RING + 1) {
            let rx_room = RING - kernel.rx_producer().wrapping_sub(kernel.rx_consumer());
            if kernel.fill_pending() == 0 || rx_room == 0 {
                break;
            }
            let base = kernel.consume_fill().expect("Fill");
            assert!(kernel.produce_rx(XdpDescriptor {
                address: base + HEADROOM,
                len: 128,
                options: 0,
            }));
        }
        let mut handoffs: [Option<TxHandoff>; RING as usize] = Default::default();
        let mut batch = engine.poll(RING).expect("poll");
        let mut slot = 0;
        while let Some(mut frame) = batch.next_frame() {
            frame.bytes_mut()[0] ^= 1;
            if round % 3 == 0 {
                handoffs[slot] = Some(frame.stage_tx());
                slot += 1;
            } else {
                frame.recycle();
            }
        }
        drop(batch);
        for handoff in handoffs.iter_mut().filter_map(Option::take) {
            engine.cancel_tx_handoff(handoff).expect("cancel");
        }
    }
    assert_eq!(allocation_count(), before, "hot path allocated");
    audit(&engine);
}

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
    let layout = UmemLayout::new(domain(0x5302), FRAMES, FRAME_SIZE, XDP_PACKET_HEADROOM)
        .expect("model layout");
    FakeKernel::new(
        FakeEndpointId::new(NonZeroU128::new(0x5303).expect("nonzero")),
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

/// Mirrors every Fill entry the engine published since `mirrored`.
fn mirror_fill(kernel: &ScriptedKernel, model: &mut Model, mirrored: &mut u32) {
    while *mirrored != kernel.fill_producer() {
        let address = kernel.fill_entry(*mirrored);
        let frame = u32::try_from(address / u64::from(FRAME_SIZE)).expect("frame");
        model
            .reserve_fill(frame)
            .expect("model reserve")
            .publish()
            .expect("model publish");
        *mirrored = mirrored.wrapping_add(1);
    }
}

/// Compares per-frame state and generation.
///
/// The model records a frame `RxAvailable` as soon as its kernel produces
/// the RX descriptor; the native engine cannot observe that until it reads
/// the RX ring, so it still records `FillOwnedByKernel`. Both mean "held by
/// the kernel side", and the comparison projects the model onto that. The
/// schedule drains every batch, so the engine has no `RxAvailable` frame at
/// a step boundary.
fn assert_same(engine: &RxFillEngine<'_>, model: &Model, step: usize) {
    let kernel_held = |(kind, generation): (FrameStateKind, Option<u64>)| match kind {
        FrameStateKind::RxAvailable => (FrameStateKind::FillOwnedByKernel, generation),
        _ => (kind, generation),
    };
    let model_view: Vec<_> = snapshot(model.ledger())
        .into_iter()
        .map(kernel_held)
        .collect();
    assert_eq!(snapshot(engine.ledger()), model_view, "step {step}");
    assert_eq!(engine.pending_rx(), 0, "step {step}");
    model.ledger().deep_audit().expect("model audit");
    engine
        .audit()
        .unwrap_or_else(|error| panic!("step {step}: {error:?}"));
}

#[test]
fn rx_fill_differential_matches_fake_kernel_ownership_model() {
    for seed in [
        0x9e37_79b9_7f4a_7c15_u64,
        0xdead_beef,
        0x0123_4567_89ab_cdef,
    ] {
        let kernel = kernel();
        let mut engine = engine(&kernel, 5);
        let mut model = model();
        let mut mirrored = 0_u32;
        let mut rng = Rng(seed);
        let mut handoffs: Vec<TxHandoff> = Vec::new();
        let mut written = [0_u8; FRAMES as usize];
        mirror_fill(&kernel, &mut model, &mut mirrored);
        assert_same(&engine, &model, 0);
        let steps = if cfg!(miri) { 60 } else { 600 };
        for step in 1..=steps {
            match rng.below(4) {
                // Kernel: receive into some Fill frames, if RX has room.
                0 | 1 => {
                    for _ in 0..rng.below(u64::from(RING)) + 1 {
                        let rx_room =
                            RING - kernel.rx_producer().wrapping_sub(kernel.rx_consumer());
                        if kernel.fill_pending() == 0 || rx_room == 0 {
                            break;
                        }
                        let base = kernel.consume_fill().expect("Fill");
                        let len =
                            ETHERNET_HEADER_LEN + u32::try_from(rng.below(1_000)).expect("small");
                        let raw = XdpDescriptor {
                            address: base + HEADROOM,
                            len,
                            options: 0,
                        };
                        let frame = (base / u64::from(FRAME_SIZE)) as usize;
                        written[frame] = step as u8;
                        kernel.write_umem(base + HEADROOM, &[step as u8; 4]);
                        assert!(kernel.produce_rx(raw));
                        model
                            .kernel_consume_fill()
                            .expect("model Fill")
                            .produce_rx(RawDescriptor {
                                addr: raw.address,
                                len,
                                options: 0,
                            })
                            .expect("model RX");
                    }
                }
                // Engine: poll and drain the batch with a random completion.
                2 => {
                    let budget = u32::try_from(rng.below(u64::from(RING) + 2)).expect("small");
                    let consumed_before = kernel.rx_consumer();
                    let mut batch = engine.poll(budget).expect("poll");
                    let consumed = kernel.rx_consumer().wrapping_sub(consumed_before);
                    if consumed > 0 {
                        model
                            .acquire_rx(consumed as usize)
                            .expect("model RX acquire")
                            .release_consume()
                            .expect("model RX consume");
                    }
                    let mut lent = 0;
                    while let Some(frame) = batch.next_frame() {
                        lent += 1;
                        let index = frame.frame().index();
                        let mark = written[index as usize];
                        assert_eq!(&frame.bytes()[..4], &[mark; 4], "step {step}");
                        let token = model_token(&model, index);
                        match rng.below(3) {
                            0 => frame.recycle(),
                            1 => drop(frame),
                            _ => {
                                handoffs.push(frame.stage_tx());
                                model.stage_tx(token).expect("model stage");
                                continue;
                            }
                        }
                        model.recycle_lease(token).expect("model recycle");
                    }
                    assert_eq!(lent, consumed, "every valid descriptor drained");
                    drop(batch);
                    mirror_fill(&kernel, &mut model, &mut mirrored);
                }
                // TX side stand-in: cancel a random handoff, then refill.
                _ => {
                    if !handoffs.is_empty() {
                        let pick = rng.below(handoffs.len() as u64) as usize;
                        let handoff = handoffs.swap_remove(pick);
                        let token = model_token(&model, handoff.frame().index());
                        engine.cancel_tx_handoff(handoff).expect("cancel");
                        model.cancel_pending_tx(token).expect("model cancel");
                        model.recycle_lease(token).expect("model recycle");
                    }
                    let _ = engine.refill().expect("refill");
                    mirror_fill(&kernel, &mut model, &mut mirrored);
                }
            }
            assert_same(&engine, &model, step);
        }
        for handoff in handoffs.drain(..) {
            let token = model_token(&model, handoff.frame().index());
            engine.cancel_tx_handoff(handoff).expect("cancel");
            model.cancel_pending_tx(token).expect("model cancel");
            model.recycle_lease(token).expect("model recycle");
        }
        assert_same(&engine, &model, usize::MAX);
        let counters = engine.counters();
        assert_eq!(counters.rx_invalid_total(), 0);
        // The schedule exercised every completion path and starvation.
        assert!(counters.rx_leased >= steps as u64 / 10, "{counters:?}");
        assert!(counters.rx_recycled > 0 && counters.rx_abandoned > 0);
        assert!(counters.rx_tx_handoffs > 0 && counters.tx_handoffs_cancelled > 0);
        assert_eq!(
            counters.rx_leased,
            counters.rx_recycled + counters.rx_abandoned + counters.rx_tx_handoffs
        );
    }
}

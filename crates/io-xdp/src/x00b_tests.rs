use std::{mem::size_of, num::NonZeroU128};

use crate::{
    DescriptorError, EndpointLocation, FakeEndpointId, FakeFault, FakeKernel, FrameLedger,
    FrameStateKind, LedgerError, RawDescriptor, RingDescriptor, RingError, RingKind, SpscRing,
    UmemDomainId, UmemLayout,
};

fn endpoint_id(value: u128) -> FakeEndpointId {
    FakeEndpointId::new(NonZeroU128::new(value).expect("nonzero endpoint identity"))
}

fn ledger(domain: u128, frames: u32) -> FrameLedger {
    let layout = UmemLayout::new(
        UmemDomainId::new(NonZeroU128::new(domain).expect("nonzero UMEM domain")),
        frames,
        2_048,
        256,
    )
    .expect("layout");
    FrameLedger::new(layout).expect("ledger")
}

fn make_fake<const RING_SIZE: usize, const FRAME_COUNT: usize>(
    endpoint: u128,
    domain: u128,
    location: EndpointLocation,
) -> FakeKernel<RING_SIZE, FRAME_COUNT> {
    FakeKernel::new(
        endpoint_id(endpoint),
        location,
        ledger(
            domain,
            u32::try_from(FRAME_COUNT).expect("test frame count fits u32"),
        ),
    )
    .expect("fake")
}

fn assert_partition<const RING_SIZE: usize, const FRAME_COUNT: usize>(
    fake: &FakeKernel<RING_SIZE, FRAME_COUNT>,
) {
    assert_eq!(fake.ledger().counts().total(), FRAME_COUNT);
    fake.ledger().deep_audit().expect("ledger partition");
}

fn assert_terminal<const RING_SIZE: usize, const FRAME_COUNT: usize>(
    fake: &FakeKernel<RING_SIZE, FRAME_COUNT>,
) {
    for kind in [
        RingKind::Fill,
        RingKind::Rx,
        RingKind::Tx,
        RingKind::Completion,
    ] {
        assert_eq!(fake.ring_occupied(kind), Ok(0));
    }
    assert_eq!(
        fake.ledger().counts().get(FrameStateKind::Free),
        FRAME_COUNT
    );
    assert_partition(fake);
}

#[test]
fn x00b_06_observation_is_derived_from_physical_endpoint_handle() {
    let location = EndpointLocation::new(7, 3);
    let first = make_fake::<4, 1>(101, 201, location);
    let second = make_fake::<4, 1>(102, 202, location);
    let first_fill = first.endpoint_handle().observe(RingKind::Fill);
    let first_tx = first.endpoint_handle().observe(RingKind::Tx);
    let second_fill = second.endpoint_handle().observe(RingKind::Fill);
    assert_eq!(first_fill.location(), location);
    assert_eq!(first_fill.kind(), RingKind::Fill);
    assert_ne!(first_fill, first_tx);
    assert_ne!(first_fill, second_fill);

    let mut ring = SpscRing::<u32, 4>::new(first_fill).expect("ring");
    let mut reservation = ring.reserve(1).expect("reserve");
    assert_eq!(
        reservation.write(0, second_fill.bind(1)),
        Err(RingError::WrongRing)
    );
    assert_eq!(
        reservation.write(0, first_tx.bind(1)),
        Err(RingError::WrongRing)
    );
    reservation
        .write(0, first_fill.bind(1))
        .expect("handle-derived observation");
    reservation.release_submit().expect("submit");
}

#[test]
fn x00b_07_power_of_two_capacity_and_full_empty_boundaries_are_exact() {
    let fake = make_fake::<4, 1>(103, 203, EndpointLocation::new(8, 0));
    let observation = fake.endpoint_handle().observe(RingKind::Fill);
    assert_eq!(
        SpscRing::<u32, 0>::new(observation).expect_err("zero"),
        RingError::InvalidCapacity
    );
    assert_eq!(
        SpscRing::<u32, 3>::new(observation).expect_err("not power of two"),
        RingError::InvalidCapacity
    );

    let mut ring = SpscRing::<u32, 4>::new(observation).expect("ring");
    assert_eq!(ring.capacity(), 4);
    let mut reservation = ring.reserve(4).expect("full reservation");
    for offset in 0..4 {
        reservation
            .write(offset, observation.bind(offset as u32))
            .expect("write");
    }
    reservation.release_submit().expect("publish");
    assert_eq!(ring.occupied(), Ok(4));
    assert_eq!(ring.reserve(1).err(), Some(RingError::RingFull));

    ring.acquire(4)
        .expect("acquire all")
        .release_consume()
        .expect("consume");
    assert_eq!(ring.occupied(), Ok(0));
    assert_eq!(ring.acquire(1).err(), Some(RingError::RingEmpty));
}

#[test]
fn x00b_08_u32_cursor_wrap_preserves_fifo_and_occupancy() {
    let fake = make_fake::<4, 1>(104, 204, EndpointLocation::new(9, 0));
    let observation = fake.endpoint_handle().observe(RingKind::Rx);
    let mut ring = SpscRing::<u32, 4>::new(observation).expect("ring");
    ring.set_empty_cursor_for_test(u32::MAX - 1);

    let mut reservation = ring.reserve(2).expect("reserve across wrap");
    reservation.write(0, observation.bind(41)).expect("first");
    reservation.write(1, observation.bind(42)).expect("second");
    reservation.release_submit().expect("submit");
    assert_eq!(ring.indices().producer, 0);
    assert_eq!(ring.occupied(), Ok(2));

    let acquisition = ring.acquire(2).expect("acquire");
    assert_eq!(acquisition.peek(0), Ok(41));
    assert_eq!(acquisition.peek(1), Ok(42));
    acquisition.release_consume().expect("consume");
    assert_eq!(ring.indices().consumer, 0);
    assert_eq!(ring.occupied(), Ok(0));
}

#[test]
fn x00b_09_reservation_drop_and_incomplete_submit_publish_nothing() {
    let fake = make_fake::<4, 1>(105, 205, EndpointLocation::new(10, 0));
    let observation = fake.endpoint_handle().observe(RingKind::Tx);
    let mut ring = SpscRing::<u32, 4>::new(observation).expect("ring");

    {
        let mut reservation = ring.reserve(2).expect("reserve");
        reservation.write(0, observation.bind(1)).expect("write");
    }
    assert_eq!(ring.occupied(), Ok(0));

    let error = {
        let mut reservation = ring.reserve(2).expect("reserve again");
        reservation.write(0, observation.bind(2)).expect("write");
        reservation
            .release_submit()
            .expect_err("incomplete must cancel on drop")
    };
    assert_eq!(error, RingError::IncompleteReservation);
    assert_eq!(ring.occupied(), Ok(0));

    let mut replacement = ring.reserve(2).expect("slots were cleared");
    replacement.write(0, observation.bind(3)).expect("first");
    replacement.write(1, observation.bind(4)).expect("second");
    replacement.release_cancel();
    assert_eq!(ring.occupied(), Ok(0));
}

#[test]
fn x00b_10_wrong_ring_duplicate_length_and_order_faults_are_typed() {
    let fake = make_fake::<4, 1>(106, 206, EndpointLocation::new(11, 0));
    let fill = fake.endpoint_handle().observe(RingKind::Fill);
    let tx = fake.endpoint_handle().observe(RingKind::Tx);
    let mut ring = SpscRing::<u32, 4>::new(fill).expect("ring");

    assert_eq!(ring.reserve(0).err(), Some(RingError::ZeroLength));
    assert_eq!(
        ring.reserve(5).err(),
        Some(RingError::LengthExceedsCapacity)
    );
    let mut reservation = ring.reserve(2).expect("reserve");
    assert_eq!(reservation.write(0, tx.bind(10)), Err(RingError::WrongRing));
    reservation.write(0, fill.bind(10)).expect("first write");
    assert_eq!(
        reservation.write(0, fill.bind(11)),
        Err(RingError::DuplicateWrite)
    );
    assert_eq!(
        reservation.write(2, fill.bind(12)),
        Err(RingError::OffsetOutsideRange)
    );
    assert_eq!(
        reservation.release_submit(),
        Err(RingError::IncompleteReservation)
    );
    assert_eq!(ring.occupied(), Ok(0));
}

#[test]
fn x00b_11_acquire_peek_consume_cancel_is_fifo_and_bounded() {
    let fake = make_fake::<4, 1>(107, 207, EndpointLocation::new(12, 0));
    let observation = fake.endpoint_handle().observe(RingKind::Completion);
    let mut ring = SpscRing::<u32, 4>::new(observation).expect("ring");
    let mut reservation = ring.reserve(2).expect("reserve");
    reservation.write(0, observation.bind(90)).expect("first");
    reservation.write(1, observation.bind(91)).expect("second");
    reservation.release_submit().expect("submit");

    {
        let acquisition = ring.acquire(2).expect("acquire");
        assert_eq!(acquisition.peek(0), Ok(90));
        assert_eq!(acquisition.peek(1), Ok(91));
        assert_eq!(acquisition.peek(2), Err(RingError::OffsetOutsideRange));
    }
    assert_eq!(ring.occupied(), Ok(2));
    ring.acquire(2).expect("reacquire").release_cancel();
    assert_eq!(ring.occupied(), Ok(2));

    let acquisition = ring.acquire(2).expect("final acquire");
    assert_eq!(acquisition.peek(0), Ok(90));
    assert_eq!(acquisition.peek(1), Ok(91));
    acquisition.release_consume().expect("consume");
    assert_eq!(ring.occupied(), Ok(0));
}

#[test]
fn x00b_12_fake_kernel_fill_rx_faults_are_finite_and_atomic() {
    let mut fake = make_fake::<4, 3>(108, 301, EndpointLocation::new(13, 0));
    let generated = fake.lease_generated(1).expect("generated lease");
    let counts_before_generated_fill = fake.ledger().counts();
    assert!(matches!(
        fake.authorize_fill(generated),
        Err(FakeFault::Ledger(LedgerError::WrongState {
            expected: FrameStateKind::FillReserved,
            actual: FrameStateKind::Leased,
            ..
        }))
    ));
    assert_eq!(fake.ledger().counts(), counts_before_generated_fill);
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(0));
    fake.recycle_lease(generated)
        .expect("non-TX generated lease recycle");

    let abandoned = {
        let reservation = fake.reserve_fill(0).expect("abandoned Fill reserve");
        reservation.token()
    };
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::Free
    );
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(0));

    let fill = fake.reserve_fill(0).expect("fill reservation");
    let token = fill.token();
    assert_ne!(token, abandoned);
    fill.publish().expect("publish Fill");
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(1));
    let counts_after_publish = fake.ledger().counts();
    assert!(matches!(
        fake.authorize_fill(token),
        Err(FakeFault::Ledger(LedgerError::WrongState {
            expected: FrameStateKind::FillReserved,
            actual: FrameStateKind::FillOwnedByKernel,
            ..
        }))
    ));
    assert_eq!(fake.ledger().counts(), counts_after_publish);
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(1));

    let consumed = fake.kernel_consume_fill().expect("kernel Fill consume");
    assert_eq!(consumed.token(), token);
    assert_eq!(
        consumed.produce_rx(RawDescriptor {
            addr: 256,
            len: 0,
            options: 0,
        }),
        Err(FakeFault::Descriptor(DescriptorError::EmptyPacket))
    );
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(1));
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::FillOwnedByKernel
    );
    assert_eq!(fake.ring_occupied(RingKind::Rx), Ok(0));

    let consumed = fake.kernel_consume_fill().expect("reacquire restored Fill");
    let checked = consumed
        .produce_rx(RawDescriptor {
            addr: 256,
            len: 64,
            options: 0,
        })
        .expect("valid RX retry");
    assert_eq!(fake.ring_occupied(RingKind::Rx), Ok(1));
    {
        let acquisition = fake.acquire_rx(1).expect("application RX");
        let observed = acquisition.peek(0).expect("RX descriptor");
        assert_eq!(observed.token(), token);
        assert_eq!(observed.packet_descriptor(), Some(checked));
        acquisition.release_cancel();
    }
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::RxAvailable
    );
    fake.acquire_rx(1)
        .expect("RX retry")
        .release_consume()
        .expect("consume RX");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::Leased
    );
    assert_eq!(fake.ring_occupied(RingKind::Rx), Ok(0));
    fake.recycle_lease(token).expect("RX lease recycle");
    assert_partition(&fake);

    let fill_a = fake.reserve_fill(0).expect("FIFO Fill A reserve");
    let token_a = fill_a.token();
    fill_a.publish().expect("FIFO Fill A publish");
    let fill_b = fake.reserve_fill(1).expect("FIFO Fill B reserve");
    let token_b = fill_b.token();
    fill_b.publish().expect("FIFO Fill B publish");
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(2));
    let head = fake.kernel_consume_fill().expect("peek Fill A");
    assert_eq!(head.token(), token_a);
    drop(head);
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(2));
    let head = fake
        .kernel_consume_fill()
        .expect("dropped head remains Fill A");
    assert_eq!(head.token(), token_a);
    head.produce_rx(RawDescriptor {
        addr: 256,
        len: 64,
        options: 0,
    })
    .expect("Fill A RX");
    let next = fake.kernel_consume_fill().expect("Fill B follows A");
    assert_eq!(next.token(), token_b);
    next.produce_rx(RawDescriptor {
        addr: 2_048 + 256,
        len: 64,
        options: 0,
    })
    .expect("Fill B RX");
    let rx = fake.acquire_rx(2).expect("FIFO RX pair");
    assert_eq!(rx.peek(0).expect("RX A").token(), token_a);
    assert_eq!(rx.peek(1).expect("RX B").token(), token_b);
    rx.release_consume().expect("consume FIFO RX pair");
    fake.recycle_lease(token_a).expect("recycle FIFO A");
    fake.recycle_lease(token_b).expect("recycle FIFO B");
    assert_terminal(&fake);

    let mut foreign = make_fake::<4, 1>(110, 302, EndpointLocation::new(13, 1));
    let foreign_fill = foreign.reserve_fill(0).expect("foreign reservation");
    let foreign_token = foreign_fill.token();
    drop(foreign_fill);
    let local_counts = fake.ledger().counts();
    let foreign_counts = foreign.ledger().counts();
    assert!(matches!(
        fake.authorize_fill(foreign_token),
        Err(FakeFault::Ledger(LedgerError::ForeignTokenDomain))
    ));
    assert_eq!(fake.ledger().counts(), local_counts);
    assert_eq!(foreign.ledger().counts(), foreign_counts);
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(0));
    assert_eq!(foreign.ring_occupied(RingKind::Fill), Ok(0));
    let foreign_retry = foreign.reserve_fill(0).expect("foreign owner retries");
    let foreign_token = foreign_retry.token();
    foreign_retry.publish().expect("foreign owner can publish");
    assert_eq!(foreign.ring_occupied(RingKind::Fill), Ok(1));
    let consumed = foreign.kernel_consume_fill().expect("foreign Fill consume");
    consumed
        .produce_rx(RawDescriptor {
            addr: 256,
            len: 64,
            options: 0,
        })
        .expect("foreign RX publish");
    foreign
        .acquire_rx(1)
        .expect("foreign RX acquire")
        .release_consume()
        .expect("foreign RX consume");
    foreign
        .recycle_lease(foreign_token)
        .expect("foreign lease recycle");
    assert_terminal(&fake);
    assert_terminal(&foreign);
}

#[test]
fn x00b_13_fake_tx_completion_and_fixed_storage_are_exact() {
    let mut fake = make_fake::<4, 2>(109, 401, EndpointLocation::new(14, 1));
    assert_partition(&fake);

    {
        let _abandoned = fake.reserve_fill(0).expect("early unwind Fill reserve");
    }
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::Free
    );
    let fill = fake.reserve_fill(0).expect("Fill reserve");
    let received = fill.token();
    fill.publish().expect("Fill publish");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::FillOwnedByKernel
    );
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(1));
    assert_partition(&fake);
    let consumed_fill = fake.kernel_consume_fill().expect("Fill consume");
    drop(consumed_fill);
    assert_eq!(fake.ring_occupied(RingKind::Fill), Ok(1));
    let consumed_fill = fake
        .kernel_consume_fill()
        .expect("dropped Fill capability is reacquired");
    let received_packet = consumed_fill
        .produce_rx(RawDescriptor {
            addr: 256,
            len: 96,
            options: 0,
        })
        .expect("RX publish");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::RxAvailable
    );
    assert_eq!(fake.ring_occupied(RingKind::Rx), Ok(1));
    assert_partition(&fake);
    fake.acquire_rx(1)
        .expect("RX acquire")
        .release_consume()
        .expect("RX consume");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::Leased
    );
    assert_eq!(fake.ring_occupied(RingKind::Rx), Ok(0));

    fake.stage_tx(received).expect("RX lease stage TX");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::PendingTx
    );
    {
        let _abandoned_tx = fake.reserve_tx(received).expect("early unwind TX reserve");
    }
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::PendingTx
    );
    fake.cancel_pending_tx(received)
        .expect("pending TX returns to lease");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::Leased
    );
    fake.stage_tx(received).expect("restage RX lease");
    let received_tx = fake.reserve_tx(received).expect("RX lease reserve TX");
    let reserved_token = received_tx.token();
    assert_eq!(reserved_token, received);
    received_tx
        .publish(received_packet)
        .expect("RX lease publish TX");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::TxOwnedByKernel
    );
    assert_eq!(fake.ring_occupied(RingKind::Tx), Ok(1));
    assert_partition(&fake);
    let consumed_tx = fake.kernel_consume_tx().expect("kernel TX consume");
    assert_eq!(consumed_tx.token(), received);
    drop(consumed_tx);
    assert_eq!(fake.ring_occupied(RingKind::Tx), Ok(1));
    let consumed_tx = fake
        .kernel_consume_tx()
        .expect("dropped TX capability is reacquired");
    consumed_tx
        .produce_completion()
        .expect("completion publish");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::CompletionAvailable
    );
    assert_eq!(fake.ring_occupied(RingKind::Completion), Ok(1));
    assert_partition(&fake);
    {
        let completion = fake.acquire_completion(1).expect("completion acquire");
        assert_eq!(completion.peek(0).expect("CQ").token(), received);
    }
    assert_eq!(fake.ring_occupied(RingKind::Completion), Ok(1));
    fake.acquire_completion(1)
        .expect("completion acquire")
        .release_consume()
        .expect("completion consume");
    assert_eq!(
        fake.ledger().state(0).expect("frame").kind(),
        FrameStateKind::Free
    );
    assert_eq!(fake.ring_occupied(RingKind::Completion), Ok(0));
    assert_partition(&fake);

    let generated = fake.lease_generated(1).expect("generated lease");
    fake.recycle_lease(generated)
        .expect("non-TX generated recycle");
    let generated = fake.lease_generated(1).expect("new generated lease");
    fake.stage_tx(generated).expect("generated pending TX");
    fake.cancel_pending_tx(generated)
        .expect("generated pending rollback");
    fake.recycle_lease(generated)
        .expect("rolled-back generated recycle");

    let generated_a = fake.lease_generated(0).expect("generated A lease");
    let packet_a = fake
        .layout()
        .validate_descriptor(RawDescriptor {
            addr: 256,
            len: 128,
            options: 0,
        })
        .expect("packet A descriptor");
    fake.stage_tx(generated_a).expect("generated A stage TX");
    fake.reserve_tx(generated_a)
        .expect("generated A reserve TX")
        .publish(packet_a)
        .expect("generated A publish TX");

    let generated_b = fake.lease_generated(1).expect("generated B lease");
    let packet_b = fake
        .layout()
        .validate_descriptor(RawDescriptor {
            addr: 2_048 + 256,
            len: 128,
            options: 0,
        })
        .expect("packet B descriptor");
    fake.stage_tx(generated_b).expect("generated B stage TX");
    fake.reserve_tx(generated_b)
        .expect("generated B reserve TX")
        .publish(packet_b)
        .expect("generated B publish TX");
    assert_eq!(fake.ring_occupied(RingKind::Tx), Ok(2));

    let head = fake.kernel_consume_tx().expect("peek TX A");
    assert_eq!(head.token(), generated_a);
    drop(head);
    assert_eq!(fake.ring_occupied(RingKind::Tx), Ok(2));
    let head = fake.kernel_consume_tx().expect("dropped head remains TX A");
    assert_eq!(head.token(), generated_a);
    head.produce_completion().expect("generated A completion");
    let next = fake.kernel_consume_tx().expect("TX B follows A");
    assert_eq!(next.token(), generated_b);
    next.produce_completion().expect("generated B completion");

    let completion = fake.acquire_completion(2).expect("completion pair");
    assert_eq!(
        completion.peek(0).expect("completion A").token(),
        generated_a
    );
    assert_eq!(
        completion.peek(1).expect("completion B").token(),
        generated_b
    );
    completion
        .release_consume()
        .expect("generated completion pair recycle");
    assert_terminal(&fake);

    assert!(size_of::<SpscRing<RingDescriptor, 4>>() >= size_of::<RingDescriptor>() * 4);
    assert!(size_of::<FakeKernel<4, 2>>() >= size_of::<SpscRing<RingDescriptor, 4>>() * 4);
}

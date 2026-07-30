use std::{mem::size_of, num::NonZeroU128};

use crate::{
    DescriptorError, EndpointLocation, FakeEndpointId, FakeFault, FakeKernel, FrameLedger,
    RawDescriptor, RingDescriptor, RingError, RingKind, SpscRing, UmemDomainId, UmemLayout,
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

#[test]
fn x00b_06_observation_is_derived_from_physical_endpoint_handle() {
    let location = EndpointLocation::new(7, 3);
    let first = FakeKernel::<4, 1>::new(endpoint_id(101), location).expect("first endpoint");
    let second = FakeKernel::<4, 1>::new(endpoint_id(102), location).expect("second endpoint");
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
    let fake =
        FakeKernel::<4, 1>::new(endpoint_id(103), EndpointLocation::new(8, 0)).expect("endpoint");
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
    let fake =
        FakeKernel::<4, 1>::new(endpoint_id(104), EndpointLocation::new(9, 0)).expect("endpoint");
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
    let fake =
        FakeKernel::<4, 1>::new(endpoint_id(105), EndpointLocation::new(10, 0)).expect("endpoint");
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
    let fake =
        FakeKernel::<4, 1>::new(endpoint_id(106), EndpointLocation::new(11, 0)).expect("endpoint");
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
    let fake =
        FakeKernel::<4, 1>::new(endpoint_id(107), EndpointLocation::new(12, 0)).expect("endpoint");
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
    let mut ledger = ledger(201, 2);
    let token = ledger.reserve_fill(0).expect("fill token");
    let mut fake =
        FakeKernel::<4, 2>::new(endpoint_id(108), EndpointLocation::new(13, 0)).expect("fake");
    let fill_observation = fake.endpoint_handle().observe(RingKind::Fill);

    assert_eq!(
        fake.kernel_produce_rx(
            token,
            RawDescriptor {
                addr: 256,
                len: 64,
                options: 0,
            },
            ledger.layout(),
        ),
        Err(FakeFault::WrongOrder)
    );

    let mut reservation = fake.reserve_fill(2).expect("reserve duplicate fill");
    let fill = RingDescriptor::frame(token);
    reservation
        .write(0, fill_observation.bind(fill))
        .expect("first");
    reservation
        .write(1, fill_observation.bind(fill))
        .expect("duplicate is observed by kernel");
    reservation.release_submit().expect("submit");
    assert_eq!(fake.kernel_consume_fill(), Ok(token));
    assert_eq!(fake.kernel_consume_fill(), Err(FakeFault::DuplicateToken));

    assert_eq!(
        fake.kernel_produce_rx(
            token,
            RawDescriptor {
                addr: 256,
                len: 0,
                options: 0,
            },
            ledger.layout(),
        ),
        Err(FakeFault::Descriptor(DescriptorError::EmptyPacket))
    );
    let checked = fake
        .kernel_produce_rx(
            token,
            RawDescriptor {
                addr: 256,
                len: 64,
                options: 0,
            },
            ledger.layout(),
        )
        .expect("valid RX");
    let acquisition = fake.acquire_rx(1).expect("application RX");
    assert_eq!(
        acquisition.peek(0),
        Ok(RingDescriptor::packet(token, checked))
    );
    acquisition.release_consume().expect("consume RX");
    assert_eq!(fake.kernel_consume_fill(), Err(FakeFault::DuplicateToken));
}

#[test]
fn x00b_13_fake_tx_completion_and_fixed_storage_are_exact() {
    let mut ledger = ledger(202, 2);
    let token = ledger.lease_generated(1).expect("generated token");
    let packet = ledger
        .layout()
        .validate_descriptor(RawDescriptor {
            addr: 2_048 + 256,
            len: 128,
            options: 0,
        })
        .expect("packet descriptor");
    let mut fake =
        FakeKernel::<4, 2>::new(endpoint_id(109), EndpointLocation::new(14, 1)).expect("fake");
    let tx_observation = fake.endpoint_handle().observe(RingKind::Tx);
    let mut reservation = fake.reserve_tx(1).expect("TX reserve");
    reservation
        .write(
            0,
            tx_observation.bind(RingDescriptor::packet(token, packet)),
        )
        .expect("TX write");
    reservation.release_submit().expect("TX submit");

    assert_eq!(
        fake.kernel_produce_completion(token),
        Err(FakeFault::WrongOrder)
    );
    assert_eq!(
        fake.kernel_consume_tx(ledger.layout()),
        Ok(RingDescriptor::packet(token, packet))
    );
    fake.kernel_produce_completion(token)
        .expect("completion publish");
    assert_eq!(
        fake.kernel_produce_completion(token),
        Err(FakeFault::WrongOrder)
    );
    let completion = fake.acquire_completion(1).expect("completion acquire");
    assert_eq!(completion.peek(0), Ok(RingDescriptor::frame(token)));
    completion.release_consume().expect("completion consume");

    let tx_observation = fake.endpoint_handle().observe(RingKind::Tx);
    let mut replay = fake.reserve_tx(1).expect("replay reserve");
    replay
        .write(
            0,
            tx_observation.bind(RingDescriptor::packet(token, packet)),
        )
        .expect("replay write");
    replay.release_submit().expect("replay submit");
    assert_eq!(
        fake.kernel_consume_tx(ledger.layout()),
        Err(FakeFault::DuplicateToken)
    );

    assert!(size_of::<SpscRing<RingDescriptor, 4>>() >= size_of::<RingDescriptor>() * 4);
    assert!(size_of::<FakeKernel<4, 2>>() >= size_of::<SpscRing<RingDescriptor, 4>>() * 4);
}

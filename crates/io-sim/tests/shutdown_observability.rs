use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    mem,
};

use ruster_core::{
    bind_publication_backend, ConsumeReason, DropReason, GeneratedPacketBatch, GeneratedPacketIo,
    IfId, PacketBatch, PacketIo, PublicationQuiescenceBackend,
};
use ruster_io_sim::{
    BoundSimIoControl, BoundSimIoObservabilityControl, SimIo, SimPublicationQuiescenceError,
};

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct AllocationCounts {
    alloc: u64,
    alloc_zeroed: u64,
    realloc: u64,
}

thread_local! {
    static ALLOCATION_COUNTS: Cell<AllocationCounts> = const {
        Cell::new(AllocationCounts {
            alloc: 0,
            alloc_zeroed: 0,
            realloc: 0,
        })
    };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is supplied by the allocator contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATION_COUNTS.with(|counts| {
                let mut next = counts.get();
                next.alloc = next.alloc.saturating_add(1);
                counts.set(next);
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from this allocator.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is supplied by the allocator contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            ALLOCATION_COUNTS.with(|counts| {
                let mut next = counts.get();
                next.alloc_zeroed = next.alloc_zeroed.saturating_add(1);
                counts.set(next);
            });
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: `pointer` and `layout` came from this allocator.
        let next_pointer = unsafe { System.realloc(pointer, layout, size) };
        if !next_pointer.is_null() {
            ALLOCATION_COUNTS.with(|counts| {
                let mut next = counts.get();
                next.realloc = next.realloc.saturating_add(1);
                counts.set(next);
            });
        }
        next_pointer
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn reset_allocation_counts() {
    ALLOCATION_COUNTS.with(|counts| counts.set(AllocationCounts::default()));
}

fn allocation_counts() -> AllocationCounts {
    ALLOCATION_COUNTS.with(Cell::get)
}

#[test]
// R15OBS-009
fn r15obs_009_snapshot_and_queue_gauges_are_exact_and_stable() {
    let mut io = SimIo::new();
    assert_eq!(io.stats().pending_rx, 0);
    io.inject(IfId(1), vec![1]);
    io.inject(IfId(1), vec![2]);
    let s = io.stats();
    assert_eq!(
        (s.injected_rx_total, s.pending_rx, s.rx_queue_high_watermark),
        (2, 2, 2)
    );
    let mut b = io.receive(2).unwrap();
    let p = b.next_packet().unwrap();
    p.consume(ConsumeReason::ArpControl);
    let p = b.next_packet().unwrap();
    p.recycle(DropReason::RouteMiss);
    b.finish();
    assert_eq!((io.stats().pending_rx, io.stats().pending_recycled), (0, 2));
    let mut g = io.begin_generated(IfId(2));
    let p = g.allocate(4).unwrap();
    p.cancel();
    g.finish();
    assert_eq!(io.stats().pending_generated_recycled, 1);
    let a = io.stats();
    let _ = io.pop_recycled();
    let _ = io.pop_recycled();
    let _ = io.pop_generated_recycled();
    let b = io.stats();
    assert_eq!(a.rx_queue_high_watermark, b.rx_queue_high_watermark);
    assert_eq!(b, io.stats());

    reset_allocation_counts();
    let before = io.stats();
    let snapshot_one = io.stats();
    let snapshot_two = io.stats();
    let allocations = allocation_counts();
    assert_eq!(allocations.alloc, 0);
    assert_eq!(allocations.alloc_zeroed, 0);
    assert_eq!(allocations.realloc, 0);
    assert_eq!(before, snapshot_one);
    assert_eq!(snapshot_one, snapshot_two);
}

#[test]
// R15OBS-010
fn r15obs_010_accepted_tx_completion_and_hwm_are_ownership_counters() {
    let mut io = SimIo::new();
    io.inject(IfId(1), vec![1]);
    let mut b = io.receive(1).unwrap();
    let p = b.next_packet().unwrap();
    p.commit(IfId(2));
    b.finish();
    let mut g = io.begin_generated(IfId(2));
    let p = g.allocate(3).unwrap();
    p.commit();
    g.finish();
    assert_eq!(io.stats().accepted_tx_total, 2);
    assert_eq!(io.stats().pending_tx, 2);
    assert_eq!(io.stats().tx_queue_high_watermark, 2);
    assert_eq!(
        io.stats().accepted_tx_total,
        io.stats().completed_tx_total + io.stats().pending_tx
    );
    // pop_tx observes simulated backend ownership completion; it proves no wire delivery.
    assert!(io.pop_tx().is_some());
    assert!(io.pop_tx().is_some());
    assert!(io.pop_tx().is_none());
    assert_eq!(io.stats().completed_tx_total, 2);
    assert_eq!(io.stats().tx_queue_high_watermark, 2);
    let mut reject = SimIo::new();
    reject.set_received_accept_budget(0);
    reject.inject(IfId(1), vec![1]);
    let mut b = reject.receive(1).unwrap();
    let p = b.next_packet().unwrap();
    p.commit(IfId(2));
    b.finish();
    assert_eq!(
        (
            reject.stats().accepted_tx_total,
            reject.stats().completed_tx_total,
            reject.stats().tx_queue_high_watermark,
        ),
        (0, 0, 0)
    );
}

#[test]
// R15OBS-011
fn r15obs_011_each_recycle_and_abandonment_has_its_own_total() {
    let mut io = SimIo::new();
    io.inject(IfId(1), vec![1]);
    let mut b = io.receive(1).unwrap();
    let p = b.next_packet().unwrap();
    p.recycle(DropReason::RouteMiss);
    b.finish();
    io.inject(IfId(1), vec![2]);
    let mut b = io.receive(1).unwrap();
    let p = b.next_packet().unwrap();
    p.consume(ConsumeReason::ArpControl);
    b.finish();
    io.inject(IfId(1), vec![3]);
    io.set_received_accept_budget(0);
    let mut b = io.receive(1).unwrap();
    let p = b.next_packet().unwrap();
    p.commit(IfId(2));
    b.finish();
    io.inject(IfId(1), vec![4]);
    let mut b = io.receive(1).unwrap();
    let p = b.next_packet().unwrap();
    drop(p);
    b.finish();
    io.set_generated_accept_budget(0);
    let mut g = io.begin_generated(IfId(2));
    let p = g.allocate(1).unwrap();
    p.cancel();
    let p = g.allocate(1).unwrap();
    drop(p);
    let p = g.allocate(1).unwrap();
    p.commit();
    g.finish();
    let before = io.stats();
    assert_eq!(
        (
            before.rx_forwarding_recycled_total,
            before.rx_consumed_total,
            before.rx_tx_rejected_total,
            before.rx_lease_abandoned_total,
            before.generated_cancelled_total,
            before.generated_abandoned_total,
            before.generated_tx_rejected_total,
        ),
        (1, 1, 1, 1, 1, 1, 1)
    );
    while io.pop_recycled().is_some() {}
    while io.pop_generated_recycled().is_some() {}
    let after = io.stats();
    assert_eq!(
        (
            after.rx_forwarding_recycled_total,
            after.rx_consumed_total,
            after.rx_tx_rejected_total,
            after.rx_lease_abandoned_total,
            after.generated_cancelled_total,
            after.generated_abandoned_total,
            after.generated_tx_rejected_total,
        ),
        (
            before.rx_forwarding_recycled_total,
            before.rx_consumed_total,
            before.rx_tx_rejected_total,
            before.rx_lease_abandoned_total,
            before.generated_cancelled_total,
            before.generated_abandoned_total,
            before.generated_tx_rejected_total,
        )
    );
    assert_eq!(
        (
            after.injected_rx_total,
            after.accepted_tx_total,
            after.completed_tx_total,
            after.retired_rx_total,
        ),
        (
            before.injected_rx_total,
            before.accepted_tx_total,
            before.completed_tx_total,
            before.retired_rx_total,
        )
    );
    assert_eq!(
        (after.rx_queue_high_watermark, after.tx_queue_high_watermark),
        (
            before.rx_queue_high_watermark,
            before.tx_queue_high_watermark
        )
    );
    assert_eq!(after.pending_recycled, 0);
    assert_eq!(after.pending_generated_recycled, 0);
}

#[test]
// R15OBS-012
fn r15obs_012_retirement_is_bounded_and_only_retires_rx() {
    let mut io = SimIo::new();
    for _ in 0..3 {
        io.inject(IfId(1), vec![0]);
    }
    assert_eq!(io.retire_pending_rx(), Ok(3));
    assert_eq!(io.retire_pending_rx(), Ok(0));
    io.inject(IfId(1), vec![1]);
    assert_eq!(io.retire_pending_rx(), Ok(1));

    let mut forgotten_rx_batch = SimIo::new();
    forgotten_rx_batch.inject(IfId(1), vec![0]);
    let batch = forgotten_rx_batch.receive(1).unwrap();
    mem::forget(batch);
    let before = forgotten_rx_batch.stats();
    assert_eq!(
        forgotten_rx_batch.retire_pending_rx(),
        Err(ruster_io_sim::SimPendingRxRetirementError::RxBatchNotFinished)
    );
    assert_eq!(forgotten_rx_batch.stats(), before);

    let mut forgotten_generated_batch = SimIo::new();
    let batch = forgotten_generated_batch.begin_generated(IfId(2));
    mem::forget(batch);
    let before = forgotten_generated_batch.stats();
    assert_eq!(
        forgotten_generated_batch.retire_pending_rx(),
        Err(ruster_io_sim::SimPendingRxRetirementError::GeneratedBatchNotFinished)
    );
    assert_eq!(forgotten_generated_batch.stats(), before);

    let mut forgotten_rx_lease = SimIo::new();
    forgotten_rx_lease.inject(IfId(1), vec![0]);
    let mut batch = forgotten_rx_lease.receive(1).unwrap();
    let lease = batch.next_packet().unwrap();
    mem::forget(lease);
    batch.finish();
    let before = forgotten_rx_lease.stats();
    assert_eq!(
        forgotten_rx_lease.retire_pending_rx(),
        Err(ruster_io_sim::SimPendingRxRetirementError::RxLeaseNotCompleted)
    );
    assert_eq!(forgotten_rx_lease.stats(), before);

    let mut forgotten_generated_lease = SimIo::new();
    let mut batch = forgotten_generated_lease.begin_generated(IfId(2));
    let lease = batch.allocate(1).unwrap();
    mem::forget(lease);
    batch.finish();
    let before = forgotten_generated_lease.stats();
    assert_eq!(
        forgotten_generated_lease.retire_pending_rx(),
        Err(ruster_io_sim::SimPendingRxRetirementError::GeneratedLeaseNotCompleted)
    );
    assert_eq!(forgotten_generated_lease.stats(), before);

    let mut failure_atomic = SimIo::new();
    failure_atomic.inject(IfId(1), vec![1]);
    let mut batch = failure_atomic.receive(1).unwrap();
    let lease = batch.next_packet().unwrap();
    lease.commit(IfId(2));
    batch.finish();
    let mut generated = failure_atomic.begin_generated(IfId(2));
    let lease = generated.allocate(1).unwrap();
    lease.cancel();
    generated.finish();
    failure_atomic.inject(IfId(1), vec![9]);
    let mut batch = failure_atomic.receive(1).unwrap();
    let lease = batch.next_packet().unwrap();
    lease.recycle(DropReason::RouteMiss);
    batch.finish();
    let before = failure_atomic.stats();
    assert_eq!(before.pending_tx, 1);
    assert_eq!(before.pending_recycled, 1);
    assert_eq!(before.pending_generated_recycled, 1);
    failure_atomic.inject(IfId(1), vec![2]);
    let mut batch = failure_atomic.receive(1).unwrap();
    let lease = batch.next_packet().unwrap();
    mem::forget(lease);
    batch.finish();
    let before = failure_atomic.stats();
    assert_eq!(
        failure_atomic.retire_pending_rx(),
        Err(ruster_io_sim::SimPendingRxRetirementError::RxLeaseNotCompleted)
    );
    assert_eq!(failure_atomic.stats(), before);

    let mut empty = SimIo::new();
    assert_eq!(empty.retire_pending_rx(), Ok(0));
    empty.inject(IfId(1), vec![3]);
    assert_eq!(empty.retire_pending_rx(), Ok(1));
}

#[test]
// R15OBS-013
fn r15obs_013_quiescence_distinguishes_tx_and_leases() {
    let mut io = SimIo::new();
    io.inject(IfId(1), vec![1]);
    let mut batch = io.receive(1).unwrap();
    let lease = batch.next_packet().unwrap();
    lease.commit(IfId(2));
    batch.finish();
    assert_eq!(
        io.check_publication_quiescence(),
        Err(SimPublicationQuiescenceError::TxCompletionPending)
    );
    io.pop_tx();
    assert!(io.check_publication_quiescence().is_ok());

    let mut rx_only = SimIo::new();
    rx_only.inject(IfId(1), vec![1]);
    assert!(rx_only.check_publication_quiescence().is_ok());

    let mut pending_both = SimIo::new();
    pending_both.inject(IfId(1), vec![1]);
    pending_both.inject(IfId(1), vec![2]);
    let mut batch = pending_both.receive(1).unwrap();
    let lease = batch.next_packet().unwrap();
    lease.commit(IfId(2));
    batch.finish();
    let pending_tx_before = pending_both.stats().pending_tx;
    assert_eq!(pending_both.retire_pending_rx(), Ok(1));
    assert_eq!(pending_both.stats().pending_tx, pending_tx_before);
    assert_eq!(
        pending_both.check_publication_quiescence(),
        Err(SimPublicationQuiescenceError::TxCompletionPending)
    );

    let mut leaked_rx = SimIo::new();
    leaked_rx.inject(IfId(1), vec![1]);
    let mut batch = leaked_rx.receive(1).unwrap();
    let lease = batch.next_packet().unwrap();
    mem::forget(lease);
    batch.finish();
    let rx_error = leaked_rx.check_publication_quiescence().unwrap_err();
    assert_eq!(rx_error, SimPublicationQuiescenceError::RxLeaseNotCompleted);
    assert_eq!(
        <SimIo as PublicationQuiescenceBackend>::quiescence_error_disposition(&rx_error),
        ruster_core::PublicationQuiescenceDisposition::SkipIo
    );
    let mut leaked_generated = SimIo::new();
    let mut batch = leaked_generated.begin_generated(IfId(2));
    let lease = batch.allocate(1).unwrap();
    mem::forget(lease);
    batch.finish();
    let generated_error = leaked_generated.check_publication_quiescence().unwrap_err();
    assert_eq!(
        generated_error,
        SimPublicationQuiescenceError::GeneratedLeaseNotCompleted
    );
    assert_eq!(
        <SimIo as PublicationQuiescenceBackend>::quiescence_error_disposition(&generated_error),
        ruster_core::PublicationQuiescenceDisposition::SkipIo
    );
}

#[test]
// R15OBS-014
fn r15obs_014_bound_controls_preserve_identity_and_expose_only_operations() {
    let (owner, mut io) = bind_publication_backend(SimIo::new()).unwrap();
    assert!(owner.matches_backend(&io));
    BoundSimIoControl::inject(&mut io, IfId(1), vec![1]);
    assert_eq!(io.pending_rx(), 1);
    let _ = BoundSimIoObservabilityControl::stats(&io);
    assert_eq!(
        BoundSimIoObservabilityControl::retire_pending_rx(&mut io),
        Ok(1)
    );
    assert!(io.pop_tx().is_none());
    assert!(io.pop_recycled().is_none());
    assert_eq!(BoundSimIoObservabilityControl::stats(&io).pending_rx, 0);
    assert!(owner.matches_backend(&io));
    assert_eq!(
        <SimIo as PublicationQuiescenceBackend>::current_io_disposition(&SimIo::new()),
        ruster_core::PublicationQuiescenceDisposition::ContinueOldIo
    );
}

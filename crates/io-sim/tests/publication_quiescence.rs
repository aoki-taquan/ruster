use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    mem,
};

use ruster_core::{
    bind_publication_backend, BoundPublicationBackend, GeneratedPacketBatch, GeneratedPacketIo,
    IfId, PacketBatch, PacketIo, PublicationQuiescence, PublicationQuiescenceBackend,
    PublicationQuiescenceDisposition,
};
use ruster_io_sim::{BoundSimIoControl, SimIo, SimPublicationQuiescenceError};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
fn bound_wrapper_move_and_same_type_foreign_owner_are_exact() {
    let (owner_a, backend_a) =
        bind_publication_backend(SimIo::new()).expect("binding identity available");
    let (owner_b, backend_b) =
        bind_publication_backend(SimIo::new()).expect("binding identity available");
    let mut moved_a = backend_a;
    let mut moved_b = backend_b;

    assert!(owner_a.matches_backend(&moved_a));
    assert!(owner_b.matches_backend(&moved_b));
    assert!(!owner_a.matches_backend(&moved_b));
    assert!(!owner_b.matches_backend(&moved_a));

    let raw_a = moved_a
        .try_publication_quiescence()
        .expect("moved simulated backend is quiescent");
    let Ok(matched_a) = owner_a.match_quiescence_guard(raw_a) else {
        panic!("wrapper move must preserve its private identity");
    };
    drop(matched_a);

    let raw_b = moved_b
        .try_publication_quiescence()
        .expect("foreign simulated backend is quiescent");
    let raw_b = match owner_a.match_quiescence_guard(raw_b) {
        Ok(_) => panic!("same-type foreign owner must not authorize the guard"),
        Err(raw_b) => raw_b,
    };
    let Ok(matched_b) = owner_b.match_quiescence_guard(raw_b) else {
        panic!("mismatch must return the original raw guard");
    };
    drop(matched_b);
}

#[test]
fn private_wrapper_identity_does_not_enter_inner_debug() {
    let (_owner_a, backend_a) =
        bind_publication_backend(SimIo::new()).expect("binding identity available");
    let (_owner_b, backend_b) =
        bind_publication_backend(SimIo::new()).expect("binding identity available");

    assert_eq!(
        format!("{:?}", backend_a.inner()),
        format!("{:?}", backend_b.inner())
    );
}

#[test]
fn standalone_backend_keeps_packet_io_and_quiescence_hooks() {
    let mut io = SimIo::new();
    let batch = io.receive(0).expect("standalone receive remains available");
    assert!(batch.finish().invariants_hold());
    assert_eq!(
        io.check_publication_quiescence(),
        Ok(()),
        "standalone backend exposes only the inner quiescence hook"
    );
}

#[test]
fn bound_wrapper_delegates_received_and_generated_packet_io() {
    let mut inner = SimIo::new();
    inner.inject(IfId(7), vec![0; 64]);
    let (_owner, mut io) = bind_publication_backend(inner).expect("binding identity available");

    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    assert_eq!(
        <BoundPublicationBackend<SimIo> as PublicationQuiescence>::quiescence_error_disposition(
            &SimPublicationQuiescenceError::TxCompletionPending,
        ),
        PublicationQuiescenceDisposition::ContinueOldIo
    );

    let mut rx = io.receive(1).expect("wrapper delegates receive");
    let lease = rx.next_packet().expect("one injected frame");
    lease.commit(IfId(8));
    let completion = rx.finish();
    assert!(completion.invariants_hold());
    assert_eq!(completion.tx_accepted, 1);
    assert_eq!(io.pending_tx(), 1);
    let transmitted = io
        .pop_tx()
        .expect("typed simulator control completes accepted TX");
    assert_eq!(transmitted.egress, IfId(8));

    let mut generated = io.begin_generated(IfId(9));
    let lease = generated
        .allocate(64)
        .expect("wrapper delegates allocation");
    lease.cancel();
    let completion = generated.finish();
    assert!(completion.invariants_hold());
    assert_eq!(completion.cancelled, 1);
}

#[test]
fn typed_bound_control_cannot_hide_pending_tx_from_quiescence() {
    let (owner, mut io) =
        bind_publication_backend(SimIo::new()).expect("binding identity available");
    let sequence = io.inject(IfId(1), vec![0; 64]);
    let mut batch = io.receive(1).expect("infallible simulated RX");
    let lease = batch.next_packet().expect("one injected frame");
    lease.commit(IfId(2));
    assert_eq!(batch.finish().tx_accepted, 1);

    assert!(matches!(
        io.try_publication_quiescence(),
        Err(SimPublicationQuiescenceError::TxCompletionPending)
    ));
    assert!(owner.matches_backend(&io));
    let transmitted = io.pop_tx().expect("typed control completes accepted TX");
    assert_eq!(transmitted.sequence, sequence);
    assert_eq!(transmitted.egress, IfId(2));
    assert!(owner.matches_backend(&io));

    let raw = io
        .try_publication_quiescence()
        .expect("completed backend is quiescent");
    let Ok(matched) = owner.match_quiescence_guard(raw) else {
        panic!("typed control must preserve the paired wrapper identity");
    };
    drop(matched);
}

#[test]
fn binding_wrapper_guard_match_and_standalone_constructor_allocate_nothing() {
    reset_allocation_counts();
    let binding = bind_publication_backend(SimIo::new());
    let binding_counts = allocation_counts();
    assert_eq!(binding_counts, AllocationCounts::default());
    let (owner, mut io) = binding.expect("binding identity available");

    reset_allocation_counts();
    assert!(owner.matches_backend(&io));
    let precheck_counts = allocation_counts();
    assert_eq!(precheck_counts, AllocationCounts::default());

    reset_allocation_counts();
    assert_eq!((io.pending_rx(), io.pending_tx()), (0, 0));
    assert!(io.pop_tx().is_none());
    assert!(io.pop_recycled().is_none());
    let control_counts = allocation_counts();
    assert_eq!(control_counts, AllocationCounts::default());

    reset_allocation_counts();
    let raw = io
        .try_publication_quiescence()
        .expect("new bound backend is quiescent");
    let guard_counts = allocation_counts();
    assert_eq!(guard_counts, AllocationCounts::default());

    reset_allocation_counts();
    let Ok(matched) = owner.match_quiescence_guard(raw) else {
        panic!("paired owner must authorize its guard");
    };
    let match_counts = allocation_counts();
    assert_eq!(match_counts, AllocationCounts::default());
    drop(matched);

    reset_allocation_counts();
    let standalone_io = SimIo::new();
    let standalone_counts = allocation_counts();
    assert_eq!(standalone_counts, AllocationCounts::default());
    drop(standalone_io);
}

#[test]
fn forgotten_rx_batch_is_a_sticky_typed_quiescence_failure() {
    let mut io = SimIo::new();
    let batch = io.receive(0).unwrap();
    mem::forget(batch);

    assert!(matches!(
        io.check_publication_quiescence(),
        Err(SimPublicationQuiescenceError::RxBatchNotFinished)
    ));
}

#[test]
fn forgotten_generated_batch_is_a_sticky_typed_quiescence_failure() {
    let mut io = SimIo::new();
    let batch = io.begin_generated(IfId(1));
    mem::forget(batch);

    assert!(matches!(
        io.check_publication_quiescence(),
        Err(SimPublicationQuiescenceError::GeneratedBatchNotFinished)
    ));
}

#[test]
fn forgotten_rx_lease_stays_busy_after_batch_finish() {
    let mut io = SimIo::new();
    io.inject(IfId(1), vec![0; 64]);
    let mut batch = io.receive(1).unwrap();
    let lease = batch.next_packet().expect("one injected frame");
    mem::forget(lease);
    let completion = batch.finish();
    assert!(completion.invariants_hold());

    assert!(matches!(
        io.check_publication_quiescence(),
        Err(SimPublicationQuiescenceError::RxLeaseNotCompleted)
    ));
}

#[test]
fn forgotten_generated_lease_stays_busy_after_invalid_finish_accounting() {
    let mut io = SimIo::new();
    let mut batch = io.begin_generated(IfId(1));
    let lease = batch.allocate(64).expect("one generated frame");
    mem::forget(lease);
    let completion = batch.finish();
    assert!(!completion.invariants_hold());

    assert!(matches!(
        io.check_publication_quiescence(),
        Err(SimPublicationQuiescenceError::GeneratedLeaseNotCompleted)
    ));
}

#[test]
fn accepted_tx_requires_explicit_completion_before_publication() {
    let mut io = SimIo::new();
    io.inject(IfId(1), vec![0; 64]);
    let mut batch = io.receive(1).unwrap();
    let lease = batch.next_packet().expect("one injected frame");
    lease.commit(IfId(2));
    let completion = batch.finish();
    assert_eq!(completion.tx_accepted, 1);

    assert!(matches!(
        io.check_publication_quiescence(),
        Err(SimPublicationQuiescenceError::TxCompletionPending)
    ));
    assert_eq!(io.pending_tx(), 1);
    let completed = io.pop_tx().expect("accepted TX completion");
    assert_eq!(completed.egress, IfId(2));

    let (owner, mut io) =
        bind_publication_backend(io).expect("binding identity available after completion");
    let raw = io
        .try_publication_quiescence()
        .expect("completed backend must be quiescent");
    let Ok(matched) = owner.match_quiescence_guard(raw) else {
        panic!("paired owner must authorize the completed backend");
    };
    drop(matched);
}

#[test]
fn ordinary_batch_drop_releases_quiescence_without_scalar_proof() {
    let mut io = SimIo::new();
    let rx = io.receive(0).unwrap();
    drop(rx);
    let generated = io.begin_generated(IfId(1));
    drop(generated);

    let (owner, mut io) =
        bind_publication_backend(io).expect("binding identity available after batch drops");
    let raw = io
        .try_publication_quiescence()
        .expect("no batch or accepted TX remains");
    let Ok(matched) = owner.match_quiescence_guard(raw) else {
        panic!("paired owner must authorize the released backend");
    };
    drop(matched);
}

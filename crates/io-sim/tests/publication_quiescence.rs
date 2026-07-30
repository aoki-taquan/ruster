use std::mem;

use ruster_core::{
    GeneratedPacketBatch, GeneratedPacketIo, IfId, PacketBatch, PacketIo, PublicationQuiescence,
};
use ruster_io_sim::{SimIo, SimPublicationQuiescenceError};

#[test]
fn forgotten_rx_batch_is_a_sticky_typed_quiescence_failure() {
    let mut io = SimIo::new();
    let batch = io.receive(0).unwrap();
    mem::forget(batch);

    assert!(matches!(
        io.try_publication_quiescence(),
        Err(SimPublicationQuiescenceError::RxBatchNotFinished)
    ));
}

#[test]
fn forgotten_generated_batch_is_a_sticky_typed_quiescence_failure() {
    let mut io = SimIo::new();
    let batch = io.begin_generated(IfId(1));
    mem::forget(batch);

    assert!(matches!(
        io.try_publication_quiescence(),
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
        io.try_publication_quiescence(),
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
        io.try_publication_quiescence(),
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
        io.try_publication_quiescence(),
        Err(SimPublicationQuiescenceError::TxCompletionPending)
    ));
    assert_eq!(io.pending_tx(), 1);
    let completed = io.pop_tx().expect("accepted TX completion");
    assert_eq!(completed.egress, IfId(2));

    let Ok(guard) = io.try_publication_quiescence() else {
        panic!("completed backend must be quiescent");
    };
    drop(guard);
}

#[test]
fn ordinary_batch_drop_releases_quiescence_without_scalar_proof() {
    let mut io = SimIo::new();
    let rx = io.receive(0).unwrap();
    drop(rx);
    let generated = io.begin_generated(IfId(1));
    drop(generated);

    let Ok(guard) = io.try_publication_quiescence() else {
        panic!("no batch or accepted TX remains");
    };
    drop(guard);
}

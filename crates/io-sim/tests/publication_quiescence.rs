use std::mem;

use ruster_core::{GeneratedPacketIo, IfId, PacketBatch, PacketIo, PublicationQuiescence};
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

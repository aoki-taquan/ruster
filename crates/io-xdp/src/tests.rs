use crate::{DescriptorError, FrameLedger, FrameStateKind, LayoutError, RawDescriptor, UmemLayout};

fn descriptor(layout: UmemLayout, frame: u32, offset: u32, len: u32) -> crate::ValidatedDescriptor {
    layout
        .validate_descriptor(RawDescriptor {
            addr: u64::from(frame) * u64::from(layout.frame_size()) + u64::from(offset),
            len,
            options: 0,
        })
        .expect("valid descriptor")
}

#[test]
fn layout_canonicalizes_frame_and_rejects_invalid_descriptors() {
    let layout = UmemLayout::new(4, 2_048, 256).expect("layout");
    let checked = descriptor(layout, 2, 300, 1_500);
    assert_eq!(checked.frame(), layout.frame_id(2).expect("frame"));
    assert_eq!(checked.frame_base(), 4_096);
    assert_eq!(checked.data_offset(), 300);
    assert_eq!(checked.len(), 1_500);
    assert!(!checked.is_empty());
    assert_eq!(layout.byte_len(), 8_192);

    assert_eq!(
        UmemLayout::new(0, 2_048, 0),
        Err(LayoutError::ZeroFrameCount)
    );
    assert_eq!(
        UmemLayout::new(1, 3_000, 0),
        Err(LayoutError::FrameSizeNotPowerOfTwo)
    );
    assert_eq!(
        UmemLayout::new(1, 2_048, 2_048),
        Err(LayoutError::HeadroomConsumesFrame)
    );
    assert_eq!(layout.frame_id(4), Err(LayoutError::FrameIndexOutsideUmem));
    assert_eq!(
        layout.validate_descriptor(RawDescriptor {
            addr: 8_192,
            len: 1,
            options: 0,
        }),
        Err(DescriptorError::AddressOutsideUmem)
    );
    assert_eq!(
        layout.validate_descriptor(RawDescriptor {
            addr: 100,
            len: 1,
            options: 0,
        }),
        Err(DescriptorError::DataBeforeHeadroom)
    );
    assert_eq!(
        layout.validate_descriptor(RawDescriptor {
            addr: 256,
            len: 0,
            options: 0,
        }),
        Err(DescriptorError::EmptyPacket)
    );
    assert_eq!(
        layout.validate_descriptor(RawDescriptor {
            addr: 256,
            len: 1,
            options: 1,
        }),
        Err(DescriptorError::UnsupportedOptions(1))
    );
    assert_eq!(
        layout.validate_descriptor(RawDescriptor {
            addr: 2_000,
            len: 49,
            options: 0,
        }),
        Err(DescriptorError::CrossesFrameBoundary)
    );
    assert_eq!(
        layout.validate_descriptor(RawDescriptor {
            addr: u64::MAX - 1,
            len: 4,
            options: 0,
        }),
        Err(DescriptorError::AddressOutsideUmem)
    );
}

#[test]
fn same_frame_new_cycle_increments_generation_without_wrap() {
    let mut ledger = FrameLedger::new(1).expect("ledger");
    let first = ledger.lease_generated(0).expect("first lease");
    assert_eq!(first.generation().get(), 1);
    ledger.recycle_lease(first).expect("recycle");

    let second = ledger.reserve_fill(0).expect("second cycle");
    assert_eq!(second.frame(), first.frame());
    assert_eq!(second.generation().get(), 2);
    assert_ne!(first, second);
}

#[test]
fn generation_exhaustion_quarantines_instead_of_wrapping() {
    let mut ledger = FrameLedger::new(1).expect("ledger");
    ledger.set_free_generation_for_test(0, u64::MAX);
    let error = ledger
        .lease_generated(0)
        .expect_err("must not wrap generation");
    assert!(matches!(
        error,
        crate::LedgerError::GenerationExhausted { frame } if frame.index() == 0
    ));
    assert_eq!(
        ledger.state(0).expect("state").kind(),
        FrameStateKind::Quarantined
    );
    assert_eq!(ledger.counts().get(FrameStateKind::Free), 0);
    assert_eq!(ledger.counts().get(FrameStateKind::Quarantined), 1);
    ledger.deep_audit().expect("quarantine remains consistent");
}

#[test]
fn every_transition_preserves_total_frame_partition() {
    let layout = UmemLayout::new(3, 2_048, 256).expect("layout");
    let mut ledger = FrameLedger::new(3).expect("ledger");
    assert_partition(&ledger);

    let rx = ledger.reserve_fill(0).expect("fill reserve");
    assert_state_and_partition(&ledger, 0, FrameStateKind::FillReserved);
    ledger.publish_fill(rx).expect("fill publish");
    assert_state_and_partition(&ledger, 0, FrameStateKind::FillOwnedByKernel);
    ledger
        .receive(rx, descriptor(layout, 0, 256, 64))
        .expect("receive");
    assert_state_and_partition(&ledger, 0, FrameStateKind::RxAvailable);
    assert_eq!(
        ledger.lease_rx(rx).expect("RX lease"),
        descriptor(layout, 0, 256, 64)
    );
    assert_state_and_partition(&ledger, 0, FrameStateKind::Leased);
    ledger.stage_tx(rx).expect("stage");
    assert_state_and_partition(&ledger, 0, FrameStateKind::PendingTx);
    ledger.reserve_tx(rx).expect("TX reserve");
    assert_state_and_partition(&ledger, 0, FrameStateKind::TxReserved);
    ledger.publish_tx(rx).expect("TX publish");
    assert_state_and_partition(&ledger, 0, FrameStateKind::TxOwnedByKernel);
    ledger.complete_tx(rx).expect("completion");
    assert_state_and_partition(&ledger, 0, FrameStateKind::CompletionAvailable);
    ledger.recycle_completion(rx).expect("completion recycle");
    assert_state_and_partition(&ledger, 0, FrameStateKind::Free);

    let generated = ledger.lease_generated(1).expect("generated lease");
    assert_state_and_partition(&ledger, 1, FrameStateKind::Leased);
    ledger.stage_tx(generated).expect("stage generated");
    ledger.cancel_pending_tx(generated).expect("cancel pending");
    assert_state_and_partition(&ledger, 1, FrameStateKind::Leased);
    ledger.stage_tx(generated).expect("restage generated");
    ledger.reserve_tx(generated).expect("reserve generated");
    ledger
        .cancel_tx_reservation(generated)
        .expect("cancel reservation");
    assert_state_and_partition(&ledger, 1, FrameStateKind::PendingTx);
    ledger
        .cancel_pending_tx(generated)
        .expect("cancel pending again");
    ledger.recycle_lease(generated).expect("recycle generated");
    assert_state_and_partition(&ledger, 1, FrameStateKind::Free);

    let cancelled_fill = ledger.reserve_fill(2).expect("fill reserve");
    ledger.cancel_fill(cancelled_fill).expect("cancel fill");
    assert_state_and_partition(&ledger, 2, FrameStateKind::Free);
}

#[test]
fn stale_tokens_and_descriptor_aliases_never_mutate_the_ledger() {
    let layout = UmemLayout::new(2, 2_048, 256).expect("layout");
    let mut ledger = FrameLedger::new(2).expect("ledger");
    let stale = ledger.lease_generated(0).expect("old cycle");
    ledger.recycle_lease(stale).expect("old recycle");
    let current = ledger.reserve_fill(0).expect("current cycle");

    let state_before = ledger.state(0).expect("state");
    let counts_before = ledger.counts();
    assert!(matches!(
        ledger.stage_tx(stale),
        Err(crate::LedgerError::StaleToken { .. })
    ));
    assert_eq!(ledger.state(0).expect("state"), state_before);
    assert_eq!(ledger.counts(), counts_before);

    ledger.publish_fill(current).expect("publish");
    let state_before_alias = ledger.state(0).expect("state");
    let counts_before_alias = ledger.counts();
    assert!(matches!(
        ledger.receive(current, descriptor(layout, 1, 256, 64)),
        Err(crate::LedgerError::DescriptorFrameAlias { .. })
    ));
    assert_eq!(ledger.state(0).expect("state"), state_before_alias);
    assert_eq!(ledger.counts(), counts_before_alias);
    ledger.deep_audit().expect("rejections preserved ledger");
}

fn assert_state_and_partition(ledger: &FrameLedger, frame: u32, state: FrameStateKind) {
    assert_eq!(ledger.state(frame).expect("frame").kind(), state);
    assert_partition(ledger);
}

fn assert_partition(ledger: &FrameLedger) {
    assert_eq!(ledger.counts().total(), ledger.frame_count());
    ledger.deep_audit().expect("deep audit");
}

use std::{
    hash::{Hash, Hasher},
    marker::PhantomData,
    num::NonZeroU128,
};

use crate::{
    DescriptorError, FrameLedger, FrameStateKind, LayoutError, RawDescriptor, UmemDomainId,
    UmemLayout,
};

fn domain(value: u128) -> UmemDomainId {
    UmemDomainId::new(NonZeroU128::new(value).expect("nonzero test domain"))
}

fn layout(domain_value: u128, frames: u32, frame_size: u32, headroom: u32) -> UmemLayout {
    UmemLayout::new(domain(domain_value), frames, frame_size, headroom).expect("layout")
}

fn ledger(domain_value: u128, frames: u32) -> FrameLedger {
    FrameLedger::new(layout(domain_value, frames, 2_048, 256)).expect("ledger")
}

fn descriptor(
    layout: &UmemLayout,
    frame: u32,
    offset: u32,
    len: u32,
) -> crate::ValidatedDescriptor {
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
    let layout = layout(1, 4, 2_048, 256);
    let checked = descriptor(&layout, 2, 300, 1_500);
    assert_eq!(checked.frame(), layout.frame_id(2).expect("frame"));
    assert_eq!(checked.frame_base(), 4_096);
    assert_eq!(checked.data_offset(), 300);
    assert_eq!(checked.len(), 1_500);
    assert!(!checked.is_empty());
    assert_eq!(layout.byte_len(), 8_192);

    assert_eq!(
        UmemLayout::new(domain(2), 0, 2_048, 0),
        Err(LayoutError::ZeroFrameCount)
    );
    assert_eq!(
        UmemLayout::new(domain(3), 1, 3_000, 0),
        Err(LayoutError::FrameSizeNotPowerOfTwo)
    );
    assert_eq!(
        UmemLayout::new(domain(4), 1, 2_048, 2_048),
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
    let mut ledger = ledger(5, 1);
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
    let mut ledger = ledger(6, 1);
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
    let mut ledger = ledger(7, 3);
    assert_partition(&ledger);

    let rx = ledger.reserve_fill(0).expect("fill reserve");
    assert_state_and_partition(&ledger, 0, FrameStateKind::FillReserved);
    ledger.publish_fill(rx).expect("fill publish");
    assert_state_and_partition(&ledger, 0, FrameStateKind::FillOwnedByKernel);
    let rx_descriptor = descriptor(ledger.layout(), 0, 256, 64);
    ledger.receive(rx, rx_descriptor).expect("receive");
    assert_state_and_partition(&ledger, 0, FrameStateKind::RxAvailable);
    assert_eq!(ledger.lease_rx(rx).expect("RX lease"), rx_descriptor);
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
    let mut ledger = ledger(8, 2);
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
    let alias = descriptor(ledger.layout(), 1, 256, 64);
    assert!(matches!(
        ledger.receive(current, alias),
        Err(crate::LedgerError::DescriptorFrameAlias { .. })
    ));
    assert_eq!(ledger.state(0).expect("state"), state_before_alias);
    assert_eq!(ledger.counts(), counts_before_alias);
    ledger.deep_audit().expect("rejections preserved ledger");
}

#[test]
fn foreign_ledger_token_is_rejected_without_mutation() {
    let mut first = ledger(9, 1);
    let mut second = ledger(10, 1);
    let own = first.reserve_fill(0).expect("first token");
    let foreign = second.reserve_fill(0).expect("second token");
    assert_eq!(own.frame(), foreign.frame());
    assert_eq!(own.generation(), foreign.generation());
    assert_ne!(own, foreign);

    let state_before = first.state(0).expect("state");
    let counts_before = first.counts();
    assert_eq!(
        first.publish_fill(foreign),
        Err(crate::LedgerError::ForeignTokenDomain)
    );
    assert_eq!(first.state(0).expect("state"), state_before);
    assert_eq!(first.counts(), counts_before);

    first.publish_fill(own).expect("same-domain token");
    first.deep_audit().expect("ledger remains consistent");
}

#[test]
fn foreign_umem_descriptor_is_rejected_without_mutation() {
    let mut ledger = ledger(11, 2);
    let foreign_layout = layout(12, 2, 4_096, 512);
    let token = ledger.reserve_fill(0).expect("token");
    ledger.publish_fill(token).expect("publish");
    let foreign = descriptor(&foreign_layout, 0, 512, 64);

    let state_before = ledger.state(0).expect("state");
    let counts_before = ledger.counts();
    assert_eq!(
        ledger.receive(token, foreign),
        Err(crate::LedgerError::ForeignDescriptorDomain)
    );
    assert_eq!(ledger.state(0).expect("state"), state_before);
    assert_eq!(ledger.counts(), counts_before);

    let own = descriptor(ledger.layout(), 0, 256, 64);
    ledger.receive(token, own).expect("same-domain descriptor");
    ledger.deep_audit().expect("ledger remains consistent");
}

#[test]
fn new_domain_prevents_token_aba_across_ledger_recreation() {
    let old = {
        let mut old_ledger = ledger(13, 1);
        old_ledger.reserve_fill(0).expect("old token")
    };
    let mut replacement = ledger(14, 1);
    let current = replacement.reserve_fill(0).expect("replacement token");
    assert_eq!(old.frame(), current.frame());
    assert_eq!(old.generation(), current.generation());
    assert_ne!(old, current);

    let state_before = replacement.state(0).expect("state");
    let counts_before = replacement.counts();
    assert_eq!(
        replacement.publish_fill(old),
        Err(crate::LedgerError::ForeignTokenDomain)
    );
    assert_eq!(replacement.state(0).expect("state"), state_before);
    assert_eq!(replacement.counts(), counts_before);
    replacement
        .publish_fill(current)
        .expect("new domain token remains valid");
    replacement
        .deep_audit()
        .expect("foreign rejection preserved replacement");
}

#[test]
fn domain_identity_is_redacted_from_debug_output() {
    let unique = NonZeroU128::new(12_345_678_901_234_567_890).expect("nonzero");
    let rendered = format!("{:?}", UmemDomainId::new(unique));
    assert_eq!(rendered, "UmemDomainId(<redacted>)");

    let layout_unique = 23_456_789_012_345_678_901;
    let layout = layout(layout_unique, 1, 2_048, 256);
    let checked = descriptor(&layout, 0, 256, 64);
    let rendered = format!("{layout:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(&layout_unique.to_string()));
    let rendered = format!("{checked:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(&layout_unique.to_string()));

    let mut ledger = FrameLedger::new(layout).expect("ledger");
    let token = ledger.reserve_fill(0).expect("token");
    let rendered = format!("{token:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(&layout_unique.to_string()));
    let rendered = format!("{ledger:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(&layout_unique.to_string()));
}

#[test]
fn frame_token_has_no_hash_domain_extraction_surface() {
    struct TraitProbe<T: ?Sized>(PhantomData<T>);
    trait AmbiguousIfHash<Marker> {
        fn probe() {}
    }
    impl<T: ?Sized> AmbiguousIfHash<()> for TraitProbe<T> {}
    impl<T: ?Sized + Hash> AmbiguousIfHash<u8> for TraitProbe<T> {}

    let _ = <TraitProbe<crate::FrameToken> as AmbiguousIfHash<_>>::probe;
    let _ = <TraitProbe<crate::domain::DomainIdentity> as AmbiguousIfHash<_>>::probe;

    #[derive(Default)]
    struct ExtractU128 {
        extracted: Option<u128>,
    }

    impl Hasher for ExtractU128 {
        fn finish(&self) -> u64 {
            0
        }

        fn write(&mut self, _bytes: &[u8]) {}

        fn write_u128(&mut self, value: u128) {
            self.extracted = Some(value);
        }
    }

    let mut ledger = ledger(16, 1);
    let token = ledger.reserve_fill(0).expect("token");
    let mut extractor = ExtractU128::default();
    token.frame().hash(&mut extractor);
    token.generation().hash(&mut extractor);
    assert_eq!(extractor.extracted, None);
}

#[test]
fn frame_ledger_is_not_send_or_sync() {
    struct TraitProbe<T: ?Sized>(PhantomData<T>);
    trait AmbiguousIfSend<Marker> {
        fn probe() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for TraitProbe<T> {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for TraitProbe<T> {}

    trait AmbiguousIfSync<Marker> {
        fn probe() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for TraitProbe<T> {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for TraitProbe<T> {}

    let _ = <TraitProbe<FrameLedger> as AmbiguousIfSend<_>>::probe;
    let _ = <TraitProbe<FrameLedger> as AmbiguousIfSync<_>>::probe;
}

fn assert_state_and_partition(ledger: &FrameLedger, frame: u32, state: FrameStateKind) {
    assert_eq!(ledger.state(frame).expect("frame").kind(), state);
    assert_partition(ledger);
}

fn assert_partition(ledger: &FrameLedger) {
    assert_eq!(ledger.counts().total(), ledger.frame_count());
    ledger.deep_audit().expect("deep audit");
}

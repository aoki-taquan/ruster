use std::{convert::Infallible, num::NonZeroU64};

use ruster_config::{parse, validate, ValidatedConfig, ValidationLimits};
use ruster_control::{plan_full_service_v1, FullServiceCandidateV1, FullServicePlanInputs};
use ruster_core::{
    bind_publication_backend, FirewallHashKey, IfId, Nat44TcpHashKey, Nat44UdpHashKey, PacketBatch,
    PacketIo, PublicationBackendAuthority, PublicationQuiescenceBackend,
    PublicationQuiescenceDisposition,
};
use ruster_integration::{
    activate_initial, FullServicePublicationOwner, FullServiceRuntimeStorage,
    InitialBackendBindError,
};
use ruster_io_sim::{BoundSimIoControl, SimIo, SimPublicationQuiescenceError};

const FULL_SERVICE: &str = include_str!("full-service.toml");
const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);

fn candidate() -> FullServiceCandidateV1 {
    let parsed = parse(FULL_SERVICE.as_bytes()).expect("syntax fixture");
    let config = match validate(
        parsed,
        ValidationLimits {
            max_slots_per_table: 1_048_576,
            max_runtime_bytes: 1 << 30,
        },
    )
    .expect("semantic fixture")
    {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("fixture selects schema V1"),
    };
    let inputs = FullServicePlanInputs::new(
        NonZeroU64::new(1).unwrap(),
        Nat44UdpHashKey::new(11, 12).unwrap(),
        Nat44TcpHashKey::new(13, 14).unwrap(),
        FirewallHashKey::new(15, 16).unwrap(),
    );
    let plan = match plan_full_service_v1(config, inputs) {
        Ok(plan) => plan,
        Err(failure) => panic!("fixture must plan: {:?}", failure.error()),
    };
    plan.into_candidate().expect("fixture must mint candidate")
}

fn activated<'storage>(
    storage: &'storage mut FullServiceRuntimeStorage,
    candidate: FullServiceCandidateV1,
) -> FullServicePublicationOwner<'storage> {
    match activate_initial(storage, candidate) {
        Ok(owner) => owner,
        Err(failure) => panic!("fixture must activate: {:?}", failure.error()),
    }
}

fn queue_accepted_tx(io: &mut SimIo) {
    io.inject(LAN, vec![0_u8; 64]);
    let mut batch = io.receive(1).expect("Sim RX is infallible");
    let lease = batch.next_packet().expect("injected frame");
    lease.commit(WAN);
    let completion = batch.finish();
    assert_eq!(completion.tx_accepted, 1);
    assert!(completion.invariants_hold());
}

#[test]
fn initial_bind_rejects_preexisting_tx_and_preserves_retry_capabilities() {
    let candidate = candidate();
    let generation = candidate.generation();
    let shape = candidate.storage_shape();
    let required_bytes = candidate.required_runtime_bytes();
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&candidate).expect("small fixed storage");
    let owner = activated(&mut storage, candidate);
    let interface_pointer = owner.interfaces().as_ptr();

    let mut raw_io = SimIo::new();
    queue_accepted_tx(&mut raw_io);
    let (owner_binding, mut io) =
        bind_publication_backend(raw_io).expect("binding identity remains available");

    let failure = match owner.bind_backend(owner_binding, &mut io) {
        Ok(_) => panic!("pending pre-binding TX must not cross initial authority"),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.error(),
        &InitialBackendBindError::Quiescence(SimPublicationQuiescenceError::TxCompletionPending,)
    );
    let (owner, owner_binding, error) = failure.into_parts();
    assert_eq!(
        error,
        InitialBackendBindError::Quiescence(SimPublicationQuiescenceError::TxCompletionPending,)
    );
    assert_eq!(owner.generation(), generation);
    assert_eq!(owner.storage_shape(), shape);
    assert_eq!(owner.required_runtime_bytes(), required_bytes);
    assert_eq!(owner.interfaces().as_ptr(), interface_pointer);

    assert!(io.pop_tx().is_some(), "caller resolves the transient TX");
    assert!(io.pop_tx().is_none());
    let owner = match owner.bind_backend(owner_binding, &mut io) {
        Ok(owner) => owner,
        Err(_) => panic!("the exact preserved owner and binding must retry"),
    };
    assert_eq!(owner.generation(), generation);
    assert_eq!(owner.interfaces().as_ptr(), interface_pointer);
}

#[test]
fn initial_bind_rejects_foreign_backend_before_quiescence_and_recovers() {
    let candidate = candidate();
    let generation = candidate.generation();
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&candidate).expect("small fixed storage");
    let owner = activated(&mut storage, candidate);

    let (owner_binding, mut paired_io) = bind_publication_backend(DispositionBackend {
        disposition: PublicationQuiescenceDisposition::ContinueOldIo,
        quiescence_checks: 0,
    })
    .expect("binding identity remains available");
    let (_foreign_binding, mut foreign_io) = bind_publication_backend(DispositionBackend {
        disposition: PublicationQuiescenceDisposition::ContinueOldIo,
        quiescence_checks: 0,
    })
    .expect("binding identity remains available");

    let failure = match owner.bind_backend(owner_binding, &mut foreign_io) {
        Ok(_) => panic!("same-typed foreign backend must not bind"),
        Err(failure) => failure,
    };
    assert_eq!(failure.error(), &InitialBackendBindError::BackendMismatch);
    assert_eq!(
        foreign_io.inner().quiescence_checks,
        0,
        "identity mismatch must precede the quiescence hook"
    );

    let (owner, owner_binding, error) = failure.into_parts();
    assert_eq!(error, InitialBackendBindError::BackendMismatch);
    let owner = match owner.bind_backend(owner_binding, &mut paired_io) {
        Ok(owner) => owner,
        Err(_) => panic!("preserved capability must still bind its paired backend"),
    };
    assert_eq!(paired_io.inner().quiescence_checks, 1);
    assert_eq!(owner.generation(), generation);
}

struct DispositionBackend {
    disposition: PublicationQuiescenceDisposition,
    quiescence_checks: usize,
}

// SAFETY: this fixture implements no packet or generated-batch traits, and its
// only associated output is `Infallible`; no operation can detach or alias it.
unsafe impl PublicationBackendAuthority for DispositionBackend {}

impl PublicationQuiescenceBackend for DispositionBackend {
    type Error = Infallible;

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
        self.quiescence_checks += 1;
        Ok(())
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        self.disposition
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        match *error {}
    }
}

#[test]
fn initial_bind_rejects_terminal_backend_after_matched_quiescence() {
    let candidate = candidate();
    let generation = candidate.generation();
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&candidate).expect("small fixed storage");
    let owner = activated(&mut storage, candidate);
    let (owner_binding, mut backend) = bind_publication_backend(DispositionBackend {
        disposition: PublicationQuiescenceDisposition::Stop,
        quiescence_checks: 0,
    })
    .expect("binding identity remains available");

    let failure = match owner.bind_backend(owner_binding, &mut backend) {
        Ok(_) => panic!("terminal backend must not become initial authority"),
        Err(failure) => failure,
    };
    assert_eq!(backend.inner().quiescence_checks, 1);
    assert_eq!(
        failure.error(),
        &InitialBackendBindError::IoDisposition(PublicationQuiescenceDisposition::Stop)
    );
    let (owner, _owner_binding, error) = failure.into_parts();
    assert_eq!(owner.generation(), generation);
    assert_eq!(
        error,
        InitialBackendBindError::IoDisposition(PublicationQuiescenceDisposition::Stop)
    );
}

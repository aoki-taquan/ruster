#![deny(unsafe_code)]
//! Safe cold activation and external fixed runtime storage for ruster.
//!
//! This crate is the one-way integration layer above `ruster-control`,
//! `ruster-core`, and `ruster-runtime`. It allocates no storage during activation
//! and adds no dependency from those lower layers back to integration.

mod publication;
mod storage;

pub use publication::{
    activate_initial, BoundFullServicePublicationOwner, FullServiceApplyReport,
    FullServicePublicationOwner, FullServicePublishError, FullServiceRestartRequired,
    InitialActivationError, InitialActivationFailure, InitialBackendBindError,
    InitialBackendBindFailure, UnboundPublicationOwner,
};
pub use storage::{FullServiceRuntimeStorage, RuntimeStorageAllocationError};

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, num::NonZeroU64};

    use ruster_config::{parse, validate, TickBudgetsV1, ValidatedConfig, ValidationLimits};
    use ruster_control::{
        plan_full_service_v1, FullServiceCandidateV1, FullServicePlanInputs,
        FullServiceStorageShape, SuccessorError,
    };
    use ruster_core::{
        bind_publication_backend, internet_checksum, ipv4_header_checksum, BoundPublicationBackend,
        FirewallHashKey, GeneratedArpTrace, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
        GeneratedPacketBatch, GeneratedPacketIo, GeneratedTraceSink, IfId, Ipv4Address,
        MonotonicMillis, Nat44TcpHashKey, Nat44TcpRuntimeConfigError, Nat44UdpHashKey,
        Nat44UdpRuntimeConfigError, PublicationBackendAuthority, PublicationQuiescence,
        PublicationQuiescenceBackend, PublicationQuiescenceDisposition, ResolutionFailureTrace,
        ResolutionFailureTraceSink, ResolutionTimerTrace, ResolutionTimerTraceSink, TraceEvent,
        TraceSink,
    };
    use ruster_io_sim::{BoundSimIoControl, SimIo};
    use ruster_runtime::{
        run_tick, try_publish_candidate, ActivePublicationStatus, FullServicePublication,
        PhaseReport, PublicationAttemptError, PublicationOutcome, PublicationRejection,
        RxPhaseReport, TickBudgets, TickPhaseSkip, TickPhaseTrace, TickPhaseTraceSink,
    };

    use crate::{
        activate_initial, storage::NatBackingOccupancy, BoundFullServicePublicationOwner,
        FullServiceApplyReport, FullServicePublicationOwner, FullServicePublishError,
        FullServiceRestartRequired, FullServiceRuntimeStorage, InitialActivationError,
        InitialActivationFailure,
    };

    const FULL_SERVICE: &str = include_str!("../tests/full-service.toml");

    struct TestBackend;

    // SAFETY: this zero-state fixture has no operational associated outputs or
    // mutable aliases; its infallible quiescence check covers all of its state.
    #[allow(unsafe_code)]
    unsafe impl PublicationBackendAuthority for TestBackend {}

    impl PublicationQuiescenceBackend for TestBackend {
        type Error = Infallible;

        fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
            PublicationQuiescenceDisposition::ContinueOldIo
        }

        fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
            match *error {}
        }
    }

    fn candidate(generation: u64, seed: u64) -> FullServiceCandidateV1 {
        candidate_from_source(FULL_SERVICE.as_bytes(), generation, seed)
    }

    fn candidate_from_source(source: &[u8], generation: u64, seed: u64) -> FullServiceCandidateV1 {
        let parsed = parse(source).expect("syntax fixture");
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
            NonZeroU64::new(generation).unwrap(),
            Nat44UdpHashKey::new(seed, seed + 1).unwrap(),
            Nat44TcpHashKey::new(seed + 2, seed + 3).unwrap(),
            FirewallHashKey::new(seed + 4, seed + 5).unwrap(),
        );
        let plan = match plan_full_service_v1(config, inputs) {
            Ok(plan) => plan,
            Err(failure) => panic!("full-service fixture must plan: {:?}", failure.error()),
        };
        plan.into_candidate()
            .expect("planned fixture must mint a candidate")
    }

    fn activated<'storage>(
        storage: &'storage mut FullServiceRuntimeStorage,
        candidate: FullServiceCandidateV1,
    ) -> FullServicePublicationOwner<'storage> {
        match activate_initial(storage, candidate) {
            Ok(owner) => owner,
            Err(failure) => panic!("valid fixture must activate: {:?}", failure.error()),
        }
    }

    fn bound_activated<'storage, I: PublicationBackendAuthority + PublicationQuiescenceBackend>(
        storage: &'storage mut FullServiceRuntimeStorage,
        candidate: FullServiceCandidateV1,
        backend: I,
    ) -> (
        BoundFullServicePublicationOwner<'storage, I>,
        BoundPublicationBackend<I>,
    ) {
        let owner = activated(storage, candidate);
        let (owner_binding, mut backend) =
            bind_publication_backend(backend).expect("test binding identity must remain available");
        let owner = match owner.bind_backend(owner_binding, &mut backend) {
            Ok(owner) => owner,
            Err(_) => panic!("cold test backend must bind"),
        };
        (owner, backend)
    }

    struct NoTrace;

    impl TickPhaseTraceSink for NoTrace {
        fn record_tick_phase(&mut self, _event: TickPhaseTrace) {}
    }

    impl TraceSink for NoTrace {
        fn record(&mut self, _event: TraceEvent) {}
    }

    impl ResolutionTimerTraceSink for NoTrace {
        fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
    }

    impl ResolutionFailureTraceSink for NoTrace {
        fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
    }

    impl GeneratedTraceSink for NoTrace {
        fn record_generated(&mut self, _event: GeneratedArpTrace) {}
    }

    impl GeneratedIcmpv4TraceSink for NoTrace {
        fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
    }

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const LAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const WAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
    const GATEWAY_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 3];
    const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 4];
    const HOST: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 20]);
    const UNRESOLVED_WAN_HOST: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 99]);
    const REMOTE: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 20]);

    #[allow(clippy::too_many_arguments)]
    fn udp_frame_with_endpoints(
        ethernet_destination: [u8; 6],
        ethernet_source: [u8; 6],
        source: Ipv4Address,
        destination: Ipv4Address,
        ttl: u8,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 28 + 3];
        frame[0..6].copy_from_slice(&ethernet_destination);
        frame[6..12].copy_from_slice(&ethernet_source);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&28_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = ttl;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&source.octets());
        frame[30..34].copy_from_slice(&destination.octets());
        frame[34..36].copy_from_slice(&source_port.to_be_bytes());
        frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
        frame[38..40].copy_from_slice(&8_u16.to_be_bytes());
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn udp_frame(source_port: u16, destination_port: u16) -> Vec<u8> {
        udp_frame_with_endpoints(
            LAN_MAC,
            HOST_MAC,
            HOST,
            REMOTE,
            64,
            source_port,
            destination_port,
        )
    }

    fn tcp_frame(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 40 + 3];
        frame[0..6].copy_from_slice(&LAN_MAC);
        frame[6..12].copy_from_slice(&HOST_MAC);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&HOST.octets());
        frame[30..34].copy_from_slice(&REMOTE.octets());
        frame[34..36].copy_from_slice(&source_port.to_be_bytes());
        frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
        frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
        frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
        frame[46] = 5 << 4;
        frame[47] = 0x02;
        frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());

        let mut pseudo_header = Vec::with_capacity(32);
        pseudo_header.extend_from_slice(&HOST.octets());
        pseudo_header.extend_from_slice(&REMOTE.octets());
        pseudo_header.extend_from_slice(&[0, 6]);
        pseudo_header.extend_from_slice(&20_u16.to_be_bytes());
        pseudo_header.extend_from_slice(&frame[34..54]);
        let checksum = internet_checksum(&pseudo_header);
        frame[50..52].copy_from_slice(&checksum.to_be_bytes());
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn process_one_frame(
        owner: &mut BoundFullServicePublicationOwner<'_, SimIo>,
        io: &mut BoundPublicationBackend<SimIo>,
        now_ms: u64,
        frame: Vec<u8>,
    ) {
        io.inject(LAN, frame);
        let mut trace = NoTrace;
        let report = run_tick(owner, None, io, MonotonicMillis(now_ms), &mut trace);
        let RxPhaseReport::Completed(rx) = report.rx else {
            panic!("fixture frame must complete: {:?}", report.rx);
        };
        assert_eq!(rx.completion.tx_accepted, 1);
        assert!(io.pop_tx().is_some(), "translated frame must be emitted");
    }

    fn process_state_seeding_frame(
        owner: &mut BoundFullServicePublicationOwner<'_, SimIo>,
        io: &mut BoundPublicationBackend<SimIo>,
        ingress: IfId,
        now_ms: u64,
        frame: Vec<u8>,
    ) {
        io.inject(ingress, frame);
        let mut trace = NoTrace;
        let report = run_tick(owner, None, io, MonotonicMillis(now_ms), &mut trace);
        let RxPhaseReport::Completed(rx) = report.rx else {
            panic!("state-seeding frame must complete: {:?}", report.rx);
        };
        assert_eq!(rx.received, 1);
        assert!(
            io.pop_tx().is_none(),
            "zero generated budgets must retain queued state"
        );
    }

    fn stateful_source_with_queued_generated_work() -> String {
        FULL_SERVICE
            .replace("action = \"deny\"", "action = \"allow-stateful\"")
            .replace(
                "generated-arp = 4\ngenerated-icmpv4 = 2",
                "generated-arp = 0\ngenerated-icmpv4 = 0",
            )
    }

    fn seed_all_runtime_state(
        owner: &mut BoundFullServicePublicationOwner<'_, SimIo>,
        io: &mut BoundPublicationBackend<SimIo>,
    ) {
        process_one_frame(owner, io, 1, udp_frame(12_345, 53));
        process_one_frame(owner, io, 2, tcp_frame(12_346, 443));
        process_state_seeding_frame(
            owner,
            io,
            WAN,
            3,
            udp_frame_with_endpoints(
                WAN_MAC,
                GATEWAY_MAC,
                REMOTE,
                UNRESOLVED_WAN_HOST,
                64,
                53,
                12_347,
            ),
        );
        process_state_seeding_frame(
            owner,
            io,
            LAN,
            4,
            udp_frame_with_endpoints(LAN_MAC, HOST_MAC, HOST, REMOTE, 1, 12_348, 53),
        );
    }

    #[allow(
        clippy::result_large_err,
        reason = "test helper preserves exact successor ownership on rejection"
    )]
    fn publish<'storage, I: PublicationBackendAuthority + PublicationQuiescenceBackend>(
        owner: &mut BoundFullServicePublicationOwner<'storage, I>,
        candidate: FullServiceCandidateV1,
        backend: &mut BoundPublicationBackend<I>,
    ) -> Result<
        FullServiceApplyReport,
        PublicationRejection<FullServiceCandidateV1, FullServicePublishError>,
    > {
        let guard = match backend.try_publication_quiescence() {
            Ok(guard) => guard,
            Err(_) => panic!("test backend must quiesce"),
        };
        match try_publish_candidate(owner, candidate, guard) {
            Ok(report) => Ok(report),
            Err(PublicationAttemptError::Rejected(rejection)) => Err(rejection),
            Err(PublicationAttemptError::BackendMismatch { .. }) => {
                panic!("test helper must use the owner-matched backend")
            }
        }
    }

    fn expected_tick_budgets(tick: TickBudgetsV1) -> TickBudgets {
        TickBudgets {
            rx: usize::try_from(tick.rx).unwrap(),
            resolution_timer_scans: usize::try_from(tick.resolution_timer_scans).unwrap(),
            failure_dispatch_scans: usize::try_from(tick.failure_dispatch_scans).unwrap(),
            generated_arp: usize::try_from(tick.generated_arp).unwrap(),
            generated_icmpv4: usize::try_from(tick.generated_icmpv4).unwrap(),
        }
    }

    struct CandidateEvidence {
        generation: NonZeroU64,
        interfaces_pointer: usize,
        interface_name_pointers: [usize; 2],
        interface_device_pointers: [usize; 2],
        tick: TickBudgetsV1,
        required_runtime_bytes: usize,
        storage_shape: FullServiceStorageShape,
        firewall_rules_pointer: usize,
        udp_key: Nat44UdpHashKey,
        tcp_key: Nat44TcpHashKey,
        firewall_key: FirewallHashKey,
    }

    impl CandidateEvidence {
        fn capture(candidate: &FullServiceCandidateV1) -> Self {
            let interfaces = candidate.interfaces();
            assert_eq!(interfaces.len(), 2, "fixture interface identity width");
            let authority = candidate.authority();
            let firewall = authority.firewall_config();
            Self {
                generation: candidate.generation(),
                interfaces_pointer: interfaces.as_ptr() as usize,
                interface_name_pointers: [
                    interfaces[0].name().as_ptr() as usize,
                    interfaces[1].name().as_ptr() as usize,
                ],
                interface_device_pointers: [
                    interfaces[0].device().as_ptr() as usize,
                    interfaces[1].device().as_ptr() as usize,
                ],
                tick: candidate.tick(),
                required_runtime_bytes: candidate.required_runtime_bytes(),
                storage_shape: candidate.storage_shape(),
                firewall_rules_pointer: firewall.rules().as_ptr() as usize,
                udp_key: authority.nat44_udp_hash_key(),
                tcp_key: authority.nat44_tcp_hash_key(),
                firewall_key: firewall.hash_key(),
            }
        }

        fn assert_matches(&self, candidate: &FullServiceCandidateV1) {
            let actual = Self::capture(candidate);
            assert_eq!(actual.generation, self.generation);
            assert_eq!(actual.interfaces_pointer, self.interfaces_pointer);
            assert_eq!(actual.interface_name_pointers, self.interface_name_pointers);
            assert_eq!(
                actual.interface_device_pointers,
                self.interface_device_pointers
            );
            assert_eq!(actual.tick, self.tick);
            assert_eq!(actual.required_runtime_bytes, self.required_runtime_bytes);
            assert_eq!(actual.storage_shape, self.storage_shape);
            assert_eq!(actual.firewall_rules_pointer, self.firewall_rules_pointer);
            assert_eq!(actual.udp_key, self.udp_key);
            assert_eq!(actual.tcp_key, self.tcp_key);
            assert_eq!(actual.firewall_key, self.firewall_key);
        }
    }

    struct ActiveEvidence {
        generation: NonZeroU64,
        interfaces_pointer: usize,
        interface_name_pointers: [usize; 2],
        interface_device_pointers: [usize; 2],
        tick: TickBudgetsV1,
        required_runtime_bytes: usize,
        storage_shape: FullServiceStorageShape,
        runtime: crate::publication::ActiveRuntimeEvidence,
    }

    impl ActiveEvidence {
        fn capture<Binding>(owner: &FullServicePublicationOwner<'_, Binding>) -> Self {
            let interfaces = owner.interfaces();
            let runtime = owner.runtime_evidence();
            Self {
                generation: owner.generation(),
                interfaces_pointer: interfaces.as_ptr() as usize,
                interface_name_pointers: [
                    interfaces[0].name().as_ptr() as usize,
                    interfaces[1].name().as_ptr() as usize,
                ],
                interface_device_pointers: [
                    interfaces[0].device().as_ptr() as usize,
                    interfaces[1].device().as_ptr() as usize,
                ],
                tick: owner.tick(),
                required_runtime_bytes: owner.required_runtime_bytes(),
                storage_shape: owner.storage_shape(),
                runtime,
            }
        }

        fn assert_matches<Binding>(&self, owner: &FullServicePublicationOwner<'_, Binding>) {
            let actual = Self::capture(owner);
            assert_eq!(actual.generation, self.generation);
            assert_eq!(actual.interfaces_pointer, self.interfaces_pointer);
            assert_eq!(actual.interface_name_pointers, self.interface_name_pointers);
            assert_eq!(
                actual.interface_device_pointers,
                self.interface_device_pointers
            );
            assert_eq!(actual.tick, self.tick);
            assert_eq!(actual.required_runtime_bytes, self.required_runtime_bytes);
            assert_eq!(actual.storage_shape, self.storage_shape);
            assert_eq!(actual.runtime, self.runtime);
        }
    }

    #[test]
    fn candidate_bound_storage_allocates_all_arrays_at_exact_shape_and_bytes() {
        let candidate = candidate(1, 10);
        let storage = FullServiceRuntimeStorage::try_for_candidate(&candidate)
            .expect("small fixed allocation");

        assert_eq!(storage.shape(), candidate.storage_shape());
        assert_eq!(
            storage.required_runtime_bytes(),
            candidate.required_runtime_bytes()
        );
        assert_eq!(
            storage.lengths(),
            [2, 3, 4, 5, 6, 6, 7, 3, 9, 4, 3, 16, 9, 13, 5, 17, 8, 5, 32, 17, 13, 11]
        );
    }

    #[test]
    fn shape_mismatch_rejects_before_mutation_and_returns_exact_candidate() {
        let initial_candidate = candidate(7, 100);
        let candidate_evidence = CandidateEvidence::capture(&initial_candidate);
        let expected_shape = initial_candidate.storage_shape();
        let mismatched_shape = FullServiceStorageShape::new(
            expected_shape.resolution(),
            expected_shape.icmpv4_errors(),
            expected_shape.nat44_udp(),
            expected_shape.nat44_tcp(),
            expected_shape.firewall_state_slots() + 1,
        );
        let mut storage =
            FullServiceRuntimeStorage::try_for_shape(mismatched_shape).expect("small allocation");
        let pointers = storage.pointer_identities();

        let failure = match activate_initial(&mut storage, initial_candidate) {
            Ok(_) => panic!("shape mismatch must reject"),
            Err(failure) => failure,
        };
        assert_eq!(
            failure.error(),
            &InitialActivationError::StorageShapeMismatch
        );
        let (initial_candidate, error) = failure.into_parts();
        assert_eq!(error, InitialActivationError::StorageShapeMismatch);
        candidate_evidence.assert_matches(&initial_candidate);
        assert_eq!(storage.shape(), mismatched_shape);
        assert_eq!(storage.pointer_identities(), pointers);
    }

    #[test]
    fn required_byte_mismatch_rejects_before_mutation_and_returns_exact_candidate() {
        let initial_candidate = candidate(8, 200);
        let candidate_evidence = CandidateEvidence::capture(&initial_candidate);
        let mut storage = FullServiceRuntimeStorage::try_for_candidate(&initial_candidate)
            .expect("small fixed allocation");
        let pointers = storage.pointer_identities();
        storage.set_required_runtime_bytes_for_test(
            initial_candidate
                .required_runtime_bytes()
                .checked_add(1)
                .expect("fixture byte count has room"),
        );

        let failure = match activate_initial(&mut storage, initial_candidate) {
            Ok(_) => panic!("required byte mismatch must reject"),
            Err(failure) => failure,
        };
        assert_eq!(
            failure.error(),
            &InitialActivationError::StorageRequiredBytesMismatch
        );
        let (initial_candidate, error) = failure.into_parts();
        assert_eq!(error, InitialActivationError::StorageRequiredBytesMismatch);
        candidate_evidence.assert_matches(&initial_candidate);
        assert_eq!(storage.pointer_identities(), pointers);
    }

    #[test]
    fn successful_initial_activation_is_coherent_pristine_and_fully_wired() {
        let initial_candidate = candidate(1, 10);
        let candidate_evidence = CandidateEvidence::capture(&initial_candidate);
        let (udp_config, tcp_config, firewall_key, firewall_rule_count) = {
            let authority = initial_candidate.authority();
            let firewall = authority.firewall_config();
            (
                authority.nat44_udp_config(),
                authority.nat44_tcp_config(),
                firewall.hash_key(),
                firewall.rules().len(),
            )
        };
        let shape = initial_candidate.storage_shape();
        let mut storage = FullServiceRuntimeStorage::try_for_candidate(&initial_candidate)
            .expect("small fixed allocation");
        let storage_pointers = storage.pointer_identities();
        let mut owner = activated(&mut storage, initial_candidate);

        assert_eq!(owner.generation(), candidate_evidence.generation);
        assert_eq!(owner.tick(), candidate_evidence.tick);
        assert_eq!(
            owner.required_runtime_bytes(),
            candidate_evidence.required_runtime_bytes
        );
        assert_eq!(owner.storage_shape(), shape);
        assert_eq!(
            owner.interfaces().as_ptr() as usize,
            candidate_evidence.interfaces_pointer
        );

        let runtime = owner.runtime_evidence();
        assert_eq!(runtime.storage_shape, shape);
        assert!(runtime.publication_bindings_match);
        assert_eq!(runtime.nat44_udp_mapping_occupied, 0);
        assert_eq!(runtime.nat44_udp_peer_occupied, 0);
        assert!(runtime.nat44_udp_counters_pristine);
        assert!(runtime.nat44_udp_pristine);
        assert_eq!(runtime.nat44_tcp_mapping_occupied, 0);
        assert_eq!(runtime.nat44_tcp_session_occupied, 0);
        assert!(runtime.nat44_tcp_counters_pristine);
        assert!(runtime.nat44_tcp_pristine);
        assert!(runtime.pristine);
        assert_eq!(runtime.backing_pointers, storage_pointers);

        let view = owner.active_view();
        assert_eq!(view.generation(), candidate_evidence.generation);
        assert_eq!(
            view.tick_budgets(),
            expected_tick_budgets(candidate_evidence.tick)
        );
        assert_eq!(view.nat44_udp_config(), udp_config);
        assert_eq!(view.nat44_tcp_config(), tcp_config);
        assert_eq!(view.firewall_config().hash_key(), firewall_key);
        assert_eq!(view.firewall_config().rules().len(), firewall_rule_count);
        assert!(view.has_nat44_udp_runtime());
        assert!(view.has_nat44_tcp_runtime());
        assert!(view.has_firewall_runtime());
    }

    #[test]
    fn reused_dirty_nat_storage_is_cleared_by_initial_activation() {
        let udp_allowed = FULL_SERVICE.replace("action = \"deny\"", "action = \"allow-stateful\"");
        let initial_candidate = candidate_from_source(udp_allowed.as_bytes(), 1, 10);
        let mut storage = FullServiceRuntimeStorage::try_for_candidate(&initial_candidate)
            .expect("small fixed allocation");
        let storage_pointers = storage.pointer_identities();
        assert_eq!(storage.nat_backing_occupancy(), NatBackingOccupancy::EMPTY);

        {
            let (mut owner, mut io) =
                bound_activated(&mut storage, initial_candidate, SimIo::new());
            let pristine = owner.runtime_evidence();
            assert_eq!(pristine.nat44_udp_mapping_occupied, 0);
            assert_eq!(pristine.nat44_udp_peer_occupied, 0);
            assert!(pristine.nat44_udp_counters_pristine);
            assert!(pristine.nat44_udp_pristine);
            assert_eq!(pristine.nat44_tcp_mapping_occupied, 0);
            assert_eq!(pristine.nat44_tcp_session_occupied, 0);
            assert!(pristine.nat44_tcp_counters_pristine);
            assert!(pristine.nat44_tcp_pristine);
            assert!(pristine.pristine);

            process_one_frame(&mut owner, &mut io, 1, udp_frame(12_345, 53));
            let udp_dirty = owner.runtime_evidence();
            assert!(udp_dirty.nat44_udp_mapping_occupied > 0);
            assert!(udp_dirty.nat44_udp_peer_occupied > 0);
            assert!(!udp_dirty.nat44_udp_counters_pristine);
            assert!(!udp_dirty.nat44_udp_pristine);
            assert_eq!(udp_dirty.nat44_tcp_mapping_occupied, 0);
            assert_eq!(udp_dirty.nat44_tcp_session_occupied, 0);
            assert!(udp_dirty.nat44_tcp_counters_pristine);
            assert!(udp_dirty.nat44_tcp_pristine);
            assert!(!udp_dirty.pristine);

            process_one_frame(&mut owner, &mut io, 2, tcp_frame(12_346, 443));
            let both_dirty = owner.runtime_evidence();
            assert!(both_dirty.nat44_udp_mapping_occupied > 0);
            assert!(both_dirty.nat44_udp_peer_occupied > 0);
            assert!(!both_dirty.nat44_udp_counters_pristine);
            assert!(!both_dirty.nat44_udp_pristine);
            assert!(both_dirty.nat44_tcp_mapping_occupied > 0);
            assert!(both_dirty.nat44_tcp_session_occupied > 0);
            assert!(!both_dirty.nat44_tcp_counters_pristine);
            assert!(!both_dirty.nat44_tcp_pristine);
            assert!(!both_dirty.pristine);
        }

        assert_eq!(storage.pointer_identities(), storage_pointers);
        let dirty_backings = storage.nat_backing_occupancy();
        assert!(dirty_backings.udp_mappings > 0);
        assert!(dirty_backings.udp_peers > 0);
        assert!(dirty_backings.udp_mapping_buckets > 0);
        assert!(dirty_backings.udp_mapping_nodes > 0);
        assert!(dirty_backings.udp_peer_buckets > 0);
        assert!(dirty_backings.udp_peer_nodes > 0);
        assert!(dirty_backings.udp_port_owners > 0);
        assert!(dirty_backings.tcp_mappings > 0);
        assert!(dirty_backings.tcp_sessions > 0);
        assert!(dirty_backings.tcp_mapping_buckets > 0);
        assert!(dirty_backings.tcp_mapping_nodes > 0);
        assert!(dirty_backings.tcp_session_buckets > 0);
        assert!(dirty_backings.tcp_session_nodes > 0);
        assert!(dirty_backings.tcp_port_owners > 0);

        let replacement = candidate_from_source(udp_allowed.as_bytes(), 2, 100);
        {
            let owner = activated(&mut storage, replacement);
            let reactivated = owner.runtime_evidence();
            assert_eq!(reactivated.nat44_udp_mapping_occupied, 0);
            assert_eq!(reactivated.nat44_udp_peer_occupied, 0);
            assert!(reactivated.nat44_udp_counters_pristine);
            assert!(reactivated.nat44_udp_pristine);
            assert_eq!(reactivated.nat44_tcp_mapping_occupied, 0);
            assert_eq!(reactivated.nat44_tcp_session_occupied, 0);
            assert!(reactivated.nat44_tcp_counters_pristine);
            assert!(reactivated.nat44_tcp_pristine);
            assert!(reactivated.pristine);
            assert_eq!(reactivated.backing_pointers, storage_pointers);
        }
        assert_eq!(storage.nat_backing_occupancy(), NatBackingOccupancy::EMPTY);
        assert_eq!(storage.pointer_identities(), storage_pointers);
    }

    #[test]
    fn successful_successor_reuses_all_backings_flushes_old_state_and_reports_counts() {
        let generation_one_source = stateful_source_with_queued_generated_work();
        let initial_candidate = candidate_from_source(generation_one_source.as_bytes(), 1, 10);
        let initial_evidence = CandidateEvidence::capture(&initial_candidate);
        let (initial_udp_config, initial_tcp_config) = {
            let authority = initial_candidate.authority();
            (authority.nat44_udp_config(), authority.nat44_tcp_config())
        };
        let mut storage = FullServiceRuntimeStorage::try_for_candidate(&initial_candidate)
            .expect("small fixed allocation");
        let storage_pointers = storage.pointer_identities();
        let (mut owner, mut io) = bound_activated(&mut storage, initial_candidate, SimIo::new());

        seed_all_runtime_state(&mut owner, &mut io);
        let dirty = owner.runtime_evidence();
        assert!(dirty.resolution_pending_states > 0);
        assert!(dirty.resolution_pending_actions > 0);
        assert_eq!(dirty.resolution_dynamic_neighbors, 0);
        assert!(dirty.resolution_pending_failure_holds > 0);
        assert!(!dirty.resolution_pristine);
        assert!(dirty.icmpv4_error_pending_actions > 0);
        assert!(!dirty.icmpv4_errors_pristine);
        assert!(dirty.nat44_udp_mapping_occupied > 0);
        assert!(dirty.nat44_udp_peer_occupied > 0);
        assert!(!dirty.nat44_udp_counters_pristine);
        assert!(!dirty.nat44_udp_pristine);
        assert!(dirty.nat44_tcp_mapping_occupied > 0);
        assert!(dirty.nat44_tcp_session_occupied > 0);
        assert!(!dirty.nat44_tcp_counters_pristine);
        assert!(!dirty.nat44_tcp_pristine);
        assert!(dirty.firewall_state_occupied > 0);
        assert!(!dirty.firewall_pristine);
        assert!(!dirty.pristine);
        let runtime_pointers = dirty.pointers;
        assert_eq!(dirty.backing_pointers, storage_pointers);

        let generation_two_source = generation_one_source
            .replace(
                "[nat44.udp]\nidle-ttl-ms = 300000\nallocator-seed = \"7\"",
                "[nat44.udp]\nidle-ttl-ms = 299000\nallocator-seed = \"17\"",
            )
            .replace(
                "[nat44.tcp]\nidle-ttl-ms = 7440000\nallocator-seed = \"11\"",
                "[nat44.tcp]\nidle-ttl-ms = 7441000\nallocator-seed = \"19\"",
            )
            .replace("[[firewall.rules]]\nid = 2", "[[firewall.rules]]\nid = 22")
            .replace("[[firewall.rules]]\nid = 1", "[[firewall.rules]]\nid = 21")
            .replace(
                "[tick]\nrx = 64\nresolution-timer-scans = 16\nfailure-dispatch-scans = 8\ngenerated-arp = 0\ngenerated-icmpv4 = 0",
                "[tick]\nrx = 63\nresolution-timer-scans = 15\nfailure-dispatch-scans = 7\ngenerated-arp = 3\ngenerated-icmpv4 = 1",
            );
        let successor = candidate_from_source(generation_two_source.as_bytes(), 2, 100);
        assert!(successor.interfaces() == owner.interfaces());
        assert_eq!(successor.storage_shape(), owner.storage_shape());
        let successor_evidence = CandidateEvidence::capture(&successor);
        assert_ne!(successor_evidence.udp_key, initial_evidence.udp_key);
        assert_ne!(successor_evidence.tcp_key, initial_evidence.tcp_key);
        assert_ne!(
            successor_evidence.firewall_key,
            initial_evidence.firewall_key
        );
        let (successor_udp_config, successor_tcp_config, successor_rules) = {
            let authority = successor.authority();
            let firewall = authority.firewall_config();
            assert_eq!(firewall.rules().len(), 2);
            (
                authority.nat44_udp_config(),
                authority.nat44_tcp_config(),
                [firewall.rules()[0], firewall.rules()[1]],
            )
        };
        assert_ne!(successor_udp_config, initial_udp_config);
        assert_ne!(successor_tcp_config, initial_tcp_config);

        let report = match publish(&mut owner, successor, &mut io) {
            Ok(report) => report,
            Err(rejection) => panic!(
                "same-interface, same-shape successor must publish: {:?}",
                rejection.error()
            ),
        };
        assert_eq!(report.previous_generation(), initial_evidence.generation);
        assert_eq!(report.generation(), successor_evidence.generation);
        assert_eq!(
            report.resolution().states_flushed,
            dirty.resolution_pending_states
        );
        assert!(report.resolution().states_flushed > 0);
        assert_eq!(
            report.resolution().actions_flushed,
            dirty.resolution_pending_actions
        );
        assert_eq!(
            report.resolution().dynamic_neighbors_flushed,
            dirty.resolution_dynamic_neighbors
        );
        assert_eq!(
            report.resolution().failure_holds_flushed,
            dirty.resolution_pending_failure_holds
        );
        assert!(report.icmpv4_errors().states_flushed > 0);
        assert_eq!(
            report.icmpv4_errors().actions_flushed,
            dirty.icmpv4_error_pending_actions
        );
        assert_eq!(
            report.nat44_udp().mappings_flushed,
            dirty.nat44_udp_mapping_occupied
        );
        assert_eq!(
            report.nat44_udp().peers_flushed,
            dirty.nat44_udp_peer_occupied
        );
        assert_eq!(
            report.nat44_tcp().mappings_flushed,
            dirty.nat44_tcp_mapping_occupied
        );
        assert_eq!(
            report.nat44_tcp().sessions_flushed,
            dirty.nat44_tcp_session_occupied
        );
        assert_eq!(
            report.firewall().states_flushed,
            dirty.firewall_state_occupied
        );

        assert_eq!(owner.generation(), successor_evidence.generation);
        assert_eq!(owner.tick(), successor_evidence.tick);
        assert_eq!(
            owner.required_runtime_bytes(),
            successor_evidence.required_runtime_bytes
        );
        assert_eq!(owner.storage_shape(), successor_evidence.storage_shape);
        assert_eq!(
            owner.interfaces().as_ptr() as usize,
            successor_evidence.interfaces_pointer
        );
        assert_eq!(
            [
                owner.interfaces()[0].name().as_ptr() as usize,
                owner.interfaces()[1].name().as_ptr() as usize,
            ],
            successor_evidence.interface_name_pointers
        );
        assert_eq!(
            [
                owner.interfaces()[0].device().as_ptr() as usize,
                owner.interfaces()[1].device().as_ptr() as usize,
            ],
            successor_evidence.interface_device_pointers
        );

        let active = owner.runtime_evidence();
        assert_eq!(active.pointers, runtime_pointers);
        assert_eq!(active.backing_pointers, storage_pointers);
        assert_eq!(active.storage_shape, successor_evidence.storage_shape);
        assert!(active.publication_bindings_match);
        assert_eq!(active.resolution_pending_states, 0);
        assert_eq!(active.resolution_pending_actions, 0);
        assert_eq!(active.resolution_dynamic_neighbors, 0);
        assert_eq!(active.resolution_pending_failure_holds, 0);
        assert_eq!(active.icmpv4_error_pending_actions, 0);
        assert_eq!(active.nat44_udp_mapping_occupied, 0);
        assert_eq!(active.nat44_udp_peer_occupied, 0);
        assert!(
            !active.nat44_udp_counters_pristine,
            "reconcile diagnostics remain cumulative after state flush"
        );
        assert!(!active.nat44_udp_pristine);
        assert_eq!(active.nat44_tcp_mapping_occupied, 0);
        assert_eq!(active.nat44_tcp_session_occupied, 0);
        assert!(
            !active.nat44_tcp_counters_pristine,
            "reconcile diagnostics remain cumulative after state flush"
        );
        assert!(!active.nat44_tcp_pristine);
        assert_eq!(active.firewall_state_occupied, 0);
        assert!(
            !active.pristine,
            "publication preserves cumulative reconcile counters"
        );

        let (post_apply_resolution, post_apply_icmpv4) =
            owner.flush_resolution_and_icmpv4_for_test();
        assert_eq!(post_apply_resolution.states_flushed, 0);
        assert_eq!(post_apply_resolution.actions_flushed, 0);
        assert_eq!(post_apply_resolution.dynamic_neighbors_flushed, 0);
        assert_eq!(post_apply_resolution.failure_holds_flushed, 0);
        assert_eq!(post_apply_icmpv4.states_flushed, 0);
        assert_eq!(post_apply_icmpv4.actions_flushed, 0);

        let view = owner.active_view();
        assert_eq!(view.generation(), successor_evidence.generation);
        assert_eq!(
            view.tick_budgets(),
            expected_tick_budgets(successor_evidence.tick)
        );
        assert_eq!(view.nat44_udp_config(), successor_udp_config);
        assert_eq!(view.nat44_tcp_config(), successor_tcp_config);
        let firewall = view.firewall_config();
        assert_eq!(firewall.hash_key(), successor_evidence.firewall_key);
        assert_eq!(
            firewall.rules().as_ptr() as usize,
            successor_evidence.firewall_rules_pointer
        );
        assert_eq!(firewall.rules(), &successor_rules);
        assert!(view.has_nat44_udp_runtime());
        assert!(view.has_nat44_tcp_runtime());
        assert!(view.has_firewall_runtime());
    }

    #[test]
    fn firewall_preflight_failure_drops_prior_permits_and_preserves_transaction_state() {
        let stateful_source = stateful_source_with_queued_generated_work();
        let initial_candidate = candidate_from_source(stateful_source.as_bytes(), 1, 10);
        let mut storage = FullServiceRuntimeStorage::try_for_candidate(&initial_candidate)
            .expect("small fixed allocation");
        let storage_pointers = storage.pointer_identities();
        let (mut owner, mut io) = bound_activated(&mut storage, initial_candidate, SimIo::new());
        seed_all_runtime_state(&mut owner, &mut io);

        let firewall_corruption = candidate_from_source(stateful_source.as_bytes(), 2, 200);
        let corruption_evidence = CandidateEvidence::capture(&firewall_corruption);
        let corruption_report = owner
            .reconcile_firewall_for_test(&firewall_corruption)
            .expect("intentional next-generation firewall reconcile must succeed");
        assert!(corruption_report.states_flushed > 0);

        let before = ActiveEvidence::capture(&owner);
        let baseline = owner.runtime_evidence();
        let backend_queue_baseline = (io.pending_rx(), io.pending_tx());
        assert_eq!(backend_queue_baseline, (0, 0));
        assert_eq!(baseline.backing_pointers, storage_pointers);
        assert!(baseline.resolution_pending_states > 0);
        assert!(baseline.resolution_pending_actions > 0);
        assert_eq!(baseline.resolution_dynamic_neighbors, 0);
        assert!(baseline.resolution_pending_failure_holds > 0);
        assert!(!baseline.resolution_pristine);
        assert!(baseline.icmpv4_error_pending_actions > 0);
        assert!(!baseline.icmpv4_errors_pristine);
        assert!(baseline.nat44_udp_mapping_occupied > 0);
        assert!(baseline.nat44_udp_peer_occupied > 0);
        assert!(baseline.nat44_tcp_mapping_occupied > 0);
        assert!(baseline.nat44_tcp_session_occupied > 0);
        assert_eq!(baseline.firewall_state_occupied, 0);
        assert!(baseline.firewall_counters.reconciliations > 0);
        assert!(!baseline.publication_bindings_match);

        let successor = candidate_from_source(stateful_source.as_bytes(), 2, 100);
        let successor_evidence = CandidateEvidence::capture(&successor);
        assert_ne!(
            successor_evidence.firewall_key,
            corruption_evidence.firewall_key
        );
        let expected = FullServicePublishError::FirewallReconcile(
            ruster_core::FirewallReconcileError::IdentityCollision,
        );
        let mut trace = NoTrace;
        let report = run_tick(
            &mut owner,
            Some(successor),
            &mut io,
            MonotonicMillis(5),
            &mut trace,
        );
        assert!(report.active);
        assert!(matches!(
            &report.rx,
            RxPhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert!(matches!(
            &report.resolution_timers,
            PhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert!(matches!(
            &report.failure_dispatch,
            PhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert!(matches!(
            &report.generated_arp,
            PhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert!(matches!(
            &report.generated_icmpv4,
            PhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        let rejection = match report.publication {
            PublicationOutcome::Rejected {
                rejection,
                status: ActivePublicationStatus::StopOldPublication,
            } => rejection,
            outcome => panic!("last firewall preflight must fail closed: {outcome:?}"),
        };
        assert_eq!(rejection.error(), &expected);
        let (successor, error) = rejection.into_parts();
        assert_eq!(error, expected);
        successor_evidence.assert_matches(&successor);

        assert_eq!((io.pending_rx(), io.pending_tx()), backend_queue_baseline);
        before.assert_matches(&owner);
        let after = owner.runtime_evidence();
        assert_eq!(after, baseline);
        assert_eq!(after.pointers, baseline.pointers);
        assert_eq!(after.backing_pointers, storage_pointers);
        assert_eq!(
            after.resolution_pending_states,
            baseline.resolution_pending_states
        );
        assert_eq!(
            after.resolution_pending_actions,
            baseline.resolution_pending_actions
        );
        assert_eq!(
            after.resolution_dynamic_neighbors,
            baseline.resolution_dynamic_neighbors
        );
        assert_eq!(
            after.resolution_pending_failure_holds,
            baseline.resolution_pending_failure_holds
        );
        assert_eq!(after.resolution_counters, baseline.resolution_counters);
        assert_eq!(
            after.resolution_failure_counters,
            baseline.resolution_failure_counters
        );
        assert_eq!(
            after.icmpv4_error_pending_actions,
            baseline.icmpv4_error_pending_actions
        );
        assert_eq!(after.icmpv4_error_counters, baseline.icmpv4_error_counters);
        assert_eq!(
            after.nat44_udp_mapping_occupied,
            baseline.nat44_udp_mapping_occupied
        );
        assert_eq!(
            after.nat44_udp_peer_occupied,
            baseline.nat44_udp_peer_occupied
        );
        assert_eq!(after.nat44_udp_counters, baseline.nat44_udp_counters);
        assert_eq!(
            after.nat44_tcp_mapping_occupied,
            baseline.nat44_tcp_mapping_occupied
        );
        assert_eq!(
            after.nat44_tcp_session_occupied,
            baseline.nat44_tcp_session_occupied
        );
        assert_eq!(after.nat44_tcp_counters, baseline.nat44_tcp_counters);
        assert_eq!(
            after.firewall_state_occupied,
            baseline.firewall_state_occupied
        );
        assert_eq!(after.firewall_counters, baseline.firewall_counters);

        {
            let mut generated = io.begin_generated(IfId(1));
            generated
                .allocate(64)
                .expect("simulator must provide one generated frame")
                .commit();
            let completion = generated.finish();
            assert_eq!(completion.accepted, 1);
        }
        let latched_backend_queue_baseline = (io.pending_rx(), io.pending_tx());
        assert_eq!(latched_backend_queue_baseline, (0, 1));

        let later_candidate = candidate_from_source(stateful_source.as_bytes(), 3, 300);
        let later_evidence = CandidateEvidence::capture(&later_candidate);
        let report = run_tick(
            &mut owner,
            Some(later_candidate),
            &mut io,
            MonotonicMillis(6),
            &mut trace,
        );
        assert!(report.active);
        assert!(matches!(
            &report.rx,
            RxPhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        let rejection = match report.publication {
            PublicationOutcome::Rejected {
                rejection,
                status: ActivePublicationStatus::StopOldPublication,
            } => rejection,
            outcome => panic!("latched owner must repeat the terminal cause: {outcome:?}"),
        };
        assert_eq!(rejection.error(), &expected);
        let (later_candidate, error) = rejection.into_parts();
        assert_eq!(error, expected);
        later_evidence.assert_matches(&later_candidate);
        assert_eq!(
            (io.pending_rx(), io.pending_tx()),
            latched_backend_queue_baseline,
            "latched rejection must outrank pending-TX quiescence without consuming the queue"
        );
        before.assert_matches(&owner);

        let report = run_tick(&mut owner, None, &mut io, MonotonicMillis(7), &mut trace);
        assert!(matches!(report.publication, PublicationOutcome::Unchanged));
        assert!(report.active);
        assert!(matches!(
            report.rx,
            RxPhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert!(matches!(
            report.resolution_timers,
            PhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert!(matches!(
            report.failure_dispatch,
            PhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert!(matches!(
            report.generated_arp,
            PhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert!(matches!(
            report.generated_icmpv4,
            PhaseReport::Skipped(TickPhaseSkip::ActivePublicationInvalid)
        ));
        assert_eq!(
            (io.pending_rx(), io.pending_tx()),
            latched_backend_queue_baseline
        );
        before.assert_matches(&owner);
    }

    #[test]
    fn invalid_successor_preserves_exact_candidate_and_all_active_state() {
        let initial_candidate = candidate(1, 10);
        let mut storage = FullServiceRuntimeStorage::try_for_candidate(&initial_candidate)
            .expect("small fixed allocation");
        let (mut owner, mut backend) =
            bound_activated(&mut storage, initial_candidate, TestBackend);
        let before = ActiveEvidence::capture(&owner);

        let invalid_candidate = candidate(1, 200);
        let invalid_evidence = CandidateEvidence::capture(&invalid_candidate);
        let rejection = publish(&mut owner, invalid_candidate, &mut backend)
            .expect_err("non-increasing generation must reject");
        assert_eq!(
            rejection.error(),
            &FullServicePublishError::InvalidSuccessor(SuccessorError::GenerationNotIncreasing)
        );
        let (invalid_candidate, error) = rejection.into_parts();
        assert_eq!(
            error,
            FullServicePublishError::InvalidSuccessor(SuccessorError::GenerationNotIncreasing)
        );
        invalid_evidence.assert_matches(&invalid_candidate);
        before.assert_matches(&owner);
        assert_eq!(
            owner.active_status(),
            ActivePublicationStatus::ContinueOldIo
        );

        let valid_successor = candidate(2, 300);
        let valid_generation = valid_successor.generation();
        let report = match publish(&mut owner, valid_successor, &mut backend) {
            Ok(report) => report,
            Err(rejection) => panic!(
                "candidate-safe rejection must not latch the owner: {:?}",
                rejection.error()
            ),
        };
        assert_eq!(report.generation(), valid_generation);
        assert_eq!(owner.generation(), valid_generation);
    }

    #[test]
    fn foreign_same_type_guard_preserves_candidate_and_does_not_latch_owner() {
        let initial_candidate = candidate(1, 10);
        let mut storage = FullServiceRuntimeStorage::try_for_candidate(&initial_candidate)
            .expect("small fixed allocation");
        let (mut owner, mut owner_backend) =
            bound_activated(&mut storage, initial_candidate, TestBackend);
        let (_foreign_binding, mut foreign_backend) = bind_publication_backend(TestBackend)
            .expect("test binding identity must remain available");
        let before = ActiveEvidence::capture(&owner);

        let successor = candidate(2, 200);
        let successor_evidence = CandidateEvidence::capture(&successor);
        let foreign_guard = foreign_backend
            .try_publication_quiescence()
            .expect("test backend always quiesces");
        let successor = match try_publish_candidate(&mut owner, successor, foreign_guard) {
            Err(PublicationAttemptError::BackendMismatch { candidate }) => candidate,
            Ok(_) => panic!("foreign same-type guard must not authorize publication"),
            Err(PublicationAttemptError::Rejected(_)) => {
                panic!("foreign guard must reject before the adapter hook")
            }
        };
        successor_evidence.assert_matches(&successor);
        before.assert_matches(&owner);
        assert_eq!(
            owner.active_status(),
            ActivePublicationStatus::ContinueOldIo
        );

        let report = match publish(&mut owner, successor, &mut owner_backend) {
            Ok(report) => report,
            Err(rejection) => panic!(
                "the exact owner-matched backend must remain authorized: {:?}",
                rejection.error()
            ),
        };
        assert_eq!(report.generation(), successor_evidence.generation);
        assert_eq!(owner.generation(), successor_evidence.generation);
    }

    #[test]
    fn typed_nat_activation_failures_preserve_exact_candidate_ownership() {
        for error in [
            InitialActivationError::Nat44UdpRuntime(
                Nat44UdpRuntimeConfigError::RuntimeIdentityExhausted,
            ),
            InitialActivationError::Nat44TcpRuntime(
                Nat44TcpRuntimeConfigError::RuntimeIdentityExhausted,
            ),
        ] {
            let candidate = candidate(9, 300);
            let evidence = CandidateEvidence::capture(&candidate);
            let failure: InitialActivationFailure = PublicationRejection::new(candidate, error);
            let (candidate, actual_error) = failure.into_parts();
            assert_eq!(actual_error, error);
            evidence.assert_matches(&candidate);
        }
    }

    #[test]
    fn public_error_debug_is_value_free() {
        assert_eq!(
            format!("{:?}", InitialActivationError::StorageShapeMismatch),
            "StorageShapeMismatch"
        );
        assert_eq!(
            format!(
                "{:?}",
                InitialActivationError::Nat44TcpRuntime(
                    Nat44TcpRuntimeConfigError::RuntimeIdentityExhausted
                )
            ),
            "Nat44TcpRuntime(RuntimeIdentityExhausted)"
        );
        assert_eq!(
            format!(
                "{:?}",
                FullServicePublishError::InvalidSuccessor(SuccessorError::GenerationNotIncreasing)
            ),
            "InvalidSuccessor(GenerationNotIncreasing)"
        );
        assert_eq!(
            format!("{:?}", FullServiceRestartRequired::InterfaceBindingsChanged),
            "InterfaceBindingsChanged"
        );
        assert_eq!(
            format!(
                "{:?}",
                FullServiceRestartRequired::RuntimeStorageShapeChanged
            ),
            "RuntimeStorageShapeChanged"
        );
        assert_eq!(
            format!(
                "{:?}",
                FullServicePublishError::RestartRequired(
                    FullServiceRestartRequired::InterfaceBindingsChanged
                )
            ),
            "RestartRequired(InterfaceBindingsChanged)"
        );
        assert_eq!(
            format!(
                "{:?}",
                FullServicePublishError::RestartRequired(
                    FullServiceRestartRequired::RuntimeStorageShapeChanged
                )
            ),
            "RestartRequired(RuntimeStorageShapeChanged)"
        );
    }
}

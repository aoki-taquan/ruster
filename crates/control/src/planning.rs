use std::num::NonZeroU64;

use ruster_config::{
    Icmpv4ErrorStorageShapeV1, InterfaceBindingV1, Nat44TcpStorageShapeV1, Nat44UdpStorageShapeV1,
    ResolutionStorageShapeV1, TickBudgetsV1, ValidatedBackendV1, ValidatedConfigV1,
};
use ruster_core::{
    FirewallConfigError, FirewallHashKey, Nat44TcpHashKey, Nat44UdpHashKey,
    ValidatedForwardingOwnerError,
};

use crate::{
    FirewallPublicationInput, FullServiceStorageShape, Icmpv4ErrorStorageShape,
    Nat44TcpPublicationInput, Nat44TcpStoragePlan, Nat44UdpPublicationInput, Nat44UdpStoragePlan,
    PublicationCandidateError, PublicationPlan, ResolutionStorageShape, RuntimeService,
    SuccessorError, ValidatedAuthority, ValidatedCandidate,
};

/// 一つのfull-service planへcallerが供給するpublication identity。
///
/// この型はkey freshnessを証明せず、generationとkeyを偶発的に複製またはformatしないため
/// `Clone`と`Debug`を実装しません。
///
/// ```compile_fail
/// use ruster_control::FullServicePlanInputs;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<FullServicePlanInputs>();
/// ```
///
/// ```compile_fail
/// use ruster_control::FullServicePlanInputs;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<FullServicePlanInputs>();
/// ```
///
/// ```compile_fail
/// fn expose(inputs: ruster_control::FullServicePlanInputs) {
///     let _ = inputs.generation;
/// }
/// ```
///
/// ```compile_fail
/// fn expose(inputs: ruster_control::FullServicePlanInputs) {
///     let _ = inputs.nat44_udp;
/// }
/// ```
///
/// ```compile_fail
/// fn expose(inputs: ruster_control::FullServicePlanInputs) {
///     let _ = inputs.nat44_tcp;
/// }
/// ```
///
/// ```compile_fail
/// fn expose(inputs: ruster_control::FullServicePlanInputs) {
///     let _ = inputs.firewall;
/// }
/// ```
pub struct FullServicePlanInputs {
    generation: NonZeroU64,
    nat44_udp: Nat44UdpHashKey,
    nat44_tcp: Nat44TcpHashKey,
    firewall: FirewallHashKey,
}

impl FullServicePlanInputs {
    #[must_use]
    pub const fn new(
        generation: NonZeroU64,
        nat44_udp: Nat44UdpHashKey,
        nat44_tcp: Nat44TcpHashKey,
        firewall: FirewallHashKey,
    ) -> Self {
        Self {
            generation,
            nat44_udp,
            nat44_tcp,
            firewall,
        }
    }
}

/// Planner-produced candidateのauthority mintingで生じるterminal failure。
///
/// nonce exhaustionはprocess lifetimeで再試行できません。`InternalInvariantViolation`は
/// callerがconfigを修正して再試行できるvalidation errorではありません。全variantはsource value、
/// topology、hash keyを保持せず、activationまたはapplyの失敗を表しません。
///
/// ```compile_fail
/// use ruster_control::FullServiceCandidateError;
///
/// fn exhaustive(error: FullServiceCandidateError) {
///     match error {
///         FullServiceCandidateError::ForwardingPublicationNonceExhausted => {}
///         FullServiceCandidateError::FirewallPublicationNonceExhausted => {}
///         FullServiceCandidateError::InternalInvariantViolation => {}
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FullServiceCandidateError {
    ForwardingPublicationNonceExhausted,
    FirewallPublicationNonceExhausted,
    InternalInvariantViolation,
}

/// Publicationとgeneration-tagged metadataを一緒に保持するmove-only plan。
///
/// fieldはprivateであり、[`FullServicePlanV1::into_candidate`]がauthorityとmetadataを
/// 不可分なwrapperへ遷移させるまでcoherentな組をopaqueに保持します。
///
/// ```compile_fail
/// use ruster_control::FullServicePlanV1;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<FullServicePlanV1>();
/// ```
///
/// ```compile_fail
/// use ruster_control::FullServicePlanV1;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<FullServicePlanV1>();
/// ```
///
/// ```compile_fail
/// fn expose(plan: ruster_control::FullServicePlanV1) {
///     let _ = plan.publication;
/// }
/// ```
///
/// ```compile_fail
/// fn expose(plan: ruster_control::FullServicePlanV1) {
///     let _ = plan.metadata;
/// }
/// ```
pub struct FullServicePlanV1 {
    publication: PublicationPlan,
    metadata: FullServicePlanMetadataV1,
}

impl FullServicePlanV1 {
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.metadata.generation()
    }

    #[must_use]
    pub fn interfaces(&self) -> &[InterfaceBindingV1] {
        self.metadata.interfaces()
    }

    #[must_use]
    pub const fn tick(&self) -> TickBudgetsV1 {
        self.metadata.tick()
    }

    #[must_use]
    pub const fn required_runtime_bytes(&self) -> usize {
        self.metadata.required_runtime_bytes()
    }

    /// Publication authorityをmintし、metadataとのcoherentなwrapperへ不可分に遷移します。
    ///
    /// `Err`でも`self`をconsumeして元planを返しません。forwardingまたはfirewall publication
    /// nonce exhaustionはprocess lifetimeで再試行できず、その他のlower-level validation errorは
    /// caller-correctableでない[`FullServiceCandidateError::InternalInvariantViolation`]へcollapseします。
    /// 全errorはvalue-freeであり、activationまたはapplyの失敗を表しません。
    pub fn into_candidate(self) -> Result<FullServiceCandidateV1, FullServiceCandidateError> {
        let Self {
            publication,
            metadata,
        } = self;
        let candidate =
            ValidatedCandidate::new(publication).map_err(full_service_candidate_error)?;
        Ok(FullServiceCandidateV1 {
            candidate,
            metadata,
        })
    }
}

fn full_service_candidate_error(error: PublicationCandidateError) -> FullServiceCandidateError {
    match error {
        PublicationCandidateError::Forwarding(
            ValidatedForwardingOwnerError::PublicationNonceExhausted,
        ) => FullServiceCandidateError::ForwardingPublicationNonceExhausted,
        PublicationCandidateError::Firewall(FirewallConfigError::PublicationNonceExhausted) => {
            FullServiceCandidateError::FirewallPublicationNonceExhausted
        }
        _ => FullServiceCandidateError::InternalInvariantViolation,
    }
}

/// 一つのpublication generationにbindされたconfig由来metadata。
struct FullServicePlanMetadataV1 {
    generation: NonZeroU64,
    interfaces: Box<[InterfaceBindingV1]>,
    tick: TickBudgetsV1,
    required_runtime_bytes: usize,
    backend: ValidatedBackendV1,
}

impl FullServicePlanMetadataV1 {
    const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    fn interfaces(&self) -> &[InterfaceBindingV1] {
        &self.interfaces
    }

    const fn tick(&self) -> TickBudgetsV1 {
        self.tick
    }

    const fn required_runtime_bytes(&self) -> usize {
        self.required_runtime_bytes
    }

    fn backend(&self) -> &ValidatedBackendV1 {
        &self.backend
    }
}

/// Validated authorityと同generation metadataを不可分に保持するmove-only candidate。
///
/// ```compile_fail
/// use ruster_control::FullServiceCandidateV1;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<FullServiceCandidateV1>();
/// ```
///
/// ```compile_fail
/// use ruster_control::FullServiceCandidateV1;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<FullServiceCandidateV1>();
/// ```
///
/// ```compile_fail
/// fn expose(candidate: ruster_control::FullServiceCandidateV1) {
///     let _ = candidate.candidate;
/// }
/// ```
///
/// ```compile_fail
/// fn expose(candidate: ruster_control::FullServiceCandidateV1) {
///     let _ = candidate.metadata;
/// }
/// ```
pub struct FullServiceCandidateV1 {
    candidate: ValidatedCandidate,
    metadata: FullServicePlanMetadataV1,
}

impl FullServiceCandidateV1 {
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.metadata.generation()
    }

    #[must_use]
    pub fn interfaces(&self) -> &[InterfaceBindingV1] {
        self.metadata.interfaces()
    }

    #[must_use]
    pub const fn tick(&self) -> TickBudgetsV1 {
        self.metadata.tick()
    }

    #[must_use]
    pub const fn required_runtime_bytes(&self) -> usize {
        self.metadata.required_runtime_bytes()
    }

    /// Returns the validated packet backend selected by the configuration.
    #[must_use]
    pub fn backend(&self) -> &ValidatedBackendV1 {
        self.metadata.backend()
    }

    #[must_use]
    pub fn authority(&self) -> ValidatedAuthority<'_> {
        self.candidate.authority()
    }

    #[must_use]
    pub const fn storage_shape(&self) -> FullServiceStorageShape {
        self.candidate.storage_shape()
    }

    /// Checks the value-only successor guard without mutating either candidate.
    ///
    /// First-error order is generation exhaustion, generation monotonicity, UDP
    /// hash-key reuse, TCP hash-key reuse, firewall hash-key reuse, storage
    /// shape, resolution policy, and ICMPv4-error policy. Interface bindings
    /// are intentionally outside this guard and are checked only by
    /// [`crate::classify_successor`] after these checks pass.
    pub fn validate_successor(&self, next: &Self) -> Result<(), SuccessorError> {
        self.candidate.validate_successor(&next.candidate)
    }
}

/// Full-service planningを完了できなかったvalue-freeな理由。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FullServicePlanningError {
    MissingService(RuntimeService),
}

/// Rejectされたconfigとcaller-supplied inputsを失わないmove-only failure。
///
/// `MissingService`はcold rejection pathであり、[`Self::into_parts`]で未変更のconfigとinputsを
/// 回収できます。このlarge inline errorをbox化するとallocation-free ownership-return契約を
/// 壊すため、意図的にinlineで保持します。
///
/// ```compile_fail
/// use ruster_control::FullServicePlanningFailure;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<FullServicePlanningFailure>();
/// ```
///
/// ```compile_fail
/// use ruster_control::FullServicePlanningFailure;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<FullServicePlanningFailure>();
/// ```
///
/// ```compile_fail
/// fn expose(failure: ruster_control::FullServicePlanningFailure) {
///     let _ = failure.error;
/// }
/// ```
///
/// ```compile_fail
/// fn expose(failure: ruster_control::FullServicePlanningFailure) {
///     let _ = failure.config;
/// }
/// ```
///
/// ```compile_fail
/// fn expose(failure: ruster_control::FullServicePlanningFailure) {
///     let _ = failure.inputs;
/// }
/// ```
pub struct FullServicePlanningFailure {
    error: FullServicePlanningError,
    config: ValidatedConfigV1,
    inputs: FullServicePlanInputs,
}

impl FullServicePlanningFailure {
    fn new(
        error: FullServicePlanningError,
        config: ValidatedConfigV1,
        inputs: FullServicePlanInputs,
    ) -> Self {
        Self {
            error,
            config,
            inputs,
        }
    }

    #[must_use]
    pub const fn error(&self) -> FullServicePlanningError {
        self.error
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FullServicePlanningError,
        ValidatedConfigV1,
        FullServicePlanInputs,
    ) {
        let Self {
            error,
            config,
            inputs,
        } = self;
        (error, config, inputs)
    }
}

fn full_service_storage_shape(
    resolution: ResolutionStorageShapeV1,
    icmpv4_errors: Icmpv4ErrorStorageShapeV1,
    nat44_udp: Nat44UdpStorageShapeV1,
    nat44_tcp: Nat44TcpStorageShapeV1,
    firewall_state_slots: u32,
) -> FullServiceStorageShape {
    let (
        resolution_states,
        resolution_actions,
        resolution_dynamic_neighbors,
        resolution_failure_holds,
        resolution_datagram_holds,
    ) = resolution.into_planning_parts();
    let (icmpv4_error_states, icmpv4_error_actions) = icmpv4_errors.into_planning_parts();
    let (
        udp_mappings,
        udp_peers,
        udp_mapping_buckets,
        udp_mapping_nodes,
        udp_peer_buckets,
        udp_peer_nodes,
        udp_port_owners,
    ) = nat44_udp.into_planning_parts();
    let (
        tcp_mappings,
        tcp_sessions,
        tcp_mapping_buckets,
        tcp_mapping_nodes,
        tcp_session_buckets,
        tcp_session_nodes,
        tcp_port_owners,
    ) = nat44_tcp.into_planning_parts();
    FullServiceStorageShape::new(
        ResolutionStorageShape::new(
            resolution_states,
            resolution_actions,
            resolution_dynamic_neighbors,
            resolution_failure_holds,
            resolution_datagram_holds,
        ),
        Icmpv4ErrorStorageShape::new(icmpv4_error_states, icmpv4_error_actions),
        Nat44UdpStoragePlan::new(
            udp_mappings,
            udp_peers,
            udp_mapping_buckets,
            udp_mapping_nodes,
            udp_peer_buckets,
            udp_peer_nodes,
            udp_port_owners,
        ),
        Nat44TcpStoragePlan::new(
            tcp_mappings,
            tcp_sessions,
            tcp_mapping_buckets,
            tcp_mapping_nodes,
            tcp_session_buckets,
            tcp_session_nodes,
            tcp_port_owners,
        ),
        firewall_state_slots,
    )
}

/// Validated V1 configを再確保せずに一つのfull-service planへmoveします。
///
/// reject時は[`FullServicePlanningFailure`]がconfigとinputsのownershipをcallerへ返します。
/// caller supplied keyのfreshness、runtime storage allocation、activation、applyは
/// この関数の責務ではありません。
#[allow(
    clippy::result_large_err,
    reason = "failure intentionally returns the consumed config and inputs without allocation"
)]
pub fn plan_full_service_v1(
    config: ValidatedConfigV1,
    inputs: FullServicePlanInputs,
) -> Result<FullServicePlanV1, FullServicePlanningFailure> {
    let missing = if config.resolution().is_none() {
        Some(RuntimeService::Resolution)
    } else if config.icmpv4_errors().is_none() {
        Some(RuntimeService::Icmpv4Errors)
    } else if config.nat44().and_then(|nat44| nat44.udp()).is_none() {
        Some(RuntimeService::Nat44Udp)
    } else if config.nat44().and_then(|nat44| nat44.tcp()).is_none() {
        Some(RuntimeService::Nat44Tcp)
    } else if config.firewall().is_none() {
        Some(RuntimeService::Firewall)
    } else {
        None
    };
    if let Some(service) = missing {
        return Err(FullServicePlanningFailure::new(
            FullServicePlanningError::MissingService(service),
            config,
            inputs,
        ));
    }

    let FullServicePlanInputs {
        generation,
        nat44_udp: nat44_udp_key,
        nat44_tcp: nat44_tcp_key,
        firewall: firewall_key,
    } = inputs;

    let (
        interfaces,
        core_interfaces,
        routes,
        neighbors,
        local_ipv4,
        ipv4_origin,
        resolution,
        icmpv4_errors,
        nat44,
        firewall,
        tick,
        runtime_storage,
        backend,
        required_runtime_bytes,
    ) = config.into_parts().into_planning_parts();

    let resolution =
        resolution.unwrap_or_else(|| unreachable!("presence was checked before consuming config"));
    let (resolution_policy, resolution_storage) = resolution.into_planning_parts();
    let icmpv4_errors = icmpv4_errors
        .unwrap_or_else(|| unreachable!("presence was checked before consuming config"));
    let (icmpv4_error_policy, icmpv4_error_storage) = icmpv4_errors.into_planning_parts();
    let nat44 =
        nat44.unwrap_or_else(|| unreachable!("presence was checked before consuming config"));
    let (nat44_udp, nat44_tcp) = nat44.into_planning_parts();
    let nat44_udp =
        nat44_udp.unwrap_or_else(|| unreachable!("presence was checked before consuming config"));
    let (
        nat44_udp_inside,
        nat44_udp_outside,
        nat44_udp_public_address,
        nat44_udp_first_port,
        nat44_udp_last_port,
        nat44_udp_policy,
        nat44_udp_storage,
    ) = nat44_udp.into_planning_parts();
    let nat44_tcp =
        nat44_tcp.unwrap_or_else(|| unreachable!("presence was checked before consuming config"));
    let (
        nat44_tcp_inside,
        nat44_tcp_outside,
        nat44_tcp_public_address,
        nat44_tcp_first_port,
        nat44_tcp_last_port,
        nat44_tcp_policy,
        nat44_tcp_storage,
    ) = nat44_tcp.into_planning_parts();
    let firewall =
        firewall.unwrap_or_else(|| unreachable!("presence was checked before consuming config"));
    let (firewall_rules, firewall_policy, firewall_state_slots) = firewall.into_planning_parts();
    let (
        tick_rx,
        tick_resolution_timer_scans,
        tick_failure_dispatch_scans,
        tick_generated_arp,
        tick_generated_icmpv4,
    ) = tick.into_planning_parts();
    let planned_tick = TickBudgetsV1 {
        rx: tick_rx,
        resolution_timer_scans: tick_resolution_timer_scans,
        failure_dispatch_scans: tick_failure_dispatch_scans,
        generated_arp: tick_generated_arp,
        generated_icmpv4: tick_generated_icmpv4,
    };
    let (
        runtime_resolution_storage,
        runtime_icmpv4_error_storage,
        runtime_nat44_udp_storage,
        runtime_nat44_tcp_storage,
        runtime_firewall_state_slots,
        runtime_required_bytes,
    ) = runtime_storage.into_planning_parts();
    let runtime_resolution_storage = runtime_resolution_storage
        .unwrap_or_else(|| unreachable!("resolution storage was checked before consuming config"));
    let runtime_icmpv4_error_storage = runtime_icmpv4_error_storage.unwrap_or_else(|| {
        unreachable!("ICMPv4 error storage was checked before consuming config")
    });
    let runtime_nat44_udp_storage = runtime_nat44_udp_storage
        .unwrap_or_else(|| unreachable!("UDP NAT storage was checked before consuming config"));
    let runtime_nat44_tcp_storage = runtime_nat44_tcp_storage
        .unwrap_or_else(|| unreachable!("TCP NAT storage was checked before consuming config"));
    let runtime_firewall_state_slots = runtime_firewall_state_slots
        .unwrap_or_else(|| unreachable!("firewall storage was checked before consuming config"));

    assert!(
        resolution_storage == runtime_resolution_storage,
        "validated resolution storage inventories disagree"
    );
    assert!(
        icmpv4_error_storage == runtime_icmpv4_error_storage,
        "validated ICMPv4 error storage inventories disagree"
    );
    assert!(
        nat44_udp_storage == runtime_nat44_udp_storage,
        "validated UDP NAT storage inventories disagree"
    );
    assert!(
        nat44_tcp_storage == runtime_nat44_tcp_storage,
        "validated TCP NAT storage inventories disagree"
    );
    assert_eq!(
        firewall_state_slots, runtime_firewall_state_slots,
        "validated firewall storage inventories disagree"
    );
    assert_eq!(
        required_runtime_bytes, runtime_required_bytes,
        "validated runtime byte inventories disagree"
    );

    let nat44_udp_input = Nat44UdpPublicationInput::new(
        nat44_udp_inside,
        nat44_udp_outside,
        nat44_udp_public_address,
        nat44_udp_first_port,
        nat44_udp_last_port,
        nat44_udp_policy,
        nat44_udp_key,
    );
    let nat44_tcp_input = Nat44TcpPublicationInput::new(
        nat44_tcp_inside,
        nat44_tcp_outside,
        nat44_tcp_public_address,
        nat44_tcp_first_port,
        nat44_tcp_last_port,
        nat44_tcp_policy,
        nat44_tcp_key,
    );
    let storage_shape = full_service_storage_shape(
        runtime_resolution_storage,
        runtime_icmpv4_error_storage,
        runtime_nat44_udp_storage,
        runtime_nat44_tcp_storage,
        runtime_firewall_state_slots,
    );
    let publication = PublicationPlan::new(
        generation,
        storage_shape,
        routes,
        core_interfaces,
        neighbors,
        local_ipv4,
        ipv4_origin,
        resolution_policy,
        icmpv4_error_policy,
    )
    .with_nat44_udp(nat44_udp_input)
    .with_nat44_tcp(nat44_tcp_input)
    .with_firewall(FirewallPublicationInput::new(
        firewall_rules,
        firewall_policy,
        firewall_key,
    ));

    Ok(FullServicePlanV1 {
        publication,
        metadata: FullServicePlanMetadataV1 {
            generation,
            interfaces,
            tick: planned_tick,
            required_runtime_bytes,
            backend,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_config::{parse, validate, ValidatedConfig, ValidationLimits, VersionedConfig};
    use ruster_core::SnapshotError;

    const fn limits() -> ValidationLimits {
        ValidationLimits {
            max_slots_per_table: 1_048_576,
            max_runtime_bytes: 1 << 30,
        }
    }

    fn validated(parsed: VersionedConfig) -> ValidatedConfigV1 {
        match validate(parsed, limits()).expect("full-service fixture must validate") {
            ValidatedConfig::V1(config) => config,
            _ => unreachable!("fixture selects schema V1"),
        }
    }

    fn config() -> ValidatedConfigV1 {
        validated(
            parse(include_bytes!("../tests/full-service.toml"))
                .expect("full-service fixture must parse"),
        )
    }

    fn config_without(service: RuntimeService) -> ValidatedConfigV1 {
        let VersionedConfig::V1(mut config) = parse(include_bytes!("../tests/full-service.toml"))
            .expect("full-service fixture must parse")
        else {
            unreachable!("fixture selects schema V1")
        };
        match service {
            RuntimeService::Resolution => config.resolution = None,
            RuntimeService::Icmpv4Errors => config.icmpv4_errors = None,
            RuntimeService::Nat44Udp => {
                config.nat44.as_mut().expect("fixture enables NAT44").udp = None;
            }
            RuntimeService::Nat44Tcp => {
                config.nat44.as_mut().expect("fixture enables NAT44").tcp = None;
            }
            RuntimeService::Firewall => config.firewall = None,
        }
        validated(VersionedConfig::V1(config))
    }

    fn inputs(generation: u64, seed: u64) -> FullServicePlanInputs {
        FullServicePlanInputs::new(
            NonZeroU64::new(generation).unwrap(),
            Nat44UdpHashKey::new(seed, seed + 1).unwrap(),
            Nat44TcpHashKey::new(seed + 2, seed + 3).unwrap(),
            FirewallHashKey::new(seed + 4, seed + 5).unwrap(),
        )
    }

    fn candidate(generation: u64, seed: u64) -> FullServiceCandidateV1 {
        let plan = match plan_full_service_v1(config(), inputs(generation, seed)) {
            Ok(plan) => plan,
            Err(failure) => panic!("fixture must plan: {:?}", failure.error()),
        };
        assert_eq!(plan.generation(), NonZeroU64::new(generation).unwrap());
        plan.into_candidate().expect("publication must validate")
    }

    #[test]
    fn candidate_error_taxonomy_collapses_lower_level_errors() {
        let cases = [
            (
                PublicationCandidateError::Forwarding(
                    ValidatedForwardingOwnerError::PublicationNonceExhausted,
                ),
                FullServiceCandidateError::ForwardingPublicationNonceExhausted,
            ),
            (
                PublicationCandidateError::Firewall(FirewallConfigError::PublicationNonceExhausted),
                FullServiceCandidateError::FirewallPublicationNonceExhausted,
            ),
            (
                PublicationCandidateError::Forwarding(ValidatedForwardingOwnerError::Snapshot(
                    SnapshotError::DuplicateRoute,
                )),
                FullServiceCandidateError::InternalInvariantViolation,
            ),
            (
                PublicationCandidateError::Firewall(FirewallConfigError::DuplicateRuleId),
                FullServiceCandidateError::InternalInvariantViolation,
            ),
            (
                PublicationCandidateError::Nat44RealmMismatch,
                FullServiceCandidateError::InternalInvariantViolation,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(full_service_candidate_error(error), expected);
        }
    }

    #[test]
    fn validated_config_into_parts_preserves_all_owned_box_allocations() {
        let config = config();
        let interfaces = config.interfaces().as_ptr();
        let interface_backing_pointers = config
            .interfaces()
            .iter()
            .map(|binding| (binding.name().as_ptr(), binding.device().as_ptr()))
            .collect::<Vec<_>>();
        let owned_box_pointers = [
            config.routes().as_ptr() as usize,
            config.core_interfaces().as_ptr() as usize,
            config.neighbors().as_ptr() as usize,
            config.local_ipv4().as_ptr() as usize,
            config
                .firewall()
                .expect("fixture enables firewall")
                .rules()
                .as_ptr() as usize,
        ];
        let plan = match plan_full_service_v1(config, inputs(1, 10)) {
            Ok(plan) => plan,
            Err(failure) => panic!("fixture must plan: {:?}", failure.error()),
        };
        assert_eq!(plan.interfaces().as_ptr(), interfaces);
        assert_eq!(plan.interfaces().len(), interface_backing_pointers.len());
        for (binding, (name, device)) in plan.interfaces().iter().zip(&interface_backing_pointers) {
            assert_eq!(binding.name().as_ptr(), *name);
            assert_eq!(binding.device().as_ptr(), *device);
        }
        let first = plan.into_candidate().expect("publication must validate");
        let second = candidate(2, 100);
        assert_eq!(first.interfaces().as_ptr(), interfaces);
        assert_eq!(first.interfaces().len(), interface_backing_pointers.len());
        for (binding, (name, device)) in first.interfaces().iter().zip(&interface_backing_pointers)
        {
            assert_eq!(binding.name().as_ptr(), *name);
            assert_eq!(binding.device().as_ptr(), *device);
        }
        assert_eq!(first.candidate.owned_box_pointers(), owned_box_pointers);
        assert_eq!(
            first.storage_shape(),
            FullServiceStorageShape::new(
                ResolutionStorageShape::new(2, 3, 4, 5, 6),
                Icmpv4ErrorStorageShape::new(6, 7),
                Nat44UdpStoragePlan::new(3, 9, 4, 3, 16, 9, 13),
                Nat44TcpStoragePlan::new(5, 17, 8, 5, 32, 17, 13),
                11,
            )
        );
        let first_authority = first.authority();
        assert_eq!(first_authority.generation(), first.generation());
        assert_eq!(
            first_authority.nat44_udp_hash_key(),
            Nat44UdpHashKey::new(10, 11).unwrap()
        );
        assert_eq!(
            first_authority.nat44_tcp_hash_key(),
            Nat44TcpHashKey::new(12, 13).unwrap()
        );
        assert_eq!(
            first_authority.firewall_config().hash_key(),
            FirewallHashKey::new(14, 15).unwrap()
        );
        let firewall_rules = first_authority.firewall_config().rules();
        assert_eq!(firewall_rules.len(), 2);
        assert_eq!([firewall_rules[0].id().0, firewall_rules[1].id().0], [2, 1]);
        assert_eq!(first.validate_successor(&second), Ok(()));
    }

    #[test]
    fn missing_service_failures_return_unchanged_inputs() {
        for (index, service) in [
            RuntimeService::Resolution,
            RuntimeService::Icmpv4Errors,
            RuntimeService::Nat44Udp,
            RuntimeService::Nat44Tcp,
            RuntimeService::Firewall,
        ]
        .into_iter()
        .enumerate()
        {
            let generation = 10 + index as u64;
            let seed = 1_000 + index as u64 * 10;
            let failure =
                match plan_full_service_v1(config_without(service), inputs(generation, seed)) {
                    Ok(_) => panic!("missing service must reject planning"),
                    Err(failure) => failure,
                };
            let (error, _config, inputs) = failure.into_parts();
            assert_eq!(error, FullServicePlanningError::MissingService(service));
            assert_eq!(inputs.generation, NonZeroU64::new(generation).unwrap());
            assert_eq!(
                inputs.nat44_udp,
                Nat44UdpHashKey::new(seed, seed + 1).unwrap()
            );
            assert_eq!(
                inputs.nat44_tcp,
                Nat44TcpHashKey::new(seed + 2, seed + 3).unwrap()
            );
            assert_eq!(
                inputs.firewall,
                FirewallHashKey::new(seed + 4, seed + 5).unwrap()
            );
        }
    }
}

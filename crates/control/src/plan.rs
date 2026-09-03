//! Pure, allocation-free static classification and diff between two full-service
//! candidates.
//!
//! [`plan_successor`] compares a prospective candidate against the currently
//! active one (or `None` for a first-time activation) without touching any
//! runtime. It uses the same candidate-only static classification as
//! `ruster-integration`'s actual publication path. Static eligibility does not
//! inspect the active-failure latch, backend quiescence, or runtime preflight;
//! an actual apply can therefore still be deferred or rejected after this
//! function reports an in-place-eligible successor. Every accessor this module
//! reads from [`FullServiceCandidateV1`] is allocation-free, so comparing two
//! candidates never allocates or scans runtime state.
//!
//! Section comparison covers the semantic candidate configuration: interface
//! bindings, routes, neighbors, local IPv4 bindings, IPv4 origin policy, tick
//! budgets, the selected packet backend, the five service authorities
//! (resolution policy, ICMPv4 error policy, NAT44 UDP/TCP config and hash key,
//! firewall config), and the aggregate storage shape. Publication generations,
//! nonces, snapshot authorities, allocation identities, and rule fingerprints
//! are not semantic sections and are never reported as changes.

use std::num::NonZeroU64;

use crate::{FullServiceCandidateV1, SuccessorError};

/// Which semantic config sections differ between two candidates.
///
/// This value contains only booleans and borrows no candidate state. It is
/// therefore cheap to return from the allocation-free dry-run API. The fields
/// are private so the public surface can grow without exposing construction
/// invariants; use the `*_changed` accessors to inspect a diff.
#[must_use]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct PlanSectionDiff {
    interfaces_changed: bool,
    routes_changed: bool,
    neighbors_changed: bool,
    local_ipv4_bindings_changed: bool,
    ipv4_origin_policy_changed: bool,
    tick_budgets_changed: bool,
    resolution_policy_changed: bool,
    icmpv4_error_policy_changed: bool,
    nat44_udp_config_changed: bool,
    nat44_udp_hash_key_changed: bool,
    nat44_tcp_config_changed: bool,
    nat44_tcp_hash_key_changed: bool,
    firewall_config_changed: bool,
    firewall_hash_key_changed: bool,
    storage_shape_changed: bool,
    backend_changed: bool,
}

impl PlanSectionDiff {
    #[must_use]
    pub const fn any_changed(&self) -> bool {
        let Self {
            interfaces_changed,
            routes_changed,
            neighbors_changed,
            local_ipv4_bindings_changed,
            ipv4_origin_policy_changed,
            tick_budgets_changed,
            resolution_policy_changed,
            icmpv4_error_policy_changed,
            nat44_udp_config_changed,
            nat44_udp_hash_key_changed,
            nat44_tcp_config_changed,
            nat44_tcp_hash_key_changed,
            firewall_config_changed,
            firewall_hash_key_changed,
            storage_shape_changed,
            backend_changed,
        } = *self;

        interfaces_changed
            || routes_changed
            || neighbors_changed
            || local_ipv4_bindings_changed
            || ipv4_origin_policy_changed
            || tick_budgets_changed
            || resolution_policy_changed
            || icmpv4_error_policy_changed
            || nat44_udp_config_changed
            || nat44_udp_hash_key_changed
            || nat44_tcp_config_changed
            || nat44_tcp_hash_key_changed
            || firewall_config_changed
            || firewall_hash_key_changed
            || storage_shape_changed
            || backend_changed
    }

    /// Returns whether any interface binding (`id`, name, device, or MAC)
    /// differs.
    #[must_use]
    pub const fn interfaces_changed(&self) -> bool {
        self.interfaces_changed
    }

    /// Returns whether the config-origin route table differs.
    #[must_use]
    pub const fn routes_changed(&self) -> bool {
        self.routes_changed
    }

    /// Returns whether the config-origin static-neighbor table differs.
    #[must_use]
    pub const fn neighbors_changed(&self) -> bool {
        self.neighbors_changed
    }

    /// Returns whether the config-origin local IPv4 binding table differs.
    #[must_use]
    pub const fn local_ipv4_bindings_changed(&self) -> bool {
        self.local_ipv4_bindings_changed
    }

    /// Returns whether the IPv4 origin policy differs.
    #[must_use]
    pub const fn ipv4_origin_policy_changed(&self) -> bool {
        self.ipv4_origin_policy_changed
    }

    /// Returns whether per-tick work budgets differ.
    #[must_use]
    pub const fn tick_budgets_changed(&self) -> bool {
        self.tick_budgets_changed
    }

    /// Returns whether the resolution policy differs.
    #[must_use]
    pub const fn resolution_policy_changed(&self) -> bool {
        self.resolution_policy_changed
    }

    /// Returns whether the ICMPv4 error policy differs.
    #[must_use]
    pub const fn icmpv4_error_policy_changed(&self) -> bool {
        self.icmpv4_error_policy_changed
    }

    /// Returns whether semantic UDP NAT44 config differs.
    #[must_use]
    pub const fn nat44_udp_config_changed(&self) -> bool {
        self.nat44_udp_config_changed
    }

    /// Returns whether the UDP NAT44 hash key differs.
    #[must_use]
    pub const fn nat44_udp_hash_key_changed(&self) -> bool {
        self.nat44_udp_hash_key_changed
    }

    /// Returns whether semantic TCP NAT44 config differs.
    #[must_use]
    pub const fn nat44_tcp_config_changed(&self) -> bool {
        self.nat44_tcp_config_changed
    }

    /// Returns whether the TCP NAT44 hash key differs.
    #[must_use]
    pub const fn nat44_tcp_hash_key_changed(&self) -> bool {
        self.nat44_tcp_hash_key_changed
    }

    /// Returns whether firewall rules or policy differ. Rule order remains
    /// significant because firewall evaluation uses first-match semantics.
    #[must_use]
    pub const fn firewall_config_changed(&self) -> bool {
        self.firewall_config_changed
    }

    /// Returns whether the firewall hash key differs.
    #[must_use]
    pub const fn firewall_hash_key_changed(&self) -> bool {
        self.firewall_hash_key_changed
    }

    /// Returns whether aggregate runtime storage shape differs.
    #[must_use]
    pub const fn storage_shape_changed(&self) -> bool {
        self.storage_shape_changed
    }

    /// Returns whether the packet backend or any of its cold setup values
    /// differs. Such a change requires rebuilding the worker/backend.
    #[must_use]
    pub const fn backend_changed(&self) -> bool {
        self.backend_changed
    }

    fn between(current: &FullServiceCandidateV1, next: &FullServiceCandidateV1) -> Self {
        let current_authority = current.authority();
        let next_authority = next.authority();
        let current_snapshot = current_authority.snapshot();
        let next_snapshot = next_authority.snapshot();
        let current_firewall = current_authority.firewall_config();
        let next_firewall = next_authority.firewall_config();
        Self {
            interfaces_changed: current.interfaces() != next.interfaces(),
            routes_changed: current_snapshot.routes() != next_snapshot.routes(),
            neighbors_changed: current_snapshot.neighbors() != next_snapshot.neighbors(),
            local_ipv4_bindings_changed: current_snapshot.local_ipv4()
                != next_snapshot.local_ipv4(),
            ipv4_origin_policy_changed: current_snapshot.ipv4_origin_policy()
                != next_snapshot.ipv4_origin_policy(),
            tick_budgets_changed: current.tick() != next.tick(),
            resolution_policy_changed: current_authority.resolution_policy()
                != next_authority.resolution_policy(),
            icmpv4_error_policy_changed: current_authority.icmpv4_error_policy()
                != next_authority.icmpv4_error_policy(),
            nat44_udp_config_changed: !current_authority
                .nat44_udp_config()
                .semantic_eq(next_authority.nat44_udp_config()),
            nat44_udp_hash_key_changed: current_authority.nat44_udp_hash_key()
                != next_authority.nat44_udp_hash_key(),
            nat44_tcp_config_changed: !current_authority
                .nat44_tcp_config()
                .semantic_eq(next_authority.nat44_tcp_config()),
            nat44_tcp_hash_key_changed: current_authority.nat44_tcp_hash_key()
                != next_authority.nat44_tcp_hash_key(),
            firewall_config_changed: !current_firewall.semantic_eq(next_firewall),
            firewall_hash_key_changed: current_firewall.hash_key() != next_firewall.hash_key(),
            storage_shape_changed: current.storage_shape() != next.storage_shape(),
            backend_changed: current.backend() != next.backend(),
        }
    }
}

/// Why applying `next` after `current` would require a worker restart
/// instead of an in-place successor transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlanRestartRequired {
    /// The candidate-bound external storage shape changed; a cold
    /// rebuild/restart is required before this candidate can be applied.
    RuntimeStorageShapeChanged,
    /// Interface bindings changed and the bound backend resources need to be
    /// re-attached. Other in-place semantic changes and the mandatory fresh
    /// hash-key rotations may coexist in the same diff; inspect the full
    /// [`PlanSectionDiff`] before deciding how to rebuild.
    InterfaceBindingsChanged,
    /// The resolution policy must be installed by a rebuilt worker.
    ResolutionPolicyChanged,
    /// The ICMPv4-error policy must be installed by a rebuilt worker.
    Icmpv4ErrorPolicyChanged,
    /// The packet backend or its cold setup geometry changed. The existing
    /// worker must not apply an AF_PACKET/AF_XDP transition in place.
    BackendChanged,
}

/// Candidate-only static classification shared by dry-run planning and the
/// integration apply path.
///
/// This classification checks only the two candidates. It does not inspect an
/// active-failure latch, backend identity or quiescence, or any runtime
/// preflight. [`Self::InPlaceEligible`] therefore means that the candidate pair
/// passed static successor checks and needs no cold restart; an actual
/// publication can still be deferred or rejected by its dynamic safety gates.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FullServiceSuccessorClassification {
    /// Static successor checks pass and no cold restart is required.
    InPlaceEligible,
    /// The static successor guard reaches a cold-restart decision because the
    /// indicated resource must be rebuilt before applying the successor.
    RestartRequired(PlanRestartRequired),
    /// The successor guard rejected the candidate pair.
    Rejected(SuccessorError),
}

/// Generation metadata returned by every full-service plan result.
///
/// `previous_generation` is `None` only for an initial activation. This value
/// contains no candidate authority, hash key, or allocation identity.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PlanGenerationTransition {
    previous_generation: Option<NonZeroU64>,
    next_generation: NonZeroU64,
}

impl PlanGenerationTransition {
    const fn initial(next_generation: NonZeroU64) -> Self {
        Self {
            previous_generation: None,
            next_generation,
        }
    }

    const fn successor(previous_generation: NonZeroU64, next_generation: NonZeroU64) -> Self {
        Self {
            previous_generation: Some(previous_generation),
            next_generation,
        }
    }

    /// Returns the generation being replaced, or `None` for initial activation.
    #[must_use]
    pub const fn previous_generation(self) -> Option<NonZeroU64> {
        self.previous_generation
    }

    /// Returns the generation supplied by the prospective candidate.
    #[must_use]
    pub const fn next_generation(self) -> NonZeroU64 {
        self.next_generation
    }

    /// Returns whether this transition describes initial activation.
    #[must_use]
    pub const fn is_initial(self) -> bool {
        self.previous_generation.is_none()
    }
}

/// The typed dry-run outcome of comparing a prospective candidate against the
/// currently active one.
///
/// Every outcome is value-only and allocation-free. The classification is
/// candidate-only: an in-place-eligible result does not promise that backend
/// quiescence, the active-failure latch, or the five runtime preflights will
/// succeed. A rejected successor also carries a semantic section diff and
/// generation transition, so operator tooling can inspect the proposed change
/// even though the apply path stops at its successor guard.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlanOutcome {
    /// There is no currently active candidate: this is a first-time cold
    /// activation, not a successor transaction. No semantic diff exists, but
    /// the prospective next generation is still returned.
    InitialActivation {
        transition: PlanGenerationTransition,
    },
    /// Static successor checks accept `next` and no restart is required. This
    /// is not a dynamic apply guarantee: runtime publication can still defer
    /// or reject the candidate.
    InPlaceEligible {
        diff: PlanSectionDiff,
        transition: PlanGenerationTransition,
    },
    /// Candidate-only static checks select a worker restart instead of an
    /// in-place apply. Other semantic changes and mandatory hash-key rotations
    /// can coexist with the restart reason.
    RestartRequired {
        reason: PlanRestartRequired,
        diff: PlanSectionDiff,
        transition: PlanGenerationTransition,
    },
    /// The successor guard rejects `next` outright because of a
    /// stale/duplicate generation or reused hash key. `next` cannot be applied
    /// at all in this state, but the semantic diff and generation transition
    /// remain available for operator review.
    Rejected {
        error: SuccessorError,
        diff: PlanSectionDiff,
        transition: PlanGenerationTransition,
    },
}

impl PlanOutcome {
    /// Whether this outcome corresponds to a worker restart being needed.
    #[must_use]
    pub const fn requires_restart(&self) -> bool {
        matches!(self, Self::RestartRequired { .. })
    }

    /// Returns the candidate-only static classification represented by this
    /// outcome. Initial activation has no successor classification.
    #[must_use]
    pub const fn classification(&self) -> Option<FullServiceSuccessorClassification> {
        match self {
            Self::InitialActivation { .. } => None,
            Self::InPlaceEligible { .. } => {
                Some(FullServiceSuccessorClassification::InPlaceEligible)
            }
            Self::RestartRequired { reason, .. } => {
                Some(FullServiceSuccessorClassification::RestartRequired(*reason))
            }
            Self::Rejected { error, .. } => {
                Some(FullServiceSuccessorClassification::Rejected(*error))
            }
        }
    }

    /// Returns the generation transition carried by this result.
    #[must_use = "inspect the generation transition"]
    pub const fn generation_transition(&self) -> PlanGenerationTransition {
        match self {
            Self::InitialActivation { transition }
            | Self::InPlaceEligible { transition, .. }
            | Self::RestartRequired { transition, .. }
            | Self::Rejected { transition, .. } => *transition,
        }
    }

    /// Returns the previous generation, or `None` for initial activation.
    #[must_use]
    pub const fn previous_generation(&self) -> Option<NonZeroU64> {
        self.generation_transition().previous_generation()
    }

    /// Returns the prospective next generation.
    #[must_use]
    pub const fn next_generation(&self) -> NonZeroU64 {
        self.generation_transition().next_generation()
    }

    /// Returns the section-level diff, when one was computed.
    ///
    /// [`Self::InitialActivation`] has no diff because there is no prior
    /// candidate. All successor outcomes, including [`Self::Rejected`], expose
    /// a diff. Rejected outcomes compute it only after the successor guard has
    /// been evaluated, so the comparison cannot alter apply classification.
    #[must_use]
    pub const fn section_diff(&self) -> Option<&PlanSectionDiff> {
        match self {
            Self::InitialActivation { .. } => None,
            Self::InPlaceEligible { diff, .. } | Self::RestartRequired { diff, .. } => Some(diff),
            Self::Rejected { diff, .. } => Some(diff),
        }
    }

    /// Returns the successor-guard error for a rejected outcome.
    #[must_use]
    pub const fn rejection_error(&self) -> Option<SuccessorError> {
        match self {
            Self::Rejected { error, .. } => Some(*error),
            Self::InitialActivation { .. }
            | Self::InPlaceEligible { .. }
            | Self::RestartRequired { .. } => None,
        }
    }
}

/// Classifies a candidate pair using the one static successor decision shared
/// by dry-run planning and the integration publication path.
///
/// The checks run in their actual first-error order: generation exhaustion,
/// generation monotonicity, UDP key reuse, TCP key reuse, firewall key reuse,
/// storage shape, resolution policy, ICMPv4-error policy, and finally interface
/// bindings and backend identity after the successor guard succeeds. Storage shape is therefore
/// classified before policy changes, while interface bindings are inspected
/// only after all successor-guard checks pass.
#[must_use = "inspect the static successor classification"]
pub fn classify_successor(
    current: &FullServiceCandidateV1,
    next: &FullServiceCandidateV1,
) -> FullServiceSuccessorClassification {
    match current.validate_successor(next) {
        Err(SuccessorError::StorageShapeChanged) => {
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::RuntimeStorageShapeChanged,
            )
        }
        Err(SuccessorError::ResolutionPolicyChanged) => {
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::ResolutionPolicyChanged,
            )
        }
        Err(SuccessorError::Icmpv4ErrorPolicyChanged) => {
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::Icmpv4ErrorPolicyChanged,
            )
        }
        Err(error) => FullServiceSuccessorClassification::Rejected(error),
        Ok(()) if current.backend() != next.backend() => {
            FullServiceSuccessorClassification::RestartRequired(PlanRestartRequired::BackendChanged)
        }
        Ok(()) if current.interfaces() != next.interfaces() => {
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::InterfaceBindingsChanged,
            )
        }
        Ok(()) => FullServiceSuccessorClassification::InPlaceEligible,
    }
}

/// Dry-run: classify what would happen if `next` were applied after
/// `current` (or as a first activation, if `current` is `None`), without
/// touching any runtime.
///
/// This uses the exact candidate-only static classification that
/// `ruster-integration`'s bound publication path performs before an apply is
/// allowed to mutate anything. The first-error order is generation exhausted,
/// generation monotonicity, UDP key reuse, TCP key reuse, firewall key reuse,
/// storage shape, resolution policy, ICMPv4-error policy, backend identity, and
/// then interface bindings. Static classification does not run the
/// active-failure latch, backend quiescence, or runtime preflights, so an
/// in-place-eligible result can still be deferred or rejected by actual
/// publication.
#[must_use = "inspect the planned outcome"]
pub fn plan_successor(
    current: Option<&FullServiceCandidateV1>,
    next: &FullServiceCandidateV1,
) -> PlanOutcome {
    let Some(current) = current else {
        return PlanOutcome::InitialActivation {
            transition: PlanGenerationTransition::initial(next.generation()),
        };
    };
    let transition = PlanGenerationTransition::successor(current.generation(), next.generation());
    let classification = classify_successor(current, next);
    let diff = PlanSectionDiff::between(current, next);
    match classification {
        FullServiceSuccessorClassification::InPlaceEligible => {
            PlanOutcome::InPlaceEligible { diff, transition }
        }
        FullServiceSuccessorClassification::RestartRequired(reason) => {
            PlanOutcome::RestartRequired {
                reason,
                diff,
                transition,
            }
        }
        FullServiceSuccessorClassification::Rejected(error) => PlanOutcome::Rejected {
            error,
            diff,
            transition,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use ruster_config::{
        parse, validate, AfXdpResourceV1, BackendV1, FirewallActionV1, ValidatedConfig,
        ValidatedConfigV1, ValidationLimits, VersionedConfig, XdpAttachModeV1, XdpRingsV1,
        XdpUmemV1,
    };
    use ruster_core::{FirewallHashKey, Nat44TcpHashKey, Nat44UdpHashKey};

    use super::*;
    use crate::{plan_full_service_v1, FullServicePlanInputs};

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

    fn parsed_fixture() -> VersionedConfig {
        parse(include_bytes!("../tests/full-service.toml")).expect("fixture must parse")
    }

    fn inputs(generation: u64, seed: u64) -> FullServicePlanInputs {
        FullServicePlanInputs::new(
            NonZeroU64::new(generation).unwrap(),
            Nat44UdpHashKey::new(seed, seed + 1).unwrap(),
            Nat44TcpHashKey::new(seed + 2, seed + 3).unwrap(),
            FirewallHashKey::new(seed + 4, seed + 5).unwrap(),
        )
    }

    fn candidate_from(
        config: VersionedConfig,
        generation: u64,
        seed: u64,
    ) -> FullServiceCandidateV1 {
        candidate_from_inputs(config, inputs(generation, seed))
    }

    fn candidate_from_inputs(
        config: VersionedConfig,
        inputs: FullServicePlanInputs,
    ) -> FullServiceCandidateV1 {
        let plan = plan_full_service_v1(validated(config), inputs)
            .unwrap_or_else(|failure| panic!("fixture must plan: {:?}", failure.error()));
        plan.into_candidate().expect("publication must validate")
    }

    fn candidate_with_key_seeds(
        generation: u64,
        nat44_udp_seed: u64,
        nat44_tcp_seed: u64,
        firewall_seed: u64,
    ) -> FullServiceCandidateV1 {
        candidate_from_inputs(
            parsed_fixture(),
            FullServicePlanInputs::new(
                NonZeroU64::new(generation).unwrap(),
                Nat44UdpHashKey::new(nat44_udp_seed, nat44_udp_seed + 1).unwrap(),
                Nat44TcpHashKey::new(nat44_tcp_seed, nat44_tcp_seed + 1).unwrap(),
                FirewallHashKey::new(firewall_seed, firewall_seed + 1).unwrap(),
            ),
        )
    }

    fn candidate(generation: u64, seed: u64) -> FullServiceCandidateV1 {
        candidate_from(parsed_fixture(), generation, seed)
    }

    fn with_mutated_fixture(mutate: impl FnOnce(&mut VersionedConfig)) -> VersionedConfig {
        let mut config = parsed_fixture();
        mutate(&mut config);
        config
    }

    fn af_xdp_backend() -> BackendV1 {
        BackendV1::AfXdp {
            resources: vec![
                AfXdpResourceV1 {
                    interface: "wan".to_owned(),
                    queue_id: 0,
                },
                AfXdpResourceV1 {
                    interface: "lan".to_owned(),
                    queue_id: 1,
                },
            ],
            xskmap_max_entries: 2,
            bind_flags: 1 << 3,
            attach_mode: XdpAttachModeV1::Skb,
            umem: XdpUmemV1 {
                frame_count: 2,
                frame_size: 2_048,
                headroom: 256,
                rx_frames: 1,
                generated_frames: 1,
                raw_flags: 0,
            },
            rings: XdpRingsV1 {
                fill: 4,
                rx: 4,
                tx: 4,
                completion: 4,
            },
        }
    }

    #[test]
    fn initial_activation_has_no_prior_candidate_and_no_diff() {
        let next = candidate(1, 0);
        let outcome = plan_successor(None, &next);
        assert!(matches!(outcome, PlanOutcome::InitialActivation { .. }));
        assert_eq!(outcome.section_diff(), None);
        assert!(!outcome.requires_restart());
        assert_eq!(outcome.previous_generation(), None);
        assert_eq!(outcome.next_generation(), NonZeroU64::new(1).unwrap());
        assert_eq!(
            outcome.generation_transition(),
            PlanGenerationTransition::initial(NonZeroU64::new(1).unwrap())
        );
    }

    /// Every test below moves to a fresh generation with a fresh seed
    /// (`candidate(1, 0)` -> `candidate(2, 100)` or a mutated fixture at
    /// `(2, 100)`), because [`SuccessorError`] rejects any successor that
    /// reuses a prior generation's NAT44/firewall hash key (PUB-003). That
    /// mandatory rotation means the three `*_hash_key_changed` diff fields
    /// are `true` in every one of these outcomes, independent of whatever
    /// section the test is actually targeting.
    const fn rotated_hash_keys_only() -> PlanSectionDiff {
        PlanSectionDiff {
            nat44_udp_hash_key_changed: true,
            nat44_tcp_hash_key_changed: true,
            firewall_hash_key_changed: true,
            ..unchanged_diff()
        }
    }

    const fn unchanged_diff() -> PlanSectionDiff {
        PlanSectionDiff {
            interfaces_changed: false,
            routes_changed: false,
            neighbors_changed: false,
            local_ipv4_bindings_changed: false,
            ipv4_origin_policy_changed: false,
            tick_budgets_changed: false,
            resolution_policy_changed: false,
            icmpv4_error_policy_changed: false,
            nat44_udp_config_changed: false,
            nat44_udp_hash_key_changed: false,
            nat44_tcp_config_changed: false,
            nat44_tcp_hash_key_changed: false,
            firewall_config_changed: false,
            firewall_hash_key_changed: false,
            storage_shape_changed: false,
            backend_changed: false,
        }
    }

    #[test]
    fn section_diff_any_changed_is_false_for_default_and_true_for_every_category() {
        assert!(!PlanSectionDiff::default().any_changed());
        let diffs = [
            PlanSectionDiff {
                interfaces_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                routes_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                neighbors_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                local_ipv4_bindings_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                ipv4_origin_policy_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                tick_budgets_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                resolution_policy_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                icmpv4_error_policy_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                nat44_udp_config_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                nat44_udp_hash_key_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                nat44_tcp_config_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                nat44_tcp_hash_key_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                firewall_config_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                firewall_hash_key_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                storage_shape_changed: true,
                ..PlanSectionDiff::default()
            },
            PlanSectionDiff {
                backend_changed: true,
                ..PlanSectionDiff::default()
            },
        ];
        assert!(diffs.into_iter().all(|diff| diff.any_changed()));
    }

    #[test]
    fn backend_change_is_restart_required_and_is_reported_in_the_diff() {
        let current = candidate(1, 0);
        let next_source = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.backend = Some(af_xdp_backend());
        });
        let next = candidate_from(next_source, 2, 100);
        let outcome = plan_successor(Some(&current), &next);

        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired {
                reason: PlanRestartRequired::BackendChanged,
                ..
            }
        ));
        assert!(outcome.requires_restart());
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                backend_changed: true,
                nat44_udp_hash_key_changed: true,
                nat44_tcp_hash_key_changed: true,
                firewall_hash_key_changed: true,
                ..unchanged_diff()
            })
        );
        assert!(outcome
            .section_diff()
            .expect("backend restart has an operator-visible diff")
            .backend_changed());
    }

    #[test]
    fn unchanged_config_successor_is_in_place_eligible_with_only_hash_key_rotation_diff() {
        let current = candidate(1, 0);
        let next = candidate(2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(outcome.section_diff(), Some(&rotated_hash_keys_only()));
        assert!(!outcome.requires_restart());
        assert!(outcome.section_diff().unwrap().any_changed());
        assert_eq!(outcome.previous_generation(), Some(current.generation()));
        assert_eq!(outcome.next_generation(), next.generation());
        assert_eq!(
            outcome.classification(),
            Some(FullServiceSuccessorClassification::InPlaceEligible)
        );
    }

    #[test]
    fn stale_generation_is_rejected_with_no_diff() {
        let current = candidate(2, 0);
        let next = candidate(1, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::Rejected { .. }));
        assert_eq!(outcome.section_diff(), Some(&rotated_hash_keys_only()));
        assert_eq!(
            outcome.rejection_error(),
            Some(SuccessorError::GenerationNotIncreasing)
        );
        assert!(!outcome.requires_restart());
        assert_eq!(outcome.previous_generation(), Some(current.generation()));
        assert_eq!(outcome.next_generation(), next.generation());
        assert_eq!(
            outcome.generation_transition(),
            PlanGenerationTransition::successor(current.generation(), next.generation())
        );
    }

    #[test]
    fn reused_nat44_udp_hash_key_is_rejected() {
        let current = candidate(1, 0);
        let next = candidate(2, 0);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::Rejected { .. }));
        assert_eq!(
            outcome.rejection_error(),
            Some(SuccessorError::Nat44UdpHashKeyReused)
        );
        assert_eq!(outcome.section_diff(), Some(&unchanged_diff()));
        assert!(outcome.section_diff().is_some());
    }

    #[test]
    fn reused_nat44_tcp_hash_key_is_rejected_after_udp_rotation() {
        let current = candidate_with_key_seeds(1, 0, 2, 4);
        let next = candidate_with_key_seeds(2, 100, 2, 104);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::Rejected { .. }));
        assert_eq!(
            outcome.rejection_error(),
            Some(SuccessorError::Nat44TcpHashKeyReused)
        );
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                nat44_udp_hash_key_changed: true,
                firewall_hash_key_changed: true,
                ..unchanged_diff()
            })
        );
    }

    #[test]
    fn reused_firewall_hash_key_is_rejected_after_nat_rotations() {
        let current = candidate_with_key_seeds(1, 0, 2, 4);
        let next = candidate_with_key_seeds(2, 100, 102, 4);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::Rejected { .. }));
        assert_eq!(
            outcome.rejection_error(),
            Some(SuccessorError::FirewallHashKeyReused)
        );
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                nat44_udp_hash_key_changed: true,
                nat44_tcp_hash_key_changed: true,
                ..unchanged_diff()
            })
        );
    }

    #[test]
    fn exhausted_generation_is_rejected_before_other_successor_checks() {
        let current = candidate(u64::MAX, 0);
        let next = candidate(u64::MAX, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert_eq!(
            outcome.rejection_error(),
            Some(SuccessorError::GenerationExhausted)
        );
        assert!(outcome.section_diff().is_some());
    }

    #[test]
    fn interface_change_is_restart_required_and_diff_marks_only_interfaces() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.interfaces[0].mac = "02:00:00:00:00:09".to_owned();
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired {
                reason: PlanRestartRequired::InterfaceBindingsChanged,
                ..
            }
        ));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                interfaces_changed: true,
                nat44_udp_hash_key_changed: true,
                nat44_tcp_hash_key_changed: true,
                firewall_hash_key_changed: true,
                ..PlanSectionDiff::default()
            })
        );
        assert!(outcome.requires_restart());
        assert_eq!(outcome.previous_generation(), Some(current.generation()));
        assert_eq!(outcome.next_generation(), next.generation());
    }

    #[test]
    fn nat44_udp_capacity_change_is_restart_required_via_storage_shape() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config
                .nat44
                .as_mut()
                .unwrap()
                .udp
                .as_mut()
                .unwrap()
                .capacity
                .mappings += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired {
                reason: PlanRestartRequired::RuntimeStorageShapeChanged,
                ..
            }
        ));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                storage_shape_changed: true,
                nat44_udp_hash_key_changed: true,
                nat44_tcp_hash_key_changed: true,
                firewall_hash_key_changed: true,
                ..PlanSectionDiff::default()
            })
        );
        assert!(outcome.requires_restart());
        assert_eq!(outcome.previous_generation(), Some(current.generation()));
        assert_eq!(outcome.next_generation(), next.generation());
    }

    #[test]
    fn storage_shape_restart_precedes_interface_restart() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.interfaces[0].device = "eth9".to_owned();
            config
                .nat44
                .as_mut()
                .unwrap()
                .udp
                .as_mut()
                .unwrap()
                .capacity
                .mappings += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired {
                reason: PlanRestartRequired::RuntimeStorageShapeChanged,
                ..
            }
        ));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                interfaces_changed: true,
                storage_shape_changed: true,
                nat44_udp_hash_key_changed: true,
                nat44_tcp_hash_key_changed: true,
                firewall_hash_key_changed: true,
                ..PlanSectionDiff::default()
            })
        );
    }

    #[test]
    fn storage_shape_restart_precedes_resolution_policy_restart() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.resolution.as_mut().unwrap().policy.interval_ms += 1;
            config
                .nat44
                .as_mut()
                .unwrap()
                .udp
                .as_mut()
                .unwrap()
                .capacity
                .mappings += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired {
                reason: PlanRestartRequired::RuntimeStorageShapeChanged,
                ..
            }
        ));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                storage_shape_changed: true,
                resolution_policy_changed: true,
                ..rotated_hash_keys_only()
            })
        );
        assert_eq!(outcome.rejection_error(), None);
    }

    #[test]
    fn interface_restart_retains_forwarding_tick_and_key_rotation_diff() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.interfaces[0].mac = "02:00:00:00:00:09".to_owned();
            config.routes[0].via = Some("198.51.100.2".to_owned());
            config.tick.as_mut().unwrap().rx += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired {
                reason: PlanRestartRequired::InterfaceBindingsChanged,
                ..
            }
        ));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                interfaces_changed: true,
                routes_changed: true,
                tick_budgets_changed: true,
                nat44_udp_hash_key_changed: true,
                nat44_tcp_hash_key_changed: true,
                firewall_hash_key_changed: true,
                ..PlanSectionDiff::default()
            })
        );
    }

    #[test]
    fn resolution_policy_value_change_requires_restart_with_operator_diff() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.resolution.as_mut().unwrap().policy.interval_ms += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired {
                reason: PlanRestartRequired::ResolutionPolicyChanged,
                ..
            }
        ));
        assert_eq!(outcome.rejection_error(), None);
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                resolution_policy_changed: true,
                ..rotated_hash_keys_only()
            })
        );
        assert!(outcome.requires_restart());
        assert!(outcome
            .section_diff()
            .expect("restart diff is operator-visible")
            .resolution_policy_changed());
    }

    #[test]
    fn icmpv4_error_policy_value_change_requires_restart_with_operator_diff() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.icmpv4_errors.as_mut().unwrap().policy.interval_ms += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired {
                reason: PlanRestartRequired::Icmpv4ErrorPolicyChanged,
                ..
            }
        ));
        assert_eq!(outcome.rejection_error(), None);
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                icmpv4_error_policy_changed: true,
                ..rotated_hash_keys_only()
            })
        );
        assert!(outcome.requires_restart());
        assert!(outcome
            .section_diff()
            .expect("restart diff is operator-visible")
            .icmpv4_error_policy_changed());
    }

    #[test]
    fn firewall_config_value_change_is_in_place_eligible_without_restart() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.firewall.as_mut().unwrap().policy.udp_idle_ttl_ms += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                firewall_config_changed: true,
                ..rotated_hash_keys_only()
            })
        );
        assert!(!outcome.requires_restart());
    }

    #[test]
    fn firewall_rule_change_is_in_place_eligible_and_compared_canonically() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.firewall.as_mut().unwrap().rules[0].action = FirewallActionV1::Deny;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                firewall_config_changed: true,
                ..rotated_hash_keys_only()
            })
        );
    }

    #[test]
    fn route_change_is_in_place_eligible_and_does_not_report_identity_fields() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.routes[0].via = Some("198.51.100.2".to_owned());
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                routes_changed: true,
                ..rotated_hash_keys_only()
            })
        );
    }

    #[test]
    fn neighbor_change_is_in_place_eligible_and_compared_semantically() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.neighbors[0].mac = "02:00:00:00:00:09".to_owned();
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                neighbors_changed: true,
                ..rotated_hash_keys_only()
            })
        );
    }

    #[test]
    fn local_ipv4_binding_change_is_in_place_eligible_and_compared_semantically() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.addresses[1].ipv4 = "192.0.2.2/24".to_owned();
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                local_ipv4_bindings_changed: true,
                ..rotated_hash_keys_only()
            })
        );
    }

    #[test]
    fn ipv4_origin_policy_change_is_in_place_eligible_and_compared_semantically() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.ipv4_origin.as_mut().unwrap().default_ttl = 63;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                ipv4_origin_policy_changed: true,
                ..rotated_hash_keys_only()
            })
        );
    }

    #[test]
    fn tick_budget_change_is_in_place_eligible_and_compared_semantically() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config.tick.as_mut().unwrap().rx += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                tick_budgets_changed: true,
                ..rotated_hash_keys_only()
            })
        );
    }

    #[test]
    fn nat44_udp_semantic_policy_change_is_in_place_eligible() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config
                .nat44
                .as_mut()
                .unwrap()
                .udp
                .as_mut()
                .unwrap()
                .idle_ttl_ms += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                nat44_udp_config_changed: true,
                ..rotated_hash_keys_only()
            })
        );
    }

    #[test]
    fn nat44_tcp_semantic_policy_change_is_in_place_eligible() {
        let current = candidate(1, 0);
        let mutated = with_mutated_fixture(|config| {
            let VersionedConfig::V1(config) = config else {
                unreachable!("fixture selects schema V1")
            };
            config
                .nat44
                .as_mut()
                .unwrap()
                .tcp
                .as_mut()
                .unwrap()
                .idle_ttl_ms += 1;
        });
        let next = candidate_from(mutated, 2, 100);
        let outcome = plan_successor(Some(&current), &next);
        assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
        assert_eq!(
            outcome.section_diff(),
            Some(&PlanSectionDiff {
                nat44_tcp_config_changed: true,
                ..rotated_hash_keys_only()
            })
        );
    }
}

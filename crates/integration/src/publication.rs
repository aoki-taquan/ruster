use ruster_control::{
    classify_successor, FullServiceCandidateV1, FullServiceStorageShape,
    FullServiceSuccessorClassification, InterfaceBindingV1, PlanOutcome, PlanRestartRequired,
    SuccessorError, TickBudgetsV1,
};
#[cfg(test)]
use ruster_control::{
    Icmpv4ErrorStorageShape, Nat44TcpStoragePlan, Nat44UdpStoragePlan, ResolutionStorageShape,
};
use ruster_core::{
    BoundPublicationBackend, DirectoryBucket, DirectoryNode, FirewallReconcileError,
    FirewallReconcileReport, FirewallRuntime, Icmpv4ErrorPublicationError,
    Icmpv4ErrorPublicationReport, Icmpv4ErrorRuntime, MatchedPublicationQuiescenceGuard,
    Nat44TcpConfig, Nat44TcpHashKey, Nat44TcpIndexStorage, Nat44TcpMappingSlot,
    Nat44TcpReconcileError, Nat44TcpReconcileReport, Nat44TcpRuntime, Nat44TcpRuntimeConfigError,
    Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpHashKey, Nat44UdpIndexStorage,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpReconcileError, Nat44UdpReconcileReport,
    Nat44UdpRuntime, Nat44UdpRuntimeConfigError, PortOwnerSlot, PublicationBackendAuthority,
    PublicationOwnerBinding, PublicationQuiescence, PublicationQuiescenceBackend,
    PublicationQuiescenceDisposition, ResolutionPublicationError, ResolutionPublicationReport,
    ResolutionRuntime,
};
#[cfg(test)]
use ruster_core::{
    FirewallCounters, Icmpv4ErrorCounters, Nat44TcpCounters, Nat44UdpCounters, ResolutionCounters,
    ResolutionFailureCounters,
};
use ruster_runtime::{
    observability::{BackendObservabilityStats, ObservabilityRecorder, ObservabilitySnapshot},
    ActivePublicationStatus, ActiveTickAuthority, FirewallServiceView, FullServicePublication,
    FullServiceView, Nat44TcpServiceView, Nat44UdpServiceView, PublicationRejection, TickBudgets,
};

use crate::storage::{FullServiceRuntimeStorage, RuntimeStorageSlices};

/// Reason why cold initial activation did not complete.
///
/// UDP and TCP constructor errors remain typed so callers can distinguish a
/// shape/config invariant failure from process-lifetime
/// `RuntimeIdentityExhausted`. Activation is sequential: after the shape and
/// byte checks pass, a late TCP failure can occur after earlier runtimes cleared
/// their storage and after UDP consumed a runtime identity. The returned
/// candidate remains exact, but storage contents are not rolled back and the
/// failure must not be treated as automatically retry-safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InitialActivationError {
    /// The external storage was allocated for a different candidate shape.
    StorageShapeMismatch,
    /// The external storage byte accounting differs from the candidate.
    StorageRequiredBytesMismatch,
    /// The UDP NAT runtime constructor rejected activation.
    Nat44UdpRuntime(Nat44UdpRuntimeConfigError),
    /// The TCP NAT runtime constructor rejected activation.
    Nat44TcpRuntime(Nat44TcpRuntimeConfigError),
}

fn nat44_udp_activation_error(error: Nat44UdpRuntimeConfigError) -> InitialActivationError {
    InitialActivationError::Nat44UdpRuntime(error)
}

fn nat44_tcp_activation_error(error: Nat44TcpRuntimeConfigError) -> InitialActivationError {
    InitialActivationError::Nat44TcpRuntime(error)
}

/// Failed cold activation with ownership of the exact candidate preserved.
///
/// Candidate authority can include secret hash keys. The generic rejection has
/// private fields and deliberately implements neither `Debug` nor `Clone`.
/// Recover values in `(candidate, error)` order with
/// [`PublicationRejection::into_parts`].
///
/// ```compile_fail
/// use ruster_integration::InitialActivationFailure;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<InitialActivationFailure>();
/// ```
///
/// ```compile_fail
/// use ruster_integration::InitialActivationFailure;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<InitialActivationFailure>();
/// ```
pub type InitialActivationFailure =
    PublicationRejection<FullServiceCandidateV1, InitialActivationError>;

/// Value-free reason why a successor needs fresh backend or runtime storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FullServiceRestartRequired {
    /// The candidate's interface bindings changed, so backend resources must
    /// be re-attached. Other semantic sections and mandatory hash-key rotations
    /// may coexist with this reason; consult the control-plane diff when it is
    /// available.
    InterfaceBindingsChanged,
    /// The candidate selects a different packet backend or cold backend
    /// configuration. The bound worker must not apply this transition in
    /// place; it requires a fresh backend binding.
    BackendChanged,
    /// The candidate needs a different external runtime-storage shape.
    RuntimeStorageShapeChanged,
    /// The resolution policy must be installed by a cold worker rebuild.
    ResolutionPolicyChanged,
    /// The ICMPv4-error policy must be installed by a cold worker rebuild.
    Icmpv4ErrorPolicyChanged,
    /// The control plane reported a restart reason introduced by a newer
    /// control version. The candidate is preserved, but this integration
    /// version cannot describe the reason more specifically.
    Unsupported,
}

impl From<PlanRestartRequired> for FullServiceRestartRequired {
    fn from(reason: PlanRestartRequired) -> Self {
        match reason {
            PlanRestartRequired::InterfaceBindingsChanged => Self::InterfaceBindingsChanged,
            PlanRestartRequired::BackendChanged => Self::BackendChanged,
            PlanRestartRequired::RuntimeStorageShapeChanged => Self::RuntimeStorageShapeChanged,
            PlanRestartRequired::ResolutionPolicyChanged => Self::ResolutionPolicyChanged,
            PlanRestartRequired::Icmpv4ErrorPolicyChanged => Self::Icmpv4ErrorPolicyChanged,
            _ => Self::Unsupported,
        }
    }
}

/// Typed reason why a successor was not published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FullServicePublishError {
    /// The control-plane candidate is not a valid successor of the active one.
    InvalidSuccessor(SuccessorError),
    /// Applying this candidate needs a cold backend or storage replacement.
    RestartRequired(FullServiceRestartRequired),
    /// The control plane reported a successor classification introduced by a
    /// newer version. The candidate must be returned without mutating runtime
    /// state.
    UnsupportedStaticClassification,
    /// Resolution publication preflight rejected the active runtime state.
    ResolutionPublication(ResolutionPublicationError),
    /// ICMPv4-error publication preflight rejected the active runtime state.
    Icmpv4ErrorPublication(Icmpv4ErrorPublicationError),
    /// UDP NAT successor preflight rejected the new authority.
    Nat44UdpReconcile(Nat44UdpReconcileError),
    /// TCP NAT successor preflight rejected the new authority.
    Nat44TcpReconcile(Nat44TcpReconcileError),
    /// Firewall successor preflight rejected the new authority.
    FirewallReconcile(FirewallReconcileError),
}

/// Diagnostics from one successfully committed all-service successor.
///
/// The report contains generation identities and aggregate flush counts only. It
/// deliberately retains no candidate authority, interface strings, rules, or hash
/// keys.
///
/// Ignoring the report also discards the only per-service flush diagnostics for
/// this generation boundary:
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use ruster_integration::FullServiceApplyReport;
///
/// fn discard(report: FullServiceApplyReport) {
///     report;
/// }
/// ```
#[must_use = "publication diagnostics report the state flushed at the generation boundary"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullServiceApplyReport {
    previous_generation: std::num::NonZeroU64,
    generation: std::num::NonZeroU64,
    resolution: ResolutionPublicationReport,
    icmpv4_errors: Icmpv4ErrorPublicationReport,
    nat44_udp: Nat44UdpReconcileReport,
    nat44_tcp: Nat44TcpReconcileReport,
    firewall: FirewallReconcileReport,
}

impl FullServiceApplyReport {
    /// Returns the generation replaced by this publication.
    #[must_use]
    pub const fn previous_generation(&self) -> std::num::NonZeroU64 {
        self.previous_generation
    }

    /// Returns the newly active generation.
    #[must_use]
    pub const fn generation(&self) -> std::num::NonZeroU64 {
        self.generation
    }

    /// Returns resolution flush diagnostics.
    #[must_use]
    pub const fn resolution(&self) -> ResolutionPublicationReport {
        self.resolution
    }

    /// Returns generated-ICMPv4 flush diagnostics.
    #[must_use]
    pub const fn icmpv4_errors(&self) -> Icmpv4ErrorPublicationReport {
        self.icmpv4_errors
    }

    /// Returns UDP NAT flush diagnostics.
    #[must_use]
    pub const fn nat44_udp(&self) -> Nat44UdpReconcileReport {
        self.nat44_udp
    }

    /// Returns TCP NAT flush diagnostics.
    #[must_use]
    pub const fn nat44_tcp(&self) -> Nat44TcpReconcileReport {
        self.nat44_tcp
    }

    /// Returns firewall flush diagnostics.
    #[must_use]
    pub const fn firewall(&self) -> FirewallReconcileReport {
        self.firewall
    }
}

/// Typestate carried by a cold-activated owner before it is paired with a backend.
///
/// The value has no public constructor. [`activate_initial`] creates it, and
/// [`FullServicePublicationOwner::bind_backend`] consumes it exactly once.
pub struct UnboundPublicationOwner {
    _private: (),
}

/// Reason why an initial owner could not be paired with a backend.
///
/// Binding succeeds only for the exact backend paired by core, after that backend
/// has produced a matched quiescence proof and reports that packet I/O may start.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InitialBackendBindError<E> {
    /// The owner capability belongs to another same-typed backend wrapper.
    BackendMismatch,
    /// The exact backend could not establish publication quiescence.
    Quiescence(E),
    /// The quiescent backend still does not permit packet I/O.
    IoDisposition(PublicationQuiescenceDisposition),
}

/// Failed initial backend binding with all retry capabilities preserved.
///
/// The unbound owner and move-only core binding are retained verbatim. The
/// backend is borrowed only for the checked transition and remains owned by the
/// caller, so [`Self::into_parts`] can be used to retry after resolving a
/// transient backend condition. This value deliberately implements neither
/// `Debug` nor `Clone` because it retains the active candidate and private
/// publication capability.
///
/// ```compile_fail
/// use ruster_integration::InitialBackendBindFailure;
/// use ruster_io_sim::SimIo;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<InitialBackendBindFailure<'static, SimIo>>();
/// ```
pub struct InitialBackendBindFailure<'storage, I: PublicationQuiescenceBackend> {
    owner: FullServicePublicationOwner<'storage>,
    publication_binding: PublicationOwnerBinding<BoundPublicationBackend<I>>,
    error: InitialBackendBindError<I::Error>,
}

impl<'storage, I: PublicationQuiescenceBackend> InitialBackendBindFailure<'storage, I> {
    /// Borrows the typed failure reason.
    #[must_use]
    pub const fn error(&self) -> &InitialBackendBindError<I::Error> {
        &self.error
    }

    /// Recovers the exact unbound owner, binding capability, and failure reason.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FullServicePublicationOwner<'storage>,
        PublicationOwnerBinding<BoundPublicationBackend<I>>,
        InitialBackendBindError<I::Error>,
    ) {
        (self.owner, self.publication_binding, self.error)
    }
}

/// The exhaustive worker-local runtime inventory for one full-service owner.
///
/// This is intentionally private and exhaustive. Adding a runtime requires
/// updating every owner/view/transaction destructure that carries the full
/// service set instead of allowing an omitted field to be hidden by `..`.
struct FullServiceRuntimeSet<'storage> {
    resolution: ResolutionRuntime<'storage>,
    icmpv4_errors: Icmpv4ErrorRuntime<'storage>,
    nat44_udp: Nat44UdpRuntime<'storage>,
    nat44_tcp: Nat44TcpRuntime<'storage>,
    firewall: FirewallRuntime<'storage>,
}

/// Active candidate and all five worker-local runtimes over external storage.
///
/// Cold activation returns the default unbound typestate. Publication and packet
/// runtime execution are implemented only after [`Self::bind_backend`] consumes a
/// core-owned [`PublicationOwnerBinding`] for one exact
/// [`BoundPublicationBackend`] instance.
///
/// The candidate and runtime fields are private so callers can only borrow one
/// coherent generation through [`Self::active_view`] or
/// [`FullServicePublication::active`]. The returned view exposes copied authority
/// but does not expose raw mutable runtimes, preventing out-of-band NAT key
/// reconciliation behind the active candidate.
///
/// ```compile_fail
/// use ruster_integration::FullServicePublicationOwner;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<FullServicePublicationOwner<'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_integration::FullServicePublicationOwner;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<FullServicePublicationOwner<'static>>();
/// ```
///
/// Cold activation alone cannot satisfy the runtime publication contract:
///
/// ```compile_fail
/// use ruster_core::BoundPublicationBackend;
/// use ruster_integration::FullServicePublicationOwner;
/// use ruster_io_sim::SimIo;
/// use ruster_runtime::FullServicePublication;
///
/// fn require_bound<P: FullServicePublication<'static, BoundPublicationBackend<SimIo>>>() {}
/// require_bound::<FullServicePublicationOwner<'static>>();
/// ```
pub struct FullServicePublicationOwner<'storage, Binding = UnboundPublicationOwner> {
    publication_binding: Binding,
    active_candidate: FullServiceCandidateV1,
    active_tick_authority: ActiveTickAuthority,
    runtimes: FullServiceRuntimeSet<'storage>,
    active_failure: Option<FullServicePublishError>,
    #[cfg(test)]
    backing_pointers: [usize; 21],
}

/// Backend-bound owner accepted by [`ruster_runtime::run_tick`].
pub type BoundFullServicePublicationOwner<'storage, I> =
    FullServicePublicationOwner<'storage, PublicationOwnerBinding<BoundPublicationBackend<I>>>;

struct Nat44UdpRuntimeStorage<'storage> {
    mappings: &'storage mut [Nat44UdpMappingSlot],
    peers: &'storage mut [Nat44UdpPeerSlot],
    mapping_buckets: &'storage mut [DirectoryBucket],
    mapping_nodes: &'storage mut [DirectoryNode],
    peer_buckets: &'storage mut [DirectoryBucket],
    peer_nodes: &'storage mut [DirectoryNode],
    port_owners: &'storage mut [PortOwnerSlot],
}

struct ActivatedNat44Udp<'storage> {
    runtime: Nat44UdpRuntime<'storage>,
    #[cfg(test)]
    backing_pointers: [usize; 7],
}

impl<'storage> Nat44UdpRuntimeStorage<'storage> {
    fn activate(
        self,
        config: Nat44UdpConfig,
        hash_key: Nat44UdpHashKey,
    ) -> Result<ActivatedNat44Udp<'storage>, Nat44UdpRuntimeConfigError> {
        let Self {
            mappings,
            peers,
            mapping_buckets,
            mapping_nodes,
            peer_buckets,
            peer_nodes,
            port_owners,
        } = self;
        #[cfg(test)]
        let backing_pointers = [
            mappings.as_ptr() as usize,
            peers.as_ptr() as usize,
            mapping_buckets.as_ptr() as usize,
            mapping_nodes.as_ptr() as usize,
            peer_buckets.as_ptr() as usize,
            peer_nodes.as_ptr() as usize,
            port_owners.as_ptr() as usize,
        ];
        let indexes = Nat44UdpIndexStorage::new(
            mapping_buckets,
            mapping_nodes,
            peer_buckets,
            peer_nodes,
            port_owners,
        );
        let runtime = Nat44UdpRuntime::new(config, mappings, peers, indexes, hash_key)?;
        Ok(ActivatedNat44Udp {
            runtime,
            #[cfg(test)]
            backing_pointers,
        })
    }
}

struct Nat44TcpRuntimeStorage<'storage> {
    mappings: &'storage mut [Nat44TcpMappingSlot],
    sessions: &'storage mut [Nat44TcpSessionSlot],
    mapping_buckets: &'storage mut [DirectoryBucket],
    mapping_nodes: &'storage mut [DirectoryNode],
    session_buckets: &'storage mut [DirectoryBucket],
    session_nodes: &'storage mut [DirectoryNode],
    port_owners: &'storage mut [PortOwnerSlot],
}

struct ActivatedNat44Tcp<'storage> {
    runtime: Nat44TcpRuntime<'storage>,
    #[cfg(test)]
    backing_pointers: [usize; 7],
}

impl<'storage> Nat44TcpRuntimeStorage<'storage> {
    fn activate(
        self,
        config: Nat44TcpConfig,
        hash_key: Nat44TcpHashKey,
    ) -> Result<ActivatedNat44Tcp<'storage>, Nat44TcpRuntimeConfigError> {
        let Self {
            mappings,
            sessions,
            mapping_buckets,
            mapping_nodes,
            session_buckets,
            session_nodes,
            port_owners,
        } = self;
        #[cfg(test)]
        let backing_pointers = [
            mappings.as_ptr() as usize,
            sessions.as_ptr() as usize,
            mapping_buckets.as_ptr() as usize,
            mapping_nodes.as_ptr() as usize,
            session_buckets.as_ptr() as usize,
            session_nodes.as_ptr() as usize,
            port_owners.as_ptr() as usize,
        ];
        let indexes = Nat44TcpIndexStorage::new(
            mapping_buckets,
            mapping_nodes,
            session_buckets,
            session_nodes,
            port_owners,
        );
        let runtime = Nat44TcpRuntime::new(config, mappings, sessions, indexes, hash_key)?;
        Ok(ActivatedNat44Tcp {
            runtime,
            #[cfg(test)]
            backing_pointers,
        })
    }
}

struct ActivatedRuntimes<'storage> {
    runtimes: FullServiceRuntimeSet<'storage>,
    #[cfg(test)]
    backing_pointers: [usize; 21],
}

fn activate_runtimes<'storage>(
    candidate: &FullServiceCandidateV1,
    slices: RuntimeStorageSlices<'storage>,
) -> Result<ActivatedRuntimes<'storage>, InitialActivationError> {
    let RuntimeStorageSlices {
        resolution_states,
        resolution_actions,
        resolution_dynamic_neighbors,
        resolution_failure_holds,
        icmpv4_error_states,
        icmpv4_error_actions,
        nat44_udp_mappings,
        nat44_udp_peers,
        nat44_udp_mapping_buckets,
        nat44_udp_mapping_nodes,
        nat44_udp_peer_buckets,
        nat44_udp_peer_nodes,
        nat44_udp_port_owners,
        nat44_tcp_mappings,
        nat44_tcp_sessions,
        nat44_tcp_mapping_buckets,
        nat44_tcp_mapping_nodes,
        nat44_tcp_session_buckets,
        nat44_tcp_session_nodes,
        nat44_tcp_port_owners,
        firewall_states,
    } = slices;
    #[cfg(test)]
    let fixed_service_pointers = [
        resolution_states.as_ptr() as usize,
        resolution_actions.as_ptr() as usize,
        resolution_dynamic_neighbors.as_ptr() as usize,
        resolution_failure_holds.as_ptr() as usize,
        icmpv4_error_states.as_ptr() as usize,
        icmpv4_error_actions.as_ptr() as usize,
        firewall_states.as_ptr() as usize,
    ];
    let authority = candidate.authority();
    let resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        authority.resolution_policy(),
        resolution_states,
        resolution_actions,
        resolution_dynamic_neighbors,
        resolution_failure_holds,
    );
    let icmpv4_errors = Icmpv4ErrorRuntime::new(
        authority.icmpv4_error_policy(),
        icmpv4_error_states,
        icmpv4_error_actions,
    );
    let udp = Nat44UdpRuntimeStorage {
        mappings: nat44_udp_mappings,
        peers: nat44_udp_peers,
        mapping_buckets: nat44_udp_mapping_buckets,
        mapping_nodes: nat44_udp_mapping_nodes,
        peer_buckets: nat44_udp_peer_buckets,
        peer_nodes: nat44_udp_peer_nodes,
        port_owners: nat44_udp_port_owners,
    }
    .activate(authority.nat44_udp_config(), authority.nat44_udp_hash_key())
    .map_err(nat44_udp_activation_error)?;
    let tcp = Nat44TcpRuntimeStorage {
        mappings: nat44_tcp_mappings,
        sessions: nat44_tcp_sessions,
        mapping_buckets: nat44_tcp_mapping_buckets,
        mapping_nodes: nat44_tcp_mapping_nodes,
        session_buckets: nat44_tcp_session_buckets,
        session_nodes: nat44_tcp_session_nodes,
        port_owners: nat44_tcp_port_owners,
    }
    .activate(authority.nat44_tcp_config(), authority.nat44_tcp_hash_key())
    .map_err(nat44_tcp_activation_error)?;
    let firewall = FirewallRuntime::new(authority.firewall_config(), firewall_states);

    Ok(ActivatedRuntimes {
        runtimes: FullServiceRuntimeSet {
            resolution,
            icmpv4_errors,
            nat44_udp: udp.runtime,
            nat44_tcp: tcp.runtime,
            firewall,
        },
        #[cfg(test)]
        backing_pointers: [
            fixed_service_pointers[0],
            fixed_service_pointers[1],
            fixed_service_pointers[2],
            fixed_service_pointers[3],
            fixed_service_pointers[4],
            fixed_service_pointers[5],
            udp.backing_pointers[0],
            udp.backing_pointers[1],
            udp.backing_pointers[2],
            udp.backing_pointers[3],
            udp.backing_pointers[4],
            udp.backing_pointers[5],
            udp.backing_pointers[6],
            tcp.backing_pointers[0],
            tcp.backing_pointers[1],
            tcp.backing_pointers[2],
            tcp.backing_pointers[3],
            tcp.backing_pointers[4],
            tcp.backing_pointers[5],
            tcp.backing_pointers[6],
            fixed_service_pointers[6],
        ],
    })
}

/// Activates one candidate against exact-shape external storage before workers start.
///
/// This cold operation does not require a publication-quiescence guard because no
/// worker or packet backend is using the initial authority yet. Shape and concrete
/// byte mismatches are detected before any runtime constructor can mutate storage.
/// On every failure, [`InitialActivationFailure`] returns the exact candidate.
/// Once constructors begin, storage rollback is not guaranteed; in particular, a
/// late TCP failure follows UDP identity allocation and earlier storage clearing.
#[allow(
    clippy::result_large_err,
    reason = "failure intentionally returns the consumed candidate without allocation"
)]
pub fn activate_initial<'storage>(
    storage: &'storage mut FullServiceRuntimeStorage,
    candidate: FullServiceCandidateV1,
) -> Result<FullServicePublicationOwner<'storage>, InitialActivationFailure> {
    if storage.shape() != candidate.storage_shape() {
        return Err(PublicationRejection::new(
            candidate,
            InitialActivationError::StorageShapeMismatch,
        ));
    }
    if storage.required_runtime_bytes() != candidate.required_runtime_bytes() {
        return Err(PublicationRejection::new(
            candidate,
            InitialActivationError::StorageRequiredBytesMismatch,
        ));
    }

    let active_tick_authority = ActiveTickAuthority::new(
        candidate.generation(),
        runtime_tick_budgets(candidate.tick()),
    );

    match activate_runtimes(&candidate, storage.slices()) {
        Ok(ActivatedRuntimes {
            runtimes,
            #[cfg(test)]
            backing_pointers,
        }) => Ok(FullServicePublicationOwner {
            publication_binding: UnboundPublicationOwner { _private: () },
            active_candidate: candidate,
            active_tick_authority,
            runtimes,
            active_failure: None,
            #[cfg(test)]
            backing_pointers,
        }),
        Err(error) => Err(PublicationRejection::new(candidate, error)),
    }
}

fn runtime_tick_budgets(tick: TickBudgetsV1) -> TickBudgets {
    TickBudgets {
        rx: usize::try_from(tick.rx).expect("u32 tick budget fits target usize"),
        resolution_timer_scans: usize::try_from(tick.resolution_timer_scans)
            .expect("u32 tick budget fits target usize"),
        failure_dispatch_scans: usize::try_from(tick.failure_dispatch_scans)
            .expect("u32 tick budget fits target usize"),
        generated_arp: usize::try_from(tick.generated_arp)
            .expect("u32 tick budget fits target usize"),
        generated_icmpv4: usize::try_from(tick.generated_icmpv4)
            .expect("u32 tick budget fits target usize"),
    }
}

impl<'storage> FullServicePublicationOwner<'storage> {
    /// Checks and pairs the cold owner with one exact quiescent backend.
    ///
    /// The binding is move-only and can only be obtained together with its
    /// [`BoundPublicationBackend`] from
    /// [`ruster_core::bind_publication_backend`]. This transition checks the
    /// immutable identity before quiescence, matches the resulting raw guard to
    /// the same owner capability, and requires the backend to report
    /// [`PublicationQuiescenceDisposition::ContinueOldIo`] before producing the
    /// only owner form that implements [`FullServicePublication`]. Work accepted
    /// before this call therefore cannot cross into the initial publication.
    ///
    /// On failure, [`InitialBackendBindFailure::into_parts`] returns the exact
    /// unbound owner and binding for a retry; `backend` remains caller-owned.
    ///
    /// ```
    /// use ruster_core::bind_publication_backend;
    /// use ruster_integration::activate_initial;
    /// use ruster_io_sim::SimIo;
    /// # use ruster_integration::FullServiceRuntimeStorage;
    /// # fn example(
    /// #     owner: ruster_integration::FullServicePublicationOwner<'_>,
    /// # ) {
    /// let (owner_binding, mut backend) =
    ///     bind_publication_backend(SimIo::new()).unwrap();
    /// let owner = match owner.bind_backend(owner_binding, &mut backend) {
    ///     Ok(owner) => owner,
    ///     Err(failure) => {
    ///         let (_owner, _owner_binding, _error) = failure.into_parts();
    ///         return;
    ///     }
    /// };
    /// # let _ = owner;
    /// # }
    /// ```
    #[allow(
        clippy::result_large_err,
        reason = "failure preserves the exact active owner and move-only binding for retry"
    )]
    pub fn bind_backend<I: PublicationBackendAuthority + PublicationQuiescenceBackend>(
        self,
        publication_binding: PublicationOwnerBinding<BoundPublicationBackend<I>>,
        backend: &mut BoundPublicationBackend<I>,
    ) -> Result<BoundFullServicePublicationOwner<'storage, I>, InitialBackendBindFailure<'storage, I>>
    {
        if !publication_binding.matches_backend(backend) {
            return Err(InitialBackendBindFailure {
                owner: self,
                publication_binding,
                error: InitialBackendBindError::BackendMismatch,
            });
        }

        let raw_guard = match backend.try_publication_quiescence() {
            Ok(guard) => guard,
            Err(error) => {
                return Err(InitialBackendBindFailure {
                    owner: self,
                    publication_binding,
                    error: InitialBackendBindError::Quiescence(error),
                });
            }
        };
        let matched_guard = match publication_binding.match_quiescence_guard(raw_guard) {
            Ok(guard) => guard,
            Err(raw_guard) => {
                drop(raw_guard);
                return Err(InitialBackendBindFailure {
                    owner: self,
                    publication_binding,
                    error: InitialBackendBindError::BackendMismatch,
                });
            }
        };
        drop(matched_guard);

        let io_disposition = backend.current_io_disposition();
        if io_disposition != PublicationQuiescenceDisposition::ContinueOldIo {
            return Err(InitialBackendBindFailure {
                owner: self,
                publication_binding,
                error: InitialBackendBindError::IoDisposition(io_disposition),
            });
        }

        let Self {
            publication_binding: _,
            active_candidate,
            active_tick_authority,
            runtimes,
            active_failure,
            #[cfg(test)]
            backing_pointers,
        } = self;
        Ok(FullServicePublicationOwner {
            publication_binding,
            active_candidate,
            active_tick_authority,
            runtimes,
            active_failure,
            #[cfg(test)]
            backing_pointers,
        })
    }
}

impl<'storage, Binding> FullServicePublicationOwner<'storage, Binding> {
    /// Returns the active generation.
    #[must_use]
    pub const fn generation(&self) -> std::num::NonZeroU64 {
        self.active_candidate.generation()
    }

    /// Returns generation-bound interface metadata without cloning it.
    #[must_use]
    pub fn interfaces(&self) -> &[InterfaceBindingV1] {
        self.active_candidate.interfaces()
    }

    /// Returns the active generation's tick budgets.
    #[must_use]
    pub const fn tick(&self) -> TickBudgetsV1 {
        self.active_candidate.tick()
    }

    /// Returns the validated concrete runtime byte requirement.
    #[must_use]
    pub const fn required_runtime_bytes(&self) -> usize {
        self.active_candidate.required_runtime_bytes()
    }

    /// Returns the active generation's complete storage shape.
    #[must_use]
    pub const fn storage_shape(&self) -> FullServiceStorageShape {
        self.active_candidate.storage_shape()
    }

    /// Classifies `next` against the active candidate using the control-plane
    /// static plan API without exposing that candidate or any authority fields.
    ///
    /// This method is allocation-free, read-only, and independent of backend
    /// state. It checks only candidate successor invariants and interface
    /// restart requirements; it does not inspect the active-failure latch,
    /// backend quiescence, or the five runtime preflights. An
    /// [`PlanOutcome::InPlaceEligible`] result can therefore still be deferred
    /// or rejected by an actual publication attempt.
    #[must_use = "inspect the static plan result"]
    pub fn plan_successor(&self, next: &FullServiceCandidateV1) -> PlanOutcome {
        ruster_control::plan_successor(Some(&self.active_candidate), next)
    }

    /// Borrows one backend-independent, generation-coherent active view.
    ///
    /// The view's mutable runtimes are sealed inside `ruster-runtime`; callers
    /// can inspect copied authority and pass the view through the publication
    /// trait, but cannot reconcile a NAT runtime out of band.
    #[must_use]
    pub fn active_view(&mut self) -> FullServiceView<'_, 'storage> {
        let Self {
            active_candidate,
            active_tick_authority,
            runtimes:
                FullServiceRuntimeSet {
                    resolution,
                    icmpv4_errors,
                    nat44_udp,
                    nat44_tcp,
                    firewall,
                },
            ..
        } = self;
        let authority = active_candidate.authority();

        FullServiceView::new(
            &*active_tick_authority,
            authority.snapshot(),
            resolution,
            icmpv4_errors,
            Nat44UdpServiceView::new(authority.nat44_udp_config(), Some(nat44_udp)),
            Nat44TcpServiceView::new(authority.nat44_tcp_config(), Some(nat44_tcp)),
            FirewallServiceView::new(authority.firewall_config(), Some(firewall)),
        )
    }

    /// Folds this tick's core-service counters into `recorder` using
    /// `active_status` for readiness and returns the resulting
    /// allocation-free observability snapshot. `backend` carries this tick's
    /// backend-specific stats through the [`BackendObservabilityStats`]
    /// extension point.
    fn observability_snapshot_with_status<Backend: BackendObservabilityStats>(
        &mut self,
        active_status: ActivePublicationStatus,
        recorder: &mut ObservabilityRecorder<Backend>,
        backend: Backend,
    ) -> ObservabilitySnapshot<Backend> {
        let view = self.active_view();
        let generation = view.generation();
        let firewall = view.firewall_counters();
        let nat44_udp = view.nat44_udp_counters();
        let nat44_tcp = view.nat44_tcp_counters();

        recorder.record_tick(
            generation,
            active_status,
            firewall,
            nat44_udp,
            nat44_tcp,
            backend,
        )
    }
}

impl<'storage> FullServicePublicationOwner<'storage, UnboundPublicationOwner> {
    /// Folds this tick's core-service counters into `recorder` and returns
    /// the resulting allocation-free observability snapshot.
    ///
    /// No backend has been bound yet, so readiness is always
    /// [`ruster_runtime::observability::Readiness::Cold`] (via [`ActivePublicationStatus::Absent`])
    /// regardless of the persistent active-failure latch: there is no bound
    /// backend for I/O to continue on. `backend` carries this tick's
    /// backend-specific stats through the [`BackendObservabilityStats`]
    /// extension point.
    pub fn observability_snapshot<Backend: BackendObservabilityStats>(
        &mut self,
        recorder: &mut ObservabilityRecorder<Backend>,
        backend: Backend,
    ) -> ObservabilitySnapshot<Backend> {
        self.observability_snapshot_with_status(ActivePublicationStatus::Absent, recorder, backend)
    }
}

impl<'storage, I: PublicationBackendAuthority + PublicationQuiescenceBackend>
    BoundFullServicePublicationOwner<'storage, I>
{
    /// Folds this tick's core-service counters into `recorder` and returns
    /// the resulting allocation-free observability snapshot.
    ///
    /// Readiness reflects the persistent active-failure latch: this owner
    /// has a bound backend, so it is never [`ruster_runtime::observability::Readiness::Cold`]. `backend`
    /// carries this tick's backend-specific stats through the
    /// [`BackendObservabilityStats`] extension point.
    pub fn observability_snapshot<Backend: BackendObservabilityStats>(
        &mut self,
        recorder: &mut ObservabilityRecorder<Backend>,
        backend: Backend,
    ) -> ObservabilitySnapshot<Backend> {
        let active_status = match self.active_failure {
            Some(error) => publish_error_disposition(error),
            None => ActivePublicationStatus::ContinueOldIo,
        };
        self.observability_snapshot_with_status(active_status, recorder, backend)
    }
}

fn publish_error_disposition(error: FullServicePublishError) -> ActivePublicationStatus {
    match error {
        FullServicePublishError::InvalidSuccessor(_)
        | FullServicePublishError::RestartRequired(_) => ActivePublicationStatus::ContinueOldIo,
        _ => ActivePublicationStatus::StopOldPublication,
    }
}

fn finish_publication_after_quiescence<Quiescence, Retired, Output>(
    quiescence: Quiescence,
    retired: Retired,
    output: Output,
) -> Output {
    // Tuple elements drop in declaration order. Keeping both values under one
    // owner also preserves that order during unwinding, so retired authority can
    // never begin dropping before the quiescence guard begins dropping.
    let retirement = (quiescence, retired);
    drop(retirement);
    output
}

fn unsupported_static_classification<C>(
    candidate: C,
) -> PublicationRejection<C, FullServicePublishError> {
    PublicationRejection::new(
        candidate,
        FullServicePublishError::UnsupportedStaticClassification,
    )
}

// SAFETY: `publication_owner_binding` always returns the same immutable
// binding for the owner's lifetime. `reject_candidate_if_active_stopped` and
// `publish_candidate_authorized` both return every `Err` through
// `PublicationRejection::new(candidate, ..)` with the exact candidate the
// caller supplied, never a substitute value. `publish_candidate_authorized`
// only installs a candidate via the single `mem::replace(active_candidate,
// candidate)` after all five preflight permits succeed and commit
// infallibly; any earlier failure returns the candidate unchanged and, for
// the five `active_failure`-latching branches, leaves `active_candidate`
// untouched. `active_status` derives deterministically from `active_failure`
// and agrees with the latched cause `reject_candidate_if_active_stopped`
// returns. `active` is O(1): it borrows the five already-owned runtimes and
// copies small `Copy` authority out of `active_candidate` without scanning
// or allocating.
#[allow(unsafe_code)]
unsafe impl<'storage, I: PublicationBackendAuthority + PublicationQuiescenceBackend>
    FullServicePublication<'storage, BoundPublicationBackend<I>>
    for BoundFullServicePublicationOwner<'storage, I>
{
    type Candidate = FullServiceCandidateV1;
    type Reject = FullServicePublishError;
    type ApplyReport = FullServiceApplyReport;

    fn publication_owner_binding(&self) -> &PublicationOwnerBinding<BoundPublicationBackend<I>> {
        &self.publication_binding
    }

    fn reject_candidate_if_active_stopped(
        &self,
        candidate: Self::Candidate,
    ) -> Result<Self::Candidate, PublicationRejection<Self::Candidate, Self::Reject>> {
        match self.active_failure {
            Some(error) => Err(PublicationRejection::new(candidate, error)),
            None => Ok(candidate),
        }
    }

    #[allow(
        unsafe_code,
        clippy::result_large_err,
        reason = "the runtime-safe gate supplies the matched capability; rejection preserves the exact candidate"
    )]
    unsafe fn publish_candidate_authorized(
        &mut self,
        candidate: Self::Candidate,
        quiescence: MatchedPublicationQuiescenceGuard<'_, BoundPublicationBackend<I>>,
    ) -> Result<Self::ApplyReport, PublicationRejection<Self::Candidate, Self::Reject>> {
        if let Some(error) = self.active_failure {
            return Err(PublicationRejection::new(candidate, error));
        }
        match classify_successor(&self.active_candidate, &candidate) {
            FullServiceSuccessorClassification::Rejected(error) => {
                return Err(PublicationRejection::new(
                    candidate,
                    FullServicePublishError::InvalidSuccessor(error),
                ));
            }
            FullServiceSuccessorClassification::RestartRequired(reason) => {
                return Err(PublicationRejection::new(
                    candidate,
                    FullServicePublishError::RestartRequired(reason.into()),
                ));
            }
            FullServiceSuccessorClassification::InPlaceEligible => {}
            _ => return Err(unsupported_static_classification(candidate)),
        }

        let (nat44_udp_config, nat44_udp_hash_key, nat44_tcp_config, nat44_tcp_hash_key) = {
            let authority = candidate.authority();
            (
                authority.nat44_udp_config(),
                authority.nat44_udp_hash_key(),
                authority.nat44_tcp_config(),
                authority.nat44_tcp_hash_key(),
            )
        };
        let generation = candidate.generation();
        let next_tick_authority =
            ActiveTickAuthority::new(generation, runtime_tick_budgets(candidate.tick()));
        let Self {
            active_candidate,
            active_tick_authority,
            runtimes:
                FullServiceRuntimeSet {
                    resolution,
                    icmpv4_errors,
                    nat44_udp,
                    nat44_tcp,
                    firewall,
                },
            active_failure,
            ..
        } = self;
        let previous_generation = active_candidate.generation();

        let resolution = match resolution.preflight_publication() {
            Ok(permit) => permit,
            Err(error) => {
                let error = FullServicePublishError::ResolutionPublication(error);
                debug_assert_eq!(
                    publish_error_disposition(error),
                    ActivePublicationStatus::StopOldPublication
                );
                *active_failure = Some(error);
                return Err(PublicationRejection::new(candidate, error));
            }
        };
        let icmpv4_errors = match icmpv4_errors.preflight_publication() {
            Ok(permit) => permit,
            Err(error) => {
                let error = FullServicePublishError::Icmpv4ErrorPublication(error);
                debug_assert_eq!(
                    publish_error_disposition(error),
                    ActivePublicationStatus::StopOldPublication
                );
                *active_failure = Some(error);
                return Err(PublicationRejection::new(candidate, error));
            }
        };
        let nat44_udp = match nat44_udp.preflight_reconcile(nat44_udp_config, nat44_udp_hash_key) {
            Ok(permit) => permit,
            Err(error) => {
                let error = FullServicePublishError::Nat44UdpReconcile(error);
                debug_assert_eq!(
                    publish_error_disposition(error),
                    ActivePublicationStatus::StopOldPublication
                );
                *active_failure = Some(error);
                return Err(PublicationRejection::new(candidate, error));
            }
        };
        let nat44_tcp = match nat44_tcp.preflight_reconcile(nat44_tcp_config, nat44_tcp_hash_key) {
            Ok(permit) => permit,
            Err(error) => {
                let error = FullServicePublishError::Nat44TcpReconcile(error);
                debug_assert_eq!(
                    publish_error_disposition(error),
                    ActivePublicationStatus::StopOldPublication
                );
                *active_failure = Some(error);
                return Err(PublicationRejection::new(candidate, error));
            }
        };
        let firewall = {
            let authority = candidate.authority();
            firewall.preflight_reconcile(authority.firewall_config())
        };
        let firewall = match firewall {
            Ok(permit) => permit,
            Err(error) => {
                let error = FullServicePublishError::FirewallReconcile(error);
                debug_assert_eq!(
                    publish_error_disposition(error),
                    ActivePublicationStatus::StopOldPublication
                );
                *active_failure = Some(error);
                return Err(PublicationRejection::new(candidate, error));
            }
        };

        let resolution = resolution.commit();
        let icmpv4_errors = icmpv4_errors.commit();
        let nat44_udp = nat44_udp.commit();
        let nat44_tcp = nat44_tcp.commit();
        let firewall = firewall.commit();
        *active_tick_authority = next_tick_authority;
        let retired_candidate = core::mem::replace(active_candidate, candidate);
        let report = FullServiceApplyReport {
            previous_generation,
            generation,
            resolution,
            icmpv4_errors,
            nat44_udp,
            nat44_tcp,
            firewall,
        };

        Ok(finish_publication_after_quiescence(
            quiescence,
            retired_candidate,
            report,
        ))
    }

    fn active_status(&self) -> ActivePublicationStatus {
        match self.active_failure {
            Some(error) => publish_error_disposition(error),
            None => ActivePublicationStatus::ContinueOldIo,
        }
    }

    fn active(&mut self) -> FullServiceView<'_, 'storage> {
        self.active_view()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActiveRuntimeEvidence {
    pub(crate) pointers: [usize; 10],
    pub(crate) backing_pointers: [usize; 21],
    pub(crate) storage_shape: FullServiceStorageShape,
    pub(crate) publication_bindings_match: bool,
    pub(crate) resolution_pending_states: usize,
    pub(crate) resolution_pending_actions: usize,
    pub(crate) resolution_dynamic_neighbors: usize,
    pub(crate) resolution_pending_failure_holds: usize,
    pub(crate) resolution_counters: ResolutionCounters,
    pub(crate) resolution_failure_counters: ResolutionFailureCounters,
    pub(crate) resolution_pristine: bool,
    pub(crate) icmpv4_error_pending_actions: usize,
    pub(crate) icmpv4_error_counters: Icmpv4ErrorCounters,
    pub(crate) icmpv4_errors_pristine: bool,
    pub(crate) nat44_udp_mapping_occupied: usize,
    pub(crate) nat44_udp_peer_occupied: usize,
    pub(crate) nat44_udp_counters: Nat44UdpCounters,
    pub(crate) nat44_udp_counters_pristine: bool,
    pub(crate) nat44_udp_pristine: bool,
    pub(crate) nat44_tcp_mapping_occupied: usize,
    pub(crate) nat44_tcp_session_occupied: usize,
    pub(crate) nat44_tcp_counters: Nat44TcpCounters,
    pub(crate) nat44_tcp_counters_pristine: bool,
    pub(crate) nat44_tcp_pristine: bool,
    pub(crate) firewall_state_occupied: usize,
    pub(crate) firewall_counters: FirewallCounters,
    pub(crate) firewall_pristine: bool,
    pub(crate) pristine: bool,
}

#[cfg(test)]
impl<Binding> FullServicePublicationOwner<'_, Binding> {
    pub(crate) fn reconcile_firewall_for_test(
        &mut self,
        candidate: &FullServiceCandidateV1,
    ) -> Result<FirewallReconcileReport, FirewallReconcileError> {
        let authority = candidate.authority();
        self.runtimes
            .firewall
            .reconcile(authority.firewall_config())
    }

    pub(crate) fn flush_resolution_and_icmpv4_for_test(
        &mut self,
    ) -> (ResolutionPublicationReport, Icmpv4ErrorPublicationReport) {
        let resolution = self
            .runtimes
            .resolution
            .preflight_publication()
            .expect("test evidence requires coherent resolution state")
            .commit();
        let icmpv4_errors = self
            .runtimes
            .icmpv4_errors
            .preflight_publication()
            .expect("test evidence requires coherent ICMPv4-error state")
            .commit();
        (resolution, icmpv4_errors)
    }

    pub(crate) fn runtime_evidence(&self) -> ActiveRuntimeEvidence {
        let FullServiceRuntimeSet {
            resolution,
            icmpv4_errors,
            nat44_udp,
            nat44_tcp,
            firewall,
        } = &self.runtimes;
        let authority = self.active_candidate.authority();
        let udp = nat44_udp.storage_shape();
        let tcp = nat44_tcp.storage_shape();
        let storage_shape = FullServiceStorageShape::new(
            ResolutionStorageShape::new(
                u32::try_from(resolution.state_capacity()).expect("validated capacity"),
                u32::try_from(resolution.action_capacity()).expect("validated capacity"),
                u32::try_from(resolution.dynamic_neighbor_capacity()).expect("validated capacity"),
                u32::try_from(resolution.failure_hold_capacity()).expect("validated capacity"),
            ),
            Icmpv4ErrorStorageShape::new(
                u32::try_from(icmpv4_errors.state_capacity()).expect("validated capacity"),
                u32::try_from(icmpv4_errors.action_capacity()).expect("validated capacity"),
            ),
            Nat44UdpStoragePlan::new(
                udp.mapping_slots(),
                udp.peer_slots(),
                udp.mapping_buckets(),
                udp.mapping_nodes(),
                udp.peer_buckets(),
                udp.peer_nodes(),
                udp.port_owner_slots(),
            ),
            Nat44TcpStoragePlan::new(
                tcp.mapping_slots(),
                tcp.session_slots(),
                tcp.mapping_buckets(),
                tcp.mapping_nodes(),
                tcp.session_buckets(),
                tcp.session_nodes(),
                tcp.port_owner_slots(),
            ),
            u32::try_from(firewall.states().len()).expect("validated capacity"),
        );
        let publication_bindings_match = nat44_udp.publication_binding_matches(
            authority.nat44_udp_config(),
            authority.nat44_udp_hash_key(),
        ) && nat44_tcp.publication_binding_matches(
            authority.nat44_tcp_config(),
            authority.nat44_tcp_hash_key(),
        ) && firewall.config_matches(&authority.firewall_config());
        let resolution_pending_states = resolution.pending_states();
        let resolution_pending_actions = resolution.pending_actions();
        let resolution_dynamic_neighbors = resolution.dynamic_neighbor_count();
        let resolution_pending_failure_holds = resolution.pending_failure_holds();
        let resolution_counters = resolution.counters();
        let resolution_failure_counters = resolution.failure_counters();
        let resolution_pristine = resolution.is_pristine();
        let icmpv4_error_pending_actions = icmpv4_errors.pending_actions();
        let icmpv4_error_counters = icmpv4_errors.counters();
        let icmpv4_errors_pristine = icmpv4_errors.is_pristine();
        let nat44_udp_mapping_occupied = nat44_udp
            .mappings()
            .iter()
            .filter(|slot| **slot != Nat44UdpMappingSlot::default())
            .count();
        let nat44_udp_peer_occupied = nat44_udp
            .peers()
            .iter()
            .filter(|slot| **slot != Nat44UdpPeerSlot::default())
            .count();
        let nat44_udp_counters = nat44_udp.counters();
        let nat44_udp_counters_pristine = nat44_udp_counters == Nat44UdpCounters::default();
        let nat44_udp_pristine = nat44_udp_mapping_occupied == 0
            && nat44_udp_peer_occupied == 0
            && nat44_udp_counters_pristine;
        let nat44_tcp_mapping_occupied = nat44_tcp
            .mappings()
            .iter()
            .filter(|slot| **slot != Nat44TcpMappingSlot::default())
            .count();
        let nat44_tcp_session_occupied = nat44_tcp
            .sessions()
            .iter()
            .filter(|slot| **slot != Nat44TcpSessionSlot::default())
            .count();
        let nat44_tcp_counters = nat44_tcp.counters();
        let nat44_tcp_counters_pristine = nat44_tcp_counters == Nat44TcpCounters::default();
        let nat44_tcp_pristine = nat44_tcp_mapping_occupied == 0
            && nat44_tcp_session_occupied == 0
            && nat44_tcp_counters_pristine;
        let firewall_state_occupied = firewall
            .states()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count();
        let firewall_counters = firewall.counters();
        let firewall_pristine = firewall.is_pristine();
        let pristine = resolution_pristine
            && icmpv4_errors_pristine
            && nat44_udp_pristine
            && nat44_tcp_pristine
            && firewall_pristine;

        ActiveRuntimeEvidence {
            pointers: [
                core::ptr::from_ref(resolution) as usize,
                core::ptr::from_ref(icmpv4_errors) as usize,
                core::ptr::from_ref(nat44_udp) as usize,
                nat44_udp.mappings().as_ptr() as usize,
                nat44_udp.peers().as_ptr() as usize,
                core::ptr::from_ref(nat44_tcp) as usize,
                nat44_tcp.mappings().as_ptr() as usize,
                nat44_tcp.sessions().as_ptr() as usize,
                core::ptr::from_ref(firewall) as usize,
                firewall.states().as_ptr() as usize,
            ],
            backing_pointers: self.backing_pointers,
            storage_shape,
            publication_bindings_match,
            resolution_pending_states,
            resolution_pending_actions,
            resolution_dynamic_neighbors,
            resolution_pending_failure_holds,
            resolution_counters,
            resolution_failure_counters,
            resolution_pristine,
            icmpv4_error_pending_actions,
            icmpv4_error_counters,
            icmpv4_errors_pristine,
            nat44_udp_mapping_occupied,
            nat44_udp_peer_occupied,
            nat44_udp_counters,
            nat44_udp_counters_pristine,
            nat44_udp_pristine,
            nat44_tcp_mapping_occupied,
            nat44_tcp_session_occupied,
            nat44_tcp_counters,
            nat44_tcp_counters_pristine,
            nat44_tcp_pristine,
            firewall_state_occupied,
            firewall_counters,
            firewall_pristine,
            pristine,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        panic::{catch_unwind, AssertUnwindSafe},
    };

    use super::*;

    struct DropProbe<'events> {
        event: &'static str,
        events: &'events RefCell<Vec<&'static str>>,
        panic_after_record: bool,
    }

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.events.borrow_mut().push(self.event);
            assert!(
                !self.panic_after_record,
                "intentional publication drop-order probe panic"
            );
        }
    }

    #[test]
    fn finish_publication_drops_quiescence_before_retired_value() {
        let events = RefCell::new(Vec::new());

        let output = finish_publication_after_quiescence(
            DropProbe {
                event: "guard",
                events: &events,
                panic_after_record: false,
            },
            DropProbe {
                event: "retired",
                events: &events,
                panic_after_record: false,
            },
            17_u8,
        );

        assert_eq!(output, 17);
        assert_eq!(events.borrow().as_slice(), ["guard", "retired"]);
    }

    #[test]
    fn finish_publication_preserves_drop_order_during_guard_unwind() {
        let events = RefCell::new(Vec::new());

        let result = catch_unwind(AssertUnwindSafe(|| {
            finish_publication_after_quiescence(
                DropProbe {
                    event: "guard",
                    events: &events,
                    panic_after_record: true,
                },
                DropProbe {
                    event: "retired",
                    events: &events,
                    panic_after_record: false,
                },
                (),
            );
        }));

        assert!(result.is_err());
        assert_eq!(events.borrow().as_slice(), ["guard", "retired"]);
    }

    #[test]
    fn production_nat_error_mappers_preserve_every_typed_value() {
        for error in [
            Nat44UdpRuntimeConfigError::MappingNodeCountMismatch,
            Nat44UdpRuntimeConfigError::PeerNodeCountMismatch,
            Nat44UdpRuntimeConfigError::MappingDirectoryInvalid,
            Nat44UdpRuntimeConfigError::PeerDirectoryInvalid,
            Nat44UdpRuntimeConfigError::PortOwnerTableInvalid,
            Nat44UdpRuntimeConfigError::RuntimeIdentityExhausted,
        ] {
            assert_eq!(
                nat44_udp_activation_error(error),
                InitialActivationError::Nat44UdpRuntime(error)
            );
        }
        for error in [
            Nat44TcpRuntimeConfigError::MappingNodeCountMismatch,
            Nat44TcpRuntimeConfigError::SessionNodeCountMismatch,
            Nat44TcpRuntimeConfigError::MappingDirectoryInvalid,
            Nat44TcpRuntimeConfigError::SessionDirectoryInvalid,
            Nat44TcpRuntimeConfigError::PortOwnerTableInvalid,
            Nat44TcpRuntimeConfigError::RuntimeIdentityExhausted,
        ] {
            assert_eq!(
                nat44_tcp_activation_error(error),
                InitialActivationError::Nat44TcpRuntime(error)
            );
        }
    }

    #[test]
    fn static_classification_fallback_is_typed_value_free_and_preserves_candidate() {
        assert_eq!(
            FullServiceRestartRequired::from(PlanRestartRequired::ResolutionPolicyChanged),
            FullServiceRestartRequired::ResolutionPolicyChanged
        );
        assert_eq!(
            FullServiceRestartRequired::from(PlanRestartRequired::Icmpv4ErrorPolicyChanged),
            FullServiceRestartRequired::Icmpv4ErrorPolicyChanged
        );
        assert_eq!(
            FullServiceRestartRequired::from(PlanRestartRequired::BackendChanged),
            FullServiceRestartRequired::BackendChanged
        );

        let rejection = unsupported_static_classification(17_u8);
        let (candidate, error) = rejection.into_parts();
        assert_eq!(candidate, 17);
        assert_eq!(
            error,
            FullServicePublishError::UnsupportedStaticClassification
        );
        assert_eq!(
            format!(
                "{:?}",
                FullServicePublishError::UnsupportedStaticClassification
            ),
            "UnsupportedStaticClassification"
        );
    }

    #[test]
    fn publish_error_disposition_continues_old_io_for_retryable_publication_errors() {
        // Protects the contract that an invalid successor or a restart-required
        // successor leaves the active backend running while the candidate is retried.
        for error in [
            FullServicePublishError::InvalidSuccessor(SuccessorError::GenerationNotIncreasing),
            FullServicePublishError::RestartRequired(
                FullServiceRestartRequired::InterfaceBindingsChanged,
            ),
        ] {
            assert_eq!(
                publish_error_disposition(error),
                ActivePublicationStatus::ContinueOldIo,
                "retryable publication errors must preserve the old I/O path: {error:?}"
            );
        }
    }
}

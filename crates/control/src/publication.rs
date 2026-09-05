use std::num::NonZeroU64;

use ruster_core::{
    FirewallConfig, FirewallConfigError, FirewallHashKey, FirewallPolicy, FirewallRule,
    ForwardingSnapshot, Icmpv4ErrorPolicy, IfId, Interface, Ipv4Address, Ipv4OriginPolicy,
    LocalIpv4Binding, Nat44TcpConfig, Nat44TcpConfigError, Nat44TcpHashKey, Nat44TcpPolicy,
    Nat44UdpConfig, Nat44UdpConfigError, Nat44UdpHashKey, Nat44UdpPolicy, Neighbor,
    ResolutionPolicy, Route, ValidatedFirewallOwner, ValidatedForwardingOwner,
    ValidatedForwardingOwnerError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionStorageShape {
    state_slots: u32,
    action_slots: u32,
    dynamic_neighbor_slots: u32,
    failure_hold_slots: u32,
    datagram_hold_slots: u32,
}

impl ResolutionStorageShape {
    #[must_use]
    pub const fn new(
        state_slots: u32,
        action_slots: u32,
        dynamic_neighbor_slots: u32,
        failure_hold_slots: u32,
        datagram_hold_slots: u32,
    ) -> Self {
        Self {
            state_slots,
            action_slots,
            dynamic_neighbor_slots,
            failure_hold_slots,
            datagram_hold_slots,
        }
    }

    #[must_use]
    pub const fn state_slots(self) -> u32 {
        self.state_slots
    }

    #[must_use]
    pub const fn action_slots(self) -> u32 {
        self.action_slots
    }

    #[must_use]
    pub const fn dynamic_neighbor_slots(self) -> u32 {
        self.dynamic_neighbor_slots
    }

    #[must_use]
    pub const fn failure_hold_slots(self) -> u32 {
        self.failure_hold_slots
    }

    /// Slots for datagrams held while their next hop resolves (FWD-008).
    #[must_use]
    pub const fn datagram_hold_slots(self) -> u32 {
        self.datagram_hold_slots
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorStorageShape {
    state_slots: u32,
    action_slots: u32,
}

impl Icmpv4ErrorStorageShape {
    #[must_use]
    pub const fn new(state_slots: u32, action_slots: u32) -> Self {
        Self {
            state_slots,
            action_slots,
        }
    }

    #[must_use]
    pub const fn state_slots(self) -> u32 {
        self.state_slots
    }

    #[must_use]
    pub const fn action_slots(self) -> u32 {
        self.action_slots
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpStoragePlan {
    mapping_slots: u32,
    peer_slots: u32,
    mapping_buckets: u32,
    mapping_nodes: u32,
    peer_buckets: u32,
    peer_nodes: u32,
    port_owner_slots: u32,
}

impl Nat44UdpStoragePlan {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        mapping_slots: u32,
        peer_slots: u32,
        mapping_buckets: u32,
        mapping_nodes: u32,
        peer_buckets: u32,
        peer_nodes: u32,
        port_owner_slots: u32,
    ) -> Self {
        Self {
            mapping_slots,
            peer_slots,
            mapping_buckets,
            mapping_nodes,
            peer_buckets,
            peer_nodes,
            port_owner_slots,
        }
    }

    #[must_use]
    pub const fn mapping_slots(self) -> u32 {
        self.mapping_slots
    }

    #[must_use]
    pub const fn peer_slots(self) -> u32 {
        self.peer_slots
    }

    #[must_use]
    pub const fn mapping_buckets(self) -> u32 {
        self.mapping_buckets
    }

    #[must_use]
    pub const fn mapping_nodes(self) -> u32 {
        self.mapping_nodes
    }

    #[must_use]
    pub const fn peer_buckets(self) -> u32 {
        self.peer_buckets
    }

    #[must_use]
    pub const fn peer_nodes(self) -> u32 {
        self.peer_nodes
    }

    #[must_use]
    pub const fn port_owner_slots(self) -> u32 {
        self.port_owner_slots
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpStoragePlan {
    mapping_slots: u32,
    session_slots: u32,
    mapping_buckets: u32,
    mapping_nodes: u32,
    session_buckets: u32,
    session_nodes: u32,
    port_owner_slots: u32,
}

impl Nat44TcpStoragePlan {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        mapping_slots: u32,
        session_slots: u32,
        mapping_buckets: u32,
        mapping_nodes: u32,
        session_buckets: u32,
        session_nodes: u32,
        port_owner_slots: u32,
    ) -> Self {
        Self {
            mapping_slots,
            session_slots,
            mapping_buckets,
            mapping_nodes,
            session_buckets,
            session_nodes,
            port_owner_slots,
        }
    }

    #[must_use]
    pub const fn mapping_slots(self) -> u32 {
        self.mapping_slots
    }

    #[must_use]
    pub const fn session_slots(self) -> u32 {
        self.session_slots
    }

    #[must_use]
    pub const fn mapping_buckets(self) -> u32 {
        self.mapping_buckets
    }

    #[must_use]
    pub const fn mapping_nodes(self) -> u32 {
        self.mapping_nodes
    }

    #[must_use]
    pub const fn session_buckets(self) -> u32 {
        self.session_buckets
    }

    #[must_use]
    pub const fn session_nodes(self) -> u32 {
        self.session_nodes
    }

    #[must_use]
    pub const fn port_owner_slots(self) -> u32 {
        self.port_owner_slots
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullServiceStorageShape {
    resolution: ResolutionStorageShape,
    icmpv4_errors: Icmpv4ErrorStorageShape,
    nat44_udp: Nat44UdpStoragePlan,
    nat44_tcp: Nat44TcpStoragePlan,
    firewall_state_slots: u32,
}

impl FullServiceStorageShape {
    #[must_use]
    pub const fn new(
        resolution: ResolutionStorageShape,
        icmpv4_errors: Icmpv4ErrorStorageShape,
        nat44_udp: Nat44UdpStoragePlan,
        nat44_tcp: Nat44TcpStoragePlan,
        firewall_state_slots: u32,
    ) -> Self {
        Self {
            resolution,
            icmpv4_errors,
            nat44_udp,
            nat44_tcp,
            firewall_state_slots,
        }
    }

    #[must_use]
    pub const fn resolution(self) -> ResolutionStorageShape {
        self.resolution
    }

    #[must_use]
    pub const fn icmpv4_errors(self) -> Icmpv4ErrorStorageShape {
        self.icmpv4_errors
    }

    #[must_use]
    pub const fn nat44_udp(self) -> Nat44UdpStoragePlan {
        self.nat44_udp
    }

    #[must_use]
    pub const fn nat44_tcp(self) -> Nat44TcpStoragePlan {
        self.nat44_tcp
    }

    #[must_use]
    pub const fn firewall_state_slots(self) -> u32 {
        self.firewall_state_slots
    }
}

/// Complete UDP NAT publication input.
///
/// This type deliberately has no `Debug` or `Clone` implementation because it
/// carries a publication hash key.
pub struct Nat44UdpPublicationInput {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44UdpPolicy,
    hash_key: Nat44UdpHashKey,
}

impl Nat44UdpPublicationInput {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        first_port: u16,
        last_port: u16,
        policy: Nat44UdpPolicy,
        hash_key: Nat44UdpHashKey,
    ) -> Self {
        Self {
            inside,
            outside,
            public_address,
            first_port,
            last_port,
            policy,
            hash_key,
        }
    }
}

/// Complete TCP NAT publication input.
///
/// This type deliberately has no `Debug` or `Clone` implementation because it
/// carries a publication hash key.
pub struct Nat44TcpPublicationInput {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44TcpPolicy,
    hash_key: Nat44TcpHashKey,
}

impl Nat44TcpPublicationInput {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        first_port: u16,
        last_port: u16,
        policy: Nat44TcpPolicy,
        hash_key: Nat44TcpHashKey,
    ) -> Self {
        Self {
            inside,
            outside,
            public_address,
            first_port,
            last_port,
            policy,
            hash_key,
        }
    }
}

/// Owned firewall input. Rules and the hash key are never formatted.
pub struct FirewallPublicationInput {
    rules: Box<[FirewallRule]>,
    policy: FirewallPolicy,
    hash_key: FirewallHashKey,
}

impl FirewallPublicationInput {
    #[must_use]
    pub fn new(
        rules: Box<[FirewallRule]>,
        policy: FirewallPolicy,
        hash_key: FirewallHashKey,
    ) -> Self {
        Self {
            rules,
            policy,
            hash_key,
        }
    }
}

/// Owned cold-path input for one required full-service publication.
///
/// The builder permits services to be supplied in any order, but
/// [`ValidatedCandidate::new`] rejects a missing UDP, TCP, or firewall service
/// with a typed, value-free error. It intentionally cannot be formatted or
/// cloned.
///
/// ```compile_fail
/// use ruster_control::PublicationPlan;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<PublicationPlan>();
/// ```
///
/// ```compile_fail
/// use ruster_control::PublicationPlan;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<PublicationPlan>();
/// ```
pub struct PublicationPlan {
    generation: NonZeroU64,
    storage_shape: FullServiceStorageShape,
    routes: Box<[Route]>,
    interfaces: Box<[Interface]>,
    neighbors: Box<[Neighbor]>,
    local_ipv4: Box<[LocalIpv4Binding]>,
    ipv4_origin: Ipv4OriginPolicy,
    resolution_policy: ResolutionPolicy,
    icmpv4_error_policy: Icmpv4ErrorPolicy,
    nat44_udp: Option<Nat44UdpPublicationInput>,
    nat44_tcp: Option<Nat44TcpPublicationInput>,
    firewall: Option<FirewallPublicationInput>,
}

impl PublicationPlan {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        generation: NonZeroU64,
        storage_shape: FullServiceStorageShape,
        routes: Box<[Route]>,
        interfaces: Box<[Interface]>,
        neighbors: Box<[Neighbor]>,
        local_ipv4: Box<[LocalIpv4Binding]>,
        ipv4_origin: Ipv4OriginPolicy,
        resolution_policy: ResolutionPolicy,
        icmpv4_error_policy: Icmpv4ErrorPolicy,
    ) -> Self {
        Self {
            generation,
            storage_shape,
            routes,
            interfaces,
            neighbors,
            local_ipv4,
            ipv4_origin,
            resolution_policy,
            icmpv4_error_policy,
            nat44_udp: None,
            nat44_tcp: None,
            firewall: None,
        }
    }

    #[must_use]
    pub fn with_nat44_udp(mut self, input: Nat44UdpPublicationInput) -> Self {
        self.nat44_udp = Some(input);
        self
    }

    #[must_use]
    pub fn with_nat44_tcp(mut self, input: Nat44TcpPublicationInput) -> Self {
        self.nat44_tcp = Some(input);
        self
    }

    #[must_use]
    pub fn with_firewall(mut self, input: FirewallPublicationInput) -> Self {
        self.firewall = Some(input);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeService {
    Resolution,
    Icmpv4Errors,
    Nat44Udp,
    Nat44Tcp,
    Firewall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StorageShapeError {
    UdpMappingNodeCount,
    UdpPeerNodeCount,
    UdpMappingDirectory,
    UdpPeerDirectory,
    UdpPortOwnerCount,
    TcpMappingNodeCount,
    TcpSessionNodeCount,
    TcpMappingDirectory,
    TcpSessionDirectory,
    TcpPortOwnerCount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublicationCandidateError {
    MissingService(RuntimeService),
    StorageShape(StorageShapeError),
    Forwarding(ValidatedForwardingOwnerError),
    Nat44Udp(Nat44UdpConfigError),
    Nat44Tcp(Nat44TcpConfigError),
    Nat44RealmMismatch,
    Firewall(FirewallConfigError),
}

/// Fully validated owned authority for one generation.
///
/// Dependent by-value NAT configurations and the firewall owner are declared
/// before the forwarding owner. Rust therefore drops them before their
/// forwarding authority. No field borrows another field.
///
/// ```compile_fail
/// use ruster_control::ValidatedCandidate;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<ValidatedCandidate>();
/// ```
///
/// ```compile_fail
/// use ruster_control::ValidatedCandidate;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<ValidatedCandidate>();
/// ```
pub struct ValidatedCandidate {
    generation: NonZeroU64,
    storage_shape: FullServiceStorageShape,
    resolution_policy: ResolutionPolicy,
    icmpv4_error_policy: Icmpv4ErrorPolicy,
    nat44_udp: Nat44UdpConfig,
    nat44_udp_hash_key: Nat44UdpHashKey,
    nat44_tcp: Nat44TcpConfig,
    nat44_tcp_hash_key: Nat44TcpHashKey,
    firewall: ValidatedFirewallOwner,
    forwarding: ValidatedForwardingOwner,
}

impl ValidatedCandidate {
    pub fn new(plan: PublicationPlan) -> Result<Self, PublicationCandidateError> {
        let PublicationPlan {
            generation,
            storage_shape,
            routes,
            interfaces,
            neighbors,
            local_ipv4,
            ipv4_origin,
            resolution_policy,
            icmpv4_error_policy,
            nat44_udp,
            nat44_tcp,
            firewall,
        } = plan;
        let nat44_udp = nat44_udp.ok_or(PublicationCandidateError::MissingService(
            RuntimeService::Nat44Udp,
        ))?;
        let nat44_tcp = nat44_tcp.ok_or(PublicationCandidateError::MissingService(
            RuntimeService::Nat44Tcp,
        ))?;
        let firewall = firewall.ok_or(PublicationCandidateError::MissingService(
            RuntimeService::Firewall,
        ))?;
        validate_structural_shapes(storage_shape)
            .map_err(PublicationCandidateError::StorageShape)?;

        // The owner is created before every dependent config. Box allocation
        // addresses remain stable when the finished candidate is moved.
        let forwarding =
            ValidatedForwardingOwner::new(routes, interfaces, neighbors, local_ipv4, ipv4_origin)
                .map_err(PublicationCandidateError::Forwarding)?;
        let snapshot = forwarding.snapshot();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            nat44_udp.inside,
            nat44_udp.outside,
            nat44_udp.public_address,
            nat44_udp.first_port,
            nat44_udp.last_port,
            nat44_udp.policy,
        )
        .map_err(PublicationCandidateError::Nat44Udp)?;
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            nat44_tcp.inside,
            nat44_tcp.outside,
            nat44_tcp.public_address,
            nat44_tcp.first_port,
            nat44_tcp.last_port,
            nat44_tcp.policy,
        )
        .map_err(PublicationCandidateError::Nat44Tcp)?;
        if udp_config.inside() != tcp_config.inside()
            || udp_config.outside() != tcp_config.outside()
            || udp_config.public_address() != tcp_config.public_address()
        {
            return Err(PublicationCandidateError::Nat44RealmMismatch);
        }
        validate_port_owner_shapes(storage_shape, udp_config, tcp_config)
            .map_err(PublicationCandidateError::StorageShape)?;
        let firewall_owner = ValidatedFirewallOwner::new(
            &snapshot,
            firewall.rules,
            firewall.policy,
            generation.get(),
            firewall.hash_key,
        )
        .map_err(PublicationCandidateError::Firewall)?;
        Ok(Self {
            generation,
            storage_shape,
            resolution_policy,
            icmpv4_error_policy,
            nat44_udp: udp_config,
            nat44_udp_hash_key: nat44_udp.hash_key,
            nat44_tcp: tcp_config,
            nat44_tcp_hash_key: nat44_tcp.hash_key,
            firewall: firewall_owner,
            forwarding,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    #[must_use]
    pub const fn storage_shape(&self) -> FullServiceStorageShape {
        self.storage_shape
    }

    #[cfg(test)]
    pub(crate) fn owned_box_pointers(&self) -> [usize; 5] {
        [
            self.forwarding.routes().as_ptr() as usize,
            self.forwarding.interfaces().as_ptr() as usize,
            self.forwarding.neighbors().as_ptr() as usize,
            self.forwarding.local_ipv4().as_ptr() as usize,
            self.firewall.rules().as_ptr() as usize,
        ]
    }

    /// Builds one O(1), lifetime-bound authority borrow.
    #[must_use]
    pub fn authority(&self) -> ValidatedAuthority<'_> {
        let snapshot = self.forwarding.snapshot();
        ValidatedAuthority {
            generation: self.generation,
            snapshot,
            resolution_policy: self.resolution_policy,
            icmpv4_error_policy: self.icmpv4_error_policy,
            nat44_udp: self.nat44_udp,
            nat44_udp_hash_key: self.nat44_udp_hash_key,
            nat44_tcp: self.nat44_tcp,
            nat44_tcp_hash_key: self.nat44_tcp_hash_key,
            firewall: self.firewall.config(),
        }
    }

    /// Checks cold successor invariants without installing either owner.
    pub fn validate_successor(&self, candidate: &Self) -> Result<(), SuccessorError> {
        if self.generation.get() == u64::MAX {
            return Err(SuccessorError::GenerationExhausted);
        }
        if candidate.generation <= self.generation {
            return Err(SuccessorError::GenerationNotIncreasing);
        }
        if candidate.nat44_udp_hash_key == self.nat44_udp_hash_key {
            return Err(SuccessorError::Nat44UdpHashKeyReused);
        }
        if candidate.nat44_tcp_hash_key == self.nat44_tcp_hash_key {
            return Err(SuccessorError::Nat44TcpHashKeyReused);
        }
        if candidate.firewall.config().hash_key() == self.firewall.config().hash_key() {
            return Err(SuccessorError::FirewallHashKeyReused);
        }
        if candidate.storage_shape != self.storage_shape {
            return Err(SuccessorError::StorageShapeChanged);
        }
        if candidate.resolution_policy != self.resolution_policy {
            return Err(SuccessorError::ResolutionPolicyChanged);
        }
        if candidate.icmpv4_error_policy != self.icmpv4_error_policy {
            return Err(SuccessorError::Icmpv4ErrorPolicyChanged);
        }
        Ok(())
    }
}

/// Borrow-scoped coherent configuration for runtime construction or checking.
///
/// This view is move-only and non-debuggable. Its forwarding snapshot and
/// firewall config cannot outlive or overlap a move of the owner.
///
/// ```compile_fail
/// use ruster_control::ValidatedCandidate;
/// use ruster_core::ForwardingSnapshot;
///
/// fn escape(candidate: &ValidatedCandidate) -> ForwardingSnapshot<'static> {
///     candidate.authority().snapshot()
/// }
/// ```
///
/// ```compile_fail
/// use ruster_control::ValidatedCandidate;
///
/// fn move_while_borrowed(candidate: ValidatedCandidate) {
///     let authority = candidate.authority();
///     let snapshot = authority.snapshot();
///     let moved = candidate;
///     drop((snapshot, moved));
/// }
/// ```
///
/// ```compile_fail
/// use ruster_control::ValidatedAuthority;
///
/// fn require_copy<T: Copy>() {}
/// require_copy::<ValidatedAuthority<'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_control::ValidatedAuthority;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<ValidatedAuthority<'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_control::ValidatedAuthority;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<ValidatedAuthority<'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_control::ValidatedCandidate;
/// use ruster_core::FirewallConfig;
///
/// fn escape(candidate: &ValidatedCandidate) -> FirewallConfig<'static> {
///     candidate.authority().firewall_config()
/// }
/// ```
pub struct ValidatedAuthority<'view> {
    generation: NonZeroU64,
    snapshot: ForwardingSnapshot<'view>,
    resolution_policy: ResolutionPolicy,
    icmpv4_error_policy: Icmpv4ErrorPolicy,
    nat44_udp: Nat44UdpConfig,
    nat44_udp_hash_key: Nat44UdpHashKey,
    nat44_tcp: Nat44TcpConfig,
    nat44_tcp_hash_key: Nat44TcpHashKey,
    firewall: FirewallConfig<'view>,
}

impl<'view> ValidatedAuthority<'view> {
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    #[must_use]
    pub const fn snapshot(&self) -> ForwardingSnapshot<'view> {
        self.snapshot
    }

    #[must_use]
    pub const fn resolution_policy(&self) -> ResolutionPolicy {
        self.resolution_policy
    }

    #[must_use]
    pub const fn icmpv4_error_policy(&self) -> Icmpv4ErrorPolicy {
        self.icmpv4_error_policy
    }

    #[must_use]
    pub const fn nat44_udp_config(&self) -> Nat44UdpConfig {
        self.nat44_udp
    }

    #[must_use]
    pub const fn nat44_udp_hash_key(&self) -> Nat44UdpHashKey {
        self.nat44_udp_hash_key
    }

    #[must_use]
    pub const fn nat44_tcp_config(&self) -> Nat44TcpConfig {
        self.nat44_tcp
    }

    #[must_use]
    pub const fn nat44_tcp_hash_key(&self) -> Nat44TcpHashKey {
        self.nat44_tcp_hash_key
    }

    #[must_use]
    pub const fn firewall_config(&self) -> FirewallConfig<'view> {
        self.firewall
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SuccessorError {
    GenerationExhausted,
    GenerationNotIncreasing,
    Nat44UdpHashKeyReused,
    Nat44TcpHashKeyReused,
    FirewallHashKeyReused,
    StorageShapeChanged,
    ResolutionPolicyChanged,
    Icmpv4ErrorPolicyChanged,
}

fn validate_structural_shapes(shape: FullServiceStorageShape) -> Result<(), StorageShapeError> {
    if shape.nat44_udp.mapping_nodes != shape.nat44_udp.mapping_slots {
        return Err(StorageShapeError::UdpMappingNodeCount);
    }
    if shape.nat44_udp.peer_nodes != shape.nat44_udp.peer_slots {
        return Err(StorageShapeError::UdpPeerNodeCount);
    }
    if !directory_shape_valid(
        shape.nat44_udp.mapping_buckets,
        shape.nat44_udp.mapping_nodes,
    ) {
        return Err(StorageShapeError::UdpMappingDirectory);
    }
    if !directory_shape_valid(shape.nat44_udp.peer_buckets, shape.nat44_udp.peer_nodes) {
        return Err(StorageShapeError::UdpPeerDirectory);
    }
    if shape.nat44_tcp.mapping_nodes != shape.nat44_tcp.mapping_slots {
        return Err(StorageShapeError::TcpMappingNodeCount);
    }
    if shape.nat44_tcp.session_nodes != shape.nat44_tcp.session_slots {
        return Err(StorageShapeError::TcpSessionNodeCount);
    }
    if !directory_shape_valid(
        shape.nat44_tcp.mapping_buckets,
        shape.nat44_tcp.mapping_nodes,
    ) {
        return Err(StorageShapeError::TcpMappingDirectory);
    }
    if !directory_shape_valid(
        shape.nat44_tcp.session_buckets,
        shape.nat44_tcp.session_nodes,
    ) {
        return Err(StorageShapeError::TcpSessionDirectory);
    }
    Ok(())
}

fn validate_port_owner_shapes(
    shape: FullServiceStorageShape,
    udp: Nat44UdpConfig,
    tcp: Nat44TcpConfig,
) -> Result<(), StorageShapeError> {
    let udp_ports = u32::from(udp.last_port()) - u32::from(udp.first_port()) + 1;
    if shape.nat44_udp.port_owner_slots != udp_ports {
        return Err(StorageShapeError::UdpPortOwnerCount);
    }
    let tcp_ports = u32::from(tcp.last_port()) - u32::from(tcp.first_port()) + 1;
    if shape.nat44_tcp.port_owner_slots != tcp_ports {
        return Err(StorageShapeError::TcpPortOwnerCount);
    }
    Ok(())
}

fn directory_shape_valid(bucket_count: u32, node_count: u32) -> bool {
    if node_count == 0 {
        return bucket_count == 0;
    }
    bucket_count != 0
        && bucket_count.is_power_of_two()
        && node_count
            .checked_next_power_of_two()
            .is_some_and(|minimum| bucket_count >= minimum)
}

#[cfg(test)]
mod tests {
    use super::directory_shape_valid;

    #[test]
    fn directory_shape_valid_requires_zero_pair_and_sufficient_power_of_two_buckets() {
        // Protects the empty-directory special case, the non-zero power-of-
        // two requirement, and the minimum bucket capacity for nodes.
        for (bucket_count, node_count, expected) in [
            (0, 0, true),
            (1, 0, false),
            (3, 1, false),
            (1, 2, false),
            (4, 3, true),
            (8, 4, true),
        ] {
            assert_eq!(
                directory_shape_valid(bucket_count, node_count),
                expected,
                "bucket_count={bucket_count}, node_count={node_count}"
            );
        }
    }
}

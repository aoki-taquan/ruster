use std::num::NonZeroU64;

use ruster_core::{
    ArpPolicy, FirewallConfig, FirewallConfigError, FirewallHashKey, FirewallPolicy, FirewallRule,
    ForwardingSnapshot, Icmpv4ErrorPolicy, IfId, Interface, Ipv4Address,
    Ipv4FragmentTrackingPolicy, Ipv4FragmentationPolicy, Ipv4OriginPolicy, LocalIpv4Binding,
    Nat44IcmpConfig, Nat44IcmpConfigError, Nat44IcmpHashKey, Nat44IcmpPolicy, Nat44TcpConfig,
    Nat44TcpConfigError, Nat44TcpHashKey, Nat44TcpPolicy, Nat44UdpConfig, Nat44UdpConfigError,
    Nat44UdpHashKey, Nat44UdpPolicy, Neighbor, ResolutionHashKey, ResolutionPolicy, Route,
    ValidatedFirewallOwner, ValidatedForwardingOwner, ValidatedForwardingOwnerError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionStorageShape {
    state_slots: u32,
    action_slots: u32,
    dynamic_neighbor_slots: u32,
    failure_hold_slots: u32,
}

impl ResolutionStorageShape {
    #[must_use]
    pub const fn new(
        state_slots: u32,
        action_slots: u32,
        dynamic_neighbor_slots: u32,
        failure_hold_slots: u32,
    ) -> Self {
        Self {
            state_slots,
            action_slots,
            dynamic_neighbor_slots,
            failure_hold_slots,
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
    host_slots: u32,
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
            host_slots: 0,
        }
    }

    /// This plan with `slots` host slots of the per-host mapping accounting
    /// (N3; `0` from [`Self::new`]): `0`, or the mapping slot count. Each
    /// comes with a host link and a host directory node, and the host
    /// directory has the mapping directory's bucket count.
    #[must_use]
    pub const fn with_host_slots(mut self, slots: u32) -> Self {
        self.host_slots = slots;
        self
    }

    #[must_use]
    pub const fn host_slots(self) -> u32 {
        self.host_slots
    }

    /// Buckets of the host directory: the mapping directory's, or `0`
    /// without host slots.
    #[must_use]
    pub const fn host_buckets(self) -> u32 {
        if self.host_slots == 0 {
            0
        } else {
            self.mapping_buckets
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
    unsolicited_syn_hold_slots: u32,
    host_slots: u32,
    session_host_slots: u32,
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
            unsolicited_syn_hold_slots: 0,
            host_slots: 0,
            session_host_slots: 0,
        }
    }

    /// This plan with `slots` host slots of the per-host session accounting
    /// (N6; `0` from [`Self::new`]): `0`, or the session slot count. Each
    /// comes with a host link and a host directory node, and that directory
    /// has the session directory's bucket count.
    #[must_use]
    pub const fn with_session_host_slots(mut self, slots: u32) -> Self {
        self.session_host_slots = slots;
        self
    }

    #[must_use]
    pub const fn session_host_slots(self) -> u32 {
        self.session_host_slots
    }

    /// Buckets of the session host directory: the session directory's, or
    /// `0` without session host slots.
    #[must_use]
    pub const fn session_host_buckets(self) -> u32 {
        if self.session_host_slots == 0 {
            0
        } else {
            self.session_buckets
        }
    }

    /// This plan with `slots` host slots of the per-host mapping accounting
    /// (N3; `0` from [`Self::new`]); see
    /// [`Nat44UdpStoragePlan::with_host_slots`].
    #[must_use]
    pub const fn with_host_slots(mut self, slots: u32) -> Self {
        self.host_slots = slots;
        self
    }

    #[must_use]
    pub const fn host_slots(self) -> u32 {
        self.host_slots
    }

    /// Buckets of the host directory: the mapping directory's, or `0`
    /// without host slots.
    #[must_use]
    pub const fn host_buckets(self) -> u32 {
        if self.host_slots == 0 {
            0
        } else {
            self.mapping_buckets
        }
    }

    /// This plan with `slots` unsolicited-SYN hold slots (RFC 5382 REQ-4;
    /// `0` from [`Self::new`]).
    #[must_use]
    pub const fn with_unsolicited_syn_hold_slots(mut self, slots: u32) -> Self {
        self.unsolicited_syn_hold_slots = slots;
        self
    }

    #[must_use]
    pub const fn unsolicited_syn_hold_slots(self) -> u32 {
        self.unsolicited_syn_hold_slots
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

/// Storage of the optional ICMP query NAT (N5): the datagram mapping
/// engine's tables, with one owner slot per public identifier in place of
/// the port owners.
pub type Nat44IcmpStoragePlan = Nat44UdpStoragePlan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FullServiceStorageShape {
    resolution: ResolutionStorageShape,
    icmpv4_errors: Icmpv4ErrorStorageShape,
    nat44_udp: Nat44UdpStoragePlan,
    nat44_tcp: Nat44TcpStoragePlan,
    /// `None` without ICMP query NAT; adding or removing it changes the
    /// shape (restart-required).
    nat44_icmp: Option<Nat44IcmpStoragePlan>,
    firewall_state_slots: u32,
    /// `None` without fragmentation (off, or not configured); the policy is
    /// part of the shape, so any `[fragmentation]` change is restart-required
    /// (`STORAGE_SHAPE`).
    fragmentation: Option<FragmentationStoragePlan>,
    /// `None` without fragment association (`[fragment-tracking] mode =
    /// "refuse"`); the policy is part of the shape (restart-required).
    fragment_tracking: Option<FragmentTrackingStoragePlan>,
}

/// IPv4 fragment association (NAT-FRAG): its policy, `entries` entry and
/// host slots with `buckets` buckets per directory, and `held` held
/// fragments of `held_slot_bytes` bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentTrackingStoragePlan {
    policy: Ipv4FragmentTrackingPolicy,
    entries: u32,
    buckets: u32,
    held: u32,
    held_slot_bytes: u32,
}

impl FragmentTrackingStoragePlan {
    #[must_use]
    pub const fn new(
        policy: Ipv4FragmentTrackingPolicy,
        entries: u32,
        buckets: u32,
        held: u32,
        held_slot_bytes: u32,
    ) -> Self {
        Self {
            policy,
            entries,
            buckets,
            held,
            held_slot_bytes,
        }
    }

    #[must_use]
    pub const fn policy(self) -> Ipv4FragmentTrackingPolicy {
        self.policy
    }

    #[must_use]
    pub const fn entries(self) -> u32 {
        self.entries
    }

    #[must_use]
    pub const fn buckets(self) -> u32 {
        self.buckets
    }

    #[must_use]
    pub const fn held(self) -> u32 {
        self.held
    }

    #[must_use]
    pub const fn held_slot_bytes(self) -> u32 {
        self.held_slot_bytes
    }
}

/// IPv4 fragmentation (MTU2 part B): its policy (enabled) and `datagrams`
/// slots of `slot_bytes` bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentationStoragePlan {
    policy: Ipv4FragmentationPolicy,
    datagrams: u32,
    slot_bytes: u32,
}

impl FragmentationStoragePlan {
    #[must_use]
    pub const fn new(policy: Ipv4FragmentationPolicy, datagrams: u32, slot_bytes: u32) -> Self {
        Self {
            policy,
            datagrams,
            slot_bytes,
        }
    }

    #[must_use]
    pub const fn policy(self) -> Ipv4FragmentationPolicy {
        self.policy
    }

    #[must_use]
    pub const fn datagrams(self) -> u32 {
        self.datagrams
    }

    #[must_use]
    pub const fn slot_bytes(self) -> u32 {
        self.slot_bytes
    }
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
            nat44_icmp: None,
            firewall_state_slots,
            fragmentation: None,
            fragment_tracking: None,
        }
    }

    /// This shape with IPv4 fragment association (NAT-FRAG). Without it
    /// every received fragment is refused (`FIREWALL_FRAGMENT_UNSUPPORTED`
    /// first).
    #[must_use]
    pub const fn with_fragment_tracking(mut self, plan: FragmentTrackingStoragePlan) -> Self {
        self.fragment_tracking = Some(plan);
        self
    }

    #[must_use]
    pub const fn fragment_tracking(self) -> Option<FragmentTrackingStoragePlan> {
        self.fragment_tracking
    }

    /// This shape with IPv4 fragmentation (MTU2 part B). Without it a
    /// DF-clear datagram above its egress MTU is `IPV4_FRAGMENTATION_REQUIRED`.
    #[must_use]
    pub const fn with_fragmentation(mut self, plan: FragmentationStoragePlan) -> Self {
        self.fragmentation = Some(plan);
        self
    }

    #[must_use]
    pub const fn fragmentation(self) -> Option<FragmentationStoragePlan> {
        self.fragmentation
    }

    /// This shape with ICMP query NAT storage (N5).
    #[must_use]
    pub const fn with_nat44_icmp(mut self, plan: Nat44IcmpStoragePlan) -> Self {
        self.nat44_icmp = Some(plan);
        self
    }

    #[must_use]
    pub const fn nat44_icmp(self) -> Option<Nat44IcmpStoragePlan> {
        self.nat44_icmp
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

/// Complete ICMP query NAT publication input (N5).
///
/// No `Debug` or `Clone`: it carries a publication hash key.
pub struct Nat44IcmpPublicationInput {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_identifier: u16,
    last_identifier: u16,
    policy: Nat44IcmpPolicy,
    hash_key: Nat44IcmpHashKey,
}

impl Nat44IcmpPublicationInput {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        first_identifier: u16,
        last_identifier: u16,
        policy: Nat44IcmpPolicy,
        hash_key: Nat44IcmpHashKey,
    ) -> Self {
        Self {
            inside,
            outside,
            public_address,
            first_identifier,
            last_identifier,
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
    arp_policy: ArpPolicy,
    resolution_policy: ResolutionPolicy,
    icmpv4_error_policy: Icmpv4ErrorPolicy,
    resolution_hash_key: Option<ResolutionHashKey>,
    nat44_udp: Option<Nat44UdpPublicationInput>,
    nat44_tcp: Option<Nat44TcpPublicationInput>,
    nat44_icmp: Option<Nat44IcmpPublicationInput>,
    firewall: Option<FirewallPublicationInput>,
    reload_state: ReloadState,
}

/// What applying a candidate does with the live runtimes' state
/// (RELOAD-CARRY).
///
/// The state family that a successor does not invalidate is carried with its
/// hash key; the rest flushes with a fresh key. See
/// [`ActivePublication`](crate::ActivePublication) for the per-family rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReloadState {
    /// Keep NAT44 mappings/sessions, firewall flows (re-evaluated against
    /// changed rules), and learned ARP neighbors whose meaning the
    /// successor does not change. `[reload] state = "carry"`, the config
    /// default.
    Carry,
    /// Flush every family and rotate every hash key, the behavior before
    /// RELOAD-CARRY. `[reload] state = "flush"`, and the default of a
    /// [`PublicationPlan`] built without
    /// [`PublicationPlan::with_reload_state`].
    Flush,
}

impl ReloadState {
    /// Stable lowercase label (`carry`, `flush`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Carry => "carry",
            Self::Flush => "flush",
        }
    }
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
            arp_policy: ArpPolicy::RFC826,
            resolution_policy,
            icmpv4_error_policy,
            resolution_hash_key: None,
            nat44_udp: None,
            nat44_tcp: None,
            nat44_icmp: None,
            firewall: None,
            reload_state: ReloadState::Flush,
        }
    }

    /// Sets what applying this candidate does with live state (default
    /// [`ReloadState::Flush`]; the config bridge passes `[reload] state`).
    #[must_use]
    pub fn with_reload_state(mut self, reload_state: ReloadState) -> Self {
        self.reload_state = reload_state;
        self
    }

    /// Adds the optional ICMP query NAT (N5). Its storage must be in the
    /// shape ([`FullServiceStorageShape::with_nat44_icmp`]) and its realm
    /// must match UDP and TCP.
    #[must_use]
    pub fn with_nat44_icmp(mut self, input: Nat44IcmpPublicationInput) -> Self {
        self.nat44_icmp = Some(input);
        self
    }

    /// Supplies the secret key of the resolution runtime's hashed indexes
    /// (required; without it the candidate is
    /// `MissingService(RuntimeService::Resolution)`).
    #[must_use]
    pub fn with_resolution_hash_key(mut self, hash_key: ResolutionHashKey) -> Self {
        self.resolution_hash_key = Some(hash_key);
        self
    }

    /// Sets the ARP receive policy of the forwarding snapshot (default
    /// [`ArpPolicy::RFC826`]).
    #[must_use]
    pub fn with_arp_policy(mut self, arp: ArpPolicy) -> Self {
        self.arp_policy = arp;
        self
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
    /// The optional ICMP query NAT (N5).
    Nat44Icmp,
    /// The optional IPv4 fragmentation slots (MTU2 part B).
    Fragmentation,
    /// The optional IPv4 fragment association table (NAT-FRAG).
    FragmentTracking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StorageShapeError {
    /// ICMP query NAT storage (N5) is present without the service or the
    /// service without its storage.
    IcmpPresence,
    IcmpMappingNodeCount,
    IcmpPeerNodeCount,
    IcmpMappingDirectory,
    IcmpPeerDirectory,
    /// Identifier owner slots differ from the identifier pool size.
    IcmpIdentifierOwnerCount,
    IcmpHostSlotCount,
    UdpMappingNodeCount,
    UdpPeerNodeCount,
    UdpMappingDirectory,
    UdpPeerDirectory,
    UdpPortOwnerCount,
    /// UDP host slots (N3) are neither `0` nor the mapping slot count, or
    /// are `0` while the policy sets a per-host mapping or peer limit.
    UdpHostSlotCount,
    TcpMappingNodeCount,
    TcpSessionNodeCount,
    TcpMappingDirectory,
    TcpSessionDirectory,
    TcpPortOwnerCount,
    /// TCP host slots (N3), as for UDP.
    TcpHostSlotCount,
    /// TCP session host slots (N6) are neither `0` nor the session slot
    /// count, or are `0` while the policy sets a per-host session limit.
    TcpSessionHostSlotCount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublicationCandidateError {
    MissingService(RuntimeService),
    StorageShape(StorageShapeError),
    Forwarding(ValidatedForwardingOwnerError),
    Nat44Udp(Nat44UdpConfigError),
    Nat44Tcp(Nat44TcpConfigError),
    Nat44Icmp(Nat44IcmpConfigError),
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
    resolution_hash_key: ResolutionHashKey,
    icmpv4_error_policy: Icmpv4ErrorPolicy,
    /// Owned copy of the published interface identities (IfId, MAC, MTU),
    /// compared by successor validation. It borrows nothing.
    interfaces: Box<[Interface]>,
    nat44_udp: Nat44UdpConfig,
    nat44_udp_hash_key: Nat44UdpHashKey,
    nat44_tcp: Nat44TcpConfig,
    nat44_tcp_hash_key: Nat44TcpHashKey,
    nat44_icmp: Option<(Nat44IcmpConfig, Nat44IcmpHashKey)>,
    firewall: ValidatedFirewallOwner,
    forwarding: ValidatedForwardingOwner,
    reload_state: ReloadState,
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
            arp_policy,
            resolution_policy,
            icmpv4_error_policy,
            resolution_hash_key,
            nat44_udp,
            nat44_tcp,
            nat44_icmp,
            firewall,
            reload_state,
        } = plan;
        let resolution_hash_key = resolution_hash_key.ok_or(
            PublicationCandidateError::MissingService(RuntimeService::Resolution),
        )?;
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

        let interface_identities = interfaces.clone();
        // The owner is created before every dependent config. Box allocation
        // addresses remain stable when the finished candidate is moved.
        let forwarding =
            ValidatedForwardingOwner::new(routes, interfaces, neighbors, local_ipv4, ipv4_origin)
                .map_err(PublicationCandidateError::Forwarding)?
                .with_arp_policy(arp_policy);
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
        let nat44_icmp = match (nat44_icmp, storage_shape.nat44_icmp) {
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                return Err(PublicationCandidateError::StorageShape(
                    StorageShapeError::IcmpPresence,
                ))
            }
            (Some(input), Some(plan)) => {
                let config = Nat44IcmpConfig::new(
                    &snapshot,
                    input.inside,
                    input.outside,
                    input.public_address,
                    input.first_identifier,
                    input.last_identifier,
                    input.policy,
                )
                .map_err(PublicationCandidateError::Nat44Icmp)?;
                if config.inside() != udp_config.inside()
                    || config.outside() != udp_config.outside()
                    || config.public_address() != udp_config.public_address()
                {
                    return Err(PublicationCandidateError::Nat44RealmMismatch);
                }
                validate_icmp_shape(plan, config)
                    .map_err(PublicationCandidateError::StorageShape)?;
                Some((config, input.hash_key))
            }
        };
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
            resolution_hash_key,
            icmpv4_error_policy,
            interfaces: interface_identities,
            nat44_udp: udp_config,
            nat44_udp_hash_key: nat44_udp.hash_key,
            nat44_tcp: tcp_config,
            nat44_tcp_hash_key: nat44_tcp.hash_key,
            nat44_icmp,
            firewall: firewall_owner,
            forwarding,
            reload_state,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    /// What applying this candidate does with live state.
    #[must_use]
    pub const fn reload_state(&self) -> ReloadState {
        self.reload_state
    }

    #[must_use]
    pub const fn storage_shape(&self) -> FullServiceStorageShape {
        self.storage_shape
    }

    /// Test-only read access to the owned forwarding tables.
    #[cfg(feature = "validation-test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub const fn forwarding_owner(&self) -> &ValidatedForwardingOwner {
        &self.forwarding
    }

    /// Builds one O(1), lifetime-bound authority borrow.
    #[must_use]
    pub fn authority(&self) -> ValidatedAuthority<'_> {
        let snapshot = self.forwarding.snapshot();
        ValidatedAuthority {
            generation: self.generation,
            snapshot,
            resolution_policy: self.resolution_policy,
            resolution_hash_key: self.resolution_hash_key,
            icmpv4_error_policy: self.icmpv4_error_policy,
            nat44_udp: self.nat44_udp,
            nat44_udp_hash_key: self.nat44_udp_hash_key,
            nat44_tcp: self.nat44_tcp,
            nat44_tcp_hash_key: self.nat44_tcp_hash_key,
            nat44_icmp: self.nat44_icmp,
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
        if let (Some((_, new)), Some((_, old))) = (candidate.nat44_icmp, self.nat44_icmp) {
            if new == old {
                return Err(SuccessorError::Nat44IcmpHashKeyReused);
            }
        }
        if candidate.firewall.config().hash_key() == self.firewall.config().hash_key() {
            return Err(SuccessorError::FirewallHashKeyReused);
        }
        if candidate.resolution_hash_key == self.resolution_hash_key {
            return Err(SuccessorError::ResolutionHashKeyReused);
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
        // The validated owner rejects duplicate IfIds, so equal length plus
        // inclusion is set equality of (IfId, MAC, MTU) triples.
        if candidate.interfaces.len() != self.interfaces.len()
            || !candidate
                .interfaces
                .iter()
                .all(|interface| self.interfaces.contains(interface))
        {
            return Err(SuccessorError::InterfacesChanged);
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
    resolution_hash_key: ResolutionHashKey,
    icmpv4_error_policy: Icmpv4ErrorPolicy,
    nat44_udp: Nat44UdpConfig,
    nat44_udp_hash_key: Nat44UdpHashKey,
    nat44_tcp: Nat44TcpConfig,
    nat44_tcp_hash_key: Nat44TcpHashKey,
    nat44_icmp: Option<(Nat44IcmpConfig, Nat44IcmpHashKey)>,
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
    pub const fn resolution_hash_key(&self) -> ResolutionHashKey {
        self.resolution_hash_key
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

    /// The ICMP query NAT config (N5), if configured.
    #[must_use]
    pub const fn nat44_icmp_config(&self) -> Option<Nat44IcmpConfig> {
        match self.nat44_icmp {
            Some((config, _)) => Some(config),
            None => None,
        }
    }

    #[must_use]
    pub const fn nat44_icmp_hash_key(&self) -> Option<Nat44IcmpHashKey> {
        match self.nat44_icmp {
            Some((_, key)) => Some(key),
            None => None,
        }
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
    Nat44IcmpHashKeyReused,
    FirewallHashKeyReused,
    ResolutionHashKeyReused,
    StorageShapeChanged,
    ResolutionPolicyChanged,
    Icmpv4ErrorPolicyChanged,
    /// The set of interface IfIds or their MAC addresses changed.
    InterfacesChanged,
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
    if shape.nat44_udp.host_slots != 0
        && shape.nat44_udp.host_slots != shape.nat44_udp.mapping_slots
    {
        return Err(StorageShapeError::UdpHostSlotCount);
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
    if shape.nat44_tcp.host_slots != 0
        && shape.nat44_tcp.host_slots != shape.nat44_tcp.mapping_slots
    {
        return Err(StorageShapeError::TcpHostSlotCount);
    }
    if shape.nat44_tcp.session_host_slots != 0
        && shape.nat44_tcp.session_host_slots != shape.nat44_tcp.session_slots
    {
        return Err(StorageShapeError::TcpSessionHostSlotCount);
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
    // A per-host mapping (N3) or peer (N6) limit needs the per-host
    // storage, a per-host session limit (N6) the per-session one.
    if (udp.policy().mappings_per_host() != 0 || udp.policy().peers_per_host() != 0)
        && shape.nat44_udp.host_slots != shape.nat44_udp.mapping_slots
    {
        return Err(StorageShapeError::UdpHostSlotCount);
    }
    if tcp.policy().mappings_per_host() != 0
        && shape.nat44_tcp.host_slots != shape.nat44_tcp.mapping_slots
    {
        return Err(StorageShapeError::TcpHostSlotCount);
    }
    if tcp.policy().sessions_per_host() != 0
        && shape.nat44_tcp.session_host_slots != shape.nat44_tcp.session_slots
    {
        return Err(StorageShapeError::TcpSessionHostSlotCount);
    }
    Ok(())
}

fn validate_icmp_shape(
    plan: Nat44IcmpStoragePlan,
    config: Nat44IcmpConfig,
) -> Result<(), StorageShapeError> {
    if plan.mapping_nodes != plan.mapping_slots {
        return Err(StorageShapeError::IcmpMappingNodeCount);
    }
    if plan.peer_nodes != plan.peer_slots {
        return Err(StorageShapeError::IcmpPeerNodeCount);
    }
    if !directory_shape_valid(plan.mapping_buckets, plan.mapping_nodes) {
        return Err(StorageShapeError::IcmpMappingDirectory);
    }
    if !directory_shape_valid(plan.peer_buckets, plan.peer_nodes) {
        return Err(StorageShapeError::IcmpPeerDirectory);
    }
    let identifiers =
        u32::from(config.last_identifier()) - u32::from(config.first_identifier()) + 1;
    if plan.port_owner_slots != identifiers {
        return Err(StorageShapeError::IcmpIdentifierOwnerCount);
    }
    if (plan.host_slots != 0 && plan.host_slots != plan.mapping_slots)
        || ((config.policy().mappings_per_host() != 0 || config.policy().peers_per_host() != 0)
            && plan.host_slots != plan.mapping_slots)
    {
        return Err(StorageShapeError::IcmpHostSlotCount);
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

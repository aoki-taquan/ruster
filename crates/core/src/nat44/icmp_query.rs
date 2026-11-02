//! NAT44 ICMP query translation (RFC 5508 §3, N5).
//!
//! An ICMP query (Echo, RFC 792; Timestamp, RFC 792) carries no ports. RFC
//! 5508 §3.1 identifies an ICMP query session by the Query Identifier, and a
//! NAPT translates that identifier (REQ-1) with a mapping that SHOULD be
//! external-host independent (REQ-1 a). The state of such a mapping is the
//! state of an Endpoint-Independent UDP mapping with the identifier in the
//! place of the port:
//!
//! - mapping key: inside interface, internal IPv4 address, internal
//!   identifier (REQ-1 a: the remote host is not part of it);
//! - public identifier: unique among live mappings, preserved when free and
//!   in the pool, otherwise selected by the keyed RFC 6056 search (N2);
//! - filter peers: the remote addresses the mapping has queried, used for
//!   address-dependent filtering of replies and for the authority of
//!   translated ICMP errors;
//! - one idle timer per mapping (REQ-2: at least 60 s), refreshed only by
//!   outbound queries.
//!
//! [`Nat44IcmpRuntime`] therefore drives the same caller-backed mapping
//! engine as [`Nat44UdpRuntime`] (O(1) slot lists, keyed directories, the
//! free-identifier bitmap, and the per-host quota) on its own storage, with
//! its own fresh hash key, its own counters, and an identifier pool that is
//! independent of the UDP and TCP port pools. Nothing is shared with the UDP
//! runtime: the two engines never see each other's state or key.

use super::*;

/// RFC 5508 REQ-2: an ICMP query session timer MUST NOT expire in less than
/// 60 seconds.
pub const NAT44_ICMP_MIN_IDLE_TTL_MS: u64 = 60_000;
/// Default ICMP query idle timeout: the RFC 5508 REQ-2 floor.
pub const NAT44_ICMP_DEFAULT_IDLE_TTL_MS: u64 = NAT44_ICMP_MIN_IDLE_TTL_MS;
/// Largest configurable ICMP query idle timeout (one day, as for UDP).
pub const NAT44_ICMP_MAX_IDLE_TTL_MS: u64 = NAT44_UDP_MAX_IDLE_TTL_MS;

/// ICMP query translation policy (RFC 5508 §3).
///
/// Filtering is [`Nat44Filtering::EndpointIndependent`] or the default
/// [`Nat44Filtering::AddressDependent`]: a query has no remote port, so
/// address-and-port-dependent filtering does not exist for it and is
/// refused. Identifier preservation is the port preservation of N2 applied
/// to the identifier. `icmpv4_errors` governs the ICMP errors that quote an
/// ICMP query (RFC 5508 REQ-4 and REQ-5); errors that quote UDP or TCP stay
/// governed by those protocols.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44IcmpPolicy {
    idle_ttl_ms: u64,
    allocator_seed: u64,
    icmpv4_errors: Nat44Icmpv4ErrorPolicy,
    filtering: Nat44Filtering,
    identifier_preservation: bool,
    mappings_per_host: u16,
}

impl std::fmt::Debug for Nat44IcmpPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44IcmpPolicy")
            .field("idle_ttl_ms", &self.idle_ttl_ms)
            .field("allocator_seed", &Redacted)
            .field("icmpv4_errors", &self.icmpv4_errors)
            .field("filtering", &self.filtering)
            .field("identifier_preservation", &self.identifier_preservation)
            .field("mappings_per_host", &self.mappings_per_host)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44IcmpPolicyError {
    /// Below the RFC 5508 REQ-2 floor of 60 seconds.
    IdleTtlTooShort,
    IdleTtlTooLong,
    /// Address-and-port-dependent filtering needs a remote port, which an
    /// ICMP query does not have.
    FilteringNeedsPorts,
}

impl Nat44IcmpPolicy {
    pub const fn new(idle_ttl_ms: u64, allocator_seed: u64) -> Result<Self, Nat44IcmpPolicyError> {
        if idle_ttl_ms < NAT44_ICMP_MIN_IDLE_TTL_MS {
            return Err(Nat44IcmpPolicyError::IdleTtlTooShort);
        }
        if idle_ttl_ms > NAT44_ICMP_MAX_IDLE_TTL_MS {
            return Err(Nat44IcmpPolicyError::IdleTtlTooLong);
        }
        Ok(Self {
            idle_ttl_ms,
            allocator_seed,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Bidirectional,
            filtering: Nat44Filtering::AddressDependent,
            identifier_preservation: true,
            mappings_per_host: NAT44_DEFAULT_MAPPINGS_PER_HOST,
        })
    }

    #[must_use]
    pub const fn idle_ttl_ms(self) -> u64 {
        self.idle_ttl_ms
    }

    #[must_use]
    pub const fn allocator_seed(self) -> u64 {
        self.allocator_seed
    }

    /// Selects reply filtering. `AddressAndPortDependent` is refused: a
    /// query has no remote port.
    pub const fn with_filtering(
        mut self,
        filtering: Nat44Filtering,
    ) -> Result<Self, Nat44IcmpPolicyError> {
        if matches!(filtering, Nat44Filtering::AddressAndPortDependent) {
            return Err(Nat44IcmpPolicyError::FilteringNeedsPorts);
        }
        self.filtering = filtering;
        Ok(self)
    }

    #[must_use]
    pub const fn filtering(self) -> Nat44Filtering {
        self.filtering
    }

    /// Which ICMP errors quoting an ICMP query are translated (RFC 5508
    /// REQ-4, REQ-5). The default is [`Nat44Icmpv4ErrorPolicy::Bidirectional`].
    #[must_use]
    pub const fn with_icmpv4_errors(mut self, policy: Nat44Icmpv4ErrorPolicy) -> Self {
        self.icmpv4_errors = policy;
        self
    }

    #[must_use]
    pub const fn icmpv4_errors(self) -> Nat44Icmpv4ErrorPolicy {
        self.icmpv4_errors
    }

    /// Enables or disables identifier preservation: a new mapping keeps the
    /// internal identifier when it is in the pool and has no live owner.
    /// `false` always selects the keyed identifier, so the public
    /// identifier does not repeat the host's own (N2 applied to queries).
    #[must_use]
    pub const fn with_identifier_preservation(mut self, enabled: bool) -> Self {
        self.identifier_preservation = enabled;
        self
    }

    #[must_use]
    pub const fn identifier_preservation(self) -> bool {
        self.identifier_preservation
    }

    /// Limits the live query mappings of one internal IPv4 address (N3,
    /// RFC 6888 REQ-4 applied to identifiers). `0` is no limit; a nonzero
    /// limit needs per-host storage.
    #[must_use]
    pub const fn with_mappings_per_host(mut self, limit: u16) -> Self {
        self.mappings_per_host = limit;
        self
    }

    #[must_use]
    pub const fn mappings_per_host(self) -> u16 {
        self.mappings_per_host
    }

    /// The mapping-engine policy. Hairpinning is off: no inbound query
    /// session can exist, so the engine never sees a hairpin plan.
    const fn engine(self) -> Nat44UdpPolicy {
        Nat44UdpPolicy {
            idle_ttl_ms: self.idle_ttl_ms,
            allocator_seed: self.allocator_seed,
            icmpv4_errors: self.icmpv4_errors,
            filtering: self.filtering,
            hairpinning: false,
            port_preservation: self.identifier_preservation,
            mappings_per_host: self.mappings_per_host,
        }
    }

    const fn from_engine(policy: Nat44UdpPolicy) -> Self {
        Self {
            idle_ttl_ms: policy.idle_ttl_ms,
            allocator_seed: policy.allocator_seed,
            icmpv4_errors: policy.icmpv4_errors,
            filtering: policy.filtering,
            identifier_preservation: policy.port_preservation,
            mappings_per_host: policy.mappings_per_host,
        }
    }
}

impl Default for Nat44IcmpPolicy {
    fn default() -> Self {
        Self {
            idle_ttl_ms: NAT44_ICMP_DEFAULT_IDLE_TTL_MS,
            allocator_seed: 0,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Bidirectional,
            filtering: Nat44Filtering::AddressDependent,
            identifier_preservation: true,
            mappings_per_host: NAT44_DEFAULT_MAPPINGS_PER_HOST,
        }
    }
}

/// Control-plane supplied ICMP query NAT index key. It must be fresh for
/// every runtime construction and publication, and independent of the UDP
/// and TCP keys.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44IcmpHashKey(Nat44UdpHashKey);

impl std::fmt::Debug for Nat44IcmpHashKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Nat44IcmpHashKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44IcmpHashKeyError {
    AllZero,
}

impl Nat44IcmpHashKey {
    pub const fn new(first: u64, second: u64) -> Result<Self, Nat44IcmpHashKeyError> {
        match Nat44UdpHashKey::new(first, second) {
            Ok(key) => Ok(Self(key)),
            Err(_) => Err(Nat44IcmpHashKeyError::AllZero),
        }
    }
}

/// Validated ICMP query NAT realm, identifier pool, and policy.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44IcmpConfig(Nat44UdpConfig);

impl std::fmt::Debug for Nat44IcmpConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44IcmpConfig")
            .field("inside", &self.0.inside)
            .field("outside", &self.0.outside)
            .field("public_address", &self.0.public_address)
            .field("first_identifier", &self.0.first_port)
            .field("last_identifier", &self.0.last_port)
            .field("policy", &self.policy())
            .field("authority", &Redacted)
            .field("snapshot_identity", &Redacted)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44IcmpConfigError {
    InterfacesEqual,
    InsideInterfaceMissing,
    OutsideInterfaceMissing,
    PublicAddressNotHostUnicast,
    PublicBindingMissing,
    PublicBindingWrongInterface,
    /// The public identifier pool contains identifier 0.
    IdentifierPoolIncludesZero,
    IdentifierPoolReversed,
}

impl Nat44IcmpConfig {
    pub fn new(
        snapshot: &ForwardingSnapshot<'_>,
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        first_identifier: u16,
        last_identifier: u16,
        policy: Nat44IcmpPolicy,
    ) -> Result<Self, Nat44IcmpConfigError> {
        Nat44UdpConfig::new(
            snapshot,
            inside,
            outside,
            public_address,
            first_identifier,
            last_identifier,
            policy.engine(),
        )
        .map(Self)
        .map_err(|error| match error {
            Nat44UdpConfigError::InterfacesEqual => Nat44IcmpConfigError::InterfacesEqual,
            Nat44UdpConfigError::InsideInterfaceMissing => {
                Nat44IcmpConfigError::InsideInterfaceMissing
            }
            Nat44UdpConfigError::OutsideInterfaceMissing => {
                Nat44IcmpConfigError::OutsideInterfaceMissing
            }
            Nat44UdpConfigError::PublicAddressNotHostUnicast => {
                Nat44IcmpConfigError::PublicAddressNotHostUnicast
            }
            Nat44UdpConfigError::PublicBindingMissing => Nat44IcmpConfigError::PublicBindingMissing,
            Nat44UdpConfigError::PublicBindingWrongInterface => {
                Nat44IcmpConfigError::PublicBindingWrongInterface
            }
            Nat44UdpConfigError::PortPoolIncludesZero => {
                Nat44IcmpConfigError::IdentifierPoolIncludesZero
            }
            Nat44UdpConfigError::PortPoolReversed => Nat44IcmpConfigError::IdentifierPoolReversed,
        })
    }

    #[must_use]
    pub const fn inside(self) -> IfId {
        self.0.inside
    }

    #[must_use]
    pub const fn outside(self) -> IfId {
        self.0.outside
    }

    #[must_use]
    pub const fn public_address(self) -> Ipv4Address {
        self.0.public_address
    }

    #[must_use]
    pub const fn first_identifier(self) -> u16 {
        self.0.first_port
    }

    #[must_use]
    pub const fn last_identifier(self) -> u16 {
        self.0.last_port
    }

    #[must_use]
    pub const fn policy(self) -> Nat44IcmpPolicy {
        Nat44IcmpPolicy::from_engine(self.0.policy)
    }

    pub(crate) fn authority_matches(self, snapshot: &ForwardingSnapshot<'_>) -> bool {
        self.0.authority_matches(snapshot)
    }

    pub(crate) fn realm_matches(self, inside: IfId, outside: IfId, public: Ipv4Address) -> bool {
        self.0.inside == inside && self.0.outside == outside && self.0.public_address == public
    }
}

/// Mapping slot of the ICMP query runtime (the datagram mapping layout,
/// with the identifier in the port fields).
pub type Nat44IcmpMappingSlot = Nat44UdpMappingSlot;
/// Filter-peer slot of the ICMP query runtime (remote addresses queried).
pub type Nat44IcmpPeerSlot = Nat44UdpPeerSlot;
/// Caller-owned index storage of the ICMP query runtime; the port-owner
/// index is the public identifier owner index.
pub type Nat44IcmpIndexStorage<'a> = Nat44UdpIndexStorage<'a>;
pub type Nat44IcmpRuntimeConfigError = Nat44UdpRuntimeConfigError;
pub type Nat44IcmpReconcileError = Nat44UdpReconcileError;
pub type Nat44IcmpReconcileReport = Nat44UdpReconcileReport;
pub type Nat44IcmpStorageShape = Nat44UdpStorageShape;
pub type Nat44IcmpOccupancy = Nat44UdpOccupancy;

/// Cumulative ICMP query NAT counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44IcmpCounters {
    pub mappings_created: u64,
    pub mappings_reused: u64,
    pub mappings_expired: u64,
    pub peers_created: u64,
    pub outbound_translated: u64,
    pub inbound_translated: u64,
    pub mapping_misses: u64,
    pub filter_denied: u64,
    pub mapping_full: u64,
    pub peer_full: u64,
    pub identifier_exhausted: u64,
    pub clock_regressions: u64,
    pub config_mismatches: u64,
    pub reconciliations: u64,
    pub host_quota_exceeded: u64,
}

impl Nat44IcmpCounters {
    const fn from_engine(counters: Nat44UdpCounters) -> Self {
        Self {
            mappings_created: counters.mappings_created,
            mappings_reused: counters.mappings_reused,
            mappings_expired: counters.mappings_expired,
            peers_created: counters.peers_created,
            outbound_translated: counters.outbound_translated,
            inbound_translated: counters.inbound_translated,
            mapping_misses: counters.mapping_misses,
            filter_denied: counters.filter_denied,
            mapping_full: counters.mapping_full,
            peer_full: counters.peer_full,
            identifier_exhausted: counters.port_exhausted,
            clock_regressions: counters.clock_regressions,
            config_mismatches: counters.config_mismatches,
            reconciliations: counters.reconciliations,
            host_quota_exceeded: counters.host_quota_exceeded,
        }
    }
}

/// Outcome of one ICMP query NAT decision (trace).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44IcmpDisposition {
    OutboundTranslated {
        public_identifier: u16,
        mapping_created: bool,
        peer_created: bool,
    },
    InboundTranslated {
        internal_address: Ipv4Address,
        internal_identifier: u16,
    },
    MappingMiss,
    FilterDenied,
    MappingFull,
    PeerFull,
    IdentifierExhausted,
    HostQuotaExceeded,
    ClockRegression,
    ConfigMismatch,
    Rejected {
        reason: crate::DropReason,
    },
}

impl Nat44IcmpDisposition {
    pub(crate) const fn from_engine(disposition: Nat44UdpDisposition) -> Self {
        match disposition {
            Nat44UdpDisposition::OutboundTranslated {
                public_port,
                mapping_created,
                peer_created,
            }
            | Nat44UdpDisposition::HairpinOutboundCommitted {
                public_port,
                mapping_created,
                peer_created,
            } => Self::OutboundTranslated {
                public_identifier: public_port,
                mapping_created,
                peer_created,
            },
            Nat44UdpDisposition::InboundTranslated {
                internal_address,
                internal_port,
            }
            | Nat44UdpDisposition::HairpinTranslated {
                internal_address,
                internal_port,
                ..
            } => Self::InboundTranslated {
                internal_address,
                internal_identifier: internal_port,
            },
            Nat44UdpDisposition::MappingMiss => Self::MappingMiss,
            Nat44UdpDisposition::FilterDenied => Self::FilterDenied,
            Nat44UdpDisposition::MappingFull => Self::MappingFull,
            Nat44UdpDisposition::PeerFull => Self::PeerFull,
            Nat44UdpDisposition::PortExhausted => Self::IdentifierExhausted,
            Nat44UdpDisposition::HostQuotaExceeded => Self::HostQuotaExceeded,
            Nat44UdpDisposition::ClockRegression => Self::ClockRegression,
            Nat44UdpDisposition::ConfigMismatch => Self::ConfigMismatch,
            Nat44UdpDisposition::Rejected { reason } => Self::Rejected { reason },
        }
    }
}

/// Lifetime-bound proof that an ICMP query NAT reconcile can commit.
///
/// ```compile_fail
/// use ruster_core::Nat44IcmpReconcilePermit;
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<Nat44IcmpReconcilePermit<'static, 'static>>();
/// ```
#[must_use = "dropping an ICMP query NAT reconcile permit leaves the runtime unchanged"]
pub struct Nat44IcmpReconcilePermit<'runtime, 'storage>(
    Nat44UdpReconcilePermit<'runtime, 'storage>,
);

impl Nat44IcmpReconcilePermit<'_, '_> {
    /// Consumes this one-shot permit and applies its prevalidated reconcile:
    /// every mapping and peer is flushed and the key rotates.
    pub fn commit(self) -> Nat44IcmpReconcileReport {
        self.0.commit()
    }
}

/// Worker-local ICMP query NAT state (RFC 5508 §3) on caller-backed storage.
///
/// `!Send + !Sync` like every NAT runtime. See the module documentation for
/// how it relates to [`Nat44UdpRuntime`].
pub struct Nat44IcmpRuntime<'a> {
    engine: Nat44UdpRuntime<'a>,
}

impl<'a> Nat44IcmpRuntime<'a> {
    /// `indexes` is sized like a UDP runtime's with the identifier pool as
    /// the port pool; `hosts` storage is required for a nonzero per-host
    /// limit.
    pub fn new(
        config: Nat44IcmpConfig,
        mappings: &'a mut [Nat44IcmpMappingSlot],
        peers: &'a mut [Nat44IcmpPeerSlot],
        indexes: Nat44IcmpIndexStorage<'a>,
        hash_key: Nat44IcmpHashKey,
    ) -> Result<Self, Nat44IcmpRuntimeConfigError> {
        Nat44UdpRuntime::new(config.0, mappings, peers, indexes, hash_key.0)
            .map(|engine| Self { engine })
    }

    #[must_use]
    pub const fn config(&self) -> Nat44IcmpConfig {
        Nat44IcmpConfig(self.engine.config())
    }

    /// Checks the exact control-plane binding without exposing the key.
    #[must_use]
    pub fn publication_binding_matches(
        &self,
        config: Nat44IcmpConfig,
        hash_key: Nat44IcmpHashKey,
    ) -> bool {
        self.engine
            .publication_binding_matches(config.0, hash_key.0)
    }

    #[must_use]
    pub const fn counters(&self) -> Nat44IcmpCounters {
        Nat44IcmpCounters::from_engine(self.engine.counters())
    }

    #[must_use]
    pub fn mappings(&self) -> &[Nat44IcmpMappingSlot] {
        self.engine.mappings()
    }

    #[must_use]
    pub fn peers(&self) -> &[Nat44IcmpPeerSlot] {
        self.engine.peers()
    }

    /// Allocated mapping and peer slots and their high-water marks, O(1);
    /// see [`Nat44UdpRuntime::occupancy`].
    #[must_use]
    pub fn occupancy(&self) -> Nat44IcmpOccupancy {
        self.engine.occupancy()
    }

    #[must_use]
    pub fn storage_shape(&self) -> Nat44IcmpStorageShape {
        self.engine.storage_shape()
    }

    pub fn reconcile(
        &mut self,
        config: Nat44IcmpConfig,
        hash_key: Nat44IcmpHashKey,
    ) -> Result<Nat44IcmpReconcileReport, Nat44IcmpReconcileError> {
        self.preflight_reconcile(config, hash_key)
            .map(Nat44IcmpReconcilePermit::commit)
    }

    pub fn preflight_reconcile<'runtime>(
        &'runtime mut self,
        config: Nat44IcmpConfig,
        hash_key: Nat44IcmpHashKey,
    ) -> Result<Nat44IcmpReconcilePermit<'runtime, 'a>, Nat44IcmpReconcileError> {
        self.engine
            .preflight_reconcile(config.0, hash_key.0)
            .map(Nat44IcmpReconcilePermit)
    }

    pub(crate) fn record_config_mismatch(&mut self) {
        self.engine.record_config_mismatch();
    }

    pub(crate) fn observe_now(&mut self, now_ms: u64) -> Result<(), Nat44UdpPlanError> {
        self.engine.observe_now(now_ms)
    }

    /// Plans the outbound query `internal:identifier -> remote`: the
    /// endpoint-independent mapping (REQ-1 a) and, for filtering and error
    /// authority, the address-granular peer `remote`.
    pub(crate) fn plan_outbound(
        &mut self,
        internal_address: Ipv4Address,
        identifier: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        self.engine
            .plan_outbound(internal_address, identifier, remote_address, 0, now_ms)
    }

    pub(crate) fn plan_outbound_read_only(
        &self,
        internal_address: Ipv4Address,
        identifier: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        self.engine
            .plan_outbound_read_only(internal_address, identifier, remote_address, 0, now_ms)
    }

    /// Plans the inbound reply `remote -> public:identifier`: a live mapping
    /// and, unless endpoint-independent, a queried peer `remote`.
    pub(crate) fn plan_inbound(
        &mut self,
        public_identifier: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        self.engine
            .plan_inbound(public_identifier, remote_address, 0, now_ms)
    }

    pub(crate) fn plan_inbound_read_only(
        &self,
        public_identifier: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        self.engine
            .plan_inbound_read_only(public_identifier, remote_address, 0, now_ms)
    }

    pub(crate) fn prevalidate_outbound_commit(
        &self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.engine.prevalidate_outbound_commit(plan, now_ms)
    }

    pub(crate) fn prevalidate_inbound_commit(
        &self,
        plan: Nat44UdpInboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.engine.prevalidate_inbound_commit(plan, now_ms)
    }

    pub(crate) fn commit_outbound(
        &mut self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.engine.commit_outbound(plan, now_ms)
    }

    pub(crate) fn commit_inbound(
        &mut self,
        plan: Nat44UdpInboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.engine.commit_inbound(plan, now_ms)
    }

    pub(crate) fn record_plan_error(&mut self, error: Nat44UdpPlanError) {
        self.engine.record_plan_error(error);
    }

    pub(crate) fn record_read_only_plan_error(&mut self, error: Nat44UdpPlanError) {
        self.engine.record_read_only_plan_error(error);
    }

    /// Read-only authority for a quoted outbound query `public:identifier
    /// -> remote` in an external error (RFC 5508 REQ-4): a live mapping
    /// whose peers include `remote`, whatever the filtering mode.
    pub(crate) fn inspect_error_quote(
        &self,
        public_identifier: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpIcmpv4Lookup, Nat44UdpPlanError> {
        self.engine
            .inspect_icmpv4(public_identifier, remote_address, 0, now_ms)
    }

    /// Read-only authority for a quoted inbound reply `remote ->
    /// internal:identifier` in an inside error (RFC 5508 REQ-5). Returns
    /// the public identifier.
    pub(crate) fn inspect_inbound_quote(
        &self,
        internal_address: Ipv4Address,
        identifier: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<u16, Nat44UdpPlanError> {
        self.engine.inspect_icmpv4_inbound_quote(
            internal_address,
            identifier,
            remote_address,
            0,
            now_ms,
        )
    }

    #[cfg(test)]
    pub(crate) fn engine(&self) -> &Nat44UdpRuntime<'a> {
        &self.engine
    }
}

#[cfg(test)]
mod tests;

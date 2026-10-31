//! Cold-path bridge from semantically validated configuration to an owned
//! publication candidate.
//!
//! The bridge adds exactly two inputs that configuration deliberately does not
//! own: an explicit publication generation and fresh per-publication hash keys
//! from a [`PublicationKeySource`]. Everything else (topology, policies, and
//! storage shape) is copied from [`ValidatedConfigV1`] and then re-checked by
//! [`ValidatedCandidate::new`].
//!
//! M1 requires every runtime service. A configuration that omits resolution,
//! ICMPv4 errors, UDP NAT, TCP NAT, or the firewall is rejected with a typed,
//! value-free [`ConfigBridgeError::MissingService`] before any key is drawn.

use std::{fmt, num::NonZeroU64};

use ruster_config::ValidatedConfigV1;
use ruster_core::{FirewallHashKey, Nat44TcpHashKey, Nat44UdpHashKey};

use crate::publication::{
    FirewallPublicationInput, FullServiceStorageShape, Icmpv4ErrorStorageShape,
    Nat44TcpPublicationInput, Nat44TcpStoragePlan, Nat44UdpPublicationInput, Nat44UdpStoragePlan,
    PublicationCandidateError, PublicationPlan, ResolutionStorageShape, RuntimeService,
    ValidatedCandidate,
};

/// How a [`PublicationKeySource`] obtains its keys.
///
/// The kind is self-declared by the implementation. A future production entry
/// point must reject [`KeySourceKind::DeterministicSimulation`], for example
/// with a const assertion on `S::KIND` or a sealed production marker trait.
/// This is not enforced yet; no production entry point exists in M1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeySourceKind {
    /// Keys are a reproducible, publicly derivable function of a seed. Only
    /// valid for simulation and tests; never for live traffic.
    DeterministicSimulation,
}

/// Value-free key-source failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeySourceError {
    /// The source produced an all-zero key, which core rejects.
    ///
    /// Defensive only for [`SimDeterministicKeySource`]: the two words of one
    /// key come from distinct tags through an injective map, so they never
    /// coincide and in particular are never both zero.
    AllZeroKey(RuntimeService),
}

/// The three hash keys bound to one publication generation.
///
/// Formatting is redacted and the type is not `Clone`, so a key set is
/// consumed by exactly one candidate build.
#[derive(Eq, PartialEq)]
pub struct PublicationKeys {
    nat44_udp: Nat44UdpHashKey,
    nat44_tcp: Nat44TcpHashKey,
    firewall: FirewallHashKey,
}

impl PublicationKeys {
    #[must_use]
    pub const fn new(
        nat44_udp: Nat44UdpHashKey,
        nat44_tcp: Nat44TcpHashKey,
        firewall: FirewallHashKey,
    ) -> Self {
        Self {
            nat44_udp,
            nat44_tcp,
            firewall,
        }
    }

    #[must_use]
    pub const fn nat44_udp(&self) -> Nat44UdpHashKey {
        self.nat44_udp
    }

    #[must_use]
    pub const fn nat44_tcp(&self) -> Nat44TcpHashKey {
        self.nat44_tcp
    }

    #[must_use]
    pub const fn firewall(&self) -> FirewallHashKey {
        self.firewall
    }
}

impl fmt::Debug for PublicationKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationKeys([REDACTED])")
    }
}

/// Supplies fresh hash keys for one publication generation.
///
/// This is a cold-path, statically dispatched abstraction. Implementations
/// must return keys distinct from every earlier generation they served so
/// that successor validation accepts the resulting candidate.
///
/// [`candidate_from_config`] draws the key set after the missing-service
/// checks but before [`ValidatedCandidate::new`]. A build that is then
/// rejected still consumes one key set, which a source enforcing unique,
/// never-reissued keys must account for.
pub trait PublicationKeySource {
    /// Provenance of the keys, checked by entry points that require a
    /// particular kind.
    const KIND: KeySourceKind;

    /// Returns the key set for `generation`.
    fn publication_keys(
        &mut self,
        generation: NonZeroU64,
    ) -> Result<PublicationKeys, KeySourceError>;
}

/// **Simulation/test only.** Deterministic, publicly derivable key source.
///
/// Keys are a pure function of `(seed, generation)` so `run-sim` output is
/// byte-reproducible. They are *not* unpredictable and must never protect live
/// traffic. Its [`PublicationKeySource::KIND`] is
/// [`KeySourceKind::DeterministicSimulation`]; a future production entry point
/// must reject that kind, which is not enforced yet (M2).
///
/// # Derivation
///
/// With `mix` the SplitMix64 output finalizer (a bijection on `u64`),
/// `GAMMA = 0x9e37_79b9_7f4a_7c15`, and a fixed per-word domain tag `tag`
/// (UDP first/second, TCP first/second, firewall first/second; six distinct
/// constants), each key word is
///
/// ```text
/// word = mix(seed ^ mix(generation.wrapping_mul(GAMMA) ^ tag))
/// ```
///
/// For a fixed seed and tag every step is a bijection of `generation`, so two
/// different generations always produce different first words and therefore
/// different keys for every service. Identical `(seed, generation)` yields
/// identical keys. For one key the two words are `mix(seed ^ mix(g ^ t1))`
/// and `mix(seed ^ mix(g ^ t2))` with `t1 != t2`; by injectivity they differ,
/// so an all-zero pair is unreachable. The [`KeySourceError::AllZeroKey`]
/// mapping through the core constructors is purely defensive.
///
/// The seed is never formatted.
pub struct SimDeterministicKeySource {
    seed: u64,
}

impl SimDeterministicKeySource {
    /// Creates a simulation-only source from a scenario seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { seed }
    }

    const fn word(&self, generation: NonZeroU64, tag: u64) -> u64 {
        mix(self.seed ^ mix(generation.get().wrapping_mul(GAMMA) ^ tag))
    }
}

impl fmt::Debug for SimDeterministicKeySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SimDeterministicKeySource([REDACTED])")
    }
}

const GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const TAG_UDP_FIRST: u64 = 0x7275_7374_7564_7031;
const TAG_UDP_SECOND: u64 = 0x7275_7374_7564_7032;
const TAG_TCP_FIRST: u64 = 0x7275_7374_7463_7031;
const TAG_TCP_SECOND: u64 = 0x7275_7374_7463_7032;
const TAG_FIREWALL_FIRST: u64 = 0x7275_7374_6677_6b31;
const TAG_FIREWALL_SECOND: u64 = 0x7275_7374_6677_6b32;

const fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

impl PublicationKeySource for SimDeterministicKeySource {
    const KIND: KeySourceKind = KeySourceKind::DeterministicSimulation;

    fn publication_keys(
        &mut self,
        generation: NonZeroU64,
    ) -> Result<PublicationKeys, KeySourceError> {
        let udp = Nat44UdpHashKey::new(
            self.word(generation, TAG_UDP_FIRST),
            self.word(generation, TAG_UDP_SECOND),
        )
        .map_err(|_| KeySourceError::AllZeroKey(RuntimeService::Nat44Udp))?;
        let tcp = Nat44TcpHashKey::new(
            self.word(generation, TAG_TCP_FIRST),
            self.word(generation, TAG_TCP_SECOND),
        )
        .map_err(|_| KeySourceError::AllZeroKey(RuntimeService::Nat44Tcp))?;
        let firewall = FirewallHashKey::new(
            self.word(generation, TAG_FIREWALL_FIRST),
            self.word(generation, TAG_FIREWALL_SECOND),
        )
        .map_err(|_| KeySourceError::AllZeroKey(RuntimeService::Firewall))?;
        Ok(PublicationKeys::new(udp, tcp, firewall))
    }
}

/// Value-free rejection while bridging configuration to a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigBridgeError {
    /// The configuration omits a service that M1 requires.
    MissingService(RuntimeService),
    /// The key source could not supply a key set.
    KeySource(KeySourceError),
    /// Candidate validation rejected the mapped plan.
    Candidate(PublicationCandidateError),
}

/// Builds a full-service candidate for `generation` from validated config.
///
/// Missing services are rejected before the key source is consulted. The
/// configuration is only borrowed, so the same document can be re-published
/// later as a new generation (for example as an M1 rollback).
pub fn candidate_from_config<S: PublicationKeySource>(
    config: &ValidatedConfigV1,
    generation: NonZeroU64,
    keys: &mut S,
) -> Result<ValidatedCandidate, ConfigBridgeError> {
    let missing = ConfigBridgeError::MissingService;
    let storage = config.storage_shape();
    let resolution = config
        .resolution()
        .zip(storage.resolution)
        .ok_or(missing(RuntimeService::Resolution))?;
    let icmpv4_errors = config
        .icmpv4_errors()
        .zip(storage.icmpv4_errors)
        .ok_or(missing(RuntimeService::Icmpv4Errors))?;
    let nat44 = config.nat44();
    let udp = nat44
        .and_then(|nat44| nat44.udp())
        .zip(storage.nat44_udp)
        .ok_or(missing(RuntimeService::Nat44Udp))?;
    let tcp = nat44
        .and_then(|nat44| nat44.tcp())
        .zip(storage.nat44_tcp)
        .ok_or(missing(RuntimeService::Nat44Tcp))?;
    let (firewall, firewall_states) = config
        .firewall()
        .zip(storage.firewall_states)
        .ok_or(missing(RuntimeService::Firewall))?;

    let (resolution, resolution_shape) = resolution;
    let (icmpv4_errors, icmpv4_shape) = icmpv4_errors;
    let (udp, udp_shape) = udp;
    let (tcp, tcp_shape) = tcp;
    let shape = FullServiceStorageShape::new(
        ResolutionStorageShape::new(
            resolution_shape.states,
            resolution_shape.actions,
            resolution_shape.dynamic_neighbors,
            resolution_shape.failure_holds,
        ),
        Icmpv4ErrorStorageShape::new(icmpv4_shape.states, icmpv4_shape.actions),
        Nat44UdpStoragePlan::new(
            udp_shape.mappings,
            udp_shape.peers,
            udp_shape.mapping_buckets,
            udp_shape.mapping_nodes,
            udp_shape.peer_buckets,
            udp_shape.peer_nodes,
            udp_shape.port_owners,
        ),
        Nat44TcpStoragePlan::new(
            tcp_shape.mappings,
            tcp_shape.sessions,
            tcp_shape.mapping_buckets,
            tcp_shape.mapping_nodes,
            tcp_shape.session_buckets,
            tcp_shape.session_nodes,
            tcp_shape.port_owners,
        ),
        firewall_states,
    );

    let key_set = keys
        .publication_keys(generation)
        .map_err(ConfigBridgeError::KeySource)?;

    let plan = PublicationPlan::new(
        generation,
        shape,
        config.routes().into(),
        config.core_interfaces().into(),
        config.neighbors().into(),
        config.local_ipv4().into(),
        config.ipv4_origin(),
        resolution.policy(),
        icmpv4_errors.policy(),
    )
    .with_nat44_udp(Nat44UdpPublicationInput::new(
        udp.inside(),
        udp.outside(),
        udp.public_address(),
        udp.first_port(),
        udp.last_port(),
        udp.policy(),
        key_set.nat44_udp,
    ))
    .with_nat44_tcp(Nat44TcpPublicationInput::new(
        tcp.inside(),
        tcp.outside(),
        tcp.public_address(),
        tcp.first_port(),
        tcp.last_port(),
        tcp.policy(),
        key_set.nat44_tcp,
    ))
    .with_firewall(FirewallPublicationInput::new(
        firewall.rules().into(),
        firewall.policy(),
        key_set.firewall,
    ));
    ValidatedCandidate::new(plan).map_err(ConfigBridgeError::Candidate)
}

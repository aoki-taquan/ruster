use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{ForwardingSnapshot, IfId, Ipv4Address};

pub const FIREWALL_UDP_MIN_IDLE_TTL_MS: u64 = 120_000;
pub const FIREWALL_UDP_DEFAULT_IDLE_TTL_MS: u64 = 300_000;
pub const FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS: u64 = 240_000;
pub const FIREWALL_TCP_OPENING_DEFAULT_IDLE_TTL_MS: u64 = 240_000;
pub const FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS: u64 = 7_440_000;
pub const FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS: u64 = 7_440_000;
pub const FIREWALL_MAX_IDLE_TTL_MS: u64 = 604_800_000;

static NEXT_FIREWALL_RUNTIME_IDENTITY: AtomicU64 = AtomicU64::new(1);

fn allocate_firewall_runtime_identity() -> u64 {
    NEXT_FIREWALL_RUNTIME_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .expect("firewall runtime identity exhausted")
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FirewallRuleId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallInterface {
    Any,
    Interface(IfId),
}

impl FirewallInterface {
    fn matches(self, interface: IfId) -> bool {
        match self {
            Self::Any => true,
            Self::Interface(expected) => expected == interface,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallIpv4Prefix {
    address: Ipv4Address,
    prefix_len: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallIpv4PrefixError {
    InvalidPrefixLength,
    HostBitsSet,
}

impl FirewallIpv4Prefix {
    pub fn new(address: Ipv4Address, prefix_len: u8) -> Result<Self, FirewallIpv4PrefixError> {
        let Some(mask) = prefix_mask(prefix_len) else {
            return Err(FirewallIpv4PrefixError::InvalidPrefixLength);
        };
        let value = u32::from_be_bytes(address.octets());
        if value & !mask != 0 {
            return Err(FirewallIpv4PrefixError::HostBitsSet);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    #[must_use]
    pub const fn address(self) -> Ipv4Address {
        self.address
    }

    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    fn matches(self, address: Ipv4Address) -> bool {
        let mask = prefix_mask(self.prefix_len).expect("prefix constructor validates length");
        u32::from_be_bytes(address.octets()) & mask == u32::from_be_bytes(self.address.octets())
    }
}

fn prefix_mask(prefix_len: u8) -> Option<u32> {
    match prefix_len {
        0 => Some(0),
        1..=32 => Some(u32::MAX << (32 - u32::from(prefix_len))),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallPortRange {
    first: u16,
    last: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallPortRangeError {
    Reversed,
}

impl FirewallPortRange {
    pub const fn new(first: u16, last: u16) -> Result<Self, FirewallPortRangeError> {
        if first > last {
            return Err(FirewallPortRangeError::Reversed);
        }
        Ok(Self { first, last })
    }

    #[must_use]
    pub const fn first(self) -> u16 {
        self.first
    }

    #[must_use]
    pub const fn last(self) -> u16 {
        self.last
    }

    const fn contains(self, port: u16) -> bool {
        self.first <= port && port <= self.last
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallProtocol {
    Tcp,
    Udp,
}

impl FirewallProtocol {
    pub(crate) const fn from_ipv4(protocol: u8) -> Option<Self> {
        match protocol {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallAction {
    AllowStateful,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallRule {
    id: FirewallRuleId,
    ingress: FirewallInterface,
    egress: FirewallInterface,
    source: FirewallIpv4Prefix,
    destination: FirewallIpv4Prefix,
    protocol: FirewallProtocol,
    source_ports: FirewallPortRange,
    destination_ports: FirewallPortRange,
    action: FirewallAction,
}

impl FirewallRule {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: FirewallRuleId,
        ingress: FirewallInterface,
        egress: FirewallInterface,
        source: FirewallIpv4Prefix,
        destination: FirewallIpv4Prefix,
        protocol: FirewallProtocol,
        source_ports: FirewallPortRange,
        destination_ports: FirewallPortRange,
        action: FirewallAction,
    ) -> Self {
        Self {
            id,
            ingress,
            egress,
            source,
            destination,
            protocol,
            source_ports,
            destination_ports,
            action,
        }
    }

    #[must_use]
    pub const fn id(self) -> FirewallRuleId {
        self.id
    }

    #[must_use]
    pub const fn ingress(self) -> FirewallInterface {
        self.ingress
    }

    #[must_use]
    pub const fn egress(self) -> FirewallInterface {
        self.egress
    }

    #[must_use]
    pub const fn source(self) -> FirewallIpv4Prefix {
        self.source
    }

    #[must_use]
    pub const fn destination(self) -> FirewallIpv4Prefix {
        self.destination
    }

    #[must_use]
    pub const fn protocol(self) -> FirewallProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn source_ports(self) -> FirewallPortRange {
        self.source_ports
    }

    #[must_use]
    pub const fn destination_ports(self) -> FirewallPortRange {
        self.destination_ports
    }

    #[must_use]
    pub const fn action(self) -> FirewallAction {
        self.action
    }

    fn matches(self, packet: FirewallPacket) -> bool {
        self.ingress.matches(packet.ingress)
            && self.egress.matches(packet.egress)
            && self.source.matches(packet.source)
            && self.destination.matches(packet.destination)
            && self.protocol == packet.protocol
            && self.source_ports.contains(packet.source_port)
            && self.destination_ports.contains(packet.destination_port)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallPolicy {
    udp_idle_ttl_ms: u64,
    tcp_opening_idle_ttl_ms: u64,
    tcp_active_idle_ttl_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallPolicyError {
    UdpIdleTtlTooShort,
    UdpIdleTtlTooLong,
    TcpOpeningIdleTtlTooShort,
    TcpOpeningIdleTtlTooLong,
    TcpActiveIdleTtlTooShort,
    TcpActiveIdleTtlTooLong,
}

impl FirewallPolicy {
    pub const fn new(
        udp_idle_ttl_ms: u64,
        tcp_opening_idle_ttl_ms: u64,
        tcp_active_idle_ttl_ms: u64,
    ) -> Result<Self, FirewallPolicyError> {
        if udp_idle_ttl_ms < FIREWALL_UDP_MIN_IDLE_TTL_MS {
            return Err(FirewallPolicyError::UdpIdleTtlTooShort);
        }
        if udp_idle_ttl_ms > FIREWALL_MAX_IDLE_TTL_MS {
            return Err(FirewallPolicyError::UdpIdleTtlTooLong);
        }
        if tcp_opening_idle_ttl_ms < FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS {
            return Err(FirewallPolicyError::TcpOpeningIdleTtlTooShort);
        }
        if tcp_opening_idle_ttl_ms > FIREWALL_MAX_IDLE_TTL_MS {
            return Err(FirewallPolicyError::TcpOpeningIdleTtlTooLong);
        }
        if tcp_active_idle_ttl_ms < FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS {
            return Err(FirewallPolicyError::TcpActiveIdleTtlTooShort);
        }
        if tcp_active_idle_ttl_ms > FIREWALL_MAX_IDLE_TTL_MS {
            return Err(FirewallPolicyError::TcpActiveIdleTtlTooLong);
        }
        Ok(Self {
            udp_idle_ttl_ms,
            tcp_opening_idle_ttl_ms,
            tcp_active_idle_ttl_ms,
        })
    }

    #[must_use]
    pub const fn udp_idle_ttl_ms(self) -> u64 {
        self.udp_idle_ttl_ms
    }

    #[must_use]
    pub const fn tcp_opening_idle_ttl_ms(self) -> u64 {
        self.tcp_opening_idle_ttl_ms
    }

    #[must_use]
    pub const fn tcp_active_idle_ttl_ms(self) -> u64 {
        self.tcp_active_idle_ttl_ms
    }
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self {
            udp_idle_ttl_ms: FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,
            tcp_opening_idle_ttl_ms: FIREWALL_TCP_OPENING_DEFAULT_IDLE_TTL_MS,
            tcp_active_idle_ttl_ms: FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FirewallHashKey {
    first: u64,
    second: u64,
}

impl std::fmt::Debug for FirewallHashKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FirewallHashKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallHashKeyError {
    AllZero,
}

impl FirewallHashKey {
    /// Constructs a control-plane supplied 128-bit flow-table hash key.
    ///
    /// The control plane must generate a fresh, unpredictable key for every
    /// configuration publication. The packet path never generates randomness.
    pub const fn new(first: u64, second: u64) -> Result<Self, FirewallHashKeyError> {
        if first == 0 && second == 0 {
            return Err(FirewallHashKeyError::AllZero);
        }
        Ok(Self { first, second })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FirewallConfig<'a> {
    rules: &'a [FirewallRule],
    policy: FirewallPolicy,
    generation: u64,
    hash_key: FirewallHashKey,
    snapshot_authority: u64,
    snapshot_identity: [usize; 8],
    rules_identity: usize,
    rules_len: usize,
    rules_fingerprint: u64,
}

const VALIDATED_FIREWALL_OWNER_AUTHORITY_BIT: u64 = 1 << 63;

impl std::fmt::Debug for FirewallConfig<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirewallConfig")
            .field("policy", &self.policy)
            .field("generation", &self.generation)
            .field("hash_key", &self.hash_key)
            .field("rules_len", &self.rules_len)
            .finish_non_exhaustive()
    }
}

/// Immutable validated firewall rules owned by the cold publication path.
///
/// Construction consumes caller-allocated rule storage and validates it once.
/// [`Self::config`] is an infallible O(1) borrow scoped to this owner.
///
/// ```compile_fail
/// use ruster_core::{FirewallConfig, ValidatedFirewallOwner};
///
/// fn escape(owner: &ValidatedFirewallOwner) -> FirewallConfig<'static> {
///     owner.config()
/// }
/// ```
pub struct ValidatedFirewallOwner {
    rules: Box<[FirewallRule]>,
    binding: FirewallConfigBinding,
}

impl std::fmt::Debug for ValidatedFirewallOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedFirewallOwner")
            .field("policy", &self.binding.policy)
            .field("generation", &self.binding.generation)
            .field("hash_key", &self.binding.hash_key)
            .field("rules_len", &self.rules.len())
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "validation-test-hooks"))]
std::thread_local! {
    static FULL_FIREWALL_VALIDATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Returns and resets the current thread's full firewall validation count.
#[cfg(feature = "validation-test-hooks")]
#[doc(hidden)]
pub fn take_full_firewall_validation_count() -> usize {
    FULL_FIREWALL_VALIDATIONS.with(|count| count.replace(0))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallConfigError {
    GenerationZero,
    RuleIdZero,
    DuplicateRuleId,
    IngressInterfaceMissing,
    EgressInterfaceMissing,
    PublicationOwnerRequired,
    PublicationNonceExhausted,
}

/// Validates firewall rule identity and interface references without creating
/// publication state.
///
/// This is the control-plane validation seam for an offline configuration.
/// It does not require a configuration generation or a per-publication
/// [`FirewallHashKey`]. Policy values are validated independently by
/// [`FirewallPolicy::new`].
///
/// Rules are checked in slice order. Within each rule, the stable error
/// precedence is zero ID, duplicate ID, missing ingress, then missing egress.
pub fn validate_firewall_rules(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &[FirewallRule],
) -> Result<(), FirewallConfigError> {
    for (index, rule) in rules.iter().enumerate() {
        if rule.id.0 == 0 {
            return Err(FirewallConfigError::RuleIdZero);
        }
        if rules[..index]
            .iter()
            .any(|candidate| candidate.id == rule.id)
        {
            return Err(FirewallConfigError::DuplicateRuleId);
        }
        if let FirewallInterface::Interface(interface) = rule.ingress {
            if !snapshot
                .interfaces
                .iter()
                .any(|candidate| candidate.id == interface)
            {
                return Err(FirewallConfigError::IngressInterfaceMissing);
            }
        }
        if let FirewallInterface::Interface(interface) = rule.egress {
            if !snapshot
                .interfaces
                .iter()
                .any(|candidate| candidate.id == interface)
            {
                return Err(FirewallConfigError::EgressInterfaceMissing);
            }
        }
    }
    Ok(())
}

impl<'a> FirewallConfig<'a> {
    pub fn new(
        snapshot: &ForwardingSnapshot<'_>,
        rules: &'a [FirewallRule],
        policy: FirewallPolicy,
        generation: u64,
        hash_key: FirewallHashKey,
    ) -> Result<Self, FirewallConfigError> {
        #[cfg(any(test, feature = "validation-test-hooks"))]
        FULL_FIREWALL_VALIDATIONS.with(|count| count.set(count.get().saturating_add(1)));
        if generation == 0 {
            return Err(FirewallConfigError::GenerationZero);
        }
        validate_firewall_rules(snapshot, rules)?;
        Ok(Self {
            rules,
            policy,
            generation,
            hash_key,
            snapshot_authority: snapshot.authority(),
            snapshot_identity: snapshot.identity(),
            rules_identity: rules.as_ptr() as usize,
            rules_len: rules.len(),
            rules_fingerprint: rules_fingerprint(rules) & !VALIDATED_FIREWALL_OWNER_AUTHORITY_BIT,
        })
    }

    #[must_use]
    pub const fn rules(self) -> &'a [FirewallRule] {
        self.rules
    }

    #[must_use]
    pub const fn policy(self) -> FirewallPolicy {
        self.policy
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn hash_key(self) -> FirewallHashKey {
        self.hash_key
    }

    /// Compares firewall behavior while excluding publication and storage
    /// identity metadata.
    ///
    /// Rule order is intentionally preserved because rules use first-match
    /// semantics. The exhaustive field inventory makes a future top-level field
    /// addition require an explicit decision here instead of silently changing
    /// the meaning of a semantic comparison. Hash key, generation, authority,
    /// allocation identity, cached length, and fingerprint are not behavior.
    #[must_use]
    pub fn semantic_eq<'b>(self, other: FirewallConfig<'b>) -> bool {
        let FirewallConfig {
            rules,
            policy,
            generation: _,
            hash_key: _,
            snapshot_authority: _,
            snapshot_identity: _,
            rules_identity: _,
            rules_len: _,
            rules_fingerprint: _,
        } = self;
        let FirewallConfig {
            rules: other_rules,
            policy: other_policy,
            generation: _,
            hash_key: _,
            snapshot_authority: _,
            snapshot_identity: _,
            rules_identity: _,
            rules_len: _,
            rules_fingerprint: _,
        } = other;

        policy == other_policy && rules == other_rules
    }

    pub(crate) fn authority_matches(self, snapshot: &ForwardingSnapshot<'_>) -> bool {
        let authority = if self.rules_fingerprint & VALIDATED_FIREWALL_OWNER_AUTHORITY_BIT == 0 {
            snapshot.authority()
        } else {
            snapshot.publication_nonce()
        };
        self.snapshot_authority == authority && self.snapshot_identity == snapshot.identity()
    }

    const fn binding(self) -> FirewallConfigBinding {
        FirewallConfigBinding {
            policy: self.policy,
            generation: self.generation,
            hash_key: self.hash_key,
            snapshot_authority: self.snapshot_authority,
            snapshot_identity: self.snapshot_identity,
            rules_identity: self.rules_identity,
            rules_len: self.rules_len,
            rules_fingerprint: self.rules_fingerprint,
        }
    }
}

impl ValidatedFirewallOwner {
    pub fn new(
        snapshot: &ForwardingSnapshot<'_>,
        rules: Box<[FirewallRule]>,
        policy: FirewallPolicy,
        generation: u64,
        hash_key: FirewallHashKey,
    ) -> Result<Self, FirewallConfigError> {
        if snapshot.publication_nonce() == 0 {
            return Err(FirewallConfigError::PublicationOwnerRequired);
        }
        let mut binding =
            FirewallConfig::new(snapshot, &rules, policy, generation, hash_key)?.binding();
        binding.snapshot_authority = snapshot.publication_nonce();
        binding.rules_fingerprint = next_firewall_publication_nonce()
            .ok_or(FirewallConfigError::PublicationNonceExhausted)?;
        Ok(Self { rules, binding })
    }

    /// Borrows the validated configuration without validation or hashing.
    #[must_use]
    pub fn config(&self) -> FirewallConfig<'_> {
        let binding = self.binding;
        FirewallConfig {
            rules: &self.rules,
            policy: binding.policy,
            generation: binding.generation,
            hash_key: binding.hash_key,
            snapshot_authority: binding.snapshot_authority,
            snapshot_identity: binding.snapshot_identity,
            rules_identity: self.rules.as_ptr() as usize,
            rules_len: self.rules.len(),
            rules_fingerprint: binding.rules_fingerprint,
        }
    }

    #[must_use]
    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }
}

/// Owned publication identity retained by [`FirewallRuntime`].
///
/// The rules pointer is compared as an opaque identity only and is never
/// dereferenced. Rule evaluation always borrows the current
/// [`FirewallConfig`] supplied by the caller.
#[derive(Clone, Copy, Eq, PartialEq)]
struct FirewallConfigBinding {
    policy: FirewallPolicy,
    generation: u64,
    hash_key: FirewallHashKey,
    snapshot_authority: u64,
    snapshot_identity: [usize; 8],
    rules_identity: usize,
    rules_len: usize,
    rules_fingerprint: u64,
}

impl FirewallConfigBinding {
    #[cfg(test)]
    const fn publication_nonce(self) -> u64 {
        if self.rules_fingerprint & VALIDATED_FIREWALL_OWNER_AUTHORITY_BIT == 0 {
            0
        } else {
            self.rules_fingerprint
        }
    }
}

impl std::fmt::Debug for FirewallConfigBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirewallConfigBinding")
            .field("policy", &self.policy)
            .field("generation", &self.generation)
            .field("hash_key", &self.hash_key)
            .field("rules_len", &self.rules_len)
            .finish_non_exhaustive()
    }
}

fn next_firewall_publication_nonce() -> Option<u64> {
    use std::sync::atomic::AtomicU64;

    static NEXT_FIREWALL_PUBLICATION_NONCE: AtomicU64 =
        AtomicU64::new(VALIDATED_FIREWALL_OWNER_AUTHORITY_BIT | 1);
    next_firewall_publication_nonce_from(&NEXT_FIREWALL_PUBLICATION_NONCE)
}

fn next_firewall_publication_nonce_from(counter: &std::sync::atomic::AtomicU64) -> Option<u64> {
    use std::sync::atomic::Ordering;

    counter
        .fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| match current {
                0 => None,
                u64::MAX => Some(0),
                _ => current.checked_add(1),
            },
        )
        .ok()
        .filter(|nonce| *nonce != 0)
}

fn rules_fingerprint(rules: &[FirewallRule]) -> u64 {
    fn mix(hash: u64, value: u64) -> u64 {
        (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
    }

    let mut hash = 0xcbf2_9ce4_8422_2325;
    for rule in rules {
        hash = mix(hash, u64::from(rule.id.0));
        hash = mix(
            hash,
            match rule.ingress {
                FirewallInterface::Any => u64::MAX,
                FirewallInterface::Interface(interface) => u64::from(interface.0),
            },
        );
        hash = mix(
            hash,
            match rule.egress {
                FirewallInterface::Any => u64::MAX,
                FirewallInterface::Interface(interface) => u64::from(interface.0),
            },
        );
        hash = mix(
            hash,
            u64::from(u32::from_be_bytes(rule.source.address.octets())),
        );
        hash = mix(hash, u64::from(rule.source.prefix_len));
        hash = mix(
            hash,
            u64::from(u32::from_be_bytes(rule.destination.address.octets())),
        );
        hash = mix(hash, u64::from(rule.destination.prefix_len));
        hash = mix(
            hash,
            match rule.protocol {
                FirewallProtocol::Tcp => 6,
                FirewallProtocol::Udp => 17,
            },
        );
        hash = mix(hash, u64::from(rule.source_ports.first));
        hash = mix(hash, u64::from(rule.source_ports.last));
        hash = mix(hash, u64::from(rule.destination_ports.first));
        hash = mix(hash, u64::from(rule.destination_ports.last));
        hash = mix(
            hash,
            match rule.action {
                FirewallAction::AllowStateful => 1,
                FirewallAction::Deny => 0,
            },
        );
    }
    mix(hash, rules.len() as u64)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallTcpPhase {
    Opening,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallStateSlot {
    occupied: bool,
    slot_generation: u64,
    config_generation: u64,
    protocol: FirewallProtocol,
    origin_ingress: IfId,
    origin_egress: IfId,
    initiator_address: Ipv4Address,
    responder_address: Ipv4Address,
    initiator_port: u16,
    responder_port: u16,
    last_activity_ms: u64,
    tcp_phase: FirewallTcpPhase,
    tcp_forward_ack: bool,
    tcp_reverse_ack: bool,
    origin_rule_id: FirewallRuleId,
}

impl Default for FirewallStateSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            slot_generation: 0,
            config_generation: 0,
            protocol: FirewallProtocol::Udp,
            origin_ingress: IfId(0),
            origin_egress: IfId(0),
            initiator_address: Ipv4Address::from_octets([0; 4]),
            responder_address: Ipv4Address::from_octets([0; 4]),
            initiator_port: 0,
            responder_port: 0,
            last_activity_ms: 0,
            tcp_phase: FirewallTcpPhase::Opening,
            tcp_forward_ack: false,
            tcp_reverse_ack: false,
            origin_rule_id: FirewallRuleId(0),
        }
    }
}

impl FirewallStateSlot {
    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn protocol(self) -> FirewallProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn tcp_phase(self) -> FirewallTcpPhase {
        self.tcp_phase
    }

    #[must_use]
    pub const fn last_activity_ms(self) -> u64 {
        self.last_activity_ms
    }

    #[must_use]
    pub const fn config_generation(self) -> u64 {
        self.config_generation
    }

    #[must_use]
    pub const fn origin_ingress(self) -> IfId {
        self.origin_ingress
    }

    #[must_use]
    pub const fn origin_egress(self) -> IfId {
        self.origin_egress
    }

    #[must_use]
    pub const fn initiator_address(self) -> Ipv4Address {
        self.initiator_address
    }

    #[must_use]
    pub const fn responder_address(self) -> Ipv4Address {
        self.responder_address
    }

    #[must_use]
    pub const fn initiator_port(self) -> u16 {
        self.initiator_port
    }

    #[must_use]
    pub const fn responder_port(self) -> u16 {
        self.responder_port
    }

    #[must_use]
    pub const fn origin_rule_id(self) -> FirewallRuleId {
        self.origin_rule_id
    }
}

fn firewall_authority_digest_step(digest: u64, value: u64) -> u64 {
    digest
        .wrapping_add(value.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .rotate_left(17)
        ^ 0xa5a5_5a5a_c3c3_3c3c
}

fn firewall_state_authority_digest(states: &[FirewallStateSlot]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, state) in states.iter().copied().enumerate() {
        for value in [
            u64::try_from(index).expect("validated firewall capacity fits u64"),
            u64::from(state.occupied),
            state.slot_generation,
            state.config_generation,
            u64::from(state.protocol == FirewallProtocol::Tcp),
            u64::from(state.origin_ingress.0),
            u64::from(state.origin_egress.0),
            u64::from(u32::from_be_bytes(state.initiator_address.octets())),
            u64::from(u32::from_be_bytes(state.responder_address.octets())),
            u64::from(state.initiator_port),
            u64::from(state.responder_port),
            state.last_activity_ms,
            u64::from(state.tcp_phase == FirewallTcpPhase::Active),
            u64::from(state.tcp_forward_ack),
            u64::from(state.tcp_reverse_ack),
            u64::from(state.origin_rule_id.0),
        ] {
            digest = firewall_authority_digest_step(digest, value);
        }
    }
    digest
}

const FIREWALL_AUTHORITY_COMMITMENT_TAG: u64 = 0x5255_5354_2e46_4952;

/// Commits the firewall constructor hash configuration and every bounded
/// state node without exposing either the key or the state backing. The keyed
/// configuration probe makes an alternate key distinguishable even when all
/// open-addressing start buckets are preserved; the per-state keyed flow hash
/// binds the node/hash relation as well.
#[allow(clippy::too_many_arguments)]
fn firewall_authority_commitment(
    binding: FirewallConfigBinding,
    states: &[FirewallStateSlot],
    watermark_ms: Option<u64>,
    runtime_epoch: u64,
    next_slot_generation: u64,
    occupied_count: usize,
    recomputed_occupied_count: usize,
    state_digest: u64,
) -> u64 {
    let mut commitment = siphash24(
        binding.hash_key,
        [
            FIREWALL_AUTHORITY_COMMITMENT_TAG,
            binding.generation,
            u64::try_from(states.len()).expect("validated firewall capacity fits u64"),
            u64::from(watermark_ms.is_some()),
            watermark_ms.unwrap_or_default(),
            runtime_epoch,
            next_slot_generation,
            u64::try_from(occupied_count).expect("validated firewall count fits u64"),
            u64::try_from(recomputed_occupied_count).expect("validated firewall count fits u64"),
            state_digest,
        ],
    );
    for (index, state) in states.iter().copied().enumerate() {
        commitment = firewall_authority_digest_step(
            commitment,
            u64::try_from(index).expect("validated firewall index fits u64"),
        );
        commitment = firewall_authority_digest_step(commitment, u64::from(state.occupied));
        let node_hash = state
            .occupied
            .then(|| flow_hash(slot_packet(state), binding.generation, binding.hash_key));
        commitment = firewall_authority_digest_step(commitment, node_hash.unwrap_or_default());
    }
    commitment
}

/// Opaque, fixed-width authority evidence for a firewall runtime.
///
/// `Eq` compares the complete private envelope, including lifecycle scalars,
/// occupied counts, slot generations, and the bounded state digest. `Debug`
/// intentionally emits only a redacted marker, so a consumer cannot recover
/// state topology, packet tuples, keys, or generation values from diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FirewallAuthorityEvidence {
    words: [u64; 7],
}

impl std::fmt::Debug for FirewallAuthorityEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FirewallAuthorityEvidence([REDACTED])")
    }
}

impl FirewallAuthorityEvidence {
    /// Encodes a bounded, independently calculated expected contract.
    ///
    /// This creates an opaque equality value only; it never extracts or
    /// enumerates runtime state. The fixed envelope is deliberately not
    /// exposed after construction.
    pub const fn from_expected_contract(words: [u64; 7]) -> Self {
        Self { words }
    }

    /// Returns only the aggregate maintained/recomputed occupancy verdict.
    /// Full authority checks must compare the opaque value with `Eq`.
    #[must_use]
    pub const fn occupied_count_conserved(self) -> bool {
        self.words[4] == self.words[5]
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FirewallCounters {
    pub allowed_new: u64,
    pub allowed_established: u64,
    pub denied_by_rule: u64,
    pub denied_default: u64,
    pub invalid_packets: u64,
    pub state_full: u64,
    pub clock_regressions: u64,
    pub config_mismatches: u64,
    pub reconciliations: u64,
    pub states_expired: u64,
    pub state_probes: u64,
    pub maintenance_steps: u64,
    pub rule_evaluations: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallVerdict {
    Allow,
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallConnectionClass {
    New,
    Established,
    Related,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallPolicySource {
    Rule(FirewallRuleId),
    Default,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallFailure {
    InvalidInitialTcp,
    StateTableFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallDisposition {
    pub verdict: FirewallVerdict,
    pub class: FirewallConnectionClass,
    pub source: FirewallPolicySource,
    pub matched_action: Option<FirewallAction>,
    pub failure: Option<FirewallFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallAuditRecord {
    pub ingress: IfId,
    pub egress: IfId,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub protocol: FirewallProtocol,
    pub source_port: u16,
    pub destination_port: u16,
    pub disposition: FirewallDisposition,
}

impl Default for FirewallAuditRecord {
    fn default() -> Self {
        Self {
            ingress: IfId(0),
            egress: IfId(0),
            source: Ipv4Address::from_octets([0; 4]),
            destination: Ipv4Address::from_octets([0; 4]),
            protocol: FirewallProtocol::Udp,
            source_port: 0,
            destination_port: 0,
            disposition: FirewallDisposition {
                verdict: FirewallVerdict::Drop,
                class: FirewallConnectionClass::New,
                source: FirewallPolicySource::Default,
                matched_action: None,
                failure: None,
            },
        }
    }
}

pub struct FirewallAuditBuffer<'a> {
    storage: &'a mut [FirewallAuditRecord],
    len: usize,
    dropped_records: u64,
}

impl<'a> FirewallAuditBuffer<'a> {
    pub fn new(storage: &'a mut [FirewallAuditRecord]) -> Self {
        storage.fill(FirewallAuditRecord::default());
        Self {
            storage,
            len: 0,
            dropped_records: 0,
        }
    }

    pub(crate) fn record(&mut self, packet: FirewallPacket, disposition: FirewallDisposition) {
        if let Some(slot) = self.storage.get_mut(self.len) {
            *slot = FirewallAuditRecord {
                ingress: packet.ingress,
                egress: packet.egress,
                source: packet.source,
                destination: packet.destination,
                protocol: packet.protocol,
                source_port: packet.source_port,
                destination_port: packet.destination_port,
                disposition,
            };
            self.len += 1;
        } else {
            self.dropped_records = self.dropped_records.saturating_add(1);
        }
    }

    #[must_use]
    pub fn records(&self) -> &[FirewallAuditRecord] {
        &self.storage[..self.len]
    }

    #[must_use]
    pub const fn dropped_records(&self) -> u64 {
        self.dropped_records
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.dropped_records = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallPlanError {
    RuleDenied(FirewallRuleId),
    DefaultDenied,
    InvalidInitialTcp(FirewallRuleId),
    StateFull(FirewallRuleId),
    ClockRegression,
}

/// Canonical forward/origin tuple quoted by an ICMPv4 error.
///
/// The interfaces and endpoints must describe the original packet before NAT
/// translation. RELATED inspection deliberately never reverses this tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallRelatedIcmpv4Flow {
    ingress: IfId,
    egress: IfId,
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: FirewallProtocol,
    source_port: u16,
    destination_port: u16,
}

impl FirewallRelatedIcmpv4Flow {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        ingress: IfId,
        egress: IfId,
        source: Ipv4Address,
        destination: Ipv4Address,
        protocol: FirewallProtocol,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Self {
            ingress,
            egress,
            source,
            destination,
            protocol,
            source_port,
            destination_port,
        }
    }

    const fn packet(self) -> FirewallPacket {
        FirewallPacket {
            ingress: self.ingress,
            egress: self.egress,
            source: self.source,
            destination: self.destination,
            protocol: self.protocol,
            source_port: self.source_port,
            destination_port: self.destination_port,
            tcp_flags: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallRelatedIcmpv4Error {
    StateMiss,
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FirewallPacket {
    pub ingress: IfId,
    pub egress: IfId,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub protocol: FirewallProtocol,
    pub source_port: u16,
    pub destination_port: u16,
    pub tcp_flags: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FirewallPlan {
    index: usize,
    expected_runtime_identity: u64,
    expected_generation: u64,
    expected_runtime_epoch: u64,
    expected_config_generation: u64,
    replacement: FirewallStateSlot,
    created: bool,
    replaced_expired: bool,
    disposition: FirewallDisposition,
}

impl FirewallPlan {
    pub(crate) const fn disposition(self) -> FirewallDisposition {
        self.disposition
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallCommitError {
    RuntimeIdentityChanged,
    RuntimeEpochChanged,
    ConfigGenerationChanged,
    SlotOutOfBounds,
    SlotGenerationChanged,
    UsableCapacityExceeded,
    EstablishedStateRegressed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FirewallProbe {
    live: Option<(usize, bool)>,
    reusable: Option<usize>,
    probes: usize,
}

fn flow_hash(packet: FirewallPacket, config_generation: u64, hash_key: FirewallHashKey) -> u64 {
    siphash24(hash_key, canonical_flow_words(packet, config_generation))
}

fn canonical_flow_words(packet: FirewallPacket, config_generation: u64) -> [u64; 8] {
    let mut first = (
        packet.ingress.0,
        u32::from_be_bytes(packet.source.octets()),
        packet.source_port,
    );
    let mut second = (
        packet.egress.0,
        u32::from_be_bytes(packet.destination.octets()),
        packet.destination_port,
    );
    if second < first {
        std::mem::swap(&mut first, &mut second);
    }
    [
        config_generation,
        match packet.protocol {
            FirewallProtocol::Tcp => 6,
            FirewallProtocol::Udp => 17,
        },
        u64::from(first.0),
        u64::from(first.1),
        u64::from(first.2),
        u64::from(second.0),
        u64::from(second.1),
        u64::from(second.2),
    ]
}

fn siphash24<const WORDS: usize>(key: FirewallHashKey, words: [u64; WORDS]) -> u64 {
    fn round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(13);
        *v1 ^= *v0;
        *v0 = v0.rotate_left(32);
        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(16);
        *v3 ^= *v2;
        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(21);
        *v3 ^= *v0;
        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(17);
        *v1 ^= *v2;
        *v2 = v2.rotate_left(32);
    }

    let mut v0 = key.first ^ 0x736f_6d65_7073_6575;
    let mut v1 = key.second ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key.first ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key.second ^ 0x7465_6462_7974_6573;
    for word in words {
        v3 ^= word;
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= word;
    }
    let final_block = ((WORDS * 8) as u64) << 56;
    v3 ^= final_block;
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= final_block;
    v2 ^= 0xff;
    for _ in 0..4 {
        round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

#[cfg(test)]
fn siphash24_bytes(key: FirewallHashKey, input: &[u8]) -> u64 {
    fn round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(13);
        *v1 ^= *v0;
        *v0 = v0.rotate_left(32);
        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(16);
        *v3 ^= *v2;
        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(21);
        *v3 ^= *v0;
        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(17);
        *v1 ^= *v2;
        *v2 = v2.rotate_left(32);
    }

    let mut v0 = key.first ^ 0x736f_6d65_7073_6575;
    let mut v1 = key.second ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key.first ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key.second ^ 0x7465_6462_7974_6573;
    let mut chunks = input.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().expect("chunk size is exact"));
        v3 ^= word;
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= word;
    }
    let mut final_block = (input.len() as u64) << 56;
    for (offset, byte) in chunks.remainder().iter().copied().enumerate() {
        final_block |= u64::from(byte) << (offset * 8);
    }
    v3 ^= final_block;
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= final_block;
    v2 ^= 0xff;
    for _ in 0..4 {
        round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

fn slot_packet(slot: FirewallStateSlot) -> FirewallPacket {
    FirewallPacket {
        ingress: slot.origin_ingress,
        egress: slot.origin_egress,
        source: slot.initiator_address,
        destination: slot.responder_address,
        protocol: slot.protocol,
        source_port: slot.initiator_port,
        destination_port: slot.responder_port,
        tcp_flags: 0,
    }
}

fn probe_distance(home: usize, position: usize, capacity: usize) -> usize {
    if position >= home {
        position - home
    } else {
        capacity - home + position
    }
}

const fn usable_state_capacity(capacity: usize) -> usize {
    match capacity {
        0 => 0,
        1..=3 => capacity,
        _ => capacity - ((capacity - 1) / 4 + 1),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallReconcileReport {
    pub states_flushed: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallReconcileError {
    GenerationRegression,
    IdentityCollision,
    HashKeyNotRotated,
    RuntimeEpochExhausted,
}

/// Exclusive proof that one firewall publication can be committed totally.
///
/// The permit owns the exact runtime borrow validated by preflight. It cannot
/// be applied to another runtime, cloned, or committed twice.
///
/// ```compile_fail
/// use ruster_core::{FirewallConfig, FirewallRuntime};
///
/// fn reborrow<'state>(
///     runtime: &mut FirewallRuntime<'state>,
///     config: FirewallConfig<'_>,
/// ) {
///     let permit = runtime.preflight_reconcile(config).unwrap();
///     let _ = runtime.counters();
///     permit.commit();
/// }
/// ```
#[must_use]
pub struct FirewallReconcilePermit<'runtime, 'state> {
    runtime: &'runtime mut FirewallRuntime<'state>,
    next: FirewallConfigBinding,
    next_runtime_epoch: u64,
    advance: bool,
    report: FirewallReconcileReport,
}

/// Fixed-capacity, worker-local IPv4 flow state.
///
/// `ESTABLISHED` in this API means only an exact local tuple/interface state
/// hit. It is not a TCP sequence/window validation claim.
///
/// ```compile_fail
/// use ruster_core::FirewallRuntime;
/// fn assert_send<T: Send>() {}
/// assert_send::<FirewallRuntime<'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::FirewallRuntime;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<FirewallRuntime<'static>>();
/// ```
pub struct FirewallRuntime<'state> {
    binding: FirewallConfigBinding,
    states: &'state mut [FirewallStateSlot],
    runtime_identity: u64,
    watermark_ms: Option<u64>,
    runtime_epoch: u64,
    next_slot_generation: u64,
    occupied_count: usize,
    counters: FirewallCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'state> FirewallRuntime<'state> {
    /// Creates runtime state bound to one validated firewall publication.
    ///
    /// The runtime retains only owned identity metadata. It does not borrow
    /// the rules slice; callers provide the current [`FirewallConfig`] again
    /// for each rule-evaluating packet plan.
    pub fn new(config: FirewallConfig<'_>, states: &'state mut [FirewallStateSlot]) -> Self {
        let runtime_identity = allocate_firewall_runtime_identity();
        states.fill(FirewallStateSlot::default());
        Self {
            binding: config.binding(),
            states,
            runtime_identity,
            watermark_ms: None,
            runtime_epoch: 1,
            next_slot_generation: 1,
            occupied_count: 0,
            counters: FirewallCounters::default(),
            _worker_local: PhantomData,
        }
    }

    /// Returns whether `config` is the exact publication currently bound.
    ///
    /// This compares owned scalar, pointer-value, length, and fingerprint
    /// metadata without dereferencing the rules identity retained by the
    /// runtime.
    #[must_use]
    pub fn config_matches(&self, config: &FirewallConfig<'_>) -> bool {
        self.binding == config.binding()
    }

    #[must_use]
    pub const fn counters(&self) -> FirewallCounters {
        self.counters
    }

    #[must_use]
    pub fn states(&self) -> &[FirewallStateSlot] {
        self.states
    }

    /// Returns fixed, secret-free authority evidence for cold/test consumers.
    ///
    /// The words are watermark-present, watermark, runtime epoch, next slot
    /// generation, maintained occupied count, recomputed occupied count, and
    /// a private keyed commitment over the constructor hash configuration,
    /// every bounded state node/hash relation, and the complete state digest.
    /// No packet, rule source, hash key, or allocation is exposed. This
    /// deliberately cold validation must stay out of the packet path.
    #[must_use]
    pub fn authority_evidence(&self) -> FirewallAuthorityEvidence {
        let occupied_count = self.states.iter().filter(|slot| slot.occupied).count();
        let state_digest = firewall_state_authority_digest(self.states);
        FirewallAuthorityEvidence {
            words: [
                u64::from(self.watermark_ms.is_some()),
                self.watermark_ms.unwrap_or_default(),
                self.runtime_epoch,
                self.next_slot_generation,
                u64::try_from(self.occupied_count).expect("validated firewall count fits u64"),
                u64::try_from(occupied_count).expect("validated firewall count fits u64"),
                firewall_authority_commitment(
                    self.binding,
                    self.states,
                    self.watermark_ms,
                    self.runtime_epoch,
                    self.next_slot_generation,
                    self.occupied_count,
                    occupied_count,
                    state_digest,
                ),
            ],
        }
    }

    #[must_use]
    pub const fn usable_capacity(&self) -> usize {
        usable_state_capacity(self.states.len())
    }

    /// Returns whether this runtime is still in its exact constructor state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.states
            .iter()
            .all(|slot| *slot == FirewallStateSlot::default())
            && self.watermark_ms.is_none()
            && self.runtime_epoch == 1
            && self.next_slot_generation == 1
            && self.occupied_count == 0
            && self.counters == FirewallCounters::default()
    }

    /// Validates a publication and exclusively retains this exact runtime.
    ///
    /// Dropping the returned permit leaves every runtime byte unchanged.
    pub fn preflight_reconcile<'runtime>(
        &'runtime mut self,
        config: FirewallConfig<'_>,
    ) -> Result<FirewallReconcilePermit<'runtime, 'state>, FirewallReconcileError> {
        let next = config.binding();
        if next.generation < self.binding.generation {
            return Err(FirewallReconcileError::GenerationRegression);
        }
        if next.generation == self.binding.generation {
            if next != self.binding {
                return Err(FirewallReconcileError::IdentityCollision);
            }
            let next_runtime_epoch = self.runtime_epoch;
            return Ok(FirewallReconcilePermit {
                runtime: self,
                next,
                next_runtime_epoch,
                advance: false,
                report: FirewallReconcileReport { states_flushed: 0 },
            });
        }
        if next.hash_key == self.binding.hash_key {
            return Err(FirewallReconcileError::HashKeyNotRotated);
        }
        let next_runtime_epoch = self
            .runtime_epoch
            .checked_add(1)
            .ok_or(FirewallReconcileError::RuntimeEpochExhausted)?;
        let states_flushed = self.occupied_count;
        Ok(FirewallReconcilePermit {
            runtime: self,
            next,
            next_runtime_epoch,
            advance: true,
            report: FirewallReconcileReport { states_flushed },
        })
    }

    /// Binds a validated publication and flushes state on a fresh generation.
    ///
    /// No borrow of `config` or its rules slice is retained after this call.
    pub fn reconcile(
        &mut self,
        config: FirewallConfig<'_>,
    ) -> Result<FirewallReconcileReport, FirewallReconcileError> {
        self.preflight_reconcile(config)
            .map(FirewallReconcilePermit::commit)
    }

    pub(crate) fn record_config_mismatch(&mut self) {
        self.counters.config_mismatches = self.counters.config_mismatches.saturating_add(1);
    }

    pub(crate) fn record_invalid_packet(&mut self) {
        self.counters.invalid_packets = self.counters.invalid_packets.saturating_add(1);
    }

    pub(crate) fn observe_attempt(&mut self, now_ms: u64) -> Result<(), FirewallPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            self.counters.clock_regressions = self.counters.clock_regressions.saturating_add(1);
            return Err(FirewallPlanError::ClockRegression);
        }
        self.watermark_ms = Some(now_ms);
        Ok(())
    }

    pub(crate) fn record_plan_error(&mut self, error: FirewallPlanError) {
        match error {
            FirewallPlanError::RuleDenied(_) => {
                self.counters.denied_by_rule = self.counters.denied_by_rule.saturating_add(1);
            }
            FirewallPlanError::DefaultDenied => {
                self.counters.denied_default = self.counters.denied_default.saturating_add(1);
            }
            FirewallPlanError::InvalidInitialTcp(_) => {
                self.counters.invalid_packets = self.counters.invalid_packets.saturating_add(1);
            }
            FirewallPlanError::StateFull(_) => {
                self.counters.state_full = self.counters.state_full.saturating_add(1);
            }
            FirewallPlanError::ClockRegression => {
                // `observe_attempt` owns this counter.
            }
        }
    }

    pub(crate) fn plan_packet(
        &mut self,
        config: &FirewallConfig<'_>,
        packet: FirewallPacket,
        now_ms: u64,
    ) -> Result<FirewallPlan, FirewallPlanError> {
        debug_assert!(self.config_matches(config));
        self.observe_attempt(now_ms)?;
        let probe = self.probe(packet, now_ms);
        self.counters.state_probes = self
            .counters
            .state_probes
            .saturating_add(probe.probes as u64);
        if let Some((index, reverse)) = probe.live {
            let current = self.states[index];
            let rst = packet.protocol == FirewallProtocol::Tcp && packet.tcp_flags & 0x04 != 0;
            let mut replacement = current;
            if !rst {
                replacement.last_activity_ms = now_ms;
                if packet.protocol == FirewallProtocol::Tcp && packet.tcp_flags & 0x10 != 0 {
                    if reverse {
                        replacement.tcp_reverse_ack = true;
                    } else {
                        replacement.tcp_forward_ack = true;
                    }
                    if replacement.tcp_forward_ack && replacement.tcp_reverse_ack {
                        replacement.tcp_phase = FirewallTcpPhase::Active;
                    }
                }
            }
            return Ok(FirewallPlan {
                index,
                expected_runtime_identity: self.runtime_identity,
                expected_generation: current.slot_generation,
                expected_runtime_epoch: self.runtime_epoch,
                expected_config_generation: self.binding.generation,
                replacement,
                created: false,
                replaced_expired: false,
                disposition: FirewallDisposition {
                    verdict: FirewallVerdict::Allow,
                    class: FirewallConnectionClass::Established,
                    source: FirewallPolicySource::Rule(current.origin_rule_id),
                    matched_action: Some(FirewallAction::AllowStateful),
                    failure: None,
                },
            });
        }

        let mut matched = None;
        for rule in config.rules.iter().copied() {
            self.counters.rule_evaluations = self.counters.rule_evaluations.saturating_add(1);
            if rule.matches(packet) {
                matched = Some(rule);
                break;
            }
        }
        match matched {
            Some(rule) if rule.action == FirewallAction::Deny => {
                return Err(FirewallPlanError::RuleDenied(rule.id));
            }
            None => return Err(FirewallPlanError::DefaultDenied),
            Some(_) => {}
        }
        let rule_id = matched.expect("allow branch requires a matching rule").id;
        if packet.protocol == FirewallProtocol::Tcp && packet.tcp_flags & 0x17 != 0x02 {
            return Err(FirewallPlanError::InvalidInitialTcp(rule_id));
        }
        let index = probe
            .reusable
            .ok_or(FirewallPlanError::StateFull(rule_id))?;
        let current = self.states[index];
        if !current.occupied && self.occupied_count >= self.usable_capacity() {
            return Err(FirewallPlanError::StateFull(rule_id));
        }
        let slot_generation = self.next_slot_generation.max(1);
        Ok(FirewallPlan {
            index,
            expected_runtime_identity: self.runtime_identity,
            expected_generation: current.slot_generation,
            expected_runtime_epoch: self.runtime_epoch,
            expected_config_generation: self.binding.generation,
            replacement: FirewallStateSlot {
                occupied: true,
                slot_generation,
                config_generation: self.binding.generation,
                protocol: packet.protocol,
                origin_ingress: packet.ingress,
                origin_egress: packet.egress,
                initiator_address: packet.source,
                responder_address: packet.destination,
                initiator_port: packet.source_port,
                responder_port: packet.destination_port,
                last_activity_ms: now_ms,
                tcp_phase: FirewallTcpPhase::Opening,
                tcp_forward_ack: false,
                tcp_reverse_ack: false,
                origin_rule_id: rule_id,
            },
            created: true,
            replaced_expired: current.occupied,
            disposition: FirewallDisposition {
                verdict: FirewallVerdict::Allow,
                class: FirewallConnectionClass::New,
                source: FirewallPolicySource::Rule(rule_id),
                matched_action: Some(FirewallAction::AllowStateful),
                failure: None,
            },
        })
    }

    /// Looks up a live originating flow without changing any runtime state.
    ///
    /// This bounded probe accepts only the exact forward/origin tuple. It does
    /// not scan rules, accept reverse tuples, refresh activity, advance the
    /// clock watermark, clean expired slots, or update counters.
    pub fn inspect_related_icmpv4(
        &self,
        flow: FirewallRelatedIcmpv4Flow,
        now_ms: u64,
    ) -> Result<FirewallRuleId, FirewallRelatedIcmpv4Error> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            return Err(FirewallRelatedIcmpv4Error::ClockRegression);
        }
        if self.states.is_empty() {
            return Err(FirewallRelatedIcmpv4Error::StateMiss);
        }

        let packet = flow.packet();
        let capacity = self.states.len();
        let start =
            flow_hash(packet, self.binding.generation, self.binding.hash_key) as usize % capacity;
        for distance in 0..capacity {
            let slot = self.states[(start + distance) % capacity];
            if !slot.occupied {
                break;
            }
            if !self.slot_live(slot, now_ms) || slot.protocol != packet.protocol {
                continue;
            }
            let direct = slot.origin_ingress == packet.ingress
                && slot.origin_egress == packet.egress
                && slot.initiator_address == packet.source
                && slot.responder_address == packet.destination
                && slot.initiator_port == packet.source_port
                && slot.responder_port == packet.destination_port;
            if direct {
                return Ok(slot.origin_rule_id);
            }
        }
        Err(FirewallRelatedIcmpv4Error::StateMiss)
    }

    pub(crate) fn commit(&mut self, plan: FirewallPlan) -> Result<(), FirewallCommitError> {
        if self.runtime_identity != plan.expected_runtime_identity {
            return Err(FirewallCommitError::RuntimeIdentityChanged);
        }
        if self.runtime_epoch != plan.expected_runtime_epoch {
            return Err(FirewallCommitError::RuntimeEpochChanged);
        }
        if self.binding.generation != plan.expected_config_generation {
            return Err(FirewallCommitError::ConfigGenerationChanged);
        }
        let Some(&current) = self.states.get(plan.index) else {
            return Err(FirewallCommitError::SlotOutOfBounds);
        };
        if current.slot_generation != plan.expected_generation {
            return Err(FirewallCommitError::SlotGenerationChanged);
        }
        if plan.created && !current.occupied && self.occupied_count >= self.usable_capacity() {
            return Err(FirewallCommitError::UsableCapacityExceeded);
        }
        if !plan.created
            && (plan.replacement.last_activity_ms < current.last_activity_ms
                || (current.protocol == FirewallProtocol::Tcp
                    && ((current.tcp_phase == FirewallTcpPhase::Active
                        && plan.replacement.tcp_phase == FirewallTcpPhase::Opening)
                        || (current.tcp_forward_ack && !plan.replacement.tcp_forward_ack)
                        || (current.tcp_reverse_ack && !plan.replacement.tcp_reverse_ack))))
        {
            return Err(FirewallCommitError::EstablishedStateRegressed);
        }
        self.states[plan.index] = plan.replacement;
        if plan.created {
            if !current.occupied {
                self.occupied_count += 1;
            }
            self.next_slot_generation = plan.replacement.slot_generation.wrapping_add(1).max(1);
            self.counters.allowed_new = self.counters.allowed_new.saturating_add(1);
            if plan.replaced_expired {
                self.counters.states_expired = self.counters.states_expired.saturating_add(1);
            }
        } else {
            self.counters.allowed_established = self.counters.allowed_established.saturating_add(1);
        }
        Ok(())
    }

    fn probe(&mut self, packet: FirewallPacket, now_ms: u64) -> FirewallProbe {
        if self.states.is_empty() {
            return FirewallProbe {
                live: None,
                reusable: None,
                probes: 0,
            };
        }
        let capacity = self.states.len();
        let start =
            flow_hash(packet, self.binding.generation, self.binding.hash_key) as usize % capacity;
        let mut probes = 0;
        let mut cleanup_allowed = true;
        for _pass in 0..2 {
            let mut first_expired = None;
            let mut restart = false;
            for distance in 0..capacity {
                let index = (start + distance) % capacity;
                let slot = self.states[index];
                probes += 1;
                if !slot.occupied {
                    return FirewallProbe {
                        live: None,
                        reusable: Some(first_expired.unwrap_or(index)),
                        probes,
                    };
                }
                if !self.slot_live(slot, now_ms) {
                    if cleanup_allowed {
                        self.delete_expired_and_shift(index);
                        cleanup_allowed = false;
                        restart = true;
                        break;
                    }
                    first_expired.get_or_insert(index);
                    continue;
                }
                if slot.protocol != packet.protocol {
                    continue;
                }
                let direct = slot.origin_ingress == packet.ingress
                    && slot.origin_egress == packet.egress
                    && slot.initiator_address == packet.source
                    && slot.responder_address == packet.destination
                    && slot.initiator_port == packet.source_port
                    && slot.responder_port == packet.destination_port;
                let reverse = slot.origin_ingress == packet.egress
                    && slot.origin_egress == packet.ingress
                    && slot.initiator_address == packet.destination
                    && slot.responder_address == packet.source
                    && slot.initiator_port == packet.destination_port
                    && slot.responder_port == packet.source_port;
                if direct || reverse {
                    return FirewallProbe {
                        live: Some((index, reverse)),
                        reusable: None,
                        probes,
                    };
                }
            }
            if restart {
                continue;
            }
            return FirewallProbe {
                live: None,
                reusable: first_expired,
                probes,
            };
        }
        unreachable!("one cleanup permits at most one bounded restart")
    }

    fn delete_expired_and_shift(&mut self, index: usize) {
        let capacity = self.states.len();
        self.states[index] = FirewallStateSlot::default();
        self.occupied_count -= 1;
        self.runtime_epoch = self.runtime_epoch.wrapping_add(1).max(1);
        self.counters.states_expired = self.counters.states_expired.saturating_add(1);
        self.counters.maintenance_steps = self.counters.maintenance_steps.saturating_add(1);
        let mut hole = index;
        let mut scan = (index + 1) % capacity;
        for _ in 0..capacity {
            self.counters.maintenance_steps = self.counters.maintenance_steps.saturating_add(1);
            let slot = self.states[scan];
            if !slot.occupied {
                break;
            }
            self.counters.maintenance_steps = self.counters.maintenance_steps.saturating_add(1);
            let home = flow_hash(
                slot_packet(slot),
                self.binding.generation,
                self.binding.hash_key,
            ) as usize
                % capacity;
            if probe_distance(home, hole, capacity) < probe_distance(home, scan, capacity) {
                self.states[hole] = slot;
                self.states[scan] = FirewallStateSlot::default();
                hole = scan;
                self.counters.maintenance_steps = self.counters.maintenance_steps.saturating_add(1);
            }
            scan = (scan + 1) % capacity;
        }
    }

    fn slot_live(&self, slot: FirewallStateSlot, now_ms: u64) -> bool {
        if !slot.occupied
            || slot.config_generation != self.binding.generation
            || now_ms < slot.last_activity_ms
        {
            return false;
        }
        let ttl = match (slot.protocol, slot.tcp_phase) {
            (FirewallProtocol::Udp, _) => self.binding.policy.udp_idle_ttl_ms,
            (FirewallProtocol::Tcp, FirewallTcpPhase::Opening) => {
                self.binding.policy.tcp_opening_idle_ttl_ms
            }
            (FirewallProtocol::Tcp, FirewallTcpPhase::Active) => {
                self.binding.policy.tcp_active_idle_ttl_ms
            }
        };
        now_ms - slot.last_activity_ms < ttl
    }
}

impl FirewallReconcilePermit<'_, '_> {
    /// Commits the preflighted publication without validation or failure.
    pub fn commit(self) -> FirewallReconcileReport {
        if self.advance {
            self.runtime.states.fill(FirewallStateSlot::default());
            self.runtime.occupied_count = 0;
            self.runtime.binding = self.next;
            self.runtime.runtime_epoch = self.next_runtime_epoch;
            self.runtime.counters.reconciliations =
                self.runtime.counters.reconciliations.saturating_add(1);
        }
        self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Interface, Ipv4Mtu, Ipv4OriginPolicy, LocalIpv4Binding, MacAddress, Neighbor, Route,
        ValidatedForwardingOwner,
    };

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const INTERNAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
    const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);

    fn with_snapshot<T>(test: impl FnOnce(&ForwardingSnapshot<'_>) -> T) -> T {
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(
                Ipv4Address::from_octets([0; 4]),
                0,
                WAN,
                Some(Ipv4Address::from_octets([203, 0, 113, 1])),
            )
            .unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let neighbors = [Neighbor {
            interface: WAN,
            target: Ipv4Address::from_octets([203, 0, 113, 1]),
            mac: MacAddress([2, 0, 0, 0, 0, 3]),
        }];
        let bindings = [LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        test(&snapshot)
    }

    fn validated_forwarding_owner() -> ValidatedForwardingOwner {
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(
                Ipv4Address::from_octets([0; 4]),
                0,
                WAN,
                Some(Ipv4Address::from_octets([203, 0, 113, 1])),
            )
            .unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let neighbors = [Neighbor {
            interface: WAN,
            target: Ipv4Address::from_octets([203, 0, 113, 1]),
            mac: MacAddress([2, 0, 0, 0, 0, 3]),
        }];
        let bindings = [LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        }];
        ValidatedForwardingOwner::new(
            routes.into(),
            interfaces.into(),
            neighbors.into(),
            bindings.into(),
            Ipv4OriginPolicy::default(),
        )
        .unwrap()
    }

    fn any() -> FirewallIpv4Prefix {
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap()
    }

    fn hash_key() -> FirewallHashKey {
        FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap()
    }

    fn rotated_hash_key() -> FirewallHashKey {
        FirewallHashKey::new(0xa5a5_5a5a_0123_4567, 0x1357_9bdf_2468_ace0).unwrap()
    }

    fn rule(id: u32, action: FirewallAction, protocol: FirewallProtocol) -> FirewallRule {
        FirewallRule::new(
            FirewallRuleId(id),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            any(),
            any(),
            protocol,
            FirewallPortRange::new(0, u16::MAX).unwrap(),
            FirewallPortRange::new(1, u16::MAX).unwrap(),
            action,
        )
    }

    fn packet(protocol: FirewallProtocol, flags: u8) -> FirewallPacket {
        FirewallPacket {
            ingress: LAN,
            egress: WAN,
            source: INTERNAL,
            destination: REMOTE,
            protocol,
            source_port: 12_345,
            destination_port: 443,
            tcp_flags: flags,
        }
    }

    fn validated_firewall_owner(
        snapshot: &ForwardingSnapshot<'_>,
        generation: u64,
        hash_key: FirewallHashKey,
    ) -> ValidatedFirewallOwner {
        ValidatedFirewallOwner::new(
            snapshot,
            vec![rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )]
            .into_boxed_slice(),
            FirewallPolicy::default(),
            generation,
            hash_key,
        )
        .unwrap()
    }

    #[test]
    fn firewall_config_semantic_eq_tracks_rules_and_policy_only() {
        let forwarding = validated_forwarding_owner();
        let snapshot = forwarding.snapshot();
        {
            let owner = validated_firewall_owner(&snapshot, 1, hash_key());
            let base = owner.config();

            let mut identity_only = base;
            identity_only.generation = u64::MAX;
            identity_only.hash_key = rotated_hash_key();
            identity_only.snapshot_authority = u64::MAX;
            identity_only.snapshot_identity = [usize::MAX; 8];
            identity_only.rules_identity = usize::MAX;
            identity_only.rules_len = usize::MAX;
            identity_only.rules_fingerprint = u64::MAX;
            assert!(base.semantic_eq(identity_only));

            let changed_policy = FirewallPolicy::new(
                base.policy().udp_idle_ttl_ms() + 1,
                base.policy().tcp_opening_idle_ttl_ms(),
                base.policy().tcp_active_idle_ttl_ms(),
            )
            .unwrap();
            let policy_config = FirewallConfig::new(
                &snapshot,
                base.rules(),
                changed_policy,
                base.generation(),
                base.hash_key(),
            )
            .unwrap();
            assert!(!base.semantic_eq(policy_config));

            let changed_rules = [rule(1, FirewallAction::Deny, FirewallProtocol::Udp)];
            let rules_config = FirewallConfig::new(
                &snapshot,
                &changed_rules,
                base.policy(),
                base.generation(),
                base.hash_key(),
            )
            .unwrap();
            assert!(!base.semantic_eq(rules_config));
        }
    }

    #[test]
    fn firewall_authority_evidence_is_full_eq_and_redacted_debug() {
        fn assert_copy_eq<T: Copy + Eq + PartialEq>() {}

        assert_copy_eq::<FirewallAuthorityEvidence>();

        const POISON: u64 = 0xfedc_ba98_7654_3210;
        let words = [POISON; 7];
        let evidence = FirewallAuthorityEvidence::from_expected_contract(words);
        let mut changed_words = words;
        changed_words[6] ^= 1;
        let changed = FirewallAuthorityEvidence::from_expected_contract(changed_words);

        assert_ne!(evidence, changed);
        for index in 0..7 {
            let mut changed_words = words;
            changed_words[index] ^= 1;
            assert_ne!(
                evidence,
                FirewallAuthorityEvidence::from_expected_contract(changed_words),
                "firewall authority word {index} must participate in Eq"
            );
        }
        assert_eq!(
            format!("{evidence:?}"),
            "FirewallAuthorityEvidence([REDACTED])"
        );
        assert_eq!(format!("{evidence:#?}"), format!("{evidence:?}"));
        assert!(!format!("{evidence:?}").contains(&POISON.to_string()));
        assert!(!format!("{evidence:?}").contains(&format!("{POISON:x}")));

        let mut count_changed = words;
        count_changed[4] ^= 1;
        assert_ne!(
            evidence,
            FirewallAuthorityEvidence::from_expected_contract(count_changed)
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RuntimeImage {
        binding: FirewallConfigBinding,
        states: Vec<FirewallStateSlot>,
        watermark_ms: Option<u64>,
        runtime_epoch: u64,
        next_slot_generation: u64,
        occupied_count: usize,
        counters: FirewallCounters,
    }

    fn runtime_image(runtime: &FirewallRuntime<'_>) -> RuntimeImage {
        RuntimeImage {
            binding: runtime.binding,
            states: runtime.states.to_vec(),
            watermark_ms: runtime.watermark_ms,
            runtime_epoch: runtime.runtime_epoch,
            next_slot_generation: runtime.next_slot_generation,
            occupied_count: runtime.occupied_count,
            counters: runtime.counters,
        }
    }

    fn assert_reconcile_error_is_atomic(
        runtime: &mut FirewallRuntime<'_>,
        config: FirewallConfig<'_>,
        expected: FirewallReconcileError,
    ) {
        let before = runtime_image(runtime);
        assert_eq!(runtime.preflight_reconcile(config).err(), Some(expected));
        assert_eq!(runtime_image(runtime), before);
    }

    #[test]
    fn validated_firewall_owner_rejects_legacy_snapshot_and_caches_validation() {
        with_snapshot(|legacy| {
            assert!(matches!(
                ValidatedFirewallOwner::new(
                    legacy,
                    Vec::new().into_boxed_slice(),
                    FirewallPolicy::default(),
                    1,
                    hash_key(),
                ),
                Err(FirewallConfigError::PublicationOwnerRequired)
            ));
        });

        FULL_FIREWALL_VALIDATIONS.with(|count| count.set(0));
        let forwarding = validated_forwarding_owner();
        let owner = validated_firewall_owner(&forwarding.snapshot(), 1, hash_key());
        assert_eq!(FULL_FIREWALL_VALIDATIONS.with(std::cell::Cell::get), 1);
        let first = owner.config();
        for _ in 0..1_024 {
            assert_eq!(owner.config().binding(), first.binding());
        }
        assert_eq!(FULL_FIREWALL_VALIDATIONS.with(std::cell::Cell::get), 1);
        assert_eq!(
            format!("{first:?}"),
            "FirewallConfig { policy: FirewallPolicy { udp_idle_ttl_ms: 300000, \
             tcp_opening_idle_ttl_ms: 240000, tcp_active_idle_ttl_ms: 7440000 }, generation: 1, \
             hash_key: FirewallHashKey([REDACTED]), rules_len: 1, .. }"
        );
        assert_eq!(
            format!("{owner:?}"),
            "ValidatedFirewallOwner { policy: FirewallPolicy { udp_idle_ttl_ms: 300000, \
             tcp_opening_idle_ttl_ms: 240000, tcp_active_idle_ttl_ms: 7440000 }, generation: 1, \
             hash_key: FirewallHashKey([REDACTED]), rules_len: 1, .. }"
        );
        assert_eq!(
            format!("{:?}", first.binding()),
            "FirewallConfigBinding { policy: FirewallPolicy { udp_idle_ttl_ms: 300000, \
             tcp_opening_idle_ttl_ms: 240000, tcp_active_idle_ttl_ms: 7440000 }, generation: 1, \
             hash_key: FirewallHashKey([REDACTED]), rules_len: 1, .. }"
        );
        let baseline = first.binding();
        let mut sensitive = baseline;
        sensitive.snapshot_authority = u64::MAX;
        sensitive.snapshot_identity = [usize::MAX; 8];
        sensitive.rules_identity = usize::MAX;
        sensitive.rules_fingerprint = u64::MAX;
        assert_eq!(format!("{baseline:?}"), format!("{sensitive:?}"));
        assert_eq!(format!("{baseline:#?}"), format!("{sensitive:#?}"));
        assert!(!format!("{sensitive:?}").contains(&u64::MAX.to_string()));
        assert!(!format!("{sensitive:#?}").contains(&u64::MAX.to_string()));
    }

    #[test]
    fn firewall_publication_nonce_prevents_empty_rule_aba_and_never_wraps() {
        use std::sync::atomic::AtomicU64;

        let forwarding = validated_forwarding_owner();
        let snapshot = forwarding.snapshot();
        let first = ValidatedFirewallOwner::new(
            &snapshot,
            Vec::new().into_boxed_slice(),
            FirewallPolicy::default(),
            1,
            hash_key(),
        )
        .unwrap();
        let second = ValidatedFirewallOwner::new(
            &snapshot,
            Vec::new().into_boxed_slice(),
            FirewallPolicy::default(),
            1,
            hash_key(),
        )
        .unwrap();
        let first_config = first.config();
        let identity = first_config.rules_identity;
        let nonce = first_config.binding().publication_nonce();
        assert_eq!(identity, second.config().rules_identity);
        assert_ne!(first_config.binding(), second.config().binding());
        assert_ne!(nonce & VALIDATED_FIREWALL_OWNER_AUTHORITY_BIT, 0);

        let moved = first;
        assert_eq!(moved.config().rules_identity, identity);
        assert_eq!(moved.config().binding().publication_nonce(), nonce);

        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            next_firewall_publication_nonce_from(&counter),
            Some(u64::MAX - 1)
        );
        assert_eq!(
            next_firewall_publication_nonce_from(&counter),
            Some(u64::MAX)
        );
        assert_eq!(next_firewall_publication_nonce_from(&counter), None);
        assert_eq!(next_firewall_publication_nonce_from(&counter), None);
    }

    #[test]
    fn firewall_reconcile_preflight_errors_are_atomic() {
        let forwarding = validated_forwarding_owner();
        let snapshot = forwarding.snapshot();
        let current_owner = validated_firewall_owner(&snapshot, 2, hash_key());
        let regression_owner = validated_firewall_owner(&snapshot, 1, rotated_hash_key());
        let collision_owner = validated_firewall_owner(&snapshot, 2, hash_key());
        let unrotated_owner = validated_firewall_owner(&snapshot, 3, hash_key());
        let rotated_owner = validated_firewall_owner(&snapshot, 3, rotated_hash_key());
        let mut states = [FirewallStateSlot::default(); 1];
        let mut runtime = FirewallRuntime::new(current_owner.config(), &mut states);

        assert_reconcile_error_is_atomic(
            &mut runtime,
            regression_owner.config(),
            FirewallReconcileError::GenerationRegression,
        );
        assert_reconcile_error_is_atomic(
            &mut runtime,
            collision_owner.config(),
            FirewallReconcileError::IdentityCollision,
        );
        assert_reconcile_error_is_atomic(
            &mut runtime,
            unrotated_owner.config(),
            FirewallReconcileError::HashKeyNotRotated,
        );
        runtime.runtime_epoch = u64::MAX;
        assert_reconcile_error_is_atomic(
            &mut runtime,
            rotated_owner.config(),
            FirewallReconcileError::RuntimeEpochExhausted,
        );
    }

    #[test]
    fn firewall_reconcile_permit_is_exact_drop_safe_and_total() {
        let forwarding = validated_forwarding_owner();
        let snapshot = forwarding.snapshot();
        let current_owner = validated_firewall_owner(&snapshot, 1, hash_key());
        let next_owner = validated_firewall_owner(&snapshot, 2, rotated_hash_key());
        let current = current_owner.config();
        let next = next_owner.config();
        let mut states = [FirewallStateSlot::default(); 2];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        runtime.states[0].occupied = true;
        runtime.occupied_count = 1;
        runtime.watermark_ms = Some(9);
        runtime.counters.reconciliations = u64::MAX;

        let before = runtime_image(&runtime);
        let permit = runtime.preflight_reconcile(next).unwrap();
        assert_eq!(permit.report, FirewallReconcileReport { states_flushed: 1 });
        drop(permit);
        assert_eq!(runtime_image(&runtime), before);

        assert_eq!(
            runtime.preflight_reconcile(next).unwrap().commit(),
            FirewallReconcileReport { states_flushed: 1 }
        );
        assert!(runtime
            .states
            .iter()
            .all(|slot| *slot == FirewallStateSlot::default()));
        assert_eq!(runtime.occupied_count, 0);
        assert_eq!(runtime.runtime_epoch, 2);
        assert_eq!(runtime.counters.reconciliations, u64::MAX);
        assert!(runtime.config_matches(&next));
        assert!(!runtime.config_matches(&current));
    }

    #[test]
    fn firewall_same_generation_noop_and_pristine_check_are_exact() {
        let forwarding = validated_forwarding_owner();
        let owner = validated_firewall_owner(&forwarding.snapshot(), 1, hash_key());
        let config = owner.config();
        let mut states = [FirewallStateSlot::default(); 1];
        let mut runtime = FirewallRuntime::new(config, &mut states);
        assert!(runtime.is_pristine());
        let before = runtime_image(&runtime);
        assert_eq!(
            runtime.preflight_reconcile(config).unwrap().commit(),
            FirewallReconcileReport { states_flushed: 0 }
        );
        assert_eq!(runtime_image(&runtime), before);
        runtime.states[0].slot_generation = 9;
        assert!(!runtime.is_pristine());
    }

    #[test]
    fn config_validates_prefix_range_ids_interfaces_generation_and_first_match() {
        assert_eq!(
            FirewallHashKey::new(0, 0),
            Err(FirewallHashKeyError::AllZero)
        );
        assert_eq!(format!("{:?}", hash_key()), "FirewallHashKey([REDACTED])");
        assert!(any().matches(Ipv4Address::from_octets([255; 4])));
        let host = FirewallIpv4Prefix::new(INTERNAL, 32).unwrap();
        assert!(host.matches(INTERNAL));
        assert!(!host.matches(Ipv4Address::from_octets([10, 0, 0, 11])));
        let endpoints = FirewallPortRange::new(53, 54).unwrap();
        assert!(endpoints.contains(53));
        assert!(endpoints.contains(54));
        assert!(!endpoints.contains(52));
        assert_eq!(
            FirewallIpv4Prefix::new(INTERNAL, 24),
            Err(FirewallIpv4PrefixError::HostBitsSet)
        );
        assert_eq!(
            FirewallIpv4Prefix::new(INTERNAL, 33),
            Err(FirewallIpv4PrefixError::InvalidPrefixLength)
        );
        assert_eq!(
            FirewallPortRange::new(2, 1),
            Err(FirewallPortRangeError::Reversed)
        );
        with_snapshot(|snapshot| {
            let duplicate = [
                rule(1, FirewallAction::Deny, FirewallProtocol::Udp),
                rule(1, FirewallAction::AllowStateful, FirewallProtocol::Udp),
            ];
            assert_eq!(
                FirewallConfig::new(
                    snapshot,
                    &duplicate,
                    FirewallPolicy::default(),
                    1,
                    hash_key()
                ),
                Err(FirewallConfigError::DuplicateRuleId)
            );
            assert_eq!(
                FirewallConfig::new(
                    snapshot,
                    &duplicate[..1],
                    FirewallPolicy::default(),
                    0,
                    hash_key(),
                ),
                Err(FirewallConfigError::GenerationZero)
            );
            let unknown = [FirewallRule::new(
                FirewallRuleId(3),
                FirewallInterface::Interface(IfId(99)),
                FirewallInterface::Any,
                any(),
                any(),
                FirewallProtocol::Udp,
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallAction::AllowStateful,
            )];
            assert_eq!(
                FirewallConfig::new(snapshot, &unknown, FirewallPolicy::default(), 1, hash_key()),
                Err(FirewallConfigError::IngressInterfaceMissing)
            );
            let rules = [
                rule(1, FirewallAction::Deny, FirewallProtocol::Udp),
                rule(2, FirewallAction::AllowStateful, FirewallProtocol::Udp),
            ];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            assert_eq!(
                runtime.plan_packet(&config, packet(FirewallProtocol::Udp, 0), 0),
                Err(FirewallPlanError::RuleDenied(FirewallRuleId(1)))
            );
        });
    }

    #[test]
    fn offline_rule_validation_matches_publication_validation_and_error_order() {
        with_snapshot(|snapshot| {
            let valid = [
                rule(1, FirewallAction::Deny, FirewallProtocol::Udp),
                rule(2, FirewallAction::AllowStateful, FirewallProtocol::Tcp),
            ];
            assert_eq!(validate_firewall_rules(snapshot, &[]), Ok(()));
            assert_eq!(validate_firewall_rules(snapshot, &valid), Ok(()));
            assert!(FirewallConfig::new(
                snapshot,
                &valid,
                FirewallPolicy::default(),
                1,
                hash_key(),
            )
            .is_ok());

            let zero_id_before_missing_interfaces = [FirewallRule::new(
                FirewallRuleId(0),
                FirewallInterface::Interface(IfId(98)),
                FirewallInterface::Interface(IfId(99)),
                any(),
                any(),
                FirewallProtocol::Udp,
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallAction::Deny,
            )];
            let duplicate_before_missing_interfaces = [
                rule(7, FirewallAction::Deny, FirewallProtocol::Udp),
                FirewallRule::new(
                    FirewallRuleId(7),
                    FirewallInterface::Interface(IfId(98)),
                    FirewallInterface::Interface(IfId(99)),
                    any(),
                    any(),
                    FirewallProtocol::Udp,
                    FirewallPortRange::new(0, u16::MAX).unwrap(),
                    FirewallPortRange::new(0, u16::MAX).unwrap(),
                    FirewallAction::Deny,
                ),
            ];
            let ingress_before_egress = [FirewallRule::new(
                FirewallRuleId(8),
                FirewallInterface::Interface(IfId(98)),
                FirewallInterface::Interface(IfId(99)),
                any(),
                any(),
                FirewallProtocol::Udp,
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallAction::Deny,
            )];
            let missing_egress = [FirewallRule::new(
                FirewallRuleId(9),
                FirewallInterface::Any,
                FirewallInterface::Interface(IfId(99)),
                any(),
                any(),
                FirewallProtocol::Udp,
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallAction::Deny,
            )];

            for (rules, expected) in [
                (
                    zero_id_before_missing_interfaces.as_slice(),
                    FirewallConfigError::RuleIdZero,
                ),
                (
                    duplicate_before_missing_interfaces.as_slice(),
                    FirewallConfigError::DuplicateRuleId,
                ),
                (
                    ingress_before_egress.as_slice(),
                    FirewallConfigError::IngressInterfaceMissing,
                ),
                (
                    missing_egress.as_slice(),
                    FirewallConfigError::EgressInterfaceMissing,
                ),
            ] {
                assert_eq!(validate_firewall_rules(snapshot, rules), Err(expected));
                assert_eq!(
                    FirewallConfig::new(snapshot, rules, FirewallPolicy::default(), 1, hash_key(),),
                    Err(expected)
                );
            }

            assert_eq!(
                FirewallConfig::new(
                    snapshot,
                    &zero_id_before_missing_interfaces,
                    FirewallPolicy::default(),
                    0,
                    hash_key(),
                ),
                Err(FirewallConfigError::GenerationZero),
                "publication metadata remains the first FirewallConfig::new check"
            );
        });
    }

    #[test]
    fn firewall_rule_matches_requires_every_packet_field() {
        // Contract: a rule matches only when interface, endpoint, protocol, and both ports all match.
        let source = FirewallIpv4Prefix::new(INTERNAL, 32).unwrap();
        let destination = FirewallIpv4Prefix::new(REMOTE, 32).unwrap();
        let source_ports = FirewallPortRange::new(12_345, 12_345).unwrap();
        let destination_ports = FirewallPortRange::new(443, 443).unwrap();
        let rule = FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            source,
            destination,
            FirewallProtocol::Udp,
            source_ports,
            destination_ports,
            FirewallAction::AllowStateful,
        );
        let matching = packet(FirewallProtocol::Udp, 0);
        assert!(rule.matches(matching));

        let mut mismatches = [matching; 7];
        mismatches[0].ingress = WAN;
        mismatches[1].egress = LAN;
        mismatches[2].source = Ipv4Address::from_octets([10, 0, 0, 11]);
        mismatches[3].destination = Ipv4Address::from_octets([198, 51, 100, 21]);
        mismatches[4].protocol = FirewallProtocol::Tcp;
        mismatches[5].source_port = 12_346;
        mismatches[6].destination_port = 444;
        for (index, candidate) in mismatches.into_iter().enumerate() {
            assert!(!rule.matches(candidate), "mismatch {index} must not match");
        }
    }

    #[test]
    fn firewall_config_authority_matches_requires_authority_and_identity() {
        // Contract: a configuration is authorized only for the exact snapshot authority and identity.
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            assert!(config.authority_matches(snapshot));

            let mut wrong_authority = config;
            wrong_authority.snapshot_authority ^= 1;
            assert!(!wrong_authority.authority_matches(snapshot));

            let mut wrong_identity = config;
            wrong_identity.snapshot_identity[0] ^= 1;
            assert!(!wrong_identity.authority_matches(snapshot));
        });
    }

    #[test]
    fn firewall_state_authority_digest_encodes_protocol_and_tcp_phase() {
        // Contract: authority digest distinguishes the protocol and TCP phase bits of every slot.
        let default_state = FirewallStateSlot::default();
        assert_eq!(
            firewall_state_authority_digest(&[default_state]),
            0xf58d_cf69_4a4c_80b9
        );

        let mut tcp_state = default_state;
        tcp_state.protocol = FirewallProtocol::Tcp;
        assert_eq!(
            firewall_state_authority_digest(&[tcp_state]),
            0x7de9_6766_a38f_d944
        );

        let mut active_state = default_state;
        active_state.tcp_phase = FirewallTcpPhase::Active;
        assert_eq!(
            firewall_state_authority_digest(&[active_state]),
            0x1215_6b01_55a4_4202
        );
    }

    #[test]
    fn firewall_authority_evidence_occupied_count_conservation_is_exact() {
        // Contract: maintained and recomputed occupancy are conserved iff their counts are equal.
        let conserved = FirewallAuthorityEvidence::from_expected_contract([0, 0, 1, 1, 3, 3, 0]);
        assert!(conserved.occupied_count_conserved());

        let not_conserved =
            FirewallAuthorityEvidence::from_expected_contract([0, 0, 1, 1, 3, 2, 0]);
        assert!(!not_conserved.occupied_count_conserved());
    }

    #[test]
    fn firewall_plan_packet_requires_tcp_protocol_for_rst_and_ack_flags() {
        // Contract: TCP-only RST/ACK handling must not suppress refreshes or set TCP flags on UDP state.
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let initial = runtime
                .plan_packet(&config, packet(FirewallProtocol::Udp, 0), 0)
                .unwrap();
            runtime.commit(initial).unwrap();

            let rst_flagged = runtime
                .plan_packet(&config, packet(FirewallProtocol::Udp, 0x04), 5)
                .unwrap();
            runtime.commit(rst_flagged).unwrap();
            assert_eq!(runtime.states()[0].last_activity_ms(), 5);

            let ack_flagged = runtime
                .plan_packet(&config, packet(FirewallProtocol::Udp, 0x10), 6)
                .unwrap();
            runtime.commit(ack_flagged).unwrap();
            assert!(!runtime.states()[0].tcp_forward_ack);
            assert!(!runtime.states()[0].tcp_reverse_ack);
        });
    }

    #[test]
    fn firewall_commit_rejects_each_established_state_regression_condition() {
        // Contract: an established commit must preserve activity, TCP phase, and both ACK observations.
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Tcp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);

            let initial = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x02), 0)
                .unwrap();
            runtime.commit(initial).unwrap();
            let mut reverse = packet(FirewallProtocol::Tcp, 0x12);
            reverse.ingress = WAN;
            reverse.egress = LAN;
            reverse.source = REMOTE;
            reverse.destination = INTERNAL;
            reverse.source_port = 443;
            reverse.destination_port = 12_345;
            let reverse_syn_ack = runtime.plan_packet(&config, reverse, 1).unwrap();
            runtime.commit(reverse_syn_ack).unwrap();
            assert_eq!(runtime.states()[0].tcp_phase(), FirewallTcpPhase::Opening);
            let direct_ack = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x10), 2)
                .unwrap();
            runtime.commit(direct_ack).unwrap();
            assert_eq!(runtime.states()[0].tcp_phase(), FirewallTcpPhase::Active);

            let mut phase_regression = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x10), 3)
                .unwrap();
            phase_regression.replacement.tcp_phase = FirewallTcpPhase::Opening;
            assert_eq!(
                runtime.commit(phase_regression),
                Err(FirewallCommitError::EstablishedStateRegressed)
            );

            let mut forward_ack_regression = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x10), 3)
                .unwrap();
            forward_ack_regression.replacement.tcp_forward_ack = false;
            assert_eq!(
                runtime.commit(forward_ack_regression),
                Err(FirewallCommitError::EstablishedStateRegressed)
            );

            let mut reverse_ack_regression = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x10), 3)
                .unwrap();
            reverse_ack_regression.replacement.tcp_reverse_ack = false;
            assert_eq!(
                runtime.commit(reverse_ack_regression),
                Err(FirewallCommitError::EstablishedStateRegressed)
            );
        });
    }

    #[test]
    fn firewall_slot_live_rejects_unoccupied_and_wrong_generation_slots() {
        // Contract: only occupied state from this configuration and a non-regressing clock is live.
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let runtime = FirewallRuntime::new(config, &mut slots);

            let unoccupied = FirewallStateSlot {
                config_generation: runtime.binding.generation,
                ..FirewallStateSlot::default()
            };
            assert!(!runtime.slot_live(unoccupied, 0));

            let wrong_generation = FirewallStateSlot {
                occupied: true,
                config_generation: runtime.binding.generation + 1,
                ..FirewallStateSlot::default()
            };
            assert!(!runtime.slot_live(wrong_generation, 0));
        });
    }

    #[test]
    fn siphash_vectors_and_canonical_flow_layout_match_independent_references() {
        let reference_key =
            FirewallHashKey::new(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908).unwrap();
        let mut message = [0_u8; 63];
        for (index, byte) in message.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for (length, expected) in [
            (0, 0x726f_db47_dd0e_0e31),
            (1, 0x74f8_39c5_93dc_67fd),
            (7, 0xab02_00f5_8b01_d137),
            (8, 0x93f5_f579_9a93_2462),
            (15, 0xa129_ca61_49be_45e5),
            (16, 0x3f2a_cc7f_57c2_9bdb),
            (63, 0x958a_324c_eb06_4572),
        ] {
            assert_eq!(siphash24_bytes(reference_key, &message[..length]), expected);
        }
        assert_eq!(
            siphash24(reference_key, [0x0706_0504_0302_0100]),
            0x93f5_f579_9a93_2462
        );
        assert_eq!(
            siphash24(
                reference_key,
                [0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908]
            ),
            0x3f2a_cc7f_57c2_9bdb
        );

        let candidate = packet(FirewallProtocol::Udp, 0);
        let words = canonical_flow_words(candidate, 1);
        let mut layout = [0_u8; 64];
        for (word, chunk) in words.iter().zip(layout.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        const EXPECTED_CANONICAL_HASH: u64 = 0x6040_22bd_edf7_0c4d;
        assert_eq!(
            siphash24_bytes(hash_key(), &layout),
            EXPECTED_CANONICAL_HASH
        );
        assert_eq!(flow_hash(candidate, 1, hash_key()), EXPECTED_CANONICAL_HASH);
    }

    #[test]
    fn exact_reverse_phase_rst_and_expiry_are_bounded_and_transactional() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Tcp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let initial = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x02), 0)
                .unwrap();
            assert!(runtime.states().iter().all(|slot| !slot.is_occupied()));
            runtime.commit(initial).unwrap();
            let mut reverse = packet(FirewallProtocol::Tcp, 0x12);
            reverse.ingress = WAN;
            reverse.egress = LAN;
            reverse.source = REMOTE;
            reverse.destination = INTERNAL;
            reverse.source_port = 443;
            reverse.destination_port = 12_345;
            let plan = runtime.plan_packet(&config, reverse, 1).unwrap();
            runtime.commit(plan).unwrap();
            let direct_ack = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x10), 2)
                .unwrap();
            runtime.commit(direct_ack).unwrap();
            assert_eq!(runtime.states()[0].tcp_phase(), FirewallTcpPhase::Active);
            let before_rst = runtime.states()[0].last_activity_ms();
            let rst = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x04), 3)
                .unwrap();
            runtime.commit(rst).unwrap();
            assert_eq!(runtime.states()[0].last_activity_ms(), before_rst);
            assert!(runtime
                .plan_packet(
                    &config,
                    reverse,
                    2 + FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS - 1
                )
                .is_ok());
            assert_eq!(
                runtime.plan_packet(
                    &config,
                    reverse,
                    2 + FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS
                ),
                Err(FirewallPlanError::DefaultDenied)
            );
        });
    }

    #[test]
    fn related_icmpv4_inspection_is_direct_exact_bounded_and_read_only() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                7,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 4];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let origin = packet(FirewallProtocol::Udp, 0);
            let plan = runtime.plan_packet(&config, origin, 10).unwrap();
            runtime.commit(plan).unwrap();
            let flow = FirewallRelatedIcmpv4Flow::new(
                origin.ingress,
                origin.egress,
                origin.source,
                origin.destination,
                origin.protocol,
                origin.source_port,
                origin.destination_port,
            );
            let before_states = runtime.states().to_vec();
            let before_counters = runtime.counters();

            assert_eq!(
                runtime.inspect_related_icmpv4(flow, 10),
                Ok(FirewallRuleId(7))
            );
            let wrong_remote_port = FirewallRelatedIcmpv4Flow::new(
                origin.ingress,
                origin.egress,
                origin.source,
                origin.destination,
                origin.protocol,
                origin.source_port,
                origin.destination_port + 1,
            );
            assert_eq!(
                runtime.inspect_related_icmpv4(wrong_remote_port, 10),
                Err(FirewallRelatedIcmpv4Error::StateMiss)
            );
            let reverse = FirewallRelatedIcmpv4Flow::new(
                origin.egress,
                origin.ingress,
                origin.destination,
                origin.source,
                origin.protocol,
                origin.destination_port,
                origin.source_port,
            );
            assert_eq!(
                runtime.inspect_related_icmpv4(reverse, 10),
                Err(FirewallRelatedIcmpv4Error::StateMiss)
            );
            let wrong_egress = FirewallRelatedIcmpv4Flow::new(
                origin.ingress,
                IfId(99),
                origin.source,
                origin.destination,
                origin.protocol,
                origin.source_port,
                origin.destination_port,
            );
            assert_eq!(
                runtime.inspect_related_icmpv4(wrong_egress, 10),
                Err(FirewallRelatedIcmpv4Error::StateMiss)
            );
            assert_eq!(
                runtime.inspect_related_icmpv4(flow, 9),
                Err(FirewallRelatedIcmpv4Error::ClockRegression)
            );
            assert_eq!(
                runtime.inspect_related_icmpv4(flow, 10 + FIREWALL_UDP_DEFAULT_IDLE_TTL_MS),
                Err(FirewallRelatedIcmpv4Error::StateMiss)
            );
            assert_eq!(runtime.states(), before_states);
            assert_eq!(runtime.counters(), before_counters);

            let config2 = FirewallConfig::new(
                snapshot,
                &rules,
                FirewallPolicy::default(),
                2,
                rotated_hash_key(),
            )
            .unwrap();
            assert_eq!(runtime.reconcile(config2).unwrap().states_flushed, 1);
            assert_eq!(
                runtime.inspect_related_icmpv4(flow, 10),
                Err(FirewallRelatedIcmpv4Error::StateMiss)
            );
        });
    }

    #[test]
    fn related_icmpv4_probe_crosses_expired_same_home_wrap_without_mutation() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                9,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut candidates = [packet(FirewallProtocol::Udp, 0); 4];
            let mut first_port = 1_u16;
            for candidate in &mut candidates {
                let mut trial = *candidate;
                let port = (first_port..=u16::MAX)
                    .find(|port| {
                        trial.source_port = *port;
                        flow_hash(trial, 1, hash_key()) as usize % 3 == 2
                    })
                    .expect("four UDP tuples hash to the wrapped home");
                candidate.source_port = port;
                first_port = port.saturating_add(1);
            }

            let mut slots = [FirewallStateSlot::default(); 3];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let first = runtime.plan_packet(&config, candidates[0], 0).unwrap();
            runtime.commit(first).unwrap();
            for candidate in &candidates[1..3] {
                let plan = runtime
                    .plan_packet(&config, *candidate, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS - 1)
                    .unwrap();
                runtime.commit(plan).unwrap();
            }
            assert_eq!(
                [
                    runtime.states()[2].initiator_port(),
                    runtime.states()[0].initiator_port(),
                    runtime.states()[1].initiator_port(),
                ],
                [
                    candidates[0].source_port,
                    candidates[1].source_port,
                    candidates[2].source_port,
                ]
            );

            let related = |candidate: FirewallPacket| {
                FirewallRelatedIcmpv4Flow::new(
                    candidate.ingress,
                    candidate.egress,
                    candidate.source,
                    candidate.destination,
                    candidate.protocol,
                    candidate.source_port,
                    candidate.destination_port,
                )
            };
            let before_states = runtime.states().to_vec();
            let before_counters = runtime.counters();
            assert_eq!(
                runtime.inspect_related_icmpv4(
                    related(candidates[1]),
                    FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,
                ),
                Ok(FirewallRuleId(9)),
                "the displaced direct hit remains reachable past an expired wrapped blocker"
            );
            assert_eq!(
                runtime.inspect_related_icmpv4(
                    related(candidates[3]),
                    FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,
                ),
                Err(FirewallRelatedIcmpv4Error::StateMiss),
                "a full same-home table terminates after one capacity-bounded probe"
            );
            assert_eq!(runtime.states(), before_states);
            assert_eq!(runtime.counters(), before_counters);
        });
    }

    #[test]
    fn zero_full_regression_and_reconcile_do_not_evict_live_state() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut no_slots = [];
            let mut runtime = FirewallRuntime::new(config, &mut no_slots);
            assert_eq!(
                runtime.plan_packet(&config, packet(FirewallProtocol::Udp, 0), 0),
                Err(FirewallPlanError::StateFull(FirewallRuleId(1)))
            );

            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let plan = runtime
                .plan_packet(&config, packet(FirewallProtocol::Udp, 0), 10)
                .unwrap();
            runtime.commit(plan).unwrap();
            let mut different = packet(FirewallProtocol::Udp, 0);
            different.source_port = 12_346;
            assert_eq!(
                runtime.plan_packet(&config, different, 10),
                Err(FirewallPlanError::StateFull(FirewallRuleId(1)))
            );
            assert!(runtime
                .plan_packet(&config, different, 10 + FIREWALL_UDP_DEFAULT_IDLE_TTL_MS)
                .is_ok());
            assert_eq!(
                runtime.plan_packet(&config, packet(FirewallProtocol::Udp, 0), 9),
                Err(FirewallPlanError::ClockRegression)
            );
            let same = runtime.reconcile(config).unwrap();
            assert_eq!(same.states_flushed, 0);
            let copied_rules = rules;
            let collision = FirewallConfig::new(
                snapshot,
                &copied_rules,
                FirewallPolicy::default(),
                1,
                hash_key(),
            )
            .unwrap();
            assert_eq!(
                runtime.reconcile(collision),
                Err(FirewallReconcileError::IdentityCollision)
            );
            let unrotated =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 2, hash_key())
                    .unwrap();
            assert_eq!(
                runtime.reconcile(unrotated),
                Err(FirewallReconcileError::HashKeyNotRotated)
            );
            let config2 = FirewallConfig::new(
                snapshot,
                &rules,
                FirewallPolicy::default(),
                2,
                rotated_hash_key(),
            )
            .unwrap();
            assert_eq!(runtime.reconcile(config2).unwrap().states_flushed, 0);
            assert!(runtime.states().iter().all(|slot| !slot.is_occupied()));
            assert_eq!(
                runtime.reconcile(config),
                Err(FirewallReconcileError::GenerationRegression)
            );
        });
    }

    #[test]
    fn reconcile_releases_old_and_current_rule_storage_lifetimes() {
        with_snapshot(|snapshot| {
            let old_rules = vec![rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let old_config = FirewallConfig::new(
                snapshot,
                &old_rules,
                FirewallPolicy::default(),
                1,
                hash_key(),
            )
            .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(old_config, &mut slots);
            let plan = runtime
                .plan_packet(&old_config, packet(FirewallProtocol::Udp, 0), 0)
                .unwrap();
            runtime.commit(plan).unwrap();

            let new_rules = vec![rule(2, FirewallAction::Deny, FirewallProtocol::Udp)];
            let new_config = FirewallConfig::new(
                snapshot,
                &new_rules,
                FirewallPolicy::default(),
                2,
                rotated_hash_key(),
            )
            .unwrap();
            assert_eq!(runtime.reconcile(new_config).unwrap().states_flushed, 1);
            assert!(!runtime.config_matches(&old_config));
            drop(old_rules);

            assert!(runtime.config_matches(&new_config));
            assert_eq!(
                runtime.plan_packet(&new_config, packet(FirewallProtocol::Udp, 0), 1),
                Err(FirewallPlanError::RuleDenied(FirewallRuleId(2)))
            );
            drop(new_rules);

            assert!(runtime.states().iter().all(|slot| !slot.is_occupied()));
            assert_eq!(runtime.counters().reconciliations, 1);
        });
    }

    #[test]
    fn keyed_symmetric_hash_reclaims_mixed_wrapped_clusters_without_live_eviction() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut first = packet(FirewallProtocol::Udp, 0);
            first.source_port = (1..=u16::MAX)
                .find(|port| {
                    first.source_port = *port;
                    flow_hash(first, 1, hash_key()) % 3 == 2
                })
                .unwrap();
            let mut second = first;
            second.source_port = (first.source_port + 1..=u16::MAX)
                .find(|port| {
                    second.source_port = *port;
                    flow_hash(second, 1, hash_key()) % 3 == 2
                })
                .unwrap();
            let mut third = second;
            third.source_port = (second.source_port + 1..=u16::MAX)
                .find(|port| {
                    third.source_port = *port;
                    flow_hash(third, 1, hash_key()) % 3 == 2
                })
                .unwrap();

            let mut slots = [FirewallStateSlot::default(); 3];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let first_plan = runtime.plan_packet(&config, first, 0).unwrap();
            runtime.commit(first_plan).unwrap();
            let second_plan = runtime.plan_packet(&config, second, 0).unwrap();
            runtime.commit(second_plan).unwrap();
            assert_eq!(runtime.states()[2].initiator_port(), first.source_port);
            assert_eq!(runtime.states()[0].initiator_port(), second.source_port);
            let rule_evaluations = runtime.counters().rule_evaluations;

            let mut reverse_second = second;
            reverse_second.ingress = WAN;
            reverse_second.egress = LAN;
            reverse_second.source = REMOTE;
            reverse_second.destination = INTERNAL;
            reverse_second.source_port = second.destination_port;
            reverse_second.destination_port = second.source_port;
            let refresh = runtime
                .plan_packet(
                    &config,
                    reverse_second,
                    FIREWALL_UDP_DEFAULT_IDLE_TTL_MS - 1,
                )
                .unwrap();
            runtime.commit(refresh).unwrap();
            assert_eq!(runtime.counters().rule_evaluations, rule_evaluations);
            let stale_before_movement = runtime
                .plan_packet(
                    &config,
                    reverse_second,
                    FIREWALL_UDP_DEFAULT_IDLE_TTL_MS - 1,
                )
                .unwrap();

            let replacement = runtime
                .plan_packet(&config, third, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS)
                .unwrap();
            assert_eq!(
                runtime.commit(stale_before_movement),
                Err(FirewallCommitError::RuntimeEpochChanged)
            );
            runtime.commit(replacement).unwrap();
            assert_eq!(runtime.states()[2].initiator_port(), second.source_port);
            assert_eq!(runtime.states()[0].initiator_port(), third.source_port);
            assert!(runtime
                .plan_packet(&config, reverse_second, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS)
                .is_ok());
            assert!(runtime.counters().state_probes >= 8);
        });
    }

    #[test]
    fn cleanup_budget_is_linear_for_n_and_two_n_capacity() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();

            let mut small_slots = [FirewallStateSlot::default(); 4];
            let mut small = FirewallRuntime::new(config, &mut small_slots);
            assert_eq!(small.usable_capacity(), 3);
            let mut distinct_homes = [packet(FirewallProtocol::Udp, 0); 4];
            for (home, candidate) in distinct_homes.iter_mut().enumerate() {
                let mut trial = *candidate;
                candidate.source_port = (1..=u16::MAX)
                    .find(|port| {
                        trial.source_port = *port;
                        flow_hash(trial, 1, hash_key()) as usize % 4 == home
                    })
                    .unwrap();
            }
            let plans =
                distinct_homes.map(|candidate| small.plan_packet(&config, candidate, 0).unwrap());
            for plan in &plans[..3] {
                small.commit(*plan).unwrap();
            }
            assert_eq!(
                small.commit(plans[3]),
                Err(FirewallCommitError::UsableCapacityExceeded)
            );
            assert_eq!(
                small
                    .states()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count(),
                small.usable_capacity()
            );

            for capacity in [32, 64] {
                let mut slots = vec![FirewallStateSlot::default(); capacity];
                let mut runtime = FirewallRuntime::new(config, &mut slots);
                let usable = runtime.usable_capacity();
                assert_eq!(usable, capacity * 3 / 4);
                let mut candidates = Vec::with_capacity(usable + 1);
                for port in 1..=u16::MAX {
                    let mut candidate = packet(FirewallProtocol::Udp, 0);
                    candidate.source_port = port;
                    if flow_hash(candidate, 1, hash_key()) as usize % capacity == capacity - 1 {
                        candidates.push(candidate);
                        if candidates.len() == usable + 1 {
                            break;
                        }
                    }
                }
                assert_eq!(candidates.len(), usable + 1);
                for candidate in &candidates[..usable] {
                    let plan = runtime.plan_packet(&config, *candidate, 0).unwrap();
                    runtime.commit(plan).unwrap();
                }
                assert_eq!(
                    runtime
                        .states()
                        .iter()
                        .filter(|slot| slot.is_occupied())
                        .count(),
                    usable
                );
                assert_eq!(
                    runtime.plan_packet(&config, candidates[usable], 0),
                    Err(FirewallPlanError::StateFull(FirewallRuleId(1)))
                );
                assert!(runtime
                    .states()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .all(|slot| candidates[..usable]
                        .iter()
                        .any(|candidate| candidate.source_port == slot.initiator_port())));

                let stale = runtime
                    .plan_packet(&config, candidates[0], FIREWALL_UDP_DEFAULT_IDLE_TTL_MS - 1)
                    .unwrap();
                for _ in 0..usable {
                    let before = runtime.counters();
                    let _uncommitted = runtime
                        .plan_packet(
                            &config,
                            candidates[usable],
                            FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,
                        )
                        .unwrap();
                    let after = runtime.counters();
                    let operations = (after.state_probes - before.state_probes)
                        + (after.maintenance_steps - before.maintenance_steps);
                    assert!(operations <= (capacity as u64) * 6 + 2);
                    assert!(after.maintenance_steps > before.maintenance_steps);
                }
                assert!(runtime.states().iter().all(|slot| !slot.is_occupied()));
                assert_eq!(runtime.counters().states_expired, usable as u64);
                assert_eq!(
                    runtime.commit(stale),
                    Err(FirewallCommitError::RuntimeEpochChanged)
                );

                let before = runtime.counters();
                assert!(runtime
                    .plan_packet(
                        &config,
                        candidates[usable],
                        FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,
                    )
                    .is_ok());
                let after = runtime.counters();
                assert_eq!(after.state_probes - before.state_probes, 1);
                assert_eq!(after.maintenance_steps - before.maintenance_steps, 0);
            }
        });
    }

    #[test]
    fn secret_changes_hash_and_rotation_flushes_state() {
        with_snapshot(|snapshot| {
            let first_key = hash_key();
            let second_key = rotated_hash_key();
            let candidate = packet(FirewallProtocol::Udp, 0);
            assert_ne!(
                flow_hash(candidate, 1, first_key),
                flow_hash(candidate, 1, second_key)
            );
            let mut reverse = candidate;
            reverse.ingress = candidate.egress;
            reverse.egress = candidate.ingress;
            reverse.source = candidate.destination;
            reverse.destination = candidate.source;
            reverse.source_port = candidate.destination_port;
            reverse.destination_port = candidate.source_port;
            assert_eq!(
                flow_hash(candidate, 1, first_key),
                flow_hash(reverse, 1, first_key)
            );

            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, first_key)
                    .unwrap();
            let unrotated =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 2, first_key)
                    .unwrap();
            let rotated =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 2, second_key)
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let plan = runtime.plan_packet(&config, candidate, 0).unwrap();
            runtime.commit(plan).unwrap();
            let survives_rejection = runtime.plan_packet(&config, candidate, 1).unwrap();
            assert_eq!(
                runtime.reconcile(unrotated),
                Err(FirewallReconcileError::HashKeyNotRotated)
            );
            runtime.commit(survives_rejection).unwrap();
            let stale_after_rotation = runtime.plan_packet(&config, candidate, 2).unwrap();
            assert_eq!(runtime.reconcile(rotated).unwrap().states_flushed, 1);
            assert_eq!(
                runtime.commit(stale_after_rotation),
                Err(FirewallCommitError::RuntimeEpochChanged)
            );
            assert!(!runtime.states()[0].is_occupied());
        });
    }

    #[test]
    fn stale_plans_fail_after_reconcile_and_slot_reuse_in_release_paths() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let config2 = FirewallConfig::new(
                snapshot,
                &rules,
                FirewallPolicy::default(),
                2,
                rotated_hash_key(),
            )
            .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let stale_epoch = runtime
                .plan_packet(&config, packet(FirewallProtocol::Udp, 0), 0)
                .unwrap();
            runtime.reconcile(config2).unwrap();
            assert_eq!(
                runtime.commit(stale_epoch),
                Err(FirewallCommitError::RuntimeEpochChanged)
            );
            assert!(!runtime.states()[0].is_occupied());

            let stale_slot = runtime
                .plan_packet(&config2, packet(FirewallProtocol::Udp, 0), 1)
                .unwrap();
            let mut winner = packet(FirewallProtocol::Udp, 0);
            winner.source_port += 1;
            let winner = runtime.plan_packet(&config2, winner, 1).unwrap();
            runtime.commit(winner).unwrap();
            assert_eq!(
                runtime.commit(stale_slot),
                Err(FirewallCommitError::SlotGenerationChanged)
            );
        });
    }

    #[test]
    fn stale_established_plan_is_rejected_after_same_slot_runtime_recreation() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let first_flow = packet(FirewallProtocol::Udp, 0);
            let stale = {
                let mut runtime = FirewallRuntime::new(config, &mut slots);
                let first = runtime.plan_packet(&config, first_flow, 0).unwrap();
                runtime.commit(first).unwrap();
                runtime.plan_packet(&config, first_flow, 0).unwrap()
            };

            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let mut replacement_flow = first_flow;
            replacement_flow.source_port += 1;
            let replacement = runtime.plan_packet(&config, replacement_flow, 0).unwrap();
            runtime.commit(replacement).unwrap();

            let result = runtime.commit(stale);
            assert!(
                result.is_err(),
                "same-slot runtime recreation accepted stale firewall plan: {result:?}"
            );
            assert_eq!(
                runtime.states()[0].initiator_port(),
                replacement_flow.source_port
            );
        });
    }

    #[test]
    fn stale_tcp_established_plan_cannot_roll_back_activity_or_phase() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Tcp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let initial = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x02), 0)
                .unwrap();
            runtime.commit(initial).unwrap();

            let mut reverse = packet(FirewallProtocol::Tcp, 0x12);
            reverse.ingress = WAN;
            reverse.egress = LAN;
            reverse.source = REMOTE;
            reverse.destination = INTERNAL;
            reverse.source_port = 443;
            reverse.destination_port = 12_345;
            let reverse_syn_ack = runtime.plan_packet(&config, reverse, 1).unwrap();
            runtime.commit(reverse_syn_ack).unwrap();

            let stale = runtime.plan_packet(&config, reverse, 2).unwrap();
            let direct_ack = runtime
                .plan_packet(&config, packet(FirewallProtocol::Tcp, 0x10), 3)
                .unwrap();
            runtime.commit(direct_ack).unwrap();
            assert_eq!(runtime.states()[0].tcp_phase(), FirewallTcpPhase::Active);
            assert_eq!(runtime.states()[0].last_activity_ms(), 3);

            let result = runtime.commit(stale);
            assert!(
                result.is_err(),
                "stale TCP established plan rolled back active state: {result:?}"
            );
            assert_eq!(runtime.states()[0].tcp_phase(), FirewallTcpPhase::Active);
            assert_eq!(runtime.states()[0].last_activity_ms(), 3);
        });
    }

    #[test]
    fn stale_udp_established_plan_cannot_roll_back_activity() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let flow = packet(FirewallProtocol::Udp, 0);
            let initial = runtime.plan_packet(&config, flow, 0).unwrap();
            runtime.commit(initial).unwrap();

            let stale = runtime.plan_packet(&config, flow, 2).unwrap();
            let fresh = runtime.plan_packet(&config, flow, 3).unwrap();
            runtime.commit(fresh).unwrap();
            assert_eq!(runtime.states()[0].last_activity_ms(), 3);

            let result = runtime.commit(stale);
            assert!(
                result.is_err(),
                "stale UDP established plan rolled back activity: {result:?}"
            );
            assert_eq!(runtime.states()[0].last_activity_ms(), 3);
        });
    }

    #[test]
    fn policy_bounds_are_protocol_and_phase_specific() {
        assert_eq!(
            FirewallPolicy::new(
                FIREWALL_UDP_MIN_IDLE_TTL_MS - 1,
                FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS,
                FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS,
            ),
            Err(FirewallPolicyError::UdpIdleTtlTooShort)
        );
        assert_eq!(
            FirewallPolicy::new(
                FIREWALL_UDP_MIN_IDLE_TTL_MS,
                FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS - 1,
                FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS,
            ),
            Err(FirewallPolicyError::TcpOpeningIdleTtlTooShort)
        );
        assert_eq!(
            FirewallPolicy::new(
                FIREWALL_UDP_MIN_IDLE_TTL_MS,
                FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS,
                FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS - 1,
            ),
            Err(FirewallPolicyError::TcpActiveIdleTtlTooShort)
        );
        assert_eq!(
            FirewallPolicy::default(),
            FirewallPolicy::new(
                FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,
                FIREWALL_TCP_OPENING_DEFAULT_IDLE_TTL_MS,
                FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS,
            )
            .unwrap()
        );
    }

    #[test]
    fn probe_distance_counts_forward_including_the_wrap() {
        // Robin-hood insertion compares how far each entry sits from its home
        // slot. Getting the wrapped case wrong makes a displaced entry look
        // closer to home than it is, and the table stops being searchable.
        assert_eq!(super::probe_distance(3, 5, 8), 2, "no wrap");
        assert_eq!(super::probe_distance(3, 3, 8), 0, "at home");
        assert_eq!(super::probe_distance(6, 1, 8), 3, "wrapped past the end");
        assert_eq!(super::probe_distance(7, 0, 8), 1, "wrapped by one");
        assert_eq!(super::probe_distance(1, 0, 8), 7, "the longest wrap");
    }

    #[test]
    fn an_empty_state_table_has_no_usable_capacity() {
        // Every other size reserves headroom; zero has nothing to reserve from
        // and must not underflow into a huge capacity.
        assert_eq!(super::usable_state_capacity(0), 0);
        assert_eq!(super::usable_state_capacity(1), 1);
        assert_eq!(super::usable_state_capacity(3), 3);
        assert_eq!(super::usable_state_capacity(4), 3);
        assert_eq!(super::usable_state_capacity(8), 6);
    }

    #[test]
    fn the_rules_fingerprint_distinguishes_every_field_it_covers() {
        // The fingerprint is what tells a successor publication that the rule
        // set changed. A field it does not cover is a rule change that could
        // be applied without anyone noticing.
        let base = [rule(
            1,
            FirewallAction::AllowStateful,
            FirewallProtocol::Tcp,
        )];
        let baseline = super::rules_fingerprint(&base);

        let same = [rule(
            1,
            FirewallAction::AllowStateful,
            FirewallProtocol::Tcp,
        )];
        assert_eq!(
            super::rules_fingerprint(&same),
            baseline,
            "an identical rule set must fingerprint identically"
        );

        for (label, rules) in [
            (
                "id",
                [rule(
                    2,
                    FirewallAction::AllowStateful,
                    FirewallProtocol::Tcp,
                )],
            ),
            (
                "action",
                [rule(1, FirewallAction::Deny, FirewallProtocol::Tcp)],
            ),
            (
                "protocol",
                [rule(
                    1,
                    FirewallAction::AllowStateful,
                    FirewallProtocol::Udp,
                )],
            ),
        ] {
            assert_ne!(
                super::rules_fingerprint(&rules),
                baseline,
                "a change of {label} must change the fingerprint"
            );
        }

        assert_ne!(
            super::rules_fingerprint(&[]),
            baseline,
            "an empty rule set must not fingerprint as a populated one"
        );
        assert_ne!(
            super::rules_fingerprint(&[
                rule(1, FirewallAction::AllowStateful, FirewallProtocol::Tcp),
                rule(2, FirewallAction::AllowStateful, FirewallProtocol::Tcp),
            ]),
            baseline,
            "an appended rule must change the fingerprint"
        );
    }

    #[test]
    fn the_rules_fingerprint_is_order_sensitive() {
        // Two rule sets with the same rules in a different order decide
        // different things, so they must not share a fingerprint.
        let ascending = [
            rule(1, FirewallAction::AllowStateful, FirewallProtocol::Tcp),
            rule(2, FirewallAction::Deny, FirewallProtocol::Udp),
        ];
        let descending = [
            rule(2, FirewallAction::Deny, FirewallProtocol::Udp),
            rule(1, FirewallAction::AllowStateful, FirewallProtocol::Tcp),
        ];
        assert_ne!(
            super::rules_fingerprint(&ascending),
            super::rules_fingerprint(&descending)
        );
    }

    #[test]
    fn related_inspection_finds_a_flow_that_collided_into_a_later_slot() {
        // The lookup walks forward from the flow's home slot. Several flows
        // share a home in a small table, so a flow that landed behind another
        // is only findable if the walk goes the right way — and going the
        // wrong way in a `usize` index also runs off the front of the table.
        with_snapshot(|snapshot| {
            let rules = [rule(
                7,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 4];
            let mut runtime = FirewallRuntime::new(config, &mut slots);

            // A colliding pair is searched for rather than hoped for: without
            // one the walk never takes a step and the direction it takes could
            // not be observed.
            let capacity = 4_usize;
            let home = |source_port: u16| {
                let mut origin = packet(FirewallProtocol::Udp, 0);
                origin.source_port = source_port;
                super::flow_hash(origin, 1, hash_key()) as usize % capacity
            };
            let first_port = 1_000_u16;
            let first_home = home(first_port);
            let second_port = (first_port + 1..first_port + 500)
                .find(|port| home(*port) == first_home)
                .expect("a colliding source port must exist in a four-slot table");

            let mut origins = Vec::new();
            for source_port in [first_port, second_port] {
                let mut origin = packet(FirewallProtocol::Udp, 0);
                origin.source_port = source_port;
                let plan = runtime
                    .plan_packet(&config, origin, 10)
                    .expect("each distinct flow must be admitted");
                runtime.commit(plan).expect("each plan must commit");
                origins.push(origin);
            }
            assert_eq!(
                runtime.states().iter().filter(|slot| slot.occupied).count(),
                2
            );
            assert_eq!(
                home(first_port),
                home(second_port),
                "the two flows must share a home slot"
            );

            for origin in origins {
                let flow = FirewallRelatedIcmpv4Flow::new(
                    origin.ingress,
                    origin.egress,
                    origin.source,
                    origin.destination,
                    origin.protocol,
                    origin.source_port,
                    origin.destination_port,
                );
                assert_eq!(
                    runtime.inspect_related_icmpv4(flow, 10),
                    Ok(FirewallRuleId(7)),
                    "a committed flow must be findable from its home slot, \
                     source_port={}",
                    origin.source_port
                );
            }
        });
    }

    #[test]
    fn an_ack_on_an_established_tcp_flow_refreshes_it_and_a_reset_does_not() {
        // Only a reset stops a packet from refreshing the flow it belongs to.
        // Treating every segment as a reset would freeze `last_activity_ms`,
        // so a busy connection would expire while it was still in use, and no
        // connection would ever reach the active phase.
        with_snapshot(|snapshot| {
            let rules = [rule(
                9,
                FirewallAction::AllowStateful,
                FirewallProtocol::Tcp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 4];
            let mut runtime = FirewallRuntime::new(config, &mut slots);

            // SYN opens the flow.
            let syn = packet(FirewallProtocol::Tcp, 0x02);
            let plan = runtime.plan_packet(&config, syn, 10).unwrap();
            runtime.commit(plan).unwrap();
            let opened = runtime
                .states()
                .iter()
                .find(|slot| slot.occupied)
                .copied()
                .unwrap();
            assert_eq!(opened.last_activity_ms(), 10);
            assert_eq!(opened.tcp_phase(), FirewallTcpPhase::Opening);

            // An ACK in the forward direction refreshes the flow.
            let forward_ack = packet(FirewallProtocol::Tcp, 0x10);
            let plan = runtime.plan_packet(&config, forward_ack, 20).unwrap();
            runtime.commit(plan).unwrap();
            let after_forward = runtime
                .states()
                .iter()
                .find(|slot| slot.occupied)
                .copied()
                .unwrap();
            assert_eq!(
                after_forward.last_activity_ms(),
                20,
                "an ordinary segment must refresh the flow"
            );

            // An ACK in the reverse direction completes the handshake.
            let mut reverse_ack = packet(FirewallProtocol::Tcp, 0x10);
            std::mem::swap(&mut reverse_ack.source, &mut reverse_ack.destination);
            std::mem::swap(
                &mut reverse_ack.source_port,
                &mut reverse_ack.destination_port,
            );
            std::mem::swap(&mut reverse_ack.ingress, &mut reverse_ack.egress);
            let plan = runtime.plan_packet(&config, reverse_ack, 30).unwrap();
            runtime.commit(plan).unwrap();
            let after_reverse = runtime
                .states()
                .iter()
                .find(|slot| slot.occupied)
                .copied()
                .unwrap();
            assert_eq!(after_reverse.last_activity_ms(), 30);
            assert_eq!(
                after_reverse.tcp_phase(),
                FirewallTcpPhase::Active,
                "both directions acknowledged makes the flow active"
            );

            // A reset is the one segment that does not refresh.
            let reset = packet(FirewallProtocol::Tcp, 0x04);
            let plan = runtime.plan_packet(&config, reset, 40).unwrap();
            runtime.commit(plan).unwrap();
            let after_reset = runtime
                .states()
                .iter()
                .find(|slot| slot.occupied)
                .copied()
                .unwrap();
            assert_eq!(
                after_reset.last_activity_ms(),
                30,
                "a reset must not extend the flow's life"
            );
        });
    }

    #[test]
    fn every_refusal_the_firewall_records_reaches_its_own_counter() {
        // These counters are how an operator sees why traffic is being
        // refused. A recorder that does nothing leaves a firewall that drops
        // silently, which is indistinguishable from one that is not dropping.
        with_snapshot(|snapshot| {
            let rules = [
                rule(1, FirewallAction::Deny, FirewallProtocol::Tcp),
                rule(2, FirewallAction::AllowStateful, FirewallProtocol::Udp),
            ];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1, hash_key())
                    .unwrap();
            let mut slots = [FirewallStateSlot::default(); 4];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            assert_eq!(runtime.counters(), FirewallCounters::default());

            runtime.record_config_mismatch();
            assert_eq!(
                runtime.counters().config_mismatches,
                1,
                "a configuration mismatch must be counted"
            );

            runtime.record_invalid_packet();
            assert_eq!(
                runtime.counters().invalid_packets,
                1,
                "a packet the firewall could not validate must be counted"
            );

            // A rule that denies, and the default deny, are separate reasons
            // and must not share a counter.
            let denied = packet(FirewallProtocol::Tcp, 0x02);
            let error = runtime
                .plan_packet(&config, denied, 10)
                .expect_err("the deny rule must refuse this packet");
            runtime.record_plan_error(error);
            assert_eq!(runtime.counters().denied_by_rule, 1);
            assert_eq!(runtime.counters().denied_default, 0);

            let mut unmatched = packet(FirewallProtocol::Udp, 0);
            unmatched.destination_port = 0;
            let error = runtime
                .plan_packet(&config, unmatched, 10)
                .expect_err("no rule matches this packet");
            runtime.record_plan_error(error);
            assert_eq!(runtime.counters().denied_default, 1);
            assert_eq!(
                runtime.counters().denied_by_rule,
                1,
                "the default deny must not be counted as a rule deny"
            );
        });
    }
}

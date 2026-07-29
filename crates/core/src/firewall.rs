use std::{marker::PhantomData, rc::Rc};

use crate::{ForwardingSnapshot, IfId, Ipv4Address};

pub const FIREWALL_UDP_MIN_IDLE_TTL_MS: u64 = 120_000;
pub const FIREWALL_UDP_DEFAULT_IDLE_TTL_MS: u64 = 300_000;
pub const FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS: u64 = 240_000;
pub const FIREWALL_TCP_OPENING_DEFAULT_IDLE_TTL_MS: u64 = 240_000;
pub const FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS: u64 = 7_440_000;
pub const FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS: u64 = 7_440_000;
pub const FIREWALL_MAX_IDLE_TTL_MS: u64 = 604_800_000;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallConfigError {
    GenerationZero,
    RuleIdZero,
    DuplicateRuleId,
    IngressInterfaceMissing,
    EgressInterfaceMissing,
}

impl<'a> FirewallConfig<'a> {
    pub fn new(
        snapshot: &ForwardingSnapshot<'_>,
        rules: &'a [FirewallRule],
        policy: FirewallPolicy,
        generation: u64,
        hash_key: FirewallHashKey,
    ) -> Result<Self, FirewallConfigError> {
        if generation == 0 {
            return Err(FirewallConfigError::GenerationZero);
        }
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
        Ok(Self {
            rules,
            policy,
            generation,
            hash_key,
            snapshot_authority: snapshot.authority(),
            snapshot_identity: snapshot.identity(),
            rules_identity: rules.as_ptr() as usize,
            rules_len: rules.len(),
            rules_fingerprint: rules_fingerprint(rules),
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

    pub(crate) fn authority_matches(self, snapshot: &ForwardingSnapshot<'_>) -> bool {
        self.snapshot_authority == snapshot.authority()
            && self.snapshot_identity == snapshot.identity()
    }

    pub(crate) fn identity_matches(self, other: FirewallConfig<'_>) -> bool {
        self.policy == other.policy
            && self.generation == other.generation
            && self.hash_key == other.hash_key
            && self.snapshot_authority == other.snapshot_authority
            && self.snapshot_identity == other.snapshot_identity
            && self.rules_identity == other.rules_identity
            && self.rules_len == other.rules_len
            && self.rules_fingerprint == other.rules_fingerprint
    }
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
    RelatedStateMiss,
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
    RuntimeEpochChanged,
    ConfigGenerationChanged,
    SlotOutOfBounds,
    SlotGenerationChanged,
    UsableCapacityExceeded,
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
}

/// Fixed-capacity, worker-local IPv4 flow state.
///
/// `ESTABLISHED` in this API means only an exact local tuple/interface state
/// hit. It is not a TCP sequence/window validation claim.
///
/// ```compile_fail
/// use ruster_core::FirewallRuntime;
/// fn assert_send<T: Send>() {}
/// assert_send::<FirewallRuntime<'static, 'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::FirewallRuntime;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<FirewallRuntime<'static, 'static>>();
/// ```
pub struct FirewallRuntime<'rules, 'state> {
    config: FirewallConfig<'rules>,
    states: &'state mut [FirewallStateSlot],
    watermark_ms: Option<u64>,
    runtime_epoch: u64,
    next_slot_generation: u64,
    occupied_count: usize,
    counters: FirewallCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'rules, 'state> FirewallRuntime<'rules, 'state> {
    pub fn new(config: FirewallConfig<'rules>, states: &'state mut [FirewallStateSlot]) -> Self {
        states.fill(FirewallStateSlot::default());
        Self {
            config,
            states,
            watermark_ms: None,
            runtime_epoch: 1,
            next_slot_generation: 1,
            occupied_count: 0,
            counters: FirewallCounters::default(),
            _worker_local: PhantomData,
        }
    }

    #[must_use]
    pub const fn config(&self) -> FirewallConfig<'rules> {
        self.config
    }

    #[must_use]
    pub const fn counters(&self) -> FirewallCounters {
        self.counters
    }

    #[must_use]
    pub fn states(&self) -> &[FirewallStateSlot] {
        self.states
    }

    #[must_use]
    pub const fn usable_capacity(&self) -> usize {
        usable_state_capacity(self.states.len())
    }

    pub fn reconcile(
        &mut self,
        config: FirewallConfig<'rules>,
    ) -> Result<FirewallReconcileReport, FirewallReconcileError> {
        if config.generation < self.config.generation {
            return Err(FirewallReconcileError::GenerationRegression);
        }
        if config.generation == self.config.generation {
            if config.identity_matches(self.config) {
                return Ok(FirewallReconcileReport { states_flushed: 0 });
            }
            return Err(FirewallReconcileError::IdentityCollision);
        }
        if config.hash_key == self.config.hash_key {
            return Err(FirewallReconcileError::HashKeyNotRotated);
        }
        let states_flushed = self.states.iter().filter(|slot| slot.occupied).count();
        self.states.fill(FirewallStateSlot::default());
        self.occupied_count = 0;
        self.config = config;
        self.runtime_epoch = self.runtime_epoch.wrapping_add(1).max(1);
        self.counters.reconciliations = self.counters.reconciliations.saturating_add(1);
        Ok(FirewallReconcileReport { states_flushed })
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
        packet: FirewallPacket,
        now_ms: u64,
    ) -> Result<FirewallPlan, FirewallPlanError> {
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
                expected_generation: current.slot_generation,
                expected_runtime_epoch: self.runtime_epoch,
                expected_config_generation: self.config.generation,
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
        for rule in self.config.rules.iter().copied() {
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
            expected_generation: current.slot_generation,
            expected_runtime_epoch: self.runtime_epoch,
            expected_config_generation: self.config.generation,
            replacement: FirewallStateSlot {
                occupied: true,
                slot_generation,
                config_generation: self.config.generation,
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
            flow_hash(packet, self.config.generation, self.config.hash_key) as usize % capacity;
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
        if self.runtime_epoch != plan.expected_runtime_epoch {
            return Err(FirewallCommitError::RuntimeEpochChanged);
        }
        if self.config.generation != plan.expected_config_generation {
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
            flow_hash(packet, self.config.generation, self.config.hash_key) as usize % capacity;
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
                self.config.generation,
                self.config.hash_key,
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
            || slot.config_generation != self.config.generation
            || now_ms < slot.last_activity_ms
        {
            return false;
        }
        let ttl = match (slot.protocol, slot.tcp_phase) {
            (FirewallProtocol::Udp, _) => self.config.policy.udp_idle_ttl_ms,
            (FirewallProtocol::Tcp, FirewallTcpPhase::Opening) => {
                self.config.policy.tcp_opening_idle_ttl_ms
            }
            (FirewallProtocol::Tcp, FirewallTcpPhase::Active) => {
                self.config.policy.tcp_active_idle_ttl_ms
            }
        };
        now_ms - slot.last_activity_ms < ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, LocalIpv4Binding, MacAddress, Neighbor, Route};

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
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
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
                runtime.plan_packet(packet(FirewallProtocol::Udp, 0), 0),
                Err(FirewallPlanError::RuleDenied(FirewallRuleId(1)))
            );
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
                .plan_packet(packet(FirewallProtocol::Tcp, 0x02), 0)
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
            let plan = runtime.plan_packet(reverse, 1).unwrap();
            runtime.commit(plan).unwrap();
            let direct_ack = runtime
                .plan_packet(packet(FirewallProtocol::Tcp, 0x10), 2)
                .unwrap();
            runtime.commit(direct_ack).unwrap();
            assert_eq!(runtime.states()[0].tcp_phase(), FirewallTcpPhase::Active);
            let before_rst = runtime.states()[0].last_activity_ms();
            let rst = runtime
                .plan_packet(packet(FirewallProtocol::Tcp, 0x04), 3)
                .unwrap();
            runtime.commit(rst).unwrap();
            assert_eq!(runtime.states()[0].last_activity_ms(), before_rst);
            assert!(runtime
                .plan_packet(reverse, 2 + FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS - 1)
                .is_ok());
            assert_eq!(
                runtime.plan_packet(reverse, 2 + FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS),
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
            let plan = runtime.plan_packet(origin, 10).unwrap();
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
                runtime.plan_packet(packet(FirewallProtocol::Udp, 0), 0),
                Err(FirewallPlanError::StateFull(FirewallRuleId(1)))
            );

            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let plan = runtime
                .plan_packet(packet(FirewallProtocol::Udp, 0), 10)
                .unwrap();
            runtime.commit(plan).unwrap();
            let mut different = packet(FirewallProtocol::Udp, 0);
            different.source_port = 12_346;
            assert_eq!(
                runtime.plan_packet(different, 10),
                Err(FirewallPlanError::StateFull(FirewallRuleId(1)))
            );
            assert!(runtime
                .plan_packet(different, 10 + FIREWALL_UDP_DEFAULT_IDLE_TTL_MS)
                .is_ok());
            assert_eq!(
                runtime.plan_packet(packet(FirewallProtocol::Udp, 0), 9),
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
            let first_plan = runtime.plan_packet(first, 0).unwrap();
            runtime.commit(first_plan).unwrap();
            let second_plan = runtime.plan_packet(second, 0).unwrap();
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
                .plan_packet(reverse_second, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS - 1)
                .unwrap();
            runtime.commit(refresh).unwrap();
            assert_eq!(runtime.counters().rule_evaluations, rule_evaluations);
            let stale_before_movement = runtime
                .plan_packet(reverse_second, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS - 1)
                .unwrap();

            let replacement = runtime
                .plan_packet(third, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS)
                .unwrap();
            assert_eq!(
                runtime.commit(stale_before_movement),
                Err(FirewallCommitError::RuntimeEpochChanged)
            );
            runtime.commit(replacement).unwrap();
            assert_eq!(runtime.states()[2].initiator_port(), second.source_port);
            assert_eq!(runtime.states()[0].initiator_port(), third.source_port);
            assert!(runtime
                .plan_packet(reverse_second, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS)
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
            let plans = distinct_homes.map(|candidate| small.plan_packet(candidate, 0).unwrap());
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
                    let plan = runtime.plan_packet(*candidate, 0).unwrap();
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
                    runtime.plan_packet(candidates[usable], 0),
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
                    .plan_packet(candidates[0], FIREWALL_UDP_DEFAULT_IDLE_TTL_MS - 1)
                    .unwrap();
                for _ in 0..usable {
                    let before = runtime.counters();
                    let _uncommitted = runtime
                        .plan_packet(candidates[usable], FIREWALL_UDP_DEFAULT_IDLE_TTL_MS)
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
                    .plan_packet(candidates[usable], FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,)
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
            let plan = runtime.plan_packet(candidate, 0).unwrap();
            runtime.commit(plan).unwrap();
            let survives_rejection = runtime.plan_packet(candidate, 1).unwrap();
            assert_eq!(
                runtime.reconcile(unrotated),
                Err(FirewallReconcileError::HashKeyNotRotated)
            );
            runtime.commit(survives_rejection).unwrap();
            let stale_after_rotation = runtime.plan_packet(candidate, 2).unwrap();
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
                .plan_packet(packet(FirewallProtocol::Udp, 0), 0)
                .unwrap();
            runtime.reconcile(config2).unwrap();
            assert_eq!(
                runtime.commit(stale_epoch),
                Err(FirewallCommitError::RuntimeEpochChanged)
            );
            assert!(!runtime.states()[0].is_occupied());

            let stale_slot = runtime
                .plan_packet(packet(FirewallProtocol::Udp, 0), 1)
                .unwrap();
            let mut winner = packet(FirewallProtocol::Udp, 0);
            winner.source_port += 1;
            let winner = runtime.plan_packet(winner, 1).unwrap();
            runtime.commit(winner).unwrap();
            assert_eq!(
                runtime.commit(stale_slot),
                Err(FirewallCommitError::SlotGenerationChanged)
            );
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
}

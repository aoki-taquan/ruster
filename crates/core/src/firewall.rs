use std::{marker::PhantomData, rc::Rc};

use crate::{nat44::snapshot_authority, ForwardingSnapshot, IfId, Ipv4Address};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallConfig<'a> {
    rules: &'a [FirewallRule],
    policy: FirewallPolicy,
    generation: u64,
    snapshot_authority: u64,
    snapshot_identity: [usize; 8],
    rules_identity: usize,
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
            snapshot_authority: snapshot_authority(snapshot),
            snapshot_identity: [
                snapshot.routes.as_ptr() as usize,
                snapshot.routes.len(),
                snapshot.interfaces.as_ptr() as usize,
                snapshot.interfaces.len(),
                snapshot.neighbors.as_ptr() as usize,
                snapshot.neighbors.len(),
                snapshot.local_ipv4.as_ptr() as usize,
                snapshot.local_ipv4.len(),
            ],
            rules_identity: rules.as_ptr() as usize,
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

    pub(crate) fn authority_matches(self, snapshot: &ForwardingSnapshot<'_>) -> bool {
        self.snapshot_authority == snapshot_authority(snapshot)
            && self.snapshot_identity
                == [
                    snapshot.routes.as_ptr() as usize,
                    snapshot.routes.len(),
                    snapshot.interfaces.as_ptr() as usize,
                    snapshot.interfaces.len(),
                    snapshot.neighbors.as_ptr() as usize,
                    snapshot.neighbors.len(),
                    snapshot.local_ipv4.as_ptr() as usize,
                    snapshot.local_ipv4.len(),
                ]
    }

    pub(crate) fn identity_matches(self, other: FirewallConfig<'_>) -> bool {
        self.policy == other.policy
            && self.generation == other.generation
            && self.snapshot_authority == other.snapshot_authority
            && self.snapshot_identity == other.snapshot_identity
            && self.rules_identity == other.rules_identity
            && self.rules == other.rules
    }
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FirewallPlanError {
    RuleDenied(FirewallRuleId),
    DefaultDenied,
    InvalidInitialTcp,
    StateFull,
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
    replacement: FirewallStateSlot,
    created: bool,
    expired: bool,
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
    next_slot_generation: u64,
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
            next_slot_generation: 1,
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

    pub fn reconcile(
        &mut self,
        config: FirewallConfig<'rules>,
    ) -> Result<FirewallReconcileReport, FirewallReconcileError> {
        if config.generation < self.config.generation {
            return Err(FirewallReconcileError::GenerationRegression);
        }
        if config.generation == self.config.generation {
            if config == self.config {
                return Ok(FirewallReconcileReport { states_flushed: 0 });
            }
            return Err(FirewallReconcileError::IdentityCollision);
        }
        let states_flushed = self.states.iter().filter(|slot| slot.occupied).count();
        self.states.fill(FirewallStateSlot::default());
        self.config = config;
        self.watermark_ms = None;
        self.next_slot_generation = 1;
        self.counters.reconciliations = self.counters.reconciliations.saturating_add(1);
        Ok(FirewallReconcileReport { states_flushed })
    }

    pub(crate) fn record_config_mismatch(&mut self) {
        self.counters.config_mismatches = self.counters.config_mismatches.saturating_add(1);
    }

    pub(crate) fn record_invalid_packet(&mut self) {
        self.counters.invalid_packets = self.counters.invalid_packets.saturating_add(1);
    }

    pub(crate) fn record_plan_error(&mut self, error: FirewallPlanError) {
        match error {
            FirewallPlanError::RuleDenied(_) => {
                self.counters.denied_by_rule = self.counters.denied_by_rule.saturating_add(1);
            }
            FirewallPlanError::DefaultDenied => {
                self.counters.denied_default = self.counters.denied_default.saturating_add(1);
            }
            FirewallPlanError::InvalidInitialTcp => {
                self.counters.invalid_packets = self.counters.invalid_packets.saturating_add(1);
            }
            FirewallPlanError::StateFull => {
                self.counters.state_full = self.counters.state_full.saturating_add(1);
            }
            FirewallPlanError::ClockRegression => {
                self.counters.clock_regressions = self.counters.clock_regressions.saturating_add(1);
            }
        }
    }

    pub(crate) fn plan_packet(
        &self,
        packet: FirewallPacket,
        now_ms: u64,
    ) -> Result<FirewallPlan, FirewallPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            return Err(FirewallPlanError::ClockRegression);
        }
        if let Some((index, reverse)) = self.find_live(packet, now_ms) {
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
                replacement,
                created: false,
                expired: false,
            });
        }

        let matched = self
            .config
            .rules
            .iter()
            .copied()
            .find(|rule| rule.matches(packet));
        match matched {
            Some(rule) if rule.action == FirewallAction::Deny => {
                return Err(FirewallPlanError::RuleDenied(rule.id));
            }
            None => return Err(FirewallPlanError::DefaultDenied),
            Some(_) => {}
        }
        if packet.protocol == FirewallProtocol::Tcp && packet.tcp_flags & 0x17 != 0x02 {
            return Err(FirewallPlanError::InvalidInitialTcp);
        }
        let (index, expired) = self
            .states
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                if !slot.occupied {
                    Some((index, false))
                } else if !self.slot_live(*slot, now_ms) {
                    Some((index, true))
                } else {
                    None
                }
            })
            .ok_or(FirewallPlanError::StateFull)?;
        let current = self.states[index];
        let slot_generation = self.next_slot_generation.max(1);
        Ok(FirewallPlan {
            index,
            expected_generation: current.slot_generation,
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
            },
            created: true,
            expired,
        })
    }

    pub(crate) fn commit(&mut self, plan: FirewallPlan, now_ms: u64) {
        debug_assert_eq!(
            self.states[plan.index].slot_generation,
            plan.expected_generation
        );
        self.states[plan.index] = plan.replacement;
        self.watermark_ms = Some(self.watermark_ms.map_or(now_ms, |old| old.max(now_ms)));
        if plan.created {
            self.next_slot_generation = plan.replacement.slot_generation.wrapping_add(1).max(1);
            self.counters.allowed_new = self.counters.allowed_new.saturating_add(1);
            if plan.expired {
                self.counters.states_expired = self.counters.states_expired.saturating_add(1);
            }
        } else {
            self.counters.allowed_established = self.counters.allowed_established.saturating_add(1);
        }
    }

    fn find_live(&self, packet: FirewallPacket, now_ms: u64) -> Option<(usize, bool)> {
        self.states.iter().enumerate().find_map(|(index, slot)| {
            if !self.slot_live(*slot, now_ms) || slot.protocol != packet.protocol {
                return None;
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
            if direct {
                Some((index, false))
            } else if reverse {
                Some((index, true))
            } else {
                None
            }
        })
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
                FirewallConfig::new(snapshot, &duplicate, FirewallPolicy::default(), 1),
                Err(FirewallConfigError::DuplicateRuleId)
            );
            assert_eq!(
                FirewallConfig::new(snapshot, &duplicate[..1], FirewallPolicy::default(), 0),
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
                FirewallConfig::new(snapshot, &unknown, FirewallPolicy::default(), 1),
                Err(FirewallConfigError::IngressInterfaceMissing)
            );
            let rules = [
                rule(1, FirewallAction::Deny, FirewallProtocol::Udp),
                rule(2, FirewallAction::AllowStateful, FirewallProtocol::Udp),
            ];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let runtime = FirewallRuntime::new(config, &mut slots);
            assert_eq!(
                runtime.plan_packet(packet(FirewallProtocol::Udp, 0), 0),
                Err(FirewallPlanError::RuleDenied(FirewallRuleId(1)))
            );
        });
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
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let initial = runtime
                .plan_packet(packet(FirewallProtocol::Tcp, 0x02), 0)
                .unwrap();
            assert!(runtime.states().iter().all(|slot| !slot.is_occupied()));
            runtime.commit(initial, 0);
            let mut reverse = packet(FirewallProtocol::Tcp, 0x12);
            reverse.ingress = WAN;
            reverse.egress = LAN;
            reverse.source = REMOTE;
            reverse.destination = INTERNAL;
            reverse.source_port = 443;
            reverse.destination_port = 12_345;
            let plan = runtime.plan_packet(reverse, 1).unwrap();
            runtime.commit(plan, 1);
            let direct_ack = runtime
                .plan_packet(packet(FirewallProtocol::Tcp, 0x10), 2)
                .unwrap();
            runtime.commit(direct_ack, 2);
            assert_eq!(runtime.states()[0].tcp_phase(), FirewallTcpPhase::Active);
            let before_rst = runtime.states()[0].last_activity_ms();
            let rst = runtime
                .plan_packet(packet(FirewallProtocol::Tcp, 0x04), 3)
                .unwrap();
            runtime.commit(rst, 3);
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
    fn zero_full_regression_and_reconcile_do_not_evict_live_state() {
        with_snapshot(|snapshot| {
            let rules = [rule(
                1,
                FirewallAction::AllowStateful,
                FirewallProtocol::Udp,
            )];
            let config =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
            let mut no_slots = [];
            let runtime = FirewallRuntime::new(config, &mut no_slots);
            assert_eq!(
                runtime.plan_packet(packet(FirewallProtocol::Udp, 0), 0),
                Err(FirewallPlanError::StateFull)
            );

            let mut slots = [FirewallStateSlot::default(); 1];
            let mut runtime = FirewallRuntime::new(config, &mut slots);
            let plan = runtime
                .plan_packet(packet(FirewallProtocol::Udp, 0), 10)
                .unwrap();
            runtime.commit(plan, 10);
            let mut different = packet(FirewallProtocol::Udp, 0);
            different.source_port = 12_346;
            assert_eq!(
                runtime.plan_packet(different, 10),
                Err(FirewallPlanError::StateFull)
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
            let collision =
                FirewallConfig::new(snapshot, &copied_rules, FirewallPolicy::default(), 1).unwrap();
            assert_eq!(
                runtime.reconcile(collision),
                Err(FirewallReconcileError::IdentityCollision)
            );
            let config2 =
                FirewallConfig::new(snapshot, &rules, FirewallPolicy::default(), 2).unwrap();
            assert_eq!(runtime.reconcile(config2).unwrap().states_flushed, 1);
            assert!(runtime.states().iter().all(|slot| !slot.is_occupied()));
            assert_eq!(
                runtime.reconcile(config),
                Err(FirewallReconcileError::GenerationRegression)
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

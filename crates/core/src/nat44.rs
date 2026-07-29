use std::{marker::PhantomData, rc::Rc};

use crate::{route, ForwardingSnapshot, IfId, Ipv4Address};

pub const NAT44_UDP_MIN_IDLE_TTL_MS: u64 = 120_000;
pub const NAT44_UDP_DEFAULT_IDLE_TTL_MS: u64 = 300_000;
pub const NAT44_UDP_MAX_IDLE_TTL_MS: u64 = 86_400_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpPolicy {
    idle_ttl_ms: u64,
    allocator_seed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpPolicyError {
    IdleTtlTooShort,
    IdleTtlTooLong,
}

impl Nat44UdpPolicy {
    pub const fn new(idle_ttl_ms: u64, allocator_seed: u64) -> Result<Self, Nat44UdpPolicyError> {
        if idle_ttl_ms < NAT44_UDP_MIN_IDLE_TTL_MS {
            return Err(Nat44UdpPolicyError::IdleTtlTooShort);
        }
        if idle_ttl_ms > NAT44_UDP_MAX_IDLE_TTL_MS {
            return Err(Nat44UdpPolicyError::IdleTtlTooLong);
        }
        Ok(Self {
            idle_ttl_ms,
            allocator_seed,
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
}

impl Default for Nat44UdpPolicy {
    fn default() -> Self {
        Self {
            idle_ttl_ms: NAT44_UDP_DEFAULT_IDLE_TTL_MS,
            allocator_seed: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpConfig {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44UdpPolicy,
    authority: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpConfigError {
    InterfacesEqual,
    InsideInterfaceMissing,
    OutsideInterfaceMissing,
    PublicAddressNotHostUnicast,
    PublicBindingMissing,
    PublicBindingWrongInterface,
    PortPoolIncludesZero,
    PortPoolReversed,
}

impl Nat44UdpConfig {
    pub fn new(
        snapshot: &ForwardingSnapshot<'_>,
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        first_port: u16,
        last_port: u16,
        policy: Nat44UdpPolicy,
    ) -> Result<Self, Nat44UdpConfigError> {
        if inside == outside {
            return Err(Nat44UdpConfigError::InterfacesEqual);
        }
        if !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.id == inside)
        {
            return Err(Nat44UdpConfigError::InsideInterfaceMissing);
        }
        if !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.id == outside)
        {
            return Err(Nat44UdpConfigError::OutsideInterfaceMissing);
        }
        if !address_is_host_unicast(snapshot, public_address) {
            return Err(Nat44UdpConfigError::PublicAddressNotHostUnicast);
        }
        let Some(binding) = snapshot
            .local_ipv4
            .iter()
            .find(|binding| binding.address == public_address)
        else {
            return Err(Nat44UdpConfigError::PublicBindingMissing);
        };
        if binding.interface != outside {
            return Err(Nat44UdpConfigError::PublicBindingWrongInterface);
        }
        if first_port == 0 {
            return Err(Nat44UdpConfigError::PortPoolIncludesZero);
        }
        if first_port > last_port {
            return Err(Nat44UdpConfigError::PortPoolReversed);
        }
        Ok(Self {
            inside,
            outside,
            public_address,
            first_port,
            last_port,
            policy,
            authority: snapshot_authority(snapshot),
        })
    }

    #[must_use]
    pub const fn inside(self) -> IfId {
        self.inside
    }

    #[must_use]
    pub const fn outside(self) -> IfId {
        self.outside
    }

    #[must_use]
    pub const fn public_address(self) -> Ipv4Address {
        self.public_address
    }

    #[must_use]
    pub const fn first_port(self) -> u16 {
        self.first_port
    }

    #[must_use]
    pub const fn last_port(self) -> u16 {
        self.last_port
    }

    #[must_use]
    pub const fn policy(self) -> Nat44UdpPolicy {
        self.policy
    }

    pub(crate) fn authority_matches(self, snapshot: &ForwardingSnapshot<'_>) -> bool {
        self.authority == snapshot_authority(snapshot)
            && snapshot.local_ipv4.iter().any(|binding| {
                binding.interface == self.outside && binding.address == self.public_address
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpMappingSlot {
    occupied: bool,
    generation: u64,
    inside: IfId,
    internal_address: Ipv4Address,
    internal_port: u16,
    public_port: u16,
    last_outbound_ms: u64,
}

impl Default for Nat44UdpMappingSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            generation: 0,
            inside: IfId(0),
            internal_address: Ipv4Address::from_octets([0; 4]),
            internal_port: 0,
            public_port: 0,
            last_outbound_ms: 0,
        }
    }
}

impl Nat44UdpMappingSlot {
    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn internal_address(self) -> Ipv4Address {
        self.internal_address
    }

    #[must_use]
    pub const fn internal_port(self) -> u16 {
        self.internal_port
    }

    #[must_use]
    pub const fn public_port(self) -> u16 {
        self.public_port
    }

    #[must_use]
    pub const fn last_outbound_ms(self) -> u64 {
        self.last_outbound_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpPeerSlot {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    remote_address: Ipv4Address,
}

impl Default for Nat44UdpPeerSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            mapping_index: 0,
            mapping_generation: 0,
            remote_address: Ipv4Address::from_octets([0; 4]),
        }
    }
}

impl Nat44UdpPeerSlot {
    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn remote_address(self) -> Ipv4Address {
        self.remote_address
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44UdpCounters {
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
    pub port_exhausted: u64,
    pub clock_regressions: u64,
    pub config_mismatches: u64,
    pub reconciliations: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpDisposition {
    OutboundTranslated {
        public_port: u16,
        mapping_created: bool,
        peer_created: bool,
    },
    InboundTranslated {
        internal_address: Ipv4Address,
        internal_port: u16,
    },
    MappingMiss,
    FilterDenied,
    MappingFull,
    PeerFull,
    PortExhausted,
    ClockRegression,
    ConfigMismatch,
    Rejected {
        reason: crate::DropReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpReconcileReport {
    pub mappings_flushed: usize,
    pub peers_flushed: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct Nat44UdpOutboundPlan {
    mapping_index: usize,
    mapping: Nat44UdpMappingSlot,
    peer_index: Option<usize>,
    peer: Option<Nat44UdpPeerSlot>,
    mapping_created: bool,
    mapping_expired: bool,
    peer_created: bool,
}

impl Nat44UdpOutboundPlan {
    pub(crate) const fn public_port(self) -> u16 {
        self.mapping.public_port
    }

    pub(crate) const fn disposition(self) -> Nat44UdpDisposition {
        Nat44UdpDisposition::OutboundTranslated {
            public_port: self.mapping.public_port,
            mapping_created: self.mapping_created,
            peer_created: self.peer_created,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Nat44UdpInboundPlan {
    mapping_index: usize,
    mapping_generation: u64,
    internal_address: Ipv4Address,
    internal_port: u16,
}

impl Nat44UdpInboundPlan {
    pub(crate) const fn internal_address(self) -> Ipv4Address {
        self.internal_address
    }

    pub(crate) const fn internal_port(self) -> u16 {
        self.internal_port
    }

    pub(crate) const fn disposition(self) -> Nat44UdpDisposition {
        Nat44UdpDisposition::InboundTranslated {
            internal_address: self.internal_address,
            internal_port: self.internal_port,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Nat44UdpPlanError {
    MappingMiss,
    FilterDenied,
    MappingFull,
    PeerFull,
    PortExhausted,
    ClockRegression,
}

/// Fixed-capacity, worker-local UDP NAPT state.
///
/// The caller owns both storage arrays. Recreating the runtime deliberately
/// clears them. The `Rc` marker makes the runtime `!Send + !Sync`, so a mapping
/// shard cannot accidentally migrate between packet workers.
///
/// ```compile_fail
/// use ruster_core::Nat44UdpRuntime;
/// fn assert_send<T: Send>() {}
/// assert_send::<Nat44UdpRuntime<'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::Nat44UdpRuntime;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<Nat44UdpRuntime<'static>>();
/// ```
pub struct Nat44UdpRuntime<'a> {
    config: Nat44UdpConfig,
    mappings: &'a mut [Nat44UdpMappingSlot],
    peers: &'a mut [Nat44UdpPeerSlot],
    watermark_ms: Option<u64>,
    next_generation: u64,
    counters: Nat44UdpCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> Nat44UdpRuntime<'a> {
    pub fn new(
        config: Nat44UdpConfig,
        mappings: &'a mut [Nat44UdpMappingSlot],
        peers: &'a mut [Nat44UdpPeerSlot],
    ) -> Self {
        mappings.fill(Nat44UdpMappingSlot::default());
        peers.fill(Nat44UdpPeerSlot::default());
        Self {
            config,
            mappings,
            peers,
            watermark_ms: None,
            next_generation: 1,
            counters: Nat44UdpCounters::default(),
            _worker_local: PhantomData,
        }
    }

    #[must_use]
    pub const fn config(&self) -> Nat44UdpConfig {
        self.config
    }

    #[must_use]
    pub const fn counters(&self) -> Nat44UdpCounters {
        self.counters
    }

    #[must_use]
    pub fn mappings(&self) -> &[Nat44UdpMappingSlot] {
        self.mappings
    }

    #[must_use]
    pub fn peers(&self) -> &[Nat44UdpPeerSlot] {
        self.peers
    }

    pub fn reconcile(&mut self, config: Nat44UdpConfig) -> Nat44UdpReconcileReport {
        let mappings_flushed = self
            .mappings
            .iter()
            .filter(|mapping| mapping.occupied)
            .count();
        let peers_flushed = self.peers.iter().filter(|peer| peer.occupied).count();
        self.mappings.fill(Nat44UdpMappingSlot::default());
        self.peers.fill(Nat44UdpPeerSlot::default());
        self.config = config;
        self.watermark_ms = None;
        self.next_generation = 1;
        self.counters.reconciliations = self.counters.reconciliations.saturating_add(1);
        Nat44UdpReconcileReport {
            mappings_flushed,
            peers_flushed,
        }
    }

    pub(crate) fn record_config_mismatch(&mut self) {
        self.counters.config_mismatches = self.counters.config_mismatches.saturating_add(1);
    }

    pub(crate) fn plan_outbound(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        self.check_clock(now_ms)?;
        if let Some((mapping_index, mapping)) =
            self.find_mapping(internal_address, internal_port, now_ms)
        {
            if self.peer_exists(mapping_index, mapping.generation, remote_address) {
                let mut refreshed = mapping;
                refreshed.last_outbound_ms = now_ms;
                return Ok(Nat44UdpOutboundPlan {
                    mapping_index,
                    mapping: refreshed,
                    peer_index: None,
                    peer: None,
                    mapping_created: false,
                    mapping_expired: false,
                    peer_created: false,
                });
            }
            let Some(peer_index) = self.find_reusable_peer(now_ms) else {
                return Err(Nat44UdpPlanError::PeerFull);
            };
            let mut refreshed = mapping;
            refreshed.last_outbound_ms = now_ms;
            return Ok(Nat44UdpOutboundPlan {
                mapping_index,
                mapping: refreshed,
                peer_index: Some(peer_index),
                peer: Some(Nat44UdpPeerSlot {
                    occupied: true,
                    mapping_index,
                    mapping_generation: mapping.generation,
                    remote_address,
                }),
                mapping_created: false,
                mapping_expired: false,
                peer_created: true,
            });
        }

        let Some(mapping_index) = self.find_reusable_mapping(now_ms) else {
            return Err(Nat44UdpPlanError::MappingFull);
        };
        let Some(peer_index) = self.find_reusable_peer(now_ms) else {
            return Err(Nat44UdpPlanError::PeerFull);
        };
        let Some(public_port) = self.allocate_port(internal_address, internal_port, now_ms) else {
            return Err(Nat44UdpPlanError::PortExhausted);
        };
        let generation = self.next_nonzero_generation();
        let mapping_expired = self.mappings[mapping_index].occupied;
        Ok(Nat44UdpOutboundPlan {
            mapping_index,
            mapping: Nat44UdpMappingSlot {
                occupied: true,
                generation,
                inside: self.config.inside,
                internal_address,
                internal_port,
                public_port,
                last_outbound_ms: now_ms,
            },
            peer_index: Some(peer_index),
            peer: Some(Nat44UdpPeerSlot {
                occupied: true,
                mapping_index,
                mapping_generation: generation,
                remote_address,
            }),
            mapping_created: true,
            mapping_expired,
            peer_created: true,
        })
    }

    pub(crate) fn commit_outbound(&mut self, plan: Nat44UdpOutboundPlan, now_ms: u64) {
        if plan.mapping_created {
            for peer in self
                .peers
                .iter_mut()
                .filter(|peer| peer.occupied && peer.mapping_index == plan.mapping_index)
            {
                *peer = Nat44UdpPeerSlot::default();
            }
        }
        self.mappings[plan.mapping_index] = plan.mapping;
        if let (Some(index), Some(peer)) = (plan.peer_index, plan.peer) {
            self.peers[index] = peer;
        }
        self.watermark_ms = Some(now_ms);
        if plan.mapping_created {
            self.counters.mappings_created = self.counters.mappings_created.saturating_add(1);
            if plan.mapping_expired {
                self.counters.mappings_expired = self.counters.mappings_expired.saturating_add(1);
            }
            self.next_generation = plan.mapping.generation.wrapping_add(1).max(1);
        } else {
            self.counters.mappings_reused = self.counters.mappings_reused.saturating_add(1);
        }
        if plan.peer_created {
            self.counters.peers_created = self.counters.peers_created.saturating_add(1);
        }
        self.counters.outbound_translated = self.counters.outbound_translated.saturating_add(1);
    }

    pub(crate) fn plan_inbound(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        self.check_clock(now_ms)?;
        let Some((mapping_index, mapping)) =
            self.mappings
                .iter()
                .copied()
                .enumerate()
                .find(|(_, mapping)| {
                    self.mapping_is_live(*mapping, now_ms) && mapping.public_port == public_port
                })
        else {
            return Err(Nat44UdpPlanError::MappingMiss);
        };
        if !self.peer_exists(mapping_index, mapping.generation, remote_address) {
            return Err(Nat44UdpPlanError::FilterDenied);
        }
        Ok(Nat44UdpInboundPlan {
            mapping_index,
            mapping_generation: mapping.generation,
            internal_address: mapping.internal_address,
            internal_port: mapping.internal_port,
        })
    }

    pub(crate) fn commit_inbound(&mut self, plan: Nat44UdpInboundPlan, now_ms: u64) {
        debug_assert!(self
            .mappings
            .get(plan.mapping_index)
            .is_some_and(|mapping| {
                mapping.occupied && mapping.generation == plan.mapping_generation
            }));
        self.watermark_ms = Some(now_ms);
        self.counters.inbound_translated = self.counters.inbound_translated.saturating_add(1);
    }

    pub(crate) fn record_plan_error(&mut self, error: Nat44UdpPlanError) {
        match error {
            Nat44UdpPlanError::MappingMiss => {
                self.counters.mapping_misses = self.counters.mapping_misses.saturating_add(1);
            }
            Nat44UdpPlanError::FilterDenied => {
                self.counters.filter_denied = self.counters.filter_denied.saturating_add(1);
            }
            Nat44UdpPlanError::MappingFull => {
                self.counters.mapping_full = self.counters.mapping_full.saturating_add(1);
            }
            Nat44UdpPlanError::PeerFull => {
                self.counters.peer_full = self.counters.peer_full.saturating_add(1);
            }
            Nat44UdpPlanError::PortExhausted => {
                self.counters.port_exhausted = self.counters.port_exhausted.saturating_add(1);
            }
            Nat44UdpPlanError::ClockRegression => {
                self.counters.clock_regressions = self.counters.clock_regressions.saturating_add(1);
            }
        }
    }

    fn check_clock(&self, now_ms: u64) -> Result<(), Nat44UdpPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            Err(Nat44UdpPlanError::ClockRegression)
        } else {
            Ok(())
        }
    }

    fn mapping_is_live(&self, mapping: Nat44UdpMappingSlot, now_ms: u64) -> bool {
        mapping.occupied
            && now_ms >= mapping.last_outbound_ms
            && now_ms - mapping.last_outbound_ms < self.config.policy.idle_ttl_ms
    }

    fn find_mapping(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        now_ms: u64,
    ) -> Option<(usize, Nat44UdpMappingSlot)> {
        self.mappings
            .iter()
            .copied()
            .enumerate()
            .find(|(_, mapping)| {
                self.mapping_is_live(*mapping, now_ms)
                    && mapping.inside == self.config.inside
                    && mapping.internal_address == internal_address
                    && mapping.internal_port == internal_port
            })
    }

    fn find_reusable_mapping(&self, now_ms: u64) -> Option<usize> {
        self.mappings
            .iter()
            .position(|mapping| !self.mapping_is_live(*mapping, now_ms))
    }

    fn peer_exists(
        &self,
        mapping_index: usize,
        mapping_generation: u64,
        remote_address: Ipv4Address,
    ) -> bool {
        self.peers.iter().any(|peer| {
            peer.occupied
                && peer.mapping_index == mapping_index
                && peer.mapping_generation == mapping_generation
                && peer.remote_address == remote_address
        })
    }

    fn find_reusable_peer(&self, now_ms: u64) -> Option<usize> {
        self.peers.iter().position(|peer| {
            if !peer.occupied {
                return true;
            }
            self.mappings.get(peer.mapping_index).is_none_or(|mapping| {
                !self.mapping_is_live(*mapping, now_ms)
                    || mapping.generation != peer.mapping_generation
            })
        })
    }

    fn port_is_free(&self, port: u16, now_ms: u64) -> bool {
        !self
            .mappings
            .iter()
            .any(|mapping| self.mapping_is_live(*mapping, now_ms) && mapping.public_port == port)
    }

    fn allocate_port(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        now_ms: u64,
    ) -> Option<u16> {
        if (self.config.first_port..=self.config.last_port).contains(&internal_port)
            && self.port_is_free(internal_port, now_ms)
        {
            return Some(internal_port);
        }
        let pool_size = u32::from(self.config.last_port) - u32::from(self.config.first_port) + 1;
        let address = u32::from_be_bytes(internal_address.octets());
        let mixed = self.config.policy.allocator_seed
            ^ u64::from(address)
            ^ u64::from(internal_port).rotate_left(17);
        let start = u32::try_from(mixed % u64::from(pool_size)).ok()?;
        for step in 0..pool_size {
            let offset = (start + step) % pool_size;
            let candidate = u16::try_from(u32::from(self.config.first_port) + offset).ok()?;
            if self.port_is_free(candidate, now_ms) {
                return Some(candidate);
            }
        }
        None
    }

    fn next_nonzero_generation(&self) -> u64 {
        self.next_generation.max(1)
    }
}

fn address_is_host_unicast(snapshot: &ForwardingSnapshot<'_>, address: Ipv4Address) -> bool {
    let octets = address.octets();
    if octets[0] == 0 || octets[0] == 127 || octets[0] >= 224 || octets == [255; 4] {
        return false;
    }
    !route::lookup(snapshot.routes, address).is_some_and(|selected| {
        selected.is_prefix_network_address(address)
            || selected.is_prefix_directed_broadcast(address)
    })
}

fn snapshot_authority(snapshot: &ForwardingSnapshot<'_>) -> u64 {
    fn mix(hash: u64, value: u64) -> u64 {
        (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
    }

    let mut hash = 0xcbf2_9ce4_8422_2325;
    for interface in snapshot.interfaces {
        hash = mix(hash, u64::from(interface.id.0));
        for octet in interface.mac.0 {
            hash = mix(hash, u64::from(octet));
        }
    }
    hash = mix(hash, 0xff);
    for binding in snapshot.local_ipv4 {
        hash = mix(hash, u64::from(binding.interface.0));
        hash = mix(
            hash,
            u64::from(u32::from_be_bytes(binding.address.octets())),
        );
    }
    hash = mix(hash, 0xfe);
    for route in snapshot.routes {
        hash = mix(hash, u64::from(u32::from_be_bytes(route.prefix().octets())));
        hash = mix(hash, u64::from(route.prefix_len()));
        hash = mix(hash, u64::from(route.egress().0));
        hash = mix(
            hash,
            route.next_hop().map_or(u64::MAX, |next| {
                u64::from(u32::from_be_bytes(next.octets()))
            }),
        );
    }
    hash = mix(hash, 0xfd);
    for neighbor in snapshot.neighbors {
        hash = mix(hash, u64::from(neighbor.interface.0));
        hash = mix(
            hash,
            u64::from(u32::from_be_bytes(neighbor.target.octets())),
        );
        for octet in neighbor.mac.0 {
            hash = mix(hash, u64::from(octet));
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, LocalIpv4Binding, MacAddress, Neighbor, Route};

    const INSIDE: IfId = IfId(1);
    const OUTSIDE: IfId = IfId(2);
    const INTERNAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
    const INTERNAL2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const REMOTE1: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
    const REMOTE2: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 2]);

    fn with_config<R>(policy: Nat44UdpPolicy, run: impl FnOnce(Nat44UdpConfig) -> R) -> R {
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, INSIDE, None).unwrap(),
            Route::new(
                Ipv4Address::from_octets([0, 0, 0, 0]),
                0,
                OUTSIDE,
                Some(Ipv4Address::from_octets([203, 0, 113, 1])),
            )
            .unwrap(),
        ];
        let interfaces = [
            Interface {
                id: INSIDE,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
            },
            Interface {
                id: OUTSIDE,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
            },
        ];
        let neighbors = [Neighbor {
            interface: OUTSIDE,
            target: Ipv4Address::from_octets([203, 0, 113, 1]),
            mac: MacAddress([2, 0, 0, 0, 0, 3]),
        }];
        let bindings = [
            LocalIpv4Binding {
                interface: INSIDE,
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
            },
            LocalIpv4Binding {
                interface: OUTSIDE,
                address: PUBLIC,
            },
        ];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let config =
            Nat44UdpConfig::new(&snapshot, INSIDE, OUTSIDE, PUBLIC, 40_000, 40_001, policy)
                .unwrap();
        run(config)
    }

    #[test]
    fn eim_adf_expiry_and_generation_invalidate_stale_peers() {
        let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 11).unwrap();
        with_config(policy, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 2];
            let mut runtime = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            assert_eq!(first.public_port(), 40_000);
            runtime.commit_outbound(first, 0);
            let second = runtime.plan_outbound(INTERNAL, 40_000, REMOTE2, 1).unwrap();
            assert_eq!(second.public_port(), 40_000);
            runtime.commit_outbound(second, 1);
            assert!(runtime.plan_inbound(40_000, REMOTE1, 2).is_ok());
            assert!(runtime.plan_inbound(40_000, REMOTE2, 2).is_ok());

            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, NAT44_UDP_MIN_IDLE_TTL_MS + 1),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            let reused = runtime
                .plan_outbound(INTERNAL2, 40_000, REMOTE2, NAT44_UDP_MIN_IDLE_TTL_MS + 1)
                .unwrap();
            runtime.commit_outbound(reused, NAT44_UDP_MIN_IDLE_TTL_MS + 1);
            assert!(matches!(
                runtime.plan_inbound(reused.public_port(), REMOTE1, NAT44_UDP_MIN_IDLE_TTL_MS + 1),
                Err(Nat44UdpPlanError::FilterDenied)
            ));
            assert!(runtime
                .plan_inbound(reused.public_port(), REMOTE2, NAT44_UDP_MIN_IDLE_TTL_MS + 1)
                .is_ok());
        });
    }

    #[test]
    fn full_tables_do_not_evict_or_refresh_live_state_and_zero_capacity_is_safe() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 10)
                .unwrap();
            runtime.commit_outbound(first, 10);
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE2, 20),
                Err(Nat44UdpPlanError::PeerFull)
            ));
            assert_eq!(runtime.mappings()[0].last_outbound_ms(), 10);
            assert!(matches!(
                runtime.plan_outbound(INTERNAL2, 40_001, REMOTE1, 20),
                Err(Nat44UdpPlanError::MappingFull)
            ));
            assert_eq!(runtime.mappings()[0].internal_address(), INTERNAL);

            let mut no_mappings = [];
            let mut one_peer = [Nat44UdpPeerSlot::default(); 1];
            let empty = Nat44UdpRuntime::new(config, &mut no_mappings, &mut one_peer);
            assert!(matches!(
                empty.plan_outbound(INTERNAL, 40_000, REMOTE1, 0),
                Err(Nat44UdpPlanError::MappingFull)
            ));
            let mut one_mapping = [Nat44UdpMappingSlot::default(); 1];
            let mut no_peers = [];
            let empty = Nat44UdpRuntime::new(config, &mut one_mapping, &mut no_peers);
            assert!(matches!(
                empty.plan_outbound(INTERNAL, 40_000, REMOTE1, 0),
                Err(Nat44UdpPlanError::PeerFull)
            ));
        });
    }

    #[test]
    fn seeded_scan_wraps_once_after_a_preserved_port_collision() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 2];
            let mut peers = [Nat44UdpPeerSlot::default(); 2];
            let mut runtime = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
            let last = runtime.plan_outbound(INTERNAL, 40_001, REMOTE1, 0).unwrap();
            assert_eq!(last.public_port(), 40_001);
            runtime.commit_outbound(last, 0);

            // For INTERNAL2/50000 and seed zero the deterministic start is
            // offset one. It collides with 40001, wraps, and selects 40000.
            let wrapped = runtime
                .plan_outbound(INTERNAL2, 50_000, REMOTE1, 0)
                .unwrap();
            assert_eq!(wrapped.public_port(), 40_000);
            runtime.commit_outbound(wrapped, 0);
            assert_ne!(
                runtime.mappings()[0].public_port(),
                runtime.mappings()[1].public_port()
            );
        });
    }

    #[test]
    fn clock_regression_is_atomic_and_equal_time_recovers() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 100)
                .unwrap();
            runtime.commit_outbound(first, 100);
            let before = runtime.mappings()[0];
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 99),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert_eq!(runtime.mappings()[0], before);
            let equal = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 100)
                .unwrap();
            runtime.commit_outbound(equal, 100);
            assert_eq!(runtime.mappings()[0].last_outbound_ms(), 100);
        });
    }

    #[test]
    fn reconcile_flushes_every_mapping_and_peer_before_rebinding() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(first, 0);
            let report = runtime.reconcile(config);
            assert_eq!(
                report,
                Nat44UdpReconcileReport {
                    mappings_flushed: 1,
                    peers_flushed: 1,
                }
            );
            assert!(runtime.mappings().iter().all(|slot| !slot.occupied));
            assert!(runtime.peers().iter().all(|slot| !slot.occupied));
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, 0),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
        });
    }

    #[test]
    fn policy_and_config_reject_ambiguous_or_unsafe_authority() {
        assert_eq!(
            Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS - 1, 0),
            Err(Nat44UdpPolicyError::IdleTtlTooShort)
        );
        assert_eq!(
            Nat44UdpPolicy::new(NAT44_UDP_MAX_IDLE_TTL_MS + 1, 0),
            Err(Nat44UdpPolicyError::IdleTtlTooLong)
        );
        with_config(Nat44UdpPolicy::default(), |config| {
            assert_eq!(config.policy().idle_ttl_ms(), NAT44_UDP_DEFAULT_IDLE_TTL_MS);
            assert_ne!(config.inside(), config.outside());
            assert_ne!(config.first_port(), 0);
        });
    }
}

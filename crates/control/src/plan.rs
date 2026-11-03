//! Cold-path apply planning, generation sequencing, and M1 rollback.
//!
//! [`ApplyPlan`] describes what applying one validated configuration on top
//! of another would change, without building runtimes, drawing keys, or
//! mutating anything. Diff entries are ordered by a stable key (route prefix,
//! neighbor interface and target, interface id, rule id), so the same two
//! documents always produce the same plan. [`ApplyPlan::for_active`]
//! additionally dry-runs a built successor against a live
//! [`ActivePublication`] through [`ActivePublication::check_successor`] and
//! reports exact live flush counts.
//!
//! The plan carries configuration values that an operator already owns
//! (prefixes, MAC addresses, rule ids, NAT realm and ports). It never carries
//! a hash key, a key-source seed, or a NAT allocator seed: NAT and firewall
//! policies are reported only as changed/unchanged.
//!
//! [`PublicationSequencer`] owns generation numbering. It issues strictly
//! increasing generations, consumes a generation even when a build fails, and
//! refuses any key set that it already issued within this process. An M1
//! rollback is simply building the old configuration document again: the
//! result is a new generation with new keys, applied like any successor.
//! [`ProductionSequencer`] is the same sequencer restricted to a sealed
//! [`ProductionKeySource`]; the live `run` path must use it, so a
//! deterministic simulation key source cannot reach live traffic.
//!
//! Across process restarts nothing is remembered: M1 starts from scratch, so
//! a new process restarts numbering at generation 1 with a fresh sequencer
//! and fresh storage. Durable generation/key history is out of scope for M1.

use std::{cmp::Ordering, fmt, num::NonZeroU64};

use ruster_config::{
    BackendKindV1, ExistingXdpProgramV1, InterfaceBindingV1, ValidatedAfPacketPortV1,
    ValidatedAfXdpPortV1, ValidatedBackendV1, ValidatedConfigV1,
};
use ruster_core::{
    FirewallHashKey, FirewallRule, FirewallRuleId, IfId, Interface, Ipv4Address, LocalIpv4Binding,
    Nat44Filtering, Nat44TcpHashKey, Nat44TcpInboundRst, Nat44UdpHashKey, Neighbor,
    PublicationQuiescence, ResolutionHashKey, Route,
};

use crate::{
    candidate_from_config,
    config_bridge::{required_services, RequiredServices},
    ActivePublication, ApplyError, ConfigBridgeError, ProductionKeySource, PublicationKeySource,
    RestartRequired, RuntimeService, ValidatedCandidate,
};

/// How many entries of one kind of publication-bound state an apply flushes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlushCount {
    /// Every entry is flushed; the live count is not known to the plan.
    All,
    /// Exactly this many live entries are flushed.
    Exact(usize),
}

/// Expected flush of publication-bound state on apply.
///
/// Every reload flushes ARP learning and pending resolution/ICMPv4 work and,
/// because NAT and firewall hash keys rotate on every generation, all NAT
/// mappings/peers/sessions and all firewall flows. Cumulative counters are
/// preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct StateFlush {
    pub resolution_states: FlushCount,
    pub resolution_actions: FlushCount,
    pub dynamic_neighbors: FlushCount,
    pub failure_holds: FlushCount,
    pub icmpv4_error_states: FlushCount,
    pub icmpv4_error_actions: FlushCount,
    pub nat44_udp_mappings: FlushCount,
    pub nat44_udp_peers: FlushCount,
    pub nat44_tcp_mappings: FlushCount,
    pub nat44_tcp_sessions: FlushCount,
    /// ICMP query NAT (N5); `Exact(0)` from a live publication without it.
    pub nat44_icmp_mappings: FlushCount,
    pub nat44_icmp_peers: FlushCount,
    pub firewall_flows: FlushCount,
}

impl StateFlush {
    /// Flush expectation without live state: everything.
    pub const ALL: Self = Self {
        resolution_states: FlushCount::All,
        resolution_actions: FlushCount::All,
        dynamic_neighbors: FlushCount::All,
        failure_holds: FlushCount::All,
        icmpv4_error_states: FlushCount::All,
        icmpv4_error_actions: FlushCount::All,
        nat44_udp_mappings: FlushCount::All,
        nat44_udp_peers: FlushCount::All,
        nat44_tcp_mappings: FlushCount::All,
        nat44_tcp_sessions: FlushCount::All,
        nat44_icmp_mappings: FlushCount::All,
        nat44_icmp_peers: FlushCount::All,
        firewall_flows: FlushCount::All,
    };
}

/// Result of a successful guard-free dry-run of one successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SuccessorCheck {
    pub previous_generation: NonZeroU64,
    pub generation: NonZeroU64,
    /// Live flush counts at the time of the check. Traffic between the check
    /// and the apply tick can change them; the apply report is authoritative.
    pub flush: StateFlush,
}

/// An old and a new value of one keyed item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delta<T> {
    pub old: T,
    pub new: T,
}

/// One keyed difference between two configurations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change<T> {
    Added(T),
    Removed(T),
    Changed(Delta<T>),
}

/// NAT44 address realm of one protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct NatRealm {
    pub inside: IfId,
    pub outside: IfId,
    pub public_address: Ipv4Address,
}

/// Inclusive NAT44 public port pool of one protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct NatPortRange {
    pub first: u16,
    pub last: u16,
}

/// Difference of one NAT44 protocol. The filtering behavior, the
/// hairpinning switch, the port preservation switch, the per-host mapping,
/// peer, and session limits, the TCP per-remote inbound session limit, the
/// TCP unsolicited-SYN ICMP switch, and the TCP inbound-RST policy are not
/// secret and are reported as typed deltas. The
/// rest of the policy (which includes the allocator seed) is never exposed,
/// only whether it changed: `policy_changed` ignores changes of only those
/// values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct NatChange {
    pub realm: Option<Delta<NatRealm>>,
    pub ports: Option<Delta<NatPortRange>>,
    pub filtering: Option<Delta<Nat44Filtering>>,
    pub hairpinning: Option<Delta<bool>>,
    /// The port preservation switch (`port-preservation`, N2).
    pub port_preservation: Option<Delta<bool>>,
    /// The per-host mapping limit (`mappings-per-host`, N3); `0` means no
    /// limit. Switching between `0` and a limit also changes the storage
    /// shape (restart-required); a change between two limits is reloadable.
    pub mappings_per_host: Option<Delta<u16>>,
    /// UDP and ICMP queries only (always `None` for TCP): the per-host
    /// filter peer limit (`peers-per-host`, N6); `0` means no limit. It
    /// shares the per-host storage of `mappings-per-host`, so it changes
    /// the storage shape only when it switches that storage on or off.
    pub peers_per_host: Option<Delta<u16>>,
    /// TCP only (always `None` for UDP and ICMP): the per-host session
    /// limit (`sessions-per-host`, N6); `0` means no limit. Switching
    /// between `0` and a limit also changes the storage shape.
    pub sessions_per_host: Option<Delta<u16>>,
    /// TCP only (always `None` for UDP); `0` means no limit.
    pub inbound_sessions_per_remote: Option<Delta<u8>>,
    /// TCP only (always `None` for UDP): the RFC 5382 REQ-4 delayed ICMP
    /// Port Unreachable switch (`unsolicited-syn-icmp`).
    pub unsolicited_syn_icmp: Option<Delta<bool>>,
    /// TCP only (always `None` for UDP): what inbound RST/FIN segments do
    /// to a session's phase (`inbound-rst`).
    pub inbound_rst: Option<Delta<Nat44TcpInboundRst>>,
    pub policy_changed: bool,
}

impl NatChange {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.realm.is_none()
            && self.ports.is_none()
            && self.filtering.is_none()
            && self.hairpinning.is_none()
            && self.port_preservation.is_none()
            && self.mappings_per_host.is_none()
            && self.peers_per_host.is_none()
            && self.sessions_per_host.is_none()
            && self.inbound_sessions_per_remote.is_none()
            && self.unsolicited_syn_icmp.is_none()
            && self.inbound_rst.is_none()
            && !self.policy_changed
    }
}

/// Difference of the `[backend]` section. Backend settings are not secret,
/// so every difference is a typed value. Any non-empty change is
/// [`RestartRequired::Backend`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct BackendChange {
    pub kind: Option<Delta<BackendKindV1>>,
    pub existing_xdp_program: Option<Delta<ExistingXdpProgramV1>>,
    /// AF_XDP ports keyed by interface IfId. The simulation backend has
    /// none, so a `sim` to `af-xdp` change adds every port. A port includes
    /// its bound device, so moving an interface to another device (or
    /// swapping two devices) is a port change, not just a label change.
    pub ports: Box<[Change<ValidatedAfXdpPortV1>]>,
    /// The AF_PACKET maximum frame (`None` on a side without the AF_PACKET
    /// backend).
    pub af_packet_max_frame_len: Option<Delta<Option<u32>>>,
    /// AF_PACKET ports keyed by interface IfId, like [`Self::ports`]: a
    /// change of kind to or from `af-packet` adds or removes every port.
    pub af_packet_ports: Box<[Change<ValidatedAfPacketPortV1>]>,
}

impl BackendChange {
    fn between(old: &ValidatedBackendV1, new: &ValidatedBackendV1) -> Self {
        let ports = |backend: &ValidatedBackendV1| {
            backend
                .af_xdp()
                .map_or(&[][..], ruster_config::ValidatedAfXdpV1::ports)
                .to_vec()
        };
        let program = |backend: &ValidatedBackendV1| {
            backend
                .af_xdp()
                .map(ruster_config::ValidatedAfXdpV1::existing_program)
        };
        let existing_xdp_program = match (program(old), program(new)) {
            (Some(old), Some(new)) => delta(old, new),
            _ => None,
        };
        let packet_ports = |backend: &ValidatedBackendV1| {
            backend
                .af_packet()
                .map_or(&[][..], ruster_config::ValidatedAfPacketV1::ports)
                .to_vec()
        };
        let max_frame = |backend: &ValidatedBackendV1| {
            backend
                .af_packet()
                .map(ruster_config::ValidatedAfPacketV1::max_frame_len)
        };
        Self {
            kind: delta(old.kind(), new.kind()),
            existing_xdp_program,
            ports: diff(&ports(old), &ports(new), ValidatedAfXdpPortV1::interface),
            af_packet_max_frame_len: delta(max_frame(old), max_frame(new)),
            af_packet_ports: diff(
                &packet_ports(old),
                &packet_ports(new),
                ValidatedAfPacketPortV1::interface,
            ),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kind.is_none()
            && self.existing_xdp_program.is_none()
            && self.ports.is_empty()
            && self.af_packet_max_frame_len.is_none()
            && self.af_packet_ports.is_empty()
    }
}

/// Control-plane labels of one interface. Informational only: core
/// identity is the IfId and MAC, so a label change is reloadable.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InterfaceLabels {
    pub id: IfId,
    pub name: Box<str>,
    pub device: Box<str>,
}

impl InterfaceLabels {
    fn of(binding: &InterfaceBindingV1) -> Self {
        Self {
            id: binding.id(),
            name: binding.name().into(),
            device: binding.device().into(),
        }
    }
}

/// Which input of a plan was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanSide {
    Current,
    Next,
}

/// Typed, value-free reason a plan could not be built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlanError {
    /// One configuration omits a service that M1 requires.
    MissingService {
        side: PlanSide,
        service: RuntimeService,
    },
}

/// Typed description of applying `next` on top of `current`.
///
/// Building a plan never mutates configuration, candidates, storage, or
/// runtimes. Restart-required reasons are listed in the order successor
/// validation checks them, so a list whose first reason is not
/// [`RestartRequired::Backend`] predicts the rejection
/// `RestartRequired(restart_required()[0])` for any successor built from
/// `next` with a fresh generation and keys. `Backend` is always last: the
/// publication candidate carries no backend, so only the backend-owning
/// process can enforce it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyPlan {
    routes: Box<[Change<Route>]>,
    neighbors: Box<[Change<Neighbor>]>,
    local_ipv4: Box<[Change<LocalIpv4Binding>]>,
    interfaces: Box<[Change<Interface>]>,
    interface_labels: Box<[Delta<InterfaceLabels>]>,
    firewall_rules: Box<[Change<FirewallRule>]>,
    firewall_rule_order_changed: bool,
    firewall_policy_changed: bool,
    ipv4_origin_changed: bool,
    arp_policy_changed: bool,
    nat44_udp: NatChange,
    nat44_tcp: NatChange,
    nat44_icmp_presence: Option<Delta<bool>>,
    nat44_icmp: NatChange,
    backend: BackendChange,
    restart_required: Box<[RestartRequired]>,
    flush: StateFlush,
    dry_run: Option<Result<SuccessorCheck, ApplyError>>,
}

impl ApplyPlan {
    /// Plans `next` against `current` from the documents alone.
    ///
    /// No live state is consulted, so every flush count is
    /// [`FlushCount::All`].
    pub fn between(
        current: &ValidatedConfigV1,
        next: &ValidatedConfigV1,
    ) -> Result<Self, PlanError> {
        let missing = |side| move |service| PlanError::MissingService { side, service };
        let old = required_services(current).map_err(missing(PlanSide::Current))?;
        let new = required_services(next).map_err(missing(PlanSide::Next))?;

        let interfaces = diff(current.core_interfaces(), next.core_interfaces(), |item| {
            item.id
        });
        let mut restart_required = Vec::new();
        if old.shape != new.shape {
            restart_required.push(RestartRequired::StorageShape);
        }
        if old.resolution.policy() != new.resolution.policy() {
            restart_required.push(RestartRequired::ResolutionPolicy);
        }
        if old.icmpv4_errors.policy() != new.icmpv4_errors.policy() {
            restart_required.push(RestartRequired::Icmpv4ErrorPolicy);
        }
        if !interfaces.is_empty() {
            restart_required.push(RestartRequired::Interfaces);
        }
        let backend = BackendChange::between(current.backend(), next.backend());
        debug_assert_eq!(backend.is_empty(), current.backend() == next.backend());
        if current.backend() != next.backend() {
            restart_required.push(RestartRequired::Backend);
        }

        let old_rules = old.firewall.rules();
        let new_rules = new.firewall.rules();
        Ok(Self {
            routes: diff(current.routes(), next.routes(), |route| {
                (route.prefix(), route.prefix_len())
            }),
            neighbors: diff(current.neighbors(), next.neighbors(), |neighbor| {
                (neighbor.interface, neighbor.target)
            }),
            local_ipv4: diff(current.local_ipv4(), next.local_ipv4(), |binding| {
                binding.interface
            }),
            interfaces,
            interface_labels: label_changes(current.interfaces(), next.interfaces()),
            firewall_rules: diff(old_rules, new_rules, |rule| rule.id()),
            firewall_rule_order_changed: common_order_changed(old_rules, new_rules),
            firewall_policy_changed: old.firewall.policy() != new.firewall.policy(),
            ipv4_origin_changed: current.ipv4_origin() != next.ipv4_origin(),
            arp_policy_changed: current.arp() != next.arp(),
            nat44_udp: nat_change(&old, &new, Protocol::Udp),
            nat44_tcp: nat_change(&old, &new, Protocol::Tcp),
            nat44_icmp_presence: delta(old.icmp.is_some(), new.icmp.is_some()),
            nat44_icmp: icmp_change(&old, &new),
            backend,
            restart_required: restart_required.into_boxed_slice(),
            flush: StateFlush::ALL,
            dry_run: None,
        })
    }

    /// Plans `next` against `current` and dry-runs `successor` (built from
    /// `next`) against the live publication.
    ///
    /// The dry-run takes no quiescence guard or tick and leaves the live
    /// publication unchanged. On success the flush counts are the live
    /// counts; on rejection the typed error is recorded and the flush stays
    /// [`FlushCount::All`]. The caller is responsible for `current` being the
    /// document of the active generation and `successor` being built from
    /// `next`.
    ///
    /// A [`RestartRequired::Backend`] plan is never live-applicable even
    /// though the publication would accept the successor (a candidate
    /// carries no backend). Such a plan skips the live check: the dry run is
    /// recorded as `Err(ApplyError::RestartRequired(restart_required()[0]))`
    /// (`Backend` itself only when it is the sole reason, because `Backend`
    /// is always listed last), and the flush stays [`FlushCount::All`], so
    /// no caller can mistake it for an in-place reload and the recorded
    /// reason is the first one, as for every other restart-required plan.
    pub fn for_active<I: PublicationQuiescence>(
        active: &mut ActivePublication<'_, I>,
        current: &ValidatedConfigV1,
        next: &ValidatedConfigV1,
        successor: &ValidatedCandidate,
    ) -> Result<Self, PlanError> {
        let mut plan = Self::between(current, next)?;
        if plan.restart_required.contains(&RestartRequired::Backend) {
            let first = plan.restart_required[0];
            plan.dry_run = Some(Err(ApplyError::RestartRequired(first)));
            return Ok(plan);
        }
        let check = active.check_successor(successor);
        if let Ok(check) = check {
            plan.flush = check.flush;
        }
        plan.dry_run = Some(check);
        Ok(plan)
    }

    #[must_use]
    pub fn routes(&self) -> &[Change<Route>] {
        &self.routes
    }

    #[must_use]
    pub fn neighbors(&self) -> &[Change<Neighbor>] {
        &self.neighbors
    }

    #[must_use]
    pub fn local_ipv4(&self) -> &[Change<LocalIpv4Binding>] {
        &self.local_ipv4
    }

    /// Interface IfId additions/removals and MAC changes. Any entry is
    /// restart-required.
    #[must_use]
    pub fn interfaces(&self) -> &[Change<Interface>] {
        &self.interfaces
    }

    /// Name/device changes of interfaces present in both documents, in IfId
    /// order. Not restart-required; additions/removals are in
    /// [`ApplyPlan::interfaces`].
    #[must_use]
    pub fn interface_labels(&self) -> &[Delta<InterfaceLabels>] {
        &self.interface_labels
    }

    #[must_use]
    pub fn firewall_rules(&self) -> &[Change<FirewallRule>] {
        &self.firewall_rules
    }

    /// Whether rules present in both documents changed their relative
    /// first-match order.
    #[must_use]
    pub const fn firewall_rule_order_changed(&self) -> bool {
        self.firewall_rule_order_changed
    }

    #[must_use]
    pub const fn firewall_policy_changed(&self) -> bool {
        self.firewall_policy_changed
    }

    #[must_use]
    pub const fn ipv4_origin_changed(&self) -> bool {
        self.ipv4_origin_changed
    }

    /// Whether the `[arp]` receive policy changed. Reloadable: the policy
    /// is part of the forwarding snapshot that every reload replaces, and
    /// every reload flushes ARP learning anyway.
    #[must_use]
    pub const fn arp_policy_changed(&self) -> bool {
        self.arp_policy_changed
    }

    #[must_use]
    pub const fn nat44_udp(&self) -> NatChange {
        self.nat44_udp
    }

    #[must_use]
    pub const fn nat44_tcp(&self) -> NatChange {
        self.nat44_tcp
    }

    /// Whether ICMP query NAT (N5) is added or removed: a storage-shape
    /// change, so restart-required.
    #[must_use]
    pub const fn nat44_icmp_presence(&self) -> Option<Delta<bool>> {
        self.nat44_icmp_presence
    }

    /// Difference of ICMP query NAT (N5) when both documents configure it
    /// (empty otherwise). `ports` is the identifier pool and
    /// `port_preservation` the identifier preservation switch; `realm` is
    /// shared with UDP/TCP and `hairpinning` and the TCP-only fields are
    /// always `None`.
    #[must_use]
    pub const fn nat44_icmp(&self) -> NatChange {
        self.nat44_icmp
    }

    /// Difference of the `[backend]` section; non-empty exactly when
    /// [`RestartRequired::Backend`] is listed.
    #[must_use]
    pub const fn backend(&self) -> &BackendChange {
        &self.backend
    }

    /// Reasons the change cannot be applied in place, in successor
    /// validation order (with [`RestartRequired::Backend`] last). The NAT port-owner table holds exactly one slot per
    /// pool port, so only a pool *size* change alters the storage shape and
    /// is restart-required; a same-size shift of the range and a realm change
    /// are reloadable.
    #[must_use]
    pub fn restart_required(&self) -> &[RestartRequired] {
        &self.restart_required
    }

    #[must_use]
    pub fn requires_restart(&self) -> bool {
        !self.restart_required.is_empty()
    }

    /// Expected state flush. A restart flushes everything regardless.
    #[must_use]
    pub const fn flush(&self) -> StateFlush {
        self.flush
    }

    /// Outcome of the live dry-run, if the plan was built with one.
    #[must_use]
    pub const fn dry_run(&self) -> Option<Result<SuccessorCheck, ApplyError>> {
        self.dry_run
    }
}

/// Keyed diff, ordered by key. Validated configuration has unique keys.
fn diff<T: Clone + Eq, K: Ord>(old: &[T], new: &[T], key: impl Fn(&T) -> K) -> Box<[Change<T>]> {
    let sorted = |items: &[T]| {
        let mut items = items.to_vec();
        items.sort_by_key(|item| key(item));
        items
    };
    let (old, new) = (sorted(old), sorted(new));
    let (mut old, mut new) = (old.iter().peekable(), new.iter().peekable());
    let mut changes = Vec::new();
    loop {
        let order = match (old.peek(), new.peek()) {
            (None, None) => break,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => key(a).cmp(&key(b)),
        };
        match order {
            Ordering::Less => changes.extend(old.next().cloned().map(Change::Removed)),
            Ordering::Greater => changes.extend(new.next().cloned().map(Change::Added)),
            Ordering::Equal => {
                if let (Some(old), Some(new)) = (old.next(), new.next()) {
                    if old != new {
                        changes.push(Change::Changed(Delta {
                            old: old.clone(),
                            new: new.clone(),
                        }));
                    }
                }
            }
        }
    }
    changes.into_boxed_slice()
}

fn label_changes(
    old: &[InterfaceBindingV1],
    new: &[InterfaceBindingV1],
) -> Box<[Delta<InterfaceLabels>]> {
    let mut changes: Vec<_> = old
        .iter()
        .filter_map(|old| {
            let new = new.iter().find(|new| new.id() == old.id())?;
            (old.name() != new.name() || old.device() != new.device()).then(|| Delta {
                old: InterfaceLabels::of(old),
                new: InterfaceLabels::of(new),
            })
        })
        .collect();
    changes.sort_by_key(|change| change.old.id);
    changes.into_boxed_slice()
}

fn common_order_changed(old: &[FirewallRule], new: &[FirewallRule]) -> bool {
    let common = |rules: &[FirewallRule], other: &[FirewallRule]| -> Vec<FirewallRuleId> {
        rules
            .iter()
            .map(|rule| rule.id())
            .filter(|id| other.iter().any(|rule| rule.id() == *id))
            .collect()
    };
    common(old, new) != common(new, old)
}

#[derive(Clone, Copy)]
enum Protocol {
    Udp,
    Tcp,
}

fn nat_parts(services: &RequiredServices<'_>, protocol: Protocol) -> (NatRealm, NatPortRange) {
    macro_rules! parts {
        ($nat:expr) => {
            (
                NatRealm {
                    inside: $nat.inside(),
                    outside: $nat.outside(),
                    public_address: $nat.public_address(),
                },
                NatPortRange {
                    first: $nat.first_port(),
                    last: $nat.last_port(),
                },
            )
        };
    }
    match protocol {
        Protocol::Udp => parts!(services.udp),
        Protocol::Tcp => parts!(services.tcp),
    }
}

fn delta<T: Eq>(old: T, new: T) -> Option<Delta<T>> {
    (old != new).then_some(Delta { old, new })
}

fn nat_change(
    old: &RequiredServices<'_>,
    new: &RequiredServices<'_>,
    protocol: Protocol,
) -> NatChange {
    let (old_realm, old_ports) = nat_parts(old, protocol);
    let (new_realm, new_ports) = nat_parts(new, protocol);
    // Filtering, hairpinning, port preservation, the per-host limits, the
    // TCP inbound limit, the TCP unsolicited-SYN ICMP switch, and the TCP
    // inbound-RST policy are reported separately, so compare the rest of the
    // policy with the new values substituted into the old one.
    let (
        filtering,
        hairpinning,
        port_preservation,
        (mappings_per_host, peers_per_host, sessions_per_host),
        inbound_sessions_per_remote,
        unsolicited_syn_icmp,
        inbound_rst,
        policy_changed,
    ) = match protocol {
        Protocol::Udp => {
            let (old, new) = (old.udp.policy(), new.udp.policy());
            (
                delta(old.filtering(), new.filtering()),
                delta(old.hairpinning(), new.hairpinning()),
                delta(old.port_preservation(), new.port_preservation()),
                (
                    delta(old.mappings_per_host(), new.mappings_per_host()),
                    delta(old.peers_per_host(), new.peers_per_host()),
                    None,
                ),
                None,
                None,
                None,
                old.with_filtering(new.filtering())
                    .with_hairpinning(new.hairpinning())
                    .with_port_preservation(new.port_preservation())
                    .with_mappings_per_host(new.mappings_per_host())
                    .with_peers_per_host(new.peers_per_host())
                    != new,
            )
        }
        Protocol::Tcp => {
            let (old, new) = (old.tcp.policy(), new.tcp.policy());
            (
                delta(old.filtering(), new.filtering()),
                delta(old.hairpinning(), new.hairpinning()),
                delta(old.port_preservation(), new.port_preservation()),
                (
                    delta(old.mappings_per_host(), new.mappings_per_host()),
                    None,
                    delta(old.sessions_per_host(), new.sessions_per_host()),
                ),
                delta(
                    old.inbound_sessions_per_remote(),
                    new.inbound_sessions_per_remote(),
                ),
                delta(old.unsolicited_syn_icmp(), new.unsolicited_syn_icmp()),
                delta(old.inbound_rst(), new.inbound_rst()),
                old.with_filtering(new.filtering())
                    .with_hairpinning(new.hairpinning())
                    .with_port_preservation(new.port_preservation())
                    .with_mappings_per_host(new.mappings_per_host())
                    .with_sessions_per_host(new.sessions_per_host())
                    .with_unsolicited_syn_icmp(new.unsolicited_syn_icmp())
                    .with_inbound_rst(new.inbound_rst())
                    .with_inbound_sessions_per_remote(new.inbound_sessions_per_remote())
                    .expect("a validated policy's limit is in range")
                    != new,
            )
        }
    };
    NatChange {
        realm: delta(old_realm, new_realm),
        ports: delta(old_ports, new_ports),
        filtering,
        hairpinning,
        port_preservation,
        mappings_per_host,
        peers_per_host,
        sessions_per_host,
        inbound_sessions_per_remote,
        unsolicited_syn_icmp,
        inbound_rst,
        policy_changed,
    }
}

fn icmp_change(old: &RequiredServices<'_>, new: &RequiredServices<'_>) -> NatChange {
    let empty = NatChange {
        realm: None,
        ports: None,
        filtering: None,
        hairpinning: None,
        port_preservation: None,
        mappings_per_host: None,
        peers_per_host: None,
        sessions_per_host: None,
        inbound_sessions_per_remote: None,
        unsolicited_syn_icmp: None,
        inbound_rst: None,
        policy_changed: false,
    };
    let (Some(old), Some(new)) = (old.icmp, new.icmp) else {
        return empty;
    };
    let range = |icmp: &ruster_config::ValidatedNat44IcmpV1| NatPortRange {
        first: icmp.first_identifier(),
        last: icmp.last_identifier(),
    };
    let realm = |icmp: &ruster_config::ValidatedNat44IcmpV1| NatRealm {
        inside: icmp.inside(),
        outside: icmp.outside(),
        public_address: icmp.public_address(),
    };
    let (old_policy, new_policy) = (old.policy(), new.policy());
    // Filtering, identifier preservation, and the per-host limit are
    // reported separately; the rest of the policy (seed, idle timeout, error
    // translation) only as changed.
    let rest = old_policy
        .with_filtering(new_policy.filtering())
        .expect("a validated filtering is supported")
        .with_identifier_preservation(new_policy.identifier_preservation())
        .with_mappings_per_host(new_policy.mappings_per_host())
        .with_peers_per_host(new_policy.peers_per_host());
    NatChange {
        realm: delta(realm(old), realm(new)),
        ports: delta(range(old), range(new)),
        filtering: delta(old_policy.filtering(), new_policy.filtering()),
        port_preservation: delta(
            old_policy.identifier_preservation(),
            new_policy.identifier_preservation(),
        ),
        mappings_per_host: delta(
            old_policy.mappings_per_host(),
            new_policy.mappings_per_host(),
        ),
        peers_per_host: delta(old_policy.peers_per_host(), new_policy.peers_per_host()),
        policy_changed: rest != new_policy,
        ..empty
    }
}

/// Typed, value-free failure to issue a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SequencerError {
    /// Every generation of this process has been issued.
    GenerationExhausted,
    /// The configuration could not be bridged; the generation is consumed.
    Bridge(ConfigBridgeError),
    /// The key source repeated a key this sequencer already issued; the
    /// generation is consumed and the candidate discarded.
    KeyReused(RuntimeService),
    /// The issued-key history could not grow.
    HistoryAllocation,
}

/// Keys of one issued generation. Never formatted.
struct IssuedKeys {
    nat44_udp: Nat44UdpHashKey,
    nat44_tcp: Nat44TcpHashKey,
    firewall: FirewallHashKey,
    resolution: ResolutionHashKey,
    /// `None` for a generation without ICMP query NAT (N5).
    nat44_icmp: Option<ruster_core::Nat44IcmpHashKey>,
}

/// Control-owned generation allocator and key-reuse guard.
///
/// Each [`PublicationSequencer::candidate`] call consumes the next
/// generation, whether or not the build succeeds, so no generation is ever
/// issued twice. Every issued key is remembered for the lifetime of the
/// sequencer (four keys per generation, cold path), and a candidate whose
/// UDP, TCP, firewall, or resolution key equals any earlier issued key of
/// that service is rejected. A→B→A therefore yields three generations with
/// three distinct key sets even when the key source misbehaves.
///
/// Exactly one sequencer must serve the whole process (S5b driver and S6
/// CLI included), also across storage re-creation for a restart-required
/// change: new storage starts with no generation floor, so only the shared
/// sequencer keeps the new storage above every generation already issued.
/// Building with caller-chosen generations through `candidate_from_config`
/// bypasses this guarantee. Nothing persists across process restarts (M1).
///
/// ```compile_fail
/// use ruster_control::{PublicationSequencer, SimDeterministicKeySource};
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<PublicationSequencer<SimDeterministicKeySource>>();
/// ```
pub struct PublicationSequencer<S> {
    keys: S,
    last_issued: Option<NonZeroU64>,
    issued: Vec<IssuedKeys>,
}

impl<S> fmt::Debug for PublicationSequencer<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationSequencer")
            .field("last_issued", &self.last_issued)
            .field("issued_key_sets", &self.issued.len())
            .finish_non_exhaustive()
    }
}

impl<S: PublicationKeySource> PublicationSequencer<S> {
    /// Starts a process-lifetime sequence at generation 1.
    #[must_use]
    pub const fn new(keys: S) -> Self {
        Self {
            keys,
            last_issued: None,
            issued: Vec::new(),
        }
    }

    /// The highest generation consumed so far.
    #[must_use]
    pub const fn last_issued(&self) -> Option<NonZeroU64> {
        self.last_issued
    }

    /// The generation the next build will consume.
    pub fn next_generation(&self) -> Result<NonZeroU64, SequencerError> {
        match self.last_issued {
            None => Ok(NonZeroU64::MIN),
            Some(last) => last
                .checked_add(1)
                .ok_or(SequencerError::GenerationExhausted),
        }
    }

    /// Builds `config` as the next generation with fresh keys.
    ///
    /// This is also the M1 rollback: re-validate the old document and build
    /// it here, then apply the result like any successor.
    pub fn candidate(
        &mut self,
        config: &ValidatedConfigV1,
    ) -> Result<ValidatedCandidate, SequencerError> {
        let generation = self.next_generation()?;
        self.issued
            .try_reserve(1)
            .map_err(|_| SequencerError::HistoryAllocation)?;
        self.last_issued = Some(generation);
        let candidate = candidate_from_config(config, generation, &mut self.keys)
            .map_err(SequencerError::Bridge)?;
        let authority = candidate.authority();
        let keys = IssuedKeys {
            nat44_udp: authority.nat44_udp_hash_key(),
            nat44_tcp: authority.nat44_tcp_hash_key(),
            firewall: authority.firewall_config().hash_key(),
            resolution: authority.resolution_hash_key(),
            nat44_icmp: authority.nat44_icmp_hash_key(),
        };
        for issued in &self.issued {
            let reused = if issued.nat44_udp == keys.nat44_udp {
                Some(RuntimeService::Nat44Udp)
            } else if issued.nat44_tcp == keys.nat44_tcp {
                Some(RuntimeService::Nat44Tcp)
            } else if issued.firewall == keys.firewall {
                Some(RuntimeService::Firewall)
            } else if issued.resolution == keys.resolution {
                Some(RuntimeService::Resolution)
            } else if issued.nat44_icmp.is_some() && issued.nat44_icmp == keys.nat44_icmp {
                Some(RuntimeService::Nat44Icmp)
            } else {
                None
            };
            if let Some(service) = reused {
                return Err(SequencerError::KeyReused(service));
            }
        }
        self.issued.push(keys);
        Ok(candidate)
    }
}

/// The [`PublicationSequencer`] for live traffic.
///
/// Identical generation numbering, key-reuse guard, and rollback semantics,
/// but it can only be built from a sealed [`ProductionKeySource`] (today only
/// [`crate::OsRandomKeySource`]), and [`ProductionSequencer::new`] also
/// asserts at compile time that `S::KIND` is a production kind (never
/// [`crate::KeySourceKind::DeterministicSimulation`]). The production `run` entry
/// point takes this type, never a bare [`PublicationSequencer`]; `run-sim`
/// keeps using [`PublicationSequencer`] with
/// [`crate::SimDeterministicKeySource`].
///
/// ```no_run
/// use ruster_control::{KeySourceError, OsRandomKeySource, ProductionSequencer};
///
/// let sequencer = ProductionSequencer::new(OsRandomKeySource::open()?);
/// assert_eq!(sequencer.last_issued(), None);
/// # Ok::<(), KeySourceError>(())
/// ```
///
/// A simulation source is rejected at compile time:
///
/// ```compile_fail,E0277
/// use ruster_control::{ProductionSequencer, SimDeterministicKeySource};
///
/// let _ = ProductionSequencer::new(SimDeterministicKeySource::new(7));
/// ```
///
/// Like [`PublicationSequencer`] it is not `Clone`:
///
/// ```compile_fail
/// use ruster_control::{OsRandomKeySource, ProductionSequencer};
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<ProductionSequencer<OsRandomKeySource>>();
/// ```
pub struct ProductionSequencer<S: ProductionKeySource> {
    inner: PublicationSequencer<S>,
}

impl<S: ProductionKeySource> ProductionSequencer<S> {
    /// Starts a process-lifetime production sequence at generation 1.
    #[must_use]
    pub const fn new(keys: S) -> Self {
        const {
            assert!(
                S::KIND.is_production(),
                "a production sequencer requires a production key source"
            );
        }
        Self {
            inner: PublicationSequencer::new(keys),
        }
    }

    /// The highest generation consumed so far.
    #[must_use]
    pub const fn last_issued(&self) -> Option<NonZeroU64> {
        self.inner.last_issued()
    }

    /// The generation the next build will consume.
    pub fn next_generation(&self) -> Result<NonZeroU64, SequencerError> {
        self.inner.next_generation()
    }

    /// Builds `config` as the next generation with fresh keys; see
    /// [`PublicationSequencer::candidate`]. A key-source failure consumes the
    /// generation and yields no candidate.
    pub fn candidate(
        &mut self,
        config: &ValidatedConfigV1,
    ) -> Result<ValidatedCandidate, SequencerError> {
        self.inner.candidate(config)
    }
}

impl<S: ProductionKeySource> fmt::Debug for ProductionSequencer<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionSequencer")
            .field("last_issued", &self.inner.last_issued)
            .field("issued_key_sets", &self.inner.issued.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests;

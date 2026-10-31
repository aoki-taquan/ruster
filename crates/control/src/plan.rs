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
//!
//! Across process restarts nothing is remembered: M1 starts from scratch, so
//! a new process restarts numbering at generation 1 with a fresh sequencer
//! and fresh storage. Durable generation/key history is out of scope for M1.

use std::{cmp::Ordering, fmt, num::NonZeroU64};

use ruster_config::{InterfaceBindingV1, ValidatedConfigV1};
use ruster_core::{
    FirewallHashKey, FirewallRule, FirewallRuleId, IfId, Interface, Ipv4Address, LocalIpv4Binding,
    Nat44TcpHashKey, Nat44UdpHashKey, Neighbor, PublicationQuiescence, Route,
};

use crate::{
    candidate_from_config,
    config_bridge::{required_services, RequiredServices},
    ActivePublication, ApplyError, ConfigBridgeError, PublicationKeySource, RestartRequired,
    RuntimeService, ValidatedCandidate,
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

/// Difference of one NAT44 protocol. The policy itself (which includes the
/// allocator seed) is never exposed, only whether it changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct NatChange {
    pub realm: Option<Delta<NatRealm>>,
    pub ports: Option<Delta<NatPortRange>>,
    pub policy_changed: bool,
}

impl NatChange {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.realm.is_none() && self.ports.is_none() && !self.policy_changed
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
/// validation checks them, so a non-empty list predicts the rejection
/// `RestartRequired(restart_required()[0])` for any successor built from
/// `next` with a fresh generation and keys.
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
    nat44_udp: NatChange,
    nat44_tcp: NatChange,
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
            nat44_udp: nat_change(&old, &new, Protocol::Udp),
            nat44_tcp: nat_change(&old, &new, Protocol::Tcp),
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
    pub fn for_active<I: PublicationQuiescence>(
        active: &mut ActivePublication<'_, I>,
        current: &ValidatedConfigV1,
        next: &ValidatedConfigV1,
        successor: &ValidatedCandidate,
    ) -> Result<Self, PlanError> {
        let mut plan = Self::between(current, next)?;
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

    #[must_use]
    pub const fn nat44_udp(&self) -> NatChange {
        self.nat44_udp
    }

    #[must_use]
    pub const fn nat44_tcp(&self) -> NatChange {
        self.nat44_tcp
    }

    /// Reasons the change cannot be applied in place, in successor
    /// validation order. The NAT port-owner table holds exactly one slot per
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
fn diff<T: Copy + Eq, K: Ord>(old: &[T], new: &[T], key: impl Fn(&T) -> K) -> Box<[Change<T>]> {
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
            Ordering::Less => changes.extend(old.next().map(|item| Change::Removed(*item))),
            Ordering::Greater => changes.extend(new.next().map(|item| Change::Added(*item))),
            Ordering::Equal => {
                if let (Some(&old), Some(&new)) = (old.next(), new.next()) {
                    if old != new {
                        changes.push(Change::Changed(Delta { old, new }));
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
    let policy_changed = match protocol {
        Protocol::Udp => old.udp.policy() != new.udp.policy(),
        Protocol::Tcp => old.tcp.policy() != new.tcp.policy(),
    };
    NatChange {
        realm: delta(old_realm, new_realm),
        ports: delta(old_ports, new_ports),
        policy_changed,
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
}

/// Control-owned generation allocator and key-reuse guard.
///
/// Each [`PublicationSequencer::candidate`] call consumes the next
/// generation, whether or not the build succeeds, so no generation is ever
/// issued twice. Every issued key is remembered for the lifetime of the
/// sequencer (three keys per generation, cold path), and a candidate whose
/// UDP, TCP, or firewall key equals any earlier issued key of that service is
/// rejected. A→B→A therefore yields three generations with three distinct key
/// sets even when the key source misbehaves.
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
        };
        for issued in &self.issued {
            let reused = if issued.nat44_udp == keys.nat44_udp {
                Some(RuntimeService::Nat44Udp)
            } else if issued.nat44_tcp == keys.nat44_tcp {
                Some(RuntimeService::Nat44Tcp)
            } else if issued.firewall == keys.firewall {
                Some(RuntimeService::Firewall)
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

#[cfg(test)]
pub(crate) mod tests;

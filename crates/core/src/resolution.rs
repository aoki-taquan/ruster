use std::{marker::PhantomData, rc::Rc};

use crate::{
    GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo,
    Icmpv4ErrorAction, Icmpv4ErrorDisposition, Icmpv4ErrorKind, Icmpv4ErrorRuntime, IfId,
    Ipv4Address, MacAddress, ARP_ETHERTYPE, ICMPV4_ERROR_MAX_QUOTE_LEN, IPV4_ETHERTYPE,
};

pub const ARP_REQUEST_FRAME_LEN: usize = 60;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionPolicyError {
    IntervalTooShort,
    StateTtlTooShort,
    DynamicNeighborTtlZero,
    MaxAttemptsZero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionPolicy {
    interval_ms: u64,
    state_ttl_ms: u64,
    dynamic_neighbor_ttl_ms: u64,
    max_attempts: u16,
}

impl ResolutionPolicy {
    pub fn new(interval_ms: u64, state_ttl_ms: u64) -> Result<Self, ResolutionPolicyError> {
        if interval_ms < 1_000 {
            return Err(ResolutionPolicyError::IntervalTooShort);
        }
        if state_ttl_ms < interval_ms {
            return Err(ResolutionPolicyError::StateTtlTooShort);
        }
        Ok(Self {
            interval_ms,
            state_ttl_ms,
            dynamic_neighbor_ttl_ms: 60_000,
            max_attempts: 3,
        })
    }

    pub fn with_retry(
        interval_ms: u64,
        state_ttl_ms: u64,
        max_attempts: u16,
    ) -> Result<Self, ResolutionPolicyError> {
        if max_attempts == 0 {
            return Err(ResolutionPolicyError::MaxAttemptsZero);
        }
        let mut policy = Self::new(interval_ms, state_ttl_ms)?;
        policy.max_attempts = max_attempts;
        Ok(policy)
    }

    pub fn with_dynamic_neighbor_ttl(
        interval_ms: u64,
        state_ttl_ms: u64,
        dynamic_neighbor_ttl_ms: u64,
    ) -> Result<Self, ResolutionPolicyError> {
        let mut policy = Self::new(interval_ms, state_ttl_ms)?;
        if dynamic_neighbor_ttl_ms == 0 {
            return Err(ResolutionPolicyError::DynamicNeighborTtlZero);
        }
        policy.dynamic_neighbor_ttl_ms = dynamic_neighbor_ttl_ms;
        Ok(policy)
    }

    pub fn with_retry_and_dynamic_neighbor_ttl(
        interval_ms: u64,
        state_ttl_ms: u64,
        max_attempts: u16,
        dynamic_neighbor_ttl_ms: u64,
    ) -> Result<Self, ResolutionPolicyError> {
        let mut policy = Self::with_retry(interval_ms, state_ttl_ms, max_attempts)?;
        if dynamic_neighbor_ttl_ms == 0 {
            return Err(ResolutionPolicyError::DynamicNeighborTtlZero);
        }
        policy.dynamic_neighbor_ttl_ms = dynamic_neighbor_ttl_ms;
        Ok(policy)
    }

    #[must_use]
    pub const fn interval_ms(self) -> u64 {
        self.interval_ms
    }

    #[must_use]
    pub const fn failed_hold_ms(self) -> u64 {
        self.state_ttl_ms
    }

    #[must_use]
    pub const fn max_attempts(self) -> u16 {
        self.max_attempts
    }

    #[must_use]
    pub const fn dynamic_neighbor_ttl_ms(self) -> u64 {
        self.dynamic_neighbor_ttl_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpRequestAction {
    pub egress: IfId,
    pub source_mac: MacAddress,
    pub source_ip: Ipv4Address,
    pub target_ip: Ipv4Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolutionKey {
    egress: IfId,
    target: Ipv4Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueuedAction {
    action: ArpRequestAction,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionPhase {
    InitialQueued,
    Waiting,
    RetryQueued,
    Failed,
    Cooldown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionActionSlot(Option<QueuedAction>);

impl ResolutionActionSlot {
    pub const EMPTY: Self = Self(None);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionStateSlot {
    key: ResolutionKey,
    action: ArpRequestAction,
    generation: u64,
    attempts: u16,
    accepted_attempts: u16,
    requested_at: MonotonicMillis,
    failed_at: MonotonicMillis,
    occupied: bool,
    phase: ResolutionPhase,
    failure_notified: bool,
}

impl ResolutionStateSlot {
    pub const EMPTY: Self = Self {
        key: ResolutionKey {
            egress: IfId(0),
            target: Ipv4Address::from_octets([0; 4]),
        },
        action: ArpRequestAction {
            egress: IfId(0),
            source_mac: MacAddress([0; 6]),
            source_ip: Ipv4Address::from_octets([0; 4]),
            target_ip: Ipv4Address::from_octets([0; 4]),
        },
        generation: 0,
        attempts: 0,
        accepted_attempts: 0,
        requested_at: MonotonicMillis(0),
        failed_at: MonotonicMillis(0),
        occupied: false,
        phase: ResolutionPhase::InitialQueued,
        failure_notified: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicNeighborSlot {
    interface: IfId,
    target: Ipv4Address,
    mac: MacAddress,
    refreshed_at: MonotonicMillis,
    occupied: bool,
}

impl DynamicNeighborSlot {
    pub const EMPTY: Self = Self {
        interface: IfId(0),
        target: Ipv4Address::from_octets([0; 4]),
        mac: MacAddress([0; 6]),
        refreshed_at: MonotonicMillis(0),
        occupied: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicLookup {
    Hit(MacAddress),
    Miss,
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlDisposition {
    Inserted,
    Updated,
    Ignored,
    StaticPreserved,
    CacheFull,
    Probe,
    SenderNotHost,
    LocalAddressPreserved,
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StaticReconcileReport {
    pub dynamic_removed: usize,
    pub states_removed: usize,
    pub actions_removed: usize,
    pub invalid_states_removed: usize,
    pub invalid_actions_removed: usize,
    pub cooldowns_retained: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResolutionPublicationError {
    ActionQueueCapacity,
    ActionQueueHead,
    ActionQueueWindow,
    PendingStateCount,
    PendingFailureHoldCount,
    RuntimeEpochExhausted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionPublicationReport {
    pub states_flushed: usize,
    pub actions_flushed: usize,
    pub dynamic_neighbors_flushed: usize,
    pub failure_holds_flushed: usize,
}

/// Exclusive proof that old resolution authority can be flushed totally.
///
/// A fresh publication conservatively flushes all learned and queued
/// resolution authority. The permit therefore retains no target-owner borrow
/// and cannot become self-referential when that owner moves into its active
/// slot.
///
/// ```compile_fail
/// use ruster_core::ResolutionRuntime;
///
/// fn reborrow<'storage>(runtime: &mut ResolutionRuntime<'storage>) {
///     let permit = runtime.preflight_publication().unwrap();
///     let _ = runtime.pending_actions();
///     permit.commit();
/// }
/// ```
#[must_use]
pub struct ResolutionPublicationPermit<'runtime, 'storage> {
    runtime: &'runtime mut ResolutionRuntime<'storage>,
    next_runtime_epoch: u128,
    preview: ResolutionPublicationReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionResult {
    Queued,
    RetryQueued,
    Suppressed,
    TimedOut,
    Failed,
    StateFull,
    ActionFull,
    ClockRegression,
    ForbiddenTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionStatus {
    pub phase: ResolutionPhase,
    pub attempts: u16,
    pub accepted_attempts: u16,
    pub generation: u64,
    pub requested_at: Option<MonotonicMillis>,
    pub failed_at: Option<MonotonicMillis>,
    pub terminal_notified: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionCounters {
    pub queued: usize,
    pub suppressed: usize,
    pub state_full: usize,
    pub action_full: usize,
    pub clock_regressions: usize,
    pub forbidden_target: usize,
    pub dequeued: usize,
    pub retry_queued: usize,
    pub attempts_committed: usize,
    pub attempts_accepted: usize,
    pub timed_out: usize,
    pub failed_hits: usize,
    pub failures_expired: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionGenerationToken {
    pub egress: IfId,
    pub target: Ipv4Address,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionFailureHoldPhase {
    Empty,
    WaitingForward,
    TerminalReady,
    WaitingReverse,
}

/// A bounded quote-only candidate for a future ICMPv4 Host Unreachable.
///
/// This is deliberately separate from [`ResolutionStateSlot`]. It never owns
/// an RX/TX lease and is not a packet queue: only validated metadata and at
/// most 548 original IPv4 bytes are copied before the original RX is recycled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionFailureHoldSlot {
    phase: ResolutionFailureHoldPhase,
    forward: ResolutionGenerationToken,
    reverse: ResolutionGenerationToken,
    original_source: Ipv4Address,
    original_destination: Ipv4Address,
    forward_source_mac: MacAddress,
    forward_source_ip: Ipv4Address,
    forward_prefix: Ipv4Address,
    forward_prefix_len: u8,
    original_tos: u8,
    quote_len: u16,
    quote: [u8; ICMPV4_ERROR_MAX_QUOTE_LEN],
}

impl ResolutionFailureHoldSlot {
    pub const EMPTY: Self = Self {
        phase: ResolutionFailureHoldPhase::Empty,
        forward: ResolutionGenerationToken {
            egress: IfId(0),
            target: Ipv4Address::from_octets([0; 4]),
            generation: 0,
        },
        reverse: ResolutionGenerationToken {
            egress: IfId(0),
            target: Ipv4Address::from_octets([0; 4]),
            generation: 0,
        },
        original_source: Ipv4Address::from_octets([0; 4]),
        original_destination: Ipv4Address::from_octets([0; 4]),
        forward_source_mac: MacAddress([0; 6]),
        forward_source_ip: Ipv4Address::from_octets([0; 4]),
        forward_prefix: Ipv4Address::from_octets([0; 4]),
        forward_prefix_len: 0,
        original_tos: 0,
        quote_len: 0,
        quote: [0; ICMPV4_ERROR_MAX_QUOTE_LEN],
    };

    #[must_use]
    pub const fn phase(&self) -> ResolutionFailureHoldPhase {
        self.phase
    }

    #[must_use]
    pub const fn forward_token(&self) -> Option<ResolutionGenerationToken> {
        if matches!(self.phase, ResolutionFailureHoldPhase::Empty) {
            None
        } else {
            Some(self.forward)
        }
    }

    #[must_use]
    pub const fn quote_len(&self) -> usize {
        self.quote_len as usize
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionFailureCounters {
    pub captured: usize,
    pub capture_full: usize,
    pub promoted: usize,
    pub no_accepted_arp_request: usize,
    pub cancelled: usize,
    pub reverse_arp_scheduled: usize,
    pub reverse_arp_pending: usize,
    pub reverse_resolution_failed: usize,
    pub same_failed_key: usize,
    pub queued: usize,
    pub retained_transient: usize,
    pub retired_permanent: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionFailureDispatchReport {
    pub scanned: usize,
    pub queued: usize,
    pub retained: usize,
    pub retired: usize,
    pub reverse_arp_scheduled: usize,
    pub reverse_arp_pending: usize,
    pub pending: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionFailureDispatchError {
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionFailureCapture {
    Captured(ResolutionGenerationToken),
    Existing(ResolutionGenerationToken),
    Inactive,
    CapacityFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionFailureTrace {
    Queued {
        forward: ResolutionGenerationToken,
        reverse_egress: IfId,
    },
    ReverseArpScheduled {
        forward: ResolutionGenerationToken,
        reverse: ResolutionGenerationToken,
    },
    ReverseArpPending {
        forward: ResolutionGenerationToken,
        reverse: ResolutionGenerationToken,
    },
    Retained {
        forward: ResolutionGenerationToken,
        disposition: Icmpv4ErrorDisposition,
    },
    ReverseResolutionFailed {
        forward: ResolutionGenerationToken,
        reverse: ResolutionGenerationToken,
    },
    SameFailedKey {
        forward: ResolutionGenerationToken,
    },
    ForwardAuthorityLost {
        forward: ResolutionGenerationToken,
    },
    ClockRegression,
}

pub trait ResolutionFailureTraceSink {
    fn record_resolution_failure(&mut self, event: ResolutionFailureTrace);
}

#[derive(Default)]
pub struct NoResolutionFailureTrace;

impl ResolutionFailureTraceSink for NoResolutionFailureTrace {
    fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionTimerReport {
    pub scanned: usize,
    pub retries_queued: usize,
    pub timed_out: usize,
    pub no_accepted_arp_request: usize,
    pub failures_expired: usize,
    pub action_full: usize,
    pub deferred_due: usize,
    pub pending: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionTimerError {
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionTimerTrace {
    RetryQueued {
        egress: IfId,
        target: Ipv4Address,
        attempts: u16,
        generation: u64,
    },
    TimedOut {
        egress: IfId,
        target: Ipv4Address,
        attempts: u16,
        generation: u64,
    },
    NoAcceptedArpRequest {
        egress: IfId,
        target: Ipv4Address,
        generation: u64,
    },
    FailureExpired {
        egress: IfId,
        target: Ipv4Address,
        generation: u64,
    },
    ActionFull {
        egress: IfId,
        target: Ipv4Address,
        attempts: u16,
        generation: u64,
    },
    ClockRegression,
}

pub trait ResolutionTimerTraceSink {
    fn record_resolution_timer(&mut self, event: ResolutionTimerTrace);
}

#[derive(Default)]
pub struct NoResolutionTimerTrace;

impl ResolutionTimerTraceSink for NoResolutionTimerTrace {
    #[inline]
    fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
}

/// Caller-backed worker-local resolution state.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::ResolutionRuntime<'static>>();
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<ruster_core::ResolutionRuntime<'static>>();
/// ```
pub struct ResolutionRuntime<'a> {
    policy: ResolutionPolicy,
    states: &'a mut [ResolutionStateSlot],
    actions: &'a mut [ResolutionActionSlot],
    dynamic_neighbors: &'a mut [DynamicNeighborSlot],
    failure_holds: &'a mut [ResolutionFailureHoldSlot],
    head: usize,
    len: usize,
    pending_state_count: usize,
    pending_failure_hold_count: usize,
    poll_cursor: usize,
    failure_cursor: usize,
    last_now: Option<MonotonicMillis>,
    publication_epoch: u128,
    counters: ResolutionCounters,
    failure_counters: ResolutionFailureCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> ResolutionRuntime<'a> {
    #[must_use]
    pub fn new(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
    ) -> Self {
        Self::with_dynamic_neighbors(policy, states, action_storage, &mut [])
    }

    #[must_use]
    pub fn with_dynamic_neighbors(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
        dynamic_neighbors: &'a mut [DynamicNeighborSlot],
    ) -> Self {
        Self::with_dynamic_neighbors_and_failure_holds(
            policy,
            states,
            action_storage,
            dynamic_neighbors,
            &mut [],
        )
    }

    #[must_use]
    pub fn with_dynamic_neighbors_and_failure_holds(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
        dynamic_neighbors: &'a mut [DynamicNeighborSlot],
        failure_holds: &'a mut [ResolutionFailureHoldSlot],
    ) -> Self {
        states.fill(ResolutionStateSlot::EMPTY);
        action_storage.fill(ResolutionActionSlot::EMPTY);
        dynamic_neighbors.fill(DynamicNeighborSlot::EMPTY);
        failure_holds.fill(ResolutionFailureHoldSlot::EMPTY);
        Self {
            policy,
            states,
            actions: action_storage,
            dynamic_neighbors,
            failure_holds,
            head: 0,
            len: 0,
            pending_state_count: 0,
            pending_failure_hold_count: 0,
            poll_cursor: 0,
            failure_cursor: 0,
            last_now: None,
            publication_epoch: 1,
            counters: ResolutionCounters::default(),
            failure_counters: ResolutionFailureCounters::default(),
            _worker_local: PhantomData,
        }
    }

    #[must_use]
    pub fn dynamic_neighbor_count(&self) -> usize {
        self.dynamic_neighbors
            .iter()
            .filter(|slot| slot.occupied)
            .count()
    }

    #[must_use]
    pub const fn policy(&self) -> ResolutionPolicy {
        self.policy
    }

    #[must_use]
    pub const fn state_capacity(&self) -> usize {
        self.states.len()
    }

    #[must_use]
    pub const fn action_capacity(&self) -> usize {
        self.actions.len()
    }

    #[must_use]
    pub const fn dynamic_neighbor_capacity(&self) -> usize {
        self.dynamic_neighbors.len()
    }

    #[must_use]
    pub const fn failure_hold_capacity(&self) -> usize {
        self.failure_holds.len()
    }

    /// Returns whether this runtime is still in its exact constructor state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.states
            .iter()
            .all(|slot| *slot == ResolutionStateSlot::EMPTY)
            && self
                .actions
                .iter()
                .all(|slot| *slot == ResolutionActionSlot::EMPTY)
            && self
                .dynamic_neighbors
                .iter()
                .all(|slot| *slot == DynamicNeighborSlot::EMPTY)
            && self
                .failure_holds
                .iter()
                .all(|slot| *slot == ResolutionFailureHoldSlot::EMPTY)
            && self.head == 0
            && self.len == 0
            && self.pending_state_count == 0
            && self.pending_failure_hold_count == 0
            && self.poll_cursor == 0
            && self.failure_cursor == 0
            && self.last_now.is_none()
            && self.publication_epoch == 1
            && self.counters == ResolutionCounters::default()
            && self.failure_counters == ResolutionFailureCounters::default()
    }

    /// Validates queue/accounting invariants and previews one publication.
    ///
    /// Preflight never mutates runtime state. The returned permit retains the
    /// exact runtime exclusively until it is committed or dropped.
    pub fn preflight_publication<'runtime>(
        &'runtime mut self,
    ) -> Result<ResolutionPublicationPermit<'runtime, 'a>, ResolutionPublicationError> {
        self.validate_publication_invariants()?;
        let next_runtime_epoch = self
            .publication_epoch
            .checked_add(1)
            .ok_or(ResolutionPublicationError::RuntimeEpochExhausted)?;
        let preview = ResolutionPublicationReport {
            states_flushed: self.states.iter().filter(|state| state.occupied).count(),
            actions_flushed: self.len,
            dynamic_neighbors_flushed: self
                .dynamic_neighbors
                .iter()
                .filter(|slot| slot.occupied)
                .count(),
            failure_holds_flushed: self
                .failure_holds
                .iter()
                .filter(|hold| hold.phase != ResolutionFailureHoldPhase::Empty)
                .count(),
        };
        Ok(ResolutionPublicationPermit {
            runtime: self,
            next_runtime_epoch,
            preview,
        })
    }

    /// Removes worker-local state shadowed by a newly published static set.
    ///
    /// The owner must call this on the same worker tick that publishes the
    /// corresponding immutable forwarding snapshot, before processing another
    /// packet with that snapshot.
    pub fn reconcile_static(&mut self, neighbors: &[crate::Neighbor]) -> StaticReconcileReport {
        let mut report = StaticReconcileReport::default();
        for slot in &mut *self.dynamic_neighbors {
            if slot.occupied
                && neighbors.iter().any(|neighbor| {
                    neighbor.interface == slot.interface && neighbor.target == slot.target
                })
            {
                *slot = DynamicNeighborSlot::EMPTY;
                report.dynamic_removed += 1;
            }
        }
        for index in 0..self.states.len() {
            if self.states[index].occupied
                && self.states[index].phase != ResolutionPhase::Cooldown
                && neighbors.iter().any(|neighbor| {
                    neighbor.interface == self.states[index].key.egress
                        && neighbor.target == self.states[index].key.target
                })
            {
                if self.states[index].attempts != 0 {
                    report.cooldowns_retained += 1;
                }
                self.cancel_state_at(index);
                report.states_removed += 1;
            }
        }
        report.actions_removed = self.compact_actions(|action| {
            neighbors.iter().any(|neighbor| {
                neighbor.interface == action.egress && neighbor.target == action.target_ip
            })
        });
        for index in 0..self.failure_holds.len() {
            if self.failure_holds[index].phase != ResolutionFailureHoldPhase::Empty
                && neighbors.iter().any(|neighbor| {
                    neighbor.interface == self.failure_holds[index].forward.egress
                        && neighbor.target == self.failure_holds[index].forward.target
                })
            {
                self.clear_failure_hold(index);
                self.failure_counters.cancelled += 1;
            }
        }
        report
    }

    /// Reconciles resolution authority with a newly published snapshot.
    ///
    /// The owner must publish the snapshot and call this method on the same
    /// worker tick, before timer polling or packet processing. Static
    /// resolution and changed/removed interface, binding, route, or target
    /// authority cancel matching states and actions atomically.
    pub fn reconcile_publication(
        &mut self,
        snapshot: &crate::ForwardingSnapshot<'_>,
    ) -> StaticReconcileReport {
        self.commit_publication(snapshot)
    }

    fn validate_publication_invariants(&self) -> Result<(), ResolutionPublicationError> {
        if self.len > self.actions.len() {
            return Err(ResolutionPublicationError::ActionQueueCapacity);
        }
        if self.actions.is_empty() {
            if self.head != 0 || self.len != 0 {
                return Err(ResolutionPublicationError::ActionQueueHead);
            }
        } else if self.head >= self.actions.len() {
            return Err(ResolutionPublicationError::ActionQueueHead);
        }
        for index in 0..self.actions.len() {
            let distance = (index + self.actions.len() - self.head) % self.actions.len();
            if self.actions[index].0.is_some() != (distance < self.len) {
                return Err(ResolutionPublicationError::ActionQueueWindow);
            }
        }
        let pending_states = self
            .states
            .iter()
            .filter(|state| state_is_pending(**state))
            .count();
        if pending_states != self.pending_state_count {
            return Err(ResolutionPublicationError::PendingStateCount);
        }
        let pending_holds = self
            .failure_holds
            .iter()
            .filter(|hold| hold.phase != ResolutionFailureHoldPhase::Empty)
            .count();
        if pending_holds != self.pending_failure_hold_count {
            return Err(ResolutionPublicationError::PendingFailureHoldCount);
        }
        Ok(())
    }

    fn commit_publication(
        &mut self,
        snapshot: &crate::ForwardingSnapshot<'_>,
    ) -> StaticReconcileReport {
        let mut report = StaticReconcileReport::default();
        for slot in &mut *self.dynamic_neighbors {
            if slot.occupied
                && snapshot.neighbors.iter().any(|neighbor| {
                    neighbor.interface == slot.interface && neighbor.target == slot.target
                })
            {
                *slot = DynamicNeighborSlot::EMPTY;
                report.dynamic_removed = report.dynamic_removed.saturating_add(1);
            }
        }
        for index in 0..self.states.len() {
            let state = self.states[index];
            if !state_is_pending(state) {
                continue;
            }
            let authority = snapshot.resolution_action_authority(state.action);
            if authority == crate::forwarding::ResolutionActionAuthority::Valid {
                continue;
            }
            if state.attempts != 0 {
                report.cooldowns_retained = report.cooldowns_retained.saturating_add(1);
            }
            if cancel_state(&mut self.states[index]) {
                self.pending_state_count = self.pending_state_count.saturating_sub(1);
            }
            match authority {
                crate::forwarding::ResolutionActionAuthority::StaticResolved => {
                    report.states_removed = report.states_removed.saturating_add(1);
                }
                crate::forwarding::ResolutionActionAuthority::Invalid => {
                    report.invalid_states_removed = report.invalid_states_removed.saturating_add(1);
                }
                crate::forwarding::ResolutionActionAuthority::Valid => {}
            }
        }
        let (static_removed, invalid_removed) = self.compact_publication_actions(snapshot);
        report.actions_removed = static_removed;
        report.invalid_actions_removed = invalid_removed;
        for index in 0..self.failure_holds.len() {
            let hold = self.failure_holds[index];
            if hold.phase == ResolutionFailureHoldPhase::Empty
                || publication_hold_valid(snapshot, hold)
            {
                continue;
            }
            self.failure_holds[index] = ResolutionFailureHoldSlot::EMPTY;
            self.pending_failure_hold_count = self.pending_failure_hold_count.saturating_sub(1);
            self.failure_counters.cancelled = self.failure_counters.cancelled.saturating_add(1);
        }
        report
    }

    fn compact_publication_actions(
        &mut self,
        snapshot: &crate::ForwardingSnapshot<'_>,
    ) -> (usize, usize) {
        if self.actions.is_empty() {
            self.head = 0;
            self.len = 0;
            return (0, 0);
        }
        let capacity = self.actions.len();
        let head = self.head % capacity;
        let old_len = self.len.min(capacity);
        let mut retained = 0usize;
        let mut static_removed = 0usize;
        let mut invalid_removed = 0usize;
        for offset in 0..old_len {
            let read_index = (head + offset) % capacity;
            let Some(queued) = self.actions[read_index].0.take() else {
                continue;
            };
            match snapshot.resolution_action_authority(queued.action) {
                crate::forwarding::ResolutionActionAuthority::Valid => {
                    let write_index = (head + retained) % capacity;
                    self.actions[write_index].0 = Some(queued);
                    retained = retained.saturating_add(1);
                }
                crate::forwarding::ResolutionActionAuthority::StaticResolved => {
                    static_removed = static_removed.saturating_add(1);
                }
                crate::forwarding::ResolutionActionAuthority::Invalid => {
                    invalid_removed = invalid_removed.saturating_add(1);
                }
            }
        }
        for index in 0..capacity {
            let distance = (index + capacity - head) % capacity;
            if distance >= retained {
                self.actions[index] = ResolutionActionSlot::EMPTY;
            }
        }
        self.head = if retained == 0 { 0 } else { head };
        self.len = retained;
        (static_removed, invalid_removed)
    }

    #[must_use]
    pub const fn counters(&self) -> ResolutionCounters {
        self.counters
    }

    #[must_use]
    pub const fn failure_counters(&self) -> ResolutionFailureCounters {
        self.failure_counters
    }

    #[must_use]
    pub const fn pending_failure_holds(&self) -> usize {
        self.pending_failure_hold_count
    }

    #[must_use]
    pub const fn pending_actions(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn pending_states(&self) -> usize {
        self.pending_state_count
    }

    #[must_use]
    pub fn cooldown_count(&self) -> usize {
        self.states
            .iter()
            .filter(|state| state.occupied && state.phase == ResolutionPhase::Cooldown)
            .count()
    }

    #[must_use]
    pub fn status(&self, egress: IfId, target: Ipv4Address) -> Option<ResolutionStatus> {
        self.states
            .iter()
            .find(|state| {
                state.occupied && state.key.egress == egress && state.key.target == target
            })
            .map(|state| ResolutionStatus {
                phase: state.phase,
                attempts: state.attempts,
                accepted_attempts: state.accepted_attempts,
                generation: state.generation,
                requested_at: (state.attempts != 0).then_some(state.requested_at),
                failed_at: (state.phase == ResolutionPhase::Failed).then_some(state.failed_at),
                terminal_notified: state.failure_notified,
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture_failure_candidate(
        &mut self,
        egress: IfId,
        target: Ipv4Address,
        source: Ipv4Address,
        destination: Ipv4Address,
        forward_source_mac: MacAddress,
        forward_source_ip: Ipv4Address,
        forward_prefix: Ipv4Address,
        forward_prefix_len: u8,
        original_tos: u8,
        original_ipv4: &[u8],
    ) -> ResolutionFailureCapture {
        let Some(state) = self.states.iter().find(|state| {
            state.occupied
                && state.key.egress == egress
                && state.key.target == target
                && matches!(
                    state.phase,
                    ResolutionPhase::InitialQueued
                        | ResolutionPhase::Waiting
                        | ResolutionPhase::RetryQueued
                )
        }) else {
            return ResolutionFailureCapture::Inactive;
        };
        let token = ResolutionGenerationToken {
            egress,
            target,
            generation: state.generation,
        };
        if self
            .failure_holds
            .iter()
            .any(|hold| hold.phase != ResolutionFailureHoldPhase::Empty && hold.forward == token)
        {
            return ResolutionFailureCapture::Existing(token);
        }
        let Some(index) = self
            .failure_holds
            .iter()
            .position(|hold| hold.phase == ResolutionFailureHoldPhase::Empty)
        else {
            self.failure_counters.capture_full += 1;
            return ResolutionFailureCapture::CapacityFull;
        };
        let quote_len = original_ipv4.len().min(ICMPV4_ERROR_MAX_QUOTE_LEN);
        let slot = &mut self.failure_holds[index];
        *slot = ResolutionFailureHoldSlot::EMPTY;
        slot.phase = ResolutionFailureHoldPhase::WaitingForward;
        slot.forward = token;
        slot.original_source = source;
        slot.original_destination = destination;
        slot.forward_source_mac = forward_source_mac;
        slot.forward_source_ip = forward_source_ip;
        slot.forward_prefix = forward_prefix;
        slot.forward_prefix_len = forward_prefix_len;
        slot.original_tos = original_tos;
        slot.quote_len = quote_len as u16;
        slot.quote[..quote_len].copy_from_slice(&original_ipv4[..quote_len]);
        debug_assert!(self.pending_failure_hold_count < self.failure_holds.len());
        self.pending_failure_hold_count += 1;
        self.failure_counters.captured += 1;
        ResolutionFailureCapture::Captured(token)
    }

    pub(crate) fn schedule(
        &mut self,
        action: ArpRequestAction,
        now: MonotonicMillis,
        forbidden_by_snapshot: bool,
    ) -> ResolutionResult {
        if !self.observe_now(now) {
            return ResolutionResult::ClockRegression;
        }
        if forbidden_by_snapshot
            || action.target_ip == action.source_ip
            || forbidden_target(action.target_ip)
        {
            self.counters.forbidden_target += 1;
            return ResolutionResult::ForbiddenTarget;
        }
        let key = ResolutionKey {
            egress: action.egress,
            target: action.target_ip,
        };
        let existing = self
            .states
            .iter()
            .position(|slot| slot.occupied && slot.key == key);
        if let Some(index) = existing {
            match self.states[index].phase {
                ResolutionPhase::InitialQueued | ResolutionPhase::RetryQueued => {
                    self.counters.suppressed += 1;
                    return ResolutionResult::Suppressed;
                }
                ResolutionPhase::Waiting => {
                    if now.0 - self.states[index].requested_at.0 < self.policy.interval_ms {
                        self.counters.suppressed += 1;
                        return ResolutionResult::Suppressed;
                    }
                    if self.states[index].attempts >= self.policy.max_attempts {
                        return self.mark_failed(index, now);
                    }
                    if self.len == self.actions.len() {
                        self.counters.action_full += 1;
                        return ResolutionResult::ActionFull;
                    }
                    self.states[index].action = action;
                    return self.enqueue_retry(index);
                }
                ResolutionPhase::Failed => {
                    if now.0 - self.states[index].failed_at.0 < self.policy.state_ttl_ms {
                        self.counters.failed_hits += 1;
                        return ResolutionResult::Failed;
                    }
                    if self.len == self.actions.len() {
                        self.counters.action_full += 1;
                        return ResolutionResult::ActionFull;
                    }
                    self.counters.failures_expired += 1;
                    let expired = ResolutionGenerationToken {
                        egress: self.states[index].key.egress,
                        target: self.states[index].key.target,
                        generation: self.states[index].generation,
                    };
                    for hold_index in 0..self.failure_holds.len() {
                        let hold = self.failure_holds[hold_index];
                        if hold.phase != ResolutionFailureHoldPhase::Empty
                            && (hold.forward == expired
                                || (hold.phase == ResolutionFailureHoldPhase::WaitingReverse
                                    && hold.reverse == expired))
                        {
                            self.clear_failure_hold(hold_index);
                            self.failure_counters.cancelled += 1;
                        }
                    }
                    self.start_cycle(index, action);
                    return self.enqueue_initial(index);
                }
                ResolutionPhase::Cooldown => {
                    if now.0 - self.states[index].requested_at.0 < self.policy.interval_ms {
                        self.counters.suppressed += 1;
                        return ResolutionResult::Suppressed;
                    }
                    if self.len == self.actions.len() {
                        self.counters.action_full += 1;
                        return ResolutionResult::ActionFull;
                    }
                    self.start_cycle(index, action);
                    return self.enqueue_initial(index);
                }
            }
        }
        let reusable = self.states.iter().position(|slot| {
            !slot.occupied
                || (slot.phase == ResolutionPhase::Cooldown
                    && now.0 - slot.requested_at.0 >= self.policy.interval_ms)
        });
        let Some(index) = reusable else {
            self.counters.state_full += 1;
            return ResolutionResult::StateFull;
        };
        if self.len == self.actions.len() {
            self.counters.action_full += 1;
            return ResolutionResult::ActionFull;
        }
        self.start_cycle(index, action);
        debug_assert_eq!(self.states[index].key, key);
        self.enqueue_initial(index)
    }

    pub(crate) fn lookup_dynamic(
        &mut self,
        interface: IfId,
        target: Ipv4Address,
        now: MonotonicMillis,
    ) -> DynamicLookup {
        if !self.observe_now(now) {
            return DynamicLookup::ClockRegression;
        }
        let Some(slot) = self
            .dynamic_neighbors
            .iter_mut()
            .find(|slot| slot.occupied && slot.interface == interface && slot.target == target)
        else {
            return DynamicLookup::Miss;
        };
        if now.0 - slot.refreshed_at.0 >= self.policy.dynamic_neighbor_ttl_ms {
            *slot = DynamicNeighborSlot::EMPTY;
            DynamicLookup::Miss
        } else {
            DynamicLookup::Hit(slot.mac)
        }
    }

    pub(crate) fn merge_dynamic(
        &mut self,
        interface: IfId,
        sender: Ipv4Address,
        mac: MacAddress,
        allow_insert: bool,
        static_key: bool,
        now: MonotonicMillis,
    ) -> ControlDisposition {
        if !self.observe_now(now) {
            return ControlDisposition::ClockRegression;
        }
        if static_key {
            self.reconcile_static_key(interface, sender);
            return ControlDisposition::StaticPreserved;
        }
        if let Some(index) = self
            .dynamic_neighbors
            .iter()
            .position(|slot| slot.occupied && slot.interface == interface && slot.target == sender)
        {
            if now.0 - self.dynamic_neighbors[index].refreshed_at.0
                < self.policy.dynamic_neighbor_ttl_ms
            {
                self.dynamic_neighbors[index].mac = mac;
                self.dynamic_neighbors[index].refreshed_at = now;
                self.clear_resolution(interface, sender);
                return ControlDisposition::Updated;
            }
            self.dynamic_neighbors[index] = DynamicNeighborSlot::EMPTY;
        }
        if !allow_insert {
            return ControlDisposition::Ignored;
        }
        let reusable = self.dynamic_neighbors.iter().position(|slot| {
            !slot.occupied || now.0 - slot.refreshed_at.0 >= self.policy.dynamic_neighbor_ttl_ms
        });
        let Some(index) = reusable else {
            return ControlDisposition::CacheFull;
        };
        self.dynamic_neighbors[index] = DynamicNeighborSlot {
            interface,
            target: sender,
            mac,
            refreshed_at: now,
            occupied: true,
        };
        self.clear_resolution(interface, sender);
        ControlDisposition::Inserted
    }

    fn observe_now(&mut self, now: MonotonicMillis) -> bool {
        if self.last_now.is_some_and(|last| now < last) {
            self.counters.clock_regressions += 1;
            return false;
        }
        self.last_now = Some(now);
        true
    }

    pub(crate) fn observe_control(&mut self, now: MonotonicMillis) -> bool {
        self.observe_now(now)
    }

    fn clear_resolution(&mut self, interface: IfId, target: Ipv4Address) {
        for index in 0..self.states.len() {
            let state = self.states[index];
            if state.occupied && state.key.egress == interface && state.key.target == target {
                self.cancel_state_at(index);
            }
        }
        self.compact_actions(|action| action.egress == interface && action.target_ip == target);
        self.cancel_forward_holds(interface, target);
    }

    fn reconcile_static_key(&mut self, interface: IfId, target: Ipv4Address) {
        for slot in &mut *self.dynamic_neighbors {
            if slot.occupied && slot.interface == interface && slot.target == target {
                *slot = DynamicNeighborSlot::EMPTY;
            }
        }
        self.clear_resolution(interface, target);
    }

    fn compact_actions(&mut self, remove: impl Fn(ArpRequestAction) -> bool) -> usize {
        self.compact_queued_actions(|queued| remove(queued.action))
    }

    fn compact_queued_actions(&mut self, mut remove: impl FnMut(QueuedAction) -> bool) -> usize {
        if self.actions.is_empty() {
            return 0;
        }
        let old_len = self.len;
        let mut retained = 0;
        for read in 0..old_len {
            let read_index = (self.head + read) % self.actions.len();
            let Some(queued) = self.actions[read_index].0.take() else {
                continue;
            };
            if remove(queued) {
                continue;
            }
            let write_index = (self.head + retained) % self.actions.len();
            self.actions[write_index].0 = Some(queued);
            retained += 1;
        }
        self.len = retained;
        old_len.saturating_sub(retained)
    }

    fn cancel_state_at(&mut self, index: usize) {
        if cancel_state(&mut self.states[index]) {
            debug_assert!(self.pending_state_count != 0);
            self.pending_state_count -= 1;
        }
    }

    fn vacate_state_at(&mut self, index: usize) {
        let was_pending = state_is_pending(self.states[index]);
        vacate_state(&mut self.states[index]);
        if was_pending {
            debug_assert!(self.pending_state_count != 0);
            self.pending_state_count -= 1;
        }
    }

    fn clear_failure_hold(&mut self, index: usize) {
        debug_assert!(
            self.failure_holds[index].phase != ResolutionFailureHoldPhase::Empty,
            "only a live failure hold can be cleared"
        );
        self.failure_holds[index] = ResolutionFailureHoldSlot::EMPTY;
        debug_assert!(self.pending_failure_hold_count != 0);
        self.pending_failure_hold_count -= 1;
    }

    fn start_cycle(&mut self, index: usize, action: ArpRequestAction) {
        let was_pending = state_is_pending(self.states[index]);
        let generation = self.next_generation(
            action.egress,
            action.target_ip,
            self.states[index].generation,
        );
        self.states[index] = ResolutionStateSlot {
            key: ResolutionKey {
                egress: action.egress,
                target: action.target_ip,
            },
            action,
            generation,
            attempts: 0,
            accepted_attempts: 0,
            requested_at: MonotonicMillis(0),
            failed_at: MonotonicMillis(0),
            occupied: true,
            phase: ResolutionPhase::InitialQueued,
            failure_notified: false,
        };
        if !was_pending {
            debug_assert!(self.pending_state_count < self.states.len());
            self.pending_state_count += 1;
        }
    }

    fn enqueue_initial(&mut self, index: usize) -> ResolutionResult {
        debug_assert_eq!(self.states[index].attempts, 0);
        debug_assert_eq!(self.states[index].phase, ResolutionPhase::InitialQueued);
        self.enqueue_state_action(index);
        self.counters.queued += 1;
        ResolutionResult::Queued
    }

    fn enqueue_retry(&mut self, index: usize) -> ResolutionResult {
        if self.len == self.actions.len() {
            self.counters.action_full += 1;
            return ResolutionResult::ActionFull;
        }
        self.states[index].phase = ResolutionPhase::RetryQueued;
        self.enqueue_state_action(index);
        self.counters.queued += 1;
        self.counters.retry_queued += 1;
        ResolutionResult::RetryQueued
    }

    fn enqueue_state_action(&mut self, index: usize) {
        debug_assert!(self.len < self.actions.len());
        let action = self.states[index].action;
        let generation = self.states[index].generation;
        let tail = (self.head + self.len) % self.actions.len();
        self.actions[tail].0 = Some(QueuedAction { action, generation });
        self.len += 1;
    }

    fn mark_failed(&mut self, index: usize, now: MonotonicMillis) -> ResolutionResult {
        debug_assert_eq!(self.states[index].phase, ResolutionPhase::Waiting);
        debug_assert!(self.states[index].attempts >= self.policy.max_attempts);
        self.states[index].phase = ResolutionPhase::Failed;
        self.states[index].failed_at = now;
        self.states[index].failure_notified = true;
        self.counters.timed_out += 1;
        let token = ResolutionGenerationToken {
            egress: self.states[index].key.egress,
            target: self.states[index].key.target,
            generation: self.states[index].generation,
        };
        if self.states[index].accepted_attempts == 0 {
            for hold_index in 0..self.failure_holds.len() {
                let hold = self.failure_holds[hold_index];
                if hold.phase == ResolutionFailureHoldPhase::WaitingForward && hold.forward == token
                {
                    self.clear_failure_hold(hold_index);
                    self.failure_counters.no_accepted_arp_request += 1;
                }
            }
        } else {
            for hold in &mut *self.failure_holds {
                if hold.phase == ResolutionFailureHoldPhase::WaitingForward && hold.forward == token
                {
                    hold.phase = ResolutionFailureHoldPhase::TerminalReady;
                    self.failure_counters.promoted += 1;
                }
            }
        }
        ResolutionResult::TimedOut
    }

    fn front(&self) -> Option<QueuedAction> {
        self.actions.get(self.head).and_then(|item| item.0)
    }

    fn execution_time_valid(&mut self, now: MonotonicMillis) -> bool {
        self.observe_now(now)
    }

    fn committed(&mut self, queued: QueuedAction, now: MonotonicMillis) {
        let item = self.actions[self.head]
            .0
            .take()
            .expect("committed action is queue front");
        debug_assert_eq!(item, queued);
        self.head = (self.head + 1) % self.actions.len();
        self.len -= 1;
        self.counters.dequeued += 1;
        if let Some(state) = self.states.iter_mut().find(|state| {
            state.occupied
                && state.key.egress == queued.action.egress
                && state.key.target == queued.action.target_ip
                && state.generation == queued.generation
        }) {
            debug_assert!(matches!(
                state.phase,
                ResolutionPhase::InitialQueued | ResolutionPhase::RetryQueued
            ));
            debug_assert!(state.attempts < self.policy.max_attempts);
            state.attempts += 1;
            state.phase = ResolutionPhase::Waiting;
            state.requested_at = now;
            self.counters.attempts_committed += 1;
        }
    }

    fn accepted(&mut self, queued: QueuedAction, accepted: usize) {
        if accepted == 0 {
            return;
        }
        if let Some(state) = self.states.iter_mut().find(|state| {
            state.occupied
                && state.key.egress == queued.action.egress
                && state.key.target == queued.action.target_ip
                && state.generation == queued.generation
        }) {
            state.accepted_attempts = state.accepted_attempts.saturating_add(accepted as u16);
            self.counters.attempts_accepted += accepted;
        }
    }

    fn next_generation(&self, egress: IfId, target: Ipv4Address, previous: u64) -> u64 {
        let mut candidate = previous.wrapping_add(1);
        for _ in 0..=self.failure_holds.len() {
            let aliases = self.failure_holds.iter().any(|hold| {
                hold.phase != ResolutionFailureHoldPhase::Empty
                    && ((hold.forward.egress == egress
                        && hold.forward.target == target
                        && hold.forward.generation == candidate)
                        || (hold.phase == ResolutionFailureHoldPhase::WaitingReverse
                            && hold.reverse.egress == egress
                            && hold.reverse.target == target
                            && hold.reverse.generation == candidate))
            });
            if !aliases {
                return candidate;
            }
            candidate = candidate.wrapping_add(1);
        }
        unreachable!("more live tokens than caller-backed hold slots")
    }

    fn cancel_forward_holds(&mut self, egress: IfId, target: Ipv4Address) {
        for index in 0..self.failure_holds.len() {
            let hold = self.failure_holds[index];
            if hold.phase != ResolutionFailureHoldPhase::Empty
                && hold.forward.egress == egress
                && hold.forward.target == target
            {
                self.clear_failure_hold(index);
                self.failure_counters.cancelled += 1;
            }
        }
    }

    fn poll_timers<T: ResolutionTimerTraceSink>(
        &mut self,
        now: MonotonicMillis,
        scan_budget: usize,
        trace: &mut T,
    ) -> Result<ResolutionTimerReport, ResolutionTimerError> {
        if !self.observe_now(now) {
            trace.record_resolution_timer(ResolutionTimerTrace::ClockRegression);
            return Err(ResolutionTimerError::ClockRegression);
        }
        let mut report = ResolutionTimerReport::default();
        if self.states.is_empty() || scan_budget == 0 {
            report.pending = self.pending_states();
            return Ok(report);
        }
        let scans = scan_budget.min(self.states.len());
        for _ in 0..scans {
            let index = self.poll_cursor;
            self.poll_cursor = (self.poll_cursor + 1) % self.states.len();
            report.scanned += 1;
            if !self.states[index].occupied {
                continue;
            }
            match self.states[index].phase {
                ResolutionPhase::InitialQueued | ResolutionPhase::RetryQueued => {}
                ResolutionPhase::Waiting => {
                    if now.0 - self.states[index].requested_at.0 < self.policy.interval_ms {
                        continue;
                    }
                    if self.states[index].attempts >= self.policy.max_attempts {
                        let state = self.states[index];
                        let token = ResolutionGenerationToken {
                            egress: state.key.egress,
                            target: state.key.target,
                            generation: state.generation,
                        };
                        let no_accepted_candidate = state.accepted_attempts == 0
                            && self.failure_holds.iter().any(|hold| {
                                hold.phase == ResolutionFailureHoldPhase::WaitingForward
                                    && hold.forward == token
                            });
                        self.mark_failed(index, now);
                        report.timed_out += 1;
                        trace.record_resolution_timer(ResolutionTimerTrace::TimedOut {
                            egress: state.key.egress,
                            target: state.key.target,
                            attempts: state.attempts,
                            generation: state.generation,
                        });
                        if no_accepted_candidate {
                            report.no_accepted_arp_request += 1;
                            trace.record_resolution_timer(
                                ResolutionTimerTrace::NoAcceptedArpRequest {
                                    egress: state.key.egress,
                                    target: state.key.target,
                                    generation: state.generation,
                                },
                            );
                        }
                    } else if self.len == self.actions.len() {
                        let state = self.states[index];
                        self.counters.action_full += 1;
                        report.action_full += 1;
                        report.deferred_due += 1;
                        trace.record_resolution_timer(ResolutionTimerTrace::ActionFull {
                            egress: state.key.egress,
                            target: state.key.target,
                            attempts: state.attempts,
                            generation: state.generation,
                        });
                    } else {
                        let state = self.states[index];
                        let result = self.enqueue_retry(index);
                        debug_assert_eq!(result, ResolutionResult::RetryQueued);
                        report.retries_queued += 1;
                        trace.record_resolution_timer(ResolutionTimerTrace::RetryQueued {
                            egress: state.key.egress,
                            target: state.key.target,
                            attempts: state.attempts,
                            generation: state.generation,
                        });
                    }
                }
                ResolutionPhase::Failed => {
                    if now.0 - self.states[index].failed_at.0 >= self.policy.state_ttl_ms {
                        let state = self.states[index];
                        let token = ResolutionGenerationToken {
                            egress: state.key.egress,
                            target: state.key.target,
                            generation: state.generation,
                        };
                        for hold_index in 0..self.failure_holds.len() {
                            let hold = self.failure_holds[hold_index];
                            if hold.phase != ResolutionFailureHoldPhase::Empty
                                && (hold.forward == token
                                    || (hold.phase == ResolutionFailureHoldPhase::WaitingReverse
                                        && hold.reverse == token))
                            {
                                self.clear_failure_hold(hold_index);
                                self.failure_counters.cancelled += 1;
                            }
                        }
                        self.vacate_state_at(index);
                        self.counters.failures_expired += 1;
                        report.failures_expired += 1;
                        trace.record_resolution_timer(ResolutionTimerTrace::FailureExpired {
                            egress: state.key.egress,
                            target: state.key.target,
                            generation: state.generation,
                        });
                    }
                }
                ResolutionPhase::Cooldown => {}
            }
        }
        report.pending = self.pending_states();
        Ok(report)
    }
}

impl ResolutionPublicationPermit<'_, '_> {
    #[must_use]
    pub const fn preview(&self) -> ResolutionPublicationReport {
        self.preview
    }

    /// Flushes all old publication authority without failure.
    pub fn commit(self) -> ResolutionPublicationReport {
        self.runtime.states.fill(ResolutionStateSlot::EMPTY);
        self.runtime.actions.fill(ResolutionActionSlot::EMPTY);
        self.runtime
            .dynamic_neighbors
            .fill(DynamicNeighborSlot::EMPTY);
        self.runtime
            .failure_holds
            .fill(ResolutionFailureHoldSlot::EMPTY);
        self.runtime.head = 0;
        self.runtime.len = 0;
        self.runtime.pending_state_count = 0;
        self.runtime.pending_failure_hold_count = 0;
        self.runtime.poll_cursor = 0;
        self.runtime.failure_cursor = 0;
        self.runtime.publication_epoch = self.next_runtime_epoch;
        self.preview
    }
}

fn publication_hold_valid(
    snapshot: &crate::ForwardingSnapshot<'_>,
    hold: ResolutionFailureHoldSlot,
) -> bool {
    crate::route::lookup(snapshot.routes, hold.original_destination).is_some_and(|route| {
        route.egress() == hold.forward.egress
            && route.next_hop().is_none()
            && hold.forward.target == hold.original_destination
            && route.prefix() == hold.forward_prefix
            && route.prefix_len() == hold.forward_prefix_len
    }) && snapshot.interfaces.iter().any(|interface| {
        interface.id == hold.forward.egress && interface.mac == hold.forward_source_mac
    }) && snapshot.local_ipv4.iter().any(|binding| {
        binding.interface == hold.forward.egress && binding.address == hold.forward_source_ip
    }) && !snapshot.neighbors.iter().any(|neighbor| {
        neighbor.interface == hold.forward.egress && neighbor.target == hold.forward.target
    }) && !host_failure_target_forbidden(
        snapshot,
        hold.forward.egress,
        hold.forward.target,
        hold.forward_source_ip,
    )
}

const fn state_is_pending(state: ResolutionStateSlot) -> bool {
    state.occupied && !matches!(state.phase, ResolutionPhase::Cooldown)
}

fn vacate_state(state: &mut ResolutionStateSlot) {
    let generation = state.generation;
    *state = ResolutionStateSlot::EMPTY;
    state.generation = generation;
}

fn cancel_state(state: &mut ResolutionStateSlot) -> bool {
    let was_pending = state_is_pending(*state);
    if state.attempts == 0 {
        vacate_state(state);
        return was_pending;
    }
    let key = state.key;
    let generation = state.generation;
    let attempts = state.attempts;
    let requested_at = state.requested_at;
    *state = ResolutionStateSlot::EMPTY;
    state.key = key;
    state.generation = generation;
    state.attempts = attempts;
    state.requested_at = requested_at;
    state.occupied = true;
    state.phase = ResolutionPhase::Cooldown;
    was_pending
}

/// Advances bounded ARP retry/timeout state without performing packet I/O.
pub fn poll_resolution_timers<T: ResolutionTimerTraceSink>(
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
    scan_budget: usize,
    trace: &mut T,
) -> Result<ResolutionTimerReport, ResolutionTimerError> {
    runtime.poll_timers(now, scan_budget, trace)
}

/// Boundedly promotes fruitless directly-connected ARP generations into
/// ICMPv4 Destination Unreachable, Host Unreachable actions.
///
/// Call after publication reconciliation, RX processing, and resolution timer
/// polling, but before generated ARP and ICMP execution.
pub fn dispatch_host_unreachable_failures<T: ResolutionFailureTraceSink>(
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    now: MonotonicMillis,
    scan_budget: usize,
    trace: &mut T,
) -> Result<ResolutionFailureDispatchReport, ResolutionFailureDispatchError> {
    if !resolution.observe_now(now) {
        trace.record_resolution_failure(ResolutionFailureTrace::ClockRegression);
        return Err(ResolutionFailureDispatchError::ClockRegression);
    }
    let mut report = ResolutionFailureDispatchReport::default();
    if resolution.failure_holds.is_empty() || scan_budget == 0 {
        report.pending = resolution.pending_failure_holds();
        return Ok(report);
    }
    let scans = scan_budget.min(resolution.failure_holds.len());
    for _ in 0..scans {
        let index = resolution.failure_cursor;
        resolution.failure_cursor =
            (resolution.failure_cursor + 1) % resolution.failure_holds.len();
        report.scanned += 1;
        let hold = resolution.failure_holds[index];
        if !matches!(
            hold.phase,
            ResolutionFailureHoldPhase::TerminalReady | ResolutionFailureHoldPhase::WaitingReverse
        ) {
            continue;
        }
        match dispatch_one_failure(resolution, icmpv4_errors, snapshot, now, hold) {
            FailureDispatch::Queued(reverse_egress) => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.queued += 1;
                report.queued += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::Queued {
                    forward: hold.forward,
                    reverse_egress,
                });
            }
            FailureDispatch::WaitReverse {
                reverse,
                newly_scheduled,
            } => {
                resolution.failure_holds[index].phase = ResolutionFailureHoldPhase::WaitingReverse;
                resolution.failure_holds[index].reverse = reverse;
                report.retained += 1;
                if newly_scheduled {
                    resolution.failure_counters.reverse_arp_scheduled += 1;
                    report.reverse_arp_scheduled += 1;
                    trace.record_resolution_failure(ResolutionFailureTrace::ReverseArpScheduled {
                        forward: hold.forward,
                        reverse,
                    });
                } else {
                    resolution.failure_counters.reverse_arp_pending += 1;
                    report.reverse_arp_pending += 1;
                    trace.record_resolution_failure(ResolutionFailureTrace::ReverseArpPending {
                        forward: hold.forward,
                        reverse,
                    });
                }
            }
            FailureDispatch::Retain(disposition) => {
                resolution.failure_counters.retained_transient += 1;
                report.retained += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::Retained {
                    forward: hold.forward,
                    disposition,
                });
            }
            FailureDispatch::ReverseFailed(reverse) => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.reverse_resolution_failed += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::ReverseResolutionFailed {
                    forward: hold.forward,
                    reverse,
                });
            }
            FailureDispatch::SameFailedKey => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.same_failed_key += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::SameFailedKey {
                    forward: hold.forward,
                });
            }
            FailureDispatch::AuthorityLost => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.retired_permanent += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::ForwardAuthorityLost {
                    forward: hold.forward,
                });
            }
        }
    }
    report.pending = resolution.pending_failure_holds();
    Ok(report)
}

enum FailureDispatch {
    Queued(IfId),
    WaitReverse {
        reverse: ResolutionGenerationToken,
        newly_scheduled: bool,
    },
    Retain(Icmpv4ErrorDisposition),
    ReverseFailed(ResolutionGenerationToken),
    SameFailedKey,
    AuthorityLost,
}

fn dispatch_one_failure(
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    now: MonotonicMillis,
    hold: ResolutionFailureHoldSlot,
) -> FailureDispatch {
    let forward_status = resolution.status(hold.forward.egress, hold.forward.target);
    if !forward_status.is_some_and(|status| {
        status.generation == hold.forward.generation
            && status.phase == ResolutionPhase::Failed
            && status.accepted_attempts != 0
    }) {
        return FailureDispatch::AuthorityLost;
    }
    let forward_route = crate::route::lookup(snapshot.routes, hold.original_destination);
    if !forward_route.is_some_and(|route| {
        route.egress() == hold.forward.egress
            && route.next_hop().is_none()
            && hold.forward.target == hold.original_destination
            && route.prefix() == hold.forward_prefix
            && route.prefix_len() == hold.forward_prefix_len
    }) || !snapshot.interfaces.iter().any(|interface| {
        interface.id == hold.forward.egress && interface.mac == hold.forward_source_mac
    }) || !snapshot.local_ipv4.iter().any(|binding| {
        binding.interface == hold.forward.egress && binding.address == hold.forward_source_ip
    }) || snapshot.neighbors.iter().any(|neighbor| {
        neighbor.interface == hold.forward.egress && neighbor.target == hold.forward.target
    }) || host_failure_target_forbidden(
        snapshot,
        hold.forward.egress,
        hold.forward.target,
        hold.forward_source_ip,
    ) {
        return FailureDispatch::AuthorityLost;
    }
    match resolution.lookup_dynamic(hold.forward.egress, hold.forward.target, now) {
        DynamicLookup::Hit(_) | DynamicLookup::ClockRegression => {
            return FailureDispatch::AuthorityLost;
        }
        DynamicLookup::Miss => {}
    }
    if !current_icmp_error_eligible(snapshot, hold) {
        return FailureDispatch::AuthorityLost;
    }

    let Some(reverse_route) = crate::route::lookup(snapshot.routes, hold.original_source) else {
        return FailureDispatch::AuthorityLost;
    };
    let reverse_egress = reverse_route.egress();
    let Some(interface) = snapshot
        .interfaces
        .iter()
        .find(|interface| interface.id == reverse_egress)
    else {
        return FailureDispatch::AuthorityLost;
    };
    let Some(binding) = snapshot
        .local_ipv4
        .iter()
        .find(|binding| binding.interface == reverse_egress)
    else {
        return FailureDispatch::AuthorityLost;
    };
    let target = reverse_route.next_hop().unwrap_or(hold.original_source);
    if host_failure_target_forbidden(snapshot, reverse_egress, target, binding.address) {
        return FailureDispatch::AuthorityLost;
    }
    let reverse_key = ResolutionKey {
        egress: reverse_egress,
        target,
    };
    if reverse_key
        == (ResolutionKey {
            egress: hold.forward.egress,
            target: hold.forward.target,
        })
    {
        return FailureDispatch::SameFailedKey;
    }

    let destination_mac = if let Some(neighbor) = snapshot
        .neighbors
        .iter()
        .find(|neighbor| neighbor.interface == reverse_egress && neighbor.target == target)
    {
        neighbor.mac
    } else {
        match resolution.lookup_dynamic(reverse_egress, target, now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                return FailureDispatch::Retain(Icmpv4ErrorDisposition::ClockRegression);
            }
            DynamicLookup::Miss => {
                if hold.phase == ResolutionFailureHoldPhase::WaitingReverse
                    && hold.reverse.egress == reverse_egress
                    && hold.reverse.target == target
                    && resolution
                        .status(hold.reverse.egress, hold.reverse.target)
                        .is_some_and(|status| {
                            status.generation == hold.reverse.generation
                                && status.phase == ResolutionPhase::Failed
                        })
                {
                    return FailureDispatch::ReverseFailed(hold.reverse);
                }
                let result = resolution.schedule(
                    ArpRequestAction {
                        egress: reverse_egress,
                        source_mac: interface.mac,
                        source_ip: binding.address,
                        target_ip: target,
                    },
                    now,
                    false,
                );
                if matches!(
                    result,
                    ResolutionResult::Failed | ResolutionResult::TimedOut
                ) {
                    if let Some(status) = resolution.status(reverse_egress, target) {
                        return FailureDispatch::ReverseFailed(ResolutionGenerationToken {
                            egress: reverse_egress,
                            target,
                            generation: status.generation,
                        });
                    }
                }
                if resolution
                    .status(reverse_egress, target)
                    .is_some_and(|status| {
                        matches!(
                            status.phase,
                            ResolutionPhase::InitialQueued
                                | ResolutionPhase::RetryQueued
                                | ResolutionPhase::Waiting
                        )
                    })
                {
                    let status = resolution
                        .status(reverse_egress, target)
                        .expect("active status was just observed");
                    return FailureDispatch::WaitReverse {
                        reverse: ResolutionGenerationToken {
                            egress: reverse_egress,
                            target,
                            generation: status.generation,
                        },
                        newly_scheduled: matches!(
                            result,
                            ResolutionResult::Queued | ResolutionResult::RetryQueued
                        ),
                    };
                }
                return FailureDispatch::Retain(
                    Icmpv4ErrorDisposition::ReverseNeighborUnresolved {
                        egress: reverse_egress,
                        target,
                        resolution: result,
                    },
                );
            }
        }
    };

    let disposition = icmpv4_errors.schedule(
        Icmpv4ErrorAction::new_with_kind(
            Icmpv4ErrorKind::DestinationUnreachableHost,
            reverse_egress,
            interface.mac,
            destination_mac,
            binding.address,
            hold.original_source,
            hold.original_tos,
            snapshot.ipv4_origin.default_ttl(),
            &hold.quote[..usize::from(hold.quote_len)],
        ),
        now,
    );
    if matches!(
        disposition,
        Icmpv4ErrorDisposition::HostUnreachableQueued { .. }
    ) {
        FailureDispatch::Queued(reverse_egress)
    } else {
        FailureDispatch::Retain(disposition)
    }
}

fn current_icmp_error_eligible(
    snapshot: &crate::ForwardingSnapshot<'_>,
    hold: ResolutionFailureHoldSlot,
) -> bool {
    let source = hold.original_source.octets();
    source[0] != 0
        && source[0] != 127
        && source[0] < 224
        && !snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == hold.original_source)
        && !crate::route::lookup(snapshot.routes, hold.original_source).is_some_and(|route| {
            route.is_prefix_network_address(hold.original_source)
                || route.is_prefix_directed_broadcast(hold.original_source)
        })
}

fn host_failure_target_forbidden(
    snapshot: &crate::ForwardingSnapshot<'_>,
    egress: IfId,
    target: Ipv4Address,
    local: Ipv4Address,
) -> bool {
    let octets = target.octets();
    octets[0] == 0
        || octets[0] == 127
        || octets[0] >= 224
        || octets == [255; 4]
        || target == local
        || snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == target)
        || snapshot.routes.iter().any(|route| {
            route.egress() == egress
                && (route.is_connected_directed_broadcast(target)
                    || route.is_connected_network_address(target))
        })
}

fn forbidden_target(target: Ipv4Address) -> bool {
    let octets = target.octets();
    octets[0] == 0 || octets[0] == 127 || octets[0] >= 224 || octets == [255; 4]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedArpTrace {
    AllocationFailed(GeneratedAllocationError),
    BuildFailed(ArpRequestBuildError),
    ClockRegression,
    TxRequested { egress: IfId, target: Ipv4Address },
    BatchCompleted { accepted: usize, rejected: usize },
}

pub trait GeneratedTraceSink {
    fn record_generated(&mut self, event: GeneratedArpTrace);
}

#[derive(Default)]
pub struct NoGeneratedTrace;

impl GeneratedTraceSink for NoGeneratedTrace {
    #[inline]
    fn record_generated(&mut self, _event: GeneratedArpTrace) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpRequestBuildError {
    ExactLengthRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecuteArpRequestError {
    ClockRegression,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedArpReport<E> {
    pub action: ArpRequestAction,
    pub allocation_error: Option<GeneratedAllocationError>,
    pub build_error: Option<ArpRequestBuildError>,
    pub completion: GeneratedBatchCompletion<E>,
}

/// Executes at most one queued action. Allocation failure retains the action.
pub fn execute_one_arp_request<I, T>(
    io: &mut I,
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<Option<GeneratedArpReport<I::Error>>, ExecuteArpRequestError>
where
    I: GeneratedPacketIo,
    T: GeneratedTraceSink,
{
    let Some(queued) = runtime.front() else {
        return Ok(None);
    };
    if !runtime.execution_time_valid(now) {
        trace.record_generated(GeneratedArpTrace::ClockRegression);
        return Err(ExecuteArpRequestError::ClockRegression);
    }
    let mut batch = io.begin_generated(queued.action.egress);
    let (allocation_error, build_error, committed) =
        match allocate_arp_request(&mut batch, queued.action) {
            Ok(()) => {
                runtime.committed(queued, now);
                trace.record_generated(GeneratedArpTrace::TxRequested {
                    egress: queued.action.egress,
                    target: queued.action.target_ip,
                });
                (None, None, true)
            }
            Err(ArpRequestGenerationError::Allocation(error)) => {
                trace.record_generated(GeneratedArpTrace::AllocationFailed(error));
                (Some(error), None, false)
            }
            Err(ArpRequestGenerationError::Build(error)) => {
                trace.record_generated(GeneratedArpTrace::BuildFailed(error));
                (None, Some(error), false)
            }
        };
    let completion = batch.finish();
    if committed {
        runtime.accepted(queued, completion.accepted);
    }
    trace.record_generated(GeneratedArpTrace::BatchCompleted {
        accepted: completion.accepted,
        rejected: completion.rejected,
    });
    Ok(Some(GeneratedArpReport {
        action: queued.action,
        allocation_error,
        build_error,
        completion,
    }))
}

enum ArpRequestGenerationError {
    Allocation(GeneratedAllocationError),
    Build(ArpRequestBuildError),
}

fn allocate_arp_request<B: GeneratedPacketBatch>(
    batch: &mut B,
    action: ArpRequestAction,
) -> Result<(), ArpRequestGenerationError> {
    let mut lease = batch
        .allocate(ARP_REQUEST_FRAME_LEN)
        .map_err(ArpRequestGenerationError::Allocation)?;
    if lease.bytes_mut().len() != ARP_REQUEST_FRAME_LEN {
        lease.cancel();
        return Err(ArpRequestGenerationError::Build(
            ArpRequestBuildError::ExactLengthRequired,
        ));
    }
    build_arp_request(lease.bytes_mut(), action);
    lease.commit();
    Ok(())
}

fn build_arp_request(frame: &mut [u8], action: ArpRequestAction) {
    debug_assert_eq!(frame.len(), ARP_REQUEST_FRAME_LEN);
    frame.fill(0);
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&action.source_mac.0);
    frame[12..14].copy_from_slice(&ARP_ETHERTYPE.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&action.source_mac.0);
    frame[28..32].copy_from_slice(&action.source_ip.octets());
    frame[38..42].copy_from_slice(&action.target_ip.octets());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ForwardingSnapshot, Interface, LocalIpv4Binding, Neighbor, Route};

    const WAN: IfId = IfId(2);
    const SOURCE_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
    const SOURCE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);

    fn target(last: u8) -> Ipv4Address {
        Ipv4Address::from_octets([192, 0, 2, last])
    }

    fn action(last: u8) -> ArpRequestAction {
        ArpRequestAction {
            egress: WAN,
            source_mac: SOURCE_MAC,
            source_ip: SOURCE_IP,
            target_ip: target(last),
        }
    }

    fn commit_front(runtime: &mut ResolutionRuntime<'_>, now: u64) {
        let queued = runtime.front().expect("queued action");
        runtime.committed(queued, MonotonicMillis(now));
    }

    fn commit_front_accepted(runtime: &mut ResolutionRuntime<'_>, now: u64) {
        let queued = runtime.front().expect("queued action");
        runtime.committed(queued, MonotonicMillis(now));
        runtime.accepted(queued, 1);
    }

    fn assert_pending_accounting(runtime: &ResolutionRuntime<'_>) {
        assert_eq!(
            runtime.pending_states(),
            runtime
                .states
                .iter()
                .copied()
                .filter(|state| state_is_pending(*state))
                .count()
        );
        assert_eq!(
            runtime.pending_failure_holds(),
            runtime
                .failure_holds
                .iter()
                .filter(|hold| hold.phase != ResolutionFailureHoldPhase::Empty)
                .count()
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RuntimeImage {
        policy: ResolutionPolicy,
        states: Vec<ResolutionStateSlot>,
        actions: Vec<ResolutionActionSlot>,
        dynamic_neighbors: Vec<DynamicNeighborSlot>,
        failure_holds: Vec<ResolutionFailureHoldSlot>,
        head: usize,
        len: usize,
        pending_state_count: usize,
        pending_failure_hold_count: usize,
        poll_cursor: usize,
        failure_cursor: usize,
        last_now: Option<MonotonicMillis>,
        publication_epoch: u128,
        counters: ResolutionCounters,
        failure_counters: ResolutionFailureCounters,
    }

    fn runtime_image(runtime: &ResolutionRuntime<'_>) -> RuntimeImage {
        RuntimeImage {
            policy: runtime.policy,
            states: runtime.states.to_vec(),
            actions: runtime.actions.to_vec(),
            dynamic_neighbors: runtime.dynamic_neighbors.to_vec(),
            failure_holds: runtime.failure_holds.to_vec(),
            head: runtime.head,
            len: runtime.len,
            pending_state_count: runtime.pending_state_count,
            pending_failure_hold_count: runtime.pending_failure_hold_count,
            poll_cursor: runtime.poll_cursor,
            failure_cursor: runtime.failure_cursor,
            last_now: runtime.last_now,
            publication_epoch: runtime.publication_epoch,
            counters: runtime.counters,
            failure_counters: runtime.failure_counters,
        }
    }

    fn assert_publication_error_is_atomic(
        runtime: &mut ResolutionRuntime<'_>,
        expected: ResolutionPublicationError,
    ) {
        let before = runtime_image(runtime);
        assert_eq!(runtime.preflight_publication().err(), Some(expected));
        assert_eq!(runtime_image(runtime), before);
    }

    #[derive(Default)]
    struct TimerTrace {
        events: [Option<ResolutionTimerTrace>; 16],
        len: usize,
    }

    #[test]
    fn publication_preflight_errors_leave_runtime_exactly_unchanged() {
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.len = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::ActionQueueCapacity,
        );

        let mut states = [];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.head = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::ActionQueueHead,
        );

        let mut states = [];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.len = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::ActionQueueWindow,
        );

        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.pending_state_count = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::PendingStateCount,
        );

        let mut states = [];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.pending_failure_hold_count = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::PendingFailureHoldCount,
        );

        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.publication_epoch = u128::MAX;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::RuntimeEpochExhausted,
        );
    }

    #[test]
    fn publication_permit_drop_and_commit_flush_all_authority_without_overflow() {
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 2];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
            &mut holds,
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        commit_front(&mut runtime, 0);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                usize::MAX,
                &mut NoResolutionTimerTrace,
            )
            .unwrap()
            .retries_queued,
            1
        );
        assert_eq!(runtime.head, 1);
        assert_eq!(runtime.len, 2);
        runtime.dynamic_neighbors[0] = DynamicNeighborSlot {
            interface: WAN,
            target: target(9),
            mac: MacAddress([2, 0, 0, 0, 0, 9]),
            refreshed_at: MonotonicMillis(1_000),
            occupied: true,
        };
        runtime.failure_holds[0].phase = ResolutionFailureHoldPhase::TerminalReady;
        runtime.pending_failure_hold_count = 1;
        runtime.counters.queued = usize::MAX;
        runtime.failure_counters.cancelled = usize::MAX;

        let before = runtime_image(&runtime);
        let permit = runtime.preflight_publication().unwrap();
        assert_eq!(
            permit.preview(),
            ResolutionPublicationReport {
                states_flushed: 2,
                actions_flushed: 2,
                dynamic_neighbors_flushed: 1,
                failure_holds_flushed: 1,
            }
        );
        drop(permit);
        assert_eq!(runtime_image(&runtime), before);

        let counters = runtime.counters;
        let failure_counters = runtime.failure_counters;
        let report = runtime.preflight_publication().unwrap().commit();
        assert_eq!(
            report,
            ResolutionPublicationReport {
                states_flushed: 2,
                actions_flushed: 2,
                dynamic_neighbors_flushed: 1,
                failure_holds_flushed: 1,
            }
        );
        assert!(runtime
            .states
            .iter()
            .all(|slot| *slot == ResolutionStateSlot::EMPTY));
        assert!(runtime
            .actions
            .iter()
            .all(|slot| *slot == ResolutionActionSlot::EMPTY));
        assert!(runtime
            .dynamic_neighbors
            .iter()
            .all(|slot| *slot == DynamicNeighborSlot::EMPTY));
        assert!(runtime
            .failure_holds
            .iter()
            .all(|slot| *slot == ResolutionFailureHoldSlot::EMPTY));
        assert_eq!(
            (
                runtime.head,
                runtime.len,
                runtime.pending_state_count,
                runtime.pending_failure_hold_count,
                runtime.poll_cursor,
                runtime.failure_cursor,
                runtime.publication_epoch,
            ),
            (0, 0, 0, 0, 0, 0, 2)
        );
        assert_eq!(runtime.counters, counters);
        assert_eq!(runtime.failure_counters, failure_counters);
    }

    #[test]
    fn publication_zero_capacity_is_total_and_pristine_is_exact() {
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
        );
        assert!(runtime.is_pristine());
        assert_eq!(
            runtime.preflight_publication().unwrap().commit(),
            ResolutionPublicationReport::default()
        );
        assert!(!runtime.is_pristine());

        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
        );
        runtime.states[0].generation = 9;
        assert!(!runtime.is_pristine());
    }

    impl ResolutionTimerTraceSink for TimerTrace {
        fn record_resolution_timer(&mut self, event: ResolutionTimerTrace) {
            self.events[self.len] = Some(event);
            self.len += 1;
        }
    }

    #[test]
    fn exact_three_attempt_timeline_and_max_one_wait_full_interval() {
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        assert_eq!(policy.interval_ms(), 1_000);
        assert_eq!(policy.failed_hold_ms(), 1_000);
        assert_eq!(policy.max_attempts(), 3);
        assert_eq!(policy.dynamic_neighbor_ttl_ms(), 60_000);
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        commit_front(&mut runtime, 0);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(999),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            0
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            1
        );
        commit_front(&mut runtime, 1_000);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(2_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            1
        );
        commit_front(&mut runtime, 2_000);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(2_999),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .timed_out,
            0
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(3_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .timed_out,
            1
        );
        assert_eq!(
            runtime.status(WAN, target(2)).unwrap().phase,
            ResolutionPhase::Failed
        );
        assert_eq!(runtime.counters().attempts_committed, 3);

        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        commit_front(&mut runtime, 0);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(999),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .timed_out,
            0
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .timed_out,
            1
        );
    }

    #[test]
    fn late_poll_queues_only_one_retry_and_rx_timer_order_is_idempotent() {
        for rx_first in [false, true] {
            let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
            let mut states = [ResolutionStateSlot::EMPTY; 1];
            let mut actions = [ResolutionActionSlot::EMPTY; 1];
            let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
            assert_eq!(
                runtime.schedule(action(2), MonotonicMillis(0), false),
                ResolutionResult::Queued
            );
            commit_front(&mut runtime, 0);
            if rx_first {
                assert_eq!(
                    runtime.schedule(action(2), MonotonicMillis(5_000), false),
                    ResolutionResult::RetryQueued
                );
                assert_eq!(
                    poll_resolution_timers(
                        &mut runtime,
                        MonotonicMillis(5_000),
                        1,
                        &mut NoResolutionTimerTrace
                    )
                    .unwrap()
                    .retries_queued,
                    0
                );
            } else {
                assert_eq!(
                    poll_resolution_timers(
                        &mut runtime,
                        MonotonicMillis(5_000),
                        1,
                        &mut NoResolutionTimerTrace
                    )
                    .unwrap()
                    .retries_queued,
                    1
                );
                assert_eq!(
                    runtime.schedule(action(2), MonotonicMillis(5_000), false),
                    ResolutionResult::Suppressed
                );
            }
            assert_eq!(runtime.pending_actions(), 1);
            assert_eq!(runtime.status(WAN, target(2)).unwrap().attempts, 1);
        }
    }

    #[test]
    fn failed_hold_has_one_terminal_transition_and_exact_expiry_new_generation() {
        let policy = ResolutionPolicy::with_retry(1_000, 2_000, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        let first_generation = runtime.status(WAN, target(2)).unwrap().generation;
        commit_front(&mut runtime, 0);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(1_000), false),
            ResolutionResult::TimedOut
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(2_999), false),
            ResolutionResult::Failed
        );
        assert_eq!(runtime.counters().timed_out, 1);
        assert_eq!(runtime.counters().failed_hits, 1);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(3_000), false),
            ResolutionResult::Queued
        );
        let status = runtime.status(WAN, target(2)).unwrap();
        assert_eq!(status.phase, ResolutionPhase::InitialQueued);
        assert_eq!(status.attempts, 0);
        assert_eq!(status.generation, first_generation.wrapping_add(1));
        assert_eq!(runtime.counters().failures_expired, 1);
    }

    #[test]
    fn bounded_round_robin_makes_progress_under_action_pressure() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);
        runtime.schedule(action(3), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);

        let first = poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(1_000),
            1,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!((first.scanned, first.retries_queued), (1, 1));
        let mut trace = TimerTrace::default();
        let second =
            poll_resolution_timers(&mut runtime, MonotonicMillis(1_000), 1, &mut trace).unwrap();
        assert_eq!(
            (
                second.scanned,
                second.retries_queued,
                second.action_full,
                second.deferred_due
            ),
            (1, 0, 1, 1)
        );
        assert!(matches!(
            trace.events[0],
            Some(ResolutionTimerTrace::ActionFull { target: value, .. }) if value == target(3)
        ));
        commit_front(&mut runtime, 1_000);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            0,
            "persistent cursor first scans the other state"
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            1
        );
        assert_eq!(runtime.front().unwrap().action.target_ip, target(3));
    }

    #[test]
    fn clock_regression_is_atomic_for_poll_and_equal_time_recovers() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(u64::MAX - 2_000), false);
        commit_front(&mut runtime, u64::MAX - 2_000);
        let before = runtime.status(WAN, target(2));
        let mut trace = TimerTrace::default();
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(u64::MAX - 2_001),
                1,
                &mut trace
            ),
            Err(ResolutionTimerError::ClockRegression)
        );
        assert_eq!(runtime.status(WAN, target(2)), before);
        assert_eq!(runtime.pending_actions(), 0);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(u64::MAX - 1_000),
                1,
                &mut trace
            )
            .unwrap()
            .retries_queued,
            1
        );
        assert!(matches!(
            trace.events[0],
            Some(ResolutionTimerTrace::ClockRegression)
        ));
    }

    #[test]
    fn successful_merge_cancels_queued_waiting_and_failed_cycles() {
        for cancellation_point in 0..4 {
            let policy = ResolutionPolicy::with_retry(1_000, 2_000, 1).unwrap();
            let mut states = [ResolutionStateSlot::EMPTY; 1];
            let mut actions = [ResolutionActionSlot::EMPTY; 1];
            let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
                policy,
                &mut states,
                &mut actions,
                &mut dynamic,
            );
            runtime.schedule(action(2), MonotonicMillis(0), false);
            if cancellation_point >= 1 {
                commit_front(&mut runtime, 0);
            }
            if cancellation_point == 2 {
                runtime.policy.max_attempts = 2;
                poll_resolution_timers(
                    &mut runtime,
                    MonotonicMillis(1_000),
                    1,
                    &mut NoResolutionTimerTrace,
                )
                .unwrap();
            }
            if cancellation_point == 3 {
                poll_resolution_timers(
                    &mut runtime,
                    MonotonicMillis(1_000),
                    1,
                    &mut NoResolutionTimerTrace,
                )
                .unwrap();
            }
            assert_eq!(
                runtime.merge_dynamic(
                    WAN,
                    target(2),
                    MacAddress([3; 6]),
                    true,
                    false,
                    MonotonicMillis(1_000),
                ),
                ControlDisposition::Inserted
            );
            if cancellation_point == 0 {
                assert_eq!(runtime.status(WAN, target(2)), None);
            } else {
                assert_eq!(
                    runtime.status(WAN, target(2)).unwrap().phase,
                    ResolutionPhase::Cooldown
                );
            }
            assert_eq!(runtime.pending_actions(), 0);
        }
    }

    #[test]
    fn publication_reconciliation_removes_static_and_invalid_authority_only() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 3];
        let mut actions = [ResolutionActionSlot::EMPTY; 3];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        for last in [2, 3, 4] {
            runtime.schedule(action(last), MonotonicMillis(0), false);
        }
        let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap()];
        let interfaces = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: SOURCE_IP,
        }];
        let neighbors = [Neighbor {
            interface: WAN,
            target: target(3),
            mac: MacAddress([9; 6]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let report = runtime.reconcile_publication(&snapshot);
        assert_eq!(report.states_removed, 1);
        assert_eq!(report.actions_removed, 1);
        assert_eq!(runtime.pending_actions(), 2);
        assert_eq!(runtime.front().unwrap().action.target_ip, target(2));
        commit_front(&mut runtime, 0);
        assert_eq!(runtime.front().unwrap().action.target_ip, target(4));

        let changed_interfaces = [Interface {
            id: WAN,
            mac: MacAddress([7; 6]),
        }];
        let changed =
            ForwardingSnapshot::new(&routes, &changed_interfaces, &[], &bindings).unwrap();
        let report = runtime.reconcile_publication(&changed);
        assert_eq!(report.invalid_states_removed, 2);
        assert_eq!(report.invalid_actions_removed, 1);
        assert_eq!(runtime.pending_actions(), 0);
    }

    #[test]
    fn zero_storage_and_policy_validation_are_safe() {
        assert_eq!(
            ResolutionPolicy::with_retry(1_000, 1_000, 0),
            Err(ResolutionPolicyError::MaxAttemptsZero)
        );
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), false),
            ResolutionResult::StateFull
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(0),
                usize::MAX,
                &mut NoResolutionTimerTrace
            )
            .unwrap(),
            ResolutionTimerReport::default()
        );
    }

    #[test]
    fn generation_wrap_and_due_action_full_are_lifecycle_safe_and_atomic() {
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 2).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.states[0].generation = u64::MAX;
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        assert_eq!(runtime.status(WAN, target(2)).unwrap().generation, 0);
        commit_front(&mut runtime, 0);

        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );
        let authoritative = runtime
            .states
            .iter()
            .find(|state| state.occupied && state.key.target == target(2))
            .unwrap()
            .action;
        let mut changed = action(2);
        changed.source_mac = MacAddress([9; 6]);
        assert_eq!(
            runtime.schedule(changed, MonotonicMillis(1_000), false),
            ResolutionResult::ActionFull
        );
        assert_eq!(
            runtime
                .states
                .iter()
                .find(|state| state.occupied && state.key.target == target(2))
                .unwrap()
                .action,
            authoritative
        );
        assert_eq!(runtime.status(WAN, target(2)).unwrap().attempts, 1);
    }

    #[test]
    fn learned_mapping_with_short_ttl_cannot_reset_committed_cooldown() {
        let policy =
            ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(1_000, 2_000, 3, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.schedule(action(2), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);
        assert_eq!(
            runtime.merge_dynamic(
                WAN,
                target(2),
                MacAddress([3; 6]),
                true,
                false,
                MonotonicMillis(1),
            ),
            ControlDisposition::Inserted
        );
        assert_eq!(
            runtime.status(WAN, target(2)).unwrap().phase,
            ResolutionPhase::Cooldown
        );
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(2), MonotonicMillis(2)),
            DynamicLookup::Miss
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(2), false),
            ResolutionResult::Suppressed
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(999),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            0
        );
        assert_eq!(runtime.pending_actions(), 0);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );
    }

    #[test]
    fn static_publication_removal_cannot_reset_committed_cooldown() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);

        let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap()];
        let interfaces = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: SOURCE_IP,
        }];
        let neighbors = [Neighbor {
            interface: WAN,
            target: target(2),
            mac: MacAddress([4; 6]),
        }];
        let with_static =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let report = runtime.reconcile_publication(&with_static);
        assert_eq!(report.cooldowns_retained, 1);
        assert_eq!(
            runtime.status(WAN, target(2)).unwrap().phase,
            ResolutionPhase::Cooldown
        );

        let without_static = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        assert_eq!(
            runtime.reconcile_publication(&without_static),
            StaticReconcileReport::default()
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(999), false),
            ResolutionResult::Suppressed
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );
    }

    #[test]
    fn uncommitted_cancel_has_no_cooldown_and_expired_tombstone_is_reusable() {
        let policy =
            ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(1_000, 2_000, 3, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.schedule(action(2), MonotonicMillis(0), false);
        runtime.merge_dynamic(
            WAN,
            target(2),
            MacAddress([3; 6]),
            true,
            false,
            MonotonicMillis(1),
        );
        assert_eq!(runtime.status(WAN, target(2)), None);
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(2), MonotonicMillis(2)),
            DynamicLookup::Miss
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(2), false),
            ResolutionResult::Queued
        );
        commit_front(&mut runtime, 2);
        runtime.clear_resolution(WAN, target(2));
        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(1_001), false),
            ResolutionResult::StateFull
        );
        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(1_002), false),
            ResolutionResult::Queued,
            "expired cooldown slot is reusable by a different key"
        );
    }

    #[test]
    fn authority_change_scrubs_retry_but_preserves_cooldown_and_clock_atomicity() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);

        let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap()];
        let new_mac = MacAddress([8; 6]);
        let interfaces = [Interface {
            id: WAN,
            mac: new_mac,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: SOURCE_IP,
        }];
        let changed = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let report = runtime.reconcile_publication(&changed);
        assert_eq!(
            (report.invalid_states_removed, report.cooldowns_retained),
            (1, 1)
        );
        assert_eq!(runtime.pending_actions(), 0);
        let mut fresh = action(2);
        fresh.source_mac = new_mac;
        assert_eq!(
            runtime.schedule(fresh, MonotonicMillis(500), false),
            ResolutionResult::Suppressed
        );
        let before = runtime.status(WAN, target(2));
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(499),
                1,
                &mut NoResolutionTimerTrace
            ),
            Err(ResolutionTimerError::ClockRegression)
        );
        assert_eq!(runtime.status(WAN, target(2)), before);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(500),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            0
        );
        assert_eq!(runtime.status(WAN, target(2)), before);
        assert_eq!(
            runtime.schedule(fresh, MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );
        assert_eq!(runtime.front().unwrap().action.source_mac, new_mac);
    }

    #[test]
    fn pending_state_accounting_survives_rollback_reconcile_regression_and_cursor_wrap() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 4];
        let mut actions = [ResolutionActionSlot::EMPTY; 3];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        for last in [2, 3, 4] {
            assert_eq!(
                runtime.schedule(action(last), MonotonicMillis(100), false),
                ResolutionResult::Queued
            );
        }
        assert_pending_accounting(&runtime);
        assert_eq!(runtime.pending_states(), 3);

        assert_eq!(
            runtime.schedule(action(5), MonotonicMillis(100), false),
            ResolutionResult::ActionFull
        );
        assert_pending_accounting(&runtime);
        assert_eq!(runtime.pending_states(), 3);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(99),
                usize::MAX,
                &mut NoResolutionTimerTrace
            ),
            Err(ResolutionTimerError::ClockRegression)
        );
        assert_pending_accounting(&runtime);
        let zero_budget = poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(100),
            0,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!((zero_budget.scanned, zero_budget.pending), (0, 3));

        commit_front(&mut runtime, 100);
        let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap()];
        let interfaces = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: SOURCE_IP,
        }];
        let neighbors = [
            Neighbor {
                interface: WAN,
                target: target(2),
                mac: MacAddress([8; 6]),
            },
            Neighbor {
                interface: WAN,
                target: target(3),
                mac: MacAddress([9; 6]),
            },
        ];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let reconciled = runtime.reconcile_publication(&snapshot);
        assert_eq!(
            (
                reconciled.states_removed,
                reconciled.cooldowns_retained,
                reconciled.actions_removed
            ),
            (2, 1, 1)
        );
        assert_pending_accounting(&runtime);
        assert_eq!(runtime.pending_states(), 1);

        for _ in 0..=runtime.states.len() {
            let report = poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(100),
                1,
                &mut NoResolutionTimerTrace,
            )
            .unwrap();
            assert_eq!((report.scanned, report.pending), (1, 1));
            assert_pending_accounting(&runtime);
        }
    }

    #[test]
    fn pending_failure_accounting_survives_capacity_regression_dispatch_wrap_and_expiry() {
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 3];
        let mut actions = [ResolutionActionSlot::EMPTY; 3];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        for last in [2, 3, 4] {
            assert_eq!(
                runtime.schedule(action(last), MonotonicMillis(0), false),
                ResolutionResult::Queued
            );
            commit_front_accepted(&mut runtime, 0);
            let capture = runtime.capture_failure_candidate(
                WAN,
                target(last),
                target(100 + last),
                target(last),
                SOURCE_MAC,
                SOURCE_IP,
                Ipv4Address::from_octets([192, 0, 2, 0]),
                24,
                0,
                &[0x45; 28],
            );
            if last == 4 {
                assert_eq!(capture, ResolutionFailureCapture::CapacityFull);
            } else {
                assert!(matches!(capture, ResolutionFailureCapture::Captured(_)));
            }
            assert_pending_accounting(&runtime);
        }
        assert_eq!(
            (runtime.pending_states(), runtime.pending_failure_holds()),
            (3, 2)
        );

        let timed_out = poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(1_000),
            usize::MAX,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!((timed_out.timed_out, timed_out.pending), (3, 3));
        assert_pending_accounting(&runtime);
        assert_eq!(runtime.pending_failure_holds(), 2);

        let snapshot = ForwardingSnapshot::new(&[], &[], &[], &[]).unwrap();
        let mut icmp_states = [crate::Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut icmp_actions = [crate::Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
            crate::Icmpv4ErrorPolicy::default(),
            &mut icmp_states,
            &mut icmp_actions,
        );
        assert_eq!(
            dispatch_host_unreachable_failures(
                &mut runtime,
                &mut icmpv4_errors,
                &snapshot,
                MonotonicMillis(999),
                usize::MAX,
                &mut NoResolutionFailureTrace
            ),
            Err(ResolutionFailureDispatchError::ClockRegression)
        );
        assert_pending_accounting(&runtime);

        for expected_pending in [1, 0] {
            let report = dispatch_host_unreachable_failures(
                &mut runtime,
                &mut icmpv4_errors,
                &snapshot,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionFailureTrace,
            )
            .unwrap();
            assert_eq!(
                (report.scanned, report.retired, report.pending),
                (1, 1, expected_pending)
            );
            assert_pending_accounting(&runtime);
        }
        let wrapped = dispatch_host_unreachable_failures(
            &mut runtime,
            &mut icmpv4_errors,
            &snapshot,
            MonotonicMillis(1_000),
            1,
            &mut NoResolutionFailureTrace,
        )
        .unwrap();
        assert_eq!((wrapped.scanned, wrapped.pending), (1, 0));
        assert_pending_accounting(&runtime);

        let expired = poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(2_000),
            usize::MAX,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!((expired.failures_expired, expired.pending), (3, 0));
        assert_pending_accounting(&runtime);
    }

    #[test]
    fn generation_wrap_skips_live_failure_token_and_recreation_zeroes_quote() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        {
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
                policy,
                &mut states,
                &mut actions,
                &mut [],
                &mut holds,
            );
            runtime.states[0].generation = u64::MAX;
            runtime.failure_holds[0].phase = ResolutionFailureHoldPhase::TerminalReady;
            runtime.failure_holds[0].forward = ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 0,
            };
            runtime.failure_holds[0].quote_len = 1;
            runtime.failure_holds[0].quote[0] = 0xa5;
            assert_eq!(
                runtime.schedule(action(2), MonotonicMillis(0), false),
                ResolutionResult::Queued
            );
            assert_eq!(runtime.status(WAN, target(2)).unwrap().generation, 1);
        }
        {
            let runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
                policy,
                &mut states,
                &mut actions,
                &mut [],
                &mut holds,
            );
            assert_eq!(runtime.pending_failure_holds(), 0);
        }
        assert_eq!(holds[0].quote_len, 0);
        assert!(holds[0].quote.iter().all(|byte| *byte == 0));
    }
}

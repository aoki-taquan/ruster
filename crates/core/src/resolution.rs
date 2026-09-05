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
    /// Whether a value stamped at `held_at` has outlived the resolution TTL.
    ///
    /// A held datagram shares the lifetime of the resolution that holds it up:
    /// once the resolution itself has expired, nothing is coming to release
    /// the datagram and sending it later would surprise the sender.
    #[must_use]
    pub(crate) const fn is_expired(&self, held_at: MonotonicMillis, now: MonotonicMillis) -> bool {
        now.0.saturating_sub(held_at.0) >= self.state_ttl_ms
    }

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

    /// Returns the queued ARP action and its resolution generation.
    ///
    /// The value is a copy of bounded metadata; it does not expose a packet
    /// lease or any owner capability.
    #[must_use]
    pub const fn queued(self) -> Option<(ArpRequestAction, u64)> {
        match self.0 {
            Some(queued) => Some((queued.action, queued.generation)),
            None => None,
        }
    }
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

    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn egress(self) -> IfId {
        self.key.egress
    }

    #[must_use]
    pub const fn target(self) -> Ipv4Address {
        self.key.target
    }

    #[must_use]
    pub const fn action(self) -> ArpRequestAction {
        self.action
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn attempts(self) -> u16 {
        self.attempts
    }

    #[must_use]
    pub const fn accepted_attempts(self) -> u16 {
        self.accepted_attempts
    }

    #[must_use]
    pub const fn requested_at(self) -> MonotonicMillis {
        self.requested_at
    }

    #[must_use]
    pub const fn failed_at(self) -> MonotonicMillis {
        self.failed_at
    }

    #[must_use]
    pub const fn phase(self) -> ResolutionPhase {
        self.phase
    }

    #[must_use]
    pub const fn failure_notified(self) -> bool {
        self.failure_notified
    }
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

    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn interface(self) -> IfId {
        self.interface
    }

    #[must_use]
    pub const fn target(self) -> Ipv4Address {
        self.target
    }

    #[must_use]
    pub const fn mac(self) -> MacAddress {
        self.mac
    }

    #[must_use]
    pub const fn refreshed_at(self) -> MonotonicMillis {
        self.refreshed_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicLookup {
    Hit(MacAddress),
    Miss,
    ClockRegression,
}

/// The largest frame this router holds while its next hop resolves.
///
/// One standard Ethernet frame. A datagram larger than this is forwarded the
/// moment its next hop is known but is not held meanwhile, which keeps the
/// per-slot storage fixed and small enough to sit beside the other resolution
/// arrays.
pub const RESOLUTION_HOLD_MAX_FRAME_LEN: usize = 1_514;

/// One datagram kept while the next hop it needs is being resolved.
///
/// RFC 1122 §2.3.2.2 asks the link layer to save, rather than discard, at
/// least one packet per unresolved address, and RFC 1812 §3.3.2 repeats it
/// for routers. Without this the first datagram to every new destination is
/// lost even though the resolution it triggered succeeds.
///
/// The slot never owns an RX lease: holding one would stall the receive ring.
/// It stores a copy of the frame with the forwarding rewrite already applied
/// — the TTL is decremented and the header checksum updated exactly once, at
/// the moment the datagram arrived — leaving only the destination MAC to fill
/// in when the address is learned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionDatagramHoldSlot {
    occupied: bool,
    egress: IfId,
    target: Ipv4Address,
    held_at: MonotonicMillis,
    len: u16,
    frame: [u8; RESOLUTION_HOLD_MAX_FRAME_LEN],
}

impl ResolutionDatagramHoldSlot {
    pub const EMPTY: Self = Self {
        occupied: false,
        egress: IfId(0),
        target: Ipv4Address::from_octets([0; 4]),
        held_at: MonotonicMillis(0),
        len: 0,
        frame: [0; RESOLUTION_HOLD_MAX_FRAME_LEN],
    };

    #[must_use]
    pub const fn is_occupied(&self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn egress(&self) -> IfId {
        self.egress
    }

    #[must_use]
    pub const fn target(&self) -> Ipv4Address {
        self.target
    }

    /// The held frame, still missing its destination MAC.
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame[..self.len()]
    }

    /// The slot storage past the held frame.
    ///
    /// A slot outlives the datagrams that pass through it, so the bytes past
    /// the current one are cleared rather than left holding another flow's
    /// payload. Nothing sends them — [`Self::frame`] stops at the length —
    /// but retaining them would be needless.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn storage_past_frame(&self) -> &[u8] {
        &self.frame[self.len()..]
    }
}

/// What became of a datagram offered to the hold queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionHoldDisposition {
    /// The datagram is held and will be sent when the address is learned.
    Held { egress: IfId, len: usize },
    /// An earlier datagram for this key was replaced. RFC 1122 requires only
    /// that at least one packet be saved, and the newest is the one most
    /// likely still to be wanted.
    Replaced { egress: IfId, len: usize },
    /// The frame does not fit a hold slot.
    FrameTooLong { len: usize },
    /// Every slot holds a datagram for a different unresolved address.
    QueueFull,
    /// Time moved backwards, so no lifetime can be established.
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionHoldCounters {
    pub held: usize,
    pub replaced: usize,
    pub frame_too_long: usize,
    pub queue_full: usize,
    pub replayed: usize,
    pub expired: usize,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolutionPublicationValidation {
    states_flushed: usize,
    failure_holds_flushed: usize,
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
    datagram_holds: &'a mut [ResolutionDatagramHoldSlot],
    head: usize,
    len: usize,
    pending_state_count: usize,
    pending_failure_hold_count: usize,
    poll_cursor: usize,
    failure_cursor: usize,
    last_now: Option<MonotonicMillis>,
    last_interface_identity: Option<u64>,
    publication_epoch: u128,
    counters: ResolutionCounters,
    failure_counters: ResolutionFailureCounters,
    hold_counters: ResolutionHoldCounters,
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
        Self::with_dynamic_neighbors_failure_holds_and_datagram_holds(
            policy,
            states,
            action_storage,
            dynamic_neighbors,
            failure_holds,
            &mut [],
        )
    }

    /// Builds a runtime that also holds datagrams for unresolved next hops.
    ///
    /// With no hold slots the first datagram to an unresolved address is
    /// dropped, which is the behaviour every constructor above keeps.
    #[must_use]
    pub fn with_dynamic_neighbors_failure_holds_and_datagram_holds(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
        dynamic_neighbors: &'a mut [DynamicNeighborSlot],
        failure_holds: &'a mut [ResolutionFailureHoldSlot],
        datagram_holds: &'a mut [ResolutionDatagramHoldSlot],
    ) -> Self {
        states.fill(ResolutionStateSlot::EMPTY);
        action_storage.fill(ResolutionActionSlot::EMPTY);
        dynamic_neighbors.fill(DynamicNeighborSlot::EMPTY);
        failure_holds.fill(ResolutionFailureHoldSlot::EMPTY);
        datagram_holds.fill(ResolutionDatagramHoldSlot::EMPTY);
        Self {
            policy,
            states,
            actions: action_storage,
            dynamic_neighbors,
            failure_holds,
            datagram_holds,
            head: 0,
            len: 0,
            pending_state_count: 0,
            pending_failure_hold_count: 0,
            poll_cursor: 0,
            failure_cursor: 0,
            last_now: None,
            last_interface_identity: None,
            publication_epoch: 1,
            counters: ResolutionCounters::default(),
            failure_counters: ResolutionFailureCounters::default(),
            hold_counters: ResolutionHoldCounters::default(),
            _worker_local: PhantomData,
        }
    }

    /// Keeps one datagram for an address that is being resolved.
    ///
    /// `frame` must already carry the forwarding rewrite with its destination
    /// MAC left unset: the TTL is decremented and the header checksum updated
    /// once, when the datagram arrives, so a replay is byte-for-byte what an
    /// immediate forward would have sent.
    ///
    /// One datagram per unresolved address is kept, which is what RFC 1122
    /// §2.3.2.2 asks for. A second datagram for the same address replaces the
    /// first: the newest is the one whose sender is most likely still waiting.
    pub fn hold_datagram(
        &mut self,
        egress: IfId,
        target: Ipv4Address,
        frame: &[u8],
        now: MonotonicMillis,
    ) -> ResolutionHoldDisposition {
        if !self.observe_now(now) {
            return ResolutionHoldDisposition::ClockRegression;
        }
        let len = frame.len();
        if len > RESOLUTION_HOLD_MAX_FRAME_LEN {
            self.hold_counters.frame_too_long += 1;
            return ResolutionHoldDisposition::FrameTooLong { len };
        }
        let existing = self
            .datagram_holds
            .iter()
            .position(|slot| slot.occupied && slot.egress == egress && slot.target == target);
        let (index, replaced) = match existing {
            Some(index) => (index, true),
            None => {
                let free = self
                    .datagram_holds
                    .iter()
                    .position(|slot| !slot.occupied || self.policy.is_expired(slot.held_at, now));
                let Some(index) = free else {
                    self.hold_counters.queue_full += 1;
                    return ResolutionHoldDisposition::QueueFull;
                };
                if self.datagram_holds[index].occupied {
                    self.hold_counters.expired += 1;
                }
                (index, false)
            }
        };
        let slot = &mut self.datagram_holds[index];
        slot.occupied = true;
        slot.egress = egress;
        slot.target = target;
        slot.held_at = now;
        slot.len = u16::try_from(len).expect("the length was bounded above");
        slot.frame[..len].copy_from_slice(frame);
        slot.frame[len..].fill(0);
        if replaced {
            self.hold_counters.replaced += 1;
            ResolutionHoldDisposition::Replaced { egress, len }
        } else {
            self.hold_counters.held += 1;
            ResolutionHoldDisposition::Held { egress, len }
        }
    }

    /// Takes the next held datagram whose address is now known.
    ///
    /// Returns the egress, the learned MAC and the held frame. Expired holds
    /// are released as they are passed over, so a datagram is never sent after
    /// the sender has certainly given up on it.
    pub fn take_resolved_datagram(
        &mut self,
        now: MonotonicMillis,
    ) -> Option<(IfId, MacAddress, &[u8])> {
        if !self.observe_now(now) {
            return None;
        }
        let mut found = None;
        for index in 0..self.datagram_holds.len() {
            let slot = self.datagram_holds[index];
            if !slot.occupied {
                continue;
            }
            if self.policy.is_expired(slot.held_at, now) {
                self.datagram_holds[index] = ResolutionDatagramHoldSlot::EMPTY;
                self.hold_counters.expired += 1;
                continue;
            }
            if let Some(mac) = self.resolved_mac(slot.egress, slot.target, now) {
                found = Some((index, mac));
                break;
            }
        }
        let (index, mac) = found?;
        let egress = self.datagram_holds[index].egress;
        self.datagram_holds[index].occupied = false;
        self.hold_counters.replayed += 1;
        let len = self.datagram_holds[index].len();
        Some((egress, mac, &self.datagram_holds[index].frame[..len]))
    }

    /// The MAC currently known for one unresolved-address key, if any.
    fn resolved_mac(
        &self,
        egress: IfId,
        target: Ipv4Address,
        now: MonotonicMillis,
    ) -> Option<MacAddress> {
        self.dynamic_neighbors
            .iter()
            .find(|slot| {
                slot.occupied
                    && slot.interface == egress
                    && slot.target == target
                    && now.0.saturating_sub(slot.refreshed_at.0)
                        < self.policy.dynamic_neighbor_ttl_ms
            })
            .map(|slot| slot.mac)
    }

    #[must_use]
    pub fn hold_counters(&self) -> ResolutionHoldCounters {
        self.hold_counters
    }

    #[must_use]
    pub fn held_datagram_count(&self) -> usize {
        self.datagram_holds
            .iter()
            .filter(|slot| slot.occupied)
            .count()
    }

    #[must_use]
    pub fn dynamic_neighbor_count(&self) -> usize {
        self.dynamic_neighbors
            .iter()
            .filter(|slot| slot.occupied)
            .count()
    }

    /// Returns the caller-owned resolution state slots for cold/test evidence.
    #[must_use]
    pub fn state_slots(&self) -> &[ResolutionStateSlot] {
        self.states
    }

    /// Returns the caller-owned action slots for cold/test evidence.
    #[must_use]
    pub fn action_slots(&self) -> &[ResolutionActionSlot] {
        self.actions
    }

    /// Returns the caller-owned dynamic-neighbor slots for cold/test evidence.
    #[must_use]
    pub fn dynamic_neighbor_slots(&self) -> &[DynamicNeighborSlot] {
        self.dynamic_neighbors
    }

    /// Returns one pending action in FIFO order without changing queue state.
    #[must_use]
    pub fn queued_action(&self, position: usize) -> Option<(ArpRequestAction, u64)> {
        if position >= self.len || self.actions.is_empty() {
            return None;
        }
        let index = (self.head + position) % self.actions.len();
        self.actions[index].queued()
    }

    /// Returns the last monotonic timestamp accepted by this runtime.
    #[must_use]
    pub const fn last_observed_at(&self) -> Option<MonotonicMillis> {
        self.last_now
    }

    /// Returns the current publication epoch of this worker-local runtime.
    #[must_use]
    pub const fn publication_epoch(&self) -> u128 {
        self.publication_epoch
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
            && self.last_interface_identity.is_none()
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
        let validation = self.validate_publication_invariants()?;
        let next_runtime_epoch = self
            .publication_epoch
            .checked_add(1)
            .ok_or(ResolutionPublicationError::RuntimeEpochExhausted)?;
        let preview = ResolutionPublicationReport {
            states_flushed: validation.states_flushed,
            actions_flushed: self.len,
            dynamic_neighbors_flushed: self
                .dynamic_neighbors
                .iter()
                .filter(|slot| slot.occupied)
                .count(),
            failure_holds_flushed: validation.failure_holds_flushed,
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

    fn validate_publication_invariants(
        &self,
    ) -> Result<ResolutionPublicationValidation, ResolutionPublicationError> {
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
        let mut states_flushed = 0;
        let mut pending_states = 0;
        for state in &*self.states {
            if state.occupied {
                states_flushed += 1;
            }
            if state_is_pending(*state) {
                pending_states += 1;
            }
        }
        if pending_states != self.pending_state_count {
            return Err(ResolutionPublicationError::PendingStateCount);
        }
        let failure_holds_flushed = self
            .failure_holds
            .iter()
            .filter(|hold| hold.phase != ResolutionFailureHoldPhase::Empty)
            .count();
        if failure_holds_flushed != self.pending_failure_hold_count {
            return Err(ResolutionPublicationError::PendingFailureHoldCount);
        }
        Ok(ResolutionPublicationValidation {
            states_flushed,
            failure_holds_flushed,
        })
    }

    fn commit_publication(
        &mut self,
        snapshot: &crate::ForwardingSnapshot<'_>,
    ) -> StaticReconcileReport {
        let mut report = StaticReconcileReport::default();
        let interface_identity = snapshot_interface_identity(snapshot);
        if self.last_interface_identity != Some(interface_identity) {
            for slot in &mut *self.dynamic_neighbors {
                if slot.occupied {
                    *slot = DynamicNeighborSlot::EMPTY;
                    report.dynamic_removed = report.dynamic_removed.saturating_add(1);
                }
            }
            self.last_interface_identity = Some(interface_identity);
        }
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
        self.runtime.last_interface_identity = None;
        self.preview
    }
}

fn snapshot_interface_identity(snapshot: &crate::ForwardingSnapshot<'_>) -> u64 {
    fn mix(identity: u64, value: u64) -> u64 {
        (identity ^ value).wrapping_mul(0x0000_0100_0000_01b3)
    }

    let mut identity = 0xcbf2_9ce4_8422_2325;
    for interface in snapshot.interfaces {
        identity = mix(identity, u64::from(interface.id.0));
        for octet in interface.mac.0 {
            identity = mix(identity, u64::from(octet));
        }
    }
    mix(identity, 0xff)
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

/// What one replay attempt did.
#[derive(Debug, Eq, PartialEq)]
pub struct HeldDatagramReport<E> {
    pub egress: IfId,
    pub destination_mac: MacAddress,
    pub len: usize,
    pub allocation_error: Option<GeneratedAllocationError>,
    pub build_error: Option<HeldDatagramBuildError>,
    pub completion: GeneratedBatchCompletion<E>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeldDatagramBuildError {
    ExactLengthRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecuteHeldDatagramError {
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedHeldDatagramTrace {
    TxRequested { egress: IfId, len: usize },
    AllocationFailed(GeneratedAllocationError),
    BuildFailed(HeldDatagramBuildError),
    BatchCompleted { accepted: usize, rejected: usize },
}

pub trait GeneratedHeldDatagramTraceSink {
    fn record_generated_held_datagram(&mut self, event: GeneratedHeldDatagramTrace);
}

#[derive(Default)]
pub struct NoGeneratedHeldDatagramTrace;

impl GeneratedHeldDatagramTraceSink for NoGeneratedHeldDatagramTrace {
    fn record_generated_held_datagram(&mut self, _event: GeneratedHeldDatagramTrace) {}
}

/// Sends at most one held datagram whose next hop has become known.
///
/// The datagram is released from its slot before the send is attempted, so a
/// backend that rejects the frame drops it rather than replaying it forever:
/// the sender's own retransmission is the recovery path, and this router
/// promised only to save the packet, not to deliver it.
pub fn execute_one_held_datagram<I, T>(
    io: &mut I,
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<Option<HeldDatagramReport<I::Error>>, ExecuteHeldDatagramError>
where
    I: GeneratedPacketIo,
    T: GeneratedHeldDatagramTraceSink,
{
    if !runtime.execution_time_valid(now) {
        return Err(ExecuteHeldDatagramError::ClockRegression);
    }
    let Some((egress, destination_mac, frame)) = runtime.take_resolved_datagram(now) else {
        return Ok(None);
    };
    let len = frame.len();
    let mut staged = [0_u8; RESOLUTION_HOLD_MAX_FRAME_LEN];
    staged[..len].copy_from_slice(frame);
    staged[0..6].copy_from_slice(&destination_mac.0);

    let mut batch = io.begin_generated(egress);
    let (allocation_error, build_error) = match allocate_held_datagram(&mut batch, &staged[..len]) {
        Ok(()) => {
            trace.record_generated_held_datagram(GeneratedHeldDatagramTrace::TxRequested {
                egress,
                len,
            });
            (None, None)
        }
        Err(HeldDatagramGenerationError::Allocation(error)) => {
            trace.record_generated_held_datagram(GeneratedHeldDatagramTrace::AllocationFailed(
                error,
            ));
            (Some(error), None)
        }
        Err(HeldDatagramGenerationError::Build(error)) => {
            trace.record_generated_held_datagram(GeneratedHeldDatagramTrace::BuildFailed(error));
            (None, Some(error))
        }
    };
    let completion = batch.finish();
    trace.record_generated_held_datagram(GeneratedHeldDatagramTrace::BatchCompleted {
        accepted: completion.accepted,
        rejected: completion.rejected,
    });
    Ok(Some(HeldDatagramReport {
        egress,
        destination_mac,
        len,
        allocation_error,
        build_error,
        completion,
    }))
}

enum HeldDatagramGenerationError {
    Allocation(GeneratedAllocationError),
    Build(HeldDatagramBuildError),
}

fn allocate_held_datagram<B: GeneratedPacketBatch>(
    batch: &mut B,
    frame: &[u8],
) -> Result<(), HeldDatagramGenerationError> {
    let mut lease = batch
        .allocate(frame.len())
        .map_err(HeldDatagramGenerationError::Allocation)?;
    if lease.bytes_mut().len() != frame.len() {
        lease.cancel();
        return Err(HeldDatagramGenerationError::Build(
            HeldDatagramBuildError::ExactLengthRequired,
        ));
    }
    lease.bytes_mut().copy_from_slice(frame);
    lease.commit();
    Ok(())
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
    use std::{cell::RefCell, rc::Rc};

    use super::*;
    use crate::{ForwardingSnapshot, Interface, Ipv4Mtu, LocalIpv4Binding, Neighbor, Route};

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
        last_interface_identity: Option<u64>,
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
            last_interface_identity: runtime.last_interface_identity,
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

    const REVERSE_EGRESS: IfId = IfId(3);
    const ORIGINAL_SOURCE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 2]);
    const REVERSE_SOURCE_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
    const FORWARD_PREFIX: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 0]);
    const REVERSE_PREFIX: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 0]);
    const REVERSE_MAC: MacAddress = MacAddress([3, 0, 0, 0, 0, 1]);

    fn state_slot(
        resolution_action: ArpRequestAction,
        phase: ResolutionPhase,
        attempts: u16,
        accepted_attempts: u16,
        generation: u64,
    ) -> ResolutionStateSlot {
        ResolutionStateSlot {
            key: ResolutionKey {
                egress: resolution_action.egress,
                target: resolution_action.target_ip,
            },
            action: resolution_action,
            generation,
            attempts,
            accepted_attempts,
            requested_at: MonotonicMillis(0),
            failed_at: MonotonicMillis(0),
            occupied: true,
            phase,
            failure_notified: false,
        }
    }

    fn failure_hold(
        phase: ResolutionFailureHoldPhase,
        forward: ResolutionGenerationToken,
    ) -> ResolutionFailureHoldSlot {
        let mut hold = ResolutionFailureHoldSlot {
            phase,
            forward,
            reverse: ResolutionGenerationToken {
                egress: REVERSE_EGRESS,
                target: ORIGINAL_SOURCE,
                generation: 1,
            },
            original_source: ORIGINAL_SOURCE,
            original_destination: target(2),
            forward_source_mac: SOURCE_MAC,
            forward_source_ip: SOURCE_IP,
            forward_prefix: FORWARD_PREFIX,
            forward_prefix_len: 24,
            original_tos: 0x12,
            quote_len: 4,
            ..ResolutionFailureHoldSlot::EMPTY
        };
        hold.quote[..4].copy_from_slice(&[0x45, 0, 0, 4]);
        hold
    }

    struct FailureSnapshotFixture {
        routes: Vec<Route>,
        interfaces: Vec<Interface>,
        neighbors: Vec<Neighbor>,
        bindings: Vec<LocalIpv4Binding>,
    }

    impl FailureSnapshotFixture {
        fn direct(with_reverse_neighbor: bool) -> Self {
            Self {
                routes: vec![
                    Route::new(FORWARD_PREFIX, 24, WAN, None).unwrap(),
                    Route::new(REVERSE_PREFIX, 24, REVERSE_EGRESS, None).unwrap(),
                ],
                interfaces: vec![
                    Interface {
                        id: WAN,
                        mac: SOURCE_MAC,
                        mtu: Ipv4Mtu::ETHERNET,
                    },
                    Interface {
                        id: REVERSE_EGRESS,
                        mac: REVERSE_MAC,
                        mtu: Ipv4Mtu::ETHERNET,
                    },
                ],
                neighbors: if with_reverse_neighbor {
                    vec![Neighbor {
                        interface: REVERSE_EGRESS,
                        target: ORIGINAL_SOURCE,
                        mac: MacAddress([9; 6]),
                    }]
                } else {
                    Vec::new()
                },
                bindings: vec![
                    LocalIpv4Binding {
                        interface: WAN,
                        address: SOURCE_IP,
                    },
                    LocalIpv4Binding {
                        interface: REVERSE_EGRESS,
                        address: REVERSE_SOURCE_IP,
                    },
                ],
            }
        }

        fn snapshot(&self) -> ForwardingSnapshot<'_> {
            ForwardingSnapshot::new(
                &self.routes,
                &self.interfaces,
                &self.neighbors,
                &self.bindings,
            )
            .unwrap()
        }
    }

    struct TestGeneratedIo;

    struct TestGeneratedBatch;

    struct TestGeneratedSlot {
        bytes: Vec<u8>,
    }

    impl GeneratedPacketIo for TestGeneratedIo {
        type Error = ();
        type Batch<'a>
            = TestGeneratedBatch
        where
            Self: 'a;

        fn begin_generated(&mut self, _egress: IfId) -> Self::Batch<'_> {
            TestGeneratedBatch
        }
    }

    impl GeneratedPacketBatch for TestGeneratedBatch {
        type Error = ();
        type Slot<'a>
            = TestGeneratedSlot
        where
            Self: 'a;

        fn allocate(
            &mut self,
            frame_len: usize,
        ) -> Result<crate::GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
            Ok(crate::GeneratedPacketLease::new(TestGeneratedSlot {
                bytes: vec![0; frame_len],
            }))
        }

        fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
            GeneratedBatchCompletion {
                attempts: 1,
                allocated: 1,
                failed: 0,
                requested: 1,
                cancelled: 0,
                abandoned: 0,
                accepted: 1,
                rejected: 0,
                error: None,
            }
        }
    }

    impl crate::GeneratedPacketSlot for TestGeneratedSlot {
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.bytes
        }

        fn complete(self, _completion: crate::GeneratedSlotCompletion) {}
    }

    fn dispatch_failure_case(
        fixture: &FailureSnapshotFixture,
        hold: ResolutionFailureHoldSlot,
        state_slots: &[ResolutionStateSlot],
        dynamic_slots: &[DynamicNeighborSlot],
    ) -> (
        FailureDispatch,
        ResolutionCounters,
        Option<Icmpv4ErrorAction>,
    ) {
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = state_slots.to_vec();
        let mut actions = [ResolutionActionSlot::EMPTY; 2];
        let mut dynamic_neighbors = dynamic_slots.to_vec();
        let mut resolution = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic_neighbors,
        );
        resolution.states.copy_from_slice(state_slots);
        resolution.pending_state_count = state_slots
            .iter()
            .filter(|state| state_is_pending(**state))
            .count();

        let mut icmp_states = [crate::Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut icmp_actions = [crate::Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
            crate::Icmpv4ErrorPolicy::default(),
            &mut icmp_states,
            &mut icmp_actions,
        );
        let snapshot = fixture.snapshot();
        let outcome = dispatch_one_failure(
            &mut resolution,
            &mut icmpv4_errors,
            &snapshot,
            MonotonicMillis(0),
            hold,
        );
        let action = if matches!(outcome, FailureDispatch::Queued(_)) {
            let mut io = TestGeneratedIo;
            crate::execute_one_icmpv4_error(
                &mut io,
                &mut icmpv4_errors,
                MonotonicMillis(0),
                &mut crate::NoGeneratedIcmpv4Trace,
            )
            .unwrap()
            .map(|report| report.action)
        } else {
            None
        };
        (outcome, resolution.counters(), action)
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
    fn schedule_expired_failed_state_clears_only_matching_failure_holds() {
        // Protects #52-57 at the exact state-TTL boundary: live phase, forward-key,
        // WaitingReverse-phase, and reverse-key checks must all be evaluated together.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 4];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        let expired = ResolutionGenerationToken {
            egress: WAN,
            target: target(2),
            generation: 1,
        };
        let unrelated_forward = ResolutionGenerationToken {
            egress: WAN,
            target: target(3),
            generation: 1,
        };
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        runtime.states[0].failed_at = MonotonicMillis(0);

        // A protects the non-empty phase and exact forward-key match branches.
        let hold_a = failure_hold(ResolutionFailureHoldPhase::TerminalReady, expired);
        // B protects TerminalReady from using a reverse match without WaitingReverse.
        let mut hold_b = failure_hold(ResolutionFailureHoldPhase::TerminalReady, unrelated_forward);
        hold_b.reverse = expired;
        // C protects the WaitingReverse phase and exact reverse-key match branches.
        let mut hold_c = failure_hold(
            ResolutionFailureHoldPhase::WaitingReverse,
            unrelated_forward,
        );
        hold_c.reverse = expired;
        runtime.failure_holds[0] = hold_a;
        runtime.failure_holds[1] = hold_b;
        runtime.failure_holds[2] = hold_c;
        // Protects #51's outer `phase != Empty && (...)` guard: an empty slot
        // with only a matching forward token must be ignored; changing `&&`
        // to `||` reaches clear_failure_hold and trips its live-slot assertion.
        runtime.failure_holds[3] = ResolutionFailureHoldSlot::EMPTY;
        runtime.failure_holds[3].forward = expired;
        runtime.pending_failure_hold_count = 3;

        assert_eq!(runtime.pending_failure_holds(), 3);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );

        // A and C are cleared, while B remains because only its reverse key matches.
        assert_eq!(runtime.pending_failure_holds(), 1);
        assert_eq!(runtime.failure_holds[0], ResolutionFailureHoldSlot::EMPTY);
        assert_eq!(runtime.failure_holds[1], hold_b);
        assert_eq!(runtime.failure_holds[2], ResolutionFailureHoldSlot::EMPTY);
        assert_eq!(
            runtime.failure_holds[3].phase,
            ResolutionFailureHoldPhase::Empty
        );
        assert_eq!(runtime.failure_holds[3].forward, expired);
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
            mtu: Ipv4Mtu::ETHERNET,
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
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let changed =
            ForwardingSnapshot::new(&routes, &changed_interfaces, &[], &bindings).unwrap();
        let report = runtime.reconcile_publication(&changed);
        assert_eq!(report.invalid_states_removed, 2);
        assert_eq!(report.invalid_actions_removed, 1);
        assert_eq!(runtime.pending_actions(), 0);
    }

    #[test]
    fn publication_reconciliation_invalidates_dynamic_neighbor_on_interface_reuse() {
        let policy = ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 2_000, 60_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        let old_interface = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let old_snapshot = ForwardingSnapshot::new(&[], &old_interface, &[], &[]).unwrap();
        assert_eq!(
            runtime.reconcile_publication(&old_snapshot),
            StaticReconcileReport::default()
        );
        let old_neighbor_mac = MacAddress([3; 6]);
        assert_eq!(
            runtime.merge_dynamic(
                WAN,
                target(2),
                old_neighbor_mac,
                true,
                false,
                MonotonicMillis(1_000),
            ),
            ControlDisposition::Inserted
        );
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(2), MonotonicMillis(2_000)),
            DynamicLookup::Hit(old_neighbor_mac)
        );
        assert_eq!(
            runtime.reconcile_publication(&old_snapshot),
            StaticReconcileReport::default()
        );
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(2), MonotonicMillis(2_000)),
            DynamicLookup::Hit(old_neighbor_mac)
        );

        let reused_interface = [Interface {
            id: WAN,
            mac: MacAddress([7; 6]),
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let reused_snapshot = ForwardingSnapshot::new(&[], &reused_interface, &[], &[]).unwrap();
        let report = runtime.reconcile_publication(&reused_snapshot);

        assert_eq!(report.dynamic_removed, 1);
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(2), MonotonicMillis(2_000)),
            DynamicLookup::Miss
        );
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
            mtu: Ipv4Mtu::ETHERNET,
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
            mtu: Ipv4Mtu::ETHERNET,
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
            mtu: Ipv4Mtu::ETHERNET,
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

    #[test]
    fn publication_validation_covers_empty_head_and_queue_window_boundaries() {
        // Protects validation of a nonzero head in an empty action ring.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.head = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::ActionQueueHead,
        );

        // Protects the strict queue-window boundary when a nonempty ring has no queued slot.
        let mut states = [];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        let permit = runtime.preflight_publication().unwrap();
        assert_eq!(permit.preview(), ResolutionPublicationReport::default());
        drop(permit);
    }

    #[test]
    fn publication_reconciliation_matches_dynamic_neighbors_and_holds_exactly() {
        // Protects interface/target conjunctions while removing static-shadowed dynamic neighbors.
        for neighbor in [
            Neighbor {
                interface: REVERSE_EGRESS,
                target: target(2),
                mac: MacAddress([8; 6]),
            },
            Neighbor {
                interface: WAN,
                target: target(3),
                mac: MacAddress([8; 6]),
            },
        ] {
            let mut fixture = FailureSnapshotFixture::direct(false);
            fixture.neighbors.push(neighbor);
            let snapshot = fixture.snapshot();
            let mut states = [];
            let mut actions = [];
            let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
                ResolutionPolicy::new(1_000, 1_000).unwrap(),
                &mut states,
                &mut actions,
                &mut dynamic,
            );
            runtime.reconcile_publication(&snapshot);
            runtime.dynamic_neighbors[0] = DynamicNeighborSlot {
                interface: WAN,
                target: target(2),
                mac: MacAddress([7; 6]),
                refreshed_at: MonotonicMillis(0),
                occupied: true,
            };
            assert_eq!(
                runtime.reconcile_publication(&snapshot),
                StaticReconcileReport::default()
            );
            assert!(runtime.dynamic_neighbors[0].is_occupied());
        }
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.neighbors.push(Neighbor {
            interface: WAN,
            target: target(2),
            mac: MacAddress([8; 6]),
        });
        let snapshot = fixture.snapshot();
        let mut states = [];
        let mut actions = [];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.reconcile_publication(&snapshot);
        runtime.dynamic_neighbors[0] = DynamicNeighborSlot {
            interface: WAN,
            target: target(2),
            mac: MacAddress([7; 6]),
            refreshed_at: MonotonicMillis(0),
            occupied: true,
        };
        assert_eq!(runtime.reconcile_publication(&snapshot).dynamic_removed, 1);
        assert!(!runtime.dynamic_neighbors[0].is_occupied());

        // Protects the valid-hold branch from being treated as invalid by a changed boolean join.
        let fixture = FailureSnapshotFixture::direct(false);
        let snapshot = fixture.snapshot();
        let hold = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        let mut states = [];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.reconcile_publication(&snapshot);
        runtime.failure_holds[0] = hold;
        runtime.pending_failure_hold_count = 1;
        assert_eq!(
            runtime.reconcile_publication(&snapshot),
            StaticReconcileReport::default()
        );
        assert_eq!(runtime.pending_failure_holds(), 1);

        // Protects the empty-hold short circuit from incrementing cancellation accounting.
        let empty_snapshot = ForwardingSnapshot::new(&[], &[], &[], &[]).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.reconcile_publication(&empty_snapshot);
        assert_eq!(runtime.failure_counters.cancelled, 0);
    }

    #[test]
    fn compact_publication_actions_resets_head_after_removing_last_action() {
        // Protects ring-head normalization when publication compaction retains no actions.
        let fixture = ForwardingSnapshot::new(&[], &[], &[], &[]).unwrap();
        let mut states = [];
        let mut actions = [ResolutionActionSlot::EMPTY; 2];
        let mut runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
        );
        runtime.head = 1;
        runtime.len = 1;
        runtime.actions[1].0 = Some(QueuedAction {
            action: action(2),
            generation: 1,
        });
        runtime.reconcile_publication(&fixture);
        assert_eq!((runtime.head, runtime.len), (0, 0));
    }

    #[test]
    fn cooldown_count_and_status_require_occupied_matching_states() {
        // Protects cooldown counting from including active or empty slots.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 3];
        let mut actions = [];
        let runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Waiting, 1, 0, 1);
        runtime.states[1] = state_slot(action(4), ResolutionPhase::Cooldown, 1, 0, 2);
        // Protects cooldown_count from counting an occupied non-Cooldown terminal state.
        runtime.states[2] = state_slot(action(6), ResolutionPhase::Failed, 1, 0, 3);
        assert_eq!(runtime.cooldown_count(), 1);

        // Protects status lookup from matching an empty slot or a partially matching key.
        assert_eq!(
            runtime.status(IfId(0), Ipv4Address::from_octets([0; 4])),
            None
        );
        assert_eq!(runtime.status(WAN, target(3)), None);
        let status = runtime.status(WAN, target(2)).unwrap();
        assert_eq!(
            status,
            ResolutionStatus {
                phase: ResolutionPhase::Waiting,
                attempts: 1,
                accepted_attempts: 0,
                generation: 1,
                requested_at: Some(MonotonicMillis(0)),
                failed_at: None,
                terminal_notified: false,
            }
        );
        runtime.states[0].phase = ResolutionPhase::Failed;
        runtime.states[0].failed_at = MonotonicMillis(7);
        runtime.states[0].failure_notified = true;
        assert_eq!(
            runtime.status(WAN, target(2)).unwrap().failed_at,
            Some(MonotonicMillis(7))
        );
        assert!(runtime.status(WAN, target(2)).unwrap().terminal_notified);
    }

    #[test]
    fn publication_hold_valid_requires_every_forwarding_authority_field() {
        // Protects the valid publication-hold conjunction and both terminal rejection conditions.
        let base_fixture = FailureSnapshotFixture::direct(false);
        let base_snapshot = base_fixture.snapshot();
        let base_hold = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        assert!(publication_hold_valid(&base_snapshot, base_hold));

        // Protects #129's neighbor-key `&&`: an interface-only match is not an exact
        // static neighbor, so changing the inner conjunction to `||` must not reject it.
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.neighbors.push(Neighbor {
            interface: WAN,
            target: target(3),
            mac: MacAddress([8; 6]),
        });
        assert!(publication_hold_valid(&fixture.snapshot(), base_hold));
        // Protects the other partial-key boundary: a target-only match is also valid.
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.neighbors.push(Neighbor {
            interface: REVERSE_EGRESS,
            target: target(2),
            mac: MacAddress([8; 6]),
        });
        assert!(publication_hold_valid(&fixture.snapshot(), base_hold));

        // Protects every route component and route/interface boolean join.
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.routes[0] = Route::new(FORWARD_PREFIX, 24, REVERSE_EGRESS, None).unwrap();
        assert!(!publication_hold_valid(&fixture.snapshot(), base_hold));
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.routes[0] = Route::new(FORWARD_PREFIX, 24, WAN, Some(target(9))).unwrap();
        assert!(!publication_hold_valid(&fixture.snapshot(), base_hold));
        let mut hold = base_hold;
        hold.forward.target = target(3);
        assert!(!publication_hold_valid(&base_snapshot, hold));
        let mut hold = base_hold;
        hold.forward_prefix = Ipv4Address::from_octets([192, 0, 3, 0]);
        assert!(!publication_hold_valid(&base_snapshot, hold));
        let mut hold = base_hold;
        hold.forward_prefix_len = 23;
        assert!(!publication_hold_valid(&base_snapshot, hold));

        // Protects interface and local-binding identity joins and their comparisons.
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.interfaces[0].mac = MacAddress([8; 6]);
        assert!(!publication_hold_valid(&fixture.snapshot(), base_hold));
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.bindings[0].address = target(9);
        assert!(!publication_hold_valid(&fixture.snapshot(), base_hold));
        // Protects the exact static-neighbor exclusion and host-forbidden exclusion separately.
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.neighbors.push(Neighbor {
            interface: WAN,
            target: target(2),
            mac: MacAddress([8; 6]),
        });
        assert!(!publication_hold_valid(&fixture.snapshot(), base_hold));
        let mut fixture = FailureSnapshotFixture::direct(false);
        fixture.bindings[0].address = target(2);
        let mut hold = base_hold;
        hold.forward_source_ip = target(2);
        assert!(!publication_hold_valid(&fixture.snapshot(), hold));

        // Protects route/interface and local-binding exact comparisons with a fully valid snapshot.
        assert!(publication_hold_valid(&base_snapshot, base_hold));
    }

    #[test]
    fn current_icmp_error_eligibility_covers_unicast_local_and_route_boundaries() {
        // Protects the positive eligibility result and the constant replacement mutants.
        let empty = ForwardingSnapshot::new(&[], &[], &[], &[]).unwrap();
        let mut eligible = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        eligible.original_source = ORIGINAL_SOURCE;
        assert!(current_icmp_error_eligible(&empty, eligible));

        // Protects unspecified, loopback, multicast, and each first-octet comparison.
        for source in [
            Ipv4Address::from_octets([0, 1, 2, 3]),
            Ipv4Address::from_octets([127, 1, 2, 3]),
            Ipv4Address::from_octets([224, 1, 2, 3]),
        ] {
            let mut hold = eligible;
            hold.original_source = source;
            assert!(!current_icmp_error_eligible(&empty, hold));
        }
        let mut below_multicast = eligible;
        below_multicast.original_source = Ipv4Address::from_octets([223, 1, 2, 3]);
        assert!(current_icmp_error_eligible(&empty, below_multicast));
        let mut above_multicast = eligible;
        above_multicast.original_source = Ipv4Address::from_octets([225, 1, 2, 3]);
        assert!(!current_icmp_error_eligible(&empty, above_multicast));

        // Protects suppression of ICMP errors for a local original source.
        let interfaces = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: ORIGINAL_SOURCE,
        }];
        let local_snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &bindings).unwrap();
        assert!(!current_icmp_error_eligible(&local_snapshot, eligible));

        // Protects network-address and directed-broadcast route exclusions independently.
        let routes = [Route::new(FORWARD_PREFIX, 24, WAN, None).unwrap()];
        let route_snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &[]).unwrap();
        for source in [FORWARD_PREFIX, Ipv4Address::from_octets([192, 0, 2, 255])] {
            let mut hold = eligible;
            hold.original_source = source;
            assert!(!current_icmp_error_eligible(&route_snapshot, hold));
        }

        // Protects the local-source and route-source boolean joins with one false operand each.
        assert!(!current_icmp_error_eligible(&local_snapshot, eligible));
    }

    #[test]
    fn host_failure_target_forbidden_covers_address_and_connected_route_rules() {
        // Protects the allowed ordinary host target and the constant replacement mutants.
        let empty = ForwardingSnapshot::new(&[], &[], &[], &[]).unwrap();
        let local = SOURCE_IP;
        assert!(!host_failure_target_forbidden(
            &empty,
            WAN,
            target(2),
            local
        ));
        for target_ip in [
            Ipv4Address::from_octets([0, 1, 2, 3]),
            Ipv4Address::from_octets([127, 1, 2, 3]),
            Ipv4Address::from_octets([224, 1, 2, 3]),
            Ipv4Address::from_octets([255; 4]),
        ] {
            assert!(host_failure_target_forbidden(&empty, WAN, target_ip, local));
        }
        assert!(host_failure_target_forbidden(&empty, WAN, local, local));

        // Protects every first-octet, broadcast, and local-address comparison on allowed input.
        assert!(!host_failure_target_forbidden(
            &empty,
            WAN,
            Ipv4Address::from_octets([192, 0, 2, 2]),
            local,
        ));
        let interfaces = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        }];
        let local_target = target(9);
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: local_target,
        }];
        let local_snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &bindings).unwrap();
        assert!(host_failure_target_forbidden(
            &local_snapshot,
            WAN,
            local_target,
            local,
        ));

        // Protects connected network/broadcast routes and requires the correct egress.
        let routes = [Route::new(FORWARD_PREFIX, 24, WAN, None).unwrap()];
        let route_snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &[]).unwrap();
        assert!(host_failure_target_forbidden(
            &route_snapshot,
            WAN,
            FORWARD_PREFIX,
            local,
        ));
        assert!(host_failure_target_forbidden(
            &route_snapshot,
            WAN,
            Ipv4Address::from_octets([192, 0, 2, 255]),
            local,
        ));
        assert!(!host_failure_target_forbidden(
            &route_snapshot,
            REVERSE_EGRESS,
            FORWARD_PREFIX,
            local,
        ));

        // Protects both route subconditions when only one of network/broadcast is true.
        assert!(host_failure_target_forbidden(
            &route_snapshot,
            WAN,
            FORWARD_PREFIX,
            local,
        ));

        // Protects the local-binding/route boolean join when the route alone forbids the target.
        assert!(host_failure_target_forbidden(
            &route_snapshot,
            WAN,
            FORWARD_PREFIX,
            local,
        ));
    }

    #[test]
    fn forbidden_target_has_independent_first_octet_and_broadcast_guards() {
        // Protects the standalone forbidden_target helper from a constant result.
        assert!(!forbidden_target(target(2)));
        for target_ip in [
            Ipv4Address::from_octets([0, 1, 2, 3]),
            Ipv4Address::from_octets([127, 1, 2, 3]),
            Ipv4Address::from_octets([224, 1, 2, 3]),
            Ipv4Address::from_octets([255; 4]),
        ] {
            assert!(forbidden_target(target_ip));
        }
    }

    #[test]
    fn next_generation_rejects_every_live_reverse_token_alias() {
        // Protects reverse-hold phase, key, and generation conjunctions from aliasing a live token.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        let unrelated_forward = ResolutionGenerationToken {
            egress: IfId(9),
            target: Ipv4Address::from_octets([203, 0, 113, 9]),
            generation: 99,
        };
        let reverse = ResolutionGenerationToken {
            egress: WAN,
            target: target(2),
            generation: 1,
        };
        let mut exact = failure_hold(
            ResolutionFailureHoldPhase::WaitingReverse,
            unrelated_forward,
        );
        exact.reverse = reverse;
        runtime.failure_holds[0] = exact;
        assert_eq!(runtime.next_generation(WAN, target(2), 0), 2);

        // Protects each reverse comparison when one field is deliberately mismatched.
        let mut phase_mismatch = exact;
        phase_mismatch.phase = ResolutionFailureHoldPhase::TerminalReady;
        runtime.failure_holds[0] = phase_mismatch;
        assert_eq!(runtime.next_generation(WAN, target(2), 0), 1);
        let mut egress_mismatch = exact;
        egress_mismatch.reverse.egress = REVERSE_EGRESS;
        runtime.failure_holds[0] = egress_mismatch;
        assert_eq!(runtime.next_generation(WAN, target(2), 0), 1);
        let mut target_mismatch = exact;
        target_mismatch.reverse.target = target(3);
        runtime.failure_holds[0] = target_mismatch;
        assert_eq!(runtime.next_generation(WAN, target(2), 0), 1);
        let mut generation_mismatch = exact;
        generation_mismatch.reverse.generation = 2;
        runtime.failure_holds[0] = generation_mismatch;
        assert_eq!(runtime.next_generation(WAN, target(2), 0), 1);

        // Protects every reverse && operator from accepting an alias when one operand is false.
        let mut phase_or_egress = exact;
        phase_or_egress.reverse.egress = REVERSE_EGRESS;
        runtime.failure_holds[0] = phase_or_egress;
        assert_eq!(runtime.next_generation(WAN, target(2), 0), 1);
        let mut egress_or_target = exact;
        egress_or_target.reverse.target = target(3);
        runtime.failure_holds[0] = egress_or_target;
        assert_eq!(runtime.next_generation(WAN, target(2), 0), 1);
        let mut target_or_generation = exact;
        target_or_generation.reverse.generation = 2;
        runtime.failure_holds[0] = target_or_generation;
        assert_eq!(runtime.next_generation(WAN, target(2), 0), 1);
    }

    #[test]
    fn poll_timers_reports_only_a_matching_no_accepted_candidate() {
        // Protects no-accepted accounting and hold matching at terminal timeout.
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let token = ResolutionGenerationToken {
            egress: WAN,
            target: target(2),
            generation: 1,
        };
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Waiting, 1, 0, 1);
        runtime.states[0].requested_at = MonotonicMillis(0);
        runtime.pending_state_count = 1;
        runtime.failure_holds[0] = failure_hold(ResolutionFailureHoldPhase::WaitingForward, token);
        runtime.pending_failure_hold_count = 1;
        let mut trace = TimerTrace::default();
        let report = runtime
            .poll_timers(MonotonicMillis(1_000), 1, &mut trace)
            .unwrap();
        assert_eq!((report.timed_out, report.no_accepted_arp_request), (1, 1));
        assert_eq!(runtime.pending_failure_holds(), 0);
        assert!(matches!(
            trace.events[1],
            Some(ResolutionTimerTrace::NoAcceptedArpRequest { .. })
        ));

        // Protects the any() predicate from accepting the right phase with the wrong token.
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Waiting, 1, 0, 1);
        runtime.pending_state_count = 1;
        runtime.failure_holds[0] = failure_hold(
            ResolutionFailureHoldPhase::WaitingForward,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(3),
                generation: 1,
            },
        );
        runtime.pending_failure_hold_count = 1;
        let report = runtime
            .poll_timers(MonotonicMillis(1_000), 1, &mut NoResolutionTimerTrace)
            .unwrap();
        assert_eq!(report.no_accepted_arp_request, 0);
        assert_eq!(runtime.pending_failure_holds(), 1);
    }

    #[test]
    fn poll_timers_expires_forward_and_reverse_holds_only_on_exact_tokens() {
        // Protects terminal expiry cleanup for a matching forward token.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let token = ResolutionGenerationToken {
            egress: WAN,
            target: target(2),
            generation: 1,
        };
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        runtime.states[0].failed_at = MonotonicMillis(0);
        runtime.pending_state_count = 1;
        runtime.failure_holds[0] = failure_hold(ResolutionFailureHoldPhase::TerminalReady, token);
        runtime.pending_failure_hold_count = 1;
        let report = runtime
            .poll_timers(MonotonicMillis(1_000), 1, &mut NoResolutionTimerTrace)
            .unwrap();
        assert_eq!(report.failures_expired, 1);
        assert_eq!(runtime.pending_failure_holds(), 0);

        // Protects reverse-only cleanup from requiring the forward token to match as well.
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        runtime.states[0].failed_at = MonotonicMillis(0);
        runtime.pending_state_count = 1;
        let mut reverse_hold = failure_hold(
            ResolutionFailureHoldPhase::WaitingReverse,
            ResolutionGenerationToken {
                egress: REVERSE_EGRESS,
                target: target(3),
                generation: 7,
            },
        );
        reverse_hold.reverse = token;
        runtime.failure_holds[0] = reverse_hold;
        runtime.pending_failure_hold_count = 1;
        let report = runtime
            .poll_timers(MonotonicMillis(1_000), 1, &mut NoResolutionTimerTrace)
            .unwrap();
        assert_eq!(report.failures_expired, 1);
        assert_eq!(runtime.pending_failure_holds(), 0);

        // Protects phase and reverse-field checks from clearing an unrelated reverse token.
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        runtime.states[0].failed_at = MonotonicMillis(0);
        runtime.pending_state_count = 1;
        let mut unrelated_phase = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: REVERSE_EGRESS,
                target: target(3),
                generation: 7,
            },
        );
        unrelated_phase.reverse = token;
        runtime.failure_holds[0] = unrelated_phase;
        runtime.failure_holds[1] = ResolutionFailureHoldSlot::EMPTY;
        runtime.pending_failure_hold_count = 1;
        let report = runtime
            .poll_timers(MonotonicMillis(1_000), 1, &mut NoResolutionTimerTrace)
            .unwrap();
        assert_eq!(report.failures_expired, 1);
        assert_eq!(runtime.pending_failure_holds(), 1);
    }

    #[test]
    fn capture_failure_candidate_requires_an_active_exact_generation() {
        // Protects capture from inactive, differently keyed, and duplicate candidates.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let original_ipv4 = [0x45, 0, 0, 4];
        let capture_args = |runtime: &mut ResolutionRuntime<'_>| {
            runtime.capture_failure_candidate(
                WAN,
                target(2),
                ORIGINAL_SOURCE,
                target(2),
                SOURCE_MAC,
                SOURCE_IP,
                FORWARD_PREFIX,
                24,
                0x12,
                &original_ipv4,
            )
        };

        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Waiting, 1, 0, 1);
        runtime.pending_state_count = 1;
        assert!(matches!(
            capture_args(&mut runtime),
            ResolutionFailureCapture::Captured(_)
        ));
        assert!(matches!(
            capture_args(&mut runtime),
            ResolutionFailureCapture::Existing(_)
        ));

        runtime.states[0].phase = ResolutionPhase::Failed;
        assert_eq!(
            capture_args(&mut runtime),
            ResolutionFailureCapture::Inactive
        );

        // Each mismatch makes the original conjunction false while retaining the other fields.
        for mismatch in 0..3 {
            let mut states = [ResolutionStateSlot::EMPTY; 1];
            let mut actions = [];
            let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
                policy,
                &mut states,
                &mut actions,
                &mut [],
                &mut holds,
            );
            let mut candidate = state_slot(action(2), ResolutionPhase::Waiting, 1, 0, 1);
            match mismatch {
                0 => candidate.occupied = false,
                1 => {
                    candidate.key.egress = REVERSE_EGRESS;
                    candidate.action.egress = REVERSE_EGRESS;
                }
                2 => {
                    candidate.key.target = target(3);
                    candidate.action.target_ip = target(3);
                }
                _ => unreachable!(),
            }
            runtime.states[0] = candidate;
            assert_eq!(
                capture_args(&mut runtime),
                ResolutionFailureCapture::Inactive
            );
        }
    }

    #[test]
    fn schedule_rejects_each_forbidden_target_reason_independently() {
        // Protects the three independent forbidden-target checks from being joined with AND.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 3];
        let mut actions = [ResolutionActionSlot::EMPTY; 3];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), true),
            ResolutionResult::ForbiddenTarget
        );

        let mut self_target = action(3);
        self_target.target_ip = self_target.source_ip;
        assert_eq!(
            runtime.schedule(self_target, MonotonicMillis(0), false),
            ResolutionResult::ForbiddenTarget
        );

        let mut multicast = action(4);
        multicast.target_ip = Ipv4Address::from_octets([224, 0, 0, 1]);
        assert_eq!(
            runtime.schedule(multicast, MonotonicMillis(0), false),
            ResolutionResult::ForbiddenTarget
        );
        assert_eq!(runtime.counters().forbidden_target, 3);
    }

    #[test]
    fn dynamic_lookup_and_merge_require_exact_keys_and_ttl_boundaries() {
        // Protects dynamic lookup from matching an occupied slot on only one key component.
        let policy = ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 1_000, 1_000).unwrap();
        let dynamic_slot = DynamicNeighborSlot {
            interface: WAN,
            target: target(2),
            mac: MacAddress([7; 6]),
            refreshed_at: MonotonicMillis(0),
            occupied: true,
        };
        let mut states = [];
        let mut actions = [];
        let mut dynamic = [dynamic_slot];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.dynamic_neighbors[0] = dynamic_slot;
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(2), MonotonicMillis(1)),
            DynamicLookup::Hit(MacAddress([7; 6]))
        );
        assert_eq!(
            runtime.lookup_dynamic(REVERSE_EGRESS, target(2), MonotonicMillis(1)),
            DynamicLookup::Miss
        );
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(3), MonotonicMillis(1)),
            DynamicLookup::Miss
        );

        // Protects merge from treating an empty slot as an existing entry.
        let mut states = [];
        let mut actions = [];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        assert_eq!(
            runtime.merge_dynamic(
                IfId(0),
                Ipv4Address::from_octets([0; 4]),
                MacAddress([1; 6]),
                true,
                false,
                MonotonicMillis(0),
            ),
            ControlDisposition::Inserted
        );

        // Protects exact-key updates and prevents a fresh mismatched entry from being updated.
        let mut states = [];
        let mut actions = [];
        let mut dynamic = [dynamic_slot];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.dynamic_neighbors[0] = dynamic_slot;
        assert_eq!(
            runtime.merge_dynamic(
                WAN,
                target(2),
                MacAddress([8; 6]),
                true,
                false,
                MonotonicMillis(1),
            ),
            ControlDisposition::Updated
        );
        assert_eq!(
            runtime.merge_dynamic(
                REVERSE_EGRESS,
                target(2),
                MacAddress([9; 6]),
                true,
                false,
                MonotonicMillis(1),
            ),
            ControlDisposition::CacheFull
        );

        // Protects strict expiration at equality and after the configured TTL.
        for now in [1_000, 2_001] {
            let mut states = [];
            let mut actions = [];
            let mut dynamic = [dynamic_slot];
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
                policy,
                &mut states,
                &mut actions,
                &mut dynamic,
            );
            runtime.dynamic_neighbors[0] = dynamic_slot;
            assert_eq!(
                runtime.merge_dynamic(
                    WAN,
                    target(2),
                    MacAddress([8; 6]),
                    true,
                    false,
                    MonotonicMillis(now),
                ),
                ControlDisposition::Inserted
            );
        }

        // Protects reuse of a stale occupied slot for a different key.
        let mut states = [];
        let mut actions = [];
        let mut dynamic = [dynamic_slot];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.dynamic_neighbors[0] = dynamic_slot;
        assert_eq!(
            runtime.merge_dynamic(
                WAN,
                target(3),
                MacAddress([9; 6]),
                true,
                false,
                MonotonicMillis(1_000),
            ),
            ControlDisposition::Inserted
        );
    }

    #[test]
    fn observe_control_clear_resolution_and_static_key_use_exact_keys() {
        // Protects control-clock monotonicity independently of packet-resolution decisions.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert!(runtime.observe_control(MonotonicMillis(10)));
        assert!(!runtime.observe_control(MonotonicMillis(9)));

        // Protects clear_resolution from cancelling a state, action, or hold on a partial key.
        let mut states = [ResolutionStateSlot::EMPTY; 3];
        let mut actions = [ResolutionActionSlot::EMPTY; 3];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 3];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        let mut other_egress = action(2);
        other_egress.egress = REVERSE_EGRESS;
        runtime.states[0] = state_slot(other_egress, ResolutionPhase::Waiting, 0, 0, 1);
        runtime.states[1] = state_slot(action(3), ResolutionPhase::Waiting, 0, 0, 1);
        runtime.states[2] = state_slot(action(2), ResolutionPhase::Waiting, 0, 0, 1);
        runtime.pending_state_count = 3;
        runtime.actions[0].0 = Some(QueuedAction {
            action: other_egress,
            generation: 1,
        });
        runtime.actions[1].0 = Some(QueuedAction {
            action: action(3),
            generation: 1,
        });
        runtime.actions[2].0 = Some(QueuedAction {
            action: action(2),
            generation: 1,
        });
        runtime.len = 3;
        runtime.failure_holds[0] = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: REVERSE_EGRESS,
                target: target(2),
                generation: 1,
            },
        );
        runtime.failure_holds[1] = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(3),
                generation: 1,
            },
        );
        runtime.failure_holds[2] = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        runtime.pending_failure_hold_count = 3;
        runtime.clear_resolution(WAN, target(2));
        assert!(runtime.states[0].is_occupied());
        assert!(runtime.states[1].is_occupied());
        assert!(!runtime.states[2].is_occupied());
        assert_eq!(runtime.pending_actions(), 2);
        assert_eq!(runtime.pending_failure_holds(), 2);

        // Protects reconcile_static_key from deleting a dynamic neighbor on a partial key.
        let mut states = [];
        let mut actions = [];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 3];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.dynamic_neighbors[0] = DynamicNeighborSlot {
            interface: REVERSE_EGRESS,
            target: target(2),
            mac: MacAddress([1; 6]),
            refreshed_at: MonotonicMillis(0),
            occupied: true,
        };
        runtime.dynamic_neighbors[1] = DynamicNeighborSlot {
            interface: WAN,
            target: target(3),
            mac: MacAddress([2; 6]),
            refreshed_at: MonotonicMillis(0),
            occupied: true,
        };
        runtime.dynamic_neighbors[2] = DynamicNeighborSlot {
            interface: WAN,
            target: target(2),
            mac: MacAddress([3; 6]),
            refreshed_at: MonotonicMillis(0),
            occupied: true,
        };
        runtime.reconcile_static_key(WAN, target(2));
        assert!(runtime.dynamic_neighbors[0].is_occupied());
        assert!(runtime.dynamic_neighbors[1].is_occupied());
        assert!(!runtime.dynamic_neighbors[2].is_occupied());
    }

    #[test]
    fn observe_and_execution_time_validation_preserve_regressions() {
        // Protects execution-time validation from accepting a regressed timestamp or rejecting a valid one.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert!(runtime.execution_time_valid(MonotonicMillis(10)));
        assert!(!runtime.execution_time_valid(MonotonicMillis(9)));
    }

    #[test]
    fn mark_failed_filters_hold_phase_and_generation_for_both_acceptance_paths() {
        // Protects no-accepted failure cleanup from clearing a hold with a different token.
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Waiting, 1, 0, 1);
        runtime.pending_state_count = 1;
        runtime.failure_holds[0] = failure_hold(
            ResolutionFailureHoldPhase::WaitingForward,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        runtime.failure_holds[1] = failure_hold(
            ResolutionFailureHoldPhase::WaitingForward,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(3),
                generation: 1,
            },
        );
        runtime.pending_failure_hold_count = 2;
        assert_eq!(
            runtime.mark_failed(0, MonotonicMillis(1)),
            ResolutionResult::TimedOut
        );
        assert_eq!(runtime.pending_failure_holds(), 1);
        assert_eq!(
            runtime.failure_holds[1].phase,
            ResolutionFailureHoldPhase::WaitingForward
        );
        assert_eq!(runtime.failure_counters.no_accepted_arp_request, 1);

        // Protects accepted failure promotion from promoting a hold for a different token.
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Waiting, 1, 1, 1);
        runtime.pending_state_count = 1;
        runtime.failure_holds[0] = failure_hold(
            ResolutionFailureHoldPhase::WaitingForward,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        runtime.failure_holds[1] = failure_hold(
            ResolutionFailureHoldPhase::WaitingForward,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(3),
                generation: 1,
            },
        );
        runtime.pending_failure_hold_count = 2;
        assert_eq!(
            runtime.mark_failed(0, MonotonicMillis(1)),
            ResolutionResult::TimedOut
        );
        assert_eq!(
            runtime.failure_holds[0].phase,
            ResolutionFailureHoldPhase::TerminalReady
        );
        assert_eq!(
            runtime.failure_holds[1].phase,
            ResolutionFailureHoldPhase::WaitingForward
        );
        assert_eq!(runtime.failure_counters.promoted, 1);
    }

    #[test]
    fn slot_accessors_report_occupancy_and_terminal_notification_exactly() {
        // Protects the public slot accessors from returning constants instead of stored state.
        let mut state = ResolutionStateSlot::EMPTY;
        assert!(!state.is_occupied());
        assert!(!state.failure_notified());
        state.occupied = true;
        state.failure_notified = true;
        assert!(state.is_occupied());
        assert!(state.failure_notified());

        let mut neighbor = DynamicNeighborSlot::EMPTY;
        assert!(!neighbor.is_occupied());
        neighbor.occupied = true;
        assert!(neighbor.is_occupied());
    }

    #[test]
    fn queued_action_checks_both_position_window_and_storage_capacity() {
        // Protects the empty-queue and out-of-window contracts of queued_action.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(runtime.queued_action(0), None);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        assert_eq!(runtime.queued_action(0), Some((action(2), 1)));
        assert_eq!(runtime.queued_action(1), None);

        let mut states = [];
        let mut actions = [];
        let runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(runtime.queued_action(0), None);
    }

    #[test]
    fn is_pristine_checks_actions_dynamic_neighbors_and_failure_holds_independently() {
        // Protects the exact-constructor predicate for each caller-owned storage class.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();

        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert!(runtime.is_pristine());
        runtime.actions[0].0 = Some(QueuedAction {
            action: action(2),
            generation: 1,
        });
        assert!(!runtime.is_pristine());

        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        assert!(runtime.is_pristine());
        runtime.dynamic_neighbors[0].occupied = true;
        assert!(!runtime.is_pristine());

        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        assert!(runtime.is_pristine());
        runtime.failure_holds[0].phase = ResolutionFailureHoldPhase::TerminalReady;
        assert!(!runtime.is_pristine());
    }

    #[test]
    fn reconcile_static_requires_exact_dynamic_state_action_and_hold_keys() {
        // Protects dynamic-neighbor reconciliation from occupancy, interface, and target overmatching.
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let dynamic_slot = DynamicNeighborSlot {
            interface: WAN,
            target: target(2),
            mac: MacAddress([7; 6]),
            refreshed_at: MonotonicMillis(0),
            occupied: true,
        };
        for neighbor in [
            Neighbor {
                interface: IfId(3),
                target: target(2),
                mac: MacAddress([8; 6]),
            },
            Neighbor {
                interface: WAN,
                target: target(3),
                mac: MacAddress([8; 6]),
            },
        ] {
            let mut states = [];
            let mut actions = [];
            let mut dynamic = [dynamic_slot];
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
                policy,
                &mut states,
                &mut actions,
                &mut dynamic,
            );
            runtime.dynamic_neighbors[0] = dynamic_slot;
            assert_eq!(
                runtime.reconcile_static(&[neighbor]),
                StaticReconcileReport::default()
            );
            assert!(runtime.dynamic_neighbors[0].is_occupied());
        }
        let mut states = [];
        let mut actions = [];
        let mut dynamic = [dynamic_slot];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.dynamic_neighbors[0] = dynamic_slot;
        assert_eq!(
            runtime.reconcile_static(&[Neighbor {
                interface: WAN,
                target: target(2),
                mac: MacAddress([8; 6]),
            }]),
            StaticReconcileReport {
                dynamic_removed: 1,
                ..StaticReconcileReport::default()
            }
        );
        assert!(!runtime.dynamic_neighbors[0].is_occupied());

        // Protects state reconciliation from removing empty, cooldown, or differently keyed states.
        let state = ResolutionStateSlot {
            key: ResolutionKey {
                egress: WAN,
                target: target(2),
            },
            action: action(2),
            generation: 1,
            attempts: 1,
            accepted_attempts: 0,
            requested_at: MonotonicMillis(0),
            failed_at: MonotonicMillis(0),
            occupied: true,
            phase: ResolutionPhase::Waiting,
            failure_notified: false,
        };
        for neighbor in [
            Neighbor {
                interface: IfId(3),
                target: target(2),
                mac: MacAddress([8; 6]),
            },
            Neighbor {
                interface: WAN,
                target: target(3),
                mac: MacAddress([8; 6]),
            },
        ] {
            let mut states = [state];
            let mut actions = [];
            let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
            runtime.states[0] = state;
            runtime.pending_state_count = 1;
            assert_eq!(
                runtime.reconcile_static(&[neighbor]),
                StaticReconcileReport::default()
            );
            assert!(runtime.states[0].is_occupied());
        }
        let mut states = [state];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.states[0] = state;
        runtime.pending_state_count = 1;
        assert_eq!(
            runtime.reconcile_static(&[Neighbor {
                interface: WAN,
                target: target(2),
                mac: MacAddress([8; 6]),
            }]),
            StaticReconcileReport {
                states_removed: 1,
                cooldowns_retained: 1,
                ..StaticReconcileReport::default()
            }
        );
        assert!(runtime.states[0].is_occupied());
        assert_eq!(runtime.states[0].phase(), ResolutionPhase::Cooldown);

        let mut cooldown = state;
        cooldown.phase = ResolutionPhase::Cooldown;
        let mut states = [cooldown];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.states[0] = cooldown;
        assert_eq!(
            runtime.reconcile_static(&[Neighbor {
                interface: WAN,
                target: target(2),
                mac: MacAddress([8; 6]),
            }]),
            StaticReconcileReport::default()
        );
        assert!(runtime.states[0].is_occupied());

        // Protects action compaction from matching a neighbor on only one key component.
        for neighbor in [
            Neighbor {
                interface: IfId(3),
                target: target(2),
                mac: MacAddress([8; 6]),
            },
            Neighbor {
                interface: WAN,
                target: target(3),
                mac: MacAddress([8; 6]),
            },
        ] {
            let mut states = [];
            let mut actions = [ResolutionActionSlot(Some(QueuedAction {
                action: action(2),
                generation: 1,
            }))];
            let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
            runtime.actions[0].0 = Some(QueuedAction {
                action: action(2),
                generation: 1,
            });
            runtime.len = 1;
            assert_eq!(runtime.reconcile_static(&[neighbor]).actions_removed, 0);
            assert_eq!(runtime.pending_actions(), 1);
        }
        let mut states = [];
        let mut actions = [ResolutionActionSlot(Some(QueuedAction {
            action: action(2),
            generation: 1,
        }))];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.actions[0].0 = Some(QueuedAction {
            action: action(2),
            generation: 1,
        });
        runtime.len = 1;
        assert_eq!(
            runtime
                .reconcile_static(&[Neighbor {
                    interface: WAN,
                    target: target(2),
                    mac: MacAddress([8; 6]),
                }])
                .actions_removed,
            1
        );
        assert_eq!(runtime.pending_actions(), 0);

        // Protects failure-hold reconciliation from clearing a hold unless both key fields match.
        let hold = ResolutionFailureHoldSlot {
            phase: ResolutionFailureHoldPhase::TerminalReady,
            forward: ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
            ..ResolutionFailureHoldSlot::EMPTY
        };
        for neighbor in [
            Neighbor {
                interface: IfId(3),
                target: target(2),
                mac: MacAddress([8; 6]),
            },
            Neighbor {
                interface: WAN,
                target: target(3),
                mac: MacAddress([8; 6]),
            },
        ] {
            let mut states = [];
            let mut actions = [];
            let mut holds = [hold];
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
                policy,
                &mut states,
                &mut actions,
                &mut [],
                &mut holds,
            );
            runtime.failure_holds[0] = hold;
            runtime.pending_failure_hold_count = 1;
            assert_eq!(
                runtime.reconcile_static(&[neighbor]),
                StaticReconcileReport::default()
            );
            assert_eq!(runtime.pending_failure_holds(), 1);
        }
        let mut states = [];
        let mut actions = [];
        let mut holds = [hold];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.failure_holds[0] = hold;
        runtime.pending_failure_hold_count = 1;
        runtime.reconcile_static(&[Neighbor {
            interface: WAN,
            target: target(2),
            mac: MacAddress([8; 6]),
        }]);
        assert_eq!(runtime.pending_failure_holds(), 0);
        assert_eq!(runtime.failure_counters.cancelled, 1);
    }

    #[test]
    fn dispatch_one_failure_requires_current_failed_forward_status() {
        // Protects the successful dispatch baseline used by every forward-status guard.
        let fixture = FailureSnapshotFixture::direct(true);
        let hold = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        let valid_state = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        assert!(matches!(
            dispatch_failure_case(&fixture, hold, &[valid_state], &[]).0,
            FailureDispatch::Queued(REVERSE_EGRESS)
        ));

        // Protects generation identity: a stale failed generation cannot emit an ICMP error.
        let mut generation_mismatch = valid_state;
        generation_mismatch.generation = 2;
        assert!(matches!(
            dispatch_failure_case(&fixture, hold, &[generation_mismatch], &[]).0,
            FailureDispatch::AuthorityLost
        ));

        // Protects the Failed phase requirement: Waiting is not terminal authority.
        let mut phase_mismatch = valid_state;
        phase_mismatch.phase = ResolutionPhase::Waiting;
        assert!(matches!(
            dispatch_failure_case(&fixture, hold, &[phase_mismatch], &[]).0,
            FailureDispatch::AuthorityLost
        ));

        // Protects accepted-attempt evidence: a timeout without an accepted ARP is not dispatchable.
        let mut accepted_mismatch = valid_state;
        accepted_mismatch.accepted_attempts = 0;
        assert!(matches!(
            dispatch_failure_case(&fixture, hold, &[accepted_mismatch], &[]).0,
            FailureDispatch::AuthorityLost
        ));
    }

    #[test]
    fn dispatch_one_failure_direct_call_queues_with_valid_authority() {
        // Protects the direct dispatch entry point from losing the valid
        // forward/reverse fixture before queueing a host-unreachable error.
        let fixture = FailureSnapshotFixture::direct(true);
        let snapshot = fixture.snapshot();
        let hold = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
        );
        resolution.states[0] = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        let mut icmp_states = [crate::Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut icmp_actions = [crate::Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
            crate::Icmpv4ErrorPolicy::default(),
            &mut icmp_states,
            &mut icmp_actions,
        );

        assert!(matches!(
            dispatch_one_failure(
                &mut resolution,
                &mut icmpv4_errors,
                &snapshot,
                MonotonicMillis(0),
                hold,
            ),
            FailureDispatch::Queued(REVERSE_EGRESS)
        ));
    }

    #[test]
    fn dispatch_one_failure_requires_each_forward_authority_field() {
        let fixture = FailureSnapshotFixture::direct(true);
        let hold = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        let valid_state = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        let authority_lost = |fixture: &FailureSnapshotFixture,
                              hold: ResolutionFailureHoldSlot,
                              states: &[ResolutionStateSlot]| {
            assert!(matches!(
                dispatch_failure_case(fixture, hold, states, &[]).0,
                FailureDispatch::AuthorityLost
            ));
        };

        // Protects every forward-route comparison and the route/interface OR boundary.
        let mut route_fixture = FailureSnapshotFixture::direct(true);
        route_fixture.routes[0] = Route::new(FORWARD_PREFIX, 24, REVERSE_EGRESS, None).unwrap();
        authority_lost(&route_fixture, hold, &[valid_state]);

        let mut route_fixture = FailureSnapshotFixture::direct(true);
        route_fixture.routes[0] = Route::new(FORWARD_PREFIX, 24, WAN, Some(target(9))).unwrap();
        authority_lost(&route_fixture, hold, &[valid_state]);

        let mut destination_mismatch = hold;
        destination_mismatch.original_destination = target(3);
        authority_lost(&fixture, destination_mismatch, &[valid_state]);

        let mut prefix_mismatch = hold;
        prefix_mismatch.forward_prefix = Ipv4Address::from_octets([192, 0, 3, 0]);
        authority_lost(&fixture, prefix_mismatch, &[valid_state]);

        let mut prefix_len_mismatch = hold;
        prefix_len_mismatch.forward_prefix_len = 23;
        authority_lost(&fixture, prefix_len_mismatch, &[valid_state]);

        // Protects forward interface identity and MAC comparisons independently.
        let mut interface_id_mismatch = FailureSnapshotFixture::direct(true);
        interface_id_mismatch.interfaces[0].mac = MacAddress([8; 6]);
        interface_id_mismatch.interfaces.push(Interface {
            id: IfId(9),
            mac: SOURCE_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        });
        authority_lost(&interface_id_mismatch, hold, &[valid_state]);

        let mut interface_mac_mismatch = FailureSnapshotFixture::direct(true);
        interface_mac_mismatch.interfaces[0].mac = MacAddress([8; 6]);
        authority_lost(&interface_mac_mismatch, hold, &[valid_state]);

        // Protects forward local-binding identity and address comparisons independently.
        let mut binding_interface_mismatch = FailureSnapshotFixture::direct(true);
        binding_interface_mismatch.bindings[0].address = target(9);
        binding_interface_mismatch.bindings.push(LocalIpv4Binding {
            interface: IfId(9),
            address: SOURCE_IP,
        });
        binding_interface_mismatch.interfaces.push(Interface {
            id: IfId(9),
            mac: MacAddress([9; 6]),
            mtu: Ipv4Mtu::ETHERNET,
        });
        authority_lost(&binding_interface_mismatch, hold, &[valid_state]);

        let mut binding_address_mismatch = FailureSnapshotFixture::direct(true);
        binding_address_mismatch.bindings[0].address = target(9);
        authority_lost(&binding_address_mismatch, hold, &[valid_state]);

        // Protects an exact forward static neighbor from being dispatched.
        let mut static_neighbor = FailureSnapshotFixture::direct(true);
        static_neighbor.neighbors.push(Neighbor {
            interface: WAN,
            target: target(2),
            mac: MacAddress([8; 6]),
        });
        authority_lost(&static_neighbor, hold, &[valid_state]);

        // Protects host-forbidden forward targets as a separate authority condition.
        let mut forbidden_hold = hold;
        forbidden_hold.forward.target = SOURCE_IP;
        forbidden_hold.original_destination = SOURCE_IP;
        let forbidden_state = state_slot(
            ArpRequestAction {
                egress: WAN,
                source_mac: SOURCE_MAC,
                source_ip: SOURCE_IP,
                target_ip: SOURCE_IP,
            },
            ResolutionPhase::Failed,
            1,
            1,
            1,
        );
        authority_lost(&fixture, forbidden_hold, &[forbidden_state]);

        // Protects mismatched forward neighbors from being treated as exact matches.
        for neighbor in [
            Neighbor {
                interface: WAN,
                target: target(3),
                mac: MacAddress([8; 6]),
            },
            Neighbor {
                interface: REVERSE_EGRESS,
                target: target(2),
                mac: MacAddress([8; 6]),
            },
        ] {
            let mut mismatch = FailureSnapshotFixture::direct(true);
            mismatch.neighbors.push(neighbor);
            let (outcome, _, generated) =
                dispatch_failure_case(&mismatch, hold, &[valid_state], &[]);
            assert!(matches!(outcome, FailureDispatch::Queued(REVERSE_EGRESS)));
            let generated = generated.unwrap();
            assert_eq!(generated.source_mac, REVERSE_MAC);
            assert_eq!(generated.source_ip, REVERSE_SOURCE_IP);
        }
    }

    #[test]
    fn dispatch_one_failure_requires_reverse_authority_and_exact_neighbor_keys() {
        let hold = failure_hold(
            ResolutionFailureHoldPhase::TerminalReady,
            ResolutionGenerationToken {
                egress: WAN,
                target: target(2),
                generation: 1,
            },
        );
        let forward_state = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);

        // Protects reverse interface selection; a changed comparison must alter the ICMP source MAC.
        let fixture = FailureSnapshotFixture::direct(true);
        let (outcome, _, generated) = dispatch_failure_case(&fixture, hold, &[forward_state], &[]);
        assert!(matches!(outcome, FailureDispatch::Queued(REVERSE_EGRESS)));
        assert_eq!(generated.unwrap().source_mac, REVERSE_MAC);

        // Protects reverse binding selection; a changed comparison must alter the ICMP source IP.
        let mut wrong_binding = FailureSnapshotFixture::direct(true);
        wrong_binding.bindings.swap(0, 1);
        let (outcome, _, generated) =
            dispatch_failure_case(&wrong_binding, hold, &[forward_state], &[]);
        assert!(matches!(outcome, FailureDispatch::Queued(REVERSE_EGRESS)));
        assert_eq!(generated.unwrap().source_ip, REVERSE_SOURCE_IP);

        // Protects SameFailedKey before reverse-neighbor lookup.
        let same_key_fixture = FailureSnapshotFixture {
            routes: vec![Route::new(FORWARD_PREFIX, 24, WAN, None).unwrap()],
            interfaces: vec![Interface {
                id: WAN,
                mac: SOURCE_MAC,
                mtu: Ipv4Mtu::ETHERNET,
            }],
            neighbors: Vec::new(),
            bindings: vec![LocalIpv4Binding {
                interface: WAN,
                address: SOURCE_IP,
            }],
        };
        let mut same_key_hold = hold;
        same_key_hold.original_source = target(2);
        let (outcome, _, _) =
            dispatch_failure_case(&same_key_fixture, same_key_hold, &[forward_state], &[]);
        assert!(matches!(outcome, FailureDispatch::SameFailedKey));

        // Protects reverse-neighbor matching from accepting a target-only match.
        let mut wrong_target_neighbor = FailureSnapshotFixture::direct(false);
        wrong_target_neighbor.neighbors.push(Neighbor {
            interface: REVERSE_EGRESS,
            target: target(3),
            mac: MacAddress([8; 6]),
        });
        let (outcome, _, _) = dispatch_failure_case(
            &wrong_target_neighbor,
            hold,
            &[forward_state, ResolutionStateSlot::EMPTY],
            &[],
        );
        assert!(matches!(outcome, FailureDispatch::WaitReverse { .. }));

        // Protects reverse-neighbor matching from accepting an interface-only match.
        let mut wrong_interface_neighbor = FailureSnapshotFixture::direct(false);
        wrong_interface_neighbor.neighbors.push(Neighbor {
            interface: WAN,
            target: ORIGINAL_SOURCE,
            mac: MacAddress([8; 6]),
        });
        let (outcome, _, _) = dispatch_failure_case(
            &wrong_interface_neighbor,
            hold,
            &[forward_state, ResolutionStateSlot::EMPTY],
            &[],
        );
        assert!(matches!(outcome, FailureDispatch::WaitReverse { .. }));
    }

    #[test]
    fn dispatch_one_failure_requires_exact_waiting_reverse_token() {
        let fixture = FailureSnapshotFixture::direct(false);
        let forward_token = ResolutionGenerationToken {
            egress: WAN,
            target: target(2),
            generation: 1,
        };
        let reverse_token = ResolutionGenerationToken {
            egress: REVERSE_EGRESS,
            target: ORIGINAL_SOURCE,
            generation: 7,
        };
        let forward_state = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        let reverse_action = ArpRequestAction {
            egress: REVERSE_EGRESS,
            source_mac: REVERSE_MAC,
            source_ip: REVERSE_SOURCE_IP,
            target_ip: ORIGINAL_SOURCE,
        };
        let reverse_failed = state_slot(
            reverse_action,
            ResolutionPhase::Failed,
            1,
            1,
            reverse_token.generation,
        );

        // Protects the successful WaitingReverse/Failed-token branch.
        let mut exact = failure_hold(ResolutionFailureHoldPhase::WaitingReverse, forward_token);
        exact.reverse = reverse_token;
        let (outcome, _, _) =
            dispatch_failure_case(&fixture, exact, &[forward_state, reverse_failed], &[]);
        assert!(matches!(outcome, FailureDispatch::ReverseFailed(token) if token == reverse_token));

        // Protects the hold phase check; TerminalReady must use the normal schedule path.
        let mut phase_mismatch = exact;
        phase_mismatch.phase = ResolutionFailureHoldPhase::TerminalReady;
        let (outcome, counters, _) = dispatch_failure_case(
            &fixture,
            phase_mismatch,
            &[forward_state, reverse_failed],
            &[],
        );
        assert!(matches!(outcome, FailureDispatch::ReverseFailed(token) if token == reverse_token));
        assert_eq!(counters.failed_hits, 1);

        // Protects reverse-egress matching; a failed state at another egress is not an alias.
        let mut egress_mismatch = exact;
        egress_mismatch.reverse.egress = WAN;
        let wrong_egress_state = state_slot(
            ArpRequestAction {
                egress: WAN,
                source_mac: SOURCE_MAC,
                source_ip: SOURCE_IP,
                target_ip: ORIGINAL_SOURCE,
            },
            ResolutionPhase::Failed,
            1,
            1,
            reverse_token.generation,
        );
        let (outcome, _, _) = dispatch_failure_case(
            &fixture,
            egress_mismatch,
            &[
                forward_state,
                wrong_egress_state,
                ResolutionStateSlot::EMPTY,
            ],
            &[],
        );
        assert!(matches!(outcome, FailureDispatch::WaitReverse { .. }));

        // Protects reverse-target matching; a failed state for another target is not an alias.
        let mut target_mismatch = exact;
        target_mismatch.reverse.target = target(3);
        let wrong_target_state = state_slot(
            ArpRequestAction {
                egress: REVERSE_EGRESS,
                source_mac: REVERSE_MAC,
                source_ip: REVERSE_SOURCE_IP,
                target_ip: target(3),
            },
            ResolutionPhase::Failed,
            1,
            1,
            reverse_token.generation,
        );
        let (outcome, _, _) = dispatch_failure_case(
            &fixture,
            target_mismatch,
            &[
                forward_state,
                wrong_target_state,
                ResolutionStateSlot::EMPTY,
            ],
            &[],
        );
        assert!(matches!(outcome, FailureDispatch::WaitReverse { .. }));

        // Protects reverse generation matching and the status-generation conjunction.
        let mut generation_mismatch = exact;
        generation_mismatch.reverse.generation = 8;
        let (outcome, _, _) = dispatch_failure_case(
            &fixture,
            generation_mismatch,
            &[forward_state, reverse_failed],
            &[],
        );
        assert!(matches!(outcome, FailureDispatch::ReverseFailed(token) if token == reverse_token));

        // Protects status phase matching; Waiting remains a pending reverse resolution.
        let reverse_waiting = state_slot(
            reverse_action,
            ResolutionPhase::Waiting,
            1,
            1,
            reverse_token.generation,
        );
        let (outcome, _, _) =
            dispatch_failure_case(&fixture, exact, &[forward_state, reverse_waiting], &[]);
        assert!(matches!(outcome, FailureDispatch::WaitReverse { .. }));
    }

    #[test]
    fn poll_timers_does_not_count_an_accepted_matching_forward_candidate() {
        // Protects accepted_attempts == 0 && WaitingForward: an accepted ARP is not unaccepted.
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let token = ResolutionGenerationToken {
            egress: WAN,
            target: target(2),
            generation: 1,
        };
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Waiting, 1, 1, 1);
        runtime.states[0].requested_at = MonotonicMillis(0);
        runtime.pending_state_count = 1;
        runtime.failure_holds[0] = failure_hold(ResolutionFailureHoldPhase::WaitingForward, token);
        runtime.pending_failure_hold_count = 1;
        let report = runtime
            .poll_timers(MonotonicMillis(1_000), 1, &mut NoResolutionTimerTrace)
            .unwrap();
        assert_eq!(report.timed_out, 1);
        assert_eq!(report.no_accepted_arp_request, 0);
        assert_eq!(runtime.pending_failure_holds(), 1);
    }

    #[test]
    fn poll_timers_ignores_an_empty_hold_even_when_its_stale_token_matches() {
        // Protects the live-hold outer guard: an empty slot must never be cleared or counted.
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let token = ResolutionGenerationToken {
            egress: WAN,
            target: target(2),
            generation: 1,
        };
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.states[0] = state_slot(action(2), ResolutionPhase::Failed, 1, 1, 1);
        runtime.states[0].failed_at = MonotonicMillis(0);
        runtime.pending_state_count = 1;
        runtime.failure_holds[0].forward = token;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.poll_timers(MonotonicMillis(1_000), 1, &mut NoResolutionTimerTrace)
        }));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap().failures_expired, 1);
        assert_eq!(runtime.pending_failure_holds(), 0);
    }

    struct ShortVisibleArpBatch {
        completion: Rc<RefCell<Option<crate::GeneratedSlotCompletion>>>,
    }

    struct ShortVisibleArpSlot {
        bytes: Vec<u8>,
        completion: Rc<RefCell<Option<crate::GeneratedSlotCompletion>>>,
    }

    impl GeneratedPacketBatch for ShortVisibleArpBatch {
        type Error = ();
        type Slot<'a>
            = ShortVisibleArpSlot
        where
            Self: 'a;

        fn allocate(
            &mut self,
            frame_len: usize,
        ) -> Result<crate::GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
            assert_eq!(frame_len, ARP_REQUEST_FRAME_LEN);
            Ok(crate::GeneratedPacketLease::new(ShortVisibleArpSlot {
                bytes: vec![0; frame_len - 1],
                completion: Rc::clone(&self.completion),
            }))
        }

        fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
            GeneratedBatchCompletion {
                attempts: 0,
                allocated: 0,
                failed: 0,
                requested: 0,
                cancelled: 0,
                abandoned: 0,
                accepted: 0,
                rejected: 0,
                error: None,
            }
        }
    }

    impl crate::GeneratedPacketSlot for ShortVisibleArpSlot {
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.bytes
        }

        fn complete(self, completion: crate::GeneratedSlotCompletion) {
            *self.completion.borrow_mut() = Some(completion);
        }
    }

    #[test]
    fn allocate_arp_request_rejects_short_visible_buffer_and_cancels_lease() {
        // Protects the exact-length guard and ensures a short backend buffer is cancelled.
        let completion = Rc::new(RefCell::new(None));
        let mut batch = ShortVisibleArpBatch {
            completion: Rc::clone(&completion),
        };

        let result = allocate_arp_request(&mut batch, action(2));

        assert!(matches!(
            result,
            Err(ArpRequestGenerationError::Build(
                ArpRequestBuildError::ExactLengthRequired
            ))
        ));
        assert_eq!(
            *completion.borrow(),
            Some(crate::GeneratedSlotCompletion::Cancelled)
        );
    }

    const HOLD_EGRESS: IfId = IfId(2);
    const HOLD_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xcc]);

    fn hold_policy() -> ResolutionPolicy {
        ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 3_000, 60_000).unwrap()
    }

    fn held_frame(marker: u8, len: usize) -> Vec<u8> {
        let mut frame = vec![marker; len];
        // The destination MAC is the one field a held frame still lacks.
        frame[0..6].fill(0);
        frame
    }

    #[test]
    fn a_datagram_held_for_an_unresolved_hop_is_returned_once_the_hop_resolves() {
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut neighbors = [DynamicNeighborSlot::EMPTY; 1];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 2];
        let mut runtime =
            ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
                hold_policy(),
                &mut states,
                &mut actions,
                &mut neighbors,
                &mut failure_holds,
                &mut datagram_holds,
            );

        let frame = held_frame(0xa5, 64);
        assert_eq!(
            runtime.hold_datagram(HOLD_EGRESS, target(9), &frame, MonotonicMillis(0)),
            ResolutionHoldDisposition::Held {
                egress: HOLD_EGRESS,
                len: 64
            }
        );
        assert_eq!(runtime.held_datagram_count(), 1);
        // Nothing is released while the address is still unknown.
        assert!(runtime
            .take_resolved_datagram(MonotonicMillis(10))
            .is_none());

        runtime.merge_dynamic(
            HOLD_EGRESS,
            target(9),
            HOLD_MAC,
            true,
            false,
            MonotonicMillis(20),
        );
        let (egress, mac, replayed) = runtime
            .take_resolved_datagram(MonotonicMillis(20))
            .expect("a resolved hop must release its held datagram");
        assert_eq!(egress, HOLD_EGRESS);
        assert_eq!(mac, HOLD_MAC);
        assert_eq!(replayed, frame.as_slice());
        assert_eq!(runtime.held_datagram_count(), 0);
        assert_eq!(runtime.hold_counters().held, 1);
        assert_eq!(runtime.hold_counters().replayed, 1);
    }

    #[test]
    fn a_second_datagram_for_the_same_hop_replaces_the_first() {
        // RFC 1122 §2.3.2.2 asks for at least one packet to be saved. Keeping
        // the newest is what a sender that is still retrying expects to see.
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut neighbors = [DynamicNeighborSlot::EMPTY; 1];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 2];
        let mut runtime =
            ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
                hold_policy(),
                &mut states,
                &mut actions,
                &mut neighbors,
                &mut failure_holds,
                &mut datagram_holds,
            );

        let first = held_frame(0x11, 64);
        let second = held_frame(0x22, 96);
        runtime.hold_datagram(HOLD_EGRESS, target(9), &first, MonotonicMillis(0));
        assert_eq!(
            runtime.hold_datagram(HOLD_EGRESS, target(9), &second, MonotonicMillis(1)),
            ResolutionHoldDisposition::Replaced {
                egress: HOLD_EGRESS,
                len: 96
            }
        );
        assert_eq!(
            runtime.held_datagram_count(),
            1,
            "the key holds one datagram"
        );

        runtime.merge_dynamic(
            HOLD_EGRESS,
            target(9),
            HOLD_MAC,
            true,
            false,
            MonotonicMillis(2),
        );
        let (_, _, replayed) = runtime
            .take_resolved_datagram(MonotonicMillis(2))
            .expect("the surviving datagram must be released");
        assert_eq!(replayed, second.as_slice(), "the newest datagram survives");
        assert_eq!(runtime.hold_counters().replaced, 1);
    }

    #[test]
    fn a_full_hold_queue_refuses_a_further_address_without_evicting_one() {
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut neighbors = [DynamicNeighborSlot::EMPTY; 2];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 1];
        let mut runtime =
            ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
                hold_policy(),
                &mut states,
                &mut actions,
                &mut neighbors,
                &mut failure_holds,
                &mut datagram_holds,
            );

        let first = held_frame(0x33, 64);
        runtime.hold_datagram(HOLD_EGRESS, target(9), &first, MonotonicMillis(0));
        assert_eq!(
            runtime.hold_datagram(HOLD_EGRESS, target(10), &first, MonotonicMillis(0)),
            ResolutionHoldDisposition::QueueFull
        );
        assert_eq!(runtime.hold_counters().queue_full, 1);

        // The datagram already held is untouched by the refusal.
        runtime.merge_dynamic(
            HOLD_EGRESS,
            target(9),
            HOLD_MAC,
            true,
            false,
            MonotonicMillis(1),
        );
        assert!(runtime.take_resolved_datagram(MonotonicMillis(1)).is_some());
    }

    #[test]
    fn a_frame_larger_than_a_hold_slot_is_refused_rather_than_truncated() {
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut neighbors = [DynamicNeighborSlot::EMPTY; 1];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 1];
        let mut runtime =
            ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
                hold_policy(),
                &mut states,
                &mut actions,
                &mut neighbors,
                &mut failure_holds,
                &mut datagram_holds,
            );

        let exact = held_frame(0x44, RESOLUTION_HOLD_MAX_FRAME_LEN);
        assert_eq!(
            runtime.hold_datagram(HOLD_EGRESS, target(9), &exact, MonotonicMillis(0)),
            ResolutionHoldDisposition::Held {
                egress: HOLD_EGRESS,
                len: RESOLUTION_HOLD_MAX_FRAME_LEN
            },
            "a frame of exactly the slot size is held whole"
        );

        let oversized = held_frame(0x55, RESOLUTION_HOLD_MAX_FRAME_LEN + 1);
        assert_eq!(
            runtime.hold_datagram(HOLD_EGRESS, target(10), &oversized, MonotonicMillis(0)),
            ResolutionHoldDisposition::FrameTooLong {
                len: RESOLUTION_HOLD_MAX_FRAME_LEN + 1
            }
        );
        assert_eq!(runtime.hold_counters().frame_too_long, 1);
    }

    #[test]
    fn a_hold_that_outlives_its_resolution_is_released_rather_than_sent() {
        // Sending a datagram after the sender has certainly given up on it is
        // worse than dropping it: the reply would arrive unsolicited.
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut neighbors = [DynamicNeighborSlot::EMPTY; 1];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 1];
        let mut runtime =
            ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
                hold_policy(),
                &mut states,
                &mut actions,
                &mut neighbors,
                &mut failure_holds,
                &mut datagram_holds,
            );

        let frame = held_frame(0x66, 64);
        runtime.hold_datagram(HOLD_EGRESS, target(9), &frame, MonotonicMillis(0));
        runtime.merge_dynamic(
            HOLD_EGRESS,
            target(9),
            HOLD_MAC,
            true,
            false,
            MonotonicMillis(2_999),
        );
        // One millisecond before the TTL the datagram is still eligible.
        assert!(runtime
            .take_resolved_datagram(MonotonicMillis(2_999))
            .is_some());

        runtime.hold_datagram(HOLD_EGRESS, target(9), &frame, MonotonicMillis(3_000));
        assert!(
            runtime
                .take_resolved_datagram(MonotonicMillis(6_000))
                .is_none(),
            "a hold at or past the resolution TTL must not be sent"
        );
        assert_eq!(runtime.held_datagram_count(), 0);
        assert_eq!(runtime.hold_counters().expired, 1);
    }

    #[test]
    fn a_runtime_without_hold_slots_keeps_the_earlier_drop_behaviour() {
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(hold_policy(), &mut states, &mut actions);
        let frame = held_frame(0x77, 64);
        assert_eq!(
            runtime.hold_datagram(HOLD_EGRESS, target(9), &frame, MonotonicMillis(0)),
            ResolutionHoldDisposition::QueueFull
        );
        assert_eq!(runtime.held_datagram_count(), 0);
    }

    #[test]
    fn a_shorter_datagram_does_not_leave_the_previous_one_in_the_slot() {
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut neighbors = [DynamicNeighborSlot::EMPTY; 1];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 1];
        let mut runtime =
            ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
                hold_policy(),
                &mut states,
                &mut actions,
                &mut neighbors,
                &mut failure_holds,
                &mut datagram_holds,
            );

        runtime.hold_datagram(
            HOLD_EGRESS,
            target(9),
            &held_frame(0x9c, 512),
            MonotonicMillis(0),
        );
        let short = held_frame(0x3e, 64);
        runtime.hold_datagram(HOLD_EGRESS, target(9), &short, MonotonicMillis(1));
        // The runtime borrows the storage, so its borrow ends here before the
        // slot itself is inspected.
        let _ = runtime.held_datagram_count();
        let slot = datagram_holds[0];
        assert_eq!(slot.frame(), short.as_slice());
        assert!(
            slot.storage_past_frame().iter().all(|byte| *byte == 0),
            "a slot must not keep the payload of the datagram it replaced"
        );
    }

    #[test]
    fn a_hold_offered_with_time_moving_backwards_is_refused() {
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut neighbors = [DynamicNeighborSlot::EMPTY; 1];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 1];
        let mut runtime =
            ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
                hold_policy(),
                &mut states,
                &mut actions,
                &mut neighbors,
                &mut failure_holds,
                &mut datagram_holds,
            );
        let frame = held_frame(0x88, 64);
        runtime.hold_datagram(HOLD_EGRESS, target(9), &frame, MonotonicMillis(100));
        assert_eq!(
            runtime.hold_datagram(HOLD_EGRESS, target(10), &frame, MonotonicMillis(99)),
            ResolutionHoldDisposition::ClockRegression
        );
    }
}

use std::{marker::PhantomData, rc::Rc};

use crate::{
    internet_checksum, ipv4_header_checksum, GeneratedAllocationError, GeneratedBatchCompletion,
    GeneratedPacketBatch, GeneratedPacketIo, IfId, Ipv4Address, MacAddress, MonotonicMillis,
    IPV4_ETHERTYPE,
};

pub const ICMPV4_ERROR_MAX_QUOTE_LEN: usize = 548;
pub const ICMPV4_ERROR_MAX_FRAME_LEN: usize = 590;
pub const ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN: usize = ICMPV4_ERROR_MAX_QUOTE_LEN;
pub const ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN: usize = ICMPV4_ERROR_MAX_FRAME_LEN;
const ETHERNET_MIN_FRAME_LEN: usize = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4ErrorKind {
    TimeExceededTtl,
    DestinationUnreachableNetwork,
    DestinationUnreachableHost,
}

impl Icmpv4ErrorKind {
    const fn icmp_type(self) -> u8 {
        match self {
            Self::TimeExceededTtl => 11,
            Self::DestinationUnreachableNetwork | Self::DestinationUnreachableHost => 3,
        }
    }

    const fn icmp_code(self) -> u8 {
        match self {
            Self::DestinationUnreachableHost => 1,
            Self::TimeExceededTtl | Self::DestinationUnreachableNetwork => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4ErrorPolicyError {
    IntervalZero,
    StateTtlTooShort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorPolicy {
    interval_ms: u64,
    state_ttl_ms: u64,
}

impl Icmpv4ErrorPolicy {
    pub const fn new(interval_ms: u64, state_ttl_ms: u64) -> Result<Self, Icmpv4ErrorPolicyError> {
        if interval_ms == 0 {
            return Err(Icmpv4ErrorPolicyError::IntervalZero);
        }
        if state_ttl_ms < interval_ms {
            return Err(Icmpv4ErrorPolicyError::StateTtlTooShort);
        }
        Ok(Self {
            interval_ms,
            state_ttl_ms,
        })
    }

    #[must_use]
    pub const fn interval_ms(self) -> u64 {
        self.interval_ms
    }

    #[must_use]
    pub const fn state_ttl_ms(self) -> u64 {
        self.state_ttl_ms
    }
}

impl Default for Icmpv4ErrorPolicy {
    fn default() -> Self {
        Self {
            interval_ms: 100,
            state_ttl_ms: 60_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorAction {
    pub kind: Icmpv4ErrorKind,
    pub egress: IfId,
    pub source_mac: MacAddress,
    pub destination_mac: MacAddress,
    pub source_ip: Ipv4Address,
    pub destination_ip: Ipv4Address,
    pub outer_tos: u8,
    pub outer_ttl: u8,
    quote_len: u16,
    quote: [u8; ICMPV4_ERROR_MAX_QUOTE_LEN],
}

impl Icmpv4ErrorAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        egress: IfId,
        source_mac: MacAddress,
        destination_mac: MacAddress,
        source_ip: Ipv4Address,
        destination_ip: Ipv4Address,
        original_tos: u8,
        outer_ttl: u8,
        original_ipv4: &[u8],
    ) -> Self {
        Self::new_with_kind(
            Icmpv4ErrorKind::TimeExceededTtl,
            egress,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            original_tos,
            outer_ttl,
            original_ipv4,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_kind(
        kind: Icmpv4ErrorKind,
        egress: IfId,
        source_mac: MacAddress,
        destination_mac: MacAddress,
        source_ip: Ipv4Address,
        destination_ip: Ipv4Address,
        original_tos: u8,
        outer_ttl: u8,
        original_ipv4: &[u8],
    ) -> Self {
        let quote_len = original_ipv4.len().min(ICMPV4_ERROR_MAX_QUOTE_LEN);
        let mut quote = [0; ICMPV4_ERROR_MAX_QUOTE_LEN];
        quote[..quote_len].copy_from_slice(&original_ipv4[..quote_len]);
        Self {
            kind,
            egress,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            outer_tos: (original_tos & 0x1e) | 0xc0,
            outer_ttl,
            quote_len: quote_len as u16,
            quote,
        }
    }

    #[must_use]
    pub fn quote(&self) -> &[u8] {
        &self.quote[..usize::from(self.quote_len)]
    }

    #[must_use]
    pub const fn quote_len(&self) -> usize {
        self.quote_len as usize
    }

    #[must_use]
    pub const fn frame_len(&self) -> usize {
        let visible = 14 + 28 + self.quote_len as usize;
        if visible < ETHERNET_MIN_FRAME_LEN {
            ETHERNET_MIN_FRAME_LEN
        } else {
            visible
        }
    }
}

pub type Icmpv4TimeExceededAction = Icmpv4ErrorAction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorActionSlot(Option<QueuedAction>);

impl Icmpv4ErrorActionSlot {
    pub const EMPTY: Self = Self(None);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorStateSlot {
    egress: IfId,
    generation: u64,
    requested_at: MonotonicMillis,
    occupied: bool,
    action_queued: bool,
    has_requested: bool,
}

impl Icmpv4ErrorStateSlot {
    pub const EMPTY: Self = Self {
        egress: IfId(0),
        generation: 0,
        requested_at: MonotonicMillis(0),
        occupied: false,
        action_queued: false,
        has_requested: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueuedAction {
    action: Icmpv4ErrorAction,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Icmpv4ErrorDisposition {
    Queued {
        egress: IfId,
        quote_len: usize,
    },
    DestinationUnreachableQueued {
        egress: IfId,
        quote_len: usize,
    },
    HostUnreachableQueued {
        egress: IfId,
        quote_len: usize,
    },
    Pending {
        egress: IfId,
    },
    RateLimited {
        egress: IfId,
    },
    StateFull,
    ActionFull,
    ClockRegression,
    SourceNotUnicast,
    SourceIsLocal,
    DestinationMulticast,
    DestinationLimitedBroadcast,
    DestinationNetworkAddress,
    DestinationDirectedBroadcast,
    EthernetDestinationGroup,
    NonInitialFragment,
    IcmpErrorMessage,
    IcmpTypeMissing,
    ReverseRouteMiss,
    ReverseInterfaceMiss {
        egress: IfId,
    },
    ReverseBindingMiss {
        egress: IfId,
    },
    ReverseTargetForbidden {
        egress: IfId,
        target: Ipv4Address,
    },
    ReverseNeighborUnresolved {
        egress: IfId,
        target: Ipv4Address,
        resolution: crate::ResolutionResult,
    },
}

pub type Icmpv4TimeExceededDisposition = Icmpv4ErrorDisposition;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Icmpv4ErrorCounters {
    pub queued: usize,
    pub queued_time_exceeded: usize,
    pub queued_destination_unreachable: usize,
    pub queued_host_unreachable: usize,
    pub pending: usize,
    pub rate_limited: usize,
    pub state_full: usize,
    pub action_full: usize,
    pub clock_regressions: usize,
    pub source_not_unicast: usize,
    pub source_is_local: usize,
    pub destination_multicast: usize,
    pub destination_limited_broadcast: usize,
    pub destination_network_address: usize,
    pub destination_directed_broadcast: usize,
    pub ethernet_destination_group: usize,
    pub noninitial_fragment: usize,
    pub icmp_error_message: usize,
    pub icmp_type_missing: usize,
    pub reverse_route_miss: usize,
    pub reverse_interface_miss: usize,
    pub reverse_binding_miss: usize,
    pub reverse_target_forbidden: usize,
    pub reverse_neighbor_unresolved: usize,
    pub dequeued: usize,
    pub dequeued_time_exceeded: usize,
    pub dequeued_destination_unreachable: usize,
    pub dequeued_host_unreachable: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Icmpv4ErrorPublicationReport {
    pub states_flushed: usize,
    pub actions_flushed: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Icmpv4ErrorPublicationError {
    ActionQueueCapacity,
    ActionQueueHead,
    ActionQueueWindow,
    QueuedStateMismatch,
    RuntimeEpochExhausted,
}

/// Exclusive proof that old generated-ICMP authority can be flushed totally.
///
/// ```compile_fail
/// use ruster_core::Icmpv4ErrorRuntime;
///
/// fn reborrow<'storage>(runtime: &mut Icmpv4ErrorRuntime<'storage>) {
///     let permit = runtime.preflight_publication().unwrap();
///     let _ = runtime.pending_actions();
///     permit.commit();
/// }
/// ```
#[must_use]
pub struct Icmpv4ErrorPublicationPermit<'runtime, 'storage> {
    runtime: &'runtime mut Icmpv4ErrorRuntime<'storage>,
    next_runtime_epoch: u128,
    report: Icmpv4ErrorPublicationReport,
}

/// Caller-backed, worker-local ICMP error queue and per-egress limiter.
///
/// The runtime deliberately has no shared state and cannot cross worker
/// boundaries.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::Icmpv4ErrorRuntime<'static>>();
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<ruster_core::Icmpv4ErrorRuntime<'static>>();
/// ```
pub struct Icmpv4ErrorRuntime<'a> {
    policy: Icmpv4ErrorPolicy,
    states: &'a mut [Icmpv4ErrorStateSlot],
    actions: &'a mut [Icmpv4ErrorActionSlot],
    head: usize,
    len: usize,
    last_now: Option<MonotonicMillis>,
    runtime_epoch: u128,
    counters: Icmpv4ErrorCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> Icmpv4ErrorRuntime<'a> {
    #[must_use]
    pub fn new(
        policy: Icmpv4ErrorPolicy,
        states: &'a mut [Icmpv4ErrorStateSlot],
        actions: &'a mut [Icmpv4ErrorActionSlot],
    ) -> Self {
        states.fill(Icmpv4ErrorStateSlot::EMPTY);
        actions.fill(Icmpv4ErrorActionSlot::EMPTY);
        Self {
            policy,
            states,
            actions,
            head: 0,
            len: 0,
            last_now: None,
            runtime_epoch: 1,
            counters: Icmpv4ErrorCounters::default(),
            _worker_local: PhantomData,
        }
    }

    #[must_use]
    pub const fn pending_actions(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn counters(&self) -> Icmpv4ErrorCounters {
        self.counters
    }

    #[must_use]
    pub const fn policy(&self) -> Icmpv4ErrorPolicy {
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

    /// Returns whether this runtime is still in its exact constructor state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.states
            .iter()
            .all(|slot| *slot == Icmpv4ErrorStateSlot::EMPTY)
            && self
                .actions
                .iter()
                .all(|slot| *slot == Icmpv4ErrorActionSlot::EMPTY)
            && self.head == 0
            && self.len == 0
            && self.last_now.is_none()
            && self.runtime_epoch == 1
            && self.counters == Icmpv4ErrorCounters::default()
    }

    /// Validates the generated-action queue without changing runtime state.
    ///
    /// Successful commit clears all limiter and action state because queued
    /// actions contain publication-specific egress, MAC, and IPv4 authority.
    /// Cumulative operational counters are deliberately preserved.
    pub fn preflight_publication<'runtime>(
        &'runtime mut self,
    ) -> Result<Icmpv4ErrorPublicationPermit<'runtime, 'a>, Icmpv4ErrorPublicationError> {
        if self.len > self.actions.len() {
            return Err(Icmpv4ErrorPublicationError::ActionQueueCapacity);
        }
        if self.actions.is_empty() {
            if self.head != 0 || self.len != 0 {
                return Err(Icmpv4ErrorPublicationError::ActionQueueHead);
            }
        } else if self.head >= self.actions.len() {
            return Err(Icmpv4ErrorPublicationError::ActionQueueHead);
        }
        for index in 0..self.actions.len() {
            let distance = (index + self.actions.len() - self.head) % self.actions.len();
            if self.actions[index].0.is_some() != (distance < self.len) {
                return Err(Icmpv4ErrorPublicationError::ActionQueueWindow);
            }
        }
        if self
            .states
            .iter()
            .any(|state| state.action_queued && !state.occupied)
        {
            return Err(Icmpv4ErrorPublicationError::QueuedStateMismatch);
        }
        let queued_states = self
            .states
            .iter()
            .filter(|state| state.occupied && state.action_queued)
            .count();
        if queued_states != self.len {
            return Err(Icmpv4ErrorPublicationError::QueuedStateMismatch);
        }
        for offset in 0..self.len {
            let index = (self.head + offset) % self.actions.len();
            let Some(queued) = self.actions[index].0 else {
                return Err(Icmpv4ErrorPublicationError::ActionQueueWindow);
            };
            if (0..offset).any(|previous_offset| {
                let previous_index = (self.head + previous_offset) % self.actions.len();
                self.actions[previous_index].0.is_some_and(|previous| {
                    previous.action.egress == queued.action.egress
                        && previous.generation == queued.generation
                })
            }) {
                return Err(Icmpv4ErrorPublicationError::QueuedStateMismatch);
            }
            if !self.states.iter().any(|state| {
                state.occupied
                    && state.action_queued
                    && state.egress == queued.action.egress
                    && state.generation == queued.generation
            }) {
                return Err(Icmpv4ErrorPublicationError::QueuedStateMismatch);
            }
        }
        let next_runtime_epoch = self
            .runtime_epoch
            .checked_add(1)
            .ok_or(Icmpv4ErrorPublicationError::RuntimeEpochExhausted)?;
        let report = Icmpv4ErrorPublicationReport {
            states_flushed: self.states.iter().filter(|state| state.occupied).count(),
            actions_flushed: self.len,
        };
        Ok(Icmpv4ErrorPublicationPermit {
            runtime: self,
            next_runtime_epoch,
            report,
        })
    }

    pub(crate) fn record_suppression(
        &mut self,
        disposition: Icmpv4ErrorDisposition,
    ) -> Icmpv4ErrorDisposition {
        match disposition {
            Icmpv4ErrorDisposition::Queued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_time_exceeded += 1;
            }
            Icmpv4ErrorDisposition::DestinationUnreachableQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_destination_unreachable += 1;
            }
            Icmpv4ErrorDisposition::HostUnreachableQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_host_unreachable += 1;
            }
            Icmpv4ErrorDisposition::Pending { .. } => self.counters.pending += 1,
            Icmpv4ErrorDisposition::RateLimited { .. } => {
                self.counters.rate_limited += 1;
            }
            Icmpv4ErrorDisposition::StateFull => self.counters.state_full += 1,
            Icmpv4ErrorDisposition::ActionFull => self.counters.action_full += 1,
            Icmpv4ErrorDisposition::ClockRegression => {
                self.counters.clock_regressions += 1;
            }
            Icmpv4ErrorDisposition::SourceNotUnicast => {
                self.counters.source_not_unicast += 1;
            }
            Icmpv4ErrorDisposition::SourceIsLocal => self.counters.source_is_local += 1,
            Icmpv4ErrorDisposition::DestinationMulticast => {
                self.counters.destination_multicast += 1;
            }
            Icmpv4ErrorDisposition::DestinationLimitedBroadcast => {
                self.counters.destination_limited_broadcast += 1;
            }
            Icmpv4ErrorDisposition::DestinationNetworkAddress => {
                self.counters.destination_network_address += 1;
            }
            Icmpv4ErrorDisposition::DestinationDirectedBroadcast => {
                self.counters.destination_directed_broadcast += 1;
            }
            Icmpv4ErrorDisposition::EthernetDestinationGroup => {
                self.counters.ethernet_destination_group += 1;
            }
            Icmpv4ErrorDisposition::NonInitialFragment => {
                self.counters.noninitial_fragment += 1;
            }
            Icmpv4ErrorDisposition::IcmpErrorMessage => {
                self.counters.icmp_error_message += 1;
            }
            Icmpv4ErrorDisposition::IcmpTypeMissing => {
                self.counters.icmp_type_missing += 1;
            }
            Icmpv4ErrorDisposition::ReverseRouteMiss => {
                self.counters.reverse_route_miss += 1;
            }
            Icmpv4ErrorDisposition::ReverseInterfaceMiss { .. } => {
                self.counters.reverse_interface_miss += 1;
            }
            Icmpv4ErrorDisposition::ReverseBindingMiss { .. } => {
                self.counters.reverse_binding_miss += 1;
            }
            Icmpv4ErrorDisposition::ReverseTargetForbidden { .. } => {
                self.counters.reverse_target_forbidden += 1;
            }
            Icmpv4ErrorDisposition::ReverseNeighborUnresolved { .. } => {
                self.counters.reverse_neighbor_unresolved += 1;
            }
        }
        disposition
    }

    pub(crate) fn schedule(
        &mut self,
        action: Icmpv4ErrorAction,
        now: MonotonicMillis,
    ) -> Icmpv4ErrorDisposition {
        if !self.observe_now(now) {
            return self.record_suppression(Icmpv4TimeExceededDisposition::ClockRegression);
        }
        if let Some(index) = self
            .states
            .iter()
            .position(|state| state.occupied && state.egress == action.egress)
        {
            let state = self.states[index];
            if state.action_queued {
                return self.record_suppression(Icmpv4TimeExceededDisposition::Pending {
                    egress: action.egress,
                });
            }
            if state.has_requested
                && now.0.saturating_sub(state.requested_at.0) < self.policy.interval_ms
            {
                return self.record_suppression(Icmpv4TimeExceededDisposition::RateLimited {
                    egress: action.egress,
                });
            }
            return self.enqueue(index, action);
        }

        let Some(index) = self.states.iter().position(|state| {
            !state.occupied
                || (!state.action_queued
                    && state.has_requested
                    && now.0.saturating_sub(state.requested_at.0) >= self.policy.state_ttl_ms)
        }) else {
            return self.record_suppression(Icmpv4TimeExceededDisposition::StateFull);
        };
        if self.len == self.actions.len() {
            return self.record_suppression(Icmpv4TimeExceededDisposition::ActionFull);
        }
        self.states[index] = Icmpv4ErrorStateSlot {
            egress: action.egress,
            generation: self.states[index].generation.wrapping_add(1),
            requested_at: MonotonicMillis(0),
            occupied: true,
            action_queued: false,
            has_requested: false,
        };
        self.enqueue(index, action)
    }

    fn enqueue(&mut self, state_index: usize, action: Icmpv4ErrorAction) -> Icmpv4ErrorDisposition {
        if self.len == self.actions.len() {
            return self.record_suppression(Icmpv4TimeExceededDisposition::ActionFull);
        }
        let generation = self.states[state_index].generation.wrapping_add(1);
        let tail = (self.head + self.len) % self.actions.len();
        self.actions[tail].0 = Some(QueuedAction { action, generation });
        self.states[state_index].generation = generation;
        self.states[state_index].action_queued = true;
        self.len += 1;
        let disposition = match action.kind {
            Icmpv4ErrorKind::TimeExceededTtl => Icmpv4ErrorDisposition::Queued {
                egress: action.egress,
                quote_len: action.quote_len(),
            },
            Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                Icmpv4ErrorDisposition::DestinationUnreachableQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                }
            }
            Icmpv4ErrorKind::DestinationUnreachableHost => {
                Icmpv4ErrorDisposition::HostUnreachableQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                }
            }
        };
        self.record_suppression(disposition)
    }

    pub(crate) fn observe_decision(&mut self, now: MonotonicMillis) -> bool {
        self.observe_now(now)
    }

    fn observe_now(&mut self, now: MonotonicMillis) -> bool {
        if self.last_now.is_some_and(|last| now < last) {
            return false;
        }
        self.last_now = Some(now);
        true
    }

    fn front(&self) -> Option<QueuedAction> {
        self.actions.get(self.head).and_then(|slot| slot.0)
    }

    fn execution_time_valid(&mut self, now: MonotonicMillis) -> bool {
        if self.observe_now(now) {
            true
        } else {
            self.counters.clock_regressions += 1;
            false
        }
    }

    fn committed(&mut self, queued: QueuedAction, now: MonotonicMillis) {
        let actual = self.actions[self.head]
            .0
            .take()
            .expect("committed ICMP action is queue front");
        debug_assert_eq!(actual, queued);
        self.head = (self.head + 1) % self.actions.len();
        self.len -= 1;
        self.counters.dequeued += 1;
        match queued.action.kind {
            Icmpv4ErrorKind::TimeExceededTtl => self.counters.dequeued_time_exceeded += 1,
            Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                self.counters.dequeued_destination_unreachable += 1;
            }
            Icmpv4ErrorKind::DestinationUnreachableHost => {
                self.counters.dequeued_host_unreachable += 1;
            }
        }
        if let Some(state) = self.states.iter_mut().find(|state| {
            state.occupied
                && state.egress == queued.action.egress
                && state.generation == queued.generation
        }) {
            state.action_queued = false;
            state.has_requested = true;
            state.requested_at = now;
        }
    }
}

impl Icmpv4ErrorPublicationPermit<'_, '_> {
    /// Flushes old publication authority without failure.
    pub fn commit(self) -> Icmpv4ErrorPublicationReport {
        self.runtime.states.fill(Icmpv4ErrorStateSlot::EMPTY);
        self.runtime.actions.fill(Icmpv4ErrorActionSlot::EMPTY);
        self.runtime.head = 0;
        self.runtime.len = 0;
        self.runtime.last_now = None;
        self.runtime.runtime_epoch = self.next_runtime_epoch;
        self.report
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4ErrorBuildError {
    ExactLengthRequired,
}

pub type Icmpv4TimeExceededBuildError = Icmpv4ErrorBuildError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecuteIcmpv4Error {
    ClockRegression,
}

pub type ExecuteIcmpv4TimeExceededError = ExecuteIcmpv4Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedIcmpv4Trace {
    AllocationFailed(GeneratedAllocationError),
    BuildFailed(Icmpv4ErrorBuildError),
    DestinationUnreachableAllocationFailed(GeneratedAllocationError),
    DestinationUnreachableBuildFailed(Icmpv4ErrorBuildError),
    HostUnreachableAllocationFailed(GeneratedAllocationError),
    HostUnreachableBuildFailed(Icmpv4ErrorBuildError),
    ClockRegression,
    DestinationUnreachableClockRegression,
    HostUnreachableClockRegression,
    TxRequested {
        egress: IfId,
        destination: Ipv4Address,
    },
    DestinationUnreachableTxRequested {
        egress: IfId,
        destination: Ipv4Address,
    },
    HostUnreachableTxRequested {
        egress: IfId,
        destination: Ipv4Address,
    },
    BatchCompleted {
        accepted: usize,
        rejected: usize,
    },
    DestinationUnreachableBatchCompleted {
        accepted: usize,
        rejected: usize,
    },
    HostUnreachableBatchCompleted {
        accepted: usize,
        rejected: usize,
    },
}

pub trait GeneratedIcmpv4TraceSink {
    fn record_generated_icmpv4(&mut self, event: GeneratedIcmpv4Trace);
}

#[derive(Default)]
pub struct NoGeneratedIcmpv4Trace;

impl GeneratedIcmpv4TraceSink for NoGeneratedIcmpv4Trace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedIcmpv4Report<E> {
    pub action: Icmpv4ErrorAction,
    pub allocation_error: Option<GeneratedAllocationError>,
    pub build_error: Option<Icmpv4ErrorBuildError>,
    pub completion: GeneratedBatchCompletion<E>,
}

pub fn execute_one_icmpv4_time_exceeded<I, T>(
    io: &mut I,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<Option<GeneratedIcmpv4Report<I::Error>>, ExecuteIcmpv4TimeExceededError>
where
    I: GeneratedPacketIo,
    T: GeneratedIcmpv4TraceSink,
{
    execute_one_icmpv4_error(io, runtime, now, trace)
}

pub fn execute_one_icmpv4_error<I, T>(
    io: &mut I,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<Option<GeneratedIcmpv4Report<I::Error>>, ExecuteIcmpv4Error>
where
    I: GeneratedPacketIo,
    T: GeneratedIcmpv4TraceSink,
{
    let Some(queued) = runtime.front() else {
        return Ok(None);
    };
    if !runtime.execution_time_valid(now) {
        let event = match queued.action.kind {
            Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::ClockRegression,
            Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                GeneratedIcmpv4Trace::DestinationUnreachableClockRegression
            }
            Icmpv4ErrorKind::DestinationUnreachableHost => {
                GeneratedIcmpv4Trace::HostUnreachableClockRegression
            }
        };
        trace.record_generated_icmpv4(event);
        return Err(ExecuteIcmpv4TimeExceededError::ClockRegression);
    }
    let mut batch = io.begin_generated(queued.action.egress);
    let (allocation_error, build_error) = match allocate_icmpv4_error(&mut batch, &queued.action) {
        Ok(()) => {
            runtime.committed(queued, now);
            let event = match queued.action.kind {
                Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::TxRequested {
                    egress: queued.action.egress,
                    destination: queued.action.destination_ip,
                },
                Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                    GeneratedIcmpv4Trace::DestinationUnreachableTxRequested {
                        egress: queued.action.egress,
                        destination: queued.action.destination_ip,
                    }
                }
                Icmpv4ErrorKind::DestinationUnreachableHost => {
                    GeneratedIcmpv4Trace::HostUnreachableTxRequested {
                        egress: queued.action.egress,
                        destination: queued.action.destination_ip,
                    }
                }
            };
            trace.record_generated_icmpv4(event);
            (None, None)
        }
        Err(GenerationError::Allocation(error)) => {
            let event = match queued.action.kind {
                Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::AllocationFailed(error),
                Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                    GeneratedIcmpv4Trace::DestinationUnreachableAllocationFailed(error)
                }
                Icmpv4ErrorKind::DestinationUnreachableHost => {
                    GeneratedIcmpv4Trace::HostUnreachableAllocationFailed(error)
                }
            };
            trace.record_generated_icmpv4(event);
            (Some(error), None)
        }
        Err(GenerationError::Build(error)) => {
            let event = match queued.action.kind {
                Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::BuildFailed(error),
                Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                    GeneratedIcmpv4Trace::DestinationUnreachableBuildFailed(error)
                }
                Icmpv4ErrorKind::DestinationUnreachableHost => {
                    GeneratedIcmpv4Trace::HostUnreachableBuildFailed(error)
                }
            };
            trace.record_generated_icmpv4(event);
            (None, Some(error))
        }
    };
    let completion = batch.finish();
    let event = match queued.action.kind {
        Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::BatchCompleted {
            accepted: completion.accepted,
            rejected: completion.rejected,
        },
        Icmpv4ErrorKind::DestinationUnreachableNetwork => {
            GeneratedIcmpv4Trace::DestinationUnreachableBatchCompleted {
                accepted: completion.accepted,
                rejected: completion.rejected,
            }
        }
        Icmpv4ErrorKind::DestinationUnreachableHost => {
            GeneratedIcmpv4Trace::HostUnreachableBatchCompleted {
                accepted: completion.accepted,
                rejected: completion.rejected,
            }
        }
    };
    trace.record_generated_icmpv4(event);
    Ok(Some(GeneratedIcmpv4Report {
        action: queued.action,
        allocation_error,
        build_error,
        completion,
    }))
}

enum GenerationError {
    Allocation(GeneratedAllocationError),
    Build(Icmpv4ErrorBuildError),
}

fn allocate_icmpv4_error<B: GeneratedPacketBatch>(
    batch: &mut B,
    action: &Icmpv4ErrorAction,
) -> Result<(), GenerationError> {
    let frame_len = action.frame_len();
    let mut lease = batch
        .allocate(frame_len)
        .map_err(GenerationError::Allocation)?;
    if lease.bytes_mut().len() != frame_len {
        lease.cancel();
        return Err(GenerationError::Build(
            Icmpv4TimeExceededBuildError::ExactLengthRequired,
        ));
    }
    build_icmpv4_error(lease.bytes_mut(), action);
    lease.commit();
    Ok(())
}

fn build_icmpv4_error(frame: &mut [u8], action: &Icmpv4ErrorAction) {
    debug_assert_eq!(frame.len(), action.frame_len());
    let quote_len = action.quote_len();
    let ipv4_total_len = 28 + quote_len;
    let icmp_end = 42 + quote_len;
    frame.fill(0);
    frame[0..6].copy_from_slice(&action.destination_mac.0);
    frame[6..12].copy_from_slice(&action.source_mac.0);
    frame[12..14].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = action.outer_tos;
    frame[16..18].copy_from_slice(&(ipv4_total_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = action.outer_ttl;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&action.source_ip.octets());
    frame[30..34].copy_from_slice(&action.destination_ip.octets());
    let header_checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&header_checksum.to_be_bytes());
    frame[34] = action.kind.icmp_type();
    frame[35] = action.kind.icmp_code();
    frame[42..icmp_end].copy_from_slice(action.quote());
    let icmp_checksum = internet_checksum(&frame[34..icmp_end]);
    frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct RuntimeImage {
        policy: Icmpv4ErrorPolicy,
        states: Vec<Icmpv4ErrorStateSlot>,
        actions: Vec<Icmpv4ErrorActionSlot>,
        head: usize,
        len: usize,
        last_now: Option<MonotonicMillis>,
        runtime_epoch: u128,
        counters: Icmpv4ErrorCounters,
    }

    fn runtime_image(runtime: &Icmpv4ErrorRuntime<'_>) -> RuntimeImage {
        RuntimeImage {
            policy: runtime.policy,
            states: runtime.states.to_vec(),
            actions: runtime.actions.to_vec(),
            head: runtime.head,
            len: runtime.len,
            last_now: runtime.last_now,
            runtime_epoch: runtime.runtime_epoch,
            counters: runtime.counters,
        }
    }

    fn assert_publication_error_is_atomic(
        runtime: &mut Icmpv4ErrorRuntime<'_>,
        expected: Icmpv4ErrorPublicationError,
    ) {
        let before = runtime_image(runtime);
        assert_eq!(runtime.preflight_publication().err(), Some(expected));
        assert_eq!(runtime_image(runtime), before);
    }

    fn action(egress: u16, quote_len: usize) -> Icmpv4TimeExceededAction {
        let original = [0xa5; ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN];
        Icmpv4TimeExceededAction::new(
            IfId(egress),
            MacAddress([2, 0, 0, 0, 0, 1]),
            MacAddress([2, 0, 0, 0, 0, 2]),
            Ipv4Address::from_octets([192, 0, 2, 1]),
            Ipv4Address::from_octets([198, 51, 100, 1]),
            0x2f,
            64,
            &original[..quote_len],
        )
    }

    fn action_kind(kind: Icmpv4ErrorKind, egress: u16, quote_len: usize) -> Icmpv4ErrorAction {
        let original = [0x5a; ICMPV4_ERROR_MAX_QUOTE_LEN];
        Icmpv4ErrorAction::new_with_kind(
            kind,
            IfId(egress),
            MacAddress([2, 0, 0, 0, 0, 1]),
            MacAddress([2, 0, 0, 0, 0, 2]),
            Ipv4Address::from_octets([192, 0, 2, 1]),
            Ipv4Address::from_octets([198, 51, 100, 1]),
            0,
            64,
            &original[..quote_len],
        )
    }

    #[test]
    fn policy_validates_and_defaults_to_ten_per_second() {
        assert_eq!(
            Icmpv4ErrorPolicy::new(0, 100),
            Err(Icmpv4ErrorPolicyError::IntervalZero)
        );
        assert_eq!(
            Icmpv4ErrorPolicy::new(100, 99),
            Err(Icmpv4ErrorPolicyError::StateTtlTooShort)
        );
        assert_eq!(Icmpv4ErrorPolicy::default().interval_ms(), 100);
    }

    #[test]
    fn publication_preflight_errors_leave_runtime_exactly_unchanged() {
        let mut states = [];
        let mut actions = [];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.len = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::ActionQueueCapacity,
        );

        let mut states = [];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.head = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::ActionQueueHead,
        );

        let mut states = [];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.len = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::ActionQueueWindow,
        );

        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        assert!(matches!(
            runtime.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        runtime.states[0].action_queued = false;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::QueuedStateMismatch,
        );

        let mut states = [];
        let mut actions = [];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.runtime_epoch = u128::MAX;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::RuntimeEpochExhausted,
        );
    }

    #[test]
    fn publication_preflight_rejects_duplicate_action_authority() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        assert!(matches!(
            runtime.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        assert!(matches!(
            runtime.schedule(action(2, 20), MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        runtime.actions[1] = runtime.actions[0];
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::QueuedStateMismatch,
        );
    }

    #[test]
    fn publication_permit_drop_and_commit_cover_wrapped_fifo_and_counter_policy() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(1, 2).unwrap(),
            &mut states,
            &mut actions,
        );
        runtime.schedule(action(1, 20), MonotonicMillis(0));
        runtime.schedule(action(2, 20), MonotonicMillis(0));
        let first = runtime.front().unwrap();
        runtime.committed(first, MonotonicMillis(0));
        runtime.schedule(action(1, 20), MonotonicMillis(1));
        runtime.counters.queued = usize::MAX;

        let before = runtime_image(&runtime);
        let permit = runtime.preflight_publication().unwrap();
        assert_eq!(
            permit.report,
            Icmpv4ErrorPublicationReport {
                states_flushed: 2,
                actions_flushed: 2,
            }
        );
        drop(permit);
        assert_eq!(runtime_image(&runtime), before);

        let counters = runtime.counters;
        let report = runtime.preflight_publication().unwrap().commit();
        assert_eq!(
            report,
            Icmpv4ErrorPublicationReport {
                states_flushed: 2,
                actions_flushed: 2,
            }
        );
        assert!(runtime
            .states
            .iter()
            .all(|slot| *slot == Icmpv4ErrorStateSlot::EMPTY));
        assert!(runtime
            .actions
            .iter()
            .all(|slot| *slot == Icmpv4ErrorActionSlot::EMPTY));
        assert_eq!((runtime.head, runtime.len), (0, 0));
        assert_eq!(runtime.last_now, None);
        assert_eq!(runtime.runtime_epoch, 2);
        assert_eq!(runtime.counters, counters);
    }

    #[test]
    fn publication_zero_capacity_is_total_and_pristine_is_exact() {
        let mut states = [];
        let mut actions = [];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        assert!(runtime.is_pristine());
        assert_eq!(
            runtime.preflight_publication().unwrap().commit(),
            Icmpv4ErrorPublicationReport::default()
        );
        assert!(!runtime.is_pristine());

        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut actions = [];
        let runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.states[0].egress = IfId(9);
        assert!(!runtime.is_pristine());
    }

    #[test]
    fn action_bounds_quote_and_frame_and_zeroes_unused_storage() {
        let short = action(1, 20);
        assert_eq!(short.quote_len(), 20);
        assert_eq!(short.frame_len(), 62);
        assert!(short.quote[20..].iter().all(|byte| *byte == 0));
        let long = action(1, 548);
        assert_eq!(long.frame_len(), ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN);
        assert_eq!(long.outer_tos, 0xce, "RFC 1812 reserved TOS bit is cleared");
    }

    #[test]
    fn host_unreachable_code_and_maximum_odd_quote_wire_are_exact() {
        let action = action_kind(
            Icmpv4ErrorKind::DestinationUnreachableHost,
            1,
            ICMPV4_ERROR_MAX_QUOTE_LEN,
        );
        let mut frame = [0xa5; ICMPV4_ERROR_MAX_FRAME_LEN];
        build_icmpv4_error(&mut frame, &action);
        assert_eq!(&frame[34..36], &[3, 1]);
        assert_eq!(&frame[38..42], &[0; 4]);
        assert_eq!(
            u16::from_be_bytes([frame[16], frame[17]]),
            576,
            "outer IPv4 remains within the RFC 1812 quote ceiling"
        );
        assert_eq!(ipv4_header_checksum(&frame[14..34]), 0);
        assert_eq!(internet_checksum(&frame[34..]), 0);

        let odd = action_kind(Icmpv4ErrorKind::DestinationUnreachableHost, 1, 21);
        let mut odd_frame = [0; 63];
        build_icmpv4_error(&mut odd_frame, &odd);
        assert_eq!(internet_checksum(&odd_frame[34..63]), 0);
    }

    #[test]
    fn limiter_is_per_egress_and_exact_boundary_is_allowed() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(100, 1_000).unwrap(),
            &mut states,
            &mut slots,
        );
        assert!(matches!(
            runtime.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
        assert_eq!(
            runtime.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::Pending { egress: IfId(1) }
        );
        assert!(matches!(
            runtime.schedule(action(2, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
        let first = runtime.front().unwrap();
        runtime.committed(first, MonotonicMillis(0));
        assert_eq!(
            runtime.schedule(action(1, 20), MonotonicMillis(99)),
            Icmpv4TimeExceededDisposition::RateLimited { egress: IfId(1) }
        );
        assert!(matches!(
            runtime.schedule(action(1, 20), MonotonicMillis(100)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
    }

    #[test]
    fn mixed_kinds_share_fifo_pending_and_exact_rate_boundary() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(100, 1_000).unwrap(),
            &mut states,
            &mut slots,
        );
        let time = action_kind(Icmpv4ErrorKind::TimeExceededTtl, 1, 20);
        let unreachable = action_kind(Icmpv4ErrorKind::DestinationUnreachableNetwork, 1, 21);
        assert!(matches!(
            runtime.schedule(time, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        assert_eq!(
            runtime.schedule(unreachable, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Pending { egress: IfId(1) }
        );
        let queued = runtime.front().unwrap();
        assert_eq!(queued.action.kind, Icmpv4ErrorKind::TimeExceededTtl);
        runtime.committed(queued, MonotonicMillis(0));
        assert_eq!(
            runtime.schedule(unreachable, MonotonicMillis(99)),
            Icmpv4ErrorDisposition::RateLimited { egress: IfId(1) }
        );
        assert!(matches!(
            runtime.schedule(unreachable, MonotonicMillis(100)),
            Icmpv4ErrorDisposition::DestinationUnreachableQueued { .. }
        ));
        let queued = runtime.front().unwrap();
        assert_eq!(
            queued.action.kind,
            Icmpv4ErrorKind::DestinationUnreachableNetwork
        );
        runtime.committed(queued, MonotonicMillis(100));
        assert_eq!(
            runtime.counters(),
            Icmpv4ErrorCounters {
                queued: 2,
                queued_time_exceeded: 1,
                queued_destination_unreachable: 1,
                pending: 1,
                rate_limited: 1,
                dequeued: 2,
                dequeued_time_exceeded: 1,
                dequeued_destination_unreachable: 1,
                ..Icmpv4ErrorCounters::default()
            }
        );
    }

    #[test]
    fn mixed_kind_fifo_is_ordered_across_egresses_and_clock_failure_is_atomic() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut slots);
        let time = action_kind(Icmpv4ErrorKind::TimeExceededTtl, 1, 20);
        let unreachable = action_kind(Icmpv4ErrorKind::DestinationUnreachableNetwork, 2, 20);
        runtime.schedule(time, MonotonicMillis(10));
        runtime.schedule(unreachable, MonotonicMillis(10));
        assert_eq!(runtime.pending_actions(), 2);
        let first = runtime.front().unwrap();
        assert_eq!(first.action.kind, Icmpv4ErrorKind::TimeExceededTtl);
        runtime.committed(first, MonotonicMillis(10));
        let second = runtime.front().unwrap();
        assert_eq!(
            second.action.kind,
            Icmpv4ErrorKind::DestinationUnreachableNetwork
        );
        assert_eq!(
            runtime.schedule(time, MonotonicMillis(9)),
            Icmpv4ErrorDisposition::ClockRegression
        );
        assert_eq!(runtime.front(), Some(second));
        assert_eq!(runtime.pending_actions(), 1);
    }

    #[test]
    fn zero_capacity_and_clock_regression_do_not_create_phantom_actions() {
        let mut states = [];
        let mut slots = [];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut slots);
        assert_eq!(
            runtime.schedule(action(1, 20), MonotonicMillis(10)),
            Icmpv4TimeExceededDisposition::StateFull
        );
        assert_eq!(
            runtime.schedule(action(1, 20), MonotonicMillis(9)),
            Icmpv4TimeExceededDisposition::ClockRegression
        );
        assert_eq!(runtime.pending_actions(), 0);
    }

    #[test]
    fn action_and_state_full_are_atomic_and_runtime_recreation_clears_storage() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut no_actions = [];
        let mut action_full =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut no_actions);
        assert_eq!(
            action_full.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::ActionFull
        );
        assert_eq!(action_full.pending_actions(), 0);

        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        {
            let mut runtime =
                Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut slots);
            runtime.schedule(action(1, 20), MonotonicMillis(0));
            assert_eq!(
                runtime.schedule(action(2, 20), MonotonicMillis(0)),
                Icmpv4TimeExceededDisposition::StateFull
            );
            assert_eq!(runtime.pending_actions(), 1);
        }
        let recreated =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut slots);
        assert_eq!(recreated.pending_actions(), 0);
    }

    #[test]
    fn wrapped_fifo_reuses_only_expired_idle_state() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(1, 2).unwrap(),
            &mut states,
            &mut slots,
        );
        runtime.schedule(action(1, 20), MonotonicMillis(0));
        runtime.schedule(action(2, 20), MonotonicMillis(0));
        let first = runtime.front().unwrap();
        runtime.committed(first, MonotonicMillis(0));
        runtime.schedule(action(1, 20), MonotonicMillis(1));
        let second = runtime.front().unwrap();
        assert_eq!(second.action.egress, IfId(2));
        runtime.committed(second, MonotonicMillis(1));
        let third = runtime.front().unwrap();
        assert_eq!(third.action.egress, IfId(1));
        runtime.committed(third, MonotonicMillis(1));
        assert!(matches!(
            runtime.schedule(action(3, 20), MonotonicMillis(3)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
    }
}

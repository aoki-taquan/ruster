use std::{marker::PhantomData, rc::Rc};

use crate::{
    internet_checksum, ipv4_header_checksum, GeneratedAllocationError, GeneratedBatchCompletion,
    GeneratedPacketBatch, GeneratedPacketIo, IfId, Ipv4Address, MacAddress, MonotonicMillis,
    IPV4_ETHERTYPE,
};

pub const ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN: usize = 548;
pub const ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN: usize = 590;
const ETHERNET_MIN_FRAME_LEN: usize = 60;

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
pub struct Icmpv4TimeExceededAction {
    pub egress: IfId,
    pub source_mac: MacAddress,
    pub destination_mac: MacAddress,
    pub source_ip: Ipv4Address,
    pub destination_ip: Ipv4Address,
    pub outer_tos: u8,
    pub outer_ttl: u8,
    quote_len: u16,
    quote: [u8; ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN],
}

impl Icmpv4TimeExceededAction {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        egress: IfId,
        source_mac: MacAddress,
        destination_mac: MacAddress,
        source_ip: Ipv4Address,
        destination_ip: Ipv4Address,
        original_tos: u8,
        outer_ttl: u8,
        original_ipv4: &[u8],
    ) -> Self {
        let quote_len = original_ipv4.len().min(ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN);
        let mut quote = [0; ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN];
        quote[..quote_len].copy_from_slice(&original_ipv4[..quote_len]);
        Self {
            egress,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            outer_tos: (original_tos & 0x1f) | 0xc0,
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
    action: Icmpv4TimeExceededAction,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Icmpv4TimeExceededDisposition {
    Queued {
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Icmpv4ErrorCounters {
    pub queued: usize,
    pub pending: usize,
    pub rate_limited: usize,
    pub state_full: usize,
    pub action_full: usize,
    pub clock_regressions: usize,
    pub source_not_unicast: usize,
    pub source_is_local: usize,
    pub destination_multicast: usize,
    pub destination_limited_broadcast: usize,
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

    pub(crate) fn record_suppression(
        &mut self,
        disposition: Icmpv4TimeExceededDisposition,
    ) -> Icmpv4TimeExceededDisposition {
        match disposition {
            Icmpv4TimeExceededDisposition::Queued { .. } => self.counters.queued += 1,
            Icmpv4TimeExceededDisposition::Pending { .. } => self.counters.pending += 1,
            Icmpv4TimeExceededDisposition::RateLimited { .. } => {
                self.counters.rate_limited += 1;
            }
            Icmpv4TimeExceededDisposition::StateFull => self.counters.state_full += 1,
            Icmpv4TimeExceededDisposition::ActionFull => self.counters.action_full += 1,
            Icmpv4TimeExceededDisposition::ClockRegression => {
                self.counters.clock_regressions += 1;
            }
            Icmpv4TimeExceededDisposition::SourceNotUnicast => {
                self.counters.source_not_unicast += 1;
            }
            Icmpv4TimeExceededDisposition::SourceIsLocal => self.counters.source_is_local += 1,
            Icmpv4TimeExceededDisposition::DestinationMulticast => {
                self.counters.destination_multicast += 1;
            }
            Icmpv4TimeExceededDisposition::DestinationLimitedBroadcast => {
                self.counters.destination_limited_broadcast += 1;
            }
            Icmpv4TimeExceededDisposition::DestinationDirectedBroadcast => {
                self.counters.destination_directed_broadcast += 1;
            }
            Icmpv4TimeExceededDisposition::EthernetDestinationGroup => {
                self.counters.ethernet_destination_group += 1;
            }
            Icmpv4TimeExceededDisposition::NonInitialFragment => {
                self.counters.noninitial_fragment += 1;
            }
            Icmpv4TimeExceededDisposition::IcmpErrorMessage => {
                self.counters.icmp_error_message += 1;
            }
            Icmpv4TimeExceededDisposition::IcmpTypeMissing => {
                self.counters.icmp_type_missing += 1;
            }
            Icmpv4TimeExceededDisposition::ReverseRouteMiss => {
                self.counters.reverse_route_miss += 1;
            }
            Icmpv4TimeExceededDisposition::ReverseInterfaceMiss { .. } => {
                self.counters.reverse_interface_miss += 1;
            }
            Icmpv4TimeExceededDisposition::ReverseBindingMiss { .. } => {
                self.counters.reverse_binding_miss += 1;
            }
            Icmpv4TimeExceededDisposition::ReverseTargetForbidden { .. } => {
                self.counters.reverse_target_forbidden += 1;
            }
            Icmpv4TimeExceededDisposition::ReverseNeighborUnresolved { .. } => {
                self.counters.reverse_neighbor_unresolved += 1;
            }
        }
        disposition
    }

    pub(crate) fn schedule(
        &mut self,
        action: Icmpv4TimeExceededAction,
        now: MonotonicMillis,
    ) -> Icmpv4TimeExceededDisposition {
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

    fn enqueue(
        &mut self,
        state_index: usize,
        action: Icmpv4TimeExceededAction,
    ) -> Icmpv4TimeExceededDisposition {
        if self.len == self.actions.len() {
            return self.record_suppression(Icmpv4TimeExceededDisposition::ActionFull);
        }
        let generation = self.states[state_index].generation.wrapping_add(1);
        let tail = (self.head + self.len) % self.actions.len();
        self.actions[tail].0 = Some(QueuedAction { action, generation });
        self.states[state_index].generation = generation;
        self.states[state_index].action_queued = true;
        self.len += 1;
        self.record_suppression(Icmpv4TimeExceededDisposition::Queued {
            egress: action.egress,
            quote_len: action.quote_len(),
        })
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4TimeExceededBuildError {
    ExactLengthRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecuteIcmpv4TimeExceededError {
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedIcmpv4Trace {
    AllocationFailed(GeneratedAllocationError),
    BuildFailed(Icmpv4TimeExceededBuildError),
    ClockRegression,
    TxRequested {
        egress: IfId,
        destination: Ipv4Address,
    },
    BatchCompleted {
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
    pub action: Icmpv4TimeExceededAction,
    pub allocation_error: Option<GeneratedAllocationError>,
    pub build_error: Option<Icmpv4TimeExceededBuildError>,
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
    let Some(queued) = runtime.front() else {
        return Ok(None);
    };
    if !runtime.execution_time_valid(now) {
        trace.record_generated_icmpv4(GeneratedIcmpv4Trace::ClockRegression);
        return Err(ExecuteIcmpv4TimeExceededError::ClockRegression);
    }
    let mut batch = io.begin_generated(queued.action.egress);
    let (allocation_error, build_error) = match allocate_time_exceeded(&mut batch, &queued.action) {
        Ok(()) => {
            runtime.committed(queued, now);
            trace.record_generated_icmpv4(GeneratedIcmpv4Trace::TxRequested {
                egress: queued.action.egress,
                destination: queued.action.destination_ip,
            });
            (None, None)
        }
        Err(GenerationError::Allocation(error)) => {
            trace.record_generated_icmpv4(GeneratedIcmpv4Trace::AllocationFailed(error));
            (Some(error), None)
        }
        Err(GenerationError::Build(error)) => {
            trace.record_generated_icmpv4(GeneratedIcmpv4Trace::BuildFailed(error));
            (None, Some(error))
        }
    };
    let completion = batch.finish();
    trace.record_generated_icmpv4(GeneratedIcmpv4Trace::BatchCompleted {
        accepted: completion.accepted,
        rejected: completion.rejected,
    });
    Ok(Some(GeneratedIcmpv4Report {
        action: queued.action,
        allocation_error,
        build_error,
        completion,
    }))
}

enum GenerationError {
    Allocation(GeneratedAllocationError),
    Build(Icmpv4TimeExceededBuildError),
}

fn allocate_time_exceeded<B: GeneratedPacketBatch>(
    batch: &mut B,
    action: &Icmpv4TimeExceededAction,
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
    build_time_exceeded(lease.bytes_mut(), action);
    lease.commit();
    Ok(())
}

fn build_time_exceeded(frame: &mut [u8], action: &Icmpv4TimeExceededAction) {
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
    frame[34] = 11;
    frame[35] = 0;
    frame[42..icmp_end].copy_from_slice(action.quote());
    let icmp_checksum = internet_checksum(&frame[34..icmp_end]);
    frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(egress: u16, quote_len: usize) -> Icmpv4TimeExceededAction {
        let original = [0xa5; ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN];
        Icmpv4TimeExceededAction::new(
            IfId(egress),
            MacAddress([2, 0, 0, 0, 0, 1]),
            MacAddress([2, 0, 0, 0, 0, 2]),
            Ipv4Address::from_octets([192, 0, 2, 1]),
            Ipv4Address::from_octets([198, 51, 100, 1]),
            0x2e,
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
    fn action_bounds_quote_and_frame_and_zeroes_unused_storage() {
        let short = action(1, 20);
        assert_eq!(short.quote_len(), 20);
        assert_eq!(short.frame_len(), 62);
        assert!(short.quote[20..].iter().all(|byte| *byte == 0));
        let long = action(1, 548);
        assert_eq!(long.frame_len(), ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN);
        assert_eq!(long.outer_tos, 0xce);
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

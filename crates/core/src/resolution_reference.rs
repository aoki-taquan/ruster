//! Test-only reference: the resolution runtime exactly as it was before H4b
//! (origin/main b1e31aa, `crates/core/src/resolution.rs`), with full-table
//! scans for every lookup and free-slot search. Only names changed (`Ref*`),
//! doc comments and the publication preflight were dropped, and private
//! policy fields are read through their accessors. The H4b equivalence test
//! drives it and the indexed runtime with the same operations and compares
//! every observable result and every slot.

#![allow(dead_code, clippy::all)]

use std::{marker::PhantomData, rc::Rc};

use crate::{
    resolution::{
        ArpRequestAction, ControlDisposition, DynamicLookup, MonotonicMillis, ResolutionCounters,
        ResolutionFailureCapture, ResolutionFailureCounters, ResolutionFailureDispatchError,
        ResolutionFailureDispatchReport, ResolutionFailureHoldPhase, ResolutionFailureTrace,
        ResolutionFailureTraceSink, ResolutionGenerationToken, ResolutionPhase, ResolutionPolicy,
        ResolutionPublicationError, ResolutionResult, ResolutionStatus, ResolutionTimerError,
        ResolutionTimerReport, ResolutionTimerTrace, ResolutionTimerTraceSink,
        StaticReconcileReport,
    },
    Icmpv4ErrorAction, Icmpv4ErrorDisposition, Icmpv4ErrorKind, Icmpv4ErrorRuntime, IfId,
    Ipv4Address, MacAddress, ICMPV4_ERROR_MAX_QUOTE_LEN,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolutionKey {
    pub(crate) egress: IfId,
    pub(crate) target: Ipv4Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QueuedAction {
    pub(crate) action: ArpRequestAction,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RefAction(pub(crate) Option<QueuedAction>);

impl RefAction {
    pub(crate) const EMPTY: Self = Self(None);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RefState {
    pub(crate) key: ResolutionKey,
    pub(crate) action: ArpRequestAction,
    pub(crate) generation: u64,
    pub(crate) attempts: u16,
    pub(crate) accepted_attempts: u16,
    pub(crate) requested_at: MonotonicMillis,
    pub(crate) failed_at: MonotonicMillis,
    pub(crate) occupied: bool,
    pub(crate) phase: ResolutionPhase,
    pub(crate) failure_notified: bool,
}

impl RefState {
    pub(crate) const EMPTY: Self = Self {
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
pub(crate) struct RefDynamic {
    pub(crate) interface: IfId,
    pub(crate) target: Ipv4Address,
    pub(crate) mac: MacAddress,
    pub(crate) refreshed_at: MonotonicMillis,
    pub(crate) occupied: bool,
}

impl RefDynamic {
    pub(crate) const EMPTY: Self = Self {
        interface: IfId(0),
        target: Ipv4Address::from_octets([0; 4]),
        mac: MacAddress([0; 6]),
        refreshed_at: MonotonicMillis(0),
        occupied: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RefHold {
    pub(crate) phase: ResolutionFailureHoldPhase,
    pub(crate) forward: ResolutionGenerationToken,
    pub(crate) reverse: ResolutionGenerationToken,
    pub(crate) original_source: Ipv4Address,
    pub(crate) original_destination: Ipv4Address,
    pub(crate) forward_source_mac: MacAddress,
    pub(crate) forward_source_ip: Ipv4Address,
    pub(crate) forward_prefix: Ipv4Address,
    pub(crate) forward_prefix_len: u8,
    pub(crate) original_tos: u8,
    pub(crate) quote_len: u16,
    pub(crate) quote: [u8; ICMPV4_ERROR_MAX_QUOTE_LEN],
}

impl RefHold {
    pub(crate) const EMPTY: Self = Self {
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
    pub(crate) const fn phase(&self) -> ResolutionFailureHoldPhase {
        self.phase
    }

    #[must_use]
    pub(crate) const fn forward_token(&self) -> Option<ResolutionGenerationToken> {
        if matches!(self.phase, ResolutionFailureHoldPhase::Empty) {
            None
        } else {
            Some(self.forward)
        }
    }

    #[must_use]
    pub(crate) const fn quote_len(&self) -> usize {
        self.quote_len as usize
    }
}

pub(crate) struct RefRuntime<'a> {
    pub(crate) policy: ResolutionPolicy,
    pub(crate) states: &'a mut [RefState],
    pub(crate) actions: &'a mut [RefAction],
    pub(crate) dynamic_neighbors: &'a mut [RefDynamic],
    pub(crate) failure_holds: &'a mut [RefHold],
    pub(crate) head: usize,
    pub(crate) len: usize,
    pub(crate) pending_state_count: usize,
    pub(crate) pending_failure_hold_count: usize,
    pub(crate) poll_cursor: usize,
    pub(crate) failure_cursor: usize,
    pub(crate) last_now: Option<MonotonicMillis>,
    pub(crate) publication_epoch: u128,
    pub(crate) counters: ResolutionCounters,
    pub(crate) failure_counters: ResolutionFailureCounters,
    pub(crate) _worker_local: PhantomData<Rc<()>>,
}

impl<'a> RefRuntime<'a> {
    #[must_use]
    pub(crate) fn new(
        policy: ResolutionPolicy,
        states: &'a mut [RefState],
        action_storage: &'a mut [RefAction],
    ) -> Self {
        Self::with_dynamic_neighbors(policy, states, action_storage, &mut [])
    }

    #[must_use]
    pub(crate) fn with_dynamic_neighbors(
        policy: ResolutionPolicy,
        states: &'a mut [RefState],
        action_storage: &'a mut [RefAction],
        dynamic_neighbors: &'a mut [RefDynamic],
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
    pub(crate) fn with_dynamic_neighbors_and_failure_holds(
        policy: ResolutionPolicy,
        states: &'a mut [RefState],
        action_storage: &'a mut [RefAction],
        dynamic_neighbors: &'a mut [RefDynamic],
        failure_holds: &'a mut [RefHold],
    ) -> Self {
        states.fill(RefState::EMPTY);
        action_storage.fill(RefAction::EMPTY);
        dynamic_neighbors.fill(RefDynamic::EMPTY);
        failure_holds.fill(RefHold::EMPTY);
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
    pub(crate) fn dynamic_neighbor_count(&self) -> usize {
        self.dynamic_neighbors
            .iter()
            .filter(|slot| slot.occupied)
            .count()
    }

    #[must_use]
    pub(crate) const fn policy(&self) -> ResolutionPolicy {
        self.policy
    }

    #[must_use]
    pub(crate) const fn state_capacity(&self) -> usize {
        self.states.len()
    }

    #[must_use]
    pub(crate) const fn action_capacity(&self) -> usize {
        self.actions.len()
    }

    #[must_use]
    pub(crate) const fn dynamic_neighbor_capacity(&self) -> usize {
        self.dynamic_neighbors.len()
    }

    #[must_use]
    pub(crate) const fn failure_hold_capacity(&self) -> usize {
        self.failure_holds.len()
    }

    #[must_use]
    pub(crate) fn is_pristine(&self) -> bool {
        self.states.iter().all(|slot| *slot == RefState::EMPTY)
            && self.actions.iter().all(|slot| *slot == RefAction::EMPTY)
            && self
                .dynamic_neighbors
                .iter()
                .all(|slot| *slot == RefDynamic::EMPTY)
            && self
                .failure_holds
                .iter()
                .all(|slot| *slot == RefHold::EMPTY)
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

    pub(crate) fn reconcile_static(
        &mut self,
        neighbors: &[crate::Neighbor],
    ) -> StaticReconcileReport {
        let mut report = StaticReconcileReport::default();
        for slot in &mut *self.dynamic_neighbors {
            if slot.occupied
                && neighbors.iter().any(|neighbor| {
                    neighbor.interface == slot.interface && neighbor.target == slot.target
                })
            {
                *slot = RefDynamic::EMPTY;
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

    pub(crate) fn reconcile_publication(
        &mut self,
        snapshot: &crate::ForwardingSnapshot<'_>,
    ) -> StaticReconcileReport {
        self.commit_publication(snapshot)
    }

    pub(crate) fn validate_publication_invariants(&self) -> Result<(), ResolutionPublicationError> {
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

    pub(crate) fn commit_publication(
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
                *slot = RefDynamic::EMPTY;
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
            self.failure_holds[index] = RefHold::EMPTY;
            self.pending_failure_hold_count = self.pending_failure_hold_count.saturating_sub(1);
            self.failure_counters.cancelled = self.failure_counters.cancelled.saturating_add(1);
        }
        report
    }

    pub(crate) fn compact_publication_actions(
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
                self.actions[index] = RefAction::EMPTY;
            }
        }
        self.head = if retained == 0 { 0 } else { head };
        self.len = retained;
        (static_removed, invalid_removed)
    }

    #[must_use]
    pub(crate) const fn counters(&self) -> ResolutionCounters {
        self.counters
    }

    #[must_use]
    pub(crate) const fn failure_counters(&self) -> ResolutionFailureCounters {
        self.failure_counters
    }

    #[must_use]
    pub(crate) const fn pending_failure_holds(&self) -> usize {
        self.pending_failure_hold_count
    }

    #[must_use]
    pub(crate) const fn pending_actions(&self) -> usize {
        self.len
    }

    #[must_use]
    pub(crate) const fn pending_states(&self) -> usize {
        self.pending_state_count
    }

    #[must_use]
    pub(crate) fn cooldown_count(&self) -> usize {
        self.states
            .iter()
            .filter(|state| state.occupied && state.phase == ResolutionPhase::Cooldown)
            .count()
    }

    #[must_use]
    pub(crate) fn status(&self, egress: IfId, target: Ipv4Address) -> Option<ResolutionStatus> {
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
        *slot = RefHold::EMPTY;
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
                    if now.0 - self.states[index].requested_at.0 < self.policy.interval_ms() {
                        self.counters.suppressed += 1;
                        return ResolutionResult::Suppressed;
                    }
                    if self.states[index].attempts >= self.policy.max_attempts() {
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
                    if now.0 - self.states[index].failed_at.0 < self.policy.failed_hold_ms() {
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
                    if now.0 - self.states[index].requested_at.0 < self.policy.interval_ms() {
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
                    && now.0 - slot.requested_at.0 >= self.policy.interval_ms())
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
        if now.0 - slot.refreshed_at.0 >= self.policy.dynamic_neighbor_ttl_ms() {
            *slot = RefDynamic::EMPTY;
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
                < self.policy.dynamic_neighbor_ttl_ms()
            {
                self.dynamic_neighbors[index].mac = mac;
                self.dynamic_neighbors[index].refreshed_at = now;
                self.clear_resolution(interface, sender);
                return ControlDisposition::Updated;
            }
            self.dynamic_neighbors[index] = RefDynamic::EMPTY;
        }
        if !allow_insert {
            return ControlDisposition::Ignored;
        }
        let reusable = self.dynamic_neighbors.iter().position(|slot| {
            !slot.occupied || now.0 - slot.refreshed_at.0 >= self.policy.dynamic_neighbor_ttl_ms()
        });
        let Some(index) = reusable else {
            return ControlDisposition::CacheFull;
        };
        self.dynamic_neighbors[index] = RefDynamic {
            interface,
            target: sender,
            mac,
            refreshed_at: now,
            occupied: true,
        };
        self.clear_resolution(interface, sender);
        ControlDisposition::Inserted
    }

    pub(crate) fn observe_now(&mut self, now: MonotonicMillis) -> bool {
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

    pub(crate) fn clear_resolution(&mut self, interface: IfId, target: Ipv4Address) {
        for index in 0..self.states.len() {
            let state = self.states[index];
            if state.occupied && state.key.egress == interface && state.key.target == target {
                self.cancel_state_at(index);
            }
        }
        self.compact_actions(|action| action.egress == interface && action.target_ip == target);
        self.cancel_forward_holds(interface, target);
    }

    pub(crate) fn reconcile_static_key(&mut self, interface: IfId, target: Ipv4Address) {
        for slot in &mut *self.dynamic_neighbors {
            if slot.occupied && slot.interface == interface && slot.target == target {
                *slot = RefDynamic::EMPTY;
            }
        }
        self.clear_resolution(interface, target);
    }

    pub(crate) fn compact_actions(&mut self, remove: impl Fn(ArpRequestAction) -> bool) -> usize {
        self.compact_queued_actions(|queued| remove(queued.action))
    }

    pub(crate) fn compact_queued_actions(
        &mut self,
        mut remove: impl FnMut(QueuedAction) -> bool,
    ) -> usize {
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

    pub(crate) fn cancel_state_at(&mut self, index: usize) {
        if cancel_state(&mut self.states[index]) {
            debug_assert!(self.pending_state_count != 0);
            self.pending_state_count -= 1;
        }
    }

    pub(crate) fn vacate_state_at(&mut self, index: usize) {
        let was_pending = state_is_pending(self.states[index]);
        vacate_state(&mut self.states[index]);
        if was_pending {
            debug_assert!(self.pending_state_count != 0);
            self.pending_state_count -= 1;
        }
    }

    pub(crate) fn clear_failure_hold(&mut self, index: usize) {
        debug_assert!(
            self.failure_holds[index].phase != ResolutionFailureHoldPhase::Empty,
            "only a live failure hold can be cleared"
        );
        self.failure_holds[index] = RefHold::EMPTY;
        debug_assert!(self.pending_failure_hold_count != 0);
        self.pending_failure_hold_count -= 1;
    }

    pub(crate) fn start_cycle(&mut self, index: usize, action: ArpRequestAction) {
        let was_pending = state_is_pending(self.states[index]);
        let generation = self.next_generation(
            action.egress,
            action.target_ip,
            self.states[index].generation,
        );
        self.states[index] = RefState {
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

    pub(crate) fn enqueue_initial(&mut self, index: usize) -> ResolutionResult {
        debug_assert_eq!(self.states[index].attempts, 0);
        debug_assert_eq!(self.states[index].phase, ResolutionPhase::InitialQueued);
        self.enqueue_state_action(index);
        self.counters.queued += 1;
        ResolutionResult::Queued
    }

    pub(crate) fn enqueue_retry(&mut self, index: usize) -> ResolutionResult {
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

    pub(crate) fn enqueue_state_action(&mut self, index: usize) {
        debug_assert!(self.len < self.actions.len());
        let action = self.states[index].action;
        let generation = self.states[index].generation;
        let tail = (self.head + self.len) % self.actions.len();
        self.actions[tail].0 = Some(QueuedAction { action, generation });
        self.len += 1;
    }

    pub(crate) fn mark_failed(&mut self, index: usize, now: MonotonicMillis) -> ResolutionResult {
        debug_assert_eq!(self.states[index].phase, ResolutionPhase::Waiting);
        debug_assert!(self.states[index].attempts >= self.policy.max_attempts());
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

    pub(crate) fn front(&self) -> Option<QueuedAction> {
        self.actions.get(self.head).and_then(|item| item.0)
    }

    pub(crate) fn execution_time_valid(&mut self, now: MonotonicMillis) -> bool {
        self.observe_now(now)
    }

    pub(crate) fn committed(&mut self, queued: QueuedAction, now: MonotonicMillis) {
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
            debug_assert!(state.attempts < self.policy.max_attempts());
            state.attempts += 1;
            state.phase = ResolutionPhase::Waiting;
            state.requested_at = now;
            self.counters.attempts_committed += 1;
        }
    }

    pub(crate) fn accepted(&mut self, queued: QueuedAction, accepted: usize) {
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

    pub(crate) fn next_generation(&self, egress: IfId, target: Ipv4Address, previous: u64) -> u64 {
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

    pub(crate) fn cancel_forward_holds(&mut self, egress: IfId, target: Ipv4Address) {
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

    pub(crate) fn poll_timers<T: ResolutionTimerTraceSink>(
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
                    if now.0 - self.states[index].requested_at.0 < self.policy.interval_ms() {
                        continue;
                    }
                    if self.states[index].attempts >= self.policy.max_attempts() {
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
                    if now.0 - self.states[index].failed_at.0 >= self.policy.failed_hold_ms() {
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

fn publication_hold_valid(snapshot: &crate::ForwardingSnapshot<'_>, hold: RefHold) -> bool {
    crate::route::lookup_linear(snapshot.routes, hold.original_destination).is_some_and(|route| {
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

const fn state_is_pending(state: RefState) -> bool {
    state.occupied && !matches!(state.phase, ResolutionPhase::Cooldown)
}

fn vacate_state(state: &mut RefState) {
    let generation = state.generation;
    *state = RefState::EMPTY;
    state.generation = generation;
}

fn cancel_state(state: &mut RefState) -> bool {
    let was_pending = state_is_pending(*state);
    if state.attempts == 0 {
        vacate_state(state);
        return was_pending;
    }
    let key = state.key;
    let generation = state.generation;
    let attempts = state.attempts;
    let requested_at = state.requested_at;
    *state = RefState::EMPTY;
    state.key = key;
    state.generation = generation;
    state.attempts = attempts;
    state.requested_at = requested_at;
    state.occupied = true;
    state.phase = ResolutionPhase::Cooldown;
    was_pending
}

pub(crate) fn ref_poll_resolution_timers<T: ResolutionTimerTraceSink>(
    runtime: &mut RefRuntime<'_>,
    now: MonotonicMillis,
    scan_budget: usize,
    trace: &mut T,
) -> Result<ResolutionTimerReport, ResolutionTimerError> {
    runtime.poll_timers(now, scan_budget, trace)
}

pub(crate) fn ref_dispatch_host_unreachable_failures<T: ResolutionFailureTraceSink>(
    resolution: &mut RefRuntime<'_>,
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
            FailureDispatch::GenerationDisabled => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.generation_disabled += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::GenerationDisabled {
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
    GenerationDisabled,
    AuthorityLost,
}

fn dispatch_one_failure(
    resolution: &mut RefRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    now: MonotonicMillis,
    hold: RefHold,
) -> FailureDispatch {
    let forward_status = resolution.status(hold.forward.egress, hold.forward.target);
    if !forward_status.is_some_and(|status| {
        status.generation == hold.forward.generation
            && status.phase == ResolutionPhase::Failed
            && status.accepted_attempts != 0
    }) {
        return FailureDispatch::AuthorityLost;
    }
    let forward_route = crate::route::lookup_linear(snapshot.routes, hold.original_destination);
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
    if !icmpv4_errors
        .policy()
        .generates(Icmpv4ErrorKind::DestinationUnreachableHost)
    {
        // Retire before the reverse route or reverse ARP: a disabled kind
        // emits nothing on the wire.
        icmpv4_errors.record_suppression(Icmpv4ErrorDisposition::GenerationDisabled {
            kind: Icmpv4ErrorKind::DestinationUnreachableHost,
        });
        return FailureDispatch::GenerationDisabled;
    }

    let Some(reverse_route) = crate::route::lookup_linear(snapshot.routes, hold.original_source)
    else {
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

fn current_icmp_error_eligible(snapshot: &crate::ForwardingSnapshot<'_>, hold: RefHold) -> bool {
    let source = hold.original_source.octets();
    source[0] != 0
        && source[0] != 127
        && source[0] < 224
        && !snapshot
            .local_ipv4
            .iter()
            .any(|binding| binding.address == hold.original_source)
        && !crate::route::lookup_linear(snapshot.routes, hold.original_source).is_some_and(
            |route| {
                route.is_prefix_network_address(hold.original_source)
                    || route.is_prefix_directed_broadcast(hold.original_source)
            },
        )
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

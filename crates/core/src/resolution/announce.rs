//! RFC 5227 ARP Announcements of the router's own addresses and address
//! conflict detection and defense (ARP-016, ARP-033..ARP-039).
//!
//! RFC 5227 §1.3: "Where this document uses the term 'host', it applies
//! equally to interfaces on routers". Each interface of the forwarding
//! snapshot has one fixed [`ArpAnnounceSlot`] in caller storage (the slot
//! at index `i` belongs to `snapshot.interfaces[i]`), attached with
//! [`ResolutionRuntime::with_announce_slots`]:
//!
//! - **Triggers** (cold path): [`ResolutionRuntime::request_announcements`]
//!   at startup and after a link-up event, and
//!   [`ResolutionRuntime::announce_changed_bindings`] after a publication
//!   for every interface whose address is new or changed. A trigger only
//!   marks the slot `requested`; repeated triggers coalesce.
//! - **Sequence** (generated ARP phase, [`execute_one_arp_announcement`]):
//!   a requested slot starts a sequence of `count` Announcements
//!   (RFC 5227 §2.3: ANNOUNCE_NUM = 2) `interval_ms` apart
//!   (ANNOUNCE_INTERVAL = 2 s), the first one at once (no Probe, so no
//!   ANNOUNCE_WAIT, ARP-036), but never sooner than `min_interval_ms` after
//!   the previous sequence started on the same interface (ARP-035): a link
//!   flap storm costs at most one sequence per minimum interval, and the
//!   last trigger is never lost (it starts when the interval ends). Each
//!   frame is built from the snapshot current at send time, so it always
//!   carries the interface's current MAC and address.
//! - **Conflicts** (RX path, [`ResolutionRuntime::observe_local_sender`]):
//!   an ARP packet whose sender IP is the ingress interface's own address
//!   and whose sender MAC is not the interface's MAC is a conflicting ARP
//!   packet (§2.4). It is counted per interface. With defense on, the first
//!   conflict after DEFEND_INTERVAL (10 s) without a defense queues one
//!   Announcement (§2.4 (c)); later ones within the interval do not.
//!
//! Every frame goes through the generated-ARP phase and its frame budget,
//! after the resolution Requests, into a backend-owned generated frame
//! (no allocation, no packet copy).

use super::{
    allocate_arp_request, ArpRequestAction, ArpRequestBuildError, ArpRequestGenerationError,
    ExecuteArpRequestError, GeneratedArpReport, GeneratedArpTrace, GeneratedTraceSink,
    MonotonicMillis, ResolutionRuntime,
};
use std::num::NonZeroU8;

use crate::{ForwardingSnapshot, GeneratedPacketBatch, GeneratedPacketIo, IfId, MacAddress};

/// RFC 5227 §1.1 ANNOUNCE_NUM: Announcements per sequence.
pub const ARP_ANNOUNCE_NUM: u8 = 2;
/// RFC 5227 §1.1 ANNOUNCE_INTERVAL: time between Announcements.
pub const ARP_ANNOUNCE_INTERVAL_MS: u64 = 2_000;
/// RFC 5227 §1.1 DEFEND_INTERVAL: minimum interval between defensive
/// Announcements of one address.
pub const ARP_DEFEND_INTERVAL_MS: u64 = 10_000;
/// Default minimum interval between two announcement sequences on one
/// interface (local flap bound, ARP-035). It reuses DEFEND_INTERVAL, the
/// RFC's own floor for repeated broadcasts about one address.
pub const ARP_ANNOUNCE_DEFAULT_MIN_INTERVAL_MS: u64 = ARP_DEFEND_INTERVAL_MS;
/// Largest `count` [`ArpAnnouncePolicy::new`] accepts.
pub const ARP_ANNOUNCE_MAX_COUNT: u8 = 10;
/// Smallest `interval_ms` [`ArpAnnouncePolicy::new`] accepts.
pub const ARP_ANNOUNCE_MIN_INTERVAL_MS: u64 = 1_000;
/// Largest `interval_ms` and `min_interval_ms` [`ArpAnnouncePolicy::new`]
/// accepts (one hour).
pub const ARP_ANNOUNCE_MAX_INTERVAL_MS: u64 = 3_600_000;

/// Why [`ArpAnnouncePolicy::new`] refused its values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpAnnouncePolicyError {
    /// `count` is 0 or above [`ARP_ANNOUNCE_MAX_COUNT`].
    CountOutOfRange,
    /// `interval_ms` is below [`ARP_ANNOUNCE_MIN_INTERVAL_MS`] or above
    /// [`ARP_ANNOUNCE_MAX_INTERVAL_MS`].
    IntervalOutOfRange,
    /// `min_interval_ms` is above [`ARP_ANNOUNCE_MAX_INTERVAL_MS`] or
    /// shorter than one whole sequence (`interval_ms * (count - 1)`, and
    /// at least [`ARP_ANNOUNCE_MIN_INTERVAL_MS`]).
    MinIntervalOutOfRange,
}

/// How the router announces its own addresses (RFC 5227 §2.3).
///
/// 12 bytes (an `Option` of it too): it rides in the by-value forwarding
/// snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpAnnouncePolicy {
    count: NonZeroU8,
    interval_ms: u32,
    min_interval_ms: u32,
}

impl ArpAnnouncePolicy {
    /// RFC 5227 §1.1 values: ANNOUNCE_NUM 2, ANNOUNCE_INTERVAL 2 s, and
    /// the local minimum interval [`ARP_ANNOUNCE_DEFAULT_MIN_INTERVAL_MS`].
    pub const RFC5227: Self = Self {
        count: NonZeroU8::new(ARP_ANNOUNCE_NUM).expect("ANNOUNCE_NUM is nonzero"),
        interval_ms: ARP_ANNOUNCE_INTERVAL_MS as u32,
        min_interval_ms: ARP_ANNOUNCE_DEFAULT_MIN_INTERVAL_MS as u32,
    };

    /// A policy of `count` Announcements `interval_ms` apart, with
    /// sequences on one interface starting at least `min_interval_ms`
    /// apart.
    pub const fn new(
        count: u8,
        interval_ms: u64,
        min_interval_ms: u64,
    ) -> Result<Self, ArpAnnouncePolicyError> {
        let Some(nonzero) = NonZeroU8::new(count) else {
            return Err(ArpAnnouncePolicyError::CountOutOfRange);
        };
        if count > ARP_ANNOUNCE_MAX_COUNT {
            return Err(ArpAnnouncePolicyError::CountOutOfRange);
        }
        if interval_ms < ARP_ANNOUNCE_MIN_INTERVAL_MS || interval_ms > ARP_ANNOUNCE_MAX_INTERVAL_MS
        {
            return Err(ArpAnnouncePolicyError::IntervalOutOfRange);
        }
        let sequence = interval_ms * (count as u64 - 1);
        if min_interval_ms > ARP_ANNOUNCE_MAX_INTERVAL_MS
            || min_interval_ms < sequence
            || min_interval_ms < ARP_ANNOUNCE_MIN_INTERVAL_MS
        {
            return Err(ArpAnnouncePolicyError::MinIntervalOutOfRange);
        }
        // Both are at most ARP_ANNOUNCE_MAX_INTERVAL_MS, which fits u32.
        Ok(Self {
            count: nonzero,
            interval_ms: interval_ms as u32,
            min_interval_ms: min_interval_ms as u32,
        })
    }

    pub(crate) const fn interval_ms_u32(self) -> u32 {
        self.interval_ms
    }

    pub(crate) const fn min_interval_ms_u32(self) -> u32 {
        self.min_interval_ms
    }

    /// The policy stored as parts by [`crate::ArpPolicy`] (`count` 0:
    /// none). The parts come from a validated policy.
    pub(crate) const fn from_parts(
        count: u8,
        interval_ms: u32,
        min_interval_ms: u32,
    ) -> Option<Self> {
        match NonZeroU8::new(count) {
            Some(count) => Some(Self {
                count,
                interval_ms,
                min_interval_ms,
            }),
            None => None,
        }
    }

    #[must_use]
    pub const fn count(self) -> u8 {
        self.count.get()
    }

    #[must_use]
    pub const fn interval_ms(self) -> u64 {
        self.interval_ms as u64
    }

    #[must_use]
    pub const fn min_interval_ms(self) -> u64 {
        self.min_interval_ms as u64
    }
}

const NEVER: u64 = u64::MAX;
/// `next_due` of a waiting slot whose start the minimum interval holds
/// back (already counted `rate_limited`).
const DEFERRED: u64 = u64::MAX;

/// Announcement and conflict state of one interface (32 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpAnnounceSlot {
    interface: IfId,
    /// Announcements left in the running sequence (0: none running).
    remaining: u8,
    /// A trigger waits for the next sequence.
    requested: bool,
    /// Conflicting ARP packets seen on the interface (saturating).
    conflicts: u32,
    /// When the next Announcement of the running sequence is due.
    next_due: u64,
    /// When the last sequence started ([`NEVER`]: none yet).
    last_start: u64,
    /// When the last defense was decided ([`NEVER`]: none yet).
    last_defense: u64,
}

impl ArpAnnounceSlot {
    pub const EMPTY: Self = Self {
        interface: IfId(0),
        remaining: 0,
        requested: false,
        conflicts: 0,
        next_due: 0,
        last_start: NEVER,
        last_defense: NEVER,
    };

    const fn busy(&self) -> bool {
        self.requested || self.remaining != 0
    }
}

/// Announcement and conflict counters (section `arp_announce`). `ruster
/// run` renders them in its stats blocks; the run-sim schema does not
/// include them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArpAnnounceCounters {
    /// Triggers that marked an idle interface (startup, link-up, changed
    /// address).
    pub requested: u64,
    /// Triggers folded into one already waiting or running.
    pub coalesced: u64,
    /// Triggers ignored because announcements are off.
    pub disabled: u64,
    /// Sequences started.
    pub sequences: u64,
    /// Waiting triggers whose sequence start the minimum interval held
    /// back (flap bound), once per wait.
    pub rate_limited: u64,
    /// Announcements committed for TX (defenses included).
    pub sent: u64,
    /// Waiting or running sequences dropped because the interface had no
    /// IPv4 address (or announcements were switched off) at send time.
    pub cancelled: u64,
    /// Conflicting ARP packets (RFC 5227 §2.4), all interfaces.
    pub conflicts: u64,
    /// Defensive Announcements queued (§2.4 (c)).
    pub defended: u64,
    /// Conflicts within DEFEND_INTERVAL of the last defense (not
    /// defended, §2.4 (c)) or seen with defense off.
    pub defense_suppressed: u64,
}

impl crate::ObservableFields for ArpAnnounceCounters {
    fn visit_fields<V: crate::FieldVisitor>(&self, visitor: &mut V) {
        let Self {
            requested,
            coalesced,
            disabled,
            sequences,
            rate_limited,
            sent,
            cancelled,
            conflicts,
            defended,
            defense_suppressed,
        } = *self;
        for (key, value) in [
            ("requested", requested),
            ("coalesced", coalesced),
            ("disabled", disabled),
            ("sequences", sequences),
            ("rate_limited", rate_limited),
            ("sent", sent),
            ("cancelled", cancelled),
            ("conflicts", conflicts),
            ("defended", defended),
            ("defense_suppressed", defense_suppressed),
        ] {
            visitor.field("arp_announce", key, crate::FieldValue::Count(value));
        }
    }
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

impl<'a> ResolutionRuntime<'a> {
    /// Attaches one announcement slot per interface of `snapshot` (the
    /// slot at index `i` belongs to its `i`-th interface) and clears them.
    ///
    /// `slots` must have exactly as many slots as `snapshot` has
    /// interfaces; any other length leaves announcements and conflict
    /// counting off (no slot is used).
    #[must_use]
    pub fn with_announce_slots(
        mut self,
        slots: &'a mut [ArpAnnounceSlot],
        snapshot: &ForwardingSnapshot<'_>,
    ) -> Self {
        slots.fill(ArpAnnounceSlot::EMPTY);
        let interfaces = snapshot.interfaces();
        if slots.len() == interfaces.len() {
            for (slot, interface) in slots.iter_mut().zip(interfaces) {
                slot.interface = interface.id;
            }
            self.announce = slots;
        }
        self.announce_busy = 0;
        self
    }

    /// The announcement and conflict counters.
    #[must_use]
    pub const fn announce_counters(&self) -> ArpAnnounceCounters {
        self.announce_counters
    }

    /// Interfaces with an announcement waiting or running.
    #[must_use]
    pub const fn pending_announcements(&self) -> usize {
        self.announce_busy
    }

    /// The conflicting ARP packets seen on each interface, in snapshot
    /// interface order.
    pub fn address_conflicts(&self) -> impl Iterator<Item = (IfId, u32)> + '_ {
        self.announce
            .iter()
            .map(|slot| (slot.interface, slot.conflicts))
    }

    /// Marks `interface` (every interface when `None`) to announce its
    /// address (startup, link-up). Returns the interfaces newly marked.
    /// Interfaces without an IPv4 address in `snapshot` are skipped; with
    /// announcements off in `snapshot` nothing is marked (counted
    /// `disabled`).
    pub fn request_announcements(
        &mut self,
        snapshot: &ForwardingSnapshot<'_>,
        interface: Option<IfId>,
    ) -> usize {
        let mut marked = 0;
        for index in 0..self.announce.len() {
            let id = self.announce[index].interface;
            if interface.is_some_and(|wanted| wanted != id)
                || snapshot.local_binding_on(id).is_none()
            {
                continue;
            }
            marked += usize::from(self.request_at(index, snapshot));
        }
        marked
    }

    /// Marks every interface whose IPv4 address in `next` is new or
    /// differs from `current` (a reload that adds or changes an address),
    /// and rebinds the slots to `next`'s interface order (the interface
    /// set itself is restart-required, so only the order can differ).
    /// Returns the interfaces newly marked.
    pub fn announce_changed_bindings(
        &mut self,
        current: &ForwardingSnapshot<'_>,
        next: &ForwardingSnapshot<'_>,
    ) -> usize {
        self.rebind_announce_slots(next);
        let mut marked = 0;
        for index in 0..self.announce.len() {
            let id = self.announce[index].interface;
            let Some(binding) = next.local_binding_on(id) else {
                continue;
            };
            let before = current.local_binding_on(id).map(|binding| binding.address);
            if before != Some(binding.address) {
                marked += usize::from(self.request_at(index, next));
            }
        }
        marked
    }

    /// Keeps each slot with its interface when `next` orders the
    /// interfaces differently (cold, O(interfaces²) at most).
    fn rebind_announce_slots(&mut self, next: &ForwardingSnapshot<'_>) {
        let interfaces = next.interfaces();
        if interfaces.len() != self.announce.len() {
            // Not reachable through a validated publication (the
            // interface set is restart-required): stop using the slots.
            self.announce = &mut [];
            self.announce_busy = 0;
            return;
        }
        for (index, interface) in interfaces.iter().enumerate() {
            if self.announce[index].interface == interface.id {
                continue;
            }
            let found = (index + 1..self.announce.len())
                .find(|&other| self.announce[other].interface == interface.id);
            match found {
                Some(other) => self.announce.swap(index, other),
                None => {
                    if self.announce[index].busy() {
                        self.announce_busy -= 1;
                    }
                    self.announce[index] = ArpAnnounceSlot {
                        interface: interface.id,
                        ..ArpAnnounceSlot::EMPTY
                    };
                }
            }
        }
    }

    fn request_at(&mut self, index: usize, snapshot: &ForwardingSnapshot<'_>) -> bool {
        if snapshot.arp.announce().is_none() {
            bump(&mut self.announce_counters.disabled);
            return false;
        }
        let slot = &mut self.announce[index];
        if slot.requested {
            bump(&mut self.announce_counters.coalesced);
            return false;
        }
        if slot.remaining != 0 {
            bump(&mut self.announce_counters.coalesced);
        } else {
            bump(&mut self.announce_counters.requested);
            self.announce_busy += 1;
        }
        slot.requested = true;
        true
    }

    /// RX path: an ARP packet on `ingress` whose sender IP is the
    /// interface's own address. A sender MAC other than the interface's is
    /// a conflicting ARP packet (RFC 5227 §2.4): counted, and with defense
    /// on, defended by one Announcement unless one was decided within
    /// DEFEND_INTERVAL. O(log interfaces), no allocation.
    pub(crate) fn observe_local_sender(
        &mut self,
        snapshot: &ForwardingSnapshot<'_>,
        ingress: IfId,
        sender_mac: MacAddress,
        now: MonotonicMillis,
    ) {
        let Some(interface) = snapshot.interface(ingress) else {
            return;
        };
        if interface.mac == sender_mac {
            return;
        }
        bump(&mut self.announce_counters.conflicts);
        let Some(index) = snapshot.interface_slot(ingress).filter(|&index| {
            self.announce
                .get(index)
                .is_some_and(|slot| slot.interface == ingress)
        }) else {
            return;
        };
        let slot = &mut self.announce[index];
        slot.conflicts = slot.conflicts.saturating_add(1);
        let recent = slot.last_defense != NEVER
            && now.0.saturating_sub(slot.last_defense) < ARP_DEFEND_INTERVAL_MS;
        if !snapshot.arp.defend_conflicts() || recent {
            bump(&mut self.announce_counters.defense_suppressed);
            return;
        }
        slot.last_defense = now.0;
        bump(&mut self.announce_counters.defended);
        if slot.remaining == 0 {
            if !slot.requested {
                self.announce_busy += 1;
            }
            slot.remaining = 1;
            slot.next_due = now.0;
        } else {
            // A running sequence sends its next Announcement now.
            slot.next_due = slot.next_due.min(now.0);
        }
    }

    /// The first slot with an Announcement due at `now`, starting the
    /// sequences whose minimum interval has passed. O(interfaces) only
    /// while some interface is waiting or running; O(1) otherwise.
    fn due_announcement(
        &mut self,
        snapshot: &ForwardingSnapshot<'_>,
        now: MonotonicMillis,
    ) -> Option<(usize, ArpRequestAction)> {
        if self.announce_busy == 0 {
            return None;
        }
        let policy = snapshot.arp.announce();
        for index in 0..self.announce.len() {
            let slot = self.announce[index];
            if !slot.busy() {
                continue;
            }
            let binding = snapshot.local_binding_on(slot.interface);
            let interface = snapshot.interface(slot.interface);
            let (Some(binding), Some(interface)) = (binding, interface) else {
                self.cancel_announce(index);
                continue;
            };
            // A defense (remaining set by a conflict) runs with
            // announcements off; a waiting trigger does not.
            if slot.requested && slot.remaining == 0 {
                let Some(policy) = policy else {
                    self.cancel_announce(index);
                    continue;
                };
                if slot.last_start != NEVER
                    && now.0.saturating_sub(slot.last_start) < policy.min_interval_ms()
                {
                    // The flap bound holds this trigger back. An idle
                    // slot's `next_due` is unused, so it marks the wait to
                    // count it once.
                    if slot.next_due != DEFERRED {
                        self.announce[index].next_due = DEFERRED;
                        bump(&mut self.announce_counters.rate_limited);
                    }
                    continue;
                }
                let slot = &mut self.announce[index];
                slot.requested = false;
                slot.remaining = policy.count();
                slot.next_due = now.0;
                slot.last_start = now.0;
                bump(&mut self.announce_counters.sequences);
            }
            let slot = self.announce[index];
            if slot.remaining != 0 && now.0 >= slot.next_due {
                return Some((
                    index,
                    ArpRequestAction {
                        egress: slot.interface,
                        source_mac: interface.mac,
                        source_ip: binding.address,
                        target_ip: binding.address,
                    },
                ));
            }
        }
        None
    }

    fn cancel_announce(&mut self, index: usize) {
        let slot = &mut self.announce[index];
        if slot.busy() {
            slot.requested = false;
            slot.remaining = 0;
            slot.next_due = 0;
            self.announce_busy -= 1;
            bump(&mut self.announce_counters.cancelled);
        }
    }

    fn announcement_committed(&mut self, index: usize, now: MonotonicMillis, interval: u64) {
        let slot = &mut self.announce[index];
        slot.remaining -= 1;
        slot.next_due = now.0.saturating_add(interval);
        if !slot.busy() {
            self.announce_busy -= 1;
        }
        bump(&mut self.announce_counters.sent);
    }

    /// The earliest time an interface's waiting or running announcement
    /// becomes due, for an idle wait; `None` when none waits.
    #[must_use]
    pub fn next_announcement_due(
        &self,
        snapshot: &ForwardingSnapshot<'_>,
    ) -> Option<MonotonicMillis> {
        if self.announce_busy == 0 {
            return None;
        }
        let min_interval = snapshot
            .arp
            .announce()
            .map_or(0, ArpAnnouncePolicy::min_interval_ms);
        self.announce
            .iter()
            .filter(|slot| slot.busy())
            .map(|slot| {
                if slot.remaining != 0 {
                    slot.next_due
                } else if slot.last_start == NEVER {
                    0
                } else {
                    slot.last_start.saturating_add(min_interval)
                }
            })
            .min()
            .map(MonotonicMillis)
    }
}

/// Sends at most one due ARP Announcement (RFC 5227 §2.3 format: an ARP
/// Request with sender IP = target IP = the interface's address, target
/// MAC zero, broadcast) into a backend-owned generated frame.
///
/// Returns `Ok(None)` when none is due. An allocation or build failure
/// keeps the Announcement due for a later tick.
pub fn execute_one_arp_announcement<I, T>(
    io: &mut I,
    runtime: &mut ResolutionRuntime<'_>,
    snapshot: &ForwardingSnapshot<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<Option<GeneratedArpReport<I::Error>>, ExecuteArpRequestError>
where
    I: GeneratedPacketIo,
    T: GeneratedTraceSink,
{
    if runtime.announce_busy == 0 {
        return Ok(None);
    }
    if !runtime.execution_time_valid(now) {
        trace.record_generated(GeneratedArpTrace::ClockRegression);
        return Err(ExecuteArpRequestError::ClockRegression);
    }
    let interval = snapshot
        .arp
        .announce()
        .map_or(ARP_ANNOUNCE_INTERVAL_MS, ArpAnnouncePolicy::interval_ms);
    let Some((index, action)) = runtime.due_announcement(snapshot, now) else {
        return Ok(None);
    };
    let mut batch = io.begin_generated(action.egress);
    let (allocation_error, build_error) = match allocate_arp_request(&mut batch, action) {
        Ok(()) => {
            runtime.announcement_committed(index, now, interval);
            trace.record_generated(GeneratedArpTrace::TxRequested {
                egress: action.egress,
                target: action.target_ip,
            });
            (None, None)
        }
        Err(ArpRequestGenerationError::Allocation(error)) => {
            trace.record_generated(GeneratedArpTrace::AllocationFailed(error));
            (Some(error), None)
        }
        Err(ArpRequestGenerationError::Build(error)) => {
            trace.record_generated(GeneratedArpTrace::BuildFailed(error));
            (None, Some::<ArpRequestBuildError>(error))
        }
    };
    let completion = batch.finish();
    trace.record_generated(GeneratedArpTrace::BatchCompleted {
        accepted: completion.accepted,
        rejected: completion.rejected,
    });
    Ok(Some(GeneratedArpReport {
        action,
        allocation_error,
        build_error,
        completion,
    }))
}

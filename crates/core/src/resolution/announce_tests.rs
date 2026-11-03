//! Unit tests of the RFC 5227 announcement slots (ARP-033..ARP-040): the
//! defense frame next to a running sequence and a flap-bound wait, retry
//! after `Unavailable` without holding other ports back, backend rejects,
//! the reload switch-off, the counters, and the slot rebind.

use super::*;
use crate::{
    ArpPolicy, GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketLease,
    GeneratedPacketSlot, GeneratedSlotCompletion, Interface, Ipv4Address, LocalIpv4Binding,
    ResolutionActionSlot, ResolutionPolicy, ResolutionStateSlot, Route,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const OTHER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x66]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);

/// A generated-frame backend: every egress in `unavailable` refuses
/// allocation, every committed frame of an egress in `rejecting` is
/// refused at TX, the others are accepted and recorded.
#[derive(Default)]
struct Io {
    unavailable: Vec<IfId>,
    rejecting: Vec<IfId>,
    sent: Vec<(IfId, Vec<u8>)>,
}

struct Batch<'a> {
    io: &'a mut Io,
    egress: IfId,
    completion: GeneratedBatchCompletion<()>,
}

struct Slot<'a> {
    bytes: Vec<u8>,
    egress: IfId,
    reject: bool,
    sent: &'a mut Vec<(IfId, Vec<u8>)>,
    completion: &'a mut GeneratedBatchCompletion<()>,
}

impl GeneratedPacketSlot for Slot<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        match completion {
            GeneratedSlotCompletion::Transmit => {
                self.completion.requested += 1;
                if self.reject {
                    self.completion.rejected += 1;
                } else {
                    self.completion.accepted += 1;
                    self.sent.push((self.egress, self.bytes));
                }
            }
            GeneratedSlotCompletion::Cancelled => self.completion.cancelled += 1,
            GeneratedSlotCompletion::Abandoned => self.completion.abandoned += 1,
        }
    }
}

impl GeneratedPacketIo for Io {
    type Error = ();
    type Batch<'a> = Batch<'a>;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        Batch {
            io: self,
            egress,
            completion: GeneratedBatchCompletion {
                attempts: 0,
                allocated: 0,
                failed: 0,
                requested: 0,
                cancelled: 0,
                abandoned: 0,
                accepted: 0,
                rejected: 0,
                error: None,
            },
        }
    }
}

impl GeneratedPacketBatch for Batch<'_> {
    type Error = ();
    type Slot<'a>
        = Slot<'a>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.completion.attempts += 1;
        if self.io.unavailable.contains(&self.egress) {
            self.completion.failed += 1;
            return Err(GeneratedAllocationError::Unavailable);
        }
        self.completion.allocated += 1;
        Ok(GeneratedPacketLease::new(Slot {
            bytes: vec![0xa5; frame_len],
            egress: self.egress,
            reject: self.io.rejecting.contains(&self.egress),
            sent: &mut self.io.sent,
            completion: &mut self.completion,
        }))
    }

    fn check_capacity(
        &mut self,
        _frames: usize,
        _frame_len: usize,
    ) -> Result<(), GeneratedAllocationError> {
        Ok(())
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        self.completion
    }
}

fn interfaces() -> [Interface; 2] {
    [
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: 1500,
        },
    ]
}

fn routes() -> [Route; 2] {
    [
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap(),
    ]
}

fn bindings() -> [LocalIpv4Binding; 2] {
    [
        LocalIpv4Binding {
            interface: LAN,
            address: LAN_IP,
        },
        LocalIpv4Binding {
            interface: WAN,
            address: WAN_IP,
        },
    ]
}

/// Runs the announcement part of one generated ARP phase at `now` (at
/// most 8 frames) and returns the egress of every frame accepted.
fn tick(
    io: &mut Io,
    runtime: &mut ResolutionRuntime<'_>,
    snapshot: &ForwardingSnapshot<'_>,
    now: u64,
) -> Vec<IfId> {
    io.sent.clear();
    for _ in 0..8 {
        let report = execute_one_arp_announcement(
            io,
            runtime,
            snapshot,
            MonotonicMillis(now),
            &mut crate::NoGeneratedTrace,
        )
        .expect("clock");
        if report.is_none() {
            break;
        }
    }
    io.sent.iter().map(|(egress, _)| *egress).collect()
}

/// A conflicting ARP packet for `interface`'s address at `now`.
fn conflict(
    runtime: &mut ResolutionRuntime<'_>,
    snapshot: &ForwardingSnapshot<'_>,
    interface: IfId,
    now: u64,
) {
    runtime.observe_local_sender(snapshot, interface, OTHER_MAC, MonotonicMillis(now));
}

macro_rules! world {
    ($runtime:ident, $snapshot:ident, $arp:expr) => {
        let (routes, interfaces, bindings) = (routes(), interfaces(), bindings());
        let $snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings)
            .unwrap()
            .with_arp_policy($arp);
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 2];
        let mut slots = [ArpAnnounceSlot::EMPTY; 2];
        let mut $runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 3_000).unwrap(),
            &mut states,
            &mut actions,
        )
        .with_announce_slots(&mut slots, &$snapshot);
    };
}

#[test]
fn the_slot_is_48_bytes() {
    assert_eq!(std::mem::size_of::<ArpAnnounceSlot>(), 48);
}

/// §2.4 (c) during a §2.3 sequence: the defense is one extra frame at once
/// and the sequence keeps ANNOUNCE_INTERVAL (its second frame at 2 s, not
/// pulled forward).
#[test]
fn a_defense_during_a_sequence_is_an_extra_frame_and_keeps_the_interval() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io::default();
    runtime.request_announcements(&snapshot, Some(LAN));
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 0), [LAN]);
    conflict(&mut runtime, &snapshot, LAN, 500);
    assert_eq!(
        tick(&mut io, &mut runtime, &snapshot, 500),
        [LAN],
        "defense"
    );
    assert!(tick(&mut io, &mut runtime, &snapshot, 1_999).is_empty());
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 2_000), [LAN]);
    assert!(tick(&mut io, &mut runtime, &snapshot, 9_000).is_empty());
    assert_eq!(runtime.pending_announcements(), 0);
    let counters = runtime.announce_counters();
    assert_eq!(
        (counters.sequences, counters.defended, counters.committed),
        (1, 1, 3)
    );
}

/// A defense while a trigger waits for the minimum interval is sent at
/// once; the trigger still waits for the interval, counted
/// `rate_limited` once, and a second conflict within DEFEND_INTERVAL is
/// not defended.
#[test]
fn a_defense_during_a_flap_bound_wait_is_sent_and_the_wait_holds() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io::default();
    runtime.request_announcements(&snapshot, Some(LAN));
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 0), [LAN]);
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 2_000), [LAN]);
    runtime.request_announcements(&snapshot, Some(LAN));
    assert!(tick(&mut io, &mut runtime, &snapshot, 3_000).is_empty());
    conflict(&mut runtime, &snapshot, LAN, 4_000);
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 4_000), [LAN]);
    assert!(tick(&mut io, &mut runtime, &snapshot, 5_000).is_empty());
    conflict(&mut runtime, &snapshot, LAN, 6_000);
    assert!(tick(&mut io, &mut runtime, &snapshot, 6_000).is_empty());
    assert!(tick(&mut io, &mut runtime, &snapshot, 9_999).is_empty());
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 10_000), [LAN]);
    let counters = runtime.announce_counters();
    assert_eq!(
        (
            counters.rate_limited,
            counters.defended,
            counters.defense_suppressed,
            counters.sequences
        ),
        (1, 1, 1, 2)
    );
    assert_eq!(
        runtime.address_conflicts().collect::<Vec<_>>(),
        [(LAN, 2), (WAN, 0)]
    );
}

/// A trigger on a slot that only owes a defense is a new trigger
/// (`requested`), not folded into one (`coalesced`).
#[test]
fn a_trigger_on_a_defense_only_slot_counts_as_requested() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    conflict(&mut runtime, &snapshot, WAN, 0);
    assert_eq!(runtime.request_announcements(&snapshot, Some(WAN)), 1);
    let counters = runtime.announce_counters();
    assert_eq!((counters.requested, counters.coalesced), (1, 0));
    // The defense first, then the sequence's first frame, same tick.
    assert_eq!(
        tick(&mut io_default(), &mut runtime, &snapshot, 0),
        [WAN, WAN]
    );
}

fn io_default() -> Io {
    Io::default()
}

/// `Unavailable` on one port holds only that port back, for
/// ARP_ANNOUNCE_RETRY_MS; the other port is sent in the same tick
/// (round robin), and the failed one later.
#[test]
fn unavailable_retries_after_the_delay_without_holding_other_ports_back() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io {
        unavailable: vec![LAN],
        ..Io::default()
    };
    runtime.request_announcements(&snapshot, None);
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 0), [WAN]);
    assert_eq!(runtime.announce_counters().unavailable, 1);
    assert_eq!(
        runtime.next_announcement_due(&snapshot),
        Some(MonotonicMillis(ARP_ANNOUNCE_RETRY_MS)),
        "the retry, not a past deadline"
    );
    io.unavailable.clear();
    assert!(tick(&mut io, &mut runtime, &snapshot, ARP_ANNOUNCE_RETRY_MS - 1).is_empty());
    assert_eq!(
        tick(&mut io, &mut runtime, &snapshot, ARP_ANNOUNCE_RETRY_MS),
        [LAN]
    );
    // The retried port keeps its own interval from its first frame.
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 2_000), [WAN]);
    assert_eq!(
        tick(
            &mut io,
            &mut runtime,
            &snapshot,
            2_000 + ARP_ANNOUNCE_RETRY_MS
        ),
        [LAN]
    );
}

/// A frame the backend refuses at TX is committed and rejected, not
/// accepted, and is not retried.
#[test]
fn a_rejected_announcement_counts_rejected_not_accepted() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io {
        rejecting: vec![LAN],
        ..Io::default()
    };
    runtime.request_announcements(&snapshot, Some(LAN));
    assert!(tick(&mut io, &mut runtime, &snapshot, 0).is_empty());
    let counters = runtime.announce_counters();
    assert_eq!(
        (counters.committed, counters.accepted, counters.rejected),
        (1, 0, 1)
    );
    io.rejecting.clear();
    assert!(tick(&mut io, &mut runtime, &snapshot, 1_000).is_empty());
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 2_000), [LAN]);
}

/// A reload to `announce = false` cancels a waiting trigger and the rest of
/// a running sequence at once; an owed defense is still sent.
#[test]
fn announce_off_by_reload_cancels_the_sequence_but_keeps_the_defense() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io::default();
    runtime.request_announcements(&snapshot, Some(LAN));
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 0), [LAN]);
    conflict(&mut runtime, &snapshot, LAN, 100);
    let (routes, interfaces, bindings) = (routes(), interfaces(), bindings());
    let off = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings)
        .unwrap()
        .with_arp_policy(ArpPolicy::RFC826.with_announce(None));
    assert_eq!(runtime.announce_changed_bindings(&snapshot, &off), 0);
    assert_eq!(runtime.announce_counters().cancelled, 1);
    assert_eq!(tick(&mut io, &mut runtime, &off, 100), [LAN], "the defense");
    assert!(tick(&mut io, &mut runtime, &off, 2_000).is_empty());
    assert_eq!(runtime.pending_announcements(), 0);
}

/// A publication that orders the interfaces differently keeps each slot's
/// state (conflict count, running sequence) with its interface.
#[test]
fn a_reordered_publication_keeps_each_slot_with_its_interface() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io::default();
    conflict(&mut runtime, &snapshot, WAN, 0);
    conflict(&mut runtime, &snapshot, WAN, 1);
    runtime.request_announcements(&snapshot, Some(WAN));
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 0), [WAN, WAN]);
    let (routes, bindings) = (routes(), bindings());
    let [lan, wan] = interfaces();
    let reordered = [wan, lan];
    let next = ForwardingSnapshot::new(&routes, &reordered, &[], &bindings).unwrap();
    runtime.announce_changed_bindings(&snapshot, &next);
    assert_eq!(
        runtime.address_conflicts().collect::<Vec<_>>(),
        [(WAN, 2), (LAN, 0)]
    );
    assert_eq!(runtime.pending_announcements(), 1);
    assert_eq!(tick(&mut io, &mut runtime, &next, 2_000), [WAN]);
    assert_eq!(runtime.pending_announcements(), 0);
}

/// The frame is the RFC 5227 §2.3 Announcement.
#[test]
fn the_frame_is_an_rfc_5227_announcement() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io::default();
    runtime.request_announcements(&snapshot, Some(WAN));
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 0), [WAN]);
    let frame = &io.sent[0].1;
    assert_eq!(frame.len(), 60);
    assert_eq!(frame[0..6], [0xff; 6]);
    assert_eq!(frame[6..12], WAN_MAC.0);
    assert_eq!(frame[12..22], [8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    assert_eq!(frame[22..28], WAN_MAC.0);
    assert_eq!(frame[28..32], WAN_IP.octets());
    assert_eq!(frame[32..38], [0; 6]);
    assert_eq!(frame[38..42], WAN_IP.octets());
    assert!(frame[42..].iter().all(|byte| *byte == 0));
}

/// A reload to `conflict-defense = false` drops an owed defense (#351
/// re-review L2): a switched-off feature owes nothing, so nothing stays
/// pending and nothing is sent.
#[test]
fn defense_off_by_reload_drops_an_owed_defense() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io::default();
    conflict(&mut runtime, &snapshot, LAN, 0);
    assert_eq!(runtime.pending_announcements(), 1);
    let (routes, interfaces, bindings) = (routes(), interfaces(), bindings());
    let off = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings)
        .unwrap()
        .with_arp_policy(ArpPolicy::RFC826.with_defend_conflicts(false));
    runtime.announce_changed_bindings(&snapshot, &off);
    assert_eq!(runtime.pending_announcements(), 0);
    assert_eq!(runtime.next_announcement_due(&off), None);
    assert_eq!(runtime.announce_counters().cancelled, 1);
    assert!(tick(&mut io, &mut runtime, &off, 0).is_empty());
    // A running sequence is not a defense: it goes on.
    runtime.request_announcements(&off, Some(WAN));
    conflict(&mut runtime, &off, WAN, 10);
    assert_eq!(
        tick(&mut io, &mut runtime, &off, 10),
        [WAN],
        "sequence only"
    );
}

/// ARP-040: a reload that switches one interface's overrides off cancels
/// only that interface's running sequence and drops only its owed defense
/// (the same semantics as the router-wide switches); the other interface
/// keeps both. Detection still counts on the switched-off interface.
#[test]
fn per_interface_switch_off_by_reload_cancels_only_that_interface() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io::default();
    runtime.request_announcements(&snapshot, None);
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 0), [LAN, WAN]);
    conflict(&mut runtime, &snapshot, LAN, 1_000);
    conflict(&mut runtime, &snapshot, WAN, 1_000);
    assert_eq!(runtime.pending_announcements(), 2);
    let (routes, interfaces, bindings) = (routes(), interfaces(), bindings());
    let overrides = [ArpInterfacePolicy {
        interface: WAN,
        announce: Some(false),
        conflict_defense: Some(false),
    }];
    let off = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings)
        .unwrap()
        .with_arp_interfaces(&overrides)
        .unwrap();
    assert!(off.announce_on(LAN).is_some() && off.defend_conflicts_on(LAN));
    assert!(off.announce_on(WAN).is_none() && !off.defend_conflicts_on(WAN));
    runtime.announce_changed_bindings(&snapshot, &off);
    // WAN: its sequence and its defense, both cancelled.
    assert_eq!(runtime.announce_counters().cancelled, 2);
    assert_eq!(runtime.pending_announcements(), 1);
    assert_eq!(tick(&mut io, &mut runtime, &off, 1_000), [LAN], "defense");
    assert_eq!(tick(&mut io, &mut runtime, &off, 2_000), [LAN], "sequence");
    assert_eq!(runtime.pending_announcements(), 0);
    // WAN still detects and counts, but neither defends nor announces.
    conflict(&mut runtime, &off, WAN, 20_000);
    assert_eq!(
        runtime.address_conflicts().collect::<Vec<_>>(),
        [(LAN, 1), (WAN, 2)]
    );
    assert_eq!(runtime.request_announcements(&off, Some(WAN)), 0);
    assert_eq!(runtime.pending_announcements(), 0);
    assert!(tick(&mut io, &mut runtime, &off, 20_000).is_empty());
}

/// ARP-040: an interface override switches announcements on where the
/// router-wide switch is off, with the router-wide timing (kept while
/// off); the other interface inherits off.
#[test]
fn an_override_switches_announcements_on_under_a_global_off() {
    let timing = ArpAnnouncePolicy::new(3, 1_000, 5_000).unwrap();
    let global = ArpPolicy::RFC826
        .with_announce_timing(timing, false)
        .with_defend_conflicts(false);
    assert_eq!(global.announce(), None);
    assert_eq!(global.announce_timing(), timing);
    let (routes, interfaces, bindings) = (routes(), interfaces(), bindings());
    let overrides = [ArpInterfacePolicy {
        interface: LAN,
        announce: Some(true),
        conflict_defense: None,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings)
        .unwrap()
        .with_arp_policy(global)
        .with_arp_interfaces(&overrides)
        .unwrap();
    assert_eq!(snapshot.announce_on(LAN), Some(timing));
    assert_eq!(snapshot.announce_on(WAN), None);
    assert!(!snapshot.defend_conflicts_on(LAN), "inherited");
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut slots = [ArpAnnounceSlot::EMPTY; 2];
    let mut runtime = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 3_000).unwrap(),
        &mut states,
        &mut actions,
    )
    .with_announce_slots(&mut slots, &snapshot);
    let mut io = Io::default();
    assert_eq!(runtime.request_announcements(&snapshot, None), 1);
    assert_eq!(runtime.announce_counters().disabled, 1);
    let mut sent = Vec::new();
    for now in (0..=4_000).step_by(500) {
        sent.extend(
            tick(&mut io, &mut runtime, &snapshot, now)
                .into_iter()
                .map(|id| (now, id)),
        );
    }
    assert_eq!(sent, [(0, LAN), (1_000, LAN), (2_000, LAN)]);
}

/// ARP-040: borrowed overrides must name known interfaces, once each,
/// sorted; the owner sorts and drops an override that overrides nothing.
#[test]
fn arp_interface_overrides_are_checked() {
    let (routes, interfaces, bindings) = (routes(), interfaces(), bindings());
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let policy = |interface| ArpInterfacePolicy {
        interface,
        announce: Some(false),
        conflict_defense: None,
    };
    assert_eq!(std::mem::size_of::<ArpInterfacePolicy>(), 4);
    assert_eq!(
        snapshot.with_arp_interfaces(&[policy(IfId(9))]).err(),
        Some(crate::SnapshotError::ArpInterfaceUnknownInterface)
    );
    assert_eq!(
        snapshot
            .with_arp_interfaces(&[policy(LAN), policy(LAN)])
            .err(),
        Some(crate::SnapshotError::DuplicateArpInterface)
    );
    assert_eq!(
        snapshot
            .with_arp_interfaces(&[policy(WAN), policy(LAN)])
            .err(),
        Some(crate::SnapshotError::ArpInterfaceUnsorted)
    );
    let owner = crate::ValidatedForwardingOwner::new(
        routes.into(),
        interfaces.into(),
        Box::default(),
        bindings.into(),
        crate::Ipv4OriginPolicy::default(),
    )
    .unwrap()
    .with_arp_interfaces(&[
        policy(WAN),
        ArpInterfacePolicy {
            interface: LAN,
            announce: None,
            conflict_defense: None,
        },
    ])
    .unwrap();
    assert_eq!(owner.arp_interfaces(), [policy(WAN)]);
    assert_eq!(owner.snapshot().arp_interface_policies(), [policy(WAN)]);
    assert!(owner.snapshot().announce_on(WAN).is_none());
    assert!(owner.snapshot().announce_on(LAN).is_some());
}

/// A port whose generated frames keep failing backs off exponentially
/// from ARP_ANNOUNCE_RETRY_MS (10, 20, 40, ... ms) up to
/// ARP_ANNOUNCE_RETRY_MAX_MS, and a committed frame resets the backoff.
#[test]
fn unavailable_retries_back_off_exponentially_up_to_the_cap() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io {
        unavailable: vec![LAN],
        ..Io::default()
    };
    runtime.request_announcements(&snapshot, Some(LAN));
    let mut now = 0;
    let mut delays = Vec::new();
    for _ in 0..9 {
        assert!(tick(&mut io, &mut runtime, &snapshot, now).is_empty());
        let due = runtime
            .next_announcement_due(&snapshot)
            .expect("still owed")
            .0;
        delays.push(due - now);
        // Nothing before the retry.
        assert!(tick(&mut io, &mut runtime, &snapshot, due - 1).is_empty());
        now = due;
    }
    assert_eq!(delays, [10, 20, 40, 80, 160, 320, 640, 1_000, 1_000]);
    assert_eq!(runtime.announce_counters().unavailable, 9);
    io.unavailable.clear();
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, now), [LAN]);
    // Reset: the next failure waits 10 ms again.
    io.unavailable.push(LAN);
    let next = now + 2_000;
    assert!(tick(&mut io, &mut runtime, &snapshot, next).is_empty());
    assert_eq!(
        runtime.next_announcement_due(&snapshot),
        Some(MonotonicMillis(next + ARP_ANNOUNCE_RETRY_MS))
    );
}

/// Fails the port's frames at 0, 10, 30, and 70 ms: its next retry is at
/// 150 ms.
fn back_off_to_150(
    io: &mut Io,
    runtime: &mut ResolutionRuntime<'_>,
    snapshot: &ForwardingSnapshot<'_>,
) {
    for now in [0, 10, 30, 70] {
        assert!(tick(io, runtime, snapshot, now).is_empty());
    }
    assert_eq!(
        runtime.next_announcement_due(snapshot),
        Some(MonotonicMillis(150))
    );
}

/// A fresh trigger on a slot that only owes a (backing-off) defense is not
/// delayed by that backoff (#352 review L-1): the defense and the first
/// Announcement go out at once.
#[test]
fn a_fresh_trigger_resets_the_retry_backoff() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io {
        unavailable: vec![LAN],
        ..Io::default()
    };
    conflict(&mut runtime, &snapshot, LAN, 0);
    back_off_to_150(&mut io, &mut runtime, &snapshot);
    io.unavailable.clear();
    assert!(
        tick(&mut io, &mut runtime, &snapshot, 100).is_empty(),
        "backing off"
    );
    assert_eq!(runtime.request_announcements(&snapshot, Some(LAN)), 1);
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 100), [LAN, LAN]);
}

/// A new defense is not delayed by the backoff of a failing sequence
/// (#352 review L-1).
#[test]
fn a_new_defense_resets_the_retry_backoff() {
    world!(runtime, snapshot, ArpPolicy::RFC826);
    let mut io = Io {
        unavailable: vec![LAN],
        ..Io::default()
    };
    runtime.request_announcements(&snapshot, Some(LAN));
    back_off_to_150(&mut io, &mut runtime, &snapshot);
    io.unavailable.clear();
    assert!(
        tick(&mut io, &mut runtime, &snapshot, 100).is_empty(),
        "backing off"
    );
    conflict(&mut runtime, &snapshot, LAN, 100);
    assert_eq!(tick(&mut io, &mut runtime, &snapshot, 100), [LAN, LAN]);
    assert_eq!(runtime.announce_counters().defended, 1);
}

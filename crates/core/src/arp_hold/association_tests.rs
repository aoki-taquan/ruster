//! The fragment association accessors ARP-HOLD uses (`hold_first`,
//! `deny_pending`, `held_for`) and the commit-time eviction of a first
//! fragment's victims, against a real `Ipv4FragmentTracker`. Frames are
//! built here from the RFC 791 layout.

use crate::ipv4_fragment_tracking::{parse_fragment, Ipv4FragmentInfo};
use crate::{
    internet_checksum, ipv4_fragment_slot_bytes, ipv4_fragment_tracking_buckets,
    ipv4_fragment_tracking_tombstones, packet, DirectoryBucket, DirectoryNode, DropReason, IfId,
    Ipv4FragmentEntrySlot, Ipv4FragmentHeldSlot, Ipv4FragmentHostSlot, Ipv4FragmentTombstoneSlot,
    Ipv4FragmentTracker, Ipv4FragmentTrackingPolicy, Ipv4FragmentTrackingStorage,
    ResolutionHashKey,
};

const LAN: IfId = IfId(1);
const MF: u16 = 0x2000;

/// Ethernet + IPv4 UDP fragment from 10.0.0.`host` with `id`, the flags
/// and offset `word`, and `data_len` data bytes.
fn fragment(host: u8, id: u16, word: u16, data_len: usize) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 10, 0x08, 0x00];
    let mut header = [0_u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&u16::try_from(20 + data_len).unwrap().to_be_bytes());
    header[4..6].copy_from_slice(&id.to_be_bytes());
    header[6..8].copy_from_slice(&word.to_be_bytes());
    header[8] = 64;
    header[9] = 17;
    header[12..16].copy_from_slice(&[10, 0, 0, host]);
    header[16..20].copy_from_slice(&[198, 51, 100, 9]);
    let checksum = internet_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend((0..data_len).map(|i| i as u8));
    frame
}

fn info(frame: &[u8]) -> Ipv4FragmentInfo {
    let ipv4 = packet::validate_ipv4_frame(frame).unwrap();
    parse_fragment(frame, ipv4, LAN).unwrap()
}

fn tracker(entries: usize) -> Ipv4FragmentTracker<'static> {
    let buckets = ipv4_fragment_tracking_buckets(entries);
    let tombstones = ipv4_fragment_tracking_tombstones(entries);
    let held = 8;
    Ipv4FragmentTracker::new(
        Ipv4FragmentTrackingPolicy::new(1_000, 8, 8)
            .unwrap()
            .with_ingress_share_percent(100)
            .unwrap(),
        Ipv4FragmentTrackingStorage {
            entries: Vec::leak(vec![Ipv4FragmentEntrySlot::EMPTY; entries]),
            entry_buckets: Vec::leak(vec![DirectoryBucket::default(); buckets]),
            entry_nodes: Vec::leak(vec![DirectoryNode::default(); entries]),
            hosts: Vec::leak(vec![Ipv4FragmentHostSlot::EMPTY; entries]),
            host_buckets: Vec::leak(vec![DirectoryBucket::default(); buckets]),
            host_nodes: Vec::leak(vec![DirectoryNode::default(); entries]),
            tombstones: Vec::leak(vec![Ipv4FragmentTombstoneSlot::EMPTY; tombstones]),
            tombstone_buckets: Vec::leak(vec![
                DirectoryBucket::default();
                ipv4_fragment_tracking_buckets(tombstones)
            ]),
            tombstone_nodes: Vec::leak(vec![DirectoryNode::default(); tombstones]),
            held: Vec::leak(vec![Ipv4FragmentHeldSlot::EMPTY; held]),
            held_bytes: Vec::leak(vec![0; held * ipv4_fragment_slot_bytes(1500)]),
        },
        ResolutionHashKey::new(7, 9).unwrap(),
    )
    .unwrap()
}

/// Holds the later fragment (offset 16 bytes) of datagram (`host`, `id`).
fn hold_later(tracker: &mut Ipv4FragmentTracker<'_>, host: u8, id: u16, now: u64) {
    let frame = fragment(host, id, 2, 8);
    let follow = tracker.follow(info(&frame), &frame, frame.len(), now);
    assert!(follow.is_ok(), "{follow:?}");
}

#[test]
fn a_held_first_fragment_takes_or_keeps_a_pending_entry() {
    let mut tracker = tracker(4);
    let first = info(&fragment(10, 1, MF, 16));
    // No entry yet: one is taken (nothing to evict).
    let ticket = tracker.admit_first(first, 0).unwrap();
    let (index, generation) = tracker.hold_first(ticket, 0).unwrap();
    assert_eq!(tracker.entries(), 1);
    // Its later fragment joins that entry.
    hold_later(&mut tracker, 10, 1, 1);
    assert_eq!((tracker.held(), tracker.held_for(first)), (1, 1));
    // Held again (a retransmission): the same entry.
    let ticket = tracker.admit_first(first, 2).unwrap();
    assert_eq!(tracker.hold_first(ticket, 2), Some((index, generation)));
    // Denied while still that entry: the held fragment goes.
    assert!(tracker.deny_pending(index, generation, first, 0, 3));
    assert_eq!((tracker.held(), tracker.held_for(first)), (0, 0));
    let counters = tracker.counters();
    assert_eq!((counters.first_denied, counters.held_denied), (1, 1));
    // It is no longer pending: a second deny does nothing.
    assert!(!tracker.deny_pending(index, generation, first, 0, 3));
    assert_eq!(tracker.counters().first_denied, 1);
    tracker.check_invariants().unwrap();
}

#[test]
fn deny_pending_without_an_entry_does_nothing() {
    let mut tracker = tracker(4);
    let first = info(&fragment(10, 9, MF, 16));
    assert!(!tracker.deny_pending(0, 1, first, 0, 0));
    assert!(!tracker.deny_pending(99, 1, first, 0, 0), "out of range");
    assert_eq!(tracker.entries(), 0);
    assert_eq!(tracker.counters().first_denied, 0);
    tracker.check_invariants().unwrap();
}

#[test]
fn deny_pending_never_touches_a_decided_entry() {
    let mut tracker = tracker(4);
    let first = info(&fragment(10, 2, MF, 16));
    let ticket = tracker.admit_first(first, 0).unwrap();
    let (index, generation) = tracker.hold_first(ticket, 0).unwrap();
    // The replay decided it (refused here).
    let ticket = tracker.admit_first(first, 1).unwrap();
    tracker.commit_deny(ticket, 1);
    assert!(!tracker.deny_pending(index, generation, first, 0, 2));
    // Not poisoned: a byte-identical duplicate is still only a duplicate.
    assert_eq!(
        tracker.admit_first(first, 3),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    let counters = tracker.counters();
    assert_eq!((counters.poisoned, counters.duplicate_first), (0, 1));
    tracker.check_invariants().unwrap();
}

/// Review #342 M1: the held datagram's entry expires and a newer datagram
/// reusing its key (the ID wrapped) takes the same slot: the deny of the
/// dropped first fragment must not refuse the newer datagram.
#[test]
fn deny_pending_spares_a_newer_datagram_reusing_the_key() {
    let mut tracker = tracker(1);
    let first = info(&fragment(10, 3, MF, 16));
    let ticket = tracker.admit_first(first, 0).unwrap();
    let (index, generation) = tracker.hold_first(ticket, 0).unwrap();
    // The newer datagram's later fragment, after the old entry's timeout.
    hold_later(&mut tracker, 10, 3, 1_500);
    assert_eq!(tracker.entries(), 1);
    assert_eq!(tracker.held_for(first), 1);
    assert!(!tracker.deny_pending(index, generation, first, 0, 1_600));
    assert_eq!(tracker.held_for(first), 1, "the newer datagram keeps it");
    assert_eq!(tracker.counters().first_denied, 0);
    tracker.check_invariants().unwrap();
}

/// #341 re-review L4: admitting a first fragment plans its room but evicts
/// only when it commits, so a first fragment that ends ARP-held (no commit)
/// evicts nothing, and a held one takes an entry only when that needs no
/// eviction.
#[test]
fn a_first_fragment_evicts_only_at_its_commit() {
    let mut tracker = tracker(1);
    // Another datagram's pending entry fills the table.
    hold_later(&mut tracker, 20, 7, 0);
    assert_eq!((tracker.entries(), tracker.held()), (1, 1));
    let first = info(&fragment(10, 4, MF, 16));
    let ticket = tracker.admit_first(first, 1).unwrap();
    assert_eq!(
        (tracker.entries(), tracker.held()),
        (1, 1),
        "nothing evicted"
    );
    assert_eq!(
        tracker.hold_first(ticket, 1),
        None,
        "it would need an eviction"
    );
    assert_eq!((tracker.entries(), tracker.held()), (1, 1));
    assert_eq!(tracker.counters().entries_evicted, 0);
    // Committed (refused), it evicts and takes the entry.
    tracker.commit_deny(ticket, 2);
    assert_eq!((tracker.entries(), tracker.held()), (1, 0));
    assert_eq!(tracker.counters().entries_evicted, 1);
    tracker.check_invariants().unwrap();
}

/// #342 re-review core L2: however long the hold lasts, an entry created
/// after it is never denied, even when its creation stamp (16 bits of
/// milliseconds) matches the recorded one.
#[test]
fn deny_pending_spares_an_entry_created_after_the_hold_with_the_same_stamp() {
    let mut tracker = tracker(1);
    let first = info(&fragment(10, 5, MF, 16));
    let ticket = tracker.admit_first(first, 0).unwrap();
    let (index, generation) = tracker.hold_first(ticket, 0).unwrap();
    // 65.536 s later (the old entry long expired), a newer datagram on the
    // key takes the same slot with the same stamp.
    hold_later(&mut tracker, 10, 5, 65_536);
    assert_eq!(tracker.pending_for(first), Some((index, generation, 1)));
    assert!(!tracker.deny_pending(index, generation, first, 0, 65_600));
    assert_eq!(tracker.held_for(first), 1);
    tracker.check_invariants().unwrap();
}

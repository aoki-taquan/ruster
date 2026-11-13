//! Unit tests of the fragment association table (NAT-FRAG). Frames and
//! checksums are built here from the RFC 791 layout, not with the
//! production helpers; the forwarding composition is tested end to end in
//! `crates/io-sim/tests/nat_frag.rs`.

use super::*;
use crate::{
    GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo,
    GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, Interface, Ipv4Address,
    Ipv4FragmentSlot, Ipv4FragmentationPolicy, LocalIpv4Binding, MacAddress, Neighbor, Route,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const SOURCE: [u8; 4] = [10, 0, 0, 10];
const DESTINATION: [u8; 4] = [198, 51, 100, 9];
const MF: u16 = 0x2000;
const DF: u16 = 0x4000;

/// RFC 1071 one's-complement sum, written independently of `checksum.rs`.
fn reference_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in header.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ethernet II + 20-byte IPv4 header (`protocol`, ID `id`, TTL `ttl`,
/// SOURCE -> DESTINATION) + `data_len` pattern bytes.
fn fragment(id: u16, word: u16, ttl: u8, protocol: u8, data_len: usize) -> Vec<u8> {
    fragment_from(SOURCE, id, word, ttl, protocol, data_len)
}

fn fragment_from(
    source: [u8; 4],
    id: u16,
    word: u16,
    ttl: u8,
    protocol: u8,
    data_len: usize,
) -> Vec<u8> {
    let total = 20 + data_len;
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 10, 0x08, 0x00];
    let mut header = [0_u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    header[4..6].copy_from_slice(&id.to_be_bytes());
    header[6..8].copy_from_slice(&word.to_be_bytes());
    header[8] = ttl;
    header[9] = protocol;
    header[12..16].copy_from_slice(&source);
    header[16..20].copy_from_slice(&DESTINATION);
    let checksum = reference_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend((0..data_len).map(|i| (i * 11 + 5) as u8));
    frame
}

fn info(frame: &[u8]) -> Ipv4FragmentInfo {
    let ipv4 = packet::validate_ipv4_frame(frame).unwrap();
    parse_fragment(frame, ipv4, LAN).unwrap()
}

/// The template a forwarded first fragment leaves: toward WAN, translated
/// to 203.0.113.10, ID 0xbeef, `header` transport bytes.
fn template(header: u8) -> Ipv4FragmentTemplate {
    Ipv4FragmentTemplate {
        egress: WAN,
        macs: [2, 0, 0, 0, 0, 0xfe, 2, 0, 0, 0, 0, 2],
        source: [203, 0, 113, 10],
        destination: DESTINATION,
        id: 0xbeef,
        transport_header_len: header,
        keeps_ttl: false,
    }
}

struct Storage {
    entries: Vec<Ipv4FragmentEntrySlot>,
    entry_buckets: Vec<DirectoryBucket>,
    entry_nodes: Vec<DirectoryNode>,
    hosts: Vec<Ipv4FragmentHostSlot>,
    host_buckets: Vec<DirectoryBucket>,
    host_nodes: Vec<DirectoryNode>,
    tombstones: Vec<Ipv4FragmentTombstoneSlot>,
    tombstone_buckets: Vec<DirectoryBucket>,
    tombstone_nodes: Vec<DirectoryNode>,
    held: Vec<Ipv4FragmentHeldSlot>,
    held_bytes: Vec<u8>,
}

impl Storage {
    fn new(entries: usize, held: usize, held_slot: usize) -> Self {
        let buckets = ipv4_fragment_tracking_buckets(entries);
        let tombstones = ipv4_fragment_tracking_tombstones(entries);
        Self {
            entries: vec![Ipv4FragmentEntrySlot::EMPTY; entries],
            entry_buckets: vec![DirectoryBucket::default(); buckets],
            entry_nodes: vec![DirectoryNode::default(); entries],
            hosts: vec![Ipv4FragmentHostSlot::EMPTY; entries],
            host_buckets: vec![DirectoryBucket::default(); buckets],
            host_nodes: vec![DirectoryNode::default(); entries],
            tombstones: vec![Ipv4FragmentTombstoneSlot::EMPTY; tombstones],
            tombstone_buckets: vec![
                DirectoryBucket::default();
                ipv4_fragment_tracking_buckets(tombstones)
            ],
            tombstone_nodes: vec![DirectoryNode::default(); tombstones],
            held: vec![Ipv4FragmentHeldSlot::EMPTY; held],
            held_bytes: vec![0; held * held_slot],
        }
    }

    fn borrow(&mut self) -> Ipv4FragmentTrackingStorage<'_> {
        Ipv4FragmentTrackingStorage {
            entries: &mut self.entries,
            entry_buckets: &mut self.entry_buckets,
            entry_nodes: &mut self.entry_nodes,
            hosts: &mut self.hosts,
            host_buckets: &mut self.host_buckets,
            host_nodes: &mut self.host_nodes,
            tombstones: &mut self.tombstones,
            tombstone_buckets: &mut self.tombstone_buckets,
            tombstone_nodes: &mut self.tombstone_nodes,
            held: &mut self.held,
            held_bytes: &mut self.held_bytes,
        }
    }
}

fn key() -> ResolutionHashKey {
    ResolutionHashKey::new(7, 9).unwrap()
}

/// A policy without the ingress partition (one ingress in most tests; the
/// partition has its own test).
fn policy(timeout: u32, entries_per_host: u32, held_per_host: u32) -> Ipv4FragmentTrackingPolicy {
    Ipv4FragmentTrackingPolicy::new(timeout, entries_per_host, held_per_host)
        .unwrap()
        .with_ingress_share_percent(100)
        .unwrap()
}

fn snapshot(wan_mtu: u16) -> ForwardingSnapshot<'static> {
    let interfaces: &'static [Interface] = Box::leak(Box::new([
        Interface {
            id: LAN,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: wan_mtu,
        },
    ]));
    let routes: &'static [Route] = Box::leak(Box::new([Route::new(
        Ipv4Address::from_octets([0; 4]),
        0,
        WAN,
        None,
    )
    .unwrap()]));
    let neighbors: &'static [Neighbor] = Box::leak(Box::new([]));
    let bindings: &'static [LocalIpv4Binding] = Box::leak(Box::new([]));
    ForwardingSnapshot::new(routes, interfaces, neighbors, bindings).unwrap()
}

fn fragmentation(slots: usize) -> Ipv4FragmentationRuntime<'static> {
    Ipv4FragmentationRuntime::new(
        Ipv4FragmentationPolicy::DEFAULT,
        Vec::leak(vec![Ipv4FragmentSlot::EMPTY; slots]),
        Vec::leak(vec![0; slots * crate::ipv4_fragment_slot_bytes(1500)]),
    )
    .unwrap()
}

/// A generated session that records every committed frame.
#[derive(Default)]
struct Recorder {
    frames: Vec<(IfId, Vec<u8>)>,
}

struct RecorderBatch<'a> {
    recorder: &'a mut Recorder,
    egress: IfId,
    completion: GeneratedBatchCompletion<()>,
}

struct RecorderSlot<'a> {
    bytes: Vec<u8>,
    egress: IfId,
    recorder: &'a mut Recorder,
    completion: &'a mut GeneratedBatchCompletion<()>,
}

impl GeneratedPacketSlot for RecorderSlot<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        if completion == GeneratedSlotCompletion::Transmit {
            self.completion.requested += 1;
            self.completion.accepted += 1;
            self.recorder.frames.push((self.egress, self.bytes));
        } else {
            self.completion.cancelled += 1;
        }
    }
}

impl GeneratedPacketIo for Recorder {
    type Error = ();
    type Batch<'a> = RecorderBatch<'a>;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        RecorderBatch {
            recorder: self,
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

impl GeneratedPacketBatch for RecorderBatch<'_> {
    type Error = ();
    type Slot<'a>
        = RecorderSlot<'a>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.completion.attempts += 1;
        self.completion.allocated += 1;
        Ok(GeneratedPacketLease::new(RecorderSlot {
            bytes: vec![0; frame_len],
            egress: self.egress,
            recorder: self.recorder,
            completion: &mut self.completion,
        }))
    }

    fn check_capacity(&mut self, _: usize, _: usize) -> Result<(), GeneratedAllocationError> {
        Ok(())
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        self.completion
    }
}

#[test]
fn policy_bounds_fail_closed() {
    for timeout in [0, 99, 60_001, u32::MAX] {
        assert_eq!(
            Ipv4FragmentTrackingPolicy::new(timeout, 1, 1),
            Err(Ipv4FragmentTrackingPolicyError::TimeoutOutOfRange)
        );
    }
    for timeout in [100, 5_000, 60_000] {
        let policy = Ipv4FragmentTrackingPolicy::new(timeout, 1, 0).unwrap();
        assert_eq!(policy.timeout_ms(), timeout);
        assert_eq!((policy.entries_per_host(), policy.held_per_host()), (1, 0));
    }
    assert_eq!(
        Ipv4FragmentTrackingPolicy::new(5_000, 0, 1),
        Err(Ipv4FragmentTrackingPolicyError::EntriesPerHostZero)
    );
}

#[test]
fn storage_shapes_are_checked() {
    let build = |storage: &mut Storage| {
        Ipv4FragmentTracker::new(policy(1_000, 1, 1), storage.borrow(), key()).map(|_| ())
    };
    assert_eq!(build(&mut Storage::new(4, 2, 1514)), Ok(()));
    assert_eq!(build(&mut Storage::new(3, 0, 0)), Ok(()));
    assert_eq!(
        build(&mut Storage::new(0, 0, 0)),
        Err(Ipv4FragmentTrackingStorageError::NoEntries)
    );
    let mut storage = Storage::new(4, 2, 1514);
    storage.hosts.pop();
    assert_eq!(
        build(&mut storage),
        Err(Ipv4FragmentTrackingStorageError::Shape)
    );
    let mut storage = Storage::new(4, 2, 1514);
    storage.entry_buckets.push(DirectoryBucket::default());
    assert_eq!(
        build(&mut storage),
        Err(Ipv4FragmentTrackingStorageError::Shape)
    );
    let mut storage = Storage::new(4, 2, 1514);
    storage.held_bytes.pop();
    assert_eq!(
        build(&mut storage),
        Err(Ipv4FragmentTrackingStorageError::HeldBytes)
    );
    // A held slot holds at least a minimum-MTU datagram.
    assert_eq!(
        build(&mut Storage::new(4, 2, 14 + 67)),
        Err(Ipv4FragmentTrackingStorageError::HeldBytes)
    );
    assert_eq!(build(&mut Storage::new(4, 2, 14 + 68)), Ok(()));
    assert_eq!(
        build(&mut Storage::new(4, 1, 14 + 65_536)),
        Err(Ipv4FragmentTrackingStorageError::HeldBytes)
    );
    let mut storage = Storage::new(4, 0, 0);
    storage.held_bytes.push(0);
    assert_eq!(
        build(&mut storage),
        Err(Ipv4FragmentTrackingStorageError::HeldBytes)
    );
    assert_eq!(ipv4_fragment_tracking_buckets(0), 0);
    assert_eq!(ipv4_fragment_tracking_buckets(1), 1);
    assert_eq!(ipv4_fragment_tracking_buckets(256), 256);
    assert_eq!(ipv4_fragment_tracking_buckets(257), 512);
}

#[test]
fn fragments_are_parsed_and_their_structure_checked() {
    assert_eq!(
        parse_fragment(
            &fragment(1, 0, 64, 17, 16),
            packet::validate_ipv4_frame(&fragment(1, 0, 64, 17, 16)).unwrap(),
            LAN
        ),
        None,
        "a whole datagram"
    );
    assert_eq!(
        parse_fragment(
            &fragment(1, DF, 64, 17, 16),
            packet::validate_ipv4_frame(&fragment(1, DF, 64, 17, 16)).unwrap(),
            LAN
        ),
        None
    );
    let first = info(&fragment(0x1234, MF | DF, 64, 17, 24));
    assert!(first.is_first() && first.more && first.dont_fragment);
    assert_eq!((first.offset, first.data_len), (0, 24));
    assert_eq!(first.key.id, 0x1234);
    assert_eq!(first.key.ingress, LAN);
    let last = info(&fragment(1, 3, 64, 17, 5));
    assert!(!last.is_first() && !last.more && !last.dont_fragment);
    assert_eq!((last.offset, last.data_len), (24, 5));
    assert_eq!(last.check_structure(), Ok(()), "the last may be odd");
    // MF: a multiple of 8 data bytes.
    assert_eq!(info(&fragment(1, MF, 64, 17, 8)).check_structure(), Ok(()));
    assert_eq!(
        info(&fragment(1, MF | 1, 64, 17, 12)).check_structure(),
        Err(DropReason::Ipv4FragmentMalformed)
    );
    assert_eq!(
        info(&fragment(1, 1, 64, 17, 0)).check_structure(),
        Err(DropReason::Ipv4FragmentMalformed),
        "no data"
    );
    // The data ends at most 65515 bytes into the datagram: the largest
    // offset (8190 * 8 = 65520) is over with any data, 8189 (65512) with
    // 3 bytes ends exactly at 65515 and with 4 one past.
    assert_eq!(
        info(&fragment(1, 8189, 64, 17, 3)).check_structure(),
        Ok(())
    );
    assert_eq!(
        info(&fragment(1, 8189, 64, 17, 4)).check_structure(),
        Err(DropReason::Ipv4FragmentMalformed)
    );
}

#[test]
fn the_static_overlap_rule_covers_the_smallest_transport_header() {
    // TCP: offsets 1 and 2 (8 and 16 bytes) start inside any TCP header,
    // 3 (24 bytes) is past the 20-byte minimum.
    for (offset, refused) in [(1, true), (2, true), (3, false)] {
        let checked = info(&fragment(1, offset, 64, 6, 8)).check_static_overlap();
        assert_eq!(
            checked.is_err(),
            refused,
            "TCP offset {offset}: {checked:?}"
        );
    }
    // UDP and ICMP headers are 8 bytes: any later fragment is past them.
    for protocol in [17, 1, 47] {
        assert_eq!(
            info(&fragment(1, 1, 64, protocol, 8)).check_static_overlap(),
            Ok(())
        );
    }
    assert_eq!(
        info(&fragment(1, MF, 64, 6, 8)).check_static_overlap(),
        Ok(()),
        "a first fragment is the header"
    );
}

#[test]
fn a_template_rewrites_a_later_fragment_like_its_first() {
    let mut frame = fragment(0x1111, 185, 9, 17, 40);
    let original = frame.clone();
    template(8).apply(&mut frame).unwrap();
    assert_eq!(frame[0..12], [2, 0, 0, 0, 0, 0xfe, 2, 0, 0, 0, 0, 2]);
    assert_eq!(frame[12..14], [0x08, 0x00]);
    assert_eq!(frame[18..20], [0xbe, 0xef], "the first fragment's ID");
    assert_eq!(frame[20..22], original[20..22], "flags and offset kept");
    assert_eq!(frame[22], 8, "TTL - 1");
    assert_eq!(frame[26..30], [203, 0, 113, 10]);
    assert_eq!(frame[30..34], DESTINATION);
    assert_eq!(reference_checksum(&frame[14..34]), 0);
    assert_eq!(frame[34..], original[34..], "data untouched");
    // TTL 1 is not forwarded (and the frame is not touched).
    let mut expiring = fragment(0x1111, 185, 1, 17, 40);
    let before = expiring.clone();
    assert_eq!(
        template(8).apply(&mut expiring),
        Err(DropReason::Ipv4TtlExpired)
    );
    assert_eq!(expiring, before);
    let mut short = vec![0; 33];
    assert_eq!(
        template(8).apply(&mut short),
        Err(DropReason::Ipv4HeaderTruncated)
    );
}

#[test]
fn a_template_is_captured_from_the_rewritten_first_fragment() {
    let mut udp = fragment(0x2222, MF, 63, 17, 16);
    udp[0..12].copy_from_slice(&[9, 9, 9, 9, 9, 9, 8, 8, 8, 8, 8, 8]);
    let captured = Ipv4FragmentTemplate::capture(&udp, WAN).unwrap();
    assert_eq!(captured.egress, WAN);
    assert_eq!(captured.macs, [9, 9, 9, 9, 9, 9, 8, 8, 8, 8, 8, 8]);
    assert_eq!(
        (captured.source, captured.destination),
        (SOURCE, DESTINATION)
    );
    assert_eq!(captured.id, 0x2222);
    assert_eq!(captured.transport_header_len(), 8);
    // TCP: the data offset of the first fragment's header (here 11 words).
    let mut tcp = fragment(0x3333, MF, 63, 6, 48);
    tcp[34 + 12] = 11 << 4;
    assert_eq!(
        Ipv4FragmentTemplate::capture(&tcp, WAN)
            .unwrap()
            .transport_header_len(),
        44
    );
    assert_eq!(Ipv4FragmentTemplate::capture(&tcp[..46], WAN), None);
    assert_eq!(Ipv4FragmentTemplate::capture(&udp[..33], WAN), None);
}

#[test]
fn first_fragments_take_an_entry_and_decided_ones_refuse_a_second_first() {
    let mut storage = Storage::new(4, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 2), storage.borrow(), key()).unwrap();
    let snapshot = snapshot(1500);
    let first = info(&fragment(1, MF, 64, 17, 16));
    let ticket = tracker.admit_first(first, 0).unwrap();
    assert_eq!(tracker.entries(), 0, "admission changes nothing");
    tracker.commit_allow(ticket, template(8), &snapshot, None, 0);
    assert_eq!(tracker.entries(), 1);
    assert_eq!(
        tracker.admit_first(first, 1),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    let denied = info(&fragment(2, MF, 64, 17, 16));
    let ticket = tracker.admit_first(denied, 0).unwrap();
    tracker.commit_deny(ticket, 0);
    assert_eq!(
        tracker.admit_first(denied, 1),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    // A later fragment follows its first fragment's decision.
    let later = info(&fragment(1, 2, 64, 17, 8));
    let frame = fragment(1, 2, 64, 17, 8);
    match tracker.follow(later, &frame, frame.len(), 1).unwrap() {
        Ipv4FragmentFollow::Allow { template: t, .. } => assert_eq!(t, template(8)),
        other => panic!("{other:?}"),
    }
    let refused = info(&fragment(2, 2, 64, 17, 8));
    assert_eq!(
        tracker.follow(refused, &frame, frame.len(), 1),
        Ok(Ipv4FragmentFollow::Deny)
    );
    let counters = tracker.counters();
    assert_eq!((counters.first_allowed, counters.first_denied), (1, 1));
    assert_eq!(counters.followed_denied, 1);
    // Another ingress is another datagram.
    let mut elsewhere = later;
    elsewhere.key.ingress = WAN;
    assert_eq!(
        tracker.follow(elsewhere, &frame, frame.len(), 1),
        Ok(Ipv4FragmentFollow::Held)
    );
}

#[test]
fn a_later_fragment_inside_the_first_fragments_header_is_refused() {
    let mut storage = Storage::new(4, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 2), storage.borrow(), key()).unwrap();
    let first = info(&fragment(1, MF, 64, 6, 48));
    let ticket = tracker.admit_first(first, 0).unwrap();
    tracker.commit_allow(ticket, template(40), &snapshot(1500), None, 0);
    for (offset, refused) in [(4, true), (5, false)] {
        let frame = fragment(1, offset, 64, 6, 8);
        let result = tracker.follow(info(&frame), &frame, frame.len(), 0);
        assert_eq!(
            result == Err(DropReason::Ipv4FragmentTransportHeaderOverlap),
            refused,
            "offset {offset}: {result:?}"
        );
    }
}

#[test]
fn completion_frees_an_entry_once_every_byte_passed() {
    let mut storage = Storage::new(4, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 2), storage.borrow(), key()).unwrap();
    let first = info(&fragment(1, MF, 64, 17, 16));
    let ticket = tracker.admit_first(first, 0).unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
    // The last fragment first (total known), then the middle one.
    let last = info(&fragment(1, 4, 64, 17, 5));
    let Ok(Ipv4FragmentFollow::Allow { entry, .. }) = tracker.follow(last, &[], 0, 0) else {
        panic!("allowed");
    };
    tracker.followed(entry);
    assert_eq!(tracker.entries(), 1, "16 + 5 of 37 bytes");
    let middle = info(&fragment(1, 2 | MF, 64, 17, 16));
    let Ok(Ipv4FragmentFollow::Allow { entry, .. }) = tracker.follow(middle, &[], 0, 0) else {
        panic!("allowed");
    };
    tracker.followed(entry);
    assert_eq!(tracker.entries(), 0);
    let counters = tracker.counters();
    assert_eq!((counters.followed, counters.entries_completed), (2, 1));
    // Without its last fragment an entry never completes.
    let ticket = tracker
        .admit_first(info(&fragment(2, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
    let middle = info(&fragment(2, 2 | MF, 64, 17, 1000));
    let Ok(Ipv4FragmentFollow::Allow { entry, .. }) = tracker.follow(middle, &[], 0, 0) else {
        panic!("allowed");
    };
    tracker.followed(entry);
    assert_eq!(tracker.entries(), 1);
}

#[test]
fn held_fragments_need_room_and_respect_the_host_limit() {
    let mut storage = Storage::new(4, 2, 14 + 100);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 1), storage.borrow(), key()).unwrap();
    let big = fragment(1, 1, 64, 17, 81);
    assert_eq!(
        tracker.follow(info(&big), &big, big.len(), 0),
        Err(DropReason::Ipv4FragmentHoldTooLarge)
    );
    let fits = fragment(1, 1, 64, 17, 80);
    assert_eq!(
        tracker.follow(info(&fits), &fits, fits.len(), 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    let second = fragment(1, 11, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&second), &second, second.len(), 0),
        Err(DropReason::Ipv4FragmentHostHoldLimit)
    );
    let other = fragment_from([10, 0, 0, 11], 1, 1, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&other), &other, other.len(), 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    // Every held slot taken: the oldest pending datagram (SOURCE's) is
    // evicted with what it holds.
    let third = fragment_from([10, 0, 0, 12], 1, 1, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&third), &third, third.len(), 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!((tracker.entries(), tracker.held()), (2, 2));
    let counters = tracker.counters();
    assert_eq!((counters.entries_evicted, counters.held_evicted), (1, 1));
    // No held slot at all: every early fragment is refused.
    let mut none = Storage::new(4, 0, 0);
    let mut tracker = Ipv4FragmentTracker::new(policy(1_000, 4, 4), none.borrow(), key()).unwrap();
    assert_eq!(
        tracker.follow(info(&fits), &fits, fits.len(), 0),
        Err(DropReason::Ipv4FragmentHoldFull)
    );
    assert_eq!(tracker.entries(), 0, "nothing taken for a refusal");
}

#[test]
fn entries_expire_oldest_first_and_free_room_for_new_ones() {
    let mut storage = Storage::new(2, 2, 1514);
    let mut tracker = Ipv4FragmentTracker::new(policy(100, 4, 4), storage.borrow(), key()).unwrap();
    let snapshot = snapshot(1500);
    for (id, at) in [(1, 0), (2, 10)] {
        let ticket = tracker
            .admit_first(info(&fragment(id, MF, 64, 17, 8)), at)
            .unwrap();
        tracker.commit_allow(ticket, template(8), &snapshot, None, at);
    }
    // Both allowing and younger than a fifth of the timeout: nothing to
    // evict.
    assert_eq!(
        tracker.admit_first(info(&fragment(3, MF, 64, 17, 8)), 19),
        Err(DropReason::Ipv4FragmentTableFull)
    );
    // At 100 ms the oldest has expired; the younger is still live.
    let ticket = tracker
        .admit_first(info(&fragment(3, MF, 64, 17, 8)), 100)
        .unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot, None, 100);
    assert_eq!(tracker.counters().entries_expired, 1);
    let later = fragment(2, 1, 64, 17, 8);
    assert!(matches!(
        tracker.follow(info(&later), &later, later.len(), 109),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
    let gone = fragment(1, 1, 64, 17, 8);
    // Datagram 1 is unknown again: held (it takes 2's expired entry).
    assert_eq!(
        tracker.follow(info(&gone), &gone, gone.len(), 110),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!(tracker.counters().entries_expired, 2);
    // A clock that goes back expires nothing.
    let third = fragment(3, 1, 64, 17, 8);
    assert!(matches!(
        tracker.follow(info(&third), &third, third.len(), 0),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
    assert_eq!(tracker.counters().entries_expired, 2);
}

#[test]
fn per_host_entries_are_counted_released_and_evicted() {
    let mut storage = Storage::new(4, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 2, 0), storage.borrow(), key()).unwrap();
    let snapshot = snapshot(1500);
    // Two allowing entries: at its limit the host has nothing to evict.
    for id in [1, 2] {
        allow(&mut tracker, id, 0);
    }
    assert_eq!(
        tracker.admit_first(info(&fragment(3, MF, 64, 17, 8)), 0),
        Err(DropReason::Ipv4FragmentHostLimit)
    );
    // Another source has its own limit.
    let other = fragment_from([10, 0, 0, 99], 3, MF, 64, 17, 8);
    let ticket = tracker.admit_first(info(&other), 0).unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot, None, 0);
    // Completing datagram 1 frees one of the host's entries.
    complete(&mut tracker, 1, SOURCE, 0);
    assert_eq!(tracker.entries(), 2);
    let ticket = tracker
        .admit_first(info(&fragment(3, MF, 64, 17, 8)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    // At the limit again, with a refusing entry: the next datagram evicts
    // it (oldest refusing first), never the allowing one.
    let ticket = tracker
        .admit_first(info(&fragment(4, MF, 64, 17, 8)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    assert_eq!(tracker.counters().entries_evicted, 1);
    let still = fragment(2, 2, 64, 17, 3);
    assert!(matches!(
        tracker.follow(info(&still), &still, still.len(), 0),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
    let evicted = fragment(3, 2, 64, 17, 3);
    assert_eq!(
        tracker.follow(info(&evicted), &evicted, evicted.len(), 0),
        Err(DropReason::Ipv4FragmentHoldFull),
        "datagram 3 is unknown again"
    );
}

#[test]
fn released_fragments_are_rewritten_and_staged_or_dropped() {
    let mut storage = Storage::new(4, 4, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    let mut fragmentation = fragmentation(8);
    let snapshot = snapshot(576);
    // Held: one within 576 bytes, one above it with DF clear (re-cut), one
    // above with DF set (dropped), and one with TTL 1 (dropped).
    let small = fragment(1, 70 | MF, 64, 17, 504);
    let large = fragment(1, 2 | MF, 64, 17, 800);
    let df = fragment(1, 200 | DF | MF, 64, 17, 800);
    let ttl = fragment(1, 400 | MF, 1, 17, 8);
    for frame in [&small, &large, &df, &ttl] {
        assert_eq!(
            tracker.follow(info(frame), frame, frame.len(), 0),
            Ok(Ipv4FragmentFollow::Held)
        );
    }
    let ticket = tracker
        .admit_first(info(&fragment(1, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot, Some(&mut fragmentation), 0);
    assert_eq!(tracker.held(), 0);
    let counters = tracker.counters();
    assert_eq!((counters.released, counters.release_dropped), (2, 2));
    assert_eq!(fragmentation.pending(), 2);
    let mut recorder = Recorder::default();
    while crate::execute_one_ipv4_fragmentation(&mut recorder, &mut fragmentation, &mut 64)
        .is_some()
    {}
    let frames = &recorder.frames;
    // The small one whole, the large one cut in two (552 + 248 bytes).
    assert_eq!(frames.len(), 3);
    let mut expected_small = small.clone();
    template(8).apply(&mut expected_small).unwrap();
    assert_eq!(frames[0], (WAN, expected_small));
    for (egress, frame) in &frames[1..] {
        assert_eq!(*egress, WAN);
        assert_eq!(frame[18..20], [0xbe, 0xef]);
        assert_eq!(frame[26..30], [203, 0, 113, 10]);
        assert_eq!(reference_checksum(&frame[14..34]), 0);
    }
    assert_eq!(frames[1].1.len(), 14 + 20 + 552);
    assert_eq!(frames[2].1.len(), 14 + 20 + 248);
    assert_eq!(fragmentation.counters().whole, 1);
    assert_eq!(fragmentation.counters().fragmented, 1);

    // Without a fragmentation runtime nothing can leave: dropped.
    let held = fragment(2, 2, 64, 17, 8);
    tracker.follow(info(&held), &held, held.len(), 0).unwrap();
    let ticket = tracker
        .admit_first(info(&fragment(2, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot, None, 0);
    assert_eq!(tracker.counters().release_dropped, 3);
}

#[test]
fn a_refused_first_fragment_discards_what_was_held() {
    let mut storage = Storage::new(4, 4, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    for word in [2 | MF, 4] {
        let frame = fragment(1, word, 64, 17, 16);
        tracker
            .follow(info(&frame), &frame, frame.len(), 0)
            .unwrap();
    }
    let ticket = tracker
        .admit_first(info(&fragment(1, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    assert_eq!(tracker.held(), 0);
    // 16 + 16 + 16 data bytes of 48: refused whole, the entry is done.
    assert_eq!(tracker.entries(), 0);
    let counters = tracker.counters();
    assert_eq!((counters.held, counters.held_denied), (2, 2));
}

#[test]
fn flush_discards_and_counts_everything_and_the_table_is_reusable() {
    let mut storage = Storage::new(2, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    let held = fragment(1, 2, 64, 17, 8);
    tracker.follow(info(&held), &held, held.len(), 0).unwrap();
    let ticket = tracker
        .admit_first(info(&fragment(2, MF, 64, 17, 8)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    let occupancy = tracker.occupancy();
    assert_eq!(occupancy.entries, TableOccupancy::new(2, 2, 2).unwrap());
    assert_eq!(occupancy.held, TableOccupancy::new(1, 1, 2).unwrap());
    tracker.flush();
    assert_eq!((tracker.entries(), tracker.held()), (0, 0));
    // OBS-017: a flush restarts both high-water marks.
    assert_eq!(
        tracker.occupancy(),
        Ipv4FragmentTrackingOccupancy {
            entries: TableOccupancy::new(0, 0, 2).unwrap(),
            held: TableOccupancy::new(0, 0, 2).unwrap(),
        }
    );
    let counters = tracker.counters();
    assert_eq!((counters.entries_flushed, counters.held_flushed), (2, 1));
    tracker.flush_with_key(ResolutionHashKey::new(1, 1).unwrap());
    assert_eq!(tracker.counters().entries_flushed, 2);
    // Every slot is free again.
    for id in [3, 4] {
        assert!(tracker
            .follow(info(&fragment(id, 2, 64, 17, 8)), &held, held.len(), 0)
            .is_ok());
    }
    assert_eq!((tracker.entries(), tracker.held()), (2, 2));
    let occupancy = tracker.occupancy();
    assert_eq!(occupancy.entries, TableOccupancy::new(2, 2, 2).unwrap());
    assert_eq!(occupancy.held, TableOccupancy::new(2, 2, 2).unwrap());
    assert_eq!(tracker.entry_capacity(), 2);
    assert_eq!(tracker.held_capacity(), 2);
    assert_eq!(tracker.policy(), policy(1_000, 4, 4));
}

// ------------------------------------------------ mutation follow-ups ----

/// Allows a first fragment of datagram `id` from SOURCE at `now` (UDP, 16
/// data bytes, more to come) and returns its entry.
fn allow(tracker: &mut Ipv4FragmentTracker<'_>, id: u16, now: u64) {
    let ticket = tracker
        .admit_first(info(&fragment(id, MF, 64, 17, 16)), now)
        .unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, now);
}

/// The last fragment of datagram `id` (offset 2, 5 bytes): completes an
/// allowed entry whose first fragment carried 16 bytes.
fn complete(tracker: &mut Ipv4FragmentTracker<'_>, id: u16, source: [u8; 4], now: u64) {
    let last = fragment_from(source, id, 2, 64, 17, 5);
    let Ok(Ipv4FragmentFollow::Allow { entry, .. }) =
        tracker.follow(info(&last), &last, last.len(), now)
    else {
        panic!("allowed");
    };
    tracker.followed(entry);
}

#[test]
fn a_template_applies_to_a_bare_header() {
    let mut frame = fragment(1, 3, 9, 17, 0);
    assert_eq!(frame.len(), 34);
    assert_eq!(template(8).apply(&mut frame), Ok(()));
    assert_eq!(reference_checksum(&frame[14..34]), 0);
}

#[test]
fn an_expired_entry_found_by_lookup_is_counted_with_its_held_fragments() {
    let mut storage = Storage::new(4, 4, 1514);
    let mut tracker = Ipv4FragmentTracker::new(policy(100, 4, 4), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 0);
    allow(&mut tracker, 2, 0);
    // The youngest holds two fragments.
    for word in [4 | MF, 6] {
        let frame = fragment(3, word, 64, 17, 16);
        tracker
            .follow(info(&frame), &frame, frame.len(), 0)
            .unwrap();
    }
    // At 100 ms the two oldest go by the bounded expiry, the third when the
    // lookup finds it.
    let later = fragment(3, 8, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&later), &later, later.len(), 100),
        Ok(Ipv4FragmentFollow::Held)
    );
    let counters = tracker.counters();
    assert_eq!((counters.entries_expired, counters.held_expired), (3, 2));
    assert_eq!((tracker.entries(), tracker.held()), (1, 1));
}

#[test]
fn freeing_a_middle_entry_keeps_the_age_and_free_lists() {
    let mut storage = Storage::new(3, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 8, 0), storage.borrow(), key()).unwrap();
    for (id, now) in [(1, 0), (2, 1), (3, 2)] {
        allow(&mut tracker, id, now);
    }
    // The middle one completes; the oldest and the youngest still expire
    // in order, and all three slots serve new entries.
    complete(&mut tracker, 2, SOURCE, 3);
    assert_eq!(tracker.entries(), 2);
    assert!(tracker
        .admit_first(info(&fragment(4, MF, 64, 17, 16)), 50)
        .is_ok());
    allow(&mut tracker, 4, 50);
    assert_eq!(
        tracker.admit_first(info(&fragment(5, MF, 64, 17, 16)), 99),
        Err(DropReason::Ipv4FragmentTableFull)
    );
    for id in [5, 6] {
        allow(&mut tracker, id, 1_002);
    }
    assert_eq!(tracker.counters().entries_expired, 2);
    assert_eq!(tracker.entries(), 3);
    // Free everything: every slot is reachable from the free list again.
    for id in [4, 5, 6] {
        complete(&mut tracker, id, SOURCE, 1_003);
    }
    assert_eq!(tracker.entries(), 0);
    for id in [7, 8, 9] {
        allow(&mut tracker, id, 1_004);
    }
    assert_eq!(tracker.entries(), 3);
}

#[test]
fn host_slots_are_released_and_reused_and_their_counts_kept() {
    let mut storage = Storage::new(2, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 2, 0), storage.borrow(), key()).unwrap();
    let other = [10, 0, 0, 77];
    let third = [10, 0, 0, 78];
    let first_from = |tracker: &mut Ipv4FragmentTracker<'_>, source: [u8; 4], id: u16| {
        let frame = fragment_from(source, id, MF, 64, 17, 16);
        let ticket = tracker.admit_first(info(&frame), 0)?;
        tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
        Ok::<(), DropReason>(())
    };
    // SOURCE takes both entries; completing one frees a slot for a third.
    first_from(&mut tracker, SOURCE, 1).unwrap();
    first_from(&mut tracker, SOURCE, 2).unwrap();
    complete(&mut tracker, 1, SOURCE, 0);
    first_from(&mut tracker, SOURCE, 3).unwrap();
    assert_eq!(
        first_from(&mut tracker, SOURCE, 4),
        Err(DropReason::Ipv4FragmentHostLimit)
    );
    complete(&mut tracker, 2, SOURCE, 0);
    complete(&mut tracker, 3, SOURCE, 0);
    // Both host slots are free again, for two other sources.
    first_from(&mut tracker, other, 5).unwrap();
    first_from(&mut tracker, third, 6).unwrap();
    assert_eq!(tracker.entries(), 2);

    // The per-host count survives a completion of another of its entries.
    let mut storage = Storage::new(4, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 2, 0), storage.borrow(), key()).unwrap();
    first_from(&mut tracker, SOURCE, 1).unwrap();
    first_from(&mut tracker, SOURCE, 2).unwrap();
    complete(&mut tracker, 1, SOURCE, 0);
    first_from(&mut tracker, SOURCE, 3).unwrap();
    assert_eq!(
        first_from(&mut tracker, SOURCE, 4),
        Err(DropReason::Ipv4FragmentHostLimit)
    );
}

#[test]
fn a_refusal_counts_the_held_data_toward_the_datagram_end() {
    for (held, total_known) in [
        // Only a middle fragment held: the end is still unknown.
        (vec![2 | MF], false),
        // Only the last (16 data bytes at 32): 48 bytes, 32 seen.
        (vec![4], false),
    ] {
        let mut storage = Storage::new(4, 4, 1514);
        let mut tracker =
            Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
        for word in &held {
            let frame = fragment(1, *word, 64, 17, 16);
            tracker
                .follow(info(&frame), &frame, frame.len(), 0)
                .unwrap();
        }
        let ticket = tracker
            .admit_first(info(&fragment(1, MF, 64, 17, 16)), 0)
            .unwrap();
        tracker.commit_deny(ticket, 0);
        assert_eq!(tracker.entries(), usize::from(!total_known), "{held:?}");
        assert_eq!(tracker.counters().entries_completed, 0, "{held:?}");
    }
}

#[test]
fn a_padded_later_fragment_is_held_without_its_padding() {
    let mut storage = Storage::new(4, 2, 14 + 100);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    // A 1-byte last fragment padded to the Ethernet minimum (60 bytes).
    let mut frame = fragment(1, 2, 64, 17, 1);
    let frame_len = frame.len();
    frame.resize(60, 0);
    assert_eq!(
        tracker.follow(info(&frame), &frame, frame_len, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
}

#[test]
fn release_refuses_fragments_inside_the_first_fragments_header_only() {
    let mut storage = Storage::new(4, 4, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    let mut fragmentation = fragmentation(4);
    // TCP: offset 24 passes the 20-byte minimum while held but is inside
    // the first fragment's 32-byte header; offset 32 is its first data.
    for word in [3 | MF, 4] {
        let frame = fragment(1, word, 64, 6, 8);
        assert_eq!(
            tracker.follow(info(&frame), &frame, frame.len(), 0),
            Ok(Ipv4FragmentFollow::Held)
        );
    }
    let ticket = tracker
        .admit_first(info(&fragment(1, MF, 64, 6, 24)), 0)
        .unwrap();
    tracker.commit_allow(
        ticket,
        template(32),
        &snapshot(1500),
        Some(&mut fragmentation),
        0,
    );
    let counters = tracker.counters();
    assert_eq!((counters.released, counters.release_dropped), (1, 1));
    let mut recorder = Recorder::default();
    while crate::execute_one_ipv4_fragmentation(&mut recorder, &mut fragmentation, &mut 64)
        .is_some()
    {}
    // The one sent is the fragment at offset 32 (4 blocks).
    assert_eq!(recorder.frames.len(), 1);
    assert_eq!(recorder.frames[0].1[20..22], [0, 4]);
}

#[test]
fn released_fragments_at_the_mtu_or_with_df_are_sent_whole() {
    let mut storage = Storage::new(4, 4, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    let mut fragmentation = fragmentation(4);
    // 576 - 20 = 556 is not a multiple of 8: exactly the MTU must stay one
    // frame (cutting would give 552 + 4). The DF one is within the MTU.
    let exact = fragment(1, 2, 64, 17, 556);
    let df = fragment(1, 1 | MF | DF, 64, 17, 8);
    for frame in [&exact, &df] {
        tracker.follow(info(frame), frame, frame.len(), 0).unwrap();
    }
    let ticket = tracker
        .admit_first(info(&fragment(1, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_allow(
        ticket,
        template(8),
        &snapshot(576),
        Some(&mut fragmentation),
        0,
    );
    assert_eq!(tracker.counters().released, 2);
    let mut recorder = Recorder::default();
    while crate::execute_one_ipv4_fragmentation(&mut recorder, &mut fragmentation, &mut 64)
        .is_some()
    {}
    let mut expected_exact = exact.clone();
    template(8).apply(&mut expected_exact).unwrap();
    let mut expected_df = df.clone();
    template(8).apply(&mut expected_df).unwrap();
    assert_eq!(recorder.frames, [(WAN, expected_exact), (WAN, expected_df)]);
    assert_eq!(fragmentation.counters().whole, 2);
}

// --------------------------------------------- review follow-ups (#337) ----

/// Follows a later fragment of `id` from SOURCE (offset in 8-byte blocks,
/// `len` data bytes, MF as given) and, when allowed, reports it forwarded.
fn pass(
    tracker: &mut Ipv4FragmentTracker<'_>,
    id: u16,
    word: u16,
    len: usize,
) -> Result<Ipv4FragmentFollow, DropReason> {
    let frame = fragment(id, word, 64, 17, len);
    let answer = tracker.follow(info(&frame), &frame, frame.len(), 0);
    if let Ok(Ipv4FragmentFollow::Allow { entry, .. }) = answer {
        tracker.followed(entry);
    }
    answer
}

#[test]
fn coverage_counts_duplicates_and_overlaps_once() {
    let mut storage = Storage::new(4, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 0), storage.borrow(), key()).unwrap();
    // 16 + 16 + 16 + 5 data bytes; the first fragment carries 16.
    allow(&mut tracker, 1, 0);
    // The last first: the end is 53.
    assert!(pass(&mut tracker, 1, 6, 5).is_ok());
    // The last again, then the third twice: 16 + 5 + 5 + 16 + 16 = 58
    // would have reached 53 when duplicates counted.
    assert!(pass(&mut tracker, 1, 6, 5).is_ok());
    assert!(pass(&mut tracker, 1, 4 | MF, 16).is_ok());
    assert!(pass(&mut tracker, 1, 4 | MF, 16).is_ok());
    assert_eq!(tracker.entries(), 1, "bytes 16..32 not seen yet");
    // An overlapping piece (8..24) does not fill the gap either.
    assert!(pass(&mut tracker, 1, 1 | MF, 16).is_ok());
    assert_eq!(tracker.entries(), 1, "bytes 24..32 not seen yet");
    assert!(pass(&mut tracker, 1, 2 | MF, 16).is_ok());
    assert_eq!(tracker.entries(), 0);
    assert_eq!(tracker.counters().entries_completed, 1);
}

#[test]
fn a_contradicting_end_poisons_the_entry() {
    for (first_last, then, malformed) in [
        // A second last fragment with another end.
        ((6, 5), (8, 5), true),
        // Data past the end.
        ((6, 5), (4 | MF, 24), true),
        // A last fragment that ends before data already seen.
        ((6 | MF, 16), (2, 5), true),
        // The same last fragment again is a duplicate.
        ((6, 5), (6, 5), false),
    ] {
        let mut storage = Storage::new(4, 0, 0);
        let mut tracker =
            Ipv4FragmentTracker::new(policy(1_000, 4, 0), storage.borrow(), key()).unwrap();
        allow(&mut tracker, 1, 0);
        assert!(pass(&mut tracker, 1, first_last.0, first_last.1).is_ok());
        let answer = pass(&mut tracker, 1, then.0, then.1);
        assert_eq!(
            answer == Err(DropReason::Ipv4FragmentMalformed),
            malformed,
            "{then:?}: {answer:?}"
        );
        if malformed {
            // Poisoned: every later fragment is refused, and the entry
            // stays until the timeout.
            assert_eq!(
                pass(&mut tracker, 1, 2 | MF, 16),
                Ok(Ipv4FragmentFollow::Deny)
            );
            assert_eq!(tracker.counters().poisoned, 1);
            assert_eq!(tracker.entries(), 1);
        }
    }
}

#[test]
fn coverage_beyond_four_pieces_waits_for_the_timeout() {
    let mut storage = Storage::new(4, 0, 0);
    let mut tracker = Ipv4FragmentTracker::new(policy(100, 4, 0), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 0);
    // Five disjoint pieces (the first fragment's and four more).
    for block in [4, 8, 12, 16] {
        assert!(pass(&mut tracker, 1, block | MF, 8).is_ok());
    }
    for block in [2, 6, 10, 14] {
        assert!(pass(&mut tracker, 1, block | MF, 16).is_ok());
    }
    assert!(pass(&mut tracker, 1, 18, 5).is_ok());
    assert_eq!(tracker.entries(), 1, "no longer tracked exactly");
    assert_eq!(tracker.sweep(100, usize::MAX), 1);
    assert_eq!(tracker.counters().entries_expired, 1);
}

#[test]
fn a_different_second_first_fragment_poisons_an_identical_one_does_not() {
    let mut storage = Storage::new(4, 4, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 0);
    // A byte-identical duplicate is dropped alone.
    assert_eq!(
        tracker.admit_first(info(&fragment(1, MF, 64, 17, 16)), 0),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    assert!(matches!(
        pass(&mut tracker, 1, 2 | MF, 16),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
    assert_eq!(tracker.counters().duplicate_first, 1);
    // A different one (another length, or other leading bytes) poisons.
    let mut other = fragment(1, MF, 64, 17, 16);
    other[34] ^= 0xff;
    assert_eq!(
        tracker.admit_first(info(&other), 0),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    assert_eq!(
        pass(&mut tracker, 1, 4 | MF, 16),
        Ok(Ipv4FragmentFollow::Deny)
    );
    assert_eq!(
        tracker.admit_first(info(&fragment(1, MF, 64, 17, 24)), 0),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    assert_eq!(tracker.counters().poisoned, 1);
    // A first fragment whose range contradicts what a pending entry holds
    // poisons it and discards what it held.
    let held = fragment(2, 2, 64, 17, 5);
    tracker.follow(info(&held), &held, held.len(), 0).unwrap();
    assert_eq!(
        tracker.admit_first(info(&fragment(2, MF, 64, 17, 24)), 0),
        Err(DropReason::Ipv4FragmentMalformed)
    );
    let counters = tracker.counters();
    assert_eq!((counters.poisoned, counters.held_denied), (2, 1));
    assert_eq!(tracker.held(), 0);
}

#[test]
fn host_accounting_is_per_ingress_and_eviction_spares_allowing_entries() {
    let mut storage = Storage::new(3, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 1, 2), storage.borrow(), key()).unwrap();
    // SOURCE on LAN takes its one entry (allowing).
    allow(&mut tracker, 1, 0);
    // The same address on WAN (spoofed or not) has its own quota.
    let mut spoofed = info(&fragment(2, 2, 64, 17, 8));
    spoofed.key.ingress = WAN;
    let frame = fragment(2, 2, 64, 17, 8);
    assert_eq!(
        tracker.follow(spoofed, &frame, frame.len(), 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    // A second WAN datagram of that source evicts its pending one.
    let mut again = info(&fragment(3, 2, 64, 17, 8));
    again.key.ingress = WAN;
    assert_eq!(
        tracker.follow(again, &frame, frame.len(), 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    let counters = tracker.counters();
    assert_eq!((counters.entries_evicted, counters.held_evicted), (1, 1));
    // The LAN source at its limit with only an allowing entry is refused.
    assert_eq!(
        tracker.admit_first(info(&fragment(4, MF, 64, 17, 16)), 0),
        Err(DropReason::Ipv4FragmentHostLimit)
    );
    // A full table evicts the oldest pending or refusing entry, globally.
    let third = fragment_from([10, 0, 0, 50], 5, MF, 64, 17, 16);
    let ticket = tracker.admit_first(info(&third), 0).unwrap();
    tracker.commit_deny(ticket, 0);
    let fourth = fragment_from([10, 0, 0, 51], 6, MF, 64, 17, 16);
    let ticket = tracker.admit_first(info(&fourth), 0).unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
    assert_eq!(tracker.counters().entries_evicted, 2);
    // Two allowing entries and one refusing: the refusing one goes next,
    // then nothing is left to evict.
    let fifth = fragment_from([10, 0, 0, 52], 7, MF, 64, 17, 16);
    let ticket = tracker.admit_first(info(&fifth), 0).unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
    let sixth = fragment_from([10, 0, 0, 53], 8, MF, 64, 17, 16);
    assert_eq!(
        tracker.admit_first(info(&sixth), 0),
        Err(DropReason::Ipv4FragmentTableFull)
    );
    assert!(matches!(
        pass(&mut tracker, 1, 2 | MF, 16),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
}

// ------------------------------------------- re-review follow-ups (#337) ----

#[test]
fn the_ingress_share_is_bounded_and_partitions_the_table() {
    let base = Ipv4FragmentTrackingPolicy::new(1_000, 8, 8).unwrap();
    assert_eq!(base.ingress_share_percent(), 50);
    for percent in [0, 101, u8::MAX] {
        assert_eq!(
            base.with_ingress_share_percent(percent),
            Err(Ipv4FragmentTrackingPolicyError::IngressShareOutOfRange)
        );
    }
    let mut storage = Storage::new(4, 0, 0);
    let mut tracker = Ipv4FragmentTracker::new(base, storage.borrow(), key()).unwrap();
    // LAN takes its two (50 % of 4); a third LAN datagram waits for room.
    allow(&mut tracker, 1, 0);
    allow(&mut tracker, 2, 0);
    assert_eq!(
        tracker.admit_first(info(&fragment(3, MF, 64, 17, 16)), 0),
        Err(DropReason::Ipv4FragmentIngressLimit)
    );
    // WAN still has its own two.
    for id in [4, 5] {
        let mut wan = info(&fragment(id, MF, 64, 17, 16));
        wan.key.ingress = WAN;
        let ticket = tracker.admit_first(wan, 0).unwrap();
        tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
    }
    assert_eq!(tracker.entries(), 4);
    // A stalled LAN datagram (a fifth of the timeout) gives way.
    assert!(tracker
        .admit_first(info(&fragment(3, MF, 64, 17, 16)), 200)
        .is_ok());
}

#[test]
fn one_datagram_holds_at_most_sixteen_fragments() {
    let mut storage = Storage::new(4, 32, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 32), storage.borrow(), key()).unwrap();
    for block in 0..16 {
        let frame = fragment(1, (1 + block) | MF, 64, 17, 8);
        assert_eq!(
            tracker.follow(info(&frame), &frame, frame.len(), 0),
            Ok(Ipv4FragmentFollow::Held)
        );
    }
    let frame = fragment(1, 17 | MF, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&frame), &frame, frame.len(), 0),
        Err(DropReason::Ipv4FragmentDatagramHoldLimit)
    );
    assert_eq!(tracker.held(), 16);
    // The bounded sweep frees it at the timeout.
    assert_eq!(tracker.sweep(999, 4), 0);
    assert_eq!(tracker.sweep(1_000, 4), 1);
    assert_eq!(tracker.held(), 0);
}

// ------------------------------------------- low follow-ups (#337) ----

/// Holds a later fragment of `id` from `source` at `now`.
fn hold(tracker: &mut Ipv4FragmentTracker<'_>, source: [u8; 4], id: u16, now: u64) {
    let frame = fragment_from(source, id, 2 | MF, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&frame), &frame, frame.len(), now),
        Ok(Ipv4FragmentFollow::Held)
    );
}

/// Forwards a later fragment of `id` from SOURCE at `now`: 8 bytes at
/// `word` 8-byte blocks.
fn progress(tracker: &mut Ipv4FragmentTracker<'_>, id: u16, word: u16, now: u64) {
    let frame = fragment(id, word | MF, 64, 17, 8);
    assert!(matches!(
        tracker.follow(info(&frame), &frame, frame.len(), now),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
}

#[test]
fn victims_are_found_behind_any_number_of_allowing_entries() {
    // Twelve allowing entries of one host, then one pending: at the host's
    // limit the pending one is evicted however many allowing ones precede
    // it (an eight-entry probe window could be shielded).
    let mut storage = Storage::new(16, 4, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 13, 4), storage.borrow(), key()).unwrap();
    for id in 1..=12 {
        allow(&mut tracker, id, 0);
    }
    hold(&mut tracker, SOURCE, 13, 0);
    // Evicted when the first fragment commits (#341 re-review L4).
    let ticket = tracker
        .admit_first(info(&fragment(14, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    let counters = tracker.counters();
    assert_eq!((counters.entries_evicted, counters.held_evicted), (1, 1));
    // Same at the ingress share (8 of 16).
    let mut storage = Storage::new(16, 4, 1514);
    let base = Ipv4FragmentTrackingPolicy::new(1_000, 16, 4).unwrap();
    let mut tracker = Ipv4FragmentTracker::new(base, storage.borrow(), key()).unwrap();
    for id in 1..=7 {
        allow(&mut tracker, id, 0);
    }
    hold(&mut tracker, SOURCE, 8, 0);
    // Evicted when the first fragment commits (#341 re-review L4).
    let ticket = tracker
        .admit_first(info(&fragment(9, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    assert_eq!(tracker.counters().entries_evicted, 1);
}

#[test]
fn held_room_never_evicts_the_datagram_it_is_made_for() {
    // Two held slots: datagram 1 holds one (oldest), datagram 2 the other.
    let mut storage = Storage::new(4, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    hold(&mut tracker, SOURCE, 1, 0);
    hold(&mut tracker, [10, 0, 0, 11], 2, 0);
    // A second fragment of datagram 1 evicts datagram 2, not datagram 1.
    let frame = fragment(1, 3 | MF, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&frame), &frame, frame.len(), 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!((tracker.entries(), tracker.held()), (1, 2));
    let counters = tracker.counters();
    assert_eq!((counters.entries_evicted, counters.held_evicted), (1, 1));
    // Only datagram 1 holds: its next fragment finds no other victim.
    let frame = fragment(1, 4 | MF, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&frame), &frame, frame.len(), 0),
        Err(DropReason::Ipv4FragmentHoldFull)
    );
    assert_eq!(tracker.held(), 2);
}

#[test]
fn the_host_hold_limit_is_checked_before_anything_is_evicted() {
    let mut storage = Storage::new(4, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 1), storage.borrow(), key()).unwrap();
    hold(&mut tracker, [10, 0, 0, 11], 1, 0);
    hold(&mut tracker, SOURCE, 2, 0);
    // SOURCE is at its hold limit and the held slots are full: refused
    // without evicting the other host's datagram.
    let frame = fragment(3, 2 | MF, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&frame), &frame, frame.len(), 0),
        Err(DropReason::Ipv4FragmentHostHoldLimit)
    );
    assert_eq!(tracker.counters().entries_evicted, 0);
    assert_eq!(tracker.held(), 2);
}

#[test]
fn a_datagram_in_progress_is_not_stalled_however_old() {
    let mut storage = Storage::new(2, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 0), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 0);
    allow(&mut tracker, 2, 0);
    // Datagram 1 keeps progressing; 2 does not.
    for (word, now) in [(2, 150), (3, 300), (4, 450)] {
        progress(&mut tracker, 1, word, now);
    }
    // At 500 ms both are 500 ms old, but only 2 made no progress for a
    // fifth of the timeout: it is the one evicted.
    let ticket = tracker
        .admit_first(info(&fragment(3, MF, 64, 17, 16)), 500)
        .unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 500);
    progress(&mut tracker, 1, 5, 550);
    // At 600 neither stalled (progress at 550 and 500).
    assert_eq!(
        tracker.admit_first(info(&fragment(4, MF, 64, 17, 16)), 600),
        Err(DropReason::Ipv4FragmentTableFull)
    );
    // At 720 datagram 3 stalled (220 ms), 1 did not (170 ms). Evicted when
    // the first fragment commits (#341 re-review L4).
    let ticket = tracker
        .admit_first(info(&fragment(4, MF, 64, 17, 16)), 720)
        .unwrap();
    tracker.commit_deny(ticket, 720);
    progress(&mut tracker, 1, 6, 720);
    assert_eq!(tracker.counters().entries_evicted, 2);
}

#[test]
fn an_evicted_allowing_key_is_refused_until_the_timeout() {
    let mut storage = Storage::new(1, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 2), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 0);
    // Datagram 2 evicts the stalled datagram 1 and leaves a tombstone.
    allow(&mut tracker, 2, 200);
    assert_eq!(tracker.counters().entries_evicted, 1);
    complete(&mut tracker, 2, SOURCE, 200);
    assert_eq!(tracker.entries(), 0);
    // A late fragment of datagram 1 is refused, not held.
    let late = fragment(1, 2, 64, 17, 5);
    assert_eq!(
        tracker.follow(info(&late), &late, late.len(), 300),
        Ok(Ipv4FragmentFollow::Deny)
    );
    assert_eq!((tracker.entries(), tracker.held()), (0, 0));
    assert_eq!(tracker.counters().followed_denied, 1);
    // A new first fragment on the key (maybe another datagram) is refused.
    let poisoned = tracker.counters().poisoned;
    assert_eq!(
        tracker.admit_first(info(&fragment(1, MF, 64, 17, 16)), 300),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    assert_eq!(tracker.counters().poisoned, poisoned + 1);
    // Other keys are not affected; after the timeout the key is free.
    assert!(tracker
        .admit_first(info(&fragment(5, MF, 64, 17, 16)), 300)
        .is_ok());
    assert!(tracker
        .admit_first(info(&fragment(1, MF, 64, 17, 16)), 1_200)
        .is_ok());
    // A flush forgets the tombstones.
    allow(&mut tracker, 1, 1_200);
    allow(&mut tracker, 6, 1_400);
    tracker.flush();
    assert!(tracker
        .admit_first(info(&fragment(1, MF, 64, 17, 16)), 1_400)
        .is_ok());
}

#[test]
fn every_ingress_is_found_and_the_two_hundred_fifty_seventh_refused() {
    let mut storage = Storage::new(512, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 0), storage.borrow(), key()).unwrap();
    for round in 0..2_u16 {
        for ingress in 0..256_u16 {
            let mut first = info(&fragment(round, MF, 64, 17, 16));
            first.key.ingress = IfId(ingress * 7);
            let ticket = tracker.admit_first(first, 0).unwrap();
            tracker.commit_deny(ticket, 0);
        }
    }
    assert_eq!(tracker.entries(), 512);
    for ingress in 0..256_u16 {
        let slot = tracker.ingress_of(IfId(ingress * 7)).unwrap();
        assert_eq!(tracker.ingresses[slot].entries, 2);
    }
    assert_eq!(tracker.ingress_of(IfId(1)), None);
    let mut first = info(&fragment(9, MF, 64, 17, 16));
    first.key.ingress = IfId(1);
    assert_eq!(
        tracker.admit_first(first, 0),
        Err(DropReason::Ipv4FragmentIngressLimit)
    );
}

#[test]
fn stalling_counts_from_the_last_progress_not_the_creation() {
    let mut storage = Storage::new(1, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 0), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 1_000);
    progress(&mut tracker, 1, 2, 1_300);
    // 150 ms since the progress at 1300 (450 since the creation): live.
    assert_eq!(
        tracker.admit_first(info(&fragment(2, MF, 64, 17, 16)), 1_450),
        Err(DropReason::Ipv4FragmentTableFull)
    );
    // 200 ms since the progress: stalled.
    assert!(tracker
        .admit_first(info(&fragment(2, MF, 64, 17, 16)), 1_500)
        .is_ok());
}

#[test]
fn every_evicted_allowing_key_is_remembered_up_to_sixteen() {
    let mut storage = Storage::new(17, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 64, 0), storage.borrow(), key()).unwrap();
    for id in 1..=17_u16 {
        allow(&mut tracker, id, 0);
    }
    // Seventeen new datagrams evict the seventeen stalled ones in order.
    for id in 18..=34_u16 {
        allow(&mut tracker, id, 200);
    }
    assert_eq!(tracker.counters().entries_evicted, 17);
    let key_of = |id| info(&fragment(id, MF, 64, 17, 16)).key;
    // The last sixteen evicted keys are remembered; the first was
    // overwritten in the ring.
    for id in 2..=17 {
        assert!(tracker.tombstoned(key_of(id), 300), "{id}");
    }
    assert!(!tracker.tombstoned(key_of(1), 300));
    assert!(!tracker.tombstoned(key_of(18), 300));
    // Until the timeout from their eviction.
    assert!(tracker.tombstoned(key_of(2), 1_199));
    assert!(!tracker.tombstoned(key_of(2), 1_200));
    // The first tombstone was overwritten within its timeout: counted.
    assert_eq!(tracker.counters().tombstones_overwritten, 1);
    tracker.check_invariants().unwrap();
}

#[test]
fn an_entry_is_counted_against_its_own_ingress_until_freed() {
    let base = Ipv4FragmentTrackingPolicy::new(1_000, 8, 8).unwrap();
    let mut storage = Storage::new(4, 0, 0);
    let mut tracker = Ipv4FragmentTracker::new(base, storage.borrow(), key()).unwrap();
    // WAN takes the first ingress slot, LAN the second and its share (2).
    let mut wan = info(&fragment(9, MF, 64, 17, 16));
    wan.key.ingress = WAN;
    let ticket = tracker.admit_first(wan, 0).unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
    allow(&mut tracker, 1, 0);
    allow(&mut tracker, 2, 0);
    // Completing a LAN datagram gives the LAN its room back.
    complete(&mut tracker, 1, SOURCE, 0);
    assert!(tracker
        .admit_first(info(&fragment(3, MF, 64, 17, 16)), 0)
        .is_ok());
}

// ------------------------------------------- review of #341 ----

/// Offers a later fragment of `id` from `source` on `ingress` at `now` (8
/// bytes at `word` 8-byte blocks, more to come).
fn offer(
    tracker: &mut Ipv4FragmentTracker<'_>,
    ingress: IfId,
    source: [u8; 4],
    id: u16,
    word: u16,
    now: u64,
) -> Result<Ipv4FragmentFollow, DropReason> {
    let frame = fragment_from(source, id, word | MF, 64, 17, 8);
    let mut later = info(&frame);
    later.key.ingress = ingress;
    tracker.follow(later, &frame, frame.len(), now)
}

/// Review of #341 core M1: poisoning an allowing entry moved it to the
/// evictable class without a tombstone at eviction, so filling the host's
/// quota evicted it and the evicted datagram's late fragments were held
/// again, to be released by a third first fragment on the key. A poisoned
/// entry now leaves a tombstone when it is evicted.
#[test]
fn an_evicted_poisoned_entry_leaves_a_tombstone() {
    let mut storage = Storage::new(8, 4, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 2, 4), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 0);
    // A different first fragment on the key poisons the allowing entry.
    assert_eq!(
        tracker.admit_first(info(&fragment(1, MF, 64, 17, 24)), 0),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    // The host's quota (2) fills, and the next datagram evicts the
    // poisoned entry (it is refusing now).
    allow(&mut tracker, 2, 0);
    // Evicted when the first fragment commits (#341 re-review L4).
    let ticket = tracker
        .admit_first(info(&fragment(3, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    assert_eq!(tracker.counters().entries_evicted, 1);
    // The evicted datagram's late fragment is refused, not held for
    // another datagram on the key; a third first fragment is refused too.
    assert_eq!(
        offer(&mut tracker, LAN, SOURCE, 1, 2, 10),
        Ok(Ipv4FragmentFollow::Deny)
    );
    assert_eq!(tracker.held(), 0);
    assert_eq!(
        tracker.admit_first(info(&fragment(1, MF, 64, 17, 16)), 10),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    tracker.check_invariants().unwrap();
}

/// Review of #341 core M2: a duplicate fragment counted as progress, so one
/// tiny duplicate per fifth of the timeout kept an allowing entry
/// unevictable. Only a fragment that adds data is progress.
#[test]
fn duplicates_are_not_progress() {
    let mut storage = Storage::new(1, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 0), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 0);
    progress(&mut tracker, 1, 2, 150);
    // The same bytes again, and bytes inside what was seen: no progress.
    progress(&mut tracker, 1, 2, 300);
    let inside = fragment(1, 2 | MF, 64, 17, 8);
    assert!(matches!(
        tracker.follow(info(&inside), &inside, inside.len(), 340),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
    // 200 ms after the last progress (150): stalled, evicted.
    // Evicted when the first fragment commits (#341 re-review L4).
    let ticket = tracker
        .admit_first(info(&fragment(2, MF, 64, 17, 16)), 350)
        .unwrap();
    tracker.commit_deny(ticket, 350);
    assert_eq!(tracker.counters().entries_evicted, 1);
}

/// Review of #341 sec M1 / core L4: a later fragment that the host's limit
/// then refuses used to evict another host's held datagram first. Every
/// victim is chosen before any is evicted, and none is evicted when the
/// admission fails.
#[test]
fn a_refused_hold_evicts_nothing() {
    let mut storage = Storage::new(8, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 2, 4), storage.borrow(), key()).unwrap();
    let other = [10, 0, 0, 11];
    for id in [1, 2] {
        assert_eq!(
            offer(&mut tracker, LAN, other, id, 2, 0),
            Ok(Ipv4FragmentFollow::Held)
        );
    }
    // SOURCE keeps its two allowing entries alive (its quota).
    allow(&mut tracker, 3, 0);
    allow(&mut tracker, 4, 0);
    for id in 5..10 {
        assert_eq!(
            offer(&mut tracker, LAN, SOURCE, id, 2, 0),
            Err(DropReason::Ipv4FragmentHostLimit)
        );
    }
    assert_eq!(tracker.counters().entries_evicted, 0);
    assert_eq!(tracker.held(), 2);
    // Same for a first fragment: no partial eviction.
    assert_eq!(
        tracker.admit_first(info(&fragment(10, MF, 64, 17, 16)), 0),
        Err(DropReason::Ipv4FragmentHostLimit)
    );
    assert_eq!(tracker.counters().entries_evicted, 0);
    tracker.check_invariants().unwrap();
}

/// Review of #341 sec M2: held slots had no ingress protection, so forged
/// WAN fragments evicted the LAN's out-of-order fragments. An ingress at
/// its share of the held slots (`ingress-share-percent`) displaces its own
/// held fragments first; one below it displaces an ingress over its share.
#[test]
fn held_slots_are_shared_between_ingresses() {
    let base = Ipv4FragmentTrackingPolicy::new(1_000, 8, 8).unwrap();
    let mut storage = Storage::new(16, 4, 1514);
    let mut tracker = Ipv4FragmentTracker::new(base, storage.borrow(), key()).unwrap();
    // The WAN floods every held slot (its share is 2 of 4).
    for id in 1..=4 {
        assert_eq!(
            offer(
                &mut tracker,
                WAN,
                [198, 51, 100, id as u8],
                id,
                2,
                id.into()
            ),
            Ok(Ipv4FragmentFollow::Held)
        );
    }
    tracker.check_invariants().unwrap();
    // A LAN fragment displaces the WAN's oldest held datagram.
    assert_eq!(
        offer(&mut tracker, LAN, SOURCE, 7, 2, 10),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!(tracker.counters().held_evicted, 1);
    // More WAN fragments (at its share) only displace the WAN's own.
    for id in 20..30 {
        assert_eq!(
            offer(&mut tracker, WAN, [198, 51, 100, 9], id, 2, 20),
            Ok(Ipv4FragmentFollow::Held)
        );
        tracker.check_invariants().unwrap();
    }
    // The LAN datagram is still held: its first fragment releases it.
    let ticket = tracker
        .admit_first(info(&fragment(7, MF, 64, 17, 16)), 30)
        .unwrap();
    let mut fragmentation = fragmentation(4);
    tracker.commit_allow(
        ticket,
        template(8),
        &snapshot(1500),
        Some(&mut fragmentation),
        30,
    );
    assert_eq!(tracker.counters().released, 1);
    // A LAN at its own share displaces its own held datagram first.
    for id in 40..42 {
        assert_eq!(
            offer(&mut tracker, LAN, [10, 0, 0, id as u8], id, 2, 40),
            Ok(Ipv4FragmentFollow::Held)
        );
    }
    let wan = tracker.ingress_of(WAN).unwrap();
    let wan_before = tracker.ingresses[wan].held;
    assert_eq!(
        offer(&mut tracker, LAN, [10, 0, 0, 50], 50, 2, 41),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!(
        tracker.ingresses[wan].held, wan_before,
        "the LAN at its share displaced its own"
    );
    tracker.check_invariants().unwrap();
}

#[test]
fn the_fingerprint_covers_every_byte_and_the_length() {
    let base: Vec<u8> = (0..1480_u32).map(|i| (i * 7 + 3) as u8).collect();
    assert_eq!(fingerprint(&base), fingerprint(&base.clone()));
    let mut seen = std::collections::HashSet::new();
    seen.insert(fingerprint(&base));
    for position in (0..base.len()).step_by(37).chain([base.len() - 1]) {
        let mut changed = base.clone();
        changed[position] ^= 0x80;
        assert!(seen.insert(fingerprint(&changed)), "{position}");
    }
    for len in 0..64 {
        assert!(seen.insert(fingerprint(&vec![0; len])), "zeros {len}");
    }
}

/// Review of #341 core L7: random operations keep every list and count
/// consistent.
#[test]
fn random_operations_keep_the_table_consistent() {
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move |upper: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % upper
    };
    let base = Ipv4FragmentTrackingPolicy::new(400, 3, 3).unwrap();
    let mut storage = Storage::new(8, 6, 1514);
    let mut tracker = Ipv4FragmentTracker::new(base, storage.borrow(), key()).unwrap();
    let snapshot = snapshot(1500);
    let mut now = 0;
    for _ in 0..20_000 {
        now += next(25);
        let ingress = if next(2) == 0 { LAN } else { WAN };
        let source = [10, 0, 0, 10 + next(4) as u8];
        let id = next(10) as u16;
        match next(10) {
            0..=2 => {
                let frame = fragment_from(source, id, MF, 64, 17, 16 + 8 * next(2) as usize);
                let mut first = info(&frame);
                first.key.ingress = ingress;
                if let Ok(ticket) = tracker.admit_first(first, now) {
                    if next(3) == 0 {
                        tracker.commit_deny(ticket, now);
                    } else {
                        tracker.commit_allow(ticket, template(8), &snapshot, None, now);
                    }
                }
            }
            3..=7 => {
                let word = 2 + next(6) as u16;
                let more = if next(4) == 0 { 0 } else { MF };
                let frame = fragment_from(source, id, word | more, 64, 17, 8);
                let mut later = info(&frame);
                later.key.ingress = ingress;
                if let Ok(Ipv4FragmentFollow::Allow { entry, .. }) =
                    tracker.follow(later, &frame, frame.len(), now)
                {
                    tracker.followed(entry);
                }
            }
            _ => {
                tracker.sweep(now, 4);
            }
        }
        tracker.check_invariants().unwrap();
    }
    let counters = tracker.counters();
    assert!(counters.entries_evicted > 0 && counters.held > 0 && counters.poisoned > 0);
}

/// An ingress at its share of the held slots displaces its own held
/// datagram even when another ingress is over its share.
#[test]
fn an_ingress_at_its_held_share_displaces_its_own_first() {
    let base = Ipv4FragmentTrackingPolicy::new(1_000, 8, 8)
        .unwrap()
        .with_ingress_share_percent(34)
        .unwrap();
    let mut storage = Storage::new(16, 6, 1514);
    let mut tracker = Ipv4FragmentTracker::new(base, storage.borrow(), key()).unwrap();
    let dmz = IfId(3);
    // Held share 2 of 6: the WAN holds 3 (over), the LAN 2, the DMZ 1.
    for id in 1..=3_u16 {
        assert_eq!(
            offer(&mut tracker, WAN, [198, 51, 100, id as u8], id, 2, 0),
            Ok(Ipv4FragmentFollow::Held)
        );
    }
    for id in 4..=5_u16 {
        assert_eq!(
            offer(&mut tracker, LAN, [10, 0, 0, id as u8], id, 2, 0),
            Ok(Ipv4FragmentFollow::Held)
        );
    }
    assert_eq!(
        offer(&mut tracker, dmz, [192, 0, 2, 6], 6, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    let wan = tracker.ingress_of(WAN).unwrap();
    let lan = tracker.ingress_of(LAN).unwrap();
    assert_eq!(
        offer(&mut tracker, LAN, [10, 0, 0, 7], 7, 2, 1),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!(
        (tracker.ingresses[wan].held, tracker.ingresses[lan].held),
        (3, 2)
    );
    tracker.check_invariants().unwrap();
}

/// The victim that frees a held slot also counts toward the host's, the
/// ingress's, and the table's room: nothing more is evicted (and nothing
/// unevictable is needed).
#[test]
fn one_victim_can_make_every_room() {
    // Host: SOURCE at its limit (2) with a held datagram and an allowing
    // one; the table has its two entries, and its one held slot is taken.
    let mut storage = Storage::new(2, 1, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 2, 4), storage.borrow(), key()).unwrap();
    assert_eq!(
        offer(&mut tracker, LAN, SOURCE, 1, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    allow(&mut tracker, 2, 0);
    assert_eq!(
        offer(&mut tracker, LAN, SOURCE, 3, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!(tracker.counters().entries_evicted, 1);
    tracker.check_invariants().unwrap();
    // Ingress: the LAN at its share (2 of 4) with a held datagram and an
    // allowing one.
    let base = Ipv4FragmentTrackingPolicy::new(1_000, 8, 8).unwrap();
    let mut storage = Storage::new(4, 1, 1514);
    let mut tracker = Ipv4FragmentTracker::new(base, storage.borrow(), key()).unwrap();
    assert_eq!(
        offer(&mut tracker, LAN, [10, 0, 0, 1], 1, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    allow(&mut tracker, 2, 0);
    assert_eq!(
        offer(&mut tracker, LAN, [10, 0, 0, 3], 3, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!(tracker.counters().entries_evicted, 1);
    tracker.check_invariants().unwrap();
}

/// Review of #341 core L5: a ticket names its entry by index; when that
/// entry was evicted and its slot reused for another key before the
/// commit, the commit leaves the other datagram alone.
#[test]
fn a_ticket_never_decides_another_key() {
    let mut storage = Storage::new(1, 1, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    assert_eq!(
        offer(&mut tracker, LAN, SOURCE, 1, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    let ticket = tracker
        .admit_first(info(&fragment(1, MF, 64, 17, 16)), 0)
        .unwrap();
    // Datagram 2 displaces datagram 1 and takes its slot.
    assert_eq!(
        offer(&mut tracker, LAN, [10, 0, 0, 11], 2, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
    // Datagram 2 is still undecided: its next fragment is held.
    assert_eq!(tracker.held(), 1);
    let frame = fragment_from([10, 0, 0, 11], 2, 2 | MF, 64, 17, 8);
    assert!(!matches!(
        tracker.follow(info(&frame), &frame, frame.len(), 0),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
    tracker.check_invariants().unwrap();
}

/// A held datagram's fragment that contradicts its end poisons it before
/// any victim is chosen: nothing else is evicted for it.
#[test]
fn a_contradicting_hold_evicts_nothing() {
    let mut storage = Storage::new(4, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    assert_eq!(
        offer(&mut tracker, LAN, SOURCE, 1, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    assert_eq!(
        offer(&mut tracker, LAN, [10, 0, 0, 11], 2, 2, 0),
        Ok(Ipv4FragmentFollow::Held)
    );
    // Datagram 1 saw data up to 24; a last fragment ending at 16 contradicts.
    let last = fragment(1, 1, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&last), &last, last.len(), 0),
        Err(DropReason::Ipv4FragmentMalformed)
    );
    assert_eq!(tracker.counters().entries_evicted, 0);
    assert_eq!(
        tracker.held(),
        1,
        "only datagram 1's fragment was discarded"
    );
    tracker.check_invariants().unwrap();
}

// ------------------------------------------- re-review of #341 ----

/// Re-review L1: an entry that only ever refused leaves no tombstone when
/// it is evicted, poisoned or not (a flood of refused first fragments
/// cannot churn the tombstones); one that allowed and was poisoned does.
#[test]
fn a_refusing_entry_leaves_no_tombstone() {
    let mut storage = Storage::new(8, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 2, 0), storage.borrow(), key()).unwrap();
    let ticket = tracker
        .admit_first(info(&fragment(1, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    // A different first fragment poisons the refusing entry.
    assert_eq!(
        tracker.admit_first(info(&fragment(1, MF, 64, 17, 24)), 0),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    assert_eq!(tracker.counters().poisoned, 1);
    let ticket = tracker
        .admit_first(info(&fragment(2, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    // The host's quota is full: the poisoned refusing entry is evicted
    // (when the first fragment commits, ARP-HOLD #341 re-review L4).
    let ticket = tracker
        .admit_first(info(&fragment(3, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    assert_eq!(tracker.counters().entries_evicted, 1);
    let key_of = |id| info(&fragment(id, MF, 64, 17, 16)).key;
    assert!(!tracker.tombstoned(key_of(1), 0));
    // Allowed, then poisoned, then evicted: a tombstone.
    allow(&mut tracker, 4, 0);
    assert_eq!(
        tracker.admit_first(info(&fragment(4, MF, 64, 17, 24)), 0),
        Err(DropReason::Ipv4FragmentDuplicateFirst)
    );
    // The host's oldest evictable entries go first (2 went for 4, 3 goes
    // for 5), then the poisoned 4.
    let ticket = tracker
        .admit_first(info(&fragment(5, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    assert!(!tracker.tombstoned(key_of(4), 0));
    let ticket = tracker
        .admit_first(info(&fragment(6, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    assert!(tracker.tombstoned(key_of(4), 0));
    assert!(!tracker.tombstoned(key_of(2), 0));
    tracker.check_invariants().unwrap();
}

/// Re-review L2: once a datagram arrives in more than four disjoint pieces
/// its coverage is no longer tracked exactly, but a fragment adding bytes
/// is still progress (a heavily reordered datagram does not look stalled);
/// the over-approximated ranges make every replay a duplicate (follow-up
/// L-1: frozen ranges counted each replay of an outside piece).
#[test]
fn an_untracked_datagram_still_progresses() {
    let mut storage = Storage::new(1, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 0), storage.borrow(), key()).unwrap();
    allow(&mut tracker, 1, 0);
    // [0,16) [32,40) [48,56) [64,72), then a fifth piece: untracked.
    for word in [4, 6, 8, 12] {
        progress(&mut tracker, 1, word, 10);
    }
    // The ranges over-approximate: [0,16) [32,56) [64,72) [96,104) (the
    // smallest gap closed). A gap below the largest end: progress at 150.
    progress(&mut tracker, 1, 3, 150);
    // Replays are no progress: a piece inside a range, the piece that made
    // the datagram untracked, and the one that just progressed.
    for word in [4, 12, 3] {
        progress(&mut tracker, 1, word, 300);
    }
    assert_eq!(
        tracker.admit_first(info(&fragment(2, MF, 64, 17, 16)), 340),
        Err(DropReason::Ipv4FragmentTableFull)
    );
    assert!(tracker
        .admit_first(info(&fragment(2, MF, 64, 17, 16)), 350)
        .is_ok());
}

/// Re-review L3: a later fragment refused for its TTL still counts toward
/// a refused datagram's coverage, so the refusing entry completes early;
/// an allowing or pending entry is left alone.
#[test]
fn an_expired_ttl_fragment_completes_a_refused_datagram() {
    let mut storage = Storage::new(4, 2, 1514);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage.borrow(), key()).unwrap();
    let ticket = tracker
        .admit_first(info(&fragment(1, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    allow(&mut tracker, 2, 0);
    let last = |id| info(&fragment(id, 2, 1, 17, 5));
    tracker.ttl_expired(last(2), 0);
    assert_eq!(tracker.entries(), 2, "the allowing entry is left alone");
    tracker.ttl_expired(last(3), 0);
    assert_eq!((tracker.entries(), tracker.held()), (2, 0), "nothing held");
    tracker.ttl_expired(last(1), 0);
    assert_eq!(tracker.entries(), 1);
    assert_eq!(tracker.counters().entries_completed, 1);
    // A contradicting one poisons a refusing entry, as a followed one does.
    let ticket = tracker
        .admit_first(info(&fragment(4, MF, 64, 17, 24)), 0)
        .unwrap();
    tracker.commit_deny(ticket, 0);
    tracker.ttl_expired(info(&fragment(4, 1, 1, 17, 8)), 0);
    assert_eq!(tracker.counters().poisoned, 1);
    tracker.check_invariants().unwrap();
}

/// `record` directly: touching ranges merge at both ends; past four pieces
/// a piece spanning several ranges merges them, replays are duplicates, a
/// gap inside an over-approximated range is a duplicate too (the
/// trade-off), and an untracked entry never completes even when its
/// ranges look full.
#[test]
fn record_merges_touching_ranges_and_over_approximates() {
    let ranges =
        |entry: &Ipv4FragmentEntrySlot| entry.ranges[..usize::from(entry.ranges_len)].to_vec();
    // Touching at both ends: [0,8) and [16,24) joined by [8,16).
    let mut entry = Ipv4FragmentEntrySlot::EMPTY;
    assert_eq!(entry.record(0, 8, true), Ok(true));
    assert_eq!(entry.record(16, 8, true), Ok(true));
    assert_eq!(ranges(&entry), [[0, 8], [16, 24]]);
    assert_eq!(entry.record(8, 8, true), Ok(true));
    assert_eq!(ranges(&entry), [[0, 24]]);
    assert_eq!(entry.record(8, 8, true), Ok(false), "a replay");
    assert_eq!(entry.record(24, 8, false), Ok(true), "touching the end");
    assert_eq!(ranges(&entry), [[0, 32]]);
    assert!(entry.complete());

    // Five pieces: the smallest gap closes (all equal: the first).
    let mut entry = Ipv4FragmentEntrySlot::EMPTY;
    for offset in [0, 16, 32, 48] {
        assert_eq!(entry.record(offset, 8, true), Ok(true));
    }
    assert!(!entry.untracked);
    assert_eq!(entry.record(64, 8, false), Ok(true));
    assert!(entry.untracked);
    assert_eq!(ranges(&entry), [[0, 24], [32, 40], [48, 56], [64, 72]]);
    // A piece spanning several ranges merges them; its replay is a
    // duplicate.
    assert_eq!(entry.record(24, 32, true), Ok(true));
    assert_eq!(ranges(&entry), [[0, 56], [64, 72]]);
    assert_eq!(entry.record(24, 32, true), Ok(false));
    // The ranges now look full, but [8,16) was never seen: no completion.
    assert_eq!(entry.record(56, 8, true), Ok(true));
    assert_eq!(ranges(&entry), [[0, 72]]);
    assert_eq!(entry.total, 72);
    assert!(!entry.complete());
    // The never-seen gap [8,16) lies inside the over-approximated range: a
    // duplicate, so it does not refresh the stall timer (the trade-off).
    assert_eq!(entry.record(8, 8, true), Ok(false));
    assert!(!entry.complete());
    // The end still holds: data past it is a contradiction.
    assert_eq!(entry.record(72, 8, true), Err(()));
}

/// A flush of a table nothing touched since it was made or last flushed only
/// changes the key; the table then behaves as one made with that key, and once
/// touched, a flush discards everything again.
#[test]
fn a_flush_of_an_untouched_table_only_changes_the_key() {
    let new_key = ResolutionHashKey::new(3, 5).unwrap();
    let mut storage_a = Storage::new(4, 4, 1514);
    let mut flushed =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage_a.borrow(), key()).unwrap();
    flushed.flush_with_key(new_key);
    flushed.flush();
    let mut storage_b = Storage::new(4, 4, 1514);
    let mut fresh =
        Ipv4FragmentTracker::new(policy(1_000, 4, 4), storage_b.borrow(), new_key).unwrap();
    // The same fragments into both: firsts admitted and denied, later ones held,
    // over the per-host limits, at times past the timeout.
    for round in 0..40_u16 {
        let now = u64::from(round) * 300;
        let id = round % 7;
        for tracker in [&mut flushed, &mut fresh] {
            if round % 3 == 0 {
                if let Ok(ticket) = tracker.admit_first(info(&fragment(id, MF, 64, 17, 8)), now) {
                    tracker.commit_deny(ticket, now);
                }
            } else {
                let later = fragment(id, 2, 64, 17, 8);
                let _ = tracker.follow(info(&later), &later, later.len(), now);
            }
        }
        assert_eq!(flushed.occupancy(), fresh.occupancy(), "round {round}");
        assert_eq!(flushed.counters(), fresh.counters(), "round {round}");
    }
    // Touched now: a flush discards and counts what is there.
    let entries = flushed.entries();
    let held = flushed.held();
    assert!(entries > 0);
    flushed.flush_with_key(key());
    assert_eq!((flushed.entries(), flushed.held()), (0, 0));
    let counters = flushed.counters();
    assert_eq!(
        (counters.entries_flushed, counters.held_flushed),
        (entries, held)
    );
}

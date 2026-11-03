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
    }
}

struct Storage {
    entries: Vec<Ipv4FragmentEntrySlot>,
    entry_buckets: Vec<DirectoryBucket>,
    entry_nodes: Vec<DirectoryNode>,
    hosts: Vec<Ipv4FragmentHostSlot>,
    host_buckets: Vec<DirectoryBucket>,
    host_nodes: Vec<DirectoryNode>,
    held: Vec<Ipv4FragmentHeldSlot>,
    held_bytes: Vec<u8>,
}

impl Storage {
    fn new(entries: usize, held: usize, held_slot: usize) -> Self {
        let buckets = ipv4_fragment_tracking_buckets(entries);
        Self {
            entries: vec![Ipv4FragmentEntrySlot::EMPTY; entries],
            entry_buckets: vec![DirectoryBucket::default(); buckets],
            entry_nodes: vec![DirectoryNode::default(); entries],
            hosts: vec![Ipv4FragmentHostSlot::EMPTY; entries],
            host_buckets: vec![DirectoryBucket::default(); buckets],
            host_nodes: vec![DirectoryNode::default(); entries],
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
            held: &mut self.held,
            held_bytes: &mut self.held_bytes,
        }
    }
}

fn key() -> ResolutionHashKey {
    ResolutionHashKey::new(7, 9).unwrap()
}

fn policy(timeout: u32, entries_per_host: u32, held_per_host: u32) -> Ipv4FragmentTrackingPolicy {
    Ipv4FragmentTrackingPolicy::new(timeout, entries_per_host, held_per_host).unwrap()
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
    tracker.followed(entry, last);
    assert_eq!(tracker.entries(), 1, "16 + 5 of 37 bytes");
    let middle = info(&fragment(1, 2 | MF, 64, 17, 16));
    let Ok(Ipv4FragmentFollow::Allow { entry, .. }) = tracker.follow(middle, &[], 0, 0) else {
        panic!("allowed");
    };
    tracker.followed(entry, middle);
    assert_eq!(tracker.entries(), 0);
    let counters = tracker.counters();
    assert_eq!((counters.followed, counters.entries_completed), (2, 1));
    // Without its last fragment an entry never completes.
    let ticket = tracker
        .admit_first(info(&fragment(2, MF, 64, 17, 16)), 0)
        .unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot(1500), None, 0);
    tracker.note(0, 16, 1_000, true);
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
    let third = fragment_from([10, 0, 0, 12], 1, 1, 64, 17, 8);
    assert_eq!(
        tracker.follow(info(&third), &third, third.len(), 0),
        Err(DropReason::Ipv4FragmentHoldFull)
    );
    assert_eq!((tracker.entries(), tracker.held()), (2, 2));
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
    for (id, at) in [(1, 0), (2, 50)] {
        let ticket = tracker
            .admit_first(info(&fragment(id, MF, 64, 17, 8)), at)
            .unwrap();
        tracker.commit_allow(ticket, template(8), &snapshot, None, at);
    }
    assert_eq!(
        tracker.admit_first(info(&fragment(3, MF, 64, 17, 8)), 99),
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
        tracker.follow(info(&later), &later, later.len(), 149),
        Ok(Ipv4FragmentFollow::Allow { .. })
    ));
    let gone = fragment(1, 1, 64, 17, 8);
    // Datagram 1 is unknown again: held (it takes 2's expired entry).
    assert_eq!(
        tracker.follow(info(&gone), &gone, gone.len(), 150),
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
fn per_host_entries_are_counted_and_released() {
    let mut storage = Storage::new(4, 0, 0);
    let mut tracker =
        Ipv4FragmentTracker::new(policy(1_000, 2, 0), storage.borrow(), key()).unwrap();
    let snapshot = snapshot(1500);
    for id in [1, 2] {
        let ticket = tracker
            .admit_first(info(&fragment(id, MF, 64, 17, 8)), 0)
            .unwrap();
        tracker.commit_deny(ticket, 0);
    }
    assert_eq!(
        tracker.admit_first(info(&fragment(3, MF, 64, 17, 8)), 0),
        Err(DropReason::Ipv4FragmentHostLimit)
    );
    let other = fragment_from([10, 0, 0, 99], 3, MF, 64, 17, 8);
    let ticket = tracker.admit_first(info(&other), 0).unwrap();
    tracker.commit_allow(ticket, template(8), &snapshot, None, 0);
    // Completing datagram 1 (its last fragment) frees one of the host's.
    let last = fragment(1, 1, 64, 17, 3);
    assert_eq!(
        tracker.follow(info(&last), &last, last.len(), 0),
        Ok(Ipv4FragmentFollow::Deny)
    );
    assert_eq!(tracker.entries(), 2);
    assert!(tracker
        .admit_first(info(&fragment(3, MF, 64, 17, 8)), 0)
        .is_ok());
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
    let large = fragment(1, 2, 64, 17, 800);
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
    tracker.flush();
    assert_eq!((tracker.entries(), tracker.held()), (0, 0));
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
    tracker.followed(entry, info(&last));
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
    let mut tracker = Ipv4FragmentTracker::new(policy(100, 8, 0), storage.borrow(), key()).unwrap();
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
        allow(&mut tracker, id, 102);
    }
    assert_eq!(tracker.counters().entries_expired, 2);
    assert_eq!(tracker.entries(), 3);
    // Free everything: every slot is reachable from the free list again.
    for id in [4, 5, 6] {
        complete(&mut tracker, id, SOURCE, 103);
    }
    assert_eq!(tracker.entries(), 0);
    for id in [7, 8, 9] {
        allow(&mut tracker, id, 104);
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
        Err(DropReason::Ipv4FragmentTableFull)
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
    let df = fragment(1, 72 | MF | DF, 64, 17, 8);
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

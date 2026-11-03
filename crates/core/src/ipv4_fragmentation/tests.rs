//! Unit tests of the fragmentation algorithm. Every expected fragment is
//! built here from the RFC 791 §3.2 layout with this file's own checksum,
//! not with the production helpers.

use super::*;
use crate::{GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion};

const EGRESS: IfId = IfId(2);
const DST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const SRC_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

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

/// A rewritten frame as forwarding stages it: Ethernet II, a 20-byte IPv4
/// header (ID 0x1234, TTL 63, UDP, 192.0.2.1 -> 198.51.100.9), and a data
/// pattern of `data_len` bytes.
fn datagram(data_len: usize, flags_offset: u16) -> Vec<u8> {
    let total = 20 + data_len;
    let mut frame = Vec::with_capacity(14 + total);
    frame.extend_from_slice(&DST_MAC);
    frame.extend_from_slice(&SRC_MAC);
    frame.extend_from_slice(&[0x08, 0x00]);
    let mut header = [
        0x45, 0x00, 0, 0, 0x12, 0x34, 0, 0, 63, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 9,
    ];
    header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    let checksum = reference_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend((0..data_len).map(|i| (i * 7 + 3) as u8));
    frame
}

/// The fragment of `original` (from [`datagram`]) carrying data bytes
/// `start..start + len`, with MF as given, per RFC 791 §3.2: same header
/// but Total Length, MF, and Fragment Offset (original offset + start / 8),
/// and a fresh checksum.
fn expected_fragment(original: &[u8], start: usize, len: usize, more: bool) -> Vec<u8> {
    assert_eq!(start % 8, 0, "fragment data starts on an 8-byte boundary");
    let mut frame = original[..34].to_vec();
    let original_word = u16::from_be_bytes([original[20], original[21]]);
    let offset = (original_word & 0x1fff) + (start / 8) as u16;
    let mut word = (original_word & 0x8000) | offset;
    if more {
        word |= 0x2000;
    }
    frame[16..18].copy_from_slice(&((20 + len) as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&word.to_be_bytes());
    frame[24..26].copy_from_slice(&[0, 0]);
    let checksum = reference_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&original[34 + start..34 + start + len]);
    frame
}

struct Storage {
    slots: Vec<Ipv4FragmentSlot>,
    bytes: Vec<u8>,
}

impl Storage {
    fn new(slots: usize, max_mtu: u16) -> Self {
        Self {
            slots: vec![Ipv4FragmentSlot::EMPTY; slots],
            bytes: vec![0; slots * ipv4_fragment_slot_bytes(max_mtu)],
        }
    }

    fn runtime(&mut self, policy: Ipv4FragmentationPolicy) -> Ipv4FragmentationRuntime<'_> {
        Ipv4FragmentationRuntime::new(policy, &mut self.slots, &mut self.bytes).unwrap()
    }
}

#[derive(Default)]
struct FakeIo {
    /// What `check_capacity` answers (after the length checks).
    refuse: Option<GeneratedAllocationError>,
    /// Allocation number (from 0) that fails with `Unavailable`.
    fail_allocation: Option<usize>,
    /// Allocation number that lends one byte too few.
    short_lease: Option<usize>,
    max_frame: usize,
    capacity_checks: Vec<(IfId, usize, usize)>,
    sent: Vec<(IfId, Vec<u8>)>,
    cancelled: usize,
}

struct FakeBatch<'a> {
    io: &'a mut FakeIo,
    egress: IfId,
    allocations: usize,
    completion: GeneratedBatchCompletion<()>,
}

struct FakeSlot<'a> {
    bytes: Vec<u8>,
    egress: IfId,
    io: &'a mut FakeIo,
    completion: &'a mut GeneratedBatchCompletion<()>,
}

impl GeneratedPacketSlot for FakeSlot<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        match completion {
            GeneratedSlotCompletion::Transmit => {
                self.completion.requested += 1;
                self.completion.accepted += 1;
                self.io.sent.push((self.egress, self.bytes));
            }
            GeneratedSlotCompletion::Cancelled => {
                self.completion.cancelled += 1;
                self.io.cancelled += 1;
            }
            GeneratedSlotCompletion::Abandoned => self.completion.abandoned += 1,
        }
    }
}

impl GeneratedPacketIo for FakeIo {
    type Error = ();
    type Batch<'a> = FakeBatch<'a>;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        FakeBatch {
            io: self,
            egress,
            allocations: 0,
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

impl GeneratedPacketBatch for FakeBatch<'_> {
    type Error = ();
    type Slot<'a>
        = FakeSlot<'a>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        let number = self.allocations;
        self.allocations += 1;
        self.completion.attempts += 1;
        if frame_len > self.io.max_frame || self.io.fail_allocation == Some(number) {
            self.completion.failed += 1;
            return Err(GeneratedAllocationError::Unavailable);
        }
        self.completion.allocated += 1;
        let len = if self.io.short_lease == Some(number) {
            frame_len - 1
        } else {
            frame_len
        };
        Ok(GeneratedPacketLease::new(FakeSlot {
            bytes: vec![0xa5; len],
            egress: self.egress,
            io: self.io,
            completion: &mut self.completion,
        }))
    }

    fn check_capacity(
        &mut self,
        frames: usize,
        frame_len: usize,
    ) -> Result<(), GeneratedAllocationError> {
        self.io
            .capacity_checks
            .push((self.egress, frames, frame_len));
        if frame_len > self.io.max_frame {
            return Err(GeneratedAllocationError::FrameTooLarge);
        }
        self.io.refuse.map_or(Ok(()), Err)
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        self.completion
    }
}

fn io() -> FakeIo {
    FakeIo {
        max_frame: 14 + 9000,
        ..FakeIo::default()
    }
}

fn policy(max_fragments: u16) -> Ipv4FragmentationPolicy {
    Ipv4FragmentationPolicy::new(true, max_fragments).unwrap()
}

/// Stages `frame` for `mtu` and sends it; returns the frames sent.
fn fragment(frame: &[u8], mtu: u16) -> Vec<Vec<u8>> {
    let mut storage = Storage::new(1, 9000);
    let mut runtime = storage.runtime(Ipv4FragmentationPolicy::DEFAULT);
    let plan = runtime.plan(frame, mtu).unwrap();
    runtime.stage(frame, plan, EGRESS);
    let mut io = io();
    let report = execute_one_ipv4_fragmentation(&mut io, &mut runtime).unwrap();
    assert_eq!(report.outcome, Ipv4FragmentOutcome::Sent);
    assert_eq!(usize::from(report.fragments), io.sent.len());
    assert!(execute_one_ipv4_fragmentation(&mut io, &mut runtime).is_none());
    io.sent
        .into_iter()
        .map(|(egress, bytes)| {
            assert_eq!(egress, EGRESS);
            bytes
        })
        .collect()
}

#[test]
fn policy_bounds_and_default() {
    assert_eq!(
        Ipv4FragmentationPolicy::new(true, 1),
        Err(Ipv4FragmentationPolicyError::MaxFragmentsOutOfRange)
    );
    assert_eq!(
        Ipv4FragmentationPolicy::new(true, 1366),
        Err(Ipv4FragmentationPolicyError::MaxFragmentsOutOfRange)
    );
    assert_eq!(policy(2).max_fragments(), 2);
    assert_eq!(policy(1365).max_fragments(), 1365);
    assert!(!Ipv4FragmentationPolicy::new(false, 2).unwrap().enabled());
    let default = Ipv4FragmentationPolicy::default();
    assert!(default.enabled());
    assert_eq!(default.max_fragments(), 1365);
    // 65535 bytes at the minimum MTU: ceil((65535 - 20) / 48).
    assert_eq!(IPV4_FRAGMENTATION_MAX_FRAGMENTS, 1365);
    assert_eq!(65_515_usize.div_ceil(48), 1365);
}

#[test]
fn storage_must_be_whole_slots_of_a_valid_size() {
    let mut slots = [Ipv4FragmentSlot::EMPTY; 2];
    let mut bytes = vec![0; 2 * 1514 + 1];
    assert_eq!(
        Ipv4FragmentationRuntime::new(policy(4), &mut slots, &mut bytes).err(),
        Some(Ipv4FragmentationStorageError::SlotBytes)
    );
    let mut small = vec![0; 2 * (14 + 67)];
    assert_eq!(
        Ipv4FragmentationRuntime::new(policy(4), &mut slots, &mut small).err(),
        Some(Ipv4FragmentationStorageError::SlotBytes)
    );
    let mut minimum = vec![0; 2 * (14 + 68)];
    let runtime = Ipv4FragmentationRuntime::new(policy(4), &mut slots, &mut minimum).unwrap();
    assert_eq!((runtime.slot_capacity(), runtime.slot_bytes()), (2, 82));
    let mut huge = vec![0; 2 * (14 + 65_536)];
    assert_eq!(
        Ipv4FragmentationRuntime::new(policy(4), &mut slots, &mut huge).err(),
        Some(Ipv4FragmentationStorageError::SlotBytes)
    );
    let mut largest = vec![0; 2 * (14 + 65_535)];
    assert!(Ipv4FragmentationRuntime::new(policy(4), &mut slots, &mut largest).is_ok());
    let mut none: [Ipv4FragmentSlot; 0] = [];
    let mut stray = vec![0; 1];
    assert_eq!(
        Ipv4FragmentationRuntime::new(policy(4), &mut none, &mut stray).err(),
        Some(Ipv4FragmentationStorageError::SlotBytes)
    );
    let mut empty: Vec<u8> = Vec::new();
    let runtime = Ipv4FragmentationRuntime::new(policy(4), &mut none, &mut empty).unwrap();
    assert_eq!(runtime.slot_capacity(), 0);
    assert_eq!(runtime.slot_bytes(), 0);
    // No slot: every datagram that needs fragmentation finds the table full.
    assert_eq!(
        runtime.plan(&datagram(600, 0), 576),
        Err(DropReason::Ipv4FragmentationQueueFull)
    );
}

#[test]
fn a_new_runtime_is_pristine_and_cleared() {
    let mut slots = [Ipv4FragmentSlot {
        egress: IfId(9),
        mtu: 9,
        fragments: 9,
        frame_len: 9,
    }];
    let mut bytes = vec![0xee; 1514];
    let runtime = Ipv4FragmentationRuntime::new(policy(4), &mut slots, &mut bytes).unwrap();
    assert_eq!(runtime.slot_capacity(), 1);
    assert_eq!(runtime.slot_bytes(), 1514);
    assert_eq!(runtime.counters(), Ipv4FragmentationCounters::default());
    assert_eq!(runtime.pending(), 0);
    assert_eq!(runtime.policy(), policy(4));
    assert_eq!(slots[0], Ipv4FragmentSlot::EMPTY);
    assert!(bytes.iter().all(|&byte| byte == 0));
}

#[test]
fn fragment_counts_for_real_and_worst_case_mtus() {
    let runtime_counts = |data_len: usize, mtu: u16, max_mtu: u16| {
        let mut storage = Storage::new(1, max_mtu);
        let runtime = storage.runtime(Ipv4FragmentationPolicy::DEFAULT);
        runtime
            .plan(&datagram(data_len, 0), mtu)
            .map(Ipv4FragmentPlan::fragments)
    };
    // 1500 -> 1280: 1480 data bytes in 1256-byte blocks.
    assert_eq!(runtime_counts(1480, 1280, 1500), Ok(2));
    // 1500 -> 576: 552-byte blocks.
    assert_eq!(runtime_counts(1480, 576, 1500), Ok(3));
    // 9000 -> 1500: 1480-byte blocks.
    assert_eq!(runtime_counts(8980, 1500, 9000), Ok(7));
    // 65535 -> 68: 48-byte blocks, the worst case.
    assert_eq!(runtime_counts(65_515, 68, 65_535), Ok(1365));
}

#[test]
fn every_refusal_is_typed_and_checked_in_order() {
    let mut storage = Storage::new(1, 1500);
    let off = Ipv4FragmentationPolicy::new(false, 1365).unwrap();
    assert_eq!(
        storage.runtime(off).plan(&datagram(1480, 0), 576),
        Err(DropReason::Ipv4FragmentationRequired)
    );
    // Exactly the bound is admitted, one more fragment is not.
    let runtime = storage.runtime(policy(3));
    assert!(runtime.plan(&datagram(1480, 0), 576).is_ok());
    assert_eq!(
        runtime.plan(&datagram(1480, 0), 500),
        Err(DropReason::Ipv4FragmentationTooManyFragments)
    );
    // Options never reach fragmentation; refused if they did.
    let mut options = datagram(1480, 0);
    options[14] = 0x46;
    assert_eq!(
        runtime.plan(&options, 576),
        Err(DropReason::Ipv4OptionsUnsupported)
    );
    // A received fragment ending past 65535 bytes cannot be re-fragmented.
    assert_eq!(
        runtime.plan(&datagram(600, 8150), 576),
        Err(DropReason::Ipv4FragmentationOffsetOverflow)
    );
    // The largest offset that still fits: data ends at 65535 - 20.
    assert!(runtime
        .plan(&datagram(600, (65_515 - 600) / 8), 576)
        .is_ok());
    // Three fragments of 1200 data bytes at 576: the last starts 1104 bytes
    // (138 blocks) in, so offset 8053 puts it exactly at 8191 (fits) and
    // 8054 one block beyond.
    let default = storage.runtime(Ipv4FragmentationPolicy::DEFAULT);
    assert_eq!(
        default
            .plan(&datagram(1200, 8053), 576)
            .map(Ipv4FragmentPlan::fragments),
        Ok(3)
    );
    assert_eq!(
        default.plan(&datagram(1200, 8054), 576),
        Err(DropReason::Ipv4FragmentationOffsetOverflow)
    );
    // A datagram longer than a slot (1514 bytes here).
    let runtime = storage.runtime(Ipv4FragmentationPolicy::DEFAULT);
    assert_eq!(
        runtime.plan(&datagram(1481, 0), 576),
        Err(DropReason::Ipv4FragmentationDatagramTooLarge)
    );
    assert!(runtime.plan(&datagram(1480, 0), 576).is_ok());
    // A frame shorter than its Total Length is refused too.
    let truncated = datagram(1000, 0);
    assert_eq!(
        runtime.plan(&truncated[..truncated.len() - 1], 576),
        Err(DropReason::Ipv4FragmentationDatagramTooLarge)
    );
    // The bound is checked before the slot table.
    let mut runtime = runtime;
    let frame = datagram(1480, 0);
    let plan = runtime.plan(&frame, 576).unwrap();
    runtime.stage(&frame, plan, EGRESS);
    assert_eq!(
        runtime.plan(&frame, 576),
        Err(DropReason::Ipv4FragmentationQueueFull)
    );
    let mut bounded_storage = Storage::new(1, 1500);
    let mut bounded = bounded_storage.runtime(policy(2));
    bounded.stage(&frame, plan, EGRESS);
    assert_eq!(
        bounded.plan(&frame, 576),
        Err(DropReason::Ipv4FragmentationTooManyFragments)
    );
}

#[test]
fn fragments_follow_rfc791_exactly() {
    // 1500 -> 576: blocks of 552 (69 * 8), last one 376.
    let frame = datagram(1480, 0);
    let sent = fragment(&frame, 576);
    assert_eq!(
        sent,
        [
            expected_fragment(&frame, 0, 552, true),
            expected_fragment(&frame, 552, 552, true),
            expected_fragment(&frame, 1104, 376, false),
        ]
    );
    for (index, bytes) in sent.iter().enumerate() {
        assert!(bytes.len() - 14 <= 576);
        assert_eq!(reference_checksum(&bytes[14..34]), 0, "fragment {index}");
        assert_eq!(&bytes[18..20], &[0x12, 0x34], "same ID");
    }
    // Spot check the wire bytes of the second fragment's header.
    assert_eq!(&sent[1][16..18], &572_u16.to_be_bytes());
    assert_eq!(&sent[1][20..22], &(0x2000_u16 | 69).to_be_bytes());
}

#[test]
fn an_mtu_that_is_not_a_multiple_of_8_rounds_the_block_down() {
    // MTU 1006: 986 bytes of room, 984-byte blocks (123 * 8).
    let frame = datagram(2000, 0);
    let sent = fragment(&frame, 1006);
    assert_eq!(
        sent,
        [
            expected_fragment(&frame, 0, 984, true),
            expected_fragment(&frame, 984, 984, true),
            expected_fragment(&frame, 1968, 32, false),
        ]
    );
}

#[test]
fn one_byte_over_the_mtu_leaves_a_one_byte_last_fragment() {
    // MTU 576, datagram 577: 552 + 5 data bytes.
    let frame = datagram(557, 0);
    let sent = fragment(&frame, 576);
    assert_eq!(
        sent,
        [
            expected_fragment(&frame, 0, 552, true),
            expected_fragment(&frame, 552, 5, false),
        ]
    );
    assert_eq!(sent[1].len(), 14 + 25);
}

#[test]
fn a_fragment_is_refragmented_with_its_offset_and_mf() {
    // A middle fragment (MF=1, offset 100): every piece keeps MF.
    let middle = datagram(1200, 0x2000 | 100);
    assert_eq!(
        fragment(&middle, 576),
        [
            expected_fragment(&middle, 0, 552, true),
            expected_fragment(&middle, 552, 552, true),
            expected_fragment(&middle, 1104, 96, true),
        ]
    );
    let sent = fragment(&middle, 576);
    assert_eq!(&sent[2][20..22], &(0x2000_u16 | (100 + 138)).to_be_bytes());
    // The last fragment (MF=0, offset 100): only the last piece clears MF.
    let last = datagram(1200, 100);
    assert_eq!(
        fragment(&last, 576),
        [
            expected_fragment(&last, 0, 552, true),
            expected_fragment(&last, 552, 552, true),
            expected_fragment(&last, 1104, 96, false),
        ]
    );
}

#[test]
fn the_reserved_flag_is_carried_into_every_fragment() {
    let frame = datagram(1000, 0x8000);
    let sent = fragment(&frame, 576);
    assert_eq!(
        sent,
        [
            expected_fragment(&frame, 0, 552, true),
            expected_fragment(&frame, 552, 448, false),
        ]
    );
    assert_eq!(&sent[1][20..22], &(0x8000_u16 | 69).to_be_bytes());
}

#[test]
fn padding_after_total_length_is_not_sent() {
    let mut padded = datagram(600, 0);
    let clean = padded.clone();
    padded.extend_from_slice(&[0xff; 6]);
    assert_eq!(
        fragment(&padded, 576),
        [
            expected_fragment(&clean, 0, 552, true),
            expected_fragment(&clean, 552, 48, false),
        ]
    );
}

#[test]
fn the_worst_case_sends_1365_fragments_of_48_bytes() {
    let frame = datagram(65_515, 0);
    let mut storage = Storage::new(1, 65_535);
    let mut runtime = storage.runtime(Ipv4FragmentationPolicy::DEFAULT);
    let plan = runtime.plan(&frame, 68).unwrap();
    runtime.stage(&frame, plan, EGRESS);
    let mut io = FakeIo {
        max_frame: 14 + 68,
        ..FakeIo::default()
    };
    let report = execute_one_ipv4_fragmentation(&mut io, &mut runtime).unwrap();
    assert_eq!(report.outcome, Ipv4FragmentOutcome::Sent);
    assert_eq!(io.capacity_checks, [(EGRESS, 1365, 14 + 68)]);
    assert_eq!(io.sent.len(), 1365);
    for (index, (_, bytes)) in io.sent.iter().enumerate() {
        let start = index * 48;
        let len = 48.min(65_515 - start);
        assert_eq!(*bytes, expected_fragment(&frame, start, len, index < 1364));
    }
    assert_eq!(runtime.counters().fragments, 1365);
}

#[test]
fn a_refused_set_sends_nothing_and_counts_the_reason() {
    let frame = datagram(1480, 0);
    let mut storage = Storage::new(4, 1500);
    let mut runtime = storage.runtime(Ipv4FragmentationPolicy::DEFAULT);
    for _ in 0..3 {
        let plan = runtime.plan(&frame, 576).unwrap();
        runtime.stage(&frame, plan, EGRESS);
    }
    assert_eq!(runtime.pending(), 3);
    let mut refusing = FakeIo {
        refuse: Some(GeneratedAllocationError::Unavailable),
        ..io()
    };
    let report = execute_one_ipv4_fragmentation(&mut refusing, &mut runtime).unwrap();
    assert_eq!(
        report.outcome,
        Ipv4FragmentOutcome::Refused(GeneratedAllocationError::Unavailable)
    );
    assert_eq!(report.completion.attempts, 0);
    assert!(refusing.sent.is_empty());
    // The check asks for the whole set at the first fragment's length.
    assert_eq!(refusing.capacity_checks, [(EGRESS, 3, 14 + 572)]);
    let mut small = FakeIo {
        max_frame: 500,
        ..FakeIo::default()
    };
    let report = execute_one_ipv4_fragmentation(&mut small, &mut runtime).unwrap();
    assert_eq!(
        report.outcome,
        Ipv4FragmentOutcome::Refused(GeneratedAllocationError::FrameTooLarge)
    );
    assert!(small.sent.is_empty());
    let mut ok = io();
    execute_one_ipv4_fragmentation(&mut ok, &mut runtime).unwrap();
    assert_eq!(ok.sent.len(), 3);
    assert_eq!(
        runtime.counters(),
        Ipv4FragmentationCounters {
            queued: 3,
            fragmented: 1,
            fragments: 3,
            dropped_unavailable: 1,
            dropped_frame_too_large: 1,
            incomplete: 0,
            flushed: 0,
        }
    );
    assert_eq!(runtime.pending(), 0);
}

#[test]
fn a_backend_fault_after_the_check_is_counted_incomplete() {
    let frame = datagram(1480, 0);
    let mut storage = Storage::new(2, 1500);
    let mut runtime = storage.runtime(Ipv4FragmentationPolicy::DEFAULT);
    for _ in 0..2 {
        let plan = runtime.plan(&frame, 576).unwrap();
        runtime.stage(&frame, plan, EGRESS);
    }
    let mut failing = FakeIo {
        fail_allocation: Some(1),
        ..io()
    };
    let report = execute_one_ipv4_fragmentation(&mut failing, &mut runtime).unwrap();
    assert_eq!(
        report.outcome,
        Ipv4FragmentOutcome::AllocationFailed {
            committed: 1,
            error: GeneratedAllocationError::Unavailable,
        }
    );
    assert_eq!(failing.sent.len(), 1);
    assert_eq!(failing.sent[0].1, expected_fragment(&frame, 0, 552, true));
    let mut short = FakeIo {
        short_lease: Some(2),
        ..io()
    };
    let report = execute_one_ipv4_fragmentation(&mut short, &mut runtime).unwrap();
    assert_eq!(
        report.outcome,
        Ipv4FragmentOutcome::WrongLength { committed: 2 }
    );
    assert_eq!(short.sent.len(), 2);
    assert_eq!(short.cancelled, 1);
    assert_eq!(report.completion.cancelled, 1);
    let counters = runtime.counters();
    assert_eq!(counters.incomplete, 2);
    assert_eq!(counters.fragments, 3);
    assert_eq!(counters.fragmented, 0);
}

#[test]
fn datagrams_leave_in_order_and_the_table_is_reused() {
    let first = datagram(700, 0);
    let second = datagram(900, 0);
    let mut storage = Storage::new(2, 1500);
    let mut runtime = storage.runtime(Ipv4FragmentationPolicy::DEFAULT);
    let plan = runtime.plan(&first, 576).unwrap();
    runtime.stage(&first, plan, IfId(1));
    let plan = runtime.plan(&second, 576).unwrap();
    runtime.stage(&second, plan, IfId(3));
    let mut sink = io();
    execute_one_ipv4_fragmentation(&mut sink, &mut runtime).unwrap();
    assert_eq!(runtime.pending(), 1);
    execute_one_ipv4_fragmentation(&mut sink, &mut runtime).unwrap();
    assert_eq!(runtime.pending(), 0);
    assert_eq!(
        sink.sent,
        [
            (IfId(1), expected_fragment(&first, 0, 552, true)),
            (IfId(1), expected_fragment(&first, 552, 148, false)),
            (IfId(3), expected_fragment(&second, 0, 552, true)),
            (IfId(3), expected_fragment(&second, 552, 348, false)),
        ]
    );
    // Both slots are free again.
    for _ in 0..2 {
        let plan = runtime.plan(&first, 576).unwrap();
        runtime.stage(&first, plan, IfId(1));
    }
    assert_eq!(runtime.pending(), 2);
    assert_eq!(runtime.flush(), 2);
    assert_eq!(runtime.pending(), 0);
    assert_eq!(runtime.flush(), 0);
    assert_eq!(runtime.counters().flushed, 2);
    assert_eq!(runtime.counters().queued, 4);
    assert!(execute_one_ipv4_fragmentation(&mut sink, &mut runtime).is_none());
    assert!(runtime.plan(&first, 576).is_ok());
}

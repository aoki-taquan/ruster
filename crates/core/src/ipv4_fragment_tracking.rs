//! IPv4 fragment association for the NAT and the stateful firewall
//! (NAT-FRAG, RFC 4787 REQ-14, RFC 5382 §5, RFC 5508 §5, RFC 1858,
//! RFC 3128, RFC 6864 §5.3.1).
//!
//! Only the first fragment of a datagram (offset 0) carries the transport
//! header, so the NAT and the firewall can only decide on it. This module
//! keeps a bounded, keyed association table so that every later fragment of
//! the same datagram gets that first fragment's decision:
//!
//! - The key is the datagram as received: (ingress interface, source,
//!   destination, protocol, Identification), RFC 791 §3.2's reassembly key
//!   plus the ingress, so a fragment arriving on another interface never
//!   follows a decision it was not part of.
//! - The first fragment goes through the normal forwarding, firewall, and
//!   NAT decision with its transport header. When it is forwarded, the entry
//!   records how it was rewritten (an [`Ipv4FragmentTemplate`]: egress, the
//!   Ethernet addresses, the translated source and destination, and the
//!   IPv4 ID it left with, generated once for a translated non-atomic
//!   datagram per NAT44-126). When it is refused, the entry records the
//!   refusal.
//! - A later fragment with an allowing entry is rewritten with the template
//!   (TTL decremented, header checksum recomputed) and forwarded, or
//!   re-fragmented when it is above the egress MTU. A later fragment with a
//!   refusing entry is `IPV4_FRAGMENT_FIRST_DENIED`.
//! - Out of order (RFC 4787 REQ-14): a later fragment that arrives before its
//!   first fragment is copied into a core-owned held slot (option (a),
//!   bounded buffering) and consumed as `IPV4_FRAGMENT_HELD`. When the first
//!   fragment is allowed, the held fragments are rewritten with its template
//!   and staged in the fragmentation slots, which send them in the tick's
//!   generated fragment phase; when it is refused, or nothing arrives within
//!   the timeout, they are discarded and counted.
//!
//! Attacks on the transport header (RFC 1858, RFC 3128): the first fragment
//! must hold the whole transport header (the forwarding validators require
//! the UDP, ICMP, or TCP header including options within the fragment) and
//! a non-last fragment must carry a multiple of 8 data bytes; a later
//! fragment that starts inside the first fragment's transport header (for
//! TCP, RFC 1858's offset 1 rule generalized to the header length; offset 1
//! and 2 always) is `IPV4_FRAGMENT_TRANSPORT_HEADER_OVERLAP`, so no fragment
//! can rewrite the ports or the TCP flags the decision was made on.
//!
//! Two datagrams with one key (the key leaves out the ports: an ID reused
//! after a lost fragment, or a server answering two inside hosts behind one
//! public address with the same ID) must not share a decision. A second
//! first fragment for a decided datagram is `IPV4_FRAGMENT_DUPLICATE_FIRST`;
//! unless it is byte-identical to the first one (same length and a 32-bit
//! fingerprint of all its data, a network duplicate), it poisons the entry:
//! every remaining fragment of both datagrams is refused, which fails
//! closed. The fingerprint covers all the data because a prefix is not
//! enough (a checksum-0 UDP tunnel repeats its header); it costs one pass
//! over each first fragment, never over a later fragment or a whole frame. The datagram's
//! end is fixed by the first fragment with MF clear; a fragment that
//! contradicts it (another end, data past it) is `IPV4_FRAGMENT_MALFORMED`
//! and poisons the entry too.
//!
//! Bounds: a fixed number of entries and of held fragments, a per-(ingress,
//! source) limit on each, one timeout from the first fragment seen. An entry
//! is freed earlier once every data byte from 0 to the datagram's end was
//! seen: up to four disjoint data ranges are tracked exactly (duplicates and
//! overlaps count once; more pieces leave the entry to the timeout). Entries
//! all live for the same timeout, so they expire in creation order: an age
//! list makes expiry O(1) per entry with no scan. When the table or a
//! host's quota or an ingress's share is full, the oldest pending or
//! refusing entry of that scope is evicted, else the allowing one with the
//! oldest progress (a fragment that added data) if it stalled for a fifth
//! of the timeout; each scope keeps both classes on their own lists, so a
//! victim is found in O(1), and victims are evicted only once the whole
//! admission is known to succeed. Held slots are shared between ingresses
//! the same way. An evicted key that allowed its datagram is remembered (a
//! tombstone) until the timeout: a new first fragment on it is refused, so
//! its late fragments never follow another datagram's template. An evicted
//! entry that only ever refused leaves none: nothing of its datagram was
//! forwarded, but a later datagram on the reused key is not protected from
//! having the refused datagram's late fragments held and released with it
//! (a mix only of refused fragments into a new datagram, which the
//! transport checksum mostly detects; residual FRAG-012). Every table is
//! caller-owned storage sized once from the config; there is no allocation,
//! no lock, and no copy on the fast path (a frame that is not a fragment
//! costs one read of the flags word).
//!
//! The table is flushed at every publication apply (its templates name the
//! previous publication's egress and neighbors), counting what it held.
//!
//! # Standards
//!
//! - RFC 4787 REQ-14, RFC 5382 section 5 and RFC 5508 section 5: every fragment of
//!   a datagram gets its first fragment's NAT and firewall decision; fragments that
//!   arrive before it are held, a bounded number.
//! - RFC 1858 and RFC 3128: tiny and overlapping fragments are refused.
//! - RFC 6864 section 5.3.1: a translated non-atomic datagram gets one new IPv4 ID.
//!
//! Deviations: a later fragment starting at offset 1 or 2 is refused for every
//! protocol (RFC 1858 asks it for TCP); the table's limits (entries, per source,
//! held per source) and its key's ingress interface drop fragments past them or
//! from another interface.

use std::{marker::PhantomData, rc::Rc};

use crate::{
    fixed_directory::{DirectoryHashDomain, FixedDirectory},
    ipv4_header_checksum, packet, DirectoryBucket, DirectoryNode, DropReason, ForwardingSnapshot,
    HighWaterMark, IfId, Ipv4FragmentationRuntime, ResolutionHashKey, TableOccupancy,
};

const NONE: u32 = u32::MAX;
const IPV4_HEADER_LEN: usize = 20;
const FLAG_DONT_FRAGMENT: u16 = 0x4000;
const FLAG_MORE_FRAGMENTS: u16 = 0x2000;
const OFFSET_MASK: u16 = 0x1fff;
/// Data bytes of the largest IPv4 datagram (65535 minus a 20-byte header).
const MAX_DATAGRAM_DATA: u32 = u16::MAX as u32 - IPV4_HEADER_LEN as u32;

/// Default association timeout from the first fragment seen: long enough for
/// any reordering on a path, short enough that a lost fragment frees its
/// entry quickly. A local policy, not an RFC value (RFC 791 §3.2's 15 s is a
/// host reassembly timer).
pub const IPV4_FRAGMENT_TRACKING_DEFAULT_TIMEOUT_MS: u32 = 5_000;
/// Shortest `timeout-ms`.
pub const IPV4_FRAGMENT_TRACKING_MIN_TIMEOUT_MS: u32 = 100;
/// Longest `timeout-ms` (RFC 1122 §3.3.2 suggests 60 to 120 s for a host's
/// whole reassembly; a router holds memory for others, so 60 s is the cap).
pub const IPV4_FRAGMENT_TRACKING_MAX_TIMEOUT_MS: u32 = 60_000;
/// Default `ingress-share-percent`: the entries one ingress interface may
/// take, as a percentage of the table, so a flood arriving on one
/// interface cannot take the entries of datagrams from the others.
pub const IPV4_FRAGMENT_TRACKING_DEFAULT_INGRESS_SHARE_PERCENT: u8 = 50;
/// Most fragments one datagram may hold before its first fragment arrives.
pub const IPV4_FRAGMENT_TRACKING_HELD_PER_DATAGRAM: u16 = 16;
/// Most distinct ingress interfaces the table accounts (the config's
/// interface limit); a datagram from another one is refused.
pub const IPV4_FRAGMENT_TRACKING_MAX_INGRESSES: usize = 256;

/// Fragment association policy: the timeout and the per-source limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4FragmentTrackingPolicy {
    timeout_ms: u32,
    entries_per_host: u32,
    held_per_host: u32,
    ingress_share_percent: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ipv4FragmentTrackingPolicyError {
    /// `timeout-ms` outside
    /// [`IPV4_FRAGMENT_TRACKING_MIN_TIMEOUT_MS`]..=[`IPV4_FRAGMENT_TRACKING_MAX_TIMEOUT_MS`].
    TimeoutOutOfRange,
    /// `entries-per-host` is 0 (no fragment could ever be associated).
    EntriesPerHostZero,
    /// `ingress-share-percent` outside 1..=100.
    IngressShareOutOfRange,
}

impl Ipv4FragmentTrackingPolicy {
    /// `held_per_host` 0 refuses every fragment that arrives before its
    /// first fragment (`IPV4_FRAGMENT_HOST_HOLD_LIMIT`).
    pub const fn new(
        timeout_ms: u32,
        entries_per_host: u32,
        held_per_host: u32,
    ) -> Result<Self, Ipv4FragmentTrackingPolicyError> {
        if timeout_ms < IPV4_FRAGMENT_TRACKING_MIN_TIMEOUT_MS
            || timeout_ms > IPV4_FRAGMENT_TRACKING_MAX_TIMEOUT_MS
        {
            return Err(Ipv4FragmentTrackingPolicyError::TimeoutOutOfRange);
        }
        if entries_per_host == 0 {
            return Err(Ipv4FragmentTrackingPolicyError::EntriesPerHostZero);
        }
        Ok(Self {
            timeout_ms,
            entries_per_host,
            held_per_host,
            ingress_share_percent: IPV4_FRAGMENT_TRACKING_DEFAULT_INGRESS_SHARE_PERCENT,
        })
    }

    /// The share of the table (1 to 100 percent, rounded down, at least one
    /// entry) the datagrams of one ingress interface may take; 100 does not
    /// partition the table.
    pub const fn with_ingress_share_percent(
        mut self,
        percent: u8,
    ) -> Result<Self, Ipv4FragmentTrackingPolicyError> {
        if percent == 0 || percent > 100 {
            return Err(Ipv4FragmentTrackingPolicyError::IngressShareOutOfRange);
        }
        self.ingress_share_percent = percent;
        Ok(self)
    }

    #[must_use]
    pub const fn ingress_share_percent(self) -> u8 {
        self.ingress_share_percent
    }

    #[must_use]
    pub const fn timeout_ms(self) -> u32 {
        self.timeout_ms
    }

    #[must_use]
    pub const fn entries_per_host(self) -> u32 {
        self.entries_per_host
    }

    #[must_use]
    pub const fn held_per_host(self) -> u32 {
        self.held_per_host
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum EntryState {
    #[default]
    Free,
    /// Only later fragments have arrived; they are held.
    Pending,
    /// The first fragment was forwarded with the template.
    Allow,
    /// The first fragment was refused.
    Deny,
}

/// The rewrite of a forwarded first fragment, applied to every later
/// fragment of its datagram: Ethernet destination and source, translated
/// IPv4 source and destination, the IPv4 ID it left with, and its egress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4FragmentTemplate {
    pub(crate) egress: IfId,
    macs: [u8; 12],
    source: [u8; 4],
    destination: [u8; 4],
    id: u16,
    /// Bytes of the first fragment's transport header: no later fragment
    /// may start inside it.
    transport_header_len: u8,
    /// The datagram is the router's own (from the kernel's interface): its TTL
    /// stays, as the first fragment's did.
    keeps_ttl: bool,
}

impl Ipv4FragmentTemplate {
    /// Reads the template from a first fragment rewritten for `egress`
    /// (Ethernet header, IPv4 header, its transport header). Every path that
    /// admits a fragment refuses IPv4 options, but the transport header is
    /// found from the IHL all the same.
    pub(crate) fn capture(frame: &[u8], egress: IfId) -> Option<Self> {
        let header = packet::ETHERNET_HEADER_LEN;
        let ipv4 = frame.get(header..header + IPV4_HEADER_LEN)?;
        let transport = header + usize::from(ipv4[0] & 0x0f) * 4;
        let transport_header_len = if ipv4[9] == 6 {
            let data_offset = *frame.get(transport + 12)?;
            (data_offset >> 4) * 4
        } else {
            8
        };
        Some(Self {
            egress,
            macs: frame.get(0..12)?.try_into().ok()?,
            source: ipv4[12..16].try_into().ok()?,
            destination: ipv4[16..20].try_into().ok()?,
            id: u16::from_be_bytes([ipv4[4], ipv4[5]]),
            transport_header_len,
            keeps_ttl: false,
        })
    }

    /// The same template for a datagram whose TTL stays (the router's own).
    pub(crate) const fn keeping_ttl(self, keeps_ttl: bool) -> Self {
        Self { keeps_ttl, ..self }
    }

    /// Rewrites a later fragment (validated, 20-byte header, TTL above 1
    /// unless it keeps its TTL) like its first fragment: Ethernet addresses, ID,
    /// addresses, TTL - 1 (unchanged for the router's own), and a recomputed
    /// header checksum.
    pub(crate) fn apply(self, frame: &mut [u8]) -> Result<(), DropReason> {
        let header = packet::ETHERNET_HEADER_LEN;
        if frame.len() < header + IPV4_HEADER_LEN {
            return Err(DropReason::Ipv4HeaderTruncated);
        }
        let hop = u8::from(!self.keeps_ttl);
        if frame[header + 8] <= hop {
            return Err(DropReason::Ipv4TtlExpired);
        }
        frame[0..12].copy_from_slice(&self.macs);
        frame[header + 4..header + 6].copy_from_slice(&self.id.to_be_bytes());
        frame[header + 8] -= hop;
        frame[header + 12..header + 16].copy_from_slice(&self.source);
        frame[header + 16..header + 20].copy_from_slice(&self.destination);
        frame[header + 10..header + 12].copy_from_slice(&[0, 0]);
        let checksum = ipv4_header_checksum(&frame[header..header + IPV4_HEADER_LEN]);
        frame[header + 10..header + 12].copy_from_slice(&checksum.to_be_bytes());
        Ok(())
    }

    pub(crate) const fn transport_header_len(self) -> u32 {
        self.transport_header_len as u32
    }
}

/// RFC 791 §3.2's reassembly key plus the ingress interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4FragmentKey {
    ingress: IfId,
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    id: u16,
}

impl Ipv4FragmentKey {
    fn words(self) -> [u64; 3] {
        [
            u64::from(self.ingress.0),
            (u64::from(u32::from_be_bytes(self.source)) << 32)
                | u64::from(u32::from_be_bytes(self.destination)),
            (u64::from(self.protocol) << 16) | u64::from(self.id),
        ]
    }
}

/// One received fragment: its key and where its data lies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4FragmentInfo {
    pub(crate) key: Ipv4FragmentKey,
    /// Fragment Offset in bytes.
    pub(crate) offset: u32,
    /// Data bytes (Total Length minus the header).
    pub(crate) data_len: u32,
    pub(crate) more: bool,
    pub(crate) dont_fragment: bool,
    /// [`fingerprint`] of every data byte of a first fragment (0 for a later
    /// one): with its length, the identity of a byte-identical duplicate.
    pub(crate) fingerprint: u32,
}

impl Ipv4FragmentInfo {
    pub(crate) const fn is_first(self) -> bool {
        self.offset == 0
    }

    /// RFC 791 structure of a fragment, the same for first and later ones:
    /// some data, a multiple of 8 data bytes unless it is the last, and no
    /// data past the largest datagram.
    pub(crate) const fn check_structure(self) -> Result<(), DropReason> {
        if self.data_len == 0
            || (self.more && !self.data_len.is_multiple_of(8))
            || self.offset + self.data_len > MAX_DATAGRAM_DATA
        {
            return Err(DropReason::Ipv4FragmentMalformed);
        }
        Ok(())
    }

    /// RFC 1858 §3.2 (offset 1 for TCP) generalized: a later fragment that
    /// starts inside the smallest transport header of its protocol (20
    /// bytes for TCP, 8 for UDP and ICMP) could rewrite what the first
    /// fragment's decision was made on.
    pub(crate) const fn check_static_overlap(self) -> Result<(), DropReason> {
        let minimum = if self.key.protocol == 6 { 20 } else { 8 };
        if self.offset != 0 && self.offset < minimum {
            return Err(DropReason::Ipv4FragmentTransportHeaderOverlap);
        }
        Ok(())
    }
}

/// Reads the fragment fields of a frame whose IPv4 header was validated.
/// `None` for a whole datagram (MF clear and offset 0).
pub(crate) fn parse_fragment(
    frame: &[u8],
    ipv4: packet::ValidatedIpv4,
    ingress: IfId,
) -> Option<Ipv4FragmentInfo> {
    let flags = packet::read_u16(frame, ipv4.header_offset + 6)?;
    let more = flags & FLAG_MORE_FRAGMENTS != 0;
    let offset = u32::from(flags & OFFSET_MASK) * 8;
    if !more && offset == 0 {
        return None;
    }
    let data_start = ipv4.header_offset + ipv4.header_len;
    let data_end = ipv4.header_offset + ipv4.total_len;
    // Only a first fragment needs it (cold path, once per first fragment).
    let fingerprint = if offset == 0 {
        fingerprint(frame.get(data_start..data_end)?)
    } else {
        0
    };
    Some(Ipv4FragmentInfo {
        key: Ipv4FragmentKey {
            ingress,
            source: ipv4.source.octets(),
            destination: ipv4.destination.octets(),
            protocol: ipv4.protocol,
            id: packet::read_u16(frame, ipv4.header_offset + 4)?,
        },
        offset,
        data_len: u32::try_from(ipv4.total_len.checked_sub(ipv4.header_len)?).ok()?,
        more,
        dont_fragment: flags & FLAG_DONT_FRAGMENT != 0,
        fingerprint,
    })
}

/// A fingerprint of every byte of `data`: four independent 64-bit lanes,
/// each taking every fourth 8-byte word through a step that is a bijection
/// of the lane for a given word and of the word for a given lane (xor,
/// multiply by the odd FNV-1a 64 prime, rotate). Two inputs of one length
/// that differ in a single word therefore always differ in that word's
/// lane; inputs that differ in several words of one lane differ in it
/// unless those differences cancel, which no structure makes likelier
/// than any 64-bit collision. The lanes and the length are folded to 32
/// bits with the MurmurHash3 finalizer.
/// Deterministic and unkeyed: it only tells a network duplicate from
/// another first fragment (a checksum-0 tunnel repeats its header, so no
/// prefix would do), and is about a word per byte-step of FNV-1a's cost.
fn fingerprint(data: &[u8]) -> u32 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let step = |lane: u64, word: u64| (lane ^ word).wrapping_mul(PRIME).rotate_left(29);
    let mut lanes: [u64; 4] = [
        0xcbf2_9ce4_8422_2325,
        0x8422_2325_cbf2_9ce4,
        0x9e37_79b9_7f4a_7c15,
        0x7f4a_7c15_9e37_79b9,
    ];
    let mut chunks = data.chunks_exact(32);
    for chunk in &mut chunks {
        for (lane, word) in lanes.iter_mut().zip(chunk.chunks_exact(8)) {
            let word = u64::from_le_bytes(word.try_into().expect("8-byte word"));
            *lane = step(*lane, word);
        }
    }
    for (index, byte) in chunks.remainder().iter().enumerate() {
        lanes[index % 4] = step(lanes[index % 4], u64::from(*byte) | 0x100);
    }
    let fmix = |mut value: u64| {
        value ^= value >> 33;
        value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
        value ^= value >> 33;
        value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        value ^ (value >> 33)
    };
    let mut hash = data.len() as u64;
    for lane in lanes {
        hash = fmix(hash ^ fmix(lane)).wrapping_add(lane);
    }
    let hash = fmix(hash);
    (hash ^ (hash >> 32)) as u32
}

/// Coverage ranges an entry tracks exactly (RFC 815's hole list, inverted):
/// a datagram arriving in more disjoint pieces than this is no longer
/// tracked and its entry lives until the timeout.
const COVERAGE_RANGES: usize = 4;

/// The intrusive lists an entry is on, each as `[older, newer]` links:
/// - `AGE`: every live entry in creation order (expiry; the free list uses
///   its `newer` link while the slot is free);
/// - `CLASS`, `HOST`, `INGRESS`: the table's, the host's, and the
///   ingress's list of the entry's class: pending and refusing entries in
///   the order they became evictable, or allowing entries by last progress
///   (least recent first);
/// - `HELD`: the ingress's pending entries that hold fragments, oldest
///   first.
const AGE: usize = 0;
const CLASS: usize = 1;
const HOST: usize = 2;
const INGRESS: usize = 3;
const HELD: usize = 4;
const LISTS: usize = 5;
const OLDER: usize = 0;
const NEWER: usize = 1;

/// A list's oldest and newest entry.
type Ends = [u32; 2];
const NO_ENDS: Ends = [NONE, NONE];

/// No ingress slot (the over-share list of ingresses).
const NO_SLOT: u16 = u16::MAX;

/// Slots of the ingress map: twice the most ingresses, open addressing.
const INGRESS_MAP: usize = 2 * IPV4_FRAGMENT_TRACKING_MAX_INGRESSES;

/// One association entry (caller-owned storage).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4FragmentEntrySlot {
    state: EntryState,
    /// A second, different first fragment or an inconsistent end turned the
    /// entry into a refusal for good (no early completion).
    poisoned: bool,
    /// The entry has allowed its datagram at some point (it may be
    /// poisoned since): only such an entry leaves a tombstone when evicted.
    was_allowed: bool,
    key: Ipv4FragmentKey,
    template: Ipv4FragmentTemplate,
    created_ms: u64,
    /// The last time a fragment of the datagram added data (not a
    /// duplicate), in ms after `created_ms` (a live entry is younger than
    /// the timeout, at most 60000 ms).
    progress_ms: u16,
    host: u32,
    held_head: u32,
    held_tail: u32,
    held: u16,
    /// The decided first fragment: whether there was one, its data length,
    /// and a fingerprint of all its data (a byte-identical duplicate is
    /// dropped alone; any other second first fragment poisons the entry).
    has_first: bool,
    first_len: u16,
    first_fingerprint: u32,
    /// The datagram's data length, fixed by the first fragment with MF clear
    /// (0 before), and the largest data end seen: both at most 65515.
    total: u16,
    max_end: u16,
    /// Disjoint, sorted data ranges seen; `untracked` once more were needed.
    ranges: [[u16; 2]; COVERAGE_RANGES],
    ranges_len: u8,
    untracked: bool,
    links: [[u32; 2]; LISTS],
}

impl Ipv4FragmentEntrySlot {
    pub const EMPTY: Self = Self {
        state: EntryState::Free,
        poisoned: false,
        was_allowed: false,
        key: Ipv4FragmentKey {
            ingress: IfId(0),
            source: [0; 4],
            destination: [0; 4],
            protocol: 0,
            id: 0,
        },
        template: Ipv4FragmentTemplate {
            egress: IfId(0),
            macs: [0; 12],
            source: [0; 4],
            destination: [0; 4],
            id: 0,
            transport_header_len: 0,
            keeps_ttl: false,
        },
        created_ms: 0,
        progress_ms: 0,
        host: NONE,
        held_head: NONE,
        held_tail: NONE,
        held: 0,
        has_first: false,
        first_len: 0,
        first_fingerprint: 0,
        total: 0,
        max_end: 0,
        ranges: [[0; 2]; COVERAGE_RANGES],
        ranges_len: 0,
        untracked: false,
        links: [[NONE; 2]; LISTS],
    };

    /// Records the data range of one fragment: `Ok(true)` when it added
    /// data (a new end, a larger end, or bytes not covered before),
    /// `Ok(false)` for a duplicate. `Err` when it contradicts what was seen:
    /// a second, different end (MF clear), or data past the end. Duplicates
    /// and overlaps count once. Past [`COVERAGE_RANGES`] disjoint pieces the
    /// entry is `untracked` (it no longer completes early) and the ranges
    /// over-approximate: the two closest ranges are merged, so they still
    /// cover every byte seen, a fragment inside one of them is a duplicate,
    /// and progress is bounded by the datagram's size (a replayed piece
    /// never counts twice). The trade-off: a fragment that fills a gap
    /// inside a merged range counts as a duplicate too, so it does not
    /// refresh the stall timer (its datagram already arrived in more pieces
    /// than the table tracks).
    fn record(&mut self, offset: u32, len: u32, more: bool) -> Result<bool, ()> {
        if self.poisoned {
            return Ok(false);
        }
        // Data ends at most 65515 bytes in (`parse_fragment`).
        let end = u16::try_from(offset + len).map_err(|_| ())?;
        let before = (self.total, self.max_end, self.untracked);
        if !more {
            if (self.total != 0 && self.total != end) || self.max_end > end {
                return Err(());
            }
            self.total = end;
        } else if self.total != 0 && end > self.total {
            return Err(());
        }
        self.max_end = self.max_end.max(end);
        // The offset is below the end, which fits 16 bits.
        let (mut start, mut stop) = (offset as u16, end);
        let mut merged = [[0_u16; 2]; COVERAGE_RANGES + 1];
        let mut count = 0;
        let mut placed = false;
        for range in &self.ranges[..usize::from(self.ranges_len)] {
            if range[1] < start {
                merged[count] = *range;
                count += 1;
            } else if range[0] > stop {
                if !placed {
                    merged[count] = [start, stop];
                    count += 1;
                    placed = true;
                }
                merged[count] = *range;
                count += 1;
            } else {
                start = start.min(range[0]);
                stop = stop.max(range[1]);
            }
        }
        if !placed {
            merged[count] = [start, stop];
            count += 1;
        }
        if count > COVERAGE_RANGES {
            // Over-approximate: close the smallest gap.
            self.untracked = true;
            let at = (0..count - 1)
                .min_by_key(|&index| merged[index + 1][0] - merged[index][1])
                .expect("at least two ranges");
            merged[at][1] = merged[at + 1][1];
            merged.copy_within(at + 2..count, at + 1);
            count -= 1;
            merged[count] = [0, 0];
        }
        let mut ranges = [[0_u16; 2]; COVERAGE_RANGES];
        ranges.copy_from_slice(&merged[..COVERAGE_RANGES]);
        let count = u8::try_from(count).expect("at most COVERAGE_RANGES");
        let grew = before != (self.total, self.max_end, self.untracked)
            || count != self.ranges_len
            || ranges != self.ranges;
        self.ranges = ranges;
        self.ranges_len = count;
        Ok(grew)
    }

    /// Every data byte from 0 to the datagram's end was seen.
    fn complete(&self) -> bool {
        !self.poisoned
            && !self.untracked
            && self.total != 0
            && self.ranges_len == 1
            && u32::from(self.ranges[0][0]) == 0
            && self.ranges[0][1] == self.total
    }
}

impl Default for Ipv4FragmentEntrySlot {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Appends `index` to the `list` whose ends are `ends`.
fn push(entries: &mut [Ipv4FragmentEntrySlot], ends: &mut Ends, index: u32, list: usize) {
    let previous = ends[NEWER];
    entries[index as usize].links[list] = [previous, NONE];
    if previous == NONE {
        ends[OLDER] = index;
    } else {
        entries[previous as usize].links[list][NEWER] = index;
    }
    ends[NEWER] = index;
}

/// Removes `index` from the `list` whose ends are `ends`.
fn remove(entries: &mut [Ipv4FragmentEntrySlot], ends: &mut Ends, index: u32, list: usize) {
    let [older, newer] = entries[index as usize].links[list];
    if older == NONE {
        ends[OLDER] = newer;
    } else {
        entries[older as usize].links[list][NEWER] = newer;
    }
    if newer == NONE {
        ends[NEWER] = older;
    } else {
        entries[newer as usize].links[list][OLDER] = older;
    }
    entries[index as usize].links[list] = [NONE; 2];
}

/// Per-(ingress, source) accounting (caller-owned storage, one per entry).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4FragmentHostSlot {
    ingress: IfId,
    /// Index of the ingress slot of `ingress`.
    ingress_slot: u16,
    address: [u8; 4],
    entries: u32,
    held: u32,
    next_free: u32,
    /// The host's pending and refusing entries, and its allowing entries.
    evict: Ends,
    allow: Ends,
}

impl Ipv4FragmentHostSlot {
    pub const EMPTY: Self = Self {
        ingress: IfId(0),
        ingress_slot: 0,
        address: [0; 4],
        entries: 0,
        held: 0,
        next_free: NONE,
        evict: NO_ENDS,
        allow: NO_ENDS,
    };

    fn words(ingress: IfId, address: [u8; 4]) -> [u64; 2] {
        [u64::from(ingress.0), u64::from(u32::from_be_bytes(address))]
    }
}

impl Default for Ipv4FragmentHostSlot {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// One held fragment's record; its frame is in the held bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4FragmentHeldSlot {
    next: u32,
    frame_len: u32,
}

impl Ipv4FragmentHeldSlot {
    pub const EMPTY: Self = Self {
        next: NONE,
        frame_len: 0,
    };
}

impl Default for Ipv4FragmentHeldSlot {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// An evicted key that allowed its datagram and when it was evicted
/// (caller-owned storage, [`ipv4_fragment_tracking_tombstones`] of them).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4FragmentTombstoneSlot {
    key: Ipv4FragmentKey,
    live: bool,
    at_ms: u64,
}

impl Ipv4FragmentTombstoneSlot {
    pub const EMPTY: Self = Self {
        key: Ipv4FragmentEntrySlot::EMPTY.key,
        live: false,
        at_ms: 0,
    };
}

impl Default for Ipv4FragmentTombstoneSlot {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Entries of one ingress interface, its class lists, its pending entries
/// that hold fragments, and its place on the over-share list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IngressSlot {
    id: IfId,
    entries: u32,
    evict: Ends,
    allow: Ends,
    holding: Ends,
    /// Held fragments of the ingress's datagrams.
    held: u32,
    over: bool,
    over_previous: u16,
    over_next: u16,
}

impl IngressSlot {
    const EMPTY: Self = Self {
        id: IfId(0),
        entries: 0,
        evict: NO_ENDS,
        allow: NO_ENDS,
        holding: NO_ENDS,
        held: 0,
        over: false,
        over_previous: NO_SLOT,
        over_next: NO_SLOT,
    };
}

/// The entries chosen for eviction before any is evicted (an admission
/// evicts at most one per scope: held slots, host, ingress, table).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Victims {
    chosen: [u32; 4],
    len: usize,
}

impl Victims {
    const EMPTY: Self = Self {
        chosen: [NONE; 4],
        len: 0,
    };

    fn contains(&self, index: u32) -> bool {
        self.chosen[..self.len].contains(&index)
    }

    fn push(&mut self, index: u32) {
        self.chosen[self.len] = index;
        self.len += 1;
    }

    fn as_slice(&self) -> &[u32] {
        &self.chosen[..self.len]
    }
}

/// Buckets of each directory for `entries` entries (a power of two, at
/// least `entries`; 0 for none).
#[must_use]
pub const fn ipv4_fragment_tracking_buckets(entries: usize) -> usize {
    if entries == 0 {
        0
    } else {
        entries.next_power_of_two()
    }
}

/// Tombstone slots for `entries` entries: one per sixteen entries, at
/// least 16 (0 for none).
#[must_use]
pub const fn ipv4_fragment_tracking_tombstones(entries: usize) -> usize {
    if entries == 0 {
        0
    } else if entries / 16 > 16 {
        entries / 16
    } else {
        16
    }
}

/// The entries one ingress may take: `share` percent of `entries`,
/// rounded down, at least one.
#[must_use]
pub const fn ipv4_fragment_tracking_ingress_cap(entries: usize, share_percent: u8) -> usize {
    let cap = entries * share_percent as usize / 100;
    if cap == 0 {
        1
    } else {
        cap
    }
}

/// Caller-owned storage of an [`Ipv4FragmentTracker`]: `entries` entry
/// slots, as many host slots, a bucket array of
/// [`ipv4_fragment_tracking_buckets`] and a node per slot for each of the
/// two directories, [`ipv4_fragment_tracking_tombstones`] tombstone slots
/// with their own bucket array and nodes, and `held` held records with
/// `held × slot` bytes.
pub struct Ipv4FragmentTrackingStorage<'a> {
    pub entries: &'a mut [Ipv4FragmentEntrySlot],
    pub entry_buckets: &'a mut [DirectoryBucket],
    pub entry_nodes: &'a mut [DirectoryNode],
    pub hosts: &'a mut [Ipv4FragmentHostSlot],
    pub host_buckets: &'a mut [DirectoryBucket],
    pub host_nodes: &'a mut [DirectoryNode],
    pub tombstones: &'a mut [Ipv4FragmentTombstoneSlot],
    pub tombstone_buckets: &'a mut [DirectoryBucket],
    pub tombstone_nodes: &'a mut [DirectoryNode],
    pub held: &'a mut [Ipv4FragmentHeldSlot],
    pub held_bytes: &'a mut [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ipv4FragmentTrackingStorageError {
    /// No entry slot: nothing could be associated.
    NoEntries,
    /// Host slots, tombstone slots, nodes, or buckets do not match the
    /// entry count.
    Shape,
    /// The held bytes are not `held × slot` for a slot of at least one
    /// minimum-MTU datagram and at most 14 + 65535 bytes.
    HeldBytes,
}

/// Cumulative fragment association counters (never reset by a publication).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv4FragmentTrackingCounters {
    /// First fragments forwarded; their entry allows the later fragments.
    pub first_allowed: usize,
    /// First fragments refused; their entry refuses the later fragments.
    pub first_denied: usize,
    /// Later fragments forwarded (or re-fragmented) on arrival.
    pub followed: usize,
    /// Later fragments refused because their first fragment was (or the
    /// key's entry was evicted after it allowed its datagram, a tombstone).
    pub followed_denied: usize,
    /// Later fragments held because their first fragment had not arrived.
    pub held: usize,
    /// Held fragments rewritten and staged in the fragmentation slots when
    /// their first fragment was allowed (staged, not yet sent: the
    /// `fragmentation.*` counters report what the backend took).
    pub released: usize,
    /// Held fragments discarded at release: TTL, transport header overlap,
    /// DF above the egress MTU, or no fragmentation slot.
    pub release_dropped: usize,
    /// Held fragments discarded because their first fragment was refused
    /// or their entry was poisoned.
    pub held_denied: usize,
    /// Held fragments discarded because no first fragment came in time.
    pub held_expired: usize,
    /// Entries freed by the timeout.
    pub entries_expired: usize,
    /// Entries freed early: every data byte from 0 to the datagram's end
    /// was seen and decided (duplicates and overlaps count once; a fragment
    /// counts when the table answered for it, before the backend took it).
    pub entries_completed: usize,
    /// Entries evicted to make room for a new datagram or a held fragment:
    /// pending or refusing ones (oldest first), or an allowing one without
    /// progress for a fifth of the timeout (its datagram stalled).
    pub entries_evicted: usize,
    /// Held fragments discarded with an evicted entry.
    pub held_evicted: usize,
    /// Entries turned into a refusal for good: a second, different first
    /// fragment for a decided datagram (an ID reused, or two datagrams with
    /// one key), a fragment contradicting the datagram's end, or a first
    /// fragment on the key of an evicted entry that allowed its datagram.
    pub poisoned: usize,
    /// Byte-identical duplicate first fragments dropped alone.
    pub duplicate_first: usize,
    /// Entries discarded by a publication apply.
    pub entries_flushed: usize,
    /// Held fragments discarded by a publication apply.
    pub held_flushed: usize,
    /// Tombstones overwritten before their timeout (more evictions of
    /// entries that allowed their datagram within a timeout than tombstone slots):
    /// those keys are no longer refused.
    pub tombstones_overwritten: usize,
}

/// A first fragment admitted before its decision: it either continues a
/// pending entry or will take a new one (room made).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4FragmentFirstTicket {
    info: Ipv4FragmentInfo,
    existing: Option<u32>,
    /// The entries a new entry evicts, evicted only when the first fragment
    /// commits (an ARP-held first fragment, which does not commit, evicts
    /// nothing).
    victims: Victims,
}

/// What the table says about a later fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ipv4FragmentFollow {
    Allow {
        entry: u32,
        template: Ipv4FragmentTemplate,
    },
    Deny,
    /// No decision yet: the fragment was held.
    Held,
}

/// Occupancy of an [`Ipv4FragmentTracker`]; see
/// [`Ipv4FragmentTracker::occupancy`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv4FragmentTrackingOccupancy {
    /// Live entries (pending, allowing, or refusing; expired ones until
    /// expiry frees them).
    pub entries: TableOccupancy,
    /// Held later fragments.
    pub held: TableOccupancy,
}

/// Caller-backed, worker-local fragment association table.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::Ipv4FragmentTracker<'static>>();
/// ```
pub struct Ipv4FragmentTracker<'a> {
    policy: Ipv4FragmentTrackingPolicy,
    entries: &'a mut [Ipv4FragmentEntrySlot],
    entry_directory: FixedDirectory<'a>,
    hosts: &'a mut [Ipv4FragmentHostSlot],
    host_directory: FixedDirectory<'a>,
    tombstones: &'a mut [Ipv4FragmentTombstoneSlot],
    tombstone_directory: FixedDirectory<'a>,
    held: &'a mut [Ipv4FragmentHeldSlot],
    held_bytes: &'a mut [u8],
    held_slot_bytes: usize,
    free_entry: u32,
    free_host: u32,
    free_held: u32,
    /// Every live entry in creation order, and the table's class lists.
    age: Ends,
    evict: Ends,
    allow: Ends,
    /// Entries per ingress interface (`ingress_len` used), found through
    /// `ingress_map` (slot + 1, 0 empty, open addressing), and the share
    /// of the entries (`ingress_cap`) and of the held slots (`held_cap`)
    /// each may take. `over_head` lists the ingresses holding more than
    /// `held_cap` fragments.
    ingresses: [IngressSlot; IPV4_FRAGMENT_TRACKING_MAX_INGRESSES],
    ingress_map: [u16; INGRESS_MAP],
    ingress_len: usize,
    ingress_cap: u32,
    held_cap: u32,
    over_head: u16,
    tombstone_next: usize,
    live_entries: usize,
    live_held: usize,
    /// Whether anything may have been written since the last reset. Every
    /// operation that can change the table sets it first; a flush of a table
    /// that was not touched has nothing to discard, and only changes the key.
    touched: bool,
    /// Largest `live_entries` and `live_held` since construction or the
    /// last flush (OBS-017).
    entries_high_water: HighWaterMark,
    held_high_water: HighWaterMark,
    counters: Ipv4FragmentTrackingCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> Ipv4FragmentTracker<'a> {
    /// Builds an empty table over `storage`, keyed by the publication's
    /// resolution key in its own hash domains.
    pub fn new(
        policy: Ipv4FragmentTrackingPolicy,
        storage: Ipv4FragmentTrackingStorage<'a>,
        key: ResolutionHashKey,
    ) -> Result<Self, Ipv4FragmentTrackingStorageError> {
        let Ipv4FragmentTrackingStorage {
            entries,
            entry_buckets,
            entry_nodes,
            hosts,
            host_buckets,
            host_nodes,
            tombstones,
            tombstone_buckets,
            tombstone_nodes,
            held,
            held_bytes,
        } = storage;
        let count = entries.len();
        if count == 0 {
            return Err(Ipv4FragmentTrackingStorageError::NoEntries);
        }
        let buckets = ipv4_fragment_tracking_buckets(count);
        let tombstone_count = ipv4_fragment_tracking_tombstones(count);
        if count >= NONE as usize
            || hosts.len() != count
            || entry_nodes.len() != count
            || host_nodes.len() != count
            || entry_buckets.len() != buckets
            || host_buckets.len() != buckets
            || tombstones.len() != tombstone_count
            || tombstone_nodes.len() != tombstone_count
            || tombstone_buckets.len() != ipv4_fragment_tracking_buckets(tombstone_count)
        {
            return Err(Ipv4FragmentTrackingStorageError::Shape);
        }
        let held_slot_bytes = if held.is_empty() {
            if !held_bytes.is_empty() {
                return Err(Ipv4FragmentTrackingStorageError::HeldBytes);
            }
            0
        } else {
            let slot = held_bytes.len() / held.len();
            if held.len() >= NONE as usize
                || slot * held.len() != held_bytes.len()
                || slot < packet::ETHERNET_HEADER_LEN + usize::from(crate::IPV4_MIN_MTU)
                || slot > packet::ETHERNET_HEADER_LEN + usize::from(u16::MAX)
            {
                return Err(Ipv4FragmentTrackingStorageError::HeldBytes);
            }
            slot
        };
        let directory_key = key.directory_key();
        let entry_directory = FixedDirectory::new(entry_buckets, entry_nodes, directory_key)
            .map_err(|_| Ipv4FragmentTrackingStorageError::Shape)?;
        let host_directory = FixedDirectory::new(host_buckets, host_nodes, directory_key)
            .map_err(|_| Ipv4FragmentTrackingStorageError::Shape)?;
        let tombstone_directory =
            FixedDirectory::new(tombstone_buckets, tombstone_nodes, directory_key)
                .map_err(|_| Ipv4FragmentTrackingStorageError::Shape)?;
        let share = policy.ingress_share_percent;
        let held_cap = if share >= 100 {
            0
        } else {
            ipv4_fragment_tracking_ingress_cap(held.len(), share)
        };
        let mut tracker = Self {
            policy,
            entries,
            entry_directory,
            hosts,
            host_directory,
            tombstones,
            tombstone_directory,
            held,
            held_bytes,
            held_slot_bytes,
            free_entry: NONE,
            free_host: NONE,
            free_held: NONE,
            age: NO_ENDS,
            evict: NO_ENDS,
            allow: NO_ENDS,
            ingresses: [IngressSlot::EMPTY; IPV4_FRAGMENT_TRACKING_MAX_INGRESSES],
            ingress_map: [0; INGRESS_MAP],
            ingress_len: 0,
            ingress_cap: u32::try_from(ipv4_fragment_tracking_ingress_cap(count, share))
                .unwrap_or(u32::MAX),
            held_cap: u32::try_from(held_cap).unwrap_or(u32::MAX),
            over_head: NO_SLOT,
            tombstone_next: 0,
            live_entries: 0,
            live_held: 0,
            touched: true,
            entries_high_water: HighWaterMark::default(),
            held_high_water: HighWaterMark::default(),
            counters: Ipv4FragmentTrackingCounters::default(),
            _worker_local: PhantomData,
        };
        tracker.reset();
        Ok(tracker)
    }

    #[must_use]
    pub const fn policy(&self) -> Ipv4FragmentTrackingPolicy {
        self.policy
    }

    #[must_use]
    pub const fn counters(&self) -> Ipv4FragmentTrackingCounters {
        self.counters
    }

    /// Live entries (pending, allowing, or refusing).
    #[must_use]
    pub const fn entries(&self) -> usize {
        self.live_entries
    }

    /// Held fragments.
    #[must_use]
    pub const fn held(&self) -> usize {
        self.live_held
    }

    #[must_use]
    pub const fn entry_capacity(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn held_capacity(&self) -> usize {
        self.held.len()
    }

    /// Live entries and held fragments with their high-water marks since
    /// construction or the last flush (a publication apply), and the
    /// capacities (OBS-017). O(1).
    #[must_use]
    pub const fn occupancy(&self) -> Ipv4FragmentTrackingOccupancy {
        Ipv4FragmentTrackingOccupancy {
            entries: self
                .entries_high_water
                .snapshot(self.live_entries, self.entries.len()),
            held: self
                .held_high_water
                .snapshot(self.live_held, self.held.len()),
        }
    }

    /// Discards every entry, held fragment, and tombstone (entries and
    /// held fragments counted as flushed). A publication apply calls it:
    /// the templates name the old publication's egress and neighbors.
    pub fn flush(&mut self) {
        if !self.touched {
            self.debug_assert_as_reset();
            return;
        }
        self.counters.entries_flushed += self.live_entries;
        self.counters.held_flushed += self.live_held;
        self.reset();
    }

    /// [`Self::flush`] and rekey with the new publication's key.
    pub fn flush_with_key(&mut self, key: ResolutionHashKey) {
        if !self.touched {
            // Every slot and directory is as a reset left it: only the key
            // changes, without going through the storage.
            self.debug_assert_as_reset();
            self.entry_directory.rekey_empty(key.directory_key());
            self.host_directory.rekey_empty(key.directory_key());
            self.tombstone_directory.rekey_empty(key.directory_key());
            return;
        }
        self.counters.entries_flushed += self.live_entries;
        self.counters.held_flushed += self.live_held;
        self.entry_directory.clear_with_key(key.directory_key());
        self.host_directory.clear_with_key(key.directory_key());
        self.tombstone_directory.clear_with_key(key.directory_key());
        self.reset();
    }

    /// That the table is as [`Self::reset`] left it, as `touched` being unset
    /// promises. Cheap: what any write leaves behind shows in one of these.
    fn debug_assert_as_reset(&self) {
        debug_assert_eq!(
            (
                self.live_entries,
                self.live_held,
                self.ingress_len,
                self.tombstone_next
            ),
            (0, 0, 0, 0),
            "an untouched fragment table holds nothing"
        );
        debug_assert!(
            self.age == NO_ENDS && self.evict == NO_ENDS && self.allow == NO_ENDS,
            "an untouched fragment table lists nothing"
        );
    }

    fn reset(&mut self) {
        self.entry_directory.clear();
        self.host_directory.clear();
        self.tombstone_directory.clear();
        let count = self.entries.len();
        for (index, slot) in self.entries.iter_mut().enumerate() {
            *slot = Ipv4FragmentEntrySlot::EMPTY;
            slot.links[AGE][NEWER] = next_index(index, count);
        }
        for (index, slot) in self.hosts.iter_mut().enumerate() {
            *slot = Ipv4FragmentHostSlot::EMPTY;
            slot.next_free = next_index(index, count);
        }
        self.tombstones.fill(Ipv4FragmentTombstoneSlot::EMPTY);
        let held = self.held.len();
        for (index, slot) in self.held.iter_mut().enumerate() {
            *slot = Ipv4FragmentHeldSlot::EMPTY;
            slot.next = next_index(index, held);
        }
        self.free_entry = if count == 0 { NONE } else { 0 };
        self.free_host = if count == 0 { NONE } else { 0 };
        self.free_held = if held == 0 { NONE } else { 0 };
        self.age = NO_ENDS;
        self.evict = NO_ENDS;
        self.allow = NO_ENDS;
        self.ingresses = [IngressSlot::EMPTY; IPV4_FRAGMENT_TRACKING_MAX_INGRESSES];
        self.ingress_map = [0; INGRESS_MAP];
        self.ingress_len = 0;
        self.over_head = NO_SLOT;
        self.tombstone_next = 0;
        self.live_entries = 0;
        self.live_held = 0;
        self.entries_high_water.reset(0);
        self.held_high_water.reset(0);
        self.touched = false;
    }

    /// Frees every entry older than the timeout at `now_ms`, at most
    /// `budget` of them, and returns how many it freed. Expiry is otherwise
    /// lazy (each table operation expires up to two of the oldest entries);
    /// a caller can call this with a small budget so that the occupancy and
    /// the expiry counters stay current without traffic.
    pub fn sweep(&mut self, now_ms: u64, budget: usize) -> usize {
        self.touched = true;
        let before = self.live_entries;
        self.expire(now_ms, budget);
        before - self.live_entries
    }

    fn expired(&self, index: usize, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.entries[index].created_ms) >= u64::from(self.policy.timeout_ms)
    }

    /// Frees expired entries from the oldest; at most `budget` of them.
    fn expire(&mut self, now_ms: u64, budget: usize) {
        for _ in 0..budget {
            let oldest = self.age[OLDER];
            if oldest == NONE || !self.expired(oldest as usize, now_ms) {
                return;
            }
            self.counters.entries_expired += 1;
            let held = self.free_entry_at(oldest as usize);
            self.counters.held_expired += held;
        }
    }

    fn lookup(&mut self, key: Ipv4FragmentKey, now_ms: u64) -> Option<usize> {
        let entries = &*self.entries;
        let probe = self
            .entry_directory
            .lookup(
                DirectoryHashDomain::Ipv4FragmentAssociation,
                &key.words(),
                |index| entries[index].state != EntryState::Free && entries[index].key == key,
            )
            .ok()?;
        let index = probe.state_index?;
        if self.expired(index, now_ms) {
            self.counters.entries_expired += 1;
            let held = self.free_entry_at(index);
            self.counters.held_expired += held;
            return None;
        }
        Some(index)
    }

    fn host_of(&self, ingress: IfId, address: [u8; 4]) -> Option<usize> {
        let hosts = &*self.hosts;
        self.host_directory
            .lookup(
                DirectoryHashDomain::Ipv4FragmentHost,
                &Ipv4FragmentHostSlot::words(ingress, address),
                |index| {
                    hosts[index].entries != 0
                        && hosts[index].ingress == ingress
                        && hosts[index].address == address
                },
            )
            .ok()?
            .state_index
    }

    /// The ingress map's home slot for `ingress` (Fibonacci hashing).
    fn ingress_home(ingress: IfId) -> usize {
        (u32::from(ingress.0).wrapping_mul(0x9e37_79b1) >> 23) as usize % INGRESS_MAP
    }

    /// The slot of `ingress`, found in O(1) expected: the map holds at most
    /// half as many ingresses as it has slots.
    fn ingress_of(&self, ingress: IfId) -> Option<usize> {
        let mut at = Self::ingress_home(ingress);
        for _ in 0..INGRESS_MAP {
            let slot = self.ingress_map[at];
            if slot == 0 {
                return None;
            }
            if self.ingresses[usize::from(slot - 1)].id == ingress {
                return Some(usize::from(slot - 1));
            }
            at = (at + 1) % INGRESS_MAP;
        }
        None
    }

    /// The slot of `ingress`, added when new; `None` once every slot is
    /// taken.
    fn ingress_slot(&mut self, ingress: IfId) -> Option<usize> {
        if let Some(slot) = self.ingress_of(ingress) {
            return Some(slot);
        }
        if self.ingress_len == IPV4_FRAGMENT_TRACKING_MAX_INGRESSES {
            return None;
        }
        let slot = self.ingress_len;
        self.ingresses[slot] = IngressSlot {
            id: ingress,
            ..IngressSlot::EMPTY
        };
        self.ingress_len += 1;
        let mut at = Self::ingress_home(ingress);
        while self.ingress_map[at] != 0 {
            at = (at + 1) % INGRESS_MAP;
        }
        self.ingress_map[at] = u16::try_from(slot + 1).expect("at most 256 ingresses");
        Some(slot)
    }

    /// The ingress slot of a live entry.
    fn ingress_of_entry(&self, index: u32) -> usize {
        usize::from(self.hosts[self.entries[index as usize].host as usize].ingress_slot)
    }

    /// Puts an entry on the class lists of its state (table, host, ingress).
    fn class_link(&mut self, index: u32) {
        let entry = self.entries[index as usize];
        let host = entry.host as usize;
        let ingress = self.ingress_of_entry(index);
        if entry.state == EntryState::Allow {
            self.entries[index as usize].was_allowed = true;
            push(self.entries, &mut self.allow, index, CLASS);
            push(self.entries, &mut self.hosts[host].allow, index, HOST);
            push(
                self.entries,
                &mut self.ingresses[ingress].allow,
                index,
                INGRESS,
            );
        } else {
            push(self.entries, &mut self.evict, index, CLASS);
            push(self.entries, &mut self.hosts[host].evict, index, HOST);
            push(
                self.entries,
                &mut self.ingresses[ingress].evict,
                index,
                INGRESS,
            );
        }
    }

    /// Takes an entry off the class lists of its state.
    fn class_unlink(&mut self, index: u32) {
        let entry = self.entries[index as usize];
        let host = entry.host as usize;
        let ingress = self.ingress_of_entry(index);
        if entry.state == EntryState::Allow {
            remove(self.entries, &mut self.allow, index, CLASS);
            remove(self.entries, &mut self.hosts[host].allow, index, HOST);
            remove(
                self.entries,
                &mut self.ingresses[ingress].allow,
                index,
                INGRESS,
            );
        } else {
            remove(self.entries, &mut self.evict, index, CLASS);
            remove(self.entries, &mut self.hosts[host].evict, index, HOST);
            remove(
                self.entries,
                &mut self.ingresses[ingress].evict,
                index,
                INGRESS,
            );
        }
    }

    /// Moves a live entry to `state`, with its class lists.
    fn set_state(&mut self, index: usize, state: EntryState) {
        let id = u32::try_from(index).expect("entry index below NONE");
        self.class_unlink(id);
        self.entries[index].state = state;
        self.class_link(id);
    }

    /// A fragment added data to the entry's datagram: an allowing entry
    /// moves to the recent end of its class lists.
    fn touch(&mut self, index: usize, now_ms: u64) {
        let since = now_ms.saturating_sub(self.entries[index].created_ms);
        self.entries[index].progress_ms = u16::try_from(since).unwrap_or(u16::MAX);
        if self.entries[index].state == EntryState::Allow {
            let id = u32::try_from(index).expect("entry index below NONE");
            self.class_unlink(id);
            self.class_link(id);
        }
    }

    /// An allowing entry without progress for a fifth of the timeout: its
    /// datagram stalled (fragments of one datagram arrive within
    /// milliseconds; a spoofed first fragment never gets the rest). Only a
    /// fragment that adds bytes to the ranges is progress (see
    /// `Ipv4FragmentEntrySlot::record`): a replay is not, also once the
    /// ranges over-approximate.
    fn stalled(&self, index: u32, now_ms: u64) -> bool {
        let entry = &self.entries[index as usize];
        now_ms.saturating_sub(entry.created_ms + u64::from(entry.progress_ms))
            >= u64::from((self.policy.timeout_ms / 5).max(1))
    }

    /// The entry to evict from a scope with class lists `evict` and `allow`
    /// on `list`, other than the `chosen` ones (O(1): at most four are
    /// skipped): the oldest pending or refusing one, else the allowing one
    /// with the oldest progress if it stalled, else none.
    fn victim(&self, evict: Ends, allow: Ends, list: usize, chosen: &Victims, now_ms: u64) -> u32 {
        let mut current = evict[OLDER];
        while current != NONE && chosen.contains(current) {
            current = self.entries[current as usize].links[list][NEWER];
        }
        if current != NONE {
            return current;
        }
        let mut current = allow[OLDER];
        while current != NONE && chosen.contains(current) {
            current = self.entries[current as usize].links[list][NEWER];
        }
        if current != NONE && self.stalled(current, now_ms) {
            current
        } else {
            NONE
        }
    }

    /// The oldest entry of ingress `slot` that holds fragments, other than
    /// `own` and the `chosen` ones.
    fn oldest_holder(&self, slot: usize, own: Option<usize>, chosen: &Victims) -> u32 {
        let mut current = self.ingresses[slot].holding[OLDER];
        while current != NONE && (chosen.contains(current) || own == Some(current as usize)) {
            current = self.entries[current as usize].links[HELD][NEWER];
        }
        current
    }

    /// The entry whose held fragments make room for one more of ingress
    /// `requester` (O(1)): its own oldest holder when it is at its share of
    /// the held slots, else the oldest holder of an ingress over its share,
    /// else its own oldest holder; never `own` (the datagram the room is
    /// for). A flood from one ingress thus only displaces its own held
    /// fragments, or those of an ingress over its share. With a share of
    /// 100 percent an ingress holding anything is over it, and the
    /// requester's own holders go first.
    fn held_victim(&self, requester: Option<usize>, own: Option<usize>, chosen: &Victims) -> u32 {
        if let Some(slot) = requester {
            if self.ingresses[slot].held >= self.held_cap {
                let victim = self.oldest_holder(slot, own, chosen);
                if victim != NONE {
                    return victim;
                }
            }
        }
        // Skipped holders are at most `own` and four chosen: past a few
        // ingresses one with a usable holder is found.
        let mut slot = self.over_head;
        for _ in 0..8 {
            if slot == NO_SLOT {
                break;
            }
            // The requester, when it is over its share, was tried above.
            let victim = self.oldest_holder(usize::from(slot), own, chosen);
            if victim != NONE {
                return victim;
            }
            slot = self.ingresses[usize::from(slot)].over_next;
        }
        requester.map_or(NONE, |slot| self.oldest_holder(slot, own, chosen))
    }

    /// Puts ingress `slot` on or off the over-share list after its held
    /// count changed.
    fn update_over(&mut self, slot: usize) {
        let over = self.ingresses[slot].held > self.held_cap;
        if over == self.ingresses[slot].over {
            return;
        }
        let id = u16::try_from(slot).expect("at most 256 ingresses");
        if over {
            self.ingresses[slot].over_previous = NO_SLOT;
            self.ingresses[slot].over_next = self.over_head;
            if self.over_head != NO_SLOT {
                self.ingresses[usize::from(self.over_head)].over_previous = id;
            }
            self.over_head = id;
        } else {
            let previous = self.ingresses[slot].over_previous;
            let next = self.ingresses[slot].over_next;
            if previous == NO_SLOT {
                self.over_head = next;
            } else {
                self.ingresses[usize::from(previous)].over_next = next;
            }
            if next != NO_SLOT {
                self.ingresses[usize::from(next)].over_previous = previous;
            }
            self.ingresses[slot].over_previous = NO_SLOT;
            self.ingresses[slot].over_next = NO_SLOT;
        }
        self.ingresses[slot].over = over;
    }

    /// Discards an entry to make room (counted). One that ever allowed its
    /// datagram (allowing still, or poisoned since) leaves a tombstone: a
    /// new first fragment on its key could be another datagram reusing it,
    /// and its late fragments must not be held for one. An entry that only
    /// ever refused leaves none: its fragments were never forwarded, so a
    /// later datagram on the key cannot be mixed with forwarded ones, and a
    /// flood of refused first fragments cannot churn the tombstones.
    fn evict(&mut self, index: u32, now_ms: u64) {
        self.counters.entries_evicted += 1;
        let entry = self.entries[index as usize];
        if entry.was_allowed {
            self.entomb(entry.key, now_ms);
        }
        let held = self.free_entry_at(index as usize);
        self.counters.held_evicted += held;
    }

    /// Remembers `key` as evicted at `now_ms` in the oldest tombstone slot.
    fn entomb(&mut self, key: Ipv4FragmentKey, now_ms: u64) {
        let slot = self.tombstone_next;
        let old = self.tombstones[slot];
        if old.live {
            if now_ms.saturating_sub(old.at_ms) < u64::from(self.policy.timeout_ms) {
                self.counters.tombstones_overwritten += 1;
            }
            let _ = self.tombstone_directory.unlink(slot);
        }
        self.tombstones[slot] = Ipv4FragmentTombstoneSlot {
            key,
            live: true,
            at_ms: now_ms,
        };
        let linked = self.tombstone_directory.link(
            slot,
            DirectoryHashDomain::Ipv4FragmentTombstone,
            &key.words(),
        );
        if linked.is_err() {
            self.tombstones[slot] = Ipv4FragmentTombstoneSlot::EMPTY;
        }
        self.tombstone_next = (slot + 1) % self.tombstones.len();
    }

    /// Whether `key`'s entry was evicted, after it allowed its datagram, within the
    /// timeout (O(1), keyed lookup).
    fn tombstoned(&self, key: Ipv4FragmentKey, now_ms: u64) -> bool {
        let tombstones = &*self.tombstones;
        let timeout = u64::from(self.policy.timeout_ms);
        self.tombstone_directory
            .lookup(
                DirectoryHashDomain::Ipv4FragmentTombstone,
                &key.words(),
                |index| {
                    let tombstone = tombstones[index];
                    tombstone.live
                        && tombstone.key == key
                        && now_ms.saturating_sub(tombstone.at_ms) < timeout
                },
            )
            .is_ok_and(|probe| probe.state_index.is_some())
    }

    /// How many `chosen` victims belong to host `host`, and to ingress
    /// `slot`.
    fn chosen_in(&self, chosen: &Victims, host: Option<usize>, slot: Option<usize>) -> [u32; 2] {
        let mut counts = [0; 2];
        for &victim in chosen.as_slice() {
            let entry_host = self.entries[victim as usize].host as usize;
            if host == Some(entry_host) {
                counts[0] += 1;
            }
            if slot == Some(usize::from(self.hosts[entry_host].ingress_slot)) {
                counts[1] += 1;
            }
        }
        counts
    }

    /// Chooses, without evicting anything, the victims that make room for a
    /// new entry of `ingress`/`source` beside the `chosen` ones: at the
    /// host's limit, the ingress's share, or a full table, that scope's
    /// victim (see [`Self::victim`]). `Err` when a scope has none: then
    /// nothing is evicted at all. Only an allowing template ever forwards
    /// a later fragment, so evicting a pending or refusing entry can only
    /// turn later fragments into refusals or new holds; one that allowed
    /// (stalled, or poisoned since) leaves a tombstone. The table scope
    /// takes the table's oldest evictable entry without preferring an
    /// ingress over its share: while the shares do not overlap (share × n
    /// ≤ 100), the requester's own share is reached first and its victim
    /// also makes the table's room, so the table scope only decides when
    /// the shares overlap, which `ruster validate` warns about.
    fn plan_room(
        &self,
        ingress: IfId,
        source: [u8; 4],
        chosen: &mut Victims,
        now_ms: u64,
    ) -> Result<(), DropReason> {
        let host = self.host_of(ingress, source);
        let slot = self.ingress_of(ingress);
        if let Some(host) = host {
            let [taken, _] = self.chosen_in(chosen, Some(host), None);
            if self.hosts[host].entries - taken >= self.policy.entries_per_host {
                let ends = self.hosts[host];
                let victim = self.victim(ends.evict, ends.allow, HOST, chosen, now_ms);
                if victim == NONE {
                    return Err(DropReason::Ipv4FragmentHostLimit);
                }
                chosen.push(victim);
            }
        }
        match slot {
            // 100 percent does not partition: a full table decides.
            Some(slot) if (self.ingress_cap as usize) < self.entries.len() => {
                let [_, taken] = self.chosen_in(chosen, None, Some(slot));
                if self.ingresses[slot].entries - taken >= self.ingress_cap {
                    let ends = self.ingresses[slot];
                    let victim = self.victim(ends.evict, ends.allow, INGRESS, chosen, now_ms);
                    if victim == NONE {
                        return Err(DropReason::Ipv4FragmentIngressLimit);
                    }
                    chosen.push(victim);
                }
            }
            None if self.ingress_len == IPV4_FRAGMENT_TRACKING_MAX_INGRESSES => {
                return Err(DropReason::Ipv4FragmentIngressLimit);
            }
            _ => {}
        }
        if self.free_entry == NONE && chosen.len == 0 {
            let victim = self.victim(self.evict, self.allow, CLASS, chosen, now_ms);
            if victim == NONE {
                return Err(DropReason::Ipv4FragmentTableFull);
            }
            chosen.push(victim);
        }
        Ok(())
    }

    /// Evicts the chosen victims (the whole admission was planned).
    fn evict_all(&mut self, chosen: &Victims, now_ms: u64) {
        for &victim in chosen.as_slice() {
            self.evict(victim, now_ms);
        }
    }

    /// Takes a free entry for `key` (room made by `plan_room`).
    fn insert_entry(
        &mut self,
        key: Ipv4FragmentKey,
        state: EntryState,
        now_ms: u64,
    ) -> Option<usize> {
        let index = self.free_entry;
        if index == NONE {
            return None;
        }
        let ingress = self.ingress_slot(key.ingress)?;
        let host = match self.host_of(key.ingress, key.source) {
            Some(host) => host,
            None => {
                let host = self.free_host;
                if host == NONE {
                    return None;
                }
                self.host_directory
                    .link(
                        host as usize,
                        DirectoryHashDomain::Ipv4FragmentHost,
                        &Ipv4FragmentHostSlot::words(key.ingress, key.source),
                    )
                    .ok()?;
                self.free_host = self.hosts[host as usize].next_free;
                self.hosts[host as usize] = Ipv4FragmentHostSlot {
                    ingress: key.ingress,
                    ingress_slot: u16::try_from(ingress).expect("at most 256 ingresses"),
                    address: key.source,
                    ..Ipv4FragmentHostSlot::EMPTY
                };
                host as usize
            }
        };
        if self
            .entry_directory
            .link(
                index as usize,
                DirectoryHashDomain::Ipv4FragmentAssociation,
                &key.words(),
            )
            .is_err()
        {
            self.release_host_if_empty(host);
            return None;
        }
        self.free_entry = self.entries[index as usize].links[AGE][NEWER];
        self.hosts[host].entries += 1;
        self.ingresses[ingress].entries += 1;
        self.entries[index as usize] = Ipv4FragmentEntrySlot {
            state,
            key,
            created_ms: now_ms,
            host: u32::try_from(host).expect("host index below NONE"),
            ..Ipv4FragmentEntrySlot::EMPTY
        };
        push(self.entries, &mut self.age, index, AGE);
        self.class_link(index);
        self.live_entries += 1;
        self.entries_high_water.observe(self.live_entries);
        Some(index as usize)
    }

    fn release_host_if_empty(&mut self, host: usize) {
        if self.hosts[host].entries == 0 {
            let _ = self.host_directory.unlink(host);
            self.hosts[host] = Ipv4FragmentHostSlot {
                next_free: self.free_host,
                ..Ipv4FragmentHostSlot::EMPTY
            };
            self.free_host = u32::try_from(host).expect("host index below NONE");
        }
    }

    /// Frees a live entry and its held fragments; returns how many were held.
    fn free_entry_at(&mut self, index: usize) -> usize {
        let held = self.free_held_of(index);
        let id = u32::try_from(index).expect("entry index below NONE");
        self.class_unlink(id);
        remove(self.entries, &mut self.age, id, AGE);
        let host = self.entries[index].host as usize;
        let _ = self.entry_directory.unlink(index);
        let ingress = usize::from(self.hosts[host].ingress_slot);
        self.ingresses[ingress].entries = self.ingresses[ingress].entries.saturating_sub(1);
        self.hosts[host].entries = self.hosts[host].entries.saturating_sub(1);
        self.release_host_if_empty(host);
        self.entries[index] = Ipv4FragmentEntrySlot::EMPTY;
        self.entries[index].links[AGE][NEWER] = self.free_entry;
        self.free_entry = id;
        self.live_entries -= 1;
        held
    }

    /// Returns every held fragment of an entry to the free list.
    fn free_held_of(&mut self, index: usize) -> usize {
        if self.entries[index].held == 0 {
            return 0;
        }
        let id = u32::try_from(index).expect("entry index below NONE");
        let slot = self.ingress_of_entry(id);
        remove(self.entries, &mut self.ingresses[slot].holding, id, HELD);
        let mut count = 0;
        let mut current = self.entries[index].held_head;
        while current != NONE {
            let next = self.held[current as usize].next;
            self.held[current as usize] = Ipv4FragmentHeldSlot {
                next: self.free_held,
                frame_len: 0,
            };
            self.free_held = current;
            count += 1;
            current = next;
        }
        let entry = &mut self.entries[index];
        entry.held_head = NONE;
        entry.held_tail = NONE;
        entry.held = 0;
        let freed = u32::try_from(count).unwrap_or(u32::MAX);
        let host = entry.host as usize;
        self.hosts[host].held = self.hosts[host].held.saturating_sub(freed);
        self.ingresses[slot].held = self.ingresses[slot].held.saturating_sub(freed);
        self.update_over(slot);
        self.live_held -= count;
        count
    }

    /// Turns an entry into a refusal for good: what it held is discarded,
    /// every later fragment is refused, and it lives until the timeout (or
    /// is evicted, leaving a tombstone). Both datagrams that share the key
    /// fail closed.
    fn poison(&mut self, index: usize) {
        self.counters.poisoned += 1;
        let held = self.free_held_of(index);
        self.counters.held_denied += held;
        if self.entries[index].state != EntryState::Deny {
            self.set_state(index, EntryState::Deny);
        }
        self.entries[index].poisoned = true;
    }

    /// Frees an entry once its whole datagram was seen.
    fn complete_if_covered(&mut self, index: usize) {
        if self.entries[index].state != EntryState::Free
            && self.entries[index].held_head == NONE
            && self.entries[index].complete()
        {
            self.counters.entries_completed += 1;
            self.free_entry_at(index);
        }
    }

    /// Records one fragment's data in a live entry (progress when it added
    /// data); a contradiction poisons it and is `IPV4_FRAGMENT_MALFORMED`.
    fn record(
        &mut self,
        index: usize,
        info: Ipv4FragmentInfo,
        now_ms: u64,
    ) -> Result<(), DropReason> {
        match self.entries[index].record(info.offset, info.data_len, info.more) {
            Err(()) => {
                self.poison(index);
                Err(DropReason::Ipv4FragmentMalformed)
            }
            Ok(grew) => {
                if grew {
                    self.touch(index, now_ms);
                }
                Ok(())
            }
        }
    }

    /// Admits a first fragment before its decision: a pending entry
    /// continues; a decided one drops a byte-identical duplicate alone and
    /// is poisoned by any other first fragment (`IPV4_FRAGMENT_DUPLICATE_FIRST`
    /// either way); the key of an evicted entry that allowed its datagram is
    /// refused the same way (a tombstone); a new one needs room (evicting
    /// victims only when all the room it needs can be made). Changes
    /// nothing else.
    pub(crate) fn admit_first(
        &mut self,
        info: Ipv4FragmentInfo,
        now_ms: u64,
    ) -> Result<Ipv4FragmentFirstTicket, DropReason> {
        self.touched = true;
        self.expire(now_ms, 2);
        match self.lookup(info.key, now_ms) {
            Some(index) => match self.entries[index].state {
                EntryState::Pending => {
                    // A tombstoned key never gets a pending entry (`follow`
                    // refuses its fragments), so none is checked here.
                    // Its range must agree with the held fragments' end.
                    let mut probe = self.entries[index];
                    if probe.record(info.offset, info.data_len, info.more).is_err() {
                        self.poison(index);
                        return Err(DropReason::Ipv4FragmentMalformed);
                    }
                    Ok(Ipv4FragmentFirstTicket {
                        info,
                        existing: Some(u32::try_from(index).expect("entry index below NONE")),
                        victims: Victims::EMPTY,
                    })
                }
                EntryState::Allow | EntryState::Deny => {
                    let entry = self.entries[index];
                    if entry.has_first
                        && u32::from(entry.first_len) == info.data_len
                        && entry.first_fingerprint == info.fingerprint
                    {
                        self.counters.duplicate_first += 1;
                    } else if !entry.poisoned {
                        self.poison(index);
                    }
                    Err(DropReason::Ipv4FragmentDuplicateFirst)
                }
                EntryState::Free => unreachable!("lookup returns live entries"),
            },
            None => {
                if self.tombstoned(info.key, now_ms) {
                    self.counters.poisoned += 1;
                    return Err(DropReason::Ipv4FragmentDuplicateFirst);
                }
                if self.free_entry == NONE {
                    self.expire(now_ms, 1);
                }
                let mut chosen = Victims::EMPTY;
                self.plan_room(info.key.ingress, info.key.source, &mut chosen, now_ms)?;
                // Evicted at the commit (`entry_for_ticket`), with nothing
                // changed in between: the same packet's decision.
                Ok(Ipv4FragmentFirstTicket {
                    info,
                    existing: None,
                    victims: chosen,
                })
            }
        }
    }

    fn entry_for_ticket(
        &mut self,
        ticket: Ipv4FragmentFirstTicket,
        state: EntryState,
        now_ms: u64,
    ) -> Option<usize> {
        let index = match ticket.existing {
            Some(index)
                if self.entries[index as usize].state == EntryState::Pending
                    && self.entries[index as usize].key == ticket.info.key =>
            {
                let index = index as usize;
                self.set_state(index, state);
                index
            }
            Some(_) => return None,
            None => {
                self.evict_all(&ticket.victims, now_ms);
                self.insert_entry(ticket.info.key, state, now_ms)?
            }
        };
        let info = ticket.info;
        let entry = &mut self.entries[index];
        entry.has_first = true;
        entry.first_len = u16::try_from(info.data_len).unwrap_or(u16::MAX);
        entry.first_fingerprint = info.fingerprint;
        Some(index)
    }

    /// Records the forwarded first fragment's template, then rewrites and
    /// stages every fragment held for it (released toward `snapshot`'s
    /// egress MTU through `fragmentation`, which sends them in the tick's
    /// generated fragment phase).
    pub(crate) fn commit_allow(
        &mut self,
        ticket: Ipv4FragmentFirstTicket,
        template: Ipv4FragmentTemplate,
        snapshot: &ForwardingSnapshot<'_>,
        fragmentation: Option<&mut Ipv4FragmentationRuntime<'_>>,
        now_ms: u64,
    ) {
        self.touched = true;
        self.counters.first_allowed += 1;
        let Some(index) = self.entry_for_ticket(ticket, EntryState::Allow, now_ms) else {
            return;
        };
        self.entries[index].template = template;
        if self.record(index, ticket.info, now_ms).is_err() {
            return;
        }
        self.release(index, snapshot, fragmentation);
        self.complete_if_covered(index);
    }

    /// Records a refused first fragment and discards what was held for it.
    pub(crate) fn commit_deny(&mut self, ticket: Ipv4FragmentFirstTicket, now_ms: u64) {
        self.touched = true;
        self.counters.first_denied += 1;
        let Some(index) = self.entry_for_ticket(ticket, EntryState::Deny, now_ms) else {
            return;
        };
        let held = self.free_held_of(index);
        self.counters.held_denied += held;
        if self.record(index, ticket.info, now_ms).is_ok() {
            self.complete_if_covered(index);
        }
    }

    fn release(
        &mut self,
        index: usize,
        snapshot: &ForwardingSnapshot<'_>,
        mut fragmentation: Option<&mut Ipv4FragmentationRuntime<'_>>,
    ) {
        let template = self.entries[index].template;
        let mtu = snapshot
            .interface(template.egress)
            .map(|interface| interface.mtu);
        let mut current = self.entries[index].held_head;
        while current != NONE {
            let slot = self.held[current as usize];
            let start = current as usize * self.held_slot_bytes;
            let frame = &mut self.held_bytes[start..start + slot.frame_len as usize];
            if stage_released(frame, template, mtu, fragmentation.as_deref_mut()) {
                self.counters.released += 1;
            } else {
                self.counters.release_dropped += 1;
            }
            current = slot.next;
        }
        self.free_held_of(index);
    }

    /// The table's answer for a later fragment (structure and static
    /// overlap already checked): forward with the template, refuse, or hold
    /// a copy of `frame` until the first fragment decides. Every answer
    /// records the fragment's data; one that contradicts the datagram's end
    /// poisons the entry and is `IPV4_FRAGMENT_MALFORMED`. A fragment on the
    /// key of an evicted entry that allowed its datagram is refused (that
    /// datagram is gone). A hold is admitted whole before anything is
    /// evicted for it: a fragment that is then refused evicts nothing.
    pub(crate) fn follow(
        &mut self,
        info: Ipv4FragmentInfo,
        frame: &[u8],
        frame_len: usize,
        now_ms: u64,
    ) -> Result<Ipv4FragmentFollow, DropReason> {
        self.touched = true;
        self.expire(now_ms, 2);
        let existing = self.lookup(info.key, now_ms);
        if let Some(index) = existing {
            let entry = self.entries[index];
            let entry_id = u32::try_from(index).expect("entry index below NONE");
            match entry.state {
                EntryState::Allow => {
                    if info.offset < entry.template.transport_header_len() {
                        return Err(DropReason::Ipv4FragmentTransportHeaderOverlap);
                    }
                    self.record(index, info, now_ms)?;
                    return Ok(Ipv4FragmentFollow::Allow {
                        entry: entry_id,
                        template: entry.template,
                    });
                }
                EntryState::Deny => {
                    self.counters.followed_denied += 1;
                    if self.record(index, info, now_ms).is_ok() {
                        self.complete_if_covered(index);
                    }
                    return Ok(Ipv4FragmentFollow::Deny);
                }
                EntryState::Pending => {}
                EntryState::Free => unreachable!("lookup returns live entries"),
            }
        } else if self.tombstoned(info.key, now_ms) {
            self.counters.followed_denied += 1;
            return Ok(Ipv4FragmentFollow::Deny);
        }
        // Hold: every check, and the choice of every victim, before any
        // change.
        if self.held.is_empty() {
            return Err(DropReason::Ipv4FragmentHoldFull);
        }
        if frame_len > self.held_slot_bytes || frame_len > frame.len() {
            return Err(DropReason::Ipv4FragmentHoldTooLarge);
        }
        if let Some(index) = existing {
            if self.entries[index].held >= IPV4_FRAGMENT_TRACKING_HELD_PER_DATAGRAM {
                return Err(DropReason::Ipv4FragmentDatagramHoldLimit);
            }
        }
        let host_held = self
            .host_of(info.key.ingress, info.key.source)
            .map_or(0, |host| self.hosts[host].held);
        if host_held >= self.policy.held_per_host {
            return Err(DropReason::Ipv4FragmentHostHoldLimit);
        }
        if let Some(index) = existing {
            let mut probe = self.entries[index];
            if probe.record(info.offset, info.data_len, info.more).is_err() {
                self.poison(index);
                return Err(DropReason::Ipv4FragmentMalformed);
            }
        }
        if self.free_held == NONE || (existing.is_none() && self.free_entry == NONE) {
            // `existing` was live at `now_ms`, so this leaves it.
            self.expire(now_ms, 1);
        }
        let mut chosen = Victims::EMPTY;
        if self.free_held == NONE {
            let requester = self.ingress_of(info.key.ingress);
            let victim = self.held_victim(requester, existing, &chosen);
            if victim == NONE {
                return Err(DropReason::Ipv4FragmentHoldFull);
            }
            chosen.push(victim);
        }
        if existing.is_none() {
            self.plan_room(info.key.ingress, info.key.source, &mut chosen, now_ms)?;
        }
        self.evict_all(&chosen, now_ms);
        let index = match existing {
            Some(index) => index,
            None => self
                .insert_entry(info.key, EntryState::Pending, now_ms)
                .ok_or(DropReason::Ipv4FragmentTableFull)?,
        };
        self.record(index, info, now_ms)?;
        let held = self.free_held;
        self.free_held = self.held[held as usize].next;
        let start = held as usize * self.held_slot_bytes;
        self.held_bytes[start..start + frame_len].copy_from_slice(&frame[..frame_len]);
        self.held[held as usize] = Ipv4FragmentHeldSlot {
            next: NONE,
            frame_len: u32::try_from(frame_len).expect("bounded by the held slot"),
        };
        let id = u32::try_from(index).expect("entry index below NONE");
        let slot = self.ingress_of_entry(id);
        if self.entries[index].held == 0 {
            push(self.entries, &mut self.ingresses[slot].holding, id, HELD);
        }
        let entry = &mut self.entries[index];
        if entry.held_tail == NONE {
            entry.held_head = held;
        } else {
            self.held[entry.held_tail as usize].next = held;
        }
        entry.held_tail = held;
        entry.held += 1;
        let host = entry.host as usize;
        self.hosts[host].held += 1;
        self.ingresses[slot].held += 1;
        self.update_over(slot);
        self.live_held += 1;
        self.held_high_water.observe(self.live_held);
        self.counters.held += 1;
        Ok(Ipv4FragmentFollow::Held)
    }

    /// A later fragment was forwarded with its entry's template; the entry
    /// is freed once its whole datagram was seen.
    pub(crate) fn followed(&mut self, entry: u32) {
        self.touched = true;
        self.counters.followed += 1;
        let index = entry as usize;
        if self.entries.get(index).is_some() {
            self.complete_if_covered(index);
        }
    }

    /// A later fragment refused before the table for its TTL (it can never
    /// leave). When its datagram is already refused, its data still counts
    /// toward the entry's coverage (no hold, no progress), so the entry can
    /// complete early; a contradiction poisons it as in [`Self::follow`],
    /// while the fragment's own drop is still reported as
    /// `IPV4_TTL_EXPIRED` (the poisoning shows in
    /// `fragment_tracking.poisoned`). Any other entry is left alone:
    /// nothing is held or forwarded for a fragment that cannot leave.
    pub(crate) fn ttl_expired(&mut self, info: Ipv4FragmentInfo, now_ms: u64) {
        self.touched = true;
        let Some(index) = self.lookup(info.key, now_ms) else {
            return;
        };
        if self.entries[index].state != EntryState::Deny {
            return;
        }
        match self.entries[index].record(info.offset, info.data_len, info.more) {
            Ok(_) => self.complete_if_covered(index),
            Err(()) => self.poison(index),
        }
    }

    /// Walks every list and count of the table (tests only).
    #[cfg(test)]
    pub(crate) fn check_invariants(&self) -> Result<(), &'static str> {
        let walk = |ends: Ends, list: usize| -> Result<Vec<u32>, &'static str> {
            let mut out = Vec::new();
            let mut previous = NONE;
            let mut current = ends[OLDER];
            while current != NONE {
                if out.len() > self.entries.len() {
                    return Err("list cycle");
                }
                let entry = &self.entries[current as usize];
                if entry.state == EntryState::Free {
                    return Err("free entry on a list");
                }
                if entry.links[list][OLDER] != previous {
                    return Err("older link mismatch");
                }
                out.push(current);
                previous = current;
                current = entry.links[list][NEWER];
            }
            if ends[NEWER] != previous {
                return Err("newest end mismatch");
            }
            Ok(out)
        };
        let live: Vec<u32> = (0..self.entries.len() as u32)
            .filter(|&index| self.entries[index as usize].state != EntryState::Free)
            .collect();
        if live.len() != self.live_entries {
            return Err("live entry count");
        }
        let age = walk(self.age, AGE)?;
        if age.len() != live.len() {
            return Err("age list");
        }
        let evict = walk(self.evict, CLASS)?;
        let allow = walk(self.allow, CLASS)?;
        if evict.len() + allow.len() != live.len()
            || evict
                .iter()
                .any(|&index| self.entries[index as usize].state == EntryState::Allow)
            || allow
                .iter()
                .any(|&index| self.entries[index as usize].state != EntryState::Allow)
        {
            return Err("table class lists");
        }
        let progress = |index: u32| {
            let entry = &self.entries[index as usize];
            entry.created_ms + u64::from(entry.progress_ms)
        };
        // Progress order holds while the clock does not go back.
        if allow
            .windows(2)
            .any(|pair| progress(pair[0]) > progress(pair[1]))
        {
            return Err("allow list out of progress order");
        }
        let mut held_total = 0;
        for &index in &live {
            let entry = &self.entries[index as usize];
            let host = &self.hosts[entry.host as usize];
            if host.entries == 0 || host.ingress != entry.key.ingress {
                return Err("entry host");
            }
            if entry.held != 0 && entry.state != EntryState::Pending {
                return Err("decided entry holds fragments");
            }
            held_total += usize::from(entry.held);
        }
        if held_total != self.live_held {
            return Err("held count");
        }
        let mut free_held = 0;
        let mut current = self.free_held;
        while current != NONE {
            free_held += 1;
            if free_held > self.held.len() {
                return Err("free held cycle");
            }
            current = self.held[current as usize].next;
        }
        if free_held + self.live_held != self.held.len() {
            return Err("free held list");
        }
        for (index, host) in self.hosts.iter().enumerate() {
            if host.entries == 0 {
                continue;
            }
            let mine: Vec<u32> = live
                .iter()
                .copied()
                .filter(|&entry| self.entries[entry as usize].host as usize == index)
                .collect();
            let lists = walk(host.evict, HOST)?.len() + walk(host.allow, HOST)?.len();
            if mine.len() != host.entries as usize || lists != mine.len() {
                return Err("host lists");
            }
            let held: u32 = mine
                .iter()
                .map(|&entry| u32::from(self.entries[entry as usize].held))
                .sum();
            if held != host.held {
                return Err("host held");
            }
        }
        let mut over = 0;
        for slot in 0..self.ingress_len {
            let ingress = &self.ingresses[slot];
            let mine: Vec<u32> = live
                .iter()
                .copied()
                .filter(|&entry| self.ingress_of_entry(entry) == slot)
                .collect();
            let lists = walk(ingress.evict, INGRESS)?.len() + walk(ingress.allow, INGRESS)?.len();
            if mine.len() != ingress.entries as usize || lists != mine.len() {
                return Err("ingress lists");
            }
            let holding = walk(ingress.holding, HELD)?;
            let holders = mine
                .iter()
                .filter(|&&entry| self.entries[entry as usize].held != 0)
                .count();
            let held: u32 = mine
                .iter()
                .map(|&entry| u32::from(self.entries[entry as usize].held))
                .sum();
            if holding.len() != holders || held != ingress.held {
                return Err("ingress holding");
            }
            if ingress.over != (ingress.held > self.held_cap) {
                return Err("over-share flag");
            }
            over += usize::from(ingress.over);
            if self.ingress_of(ingress.id) != Some(slot) {
                return Err("ingress map");
            }
        }
        let mut listed = 0;
        let mut slot = self.over_head;
        while slot != NO_SLOT {
            listed += 1;
            if listed > IPV4_FRAGMENT_TRACKING_MAX_INGRESSES
                || !self.ingresses[usize::from(slot)].over
            {
                return Err("over-share list");
            }
            slot = self.ingresses[usize::from(slot)].over_next;
        }
        if listed != over {
            return Err("over-share list length");
        }
        if self.entry_directory.validate().is_err()
            || self.host_directory.validate().is_err()
            || self.tombstone_directory.validate().is_err()
        {
            return Err("directory structure");
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if self.entry_directory.is_linked(index) != Some(entry.state != EntryState::Free) {
                return Err("entry directory link");
            }
        }
        for (index, host) in self.hosts.iter().enumerate() {
            if self.host_directory.is_linked(index) != Some(host.entries != 0) {
                return Err("host directory link");
            }
        }
        for (index, tombstone) in self.tombstones.iter().enumerate() {
            if self.tombstone_directory.is_linked(index) != Some(tombstone.live) {
                return Err("tombstone directory link");
            }
            if tombstone.live {
                let found = self
                    .tombstone_directory
                    .lookup(
                        DirectoryHashDomain::Ipv4FragmentTombstone,
                        &tombstone.key.words(),
                        |slot| slot == index,
                    )
                    .ok()
                    .and_then(|probe| probe.state_index);
                if found != Some(index) {
                    return Err("tombstone not found by its key");
                }
            }
        }
        if self.tombstone_next >= self.tombstones.len() {
            return Err("tombstone cursor");
        }
        Ok(())
    }
}

const fn next_index(index: usize, count: usize) -> u32 {
    if index + 1 < count {
        index as u32 + 1
    } else {
        NONE
    }
}

/// Rewrites one held fragment with its first fragment's template and stages
/// it: whole when it fits the egress MTU, re-fragmented (RFC 791 §3.2) when
/// it is DF-clear and does not. `false` when it is discarded.
fn stage_released(
    frame: &mut [u8],
    template: Ipv4FragmentTemplate,
    mtu: Option<u16>,
    fragmentation: Option<&mut Ipv4FragmentationRuntime<'_>>,
) -> bool {
    let (Some(fragmentation), Some(mtu)) = (fragmentation, mtu) else {
        return false;
    };
    let Some(info) = packet::validate_ipv4_frame(frame)
        .ok()
        .and_then(|ipv4| parse_fragment(frame, ipv4, IfId(0)))
    else {
        return false;
    };
    if info.offset < template.transport_header_len() || template.apply(frame).is_err() {
        return false;
    }
    let Ok(plan) = fragmentation.plan_forward(frame, mtu) else {
        return false;
    };
    fragmentation.stage(frame, plan, template.egress);
    true
}

#[cfg(test)]
mod tests;

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
//! unless it is byte-identical to the first one (same length and an FNV-1a
//! fingerprint of all its data, a network duplicate), it poisons the entry: every remaining
//! fragment of both datagrams is refused, which fails closed. The datagram's
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
//! host's quota is full, the oldest pending or refusing entry (of the table,
//! or of that host) is evicted through its own list, in O(1); an allowing
//! entry never is, because only an allowing template ever forwards a later
//! fragment, so an eviction can only turn later fragments into refusals or
//! new holds, never forward one. Every table is
//! caller-owned storage sized once from the config; there is no allocation,
//! no lock, and no copy on the fast path (a frame that is not a fragment
//! costs one read of the flags word).
//!
//! The table is flushed at every publication apply (its templates name the
//! previous publication's egress and neighbors), counting what it held.

use std::{marker::PhantomData, rc::Rc};

use crate::{
    fixed_directory::{DirectoryHashDomain, FixedDirectory},
    ipv4_header_checksum, packet, DirectoryBucket, DirectoryNode, DropReason, ForwardingSnapshot,
    IfId, Ipv4FragmentationRuntime, ResolutionHashKey,
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
        })
    }

    /// Rewrites a later fragment (validated, 20-byte header, TTL above 1)
    /// like its first fragment: Ethernet addresses, ID, addresses, TTL - 1,
    /// and a recomputed header checksum.
    pub(crate) fn apply(self, frame: &mut [u8]) -> Result<(), DropReason> {
        let header = packet::ETHERNET_HEADER_LEN;
        if frame.len() < header + IPV4_HEADER_LEN {
            return Err(DropReason::Ipv4HeaderTruncated);
        }
        if frame[header + 8] <= 1 {
            return Err(DropReason::Ipv4TtlExpired);
        }
        frame[0..12].copy_from_slice(&self.macs);
        frame[header + 4..header + 6].copy_from_slice(&self.id.to_be_bytes());
        frame[header + 8] -= 1;
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
    /// FNV-1a over every data byte of a first fragment (0 for a later one):
    /// with its length, the identity of a byte-identical duplicate.
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
        frame
            .get(data_start..data_end)?
            .iter()
            .fold(0x811c_9dc5_u32, |hash, byte| {
                (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
            })
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

/// Coverage ranges an entry tracks exactly (RFC 815's hole list, inverted):
/// a datagram arriving in more disjoint pieces than this is no longer
/// tracked and its entry lives until the timeout.
const COVERAGE_RANGES: usize = 4;

/// One association entry (caller-owned storage).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4FragmentEntrySlot {
    state: EntryState,
    /// A second, different first fragment or an inconsistent end turned the
    /// entry into a refusal for good (no early completion).
    poisoned: bool,
    key: Ipv4FragmentKey,
    template: Ipv4FragmentTemplate,
    created_ms: u64,
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
    /// (0 before).
    total: u32,
    /// The largest data end seen.
    max_end: u32,
    /// Disjoint, sorted data ranges seen; `untracked` once more were needed.
    ranges: [[u16; 2]; COVERAGE_RANGES],
    ranges_len: u8,
    untracked: bool,
    /// Age list (creation order) while live; free list (`newer`) while free.
    older: u32,
    newer: u32,
    /// Evictable list (pending or refusing entries, in the order they
    /// became evictable).
    evict_older: u32,
    evict_newer: u32,
    /// The host's and the ingress's entries, oldest first.
    host_older: u32,
    host_newer: u32,
    ingress_older: u32,
    ingress_newer: u32,
}

impl Ipv4FragmentEntrySlot {
    pub const EMPTY: Self = Self {
        state: EntryState::Free,
        poisoned: false,
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
        },
        created_ms: 0,
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
        older: NONE,
        newer: NONE,
        evict_older: NONE,
        evict_newer: NONE,
        host_older: NONE,
        host_newer: NONE,
        ingress_older: NONE,
        ingress_newer: NONE,
    };

    /// Records the data range of one fragment. `Err` when it contradicts
    /// what was seen: a second, different end (MF clear), or data past the
    /// end. Duplicates and overlaps count once.
    fn record(&mut self, offset: u32, len: u32, more: bool) -> Result<(), ()> {
        if self.poisoned {
            return Ok(());
        }
        let end = offset + len;
        if !more {
            if (self.total != 0 && self.total != end) || self.max_end > end {
                return Err(());
            }
            self.total = end;
        } else if self.total != 0 && end > self.total {
            return Err(());
        }
        self.max_end = self.max_end.max(end);
        if self.untracked {
            return Ok(());
        }
        // Both fit 16 bits: data ends at most 65515 bytes in.
        let (mut start, mut stop) = (offset as u16, end as u16);
        let mut merged = [[0_u16; 2]; COVERAGE_RANGES];
        let mut count = 0;
        let mut placed = false;
        for range in &self.ranges[..usize::from(self.ranges_len)] {
            if range[1] < start {
                merged[count] = *range;
                count += 1;
            } else if range[0] > stop {
                if !placed {
                    if count == COVERAGE_RANGES {
                        self.untracked = true;
                        return Ok(());
                    }
                    merged[count] = [start, stop];
                    count += 1;
                    placed = true;
                }
                if count == COVERAGE_RANGES {
                    self.untracked = true;
                    return Ok(());
                }
                merged[count] = *range;
                count += 1;
            } else {
                start = start.min(range[0]);
                stop = stop.max(range[1]);
            }
        }
        if !placed {
            if count == COVERAGE_RANGES {
                self.untracked = true;
                return Ok(());
            }
            merged[count] = [start, stop];
            count += 1;
        }
        self.ranges = merged;
        self.ranges_len = u8::try_from(count).expect("at most COVERAGE_RANGES");
        Ok(())
    }

    /// Every data byte from 0 to the datagram's end was seen.
    fn complete(&self) -> bool {
        !self.poisoned
            && !self.untracked
            && self.total != 0
            && self.ranges_len == 1
            && u32::from(self.ranges[0][0]) == 0
            && u32::from(self.ranges[0][1]) == self.total
    }
}

impl Default for Ipv4FragmentEntrySlot {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Per-(ingress, source) accounting (caller-owned storage, one per entry).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4FragmentHostSlot {
    ingress: IfId,
    address: [u8; 4],
    entries: u32,
    held: u32,
    next_free: u32,
    /// The host's entries, oldest first.
    oldest: u32,
    newest: u32,
}

impl Ipv4FragmentHostSlot {
    pub const EMPTY: Self = Self {
        ingress: IfId(0),
        address: [0; 4],
        entries: 0,
        held: 0,
        next_free: NONE,
        oldest: NONE,
        newest: NONE,
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

/// Evictable entries a held fragment looks through for a pending one to
/// evict when every held slot is taken.
const HELD_EVICTION_PROBES: usize = 8;

/// Oldest entries of a host or an ingress looked through for a pending or
/// refusing one to evict.
const SCOPE_EVICTION_PROBES: usize = 8;

/// Entries of one ingress interface and their age list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IngressSlot {
    id: IfId,
    entries: u32,
    oldest: u32,
    newest: u32,
}

impl IngressSlot {
    const EMPTY: Self = Self {
        id: IfId(0),
        entries: 0,
        oldest: NONE,
        newest: NONE,
    };
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

/// Caller-owned storage of an [`Ipv4FragmentTracker`]: `entries` entry
/// slots, as many host slots, a bucket array of
/// [`ipv4_fragment_tracking_buckets`] and a node per slot for each of the
/// two directories, and `held` held records with `held × slot` bytes.
pub struct Ipv4FragmentTrackingStorage<'a> {
    pub entries: &'a mut [Ipv4FragmentEntrySlot],
    pub entry_buckets: &'a mut [DirectoryBucket],
    pub entry_nodes: &'a mut [DirectoryNode],
    pub hosts: &'a mut [Ipv4FragmentHostSlot],
    pub host_buckets: &'a mut [DirectoryBucket],
    pub host_nodes: &'a mut [DirectoryNode],
    pub held: &'a mut [Ipv4FragmentHeldSlot],
    pub held_bytes: &'a mut [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ipv4FragmentTrackingStorageError {
    /// No entry slot: nothing could be associated.
    NoEntries,
    /// Host slots, nodes, or buckets do not match the entry count.
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
    /// Later fragments refused because their first fragment was.
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
    /// pending or refusing ones (oldest first), or an allowing one older
    /// than a fifth of the timeout (its datagram stalled).
    pub entries_evicted: usize,
    /// Held fragments discarded with an evicted entry.
    pub held_evicted: usize,
    /// Entries turned into a refusal for good: a second, different first
    /// fragment for a decided datagram (an ID reused, or two datagrams with
    /// one key), or a fragment contradicting the datagram's end.
    pub poisoned: usize,
    /// Byte-identical duplicate first fragments dropped alone.
    pub duplicate_first: usize,
    /// Entries discarded by a publication apply.
    pub entries_flushed: usize,
    /// Held fragments discarded by a publication apply.
    pub held_flushed: usize,
}

/// A first fragment admitted before its decision: it either continues a
/// pending entry or will take a new one (room made).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4FragmentFirstTicket {
    info: Ipv4FragmentInfo,
    existing: Option<u32>,
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
    held: &'a mut [Ipv4FragmentHeldSlot],
    held_bytes: &'a mut [u8],
    held_slot_bytes: usize,
    free_entry: u32,
    free_host: u32,
    free_held: u32,
    /// Age list: oldest and newest live entry.
    oldest: u32,
    newest: u32,
    /// Evictable list (pending and refusing entries).
    evict_oldest: u32,
    evict_newest: u32,
    /// Entries per ingress interface (`ingress_len` used), with their age
    /// lists, and the share each may take.
    ingresses: [IngressSlot; IPV4_FRAGMENT_TRACKING_MAX_INGRESSES],
    ingress_len: usize,
    ingress_cap: u32,
    live_entries: usize,
    live_held: usize,
    counters: Ipv4FragmentTrackingCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> Ipv4FragmentTracker<'a> {
    /// Builds an empty table over `storage`, keyed by the publication's
    /// resolution key in its own hash domain.
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
            held,
            held_bytes,
        } = storage;
        let count = entries.len();
        if count == 0 {
            return Err(Ipv4FragmentTrackingStorageError::NoEntries);
        }
        let buckets = ipv4_fragment_tracking_buckets(count);
        if count >= NONE as usize
            || hosts.len() != count
            || entry_nodes.len() != count
            || host_nodes.len() != count
            || entry_buckets.len() != buckets
            || host_buckets.len() != buckets
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
        let mut tracker = Self {
            policy,
            entries,
            entry_directory,
            hosts,
            host_directory,
            held,
            held_bytes,
            held_slot_bytes,
            free_entry: NONE,
            free_host: NONE,
            free_held: NONE,
            oldest: NONE,
            newest: NONE,
            evict_oldest: NONE,
            evict_newest: NONE,
            ingresses: [IngressSlot::EMPTY; IPV4_FRAGMENT_TRACKING_MAX_INGRESSES],
            ingress_len: 0,
            ingress_cap: u32::try_from(
                (count * usize::from(policy.ingress_share_percent) / 100).max(1),
            )
            .unwrap_or(u32::MAX),
            live_entries: 0,
            live_held: 0,
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

    /// Discards every entry and held fragment (counted as flushed). A
    /// publication apply calls it: the templates name the old publication's
    /// egress and neighbors.
    pub fn flush(&mut self) {
        self.counters.entries_flushed += self.live_entries;
        self.counters.held_flushed += self.live_held;
        self.reset();
    }

    /// [`Self::flush`] and rekey with the new publication's key.
    pub fn flush_with_key(&mut self, key: ResolutionHashKey) {
        self.counters.entries_flushed += self.live_entries;
        self.counters.held_flushed += self.live_held;
        self.entry_directory.clear_with_key(key.directory_key());
        self.host_directory.clear_with_key(key.directory_key());
        self.reset();
    }

    fn reset(&mut self) {
        self.entry_directory.clear();
        self.host_directory.clear();
        let count = self.entries.len();
        for (index, slot) in self.entries.iter_mut().enumerate() {
            *slot = Ipv4FragmentEntrySlot::EMPTY;
            slot.newer = next_index(index, count);
        }
        for (index, slot) in self.hosts.iter_mut().enumerate() {
            *slot = Ipv4FragmentHostSlot::EMPTY;
            slot.next_free = next_index(index, count);
        }
        let held = self.held.len();
        for (index, slot) in self.held.iter_mut().enumerate() {
            *slot = Ipv4FragmentHeldSlot::EMPTY;
            slot.next = next_index(index, held);
        }
        self.free_entry = if count == 0 { NONE } else { 0 };
        self.free_host = if count == 0 { NONE } else { 0 };
        self.free_held = if held == 0 { NONE } else { 0 };
        self.oldest = NONE;
        self.newest = NONE;
        self.evict_oldest = NONE;
        self.evict_newest = NONE;
        self.ingresses = [IngressSlot::EMPTY; IPV4_FRAGMENT_TRACKING_MAX_INGRESSES];
        self.ingress_len = 0;
        self.live_entries = 0;
        self.live_held = 0;
    }

    /// Frees every entry older than the timeout at `now_ms`, at most
    /// `budget` of them, and returns how many it freed. Expiry is otherwise
    /// lazy (each table operation expires up to two of the oldest entries);
    /// this bounded sweep is for callers that want the occupancy and the
    /// expiry counters current without traffic.
    pub fn sweep(&mut self, now_ms: u64, budget: usize) -> usize {
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
            let oldest = self.oldest;
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

    /// Discards an evictable entry to make room (counted).
    fn evict(&mut self, index: u32) {
        self.counters.entries_evicted += 1;
        let held = self.free_entry_at(index as usize);
        self.counters.held_evicted += held;
    }

    /// Whether `index` may be evicted at `now_ms`: a pending or refusing
    /// entry always; an allowing one once its datagram has stalled for a
    /// fifth of the timeout (fragments of one datagram arrive within
    /// milliseconds; a spoofed first fragment never gets the rest).
    fn evictable(&self, index: u32, now_ms: u64) -> bool {
        let entry = &self.entries[index as usize];
        entry.state != EntryState::Allow
            || now_ms.saturating_sub(entry.created_ms)
                >= u64::from((self.policy.timeout_ms / 5).max(1))
    }

    /// The entry to evict from a host's (`host`) or an ingress's age list
    /// starting at `oldest`: the first pending or refusing entry among its
    /// oldest few, else its oldest entry if that is a stalled allowing one
    /// (the oldest is the most stalled), else none. Bounded.
    fn scope_victim(&self, oldest: u32, host: bool, now_ms: u64) -> u32 {
        let mut current = oldest;
        for _ in 0..SCOPE_EVICTION_PROBES {
            if current == NONE {
                break;
            }
            let entry = &self.entries[current as usize];
            if entry.state != EntryState::Allow {
                return current;
            }
            current = if host {
                entry.host_newer
            } else {
                entry.ingress_newer
            };
        }
        if oldest != NONE && self.evictable(oldest, now_ms) {
            oldest
        } else {
            NONE
        }
    }

    fn ingress_of(&self, ingress: IfId) -> Option<usize> {
        self.ingresses[..self.ingress_len]
            .iter()
            .position(|slot| slot.id == ingress)
    }

    /// Room for a new entry of `ingress`/`source`: expiring the oldest,
    /// then, at the host's limit, the ingress's share, or a full table,
    /// evicting the oldest evictable entry of that host, that ingress, or
    /// the table (a pending or refusing one first). An allowing entry is
    /// evicted only once stalled: only an allowing template ever forwards a
    /// later fragment, so evicting a pending or refusing one can only turn
    /// later fragments into refusals or new holds.
    fn make_room(&mut self, ingress: IfId, source: [u8; 4], now_ms: u64) -> Result<(), DropReason> {
        if self.free_entry == NONE {
            self.expire(now_ms, 1);
        }
        if let Some(host) = self.host_of(ingress, source) {
            if self.hosts[host].entries >= self.policy.entries_per_host {
                let victim = self.scope_victim(self.hosts[host].oldest, true, now_ms);
                if victim == NONE {
                    return Err(DropReason::Ipv4FragmentHostLimit);
                }
                self.evict(victim);
            }
        }
        match self.ingress_of(ingress) {
            Some(slot) => {
                // 100 percent does not partition: a full table decides.
                if self.ingresses[slot].entries >= self.ingress_cap
                    && (self.ingress_cap as usize) < self.entries.len()
                {
                    let victim = self.scope_victim(self.ingresses[slot].oldest, false, now_ms);
                    if victim == NONE {
                        return Err(DropReason::Ipv4FragmentIngressLimit);
                    }
                    self.evict(victim);
                }
            }
            None if self.ingress_len == IPV4_FRAGMENT_TRACKING_MAX_INGRESSES => {
                return Err(DropReason::Ipv4FragmentIngressLimit);
            }
            None => {}
        }
        if self.free_entry == NONE {
            let mut victim = self.evict_oldest;
            if victim == NONE {
                victim = self.oldest;
                if victim == NONE || !self.evictable(victim, now_ms) {
                    return Err(DropReason::Ipv4FragmentTableFull);
                }
            }
            self.evict(victim);
        }
        Ok(())
    }

    /// Frees a held slot for a new held fragment: evicts the oldest pending
    /// entry (with what it holds) among the first few evictable entries.
    fn make_held_room(&mut self, now_ms: u64) {
        self.expire(now_ms, 1);
        let mut current = self.evict_oldest;
        for _ in 0..HELD_EVICTION_PROBES {
            if self.free_held != NONE || current == NONE {
                return;
            }
            let next = self.entries[current as usize].evict_newer;
            if self.entries[current as usize].held != 0 {
                self.evict(current);
            }
            current = next;
        }
    }

    /// Takes a free entry for `key` (room made by `make_room`).
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
        let ingress = match self.ingress_of(key.ingress) {
            Some(slot) => slot,
            None => {
                if self.ingress_len == IPV4_FRAGMENT_TRACKING_MAX_INGRESSES {
                    self.release_host_if_empty(host);
                    let _ = self.entry_directory.unlink(index as usize);
                    return None;
                }
                self.ingresses[self.ingress_len] = IngressSlot {
                    id: key.ingress,
                    ..IngressSlot::EMPTY
                };
                self.ingress_len += 1;
                self.ingress_len - 1
            }
        };
        self.free_entry = self.entries[index as usize].newer;
        self.hosts[host].entries += 1;
        self.ingresses[ingress].entries += 1;
        self.entries[index as usize] = Ipv4FragmentEntrySlot {
            state,
            key,
            created_ms: now_ms,
            host: u32::try_from(host).expect("host index below NONE"),
            older: self.newest,
            ..Ipv4FragmentEntrySlot::EMPTY
        };
        if self.newest != NONE {
            self.entries[self.newest as usize].newer = index;
        } else {
            self.oldest = index;
        }
        self.newest = index;
        self.live_entries += 1;
        // The host's and the ingress's age lists.
        let host_previous = self.hosts[host].newest;
        self.entries[index as usize].host_older = host_previous;
        if host_previous == NONE {
            self.hosts[host].oldest = index;
        } else {
            self.entries[host_previous as usize].host_newer = index;
        }
        self.hosts[host].newest = index;
        let ingress_previous = self.ingresses[ingress].newest;
        self.entries[index as usize].ingress_older = ingress_previous;
        if ingress_previous == NONE {
            self.ingresses[ingress].oldest = index;
        } else {
            self.entries[ingress_previous as usize].ingress_newer = index;
        }
        self.ingresses[ingress].newest = index;
        if state != EntryState::Allow {
            self.evict_link(index);
        }
        Some(index as usize)
    }

    /// Appends a pending or refusing entry to the evictable list.
    fn evict_link(&mut self, index: u32) {
        let previous = self.evict_newest;
        let entry = &mut self.entries[index as usize];
        entry.evict_older = previous;
        entry.evict_newer = NONE;
        if previous == NONE {
            self.evict_oldest = index;
        } else {
            self.entries[previous as usize].evict_newer = index;
        }
        self.evict_newest = index;
    }

    /// Removes an entry from the evictable list.
    fn evict_unlink(&mut self, index: u32) {
        let entry = self.entries[index as usize];
        if entry.evict_older == NONE {
            self.evict_oldest = entry.evict_newer;
        } else {
            self.entries[entry.evict_older as usize].evict_newer = entry.evict_newer;
        }
        if entry.evict_newer == NONE {
            self.evict_newest = entry.evict_older;
        } else {
            self.entries[entry.evict_newer as usize].evict_older = entry.evict_older;
        }
        let entry = &mut self.entries[index as usize];
        entry.evict_older = NONE;
        entry.evict_newer = NONE;
    }

    /// Removes an entry from its host's and its ingress's age lists.
    fn scope_unlink(&mut self, index: usize) {
        let entry = self.entries[index];
        let host = entry.host as usize;
        if entry.host_older == NONE {
            self.hosts[host].oldest = entry.host_newer;
        } else {
            self.entries[entry.host_older as usize].host_newer = entry.host_newer;
        }
        if entry.host_newer == NONE {
            self.hosts[host].newest = entry.host_older;
        } else {
            self.entries[entry.host_newer as usize].host_older = entry.host_older;
        }
        if let Some(ingress) = self.ingress_of(entry.key.ingress) {
            if entry.ingress_older == NONE {
                self.ingresses[ingress].oldest = entry.ingress_newer;
            } else {
                self.entries[entry.ingress_older as usize].ingress_newer = entry.ingress_newer;
            }
            if entry.ingress_newer == NONE {
                self.ingresses[ingress].newest = entry.ingress_older;
            } else {
                self.entries[entry.ingress_newer as usize].ingress_older = entry.ingress_older;
            }
            self.ingresses[ingress].entries = self.ingresses[ingress].entries.saturating_sub(1);
        }
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
        if self.entries[index].state != EntryState::Allow {
            self.evict_unlink(id);
        }
        self.scope_unlink(index);
        let entry = self.entries[index];
        let _ = self.entry_directory.unlink(index);
        if entry.older == NONE {
            self.oldest = entry.newer;
        } else {
            self.entries[entry.older as usize].newer = entry.newer;
        }
        if entry.newer == NONE {
            self.newest = entry.older;
        } else {
            self.entries[entry.newer as usize].older = entry.older;
        }
        let host = entry.host as usize;
        if let Some(slot) = self.hosts.get_mut(host) {
            slot.entries = slot.entries.saturating_sub(1);
            self.release_host_if_empty(host);
        }
        self.entries[index] = Ipv4FragmentEntrySlot {
            newer: self.free_entry,
            ..Ipv4FragmentEntrySlot::EMPTY
        };
        self.free_entry = id;
        self.live_entries -= 1;
        held
    }

    /// Returns every held fragment of an entry to the free list.
    fn free_held_of(&mut self, index: usize) -> usize {
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
        if let Some(host) = self.hosts.get_mut(entry.host as usize) {
            host.held = host
                .held
                .saturating_sub(u32::try_from(count).unwrap_or(u32::MAX));
        }
        self.live_held -= count;
        count
    }

    /// Turns an entry into a refusal for good: what it held is discarded,
    /// every later fragment is refused, and it lives until the timeout (or
    /// is evicted). Both datagrams that share the key fail closed.
    fn poison(&mut self, index: usize) {
        self.counters.poisoned += 1;
        let held = self.free_held_of(index);
        self.counters.held_denied += held;
        if self.entries[index].state == EntryState::Allow {
            self.entries[index].state = EntryState::Deny;
            self.evict_link(u32::try_from(index).expect("entry index below NONE"));
        }
        self.entries[index].state = EntryState::Deny;
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

    /// Records one fragment's data in a live entry; a contradiction poisons
    /// it and is `IPV4_FRAGMENT_MALFORMED`.
    fn record(&mut self, index: usize, info: Ipv4FragmentInfo) -> Result<(), DropReason> {
        if self.entries[index]
            .record(info.offset, info.data_len, info.more)
            .is_err()
        {
            self.poison(index);
            return Err(DropReason::Ipv4FragmentMalformed);
        }
        Ok(())
    }

    /// Admits a first fragment before its decision: a pending entry
    /// continues; a decided one drops a byte-identical duplicate alone and
    /// is poisoned by any other first fragment (`IPV4_FRAGMENT_DUPLICATE_FIRST`
    /// either way); a new one needs room (evicting a pending or refusing
    /// entry if needed). Changes nothing else.
    pub(crate) fn admit_first(
        &mut self,
        info: Ipv4FragmentInfo,
        now_ms: u64,
    ) -> Result<Ipv4FragmentFirstTicket, DropReason> {
        self.expire(now_ms, 2);
        match self.lookup(info.key, now_ms) {
            Some(index) => match self.entries[index].state {
                EntryState::Pending => {
                    // Its range must agree with the held fragments' end.
                    let mut probe = self.entries[index];
                    if probe.record(info.offset, info.data_len, info.more).is_err() {
                        self.poison(index);
                        return Err(DropReason::Ipv4FragmentMalformed);
                    }
                    Ok(Ipv4FragmentFirstTicket {
                        info,
                        existing: Some(u32::try_from(index).expect("entry index below NONE")),
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
                self.make_room(info.key.ingress, info.key.source, now_ms)?;
                Ok(Ipv4FragmentFirstTicket {
                    info,
                    existing: None,
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
            Some(index) if self.entries[index as usize].state == EntryState::Pending => {
                let index = index as usize;
                self.entries[index].state = state;
                if state == EntryState::Allow {
                    self.evict_unlink(u32::try_from(index).expect("entry index below NONE"));
                }
                index
            }
            Some(_) => return None,
            None => self.insert_entry(ticket.info.key, state, now_ms)?,
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
        self.counters.first_allowed += 1;
        let Some(index) = self.entry_for_ticket(ticket, EntryState::Allow, now_ms) else {
            return;
        };
        self.entries[index].template = template;
        if self.record(index, ticket.info).is_err() {
            return;
        }
        self.release(index, snapshot, fragmentation);
        self.complete_if_covered(index);
    }

    /// Records a refused first fragment and discards what was held for it.
    pub(crate) fn commit_deny(&mut self, ticket: Ipv4FragmentFirstTicket, now_ms: u64) {
        self.counters.first_denied += 1;
        let Some(index) = self.entry_for_ticket(ticket, EntryState::Deny, now_ms) else {
            return;
        };
        let held = self.free_held_of(index);
        self.counters.held_denied += held;
        if self.record(index, ticket.info).is_ok() {
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
    /// poisons the entry and is `IPV4_FRAGMENT_MALFORMED`.
    pub(crate) fn follow(
        &mut self,
        info: Ipv4FragmentInfo,
        frame: &[u8],
        frame_len: usize,
        now_ms: u64,
    ) -> Result<Ipv4FragmentFollow, DropReason> {
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
                    self.record(index, info)?;
                    return Ok(Ipv4FragmentFollow::Allow {
                        entry: entry_id,
                        template: entry.template,
                    });
                }
                EntryState::Deny => {
                    self.counters.followed_denied += 1;
                    if self.record(index, info).is_ok() {
                        self.complete_if_covered(index);
                    }
                    return Ok(Ipv4FragmentFollow::Deny);
                }
                EntryState::Pending => {}
                EntryState::Free => unreachable!("lookup returns live entries"),
            }
        }
        // Hold: every check before any change.
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
        if self.free_held == NONE {
            self.make_held_room(now_ms);
        }
        if self.free_held == NONE {
            return Err(DropReason::Ipv4FragmentHoldFull);
        }
        let existing = match existing {
            // The expiry above may have freed it.
            Some(index) if self.entries[index].state == EntryState::Pending => Some(index),
            _ => self.lookup(info.key, now_ms),
        };
        let host_held = self
            .host_of(info.key.ingress, info.key.source)
            .map_or(0, |host| self.hosts[host].held);
        if host_held >= self.policy.held_per_host {
            return Err(DropReason::Ipv4FragmentHostHoldLimit);
        }
        let index = match existing {
            Some(index) => index,
            None => {
                self.make_room(info.key.ingress, info.key.source, now_ms)?;
                if self.free_held == NONE {
                    return Err(DropReason::Ipv4FragmentHoldFull);
                }
                self.insert_entry(info.key, EntryState::Pending, now_ms)
                    .ok_or(DropReason::Ipv4FragmentTableFull)?
            }
        };
        self.record(index, info)?;
        let held = self.free_held;
        self.free_held = self.held[held as usize].next;
        let start = held as usize * self.held_slot_bytes;
        self.held_bytes[start..start + frame_len].copy_from_slice(&frame[..frame_len]);
        self.held[held as usize] = Ipv4FragmentHeldSlot {
            next: NONE,
            frame_len: u32::try_from(frame_len).expect("bounded by the held slot"),
        };
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
        self.live_held += 1;
        self.counters.held += 1;
        Ok(Ipv4FragmentFollow::Held)
    }

    /// A later fragment was forwarded with its entry's template; the entry
    /// is freed once its whole datagram was seen.
    pub(crate) fn followed(&mut self, entry: u32) {
        self.counters.followed += 1;
        let index = entry as usize;
        if self.entries.get(index).is_some() {
            self.complete_if_covered(index);
        }
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

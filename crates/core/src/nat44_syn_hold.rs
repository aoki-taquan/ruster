//! Bounded hold table for unsolicited inbound TCP SYNs (RFC 5382 REQ-4).
//!
//! RFC 5382 §5 REQ-4: a NAT MUST NOT respond to an unsolicited inbound SYN
//! for at least 6 seconds after it is received. If during that interval the
//! NAT receives and translates an outbound SYN for the connection, it MUST
//! silently drop the original SYN; otherwise it SHOULD send an ICMP Port
//! Unreachable (Type 3, Code 3).
//!
//! The table copies the original IPv4 datagram (at most
//! [`ICMPV4_ERROR_MAX_QUOTE_LEN`] bytes) into a caller-backed slot, keyed by
//! the connection seen from the outside: public port `p`, remote IPv4 `R`,
//! and remote port `r`. One hold exists per key. Every operation is O(1) or
//! walks one keyed chain of at most [`NAT44_TCP_SYN_HOLD_CHAIN_LIMIT`] slots
//! and never allocates:
//!
//! - **Index.** Slot `i` stores the head of bucket `i` and, as a chain node,
//!   the bucket it is linked in. The bucket is the keyed SipHash of the key
//!   (the TCP NAT runtime's secret hash key, rotated on every reconcile)
//!   reduced to the slot count. A chain that already holds the limit refuses
//!   a new key (fail closed, as a full table).
//! - **Deadline order.** Occupied slots form one FIFO list. A hold's
//!   deadline is its capture time plus [`NAT44_TCP_UNSOLICITED_SYN_HOLD_MS`]
//!   and capture times never decrease (the runtime clock watermark), so the
//!   head always has the earliest deadline: maturity is a head check, not a
//!   scan. A retransmitted SYN of a held key restarts the hold at the tail.
//! - **Free list.** Unoccupied slots form a second list; a new hold takes its
//!   head.

use crate::{
    fixed_directory::{DirectoryHashDomain, DirectoryHashKey},
    slot_index::{self, key_bucket, Chain, ChainNode, IndexCorrupt, INDEX_NONE},
    slot_list::{Linked, SlotLinks, SlotList},
    Ipv4Address, OccupancyCounter, TableOccupancy, ICMPV4_ERROR_MAX_QUOTE_LEN,
};

/// Minimum time an unsolicited inbound TCP SYN is held before the NAT may
/// answer it with ICMP Port Unreachable (RFC 5382 REQ-4: "at least 6
/// seconds"). A hold is never released toward ICMP earlier.
pub const NAT44_TCP_UNSOLICITED_SYN_HOLD_MS: u64 = 6_000;

/// Longest keyed chain of the unsolicited-SYN hold index. A new key whose
/// chain already has this many holds is refused like a full table.
pub const NAT44_TCP_SYN_HOLD_CHAIN_LIMIT: usize = 16;

/// Largest supported hold table (slot indexes and links are `u32`, with
/// `u32::MAX` reserved).
pub(crate) const MAX_SYN_HOLD_SLOTS: usize = (u32::MAX - 1) as usize;

/// One caller-backed unsolicited-SYN hold: the key, the deadline, and a copy
/// of the original IPv4 datagram (no packet buffer is retained).
///
/// The `Debug` output is redacted: it never prints remote endpoints or quoted
/// bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44TcpSynHoldSlot {
    deadline_ms: u64,
    remote_address: Ipv4Address,
    public_port: u16,
    remote_port: u16,
    quote_len: u16,
    original_tos: u8,
    occupied: bool,
    chain: ChainNode,
    bucket_head: u32,
    order: SlotLinks,
    quote: [u8; ICMPV4_ERROR_MAX_QUOTE_LEN],
}

impl Nat44TcpSynHoldSlot {
    pub const EMPTY: Self = Self {
        deadline_ms: 0,
        remote_address: Ipv4Address::from_octets([0; 4]),
        public_port: 0,
        remote_port: 0,
        quote_len: 0,
        original_tos: 0,
        occupied: false,
        chain: ChainNode::UNLINKED,
        bucket_head: INDEX_NONE,
        order: SlotLinks::UNLINKED,
        quote: [0; ICMPV4_ERROR_MAX_QUOTE_LEN],
    };

    #[must_use]
    pub const fn is_occupied(&self) -> bool {
        self.occupied
    }
}

impl Default for Nat44TcpSynHoldSlot {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl std::fmt::Debug for Nat44TcpSynHoldSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44TcpSynHoldSlot")
            .field("occupied", &self.occupied)
            .finish_non_exhaustive()
    }
}

impl Linked for Nat44TcpSynHoldSlot {
    fn links(&self) -> SlotLinks {
        self.order
    }
    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.order
    }
}

struct HoldChain;

impl Chain for HoldChain {
    type Slot = Nat44TcpSynHoldSlot;
    fn node(slot: &Self::Slot) -> ChainNode {
        slot.chain
    }
    fn node_mut(slot: &mut Self::Slot) -> &mut ChainNode {
        &mut slot.chain
    }
    fn head(slot: &Self::Slot) -> u32 {
        slot.bucket_head
    }
    fn head_mut(slot: &mut Self::Slot) -> &mut u32 {
        &mut slot.bucket_head
    }
}

/// The connection an unsolicited inbound SYN tried to open, seen from the
/// outside: the SYN went from `remote_address:remote_port` to the public
/// address and `public_port`. An outbound SYN for the same connection is
/// one whose translated source port is `public_port` and whose destination
/// is `remote_address:remote_port`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SynHoldKey {
    pub public_port: u16,
    pub remote_address: Ipv4Address,
    pub remote_port: u16,
}

impl SynHoldKey {
    fn words(self) -> [u64; 3] {
        [
            u64::from(self.public_port),
            u64::from(u32::from_be_bytes(self.remote_address.octets())),
            u64::from(self.remote_port),
        ]
    }

    fn matches(self, slot: &Nat44TcpSynHoldSlot) -> bool {
        slot.occupied
            && slot.public_port == self.public_port
            && slot.remote_address == self.remote_address
            && slot.remote_port == self.remote_port
    }
}

/// Outcome of offering one unsolicited SYN to the table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SynHoldInsert {
    /// A new hold was created.
    Held,
    /// The key was already held: the deadline restarted from this SYN.
    Refreshed,
    /// No free slot, or the key's chain is at its limit: not held.
    Full,
    /// The index is inconsistent: not held (fail closed).
    IndexCorrupt,
}

/// A matured hold removed from the table, with everything needed to build
/// the ICMP error.
#[derive(Clone, Copy)]
pub(crate) struct MaturedSynHold {
    pub key: SynHoldKey,
    pub original_tos: u8,
    quote_len: u16,
    quote: [u8; ICMPV4_ERROR_MAX_QUOTE_LEN],
}

impl MaturedSynHold {
    pub(crate) fn quote(&self) -> &[u8] {
        &self.quote[..usize::from(self.quote_len)]
    }
}

/// Caller-backed unsolicited-SYN hold table; see the module documentation.
pub(crate) struct SynHoldTable<'a> {
    slots: &'a mut [Nat44TcpSynHoldSlot],
    /// Occupied slots in deadline order.
    fifo: SlotList,
    /// Unoccupied slots.
    free: SlotList,
    occupancy: OccupancyCounter,
}

impl<'a> SynHoldTable<'a> {
    /// Takes ownership of `slots` and resets them. Cold path, O(capacity).
    pub(crate) fn new(slots: &'a mut [Nat44TcpSynHoldSlot]) -> Self {
        debug_assert!(slots.len() <= MAX_SYN_HOLD_SLOTS);
        let mut table = Self {
            slots,
            fifo: SlotList::EMPTY,
            free: SlotList::EMPTY,
            occupancy: OccupancyCounter::default(),
        };
        table.reset();
        table
    }

    /// A table without slots: every SYN is refused as `Full`.
    pub(crate) fn empty() -> Self {
        Self::new(&mut [])
    }

    fn reset(&mut self) {
        self.slots.fill(Nat44TcpSynHoldSlot::EMPTY);
        self.fifo = SlotList::EMPTY;
        self.free = SlotList::EMPTY;
        for index in 0..self.slots.len() {
            self.free.push_back(self.slots, index);
        }
    }

    /// Drops every hold (publication flush). Cold path, O(capacity).
    pub(crate) fn flush(&mut self) -> usize {
        let flushed = self.fifo.len();
        self.reset();
        self.occupancy.flush();
        flushed
    }

    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.fifo.len()
    }

    pub(crate) fn occupancy(&self) -> TableOccupancy {
        self.occupancy.snapshot(self.slots.len())
    }

    fn bucket(&self, hash_key: DirectoryHashKey, key: SynHoldKey) -> Option<usize> {
        key_bucket(
            hash_key,
            DirectoryHashDomain::TcpSynHold,
            &key.words(),
            self.slots.len(),
        )
    }

    /// Finds the hold of `key`, walking at most the chain limit. Returns the
    /// bucket, the slot (if held), and the chain nodes visited.
    fn find(
        &self,
        hash_key: DirectoryHashKey,
        key: SynHoldKey,
    ) -> Result<Option<(usize, Option<usize>, usize)>, IndexCorrupt> {
        let Some(bucket) = self.bucket(hash_key, key) else {
            return Ok(None);
        };
        let walked = slot_index::walk::<HoldChain>(
            self.slots,
            bucket,
            NAT44_TCP_SYN_HOLD_CHAIN_LIMIT,
            |index| key.matches(&self.slots[index]),
        )?;
        Ok(Some((bucket, walked.found, walked.visited)))
    }

    /// Holds a copy of `original_ipv4` (truncated to the quote limit) under
    /// `key` until `deadline_ms`, or restarts the deadline of an existing
    /// hold of `key` (keeping its original quote). `deadline_ms` must not be
    /// below any deadline already held (the caller's clock is monotonic).
    pub(crate) fn insert(
        &mut self,
        hash_key: DirectoryHashKey,
        key: SynHoldKey,
        deadline_ms: u64,
        original_tos: u8,
        original_ipv4: &[u8],
    ) -> SynHoldInsert {
        let (bucket, found, visited) = match self.find(hash_key, key) {
            Ok(Some(found)) => found,
            Ok(None) => return SynHoldInsert::Full,
            Err(IndexCorrupt) => return SynHoldInsert::IndexCorrupt,
        };
        if let Some(index) = found {
            if !self.fifo_tail_allows(deadline_ms) {
                return SynHoldInsert::IndexCorrupt;
            }
            self.fifo.unlink(self.slots, index);
            self.slots[index].deadline_ms = deadline_ms;
            self.fifo.push_back(self.slots, index);
            return SynHoldInsert::Refreshed;
        }
        if visited >= NAT44_TCP_SYN_HOLD_CHAIN_LIMIT {
            return SynHoldInsert::Full;
        }
        let Some(index) = self.free.head() else {
            return SynHoldInsert::Full;
        };
        if self.slots[index].occupied || !self.fifo_tail_allows(deadline_ms) {
            return SynHoldInsert::IndexCorrupt;
        }
        if slot_index::link::<HoldChain>(self.slots, index, bucket).is_err() {
            return SynHoldInsert::IndexCorrupt;
        }
        self.free.unlink(self.slots, index);
        let quote_len = original_ipv4.len().min(ICMPV4_ERROR_MAX_QUOTE_LEN);
        let slot = &mut self.slots[index];
        slot.occupied = true;
        slot.public_port = key.public_port;
        slot.remote_address = key.remote_address;
        slot.remote_port = key.remote_port;
        slot.deadline_ms = deadline_ms;
        slot.original_tos = original_tos;
        slot.quote_len = u16::try_from(quote_len).expect("quote limit fits u16");
        slot.quote[..quote_len].copy_from_slice(&original_ipv4[..quote_len]);
        slot.quote[quote_len..].fill(0);
        self.fifo.push_back(self.slots, index);
        self.occupancy.insert();
        SynHoldInsert::Held
    }

    /// The FIFO stays in deadline order only if a new tail is not earlier
    /// than the current tail.
    fn fifo_tail_allows(&self, deadline_ms: u64) -> bool {
        self.fifo
            .tail()
            .is_none_or(|tail| self.slots[tail].deadline_ms <= deadline_ms)
    }

    /// Removes the hold of `key`, if any. Returns whether one was removed;
    /// an inconsistent index removes nothing.
    pub(crate) fn cancel(&mut self, hash_key: DirectoryHashKey, key: SynHoldKey) -> bool {
        if self.fifo.len() == 0 {
            return false;
        }
        match self.find(hash_key, key) {
            Ok(Some((_, Some(index), _))) => self.remove(index).is_ok(),
            Ok(_) | Err(IndexCorrupt) => false,
        }
    }

    /// Removes and returns the earliest hold if its deadline is at or
    /// before `now_ms`. O(1).
    pub(crate) fn pop_matured(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<MaturedSynHold>, IndexCorrupt> {
        let Some(index) = self.fifo.head() else {
            return Ok(None);
        };
        let slot = self.slots[index];
        if !slot.occupied {
            return Err(IndexCorrupt);
        }
        if slot.deadline_ms > now_ms {
            return Ok(None);
        }
        self.remove(index)?;
        Ok(Some(MaturedSynHold {
            key: SynHoldKey {
                public_port: slot.public_port,
                remote_address: slot.remote_address,
                remote_port: slot.remote_port,
            },
            original_tos: slot.original_tos,
            quote_len: slot.quote_len,
            quote: slot.quote,
        }))
    }

    fn remove(&mut self, index: usize) -> Result<(), IndexCorrupt> {
        slot_index::unlink::<HoldChain>(self.slots, index)?;
        self.fifo.unlink(self.slots, index);
        let bucket_head = self.slots[index].bucket_head;
        self.slots[index] = Nat44TcpSynHoldSlot {
            bucket_head,
            ..Nat44TcpSynHoldSlot::EMPTY
        };
        self.free.push_back(self.slots, index);
        self.occupancy.remove();
        Ok(())
    }

    /// The earliest deadline held, if any.
    #[cfg(test)]
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.fifo.head().map(|index| self.slots[index].deadline_ms)
    }

    /// Full structural check (tests only): both lists partition the slots,
    /// the FIFO is in deadline order, and the index links exactly the
    /// occupied slots under their keys.
    #[cfg(test)]
    pub(crate) fn validate(&self, hash_key: DirectoryHashKey) -> bool {
        let mut seen = vec![false; self.slots.len()];
        let mut last_deadline = 0;
        let fifo_ok = self.fifo.validate(self.slots, |index| {
            let slot = self.slots[index];
            let ordered = slot.deadline_ms >= last_deadline;
            last_deadline = slot.deadline_ms;
            let fresh = !std::mem::replace(&mut seen[index], true);
            slot.occupied && ordered && fresh
        });
        let free_ok = self.free.validate(self.slots, |index| {
            let fresh = !std::mem::replace(&mut seen[index], true);
            !self.slots[index].occupied && fresh
        });
        let chains_ok = slot_index::validate::<HoldChain>(self.slots, |index| {
            let slot = self.slots[index];
            slot.occupied.then(|| {
                self.bucket(
                    hash_key,
                    SynHoldKey {
                        public_port: slot.public_port,
                        remote_address: slot.remote_address,
                        remote_port: slot.remote_port,
                    },
                )
                .expect("non-empty table")
            })
        });
        fifo_ok
            && free_ok
            && chains_ok
            && seen.iter().all(|seen| *seen)
            && self.occupancy.occupied() == self.fifo.len()
    }

    /// Chain nodes the lookup of `key` visits (tests only).
    #[cfg(test)]
    pub(crate) fn probe_cost(&self, hash_key: DirectoryHashKey, key: SynHoldKey) -> usize {
        self.find(hash_key, key)
            .ok()
            .flatten()
            .map_or(0, |(_, _, visited)| visited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_key() -> DirectoryHashKey {
        DirectoryHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap()
    }

    fn key(n: u32) -> SynHoldKey {
        SynHoldKey {
            public_port: 40_000 + (n % 1000) as u16,
            remote_address: Ipv4Address::from_octets((0xc633_6400_u32 + n / 1000).to_be_bytes()),
            remote_port: 1024 + (n % 7) as u16,
        }
    }

    fn quote(n: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| n.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn hold_refresh_cancel_and_maturity_follow_deadline_order() {
        let mut slots = vec![Nat44TcpSynHoldSlot::EMPTY; 4];
        let mut table = SynHoldTable::new(&mut slots);
        let k = hash_key();
        assert_eq!(
            table.insert(k, key(1), 6_000, 0, &quote(1, 40)),
            SynHoldInsert::Held
        );
        assert_eq!(
            table.insert(k, key(2), 6_010, 0, &quote(2, 40)),
            SynHoldInsert::Held
        );
        assert_eq!(
            table.insert(k, key(3), 6_020, 0, &quote(3, 40)),
            SynHoldInsert::Held
        );
        assert!(table.validate(k));
        // A retransmission of key 1 restarts its hold at the tail.
        assert_eq!(
            table.insert(k, key(1), 9_000, 0, &quote(9, 40)),
            SynHoldInsert::Refreshed
        );
        assert_eq!(table.len(), 3);
        assert!(table.validate(k));
        assert_eq!(table.next_deadline(), Some(6_010));
        assert!(table.cancel(k, key(2)));
        assert!(!table.cancel(k, key(2)));
        assert!(table.validate(k));
        assert!(table.pop_matured(6_019).unwrap().is_none());
        let matured = table.pop_matured(6_020).unwrap().unwrap();
        assert_eq!(matured.key, key(3));
        assert_eq!(matured.quote(), quote(3, 40).as_slice());
        assert!(table.pop_matured(8_999).unwrap().is_none());
        let matured = table.pop_matured(9_000).unwrap().unwrap();
        assert_eq!(matured.key, key(1));
        // The refresh kept the original quote.
        assert_eq!(matured.quote(), quote(1, 40).as_slice());
        assert_eq!(table.len(), 0);
        assert!(table.validate(k));
        assert_eq!(table.occupancy().occupied(), 0);
        assert_eq!(table.occupancy().high_water(), 3);
    }

    #[test]
    fn full_and_empty_tables_refuse_and_quotes_are_bounded() {
        let mut empty = SynHoldTable::empty();
        assert_eq!(
            empty.insert(hash_key(), key(1), 1, 0, &quote(1, 40)),
            SynHoldInsert::Full
        );
        assert!(empty.pop_matured(u64::MAX).unwrap().is_none());

        let mut slots = vec![Nat44TcpSynHoldSlot::EMPTY; 2];
        let mut table = SynHoldTable::new(&mut slots);
        let k = hash_key();
        let long = quote(7, 1500);
        assert_eq!(table.insert(k, key(1), 1, 0, &long), SynHoldInsert::Held);
        assert_eq!(table.insert(k, key(2), 1, 0, &long), SynHoldInsert::Held);
        assert_eq!(table.insert(k, key(3), 1, 0, &long), SynHoldInsert::Full);
        // A held key is still refreshed when the table is full.
        assert_eq!(
            table.insert(k, key(2), 2, 0, &long),
            SynHoldInsert::Refreshed
        );
        let matured = table.pop_matured(1).unwrap().unwrap();
        assert_eq!(matured.quote().len(), ICMPV4_ERROR_MAX_QUOTE_LEN);
        assert_eq!(matured.quote(), &long[..ICMPV4_ERROR_MAX_QUOTE_LEN]);
        // A freed slot is reused and a shorter quote leaves no stale bytes.
        assert_eq!(
            table.insert(k, key(3), 3, 0, &quote(1, 20)),
            SynHoldInsert::Held
        );
        assert!(table.validate(k));
        assert_eq!(table.flush(), 2);
        assert!(table.validate(k));
        assert!(slots.iter().all(|slot| *slot == Nat44TcpSynHoldSlot::EMPTY
            || (!slot.occupied && slot.quote == [0; ICMPV4_ERROR_MAX_QUOTE_LEN])));
    }

    #[test]
    fn earlier_deadline_than_the_tail_is_refused_as_corrupt() {
        let mut slots = vec![Nat44TcpSynHoldSlot::EMPTY; 4];
        let mut table = SynHoldTable::new(&mut slots);
        let k = hash_key();
        assert_eq!(
            table.insert(k, key(1), 10, 0, &quote(1, 40)),
            SynHoldInsert::Held
        );
        assert_eq!(
            table.insert(k, key(2), 9, 0, &quote(1, 40)),
            SynHoldInsert::IndexCorrupt
        );
        assert_eq!(
            table.insert(k, key(1), 9, 0, &quote(1, 40)),
            SynHoldInsert::IndexCorrupt
        );
        assert!(table.validate(k));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn chain_limit_fails_closed_and_corrupt_links_are_detected() {
        let k = hash_key();
        let mut slots = vec![Nat44TcpSynHoldSlot::EMPTY; 64];
        let mut table = SynHoldTable::new(&mut slots);
        // Keys that all land in one bucket, found by brute force.
        let target = table.bucket(k, key(0)).unwrap();
        let same_bucket: Vec<SynHoldKey> = (0..200_000)
            .map(key)
            .filter(|candidate| table.bucket(k, *candidate) == Some(target))
            .take(NAT44_TCP_SYN_HOLD_CHAIN_LIMIT + 1)
            .collect();
        assert_eq!(same_bucket.len(), NAT44_TCP_SYN_HOLD_CHAIN_LIMIT + 1);
        for held in &same_bucket[..NAT44_TCP_SYN_HOLD_CHAIN_LIMIT] {
            assert_eq!(
                table.insert(k, *held, 1, 0, &quote(1, 40)),
                SynHoldInsert::Held
            );
        }
        assert_eq!(
            table.insert(
                k,
                same_bucket[NAT44_TCP_SYN_HOLD_CHAIN_LIMIT],
                1,
                0,
                &quote(1, 40)
            ),
            SynHoldInsert::Full
        );
        // Every key of the full chain is still found and refreshed.
        assert_eq!(
            table.insert(
                k,
                same_bucket[NAT44_TCP_SYN_HOLD_CHAIN_LIMIT - 1],
                2,
                0,
                &[]
            ),
            SynHoldInsert::Refreshed
        );
        assert!(table.validate(k));

        // A chain head outside the table fails closed.
        let mut slots = vec![Nat44TcpSynHoldSlot::EMPTY; 1];
        let mut table = SynHoldTable::new(&mut slots);
        assert_eq!(
            table.insert(k, key(1), 1, 0, &quote(1, 40)),
            SynHoldInsert::Held
        );
        table.slots[0].bucket_head = 7;
        assert_eq!(
            table.insert(k, key(2), 1, 0, &quote(1, 40)),
            SynHoldInsert::IndexCorrupt
        );
        assert!(!table.cancel(k, key(1)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn production_cap_table_work_is_bounded_per_operation() {
        let capacity = 4096;
        let mut slots = vec![Nat44TcpSynHoldSlot::EMPTY; capacity];
        let mut table = SynHoldTable::new(&mut slots);
        let k = hash_key();
        for n in 0..capacity as u32 {
            assert_eq!(
                table.insert(k, key(n), u64::from(n), 0, &quote(1, 60)),
                SynHoldInsert::Held
            );
        }
        assert_eq!(
            table.insert(k, key(5_000_000), 5_000, 0, &[]),
            SynHoldInsert::Full
        );
        let worst = (0..capacity as u32)
            .map(|n| table.probe_cost(k, key(n)))
            .max()
            .unwrap();
        assert!(worst <= NAT44_TCP_SYN_HOLD_CHAIN_LIMIT, "{worst}");
        assert!(table.validate(k));
        for n in 0..capacity as u64 {
            assert!(table.pop_matured(n).unwrap().is_some());
        }
        assert_eq!(table.len(), 0);
        assert!(table.validate(k));
    }
}

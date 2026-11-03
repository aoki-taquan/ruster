//! Bounded hold and replay of datagrams whose next hop is being resolved
//! (ARP-HOLD, FWD-008, ARP-028; RFC 1122 §2.3.2.2, RFC 1812 §3.3.2).
//!
//! RFC 1122 §2.3.2.2: the link layer SHOULD save (rather than discard) at
//! least one, the latest, packet of each set of packets destined to the
//! same unresolved IP address, and transmit it when the address has been
//! resolved; RFC 1812 §3.3.2 says the same for a router. Without it the first
//! datagram of every new flow towards an unresolved neighbour is lost: the
//! first `ping` fails, a TCP SYN waits for its retransmission, a DNS query
//! retries.
//!
//! How it works:
//!
//! - **Hold.** A forwarded datagram whose decision ends at a neighbour miss
//!   that started or joined an ARP resolution (`NEIGHBOR_UNRESOLVED` with a
//!   queued, retried, or pending request) is copied, as received and
//!   unchanged (the decision does not touch the frame before its commit),
//!   into a core-owned, preallocated slot; the received frame is returned to
//!   the backend as [`crate::ConsumeReason::ArpHeld`]. Nothing was committed
//!   for it: no TTL decrement, no NAT mapping, session, or generated ID, no
//!   firewall state. Cold path only (a miss), no allocation.
//! - **Bounds.** At most `per-neighbor` datagrams per (egress, next hop): a
//!   new one replaces the oldest of that next hop (the latest is kept, as
//!   RFC 1122 asks; the sender's own oldest one when it has one there). At
//!   most `per-host` per (ingress, source): beyond is
//!   [`DropReason::ArpHoldHostLimit`]. At most `per-ingress` per ingress
//!   interface (sources are not authenticated, so a flood on one interface
//!   cannot take another's slots): beyond is
//!   [`DropReason::ArpHoldIngressLimit`]. At most `slots` in all: beyond is
//!   [`DropReason::ArpHoldFull`]. A frame longer than a slot (sized like a
//!   fragmentation slot, so only a simulated one can be) is
//!   [`DropReason::ArpHoldTooLarge`].
//! - **Replay.** After each RX batch the tick walks the held datagrams
//!   (oldest first; O(1) when none). One whose next hop is now known (a
//!   static or a live dynamic neighbour) is run through the whole forwarding
//!   path again, as if it had just arrived, but with the hold disabled:
//!   route, TTL, firewall, NAT, MTU, and fragmentation are decided anew, with
//!   the same publication (a publication apply flushes the holds), and the
//!   NAT and firewall commit then. A datagram it sends whole is staged in a
//!   fragmentation slot ([`Ipv4FragmentationRuntime`]); one it fragments
//!   (DF clear, above the egress MTU) is staged by the forwarding path as
//!   for any datagram. The tick's generated fragment phase, after the
//!   generated ARP and ICMPv4 phases and within its frame budget, sends
//!   them. A tick replays at most as many datagrams as there are free
//!   fragmentation slots; the rest wait for the next tick.
//! - **Failure.** A datagram whose resolution failed or was cancelled is
//!   freed (`failed`); one still held when the resolution could no longer
//!   succeed (`interval × max-attempts` after the hold, the resolution's own
//!   bound) is freed (`expired`). The Host Unreachable for a failed direct
//!   next hop is the resolution's existing one (ICMP4-012H: one per failed
//!   resolution generation, quoting the first eligible datagram, rate
//!   limited per egress).
//!
//! The table is flushed at every publication apply (a held datagram's next
//! hop and its replay belong to the publication it arrived under).

use std::{convert::Infallible, marker::PhantomData, rc::Rc};

use crate::{
    packet, BatchCompletion, ConsumeReason, DropReason, ForwardingSnapshot, IfId, Ipv4Address,
    Ipv4FragmentationRuntime, PacketBatch, PacketLease, PacketSlot, SlotCompletion,
};

const NONE: u32 = u32::MAX;

/// Default `[resolution.hold] per-neighbor`: datagrams held per unresolved
/// next hop. RFC 1122 §2.3.2.2 asks for at least the latest one; three lets
/// a host open a few flows (a SYN and a DNS query, say) towards one next hop
/// at once.
pub const ARP_HOLD_DEFAULT_PER_NEIGHBOR: u16 = 3;
/// Largest `[resolution.hold] per-neighbor`.
pub const ARP_HOLD_MAX_PER_NEIGHBOR: u16 = 64;
/// Default `[resolution.hold] per-host`: datagrams held per (ingress,
/// source).
pub const ARP_HOLD_DEFAULT_PER_HOST: u16 = 16;
/// Default `[resolution.hold] packets`: datagrams held in all.
pub const ARP_HOLD_DEFAULT_PACKETS: u32 = 64;
/// Default `[resolution.hold] per-ingress`: datagrams held per ingress
/// interface, half of the default table, so datagrams arriving on one
/// interface (sources are not authenticated, a WAN flood can claim any)
/// cannot take the slots of another interface's hosts.
pub const ARP_HOLD_DEFAULT_PER_INGRESS: u16 = 32;
/// Largest `[resolution.hold] packets`. Holding and the replay walk visit
/// every held datagram, so the table stays small; and each slot is a
/// fragmentation slot's size (3840 bytes for AF_XDP), so 64 is what the
/// 64 MiB production storage bound leaves with every other table at its
/// maximum.
pub const ARP_HOLD_MAX_PACKETS: u32 = 64;

/// Hold policy: the per-next-hop, per-host, and per-ingress bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpHoldPolicy {
    per_neighbor: u16,
    per_host: u16,
    per_ingress: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArpHoldPolicyError {
    /// `per-neighbor` outside 1 to [`ARP_HOLD_MAX_PER_NEIGHBOR`].
    PerNeighbor,
    /// `per-host` is 0.
    PerHost,
    /// `per-ingress` is 0.
    PerIngress,
}

impl ArpHoldPolicy {
    pub const DEFAULT: Self = Self {
        per_neighbor: ARP_HOLD_DEFAULT_PER_NEIGHBOR,
        per_host: ARP_HOLD_DEFAULT_PER_HOST,
        per_ingress: ARP_HOLD_DEFAULT_PER_INGRESS,
    };

    /// A policy with the default per-ingress bound; see
    /// [`Self::with_per_ingress`].
    pub const fn new(per_neighbor: u16, per_host: u16) -> Result<Self, ArpHoldPolicyError> {
        if per_neighbor == 0 || per_neighbor > ARP_HOLD_MAX_PER_NEIGHBOR {
            return Err(ArpHoldPolicyError::PerNeighbor);
        }
        if per_host == 0 {
            return Err(ArpHoldPolicyError::PerHost);
        }
        Ok(Self {
            per_neighbor,
            per_host,
            per_ingress: ARP_HOLD_DEFAULT_PER_INGRESS,
        })
    }

    /// This policy with at most `per_ingress` (at least 1) datagrams held
    /// per ingress interface.
    pub const fn with_per_ingress(self, per_ingress: u16) -> Result<Self, ArpHoldPolicyError> {
        if per_ingress == 0 {
            return Err(ArpHoldPolicyError::PerIngress);
        }
        Ok(Self {
            per_ingress,
            ..self
        })
    }

    #[must_use]
    pub const fn per_ingress(self) -> u16 {
        self.per_ingress
    }

    #[must_use]
    pub const fn per_neighbor(self) -> u16 {
        self.per_neighbor
    }

    #[must_use]
    pub const fn per_host(self) -> u16 {
        self.per_host
    }
}

impl Default for ArpHoldPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HoldState {
    Free,
    /// Waiting for its next hop.
    Held,
    /// Its next hop is known; lent to this tick's replay.
    Ready,
    /// The replay committed it for TX on `egress`; staged after the replay.
    Committed,
}

/// One held datagram: the frame as received, its next hop, and its place
/// in the age list (or the free list).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpHoldSlot {
    state: HoldState,
    ingress: IfId,
    egress: IfId,
    target: Ipv4Address,
    source: Ipv4Address,
    deadline_ms: u64,
    frame_len: u32,
    older: u32,
    newer: u32,
}

impl ArpHoldSlot {
    pub const EMPTY: Self = Self {
        state: HoldState::Free,
        ingress: IfId(0),
        egress: IfId(0),
        target: Ipv4Address::from_octets([0; 4]),
        source: Ipv4Address::from_octets([0; 4]),
        deadline_ms: 0,
        frame_len: 0,
        older: NONE,
        newer: NONE,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArpHoldStorageError {
    /// The byte storage is not `slots × slot_bytes` for a slot of at least
    /// one minimum-MTU frame (14 + 68 bytes) and at most 14 + 65535.
    SlotBytes,
    /// More than [`ARP_HOLD_MAX_PACKETS`] slots.
    TooManySlots,
}

/// The neighbour miss a held datagram waits on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArpHoldMiss {
    pub(crate) egress: IfId,
    pub(crate) target: Ipv4Address,
    /// When the resolution can no longer succeed (`interval × max-attempts`
    /// after the miss).
    pub(crate) deadline_ms: u64,
}

/// What the resolution says about a held datagram's next hop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArpHoldNextHop {
    /// A static or live dynamic neighbour: replay.
    Known,
    /// Its ARP resolution is still running: keep waiting.
    Resolving,
    /// Its resolution failed (the Failed hold-down): free as `failed`.
    Failed,
    /// No resolution is running and no neighbour is known: it was
    /// cancelled (static or authority change), or a neighbour learned for
    /// it expired while the replay waited for room: free as `cancelled`.
    Gone,
}

/// Cumulative hold counters (never reset by a publication).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArpHoldCounters {
    /// Datagrams held (consumed as `ARP_HELD`).
    pub held: usize,
    /// Held datagrams replaced by a later one to the same next hop
    /// (`per-neighbor` reached; the latest is kept).
    pub replaced: usize,
    /// Datagrams refused because every slot was taken (`ARP_HOLD_FULL`).
    pub refused_full: usize,
    /// Datagrams refused by the per-host bound (`ARP_HOLD_HOST_LIMIT`).
    pub refused_host_limit: usize,
    /// Datagrams refused by the per-ingress bound
    /// (`ARP_HOLD_INGRESS_LIMIT`).
    pub refused_ingress_limit: usize,
    /// Datagrams refused for being longer than a slot
    /// (`ARP_HOLD_TOO_LARGE`).
    pub refused_too_large: usize,
    /// Held datagrams whose next hop became known, replayed through the
    /// forwarding path.
    pub replayed: usize,
    /// Replayed datagrams committed for TX whole and staged for the
    /// generated fragment phase.
    pub replay_sent: usize,
    /// Replayed datagrams the forwarding path fragmented (staged as
    /// fragments, MTU2 part B).
    pub replay_fragmented: usize,
    /// Replayed datagrams the fragment association table parked
    /// (`IPV4_FRAGMENT_HELD`, waiting for their first fragment) instead of
    /// deciding them. Not expected (only first fragments and whole
    /// datagrams are ever held here); kept apart from `replay_dropped` so
    /// it never hides there.
    pub replay_parked: usize,
    /// Replayed datagrams the forwarding path dropped or consumed (not
    /// counted again under the drop and consume reasons: the frame was
    /// counted as `ARP_HELD` when it was received).
    pub replay_dropped: usize,
    /// Replayed datagrams committed for TX that found no fragmentation slot
    /// (only when released held fragments took the room first).
    pub replay_unstaged: usize,
    /// Replays put off to a later tick for lack of a free fragmentation
    /// slot (counted per tick and datagram).
    pub deferred: usize,
    /// Held datagrams freed because their resolution failed.
    pub failed: usize,
    /// Held datagrams freed because their resolution was cancelled or its
    /// learned neighbour expired before the replay found room.
    pub cancelled: usize,
    /// Held datagrams freed when their resolution could no longer succeed.
    pub expired: usize,
    /// Held datagrams dropped by a publication apply.
    pub flushed: usize,
}

/// Caller-backed, worker-local table of datagrams held for ARP resolution.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::ArpHoldRuntime<'static>>();
/// ```
pub struct ArpHoldRuntime<'a> {
    policy: ArpHoldPolicy,
    slots: &'a mut [ArpHoldSlot],
    bytes: &'a mut [u8],
    slot_bytes: usize,
    /// Held datagrams, oldest first.
    oldest: u32,
    newest: u32,
    /// Free slots, linked through `newer`.
    free: u32,
    live: usize,
    counters: ArpHoldCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> ArpHoldRuntime<'a> {
    /// Builds an empty runtime over `slots.len()` slots of
    /// `bytes.len() / slots.len()` bytes each (size them like the
    /// fragmentation slots, [`crate::ipv4_fragment_slot_bytes`]). With no
    /// slot `bytes` must be empty and every eligible miss is
    /// [`DropReason::ArpHoldFull`].
    pub fn new(
        policy: ArpHoldPolicy,
        slots: &'a mut [ArpHoldSlot],
        bytes: &'a mut [u8],
    ) -> Result<Self, ArpHoldStorageError> {
        if slots.len() > ARP_HOLD_MAX_PACKETS as usize {
            return Err(ArpHoldStorageError::TooManySlots);
        }
        let slot_bytes = if slots.is_empty() {
            if !bytes.is_empty() {
                return Err(ArpHoldStorageError::SlotBytes);
            }
            0
        } else {
            let slot_bytes = bytes.len() / slots.len();
            if slot_bytes * slots.len() != bytes.len()
                || slot_bytes < crate::ipv4_fragment_slot_bytes(crate::IPV4_MIN_MTU)
                || slot_bytes > crate::ipv4_fragment_slot_bytes(u16::MAX)
            {
                return Err(ArpHoldStorageError::SlotBytes);
            }
            slot_bytes
        };
        let mut runtime = Self {
            policy,
            slots,
            bytes,
            slot_bytes,
            oldest: NONE,
            newest: NONE,
            free: NONE,
            live: 0,
            counters: ArpHoldCounters::default(),
            _worker_local: PhantomData,
        };
        runtime.reset();
        runtime.bytes.fill(0);
        Ok(runtime)
    }

    #[must_use]
    pub const fn policy(&self) -> ArpHoldPolicy {
        self.policy
    }

    #[must_use]
    pub const fn counters(&self) -> ArpHoldCounters {
        self.counters
    }

    /// Datagrams held now.
    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    #[must_use]
    pub const fn slot_capacity(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub const fn slot_bytes(&self) -> usize {
        self.slot_bytes
    }

    /// Drops every held datagram (counted as `flushed`) and returns how many
    /// there were. A publication apply calls it.
    pub fn flush(&mut self) -> usize {
        let live = self.live;
        self.counters.flushed += live;
        self.reset();
        live
    }

    fn reset(&mut self) {
        let count = self.slots.len();
        for (index, slot) in self.slots.iter_mut().enumerate() {
            *slot = ArpHoldSlot::EMPTY;
            slot.newer = if index + 1 < count {
                u32::try_from(index + 1).expect("bounded by ARP_HOLD_MAX_PACKETS")
            } else {
                NONE
            };
        }
        self.free = if count == 0 { NONE } else { 0 };
        self.oldest = NONE;
        self.newest = NONE;
        self.live = 0;
    }

    fn range(&self, index: usize) -> std::ops::Range<usize> {
        let start = index * self.slot_bytes;
        start..start + self.slots[index].frame_len as usize
    }

    /// Whether the held frame in `index` is a first fragment (MF set,
    /// offset 0).
    fn is_first_fragment(&self, index: usize) -> bool {
        let start = index * self.slot_bytes;
        let flags = self
            .bytes
            .get(start + packet::ETHERNET_HEADER_LEN + 6..start + packet::ETHERNET_HEADER_LEN + 8)
            .map_or(0, |word| u16::from_be_bytes([word[0], word[1]]));
        flags & 0x3fff == 0x2000
    }

    /// Unlinks a held slot from the age list and puts it on the free list.
    fn release(&mut self, index: usize) {
        let ArpHoldSlot { older, newer, .. } = self.slots[index];
        if older == NONE {
            self.oldest = newer;
        } else {
            self.slots[older as usize].newer = newer;
        }
        if newer == NONE {
            self.newest = older;
        } else {
            self.slots[newer as usize].older = older;
        }
        self.slots[index] = ArpHoldSlot {
            newer: self.free,
            ..ArpHoldSlot::EMPTY
        };
        self.free = u32::try_from(index).expect("bounded by ARP_HOLD_MAX_PACKETS");
        self.live -= 1;
    }

    /// Holds `frame` (a forwarded IPv4 datagram as received on `ingress`,
    /// unchanged) until `miss` resolves. Cold path.
    #[cold]
    #[inline(never)]
    pub(crate) fn hold(
        &mut self,
        frame: &[u8],
        ingress: IfId,
        miss: ArpHoldMiss,
        mut first_fragment_dropped: impl FnMut(&[u8], IfId),
    ) -> Result<(), DropReason> {
        if frame.len() > self.slot_bytes && !self.slots.is_empty() {
            self.counters.refused_too_large += 1;
            return Err(DropReason::ArpHoldTooLarge);
        }
        let source = frame
            .get(packet::ETHERNET_HEADER_LEN + 12..packet::ETHERNET_HEADER_LEN + 16)
            .map_or(Ipv4Address::from_octets([0; 4]), |octets| {
                Ipv4Address::from_octets([octets[0], octets[1], octets[2], octets[3]])
            });
        let mut neighbor_count = 0_usize;
        let mut neighbor_oldest_own = NONE;
        let mut neighbor_oldest_same_ingress = NONE;
        // Per ingress at this next hop: (ingress, count, oldest). At most
        // `per-neighbor` (<= 64) datagrams are held for one next hop, so at
        // most that many ingresses; a fixed array on the stack, cold path.
        let mut at_neighbor = [(IfId(0), 0_u16, NONE); ARP_HOLD_MAX_PER_NEIGHBOR as usize];
        let mut ingresses = 0_usize;
        let mut host_count = 0_usize;
        let mut ingress_count = 0_usize;
        let mut cursor = self.oldest;
        while cursor != NONE {
            let slot = &self.slots[cursor as usize];
            let own = slot.ingress == ingress && slot.source == source;
            if slot.egress == miss.egress && slot.target == miss.target {
                if own && neighbor_oldest_own == NONE {
                    neighbor_oldest_own = cursor;
                }
                if slot.ingress == ingress && neighbor_oldest_same_ingress == NONE {
                    neighbor_oldest_same_ingress = cursor;
                }
                match at_neighbor[..ingresses]
                    .iter_mut()
                    .find(|(seen, _, _)| *seen == slot.ingress)
                {
                    Some((_, count, _)) => *count += 1,
                    None if ingresses < ARP_HOLD_MAX_PER_NEIGHBOR as usize => {
                        at_neighbor[ingresses] = (slot.ingress, 1, cursor);
                        ingresses += 1;
                    }
                    None => {}
                }
                neighbor_count += 1;
            }
            host_count += usize::from(own);
            ingress_count += usize::from(slot.ingress == ingress);
            cursor = slot.newer;
        }
        // RFC 1122 §2.3.2.2 keeps the latest datagram: at the next-hop bound
        // an older datagram of that next hop makes room. Which one: the
        // sender's own oldest there, else the oldest from the same ingress
        // (one host, or one interface, cannot push out another's while it
        // has its own there), else the oldest from the ingress holding the
        // most datagrams for this next hop (the oldest of those on a tie):
        // the new ingress holds none there, so it takes from the largest
        // user, and a flood from one interface is bounded by its
        // `per-ingress` share, not by evicting a smaller one.
        let victim = if neighbor_count < usize::from(self.policy.per_neighbor) {
            None
        } else if neighbor_oldest_own != NONE {
            Some(neighbor_oldest_own)
        } else if neighbor_oldest_same_ingress != NONE {
            Some(neighbor_oldest_same_ingress)
        } else {
            // `at_neighbor` is in age order of each ingress's oldest, so the
            // first with the largest count is the oldest on a tie.
            let mut busiest: Option<(u16, u32)> = None;
            for &(_, count, oldest) in &at_neighbor[..ingresses] {
                if busiest.is_none_or(|(most, _)| count > most) {
                    busiest = Some((count, oldest));
                }
            }
            busiest.map(|(_, oldest)| oldest)
        };
        let (freed_for_host, freed_for_ingress) = victim.map_or((false, false), |victim| {
            let slot = &self.slots[victim as usize];
            (
                slot.ingress == ingress && slot.source == source,
                slot.ingress == ingress,
            )
        });
        if host_count - usize::from(freed_for_host) >= usize::from(self.policy.per_host) {
            self.counters.refused_host_limit += 1;
            return Err(DropReason::ArpHoldHostLimit);
        }
        if victim.is_none() && self.free == NONE {
            self.counters.refused_full += 1;
            return Err(DropReason::ArpHoldFull);
        }
        if ingress_count - usize::from(freed_for_ingress) >= usize::from(self.policy.per_ingress) {
            self.counters.refused_ingress_limit += 1;
            return Err(DropReason::ArpHoldIngressLimit);
        }
        if let Some(victim) = victim {
            let victim = victim as usize;
            if self.is_first_fragment(victim) {
                first_fragment_dropped(&self.bytes[self.range(victim)], self.slots[victim].ingress);
            }
            self.release(victim);
            self.counters.replaced += 1;
        }
        let index = self.free;
        if index == NONE {
            self.counters.refused_full += 1;
            return Err(DropReason::ArpHoldFull);
        }
        let index_usize = index as usize;
        self.free = self.slots[index_usize].newer;
        let start = index_usize * self.slot_bytes;
        self.bytes[start..start + frame.len()].copy_from_slice(frame);
        self.slots[index_usize] = ArpHoldSlot {
            state: HoldState::Held,
            ingress,
            egress: miss.egress,
            target: miss.target,
            source,
            deadline_ms: miss.deadline_ms,
            frame_len: u32::try_from(frame.len()).expect("bounded by the slot bytes"),
            older: self.newest,
            newer: NONE,
        };
        if self.newest == NONE {
            self.oldest = index;
        } else {
            self.slots[self.newest as usize].newer = index;
        }
        self.newest = index;
        self.live += 1;
        self.counters.held += 1;
        Ok(())
    }

    /// Marks held datagrams whose next hop `probe` says is resolved as
    /// ready for this tick's replay (oldest first) while their room fits in
    /// `room` fragmentation slots, and frees those whose resolution is over
    /// or which passed their deadline. Returns how many are ready.
    ///
    /// A datagram takes one slot; a first fragment (MF set, offset 0) takes
    /// one plus `fragment_reserve` (the fragments the association table
    /// holds, which its allowed decision releases into the same slots), so
    /// a replay whose NAT and firewall state commit always finds its slot.
    pub(crate) fn mark_ready(
        &mut self,
        now_ms: u64,
        mut room: usize,
        fragment_reserve: usize,
        mut probe: impl FnMut(IfId, Ipv4Address) -> ArpHoldNextHop,
        mut first_fragment_dropped: impl FnMut(&[u8], IfId),
    ) -> usize {
        let mut ready = 0;
        let mut cursor = self.oldest;
        while cursor != NONE {
            let index = cursor as usize;
            let slot = self.slots[index];
            cursor = slot.newer;
            if slot.state != HoldState::Held {
                continue;
            }
            let first_fragment = self.is_first_fragment(index);
            let cost = if first_fragment {
                1 + fragment_reserve
            } else {
                1
            };
            let freed = match probe(slot.egress, slot.target) {
                ArpHoldNextHop::Known if room >= cost => {
                    room -= cost;
                    ready += 1;
                    self.slots[index].state = HoldState::Ready;
                    false
                }
                _ if now_ms >= slot.deadline_ms => {
                    self.counters.expired += 1;
                    true
                }
                ArpHoldNextHop::Known => {
                    self.counters.deferred += 1;
                    false
                }
                ArpHoldNextHop::Resolving => false,
                ArpHoldNextHop::Failed => {
                    self.counters.failed += 1;
                    true
                }
                ArpHoldNextHop::Gone => {
                    self.counters.cancelled += 1;
                    true
                }
            };
            if freed {
                // A dropped first fragment refuses its datagram at once, so
                // the association table frees the later fragments it holds
                // instead of keeping them until its timeout.
                if first_fragment {
                    first_fragment_dropped(&self.bytes[self.range(index)], slot.ingress);
                }
                self.release(index);
            }
        }
        ready
    }

    /// A packet batch over the datagrams [`Self::mark_ready`] marked, for
    /// the forwarding path to decide anew.
    pub(crate) fn replay_batch(&mut self) -> ArpHoldReplayBatch<'_, 'a> {
        let cursor = self.oldest;
        ArpHoldReplayBatch {
            runtime: self,
            cursor,
            tally: ReplayTally::default(),
        }
    }

    /// Stages every datagram the replay committed for TX into a
    /// fragmentation slot (whole: it passed the egress MTU check) and frees
    /// it; a ready datagram the replay did not reach goes back to waiting.
    pub(crate) fn stage_committed(
        &mut self,
        snapshot: &ForwardingSnapshot<'_>,
        fragmentation: &mut Ipv4FragmentationRuntime<'_>,
    ) {
        let mut cursor = self.oldest;
        while cursor != NONE {
            let index = cursor as usize;
            let slot = self.slots[index];
            cursor = slot.newer;
            match slot.state {
                HoldState::Committed => {
                    let range = self.range(index);
                    let frame = &self.bytes[range];
                    let staged = snapshot
                        .interface(slot.egress)
                        .ok_or(DropReason::InterfaceMiss)
                        .and_then(|interface| fragmentation.plan_forward(frame, interface.mtu));
                    match staged {
                        Ok(plan) => {
                            fragmentation.stage(frame, plan, slot.egress);
                            self.counters.replay_sent += 1;
                        }
                        Err(_) => self.counters.replay_unstaged += 1,
                    }
                    self.release(index);
                }
                HoldState::Ready => self.slots[index].state = HoldState::Held,
                HoldState::Free | HoldState::Held => {}
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ReplayTally {
    tx: usize,
    recycled: usize,
}

/// The ready held datagrams as a [`PacketBatch`] (worker-local, never
/// fails). A transmit marks the slot committed for
/// [`ArpHoldRuntime::stage_committed`]; any other completion frees it.
pub(crate) struct ArpHoldReplayBatch<'r, 'a> {
    runtime: &'r mut ArpHoldRuntime<'a>,
    cursor: u32,
    tally: ReplayTally,
}

impl<'a> PacketBatch for ArpHoldReplayBatch<'_, 'a> {
    type Error = Infallible;
    type Slot<'s>
        = ArpHoldReplaySlot<'s, 'a>
    where
        Self: 's;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        while self.cursor != NONE {
            let index = self.cursor as usize;
            let slot = self.runtime.slots[index];
            self.cursor = slot.newer;
            if slot.state == HoldState::Ready {
                self.runtime.counters.replayed += 1;
                return Some(PacketLease::new(ArpHoldReplaySlot {
                    runtime: &mut *self.runtime,
                    tally: &mut self.tally,
                    index,
                }));
            }
        }
        None
    }

    fn finish(self) -> BatchCompletion<Infallible> {
        BatchCompletion {
            tx_requested: self.tally.tx,
            tx_accepted: self.tally.tx,
            tx_rejected: 0,
            recycled: self.tally.recycled,
            error: None,
        }
    }
}

/// One ready held datagram lent to the replay.
pub(crate) struct ArpHoldReplaySlot<'s, 'a> {
    runtime: &'s mut ArpHoldRuntime<'a>,
    tally: &'s mut ReplayTally,
    index: usize,
}

impl PacketSlot for ArpHoldReplaySlot<'_, '_> {
    fn ingress(&self) -> IfId {
        self.runtime.slots[self.index].ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let range = self.runtime.range(self.index);
        &mut self.runtime.bytes[range]
    }

    fn complete(self, completion: SlotCompletion) {
        let runtime = self.runtime;
        match completion {
            SlotCompletion::Transmit(egress) => {
                let slot = &mut runtime.slots[self.index];
                slot.state = HoldState::Committed;
                slot.egress = egress;
                self.tally.tx += 1;
            }
            SlotCompletion::Consume(ConsumeReason::Ipv4Fragmented) => {
                runtime.counters.replay_fragmented += 1;
                runtime.release(self.index);
                self.tally.recycled += 1;
            }
            SlotCompletion::Consume(ConsumeReason::Ipv4FragmentHeld) => {
                runtime.counters.replay_parked += 1;
                runtime.release(self.index);
                self.tally.recycled += 1;
            }
            SlotCompletion::Consume(_)
            | SlotCompletion::Recycle(_)
            | SlotCompletion::LeaseAbandoned => {
                runtime.counters.replay_dropped += 1;
                runtime.release(self.index);
                self.tally.recycled += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests;

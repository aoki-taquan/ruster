//! The MAC address table of the FE's bridges, and what a bridge does with a frame.
//!
//! See `docs/design/overlay.md`, section 1. A bridge is one broadcast domain whose
//! members are interfaces (ports, VLAN sub-interfaces). [`MacTable`] holds, for every
//! bridge, the member each MAC address was last seen on: entries it learned from the
//! frames' source addresses, which age, and static ones the control side wrote, which
//! do not. [`MacTable::receive`] decides what happens to a frame received on a member:
//! it goes up to the bridge's own interface (the IRB), out of one member, or out of
//! all the others (flooding). The table never allocates after [`MacTable::new`] while
//! packets pass; only [`MacTable::republish`], on a table change, does.
//!
//! # Standards
//!
//! - IEEE 802.1Q-2018 8.6 (the forwarding process): a frame goes out of the port its
//!   destination was learned on, never back out of the port it came in on, and is
//!   flooded when its destination is a group address or unknown.
//! - IEEE 802.1Q-2018 8.7 and 8.8 (learning and the filtering database): addresses
//!   are learned from the source of the frames received, a static entry is not
//!   changed by learning, and a learned entry ages out after the ageing time (300 s
//!   recommended, 8.8.3).
//! - IEEE 802.1Q-2018 8.6.3 and table 8-1: frames to 01-80-C2-00-00-00 to
//!   01-80-C2-00-00-0F are not relayed.
//!
//! Deviations: no spanning tree (the operator keeps the topology free of loops); a
//! bridge does not tell VLANs apart (VLAN-unaware: make one bridge per VLAN with VLAN
//! sub-interfaces as members); a frame with a group or all-zero source address is
//! dropped, not relayed.

use crate::fixed_directory::DirectoryHashDomain;
use crate::{IfId, ResolutionHashKey};

/// What one bridge allows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeLimits {
    /// A learned entry not seen for this long is no longer used.
    pub aging_ms: u64,
    /// The most learned entries of the bridge.
    pub max_macs: u32,
}

/// What one bridge did. Kept across table changes while the bridge stays.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BridgeCounters {
    /// Addresses learned anew.
    pub learned: u64,
    /// Learned addresses seen on another member, which they moved to.
    pub moved: u64,
    /// Learned addresses removed for not being seen within the ageing time.
    pub aged: u64,
    /// Addresses not learned because the bridge or the table was full.
    pub limited: u64,
    /// Frames sent out of the one member their destination was learned on.
    pub forwarded: u64,
    /// Frames flooded (each counted once), and copies of them that could not be sent.
    pub flooded: u64,
    pub flood_dropped: u64,
    /// Frames dropped because their destination is on the member they came in on.
    pub filtered: u64,
    /// Frames dropped because their destination is reserved (IEEE 802.1Q table 8-1)
    /// or their source is not a unicast address.
    pub dropped: u64,
}

/// What happens to a frame received on a member of a bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeDecision {
    /// The frame is the bridge's own interface's (the IRB's): it is received there.
    Irb,
    /// The frame goes out of this member only.
    Forward(IfId),
    /// The frame goes out of every member but the one it came in on, and is also
    /// received on the IRB when `irb` (a broadcast or multicast frame).
    Flood { irb: bool },
    /// The frame is dropped (and counted).
    Drop,
}

/// What learning a source address did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Learned {
    New,
    Refreshed,
    Moved,
    /// A static entry has the address; it was left as it is.
    Static,
    /// The bridge or the table is full.
    Limited,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    used: bool,
    fixed: bool,
    bridge: u16,
    mac: [u8; 6],
    member: IfId,
    seen_ms: u64,
}

const EMPTY: Slot = Slot {
    used: false,
    fixed: false,
    bridge: 0,
    mac: [0; 6],
    member: IfId(0),
    seen_ms: 0,
};

#[derive(Clone, Copy, Debug)]
struct Bridge {
    limits: BridgeLimits,
    learned: u32,
    counters: BridgeCounters,
}

/// One entry of the table, as [`MacTable::entries`] shows it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacEntry {
    pub bridge: u16,
    pub mac: [u8; 6],
    pub member: IfId,
    /// A static entry (written by the control side), not a learned one.
    pub fixed: bool,
    /// When a learned entry was last seen.
    pub seen_ms: u64,
}

/// The MAC address table of every bridge: open addressing with linear probing, at
/// most half full.
pub struct MacTable {
    slots: Box<[Slot]>,
    mask: usize,
    /// Entries in use, and the most there may be.
    len: usize,
    capacity: usize,
    key: ResolutionHashKey,
    bridges: Vec<Bridge>,
    /// Where the next [`MacTable::age`] goes on looking.
    sweep: usize,
}

impl std::fmt::Debug for MacTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacTable")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("bridges", &self.bridges)
            .finish_non_exhaustive()
    }
}

fn is_group(mac: &[u8; 6]) -> bool {
    mac[0] & 1 != 0
}

/// IEEE 802.1Q table 8-1: 01-80-C2-00-00-00 to 01-80-C2-00-00-0F.
fn is_reserved(mac: &[u8; 6]) -> bool {
    mac[..5] == [0x01, 0x80, 0xc2, 0x00, 0x00] && mac[5] <= 0x0f
}

impl MacTable {
    /// A table for at most `capacity` entries (learned and static, of all bridges),
    /// hashed with `key`. No bridge is set until [`MacTable::republish`].
    #[must_use]
    pub fn new(capacity: usize, key: ResolutionHashKey) -> Self {
        let slots = (capacity.max(1) * 2).next_power_of_two();
        Self {
            slots: vec![EMPTY; slots].into_boxed_slice(),
            mask: slots - 1,
            len: 0,
            capacity,
            key,
            bridges: Vec::new(),
            sweep: 0,
        }
    }

    fn home(&self, bridge: u16, mac: &[u8; 6]) -> usize {
        let mut word = [0_u8; 8];
        word[..2].copy_from_slice(&bridge.to_be_bytes());
        word[2..].copy_from_slice(mac);
        let hash = self
            .key
            .directory_key()
            .hash_words(DirectoryHashDomain::BridgeMac, &[u64::from_be_bytes(word)]);
        // Truncation is fine: only the low bits pick the slot.
        #[allow(clippy::cast_possible_truncation)]
        let at = hash as usize;
        at & self.mask
    }

    fn find(&self, bridge: u16, mac: &[u8; 6]) -> Option<usize> {
        let mut at = self.home(bridge, mac);
        loop {
            let slot = &self.slots[at];
            if !slot.used {
                return None;
            }
            if slot.bridge == bridge && slot.mac == *mac {
                return Some(at);
            }
            at = (at + 1) & self.mask;
        }
    }

    fn insert(&mut self, slot: Slot) {
        let mut at = self.home(slot.bridge, &slot.mac);
        while self.slots[at].used {
            at = (at + 1) & self.mask;
        }
        self.slots[at] = slot;
        self.len += 1;
    }

    /// Empties slot `at`, moving back the entries after it that would no longer be
    /// found (backward-shift deletion).
    fn remove(&mut self, mut at: usize) {
        let removed = self.slots[at];
        if !removed.fixed {
            if let Some(bridge) = self.bridges.get_mut(usize::from(removed.bridge)) {
                bridge.learned = bridge.learned.saturating_sub(1);
            }
        }
        self.slots[at] = EMPTY;
        self.len -= 1;
        let mut next = (at + 1) & self.mask;
        while self.slots[next].used {
            let home = self.home(self.slots[next].bridge, &self.slots[next].mac);
            // The entry at `next` may move to `at` if its home is not in (at, next].
            let distance_home = next.wrapping_sub(home) & self.mask;
            let distance_hole = next.wrapping_sub(at) & self.mask;
            if distance_home >= distance_hole {
                self.slots[at] = self.slots[next];
                self.slots[next] = EMPTY;
                at = next;
            }
            next = (next + 1) & self.mask;
        }
    }

    fn aged(&self, slot: &Slot, now_ms: u64) -> bool {
        !slot.fixed
            && self
                .bridges
                .get(usize::from(slot.bridge))
                .is_none_or(|b| now_ms.saturating_sub(slot.seen_ms) > b.limits.aging_ms)
    }

    /// Sets the bridges (in the order of their ids) and the static entries after a
    /// table change. Bridge `new` was bridge `old_of_new[new]` before (`None` for a new
    /// one): it keeps its counters and learned entries, but only those whose member
    /// `keep(new, member)` allows. Static entries are replaced by `statics` (bridge,
    /// address, member); those beyond the capacity are left out and their number
    /// returned.
    pub fn republish(
        &mut self,
        bridges: &[BridgeLimits],
        old_of_new: &[Option<u16>],
        keep: impl Fn(u16, IfId) -> bool,
        statics: &[(u16, [u8; 6], IfId)],
    ) -> usize {
        let old: Vec<Slot> = self.slots.iter().filter(|s| s.used).copied().collect();
        let old_bridges = std::mem::take(&mut self.bridges);
        self.slots.fill(EMPTY);
        self.len = 0;
        self.sweep = 0;
        self.bridges = bridges
            .iter()
            .enumerate()
            .map(|(at, limits)| Bridge {
                limits: *limits,
                learned: 0,
                counters: old_of_new
                    .get(at)
                    .copied()
                    .flatten()
                    .and_then(|old| old_bridges.get(usize::from(old)))
                    .map_or_else(BridgeCounters::default, |b| b.counters),
            })
            .collect();
        let mut left_out = 0;
        for &(bridge, mac, member) in statics {
            if usize::from(bridge) >= self.bridges.len() || self.find(bridge, &mac).is_some() {
                continue;
            }
            if self.len >= self.capacity {
                left_out += 1;
                continue;
            }
            self.insert(Slot {
                used: true,
                fixed: true,
                bridge,
                mac,
                member,
                seen_ms: 0,
            });
        }
        for slot in old.into_iter().filter(|s| !s.fixed) {
            let Some(new) = old_of_new
                .iter()
                .position(|&o| o == Some(slot.bridge))
                .and_then(|at| u16::try_from(at).ok())
            else {
                continue;
            };
            let room = self.bridges[usize::from(new)].learned
                < self.bridges[usize::from(new)].limits.max_macs;
            if !keep(new, slot.member)
                || self.find(new, &slot.mac).is_some()
                || self.len >= self.capacity
                || !room
            {
                continue;
            }
            self.insert(Slot {
                bridge: new,
                ..slot
            });
            self.bridges[usize::from(new)].learned += 1;
        }
        left_out
    }

    /// Learns that `mac` was seen on `member` of `bridge` at `now_ms`.
    pub fn learn(&mut self, bridge: u16, mac: [u8; 6], member: IfId, now_ms: u64) -> Learned {
        let Some(state) = self.bridges.get(usize::from(bridge)) else {
            return Learned::Limited;
        };
        let full = state.learned >= state.limits.max_macs;
        if let Some(at) = self.find(bridge, &mac) {
            let aged = self.aged(&self.slots[at], now_ms);
            let slot = &mut self.slots[at];
            if slot.fixed {
                return Learned::Static;
            }
            slot.seen_ms = now_ms;
            if slot.member == member {
                return Learned::Refreshed;
            }
            slot.member = member;
            let counters = &mut self.bridges[usize::from(bridge)].counters;
            // An entry past its age that comes back elsewhere is learned anew.
            if aged {
                counters.aged += 1;
                counters.learned += 1;
                return Learned::New;
            }
            counters.moved += 1;
            return Learned::Moved;
        }
        if full || self.len >= self.capacity {
            self.bridges[usize::from(bridge)].counters.limited += 1;
            return Learned::Limited;
        }
        self.insert(Slot {
            used: true,
            fixed: false,
            bridge,
            mac,
            member,
            seen_ms: now_ms,
        });
        let state = &mut self.bridges[usize::from(bridge)];
        state.learned += 1;
        state.counters.learned += 1;
        Learned::New
    }

    /// The member `mac` of `bridge` is on, unless it is not known or has aged (then
    /// its entry goes).
    pub fn lookup(&mut self, bridge: u16, mac: &[u8; 6], now_ms: u64) -> Option<IfId> {
        let at = self.find(bridge, mac)?;
        if self.aged(&self.slots[at], now_ms) {
            if let Some(b) = self.bridges.get_mut(usize::from(bridge)) {
                b.counters.aged += 1;
            }
            self.remove(at);
            return None;
        }
        Some(self.slots[at].member)
    }

    /// Looks at up to `budget` slots, from where the last call stopped, and removes the
    /// learned entries past their age.
    pub fn age(&mut self, now_ms: u64, budget: usize) {
        for _ in 0..budget.min(self.slots.len()) {
            let at = self.sweep;
            let slot = self.slots[at];
            if slot.used && self.aged(&slot, now_ms) {
                if let Some(b) = self.bridges.get_mut(usize::from(slot.bridge)) {
                    b.counters.aged += 1;
                }
                // An entry moved back into `at` is looked at on the next turn.
                self.remove(at);
                continue;
            }
            self.sweep = (at + 1) & self.mask;
        }
    }

    /// Decides what bridge `bridge` does with `frame` (Ethernet, without a VLAN tag)
    /// received on `member` at `now_ms`, learning its source; `irb` is the MAC address
    /// of the bridge's own interface, when it has one.
    pub fn receive(
        &mut self,
        bridge: u16,
        member: IfId,
        frame: &[u8],
        irb: Option<[u8; 6]>,
        now_ms: u64,
    ) -> BridgeDecision {
        let (Some(destination), Some(source)) = (frame.get(0..6), frame.get(6..12)) else {
            return BridgeDecision::Drop;
        };
        let destination: [u8; 6] = destination.try_into().expect("six bytes");
        let source: [u8; 6] = source.try_into().expect("six bytes");
        if usize::from(bridge) >= self.bridges.len() {
            return BridgeDecision::Drop;
        }
        if is_reserved(&destination) || is_group(&source) || source == [0; 6] {
            self.bridges[usize::from(bridge)].counters.dropped += 1;
            return BridgeDecision::Drop;
        }
        self.learn(bridge, source, member, now_ms);
        if Some(destination) == irb {
            return BridgeDecision::Irb;
        }
        if is_group(&destination) {
            return BridgeDecision::Flood { irb: irb.is_some() };
        }
        match self.lookup(bridge, &destination, now_ms) {
            Some(out) if out == member => {
                self.bridges[usize::from(bridge)].counters.filtered += 1;
                BridgeDecision::Drop
            }
            Some(out) => BridgeDecision::Forward(out),
            None => BridgeDecision::Flood { irb: false },
        }
    }

    /// The member a frame to `destination` leaves bridge `bridge` through when the
    /// bridge's own interface sends it, or `None` to flood it (a group address, or
    /// one not known).
    pub fn send(&mut self, bridge: u16, destination: &[u8; 6], now_ms: u64) -> Option<IfId> {
        if is_group(destination) {
            return None;
        }
        self.lookup(bridge, destination, now_ms)
    }

    /// Counts a frame sent out of one member.
    pub fn count_forwarded(&mut self, bridge: u16) {
        if let Some(b) = self.bridges.get_mut(usize::from(bridge)) {
            b.counters.forwarded += 1;
        }
    }

    /// Counts a flooded frame, and the copies of it that could not be sent.
    pub fn count_flood(&mut self, bridge: u16, dropped: u64) {
        if let Some(b) = self.bridges.get_mut(usize::from(bridge)) {
            b.counters.flooded += 1;
            b.counters.flood_dropped += dropped;
        }
    }

    /// Each bridge's counters, in the order of their ids.
    pub fn counters(&self) -> impl Iterator<Item = BridgeCounters> + '_ {
        self.bridges.iter().map(|b| b.counters)
    }

    /// Every entry, learned ones past their age included until they are removed.
    pub fn entries(&self) -> impl Iterator<Item = MacEntry> + '_ {
        self.slots.iter().filter(|s| s.used).map(|s| MacEntry {
            bridge: s.bridge,
            mac: s.mac,
            member: s.member,
            fixed: s.fixed,
            seen_ms: s.seen_ms,
        })
    }

    /// The entries in use.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [2, 0, 0, 0, 0, 0xa];
    const B: [u8; 6] = [2, 0, 0, 0, 0, 0xb];
    const IRB: [u8; 6] = [2, 0, 0, 0, 0, 0x1];
    const P1: IfId = IfId(1);
    const P2: IfId = IfId(2);
    const P3: IfId = IfId(3);

    fn table(capacity: usize, max_macs: u32) -> MacTable {
        let mut table = MacTable::new(capacity, ResolutionHashKey::new(7, 9).unwrap());
        table.republish(
            &[BridgeLimits {
                aging_ms: 300_000,
                max_macs,
            }],
            &[None],
            |_, _| true,
            &[],
        );
        table
    }

    fn frame(destination: [u8; 6], source: [u8; 6]) -> Vec<u8> {
        let mut f = destination.to_vec();
        f.extend_from_slice(&source);
        f.extend_from_slice(&[0x08, 0x00]);
        f
    }

    #[test]
    fn learns_forwards_floods_and_filters() {
        let mut t = table(16, 16);
        // B is not known yet: flooded, A learned on P1.
        let d = t.receive(0, P1, &frame(B, A), Some(IRB), 0);
        assert_eq!(d, BridgeDecision::Flood { irb: false });
        // A is known: B's reply goes to P1 only.
        assert_eq!(
            t.receive(0, P2, &frame(A, B), Some(IRB), 1),
            BridgeDecision::Forward(P1)
        );
        // Back to where it came from: dropped.
        assert_eq!(
            t.receive(0, P2, &frame(B, A), Some(IRB), 2),
            BridgeDecision::Drop
        );
        // A moved to P2 with that frame, so this one is filtered too.
        assert_eq!(t.counters().next().unwrap().moved, 1);
        assert_eq!(t.counters().next().unwrap().filtered, 1);
        // Broadcast: flooded and received on the IRB.
        assert_eq!(
            t.receive(0, P3, &frame([0xff; 6], [2, 0, 0, 0, 0, 0xc]), Some(IRB), 3),
            BridgeDecision::Flood { irb: true }
        );
        assert_eq!(
            t.receive(0, P3, &frame(IRB, [2, 0, 0, 0, 0, 0xc]), Some(IRB), 4),
            BridgeDecision::Irb
        );
        assert_eq!(t.counters().next().unwrap().learned, 3);
    }

    #[test]
    fn reserved_and_bad_sources_are_dropped() {
        let mut t = table(16, 16);
        let stp = [0x01, 0x80, 0xc2, 0, 0, 0];
        assert_eq!(
            t.receive(0, P1, &frame(stp, A), None, 0),
            BridgeDecision::Drop
        );
        assert_eq!(
            t.receive(0, P1, &frame(B, [0xff; 6]), None, 0),
            BridgeDecision::Drop
        );
        assert_eq!(
            t.receive(0, P1, &frame(B, [0; 6]), None, 0),
            BridgeDecision::Drop
        );
        assert_eq!(t.counters().next().unwrap().dropped, 3);
        assert!(t.is_empty());
        // IS-IS's AllL1ISs is past the reserved range: flooded.
        let isis = [0x01, 0x80, 0xc2, 0, 0, 0x14];
        assert_eq!(
            t.receive(0, P1, &frame(isis, A), None, 0),
            BridgeDecision::Flood { irb: false }
        );
    }

    #[test]
    fn entries_age() {
        let mut t = table(16, 16);
        t.learn(0, A, P1, 0);
        assert_eq!(t.send(0, &A, 300_000), Some(P1));
        assert_eq!(t.send(0, &A, 300_001), None);
        assert_eq!(t.counters().next().unwrap().aged, 1);
        assert!(t.is_empty());
        // The sweep removes those not looked up.
        t.learn(0, B, P2, 1_000);
        t.age(400_000, 1_000);
        assert!(t.is_empty());
        assert_eq!(t.counters().next().unwrap().aged, 2);
    }

    #[test]
    fn limits_and_statics() {
        let mut t = table(16, 2);
        assert_eq!(t.learn(0, A, P1, 0), Learned::New);
        assert_eq!(t.learn(0, B, P1, 0), Learned::New);
        assert_eq!(t.learn(0, [2, 0, 0, 0, 0, 9], P1, 0), Learned::Limited);
        assert_eq!(t.counters().next().unwrap().limited, 1);
        // A static entry is not moved by learning, and does not age.
        let s = [2, 0, 0, 0, 0, 0x55];
        let left = t.republish(
            &[BridgeLimits {
                aging_ms: 1,
                max_macs: 2,
            }],
            &[Some(0)],
            |_, member| member != P1,
            &[(0, s, P3)],
        );
        assert_eq!(left, 0);
        // The learned entries on P1 went; the counters stayed.
        assert_eq!(t.len(), 1);
        assert_eq!(t.counters().next().unwrap().learned, 2);
        assert_eq!(t.learn(0, s, P1, 5), Learned::Static);
        assert_eq!(t.send(0, &s, 1_000_000), Some(P3));
    }

    #[test]
    fn many_entries_survive_removals() {
        let mut t = table(512, 500);
        let mac = |i: u16| {
            let [a, b] = i.to_be_bytes();
            [2, 0, 0, 0, a, b]
        };
        for i in 0..500 {
            assert_eq!(t.learn(0, mac(i), IfId(i % 7), u64::from(i)), Learned::New);
        }
        assert_eq!(t.learn(0, mac(999), P1, 0), Learned::Limited);
        // Every other one ages out (seen at an even time, aged after 300 s from 0).
        for i in (0..500).step_by(2) {
            assert_eq!(t.lookup(0, &mac(i), 300_000 + u64::from(i) + 1), None);
        }
        for i in (1..500).step_by(2) {
            assert_eq!(t.lookup(0, &mac(i), 300_000), Some(IfId(i % 7)));
        }
        assert_eq!(t.len(), 250);
    }

    #[test]
    fn bridges_are_apart() {
        let mut t = MacTable::new(16, ResolutionHashKey::new(1, 2).unwrap());
        let limits = BridgeLimits {
            aging_ms: 1_000,
            max_macs: 4,
        };
        t.republish(&[limits, limits], &[None, None], |_, _| true, &[]);
        t.learn(0, A, P1, 0);
        assert_eq!(t.send(1, &A, 0), None);
        t.learn(1, A, P2, 0);
        assert_eq!(t.send(0, &A, 0), Some(P1));
        assert_eq!(t.send(1, &A, 0), Some(P2));
        // Bridge 1 goes, bridge 0 becomes 1.
        t.republish(&[limits], &[Some(0)], |_, _| true, &[]);
        assert_eq!(t.send(0, &A, 0), Some(P1));
        assert_eq!(t.len(), 1);
    }
}

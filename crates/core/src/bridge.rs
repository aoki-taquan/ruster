//! The MAC address table of the FE's bridges, and what a bridge does with a frame.
//!
//! See `docs/design/overlay.md`, section 1. A bridge is one broadcast domain whose
//! members are interfaces (ports, VLAN sub-interfaces, overlays). [`MacTable`] holds, for every
//! bridge, the member each MAC address was last seen on: entries it learned from the
//! frames' source addresses, which age, and static ones the control side wrote, which
//! do not. [`MacTable::receive`] decides what happens to a frame received on a member:
//! it goes up to the bridge's own interface (the IRB), out of one member, or out of
//! all the others (flooding). [`Bridges`] holds every bridge's members and IRB with the
//! table, and is what forwarding uses: frames it floods are copied out to slots made
//! at the start, for the caller to send after the batch. The table never allocates after [`MacTable::new`] while
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
//! - RFC 7348 section 4.1: an address learned on a VXLAN member is learned with the
//!   remote VTEP it came from, and frames to it go to that VTEP.
//! - RFC 7432 section 15 (MAC mobility): an address a routing daemon says is behind
//!   a remote VTEP is a movable static entry. Seen on another member, it has moved
//!   there and is learned there; the daemon hears of it from the learned entries
//!   and advertises it. While the daemon still gives the same remote entry, the
//!   learned one stays; given otherwise (another VTEP, or withdrawn and given
//!   again), the remote one replaces it.
//! - RFC 9161 section 3.3 (proxy ARP): a broadcast ARP request (RFC 826) received on
//!   a local member (a port or VLAN sub-interface, not an overlay) for a remote host
//!   a routing daemon gave is answered there, with the host's addresses as the
//!   source and sender; it is not flooded. Not answered: gratuitous requests, those
//!   for unknown addresses (flooded), and those for a host learned on the asking
//!   member.
//! - RFC 9161 section 3.3 (proxy ND) and RFC 4861 section 7.2.4: a Neighbor
//!   Solicitation to the target's solicited-node address, likewise, is answered with
//!   a Neighbor Advertisement from the host's addresses, R as the routing daemon
//!   gave, S and O set, and its MAC address as the Target Link-Layer Address.
//!
//! Deviations from RFC 9161: DAD solicitations (from the unspecified address) are
//! not answered but flooded (the host itself answers); a solicitation with an
//! extension header or with other options than the Source Link-Layer Address is
//! flooded ("forward" of section 3.3 (f)); there is no per-host O flag (always set,
//! no anycast).
//!
//! Deviations: a movable static entry is changed by learning (802.1Q 8.7 keeps
//! static entries); no spanning tree (the operator keeps the topology free of loops); a
//! bridge does not tell VLANs apart (VLAN-unaware: make one bridge per VLAN with VLAN
//! sub-interfaces as members); a frame with a group or all-zero source address is
//! dropped, not relayed.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    /// Frames flooded, each counted once.
    pub flooded: u64,
    /// Copies of flooded frames that could not be sent, and flooded frames that
    /// found no room to be copied out.
    pub flood_dropped: u64,
    /// Frames dropped because their destination is on the member they came in on.
    pub filtered: u64,
    /// ARP requests and Neighbor Solicitations the bridge answered for a remote host
    /// (RFC 9161).
    pub proxied: u64,
    /// Frames dropped because their destination is reserved (IEEE 802.1Q table 8-1)
    /// or their source is not a unicast address.
    pub dropped: u64,
}

/// What happens to a frame received on a member of a bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeDecision {
    /// The frame is the bridge's own interface's (the IRB's): it is received there.
    Irb,
    /// The frame goes out of this member only (to this remote VTEP, for an address
    /// learned on a VXLAN member).
    Forward(IfId, Option<IpAddr>),
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
    /// A static entry learning may take over on another member ([`StaticMac::movable`]).
    movable: bool,
    /// A learned entry that took over a movable static one: the member and VTEP that
    /// one had. While the same static entry is given again, the learned one stays.
    moved_from: Option<(IfId, Option<IpAddr>)>,
    bridge: u16,
    mac: [u8; 6],
    member: IfId,
    /// The remote VTEP behind a VXLAN member.
    vtep: Option<IpAddr>,
    seen_ms: u64,
}

const EMPTY: Slot = Slot {
    used: false,
    fixed: false,
    movable: false,
    moved_from: None,
    bridge: 0,
    mac: [0; 6],
    member: IfId(0),
    vtep: None,
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
    /// The remote VTEP behind a VXLAN member.
    pub vtep: Option<IpAddr>,
    /// A static entry (written by the control side), not a learned one.
    pub fixed: bool,
    /// When a learned entry was last seen.
    pub seen_ms: u64,
}

/// A static entry of a bridge's MAC address table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticMac {
    pub bridge: u16,
    pub mac: [u8; 6],
    pub member: IfId,
    /// The remote VTEP behind a VXLAN member.
    pub vtep: Option<IpAddr>,
    /// Learning takes it over when the address is seen on another member: for an
    /// address a routing daemon says is behind a remote VTEP (EVPN), which may move
    /// here before the daemon hears of it. A configured entry is not movable.
    pub movable: bool,
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
        let slots = capacity
            .clamp(1, 1 << 24)
            .saturating_mul(2)
            .next_power_of_two();
        let capacity = capacity.min(1 << 24);
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
    /// (and remote VTEP) `keep(new, member, vtep)` allows. Static entries are replaced by `statics` (bridge,
    /// address, member, the remote VTEP behind a VXLAN member); those beyond the
    /// capacity are left out and their number
    /// returned.
    pub fn republish(
        &mut self,
        bridges: &[BridgeLimits],
        old_of_new: &[Option<u16>],
        keep: impl Fn(u16, IfId, Option<IpAddr>) -> bool,
        statics: &[StaticMac],
    ) -> usize {
        // An empty table is all `EMPTY` already (`remove` leaves `EMPTY` behind):
        // with nothing learned, nothing is gone through slot by slot.
        let old: Vec<Slot> = if self.len == 0 {
            Vec::new()
        } else {
            let old = self.slots.iter().filter(|s| s.used).copied().collect();
            self.slots.fill(EMPTY);
            old
        };
        let old_bridges = std::mem::take(&mut self.bridges);
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
        // The new id of each old bridge (the first that names it).
        let mut new_of_old: Vec<Option<u16>> = vec![None; old_bridges.len()];
        for (new, old) in old_of_new.iter().enumerate().take(self.bridges.len()) {
            if let Some(slot) = old.and_then(|o| new_of_old.get_mut(usize::from(o))) {
                if slot.is_none() {
                    *slot = u16::try_from(new).ok();
                }
            }
        }
        // The learned entries that took over a static one given again as it was:
        // the static one stays out (the host moved here; the routing daemon has
        // not heard yet). One given otherwise, or not given, ends that.
        let took_over: BTreeSet<(u16, [u8; 6], IfId, Option<IpAddr>)> = old
            .iter()
            .filter(|s| !s.fixed)
            .filter_map(|s| {
                let new = new_of_old.get(usize::from(s.bridge)).copied().flatten()?;
                let (member, vtep) = s.moved_from?;
                Some((new, s.mac, member, vtep))
            })
            .collect();
        let mut kept_over: BTreeSet<(u16, [u8; 6])> = BTreeSet::new();
        let mut left_out = 0;
        for &StaticMac {
            bridge,
            mac,
            member,
            vtep,
            movable,
        } in statics
        {
            if usize::from(bridge) >= self.bridges.len() || self.find(bridge, &mac).is_some() {
                continue;
            }
            if movable && took_over.contains(&(bridge, mac, member, vtep)) {
                kept_over.insert((bridge, mac));
                continue;
            }
            if self.len >= self.capacity {
                left_out += 1;
                continue;
            }
            self.insert(Slot {
                used: true,
                fixed: true,
                movable,
                moved_from: None,
                bridge,
                mac,
                member,
                vtep,
                seen_ms: 0,
            });
        }
        for slot in old.into_iter().filter(|s| !s.fixed) {
            let Some(new) = new_of_old.get(usize::from(slot.bridge)).copied().flatten() else {
                continue;
            };
            let state = &self.bridges[usize::from(new)];
            let room = state.learned < state.limits.max_macs;
            if !keep(new, slot.member, slot.vtep)
                || self.find(new, &slot.mac).is_some()
                || self.len >= self.capacity
                || !room
            {
                continue;
            }
            let moved_from = slot
                .moved_from
                .filter(|_| kept_over.contains(&(new, slot.mac)));
            self.insert(Slot {
                bridge: new,
                moved_from,
                ..slot
            });
            self.bridges[usize::from(new)].learned += 1;
        }
        // A static entry kept out for a learned one that did not come back in.
        for kept in statics
            .iter()
            .filter(|s| kept_over.contains(&(s.bridge, s.mac)))
        {
            if self.find(kept.bridge, &kept.mac).is_some() {
                continue;
            }
            if self.len >= self.capacity {
                left_out += 1;
                continue;
            }
            self.insert(Slot {
                used: true,
                fixed: true,
                movable: true,
                moved_from: None,
                bridge: kept.bridge,
                mac: kept.mac,
                member: kept.member,
                vtep: kept.vtep,
                seen_ms: 0,
            });
        }
        left_out
    }

    /// Learns that `mac` was seen on `member` of `bridge` at `now_ms`, behind remote
    /// VTEP `vtep` for a VXLAN member.
    pub fn learn(
        &mut self,
        bridge: u16,
        mac: [u8; 6],
        member: IfId,
        vtep: Option<IpAddr>,
        now_ms: u64,
    ) -> Learned {
        let Some(state) = self.bridges.get(usize::from(bridge)) else {
            return Learned::Limited;
        };
        let full = state.learned >= state.limits.max_macs;
        if let Some(at) = self.find(bridge, &mac) {
            let aged = self.aged(&self.slots[at], now_ms);
            let slot = &mut self.slots[at];
            if slot.fixed {
                // A movable entry seen on another member, not behind a remote VTEP,
                // has moved there (EVPN, RFC 7432 section 15: where remote hosts
                // are comes from the routing daemon): it is learned there, as far
                // as there is room.
                if !slot.movable || slot.member == member || vtep.is_some() || full {
                    return Learned::Static;
                }
                *slot = Slot {
                    fixed: false,
                    movable: false,
                    moved_from: Some((slot.member, slot.vtep)),
                    member,
                    vtep,
                    seen_ms: now_ms,
                    ..*slot
                };
                let state = &mut self.bridges[usize::from(bridge)];
                state.learned += 1;
                state.counters.moved += 1;
                return Learned::Moved;
            }
            slot.seen_ms = now_ms;
            // Behind a remote VTEP again: the routing daemon's entry is what holds
            // from the next table change on.
            if vtep.is_some() {
                slot.moved_from = None;
            }
            if slot.member == member && slot.vtep == vtep {
                return Learned::Refreshed;
            }
            slot.member = member;
            slot.vtep = vtep;
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
            movable: false,
            moved_from: None,
            bridge,
            mac,
            member,
            vtep,
            seen_ms: now_ms,
        });
        let state = &mut self.bridges[usize::from(bridge)];
        state.learned += 1;
        state.counters.learned += 1;
        Learned::New
    }

    /// The member `mac` of `bridge` is on (and the remote VTEP behind it), unless it
    /// is not known or has aged (then its entry goes).
    pub fn lookup(
        &mut self,
        bridge: u16,
        mac: &[u8; 6],
        now_ms: u64,
    ) -> Option<(IfId, Option<IpAddr>)> {
        let at = self.find(bridge, mac)?;
        if self.aged(&self.slots[at], now_ms) {
            if let Some(b) = self.bridges.get_mut(usize::from(bridge)) {
                b.counters.aged += 1;
            }
            self.remove(at);
            return None;
        }
        Some((self.slots[at].member, self.slots[at].vtep))
    }

    /// Looks at up to `budget` slots, from where the last call stopped, and removes the
    /// learned entries past their age.
    pub fn age(&mut self, now_ms: u64, budget: usize) {
        if self.len == 0 {
            return;
        }
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
    /// received on `member` (from remote VTEP `vtep`, for a VXLAN member) at
    /// `now_ms`, learning its source; `irb` is the MAC address of the bridge's own
    /// interface, when it has one.
    pub fn receive(
        &mut self,
        bridge: u16,
        member: IfId,
        vtep: Option<IpAddr>,
        frame: &[u8],
        irb: Option<[u8; 6]>,
        now_ms: u64,
    ) -> BridgeDecision {
        self.receive_learning(bridge, member, vtep, frame, irb, now_ms, true)
    }

    /// [`MacTable::receive`], learning the source only when `learn`.
    #[allow(clippy::too_many_arguments)]
    pub fn receive_learning(
        &mut self,
        bridge: u16,
        member: IfId,
        vtep: Option<IpAddr>,
        frame: &[u8],
        irb: Option<[u8; 6]>,
        now_ms: u64,
        learn: bool,
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
        if learn {
            self.learn(bridge, source, member, vtep, now_ms);
        }
        if Some(destination) == irb {
            return BridgeDecision::Irb;
        }
        if is_group(&destination) {
            return BridgeDecision::Flood { irb: irb.is_some() };
        }
        match self.lookup(bridge, &destination, now_ms) {
            Some((out, _)) if out == member => {
                self.bridges[usize::from(bridge)].counters.filtered += 1;
                BridgeDecision::Drop
            }
            Some((out, to)) => BridgeDecision::Forward(out, to),
            None => BridgeDecision::Flood { irb: false },
        }
    }

    /// The member a frame to `destination` leaves bridge `bridge` through (and the
    /// remote VTEP behind it) when the bridge's own interface sends it, or `None` to
    /// flood it (a group address, or one not known).
    pub fn send(
        &mut self,
        bridge: u16,
        destination: &[u8; 6],
        now_ms: u64,
    ) -> Option<(IfId, Option<IpAddr>)> {
        if is_group(destination) {
            return None;
        }
        self.lookup(bridge, destination, now_ms)
    }

    /// Counts a frame sent out of one member.
    pub fn count_proxied(&mut self, bridge: u16) {
        if let Some(b) = self.bridges.get_mut(usize::from(bridge)) {
            b.counters.proxied += 1;
        }
    }

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

    /// Counts a flooded frame that found no room to be copied out.
    pub fn count_flood_dropped(&mut self, bridge: u16) {
        if let Some(b) = self.bridges.get_mut(usize::from(bridge)) {
            b.counters.flood_dropped += 1;
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
            vtep: s.vtep,
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

/// One bridge as the tables give it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    pub limits: BridgeLimits,
    /// The bridge's own interface and its MAC address, when it has one.
    pub irb: Option<(IfId, [u8; 6])>,
    /// The members: ports, VLAN sub-interfaces and overlays.
    pub members: Vec<IfId>,
    /// What the bridge answers ARP and ND with for remote hosts, when it does.
    pub proxy: Option<Proxy>,
    /// The members whose frames are not learned from: where the hosts behind them
    /// are comes from the control side only (an SRv6 EVPN interface: the remote
    /// End.DT2U SID a host is behind is not in its frames; RFC 8986 section 4.11).
    pub control_learned: Vec<IfId>,
}

/// The remote hosts a bridge answers ARP requests and Neighbor Solicitations for,
/// on its local members (RFC 9161: a routing daemon learned them from EVPN).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Proxy {
    /// The members requests are answered on: ports and VLAN sub-interfaces, not
    /// overlays (the remote ends answer their own hosts).
    pub members: Vec<IfId>,
    pub hosts: BTreeMap<IpAddr, ProxyHost>,
}

/// A remote host's MAC address, and whether it is a router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyHost {
    pub mac: [u8; 6],
    pub router: bool,
}

/// The address an ARP request in `frame` (Ethernet, RFC 826 for IPv4 over
/// Ethernet) asks for, unless it is a gratuitous one (its sender's own address):
/// those are not answered (RFC 9161 section 3.3).
fn arp_request_target(frame: &[u8]) -> Option<Ipv4Addr> {
    let arp = frame.get(12..42)?;
    if arp[0..10] != [0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1] {
        return None;
    }
    let (sender, target) = (&arp[16..20], &arp[26..30]);
    (sender != target).then(|| Ipv4Addr::new(target[0], target[1], target[2], target[3]))
}

/// The address a Neighbor Solicitation in `frame` (Ethernet, IPv6 with no extension
/// header) asks for, when it is one the bridge answers: to the target's
/// solicited-node address, hop limit 255, from a unicast address (not a DAD
/// solicitation, RFC 4862 section 5.4.2), with exactly the Source Link-Layer
/// Address option (RFC 4861 sections 4.3 and 7.1.1). Others go on as they are
/// (RFC 9161 section 3.3 (f), "forward").
fn solicitation_target(frame: &[u8]) -> Option<Ipv6Addr> {
    let packet = frame.get(12..86)?;
    let ip = &packet[2..42];
    let icmp = &packet[42..74];
    let address = |bytes: &[u8]| <[u8; 16]>::try_from(bytes).ok().map(Ipv6Addr::from);
    let source: Ipv6Addr = address(&ip[8..24])?;
    let destination: Ipv6Addr = address(&ip[24..40])?;
    let target: Ipv6Addr = address(&icmp[8..24])?;
    let solicited = {
        let t = target.octets();
        let mut d = [0; 16];
        d[0..2].copy_from_slice(&[0xff, 0x02]);
        d[11..13].copy_from_slice(&[1, 0xff]);
        d[13..16].copy_from_slice(&t[13..16]);
        Ipv6Addr::from(d)
    };
    let fits = packet[0..2] == [0x86, 0xdd]
        && ip[0] >> 4 == 6
        && ip[4..8] == [0, 32, 58, 255]
        && !source.is_unspecified()
        && !source.is_multicast()
        && !source.is_loopback()
        && source != target
        && destination == solicited
        && frame[3..6] == solicited.octets()[13..16]
        && icmp[0..2] == [135, 0]
        && !target.is_multicast()
        && icmp[24..26] == [1, 1]
        // RFC 4861 section 7.1.1: the checksum is good.
        && crate::ipv6::icmpv6_checksum(source.octets(), destination.octets(), icmp) == 0;
    fits.then_some(target)
}

/// Makes the Neighbor Solicitation in `frame` (see [`solicitation_target`]) the
/// Neighbor Advertisement of `host` (RFC 9161 section 3.3: its MAC address the
/// source of the frame and the Target Link-Layer Address, the target the source;
/// R as the host is, S set, O set; RFC 4861 section 7.2.4).
fn make_advertisement(frame: &mut [u8], host: ProxyHost) {
    let mut asker = [0; 6];
    asker.copy_from_slice(&frame[6..12]);
    let mut asker_ip = [0; 16];
    asker_ip.copy_from_slice(&frame[22..38]);
    let mut target = [0; 16];
    target.copy_from_slice(&frame[62..78]);
    frame[0..6].copy_from_slice(&asker);
    frame[6..12].copy_from_slice(&host.mac);
    frame[14..18].copy_from_slice(&[0x60, 0, 0, 0]);
    frame[22..38].copy_from_slice(&target);
    frame[38..54].copy_from_slice(&asker_ip);
    let icmp = &mut frame[54..86];
    icmp[0..4].copy_from_slice(&[136, 0, 0, 0]);
    icmp[4] = (u8::from(host.router) << 7) | 0x40 | 0x20;
    icmp[5..8].fill(0);
    icmp[24..26].copy_from_slice(&[2, 1]);
    icmp[26..32].copy_from_slice(&host.mac);
    let sum = crate::ipv6::icmpv6_checksum(target, asker_ip, &frame[54..86]);
    frame[56..58].copy_from_slice(&sum.to_be_bytes());
}

/// Makes the ARP request in `frame` (see [`arp_request_target`]) the reply of the
/// host `mac` (RFC 9161 section 3.3: its MAC address the source of the frame and
/// the sender's hardware address, the address asked for the sender's).
fn make_arp_reply(frame: &mut [u8], mac: [u8; 6]) {
    let mut asker = [0; 10];
    asker.copy_from_slice(&frame[22..32]);
    let mut target = [0; 4];
    target.copy_from_slice(&frame[38..42]);
    frame[0..6].copy_from_slice(&asker[0..6]);
    frame[6..12].copy_from_slice(&mac);
    frame[21] = 2;
    frame[22..28].copy_from_slice(&mac);
    frame[28..32].copy_from_slice(&target);
    frame[32..42].copy_from_slice(&asker);
}

/// The longest frame a flood copies out (an Ethernet frame with a 9216-byte payload).
pub const FLOOD_FRAME_MAX: usize = 9_216 + 14;

/// A flooded frame waiting to be sent out of the members of its bridge.
pub struct FloodFrame {
    pub bridge: u16,
    /// The member it came in on, which it does not go back out of.
    pub from: Option<IfId>,
    len: usize,
    buf: Box<[u8]>,
}

impl FloodFrame {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// How a received frame left the bridge, for the batch counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Received {
    /// Not a member's frame, or one for the IRB (its ingress is now the IRB):
    /// forwarding goes on with it.
    Pass,
    /// To be sent out of this one member (to this remote VTEP).
    Forward(IfId, Option<IpAddr>),
    Consumed,
    Dropped,
}

/// Every bridge of the FE: their members, the MAC address table, and the flooded
/// frames of the current batch.
pub struct Bridges {
    pub table: MacTable,
    bridges: Vec<BridgeConfig>,
    /// The bridge of each member, by interface id.
    member_of: Vec<Option<u16>>,
    /// The bridge of each IRB, by interface id.
    irb_of: Vec<Option<u16>>,
    flood: Vec<FloodFrame>,
    flooded: usize,
}

impl std::fmt::Debug for Bridges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridges")
            .field("table", &self.table)
            .field("bridges", &self.bridges)
            .finish_non_exhaustive()
    }
}

impl Bridges {
    /// Room for `capacity` MAC addresses and `flood_slots` flooded frames per batch,
    /// all allocated now.
    #[must_use]
    pub fn new(capacity: usize, flood_slots: usize, key: ResolutionHashKey) -> Self {
        Self {
            table: MacTable::new(capacity, key),
            bridges: Vec::new(),
            member_of: Vec::new(),
            irb_of: Vec::new(),
            flood: (0..flood_slots)
                .map(|_| FloodFrame {
                    bridge: 0,
                    from: None,
                    len: 0,
                    buf: vec![0; FLOOD_FRAME_MAX].into_boxed_slice(),
                })
                .collect(),
            flooded: 0,
        }
    }

    /// Sets the bridges after a table change (see [`MacTable::republish`]); a member
    /// listed twice stays with the first bridge. An address learned behind a remote
    /// VTEP is kept only while `vtep_kept(member, vtep)` (the VTEP is still one of
    /// the member's). Returns the static entries left out.
    pub fn publish(
        &mut self,
        bridges: Vec<BridgeConfig>,
        old_of_new: &[Option<u16>],
        statics: &[StaticMac],
        vtep_kept: impl Fn(IfId, IpAddr) -> bool,
    ) -> usize {
        let size = |ids: &mut dyn Iterator<Item = IfId>| ids.map(|id| usize::from(id.0) + 1).max();
        let len = size(
            &mut bridges
                .iter()
                .flat_map(|b| b.members.iter().copied().chain(b.irb.map(|(id, _)| id))),
        )
        .unwrap_or(0);
        self.member_of = vec![None; len];
        self.irb_of = vec![None; len];
        for (at, bridge) in bridges.iter().enumerate() {
            let at = u16::try_from(at).unwrap_or(u16::MAX);
            for member in &bridge.members {
                let slot = &mut self.member_of[usize::from(member.0)];
                if slot.is_none() {
                    *slot = Some(at);
                }
            }
            if let Some((irb, _)) = bridge.irb {
                self.irb_of[usize::from(irb.0)] = Some(at);
            }
        }
        let limits: Vec<BridgeLimits> = bridges.iter().map(|b| b.limits).collect();
        let member_of = &self.member_of;
        let left = self.table.republish(
            &limits,
            old_of_new,
            |bridge, member, vtep| {
                member_of.get(usize::from(member.0)).copied().flatten() == Some(bridge)
                    && vtep.is_none_or(|vtep| vtep_kept(member, vtep))
            },
            statics,
        );
        self.bridges = bridges;
        self.flooded = 0;
        left
    }

    /// Whether there is any bridge.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bridges.is_empty()
    }

    /// The bridge `id` is a member of.
    #[must_use]
    pub fn member_of(&self, id: IfId) -> Option<u16> {
        self.member_of.get(usize::from(id.0)).copied().flatten()
    }

    /// The bridge `id` is the own interface (IRB) of.
    #[must_use]
    pub fn irb_of(&self, id: IfId) -> Option<u16> {
        self.irb_of.get(usize::from(id.0)).copied().flatten()
    }

    /// The members of bridge `bridge`.
    #[must_use]
    pub fn members(&self, bridge: u16) -> &[IfId] {
        self.bridges
            .get(usize::from(bridge))
            .map_or(&[], |b| b.members.as_slice())
    }

    /// Copies `frame` out to be flooded over `bridge` (but not back out of `from`).
    /// Returns `false`, counting it, when there is no room or it is too long.
    pub fn stage_flood(&mut self, bridge: u16, from: Option<IfId>, frame: &[u8]) -> bool {
        let Some(slot) = self.flood.get_mut(self.flooded) else {
            self.table.count_flood_dropped(bridge);
            return false;
        };
        if frame.len() > slot.buf.len() {
            self.table.count_flood_dropped(bridge);
            return false;
        }
        slot.buf[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len();
        slot.bridge = bridge;
        slot.from = from;
        self.flooded += 1;
        true
    }

    /// The frames flooded since the last [`Bridges::clear_flood`].
    #[must_use]
    pub fn flood(&self) -> &[FloodFrame] {
        &self.flood[..self.flooded]
    }

    pub fn clear_flood(&mut self) {
        self.flooded = 0;
    }

    /// The bridge stage of a received frame: a member's frame is learned from and
    /// relayed, or made to arrive on the IRB.
    pub(crate) fn receive<S: crate::PacketSlot>(
        &mut self,
        packet: &mut crate::PacketLease<S>,
        vtep: Option<IpAddr>,
        now_ms: u64,
    ) -> Received {
        let member = packet.ingress();
        let Some(bridge) = self.member_of(member) else {
            return Received::Pass;
        };
        let irb = self.bridges[usize::from(bridge)].irb;
        if let Some(out) = self.proxy(bridge, member, packet.bytes_mut(), now_ms) {
            return out;
        }
        let learn = !self.bridges[usize::from(bridge)]
            .control_learned
            .contains(&member);
        let decision = self.table.receive_learning(
            bridge,
            member,
            vtep,
            packet.bytes_mut(),
            irb.map(|(_, mac)| mac),
            now_ms,
            learn,
        );
        match decision {
            BridgeDecision::Irb => {
                packet.set_ingress(irb.expect("an IRB decision has an IRB").0);
                Received::Pass
            }
            BridgeDecision::Forward(out, to) => {
                self.table.count_forwarded(bridge);
                Received::Forward(out, to)
            }
            BridgeDecision::Flood { irb: up } => {
                let staged = self.stage_flood(bridge, Some(member), packet.bytes_mut());
                if staged {
                    self.table.count_flood(bridge, 0);
                }
                match irb {
                    Some((id, _)) if up => {
                        packet.set_ingress(id);
                        Received::Pass
                    }
                    _ if staged => Received::Consumed,
                    _ => Received::Dropped,
                }
            }
            BridgeDecision::Drop => Received::Dropped,
        }
    }

    /// Answers an ARP request received on a local member of `bridge` for a remote
    /// host the bridge knows, in place of flooding it: the frame becomes the reply
    /// and goes back out of `member`. Not when the host is learned on `member`
    /// itself (it answers; RFC 9161 section 3.3). The source is learned as for any
    /// frame.
    fn proxy(
        &mut self,
        bridge: u16,
        member: IfId,
        frame: &mut [u8],
        now_ms: u64,
    ) -> Option<Received> {
        let proxy = self.bridges.get(usize::from(bridge))?.proxy.as_ref()?;
        if !proxy.members.contains(&member) {
            return None;
        }
        let destination = frame.get(0..6)?;
        let target = if destination == [0xff; 6] {
            IpAddr::V4(arp_request_target(frame)?)
        } else if destination[0..3] == [0x33, 0x33, 0xff] {
            IpAddr::V6(solicitation_target(frame)?)
        } else {
            return None;
        };
        let host = *proxy.hosts.get(&target)?;
        let source: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
        if source[0] & 1 != 0 || source == [0; 6] {
            return None;
        }
        if self
            .table
            .lookup(bridge, &host.mac, now_ms)
            .is_some_and(|(at, _)| at == member)
        {
            return None;
        }
        self.table.learn(bridge, source, member, None, now_ms);
        if target.is_ipv4() {
            make_arp_reply(frame, host.mac);
        } else {
            make_advertisement(frame, host);
        }
        self.table.count_proxied(bridge);
        Some(Received::Forward(member, None))
    }

    /// Where a frame sent out of `egress` goes when `egress` is an IRB: the member its
    /// destination was learned on, or `None` after it was copied out to be flooded
    /// (or dropped for want of room, `Err`). Any other egress is returned as it is.
    pub(crate) fn transmit(
        &mut self,
        egress: IfId,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Option<(IfId, Option<IpAddr>)>, crate::DropReason> {
        let Some(bridge) = self.irb_of(egress) else {
            return Ok(Some((egress, None)));
        };
        let destination: [u8; 6] = frame
            .get(0..6)
            .and_then(|d| d.try_into().ok())
            .ok_or(crate::DropReason::EthernetHeaderTruncated)?;
        if let Some(to) = self.table.send(bridge, &destination, now_ms) {
            self.table.count_forwarded(bridge);
            return Ok(Some(to));
        }
        if self.stage_flood(bridge, None, frame) {
            self.table.count_flood(bridge, 0);
            Ok(None)
        } else {
            Err(crate::DropReason::BridgeDropped)
        }
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
            |_, _, _| true,
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
        let d = t.receive(0, P1, None, &frame(B, A), Some(IRB), 0);
        assert_eq!(d, BridgeDecision::Flood { irb: false });
        // A is known: B's reply goes to P1 only.
        assert_eq!(
            t.receive(0, P2, None, &frame(A, B), Some(IRB), 1),
            BridgeDecision::Forward(P1, None)
        );
        // Back to where it came from: dropped.
        assert_eq!(
            t.receive(0, P2, None, &frame(B, A), Some(IRB), 2),
            BridgeDecision::Drop
        );
        // A moved to P2 with that frame, so this one is filtered too.
        assert_eq!(t.counters().next().unwrap().moved, 1);
        assert_eq!(t.counters().next().unwrap().filtered, 1);
        // Broadcast: flooded and received on the IRB.
        assert_eq!(
            t.receive(
                0,
                P3,
                None,
                &frame([0xff; 6], [2, 0, 0, 0, 0, 0xc]),
                Some(IRB),
                3
            ),
            BridgeDecision::Flood { irb: true }
        );
        assert_eq!(
            t.receive(0, P3, None, &frame(IRB, [2, 0, 0, 0, 0, 0xc]), Some(IRB), 4),
            BridgeDecision::Irb
        );
        assert_eq!(t.counters().next().unwrap().learned, 3);
    }

    #[test]
    fn reserved_and_bad_sources_are_dropped() {
        let mut t = table(16, 16);
        let stp = [0x01, 0x80, 0xc2, 0, 0, 0];
        assert_eq!(
            t.receive(0, P1, None, &frame(stp, A), None, 0),
            BridgeDecision::Drop
        );
        assert_eq!(
            t.receive(0, P1, None, &frame(B, [0xff; 6]), None, 0),
            BridgeDecision::Drop
        );
        assert_eq!(
            t.receive(0, P1, None, &frame(B, [0; 6]), None, 0),
            BridgeDecision::Drop
        );
        assert_eq!(t.counters().next().unwrap().dropped, 3);
        assert!(t.is_empty());
        // IS-IS's AllL1ISs is past the reserved range: flooded.
        let isis = [0x01, 0x80, 0xc2, 0, 0, 0x14];
        assert_eq!(
            t.receive(0, P1, None, &frame(isis, A), None, 0),
            BridgeDecision::Flood { irb: false }
        );
    }

    /// IEEE 802.1Q-2018 table 8-1: the whole block 01-80-C2-00-00-00 to -0F is
    /// filtered, and the address after it is relayed.
    #[test]
    fn the_reserved_block_ends_at_0f() {
        let mut t = table(16, 16);
        for last in 0..=0x0f {
            assert_eq!(
                t.receive(
                    0,
                    P1,
                    None,
                    &frame([0x01, 0x80, 0xc2, 0, 0, last], A),
                    None,
                    0
                ),
                BridgeDecision::Drop,
                "01-80-C2-00-00-{last:02X}"
            );
        }
        assert_eq!(t.counters().next().unwrap().dropped, 16);
        assert_eq!(
            t.receive(
                0,
                P1,
                None,
                &frame([0x01, 0x80, 0xc2, 0, 0, 0x10], A),
                None,
                0
            ),
            BridgeDecision::Flood { irb: false }
        );
    }

    /// IEEE 802.1Q-2018 8.6.3 and 8.8: a group address is never looked up, so a
    /// multicast frame is flooded (and taken by the IRB) even when a frame from that
    /// address was seen; a group source is not learned (8.7).
    #[test]
    fn multicast_is_flooded_and_never_learned() {
        let mut t = table(16, 16);
        let group = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05];
        assert_eq!(
            t.receive(0, P1, None, &frame(group, A), Some(IRB), 0),
            BridgeDecision::Flood { irb: true }
        );
        assert_eq!(
            t.receive(0, P2, None, &frame(group, B), None, 1),
            BridgeDecision::Flood { irb: false }
        );
        assert_eq!(
            t.receive(0, P2, None, &frame(B, group), None, 2),
            BridgeDecision::Drop
        );
        assert!(t.entries().all(|e| e.mac != group));
        assert_eq!(t.send(0, &group, 3), None);
        assert_eq!(t.send(0, &[0xff; 6], 3), None);
    }

    /// IEEE 802.1Q-2018 8.7 and 8.8.3: each frame from an address refreshes its
    /// entry, and the ageing time counts from the last one seen.
    #[test]
    fn a_frame_from_an_address_restarts_its_ageing() {
        let mut t = table(16, 16);
        t.receive(0, P1, None, &frame(B, A), None, 0);
        t.receive(0, P1, None, &frame(B, A), None, 200_000);
        assert_eq!(t.send(0, &A, 500_000), Some((P1, None)));
        assert_eq!(t.send(0, &A, 500_001), None);
        assert_eq!(t.counters().next().unwrap().learned, 1);
    }

    #[test]
    fn an_address_behind_a_vtep_is_sent_to_that_vtep() {
        let mut t = table(16, 16);
        let one = Some(IpAddr::from([192, 0, 2, 1]));
        let two = Some(IpAddr::from([192, 0, 2, 2]));
        t.receive(0, P3, one, &frame(B, A), None, 0);
        assert_eq!(
            t.receive(0, P1, None, &frame(A, B), None, 1),
            BridgeDecision::Forward(P3, one)
        );
        // A seen behind another VTEP of the same member moves there.
        assert_eq!(t.learn(0, A, P3, two, 2), Learned::Moved);
        assert_eq!(t.send(0, &A, 3), Some((P3, two)));
        assert_eq!(t.entries().find(|e| e.mac == A).unwrap().vtep, two);
    }

    #[test]
    fn entries_age() {
        let mut t = table(16, 16);
        t.learn(0, A, P1, None, 0);
        assert_eq!(t.send(0, &A, 300_000), Some((P1, None)));
        assert_eq!(t.send(0, &A, 300_001), None);
        assert_eq!(t.counters().next().unwrap().aged, 1);
        assert!(t.is_empty());
        // The sweep removes those not looked up.
        t.learn(0, B, P2, None, 1_000);
        t.age(400_000, 1_000);
        assert!(t.is_empty());
        assert_eq!(t.counters().next().unwrap().aged, 2);
    }

    #[test]
    fn limits_and_statics() {
        let mut t = table(16, 2);
        assert_eq!(t.learn(0, A, P1, None, 0), Learned::New);
        assert_eq!(t.learn(0, B, P1, None, 0), Learned::New);
        assert_eq!(
            t.learn(0, [2, 0, 0, 0, 0, 9], P1, None, 0),
            Learned::Limited
        );
        assert_eq!(t.counters().next().unwrap().limited, 1);
        // A static entry is not moved by learning, and does not age.
        let s = [2, 0, 0, 0, 0, 0x55];
        let left = t.republish(
            &[BridgeLimits {
                aging_ms: 1,
                max_macs: 2,
            }],
            &[Some(0)],
            |_, member, _| member != P1,
            &[StaticMac {
                bridge: 0,
                mac: s,
                member: P3,
                vtep: None,
                movable: false,
            }],
        );
        assert_eq!(left, 0);
        // The learned entries on P1 went; the counters stayed.
        assert_eq!(t.len(), 1);
        assert_eq!(t.counters().next().unwrap().learned, 2);
        assert_eq!(t.learn(0, s, P1, None, 5), Learned::Static);
        assert_eq!(t.send(0, &s, 1_000_000), Some((P3, None)));
    }

    #[test]
    fn a_movable_static_entry_is_taken_over_until_it_is_given_otherwise() {
        let limits = [BridgeLimits {
            aging_ms: 300_000,
            max_macs: 4,
        }];
        let vtep: IpAddr = [198, 51, 100, 2].into();
        let remote = StaticMac {
            bridge: 0,
            mac: A,
            member: P3,
            vtep: Some(vtep),
            movable: true,
        };
        let mut t = table(16, 4);
        let publish = |t: &mut MacTable, statics: &[StaticMac]| {
            t.republish(&limits, &[Some(0)], |_, _, _| true, statics)
        };
        publish(&mut t, &[remote]);
        assert_eq!(t.send(0, &A, 0), Some((P3, Some(vtep))));
        // Seen on the member it is on: stays static.
        assert_eq!(t.learn(0, A, P3, Some(vtep), 1), Learned::Static);
        // Seen on another: moved there, learned.
        assert_eq!(t.learn(0, A, P1, None, 2), Learned::Moved);
        assert_eq!(t.send(0, &A, 3), Some((P1, None)));
        assert!(t.entries().any(|e| e.mac == A && !e.fixed));
        // The same static entry again (the daemon has not heard): the learned one
        // stays.
        publish(&mut t, &[remote]);
        assert_eq!(t.send(0, &A, 4), Some((P1, None)));
        // Withdrawn, then given again (the host went back): the static one wins.
        publish(&mut t, &[]);
        assert_eq!(t.send(0, &A, 5), Some((P1, None)));
        publish(&mut t, &[remote]);
        assert_eq!(t.send(0, &A, 6), Some((P3, Some(vtep))));
        // Given behind another VTEP: the static one wins too.
        assert_eq!(t.learn(0, A, P1, None, 7), Learned::Moved);
        let other = StaticMac {
            vtep: Some([198, 51, 100, 3].into()),
            ..remote
        };
        publish(&mut t, &[other]);
        assert_eq!(t.send(0, &A, 8), Some((P3, other.vtep)));
        // Not taken over from behind a VTEP, on another member either.
        assert_eq!(t.learn(0, A, P2, Some(vtep), 9), Learned::Static);
        // Taken over, then seen behind a VTEP again: the static one is back with
        // the next change.
        assert_eq!(t.learn(0, A, P1, None, 10), Learned::Moved);
        assert_eq!(t.learn(0, A, P3, other.vtep, 11), Learned::Moved);
        publish(&mut t, &[other]);
        assert!(t.entries().any(|e| e.mac == A && e.fixed));
        // Taken over, and the member leaves the bridge: the static one is back.
        assert_eq!(t.learn(0, A, P1, None, 12), Learned::Moved);
        t.republish(&limits, &[Some(0)], |_, member, _| member != P1, &[other]);
        assert_eq!(t.send(0, &A, 13), Some((P3, other.vtep)));
    }

    #[test]
    fn an_arp_request_for_a_remote_host_is_answered_on_a_local_member() {
        let key = ResolutionHashKey::new(3, 4).unwrap();
        let mut bridges = Bridges::new(16, 1, key);
        let remote = [2, 0, 0, 0, 0, 0x22];
        let asker = [2, 0, 0, 0, 0, 0x11];
        let config = BridgeConfig {
            limits: BridgeLimits {
                aging_ms: 1_000,
                max_macs: 8,
            },
            irb: None,
            members: vec![P1, P2, P3],
            proxy: Some(Proxy {
                members: vec![P1, P2],
                hosts: [(
                    IpAddr::from([192, 0, 2, 20]),
                    ProxyHost {
                        mac: remote,
                        router: false,
                    },
                )]
                .into(),
            }),
            control_learned: Vec::new(),
        };
        bridges.publish(vec![config], &[None], &[], |_, _| true);
        let request = |sender: [u8; 4], target: [u8; 4]| {
            let mut f = vec![0xff; 6];
            f.extend_from_slice(&asker);
            f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1]);
            f.extend_from_slice(&asker);
            f.extend_from_slice(&sender);
            f.extend_from_slice(&[0; 6]);
            f.extend_from_slice(&target);
            f.resize(60, 0);
            f
        };
        let mut frame = request([192, 0, 2, 10], [192, 0, 2, 20]);
        assert_eq!(
            bridges.proxy(0, P1, &mut frame, 0),
            Some(Received::Forward(P1, None))
        );
        let mut reply = asker.to_vec();
        reply.extend_from_slice(&remote);
        reply.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 2]);
        reply.extend_from_slice(&remote);
        reply.extend_from_slice(&[192, 0, 2, 20]);
        reply.extend_from_slice(&asker);
        reply.extend_from_slice(&[192, 0, 2, 10]);
        reply.resize(60, 0);
        assert_eq!(frame, reply);
        assert_eq!(bridges.table.counters().next().unwrap().proxied, 1);
        // The asker was learned.
        assert_eq!(bridges.table.send(0, &asker, 1), Some((P1, None)));
        // Not for: another address, a gratuitous request, a request from an
        // overlay member, or when the host is on the asking member.
        for (member, mut frame) in [
            (P1, request([192, 0, 2, 10], [192, 0, 2, 21])),
            (P1, request([192, 0, 2, 20], [192, 0, 2, 20])),
            (P3, request([192, 0, 2, 10], [192, 0, 2, 20])),
        ] {
            assert_eq!(bridges.proxy(0, member, &mut frame, 2), None);
        }
        bridges.table.learn(0, remote, P2, None, 3);
        let mut frame = request([192, 0, 2, 10], [192, 0, 2, 20]);
        assert_eq!(bridges.proxy(0, P2, &mut frame, 4), None);
    }

    #[test]
    fn a_neighbor_solicitation_for_a_remote_host_is_answered_on_a_local_member() {
        let key = ResolutionHashKey::new(3, 4).unwrap();
        let mut bridges = Bridges::new(16, 1, key);
        let remote = [2, 0, 0, 0, 0, 0x22];
        let asker = [2, 0, 0, 0, 0, 0x11];
        let target: Ipv6Addr = "2001:db8::20".parse().unwrap();
        let asker_ip: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let config = BridgeConfig {
            limits: BridgeLimits {
                aging_ms: 1_000,
                max_macs: 8,
            },
            irb: None,
            members: vec![P1, P3],
            proxy: Some(Proxy {
                members: vec![P1],
                hosts: [(
                    IpAddr::V6(target),
                    ProxyHost {
                        mac: remote,
                        router: true,
                    },
                )]
                .into(),
            }),
            control_learned: Vec::new(),
        };
        bridges.publish(vec![config], &[None], &[], |_, _| true);
        let solicitation = |source: Ipv6Addr, hop: u8, extra: usize| {
            let t = target.octets();
            let mut f = vec![0x33, 0x33, 0xff, t[13], t[14], t[15]];
            f.extend_from_slice(&asker);
            f.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
            let len = u16::try_from(32 + extra).unwrap();
            f.extend_from_slice(&len.to_be_bytes());
            f.extend_from_slice(&[58, hop]);
            f.extend_from_slice(&source.octets());
            let mut d = [0; 16];
            d[0..2].copy_from_slice(&[0xff, 0x02]);
            d[11..13].copy_from_slice(&[1, 0xff]);
            d[13..16].copy_from_slice(&t[13..16]);
            f.extend_from_slice(&d);
            f.extend_from_slice(&[135, 0, 0, 0, 0, 0, 0, 0]);
            f.extend_from_slice(&t);
            f.extend_from_slice(&[1, 1]);
            f.extend_from_slice(&asker);
            f.resize(f.len() + extra, 0);
            let sum = crate::ipv6::icmpv6_checksum(source.octets(), d, &f[54..]);
            f[56..58].copy_from_slice(&sum.to_be_bytes());
            f
        };
        let mut frame = solicitation(asker_ip, 255, 0);
        assert_eq!(
            bridges.proxy(0, P1, &mut frame, 0),
            Some(Received::Forward(P1, None))
        );
        assert_eq!(&frame[0..6], &asker);
        assert_eq!(&frame[6..12], &remote);
        assert_eq!(&frame[18..22], &[0, 32, 58, 255]);
        assert_eq!(&frame[22..38], &target.octets());
        assert_eq!(&frame[38..54], &asker_ip.octets());
        assert_eq!(&frame[54..56], &[136, 0]);
        // R (a router), S and O.
        assert_eq!(&frame[58..62], &[0xe0, 0, 0, 0]);
        assert_eq!(&frame[62..78], &target.octets());
        assert_eq!(&frame[78..80], &[2, 1]);
        assert_eq!(&frame[80..86], &remote);
        assert_eq!(
            crate::ipv6::icmpv6_checksum(target.octets(), asker_ip.octets(), &frame[54..86]),
            0
        );
        assert_eq!(bridges.table.counters().next().unwrap().proxied, 1);
        // Not for: DAD, a hop limit other than 255, more options, an overlay member,
        // the target's own address as the source, a bad checksum.
        for (member, mut frame) in [
            (P1, solicitation(Ipv6Addr::UNSPECIFIED, 255, 0)),
            (P1, solicitation(asker_ip, 64, 0)),
            (P1, solicitation(asker_ip, 255, 8)),
            (P3, solicitation(asker_ip, 255, 0)),
            (P1, solicitation(target, 255, 0)),
            (P1, {
                let mut f = solicitation(asker_ip, 255, 0);
                f[57] ^= 1;
                f
            }),
        ] {
            assert_eq!(bridges.proxy(0, member, &mut frame, 1), None);
        }
    }

    #[test]
    fn many_entries_survive_removals() {
        let mut t = table(512, 500);
        let mac = |i: u16| {
            let [a, b] = i.to_be_bytes();
            [2, 0, 0, 0, a, b]
        };
        for i in 0..500 {
            assert_eq!(
                t.learn(0, mac(i), IfId(i % 7), None, u64::from(i)),
                Learned::New
            );
        }
        assert_eq!(t.learn(0, mac(999), P1, None, 0), Learned::Limited);
        // Every other one ages out (seen at an even time, aged after 300 s from 0).
        for i in (0..500).step_by(2) {
            assert_eq!(t.lookup(0, &mac(i), 300_000 + u64::from(i) + 1), None);
        }
        for i in (1..500).step_by(2) {
            assert_eq!(t.lookup(0, &mac(i), 300_000), Some((IfId(i % 7), None)));
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
        t.republish(&[limits, limits], &[None, None], |_, _, _| true, &[]);
        t.learn(0, A, P1, None, 0);
        assert_eq!(t.send(1, &A, 0), None);
        t.learn(1, A, P2, None, 0);
        assert_eq!(t.send(0, &A, 0), Some((P1, None)));
        assert_eq!(t.send(1, &A, 0), Some((P2, None)));
        // Bridge 1 goes, bridge 0 becomes 1.
        t.republish(&[limits], &[Some(0)], |_, _, _| true, &[]);
        assert_eq!(t.send(0, &A, 0), Some((P1, None)));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn an_irb_sends_to_the_learned_member_or_copies_out_to_flood() {
        let key = ResolutionHashKey::new(3, 4).unwrap();
        let mut bridges = Bridges::new(16, 1, key);
        let config = BridgeConfig {
            limits: BridgeLimits {
                aging_ms: 1_000,
                max_macs: 8,
            },
            irb: Some((IfId(9), IRB)),
            members: vec![P1, P2],
            proxy: None,
            control_learned: Vec::new(),
        };
        bridges.publish(vec![config], &[None], &[], |_, _| true);
        assert_eq!(bridges.member_of(P2), Some(0));
        assert_eq!(bridges.irb_of(IfId(9)), Some(0));
        // Not an IRB: as it is.
        assert_eq!(
            bridges.transmit(P3, &frame(A, IRB), 0),
            Ok(Some((P3, None)))
        );
        // Unknown: copied out, once (one slot).
        assert_eq!(bridges.transmit(IfId(9), &frame(A, IRB), 0), Ok(None));
        assert_eq!(bridges.flood().len(), 1);
        assert_eq!(bridges.flood()[0].bytes(), frame(A, IRB).as_slice());
        assert_eq!(bridges.flood()[0].from, None);
        assert_eq!(
            bridges.transmit(IfId(9), &frame(A, IRB), 0),
            Err(crate::DropReason::BridgeDropped)
        );
        bridges.clear_flood();
        bridges.table.learn(0, A, P2, None, 0);
        assert_eq!(
            bridges.transmit(IfId(9), &frame(A, IRB), 1),
            Ok(Some((P2, None)))
        );
        let counters = bridges.table.counters().next().unwrap();
        assert_eq!(
            (counters.flooded, counters.flood_dropped, counters.forwarded),
            (1, 1, 1)
        );
    }
}

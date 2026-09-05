//! RFC 1191 Path MTU Discovery: the per-destination estimate cache.
//!
//! A router forwards every datagram at its own egress interface's MTU
//! (`crate::forwarding` enforces that already). What that check cannot see
//! is a smaller link further down the path: some router beyond the next hop
//! may still have to drop a datagram this one happily forwarded. That
//! router's ICMPv4 Destination Unreachable (Fragmentation Needed) is the
//! only signal of that, and RFC 1191 §5 asks the estimate learned from it to
//! be kept and applied to every later datagram toward the same destination,
//! not just the one that triggered it.
//!
//! The cache is a fixed-capacity, caller-owned slice scanned linearly, the
//! same shape as [`crate::resolution`]'s dynamic neighbour table: entries
//! are aged against a caller-supplied monotonic `now` rather than a wall
//! clock, and a full cache simply declines new entries instead of evicting
//! one.

use crate::{Ipv4Address, Ipv4Mtu, MonotonicMillis, IPV4_MINIMUM_MTU};

/// How long a path-MTU estimate is trusted before it is dropped.
///
/// RFC 1191 §6.3 asks an implementation not to probe for a larger path MTU
/// more often than every 10 minutes. This cache does not send probes, but it
/// applies the same interval the other way around: once an estimate has gone
/// unconfirmed for that long, it is discarded rather than repaired, so a
/// path that has since grown its MTU back is free to do so the moment this
/// estimate ages out.
pub const PMTU_STALE_MS: u64 = 10 * 60 * 1_000;

/// The RFC 1191 §7 plateau table, largest first.
///
/// A router that predates RFC 1191 reports Fragmentation Needed with a
/// next-hop MTU of zero. Section 7 asks the value to be estimated instead
/// from the size of the datagram that did not make it through, by picking
/// the largest plateau below it. These are "common" MTUs in use when RFC
/// 1191 was written, not link-layer constants; the table is exhaustive and
/// fixed by the RFC.
const PLATEAUS: [u16; 11] = [
    65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
];

/// Picks the largest RFC 1191 §7 plateau strictly below `quoted_total_len`.
///
/// Falls back to the IPv4 minimum when the quoted datagram is already no
/// larger than the smallest plateau, which keeps the result a valid MTU
/// without a separate floor at every call site.
const fn plateau_below(quoted_total_len: u16) -> u16 {
    let mut index = 0;
    while index < PLATEAUS.len() {
        if PLATEAUS[index] < quoted_total_len {
            return PLATEAUS[index];
        }
        index += 1;
    }
    IPV4_MINIMUM_MTU
}

/// One destination's estimated path MTU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmtuSlot {
    destination: Ipv4Address,
    estimate: Ipv4Mtu,
    updated_at: MonotonicMillis,
    occupied: bool,
}

impl PmtuSlot {
    pub const EMPTY: Self = Self {
        destination: Ipv4Address::from_octets([0; 4]),
        estimate: Ipv4Mtu::MINIMUM,
        updated_at: MonotonicMillis(0),
        occupied: false,
    };

    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn destination(self) -> Ipv4Address {
        self.destination
    }

    #[must_use]
    pub const fn estimate(self) -> Ipv4Mtu {
        self.estimate
    }

    #[must_use]
    pub const fn updated_at(self) -> MonotonicMillis {
        self.updated_at
    }
}

/// What a learned Fragmentation Needed report did to the cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmtuLearnOutcome {
    /// No live estimate existed for the destination; the reported value was
    /// installed as-is.
    Inserted,
    /// A live estimate existed and the report lowered it.
    Lowered,
    /// A live estimate existed and the report did not lower it further.
    Unchanged,
    /// No slot was free and none had aged out; the report was dropped.
    CacheFull,
}

/// A fixed-capacity path-MTU cache over a caller-owned slice of slots.
pub struct PmtuCache<'a> {
    slots: &'a mut [PmtuSlot],
}

impl<'a> PmtuCache<'a> {
    /// Builds a cache over `slots`, clearing whatever they held before.
    pub fn new(slots: &'a mut [PmtuSlot]) -> Self {
        slots.fill(PmtuSlot::EMPTY);
        Self { slots }
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub fn occupied_count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.occupied).count()
    }

    /// Returns the caller-owned slots for cold/test evidence.
    #[must_use]
    pub fn slots(&self) -> &[PmtuSlot] {
        self.slots
    }

    /// The MTU to use when sending toward `destination`.
    ///
    /// This is the smaller of the egress interface's own MTU and any live
    /// path-MTU estimate learned for that destination, which is exactly
    /// where [`crate::forwarding`]'s existing fragmentation decision already
    /// compares a datagram's length against the interface MTU. An estimate
    /// found to be older than [`PMTU_STALE_MS`] is dropped here and the
    /// interface MTU is returned undiminished, restoring the path to full
    /// size until another Fragmentation Needed report constrains it again.
    pub fn effective_mtu(
        &mut self,
        destination: Ipv4Address,
        interface_mtu: Ipv4Mtu,
        now: MonotonicMillis,
    ) -> Ipv4Mtu {
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.occupied && slot.destination == destination)
        else {
            return interface_mtu;
        };
        if now.0.saturating_sub(self.slots[index].updated_at.0) >= PMTU_STALE_MS {
            self.slots[index] = PmtuSlot::EMPTY;
            return interface_mtu;
        }
        interface_mtu.min(self.slots[index].estimate)
    }

    /// Records what an RFC 1191 §5 ICMPv4 Fragmentation Needed message says
    /// about the path MTU toward `destination`.
    ///
    /// A non-zero `next_hop_mtu` is the reporting router's own word for its
    /// next link (§5). A zero `next_hop_mtu` means that router predates RFC
    /// 1191 and never learned to report one; `quoted_total_len` — the total
    /// length of the datagram quoted inside the ICMP message, the one that
    /// did not fit — is used to estimate it instead, from the RFC 1191 §7
    /// plateau table. Either way the new estimate never falls below the
    /// IPv4 minimum, and it only ever lowers a live estimate: RFC 1191 §6.3
    /// leaves raising the estimate again to ageing, not to a bigger report.
    pub fn learn(
        &mut self,
        destination: Ipv4Address,
        next_hop_mtu: u16,
        quoted_total_len: u16,
        now: MonotonicMillis,
    ) -> PmtuLearnOutcome {
        let reported = if next_hop_mtu == 0 {
            plateau_below(quoted_total_len)
        } else {
            next_hop_mtu
        }
        .max(IPV4_MINIMUM_MTU);
        let reported = Ipv4Mtu::new(reported)
            .expect("plateau and floor keep this at or above the IPv4 minimum");

        if let Some(index) = self.slots.iter().position(|slot| {
            slot.occupied
                && slot.destination == destination
                && now.0.saturating_sub(slot.updated_at.0) < PMTU_STALE_MS
        }) {
            let current = self.slots[index].estimate;
            let updated = current.min(reported);
            self.slots[index].estimate = updated;
            self.slots[index].updated_at = now;
            return if updated.bytes() < current.bytes() {
                PmtuLearnOutcome::Lowered
            } else {
                PmtuLearnOutcome::Unchanged
            };
        }
        let reusable = self.slots.iter().position(|slot| {
            !slot.occupied || now.0.saturating_sub(slot.updated_at.0) >= PMTU_STALE_MS
        });
        let Some(index) = reusable else {
            return PmtuLearnOutcome::CacheFull;
        };
        self.slots[index] = PmtuSlot {
            destination,
            estimate: reported,
            updated_at: now,
            occupied: true,
        };
        PmtuLearnOutcome::Inserted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(last: u8) -> Ipv4Address {
        Ipv4Address::from_octets([203, 0, 113, last])
    }

    #[test]
    fn cache_hit_lowers_the_fragmentation_threshold_below_the_interface_mtu() {
        let mut slots = [PmtuSlot::EMPTY; 4];
        let mut cache = PmtuCache::new(&mut slots);
        assert_eq!(
            cache.learn(dest(1), 1200, 1500, MonotonicMillis(0)),
            PmtuLearnOutcome::Inserted
        );
        let effective = cache.effective_mtu(dest(1), Ipv4Mtu::ETHERNET, MonotonicMillis(1));
        assert_eq!(effective.bytes(), 1200);
        assert!(effective.bytes() < Ipv4Mtu::ETHERNET.bytes());
    }

    #[test]
    fn an_absurdly_small_reported_mtu_never_drops_below_the_ipv4_floor() {
        let mut slots = [PmtuSlot::EMPTY; 4];
        let mut cache = PmtuCache::new(&mut slots);
        cache.learn(dest(1), 1, 1500, MonotonicMillis(0));
        let effective = cache.effective_mtu(dest(1), Ipv4Mtu::ETHERNET, MonotonicMillis(1));
        assert_eq!(effective.bytes(), IPV4_MINIMUM_MTU);
    }

    #[test]
    fn a_zero_next_hop_mtu_selects_the_plateau_below_the_quoted_datagram() {
        let mut slots = [PmtuSlot::EMPTY; 4];
        let mut cache = PmtuCache::new(&mut slots);
        // 1500 sits strictly between the 1492 and 2002 plateaus.
        cache.learn(dest(1), 0, 1500, MonotonicMillis(0));
        let effective = cache.effective_mtu(dest(1), Ipv4Mtu::ETHERNET, MonotonicMillis(1));
        assert_eq!(effective.bytes(), 1492);
    }

    #[test]
    fn a_zero_next_hop_mtu_below_every_plateau_floors_at_the_ipv4_minimum() {
        let mut slots = [PmtuSlot::EMPTY; 4];
        let mut cache = PmtuCache::new(&mut slots);
        cache.learn(dest(1), 0, 60, MonotonicMillis(0));
        let effective = cache.effective_mtu(dest(1), Ipv4Mtu::ETHERNET, MonotonicMillis(1));
        assert_eq!(effective.bytes(), IPV4_MINIMUM_MTU);
    }

    #[test]
    fn an_aged_out_entry_restores_the_interface_mtu() {
        let mut slots = [PmtuSlot::EMPTY; 4];
        let mut cache = PmtuCache::new(&mut slots);
        cache.learn(dest(1), 1200, 1500, MonotonicMillis(0));
        let still_live = cache.effective_mtu(
            dest(1),
            Ipv4Mtu::ETHERNET,
            MonotonicMillis(PMTU_STALE_MS - 1),
        );
        assert_eq!(still_live.bytes(), 1200);
        let restored =
            cache.effective_mtu(dest(1), Ipv4Mtu::ETHERNET, MonotonicMillis(PMTU_STALE_MS));
        assert_eq!(restored.bytes(), Ipv4Mtu::ETHERNET.bytes());
        assert_eq!(cache.occupied_count(), 0);
    }

    #[test]
    fn a_later_smaller_report_wins_over_an_earlier_larger_one() {
        let mut slots = [PmtuSlot::EMPTY; 4];
        let mut cache = PmtuCache::new(&mut slots);
        assert_eq!(
            cache.learn(dest(1), 1400, 1500, MonotonicMillis(0)),
            PmtuLearnOutcome::Inserted
        );
        assert_eq!(
            cache.learn(dest(1), 900, 1500, MonotonicMillis(10)),
            PmtuLearnOutcome::Lowered
        );
        // A later, larger report does not undo the smaller one: RFC 1191
        // §6.3 leaves raising the estimate to ageing, not to a bigger quote.
        assert_eq!(
            cache.learn(dest(1), 1400, 1500, MonotonicMillis(20)),
            PmtuLearnOutcome::Unchanged
        );
        let effective = cache.effective_mtu(dest(1), Ipv4Mtu::ETHERNET, MonotonicMillis(21));
        assert_eq!(effective.bytes(), 900);
    }

    #[test]
    fn a_full_cache_declines_a_new_destination_without_disturbing_live_entries() {
        let mut slots = [PmtuSlot::EMPTY; 1];
        let mut cache = PmtuCache::new(&mut slots);
        assert_eq!(
            cache.learn(dest(1), 1200, 1500, MonotonicMillis(0)),
            PmtuLearnOutcome::Inserted
        );
        assert_eq!(
            cache.learn(dest(2), 1200, 1500, MonotonicMillis(0)),
            PmtuLearnOutcome::CacheFull
        );
        let effective = cache.effective_mtu(dest(1), Ipv4Mtu::ETHERNET, MonotonicMillis(1));
        assert_eq!(effective.bytes(), 1200);
    }
}

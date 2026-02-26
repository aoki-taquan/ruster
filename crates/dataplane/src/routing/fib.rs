//! Forwarding Information Base (FIB).
//!
//! The FIB is the forwarding-optimized data structure derived from the
//! RIB's best-path selection.  It contains only the information needed
//! for longest-prefix-match (LPM) lookups: prefix, next-hop, and
//! outgoing interface.
//!
//! The FIB is rebuilt wholesale from the RIB whenever the RIB changes.
//! This simple approach is acceptable for the v0.1 route table sizes.
//!
//! RFC-REF: RFC 791 Section 3.2
//! "Routing is based on the destination address [...] the most specific
//! matching route is selected."

use super::rib::{Rib, RibEntry};
use super::table::matches_prefix;

/// A single entry in the FIB, optimized for forwarding lookups.
///
/// Contains only the data needed to make a forwarding decision; no
/// protocol metadata (source, admin distance, timestamps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibEntry {
    /// Network prefix (host-byte-order).
    pub prefix: [u8; 4],
    /// Prefix length in bits (0..=32).
    pub prefix_len: u8,
    /// Next-hop IPv4 address.
    pub next_hop: [u8; 4],
    /// Outgoing interface name.
    pub out_ifname: String,
}

/// The Forwarding Information Base.
///
/// Entries are sorted by prefix length descending so that the first
/// match in a linear scan is the longest (most specific) prefix match,
/// mirroring the behavior of the original [`super::table::RouteTable`].
#[derive(Debug, Clone)]
pub struct Fib {
    /// FIB entries sorted by prefix_len descending.
    entries: Vec<FibEntry>,
}

impl Fib {
    /// Build a FIB from the RIB's best-path selection.
    ///
    /// Extracts one route per prefix (the best route according to
    /// admin_distance then metric) and sorts them for LPM lookup.
    pub fn from_rib(rib: &Rib) -> Self {
        let best = rib.best_routes();
        let mut entries: Vec<FibEntry> = best
            .into_iter()
            .map(|r| FibEntry {
                prefix: r.prefix,
                prefix_len: r.prefix_len,
                next_hop: r.next_hop,
                out_ifname: r.out_ifname.clone(),
            })
            .collect();

        // Sort by prefix_len descending (longest first) for LPM.
        entries.sort_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then(a.prefix.cmp(&b.prefix))
        });

        Self { entries }
    }

    /// Create an empty FIB.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Longest prefix match lookup.
    ///
    /// RFC-REF: RFC 791 Section 3.2
    /// "Routing is based on the destination address [...] the most specific
    /// matching route is selected."
    ///
    /// Returns the first (longest prefix) matching entry, or `None` if no
    /// route matches.
    pub fn lookup(&self, dst_ip: &[u8; 4]) -> Option<&FibEntry> {
        self.entries
            .iter()
            .find(|entry| matches_prefix(dst_ip, &entry.prefix, entry.prefix_len))
    }

    /// Returns the number of FIB entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the FIB is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build a FIB directly from a list of RIB entries (convenience).
    ///
    /// This builds a temporary RIB, inserts all entries, and then
    /// extracts the FIB.  Useful for tests and one-shot construction.
    pub fn from_entries(entries: Vec<RibEntry>) -> Self {
        let mut rib = Rib::new();
        for entry in entries {
            rib.insert(entry);
        }
        Self::from_rib(&rib)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::protocol::ProtocolSource;
    use crate::routing::rib::RibEntry;

    fn make_rib_entry(
        prefix: [u8; 4],
        prefix_len: u8,
        next_hop: [u8; 4],
        ifname: &str,
        metric: u32,
        source: ProtocolSource,
    ) -> RibEntry {
        RibEntry {
            prefix,
            prefix_len,
            next_hop,
            out_ifname: ifname.to_string(),
            metric,
            source,
            admin_distance: source.default_admin_distance(),
        }
    }

    // ── FIB from RIB tests ───────────────────────────────────────────

    #[test]
    fn fib_from_empty_rib() {
        let rib = Rib::new();
        let fib = Fib::from_rib(&rib);
        assert!(fib.is_empty());
    }

    #[test]
    fn fib_from_rib_contains_best_routes() {
        let mut rib = Rib::new();
        // Static default route.
        rib.insert(make_rib_entry(
            [0, 0, 0, 0], 0, [10, 0, 0, 1], "wan0", 100, ProtocolSource::Static,
        ));
        // Static LAN route.
        rib.insert(make_rib_entry(
            [192, 168, 1, 0], 24, [0, 0, 0, 0], "lan0", 10, ProtocolSource::Static,
        ));

        let fib = Fib::from_rib(&rib);
        assert_eq!(fib.len(), 2);
    }

    #[test]
    fn fib_lpm_lookup_longest_match() {
        let mut rib = Rib::new();
        rib.insert(make_rib_entry(
            [0, 0, 0, 0], 0, [10, 0, 0, 1], "wan0", 100, ProtocolSource::Static,
        ));
        rib.insert(make_rib_entry(
            [192, 168, 1, 0], 24, [0, 0, 0, 0], "lan0", 10, ProtocolSource::Static,
        ));
        rib.insert(make_rib_entry(
            [192, 168, 1, 128], 25, [192, 168, 1, 254], "lan0", 10, ProtocolSource::Static,
        ));

        let fib = Fib::from_rib(&rib);

        // 192.168.1.200 matches /25 and /24; /25 should win.
        let result = fib.lookup(&[192, 168, 1, 200]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().prefix_len, 25);
        assert_eq!(result.unwrap().next_hop, [192, 168, 1, 254]);

        // 192.168.1.10 matches /24 only.
        let result = fib.lookup(&[192, 168, 1, 10]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().prefix_len, 24);

        // 8.8.8.8 matches default route.
        let result = fib.lookup(&[8, 8, 8, 8]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().prefix_len, 0);
        assert_eq!(result.unwrap().next_hop, [10, 0, 0, 1]);
    }

    #[test]
    fn fib_lookup_no_match_empty() {
        let fib = Fib::empty();
        assert!(fib.lookup(&[10, 0, 0, 1]).is_none());
    }

    #[test]
    fn fib_lookup_no_match_no_default() {
        let mut rib = Rib::new();
        rib.insert(make_rib_entry(
            [192, 168, 1, 0], 24, [0, 0, 0, 0], "lan0", 10, ProtocolSource::Static,
        ));
        let fib = Fib::from_rib(&rib);
        assert!(fib.lookup(&[10, 0, 0, 1]).is_none());
    }

    #[test]
    fn fib_reflects_admin_distance_selection() {
        let mut rib = Rib::new();
        // OSPF route with lower metric but higher AD.
        rib.insert(make_rib_entry(
            [10, 0, 0, 0], 8, [10, 0, 0, 2], "wan0", 10, ProtocolSource::Ospf,
        ));
        // Static route with higher metric but lower AD.
        rib.insert(make_rib_entry(
            [10, 0, 0, 0], 8, [10, 0, 0, 1], "wan0", 100, ProtocolSource::Static,
        ));

        let fib = Fib::from_rib(&rib);
        assert_eq!(fib.len(), 1);

        let result = fib.lookup(&[10, 1, 2, 3]).unwrap();
        // Static wins (AD=1 < AD=110).
        assert_eq!(result.next_hop, [10, 0, 0, 1]);
    }

    #[test]
    fn fib_from_entries_convenience() {
        let entries = vec![
            make_rib_entry(
                [0, 0, 0, 0], 0, [10, 0, 0, 1], "wan0", 100, ProtocolSource::Static,
            ),
            make_rib_entry(
                [192, 168, 1, 0], 24, [0, 0, 0, 0], "lan0", 10, ProtocolSource::Static,
            ),
        ];
        let fib = Fib::from_entries(entries);
        assert_eq!(fib.len(), 2);
        assert!(fib.lookup(&[192, 168, 1, 50]).is_some());
    }

    // ── FIB rebuild after RIB mutation ───────────────────────────────

    #[test]
    fn fib_rebuild_after_rib_insert() {
        let mut rib = Rib::new();
        rib.insert(make_rib_entry(
            [0, 0, 0, 0], 0, [10, 0, 0, 1], "wan0", 100, ProtocolSource::Static,
        ));

        let fib1 = Fib::from_rib(&rib);
        assert_eq!(fib1.len(), 1);

        // Add a more specific route.
        rib.insert(make_rib_entry(
            [192, 168, 1, 0], 24, [0, 0, 0, 0], "lan0", 10, ProtocolSource::Static,
        ));

        let fib2 = Fib::from_rib(&rib);
        assert_eq!(fib2.len(), 2);
    }

    #[test]
    fn fib_rebuild_after_rib_remove() {
        let mut rib = Rib::new();
        rib.insert(make_rib_entry(
            [0, 0, 0, 0], 0, [10, 0, 0, 1], "wan0", 100, ProtocolSource::Static,
        ));
        rib.insert(make_rib_entry(
            [192, 168, 1, 0], 24, [0, 0, 0, 0], "lan0", 10, ProtocolSource::Static,
        ));

        let fib1 = Fib::from_rib(&rib);
        assert_eq!(fib1.len(), 2);

        // Remove the LAN route.
        rib.remove(&[192, 168, 1, 0], 24, ProtocolSource::Static);

        let fib2 = Fib::from_rib(&rib);
        assert_eq!(fib2.len(), 1);
        assert!(fib2.lookup(&[192, 168, 1, 50]).is_some()); // falls through to default
        assert_eq!(fib2.lookup(&[192, 168, 1, 50]).unwrap().prefix_len, 0);
    }
}

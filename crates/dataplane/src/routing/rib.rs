//! Routing Information Base (RIB).
//!
//! The RIB stores all routes from every protocol source (static,
//! connected, OSPF, BGP, etc.) and performs best-path selection to
//! determine which route for each prefix should be installed in the FIB.
//!
//! # Best-path selection
//!
//! For each unique prefix, the best route is selected by:
//! 1. Lowest administrative distance (protocol preference).
//! 2. Lowest metric (tie-breaker within the same admin distance).
//!
//! RFC-REF: RFC 791 Section 3.2
//! "Routing is based on the destination address [...] the most specific
//! matching route is selected."

use super::protocol::ProtocolSource;

/// A single entry in the RIB.
///
/// Each entry represents one route learned from a particular protocol
/// source.  Multiple entries may exist for the same prefix (from
/// different sources); best-path selection picks the winner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RibEntry {
    /// Network prefix (host-byte-order, e.g. [192, 168, 1, 0]).
    pub prefix: [u8; 4],
    /// Prefix length in bits (0..=32).
    pub prefix_len: u8,
    /// Next-hop IPv4 address.
    pub next_hop: [u8; 4],
    /// Outgoing interface name.
    pub out_ifname: String,
    /// Route metric (lower is preferred within the same admin distance).
    pub metric: u32,
    /// Which routing protocol installed this route.
    pub source: ProtocolSource,
    /// Administrative distance (lower is preferred across protocols).
    pub admin_distance: u8,
}

/// The Routing Information Base.
///
/// Holds all routes from all protocol sources.  The RIB is the
/// authoritative data structure from which the FIB is derived via
/// best-path selection.
#[derive(Debug, Clone)]
pub struct Rib {
    /// All route entries, unsorted.  Best-path selection is performed
    /// on demand when building the FIB.
    entries: Vec<RibEntry>,
}

impl Rib {
    /// Create an empty RIB.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a route entry into the RIB.
    ///
    /// If an entry with the same (prefix, prefix_len, source) already
    /// exists, it is replaced.  This allows protocol adapters to update
    /// their routes without leaving stale entries.
    pub fn insert(&mut self, entry: RibEntry) {
        // Remove any existing entry from the same source for the same prefix.
        self.entries.retain(|e| {
            !(e.prefix == entry.prefix
                && e.prefix_len == entry.prefix_len
                && e.source == entry.source
                && e.out_ifname == entry.out_ifname)
        });
        self.entries.push(entry);
    }

    /// Remove all routes for a given prefix from a specific source.
    ///
    /// Returns the number of entries removed.
    pub fn remove(&mut self, prefix: &[u8; 4], prefix_len: u8, source: ProtocolSource) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| {
            !(e.prefix == *prefix && e.prefix_len == prefix_len && e.source == source)
        });
        before - self.entries.len()
    }

    /// Remove all routes from a specific protocol source.
    ///
    /// Useful when a protocol adapter is shutting down or
    /// re-synchronizing all its routes.
    ///
    /// Returns the number of entries removed.
    pub fn remove_by_source(&mut self, source: ProtocolSource) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.source != source);
        before - self.entries.len()
    }

    /// Return the best routes — one per unique prefix.
    ///
    /// For each (prefix, prefix_len) group, the entry with the lowest
    /// admin_distance wins; ties are broken by lowest metric.
    pub fn best_routes(&self) -> Vec<&RibEntry> {
        // Group entries by (prefix, prefix_len).
        use std::collections::HashMap;
        let mut groups: HashMap<([u8; 4], u8), Vec<&RibEntry>> = HashMap::new();

        for entry in &self.entries {
            groups
                .entry((entry.prefix, entry.prefix_len))
                .or_default()
                .push(entry);
        }

        let mut best: Vec<&RibEntry> = groups
            .into_values()
            .map(|mut candidates| {
                candidates.sort_by(|a, b| {
                    a.admin_distance
                        .cmp(&b.admin_distance)
                        .then(a.metric.cmp(&b.metric))
                });
                candidates[0]
            })
            .collect();

        // Sort output for deterministic ordering: longest prefix first,
        // then by prefix bytes, then by metric.
        best.sort_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then(a.prefix.cmp(&b.prefix))
                .then(a.metric.cmp(&b.metric))
        });

        best
    }

    /// Return all routes from a specific protocol source.
    pub fn routes_by_source(&self, source: ProtocolSource) -> Vec<&RibEntry> {
        self.entries.iter().filter(|e| e.source == source).collect()
    }

    /// Return the total number of entries in the RIB.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the RIB is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all entries (for testing / introspection).
    pub fn entries(&self) -> &[RibEntry] {
        &self.entries
    }
}

impl Default for Rib {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::protocol::ProtocolSource;

    fn static_entry(prefix: [u8; 4], prefix_len: u8, metric: u32) -> RibEntry {
        RibEntry {
            prefix,
            prefix_len,
            next_hop: [10, 0, 0, 1],
            out_ifname: "wan0".to_string(),
            metric,
            source: ProtocolSource::Static,
            admin_distance: ProtocolSource::Static.default_admin_distance(),
        }
    }

    fn ospf_entry(prefix: [u8; 4], prefix_len: u8, metric: u32) -> RibEntry {
        RibEntry {
            prefix,
            prefix_len,
            next_hop: [10, 0, 0, 2],
            out_ifname: "wan0".to_string(),
            metric,
            source: ProtocolSource::Ospf,
            admin_distance: ProtocolSource::Ospf.default_admin_distance(),
        }
    }

    fn bgp_entry(prefix: [u8; 4], prefix_len: u8, metric: u32) -> RibEntry {
        RibEntry {
            prefix,
            prefix_len,
            next_hop: [10, 0, 0, 3],
            out_ifname: "wan0".to_string(),
            metric,
            source: ProtocolSource::Bgp,
            admin_distance: ProtocolSource::Bgp.default_admin_distance(),
        }
    }

    fn connected_entry(prefix: [u8; 4], prefix_len: u8, ifname: &str) -> RibEntry {
        RibEntry {
            prefix,
            prefix_len,
            next_hop: [0, 0, 0, 0],
            out_ifname: ifname.to_string(),
            metric: 0,
            source: ProtocolSource::Connected,
            admin_distance: ProtocolSource::Connected.default_admin_distance(),
        }
    }

    // ── Insert / Remove tests ────────────────────────────────────────

    #[test]
    fn insert_and_len() {
        let mut rib = Rib::new();
        assert!(rib.is_empty());

        rib.insert(static_entry([10, 0, 0, 0], 8, 100));
        assert_eq!(rib.len(), 1);

        rib.insert(static_entry([192, 168, 1, 0], 24, 10));
        assert_eq!(rib.len(), 2);
    }

    #[test]
    fn insert_replaces_same_source_same_prefix() {
        let mut rib = Rib::new();
        rib.insert(static_entry([10, 0, 0, 0], 8, 100));
        assert_eq!(rib.len(), 1);

        // Insert same prefix + source: should replace.
        rib.insert(static_entry([10, 0, 0, 0], 8, 50));
        assert_eq!(rib.len(), 1);
        assert_eq!(rib.entries()[0].metric, 50);
    }

    #[test]
    fn insert_keeps_different_sources_for_same_prefix() {
        let mut rib = Rib::new();
        rib.insert(static_entry([10, 0, 0, 0], 8, 100));
        rib.insert(ospf_entry([10, 0, 0, 0], 8, 50));
        assert_eq!(rib.len(), 2);
    }

    #[test]
    fn remove_by_prefix_and_source() {
        let mut rib = Rib::new();
        rib.insert(static_entry([10, 0, 0, 0], 8, 100));
        rib.insert(ospf_entry([10, 0, 0, 0], 8, 50));

        let removed = rib.remove(&[10, 0, 0, 0], 8, ProtocolSource::Static);
        assert_eq!(removed, 1);
        assert_eq!(rib.len(), 1);
        assert_eq!(rib.entries()[0].source, ProtocolSource::Ospf);
    }

    #[test]
    fn remove_nonexistent_returns_zero() {
        let mut rib = Rib::new();
        rib.insert(static_entry([10, 0, 0, 0], 8, 100));
        let removed = rib.remove(&[10, 0, 0, 0], 8, ProtocolSource::Ospf);
        assert_eq!(removed, 0);
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn remove_by_source() {
        let mut rib = Rib::new();
        rib.insert(static_entry([10, 0, 0, 0], 8, 100));
        rib.insert(static_entry([192, 168, 1, 0], 24, 10));
        rib.insert(ospf_entry([172, 16, 0, 0], 12, 50));

        let removed = rib.remove_by_source(ProtocolSource::Static);
        assert_eq!(removed, 2);
        assert_eq!(rib.len(), 1);
        assert_eq!(rib.entries()[0].source, ProtocolSource::Ospf);
    }

    // ── Best-path selection tests ────────────────────────────────────

    #[test]
    fn best_routes_single_entry() {
        let mut rib = Rib::new();
        rib.insert(static_entry([10, 0, 0, 0], 8, 100));

        let best = rib.best_routes();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, [10, 0, 0, 0]);
    }

    #[test]
    fn best_routes_admin_distance_wins() {
        let mut rib = Rib::new();
        // Static (AD=1) and OSPF (AD=110) for the same prefix.
        rib.insert(ospf_entry([10, 0, 0, 0], 8, 10)); // lower metric but higher AD
        rib.insert(static_entry([10, 0, 0, 0], 8, 100)); // higher metric but lower AD

        let best = rib.best_routes();
        assert_eq!(best.len(), 1);
        // Static wins because AD=1 < AD=110, despite higher metric.
        assert_eq!(best[0].source, ProtocolSource::Static);
        assert_eq!(best[0].admin_distance, 1);
    }

    #[test]
    fn best_routes_metric_breaks_tie_within_same_ad() {
        let mut rib = Rib::new();
        // Two static routes for the same prefix with different metrics
        // (different out_ifname so both are kept).
        let mut entry1 = static_entry([10, 0, 0, 0], 8, 200);
        entry1.out_ifname = "wan1".to_string();
        let entry2 = static_entry([10, 0, 0, 0], 8, 100);

        rib.insert(entry1);
        rib.insert(entry2);

        let best = rib.best_routes();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].metric, 100); // lower metric wins
    }

    #[test]
    fn best_routes_multiple_prefixes() {
        let mut rib = Rib::new();
        rib.insert(static_entry([0, 0, 0, 0], 0, 100)); // default route
        rib.insert(static_entry([192, 168, 1, 0], 24, 10)); // LAN
        rib.insert(ospf_entry([10, 0, 0, 0], 8, 50)); // OSPF route

        let best = rib.best_routes();
        assert_eq!(best.len(), 3);
        // Should be sorted by prefix_len desc: /24, /8, /0.
        assert_eq!(best[0].prefix_len, 24);
        assert_eq!(best[1].prefix_len, 8);
        assert_eq!(best[2].prefix_len, 0);
    }

    #[test]
    fn best_routes_bgp_beats_ospf() {
        let mut rib = Rib::new();
        rib.insert(bgp_entry([10, 0, 0, 0], 8, 100)); // AD=20
        rib.insert(ospf_entry([10, 0, 0, 0], 8, 10)); // AD=110

        let best = rib.best_routes();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].source, ProtocolSource::Bgp);
    }

    #[test]
    fn best_routes_connected_beats_all() {
        let mut rib = Rib::new();
        rib.insert(connected_entry([192, 168, 1, 0], 24, "lan0")); // AD=0
        rib.insert(static_entry([192, 168, 1, 0], 24, 10)); // AD=1
        rib.insert(ospf_entry([192, 168, 1, 0], 24, 5)); // AD=110

        let best = rib.best_routes();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].source, ProtocolSource::Connected);
    }

    // ── routes_by_source tests ───────────────────────────────────────

    #[test]
    fn routes_by_source_filters_correctly() {
        let mut rib = Rib::new();
        rib.insert(static_entry([10, 0, 0, 0], 8, 100));
        rib.insert(static_entry([192, 168, 1, 0], 24, 10));
        rib.insert(ospf_entry([172, 16, 0, 0], 12, 50));

        let static_routes = rib.routes_by_source(ProtocolSource::Static);
        assert_eq!(static_routes.len(), 2);

        let ospf_routes = rib.routes_by_source(ProtocolSource::Ospf);
        assert_eq!(ospf_routes.len(), 1);

        let bgp_routes = rib.routes_by_source(ProtocolSource::Bgp);
        assert_eq!(bgp_routes.len(), 0);
    }

    // ── Default trait test ───────────────────────────────────────────

    #[test]
    fn default_rib_is_empty() {
        let rib = Rib::default();
        assert!(rib.is_empty());
    }
}

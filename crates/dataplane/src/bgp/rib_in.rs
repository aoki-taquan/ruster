//! Adj-RIB-In: per-peer received route storage.
//!
//! Each BGP peer maintains an Adj-RIB-In that stores all routes
//! received from that peer, before import policy is applied.
//!
//! RFC-REF: RFC 4271 Section 3.2
//! "The Adj-RIBs-In contain unprocessed routing information that has
//! been advertised to the local BGP speaker by its peers."

use super::path::PathAttributes;

/// A single route entry in the Adj-RIB-In.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjRibInEntry {
    /// Network prefix.
    pub prefix: [u8; 4],
    /// Prefix length in bits (0..=32).
    pub prefix_len: u8,
    /// Path attributes received from the peer.
    pub attributes: PathAttributes,
    /// Peer router-id (for best-path tie-breaking).
    pub peer_router_id: [u8; 4],
}

/// Per-peer Adj-RIB-In.
///
/// Stores all routes received from a single BGP peer. Routes are
/// keyed by (prefix, prefix_len); a new advertisement for the same
/// prefix replaces the previous one.
#[derive(Debug, Clone, Default)]
pub struct AdjRibIn {
    entries: Vec<AdjRibInEntry>,
}

impl AdjRibIn {
    /// Create a new empty Adj-RIB-In.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert or replace a route.
    ///
    /// If a route with the same (prefix, prefix_len) already exists,
    /// it is replaced with the new attributes.
    pub fn insert(&mut self, entry: AdjRibInEntry) {
        // Replace existing entry for the same prefix.
        self.entries
            .retain(|e| !(e.prefix == entry.prefix && e.prefix_len == entry.prefix_len));
        self.entries.push(entry);
    }

    /// Withdraw a route by (prefix, prefix_len).
    ///
    /// Returns true if the route was found and removed.
    pub fn withdraw(&mut self, prefix: &[u8; 4], prefix_len: u8) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|e| !(e.prefix == *prefix && e.prefix_len == prefix_len));
        self.entries.len() < before
    }

    /// Remove all routes (peer session down).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return all entries.
    pub fn entries(&self) -> &[AdjRibInEntry] {
        &self.entries
    }

    /// Return the number of routes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if there are no routes.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::path::{AsPath, AsPathSegment, Origin, PathAttributes};

    fn make_entry(prefix: [u8; 4], prefix_len: u8) -> AdjRibInEntry {
        AdjRibInEntry {
            prefix,
            prefix_len,
            attributes: PathAttributes {
                origin: Origin::Igp,
                as_path: AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                },
                next_hop: [10, 0, 0, 2],
                med: None,
                local_pref: Some(100),
            },
            peer_router_id: [10, 0, 0, 2],
        }
    }

    #[test]
    fn insert_and_len() {
        let mut rib = AdjRibIn::new();
        assert!(rib.is_empty());

        rib.insert(make_entry([192, 168, 1, 0], 24));
        assert_eq!(rib.len(), 1);

        rib.insert(make_entry([10, 0, 0, 0], 8));
        assert_eq!(rib.len(), 2);
    }

    #[test]
    fn insert_replaces_existing() {
        let mut rib = AdjRibIn::new();
        rib.insert(make_entry([192, 168, 1, 0], 24));
        assert_eq!(rib.len(), 1);

        // Insert same prefix with different attributes.
        let mut entry = make_entry([192, 168, 1, 0], 24);
        entry.attributes.med = Some(50);
        rib.insert(entry);
        assert_eq!(rib.len(), 1);
        assert_eq!(rib.entries()[0].attributes.med, Some(50));
    }

    #[test]
    fn withdraw_existing() {
        let mut rib = AdjRibIn::new();
        rib.insert(make_entry([192, 168, 1, 0], 24));
        rib.insert(make_entry([10, 0, 0, 0], 8));
        assert_eq!(rib.len(), 2);

        let removed = rib.withdraw(&[192, 168, 1, 0], 24);
        assert!(removed);
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn withdraw_nonexistent() {
        let mut rib = AdjRibIn::new();
        rib.insert(make_entry([192, 168, 1, 0], 24));

        let removed = rib.withdraw(&[10, 0, 0, 0], 8);
        assert!(!removed);
        assert_eq!(rib.len(), 1);
    }

    #[test]
    fn clear_removes_all() {
        let mut rib = AdjRibIn::new();
        rib.insert(make_entry([192, 168, 1, 0], 24));
        rib.insert(make_entry([10, 0, 0, 0], 8));
        assert_eq!(rib.len(), 2);

        rib.clear();
        assert!(rib.is_empty());
    }

    #[test]
    fn different_prefix_len_treated_separately() {
        let mut rib = AdjRibIn::new();
        rib.insert(make_entry([10, 0, 0, 0], 8));
        rib.insert(make_entry([10, 0, 0, 0], 16));
        assert_eq!(rib.len(), 2);
    }
}

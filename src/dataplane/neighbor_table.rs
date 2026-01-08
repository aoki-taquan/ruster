//! IPv6 Neighbor table (IP to MAC mapping) - RFC 4861

use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

/// Neighbor entry state (RFC 4861 Section 7.3.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    /// Address resolution in progress, waiting for NA
    Incomplete,
    /// Recently confirmed reachability
    Reachable,
    /// Reachability is unknown, will probe on next use
    Stale,
}

/// Neighbor table entry
#[derive(Debug, Clone)]
struct NeighborEntry {
    mac: MacAddr,
    state: NeighborState,
    last_updated: Instant,
    is_router: bool,
}

/// IPv6 Neighbor table for IP to MAC resolution
#[derive(Debug)]
pub struct NeighborTable {
    entries: HashMap<Ipv6Addr, NeighborEntry>,
    reachable_time: Duration,
    stale_time: Duration,
}

impl NeighborTable {
    pub fn new(reachable_time: Duration, stale_time: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            reachable_time,
            stale_time,
        }
    }

    /// Insert or update a neighbor entry
    pub fn insert(&mut self, ip: Ipv6Addr, mac: MacAddr) {
        self.entries.insert(
            ip,
            NeighborEntry {
                mac,
                state: NeighborState::Reachable,
                last_updated: Instant::now(),
                is_router: false,
            },
        );
    }

    /// Insert or update a neighbor entry with router flag
    pub fn insert_with_router_flag(&mut self, ip: Ipv6Addr, mac: MacAddr, is_router: bool) {
        self.entries.insert(
            ip,
            NeighborEntry {
                mac,
                state: NeighborState::Reachable,
                last_updated: Instant::now(),
                is_router,
            },
        );
    }

    /// Lookup MAC address for an IPv6 address
    pub fn lookup(&self, ip: &Ipv6Addr) -> Option<(MacAddr, NeighborState)> {
        self.entries.get(ip).map(|e| (e.mac, e.state))
    }

    /// Lookup with full entry info
    pub fn lookup_full(&self, ip: &Ipv6Addr) -> Option<(MacAddr, NeighborState, bool)> {
        self.entries.get(ip).map(|e| (e.mac, e.state, e.is_router))
    }

    /// Mark an entry as incomplete (pending NS)
    pub fn mark_incomplete(&mut self, ip: Ipv6Addr) {
        self.entries.insert(
            ip,
            NeighborEntry {
                mac: MacAddr::ZERO,
                state: NeighborState::Incomplete,
                last_updated: Instant::now(),
                is_router: false,
            },
        );
    }

    /// Update entry states based on time
    pub fn refresh_states(&mut self) {
        let now = Instant::now();
        for entry in self.entries.values_mut() {
            let age = now.duration_since(entry.last_updated);
            if entry.state == NeighborState::Reachable && age > self.reachable_time {
                entry.state = NeighborState::Stale;
            }
        }

        // Remove very old entries
        self.entries
            .retain(|_, e| now.duration_since(e.last_updated) < self.stale_time);
    }

    /// Get all entries that need neighbor refresh
    pub fn get_stale_entries(&self) -> Vec<Ipv6Addr> {
        self.entries
            .iter()
            .filter(|(_, e)| {
                e.state == NeighborState::Stale || e.state == NeighborState::Incomplete
            })
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Update an existing entry to Reachable state
    pub fn confirm_reachability(&mut self, ip: &Ipv6Addr) {
        if let Some(entry) = self.entries.get_mut(ip) {
            entry.state = NeighborState::Reachable;
            entry.last_updated = Instant::now();
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove an entry
    pub fn remove(&mut self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.entries.remove(ip).map(|e| e.mac)
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        // Default: 30 seconds reachable, 2 minutes stale timeout
        Self::new(Duration::from_secs(30), Duration::from_secs(120))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> NeighborTable {
        NeighborTable::new(Duration::from_secs(30), Duration::from_secs(120))
    }

    #[test]
    fn test_insert_and_lookup() {
        let mut table = make_table();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        table.insert(ip, mac);

        let result = table.lookup(&ip);
        assert!(result.is_some());
        let (found_mac, state) = result.unwrap();
        assert_eq!(found_mac, mac);
        assert_eq!(state, NeighborState::Reachable);
    }

    #[test]
    fn test_lookup_nonexistent() {
        let table = make_table();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(table.lookup(&ip).is_none());
    }

    #[test]
    fn test_mark_incomplete() {
        let mut table = make_table();
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();

        table.mark_incomplete(ip);

        let result = table.lookup(&ip);
        assert!(result.is_some());
        let (mac, state) = result.unwrap();
        assert_eq!(mac, MacAddr::ZERO);
        assert_eq!(state, NeighborState::Incomplete);
    }

    #[test]
    fn test_update_incomplete_to_reachable() {
        let mut table = make_table();
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        table.mark_incomplete(ip);
        table.insert(ip, mac);

        let result = table.lookup(&ip);
        assert!(result.is_some());
        let (found_mac, state) = result.unwrap();
        assert_eq!(found_mac, mac);
        assert_eq!(state, NeighborState::Reachable);
    }

    #[test]
    fn test_insert_with_router_flag() {
        let mut table = make_table();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        table.insert_with_router_flag(ip, mac, true);

        let result = table.lookup_full(&ip);
        assert!(result.is_some());
        let (found_mac, state, is_router) = result.unwrap();
        assert_eq!(found_mac, mac);
        assert_eq!(state, NeighborState::Reachable);
        assert!(is_router);
    }

    #[test]
    fn test_multiple_entries() {
        let mut table = make_table();

        let entries = [
            (
                "fe80::1".parse().unwrap(),
                MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ),
            (
                "fe80::2".parse().unwrap(),
                MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ),
            (
                "2001:db8::1".parse().unwrap(),
                MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            ),
        ];

        for (ip, mac) in &entries {
            table.insert(*ip, *mac);
        }

        assert_eq!(table.len(), 3);

        for (ip, mac) in &entries {
            let result = table.lookup(ip);
            assert!(result.is_some());
            assert_eq!(result.unwrap().0, *mac);
        }
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut table = make_table();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        table.insert("fe80::1".parse().unwrap(), MacAddr([0x00; 6]));
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_get_stale_entries_incomplete() {
        let mut table = make_table();
        let ip1: Ipv6Addr = "fe80::1".parse().unwrap();
        let ip2: Ipv6Addr = "fe80::2".parse().unwrap();

        table.mark_incomplete(ip1);
        table.insert(ip2, MacAddr([0xaa; 6]));

        let stale = table.get_stale_entries();
        assert_eq!(stale.len(), 1);
        assert!(stale.contains(&ip1));
    }

    #[test]
    fn test_confirm_reachability() {
        let mut table = make_table();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        table.insert(ip, mac);

        // Manually change to Stale for testing
        if let Some(entry) = table.entries.get_mut(&ip) {
            entry.state = NeighborState::Stale;
        }

        assert_eq!(table.lookup(&ip).unwrap().1, NeighborState::Stale);

        table.confirm_reachability(&ip);

        assert_eq!(table.lookup(&ip).unwrap().1, NeighborState::Reachable);
    }

    #[test]
    fn test_remove() {
        let mut table = make_table();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        table.insert(ip, mac);
        assert_eq!(table.len(), 1);

        let removed = table.remove(&ip);
        assert_eq!(removed, Some(mac));
        assert_eq!(table.len(), 0);

        // Remove non-existent
        let removed = table.remove(&ip);
        assert!(removed.is_none());
    }

    #[test]
    fn test_default() {
        let table = NeighborTable::default();
        assert!(table.is_empty());
    }

    #[test]
    fn test_link_local_and_global() {
        let mut table = make_table();

        // Link-local address
        let link_local: Ipv6Addr = "fe80::1234:5678:abcd:ef01".parse().unwrap();
        let mac1 = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        table.insert(link_local, mac1);

        // Global unicast address
        let global: Ipv6Addr = "2001:db8:1234::1".parse().unwrap();
        let mac2 = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        table.insert(global, mac2);

        assert_eq!(table.len(), 2);
        assert_eq!(table.lookup(&link_local).unwrap().0, mac1);
        assert_eq!(table.lookup(&global).unwrap().0, mac2);
    }
}

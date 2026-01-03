//! ARP table (IP to MAC mapping)

use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// ARP entry state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpState {
    /// Waiting for ARP reply
    Incomplete,
    /// Valid entry
    Reachable,
    /// Entry is stale, needs refresh
    Stale,
}

/// ARP table entry
#[derive(Debug, Clone)]
struct ArpEntry {
    mac: MacAddr,
    state: ArpState,
    last_updated: Instant,
}

/// ARP table for IP to MAC resolution
#[derive(Debug, Default)]
pub struct ArpTable {
    entries: HashMap<Ipv4Addr, ArpEntry>,
    reachable_time: Duration,
    stale_time: Duration,
}

impl ArpTable {
    pub fn new(reachable_time: Duration, stale_time: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            reachable_time,
            stale_time,
        }
    }

    /// Insert or update an ARP entry
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.entries.insert(
            ip,
            ArpEntry {
                mac,
                state: ArpState::Reachable,
                last_updated: Instant::now(),
            },
        );
    }

    /// Lookup MAC address for an IP
    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<(MacAddr, ArpState)> {
        self.entries.get(ip).map(|e| (e.mac, e.state))
    }

    /// Mark an entry as incomplete (pending ARP request)
    pub fn mark_incomplete(&mut self, ip: Ipv4Addr) {
        self.entries.insert(
            ip,
            ArpEntry {
                mac: MacAddr::ZERO,
                state: ArpState::Incomplete,
                last_updated: Instant::now(),
            },
        );
    }

    /// Update entry states based on time
    pub fn refresh_states(&mut self) {
        let now = Instant::now();
        for entry in self.entries.values_mut() {
            let age = now.duration_since(entry.last_updated);
            if entry.state == ArpState::Reachable && age > self.reachable_time {
                entry.state = ArpState::Stale;
            }
        }

        // Remove very old entries
        self.entries
            .retain(|_, e| now.duration_since(e.last_updated) < self.stale_time);
    }

    /// Get all entries that need ARP refresh
    pub fn get_stale_entries(&self) -> Vec<Ipv4Addr> {
        self.entries
            .iter()
            .filter(|(_, e)| e.state == ArpState::Stale || e.state == ArpState::Incomplete)
            .map(|(ip, _)| *ip)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_lookup() {
        let mut table = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        table.insert(ip, mac);

        let result = table.lookup(&ip);
        assert!(result.is_some());
        let (found_mac, state) = result.unwrap();
        assert_eq!(found_mac, mac);
        assert_eq!(state, ArpState::Reachable);
    }

    #[test]
    fn test_lookup_nonexistent() {
        let table = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        assert!(table.lookup(&ip).is_none());
    }

    #[test]
    fn test_mark_incomplete() {
        let mut table = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let ip = Ipv4Addr::new(192, 168, 1, 1);

        table.mark_incomplete(ip);

        let result = table.lookup(&ip);
        assert!(result.is_some());
        let (mac, state) = result.unwrap();
        assert_eq!(mac, MacAddr::ZERO);
        assert_eq!(state, ArpState::Incomplete);
    }

    #[test]
    fn test_update_incomplete_to_reachable() {
        let mut table = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        table.mark_incomplete(ip);
        table.insert(ip, mac);

        let result = table.lookup(&ip);
        assert!(result.is_some());
        let (found_mac, state) = result.unwrap();
        assert_eq!(found_mac, mac);
        assert_eq!(state, ArpState::Reachable);
    }

    #[test]
    fn test_multiple_entries() {
        let mut table = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));

        let entries = [
            (
                Ipv4Addr::new(192, 168, 1, 1),
                MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ),
            (
                Ipv4Addr::new(192, 168, 1, 2),
                MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ),
            (
                Ipv4Addr::new(192, 168, 1, 3),
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
        let mut table = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        table.insert(Ipv4Addr::new(192, 168, 1, 1), MacAddr([0x00; 6]));
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_get_stale_entries_incomplete() {
        let mut table = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let ip1 = Ipv4Addr::new(192, 168, 1, 1);
        let ip2 = Ipv4Addr::new(192, 168, 1, 2);

        table.mark_incomplete(ip1);
        table.insert(ip2, MacAddr([0xaa; 6]));

        let stale = table.get_stale_entries();
        assert_eq!(stale.len(), 1);
        assert!(stale.contains(&ip1));
    }

    #[test]
    fn test_default() {
        let table = ArpTable::default();
        assert!(table.is_empty());
    }
}

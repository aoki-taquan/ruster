//! Forwarding Database (MAC address table)

use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Port identifier
pub type PortId = u32;

/// FDB entry with aging support
#[derive(Debug, Clone)]
struct FdbEntry {
    port: PortId,
    last_seen: Instant,
}

/// Forwarding Database for L2 switching
///
/// Maintains MAC address to port mappings per VLAN.
#[derive(Debug, Default)]
pub struct Fdb {
    /// VLAN ID -> (MAC -> Entry)
    tables: HashMap<u16, HashMap<MacAddr, FdbEntry>>,
    /// Maximum age for entries
    max_age: Duration,
}

impl Fdb {
    pub fn new(max_age: Duration) -> Self {
        Self {
            tables: HashMap::new(),
            max_age,
        }
    }

    /// Learn a MAC address on a port
    pub fn learn(&mut self, mac: MacAddr, vlan: u16, port: PortId) {
        // Don't learn broadcast/multicast addresses
        if mac.is_broadcast() || mac.is_multicast() {
            return;
        }

        let table = self.tables.entry(vlan).or_default();
        table.insert(
            mac,
            FdbEntry {
                port,
                last_seen: Instant::now(),
            },
        );
    }

    /// Lookup a MAC address
    pub fn lookup(&self, mac: &MacAddr, vlan: u16) -> Option<PortId> {
        self.tables
            .get(&vlan)?
            .get(mac)
            .map(|entry| entry.port)
    }

    /// Remove aged-out entries
    pub fn age_out(&mut self) {
        let now = Instant::now();
        for table in self.tables.values_mut() {
            table.retain(|_, entry| now.duration_since(entry.last_seen) < self.max_age);
        }
    }

    /// Get all ports in a VLAN (for flooding)
    pub fn get_vlan_ports(&self, _vlan: u16) -> Vec<PortId> {
        // TODO: Track port membership per VLAN
        Vec::new()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.tables.clear();
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.tables.values().map(|t| t.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_learn_and_lookup() {
        let mut fdb = Fdb::new(Duration::from_secs(300));
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.learn(mac, 1, 0);
        assert_eq!(fdb.lookup(&mac, 1), Some(0));
        assert_eq!(fdb.lookup(&mac, 2), None);
    }

    #[test]
    fn test_no_learn_broadcast() {
        let mut fdb = Fdb::new(Duration::from_secs(300));

        fdb.learn(MacAddr::BROADCAST, 1, 0);
        assert_eq!(fdb.lookup(&MacAddr::BROADCAST, 1), None);
    }
}

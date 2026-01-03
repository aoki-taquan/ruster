//! Forwarding Database (MAC address table)
//!
//! Provides L2 switching functionality including:
//! - MAC address learning from received frames
//! - FDB lookup for forwarding decisions
//! - Unknown unicast/broadcast flooding
//! - Aging mechanism for stale entries
//! - Per-VLAN FDB separation (IVL - Independent VLAN Learning)

use crate::protocol::MacAddr;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Port identifier
pub type PortId = u32;

/// Default VLAN ID for untagged frames
pub const DEFAULT_VLAN: u16 = 1;

/// Default aging time in seconds (5 minutes, per IEEE 802.1D)
pub const DEFAULT_AGING_TIME_SECS: u64 = 300;

/// FDB entry with aging support
#[derive(Debug, Clone)]
struct FdbEntry {
    port: PortId,
    last_seen: Instant,
}

/// Result of a L2 forwarding decision
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2ForwardAction {
    /// Forward to a specific port (unicast hit)
    Forward { port: PortId },
    /// Flood to all ports in VLAN except ingress port (unknown unicast/broadcast/multicast)
    Flood { ports: Vec<PortId> },
    /// Filter/drop the frame (e.g., same port as source)
    Filter,
}

/// Forwarding Database for L2 switching
///
/// Maintains MAC address to port mappings per VLAN with support for:
/// - Independent VLAN Learning (IVL)
/// - Port-VLAN membership tracking
/// - Automatic aging of entries
#[derive(Debug)]
pub struct Fdb {
    /// VLAN ID -> (MAC -> Entry)
    tables: HashMap<u16, HashMap<MacAddr, FdbEntry>>,
    /// VLAN ID -> Set of member ports
    vlan_ports: HashMap<u16, HashSet<PortId>>,
    /// Maximum age for entries
    max_age: Duration,
}

impl Default for Fdb {
    fn default() -> Self {
        Self::new(Duration::from_secs(DEFAULT_AGING_TIME_SECS))
    }
}

impl Fdb {
    pub fn new(max_age: Duration) -> Self {
        Self {
            tables: HashMap::new(),
            vlan_ports: HashMap::new(),
            max_age,
        }
    }

    // ========================================
    // VLAN Port Membership Management
    // ========================================

    /// Add a port to a VLAN
    pub fn add_port_to_vlan(&mut self, port: PortId, vlan: u16) {
        self.vlan_ports.entry(vlan).or_default().insert(port);
    }

    /// Remove a port from a VLAN
    pub fn remove_port_from_vlan(&mut self, port: PortId, vlan: u16) {
        if let Some(ports) = self.vlan_ports.get_mut(&vlan) {
            ports.remove(&port);
            // Also remove any FDB entries learned on this port for this VLAN
            if let Some(table) = self.tables.get_mut(&vlan) {
                table.retain(|_, entry| entry.port != port);
            }
        }
    }

    /// Remove a port from all VLANs (e.g., when port goes down)
    pub fn remove_port(&mut self, port: PortId) {
        for ports in self.vlan_ports.values_mut() {
            ports.remove(&port);
        }
        for table in self.tables.values_mut() {
            table.retain(|_, entry| entry.port != port);
        }
    }

    /// Check if a port is a member of a VLAN
    pub fn is_port_in_vlan(&self, port: PortId, vlan: u16) -> bool {
        self.vlan_ports
            .get(&vlan)
            .is_some_and(|ports| ports.contains(&port))
    }

    /// Get all ports in a VLAN (for flooding)
    pub fn get_vlan_ports(&self, vlan: u16) -> Vec<PortId> {
        self.vlan_ports
            .get(&vlan)
            .map(|ports| ports.iter().copied().collect())
            .unwrap_or_default()
    }

    // ========================================
    // MAC Learning
    // ========================================

    /// Learn a MAC address on a port
    ///
    /// Updates the FDB with the source MAC address from a received frame.
    /// Does not learn broadcast or multicast addresses.
    ///
    /// # Arguments
    /// * `mac` - Source MAC address from the frame
    /// * `vlan` - VLAN ID of the frame
    /// * `port` - Ingress port where the frame was received
    pub fn learn(&mut self, mac: MacAddr, vlan: u16, port: PortId) {
        // Don't learn broadcast/multicast addresses
        if mac.is_broadcast() || mac.is_multicast() {
            return;
        }

        // Ensure port is member of VLAN (auto-add for flexibility)
        self.add_port_to_vlan(port, vlan);

        let table = self.tables.entry(vlan).or_default();
        table.insert(
            mac,
            FdbEntry {
                port,
                last_seen: Instant::now(),
            },
        );
    }

    /// Learn from a received Ethernet frame
    ///
    /// Convenience method that extracts source MAC and learns it.
    pub fn learn_from_frame(&mut self, src_mac: MacAddr, vlan: u16, ingress_port: PortId) {
        self.learn(src_mac, vlan, ingress_port);
    }

    // ========================================
    // FDB Lookup and Forwarding Decision
    // ========================================

    /// Lookup a MAC address in the FDB
    pub fn lookup(&self, mac: &MacAddr, vlan: u16) -> Option<PortId> {
        self.tables.get(&vlan)?.get(mac).map(|entry| entry.port)
    }

    /// Make a forwarding decision for a frame
    ///
    /// # Arguments
    /// * `dst_mac` - Destination MAC address of the frame
    /// * `vlan` - VLAN ID of the frame
    /// * `ingress_port` - Port where the frame was received
    ///
    /// # Returns
    /// L2ForwardAction indicating how to handle the frame
    pub fn forward(&self, dst_mac: &MacAddr, vlan: u16, ingress_port: PortId) -> L2ForwardAction {
        // Broadcast/multicast: always flood
        if dst_mac.is_broadcast() || dst_mac.is_multicast() {
            let ports = self.get_flood_ports(vlan, ingress_port);
            return L2ForwardAction::Flood { ports };
        }

        // Unicast: lookup in FDB
        match self.lookup(dst_mac, vlan) {
            Some(egress_port) => {
                if egress_port == ingress_port {
                    // Same port as source: filter
                    L2ForwardAction::Filter
                } else {
                    L2ForwardAction::Forward { port: egress_port }
                }
            }
            None => {
                // Unknown unicast: flood
                let ports = self.get_flood_ports(vlan, ingress_port);
                L2ForwardAction::Flood { ports }
            }
        }
    }

    /// Get ports to flood to, excluding ingress port
    fn get_flood_ports(&self, vlan: u16, ingress_port: PortId) -> Vec<PortId> {
        self.vlan_ports
            .get(&vlan)
            .map(|ports| {
                ports
                    .iter()
                    .filter(|&&p| p != ingress_port)
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    // ========================================
    // Aging
    // ========================================

    /// Remove aged-out entries
    ///
    /// Should be called periodically (e.g., every 10-30 seconds) to clean
    /// up stale FDB entries. Returns the number of entries removed.
    pub fn age_out(&mut self) -> usize {
        let now = Instant::now();
        let mut removed = 0;

        for table in self.tables.values_mut() {
            let before = table.len();
            table.retain(|_, entry| now.duration_since(entry.last_seen) < self.max_age);
            removed += before - table.len();
        }

        removed
    }

    /// Get the configured maximum age for entries
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Set the maximum age for entries
    pub fn set_max_age(&mut self, max_age: Duration) {
        self.max_age = max_age;
    }

    // ========================================
    // Utility Methods
    // ========================================

    /// Clear all FDB entries (but keep VLAN port memberships)
    pub fn clear(&mut self) {
        self.tables.clear();
    }

    /// Clear all FDB entries and VLAN port memberships
    pub fn clear_all(&mut self) {
        self.tables.clear();
        self.vlan_ports.clear();
    }

    /// Get number of MAC entries
    pub fn len(&self) -> usize {
        self.tables.values().map(|t| t.len()).sum()
    }

    /// Check if FDB is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get number of entries in a specific VLAN
    pub fn len_in_vlan(&self, vlan: u16) -> usize {
        self.tables.get(&vlan).map_or(0, |t| t.len())
    }

    /// Get all VLANs that have entries or port memberships
    pub fn vlans(&self) -> Vec<u16> {
        let mut vlans: HashSet<u16> = self.tables.keys().copied().collect();
        vlans.extend(self.vlan_ports.keys());
        vlans.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // Basic Learning and Lookup Tests
    // ========================================

    #[test]
    fn test_learn_and_lookup() {
        let mut fdb = Fdb::new(Duration::from_secs(300));
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.learn(mac, 1, 0);
        assert_eq!(fdb.lookup(&mac, 1), Some(0));
        // VLAN separation: same MAC in different VLAN should not be found
        assert_eq!(fdb.lookup(&mac, 2), None);
    }

    #[test]
    fn test_no_learn_broadcast() {
        let mut fdb = Fdb::new(Duration::from_secs(300));

        fdb.learn(MacAddr::BROADCAST, 1, 0);
        assert_eq!(fdb.lookup(&MacAddr::BROADCAST, 1), None);
    }

    #[test]
    fn test_no_learn_multicast() {
        let mut fdb = Fdb::new(Duration::from_secs(300));
        // Multicast MAC: first byte has LSB set
        let multicast_mac = MacAddr([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);

        fdb.learn(multicast_mac, 1, 0);
        assert_eq!(fdb.lookup(&multicast_mac, 1), None);
    }

    #[test]
    fn test_mac_move() {
        let mut fdb = Fdb::new(Duration::from_secs(300));
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Learn MAC on port 0
        fdb.learn(mac, 1, 0);
        assert_eq!(fdb.lookup(&mac, 1), Some(0));

        // MAC moves to port 1
        fdb.learn(mac, 1, 1);
        assert_eq!(fdb.lookup(&mac, 1), Some(1));
    }

    // ========================================
    // VLAN Separation Tests (IVL)
    // ========================================

    #[test]
    fn test_vlan_separation() {
        let mut fdb = Fdb::new(Duration::from_secs(300));
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Same MAC learned on different ports in different VLANs
        fdb.learn(mac, 10, 0);
        fdb.learn(mac, 20, 1);

        // Each VLAN has its own entry
        assert_eq!(fdb.lookup(&mac, 10), Some(0));
        assert_eq!(fdb.lookup(&mac, 20), Some(1));
        assert_eq!(fdb.len(), 2);
    }

    #[test]
    fn test_len_in_vlan() {
        let mut fdb = Fdb::new(Duration::from_secs(300));
        let mac1 = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mac2 = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x56]);

        fdb.learn(mac1, 10, 0);
        fdb.learn(mac2, 10, 1);
        fdb.learn(mac1, 20, 2);

        assert_eq!(fdb.len_in_vlan(10), 2);
        assert_eq!(fdb.len_in_vlan(20), 1);
        assert_eq!(fdb.len_in_vlan(30), 0);
    }

    // ========================================
    // VLAN Port Membership Tests
    // ========================================

    #[test]
    fn test_vlan_port_membership() {
        let mut fdb = Fdb::default();

        fdb.add_port_to_vlan(0, 10);
        fdb.add_port_to_vlan(1, 10);
        fdb.add_port_to_vlan(2, 10);
        fdb.add_port_to_vlan(1, 20);

        assert!(fdb.is_port_in_vlan(0, 10));
        assert!(fdb.is_port_in_vlan(1, 10));
        assert!(fdb.is_port_in_vlan(1, 20));
        assert!(!fdb.is_port_in_vlan(0, 20));
        assert!(!fdb.is_port_in_vlan(3, 10));

        let vlan10_ports = fdb.get_vlan_ports(10);
        assert_eq!(vlan10_ports.len(), 3);
        assert!(vlan10_ports.contains(&0));
        assert!(vlan10_ports.contains(&1));
        assert!(vlan10_ports.contains(&2));
    }

    #[test]
    fn test_remove_port_from_vlan() {
        let mut fdb = Fdb::default();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.add_port_to_vlan(0, 10);
        fdb.add_port_to_vlan(1, 10);
        fdb.learn(mac, 10, 0);

        assert_eq!(fdb.lookup(&mac, 10), Some(0));

        // Remove port 0 from VLAN 10
        fdb.remove_port_from_vlan(0, 10);

        // Port should no longer be in VLAN
        assert!(!fdb.is_port_in_vlan(0, 10));
        // MAC entry should be removed
        assert_eq!(fdb.lookup(&mac, 10), None);
        // Port 1 still in VLAN
        assert!(fdb.is_port_in_vlan(1, 10));
    }

    #[test]
    fn test_remove_port_from_all_vlans() {
        let mut fdb = Fdb::default();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.add_port_to_vlan(0, 10);
        fdb.add_port_to_vlan(0, 20);
        fdb.learn(mac, 10, 0);
        fdb.learn(mac, 20, 0);

        // Port 0 is in both VLANs
        assert!(fdb.is_port_in_vlan(0, 10));
        assert!(fdb.is_port_in_vlan(0, 20));

        // Remove port 0 from all VLANs
        fdb.remove_port(0);

        // Port should be removed from all VLANs
        assert!(!fdb.is_port_in_vlan(0, 10));
        assert!(!fdb.is_port_in_vlan(0, 20));
        // All MAC entries learned on port 0 should be removed
        assert!(fdb.is_empty());
    }

    // ========================================
    // Forwarding Decision Tests
    // ========================================

    #[test]
    fn test_forward_known_unicast() {
        let mut fdb = Fdb::default();
        let mac1 = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mac2 = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x56]);

        fdb.add_port_to_vlan(0, 10);
        fdb.add_port_to_vlan(1, 10);
        fdb.learn(mac1, 10, 0);
        fdb.learn(mac2, 10, 1);

        // Frame from port 0 to mac2 (on port 1)
        let action = fdb.forward(&mac2, 10, 0);
        assert_eq!(action, L2ForwardAction::Forward { port: 1 });
    }

    #[test]
    fn test_forward_unknown_unicast_flood() {
        let mut fdb = Fdb::default();
        let known_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let unknown_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x99]);

        fdb.add_port_to_vlan(0, 10);
        fdb.add_port_to_vlan(1, 10);
        fdb.add_port_to_vlan(2, 10);
        fdb.learn(known_mac, 10, 0);

        // Frame from port 0 to unknown MAC should flood to ports 1 and 2
        let action = fdb.forward(&unknown_mac, 10, 0);
        match action {
            L2ForwardAction::Flood { ports } => {
                assert_eq!(ports.len(), 2);
                assert!(ports.contains(&1));
                assert!(ports.contains(&2));
                assert!(!ports.contains(&0)); // Ingress port excluded
            }
            _ => panic!("Expected Flood action"),
        }
    }

    #[test]
    fn test_forward_broadcast_flood() {
        let mut fdb = Fdb::default();

        fdb.add_port_to_vlan(0, 10);
        fdb.add_port_to_vlan(1, 10);
        fdb.add_port_to_vlan(2, 10);

        // Broadcast frame from port 0 should flood to ports 1 and 2
        let action = fdb.forward(&MacAddr::BROADCAST, 10, 0);
        match action {
            L2ForwardAction::Flood { ports } => {
                assert_eq!(ports.len(), 2);
                assert!(ports.contains(&1));
                assert!(ports.contains(&2));
            }
            _ => panic!("Expected Flood action for broadcast"),
        }
    }

    #[test]
    fn test_forward_multicast_flood() {
        let mut fdb = Fdb::default();
        let multicast_mac = MacAddr([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);

        fdb.add_port_to_vlan(0, 10);
        fdb.add_port_to_vlan(1, 10);

        // Multicast frame should flood
        let action = fdb.forward(&multicast_mac, 10, 0);
        match action {
            L2ForwardAction::Flood { ports } => {
                assert!(ports.contains(&1));
            }
            _ => panic!("Expected Flood action for multicast"),
        }
    }

    #[test]
    fn test_forward_same_port_filter() {
        let mut fdb = Fdb::default();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.add_port_to_vlan(0, 10);
        fdb.learn(mac, 10, 0);

        // Frame received on same port as learned MAC should be filtered
        let action = fdb.forward(&mac, 10, 0);
        assert_eq!(action, L2ForwardAction::Filter);
    }

    // ========================================
    // Aging Tests
    // ========================================

    #[test]
    fn test_aging() {
        let mut fdb = Fdb::new(Duration::from_millis(50));
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.learn(mac, 1, 0);
        assert_eq!(fdb.lookup(&mac, 1), Some(0));

        // Wait for entry to age out
        std::thread::sleep(Duration::from_millis(60));

        let removed = fdb.age_out();
        assert_eq!(removed, 1);
        assert_eq!(fdb.lookup(&mac, 1), None);
    }

    #[test]
    fn test_aging_refresh() {
        let mut fdb = Fdb::new(Duration::from_millis(100));
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.learn(mac, 1, 0);

        // Wait half the aging time
        std::thread::sleep(Duration::from_millis(60));

        // Re-learn (refresh) the MAC
        fdb.learn(mac, 1, 0);

        // Wait a bit more
        std::thread::sleep(Duration::from_millis(60));

        // Entry should still be there (refreshed)
        let removed = fdb.age_out();
        assert_eq!(removed, 0);
        assert_eq!(fdb.lookup(&mac, 1), Some(0));
    }

    #[test]
    fn test_max_age_config() {
        let mut fdb = Fdb::new(Duration::from_secs(300));
        assert_eq!(fdb.max_age(), Duration::from_secs(300));

        fdb.set_max_age(Duration::from_secs(600));
        assert_eq!(fdb.max_age(), Duration::from_secs(600));
    }

    // ========================================
    // Utility Tests
    // ========================================

    #[test]
    fn test_clear() {
        let mut fdb = Fdb::default();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.add_port_to_vlan(0, 10);
        fdb.learn(mac, 10, 0);

        // Clear only FDB entries
        fdb.clear();
        assert!(fdb.is_empty());
        // VLAN port membership should remain
        assert!(fdb.is_port_in_vlan(0, 10));
    }

    #[test]
    fn test_clear_all() {
        let mut fdb = Fdb::default();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        fdb.add_port_to_vlan(0, 10);
        fdb.learn(mac, 10, 0);

        // Clear everything
        fdb.clear_all();
        assert!(fdb.is_empty());
        assert!(!fdb.is_port_in_vlan(0, 10));
    }

    #[test]
    fn test_vlans() {
        let mut fdb = Fdb::default();

        fdb.add_port_to_vlan(0, 10);
        fdb.add_port_to_vlan(1, 20);
        fdb.learn(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), 30, 2);

        let vlans = fdb.vlans();
        assert!(vlans.contains(&10));
        assert!(vlans.contains(&20));
        assert!(vlans.contains(&30));
    }

    #[test]
    fn test_default() {
        let fdb = Fdb::default();
        assert!(fdb.is_empty());
        assert_eq!(fdb.max_age(), Duration::from_secs(DEFAULT_AGING_TIME_SECS));
    }

    #[test]
    fn test_auto_add_port_on_learn() {
        let mut fdb = Fdb::default();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Learning automatically adds port to VLAN
        fdb.learn(mac, 10, 0);

        assert!(fdb.is_port_in_vlan(0, 10));
    }
}

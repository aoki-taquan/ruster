//! NDP packet processor
//!
//! Handles Neighbor Solicitation/Advertisement logic and table updates.

use crate::dataplane::NeighborTable;
use crate::protocol::icmpv6::{NeighborAdvertisement, NeighborSolicitation};
use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::Instant;

/// Result of processing an NDP packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdpAction {
    /// No action needed
    None,
    /// Send a Neighbor Advertisement
    SendNeighborAdvertisement(NeighborAdvertisement),
    /// Table was updated (for logging/debugging)
    TableUpdated,
}

/// Process an incoming Neighbor Solicitation
///
/// # Arguments
/// * `ns` - The parsed Neighbor Solicitation
/// * `src_ip` - Source IPv6 address from the IPv6 header
/// * `table` - The neighbor table to update
/// * `local_addrs` - Our IPv6 addresses on this interface
/// * `local_mac` - Our MAC address on this interface
///
/// # Returns
/// * `NdpAction` indicating what action to take (if any)
pub fn process_neighbor_solicitation(
    ns: &NeighborSolicitation,
    src_ip: Ipv6Addr,
    table: &mut NeighborTable,
    local_addrs: &[Ipv6Addr],
    local_mac: MacAddr,
) -> NdpAction {
    // Learn from sender's source link-layer address option (if present)
    // Only if src_ip is not unspecified (DAD uses :: as source)
    if !src_ip.is_unspecified() {
        if let Some(sender_mac) = ns.source_link_addr {
            // Check if we already know this sender or if NS is for us
            let sender_known = table.lookup(&src_ip).is_some();
            let target_is_ours = local_addrs.contains(&ns.target_addr);

            if sender_known || target_is_ours {
                table.insert(src_ip, sender_mac);
            }
        }
    }

    // Check if the target address is one of ours
    if local_addrs.contains(&ns.target_addr) {
        // Generate Neighbor Advertisement
        let na = NeighborAdvertisement::solicited_reply(ns.target_addr, local_mac);
        return NdpAction::SendNeighborAdvertisement(na);
    }

    // Not for us
    NdpAction::None
}

/// Process an incoming Neighbor Advertisement
///
/// # Arguments
/// * `na` - The parsed Neighbor Advertisement
/// * `src_ip` - Source IPv6 address from the IPv6 header
/// * `table` - The neighbor table to update
///
/// # Returns
/// * `NdpAction` indicating what action to take
pub fn process_neighbor_advertisement(
    na: &NeighborAdvertisement,
    _src_ip: Ipv6Addr,
    table: &mut NeighborTable,
) -> NdpAction {
    // RFC 4861: The target address is the address being advertised
    let target = na.target_addr;

    // Get current entry state
    let current_entry = table.lookup(&target);

    match current_entry {
        Some((current_mac, state)) => {
            // Entry exists
            if let Some(new_mac) = na.target_link_addr {
                // RFC 4861 Section 7.2.5:
                // If Override flag is set, update regardless
                // If Override flag is not set, only update if current is incomplete
                // or if MAC address is the same
                use crate::dataplane::NeighborState;

                if na.override_flag || state == NeighborState::Incomplete || current_mac == new_mac {
                    table.insert_with_router_flag(target, new_mac, na.router_flag);
                    NdpAction::TableUpdated
                } else {
                    // Don't update, but if Solicited flag is set, confirm reachability
                    if na.solicited_flag {
                        table.confirm_reachability(&target);
                    }
                    NdpAction::None
                }
            } else {
                // No link-layer address in NA
                if na.solicited_flag {
                    table.confirm_reachability(&target);
                    NdpAction::TableUpdated
                } else {
                    NdpAction::None
                }
            }
        }
        None => {
            // No existing entry - only create if we have link-layer address
            if let Some(new_mac) = na.target_link_addr {
                table.insert_with_router_flag(target, new_mac, na.router_flag);
                NdpAction::TableUpdated
            } else {
                NdpAction::None
            }
        }
    }
}

/// A pending packet waiting for NDP resolution
#[derive(Debug)]
struct PendingPacket {
    /// The packet data to send
    data: Vec<u8>,
    /// When this packet was queued
    queued_at: Instant,
}

/// Queue for packets waiting on NDP resolution
///
/// When we need to send a packet but don't have the destination MAC,
/// we queue the packet here and send a Neighbor Solicitation. When the
/// NA comes back, we dequeue and send all pending packets.
#[derive(Debug, Default)]
pub struct NdpPendingQueue {
    /// Packets waiting for each IPv6 address
    pending: HashMap<Ipv6Addr, Vec<PendingPacket>>,
    /// Maximum packets to queue per IP
    max_per_ip: usize,
    /// Maximum age of queued packets (in seconds)
    max_age_secs: u64,
}

impl NdpPendingQueue {
    /// Create a new pending queue
    pub fn new(max_per_ip: usize, max_age_secs: u64) -> Self {
        Self {
            pending: HashMap::new(),
            max_per_ip,
            max_age_secs,
        }
    }

    /// Queue a packet waiting for NDP resolution
    ///
    /// Returns true if the packet was queued, false if the queue is full
    pub fn enqueue(&mut self, target_ip: Ipv6Addr, packet_data: Vec<u8>) -> bool {
        let queue = self.pending.entry(target_ip).or_default();

        if queue.len() >= self.max_per_ip {
            return false;
        }

        queue.push(PendingPacket {
            data: packet_data,
            queued_at: Instant::now(),
        });
        true
    }

    /// Dequeue all packets for a resolved IP
    ///
    /// Returns the packet data for all pending packets
    pub fn dequeue(&mut self, ip: &Ipv6Addr) -> Vec<Vec<u8>> {
        self.pending
            .remove(ip)
            .map(|packets| packets.into_iter().map(|p| p.data).collect())
            .unwrap_or_default()
    }

    /// Check if there are pending packets for an IP
    pub fn has_pending(&self, ip: &Ipv6Addr) -> bool {
        self.pending.get(ip).is_some_and(|v| !v.is_empty())
    }

    /// Remove expired packets from the queue
    pub fn expire_old(&mut self) {
        let now = Instant::now();
        let max_age = std::time::Duration::from_secs(self.max_age_secs);

        for queue in self.pending.values_mut() {
            queue.retain(|p| now.duration_since(p.queued_at) < max_age);
        }

        // Remove empty entries
        self.pending.retain(|_, v| !v.is_empty());
    }

    /// Get the number of IPs with pending packets
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::NeighborState;
    use std::time::Duration;

    fn make_table() -> NeighborTable {
        NeighborTable::new(Duration::from_secs(30), Duration::from_secs(120))
    }

    // process_neighbor_solicitation tests

    #[test]
    fn test_process_ns_for_us() {
        let mut table = make_table();
        let local_ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let sender_ip: Ipv6Addr = "fe80::2".parse().unwrap();
        let sender_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ns = NeighborSolicitation::new(local_ip, Some(sender_mac));

        let action =
            process_neighbor_solicitation(&ns, sender_ip, &mut table, &[local_ip], local_mac);

        // Should send NA
        match action {
            NdpAction::SendNeighborAdvertisement(na) => {
                assert_eq!(na.target_addr, local_ip);
                assert_eq!(na.target_link_addr, Some(local_mac));
                assert!(na.solicited_flag);
                assert!(na.override_flag);
                assert!(!na.router_flag);
            }
            _ => panic!("Expected SendNeighborAdvertisement action"),
        }

        // Should have learned sender
        let lookup = table.lookup(&sender_ip);
        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap().0, sender_mac);
    }

    #[test]
    fn test_process_ns_not_for_us() {
        let mut table = make_table();
        let local_ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let sender_ip: Ipv6Addr = "fe80::2".parse().unwrap();
        let sender_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // NS for different target
        let target: Ipv6Addr = "fe80::3".parse().unwrap();
        let ns = NeighborSolicitation::new(target, Some(sender_mac));

        let action =
            process_neighbor_solicitation(&ns, sender_ip, &mut table, &[local_ip], local_mac);

        // Should not reply
        assert_eq!(action, NdpAction::None);

        // Should NOT learn sender (not for us and sender not known)
        let lookup = table.lookup(&sender_ip);
        assert!(lookup.is_none());
    }

    #[test]
    fn test_process_ns_from_known_sender() {
        let mut table = make_table();
        let local_ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let sender_ip: Ipv6Addr = "fe80::2".parse().unwrap();
        let old_mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let new_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // Pre-existing entry
        table.insert(sender_ip, old_mac);

        // NS for different target, but from known sender with new MAC
        let target: Ipv6Addr = "fe80::3".parse().unwrap();
        let ns = NeighborSolicitation::new(target, Some(new_mac));

        let action =
            process_neighbor_solicitation(&ns, sender_ip, &mut table, &[local_ip], local_mac);

        // Not for us
        assert_eq!(action, NdpAction::None);

        // Should have updated known sender's MAC
        let lookup = table.lookup(&sender_ip);
        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap().0, new_mac);
    }

    #[test]
    fn test_process_ns_dad_unspecified_source() {
        let mut table = make_table();
        let local_ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // DAD uses unspecified source
        let sender_ip = Ipv6Addr::UNSPECIFIED;
        let sender_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ns = NeighborSolicitation::new(local_ip, Some(sender_mac));

        let action =
            process_neighbor_solicitation(&ns, sender_ip, &mut table, &[local_ip], local_mac);

        // Should send NA (target is ours)
        match action {
            NdpAction::SendNeighborAdvertisement(_) => {}
            _ => panic!("Expected SendNeighborAdvertisement action"),
        }

        // Should NOT learn from unspecified source
        assert!(table.lookup(&sender_ip).is_none());
    }

    #[test]
    fn test_process_ns_no_source_link_addr() {
        let mut table = make_table();
        let local_ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let sender_ip: Ipv6Addr = "fe80::2".parse().unwrap();

        // NS without source link-layer address option
        let ns = NeighborSolicitation::new(local_ip, None);

        let action =
            process_neighbor_solicitation(&ns, sender_ip, &mut table, &[local_ip], local_mac);

        // Should still send NA
        match action {
            NdpAction::SendNeighborAdvertisement(_) => {}
            _ => panic!("Expected SendNeighborAdvertisement action"),
        }

        // Should NOT learn sender (no link-layer address)
        assert!(table.lookup(&sender_ip).is_none());
    }

    // process_neighbor_advertisement tests

    #[test]
    fn test_process_na_new_entry() {
        let mut table = make_table();
        let src_ip: Ipv6Addr = "fe80::2".parse().unwrap();
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let na = NeighborAdvertisement::new(target, Some(mac), false, true, true);

        let action = process_neighbor_advertisement(&na, src_ip, &mut table);

        assert_eq!(action, NdpAction::TableUpdated);

        let lookup = table.lookup(&target);
        assert!(lookup.is_some());
        assert_eq!(lookup.unwrap().0, mac);
    }

    #[test]
    fn test_process_na_update_incomplete() {
        let mut table = make_table();
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // Mark as incomplete (we sent NS)
        table.mark_incomplete(target);

        let na = NeighborAdvertisement::new(target, Some(mac), false, true, false);

        let action = process_neighbor_advertisement(&na, target, &mut table);

        assert_eq!(action, NdpAction::TableUpdated);

        let lookup = table.lookup(&target);
        assert!(lookup.is_some());
        let (found_mac, state) = lookup.unwrap();
        assert_eq!(found_mac, mac);
        assert_eq!(state, NeighborState::Reachable);
    }

    #[test]
    fn test_process_na_override_flag() {
        let mut table = make_table();
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let old_mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let new_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // Existing entry
        table.insert(target, old_mac);

        // NA with Override flag
        let na = NeighborAdvertisement::new(target, Some(new_mac), false, true, true);

        let action = process_neighbor_advertisement(&na, target, &mut table);

        assert_eq!(action, NdpAction::TableUpdated);
        assert_eq!(table.lookup(&target).unwrap().0, new_mac);
    }

    #[test]
    fn test_process_na_no_override_different_mac() {
        let mut table = make_table();
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let old_mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let new_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // Existing entry
        table.insert(target, old_mac);

        // NA without Override flag and different MAC
        let na = NeighborAdvertisement::new(target, Some(new_mac), false, false, false);

        let action = process_neighbor_advertisement(&na, target, &mut table);

        // Should NOT update (no override, different MAC, not incomplete)
        assert_eq!(action, NdpAction::None);
        assert_eq!(table.lookup(&target).unwrap().0, old_mac);
    }

    #[test]
    fn test_process_na_router_flag() {
        let mut table = make_table();
        let target: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // NA with Router flag
        let na = NeighborAdvertisement::new(target, Some(mac), true, true, true);

        let action = process_neighbor_advertisement(&na, target, &mut table);

        assert_eq!(action, NdpAction::TableUpdated);

        let lookup = table.lookup_full(&target);
        assert!(lookup.is_some());
        let (_, _, is_router) = lookup.unwrap();
        assert!(is_router);
    }

    #[test]
    fn test_process_na_no_link_addr() {
        let mut table = make_table();
        let target: Ipv6Addr = "fe80::2".parse().unwrap();

        // NA without link-layer address, no existing entry
        let na = NeighborAdvertisement::new(target, None, false, true, true);

        let action = process_neighbor_advertisement(&na, target, &mut table);

        // Should not create entry
        assert_eq!(action, NdpAction::None);
        assert!(table.lookup(&target).is_none());
    }

    // NdpPendingQueue tests

    #[test]
    fn test_pending_queue_enqueue_dequeue() {
        let mut queue = NdpPendingQueue::new(3, 60);
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();

        assert!(queue.is_empty());
        assert!(!queue.has_pending(&ip));

        // Enqueue a packet
        assert!(queue.enqueue(ip, vec![1, 2, 3]));
        assert!(!queue.is_empty());
        assert!(queue.has_pending(&ip));
        assert_eq!(queue.len(), 1);

        // Enqueue more packets
        assert!(queue.enqueue(ip, vec![4, 5, 6]));
        assert!(queue.enqueue(ip, vec![7, 8, 9]));

        // Queue is full (max_per_ip = 3)
        assert!(!queue.enqueue(ip, vec![10, 11, 12]));

        // Dequeue all
        let packets = queue.dequeue(&ip);
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0], vec![1, 2, 3]);
        assert_eq!(packets[1], vec![4, 5, 6]);
        assert_eq!(packets[2], vec![7, 8, 9]);

        assert!(queue.is_empty());
        assert!(!queue.has_pending(&ip));
    }

    #[test]
    fn test_pending_queue_multiple_ips() {
        let mut queue = NdpPendingQueue::new(3, 60);
        let ip1: Ipv6Addr = "fe80::1".parse().unwrap();
        let ip2: Ipv6Addr = "fe80::2".parse().unwrap();

        queue.enqueue(ip1, vec![1, 2, 3]);
        queue.enqueue(ip2, vec![4, 5, 6]);
        queue.enqueue(ip1, vec![7, 8, 9]);

        assert_eq!(queue.len(), 2);

        let packets1 = queue.dequeue(&ip1);
        assert_eq!(packets1.len(), 2);

        let packets2 = queue.dequeue(&ip2);
        assert_eq!(packets2.len(), 1);

        assert!(queue.is_empty());
    }

    #[test]
    fn test_pending_queue_dequeue_nonexistent() {
        let mut queue = NdpPendingQueue::new(3, 60);
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();

        let packets = queue.dequeue(&ip);
        assert!(packets.is_empty());
    }

    #[test]
    fn test_pending_queue_default() {
        let queue = NdpPendingQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }
}

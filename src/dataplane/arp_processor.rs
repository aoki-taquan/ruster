//! ARP packet processor
//!
//! Handles ARP request/reply logic and table updates.

use crate::dataplane::ArpTable;
use crate::protocol::arp::{ArpOp, ArpPacket};
use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

/// Result of processing an ARP packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpAction {
    /// No action needed
    None,
    /// Send an ARP reply
    Reply(ArpPacket),
    /// Table was updated (for logging/debugging)
    TableUpdated,
}

/// Process an incoming ARP packet
///
/// # Arguments
/// * `packet` - The parsed ARP packet
/// * `table` - The ARP table to update
/// * `local_ip` - Our own IP address on this interface
/// * `local_mac` - Our own MAC address on this interface
///
/// # Returns
/// * `ArpAction` indicating what action to take (if any)
pub fn process_arp(
    packet: &ArpPacket,
    table: &mut ArpTable,
    local_ip: Ipv4Addr,
    local_mac: MacAddr,
) -> ArpAction {
    // Always learn from sender (RFC 826 optimization)
    // This updates the table even if the packet isn't for us
    let sender_known = table.lookup(&packet.sender_ip).is_some();

    if sender_known || packet.target_ip == local_ip {
        // Update table with sender's IP/MAC binding
        table.insert(packet.sender_ip, packet.sender_mac);
    }

    match packet.operation {
        ArpOp::Request => {
            // Is this request for our IP?
            if packet.target_ip == local_ip {
                // Generate ARP reply
                let reply =
                    ArpPacket::reply(local_mac, local_ip, packet.sender_mac, packet.sender_ip);
                ArpAction::Reply(reply)
            } else if packet.is_gratuitous() {
                // Gratuitous ARP - we already updated the table above
                ArpAction::TableUpdated
            } else {
                ArpAction::None
            }
        }
        ArpOp::Reply => {
            // We already updated the table above
            ArpAction::TableUpdated
        }
    }
}

/// A pending packet waiting for ARP resolution
#[derive(Debug)]
struct PendingPacket {
    /// The packet data to send
    data: Vec<u8>,
    /// When this packet was queued
    queued_at: Instant,
}

/// Queue for packets waiting on ARP resolution
///
/// When we need to send a packet but don't have the destination MAC,
/// we queue the packet here and send an ARP request. When the reply
/// comes back, we dequeue and send all pending packets.
#[derive(Debug, Default)]
pub struct ArpPendingQueue {
    /// Packets waiting for each IP address
    pending: HashMap<Ipv4Addr, Vec<PendingPacket>>,
    /// Maximum packets to queue per IP
    max_per_ip: usize,
    /// Maximum age of queued packets (in seconds)
    max_age_secs: u64,
}

impl ArpPendingQueue {
    /// Create a new pending queue
    pub fn new(max_per_ip: usize, max_age_secs: u64) -> Self {
        Self {
            pending: HashMap::new(),
            max_per_ip,
            max_age_secs,
        }
    }

    /// Queue a packet waiting for ARP resolution
    ///
    /// Returns true if the packet was queued, false if the queue is full
    pub fn enqueue(&mut self, target_ip: Ipv4Addr, packet_data: Vec<u8>) -> bool {
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
    pub fn dequeue(&mut self, ip: &Ipv4Addr) -> Vec<Vec<u8>> {
        self.pending
            .remove(ip)
            .map(|packets| packets.into_iter().map(|p| p.data).collect())
            .unwrap_or_default()
    }

    /// Check if there are pending packets for an IP
    pub fn has_pending(&self, ip: &Ipv4Addr) -> bool {
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
    use std::time::Duration;

    fn make_table() -> ArpTable {
        ArpTable::new(Duration::from_secs(30), Duration::from_secs(120))
    }

    #[test]
    fn test_process_request_for_us() {
        let mut table = make_table();
        let local_ip = Ipv4Addr::new(192, 168, 1, 1);
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let request = ArpPacket::request(
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Ipv4Addr::new(192, 168, 1, 2),
            local_ip,
        );

        let action = process_arp(&request, &mut table, local_ip, local_mac);

        // Should reply
        match action {
            ArpAction::Reply(reply) => {
                assert_eq!(reply.operation, ArpOp::Reply);
                assert_eq!(reply.sender_mac, local_mac);
                assert_eq!(reply.sender_ip, local_ip);
                assert_eq!(
                    reply.target_mac,
                    MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
                );
                assert_eq!(reply.target_ip, Ipv4Addr::new(192, 168, 1, 2));
            }
            _ => panic!("Expected Reply action"),
        }

        // Should have learned sender
        let lookup = table.lookup(&Ipv4Addr::new(192, 168, 1, 2));
        assert!(lookup.is_some());
        assert_eq!(
            lookup.unwrap().0,
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn test_process_request_not_for_us() {
        let mut table = make_table();
        let local_ip = Ipv4Addr::new(192, 168, 1, 1);
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Request for 192.168.1.3, not us
        let request = ArpPacket::request(
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(192, 168, 1, 3),
        );

        let action = process_arp(&request, &mut table, local_ip, local_mac);

        // Should not reply
        assert_eq!(action, ArpAction::None);

        // Should NOT learn sender (not for us and sender not known)
        let lookup = table.lookup(&Ipv4Addr::new(192, 168, 1, 2));
        assert!(lookup.is_none());
    }

    #[test]
    fn test_process_reply() {
        let mut table = make_table();
        let local_ip = Ipv4Addr::new(192, 168, 1, 1);
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Mark as incomplete first (we sent a request)
        table.mark_incomplete(Ipv4Addr::new(192, 168, 1, 2));

        let reply = ArpPacket::reply(
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Ipv4Addr::new(192, 168, 1, 2),
            local_mac,
            local_ip,
        );

        let action = process_arp(&reply, &mut table, local_ip, local_mac);

        assert_eq!(action, ArpAction::TableUpdated);

        // Should have learned sender
        let lookup = table.lookup(&Ipv4Addr::new(192, 168, 1, 2));
        assert!(lookup.is_some());
        assert_eq!(
            lookup.unwrap().0,
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn test_process_gratuitous_arp() {
        let mut table = make_table();
        let local_ip = Ipv4Addr::new(192, 168, 1, 1);
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Existing entry for the sender
        table.insert(
            Ipv4Addr::new(192, 168, 1, 2),
            MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        );

        // GARP with new MAC
        let garp = ArpPacket::gratuitous(
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Ipv4Addr::new(192, 168, 1, 2),
        );

        let action = process_arp(&garp, &mut table, local_ip, local_mac);

        assert_eq!(action, ArpAction::TableUpdated);

        // Should have updated with new MAC
        let lookup = table.lookup(&Ipv4Addr::new(192, 168, 1, 2));
        assert!(lookup.is_some());
        assert_eq!(
            lookup.unwrap().0,
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn test_update_known_sender() {
        let mut table = make_table();
        let local_ip = Ipv4Addr::new(192, 168, 1, 1);
        let local_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Existing entry
        table.insert(
            Ipv4Addr::new(192, 168, 1, 2),
            MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        );

        // Request from known sender (not for us) with new MAC
        let request = ArpPacket::request(
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(192, 168, 1, 3),
        );

        let action = process_arp(&request, &mut table, local_ip, local_mac);

        // Not for us, no reply needed
        assert_eq!(action, ArpAction::None);

        // But should have updated known sender's MAC
        let lookup = table.lookup(&Ipv4Addr::new(192, 168, 1, 2));
        assert!(lookup.is_some());
        assert_eq!(
            lookup.unwrap().0,
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    // ArpPendingQueue tests

    #[test]
    fn test_pending_queue_enqueue_dequeue() {
        let mut queue = ArpPendingQueue::new(3, 60);
        let ip = Ipv4Addr::new(192, 168, 1, 1);

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
        let mut queue = ArpPendingQueue::new(3, 60);
        let ip1 = Ipv4Addr::new(192, 168, 1, 1);
        let ip2 = Ipv4Addr::new(192, 168, 1, 2);

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
        let mut queue = ArpPendingQueue::new(3, 60);
        let ip = Ipv4Addr::new(192, 168, 1, 1);

        let packets = queue.dequeue(&ip);
        assert!(packets.is_empty());
    }

    #[test]
    fn test_pending_queue_default() {
        let queue = ArpPendingQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }
}

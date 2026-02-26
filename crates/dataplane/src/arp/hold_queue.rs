//! ARP hold queue: buffers packets waiting for next-hop MAC resolution.
//!
//! When the ARP cache has no entry for a next-hop IP, the dataplane
//! enqueues the packet here instead of dropping it immediately.  Once
//! the ARP reply arrives and the cache is populated, the queued packets
//! are flushed (re-injected into TX).
//!
//! RFC-REF: RFC 1122 Section 2.3.2.2
//! "The link layer SHOULD save (rather than discard) at least one
//! (the latest) packet of each set of packets destined to the same
//! unresolved IP address, and transmit the saved packet when the
//! address has been resolved."
//!
//! We go beyond the RFC minimum by holding up to `per_ip_limit`
//! packets per destination (configurable, default 3).

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// A single packet held in the ARP hold queue.
#[derive(Debug, Clone)]
pub struct HeldPacket {
    /// The egress interface this packet should be forwarded on.
    pub egress_iface: String,
    /// The raw packet data (Ethernet frame with headers already rewritten
    /// except for the destination MAC which is unknown).
    pub data: Vec<u8>,
    /// The new TTL value to write into the IPv4 header (already decremented).
    pub new_ttl: Option<u8>,
    /// Timestamp when this packet was enqueued.
    pub enqueued_at: Instant,
}

/// Per-IP queue of held packets.
#[derive(Debug)]
struct PerIpQueue {
    /// FIFO queue of held packets.
    packets: VecDeque<HeldPacket>,
    /// The egress interface associated with this next-hop.
    egress_iface: String,
    /// When the first packet for this IP was enqueued (for timeout).
    first_enqueued: Instant,
}

/// Statistics from the hold queue (for observability).
#[derive(Debug, Clone, Copy, Default)]
pub struct HoldQueueStats {
    /// Current total number of packets held across all IPs.
    pub total_held: usize,
    /// Current number of distinct unresolved IPs.
    pub pending_ips: usize,
}

/// Result of an enqueue operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueResult {
    /// Packet was successfully enqueued.
    Enqueued,
    /// Packet was tail-dropped because the per-IP limit was reached.
    TailDropPerIp,
    /// Packet was tail-dropped because the global limit was reached.
    TailDropGlobal,
}

/// The ARP hold queue.
///
/// Indexed by next-hop IPv4 address.  Each IP has a bounded FIFO of
/// held packets.  There is also a global limit on the total number of
/// packets across all IPs to prevent memory exhaustion.
#[derive(Debug)]
pub struct HoldQueue {
    /// Per-IP queues keyed by next-hop IPv4 address.
    queues: HashMap<[u8; 4], PerIpQueue>,
    /// Maximum packets per unresolved IP.
    per_ip_limit: usize,
    /// Global maximum packets across all IPs.
    global_limit: usize,
    /// Current total number of held packets.
    total_held: usize,
}

impl HoldQueue {
    /// Create a new hold queue with the given limits.
    pub fn new(per_ip_limit: usize, global_limit: usize) -> Self {
        Self {
            queues: HashMap::new(),
            per_ip_limit,
            global_limit,
            total_held: 0,
        }
    }

    /// Enqueue a packet for an unresolved next-hop IP.
    ///
    /// Returns an [`EnqueueResult`] indicating whether the packet was
    /// accepted or tail-dropped.
    pub fn enqueue(
        &mut self,
        next_hop_ip: [u8; 4],
        egress_iface: String,
        data: Vec<u8>,
        new_ttl: Option<u8>,
    ) -> EnqueueResult {
        // Check global limit.
        if self.total_held >= self.global_limit {
            return EnqueueResult::TailDropGlobal;
        }

        let now = Instant::now();

        let queue = self.queues.entry(next_hop_ip).or_insert_with(|| PerIpQueue {
            packets: VecDeque::new(),
            egress_iface: egress_iface.clone(),
            first_enqueued: now,
        });

        // Check per-IP limit.
        if queue.packets.len() >= self.per_ip_limit {
            return EnqueueResult::TailDropPerIp;
        }

        queue.packets.push_back(HeldPacket {
            egress_iface,
            data,
            new_ttl,
            enqueued_at: now,
        });
        self.total_held += 1;

        EnqueueResult::Enqueued
    }

    /// Flush all packets held for a resolved next-hop IP.
    ///
    /// Returns the list of held packets so the caller can transmit them.
    /// Returns an empty `Vec` if no packets are held for this IP.
    pub fn flush(&mut self, next_hop_ip: &[u8; 4]) -> Vec<HeldPacket> {
        if let Some(queue) = self.queues.remove(next_hop_ip) {
            let count = queue.packets.len();
            self.total_held -= count;
            queue.packets.into_iter().collect()
        } else {
            Vec::new()
        }
    }

    /// Garbage-collect entries older than `timeout_sec`.
    ///
    /// Removes all packets for IPs whose first enqueue time exceeds the
    /// timeout.  Returns the total number of packets dropped.
    pub fn gc(&mut self, timeout_sec: u64) -> usize {
        let now = Instant::now();
        let mut dropped = 0;

        self.queues.retain(|_ip, queue| {
            if now.duration_since(queue.first_enqueued).as_secs() >= timeout_sec {
                dropped += queue.packets.len();
                false
            } else {
                true
            }
        });

        self.total_held -= dropped;
        dropped
    }

    /// Return current statistics about the hold queue.
    pub fn stats(&self) -> HoldQueueStats {
        HoldQueueStats {
            total_held: self.total_held,
            pending_ips: self.queues.len(),
        }
    }

    /// Return the list of next-hop IPs that currently have queued packets,
    /// along with their egress interface.
    ///
    /// Used by the run loop to decide which ARP requests to (re-)send.
    pub fn pending_ips(&self) -> Vec<([u8; 4], String)> {
        self.queues
            .iter()
            .map(|(ip, q)| (*ip, q.egress_iface.clone()))
            .collect()
    }

    /// Return `true` if there are any packets held.
    pub fn is_empty(&self) -> bool {
        self.total_held == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP_A: [u8; 4] = [10, 0, 0, 1];
    const IP_B: [u8; 4] = [10, 0, 0, 2];
    const IP_C: [u8; 4] = [10, 0, 0, 3];

    fn make_data(tag: u8) -> Vec<u8> {
        vec![tag; 64]
    }

    // ── Basic enqueue / flush ────────────────────────────────────────

    #[test]
    fn enqueue_and_flush() {
        let mut hq = HoldQueue::new(3, 1024);

        let r = hq.enqueue(IP_A, "wan0".into(), make_data(1), Some(63));
        assert_eq!(r, EnqueueResult::Enqueued);
        assert_eq!(hq.stats().total_held, 1);
        assert_eq!(hq.stats().pending_ips, 1);

        let r = hq.enqueue(IP_A, "wan0".into(), make_data(2), Some(63));
        assert_eq!(r, EnqueueResult::Enqueued);
        assert_eq!(hq.stats().total_held, 2);

        let flushed = hq.flush(&IP_A);
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0].data, make_data(1));
        assert_eq!(flushed[1].data, make_data(2));
        assert_eq!(hq.stats().total_held, 0);
        assert_eq!(hq.stats().pending_ips, 0);
    }

    #[test]
    fn flush_unknown_ip_returns_empty() {
        let mut hq = HoldQueue::new(3, 1024);
        let flushed = hq.flush(&IP_A);
        assert!(flushed.is_empty());
    }

    // ── Per-IP limit ─────────────────────────────────────────────────

    #[test]
    fn per_ip_limit_enforced() {
        let mut hq = HoldQueue::new(2, 1024);

        assert_eq!(
            hq.enqueue(IP_A, "wan0".into(), make_data(1), None),
            EnqueueResult::Enqueued
        );
        assert_eq!(
            hq.enqueue(IP_A, "wan0".into(), make_data(2), None),
            EnqueueResult::Enqueued
        );
        assert_eq!(
            hq.enqueue(IP_A, "wan0".into(), make_data(3), None),
            EnqueueResult::TailDropPerIp
        );
        assert_eq!(hq.stats().total_held, 2);
    }

    // ── Global limit ─────────────────────────────────────────────────

    #[test]
    fn global_limit_enforced() {
        let mut hq = HoldQueue::new(10, 3);

        hq.enqueue(IP_A, "wan0".into(), make_data(1), None);
        hq.enqueue(IP_B, "wan0".into(), make_data(2), None);
        hq.enqueue(IP_C, "wan0".into(), make_data(3), None);

        let r = hq.enqueue(IP_A, "wan0".into(), make_data(4), None);
        assert_eq!(r, EnqueueResult::TailDropGlobal);
        assert_eq!(hq.stats().total_held, 3);
    }

    // ── GC ───────────────────────────────────────────────────────────

    #[test]
    fn gc_removes_old_entries() {
        let mut hq = HoldQueue::new(3, 1024);

        hq.enqueue(IP_A, "wan0".into(), make_data(1), None);
        hq.enqueue(IP_A, "wan0".into(), make_data(2), None);

        // With timeout_sec=0 all entries should be GC'd immediately
        // (since first_enqueued is already in the past by >= 0 sec).
        std::thread::sleep(std::time::Duration::from_millis(10));
        let dropped = hq.gc(0);
        assert_eq!(dropped, 2);
        assert!(hq.is_empty());
    }

    #[test]
    fn gc_keeps_recent_entries() {
        let mut hq = HoldQueue::new(3, 1024);

        hq.enqueue(IP_A, "wan0".into(), make_data(1), None);

        let dropped = hq.gc(3600);
        assert_eq!(dropped, 0);
        assert_eq!(hq.stats().total_held, 1);
    }

    // ── pending_ips ──────────────────────────────────────────────────

    #[test]
    fn pending_ips_returns_all_queued() {
        let mut hq = HoldQueue::new(3, 1024);

        hq.enqueue(IP_A, "wan0".into(), make_data(1), None);
        hq.enqueue(IP_B, "lan0".into(), make_data(2), None);

        let pending = hq.pending_ips();
        assert_eq!(pending.len(), 2);

        let mut ips: Vec<[u8; 4]> = pending.iter().map(|(ip, _)| *ip).collect();
        ips.sort();
        assert_eq!(ips, vec![IP_A, IP_B]);
    }

    // ── is_empty ─────────────────────────────────────────────────────

    #[test]
    fn is_empty_initially() {
        let hq = HoldQueue::new(3, 1024);
        assert!(hq.is_empty());
    }

    #[test]
    fn is_empty_after_flush() {
        let mut hq = HoldQueue::new(3, 1024);
        hq.enqueue(IP_A, "wan0".into(), make_data(1), None);
        assert!(!hq.is_empty());
        hq.flush(&IP_A);
        assert!(hq.is_empty());
    }

    // ── Multiple IPs ─────────────────────────────────────────────────

    #[test]
    fn multiple_ips_independent() {
        let mut hq = HoldQueue::new(2, 1024);

        hq.enqueue(IP_A, "wan0".into(), make_data(1), None);
        hq.enqueue(IP_A, "wan0".into(), make_data(2), None);
        hq.enqueue(IP_B, "lan0".into(), make_data(3), None);

        assert_eq!(hq.stats().total_held, 3);
        assert_eq!(hq.stats().pending_ips, 2);

        let flushed_a = hq.flush(&IP_A);
        assert_eq!(flushed_a.len(), 2);
        assert_eq!(hq.stats().total_held, 1);
        assert_eq!(hq.stats().pending_ips, 1);

        let flushed_b = hq.flush(&IP_B);
        assert_eq!(flushed_b.len(), 1);
        assert!(hq.is_empty());
    }

    // ── HeldPacket fields ────────────────────────────────────────────

    #[test]
    fn held_packet_preserves_fields() {
        let mut hq = HoldQueue::new(3, 1024);
        hq.enqueue(IP_A, "wan0".into(), vec![0xAA, 0xBB], Some(62));

        let flushed = hq.flush(&IP_A);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].egress_iface, "wan0");
        assert_eq!(flushed[0].data, vec![0xAA, 0xBB]);
        assert_eq!(flushed[0].new_ttl, Some(62));
    }
}

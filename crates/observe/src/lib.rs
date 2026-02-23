//! Observability infrastructure for the ruster dataplane.
//!
//! Provides thread-safe atomic counters for tracking packet processing
//! statistics (received, transmitted, dropped) as well as the original
//! non-atomic [`Counters`] for single-threaded contexts.

use std::sync::atomic::{AtomicU64, Ordering};

/// Non-atomic packet counters (for single-threaded contexts).
#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub rx: u64,
    pub tx: u64,
    pub drop: u64,
}

impl Counters {
    pub fn inc_drop(&mut self) {
        self.drop += 1;
    }
}

/// Thread-safe atomic packet counters for the forwarding engine.
///
/// Uses `Ordering::Relaxed` because exact ordering between different
/// counters is not required — each counter is independent.
#[derive(Debug, Default)]
pub struct AtomicCounters {
    /// Total packets received.
    pub rx_packets: AtomicU64,
    /// Total packets transmitted (forwarded).
    pub tx_packets: AtomicU64,
    /// Packets dropped due to no matching route.
    pub dropped_no_route: AtomicU64,
    /// Packets dropped due to TTL expiration.
    pub dropped_ttl_expired: AtomicU64,
}

impl AtomicCounters {
    /// Create a new set of zeroed counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the received packet counter.
    pub fn inc_rx_packets(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the transmitted packet counter.
    pub fn inc_tx_packets(&self) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the no-route drop counter.
    pub fn inc_dropped_no_route(&self) {
        self.dropped_no_route.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the TTL-expired drop counter.
    pub fn inc_dropped_ttl_expired(&self) {
        self.dropped_ttl_expired.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the received packet counter.
    pub fn get_rx_packets(&self) -> u64 {
        self.rx_packets.load(Ordering::Relaxed)
    }

    /// Read the transmitted packet counter.
    pub fn get_tx_packets(&self) -> u64 {
        self.tx_packets.load(Ordering::Relaxed)
    }

    /// Read the no-route drop counter.
    pub fn get_dropped_no_route(&self) -> u64 {
        self.dropped_no_route.load(Ordering::Relaxed)
    }

    /// Read the TTL-expired drop counter.
    pub fn get_dropped_ttl_expired(&self) -> u64 {
        self.dropped_ttl_expired.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_basic() {
        let mut c = Counters::default();
        assert_eq!(c.drop, 0);
        c.inc_drop();
        assert_eq!(c.drop, 1);
    }

    #[test]
    fn atomic_counters_default_zero() {
        let c = AtomicCounters::new();
        assert_eq!(c.get_rx_packets(), 0);
        assert_eq!(c.get_tx_packets(), 0);
        assert_eq!(c.get_dropped_no_route(), 0);
        assert_eq!(c.get_dropped_ttl_expired(), 0);
    }

    #[test]
    fn atomic_counters_increment() {
        let c = AtomicCounters::new();

        c.inc_rx_packets();
        c.inc_rx_packets();
        c.inc_tx_packets();
        c.inc_dropped_no_route();
        c.inc_dropped_ttl_expired();
        c.inc_dropped_ttl_expired();
        c.inc_dropped_ttl_expired();

        assert_eq!(c.get_rx_packets(), 2);
        assert_eq!(c.get_tx_packets(), 1);
        assert_eq!(c.get_dropped_no_route(), 1);
        assert_eq!(c.get_dropped_ttl_expired(), 3);
    }

    #[test]
    fn atomic_counters_multiple_increments() {
        let c = AtomicCounters::new();

        for _ in 0..100 {
            c.inc_rx_packets();
        }
        assert_eq!(c.get_rx_packets(), 100);
    }
}

//! Metrics collection for packet statistics.
//!
//! Provides thread-safe counters for tracking packet processing metrics
//! at both the global and per-interface level.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Atomic counter for thread-safe increment operations.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Creates a new counter initialized to zero.
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Increments the counter by 1.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds a value to the counter.
    pub fn add(&self, val: u64) {
        self.0.fetch_add(val, Ordering::Relaxed);
    }

    /// Gets the current value of the counter.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Per-interface statistics.
#[derive(Debug, Default)]
pub struct InterfaceStats {
    /// Number of packets received.
    pub rx_packets: Counter,
    /// Number of bytes received.
    pub rx_bytes: Counter,
    /// Number of packets transmitted.
    pub tx_packets: Counter,
    /// Number of bytes transmitted.
    pub tx_bytes: Counter,
    /// Number of receive drops.
    pub rx_drops: Counter,
    /// Number of receive errors.
    pub rx_errors: Counter,
    /// Number of transmit errors.
    pub tx_errors: Counter,
}

impl InterfaceStats {
    /// Creates new interface statistics initialized to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a received packet.
    pub fn record_rx(&self, bytes: usize) {
        self.rx_packets.inc();
        self.rx_bytes.add(bytes as u64);
    }

    /// Records a transmitted packet.
    pub fn record_tx(&self, bytes: usize) {
        self.tx_packets.inc();
        self.tx_bytes.add(bytes as u64);
    }

    /// Records a receive error.
    pub fn record_rx_error(&self) {
        self.rx_errors.inc();
    }

    /// Records a transmit error.
    pub fn record_tx_error(&self) {
        self.tx_errors.inc();
    }

    /// Records a receive drop.
    pub fn record_rx_drop(&self) {
        self.rx_drops.inc();
    }
}

/// Global metrics registry for the router.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    /// Per-interface statistics.
    interfaces: RwLock<HashMap<String, InterfaceStats>>,

    // ARP metrics
    /// Number of ARP requests sent.
    pub arp_requests_sent: Counter,
    /// Number of ARP replies sent.
    pub arp_replies_sent: Counter,

    // Forwarding metrics
    /// Number of packets successfully forwarded.
    pub packets_forwarded: Counter,
    /// Number of packets dropped (no route, TTL expired, etc.).
    pub packets_dropped: Counter,

    // ICMP metrics
    /// Number of ICMP echo replies sent.
    pub icmp_echo_replies: Counter,

    // Filtering metrics
    /// Number of packets accepted by filter.
    pub filter_accepted: Counter,
    /// Number of packets dropped by filter.
    pub filter_dropped: Counter,
    /// Number of packets rejected by filter.
    pub filter_rejected: Counter,

    // Table size gauges (using AtomicU64 for gauges)
    /// Current number of ARP table entries.
    pub arp_table_size: AtomicU64,
    /// Current number of FDB entries.
    pub fdb_table_size: AtomicU64,
    /// Current number of routing table entries.
    pub route_count: AtomicU64,
}

impl MetricsRegistry {
    /// Creates a new metrics registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an interface for statistics tracking.
    pub fn register_interface(&self, name: &str) {
        let mut interfaces = self.interfaces.write().unwrap();
        interfaces.entry(name.to_string()).or_default();
    }

    /// Records a received packet on an interface.
    pub fn record_rx(&self, interface: &str, bytes: usize) {
        if let Some(stats) = self.interfaces.read().unwrap().get(interface) {
            stats.record_rx(bytes);
        }
    }

    /// Records a transmitted packet on an interface.
    pub fn record_tx(&self, interface: &str, bytes: usize) {
        if let Some(stats) = self.interfaces.read().unwrap().get(interface) {
            stats.record_tx(bytes);
        }
    }

    /// Records a receive error on an interface.
    pub fn record_rx_error(&self, interface: &str) {
        if let Some(stats) = self.interfaces.read().unwrap().get(interface) {
            stats.record_rx_error();
        }
    }

    /// Records a transmit error on an interface.
    pub fn record_tx_error(&self, interface: &str) {
        if let Some(stats) = self.interfaces.read().unwrap().get(interface) {
            stats.record_tx_error();
        }
    }

    /// Updates the ARP table size gauge.
    pub fn set_arp_table_size(&self, size: usize) {
        self.arp_table_size.store(size as u64, Ordering::Relaxed);
    }

    /// Updates the FDB table size gauge.
    pub fn set_fdb_table_size(&self, size: usize) {
        self.fdb_table_size.store(size as u64, Ordering::Relaxed);
    }

    /// Updates the route count gauge.
    pub fn set_route_count(&self, count: usize) {
        self.route_count.store(count as u64, Ordering::Relaxed);
    }

    /// Exports all metrics as key-value pairs.
    ///
    /// This format is designed to be easily convertible to Prometheus format
    /// in the future.
    pub fn export(&self) -> Vec<(String, u64)> {
        // Global counters and gauges
        let mut result = vec![
            ("arp_requests_sent".into(), self.arp_requests_sent.get()),
            ("arp_replies_sent".into(), self.arp_replies_sent.get()),
            ("packets_forwarded".into(), self.packets_forwarded.get()),
            ("packets_dropped".into(), self.packets_dropped.get()),
            ("icmp_echo_replies".into(), self.icmp_echo_replies.get()),
            ("filter_accepted".into(), self.filter_accepted.get()),
            ("filter_dropped".into(), self.filter_dropped.get()),
            ("filter_rejected".into(), self.filter_rejected.get()),
            (
                "arp_table_size".into(),
                self.arp_table_size.load(Ordering::Relaxed),
            ),
            (
                "fdb_table_size".into(),
                self.fdb_table_size.load(Ordering::Relaxed),
            ),
            (
                "route_count".into(),
                self.route_count.load(Ordering::Relaxed),
            ),
        ];

        // Per-interface metrics
        let interfaces = self.interfaces.read().unwrap();
        for (name, stats) in interfaces.iter() {
            result.extend([
                (format!("{}_rx_packets", name), stats.rx_packets.get()),
                (format!("{}_rx_bytes", name), stats.rx_bytes.get()),
                (format!("{}_tx_packets", name), stats.tx_packets.get()),
                (format!("{}_tx_bytes", name), stats.tx_bytes.get()),
                (format!("{}_rx_drops", name), stats.rx_drops.get()),
                (format!("{}_rx_errors", name), stats.rx_errors.get()),
                (format!("{}_tx_errors", name), stats.tx_errors.get()),
            ]);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_basic() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.add(10);
        assert_eq!(counter.get(), 11);
    }

    #[test]
    fn test_interface_stats() {
        let stats = InterfaceStats::new();

        stats.record_rx(100);
        stats.record_rx(200);
        stats.record_tx(150);

        assert_eq!(stats.rx_packets.get(), 2);
        assert_eq!(stats.rx_bytes.get(), 300);
        assert_eq!(stats.tx_packets.get(), 1);
        assert_eq!(stats.tx_bytes.get(), 150);
    }

    #[test]
    fn test_metrics_registry() {
        let registry = MetricsRegistry::new();

        registry.register_interface("eth0");
        registry.register_interface("eth1");

        registry.record_rx("eth0", 100);
        registry.record_tx("eth0", 200);
        registry.record_rx("eth1", 50);

        registry.packets_forwarded.inc();
        registry.arp_requests_sent.add(5);

        let metrics = registry.export();

        // Check global metrics
        assert!(metrics.contains(&("packets_forwarded".into(), 1)));
        assert!(metrics.contains(&("arp_requests_sent".into(), 5)));

        // Check interface metrics
        assert!(metrics.contains(&("eth0_rx_packets".into(), 1)));
        assert!(metrics.contains(&("eth0_rx_bytes".into(), 100)));
        assert!(metrics.contains(&("eth1_rx_packets".into(), 1)));
    }
}

//! Observability infrastructure for the ruster dataplane.
//!
//! Provides:
//! - Thread-safe atomic counters for tracking packet processing
//!   statistics (received, transmitted, dropped) as well as the original
//!   non-atomic [`Counters`] for single-threaded contexts.
//! - Per-interface RX/TX/drop counters ([`InterfaceCounters`]).
//! - Per-stage drop reason counters ([`DropCounters`]).
//! - An [`Observer`] hub that aggregates all counters and produces
//!   immutable snapshots ([`ObserverSnapshot`]) for display.
//! - Table occupancy reporting ([`TableStats`], [`TableReport`]).

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Legacy types (backward-compatible) ─────────────────────────────────

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

// ── Drop reason enum (cross-stage) ────────────────────────────────────

/// Reason a packet was dropped, spanning all processing stages.
///
/// Used to dispatch to the correct counter in [`DropCounters`] via
/// [`Observer::inc_drop_reason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// L2: no bridge domain owns the ingress interface.
    L2NoBridgeDomain,
    /// L3: no route matched the destination address.
    L3NoRoute,
    /// L3: TTL expired (TTL <= 1).
    L3TtlExpired,
    /// L3: packet is not IPv4.
    L3NotIpv4,
    /// NAT: session table is full.
    NatTableFull,
    /// Firewall: packet dropped by firewall rule or default policy.
    FirewallDrop,
    /// ARP: next-hop MAC address could not be resolved.
    ArpUnresolved,
    /// Packet could not be parsed.
    ParseError,
    /// Conntrack: session table is full.
    ConntrackTableFull,
    /// SRv6: packet dropped during SRv6 processing.
    Srv6Drop,
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropReason::L2NoBridgeDomain => write!(f, "L2/no-bridge-domain"),
            DropReason::L3NoRoute => write!(f, "L3/no-route"),
            DropReason::L3TtlExpired => write!(f, "L3/ttl-expired"),
            DropReason::L3NotIpv4 => write!(f, "L3/not-ipv4"),
            DropReason::NatTableFull => write!(f, "NAT/table-full"),
            DropReason::FirewallDrop => write!(f, "FW/drop"),
            DropReason::ArpUnresolved => write!(f, "ARP/unresolved"),
            DropReason::ParseError => write!(f, "parse-error"),
            DropReason::ConntrackTableFull => write!(f, "conntrack/table-full"),
            DropReason::Srv6Drop => write!(f, "SRv6/drop"),
        }
    }
}

// ── Per-interface counters ─────────────────────────────────────────────

/// Per-interface packet and byte counters.
///
/// All fields are atomic for thread-safe concurrent updates from the
/// dataplane fast path.
#[derive(Debug, Default)]
pub struct InterfaceCounters {
    /// Total packets received on this interface.
    pub rx_packets: AtomicU64,
    /// Total bytes received on this interface.
    pub rx_bytes: AtomicU64,
    /// Total packets transmitted on this interface.
    pub tx_packets: AtomicU64,
    /// Total bytes transmitted on this interface.
    pub tx_bytes: AtomicU64,
    /// Packets dropped on receive (e.g. parse error).
    pub rx_drops: AtomicU64,
    /// Packets dropped on transmit (e.g. queue full).
    pub tx_drops: AtomicU64,
}

// ── Per-stage drop reason counters ────────────────────────────────────

/// Global per-stage drop reason counters.
///
/// Each field corresponds to a specific processing stage and drop
/// cause. Updated via [`Observer::inc_drop_reason`].
#[derive(Debug, Default)]
pub struct DropCounters {
    /// L2: packet arrived on an interface not in any bridge domain.
    pub l2_no_bridge_domain: AtomicU64,
    /// L3: no route matched the destination address.
    pub l3_no_route: AtomicU64,
    /// L3: TTL expired (TTL <= 1), packet cannot be forwarded.
    pub l3_ttl_expired: AtomicU64,
    /// L3: packet is not IPv4 (e.g. ARP passed to L3 engine).
    pub l3_not_ipv4: AtomicU64,
    /// NAT: session table is full, new session could not be created.
    pub nat_table_full: AtomicU64,
    /// Firewall: packet dropped by firewall rule or default policy.
    pub fw_drop: AtomicU64,
    /// ARP: next-hop address could not be resolved.
    pub arp_unresolved: AtomicU64,
    /// Packet could not be parsed.
    pub parse_error: AtomicU64,
    /// Conntrack: session table is full.
    pub conntrack_table_full: AtomicU64,
    /// SRv6: packet dropped during SRv6 processing.
    pub srv6_drop: AtomicU64,
}

// ── ARP hold queue counters ────────────────────────────────────────────

/// Counters for the ARP hold queue (packets waiting for ARP resolution).
///
/// Tracks enqueue, flush (successful resolution), timeout/GC drops,
/// and tail-drops due to queue limits.
#[derive(Debug, Default)]
pub struct ArpHoldQueueCounters {
    /// Total packets enqueued into the ARP hold queue.
    pub enqueued: AtomicU64,
    /// Total packets flushed (forwarded) after ARP resolution.
    pub flushed: AtomicU64,
    /// Total packets dropped by the hold queue GC (timeout / stale).
    pub gc_dropped: AtomicU64,
    /// Total packets tail-dropped because per-IP or global limit was reached.
    pub tail_dropped: AtomicU64,
}

// ── Observer ──────────────────────────────────────────────────────────

/// Conntrack-specific counters.
///
/// Tracks session lifecycle events for the connection tracking engine.
#[derive(Debug, Default)]
pub struct ConntrackCounters {
    /// Sessions created (new flow detected).
    pub conntrack_new: AtomicU64,
    /// Sessions transitioned to established state.
    pub conntrack_established: AtomicU64,
    /// Sessions removed by garbage collection (timeout).
    pub conntrack_expired: AtomicU64,
    /// Session creation failures due to table full.
    pub conntrack_table_full: AtomicU64,
}

/// The main observability hub.
///
/// Aggregates per-interface counters, global drop reason counters, and
/// forwarding statistics. All counters use atomic operations so the
/// observer can be shared across threads (e.g. via `Arc<Observer>`).
#[derive(Debug)]
pub struct Observer {
    /// Per-interface counters keyed by interface name.
    pub interfaces: HashMap<String, InterfaceCounters>,
    /// Global drop reason counters.
    pub drops: DropCounters,
    /// Conntrack lifecycle counters.
    pub conntrack: ConntrackCounters,
    /// Total packets forwarded (L3 forward decision completed).
    pub forwarded: AtomicU64,
    /// Total packets delivered locally (destination is one of our IPs).
    pub local_delivery: AtomicU64,
    /// ARP hold queue counters.
    pub arp_hold_queue: ArpHoldQueueCounters,
}

impl Observer {
    /// Create a new observer with per-interface counter maps for the
    /// given interface names.
    ///
    /// All counters are initialised to zero.
    pub fn new(interface_names: &[String]) -> Self {
        let interfaces = interface_names
            .iter()
            .map(|name| (name.clone(), InterfaceCounters::default()))
            .collect();

        Self {
            interfaces,
            drops: DropCounters::default(),
            conntrack: ConntrackCounters::default(),
            forwarded: AtomicU64::new(0),
            local_delivery: AtomicU64::new(0),
            arp_hold_queue: ArpHoldQueueCounters::default(),
        }
    }

    /// Increment the RX packet and byte counters for the named interface.
    ///
    /// If the interface name is not found, the call is silently ignored.
    pub fn inc_rx(&self, ifname: &str, bytes: u64) {
        if let Some(counters) = self.interfaces.get(ifname) {
            counters.rx_packets.fetch_add(1, Ordering::Relaxed);
            counters.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Increment the TX packet and byte counters for the named interface.
    ///
    /// If the interface name is not found, the call is silently ignored.
    pub fn inc_tx(&self, ifname: &str, bytes: u64) {
        if let Some(counters) = self.interfaces.get(ifname) {
            counters.tx_packets.fetch_add(1, Ordering::Relaxed);
            counters.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Increment the RX drop counter for the named interface.
    ///
    /// If the interface name is not found, the call is silently ignored.
    pub fn inc_rx_drop(&self, ifname: &str) {
        if let Some(counters) = self.interfaces.get(ifname) {
            counters.rx_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment the TX drop counter for the named interface.
    ///
    /// If the interface name is not found, the call is silently ignored.
    pub fn inc_tx_drop(&self, ifname: &str) {
        if let Some(counters) = self.interfaces.get(ifname) {
            counters.tx_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment the forwarded packet counter.
    pub fn inc_forwarded(&self) {
        self.forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the local delivery counter.
    pub fn inc_local_delivery(&self) {
        self.local_delivery.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the ARP hold queue enqueued counter.
    pub fn inc_arp_hold_enqueued(&self) {
        self.arp_hold_queue.enqueued.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the ARP hold queue flushed counter by `n`.
    pub fn inc_arp_hold_flushed(&self, n: u64) {
        self.arp_hold_queue.flushed.fetch_add(n, Ordering::Relaxed);
    }

    /// Increment the ARP hold queue GC-dropped counter by `n`.
    pub fn inc_arp_hold_gc_dropped(&self, n: u64) {
        self.arp_hold_queue
            .gc_dropped
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Increment the ARP hold queue tail-dropped counter.
    pub fn inc_arp_hold_tail_dropped(&self) {
        self.arp_hold_queue
            .tail_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the conntrack new session counter.
    pub fn inc_conntrack_new(&self) {
        self.conntrack.conntrack_new.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the conntrack established session counter.
    pub fn inc_conntrack_established(&self) {
        self.conntrack
            .conntrack_established
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the conntrack expired session counter by the given amount.
    pub fn add_conntrack_expired(&self, count: u64) {
        self.conntrack
            .conntrack_expired
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increment the conntrack table full counter.
    pub fn inc_conntrack_table_full(&self) {
        self.conntrack
            .conntrack_table_full
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the appropriate drop reason counter for the given reason.
    ///
    /// Dispatches to the correct field in [`DropCounters`].
    pub fn inc_drop_reason(&self, reason: DropReason) {
        let counter = match reason {
            DropReason::L2NoBridgeDomain => &self.drops.l2_no_bridge_domain,
            DropReason::L3NoRoute => &self.drops.l3_no_route,
            DropReason::L3TtlExpired => &self.drops.l3_ttl_expired,
            DropReason::L3NotIpv4 => &self.drops.l3_not_ipv4,
            DropReason::NatTableFull => &self.drops.nat_table_full,
            DropReason::FirewallDrop => &self.drops.fw_drop,
            DropReason::ArpUnresolved => &self.drops.arp_unresolved,
            DropReason::ParseError => &self.drops.parse_error,
            DropReason::ConntrackTableFull => &self.drops.conntrack_table_full,
            DropReason::Srv6Drop => &self.drops.srv6_drop,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Take an immutable snapshot of all counters.
    ///
    /// The snapshot copies all atomic values at the time of the call.
    /// The interface list is sorted by name for deterministic display.
    pub fn snapshot(&self) -> ObserverSnapshot {
        let mut interfaces: Vec<InterfaceSnapshot> = self
            .interfaces
            .iter()
            .map(|(name, c)| InterfaceSnapshot {
                name: name.clone(),
                rx_packets: c.rx_packets.load(Ordering::Relaxed),
                rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
                tx_packets: c.tx_packets.load(Ordering::Relaxed),
                tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
                rx_drops: c.rx_drops.load(Ordering::Relaxed),
                tx_drops: c.tx_drops.load(Ordering::Relaxed),
            })
            .collect();

        // Sort by interface name for deterministic output.
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));

        ObserverSnapshot {
            interfaces,
            drops: DropSnapshot {
                l2_no_bridge_domain: self.drops.l2_no_bridge_domain.load(Ordering::Relaxed),
                l3_no_route: self.drops.l3_no_route.load(Ordering::Relaxed),
                l3_ttl_expired: self.drops.l3_ttl_expired.load(Ordering::Relaxed),
                l3_not_ipv4: self.drops.l3_not_ipv4.load(Ordering::Relaxed),
                nat_table_full: self.drops.nat_table_full.load(Ordering::Relaxed),
                fw_drop: self.drops.fw_drop.load(Ordering::Relaxed),
                arp_unresolved: self.drops.arp_unresolved.load(Ordering::Relaxed),
                parse_error: self.drops.parse_error.load(Ordering::Relaxed),
                conntrack_table_full: self.drops.conntrack_table_full.load(Ordering::Relaxed),
                srv6_drop: self.drops.srv6_drop.load(Ordering::Relaxed),
            },
            conntrack: ConntrackSnapshot {
                conntrack_new: self.conntrack.conntrack_new.load(Ordering::Relaxed),
                conntrack_established: self.conntrack.conntrack_established.load(Ordering::Relaxed),
                conntrack_expired: self.conntrack.conntrack_expired.load(Ordering::Relaxed),
                conntrack_table_full: self.conntrack.conntrack_table_full.load(Ordering::Relaxed),
            },
            forwarded: self.forwarded.load(Ordering::Relaxed),
            local_delivery: self.local_delivery.load(Ordering::Relaxed),
            arp_hold_queue: ArpHoldQueueSnapshot {
                enqueued: self.arp_hold_queue.enqueued.load(Ordering::Relaxed),
                flushed: self.arp_hold_queue.flushed.load(Ordering::Relaxed),
                gc_dropped: self.arp_hold_queue.gc_dropped.load(Ordering::Relaxed),
                tail_dropped: self.arp_hold_queue.tail_dropped.load(Ordering::Relaxed),
            },
        }
    }
}

// ── Snapshot types (non-atomic, for display) ──────────────────────────

/// Conntrack counter snapshot.
#[derive(Debug, Clone)]
pub struct ConntrackSnapshot {
    /// New sessions created.
    pub conntrack_new: u64,
    /// Sessions transitioned to established.
    pub conntrack_established: u64,
    /// Sessions expired by GC.
    pub conntrack_expired: u64,
    /// Session creation failures (table full).
    pub conntrack_table_full: u64,
}

/// Immutable snapshot of all observer counters.
///
/// Produced by [`Observer::snapshot`]. Implements [`fmt::Display`] for
/// text-based "show stats" output.
#[derive(Debug, Clone)]
pub struct ObserverSnapshot {
    /// Per-interface counter snapshots (sorted by name).
    pub interfaces: Vec<InterfaceSnapshot>,
    /// Drop reason counter snapshot.
    pub drops: DropSnapshot,
    /// Conntrack counter snapshot.
    pub conntrack: ConntrackSnapshot,
    /// Total forwarded packets.
    pub forwarded: u64,
    /// Total locally delivered packets.
    pub local_delivery: u64,
    /// ARP hold queue counter snapshot.
    pub arp_hold_queue: ArpHoldQueueSnapshot,
}

/// ARP hold queue counter snapshot.
#[derive(Debug, Clone)]
pub struct ArpHoldQueueSnapshot {
    /// Total packets enqueued.
    pub enqueued: u64,
    /// Total packets flushed (forwarded after ARP resolution).
    pub flushed: u64,
    /// Total packets GC-dropped (timeout/stale).
    pub gc_dropped: u64,
    /// Total packets tail-dropped (queue limit reached).
    pub tail_dropped: u64,
}

/// Per-interface counter snapshot.
#[derive(Debug, Clone)]
pub struct InterfaceSnapshot {
    /// Interface name.
    pub name: String,
    /// Total packets received.
    pub rx_packets: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Total packets transmitted.
    pub tx_packets: u64,
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Receive-side drops.
    pub rx_drops: u64,
    /// Transmit-side drops.
    pub tx_drops: u64,
}

/// Drop reason counter snapshot.
#[derive(Debug, Clone)]
pub struct DropSnapshot {
    /// L2: no bridge domain.
    pub l2_no_bridge_domain: u64,
    /// L3: no route.
    pub l3_no_route: u64,
    /// L3: TTL expired.
    pub l3_ttl_expired: u64,
    /// L3: not IPv4.
    pub l3_not_ipv4: u64,
    /// NAT: table full.
    pub nat_table_full: u64,
    /// Firewall: drop.
    pub fw_drop: u64,
    /// ARP: unresolved.
    pub arp_unresolved: u64,
    /// Parse error.
    pub parse_error: u64,
    /// Conntrack: table full.
    pub conntrack_table_full: u64,
    /// SRv6: drop.
    pub srv6_drop: u64,
}

impl fmt::Display for ObserverSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== ruster stats ===")?;
        writeln!(
            f,
            "Forwarded: {}  Local: {}",
            self.forwarded, self.local_delivery
        )?;
        writeln!(f)?;
        writeln!(f, "--- Interfaces ---")?;
        for iface in &self.interfaces {
            writeln!(
                f,
                "  {}: RX {} pkts ({} B)  TX {} pkts ({} B)  RX-drop {}  TX-drop {}",
                iface.name,
                iface.rx_packets,
                iface.rx_bytes,
                iface.tx_packets,
                iface.tx_bytes,
                iface.rx_drops,
                iface.tx_drops,
            )?;
        }
        writeln!(f)?;
        writeln!(f, "--- Drop Reasons ---")?;
        writeln!(
            f,
            "  L2/no-bridge-domain: {}",
            self.drops.l2_no_bridge_domain
        )?;
        writeln!(f, "  L3/no-route: {}", self.drops.l3_no_route)?;
        writeln!(f, "  L3/ttl-expired: {}", self.drops.l3_ttl_expired)?;
        writeln!(f, "  L3/not-ipv4: {}", self.drops.l3_not_ipv4)?;
        writeln!(f, "  NAT/table-full: {}", self.drops.nat_table_full)?;
        writeln!(f, "  FW/drop: {}", self.drops.fw_drop)?;
        writeln!(f, "  ARP/unresolved: {}", self.drops.arp_unresolved)?;
        writeln!(f, "  parse-error: {}", self.drops.parse_error)?;
        writeln!(
            f,
            "  conntrack/table-full: {}",
            self.drops.conntrack_table_full
        )?;
        writeln!(f)?;
        writeln!(f, "--- ARP Hold Queue ---")?;
        writeln!(f, "  enqueued: {}", self.arp_hold_queue.enqueued)?;
        writeln!(f, "  flushed: {}", self.arp_hold_queue.flushed)?;
        writeln!(f, "  gc-dropped: {}", self.arp_hold_queue.gc_dropped)?;
        writeln!(f, "  tail-dropped: {}", self.arp_hold_queue.tail_dropped)?;
        writeln!(f)?;
        writeln!(f, "--- Conntrack ---")?;
        writeln!(f, "  new: {}", self.conntrack.conntrack_new)?;
        writeln!(f, "  established: {}", self.conntrack.conntrack_established)?;
        writeln!(f, "  expired: {}", self.conntrack.conntrack_expired)?;
        write!(f, "  table-full: {}", self.conntrack.conntrack_table_full)?;
        Ok(())
    }
}

// ── Table stats / report ──────────────────────────────────────────────

/// Snapshot of a single table's occupancy.
///
/// The caller (e.g. the main crate) constructs these by querying the
/// dataplane engines' table sizes and passing them to [`TableReport`].
#[derive(Debug, Clone)]
pub struct TableStats {
    /// Human-readable table name (e.g. "FDB/br0", "ARP/eth0", "Conntrack").
    pub name: String,
    /// Current number of entries.
    pub current: usize,
    /// Maximum capacity.
    pub max: usize,
}

/// Report of all table occupancies.
///
/// Implements [`fmt::Display`] for text-based "show tables" output.
#[derive(Debug, Clone)]
pub struct TableReport {
    /// Table occupancy entries.
    pub tables: Vec<TableStats>,
}

impl fmt::Display for TableReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Table Usage ===")?;
        for table in &self.tables {
            let pct = if table.max > 0 {
                (table.current * 100) / table.max
            } else {
                0
            };
            writeln!(
                f,
                "  {}: {}/{} ({}%)",
                table.name, table.current, table.max, pct
            )?;
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Legacy tests (preserved) ──────────────────────────────────────

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

    // ── Observer construction ─────────────────────────────────────────

    #[test]
    fn observer_new_creates_per_interface_counters() {
        let names = vec!["eth0".to_string(), "eth1".to_string(), "wan0".to_string()];
        let obs = Observer::new(&names);

        assert_eq!(obs.interfaces.len(), 3);
        assert!(obs.interfaces.contains_key("eth0"));
        assert!(obs.interfaces.contains_key("eth1"));
        assert!(obs.interfaces.contains_key("wan0"));

        // All counters should start at zero.
        let eth0 = obs.interfaces.get("eth0").unwrap();
        assert_eq!(eth0.rx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(eth0.tx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(eth0.rx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(eth0.tx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(eth0.rx_drops.load(Ordering::Relaxed), 0);
        assert_eq!(eth0.tx_drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn observer_new_empty_interfaces() {
        let obs = Observer::new(&[]);
        assert!(obs.interfaces.is_empty());
        assert_eq!(obs.forwarded.load(Ordering::Relaxed), 0);
        assert_eq!(obs.local_delivery.load(Ordering::Relaxed), 0);
    }

    // ── inc_rx / inc_tx ───────────────────────────────────────────────

    #[test]
    fn observer_inc_rx_increments_correctly() {
        let obs = Observer::new(&["eth0".to_string()]);

        obs.inc_rx("eth0", 1500);
        obs.inc_rx("eth0", 64);

        let eth0 = obs.interfaces.get("eth0").unwrap();
        assert_eq!(eth0.rx_packets.load(Ordering::Relaxed), 2);
        assert_eq!(eth0.rx_bytes.load(Ordering::Relaxed), 1564);
    }

    #[test]
    fn observer_inc_tx_increments_correctly() {
        let obs = Observer::new(&["eth0".to_string()]);

        obs.inc_tx("eth0", 1000);
        obs.inc_tx("eth0", 500);
        obs.inc_tx("eth0", 250);

        let eth0 = obs.interfaces.get("eth0").unwrap();
        assert_eq!(eth0.tx_packets.load(Ordering::Relaxed), 3);
        assert_eq!(eth0.tx_bytes.load(Ordering::Relaxed), 1750);
    }

    #[test]
    fn observer_inc_rx_unknown_interface_ignored() {
        let obs = Observer::new(&["eth0".to_string()]);

        // Should not panic or modify anything.
        obs.inc_rx("nonexistent", 1500);

        let eth0 = obs.interfaces.get("eth0").unwrap();
        assert_eq!(eth0.rx_packets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn observer_inc_tx_unknown_interface_ignored() {
        let obs = Observer::new(&["eth0".to_string()]);
        obs.inc_tx("nonexistent", 1500);

        let eth0 = obs.interfaces.get("eth0").unwrap();
        assert_eq!(eth0.tx_packets.load(Ordering::Relaxed), 0);
    }

    // ── inc_rx_drop / inc_tx_drop ─────────────────────────────────────

    #[test]
    fn observer_inc_rx_drop() {
        let obs = Observer::new(&["eth0".to_string()]);

        obs.inc_rx_drop("eth0");
        obs.inc_rx_drop("eth0");

        let eth0 = obs.interfaces.get("eth0").unwrap();
        assert_eq!(eth0.rx_drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn observer_inc_tx_drop() {
        let obs = Observer::new(&["wan0".to_string()]);

        obs.inc_tx_drop("wan0");

        let wan0 = obs.interfaces.get("wan0").unwrap();
        assert_eq!(wan0.tx_drops.load(Ordering::Relaxed), 1);
    }

    // ── inc_forwarded / inc_local_delivery ────────────────────────────

    #[test]
    fn observer_inc_forwarded_and_local_delivery() {
        let obs = Observer::new(&[]);

        obs.inc_forwarded();
        obs.inc_forwarded();
        obs.inc_forwarded();
        obs.inc_local_delivery();

        assert_eq!(obs.forwarded.load(Ordering::Relaxed), 3);
        assert_eq!(obs.local_delivery.load(Ordering::Relaxed), 1);
    }

    // ── inc_drop_reason dispatching ───────────────────────────────────

    #[test]
    fn observer_inc_drop_reason_dispatches_l2() {
        let obs = Observer::new(&[]);

        obs.inc_drop_reason(DropReason::L2NoBridgeDomain);
        obs.inc_drop_reason(DropReason::L2NoBridgeDomain);

        assert_eq!(obs.drops.l2_no_bridge_domain.load(Ordering::Relaxed), 2);
        // Others remain zero.
        assert_eq!(obs.drops.l3_no_route.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn observer_inc_drop_reason_dispatches_all_variants() {
        let obs = Observer::new(&[]);

        obs.inc_drop_reason(DropReason::L2NoBridgeDomain);
        obs.inc_drop_reason(DropReason::L3NoRoute);
        obs.inc_drop_reason(DropReason::L3TtlExpired);
        obs.inc_drop_reason(DropReason::L3NotIpv4);
        obs.inc_drop_reason(DropReason::NatTableFull);
        obs.inc_drop_reason(DropReason::FirewallDrop);
        obs.inc_drop_reason(DropReason::ArpUnresolved);
        obs.inc_drop_reason(DropReason::ParseError);
        obs.inc_drop_reason(DropReason::ConntrackTableFull);

        assert_eq!(obs.drops.l2_no_bridge_domain.load(Ordering::Relaxed), 1);
        assert_eq!(obs.drops.l3_no_route.load(Ordering::Relaxed), 1);
        assert_eq!(obs.drops.l3_ttl_expired.load(Ordering::Relaxed), 1);
        assert_eq!(obs.drops.l3_not_ipv4.load(Ordering::Relaxed), 1);
        assert_eq!(obs.drops.nat_table_full.load(Ordering::Relaxed), 1);
        assert_eq!(obs.drops.fw_drop.load(Ordering::Relaxed), 1);
        assert_eq!(obs.drops.arp_unresolved.load(Ordering::Relaxed), 1);
        assert_eq!(obs.drops.parse_error.load(Ordering::Relaxed), 1);
        assert_eq!(obs.drops.conntrack_table_full.load(Ordering::Relaxed), 1);
    }

    // ── snapshot ──────────────────────────────────────────────────────

    #[test]
    fn observer_snapshot_captures_current_values() {
        let obs = Observer::new(&["eth0".to_string(), "eth1".to_string()]);

        obs.inc_rx("eth0", 1500);
        obs.inc_tx("eth0", 1000);
        obs.inc_rx("eth1", 64);
        obs.inc_rx_drop("eth0");
        obs.inc_forwarded();
        obs.inc_local_delivery();
        obs.inc_drop_reason(DropReason::L3NoRoute);
        obs.inc_drop_reason(DropReason::L3NoRoute);
        obs.inc_drop_reason(DropReason::FirewallDrop);

        let snap = obs.snapshot();

        assert_eq!(snap.forwarded, 1);
        assert_eq!(snap.local_delivery, 1);
        assert_eq!(snap.drops.l3_no_route, 2);
        assert_eq!(snap.drops.fw_drop, 1);
        assert_eq!(snap.drops.l2_no_bridge_domain, 0);

        // Interfaces are sorted by name.
        assert_eq!(snap.interfaces.len(), 2);
        assert_eq!(snap.interfaces[0].name, "eth0");
        assert_eq!(snap.interfaces[1].name, "eth1");

        assert_eq!(snap.interfaces[0].rx_packets, 1);
        assert_eq!(snap.interfaces[0].rx_bytes, 1500);
        assert_eq!(snap.interfaces[0].tx_packets, 1);
        assert_eq!(snap.interfaces[0].tx_bytes, 1000);
        assert_eq!(snap.interfaces[0].rx_drops, 1);
        assert_eq!(snap.interfaces[0].tx_drops, 0);

        assert_eq!(snap.interfaces[1].rx_packets, 1);
        assert_eq!(snap.interfaces[1].rx_bytes, 64);
        assert_eq!(snap.interfaces[1].tx_packets, 0);
    }

    // ── ObserverSnapshot Display ──────────────────────────────────────

    #[test]
    fn observer_snapshot_display_contains_expected_strings() {
        let obs = Observer::new(&["eth0".to_string(), "eth1".to_string()]);

        obs.inc_rx("eth0", 15000);
        for _ in 0..100 {
            obs.inc_rx("eth0", 0); // just bump the packet count
        }
        obs.inc_tx("eth0", 12000);
        obs.inc_rx_drop("eth0");
        obs.inc_rx_drop("eth0");
        obs.inc_forwarded();
        obs.inc_drop_reason(DropReason::L2NoBridgeDomain);
        obs.inc_drop_reason(DropReason::L3NoRoute);
        obs.inc_drop_reason(DropReason::L3NoRoute);
        obs.inc_drop_reason(DropReason::L3NoRoute);
        obs.inc_drop_reason(DropReason::FirewallDrop);
        obs.inc_drop_reason(DropReason::FirewallDrop);

        let snap = obs.snapshot();
        let output = format!("{snap}");

        assert!(output.contains("=== ruster stats ==="));
        assert!(output.contains("Forwarded: 1"));
        assert!(output.contains("Local: 0"));
        assert!(output.contains("--- Interfaces ---"));
        assert!(output.contains("eth0:"));
        assert!(output.contains("eth1:"));
        assert!(output.contains("RX-drop 2"));
        assert!(output.contains("--- Drop Reasons ---"));
        assert!(output.contains("L2/no-bridge-domain: 1"));
        assert!(output.contains("L3/no-route: 3"));
        assert!(output.contains("FW/drop: 2"));
        assert!(output.contains("ARP/unresolved: 0"));
    }

    // ── InterfaceCounters default to zero ─────────────────────────────

    #[test]
    fn interface_counters_default_to_zero() {
        let ic = InterfaceCounters::default();
        assert_eq!(ic.rx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(ic.rx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(ic.tx_packets.load(Ordering::Relaxed), 0);
        assert_eq!(ic.tx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(ic.rx_drops.load(Ordering::Relaxed), 0);
        assert_eq!(ic.tx_drops.load(Ordering::Relaxed), 0);
    }

    // ── DropCounters default to zero ──────────────────────────────────

    #[test]
    fn drop_counters_default_to_zero() {
        let dc = DropCounters::default();
        assert_eq!(dc.l2_no_bridge_domain.load(Ordering::Relaxed), 0);
        assert_eq!(dc.l3_no_route.load(Ordering::Relaxed), 0);
        assert_eq!(dc.l3_ttl_expired.load(Ordering::Relaxed), 0);
        assert_eq!(dc.l3_not_ipv4.load(Ordering::Relaxed), 0);
        assert_eq!(dc.nat_table_full.load(Ordering::Relaxed), 0);
        assert_eq!(dc.fw_drop.load(Ordering::Relaxed), 0);
        assert_eq!(dc.arp_unresolved.load(Ordering::Relaxed), 0);
        assert_eq!(dc.parse_error.load(Ordering::Relaxed), 0);
        assert_eq!(dc.conntrack_table_full.load(Ordering::Relaxed), 0);
    }

    // ── Multiple increments accumulate ────────────────────────────────

    #[test]
    fn observer_multiple_increments_accumulate() {
        let obs = Observer::new(&["eth0".to_string()]);

        for _ in 0..1000 {
            obs.inc_rx("eth0", 64);
        }
        for _ in 0..500 {
            obs.inc_tx("eth0", 128);
        }
        for _ in 0..50 {
            obs.inc_drop_reason(DropReason::L3NoRoute);
        }
        for _ in 0..200 {
            obs.inc_forwarded();
        }

        let snap = obs.snapshot();

        assert_eq!(snap.interfaces[0].rx_packets, 1000);
        assert_eq!(snap.interfaces[0].rx_bytes, 64000);
        assert_eq!(snap.interfaces[0].tx_packets, 500);
        assert_eq!(snap.interfaces[0].tx_bytes, 64000);
        assert_eq!(snap.drops.l3_no_route, 50);
        assert_eq!(snap.forwarded, 200);
    }

    // ── DropReason Display ────────────────────────────────────────────

    #[test]
    fn drop_reason_display() {
        assert_eq!(
            format!("{}", DropReason::L2NoBridgeDomain),
            "L2/no-bridge-domain"
        );
        assert_eq!(format!("{}", DropReason::L3NoRoute), "L3/no-route");
        assert_eq!(format!("{}", DropReason::L3TtlExpired), "L3/ttl-expired");
        assert_eq!(format!("{}", DropReason::L3NotIpv4), "L3/not-ipv4");
        assert_eq!(format!("{}", DropReason::NatTableFull), "NAT/table-full");
        assert_eq!(format!("{}", DropReason::FirewallDrop), "FW/drop");
        assert_eq!(format!("{}", DropReason::ArpUnresolved), "ARP/unresolved");
        assert_eq!(format!("{}", DropReason::ParseError), "parse-error");
        assert_eq!(
            format!("{}", DropReason::ConntrackTableFull),
            "conntrack/table-full"
        );
    }

    // ── TableStats / TableReport Display ──────────────────────────────

    #[test]
    fn table_report_display_format() {
        let report = TableReport {
            tables: vec![
                TableStats {
                    name: "FDB/br0".to_string(),
                    current: 15,
                    max: 1024,
                },
                TableStats {
                    name: "ARP/eth0".to_string(),
                    current: 3,
                    max: 256,
                },
                TableStats {
                    name: "Conntrack".to_string(),
                    current: 42,
                    max: 10000,
                },
            ],
        };

        let output = format!("{report}");

        assert!(output.contains("=== Table Usage ==="));
        assert!(output.contains("FDB/br0: 15/1024 (1%)"));
        assert!(output.contains("ARP/eth0: 3/256 (1%)"));
        assert!(output.contains("Conntrack: 42/10000 (0%)"));
    }

    #[test]
    fn table_report_empty() {
        let report = TableReport { tables: vec![] };
        let output = format!("{report}");
        assert!(output.contains("=== Table Usage ==="));
    }

    #[test]
    fn table_stats_zero_max_no_panic() {
        let report = TableReport {
            tables: vec![TableStats {
                name: "empty".to_string(),
                current: 0,
                max: 0,
            }],
        };
        let output = format!("{report}");
        assert!(output.contains("empty: 0/0 (0%)"));
    }

    #[test]
    fn table_stats_full_table() {
        let report = TableReport {
            tables: vec![TableStats {
                name: "full".to_string(),
                current: 100,
                max: 100,
            }],
        };
        let output = format!("{report}");
        assert!(output.contains("full: 100/100 (100%)"));
    }

    // ── Snapshot of freshly created observer is all zeros ─────────────

    #[test]
    fn observer_snapshot_fresh_is_all_zeros() {
        let obs = Observer::new(&["eth0".to_string()]);
        let snap = obs.snapshot();

        assert_eq!(snap.forwarded, 0);
        assert_eq!(snap.local_delivery, 0);
        assert_eq!(snap.drops.l2_no_bridge_domain, 0);
        assert_eq!(snap.drops.l3_no_route, 0);
        assert_eq!(snap.drops.l3_ttl_expired, 0);
        assert_eq!(snap.drops.l3_not_ipv4, 0);
        assert_eq!(snap.drops.nat_table_full, 0);
        assert_eq!(snap.drops.fw_drop, 0);
        assert_eq!(snap.drops.arp_unresolved, 0);
        assert_eq!(snap.drops.parse_error, 0);
        assert_eq!(snap.drops.conntrack_table_full, 0);
        assert_eq!(snap.interfaces.len(), 1);
        assert_eq!(snap.interfaces[0].rx_packets, 0);
        assert_eq!(snap.interfaces[0].tx_packets, 0);
        assert_eq!(snap.arp_hold_queue.enqueued, 0);
        assert_eq!(snap.arp_hold_queue.flushed, 0);
        assert_eq!(snap.arp_hold_queue.gc_dropped, 0);
        assert_eq!(snap.arp_hold_queue.tail_dropped, 0);
        assert_eq!(snap.conntrack.conntrack_new, 0);
        assert_eq!(snap.conntrack.conntrack_established, 0);
        assert_eq!(snap.conntrack.conntrack_expired, 0);
        assert_eq!(snap.conntrack.conntrack_table_full, 0);
    }

    // ── ARP hold queue counter tests ─────────────────────────────────

    #[test]
    fn observer_arp_hold_queue_counters() {
        let obs = Observer::new(&[]);

        obs.inc_arp_hold_enqueued();
        obs.inc_arp_hold_enqueued();
        obs.inc_arp_hold_enqueued();
        obs.inc_arp_hold_flushed(2);
        obs.inc_arp_hold_gc_dropped(1);
        obs.inc_arp_hold_tail_dropped();

        let snap = obs.snapshot();
        assert_eq!(snap.arp_hold_queue.enqueued, 3);
        assert_eq!(snap.arp_hold_queue.flushed, 2);
        assert_eq!(snap.arp_hold_queue.gc_dropped, 1);
        assert_eq!(snap.arp_hold_queue.tail_dropped, 1);
    }

    #[test]
    fn observer_snapshot_display_contains_arp_hold_queue() {
        let obs = Observer::new(&["eth0".to_string()]);
        obs.inc_arp_hold_enqueued();
        obs.inc_arp_hold_flushed(1);

        let snap = obs.snapshot();
        let output = format!("{snap}");

        assert!(output.contains("--- ARP Hold Queue ---"));
        assert!(output.contains("enqueued: 1"));
        assert!(output.contains("flushed: 1"));
        assert!(output.contains("gc-dropped: 0"));
        assert!(output.contains("tail-dropped: 0"));
    }

    #[test]
    fn observer_snapshot_display_contains_conntrack() {
        let obs = Observer::new(&[]);
        obs.inc_conntrack_new();
        obs.inc_conntrack_established();
        obs.add_conntrack_expired(10);
        obs.inc_conntrack_table_full();

        let snap = obs.snapshot();
        let output = format!("{snap}");

        assert!(output.contains("--- Conntrack ---"));
        assert!(output.contains("new: 1"));
        assert!(output.contains("established: 1"));
        assert!(output.contains("expired: 10"));
        assert!(output.contains("table-full: 1"));
    }
}

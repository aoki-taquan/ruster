//! Connection Tracking for Stateful Packet Inspection (SPI)
//!
//! Provides connection state management for firewall functionality.
//! Tracks TCP/UDP/ICMP connections to allow return traffic.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Protocol types for connection tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnProtocol {
    Tcp,
    Udp,
    Icmp,
}

impl ConnProtocol {
    /// Create protocol from IP protocol number
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(ConnProtocol::Icmp),
            6 => Some(ConnProtocol::Tcp),
            17 => Some(ConnProtocol::Udp),
            _ => None,
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// New connection (no reply yet)
    New,
    /// Established (bidirectional traffic seen)
    Established,
}

/// TCP connection state for detailed tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnState {
    /// SYN sent, waiting for SYN-ACK
    SynSent,
    /// SYN received (simultaneous open)
    SynRecv,
    /// Connection established
    Established,
    /// FIN seen, closing
    FinWait,
    /// Both FINs seen
    TimeWait,
    /// RST seen or timeout
    Closed,
}

/// Connection key (5-tuple)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: ConnProtocol,
}

impl ConnKey {
    /// Create a new connection key
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        protocol: ConnProtocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Create the reverse key (swap src/dst)
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

/// Connection entry
#[derive(Debug, Clone)]
pub struct ConnEntry {
    /// Original direction key
    pub original: ConnKey,
    /// Connection state
    pub state: ConnState,
    /// TCP-specific state
    pub tcp_state: Option<TcpConnState>,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Creation timestamp
    pub created_at: Instant,
}

impl ConnEntry {
    /// Create a new connection entry
    pub fn new(key: ConnKey) -> Self {
        let now = Instant::now();
        let tcp_state = if key.protocol == ConnProtocol::Tcp {
            Some(TcpConnState::SynSent)
        } else {
            None
        };

        Self {
            original: key,
            state: ConnState::New,
            tcp_state,
            last_seen: now,
            created_at: now,
        }
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Mark as established
    pub fn set_established(&mut self) {
        self.state = ConnState::Established;
    }
}

/// Timeout configuration for connection tracking
#[derive(Debug, Clone)]
pub struct ConnTrackTimeouts {
    /// TCP established connection (default: 2 hours)
    pub tcp_established: Duration,
    /// TCP transitory states (default: 4 minutes)
    pub tcp_transitory: Duration,
    /// UDP (default: 5 minutes)
    pub udp: Duration,
    /// ICMP (default: 1 minute)
    pub icmp: Duration,
}

impl Default for ConnTrackTimeouts {
    fn default() -> Self {
        Self {
            tcp_established: Duration::from_secs(7200), // 2 hours
            tcp_transitory: Duration::from_secs(240),   // 4 minutes
            udp: Duration::from_secs(300),              // 5 minutes
            icmp: Duration::from_secs(60),              // 1 minute
        }
    }
}

/// Connection tracking table
pub struct ConnTrackTable {
    /// Original direction -> Entry
    entries: HashMap<ConnKey, ConnEntry>,
    /// Reply direction -> Original direction key (reverse lookup)
    reply_map: HashMap<ConnKey, ConnKey>,
    /// Timeout configuration
    timeouts: ConnTrackTimeouts,
}

impl ConnTrackTable {
    /// Create a new connection tracking table
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            reply_map: HashMap::new(),
            timeouts: ConnTrackTimeouts::default(),
        }
    }

    /// Create with custom timeouts
    #[cfg(test)]
    pub fn with_timeouts(timeouts: ConnTrackTimeouts) -> Self {
        Self {
            entries: HashMap::new(),
            reply_map: HashMap::new(),
            timeouts,
        }
    }

    /// Track a new outbound connection
    pub fn track_outbound(&mut self, key: ConnKey) {
        if self.entries.contains_key(&key) {
            // Already tracked, just update timestamp
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.touch();
            }
            return;
        }

        let reply_key = key.reverse();
        let entry = ConnEntry::new(key.clone());

        self.reply_map.insert(reply_key, key.clone());
        self.entries.insert(key, entry);
    }

    /// Check if a packet matches an existing connection (for inbound)
    /// Returns true if the packet is part of an established/tracked connection
    pub fn is_tracked(&self, key: &ConnKey) -> bool {
        // Check if this is an original direction packet
        if self.entries.contains_key(key) {
            return true;
        }

        // Check if this is a reply direction packet
        self.reply_map.contains_key(key)
    }

    /// Update connection state for reply packet
    pub fn track_reply(&mut self, reply_key: &ConnKey) {
        if let Some(original_key) = self.reply_map.get(reply_key).cloned() {
            if let Some(entry) = self.entries.get_mut(&original_key) {
                entry.touch();
                entry.set_established();

                // Update TCP state
                if let Some(ref mut tcp_state) = entry.tcp_state {
                    if *tcp_state == TcpConnState::SynSent {
                        *tcp_state = TcpConnState::Established;
                    }
                }
            }
        }
    }

    /// Update TCP state based on flags
    pub fn update_tcp_state(&mut self, key: &ConnKey, syn: bool, fin: bool, rst: bool, ack: bool) {
        // Try to find the entry (original or reply direction)
        let original_key = if self.entries.contains_key(key) {
            key.clone()
        } else if let Some(orig) = self.reply_map.get(key) {
            orig.clone()
        } else {
            return;
        };

        if let Some(entry) = self.entries.get_mut(&original_key) {
            if let Some(ref mut tcp_state) = entry.tcp_state {
                *tcp_state = Self::transition_tcp_state(*tcp_state, syn, fin, rst, ack);
            }
            entry.touch();
        }
    }

    /// TCP state transition logic
    fn transition_tcp_state(
        current: TcpConnState,
        syn: bool,
        fin: bool,
        rst: bool,
        ack: bool,
    ) -> TcpConnState {
        if rst {
            return TcpConnState::Closed;
        }

        match current {
            TcpConnState::SynSent => {
                if syn && ack {
                    TcpConnState::Established
                } else {
                    current
                }
            }
            TcpConnState::SynRecv => {
                if ack && !syn {
                    TcpConnState::Established
                } else {
                    current
                }
            }
            TcpConnState::Established => {
                if fin {
                    TcpConnState::FinWait
                } else {
                    current
                }
            }
            TcpConnState::FinWait => {
                if fin {
                    TcpConnState::TimeWait
                } else {
                    current
                }
            }
            TcpConnState::TimeWait | TcpConnState::Closed => current,
        }
    }

    /// Remove expired entries
    pub fn expire_old_entries(&mut self) {
        let now = Instant::now();
        let timeouts = &self.timeouts;

        // Collect expired keys
        let expired: Vec<ConnKey> = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                let timeout = match entry.original.protocol {
                    ConnProtocol::Tcp => match entry.tcp_state {
                        Some(TcpConnState::Established) => timeouts.tcp_established,
                        Some(TcpConnState::Closed) => Duration::from_secs(0),
                        _ => timeouts.tcp_transitory,
                    },
                    ConnProtocol::Udp => timeouts.udp,
                    ConnProtocol::Icmp => timeouts.icmp,
                };

                if now.duration_since(entry.last_seen) > timeout {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove expired entries
        for key in expired {
            if let Some(entry) = self.entries.remove(&key) {
                let reply_key = entry.original.reverse();
                self.reply_map.remove(&reply_key);
            }
        }
    }

    /// Get number of tracked connections
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lookup entry by original key
    #[cfg(test)]
    pub fn lookup(&self, key: &ConnKey) -> Option<&ConnEntry> {
        self.entries.get(key)
    }
}

impl Default for ConnTrackTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_key() -> ConnKey {
        ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            80,
            ConnProtocol::Tcp,
        )
    }

    fn make_udp_key() -> ConnKey {
        ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            54321,
            53,
            ConnProtocol::Udp,
        )
    }

    fn make_icmp_key() -> ConnKey {
        ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            0x1234, // identifier
            0,
            ConnProtocol::Icmp,
        )
    }

    #[test]
    fn test_conntrack_new() {
        let table = ConnTrackTable::new();
        assert!(table.is_empty());
    }

    #[test]
    fn test_track_outbound() {
        let mut table = ConnTrackTable::new();
        let key = make_tcp_key();

        table.track_outbound(key.clone());

        assert_eq!(table.len(), 1);
        assert!(table.is_tracked(&key));
    }

    #[test]
    fn test_track_reply() {
        let mut table = ConnTrackTable::new();
        let key = make_tcp_key();
        let reply_key = key.reverse();

        table.track_outbound(key.clone());
        assert!(table.is_tracked(&reply_key)); // Reply should be tracked

        // Initially state is New
        assert_eq!(table.lookup(&key).unwrap().state, ConnState::New);

        // After reply, state becomes Established
        table.track_reply(&reply_key);
        assert_eq!(table.lookup(&key).unwrap().state, ConnState::Established);
    }

    #[test]
    fn test_udp_tracking() {
        let mut table = ConnTrackTable::new();
        let key = make_udp_key();

        table.track_outbound(key.clone());
        assert!(table.is_tracked(&key));

        let reply_key = key.reverse();
        assert!(table.is_tracked(&reply_key));

        table.track_reply(&reply_key);
        assert_eq!(table.lookup(&key).unwrap().state, ConnState::Established);
    }

    #[test]
    fn test_icmp_tracking() {
        let mut table = ConnTrackTable::new();
        let key = make_icmp_key();

        table.track_outbound(key.clone());
        assert!(table.is_tracked(&key));

        let reply_key = key.reverse();
        assert!(table.is_tracked(&reply_key));
    }

    #[test]
    fn test_untracked_inbound() {
        let table = ConnTrackTable::new();
        let key = make_tcp_key();

        // Without tracking outbound first, inbound should not be tracked
        assert!(!table.is_tracked(&key));
    }

    #[test]
    fn test_tcp_state_transition() {
        let mut table = ConnTrackTable::new();
        let key = make_tcp_key();

        table.track_outbound(key.clone());
        assert_eq!(
            table.lookup(&key).unwrap().tcp_state,
            Some(TcpConnState::SynSent)
        );

        // SYN-ACK received
        table.update_tcp_state(&key.reverse(), true, false, false, true);
        assert_eq!(
            table.lookup(&key).unwrap().tcp_state,
            Some(TcpConnState::Established)
        );

        // FIN sent
        table.update_tcp_state(&key, false, true, false, true);
        assert_eq!(
            table.lookup(&key).unwrap().tcp_state,
            Some(TcpConnState::FinWait)
        );

        // FIN received
        table.update_tcp_state(&key.reverse(), false, true, false, true);
        assert_eq!(
            table.lookup(&key).unwrap().tcp_state,
            Some(TcpConnState::TimeWait)
        );
    }

    #[test]
    fn test_rst_closes_connection() {
        let mut table = ConnTrackTable::new();
        let key = make_tcp_key();

        table.track_outbound(key.clone());
        table.update_tcp_state(&key, false, false, true, false); // RST

        assert_eq!(
            table.lookup(&key).unwrap().tcp_state,
            Some(TcpConnState::Closed)
        );
    }

    #[test]
    fn test_timeout_expiry() {
        let timeouts = ConnTrackTimeouts {
            tcp_established: Duration::from_millis(10),
            tcp_transitory: Duration::from_millis(1),
            udp: Duration::from_millis(1),
            icmp: Duration::from_millis(1),
        };
        let mut table = ConnTrackTable::with_timeouts(timeouts);

        let key = make_udp_key();
        table.track_outbound(key.clone());
        assert_eq!(table.len(), 1);

        std::thread::sleep(Duration::from_millis(10));
        table.expire_old_entries();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_key_reverse() {
        let key = make_tcp_key();
        let reply = key.reverse();

        assert_eq!(reply.src_ip, key.dst_ip);
        assert_eq!(reply.dst_ip, key.src_ip);
        assert_eq!(reply.src_port, key.dst_port);
        assert_eq!(reply.dst_port, key.src_port);
        assert_eq!(reply.protocol, key.protocol);
    }
}

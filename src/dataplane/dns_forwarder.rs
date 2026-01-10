//! DNS Forwarder
//!
//! DNS forwarder implementation with caching support.
//! Forwards DNS queries to upstream servers and caches responses.

use crate::protocol::dns::{DnsHeader, DnsPacket, DnsRcode};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// DNS forwarder processing result
#[derive(Debug)]
pub enum DnsAction {
    /// Send a DNS reply to client
    Reply {
        /// Interface to send on
        interface: String,
        /// DNS payload (to be wrapped in UDP/IP/Ethernet)
        packet: Vec<u8>,
        /// Destination IP
        dst_ip: Ipv4Addr,
        /// Destination port
        dst_port: u16,
    },
    /// Forward query to upstream server
    Forward {
        /// Upstream server IP
        upstream: Ipv4Addr,
        /// DNS packet with new transaction ID
        packet: Vec<u8>,
        /// Original transaction ID for response matching
        original_id: u16,
    },
    /// No action needed
    None,
}

/// Pending query entry awaiting upstream response
#[derive(Debug, Clone)]
pub struct PendingQuery {
    /// Original transaction ID from client
    pub original_id: u16,
    /// Client IP address
    pub client_ip: Ipv4Addr,
    /// Client port
    pub client_port: u16,
    /// Interface the query arrived on
    pub interface: String,
    /// When the query was forwarded
    pub forwarded_at: Instant,
}

/// Cache entry with TTL
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Full DNS response packet (ID will be replaced on cache hit)
    pub response: Vec<u8>,
    /// When this entry expires
    pub expires_at: Instant,
    /// When this entry was inserted
    pub inserted_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// DNS forwarder configuration
#[derive(Debug, Clone)]
pub struct DnsForwarderConfig {
    /// Upstream DNS servers
    pub upstream_servers: Vec<Ipv4Addr>,
    /// Maximum cache entries
    pub cache_size: usize,
    /// Query timeout in seconds
    pub query_timeout_secs: u64,
    /// Negative response cache TTL (for NXDOMAIN)
    pub negative_cache_ttl: u32,
}

impl Default for DnsForwarderConfig {
    fn default() -> Self {
        Self {
            upstream_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)],
            cache_size: 1000,
            query_timeout_secs: 5,
            negative_cache_ttl: 60,
        }
    }
}

/// DNS forwarder service
#[derive(Debug)]
pub struct DnsForwarder {
    config: DnsForwarderConfig,
    /// Cache: (qname_lowercase, qtype) -> CacheEntry
    cache: HashMap<(String, u16), CacheEntry>,
    /// Pending queries: forwarded_id -> PendingQuery
    pending: HashMap<u16, PendingQuery>,
    /// Next ID for upstream queries
    next_id: u16,
    /// Round-robin index for upstream selection
    upstream_index: usize,
    /// Cache hit counter
    cache_hits: u64,
    /// Cache miss counter
    cache_misses: u64,
}

impl DnsForwarder {
    /// Create a new DNS forwarder
    pub fn new(config: DnsForwarderConfig) -> Self {
        debug!(
            "DNS forwarder created with {} upstream servers, cache_size={}",
            config.upstream_servers.len(),
            config.cache_size
        );

        Self {
            config,
            cache: HashMap::new(),
            pending: HashMap::new(),
            next_id: 1,
            upstream_index: 0,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Process incoming DNS query from client
    pub fn process_query(
        &mut self,
        interface: &str,
        client_ip: Ipv4Addr,
        client_port: u16,
        dns_payload: &[u8],
    ) -> DnsAction {
        // Parse DNS header
        let header = match DnsHeader::parse(dns_payload) {
            Ok(h) => h,
            Err(e) => {
                trace!("Failed to parse DNS query: {}", e);
                return DnsAction::None;
            }
        };

        // Only handle queries
        if header.is_response() {
            trace!("Ignoring DNS response packet");
            return DnsAction::None;
        }

        let original_id = header.id();

        // Parse question to get cache key
        let packet = match DnsPacket::from_bytes(dns_payload) {
            Ok(p) => p,
            Err(e) => {
                trace!("Failed to parse DNS packet: {}", e);
                return DnsAction::None;
            }
        };

        let questions = match packet.questions() {
            Ok(q) => q,
            Err(e) => {
                trace!("Failed to parse DNS questions: {}", e);
                return DnsAction::None;
            }
        };

        if questions.is_empty() {
            trace!("DNS query with no questions");
            return DnsAction::None;
        }

        let question = &questions[0];
        let cache_key = (question.name.to_lowercase(), question.qtype);

        debug!(
            "DNS query from {}:{} for {} (type {})",
            client_ip, client_port, question.name, question.qtype
        );

        // Check cache
        if let Some(entry) = self.cache.get(&cache_key) {
            if !entry.is_expired() {
                self.cache_hits += 1;
                debug!("Cache hit for {}", question.name);

                // Clone response and replace transaction ID
                let mut response = entry.response.clone();
                if response.len() >= 2 {
                    response[0..2].copy_from_slice(&original_id.to_be_bytes());
                }

                return DnsAction::Reply {
                    interface: interface.to_string(),
                    packet: response,
                    dst_ip: client_ip,
                    dst_port: client_port,
                };
            } else {
                // Remove expired entry
                self.cache.remove(&cache_key);
            }
        }

        self.cache_misses += 1;

        // Get upstream server (round-robin)
        let upstream = match self.next_upstream() {
            Some(ip) => ip,
            None => {
                warn!("No upstream DNS servers configured");
                return DnsAction::None;
            }
        };

        // Generate new transaction ID for upstream
        let forwarded_id = self.generate_id();

        // Create forwarded packet with new ID
        let mut forwarded_packet = dns_payload.to_vec();
        if forwarded_packet.len() >= 2 {
            forwarded_packet[0..2].copy_from_slice(&forwarded_id.to_be_bytes());
        }

        // Store pending query
        self.pending.insert(
            forwarded_id,
            PendingQuery {
                original_id,
                client_ip,
                client_port,
                interface: interface.to_string(),
                forwarded_at: Instant::now(),
            },
        );

        debug!(
            "Forwarding query for {} to {} (id {} -> {})",
            question.name, upstream, original_id, forwarded_id
        );

        DnsAction::Forward {
            upstream,
            packet: forwarded_packet,
            original_id,
        }
    }

    /// Process response from upstream DNS server
    pub fn process_response(&mut self, upstream_ip: Ipv4Addr, dns_payload: &[u8]) -> DnsAction {
        // Parse DNS header
        let header = match DnsHeader::parse(dns_payload) {
            Ok(h) => h,
            Err(e) => {
                trace!("Failed to parse DNS response: {}", e);
                return DnsAction::None;
            }
        };

        // Only handle responses
        if header.is_query() {
            trace!("Ignoring DNS query packet from upstream");
            return DnsAction::None;
        }

        let response_id = header.id();

        // Look up pending query
        let pending = match self.pending.remove(&response_id) {
            Some(p) => p,
            None => {
                trace!("No pending query for response id {}", response_id);
                return DnsAction::None;
            }
        };

        debug!(
            "Received response from {} for query {} (client {}:{})",
            upstream_ip, response_id, pending.client_ip, pending.client_port
        );

        // Cache the response
        self.cache_response(dns_payload);

        // Replace transaction ID with original
        let mut response = dns_payload.to_vec();
        if response.len() >= 2 {
            response[0..2].copy_from_slice(&pending.original_id.to_be_bytes());
        }

        DnsAction::Reply {
            interface: pending.interface,
            packet: response,
            dst_ip: pending.client_ip,
            dst_port: pending.client_port,
        }
    }

    /// Cache a DNS response
    fn cache_response(&mut self, dns_payload: &[u8]) {
        if self.config.cache_size == 0 {
            return;
        }

        let packet = match DnsPacket::from_bytes(dns_payload) {
            Ok(p) => p,
            Err(_) => return,
        };

        // Get question for cache key
        let questions = match packet.questions() {
            Ok(q) => q,
            Err(_) => return,
        };

        if questions.is_empty() {
            return;
        }

        let question = &questions[0];
        let cache_key = (question.name.to_lowercase(), question.qtype);

        // Determine TTL
        let ttl = if packet.rcode() == DnsRcode::NameError as u8 {
            // NXDOMAIN - use negative cache TTL
            self.config.negative_cache_ttl
        } else {
            // Use minimum TTL from answers, or default
            packet.min_ttl().unwrap_or(300)
        };

        // Evict if cache is full
        if self.cache.len() >= self.config.cache_size {
            self.evict_oldest();
        }

        let now = Instant::now();
        self.cache.insert(
            cache_key,
            CacheEntry {
                response: dns_payload.to_vec(),
                expires_at: now + Duration::from_secs(ttl as u64),
                inserted_at: now,
            },
        );

        trace!("Cached DNS response for {} with TTL {}", question.name, ttl);
    }

    /// Evict the oldest cache entry
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .cache
            .iter()
            .min_by_key(|(_, entry)| entry.inserted_at)
            .map(|(key, _)| key.clone())
        {
            self.cache.remove(&oldest_key);
        }
    }

    /// Get next upstream server (round-robin)
    fn next_upstream(&mut self) -> Option<Ipv4Addr> {
        if self.config.upstream_servers.is_empty() {
            return None;
        }

        let server = self.config.upstream_servers[self.upstream_index];
        self.upstream_index = (self.upstream_index + 1) % self.config.upstream_servers.len();
        Some(server)
    }

    /// Generate a unique transaction ID
    fn generate_id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1; // Skip 0
        }
        id
    }

    /// Check if a given IP is one of our upstream servers
    pub fn is_upstream(&self, ip: &Ipv4Addr) -> bool {
        self.config.upstream_servers.contains(ip)
    }

    /// Run maintenance tasks (expire old entries, timeout queries)
    pub fn run_maintenance(&mut self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(self.config.query_timeout_secs);

        // Expire old cache entries
        self.cache.retain(|_, entry| !entry.is_expired());

        // Timeout pending queries
        let timed_out: Vec<u16> = self
            .pending
            .iter()
            .filter(|(_, query)| now.duration_since(query.forwarded_at) > timeout)
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            if let Some(query) = self.pending.remove(&id) {
                debug!(
                    "DNS query timeout for client {}:{} (id {})",
                    query.client_ip, query.client_port, id
                );
            }
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, u64, u64) {
        (self.cache.len(), self.cache_hits, self.cache_misses)
    }

    /// Get number of pending queries
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query_packet(id: u16, name: &str) -> Vec<u8> {
        use crate::protocol::dns::{encode_domain_name, DnsClass, DnsType};

        let mut buffer = Vec::new();

        // Header
        buffer.extend_from_slice(&id.to_be_bytes());
        buffer.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
        buffer.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buffer.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buffer.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buffer.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question
        buffer.extend(encode_domain_name(name));
        buffer.extend_from_slice(&(DnsType::A as u16).to_be_bytes());
        buffer.extend_from_slice(&(DnsClass::IN as u16).to_be_bytes());

        buffer
    }

    fn make_response_packet(id: u16, name: &str, ttl: u32) -> Vec<u8> {
        use crate::protocol::dns::{encode_domain_name, DnsClass, DnsType};

        let mut buffer = Vec::new();

        // Header
        buffer.extend_from_slice(&id.to_be_bytes());
        buffer.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: QR=1, RD=1, RA=1
        buffer.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buffer.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        buffer.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buffer.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question
        buffer.extend(encode_domain_name(name));
        buffer.extend_from_slice(&(DnsType::A as u16).to_be_bytes());
        buffer.extend_from_slice(&(DnsClass::IN as u16).to_be_bytes());

        // Answer (using name directly, no compression for simplicity)
        buffer.extend(encode_domain_name(name));
        buffer.extend_from_slice(&(DnsType::A as u16).to_be_bytes());
        buffer.extend_from_slice(&(DnsClass::IN as u16).to_be_bytes());
        buffer.extend_from_slice(&ttl.to_be_bytes());
        buffer.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        buffer.extend_from_slice(&[93, 184, 216, 34]); // RDATA: 93.184.216.34

        buffer
    }

    #[test]
    fn test_forwarder_new() {
        let config = DnsForwarderConfig::default();
        let forwarder = DnsForwarder::new(config);

        assert_eq!(forwarder.cache.len(), 0);
        assert_eq!(forwarder.pending.len(), 0);
    }

    #[test]
    fn test_process_query_cache_miss() {
        let config = DnsForwarderConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        let query = make_query_packet(0x1234, "example.com");
        let action =
            forwarder.process_query("eth0", Ipv4Addr::new(192, 168, 1, 100), 12345, &query);

        match action {
            DnsAction::Forward {
                upstream,
                packet,
                original_id,
            } => {
                assert!(
                    upstream == Ipv4Addr::new(8, 8, 8, 8) || upstream == Ipv4Addr::new(1, 1, 1, 1)
                );
                assert_eq!(original_id, 0x1234);
                // Packet should have different ID
                let new_id = u16::from_be_bytes([packet[0], packet[1]]);
                assert_ne!(new_id, 0x1234);
            }
            _ => panic!("Expected Forward action"),
        }

        assert_eq!(forwarder.pending.len(), 1);
    }

    #[test]
    fn test_process_response_pending() {
        let config = DnsForwarderConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        // First, process a query
        let query = make_query_packet(0x1234, "example.com");
        let forward_action =
            forwarder.process_query("eth0", Ipv4Addr::new(192, 168, 1, 100), 12345, &query);

        let forwarded_id = match forward_action {
            DnsAction::Forward { packet, .. } => u16::from_be_bytes([packet[0], packet[1]]),
            _ => panic!("Expected Forward action"),
        };

        // Now process a response with the forwarded ID
        let response = make_response_packet(forwarded_id, "example.com", 300);
        let reply_action = forwarder.process_response(Ipv4Addr::new(8, 8, 8, 8), &response);

        match reply_action {
            DnsAction::Reply {
                interface,
                packet,
                dst_ip,
                dst_port,
            } => {
                assert_eq!(interface, "eth0");
                assert_eq!(dst_ip, Ipv4Addr::new(192, 168, 1, 100));
                assert_eq!(dst_port, 12345);
                // ID should be restored to original
                let id = u16::from_be_bytes([packet[0], packet[1]]);
                assert_eq!(id, 0x1234);
            }
            _ => panic!("Expected Reply action"),
        }

        assert_eq!(forwarder.pending.len(), 0);
    }

    #[test]
    fn test_cache_hit() {
        let config = DnsForwarderConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        // Process query -> forward
        let query = make_query_packet(0x1234, "example.com");
        let forward_action =
            forwarder.process_query("eth0", Ipv4Addr::new(192, 168, 1, 100), 12345, &query);

        let forwarded_id = match forward_action {
            DnsAction::Forward { packet, .. } => u16::from_be_bytes([packet[0], packet[1]]),
            _ => panic!("Expected Forward action"),
        };

        // Process response -> caches
        let response = make_response_packet(forwarded_id, "example.com", 300);
        forwarder.process_response(Ipv4Addr::new(8, 8, 8, 8), &response);

        assert_eq!(forwarder.cache.len(), 1);

        // Second query should hit cache
        let query2 = make_query_packet(0x5678, "example.com");
        let cache_action =
            forwarder.process_query("eth0", Ipv4Addr::new(192, 168, 1, 101), 54321, &query2);

        match cache_action {
            DnsAction::Reply {
                packet,
                dst_ip,
                dst_port,
                ..
            } => {
                assert_eq!(dst_ip, Ipv4Addr::new(192, 168, 1, 101));
                assert_eq!(dst_port, 54321);
                // ID should be the new query's ID
                let id = u16::from_be_bytes([packet[0], packet[1]]);
                assert_eq!(id, 0x5678);
            }
            _ => panic!("Expected Reply action from cache"),
        }

        let (_, hits, misses) = forwarder.cache_stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    #[test]
    fn test_process_response_unknown_id() {
        let config = DnsForwarderConfig::default();
        let mut forwarder = DnsForwarder::new(config);

        // Process response with unknown ID
        let response = make_response_packet(0x9999, "example.com", 300);
        let action = forwarder.process_response(Ipv4Addr::new(8, 8, 8, 8), &response);

        match action {
            DnsAction::None => {}
            _ => panic!("Expected None action for unknown ID"),
        }
    }

    #[test]
    fn test_upstream_round_robin() {
        let config = DnsForwarderConfig {
            upstream_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)],
            ..Default::default()
        };
        let mut forwarder = DnsForwarder::new(config);

        let first = forwarder.next_upstream();
        let second = forwarder.next_upstream();
        let third = forwarder.next_upstream();

        assert_eq!(first, Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(second, Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(third, Some(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_is_upstream() {
        let config = DnsForwarderConfig::default();
        let forwarder = DnsForwarder::new(config);

        assert!(forwarder.is_upstream(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(forwarder.is_upstream(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!forwarder.is_upstream(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_maintenance_timeout() {
        let config = DnsForwarderConfig {
            query_timeout_secs: 0, // Immediate timeout
            ..Default::default()
        };
        let mut forwarder = DnsForwarder::new(config);

        // Add a query
        let query = make_query_packet(0x1234, "example.com");
        forwarder.process_query("eth0", Ipv4Addr::new(192, 168, 1, 100), 12345, &query);

        assert_eq!(forwarder.pending.len(), 1);

        // Run maintenance - should timeout the query
        forwarder.run_maintenance();

        assert_eq!(forwarder.pending.len(), 0);
    }
}

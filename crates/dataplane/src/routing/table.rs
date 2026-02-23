//! IPv4 static route table with longest prefix match (LPM).
//!
//! This module provides a [`RouteTable`] that loads static routes from
//! configuration and performs longest-prefix-match lookups for L3
//! forwarding decisions.
//!
//! RFC-REF: RFC 791 Section 3.2
//! "The internet modules use the addresses carried in the internet header
//! to select the next gateway (or destination host) to which the datagram
//! should be forwarded."

use ruster_config::model::RoutingConfig;

/// A single route entry in the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// Network prefix (host-byte-order, e.g. [192, 168, 1, 0]).
    pub prefix: [u8; 4],
    /// Prefix length in bits (0..=32).
    pub prefix_len: u8,
    /// Next-hop IPv4 address.
    pub next_hop: [u8; 4],
    /// Outgoing interface name.
    pub out_ifname: String,
    /// Route metric (lower is preferred).
    pub metric: u32,
}

/// IPv4 static route table.
///
/// Entries are sorted by prefix length descending so that the first match
/// in a linear scan is the longest (most specific) prefix match.
#[derive(Debug, Clone)]
pub struct RouteTable {
    /// Route entries sorted by prefix_len descending, then metric ascending.
    entries: Vec<RouteEntry>,
}

impl RouteTable {
    /// Build a route table from the routing configuration.
    ///
    /// Parses each static route's prefix string (e.g. "192.168.1.0/24")
    /// and next-hop address, then sorts entries for LPM lookup.
    pub fn from_config(routing_config: &RoutingConfig) -> Self {
        // NOTE: Config validation (ruster-config validate) ensures all prefix
        // and next_hop strings are well-formed before they reach here.
        // filter_map is retained as a defence-in-depth measure; any parse
        // failure at this stage indicates a logic bug.
        let mut entries: Vec<RouteEntry> = routing_config
            .ipv4_static_routes
            .iter()
            .filter_map(|sr| {
                let (prefix, prefix_len) = parse_prefix(&sr.prefix)?;
                let next_hop = parse_ipv4_addr(&sr.next_hop)?;
                Some(RouteEntry {
                    prefix,
                    prefix_len,
                    next_hop,
                    out_ifname: sr.out_if.clone(),
                    metric: sr.metric,
                })
            })
            .collect();

        // Sort by prefix_len descending (longest first), then metric ascending.
        entries.sort_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then(a.metric.cmp(&b.metric))
        });

        Self { entries }
    }

    /// Create an empty route table.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Longest prefix match lookup.
    ///
    /// RFC-REF: RFC 791 Section 3.2
    /// "Routing is based on the destination address [...] the most specific
    /// matching route is selected."
    ///
    /// Returns the first (longest prefix) matching entry, or `None` if no
    /// route matches.
    pub fn lookup(&self, dst_ip: &[u8; 4]) -> Option<&RouteEntry> {
        self.entries
            .iter()
            .find(|entry| matches_prefix(dst_ip, &entry.prefix, entry.prefix_len))
    }

    /// Returns the number of route entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the route table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Parse a CIDR prefix string into an IPv4 address and prefix length.
///
/// Accepts formats like "192.168.1.0/24" or "0.0.0.0/0".
/// Returns `None` if the string cannot be parsed.
pub fn parse_prefix(prefix_str: &str) -> Option<([u8; 4], u8)> {
    let (ip_str, len_str) = prefix_str.split_once('/')?;

    let ip = parse_ipv4_addr(ip_str)?;
    let prefix_len: u8 = len_str.parse().ok()?;

    if prefix_len > 32 {
        return None;
    }

    Some((ip, prefix_len))
}

/// Check whether an IPv4 address matches a given prefix.
///
/// Compares the first `prefix_len` bits of `ip` against `prefix`.
/// A `prefix_len` of 0 matches all addresses (default route).
pub fn matches_prefix(ip: &[u8; 4], prefix: &[u8; 4], prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }

    // Convert to u32 for bit comparison.
    let ip_u32 = u32::from_be_bytes(*ip);
    let prefix_u32 = u32::from_be_bytes(*prefix);

    // Build a mask with the top `prefix_len` bits set.
    let mask = if prefix_len == 32 {
        0xFFFF_FFFFu32
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };

    (ip_u32 & mask) == (prefix_u32 & mask)
}

/// Parse an IPv4 address string (e.g. "192.168.1.1") into a 4-byte array.
///
/// This is a duplicate of the helper in the `arp` module (which is private).
/// Returns `None` if the string cannot be parsed.
fn parse_ipv4_addr(addr_str: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = addr_str.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        ip[i] = part.parse::<u8>().ok()?;
    }
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_config::model::{RoutingConfig, StaticRoute};

    // ── parse_prefix tests ────────────────────────────────────────────

    #[test]
    fn parse_prefix_valid() {
        assert_eq!(parse_prefix("192.168.1.0/24"), Some(([192, 168, 1, 0], 24)));
    }

    #[test]
    fn parse_prefix_default_route() {
        assert_eq!(parse_prefix("0.0.0.0/0"), Some(([0, 0, 0, 0], 0)));
    }

    #[test]
    fn parse_prefix_host_route() {
        assert_eq!(parse_prefix("10.0.0.1/32"), Some(([10, 0, 0, 1], 32)));
    }

    #[test]
    fn parse_prefix_invalid_no_slash() {
        assert_eq!(parse_prefix("192.168.1.0"), None);
    }

    #[test]
    fn parse_prefix_invalid_prefix_len() {
        assert_eq!(parse_prefix("192.168.1.0/33"), None);
    }

    #[test]
    fn parse_prefix_invalid_ip() {
        assert_eq!(parse_prefix("invalid/24"), None);
    }

    // ── matches_prefix tests ──────────────────────────────────────────

    #[test]
    fn matches_prefix_exact() {
        assert!(matches_prefix(&[192, 168, 1, 100], &[192, 168, 1, 0], 24));
    }

    #[test]
    fn matches_prefix_no_match() {
        assert!(!matches_prefix(&[192, 168, 2, 100], &[192, 168, 1, 0], 24));
    }

    #[test]
    fn matches_prefix_default_route() {
        // /0 matches everything.
        assert!(matches_prefix(&[10, 0, 0, 1], &[0, 0, 0, 0], 0));
        assert!(matches_prefix(&[255, 255, 255, 255], &[0, 0, 0, 0], 0));
    }

    #[test]
    fn matches_prefix_host_route() {
        assert!(matches_prefix(&[10, 0, 0, 1], &[10, 0, 0, 1], 32));
        assert!(!matches_prefix(&[10, 0, 0, 2], &[10, 0, 0, 1], 32));
    }

    #[test]
    fn matches_prefix_slash_8() {
        assert!(matches_prefix(&[10, 1, 2, 3], &[10, 0, 0, 0], 8));
        assert!(!matches_prefix(&[11, 0, 0, 1], &[10, 0, 0, 0], 8));
    }

    // ── RouteTable::from_config tests ─────────────────────────────────

    fn make_routing_config() -> RoutingConfig {
        RoutingConfig {
            ipv4_static_routes: vec![
                StaticRoute {
                    prefix: "0.0.0.0/0".to_string(),
                    next_hop: "10.0.0.1".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
                StaticRoute {
                    prefix: "192.168.1.0/24".to_string(),
                    next_hop: "0.0.0.0".to_string(),
                    out_if: "lan0".to_string(),
                    metric: 10,
                },
                StaticRoute {
                    prefix: "192.168.1.128/25".to_string(),
                    next_hop: "192.168.1.254".to_string(),
                    out_if: "lan0".to_string(),
                    metric: 10,
                },
            ],
        }
    }

    #[test]
    fn from_config_parses_routes() {
        let table = RouteTable::from_config(&make_routing_config());
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn from_config_sorted_by_prefix_len_desc() {
        let table = RouteTable::from_config(&make_routing_config());
        // /25, /24, /0
        assert_eq!(table.entries[0].prefix_len, 25);
        assert_eq!(table.entries[1].prefix_len, 24);
        assert_eq!(table.entries[2].prefix_len, 0);
    }

    #[test]
    fn from_config_skips_invalid() {
        let config = RoutingConfig {
            ipv4_static_routes: vec![
                StaticRoute {
                    prefix: "invalid/24".to_string(),
                    next_hop: "10.0.0.1".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
                StaticRoute {
                    prefix: "10.0.0.0/8".to_string(),
                    next_hop: "10.0.0.1".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
            ],
        };
        let table = RouteTable::from_config(&config);
        assert_eq!(table.len(), 1);
    }

    // ── LPM lookup tests ──────────────────────────────────────────────

    #[test]
    fn lookup_longest_match_wins() {
        let table = RouteTable::from_config(&make_routing_config());

        // 192.168.1.200 matches both /25 and /24; /25 should win.
        let result = table.lookup(&[192, 168, 1, 200]);
        assert!(result.is_some());
        let entry = result.unwrap();
        assert_eq!(entry.prefix_len, 25);
        assert_eq!(entry.next_hop, [192, 168, 1, 254]);
    }

    #[test]
    fn lookup_shorter_prefix_when_longer_does_not_match() {
        let table = RouteTable::from_config(&make_routing_config());

        // 192.168.1.10 matches /24 but not /25 (128..255 range).
        let result = table.lookup(&[192, 168, 1, 10]);
        assert!(result.is_some());
        let entry = result.unwrap();
        assert_eq!(entry.prefix_len, 24);
        assert_eq!(entry.out_ifname, "lan0");
    }

    #[test]
    fn lookup_default_route() {
        let table = RouteTable::from_config(&make_routing_config());

        // 8.8.8.8 matches only the default route.
        let result = table.lookup(&[8, 8, 8, 8]);
        assert!(result.is_some());
        let entry = result.unwrap();
        assert_eq!(entry.prefix_len, 0);
        assert_eq!(entry.next_hop, [10, 0, 0, 1]);
        assert_eq!(entry.out_ifname, "wan0");
    }

    #[test]
    fn lookup_no_match_empty_table() {
        let table = RouteTable::empty();
        assert!(table.lookup(&[10, 0, 0, 1]).is_none());
    }

    #[test]
    fn lookup_no_match_no_default() {
        let config = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "192.168.1.0/24".to_string(),
                next_hop: "0.0.0.0".to_string(),
                out_if: "lan0".to_string(),
                metric: 10,
            }],
        };
        let table = RouteTable::from_config(&config);

        // 10.0.0.1 does not match 192.168.1.0/24.
        assert!(table.lookup(&[10, 0, 0, 1]).is_none());
    }

    // ── Metric ordering tests ─────────────────────────────────────────

    #[test]
    fn lookup_prefers_lower_metric_for_same_prefix_len() {
        let config = RoutingConfig {
            ipv4_static_routes: vec![
                StaticRoute {
                    prefix: "10.0.0.0/8".to_string(),
                    next_hop: "10.0.0.2".to_string(),
                    out_if: "wan1".to_string(),
                    metric: 200,
                },
                StaticRoute {
                    prefix: "10.0.0.0/8".to_string(),
                    next_hop: "10.0.0.1".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
            ],
        };
        let table = RouteTable::from_config(&config);
        let result = table.lookup(&[10, 1, 2, 3]).unwrap();
        assert_eq!(result.metric, 100);
        assert_eq!(result.next_hop, [10, 0, 0, 1]);
    }
}

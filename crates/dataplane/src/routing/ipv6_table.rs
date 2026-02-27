//! IPv6 static route table with longest prefix match (LPM).
//!
//! Analogous to the IPv4 [`RouteTable`](super::table::RouteTable), this
//! module provides an [`Ipv6RouteTable`] for IPv6 LPM lookups.
//!
//! RFC-REF: RFC 8200 Section 3
//! IPv6 routing is based on the 128-bit destination address; the most
//! specific matching prefix determines the forwarding decision.

use std::fmt;

use crate::nd::parse_ipv6_addr;
use ruster_config::model::RoutingConfig;

/// Error describing a single invalid IPv6 route entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6RouteError {
    /// Zero-based index of the entry in the config list.
    pub index: usize,
    /// The kind of parse failure.
    pub kind: Ipv6RouteErrorKind,
    /// The raw string value that failed to parse.
    pub raw_value: String,
}

/// What went wrong when parsing an IPv6 route entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6RouteErrorKind {
    /// The prefix string could not be parsed.
    InvalidPrefix,
    /// The next-hop address string could not be parsed.
    InvalidNextHop,
}

impl fmt::Display for Ipv6RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = match &self.kind {
            Ipv6RouteErrorKind::InvalidPrefix => "prefix",
            Ipv6RouteErrorKind::InvalidNextHop => "next_hop",
        };
        write!(
            f,
            "ipv6_route[{}]: invalid {} \"{}\"",
            self.index, field, self.raw_value
        )
    }
}

impl std::error::Error for Ipv6RouteError {}

/// A single IPv6 route entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6RouteEntry {
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    pub next_hop: [u8; 16],
    pub out_ifname: String,
    pub metric: u32,
}

/// IPv6 static route table with LPM lookup.
#[derive(Debug, Clone)]
pub struct Ipv6RouteTable {
    entries: Vec<Ipv6RouteEntry>,
}

impl Ipv6RouteTable {
    /// Build an IPv6 route table from configuration.
    pub fn from_config(routing_config: &RoutingConfig) -> Result<Self, Vec<Ipv6RouteError>> {
        let mut entries: Vec<Ipv6RouteEntry> =
            Vec::with_capacity(routing_config.ipv6_static_routes.len());
        let mut errors: Vec<Ipv6RouteError> = Vec::new();

        for (index, sr) in routing_config.ipv6_static_routes.iter().enumerate() {
            let prefix_result = parse_ipv6_prefix(&sr.prefix);
            let next_hop_result = parse_ipv6_addr(&sr.next_hop);

            if prefix_result.is_none() {
                errors.push(Ipv6RouteError {
                    index,
                    kind: Ipv6RouteErrorKind::InvalidPrefix,
                    raw_value: sr.prefix.clone(),
                });
            }
            if next_hop_result.is_none() {
                errors.push(Ipv6RouteError {
                    index,
                    kind: Ipv6RouteErrorKind::InvalidNextHop,
                    raw_value: sr.next_hop.clone(),
                });
            }

            if let (Some((prefix, prefix_len)), Some(next_hop)) = (prefix_result, next_hop_result) {
                entries.push(Ipv6RouteEntry {
                    prefix,
                    prefix_len,
                    next_hop,
                    out_ifname: sr.out_if.clone(),
                    metric: sr.metric,
                });
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        // Sort by prefix_len descending, then metric ascending.
        entries.sort_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then(a.metric.cmp(&b.metric))
        });

        Ok(Self { entries })
    }

    /// Create an empty route table.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Longest prefix match lookup for an IPv6 destination.
    pub fn lookup(&self, dst_ipv6: &[u8; 16]) -> Option<&Ipv6RouteEntry> {
        self.entries
            .iter()
            .find(|entry| matches_ipv6_prefix(dst_ipv6, &entry.prefix, entry.prefix_len))
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

/// Parse a CIDR prefix string into an IPv6 address and prefix length.
///
/// Accepts formats like "2001:db8::/32" or "::/0".
pub fn parse_ipv6_prefix(prefix_str: &str) -> Option<([u8; 16], u8)> {
    let (ip_str, len_str) = prefix_str.split_once('/')?;
    let ip = parse_ipv6_addr(ip_str)?;
    let prefix_len: u8 = len_str.parse().ok()?;
    if prefix_len > 128 {
        return None;
    }
    Some((ip, prefix_len))
}

/// Check whether an IPv6 address matches a given prefix.
///
/// Compares the first `prefix_len` bits of `ip` against `prefix`.
pub fn matches_ipv6_prefix(ip: &[u8; 16], prefix: &[u8; 16], prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 128 {
        return false;
    }

    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    // Compare full bytes
    if ip[..full_bytes] != prefix[..full_bytes] {
        return false;
    }

    // Compare remaining bits
    if remaining_bits > 0 {
        let mask = 0xFF << (8 - remaining_bits);
        if (ip[full_bytes] & mask) != (prefix[full_bytes] & mask) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_config::model::{Ipv6StaticRoute, RoutingConfig};

    // ── parse_ipv6_prefix tests ─────────────────────────────────────────

    #[test]
    fn parse_prefix_valid() {
        let (ip, len) = parse_ipv6_prefix("2001:db8::/32").unwrap();
        assert_eq!(len, 32);
        assert_eq!(ip[0], 0x20);
        assert_eq!(ip[1], 0x01);
        assert_eq!(ip[2], 0x0d);
        assert_eq!(ip[3], 0xb8);
        assert_eq!(ip[4..], [0u8; 12]);
    }

    #[test]
    fn parse_prefix_default_route() {
        let (ip, len) = parse_ipv6_prefix("::/0").unwrap();
        assert_eq!(ip, [0u8; 16]);
        assert_eq!(len, 0);
    }

    #[test]
    fn parse_prefix_host_route() {
        let (_, len) = parse_ipv6_prefix("2001:db8::1/128").unwrap();
        assert_eq!(len, 128);
    }

    #[test]
    fn parse_prefix_invalid_len() {
        assert!(parse_ipv6_prefix("2001:db8::/129").is_none());
    }

    #[test]
    fn parse_prefix_no_slash() {
        assert!(parse_ipv6_prefix("2001:db8::").is_none());
    }

    // ── matches_ipv6_prefix tests ───────────────────────────────────────

    #[test]
    fn matches_default_route() {
        let ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(matches_ipv6_prefix(&ip, &[0; 16], 0));
    }

    #[test]
    fn matches_slash_64() {
        let ip = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let prefix = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches_ipv6_prefix(&ip, &prefix, 64));
    }

    #[test]
    fn no_match_slash_64() {
        let ip = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let prefix = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!matches_ipv6_prefix(&ip, &prefix, 64));
    }

    #[test]
    fn matches_host_route() {
        let ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(matches_ipv6_prefix(&ip, &ip, 128));
        let ip2 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        assert!(!matches_ipv6_prefix(&ip2, &ip, 128));
    }

    #[test]
    fn matches_slash_48() {
        // /48 = first 6 bytes must match
        let ip = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let prefix = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(matches_ipv6_prefix(&ip, &prefix, 48));
    }

    // ── Ipv6RouteTable tests ───────────────────────────────────────────

    fn make_routing_config() -> RoutingConfig {
        RoutingConfig {
            ipv4_static_routes: vec![],
            ipv6_static_routes: vec![
                Ipv6StaticRoute {
                    prefix: "::/0".to_string(),
                    next_hop: "2001:db8::1".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
                Ipv6StaticRoute {
                    prefix: "2001:db8:1::/48".to_string(),
                    next_hop: "::".to_string(),
                    out_if: "lan0".to_string(),
                    metric: 10,
                },
            ],
            ospf: None,
        }
    }

    #[test]
    fn from_config_parses_routes() {
        let table = Ipv6RouteTable::from_config(&make_routing_config()).unwrap();
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn from_config_sorted_by_prefix_len() {
        let table = Ipv6RouteTable::from_config(&make_routing_config()).unwrap();
        assert_eq!(table.entries[0].prefix_len, 48); // more specific first
        assert_eq!(table.entries[1].prefix_len, 0); // default route last
    }

    #[test]
    fn lookup_specific_route() {
        let table = Ipv6RouteTable::from_config(&make_routing_config()).unwrap();
        // 2001:db8:1::100 should match the /48 route.
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        let entry = table.lookup(&dst).unwrap();
        assert_eq!(entry.prefix_len, 48);
        assert_eq!(entry.out_ifname, "lan0");
    }

    #[test]
    fn lookup_default_route() {
        let table = Ipv6RouteTable::from_config(&make_routing_config()).unwrap();
        // 2001:db8:2::1 should fall through to the default route.
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let entry = table.lookup(&dst).unwrap();
        assert_eq!(entry.prefix_len, 0);
        assert_eq!(entry.out_ifname, "wan0");
    }

    #[test]
    fn lookup_empty_table() {
        let table = Ipv6RouteTable::empty();
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(table.lookup(&dst).is_none());
    }
}

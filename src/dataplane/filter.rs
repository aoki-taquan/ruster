//! Packet filtering engine
//!
//! Provides firewall-like packet filtering with support for:
//! - Chain-based processing (INPUT/OUTPUT/FORWARD)
//! - Match conditions (IP, port, protocol, interface)
//! - Actions (ACCEPT, DROP, REJECT)
//! - IPv4 and IPv6 support

use std::net::{Ipv4Addr, Ipv6Addr};

/// Filter chain (similar to iptables chains)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// Packets destined for the router itself
    Input,
    /// Packets originating from the router
    Output,
    /// Packets being forwarded through the router
    Forward,
}

/// Filter action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    /// Allow the packet
    #[default]
    Accept,
    /// Silently drop the packet
    Drop,
    /// Drop and send ICMP error (future: not implemented yet)
    Reject,
}

/// IP address (IPv4 or IPv6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// IPv4 CIDR range
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    addr: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// Create a new IPv4 CIDR
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            addr: Self::network_addr(addr, prefix_len),
            prefix_len,
        }
    }

    /// Parse from string like "192.168.1.0/24"
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        let addr: Ipv4Addr = parts[0].parse().ok()?;
        let prefix_len: u8 = parts[1].parse().ok()?;
        if prefix_len > 32 {
            return None;
        }
        Some(Self::new(addr, prefix_len))
    }

    /// Check if an address is within this CIDR range
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = Self::prefix_to_mask(self.prefix_len);
        let network = u32::from(self.addr);
        let target = u32::from(addr);
        (network & mask) == (target & mask)
    }

    fn network_addr(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
        let mask = Self::prefix_to_mask(prefix_len);
        Ipv4Addr::from(u32::from(addr) & mask)
    }

    fn prefix_to_mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        }
    }
}

/// IPv6 CIDR range
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    addr: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Cidr {
    /// Create a new IPv6 CIDR
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            addr: Self::network_addr(addr, prefix_len),
            prefix_len,
        }
    }

    /// Parse from string like "2001:db8::/32"
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        let addr: Ipv6Addr = parts[0].parse().ok()?;
        let prefix_len: u8 = parts[1].parse().ok()?;
        if prefix_len > 128 {
            return None;
        }
        Some(Self::new(addr, prefix_len))
    }

    /// Check if an address is within this CIDR range
    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        let mask = Self::prefix_to_mask(self.prefix_len);
        let network = u128::from(self.addr);
        let target = u128::from(addr);
        (network & mask) == (target & mask)
    }

    fn network_addr(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
        let mask = Self::prefix_to_mask(prefix_len);
        Ipv6Addr::from(u128::from(addr) & mask)
    }

    fn prefix_to_mask(prefix_len: u8) -> u128 {
        if prefix_len == 0 {
            0
        } else {
            !0u128 << (128 - prefix_len)
        }
    }
}

/// IP CIDR (IPv4 or IPv6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl IpCidr {
    /// Parse from string (auto-detect v4/v6)
    pub fn parse(s: &str) -> Option<Self> {
        // Try IPv6 first (contains ':')
        if s.contains(':') {
            Ipv6Cidr::parse(s).map(IpCidr::V6)
        } else {
            Ipv4Cidr::parse(s).map(IpCidr::V4)
        }
    }

    /// Check if an address is within this CIDR range
    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self, addr) {
            (IpCidr::V4(cidr), IpAddr::V4(a)) => cidr.contains(*a),
            (IpCidr::V6(cidr), IpAddr::V6(a)) => cidr.contains(*a),
            _ => false, // v4 cidr doesn't match v6 addr and vice versa
        }
    }
}

/// Port range for matching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Create a new port range
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    /// Create a single port
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Parse from string like "80" or "1024-65535"
    pub fn parse(s: &str) -> Option<Self> {
        if let Some((start, end)) = s.split_once('-') {
            let start: u16 = start.parse().ok()?;
            let end: u16 = end.parse().ok()?;
            Some(Self::new(start, end))
        } else {
            let port: u16 = s.parse().ok()?;
            Some(Self::single(port))
        }
    }

    /// Check if a port is within this range
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// Protocol numbers
pub mod protocol {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

/// ICMPv6 types for NDP (must not be blocked)
pub mod icmpv6_type {
    pub const ROUTER_SOLICITATION: u8 = 133;
    pub const ROUTER_ADVERTISEMENT: u8 = 134;
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
    pub const REDIRECT: u8 = 137;
}

/// Filter rule
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// Chain this rule applies to
    pub chain: Chain,
    /// Protocol number (1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6)
    pub protocol: Option<u8>,
    /// Source IP/CIDR
    pub src_ip: Option<IpCidr>,
    /// Destination IP/CIDR
    pub dst_ip: Option<IpCidr>,
    /// Source port range
    pub src_port: Option<PortRange>,
    /// Destination port range
    pub dst_port: Option<PortRange>,
    /// Input interface
    pub in_interface: Option<String>,
    /// Output interface
    pub out_interface: Option<String>,
    /// Action to take
    pub action: Action,
    /// Priority (lower = higher priority)
    pub priority: u32,
}

impl FilterRule {
    /// Create a new filter rule
    pub fn new(chain: Chain, action: Action) -> Self {
        Self {
            chain,
            protocol: None,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            in_interface: None,
            out_interface: None,
            action,
            priority: 1000,
        }
    }

    /// Check if this rule matches the given context
    pub fn matches(&self, ctx: &FilterContext) -> bool {
        // Chain must match
        if self.chain != ctx.chain {
            return false;
        }

        // Protocol must match if specified
        if let Some(proto) = self.protocol {
            if proto != ctx.protocol {
                return false;
            }
        }

        // Source IP must match if specified
        if let Some(ref cidr) = self.src_ip {
            if !cidr.contains(&ctx.src_ip) {
                return false;
            }
        }

        // Destination IP must match if specified
        if let Some(ref cidr) = self.dst_ip {
            if !cidr.contains(&ctx.dst_ip) {
                return false;
            }
        }

        // Source port must match if specified (only for TCP/UDP)
        if let Some(ref range) = self.src_port {
            match ctx.src_port {
                Some(port) => {
                    if !range.contains(port) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Destination port must match if specified (only for TCP/UDP)
        if let Some(ref range) = self.dst_port {
            match ctx.dst_port {
                Some(port) => {
                    if !range.contains(port) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Input interface must match if specified
        if let Some(ref iface) = self.in_interface {
            match ctx.in_interface {
                Some(in_if) => {
                    if iface != in_if {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Output interface must match if specified
        if let Some(ref iface) = self.out_interface {
            match ctx.out_interface {
                Some(out_if) => {
                    if iface != out_if {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

/// Filter evaluation context
#[derive(Debug)]
pub struct FilterContext<'a> {
    /// Chain being evaluated
    pub chain: Chain,
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Protocol number
    pub protocol: u8,
    /// Source port (for TCP/UDP)
    pub src_port: Option<u16>,
    /// Destination port (for TCP/UDP)
    pub dst_port: Option<u16>,
    /// Input interface name
    pub in_interface: Option<&'a str>,
    /// Output interface name
    pub out_interface: Option<&'a str>,
}

/// Packet filter engine
#[derive(Debug)]
pub struct PacketFilter {
    /// Filter rules (sorted by priority)
    rules: Vec<FilterRule>,
    /// Default action when no rule matches
    default_action: Action,
}

impl PacketFilter {
    /// Create a new packet filter with the given default action
    pub fn new(default_action: Action) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    /// Add a filter rule
    pub fn add_rule(&mut self, rule: FilterRule) {
        self.rules.push(rule);
        // Sort by priority (lower = higher priority)
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Evaluate a packet against all rules
    pub fn evaluate(&self, ctx: &FilterContext) -> Action {
        // Find first matching rule
        for rule in &self.rules {
            if rule.matches(ctx) {
                return rule.action;
            }
        }
        // No rule matched, return default action
        self.default_action
    }

    /// Get the number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Check if filter is enabled (has any rules)
    pub fn is_enabled(&self) -> bool {
        !self.rules.is_empty()
    }
}

impl Default for PacketFilter {
    fn default() -> Self {
        Self::new(Action::Accept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_cidr_parse() {
        let cidr = Ipv4Cidr::parse("192.168.1.0/24").unwrap();
        assert!(cidr.contains(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(cidr.contains(Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!cidr.contains(Ipv4Addr::new(192, 168, 2, 1)));
    }

    #[test]
    fn test_ipv4_cidr_edge_cases() {
        // /32 - single host
        let cidr = Ipv4Cidr::parse("10.0.0.1/32").unwrap();
        assert!(cidr.contains(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!cidr.contains(Ipv4Addr::new(10, 0, 0, 2)));

        // /0 - all addresses
        let cidr = Ipv4Cidr::parse("0.0.0.0/0").unwrap();
        assert!(cidr.contains(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(cidr.contains(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_ipv6_cidr_parse() {
        let cidr = Ipv6Cidr::parse("2001:db8::/32").unwrap();
        assert!(cidr.contains("2001:db8::1".parse().unwrap()));
        assert!(cidr.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!cidr.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_port_range() {
        let range = PortRange::parse("80").unwrap();
        assert!(range.contains(80));
        assert!(!range.contains(81));

        let range = PortRange::parse("1024-65535").unwrap();
        assert!(range.contains(1024));
        assert!(range.contains(65535));
        assert!(!range.contains(80));
    }

    #[test]
    fn test_filter_rule_match_protocol() {
        let mut rule = FilterRule::new(Chain::Input, Action::Accept);
        rule.protocol = Some(protocol::TCP);

        let ctx_tcp = FilterContext {
            chain: Chain::Input,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            protocol: protocol::TCP,
            src_port: Some(12345),
            dst_port: Some(80),
            in_interface: Some("eth0"),
            out_interface: None,
        };

        let ctx_udp = FilterContext {
            chain: Chain::Input,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            protocol: protocol::UDP,
            src_port: Some(12345),
            dst_port: Some(53),
            in_interface: Some("eth0"),
            out_interface: None,
        };

        assert!(rule.matches(&ctx_tcp));
        assert!(!rule.matches(&ctx_udp));
    }

    #[test]
    fn test_filter_rule_match_src_ip() {
        let mut rule = FilterRule::new(Chain::Forward, Action::Drop);
        rule.src_ip = Some(IpCidr::parse("10.0.0.0/8").unwrap());

        let ctx_match = FilterContext {
            chain: Chain::Forward,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            protocol: protocol::ICMP,
            src_port: None,
            dst_port: None,
            in_interface: None,
            out_interface: None,
        };

        let ctx_no_match = FilterContext {
            chain: Chain::Forward,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            protocol: protocol::ICMP,
            src_port: None,
            dst_port: None,
            in_interface: None,
            out_interface: None,
        };

        assert!(rule.matches(&ctx_match));
        assert!(!rule.matches(&ctx_no_match));
    }

    #[test]
    fn test_filter_rule_match_dst_port() {
        let mut rule = FilterRule::new(Chain::Input, Action::Accept);
        rule.protocol = Some(protocol::TCP);
        rule.dst_port = Some(PortRange::parse("80").unwrap());

        let ctx_http = FilterContext {
            chain: Chain::Input,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            protocol: protocol::TCP,
            src_port: Some(54321),
            dst_port: Some(80),
            in_interface: None,
            out_interface: None,
        };

        let ctx_https = FilterContext {
            chain: Chain::Input,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            protocol: protocol::TCP,
            src_port: Some(54321),
            dst_port: Some(443),
            in_interface: None,
            out_interface: None,
        };

        assert!(rule.matches(&ctx_http));
        assert!(!rule.matches(&ctx_https));
    }

    #[test]
    fn test_filter_rule_match_interface() {
        let mut rule = FilterRule::new(Chain::Forward, Action::Drop);
        rule.in_interface = Some("eth0".to_string());

        let ctx_eth0 = FilterContext {
            chain: Chain::Forward,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            protocol: protocol::TCP,
            src_port: Some(1234),
            dst_port: Some(80),
            in_interface: Some("eth0"),
            out_interface: None,
        };

        let ctx_eth1 = FilterContext {
            chain: Chain::Forward,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            protocol: protocol::TCP,
            src_port: Some(1234),
            dst_port: Some(80),
            in_interface: Some("eth1"),
            out_interface: None,
        };

        assert!(rule.matches(&ctx_eth0));
        assert!(!rule.matches(&ctx_eth1));
    }

    #[test]
    fn test_filter_ipv6() {
        let mut rule = FilterRule::new(Chain::Input, Action::Accept);
        rule.protocol = Some(protocol::ICMPV6);
        rule.src_ip = Some(IpCidr::parse("2001:db8::/32").unwrap());

        let ctx = FilterContext {
            chain: Chain::Input,
            src_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
            dst_ip: IpAddr::V6("2001:db8::2".parse().unwrap()),
            protocol: protocol::ICMPV6,
            src_port: None,
            dst_port: None,
            in_interface: None,
            out_interface: None,
        };

        assert!(rule.matches(&ctx));
    }

    #[test]
    fn test_packet_filter_priority() {
        let mut filter = PacketFilter::new(Action::Drop);

        // Add rules in reverse priority order
        let mut rule_low = FilterRule::new(Chain::Input, Action::Drop);
        rule_low.priority = 100;

        let mut rule_high = FilterRule::new(Chain::Input, Action::Accept);
        rule_high.priority = 10;

        filter.add_rule(rule_low);
        filter.add_rule(rule_high);

        let ctx = FilterContext {
            chain: Chain::Input,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            protocol: protocol::TCP,
            src_port: Some(1234),
            dst_port: Some(80),
            in_interface: None,
            out_interface: None,
        };

        // Higher priority (lower number) rule should match first
        assert_eq!(filter.evaluate(&ctx), Action::Accept);
    }

    #[test]
    fn test_packet_filter_default_action() {
        let filter = PacketFilter::new(Action::Drop);

        let ctx = FilterContext {
            chain: Chain::Input,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            protocol: protocol::TCP,
            src_port: Some(1234),
            dst_port: Some(80),
            in_interface: None,
            out_interface: None,
        };

        // No rules, should return default action
        assert_eq!(filter.evaluate(&ctx), Action::Drop);
    }

    #[test]
    fn test_packet_filter_chain_isolation() {
        let mut filter = PacketFilter::new(Action::Accept);

        let mut rule = FilterRule::new(Chain::Forward, Action::Drop);
        rule.protocol = Some(protocol::TCP);
        filter.add_rule(rule);

        // INPUT chain should not be affected by FORWARD rule
        let ctx_input = FilterContext {
            chain: Chain::Input,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            protocol: protocol::TCP,
            src_port: Some(1234),
            dst_port: Some(80),
            in_interface: None,
            out_interface: None,
        };

        assert_eq!(filter.evaluate(&ctx_input), Action::Accept);

        // FORWARD chain should match the rule
        let ctx_forward = FilterContext {
            chain: Chain::Forward,
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            protocol: protocol::TCP,
            src_port: Some(1234),
            dst_port: Some(80),
            in_interface: None,
            out_interface: None,
        };

        assert_eq!(filter.evaluate(&ctx_forward), Action::Drop);
    }
}

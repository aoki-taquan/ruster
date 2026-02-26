//! ARP (Address Resolution Protocol) engine for IPv4-to-MAC resolution.
//!
//! This module provides the [`ArpEngine`] which manages per-interface ARP
//! caches and handles incoming ARP packets (requests and replies) as well
//! as next-hop resolution for L3 forwarding.
//!
//! RFC-REF: RFC 826
//! An Ethernet Address Resolution Protocol — converts protocol addresses
//! (IPv4) to hardware addresses (Ethernet MAC) within a broadcast domain.

pub mod cache;

use std::collections::HashMap;

use crate::packet::{ArpInfo, L3Info, PacketMeta};
use cache::{ArpCache, ArpEntryState};
use ruster_config::model::{InterfaceConfig, L2Config};

/// ARP operation codes.
///
/// RFC-REF: RFC 826
/// "ar$op — 1 for request, 2 for reply"
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

/// Information needed to construct an ARP reply packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpReplyInfo {
    /// MAC address of the sender (our MAC).
    pub sender_mac: [u8; 6],
    /// IPv4 address of the sender (our IP).
    pub sender_ip: [u8; 4],
    /// MAC address of the target (original requester).
    pub target_mac: [u8; 6],
    /// IPv4 address of the target (original requester).
    pub target_ip: [u8; 4],
}

/// Action the caller should take after ARP processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpAction {
    /// We need to send an ARP reply (someone asked for our MAC).
    Reply {
        /// The interface to send the reply on.
        out_ifname: String,
        /// The ARP reply fields.
        packet: ArpReplyInfo,
    },
    /// ARP resolved; here is the destination MAC for the next hop.
    Forward {
        /// The resolved MAC address.
        resolved_mac: [u8; 6],
    },
    /// We need to send an ARP request to resolve a next hop.
    SendRequest {
        /// The interface to send the request on.
        out_ifname: String,
        /// The IPv4 address we are trying to resolve.
        target_ip: [u8; 4],
        /// Our IPv4 address (sender protocol address).
        sender_ip: [u8; 4],
        /// Our MAC address (sender hardware address).
        sender_mac: [u8; 6],
    },
    /// The packet should be dropped (e.g. no interface info for resolution).
    Drop,
    /// The ARP cache was updated (e.g. gratuitous ARP); no forwarding action.
    Update,
}

/// Per-interface state needed for ARP processing.
#[derive(Debug, Clone)]
struct InterfaceInfo {
    /// MAC address of this interface (parsed from config).
    mac: [u8; 6],
    /// IPv4 addresses assigned to this interface (parsed from config).
    ipv4_addrs: Vec<[u8; 4]>,
}

/// The ARP engine.
///
/// Manages per-interface ARP caches and interface identity information.
/// Processes incoming ARP packets and resolves next-hop addresses for
/// L3 forwarding.
#[derive(Debug)]
pub struct ArpEngine {
    /// Per-interface ARP caches (interface name -> cache).
    caches: HashMap<String, ArpCache>,
    /// Per-interface identity information (interface name -> info).
    interfaces: HashMap<String, InterfaceInfo>,
    /// ARP timeout in seconds (from configuration).
    timeout_sec: u64,
    /// Maximum ARP table entries per interface (from configuration).
    max_entries: usize,
}

impl ArpEngine {
    /// Build an ARP engine from configuration.
    ///
    /// Creates a per-interface ARP cache and stores interface IP/MAC
    /// information for responding to ARP requests.
    pub fn from_config(l2_config: &L2Config, interfaces: &[InterfaceConfig]) -> Self {
        let max_entries = l2_config.arp_table_max_entries as usize;
        let timeout_sec = u64::from(l2_config.arp_timeout_sec);

        let mut caches = HashMap::new();
        let mut if_map = HashMap::new();

        for iface in interfaces {
            caches.insert(iface.name.clone(), ArpCache::new(max_entries));

            let mac = parse_mac(&iface.mac);
            let ipv4_addrs: Vec<[u8; 4]> = iface
                .ipv4_addrs
                .iter()
                .filter_map(|addr_str| parse_ipv4_addr(addr_str))
                .collect();

            if_map.insert(iface.name.clone(), InterfaceInfo { mac, ipv4_addrs });
        }

        Self {
            caches,
            interfaces: if_map,
            timeout_sec,
            max_entries,
        }
    }

    /// Process an incoming ARP packet.
    ///
    /// Handles:
    /// - ARP Request for one of our IPs -> Reply with our MAC
    /// - ARP Reply -> Update the cache with the sender's binding
    /// - Gratuitous ARP (sender_ip == target_ip) -> Update cache if entry exists
    ///
    /// RFC-REF: RFC 826
    /// "If the pair <protocol type, sender protocol address> is already in
    /// my translation table, update the sender hardware address field [...]
    /// If I am the target protocol address, [set Merge_flag] and add the
    /// triplet to the table."
    pub fn process_arp(&mut self, meta: &PacketMeta) -> ArpAction {
        let arp_info = match &meta.l3 {
            Some(L3Info::Arp(info)) => info,
            _ => return ArpAction::Drop,
        };

        let in_ifname = &meta.in_ifname;

        // Ensure we have an ARP cache for this interface. If not, create one
        // (defensive; normally from_config already created it).
        if !self.caches.contains_key(in_ifname) {
            self.caches
                .insert(in_ifname.to_string(), ArpCache::new(self.max_entries));
        }

        // Check for gratuitous ARP: sender_ip == target_ip.
        // RFC-REF: RFC 826
        // Gratuitous ARP is used for duplicate address detection and to
        // update stale cache entries. We update only if an entry already
        // exists.
        if arp_info.sender_ip == arp_info.target_ip {
            return self.handle_gratuitous_arp(in_ifname, arp_info);
        }

        match arp_info.operation {
            ARP_OP_REQUEST => self.handle_request(in_ifname, arp_info),
            ARP_OP_REPLY => self.handle_reply(in_ifname, arp_info),
            _ => ArpAction::Drop,
        }
    }

    /// Resolve a next-hop IPv4 address to a MAC address for L3 forwarding.
    ///
    /// - If the next hop is cached and `Reachable`, return `Forward` with the MAC.
    /// - If the next hop is not cached or `Stale`, mark `Pending` and return
    ///   `SendRequest` so the caller can send an ARP request.
    /// - If we have no interface information, return `Drop`.
    pub fn resolve(&mut self, next_hop_ip: [u8; 4], out_ifname: &str) -> ArpAction {
        let if_info = match self.interfaces.get(out_ifname) {
            Some(info) => info.clone(),
            None => return ArpAction::Drop,
        };

        // Ensure we have a cache for this interface.
        if !self.caches.contains_key(out_ifname) {
            self.caches
                .insert(out_ifname.to_string(), ArpCache::new(self.max_entries));
        }

        let cache = self.caches.get_mut(out_ifname).unwrap();

        if let Some(entry) = cache.lookup(&next_hop_ip) {
            if entry.state == ArpEntryState::Reachable {
                return ArpAction::Forward {
                    resolved_mac: entry.mac,
                };
            }
            // Stale or Pending: re-request.
        }

        // Mark as pending and request resolution.
        cache.mark_pending(next_hop_ip);

        // Use the first IPv4 address on the interface as sender IP.
        let sender_ip = match if_info.ipv4_addrs.first() {
            Some(ip) => *ip,
            None => return ArpAction::Drop,
        };

        ArpAction::SendRequest {
            out_ifname: out_ifname.to_string(),
            target_ip: next_hop_ip,
            sender_ip,
            sender_mac: if_info.mac,
        }
    }

    /// Pre-populate ARP caches from the kernel's neighbor table (`/proc/net/arp`).
    ///
    /// `linux_to_logical` maps Linux device names (e.g. "eth1") to logical
    /// interface names (e.g. "lan0") used as cache keys. This is used at
    /// startup so that ruster can immediately forward packets to directly
    /// connected hosts without waiting for ARP resolution.
    ///
    /// Returns the number of entries loaded.
    #[cfg(target_os = "linux")]
    pub fn load_kernel_arp(
        &mut self,
        linux_to_logical: &std::collections::HashMap<String, String>,
    ) -> usize {
        let content = match std::fs::read_to_string("/proc/net/arp") {
            Ok(c) => c,
            Err(_) => return 0,
        };
        let mut loaded = 0;
        // /proc/net/arp format:
        // IP address       HW type     Flags       HW address            Mask     Device
        // 192.168.1.100    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth1
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                continue;
            }
            let ip_str = fields[0];
            let flags = fields[2];
            let mac_str = fields[3];
            let device = fields[5];

            // Skip incomplete entries (flags 0x0 means incomplete).
            if flags == "0x0" {
                continue;
            }

            let ip = match parse_ipv4_addr(ip_str) {
                Some(ip) => ip,
                None => continue,
            };
            let mac = parse_mac(mac_str);
            if mac == [0; 6] {
                continue;
            }

            // Map Linux device name to logical interface name.
            let logical_name = linux_to_logical
                .get(device)
                .map(|s| s.as_str())
                .unwrap_or(device);

            if let Some(cache) = self.caches.get_mut(logical_name) {
                cache.insert(ip, mac);
                loaded += 1;
            }
        }
        loaded
    }

    /// Pre-populate ARP caches from the kernel's neighbor table.
    ///
    /// On non-Linux platforms this is a no-op.
    #[cfg(not(target_os = "linux"))]
    pub fn load_kernel_arp(
        &mut self,
        _linux_to_logical: &std::collections::HashMap<String, String>,
    ) -> usize {
        0
    }

    /// Insert an ARP entry directly into the cache for a given interface.
    ///
    /// This is used for pre-populating the ARP cache (e.g. from the kernel
    /// neighbor table at startup, or in tests). Returns `true` if the
    /// interface was found and the entry was inserted.
    pub fn insert(&mut self, ifname: &str, ip: [u8; 4], mac: [u8; 6]) -> bool {
        if let Some(cache) = self.caches.get_mut(ifname) {
            cache.insert(ip, mac);
            true
        } else {
            false
        }
    }

    /// Run aging on all per-interface ARP caches.
    ///
    /// Returns the total number of entries removed across all interfaces.
    pub fn age_all(&mut self) -> usize {
        let timeout = self.timeout_sec;
        self.caches
            .values_mut()
            .map(|cache| cache.age(timeout))
            .sum()
    }

    // ── Private helpers ────────────────────────────────────────────────

    /// Handle an ARP request.
    ///
    /// If the target IP matches one of our addresses on the ingress
    /// interface, learn the sender and reply with our MAC. Otherwise,
    /// still learn the sender's binding (per RFC 826 merge logic) and
    /// return `Update`.
    fn handle_request(&mut self, in_ifname: &str, arp_info: &ArpInfo) -> ArpAction {
        let cache = self.caches.get_mut(in_ifname).unwrap();

        // RFC-REF: RFC 826
        // "If the pair <protocol type, sender protocol address> is already
        // in my translation table, update the sender hardware address field."
        // We always learn the sender's binding from a request.
        cache.insert(arp_info.sender_ip, arp_info.sender_mac);

        // Check if the target IP is ours.
        let is_target_ours = self
            .interfaces
            .get(in_ifname)
            .map(|info| info.ipv4_addrs.contains(&arp_info.target_ip))
            .unwrap_or(false);

        if is_target_ours {
            let our_mac = self.interfaces.get(in_ifname).unwrap().mac;

            ArpAction::Reply {
                out_ifname: in_ifname.to_string(),
                packet: ArpReplyInfo {
                    sender_mac: our_mac,
                    sender_ip: arp_info.target_ip,
                    target_mac: arp_info.sender_mac,
                    target_ip: arp_info.sender_ip,
                },
            }
        } else {
            ArpAction::Update
        }
    }

    /// Handle an ARP reply.
    ///
    /// Update the ARP cache with the sender's binding.
    fn handle_reply(&mut self, in_ifname: &str, arp_info: &ArpInfo) -> ArpAction {
        let cache = self.caches.get_mut(in_ifname).unwrap();
        cache.insert(arp_info.sender_ip, arp_info.sender_mac);
        ArpAction::Update
    }

    /// Handle a gratuitous ARP (sender_ip == target_ip).
    ///
    /// Update the cache only if an entry for that IP already exists.
    /// This prevents unsolicited entries from filling the cache.
    fn handle_gratuitous_arp(&mut self, in_ifname: &str, arp_info: &ArpInfo) -> ArpAction {
        let cache = self.caches.get_mut(in_ifname).unwrap();

        if cache.lookup(&arp_info.sender_ip).is_some() {
            cache.insert(arp_info.sender_ip, arp_info.sender_mac);
            ArpAction::Update
        } else {
            ArpAction::Drop
        }
    }
}

// ── Utility functions ──────────────────────────────────────────────────

/// Parse a MAC address string (e.g. "00:11:22:33:44:55") into a 6-byte array.
///
/// Returns `[0; 6]` if the string cannot be parsed (defensive; config
/// validation should catch malformed MACs before we get here).
fn parse_mac(mac_str: &str) -> [u8; 6] {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return [0; 6];
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    mac
}

/// Parse an IPv4 address string, stripping an optional CIDR prefix length.
///
/// Accepts "192.168.1.1" or "192.168.1.1/24". Returns `None` if the
/// string cannot be parsed.
fn parse_ipv4_addr(addr_str: &str) -> Option<[u8; 4]> {
    // Strip optional CIDR prefix length.
    let ip_part = addr_str.split('/').next()?;
    let parts: Vec<&str> = ip_part.split('.').collect();
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
    use crate::packet::{L2Info, PacketMeta};
    use ruster_config::model::{
        BridgeDomain, InterfaceConfig, InterfaceRole, InterfaceZone, L2Config,
    };

    // ── Test constants ─────────────────────────────────────────────

    const OUR_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const OUR_IP: [u8; 4] = [192, 168, 1, 1];

    const PEER_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const PEER_IP: [u8; 4] = [192, 168, 1, 100];

    const UNKNOWN_IP: [u8; 4] = [192, 168, 1, 200];

    const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    // ── Helpers ─────────────────────────────────────────────────────

    fn make_l2_config() -> L2Config {
        L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 120,
            bridge_domains: vec![BridgeDomain {
                name: "br0".to_string(),
                members: vec!["eth0".to_string()],
            }],
        }
    }

    fn make_interface_config() -> Vec<InterfaceConfig> {
        vec![InterfaceConfig {
            name: "eth0".to_string(),
            port_id: 0,
            role: InterfaceRole::Lan,
            admin_up: true,
            mtu: 1500,
            mac: "00:11:22:33:44:55".to_string(),
            ipv4_addrs: vec!["192.168.1.1/24".to_string()],
            zone: InterfaceZone::Lan,
            l2_domain: "br0".to_string(),
            linux_if: None,
        }]
    }

    fn make_arp_meta(
        in_ifname: &str,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        operation: u16,
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> PacketMeta {
        PacketMeta {
            in_ifname: in_ifname.to_string(),
            l2: L2Info {
                dst_mac,
                src_mac,
                ethertype: 0x0806,
            },
            l3: Some(L3Info::Arp(ArpInfo {
                operation,
                sender_mac,
                sender_ip,
                target_mac,
                target_ip,
            })),
            l4: None,
            raw_len: 42,
        }
    }

    fn make_engine() -> ArpEngine {
        ArpEngine::from_config(&make_l2_config(), &make_interface_config())
    }

    // ── Engine construction tests ──────────────────────────────────

    #[test]
    fn engine_from_config() {
        let engine = make_engine();
        assert!(engine.caches.contains_key("eth0"));
        assert_eq!(engine.timeout_sec, 120);
        assert_eq!(engine.max_entries, 256);

        let info = engine.interfaces.get("eth0").unwrap();
        assert_eq!(info.mac, OUR_MAC);
        assert_eq!(info.ipv4_addrs, vec![OUR_IP]);
    }

    // ── ARP request handling tests ─────────────────────────────────

    #[test]
    fn process_arp_request_for_our_ip() {
        let mut engine = make_engine();

        // Peer sends an ARP request asking "who has 192.168.1.1?"
        let meta = make_arp_meta(
            "eth0",
            PEER_MAC,
            BROADCAST_MAC,
            ARP_OP_REQUEST,
            PEER_MAC,
            PEER_IP,
            [0; 6],
            OUR_IP,
        );

        let action = engine.process_arp(&meta);

        // We should reply with our MAC.
        assert_eq!(
            action,
            ArpAction::Reply {
                out_ifname: "eth0".to_string(),
                packet: ArpReplyInfo {
                    sender_mac: OUR_MAC,
                    sender_ip: OUR_IP,
                    target_mac: PEER_MAC,
                    target_ip: PEER_IP,
                },
            }
        );

        // The sender's binding should be learned.
        let cache = engine.caches.get("eth0").unwrap();
        let entry = cache.lookup(&PEER_IP).expect("peer should be cached");
        assert_eq!(entry.mac, PEER_MAC);
        assert_eq!(entry.state, ArpEntryState::Reachable);
    }

    #[test]
    fn process_arp_request_not_for_us() {
        let mut engine = make_engine();

        // Peer asks for an IP that is not ours.
        let meta = make_arp_meta(
            "eth0",
            PEER_MAC,
            BROADCAST_MAC,
            ARP_OP_REQUEST,
            PEER_MAC,
            PEER_IP,
            [0; 6],
            UNKNOWN_IP,
        );

        let action = engine.process_arp(&meta);

        // We should not reply, but still learn the sender.
        assert_eq!(action, ArpAction::Update);

        let cache = engine.caches.get("eth0").unwrap();
        assert!(cache.lookup(&PEER_IP).is_some());
    }

    // ── ARP reply handling tests ───────────────────────────────────

    #[test]
    fn process_arp_reply_updates_cache() {
        let mut engine = make_engine();

        // We receive an ARP reply from peer.
        let meta = make_arp_meta(
            "eth0",
            PEER_MAC,
            OUR_MAC,
            ARP_OP_REPLY,
            PEER_MAC,
            PEER_IP,
            OUR_MAC,
            OUR_IP,
        );

        let action = engine.process_arp(&meta);
        assert_eq!(action, ArpAction::Update);

        // Cache should now contain the peer's binding.
        let cache = engine.caches.get("eth0").unwrap();
        let entry = cache.lookup(&PEER_IP).expect("peer should be cached");
        assert_eq!(entry.mac, PEER_MAC);
        assert_eq!(entry.state, ArpEntryState::Reachable);
    }

    // ── Gratuitous ARP tests ───────────────────────────────────────

    #[test]
    fn process_gratuitous_arp_updates_existing() {
        let mut engine = make_engine();

        // Pre-populate cache with peer's old MAC.
        let old_mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        engine
            .caches
            .get_mut("eth0")
            .unwrap()
            .insert(PEER_IP, old_mac);

        // Gratuitous ARP: sender_ip == target_ip, with a new MAC.
        let meta = make_arp_meta(
            "eth0",
            PEER_MAC,
            BROADCAST_MAC,
            ARP_OP_REQUEST,
            PEER_MAC,
            PEER_IP,
            [0; 6],
            PEER_IP, // gratuitous: target == sender
        );

        let action = engine.process_arp(&meta);
        assert_eq!(action, ArpAction::Update);

        // Cache should be updated with the new MAC.
        let entry = engine.caches.get("eth0").unwrap().lookup(&PEER_IP).unwrap();
        assert_eq!(entry.mac, PEER_MAC);
    }

    #[test]
    fn process_gratuitous_arp_drops_if_not_cached() {
        let mut engine = make_engine();

        // Gratuitous ARP for an IP not in cache.
        let meta = make_arp_meta(
            "eth0",
            PEER_MAC,
            BROADCAST_MAC,
            ARP_OP_REQUEST,
            PEER_MAC,
            PEER_IP,
            [0; 6],
            PEER_IP,
        );

        let action = engine.process_arp(&meta);
        assert_eq!(action, ArpAction::Drop);
    }

    // ── Resolve tests ──────────────────────────────────────────────

    #[test]
    fn resolve_cache_hit() {
        let mut engine = make_engine();

        // Pre-populate cache.
        engine
            .caches
            .get_mut("eth0")
            .unwrap()
            .insert(PEER_IP, PEER_MAC);

        let action = engine.resolve(PEER_IP, "eth0");
        assert_eq!(
            action,
            ArpAction::Forward {
                resolved_mac: PEER_MAC,
            }
        );
    }

    #[test]
    fn resolve_cache_miss_sends_request() {
        let mut engine = make_engine();

        let action = engine.resolve(PEER_IP, "eth0");
        assert_eq!(
            action,
            ArpAction::SendRequest {
                out_ifname: "eth0".to_string(),
                target_ip: PEER_IP,
                sender_ip: OUR_IP,
                sender_mac: OUR_MAC,
            }
        );

        // The IP should now be pending in cache.
        let cache = engine.caches.get("eth0").unwrap();
        let entry = cache.lookup(&PEER_IP).expect("should be pending");
        assert_eq!(entry.state, ArpEntryState::Pending);
    }

    #[test]
    fn resolve_unknown_interface_drops() {
        let mut engine = make_engine();

        let action = engine.resolve(PEER_IP, "unknown_if");
        assert_eq!(action, ArpAction::Drop);
    }

    // ── Aging tests ────────────────────────────────────────────────

    #[test]
    fn age_all_removes_old_entries() {
        let l2_config = L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 0, // Age everything immediately.
            bridge_domains: vec![BridgeDomain {
                name: "br0".to_string(),
                members: vec!["eth0".to_string()],
            }],
        };
        let mut engine = ArpEngine::from_config(&l2_config, &make_interface_config());

        // Insert an entry.
        engine
            .caches
            .get_mut("eth0")
            .unwrap()
            .insert(PEER_IP, PEER_MAC);

        let removed = engine.age_all();
        assert_eq!(removed, 1);
        assert!(engine.caches.get("eth0").unwrap().is_empty());
    }

    // ── Non-ARP packet test ────────────────────────────────────────

    #[test]
    fn process_non_arp_packet_drops() {
        let mut engine = make_engine();

        let meta = PacketMeta {
            in_ifname: "eth0".to_string(),
            l2: L2Info {
                dst_mac: OUR_MAC,
                src_mac: PEER_MAC,
                ethertype: 0x0800,
            },
            l3: None,
            l4: None,
            raw_len: 64,
        };

        let action = engine.process_arp(&meta);
        assert_eq!(action, ArpAction::Drop);
    }

    // ── Utility function tests ─────────────────────────────────────

    #[test]
    fn test_parse_mac() {
        assert_eq!(
            parse_mac("00:11:22:33:44:55"),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert_eq!(
            parse_mac("ff:ff:ff:ff:ff:ff"),
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // Invalid input returns zeroed MAC.
        assert_eq!(parse_mac("invalid"), [0; 6]);
    }

    #[test]
    fn test_parse_ipv4_addr() {
        assert_eq!(parse_ipv4_addr("192.168.1.1"), Some([192, 168, 1, 1]));
        assert_eq!(parse_ipv4_addr("192.168.1.1/24"), Some([192, 168, 1, 1]));
        assert_eq!(parse_ipv4_addr("10.0.0.1/8"), Some([10, 0, 0, 1]));
        assert_eq!(parse_ipv4_addr("invalid"), None);
    }
}

//! Neighbor Discovery (ND) engine for IPv6 address resolution.
//!
//! This module provides the [`NdEngine`] which manages per-interface ND
//! caches and handles incoming Neighbor Solicitation/Advertisement messages,
//! as well as next-hop resolution for IPv6 L3 forwarding.
//!
//! RFC-REF: RFC 4861
//! Neighbor Discovery for IP version 6 (IPv6) — provides address
//! resolution (analogous to ARP for IPv4), router discovery, and
//! prefix/parameter discovery.

use std::collections::HashMap;
use std::time::Instant;

use crate::packet::{Ipv6Info, L3Info, L4Info, NdInfo, PacketMeta};
use ruster_config::model::{InterfaceConfig, L2Config};

/// Action the caller should take after ND processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdAction {
    /// We need to send a Neighbor Advertisement (someone asked for our MAC).
    Reply {
        /// The interface to send the reply on.
        out_ifname: String,
        /// The NA packet fields.
        packet: NaReplyInfo,
    },
    /// ND resolved; here is the destination MAC for the next hop.
    Forward {
        /// The resolved MAC address.
        resolved_mac: [u8; 6],
    },
    /// We need to send a Neighbor Solicitation to resolve a next hop.
    SendSolicitation {
        /// The interface to send the solicitation on.
        out_ifname: String,
        /// The IPv6 address we are trying to resolve.
        target_ipv6: [u8; 16],
        /// Our IPv6 address (source).
        sender_ipv6: [u8; 16],
        /// Our MAC address (source link-layer address option).
        sender_mac: [u8; 6],
    },
    /// The packet should be dropped.
    Drop,
    /// The ND cache was updated; no forwarding action needed.
    Update,
}

/// Information needed to construct a Neighbor Advertisement reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaReplyInfo {
    /// Our MAC address (source link-layer address).
    pub sender_mac: [u8; 6],
    /// Our IPv6 address (source IP).
    pub sender_ipv6: [u8; 16],
    /// The target IPv6 address being advertised (same as the NS target).
    pub target_ipv6: [u8; 16],
    /// The requester's MAC address (destination).
    pub requester_mac: [u8; 6],
    /// The requester's IPv6 address (destination IP).
    pub requester_ipv6: [u8; 16],
}

/// State of an ND cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdEntryState {
    /// Confirmed by a recent NA or NS.
    Reachable,
    /// An NS has been sent but no NA received yet.
    Pending,
}

/// A single ND cache entry.
#[derive(Debug, Clone)]
pub struct NdEntry {
    /// The resolved MAC address (meaningless when state is `Pending`).
    pub mac: [u8; 6],
    /// The time this entry was learned or last refreshed.
    pub learned_at: Instant,
    /// Current state.
    pub state: NdEntryState,
}

/// Per-interface ND cache: IPv6 address -> MAC resolution.
#[derive(Debug)]
pub struct NdCache {
    entries: HashMap<[u8; 16], NdEntry>,
    max_entries: usize,
}

impl NdCache {
    /// Create a new ND cache with the given maximum capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Look up an IPv6 address.
    pub fn lookup(&self, ipv6: &[u8; 16]) -> Option<&NdEntry> {
        self.entries.get(ipv6)
    }

    /// Insert or update an entry as `Reachable`.
    pub fn insert(&mut self, ipv6: [u8; 16], mac: [u8; 6]) {
        if self.entries.contains_key(&ipv6) {
            let entry = self.entries.get_mut(&ipv6).unwrap();
            entry.mac = mac;
            entry.learned_at = Instant::now();
            entry.state = NdEntryState::Reachable;
        } else if self.entries.len() < self.max_entries {
            self.entries.insert(
                ipv6,
                NdEntry {
                    mac,
                    learned_at: Instant::now(),
                    state: NdEntryState::Reachable,
                },
            );
        }
    }

    /// Mark an IPv6 address as `Pending`.
    pub fn mark_pending(&mut self, ipv6: [u8; 16]) {
        if let Some(entry) = self.entries.get_mut(&ipv6) {
            entry.state = NdEntryState::Pending;
            entry.learned_at = Instant::now();
        } else if self.entries.len() < self.max_entries {
            self.entries.insert(
                ipv6,
                NdEntry {
                    mac: [0; 6],
                    learned_at: Instant::now(),
                    state: NdEntryState::Pending,
                },
            );
        }
    }

    /// Remove entries older than `timeout_sec` seconds.
    pub fn age(&mut self, timeout_sec: u64) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now.duration_since(entry.learned_at).as_secs() < timeout_sec);
        before - self.entries.len()
    }

    /// Return the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Per-interface identity for ND processing.
#[derive(Debug, Clone)]
struct InterfaceInfo {
    mac: [u8; 6],
    ipv6_addrs: Vec<[u8; 16]>,
}

/// The ND engine.
///
/// Manages per-interface ND caches and interface identity information.
/// Processes incoming ND messages and resolves next-hop IPv6 addresses.
#[derive(Debug)]
pub struct NdEngine {
    caches: HashMap<String, NdCache>,
    interfaces: HashMap<String, InterfaceInfo>,
    max_entries: usize,
}

impl NdEngine {
    /// Build an ND engine from configuration.
    pub fn from_config(l2_config: &L2Config, interfaces: &[InterfaceConfig]) -> Self {
        // Reuse the ARP table limits for ND cache (reasonable for home-lab).
        let max_entries = l2_config.arp_table_max_entries as usize;

        let mut caches = HashMap::new();
        let mut if_map = HashMap::new();

        for iface in interfaces {
            caches.insert(iface.name.clone(), NdCache::new(max_entries));

            let mac = parse_mac(&iface.mac);
            let ipv6_addrs: Vec<[u8; 16]> = iface
                .ipv6_addrs
                .iter()
                .filter_map(|addr_str| parse_ipv6_addr(addr_str))
                .collect();

            if_map.insert(iface.name.clone(), InterfaceInfo { mac, ipv6_addrs });
        }

        Self {
            caches,
            interfaces: if_map,
            max_entries,
        }
    }

    /// Process an incoming ND packet (Neighbor Solicitation or Advertisement).
    ///
    /// RFC-REF: RFC 4861 Section 7.1, 7.2
    pub fn process_nd(&mut self, meta: &PacketMeta) -> NdAction {
        // Extract IPv6 + ICMPv6 + ND info from the packet.
        let ipv6_info = match &meta.l3 {
            Some(L3Info::Ipv6(info)) => info,
            _ => return NdAction::Drop,
        };

        let icmpv6_info = match &meta.l4 {
            Some(L4Info::Icmpv6(info)) => info,
            _ => return NdAction::Drop,
        };

        let nd_info = match &icmpv6_info.nd {
            Some(nd) => nd,
            None => return NdAction::Drop,
        };

        let in_ifname = &meta.in_ifname;

        // Ensure we have a cache for this interface.
        if !self.caches.contains_key(in_ifname) {
            self.caches
                .insert(in_ifname.to_string(), NdCache::new(self.max_entries));
        }

        match nd_info {
            NdInfo::NeighborSolicitation {
                target_addr,
                source_mac,
            } => self.handle_ns(
                in_ifname,
                ipv6_info,
                target_addr,
                source_mac,
                meta.l2.src_mac,
            ),
            NdInfo::NeighborAdvertisement {
                target_addr,
                target_mac,
            } => self.handle_na(in_ifname, target_addr, target_mac),
        }
    }

    /// Resolve an IPv6 next-hop address to a MAC address.
    pub fn resolve(&mut self, next_hop_ipv6: [u8; 16], out_ifname: &str) -> NdAction {
        let if_info = match self.interfaces.get(out_ifname) {
            Some(info) => info.clone(),
            None => return NdAction::Drop,
        };

        if !self.caches.contains_key(out_ifname) {
            self.caches
                .insert(out_ifname.to_string(), NdCache::new(self.max_entries));
        }

        let cache = self.caches.get_mut(out_ifname).unwrap();

        if let Some(entry) = cache.lookup(&next_hop_ipv6) {
            if entry.state == NdEntryState::Reachable {
                return NdAction::Forward {
                    resolved_mac: entry.mac,
                };
            }
        }

        cache.mark_pending(next_hop_ipv6);

        let sender_ipv6 = match if_info.ipv6_addrs.first() {
            Some(ip) => *ip,
            None => return NdAction::Drop,
        };

        NdAction::SendSolicitation {
            out_ifname: out_ifname.to_string(),
            target_ipv6: next_hop_ipv6,
            sender_ipv6,
            sender_mac: if_info.mac,
        }
    }

    /// Insert an ND entry directly (for testing or pre-population).
    pub fn insert(&mut self, ifname: &str, ipv6: [u8; 16], mac: [u8; 6]) -> bool {
        if let Some(cache) = self.caches.get_mut(ifname) {
            cache.insert(ipv6, mac);
            true
        } else {
            false
        }
    }

    /// Run aging on all per-interface ND caches.
    pub fn age_all(&mut self, timeout_sec: u64) -> usize {
        self.caches
            .values_mut()
            .map(|cache| cache.age(timeout_sec))
            .sum()
    }

    /// Check if the given IPv6 address is one of the router's local addresses.
    pub fn is_local_ipv6(&self, ipv6: &[u8; 16]) -> bool {
        self.interfaces
            .values()
            .any(|info| info.ipv6_addrs.contains(ipv6))
    }

    // ── Private helpers ────────────────────────────────────────────────

    /// Handle Neighbor Solicitation.
    fn handle_ns(
        &mut self,
        in_ifname: &str,
        ipv6_info: &Ipv6Info,
        target_addr: &[u8; 16],
        source_mac: &Option<[u8; 6]>,
        l2_src_mac: [u8; 6],
    ) -> NdAction {
        let cache = self.caches.get_mut(in_ifname).unwrap();

        // Learn the sender's binding if we have their MAC.
        if let Some(mac) = source_mac {
            cache.insert(ipv6_info.src_addr, *mac);
        }

        // Check if the target is one of our addresses.
        let is_target_ours = self
            .interfaces
            .get(in_ifname)
            .map(|info| info.ipv6_addrs.contains(target_addr))
            .unwrap_or(false);

        if is_target_ours {
            let our_mac = self.interfaces.get(in_ifname).unwrap().mac;
            NdAction::Reply {
                out_ifname: in_ifname.to_string(),
                packet: NaReplyInfo {
                    sender_mac: our_mac,
                    sender_ipv6: *target_addr,
                    target_ipv6: *target_addr,
                    // Use the ND option source MAC if available, otherwise
                    // fall back to the Ethernet source MAC from L2 header.
                    requester_mac: source_mac.unwrap_or(l2_src_mac),
                    requester_ipv6: ipv6_info.src_addr,
                },
            }
        } else {
            NdAction::Update
        }
    }

    /// Handle Neighbor Advertisement.
    fn handle_na(
        &mut self,
        in_ifname: &str,
        target_addr: &[u8; 16],
        target_mac: &Option<[u8; 6]>,
    ) -> NdAction {
        if let Some(mac) = target_mac {
            let cache = self.caches.get_mut(in_ifname).unwrap();
            cache.insert(*target_addr, *mac);
        }
        NdAction::Update
    }
}

// ── NA packet construction ───────────────────────────────────────────────

/// Build a complete Ethernet + IPv6 + ICMPv6 Neighbor Advertisement packet.
///
/// RFC-REF: RFC 4861 Section 4.4
/// The NA includes the Solicited (S) and Override (O) flags set, the
/// target address, and a Target Link-Layer Address option.
pub fn build_na_packet(reply: &NaReplyInfo) -> Vec<u8> {
    // Ethernet header (14 bytes)
    let mut pkt = Vec::with_capacity(86);
    pkt.extend_from_slice(&reply.requester_mac); // dst MAC
    pkt.extend_from_slice(&reply.sender_mac); // src MAC
    pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6

    // IPv6 header (40 bytes)
    // Version (4) + Traffic Class (8) + Flow Label (20)
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    // Payload Length: ICMPv6 header (4) + flags/reserved (4) + target (16) + option (8) = 32
    let payload_len: u16 = 32;
    pkt.extend_from_slice(&payload_len.to_be_bytes());
    pkt.push(58); // Next Header: ICMPv6
    pkt.push(255); // Hop Limit
    pkt.extend_from_slice(&reply.sender_ipv6); // Source IPv6
    pkt.extend_from_slice(&reply.requester_ipv6); // Destination IPv6

    // ICMPv6 Neighbor Advertisement (type 136, code 0)
    let icmpv6_start = pkt.len();
    pkt.push(136); // Type: Neighbor Advertisement
    pkt.push(0); // Code
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
                                          // Flags: R=0, S=1 (solicited), O=1 (override) = 0x60
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&reply.target_ipv6); // Target Address

    // Target Link-Layer Address option (type=2, length=1 = 8 bytes)
    pkt.push(2); // Option type: Target Link-Layer Address
    pkt.push(1); // Option length: 1 (in units of 8 bytes)
    pkt.extend_from_slice(&reply.sender_mac);

    // Compute ICMPv6 checksum (RFC 4443 Section 2.3).
    // The checksum covers the IPv6 pseudo-header + ICMPv6 message.
    let icmpv6_data = &pkt[icmpv6_start..];
    let checksum = compute_icmpv6_checksum(&reply.sender_ipv6, &reply.requester_ipv6, icmpv6_data);
    pkt[icmpv6_start + 2] = (checksum >> 8) as u8;
    pkt[icmpv6_start + 3] = (checksum & 0xFF) as u8;

    pkt
}

/// Compute the ICMPv6 checksum per RFC 4443 Section 2.3.
///
/// The checksum covers a pseudo-header (src IPv6, dst IPv6, upper-layer
/// packet length, next header = 58) plus the ICMPv6 message body.
fn compute_icmpv6_checksum(src_ipv6: &[u8; 16], dst_ipv6: &[u8; 16], icmpv6_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address (16 bytes)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src_ipv6[i], src_ipv6[i + 1]]) as u32;
    }
    // Pseudo-header: destination address (16 bytes)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst_ipv6[i], dst_ipv6[i + 1]]) as u32;
    }
    // Pseudo-header: upper-layer packet length (4 bytes)
    let length = icmpv6_data.len() as u32;
    sum += length >> 16;
    sum += length & 0xFFFF;
    // Pseudo-header: next header = 58 (ICMPv6)
    sum += 58u32;

    // ICMPv6 message body
    let mut i = 0;
    while i + 1 < icmpv6_data.len() {
        sum += u16::from_be_bytes([icmpv6_data[i], icmpv6_data[i + 1]]) as u32;
        i += 2;
    }
    if i < icmpv6_data.len() {
        sum += (icmpv6_data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

// ── Utility functions ──────────────────────────────────────────────────

/// Parse a MAC address string (e.g. "00:11:22:33:44:55") into a 6-byte array.
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

/// Parse an IPv6 address string, stripping an optional prefix length.
///
/// Accepts "2001:db8::1" or "2001:db8::1/64".
/// Delegates to `std::net::Ipv6Addr` for full RFC 5952 compliance.
pub fn parse_ipv6_addr(addr_str: &str) -> Option<[u8; 16]> {
    let ip_part = addr_str.split('/').next()?;
    ip_part
        .parse::<std::net::Ipv6Addr>()
        .ok()
        .map(|a| a.octets())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Icmpv6Info, L2Info, L4Info, PacketMeta};
    use ruster_config::model::{
        BridgeDomain, InterfaceConfig, InterfaceRole, InterfaceZone, L2Config,
    };

    const OUR_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const OUR_IPV6: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    const PEER_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const PEER_IPV6: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    fn make_l2_config() -> L2Config {
        L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 120,
            arp_hold_queue_max: None,
            arp_hold_queue_per_ip: None,
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
            ipv4_addrs: vec![],
            ipv6_addrs: vec!["2001:db8::1/64".to_string()],
            zone: InterfaceZone::Lan,
            l2_domain: "br0".to_string(),
            linux_if: None,
        }]
    }

    fn make_engine() -> NdEngine {
        NdEngine::from_config(&make_l2_config(), &make_interface_config())
    }

    fn make_ns_meta(
        in_ifname: &str,
        src_ipv6: [u8; 16],
        target_ipv6: [u8; 16],
        source_mac: Option<[u8; 6]>,
    ) -> PacketMeta {
        PacketMeta {
            in_ifname: in_ifname.to_string(),
            l2: L2Info {
                dst_mac: [0x33, 0x33, 0xFF, 0x00, 0x00, 0x01], // solicited-node multicast
                src_mac: PEER_MAC,
                ethertype: 0x86DD,
            },
            l3: Some(L3Info::Ipv6(Ipv6Info {
                src_addr: src_ipv6,
                dst_addr: target_ipv6,
                hop_limit: 255,
                next_header: 58,
                payload_length: 32,
                traffic_class: 0,
                flow_label: 0,
                payload_offset: 54,
            })),
            l4: Some(L4Info::Icmpv6(Icmpv6Info {
                icmpv6_type: 135,
                icmpv6_code: 0,
                checksum: 0,
                nd: Some(NdInfo::NeighborSolicitation {
                    target_addr: target_ipv6,
                    source_mac,
                }),
            })),
            raw_len: 86,
        }
    }

    fn make_na_meta(
        in_ifname: &str,
        target_ipv6: [u8; 16],
        target_mac: Option<[u8; 6]>,
    ) -> PacketMeta {
        PacketMeta {
            in_ifname: in_ifname.to_string(),
            l2: L2Info {
                dst_mac: OUR_MAC,
                src_mac: PEER_MAC,
                ethertype: 0x86DD,
            },
            l3: Some(L3Info::Ipv6(Ipv6Info {
                src_addr: PEER_IPV6,
                dst_addr: OUR_IPV6,
                hop_limit: 255,
                next_header: 58,
                payload_length: 32,
                traffic_class: 0,
                flow_label: 0,
                payload_offset: 54,
            })),
            l4: Some(L4Info::Icmpv6(Icmpv6Info {
                icmpv6_type: 136,
                icmpv6_code: 0,
                checksum: 0,
                nd: Some(NdInfo::NeighborAdvertisement {
                    target_addr: target_ipv6,
                    target_mac,
                }),
            })),
            raw_len: 86,
        }
    }

    // ── Engine construction ───────────────────────────────────────────

    #[test]
    fn engine_from_config() {
        let engine = make_engine();
        assert!(engine.caches.contains_key("eth0"));
        let info = engine.interfaces.get("eth0").unwrap();
        assert_eq!(info.mac, OUR_MAC);
        assert_eq!(info.ipv6_addrs, vec![OUR_IPV6]);
    }

    // ── NS handling ────────────────────────────────────────────────────

    #[test]
    fn process_ns_for_our_ip() {
        let mut engine = make_engine();
        let meta = make_ns_meta("eth0", PEER_IPV6, OUR_IPV6, Some(PEER_MAC));
        let action = engine.process_nd(&meta);

        match action {
            NdAction::Reply { out_ifname, packet } => {
                assert_eq!(out_ifname, "eth0");
                assert_eq!(packet.sender_mac, OUR_MAC);
                assert_eq!(packet.sender_ipv6, OUR_IPV6);
                assert_eq!(packet.requester_mac, PEER_MAC);
            }
            _ => panic!("expected Reply, got {:?}", action),
        }

        // Peer should be learned in cache.
        let cache = engine.caches.get("eth0").unwrap();
        let entry = cache.lookup(&PEER_IPV6).expect("peer should be cached");
        assert_eq!(entry.mac, PEER_MAC);
        assert_eq!(entry.state, NdEntryState::Reachable);
    }

    #[test]
    fn process_ns_not_for_us() {
        let mut engine = make_engine();
        let other_ipv6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF,
        ];
        let meta = make_ns_meta("eth0", PEER_IPV6, other_ipv6, Some(PEER_MAC));
        let action = engine.process_nd(&meta);
        assert_eq!(action, NdAction::Update);
    }

    // ── NA handling ────────────────────────────────────────────────────

    #[test]
    fn process_na_updates_cache() {
        let mut engine = make_engine();
        let meta = make_na_meta("eth0", PEER_IPV6, Some(PEER_MAC));
        let action = engine.process_nd(&meta);
        assert_eq!(action, NdAction::Update);

        let cache = engine.caches.get("eth0").unwrap();
        let entry = cache.lookup(&PEER_IPV6).expect("peer should be cached");
        assert_eq!(entry.mac, PEER_MAC);
    }

    // ── Resolve ────────────────────────────────────────────────────────

    #[test]
    fn resolve_cache_hit() {
        let mut engine = make_engine();
        engine.insert("eth0", PEER_IPV6, PEER_MAC);

        let action = engine.resolve(PEER_IPV6, "eth0");
        assert_eq!(
            action,
            NdAction::Forward {
                resolved_mac: PEER_MAC,
            }
        );
    }

    #[test]
    fn resolve_cache_miss() {
        let mut engine = make_engine();
        let action = engine.resolve(PEER_IPV6, "eth0");

        match action {
            NdAction::SendSolicitation {
                out_ifname,
                target_ipv6,
                sender_ipv6,
                sender_mac,
            } => {
                assert_eq!(out_ifname, "eth0");
                assert_eq!(target_ipv6, PEER_IPV6);
                assert_eq!(sender_ipv6, OUR_IPV6);
                assert_eq!(sender_mac, OUR_MAC);
            }
            _ => panic!("expected SendSolicitation, got {:?}", action),
        }

        // Should be pending in cache.
        let cache = engine.caches.get("eth0").unwrap();
        let entry = cache.lookup(&PEER_IPV6).expect("should be pending");
        assert_eq!(entry.state, NdEntryState::Pending);
    }

    #[test]
    fn resolve_unknown_interface() {
        let mut engine = make_engine();
        let action = engine.resolve(PEER_IPV6, "unknown_if");
        assert_eq!(action, NdAction::Drop);
    }

    // ── Local IP check ─────────────────────────────────────────────────

    #[test]
    fn is_local_ipv6_true() {
        let engine = make_engine();
        assert!(engine.is_local_ipv6(&OUR_IPV6));
    }

    #[test]
    fn is_local_ipv6_false() {
        let engine = make_engine();
        assert!(!engine.is_local_ipv6(&PEER_IPV6));
    }

    // ── IPv6 address parsing ───────────────────────────────────────────

    #[test]
    fn parse_ipv6_addr_full() {
        let result = parse_ipv6_addr("2001:0db8:0000:0000:0000:0000:0000:0001");
        assert_eq!(result, Some(OUR_IPV6));
    }

    #[test]
    fn parse_ipv6_addr_compressed() {
        let result = parse_ipv6_addr("2001:db8::1");
        assert_eq!(result, Some(OUR_IPV6));
    }

    #[test]
    fn parse_ipv6_addr_with_prefix() {
        let result = parse_ipv6_addr("2001:db8::1/64");
        assert_eq!(result, Some(OUR_IPV6));
    }

    #[test]
    fn parse_ipv6_addr_all_zeros() {
        let result = parse_ipv6_addr("::");
        assert_eq!(result, Some([0u8; 16]));
    }

    #[test]
    fn parse_ipv6_addr_loopback() {
        let result = parse_ipv6_addr("::1");
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert_eq!(result, Some(expected));
    }

    // ── ND cache unit tests ────────────────────────────────────────────

    #[test]
    fn cache_insert_and_lookup() {
        let mut cache = NdCache::new(100);
        cache.insert(OUR_IPV6, OUR_MAC);
        let entry = cache.lookup(&OUR_IPV6).unwrap();
        assert_eq!(entry.mac, OUR_MAC);
        assert_eq!(entry.state, NdEntryState::Reachable);
    }

    #[test]
    fn cache_miss() {
        let cache = NdCache::new(100);
        assert!(cache.lookup(&OUR_IPV6).is_none());
    }

    #[test]
    fn cache_pending_resolved() {
        let mut cache = NdCache::new(100);
        cache.mark_pending(OUR_IPV6);
        assert_eq!(
            cache.lookup(&OUR_IPV6).unwrap().state,
            NdEntryState::Pending
        );
        cache.insert(OUR_IPV6, OUR_MAC);
        assert_eq!(
            cache.lookup(&OUR_IPV6).unwrap().state,
            NdEntryState::Reachable
        );
    }

    #[test]
    fn cache_max_entries() {
        let mut cache = NdCache::new(1);
        cache.insert(OUR_IPV6, OUR_MAC);
        cache.insert(PEER_IPV6, PEER_MAC);
        assert_eq!(cache.len(), 1);
        assert!(cache.lookup(&PEER_IPV6).is_none());
    }
}

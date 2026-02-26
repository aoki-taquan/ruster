//! Pipeline processing orchestration for the ruster dataplane.
//!
//! Processes a single packet through the forwarding path:
//!
//! ```text
//! parse -> L3 route -> firewall -> forward/drop
//! ```
//!
//! The main entry point is [`process_packet`], which takes a raw packet
//! and references to the forwarding engines, then returns a
//! [`PipelineResult`] indicating whether the packet should be forwarded,
//! dropped, or was consumed internally.

use std::collections::HashMap;

use crate::conntrack::session::{SessionKey, SessionState, TcpState};
use crate::conntrack::{ConntrackEngine, ConntrackError};
use crate::firewall::{FirewallEngine, FwChain, FwContext, FwVerdict};
use crate::icmp::{self, IcmpReply};
use crate::io::RawPacket;
use crate::l2::bridge::L2Decision;
use crate::l2::L2Engine;
use crate::packet;
use crate::packet::{L3Info, L4Info};
use crate::routing::{L3Decision, L3DropReason, L3Engine};

use ruster_config::model::{FirewallZone, InterfaceConfig, InterfaceZone};

// ── Zone resolver ─────────────────────────────────────────────────

/// Maps interface names to their firewall zones.
#[derive(Debug, Clone)]
pub struct ZoneResolver {
    zones: HashMap<String, FirewallZone>,
}

impl ZoneResolver {
    /// Build a zone resolver from interface configuration.
    pub fn from_config(interfaces: &[InterfaceConfig]) -> Self {
        let zones = interfaces
            .iter()
            .map(|iface| {
                let zone = match iface.zone {
                    InterfaceZone::Lan => FirewallZone::Lan,
                    InterfaceZone::Wan => FirewallZone::Wan,
                };
                (iface.name.clone(), zone)
            })
            .collect();
        Self { zones }
    }

    /// Resolve the firewall zone for a given interface name.
    /// Returns `FirewallZone::Lan` as default if the interface is not found.
    pub fn resolve(&self, iface: &str) -> FirewallZone {
        self.zones.get(iface).copied().unwrap_or(FirewallZone::Lan)
    }
}

// ── Pipeline result types ───────────────────────────────────────────

/// Result of processing a single packet through the pipeline.
#[derive(Debug)]
pub enum PipelineResult {
    /// Packet should be forwarded out the given interface.
    Forward {
        /// Name of the egress interface.
        egress_iface: String,
        /// New TTL after L3 decrement (Some for L3 forwarded packets, None for L2-only).
        new_ttl: Option<u8>,
        /// Next-hop IPv4 address (Some for L3 forwarded packets, None for L2-only).
        next_hop: Option<[u8; 4]>,
    },
    /// Packet should be flooded to all listed interfaces (L2 unknown
    /// unicast or broadcast within a bridge domain).
    Flood {
        /// Names of the egress interfaces (excludes the ingress port).
        egress_ifaces: Vec<String>,
    },
    /// Packet was dropped.
    Drop {
        /// Why the packet was dropped.
        reason: DropReason,
        /// Optional ICMP error reply to send back to the original sender.
        /// Present for TTL expired and no-route drops (when the original
        /// packet is not itself ICMP).
        icmp_reply: Option<IcmpReply>,
    },
    /// Packet was consumed (e.g., ARP reply generated internally).
    Consumed,
}

/// Reason a packet was dropped during pipeline processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The raw bytes could not be parsed into a valid packet.
    ParseError,
    /// L2 engine dropped the packet.
    L2Drop,
    /// L3 engine found no matching route.
    L3NoRoute,
    /// L3 engine detected TTL expiration.
    L3TtlExpired,
    /// L3 engine received a non-IPv4 packet.
    L3NotIpv4,
    /// Firewall dropped the packet.
    FirewallDrop,
    /// NAT engine dropped the packet.
    NatDrop,
    /// Conntrack session table is full.
    ConntrackTableFull,
}

// ── Pipeline function ───────────────────────────────────────────────

/// Result of a conntrack lookup/create attempt for the pipeline.
///
/// Used internally by [`process_packet`] to communicate conntrack
/// state to downstream stages (firewall, NAT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackResult {
    /// Existing session matched (forward or reverse direction).
    Existing,
    /// New session was created.
    Created,
    /// Session table is full; the packet should be dropped.
    TableFull,
    /// Packet is not trackable (non-IPv4 or no L4 header).
    Untracked,
}

/// Process a single raw packet through the forwarding pipeline.
///
/// The processing flow is:
/// 1. Parse the raw bytes into a [`PacketMeta`](packet::PacketMeta).
/// 2. If parsing fails, return `Drop(ParseError)`.
/// 3. **L2 check**: if the ingress interface belongs to a bridge domain:
///    a. Learn source MAC (FDB update).
///    b. If the destination IP is one of the router's local IPs,
///       fall through to L3 processing.
///    c. Otherwise, make an L2 forwarding decision:
///       Known unicast -> `Forward` to the learned port.
///       Unknown unicast / broadcast -> `Flood` to all bridge domain
///       ports except ingress.
///       Same-port drop -> `Drop(L2Drop)`.
/// 4. If the interface is **not** in a bridge domain, proceed to L3.
/// 5. **Conntrack lookup/create**: for every trackable packet, look up
///    both forward and reverse session keys. Create a new session for
///    new flows; update TCP state and refresh timestamps for existing
///    sessions.
/// 6. Check L3 routing via [`L3Engine::process`].
/// 7. Based on the L3 decision:
///    - `Forward { .. }` -> check firewall -> `Forward` or `Drop(FirewallDrop)`.
///    - `LocalDelivery` -> `Consumed`.
///    - `Drop(reason)` -> `Drop` with a mapped reason.
pub fn process_packet(
    raw_pkt: &RawPacket,
    l2: &mut L2Engine,
    l3: &L3Engine,
    firewall: &FirewallEngine,
    conntrack: &mut ConntrackEngine,
    zone_resolver: &ZoneResolver,
    iface_macs: &std::collections::HashMap<String, [u8; 6]>,
) -> PipelineResult {
    // Step 1: Parse raw bytes.
    let meta = match packet::parse_packet(&raw_pkt.data, &raw_pkt.ingress_iface) {
        Ok(m) => m,
        Err(_) => {
            return PipelineResult::Drop {
                reason: DropReason::ParseError,
                icmp_reply: None,
            }
        }
    };

    // Step 2: L2 bridge domain processing.
    if l2.is_bridged(&meta.in_ifname) {
        let l2_decision = l2.process(&meta);

        // Check whether the packet should be punted to L3 processing.
        // This happens when either:
        // - The destination IP is one of the router's own IPs (local delivery), OR
        // - The destination MAC matches the router's MAC on the ingress interface
        //   (transit routing — the host is using us as the default gateway).
        let is_local_ip = match &meta.l3 {
            Some(L3Info::Ipv4(ipv4)) => l3.is_local_ip(&ipv4.dst_addr),
            _ => false,
        };
        let is_router_mac = iface_macs
            .get(&meta.in_ifname)
            .is_some_and(|our_mac| meta.l2.dst_mac == *our_mac);
        let is_local = is_local_ip || is_router_mac;

        if !is_local {
            // Pure L2 forwarding — do not enter L3.
            return match l2_decision {
                L2Decision::Unicast { out_ifname } => PipelineResult::Forward {
                    egress_iface: out_ifname,
                    new_ttl: None,
                    next_hop: None,
                },
                L2Decision::Flood { out_ifnames } => PipelineResult::Flood {
                    egress_ifaces: out_ifnames,
                },
                L2Decision::Drop => PipelineResult::Drop {
                    reason: DropReason::L2Drop,
                    icmp_reply: None,
                },
            };
        }
        // else: packet is for our local IP -> fall through to L3.
    }

    // Step 3: Conntrack lookup/create.
    //
    // For every trackable packet (IPv4 with TCP/UDP/ICMP L4 header),
    // perform a session lookup. If a forward or reverse session exists,
    // update its state and refresh the timestamp. Otherwise, create a
    // new session for the flow.
    let ct_result = conntrack_process(&meta, conntrack);

    // If the session table is full, drop the packet immediately.
    if ct_result == ConntrackResult::TableFull {
        return PipelineResult::Drop {
            reason: DropReason::ConntrackTableFull,
            icmp_reply: None,
        };
    }

    // Step 4: L3 routing decision.
    let l3_decision = l3.process(&meta);

    match l3_decision {
        L3Decision::Forward {
            out_ifname,
            next_hop,
            new_ttl,
        } => {
            // Step 5: Firewall check on the forward chain.
            let src_zone = zone_resolver.resolve(&raw_pkt.ingress_iface);
            let dst_zone = zone_resolver.resolve(&out_ifname);
            let is_new_session = matches!(
                ct_result,
                ConntrackResult::Created | ConntrackResult::Untracked
            );
            let fw_ctx = FwContext::from_packet(
                &meta,
                FwChain::Forward,
                src_zone,
                dst_zone,
                conntrack,
                is_new_session,
            );
            let verdict = firewall.evaluate(&fw_ctx);

            match verdict {
                FwVerdict::Accept | FwVerdict::AcceptRule { .. } => PipelineResult::Forward {
                    egress_iface: out_ifname,
                    new_ttl: Some(new_ttl),
                    next_hop: Some(next_hop),
                },
                FwVerdict::Drop | FwVerdict::DropRule { .. } => PipelineResult::Drop {
                    reason: DropReason::FirewallDrop,
                    icmp_reply: None,
                },
            }
        }
        L3Decision::LocalDelivery => PipelineResult::Consumed,
        L3Decision::Drop { reason } => {
            let drop_reason = map_l3_drop_reason(reason);
            let icmp_reply = match drop_reason {
                DropReason::L3TtlExpired => {
                    let router_ip = l3.router_ip_for_iface(&raw_pkt.ingress_iface);
                    router_ip.and_then(|ip| {
                        icmp::generate_icmp_error(
                            &raw_pkt.data,
                            icmp::IcmpError::TtlExceeded,
                            ip,
                            &raw_pkt.ingress_iface,
                        )
                    })
                }
                DropReason::L3NoRoute => {
                    let router_ip = l3.router_ip_for_iface(&raw_pkt.ingress_iface);
                    router_ip.and_then(|ip| {
                        icmp::generate_icmp_error(
                            &raw_pkt.data,
                            icmp::IcmpError::NetUnreachable,
                            ip,
                            &raw_pkt.ingress_iface,
                        )
                    })
                }
                // No ICMP for non-IPv4 drops or other reasons.
                _ => None,
            };
            PipelineResult::Drop {
                reason: drop_reason,
                icmp_reply,
            }
        }
    }
}

/// Perform conntrack lookup/create/update for a single packet.
///
/// This is called on every packet entering the L3 processing path.
/// The logic:
/// 1. Extract a session key from the packet. If the packet is not
///    trackable (non-IPv4, no L4 header), return `Untracked`.
/// 2. Look up the forward key. If found, update TCP state and touch.
/// 3. Look up the reverse key. If found, update TCP state and touch.
/// 4. If neither direction is found, create a new session with the
///    appropriate initial state.
/// 5. If the table is full, return `TableFull`.
fn conntrack_process(
    meta: &packet::PacketMeta,
    conntrack: &mut ConntrackEngine,
) -> ConntrackResult {
    let forward_key = match SessionKey::from_packet(meta) {
        Some(k) => k,
        None => return ConntrackResult::Untracked,
    };

    let reverse_key = forward_key.reverse();

    // Check forward direction.
    if conntrack.lookup(&forward_key).is_some() {
        // Update TCP state machine if applicable.
        if let Some(L4Info::Tcp(tcp)) = &meta.l4 {
            conntrack.update_tcp_state(&forward_key, tcp.flags);
        }
        conntrack.touch(&forward_key);
        return ConntrackResult::Existing;
    }

    // Check reverse direction (return traffic).
    if conntrack.lookup(&reverse_key).is_some() {
        // Update TCP state machine on the original session.
        if let Some(L4Info::Tcp(tcp)) = &meta.l4 {
            conntrack.update_tcp_state(&reverse_key, tcp.flags);
        }
        conntrack.touch(&reverse_key);
        return ConntrackResult::Existing;
    }

    // New flow: create a session.
    let state = initial_session_state(meta);
    match conntrack.create_session(forward_key, state) {
        Ok(_) => ConntrackResult::Created,
        Err(ConntrackError::TableFull) => ConntrackResult::TableFull,
    }
}

/// Determine the initial session state from packet metadata.
fn initial_session_state(meta: &packet::PacketMeta) -> SessionState {
    match &meta.l4 {
        Some(L4Info::Tcp(_)) => SessionState::Tcp(TcpState::SynSent),
        Some(L4Info::Udp(_)) => SessionState::Udp,
        Some(L4Info::Icmp(_)) => SessionState::Icmp,
        None => SessionState::Udp, // fallback, should not happen for tracked packets
    }
}

/// Map an L3 drop reason to a pipeline drop reason.
fn map_l3_drop_reason(reason: L3DropReason) -> DropReason {
    match reason {
        L3DropReason::NotIpv4 => DropReason::L3NotIpv4,
        L3DropReason::TtlExpired => DropReason::L3TtlExpired,
        L3DropReason::NoRoute => DropReason::L3NoRoute,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::{ConntrackConfig, ConntrackEngine};
    use crate::io::RawPacket;
    use crate::l2::L2Engine;
    use ruster_config::model::{
        BridgeDomain, DefaultPolicy, FirewallConfig, InterfaceConfig, InterfaceRole, InterfaceZone,
        L2Config, RoutingConfig, StaticRoute,
    };

    // ── Test helpers ────────────────────────────────────────────────

    /// Create an L2 engine with **no** bridge domains, so all interfaces
    /// skip L2 processing and go directly to L3.  This preserves the
    /// behaviour of every pre-existing pipeline test.
    fn make_l2_engine_empty() -> L2Engine {
        L2Engine::from_config(&L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 120,
            arp_hold_queue_per_ip: 3,
            arp_hold_queue_max: 1024,
            bridge_domains: vec![],
        })
    }

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
            ],
        }
    }

    fn make_interfaces() -> Vec<InterfaceConfig> {
        vec![
            InterfaceConfig {
                name: "wan0".to_string(),
                port_id: 0,
                role: InterfaceRole::Wan,
                admin_up: true,
                mtu: 1500,
                mac: "00:11:22:33:44:55".to_string(),
                ipv4_addrs: vec!["10.0.0.2/24".to_string()],
                zone: InterfaceZone::Wan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "lan0".to_string(),
                port_id: 1,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "00:AA:BB:CC:DD:EE".to_string(),
                ipv4_addrs: vec!["192.168.1.1/24".to_string()],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
        ]
    }

    fn make_l3_engine() -> L3Engine {
        L3Engine::from_config(&make_routing_config(), &make_interfaces()).unwrap()
    }

    fn make_fw_accept_all() -> FirewallEngine {
        FirewallEngine::from_config(&FirewallConfig {
            enabled: false,
            default_input: DefaultPolicy::Accept,
            default_forward: DefaultPolicy::Accept,
            default_output: DefaultPolicy::Accept,
            allow_established_related: false,
            rules: vec![],
        })
    }

    fn make_fw_drop_all() -> FirewallEngine {
        FirewallEngine::from_config(&FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Drop,
            allow_established_related: false,
            rules: vec![],
        })
    }

    fn make_conntrack() -> ConntrackEngine {
        ConntrackEngine::new(ConntrackConfig {
            max_sessions: 1000,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
        })
    }

    fn make_zone_resolver() -> ZoneResolver {
        ZoneResolver::from_config(&make_interfaces())
    }

    /// Compute IPv4 header checksum and write it into the header.
    fn set_ipv4_checksum(hdr: &mut [u8]) {
        hdr[10] = 0x00;
        hdr[11] = 0x00;
        let mut sum: u32 = 0;
        for i in (0..hdr.len()).step_by(2) {
            let word = if i + 1 < hdr.len() {
                u16::from_be_bytes([hdr[i], hdr[i + 1]])
            } else {
                u16::from_be_bytes([hdr[i], 0])
            };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = (cksum & 0xFF) as u8;
    }

    /// Build a valid Ethernet + IPv4 + UDP packet.
    fn make_ipv4_packet(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        ttl: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&dst_mac);
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // IPv4 header (20 bytes minimum)
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 20 + 8; // IP header + 8 bytes UDP
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        pkt.push(ttl);
        pkt.push(17); // protocol: UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // Compute IPv4 checksum
        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // Minimal UDP header (8 bytes)
        pkt.extend_from_slice(&[0x00, 0x50]); // src port: 80
        pkt.extend_from_slice(&[0x00, 0x51]); // dst port: 81
        pkt.extend_from_slice(&[0x00, 0x08]); // length: 8
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum: 0
        pkt
    }

    // ── Pipeline tests ──────────────────────────────────────────────

    #[test]
    fn forward_routed_packet() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();

        // Packet from LAN to internet (8.8.8.8) -> default route via wan0.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Forward { egress_iface, .. } => {
                assert_eq!(egress_iface, "wan0");
            }
            other => panic!("expected Forward, got {:?}", other),
        }
    }

    #[test]
    fn drop_parse_error_too_short() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();

        // Packet too short to parse (< 14 bytes).
        let raw_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::ParseError);
            }
            other => panic!("expected Drop(ParseError), got {:?}", other),
        }
    }

    #[test]
    fn drop_no_route() {
        // L3 engine with only a /24 route (no default route).
        let routing = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "192.168.1.0/24".to_string(),
                next_hop: "0.0.0.0".to_string(),
                out_if: "lan0".to_string(),
                metric: 10,
            }],
        };
        let l3 = L3Engine::from_config(&routing, &make_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();

        // Destination 8.8.8.8 has no matching route.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3NoRoute);
            }
            other => panic!("expected Drop(L3NoRoute), got {:?}", other),
        }
    }

    #[test]
    fn drop_ttl_expired() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();

        // TTL = 1 -> after decrement would be 0, so L3 engine drops.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            1, // TTL expired
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3TtlExpired);
            }
            other => panic!("expected Drop(L3TtlExpired), got {:?}", other),
        }
    }

    #[test]
    fn consumed_local_delivery() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();

        // Destination is our local IP (10.0.0.2) -> LocalDelivery -> Consumed.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [10, 0, 0, 2], // our WAN IP
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        assert!(matches!(result, PipelineResult::Consumed));
    }

    #[test]
    fn drop_firewall_blocks() {
        let l3 = make_l3_engine();
        let fw = make_fw_drop_all();
        let mut ct = make_conntrack();

        // Packet should be routed, but firewall drops everything.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::FirewallDrop);
            }
            other => panic!("expected Drop(FirewallDrop), got {:?}", other),
        }
    }

    #[test]
    fn drop_not_ipv4() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();

        // ARP packet -> L3 engine returns Drop(NotIpv4).
        let mut data = Vec::new();
        // Ethernet header
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // dst: broadcast
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
        data.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
                                               // ARP payload (28 bytes)
        data.extend_from_slice(&[0x00, 0x01]); // HW Type: Ethernet
        data.extend_from_slice(&[0x08, 0x00]); // Proto Type: IPv4
        data.push(0x06); // HW Addr Len
        data.push(0x04); // Proto Addr Len
        data.extend_from_slice(&[0x00, 0x01]); // Operation: Request
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Sender MAC
        data.extend_from_slice(&[192, 168, 1, 1]); // Sender IP
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Target MAC
        data.extend_from_slice(&[192, 168, 1, 2]); // Target IP

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3NotIpv4);
            }
            other => panic!("expected Drop(L3NotIpv4), got {:?}", other),
        }
    }

    #[test]
    fn drop_reason_counters_can_be_tracked() {
        // This test demonstrates that pipeline results can be used to
        // accumulate per-reason drop counters.
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        let mut parse_errors = 0u64;
        let mut ttl_drops = 0u64;
        let mut forwards = 0u64;

        // 1. Too-short packet -> ParseError
        let short_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };
        match process_packet(&short_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im) {
            PipelineResult::Drop {
                reason: DropReason::ParseError,
                ..
            } => parse_errors += 1,
            _ => {}
        }

        // 2. TTL=1 packet -> TtlExpired
        let ttl_data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 1);
        let ttl_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: ttl_data,
        };
        match process_packet(&ttl_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im) {
            PipelineResult::Drop {
                reason: DropReason::L3TtlExpired,
                ..
            } => ttl_drops += 1,
            _ => {}
        }

        // 3. Routable packet -> Forward
        let fwd_data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let fwd_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: fwd_data,
        };
        match process_packet(&fwd_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im) {
            PipelineResult::Forward { .. } => forwards += 1,
            _ => {}
        }

        assert_eq!(parse_errors, 1);
        assert_eq!(ttl_drops, 1);
        assert_eq!(forwards, 1);
    }

    // ── Zone resolution tests ───────────────────────────────────────

    #[test]
    fn forward_resolves_ingress_zone() {
        // Verify that the ingress interface zone is correctly resolved.
        // A packet entering from "lan0" (Lan zone) going to "wan0" (Wan zone)
        // should have src_zone=Lan. With a firewall that allows Lan->Wan,
        // the packet should be forwarded.
        use ruster_config::model::{Chain, ConnState, FirewallRule, RuleAction, RuleProto};

        let l3 = make_l3_engine();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // Firewall: only allow Lan->Wan forward, drop everything else.
        let fw = FirewallEngine::from_config(&FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Drop,
            allow_established_related: false,
            rules: vec![FirewallRule {
                name: "allow-lan-to-wan".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Any,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                state: vec![ConnState::New],
            }],
        });

        // Packet from lan0 (Lan) to 8.8.8.8 routed via wan0 (Wan).
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Forward { egress_iface, .. } => {
                assert_eq!(egress_iface, "wan0");
            }
            other => panic!(
                "expected Forward (Lan->Wan should be accepted), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn forward_resolves_egress_zone() {
        // Verify that the egress interface zone is correctly resolved.
        // A packet entering from "wan0" (Wan zone) going to a LAN address
        // routed via "lan0" (Lan zone) should have src_zone=Wan, dst_zone=Lan.
        // With a firewall that only allows Lan->Wan, this should be dropped.
        use ruster_config::model::{Chain, ConnState, FirewallRule, RuleAction, RuleProto};

        let l3 = make_l3_engine();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // Firewall: only allow Lan->Wan forward, drop everything else.
        let fw = FirewallEngine::from_config(&FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Drop,
            allow_established_related: false,
            rules: vec![FirewallRule {
                name: "allow-lan-to-wan".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Any,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                state: vec![ConnState::New],
            }],
        });

        // Packet from wan0 (Wan) to 192.168.1.100 routed via lan0 (Lan).
        // src_zone=Wan, dst_zone=Lan -> no matching rule -> drop.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            [8, 8, 8, 8],
            [192, 168, 1, 100],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "wan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::FirewallDrop);
            }
            other => panic!(
                "expected Drop(FirewallDrop) for Wan->Lan with no matching rule, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn unknown_interface_defaults_to_lan() {
        // Verify that an unknown interface name defaults to FirewallZone::Lan.
        let zr = make_zone_resolver();
        assert_eq!(zr.resolve("unknown_iface"), FirewallZone::Lan);
        assert_eq!(zr.resolve(""), FirewallZone::Lan);
    }

    // ── ICMP error generation tests ─────────────────────────────────

    #[test]
    fn ttl_expired_generates_icmp_reply() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // TTL = 1 -> L3 drops with TtlExpired -> should generate ICMP.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            1,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3TtlExpired);
                let reply = icmp_reply.expect("should generate ICMP reply for TTL expired");
                assert_eq!(reply.egress_iface, "lan0");

                // Check ICMP type/code: Time Exceeded (11, 0).
                let icmp_start = 14 + 20; // Ethernet + IPv4
                assert_eq!(reply.data[icmp_start], 11);
                assert_eq!(reply.data[icmp_start + 1], 0);

                // Check that the router IP is the lan0 IP (192.168.1.1).
                let src_ip = &reply.data[14 + 12..14 + 16];
                assert_eq!(src_ip, &[192, 168, 1, 1]);
            }
            other => panic!("expected Drop with ICMP reply, got {:?}", other),
        }
    }

    #[test]
    fn no_route_generates_icmp_reply() {
        // L3 engine with only a /24 route (no default route).
        let routing = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "192.168.1.0/24".to_string(),
                next_hop: "0.0.0.0".to_string(),
                out_if: "lan0".to_string(),
                metric: 10,
            }],
        };
        let l3 = L3Engine::from_config(&routing, &make_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // Destination 8.8.8.8 has no matching route.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3NoRoute);
                let reply = icmp_reply.expect("should generate ICMP reply for no route");
                assert_eq!(reply.egress_iface, "lan0");

                // Check ICMP type/code: Destination Unreachable / Net Unreachable (3, 0).
                let icmp_start = 14 + 20;
                assert_eq!(reply.data[icmp_start], 3);
                assert_eq!(reply.data[icmp_start + 1], 0);
            }
            other => panic!("expected Drop with ICMP reply, got {:?}", other),
        }
    }

    #[test]
    fn no_icmp_for_icmp_packets() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // Build an ICMP packet (protocol=1) with TTL=1.
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // IPv4 header
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00);
        let total_len: u16 = 20 + 8; // IP header + 8 bytes ICMP
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        pkt.push(1); // TTL = 1
        pkt.push(1); // protocol = ICMP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&[192, 168, 1, 100]); // src
        pkt.extend_from_slice(&[8, 8, 8, 8]); // dst

        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // ICMP Echo Request (8 bytes)
        pkt.push(8); // type: Echo Request
        pkt.push(0); // code: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // ID + seq

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: pkt,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3TtlExpired);
                assert!(
                    icmp_reply.is_none(),
                    "should NOT generate ICMP for ICMP packets (loop prevention)"
                );
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }

    #[test]
    fn parse_error_no_icmp() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        let raw_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::ParseError);
                assert!(icmp_reply.is_none(), "no ICMP for parse errors");
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }

    #[test]
    fn firewall_drop_no_icmp() {
        let l3 = make_l3_engine();
        let fw = make_fw_drop_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::FirewallDrop);
                assert!(icmp_reply.is_none(), "no ICMP for firewall drops");
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }

    #[test]
    fn not_ipv4_no_icmp() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // ARP packet.
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&[0x08, 0x06]); // ARP
        data.extend_from_slice(&[0x00, 0x01]);
        data.extend_from_slice(&[0x08, 0x00]);
        data.push(0x06);
        data.push(0x04);
        data.extend_from_slice(&[0x00, 0x01]);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&[192, 168, 1, 1]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[192, 168, 1, 2]);

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3NotIpv4);
                assert!(icmp_reply.is_none(), "no ICMP for non-IPv4");
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }

    // ── L2 pipeline integration tests ──────────────────────────────

    /// Helper: build an L2 engine with a bridge domain containing
    /// eth0, eth1, eth2.
    fn make_l2_engine_bridged() -> L2Engine {
        L2Engine::from_config(&L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 120,
            arp_hold_queue_per_ip: 3,
            arp_hold_queue_max: 1024,
            bridge_domains: vec![BridgeDomain {
                name: "br0".to_string(),
                members: vec!["eth0".to_string(), "eth1".to_string(), "eth2".to_string()],
            }],
        })
    }

    /// Helper: build an L3 engine that knows about eth0/eth1/eth2
    /// so that local IP checks work in the L2 pipeline tests.
    fn make_l3_engine_with_bridge_ifaces() -> L3Engine {
        let routing = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "0.0.0.0/0".to_string(),
                next_hop: "10.0.0.1".to_string(),
                out_if: "wan0".to_string(),
                metric: 100,
            }],
        };
        let ifaces = vec![
            InterfaceConfig {
                name: "eth0".to_string(),
                port_id: 0,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "02:00:00:00:00:01".to_string(),
                ipv4_addrs: vec!["192.168.1.1/24".to_string()],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "eth1".to_string(),
                port_id: 1,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "02:00:00:00:00:02".to_string(),
                ipv4_addrs: vec![],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "eth2".to_string(),
                port_id: 2,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "02:00:00:00:00:03".to_string(),
                ipv4_addrs: vec![],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "wan0".to_string(),
                port_id: 3,
                role: InterfaceRole::Wan,
                admin_up: true,
                mtu: 1500,
                mac: "02:00:00:00:10:01".to_string(),
                ipv4_addrs: vec!["10.0.0.2/24".to_string()],
                zone: InterfaceZone::Wan,
                l2_domain: "bd-wan".to_string(),
                linux_if: None,
            },
        ];
        L3Engine::from_config(&routing, &ifaces).unwrap()
    }

    const MAC_HOST_A: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
    const MAC_HOST_B: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02];
    const MAC_BROADCAST: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    /// Build a raw Ethernet + IPv4 + UDP packet with specified MACs and IPs.
    fn make_l2_raw_packet(
        ingress_iface: &str,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
    ) -> RawPacket {
        RawPacket {
            ingress_iface: ingress_iface.to_string(),
            data: make_ipv4_packet(src_mac, dst_mac, src_ip, dst_ip, 64),
        }
    }

    #[test]
    fn l2_forward_known_unicast() {
        // Pre-learn MAC_HOST_B on eth1, then send a packet from eth0
        // to MAC_HOST_B -> should L2 forward to eth1.
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        // Step 1: Learn MAC_HOST_B on eth1.
        let learn_pkt = make_l2_raw_packet(
            "eth1",
            MAC_HOST_B,
            MAC_HOST_A,
            [192, 168, 1, 50],
            [192, 168, 1, 60],
        );
        let _ = process_packet(&learn_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        // Step 2: Send from MAC_HOST_A on eth0 to MAC_HOST_B -> unicast to eth1.
        let pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_HOST_B,
            [192, 168, 1, 60],
            [192, 168, 1, 50],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        match result {
            PipelineResult::Forward { egress_iface, .. } => {
                assert_eq!(egress_iface, "eth1");
            }
            other => panic!("expected Forward to eth1, got {:?}", other),
        }
    }

    #[test]
    fn l2_flood_unknown_mac() {
        // Send to an unknown MAC on eth0 -> should flood to eth1, eth2.
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        let pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_HOST_B,
            [192, 168, 1, 60],
            [192, 168, 1, 50],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        match result {
            PipelineResult::Flood { egress_ifaces } => {
                assert!(
                    !egress_ifaces.contains(&"eth0".to_string()),
                    "must not include ingress"
                );
                assert!(egress_ifaces.contains(&"eth1".to_string()));
                assert!(egress_ifaces.contains(&"eth2".to_string()));
                assert_eq!(egress_ifaces.len(), 2);
            }
            other => panic!("expected Flood, got {:?}", other),
        }
    }

    #[test]
    fn l2_broadcast_floods() {
        // Broadcast MAC should always flood.
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        let pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_BROADCAST,
            [192, 168, 1, 60],
            [192, 168, 1, 255],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        match result {
            PipelineResult::Flood { egress_ifaces } => {
                assert!(
                    !egress_ifaces.contains(&"eth0".to_string()),
                    "must not include ingress"
                );
                assert!(egress_ifaces.contains(&"eth1".to_string()));
                assert!(egress_ifaces.contains(&"eth2".to_string()));
                assert_eq!(egress_ifaces.len(), 2);
            }
            other => panic!("expected Flood for broadcast, got {:?}", other),
        }
    }

    #[test]
    fn l2_learning_source_mac() {
        // After processing a packet from eth0 with MAC_HOST_A,
        // MAC_HOST_A should be learned on eth0. A subsequent packet
        // to MAC_HOST_A from eth1 should unicast to eth0.
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        // Step 1: MAC_HOST_A arrives on eth0 (triggers learning).
        let learn_pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_HOST_B,
            [192, 168, 1, 60],
            [192, 168, 1, 50],
        );
        let _ = process_packet(&learn_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        // Step 2: Send to MAC_HOST_A from eth1 -> should unicast to eth0.
        let pkt = make_l2_raw_packet(
            "eth1",
            MAC_HOST_B,
            MAC_HOST_A,
            [192, 168, 1, 50],
            [192, 168, 1, 60],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        match result {
            PipelineResult::Forward { egress_iface, .. } => {
                assert_eq!(egress_iface, "eth0");
            }
            other => panic!("expected Forward to eth0, got {:?}", other),
        }
    }

    #[test]
    fn l2_plus_l3_local_ip_goes_to_l3() {
        // A packet in a bridge domain but destined for the router's
        // own IP (192.168.1.1) should bypass L2 forwarding and be
        // handed to L3 (resulting in Consumed / LocalDelivery).
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        let pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_HOST_B,
            [192, 168, 1, 60],
            [192, 168, 1, 1],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        // The packet's dst IP (192.168.1.1) is a local IP on eth0,
        // so L3 should handle it as LocalDelivery -> Consumed.
        assert!(
            matches!(result, PipelineResult::Consumed),
            "expected Consumed for local IP, got {:?}",
            result
        );
    }

    #[test]
    fn l2_not_in_bridge_domain_goes_to_l3() {
        // An interface NOT in any bridge domain should skip L2 and
        // go directly to L3 routing.
        let mut l2 = make_l2_engine_bridged(); // br0: eth0, eth1, eth2
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        // wan0 is NOT in br0, so it skips L2 entirely.
        let pkt = make_l2_raw_packet(
            "wan0",
            [0xAA; 6],
            [0xBB; 6],
            [10, 0, 0, 5],
            [192, 168, 1, 1], // local IP -> Consumed
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        assert!(
            matches!(result, PipelineResult::Consumed),
            "expected Consumed (L3 local delivery), got {:?}",
            result
        );
    }

    // ── Conntrack integration tests ─────────────────────────────────

    /// Build a valid Ethernet + IPv4 + TCP packet with specified flags.
    fn make_tcp_packet(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
        ttl: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&dst_mac);
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // IPv4 header (20 bytes)
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 20 + 20; // IP header + TCP header
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        pkt.push(ttl);
        pkt.push(6); // protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // Compute IPv4 checksum.
        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // TCP header (20 bytes minimum)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        pkt.push(0x50); // data offset = 5 (20 bytes), reserved bits
        pkt.push(tcp_flags);
        pkt.extend_from_slice(&[0xFF, 0xFF]); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer
        pkt
    }

    #[test]
    fn conntrack_creates_session_for_new_flow() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        assert_eq!(ct.session_count(), 0);

        // Send a UDP packet from LAN to WAN.
        let data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        assert!(matches!(result, PipelineResult::Forward { .. }));

        // A conntrack session should have been created.
        assert_eq!(ct.session_count(), 1);
    }

    #[test]
    fn conntrack_reuses_session_for_same_flow() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        let data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);

        // Send the same packet twice.
        let pkt1 = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: data.clone(),
        };
        let _ = process_packet(&pkt1, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        assert_eq!(ct.session_count(), 1);

        let pkt2 = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };
        let _ = process_packet(&pkt2, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        // Should still be 1 session (reused).
        assert_eq!(ct.session_count(), 1);
    }

    #[test]
    fn conntrack_matches_reverse_direction() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // SYN: LAN 192.168.1.100:49152 -> WAN 8.8.8.8:80
        let syn_data = make_tcp_packet(
            [0xAA; 6],
            [0xBB; 6],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            49152,
            80,
            0x02, // SYN
            64,
        );
        let syn_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: syn_data,
        };
        let _ = process_packet(&syn_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        assert_eq!(ct.session_count(), 1);

        // SYN-ACK: WAN 8.8.8.8:80 -> LAN 192.168.1.100:49152
        // This is the reverse direction.
        let synack_data = make_tcp_packet(
            [0xBB; 6],
            [0xAA; 6],
            [8, 8, 8, 8],
            [192, 168, 1, 100],
            80,
            49152,
            0x12, // SYN+ACK
            64,
        );
        let synack_pkt = RawPacket {
            ingress_iface: "wan0".to_string(),
            data: synack_data,
        };
        let _ = process_packet(&synack_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);

        // Should still be 1 session (reverse matched the existing one).
        assert_eq!(ct.session_count(), 1);
    }

    #[test]
    fn conntrack_tcp_lifecycle_syn_established_fin() {
        use crate::conntrack::session::{SessionKey, SessionProto, SessionState, TcpState};

        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        let src_ip = [192, 168, 1, 100];
        let dst_ip = [8, 8, 8, 8];
        let src_port = 49152u16;
        let dst_port = 80u16;

        // Step 1: SYN
        let syn = make_tcp_packet(
            [0xAA; 6], [0xBB; 6], src_ip, dst_ip, src_port, dst_port, 0x02, 64,
        );
        let _ = process_packet(
            &RawPacket {
                ingress_iface: "lan0".to_string(),
                data: syn,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &zr,
            &im,
        );

        let key = SessionKey {
            src_ip,
            dst_ip,
            proto: SessionProto::Tcp { src_port, dst_port },
        };
        let session = ct.lookup(&key).expect("session should exist after SYN");
        assert_eq!(session.state, SessionState::Tcp(TcpState::SynSent));

        // Step 2: SYN-ACK (reverse direction triggers ACK flag -> Established)
        let synack = make_tcp_packet(
            [0xBB; 6], [0xAA; 6], dst_ip, src_ip, dst_port, src_port, 0x12, 64,
        );
        let _ = process_packet(
            &RawPacket {
                ingress_iface: "wan0".to_string(),
                data: synack,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &zr,
            &im,
        );

        let session = ct
            .lookup(&key)
            .expect("session should still exist after SYN-ACK");
        assert_eq!(session.state, SessionState::Tcp(TcpState::Established));

        // Step 3: FIN (forward direction)
        let fin = make_tcp_packet(
            [0xAA; 6], [0xBB; 6], src_ip, dst_ip, src_port, dst_port, 0x01, 64,
        );
        let _ = process_packet(
            &RawPacket {
                ingress_iface: "lan0".to_string(),
                data: fin,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &zr,
            &im,
        );

        let session = ct
            .lookup(&key)
            .expect("session should still exist after FIN");
        assert_eq!(session.state, SessionState::Tcp(TcpState::FinWait));

        // Step 4: FIN (reverse direction) -> Closed
        let fin_rev = make_tcp_packet(
            [0xBB; 6], [0xAA; 6], dst_ip, src_ip, dst_port, src_port, 0x01, 64,
        );
        let _ = process_packet(
            &RawPacket {
                ingress_iface: "wan0".to_string(),
                data: fin_rev,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &zr,
            &im,
        );

        let session = ct
            .lookup(&key)
            .expect("session should still exist after both FINs");
        assert_eq!(session.state, SessionState::Tcp(TcpState::Closed));
    }

    #[test]
    fn conntrack_table_full_drops_packet() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        // Create a conntrack with max 1 session.
        let mut ct = ConntrackEngine::new(ConntrackConfig {
            max_sessions: 1,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
        });
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // First packet fills the table.
        let data1 = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let pkt1 = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: data1,
        };
        let result1 = process_packet(&pkt1, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        assert!(matches!(result1, PipelineResult::Forward { .. }));
        assert_eq!(ct.session_count(), 1);

        // Second packet from a different flow should be dropped (table full).
        let data2 = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 101], [8, 8, 8, 8], 64);
        let pkt2 = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: data2,
        };
        let result2 = process_packet(&pkt2, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        assert!(
            matches!(
                result2,
                PipelineResult::Drop {
                    reason: DropReason::ConntrackTableFull,
                    ..
                }
            ),
            "expected Drop(ConntrackTableFull) when table is full, got {:?}",
            result2
        );
    }

    #[test]
    fn conntrack_gc_removes_expired_sessions() {
        use std::thread;
        use std::time::Duration;

        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        // Conntrack with 0-second UDP timeout so sessions expire immediately.
        let mut ct = ConntrackEngine::new(ConntrackConfig {
            max_sessions: 1000,
            tcp_established_timeout_sec: 3600,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 0,
            icmp_timeout_sec: 30,
        });
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // Create a UDP session.
        let data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };
        let _ = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        assert_eq!(ct.session_count(), 1);

        // Wait for session to expire.
        thread::sleep(Duration::from_millis(10));

        // Run GC.
        let expired = ct.gc();
        assert_eq!(expired, 1);
        assert_eq!(ct.session_count(), 0);
    }

    #[test]
    fn conntrack_fw_allow_established_integration() {
        // Integration test: firewall with allow_established_related and
        // default_forward=drop. A new outbound flow creates a conntrack
        // session, then the reverse (return) traffic should be accepted
        // because the session exists.
        use ruster_config::model::{Chain, ConnState, FirewallRule, RuleAction, RuleProto};

        let l3 = make_l3_engine();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // FW: allow LAN->WAN new, allow established/related, default forward=drop.
        let fw = FirewallEngine::from_config(&FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Accept,
            allow_established_related: true,
            rules: vec![FirewallRule {
                name: "allow-lan-to-wan".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Any,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                state: vec![ConnState::New],
            }],
        });

        // Step 1: Outbound SYN from LAN -> WAN (should be accepted by rule).
        let syn = make_tcp_packet(
            [0xAA; 6],
            [0xBB; 6],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            49152,
            80,
            0x02,
            64,
        );
        let result1 = process_packet(
            &RawPacket {
                ingress_iface: "lan0".to_string(),
                data: syn,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &zr,
            &im,
        );
        assert!(
            matches!(result1, PipelineResult::Forward { .. }),
            "outbound SYN should be forwarded, got {:?}",
            result1
        );
        assert_eq!(ct.session_count(), 1, "session should be created");

        // Step 2: Return SYN-ACK from WAN -> LAN (reverse direction).
        // Without conntrack, this would be dropped by default_forward=drop
        // because there's no rule for WAN->LAN new traffic.
        // With conntrack, the reverse key matches the existing session,
        // so FwContext::from_packet sees is_established=true ->
        // allow_established_related accepts it.
        let synack = make_tcp_packet(
            [0xBB; 6],
            [0xAA; 6],
            [8, 8, 8, 8],
            [192, 168, 1, 100],
            80,
            49152,
            0x12,
            64,
        );
        let result2 = process_packet(
            &RawPacket {
                ingress_iface: "wan0".to_string(),
                data: synack,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &zr,
            &im,
        );
        assert!(
            matches!(result2, PipelineResult::Forward { .. }),
            "return SYN-ACK should be forwarded (established), got {:?}",
            result2
        );
    }

    #[test]
    fn conntrack_untracked_arp_does_not_create_session() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // ARP packet -> not trackable -> no session created.
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&[0x08, 0x06]); // ARP
        data.extend_from_slice(&[0x00, 0x01]);
        data.extend_from_slice(&[0x08, 0x00]);
        data.push(0x06);
        data.push(0x04);
        data.extend_from_slice(&[0x00, 0x01]);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&[192, 168, 1, 1]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[192, 168, 1, 2]);

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let _ = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &zr, &im);
        assert_eq!(
            ct.session_count(),
            0,
            "ARP should not create a conntrack session"
        );
    }
}

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

use crate::conntrack::ConntrackEngine;
use crate::firewall::{FirewallEngine, FwChain, FwContext, FwVerdict};
use crate::icmp::{self, IcmpReply};
use crate::io::RawPacket;
use crate::packet;
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
}

// ── Pipeline function ───────────────────────────────────────────────

/// Process a single raw packet through the forwarding pipeline.
///
/// The simplified v0.1 flow is:
/// 1. Parse the raw bytes into a [`PacketMeta`](packet::PacketMeta).
/// 2. If parsing fails, return `Drop(ParseError)`.
/// 3. Check L3 routing via [`L3Engine::process`].
/// 4. Based on the L3 decision:
///    - `Forward { .. }` -> check firewall -> return `Forward` or `Drop(FirewallDrop)`.
///    - `LocalDelivery` -> `Consumed`.
///    - `Drop(reason)` -> `Drop` with a mapped reason.
/// 5. If the firewall blocks the packet, return `Drop(FirewallDrop)`.
pub fn process_packet(
    raw_pkt: &RawPacket,
    l3: &L3Engine,
    firewall: &FirewallEngine,
    conntrack: &ConntrackEngine,
    zone_resolver: &ZoneResolver,
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

    // Step 2: L3 routing decision.
    let l3_decision = l3.process(&meta);

    match l3_decision {
        L3Decision::Forward {
            out_ifname,
            next_hop: _,
            new_ttl: _,
        } => {
            // Step 3: Firewall check on the forward chain.
            let src_zone = zone_resolver.resolve(&raw_pkt.ingress_iface);
            let dst_zone = zone_resolver.resolve(&out_ifname);
            let fw_ctx =
                FwContext::from_packet(&meta, FwChain::Forward, src_zone, dst_zone, conntrack);
            let verdict = firewall.evaluate(&fw_ctx);

            match verdict {
                FwVerdict::Accept | FwVerdict::AcceptRule { .. } => PipelineResult::Forward {
                    egress_iface: out_ifname,
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
    use ruster_config::model::{
        DefaultPolicy, FirewallConfig, InterfaceConfig, InterfaceRole, InterfaceZone,
        RoutingConfig, StaticRoute,
    };

    // ── Test helpers ────────────────────────────────────────────────

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
        let ct = make_conntrack();

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
        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
        match result {
            PipelineResult::Forward { egress_iface } => {
                assert_eq!(egress_iface, "wan0");
            }
            other => panic!("expected Forward, got {:?}", other),
        }
    }

    #[test]
    fn drop_parse_error_too_short() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let ct = make_conntrack();

        // Packet too short to parse (< 14 bytes).
        let raw_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };

        let zr = make_zone_resolver();
        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();

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
        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();

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
        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();

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
        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
        assert!(matches!(result, PipelineResult::Consumed));
    }

    #[test]
    fn drop_firewall_blocks() {
        let l3 = make_l3_engine();
        let fw = make_fw_drop_all();
        let ct = make_conntrack();

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
        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();

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
        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

        let mut parse_errors = 0u64;
        let mut ttl_drops = 0u64;
        let mut forwards = 0u64;

        // 1. Too-short packet -> ParseError
        let short_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };
        match process_packet(&short_pkt, &l3, &fw, &ct, &zr) {
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
        match process_packet(&ttl_pkt, &l3, &fw, &ct, &zr) {
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
        match process_packet(&fwd_pkt, &l3, &fw, &ct, &zr) {
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

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

        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
        match result {
            PipelineResult::Forward { egress_iface } => {
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

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

        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

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

        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

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

        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

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

        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

        let raw_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };

        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

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

        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
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
        let ct = make_conntrack();
        let zr = make_zone_resolver();

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

        let result = process_packet(&raw_pkt, &l3, &fw, &ct, &zr);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3NotIpv4);
                assert!(icmp_reply.is_none(), "no ICMP for non-IPv4");
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }
}

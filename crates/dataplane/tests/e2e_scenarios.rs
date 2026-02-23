//! E2E functional test scenarios for ruster v0.1 acceptance.
//!
//! These tests wire up multiple dataplane engines together to verify the
//! full packet-processing pipeline (L2 bridging, L3 routing, NAT, firewall,
//! conntrack, and observer counters) end-to-end.
//!
//! Each scenario creates its own engines and configuration, making the
//! tests self-contained and independently runnable.

// ── Imports ──────────────────────────────────────────────────────────

use ruster_config::model::{
    BridgeDomain, Chain, ConnState, DefaultPolicy, FirewallConfig, FirewallRule, FirewallZone,
    InterfaceConfig, InterfaceRole, InterfaceZone, L2Config, NatConfig, NatMode, PortForward,
    PortForwardProto, RoutingConfig, RuleAction, RuleProto, StaticRoute,
};
use ruster_dataplane::conntrack::session::{SessionKey, SessionProto, SessionState, TcpState};
use ruster_dataplane::conntrack::{ConntrackConfig, ConntrackEngine};
use ruster_dataplane::firewall::{FirewallEngine, FwChain, FwContext, FwVerdict};
use ruster_dataplane::l2::bridge::L2Decision;
use ruster_dataplane::l2::L2Engine;
use ruster_dataplane::nat::{NatAction, NatEngine};
use ruster_dataplane::packet::{Ipv4Info, L2Info, L3Info, L4Info, PacketMeta, TcpInfo};
use ruster_dataplane::routing::{L3Decision, L3DropReason, L3Engine};
use ruster_observe::{DropReason, Observer};

// ── MAC / IP constants ───────────────────────────────────────────────

// WAN side
const WAN_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const WAN_IP: [u8; 4] = [10, 0, 0, 2];
const GW_IP: [u8; 4] = [10, 0, 0, 1];

// LAN side
const LAN_MAC: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
const LAN_IP: [u8; 4] = [192, 168, 1, 1];

// Hosts
const HOST_A_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
const HOST_B_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02];
const HOST_A_IP: [u8; 4] = [192, 168, 1, 100];
const HOST_B_IP: [u8; 4] = [192, 168, 1, 101];

// Internal server for port-forward
const INTERNAL_SERVER_IP: [u8; 4] = [192, 168, 1, 100];

// External
const EXTERNAL_IP: [u8; 4] = [8, 8, 8, 8];
const EXTERNAL_CLIENT_IP: [u8; 4] = [203, 0, 113, 50];

// ── Common config helper ─────────────────────────────────────────────

/// Build a home-router-like configuration.
///
/// - WAN: eth0 (10.0.0.2/24, wan zone)
/// - LAN: eth1 (192.168.1.1/24, lan zone)
/// - LAN: eth2 (no IP, lan zone, bridge member)
/// - Bridge: br0 (eth1, eth2)
/// - Default route: 0.0.0.0/0 via 10.0.0.1 out eth0
/// - LAN route: 192.168.1.0/24 via 0.0.0.0 out eth1
/// - NAT: enabled, external_if=eth0, hairpin=true
/// - Port forward: TCP 8080 -> 192.168.1.100:80
/// - FW: default_forward=drop, allow_established_related=true,
///     allow lan->wan new forward, allow wan->lan tcp dst_port 8080 (via port forward)
fn make_home_router_config() -> (
    L2Config,
    RoutingConfig,
    NatConfig,
    FirewallConfig,
    Vec<InterfaceConfig>,
) {
    let interfaces = vec![
        InterfaceConfig {
            name: "eth0".to_string(),
            port_id: 0,
            role: InterfaceRole::Wan,
            admin_up: true,
            mtu: 1500,
            mac: "00:11:22:33:44:55".to_string(),
            ipv4_addrs: vec!["10.0.0.2/24".to_string()],
            zone: InterfaceZone::Wan,
            l2_domain: "".to_string(),
        },
        InterfaceConfig {
            name: "eth1".to_string(),
            port_id: 1,
            role: InterfaceRole::Lan,
            admin_up: true,
            mtu: 1500,
            mac: "00:AA:BB:CC:DD:EE".to_string(),
            ipv4_addrs: vec!["192.168.1.1/24".to_string()],
            zone: InterfaceZone::Lan,
            l2_domain: "br0".to_string(),
        },
        InterfaceConfig {
            name: "eth2".to_string(),
            port_id: 2,
            role: InterfaceRole::Lan,
            admin_up: true,
            mtu: 1500,
            mac: "00:AA:BB:CC:DD:FF".to_string(),
            ipv4_addrs: vec![],
            zone: InterfaceZone::Lan,
            l2_domain: "br0".to_string(),
        },
    ];

    let l2_config = L2Config {
        mac_table_max_entries: 1024,
        mac_aging_sec: 300,
        arp_table_max_entries: 256,
        arp_timeout_sec: 120,
        bridge_domains: vec![BridgeDomain {
            name: "br0".to_string(),
            members: vec!["eth1".to_string(), "eth2".to_string()],
        }],
    };

    let routing_config = RoutingConfig {
        ipv4_static_routes: vec![
            StaticRoute {
                prefix: "0.0.0.0/0".to_string(),
                next_hop: "10.0.0.1".to_string(),
                out_if: "eth0".to_string(),
                metric: 100,
            },
            StaticRoute {
                prefix: "192.168.1.0/24".to_string(),
                next_hop: "0.0.0.0".to_string(),
                out_if: "eth1".to_string(),
                metric: 10,
            },
        ],
    };

    let nat_config = NatConfig {
        enabled: true,
        mode: NatMode::Napt44,
        external_if: "eth0".to_string(),
        hairpin: true,
        session_table_max_entries: 10000,
        tcp_established_timeout_sec: 7200,
        tcp_transitory_timeout_sec: 120,
        udp_timeout_sec: 300,
        icmp_timeout_sec: 30,
        port_forwards: vec![PortForward {
            name: "web-server".to_string(),
            proto: PortForwardProto::Tcp,
            external_port: 8080,
            internal_addr: "192.168.1.100".to_string(),
            internal_port: 80,
        }],
    };

    let firewall_config = FirewallConfig {
        enabled: true,
        default_input: DefaultPolicy::Drop,
        default_forward: DefaultPolicy::Drop,
        default_output: DefaultPolicy::Accept,
        allow_established_related: true,
        rules: vec![
            // Allow LAN -> WAN new forward connections
            FirewallRule {
                name: "allow-lan-to-wan".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Any,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                state: vec![ConnState::New, ConnState::Established, ConnState::Related],
            },
            // Allow WAN -> LAN tcp to port-forwarded services (new connections)
            FirewallRule {
                name: "allow-wan-to-lan-pf".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Tcp,
                src_zone: FirewallZone::Wan,
                dst_zone: FirewallZone::Lan,
                state: vec![ConnState::New],
            },
        ],
    };

    (
        l2_config,
        routing_config,
        nat_config,
        firewall_config,
        interfaces,
    )
}

// ── Packet meta helpers ──────────────────────────────────────────────

fn make_l2(src_mac: [u8; 6], dst_mac: [u8; 6]) -> L2Info {
    L2Info {
        dst_mac,
        src_mac,
        ethertype: 0x0800,
    }
}

fn make_ipv4(src: [u8; 4], dst: [u8; 4], ttl: u8, protocol: u8) -> Ipv4Info {
    Ipv4Info {
        src_addr: src,
        dst_addr: dst,
        ttl,
        protocol,
        header_len: 20,
        total_len: 40,
        identification: 1,
        flags: 0x40, // DF
        fragment_offset: 0,
        checksum: 0,
        payload_offset: 34,
    }
}

fn make_tcp_l4(src_port: u16, dst_port: u16, flags: u8) -> L4Info {
    L4Info::Tcp(TcpInfo {
        src_port,
        dst_port,
        seq_num: 1000,
        ack_num: 0,
        data_offset: 5,
        flags,
        window: 65535,
        checksum: 0,
    })
}

/// Build a TCP packet meta for LAN -> WAN traffic.
fn make_tcp_meta(
    in_ifname: &str,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    flags: u8,
) -> PacketMeta {
    PacketMeta {
        in_ifname: in_ifname.to_string(),
        l2: make_l2(src_mac, dst_mac),
        l3: Some(L3Info::Ipv4(make_ipv4(src_ip, dst_ip, ttl, 6))),
        l4: Some(make_tcp_l4(src_port, dst_port, flags)),
        raw_len: 54,
    }
}

fn make_conntrack_from_nat(nat_config: &NatConfig) -> ConntrackEngine {
    ConntrackEngine::new(ConntrackConfig {
        max_sessions: nat_config.session_table_max_entries as usize,
        tcp_established_timeout_sec: u64::from(nat_config.tcp_established_timeout_sec),
        tcp_transitory_timeout_sec: u64::from(nat_config.tcp_transitory_timeout_sec),
        udp_timeout_sec: u64::from(nat_config.udp_timeout_sec),
        icmp_timeout_sec: u64::from(nat_config.icmp_timeout_sec),
    })
}

// ── TCP flag constants ───────────────────────────────────────────────

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_SYN_ACK: u8 = TCP_SYN | TCP_ACK;

// ══════════════════════════════════════════════════════════════════════
// Scenario 1: L2 Communication (bridge flood then unicast)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_l2_bridge_flood_then_unicast() {
    let (l2_config, _, _, _, _) = make_home_router_config();
    let mut l2 = L2Engine::from_config(&l2_config);

    // ── Step 1: Host A sends to Host B (unknown MAC) on eth1 → flood ─
    let pkt1 = PacketMeta {
        in_ifname: "eth1".to_string(),
        l2: make_l2(HOST_A_MAC, HOST_B_MAC),
        l3: None,
        l4: None,
        raw_len: 64,
    };
    let decision1 = l2.process(&pkt1);
    match &decision1 {
        L2Decision::Flood { out_ifnames } => {
            // Should flood to eth2 (the other bridge member), not eth1.
            assert!(
                out_ifnames.contains(&"eth2".to_string()),
                "flood should include eth2"
            );
            assert!(
                !out_ifnames.contains(&"eth1".to_string()),
                "flood should exclude ingress eth1"
            );
        }
        other => panic!("expected Flood for unknown MAC, got {:?}", other),
    }

    // ── Step 2: Host B replies from eth2 (learns Host B MAC on eth2) ─
    let pkt2 = PacketMeta {
        in_ifname: "eth2".to_string(),
        l2: make_l2(HOST_B_MAC, HOST_A_MAC),
        l3: None,
        l4: None,
        raw_len: 64,
    };
    let decision2 = l2.process(&pkt2);
    // Host A was learned from pkt1 on eth1, so this should unicast.
    assert_eq!(
        decision2,
        L2Decision::Unicast {
            out_ifname: "eth1".to_string()
        },
        "after learning, Host A should be unicast to eth1"
    );

    // ── Step 3: Host A sends again to Host B → unicast to eth2 ───────
    let pkt3 = PacketMeta {
        in_ifname: "eth1".to_string(),
        l2: make_l2(HOST_A_MAC, HOST_B_MAC),
        l3: None,
        l4: None,
        raw_len: 64,
    };
    let decision3 = l2.process(&pkt3);
    assert_eq!(
        decision3,
        L2Decision::Unicast {
            out_ifname: "eth2".to_string()
        },
        "after learning, Host B should be unicast to eth2"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 2: L3 Static Routing (LAN -> WAN)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_l3_static_routing_lan_to_wan() {
    let (_, routing_config, _, _, interfaces) = make_home_router_config();
    let l3 = L3Engine::from_config(&routing_config, &interfaces);

    // LAN host 192.168.1.100 sends to 8.8.8.8
    let meta = PacketMeta {
        in_ifname: "eth1".to_string(),
        l2: make_l2(HOST_A_MAC, LAN_MAC),
        l3: Some(L3Info::Ipv4(make_ipv4(HOST_A_IP, EXTERNAL_IP, 64, 6))),
        l4: Some(make_tcp_l4(49152, 80, TCP_SYN)),
        raw_len: 54,
    };

    let decision = l3.process(&meta);
    assert_eq!(
        decision,
        L3Decision::Forward {
            out_ifname: "eth0".to_string(),
            next_hop: GW_IP,
            new_ttl: 63,
        },
        "LAN -> WAN should forward via default route to eth0 with TTL decremented"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 3: L3 Static Routing (TTL Expired / Local Delivery)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_l3_ttl_expired_vs_local_delivery() {
    let (_, routing_config, _, _, interfaces) = make_home_router_config();
    let l3 = L3Engine::from_config(&routing_config, &interfaces);

    // ── Case A: TTL=1 destined for external IP → Drop(TtlExpired) ────
    let meta_ttl1 = PacketMeta {
        in_ifname: "eth1".to_string(),
        l2: make_l2(HOST_A_MAC, LAN_MAC),
        l3: Some(L3Info::Ipv4(make_ipv4(HOST_A_IP, EXTERNAL_IP, 1, 6))),
        l4: Some(make_tcp_l4(49152, 80, TCP_SYN)),
        raw_len: 54,
    };
    let decision_a = l3.process(&meta_ttl1);
    assert_eq!(
        decision_a,
        L3Decision::Drop {
            reason: L3DropReason::TtlExpired,
        },
        "TTL=1 to external should be dropped with TtlExpired"
    );

    // ── Case B: TTL=1 to our own IP → LocalDelivery (TTL not checked) ─
    let meta_local = PacketMeta {
        in_ifname: "eth1".to_string(),
        l2: make_l2(HOST_A_MAC, LAN_MAC),
        l3: Some(L3Info::Ipv4(make_ipv4(HOST_A_IP, LAN_IP, 1, 6))),
        l4: Some(make_tcp_l4(49152, 22, TCP_SYN)),
        raw_len: 54,
    };
    let decision_b = l3.process(&meta_local);
    assert_eq!(
        decision_b,
        L3Decision::LocalDelivery,
        "TTL=1 to our own IP should still be LocalDelivery"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 4: NAT Outbound (LAN -> WAN)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_nat_outbound_snat() {
    let (_, _, nat_config, _, interfaces) = make_home_router_config();
    let mut nat = NatEngine::from_config(&nat_config, &interfaces);
    let mut conntrack = make_conntrack_from_nat(&nat_config);

    // ── First packet: new TCP SYN from LAN host → allocate SNAT port ─
    let pkt1 = make_tcp_meta(
        "eth1",
        HOST_A_MAC,
        LAN_MAC,
        HOST_A_IP,
        EXTERNAL_IP,
        49152,
        80,
        64,
        TCP_SYN,
    );
    let action1 = nat.process_outbound(&pkt1, &mut conntrack);
    let allocated_port_1 = match &action1 {
        NatAction::Snat {
            new_src_ip,
            new_src_port,
        } => {
            assert_eq!(*new_src_ip, WAN_IP, "SNAT should rewrite to WAN IP");
            *new_src_port
        }
        other => panic!("expected Snat, got {:?}", other),
    };
    assert_eq!(
        conntrack.session_count(),
        1,
        "one session after first packet"
    );

    // ── Second packet: same flow → reuse same SNAT translation ───────
    let action2 = nat.process_outbound(&pkt1, &mut conntrack);
    assert_eq!(
        action1, action2,
        "same flow should reuse the same SNAT translation"
    );
    assert_eq!(
        conntrack.session_count(),
        1,
        "still one session after second packet"
    );

    // ── Third packet: different LAN host → different allocated port ──
    let pkt3 = make_tcp_meta(
        "eth1",
        HOST_B_MAC,
        LAN_MAC,
        HOST_B_IP,
        EXTERNAL_IP,
        49153,
        80,
        64,
        TCP_SYN,
    );
    let action3 = nat.process_outbound(&pkt3, &mut conntrack);
    let allocated_port_3 = match &action3 {
        NatAction::Snat { new_src_port, .. } => *new_src_port,
        other => panic!("expected Snat, got {:?}", other),
    };
    assert_ne!(
        allocated_port_1, allocated_port_3,
        "different hosts should get different ports"
    );
    assert_eq!(
        conntrack.session_count(),
        2,
        "two sessions for two different flows"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 5: NAT Port Forward (WAN -> LAN)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_nat_port_forward_inbound() {
    let (_, _, nat_config, _, interfaces) = make_home_router_config();
    let mut nat = NatEngine::from_config(&nat_config, &interfaces);
    let mut conntrack = make_conntrack_from_nat(&nat_config);

    // External client sends TCP to our WAN IP on port 8080.
    let pkt = make_tcp_meta(
        "eth0",
        [0xEE; 6],
        WAN_MAC,
        EXTERNAL_CLIENT_IP,
        WAN_IP,
        54321,
        8080,
        64,
        TCP_SYN,
    );
    let action = nat.process_inbound(&pkt, &mut conntrack);
    assert_eq!(
        action,
        NatAction::Dnat {
            new_dst_ip: INTERNAL_SERVER_IP,
            new_dst_port: 80,
        },
        "port forward should DNAT to internal server"
    );
    assert_eq!(
        conntrack.session_count(),
        1,
        "one session created for port forward"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 6: NAT Hairpin
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_nat_hairpin() {
    let (_, _, nat_config, _, interfaces) = make_home_router_config();
    let mut nat = NatEngine::from_config(&nat_config, &interfaces);
    let mut conntrack = make_conntrack_from_nat(&nat_config);

    // LAN host 192.168.1.101 accesses the internal server via our
    // external IP 10.0.0.2:8080 (hairpin scenario).
    let pkt = make_tcp_meta(
        "eth1", HOST_B_MAC, LAN_MAC, HOST_B_IP, WAN_IP, 50000, 8080, 64, TCP_SYN,
    );
    let action = nat.process_hairpin(&pkt, &mut conntrack);
    assert_eq!(
        action,
        NatAction::Dnat {
            new_dst_ip: INTERNAL_SERVER_IP,
            new_dst_port: 80,
        },
        "hairpin should DNAT to internal server"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 7: Firewall Allow (LAN -> WAN)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_firewall_allow_lan_to_wan() {
    let (_, _, nat_config, fw_config, _) = make_home_router_config();
    let fw = FirewallEngine::from_config(&fw_config);
    let conntrack = make_conntrack_from_nat(&nat_config);

    // New TCP from LAN host to external server.
    let pkt = make_tcp_meta(
        "eth1",
        HOST_A_MAC,
        LAN_MAC,
        HOST_A_IP,
        EXTERNAL_IP,
        49152,
        80,
        64,
        TCP_SYN,
    );
    let ctx = FwContext::from_packet(
        &pkt,
        FwChain::Forward,
        FirewallZone::Lan,
        FirewallZone::Wan,
        &conntrack,
    );
    let verdict = fw.evaluate(&ctx);
    assert!(
        matches!(verdict, FwVerdict::AcceptRule { .. }),
        "LAN->WAN new forward should be accepted by rule, got {:?}",
        verdict
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 8: Firewall Deny (WAN -> LAN uninvited)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_firewall_deny_wan_to_lan_uninvited() {
    let (_, _, _, _, _interfaces) = make_home_router_config();

    // Build a firewall config with only the lan->wan rule (no port-forward rule).
    let fw_config = FirewallConfig {
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
    };
    let fw = FirewallEngine::from_config(&fw_config);
    let conntrack = ConntrackEngine::new(ConntrackConfig {
        max_sessions: 10000,
        tcp_established_timeout_sec: 7200,
        tcp_transitory_timeout_sec: 120,
        udp_timeout_sec: 300,
        icmp_timeout_sec: 30,
    });

    // New TCP from WAN to LAN on a non-port-forwarded port (9999).
    let pkt = make_tcp_meta(
        "eth0",
        [0xEE; 6],
        WAN_MAC,
        EXTERNAL_CLIENT_IP,
        [192, 168, 1, 50],
        54321,
        9999,
        64,
        TCP_SYN,
    );
    let ctx = FwContext::from_packet(
        &pkt,
        FwChain::Forward,
        FirewallZone::Wan,
        FirewallZone::Lan,
        &conntrack,
    );
    let verdict = fw.evaluate(&ctx);
    assert_eq!(
        verdict,
        FwVerdict::Drop,
        "WAN->LAN new forward with no matching rule should be dropped by default policy"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 9: Firewall Established Return Traffic
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_firewall_established_return_traffic() {
    let (_, _, _, fw_config, _) = make_home_router_config();
    let fw = FirewallEngine::from_config(&fw_config);

    // Pre-populate conntrack with an established session.
    let mut conntrack = ConntrackEngine::new(ConntrackConfig {
        max_sessions: 10000,
        tcp_established_timeout_sec: 7200,
        tcp_transitory_timeout_sec: 120,
        udp_timeout_sec: 300,
        icmp_timeout_sec: 30,
    });
    let key = SessionKey {
        src_ip: EXTERNAL_IP,
        dst_ip: WAN_IP,
        proto: SessionProto::Tcp {
            src_port: 80,
            dst_port: 10000, // allocated NAT port
        },
    };
    conntrack
        .create_session(key, SessionState::Tcp(TcpState::Established))
        .unwrap();

    // Return packet from external server (8.8.8.8:80) to our WAN IP.
    let return_pkt = make_tcp_meta(
        "eth0",
        [0xEE; 6],
        WAN_MAC,
        EXTERNAL_IP,
        WAN_IP,
        80,
        10000,
        64,
        TCP_ACK,
    );
    let ctx = FwContext::from_packet(
        &return_pkt,
        FwChain::Forward,
        FirewallZone::Wan,
        FirewallZone::Lan,
        &conntrack,
    );
    let verdict = fw.evaluate(&ctx);
    assert_eq!(
        verdict,
        FwVerdict::Accept,
        "established return traffic should be accepted by allow_established_related"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 10: Full Pipeline (LAN -> WAN outbound + WAN -> LAN reply)
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_full_pipeline_outbound_and_reply() {
    let (_, routing_config, nat_config, fw_config, interfaces) = make_home_router_config();

    let l3 = L3Engine::from_config(&routing_config, &interfaces);
    let mut nat = NatEngine::from_config(&nat_config, &interfaces);
    let fw = FirewallEngine::from_config(&fw_config);
    let mut conntrack = make_conntrack_from_nat(&nat_config);

    // ══════════════════════════════════════════════════════════════════
    // Part A: Outbound (LAN host 192.168.1.100 → 8.8.8.8:80)
    // ══════════════════════════════════════════════════════════════════

    let outbound_pkt = make_tcp_meta(
        "eth1",
        HOST_A_MAC,
        LAN_MAC,
        HOST_A_IP,
        EXTERNAL_IP,
        49152,
        80,
        64,
        TCP_SYN,
    );

    // Step 1: L3 routing
    let l3_decision = l3.process(&outbound_pkt);
    assert_eq!(
        l3_decision,
        L3Decision::Forward {
            out_ifname: "eth0".to_string(),
            next_hop: GW_IP,
            new_ttl: 63,
        },
        "L3 should forward to eth0 via default route"
    );

    // Step 2: Firewall (LAN -> WAN new forward)
    let fw_ctx = FwContext::from_packet(
        &outbound_pkt,
        FwChain::Forward,
        FirewallZone::Lan,
        FirewallZone::Wan,
        &conntrack,
    );
    let fw_verdict = fw.evaluate(&fw_ctx);
    assert!(
        matches!(fw_verdict, FwVerdict::AcceptRule { .. }),
        "FW should accept LAN->WAN new forward, got {:?}",
        fw_verdict
    );

    // Step 3: NAT outbound SNAT
    let nat_action = nat.process_outbound(&outbound_pkt, &mut conntrack);
    let allocated_port = match &nat_action {
        NatAction::Snat {
            new_src_ip,
            new_src_port,
        } => {
            assert_eq!(*new_src_ip, WAN_IP, "SNAT to WAN IP");
            *new_src_port
        }
        other => panic!("expected Snat, got {:?}", other),
    };

    // ══════════════════════════════════════════════════════════════════
    // Part B: Inbound reply (8.8.8.8:80 → WAN_IP:allocated_port)
    // ══════════════════════════════════════════════════════════════════

    // For the return path to work, we need a reverse session in conntrack.
    // In a real router, this would be created when the outbound packet is
    // actually sent. For this test, we manually create it.
    let reverse_key = SessionKey {
        src_ip: EXTERNAL_IP,
        dst_ip: WAN_IP,
        proto: SessionProto::Tcp {
            src_port: 80,
            dst_port: allocated_port,
        },
    };
    conntrack
        .create_session(reverse_key, SessionState::Tcp(TcpState::Established))
        .unwrap();

    let reply_pkt = make_tcp_meta(
        "eth0",
        [0xEE; 6],
        WAN_MAC,
        EXTERNAL_IP,
        WAN_IP,
        80,
        allocated_port,
        64,
        TCP_SYN_ACK,
    );

    // Step 4: Firewall (WAN -> LAN established)
    let reply_fw_ctx = FwContext::from_packet(
        &reply_pkt,
        FwChain::Forward,
        FirewallZone::Wan,
        FirewallZone::Lan,
        &conntrack,
    );
    let reply_fw_verdict = fw.evaluate(&reply_fw_ctx);
    assert_eq!(
        reply_fw_verdict,
        FwVerdict::Accept,
        "established return traffic should be accepted"
    );

    // Step 5: L3 routing for reply (to LAN subnet)
    // Simulate the NAT-rewritten packet destined to LAN host
    let reply_after_nat = PacketMeta {
        in_ifname: "eth0".to_string(),
        l2: make_l2([0xEE; 6], WAN_MAC),
        l3: Some(L3Info::Ipv4(make_ipv4(EXTERNAL_IP, HOST_A_IP, 63, 6))),
        l4: Some(make_tcp_l4(80, 49152, TCP_SYN_ACK)),
        raw_len: 54,
    };
    let reply_l3 = l3.process(&reply_after_nat);
    assert_eq!(
        reply_l3,
        L3Decision::Forward {
            out_ifname: "eth1".to_string(),
            next_hop: [0, 0, 0, 0],
            new_ttl: 62,
        },
        "reply should be routed to LAN via eth1"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Scenario 11: Observer Integration
// ══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_observer_counter_tracking() {
    let (_, routing_config, nat_config, _, interfaces) = make_home_router_config();

    let l3 = L3Engine::from_config(&routing_config, &interfaces);

    // Use a restrictive firewall config that only allows LAN->WAN
    // (no WAN->LAN rule), so our uninvited WAN packet will be dropped.
    let restrictive_fw_config = FirewallConfig {
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
    };
    let fw = FirewallEngine::from_config(&restrictive_fw_config);

    // Create observer with the configured interface names.
    let if_names: Vec<String> = interfaces.iter().map(|i| i.name.clone()).collect();
    let observer = Observer::new(&if_names);

    // ── Packet 1: LAN -> WAN (successful forward) ───────────────────
    let pkt1 = make_tcp_meta(
        "eth1",
        HOST_A_MAC,
        LAN_MAC,
        HOST_A_IP,
        EXTERNAL_IP,
        49152,
        80,
        64,
        TCP_SYN,
    );
    observer.inc_rx("eth1", pkt1.raw_len as u64);

    let l3_decision = l3.process(&pkt1);
    match &l3_decision {
        L3Decision::Forward { out_ifname, .. } => {
            observer.inc_forwarded();
            observer.inc_tx(out_ifname, pkt1.raw_len as u64);
        }
        L3Decision::Drop { reason } => match reason {
            L3DropReason::TtlExpired => observer.inc_drop_reason(DropReason::L3TtlExpired),
            L3DropReason::NoRoute => observer.inc_drop_reason(DropReason::L3NoRoute),
            L3DropReason::NotIpv4 => observer.inc_drop_reason(DropReason::L3NotIpv4),
        },
        L3Decision::LocalDelivery => {
            observer.inc_local_delivery();
        }
    }

    // ── Packet 2: TTL expired → drop ────────────────────────────────
    let pkt2 = PacketMeta {
        in_ifname: "eth1".to_string(),
        l2: make_l2(HOST_A_MAC, LAN_MAC),
        l3: Some(L3Info::Ipv4(make_ipv4(HOST_A_IP, EXTERNAL_IP, 1, 6))),
        l4: Some(make_tcp_l4(49153, 80, TCP_SYN)),
        raw_len: 54,
    };
    observer.inc_rx("eth1", pkt2.raw_len as u64);

    let l3_decision2 = l3.process(&pkt2);
    match &l3_decision2 {
        L3Decision::Forward { out_ifname, .. } => {
            observer.inc_forwarded();
            observer.inc_tx(out_ifname, pkt2.raw_len as u64);
        }
        L3Decision::Drop { reason } => match reason {
            L3DropReason::TtlExpired => observer.inc_drop_reason(DropReason::L3TtlExpired),
            L3DropReason::NoRoute => observer.inc_drop_reason(DropReason::L3NoRoute),
            L3DropReason::NotIpv4 => observer.inc_drop_reason(DropReason::L3NotIpv4),
        },
        L3Decision::LocalDelivery => {
            observer.inc_local_delivery();
        }
    }

    // ── Packet 3: Firewall drop (WAN -> LAN uninvited) ──────────────
    let pkt3 = make_tcp_meta(
        "eth0",
        [0xEE; 6],
        WAN_MAC,
        EXTERNAL_CLIENT_IP,
        [192, 168, 1, 50],
        54321,
        9999,
        64,
        TCP_SYN,
    );
    observer.inc_rx("eth0", pkt3.raw_len as u64);
    let conntrack = make_conntrack_from_nat(&nat_config);
    let fw_ctx = FwContext::from_packet(
        &pkt3,
        FwChain::Forward,
        FirewallZone::Wan,
        FirewallZone::Lan,
        &conntrack,
    );
    let fw_verdict = fw.evaluate(&fw_ctx);
    if matches!(fw_verdict, FwVerdict::Drop | FwVerdict::DropRule { .. }) {
        observer.inc_drop_reason(DropReason::FirewallDrop);
    }

    // ── Verify counters via snapshot ─────────────────────────────────
    let snap = observer.snapshot();

    // Forwarded count
    assert_eq!(snap.forwarded, 1, "one packet successfully forwarded");
    assert_eq!(snap.local_delivery, 0, "no local deliveries");

    // Drop counters
    assert_eq!(snap.drops.l3_ttl_expired, 1, "one TTL-expired drop");
    assert_eq!(snap.drops.fw_drop, 1, "one firewall drop");
    assert_eq!(snap.drops.l3_no_route, 0, "no no-route drops");

    // Per-interface counters
    let eth1_snap = snap.interfaces.iter().find(|i| i.name == "eth1").unwrap();
    assert_eq!(eth1_snap.rx_packets, 2, "eth1 received 2 packets");
    assert_eq!(eth1_snap.rx_bytes, 108, "eth1 received 54 + 54 = 108 bytes");

    let eth0_snap = snap.interfaces.iter().find(|i| i.name == "eth0").unwrap();
    assert_eq!(eth0_snap.rx_packets, 1, "eth0 received 1 packet (WAN)");
    assert_eq!(
        eth0_snap.tx_packets, 1,
        "eth0 transmitted 1 packet (forwarded outbound)"
    );

    // Verify Display output contains expected keywords.
    let display_output = format!("{snap}");
    assert!(
        display_output.contains("ruster stats"),
        "display should contain header"
    );
    assert!(
        display_output.contains("Forwarded: 1"),
        "display should show forwarded count"
    );
    assert!(
        display_output.contains("L3/ttl-expired: 1"),
        "display should show TTL-expired drop"
    );
    assert!(
        display_output.contains("FW/drop: 1"),
        "display should show FW drop"
    );
}

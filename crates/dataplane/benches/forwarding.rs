//! Criterion benchmarks for the ruster dataplane forwarding path.
//!
//! Measures per-packet processing time and throughput for individual
//! pipeline stages and the full forwarding path.
//!
//! Run:
//!   cargo bench -p ruster-dataplane
//!
//! Generate HTML report:
//!   cargo bench -p ruster-dataplane -- --output-format bencher

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ruster_config::model::{
    BridgeDomain, Chain, ConnState, DefaultPolicy, FirewallConfig, FirewallRule, FirewallZone,
    InterfaceConfig, InterfaceRole, InterfaceZone, L2Config, NatConfig, NatMode, PortForward,
    PortForwardProto, RoutingConfig, RuleAction, RuleProto, StaticRoute,
};

use ruster_dataplane::arp::ArpEngine;
use ruster_dataplane::conntrack::session::{SessionKey, SessionProto, SessionState, TcpState};
use ruster_dataplane::conntrack::{ConntrackConfig, ConntrackEngine};
use ruster_dataplane::firewall::{FirewallEngine, FwChain, FwContext, FwProto};
use ruster_dataplane::l2::L2Engine;
use ruster_dataplane::nat::NatEngine;
use ruster_dataplane::packet::{ArpInfo, Ipv4Info, L2Info, L3Info, L4Info, PacketMeta, TcpInfo};
use ruster_dataplane::routing::L3Engine;

// ── Packet sizes for throughput calculation ─────────────────────────

const SMALL_PKT: usize = 64;
const MEDIUM_PKT: usize = 512;
const LARGE_PKT: usize = 1500;

// ── Configuration builders (shared across benchmarks) ───────────────

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
        InterfaceConfig {
            name: "lan1".to_string(),
            port_id: 2,
            role: InterfaceRole::Lan,
            admin_up: true,
            mtu: 1500,
            mac: "00:AA:BB:CC:DD:FF".to_string(),
            ipv4_addrs: vec!["192.168.2.1/24".to_string()],
            zone: InterfaceZone::Lan,
            l2_domain: "br0".to_string(),
            linux_if: None,
        },
    ]
}

fn make_l2_config() -> L2Config {
    L2Config {
        mac_table_max_entries: 4096,
        mac_aging_sec: 300,
        arp_table_max_entries: 1024,
        arp_timeout_sec: 120,
        bridge_domains: vec![BridgeDomain {
            name: "br0".to_string(),
            members: vec!["wan0".to_string(), "lan0".to_string(), "lan1".to_string()],
        }],
    }
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
            StaticRoute {
                prefix: "192.168.2.0/24".to_string(),
                next_hop: "0.0.0.0".to_string(),
                out_if: "lan1".to_string(),
                metric: 10,
            },
        ],
        ipv6_static_routes: vec![],
        ospf: None,
        bgp: None,
    }
}

fn make_nat_config() -> NatConfig {
    NatConfig {
        enabled: true,
        mode: NatMode::Napt44,
        external_if: "wan0".to_string(),
        hairpin: false,
        session_table_max_entries: 65536,
        tcp_established_timeout_sec: 7200,
        tcp_transitory_timeout_sec: 120,
        udp_timeout_sec: 300,
        icmp_timeout_sec: 30,
        port_forwards: vec![PortForward {
            name: "web".to_string(),
            proto: PortForwardProto::Tcp,
            external_port: 8080,
            internal_addr: "192.168.1.50".to_string(),
            internal_port: 80,
        }],
    }
}

fn make_fw_config() -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        default_input: DefaultPolicy::Drop,
        default_forward: DefaultPolicy::Drop,
        default_output: DefaultPolicy::Accept,
        allow_established_related: true,
        rules: vec![
            FirewallRule {
                name: "allow-lan-to-wan".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Any,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                state: vec![ConnState::New, ConnState::Established, ConnState::Related],
            },
            FirewallRule {
                name: "allow-lan-input-icmp".to_string(),
                chain: Chain::Input,
                action: RuleAction::Accept,
                proto: RuleProto::Icmp,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Any,
                state: vec![ConnState::New],
            },
        ],
    }
}

fn make_conntrack_config() -> ConntrackConfig {
    ConntrackConfig {
        max_sessions: 65536,
        tcp_established_timeout_sec: 7200,
        tcp_transitory_timeout_sec: 120,
        udp_timeout_sec: 300,
        icmp_timeout_sec: 30,
    }
}

// ── Packet builders ──────────────────────────────────────────────────

fn make_l2_meta(
    _in_ifname: &str,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    pkt_size: usize,
) -> PacketMeta {
    PacketMeta {
        in_ifindex: 0, // test index
        l2: L2Info {
            dst_mac,
            src_mac,
            ethertype: 0x0800,
        },
        l3: None,
        l4: None,
        raw_len: pkt_size,
    }
}

fn make_ipv4_tcp_meta(
    _in_ifname: &str,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    pkt_size: usize,
) -> PacketMeta {
    PacketMeta {
        in_ifindex: 0, // test index
        l2: L2Info {
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ethertype: 0x0800,
        },
        l3: Some(L3Info::Ipv4(Ipv4Info {
            src_addr,
            dst_addr,
            ttl: 64,
            protocol: 6,
            header_len: 20,
            total_len: (pkt_size - 14) as u16,
            identification: 1,
            flags: 0x40,
            fragment_offset: 0,
            checksum: 0,
            payload_offset: 34,
        })),
        l4: Some(L4Info::Tcp(TcpInfo {
            src_port,
            dst_port,
            seq_num: 1000,
            ack_num: 500,
            data_offset: 5,
            flags: 0x10, // ACK
            window: 65535,
            checksum: 0,
        })),
        raw_len: pkt_size,
    }
}

/// Build a raw Ethernet + IPv4 + TCP packet for parsing benchmarks.
fn build_raw_tcp_packet(pkt_size: usize) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(pkt_size);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
    pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes)
    let ipv4_total_len = (pkt_size - 14) as u16;
    let ipv4_start = pkt.len();
    pkt.push(0x45); // Version=4, IHL=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&ipv4_total_len.to_be_bytes()); // Total Length
    pkt.extend_from_slice(&[0x00, 0x01]); // Identification
    pkt.extend_from_slice(&[0x40, 0x00]); // Flags: DF
    pkt.push(64); // TTL
    pkt.push(6); // Protocol: TCP
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
    pkt.extend_from_slice(&[192, 168, 1, 100]); // Src
    pkt.extend_from_slice(&[8, 8, 8, 8]); // Dst

    // Compute IPv4 checksum
    {
        let hdr = &mut pkt[ipv4_start..ipv4_start + 20];
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

    // TCP header (20 bytes)
    pkt.extend_from_slice(&[0xC0, 0x00]); // Src port: 49152
    pkt.extend_from_slice(&[0x00, 0x50]); // Dst port: 80
    pkt.extend_from_slice(&[0x00, 0x00, 0x03, 0xE8]); // Seq: 1000
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack: 0
    pkt.push(0x50); // Data offset: 5
    pkt.push(0x02); // Flags: SYN
    pkt.extend_from_slice(&[0xFF, 0xFF]); // Window
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

    // Pad to the requested packet size
    while pkt.len() < pkt_size {
        pkt.push(0x00);
    }

    pkt
}

// ── Benchmarks ───────────────────────────────────────────────────────

fn bench_packet_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_parse");

    for &pkt_size in &[SMALL_PKT, MEDIUM_PKT, LARGE_PKT] {
        let raw = build_raw_tcp_packet(pkt_size);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("tcp_ipv4", pkt_size), &raw, |b, raw| {
            b.iter(|| ruster_dataplane::packet::parse_packet(black_box(raw), 0));
        });
    }

    group.finish();
}

fn bench_l2_bridge(c: &mut Criterion) {
    let mut group = c.benchmark_group("l2_bridge");
    group.throughput(Throughput::Elements(1));

    let l2_config = make_l2_config();

    // FDB hit benchmark
    {
        let ifm = ruster_dataplane::pipeline::IfIndexMap::from_names(&[
            "eth0".to_string(),
            "eth1".to_string(),
            "eth2".to_string(),
        ]);
        let mut engine = L2Engine::from_config(&l2_config, &ifm);
        let dst_mac: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let learn_meta = make_l2_meta("lan1", dst_mac, [0x00; 6], LARGE_PKT);
        engine.process(&learn_meta);

        let src_mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let meta = make_l2_meta("lan0", src_mac, dst_mac, LARGE_PKT);

        group.bench_function("fdb_hit", |b| {
            b.iter(|| engine.process(black_box(&meta)));
        });
    }

    // FDB miss (flood) benchmark
    {
        let ifm = ruster_dataplane::pipeline::IfIndexMap::from_names(&[
            "eth0".to_string(),
            "eth1".to_string(),
            "eth2".to_string(),
        ]);
        let mut engine = L2Engine::from_config(&l2_config, &ifm);
        let src_mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let unknown_mac: [u8; 6] = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA];
        let meta = make_l2_meta("lan0", src_mac, unknown_mac, LARGE_PKT);

        group.bench_function("fdb_miss_flood", |b| {
            b.iter(|| engine.process(black_box(&meta)));
        });
    }

    group.finish();
}

fn bench_l3_forward(c: &mut Criterion) {
    let mut group = c.benchmark_group("l3_forward");
    group.throughput(Throughput::Elements(1));

    let interfaces = make_interfaces();
    let engine = L3Engine::from_config(&make_routing_config(), &interfaces).unwrap();

    // Default route hit (LAN -> WAN)
    let meta = make_ipv4_tcp_meta(
        "lan0",
        [192, 168, 1, 100],
        [8, 8, 8, 8],
        49152,
        80,
        LARGE_PKT,
    );
    group.bench_function("default_route", |b| {
        b.iter(|| engine.process(black_box(&meta)));
    });

    // Direct route hit (LAN subnet)
    let meta_direct = make_ipv4_tcp_meta(
        "wan0",
        [10, 0, 0, 1],
        [192, 168, 1, 100],
        49152,
        80,
        LARGE_PKT,
    );
    group.bench_function("direct_route", |b| {
        b.iter(|| engine.process(black_box(&meta_direct)));
    });

    group.finish();
}

fn bench_firewall(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall");
    group.throughput(Throughput::Elements(1));

    let engine = FirewallEngine::from_config(&make_fw_config());

    // Accept path (matches first rule)
    let ctx_accept = FwContext {
        chain: FwChain::Forward,
        src_zone: FirewallZone::Lan,
        dst_zone: FirewallZone::Wan,
        proto: FwProto::Tcp,
        is_established: false,
        is_new: true,
    };
    group.bench_function("accept", |b| {
        b.iter(|| engine.evaluate(black_box(&ctx_accept)));
    });

    // Drop path (falls through all rules to default policy)
    let ctx_drop = FwContext {
        chain: FwChain::Forward,
        src_zone: FirewallZone::Wan,
        dst_zone: FirewallZone::Lan,
        proto: FwProto::Tcp,
        is_established: false,
        is_new: true,
    };
    group.bench_function("drop", |b| {
        b.iter(|| engine.evaluate(black_box(&ctx_drop)));
    });

    group.finish();
}

fn bench_nat(c: &mut Criterion) {
    let mut group = c.benchmark_group("nat");
    group.throughput(Throughput::Elements(1));

    let nat_config = make_nat_config();
    let interfaces = make_interfaces();

    // Existing session (fast path)
    {
        let mut nat_engine = NatEngine::from_config(&nat_config, &interfaces);
        let mut conntrack = ConntrackEngine::new(make_conntrack_config());
        let meta = make_ipv4_tcp_meta(
            "lan0",
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            49152,
            80,
            LARGE_PKT,
        );
        nat_engine.process_outbound(&meta, &mut conntrack);

        group.bench_function("outbound_existing", |b| {
            b.iter(|| nat_engine.process_outbound(black_box(&meta), &mut conntrack));
        });
    }

    group.finish();
}

fn bench_conntrack(c: &mut Criterion) {
    let mut group = c.benchmark_group("conntrack");
    group.throughput(Throughput::Elements(1));

    let mut conntrack = ConntrackEngine::new(make_conntrack_config());
    let key = SessionKey {
        src_ip: [192, 168, 1, 100],
        dst_ip: [8, 8, 8, 8],
        proto: SessionProto::Tcp {
            src_port: 49152,
            dst_port: 80,
        },
    };
    conntrack
        .create_session(key, SessionState::Tcp(TcpState::Established))
        .unwrap();

    group.bench_function("lookup_hit", |b| {
        b.iter(|| conntrack.lookup(black_box(&key)));
    });

    group.finish();
}

fn bench_arp_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("arp_cache");
    group.throughput(Throughput::Elements(1));

    let l2_config = make_l2_config();
    let interfaces = make_interfaces();
    let mut engine = ArpEngine::from_config(&l2_config, &interfaces);

    // Pre-populate ARP cache via a reply.
    let reply_meta = PacketMeta {
        in_ifindex: 0, // lan0
        l2: L2Info {
            dst_mac: [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            src_mac: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            ethertype: 0x0806,
        },
        l3: Some(L3Info::Arp(ArpInfo {
            operation: 2,
            sender_mac: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            sender_ip: [192, 168, 1, 100],
            target_mac: [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            target_ip: [192, 168, 1, 1],
        })),
        l4: None,
        raw_len: 42,
    };
    engine.process_arp(&reply_meta, "eth0");

    let target_ip: [u8; 4] = [192, 168, 1, 100];

    group.bench_function("resolve_hit", |b| {
        b.iter(|| engine.resolve(black_box(target_ip), "lan0"));
    });

    group.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");
    group.throughput(Throughput::Elements(1));

    let interfaces = make_interfaces();
    let l3_engine = L3Engine::from_config(&make_routing_config(), &interfaces).unwrap();
    let fw_engine = FirewallEngine::from_config(&make_fw_config());
    let nat_config = make_nat_config();
    let mut nat_engine = NatEngine::from_config(&nat_config, &interfaces);
    let mut conntrack = ConntrackEngine::new(make_conntrack_config());

    let meta = make_ipv4_tcp_meta(
        "lan0",
        [192, 168, 1, 100],
        [8, 8, 8, 8],
        49152,
        80,
        LARGE_PKT,
    );
    nat_engine.process_outbound(&meta, &mut conntrack);

    group.bench_function("l3_fw_nat", |b| {
        b.iter(|| {
            // Step 1: L3 routing decision
            let _ = l3_engine.process(black_box(&meta));

            // Step 2: Firewall evaluation
            let ctx = FwContext {
                chain: FwChain::Forward,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                proto: FwProto::Tcp,
                is_established: false,
                is_new: true,
            };
            let _ = fw_engine.evaluate(black_box(&ctx));

            // Step 3: NAT outbound
            let _ = nat_engine.process_outbound(black_box(&meta), &mut conntrack);
        });
    });

    group.finish();
}

// ── Criterion harness ────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_packet_parse,
    bench_l2_bridge,
    bench_l3_forward,
    bench_firewall,
    bench_nat,
    bench_conntrack,
    bench_arp_cache,
    bench_full_pipeline,
);
criterion_main!(benches);

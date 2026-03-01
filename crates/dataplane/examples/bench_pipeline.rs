//! Performance measurement tool for the ruster dataplane pipeline.
//!
//! Usage: cargo run --release -p ruster-dataplane --example bench_pipeline
//!
//! Measures per-packet processing time and throughput for:
//! - L2 bridging (FDB lookup)
//! - L3 routing (LPM lookup)
//! - NAT translation (outbound SNAT)
//! - Firewall evaluation
//! - Full pipeline (L3 + FW + NAT)
//! - Conntrack lookup
//! - ARP cache lookup

use std::time::{Duration, Instant};

use ruster_config::model::{
    BridgeDomain, Chain, ConnState, DefaultPolicy, FirewallConfig, FirewallRule, FirewallZone,
    InterfaceConfig, InterfaceRole, InterfaceZone, L2Config, NatConfig, NatMode, PortForward,
    PortForwardProto, RoutingConfig, RuleAction, RuleProto, StaticRoute,
};

use ruster_dataplane::arp::ArpEngine;
use ruster_dataplane::conntrack::session::{SessionKey, SessionProto, SessionState, TcpState};
use ruster_dataplane::conntrack::{ConntrackConfig, ConntrackEngine};
use ruster_dataplane::firewall::{FirewallEngine, FwChain, FwContext, FwProto, FwVerdict};
use ruster_dataplane::l2::L2Engine;
use ruster_dataplane::nat::NatEngine;
use ruster_dataplane::packet::{Ipv4Info, L2Info, L3Info, L4Info, PacketMeta, TcpInfo};
use ruster_dataplane::routing::L3Engine;

// ── Constants ────────────────────────────────────────────────────────

const ITERATIONS: u64 = 1_000_000;
const PACKET_SIZE: u64 = 1500;

// ── Benchmark result ─────────────────────────────────────────────────

struct BenchResult {
    name: String,
    total_time: Duration,
    iterations: u64,
}

impl BenchResult {
    fn time_per_pkt_ns(&self) -> f64 {
        self.total_time.as_nanos() as f64 / self.iterations as f64
    }

    fn mpps(&self) -> f64 {
        let pps = self.iterations as f64 / self.total_time.as_secs_f64();
        pps / 1_000_000.0
    }

    fn gbps(&self) -> f64 {
        let pps = self.iterations as f64 / self.total_time.as_secs_f64();
        (pps * PACKET_SIZE as f64 * 8.0) / 1_000_000_000.0
    }
}

// ── Configuration helpers ────────────────────────────────────────────

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
            ipv6_addrs: vec![],
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
            ipv6_addrs: vec![],
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
            ipv6_addrs: vec![],
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
        arp_hold_queue_per_ip: 3,
        arp_hold_queue_max: 1024,
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

fn make_l2_meta(_in_ifname: &str, src_mac: [u8; 6], dst_mac: [u8; 6]) -> PacketMeta {
    PacketMeta {
        in_ifindex: 0, // test index
        l2: L2Info {
            dst_mac,
            src_mac,
            ethertype: 0x0800,
        },
        l3: None,
        l4: None,
        raw_len: PACKET_SIZE as usize,
    }
}

fn make_ipv4_tcp_meta(
    _in_ifname: &str,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
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
            total_len: 1480,
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
        raw_len: PACKET_SIZE as usize,
    }
}

// ── Warmup helper ────────────────────────────────────────────────────

/// Run a warmup phase to stabilize CPU caches and branch predictors.
fn warmup<F: FnMut()>(mut f: F) {
    for _ in 0..10_000 {
        f();
    }
}

// ── Benchmark functions ──────────────────────────────────────────────

fn bench_l2_fdb_hit() -> BenchResult {
    let l2_config = make_l2_config();
    let ifm = ruster_dataplane::pipeline::IfIndexMap::from_names(&[
        "eth0".to_string(),
        "eth1".to_string(),
        "eth2".to_string(),
    ]);
    let mut engine = L2Engine::from_config(&l2_config, &ifm);

    // Learn a MAC so subsequent lookups are cache hits.
    let dst_mac: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
    let learn_meta = make_l2_meta("lan1", dst_mac, [0x00; 6]);
    engine.process(&learn_meta);

    // Packet from lan0 to the learned MAC on lan1 -> unicast hit.
    let src_mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let meta = make_l2_meta("lan0", src_mac, dst_mac);

    warmup(|| {
        let _ = engine.process(&meta);
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = engine.process(&meta);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "L2 FDB lookup (hit)".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

fn bench_l3_lpm_lookup() -> BenchResult {
    let routing_config = make_routing_config();
    let interfaces = make_interfaces();
    let engine = L3Engine::from_config(&routing_config, &interfaces).unwrap();

    // Packet destined to an external IP -> LPM hit on default route.
    let meta = make_ipv4_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);

    warmup(|| {
        let _ = engine.process(&meta);
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = engine.process(&meta);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "L3 LPM lookup".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

fn bench_nat_outbound_existing() -> BenchResult {
    let nat_config = make_nat_config();
    let interfaces = make_interfaces();
    let mut nat_engine = NatEngine::from_config(&nat_config, &interfaces);
    let mut conntrack = ConntrackEngine::new(make_conntrack_config());

    // Create a session with the first outbound packet.
    let meta = make_ipv4_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);
    nat_engine.process_outbound(&meta, &mut conntrack);

    // Subsequent packets reuse the existing session.
    warmup(|| {
        let _ = nat_engine.process_outbound(&meta, &mut conntrack);
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = nat_engine.process_outbound(&meta, &mut conntrack);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "NAT outbound (existing)".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

fn bench_nat_outbound_new() -> BenchResult {
    let nat_config = make_nat_config();
    let interfaces = make_interfaces();

    // We measure single-shot "new session" creation performance by creating
    // many unique sessions. We use fewer iterations to keep conntrack reasonable.
    let iterations = 100_000u64;

    let mut nat_engine = NatEngine::from_config(&nat_config, &interfaces);
    let mut conntrack = ConntrackEngine::new(ConntrackConfig {
        max_sessions: iterations as usize + 10,
        ..make_conntrack_config()
    });

    // Build unique packet metadata per iteration (varying source port).
    let metas: Vec<PacketMeta> = (0..iterations)
        .map(|i| {
            let src_port = 10000 + (i as u16);
            make_ipv4_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], src_port, 80)
        })
        .collect();

    // Warmup with a separate engine.
    let mut warmup_nat = NatEngine::from_config(&nat_config, &interfaces);
    let mut warmup_ct = ConntrackEngine::new(ConntrackConfig {
        max_sessions: 20_000,
        ..make_conntrack_config()
    });
    for meta in metas.iter().take(10_000) {
        let _ = warmup_nat.process_outbound(meta, &mut warmup_ct);
    }

    let start = Instant::now();
    for meta in &metas {
        let _ = nat_engine.process_outbound(meta, &mut conntrack);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "NAT outbound (new session)".to_string(),
        total_time: elapsed,
        iterations,
    }
}

fn bench_fw_accept() -> BenchResult {
    let fw_config = make_fw_config();
    let engine = FirewallEngine::from_config(&fw_config);

    // New LAN -> WAN forward: matches the "allow-lan-to-wan" rule.
    let ctx = FwContext {
        chain: FwChain::Forward,
        src_zone: FirewallZone::Lan,
        dst_zone: FirewallZone::Wan,
        proto: FwProto::Tcp,
        is_established: false,
        is_new: true,
    };

    warmup(|| {
        let _ = engine.evaluate(&ctx);
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = engine.evaluate(&ctx);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "Firewall evaluate (accept)".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

fn bench_fw_drop() -> BenchResult {
    let fw_config = make_fw_config();
    let engine = FirewallEngine::from_config(&fw_config);

    // New WAN -> LAN forward: no matching rule, falls through to default drop.
    let ctx = FwContext {
        chain: FwChain::Forward,
        src_zone: FirewallZone::Wan,
        dst_zone: FirewallZone::Lan,
        proto: FwProto::Tcp,
        is_established: false,
        is_new: true,
    };

    warmup(|| {
        let _ = engine.evaluate(&ctx);
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = engine.evaluate(&ctx);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "Firewall evaluate (drop)".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

fn bench_conntrack_lookup() -> BenchResult {
    let mut conntrack = ConntrackEngine::new(make_conntrack_config());

    // Pre-populate with a session.
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

    warmup(|| {
        let _ = conntrack.lookup(&key);
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = conntrack.lookup(&key);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "Conntrack lookup".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

fn bench_arp_cache_hit() -> BenchResult {
    let l2_config = make_l2_config();
    let interfaces = make_interfaces();
    let mut engine = ArpEngine::from_config(&l2_config, &interfaces);

    // Pre-populate ARP cache with a resolved entry by calling resolve
    // first (which marks pending), then simulate a reply by using the
    // internal process_arp flow. Instead, we just call resolve twice
    // after manually inserting. The ArpEngine test pattern uses the
    // caches field which is private. We use process_arp with a reply.
    use ruster_dataplane::packet::ArpInfo;

    let reply_meta = PacketMeta {
        in_ifindex: 0, // lan0
        l2: L2Info {
            dst_mac: [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            src_mac: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            ethertype: 0x0806,
        },
        l3: Some(L3Info::Arp(ArpInfo {
            operation: 2, // ARP reply
            sender_mac: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
            sender_ip: [192, 168, 1, 100],
            target_mac: [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            target_ip: [192, 168, 1, 1],
        })),
        l4: None,
        raw_len: 42,
    };
    engine.process_arp(&reply_meta, "eth0");

    // Now resolve should hit the cache.
    let target_ip: [u8; 4] = [192, 168, 1, 100];

    warmup(|| {
        let _ = engine.resolve(target_ip, "lan0");
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = engine.resolve(target_ip, "lan0");
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "ARP cache lookup".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

fn bench_full_pipeline() -> BenchResult {
    // Set up all engines.
    let interfaces = make_interfaces();
    let l3_engine = L3Engine::from_config(&make_routing_config(), &interfaces).unwrap();
    let fw_engine = FirewallEngine::from_config(&make_fw_config());
    let nat_config = make_nat_config();
    let mut nat_engine = NatEngine::from_config(&nat_config, &interfaces);
    let mut conntrack = ConntrackEngine::new(make_conntrack_config());

    // LAN host (192.168.1.100) sending TCP to external (8.8.8.8:80).
    let meta = make_ipv4_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);

    // Pre-create the NAT session so subsequent calls reuse it.
    nat_engine.process_outbound(&meta, &mut conntrack);

    // Full pipeline: L3 -> FW -> NAT
    warmup(|| {
        // L3 routing
        let _ = l3_engine.process(&meta);
        // Firewall
        let ctx = FwContext {
            chain: FwChain::Forward,
            src_zone: FirewallZone::Lan,
            dst_zone: FirewallZone::Wan,
            proto: FwProto::Tcp,
            is_established: false,
            is_new: true,
        };
        let _ = fw_engine.evaluate(&ctx);
        // NAT
        let _ = nat_engine.process_outbound(&meta, &mut conntrack);
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        // Step 1: L3 routing decision
        let _ = l3_engine.process(&meta);

        // Step 2: Firewall evaluation
        let ctx = FwContext {
            chain: FwChain::Forward,
            src_zone: FirewallZone::Lan,
            dst_zone: FirewallZone::Wan,
            proto: FwProto::Tcp,
            is_established: false,
            is_new: true,
        };
        let _ = fw_engine.evaluate(&ctx);

        // Step 3: NAT outbound
        let _ = nat_engine.process_outbound(&meta, &mut conntrack);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "Full pipeline (L3+FW+NAT)".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

fn bench_packet_parse() -> BenchResult {
    // Build a raw TCP/IPv4 packet for parsing benchmarks.
    let raw_packet = build_raw_tcp_packet();

    warmup(|| {
        let _ = ruster_dataplane::packet::parse_packet(&raw_packet, 0);
    });

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = ruster_dataplane::packet::parse_packet(&raw_packet, 0);
    }
    let elapsed = start.elapsed();

    BenchResult {
        name: "Packet parse (TCP/IPv4)".to_string(),
        total_time: elapsed,
        iterations: ITERATIONS,
    }
}

/// Build a raw Ethernet + IPv4 + TCP packet for parsing benchmarks.
fn build_raw_tcp_packet() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(54);

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
    pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes)
    let ipv4_start = pkt.len();
    pkt.push(0x45); // Version=4, IHL=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&[0x00, 0x28]); // Total Length: 40
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

    pkt
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    println!();
    println!("=== ruster v0.1 Performance Report ===");
    println!("Packet size: {} bytes", PACKET_SIZE);
    println!(
        "Iterations : {} (per benchmark, except NAT new = 100K)",
        ITERATIONS
    );
    println!();

    let results = vec![
        bench_packet_parse(),
        bench_l2_fdb_hit(),
        bench_l3_lpm_lookup(),
        bench_nat_outbound_existing(),
        bench_nat_outbound_new(),
        bench_fw_accept(),
        bench_fw_drop(),
        bench_conntrack_lookup(),
        bench_arp_cache_hit(),
        bench_full_pipeline(),
    ];

    println!(
        "{:<30} | {:>14} | {:>7} | {:>12}",
        "Benchmark", "Time/pkt (ns)", "Mpps", "Gbps (1500B)"
    );
    println!("{}", "-".repeat(72));

    for r in &results {
        println!(
            "{:<30} | {:>14.1} | {:>7.2} | {:>12.2}",
            r.name,
            r.time_per_pkt_ns(),
            r.mpps(),
            r.gbps()
        );
    }

    println!();
    println!("=== Analysis ===");

    // Find the full pipeline result for analysis.
    if let Some(full) = results.iter().find(|r| r.name.starts_with("Full pipeline")) {
        let mpps = full.mpps();
        let gbps = full.gbps();
        println!(
            "- Full pipeline: ~{:.1} Mpps -> ~{:.2} Gbps @ {}B",
            mpps, gbps, PACKET_SIZE
        );
        // 10GbE line rate at 1500B: ~0.83 Mpps
        // (10 Gbps / (1500 bytes * 8 bits/byte) = 833,333 pps)
        let line_rate_mpps = 10_000_000_000.0 / (PACKET_SIZE as f64 * 8.0) / 1_000_000.0;
        let speedup = line_rate_mpps / mpps;
        if speedup > 1.0 {
            println!(
                "- For 10GbE line rate ({:.1} Mpps @ {}B): pipeline needs ~{:.1}x speedup",
                line_rate_mpps, PACKET_SIZE, speedup
            );
        } else {
            println!(
                "- Full pipeline exceeds 10GbE line rate ({:.1} Mpps @ {}B)",
                line_rate_mpps, PACKET_SIZE
            );
        }
    }

    // Find the bottleneck (slowest per-packet time).
    if let Some(slowest) = results.iter().max_by(|a, b| {
        a.time_per_pkt_ns()
            .partial_cmp(&b.time_per_pkt_ns())
            .unwrap()
    }) {
        if !slowest.name.starts_with("Full pipeline") {
            println!(
                "- Bottleneck stage: {} ({:.1} ns/pkt)",
                slowest.name,
                slowest.time_per_pkt_ns()
            );
        }
    }

    println!();
    println!("=== Optimization Candidates for v0.2 ===");
    println!("  1. Replace HashMap with array-based lookup for small tables (FDB, ARP)");
    println!("  2. Avoid String cloning in hot paths (use &str or indices)");
    println!("  3. Batch processing (amortize function call overhead)");
    println!("  4. SIMD-accelerated LPM (trie vs linear scan)");
    println!("  5. Pre-parsed PacketMeta pool (avoid allocation per packet)");
    println!("  6. Lock-free conntrack with sharded hash tables");
    println!("  7. DPDK native batch RX/TX with ring buffers");
    println!();

    // Verify correctness: run one of each path and ensure expected results.
    verify_correctness();
}

/// Quick correctness check to ensure the benchmarked code paths produce
/// expected results (guards against measuring broken code).
fn verify_correctness() {
    println!("=== Correctness Verification ===");

    // L2 FDB
    let l2_config = make_l2_config();
    let ifm2 = ruster_dataplane::pipeline::IfIndexMap::from_names(&[
        "eth0".to_string(),
        "eth1".to_string(),
        "eth2".to_string(),
    ]);
    let mut l2_engine = L2Engine::from_config(&l2_config, &ifm2);
    let dst_mac: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
    let learn_meta = make_l2_meta("lan1", dst_mac, [0x00; 6]);
    l2_engine.process(&learn_meta);
    let src_mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let meta = make_l2_meta("lan0", src_mac, dst_mac);
    let decision = l2_engine.process(&meta);
    assert!(
        matches!(
            decision,
            ruster_dataplane::l2::bridge::L2Decision::Unicast { .. }
        ),
        "L2 FDB: expected Unicast"
    );
    println!("  L2 FDB lookup       : OK");

    // L3 LPM
    let interfaces = make_interfaces();
    let l3_engine = L3Engine::from_config(&make_routing_config(), &interfaces).unwrap();
    let meta = make_ipv4_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);
    let decision = l3_engine.process(&meta);
    assert!(
        matches!(
            decision,
            ruster_dataplane::routing::L3Decision::Forward { .. }
        ),
        "L3: expected Forward"
    );
    println!("  L3 LPM lookup       : OK");

    // NAT outbound
    let nat_config = make_nat_config();
    let mut nat_engine = NatEngine::from_config(&nat_config, &interfaces);
    let mut conntrack = ConntrackEngine::new(make_conntrack_config());
    let meta = make_ipv4_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);
    let action = nat_engine.process_outbound(&meta, &mut conntrack);
    assert!(
        matches!(action, ruster_dataplane::nat::NatAction::Snat { .. }),
        "NAT: expected Snat"
    );
    println!("  NAT outbound        : OK");

    // Firewall accept
    let fw_engine = FirewallEngine::from_config(&make_fw_config());
    let ctx = FwContext {
        chain: FwChain::Forward,
        src_zone: FirewallZone::Lan,
        dst_zone: FirewallZone::Wan,
        proto: FwProto::Tcp,
        is_established: false,
        is_new: true,
    };
    let verdict = fw_engine.evaluate(&ctx);
    assert!(
        matches!(verdict, FwVerdict::AcceptRule { .. }),
        "FW: expected AcceptRule"
    );
    println!("  Firewall evaluate   : OK");

    // Conntrack lookup
    let mut conntrack2 = ConntrackEngine::new(make_conntrack_config());
    let key = SessionKey {
        src_ip: [192, 168, 1, 100],
        dst_ip: [8, 8, 8, 8],
        proto: SessionProto::Tcp {
            src_port: 49152,
            dst_port: 80,
        },
    };
    conntrack2
        .create_session(key, SessionState::Tcp(TcpState::Established))
        .unwrap();
    assert!(conntrack2.lookup(&key).is_some(), "Conntrack: expected hit");
    println!("  Conntrack lookup    : OK");

    // Packet parse
    let raw = build_raw_tcp_packet();
    let result = ruster_dataplane::packet::parse_packet(&raw, 0);
    assert!(result.is_ok(), "Parse: expected Ok");
    println!("  Packet parse        : OK");

    println!();
    println!("All correctness checks passed.");
    println!();
}

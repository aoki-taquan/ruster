//! OSPF integration tests.
//!
//! These tests exercise the OSPF engine at a higher level than the
//! unit tests in `ospf/mod.rs`.  They simulate two routers (R1 and R2)
//! communicating through the engine API to verify:
//!
//! - Hello exchange and full adjacency formation
//! - SPF route computation from neighbor LSAs
//! - RIB entry generation with correct source and admin distance
//! - Neighbor dead-interval expiration and route withdrawal
//! - Multiple stub network advertisement and route computation

use ruster_dataplane::ospf::config::{AreaConfig, OspfConfig, OspfInterfaceConfig};
use ruster_dataplane::ospf::lsdb::INITIAL_SEQUENCE_NUMBER;
use ruster_dataplane::ospf::neighbor::{NeighborEvent, NeighborState};
use ruster_dataplane::ospf::packet::{
    HelloPacket, Lsa, LsaBody, LsaHeader, LsaType, OspfHeader, OspfPacketType, RouterLink,
    RouterLsa, LINK_TYPE_P2P, LINK_TYPE_STUB, OSPF_VERSION,
};
use ruster_dataplane::ospf::OspfEngine;
use ruster_dataplane::routing::protocol::ProtocolSource;

// ── Helpers ──────────────────────────────────────────────────────────

fn make_config(router_id: [u8; 4], iface_name: &str) -> OspfConfig {
    OspfConfig {
        router_id,
        areas: vec![AreaConfig {
            id: [0, 0, 0, 0],
            interfaces: vec![OspfInterfaceConfig {
                name: iface_name.to_string(),
                hello_interval: 10,
                dead_interval: 40,
            }],
        }],
    }
}

fn make_hello(
    router_id: [u8; 4],
    neighbors: Vec<[u8; 4]>,
    hello_interval: u16,
    dead_interval: u32,
) -> HelloPacket {
    HelloPacket {
        header: OspfHeader {
            version: OSPF_VERSION,
            packet_type: OspfPacketType::Hello,
            packet_length: 0,
            router_id,
            area_id: [0, 0, 0, 0],
            checksum: 0,
            auth_type: 0,
            auth_data: [0; 8],
        },
        network_mask: [255, 255, 255, 0],
        hello_interval,
        options: 0x02,
        router_priority: 1,
        router_dead_interval: dead_interval,
        designated_router: [0; 4],
        backup_designated_router: [0; 4],
        neighbors,
    }
}

fn make_router_lsa(router_id: [u8; 4], links: Vec<RouterLink>) -> Lsa {
    let num_links = links.len();
    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaType::Router as u8,
            link_state_id: router_id,
            advertising_router: router_id,
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: (20 + 4 + num_links * 12) as u16,
        },
        body: LsaBody::Router(RouterLsa { flags: 0, links }),
    }
}

/// Drive R1's neighbor (R2) from Init through to Full adjacency.
fn establish_full_adjacency(
    engine: &mut OspfEngine,
    iface: &str,
    r2_id: [u8; 4],
    r1_id: [u8; 4],
    r2_ip: [u8; 4],
    now: u64,
) {
    // R2 sends Hello without listing R1 → Init.
    let hello1 = make_hello(r2_id, vec![], 10, 40);
    let state = engine.process_hello(iface, &hello1, r2_ip, now);
    assert_eq!(state, Some(NeighborState::Init));

    // R2 sends Hello listing R1 → ExStart (bidirectional).
    let hello2 = make_hello(r2_id, vec![r1_id], 10, 40);
    let state = engine.process_hello(iface, &hello2, r2_ip, now + 1);
    assert_eq!(state, Some(NeighborState::ExStart));

    // Simulate DD/LSR/LSU exchange → Full.
    engine.advance_neighbor(iface, &r2_id, NeighborEvent::NegotiationDone);
    engine.advance_neighbor(iface, &r2_id, NeighborEvent::ExchangeDone);
    let state = engine.advance_neighbor(iface, &r2_id, NeighborEvent::LoadingDone);
    assert_eq!(state, Some(NeighborState::Full));
}

// ── Tests ────────────────────────────────────────────────────────────

/// Two-router Hello exchange reaching Full adjacency.
///
/// Simulates R1 (1.1.1.1) and R2 (2.2.2.2) on a shared /24 link.
/// R1 is the engine under test.  R2's Hellos are injected manually.
///
/// Sequence:
///   1. R2 sends Hello (empty neighbor list) → R1 records Init
///   2. R2 sends Hello (includes R1's ID) → R1 transitions to ExStart
///   3. Manual advance: NegotiationDone → Exchange
///   4. Manual advance: ExchangeDone → Loading
///   5. Manual advance: LoadingDone → Full
#[test]
fn hello_exchange_and_adjacency() {
    let r1_id = [1, 1, 1, 1];
    let r2_id = [2, 2, 2, 2];
    let r2_ip = [10, 0, 0, 2];

    let config = make_config(r1_id, "eth0");
    let mut engine = OspfEngine::new(&config, &[("eth0", [10, 0, 0, 1], [255, 255, 255, 0])]);
    engine.start();

    // Verify engine can build Hello for the interface.
    let hello = engine.build_hello("eth0");
    assert!(hello.is_some());
    let hello = hello.unwrap();
    assert_eq!(hello.header.router_id, r1_id);

    establish_full_adjacency(&mut engine, "eth0", r2_id, r1_id, r2_ip, 100);

    // Verify neighbor is in Full state.
    let iface = &engine.interfaces()[0];
    assert_eq!(iface.full_neighbor_count(), 1);
    let nbr = iface.get_neighbor(&r2_id).unwrap();
    assert_eq!(nbr.state, NeighborState::Full);
    assert_eq!(nbr.ip_addr, r2_ip);
}

/// SPF route computation from a neighbor's Router-LSA.
///
/// R2 advertises a stub network 192.168.1.0/24 via its Router-LSA.
/// After SPF runs, R1 should have a route to that network via R2.
#[test]
fn spf_route_computation() {
    let r1_id = [1, 1, 1, 1];
    let r2_id = [2, 2, 2, 2];
    let r2_ip = [10, 0, 0, 2];

    let config = make_config(r1_id, "eth0");
    let mut engine = OspfEngine::new(&config, &[("eth0", [10, 0, 0, 1], [255, 255, 255, 0])]);
    engine.start();
    establish_full_adjacency(&mut engine, "eth0", r2_id, r1_id, r2_ip, 100);

    // Install R2's Router-LSA with a P2P link (to R1) and a stub network.
    let r2_lsa = make_router_lsa(
        r2_id,
        vec![
            RouterLink {
                link_id: r1_id,
                link_data: r2_ip,
                link_type: LINK_TYPE_P2P,
                num_tos: 0,
                metric: 10,
            },
            RouterLink {
                link_id: [192, 168, 1, 0],
                link_data: [255, 255, 255, 0],
                link_type: LINK_TYPE_STUB,
                num_tos: 0,
                metric: 1,
            },
        ],
    );
    assert!(engine.install_lsa(r2_lsa, 102));

    // Trigger periodic tasks → SPF recomputation.
    let changed = engine.tick(103);
    assert!(changed);

    // Verify route to 192.168.1.0/24 was computed.
    let routes = engine.last_routes();
    let target_route = routes
        .iter()
        .find(|r| r.prefix == [192, 168, 1, 0] && r.prefix_len == 24);
    assert!(
        target_route.is_some(),
        "SPF should produce a route to 192.168.1.0/24, got: {routes:?}"
    );

    let route = target_route.unwrap();
    assert_eq!(route.next_hop, r2_ip);
    assert_eq!(route.out_ifname, "eth0");
}

/// RIB entry generation from OSPF routes.
///
/// Verifies that `routes_as_rib_entries()` produces entries with:
/// - source = ProtocolSource::Ospf
/// - admin_distance = 110
#[test]
fn rib_entry_generation() {
    let r1_id = [1, 1, 1, 1];
    let r2_id = [2, 2, 2, 2];
    let r2_ip = [10, 0, 0, 2];

    let config = make_config(r1_id, "eth0");
    let mut engine = OspfEngine::new(&config, &[("eth0", [10, 0, 0, 1], [255, 255, 255, 0])]);
    engine.start();
    establish_full_adjacency(&mut engine, "eth0", r2_id, r1_id, r2_ip, 100);

    // Install R2's Router-LSA with stub network.
    let r2_lsa = make_router_lsa(
        r2_id,
        vec![
            RouterLink {
                link_id: r1_id,
                link_data: r2_ip,
                link_type: LINK_TYPE_P2P,
                num_tos: 0,
                metric: 10,
            },
            RouterLink {
                link_id: [172, 16, 0, 0],
                link_data: [255, 255, 0, 0],
                link_type: LINK_TYPE_STUB,
                num_tos: 0,
                metric: 5,
            },
        ],
    );
    engine.install_lsa(r2_lsa, 102);
    engine.tick(103);

    let rib = engine.routes_as_rib_entries();
    let target_entry = rib
        .iter()
        .find(|e| e.prefix == [172, 16, 0, 0] && e.prefix_len == 16);
    assert!(
        target_entry.is_some(),
        "RIB should contain 172.16.0.0/16, got: {rib:?}"
    );

    let entry = target_entry.unwrap();
    assert_eq!(entry.source, ProtocolSource::Ospf);
    assert_eq!(entry.admin_distance, 110);
    assert_eq!(entry.next_hop, r2_ip);
    assert_eq!(entry.out_ifname, "eth0");
}

/// Neighbor dead-interval expiration removes neighbor and withdraws routes.
///
/// After `dead_interval` (40s) with no Hello, the neighbor should be
/// removed and routes through it should disappear.
#[test]
fn neighbor_dead_expiration() {
    let r1_id = [1, 1, 1, 1];
    let r2_id = [2, 2, 2, 2];
    let r2_ip = [10, 0, 0, 2];

    let config = make_config(r1_id, "eth0");
    let mut engine = OspfEngine::new(&config, &[("eth0", [10, 0, 0, 1], [255, 255, 255, 0])]);
    engine.start();
    establish_full_adjacency(&mut engine, "eth0", r2_id, r1_id, r2_ip, 100);

    // Install R2's LSA and compute routes.
    let r2_lsa = make_router_lsa(
        r2_id,
        vec![
            RouterLink {
                link_id: r1_id,
                link_data: r2_ip,
                link_type: LINK_TYPE_P2P,
                num_tos: 0,
                metric: 10,
            },
            RouterLink {
                link_id: [192, 168, 1, 0],
                link_data: [255, 255, 255, 0],
                link_type: LINK_TYPE_STUB,
                num_tos: 0,
                metric: 1,
            },
        ],
    );
    engine.install_lsa(r2_lsa, 102);
    engine.tick(103);

    // Confirm route exists.
    assert!(
        !engine.last_routes().is_empty(),
        "Should have routes before expiration"
    );

    // Wait beyond dead_interval (40s): last hello at t=101, dead at t=141+.
    let changed = engine.tick(200);
    assert!(changed, "tick should report route change after neighbor death");

    // Neighbor should be removed.
    assert!(
        engine.interfaces()[0].neighbors.is_empty(),
        "Neighbor should be expired"
    );

    // Routes through R2 should be gone (only self-originated stub routes remain).
    let rib = engine.routes_as_rib_entries();
    let r2_route = rib
        .iter()
        .find(|e| e.prefix == [192, 168, 1, 0] && e.prefix_len == 24);
    assert!(
        r2_route.is_none(),
        "Route via dead neighbor should be withdrawn, got: {rib:?}"
    );
}

/// Multiple stub networks advertised by R2 are all computed by SPF.
///
/// R2 advertises three stub networks.  After SPF, R1 should have
/// routes to all three.
#[test]
fn multiple_stub_networks() {
    let r1_id = [1, 1, 1, 1];
    let r2_id = [2, 2, 2, 2];
    let r2_ip = [10, 0, 0, 2];

    let config = make_config(r1_id, "eth0");
    let mut engine = OspfEngine::new(&config, &[("eth0", [10, 0, 0, 1], [255, 255, 255, 0])]);
    engine.start();
    establish_full_adjacency(&mut engine, "eth0", r2_id, r1_id, r2_ip, 100);

    // R2 advertises a P2P link plus three stub networks.
    let r2_lsa = make_router_lsa(
        r2_id,
        vec![
            RouterLink {
                link_id: r1_id,
                link_data: r2_ip,
                link_type: LINK_TYPE_P2P,
                num_tos: 0,
                metric: 10,
            },
            RouterLink {
                link_id: [192, 168, 1, 0],
                link_data: [255, 255, 255, 0],
                link_type: LINK_TYPE_STUB,
                num_tos: 0,
                metric: 1,
            },
            RouterLink {
                link_id: [192, 168, 2, 0],
                link_data: [255, 255, 255, 0],
                link_type: LINK_TYPE_STUB,
                num_tos: 0,
                metric: 2,
            },
            RouterLink {
                link_id: [172, 16, 0, 0],
                link_data: [255, 255, 0, 0],
                link_type: LINK_TYPE_STUB,
                num_tos: 0,
                metric: 5,
            },
        ],
    );
    engine.install_lsa(r2_lsa, 102);
    engine.tick(103);

    let rib = engine.routes_as_rib_entries();

    let expected_prefixes: &[([u8; 4], u8)] = &[
        ([192, 168, 1, 0], 24),
        ([192, 168, 2, 0], 24),
        ([172, 16, 0, 0], 16),
    ];

    for &(prefix, prefix_len) in expected_prefixes {
        let found = rib
            .iter()
            .any(|e| e.prefix == prefix && e.prefix_len == prefix_len);
        assert!(
            found,
            "RIB should contain {}.{}.{}.{}/{}, got: {:?}",
            prefix[0], prefix[1], prefix[2], prefix[3], prefix_len, rib
        );
    }

    // Verify all routes go through R2.
    for entry in &rib {
        if entry.next_hop != [0, 0, 0, 0] {
            assert_eq!(entry.next_hop, r2_ip);
        }
    }
}

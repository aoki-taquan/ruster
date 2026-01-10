//! E2E tests using containerlab
//!
//! Run with: cargo test --test e2e --features e2e
//!
//! Prerequisites:
//! - containerlab installed (requires sudo)
//! - docker running (user should be in docker group)
//!
//! Topology:
//! ```text
//! ┌─────────┐     ┌─────────────┐     ┌─────────┐
//! │ client  │────▶│   ruster    │◀────│ server  │
//! │10.0.1.2 │eth1 │ 10.0.1.1    │eth2 │10.0.2.2 │
//! └─────────┘     │ 10.0.2.1    │     └─────────┘
//!                 └─────────────┘
//! ```

mod clab;
mod home_router;
mod ipv6;
mod switching;

use clab::Topology;
use std::path::PathBuf;

fn topology_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/clab/topology.yml")
}

/// Test basic L2/L3 connectivity to ruster interfaces
///
/// This test verifies that hosts can reach ruster's directly connected interfaces.
/// Does NOT require ruster's packet processing - uses Linux kernel networking.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_ping_connectivity() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    // Wait for interfaces to be ready
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Test 1: Client can reach ruster's eth1 (directly connected)
    assert!(
        topo.ping("client", "10.0.1.1", 3),
        "Client should be able to ping ruster (10.0.1.1)"
    );

    // Test 2: Server can reach ruster's eth2 (directly connected)
    assert!(
        topo.ping("server", "10.0.2.1", 3),
        "Server should be able to ping ruster (10.0.2.1)"
    );

    // Test 3: Verify client has correct route to server network
    let output = topo.exec("client", "ip route show 10.0.2.0/24");
    let route_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        route_output.contains("via 10.0.1.1"),
        "Client should have route to 10.0.2.0/24 via ruster"
    );

    // Test 4: Verify server has correct route to client network
    let output = topo.exec("server", "ip route show 10.0.1.0/24");
    let route_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        route_output.contains("via 10.0.2.1"),
        "Server should have route to 10.0.1.0/24 via ruster"
    );
}

/// Test L3 forwarding through ruster
///
/// This test requires ruster to be running and processing packets.
/// Currently uses Linux kernel IP forwarding as a baseline.
///
/// Once ruster's main loop is implemented, this should:
/// 1. Start ruster in the container
/// 2. Disable kernel IP forwarding
/// 3. Verify traffic flows through ruster
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_routing_through_ruster() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Currently relies on Linux kernel forwarding
    // TODO: Once ruster main loop is implemented:
    //   1. topo.exec("ruster", "sysctl -w net.ipv4.ip_forward=0")
    //   2. topo.exec("ruster", "/usr/local/bin/ruster &")
    //   3. Verify packets go through ruster, not kernel

    // Test: Client can reach server through ruster
    assert!(
        topo.ping("client", "10.0.2.2", 3),
        "Client should be able to ping server (10.0.2.2) through ruster"
    );

    // Test: Server can reach client through ruster
    assert!(
        topo.ping("server", "10.0.1.2", 3),
        "Server should be able to ping client (10.0.1.2) through ruster"
    );
}

/// Test ARP resolution works correctly
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_arp_resolution() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Ping to populate ARP cache
    topo.ping("client", "10.0.1.1", 1);

    // Check ARP entry exists
    let output = topo.exec("client", "arp -n 10.0.1.1");
    let arp_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        !arp_output.contains("no entry") && !arp_output.is_empty(),
        "Client should have ARP entry for ruster (10.0.1.1)"
    );
}

/// Test ICMP echo reply (ping response)
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_icmp_echo_reply() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Ping with verbose output to check ICMP responses
    let output = topo.exec("client", "ping -c 3 -W 2 10.0.1.1");
    let ping_output = String::from_utf8_lossy(&output.stdout);

    // Verify we got responses
    assert!(
        ping_output.contains("bytes from 10.0.1.1"),
        "Should receive ICMP echo replies from ruster"
    );

    // Verify no packet loss
    assert!(
        ping_output.contains("0% packet loss") || ping_output.contains("0.0% packet loss"),
        "Should have 0% packet loss"
    );
}

// ============================================================================
// Static Routing Tests
// ============================================================================

/// Test connected routes are working
///
/// Verifies that directly connected networks are reachable.
/// These routes are auto-generated from interface addresses.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_connected_routes() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify ruster has connected routes for both interfaces
    let output = topo.exec("ruster", "ip route show");
    let route_output = String::from_utf8_lossy(&output.stdout);

    // Should have routes for 10.0.1.0/24 and 10.0.2.0/24
    assert!(
        route_output.contains("10.0.1.0/24"),
        "ruster should have connected route for 10.0.1.0/24, got: {}",
        route_output
    );
    assert!(
        route_output.contains("10.0.2.0/24"),
        "ruster should have connected route for 10.0.2.0/24, got: {}",
        route_output
    );
}

/// Test route table entries on ruster
///
/// Verifies that the routing table has correct entries for packet forwarding.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_routing_table_entries() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Check routing table on ruster
    let output = topo.exec("ruster", "ip route show table main");
    let route_output = String::from_utf8_lossy(&output.stdout);

    // Routes should be associated with correct interfaces
    assert!(
        route_output.contains("10.0.1.0/24") && route_output.contains("eth1"),
        "Route to 10.0.1.0/24 should be via eth1, got: {}",
        route_output
    );
    assert!(
        route_output.contains("10.0.2.0/24") && route_output.contains("eth2"),
        "Route to 10.0.2.0/24 should be via eth2, got: {}",
        route_output
    );
}

/// Test multi-hop routing
///
/// Verifies that packets traverse the correct path through multiple hops.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_multi_hop_routing() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Use traceroute to verify the path
    let output = topo.exec("client", "traceroute -n -m 3 -w 2 10.0.2.2");
    let traceroute_output = String::from_utf8_lossy(&output.stdout);

    // The path should go through ruster (10.0.1.1)
    assert!(
        traceroute_output.contains("10.0.1.1") || traceroute_output.contains("10.0.2.1"),
        "Traffic should pass through ruster, got: {}",
        traceroute_output
    );
}

/// Test bidirectional routing symmetry
///
/// Verifies that routing works correctly in both directions.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_bidirectional_routing() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Test client -> server
    let output = topo.exec("client", "ping -c 3 -W 2 10.0.2.2");
    assert!(
        output.status.success(),
        "Client -> Server routing should work"
    );

    // Test server -> client
    let output = topo.exec("server", "ping -c 3 -W 2 10.0.1.2");
    assert!(
        output.status.success(),
        "Server -> Client routing should work"
    );

    // Verify both hosts can reach ruster's interfaces
    assert!(
        topo.ping("client", "10.0.2.1", 2),
        "Client should reach ruster's eth2 interface"
    );
    assert!(
        topo.ping("server", "10.0.1.1", 2),
        "Server should reach ruster's eth1 interface"
    );
}

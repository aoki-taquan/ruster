//! E2E tests using containerlab
//!
//! Run with: cargo test --test e2e -- --ignored

mod clab;

use clab::Topology;
use std::path::PathBuf;

fn topology_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/clab/topology.yml")
}

/// Test basic L3 connectivity through ruster
///
/// Topology:
///   client (10.0.1.2) -- eth1 -- ruster -- eth2 -- server (10.0.2.2)
#[test]
#[ignore] // Requires containerlab and sudo
fn test_ping_connectivity() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    // Wait for interfaces to be ready
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Test 1: Client can reach ruster's eth1
    assert!(
        topo.ping("client", "10.0.1.1", 3),
        "Client should be able to ping ruster (10.0.1.1)"
    );

    // Test 2: Server can reach ruster's eth2
    assert!(
        topo.ping("server", "10.0.2.1", 3),
        "Server should be able to ping ruster (10.0.2.1)"
    );
}

/// Test L3 forwarding through ruster (requires ruster to be running)
#[test]
#[ignore] // Requires containerlab, sudo, and ruster implementation
fn test_routing_through_ruster() {
    let topo = Topology::deploy(topology_path()).expect("Failed to deploy topology");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // This test will pass once ruster implements IP forwarding
    // For now, Linux kernel forwarding in the container handles this
    assert!(
        topo.ping("client", "10.0.2.2", 3),
        "Client should be able to ping server (10.0.2.2) through ruster"
    );
}

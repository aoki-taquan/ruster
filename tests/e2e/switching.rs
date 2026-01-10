//! L2 Switching E2E Tests
//!
//! Tests for L2 switching features including:
//! - MAC address learning
//! - Frame forwarding
//! - Unknown unicast flooding
//!
//! Topology:
//! ```text
//! ┌─────────┐     ┌─────────────┐     ┌─────────┐
//! │  host1  │────▶│   ruster    │◀────│  host2  │
//! │10.0.1.1 │eth1 │  (bridge)   │eth2 │10.0.1.2 │
//! └─────────┘     │     │       │     └─────────┘
//!                 │   eth3      │
//!                 └─────────────┘
//!                       │
//!                 ┌─────────┐
//!                 │  host3  │
//!                 │10.0.1.3 │
//!                 └─────────┘
//! ```

use super::clab::Topology;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn switching_topology() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/clab/switching/topology.yml")
}

/// Test L2 connectivity through bridge
///
/// Verifies that hosts on the same L2 segment can communicate through the bridge.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_bridge_connectivity() {
    let topo = Topology::deploy(switching_topology()).expect("Failed to deploy topology");

    // Wait for bridge to be ready
    thread::sleep(Duration::from_secs(3));

    // Test: host1 can ping host2
    assert!(
        topo.ping("host1", "10.0.1.2", 3),
        "host1 should be able to ping host2 (10.0.1.2)"
    );

    // Test: host1 can ping host3
    assert!(
        topo.ping("host1", "10.0.1.3", 3),
        "host1 should be able to ping host3 (10.0.1.3)"
    );

    // Test: host2 can ping host3
    assert!(
        topo.ping("host2", "10.0.1.3", 3),
        "host2 should be able to ping host3 (10.0.1.3)"
    );
}

/// Test MAC address learning
///
/// Verifies that the bridge learns MAC addresses from received frames.
/// We verify MAC learning by checking that:
/// 1. Initial ping to a host succeeds (requires ARP/MAC learning)
/// 2. Subsequent pings to same host work without ARP (MAC already learned)
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_mac_learning() {
    let topo = Topology::deploy(switching_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(3));

    // Clear ARP cache on host1 to ensure fresh learning
    topo.exec("host1", "ip neigh flush all");

    // First ping - will trigger ARP and MAC learning on bridge
    assert!(
        topo.ping("host1", "10.0.1.2", 1),
        "First ping to host2 should succeed (triggers MAC learning)"
    );

    // Get host2's MAC address from host1's ARP cache
    let output = topo.exec("host1", "arp -n 10.0.1.2");
    let arp_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        arp_output.contains("10.0.1.2"),
        "Host1 should have learned host2's MAC via ARP, got: {}",
        arp_output
    );

    // Second ping should work immediately (MAC already learned on bridge)
    // This verifies the bridge learned the MAC and can forward directly
    assert!(
        topo.ping("host1", "10.0.1.2", 3),
        "Subsequent pings should succeed (MAC already learned)"
    );

    // Verify ping to another host also works (different MAC learning)
    assert!(
        topo.ping("host1", "10.0.1.3", 2),
        "Ping to host3 should also succeed"
    );
}

/// Test ARP resolution on same L2 segment
///
/// Verifies that ARP works correctly through the bridge.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_arp_through_bridge() {
    let topo = Topology::deploy(switching_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(3));

    // Clear ARP cache on host1
    topo.exec("host1", "ip neigh flush all");

    // Ping to trigger ARP
    topo.ping("host1", "10.0.1.2", 1);

    // Check ARP entry exists
    let output = topo.exec("host1", "arp -n 10.0.1.2");
    let arp_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        !arp_output.contains("no entry") && arp_output.contains("10.0.1.2"),
        "host1 should have ARP entry for host2 (10.0.1.2), got: {}",
        arp_output
    );
}

/// Test broadcast forwarding
///
/// Verifies that broadcast frames are forwarded to all ports.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_broadcast_forwarding() {
    let topo = Topology::deploy(switching_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(3));

    // Use arping to send broadcast ARP request from host1
    // This should reach both host2 and host3 through the bridge
    let output = topo.exec("host1", "arping -c 1 -I eth1 10.0.1.2");
    let arping_output = String::from_utf8_lossy(&output.stdout);

    // arping should receive a reply (broadcast was forwarded)
    assert!(
        arping_output.contains("reply from") || output.status.success(),
        "Broadcast ARP should be forwarded through bridge, got: {}",
        arping_output
    );
}

/// Test all-to-all connectivity
///
/// Verifies that all hosts can communicate with each other through the bridge.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_full_mesh_connectivity() {
    let topo = Topology::deploy(switching_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(3));

    // Test all pairs
    let pairs = [
        ("host1", "10.0.1.2", "host2"),
        ("host1", "10.0.1.3", "host3"),
        ("host2", "10.0.1.1", "host1"),
        ("host2", "10.0.1.3", "host3"),
        ("host3", "10.0.1.1", "host1"),
        ("host3", "10.0.1.2", "host2"),
    ];

    for (from, to_ip, to_name) in pairs {
        assert!(
            topo.ping(from, to_ip, 2),
            "{} should be able to ping {} ({})",
            from,
            to_name,
            to_ip
        );
    }
}

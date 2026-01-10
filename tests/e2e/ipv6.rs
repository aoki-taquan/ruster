//! IPv6 E2E Tests
//!
//! Tests for IPv6 networking features including:
//! - ICMPv6 Echo Request/Reply (ping6)
//! - IPv6 routing through ruster
//! - Neighbor Discovery Protocol (NDP)
//!
//! Topology:
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │   client    │────▶│   ruster    │◀────│   server    │
//! │2001:db8:1::2│eth1 │2001:db8:1::1│eth2 │2001:db8:2::2│
//! └─────────────┘     │2001:db8:2::1│     └─────────────┘
//!                     └─────────────┘
//! ```

use super::clab::Topology;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn ipv6_topology() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/clab/ipv6/topology.yml")
}

/// Test basic ICMPv6 connectivity to ruster interfaces
///
/// Verifies that hosts can ping6 ruster's directly connected interfaces.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_ipv6_ping_connectivity() {
    let topo = Topology::deploy(ipv6_topology()).expect("Failed to deploy topology");

    // Wait for interfaces to be ready and IPv6 DAD to complete
    thread::sleep(Duration::from_secs(3));

    // Test: Client can ping ruster's eth1 (directly connected)
    let output = topo.exec("client", "ping6 -c 3 -W 2 2001:db8:1::1");
    assert!(
        output.status.success(),
        "Client should be able to ping6 ruster (2001:db8:1::1), stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Test: Server can ping ruster's eth2 (directly connected)
    let output = topo.exec("server", "ping6 -c 3 -W 2 2001:db8:2::1");
    assert!(
        output.status.success(),
        "Server should be able to ping6 ruster (2001:db8:2::1), stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Test IPv6 routing through ruster
///
/// Verifies that IPv6 packets can be forwarded through ruster.
/// Currently uses Linux kernel IPv6 forwarding as a baseline.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_ipv6_routing_through_ruster() {
    let topo = Topology::deploy(ipv6_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(3));

    // Test: Client can reach server through ruster
    let output = topo.exec("client", "ping6 -c 3 -W 2 2001:db8:2::2");
    assert!(
        output.status.success(),
        "Client should be able to ping6 server (2001:db8:2::2) through ruster, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Test: Server can reach client through ruster
    let output = topo.exec("server", "ping6 -c 3 -W 2 2001:db8:1::2");
    assert!(
        output.status.success(),
        "Server should be able to ping6 client (2001:db8:1::2) through ruster, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Test IPv6 Neighbor Discovery (NDP)
///
/// Verifies that NDP neighbor entries are created after communication.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_ipv6_ndp() {
    let topo = Topology::deploy(ipv6_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(3));

    // Ping to populate neighbor cache
    topo.exec("client", "ping6 -c 1 -W 2 2001:db8:1::1");

    // Check neighbor entry exists
    let output = topo.exec("client", "ip -6 neigh show 2001:db8:1::1");
    let neigh_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        neigh_output.contains("2001:db8:1::1") && !neigh_output.is_empty(),
        "Client should have NDP neighbor entry for ruster (2001:db8:1::1), got: {}",
        neigh_output
    );
}

/// Test ICMPv6 Echo Reply verification
///
/// Verifies that ICMPv6 echo replies are received with proper content.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_icmpv6_echo_reply() {
    let topo = Topology::deploy(ipv6_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(3));

    // Ping with verbose output to check ICMPv6 responses
    let output = topo.exec("client", "ping6 -c 3 -W 2 2001:db8:1::1");
    let ping_output = String::from_utf8_lossy(&output.stdout);

    // Verify we got responses
    assert!(
        ping_output.contains("bytes from 2001:db8:1::1"),
        "Should receive ICMPv6 echo replies from ruster, got: {}",
        ping_output
    );

    // Verify no packet loss
    assert!(
        ping_output.contains("0% packet loss") || ping_output.contains("0.0% packet loss"),
        "Should have 0% packet loss, got: {}",
        ping_output
    );
}

/// Test IPv6 route verification
///
/// Verifies that correct IPv6 routes are configured on hosts.
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_ipv6_route_entries() {
    let topo = Topology::deploy(ipv6_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(3));

    // Verify client has correct route to server network
    let output = topo.exec("client", "ip -6 route show 2001:db8:2::/64");
    let route_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        route_output.contains("via 2001:db8:1::1"),
        "Client should have route to 2001:db8:2::/64 via ruster, got: {}",
        route_output
    );

    // Verify server has correct route to client network
    let output = topo.exec("server", "ip -6 route show 2001:db8:1::/64");
    let route_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        route_output.contains("via 2001:db8:2::1"),
        "Server should have route to 2001:db8:1::/64 via ruster, got: {}",
        route_output
    );
}

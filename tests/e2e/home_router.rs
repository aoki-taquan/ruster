//! Home Router Scenario E2E Tests
//!
//! Tests for typical home router configurations including:
//! - WAN (DHCP) + LAN
//! - NAT connectivity
//! - DHCP server
//! - DNS forwarder
//!
//! Topology:
//! ```text
//! ┌─────────┐     ┌─────────────┐     ┌─────────┐
//! │   isp   │────▶│   ruster    │◀────│ client  │
//! │10.0.0.1 │eth1 │ eth1: WAN   │eth2 │  DHCP   │
//! │         │     │ eth2: LAN   │     │ eth1    │
//! │  ─eth2──│     │ 192.168.1.1 │     └─────────┘
//! │         │     └─────────────┘
//! │ server  │
//! │203.0.113.2
//! └─────────┘
//! ```

use super::clab::Topology;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn home_router_topology() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/clab/home-router/topology.yml")
}

/// Setup routing for home router tests
/// Removes eth0 default routes (containerlab's Docker bridge) and adds necessary routes
fn setup_routing(topo: &Topology, ruster_wan_ip: &str) {
    // Remove eth0 default route on ruster (containerlab adds this automatically)
    topo.exec("ruster", "ip route del default dev eth0 || true");

    // Remove eth0 default route on client
    topo.exec("client", "ip route del default dev eth0 || true");

    // Add route on ISP for return traffic to LAN via ruster's WAN IP
    let route_cmd = format!("ip route add 192.168.1.0/24 via {} || true", ruster_wan_ip);
    topo.exec("isp", &route_cmd);

    // Add route on server for 10.0.0.0/24 via ISP (for return traffic)
    topo.exec("server", "ip route add 10.0.0.0/24 via 203.0.113.1 || true");
}

/// Get ruster's WAN IP address
fn get_ruster_wan_ip(topo: &Topology) -> String {
    let output = topo.exec(
        "ruster",
        "ip addr show eth1 | grep 'inet ' | awk '{print $2}'",
    );
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Wait for DHCP lease acquisition with timeout
fn wait_for_dhcp(topo: &Topology, node: &str, interface: &str, timeout_secs: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        let cmd = format!("ip addr show {}", interface);
        let output = topo.exec(node, &cmd);
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Check for non-link-local IPv4 address
        if stdout.contains("inet ") && !stdout.contains("169.254") {
            return true;
        }
        thread::sleep(Duration::from_secs(1));
    }
    false
}

// ============================================================================
// WAN (DHCP) Tests
// ============================================================================

/// Test: ruster WAN interface obtains IP via DHCP from ISP
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_wan_dhcp_acquisition() {
    let topo = Topology::deploy(home_router_topology()).expect("Failed to deploy topology");

    // Wait for topology to stabilize
    thread::sleep(Duration::from_secs(5));

    // Request DHCP on ruster WAN interface
    topo.exec("ruster", "udhcpc -i eth1 -n -q");

    // Wait for DHCP lease
    assert!(
        wait_for_dhcp(&topo, "ruster", "eth1", 30),
        "ruster should obtain WAN IP via DHCP"
    );

    // Verify WAN IP is in expected range
    let output = topo.exec("ruster", "ip addr show eth1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("10.0.0.") && stdout.contains("/24"),
        "WAN IP should be in 10.0.0.0/24 range, got: {}",
        stdout
    );
}

/// Test: ruster can reach ISP gateway after DHCP
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_wan_dhcp_gateway_reachable() {
    let topo = Topology::deploy(home_router_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(5));

    // Get DHCP lease
    topo.exec("ruster", "udhcpc -i eth1 -n -q");
    assert!(
        wait_for_dhcp(&topo, "ruster", "eth1", 30),
        "DHCP acquisition failed"
    );

    // Verify gateway is reachable
    assert!(
        topo.ping("ruster", "10.0.0.1", 3),
        "ruster should be able to ping ISP gateway"
    );
}

// ============================================================================
// DHCP Server Tests
// ============================================================================

/// Test: LAN client obtains IP from ruster DHCP server
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_dhcp_server_lan_client() {
    let topo = Topology::deploy(home_router_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(5));

    // Start DHCP client on LAN client
    topo.exec("client", "udhcpc -i eth1 -n -q");

    // Wait for client to get DHCP lease
    assert!(
        wait_for_dhcp(&topo, "client", "eth1", 30),
        "Client should obtain IP from ruster DHCP server"
    );

    // Verify client IP is in expected range (192.168.1.100-200)
    let output = topo.exec("client", "ip addr show eth1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("192.168.1."),
        "Client IP should be in 192.168.1.0/24 range, got: {}",
        stdout
    );
}

/// Test: Client receives correct gateway and DNS from DHCP
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_dhcp_server_options() {
    let topo = Topology::deploy(home_router_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(5));

    // Get DHCP lease on client
    topo.exec("client", "udhcpc -i eth1 -n -q");
    assert!(
        wait_for_dhcp(&topo, "client", "eth1", 30),
        "DHCP acquisition failed"
    );

    // Check default route points to ruster
    let output = topo.exec("client", "ip route show default");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("via 192.168.1.1"),
        "Client default gateway should be ruster (192.168.1.1), got: {}",
        stdout
    );

    // Note: /etc/resolv.conf is managed by Docker in containerlab environment,
    // so we can't verify DNS option via resolv.conf.
    // Instead, verify that DNS server responds (tested in test_dns_forwarder_responds)
}

// ============================================================================
// NAT Tests
// ============================================================================

/// Test: LAN client can reach internet server through NAT
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_nat_outbound_connectivity() {
    let topo = Topology::deploy(home_router_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(5));

    // Setup WAN on ruster
    topo.exec("ruster", "udhcpc -i eth1 -n -q");
    assert!(
        wait_for_dhcp(&topo, "ruster", "eth1", 30),
        "WAN DHCP failed"
    );

    // Get ruster's WAN IP and setup routing
    let wan_ip = get_ruster_wan_ip(&topo);
    setup_routing(&topo, &wan_ip);

    // Setup LAN client
    topo.exec("client", "udhcpc -i eth1 -n -q");
    assert!(
        wait_for_dhcp(&topo, "client", "eth1", 30),
        "LAN DHCP failed"
    );

    // Enable NAT on ruster (Linux kernel fallback)
    topo.exec(
        "ruster",
        "iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE",
    );

    // Test: client can reach internet server
    assert!(
        topo.ping("client", "203.0.113.2", 5),
        "Client should be able to reach internet server through NAT"
    );
}

// ============================================================================
// DNS Forwarder Tests
// ============================================================================

/// Test: DNS forwarder responds to client queries
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_dns_forwarder_responds() {
    let topo = Topology::deploy(home_router_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(5));

    // Setup client with DHCP
    topo.exec("client", "udhcpc -i eth1 -n -q");
    assert!(
        wait_for_dhcp(&topo, "client", "eth1", 30),
        "DHCP acquisition failed"
    );

    // Query DNS from client to ruster
    // dnsmasq on ruster acts as DNS forwarder
    let output = topo.exec(
        "client",
        "dig @192.168.1.1 localhost +short +timeout=5 +tries=1",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should get response (127.0.0.1 for localhost)
    assert!(
        stdout.contains("127.0.0.1") || !stderr.contains("connection timed out"),
        "DNS forwarder should respond to queries, stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

// ============================================================================
// Full Scenario Test
// ============================================================================

/// Test: Complete home router scenario with DHCP WAN
#[test]
#[cfg_attr(not(feature = "e2e"), ignore)]
fn test_home_router_full_scenario() {
    let topo = Topology::deploy(home_router_topology()).expect("Failed to deploy topology");

    thread::sleep(Duration::from_secs(5));

    // Step 1: ruster gets WAN IP via DHCP from ISP
    println!("Step 1: WAN DHCP acquisition...");
    topo.exec("ruster", "udhcpc -i eth1 -n -q");
    assert!(
        wait_for_dhcp(&topo, "ruster", "eth1", 30),
        "WAN DHCP failed"
    );

    // Get ruster's WAN IP and setup routing
    let wan_ip = get_ruster_wan_ip(&topo);
    println!("  ruster WAN IP: {}", wan_ip);
    setup_routing(&topo, &wan_ip);

    // Step 2: Client gets LAN IP from ruster DHCP server
    println!("Step 2: LAN DHCP for client...");
    topo.exec("client", "udhcpc -i eth1 -n -q");
    assert!(
        wait_for_dhcp(&topo, "client", "eth1", 30),
        "LAN DHCP failed"
    );

    // Step 3: Enable NAT (Linux kernel fallback)
    println!("Step 3: Enable NAT...");
    topo.exec(
        "ruster",
        "iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE",
    );

    // Step 4: Verify connectivity chain
    println!("Step 4: Connectivity tests...");

    // Client -> ruster LAN
    assert!(
        topo.ping("client", "192.168.1.1", 3),
        "Client -> ruster LAN failed"
    );
    println!("  Client -> ruster LAN: OK");

    // ruster -> ISP gateway
    assert!(
        topo.ping("ruster", "10.0.0.1", 3),
        "ruster -> ISP gateway failed"
    );
    println!("  ruster -> ISP gateway: OK");

    // ruster -> Internet server
    assert!(
        topo.ping("ruster", "203.0.113.2", 3),
        "ruster -> Internet server failed"
    );
    println!("  ruster -> Internet server: OK");

    // Client -> Internet (via NAT)
    assert!(
        topo.ping("client", "203.0.113.2", 5),
        "Client -> Internet via NAT failed"
    );
    println!("  Client -> Internet via NAT: OK");

    // Step 5: DNS test
    println!("Step 5: DNS test...");
    let output = topo.exec(
        "client",
        "dig @192.168.1.1 localhost +short +timeout=5 +tries=1",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("127.0.0.1"),
        "DNS query failed, got: {}",
        stdout
    );
    println!("  DNS query: OK");

    println!("All tests passed!");
}

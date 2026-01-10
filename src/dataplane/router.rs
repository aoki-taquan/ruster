//! Packet processing router
//!
//! Integrates all dataplane components (FDB, Forwarder, ARP) into
//! a unified packet processing pipeline.

use crate::capture::AfPacketSocket;
use crate::dataplane::{
    network_address, process_arp, Action, ArpAction, ArpPendingQueue, ArpTable, Chain, Dhcp6Client,
    Dhcp6ClientAction, DhcpAction, DhcpClient, DhcpClientAction, DhcpPoolConfig, DhcpServer, Fdb,
    FilterContext, FilterIpAddr, ForwardAction, Forwarder, InterfaceInfo, NaptProcessor,
    NaptResult, PacketFilter, RaClient, RaClientAction, RaServer, RaServerAction, RaServerConfig,
    Route, RouteSource, RoutingSystem, StatefulFirewall,
};
use crate::protocol::arp::ArpPacket;
use crate::protocol::ethernet::{Frame, FrameBuilder};
use crate::protocol::icmp::{build_echo_reply, IcmpType};
use crate::protocol::ipv4::Ipv4Header;
use crate::protocol::types::EtherType;
use crate::protocol::MacAddr;
use crate::telemetry::MetricsRegistry;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, Interval};
use tracing::{debug, trace, warn};

/// Default FDB aging time in seconds
const FDB_AGING_SECS: u64 = 300;

/// Default ARP reachable time in seconds
const ARP_REACHABLE_SECS: u64 = 30;

/// Default ARP stale time in seconds
const ARP_STALE_SECS: u64 = 120;

/// Maximum packets to queue per ARP resolution
const ARP_QUEUE_MAX_PER_IP: usize = 3;

/// Maximum age of queued ARP packets in seconds
const ARP_QUEUE_MAX_AGE_SECS: u64 = 60;

/// Port ID type for FDB
pub type PortId = u32;

/// Interface with its socket and metadata
pub struct Interface {
    /// The raw socket for packet I/O
    pub socket: AfPacketSocket,
    /// Interface name
    pub name: String,
    /// MAC address
    pub mac_addr: MacAddr,
    /// IP address (if configured)
    pub ip_addr: Option<Ipv4Addr>,
    /// Prefix length (if configured)
    pub prefix_len: Option<u8>,
    /// IPv6 addresses (if configured)
    pub ipv6_addrs: Vec<Ipv6Addr>,
    /// Port ID for FDB
    pub port_id: PortId,
}

/// The main router structure integrating all components
pub struct Router {
    /// Interfaces indexed by name
    interfaces: HashMap<String, Interface>,
    /// Port ID to interface name mapping
    port_to_name: HashMap<PortId, String>,
    /// All port IDs (for flooding)
    all_ports: HashSet<PortId>,
    /// L2 forwarding database
    fdb: Fdb,
    /// IP routing system with policy-based routing support
    routing_system: RoutingSystem,
    /// ARP table
    arp_table: ArpTable,
    /// Pending packets waiting for ARP resolution
    arp_pending: ArpPendingQueue,
    /// L3 forwarder
    forwarder: Forwarder,
    /// Next port ID to assign
    next_port_id: PortId,
    /// NAPT processor (optional)
    napt: Option<NaptProcessor>,
    /// WAN interface name (for NAPT)
    wan_interface: Option<String>,
    /// Packet filter (optional)
    filter: Option<PacketFilter>,
    /// Stateful firewall (optional)
    firewall: Option<StatefulFirewall>,
    /// DHCP server (optional)
    dhcp_server: Option<DhcpServer>,
    /// DHCPv6 client (optional)
    dhcp6_client: Option<Dhcp6Client>,
    /// DHCP clients for interfaces with addressing=dhcp
    dhcp_clients: HashMap<String, DhcpClient>,
    /// RA client for WAN interfaces (optional)
    ra_client: Option<RaClient>,
    /// RA server for LAN interfaces (optional)
    ra_server: Option<RaServer>,
    /// Metrics registry for statistics
    metrics: Arc<MetricsRegistry>,
}

impl Router {
    /// Create a new router with the given metrics registry
    pub fn new(metrics: Arc<MetricsRegistry>) -> Self {
        Self {
            interfaces: HashMap::new(),
            port_to_name: HashMap::new(),
            all_ports: HashSet::new(),
            fdb: Fdb::new(Duration::from_secs(FDB_AGING_SECS)),
            routing_system: RoutingSystem::new(),
            arp_table: ArpTable::new(
                Duration::from_secs(ARP_REACHABLE_SECS),
                Duration::from_secs(ARP_STALE_SECS),
            ),
            arp_pending: ArpPendingQueue::new(ARP_QUEUE_MAX_PER_IP, ARP_QUEUE_MAX_AGE_SECS),
            forwarder: Forwarder::new(),
            next_port_id: 1,
            napt: None,
            wan_interface: None,
            filter: None,
            firewall: None,
            dhcp_server: None,
            dhcp6_client: None,
            dhcp_clients: HashMap::new(),
            ra_client: None,
            ra_server: None,
            metrics,
        }
    }

    /// Set the packet filter
    pub fn set_filter(&mut self, filter: PacketFilter) {
        self.filter = Some(filter);
    }

    /// Get the packet filter
    pub fn filter(&self) -> Option<&PacketFilter> {
        self.filter.as_ref()
    }

    /// Get a reference to the metrics registry
    pub fn metrics(&self) -> &Arc<MetricsRegistry> {
        &self.metrics
    }

    /// Enable NAPT (IPマスカレード)
    ///
    /// # Arguments
    /// * `wan_interface` - WAN interface name
    /// * `external_ip` - External IP address (WAN IP)
    pub fn enable_napt(&mut self, wan_interface: String, external_ip: Ipv4Addr) {
        debug!(
            "Enabling NAPT on {} with external IP {}",
            wan_interface, external_ip
        );
        self.wan_interface = Some(wan_interface.clone());
        self.napt = Some(NaptProcessor::new(wan_interface, external_ip));
    }

    /// Disable NAPT
    pub fn disable_napt(&mut self) {
        self.napt = None;
        self.wan_interface = None;
    }

    /// Check if NAPT is enabled
    pub fn is_napt_enabled(&self) -> bool {
        self.napt.is_some()
    }

    /// Enable stateful firewall (SPI)
    ///
    /// # Arguments
    /// * `wan_interfaces` - WAN interface names where SPI is applied
    pub fn enable_firewall(&mut self, wan_interfaces: Vec<String>) {
        debug!(
            "Enabling stateful firewall for WAN interfaces: {:?}",
            wan_interfaces
        );
        self.firewall = Some(StatefulFirewall::new(wan_interfaces));
    }

    /// Disable stateful firewall
    pub fn disable_firewall(&mut self) {
        self.firewall = None;
    }

    /// Check if stateful firewall is enabled
    pub fn is_firewall_enabled(&self) -> bool {
        self.firewall.is_some()
    }

    /// Enable DHCP server for an interface
    ///
    /// # Arguments
    /// * `config` - DHCP pool configuration
    pub fn enable_dhcp(&mut self, config: DhcpPoolConfig) {
        debug!(
            "Enabling DHCP on {} with range {} - {}",
            config.interface, config.range_start, config.range_end
        );
        let server = self.dhcp_server.get_or_insert_with(DhcpServer::new);
        server.add_pool(config);
    }

    /// Disable DHCP server for an interface
    pub fn disable_dhcp(&mut self, interface: &str) {
        if let Some(ref mut server) = self.dhcp_server {
            server.remove_pool(interface);
        }
    }

    /// Check if DHCP is enabled for an interface
    pub fn is_dhcp_enabled(&self, interface: &str) -> bool {
        self.dhcp_server
            .as_ref()
            .is_some_and(|s| s.has_pool(interface))
    }

    // ===== DHCPv6 Client Methods =====

    /// Enable DHCPv6 client for an interface
    ///
    /// # Arguments
    /// * `interface` - Interface name to enable DHCPv6 client on
    pub fn enable_dhcp6(&mut self, interface: &str) -> Vec<Dhcp6ClientAction> {
        let iface = match self.interfaces.get(interface) {
            Some(i) => i,
            None => {
                warn!("Cannot enable DHCPv6: interface {} not found", interface);
                return vec![];
            }
        };

        let mac = iface.mac_addr;
        debug!("Enabling DHCPv6 client on {}", interface);

        let client = self.dhcp6_client.get_or_insert_with(Dhcp6Client::new);
        client.add_interface(interface.to_string(), &mac);
        client.start(interface)
    }

    /// Disable DHCPv6 client for an interface
    pub fn disable_dhcp6(&mut self, interface: &str) -> Vec<Dhcp6ClientAction> {
        if let Some(ref mut client) = self.dhcp6_client {
            return client.remove_interface(interface);
        }
        vec![]
    }

    /// Check if DHCPv6 client is enabled for an interface
    pub fn is_dhcp6_enabled(&self, interface: &str) -> bool {
        self.dhcp6_client
            .as_ref()
            .is_some_and(|c| c.has_interface(interface))
    }

    /// Get DHCPv6 client reference
    pub fn dhcp6_client(&self) -> Option<&Dhcp6Client> {
        self.dhcp6_client.as_ref()
    }

    /// Get mutable DHCPv6 client reference
    pub fn dhcp6_client_mut(&mut self) -> Option<&mut Dhcp6Client> {
        self.dhcp6_client.as_mut()
    }

    // ===== RA Client Methods =====

    /// Enable RA client on an interface (WAN side)
    ///
    /// # Arguments
    /// * `interface` - Interface name to enable RA client on
    pub fn enable_ra_client(&mut self, interface: &str) -> Vec<RaClientAction> {
        let iface = match self.interfaces.get(interface) {
            Some(i) => i,
            None => {
                warn!("Cannot enable RA client: interface {} not found", interface);
                return vec![];
            }
        };

        let mac = iface.mac_addr;
        debug!("Enabling RA client on {}", interface);

        let client = self.ra_client.get_or_insert_with(RaClient::new);
        client.add_interface(interface.to_string(), &mac)
    }

    /// Disable RA client on an interface
    pub fn disable_ra_client(&mut self, interface: &str) -> Vec<RaClientAction> {
        if let Some(ref mut client) = self.ra_client {
            return client.remove_interface(interface);
        }
        vec![]
    }

    /// Check if RA client is enabled on an interface
    pub fn is_ra_client_enabled(&self, interface: &str) -> bool {
        self.ra_client
            .as_ref()
            .is_some_and(|c| c.is_enabled(interface))
    }

    /// Get RA client reference
    pub fn ra_client(&self) -> Option<&RaClient> {
        self.ra_client.as_ref()
    }

    // ===== RA Server Methods =====

    /// Enable RA server on an interface (LAN side)
    ///
    /// # Arguments
    /// * `config` - RA server configuration
    pub fn enable_ra_server(&mut self, config: RaServerConfig) -> RaServerAction {
        let interface = &config.interface;
        let iface = match self.interfaces.get(interface) {
            Some(i) => i,
            None => {
                warn!("Cannot enable RA server: interface {} not found", interface);
                return RaServerAction::None;
            }
        };

        let mac = iface.mac_addr;
        debug!("Enabling RA server on {}", interface);

        let server = self.ra_server.get_or_insert_with(RaServer::new);
        server.add_interface(config, &mac)
    }

    /// Disable RA server on an interface
    pub fn disable_ra_server(&mut self, interface: &str) -> RaServerAction {
        if let Some(ref mut server) = self.ra_server {
            return server.remove_interface(interface);
        }
        RaServerAction::None
    }

    /// Check if RA server is enabled on an interface
    pub fn is_ra_server_enabled(&self, interface: &str) -> bool {
        self.ra_server
            .as_ref()
            .is_some_and(|s| s.is_enabled(interface))
    }

    /// Get RA server reference
    pub fn ra_server(&self) -> Option<&RaServer> {
        self.ra_server.as_ref()
    }

    // ===== DHCP Client Methods =====

    /// Enable DHCP client on an interface to obtain IP address
    pub fn enable_dhcp_client(&mut self, interface: &str) -> Vec<(String, Vec<u8>)> {
        let mac_addr = match self.interfaces.get(interface) {
            Some(iface) => iface.mac_addr,
            None => {
                warn!("DHCP client: interface {} not found", interface);
                return vec![];
            }
        };

        debug!("Enabling DHCP client on {}", interface);
        let mut client = DhcpClient::new(interface.to_string(), mac_addr);
        let action = client.start();
        self.dhcp_clients.insert(interface.to_string(), client);

        self.execute_dhcp_client_action(action)
    }

    /// Disable DHCP client on an interface
    pub fn disable_dhcp_client(&mut self, interface: &str) {
        self.dhcp_clients.remove(interface);
    }

    /// Check if DHCP client is enabled for an interface
    pub fn is_dhcp_client_enabled(&self, interface: &str) -> bool {
        self.dhcp_clients.contains_key(interface)
    }

    /// Execute a DHCP client action
    fn execute_dhcp_client_action(&mut self, action: DhcpClientAction) -> Vec<(String, Vec<u8>)> {
        use crate::protocol::dhcp::{DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
        use crate::protocol::ipv4::Ipv4Builder;
        use crate::protocol::udp::UdpBuilder;

        match action {
            DhcpClientAction::SendPacket {
                interface,
                packet,
                dst_ip,
                dst_mac,
            } => {
                let iface = match self.interfaces.get(&interface) {
                    Some(i) => i,
                    None => return vec![],
                };

                // Source IP is 0.0.0.0 if we don't have an IP yet
                let src_ip = iface.ip_addr.unwrap_or(Ipv4Addr::UNSPECIFIED);

                // Build UDP packet
                let udp_packet = UdpBuilder::new()
                    .src_port(DHCP_CLIENT_PORT)
                    .dst_port(DHCP_SERVER_PORT)
                    .payload(&packet)
                    .build(src_ip, dst_ip);

                // Build IP packet
                let ip_packet = Ipv4Builder::new()
                    .src_addr(src_ip)
                    .dst_addr(dst_ip)
                    .ttl(64)
                    .protocol(17) // UDP
                    .payload(&udp_packet)
                    .build();

                // Build Ethernet frame
                let frame = FrameBuilder::new()
                    .src_mac(iface.mac_addr)
                    .dst_mac(dst_mac)
                    .ethertype(EtherType::Ipv4 as u16)
                    .payload(&ip_packet)
                    .build();

                vec![(interface, frame)]
            }
            DhcpClientAction::ConfigureInterface {
                interface,
                ip_addr,
                prefix_len,
                gateway,
                dns_servers: _,
            } => {
                self.configure_dhcp_interface(&interface, ip_addr, prefix_len, gateway);
                vec![]
            }
            DhcpClientAction::DeconfigureInterface { interface } => {
                self.deconfigure_dhcp_interface(&interface);
                vec![]
            }
            DhcpClientAction::None => vec![],
        }
    }

    /// Execute RA client actions
    fn execute_ra_client_actions(
        &mut self,
        actions: Vec<RaClientAction>,
    ) -> Vec<(String, Vec<u8>)> {
        use crate::protocol::ipv6::Ipv6Builder;

        let mut to_send = Vec::new();

        for action in actions {
            match action {
                RaClientAction::SendRs { interface, packet } => {
                    let iface = match self.interfaces.get(&interface) {
                        Some(i) => i,
                        None => continue,
                    };

                    // Source: link-local address
                    let src_ip = self.get_link_local(&iface.mac_addr);
                    // Destination: all-routers multicast
                    let dst_ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
                    let dst_mac = MacAddr([0x33, 0x33, 0x00, 0x00, 0x00, 0x02]);

                    // Build IPv6 packet
                    let ip_packet = Ipv6Builder::new()
                        .hop_limit(255)
                        .src_addr(src_ip)
                        .dst_addr(dst_ip)
                        .next_header(58) // ICMPv6
                        .payload(&packet)
                        .build();

                    // Build Ethernet frame
                    let frame = FrameBuilder::new()
                        .src_mac(iface.mac_addr)
                        .dst_mac(dst_mac)
                        .ethertype(EtherType::Ipv6 as u16)
                        .payload(&ip_packet)
                        .build();

                    to_send.push((interface, frame));
                }
                RaClientAction::PrefixAcquired {
                    interface,
                    prefix: _,
                    address,
                    router: _,
                    dns_servers: _,
                } => {
                    // Add the acquired address to the interface
                    if let Some(iface) = self.interfaces.get_mut(&interface) {
                        if !iface.ipv6_addrs.contains(&address) {
                            iface.ipv6_addrs.push(address);
                            debug!(
                                interface = %interface,
                                address = %address,
                                "SLAAC: Added IPv6 address"
                            );
                        }
                    }
                }
                RaClientAction::PrefixExpired { interface, address } => {
                    // Remove the expired address from the interface
                    if let Some(iface) = self.interfaces.get_mut(&interface) {
                        iface.ipv6_addrs.retain(|a| *a != address);
                        debug!(
                            interface = %interface,
                            address = %address,
                            "SLAAC: Removed expired IPv6 address"
                        );
                    }
                }
                RaClientAction::DefaultRouterUpdate {
                    interface: _,
                    router,
                    lifetime: _,
                } => {
                    // TODO: Update IPv6 routing table with default router
                    trace!(
                        router = ?router,
                        "Default router updated"
                    );
                }
                RaClientAction::None => {}
            }
        }

        to_send
    }

    /// Execute RA server actions
    fn execute_ra_server_actions(
        &mut self,
        actions: Vec<RaServerAction>,
    ) -> Vec<(String, Vec<u8>)> {
        use crate::protocol::ipv6::Ipv6Builder;

        let mut to_send = Vec::new();

        for action in actions {
            match action {
                RaServerAction::SendRa {
                    interface,
                    packet,
                    dst_ip,
                    dst_mac,
                } => {
                    let iface = match self.interfaces.get(&interface) {
                        Some(i) => i,
                        None => continue,
                    };

                    // Source: link-local address
                    let src_ip = self.get_link_local(&iface.mac_addr);

                    // Build IPv6 packet
                    let ip_packet = Ipv6Builder::new()
                        .hop_limit(255)
                        .src_addr(src_ip)
                        .dst_addr(dst_ip)
                        .next_header(58) // ICMPv6
                        .payload(&packet)
                        .build();

                    // Build Ethernet frame
                    let frame = FrameBuilder::new()
                        .src_mac(iface.mac_addr)
                        .dst_mac(dst_mac)
                        .ethertype(EtherType::Ipv6 as u16)
                        .payload(&ip_packet)
                        .build();

                    to_send.push((interface, frame));
                }
                RaServerAction::None => {}
            }
        }

        to_send
    }

    /// Generate link-local address from MAC using EUI-64
    fn get_link_local(&self, mac: &MacAddr) -> Ipv6Addr {
        let m = &mac.0;
        let eui64: [u8; 8] = [m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]];

        Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            u16::from_be_bytes([eui64[0], eui64[1]]),
            u16::from_be_bytes([eui64[2], eui64[3]]),
            u16::from_be_bytes([eui64[4], eui64[5]]),
            u16::from_be_bytes([eui64[6], eui64[7]]),
        )
    }

    /// Configure interface with DHCP-obtained IP
    fn configure_dhcp_interface(
        &mut self,
        interface: &str,
        ip_addr: Ipv4Addr,
        prefix_len: u8,
        gateway: Option<Ipv4Addr>,
    ) {
        // Update interface IP
        if let Some(iface) = self.interfaces.get_mut(interface) {
            iface.ip_addr = Some(ip_addr);
            iface.prefix_len = Some(prefix_len);

            // Update forwarder
            self.forwarder.add_interface(
                interface.to_string(),
                InterfaceInfo {
                    ip_addr,
                    mac_addr: iface.mac_addr,
                    prefix_len,
                },
            );
        }

        // Add connected route for the network
        let network = network_address(ip_addr, prefix_len);
        self.routing_system.main_table_mut().add(Route {
            destination: network,
            prefix_len,
            next_hop: None,
            interface: interface.to_string(),
            metric: 0,
            source: RouteSource::Dhcp,
        });

        // Add default route via gateway if provided
        if let Some(gw) = gateway {
            self.routing_system.main_table_mut().add(Route {
                destination: Ipv4Addr::UNSPECIFIED,
                prefix_len: 0,
                next_hop: Some(gw),
                interface: interface.to_string(),
                metric: 10,
                source: RouteSource::Dhcp,
            });
        }
    }

    /// Remove DHCP configuration from interface
    fn deconfigure_dhcp_interface(&mut self, interface: &str) {
        // Remove DHCP-learned routes
        self.routing_system
            .main_table_mut()
            .remove_by_source(RouteSource::Dhcp);

        // Clear interface IP
        if let Some(iface) = self.interfaces.get_mut(interface) {
            iface.ip_addr = None;
            iface.prefix_len = None;
        }

        // Remove from forwarder
        self.forwarder.remove_interface(interface);
    }

    /// Add an interface to the router
    pub fn add_interface(
        &mut self,
        name: String,
        socket: AfPacketSocket,
        mac_addr: MacAddr,
        ip_addr: Option<Ipv4Addr>,
        prefix_len: Option<u8>,
    ) -> PortId {
        let port_id = self.next_port_id;
        self.next_port_id += 1;

        // Register interface for metrics
        self.metrics.register_interface(&name);

        // Track port for flooding
        self.all_ports.insert(port_id);

        // Register with L3 forwarder if IP configured
        if let (Some(ip), Some(prefix)) = (ip_addr, prefix_len) {
            self.forwarder.add_interface(
                name.clone(),
                InterfaceInfo {
                    ip_addr: ip,
                    mac_addr,
                    prefix_len: prefix,
                },
            );
        }

        self.port_to_name.insert(port_id, name.clone());
        self.interfaces.insert(
            name.clone(),
            Interface {
                socket,
                name,
                mac_addr,
                ip_addr,
                prefix_len,
                ipv6_addrs: Vec::new(),
                port_id,
            },
        );

        debug!("Added interface with port_id={}", port_id);
        port_id
    }

    /// Add a static route
    pub fn add_route(&mut self, route: crate::dataplane::Route) {
        self.routing_system.main_table_mut().add(route);
    }

    /// Get mutable reference to the routing system
    pub fn routing_system_mut(&mut self) -> &mut RoutingSystem {
        &mut self.routing_system
    }

    /// Get reference to the routing system
    pub fn routing_system(&self) -> &RoutingSystem {
        &self.routing_system
    }

    /// Get interface by name
    pub fn get_interface(&self, name: &str) -> Option<&Interface> {
        self.interfaces.get(name)
    }

    /// Get mutable interface by name
    pub fn get_interface_mut(&mut self, name: &str) -> Option<&mut Interface> {
        self.interfaces.get_mut(name)
    }

    /// Get interface by port ID
    fn get_interface_by_port(&self, port_id: PortId) -> Option<&Interface> {
        self.port_to_name
            .get(&port_id)
            .and_then(|name| self.interfaces.get(name))
    }

    /// Get all interface names
    pub fn interface_names(&self) -> Vec<String> {
        self.interfaces.keys().cloned().collect()
    }

    /// Get flood ports (all except ingress)
    fn get_flood_ports(&self, ingress_port: PortId) -> Vec<PortId> {
        self.all_ports
            .iter()
            .copied()
            .filter(|&p| p != ingress_port)
            .collect()
    }

    /// Process a received packet
    ///
    /// Returns a list of (interface_name, packet_data) to send
    pub fn process_packet(&mut self, ingress_iface: &str, packet: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut to_send = Vec::new();

        // Record received packet metrics
        self.metrics.record_rx(ingress_iface, packet.len());

        // Get ingress interface info
        let (ingress_port, ingress_mac, _ingress_ip) = {
            let iface = match self.interfaces.get(ingress_iface) {
                Some(i) => i,
                None => {
                    warn!("Unknown ingress interface: {}", ingress_iface);
                    return to_send;
                }
            };
            (iface.port_id, iface.mac_addr, iface.ip_addr)
        };

        // Parse Ethernet frame
        let frame = match Frame::parse(packet) {
            Ok(f) => f,
            Err(e) => {
                trace!("Failed to parse Ethernet frame: {:?}", e);
                self.metrics.record_rx_error(ingress_iface);
                return to_send;
            }
        };

        let src_mac = frame.src_mac();
        let dst_mac = frame.dst_mac();
        let ethertype = frame.ethertype();

        // MAC learning (VLAN 1 for now)
        self.fdb.learn(src_mac, 1, ingress_port);
        trace!(
            "Learned {} on port {} ({})",
            src_mac,
            ingress_port,
            ingress_iface
        );

        // Check if frame is for us (broadcast, multicast, or our MAC)
        let is_for_us = dst_mac.is_broadcast() || dst_mac.is_multicast() || dst_mac == ingress_mac;

        if is_for_us {
            // L3 processing
            match ethertype {
                x if x == EtherType::Arp as u16 => {
                    if let Some(packets) = self.process_arp_packet(ingress_iface, frame.payload()) {
                        to_send.extend(packets);
                    }
                }
                x if x == EtherType::Ipv4 as u16 => {
                    if let Some(packets) = self.process_ipv4_packet(ingress_iface, frame.payload())
                    {
                        to_send.extend(packets);
                    }
                }
                _ => {
                    trace!("Unsupported EtherType: 0x{:04x}", ethertype);
                }
            }
        } else {
            // L2 forwarding - lookup destination MAC
            if let Some(egress_port) = self.fdb.lookup(&dst_mac, 1) {
                // Known unicast - forward to specific port
                if egress_port != ingress_port {
                    if let Some(iface) = self.get_interface_by_port(egress_port) {
                        to_send.push((iface.name.clone(), packet.to_vec()));
                        trace!("L2 forward to port {} ({})", egress_port, iface.name);
                    }
                } else {
                    trace!("L2 filter (same port)");
                }
            } else {
                // Unknown unicast - flood to all ports except ingress
                let flood_ports = self.get_flood_ports(ingress_port);
                for port in flood_ports {
                    if let Some(iface) = self.get_interface_by_port(port) {
                        to_send.push((iface.name.clone(), packet.to_vec()));
                    }
                }
                trace!("L2 flood (unknown destination)");
            }
        }

        to_send
    }

    /// Process an ARP packet
    fn process_arp_packet(
        &mut self,
        ingress_iface: &str,
        payload: &[u8],
    ) -> Option<Vec<(String, Vec<u8>)>> {
        let arp = match ArpPacket::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                trace!("Failed to parse ARP: {:?}", e);
                return None;
            }
        };

        let iface = self.interfaces.get(ingress_iface)?;
        let local_ip = iface.ip_addr?;
        let local_mac = iface.mac_addr;
        let iface_name = iface.name.clone();

        let action = process_arp(&arp, &mut self.arp_table, local_ip, local_mac);

        match action {
            ArpAction::Reply(reply) => {
                self.metrics.arp_replies_sent.inc();
                // Build Ethernet frame for ARP reply
                let frame = FrameBuilder::new()
                    .src_mac(local_mac)
                    .dst_mac(reply.target_mac)
                    .ethertype(EtherType::Arp as u16)
                    .payload(&reply.to_bytes())
                    .build();

                debug!("Sending ARP reply to {}", reply.target_ip);
                Some(vec![(iface_name, frame)])
            }
            ArpAction::TableUpdated => {
                // Check if we have pending packets for this IP
                let pending = self.arp_pending.dequeue(&arp.sender_ip);
                if !pending.is_empty() {
                    debug!(
                        "ARP resolved for {}, sending {} queued packets",
                        arp.sender_ip,
                        pending.len()
                    );
                    let mut results = Vec::new();
                    for ip_packet in pending {
                        let frame = FrameBuilder::new()
                            .src_mac(local_mac)
                            .dst_mac(arp.sender_mac)
                            .ethertype(EtherType::Ipv4 as u16)
                            .payload(&ip_packet)
                            .build();
                        results.push((iface_name.clone(), frame));
                    }
                    Some(results)
                } else {
                    None
                }
            }
            ArpAction::None => None,
        }
    }

    /// Process an IPv4 packet
    fn process_ipv4_packet(
        &mut self,
        ingress_iface: &str,
        payload: &[u8],
    ) -> Option<Vec<(String, Vec<u8>)>> {
        // Stateful firewall inspection (before NAPT)
        if let Some(ref firewall) = self.firewall {
            use crate::dataplane::FirewallVerdict;
            match firewall.inspect(payload, ingress_iface) {
                FirewallVerdict::Accept => {}
                FirewallVerdict::Drop => {
                    self.metrics.packets_dropped.inc();
                    trace!("Firewall: dropped inbound packet from {}", ingress_iface);
                    return None;
                }
            }
        }

        // Apply NAPT if enabled
        let (packet_to_forward, is_inbound_nat) = self.apply_napt_if_needed(ingress_iface, payload);
        let packet_to_forward = packet_to_forward?;

        let action = self.forwarder.forward_with_policy(
            &packet_to_forward,
            ingress_iface,
            &self.routing_system,
            &self.arp_table,
            &mut self.arp_pending,
        );

        match action {
            ForwardAction::Forward {
                interface,
                next_hop_mac,
                packet,
            } => {
                // Apply FORWARD chain filter before forwarding
                if let Ok(ip) = Ipv4Header::parse(&packet) {
                    let (src_port, dst_port) = self.extract_ports(&packet, ip.protocol());
                    if self.apply_filter(
                        Chain::Forward,
                        FilterIpAddr::V4(ip.src_addr()),
                        FilterIpAddr::V4(ip.dst_addr()),
                        ip.protocol(),
                        src_port,
                        dst_port,
                        Some(ingress_iface),
                        Some(&interface),
                    ) {
                        self.metrics.packets_dropped.inc();
                        return None;
                    }
                }

                self.metrics.packets_forwarded.inc();
                // Apply outbound NAPT (SNAT) if forwarding to WAN
                let final_packet = if !is_inbound_nat {
                    self.apply_outbound_napt_if_needed(&interface, &packet)
                } else {
                    packet
                };

                // Track connection for stateful firewall
                if let Some(ref mut firewall) = self.firewall {
                    firewall.track(payload, ingress_iface);
                }

                let iface = self.interfaces.get(&interface)?;
                let frame = FrameBuilder::new()
                    .src_mac(iface.mac_addr)
                    .dst_mac(next_hop_mac)
                    .ethertype(EtherType::Ipv4 as u16)
                    .payload(&final_packet)
                    .build();

                debug!(
                    "Forwarding IPv4 packet to {} via {}",
                    next_hop_mac, interface
                );
                Some(vec![(interface, frame)])
            }
            ForwardAction::ArpRequest {
                interface,
                target_ip,
                request,
            } => {
                self.metrics.arp_requests_sent.inc();
                let iface = self.interfaces.get(&interface)?;
                let frame = FrameBuilder::new()
                    .src_mac(iface.mac_addr)
                    .dst_mac(MacAddr::BROADCAST)
                    .ethertype(EtherType::Arp as u16)
                    .payload(&request.to_bytes())
                    .build();

                debug!("Sending ARP request for {} on {}", target_ip, interface);
                Some(vec![(interface, frame)])
            }
            ForwardAction::Local => {
                // Apply INPUT chain filter before handling locally
                if let Ok(ip) = Ipv4Header::parse(&packet_to_forward) {
                    let (src_port, dst_port) =
                        self.extract_ports(&packet_to_forward, ip.protocol());
                    if self.apply_filter(
                        Chain::Input,
                        FilterIpAddr::V4(ip.src_addr()),
                        FilterIpAddr::V4(ip.dst_addr()),
                        ip.protocol(),
                        src_port,
                        dst_port,
                        Some(ingress_iface),
                        None,
                    ) {
                        self.metrics.packets_dropped.inc();
                        return None;
                    }
                }

                // Packet is for us - handle locally (e.g., ICMP)
                // For inbound NAT, this means packet is destined for WAN IP but no mapping
                self.handle_local_packet(ingress_iface, &packet_to_forward)
            }
            ForwardAction::TtlExpired { src_addr, .. } => {
                self.metrics.packets_dropped.inc();
                debug!("TTL expired for packet from {}", src_addr);
                // TODO: Send ICMP Time Exceeded
                None
            }
            ForwardAction::NoRoute { dst_addr } => {
                self.metrics.packets_dropped.inc();
                debug!("No route to {}", dst_addr);
                // TODO: Send ICMP Destination Unreachable
                None
            }
            ForwardAction::Dropped => {
                self.metrics.packets_dropped.inc();
                trace!("Packet dropped");
                None
            }
        }
    }

    /// Apply NAPT for inbound traffic (DNAT) if needed
    ///
    /// Returns (packet, is_inbound_nat)
    fn apply_napt_if_needed(
        &mut self,
        ingress_iface: &str,
        payload: &[u8],
    ) -> (Option<Vec<u8>>, bool) {
        // Check if NAPT is enabled and packet is from WAN
        let is_from_wan = self
            .wan_interface
            .as_ref()
            .is_some_and(|wan| wan == ingress_iface);

        if !is_from_wan {
            return (Some(payload.to_vec()), false);
        }

        // Apply inbound NAPT (DNAT)
        if let Some(ref mut napt) = self.napt {
            match napt.process_inbound(payload) {
                NaptResult::Translated { packet } => {
                    trace!("NAPT: Inbound packet translated");
                    (Some(packet), true)
                }
                NaptResult::PassThrough => {
                    // Not destined for our external IP
                    (Some(payload.to_vec()), false)
                }
                NaptResult::NoMapping => {
                    // Destined for our external IP but no mapping - treat as local
                    trace!("NAPT: No mapping for inbound packet");
                    (Some(payload.to_vec()), false)
                }
                NaptResult::Unsupported | NaptResult::Error(_) => (Some(payload.to_vec()), false),
            }
        } else {
            (Some(payload.to_vec()), false)
        }
    }

    /// Apply NAPT for outbound traffic (SNAT) if forwarding to WAN
    fn apply_outbound_napt_if_needed(&mut self, egress_iface: &str, packet: &[u8]) -> Vec<u8> {
        // Check if NAPT is enabled and packet is going to WAN
        let is_to_wan = self
            .wan_interface
            .as_ref()
            .is_some_and(|wan| wan == egress_iface);

        if !is_to_wan {
            return packet.to_vec();
        }

        // Apply outbound NAPT (SNAT)
        if let Some(ref mut napt) = self.napt {
            match napt.process_outbound(packet) {
                NaptResult::Translated { packet: translated } => {
                    trace!("NAPT: Outbound packet translated");
                    translated
                }
                _ => packet.to_vec(),
            }
        } else {
            packet.to_vec()
        }
    }

    /// Handle a packet destined for this router
    fn handle_local_packet(
        &mut self,
        ingress_iface: &str,
        payload: &[u8],
    ) -> Option<Vec<(String, Vec<u8>)>> {
        use crate::protocol::dhcp::DHCP_SERVER_PORT;
        use crate::protocol::icmp::IcmpPacket;
        use crate::protocol::ipv4::{Ipv4Builder, Ipv4Header};
        use crate::protocol::udp::UdpHeader;

        let ip_header = Ipv4Header::parse(payload).ok()?;
        let ip_payload = ip_header.payload();

        match ip_header.protocol() {
            1 => {
                // ICMP
                let icmp = IcmpPacket::parse(ip_payload).ok()?;

                // Handle echo request (ping)
                if icmp.icmp_type() == IcmpType::EchoRequest as u8 {
                    let iface = self.interfaces.get(ingress_iface)?;
                    let local_ip = iface.ip_addr?;

                    // Build ICMP echo reply from the request
                    let icmp_reply = build_echo_reply(icmp.as_bytes()).ok()?;

                    // Build IPv4 packet
                    let ip_packet = Ipv4Builder::new()
                        .src_addr(local_ip)
                        .dst_addr(ip_header.src_addr())
                        .ttl(64)
                        .protocol(1) // ICMP
                        .payload(&icmp_reply)
                        .build();

                    // Lookup MAC for reply
                    if let Some((dst_mac, _)) = self.arp_table.lookup(&ip_header.src_addr()) {
                        self.metrics.icmp_echo_replies.inc();
                        let frame = FrameBuilder::new()
                            .src_mac(iface.mac_addr)
                            .dst_mac(dst_mac)
                            .ethertype(EtherType::Ipv4 as u16)
                            .payload(&ip_packet)
                            .build();

                        debug!("Sending ICMP echo reply to {}", ip_header.src_addr());
                        return Some(vec![(iface.name.clone(), frame)]);
                    }
                }
                None
            }
            17 => {
                // UDP
                use crate::protocol::dhcp::DHCP_CLIENT_PORT;
                let udp = UdpHeader::parse(ip_payload).ok()?;

                match udp.dst_port() {
                    p if p == DHCP_SERVER_PORT => {
                        // DHCP request (to server)
                        self.handle_dhcp(ingress_iface, udp.payload())
                    }
                    p if p == DHCP_CLIENT_PORT => {
                        // DHCP response (to client)
                        self.handle_dhcp_client_response(ingress_iface, udp.payload())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Handle DHCP request
    fn handle_dhcp(
        &mut self,
        ingress_iface: &str,
        dhcp_payload: &[u8],
    ) -> Option<Vec<(String, Vec<u8>)>> {
        use crate::protocol::dhcp::DHCP_CLIENT_PORT;
        use crate::protocol::ipv4::Ipv4Builder;
        use crate::protocol::udp::UdpBuilder;

        let dhcp_server = self.dhcp_server.as_mut()?;
        let iface = self.interfaces.get(ingress_iface)?;
        let server_ip = iface.ip_addr?;

        let action = dhcp_server.process_dhcp(ingress_iface, server_ip, dhcp_payload);

        match action {
            DhcpAction::Reply {
                interface,
                packet,
                dst_ip,
                dst_mac,
            } => {
                let iface = self.interfaces.get(&interface)?;
                let src_ip = iface.ip_addr?;

                // Build UDP packet
                let udp_packet = UdpBuilder::new()
                    .src_port(crate::protocol::dhcp::DHCP_SERVER_PORT)
                    .dst_port(DHCP_CLIENT_PORT)
                    .payload(&packet)
                    .build(src_ip, dst_ip);

                // Build IPv4 packet
                let ip_packet = Ipv4Builder::new()
                    .src_addr(src_ip)
                    .dst_addr(dst_ip)
                    .ttl(64)
                    .protocol(17) // UDP
                    .payload(&udp_packet)
                    .build();

                // Build Ethernet frame
                let frame = FrameBuilder::new()
                    .src_mac(iface.mac_addr)
                    .dst_mac(dst_mac)
                    .ethertype(EtherType::Ipv4 as u16)
                    .payload(&ip_packet)
                    .build();

                debug!("Sending DHCP reply to {} via {}", dst_ip, interface);
                Some(vec![(interface, frame)])
            }
            DhcpAction::None => None,
        }
    }

    /// Handle DHCP client response (OFFER, ACK, NAK)
    fn handle_dhcp_client_response(
        &mut self,
        ingress_iface: &str,
        dhcp_payload: &[u8],
    ) -> Option<Vec<(String, Vec<u8>)>> {
        let client = self.dhcp_clients.get_mut(ingress_iface)?;
        let action = client.process_response(dhcp_payload);
        let packets = self.execute_dhcp_client_action(action);

        if packets.is_empty() {
            None
        } else {
            Some(packets)
        }
    }

    /// Apply packet filter and record metrics
    ///
    /// Returns true if the packet should be dropped
    #[allow(clippy::too_many_arguments)]
    fn apply_filter(
        &self,
        chain: Chain,
        src_ip: FilterIpAddr,
        dst_ip: FilterIpAddr,
        protocol: u8,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
    ) -> bool {
        let filter = match &self.filter {
            Some(f) => f,
            None => return false, // No filter, accept all
        };

        let ctx = FilterContext {
            chain,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            in_interface,
            out_interface,
        };

        match filter.evaluate(&ctx) {
            Action::Accept => {
                self.metrics.filter_accepted.inc();
                false
            }
            Action::Drop => {
                self.metrics.filter_dropped.inc();
                trace!("Filter dropped packet: {:?}", ctx);
                true
            }
            Action::Reject => {
                self.metrics.filter_rejected.inc();
                trace!("Filter rejected packet: {:?}", ctx);
                true
            }
        }
    }

    /// Extract L4 ports from IPv4 packet
    fn extract_ports(&self, payload: &[u8], protocol: u8) -> (Option<u16>, Option<u16>) {
        use crate::dataplane::protocol::{TCP, UDP};

        if protocol != TCP && protocol != UDP {
            return (None, None);
        }

        // L4 header starts after IP header
        if let Ok(ip) = Ipv4Header::parse(payload) {
            let l4_offset = ip.header_len();
            let l4_payload = &payload[l4_offset..];

            if l4_payload.len() >= 4 {
                let src_port = u16::from_be_bytes([l4_payload[0], l4_payload[1]]);
                let dst_port = u16::from_be_bytes([l4_payload[2], l4_payload[3]]);
                return (Some(src_port), Some(dst_port));
            }
        }

        (None, None)
    }

    /// Run aging for FDB, ARP, NAPT, firewall, and DHCP tables
    pub fn run_aging(&mut self) -> Vec<(String, Vec<u8>)> {
        self.fdb.age_out();
        self.arp_table.refresh_states();
        self.arp_pending.expire_old();

        // Run NAPT maintenance if enabled
        if let Some(ref mut napt) = self.napt {
            napt.run_maintenance();
        }

        // Run firewall maintenance if enabled
        if let Some(ref mut firewall) = self.firewall {
            firewall.run_maintenance();
        }

        // Run DHCP server maintenance if enabled
        if let Some(ref mut dhcp) = self.dhcp_server {
            dhcp.run_maintenance();
        }

        // Run DHCPv6 client maintenance if enabled
        if let Some(ref mut dhcp6) = self.dhcp6_client {
            let _actions = dhcp6.run_maintenance();
            // TODO: Process DHCPv6 client actions (send packets, update addresses)
        }

        // Collect packets to send
        let mut to_send = Vec::new();

        // Run RA client maintenance if enabled
        if let Some(ref mut ra_client) = self.ra_client {
            let actions = ra_client.run_maintenance();
            to_send.extend(self.execute_ra_client_actions(actions));
        }

        // Run RA server maintenance if enabled
        if let Some(ref mut ra_server) = self.ra_server {
            let actions = ra_server.run_maintenance();
            to_send.extend(self.execute_ra_server_actions(actions));
        }

        // Tick DHCP clients
        let client_interfaces: Vec<String> = self.dhcp_clients.keys().cloned().collect();
        for iface_name in client_interfaces {
            if let Some(client) = self.dhcp_clients.get_mut(&iface_name) {
                let action = client.tick();
                to_send.extend(self.execute_dhcp_client_action(action));
            }
        }

        // Update table size metrics
        self.metrics.set_fdb_table_size(self.fdb.len());
        self.metrics.set_arp_table_size(self.arp_table.len());
        self.metrics
            .set_route_count(self.routing_system.main_table().len());

        to_send
    }

    /// Create an aging timer interval
    pub fn aging_interval() -> Interval {
        interval(Duration::from_secs(FDB_AGING_SECS / 10))
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new(Arc::new(MetricsRegistry::new()))
    }
}

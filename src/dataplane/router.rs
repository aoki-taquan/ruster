//! Packet processing router
//!
//! Integrates all dataplane components (FDB, Forwarder, ARP) into
//! a unified packet processing pipeline.

use crate::capture::AfPacketSocket;
use crate::dataplane::{
    process_arp, ArpAction, ArpPendingQueue, ArpTable, Fdb, ForwardAction, Forwarder,
    InterfaceInfo, NaptProcessor, NaptResult, RoutingSystem,
};
use crate::protocol::arp::ArpPacket;
use crate::protocol::ethernet::{Frame, FrameBuilder};
use crate::protocol::icmp::{build_echo_reply, IcmpType};
use crate::protocol::types::EtherType;
use crate::protocol::MacAddr;
use crate::telemetry::MetricsRegistry;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
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
            metrics,
        }
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
                self.metrics.packets_forwarded.inc();
                // Apply outbound NAPT (SNAT) if forwarding to WAN
                let final_packet = if !is_inbound_nat {
                    self.apply_outbound_napt_if_needed(&interface, &packet)
                } else {
                    packet
                };

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
        use crate::protocol::icmp::IcmpPacket;
        use crate::protocol::ipv4::{Ipv4Builder, Ipv4Header};

        let ip_header = Ipv4Header::parse(payload).ok()?;
        let ip_payload = ip_header.payload();

        // Check if ICMP
        if ip_header.protocol() != 1 {
            return None;
        }

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

    /// Run aging for FDB, ARP, and NAPT tables
    pub fn run_aging(&mut self) {
        self.fdb.age_out();
        self.arp_table.refresh_states();
        self.arp_pending.expire_old();

        // Run NAPT maintenance if enabled
        if let Some(ref mut napt) = self.napt {
            napt.run_maintenance();
        }

        // Update table size metrics
        self.metrics.set_fdb_table_size(self.fdb.len());
        self.metrics.set_arp_table_size(self.arp_table.len());
        self.metrics
            .set_route_count(self.routing_system.main_table().len());
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

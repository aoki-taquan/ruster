//! DHCPv4 client implementation
//!
//! Implements RFC 2131 DHCP client state machine for automatic IP configuration.

use crate::protocol::dhcp::{options, BootpOp, DhcpBuilder, DhcpHeader, DhcpMessageType};
use crate::protocol::MacAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Maximum retries before restarting discovery
const MAX_RETRIES: u8 = 10;

/// Base retransmit timeout in seconds
const BASE_TIMEOUT_SECS: u64 = 4;

/// DHCP client state per RFC 2131
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpClientState {
    /// Initial state, no lease
    Init,
    /// DISCOVER sent, waiting for OFFER
    Selecting,
    /// REQUEST sent, waiting for ACK
    Requesting,
    /// Lease acquired and valid
    Bound,
    /// T1 expired, renewing unicast
    Renewing,
    /// T2 expired, rebinding broadcast
    Rebinding,
}

/// Information acquired from DHCP server
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// Assigned IP address
    pub ip_addr: Ipv4Addr,
    /// Subnet mask
    pub subnet_mask: Ipv4Addr,
    /// Prefix length (derived from subnet mask)
    pub prefix_len: u8,
    /// Default gateway
    pub gateway: Option<Ipv4Addr>,
    /// DNS servers
    pub dns_servers: Vec<Ipv4Addr>,
    /// DHCP server that granted lease
    pub server_id: Ipv4Addr,
    /// Lease duration in seconds
    pub lease_time: u32,
    /// T1 renewal time (default: lease_time / 2)
    pub renewal_time: u32,
    /// T2 rebinding time (default: lease_time * 7/8)
    pub rebinding_time: u32,
    /// When the lease was obtained
    pub obtained_at: Instant,
}

impl DhcpLease {
    /// Check if T1 (renewal time) has passed
    pub fn is_renewal_due(&self) -> bool {
        self.obtained_at.elapsed().as_secs() as u32 >= self.renewal_time
    }

    /// Check if T2 (rebinding time) has passed
    pub fn is_rebinding_due(&self) -> bool {
        self.obtained_at.elapsed().as_secs() as u32 >= self.rebinding_time
    }

    /// Check if lease has expired
    pub fn is_expired(&self) -> bool {
        self.obtained_at.elapsed().as_secs() as u32 >= self.lease_time
    }
}

/// Actions the DHCP client needs the router to perform
#[derive(Debug)]
pub enum DhcpClientAction {
    /// Send a DHCP packet (broadcast or unicast)
    SendPacket {
        interface: String,
        packet: Vec<u8>,
        dst_ip: Ipv4Addr,
        dst_mac: MacAddr,
    },
    /// Configure interface with obtained IP
    ConfigureInterface {
        interface: String,
        ip_addr: Ipv4Addr,
        prefix_len: u8,
        gateway: Option<Ipv4Addr>,
        dns_servers: Vec<Ipv4Addr>,
    },
    /// Remove interface IP configuration
    DeconfigureInterface { interface: String },
    /// No action needed
    None,
}

/// DHCPv4 client for a single interface
#[derive(Debug)]
pub struct DhcpClient {
    /// Interface name
    interface: String,
    /// Interface MAC address
    mac_addr: MacAddr,
    /// Current state
    state: DhcpClientState,
    /// Transaction ID for current exchange
    xid: u32,
    /// Current lease (if any)
    lease: Option<DhcpLease>,
    /// Last DISCOVER/REQUEST sent time (for retransmission)
    last_sent: Option<Instant>,
    /// Retransmission count
    retries: u8,
    /// Server IP from OFFER (for REQUEST)
    offered_server: Option<Ipv4Addr>,
    /// IP from OFFER (for REQUEST)
    offered_ip: Option<Ipv4Addr>,
}

impl DhcpClient {
    /// Create a new DHCP client for an interface
    pub fn new(interface: String, mac_addr: MacAddr) -> Self {
        Self {
            interface,
            mac_addr,
            state: DhcpClientState::Init,
            xid: Self::generate_xid(),
            lease: None,
            last_sent: None,
            retries: 0,
            offered_server: None,
            offered_ip: None,
        }
    }

    /// Get interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get current state
    pub fn state(&self) -> DhcpClientState {
        self.state
    }

    /// Get current lease
    pub fn lease(&self) -> Option<&DhcpLease> {
        self.lease.as_ref()
    }

    /// Generate random transaction ID
    fn generate_xid() -> u32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        // Simple PRNG with salt from address
        seed.wrapping_mul(1103515245).wrapping_add(12345)
    }

    /// Start or restart DHCP discovery process
    pub fn start(&mut self) -> DhcpClientAction {
        info!("DHCP client starting on {}", self.interface);
        self.state = DhcpClientState::Init;
        self.xid = Self::generate_xid();
        self.retries = 0;
        self.offered_server = None;
        self.offered_ip = None;
        self.send_discover()
    }

    /// Build and send DISCOVER packet
    fn send_discover(&mut self) -> DhcpClientAction {
        debug!(
            "DHCP: Sending DISCOVER on {} (xid=0x{:08x})",
            self.interface, self.xid
        );
        self.state = DhcpClientState::Selecting;
        self.last_sent = Some(Instant::now());

        let packet = self.build_discover();

        DhcpClientAction::SendPacket {
            interface: self.interface.clone(),
            packet,
            dst_ip: Ipv4Addr::BROADCAST,
            dst_mac: MacAddr::BROADCAST,
        }
    }

    /// Build DHCP DISCOVER message
    fn build_discover(&self) -> Vec<u8> {
        DhcpBuilder::new()
            .op(BootpOp::Request)
            .xid(self.xid)
            .flags(0x8000) // Broadcast flag
            .chaddr(&self.mac_addr.0)
            .message_type(DhcpMessageType::Discover)
            .parameter_request_list(&[
                options::SUBNET_MASK,
                options::ROUTER,
                options::DNS_SERVER,
                options::DOMAIN_NAME,
                options::LEASE_TIME,
                options::RENEWAL_TIME,
                options::REBINDING_TIME,
            ])
            .build()
    }

    /// Process a received DHCP message
    pub fn process_response(&mut self, dhcp_payload: &[u8]) -> DhcpClientAction {
        let msg = match DhcpHeader::parse(dhcp_payload) {
            Ok(m) => m,
            Err(e) => {
                debug!("DHCP: Failed to parse response: {}", e);
                return DhcpClientAction::None;
            }
        };

        // Verify it's for us
        if msg.xid() != self.xid {
            debug!(
                "DHCP: Ignoring response with wrong xid (got 0x{:08x}, expected 0x{:08x})",
                msg.xid(),
                self.xid
            );
            return DhcpClientAction::None;
        }
        if msg.client_mac() != self.mac_addr.0 {
            debug!("DHCP: Ignoring response for different MAC");
            return DhcpClientAction::None;
        }

        let msg_type = match msg.message_type() {
            Some(t) => t,
            None => {
                debug!("DHCP: Response missing message type");
                return DhcpClientAction::None;
            }
        };

        debug!(
            "DHCP: Received {:?} in state {:?} on {}",
            msg_type, self.state, self.interface
        );

        match (self.state, msg_type) {
            (DhcpClientState::Selecting, DhcpMessageType::Offer) => self.handle_offer(&msg),
            (DhcpClientState::Requesting, DhcpMessageType::Ack) => self.handle_ack(&msg),
            (DhcpClientState::Requesting, DhcpMessageType::Nak) => self.handle_nak(),
            (
                DhcpClientState::Renewing | DhcpClientState::Rebinding,
                DhcpMessageType::Ack,
            ) => self.handle_renew_ack(&msg),
            (
                DhcpClientState::Renewing | DhcpClientState::Rebinding,
                DhcpMessageType::Nak,
            ) => self.handle_nak(),
            _ => {
                debug!(
                    "DHCP: Unexpected {:?} in state {:?}",
                    msg_type, self.state
                );
                DhcpClientAction::None
            }
        }
    }

    /// Handle DHCP OFFER
    fn handle_offer(&mut self, msg: &DhcpHeader) -> DhcpClientAction {
        let offered_ip = msg.yiaddr();
        let server_id = msg.server_id();

        info!(
            "DHCP: Received OFFER for {} from {:?} on {}",
            offered_ip, server_id, self.interface
        );

        self.offered_ip = Some(offered_ip);
        self.offered_server = server_id;
        self.send_request()
    }

    /// Build and send REQUEST packet
    fn send_request(&mut self) -> DhcpClientAction {
        debug!(
            "DHCP: Sending REQUEST for {:?} on {}",
            self.offered_ip, self.interface
        );
        self.state = DhcpClientState::Requesting;
        self.last_sent = Some(Instant::now());
        self.retries = 0;

        let packet = self.build_request();

        // REQUEST during initial exchange is broadcast
        DhcpClientAction::SendPacket {
            interface: self.interface.clone(),
            packet,
            dst_ip: Ipv4Addr::BROADCAST,
            dst_mac: MacAddr::BROADCAST,
        }
    }

    /// Build DHCP REQUEST message
    fn build_request(&self) -> Vec<u8> {
        let mut builder = DhcpBuilder::new()
            .op(BootpOp::Request)
            .xid(self.xid)
            .flags(0x8000) // Broadcast flag
            .chaddr(&self.mac_addr.0)
            .message_type(DhcpMessageType::Request);

        // During SELECTING state: include requested IP and server ID
        if let Some(ip) = self.offered_ip {
            builder = builder.requested_ip(ip);
        }
        if let Some(server) = self.offered_server {
            builder = builder.server_id(server);
        }

        builder = builder.parameter_request_list(&[
            options::SUBNET_MASK,
            options::ROUTER,
            options::DNS_SERVER,
            options::LEASE_TIME,
            options::RENEWAL_TIME,
            options::REBINDING_TIME,
        ]);

        builder.build()
    }

    /// Handle DHCP ACK - lease acquired
    fn handle_ack(&mut self, msg: &DhcpHeader) -> DhcpClientAction {
        let lease = self.parse_lease(msg);

        info!(
            "DHCP: Lease acquired on {}: {} (lease_time={}s, T1={}s, T2={}s)",
            self.interface,
            lease.ip_addr,
            lease.lease_time,
            lease.renewal_time,
            lease.rebinding_time
        );

        self.state = DhcpClientState::Bound;
        let action = DhcpClientAction::ConfigureInterface {
            interface: self.interface.clone(),
            ip_addr: lease.ip_addr,
            prefix_len: lease.prefix_len,
            gateway: lease.gateway,
            dns_servers: lease.dns_servers.clone(),
        };
        self.lease = Some(lease);

        action
    }

    /// Handle DHCP ACK during renewal/rebinding
    fn handle_renew_ack(&mut self, msg: &DhcpHeader) -> DhcpClientAction {
        let lease = self.parse_lease(msg);

        info!(
            "DHCP: Lease renewed on {}: {} (lease_time={}s)",
            self.interface, lease.ip_addr, lease.lease_time
        );

        self.state = DhcpClientState::Bound;
        self.lease = Some(lease);

        // No need to reconfigure interface, IP should be the same
        DhcpClientAction::None
    }

    /// Parse lease information from ACK message
    fn parse_lease(&self, msg: &DhcpHeader) -> DhcpLease {
        let ip_addr = msg.yiaddr();

        // Extract options
        let subnet_mask = msg
            .find_option_ip(options::SUBNET_MASK)
            .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
        let prefix_len = subnet_mask_to_prefix(subnet_mask);

        let gateway = msg.find_option_ip(options::ROUTER);

        let dns_servers = msg
            .find_option_ip_list(options::DNS_SERVER)
            .unwrap_or_default();

        let server_id = msg.server_id().unwrap_or(Ipv4Addr::UNSPECIFIED);

        let lease_time = msg
            .find_option_u32(options::LEASE_TIME)
            .unwrap_or(86400); // Default 24 hours

        let renewal_time = msg
            .find_option_u32(options::RENEWAL_TIME)
            .unwrap_or(lease_time / 2);

        let rebinding_time = msg
            .find_option_u32(options::REBINDING_TIME)
            .unwrap_or(lease_time * 7 / 8);

        DhcpLease {
            ip_addr,
            subnet_mask,
            prefix_len,
            gateway,
            dns_servers,
            server_id,
            lease_time,
            renewal_time,
            rebinding_time,
            obtained_at: Instant::now(),
        }
    }

    /// Handle DHCP NAK - restart discovery
    fn handle_nak(&mut self) -> DhcpClientAction {
        warn!("DHCP: Received NAK on {}, restarting discovery", self.interface);
        self.lease = None;
        self.start()
    }

    /// Called periodically to check timers and retransmit
    pub fn tick(&mut self) -> DhcpClientAction {
        let now = Instant::now();

        match self.state {
            DhcpClientState::Init => {
                // Should not happen if start() was called
                self.start()
            }

            DhcpClientState::Selecting | DhcpClientState::Requesting => {
                // Check retransmission timer
                if let Some(last) = self.last_sent {
                    let elapsed = now.duration_since(last);
                    let timeout = self.retransmit_timeout();

                    if elapsed > timeout {
                        self.retries += 1;
                        if self.retries > MAX_RETRIES {
                            warn!(
                                "DHCP: Max retries exceeded on {}, restarting",
                                self.interface
                            );
                            return self.start();
                        }

                        debug!(
                            "DHCP: Retransmit timeout on {} (retry {})",
                            self.interface, self.retries
                        );

                        // Retransmit
                        self.last_sent = Some(now);
                        return if self.state == DhcpClientState::Selecting {
                            self.resend_discover()
                        } else {
                            self.resend_request()
                        };
                    }
                }
                DhcpClientAction::None
            }

            DhcpClientState::Bound => {
                // Check if T1 (renewal) time has passed
                if let Some(ref lease) = self.lease {
                    if lease.is_renewal_due() {
                        return self.start_renew();
                    }
                }
                DhcpClientAction::None
            }

            DhcpClientState::Renewing => {
                if let Some(ref lease) = self.lease {
                    // Check if T2 (rebinding) time has passed
                    if lease.is_rebinding_due() {
                        return self.start_rebind();
                    }

                    // Check retransmit
                    if let Some(last) = self.last_sent {
                        if now.duration_since(last) > self.retransmit_timeout() {
                            return self.resend_renew_request();
                        }
                    }
                }
                DhcpClientAction::None
            }

            DhcpClientState::Rebinding => {
                if let Some(ref lease) = self.lease {
                    // Check if lease has expired
                    if lease.is_expired() {
                        warn!("DHCP: Lease expired on {}", self.interface);
                        self.lease = None;
                        self.state = DhcpClientState::Init;
                        return DhcpClientAction::DeconfigureInterface {
                            interface: self.interface.clone(),
                        };
                    }

                    // Check retransmit
                    if let Some(last) = self.last_sent {
                        if now.duration_since(last) > self.retransmit_timeout() {
                            return self.resend_rebind_request();
                        }
                    }
                }
                DhcpClientAction::None
            }
        }
    }

    /// Calculate retransmit timeout with exponential backoff
    fn retransmit_timeout(&self) -> Duration {
        // RFC 2131: Start at 4 seconds, double each retry, max 64 seconds
        let multiplier = 1u64 << self.retries.min(4); // 1, 2, 4, 8, 16
        Duration::from_secs(BASE_TIMEOUT_SECS * multiplier)
    }

    /// Resend DISCOVER (after timeout)
    fn resend_discover(&mut self) -> DhcpClientAction {
        debug!(
            "DHCP: Resending DISCOVER on {} (retry {})",
            self.interface, self.retries
        );
        let packet = self.build_discover();
        DhcpClientAction::SendPacket {
            interface: self.interface.clone(),
            packet,
            dst_ip: Ipv4Addr::BROADCAST,
            dst_mac: MacAddr::BROADCAST,
        }
    }

    /// Resend REQUEST (after timeout)
    fn resend_request(&mut self) -> DhcpClientAction {
        debug!(
            "DHCP: Resending REQUEST on {} (retry {})",
            self.interface, self.retries
        );
        let packet = self.build_request();
        DhcpClientAction::SendPacket {
            interface: self.interface.clone(),
            packet,
            dst_ip: Ipv4Addr::BROADCAST,
            dst_mac: MacAddr::BROADCAST,
        }
    }

    /// Start renewal process (unicast to server)
    fn start_renew(&mut self) -> DhcpClientAction {
        info!("DHCP: Starting renewal on {}", self.interface);
        self.state = DhcpClientState::Renewing;
        self.xid = Self::generate_xid();
        self.retries = 0;
        self.last_sent = Some(Instant::now());

        self.send_renew_request()
    }

    /// Send renew REQUEST (unicast)
    fn send_renew_request(&mut self) -> DhcpClientAction {
        let lease = match &self.lease {
            Some(l) => l,
            None => return self.start(),
        };

        let packet = DhcpBuilder::new()
            .op(BootpOp::Request)
            .xid(self.xid)
            .ciaddr(lease.ip_addr) // Client IP in ciaddr during renewal
            .chaddr(&self.mac_addr.0)
            .message_type(DhcpMessageType::Request)
            .parameter_request_list(&[
                options::SUBNET_MASK,
                options::ROUTER,
                options::DNS_SERVER,
                options::LEASE_TIME,
            ])
            .build();

        // Renewal is unicast to the server
        // Note: In practice, we might need ARP to resolve server MAC
        // For now, we use broadcast MAC but unicast IP
        DhcpClientAction::SendPacket {
            interface: self.interface.clone(),
            packet,
            dst_ip: lease.server_id,
            dst_mac: MacAddr::BROADCAST, // Will be resolved by ARP
        }
    }

    /// Resend renew REQUEST
    fn resend_renew_request(&mut self) -> DhcpClientAction {
        debug!(
            "DHCP: Resending renew REQUEST on {} (retry {})",
            self.interface, self.retries
        );
        self.retries += 1;
        self.last_sent = Some(Instant::now());
        self.send_renew_request()
    }

    /// Start rebinding process (broadcast)
    fn start_rebind(&mut self) -> DhcpClientAction {
        info!("DHCP: Starting rebinding on {}", self.interface);
        self.state = DhcpClientState::Rebinding;
        self.retries = 0;
        self.last_sent = Some(Instant::now());

        self.send_rebind_request()
    }

    /// Send rebind REQUEST (broadcast)
    fn send_rebind_request(&mut self) -> DhcpClientAction {
        let lease = match &self.lease {
            Some(l) => l,
            None => return self.start(),
        };

        let packet = DhcpBuilder::new()
            .op(BootpOp::Request)
            .xid(self.xid)
            .ciaddr(lease.ip_addr)
            .chaddr(&self.mac_addr.0)
            .message_type(DhcpMessageType::Request)
            .parameter_request_list(&[
                options::SUBNET_MASK,
                options::ROUTER,
                options::DNS_SERVER,
                options::LEASE_TIME,
            ])
            .build();

        // Rebinding is broadcast
        DhcpClientAction::SendPacket {
            interface: self.interface.clone(),
            packet,
            dst_ip: Ipv4Addr::BROADCAST,
            dst_mac: MacAddr::BROADCAST,
        }
    }

    /// Resend rebind REQUEST
    fn resend_rebind_request(&mut self) -> DhcpClientAction {
        debug!(
            "DHCP: Resending rebind REQUEST on {} (retry {})",
            self.interface, self.retries
        );
        self.retries += 1;
        self.last_sent = Some(Instant::now());
        self.send_rebind_request()
    }
}

/// Convert subnet mask to prefix length
fn subnet_mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    bits.count_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_mac() -> MacAddr {
        MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    }

    #[test]
    fn test_client_initial_state() {
        let client = DhcpClient::new("eth0".into(), make_test_mac());
        assert_eq!(client.state(), DhcpClientState::Init);
        assert!(client.lease().is_none());
    }

    #[test]
    fn test_start_sends_discover() {
        let mut client = DhcpClient::new("eth0".into(), make_test_mac());
        let action = client.start();

        match action {
            DhcpClientAction::SendPacket {
                dst_ip, packet, ..
            } => {
                assert_eq!(dst_ip, Ipv4Addr::BROADCAST);
                let dhcp = DhcpHeader::parse(&packet).unwrap();
                assert_eq!(dhcp.message_type(), Some(DhcpMessageType::Discover));
            }
            _ => panic!("Expected SendPacket action"),
        }

        assert_eq!(client.state(), DhcpClientState::Selecting);
    }

    #[test]
    fn test_subnet_mask_to_prefix() {
        assert_eq!(subnet_mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(subnet_mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(subnet_mask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(subnet_mask_to_prefix(Ipv4Addr::new(255, 255, 255, 128)), 25);
        assert_eq!(subnet_mask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    fn make_offer(xid: u32, offered_ip: Ipv4Addr, server_ip: Ipv4Addr) -> Vec<u8> {
        use crate::protocol::dhcp::MAGIC_COOKIE;

        let mut packet = vec![0u8; 300];

        // BOOTP header
        packet[0] = 2; // op = BOOTREPLY
        packet[1] = 1; // htype = Ethernet
        packet[2] = 6; // hlen = 6

        // xid
        packet[4..8].copy_from_slice(&xid.to_be_bytes());

        // yiaddr (offered IP)
        packet[16..20].copy_from_slice(&offered_ip.octets());

        // chaddr
        packet[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Magic cookie
        packet[236..240].copy_from_slice(&MAGIC_COOKIE);

        // Options
        let mut pos = 240;

        // Message Type = OFFER
        packet[pos] = 53;
        packet[pos + 1] = 1;
        packet[pos + 2] = 2;
        pos += 3;

        // Server ID
        packet[pos] = 54;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&server_ip.octets());
        pos += 6;

        // End
        packet[pos] = 255;

        packet
    }

    fn make_ack(
        xid: u32,
        offered_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        gateway: Ipv4Addr,
        lease_time: u32,
    ) -> Vec<u8> {
        use crate::protocol::dhcp::MAGIC_COOKIE;

        let mut packet = vec![0u8; 300];

        packet[0] = 2; // op = BOOTREPLY
        packet[1] = 1;
        packet[2] = 6;

        packet[4..8].copy_from_slice(&xid.to_be_bytes());
        packet[16..20].copy_from_slice(&offered_ip.octets());
        packet[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        packet[236..240].copy_from_slice(&MAGIC_COOKIE);

        let mut pos = 240;

        // Message Type = ACK
        packet[pos] = 53;
        packet[pos + 1] = 1;
        packet[pos + 2] = 5;
        pos += 3;

        // Server ID
        packet[pos] = 54;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&server_ip.octets());
        pos += 6;

        // Subnet mask
        packet[pos] = 1;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&subnet_mask.octets());
        pos += 6;

        // Router
        packet[pos] = 3;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&gateway.octets());
        pos += 6;

        // Lease time
        packet[pos] = 51;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&lease_time.to_be_bytes());
        pos += 6;

        // End
        packet[pos] = 255;

        packet
    }

    fn make_nak(xid: u32) -> Vec<u8> {
        use crate::protocol::dhcp::MAGIC_COOKIE;

        let mut packet = vec![0u8; 300];

        packet[0] = 2;
        packet[1] = 1;
        packet[2] = 6;

        packet[4..8].copy_from_slice(&xid.to_be_bytes());
        packet[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        packet[236..240].copy_from_slice(&MAGIC_COOKIE);

        // Message Type = NAK
        packet[240] = 53;
        packet[241] = 1;
        packet[242] = 6;
        packet[243] = 255;

        packet
    }

    #[test]
    fn test_offer_transitions_to_requesting() {
        let mut client = DhcpClient::new("eth0".into(), make_test_mac());
        client.start();
        let xid = client.xid;

        let offer = make_offer(xid, Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, 1));
        let action = client.process_response(&offer);

        match action {
            DhcpClientAction::SendPacket { packet, .. } => {
                let dhcp = DhcpHeader::parse(&packet).unwrap();
                assert_eq!(dhcp.message_type(), Some(DhcpMessageType::Request));
            }
            _ => panic!("Expected SendPacket action"),
        }

        assert_eq!(client.state(), DhcpClientState::Requesting);
    }

    #[test]
    fn test_ack_transitions_to_bound() {
        let mut client = DhcpClient::new("eth0".into(), make_test_mac());
        client.start();
        let xid = client.xid;

        // Simulate OFFER
        let offer = make_offer(xid, Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, 1));
        client.process_response(&offer);

        // Simulate ACK
        let ack = make_ack(
            xid,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 1, 1),
            86400,
        );
        let action = client.process_response(&ack);

        match action {
            DhcpClientAction::ConfigureInterface { ip_addr, prefix_len, gateway, .. } => {
                assert_eq!(ip_addr, Ipv4Addr::new(192, 168, 1, 100));
                assert_eq!(prefix_len, 24);
                assert_eq!(gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
            }
            _ => panic!("Expected ConfigureInterface action"),
        }

        assert_eq!(client.state(), DhcpClientState::Bound);
        assert!(client.lease().is_some());
    }

    #[test]
    fn test_nak_restarts_discovery() {
        let mut client = DhcpClient::new("eth0".into(), make_test_mac());
        client.start();
        let xid = client.xid;

        let offer = make_offer(xid, Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, 1));
        client.process_response(&offer);

        let nak = make_nak(xid);
        let action = client.process_response(&nak);

        match action {
            DhcpClientAction::SendPacket { packet, .. } => {
                let dhcp = DhcpHeader::parse(&packet).unwrap();
                assert_eq!(dhcp.message_type(), Some(DhcpMessageType::Discover));
            }
            _ => panic!("Expected SendPacket action (new DISCOVER)"),
        }

        assert_eq!(client.state(), DhcpClientState::Selecting);
    }

    #[test]
    fn test_wrong_xid_ignored() {
        let mut client = DhcpClient::new("eth0".into(), make_test_mac());
        client.start();

        // Offer with wrong xid
        let offer = make_offer(
            0xDEADBEEF,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        let action = client.process_response(&offer);

        match action {
            DhcpClientAction::None => {}
            _ => panic!("Expected None action for wrong xid"),
        }

        // State should still be Selecting
        assert_eq!(client.state(), DhcpClientState::Selecting);
    }
}

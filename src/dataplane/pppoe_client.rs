//! PPPoE client implementation
//!
//! Implements RFC 2516 PPPoE client state machine for establishing PPP sessions.

use crate::protocol::chap::{self, calculate_chap_md5, ChapBuilder, ChapPacket};
use crate::protocol::ethernet::FrameBuilder;
use crate::protocol::ipcp::{self, IpcpBuilder, IpcpPacket};
use crate::protocol::lcp::{self, LcpBuilder, LcpPacket};
use crate::protocol::pap::{PapBuilder, PapPacket};
use crate::protocol::ppp::{self, PppBuilder, PppFrame};
use crate::protocol::pppoe::{self, codes as pppoe_codes, tags, PppoeBuilder, PppoeFrame};
use crate::protocol::MacAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Maximum retries before giving up
const MAX_RETRIES: u8 = 10;

/// Discovery timeout in seconds
const DISCOVERY_TIMEOUT_SECS: u64 = 5;

/// LCP/IPCP timeout in seconds
const LCP_TIMEOUT_SECS: u64 = 3;

/// Authentication timeout in seconds
const AUTH_TIMEOUT_SECS: u64 = 10;

/// LCP Echo interval in seconds
const ECHO_INTERVAL_SECS: u64 = 30;

/// Maximum missed Echo-Reply before terminating
const ECHO_FAILURE_COUNT: u8 = 3;

/// PPPoE MTU (1500 - 8 PPPoE header)
pub const PPPOE_MTU: u16 = 1492;

/// PPPoE client state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PppoeClientState {
    /// Initial state
    Init,
    /// PADI sent, waiting for PADO
    PadiSent,
    /// PADR sent, waiting for PADS
    PadrSent,
    /// LCP negotiation in progress
    LcpNegotiating,
    /// Authentication in progress (PAP or CHAP)
    Authenticating,
    /// IPCP negotiation in progress
    IpcpNegotiating,
    /// Session established
    Opened,
    /// Terminating session
    Terminating,
}

/// PPPoE session information
#[derive(Debug, Clone)]
pub struct PppoeSession {
    /// Assigned IP address
    pub ip_addr: Ipv4Addr,
    /// Peer IP address (for point-to-point link)
    pub peer_ip: Ipv4Addr,
    /// Primary DNS server
    pub dns1: Option<Ipv4Addr>,
    /// Secondary DNS server
    pub dns2: Option<Ipv4Addr>,
    /// Session ID
    pub session_id: u16,
    /// When session was established
    pub established_at: Instant,
}

/// Actions the PPPoE client needs the router to perform
#[derive(Debug)]
pub enum PppoeClientAction {
    /// Send a PPPoE Discovery packet
    SendDiscovery { interface: String, packet: Vec<u8> },
    /// Send a PPPoE Session packet
    SendSession { interface: String, packet: Vec<u8> },
    /// Configure interface with obtained IP
    ConfigureInterface {
        interface: String,
        ip_addr: Ipv4Addr,
        peer_ip: Ipv4Addr,
        dns_servers: Vec<Ipv4Addr>,
    },
    /// Remove interface IP configuration
    DeconfigureInterface { interface: String },
    /// Session terminated
    SessionTerminated { interface: String, reason: String },
    /// No action needed
    None,
}

/// Authentication method negotiated via LCP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMethod {
    None,
    Pap,
    ChapMd5,
}

/// PPPoE client for a single interface
#[derive(Debug)]
pub struct PppoeClient {
    // Basic info
    interface: String,
    mac_addr: MacAddr,

    // Credentials
    username: String,
    password: String,
    service_name: Option<String>,

    // State
    state: PppoeClientState,
    session_id: u16,
    ac_mac: MacAddr,

    // Discovery state
    host_uniq: [u8; 4],
    ac_cookie: Option<Vec<u8>>,

    // LCP state
    lcp_identifier: u8,
    lcp_our_magic: u32,
    lcp_peer_magic: u32,
    lcp_our_config_acked: bool,
    lcp_peer_config_acked: bool,
    auth_method: AuthMethod,

    // Authentication state
    auth_identifier: u8,

    // IPCP state
    ipcp_identifier: u8,
    ipcp_our_config_acked: bool,
    ipcp_peer_config_acked: bool,
    assigned_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    dns1: Ipv4Addr,
    dns2: Ipv4Addr,

    // Session info
    session: Option<PppoeSession>,

    // Timers
    last_sent: Option<Instant>,
    retries: u8,

    // Echo keepalive
    echo_identifier: u8,
    echo_pending: bool,
    echo_failures: u8,
    last_echo_sent: Option<Instant>,
}

impl PppoeClient {
    /// Create a new PPPoE client
    pub fn new(
        interface: String,
        mac_addr: MacAddr,
        username: String,
        password: String,
        service_name: Option<String>,
    ) -> Self {
        Self {
            interface,
            mac_addr,
            username,
            password,
            service_name,
            state: PppoeClientState::Init,
            session_id: 0,
            ac_mac: MacAddr::ZERO,
            host_uniq: Self::generate_host_uniq(),
            ac_cookie: None,
            lcp_identifier: 0,
            lcp_our_magic: Self::generate_magic(),
            lcp_peer_magic: 0,
            lcp_our_config_acked: false,
            lcp_peer_config_acked: false,
            auth_method: AuthMethod::None,
            auth_identifier: 0,
            ipcp_identifier: 0,
            ipcp_our_config_acked: false,
            ipcp_peer_config_acked: false,
            assigned_ip: Ipv4Addr::UNSPECIFIED,
            peer_ip: Ipv4Addr::UNSPECIFIED,
            dns1: Ipv4Addr::UNSPECIFIED,
            dns2: Ipv4Addr::UNSPECIFIED,
            session: None,
            last_sent: None,
            retries: 0,
            echo_identifier: 0,
            echo_pending: false,
            echo_failures: 0,
            last_echo_sent: None,
        }
    }

    /// Get interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get current state
    pub fn state(&self) -> PppoeClientState {
        self.state
    }

    /// Get current session info
    pub fn session(&self) -> Option<&PppoeSession> {
        self.session.as_ref()
    }

    /// Get session ID (0 if not connected)
    pub fn session_id(&self) -> u16 {
        self.session_id
    }

    /// Generate random host_uniq
    fn generate_host_uniq() -> [u8; 4] {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        seed.wrapping_mul(1103515245)
            .wrapping_add(12345)
            .to_be_bytes()
    }

    /// Generate random magic number
    fn generate_magic() -> u32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        seed.wrapping_mul(1664525).wrapping_add(1013904223)
    }

    /// Start PPPoE discovery
    pub fn start(&mut self) -> PppoeClientAction {
        info!("PPPoE client starting on {}", self.interface);
        self.reset_state();
        self.send_padi()
    }

    /// Reset all state for new connection attempt
    fn reset_state(&mut self) {
        self.state = PppoeClientState::Init;
        self.session_id = 0;
        self.ac_mac = MacAddr::ZERO;
        self.host_uniq = Self::generate_host_uniq();
        self.ac_cookie = None;
        self.lcp_identifier = 0;
        self.lcp_our_magic = Self::generate_magic();
        self.lcp_peer_magic = 0;
        self.lcp_our_config_acked = false;
        self.lcp_peer_config_acked = false;
        self.auth_method = AuthMethod::None;
        self.auth_identifier = 0;
        self.ipcp_identifier = 0;
        self.ipcp_our_config_acked = false;
        self.ipcp_peer_config_acked = false;
        self.assigned_ip = Ipv4Addr::UNSPECIFIED;
        self.peer_ip = Ipv4Addr::UNSPECIFIED;
        self.dns1 = Ipv4Addr::UNSPECIFIED;
        self.dns2 = Ipv4Addr::UNSPECIFIED;
        self.session = None;
        self.last_sent = None;
        self.retries = 0;
        self.echo_identifier = 0;
        self.echo_pending = false;
        self.echo_failures = 0;
        self.last_echo_sent = None;
    }

    /// Send PADI (PPPoE Active Discovery Initiation)
    fn send_padi(&mut self) -> PppoeClientAction {
        debug!("PPPoE: Sending PADI on {}", self.interface);
        self.state = PppoeClientState::PadiSent;
        self.last_sent = Some(Instant::now());

        let pppoe = self.build_padi();
        let frame = self.wrap_discovery_frame(&pppoe, MacAddr::BROADCAST);

        PppoeClientAction::SendDiscovery {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Build PADI packet
    fn build_padi(&self) -> Vec<u8> {
        let mut builder = PppoeBuilder::discovery()
            .code(pppoe_codes::PADI)
            .host_uniq(&self.host_uniq);

        if let Some(ref name) = self.service_name {
            builder = builder.service_name(name);
        } else {
            builder = builder.service_name_any();
        }

        builder.build()
    }

    /// Send PADR (PPPoE Active Discovery Request)
    fn send_padr(&mut self) -> PppoeClientAction {
        debug!(
            "PPPoE: Sending PADR to {:?} on {}",
            self.ac_mac, self.interface
        );
        self.state = PppoeClientState::PadrSent;
        self.last_sent = Some(Instant::now());
        self.retries = 0;

        let pppoe = self.build_padr();
        let frame = self.wrap_discovery_frame(&pppoe, self.ac_mac);

        PppoeClientAction::SendDiscovery {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Build PADR packet
    fn build_padr(&self) -> Vec<u8> {
        let mut builder = PppoeBuilder::discovery()
            .code(pppoe_codes::PADR)
            .host_uniq(&self.host_uniq);

        if let Some(ref name) = self.service_name {
            builder = builder.service_name(name);
        } else {
            builder = builder.service_name_any();
        }

        if let Some(ref cookie) = self.ac_cookie {
            builder = builder.ac_cookie(cookie);
        }

        builder.build()
    }

    /// Send PADT (PPPoE Active Discovery Terminate)
    fn send_padt(&mut self, reason: &str) -> PppoeClientAction {
        debug!("PPPoE: Sending PADT on {} ({})", self.interface, reason);

        if self.session_id == 0 {
            return PppoeClientAction::SessionTerminated {
                interface: self.interface.clone(),
                reason: reason.to_string(),
            };
        }

        let pppoe = PppoeBuilder::discovery()
            .code(pppoe_codes::PADT)
            .session_id(self.session_id)
            .build();
        let frame = self.wrap_discovery_frame(&pppoe, self.ac_mac);

        self.state = PppoeClientState::Terminating;

        PppoeClientAction::SendDiscovery {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Wrap PPPoE in Ethernet frame for Discovery
    fn wrap_discovery_frame(&self, pppoe: &[u8], dst_mac: MacAddr) -> Vec<u8> {
        FrameBuilder::new()
            .dst_mac(dst_mac)
            .src_mac(self.mac_addr)
            .ethertype(pppoe::PPPOE_DISCOVERY_ETHERTYPE)
            .payload(pppoe)
            .build()
    }

    /// Wrap PPPoE in Ethernet frame for Session
    fn wrap_session_frame(&self, pppoe: &[u8]) -> Vec<u8> {
        FrameBuilder::new()
            .dst_mac(self.ac_mac)
            .src_mac(self.mac_addr)
            .ethertype(pppoe::PPPOE_SESSION_ETHERTYPE)
            .payload(pppoe)
            .build()
    }

    /// Wrap PPP in PPPoE Session frame
    fn wrap_ppp_in_pppoe(&self, ppp: &[u8]) -> Vec<u8> {
        PppoeBuilder::session(self.session_id).payload(ppp).build()
    }

    /// Process received PPPoE Discovery packet
    pub fn process_discovery(&mut self, src_mac: MacAddr, pppoe: &PppoeFrame) -> PppoeClientAction {
        match pppoe.code() {
            pppoe_codes::PADO => self.handle_pado(src_mac, pppoe),
            pppoe_codes::PADS => self.handle_pads(pppoe),
            pppoe_codes::PADT => self.handle_padt(),
            _ => {
                debug!("PPPoE: Ignoring discovery code 0x{:02x}", pppoe.code());
                PppoeClientAction::None
            }
        }
    }

    /// Handle PADO (PPPoE Active Discovery Offer)
    fn handle_pado(&mut self, src_mac: MacAddr, pppoe: &PppoeFrame) -> PppoeClientAction {
        if self.state != PppoeClientState::PadiSent {
            debug!("PPPoE: Ignoring PADO in state {:?}", self.state);
            return PppoeClientAction::None;
        }

        // Verify Host-Uniq matches
        if let Some(uniq) = pppoe.find_tag(tags::HOST_UNIQ) {
            if uniq != self.host_uniq {
                debug!("PPPoE: PADO Host-Uniq mismatch");
                return PppoeClientAction::None;
            }
        }

        // Store AC info
        self.ac_mac = src_mac;
        self.ac_cookie = pppoe.find_tag(tags::AC_COOKIE).map(|c| c.to_vec());

        let ac_name = pppoe
            .find_tag(tags::AC_NAME)
            .and_then(|n| std::str::from_utf8(n).ok())
            .unwrap_or("unknown");

        info!(
            "PPPoE: Received PADO from {} (AC: {}) on {}",
            src_mac, ac_name, self.interface
        );

        self.send_padr()
    }

    /// Handle PADS (PPPoE Active Discovery Session-confirmation)
    fn handle_pads(&mut self, pppoe: &PppoeFrame) -> PppoeClientAction {
        if self.state != PppoeClientState::PadrSent {
            debug!("PPPoE: Ignoring PADS in state {:?}", self.state);
            return PppoeClientAction::None;
        }

        // Check for errors
        if let Some(err) = pppoe.find_tag(tags::SERVICE_NAME_ERROR) {
            let msg = std::str::from_utf8(err).unwrap_or("unknown error");
            warn!("PPPoE: PADS Service-Name-Error: {}", msg);
            return self.send_padt(msg);
        }
        if let Some(err) = pppoe.find_tag(tags::AC_SYSTEM_ERROR) {
            let msg = std::str::from_utf8(err).unwrap_or("unknown error");
            warn!("PPPoE: PADS AC-System-Error: {}", msg);
            return self.send_padt(msg);
        }
        if let Some(err) = pppoe.find_tag(tags::GENERIC_ERROR) {
            let msg = std::str::from_utf8(err).unwrap_or("unknown error");
            warn!("PPPoE: PADS Generic-Error: {}", msg);
            return self.send_padt(msg);
        }

        self.session_id = pppoe.session_id();

        if self.session_id == 0 {
            warn!("PPPoE: PADS with session_id=0");
            return self.send_padt("invalid session_id");
        }

        info!(
            "PPPoE: Session established (id=0x{:04x}) on {}",
            self.session_id, self.interface
        );

        // Start LCP negotiation
        self.start_lcp()
    }

    /// Handle PADT (PPPoE Active Discovery Terminate)
    fn handle_padt(&mut self) -> PppoeClientAction {
        info!("PPPoE: Received PADT on {}", self.interface);
        let old_state = self.state;
        self.reset_state();

        if old_state == PppoeClientState::Opened {
            PppoeClientAction::DeconfigureInterface {
                interface: self.interface.clone(),
            }
        } else {
            PppoeClientAction::SessionTerminated {
                interface: self.interface.clone(),
                reason: "PADT received".to_string(),
            }
        }
    }

    /// Process received PPPoE Session packet
    pub fn process_session(&mut self, pppoe: &PppoeFrame) -> PppoeClientAction {
        // Verify session ID
        if pppoe.session_id() != self.session_id {
            debug!(
                "PPPoE: Session ID mismatch (got 0x{:04x}, expected 0x{:04x})",
                pppoe.session_id(),
                self.session_id
            );
            return PppoeClientAction::None;
        }

        // Parse PPP frame
        let ppp = match PppFrame::parse(pppoe.payload()) {
            Ok(p) => p,
            Err(e) => {
                debug!("PPPoE: Failed to parse PPP: {}", e);
                return PppoeClientAction::None;
            }
        };

        match ppp.protocol() {
            ppp::protocols::LCP => self.handle_lcp(ppp.payload()),
            ppp::protocols::PAP => self.handle_pap(ppp.payload()),
            ppp::protocols::CHAP => self.handle_chap(ppp.payload()),
            ppp::protocols::IPCP => self.handle_ipcp(ppp.payload()),
            _ => {
                debug!("PPPoE: Ignoring PPP protocol 0x{:04x}", ppp.protocol());
                PppoeClientAction::None
            }
        }
    }

    /// Start LCP negotiation
    fn start_lcp(&mut self) -> PppoeClientAction {
        debug!("PPPoE: Starting LCP negotiation on {}", self.interface);
        self.state = PppoeClientState::LcpNegotiating;
        self.lcp_identifier = self.lcp_identifier.wrapping_add(1);
        self.lcp_our_config_acked = false;
        self.lcp_peer_config_acked = false;
        self.last_sent = Some(Instant::now());
        self.retries = 0;

        self.send_lcp_config_request()
    }

    /// Send LCP Configure-Request
    fn send_lcp_config_request(&mut self) -> PppoeClientAction {
        let lcp = LcpBuilder::configure_request(self.lcp_identifier)
            .mru(PPPOE_MTU)
            .magic_number(self.lcp_our_magic)
            .build();

        let ppp = PppBuilder::lcp().payload(&lcp).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        debug!(
            "PPPoE: Sending LCP Configure-Request (id={}) on {}",
            self.lcp_identifier, self.interface
        );

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Handle LCP packet
    fn handle_lcp(&mut self, payload: &[u8]) -> PppoeClientAction {
        let lcp = match LcpPacket::parse(payload) {
            Ok(l) => l,
            Err(e) => {
                debug!("PPPoE: Failed to parse LCP: {}", e);
                return PppoeClientAction::None;
            }
        };

        debug!(
            "PPPoE: Received LCP code={} id={} on {}",
            lcp.code(),
            lcp.identifier(),
            self.interface
        );

        match lcp.code() {
            lcp::codes::CONFIGURE_REQUEST => self.handle_lcp_config_request(&lcp),
            lcp::codes::CONFIGURE_ACK => self.handle_lcp_config_ack(&lcp),
            lcp::codes::CONFIGURE_NAK => self.handle_lcp_config_nak(&lcp),
            lcp::codes::CONFIGURE_REJECT => self.handle_lcp_config_reject(&lcp),
            lcp::codes::TERMINATE_REQUEST => self.handle_lcp_terminate_request(&lcp),
            lcp::codes::TERMINATE_ACK => self.handle_lcp_terminate_ack(),
            lcp::codes::ECHO_REQUEST => self.handle_lcp_echo_request(&lcp),
            lcp::codes::ECHO_REPLY => self.handle_lcp_echo_reply(&lcp),
            _ => {
                debug!("PPPoE: Ignoring LCP code {}", lcp.code());
                PppoeClientAction::None
            }
        }
    }

    /// Handle LCP Configure-Request from peer
    fn handle_lcp_config_request(&mut self, lcp: &LcpPacket) -> PppoeClientAction {
        // Check for options we don't support
        let mut reject_options = Vec::new();
        let mut nak_options = Vec::new();

        for opt in lcp.iter_options() {
            match opt.opt_type {
                lcp::options::MRU => {
                    // Accept any MRU
                }
                lcp::options::MAGIC_NUMBER => {
                    if opt.data.len() >= 4 {
                        self.lcp_peer_magic = u32::from_be_bytes([
                            opt.data[0],
                            opt.data[1],
                            opt.data[2],
                            opt.data[3],
                        ]);
                    }
                }
                lcp::options::AUTH_PROTOCOL => {
                    if opt.data.len() >= 2 {
                        let proto = u16::from_be_bytes([opt.data[0], opt.data[1]]);
                        match proto {
                            lcp::auth::PAP => {
                                self.auth_method = AuthMethod::Pap;
                            }
                            lcp::auth::CHAP => {
                                if opt.data.len() >= 3 && opt.data[2] == lcp::auth::CHAP_MD5 {
                                    self.auth_method = AuthMethod::ChapMd5;
                                } else {
                                    // NAK with CHAP MD5
                                    nak_options.push((opt.opt_type, vec![0xc2, 0x23, 0x05]));
                                }
                            }
                            _ => {
                                // NAK with PAP (simpler)
                                nak_options.push((opt.opt_type, vec![0xc0, 0x23]));
                            }
                        }
                    }
                }
                lcp::options::PFC | lcp::options::ACFC => {
                    // Reject compression options for PPPoE
                    reject_options.push((opt.opt_type, opt.data.to_vec()));
                }
                _ => {
                    // Reject unknown options
                    reject_options.push((opt.opt_type, opt.data.to_vec()));
                }
            }
        }

        // Send Configure-Reject if any options rejected
        if !reject_options.is_empty() {
            return self.send_lcp_config_reject(lcp.identifier(), &reject_options);
        }

        // Send Configure-Nak if any options need modification
        if !nak_options.is_empty() {
            return self.send_lcp_config_nak(lcp.identifier(), &nak_options);
        }

        // Send Configure-Ack
        self.send_lcp_config_ack(lcp)
    }

    /// Send LCP Configure-Ack
    fn send_lcp_config_ack(&mut self, lcp: &LcpPacket) -> PppoeClientAction {
        self.lcp_peer_config_acked = true;

        let ack = LcpBuilder::configure_ack(lcp.identifier())
            .raw_data(lcp.data())
            .build();

        let ppp = PppBuilder::lcp().payload(&ack).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        debug!(
            "PPPoE: Sending LCP Configure-Ack (id={}) on {}",
            lcp.identifier(),
            self.interface
        );

        // Check if LCP is now open
        if self.lcp_our_config_acked && self.lcp_peer_config_acked {
            // LCP opened, but we need to send the Ack first
            // The transition will happen in the next tick or when processing continues
        }

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Send LCP Configure-Nak
    fn send_lcp_config_nak(&self, identifier: u8, options: &[(u8, Vec<u8>)]) -> PppoeClientAction {
        let mut builder = LcpBuilder::configure_nak(identifier);
        for (opt_type, data) in options {
            builder = builder.add_option(*opt_type, data);
        }
        let nak = builder.build();

        let ppp = PppBuilder::lcp().payload(&nak).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        debug!(
            "PPPoE: Sending LCP Configure-Nak (id={}) on {}",
            identifier, self.interface
        );

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Send LCP Configure-Reject
    fn send_lcp_config_reject(
        &self,
        identifier: u8,
        options: &[(u8, Vec<u8>)],
    ) -> PppoeClientAction {
        let mut builder = LcpBuilder::configure_reject(identifier);
        for (opt_type, data) in options {
            builder = builder.add_option(*opt_type, data);
        }
        let reject = builder.build();

        let ppp = PppBuilder::lcp().payload(&reject).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        debug!(
            "PPPoE: Sending LCP Configure-Reject (id={}) on {}",
            identifier, self.interface
        );

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Handle LCP Configure-Ack from peer
    fn handle_lcp_config_ack(&mut self, lcp: &LcpPacket) -> PppoeClientAction {
        if lcp.identifier() != self.lcp_identifier {
            debug!("PPPoE: LCP Configure-Ack identifier mismatch");
            return PppoeClientAction::None;
        }

        debug!("PPPoE: LCP Configure-Ack received on {}", self.interface);
        self.lcp_our_config_acked = true;

        self.check_lcp_opened()
    }

    /// Handle LCP Configure-Nak from peer
    fn handle_lcp_config_nak(&mut self, _lcp: &LcpPacket) -> PppoeClientAction {
        debug!("PPPoE: LCP Configure-Nak received on {}", self.interface);

        // Server suggests different values - we'll just retry with same values
        // In a real implementation, we'd adjust our config
        self.lcp_identifier = self.lcp_identifier.wrapping_add(1);
        self.last_sent = Some(Instant::now());
        self.send_lcp_config_request()
    }

    /// Handle LCP Configure-Reject from peer
    fn handle_lcp_config_reject(&mut self, _lcp: &LcpPacket) -> PppoeClientAction {
        debug!("PPPoE: LCP Configure-Reject received on {}", self.interface);

        // Server rejected some options - for now just retry
        // In a real implementation, we'd remove rejected options
        self.lcp_identifier = self.lcp_identifier.wrapping_add(1);
        self.last_sent = Some(Instant::now());
        self.send_lcp_config_request()
    }

    /// Handle LCP Terminate-Request
    fn handle_lcp_terminate_request(&mut self, lcp: &LcpPacket) -> PppoeClientAction {
        info!(
            "PPPoE: LCP Terminate-Request received on {}",
            self.interface
        );

        // Send Terminate-Ack
        let ack = LcpBuilder::terminate_ack(lcp.identifier()).build();
        let ppp = PppBuilder::lcp().payload(&ack).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        let old_state = self.state;
        self.reset_state();

        // Return both the Ack and termination notification
        // For simplicity, we just send the Ack
        if old_state == PppoeClientState::Opened {
            // Should also deconfigure interface, but for now just send Ack
        }

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Handle LCP Terminate-Ack
    fn handle_lcp_terminate_ack(&mut self) -> PppoeClientAction {
        debug!("PPPoE: LCP Terminate-Ack received on {}", self.interface);
        let old_state = self.state;
        self.reset_state();

        if old_state == PppoeClientState::Opened {
            PppoeClientAction::DeconfigureInterface {
                interface: self.interface.clone(),
            }
        } else {
            PppoeClientAction::SessionTerminated {
                interface: self.interface.clone(),
                reason: "LCP terminated".to_string(),
            }
        }
    }

    /// Handle LCP Echo-Request
    fn handle_lcp_echo_request(&mut self, lcp: &LcpPacket) -> PppoeClientAction {
        // Reply with our magic number
        let reply = LcpBuilder::echo_reply(lcp.identifier(), self.lcp_our_magic).build();
        let ppp = PppBuilder::lcp().payload(&reply).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Handle LCP Echo-Reply
    fn handle_lcp_echo_reply(&mut self, lcp: &LcpPacket) -> PppoeClientAction {
        if lcp.identifier() == self.echo_identifier {
            self.echo_pending = false;
            self.echo_failures = 0;
            debug!("PPPoE: Echo-Reply received on {}", self.interface);
        }
        PppoeClientAction::None
    }

    /// Check if LCP is now opened
    fn check_lcp_opened(&mut self) -> PppoeClientAction {
        if self.lcp_our_config_acked && self.lcp_peer_config_acked {
            info!(
                "PPPoE: LCP opened (auth={:?}) on {}",
                self.auth_method, self.interface
            );

            match self.auth_method {
                AuthMethod::None => {
                    // No auth required, go straight to IPCP
                    self.start_ipcp()
                }
                AuthMethod::Pap => {
                    // Start PAP authentication
                    self.start_pap()
                }
                AuthMethod::ChapMd5 => {
                    // Wait for CHAP Challenge from server
                    self.state = PppoeClientState::Authenticating;
                    self.last_sent = Some(Instant::now());
                    PppoeClientAction::None
                }
            }
        } else {
            PppoeClientAction::None
        }
    }

    /// Start PAP authentication
    fn start_pap(&mut self) -> PppoeClientAction {
        debug!("PPPoE: Starting PAP authentication on {}", self.interface);
        self.state = PppoeClientState::Authenticating;
        self.auth_identifier = self.auth_identifier.wrapping_add(1);
        self.last_sent = Some(Instant::now());
        self.retries = 0;

        let pap =
            PapBuilder::authenticate_request(self.auth_identifier, &self.username, &self.password)
                .build();

        let ppp = PppBuilder::pap().payload(&pap).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        debug!(
            "PPPoE: Sending PAP Authenticate-Request on {}",
            self.interface
        );

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Handle PAP packet
    fn handle_pap(&mut self, payload: &[u8]) -> PppoeClientAction {
        let pap = match PapPacket::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                debug!("PPPoE: Failed to parse PAP: {}", e);
                return PppoeClientAction::None;
            }
        };

        if pap.is_success() {
            let msg = pap
                .message()
                .and_then(|m| std::str::from_utf8(m).ok())
                .unwrap_or("");
            info!(
                "PPPoE: PAP authentication success: {} on {}",
                msg, self.interface
            );
            self.start_ipcp()
        } else if pap.is_failure() {
            let msg = pap
                .message()
                .and_then(|m| std::str::from_utf8(m).ok())
                .unwrap_or("unknown");
            warn!(
                "PPPoE: PAP authentication failed: {} on {}",
                msg, self.interface
            );
            self.send_padt(&format!("PAP auth failed: {}", msg))
        } else {
            PppoeClientAction::None
        }
    }

    /// Handle CHAP packet
    fn handle_chap(&mut self, payload: &[u8]) -> PppoeClientAction {
        let chap = match ChapPacket::parse(payload) {
            Ok(c) => c,
            Err(e) => {
                debug!("PPPoE: Failed to parse CHAP: {}", e);
                return PppoeClientAction::None;
            }
        };

        match chap.code() {
            chap::codes::CHALLENGE => self.handle_chap_challenge(&chap),
            chap::codes::SUCCESS => self.handle_chap_success(&chap),
            chap::codes::FAILURE => self.handle_chap_failure(&chap),
            _ => {
                debug!("PPPoE: Ignoring CHAP code {}", chap.code());
                PppoeClientAction::None
            }
        }
    }

    /// Handle CHAP Challenge
    fn handle_chap_challenge(&mut self, chap: &ChapPacket) -> PppoeClientAction {
        if self.state != PppoeClientState::Authenticating {
            debug!("PPPoE: CHAP Challenge in unexpected state {:?}", self.state);
            return PppoeClientAction::None;
        }

        let challenge = match chap.value() {
            Some(v) => v,
            None => {
                debug!("PPPoE: CHAP Challenge missing value");
                return PppoeClientAction::None;
            }
        };

        let server_name = chap
            .name()
            .and_then(|n| std::str::from_utf8(n).ok())
            .unwrap_or("server");

        debug!(
            "PPPoE: CHAP Challenge from {} (id={}) on {}",
            server_name,
            chap.identifier(),
            self.interface
        );

        // Calculate MD5 response
        let response = calculate_chap_md5(chap.identifier(), &self.password, challenge);

        let resp_packet =
            ChapBuilder::response(chap.identifier(), &response, &self.username).build();

        let ppp = PppBuilder::chap().payload(&resp_packet).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        debug!("PPPoE: Sending CHAP Response on {}", self.interface);

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Handle CHAP Success
    fn handle_chap_success(&mut self, chap: &ChapPacket) -> PppoeClientAction {
        let msg = chap
            .message()
            .and_then(|m| std::str::from_utf8(m).ok())
            .unwrap_or("");
        info!(
            "PPPoE: CHAP authentication success: {} on {}",
            msg, self.interface
        );
        self.start_ipcp()
    }

    /// Handle CHAP Failure
    fn handle_chap_failure(&mut self, chap: &ChapPacket) -> PppoeClientAction {
        let msg = chap
            .message()
            .and_then(|m| std::str::from_utf8(m).ok())
            .unwrap_or("unknown");
        warn!(
            "PPPoE: CHAP authentication failed: {} on {}",
            msg, self.interface
        );
        self.send_padt(&format!("CHAP auth failed: {}", msg))
    }

    /// Start IPCP negotiation
    fn start_ipcp(&mut self) -> PppoeClientAction {
        debug!("PPPoE: Starting IPCP negotiation on {}", self.interface);
        self.state = PppoeClientState::IpcpNegotiating;
        self.ipcp_identifier = self.ipcp_identifier.wrapping_add(1);
        self.ipcp_our_config_acked = false;
        self.ipcp_peer_config_acked = false;
        self.last_sent = Some(Instant::now());
        self.retries = 0;

        self.send_ipcp_config_request()
    }

    /// Send IPCP Configure-Request
    fn send_ipcp_config_request(&mut self) -> PppoeClientAction {
        let ipcp = IpcpBuilder::configure_request(self.ipcp_identifier)
            .ip_address(self.assigned_ip)
            .primary_dns(self.dns1)
            .secondary_dns(self.dns2)
            .build();

        let ppp = PppBuilder::ipcp().payload(&ipcp).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        debug!(
            "PPPoE: Sending IPCP Configure-Request (id={}) on {}",
            self.ipcp_identifier, self.interface
        );

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Handle IPCP packet
    fn handle_ipcp(&mut self, payload: &[u8]) -> PppoeClientAction {
        let ipcp = match IpcpPacket::parse(payload) {
            Ok(i) => i,
            Err(e) => {
                debug!("PPPoE: Failed to parse IPCP: {}", e);
                return PppoeClientAction::None;
            }
        };

        debug!(
            "PPPoE: Received IPCP code={} id={} on {}",
            ipcp.code(),
            ipcp.identifier(),
            self.interface
        );

        match ipcp.code() {
            ipcp::codes::CONFIGURE_REQUEST => self.handle_ipcp_config_request(&ipcp),
            ipcp::codes::CONFIGURE_ACK => self.handle_ipcp_config_ack(&ipcp),
            ipcp::codes::CONFIGURE_NAK => self.handle_ipcp_config_nak(&ipcp),
            ipcp::codes::CONFIGURE_REJECT => self.handle_ipcp_config_reject(&ipcp),
            _ => {
                debug!("PPPoE: Ignoring IPCP code {}", ipcp.code());
                PppoeClientAction::None
            }
        }
    }

    /// Handle IPCP Configure-Request from peer
    fn handle_ipcp_config_request(&mut self, ipcp: &IpcpPacket) -> PppoeClientAction {
        // Server wants to configure its side - we just accept
        // Store peer's IP if provided
        if let Some(ip) = ipcp.ip_address() {
            self.peer_ip = ip;
        }

        self.ipcp_peer_config_acked = true;

        let ack = IpcpBuilder::configure_ack(ipcp.identifier())
            .raw_data(ipcp.data())
            .build();

        let ppp = PppBuilder::ipcp().payload(&ack).build();
        let pppoe = self.wrap_ppp_in_pppoe(&ppp);
        let frame = self.wrap_session_frame(&pppoe);

        debug!(
            "PPPoE: Sending IPCP Configure-Ack (id={}) on {}",
            ipcp.identifier(),
            self.interface
        );

        // Check if IPCP is now open
        if self.ipcp_our_config_acked && self.ipcp_peer_config_acked {
            // Will open session after sending this Ack
        }

        PppoeClientAction::SendSession {
            interface: self.interface.clone(),
            packet: frame,
        }
    }

    /// Handle IPCP Configure-Ack from peer
    fn handle_ipcp_config_ack(&mut self, ipcp: &IpcpPacket) -> PppoeClientAction {
        if ipcp.identifier() != self.ipcp_identifier {
            debug!("PPPoE: IPCP Configure-Ack identifier mismatch");
            return PppoeClientAction::None;
        }

        debug!("PPPoE: IPCP Configure-Ack received on {}", self.interface);
        self.ipcp_our_config_acked = true;

        self.check_ipcp_opened()
    }

    /// Handle IPCP Configure-Nak from peer
    fn handle_ipcp_config_nak(&mut self, ipcp: &IpcpPacket) -> PppoeClientAction {
        debug!("PPPoE: IPCP Configure-Nak received on {}", self.interface);

        // Server suggests different values - accept them
        if let Some(ip) = ipcp.ip_address() {
            self.assigned_ip = ip;
            debug!("PPPoE: Server suggests IP: {}", ip);
        }
        if let Some(dns) = ipcp.primary_dns() {
            self.dns1 = dns;
            debug!("PPPoE: Server suggests DNS1: {}", dns);
        }
        if let Some(dns) = ipcp.secondary_dns() {
            self.dns2 = dns;
            debug!("PPPoE: Server suggests DNS2: {}", dns);
        }

        // Send new request with suggested values
        self.ipcp_identifier = self.ipcp_identifier.wrapping_add(1);
        self.last_sent = Some(Instant::now());
        self.send_ipcp_config_request()
    }

    /// Handle IPCP Configure-Reject from peer
    fn handle_ipcp_config_reject(&mut self, _ipcp: &IpcpPacket) -> PppoeClientAction {
        debug!(
            "PPPoE: IPCP Configure-Reject received on {}",
            self.interface
        );

        // Server rejected some options - for now just retry
        self.ipcp_identifier = self.ipcp_identifier.wrapping_add(1);
        self.last_sent = Some(Instant::now());
        self.send_ipcp_config_request()
    }

    /// Check if IPCP is now opened
    fn check_ipcp_opened(&mut self) -> PppoeClientAction {
        if self.ipcp_our_config_acked && self.ipcp_peer_config_acked {
            info!(
                "PPPoE: Session opened - IP={}, DNS={},{} on {}",
                self.assigned_ip, self.dns1, self.dns2, self.interface
            );

            self.state = PppoeClientState::Opened;
            self.session = Some(PppoeSession {
                ip_addr: self.assigned_ip,
                peer_ip: self.peer_ip,
                dns1: if self.dns1.is_unspecified() {
                    None
                } else {
                    Some(self.dns1)
                },
                dns2: if self.dns2.is_unspecified() {
                    None
                } else {
                    Some(self.dns2)
                },
                session_id: self.session_id,
                established_at: Instant::now(),
            });

            self.last_echo_sent = None;
            self.echo_pending = false;
            self.echo_failures = 0;

            let mut dns_servers = Vec::new();
            if !self.dns1.is_unspecified() {
                dns_servers.push(self.dns1);
            }
            if !self.dns2.is_unspecified() {
                dns_servers.push(self.dns2);
            }

            PppoeClientAction::ConfigureInterface {
                interface: self.interface.clone(),
                ip_addr: self.assigned_ip,
                peer_ip: self.peer_ip,
                dns_servers,
            }
        } else {
            PppoeClientAction::None
        }
    }

    /// Timer tick - handle retransmits and keepalives
    pub fn tick(&mut self) -> PppoeClientAction {
        let now = Instant::now();

        match self.state {
            PppoeClientState::Init => PppoeClientAction::None,

            PppoeClientState::PadiSent | PppoeClientState::PadrSent => {
                if let Some(last) = self.last_sent {
                    if now.duration_since(last) >= Duration::from_secs(DISCOVERY_TIMEOUT_SECS) {
                        self.retries += 1;
                        if self.retries > MAX_RETRIES {
                            warn!("PPPoE: Discovery timeout on {}", self.interface);
                            return PppoeClientAction::SessionTerminated {
                                interface: self.interface.clone(),
                                reason: "Discovery timeout".to_string(),
                            };
                        }
                        debug!(
                            "PPPoE: Retransmitting (attempt {}) on {}",
                            self.retries, self.interface
                        );
                        return if self.state == PppoeClientState::PadiSent {
                            self.send_padi()
                        } else {
                            self.send_padr()
                        };
                    }
                }
                PppoeClientAction::None
            }

            PppoeClientState::LcpNegotiating => {
                if let Some(last) = self.last_sent {
                    if now.duration_since(last) >= Duration::from_secs(LCP_TIMEOUT_SECS) {
                        self.retries += 1;
                        if self.retries > MAX_RETRIES {
                            warn!("PPPoE: LCP timeout on {}", self.interface);
                            return self.send_padt("LCP timeout");
                        }
                        self.lcp_identifier = self.lcp_identifier.wrapping_add(1);
                        self.last_sent = Some(now);
                        return self.send_lcp_config_request();
                    }
                }
                PppoeClientAction::None
            }

            PppoeClientState::Authenticating => {
                if let Some(last) = self.last_sent {
                    if now.duration_since(last) >= Duration::from_secs(AUTH_TIMEOUT_SECS) {
                        self.retries += 1;
                        if self.retries > MAX_RETRIES {
                            warn!("PPPoE: Authentication timeout on {}", self.interface);
                            return self.send_padt("Auth timeout");
                        }
                        if self.auth_method == AuthMethod::Pap {
                            return self.start_pap();
                        }
                        // For CHAP, wait for server challenge
                    }
                }
                PppoeClientAction::None
            }

            PppoeClientState::IpcpNegotiating => {
                if let Some(last) = self.last_sent {
                    if now.duration_since(last) >= Duration::from_secs(LCP_TIMEOUT_SECS) {
                        self.retries += 1;
                        if self.retries > MAX_RETRIES {
                            warn!("PPPoE: IPCP timeout on {}", self.interface);
                            return self.send_padt("IPCP timeout");
                        }
                        self.ipcp_identifier = self.ipcp_identifier.wrapping_add(1);
                        self.last_sent = Some(now);
                        return self.send_ipcp_config_request();
                    }
                }
                PppoeClientAction::None
            }

            PppoeClientState::Opened => {
                // Send LCP Echo for keepalive
                let should_send_echo = match self.last_echo_sent {
                    None => true,
                    Some(last) => {
                        now.duration_since(last) >= Duration::from_secs(ECHO_INTERVAL_SECS)
                    }
                };

                if should_send_echo {
                    if self.echo_pending {
                        self.echo_failures += 1;
                        if self.echo_failures >= ECHO_FAILURE_COUNT {
                            warn!(
                                "PPPoE: Echo timeout ({} failures) on {}",
                                self.echo_failures, self.interface
                            );
                            return self.send_padt("Echo timeout");
                        }
                    }

                    self.echo_identifier = self.echo_identifier.wrapping_add(1);
                    self.echo_pending = true;
                    self.last_echo_sent = Some(now);

                    let echo =
                        LcpBuilder::echo_request(self.echo_identifier, self.lcp_our_magic).build();
                    let ppp = PppBuilder::lcp().payload(&echo).build();
                    let pppoe = self.wrap_ppp_in_pppoe(&ppp);
                    let frame = self.wrap_session_frame(&pppoe);

                    return PppoeClientAction::SendSession {
                        interface: self.interface.clone(),
                        packet: frame,
                    };
                }

                PppoeClientAction::None
            }

            PppoeClientState::Terminating => {
                // Already sent PADT, just wait
                PppoeClientAction::None
            }
        }
    }

    /// Gracefully terminate the session
    pub fn terminate(&mut self) -> PppoeClientAction {
        info!("PPPoE: Terminating session on {}", self.interface);
        self.send_padt("user request")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_client() -> PppoeClient {
        PppoeClient::new(
            "eth0".to_string(),
            MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            "testuser".to_string(),
            "testpass".to_string(),
            None,
        )
    }

    #[test]
    fn test_initial_state() {
        let client = create_test_client();
        assert_eq!(client.state(), PppoeClientState::Init);
        assert_eq!(client.session_id(), 0);
    }

    #[test]
    fn test_start_sends_padi() {
        let mut client = create_test_client();
        let action = client.start();

        assert_eq!(client.state(), PppoeClientState::PadiSent);
        match action {
            PppoeClientAction::SendDiscovery { interface, packet } => {
                assert_eq!(interface, "eth0");
                assert!(!packet.is_empty());
            }
            _ => panic!("Expected SendDiscovery action"),
        }
    }

    #[test]
    fn test_pado_transitions_to_padr_sent() {
        let mut client = create_test_client();
        client.start();

        // Simulate PADO
        let pado = PppoeBuilder::discovery()
            .code(pppoe_codes::PADO)
            .host_uniq(&client.host_uniq)
            .ac_cookie(&[0x01, 0x02, 0x03, 0x04])
            .build();

        let pppoe = PppoeFrame::parse(&pado).unwrap();
        let ac_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let action = client.process_discovery(ac_mac, &pppoe);

        assert_eq!(client.state(), PppoeClientState::PadrSent);
        assert_eq!(client.ac_mac, ac_mac);
        match action {
            PppoeClientAction::SendDiscovery { .. } => {}
            _ => panic!("Expected SendDiscovery action for PADR"),
        }
    }

    #[test]
    fn test_pads_starts_lcp() {
        let mut client = create_test_client();
        client.start();

        // Move to PadrSent state
        client.state = PppoeClientState::PadrSent;
        client.ac_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        // Simulate PADS
        let pads = PppoeBuilder::discovery()
            .code(pppoe_codes::PADS)
            .session_id(0x1234)
            .build();

        let pppoe = PppoeFrame::parse(&pads).unwrap();
        let action = client.process_discovery(MacAddr::ZERO, &pppoe);

        assert_eq!(client.state(), PppoeClientState::LcpNegotiating);
        assert_eq!(client.session_id(), 0x1234);
        match action {
            PppoeClientAction::SendSession { .. } => {}
            _ => panic!("Expected SendSession action for LCP"),
        }
    }

    #[test]
    fn test_padt_resets_state() {
        let mut client = create_test_client();
        client.state = PppoeClientState::Opened;
        client.session_id = 0x1234;

        let padt = PppoeBuilder::discovery()
            .code(pppoe_codes::PADT)
            .session_id(0x1234)
            .build();

        let pppoe = PppoeFrame::parse(&padt).unwrap();
        let action = client.process_discovery(MacAddr::ZERO, &pppoe);

        assert_eq!(client.state(), PppoeClientState::Init);
        match action {
            PppoeClientAction::DeconfigureInterface { .. } => {}
            _ => panic!("Expected DeconfigureInterface action"),
        }
    }

    #[test]
    fn test_tick_retransmit() {
        let mut client = create_test_client();
        client.start();

        // Set last_sent to past
        client.last_sent = Some(Instant::now() - Duration::from_secs(10));

        let action = client.tick();
        match action {
            PppoeClientAction::SendDiscovery { .. } => {}
            _ => panic!("Expected SendDiscovery action for retransmit"),
        }
        assert_eq!(client.retries, 1);
    }

    #[test]
    fn test_terminate() {
        let mut client = create_test_client();
        client.state = PppoeClientState::Opened;
        client.session_id = 0x1234;
        client.ac_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let action = client.terminate();

        assert_eq!(client.state(), PppoeClientState::Terminating);
        match action {
            PppoeClientAction::SendDiscovery { .. } => {}
            _ => panic!("Expected SendDiscovery action for PADT"),
        }
    }
}

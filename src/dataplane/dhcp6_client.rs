//! DHCPv6 Client
//!
//! DHCPv6 client implementation for automatic IPv6 address assignment.
//! Supports SOLICIT/ADVERTISE/REQUEST/REPLY flow per RFC 8415.

use crate::protocol::dhcpv6::{
    options, Dhcp6Builder, Dhcp6Header, Dhcp6MessageType, Duid, IaAddress, IaNa, StatusCode,
    ALL_DHCP_SERVERS,
};
use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// DHCPv6 client processing result
#[derive(Debug)]
pub enum Dhcp6ClientAction {
    /// Send a DHCPv6 message
    Send {
        /// Interface to send on
        interface: String,
        /// DHCPv6 payload (to be wrapped in UDP/IP/Ethernet)
        packet: Vec<u8>,
        /// Destination IPv6 address
        dst_ip: Ipv6Addr,
    },
    /// Address acquired or renewed
    AddressAcquired {
        /// Interface name
        interface: String,
        /// Acquired lease information
        lease: Dhcp6Lease,
    },
    /// Address lost (lease expired or released)
    AddressLost {
        /// Interface name
        interface: String,
        /// Lost addresses
        addresses: Vec<Ipv6Addr>,
    },
    /// No action needed
    None,
}

/// DHCPv6 client state machine states (RFC 8415 Section 18)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcp6State {
    /// Initial state
    Init,
    /// Waiting for ADVERTISE after sending SOLICIT
    Selecting,
    /// Waiting for REPLY after sending REQUEST
    Requesting,
    /// Address bound, normal operation
    Bound,
    /// Renewing lease (T1 expired), sending RENEW
    Renewing,
    /// Rebinding (T2 expired, no response to RENEW), sending REBIND
    Rebinding,
    /// Releasing addresses
    Releasing,
}

/// Information about a leased address
#[derive(Debug, Clone)]
pub struct LeaseAddress {
    pub address: Ipv6Addr,
    pub preferred_lifetime: Duration,
    pub valid_lifetime: Duration,
}

/// Information acquired from DHCPv6
#[derive(Debug, Clone)]
pub struct Dhcp6Lease {
    /// IAID
    pub iaid: u32,
    /// Assigned IPv6 addresses
    pub addresses: Vec<LeaseAddress>,
    /// T1 (renewal time)
    pub t1: Duration,
    /// T2 (rebinding time)
    pub t2: Duration,
    /// DNS servers
    pub dns_servers: Vec<Ipv6Addr>,
    /// Domain search list
    pub domain_list: Vec<String>,
    /// Server DUID
    pub server_duid: Duid,
    /// When the lease was acquired
    pub acquired_at: Instant,
}

impl Dhcp6Lease {
    /// Check if T1 (renewal time) has passed
    pub fn is_t1_expired(&self) -> bool {
        if self.t1.is_zero() {
            return false;
        }
        self.acquired_at.elapsed() >= self.t1
    }

    /// Check if T2 (rebinding time) has passed
    pub fn is_t2_expired(&self) -> bool {
        if self.t2.is_zero() {
            return false;
        }
        self.acquired_at.elapsed() >= self.t2
    }

    /// Check if the lease has expired (valid lifetime)
    pub fn is_expired(&self) -> bool {
        self.addresses.iter().all(|addr| {
            if addr.valid_lifetime.is_zero() {
                return false; // Infinite
            }
            self.acquired_at.elapsed() >= addr.valid_lifetime
        })
    }
}

/// Received ADVERTISE message info
#[derive(Debug, Clone)]
struct ReceivedAdvertise {
    server_duid: Duid,
    preference: u8,
    ia_na: IaNa,
    dns_servers: Vec<Ipv6Addr>,
    domain_list: Vec<String>,
    has_rapid_commit: bool,
}

/// DHCPv6 client instance for a single interface
#[derive(Debug)]
pub struct Dhcp6ClientInterface {
    /// Interface name
    interface: String,
    /// Current state
    state: Dhcp6State,
    /// Our DUID
    client_duid: Duid,
    /// IAID for IA_NA
    iaid: u32,
    /// Current transaction ID
    transaction_id: u32,
    /// Server DUID (selected server)
    server_duid: Option<Duid>,
    /// Current lease
    lease: Option<Dhcp6Lease>,
    /// Received advertisements (during SELECTING)
    advertisements: Vec<ReceivedAdvertise>,
    /// Start time for elapsed time calculation
    start_time: Option<Instant>,
    /// Retransmit count
    retransmit_count: u32,
    /// Last retransmit time
    last_retransmit: Option<Instant>,
    /// Use rapid commit
    rapid_commit: bool,
    /// Options to request
    request_options: Vec<u16>,
}

impl Dhcp6ClientInterface {
    /// Create a new DHCPv6 client for an interface
    pub fn new(interface: String, mac: &MacAddr) -> Self {
        // Generate IAID from interface name hash
        let iaid = interface
            .bytes()
            .fold(0u32, |acc, b| acc.wrapping_add(b as u32));

        Self {
            interface,
            state: Dhcp6State::Init,
            client_duid: Duid::from_mac(mac),
            iaid,
            transaction_id: 0,
            server_duid: None,
            lease: None,
            advertisements: Vec::new(),
            start_time: None,
            retransmit_count: 0,
            last_retransmit: None,
            rapid_commit: true,
            request_options: vec![options::DNS_SERVERS, options::DOMAIN_LIST],
        }
    }

    /// Generate a new random transaction ID (24-bit)
    fn generate_transaction_id(&mut self) {
        // Simple pseudo-random based on current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.transaction_id = (now.as_nanos() as u32) & 0x00FFFFFF;
    }

    /// Get elapsed time in centiseconds since start
    fn elapsed_centiseconds(&self) -> u16 {
        self.start_time
            .map(|t| {
                let elapsed = t.elapsed().as_millis() / 10;
                elapsed.min(0xFFFF) as u16
            })
            .unwrap_or(0)
    }

    /// Start DHCPv6 process (send SOLICIT)
    pub fn start(&mut self) -> Vec<Dhcp6ClientAction> {
        debug!("DHCPv6: Starting on interface {}", self.interface);
        self.state = Dhcp6State::Init;
        self.advertisements.clear();
        self.generate_transaction_id();
        self.start_time = Some(Instant::now());
        self.retransmit_count = 0;

        self.send_solicit()
    }

    /// Build and send SOLICIT message
    fn send_solicit(&mut self) -> Vec<Dhcp6ClientAction> {
        self.state = Dhcp6State::Selecting;
        self.last_retransmit = Some(Instant::now());

        let mut builder = Dhcp6Builder::new(Dhcp6MessageType::Solicit)
            .transaction_id(self.transaction_id)
            .client_id(&self.client_duid)
            .ia_na(self.iaid, 0, 0)
            .elapsed_time(self.elapsed_centiseconds())
            .option_request(&self.request_options);

        if self.rapid_commit {
            builder = builder.rapid_commit();
        }

        let packet = builder.build();

        debug!(
            "DHCPv6: Sending SOLICIT on {} (xid: {:06x})",
            self.interface, self.transaction_id
        );

        vec![Dhcp6ClientAction::Send {
            interface: self.interface.clone(),
            packet,
            dst_ip: ALL_DHCP_SERVERS,
        }]
    }

    /// Build and send REQUEST message
    fn send_request(&mut self) -> Vec<Dhcp6ClientAction> {
        let server_duid = match &self.server_duid {
            Some(d) => d.clone(),
            None => {
                warn!("DHCPv6: No server DUID for REQUEST");
                return vec![];
            }
        };

        // Get the IA_NA from the best advertisement
        let best_adv = match self.advertisements.first() {
            Some(a) => a.clone(),
            None => {
                warn!("DHCPv6: No advertisement for REQUEST");
                return vec![];
            }
        };

        self.state = Dhcp6State::Requesting;
        self.last_retransmit = Some(Instant::now());

        let packet = Dhcp6Builder::new(Dhcp6MessageType::Request)
            .transaction_id(self.transaction_id)
            .client_id(&self.client_duid)
            .server_id(&server_duid)
            .ia_na_with_addresses(&best_adv.ia_na)
            .elapsed_time(self.elapsed_centiseconds())
            .option_request(&self.request_options)
            .build();

        debug!(
            "DHCPv6: Sending REQUEST on {} (xid: {:06x})",
            self.interface, self.transaction_id
        );

        vec![Dhcp6ClientAction::Send {
            interface: self.interface.clone(),
            packet,
            dst_ip: ALL_DHCP_SERVERS,
        }]
    }

    /// Build and send RENEW message
    fn send_renew(&mut self) -> Vec<Dhcp6ClientAction> {
        let lease = match &self.lease {
            Some(l) => l.clone(),
            None => return vec![],
        };

        self.generate_transaction_id();
        self.start_time = Some(Instant::now());
        self.state = Dhcp6State::Renewing;
        self.last_retransmit = Some(Instant::now());
        self.retransmit_count = 0;

        let ia_na = IaNa {
            iaid: lease.iaid,
            t1: 0,
            t2: 0,
            addresses: lease
                .addresses
                .iter()
                .map(|a| IaAddress {
                    address: a.address,
                    preferred_lifetime: a.preferred_lifetime.as_secs() as u32,
                    valid_lifetime: a.valid_lifetime.as_secs() as u32,
                })
                .collect(),
            status: None,
        };

        let packet = Dhcp6Builder::new(Dhcp6MessageType::Renew)
            .transaction_id(self.transaction_id)
            .client_id(&self.client_duid)
            .server_id(&lease.server_duid)
            .ia_na_with_addresses(&ia_na)
            .elapsed_time(0)
            .option_request(&self.request_options)
            .build();

        debug!(
            "DHCPv6: Sending RENEW on {} (xid: {:06x})",
            self.interface, self.transaction_id
        );

        vec![Dhcp6ClientAction::Send {
            interface: self.interface.clone(),
            packet,
            dst_ip: ALL_DHCP_SERVERS,
        }]
    }

    /// Build and send REBIND message
    fn send_rebind(&mut self) -> Vec<Dhcp6ClientAction> {
        let lease = match &self.lease {
            Some(l) => l.clone(),
            None => return vec![],
        };

        self.generate_transaction_id();
        self.start_time = Some(Instant::now());
        self.state = Dhcp6State::Rebinding;
        self.last_retransmit = Some(Instant::now());
        self.retransmit_count = 0;

        let ia_na = IaNa {
            iaid: lease.iaid,
            t1: 0,
            t2: 0,
            addresses: lease
                .addresses
                .iter()
                .map(|a| IaAddress {
                    address: a.address,
                    preferred_lifetime: a.preferred_lifetime.as_secs() as u32,
                    valid_lifetime: a.valid_lifetime.as_secs() as u32,
                })
                .collect(),
            status: None,
        };

        // REBIND does not include server ID (multicast to any server)
        let packet = Dhcp6Builder::new(Dhcp6MessageType::Rebind)
            .transaction_id(self.transaction_id)
            .client_id(&self.client_duid)
            .ia_na_with_addresses(&ia_na)
            .elapsed_time(0)
            .option_request(&self.request_options)
            .build();

        debug!(
            "DHCPv6: Sending REBIND on {} (xid: {:06x})",
            self.interface, self.transaction_id
        );

        vec![Dhcp6ClientAction::Send {
            interface: self.interface.clone(),
            packet,
            dst_ip: ALL_DHCP_SERVERS,
        }]
    }

    /// Build and send RELEASE message
    pub fn release(&mut self) -> Vec<Dhcp6ClientAction> {
        let lease = match &self.lease {
            Some(l) => l.clone(),
            None => return vec![],
        };

        self.generate_transaction_id();
        self.state = Dhcp6State::Releasing;

        let ia_na = IaNa {
            iaid: lease.iaid,
            t1: 0,
            t2: 0,
            addresses: lease
                .addresses
                .iter()
                .map(|a| IaAddress {
                    address: a.address,
                    preferred_lifetime: 0,
                    valid_lifetime: 0,
                })
                .collect(),
            status: None,
        };

        let packet = Dhcp6Builder::new(Dhcp6MessageType::Release)
            .transaction_id(self.transaction_id)
            .client_id(&self.client_duid)
            .server_id(&lease.server_duid)
            .ia_na_with_addresses(&ia_na)
            .elapsed_time(0)
            .build();

        debug!(
            "DHCPv6: Sending RELEASE on {} (xid: {:06x})",
            self.interface, self.transaction_id
        );

        let lost_addresses: Vec<Ipv6Addr> = lease.addresses.iter().map(|a| a.address).collect();

        self.lease = None;
        self.state = Dhcp6State::Init;

        vec![
            Dhcp6ClientAction::Send {
                interface: self.interface.clone(),
                packet,
                dst_ip: ALL_DHCP_SERVERS,
            },
            Dhcp6ClientAction::AddressLost {
                interface: self.interface.clone(),
                addresses: lost_addresses,
            },
        ]
    }

    /// Process received DHCPv6 message
    pub fn process_message(&mut self, msg: &Dhcp6Header) -> Vec<Dhcp6ClientAction> {
        // Verify transaction ID matches (except for server-initiated messages)
        if msg.transaction_id() != self.transaction_id {
            trace!(
                "DHCPv6: Transaction ID mismatch: expected {:06x}, got {:06x}",
                self.transaction_id,
                msg.transaction_id()
            );
            return vec![];
        }

        // Verify client ID matches
        if let Some(client_id) = msg.client_id() {
            if client_id != self.client_duid {
                trace!("DHCPv6: Client ID mismatch");
                return vec![];
            }
        }

        match msg.message_type() {
            Some(Dhcp6MessageType::Advertise) => self.handle_advertise(msg),
            Some(Dhcp6MessageType::Reply) => self.handle_reply(msg),
            _ => {
                trace!("DHCPv6: Ignoring message type {:?}", msg.message_type());
                vec![]
            }
        }
    }

    /// Handle ADVERTISE message
    fn handle_advertise(&mut self, msg: &Dhcp6Header) -> Vec<Dhcp6ClientAction> {
        if self.state != Dhcp6State::Selecting {
            trace!("DHCPv6: Ignoring ADVERTISE in state {:?}", self.state);
            return vec![];
        }

        let server_duid = match msg.server_id() {
            Some(d) => d,
            None => {
                debug!("DHCPv6: ADVERTISE without server ID");
                return vec![];
            }
        };

        let ia_na = match msg.ia_na() {
            Some(ia) => ia,
            None => {
                debug!("DHCPv6: ADVERTISE without IA_NA");
                return vec![];
            }
        };

        // Check status code
        if let Some((status, msg_text)) = &ia_na.status {
            if *status != StatusCode::Success {
                debug!("DHCPv6: ADVERTISE with status {:?}: {}", status, msg_text);
                return vec![];
            }
        }

        // Check if rapid commit was accepted
        if self.rapid_commit && msg.has_rapid_commit() {
            debug!("DHCPv6: Rapid commit accepted");
            return self.process_successful_reply(msg, &server_duid, &ia_na);
        }

        let preference = msg.preference().unwrap_or(0);

        debug!(
            "DHCPv6: Received ADVERTISE from server with preference {}",
            preference
        );

        // Store advertisement
        self.advertisements.push(ReceivedAdvertise {
            server_duid: server_duid.clone(),
            preference,
            ia_na,
            dns_servers: msg.dns_servers(),
            domain_list: msg.domain_list(),
            has_rapid_commit: msg.has_rapid_commit(),
        });

        // Sort by preference (highest first)
        self.advertisements
            .sort_by(|a, b| b.preference.cmp(&a.preference));

        // If we got max preference (255), proceed immediately
        if preference == 255 {
            self.server_duid = Some(server_duid);
            return self.send_request();
        }

        // Otherwise wait for more advertisements (handled by retransmit timer)
        vec![]
    }

    /// Handle REPLY message
    fn handle_reply(&mut self, msg: &Dhcp6Header) -> Vec<Dhcp6ClientAction> {
        match self.state {
            Dhcp6State::Requesting | Dhcp6State::Renewing | Dhcp6State::Rebinding => {}
            _ => {
                trace!("DHCPv6: Ignoring REPLY in state {:?}", self.state);
                return vec![];
            }
        }

        let server_duid = match msg.server_id() {
            Some(d) => d,
            None => {
                debug!("DHCPv6: REPLY without server ID");
                return vec![];
            }
        };

        let ia_na = match msg.ia_na() {
            Some(ia) => ia,
            None => {
                debug!("DHCPv6: REPLY without IA_NA");
                return vec![];
            }
        };

        // Check status code
        if let Some((status, msg_text)) = &ia_na.status {
            if *status != StatusCode::Success {
                debug!("DHCPv6: REPLY with status {:?}: {}", status, msg_text);
                // On failure, restart
                return self.start();
            }
        }

        self.process_successful_reply(msg, &server_duid, &ia_na)
    }

    /// Process a successful REPLY (or rapid commit ADVERTISE)
    fn process_successful_reply(
        &mut self,
        msg: &Dhcp6Header,
        server_duid: &Duid,
        ia_na: &IaNa,
    ) -> Vec<Dhcp6ClientAction> {
        let addresses: Vec<LeaseAddress> = ia_na
            .addresses
            .iter()
            .map(|a| LeaseAddress {
                address: a.address,
                preferred_lifetime: Duration::from_secs(a.preferred_lifetime as u64),
                valid_lifetime: Duration::from_secs(a.valid_lifetime as u64),
            })
            .collect();

        if addresses.is_empty() {
            warn!("DHCPv6: REPLY with no addresses");
            return self.start();
        }

        let t1 = Duration::from_secs(ia_na.t1 as u64);
        let t2 = Duration::from_secs(ia_na.t2 as u64);

        let lease = Dhcp6Lease {
            iaid: ia_na.iaid,
            addresses: addresses.clone(),
            t1,
            t2,
            dns_servers: msg.dns_servers(),
            domain_list: msg.domain_list(),
            server_duid: server_duid.clone(),
            acquired_at: Instant::now(),
        };

        debug!(
            "DHCPv6: Address acquired on {}: {:?}, T1={:?}, T2={:?}",
            self.interface,
            addresses.iter().map(|a| a.address).collect::<Vec<_>>(),
            t1,
            t2
        );

        self.state = Dhcp6State::Bound;
        self.server_duid = Some(server_duid.clone());
        self.lease = Some(lease.clone());
        self.advertisements.clear();

        vec![Dhcp6ClientAction::AddressAcquired {
            interface: self.interface.clone(),
            lease,
        }]
    }

    /// Run maintenance - check timers and retransmit if needed
    pub fn run_maintenance(&mut self) -> Vec<Dhcp6ClientAction> {
        match self.state {
            Dhcp6State::Init => vec![],
            Dhcp6State::Selecting => self.maintenance_selecting(),
            Dhcp6State::Requesting => self.maintenance_requesting(),
            Dhcp6State::Bound => self.maintenance_bound(),
            Dhcp6State::Renewing => self.maintenance_renewing(),
            Dhcp6State::Rebinding => self.maintenance_rebinding(),
            Dhcp6State::Releasing => vec![],
        }
    }

    fn maintenance_selecting(&mut self) -> Vec<Dhcp6ClientAction> {
        let elapsed = self
            .last_retransmit
            .map(|t| t.elapsed())
            .unwrap_or_default();

        // RFC 8415: Initial retransmit time is 1 second
        let retransmit_interval = Duration::from_secs(1 << self.retransmit_count.min(6));

        if elapsed >= retransmit_interval {
            // If we have advertisements, proceed with best one
            if !self.advertisements.is_empty() {
                let best = self.advertisements.first().unwrap().clone();
                self.server_duid = Some(best.server_duid);
                return self.send_request();
            }

            // Otherwise retransmit SOLICIT
            self.retransmit_count += 1;
            if self.retransmit_count > 8 {
                warn!(
                    "DHCPv6: Max retransmits reached on {}, restarting",
                    self.interface
                );
                return self.start();
            }
            return self.send_solicit();
        }
        vec![]
    }

    fn maintenance_requesting(&mut self) -> Vec<Dhcp6ClientAction> {
        let elapsed = self
            .last_retransmit
            .map(|t| t.elapsed())
            .unwrap_or_default();

        let retransmit_interval = Duration::from_secs(1 << self.retransmit_count.min(6));

        if elapsed >= retransmit_interval {
            self.retransmit_count += 1;
            if self.retransmit_count > 10 {
                warn!(
                    "DHCPv6: Max REQUEST retransmits on {}, restarting",
                    self.interface
                );
                return self.start();
            }
            return self.send_request();
        }
        vec![]
    }

    fn maintenance_bound(&mut self) -> Vec<Dhcp6ClientAction> {
        let lease = match &self.lease {
            Some(l) => l,
            None => return self.start(),
        };

        // Check if lease expired
        if lease.is_expired() {
            warn!("DHCPv6: Lease expired on {}", self.interface);
            let lost_addresses: Vec<Ipv6Addr> = lease.addresses.iter().map(|a| a.address).collect();
            self.lease = None;
            return vec![
                Dhcp6ClientAction::AddressLost {
                    interface: self.interface.clone(),
                    addresses: lost_addresses,
                },
                // Restart
                self.start()
                    .into_iter()
                    .next()
                    .unwrap_or(Dhcp6ClientAction::None),
            ]
            .into_iter()
            .filter(|a| !matches!(a, Dhcp6ClientAction::None))
            .collect();
        }

        // Check T2 first (rebind)
        if lease.is_t2_expired() {
            debug!("DHCPv6: T2 expired on {}, starting REBIND", self.interface);
            return self.send_rebind();
        }

        // Check T1 (renew)
        if lease.is_t1_expired() {
            debug!("DHCPv6: T1 expired on {}, starting RENEW", self.interface);
            return self.send_renew();
        }

        vec![]
    }

    fn maintenance_renewing(&mut self) -> Vec<Dhcp6ClientAction> {
        let lease = match &self.lease {
            Some(l) => l,
            None => return self.start(),
        };

        // Check if we should switch to REBIND
        if lease.is_t2_expired() {
            debug!(
                "DHCPv6: T2 expired during RENEW on {}, switching to REBIND",
                self.interface
            );
            return self.send_rebind();
        }

        let elapsed = self
            .last_retransmit
            .map(|t| t.elapsed())
            .unwrap_or_default();

        let retransmit_interval = Duration::from_secs(10.min(1 << self.retransmit_count.min(6)));

        if elapsed >= retransmit_interval {
            self.retransmit_count += 1;
            self.last_retransmit = Some(Instant::now());

            let ia_na = IaNa {
                iaid: lease.iaid,
                t1: 0,
                t2: 0,
                addresses: lease
                    .addresses
                    .iter()
                    .map(|a| IaAddress {
                        address: a.address,
                        preferred_lifetime: a.preferred_lifetime.as_secs() as u32,
                        valid_lifetime: a.valid_lifetime.as_secs() as u32,
                    })
                    .collect(),
                status: None,
            };

            let packet = Dhcp6Builder::new(Dhcp6MessageType::Renew)
                .transaction_id(self.transaction_id)
                .client_id(&self.client_duid)
                .server_id(&lease.server_duid)
                .ia_na_with_addresses(&ia_na)
                .elapsed_time(self.elapsed_centiseconds())
                .option_request(&self.request_options)
                .build();

            return vec![Dhcp6ClientAction::Send {
                interface: self.interface.clone(),
                packet,
                dst_ip: ALL_DHCP_SERVERS,
            }];
        }
        vec![]
    }

    fn maintenance_rebinding(&mut self) -> Vec<Dhcp6ClientAction> {
        let lease = match &self.lease {
            Some(l) => l,
            None => return self.start(),
        };

        // Check if lease expired
        if lease.is_expired() {
            warn!("DHCPv6: Lease expired during REBIND on {}", self.interface);
            let lost_addresses: Vec<Ipv6Addr> = lease.addresses.iter().map(|a| a.address).collect();
            self.lease = None;
            return vec![
                Dhcp6ClientAction::AddressLost {
                    interface: self.interface.clone(),
                    addresses: lost_addresses,
                },
                self.start()
                    .into_iter()
                    .next()
                    .unwrap_or(Dhcp6ClientAction::None),
            ]
            .into_iter()
            .filter(|a| !matches!(a, Dhcp6ClientAction::None))
            .collect();
        }

        let elapsed = self
            .last_retransmit
            .map(|t| t.elapsed())
            .unwrap_or_default();

        let retransmit_interval = Duration::from_secs(10.min(1 << self.retransmit_count.min(6)));

        if elapsed >= retransmit_interval {
            self.retransmit_count += 1;
            self.last_retransmit = Some(Instant::now());

            let ia_na = IaNa {
                iaid: lease.iaid,
                t1: 0,
                t2: 0,
                addresses: lease
                    .addresses
                    .iter()
                    .map(|a| IaAddress {
                        address: a.address,
                        preferred_lifetime: a.preferred_lifetime.as_secs() as u32,
                        valid_lifetime: a.valid_lifetime.as_secs() as u32,
                    })
                    .collect(),
                status: None,
            };

            let packet = Dhcp6Builder::new(Dhcp6MessageType::Rebind)
                .transaction_id(self.transaction_id)
                .client_id(&self.client_duid)
                .ia_na_with_addresses(&ia_na)
                .elapsed_time(self.elapsed_centiseconds())
                .option_request(&self.request_options)
                .build();

            return vec![Dhcp6ClientAction::Send {
                interface: self.interface.clone(),
                packet,
                dst_ip: ALL_DHCP_SERVERS,
            }];
        }
        vec![]
    }

    /// Get current state
    pub fn state(&self) -> Dhcp6State {
        self.state
    }

    /// Get current lease
    pub fn lease(&self) -> Option<&Dhcp6Lease> {
        self.lease.as_ref()
    }
}

/// DHCPv6 client managing multiple interfaces
#[derive(Debug, Default)]
pub struct Dhcp6Client {
    /// Per-interface clients
    clients: HashMap<String, Dhcp6ClientInterface>,
}

impl Dhcp6Client {
    /// Create a new DHCPv6 client
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    /// Add a client for an interface
    pub fn add_interface(&mut self, interface: String, mac: &MacAddr) {
        let client = Dhcp6ClientInterface::new(interface.clone(), mac);
        self.clients.insert(interface, client);
    }

    /// Remove a client
    pub fn remove_interface(&mut self, interface: &str) -> Vec<Dhcp6ClientAction> {
        if let Some(mut client) = self.clients.remove(interface) {
            return client.release();
        }
        vec![]
    }

    /// Check if client exists for interface
    pub fn has_interface(&self, interface: &str) -> bool {
        self.clients.contains_key(interface)
    }

    /// Start DHCPv6 on an interface
    pub fn start(&mut self, interface: &str) -> Vec<Dhcp6ClientAction> {
        if let Some(client) = self.clients.get_mut(interface) {
            return client.start();
        }
        vec![]
    }

    /// Process received DHCPv6 message on interface
    pub fn process_dhcp(&mut self, interface: &str, dhcp_payload: &[u8]) -> Vec<Dhcp6ClientAction> {
        let msg = match Dhcp6Header::parse(dhcp_payload) {
            Ok(m) => m,
            Err(e) => {
                debug!("DHCPv6: Failed to parse message: {}", e);
                return vec![];
            }
        };

        if let Some(client) = self.clients.get_mut(interface) {
            return client.process_message(&msg);
        }

        debug!("DHCPv6: No client for interface {}", interface);
        vec![]
    }

    /// Get current lease for interface
    pub fn get_lease(&self, interface: &str) -> Option<&Dhcp6Lease> {
        self.clients.get(interface).and_then(|c| c.lease())
    }

    /// Get state for interface
    pub fn get_state(&self, interface: &str) -> Option<Dhcp6State> {
        self.clients.get(interface).map(|c| c.state())
    }

    /// Run maintenance on all clients
    pub fn run_maintenance(&mut self) -> Vec<Dhcp6ClientAction> {
        let mut actions = Vec::new();
        for client in self.clients.values_mut() {
            actions.extend(client.run_maintenance());
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::dhcpv6::{Dhcp6Builder, Dhcp6MessageType, Duid};

    fn make_mac() -> MacAddr {
        MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    }

    fn make_server_mac() -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    }

    fn make_advertise(
        xid: u32,
        client_duid: &Duid,
        server_duid: &Duid,
        address: Ipv6Addr,
    ) -> Vec<u8> {
        let mut packet = Vec::new();

        // Header
        packet.push(Dhcp6MessageType::Advertise as u8);
        let xid_bytes = xid.to_be_bytes();
        packet.extend_from_slice(&xid_bytes[1..4]);

        // Client ID
        let client_bytes = client_duid.to_bytes();
        packet.extend_from_slice(&options::CLIENT_ID.to_be_bytes());
        packet.extend_from_slice(&(client_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(&client_bytes);

        // Server ID
        let server_bytes = server_duid.to_bytes();
        packet.extend_from_slice(&options::SERVER_ID.to_be_bytes());
        packet.extend_from_slice(&(server_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(&server_bytes);

        // IA_NA with address
        let ia_na_start = packet.len();
        packet.extend_from_slice(&options::IA_NA.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder
        packet.extend_from_slice(&1u32.to_be_bytes()); // IAID
        packet.extend_from_slice(&3600u32.to_be_bytes()); // T1
        packet.extend_from_slice(&5400u32.to_be_bytes()); // T2

        // IA_ADDR sub-option
        packet.extend_from_slice(&options::IA_ADDR.to_be_bytes());
        packet.extend_from_slice(&24u16.to_be_bytes());
        packet.extend_from_slice(&address.octets());
        packet.extend_from_slice(&7200u32.to_be_bytes()); // preferred
        packet.extend_from_slice(&7200u32.to_be_bytes()); // valid

        let ia_na_len = packet.len() - ia_na_start - 4;
        packet[ia_na_start + 2..ia_na_start + 4].copy_from_slice(&(ia_na_len as u16).to_be_bytes());

        packet
    }

    fn make_reply(xid: u32, client_duid: &Duid, server_duid: &Duid, address: Ipv6Addr) -> Vec<u8> {
        let mut packet = Vec::new();

        // Header
        packet.push(Dhcp6MessageType::Reply as u8);
        let xid_bytes = xid.to_be_bytes();
        packet.extend_from_slice(&xid_bytes[1..4]);

        // Client ID
        let client_bytes = client_duid.to_bytes();
        packet.extend_from_slice(&options::CLIENT_ID.to_be_bytes());
        packet.extend_from_slice(&(client_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(&client_bytes);

        // Server ID
        let server_bytes = server_duid.to_bytes();
        packet.extend_from_slice(&options::SERVER_ID.to_be_bytes());
        packet.extend_from_slice(&(server_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(&server_bytes);

        // IA_NA with address
        let ia_na_start = packet.len();
        packet.extend_from_slice(&options::IA_NA.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder
        packet.extend_from_slice(&1u32.to_be_bytes()); // IAID
        packet.extend_from_slice(&1800u32.to_be_bytes()); // T1 = 30min
        packet.extend_from_slice(&2700u32.to_be_bytes()); // T2 = 45min

        // IA_ADDR sub-option
        packet.extend_from_slice(&options::IA_ADDR.to_be_bytes());
        packet.extend_from_slice(&24u16.to_be_bytes());
        packet.extend_from_slice(&address.octets());
        packet.extend_from_slice(&3600u32.to_be_bytes()); // preferred = 1h
        packet.extend_from_slice(&7200u32.to_be_bytes()); // valid = 2h

        let ia_na_len = packet.len() - ia_na_start - 4;
        packet[ia_na_start + 2..ia_na_start + 4].copy_from_slice(&(ia_na_len as u16).to_be_bytes());

        packet
    }

    #[test]
    fn test_client_start() {
        let mac = make_mac();
        let mut client = Dhcp6ClientInterface::new("eth0".to_string(), &mac);

        let actions = client.start();
        assert_eq!(actions.len(), 1);

        match &actions[0] {
            Dhcp6ClientAction::Send {
                interface,
                packet,
                dst_ip,
            } => {
                assert_eq!(interface, "eth0");
                assert_eq!(*dst_ip, ALL_DHCP_SERVERS);

                let header = Dhcp6Header::parse(packet).unwrap();
                assert_eq!(header.message_type(), Some(Dhcp6MessageType::Solicit));
                assert!(header.find_option(options::CLIENT_ID).is_some());
                assert!(header.find_option(options::IA_NA).is_some());
            }
            _ => panic!("Expected Send action"),
        }

        assert_eq!(client.state(), Dhcp6State::Selecting);
    }

    #[test]
    fn test_client_receive_advertise() {
        let mac = make_mac();
        let server_mac = make_server_mac();
        let mut client = Dhcp6ClientInterface::new("eth0".to_string(), &mac);

        // Start client
        client.start();
        let xid = client.transaction_id;
        let client_duid = client.client_duid.clone();
        let server_duid = Duid::from_mac(&server_mac);
        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // Receive ADVERTISE
        let advertise = make_advertise(xid, &client_duid, &server_duid, address);
        let header = Dhcp6Header::parse(&advertise).unwrap();
        let actions = client.process_message(&header);

        // Should not immediately transition (wait for more ads or timeout)
        assert!(actions.is_empty());
        assert_eq!(client.state(), Dhcp6State::Selecting);
        assert_eq!(client.advertisements.len(), 1);
    }

    #[test]
    fn test_client_full_flow() {
        let mac = make_mac();
        let server_mac = make_server_mac();
        let mut client = Dhcp6ClientInterface::new("eth0".to_string(), &mac);

        // Start client
        client.start();
        let xid = client.transaction_id;
        let client_duid = client.client_duid.clone();
        let server_duid = Duid::from_mac(&server_mac);
        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // Receive ADVERTISE with max preference
        let mut advertise = make_advertise(xid, &client_duid, &server_duid, address);
        // Add preference = 255
        advertise.extend_from_slice(&options::PREFERENCE.to_be_bytes());
        advertise.extend_from_slice(&1u16.to_be_bytes());
        advertise.push(255);

        let header = Dhcp6Header::parse(&advertise).unwrap();
        let actions = client.process_message(&header);

        // Should send REQUEST
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Dhcp6ClientAction::Send { packet, .. } => {
                let header = Dhcp6Header::parse(packet).unwrap();
                assert_eq!(header.message_type(), Some(Dhcp6MessageType::Request));
            }
            _ => panic!("Expected Send action"),
        }
        assert_eq!(client.state(), Dhcp6State::Requesting);

        // Receive REPLY
        let reply = make_reply(xid, &client_duid, &server_duid, address);
        let header = Dhcp6Header::parse(&reply).unwrap();
        let actions = client.process_message(&header);

        // Should transition to BOUND
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Dhcp6ClientAction::AddressAcquired { interface, lease } => {
                assert_eq!(interface, "eth0");
                assert_eq!(lease.addresses.len(), 1);
                assert_eq!(lease.addresses[0].address, address);
            }
            _ => panic!("Expected AddressAcquired action"),
        }
        assert_eq!(client.state(), Dhcp6State::Bound);
    }

    #[test]
    fn test_client_wrong_xid() {
        let mac = make_mac();
        let server_mac = make_server_mac();
        let mut client = Dhcp6ClientInterface::new("eth0".to_string(), &mac);

        client.start();
        let client_duid = client.client_duid.clone();
        let server_duid = Duid::from_mac(&server_mac);
        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // Receive ADVERTISE with wrong xid
        let advertise = make_advertise(0xFFFFFF, &client_duid, &server_duid, address);
        let header = Dhcp6Header::parse(&advertise).unwrap();
        let actions = client.process_message(&header);

        // Should be ignored
        assert!(actions.is_empty());
    }

    #[test]
    fn test_multi_client() {
        let mac1 = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mac2 = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x66]);

        let mut client = Dhcp6Client::new();
        client.add_interface("eth0".to_string(), &mac1);
        client.add_interface("eth1".to_string(), &mac2);

        assert!(client.has_interface("eth0"));
        assert!(client.has_interface("eth1"));
        assert!(!client.has_interface("eth2"));

        let actions = client.start("eth0");
        assert_eq!(actions.len(), 1);

        assert_eq!(client.get_state("eth0"), Some(Dhcp6State::Selecting));
        assert_eq!(client.get_state("eth1"), Some(Dhcp6State::Init));
    }

    #[test]
    fn test_lease_timers() {
        let lease = Dhcp6Lease {
            iaid: 1,
            addresses: vec![LeaseAddress {
                address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                preferred_lifetime: Duration::from_secs(3600),
                valid_lifetime: Duration::from_secs(7200),
            }],
            t1: Duration::from_millis(10), // Very short for test
            t2: Duration::from_millis(20),
            dns_servers: vec![],
            domain_list: vec![],
            server_duid: Duid::from_mac(&make_mac()),
            acquired_at: Instant::now(),
        };

        assert!(!lease.is_t1_expired());
        assert!(!lease.is_t2_expired());
        assert!(!lease.is_expired());

        std::thread::sleep(Duration::from_millis(15));
        assert!(lease.is_t1_expired());
        assert!(!lease.is_t2_expired());

        std::thread::sleep(Duration::from_millis(10));
        assert!(lease.is_t2_expired());
    }
}

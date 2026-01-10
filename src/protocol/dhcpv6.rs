//! DHCPv6 protocol - RFC 8415
//!
//! DHCPv6 message parsing and building for DHCPv6 client functionality.

use crate::protocol::types::MacAddr;
use crate::{Error, Result};
use std::net::Ipv6Addr;

/// DHCPv6 server port
pub const DHCP6_SERVER_PORT: u16 = 547;

/// DHCPv6 client port
pub const DHCP6_CLIENT_PORT: u16 = 546;

/// Fixed header size (msg-type + transaction-id)
pub const DHCP6_HEADER_SIZE: usize = 4;

/// Minimum packet size (header only, options are optional)
pub const MIN_PACKET_SIZE: usize = DHCP6_HEADER_SIZE;

/// All_DHCP_Relay_Agents_and_Servers multicast address (ff02::1:2)
pub const ALL_DHCP_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// DHCPv6 message types (RFC 8415 Section 7.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcp6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForward = 12,
    RelayReply = 13,
}

impl Dhcp6MessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Dhcp6MessageType::Solicit),
            2 => Some(Dhcp6MessageType::Advertise),
            3 => Some(Dhcp6MessageType::Request),
            4 => Some(Dhcp6MessageType::Confirm),
            5 => Some(Dhcp6MessageType::Renew),
            6 => Some(Dhcp6MessageType::Rebind),
            7 => Some(Dhcp6MessageType::Reply),
            8 => Some(Dhcp6MessageType::Release),
            9 => Some(Dhcp6MessageType::Decline),
            10 => Some(Dhcp6MessageType::Reconfigure),
            11 => Some(Dhcp6MessageType::InformationRequest),
            12 => Some(Dhcp6MessageType::RelayForward),
            13 => Some(Dhcp6MessageType::RelayReply),
            _ => None,
        }
    }
}

/// DHCPv6 option codes (RFC 8415, RFC 3646, etc.)
pub mod options {
    pub const CLIENT_ID: u16 = 1;
    pub const SERVER_ID: u16 = 2;
    pub const IA_NA: u16 = 3;
    pub const IA_TA: u16 = 4;
    pub const IA_ADDR: u16 = 5;
    pub const ORO: u16 = 6; // Option Request Option
    pub const PREFERENCE: u16 = 7;
    pub const ELAPSED_TIME: u16 = 8;
    pub const RELAY_MSG: u16 = 9;
    pub const AUTH: u16 = 11;
    pub const UNICAST: u16 = 12;
    pub const STATUS_CODE: u16 = 13;
    pub const RAPID_COMMIT: u16 = 14;
    pub const USER_CLASS: u16 = 15;
    pub const VENDOR_CLASS: u16 = 16;
    pub const VENDOR_OPTS: u16 = 17;
    pub const INTERFACE_ID: u16 = 18;
    pub const RECONF_MSG: u16 = 19;
    pub const RECONF_ACCEPT: u16 = 20;
    pub const DNS_SERVERS: u16 = 23; // RFC 3646
    pub const DOMAIN_LIST: u16 = 24; // RFC 3646
    pub const IA_PD: u16 = 25; // Prefix Delegation
    pub const IA_PREFIX: u16 = 26;
    pub const INFO_REFRESH: u16 = 32; // RFC 4242
    pub const SOL_MAX_RT: u16 = 82; // RFC 8415
    pub const INF_MAX_RT: u16 = 83; // RFC 8415
}

/// DHCPv6 status codes (RFC 8415 Section 21.13)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusCode {
    Success = 0,
    UnspecFail = 1,
    NoAddrsAvail = 2,
    NoBinding = 3,
    NotOnLink = 4,
    UseMulticast = 5,
    NoPrefixAvail = 6,
}

impl StatusCode {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(StatusCode::Success),
            1 => Some(StatusCode::UnspecFail),
            2 => Some(StatusCode::NoAddrsAvail),
            3 => Some(StatusCode::NoBinding),
            4 => Some(StatusCode::NotOnLink),
            5 => Some(StatusCode::UseMulticast),
            6 => Some(StatusCode::NoPrefixAvail),
            _ => None,
        }
    }
}

/// DUID types (RFC 8415 Section 11)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Duid {
    /// DUID-LLT: Link-layer address plus time (type 1)
    Llt {
        hardware_type: u16,
        time: u32,
        link_layer_addr: Vec<u8>,
    },
    /// DUID-EN: Enterprise number (type 2)
    En {
        enterprise_number: u32,
        identifier: Vec<u8>,
    },
    /// DUID-LL: Link-layer address (type 3)
    Ll {
        hardware_type: u16,
        link_layer_addr: Vec<u8>,
    },
    /// DUID-UUID (RFC 6355) (type 4)
    Uuid { uuid: [u8; 16] },
    /// Unknown DUID type
    Unknown { duid_type: u16, data: Vec<u8> },
}

impl Duid {
    /// Generate DUID-LL from MAC address
    pub fn from_mac(mac: &MacAddr) -> Self {
        Duid::Ll {
            hardware_type: 1, // Ethernet
            link_layer_addr: mac.0.to_vec(),
        }
    }

    /// Generate DUID-LLT from MAC address and time
    pub fn from_mac_with_time(mac: &MacAddr, time: u32) -> Self {
        Duid::Llt {
            hardware_type: 1, // Ethernet
            time,
            link_layer_addr: mac.0.to_vec(),
        }
    }

    /// Parse DUID from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::Parse("DUID too short".into()));
        }

        let duid_type = u16::from_be_bytes([data[0], data[1]]);
        let payload = &data[2..];

        match duid_type {
            1 => {
                // DUID-LLT
                if payload.len() < 6 {
                    return Err(Error::Parse("DUID-LLT too short".into()));
                }
                Ok(Duid::Llt {
                    hardware_type: u16::from_be_bytes([payload[0], payload[1]]),
                    time: u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]),
                    link_layer_addr: payload[6..].to_vec(),
                })
            }
            2 => {
                // DUID-EN
                if payload.len() < 4 {
                    return Err(Error::Parse("DUID-EN too short".into()));
                }
                Ok(Duid::En {
                    enterprise_number: u32::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]),
                    identifier: payload[4..].to_vec(),
                })
            }
            3 => {
                // DUID-LL
                if payload.len() < 2 {
                    return Err(Error::Parse("DUID-LL too short".into()));
                }
                Ok(Duid::Ll {
                    hardware_type: u16::from_be_bytes([payload[0], payload[1]]),
                    link_layer_addr: payload[2..].to_vec(),
                })
            }
            4 => {
                // DUID-UUID
                if payload.len() < 16 {
                    return Err(Error::Parse("DUID-UUID too short".into()));
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&payload[0..16]);
                Ok(Duid::Uuid { uuid })
            }
            _ => Ok(Duid::Unknown {
                duid_type,
                data: payload.to_vec(),
            }),
        }
    }

    /// Serialize DUID to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Duid::Llt {
                hardware_type,
                time,
                link_layer_addr,
            } => {
                bytes.extend_from_slice(&1u16.to_be_bytes());
                bytes.extend_from_slice(&hardware_type.to_be_bytes());
                bytes.extend_from_slice(&time.to_be_bytes());
                bytes.extend_from_slice(link_layer_addr);
            }
            Duid::En {
                enterprise_number,
                identifier,
            } => {
                bytes.extend_from_slice(&2u16.to_be_bytes());
                bytes.extend_from_slice(&enterprise_number.to_be_bytes());
                bytes.extend_from_slice(identifier);
            }
            Duid::Ll {
                hardware_type,
                link_layer_addr,
            } => {
                bytes.extend_from_slice(&3u16.to_be_bytes());
                bytes.extend_from_slice(&hardware_type.to_be_bytes());
                bytes.extend_from_slice(link_layer_addr);
            }
            Duid::Uuid { uuid } => {
                bytes.extend_from_slice(&4u16.to_be_bytes());
                bytes.extend_from_slice(uuid);
            }
            Duid::Unknown { duid_type, data } => {
                bytes.extend_from_slice(&duid_type.to_be_bytes());
                bytes.extend_from_slice(data);
            }
        }
        bytes
    }
}

/// IA Address option (RFC 8415 Section 21.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaAddress {
    pub address: Ipv6Addr,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

impl IaAddress {
    /// Parse IA Address from option data
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 24 {
            return Err(Error::Parse("IA Address too short".into()));
        }

        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&data[0..16]);

        Ok(IaAddress {
            address: Ipv6Addr::from(addr_bytes),
            preferred_lifetime: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            valid_lifetime: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&self.address.octets());
        bytes.extend_from_slice(&self.preferred_lifetime.to_be_bytes());
        bytes.extend_from_slice(&self.valid_lifetime.to_be_bytes());
        bytes
    }
}

/// IA_NA option (RFC 8415 Section 21.4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaNa {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub addresses: Vec<IaAddress>,
    pub status: Option<(StatusCode, String)>,
}

impl IaNa {
    /// Parse IA_NA from option data
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(Error::Parse("IA_NA too short".into()));
        }

        let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let t1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let t2 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let mut addresses = Vec::new();
        let mut status = None;

        // Parse nested options
        let opts = &data[12..];
        let mut pos = 0;
        while pos + 4 <= opts.len() {
            let opt_code = u16::from_be_bytes([opts[pos], opts[pos + 1]]);
            let opt_len = u16::from_be_bytes([opts[pos + 2], opts[pos + 3]]) as usize;
            pos += 4;

            if pos + opt_len > opts.len() {
                break;
            }

            let opt_data = &opts[pos..pos + opt_len];
            pos += opt_len;

            match opt_code {
                options::IA_ADDR => {
                    if let Ok(addr) = IaAddress::parse(opt_data) {
                        addresses.push(addr);
                    }
                }
                options::STATUS_CODE => {
                    if opt_data.len() >= 2 {
                        let code = u16::from_be_bytes([opt_data[0], opt_data[1]]);
                        let msg = String::from_utf8_lossy(&opt_data[2..]).to_string();
                        if let Some(sc) = StatusCode::from_u16(code) {
                            status = Some((sc, msg));
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(IaNa {
            iaid,
            t1,
            t2,
            addresses,
            status,
        })
    }

    /// Serialize to bytes (without nested options for client requests)
    pub fn to_bytes_request(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.iaid.to_be_bytes());
        bytes.extend_from_slice(&self.t1.to_be_bytes());
        bytes.extend_from_slice(&self.t2.to_be_bytes());
        bytes
    }

    /// Serialize to bytes with addresses (for REQUEST after ADVERTISE)
    pub fn to_bytes_with_addresses(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.iaid.to_be_bytes());
        bytes.extend_from_slice(&self.t1.to_be_bytes());
        bytes.extend_from_slice(&self.t2.to_be_bytes());

        // Add IA_ADDR sub-options
        for addr in &self.addresses {
            let addr_bytes = addr.to_bytes();
            bytes.extend_from_slice(&options::IA_ADDR.to_be_bytes());
            bytes.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&addr_bytes);
        }

        bytes
    }
}

/// Parsed DHCPv6 header (zero-copy reference)
#[derive(Debug)]
pub struct Dhcp6Header<'a> {
    buffer: &'a [u8],
}

impl<'a> Dhcp6Header<'a> {
    /// Parse DHCPv6 message from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < MIN_PACKET_SIZE {
            return Err(Error::Parse("DHCPv6 message too short".into()));
        }

        Ok(Self { buffer })
    }

    /// Message type (1 byte)
    pub fn msg_type(&self) -> u8 {
        self.buffer[0]
    }

    /// Get typed message type
    pub fn message_type(&self) -> Option<Dhcp6MessageType> {
        Dhcp6MessageType::from_u8(self.msg_type())
    }

    /// Transaction ID (24 bits)
    pub fn transaction_id(&self) -> u32 {
        u32::from_be_bytes([0, self.buffer[1], self.buffer[2], self.buffer[3]])
    }

    /// Options section (after header)
    pub fn options_raw(&self) -> &[u8] {
        &self.buffer[DHCP6_HEADER_SIZE..]
    }

    /// Raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Find option by code, returns option data (without code and length)
    pub fn find_option(&self, code: u16) -> Option<&[u8]> {
        let opts = self.options_raw();
        let mut pos = 0;

        while pos + 4 <= opts.len() {
            let opt_code = u16::from_be_bytes([opts[pos], opts[pos + 1]]);
            let opt_len = u16::from_be_bytes([opts[pos + 2], opts[pos + 3]]) as usize;
            let data_start = pos + 4;
            let data_end = data_start + opt_len;

            if data_end > opts.len() {
                break;
            }

            if opt_code == code {
                return Some(&opts[data_start..data_end]);
            }

            pos = data_end;
        }

        None
    }

    /// Get Client ID DUID
    pub fn client_id(&self) -> Option<Duid> {
        self.find_option(options::CLIENT_ID)
            .and_then(|data| Duid::parse(data).ok())
    }

    /// Get Server ID DUID
    pub fn server_id(&self) -> Option<Duid> {
        self.find_option(options::SERVER_ID)
            .and_then(|data| Duid::parse(data).ok())
    }

    /// Get Status Code
    pub fn status_code(&self) -> Option<(StatusCode, String)> {
        self.find_option(options::STATUS_CODE).and_then(|data| {
            if data.len() >= 2 {
                let code = u16::from_be_bytes([data[0], data[1]]);
                let msg = String::from_utf8_lossy(&data[2..]).to_string();
                StatusCode::from_u16(code).map(|sc| (sc, msg))
            } else {
                None
            }
        })
    }

    /// Get Server Preference
    pub fn preference(&self) -> Option<u8> {
        self.find_option(options::PREFERENCE)
            .and_then(|data| data.first().copied())
    }

    /// Check if Rapid Commit option is present
    pub fn has_rapid_commit(&self) -> bool {
        self.find_option(options::RAPID_COMMIT).is_some()
    }

    /// Get IA_NA option
    pub fn ia_na(&self) -> Option<IaNa> {
        self.find_option(options::IA_NA)
            .and_then(|data| IaNa::parse(data).ok())
    }

    /// Get DNS servers (RFC 3646)
    pub fn dns_servers(&self) -> Vec<Ipv6Addr> {
        let mut servers = Vec::new();
        if let Some(data) = self.find_option(options::DNS_SERVERS) {
            for chunk in data.chunks_exact(16) {
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(chunk);
                servers.push(Ipv6Addr::from(addr_bytes));
            }
        }
        servers
    }

    /// Get Domain Search List (RFC 3646)
    pub fn domain_list(&self) -> Vec<String> {
        let mut domains = Vec::new();
        if let Some(data) = self.find_option(options::DOMAIN_LIST) {
            // Domain names are encoded as DNS labels
            let mut pos = 0;
            while pos < data.len() {
                let (domain, next_pos) = parse_dns_name(data, pos);
                if domain.is_empty() {
                    break;
                }
                domains.push(domain);
                pos = next_pos;
            }
        }
        domains
    }

    /// Iterate over all options
    pub fn iter_options(&self) -> Dhcp6OptionIterator<'_> {
        Dhcp6OptionIterator {
            data: self.options_raw(),
            pos: 0,
        }
    }
}

/// Parse DNS name from wire format
fn parse_dns_name(data: &[u8], start: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut pos = start;

    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if pos + 1 + len > data.len() {
            break;
        }
        if let Ok(label) = std::str::from_utf8(&data[pos + 1..pos + 1 + len]) {
            labels.push(label.to_string());
        }
        pos += 1 + len;
    }

    (labels.join("."), pos)
}

/// Iterator over DHCPv6 options
pub struct Dhcp6OptionIterator<'a> {
    data: &'a [u8],
    pos: usize,
}

/// A single DHCPv6 option
#[derive(Debug, Clone)]
pub struct Dhcp6Option<'a> {
    pub code: u16,
    pub data: &'a [u8],
}

impl<'a> Iterator for Dhcp6OptionIterator<'a> {
    type Item = Dhcp6Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.data.len() {
            return None;
        }

        let code = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        let len = u16::from_be_bytes([self.data[self.pos + 2], self.data[self.pos + 3]]) as usize;
        let data_start = self.pos + 4;
        let data_end = data_start + len;

        if data_end > self.data.len() {
            return None;
        }

        self.pos = data_end;
        Some(Dhcp6Option {
            code,
            data: &self.data[data_start..data_end],
        })
    }
}

/// DHCPv6 message builder for client messages
#[derive(Debug, Clone)]
pub struct Dhcp6Builder {
    msg_type: u8,
    transaction_id: u32,
    options: Vec<u8>,
}

impl Dhcp6Builder {
    /// Create a new builder with specified message type
    pub fn new(msg_type: Dhcp6MessageType) -> Self {
        Self {
            msg_type: msg_type as u8,
            transaction_id: 0,
            options: Vec::new(),
        }
    }

    /// Set transaction ID (only lower 24 bits used)
    pub fn transaction_id(mut self, xid: u32) -> Self {
        self.transaction_id = xid & 0x00FFFFFF;
        self
    }

    /// Add Client ID option
    pub fn client_id(mut self, duid: &Duid) -> Self {
        let data = duid.to_bytes();
        self.add_option(options::CLIENT_ID, &data);
        self
    }

    /// Add Server ID option
    pub fn server_id(mut self, duid: &Duid) -> Self {
        let data = duid.to_bytes();
        self.add_option(options::SERVER_ID, &data);
        self
    }

    /// Add IA_NA option (request address assignment)
    pub fn ia_na(mut self, iaid: u32, t1: u32, t2: u32) -> Self {
        let ia = IaNa {
            iaid,
            t1,
            t2,
            addresses: Vec::new(),
            status: None,
        };
        self.add_option(options::IA_NA, &ia.to_bytes_request());
        self
    }

    /// Add IA_NA option with addresses (for REQUEST/RENEW/REBIND)
    pub fn ia_na_with_addresses(mut self, ia_na: &IaNa) -> Self {
        self.add_option(options::IA_NA, &ia_na.to_bytes_with_addresses());
        self
    }

    /// Add Option Request Option (ORO)
    pub fn option_request(mut self, options: &[u16]) -> Self {
        let mut data = Vec::with_capacity(options.len() * 2);
        for opt in options {
            data.extend_from_slice(&opt.to_be_bytes());
        }
        self.add_option(options::ORO, &data);
        self
    }

    /// Add Elapsed Time option
    pub fn elapsed_time(mut self, centiseconds: u16) -> Self {
        self.add_option(options::ELAPSED_TIME, &centiseconds.to_be_bytes());
        self
    }

    /// Add Rapid Commit option
    pub fn rapid_commit(mut self) -> Self {
        self.add_option(options::RAPID_COMMIT, &[]);
        self
    }

    /// Add raw option
    fn add_option(&mut self, code: u16, data: &[u8]) {
        self.options.extend_from_slice(&code.to_be_bytes());
        self.options
            .extend_from_slice(&(data.len() as u16).to_be_bytes());
        self.options.extend_from_slice(data);
    }

    /// Build the DHCPv6 message
    pub fn build(self) -> Vec<u8> {
        let total_len = DHCP6_HEADER_SIZE + self.options.len();
        let mut buffer = Vec::with_capacity(total_len);

        // Header
        buffer.push(self.msg_type);
        let xid_bytes = self.transaction_id.to_be_bytes();
        buffer.extend_from_slice(&xid_bytes[1..4]); // Only lower 24 bits

        // Options
        buffer.extend_from_slice(&self.options);

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_solicit_packet(xid: u32, client_duid: &Duid) -> Vec<u8> {
        Dhcp6Builder::new(Dhcp6MessageType::Solicit)
            .transaction_id(xid)
            .client_id(client_duid)
            .ia_na(1, 0, 0)
            .elapsed_time(0)
            .option_request(&[options::DNS_SERVERS, options::DOMAIN_LIST])
            .build()
    }

    fn make_advertise_packet(
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
        packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder for length
        packet.extend_from_slice(&1u32.to_be_bytes()); // IAID
        packet.extend_from_slice(&3600u32.to_be_bytes()); // T1
        packet.extend_from_slice(&5400u32.to_be_bytes()); // T2

        // IA_ADDR sub-option
        packet.extend_from_slice(&options::IA_ADDR.to_be_bytes());
        packet.extend_from_slice(&24u16.to_be_bytes()); // IA_ADDR length
        packet.extend_from_slice(&address.octets());
        packet.extend_from_slice(&7200u32.to_be_bytes()); // preferred lifetime
        packet.extend_from_slice(&7200u32.to_be_bytes()); // valid lifetime

        // Update IA_NA length
        let ia_na_len = packet.len() - ia_na_start - 4;
        packet[ia_na_start + 2..ia_na_start + 4].copy_from_slice(&(ia_na_len as u16).to_be_bytes());

        // Preference
        packet.extend_from_slice(&options::PREFERENCE.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.push(255); // max preference

        packet
    }

    #[test]
    fn test_duid_ll_roundtrip() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let duid = Duid::from_mac(&mac);
        let bytes = duid.to_bytes();
        let parsed = Duid::parse(&bytes).unwrap();
        assert_eq!(duid, parsed);
    }

    #[test]
    fn test_duid_llt_roundtrip() {
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let duid = Duid::from_mac_with_time(&mac, 12345678);
        let bytes = duid.to_bytes();
        let parsed = Duid::parse(&bytes).unwrap();
        assert_eq!(duid, parsed);
    }

    #[test]
    fn test_parse_solicit() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let duid = Duid::from_mac(&mac);
        let packet = make_solicit_packet(0x123456, &duid);

        let header = Dhcp6Header::parse(&packet).unwrap();
        assert_eq!(header.message_type(), Some(Dhcp6MessageType::Solicit));
        assert_eq!(header.transaction_id(), 0x123456);
        assert_eq!(header.client_id(), Some(duid));
    }

    #[test]
    fn test_parse_advertise() {
        let client_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let server_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let client_duid = Duid::from_mac(&client_mac);
        let server_duid = Duid::from_mac(&server_mac);
        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let packet = make_advertise_packet(0xABCDEF, &client_duid, &server_duid, address);

        let header = Dhcp6Header::parse(&packet).unwrap();
        assert_eq!(header.message_type(), Some(Dhcp6MessageType::Advertise));
        assert_eq!(header.transaction_id(), 0xABCDEF);
        assert_eq!(header.client_id(), Some(client_duid));
        assert_eq!(header.server_id(), Some(server_duid));
        assert_eq!(header.preference(), Some(255));

        let ia_na = header.ia_na().unwrap();
        assert_eq!(ia_na.iaid, 1);
        assert_eq!(ia_na.t1, 3600);
        assert_eq!(ia_na.t2, 5400);
        assert_eq!(ia_na.addresses.len(), 1);
        assert_eq!(ia_na.addresses[0].address, address);
    }

    #[test]
    fn test_parse_too_short() {
        let packet = vec![0u8; 2];
        assert!(Dhcp6Header::parse(&packet).is_err());
    }

    #[test]
    fn test_option_iterator() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let duid = Duid::from_mac(&mac);
        let packet = make_solicit_packet(0x123456, &duid);

        let header = Dhcp6Header::parse(&packet).unwrap();
        let options: Vec<_> = header.iter_options().collect();

        // CLIENT_ID, IA_NA, ELAPSED_TIME, ORO
        assert_eq!(options.len(), 4);
        assert_eq!(options[0].code, options::CLIENT_ID);
        assert_eq!(options[1].code, options::IA_NA);
        assert_eq!(options[2].code, options::ELAPSED_TIME);
        assert_eq!(options[3].code, options::ORO);
    }

    #[test]
    fn test_build_request() {
        let client_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let server_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let client_duid = Duid::from_mac(&client_mac);
        let server_duid = Duid::from_mac(&server_mac);

        let ia_na = IaNa {
            iaid: 1,
            t1: 0,
            t2: 0,
            addresses: vec![IaAddress {
                address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                preferred_lifetime: 7200,
                valid_lifetime: 7200,
            }],
            status: None,
        };

        let packet = Dhcp6Builder::new(Dhcp6MessageType::Request)
            .transaction_id(0x123456)
            .client_id(&client_duid)
            .server_id(&server_duid)
            .ia_na_with_addresses(&ia_na)
            .elapsed_time(100)
            .build();

        let header = Dhcp6Header::parse(&packet).unwrap();
        assert_eq!(header.message_type(), Some(Dhcp6MessageType::Request));
        assert_eq!(header.transaction_id(), 0x123456);
        assert_eq!(header.client_id(), Some(client_duid));
        assert_eq!(header.server_id(), Some(server_duid));

        let parsed_ia = header.ia_na().unwrap();
        assert_eq!(parsed_ia.addresses.len(), 1);
        assert_eq!(
            parsed_ia.addresses[0].address,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
        );
    }

    #[test]
    fn test_rapid_commit() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let duid = Duid::from_mac(&mac);

        let packet = Dhcp6Builder::new(Dhcp6MessageType::Solicit)
            .transaction_id(0x123456)
            .client_id(&duid)
            .ia_na(1, 0, 0)
            .rapid_commit()
            .build();

        let header = Dhcp6Header::parse(&packet).unwrap();
        assert!(header.has_rapid_commit());
    }

    #[test]
    fn test_transaction_id_24bit() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let duid = Duid::from_mac(&mac);

        // Test that only lower 24 bits are used
        let packet = Dhcp6Builder::new(Dhcp6MessageType::Solicit)
            .transaction_id(0xFFABCDEF) // Upper 8 bits should be ignored
            .client_id(&duid)
            .build();

        let header = Dhcp6Header::parse(&packet).unwrap();
        assert_eq!(header.transaction_id(), 0xABCDEF);
    }

    #[test]
    fn test_dns_servers() {
        let mut packet = Vec::new();
        packet.push(Dhcp6MessageType::Reply as u8);
        packet.extend_from_slice(&[0x12, 0x34, 0x56]); // xid

        // DNS Servers option
        let dns1 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let dns2 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844);

        packet.extend_from_slice(&options::DNS_SERVERS.to_be_bytes());
        packet.extend_from_slice(&32u16.to_be_bytes()); // 2 * 16 bytes
        packet.extend_from_slice(&dns1.octets());
        packet.extend_from_slice(&dns2.octets());

        let header = Dhcp6Header::parse(&packet).unwrap();
        let servers = header.dns_servers();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], dns1);
        assert_eq!(servers[1], dns2);
    }

    #[test]
    fn test_ia_address_roundtrip() {
        let addr = IaAddress {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        };

        let bytes = addr.to_bytes();
        let parsed = IaAddress::parse(&bytes).unwrap();
        assert_eq!(addr, parsed);
    }
}

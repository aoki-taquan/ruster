//! DHCP protocol - RFC 2131, 2132
//!
//! DHCPv4 message parsing and building for DHCP server functionality.

use crate::{Error, Result};
use std::net::Ipv4Addr;

/// DHCP server port (bootps)
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port (bootpc)
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Fixed header size (before options)
pub const DHCP_HEADER_SIZE: usize = 236;

/// Magic cookie marking start of options
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Minimum packet size (header + magic cookie + end option)
pub const MIN_PACKET_SIZE: usize = DHCP_HEADER_SIZE + 4 + 1;

/// BOOTP operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootpOp {
    Request = 1,
    Reply = 2,
}

impl BootpOp {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(BootpOp::Request),
            2 => Some(BootpOp::Reply),
            _ => None,
        }
    }
}

/// DHCP message types (Option 53)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl DhcpMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DhcpMessageType::Discover),
            2 => Some(DhcpMessageType::Offer),
            3 => Some(DhcpMessageType::Request),
            4 => Some(DhcpMessageType::Decline),
            5 => Some(DhcpMessageType::Ack),
            6 => Some(DhcpMessageType::Nak),
            7 => Some(DhcpMessageType::Release),
            8 => Some(DhcpMessageType::Inform),
            _ => None,
        }
    }
}

/// DHCP option codes
pub mod options {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS_SERVER: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const BROADCAST_ADDR: u8 = 28;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_REQUEST: u8 = 55;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const CLIENT_ID: u8 = 61;
    pub const END: u8 = 255;
}

/// Parsed DHCP header (zero-copy reference)
#[derive(Debug)]
pub struct DhcpHeader<'a> {
    buffer: &'a [u8],
}

impl<'a> DhcpHeader<'a> {
    /// Parse DHCP message from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < MIN_PACKET_SIZE {
            return Err(Error::Parse("DHCP message too short".into()));
        }

        // Verify magic cookie
        let cookie = &buffer[236..240];
        if cookie != MAGIC_COOKIE {
            return Err(Error::Parse("Invalid DHCP magic cookie".into()));
        }

        Ok(Self { buffer })
    }

    /// Operation code (1=request, 2=reply)
    pub fn op(&self) -> u8 {
        self.buffer[0]
    }

    /// Hardware type (1=Ethernet)
    pub fn htype(&self) -> u8 {
        self.buffer[1]
    }

    /// Hardware address length (6 for Ethernet)
    pub fn hlen(&self) -> u8 {
        self.buffer[2]
    }

    /// Hop count
    pub fn hops(&self) -> u8 {
        self.buffer[3]
    }

    /// Transaction ID
    pub fn xid(&self) -> u32 {
        u32::from_be_bytes([
            self.buffer[4],
            self.buffer[5],
            self.buffer[6],
            self.buffer[7],
        ])
    }

    /// Seconds elapsed since client began acquisition/renewal
    pub fn secs(&self) -> u16 {
        u16::from_be_bytes([self.buffer[8], self.buffer[9]])
    }

    /// Flags (bit 15 = broadcast)
    pub fn flags(&self) -> u16 {
        u16::from_be_bytes([self.buffer[10], self.buffer[11]])
    }

    /// Is broadcast flag set?
    pub fn is_broadcast(&self) -> bool {
        self.flags() & 0x8000 != 0
    }

    /// Client IP address (ciaddr)
    pub fn ciaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[12],
            self.buffer[13],
            self.buffer[14],
            self.buffer[15],
        )
    }

    /// Your IP address (yiaddr) - assigned to client
    pub fn yiaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[16],
            self.buffer[17],
            self.buffer[18],
            self.buffer[19],
        )
    }

    /// Server IP address (siaddr)
    pub fn siaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[20],
            self.buffer[21],
            self.buffer[22],
            self.buffer[23],
        )
    }

    /// Gateway IP address (giaddr) - relay agent
    pub fn giaddr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[24],
            self.buffer[25],
            self.buffer[26],
            self.buffer[27],
        )
    }

    /// Client hardware address (chaddr) - first 16 bytes
    pub fn chaddr(&self) -> &[u8] {
        &self.buffer[28..44]
    }

    /// Client MAC address (first 6 bytes of chaddr for Ethernet)
    pub fn client_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.buffer[28..34]);
        mac
    }

    /// Server hostname (sname) - 64 bytes
    pub fn sname(&self) -> &[u8] {
        &self.buffer[44..108]
    }

    /// Boot filename (file) - 128 bytes
    pub fn file(&self) -> &[u8] {
        &self.buffer[108..236]
    }

    /// Options section (after magic cookie)
    pub fn options_raw(&self) -> &[u8] {
        &self.buffer[240..]
    }

    /// Raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Get DHCP message type from options
    pub fn message_type(&self) -> Option<DhcpMessageType> {
        self.find_option(options::MESSAGE_TYPE)
            .and_then(|data| data.first().copied())
            .and_then(DhcpMessageType::from_u8)
    }

    /// Get requested IP address from options (Option 50)
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.find_option(options::REQUESTED_IP).and_then(|data| {
            if data.len() >= 4 {
                Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            } else {
                None
            }
        })
    }

    /// Get server identifier from options (Option 54)
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.find_option(options::SERVER_ID).and_then(|data| {
            if data.len() >= 4 {
                Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            } else {
                None
            }
        })
    }

    /// Get client identifier from options (Option 61)
    pub fn client_id(&self) -> Option<&[u8]> {
        self.find_option(options::CLIENT_ID)
    }

    /// Get hostname from options (Option 12)
    pub fn hostname(&self) -> Option<&str> {
        self.find_option(options::HOSTNAME)
            .and_then(|data| std::str::from_utf8(data).ok())
    }

    /// Get parameter request list from options (Option 55)
    pub fn parameter_request_list(&self) -> Option<&[u8]> {
        self.find_option(options::PARAMETER_REQUEST)
    }

    /// Find option by code, returns option data (without code and length)
    fn find_option(&self, code: u8) -> Option<&[u8]> {
        let opts = self.options_raw();
        let mut i = 0;

        while i < opts.len() {
            let opt_code = opts[i];

            // Handle special options
            if opt_code == options::PAD {
                i += 1;
                continue;
            }
            if opt_code == options::END {
                break;
            }

            // Regular option: code + length + data
            if i + 1 >= opts.len() {
                break;
            }
            let opt_len = opts[i + 1] as usize;
            let data_start = i + 2;
            let data_end = data_start + opt_len;

            if data_end > opts.len() {
                break;
            }

            if opt_code == code {
                return Some(&opts[data_start..data_end]);
            }

            i = data_end;
        }

        None
    }

    /// Iterate over all options
    pub fn iter_options(&self) -> DhcpOptionIterator<'_> {
        DhcpOptionIterator {
            data: self.options_raw(),
            pos: 0,
        }
    }
}

/// Iterator over DHCP options
pub struct DhcpOptionIterator<'a> {
    data: &'a [u8],
    pos: usize,
}

/// A single DHCP option
#[derive(Debug, Clone)]
pub struct DhcpOption<'a> {
    pub code: u8,
    pub data: &'a [u8],
}

impl<'a> Iterator for DhcpOptionIterator<'a> {
    type Item = DhcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.data.len() {
            let code = self.data[self.pos];

            if code == options::PAD {
                self.pos += 1;
                continue;
            }
            if code == options::END {
                return None;
            }

            if self.pos + 1 >= self.data.len() {
                return None;
            }
            let len = self.data[self.pos + 1] as usize;
            let data_start = self.pos + 2;
            let data_end = data_start + len;

            if data_end > self.data.len() {
                return None;
            }

            self.pos = data_end;
            return Some(DhcpOption {
                code,
                data: &self.data[data_start..data_end],
            });
        }
        None
    }
}

/// DHCP message builder for server responses
#[derive(Debug, Clone)]
pub struct DhcpBuilder {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    options: Vec<u8>,
}

impl DhcpBuilder {
    /// Create a new builder for a DHCP reply based on a request
    pub fn reply(request: &DhcpHeader) -> Self {
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(request.chaddr());

        Self {
            op: BootpOp::Reply as u8,
            htype: request.htype(),
            hlen: request.hlen(),
            hops: 0,
            xid: request.xid(),
            secs: 0,
            flags: request.flags(),
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: request.giaddr(),
            chaddr,
            options: Vec::new(),
        }
    }

    /// Create a new empty builder
    pub fn new() -> Self {
        Self {
            op: BootpOp::Reply as u8,
            htype: 1, // Ethernet
            hlen: 6,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; 16],
            options: Vec::new(),
        }
    }

    /// Set DHCP message type
    pub fn message_type(mut self, msg_type: DhcpMessageType) -> Self {
        self.add_option(options::MESSAGE_TYPE, &[msg_type as u8]);
        self
    }

    /// Set assigned IP address (yiaddr)
    pub fn yiaddr(mut self, ip: Ipv4Addr) -> Self {
        self.yiaddr = ip;
        self
    }

    /// Set server IP address (siaddr)
    pub fn siaddr(mut self, ip: Ipv4Addr) -> Self {
        self.siaddr = ip;
        self
    }

    /// Set server identifier (Option 54)
    pub fn server_id(mut self, ip: Ipv4Addr) -> Self {
        self.add_option(options::SERVER_ID, &ip.octets());
        self
    }

    /// Set subnet mask (Option 1)
    pub fn subnet_mask(mut self, mask: Ipv4Addr) -> Self {
        self.add_option(options::SUBNET_MASK, &mask.octets());
        self
    }

    /// Set router/gateway (Option 3)
    pub fn router(mut self, routers: &[Ipv4Addr]) -> Self {
        let mut data = Vec::new();
        for r in routers {
            data.extend_from_slice(&r.octets());
        }
        self.add_option(options::ROUTER, &data);
        self
    }

    /// Set DNS servers (Option 6)
    pub fn dns(mut self, servers: &[Ipv4Addr]) -> Self {
        let mut data = Vec::new();
        for s in servers {
            data.extend_from_slice(&s.octets());
        }
        self.add_option(options::DNS_SERVER, &data);
        self
    }

    /// Set broadcast address (Option 28)
    pub fn broadcast_addr(mut self, addr: Ipv4Addr) -> Self {
        self.add_option(options::BROADCAST_ADDR, &addr.octets());
        self
    }

    /// Set lease time in seconds (Option 51)
    pub fn lease_time(mut self, seconds: u32) -> Self {
        self.add_option(options::LEASE_TIME, &seconds.to_be_bytes());
        self
    }

    /// Set renewal time T1 in seconds (Option 58)
    pub fn renewal_time(mut self, seconds: u32) -> Self {
        self.add_option(options::RENEWAL_TIME, &seconds.to_be_bytes());
        self
    }

    /// Set rebinding time T2 in seconds (Option 59)
    pub fn rebinding_time(mut self, seconds: u32) -> Self {
        self.add_option(options::REBINDING_TIME, &seconds.to_be_bytes());
        self
    }

    /// Set domain name (Option 15)
    pub fn domain_name(mut self, domain: &str) -> Self {
        self.add_option(options::DOMAIN_NAME, domain.as_bytes());
        self
    }

    /// Add raw option
    fn add_option(&mut self, code: u8, data: &[u8]) {
        self.options.push(code);
        self.options.push(data.len() as u8);
        self.options.extend_from_slice(data);
    }

    /// Build the DHCP packet
    pub fn build(mut self) -> Vec<u8> {
        // Add END option
        self.options.push(options::END);

        // Calculate total size (header + magic cookie + options)
        // Pad to minimum 300 bytes for compatibility
        let options_len = self.options.len();
        let total_len = DHCP_HEADER_SIZE + 4 + options_len;
        let padded_len = total_len.max(300);

        let mut buffer = vec![0u8; padded_len];

        // Fixed header
        buffer[0] = self.op;
        buffer[1] = self.htype;
        buffer[2] = self.hlen;
        buffer[3] = self.hops;
        buffer[4..8].copy_from_slice(&self.xid.to_be_bytes());
        buffer[8..10].copy_from_slice(&self.secs.to_be_bytes());
        buffer[10..12].copy_from_slice(&self.flags.to_be_bytes());
        buffer[12..16].copy_from_slice(&self.ciaddr.octets());
        buffer[16..20].copy_from_slice(&self.yiaddr.octets());
        buffer[20..24].copy_from_slice(&self.siaddr.octets());
        buffer[24..28].copy_from_slice(&self.giaddr.octets());
        buffer[28..44].copy_from_slice(&self.chaddr);
        // sname and file are left as zeros

        // Magic cookie
        buffer[236..240].copy_from_slice(&MAGIC_COOKIE);

        // Options
        buffer[240..240 + options_len].copy_from_slice(&self.options);

        buffer
    }
}

impl Default for DhcpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_discover_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 300];

        // BOOTP header
        packet[0] = 1; // op = BOOTREQUEST
        packet[1] = 1; // htype = Ethernet
        packet[2] = 6; // hlen = 6
        packet[3] = 0; // hops

        // xid = 0x12345678
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());

        // flags = 0x8000 (broadcast)
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());

        // chaddr = 00:11:22:33:44:55
        packet[28] = 0x00;
        packet[29] = 0x11;
        packet[30] = 0x22;
        packet[31] = 0x33;
        packet[32] = 0x44;
        packet[33] = 0x55;

        // Magic cookie
        packet[236..240].copy_from_slice(&MAGIC_COOKIE);

        // Options
        // Message Type = DISCOVER (53, 1, 1)
        packet[240] = 53;
        packet[241] = 1;
        packet[242] = 1;

        // Parameter Request List (55, 4, 1, 3, 6, 15)
        packet[243] = 55;
        packet[244] = 4;
        packet[245] = 1; // subnet mask
        packet[246] = 3; // router
        packet[247] = 6; // dns
        packet[248] = 15; // domain name

        // End
        packet[249] = 255;

        packet
    }

    fn make_request_packet(requested_ip: Ipv4Addr, server_id: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 300];

        packet[0] = 1; // op = BOOTREQUEST
        packet[1] = 1; // htype = Ethernet
        packet[2] = 6; // hlen = 6

        // xid = 0xABCDEF00
        packet[4..8].copy_from_slice(&0xABCDEF00u32.to_be_bytes());

        // chaddr
        packet[28..34].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // Magic cookie
        packet[236..240].copy_from_slice(&MAGIC_COOKIE);

        // Options
        let mut pos = 240;

        // Message Type = REQUEST (53, 1, 3)
        packet[pos] = 53;
        packet[pos + 1] = 1;
        packet[pos + 2] = 3;
        pos += 3;

        // Requested IP (50, 4, ip)
        packet[pos] = 50;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&requested_ip.octets());
        pos += 6;

        // Server ID (54, 4, ip)
        packet[pos] = 54;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&server_id.octets());
        pos += 6;

        // End
        packet[pos] = 255;

        packet
    }

    #[test]
    fn test_parse_discover() {
        let packet = make_discover_packet();
        let header = DhcpHeader::parse(&packet).unwrap();

        assert_eq!(header.op(), 1);
        assert_eq!(header.htype(), 1);
        assert_eq!(header.hlen(), 6);
        assert_eq!(header.xid(), 0x12345678);
        assert!(header.is_broadcast());
        assert_eq!(header.client_mac(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(header.message_type(), Some(DhcpMessageType::Discover));
    }

    #[test]
    fn test_parse_request() {
        let requested = Ipv4Addr::new(192, 168, 1, 100);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let packet = make_request_packet(requested, server);
        let header = DhcpHeader::parse(&packet).unwrap();

        assert_eq!(header.message_type(), Some(DhcpMessageType::Request));
        assert_eq!(header.requested_ip(), Some(requested));
        assert_eq!(header.server_id(), Some(server));
        assert_eq!(header.client_mac(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_too_short() {
        let packet = vec![0u8; 100];
        assert!(DhcpHeader::parse(&packet).is_err());
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut packet = vec![0u8; 300];
        packet[236..240].copy_from_slice(&[0, 0, 0, 0]); // Invalid magic
        assert!(DhcpHeader::parse(&packet).is_err());
    }

    #[test]
    fn test_option_iterator() {
        let packet = make_discover_packet();
        let header = DhcpHeader::parse(&packet).unwrap();

        let options: Vec<_> = header.iter_options().collect();
        assert_eq!(options.len(), 2); // MESSAGE_TYPE and PARAMETER_REQUEST

        assert_eq!(options[0].code, 53);
        assert_eq!(options[0].data, &[1]);

        assert_eq!(options[1].code, 55);
        assert_eq!(options[1].data, &[1, 3, 6, 15]);
    }

    #[test]
    fn test_build_offer() {
        let discover = make_discover_packet();
        let request = DhcpHeader::parse(&discover).unwrap();

        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let offer_ip = Ipv4Addr::new(192, 168, 1, 100);
        let subnet = Ipv4Addr::new(255, 255, 255, 0);
        let dns = vec![Ipv4Addr::new(8, 8, 8, 8)];

        let offer = DhcpBuilder::reply(&request)
            .message_type(DhcpMessageType::Offer)
            .yiaddr(offer_ip)
            .siaddr(server_ip)
            .server_id(server_ip)
            .subnet_mask(subnet)
            .router(&[server_ip])
            .dns(&dns)
            .lease_time(86400)
            .build();

        // Parse and verify
        let header = DhcpHeader::parse(&offer).unwrap();
        assert_eq!(header.op(), 2); // BOOTREPLY
        assert_eq!(header.xid(), 0x12345678);
        assert_eq!(header.yiaddr(), offer_ip);
        assert_eq!(header.siaddr(), server_ip);
        assert_eq!(header.message_type(), Some(DhcpMessageType::Offer));
        assert_eq!(header.server_id(), Some(server_ip));
        assert!(header.is_broadcast()); // Preserved from request
    }

    #[test]
    fn test_build_ack() {
        let request_ip = Ipv4Addr::new(192, 168, 1, 100);
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let request = make_request_packet(request_ip, server_ip);
        let req_header = DhcpHeader::parse(&request).unwrap();

        let ack = DhcpBuilder::reply(&req_header)
            .message_type(DhcpMessageType::Ack)
            .yiaddr(request_ip)
            .siaddr(server_ip)
            .server_id(server_ip)
            .subnet_mask(Ipv4Addr::new(255, 255, 255, 0))
            .router(&[server_ip])
            .lease_time(86400)
            .renewal_time(43200)
            .rebinding_time(75600)
            .build();

        let header = DhcpHeader::parse(&ack).unwrap();
        assert_eq!(header.op(), 2);
        assert_eq!(header.message_type(), Some(DhcpMessageType::Ack));
        assert_eq!(header.yiaddr(), request_ip);
    }

    #[test]
    fn test_build_nak() {
        let request_ip = Ipv4Addr::new(192, 168, 1, 100);
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let request = make_request_packet(request_ip, server_ip);
        let req_header = DhcpHeader::parse(&request).unwrap();

        let nak = DhcpBuilder::reply(&req_header)
            .message_type(DhcpMessageType::Nak)
            .server_id(server_ip)
            .build();

        let header = DhcpHeader::parse(&nak).unwrap();
        assert_eq!(header.message_type(), Some(DhcpMessageType::Nak));
        assert_eq!(header.yiaddr(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_parameter_request_list() {
        let packet = make_discover_packet();
        let header = DhcpHeader::parse(&packet).unwrap();

        let params = header.parameter_request_list().unwrap();
        assert_eq!(params, &[1, 3, 6, 15]);
    }

    #[test]
    fn test_roundtrip() {
        let original = make_discover_packet();
        let header = DhcpHeader::parse(&original).unwrap();

        // Build a reply
        let reply = DhcpBuilder::reply(&header)
            .message_type(DhcpMessageType::Offer)
            .yiaddr(Ipv4Addr::new(10, 0, 0, 100))
            .build();

        // Parse the reply
        let reply_header = DhcpHeader::parse(&reply).unwrap();

        // Verify xid and chaddr are preserved
        assert_eq!(reply_header.xid(), header.xid());
        assert_eq!(reply_header.chaddr(), header.chaddr());
    }
}

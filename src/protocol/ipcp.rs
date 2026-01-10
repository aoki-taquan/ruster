//! IPCP protocol - RFC 1332
//!
//! Internet Protocol Control Protocol for negotiating IPv4 parameters.

use crate::{Error, Result};
use std::net::Ipv4Addr;

/// IPCP header size (code + identifier + length)
pub const IPCP_HEADER_SIZE: usize = 4;

/// IPCP packet codes (same as LCP)
pub mod codes {
    /// Configure-Request
    pub const CONFIGURE_REQUEST: u8 = 1;
    /// Configure-Ack
    pub const CONFIGURE_ACK: u8 = 2;
    /// Configure-Nak
    pub const CONFIGURE_NAK: u8 = 3;
    /// Configure-Reject
    pub const CONFIGURE_REJECT: u8 = 4;
    /// Terminate-Request
    pub const TERMINATE_REQUEST: u8 = 5;
    /// Terminate-Ack
    pub const TERMINATE_ACK: u8 = 6;
    /// Code-Reject
    pub const CODE_REJECT: u8 = 7;
}

/// IPCP option types
pub mod options {
    /// IP-Addresses (deprecated, RFC 1172)
    pub const IP_ADDRESSES: u8 = 1;
    /// IP-Compression-Protocol
    pub const IP_COMPRESSION: u8 = 2;
    /// IP-Address
    pub const IP_ADDRESS: u8 = 3;
    /// Primary DNS Server Address (Microsoft extension)
    pub const PRIMARY_DNS: u8 = 129;
    /// Primary NBNS Server Address (Microsoft extension)
    pub const PRIMARY_NBNS: u8 = 130;
    /// Secondary DNS Server Address (Microsoft extension)
    pub const SECONDARY_DNS: u8 = 131;
    /// Secondary NBNS Server Address (Microsoft extension)
    pub const SECONDARY_NBNS: u8 = 132;
}

/// Parsed IPCP packet (zero-copy reference)
#[derive(Debug)]
pub struct IpcpPacket<'a> {
    buffer: &'a [u8],
}

impl<'a> IpcpPacket<'a> {
    /// Parse IPCP packet from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < IPCP_HEADER_SIZE {
            return Err(Error::Parse("IPCP packet too short".into()));
        }

        let packet = Self { buffer };

        let length = packet.length() as usize;
        if length < IPCP_HEADER_SIZE {
            return Err(Error::Parse("IPCP length too small".into()));
        }
        if buffer.len() < length {
            return Err(Error::Parse("IPCP packet truncated".into()));
        }

        Ok(packet)
    }

    /// Code field
    pub fn code(&self) -> u8 {
        self.buffer[0]
    }

    /// Identifier field
    pub fn identifier(&self) -> u8 {
        self.buffer[1]
    }

    /// Length field
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Data (options)
    pub fn data(&self) -> &[u8] {
        let len = self.length() as usize;
        &self.buffer[IPCP_HEADER_SIZE..len]
    }

    /// Iterate over options
    pub fn iter_options(&self) -> IpcpOptionIterator<'_> {
        IpcpOptionIterator {
            data: self.data(),
            offset: 0,
        }
    }

    /// Find a specific option by type
    pub fn find_option(&self, opt_type: u8) -> Option<&[u8]> {
        for opt in self.iter_options() {
            if opt.opt_type == opt_type {
                return Some(opt.data);
            }
        }
        None
    }

    /// Get IP-Address option as Ipv4Addr
    pub fn ip_address(&self) -> Option<Ipv4Addr> {
        self.find_option_ip(options::IP_ADDRESS)
    }

    /// Get Primary-DNS option as Ipv4Addr
    pub fn primary_dns(&self) -> Option<Ipv4Addr> {
        self.find_option_ip(options::PRIMARY_DNS)
    }

    /// Get Secondary-DNS option as Ipv4Addr
    pub fn secondary_dns(&self) -> Option<Ipv4Addr> {
        self.find_option_ip(options::SECONDARY_DNS)
    }

    /// Helper to extract IPv4 address from option
    pub fn find_option_ip(&self, opt_type: u8) -> Option<Ipv4Addr> {
        self.find_option(opt_type).and_then(|data| {
            if data.len() >= 4 {
                Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            } else {
                None
            }
        })
    }

    /// Get the raw buffer
    pub fn as_bytes(&self) -> &[u8] {
        let len = self.length() as usize;
        &self.buffer[..len]
    }
}

/// An IPCP option during iteration
#[derive(Debug, Clone)]
pub struct IpcpOption<'a> {
    /// Option type
    pub opt_type: u8,
    /// Option data (excluding type and length bytes)
    pub data: &'a [u8],
}

/// Iterator over IPCP options
pub struct IpcpOptionIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for IpcpOptionIterator<'a> {
    type Item = IpcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + 2 > self.data.len() {
            return None;
        }

        let opt_type = self.data[self.offset];
        let opt_len = self.data[self.offset + 1] as usize;

        if opt_len < 2 || self.offset + opt_len > self.data.len() {
            return None;
        }

        let data_start = self.offset + 2;
        let data_end = self.offset + opt_len;

        let opt = IpcpOption {
            opt_type,
            data: &self.data[data_start..data_end],
        };

        self.offset = data_end;
        Some(opt)
    }
}

/// Builder for IPCP packets
#[derive(Debug, Default)]
pub struct IpcpBuilder {
    code: u8,
    identifier: u8,
    data: Vec<u8>,
}

impl IpcpBuilder {
    /// Create a new IPCP packet builder
    pub fn new(code: u8, identifier: u8) -> Self {
        Self {
            code,
            identifier,
            data: Vec::new(),
        }
    }

    /// Create Configure-Request builder
    pub fn configure_request(identifier: u8) -> Self {
        Self::new(codes::CONFIGURE_REQUEST, identifier)
    }

    /// Create Configure-Ack builder
    pub fn configure_ack(identifier: u8) -> Self {
        Self::new(codes::CONFIGURE_ACK, identifier)
    }

    /// Create Configure-Nak builder
    pub fn configure_nak(identifier: u8) -> Self {
        Self::new(codes::CONFIGURE_NAK, identifier)
    }

    /// Create Configure-Reject builder
    pub fn configure_reject(identifier: u8) -> Self {
        Self::new(codes::CONFIGURE_REJECT, identifier)
    }

    /// Add a raw option
    pub fn add_option(mut self, opt_type: u8, data: &[u8]) -> Self {
        let opt_len = (2 + data.len()) as u8;
        self.data.push(opt_type);
        self.data.push(opt_len);
        self.data.extend_from_slice(data);
        self
    }

    /// Add IP-Address option
    pub fn ip_address(self, ip: Ipv4Addr) -> Self {
        self.add_option(options::IP_ADDRESS, &ip.octets())
    }

    /// Add Primary-DNS option
    pub fn primary_dns(self, ip: Ipv4Addr) -> Self {
        self.add_option(options::PRIMARY_DNS, &ip.octets())
    }

    /// Add Secondary-DNS option
    pub fn secondary_dns(self, ip: Ipv4Addr) -> Self {
        self.add_option(options::SECONDARY_DNS, &ip.octets())
    }

    /// Set raw data (for copying options in Ack)
    pub fn raw_data(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Build the IPCP packet
    pub fn build(self) -> Vec<u8> {
        let length = (IPCP_HEADER_SIZE + self.data.len()) as u16;
        let mut packet = Vec::with_capacity(length as usize);

        packet.push(self.code);
        packet.push(self.identifier);
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&self.data);

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_configure_request() {
        // IPCP Configure-Request with IP=0.0.0.0 (request assignment)
        let data = [
            0x01, // Code: Configure-Request
            0x01, // Identifier
            0x00, 0x0a, // Length=10
            // IP-Address option
            0x03, 0x06, // Type=3, Length=6
            0x00, 0x00, 0x00, 0x00, // IP=0.0.0.0
        ];

        let packet = IpcpPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::CONFIGURE_REQUEST);
        assert_eq!(packet.identifier(), 1);
        assert_eq!(packet.ip_address(), Some(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_parse_configure_nak_with_ip() {
        // IPCP Configure-Nak with suggested IP
        let data = [
            0x03, // Code: Configure-Nak
            0x01, // Identifier
            0x00, 0x0a, // Length=10
            // IP-Address option
            0x03, 0x06, // Type=3, Length=6
            0xc0, 0xa8, 0x01, 0x64, // IP=192.168.1.100
        ];

        let packet = IpcpPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::CONFIGURE_NAK);
        assert_eq!(packet.ip_address(), Some(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_parse_with_dns() {
        // IPCP Configure-Request with IP and DNS options
        let data = [
            0x01, // Code: Configure-Request
            0x01, // Identifier
            0x00, 0x16, // Length=22
            // IP-Address option
            0x03, 0x06, 0x00, 0x00, 0x00, 0x00, // Primary DNS
            0x81, 0x06, 0x00, 0x00, 0x00, 0x00, // Secondary DNS
            0x83, 0x06, 0x00, 0x00, 0x00, 0x00,
        ];

        let packet = IpcpPacket::parse(&data).unwrap();
        assert_eq!(packet.ip_address(), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(packet.primary_dns(), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(packet.secondary_dns(), Some(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_parse_nak_with_dns() {
        // IPCP Configure-Nak with suggested DNS servers
        let data = [
            0x03, // Code: Configure-Nak
            0x01, // Identifier
            0x00, 0x16, // Length=22
            // IP-Address option
            0x03, 0x06, 0xc0, 0xa8, 0x01, 0x64, // 192.168.1.100
            // Primary DNS
            0x81, 0x06, 0x08, 0x08, 0x08, 0x08, // 8.8.8.8
            // Secondary DNS
            0x83, 0x06, 0x08, 0x08, 0x04, 0x04, // 8.8.4.4
        ];

        let packet = IpcpPacket::parse(&data).unwrap();
        assert_eq!(packet.ip_address(), Some(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(packet.primary_dns(), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(packet.secondary_dns(), Some(Ipv4Addr::new(8, 8, 4, 4)));
    }

    #[test]
    fn test_iterate_options() {
        let data = [
            0x01, 0x01, 0x00, 0x16, 0x03, 0x06, 0x00, 0x00, 0x00, 0x00, 0x81, 0x06, 0x00, 0x00,
            0x00, 0x00, 0x83, 0x06, 0x00, 0x00, 0x00, 0x00,
        ];

        let packet = IpcpPacket::parse(&data).unwrap();
        let opts: Vec<_> = packet.iter_options().collect();
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0].opt_type, options::IP_ADDRESS);
        assert_eq!(opts[1].opt_type, options::PRIMARY_DNS);
        assert_eq!(opts[2].opt_type, options::SECONDARY_DNS);
    }

    #[test]
    fn test_build_configure_request() {
        let packet = IpcpBuilder::configure_request(1)
            .ip_address(Ipv4Addr::new(0, 0, 0, 0))
            .primary_dns(Ipv4Addr::new(0, 0, 0, 0))
            .secondary_dns(Ipv4Addr::new(0, 0, 0, 0))
            .build();

        let parsed = IpcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::CONFIGURE_REQUEST);
        assert_eq!(parsed.identifier(), 1);
        assert_eq!(parsed.ip_address(), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(parsed.primary_dns(), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(parsed.secondary_dns(), Some(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_build_configure_ack() {
        let options_data = [0x03, 0x06, 0xc0, 0xa8, 0x01, 0x64]; // IP=192.168.1.100
        let packet = IpcpBuilder::configure_ack(5)
            .raw_data(&options_data)
            .build();

        let parsed = IpcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::CONFIGURE_ACK);
        assert_eq!(parsed.identifier(), 5);
        assert_eq!(parsed.ip_address(), Some(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_build_configure_nak() {
        let packet = IpcpBuilder::configure_nak(1)
            .ip_address(Ipv4Addr::new(10, 0, 0, 100))
            .primary_dns(Ipv4Addr::new(8, 8, 8, 8))
            .build();

        let parsed = IpcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::CONFIGURE_NAK);
        assert_eq!(parsed.ip_address(), Some(Ipv4Addr::new(10, 0, 0, 100)));
        assert_eq!(parsed.primary_dns(), Some(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_roundtrip() {
        let original = IpcpBuilder::configure_request(42)
            .ip_address(Ipv4Addr::new(172, 16, 0, 1))
            .primary_dns(Ipv4Addr::new(1, 1, 1, 1))
            .secondary_dns(Ipv4Addr::new(1, 0, 0, 1))
            .build();

        let parsed = IpcpPacket::parse(&original).unwrap();
        assert_eq!(parsed.as_bytes(), original.as_slice());
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0x01, 0x01, 0x00];
        assert!(IpcpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_length() {
        let data = [0x01, 0x01, 0x00, 0x02]; // Length=2, but min is 4
        assert!(IpcpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x01, 0x01, 0x00, 0x10]; // Length=16, but only 4 bytes
        assert!(IpcpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_no_options() {
        let data = [0x01, 0x01, 0x00, 0x04]; // No options
        let packet = IpcpPacket::parse(&data).unwrap();
        assert_eq!(packet.ip_address(), None);
        assert_eq!(packet.primary_dns(), None);
    }
}

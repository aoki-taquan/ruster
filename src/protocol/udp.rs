//! UDP protocol - RFC 768
//!
//! UDP header parsing and checksum calculation for NAPT.

use crate::{Error, Result};
use std::net::Ipv4Addr;

/// UDP header size (fixed)
pub const HEADER_SIZE: usize = 8;

/// UDP protocol number for pseudo-header
pub const PROTOCOL_NUMBER: u8 = 17;

/// Parsed UDP header (zero-copy reference)
#[derive(Debug)]
pub struct UdpHeader<'a> {
    buffer: &'a [u8],
}

impl<'a> UdpHeader<'a> {
    /// Parse UDP header from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < HEADER_SIZE {
            return Err(Error::Parse("UDP header too short".into()));
        }

        Ok(Self { buffer })
    }

    /// Source port (offset 0-1)
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    /// Destination port (offset 2-3)
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Length (header + data) (offset 4-5)
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Checksum (offset 6-7)
    /// Note: 0 means checksum not computed (valid for UDP over IPv4)
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    /// Payload (data after header)
    pub fn payload(&self) -> &[u8] {
        &self.buffer[HEADER_SIZE..]
    }

    /// Raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Validate checksum with pseudo-header
    /// Returns true if checksum is valid or if checksum is 0 (not computed)
    pub fn validate_checksum(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> bool {
        if self.checksum() == 0 {
            // Checksum not computed - valid for UDP over IPv4
            return true;
        }
        udp_checksum(src_ip, dst_ip, self.buffer) == 0
    }
}

/// Mutable UDP datagram for NAPT modifications
#[derive(Debug, Clone)]
pub struct UdpPacket {
    buffer: Vec<u8>,
}

impl UdpPacket {
    /// Create from raw bytes (copies the data)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::Parse("UDP datagram too short".into()));
        }

        Ok(Self {
            buffer: data.to_vec(),
        })
    }

    /// Source port
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    /// Destination port
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Set source port (checksum must be updated separately)
    pub fn set_src_port(&mut self, port: u16) {
        self.buffer[0..2].copy_from_slice(&port.to_be_bytes());
    }

    /// Set destination port (checksum must be updated separately)
    pub fn set_dst_port(&mut self, port: u16) {
        self.buffer[2..4].copy_from_slice(&port.to_be_bytes());
    }

    /// Get checksum value
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    /// Update checksum with new IP addresses
    pub fn update_checksum(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
        // Zero out checksum field first
        self.buffer[6] = 0;
        self.buffer[7] = 0;

        let sum = udp_checksum(src_ip, dst_ip, &self.buffer);

        // For UDP, if computed checksum is 0, use 0xFFFF instead
        // (0 is reserved for "no checksum")
        let sum = if sum == 0 { 0xFFFF } else { sum };

        self.buffer[6..8].copy_from_slice(&sum.to_be_bytes());
    }

    /// Consume and return the buffer
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Get reference to buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Get mutable reference to buffer
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Length field
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }
}

/// UDP packet builder for creating new UDP datagrams
#[derive(Debug, Clone, Default)]
pub struct UdpBuilder {
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
}

impl UdpBuilder {
    /// Create a new UDP builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set source port
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    /// Set destination port
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    /// Set payload
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    /// Build the UDP datagram with checksum
    pub fn build(self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
        let length = (HEADER_SIZE + self.payload.len()) as u16;
        let mut buffer = vec![0u8; HEADER_SIZE + self.payload.len()];

        // Header
        buffer[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buffer[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buffer[4..6].copy_from_slice(&length.to_be_bytes());
        // Checksum placeholder (offset 6-7) is already 0

        // Payload
        buffer[HEADER_SIZE..].copy_from_slice(&self.payload);

        // Calculate checksum
        let sum = udp_checksum(src_ip, dst_ip, &buffer);
        let sum = if sum == 0 { 0xFFFF } else { sum };
        buffer[6..8].copy_from_slice(&sum.to_be_bytes());

        buffer
    }
}

/// Calculate UDP checksum with pseudo-header (RFC 768)
///
/// Pseudo-header:
/// ```text
/// +--------+--------+--------+--------+
/// |          Source Address           |
/// +--------+--------+--------+--------+
/// |        Destination Address        |
/// +--------+--------+--------+--------+
/// |  Zero  |Protocol|   UDP Length    |
/// +--------+--------+--------+--------+
/// ```
pub fn udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_datagram: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    let src = src_ip.octets();
    let dst = dst_ip.octets();

    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += PROTOCOL_NUMBER as u32;
    sum += udp_datagram.len() as u32;

    // UDP datagram
    for i in (0..udp_datagram.len()).step_by(2) {
        let word = if i + 1 < udp_datagram.len() {
            u16::from_be_bytes([udp_datagram[i], udp_datagram[i + 1]])
        } else {
            // Pad with zero if odd length
            u16::from_be_bytes([udp_datagram[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_udp_datagram() -> Vec<u8> {
        // UDP datagram: src_port=12345, dst_port=53 (DNS), length=12, payload="test"
        let mut dgram = vec![
            0x30, 0x39, // src_port = 12345
            0x00, 0x35, // dst_port = 53
            0x00, 0x0c, // length = 12 (8 header + 4 data)
            0x00, 0x00, // checksum (placeholder)
            b't', b'e', b's', b't', // payload
        ];

        // Calculate checksum with test IPs
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        let sum = udp_checksum(src_ip, dst_ip, &dgram);
        dgram[6..8].copy_from_slice(&sum.to_be_bytes());
        dgram
    }

    #[test]
    fn test_udp_header_parse() {
        let dgram = make_udp_datagram();
        let hdr = UdpHeader::parse(&dgram).unwrap();

        assert_eq!(hdr.src_port(), 12345);
        assert_eq!(hdr.dst_port(), 53);
        assert_eq!(hdr.length(), 12);
        assert_eq!(hdr.payload(), b"test");
    }

    #[test]
    fn test_udp_header_parse_too_short() {
        let dgram = vec![0u8; 7];
        assert!(UdpHeader::parse(&dgram).is_err());
    }

    #[test]
    fn test_udp_header_validate_checksum() {
        let dgram = make_udp_datagram();
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);

        let hdr = UdpHeader::parse(&dgram).unwrap();
        assert!(hdr.validate_checksum(src_ip, dst_ip));
    }

    #[test]
    fn test_udp_header_no_checksum() {
        let mut dgram = make_udp_datagram();
        dgram[6] = 0;
        dgram[7] = 0; // checksum = 0

        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);

        let hdr = UdpHeader::parse(&dgram).unwrap();
        // checksum = 0 is valid for UDP (means not computed)
        assert!(hdr.validate_checksum(src_ip, dst_ip));
    }

    #[test]
    fn test_udp_packet_set_ports() {
        let dgram = make_udp_datagram();
        let mut pkt = UdpPacket::from_bytes(&dgram).unwrap();

        assert_eq!(pkt.src_port(), 12345);
        pkt.set_src_port(54321);
        assert_eq!(pkt.src_port(), 54321);

        assert_eq!(pkt.dst_port(), 53);
        pkt.set_dst_port(5353);
        assert_eq!(pkt.dst_port(), 5353);
    }

    #[test]
    fn test_udp_packet_update_checksum() {
        let dgram = make_udp_datagram();
        let mut pkt = UdpPacket::from_bytes(&dgram).unwrap();

        // Change port and update checksum
        pkt.set_src_port(54321);

        let new_src_ip = Ipv4Addr::new(203, 0, 113, 1);
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        pkt.update_checksum(new_src_ip, dst_ip);

        // Verify checksum is valid
        let hdr = UdpHeader::parse(pkt.as_bytes()).unwrap();
        assert!(hdr.validate_checksum(new_src_ip, dst_ip));
    }

    #[test]
    fn test_udp_checksum_known_value() {
        let dgram = vec![
            0x30, 0x39, // src_port = 12345
            0x00, 0x35, // dst_port = 53
            0x00, 0x0c, // length = 12
            0x00, 0x00, // checksum = 0 for calculation
            b't', b'e', b's', b't',
        ];

        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(8, 8, 8, 8);

        let checksum = udp_checksum(src, dst, &dgram);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_udp_checksum_odd_length() {
        // Odd-length payload should be padded
        let dgram = vec![
            0x30, 0x39, // src_port
            0x00, 0x35, // dst_port
            0x00, 0x0d, // length = 13 (8 header + 5 data)
            0x00, 0x00, // checksum
            b'h', b'e', b'l', b'l', b'o',
        ];

        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);

        let checksum = udp_checksum(src, dst, &dgram);
        // Should compute without panic
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_udp_packet_into_bytes() {
        let dgram = make_udp_datagram();
        let pkt = UdpPacket::from_bytes(&dgram).unwrap();
        let bytes = pkt.into_bytes();
        assert_eq!(bytes, dgram);
    }
}

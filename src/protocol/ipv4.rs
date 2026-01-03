//! IPv4 protocol - RFC 791

use crate::{Error, Result};
use std::net::Ipv4Addr;

/// Minimum IPv4 header size (without options)
pub const MIN_HEADER_SIZE: usize = 20;

/// IPv4 protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
}

impl Protocol {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Protocol::Icmp),
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            58 => Some(Protocol::Icmpv6),
            _ => None,
        }
    }
}

/// Parsed IPv4 header (zero-copy reference)
#[derive(Debug)]
pub struct Ipv4Header<'a> {
    buffer: &'a [u8],
    header_len: usize,
}

impl<'a> Ipv4Header<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < MIN_HEADER_SIZE {
            return Err(Error::Parse("IPv4 header too short".into()));
        }

        let version = buffer[0] >> 4;
        if version != 4 {
            return Err(Error::Parse("not an IPv4 packet".into()));
        }

        let ihl = (buffer[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if buffer.len() < header_len {
            return Err(Error::Parse("IPv4 header truncated".into()));
        }

        Ok(Self { buffer, header_len })
    }

    pub fn version(&self) -> u8 {
        self.buffer[0] >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.buffer[0] & 0x0F
    }

    pub fn dscp(&self) -> u8 {
        self.buffer[1] >> 2
    }

    pub fn ecn(&self) -> u8 {
        self.buffer[1] & 0x03
    }

    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    pub fn flags(&self) -> u8 {
        self.buffer[6] >> 5
    }

    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6] & 0x1F, self.buffer[7]])
    }

    pub fn ttl(&self) -> u8 {
        self.buffer[8]
    }

    pub fn protocol(&self) -> u8 {
        self.buffer[9]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[10], self.buffer[11]])
    }

    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[12],
            self.buffer[13],
            self.buffer[14],
            self.buffer[15],
        )
    }

    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[16],
            self.buffer[17],
            self.buffer[18],
            self.buffer[19],
        )
    }

    pub fn header_len(&self) -> usize {
        self.header_len
    }

    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.header_len..]
    }
}

/// Fragment flags
pub mod flags {
    /// Don't Fragment
    pub const DF: u8 = 0b010;
    /// More Fragments
    pub const MF: u8 = 0b001;
}

impl<'a> Ipv4Header<'a> {
    /// Check if Don't Fragment flag is set
    pub fn dont_fragment(&self) -> bool {
        (self.flags() & flags::DF) != 0
    }

    /// Check if More Fragments flag is set
    pub fn more_fragments(&self) -> bool {
        (self.flags() & flags::MF) != 0
    }

    /// Check if this is a fragment (MF set or offset > 0)
    pub fn is_fragment(&self) -> bool {
        self.more_fragments() || self.fragment_offset() > 0
    }

    /// Validate header checksum
    pub fn validate_checksum(&self) -> bool {
        checksum(&self.buffer[..self.header_len]) == 0
    }

    /// Get raw header bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.header_len]
    }
}

/// Calculate IPv4 header checksum
pub fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Mutable IPv4 packet for modification (TTL decrement, etc.)
#[derive(Debug)]
pub struct Ipv4Packet {
    buffer: Vec<u8>,
    header_len: usize,
}

impl Ipv4Packet {
    /// Create from raw bytes (copies the data)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_HEADER_SIZE {
            return Err(Error::Parse("IPv4 packet too short".into()));
        }

        let version = data[0] >> 4;
        if version != 4 {
            return Err(Error::Parse("not an IPv4 packet".into()));
        }

        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if data.len() < header_len {
            return Err(Error::Parse("IPv4 header truncated".into()));
        }

        Ok(Self {
            buffer: data.to_vec(),
            header_len,
        })
    }

    /// Get TTL
    pub fn ttl(&self) -> u8 {
        self.buffer[8]
    }

    /// Decrement TTL and update checksum
    /// Returns false if TTL would become 0 (packet should be dropped)
    pub fn decrement_ttl(&mut self) -> bool {
        if self.buffer[8] <= 1 {
            return false;
        }

        self.buffer[8] -= 1;
        self.update_checksum();
        true
    }

    /// Set TTL and update checksum
    pub fn set_ttl(&mut self, ttl: u8) {
        self.buffer[8] = ttl;
        self.update_checksum();
    }

    /// Recalculate and update header checksum
    pub fn update_checksum(&mut self) {
        // Zero out checksum field first
        self.buffer[10] = 0;
        self.buffer[11] = 0;

        let sum = checksum(&self.buffer[..self.header_len]);
        self.buffer[10..12].copy_from_slice(&sum.to_be_bytes());
    }

    /// Get source address
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[12],
            self.buffer[13],
            self.buffer[14],
            self.buffer[15],
        )
    }

    /// Get destination address
    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[16],
            self.buffer[17],
            self.buffer[18],
            self.buffer[19],
        )
    }

    /// Get protocol number
    pub fn protocol(&self) -> u8 {
        self.buffer[9]
    }

    /// Get total length
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Get header length
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Get payload
    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.header_len..]
    }

    /// Get mutable payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.header_len..]
    }

    /// Consume and return the buffer
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Get a reference to the buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

/// Builder for constructing IPv4 packets
#[derive(Debug, Clone)]
pub struct Ipv4Builder {
    dscp: u8,
    ecn: u8,
    identification: u16,
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    payload: Vec<u8>,
}

impl Ipv4Builder {
    pub fn new() -> Self {
        Self {
            dscp: 0,
            ecn: 0,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol: 0,
            src_addr: Ipv4Addr::UNSPECIFIED,
            dst_addr: Ipv4Addr::UNSPECIFIED,
            payload: Vec::new(),
        }
    }

    pub fn dscp(mut self, dscp: u8) -> Self {
        self.dscp = dscp & 0x3F;
        self
    }

    pub fn ecn(mut self, ecn: u8) -> Self {
        self.ecn = ecn & 0x03;
        self
    }

    pub fn identification(mut self, id: u16) -> Self {
        self.identification = id;
        self
    }

    pub fn dont_fragment(mut self, df: bool) -> Self {
        self.dont_fragment = df;
        self
    }

    pub fn more_fragments(mut self, mf: bool) -> Self {
        self.more_fragments = mf;
        self
    }

    pub fn fragment_offset(mut self, offset: u16) -> Self {
        self.fragment_offset = offset & 0x1FFF;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn src_addr(mut self, addr: Ipv4Addr) -> Self {
        self.src_addr = addr;
        self
    }

    pub fn dst_addr(mut self, addr: Ipv4Addr) -> Self {
        self.dst_addr = addr;
        self
    }

    pub fn payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
        self
    }

    pub fn build(self) -> Vec<u8> {
        let total_length = (MIN_HEADER_SIZE + self.payload.len()) as u16;
        let mut buffer = vec![0u8; MIN_HEADER_SIZE + self.payload.len()];

        // Version (4) + IHL (5 = 20 bytes, no options)
        buffer[0] = 0x45;

        // DSCP + ECN
        buffer[1] = (self.dscp << 2) | self.ecn;

        // Total length
        buffer[2..4].copy_from_slice(&total_length.to_be_bytes());

        // Identification
        buffer[4..6].copy_from_slice(&self.identification.to_be_bytes());

        // Flags + Fragment offset
        let mut flags_frag = self.fragment_offset;
        if self.dont_fragment {
            flags_frag |= 0x4000;
        }
        if self.more_fragments {
            flags_frag |= 0x2000;
        }
        buffer[6..8].copy_from_slice(&flags_frag.to_be_bytes());

        // TTL
        buffer[8] = self.ttl;

        // Protocol
        buffer[9] = self.protocol;

        // Checksum (filled later)
        buffer[10] = 0;
        buffer[11] = 0;

        // Source address
        buffer[12..16].copy_from_slice(&self.src_addr.octets());

        // Destination address
        buffer[16..20].copy_from_slice(&self.dst_addr.octets());

        // Payload
        buffer[MIN_HEADER_SIZE..].copy_from_slice(&self.payload);

        // Calculate checksum
        let sum = checksum(&buffer[..MIN_HEADER_SIZE]);
        buffer[10..12].copy_from_slice(&sum.to_be_bytes());

        buffer
    }
}

impl Default for Ipv4Builder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_packet() -> Vec<u8> {
        // IPv4 packet: src=192.168.1.1, dst=192.168.1.2, TTL=64, ICMP
        let mut pkt = vec![
            0x45, // Version=4, IHL=5
            0x00, // DSCP=0, ECN=0
            0x00, 0x1c, // Total length = 28
            0x00, 0x00, // Identification
            0x40, 0x00, // Flags=DF, Fragment offset=0
            0x40, // TTL=64
            0x01, // Protocol=ICMP
            0x00, 0x00, // Checksum (placeholder)
            192, 168, 1, 1, // Source
            192, 168, 1, 2, // Destination
            // Payload (8 bytes)
            0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        // Calculate correct checksum
        let sum = checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&sum.to_be_bytes());
        pkt
    }

    fn make_fragment_packet(mf: bool, offset: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x45, 0x00, 0x00, 0x1c, // Version, IHL, TOS, Total length
            0x12, 0x34, // Identification
            0x00, 0x00, // Flags + offset (placeholder)
            0x40, 0x01, // TTL, Protocol
            0x00, 0x00, // Checksum
            192, 168, 1, 1, 192, 168, 1, 2, // Src, Dst
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Payload
        ];

        let mut flags_offset = offset & 0x1FFF;
        if mf {
            flags_offset |= 0x2000;
        }
        pkt[6..8].copy_from_slice(&flags_offset.to_be_bytes());

        let sum = checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&sum.to_be_bytes());
        pkt
    }

    // Protocol tests
    #[test]
    fn test_protocol_from_u8() {
        assert_eq!(Protocol::from_u8(1), Some(Protocol::Icmp));
        assert_eq!(Protocol::from_u8(6), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_u8(17), Some(Protocol::Udp));
        assert_eq!(Protocol::from_u8(58), Some(Protocol::Icmpv6));
        assert_eq!(Protocol::from_u8(0), None);
        assert_eq!(Protocol::from_u8(255), None);
    }

    // Ipv4Header parse tests
    #[test]
    fn test_parse_simple() {
        let data = make_simple_packet();
        let hdr = Ipv4Header::parse(&data).unwrap();

        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 5);
        assert_eq!(hdr.header_len(), 20);
        assert_eq!(hdr.dscp(), 0);
        assert_eq!(hdr.ecn(), 0);
        assert_eq!(hdr.total_length(), 28);
        assert_eq!(hdr.identification(), 0);
        assert_eq!(hdr.ttl(), 64);
        assert_eq!(hdr.protocol(), 1);
        assert_eq!(hdr.src_addr(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hdr.dst_addr(), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(hdr.payload().len(), 8);
    }

    #[test]
    fn test_parse_too_short() {
        let short = vec![0u8; 19];
        assert!(Ipv4Header::parse(&short).is_err());
    }

    #[test]
    fn test_parse_wrong_version() {
        let mut data = make_simple_packet();
        data[0] = 0x65; // Version 6
        assert!(Ipv4Header::parse(&data).is_err());
    }

    #[test]
    fn test_parse_truncated_header() {
        let mut data = make_simple_packet();
        data[0] = 0x4F; // IHL=15 (60 bytes)
        assert!(Ipv4Header::parse(&data).is_err());
    }

    // Fragment tests
    #[test]
    fn test_dont_fragment_flag() {
        let data = make_simple_packet();
        let hdr = Ipv4Header::parse(&data).unwrap();
        assert!(hdr.dont_fragment());
        assert!(!hdr.more_fragments());
        assert!(!hdr.is_fragment());
    }

    #[test]
    fn test_more_fragments_flag() {
        let data = make_fragment_packet(true, 0);
        let hdr = Ipv4Header::parse(&data).unwrap();
        assert!(!hdr.dont_fragment());
        assert!(hdr.more_fragments());
        assert!(hdr.is_fragment());
    }

    #[test]
    fn test_fragment_offset() {
        let data = make_fragment_packet(false, 185); // offset in 8-byte units
        let hdr = Ipv4Header::parse(&data).unwrap();
        assert_eq!(hdr.fragment_offset(), 185);
        assert!(hdr.is_fragment());
    }

    // Checksum tests
    #[test]
    fn test_validate_checksum() {
        let data = make_simple_packet();
        let hdr = Ipv4Header::parse(&data).unwrap();
        assert!(hdr.validate_checksum());
    }

    #[test]
    fn test_validate_checksum_bad() {
        let mut data = make_simple_packet();
        data[10] = 0xFF; // Corrupt checksum
        let hdr = Ipv4Header::parse(&data).unwrap();
        assert!(!hdr.validate_checksum());
    }

    #[test]
    fn test_as_bytes() {
        let data = make_simple_packet();
        let hdr = Ipv4Header::parse(&data).unwrap();
        assert_eq!(hdr.as_bytes().len(), 20);
    }

    // Ipv4Packet (mutable) tests
    #[test]
    fn test_packet_from_bytes() {
        let data = make_simple_packet();
        let pkt = Ipv4Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.ttl(), 64);
        assert_eq!(pkt.protocol(), 1);
        assert_eq!(pkt.src_addr(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(pkt.dst_addr(), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(pkt.header_len(), 20);
        assert_eq!(pkt.total_length(), 28);
    }

    #[test]
    fn test_packet_decrement_ttl() {
        let data = make_simple_packet();
        let mut pkt = Ipv4Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.ttl(), 64);
        assert!(pkt.decrement_ttl());
        assert_eq!(pkt.ttl(), 63);

        // Verify checksum is still valid
        let hdr = Ipv4Header::parse(pkt.as_bytes()).unwrap();
        assert!(hdr.validate_checksum());
    }

    #[test]
    fn test_packet_decrement_ttl_expires() {
        let mut data = make_simple_packet();
        data[8] = 1; // TTL=1
                     // Recalculate checksum
        data[10] = 0;
        data[11] = 0;
        let sum = checksum(&data[..20]);
        data[10..12].copy_from_slice(&sum.to_be_bytes());

        let mut pkt = Ipv4Packet::from_bytes(&data).unwrap();
        assert_eq!(pkt.ttl(), 1);
        assert!(!pkt.decrement_ttl()); // Should return false
        assert_eq!(pkt.ttl(), 1); // TTL unchanged
    }

    #[test]
    fn test_packet_decrement_ttl_zero() {
        let mut data = make_simple_packet();
        data[8] = 0; // TTL=0
        data[10] = 0;
        data[11] = 0;
        let sum = checksum(&data[..20]);
        data[10..12].copy_from_slice(&sum.to_be_bytes());

        let mut pkt = Ipv4Packet::from_bytes(&data).unwrap();
        assert!(!pkt.decrement_ttl());
    }

    #[test]
    fn test_packet_set_ttl() {
        let data = make_simple_packet();
        let mut pkt = Ipv4Packet::from_bytes(&data).unwrap();

        pkt.set_ttl(128);
        assert_eq!(pkt.ttl(), 128);

        let hdr = Ipv4Header::parse(pkt.as_bytes()).unwrap();
        assert!(hdr.validate_checksum());
    }

    #[test]
    fn test_packet_payload() {
        let data = make_simple_packet();
        let pkt = Ipv4Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.payload().len(), 8);
        assert_eq!(pkt.payload()[0], 0x08); // ICMP Echo Request
    }

    #[test]
    fn test_packet_payload_mut() {
        let data = make_simple_packet();
        let mut pkt = Ipv4Packet::from_bytes(&data).unwrap();

        pkt.payload_mut()[0] = 0x00; // Change to ICMP Echo Reply
        assert_eq!(pkt.payload()[0], 0x00);
    }

    #[test]
    fn test_packet_into_bytes() {
        let data = make_simple_packet();
        let pkt = Ipv4Packet::from_bytes(&data).unwrap();
        let bytes = pkt.into_bytes();
        assert_eq!(bytes, data);
    }

    // Ipv4Builder tests
    #[test]
    fn test_builder_simple() {
        let packet = Ipv4Builder::new()
            .src_addr(Ipv4Addr::new(10, 0, 0, 1))
            .dst_addr(Ipv4Addr::new(10, 0, 0, 2))
            .ttl(64)
            .protocol(Protocol::Icmp as u8)
            .payload(&[0x08, 0x00, 0x00, 0x00])
            .build();

        let hdr = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 5);
        assert_eq!(hdr.src_addr(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(hdr.dst_addr(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(hdr.ttl(), 64);
        assert_eq!(hdr.protocol(), 1);
        assert!(hdr.validate_checksum());
        assert!(hdr.dont_fragment()); // Default is true
    }

    #[test]
    fn test_builder_with_dscp_ecn() {
        let packet = Ipv4Builder::new()
            .src_addr(Ipv4Addr::new(10, 0, 0, 1))
            .dst_addr(Ipv4Addr::new(10, 0, 0, 2))
            .dscp(46) // EF (Expedited Forwarding)
            .ecn(2)
            .build();

        let hdr = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(hdr.dscp(), 46);
        assert_eq!(hdr.ecn(), 2);
        assert!(hdr.validate_checksum());
    }

    #[test]
    fn test_builder_fragment() {
        let packet = Ipv4Builder::new()
            .src_addr(Ipv4Addr::new(10, 0, 0, 1))
            .dst_addr(Ipv4Addr::new(10, 0, 0, 2))
            .identification(0x1234)
            .dont_fragment(false)
            .more_fragments(true)
            .fragment_offset(0)
            .payload(&[0u8; 100])
            .build();

        let hdr = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(hdr.identification(), 0x1234);
        assert!(!hdr.dont_fragment());
        assert!(hdr.more_fragments());
        assert_eq!(hdr.fragment_offset(), 0);
        assert!(hdr.is_fragment());
        assert!(hdr.validate_checksum());
    }

    #[test]
    fn test_builder_fragment_offset() {
        let packet = Ipv4Builder::new()
            .src_addr(Ipv4Addr::new(10, 0, 0, 1))
            .dst_addr(Ipv4Addr::new(10, 0, 0, 2))
            .dont_fragment(false)
            .fragment_offset(185)
            .payload(&[0u8; 100])
            .build();

        let hdr = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(hdr.fragment_offset(), 185);
        assert!(hdr.is_fragment());
    }

    #[test]
    fn test_builder_default() {
        let builder = Ipv4Builder::default();
        let packet = builder.build();
        let hdr = Ipv4Header::parse(&packet).unwrap();

        assert_eq!(hdr.ttl(), 64);
        assert!(hdr.dont_fragment());
        assert!(hdr.validate_checksum());
    }

    #[test]
    fn test_builder_roundtrip() {
        let original = Ipv4Builder::new()
            .src_addr(Ipv4Addr::new(192, 168, 1, 100))
            .dst_addr(Ipv4Addr::new(8, 8, 8, 8))
            .ttl(128)
            .protocol(Protocol::Udp as u8)
            .identification(0xABCD)
            .dscp(0)
            .ecn(0)
            .payload(&[1, 2, 3, 4, 5, 6, 7, 8])
            .build();

        let hdr = Ipv4Header::parse(&original).unwrap();
        assert_eq!(hdr.src_addr(), Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(hdr.dst_addr(), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(hdr.ttl(), 128);
        assert_eq!(hdr.protocol(), 17);
        assert_eq!(hdr.identification(), 0xABCD);
        assert_eq!(hdr.total_length(), 28);
        assert_eq!(hdr.payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(hdr.validate_checksum());
    }

    // Checksum function tests
    #[test]
    fn test_checksum_known_good() {
        // A known good IPv4 header with valid checksum
        let data = make_simple_packet();
        // checksum of valid header should be 0
        assert_eq!(checksum(&data[..20]), 0);
    }

    #[test]
    fn test_checksum_odd_length() {
        // Test with odd-length header (padding case)
        let header = vec![0x45, 0x00, 0x00, 0x1c, 0x00];
        let _ = checksum(&header); // Should not panic
    }
}

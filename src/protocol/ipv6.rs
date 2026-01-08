//! IPv6 protocol - RFC 8200

use crate::{Error, Result};
use std::net::Ipv6Addr;

/// IPv6 header size (fixed, unlike IPv4)
pub const HEADER_SIZE: usize = 40;

/// IPv6 next header values (same as IPv4 protocol numbers)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NextHeader {
    HopByHop = 0,
    Icmpv6 = 58,
    Tcp = 6,
    Udp = 17,
    NoNextHeader = 59,
}

impl NextHeader {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(NextHeader::HopByHop),
            6 => Some(NextHeader::Tcp),
            17 => Some(NextHeader::Udp),
            58 => Some(NextHeader::Icmpv6),
            59 => Some(NextHeader::NoNextHeader),
            _ => None,
        }
    }
}

/// Parsed IPv6 header (zero-copy reference)
#[derive(Debug)]
pub struct Ipv6Header<'a> {
    buffer: &'a [u8],
}

impl<'a> Ipv6Header<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < HEADER_SIZE {
            return Err(Error::Parse("IPv6 header too short".into()));
        }

        let version = buffer[0] >> 4;
        if version != 6 {
            return Err(Error::Parse("not an IPv6 packet".into()));
        }

        Ok(Self { buffer })
    }

    /// Version (always 6)
    pub fn version(&self) -> u8 {
        self.buffer[0] >> 4
    }

    /// Traffic Class (6 bits from byte 0, 2 bits from byte 1)
    pub fn traffic_class(&self) -> u8 {
        ((self.buffer[0] & 0x0F) << 4) | (self.buffer[1] >> 4)
    }

    /// Flow Label (20 bits)
    pub fn flow_label(&self) -> u32 {
        let b1 = (self.buffer[1] & 0x0F) as u32;
        let b2 = self.buffer[2] as u32;
        let b3 = self.buffer[3] as u32;
        (b1 << 16) | (b2 << 8) | b3
    }

    /// Payload Length (does not include header)
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Next Header (protocol)
    pub fn next_header(&self) -> u8 {
        self.buffer[6]
    }

    /// Hop Limit (equivalent to IPv4 TTL)
    pub fn hop_limit(&self) -> u8 {
        self.buffer[7]
    }

    /// Source Address
    pub fn src_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer[8..24].try_into().unwrap();
        Ipv6Addr::from(bytes)
    }

    /// Destination Address
    pub fn dst_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer[24..40].try_into().unwrap();
        Ipv6Addr::from(bytes)
    }

    /// Header length (always 40 for base header)
    pub fn header_len(&self) -> usize {
        HEADER_SIZE
    }

    /// Payload (after header)
    pub fn payload(&self) -> &[u8] {
        &self.buffer[HEADER_SIZE..]
    }

    /// Get raw header bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..HEADER_SIZE]
    }
}

/// Mutable IPv6 packet for modification (hop limit decrement, etc.)
#[derive(Debug)]
pub struct Ipv6Packet {
    buffer: Vec<u8>,
}

impl Ipv6Packet {
    /// Create from raw bytes (copies the data)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::Parse("IPv6 packet too short".into()));
        }

        let version = data[0] >> 4;
        if version != 6 {
            return Err(Error::Parse("not an IPv6 packet".into()));
        }

        Ok(Self {
            buffer: data.to_vec(),
        })
    }

    /// Get Hop Limit
    pub fn hop_limit(&self) -> u8 {
        self.buffer[7]
    }

    /// Decrement Hop Limit
    /// Returns false if hop limit would become 0 (packet should be dropped)
    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.buffer[7] <= 1 {
            return false;
        }

        self.buffer[7] -= 1;
        true
    }

    /// Set Hop Limit
    pub fn set_hop_limit(&mut self, hop_limit: u8) {
        self.buffer[7] = hop_limit;
    }

    /// Get Next Header
    pub fn next_header(&self) -> u8 {
        self.buffer[6]
    }

    /// Get Source Address
    pub fn src_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer[8..24].try_into().unwrap();
        Ipv6Addr::from(bytes)
    }

    /// Get Destination Address
    pub fn dst_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer[24..40].try_into().unwrap();
        Ipv6Addr::from(bytes)
    }

    /// Get Payload Length
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Get header length
    pub fn header_len(&self) -> usize {
        HEADER_SIZE
    }

    /// Get payload
    pub fn payload(&self) -> &[u8] {
        &self.buffer[HEADER_SIZE..]
    }

    /// Get mutable payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[HEADER_SIZE..]
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

/// Builder for constructing IPv6 packets
#[derive(Debug, Clone)]
pub struct Ipv6Builder {
    traffic_class: u8,
    flow_label: u32,
    next_header: u8,
    hop_limit: u8,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    payload: Vec<u8>,
}

impl Ipv6Builder {
    pub fn new() -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            next_header: 0,
            hop_limit: 64,
            src_addr: Ipv6Addr::UNSPECIFIED,
            dst_addr: Ipv6Addr::UNSPECIFIED,
            payload: Vec::new(),
        }
    }

    pub fn traffic_class(mut self, tc: u8) -> Self {
        self.traffic_class = tc;
        self
    }

    pub fn flow_label(mut self, fl: u32) -> Self {
        self.flow_label = fl & 0xFFFFF; // 20 bits
        self
    }

    pub fn next_header(mut self, nh: u8) -> Self {
        self.next_header = nh;
        self
    }

    pub fn hop_limit(mut self, hl: u8) -> Self {
        self.hop_limit = hl;
        self
    }

    pub fn src_addr(mut self, addr: Ipv6Addr) -> Self {
        self.src_addr = addr;
        self
    }

    pub fn dst_addr(mut self, addr: Ipv6Addr) -> Self {
        self.dst_addr = addr;
        self
    }

    pub fn payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
        self
    }

    pub fn build(self) -> Vec<u8> {
        let payload_length = self.payload.len() as u16;
        let mut buffer = vec![0u8; HEADER_SIZE + self.payload.len()];

        // Version (6) + Traffic Class (upper 4 bits)
        buffer[0] = 0x60 | (self.traffic_class >> 4);

        // Traffic Class (lower 4 bits) + Flow Label (upper 4 bits)
        buffer[1] = ((self.traffic_class & 0x0F) << 4) | ((self.flow_label >> 16) as u8 & 0x0F);

        // Flow Label (middle 8 bits)
        buffer[2] = (self.flow_label >> 8) as u8;

        // Flow Label (lower 8 bits)
        buffer[3] = self.flow_label as u8;

        // Payload Length
        buffer[4..6].copy_from_slice(&payload_length.to_be_bytes());

        // Next Header
        buffer[6] = self.next_header;

        // Hop Limit
        buffer[7] = self.hop_limit;

        // Source Address
        buffer[8..24].copy_from_slice(&self.src_addr.octets());

        // Destination Address
        buffer[24..40].copy_from_slice(&self.dst_addr.octets());

        // Payload
        buffer[HEADER_SIZE..].copy_from_slice(&self.payload);

        buffer
    }
}

impl Default for Ipv6Builder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_packet() -> Vec<u8> {
        // IPv6 packet: src=2001:db8::1, dst=2001:db8::2, hop_limit=64, ICMPv6
        let pkt = vec![
            0x60, 0x00, 0x00, 0x00, // Version=6, TC=0, Flow Label=0
            0x00, 0x08, // Payload length = 8
            0x3a, // Next Header = ICMPv6 (58)
            0x40, // Hop Limit = 64
            // Source: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, // Payload (8 bytes)
            0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        pkt
    }

    fn make_traffic_class_flow_label_packet() -> Vec<u8> {
        // IPv6 with TC=0x12, Flow Label=0xABCDE
        vec![
            0x61, 0x2A, 0xBC, 0xDE, // Version=6, TC=0x12, Flow Label=0xABCDE
            0x00, 0x00, // Payload length = 0
            0x3a, // Next Header = ICMPv6
            0x40, // Hop Limit = 64
            // Source: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination: ::2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]
    }

    // NextHeader tests
    #[test]
    fn test_next_header_from_u8() {
        assert_eq!(NextHeader::from_u8(0), Some(NextHeader::HopByHop));
        assert_eq!(NextHeader::from_u8(6), Some(NextHeader::Tcp));
        assert_eq!(NextHeader::from_u8(17), Some(NextHeader::Udp));
        assert_eq!(NextHeader::from_u8(58), Some(NextHeader::Icmpv6));
        assert_eq!(NextHeader::from_u8(59), Some(NextHeader::NoNextHeader));
        assert_eq!(NextHeader::from_u8(255), None);
    }

    // Ipv6Header parse tests
    #[test]
    fn test_parse_simple() {
        let data = make_simple_packet();
        let hdr = Ipv6Header::parse(&data).unwrap();

        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.traffic_class(), 0);
        assert_eq!(hdr.flow_label(), 0);
        assert_eq!(hdr.payload_length(), 8);
        assert_eq!(hdr.next_header(), 58); // ICMPv6
        assert_eq!(hdr.hop_limit(), 64);
        assert_eq!(hdr.src_addr(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hdr.dst_addr(), "2001:db8::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hdr.header_len(), 40);
        assert_eq!(hdr.payload().len(), 8);
    }

    #[test]
    fn test_parse_traffic_class_flow_label() {
        let data = make_traffic_class_flow_label_packet();
        let hdr = Ipv6Header::parse(&data).unwrap();

        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.traffic_class(), 0x12);
        assert_eq!(hdr.flow_label(), 0xABCDE);
    }

    #[test]
    fn test_parse_too_short() {
        let short = vec![0u8; 39];
        assert!(Ipv6Header::parse(&short).is_err());
    }

    #[test]
    fn test_parse_wrong_version() {
        let mut data = make_simple_packet();
        data[0] = 0x40; // Version 4
        assert!(Ipv6Header::parse(&data).is_err());
    }

    #[test]
    fn test_as_bytes() {
        let data = make_simple_packet();
        let hdr = Ipv6Header::parse(&data).unwrap();
        assert_eq!(hdr.as_bytes().len(), 40);
    }

    // Ipv6Packet (mutable) tests
    #[test]
    fn test_packet_from_bytes() {
        let data = make_simple_packet();
        let pkt = Ipv6Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.hop_limit(), 64);
        assert_eq!(pkt.next_header(), 58);
        assert_eq!(pkt.src_addr(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(pkt.dst_addr(), "2001:db8::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(pkt.header_len(), 40);
        assert_eq!(pkt.payload_length(), 8);
    }

    #[test]
    fn test_packet_decrement_hop_limit() {
        let data = make_simple_packet();
        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.hop_limit(), 64);
        assert!(pkt.decrement_hop_limit());
        assert_eq!(pkt.hop_limit(), 63);
    }

    #[test]
    fn test_packet_decrement_hop_limit_expires() {
        let mut data = make_simple_packet();
        data[7] = 1; // Hop Limit = 1

        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();
        assert_eq!(pkt.hop_limit(), 1);
        assert!(!pkt.decrement_hop_limit()); // Should return false
        assert_eq!(pkt.hop_limit(), 1); // Unchanged
    }

    #[test]
    fn test_packet_decrement_hop_limit_zero() {
        let mut data = make_simple_packet();
        data[7] = 0; // Hop Limit = 0

        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();
        assert!(!pkt.decrement_hop_limit());
    }

    #[test]
    fn test_packet_set_hop_limit() {
        let data = make_simple_packet();
        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();

        pkt.set_hop_limit(128);
        assert_eq!(pkt.hop_limit(), 128);
    }

    #[test]
    fn test_packet_payload() {
        let data = make_simple_packet();
        let pkt = Ipv6Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.payload().len(), 8);
        assert_eq!(pkt.payload()[0], 0x80); // ICMPv6 Echo Request
    }

    #[test]
    fn test_packet_payload_mut() {
        let data = make_simple_packet();
        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();

        pkt.payload_mut()[0] = 0x81; // Change to ICMPv6 Echo Reply
        assert_eq!(pkt.payload()[0], 0x81);
    }

    #[test]
    fn test_packet_into_bytes() {
        let data = make_simple_packet();
        let pkt = Ipv6Packet::from_bytes(&data).unwrap();
        let bytes = pkt.into_bytes();
        assert_eq!(bytes, data);
    }

    // Ipv6Builder tests
    #[test]
    fn test_builder_simple() {
        let packet = Ipv6Builder::new()
            .src_addr("2001:db8::1".parse().unwrap())
            .dst_addr("2001:db8::2".parse().unwrap())
            .hop_limit(64)
            .next_header(NextHeader::Icmpv6 as u8)
            .payload(&[0x80, 0x00, 0x00, 0x00])
            .build();

        let hdr = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.src_addr(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hdr.dst_addr(), "2001:db8::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hdr.hop_limit(), 64);
        assert_eq!(hdr.next_header(), 58);
        assert_eq!(hdr.payload_length(), 4);
    }

    #[test]
    fn test_builder_with_traffic_class_flow_label() {
        let packet = Ipv6Builder::new()
            .src_addr("::1".parse().unwrap())
            .dst_addr("::2".parse().unwrap())
            .traffic_class(0x12)
            .flow_label(0xABCDE)
            .build();

        let hdr = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(hdr.traffic_class(), 0x12);
        assert_eq!(hdr.flow_label(), 0xABCDE);
    }

    #[test]
    fn test_builder_default() {
        let builder = Ipv6Builder::default();
        let packet = builder.build();
        let hdr = Ipv6Header::parse(&packet).unwrap();

        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.hop_limit(), 64);
        assert_eq!(hdr.traffic_class(), 0);
        assert_eq!(hdr.flow_label(), 0);
    }

    #[test]
    fn test_builder_roundtrip() {
        let original = Ipv6Builder::new()
            .src_addr("fe80::1".parse().unwrap())
            .dst_addr("ff02::1".parse().unwrap())
            .hop_limit(255)
            .next_header(NextHeader::Udp as u8)
            .traffic_class(0xAB)
            .flow_label(0x12345)
            .payload(&[1, 2, 3, 4, 5, 6, 7, 8])
            .build();

        let hdr = Ipv6Header::parse(&original).unwrap();
        assert_eq!(hdr.src_addr(), "fe80::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hdr.dst_addr(), "ff02::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hdr.hop_limit(), 255);
        assert_eq!(hdr.next_header(), 17);
        assert_eq!(hdr.traffic_class(), 0xAB);
        assert_eq!(hdr.flow_label(), 0x12345);
        assert_eq!(hdr.payload_length(), 8);
        assert_eq!(hdr.payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}

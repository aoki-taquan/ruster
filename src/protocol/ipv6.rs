//! IPv6 protocol - RFC 8200

use crate::{Error, Result};
use std::net::Ipv6Addr;

/// IPv6 fixed header size (always 40 bytes)
pub const HEADER_SIZE: usize = 40;

/// IPv6 Next Header values (RFC 8200, IANA assignments)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NextHeader {
    HopByHop = 0,
    Tcp = 6,
    Udp = 17,
    Routing = 43,
    Fragment = 44,
    Esp = 50,
    Ah = 51,
    Icmpv6 = 58,
    NoNextHeader = 59,
    DestinationOptions = 60,
}

impl NextHeader {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::HopByHop),
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            43 => Some(Self::Routing),
            44 => Some(Self::Fragment),
            50 => Some(Self::Esp),
            51 => Some(Self::Ah),
            58 => Some(Self::Icmpv6),
            59 => Some(Self::NoNextHeader),
            60 => Some(Self::DestinationOptions),
            _ => None,
        }
    }

    /// Check if this Next Header value indicates an extension header
    pub fn is_extension_header(value: u8) -> bool {
        matches!(value, 0 | 43 | 44 | 51 | 60)
    }
}

/// Parsed IPv6 header (zero-copy reference)
///
/// IPv6 Header Format (40 bytes):
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |Version| Traffic Class |           Flow Label                  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |         Payload Length        |  Next Header  |   Hop Limit   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  +                                                               +
///  |                         Source Address                        |
///  +                          (128 bits)                           +
///  |                                                               |
///  +                                                               +
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  +                                                               +
///  |                      Destination Address                      |
///  +                          (128 bits)                           +
///  |                                                               |
///  +                                                               +
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
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

    /// Traffic Class (8 bits: 6-bit DSCP + 2-bit ECN)
    pub fn traffic_class(&self) -> u8 {
        ((self.buffer[0] & 0x0F) << 4) | (self.buffer[1] >> 4)
    }

    /// DSCP (6 bits from Traffic Class)
    pub fn dscp(&self) -> u8 {
        self.traffic_class() >> 2
    }

    /// ECN (2 bits from Traffic Class)
    pub fn ecn(&self) -> u8 {
        self.traffic_class() & 0x03
    }

    /// Flow Label (20 bits)
    pub fn flow_label(&self) -> u32 {
        let b1 = (self.buffer[1] & 0x0F) as u32;
        let b2 = self.buffer[2] as u32;
        let b3 = self.buffer[3] as u32;
        (b1 << 16) | (b2 << 8) | b3
    }

    /// Payload Length (excludes 40-byte header)
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Next Header (protocol or extension header type)
    pub fn next_header(&self) -> u8 {
        self.buffer[6]
    }

    /// Hop Limit (equivalent to IPv4 TTL)
    pub fn hop_limit(&self) -> u8 {
        self.buffer[7]
    }

    /// Source address (128-bit)
    pub fn src_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer[8..24].try_into().unwrap();
        Ipv6Addr::from(bytes)
    }

    /// Destination address (128-bit)
    pub fn dst_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer[24..40].try_into().unwrap();
        Ipv6Addr::from(bytes)
    }

    /// Fixed header length (always 40)
    pub fn header_len(&self) -> usize {
        HEADER_SIZE
    }

    /// Payload (everything after 40-byte header)
    pub fn payload(&self) -> &[u8] {
        &self.buffer[HEADER_SIZE..]
    }

    /// Get raw header bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..HEADER_SIZE]
    }
}

/// Mutable IPv6 packet for modification (Hop Limit decrement, etc.)
///
/// Note: IPv6 has NO header checksum, so modifications are simpler than IPv4
#[derive(Debug, Clone)]
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
    /// Returns false if Hop Limit would become 0 (packet should be dropped)
    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.buffer[7] <= 1 {
            return false;
        }
        self.buffer[7] -= 1;
        // Note: No checksum update needed - IPv6 has no header checksum!
        true
    }

    /// Set Hop Limit
    pub fn set_hop_limit(&mut self, hop_limit: u8) {
        self.buffer[7] = hop_limit;
    }

    /// Get source address
    pub fn src_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer[8..24].try_into().unwrap();
        Ipv6Addr::from(bytes)
    }

    /// Get destination address
    pub fn dst_addr(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer[24..40].try_into().unwrap();
        Ipv6Addr::from(bytes)
    }

    /// Set source address
    pub fn set_src_addr(&mut self, addr: Ipv6Addr) {
        self.buffer[8..24].copy_from_slice(&addr.octets());
    }

    /// Set destination address
    pub fn set_dst_addr(&mut self, addr: Ipv6Addr) {
        self.buffer[24..40].copy_from_slice(&addr.octets());
    }

    /// Next Header field
    pub fn next_header(&self) -> u8 {
        self.buffer[6]
    }

    /// Payload length from header
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Get payload (after fixed 40-byte header)
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

    /// Get reference to buffer
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

    pub fn dscp(mut self, dscp: u8) -> Self {
        self.traffic_class = (dscp << 2) | (self.traffic_class & 0x03);
        self
    }

    pub fn ecn(mut self, ecn: u8) -> Self {
        self.traffic_class = (self.traffic_class & 0xFC) | (ecn & 0x03);
        self
    }

    pub fn flow_label(mut self, label: u32) -> Self {
        self.flow_label = label & 0xFFFFF; // 20 bits
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
        let payload_len = self.payload.len() as u16;
        let mut buffer = vec![0u8; HEADER_SIZE + self.payload.len()];

        // Version (6) + Traffic Class (upper 4 bits)
        buffer[0] = 0x60 | (self.traffic_class >> 4);

        // Traffic Class (lower 4 bits) + Flow Label (upper 4 bits)
        buffer[1] = (self.traffic_class << 4) | ((self.flow_label >> 16) as u8 & 0x0F);

        // Flow Label (remaining 16 bits)
        buffer[2] = (self.flow_label >> 8) as u8;
        buffer[3] = self.flow_label as u8;

        // Payload Length
        buffer[4..6].copy_from_slice(&payload_len.to_be_bytes());

        // Next Header
        buffer[6] = self.next_header;

        // Hop Limit
        buffer[7] = self.hop_limit;

        // Source Address (16 bytes)
        buffer[8..24].copy_from_slice(&self.src_addr.octets());

        // Destination Address (16 bytes)
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

/// Extension header information
#[derive(Debug, Clone)]
pub struct ExtensionHeader {
    /// Next Header value of this extension (type of this header)
    pub header_type: u8,
    /// Next Header value in this extension (points to next ext or upper layer)
    pub next_header: u8,
    /// Total length of this extension header in bytes
    pub length: usize,
}

/// Parse extension headers and find the upper-layer protocol
///
/// Returns (final_next_header, total_ext_header_length, list_of_ext_headers)
///
/// # Arguments
/// * `first_next_header` - The Next Header value from the IPv6 fixed header
/// * `payload` - The bytes after the fixed 40-byte IPv6 header
pub fn parse_extension_headers(
    first_next_header: u8,
    payload: &[u8],
) -> Result<(u8, usize, Vec<ExtensionHeader>)> {
    let mut extensions = Vec::new();
    let mut current_nh = first_next_header;
    let mut offset = 0;

    loop {
        // Check if current Next Header is an extension header
        if !NextHeader::is_extension_header(current_nh) {
            // Reached upper-layer protocol
            break;
        }

        // Parse extension header
        if offset + 2 > payload.len() {
            return Err(Error::Parse("Extension header truncated".into()));
        }

        let next_header = payload[offset];
        let ext_len = match current_nh {
            44 => {
                // Fragment header is always 8 bytes
                8
            }
            51 => {
                // AH header: (payload[offset+1] + 2) * 4 bytes
                let len_field = payload[offset + 1] as usize;
                (len_field + 2) * 4
            }
            _ => {
                // Other extension headers: (payload[offset+1] + 1) * 8 bytes
                let len_field = payload[offset + 1] as usize;
                (len_field + 1) * 8
            }
        };

        if offset + ext_len > payload.len() {
            return Err(Error::Parse(
                "Extension header extends beyond packet".into(),
            ));
        }

        extensions.push(ExtensionHeader {
            header_type: current_nh,
            next_header,
            length: ext_len,
        });

        offset += ext_len;
        current_nh = next_header;

        // Safety: prevent infinite loop
        if extensions.len() > 10 {
            return Err(Error::Parse("Too many extension headers".into()));
        }
    }

    Ok((current_nh, offset, extensions))
}

/// Fragment Header structure (8 bytes)
#[derive(Debug, Clone, Copy)]
pub struct FragmentHeader {
    pub next_header: u8,
    pub fragment_offset: u16, // 13 bits, in 8-byte units
    pub more_fragments: bool,
    pub identification: u32,
}

impl FragmentHeader {
    /// Fragment header size (always 8 bytes)
    pub const SIZE: usize = 8;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::Parse("Fragment header too short".into()));
        }

        let next_header = data[0];
        // data[1] is reserved
        let frag_off_m = u16::from_be_bytes([data[2], data[3]]);
        let fragment_offset = frag_off_m >> 3;
        let more_fragments = (frag_off_m & 0x01) != 0;
        let identification = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        Ok(Self {
            next_header,
            fragment_offset,
            more_fragments,
            identification,
        })
    }

    /// Check if this is a fragment (MF set or offset > 0)
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_ipv6_packet() -> Vec<u8> {
        // IPv6 packet: src=2001:db8::1, dst=2001:db8::2, Hop Limit=64, ICMPv6
        vec![
            // Version=6, Traffic Class=0, Flow Label=0
            0x60, 0x00, 0x00, 0x00, // Payload Length=8
            0x00, 0x08, // Next Header=58 (ICMPv6), Hop Limit=64
            0x3a, 0x40, // Source: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, // ICMPv6 Echo Request payload (8 bytes)
            0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ]
    }

    fn make_ipv6_with_hop_by_hop() -> Vec<u8> {
        // IPv6 packet with Hop-by-Hop Options extension header
        vec![
            // IPv6 Header
            0x60, 0x00, 0x00, 0x00, // Version=6, TC=0, Flow Label=0
            0x00, 0x10, // Payload Length=16 (8 ext + 8 payload)
            0x00, // Next Header=0 (Hop-by-Hop)
            0x40, // Hop Limit=64
            // Source: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, // Hop-by-Hop Options Header (8 bytes)
            0x3a, // Next Header=58 (ICMPv6)
            0x00, // Hdr Ext Len=0 -> (0+1)*8=8 bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
            // ICMPv6 payload (8 bytes)
            0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ]
    }

    fn make_ipv6_with_fragment() -> Vec<u8> {
        // IPv6 packet with Fragment header
        vec![
            // IPv6 Header
            0x60, 0x00, 0x00, 0x00, // Version=6, TC=0, Flow Label=0
            0x00, 0x10, // Payload Length=16 (8 frag + 8 payload)
            0x2c, // Next Header=44 (Fragment)
            0x40, // Hop Limit=64
            // Source: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, // Fragment Header (8 bytes)
            0x3a, // Next Header=58 (ICMPv6)
            0x00, // Reserved
            0x00, 0x01, // Fragment Offset=0, M=1 (more fragments)
            0x12, 0x34, 0x56, 0x78, // Identification
            // ICMPv6 payload (8 bytes)
            0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ]
    }

    // ============ NextHeader tests ============

    #[test]
    fn test_next_header_from_u8() {
        assert_eq!(NextHeader::from_u8(0), Some(NextHeader::HopByHop));
        assert_eq!(NextHeader::from_u8(6), Some(NextHeader::Tcp));
        assert_eq!(NextHeader::from_u8(17), Some(NextHeader::Udp));
        assert_eq!(NextHeader::from_u8(43), Some(NextHeader::Routing));
        assert_eq!(NextHeader::from_u8(44), Some(NextHeader::Fragment));
        assert_eq!(NextHeader::from_u8(50), Some(NextHeader::Esp));
        assert_eq!(NextHeader::from_u8(51), Some(NextHeader::Ah));
        assert_eq!(NextHeader::from_u8(58), Some(NextHeader::Icmpv6));
        assert_eq!(NextHeader::from_u8(59), Some(NextHeader::NoNextHeader));
        assert_eq!(
            NextHeader::from_u8(60),
            Some(NextHeader::DestinationOptions)
        );
        assert_eq!(NextHeader::from_u8(255), None);
    }

    #[test]
    fn test_next_header_is_extension() {
        assert!(NextHeader::is_extension_header(0)); // Hop-by-Hop
        assert!(NextHeader::is_extension_header(43)); // Routing
        assert!(NextHeader::is_extension_header(44)); // Fragment
        assert!(NextHeader::is_extension_header(51)); // AH
        assert!(NextHeader::is_extension_header(60)); // Destination Options
        assert!(!NextHeader::is_extension_header(6)); // TCP
        assert!(!NextHeader::is_extension_header(17)); // UDP
        assert!(!NextHeader::is_extension_header(58)); // ICMPv6
    }

    // ============ Ipv6Header parse tests ============

    #[test]
    fn test_parse_simple() {
        let data = make_simple_ipv6_packet();
        let hdr = Ipv6Header::parse(&data).unwrap();

        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.traffic_class(), 0);
        assert_eq!(hdr.dscp(), 0);
        assert_eq!(hdr.ecn(), 0);
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
    fn test_parse_too_short() {
        let short = vec![0u8; 39];
        assert!(Ipv6Header::parse(&short).is_err());
    }

    #[test]
    fn test_parse_wrong_version() {
        let mut data = make_simple_ipv6_packet();
        data[0] = 0x45; // Version 4
        assert!(Ipv6Header::parse(&data).is_err());
    }

    #[test]
    fn test_traffic_class() {
        // Traffic Class = 0xAB (DSCP=42, ECN=3)
        let mut data = make_simple_ipv6_packet();
        // Version (6) | TC upper 4 bits
        data[0] = 0x6A; // 0110 1010 -> Version=6, TC[7:4]=0xA
                        // TC lower 4 bits | Flow Label upper 4 bits
        data[1] = 0xB0; // 1011 0000 -> TC[3:0]=0xB, FL[19:16]=0

        let hdr = Ipv6Header::parse(&data).unwrap();
        assert_eq!(hdr.traffic_class(), 0xAB);
        assert_eq!(hdr.dscp(), 42); // 0xAB >> 2 = 42
        assert_eq!(hdr.ecn(), 3); // 0xAB & 0x03 = 3
    }

    #[test]
    fn test_flow_label() {
        let mut data = make_simple_ipv6_packet();
        // Set Flow Label to 0xABCDE (20 bits)
        data[1] = (data[1] & 0xF0) | 0x0A; // FL[19:16] = 0xA
        data[2] = 0xBC; // FL[15:8]
        data[3] = 0xDE; // FL[7:0]

        let hdr = Ipv6Header::parse(&data).unwrap();
        assert_eq!(hdr.flow_label(), 0xABCDE);
    }

    #[test]
    fn test_as_bytes() {
        let data = make_simple_ipv6_packet();
        let hdr = Ipv6Header::parse(&data).unwrap();
        assert_eq!(hdr.as_bytes().len(), 40);
        assert_eq!(hdr.as_bytes(), &data[..40]);
    }

    // ============ Ipv6Packet (mutable) tests ============

    #[test]
    fn test_packet_from_bytes() {
        let data = make_simple_ipv6_packet();
        let pkt = Ipv6Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.hop_limit(), 64);
        assert_eq!(pkt.next_header(), 58);
        assert_eq!(pkt.src_addr(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(pkt.dst_addr(), "2001:db8::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(pkt.payload_length(), 8);
    }

    #[test]
    fn test_packet_decrement_hop_limit() {
        let data = make_simple_ipv6_packet();
        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.hop_limit(), 64);
        assert!(pkt.decrement_hop_limit());
        assert_eq!(pkt.hop_limit(), 63);
    }

    #[test]
    fn test_packet_decrement_hop_limit_expires() {
        let mut data = make_simple_ipv6_packet();
        data[7] = 1; // Hop Limit=1

        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();
        assert_eq!(pkt.hop_limit(), 1);
        assert!(!pkt.decrement_hop_limit()); // Should return false
        assert_eq!(pkt.hop_limit(), 1); // Hop Limit unchanged
    }

    #[test]
    fn test_packet_decrement_hop_limit_zero() {
        let mut data = make_simple_ipv6_packet();
        data[7] = 0; // Hop Limit=0

        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();
        assert!(!pkt.decrement_hop_limit());
    }

    #[test]
    fn test_packet_set_hop_limit() {
        let data = make_simple_ipv6_packet();
        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();

        pkt.set_hop_limit(128);
        assert_eq!(pkt.hop_limit(), 128);
    }

    #[test]
    fn test_packet_set_addresses() {
        let data = make_simple_ipv6_packet();
        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();

        let new_src: Ipv6Addr = "2001:db8::100".parse().unwrap();
        let new_dst: Ipv6Addr = "2001:db8::200".parse().unwrap();

        pkt.set_src_addr(new_src);
        pkt.set_dst_addr(new_dst);

        assert_eq!(pkt.src_addr(), new_src);
        assert_eq!(pkt.dst_addr(), new_dst);
    }

    #[test]
    fn test_packet_payload() {
        let data = make_simple_ipv6_packet();
        let pkt = Ipv6Packet::from_bytes(&data).unwrap();

        assert_eq!(pkt.payload().len(), 8);
        assert_eq!(pkt.payload()[0], 0x80); // ICMPv6 Echo Request
    }

    #[test]
    fn test_packet_payload_mut() {
        let data = make_simple_ipv6_packet();
        let mut pkt = Ipv6Packet::from_bytes(&data).unwrap();

        pkt.payload_mut()[0] = 0x81; // Change to ICMPv6 Echo Reply
        assert_eq!(pkt.payload()[0], 0x81);
    }

    #[test]
    fn test_packet_into_bytes() {
        let data = make_simple_ipv6_packet();
        let pkt = Ipv6Packet::from_bytes(&data).unwrap();
        let bytes = pkt.into_bytes();
        assert_eq!(bytes, data);
    }

    // ============ Ipv6Builder tests ============

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
    fn test_builder_with_traffic_class() {
        let packet = Ipv6Builder::new().traffic_class(0xAB).build();

        let hdr = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(hdr.traffic_class(), 0xAB);
        assert_eq!(hdr.dscp(), 42);
        assert_eq!(hdr.ecn(), 3);
    }

    #[test]
    fn test_builder_with_dscp_ecn() {
        let packet = Ipv6Builder::new()
            .dscp(46) // EF (Expedited Forwarding)
            .ecn(2)
            .build();

        let hdr = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(hdr.dscp(), 46);
        assert_eq!(hdr.ecn(), 2);
    }

    #[test]
    fn test_builder_with_flow_label() {
        let packet = Ipv6Builder::new().flow_label(0xABCDE).build();

        let hdr = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(hdr.flow_label(), 0xABCDE);
    }

    #[test]
    fn test_builder_flow_label_mask() {
        // Flow label should be masked to 20 bits
        let packet = Ipv6Builder::new().flow_label(0xFFFFFFFF).build();

        let hdr = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(hdr.flow_label(), 0xFFFFF); // Only 20 bits
    }

    #[test]
    fn test_builder_default() {
        let builder = Ipv6Builder::default();
        let packet = builder.build();
        let hdr = Ipv6Header::parse(&packet).unwrap();

        assert_eq!(hdr.hop_limit(), 64);
        assert_eq!(hdr.traffic_class(), 0);
        assert_eq!(hdr.flow_label(), 0);
    }

    #[test]
    fn test_builder_roundtrip() {
        let original = Ipv6Builder::new()
            .src_addr("2001:db8::100".parse().unwrap())
            .dst_addr("2001:db8::200".parse().unwrap())
            .hop_limit(128)
            .next_header(NextHeader::Udp as u8)
            .traffic_class(0x12)
            .flow_label(0x12345)
            .payload(&[1, 2, 3, 4, 5, 6, 7, 8])
            .build();

        let hdr = Ipv6Header::parse(&original).unwrap();
        assert_eq!(hdr.src_addr(), "2001:db8::100".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hdr.dst_addr(), "2001:db8::200".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hdr.hop_limit(), 128);
        assert_eq!(hdr.next_header(), 17);
        assert_eq!(hdr.traffic_class(), 0x12);
        assert_eq!(hdr.flow_label(), 0x12345);
        assert_eq!(hdr.payload_length(), 8);
        assert_eq!(hdr.payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    // ============ Extension header tests ============

    #[test]
    fn test_parse_no_extensions() {
        let data = make_simple_ipv6_packet();
        let hdr = Ipv6Header::parse(&data).unwrap();

        let (final_nh, total_len, extensions) =
            parse_extension_headers(hdr.next_header(), hdr.payload()).unwrap();

        assert_eq!(final_nh, 58); // ICMPv6
        assert_eq!(total_len, 0);
        assert!(extensions.is_empty());
    }

    #[test]
    fn test_parse_hop_by_hop() {
        let data = make_ipv6_with_hop_by_hop();
        let hdr = Ipv6Header::parse(&data).unwrap();

        let (final_nh, total_len, extensions) =
            parse_extension_headers(hdr.next_header(), hdr.payload()).unwrap();

        assert_eq!(final_nh, 58); // ICMPv6
        assert_eq!(total_len, 8);
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].header_type, 0); // Hop-by-Hop
        assert_eq!(extensions[0].next_header, 58);
        assert_eq!(extensions[0].length, 8);
    }

    #[test]
    fn test_parse_fragment_header() {
        let data = make_ipv6_with_fragment();
        let hdr = Ipv6Header::parse(&data).unwrap();

        let (final_nh, total_len, extensions) =
            parse_extension_headers(hdr.next_header(), hdr.payload()).unwrap();

        assert_eq!(final_nh, 58); // ICMPv6
        assert_eq!(total_len, 8);
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].header_type, 44); // Fragment
        assert_eq!(extensions[0].length, 8);
    }

    #[test]
    fn test_parse_multiple_extensions() {
        // IPv6 with Hop-by-Hop -> Routing -> ICMPv6
        let data = vec![
            // IPv6 Header
            0x60, 0x00, 0x00, 0x00, // Version=6, TC=0, Flow Label=0
            0x00, 0x18, // Payload Length=24 (8+8+8)
            0x00, // Next Header=0 (Hop-by-Hop)
            0x40, // Hop Limit=64
            // Source: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Destination: ::2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, // Hop-by-Hop Options Header (8 bytes)
            0x2b, // Next Header=43 (Routing)
            0x00, // Hdr Ext Len=0 -> 8 bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Routing Header (8 bytes)
            0x3a, // Next Header=58 (ICMPv6)
            0x00, // Hdr Ext Len=0 -> 8 bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ICMPv6 payload (8 bytes)
            0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let hdr = Ipv6Header::parse(&data).unwrap();
        let (final_nh, total_len, extensions) =
            parse_extension_headers(hdr.next_header(), hdr.payload()).unwrap();

        assert_eq!(final_nh, 58); // ICMPv6
        assert_eq!(total_len, 16); // 8 + 8
        assert_eq!(extensions.len(), 2);
        assert_eq!(extensions[0].header_type, 0); // Hop-by-Hop
        assert_eq!(extensions[1].header_type, 43); // Routing
    }

    #[test]
    fn test_parse_truncated_extension() {
        // Only 1 byte of payload where extension header expected
        let data = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, // Header with NH=0 (Hop-by-Hop)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x3a, // Only 1 byte of payload
        ];

        let hdr = Ipv6Header::parse(&data).unwrap();
        let result = parse_extension_headers(hdr.next_header(), hdr.payload());
        assert!(result.is_err());
    }

    // ============ FragmentHeader tests ============

    #[test]
    fn test_fragment_header_parse() {
        let frag_data = vec![
            0x3a, // Next Header=58 (ICMPv6)
            0x00, // Reserved
            0x00, 0x09, // Fragment Offset=1, M=1
            0x12, 0x34, 0x56, 0x78, // Identification
        ];

        let frag = FragmentHeader::parse(&frag_data).unwrap();
        assert_eq!(frag.next_header, 58);
        assert_eq!(frag.fragment_offset, 1);
        assert!(frag.more_fragments);
        assert_eq!(frag.identification, 0x12345678);
        assert!(frag.is_fragment());
    }

    #[test]
    fn test_fragment_header_last_fragment() {
        let frag_data = vec![
            0x3a, // Next Header=58 (ICMPv6)
            0x00, // Reserved
            0x01, 0x00, // Fragment Offset=32 (0x100 >> 3 = 32), M=0
            0x12, 0x34, 0x56, 0x78,
        ];

        let frag = FragmentHeader::parse(&frag_data).unwrap();
        assert_eq!(frag.fragment_offset, 32);
        assert!(!frag.more_fragments);
        assert!(frag.is_fragment()); // offset > 0
    }

    #[test]
    fn test_fragment_header_not_fragment() {
        let frag_data = vec![
            0x3a, // Next Header=58 (ICMPv6)
            0x00, // Reserved
            0x00, 0x00, // Fragment Offset=0, M=0
            0x12, 0x34, 0x56, 0x78,
        ];

        let frag = FragmentHeader::parse(&frag_data).unwrap();
        assert_eq!(frag.fragment_offset, 0);
        assert!(!frag.more_fragments);
        assert!(!frag.is_fragment());
    }

    #[test]
    fn test_fragment_header_too_short() {
        let short = vec![0x3a, 0x00, 0x00];
        assert!(FragmentHeader::parse(&short).is_err());
    }
}

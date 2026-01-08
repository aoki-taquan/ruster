//! ICMP (Internet Control Message Protocol) - RFC 792

use crate::{Error, Result};

/// ICMP header size (minimum)
pub const ICMP_HEADER_SIZE: usize = 8;

/// ICMP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    Redirect = 5,
    EchoRequest = 8,
    TimeExceeded = 11,
    ParameterProblem = 12,
}

impl IcmpType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(IcmpType::EchoReply),
            3 => Some(IcmpType::DestinationUnreachable),
            5 => Some(IcmpType::Redirect),
            8 => Some(IcmpType::EchoRequest),
            11 => Some(IcmpType::TimeExceeded),
            12 => Some(IcmpType::ParameterProblem),
            _ => None,
        }
    }
}

/// Destination Unreachable codes (RFC 792)
pub mod dest_unreachable {
    /// Network unreachable
    pub const NET_UNREACHABLE: u8 = 0;
    /// Host unreachable
    pub const HOST_UNREACHABLE: u8 = 1;
    /// Protocol unreachable
    pub const PROTOCOL_UNREACHABLE: u8 = 2;
    /// Port unreachable
    pub const PORT_UNREACHABLE: u8 = 3;
    /// Fragmentation needed but DF set
    pub const FRAGMENTATION_NEEDED: u8 = 4;
    /// Source route failed
    pub const SOURCE_ROUTE_FAILED: u8 = 5;
    /// Destination network unknown
    pub const NET_UNKNOWN: u8 = 6;
    /// Destination host unknown
    pub const HOST_UNKNOWN: u8 = 7;
    /// Source host isolated
    pub const SOURCE_ISOLATED: u8 = 8;
    /// Network administratively prohibited
    pub const NET_PROHIBITED: u8 = 9;
    /// Host administratively prohibited
    pub const HOST_PROHIBITED: u8 = 10;
    /// Network unreachable for ToS
    pub const NET_UNREACHABLE_TOS: u8 = 11;
    /// Host unreachable for ToS
    pub const HOST_UNREACHABLE_TOS: u8 = 12;
    /// Communication administratively prohibited
    pub const COMM_PROHIBITED: u8 = 13;
}

/// Time Exceeded codes (RFC 792)
pub mod time_exceeded {
    /// TTL exceeded in transit
    pub const TTL_EXCEEDED: u8 = 0;
    /// Fragment reassembly time exceeded
    pub const FRAGMENT_REASSEMBLY: u8 = 1;
}

/// Parameter Problem codes (RFC 792)
pub mod parameter_problem {
    /// Pointer indicates the error
    pub const POINTER_ERROR: u8 = 0;
    /// Missing required option
    pub const MISSING_OPTION: u8 = 1;
    /// Bad length
    pub const BAD_LENGTH: u8 = 2;
}

/// Parsed ICMP message
#[derive(Debug)]
pub struct IcmpPacket<'a> {
    buffer: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Parse("ICMP packet too short".into()));
        }

        Ok(Self { buffer })
    }

    pub fn icmp_type(&self) -> u8 {
        self.buffer[0]
    }

    pub fn code(&self) -> u8 {
        self.buffer[1]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// For Echo Request/Reply: identifier
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// For Echo Request/Reply: sequence number
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.buffer[8..]
    }

    /// Get the raw buffer
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Validate the ICMP checksum
    pub fn validate_checksum(&self) -> bool {
        icmp_checksum(self.buffer) == 0
    }

    /// Get the typed ICMP message type
    pub fn message_type(&self) -> Option<IcmpType> {
        IcmpType::from_u8(self.icmp_type())
    }

    /// Check if this is an Echo Request
    pub fn is_echo_request(&self) -> bool {
        self.icmp_type() == IcmpType::EchoRequest as u8
    }

    /// Check if this is an Echo Reply
    pub fn is_echo_reply(&self) -> bool {
        self.icmp_type() == IcmpType::EchoReply as u8
    }

    /// For error messages: get the original IP header + 8 bytes
    /// (Destination Unreachable, Time Exceeded, etc.)
    pub fn original_datagram(&self) -> &[u8] {
        // Error messages have: Type(1) + Code(1) + Checksum(2) + Unused(4) + Original data
        &self.buffer[8..]
    }
}

/// Build an ICMP Echo Reply from an Echo Request
pub fn build_echo_reply(request: &[u8]) -> Result<Vec<u8>> {
    if request.len() < 8 {
        return Err(Error::Parse("ICMP request too short".into()));
    }

    let mut reply = request.to_vec();

    // Change type from Echo Request (8) to Echo Reply (0)
    reply[0] = IcmpType::EchoReply as u8;

    // Clear checksum field
    reply[2] = 0;
    reply[3] = 0;

    // Calculate new checksum
    let checksum = icmp_checksum(&reply);
    reply[2..4].copy_from_slice(&checksum.to_be_bytes());

    Ok(reply)
}

/// Calculate ICMP checksum
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            u16::from_be_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Build a Destination Unreachable message
///
/// # Arguments
/// * `code` - The unreachable code (see `dest_unreachable` module)
/// * `original_header` - The original IP header that caused the error
/// * `original_payload` - The first 8 bytes of the original datagram payload
/// * `mtu` - For FRAGMENTATION_NEEDED (code 4), the next-hop MTU; otherwise 0
///
/// Returns the complete ICMP message
pub fn build_destination_unreachable(
    code: u8,
    original_header: &[u8],
    original_payload: &[u8],
    mtu: u16,
) -> Vec<u8> {
    // ICMP Destination Unreachable format:
    // Type (1) + Code (1) + Checksum (2) + Unused/MTU (4) + Original IP header + 8 bytes
    let payload_len = original_payload.len().min(8);
    let total_len = 8 + original_header.len() + payload_len;
    let mut packet = vec![0u8; total_len];

    // Type: Destination Unreachable (3)
    packet[0] = IcmpType::DestinationUnreachable as u8;
    // Code
    packet[1] = code;
    // Checksum: will be calculated later
    packet[2] = 0;
    packet[3] = 0;

    // For FRAGMENTATION_NEEDED, bytes 6-7 contain the next-hop MTU
    if code == dest_unreachable::FRAGMENTATION_NEEDED {
        packet[6..8].copy_from_slice(&mtu.to_be_bytes());
    }
    // Otherwise bytes 4-7 are unused (already zero)

    // Copy original IP header
    packet[8..8 + original_header.len()].copy_from_slice(original_header);

    // Copy first 8 bytes of original payload
    packet[8 + original_header.len()..].copy_from_slice(&original_payload[..payload_len]);

    // Calculate checksum
    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());

    packet
}

/// Build a Time Exceeded message
///
/// # Arguments
/// * `code` - The time exceeded code (see `time_exceeded` module)
/// * `original_header` - The original IP header that caused the error
/// * `original_payload` - The first 8 bytes of the original datagram payload
///
/// Returns the complete ICMP message
pub fn build_time_exceeded(code: u8, original_header: &[u8], original_payload: &[u8]) -> Vec<u8> {
    // ICMP Time Exceeded format:
    // Type (1) + Code (1) + Checksum (2) + Unused (4) + Original IP header + 8 bytes
    let payload_len = original_payload.len().min(8);
    let total_len = 8 + original_header.len() + payload_len;
    let mut packet = vec![0u8; total_len];

    // Type: Time Exceeded (11)
    packet[0] = IcmpType::TimeExceeded as u8;
    // Code
    packet[1] = code;
    // Checksum: will be calculated later
    packet[2] = 0;
    packet[3] = 0;
    // Bytes 4-7 are unused (already zero)

    // Copy original IP header
    packet[8..8 + original_header.len()].copy_from_slice(original_header);

    // Copy first 8 bytes of original payload
    packet[8 + original_header.len()..].copy_from_slice(&original_payload[..payload_len]);

    // Calculate checksum
    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());

    packet
}

/// Build a Parameter Problem message
///
/// # Arguments
/// * `code` - The parameter problem code (see `parameter_problem` module)
/// * `pointer` - Byte offset in the original IP header where the error was detected
/// * `original_header` - The original IP header that caused the error
/// * `original_payload` - The first 8 bytes of the original datagram payload
///
/// Returns the complete ICMP message
pub fn build_parameter_problem(
    code: u8,
    pointer: u8,
    original_header: &[u8],
    original_payload: &[u8],
) -> Vec<u8> {
    // ICMP Parameter Problem format:
    // Type (1) + Code (1) + Checksum (2) + Pointer (1) + Unused (3) + Original IP header + 8 bytes
    let payload_len = original_payload.len().min(8);
    let total_len = 8 + original_header.len() + payload_len;
    let mut packet = vec![0u8; total_len];

    // Type: Parameter Problem (12)
    packet[0] = IcmpType::ParameterProblem as u8;
    // Code
    packet[1] = code;
    // Checksum: will be calculated later
    packet[2] = 0;
    packet[3] = 0;
    // Pointer: byte offset where the error was detected
    packet[4] = pointer;
    // Bytes 5-7 are unused (already zero)

    // Copy original IP header
    packet[8..8 + original_header.len()].copy_from_slice(original_header);

    // Copy first 8 bytes of original payload
    packet[8 + original_header.len()..].copy_from_slice(&original_payload[..payload_len]);

    // Calculate checksum
    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());

    packet
}

/// Mutable ICMP packet for NAPT modifications (RFC 5508)
///
/// Used to modify ICMP Echo Request/Reply identifier for NAT traversal.
#[derive(Debug, Clone)]
pub struct IcmpMutablePacket {
    buffer: Vec<u8>,
}

impl IcmpMutablePacket {
    /// Create from raw bytes (copies the data)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < ICMP_HEADER_SIZE {
            return Err(Error::Parse("ICMP packet too short".into()));
        }

        Ok(Self {
            buffer: data.to_vec(),
        })
    }

    /// ICMP type
    pub fn icmp_type(&self) -> u8 {
        self.buffer[0]
    }

    /// ICMP code
    pub fn code(&self) -> u8 {
        self.buffer[1]
    }

    /// Get identifier (for Echo Request/Reply)
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Set identifier and update checksum (for NAPT)
    pub fn set_identifier(&mut self, id: u16) {
        self.buffer[4..6].copy_from_slice(&id.to_be_bytes());
        self.update_checksum();
    }

    /// Get sequence number (for Echo Request/Reply)
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    /// Get checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Update checksum
    pub fn update_checksum(&mut self) {
        // Zero out checksum field
        self.buffer[2] = 0;
        self.buffer[3] = 0;

        let sum = icmp_checksum(&self.buffer);
        self.buffer[2..4].copy_from_slice(&sum.to_be_bytes());
    }

    /// Check if this is an Echo Request
    pub fn is_echo_request(&self) -> bool {
        self.icmp_type() == IcmpType::EchoRequest as u8
    }

    /// Check if this is an Echo Reply
    pub fn is_echo_reply(&self) -> bool {
        self.icmp_type() == IcmpType::EchoReply as u8
    }

    /// Check if this is an Echo (Request or Reply) - NAPT can translate these
    pub fn is_echo(&self) -> bool {
        self.is_echo_request() || self.is_echo_reply()
    }

    /// Consume and return the buffer
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Get reference to buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Validate checksum
    pub fn validate_checksum(&self) -> bool {
        icmp_checksum(&self.buffer) == 0
    }
}

/// Builder for ICMP Echo Request packets
#[derive(Debug, Clone)]
pub struct EchoRequestBuilder {
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

impl EchoRequestBuilder {
    /// Create a new Echo Request builder
    pub fn new(identifier: u16, sequence: u16) -> Self {
        Self {
            identifier,
            sequence,
            payload: Vec::new(),
        }
    }

    /// Set the payload data
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    /// Build the ICMP Echo Request packet
    pub fn build(self) -> Vec<u8> {
        let total_len = 8 + self.payload.len();
        let mut packet = vec![0u8; total_len];

        // Type: Echo Request (8)
        packet[0] = IcmpType::EchoRequest as u8;
        // Code: 0
        packet[1] = 0;
        // Checksum: will be calculated later
        packet[2] = 0;
        packet[3] = 0;
        // Identifier
        packet[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        // Sequence number
        packet[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        // Payload
        packet[8..].copy_from_slice(&self.payload);

        // Calculate checksum
        let checksum = icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create an Echo Request packet
    fn make_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 8 + payload.len()];
        packet[0] = IcmpType::EchoRequest as u8;
        packet[1] = 0;
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        packet[8..].copy_from_slice(payload);
        let checksum = icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    // Helper to create a minimal IP header (20 bytes)
    fn make_ip_header() -> Vec<u8> {
        let mut header = vec![0u8; 20];
        header[0] = 0x45; // Version 4, IHL 5
        header[8] = 64; // TTL
        header[9] = 1; // Protocol: ICMP
                       // Source: 192.168.1.1
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        // Dest: 192.168.1.2
        header[16..20].copy_from_slice(&[192, 168, 1, 2]);
        header
    }

    // ==================== IcmpType tests ====================

    #[test]
    fn test_icmp_type_from_u8() {
        assert_eq!(IcmpType::from_u8(0), Some(IcmpType::EchoReply));
        assert_eq!(IcmpType::from_u8(3), Some(IcmpType::DestinationUnreachable));
        assert_eq!(IcmpType::from_u8(5), Some(IcmpType::Redirect));
        assert_eq!(IcmpType::from_u8(8), Some(IcmpType::EchoRequest));
        assert_eq!(IcmpType::from_u8(11), Some(IcmpType::TimeExceeded));
        assert_eq!(IcmpType::from_u8(12), Some(IcmpType::ParameterProblem));
        assert_eq!(IcmpType::from_u8(99), None);
    }

    // ==================== IcmpPacket tests ====================

    #[test]
    fn test_parse_echo_request() {
        let packet = make_echo_request(0x1234, 0x0001, b"hello");
        let parsed = IcmpPacket::parse(&packet).unwrap();

        assert_eq!(parsed.icmp_type(), IcmpType::EchoRequest as u8);
        assert_eq!(parsed.code(), 0);
        assert_eq!(parsed.identifier(), 0x1234);
        assert_eq!(parsed.sequence(), 0x0001);
        assert_eq!(parsed.payload(), b"hello");
    }

    #[test]
    fn test_parse_too_short() {
        let short = [0u8; 7];
        assert!(IcmpPacket::parse(&short).is_err());
    }

    #[test]
    fn test_parse_minimum_size() {
        let packet = make_echo_request(0, 0, &[]);
        assert!(IcmpPacket::parse(&packet).is_ok());
    }

    #[test]
    fn test_validate_checksum_valid() {
        let packet = make_echo_request(0x1234, 0x0001, b"hello");
        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert!(parsed.validate_checksum());
    }

    #[test]
    fn test_validate_checksum_invalid() {
        let mut packet = make_echo_request(0x1234, 0x0001, b"hello");
        packet[8] ^= 0xFF; // Corrupt payload
        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert!(!parsed.validate_checksum());
    }

    #[test]
    fn test_message_type() {
        let packet = make_echo_request(0, 0, &[]);
        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.message_type(), Some(IcmpType::EchoRequest));
    }

    #[test]
    fn test_is_echo_request() {
        let packet = make_echo_request(0, 0, &[]);
        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert!(parsed.is_echo_request());
        assert!(!parsed.is_echo_reply());
    }

    #[test]
    fn test_as_bytes() {
        let packet = make_echo_request(0x1234, 0x0001, b"test");
        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.as_bytes(), packet.as_slice());
    }

    // ==================== build_echo_reply tests ====================

    #[test]
    fn test_build_echo_reply() {
        let request = make_echo_request(0x1234, 0x0001, b"hello");
        let reply = build_echo_reply(&request).unwrap();

        let parsed = IcmpPacket::parse(&reply).unwrap();
        assert_eq!(parsed.icmp_type(), IcmpType::EchoReply as u8);
        assert_eq!(parsed.code(), 0);
        assert_eq!(parsed.identifier(), 0x1234);
        assert_eq!(parsed.sequence(), 0x0001);
        assert_eq!(parsed.payload(), b"hello");
        assert!(parsed.validate_checksum());
    }

    #[test]
    fn test_build_echo_reply_too_short() {
        let short = [0u8; 7];
        assert!(build_echo_reply(&short).is_err());
    }

    #[test]
    fn test_build_echo_reply_preserves_payload() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let request = make_echo_request(0x5678, 0x0002, &payload);
        let reply = build_echo_reply(&request).unwrap();

        let parsed = IcmpPacket::parse(&reply).unwrap();
        assert_eq!(parsed.payload(), &payload);
    }

    // ==================== icmp_checksum tests ====================

    #[test]
    fn test_checksum_zero_data() {
        // All zeros should give checksum 0xFFFF
        let data = [0u8; 8];
        assert_eq!(icmp_checksum(&data), 0xFFFF);
    }

    #[test]
    fn test_checksum_odd_length() {
        // Odd length should still work
        let data = [0x01, 0x02, 0x03];
        let checksum = icmp_checksum(&data);
        // Verify by recalculating with checksum included
        let mut verify = data.to_vec();
        verify.push(0);
        verify.push(0);
        verify[3] = (checksum >> 8) as u8;
        verify[4] = (checksum & 0xFF) as u8;
        // The sum including checksum should give 0 (after folding)
    }

    #[test]
    fn test_checksum_roundtrip() {
        let packet = make_echo_request(0x1234, 0x0001, b"test data");
        // Checksum of valid packet should be 0
        assert_eq!(icmp_checksum(&packet), 0);
    }

    // ==================== build_destination_unreachable tests ====================

    #[test]
    fn test_build_destination_unreachable_host() {
        let ip_header = make_ip_header();
        let original_payload = [1, 2, 3, 4, 5, 6, 7, 8];

        let packet = build_destination_unreachable(
            dest_unreachable::HOST_UNREACHABLE,
            &ip_header,
            &original_payload,
            0,
        );

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.icmp_type(), IcmpType::DestinationUnreachable as u8);
        assert_eq!(parsed.code(), dest_unreachable::HOST_UNREACHABLE);
        assert!(parsed.validate_checksum());

        // Check that original datagram is included
        let original = parsed.original_datagram();
        assert_eq!(&original[..20], ip_header.as_slice());
        assert_eq!(&original[20..28], &original_payload);
    }

    #[test]
    fn test_build_destination_unreachable_port() {
        let ip_header = make_ip_header();
        let original_payload = [0u8; 8];

        let packet = build_destination_unreachable(
            dest_unreachable::PORT_UNREACHABLE,
            &ip_header,
            &original_payload,
            0,
        );

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), dest_unreachable::PORT_UNREACHABLE);
        assert!(parsed.validate_checksum());
    }

    #[test]
    fn test_build_destination_unreachable_fragmentation_needed() {
        let ip_header = make_ip_header();
        let original_payload = [0u8; 8];
        let mtu = 1280u16;

        let packet = build_destination_unreachable(
            dest_unreachable::FRAGMENTATION_NEEDED,
            &ip_header,
            &original_payload,
            mtu,
        );

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), dest_unreachable::FRAGMENTATION_NEEDED);
        assert!(parsed.validate_checksum());

        // Check MTU is in bytes 6-7
        let raw = parsed.as_bytes();
        let stored_mtu = u16::from_be_bytes([raw[6], raw[7]]);
        assert_eq!(stored_mtu, mtu);
    }

    #[test]
    fn test_build_destination_unreachable_short_payload() {
        let ip_header = make_ip_header();
        let original_payload = [1, 2, 3]; // Less than 8 bytes

        let packet = build_destination_unreachable(
            dest_unreachable::NET_UNREACHABLE,
            &ip_header,
            &original_payload,
            0,
        );

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert!(parsed.validate_checksum());

        // Only 3 bytes of original payload should be included
        let original = parsed.original_datagram();
        assert_eq!(original.len(), 20 + 3);
    }

    // ==================== build_time_exceeded tests ====================

    #[test]
    fn test_build_time_exceeded_ttl() {
        let ip_header = make_ip_header();
        let original_payload = [1, 2, 3, 4, 5, 6, 7, 8];

        let packet =
            build_time_exceeded(time_exceeded::TTL_EXCEEDED, &ip_header, &original_payload);

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.icmp_type(), IcmpType::TimeExceeded as u8);
        assert_eq!(parsed.code(), time_exceeded::TTL_EXCEEDED);
        assert!(parsed.validate_checksum());

        // Check that original datagram is included
        let original = parsed.original_datagram();
        assert_eq!(&original[..20], ip_header.as_slice());
        assert_eq!(&original[20..28], &original_payload);
    }

    #[test]
    fn test_build_time_exceeded_fragment_reassembly() {
        let ip_header = make_ip_header();
        let original_payload = [0u8; 8];

        let packet = build_time_exceeded(
            time_exceeded::FRAGMENT_REASSEMBLY,
            &ip_header,
            &original_payload,
        );

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), time_exceeded::FRAGMENT_REASSEMBLY);
        assert!(parsed.validate_checksum());
    }

    // ==================== EchoRequestBuilder tests ====================

    #[test]
    fn test_echo_request_builder_basic() {
        let packet = EchoRequestBuilder::new(0x1234, 0x0001).build();

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.icmp_type(), IcmpType::EchoRequest as u8);
        assert_eq!(parsed.code(), 0);
        assert_eq!(parsed.identifier(), 0x1234);
        assert_eq!(parsed.sequence(), 0x0001);
        assert!(parsed.payload().is_empty());
        assert!(parsed.validate_checksum());
    }

    #[test]
    fn test_echo_request_builder_with_payload() {
        let payload = b"ping test data";
        let packet = EchoRequestBuilder::new(0xABCD, 0x0005)
            .payload(payload)
            .build();

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.identifier(), 0xABCD);
        assert_eq!(parsed.sequence(), 0x0005);
        assert_eq!(parsed.payload(), payload);
        assert!(parsed.validate_checksum());
    }

    #[test]
    fn test_echo_request_builder_roundtrip() {
        let request = EchoRequestBuilder::new(0x5678, 0x000A)
            .payload(b"roundtrip test")
            .build();

        let reply = build_echo_reply(&request).unwrap();

        let parsed_reply = IcmpPacket::parse(&reply).unwrap();
        assert!(parsed_reply.is_echo_reply());
        assert_eq!(parsed_reply.identifier(), 0x5678);
        assert_eq!(parsed_reply.sequence(), 0x000A);
        assert_eq!(parsed_reply.payload(), b"roundtrip test");
        assert!(parsed_reply.validate_checksum());
    }

    // ==================== Code constants tests ====================

    #[test]
    fn test_dest_unreachable_codes() {
        assert_eq!(dest_unreachable::NET_UNREACHABLE, 0);
        assert_eq!(dest_unreachable::HOST_UNREACHABLE, 1);
        assert_eq!(dest_unreachable::PROTOCOL_UNREACHABLE, 2);
        assert_eq!(dest_unreachable::PORT_UNREACHABLE, 3);
        assert_eq!(dest_unreachable::FRAGMENTATION_NEEDED, 4);
        assert_eq!(dest_unreachable::SOURCE_ROUTE_FAILED, 5);
    }

    #[test]
    fn test_time_exceeded_codes() {
        assert_eq!(time_exceeded::TTL_EXCEEDED, 0);
        assert_eq!(time_exceeded::FRAGMENT_REASSEMBLY, 1);
    }

    #[test]
    fn test_parameter_problem_codes() {
        assert_eq!(parameter_problem::POINTER_ERROR, 0);
        assert_eq!(parameter_problem::MISSING_OPTION, 1);
        assert_eq!(parameter_problem::BAD_LENGTH, 2);
    }

    // ==================== build_parameter_problem tests ====================

    #[test]
    fn test_build_parameter_problem_pointer_error() {
        let ip_header = make_ip_header();
        let original_payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let pointer = 9u8; // Pointing to protocol field

        let packet = build_parameter_problem(
            parameter_problem::POINTER_ERROR,
            pointer,
            &ip_header,
            &original_payload,
        );

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.icmp_type(), IcmpType::ParameterProblem as u8);
        assert_eq!(parsed.code(), parameter_problem::POINTER_ERROR);
        assert!(parsed.validate_checksum());

        // Check pointer is in byte 4
        let raw = parsed.as_bytes();
        assert_eq!(raw[4], pointer);

        // Check that original datagram is included
        let original = parsed.original_datagram();
        assert_eq!(&original[..20], ip_header.as_slice());
        assert_eq!(&original[20..28], &original_payload);
    }

    #[test]
    fn test_build_parameter_problem_bad_length() {
        let ip_header = make_ip_header();
        let original_payload = [0u8; 8];
        let pointer = 2u8; // Pointing to total length field

        let packet = build_parameter_problem(
            parameter_problem::BAD_LENGTH,
            pointer,
            &ip_header,
            &original_payload,
        );

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), parameter_problem::BAD_LENGTH);
        assert!(parsed.validate_checksum());

        let raw = parsed.as_bytes();
        assert_eq!(raw[4], pointer);
    }

    // ==================== Edge cases ====================

    #[test]
    fn test_large_payload() {
        let payload = vec![0xAA; 1000];
        let request = EchoRequestBuilder::new(1, 1).payload(&payload).build();

        let parsed = IcmpPacket::parse(&request).unwrap();
        assert_eq!(parsed.payload().len(), 1000);
        assert!(parsed.validate_checksum());
    }

    #[test]
    fn test_empty_original_payload() {
        let ip_header = make_ip_header();
        let original_payload: [u8; 0] = [];

        let packet =
            build_time_exceeded(time_exceeded::TTL_EXCEEDED, &ip_header, &original_payload);

        let parsed = IcmpPacket::parse(&packet).unwrap();
        assert!(parsed.validate_checksum());
        // Only IP header should be in original datagram
        assert_eq!(parsed.original_datagram().len(), 20);
    }

    // ==================== IcmpMutablePacket tests ====================

    #[test]
    fn test_icmp_mutable_from_bytes() {
        let request = make_echo_request(0x1234, 0x0001, b"test");
        let pkt = IcmpMutablePacket::from_bytes(&request).unwrap();

        assert_eq!(pkt.icmp_type(), IcmpType::EchoRequest as u8);
        assert_eq!(pkt.code(), 0);
        assert_eq!(pkt.identifier(), 0x1234);
        assert_eq!(pkt.sequence(), 0x0001);
        assert!(pkt.validate_checksum());
    }

    #[test]
    fn test_icmp_mutable_from_bytes_too_short() {
        let short = vec![0u8; 7];
        assert!(IcmpMutablePacket::from_bytes(&short).is_err());
    }

    #[test]
    fn test_icmp_mutable_set_identifier() {
        let request = make_echo_request(0x1234, 0x0001, b"test");
        let mut pkt = IcmpMutablePacket::from_bytes(&request).unwrap();

        assert_eq!(pkt.identifier(), 0x1234);
        pkt.set_identifier(0x5678);
        assert_eq!(pkt.identifier(), 0x5678);

        // Checksum should still be valid
        assert!(pkt.validate_checksum());
    }

    #[test]
    fn test_icmp_mutable_is_echo() {
        let request = make_echo_request(0x1234, 0x0001, &[]);
        let pkt = IcmpMutablePacket::from_bytes(&request).unwrap();
        assert!(pkt.is_echo_request());
        assert!(pkt.is_echo());
        assert!(!pkt.is_echo_reply());

        // Create echo reply
        let reply = build_echo_reply(&request).unwrap();
        let pkt_reply = IcmpMutablePacket::from_bytes(&reply).unwrap();
        assert!(pkt_reply.is_echo_reply());
        assert!(pkt_reply.is_echo());
        assert!(!pkt_reply.is_echo_request());
    }

    #[test]
    fn test_icmp_mutable_into_bytes() {
        let request = make_echo_request(0x1234, 0x0001, b"data");
        let pkt = IcmpMutablePacket::from_bytes(&request).unwrap();
        let bytes = pkt.into_bytes();
        assert_eq!(bytes, request);
    }

    #[test]
    fn test_icmp_mutable_roundtrip_modification() {
        // Simulate NAPT: change identifier, verify checksum
        let original = make_echo_request(0x1000, 0x0001, b"ping");
        let mut pkt = IcmpMutablePacket::from_bytes(&original).unwrap();

        // NAT changes the identifier
        pkt.set_identifier(0x2000);

        // Verify the modified packet is valid
        let modified = pkt.into_bytes();
        let verified = IcmpMutablePacket::from_bytes(&modified).unwrap();
        assert_eq!(verified.identifier(), 0x2000);
        assert!(verified.validate_checksum());
    }
}

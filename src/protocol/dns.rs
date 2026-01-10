//! DNS protocol - RFC 1035
//!
//! DNS message parsing and building for DNS forwarder functionality.

use crate::{Error, Result};

/// DNS server/client port
pub const DNS_PORT: u16 = 53;

/// DNS header size (fixed at 12 bytes)
pub const DNS_HEADER_SIZE: usize = 12;

/// Maximum UDP DNS message size (RFC 1035)
pub const MAX_UDP_SIZE: usize = 512;

/// DNS operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsOpcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
}

impl DnsOpcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(DnsOpcode::Query),
            1 => Some(DnsOpcode::IQuery),
            2 => Some(DnsOpcode::Status),
            _ => None,
        }
    }
}

/// DNS response codes (RCODE)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsRcode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl DnsRcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(DnsRcode::NoError),
            1 => Some(DnsRcode::FormatError),
            2 => Some(DnsRcode::ServerFailure),
            3 => Some(DnsRcode::NameError),
            4 => Some(DnsRcode::NotImplemented),
            5 => Some(DnsRcode::Refused),
            _ => None,
        }
    }
}

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    ANY = 255,
}

impl DnsType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(DnsType::A),
            2 => Some(DnsType::NS),
            5 => Some(DnsType::CNAME),
            6 => Some(DnsType::SOA),
            12 => Some(DnsType::PTR),
            15 => Some(DnsType::MX),
            16 => Some(DnsType::TXT),
            28 => Some(DnsType::AAAA),
            33 => Some(DnsType::SRV),
            255 => Some(DnsType::ANY),
            _ => None,
        }
    }
}

/// DNS record class
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsClass {
    IN = 1,
    CH = 3,
    HS = 4,
    ANY = 255,
}

impl DnsClass {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(DnsClass::IN),
            3 => Some(DnsClass::CH),
            4 => Some(DnsClass::HS),
            255 => Some(DnsClass::ANY),
            _ => None,
        }
    }
}

/// Parsed DNS question
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Parsed DNS resource record
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// Zero-copy DNS header parser
#[derive(Debug)]
pub struct DnsHeader<'a> {
    buffer: &'a [u8],
}

impl<'a> DnsHeader<'a> {
    /// Parse DNS header from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < DNS_HEADER_SIZE {
            return Err(Error::Parse("DNS header too short".into()));
        }
        Ok(Self { buffer })
    }

    /// Transaction ID (offset 0-1)
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    /// Flags (offset 2-3)
    fn flags(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Query/Response flag (bit 15)
    /// false = query, true = response
    pub fn is_response(&self) -> bool {
        self.flags() & 0x8000 != 0
    }

    /// Is this a query?
    pub fn is_query(&self) -> bool {
        !self.is_response()
    }

    /// Opcode (bits 11-14)
    pub fn opcode(&self) -> u8 {
        ((self.flags() >> 11) & 0x0F) as u8
    }

    /// Authoritative Answer flag (bit 10)
    pub fn is_authoritative(&self) -> bool {
        self.flags() & 0x0400 != 0
    }

    /// Truncated flag (bit 9)
    pub fn is_truncated(&self) -> bool {
        self.flags() & 0x0200 != 0
    }

    /// Recursion Desired flag (bit 8)
    pub fn recursion_desired(&self) -> bool {
        self.flags() & 0x0100 != 0
    }

    /// Recursion Available flag (bit 7)
    pub fn recursion_available(&self) -> bool {
        self.flags() & 0x0080 != 0
    }

    /// Response code (bits 0-3)
    pub fn rcode(&self) -> u8 {
        (self.flags() & 0x000F) as u8
    }

    /// Question count (offset 4-5)
    pub fn question_count(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Answer count (offset 6-7)
    pub fn answer_count(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    /// Authority count (offset 8-9)
    pub fn authority_count(&self) -> u16 {
        u16::from_be_bytes([self.buffer[8], self.buffer[9]])
    }

    /// Additional count (offset 10-11)
    pub fn additional_count(&self) -> u16 {
        u16::from_be_bytes([self.buffer[10], self.buffer[11]])
    }

    /// Raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }
}

/// Mutable DNS packet for manipulation
#[derive(Debug, Clone)]
pub struct DnsPacket {
    buffer: Vec<u8>,
}

impl DnsPacket {
    /// Create from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < DNS_HEADER_SIZE {
            return Err(Error::Parse("DNS packet too short".into()));
        }
        Ok(Self {
            buffer: data.to_vec(),
        })
    }

    /// Transaction ID
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    /// Set transaction ID
    pub fn set_id(&mut self, id: u16) {
        self.buffer[0..2].copy_from_slice(&id.to_be_bytes());
    }

    /// Is this a response?
    pub fn is_response(&self) -> bool {
        self.buffer[2] & 0x80 != 0
    }

    /// Question count
    pub fn question_count(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// Answer count
    pub fn answer_count(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    /// Response code
    pub fn rcode(&self) -> u8 {
        self.buffer[3] & 0x0F
    }

    /// Parse questions from the packet
    pub fn questions(&self) -> Result<Vec<DnsQuestion>> {
        let mut questions = Vec::new();
        let count = self.question_count();
        let mut offset = DNS_HEADER_SIZE;

        for _ in 0..count {
            let (name, new_offset) = parse_domain_name(&self.buffer, offset)?;
            offset = new_offset;

            if offset + 4 > self.buffer.len() {
                return Err(Error::Parse("DNS question truncated".into()));
            }

            let qtype = u16::from_be_bytes([self.buffer[offset], self.buffer[offset + 1]]);
            let qclass = u16::from_be_bytes([self.buffer[offset + 2], self.buffer[offset + 3]]);
            offset += 4;

            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        Ok(questions)
    }

    /// Parse answer records from the packet
    pub fn answers(&self) -> Result<Vec<DnsRecord>> {
        // Skip header and questions to get to answers
        let mut offset = DNS_HEADER_SIZE;
        let q_count = self.question_count();

        // Skip questions
        for _ in 0..q_count {
            let (_, new_offset) = parse_domain_name(&self.buffer, offset)?;
            offset = new_offset + 4; // Skip QTYPE and QCLASS
        }

        // Parse answers
        let a_count = self.answer_count();
        let mut answers = Vec::new();

        for _ in 0..a_count {
            let (name, new_offset) = parse_domain_name(&self.buffer, offset)?;
            offset = new_offset;

            if offset + 10 > self.buffer.len() {
                return Err(Error::Parse("DNS answer truncated".into()));
            }

            let rtype = u16::from_be_bytes([self.buffer[offset], self.buffer[offset + 1]]);
            let rclass = u16::from_be_bytes([self.buffer[offset + 2], self.buffer[offset + 3]]);
            let ttl = u32::from_be_bytes([
                self.buffer[offset + 4],
                self.buffer[offset + 5],
                self.buffer[offset + 6],
                self.buffer[offset + 7],
            ]);
            let rdlength =
                u16::from_be_bytes([self.buffer[offset + 8], self.buffer[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > self.buffer.len() {
                return Err(Error::Parse("DNS RDATA truncated".into()));
            }

            let rdata = self.buffer[offset..offset + rdlength].to_vec();
            offset += rdlength;

            answers.push(DnsRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
        }

        Ok(answers)
    }

    /// Get minimum TTL from answer records (for caching)
    pub fn min_ttl(&self) -> Option<u32> {
        self.answers().ok()?.iter().map(|r| r.ttl).min()
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

/// Parse a domain name from DNS wire format
///
/// Handles both label format and compression pointers (RFC 1035 section 4.1.4)
pub fn parse_domain_name(buffer: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut final_offset = start;
    let mut jumps = 0;
    const MAX_JUMPS: usize = 128;

    loop {
        if jumps > MAX_JUMPS {
            return Err(Error::Parse("DNS name compression loop detected".into()));
        }

        if offset >= buffer.len() {
            return Err(Error::Parse("DNS name truncated".into()));
        }

        let len = buffer[offset] as usize;

        if len == 0 {
            // End of name
            if !jumped {
                final_offset = offset + 1;
            }
            break;
        } else if len & 0xC0 == 0xC0 {
            // Compression pointer
            if offset + 1 >= buffer.len() {
                return Err(Error::Parse("DNS compression pointer truncated".into()));
            }

            if !jumped {
                final_offset = offset + 2;
            }

            let pointer = ((len & 0x3F) << 8) | (buffer[offset + 1] as usize);
            offset = pointer;
            jumped = true;
            jumps += 1;
        } else {
            // Normal label
            offset += 1;
            if offset + len > buffer.len() {
                return Err(Error::Parse("DNS label truncated".into()));
            }

            let label = std::str::from_utf8(&buffer[offset..offset + len])
                .map_err(|_| Error::Parse("DNS label not valid UTF-8".into()))?;
            labels.push(label.to_string());
            offset += len;

            if !jumped {
                final_offset = offset;
            }
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Ok((name, final_offset))
}

/// Encode a domain name to DNS wire format
pub fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut result = Vec::new();

    // Handle root domain
    if name == "." || name.is_empty() {
        result.push(0);
        return result;
    }

    // Remove trailing dot if present
    let name = name.trim_end_matches('.');

    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result.push(0); // Terminating zero

    result
}

/// DNS query builder
#[derive(Debug, Clone, Default)]
pub struct DnsBuilder {
    id: u16,
    flags: u16,
    questions: Vec<DnsQuestion>,
}

impl DnsBuilder {
    /// Create a new DNS builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set transaction ID
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Set as query (QR=0)
    pub fn query(mut self) -> Self {
        self.flags &= !0x8000;
        self
    }

    /// Set as response (QR=1)
    pub fn response(mut self) -> Self {
        self.flags |= 0x8000;
        self
    }

    /// Set recursion desired flag
    pub fn recursion_desired(mut self, rd: bool) -> Self {
        if rd {
            self.flags |= 0x0100;
        } else {
            self.flags &= !0x0100;
        }
        self
    }

    /// Set recursion available flag
    pub fn recursion_available(mut self, ra: bool) -> Self {
        if ra {
            self.flags |= 0x0080;
        } else {
            self.flags &= !0x0080;
        }
        self
    }

    /// Set response code
    pub fn rcode(mut self, rcode: DnsRcode) -> Self {
        self.flags = (self.flags & !0x000F) | (rcode as u16);
        self
    }

    /// Add a question
    pub fn add_question(mut self, name: &str, qtype: DnsType, qclass: DnsClass) -> Self {
        self.questions.push(DnsQuestion {
            name: name.to_string(),
            qtype: qtype as u16,
            qclass: qclass as u16,
        });
        self
    }

    /// Build the DNS packet
    pub fn build(self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Header
        buffer.extend_from_slice(&self.id.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&(self.questions.len() as u16).to_be_bytes()); // QDCOUNT
        buffer.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buffer.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buffer.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Questions
        for q in &self.questions {
            buffer.extend(encode_domain_name(&q.name));
            buffer.extend_from_slice(&q.qtype.to_be_bytes());
            buffer.extend_from_slice(&q.qclass.to_be_bytes());
        }

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a simple DNS query packet for testing
    fn make_query_packet() -> Vec<u8> {
        // DNS query for "example.com" type A, class IN
        vec![
            0x12, 0x34, // ID = 0x1234
            0x01, 0x00, // Flags: QR=0 (query), RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // Terminating zero
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ]
    }

    /// Create a DNS response packet for testing
    fn make_response_packet() -> Vec<u8> {
        vec![
            0x12, 0x34, // ID = 0x1234
            0x81, 0x80, // Flags: QR=1 (response), RD=1, RA=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Answer: example.com (using compression pointer)
            0xc0, 0x0c, // Pointer to offset 12 (example.com)
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x01, 0x2c, // TTL = 300
            0x00, 0x04, // RDLENGTH = 4
            0x5d, 0xb8, 0xd8, 0x22, // RDATA = 93.184.216.34
        ]
    }

    #[test]
    fn test_dns_header_parse() {
        let packet = make_query_packet();
        let header = DnsHeader::parse(&packet).unwrap();

        assert_eq!(header.id(), 0x1234);
        assert!(header.is_query());
        assert!(!header.is_response());
        assert!(header.recursion_desired());
        assert_eq!(header.question_count(), 1);
        assert_eq!(header.answer_count(), 0);
    }

    #[test]
    fn test_dns_header_parse_too_short() {
        let packet = vec![0u8; 11];
        assert!(DnsHeader::parse(&packet).is_err());
    }

    #[test]
    fn test_dns_header_response() {
        let packet = make_response_packet();
        let header = DnsHeader::parse(&packet).unwrap();

        assert!(header.is_response());
        assert!(!header.is_query());
        assert!(header.recursion_desired());
        assert!(header.recursion_available());
        assert_eq!(header.rcode(), 0); // NoError
        assert_eq!(header.question_count(), 1);
        assert_eq!(header.answer_count(), 1);
    }

    #[test]
    fn test_parse_domain_name_simple() {
        // "example.com" in wire format
        let buffer = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let (name, offset) = parse_domain_name(&buffer, 0).unwrap();

        assert_eq!(name, "example.com");
        assert_eq!(offset, 13);
    }

    #[test]
    fn test_parse_domain_name_with_pointer() {
        let packet = make_response_packet();
        // Answer section starts at offset 29, name is compression pointer at 0xc00c
        let (name, _) = parse_domain_name(&packet, 29).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn test_parse_domain_name_root() {
        let buffer = [0x00];
        let (name, offset) = parse_domain_name(&buffer, 0).unwrap();
        assert_eq!(name, ".");
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_encode_domain_name() {
        let encoded = encode_domain_name("example.com");
        let expected = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_encode_domain_name_with_trailing_dot() {
        let encoded = encode_domain_name("example.com.");
        let expected = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_encode_domain_name_root() {
        let encoded = encode_domain_name(".");
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_dns_packet_questions() {
        let packet = DnsPacket::from_bytes(&make_query_packet()).unwrap();
        let questions = packet.questions().unwrap();

        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].name, "example.com");
        assert_eq!(questions[0].qtype, DnsType::A as u16);
        assert_eq!(questions[0].qclass, DnsClass::IN as u16);
    }

    #[test]
    fn test_dns_packet_answers() {
        let packet = DnsPacket::from_bytes(&make_response_packet()).unwrap();
        let answers = packet.answers().unwrap();

        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "example.com");
        assert_eq!(answers[0].rtype, DnsType::A as u16);
        assert_eq!(answers[0].ttl, 300);
        assert_eq!(answers[0].rdata, vec![0x5d, 0xb8, 0xd8, 0x22]);
    }

    #[test]
    fn test_dns_packet_min_ttl() {
        let packet = DnsPacket::from_bytes(&make_response_packet()).unwrap();
        assert_eq!(packet.min_ttl(), Some(300));
    }

    #[test]
    fn test_dns_packet_set_id() {
        let mut packet = DnsPacket::from_bytes(&make_query_packet()).unwrap();
        assert_eq!(packet.id(), 0x1234);

        packet.set_id(0xABCD);
        assert_eq!(packet.id(), 0xABCD);
    }

    #[test]
    fn test_dns_builder_query() {
        let packet = DnsBuilder::new()
            .id(0x5678)
            .query()
            .recursion_desired(true)
            .add_question("test.example.com", DnsType::A, DnsClass::IN)
            .build();

        let header = DnsHeader::parse(&packet).unwrap();
        assert_eq!(header.id(), 0x5678);
        assert!(header.is_query());
        assert!(header.recursion_desired());
        assert_eq!(header.question_count(), 1);

        let pkt = DnsPacket::from_bytes(&packet).unwrap();
        let questions = pkt.questions().unwrap();
        assert_eq!(questions[0].name, "test.example.com");
    }

    #[test]
    fn test_roundtrip() {
        let original = make_query_packet();
        let packet = DnsPacket::from_bytes(&original).unwrap();
        let questions = packet.questions().unwrap();

        let rebuilt = DnsBuilder::new()
            .id(packet.id())
            .query()
            .recursion_desired(true)
            .add_question(&questions[0].name, DnsType::A, DnsClass::IN)
            .build();

        // Parse both and compare
        let orig_hdr = DnsHeader::parse(&original).unwrap();
        let new_hdr = DnsHeader::parse(&rebuilt).unwrap();

        assert_eq!(orig_hdr.id(), new_hdr.id());
        assert_eq!(orig_hdr.question_count(), new_hdr.question_count());
    }

    #[test]
    fn test_dns_rcode() {
        assert_eq!(DnsRcode::from_u8(0), Some(DnsRcode::NoError));
        assert_eq!(DnsRcode::from_u8(3), Some(DnsRcode::NameError));
        assert_eq!(DnsRcode::from_u8(10), None);
    }

    #[test]
    fn test_dns_type() {
        assert_eq!(DnsType::from_u16(1), Some(DnsType::A));
        assert_eq!(DnsType::from_u16(28), Some(DnsType::AAAA));
        assert_eq!(DnsType::from_u16(999), None);
    }
}

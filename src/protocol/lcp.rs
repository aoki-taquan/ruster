//! LCP protocol - RFC 1661
//!
//! Link Control Protocol for establishing, configuring, and testing
//! the data-link connection.

use crate::{Error, Result};

/// LCP header size (code + identifier + length)
pub const LCP_HEADER_SIZE: usize = 4;

/// LCP packet codes
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
    /// Protocol-Reject
    pub const PROTOCOL_REJECT: u8 = 8;
    /// Echo-Request
    pub const ECHO_REQUEST: u8 = 9;
    /// Echo-Reply
    pub const ECHO_REPLY: u8 = 10;
    /// Discard-Request
    pub const DISCARD_REQUEST: u8 = 11;
}

/// LCP option types
pub mod options {
    /// Maximum-Receive-Unit
    pub const MRU: u8 = 1;
    /// Async-Control-Character-Map (not used in PPPoE)
    pub const ACCM: u8 = 2;
    /// Authentication-Protocol
    pub const AUTH_PROTOCOL: u8 = 3;
    /// Quality-Protocol
    pub const QUALITY_PROTOCOL: u8 = 4;
    /// Magic-Number
    pub const MAGIC_NUMBER: u8 = 5;
    /// Protocol-Field-Compression
    pub const PFC: u8 = 7;
    /// Address-and-Control-Field-Compression
    pub const ACFC: u8 = 8;
}

/// Authentication protocol values for LCP option 3
pub mod auth {
    /// Password Authentication Protocol
    pub const PAP: u16 = 0xc023;
    /// Challenge Handshake Authentication Protocol
    pub const CHAP: u16 = 0xc223;
    /// CHAP algorithm: MD5
    pub const CHAP_MD5: u8 = 5;
}

/// Parsed LCP packet (zero-copy reference)
#[derive(Debug)]
pub struct LcpPacket<'a> {
    buffer: &'a [u8],
}

impl<'a> LcpPacket<'a> {
    /// Parse LCP packet from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < LCP_HEADER_SIZE {
            return Err(Error::Parse("LCP packet too short".into()));
        }

        let packet = Self { buffer };

        // Verify length field
        let length = packet.length() as usize;
        if length < LCP_HEADER_SIZE {
            return Err(Error::Parse("LCP length too small".into()));
        }
        if buffer.len() < length {
            return Err(Error::Parse("LCP packet truncated".into()));
        }

        Ok(packet)
    }

    /// Code field
    pub fn code(&self) -> u8 {
        self.buffer[0]
    }

    /// Identifier field (for matching requests and responses)
    pub fn identifier(&self) -> u8 {
        self.buffer[1]
    }

    /// Length field (total packet length including header)
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Data (options for Configure-*, or payload for Echo-*)
    pub fn data(&self) -> &[u8] {
        let len = self.length() as usize;
        &self.buffer[LCP_HEADER_SIZE..len]
    }

    /// Iterate over options (for Configure-Request/Ack/Nak/Reject)
    pub fn iter_options(&self) -> LcpOptionIterator<'_> {
        LcpOptionIterator {
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

    /// Get MRU option value
    pub fn mru(&self) -> Option<u16> {
        self.find_option(options::MRU).and_then(|data| {
            if data.len() >= 2 {
                Some(u16::from_be_bytes([data[0], data[1]]))
            } else {
                None
            }
        })
    }

    /// Get Magic-Number option value
    pub fn magic_number(&self) -> Option<u32> {
        self.find_option(options::MAGIC_NUMBER).and_then(|data| {
            if data.len() >= 4 {
                Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            } else {
                None
            }
        })
    }

    /// Get Authentication-Protocol option
    pub fn auth_protocol(&self) -> Option<(u16, Option<u8>)> {
        self.find_option(options::AUTH_PROTOCOL).and_then(|data| {
            if data.len() >= 2 {
                let proto = u16::from_be_bytes([data[0], data[1]]);
                let algorithm = if data.len() >= 3 { Some(data[2]) } else { None };
                Some((proto, algorithm))
            } else {
                None
            }
        })
    }

    /// For Echo-Request/Reply, get the magic number from data
    pub fn echo_magic(&self) -> Option<u32> {
        let data = self.data();
        if data.len() >= 4 {
            Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        }
    }

    /// Get the raw buffer
    pub fn as_bytes(&self) -> &[u8] {
        let len = self.length() as usize;
        &self.buffer[..len]
    }
}

/// An LCP option during iteration
#[derive(Debug, Clone)]
pub struct LcpOption<'a> {
    /// Option type
    pub opt_type: u8,
    /// Option data (excluding type and length bytes)
    pub data: &'a [u8],
}

/// Iterator over LCP options
pub struct LcpOptionIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for LcpOptionIterator<'a> {
    type Item = LcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Need at least 2 bytes for option header (type + length)
        if self.offset + 2 > self.data.len() {
            return None;
        }

        let opt_type = self.data[self.offset];
        let opt_len = self.data[self.offset + 1] as usize;

        // Option length includes type and length bytes
        if opt_len < 2 || self.offset + opt_len > self.data.len() {
            return None;
        }

        let data_start = self.offset + 2;
        let data_end = self.offset + opt_len;

        let opt = LcpOption {
            opt_type,
            data: &self.data[data_start..data_end],
        };

        self.offset = data_end;
        Some(opt)
    }
}

/// Builder for LCP packets
#[derive(Debug, Default)]
pub struct LcpBuilder {
    code: u8,
    identifier: u8,
    data: Vec<u8>,
}

impl LcpBuilder {
    /// Create a new LCP packet builder
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

    /// Create Terminate-Request builder
    pub fn terminate_request(identifier: u8) -> Self {
        Self::new(codes::TERMINATE_REQUEST, identifier)
    }

    /// Create Terminate-Ack builder
    pub fn terminate_ack(identifier: u8) -> Self {
        Self::new(codes::TERMINATE_ACK, identifier)
    }

    /// Create Echo-Request builder
    pub fn echo_request(identifier: u8, magic: u32) -> Self {
        let mut builder = Self::new(codes::ECHO_REQUEST, identifier);
        builder.data.extend_from_slice(&magic.to_be_bytes());
        builder
    }

    /// Create Echo-Reply builder
    pub fn echo_reply(identifier: u8, magic: u32) -> Self {
        let mut builder = Self::new(codes::ECHO_REPLY, identifier);
        builder.data.extend_from_slice(&magic.to_be_bytes());
        builder
    }

    /// Add a raw option
    pub fn add_option(mut self, opt_type: u8, data: &[u8]) -> Self {
        let opt_len = (2 + data.len()) as u8;
        self.data.push(opt_type);
        self.data.push(opt_len);
        self.data.extend_from_slice(data);
        self
    }

    /// Add MRU option
    pub fn mru(self, mru: u16) -> Self {
        self.add_option(options::MRU, &mru.to_be_bytes())
    }

    /// Add Magic-Number option
    pub fn magic_number(self, magic: u32) -> Self {
        self.add_option(options::MAGIC_NUMBER, &magic.to_be_bytes())
    }

    /// Add Authentication-Protocol option (PAP)
    pub fn auth_pap(self) -> Self {
        self.add_option(options::AUTH_PROTOCOL, &auth::PAP.to_be_bytes())
    }

    /// Add Authentication-Protocol option (CHAP MD5)
    pub fn auth_chap_md5(self) -> Self {
        let mut data = auth::CHAP.to_be_bytes().to_vec();
        data.push(auth::CHAP_MD5);
        self.add_option(options::AUTH_PROTOCOL, &data)
    }

    /// Set raw data (for Echo packets or copying options)
    pub fn raw_data(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Build the LCP packet
    pub fn build(self) -> Vec<u8> {
        let length = (LCP_HEADER_SIZE + self.data.len()) as u16;
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
        // LCP Configure-Request with MRU=1492 and Magic-Number
        let data = [
            0x01, // Code: Configure-Request
            0x01, // Identifier
            0x00, 0x0e, // Length=14 (4 header + 4 MRU + 6 Magic)
            // MRU option
            0x01, 0x04, // Type=1, Length=4
            0x05, 0xd4, // MRU=1492
            // Magic-Number option
            0x05, 0x06, // Type=5, Length=6
            0x12, 0x34, 0x56, 0x78, // Magic
        ];

        let packet = LcpPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::CONFIGURE_REQUEST);
        assert_eq!(packet.identifier(), 1);
        assert_eq!(packet.length(), 14);
        assert_eq!(packet.mru(), Some(1492));
        assert_eq!(packet.magic_number(), Some(0x12345678));
    }

    #[test]
    fn test_parse_configure_request_with_auth() {
        // LCP Configure-Request with CHAP MD5
        let data = [
            0x01, // Code: Configure-Request
            0x02, // Identifier
            0x00, 0x09, // Length=9
            // Auth-Protocol option (CHAP MD5)
            0x03, 0x05, // Type=3, Length=5
            0xc2, 0x23, // CHAP
            0x05, // MD5
        ];

        let packet = LcpPacket::parse(&data).unwrap();
        assert_eq!(
            packet.auth_protocol(),
            Some((auth::CHAP, Some(auth::CHAP_MD5)))
        );
    }

    #[test]
    fn test_parse_echo_request() {
        let data = [
            0x09, // Code: Echo-Request
            0x01, // Identifier
            0x00, 0x08, // Length=8
            0xab, 0xcd, 0xef, 0x12, // Magic number
        ];

        let packet = LcpPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::ECHO_REQUEST);
        assert_eq!(packet.echo_magic(), Some(0xabcdef12));
    }

    #[test]
    fn test_iterate_options() {
        let data = [
            0x01, 0x01, 0x00, 0x0e, // Length=14 (4 header + 4 MRU + 6 Magic)
            // MRU option
            0x01, 0x04, 0x05, 0xd4, // Magic option
            0x05, 0x06, 0x00, 0x00, 0x00, 0x01,
        ];

        let packet = LcpPacket::parse(&data).unwrap();
        let opts: Vec<_> = packet.iter_options().collect();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].opt_type, options::MRU);
        assert_eq!(opts[1].opt_type, options::MAGIC_NUMBER);
    }

    #[test]
    fn test_build_configure_request() {
        let packet = LcpBuilder::configure_request(1)
            .mru(1492)
            .magic_number(0x12345678)
            .build();

        let parsed = LcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::CONFIGURE_REQUEST);
        assert_eq!(parsed.identifier(), 1);
        assert_eq!(parsed.mru(), Some(1492));
        assert_eq!(parsed.magic_number(), Some(0x12345678));
    }

    #[test]
    fn test_build_configure_ack() {
        let options_data = [0x01, 0x04, 0x05, 0xd4]; // MRU=1492
        let packet = LcpBuilder::configure_ack(5).raw_data(&options_data).build();

        let parsed = LcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::CONFIGURE_ACK);
        assert_eq!(parsed.identifier(), 5);
        assert_eq!(parsed.mru(), Some(1492));
    }

    #[test]
    fn test_build_echo_request() {
        let packet = LcpBuilder::echo_request(10, 0xdeadbeef).build();

        let parsed = LcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::ECHO_REQUEST);
        assert_eq!(parsed.identifier(), 10);
        assert_eq!(parsed.echo_magic(), Some(0xdeadbeef));
    }

    #[test]
    fn test_build_echo_reply() {
        let packet = LcpBuilder::echo_reply(10, 0xdeadbeef).build();

        let parsed = LcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::ECHO_REPLY);
        assert_eq!(parsed.identifier(), 10);
        assert_eq!(parsed.echo_magic(), Some(0xdeadbeef));
    }

    #[test]
    fn test_build_with_auth_pap() {
        let packet = LcpBuilder::configure_request(1).auth_pap().build();

        let parsed = LcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.auth_protocol(), Some((auth::PAP, None)));
    }

    #[test]
    fn test_build_with_auth_chap() {
        let packet = LcpBuilder::configure_request(1).auth_chap_md5().build();

        let parsed = LcpPacket::parse(&packet).unwrap();
        assert_eq!(
            parsed.auth_protocol(),
            Some((auth::CHAP, Some(auth::CHAP_MD5)))
        );
    }

    #[test]
    fn test_roundtrip() {
        let original = LcpBuilder::configure_request(42)
            .mru(1400)
            .magic_number(0xfeedface)
            .build();

        let parsed = LcpPacket::parse(&original).unwrap();
        assert_eq!(parsed.as_bytes(), original.as_slice());
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0x01, 0x01, 0x00];
        assert!(LcpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_length() {
        let data = [0x01, 0x01, 0x00, 0x02]; // Length=2, but min is 4
        assert!(LcpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x01, 0x01, 0x00, 0x10]; // Length=16, but only 4 bytes
        assert!(LcpPacket::parse(&data).is_err());
    }
}

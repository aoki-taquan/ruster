//! PPP protocol - RFC 1661
//!
//! Point-to-Point Protocol frame parsing and building.
//! PPP frames are encapsulated within PPPoE Session frames.

use crate::{Error, Result};

/// PPP header size (protocol field only, no HDLC framing in PPPoE)
pub const PPP_HEADER_SIZE: usize = 2;

/// PPP protocol numbers
pub mod protocols {
    /// Internet Protocol version 4
    pub const IP: u16 = 0x0021;
    /// Internet Protocol version 6
    pub const IPV6: u16 = 0x0057;
    /// Internet Protocol Control Protocol
    pub const IPCP: u16 = 0x8021;
    /// IPv6 Control Protocol
    pub const IPV6CP: u16 = 0x8057;
    /// Link Control Protocol
    pub const LCP: u16 = 0xc021;
    /// Password Authentication Protocol
    pub const PAP: u16 = 0xc023;
    /// Challenge Handshake Authentication Protocol
    pub const CHAP: u16 = 0xc223;
}

/// Parsed PPP frame (zero-copy reference)
#[derive(Debug)]
pub struct PppFrame<'a> {
    buffer: &'a [u8],
}

impl<'a> PppFrame<'a> {
    /// Parse PPP frame from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < PPP_HEADER_SIZE {
            return Err(Error::Parse("PPP frame too short".into()));
        }
        Ok(Self { buffer })
    }

    /// Protocol field
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    /// Payload (protocol-specific data)
    pub fn payload(&self) -> &[u8] {
        &self.buffer[PPP_HEADER_SIZE..]
    }

    /// Check if this is a control protocol (LCP, PAP, CHAP, IPCP, etc.)
    pub fn is_control(&self) -> bool {
        let proto = self.protocol();
        // Control protocols have values >= 0x8000 or authentication protocols
        proto >= 0x8000 || proto == protocols::PAP || proto == protocols::CHAP
    }

    /// Check if this is a network protocol (IP, IPv6)
    pub fn is_network(&self) -> bool {
        matches!(self.protocol(), protocols::IP | protocols::IPV6)
    }

    /// Get the raw buffer
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }
}

/// Builder for PPP frames
#[derive(Debug, Default)]
pub struct PppBuilder {
    protocol: u16,
    payload: Vec<u8>,
}

impl PppBuilder {
    /// Create a new PPP frame builder
    pub fn new(protocol: u16) -> Self {
        Self {
            protocol,
            payload: Vec::new(),
        }
    }

    /// Create builder for LCP
    pub fn lcp() -> Self {
        Self::new(protocols::LCP)
    }

    /// Create builder for PAP
    pub fn pap() -> Self {
        Self::new(protocols::PAP)
    }

    /// Create builder for CHAP
    pub fn chap() -> Self {
        Self::new(protocols::CHAP)
    }

    /// Create builder for IPCP
    pub fn ipcp() -> Self {
        Self::new(protocols::IPCP)
    }

    /// Create builder for IPv6CP
    pub fn ipv6cp() -> Self {
        Self::new(protocols::IPV6CP)
    }

    /// Create builder for IPv4 data
    pub fn ip() -> Self {
        Self::new(protocols::IP)
    }

    /// Create builder for IPv6 data
    pub fn ipv6() -> Self {
        Self::new(protocols::IPV6)
    }

    /// Set the payload
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    /// Build the PPP frame
    pub fn build(self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(PPP_HEADER_SIZE + self.payload.len());
        frame.extend_from_slice(&self.protocol.to_be_bytes());
        frame.extend_from_slice(&self.payload);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lcp() {
        let data = [
            0xc0, 0x21, // Protocol: LCP
            0x01, 0x01, 0x00, 0x04, // LCP payload
        ];

        let frame = PppFrame::parse(&data).unwrap();
        assert_eq!(frame.protocol(), protocols::LCP);
        assert!(frame.is_control());
        assert!(!frame.is_network());
        assert_eq!(frame.payload(), &[0x01, 0x01, 0x00, 0x04]);
    }

    #[test]
    fn test_parse_ipcp() {
        let data = [
            0x80, 0x21, // Protocol: IPCP
            0x01, 0x02, 0x00, 0x0a, // IPCP payload
        ];

        let frame = PppFrame::parse(&data).unwrap();
        assert_eq!(frame.protocol(), protocols::IPCP);
        assert!(frame.is_control());
    }

    #[test]
    fn test_parse_ip() {
        let data = [
            0x00, 0x21, // Protocol: IP
            0x45, 0x00, // IP header start
        ];

        let frame = PppFrame::parse(&data).unwrap();
        assert_eq!(frame.protocol(), protocols::IP);
        assert!(!frame.is_control());
        assert!(frame.is_network());
    }

    #[test]
    fn test_parse_pap() {
        let data = [
            0xc0, 0x23, // Protocol: PAP
            0x01, 0x01, // PAP payload
        ];

        let frame = PppFrame::parse(&data).unwrap();
        assert_eq!(frame.protocol(), protocols::PAP);
        assert!(frame.is_control());
    }

    #[test]
    fn test_parse_chap() {
        let data = [
            0xc2, 0x23, // Protocol: CHAP
            0x01, 0x01, // CHAP payload
        ];

        let frame = PppFrame::parse(&data).unwrap();
        assert_eq!(frame.protocol(), protocols::CHAP);
        assert!(frame.is_control());
    }

    #[test]
    fn test_build_lcp() {
        let payload = [0x01, 0x01, 0x00, 0x04];
        let frame = PppBuilder::lcp().payload(&payload).build();

        assert_eq!(frame[0..2], [0xc0, 0x21]);
        assert_eq!(&frame[2..], &payload);
    }

    #[test]
    fn test_build_ipcp() {
        let payload = [0x01, 0x02, 0x00, 0x0a];
        let frame = PppBuilder::ipcp().payload(&payload).build();

        assert_eq!(frame[0..2], [0x80, 0x21]);
    }

    #[test]
    fn test_build_ip() {
        let ip_packet = [0x45, 0x00, 0x00, 0x14];
        let frame = PppBuilder::ip().payload(&ip_packet).build();

        assert_eq!(frame[0..2], [0x00, 0x21]);
        assert_eq!(&frame[2..], &ip_packet);
    }

    #[test]
    fn test_roundtrip() {
        let payload = [0x01, 0x02, 0x03, 0x04];
        let frame = PppBuilder::lcp().payload(&payload).build();

        let parsed = PppFrame::parse(&frame).unwrap();
        assert_eq!(parsed.protocol(), protocols::LCP);
        assert_eq!(parsed.payload(), &payload);
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0xc0];
        assert!(PppFrame::parse(&data).is_err());
    }

    #[test]
    fn test_parse_empty_payload() {
        let data = [0xc0, 0x21]; // Just protocol, no payload
        let frame = PppFrame::parse(&data).unwrap();
        assert_eq!(frame.protocol(), protocols::LCP);
        assert!(frame.payload().is_empty());
    }
}

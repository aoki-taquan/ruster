//! PAP protocol - RFC 1334
//!
//! Password Authentication Protocol for simple clear-text authentication.

use crate::{Error, Result};

/// PAP header size (code + identifier + length)
pub const PAP_HEADER_SIZE: usize = 4;

/// PAP packet codes
pub mod codes {
    /// Authenticate-Request
    pub const AUTHENTICATE_REQUEST: u8 = 1;
    /// Authenticate-Ack (success)
    pub const AUTHENTICATE_ACK: u8 = 2;
    /// Authenticate-Nak (failure)
    pub const AUTHENTICATE_NAK: u8 = 3;
}

/// Parsed PAP packet (zero-copy reference)
#[derive(Debug)]
pub struct PapPacket<'a> {
    buffer: &'a [u8],
}

impl<'a> PapPacket<'a> {
    /// Parse PAP packet from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < PAP_HEADER_SIZE {
            return Err(Error::Parse("PAP packet too short".into()));
        }

        let packet = Self { buffer };

        let length = packet.length() as usize;
        if length < PAP_HEADER_SIZE {
            return Err(Error::Parse("PAP length too small".into()));
        }
        if buffer.len() < length {
            return Err(Error::Parse("PAP packet truncated".into()));
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

    /// Data field
    pub fn data(&self) -> &[u8] {
        let len = self.length() as usize;
        &self.buffer[PAP_HEADER_SIZE..len]
    }

    /// Get Peer-ID from Authenticate-Request
    /// Format: Peer-ID-Length (1 byte) + Peer-ID
    pub fn peer_id(&self) -> Option<&[u8]> {
        if self.code() != codes::AUTHENTICATE_REQUEST {
            return None;
        }
        let data = self.data();
        if data.is_empty() {
            return None;
        }
        let peer_id_len = data[0] as usize;
        if data.len() < 1 + peer_id_len {
            return None;
        }
        Some(&data[1..1 + peer_id_len])
    }

    /// Get Password from Authenticate-Request
    /// Format: Peer-ID-Length (1) + Peer-ID + Passwd-Length (1) + Password
    pub fn password(&self) -> Option<&[u8]> {
        if self.code() != codes::AUTHENTICATE_REQUEST {
            return None;
        }
        let data = self.data();
        if data.is_empty() {
            return None;
        }
        let peer_id_len = data[0] as usize;
        let passwd_offset = 1 + peer_id_len;
        if data.len() < passwd_offset + 1 {
            return None;
        }
        let passwd_len = data[passwd_offset] as usize;
        let passwd_start = passwd_offset + 1;
        if data.len() < passwd_start + passwd_len {
            return None;
        }
        Some(&data[passwd_start..passwd_start + passwd_len])
    }

    /// Get message from Authenticate-Ack/Nak
    /// Format: Msg-Length (1 byte) + Message
    pub fn message(&self) -> Option<&[u8]> {
        if self.code() != codes::AUTHENTICATE_ACK && self.code() != codes::AUTHENTICATE_NAK {
            return None;
        }
        let data = self.data();
        if data.is_empty() {
            return Some(&[]);
        }
        let msg_len = data[0] as usize;
        if data.len() < 1 + msg_len {
            return Some(&[]);
        }
        Some(&data[1..1 + msg_len])
    }

    /// Check if this is an authentication success
    pub fn is_success(&self) -> bool {
        self.code() == codes::AUTHENTICATE_ACK
    }

    /// Check if this is an authentication failure
    pub fn is_failure(&self) -> bool {
        self.code() == codes::AUTHENTICATE_NAK
    }

    /// Get the raw buffer
    pub fn as_bytes(&self) -> &[u8] {
        let len = self.length() as usize;
        &self.buffer[..len]
    }
}

/// Builder for PAP packets
#[derive(Debug, Default)]
pub struct PapBuilder {
    code: u8,
    identifier: u8,
    data: Vec<u8>,
}

impl PapBuilder {
    /// Create a new PAP packet builder
    pub fn new(code: u8, identifier: u8) -> Self {
        Self {
            code,
            identifier,
            data: Vec::new(),
        }
    }

    /// Create Authenticate-Request builder
    pub fn authenticate_request(identifier: u8, peer_id: &str, password: &str) -> Self {
        let mut builder = Self::new(codes::AUTHENTICATE_REQUEST, identifier);

        // Peer-ID-Length + Peer-ID
        builder.data.push(peer_id.len() as u8);
        builder.data.extend_from_slice(peer_id.as_bytes());

        // Passwd-Length + Password
        builder.data.push(password.len() as u8);
        builder.data.extend_from_slice(password.as_bytes());

        builder
    }

    /// Create Authenticate-Ack builder (for testing/server side)
    pub fn authenticate_ack(identifier: u8, message: &str) -> Self {
        let mut builder = Self::new(codes::AUTHENTICATE_ACK, identifier);
        builder.data.push(message.len() as u8);
        builder.data.extend_from_slice(message.as_bytes());
        builder
    }

    /// Create Authenticate-Nak builder (for testing/server side)
    pub fn authenticate_nak(identifier: u8, message: &str) -> Self {
        let mut builder = Self::new(codes::AUTHENTICATE_NAK, identifier);
        builder.data.push(message.len() as u8);
        builder.data.extend_from_slice(message.as_bytes());
        builder
    }

    /// Build the PAP packet
    pub fn build(self) -> Vec<u8> {
        let length = (PAP_HEADER_SIZE + self.data.len()) as u16;
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
    fn test_parse_authenticate_request() {
        // PAP Authenticate-Request: user="test", password="pass"
        let data = [
            0x01, // Code: Authenticate-Request
            0x01, // Identifier
            0x00, 0x0e, // Length=14
            0x04, // Peer-ID length=4
            b't', b'e', b's', b't', // Peer-ID
            0x04, // Password length=4
            b'p', b'a', b's', b's', // Password
        ];

        let packet = PapPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::AUTHENTICATE_REQUEST);
        assert_eq!(packet.identifier(), 1);
        assert_eq!(packet.peer_id(), Some(b"test".as_slice()));
        assert_eq!(packet.password(), Some(b"pass".as_slice()));
    }

    #[test]
    fn test_parse_authenticate_ack() {
        // PAP Authenticate-Ack with message "OK"
        let data = [
            0x02, // Code: Authenticate-Ack
            0x01, // Identifier
            0x00, 0x07, // Length=7
            0x02, // Message length=2
            b'O', b'K', // Message
        ];

        let packet = PapPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::AUTHENTICATE_ACK);
        assert!(packet.is_success());
        assert!(!packet.is_failure());
        assert_eq!(packet.message(), Some(b"OK".as_slice()));
    }

    #[test]
    fn test_parse_authenticate_nak() {
        // PAP Authenticate-Nak with message "FAIL"
        let data = [
            0x03, // Code: Authenticate-Nak
            0x01, // Identifier
            0x00, 0x09, // Length=9
            0x04, // Message length=4
            b'F', b'A', b'I', b'L', // Message
        ];

        let packet = PapPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::AUTHENTICATE_NAK);
        assert!(!packet.is_success());
        assert!(packet.is_failure());
        assert_eq!(packet.message(), Some(b"FAIL".as_slice()));
    }

    #[test]
    fn test_parse_ack_empty_message() {
        let data = [
            0x02, // Code: Authenticate-Ack
            0x01, // Identifier
            0x00, 0x05, // Length=5
            0x00, // Message length=0
        ];

        let packet = PapPacket::parse(&data).unwrap();
        assert!(packet.is_success());
        assert_eq!(packet.message(), Some(b"".as_slice()));
    }

    #[test]
    fn test_build_authenticate_request() {
        let packet = PapBuilder::authenticate_request(1, "myuser", "mypass").build();

        let parsed = PapPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::AUTHENTICATE_REQUEST);
        assert_eq!(parsed.identifier(), 1);
        assert_eq!(parsed.peer_id(), Some(b"myuser".as_slice()));
        assert_eq!(parsed.password(), Some(b"mypass".as_slice()));
    }

    #[test]
    fn test_build_authenticate_ack() {
        let packet = PapBuilder::authenticate_ack(1, "Welcome").build();

        let parsed = PapPacket::parse(&packet).unwrap();
        assert!(parsed.is_success());
        assert_eq!(parsed.identifier(), 1);
        assert_eq!(parsed.message(), Some(b"Welcome".as_slice()));
    }

    #[test]
    fn test_build_authenticate_nak() {
        let packet = PapBuilder::authenticate_nak(1, "Bad credentials").build();

        let parsed = PapPacket::parse(&packet).unwrap();
        assert!(parsed.is_failure());
        assert_eq!(parsed.message(), Some(b"Bad credentials".as_slice()));
    }

    #[test]
    fn test_roundtrip() {
        let original = PapBuilder::authenticate_request(42, "user123", "secret456").build();

        let parsed = PapPacket::parse(&original).unwrap();
        assert_eq!(parsed.as_bytes(), original.as_slice());
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0x01, 0x01, 0x00];
        assert!(PapPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x01, 0x01, 0x00, 0x10]; // Length=16, but only 4 bytes
        assert!(PapPacket::parse(&data).is_err());
    }

    #[test]
    fn test_peer_id_wrong_code() {
        let data = [0x02, 0x01, 0x00, 0x05, 0x00]; // Ack, not Request
        let packet = PapPacket::parse(&data).unwrap();
        assert_eq!(packet.peer_id(), None);
        assert_eq!(packet.password(), None);
    }

    #[test]
    fn test_message_wrong_code() {
        // Request packet, message() should return None
        let data = [0x01, 0x01, 0x00, 0x08, 0x02, b'a', b'b', 0x00];
        let packet = PapPacket::parse(&data).unwrap();
        assert_eq!(packet.message(), None);
    }
}

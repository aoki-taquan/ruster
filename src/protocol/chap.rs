//! CHAP protocol - RFC 1994
//!
//! Challenge Handshake Authentication Protocol for secure authentication.

use crate::{Error, Result};

/// CHAP header size (code + identifier + length)
pub const CHAP_HEADER_SIZE: usize = 4;

/// CHAP packet codes
pub mod codes {
    /// Challenge from authenticator
    pub const CHALLENGE: u8 = 1;
    /// Response from peer
    pub const RESPONSE: u8 = 2;
    /// Authentication success
    pub const SUCCESS: u8 = 3;
    /// Authentication failure
    pub const FAILURE: u8 = 4;
}

/// CHAP algorithms
pub mod algorithms {
    /// MD5 (most common)
    pub const MD5: u8 = 5;
}

/// Parsed CHAP packet (zero-copy reference)
#[derive(Debug)]
pub struct ChapPacket<'a> {
    buffer: &'a [u8],
}

impl<'a> ChapPacket<'a> {
    /// Parse CHAP packet from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < CHAP_HEADER_SIZE {
            return Err(Error::Parse("CHAP packet too short".into()));
        }

        let packet = Self { buffer };

        let length = packet.length() as usize;
        if length < CHAP_HEADER_SIZE {
            return Err(Error::Parse("CHAP length too small".into()));
        }
        if buffer.len() < length {
            return Err(Error::Parse("CHAP packet truncated".into()));
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
        &self.buffer[CHAP_HEADER_SIZE..len]
    }

    /// Get Challenge/Response value
    /// Format for Challenge/Response: Value-Size (1 byte) + Value + Name
    pub fn value(&self) -> Option<&[u8]> {
        let code = self.code();
        if code != codes::CHALLENGE && code != codes::RESPONSE {
            return None;
        }
        let data = self.data();
        if data.is_empty() {
            return None;
        }
        let value_size = data[0] as usize;
        if data.len() < 1 + value_size {
            return None;
        }
        Some(&data[1..1 + value_size])
    }

    /// Get Name from Challenge/Response
    /// Format: Value-Size (1) + Value + Name (rest of data)
    pub fn name(&self) -> Option<&[u8]> {
        let code = self.code();
        if code != codes::CHALLENGE && code != codes::RESPONSE {
            return None;
        }
        let data = self.data();
        if data.is_empty() {
            return None;
        }
        let value_size = data[0] as usize;
        if data.len() < 1 + value_size {
            return None;
        }
        Some(&data[1 + value_size..])
    }

    /// Get message from Success/Failure
    pub fn message(&self) -> Option<&[u8]> {
        let code = self.code();
        if code != codes::SUCCESS && code != codes::FAILURE {
            return None;
        }
        Some(self.data())
    }

    /// Check if this is a challenge
    pub fn is_challenge(&self) -> bool {
        self.code() == codes::CHALLENGE
    }

    /// Check if this is an authentication success
    pub fn is_success(&self) -> bool {
        self.code() == codes::SUCCESS
    }

    /// Check if this is an authentication failure
    pub fn is_failure(&self) -> bool {
        self.code() == codes::FAILURE
    }

    /// Get the raw buffer
    pub fn as_bytes(&self) -> &[u8] {
        let len = self.length() as usize;
        &self.buffer[..len]
    }
}

/// Calculate CHAP-MD5 response
///
/// response = MD5(identifier + password + challenge)
pub fn calculate_chap_md5(identifier: u8, password: &str, challenge: &[u8]) -> [u8; 16] {
    // MD5 algorithm: MD5(ID || Secret || Challenge)
    md5_hash(identifier, password.as_bytes(), challenge)
}

/// Simple MD5 implementation for CHAP
/// MD5(ID || Secret || Challenge)
fn md5_hash(id: u8, secret: &[u8], challenge: &[u8]) -> [u8; 16] {
    // MD5 implementation following RFC 1321
    let mut input = Vec::with_capacity(1 + secret.len() + challenge.len());
    input.push(id);
    input.extend_from_slice(secret);
    input.extend_from_slice(challenge);

    md5_compute(&input)
}

/// MD5 hash computation (RFC 1321)
fn md5_compute(message: &[u8]) -> [u8; 16] {
    // Initial hash values
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Pre-computed shift amounts
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    // Pre-computed constants (floor(2^32 * abs(sin(i+1))))
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    // Pad message
    let original_len_bits = (message.len() as u64) * 8;
    let mut padded = message.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&original_len_bits.to_le_bytes());

    // Process each 512-bit block
    for chunk in padded.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

/// Builder for CHAP packets
#[derive(Debug, Default)]
pub struct ChapBuilder {
    code: u8,
    identifier: u8,
    data: Vec<u8>,
}

impl ChapBuilder {
    /// Create a new CHAP packet builder
    pub fn new(code: u8, identifier: u8) -> Self {
        Self {
            code,
            identifier,
            data: Vec::new(),
        }
    }

    /// Create Challenge builder (for testing/server side)
    pub fn challenge(identifier: u8, challenge_value: &[u8], name: &str) -> Self {
        let mut builder = Self::new(codes::CHALLENGE, identifier);
        builder.data.push(challenge_value.len() as u8);
        builder.data.extend_from_slice(challenge_value);
        builder.data.extend_from_slice(name.as_bytes());
        builder
    }

    /// Create Response builder
    pub fn response(identifier: u8, response_value: &[u8], name: &str) -> Self {
        let mut builder = Self::new(codes::RESPONSE, identifier);
        builder.data.push(response_value.len() as u8);
        builder.data.extend_from_slice(response_value);
        builder.data.extend_from_slice(name.as_bytes());
        builder
    }

    /// Create Success builder (for testing/server side)
    pub fn success(identifier: u8, message: &str) -> Self {
        let mut builder = Self::new(codes::SUCCESS, identifier);
        builder.data.extend_from_slice(message.as_bytes());
        builder
    }

    /// Create Failure builder (for testing/server side)
    pub fn failure(identifier: u8, message: &str) -> Self {
        let mut builder = Self::new(codes::FAILURE, identifier);
        builder.data.extend_from_slice(message.as_bytes());
        builder
    }

    /// Build the CHAP packet
    pub fn build(self) -> Vec<u8> {
        let length = (CHAP_HEADER_SIZE + self.data.len()) as u16;
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
    fn test_parse_challenge() {
        // CHAP Challenge: value=[0x01,0x02,0x03,0x04], name="server"
        let data = [
            0x01, // Code: Challenge
            0x01, // Identifier
            0x00, 0x0f, // Length=15
            0x04, // Value size=4
            0x01, 0x02, 0x03, 0x04, // Challenge value
            b's', b'e', b'r', b'v', b'e', b'r', // Name
        ];

        let packet = ChapPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::CHALLENGE);
        assert!(packet.is_challenge());
        assert_eq!(packet.identifier(), 1);
        assert_eq!(packet.value(), Some([0x01, 0x02, 0x03, 0x04].as_slice()));
        assert_eq!(packet.name(), Some(b"server".as_slice()));
    }

    #[test]
    fn test_parse_response() {
        // CHAP Response with MD5 hash
        let data = [
            0x02, // Code: Response
            0x01, // Identifier
            0x00, 0x19, // Length=25
            0x10, // Value size=16 (MD5)
            // 16 bytes MD5 hash
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, b'u', b's', b'e', b'r', // Name
        ];

        let packet = ChapPacket::parse(&data).unwrap();
        assert_eq!(packet.code(), codes::RESPONSE);
        assert_eq!(packet.value().unwrap().len(), 16);
        assert_eq!(packet.name(), Some(b"user".as_slice()));
    }

    #[test]
    fn test_parse_success() {
        let data = [
            0x03, // Code: Success
            0x01, // Identifier
            0x00, 0x0e, // Length=14
            b'W', b'e', b'l', b'c', b'o', b'm', b'e', b'!', b'!', b'!',
        ];

        let packet = ChapPacket::parse(&data).unwrap();
        assert!(packet.is_success());
        assert!(!packet.is_failure());
        assert_eq!(packet.message(), Some(b"Welcome!!!".as_slice()));
    }

    #[test]
    fn test_parse_failure() {
        let data = [
            0x04, // Code: Failure
            0x01, // Identifier
            0x00, 0x08, // Length=8
            b'F', b'A', b'I', b'L',
        ];

        let packet = ChapPacket::parse(&data).unwrap();
        assert!(!packet.is_success());
        assert!(packet.is_failure());
        assert_eq!(packet.message(), Some(b"FAIL".as_slice()));
    }

    #[test]
    fn test_build_challenge() {
        let challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let packet = ChapBuilder::challenge(1, &challenge, "myserver").build();

        let parsed = ChapPacket::parse(&packet).unwrap();
        assert!(parsed.is_challenge());
        assert_eq!(parsed.identifier(), 1);
        assert_eq!(parsed.value(), Some(challenge.as_slice()));
        assert_eq!(parsed.name(), Some(b"myserver".as_slice()));
    }

    #[test]
    fn test_build_response() {
        let response_hash = [0xaa; 16]; // Simulated MD5 hash
        let packet = ChapBuilder::response(1, &response_hash, "myuser").build();

        let parsed = ChapPacket::parse(&packet).unwrap();
        assert_eq!(parsed.code(), codes::RESPONSE);
        assert_eq!(parsed.value(), Some(response_hash.as_slice()));
        assert_eq!(parsed.name(), Some(b"myuser".as_slice()));
    }

    #[test]
    fn test_build_success() {
        let packet = ChapBuilder::success(1, "Auth OK").build();

        let parsed = ChapPacket::parse(&packet).unwrap();
        assert!(parsed.is_success());
        assert_eq!(parsed.message(), Some(b"Auth OK".as_slice()));
    }

    #[test]
    fn test_build_failure() {
        let packet = ChapBuilder::failure(1, "Bad password").build();

        let parsed = ChapPacket::parse(&packet).unwrap();
        assert!(parsed.is_failure());
        assert_eq!(parsed.message(), Some(b"Bad password".as_slice()));
    }

    #[test]
    fn test_calculate_chap_md5() {
        // Test vector: ID=1, password="password", challenge=[0x01,0x02,0x03,0x04]
        let challenge = [0x01, 0x02, 0x03, 0x04];
        let result = calculate_chap_md5(1, "password", &challenge);

        // The result should be deterministic
        let result2 = calculate_chap_md5(1, "password", &challenge);
        assert_eq!(result, result2);

        // Different inputs should produce different outputs
        let result3 = calculate_chap_md5(2, "password", &challenge);
        assert_ne!(result, result3);

        let result4 = calculate_chap_md5(1, "different", &challenge);
        assert_ne!(result, result4);
    }

    #[test]
    fn test_md5_known_value() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let result = md5_compute(b"");
        assert_eq!(
            result,
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );

        // MD5("a") = 0cc175b9c0f1b6a831c399e269772661
        let result = md5_compute(b"a");
        assert_eq!(
            result,
            [
                0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77,
                0x26, 0x61
            ]
        );

        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let result = md5_compute(b"abc");
        assert_eq!(
            result,
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
    }

    #[test]
    fn test_roundtrip() {
        let challenge = [0xde, 0xad, 0xbe, 0xef];
        let original = ChapBuilder::challenge(42, &challenge, "test-server").build();

        let parsed = ChapPacket::parse(&original).unwrap();
        assert_eq!(parsed.as_bytes(), original.as_slice());
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0x01, 0x01, 0x00];
        assert!(ChapPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x01, 0x01, 0x00, 0x10]; // Length=16 but only 4 bytes
        assert!(ChapPacket::parse(&data).is_err());
    }

    #[test]
    fn test_value_wrong_code() {
        let data = [0x03, 0x01, 0x00, 0x04]; // Success, not Challenge/Response
        let packet = ChapPacket::parse(&data).unwrap();
        assert_eq!(packet.value(), None);
        assert_eq!(packet.name(), None);
    }

    #[test]
    fn test_message_wrong_code() {
        // Challenge packet, message() should return None
        let data = [0x01, 0x01, 0x00, 0x06, 0x01, 0xaa];
        let packet = ChapPacket::parse(&data).unwrap();
        assert_eq!(packet.message(), None);
    }
}

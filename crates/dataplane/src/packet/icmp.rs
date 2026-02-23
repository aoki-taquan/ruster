// RFC-REF: RFC 792
// ICMP Message Format:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Rest of Header (4 bytes)                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// For Echo Request/Reply (Type 8/0):
//   Rest of Header = Identifier (2) + Sequence Number (2)

use super::{DropReason, IcmpInfo};

/// Minimum ICMP message size: type(1) + code(1) + checksum(2) + rest_of_header(4) = 8 bytes.
pub const ICMP_MIN_LEN: usize = 8;

/// ICMP Echo Reply type.
pub const ICMP_ECHO_REPLY: u8 = 0;

/// ICMP Echo Request type.
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// Parse an ICMP message from the bytes at the start of the ICMP payload.
///
/// `data` must start at the first byte of the ICMP message.
pub fn parse_icmp(data: &[u8]) -> Result<IcmpInfo, DropReason> {
    if data.len() < ICMP_MIN_LEN {
        return Err(DropReason::TruncatedL4);
    }

    // RFC-REF: RFC 792
    // Type (1 byte, offset 0)
    let icmp_type = data[0];

    // RFC-REF: RFC 792
    // Code (1 byte, offset 1)
    let icmp_code = data[1];

    // RFC-REF: RFC 792
    // Checksum (2 bytes, offset 2)
    let checksum = u16::from_be_bytes([data[2], data[3]]);

    // RFC-REF: RFC 792
    // Rest of Header (4 bytes, offset 4-7)
    // For Echo Request/Reply: Identifier (2) + Sequence Number (2)
    // For other types: type-specific data
    let mut rest_of_header = [0u8; 4];
    rest_of_header.copy_from_slice(&data[4..8]);

    Ok(IcmpInfo {
        icmp_type,
        icmp_code,
        checksum,
        rest_of_header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid ICMP Echo Request (8 bytes).
    /// Type=8, Code=0, ID=0x1234, Seq=0x0001
    fn make_icmp_echo_request() -> [u8; 8] {
        [
            0x08, // Type: Echo Request
            0x00, // Code: 0
            0x00, 0x00, // Checksum (placeholder)
            0x12, 0x34, // Identifier
            0x00, 0x01, // Sequence Number
        ]
    }

    #[test]
    fn icmp_parse_valid_echo() {
        let data = make_icmp_echo_request();
        let info = parse_icmp(&data).unwrap();
        assert_eq!(info.icmp_type, ICMP_ECHO_REQUEST);
        assert_eq!(info.icmp_code, 0);
        // Identifier and Sequence Number stored in rest_of_header
        assert_eq!(info.rest_of_header, [0x12, 0x34, 0x00, 0x01]);
        // Extract ID and Seq from rest_of_header
        let id = u16::from_be_bytes([info.rest_of_header[0], info.rest_of_header[1]]);
        let seq = u16::from_be_bytes([info.rest_of_header[2], info.rest_of_header[3]]);
        assert_eq!(id, 0x1234);
        assert_eq!(seq, 1);
    }

    #[test]
    fn icmp_too_short() {
        // Only 7 bytes
        let data = [0u8; 7];
        assert_eq!(parse_icmp(&data), Err(DropReason::TruncatedL4));
    }

    #[test]
    fn icmp_echo_reply() {
        let data: [u8; 8] = [
            0x00, // Type: Echo Reply
            0x00, // Code: 0
            0x00, 0x00, // Checksum
            0xAB, 0xCD, // Identifier
            0x00, 0x0A, // Sequence Number: 10
        ];
        let info = parse_icmp(&data).unwrap();
        assert_eq!(info.icmp_type, ICMP_ECHO_REPLY);
        assert_eq!(info.rest_of_header, [0xAB, 0xCD, 0x00, 0x0A]);
    }

    #[test]
    fn icmp_destination_unreachable() {
        let data: [u8; 8] = [
            0x03, // Type: Destination Unreachable
            0x01, // Code: Host Unreachable
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused (rest_of_header)
        ];
        let info = parse_icmp(&data).unwrap();
        assert_eq!(info.icmp_type, 3);
        assert_eq!(info.icmp_code, 1);
        assert_eq!(info.rest_of_header, [0x00; 4]);
    }
}

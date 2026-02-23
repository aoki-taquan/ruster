// RFC-REF: RFC 768
// UDP Header Format:
//  0      7 8     15 16    23 24    31
// +--------+--------+--------+--------+
// |     Source      |   Destination   |
// |      Port       |      Port       |
// +--------+--------+--------+--------+
// |                 |                 |
// |     Length      |    Checksum     |
// +--------+--------+--------+--------+

use super::{DropReason, UdpInfo};

/// Fixed UDP header size: 8 bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// Parse a UDP header from the bytes at the start of the UDP datagram.
///
/// `data` must start at the first byte of the UDP header.
pub fn parse_udp(data: &[u8]) -> Result<UdpInfo, DropReason> {
    if data.len() < UDP_HEADER_LEN {
        return Err(DropReason::TruncatedL4);
    }

    // RFC-REF: RFC 768
    // Source Port (2 bytes, offset 0)
    let src_port = u16::from_be_bytes([data[0], data[1]]);

    // RFC-REF: RFC 768
    // Destination Port (2 bytes, offset 2)
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    // RFC-REF: RFC 768
    // Length (2 bytes, offset 4): length of UDP header + data in bytes.
    // Must be >= 8 (header only).
    let length = u16::from_be_bytes([data[4], data[5]]);
    if length < UDP_HEADER_LEN as u16 {
        return Err(DropReason::TruncatedL4);
    }

    // Check that we have enough data for the declared length
    if data.len() < length as usize {
        return Err(DropReason::TruncatedL4);
    }

    // RFC-REF: RFC 768
    // Checksum (2 bytes, offset 6)
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    Ok(UdpInfo {
        src_port,
        dst_port,
        length,
        checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid UDP header (8 bytes).
    /// src_port=53, dst_port=1024, length=8 (header only)
    fn make_valid_udp_header() -> [u8; 8] {
        [
            0x00, 0x35, // Source Port: 53 (DNS)
            0x04, 0x00, // Destination Port: 1024
            0x00, 0x08, // Length: 8 (header only)
            0xAB, 0xCD, // Checksum
        ]
    }

    #[test]
    fn udp_parse_valid() {
        let hdr = make_valid_udp_header();
        let info = parse_udp(&hdr).unwrap();
        assert_eq!(info.src_port, 53);
        assert_eq!(info.dst_port, 1024);
        assert_eq!(info.length, 8);
        assert_eq!(info.checksum, 0xABCD);
    }

    #[test]
    fn udp_too_short() {
        // Only 7 bytes
        let data = [0u8; 7];
        assert_eq!(parse_udp(&data), Err(DropReason::TruncatedL4));
    }

    #[test]
    fn udp_length_too_small() {
        let mut hdr = make_valid_udp_header();
        // Set length to 7 (less than minimum 8)
        hdr[4] = 0x00;
        hdr[5] = 0x07;
        assert_eq!(parse_udp(&hdr), Err(DropReason::TruncatedL4));
    }

    #[test]
    fn udp_with_payload() {
        let mut pkt = Vec::new();
        // Source Port: 5000
        pkt.extend_from_slice(&[0x13, 0x88]);
        // Destination Port: 8080
        pkt.extend_from_slice(&[0x1F, 0x90]);
        // Length: 12 (8 header + 4 payload)
        pkt.extend_from_slice(&[0x00, 0x0C]);
        // Checksum: 0
        pkt.extend_from_slice(&[0x00, 0x00]);
        // Payload: "test"
        pkt.extend_from_slice(b"test");

        let info = parse_udp(&pkt).unwrap();
        assert_eq!(info.src_port, 5000);
        assert_eq!(info.dst_port, 8080);
        assert_eq!(info.length, 12);
    }
}

// RFC-REF: RFC 8200 Section 3
// IPv6 Header Format (fixed 40 bytes):
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                         +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                       +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::{DropReason, Ipv6Info};

/// Fixed IPv6 header size: 40 bytes.
pub const IPV6_HEADER_LEN: usize = 40;

/// Parse an IPv6 header from the bytes following the Ethernet header.
///
/// `data` must start at the first byte of the IPv6 header.
/// `eth_header_len` is the offset of the IPv6 header from the start of the
/// original packet (used to compute `payload_offset`).
pub fn parse_ipv6(data: &[u8], eth_header_len: usize) -> Result<Ipv6Info, DropReason> {
    if data.len() < IPV6_HEADER_LEN {
        return Err(DropReason::TruncatedL3);
    }

    // RFC-REF: RFC 8200 Section 3
    // Version (4 bits, upper nibble of byte 0) must be 6
    let version = data[0] >> 4;
    if version != 6 {
        return Err(DropReason::InvalidIpv6Header);
    }

    // RFC-REF: RFC 8200 Section 3
    // Traffic Class (8 bits): bits 4-11 of the first 4 bytes
    let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);

    // RFC-REF: RFC 8200 Section 3
    // Flow Label (20 bits): bits 12-31 of the first 4 bytes
    let flow_label = ((data[1] as u32 & 0x0F) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);

    // RFC-REF: RFC 8200 Section 3
    // Payload Length (2 bytes, offset 4): length of the payload after the
    // 40-byte header (in bytes). Does NOT include the header itself.
    let payload_length = u16::from_be_bytes([data[4], data[5]]);

    // RFC-REF: RFC 8200 Section 3
    // Next Header (1 byte, offset 6): identifies the type of header
    // immediately following the IPv6 header.
    let next_header = data[6];

    // RFC-REF: RFC 8200 Section 3
    // Hop Limit (1 byte, offset 7): decremented by 1 by each node that
    // forwards the packet.
    let hop_limit = data[7];

    // RFC-REF: RFC 8200 Section 3
    // Source Address (16 bytes, offset 8)
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&data[8..24]);

    // RFC-REF: RFC 8200 Section 3
    // Destination Address (16 bytes, offset 24)
    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(&data[24..40]);

    let payload_offset = eth_header_len + IPV6_HEADER_LEN;

    Ok(Ipv6Info {
        src_addr,
        dst_addr,
        hop_limit,
        next_header,
        payload_length,
        traffic_class,
        flow_label,
        payload_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPv6 header (40 bytes).
    /// src=2001:db8::1, dst=2001:db8::2, next_header=TCP(6), hop_limit=64
    fn make_valid_ipv6_header() -> [u8; 40] {
        let mut hdr = [0u8; 40];
        // Version=6, Traffic Class=0, Flow Label=0
        hdr[0] = 0x60;
        hdr[1] = 0x00;
        hdr[2] = 0x00;
        hdr[3] = 0x00;
        // Payload Length = 0 (header only in this test)
        hdr[4] = 0x00;
        hdr[5] = 0x00;
        // Next Header: TCP (6)
        hdr[6] = 6;
        // Hop Limit: 64
        hdr[7] = 64;
        // Source: 2001:0db8::1
        // 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
        hdr[8] = 0x20;
        hdr[9] = 0x01;
        hdr[10] = 0x0d;
        hdr[11] = 0xb8;
        // bytes 12-22 = 0 (already)
        hdr[23] = 0x01;
        // Destination: 2001:0db8::2
        hdr[24] = 0x20;
        hdr[25] = 0x01;
        hdr[26] = 0x0d;
        hdr[27] = 0xb8;
        // bytes 28-38 = 0 (already)
        hdr[39] = 0x02;
        hdr
    }

    #[test]
    fn ipv6_parse_valid() {
        let hdr = make_valid_ipv6_header();
        let info = parse_ipv6(&hdr, 14).unwrap();
        assert_eq!(
            info.src_addr,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        );
        assert_eq!(
            info.dst_addr,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]
        );
        assert_eq!(info.hop_limit, 64);
        assert_eq!(info.next_header, 6); // TCP
        assert_eq!(info.payload_length, 0);
        assert_eq!(info.traffic_class, 0);
        assert_eq!(info.flow_label, 0);
        assert_eq!(info.payload_offset, 54); // 14 (eth) + 40 (ipv6)
    }

    #[test]
    fn ipv6_too_short() {
        // Only 39 bytes
        let data = [0u8; 39];
        assert_eq!(parse_ipv6(&data, 14), Err(DropReason::TruncatedL3));
    }

    #[test]
    fn ipv6_bad_version() {
        let mut hdr = make_valid_ipv6_header();
        // Set version to 4 (IPv4)
        hdr[0] = 0x45;
        assert_eq!(parse_ipv6(&hdr, 14), Err(DropReason::InvalidIpv6Header));
    }

    #[test]
    fn ipv6_traffic_class_and_flow_label() {
        let mut hdr = make_valid_ipv6_header();
        // Version=6, TC=0xAB (1010_1011), FL=0xCDEF0
        // byte 0: version(4) | TC upper 4 = 0x6A
        // byte 1: TC lower 4 | FL upper 4 = 0xBC
        // byte 2: FL mid 8 = 0xDE
        // byte 3: FL lower 8 = 0xF0
        hdr[0] = 0x6A;
        hdr[1] = 0xBC;
        hdr[2] = 0xDE;
        hdr[3] = 0xF0;

        let info = parse_ipv6(&hdr, 14).unwrap();
        assert_eq!(info.traffic_class, 0xAB);
        assert_eq!(info.flow_label, 0xCDEF0);
    }

    #[test]
    fn ipv6_payload_length() {
        let mut hdr = make_valid_ipv6_header();
        // Set payload length to 1024
        hdr[4] = 0x04;
        hdr[5] = 0x00;

        let info = parse_ipv6(&hdr, 14).unwrap();
        assert_eq!(info.payload_length, 1024);
    }

    #[test]
    fn ipv6_icmpv6_next_header() {
        let mut hdr = make_valid_ipv6_header();
        // Next Header: ICMPv6 (58)
        hdr[6] = 58;

        let info = parse_ipv6(&hdr, 14).unwrap();
        assert_eq!(info.next_header, 58);
    }
}

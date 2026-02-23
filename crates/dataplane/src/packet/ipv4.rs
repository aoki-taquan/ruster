// RFC-REF: RFC 791 Section 3.1
// IPv4 Header Format:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::{DropReason, Ipv4Info};

/// Minimum IPv4 header size: 20 bytes (IHL = 5).
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Compute the ones' complement checksum over an IPv4 header.
///
/// For a valid header, the result of computing over the entire header
/// (including the checksum field) should be 0.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parse an IPv4 header from the bytes following the Ethernet header.
///
/// `data` must start at the first byte of the IPv4 header.
/// `eth_header_len` is the offset of the IPv4 header from the start of the
/// original packet (used to compute `payload_offset`).
pub fn parse_ipv4(data: &[u8], eth_header_len: usize) -> Result<Ipv4Info, DropReason> {
    if data.len() < IPV4_MIN_HEADER_LEN {
        return Err(DropReason::TruncatedL3);
    }

    // RFC-REF: RFC 791 Section 3.1
    // Version (4 bits, upper nibble of byte 0) must be 4
    let version = data[0] >> 4;
    if version != 4 {
        return Err(DropReason::InvalidIpv4Header);
    }

    // RFC-REF: RFC 791 Section 3.1
    // IHL (4 bits, lower nibble of byte 0): Internet Header Length in 32-bit words.
    // Must be >= 5 (20 bytes minimum).
    let ihl = (data[0] & 0x0F) as usize;
    if ihl < 5 {
        return Err(DropReason::InvalidIpv4Header);
    }
    let header_len = ihl * 4;

    // Ensure we have enough data for the full header (including options)
    if data.len() < header_len {
        return Err(DropReason::TruncatedL3);
    }

    // RFC-REF: RFC 791 Section 3.1
    // Total Length (2 bytes, offset 2): length of the datagram in bytes,
    // including header and data.
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    if (total_len as usize) < header_len {
        return Err(DropReason::InvalidIpv4Header);
    }
    // Check that we have at least total_len bytes available
    if data.len() < total_len as usize {
        return Err(DropReason::TruncatedL3);
    }

    // RFC-REF: RFC 791 Section 3.1
    // Header Checksum (2 bytes, offset 10): ones' complement checksum of the header.
    // Verification: computing the checksum over the entire header should yield 0.
    let checksum_result = ipv4_checksum(&data[..header_len]);
    if checksum_result != 0 {
        return Err(DropReason::Ipv4ChecksumError);
    }

    // RFC-REF: RFC 791 Section 3.1
    // Identification (2 bytes, offset 4)
    let identification = u16::from_be_bytes([data[4], data[5]]);

    // RFC-REF: RFC 791 Section 3.1
    // Flags (3 bits) and Fragment Offset (13 bits) at offset 6-7
    let flags_and_frag = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_and_frag >> 13) as u8;
    let fragment_offset = flags_and_frag & 0x1FFF;

    // RFC-REF: RFC 791 Section 3.1
    // Time to Live (1 byte, offset 8)
    let ttl = data[8];

    // RFC-REF: RFC 791 Section 3.1
    // Protocol (1 byte, offset 9)
    let protocol = data[9];

    // RFC-REF: RFC 791 Section 3.1
    // Header Checksum (2 bytes, offset 10)
    let checksum = u16::from_be_bytes([data[10], data[11]]);

    // RFC-REF: RFC 791 Section 3.1
    // Source Address (4 bytes, offset 12)
    let mut src_addr = [0u8; 4];
    src_addr.copy_from_slice(&data[12..16]);

    // RFC-REF: RFC 791 Section 3.1
    // Destination Address (4 bytes, offset 16)
    let mut dst_addr = [0u8; 4];
    dst_addr.copy_from_slice(&data[16..20]);

    let payload_offset = eth_header_len + header_len;

    Ok(Ipv4Info {
        src_addr,
        dst_addr,
        ttl,
        protocol,
        header_len,
        total_len,
        identification,
        flags,
        fragment_offset,
        checksum,
        payload_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPv4 header (20 bytes) with correct checksum.
    /// src=192.168.1.1, dst=10.0.0.1, protocol=TCP(6), ttl=64
    fn make_valid_ipv4_header() -> [u8; 20] {
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45; // Version=4, IHL=5
        hdr[1] = 0x00; // DSCP/ECN
                       // Total Length = 20 (header only, no payload)
        hdr[2] = 0x00;
        hdr[3] = 0x14;
        // Identification
        hdr[4] = 0x00;
        hdr[5] = 0x01;
        // Flags + Fragment Offset: DF set
        hdr[6] = 0x40;
        hdr[7] = 0x00;
        // TTL
        hdr[8] = 64;
        // Protocol: TCP
        hdr[9] = 6;
        // Checksum: will compute below
        hdr[10] = 0x00;
        hdr[11] = 0x00;
        // Source: 192.168.1.1
        hdr[12] = 192;
        hdr[13] = 168;
        hdr[14] = 1;
        hdr[15] = 1;
        // Destination: 10.0.0.1
        hdr[16] = 10;
        hdr[17] = 0;
        hdr[18] = 0;
        hdr[19] = 1;

        // Compute and set checksum
        let cksum = ipv4_checksum(&hdr);
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = (cksum & 0xFF) as u8;
        hdr
    }

    #[test]
    fn ipv4_parse_valid() {
        let hdr = make_valid_ipv4_header();
        let info = parse_ipv4(&hdr, 14).unwrap();
        assert_eq!(info.src_addr, [192, 168, 1, 1]);
        assert_eq!(info.dst_addr, [10, 0, 0, 1]);
        assert_eq!(info.ttl, 64);
        assert_eq!(info.protocol, 6); // TCP
        assert_eq!(info.header_len, 20);
        assert_eq!(info.total_len, 20);
        assert_eq!(info.flags, 0x02); // DF
        assert_eq!(info.fragment_offset, 0);
        assert_eq!(info.payload_offset, 34); // 14 (eth) + 20 (ipv4)
    }

    #[test]
    fn ipv4_too_short() {
        // Only 19 bytes
        let data = [0u8; 19];
        assert_eq!(parse_ipv4(&data, 14), Err(DropReason::TruncatedL3));
    }

    #[test]
    fn ipv4_bad_version() {
        let mut hdr = make_valid_ipv4_header();
        // Set version to 6 (IPv6)
        hdr[0] = 0x65; // Version=6, IHL=5
        assert_eq!(parse_ipv4(&hdr, 14), Err(DropReason::InvalidIpv4Header));
    }

    #[test]
    fn ipv4_checksum_error() {
        let mut hdr = make_valid_ipv4_header();
        // Corrupt the checksum
        hdr[10] ^= 0xFF;
        assert_eq!(parse_ipv4(&hdr, 14), Err(DropReason::Ipv4ChecksumError));
    }

    #[test]
    fn ipv4_ihl_too_small() {
        let mut hdr = make_valid_ipv4_header();
        // Set IHL to 4 (invalid, minimum is 5)
        hdr[0] = 0x44;
        assert_eq!(parse_ipv4(&hdr, 14), Err(DropReason::InvalidIpv4Header));
    }

    #[test]
    fn ipv4_total_len_less_than_header() {
        let mut hdr = make_valid_ipv4_header();
        // Set total_len to 10 (less than header_len=20)
        hdr[2] = 0x00;
        hdr[3] = 0x0A;
        // Recompute checksum with wrong total_len
        hdr[10] = 0x00;
        hdr[11] = 0x00;
        let cksum = ipv4_checksum(&hdr);
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = (cksum & 0xFF) as u8;
        assert_eq!(parse_ipv4(&hdr, 14), Err(DropReason::InvalidIpv4Header));
    }
}

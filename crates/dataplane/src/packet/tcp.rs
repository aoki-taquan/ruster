// RFC-REF: RFC 9293 Section 3.1
// TCP Header Format:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |       |C|E|U|A|P|R|S|F|                               |
// | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
// |       |       |R|E|G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::{DropReason, TcpInfo};

/// Minimum TCP header size: 20 bytes (data offset = 5).
pub const TCP_MIN_HEADER_LEN: usize = 20;

// RFC-REF: RFC 9293 Section 3.1
// TCP flag bit masks (lower 6 bits of the flags byte)
/// FIN flag: No more data from sender.
pub const TCP_FIN: u8 = 0x01;
/// SYN flag: Synchronize sequence numbers.
pub const TCP_SYN: u8 = 0x02;
/// RST flag: Reset the connection.
pub const TCP_RST: u8 = 0x04;
/// PSH flag: Push function.
pub const TCP_PSH: u8 = 0x08;
/// ACK flag: Acknowledgment field significant.
pub const TCP_ACK: u8 = 0x10;
/// URG flag: Urgent pointer field significant.
pub const TCP_URG: u8 = 0x20;

/// Parse a TCP header from the bytes at the start of the TCP segment.
///
/// `data` must start at the first byte of the TCP header.
pub fn parse_tcp(data: &[u8]) -> Result<TcpInfo, DropReason> {
    if data.len() < TCP_MIN_HEADER_LEN {
        return Err(DropReason::TruncatedL4);
    }

    // RFC-REF: RFC 9293 Section 3.1
    // Source Port (2 bytes, offset 0)
    let src_port = u16::from_be_bytes([data[0], data[1]]);

    // RFC-REF: RFC 9293 Section 3.1
    // Destination Port (2 bytes, offset 2)
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    // RFC-REF: RFC 9293 Section 3.1
    // Sequence Number (4 bytes, offset 4)
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    // RFC-REF: RFC 9293 Section 3.1
    // Acknowledgment Number (4 bytes, offset 8)
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    // RFC-REF: RFC 9293 Section 3.1
    // Data Offset (4 bits, upper nibble of byte 12): header length in 32-bit words.
    // Must be >= 5.
    let data_offset = data[12] >> 4;
    if data_offset < 5 {
        return Err(DropReason::TruncatedL4);
    }

    // Ensure we have enough data for the full header
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len {
        return Err(DropReason::TruncatedL4);
    }

    // RFC-REF: RFC 9293 Section 3.1
    // Flags (lower 6 bits of byte 13)
    let flags = data[13] & 0x3F;

    // RFC-REF: RFC 9293 Section 3.1
    // Window (2 bytes, offset 14)
    let window = u16::from_be_bytes([data[14], data[15]]);

    // RFC-REF: RFC 9293 Section 3.1
    // Checksum (2 bytes, offset 16)
    let checksum = u16::from_be_bytes([data[16], data[17]]);

    Ok(TcpInfo {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        flags,
        window,
        checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid TCP header (20 bytes).
    /// src_port=12345, dst_port=80, SYN flag set
    fn make_valid_tcp_header() -> [u8; 20] {
        let mut hdr = [0u8; 20];
        // Source Port: 12345 (0x3039)
        hdr[0] = 0x30;
        hdr[1] = 0x39;
        // Destination Port: 80 (0x0050)
        hdr[2] = 0x00;
        hdr[3] = 0x50;
        // Sequence Number: 0x00000001
        hdr[4] = 0x00;
        hdr[5] = 0x00;
        hdr[6] = 0x00;
        hdr[7] = 0x01;
        // Acknowledgment Number: 0
        hdr[8] = 0x00;
        hdr[9] = 0x00;
        hdr[10] = 0x00;
        hdr[11] = 0x00;
        // Data Offset: 5 (20 bytes), Reserved: 0
        hdr[12] = 0x50;
        // Flags: SYN
        hdr[13] = TCP_SYN;
        // Window: 65535 (0xFFFF)
        hdr[14] = 0xFF;
        hdr[15] = 0xFF;
        // Checksum: 0x1234 (not validated in parser)
        hdr[16] = 0x12;
        hdr[17] = 0x34;
        // Urgent Pointer: 0
        hdr[18] = 0x00;
        hdr[19] = 0x00;
        hdr
    }

    #[test]
    fn tcp_parse_valid() {
        let hdr = make_valid_tcp_header();
        let info = parse_tcp(&hdr).unwrap();
        assert_eq!(info.src_port, 12345);
        assert_eq!(info.dst_port, 80);
        assert_eq!(info.seq_num, 1);
        assert_eq!(info.ack_num, 0);
        assert_eq!(info.data_offset, 5);
        assert_eq!(info.flags, TCP_SYN);
        assert_eq!(info.window, 65535);
        assert_eq!(info.checksum, 0x1234);
    }

    #[test]
    fn tcp_too_short() {
        // Only 19 bytes
        let data = [0u8; 19];
        assert_eq!(parse_tcp(&data), Err(DropReason::TruncatedL4));
    }

    #[test]
    fn tcp_data_offset_too_small() {
        let mut hdr = make_valid_tcp_header();
        // Set data offset to 4 (invalid, minimum is 5)
        hdr[12] = 0x40;
        assert_eq!(parse_tcp(&hdr), Err(DropReason::TruncatedL4));
    }

    #[test]
    fn tcp_syn_ack_flags() {
        let mut hdr = make_valid_tcp_header();
        hdr[13] = TCP_SYN | TCP_ACK;
        let info = parse_tcp(&hdr).unwrap();
        assert_eq!(info.flags & TCP_SYN, TCP_SYN);
        assert_eq!(info.flags & TCP_ACK, TCP_ACK);
        assert_eq!(info.flags & TCP_FIN, 0);
    }
}

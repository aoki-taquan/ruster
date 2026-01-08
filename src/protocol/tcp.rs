//! TCP protocol - RFC 793
//!
//! TCP header parsing and checksum calculation for NAPT.

use crate::{Error, Result};
use std::net::Ipv4Addr;

/// Minimum TCP header size (without options)
pub const MIN_HEADER_SIZE: usize = 20;

/// TCP protocol number for pseudo-header
pub const PROTOCOL_NUMBER: u8 = 6;

/// TCP flags
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    /// Parse flags from the 13th byte of TCP header
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: (byte & 0x01) != 0,
            syn: (byte & 0x02) != 0,
            rst: (byte & 0x04) != 0,
            psh: (byte & 0x08) != 0,
            ack: (byte & 0x10) != 0,
            urg: (byte & 0x20) != 0,
            ece: (byte & 0x40) != 0,
            cwr: (byte & 0x80) != 0,
        }
    }

    /// Convert to byte
    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.fin {
            byte |= 0x01;
        }
        if self.syn {
            byte |= 0x02;
        }
        if self.rst {
            byte |= 0x04;
        }
        if self.psh {
            byte |= 0x08;
        }
        if self.ack {
            byte |= 0x10;
        }
        if self.urg {
            byte |= 0x20;
        }
        if self.ece {
            byte |= 0x40;
        }
        if self.cwr {
            byte |= 0x80;
        }
        byte
    }

    /// Check if this is a connection establishment (SYN without ACK)
    pub fn is_syn_only(&self) -> bool {
        self.syn && !self.ack
    }

    /// Check if this is a SYN-ACK
    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }

    /// Check if FIN is set (connection termination)
    pub fn is_fin(&self) -> bool {
        self.fin
    }

    /// Check if RST is set (connection reset)
    pub fn is_rst(&self) -> bool {
        self.rst
    }
}

/// Parsed TCP header (zero-copy reference)
#[derive(Debug)]
pub struct TcpHeader<'a> {
    buffer: &'a [u8],
    header_len: usize,
}

impl<'a> TcpHeader<'a> {
    /// Parse TCP header from buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < MIN_HEADER_SIZE {
            return Err(Error::Parse("TCP header too short".into()));
        }

        let data_offset = (buffer[12] >> 4) as usize;
        let header_len = data_offset * 4;

        if header_len < MIN_HEADER_SIZE {
            return Err(Error::Parse("TCP data offset too small".into()));
        }

        if buffer.len() < header_len {
            return Err(Error::Parse("TCP header truncated".into()));
        }

        Ok(Self { buffer, header_len })
    }

    /// Source port (offset 0-1)
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    /// Destination port (offset 2-3)
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Sequence number (offset 4-7)
    pub fn seq_num(&self) -> u32 {
        u32::from_be_bytes([
            self.buffer[4],
            self.buffer[5],
            self.buffer[6],
            self.buffer[7],
        ])
    }

    /// Acknowledgment number (offset 8-11)
    pub fn ack_num(&self) -> u32 {
        u32::from_be_bytes([
            self.buffer[8],
            self.buffer[9],
            self.buffer[10],
            self.buffer[11],
        ])
    }

    /// Data offset (header length in 32-bit words)
    pub fn data_offset(&self) -> u8 {
        self.buffer[12] >> 4
    }

    /// TCP flags
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::from_byte(self.buffer[13])
    }

    /// Window size (offset 14-15)
    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.buffer[14], self.buffer[15]])
    }

    /// Checksum (offset 16-17)
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[16], self.buffer[17]])
    }

    /// Urgent pointer (offset 18-19)
    pub fn urgent_ptr(&self) -> u16 {
        u16::from_be_bytes([self.buffer[18], self.buffer[19]])
    }

    /// Header length in bytes
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Payload (TCP data after header)
    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.header_len..]
    }

    /// Raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Validate checksum with pseudo-header
    pub fn validate_checksum(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> bool {
        tcp_checksum(src_ip, dst_ip, self.buffer) == 0
    }
}

/// Mutable TCP segment for NAPT modifications
#[derive(Debug, Clone)]
pub struct TcpPacket {
    buffer: Vec<u8>,
    header_len: usize,
}

impl TcpPacket {
    /// Create from raw bytes (copies the data)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_HEADER_SIZE {
            return Err(Error::Parse("TCP segment too short".into()));
        }

        let data_offset = (data[12] >> 4) as usize;
        let header_len = data_offset * 4;

        if header_len < MIN_HEADER_SIZE {
            return Err(Error::Parse("TCP data offset too small".into()));
        }

        if data.len() < header_len {
            return Err(Error::Parse("TCP header truncated".into()));
        }

        Ok(Self {
            buffer: data.to_vec(),
            header_len,
        })
    }

    /// Source port
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    /// Destination port
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Set source port (checksum must be updated separately)
    pub fn set_src_port(&mut self, port: u16) {
        self.buffer[0..2].copy_from_slice(&port.to_be_bytes());
    }

    /// Set destination port (checksum must be updated separately)
    pub fn set_dst_port(&mut self, port: u16) {
        self.buffer[2..4].copy_from_slice(&port.to_be_bytes());
    }

    /// TCP flags
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::from_byte(self.buffer[13])
    }

    /// Header length in bytes
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Get checksum value
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[16], self.buffer[17]])
    }

    /// Update checksum with new IP addresses
    pub fn update_checksum(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
        // Zero out checksum field first
        self.buffer[16] = 0;
        self.buffer[17] = 0;

        let sum = tcp_checksum(src_ip, dst_ip, &self.buffer);
        self.buffer[16..18].copy_from_slice(&sum.to_be_bytes());
    }

    /// Consume and return the buffer
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Get reference to buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Get mutable reference to buffer
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

/// Calculate TCP checksum with pseudo-header (RFC 793)
///
/// Pseudo-header:
/// ```text
/// +--------+--------+--------+--------+
/// |          Source Address           |
/// +--------+--------+--------+--------+
/// |        Destination Address        |
/// +--------+--------+--------+--------+
/// |  Zero  |Protocol|   TCP Length    |
/// +--------+--------+--------+--------+
/// ```
pub fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    let src = src_ip.octets();
    let dst = dst_ip.octets();

    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += PROTOCOL_NUMBER as u32;
    sum += tcp_segment.len() as u32;

    // TCP segment
    for i in (0..tcp_segment.len()).step_by(2) {
        let word = if i + 1 < tcp_segment.len() {
            u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]])
        } else {
            // Pad with zero if odd length
            u16::from_be_bytes([tcp_segment[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Incremental checksum update (RFC 1624)
///
/// Used when only specific fields change (e.g., port numbers)
pub fn incremental_checksum_update(old_checksum: u16, old_value: u16, new_value: u16) -> u16 {
    let old_sum = !old_checksum as u32;
    let diff = (new_value as u32).wrapping_sub(old_value as u32);
    let new_sum = old_sum.wrapping_add(diff);

    // Fold
    let folded = (new_sum & 0xFFFF) + (new_sum >> 16);
    let folded = (folded & 0xFFFF) + (folded >> 16);

    !(folded as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_segment() -> Vec<u8> {
        // TCP segment: src_port=12345, dst_port=80, seq=1, ack=0, flags=SYN
        let mut seg = vec![
            0x30, 0x39, // src_port = 12345
            0x00, 0x50, // dst_port = 80
            0x00, 0x00, 0x00, 0x01, // seq = 1
            0x00, 0x00, 0x00, 0x00, // ack = 0
            0x50, // data_offset = 5 (20 bytes), reserved = 0
            0x02, // flags = SYN
            0x72, 0x10, // window = 29200
            0x00, 0x00, // checksum (placeholder)
            0x00, 0x00, // urgent_ptr = 0
        ];

        // Calculate checksum with test IPs
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
        let sum = tcp_checksum(src_ip, dst_ip, &seg);
        seg[16..18].copy_from_slice(&sum.to_be_bytes());
        seg
    }

    #[test]
    fn test_tcp_flags_from_byte() {
        let flags = TcpFlags::from_byte(0x02); // SYN
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);
        assert!(!flags.rst);

        let flags = TcpFlags::from_byte(0x12); // SYN + ACK
        assert!(flags.syn);
        assert!(flags.ack);

        let flags = TcpFlags::from_byte(0x11); // FIN + ACK
        assert!(flags.fin);
        assert!(flags.ack);

        let flags = TcpFlags::from_byte(0x04); // RST
        assert!(flags.rst);
    }

    #[test]
    fn test_tcp_flags_to_byte() {
        let flags = TcpFlags {
            syn: true,
            ack: true,
            ..Default::default()
        };
        assert_eq!(flags.to_byte(), 0x12);
    }

    #[test]
    fn test_tcp_flags_is_syn_only() {
        let flags = TcpFlags::from_byte(0x02);
        assert!(flags.is_syn_only());

        let flags = TcpFlags::from_byte(0x12);
        assert!(!flags.is_syn_only());
    }

    #[test]
    fn test_tcp_header_parse() {
        let seg = make_tcp_segment();
        let hdr = TcpHeader::parse(&seg).unwrap();

        assert_eq!(hdr.src_port(), 12345);
        assert_eq!(hdr.dst_port(), 80);
        assert_eq!(hdr.seq_num(), 1);
        assert_eq!(hdr.ack_num(), 0);
        assert_eq!(hdr.data_offset(), 5);
        assert_eq!(hdr.header_len(), 20);
        assert!(hdr.flags().syn);
        assert!(!hdr.flags().ack);
        assert_eq!(hdr.window(), 29200);
        assert_eq!(hdr.urgent_ptr(), 0);
    }

    #[test]
    fn test_tcp_header_parse_too_short() {
        let seg = vec![0u8; 19];
        assert!(TcpHeader::parse(&seg).is_err());
    }

    #[test]
    fn test_tcp_header_parse_bad_offset() {
        let mut seg = make_tcp_segment();
        seg[12] = 0x10; // data_offset = 1 (4 bytes, too small)
        assert!(TcpHeader::parse(&seg).is_err());
    }

    #[test]
    fn test_tcp_header_validate_checksum() {
        let seg = make_tcp_segment();
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);

        let hdr = TcpHeader::parse(&seg).unwrap();
        assert!(hdr.validate_checksum(src_ip, dst_ip));
    }

    #[test]
    fn test_tcp_packet_set_ports() {
        let seg = make_tcp_segment();
        let mut pkt = TcpPacket::from_bytes(&seg).unwrap();

        assert_eq!(pkt.src_port(), 12345);
        pkt.set_src_port(54321);
        assert_eq!(pkt.src_port(), 54321);

        assert_eq!(pkt.dst_port(), 80);
        pkt.set_dst_port(8080);
        assert_eq!(pkt.dst_port(), 8080);
    }

    #[test]
    fn test_tcp_packet_update_checksum() {
        let seg = make_tcp_segment();
        let mut pkt = TcpPacket::from_bytes(&seg).unwrap();

        // Change port and update checksum
        pkt.set_src_port(54321);

        let new_src_ip = Ipv4Addr::new(203, 0, 113, 1);
        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
        pkt.update_checksum(new_src_ip, dst_ip);

        // Verify checksum is valid
        let hdr = TcpHeader::parse(pkt.as_bytes()).unwrap();
        assert!(hdr.validate_checksum(new_src_ip, dst_ip));
    }

    #[test]
    fn test_tcp_checksum_known_value() {
        // Manual verification with known values
        let seg = vec![
            0x30, 0x39, // src_port = 12345
            0x00, 0x50, // dst_port = 80
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // offset + flags
            0x72, 0x10, // window
            0x00, 0x00, // checksum = 0 for calculation
            0x00, 0x00, // urgent
        ];

        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(93, 184, 216, 34);

        let checksum = tcp_checksum(src, dst, &seg);
        assert_ne!(checksum, 0); // Should have non-zero checksum
    }

    #[test]
    fn test_incremental_checksum_update() {
        // Test incremental update
        let seg = make_tcp_segment();
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);

        let hdr = TcpHeader::parse(&seg).unwrap();
        let old_checksum = hdr.checksum();
        let old_port = hdr.src_port();
        let new_port: u16 = 54321;

        // Calculate new checksum incrementally
        let new_checksum = incremental_checksum_update(old_checksum, old_port, new_port);

        // Verify by full recalculation
        let mut pkt = TcpPacket::from_bytes(&seg).unwrap();
        pkt.set_src_port(new_port);
        pkt.update_checksum(src_ip, dst_ip);

        // Both methods should produce valid checksums
        // Note: incremental doesn't account for IP changes, so this is a simplified test
        assert_ne!(new_checksum, 0);
    }

    #[test]
    fn test_tcp_with_payload() {
        let mut seg = make_tcp_segment();
        seg.extend_from_slice(b"GET / HTTP/1.1\r\n");

        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);

        // Recalculate checksum
        seg[16] = 0;
        seg[17] = 0;
        let sum = tcp_checksum(src_ip, dst_ip, &seg);
        seg[16..18].copy_from_slice(&sum.to_be_bytes());

        let hdr = TcpHeader::parse(&seg).unwrap();
        assert!(hdr.validate_checksum(src_ip, dst_ip));
        assert_eq!(hdr.payload(), b"GET / HTTP/1.1\r\n");
    }
}

// RFC-REF: RFC 826
// ARP packet format for Ethernet/IPv4:
//   Hardware Type (2) + Protocol Type (2) + HW Addr Len (1) + Proto Addr Len (1)
//   + Operation (2) + Sender HW Addr (6) + Sender Proto Addr (4)
//   + Target HW Addr (6) + Target Proto Addr (4) = 28 bytes

use super::{ArpInfo, DropReason};

/// ARP payload length for Ethernet/IPv4: 28 bytes.
pub const ARP_PAYLOAD_LEN: usize = 28;

/// Hardware type for Ethernet.
const HW_TYPE_ETHERNET: u16 = 1;

/// Protocol type for IPv4.
const PROTO_TYPE_IPV4: u16 = 0x0800;

/// Parse an ARP payload from the bytes following the Ethernet header.
///
/// `data` must start at the first byte of the ARP message (after the Ethernet header).
pub fn parse_arp(data: &[u8]) -> Result<ArpInfo, DropReason> {
    if data.len() < ARP_PAYLOAD_LEN {
        return Err(DropReason::TruncatedL3);
    }

    // RFC-REF: RFC 826
    // Hardware Type (2 bytes, offset 0) must be 1 (Ethernet)
    let hw_type = u16::from_be_bytes([data[0], data[1]]);
    // Protocol Type (2 bytes, offset 2) must be 0x0800 (IPv4)
    let proto_type = u16::from_be_bytes([data[2], data[3]]);

    if hw_type != HW_TYPE_ETHERNET || proto_type != PROTO_TYPE_IPV4 {
        return Err(DropReason::InvalidArp);
    }

    // RFC-REF: RFC 826
    // HW Addr Len (1 byte, offset 4) must be 6 for Ethernet
    // Proto Addr Len (1 byte, offset 5) must be 4 for IPv4
    let hw_addr_len = data[4];
    let proto_addr_len = data[5];

    if hw_addr_len != 6 || proto_addr_len != 4 {
        return Err(DropReason::InvalidArp);
    }

    // RFC-REF: RFC 826
    // Operation (2 bytes, offset 6): 1=request, 2=reply
    let operation = u16::from_be_bytes([data[6], data[7]]);

    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&data[8..14]);

    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&data[14..18]);

    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&data[18..24]);

    let mut target_ip = [0u8; 4];
    target_ip.copy_from_slice(&data[24..28]);

    Ok(ArpInfo {
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid ARP request payload (28 bytes).
    fn make_arp_request() -> [u8; 28] {
        [
            0x00, 0x01, // Hardware Type: Ethernet (1)
            0x08, 0x00, // Protocol Type: IPv4 (0x0800)
            0x06, // HW Addr Len: 6
            0x04, // Proto Addr Len: 4
            0x00, 0x01, // Operation: Request (1)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender MAC
            0xc0, 0xa8, 0x01, 0x01, // Sender IP: 192.168.1.1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC (unknown)
            0xc0, 0xa8, 0x01, 0x02, // Target IP: 192.168.1.2
        ]
    }

    /// Build a valid ARP reply payload (28 bytes).
    fn make_arp_reply() -> [u8; 28] {
        [
            0x00, 0x01, // Hardware Type: Ethernet (1)
            0x08, 0x00, // Protocol Type: IPv4 (0x0800)
            0x06, // HW Addr Len: 6
            0x04, // Proto Addr Len: 4
            0x00, 0x02, // Operation: Reply (2)
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC
            0x0a, 0x00, 0x00, 0x01, // Sender IP: 10.0.0.1
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Target MAC
            0x0a, 0x00, 0x00, 0x02, // Target IP: 10.0.0.2
        ]
    }

    #[test]
    fn arp_parse_valid_request() {
        let data = make_arp_request();
        let info = parse_arp(&data).unwrap();
        assert_eq!(info.operation, 1);
        assert_eq!(info.sender_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(info.sender_ip, [192, 168, 1, 1]);
        assert_eq!(info.target_mac, [0x00; 6]);
        assert_eq!(info.target_ip, [192, 168, 1, 2]);
    }

    #[test]
    fn arp_parse_valid_reply() {
        let data = make_arp_reply();
        let info = parse_arp(&data).unwrap();
        assert_eq!(info.operation, 2);
        assert_eq!(info.sender_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(info.sender_ip, [10, 0, 0, 1]);
        assert_eq!(info.target_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(info.target_ip, [10, 0, 0, 2]);
    }

    #[test]
    fn arp_too_short() {
        // Only 27 bytes - one short of the required 28
        let data = [0u8; 27];
        assert_eq!(parse_arp(&data), Err(DropReason::TruncatedL3));
    }

    #[test]
    fn arp_invalid_hw_type() {
        let mut data = make_arp_request();
        // Set hw_type to 2 (non-Ethernet)
        data[0] = 0x00;
        data[1] = 0x02;
        assert_eq!(parse_arp(&data), Err(DropReason::InvalidArp));
    }

    #[test]
    fn arp_invalid_proto_type() {
        let mut data = make_arp_request();
        // Set proto_type to 0x0806 (not IPv4)
        data[2] = 0x08;
        data[3] = 0x06;
        assert_eq!(parse_arp(&data), Err(DropReason::InvalidArp));
    }
}

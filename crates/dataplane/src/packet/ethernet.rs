// RFC-REF: RFC 894
// Ethernet frame format: dst MAC (6) + src MAC (6) + EtherType (2) + payload

use super::{DropReason, L2Info};

/// Minimum Ethernet header size: 6 (dst) + 6 (src) + 2 (ethertype) = 14 bytes.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Parse an Ethernet frame header from a raw byte slice.
///
/// Returns `(L2Info, payload_offset)` on success, where `payload_offset`
/// points to the first byte after the Ethernet header.
pub fn parse_ethernet(data: &[u8]) -> Result<(L2Info, usize), DropReason> {
    if data.len() < ETHERNET_HEADER_LEN {
        return Err(DropReason::TooShort);
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);

    // RFC-REF: RFC 894
    // EtherType is a 2-byte big-endian field at offset 12
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    Ok((
        L2Info {
            dst_mac,
            src_mac,
            ethertype,
        },
        ETHERNET_HEADER_LEN,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_parse_valid() {
        // dst: 00:11:22:33:44:55, src: 66:77:88:99:aa:bb, ethertype: 0x0800 (IPv4)
        let frame: [u8; 14] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
            0x08, 0x00, // EtherType: IPv4
        ];

        let (l2, offset) = parse_ethernet(&frame).unwrap();
        assert_eq!(l2.dst_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(l2.src_mac, [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        assert_eq!(l2.ethertype, 0x0800);
        assert_eq!(offset, 14);
    }

    #[test]
    fn ethernet_too_short() {
        // Only 13 bytes - one short of minimum
        let frame: [u8; 13] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08,
        ];
        assert_eq!(parse_ethernet(&frame), Err(DropReason::TooShort));
    }

    #[test]
    fn ethernet_empty() {
        assert_eq!(parse_ethernet(&[]), Err(DropReason::TooShort));
    }

    #[test]
    fn ethernet_parse_arp_ethertype() {
        let frame: [u8; 14] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC (broadcast)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
            0x08, 0x06, // EtherType: ARP
        ];
        let (l2, _) = parse_ethernet(&frame).unwrap();
        assert_eq!(l2.ethertype, 0x0806);
    }
}

// RFC-REF: RFC 4861 Section 4.3, 4.4
// Neighbor Solicitation (type 135) and Neighbor Advertisement (type 136)
// are used for IPv6 address resolution (analogous to ARP in IPv4).
//
// RFC-REF: RFC 4443 Section 2.1
// ICMPv6 General Message Format:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Message Body                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::{DropReason, Icmpv6Info, NdInfo};

/// Minimum ICMPv6 message size: type(1) + code(1) + checksum(2) = 4 bytes.
pub const ICMPV6_MIN_LEN: usize = 4;

/// ICMPv6 type: Neighbor Solicitation.
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;

/// ICMPv6 type: Neighbor Advertisement.
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// ICMPv6 type: Echo Request.
pub const ICMPV6_ECHO_REQUEST: u8 = 128;

/// ICMPv6 type: Echo Reply.
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// ND option type: Source Link-Layer Address.
const ND_OPT_SOURCE_LINK_LAYER: u8 = 1;

/// ND option type: Target Link-Layer Address.
const ND_OPT_TARGET_LINK_LAYER: u8 = 2;

/// Minimum Neighbor Solicitation size: 4 (ICMPv6 header) + 4 (reserved) + 16 (target) = 24.
const NS_MIN_LEN: usize = 24;

/// Minimum Neighbor Advertisement size: 4 (ICMPv6 header) + 4 (flags+reserved) + 16 (target) = 24.
const NA_MIN_LEN: usize = 24;

/// Parse an ICMPv6 message from the bytes at the start of the ICMPv6 payload.
///
/// `data` must start at the first byte of the ICMPv6 message.
pub fn parse_icmpv6(data: &[u8]) -> Result<Icmpv6Info, DropReason> {
    if data.len() < ICMPV6_MIN_LEN {
        return Err(DropReason::TruncatedL4);
    }

    // RFC-REF: RFC 4443 Section 2.1
    let icmpv6_type = data[0];
    let icmpv6_code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);

    // Try to parse Neighbor Discovery messages
    let nd = match icmpv6_type {
        ICMPV6_NEIGHBOR_SOLICITATION => parse_neighbor_solicitation(data)?,
        ICMPV6_NEIGHBOR_ADVERTISEMENT => parse_neighbor_advertisement(data)?,
        _ => None,
    };

    Ok(Icmpv6Info {
        icmpv6_type,
        icmpv6_code,
        checksum,
        nd,
    })
}

/// Parse Neighbor Solicitation (type 135).
///
/// RFC-REF: RFC 4861 Section 4.3
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Target Address                          +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
fn parse_neighbor_solicitation(data: &[u8]) -> Result<Option<NdInfo>, DropReason> {
    if data.len() < NS_MIN_LEN {
        return Err(DropReason::TruncatedL4);
    }

    // Target address: bytes 8..24
    let mut target_addr = [0u8; 16];
    target_addr.copy_from_slice(&data[8..24]);

    // Look for Source Link-Layer Address option in remaining bytes
    let source_mac = parse_nd_option_mac(data, NS_MIN_LEN, ND_OPT_SOURCE_LINK_LAYER);

    Ok(Some(NdInfo::NeighborSolicitation {
        target_addr,
        source_mac,
    }))
}

/// Parse Neighbor Advertisement (type 136).
///
/// RFC-REF: RFC 4861 Section 4.4
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|S|O|                     Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Target Address                          +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
fn parse_neighbor_advertisement(data: &[u8]) -> Result<Option<NdInfo>, DropReason> {
    if data.len() < NA_MIN_LEN {
        return Err(DropReason::TruncatedL4);
    }

    // Target address: bytes 8..24
    let mut target_addr = [0u8; 16];
    target_addr.copy_from_slice(&data[8..24]);

    // Look for Target Link-Layer Address option
    let target_mac = parse_nd_option_mac(data, NA_MIN_LEN, ND_OPT_TARGET_LINK_LAYER);

    Ok(Some(NdInfo::NeighborAdvertisement {
        target_addr,
        target_mac,
    }))
}

/// Scan ND options starting at `offset` for a link-layer address option
/// with the specified `opt_type`.
///
/// RFC-REF: RFC 4861 Section 4.6.1
/// Option format:
///   Type (1 byte) | Length (1 byte, in units of 8 octets) | Link-Layer Address
fn parse_nd_option_mac(data: &[u8], start: usize, opt_type: u8) -> Option<[u8; 6]> {
    let mut offset = start;
    while offset + 2 <= data.len() {
        let t = data[offset];
        let len = data[offset + 1] as usize;
        if len == 0 {
            break; // Length of 0 is invalid, prevent infinite loop
        }
        let opt_total = len * 8;
        if offset + opt_total > data.len() {
            break;
        }
        if t == opt_type && opt_total >= 8 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&data[offset + 2..offset + 8]);
            return Some(mac);
        }
        offset += opt_total;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Neighbor Solicitation (type 135) without options.
    fn make_ns_no_options(target: [u8; 16]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(ICMPV6_NEIGHBOR_SOLICITATION); // Type
        pkt.push(0x00); // Code
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved
        pkt.extend_from_slice(&target); // Target Address
        pkt
    }

    /// Build a Neighbor Solicitation with a Source Link-Layer Address option.
    fn make_ns_with_source_mac(target: [u8; 16], mac: [u8; 6]) -> Vec<u8> {
        let mut pkt = make_ns_no_options(target);
        // Source Link-Layer Address option: type=1, length=1 (8 bytes)
        pkt.push(ND_OPT_SOURCE_LINK_LAYER);
        pkt.push(1); // length in 8-byte units
        pkt.extend_from_slice(&mac);
        pkt
    }

    /// Build a Neighbor Advertisement (type 136) with a Target Link-Layer Address option.
    fn make_na_with_target_mac(target: [u8; 16], mac: [u8; 6]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(ICMPV6_NEIGHBOR_ADVERTISEMENT); // Type
        pkt.push(0x00); // Code
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        // Flags: R=0, S=1, O=1 + Reserved
        pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&target); // Target Address
        // Target Link-Layer Address option: type=2, length=1 (8 bytes)
        pkt.push(ND_OPT_TARGET_LINK_LAYER);
        pkt.push(1);
        pkt.extend_from_slice(&mac);
        pkt
    }

    const TARGET_ADDR: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    const TEST_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    #[test]
    fn parse_ns_without_options() {
        let pkt = make_ns_no_options(TARGET_ADDR);
        let info = parse_icmpv6(&pkt).unwrap();
        assert_eq!(info.icmpv6_type, ICMPV6_NEIGHBOR_SOLICITATION);
        assert_eq!(info.icmpv6_code, 0);
        match &info.nd {
            Some(NdInfo::NeighborSolicitation {
                target_addr,
                source_mac,
            }) => {
                assert_eq!(target_addr, &TARGET_ADDR);
                assert_eq!(*source_mac, None);
            }
            _ => panic!("expected NeighborSolicitation"),
        }
    }

    #[test]
    fn parse_ns_with_source_mac() {
        let pkt = make_ns_with_source_mac(TARGET_ADDR, TEST_MAC);
        let info = parse_icmpv6(&pkt).unwrap();
        match &info.nd {
            Some(NdInfo::NeighborSolicitation {
                target_addr,
                source_mac,
            }) => {
                assert_eq!(target_addr, &TARGET_ADDR);
                assert_eq!(*source_mac, Some(TEST_MAC));
            }
            _ => panic!("expected NeighborSolicitation"),
        }
    }

    #[test]
    fn parse_na_with_target_mac() {
        let pkt = make_na_with_target_mac(TARGET_ADDR, TEST_MAC);
        let info = parse_icmpv6(&pkt).unwrap();
        assert_eq!(info.icmpv6_type, ICMPV6_NEIGHBOR_ADVERTISEMENT);
        match &info.nd {
            Some(NdInfo::NeighborAdvertisement {
                target_addr,
                target_mac,
            }) => {
                assert_eq!(target_addr, &TARGET_ADDR);
                assert_eq!(*target_mac, Some(TEST_MAC));
            }
            _ => panic!("expected NeighborAdvertisement"),
        }
    }

    #[test]
    fn parse_icmpv6_echo_request() {
        let mut pkt = vec![0u8; 8];
        pkt[0] = ICMPV6_ECHO_REQUEST;
        pkt[1] = 0;
        let info = parse_icmpv6(&pkt).unwrap();
        assert_eq!(info.icmpv6_type, ICMPV6_ECHO_REQUEST);
        assert!(info.nd.is_none());
    }

    #[test]
    fn parse_icmpv6_too_short() {
        let data = [0u8; 3];
        assert_eq!(parse_icmpv6(&data), Err(DropReason::TruncatedL4));
    }

    #[test]
    fn parse_ns_too_short() {
        // NS type but only 20 bytes (need 24)
        let mut pkt = vec![0u8; 20];
        pkt[0] = ICMPV6_NEIGHBOR_SOLICITATION;
        assert_eq!(parse_icmpv6(&pkt), Err(DropReason::TruncatedL4));
    }
}

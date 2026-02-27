//! Packet header rewrite functions for L3 forwarding.
//!
//! These pure functions modify raw packet bytes in place for:
//! - IPv4 TTL decrement with incremental checksum update (RFC 1624)
//! - Ethernet source MAC rewrite
//! - Ethernet destination MAC rewrite
//!
//! RFC-REF: RFC 1624 Section 3
//! "HC' = ~(~HC + ~m + m')"

use crate::nat::checksum::incremental_checksum_update;

/// Rewrite the IPv4 TTL field and update the IP header checksum incrementally.
///
/// Expects a full Ethernet frame (14-byte header + IPv4 payload).
/// Returns `false` if the packet is too short to contain a valid IPv4 header.
///
/// RFC-REF: RFC 791 Section 3.2
/// "The time-to-live is decremented at each point that the internet
/// header is processed."
pub fn rewrite_ipv4_ttl(data: &mut [u8], new_ttl: u8) -> bool {
    // Ethernet header is 14 bytes; IPv4 TTL is at offset 8 within the IP header.
    const ETH_HLEN: usize = 14;
    const IPV4_TTL_OFFSET: usize = ETH_HLEN + 8;
    const IPV4_CHECKSUM_OFFSET: usize = ETH_HLEN + 10;

    if data.len() < ETH_HLEN + 20 {
        return false;
    }

    let old_ttl = data[IPV4_TTL_OFFSET];

    // The TTL occupies the high byte of a 16-bit word at offset 8.
    // The word is [TTL, Protocol].
    let old_word = u16::from_be_bytes([old_ttl, data[IPV4_TTL_OFFSET + 1]]);
    let new_word = u16::from_be_bytes([new_ttl, data[IPV4_TTL_OFFSET + 1]]);

    let old_checksum =
        u16::from_be_bytes([data[IPV4_CHECKSUM_OFFSET], data[IPV4_CHECKSUM_OFFSET + 1]]);
    let new_checksum = incremental_checksum_update(old_checksum, old_word, new_word);

    data[IPV4_TTL_OFFSET] = new_ttl;
    let cksum_bytes = new_checksum.to_be_bytes();
    data[IPV4_CHECKSUM_OFFSET] = cksum_bytes[0];
    data[IPV4_CHECKSUM_OFFSET + 1] = cksum_bytes[1];

    true
}

/// Rewrite the IPv6 Hop Limit field in-place.
///
/// Expects a full Ethernet frame (14-byte header + IPv6 payload).
/// The Hop Limit is at offset 7 within the IPv6 header (no checksum
/// to update -- IPv6 has no header checksum).
///
/// RFC-REF: RFC 8200 Section 3
/// "Hop Limit: Decremented by 1 by each node that forwards the
/// packet."
pub fn rewrite_ipv6_hop_limit(data: &mut [u8], new_hop_limit: u8) -> bool {
    const ETH_HLEN: usize = 14;
    const IPV6_HOP_LIMIT_OFFSET: usize = ETH_HLEN + 7;

    if data.len() < ETH_HLEN + 40 {
        return false;
    }

    data[IPV6_HOP_LIMIT_OFFSET] = new_hop_limit;
    true
}

/// Rewrite the IPv6 Destination Address field in-place.
///
/// Expects a full Ethernet frame (14-byte header + IPv6 payload).
/// The Destination Address occupies bytes 24..40 of the IPv6 header
/// (offsets 38..54 from the start of the Ethernet frame).
/// Returns `false` if the packet is too short.
///
/// RFC-REF: RFC 8986 Section 4.1
/// "Update the DA with SID[SL]" -- this is the rewrite step that
/// makes the SRv6 forwarding decision effective in the wire packet.
pub fn rewrite_ipv6_da(data: &mut [u8], new_da: &[u8; 16]) -> bool {
    const ETH_HLEN: usize = 14;
    // IPv6 DA starts at offset 24 within the IPv6 header.
    const IPV6_DA_OFFSET: usize = ETH_HLEN + 24;

    if data.len() < IPV6_DA_OFFSET + 16 {
        return false;
    }

    data[IPV6_DA_OFFSET..IPV6_DA_OFFSET + 16].copy_from_slice(new_da);
    true
}

/// Rewrite the Ethernet source MAC address (bytes 6..12).
pub fn rewrite_src_mac(data: &mut [u8], mac: &[u8; 6]) {
    if data.len() >= 14 {
        data[6..12].copy_from_slice(mac);
    }
}

/// Rewrite the Ethernet destination MAC address (bytes 0..6).
pub fn rewrite_dst_mac(data: &mut [u8], mac: &[u8; 6]) {
    if data.len() >= 14 {
        data[0..6].copy_from_slice(mac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compute a full IPv4 header checksum from scratch for verification.
    fn compute_ipv4_checksum(hdr: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..hdr.len()).step_by(2) {
            let word = if i + 1 < hdr.len() {
                u16::from_be_bytes([hdr[i], hdr[i + 1]])
            } else {
                u16::from_be_bytes([hdr[i], 0])
            };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build a minimal Ethernet + IPv4 + UDP packet.
    fn make_test_packet(ttl: u8) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst MAC
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 20 + 8;
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // identification
        pkt.extend_from_slice(&[0x40, 0x00]); // flags: DF
        pkt.push(ttl);
        pkt.push(17); // protocol: UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&[192, 168, 1, 100]); // src IP
        pkt.extend_from_slice(&[8, 8, 8, 8]); // dst IP

        // Compute and set IPv4 checksum
        let cksum = compute_ipv4_checksum(&pkt[ipv4_start..ipv4_start + 20]);
        pkt[ipv4_start + 10] = (cksum >> 8) as u8;
        pkt[ipv4_start + 11] = (cksum & 0xFF) as u8;

        // Minimal UDP header (8 bytes)
        pkt.extend_from_slice(&[0x00, 0x50]); // src port: 80
        pkt.extend_from_slice(&[0x00, 0x51]); // dst port: 81
        pkt.extend_from_slice(&[0x00, 0x08]); // length: 8
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum: 0

        pkt
    }

    #[test]
    fn rewrite_ttl_decrements_and_updates_checksum() {
        let mut pkt = make_test_packet(64);

        // Verify the original checksum is valid.
        assert_eq!(compute_ipv4_checksum(&pkt[14..34]), 0);

        // Rewrite TTL from 64 to 63.
        assert!(rewrite_ipv4_ttl(&mut pkt, 63));
        assert_eq!(pkt[14 + 8], 63, "TTL should be 63");

        // Verify the updated checksum is still valid.
        assert_eq!(
            compute_ipv4_checksum(&pkt[14..34]),
            0,
            "checksum must be valid after TTL rewrite"
        );
    }

    #[test]
    fn rewrite_ttl_to_one() {
        let mut pkt = make_test_packet(2);
        assert!(rewrite_ipv4_ttl(&mut pkt, 1));
        assert_eq!(pkt[14 + 8], 1);
        assert_eq!(compute_ipv4_checksum(&pkt[14..34]), 0);
    }

    #[test]
    fn rewrite_ttl_large_change() {
        let mut pkt = make_test_packet(255);
        assert!(rewrite_ipv4_ttl(&mut pkt, 1));
        assert_eq!(pkt[14 + 8], 1);
        assert_eq!(compute_ipv4_checksum(&pkt[14..34]), 0);
    }

    #[test]
    fn rewrite_ttl_too_short_packet() {
        let mut pkt = vec![0u8; 20]; // Too short for Ethernet + IPv4
        assert!(!rewrite_ipv4_ttl(&mut pkt, 63));
    }

    #[test]
    fn rewrite_src_mac_changes_bytes() {
        let mut pkt = make_test_packet(64);
        let new_mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        rewrite_src_mac(&mut pkt, &new_mac);
        assert_eq!(&pkt[6..12], &new_mac);
        // dst MAC should be unchanged.
        assert_eq!(&pkt[0..6], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn rewrite_dst_mac_changes_bytes() {
        let mut pkt = make_test_packet(64);
        let new_mac = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02];
        rewrite_dst_mac(&mut pkt, &new_mac);
        assert_eq!(&pkt[0..6], &new_mac);
        // src MAC should be unchanged.
        assert_eq!(&pkt[6..12], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn rewrite_mac_too_short_packet() {
        let mut pkt = vec![0u8; 10]; // Too short for Ethernet header
                                     // Should not panic.
        rewrite_src_mac(&mut pkt, &[0xFF; 6]);
        rewrite_dst_mac(&mut pkt, &[0xFF; 6]);
    }

    // ── IPv6 Hop Limit rewrite tests ────────────────────────────────

    /// Build a minimal Ethernet + IPv6 + UDP packet.
    fn make_ipv6_test_packet(hop_limit: u8) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst MAC
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src MAC
        pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6

        // IPv6 header (40 bytes)
        pkt.push(0x60); // Version=6, TC=0
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.extend_from_slice(&8u16.to_be_bytes()); // Payload Length: 8 (UDP)
        pkt.push(17); // Next Header: UDP
        pkt.push(hop_limit);
        // src IPv6: 2001:db8::1
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        // dst IPv6: 2001:db8::2
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ]);

        // Minimal UDP header (8 bytes)
        pkt.extend_from_slice(&[0x00, 0x50]); // src port
        pkt.extend_from_slice(&[0x00, 0x51]); // dst port
        pkt.extend_from_slice(&[0x00, 0x08]); // length
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt
    }

    #[test]
    fn rewrite_ipv6_hop_limit_decrements() {
        let mut pkt = make_ipv6_test_packet(64);
        assert!(rewrite_ipv6_hop_limit(&mut pkt, 63));
        assert_eq!(pkt[14 + 7], 63, "Hop Limit should be 63");
    }

    #[test]
    fn rewrite_ipv6_hop_limit_to_one() {
        let mut pkt = make_ipv6_test_packet(2);
        assert!(rewrite_ipv6_hop_limit(&mut pkt, 1));
        assert_eq!(pkt[14 + 7], 1);
    }

    #[test]
    fn rewrite_ipv6_hop_limit_too_short() {
        // Packet too short for Ethernet + IPv6 header
        let mut pkt = vec![0u8; 40];
        assert!(!rewrite_ipv6_hop_limit(&mut pkt, 63));
    }

    // ── IPv6 DA rewrite tests ──────────────────────────────────────

    #[test]
    fn rewrite_ipv6_da_updates_destination() {
        let mut pkt = make_ipv6_test_packet(64);
        // Original DA is at bytes 38..54 (ETH 14 + IPv6 DA offset 24)
        let original_da: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];
        assert_eq!(&pkt[38..54], &original_da);

        let new_da: [u8; 16] = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(rewrite_ipv6_da(&mut pkt, &new_da));
        assert_eq!(&pkt[38..54], &new_da);

        // Verify other header fields are untouched.
        assert_eq!(pkt[14 + 7], 64, "Hop Limit should be unchanged");
    }

    #[test]
    fn rewrite_ipv6_da_too_short() {
        let mut pkt = vec![0u8; 50]; // Too short (need 54 bytes)
        assert!(!rewrite_ipv6_da(&mut pkt, &[0u8; 16]));
    }
}

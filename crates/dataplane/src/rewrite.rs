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
/// "Update the DA with SID\[SL\]" -- this is the rewrite step that
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

// ── NAT packet rewrite ─────────────────────────────────────────────

/// Byte offsets within an Ethernet + IPv4 frame.
const ETH_HLEN: usize = 14;
const IPV4_SRC_OFFSET: usize = ETH_HLEN + 12;
const IPV4_DST_OFFSET: usize = ETH_HLEN + 16;
const IPV4_CHECKSUM_OFFSET: usize = ETH_HLEN + 10;
const IPV4_PROTOCOL_OFFSET: usize = ETH_HLEN + 9;
const IPV4_IHL_OFFSET: usize = ETH_HLEN;

/// Rewrite source IP and source port for SNAT, updating IP + L4 checksums.
///
/// Modifies the packet in place. Returns `true` on success.
///
/// RFC-REF: RFC 3022 Section 4.3
/// "The checksum adjustment must be performed any time the IP header
/// or the TCP/UDP header is modified by the NAT."
pub fn rewrite_snat(data: &mut [u8], new_src_ip: [u8; 4], new_src_port: u16) -> bool {
    if data.len() < ETH_HLEN + 20 {
        return false;
    }

    let old_src_ip = [
        data[IPV4_SRC_OFFSET],
        data[IPV4_SRC_OFFSET + 1],
        data[IPV4_SRC_OFFSET + 2],
        data[IPV4_SRC_OFFSET + 3],
    ];

    // 1. Update IP header checksum for source IP change.
    let old_ip_cksum =
        u16::from_be_bytes([data[IPV4_CHECKSUM_OFFSET], data[IPV4_CHECKSUM_OFFSET + 1]]);
    let new_ip_cksum =
        crate::nat::checksum::nat_ip_checksum_update(old_ip_cksum, old_src_ip, new_src_ip);
    let ck = new_ip_cksum.to_be_bytes();
    data[IPV4_CHECKSUM_OFFSET] = ck[0];
    data[IPV4_CHECKSUM_OFFSET + 1] = ck[1];

    // 2. Write the new source IP.
    data[IPV4_SRC_OFFSET..IPV4_SRC_OFFSET + 4].copy_from_slice(&new_src_ip);

    // 3. Update L4 header (source port + checksum).
    let ihl = ((data[IPV4_IHL_OFFSET] & 0x0F) as usize) * 4;
    let l4_offset = ETH_HLEN + ihl;
    let protocol = data[IPV4_PROTOCOL_OFFSET];

    rewrite_l4_src_port(
        data,
        l4_offset,
        protocol,
        old_src_ip,
        new_src_ip,
        new_src_port,
    )
}

/// Rewrite destination IP and destination port for DNAT, updating IP + L4 checksums.
///
/// Modifies the packet in place. Returns `true` on success.
///
/// RFC-REF: RFC 3022 Section 4.3
pub fn rewrite_dnat(data: &mut [u8], new_dst_ip: [u8; 4], new_dst_port: u16) -> bool {
    if data.len() < ETH_HLEN + 20 {
        return false;
    }

    let old_dst_ip = [
        data[IPV4_DST_OFFSET],
        data[IPV4_DST_OFFSET + 1],
        data[IPV4_DST_OFFSET + 2],
        data[IPV4_DST_OFFSET + 3],
    ];

    // 1. Update IP header checksum for destination IP change.
    let old_ip_cksum =
        u16::from_be_bytes([data[IPV4_CHECKSUM_OFFSET], data[IPV4_CHECKSUM_OFFSET + 1]]);
    let new_ip_cksum =
        crate::nat::checksum::nat_ip_checksum_update(old_ip_cksum, old_dst_ip, new_dst_ip);
    let ck = new_ip_cksum.to_be_bytes();
    data[IPV4_CHECKSUM_OFFSET] = ck[0];
    data[IPV4_CHECKSUM_OFFSET + 1] = ck[1];

    // 2. Write the new destination IP.
    data[IPV4_DST_OFFSET..IPV4_DST_OFFSET + 4].copy_from_slice(&new_dst_ip);

    // 3. Update L4 header (destination port + checksum).
    let ihl = ((data[IPV4_IHL_OFFSET] & 0x0F) as usize) * 4;
    let l4_offset = ETH_HLEN + ihl;
    let protocol = data[IPV4_PROTOCOL_OFFSET];

    rewrite_l4_dst_port(
        data,
        l4_offset,
        protocol,
        old_dst_ip,
        new_dst_ip,
        new_dst_port,
    )
}

/// Rewrite L4 source port and update L4 checksum (TCP or UDP).
///
/// ICMP has no port; we skip port rewrite for ICMP but still update
/// the IP header (already done by the caller).
fn rewrite_l4_src_port(
    data: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    old_ip: [u8; 4],
    new_ip: [u8; 4],
    new_port: u16,
) -> bool {
    match protocol {
        6 => {
            // TCP: src port at offset 0, checksum at offset 16.
            if data.len() < l4_offset + 18 {
                return false;
            }
            let old_port = u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
            let old_cksum = u16::from_be_bytes([data[l4_offset + 16], data[l4_offset + 17]]);
            let new_cksum = crate::nat::checksum::nat_l4_checksum_update(
                old_cksum, old_ip, new_ip, old_port, new_port,
            );
            let port_bytes = new_port.to_be_bytes();
            data[l4_offset] = port_bytes[0];
            data[l4_offset + 1] = port_bytes[1];
            let ck = new_cksum.to_be_bytes();
            data[l4_offset + 16] = ck[0];
            data[l4_offset + 17] = ck[1];
            true
        }
        17 => {
            // UDP: src port at offset 0, checksum at offset 6.
            if data.len() < l4_offset + 8 {
                return false;
            }
            let old_port = u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]);
            let old_cksum = u16::from_be_bytes([data[l4_offset + 6], data[l4_offset + 7]]);
            // RFC-REF: RFC 768
            // "If the computed checksum is zero, it is transmitted as all ones."
            // A UDP checksum of 0 means "not computed". We only update if non-zero.
            if old_cksum != 0 {
                let new_cksum = crate::nat::checksum::nat_l4_checksum_update(
                    old_cksum, old_ip, new_ip, old_port, new_port,
                );
                // A computed result of 0 must be sent as 0xFFFF (RFC 768).
                let final_cksum = if new_cksum == 0 { 0xFFFF } else { new_cksum };
                let ck = final_cksum.to_be_bytes();
                data[l4_offset + 6] = ck[0];
                data[l4_offset + 7] = ck[1];
            }
            let port_bytes = new_port.to_be_bytes();
            data[l4_offset] = port_bytes[0];
            data[l4_offset + 1] = port_bytes[1];
            true
        }
        1 => {
            // ICMP: no port rewrite needed. IP checksum already updated.
            true
        }
        _ => true,
    }
}

/// Rewrite L4 destination port and update L4 checksum (TCP or UDP).
fn rewrite_l4_dst_port(
    data: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    old_ip: [u8; 4],
    new_ip: [u8; 4],
    new_port: u16,
) -> bool {
    match protocol {
        6 => {
            // TCP: dst port at offset 2, checksum at offset 16.
            if data.len() < l4_offset + 18 {
                return false;
            }
            let old_port = u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);
            let old_cksum = u16::from_be_bytes([data[l4_offset + 16], data[l4_offset + 17]]);
            let new_cksum = crate::nat::checksum::nat_l4_checksum_update(
                old_cksum, old_ip, new_ip, old_port, new_port,
            );
            let port_bytes = new_port.to_be_bytes();
            data[l4_offset + 2] = port_bytes[0];
            data[l4_offset + 3] = port_bytes[1];
            let ck = new_cksum.to_be_bytes();
            data[l4_offset + 16] = ck[0];
            data[l4_offset + 17] = ck[1];
            true
        }
        17 => {
            // UDP: dst port at offset 2, checksum at offset 6.
            if data.len() < l4_offset + 8 {
                return false;
            }
            let old_port = u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]);
            let old_cksum = u16::from_be_bytes([data[l4_offset + 6], data[l4_offset + 7]]);
            if old_cksum != 0 {
                let new_cksum = crate::nat::checksum::nat_l4_checksum_update(
                    old_cksum, old_ip, new_ip, old_port, new_port,
                );
                let final_cksum = if new_cksum == 0 { 0xFFFF } else { new_cksum };
                let ck = final_cksum.to_be_bytes();
                data[l4_offset + 6] = ck[0];
                data[l4_offset + 7] = ck[1];
            }
            let port_bytes = new_port.to_be_bytes();
            data[l4_offset + 2] = port_bytes[0];
            data[l4_offset + 3] = port_bytes[1];
            true
        }
        1 => {
            // ICMP: no port rewrite needed.
            true
        }
        _ => true,
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

    // ── NAT rewrite tests ────────────────────────────────────────────

    /// Build a minimal Ethernet + IPv4 + TCP packet for NAT rewrite tests.
    fn make_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        ttl: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst MAC
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 20 + 20; // IP header + TCP header
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // identification
        pkt.extend_from_slice(&[0x40, 0x00]); // flags: DF
        pkt.push(ttl);
        pkt.push(6); // protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // Compute IPv4 checksum
        let cksum = compute_ipv4_checksum(&pkt[ipv4_start..ipv4_start + 20]);
        pkt[ipv4_start + 10] = (cksum >> 8) as u8;
        pkt[ipv4_start + 11] = (cksum & 0xFF) as u8;

        // TCP header (20 bytes minimum)
        pkt.extend_from_slice(&src_port.to_be_bytes()); // src port
        pkt.extend_from_slice(&dst_port.to_be_bytes()); // dst port
        pkt.extend_from_slice(&[0x00, 0x00, 0x03, 0xE8]); // seq: 1000
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack: 0
        pkt.push(0x50); // data offset: 5 (20 bytes)
        pkt.push(0x02); // flags: SYN
        pkt.extend_from_slice(&[0xFF, 0xFF]); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

        pkt
    }

    #[test]
    fn rewrite_snat_updates_src_ip_and_port() {
        let mut pkt = make_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 49152, 80, 64);

        // Verify original IP checksum is valid.
        assert_eq!(compute_ipv4_checksum(&pkt[14..34]), 0);

        assert!(rewrite_snat(&mut pkt, [10, 0, 0, 2], 10000));

        // Verify new source IP.
        assert_eq!(&pkt[26..30], &[10, 0, 0, 2]);
        // Verify new source port (TCP offset 34).
        assert_eq!(u16::from_be_bytes([pkt[34], pkt[35]]), 10000);
        // Verify IP checksum is still valid.
        assert_eq!(
            compute_ipv4_checksum(&pkt[14..34]),
            0,
            "IP checksum must be valid after SNAT"
        );
        // Destination IP should be unchanged.
        assert_eq!(&pkt[30..34], &[8, 8, 8, 8]);
        // Destination port should be unchanged.
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), 80);
    }

    #[test]
    fn rewrite_dnat_updates_dst_ip_and_port() {
        let mut pkt = make_tcp_packet([8, 8, 8, 8], [10, 0, 0, 2], 54321, 8080, 64);

        assert_eq!(compute_ipv4_checksum(&pkt[14..34]), 0);

        assert!(rewrite_dnat(&mut pkt, [192, 168, 1, 50], 80));

        // Verify new destination IP.
        assert_eq!(&pkt[30..34], &[192, 168, 1, 50]);
        // Verify new destination port.
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), 80);
        // Verify IP checksum is still valid.
        assert_eq!(
            compute_ipv4_checksum(&pkt[14..34]),
            0,
            "IP checksum must be valid after DNAT"
        );
        // Source IP should be unchanged.
        assert_eq!(&pkt[26..30], &[8, 8, 8, 8]);
        // Source port should be unchanged.
        assert_eq!(u16::from_be_bytes([pkt[34], pkt[35]]), 54321);
    }

    #[test]
    fn rewrite_snat_udp_packet() {
        let mut pkt = make_test_packet(64);
        // Verify original is valid.
        assert_eq!(compute_ipv4_checksum(&pkt[14..34]), 0);

        assert!(rewrite_snat(&mut pkt, [10, 0, 0, 2], 10000));

        // Verify new source IP.
        assert_eq!(&pkt[26..30], &[10, 0, 0, 2]);
        // Verify new source port (UDP at offset 34).
        assert_eq!(u16::from_be_bytes([pkt[34], pkt[35]]), 10000);
        // Verify IP checksum is still valid.
        assert_eq!(compute_ipv4_checksum(&pkt[14..34]), 0);
    }

    #[test]
    fn rewrite_snat_too_short_packet_fails() {
        let mut pkt = vec![0u8; 20];
        assert!(!rewrite_snat(&mut pkt, [10, 0, 0, 2], 10000));
    }

    #[test]
    fn rewrite_dnat_too_short_packet_fails() {
        let mut pkt = vec![0u8; 20];
        assert!(!rewrite_dnat(&mut pkt, [192, 168, 1, 50], 80));
    }
}

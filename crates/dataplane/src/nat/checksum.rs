//! Incremental checksum update for NAT header rewriting.
//!
//! When NAT modifies IP addresses or port numbers, the IP header
//! checksum and TCP/UDP checksum must be updated. Rather than
//! recomputing from scratch, we use the incremental update algorithm
//! described in RFC 1624.
//!
//! RFC-REF: RFC 1624 Section 3
//! "HC' = ~(~HC + ~m + m')"
//! where HC is the old checksum, m is the old value, and m' is the
//! new value. All arithmetic is ones'-complement (16-bit).

/// Compute an incremental checksum update when a single 16-bit word changes.
///
/// Given the old checksum, the old 16-bit word, and the new 16-bit word,
/// returns the updated checksum.
///
/// RFC-REF: RFC 1624 Section 3
/// "HC' = ~(~HC + ~m + m')"
pub fn incremental_checksum_update(old_checksum: u16, old_word: u16, new_word: u16) -> u16 {
    // Work in u32 to handle carry.
    // HC' = ~(~HC + ~m + m')
    let hc = !old_checksum as u32;
    let m = !old_word as u32;
    let m_prime = new_word as u32;

    let mut sum = hc + m + m_prime;

    // Fold carry bits back into the 16-bit result.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Compute the IP header checksum update when an IPv4 address changes.
///
/// An IPv4 address spans two 16-bit words: `[a, b, c, d]` -> `(a<<8|b)` and `(c<<8|d)`.
/// We apply two sequential incremental updates.
///
/// RFC-REF: RFC 1624 Section 3
pub fn nat_ip_checksum_update(old_checksum: u16, old_ip: [u8; 4], new_ip: [u8; 4]) -> u16 {
    let old_hi = u16::from_be_bytes([old_ip[0], old_ip[1]]);
    let old_lo = u16::from_be_bytes([old_ip[2], old_ip[3]]);
    let new_hi = u16::from_be_bytes([new_ip[0], new_ip[1]]);
    let new_lo = u16::from_be_bytes([new_ip[2], new_ip[3]]);

    let cksum = incremental_checksum_update(old_checksum, old_hi, new_hi);
    incremental_checksum_update(cksum, old_lo, new_lo)
}

/// Compute the TCP/UDP checksum update after NAT translation.
///
/// The TCP/UDP pseudo-header includes the IP addresses, so changing
/// an IP address affects the L4 checksum. Additionally, NAT may
/// change the port number. This function handles both updates.
///
/// RFC-REF: RFC 1624 Section 3
pub fn nat_l4_checksum_update(
    old_checksum: u16,
    old_ip: [u8; 4],
    new_ip: [u8; 4],
    old_port: u16,
    new_port: u16,
) -> u16 {
    // Update for IP address change (two 16-bit words).
    let cksum = nat_ip_checksum_update(old_checksum, old_ip, new_ip);
    // Update for port change (one 16-bit word).
    incremental_checksum_update(cksum, old_port, new_port)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: compute a full ones'-complement checksum from scratch.
    fn full_checksum(words: &[u16]) -> u16 {
        let mut sum: u32 = words.iter().map(|&w| w as u32).sum();
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    // ── incremental_checksum_update ──────────────────────────────────

    #[test]
    fn incremental_update_no_change() {
        // If old_word == new_word, the checksum should not change.
        let cksum = 0x1234;
        let result = incremental_checksum_update(cksum, 0xABCD, 0xABCD);
        assert_eq!(result, cksum);
    }

    #[test]
    fn incremental_update_known_values() {
        // Construct a simple "header" with two 16-bit words and compute checksum.
        let w0: u16 = 0x4500;
        let w1: u16 = 0x0028;
        let original_cksum = full_checksum(&[w0, w1]);

        // Change w1 from 0x0028 to 0x003C.
        let new_w1: u16 = 0x003C;
        let incremental = incremental_checksum_update(original_cksum, w1, new_w1);
        let recomputed = full_checksum(&[w0, new_w1]);

        assert_eq!(incremental, recomputed);
    }

    #[test]
    fn incremental_update_multiple_changes() {
        // Simulate two successive changes and verify against full recompute.
        let words = [0x4500u16, 0x0028, 0xC0A8, 0x0164];
        let original_cksum = full_checksum(&words);

        // Change word[2] from 0xC0A8 to 0x0A00.
        let cksum1 = incremental_checksum_update(original_cksum, 0xC0A8, 0x0A00);
        // Change word[3] from 0x0164 to 0x0002.
        let cksum2 = incremental_checksum_update(cksum1, 0x0164, 0x0002);

        let recomputed = full_checksum(&[0x4500, 0x0028, 0x0A00, 0x0002]);
        assert_eq!(cksum2, recomputed);
    }

    // ── nat_ip_checksum_update ───────────────────────────────────────

    #[test]
    fn ip_checksum_update_src_nat() {
        // Simulate changing source IP from 192.168.1.100 to 10.0.0.2.
        let words = [
            0x4500u16, 0x0028, 0x0001, 0x4000, 0x4006, 0x0000, // checksum placeholder
            0xC0A8, 0x0164, // src: 192.168.1.100
            0x0A00, 0x0001, // dst: 10.0.0.1
        ];
        let original_cksum = full_checksum(&words);

        let old_src = [192, 168, 1, 100];
        let new_src = [10, 0, 0, 2];
        let updated = nat_ip_checksum_update(original_cksum, old_src, new_src);

        // Recompute with the new source IP.
        let new_words = [
            0x4500u16, 0x0028, 0x0001, 0x4000, 0x4006, 0x0000, 0x0A00, 0x0002, // new src
            0x0A00, 0x0001,
        ];
        let recomputed = full_checksum(&new_words);

        assert_eq!(updated, recomputed);
    }

    #[test]
    fn ip_checksum_update_dst_nat() {
        // Simulate changing destination IP from 10.0.0.2 to 192.168.1.50.
        let words = [
            0x4500u16, 0x0028, 0x0001, 0x4000, 0x4006, 0x0000, 0x0800, 0x0808, // src: 8.8.8.8
            0x0A00, 0x0002, // dst: 10.0.0.2
        ];
        let original_cksum = full_checksum(&words);

        let old_dst = [10, 0, 0, 2];
        let new_dst = [192, 168, 1, 50];
        let updated = nat_ip_checksum_update(original_cksum, old_dst, new_dst);

        let new_words = [
            0x4500u16, 0x0028, 0x0001, 0x4000, 0x4006, 0x0000, 0x0800, 0x0808, 0xC0A8,
            0x0132, // new dst: 192.168.1.50
        ];
        let recomputed = full_checksum(&new_words);

        assert_eq!(updated, recomputed);
    }

    // ── nat_l4_checksum_update ───────────────────────────────────────

    #[test]
    fn l4_checksum_update_snat() {
        // Simulate TCP checksum update for SNAT:
        // old src IP: 192.168.1.100, old src port: 49152
        // new src IP: 10.0.0.2, new src port: 10000
        //
        // Build a pseudo-header + TCP header portion for checksum.
        let words = [
            0xC0A8u16, 0x0164, // src: 192.168.1.100
            0x0A00, 0x0001, // dst: 10.0.0.1
            0x0006, 0x0014, // proto=6, tcp_len=20
            0xC000, 0x0050, // src_port=49152, dst_port=80
            0x0000, 0x03E8, // seq
            0x0000, 0x0000, // ack
        ];
        let original_cksum = full_checksum(&words);

        let old_ip = [192, 168, 1, 100];
        let new_ip = [10, 0, 0, 2];
        let old_port = 49152;
        let new_port = 10000;

        let updated = nat_l4_checksum_update(original_cksum, old_ip, new_ip, old_port, new_port);

        let new_words = [
            0x0A00u16, 0x0002, // new src: 10.0.0.2
            0x0A00, 0x0001, 0x0006, 0x0014, 0x2710, // new src_port=10000
            0x0050, 0x0000, 0x03E8, 0x0000, 0x0000,
        ];
        let recomputed = full_checksum(&new_words);

        assert_eq!(updated, recomputed);
    }

    #[test]
    fn l4_checksum_update_no_change() {
        // If IP and port don't change, checksum should remain the same.
        let cksum: u16 = 0x5678;
        let ip = [10, 0, 0, 1];
        let port = 80;

        let result = nat_l4_checksum_update(cksum, ip, ip, port, port);
        assert_eq!(result, cksum);
    }

    #[test]
    fn l4_checksum_update_dnat() {
        // Simulate UDP checksum update for DNAT:
        // old dst IP: 10.0.0.2, old dst port: 8080
        // new dst IP: 192.168.1.50, new dst port: 80
        let words = [
            0x0800u16, 0x0808, // src: 8.8.8.8
            0x0A00, 0x0002, // dst: 10.0.0.2
            0x0011, 0x0008, // proto=17, udp_len=8
            0x3039, 0x1F90, // src_port=12345, dst_port=8080
        ];
        let original_cksum = full_checksum(&words);

        let old_ip = [10, 0, 0, 2];
        let new_ip = [192, 168, 1, 50];
        let old_port = 8080;
        let new_port = 80;

        let updated = nat_l4_checksum_update(original_cksum, old_ip, new_ip, old_port, new_port);

        let new_words = [
            0x0800u16, 0x0808, 0xC0A8, 0x0132, // new dst: 192.168.1.50
            0x0011, 0x0008, 0x3039, 0x0050, // new dst_port=80
        ];
        let recomputed = full_checksum(&new_words);

        assert_eq!(updated, recomputed);
    }
}

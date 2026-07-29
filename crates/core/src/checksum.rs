/// Computes the Internet checksum over an arbitrary byte slice.
///
/// This is the checksum algorithm shared by IPv4 and ICMP. An odd final byte
/// is treated as the high byte of a zero-padded 16-bit word.
#[must_use]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut chunks = bytes.chunks_exact(2);
    let mut sum = chunks.by_ref().fold(0_u32, |sum, word| {
        sum + u32::from(u16::from_be_bytes([word[0], word[1]]))
    });
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(last) << 8;
    }
    fold(sum)
}

/// Computes the Internet checksum over an IPv4 header.
///
/// The checksum field must be zero when creating a header. A complete valid
/// header, including its checksum, produces zero.
#[must_use]
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

/// Updates an Internet checksum after replacing one 16-bit word (RFC 1624 §4).
#[must_use]
pub fn rfc1624_update(checksum: u16, old_word: u16, new_word: u16) -> u16 {
    let sum = u32::from(!checksum) + u32::from(!old_word) + u32::from(new_word);
    !fold_sum(sum)
}

fn fold(sum: u32) -> u16 {
    !fold_sum(sum)
}

fn fold_sum(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_1624_negative_zero_boundary_is_positive_zero() {
        assert_eq!(rfc1624_update(0xdd2f, 0x5555, 0x3285), 0x0000);
    }

    #[test]
    fn checksum_accepts_an_odd_slice_without_panicking() {
        assert_eq!(ipv4_header_checksum(&[0x01, 0x02, 0x03]), 0xfbfd);
    }
}

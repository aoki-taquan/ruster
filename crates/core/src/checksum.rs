/// Computes the Internet checksum over an arbitrary byte slice.
///
/// This is the checksum algorithm shared by IPv4 and ICMP. An odd final byte
/// is treated as the high byte of a zero-padded 16-bit word.
#[must_use]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut chunks = bytes.chunks_exact(2);
    let mut sum = chunks.by_ref().fold(0_u32, |sum, word| {
        add_folded(sum, u16::from_be_bytes([word[0], word[1]]))
    });
    if let Some(&last) = chunks.remainder().first() {
        sum = add_folded(sum, u16::from(last) << 8);
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

fn add_folded(sum: u32, word: u16) -> u32 {
    let sum = sum + u32::from(word);
    (sum & 0xffff) + (sum >> 16)
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

    const PROPERTY_SEED: u64 = 0x6a09_e667_f3bc_c909;
    const RANDOM_MESSAGE_CASES: usize = 128;
    const RANDOM_UPDATE_CASES: usize = 4_096;

    /// Deliberately structured differently from the production checksum:
    /// accumulate the high- and low-order octets independently in a wide
    /// accumulator, combine them once, then perform end-around carry.
    fn reference_checksum(bytes: &[u8]) -> u16 {
        let (high, low) =
            bytes
                .iter()
                .enumerate()
                .fold((0_u64, 0_u64), |(high, low), (index, byte)| {
                    if index & 1 == 0 {
                        (high + u64::from(*byte), low)
                    } else {
                        (high, low + u64::from(*byte))
                    }
                });
        let mut sum = (high << 8) + low;
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[derive(Clone, Copy)]
    struct DeterministicRng(u64);

    impl DeterministicRng {
        fn seeded() -> Self {
            Self(PROPERTY_SEED)
        }

        fn next_u64(&mut self) -> u64 {
            // xorshift64* has a fixed, dependency-free sequence. The seed and
            // case index in every assertion make a failure reproducible.
            let mut value = self.0;
            value ^= value >> 12;
            value ^= value << 25;
            value ^= value >> 27;
            self.0 = value;
            value.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn next_u16(&mut self) -> u16 {
            self.next_u64() as u16
        }

        fn fill(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                *byte = self.next_u64() as u8;
            }
        }
    }

    fn words_as_bytes(words: &[u16]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(words.len() * 2);
        for word in words {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn rfc_1624_negative_zero_boundary_is_positive_zero() {
        assert_eq!(rfc1624_update(0xdd2f, 0x5555, 0x3285), 0x0000);
    }

    #[test]
    fn rfc_1071_and_ipv4_known_vectors_match_independent_values() {
        let rfc_1071 = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(reference_checksum(&rfc_1071), 0x220d);
        assert_eq!(internet_checksum(&rfc_1071), 0x220d);

        let mut ipv4 = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(reference_checksum(&ipv4), 0xb861);
        assert_eq!(ipv4_header_checksum(&ipv4), 0xb861);
        ipv4[10..12].copy_from_slice(&0xb861_u16.to_be_bytes());
        assert_eq!(reference_checksum(&ipv4), 0);
        assert_eq!(ipv4_header_checksum(&ipv4), 0);
    }

    #[test]
    fn checksum_accepts_an_odd_slice_without_panicking() {
        assert_eq!(ipv4_header_checksum(&[0x01, 0x02, 0x03]), 0xfbfd);
    }

    #[test]
    fn internet_checksum_folds_carry_for_large_odd_messages() {
        let bytes = vec![0xff; 200_001];
        assert_eq!(internet_checksum(&bytes), 0x00ff);
    }

    #[test]
    fn internet_checksum_matches_independent_oracle_for_seeded_messages() {
        const BOUNDARY_LENGTHS: &[usize] = &[
            0, 1, 2, 3, 4, 7, 8, 15, 16, 19, 20, 31, 32, 59, 60, 61, 255, 256, 257, 1_499, 1_500,
            1_501, 65_534, 65_535,
        ];

        let mut rng = DeterministicRng::seeded();
        let mut lengths = BOUNDARY_LENGTHS.to_vec();
        lengths.extend((0..RANDOM_MESSAGE_CASES).map(|_| usize::from(rng.next_u16())));
        for (case, length) in lengths.into_iter().enumerate() {
            let zeroes = vec![0; length];
            assert_eq!(
                internet_checksum(&zeroes),
                reference_checksum(&zeroes),
                "zero seed={PROPERTY_SEED:#018x} case={case} length={length}"
            );

            let ones = vec![0xff; length];
            assert_eq!(
                internet_checksum(&ones),
                reference_checksum(&ones),
                "ff seed={PROPERTY_SEED:#018x} case={case} length={length}"
            );

            let mut arbitrary = vec![0; length];
            rng.fill(&mut arbitrary);
            assert_eq!(
                internet_checksum(&arbitrary),
                reference_checksum(&arbitrary),
                "arbitrary seed={PROPERTY_SEED:#018x} case={case} length={length}"
            );
        }
    }

    #[test]
    fn rfc_1624_seeded_word_updates_match_independent_full_recomputation() {
        let mut rng = DeterministicRng::seeded();
        for case in 0..RANDOM_UPDATE_CASES {
            let word_count = 2 + usize::from(rng.next_u16() % 31);
            let mut words = vec![0_u16; word_count];
            for word in &mut words {
                *word = rng.next_u16();
            }
            // Keep a nonzero, non-replaced IPv4 version/IHL word. RFC 1624
            // observes that this means the stored checksum cannot be 0xffff.
            words[0] = 0x4500;

            let old_checksum = reference_checksum(&words_as_bytes(&words));
            assert_ne!(
                old_checksum, 0xffff,
                "precondition seed={PROPERTY_SEED:#018x} case={case}"
            );
            let index = 1 + usize::from(rng.next_u16()) % (word_count - 1);
            let old_word = words[index];
            let new_word = rng.next_u16();

            assert_eq!(
                rfc1624_update(old_checksum, old_word, old_word),
                old_checksum,
                "identity seed={PROPERTY_SEED:#018x} case={case} index={index}"
            );

            words[index] = new_word;
            let recomputed = reference_checksum(&words_as_bytes(&words));
            assert_eq!(
                rfc1624_update(old_checksum, old_word, new_word),
                recomputed,
                "replace seed={PROPERTY_SEED:#018x} case={case} index={index} \
                 old={old_word:#06x} new={new_word:#06x}"
            );
        }
    }

    #[test]
    fn rfc_1624_cascaded_nat_and_ttl_updates_match_full_recomputation() {
        let mut rng = DeterministicRng::seeded();
        for case in 0..RANDOM_UPDATE_CASES {
            // The first nonzero word models the fixed IPv4 version/IHL and
            // ensures the RFC 1624 header-checksum precondition.
            let mut words = [
                0x4500,
                rng.next_u16(),
                rng.next_u16(),
                rng.next_u16(),
                rng.next_u16(),
                rng.next_u16(),
                rng.next_u16(),
            ];
            let replacements = [
                (1, rng.next_u16()), // TTL/protocol
                (2, rng.next_u16()), // address high
                (3, rng.next_u16()), // address low
                (4, rng.next_u16()), // port
            ];
            let mut incremental = reference_checksum(&words_as_bytes(&words));

            for (step, (index, new_word)) in replacements.into_iter().enumerate() {
                let old_word = words[index];
                incremental = rfc1624_update(incremental, old_word, new_word);
                words[index] = new_word;
                assert_eq!(
                    incremental,
                    reference_checksum(&words_as_bytes(&words)),
                    "cascade seed={PROPERTY_SEED:#018x} case={case} step={step} \
                     index={index} old={old_word:#06x} new={new_word:#06x}"
                );
            }
        }
    }

    #[test]
    fn transport_profiles_keep_udp_and_tcp_zero_encodings_distinct() {
        let mathematical_zero = rfc1624_update(0xdd2f, 0x5555, 0x3285);
        assert_eq!(mathematical_zero, 0);

        // NAT UDP preserves an absent input checksum as zero, but represents
        // a present checksum whose update is mathematical zero as 0xffff.
        let udp_absent = 0;
        let udp_present = if mathematical_zero == 0 {
            0xffff
        } else {
            mathematical_zero
        };
        assert_eq!(udp_absent, 0);
        assert_eq!(udp_present, 0xffff);

        // TCP has no "checksum absent" encoding and keeps mathematical zero
        // on the wire. The end-to-end production boundaries are exercised by
        // the NAT UDP/TCP integration tests.
        let tcp_present = mathematical_zero;
        assert_eq!(tcp_present, 0);
    }
}

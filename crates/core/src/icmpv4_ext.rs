//! RFC 4884 extension structure parsing for ICMPv4 error messages.
//!
//! Destination Unreachable (type 3), Time Exceeded (type 11) and Parameter
//! Problem (type 12) messages carry, immediately after the fixed 8-octet
//! ICMP header, an "original datagram" field. RFC 4884 lets that field be
//! followed by an ICMP Extension Structure — a 4-octet header (a version
//! nibble, a reserved nibble, and a checksum) then a sequence of extension
//! objects — and gives the ICMP header a "Length" octet that declares how
//! far the padded original-datagram field extends before the structure
//! begins.
//!
//! That Length octet is byte 5 of the ICMP message. `icmpv4_error.rs`
//! already writes a Parameter Problem pointer (or leaves the byte unused) at
//! byte 4 and an RFC 1191 next-hop MTU at bytes 6-7 of the same four-octet
//! field RFC 792 otherwise leaves alone, so byte 5 is the one octet of that
//! field neither of those two uses — which is where this module reads and,
//! were this router ever to originate a multi-part message, would write the
//! Length RFC 4884 defines.
//!
//! RFC 4884 §5.2 requires a message that looks multi-part (a non-zero
//! Length octet) but fails validation to be handled exactly like an
//! ordinary single-part message, so [`classify_icmpv4_multipart`] never
//! reports something a caller could mistake for a reason to drop the
//! packet: a bad structure is [`Icmpv4MultipartOutcome::LegacyFallback`],
//! not a rejection of the whole message.

use crate::internet_checksum;

/// RFC 4884 §4: the extension header's version nibble.
const ICMPV4_EXTENSION_VERSION: u8 = 2;

/// RFC 4884 §5.1: whenever an extension structure follows it, the original
/// datagram field must be zero-padded to at least this many octets.
const ICMPV4_MIN_ORIGINAL_DATAGRAM_LEN: usize = 128;

/// Octet offset, from the start of the ICMP message, of the fixed header
/// that precedes the original datagram field.
const ICMPV4_HEADER_LEN: usize = 8;

/// Octet offset, from the start of the ICMP message, of the RFC 4884
/// "Length" octet — see the module documentation for why this is the byte.
const ICMPV4_LENGTH_OCTET: usize = 5;

/// RFC 4884 §4: the length, in octets, of an extension object's header
/// (its Length, Class-Num and C-Type fields), before its payload.
const ICMPV4_EXTENSION_OBJECT_HEADER_LEN: usize = 4;

/// Why a message that looked RFC 4884 multi-part failed validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Icmpv4ExtensionRefusalReason {
    /// RFC 4884 §5.1: the declared original-datagram length is shorter than
    /// the 128 octets every multi-part message must reserve for it.
    OriginalDatagramTooShort,
    /// RFC 4884 §4: the Length octet declares a structure that runs past
    /// the end of the ICMP message, or leaves no room for its own header.
    StructureTruncated,
    /// RFC 4884 §4: the extension header's version nibble is not 2.
    VersionUnsupported,
    /// RFC 4884 §4: the extension header and objects fail the Internet
    /// checksum the header carries.
    ChecksumInvalid,
    /// RFC 4884 §4: an extension object's Length field is too short to
    /// cover even its own object header.
    ObjectLengthTooShort,
    /// RFC 4884 §4: an extension object's Length field runs past the end of
    /// the extension structure.
    ObjectLengthExceedsRemaining,
}

/// A malformed RFC 4884 extension structure, and the offset that condemned
/// it.
///
/// Mirrors `Ipv4OptionRefusal`'s shape in `forwarding.rs`: a typed reason
/// plus a pointer. This pointer counts from the start of the ICMP message
/// (its Type octet) rather than from an IPv4 header. RFC 4884 §5.2 means
/// this is never itself a reason to drop a packet — see the module
/// documentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Icmpv4ExtensionRefusal {
    pub(crate) reason: Icmpv4ExtensionRefusalReason,
    pub(crate) pointer: u8,
}

/// A validated RFC 4884 extension structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Icmpv4ExtensionStructure {
    /// Octet offset of the extension structure's own header, counted from
    /// the start of the ICMP message.
    pub(crate) extension_offset: usize,
    /// Length of the extension structure — its header and every object —
    /// in octets.
    pub(crate) extension_len: usize,
    /// Length the original datagram field is padded to (RFC 4884 §5.1), in
    /// octets: the Length octet's value times four.
    pub(crate) padded_original_datagram_len: usize,
}

/// Whether an ICMPv4 message is RFC 4884 multi-part.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Icmpv4MultipartOutcome {
    /// The Length octet is zero, or absent because the message is too
    /// short to carry one: an ordinary, single-part message.
    SinglePart,
    /// The Length octet is non-zero and the extension structure it
    /// introduces validates completely.
    Multipart(Icmpv4ExtensionStructure),
    /// The Length octet is non-zero but the structure it introduces does
    /// not validate. RFC 4884 §5.2 requires this to be handled exactly like
    /// [`Icmpv4MultipartOutcome::SinglePart`]; the refusal is kept only so a
    /// caller can trace why.
    LegacyFallback(Icmpv4ExtensionRefusal),
}

/// Classifies `icmp`, a complete ICMPv4 message starting at its Type octet,
/// per RFC 4884 §5.2.
pub(crate) fn classify_icmpv4_multipart(icmp: &[u8]) -> Icmpv4MultipartOutcome {
    let Some(&length_words) = icmp.get(ICMPV4_LENGTH_OCTET) else {
        return Icmpv4MultipartOutcome::SinglePart;
    };
    if length_words == 0 {
        return Icmpv4MultipartOutcome::SinglePart;
    }
    match parse_icmpv4_extension(icmp, length_words) {
        Ok(structure) => Icmpv4MultipartOutcome::Multipart(structure),
        Err(refusal) => Icmpv4MultipartOutcome::LegacyFallback(refusal),
    }
}

/// Parses and validates the RFC 4884 extension structure that `icmp`'s
/// non-zero Length octet, `length_words`, declares.
fn parse_icmpv4_extension(
    icmp: &[u8],
    length_words: u8,
) -> Result<Icmpv4ExtensionStructure, Icmpv4ExtensionRefusal> {
    let refuse = |reason, offset: usize| Icmpv4ExtensionRefusal {
        reason,
        pointer: u8::try_from(offset).unwrap_or(u8::MAX),
    };

    let padded_original_datagram_len = usize::from(length_words) * 4;
    if padded_original_datagram_len < ICMPV4_MIN_ORIGINAL_DATAGRAM_LEN {
        return Err(refuse(
            Icmpv4ExtensionRefusalReason::OriginalDatagramTooShort,
            ICMPV4_LENGTH_OCTET,
        ));
    }

    let extension_offset = ICMPV4_HEADER_LEN + padded_original_datagram_len;
    let extension_bytes = icmp
        .get(extension_offset..)
        .filter(|bytes| bytes.len() >= ICMPV4_EXTENSION_OBJECT_HEADER_LEN)
        .ok_or_else(|| {
            refuse(
                Icmpv4ExtensionRefusalReason::StructureTruncated,
                extension_offset,
            )
        })?;

    let version = extension_bytes[0] >> 4;
    if version != ICMPV4_EXTENSION_VERSION {
        return Err(refuse(
            Icmpv4ExtensionRefusalReason::VersionUnsupported,
            extension_offset,
        ));
    }
    if internet_checksum(extension_bytes) != 0 {
        return Err(refuse(
            Icmpv4ExtensionRefusalReason::ChecksumInvalid,
            extension_offset + 2,
        ));
    }

    // Walk the object area exactly like `validate_ipv4_options` walks an
    // IPv4 option area: each object names its own length, which must cover
    // at least its own header and must not run past the structure.
    let mut offset = ICMPV4_EXTENSION_OBJECT_HEADER_LEN;
    while offset < extension_bytes.len() {
        let Some(length_field) = extension_bytes.get(offset..offset + 2) else {
            return Err(refuse(
                Icmpv4ExtensionRefusalReason::ObjectLengthExceedsRemaining,
                extension_offset + offset,
            ));
        };
        let object_len = usize::from(u16::from_be_bytes([length_field[0], length_field[1]]));
        if object_len < ICMPV4_EXTENSION_OBJECT_HEADER_LEN {
            return Err(refuse(
                Icmpv4ExtensionRefusalReason::ObjectLengthTooShort,
                extension_offset + offset,
            ));
        }
        let next = offset + object_len;
        if next > extension_bytes.len() {
            return Err(refuse(
                Icmpv4ExtensionRefusalReason::ObjectLengthExceedsRemaining,
                extension_offset + offset,
            ));
        }
        offset = next;
    }

    Ok(Icmpv4ExtensionStructure {
        extension_offset,
        extension_len: extension_bytes.len(),
        padded_original_datagram_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an ICMP message of `icmp_len` octets whose Length octet is
    /// `length_words` and whose original-datagram field is real (non-zero)
    /// for its first `real_datagram_len` octets and zero-padded after that.
    fn icmp_with_length_octet(
        icmp_len: usize,
        length_words: u8,
        real_datagram_len: usize,
    ) -> Vec<u8> {
        let mut icmp = vec![0_u8; icmp_len];
        icmp[ICMPV4_LENGTH_OCTET] = length_words;
        for (index, byte) in icmp
            .get_mut(ICMPV4_HEADER_LEN..ICMPV4_HEADER_LEN + real_datagram_len)
            .unwrap_or(&mut [])
            .iter_mut()
            .enumerate()
        {
            *byte = index as u8 ^ 0xa5;
        }
        icmp
    }

    /// Appends a valid extension structure header plus one object of
    /// `payload_len` octets to `icmp`, fixing up its checksum, and returns
    /// the finished message together with the object's declared length.
    fn append_valid_extension(mut icmp: Vec<u8>, payload_len: usize) -> Vec<u8> {
        let object_len = ICMPV4_EXTENSION_OBJECT_HEADER_LEN + payload_len;
        icmp.push(ICMPV4_EXTENSION_VERSION << 4);
        icmp.push(0); // reserved
        icmp.extend_from_slice(&[0, 0]); // checksum placeholder
        icmp.extend_from_slice(&(object_len as u16).to_be_bytes());
        icmp.push(1); // class-num
        icmp.push(1); // c-type
        icmp.extend(std::iter::repeat_n(0x5a, payload_len));
        let extension_offset = icmp.len() - (ICMPV4_EXTENSION_OBJECT_HEADER_LEN + object_len);
        let checksum = internet_checksum(&icmp[extension_offset..]);
        icmp[extension_offset + 2..extension_offset + 4].copy_from_slice(&checksum.to_be_bytes());
        icmp
    }

    #[test]
    fn zero_length_octet_is_single_part() {
        let icmp = icmp_with_length_octet(64, 0, 40);
        assert_eq!(
            classify_icmpv4_multipart(&icmp),
            Icmpv4MultipartOutcome::SinglePart
        );
    }

    #[test]
    fn a_message_too_short_to_carry_a_length_octet_is_single_part() {
        assert_eq!(
            classify_icmpv4_multipart(&[0, 0, 0, 0]),
            Icmpv4MultipartOutcome::SinglePart
        );
    }

    #[test]
    fn a_valid_extension_structure_is_recognised_with_padding_applied_correctly() {
        let icmp = icmp_with_length_octet(8 + 128, 32, 40);
        let icmp = append_valid_extension(icmp, 4);
        match classify_icmpv4_multipart(&icmp) {
            Icmpv4MultipartOutcome::Multipart(structure) => {
                assert_eq!(structure.padded_original_datagram_len, 128);
                // The extension begins after the *declared* 128-octet
                // padded field, not after the 40 real octets this message
                // actually quotes: padding, not the real datagram length,
                // decides the boundary.
                assert_eq!(structure.extension_offset, 8 + 128);
                assert_eq!(structure.extension_len, 12);
                assert_eq!(
                    icmp.len(),
                    structure.extension_offset + structure.extension_len
                );
            }
            other => panic!("expected a recognised multipart structure, got {other:?}"),
        }
    }

    #[test]
    fn an_original_datagram_declared_under_128_octets_falls_back_to_legacy() {
        // 127 octets is the largest length the Length octet, in 32-bit
        // words, can declare without reaching 128.
        let icmp = icmp_with_length_octet(8 + 124, 31, 40);
        let icmp = append_valid_extension(icmp, 4);
        assert!(matches!(
            classify_icmpv4_multipart(&icmp),
            Icmpv4MultipartOutcome::LegacyFallback(Icmpv4ExtensionRefusal {
                reason: Icmpv4ExtensionRefusalReason::OriginalDatagramTooShort,
                ..
            })
        ));
    }

    #[test]
    fn a_wrong_extension_header_version_falls_back_to_legacy() {
        let icmp = icmp_with_length_octet(8 + 128, 32, 40);
        let mut icmp = append_valid_extension(icmp, 4);
        let extension_offset = 8 + 128;
        icmp[extension_offset] = 1 << 4;
        // The checksum must still be valid so the version check, not the
        // checksum check, is what is under test.
        icmp[extension_offset + 2..extension_offset + 4].fill(0);
        let checksum = internet_checksum(&icmp[extension_offset..]);
        icmp[extension_offset + 2..extension_offset + 4].copy_from_slice(&checksum.to_be_bytes());
        assert!(matches!(
            classify_icmpv4_multipart(&icmp),
            Icmpv4MultipartOutcome::LegacyFallback(Icmpv4ExtensionRefusal {
                reason: Icmpv4ExtensionRefusalReason::VersionUnsupported,
                ..
            })
        ));
    }

    #[test]
    fn a_bad_extension_checksum_falls_back_to_legacy() {
        let icmp = icmp_with_length_octet(8 + 128, 32, 40);
        let mut icmp = append_valid_extension(icmp, 4);
        let last = icmp.len() - 1;
        icmp[last] ^= 0xff;
        assert!(matches!(
            classify_icmpv4_multipart(&icmp),
            Icmpv4MultipartOutcome::LegacyFallback(Icmpv4ExtensionRefusal {
                reason: Icmpv4ExtensionRefusalReason::ChecksumInvalid,
                ..
            })
        ));
    }

    #[test]
    fn a_structure_the_length_octet_places_past_the_message_end_falls_back_to_legacy() {
        // The Length octet claims a 128-octet padded field, but the message
        // is only long enough for 64.
        let icmp = icmp_with_length_octet(8 + 64, 32, 40);
        assert!(matches!(
            classify_icmpv4_multipart(&icmp),
            Icmpv4MultipartOutcome::LegacyFallback(Icmpv4ExtensionRefusal {
                reason: Icmpv4ExtensionRefusalReason::StructureTruncated,
                ..
            })
        ));
    }

    #[test]
    fn an_object_length_of_zero_is_refused() {
        let mut icmp = icmp_with_length_octet(8 + 128, 32, 40);
        icmp.extend_from_slice(&[ICMPV4_EXTENSION_VERSION << 4, 0, 0, 0]);
        icmp.extend_from_slice(&[0, 0, 1, 1]); // object length 0
        let extension_offset = 8 + 128;
        let checksum = internet_checksum(&icmp[extension_offset..]);
        icmp[extension_offset + 2..extension_offset + 4].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            parse_icmpv4_extension(&icmp, 32),
            Err(Icmpv4ExtensionRefusal {
                reason: Icmpv4ExtensionRefusalReason::ObjectLengthTooShort,
                pointer: u8::try_from(extension_offset + ICMPV4_EXTENSION_OBJECT_HEADER_LEN)
                    .unwrap(),
            })
        );
    }

    #[test]
    fn an_object_length_overrunning_the_buffer_is_refused() {
        let mut icmp = icmp_with_length_octet(8 + 128, 32, 40);
        icmp.extend_from_slice(&[ICMPV4_EXTENSION_VERSION << 4, 0, 0, 0]);
        // Declares an object 255 octets long in a structure twelve octets
        // long: no valid checksum can cover this, so the checksum is left
        // unfixed to isolate the object-length guard from the checksum one.
        icmp.extend_from_slice(&[0, 255, 1, 1]);
        icmp.extend_from_slice(&[0, 0, 0, 0]);
        let extension_offset = 8 + 128;
        let checksum = internet_checksum(&icmp[extension_offset..]);
        icmp[extension_offset + 2..extension_offset + 4].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            parse_icmpv4_extension(&icmp, 32),
            Err(Icmpv4ExtensionRefusal {
                reason: Icmpv4ExtensionRefusalReason::ObjectLengthExceedsRemaining,
                pointer: u8::try_from(extension_offset + ICMPV4_EXTENSION_OBJECT_HEADER_LEN)
                    .unwrap(),
            })
        );
    }
}

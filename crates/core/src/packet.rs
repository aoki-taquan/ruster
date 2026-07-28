use crate::DropReason;

pub const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_ETHERTYPE: u16 = 0x0800;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacAddress(pub [u8; 6]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedIpv4 {
    pub header_offset: usize,
    pub header_len: usize,
    pub total_len: usize,
    pub ttl: u8,
    pub protocol: u8,
    pub source: crate::Ipv4Address,
    pub destination: crate::Ipv4Address,
    pub checksum: u16,
}

/// Validates Ethernet II and the entire IPv4 header without mutating the frame.
///
/// Bytes after IPv4 Total Length are link-layer padding and are deliberately
/// ignored. IPv4 options are covered by length and checksum validation but
/// their option-specific meaning is outside the v0.2 bootstrap scope.
pub fn validate_ipv4_frame(frame: &[u8]) -> Result<ValidatedIpv4, DropReason> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(DropReason::EthernetHeaderTruncated);
    }
    let ether_type = read_u16(frame, 12).ok_or(DropReason::EthernetHeaderTruncated)?;
    if ether_type != IPV4_ETHERTYPE {
        return Err(DropReason::UnsupportedEtherType);
    }

    let available = frame
        .len()
        .checked_sub(ETHERNET_HEADER_LEN)
        .ok_or(DropReason::Ipv4HeaderTruncated)?;
    if available < IPV4_MIN_HEADER_LEN {
        return Err(DropReason::Ipv4HeaderTruncated);
    }
    let first = *frame
        .get(ETHERNET_HEADER_LEN)
        .ok_or(DropReason::Ipv4HeaderTruncated)?;
    if first >> 4 != 4 {
        return Err(DropReason::Ipv4VersionUnsupported);
    }
    let ihl_words = usize::from(first & 0x0f);
    if ihl_words < 5 {
        return Err(DropReason::Ipv4IhlTooSmall);
    }
    let header_len = ihl_words
        .checked_mul(4)
        .ok_or(DropReason::Ipv4HeaderLengthExceedsPacket)?;
    if header_len > available {
        return Err(DropReason::Ipv4HeaderLengthExceedsPacket);
    }

    let total_len = usize::from(
        read_u16(frame, ETHERNET_HEADER_LEN + 2).ok_or(DropReason::Ipv4HeaderTruncated)?,
    );
    if total_len < header_len {
        return Err(DropReason::Ipv4TotalLengthTooSmall);
    }
    if total_len > available {
        return Err(DropReason::Ipv4TotalLengthExceedsPacket);
    }
    let header_end = ETHERNET_HEADER_LEN
        .checked_add(header_len)
        .ok_or(DropReason::Ipv4HeaderLengthExceedsPacket)?;
    let header = frame
        .get(ETHERNET_HEADER_LEN..header_end)
        .ok_or(DropReason::Ipv4HeaderLengthExceedsPacket)?;
    if crate::ipv4_header_checksum(header) != 0 {
        return Err(DropReason::Ipv4HeaderChecksumInvalid);
    }

    Ok(ValidatedIpv4 {
        header_offset: ETHERNET_HEADER_LEN,
        header_len,
        total_len,
        ttl: frame[ETHERNET_HEADER_LEN + 8],
        protocol: frame[ETHERNET_HEADER_LEN + 9],
        source: crate::Ipv4Address::from_octets([
            frame[ETHERNET_HEADER_LEN + 12],
            frame[ETHERNET_HEADER_LEN + 13],
            frame[ETHERNET_HEADER_LEN + 14],
            frame[ETHERNET_HEADER_LEN + 15],
        ]),
        destination: crate::Ipv4Address::from_octets([
            frame[ETHERNET_HEADER_LEN + 16],
            frame[ETHERNET_HEADER_LEN + 17],
            frame[ETHERNET_HEADER_LEN + 18],
            frame[ETHERNET_HEADER_LEN + 19],
        ]),
        checksum: read_u16(frame, ETHERNET_HEADER_LEN + 10)
            .ok_or(DropReason::Ipv4HeaderTruncated)?,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let word = bytes.get(offset..end)?;
    Some(u16::from_be_bytes([word[0], word[1]]))
}

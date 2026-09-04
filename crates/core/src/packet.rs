use crate::DropReason;

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const ARP_PACKET_LEN: usize = 28;
pub const ARP_FRAME_LEN: usize = ETHERNET_HEADER_LEN + ARP_PACKET_LEN;
const IPV4_MIN_HEADER_LEN: usize = 20;
pub const IPV4_ETHERTYPE: u16 = 0x0800;
pub const ARP_ETHERTYPE: u16 = 0x0806;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpOpcode {
    Request,
    Reply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedArp {
    pub opcode: ArpOpcode,
    pub sender_hardware: MacAddress,
    pub sender_protocol: crate::Ipv4Address,
    pub target_protocol: crate::Ipv4Address,
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

/// Validates the common Ethernet/IPv4 ARP Request/Reply profile.
///
/// The target hardware address is intentionally ignored as required by
/// RFC 826 request processing. Ethernet source and ARP sender hardware are
/// also not required to match. No bytes are mutated by this function.
pub fn validate_arp(frame: &[u8]) -> Result<ValidatedArp, DropReason> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(DropReason::EthernetHeaderTruncated);
    }
    if read_u16(frame, 12) != Some(ARP_ETHERTYPE) {
        return Err(DropReason::UnsupportedEtherType);
    }
    if frame.len() < ARP_FRAME_LEN {
        return Err(DropReason::ArpPacketTruncated);
    }

    if read_u16(frame, 14) != Some(1) {
        return Err(DropReason::ArpHardwareTypeUnsupported);
    }
    if read_u16(frame, 16) != Some(IPV4_ETHERTYPE) {
        return Err(DropReason::ArpProtocolTypeUnsupported);
    }
    if frame[18] != 6 {
        return Err(DropReason::ArpHardwareLengthUnsupported);
    }
    if frame[19] != 4 {
        return Err(DropReason::ArpProtocolLengthUnsupported);
    }
    let opcode = match read_u16(frame, 20) {
        Some(1) => ArpOpcode::Request,
        Some(2) => ArpOpcode::Reply,
        Some(_) => return Err(DropReason::ArpOpcodeUnsupported),
        None => return Err(DropReason::ArpPacketTruncated),
    };

    Ok(ValidatedArp {
        opcode,
        sender_hardware: MacAddress([
            frame[22], frame[23], frame[24], frame[25], frame[26], frame[27],
        ]),
        sender_protocol: crate::Ipv4Address::from_octets([
            frame[28], frame[29], frame[30], frame[31],
        ]),
        target_protocol: crate::Ipv4Address::from_octets([
            frame[38], frame[39], frame[40], frame[41],
        ]),
    })
}

/// Compatibility validator for callers that require a Request.
pub fn validate_arp_request(frame: &[u8]) -> Result<ValidatedArp, DropReason> {
    let arp = validate_arp(frame)?;
    if arp.opcode == ArpOpcode::Reply {
        return Err(DropReason::ArpReplyUnsupported);
    }
    Ok(arp)
}

pub type ValidatedArpRequest = ValidatedArp;

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let word = bytes.get(offset..end)?;
    Some(u16::from_be_bytes([word[0], word[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DropReason;

    fn ipv4_frame_at_ethernet_minimum() -> Vec<u8> {
        let mut frame = vec![0; ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN];
        frame[12..14].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&(IPV4_MIN_HEADER_LEN as u16).to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        let checksum = crate::ipv4_header_checksum(&frame[14..]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn arp_frame() -> Vec<u8> {
        let mut frame = vec![0; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
        frame[12..14].copy_from_slice(&ARP_ETHERTYPE.to_be_bytes());
        frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
        frame[22..28].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame[28..32].copy_from_slice(&[192, 0, 2, 1]);
        frame[32..38].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
        frame[38..42].copy_from_slice(&[192, 0, 2, 2]);
        frame
    }

    #[test]
    fn ipv4_exact_ethernet_header_is_not_treated_as_ethernet_truncated() {
        // Protects the strict Ethernet lower-bound check from `==` and `<=` mutants.
        let mut frame = vec![0; ETHERNET_HEADER_LEN];
        frame[12..14].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());

        assert_eq!(
            validate_ipv4_frame(&frame),
            Err(DropReason::Ipv4HeaderTruncated)
        );
    }

    #[test]
    fn ipv4_minimum_available_header_is_accepted() {
        // Protects the IPv4 available-length lower bound from `==` and `<=` mutants.
        let frame = ipv4_frame_at_ethernet_minimum();

        let validated = validate_ipv4_frame(&frame).unwrap();
        assert_eq!(validated.header_len, IPV4_MIN_HEADER_LEN);
        assert_eq!(validated.total_len, IPV4_MIN_HEADER_LEN);
    }

    #[test]
    fn ipv4_validation_reports_the_checksum_field_at_its_header_offset() {
        // Protects the checksum-field offset from the `+` to `-` mutant.
        let frame = ipv4_frame_at_ethernet_minimum();
        let expected_checksum = u16::from_be_bytes([frame[24], frame[25]]);
        assert_ne!(expected_checksum, 0);

        let validated = validate_ipv4_frame(&frame).unwrap();
        assert_eq!(validated.checksum, expected_checksum);
    }

    #[test]
    fn arp_exact_ethernet_header_is_reported_as_an_incomplete_arp_frame() {
        // Protects the Ethernet lower-bound check from the `==` and `<=` mutants.
        let mut frame = vec![0; ETHERNET_HEADER_LEN];
        frame[12..14].copy_from_slice(&ARP_ETHERTYPE.to_be_bytes());

        assert_eq!(validate_arp(&frame), Err(DropReason::ArpPacketTruncated));
    }

    #[test]
    fn arp_longer_than_ethernet_header_reaches_the_arp_length_check() {
        // Protects the Ethernet lower-bound check from the `>` mutant.
        let mut frame = vec![0; ETHERNET_HEADER_LEN + 1];
        frame[12..14].copy_from_slice(&ARP_ETHERTYPE.to_be_bytes());

        assert_eq!(validate_arp(&frame), Err(DropReason::ArpPacketTruncated));
    }

    #[test]
    fn arp_exact_wire_length_is_accepted() {
        // Protects the exact ARP frame-size boundary from the `==` and `<=` mutants,
        // and protects the ARP_FRAME_LEN addition from replacement with multiplication.
        let frame = arp_frame();

        assert_eq!(validate_arp(&frame).unwrap().opcode, ArpOpcode::Request);
    }

    #[test]
    fn arp_short_frame_is_rejected_before_header_value_parsing() {
        // Protects the short-frame branch from the `>` mutant at the ARP length check.
        let mut frame = vec![0; ETHERNET_HEADER_LEN + 6];
        frame[12..14].copy_from_slice(&ARP_ETHERTYPE.to_be_bytes());

        assert_eq!(validate_arp(&frame), Err(DropReason::ArpPacketTruncated));
    }

    #[test]
    fn arp_rejects_an_unsupported_hardware_type() {
        // Protects the ARP hardware-type inequality from replacement with `==`.
        let mut frame = arp_frame();
        frame[14..16].copy_from_slice(&2_u16.to_be_bytes());

        assert_eq!(
            validate_arp(&frame),
            Err(DropReason::ArpHardwareTypeUnsupported)
        );
    }

    #[test]
    fn arp_rejects_an_unsupported_ether_type() {
        // Protects the ARP EtherType inequality from replacement with `==`.
        let mut frame = arp_frame();
        frame[12..14].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());

        assert_eq!(validate_arp(&frame), Err(DropReason::UnsupportedEtherType));
    }

    #[test]
    fn arp_rejects_an_unsupported_protocol_type() {
        // Protects the ARP protocol-type inequality from replacement with `==`.
        let mut frame = arp_frame();
        frame[16..18].copy_from_slice(&0x0801_u16.to_be_bytes());

        assert_eq!(
            validate_arp(&frame),
            Err(DropReason::ArpProtocolTypeUnsupported)
        );
    }

    #[test]
    fn arp_rejects_an_unsupported_hardware_address_length() {
        // Protects the ARP hardware-length inequality from replacement with `==`.
        let mut frame = arp_frame();
        frame[18] = 5;

        assert_eq!(
            validate_arp(&frame),
            Err(DropReason::ArpHardwareLengthUnsupported)
        );
    }

    #[test]
    fn arp_rejects_an_unsupported_protocol_address_length() {
        // Protects the ARP protocol-length inequality from replacement with `==`.
        let mut frame = arp_frame();
        frame[19] = 5;

        assert_eq!(
            validate_arp(&frame),
            Err(DropReason::ArpProtocolLengthUnsupported)
        );
    }

    #[test]
    fn arp_request_validator_accepts_a_request_opcode() {
        // Protects the request-only opcode comparison from `==` to `!=`.
        let frame = arp_frame();

        assert_eq!(
            validate_arp_request(&frame).unwrap().opcode,
            ArpOpcode::Request
        );
    }
}

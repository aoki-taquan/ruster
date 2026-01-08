//! ICMPv6 protocol - RFC 4443, NDP - RFC 4861

use super::MacAddr;
use crate::{Error, Result};
use std::net::Ipv6Addr;

/// Minimum ICMPv6 header size
pub const MIN_HEADER_SIZE: usize = 4;

/// Neighbor Solicitation/Advertisement message size (without options)
pub const NDP_MSG_SIZE: usize = 24; // 4 (header) + 4 (reserved/flags) + 16 (target)

/// ICMPv6 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmpv6Type {
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
}

impl Icmpv6Type {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Icmpv6Type::DestinationUnreachable),
            2 => Some(Icmpv6Type::PacketTooBig),
            3 => Some(Icmpv6Type::TimeExceeded),
            4 => Some(Icmpv6Type::ParameterProblem),
            128 => Some(Icmpv6Type::EchoRequest),
            129 => Some(Icmpv6Type::EchoReply),
            133 => Some(Icmpv6Type::RouterSolicitation),
            134 => Some(Icmpv6Type::RouterAdvertisement),
            135 => Some(Icmpv6Type::NeighborSolicitation),
            136 => Some(Icmpv6Type::NeighborAdvertisement),
            137 => Some(Icmpv6Type::Redirect),
            _ => None,
        }
    }
}

/// NDP option types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NdpOptionType {
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    PrefixInformation = 3,
    RedirectedHeader = 4,
    Mtu = 5,
}

impl NdpOptionType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(NdpOptionType::SourceLinkLayerAddress),
            2 => Some(NdpOptionType::TargetLinkLayerAddress),
            3 => Some(NdpOptionType::PrefixInformation),
            4 => Some(NdpOptionType::RedirectedHeader),
            5 => Some(NdpOptionType::Mtu),
            _ => None,
        }
    }
}

/// Parsed ICMPv6 header (zero-copy reference)
#[derive(Debug)]
pub struct Icmpv6Packet<'a> {
    buffer: &'a [u8],
}

impl<'a> Icmpv6Packet<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < MIN_HEADER_SIZE {
            return Err(Error::Parse("ICMPv6 packet too short".into()));
        }

        Ok(Self { buffer })
    }

    /// Message type
    pub fn msg_type(&self) -> u8 {
        self.buffer[0]
    }

    /// Message code
    pub fn code(&self) -> u8 {
        self.buffer[1]
    }

    /// Checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Message body (after header)
    pub fn body(&self) -> &[u8] {
        &self.buffer[MIN_HEADER_SIZE..]
    }

    /// Raw packet bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }
}

/// Neighbor Solicitation message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborSolicitation {
    pub target_addr: Ipv6Addr,
    pub source_link_addr: Option<MacAddr>,
}

impl NeighborSolicitation {
    /// Parse from ICMPv6 body (after type/code/checksum)
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        // Minimum: 4 (reserved) + 16 (target) = 20 bytes
        if buffer.len() < 20 {
            return Err(Error::Parse("Neighbor Solicitation too short".into()));
        }

        // Skip 4 bytes reserved
        let target_bytes: [u8; 16] = buffer[4..20].try_into().unwrap();
        let target_addr = Ipv6Addr::from(target_bytes);

        // Parse options
        let source_link_addr =
            parse_link_layer_option(&buffer[20..], NdpOptionType::SourceLinkLayerAddress);

        Ok(Self {
            target_addr,
            source_link_addr,
        })
    }

    /// Build NS message bytes (ICMPv6 payload, without IPv6 header)
    pub fn to_bytes(&self) -> Vec<u8> {
        let option_len = if self.source_link_addr.is_some() {
            8
        } else {
            0
        };
        let mut buf = vec![0u8; NDP_MSG_SIZE + option_len];

        // Type
        buf[0] = Icmpv6Type::NeighborSolicitation as u8;
        // Code
        buf[1] = 0;
        // Checksum (placeholder, calculated separately)
        buf[2] = 0;
        buf[3] = 0;
        // Reserved
        buf[4..8].copy_from_slice(&[0, 0, 0, 0]);
        // Target Address
        buf[8..24].copy_from_slice(&self.target_addr.octets());

        // Source Link-Layer Address option
        if let Some(mac) = &self.source_link_addr {
            buf[24] = NdpOptionType::SourceLinkLayerAddress as u8;
            buf[25] = 1; // Length in units of 8 bytes
            buf[26..32].copy_from_slice(&mac.0);
        }

        buf
    }

    /// Create a new NS for the given target
    pub fn new(target_addr: Ipv6Addr, source_link_addr: Option<MacAddr>) -> Self {
        Self {
            target_addr,
            source_link_addr,
        }
    }
}

/// Neighbor Advertisement message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborAdvertisement {
    pub router_flag: bool,
    pub solicited_flag: bool,
    pub override_flag: bool,
    pub target_addr: Ipv6Addr,
    pub target_link_addr: Option<MacAddr>,
}

impl NeighborAdvertisement {
    /// Parse from ICMPv6 body (after type/code/checksum)
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        // Minimum: 4 (flags/reserved) + 16 (target) = 20 bytes
        if buffer.len() < 20 {
            return Err(Error::Parse("Neighbor Advertisement too short".into()));
        }

        let flags = buffer[0];
        let router_flag = (flags & 0x80) != 0;
        let solicited_flag = (flags & 0x40) != 0;
        let override_flag = (flags & 0x20) != 0;

        let target_bytes: [u8; 16] = buffer[4..20].try_into().unwrap();
        let target_addr = Ipv6Addr::from(target_bytes);

        // Parse options
        let target_link_addr =
            parse_link_layer_option(&buffer[20..], NdpOptionType::TargetLinkLayerAddress);

        Ok(Self {
            router_flag,
            solicited_flag,
            override_flag,
            target_addr,
            target_link_addr,
        })
    }

    /// Build NA message bytes (ICMPv6 payload, without IPv6 header)
    pub fn to_bytes(&self) -> Vec<u8> {
        let option_len = if self.target_link_addr.is_some() {
            8
        } else {
            0
        };
        let mut buf = vec![0u8; NDP_MSG_SIZE + option_len];

        // Type
        buf[0] = Icmpv6Type::NeighborAdvertisement as u8;
        // Code
        buf[1] = 0;
        // Checksum (placeholder)
        buf[2] = 0;
        buf[3] = 0;
        // Flags
        let mut flags: u8 = 0;
        if self.router_flag {
            flags |= 0x80;
        }
        if self.solicited_flag {
            flags |= 0x40;
        }
        if self.override_flag {
            flags |= 0x20;
        }
        buf[4] = flags;
        // Reserved
        buf[5..8].copy_from_slice(&[0, 0, 0]);
        // Target Address
        buf[8..24].copy_from_slice(&self.target_addr.octets());

        // Target Link-Layer Address option
        if let Some(mac) = &self.target_link_addr {
            buf[24] = NdpOptionType::TargetLinkLayerAddress as u8;
            buf[25] = 1; // Length in units of 8 bytes
            buf[26..32].copy_from_slice(&mac.0);
        }

        buf
    }

    /// Create a new NA (reply to NS)
    pub fn new(
        target_addr: Ipv6Addr,
        target_link_addr: Option<MacAddr>,
        router_flag: bool,
        solicited_flag: bool,
        override_flag: bool,
    ) -> Self {
        Self {
            router_flag,
            solicited_flag,
            override_flag,
            target_addr,
            target_link_addr,
        }
    }

    /// Create a solicited NA (reply to NS for our address)
    pub fn solicited_reply(target_addr: Ipv6Addr, target_link_addr: MacAddr) -> Self {
        Self {
            router_flag: false,
            solicited_flag: true,
            override_flag: true,
            target_addr,
            target_link_addr: Some(target_link_addr),
        }
    }
}

/// Parse link-layer address option from NDP options
fn parse_link_layer_option(options: &[u8], expected_type: NdpOptionType) -> Option<MacAddr> {
    let mut offset = 0;
    while offset + 2 <= options.len() {
        let opt_type = options[offset];
        let opt_len = options[offset + 1] as usize * 8; // Length in units of 8 bytes

        if opt_len == 0 {
            break; // Invalid length, stop parsing
        }

        if offset + opt_len > options.len() {
            break; // Truncated option
        }

        if opt_type == expected_type as u8 && opt_len >= 8 {
            // Link-layer address is at offset+2, 6 bytes for Ethernet
            let mac_bytes: [u8; 6] = options[offset + 2..offset + 8].try_into().ok()?;
            return Some(MacAddr(mac_bytes));
        }

        offset += opt_len;
    }
    None
}

/// Calculate ICMPv6 checksum with IPv6 pseudo-header
pub fn calculate_checksum(src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr, icmpv6_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address (16 bytes)
    for chunk in src_addr.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Pseudo-header: destination address (16 bytes)
    for chunk in dst_addr.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Pseudo-header: upper-layer packet length (4 bytes)
    let length = icmpv6_data.len() as u32;
    sum = sum.wrapping_add(length >> 16);
    sum = sum.wrapping_add(length & 0xFFFF);

    // Pseudo-header: next header (ICMPv6 = 58)
    sum = sum.wrapping_add(58);

    // ICMPv6 message (with checksum field zeroed)
    for i in (0..icmpv6_data.len()).step_by(2) {
        let word = if i + 1 < icmpv6_data.len() {
            // Skip checksum field (bytes 2-3)
            if i == 2 {
                0
            } else {
                u16::from_be_bytes([icmpv6_data[i], icmpv6_data[i + 1]])
            }
        } else {
            u16::from_be_bytes([icmpv6_data[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Set checksum in ICMPv6 message buffer
pub fn set_checksum(buffer: &mut [u8], src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr) {
    // Zero out checksum field first
    buffer[2] = 0;
    buffer[3] = 0;

    let checksum = calculate_checksum(src_addr, dst_addr, buffer);
    buffer[2..4].copy_from_slice(&checksum.to_be_bytes());
}

/// Validate ICMPv6 checksum
pub fn validate_checksum(src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr, icmpv6_data: &[u8]) -> bool {
    let mut sum: u32 = 0;

    // Pseudo-header: source address
    for chunk in src_addr.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Pseudo-header: destination address
    for chunk in dst_addr.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Pseudo-header: length
    let length = icmpv6_data.len() as u32;
    sum = sum.wrapping_add(length >> 16);
    sum = sum.wrapping_add(length & 0xFFFF);

    // Pseudo-header: next header
    sum = sum.wrapping_add(58);

    // ICMPv6 message (including checksum)
    for i in (0..icmpv6_data.len()).step_by(2) {
        let word = if i + 1 < icmpv6_data.len() {
            u16::from_be_bytes([icmpv6_data[i], icmpv6_data[i + 1]])
        } else {
            u16::from_be_bytes([icmpv6_data[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum == 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ns_packet() -> Vec<u8> {
        // Neighbor Solicitation for 2001:db8::1 with source link-layer address
        vec![
            0x87, // Type: NS (135)
            0x00, // Code: 0
            0x00, 0x00, // Checksum (placeholder)
            0x00, 0x00, 0x00, 0x00, // Reserved
            // Target: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Option: Source Link-Layer Address
            0x01, // Type: 1
            0x01, // Length: 1 (8 bytes)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC
        ]
    }

    fn make_na_packet() -> Vec<u8> {
        // Neighbor Advertisement for 2001:db8::1 with flags R=0, S=1, O=1
        vec![
            0x88, // Type: NA (136)
            0x00, // Code: 0
            0x00, 0x00, // Checksum (placeholder)
            0x60, // Flags: S=1, O=1 (0b01100000)
            0x00, 0x00, 0x00, // Reserved
            // Target: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Option: Target Link-Layer Address
            0x02, // Type: 2
            0x01, // Length: 1 (8 bytes)
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // MAC
        ]
    }

    // Icmpv6Type tests
    #[test]
    fn test_icmpv6_type_from_u8() {
        assert_eq!(
            Icmpv6Type::from_u8(1),
            Some(Icmpv6Type::DestinationUnreachable)
        );
        assert_eq!(Icmpv6Type::from_u8(128), Some(Icmpv6Type::EchoRequest));
        assert_eq!(Icmpv6Type::from_u8(129), Some(Icmpv6Type::EchoReply));
        assert_eq!(
            Icmpv6Type::from_u8(135),
            Some(Icmpv6Type::NeighborSolicitation)
        );
        assert_eq!(
            Icmpv6Type::from_u8(136),
            Some(Icmpv6Type::NeighborAdvertisement)
        );
        assert_eq!(Icmpv6Type::from_u8(255), None);
    }

    // NdpOptionType tests
    #[test]
    fn test_ndp_option_type_from_u8() {
        assert_eq!(
            NdpOptionType::from_u8(1),
            Some(NdpOptionType::SourceLinkLayerAddress)
        );
        assert_eq!(
            NdpOptionType::from_u8(2),
            Some(NdpOptionType::TargetLinkLayerAddress)
        );
        assert_eq!(
            NdpOptionType::from_u8(3),
            Some(NdpOptionType::PrefixInformation)
        );
        assert_eq!(NdpOptionType::from_u8(99), None);
    }

    // Icmpv6Packet tests
    #[test]
    fn test_icmpv6_parse() {
        let data = make_ns_packet();
        let pkt = Icmpv6Packet::parse(&data).unwrap();

        assert_eq!(pkt.msg_type(), 135);
        assert_eq!(pkt.code(), 0);
        assert_eq!(pkt.body().len(), 28); // 32 - 4
    }

    #[test]
    fn test_icmpv6_parse_too_short() {
        let short = vec![0u8; 3];
        assert!(Icmpv6Packet::parse(&short).is_err());
    }

    // NeighborSolicitation tests
    #[test]
    fn test_ns_parse() {
        let data = make_ns_packet();
        let ns = NeighborSolicitation::parse(&data[4..]).unwrap(); // Skip ICMPv6 header

        assert_eq!(ns.target_addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            ns.source_link_addr,
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
    }

    #[test]
    fn test_ns_parse_no_option() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // Reserved
            // Target: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let ns = NeighborSolicitation::parse(&data).unwrap();

        assert_eq!(ns.target_addr, "::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ns.source_link_addr, None);
    }

    #[test]
    fn test_ns_parse_too_short() {
        let short = vec![0u8; 19];
        assert!(NeighborSolicitation::parse(&short).is_err());
    }

    #[test]
    fn test_ns_to_bytes() {
        let ns = NeighborSolicitation::new(
            "2001:db8::1".parse().unwrap(),
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        );

        let bytes = ns.to_bytes();
        assert_eq!(bytes[0], 135); // Type
        assert_eq!(bytes[1], 0); // Code
        assert_eq!(
            &bytes[8..24],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(bytes[24], 1); // Option type
        assert_eq!(bytes[25], 1); // Option length
        assert_eq!(&bytes[26..32], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_ns_roundtrip() {
        let original = NeighborSolicitation::new(
            "fe80::1".parse().unwrap(),
            Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
        );

        let bytes = original.to_bytes();
        let parsed = NeighborSolicitation::parse(&bytes[4..]).unwrap(); // Skip header

        assert_eq!(parsed.target_addr, original.target_addr);
        assert_eq!(parsed.source_link_addr, original.source_link_addr);
    }

    // NeighborAdvertisement tests
    #[test]
    fn test_na_parse() {
        let data = make_na_packet();
        let na = NeighborAdvertisement::parse(&data[4..]).unwrap(); // Skip ICMPv6 header

        assert!(!na.router_flag);
        assert!(na.solicited_flag);
        assert!(na.override_flag);
        assert_eq!(na.target_addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            na.target_link_addr,
            Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        );
    }

    #[test]
    fn test_na_parse_router_flag() {
        let mut data = make_na_packet();
        data[4] = 0xE0; // R=1, S=1, O=1
        let na = NeighborAdvertisement::parse(&data[4..]).unwrap();

        assert!(na.router_flag);
        assert!(na.solicited_flag);
        assert!(na.override_flag);
    }

    #[test]
    fn test_na_parse_too_short() {
        let short = vec![0u8; 19];
        assert!(NeighborAdvertisement::parse(&short).is_err());
    }

    #[test]
    fn test_na_to_bytes() {
        let na = NeighborAdvertisement::new(
            "2001:db8::1".parse().unwrap(),
            Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            true,  // router
            true,  // solicited
            false, // override
        );

        let bytes = na.to_bytes();
        assert_eq!(bytes[0], 136); // Type
        assert_eq!(bytes[1], 0); // Code
        assert_eq!(bytes[4], 0xC0); // Flags: R=1, S=1, O=0
        assert_eq!(
            &bytes[8..24],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(bytes[24], 2); // Option type
    }

    #[test]
    fn test_na_solicited_reply() {
        let na = NeighborAdvertisement::solicited_reply(
            "fe80::1".parse().unwrap(),
            MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        );

        assert!(!na.router_flag);
        assert!(na.solicited_flag);
        assert!(na.override_flag);
        assert_eq!(na.target_addr, "fe80::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            na.target_link_addr,
            Some(MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]))
        );
    }

    #[test]
    fn test_na_roundtrip() {
        let original = NeighborAdvertisement::new(
            "2001:db8::abcd".parse().unwrap(),
            Some(MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])),
            true,
            false,
            true,
        );

        let bytes = original.to_bytes();
        let parsed = NeighborAdvertisement::parse(&bytes[4..]).unwrap();

        assert_eq!(parsed.router_flag, original.router_flag);
        assert_eq!(parsed.solicited_flag, original.solicited_flag);
        assert_eq!(parsed.override_flag, original.override_flag);
        assert_eq!(parsed.target_addr, original.target_addr);
        assert_eq!(parsed.target_link_addr, original.target_link_addr);
    }

    // Checksum tests
    #[test]
    fn test_checksum_calculation() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();

        let ns = NeighborSolicitation::new(
            "fe80::2".parse().unwrap(),
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        );
        let mut bytes = ns.to_bytes();

        set_checksum(&mut bytes, &src, &dst);

        // Verify checksum is valid
        assert!(validate_checksum(&src, &dst, &bytes));
    }

    #[test]
    fn test_checksum_invalid() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();

        let ns = NeighborSolicitation::new("fe80::2".parse().unwrap(), None);
        let mut bytes = ns.to_bytes();

        set_checksum(&mut bytes, &src, &dst);

        // Corrupt the checksum
        bytes[2] ^= 0xFF;

        assert!(!validate_checksum(&src, &dst, &bytes));
    }

    #[test]
    fn test_checksum_different_addresses() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let na = NeighborAdvertisement::solicited_reply(
            "2001:db8::1".parse().unwrap(),
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
        let mut bytes = na.to_bytes();

        set_checksum(&mut bytes, &src, &dst);

        // Valid with correct addresses
        assert!(validate_checksum(&src, &dst, &bytes));

        // Invalid with wrong source
        let wrong_src: Ipv6Addr = "2001:db8::99".parse().unwrap();
        assert!(!validate_checksum(&wrong_src, &dst, &bytes));
    }

    // Option parsing edge cases
    #[test]
    fn test_parse_option_zero_length() {
        // Option with length 0 should stop parsing
        let options = vec![
            0x01, 0x00, // Type 1, Length 0 (invalid)
            0x02, 0x01, // Type 2, Length 1
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let result = parse_link_layer_option(&options, NdpOptionType::TargetLinkLayerAddress);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_option_truncated() {
        // Option claims length but data is truncated
        let options = vec![
            0x01, 0x02, // Type 1, Length 2 (16 bytes)
            0x00, 0x11, 0x22, 0x33, // Only 4 bytes of data
        ];
        let result = parse_link_layer_option(&options, NdpOptionType::SourceLinkLayerAddress);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_multiple_options() {
        // Multiple options, target one is second
        let options = vec![
            // First option: MTU (type 5)
            0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, // MTU = 1500
            // Second option: Target Link-Layer Address
            0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ];
        let result = parse_link_layer_option(&options, NdpOptionType::TargetLinkLayerAddress);
        assert_eq!(result, Some(MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])));
    }
}

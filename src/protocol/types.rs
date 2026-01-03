//! Common protocol types

use std::fmt;
use std::str::FromStr;

/// MAC address (6 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pub const ZERO: MacAddr = MacAddr([0, 0, 0, 0, 0, 0]);

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Error type for MAC address parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMacAddrError {
    kind: ParseMacAddrErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseMacAddrErrorKind {
    Length,
    Format,
    Hex,
}

impl fmt::Display for ParseMacAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ParseMacAddrErrorKind::Length => write!(f, "invalid MAC address length"),
            ParseMacAddrErrorKind::Format => write!(f, "invalid MAC address format"),
            ParseMacAddrErrorKind::Hex => write!(f, "invalid hex digit in MAC address"),
        }
    }
}

impl std::error::Error for ParseMacAddrError {}

impl FromStr for MacAddr {
    type Err = ParseMacAddrError;

    /// Parse a MAC address from string
    ///
    /// Supported formats:
    /// - Colon-separated: "00:11:22:33:44:55"
    /// - Hyphen-separated: "00-11-22-33-44-55"
    /// - No separator: "001122334455"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<&str> = if s.contains(':') {
            s.split(':').collect()
        } else if s.contains('-') {
            s.split('-').collect()
        } else if s.len() == 12 {
            // No separator format
            let mut result = [0u8; 6];
            for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
                let hex_str = std::str::from_utf8(chunk).map_err(|_| ParseMacAddrError {
                    kind: ParseMacAddrErrorKind::Hex,
                })?;
                result[i] = u8::from_str_radix(hex_str, 16).map_err(|_| ParseMacAddrError {
                    kind: ParseMacAddrErrorKind::Hex,
                })?;
            }
            return Ok(MacAddr(result));
        } else {
            return Err(ParseMacAddrError {
                kind: ParseMacAddrErrorKind::Format,
            });
        };

        if bytes.len() != 6 {
            return Err(ParseMacAddrError {
                kind: ParseMacAddrErrorKind::Length,
            });
        }

        let mut result = [0u8; 6];
        for (i, byte_str) in bytes.iter().enumerate() {
            if byte_str.len() != 2 {
                return Err(ParseMacAddrError {
                    kind: ParseMacAddrErrorKind::Format,
                });
            }
            result[i] = u8::from_str_radix(byte_str, 16).map_err(|_| ParseMacAddrError {
                kind: ParseMacAddrErrorKind::Hex,
            })?;
        }

        Ok(MacAddr(result))
    }
}

/// EtherType values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Vlan = 0x8100,
    Ipv6 = 0x86DD,
}

impl EtherType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0800 => Some(EtherType::Ipv4),
            0x0806 => Some(EtherType::Arp),
            0x8100 => Some(EtherType::Vlan),
            0x86DD => Some(EtherType::Ipv6),
            _ => None,
        }
    }
}

/// VLAN tag (802.1Q)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    /// Priority Code Point (3 bits)
    pub pcp: u8,
    /// Drop Eligible Indicator (1 bit)
    pub dei: bool,
    /// VLAN ID (12 bits, 0-4095)
    pub vid: u16,
}

impl VlanTag {
    pub fn new(vid: u16) -> Self {
        Self {
            pcp: 0,
            dei: false,
            vid: vid & 0x0FFF,
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let value =
            ((self.pcp as u16 & 0x07) << 13) | ((self.dei as u16) << 12) | (self.vid & 0x0FFF);
        value.to_be_bytes()
    }

    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        let value = u16::from_be_bytes(bytes);
        Self {
            pcp: ((value >> 13) & 0x07) as u8,
            dei: (value >> 12) & 0x01 != 0,
            vid: value & 0x0FFF,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_addr_broadcast() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr::BROADCAST.is_unicast());
    }

    #[test]
    fn test_mac_addr_unicast() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(!mac.is_broadcast());
        assert!(!mac.is_multicast());
        assert!(mac.is_unicast());
    }

    #[test]
    fn test_mac_addr_multicast() {
        // First byte has LSB set = multicast
        let mac = MacAddr([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        assert!(!mac.is_broadcast());
        assert!(mac.is_multicast());
        assert!(!mac.is_unicast());
    }

    #[test]
    fn test_mac_addr_display() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(format!("{}", mac), "00:11:22:33:44:55");
    }

    #[test]
    fn test_mac_addr_parse_colon() {
        let mac: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        assert_eq!(mac, MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    #[test]
    fn test_mac_addr_parse_hyphen() {
        let mac: MacAddr = "00-11-22-33-44-55".parse().unwrap();
        assert_eq!(mac, MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    #[test]
    fn test_mac_addr_parse_no_separator() {
        let mac: MacAddr = "001122334455".parse().unwrap();
        assert_eq!(mac, MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    #[test]
    fn test_mac_addr_parse_uppercase() {
        let mac: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(mac, MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn test_mac_addr_parse_invalid_length() {
        let result: Result<MacAddr, _> = "00:11:22:33:44".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_mac_addr_parse_invalid_hex() {
        let result: Result<MacAddr, _> = "00:11:22:33:44:gg".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_mac_addr_parse_invalid_format() {
        let result: Result<MacAddr, _> = "00.11.22.33.44.55".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_mac_addr_roundtrip() {
        let original = MacAddr([0xab, 0xcd, 0xef, 0x12, 0x34, 0x56]);
        let s = original.to_string();
        let parsed: MacAddr = s.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_ethertype_from_u16() {
        assert_eq!(EtherType::from_u16(0x0800), Some(EtherType::Ipv4));
        assert_eq!(EtherType::from_u16(0x0806), Some(EtherType::Arp));
        assert_eq!(EtherType::from_u16(0x8100), Some(EtherType::Vlan));
        assert_eq!(EtherType::from_u16(0x86DD), Some(EtherType::Ipv6));
        assert_eq!(EtherType::from_u16(0x1234), None);
    }

    #[test]
    fn test_vlan_tag_new() {
        let tag = VlanTag::new(100);
        assert_eq!(tag.vid, 100);
        assert_eq!(tag.pcp, 0);
        assert!(!tag.dei);
    }

    #[test]
    fn test_vlan_tag_new_truncates_vid() {
        // VID is 12 bits, max 4095
        let tag = VlanTag::new(0xFFFF);
        assert_eq!(tag.vid, 0x0FFF);
    }

    #[test]
    fn test_vlan_tag_to_bytes() {
        let tag = VlanTag {
            pcp: 5,
            dei: true,
            vid: 100,
        };
        let bytes = tag.to_bytes();
        // PCP=5 (101), DEI=1, VID=100 (0x64)
        // 101 1 000001100100
        // = 0b1011_0000_0110_0100 = 0xB064
        assert_eq!(bytes, [0xB0, 0x64]);
    }

    #[test]
    fn test_vlan_tag_from_bytes() {
        let tag = VlanTag::from_bytes([0xB0, 0x64]);
        assert_eq!(tag.pcp, 5);
        assert!(tag.dei);
        assert_eq!(tag.vid, 100);
    }

    #[test]
    fn test_vlan_tag_roundtrip() {
        let original = VlanTag {
            pcp: 7,
            dei: true,
            vid: 4095,
        };
        let bytes = original.to_bytes();
        let parsed = VlanTag::from_bytes(bytes);
        assert_eq!(original.pcp, parsed.pcp);
        assert_eq!(original.dei, parsed.dei);
        assert_eq!(original.vid, parsed.vid);
    }
}

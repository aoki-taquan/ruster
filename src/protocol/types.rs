//! Common protocol types

use std::fmt;

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

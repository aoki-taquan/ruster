// IEEE Std 802.3-2022 (Revision of IEEE Std 802.3‐2018)から一部引用
// 6 OCTETS DESTINATION ADDRESS
// 6 OCTETS SOURCE ADDRESS
// 2 OCTETS LENGTH/TYPE

use crate::utils::ArrayVec;

const ETH_MAX_HEDER_NUM: usize = 1;

pub struct RawEthFrame<'a> {
    pub base_header: EthBaseHeader,
    pub option_header_payload: &'a [u8],
}

pub struct EthFrame<'a> {
    pub base_header: EthBaseHeader,
    pub option_header: ArrayVec<EthOptionHeader, ETH_MAX_HEDER_NUM>,
    pub payload: &'a [u8],
}

impl<'a> core::convert::From<RawEthFrame<'a>> for EthFrame<'a> {
    fn from(raw: RawEthFrame<'a>) -> Self {
        let mut option_header = ArrayVec::new();
        let mut payload = raw.option_header_payload;
        let base_header = raw.base_header;
        if let TypeOrLengthFeild::VLAN = base_header.get_type_or_length_field().unwrap() {
            let vlan_header = VlanHeader([payload[0], payload[1]]);
            option_header.push(EthOptionHeader::VLAN(vlan_header));
            payload = &payload[4..];
        }
        Self {
            base_header,
            option_header,
            payload,
        }
    }
}

#[derive()]
pub enum EthOptionHeader {
    VLAN(VlanHeader),
}

#[repr(C)]
pub struct EthBaseHeader {
    pub destination_address: [u8; 6],
    pub source_address: [u8; 6],
    // TODO TypeOrLengthFeildは対応が必要
    type_or_length_field: u16,
}

pub const ETH_HEADER_SIZE: usize = 14;

impl EthBaseHeader {
    #[inline(always)]
    pub fn get_type_or_length_field(&self) -> Option<TypeOrLengthFeild> {
        TypeOrLengthFeild::from_u16(self.type_or_length_field)
    }

    #[inline(always)]
    pub fn set_type_or_length_field(&mut self, value: TypeOrLengthFeild) {
        self.type_or_length_field = value.to_u16();
    }

    // fcsはnicが自動で付けるので書けない
}

#[repr(u16)]
pub enum TypeOrLengthFeild {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    VLAN = 0x8100,
    Length(u16),
}

impl TypeOrLengthFeild {
    #[inline(always)]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0800 => Some(Self::IPv4),
            0x0806 => Some(Self::ARP),
            0x86DD => Some(Self::IPv6),
            0x8100 => Some(Self::VLAN),
            _ if value <= 1500 => Some(Self::Length(value)),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::IPv4 => 0x0800,
            Self::ARP => 0x0806,
            Self::IPv6 => 0x86DD,
            Self::VLAN => 0x8100,
            Self::Length(value) => *value,
        }
    }
}

// 802.1Q VLAN Header
// 3 PCP
// 1 DEI
// 12 VID
#[repr(C)]
pub struct VlanHeader([u8; 2]);

impl VlanHeader {
    #[inline(always)]
    pub fn get_pcp(&self) -> u8 {
        self.0[0] >> 5
    }
    pub fn set_pcp(&mut self, value: u8) {
        self.0[0] = (self.0[0] & 0b0001_1111) | (value << 5);
    }

    #[inline(always)]
    pub fn get_dei(&self) -> bool {
        (self.0[0] & 0b0001_0000) != 0
    }

    #[inline(always)]
    pub fn set_dei(&mut self, value: bool) {
        if value {
            self.0[0] |= 0b0001_0000;
        } else {
            self.0[0] &= 0b1110_1111;
        }
    }

    #[inline(always)]
    pub fn get_vid(&self) -> u16 {
        u16::from_be_bytes([self.0[0] & 0b0000_1111, self.0[1]])
    }

    #[inline(always)]
    pub fn set_vid(&mut self, value: u16) {
        self.0[0] = (self.0[0] & 0b1111_0000) | ((value >> 8) as u8 & 0b0000_1111);
        self.0[1] = value as u8;
    }
}

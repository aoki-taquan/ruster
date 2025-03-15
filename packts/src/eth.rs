// IEEE Std 802.3-2022 (Revision of IEEE Std 802.3‐2018)から一部引用
// 6 OCTETS DESTINATION ADDRESS
// 6 OCTETS SOURCE ADDRESS
// 2 OCTETS LENGTH/TYPE

#[repr(C)]
pub struct EthFlame {
    pub destination_address: [u8; 6],
    pub source_address: [u8; 6],
    // TODO TypeOrLengthFeildは対応が必要
    type_or_length_field: u16,
    payload: [u8; 0],
}

pub const ETH_HEADER_SIZE: usize = 14;

impl EthFlame {
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

// TODO VLAN

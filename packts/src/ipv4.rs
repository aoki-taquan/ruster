// RFC 791: Internet Protocolより引用
//    0               1               2               3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version|  IHL  |Type of Service|          Total Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Identification        |Flags|      Fragment Offset    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Time to Live |    Protocol   |         Header Checksum       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Destination Address                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                    Example Internet Datagram Header
#[repr(C)]
pub struct Ipv4Packet {
    version_ihl: u8,
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    flags_fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8, //TODO Enum
    pub header_checksum: u16,
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
    options_payload: [u8],
}

impl Ipv4Packet {
    #[inline(always)]
    pub fn get_version(&self) -> u8 {
        self.version_ihl >> 4
    }

    #[inline(always)]
    pub fn set_version(&mut self, version: u8) {
        self.version_ihl = (self.version_ihl & 0x0F) | (version << 4);
    }

    #[inline(always)]
    pub fn get_ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    #[inline(always)]
    pub fn set_ihl(&mut self, ihl: u8) {
        self.version_ihl = (self.version_ihl & 0xF0) | (ihl & 0x0F);
    }

    #[inline(always)]
    pub fn get_dscp(&self) -> u8 {
        self.type_of_service >> 2
    }

    #[inline(always)]
    pub fn set_dscp(&mut self, dscp: u8) {
        self.type_of_service = (self.type_of_service & 0x03) | (dscp << 2);
    }

    #[inline(always)]
    pub fn get_ecn(&self) -> u8 {
        self.type_of_service & 0x03
    }

    #[inline(always)]
    pub fn set_ecn(&mut self, ecn: u8) {
        self.type_of_service = (self.type_of_service & 0xFC) | (ecn & 0x03);
    }

    #[inline(always)]
    pub fn get_flags(&self) -> u8 {
        (self.flags_fragment_offset >> 13) as u8
    }

    #[inline(always)]
    pub fn set_flags(&mut self, flags: u8) {
        self.flags_fragment_offset = (self.flags_fragment_offset & 0x1FFF) | ((flags as u16) << 13);
    }

    #[inline(always)]
    pub fn get_fragment_offset(&self) -> u16 {
        self.flags_fragment_offset & 0x1FFF
    }

    #[inline(always)]
    pub fn set_fragment_offset(&mut self, fragment_offset: u16) {
        self.flags_fragment_offset =
            (self.flags_fragment_offset & 0xE000) | (fragment_offset & 0x1FFF);
    }
}

// RFC 9293: Transmission Control Protocol より引用
// 0               1               2               3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |       |C|E|U|A|P|R|S|F|                               |
// | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
// |       |       |R|E|G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           [Options]                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               :
// :                             Data                              :
// :                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
pub struct TcpPacket {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    data_offset_rsrvd: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    option_payload: [u8],
}

impl TcpPacket {
    #[inline(always)]
    pub fn get_data_offset(&self) -> u8 {
        self.data_offset_rsrvd >> 4
    }

    #[inline(always)]
    pub fn set_data_offset(&mut self, value: u8) {
        self.data_offset_rsrvd = (self.data_offset_rsrvd & 0x0F) | (value << 4);
    }

    #[inline(always)]
    pub fn get_reserved(&self) -> u8 {
        self.data_offset_rsrvd & 0x0F
    }

    #[inline(always)]
    pub fn set_reserved(&mut self, value: u8) {
        self.data_offset_rsrvd = (self.data_offset_rsrvd & 0xF0) | value & 0x0F;
    }

    #[inline(always)]
    pub fn get_ns(&self) -> bool {
        self.data_offset_rsrvd & 0x01 != 0
    }

    #[inline(always)]
    pub fn set_ns(&mut self, value: bool) {
        self.data_offset_rsrvd = (self.data_offset_rsrvd & 0xFE) | value as u8;
    }

    #[inline(always)]
    pub fn get_cwr(&self) -> bool {
        self.flags & 0x80 != 0
    }

    #[inline(always)]
    pub fn set_cwr(&mut self, value: bool) {
        self.flags = (self.flags & 0x7F) | (value as u8) << 7;
    }

    #[inline(always)]
    pub fn get_ece(&self) -> bool {
        self.flags & 0x40 != 0
    }

    #[inline(always)]
    pub fn set_ece(&mut self, value: bool) {
        self.flags = (self.flags & 0xBF) | (value as u8) << 6;
    }

    #[inline(always)]
    pub fn get_urg(&self) -> bool {
        self.flags & 0x20 != 0
    }

    #[inline(always)]
    pub fn set_urg(&mut self, value: bool) {
        self.flags = (self.flags & 0xDF) | (value as u8) << 5;
    }

    #[inline(always)]
    pub fn get_ack(&self) -> bool {
        self.flags & 0x10 != 0
    }

    #[inline(always)]
    pub fn set_ack(&mut self, value: bool) {
        self.flags = (self.flags & 0xEF) | (value as u8) << 4;
    }

    #[inline(always)]
    pub fn get_psh(&self) -> bool {
        self.flags & 0x08 != 0
    }

    #[inline(always)]
    pub fn set_psh(&mut self, value: bool) {
        self.flags = (self.flags & 0xF7) | (value as u8) << 3;
    }

    #[inline(always)]
    pub fn get_rst(&self) -> bool {
        self.flags & 0x04 != 0
    }

    #[inline(always)]
    pub fn set_rst(&mut self, value: bool) {
        self.flags = (self.flags & 0xFB) | (value as u8) << 2;
    }

    #[inline(always)]
    pub fn get_syn(&self) -> bool {
        self.flags & 0x02 != 0
    }

    #[inline(always)]
    pub fn set_syn(&mut self, value: bool) {
        self.flags = (self.flags & 0xFD) | (value as u8) << 1;
    }

    #[inline(always)]
    pub fn get_fin(&self) -> bool {
        self.flags & 0x01 != 0
    }

    #[inline(always)]
    pub fn set_fin(&mut self, value: bool) {
        self.flags = (self.flags & 0xFE) | value as u8;
    }

    // TODO Options
}

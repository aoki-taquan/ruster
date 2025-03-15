// RFC8200 より引用
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version| Traffic Class |           Flow Label                  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Payload Length        |  Next Header  |   Hop Limit   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                         Source Address                        +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                      Destination Address                      +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

pub struct Ipv6Packet {
    version_traffic_class_flow_label: [u8; 4],
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    // TODO: extension headers
    #[allow(dead_code)]
    extension_headers_payload: [u8],
}

impl Ipv6Packet {
    #[inline(always)]
    pub fn get_verison(&self) -> u8 {
        self.version_traffic_class_flow_label[0] >> 4
    }

    #[inline(always)]
    pub fn set_version(&mut self, version: u8) {
        self.version_traffic_class_flow_label[0] =
            (self.version_traffic_class_flow_label[0] & 0x0F) | (version << 4);
    }

    #[inline(always)]
    pub fn get_traffic_class(&self) -> u8 {
        (self.version_traffic_class_flow_label[0] & 0x0F) << 4
            | self.version_traffic_class_flow_label[1] >> 4
    }

    #[inline(always)]
    pub fn set_traffic_class(&mut self, traffic_class: u8) {
        self.version_traffic_class_flow_label[0] =
            (self.version_traffic_class_flow_label[0] & 0xF0) | (traffic_class >> 4);
        self.version_traffic_class_flow_label[1] =
            (self.version_traffic_class_flow_label[1] & 0x0F) | (traffic_class << 4);
    }

    #[inline(always)]
    pub fn get_flow_label(&self) -> u32 {
        ((self.version_traffic_class_flow_label[1] as u32) << 16)
            | ((self.version_traffic_class_flow_label[2] as u32) << 8)
            | self.version_traffic_class_flow_label[3] as u32
    }

    #[inline(always)]
    pub fn set_flow_label(&mut self, flow_label: u32) {
        self.version_traffic_class_flow_label[1] =
            (self.version_traffic_class_flow_label[1] & 0xF0) | ((flow_label >> 16) as u8);
        self.version_traffic_class_flow_label[2] = (flow_label >> 8) as u8;
        self.version_traffic_class_flow_label[3] = flow_label as u8;
    }

    // todo extension headers
}

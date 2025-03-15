// RFC 768 User Datagram Protocol より引用
//  0      7 8     15 16    23 24    31
// +--------+--------+--------+--------+
// |     Source      |   Destination   |
// |      Port       |      Port       |
// +--------+--------+--------+--------+
// |                 |                 |
// |     Length      |    Checksum     |
// +--------+--------+--------+--------+
// |
// |          data octets ...
// +---------------- ...

pub struct UdpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub data: [u8],
}

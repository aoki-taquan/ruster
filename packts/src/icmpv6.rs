// RFC 4443 Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification　より引用
// Message General Format
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                         Message Body                          +
// |                                                               |

#[repr(C)]
pub struct Icmpv6MessageGeneralFormat {
    pub type_: Types,
    pub code: u8,
    pub checksum: u16,
    pub message_body: [u8],
}

#[repr(u8)]
pub enum Types {
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    EchoRequest = 128,
    EchoReply = 129,
}

// RFC 4443 Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification　より引用
// Destination Unreachable Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    As much of invoking packet                 |
// +                as possible without the ICMPv6 packet          +
// |                exceeding the minimum IPv6 MTU [IPv6]          |

#[repr(C)]
pub struct DestinationUnreachable {
    pub type_: u8,
    pub code: DestinationUnreachableCode,
    pub checksum: u16,
    pub unused: u32,
    pub invoking_packet: [u8],
}

impl DestinationUnreachable {
    pub const TYPE: u8 = Types::DestinationUnreachable as u8;
}

#[repr(u8)]
pub enum DestinationUnreachableCode {
    NoRouteToDestination = 0,
    CommunicationWithDestinationAdministrativelyProhibited = 1,
    BeyondScopeOfSourceAddress = 2,
    AddressUnreachable = 3,
    PortUnreachable = 4,
    SourceAddressFailedIngressEgressPolicy = 5,
    RejectRouteToDestination = 6,
}

// RFC 4443 Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification　より引用
// Packet Too Big Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    As much of invoking packet                 |
// +                as possible without the ICMPv6 packet          +
// |                exceeding the minimum IPv6 MTU [IPv6]          |

#[repr(C)]
pub struct PacketTooBig {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub mtu: u32,
    pub invoking_packet: [u8],
}

impl PacketTooBig {
    pub const TYPE: u8 = Types::PacketTooBig as u8;
    pub const CODE: u8 = 0;
}

// RFC 4443 Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification　より引用
// Time Exceeded Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    As much of invoking packet                 |
// +                as possible without the ICMPv6 packet          +
// |                exceeding the minimum IPv6 MTU [IPv6]          |

#[repr(C)]
pub struct TimeExceeded {
    pub type_: u8,
    pub code: TimeExceededCode,
    pub checksum: u16,
    pub unused: u32,
    pub invoking_packet: [u8],
}

impl TimeExceeded {
    pub const TYPE: u8 = Types::TimeExceeded as u8;
}

#[repr(u8)]
pub enum TimeExceededCode {
    HopLimitExceededInTransit = 0,
    FragmentReassemblyTimeExceeded = 1,
}

// RFC 4443 Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification　より引用
// Parameter Problem Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            Pointer                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    As much of invoking packet                 |
// +               as possible without the ICMPv6 packet           +
// |               exceeding the minimum IPv6 MTU [IPv6]           |

#[repr(C)]
pub struct ParameterProblem {
    pub type_: u8,
    pub code: ParameterProblemCode,
    pub checksum: u16,
    pub pointer: u32,
    pub invoking_packet: [u8],
}

impl ParameterProblem {
    pub const TYPE: u8 = Types::ParameterProblem as u8;
}

#[repr(u8)]
pub enum ParameterProblemCode {
    ErroneousHeaderField = 0,
    UnrecognizedNextHeaderType = 1,
    UnrecognizedIPv6Option = 2,
}

// RFC 4443 Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification　より引用
// Echo Request Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Identifier          |        Sequence Number        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Data ...
// +-+-+-+-+-

#[repr(C)]
pub struct EchoRequest {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub data: [u8],
}

impl EchoRequest {
    pub const TYPE: u8 = Types::EchoRequest as u8;
    pub const CODE: u8 = 0;
}

//tudo checksum

// RFC 4443 Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification　より引用
// Echo Reply Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Identifier          |        Sequence Number        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Data ...
// +-+-+-+-+-

#[repr(C)]
pub struct EchoReply {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub data: [u8],
}

impl EchoReply {
    pub const TYPE: u8 = Types::EchoReply as u8;
    pub const CODE: u8 = 0;
}

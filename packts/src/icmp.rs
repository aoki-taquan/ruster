#[repr(C)]
pub struct GeneralFormat {
    pub type_: Types,
    pub code: u8,
    pub checksum: u16,
    pub message_body: [u8],
}

#[repr(u8)]
pub enum Types {
    DestinationUnreachable = 3,
    TimeExceeded = 11,
    ParameterProblem = 12,
    SourceQuench = 4,
    Redirect = 5,
    Echo = 8,
    EchoReply = 0,
    Timestamp = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
}

// todo checksum

// RFC 792 Internet Control Message Protocol より引用
// Destination Unreachable Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
pub struct DestinationUnreachable {
    pub type_: u8,
    pub code: DestinationUnreachableCodes,
    pub checksum: u16,
    #[allow(dead_code)]
    unused: u32,
    pub internet_header_and_original_data_datagram: [u8],
}

impl DestinationUnreachable {
    pub const TYPE: u8 = Types::DestinationUnreachable as u8;
}

#[repr(u8)]
pub enum DestinationUnreachableCodes {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeededAndDFSet = 4,
    SourceRouteFailed = 5,
}

// RFC 792 Internet Control Message Protocol より引用
// Time Exceeded Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
pub struct TimeExceeded {
    pub type_: u8,
    pub code: TimeExceededCodes,
    pub checksum: u16,
    #[allow(dead_code)]
    unused: u32,
    pub internet_header_and_original_data_datagram: [u8],
}

impl TimeExceeded {
    pub const TYPE: u8 = Types::TimeExceeded as u8;
}

#[repr(u8)]
pub enum TimeExceededCodes {
    TimeToLiveExceededInTransit = 0,
    FragmentReassemblyTimeExceeded = 1,
}

// RFC 792 Internet Control Message Protocol より引用
// Parameter Problem Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Pointer    |                   unused                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
pub struct ParameterProblem {
    pub type_: u8,
    pub code: ParameterProblemCodes,
    pub checksum: u16,
    pub pointer: u8,
    #[allow(dead_code)]
    unused: [u8; 3],
    pub internet_header_and_original_data_datagram: [u8],
}

impl ParameterProblem {
    pub const TYPE: u8 = Types::ParameterProblem as u8;
}

#[repr(u8)]
pub enum ParameterProblemCodes {
    PointerIndicatesTheError = 0,
}

// RFC 792 Internet Control Message Protocol より引用
// Source Quench Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
pub struct SourceQuench {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
    #[allow(dead_code)]
    unused: u32,
    pub internet_header_and_original_data_datagram: [u8],
}

impl SourceQuench {
    pub const TYPE: u8 = Types::SourceQuench as u8;
    pub const CODE: u8 = 0;
}

// RFC 792 Internet Control Message Protocol より引用
// Redirect Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Gateway Internet Address                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
pub struct Redirect {
    pub type_: u8,
    pub code: RedirectCodes,
    pub checksum: u16,
    pub gateway_internet_address: [u8; 4],
    pub internet_header_and_original_data_datagram: [u8],
}

impl Redirect {
    pub const TYPE: u8 = Types::Redirect as u8;
}

#[repr(u8)]
pub enum RedirectCodes {
    RedirectDatagramsForTheNetwork = 0,
    RedirectDatagramsForTheHost = 1,
    RedirectDatagramsForTheTypeOfServiceAndNetwork = 2,
    RedirectDatagramsForTheTypeOfServiceAndHost = 3,
}

// RFC 792 Internet Control Message Protocol より引用
// Echo or Echo Reply Message
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
pub struct EchoOrEchoReply {
    pub type_: EchoOrEchoReplyTypes,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub data: [u8],
}

#[repr(u8)]
pub enum EchoOrEchoReplyTypes {
    Echo = Types::Echo as u8,
    EchoReply = Types::EchoReply as u8,
}

impl TryFrom<Types> for EchoOrEchoReplyTypes {
    type Error = ();

    fn try_from(t: Types) -> Result<Self, Self::Error> {
        match t {
            Types::Echo => Ok(EchoOrEchoReplyTypes::Echo),
            Types::EchoReply => Ok(EchoOrEchoReplyTypes::EchoReply),
            _ => Err(()),
        }
    }
}

impl From<EchoOrEchoReplyTypes> for Types {
    fn from(t: EchoOrEchoReplyTypes) -> Self {
        match t {
            EchoOrEchoReplyTypes::Echo => Types::Echo,
            EchoOrEchoReplyTypes::EchoReply => Types::EchoReply,
        }
    }
}

// RFC 792 Internet Control Message Protocol より引用
// Timestamp or Timestamp Reply Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |      Code     |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Identifier          |        Sequence Number        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Originate Timestamp                                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Receive Timestamp                                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Transmit Timestamp                                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
pub struct TimestampOrTimestampReply {
    pub type_: TimestampOrTimestampReplyTypes,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub originate_timestamp: u32,
    pub receive_timestamp: u32,
    pub transmit_timestamp: u32,
}

#[repr(u8)]
pub enum TimestampOrTimestampReplyTypes {
    Timestamp = Types::Timestamp as u8,
    TimestampReply = Types::TimestampReply as u8,
}

impl TryFrom<Types> for TimestampOrTimestampReplyTypes {
    type Error = ();

    fn try_from(t: Types) -> Result<Self, Self::Error> {
        match t {
            Types::Timestamp => Ok(TimestampOrTimestampReplyTypes::Timestamp),
            Types::TimestampReply => Ok(TimestampOrTimestampReplyTypes::TimestampReply),
            _ => Err(()),
        }
    }
}

impl From<TimestampOrTimestampReplyTypes> for Types {
    fn from(t: TimestampOrTimestampReplyTypes) -> Self {
        match t {
            TimestampOrTimestampReplyTypes::Timestamp => Types::Timestamp,
            TimestampOrTimestampReplyTypes::TimestampReply => Types::TimestampReply,
        }
    }
}

impl TimestampOrTimestampReply {
    pub const CODE: u8 = 0;
}

// RFC 792 Internet Control Message Protocol より引用
// Information Request or Information Reply Message
//  0               1               2               3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |      Code     |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Identifier          |        Sequence Number        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(C)]
pub struct InformationRequestOrInformationReply {
    pub type_: InformationRequestOrInformationReplyTypes,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
}

#[repr(u8)]
pub enum InformationRequestOrInformationReplyTypes {
    InformationRequest = 15,
    InformationReply = 16,
}

impl InformationRequestOrInformationReply {
    pub const CODE: u8 = 0;
}

#![cfg(feature = "ipv4")]
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

#[cfg(feature = "ipv4_options")]
use self::options::IpV4Options;

pub struct RawIpV4Packet<'a> {
    pub ipv4_base_header: IpV4BaseHeader,
    pub options_payload: &'a [u8],
}

pub struct IpV4PacketNonParseOption<'a> {
    pub ipv4_base_header: IpV4BaseHeader,
    #[cfg(feature = "ipv4_options")]
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> core::convert::From<RawIpV4Packet<'a>> for IpV4PacketNonParseOption<'a> {
    fn from(raw_ipv4_packet: RawIpV4Packet<'a>) -> Self {
        #[cfg(feature = "ipv4_options")]
        let option_end_point = raw_ipv4_packet.ipv4_base_header.get_ihl() as usize * 4;
        #[cfg(not(feature = "ipv4_options"))]
        let option_end_point = 20;
        IpV4PacketNonParseOption {
            ipv4_base_header: raw_ipv4_packet.ipv4_base_header,
            #[cfg(feature = "ipv4_options")]
            options: &raw_ipv4_packet.options_payload[20..option_end_point],
            payload: &raw_ipv4_packet.options_payload[option_end_point..],
        }
    }
}

pub struct IpV4Packet<'a> {
    pub ipv4_base_header: IpV4BaseHeader,
    #[cfg(feature = "ipv4_options")]
    pub options: IpV4Options<'a>,
    pub payload: &'a [u8],
}

impl<'a> core::convert::TryFrom<IpV4PacketNonParseOption<'a>> for IpV4Packet<'a> {
    type Error = ();

    fn try_from(
        ipv4_packet_non_parse_option: IpV4PacketNonParseOption<'a>,
    ) -> Result<Self, Self::Error> {
        Ok(IpV4Packet {
            ipv4_base_header: ipv4_packet_non_parse_option.ipv4_base_header,
            #[cfg(feature = "ipv4_options")]
            options: IpV4Options::try_from(ipv4_packet_non_parse_option.options)
                .expect("IpV4Options is full"),
            payload: ipv4_packet_non_parse_option.payload,
        })
    }
}

impl<'a> core::convert::TryFrom<RawIpV4Packet<'a>> for IpV4Packet<'a> {
    type Error = ();

    fn try_from(raw_ipv4_packet: RawIpV4Packet<'a>) -> Result<Self, Self::Error> {
        let ipv4_packet_non_parse_option = IpV4PacketNonParseOption::from(raw_ipv4_packet);
        IpV4Packet::try_from(ipv4_packet_non_parse_option)
    }
}

#[repr(C)]
pub struct IpV4BaseHeader {
    version_ihl: u8,
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    flags_fragment_offset: u16,
    pub time_to_live: u8,
    protocol: u8,
    pub header_checksum: u16,
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
}

impl IpV4BaseHeader {
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

    #[inline(always)]
    pub fn get_protocol(&self) -> Protocol {
        match self.protocol {
            #[cfg(feature = "icmp")]
            1 => Protocol::ICMP,
            #[cfg(feature = "tcp")]
            6 => Protocol::TCP,
            #[cfg(feature = "udp")]
            17 => Protocol::UDP,
            _ => Protocol::NotSupoort(self.protocol),
        }
    }

    #[inline(always)]
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.protocol = match protocol {
            #[cfg(feature = "icmp")]
            Protocol::ICMP => 1,
            #[cfg(feature = "tcp")]
            Protocol::TCP => 6,
            #[cfg(feature = "udp")]
            Protocol::UDP => 17,
            Protocol::NotSupoort(protocol) => protocol,
        }
    }
}

#[repr(u8)]
pub enum Protocol {
    #[cfg(feature = "icmp")]
    ICMP = 1,
    #[cfg(feature = "tcp")]
    TCP = 6,
    #[cfg(feature = "udp")]
    UDP = 17,
    NotSupoort(u8),
}

#[cfg(feature = "ipv4_options")]
mod options {
    // RFC 791: Internet Protocolより引用
    // The option-type octet is viewed as having 3 fields:
    //
    //   1 bit   copied flag,
    //   2 bits  option class,
    //   5 bits  option number.
    //
    // The copied flag indicates that this option is copied into all
    // fragments on fragmentation.
    //
    //   0 = not copied
    //   1 = copied
    //
    // The option classes are:
    //
    //   0 = control
    //   1 = reserved for future use
    //   2 = debugging and measurement
    //   3 = reserved for future use
    //
    // The following internet options are defined:
    //
    //   CLASS NUMBER LENGTH DESCRIPTION
    //   ----- ------ ------ -----------
    //     0     0      -    End of Option list.  This option occupies only
    //                       1 octet; it has no length octet.
    //     0     1      -    No Operation.  This option occupies only 1
    //                       octet; it has no length octet.
    //     0     2     11    Security.  Used to carry Security,
    //                       Compartmentation, User Group (TCC), and
    //                       Handling Restriction Codes compatible with DOD
    //                       requirements.
    //     0     3     var.  Loose Source Routing.  Used to route the
    //                       internet datagram based on information
    //                       supplied by the source.
    //     0     9     var.  Strict Source Routing.  Used to route the
    //                       internet datagram based on information
    //                       supplied by the source.
    //     0     7     var.  Record Route.  Used to trace the route an
    //                       internet datagram takes.
    //     0     8      4    Stream ID.  Used to carry the stream
    //                       identifier.
    //     2     4     var.  Internet Timestamp.

    #[cfg(feature = "ipv4_options")]
    use crate::utils::{self, ArrayVec};

    #[cfg(feature = "ipv4_options")]
    const IPV4_MAX_OPTION_NUM: usize = 40;

    pub struct RawIpV4Option<'a> {
        type_: IpV4OptionType,
        item: &'a [u8],
    }

    pub type IpV4Options<'a> = ArrayVec<IpV4Option<'a>, IPV4_MAX_OPTION_NUM>;

    pub struct IpV4Option<'a> {
        pub type_: IpV4OptionType,
        pub item: IpV4OptionItems<'a>,
    }

    impl<'a> core::convert::From<RawIpV4Option<'a>> for IpV4Option<'a> {
        fn from(raw_ipv4_option: RawIpV4Option<'a>) -> Self {
            let type_ = raw_ipv4_option.type_.clone();
            IpV4Option {
                type_: raw_ipv4_option.type_,
                item: IpV4OptionItems::from(type_, raw_ipv4_option.item),
            }
        }
    }

    impl<'a> core::convert::TryFrom<&'a [u8]> for IpV4Options<'a> {
        type Error = ();

        fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
            let mut options = ArrayVec::new();
            let mut option = value;
            while !option.is_empty() {
                let option_type = IpV4OptionType(option[0]);
                match option_type.option_len() {
                    IpV4OptionTypeLen::Len(len) => {
                        options
                            .push(IpV4Option::from(RawIpV4Option {
                                type_: option_type,
                                item: &option[1..len],
                            }))
                            .expect("IpV4Options is full");
                        option = &option[len..];
                    }
                    IpV4OptionTypeLen::NextOctet => {
                        let len = option[1] as usize;
                        options
                            .push(IpV4Option::from(RawIpV4Option {
                                type_: option_type,
                                item: &option[2..len],
                            }))
                            .expect("IpV4Options is full");
                        option = &option[len..];
                    }
                    IpV4OptionTypeLen::NotSupport => return Err(()),
                }
            }
            Ok(options)
        }
    }

    #[derive(Clone)]
    pub struct IpV4OptionType(u8);

    impl IpV4OptionType {
        #[inline(always)]
        pub fn get_copied_flag(&self) -> bool {
            self.0 & 0x80 == 0x80
        }

        #[inline(always)]
        pub fn set_copied_flag(&mut self, copied_flag: bool) {
            self.0 = (self.0 & 0x7F) | (copied_flag as u8) << 7;
        }

        #[inline(always)]
        pub fn get_option_class(&self) -> u8 {
            (self.0 & 0x60) >> 5
        }

        #[inline(always)]
        pub fn set_option_class(&mut self, option_class: u8) {
            self.0 = (self.0 & 0x9F) | (option_class << 5);
        }

        #[inline(always)]
        pub fn get_option_number(&self) -> u8 {
            self.0 & 0x1F
        }

        #[inline(always)]
        pub fn set_option_number(&mut self, option_number: u8) {
            self.0 = (self.0 & 0xE0) | (option_number & 0x1F);
        }

        pub fn option_len(&self) -> IpV4OptionTypeLen {
            match self.get_option_class() {
                0 => match self.get_option_number() {
                    0 => IpV4OptionTypeLen::Len(IpV4OptionEndOfOptionList::LEN),
                    _ => IpV4OptionTypeLen::NotSupport,
                },
                _ => IpV4OptionTypeLen::NotSupport,
            }
        }
    }

    pub enum IpV4OptionTypeLen {
        Len(usize),
        NextOctet,
        NotSupport,
    }

    pub enum IpV4OptionItems<'a> {
        None(IpV4OptionEndOfOptionList),
        NotSupport(IpV4OptionNotSupport<'a>),
    }

    impl<'a> IpV4OptionItems<'a> {
        pub fn from(option_type: IpV4OptionType, option: &'a [u8]) -> Self {
            match option_type.get_option_class() {
                0 => match option_type.get_option_number() {
                    0 => IpV4OptionItems::None(IpV4OptionEndOfOptionList()),
                    _ => IpV4OptionItems::NotSupport(IpV4OptionNotSupport(option)),
                },
                _ => IpV4OptionItems::NotSupport(IpV4OptionNotSupport(option)),
            }
        }
    }

    pub struct IpV4OptionEndOfOptionList();

    impl IpV4OptionEndOfOptionList {
        pub const LEN: usize = 1;
    }

    impl utils::Len for IpV4OptionEndOfOptionList {
        fn len(&self) -> usize {
            IpV4OptionEndOfOptionList::LEN
        }
    }

    pub struct IpV4OptionNotSupport<'a>(pub &'a [u8]);

    impl utils::Len for IpV4OptionNotSupport<'_> {
        fn len(&self) -> usize {
            self.0.len() + 1
        }
    }

    impl<'a> core::convert::From<&'a [u8]> for IpV4OptionNotSupport<'a> {
        fn from(option: &'a [u8]) -> Self {
            IpV4OptionNotSupport(option)
        }
    }
}

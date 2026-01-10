//! ICMPv6 protocol - RFC 4443, NDP - RFC 4861

use super::MacAddr;
use crate::{Error, Result};
use std::net::Ipv6Addr;

/// Minimum ICMPv6 header size
pub const MIN_HEADER_SIZE: usize = 4;

/// Neighbor Solicitation/Advertisement message size (without options)
pub const NDP_MSG_SIZE: usize = 24; // 4 (header) + 4 (reserved/flags) + 16 (target)

/// ICMPv6 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmpv6Type {
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
}

impl Icmpv6Type {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Icmpv6Type::DestinationUnreachable),
            2 => Some(Icmpv6Type::PacketTooBig),
            3 => Some(Icmpv6Type::TimeExceeded),
            4 => Some(Icmpv6Type::ParameterProblem),
            128 => Some(Icmpv6Type::EchoRequest),
            129 => Some(Icmpv6Type::EchoReply),
            133 => Some(Icmpv6Type::RouterSolicitation),
            134 => Some(Icmpv6Type::RouterAdvertisement),
            135 => Some(Icmpv6Type::NeighborSolicitation),
            136 => Some(Icmpv6Type::NeighborAdvertisement),
            137 => Some(Icmpv6Type::Redirect),
            _ => None,
        }
    }
}

/// Destination Unreachable codes (RFC 4443)
pub mod dest_unreachable {
    /// No route to destination
    pub const NO_ROUTE: u8 = 0;
    /// Communication with destination administratively prohibited
    pub const ADMIN_PROHIBITED: u8 = 1;
    /// Beyond scope of source address
    pub const BEYOND_SCOPE: u8 = 2;
    /// Address unreachable
    pub const ADDRESS_UNREACHABLE: u8 = 3;
    /// Port unreachable
    pub const PORT_UNREACHABLE: u8 = 4;
    /// Source address failed ingress/egress policy
    pub const FAILED_POLICY: u8 = 5;
    /// Reject route to destination
    pub const REJECT_ROUTE: u8 = 6;
}

/// Time Exceeded codes (RFC 4443)
pub mod time_exceeded {
    /// Hop limit exceeded in transit
    pub const HOP_LIMIT_EXCEEDED: u8 = 0;
    /// Fragment reassembly time exceeded
    pub const FRAGMENT_REASSEMBLY: u8 = 1;
}

/// Parameter Problem codes (RFC 4443)
pub mod parameter_problem {
    /// Erroneous header field encountered
    pub const ERRONEOUS_HEADER: u8 = 0;
    /// Unrecognized Next Header type encountered
    pub const UNRECOGNIZED_NEXT_HEADER: u8 = 1;
    /// Unrecognized IPv6 option encountered
    pub const UNRECOGNIZED_OPTION: u8 = 2;
}

/// NDP option types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NdpOptionType {
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    PrefixInformation = 3,
    RedirectedHeader = 4,
    Mtu = 5,
    Rdnss = 25,
}

impl NdpOptionType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(NdpOptionType::SourceLinkLayerAddress),
            2 => Some(NdpOptionType::TargetLinkLayerAddress),
            3 => Some(NdpOptionType::PrefixInformation),
            4 => Some(NdpOptionType::RedirectedHeader),
            5 => Some(NdpOptionType::Mtu),
            25 => Some(NdpOptionType::Rdnss),
            _ => None,
        }
    }
}

/// Parsed ICMPv6 header (zero-copy reference)
#[derive(Debug)]
pub struct Icmpv6Packet<'a> {
    buffer: &'a [u8],
}

impl<'a> Icmpv6Packet<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < MIN_HEADER_SIZE {
            return Err(Error::Parse("ICMPv6 packet too short".into()));
        }

        Ok(Self { buffer })
    }

    /// Message type
    pub fn msg_type(&self) -> u8 {
        self.buffer[0]
    }

    /// Message code
    pub fn code(&self) -> u8 {
        self.buffer[1]
    }

    /// Checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Message body (after header)
    pub fn body(&self) -> &[u8] {
        &self.buffer[MIN_HEADER_SIZE..]
    }

    /// Raw packet bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Get identifier (for Echo Request/Reply)
    pub fn identifier(&self) -> u16 {
        if self.buffer.len() >= 6 {
            u16::from_be_bytes([self.buffer[4], self.buffer[5]])
        } else {
            0
        }
    }

    /// Get sequence number (for Echo Request/Reply)
    pub fn sequence(&self) -> u16 {
        if self.buffer.len() >= 8 {
            u16::from_be_bytes([self.buffer[6], self.buffer[7]])
        } else {
            0
        }
    }

    /// Get MTU (for Packet Too Big)
    pub fn mtu(&self) -> u32 {
        if self.buffer.len() >= 8 {
            u32::from_be_bytes([
                self.buffer[4],
                self.buffer[5],
                self.buffer[6],
                self.buffer[7],
            ])
        } else {
            0
        }
    }

    /// Get payload (for Echo Request/Reply, after identifier and sequence)
    pub fn payload(&self) -> &[u8] {
        if self.buffer.len() > 8 {
            &self.buffer[8..]
        } else {
            &[]
        }
    }

    /// Check if this is an Echo Request
    pub fn is_echo_request(&self) -> bool {
        self.msg_type() == Icmpv6Type::EchoRequest as u8
    }

    /// Check if this is an Echo Reply
    pub fn is_echo_reply(&self) -> bool {
        self.msg_type() == Icmpv6Type::EchoReply as u8
    }

    /// Check if this is an error message (type < 128)
    pub fn is_error(&self) -> bool {
        self.msg_type() < 128
    }

    /// Get the typed ICMPv6 message type
    pub fn message_type(&self) -> Option<Icmpv6Type> {
        Icmpv6Type::from_u8(self.msg_type())
    }

    /// For error messages: get the original packet data
    pub fn original_packet(&self) -> &[u8] {
        if self.buffer.len() > 8 {
            &self.buffer[8..]
        } else {
            &[]
        }
    }
}

/// Neighbor Solicitation message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborSolicitation {
    pub target_addr: Ipv6Addr,
    pub source_link_addr: Option<MacAddr>,
}

impl NeighborSolicitation {
    /// Parse from ICMPv6 body (after type/code/checksum)
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        // Minimum: 4 (reserved) + 16 (target) = 20 bytes
        if buffer.len() < 20 {
            return Err(Error::Parse("Neighbor Solicitation too short".into()));
        }

        // Skip 4 bytes reserved
        let target_bytes: [u8; 16] = buffer[4..20].try_into().unwrap();
        let target_addr = Ipv6Addr::from(target_bytes);

        // Parse options
        let source_link_addr =
            parse_link_layer_option(&buffer[20..], NdpOptionType::SourceLinkLayerAddress);

        Ok(Self {
            target_addr,
            source_link_addr,
        })
    }

    /// Build NS message bytes (ICMPv6 payload, without IPv6 header)
    pub fn to_bytes(&self) -> Vec<u8> {
        let option_len = if self.source_link_addr.is_some() {
            8
        } else {
            0
        };
        let mut buf = vec![0u8; NDP_MSG_SIZE + option_len];

        // Type
        buf[0] = Icmpv6Type::NeighborSolicitation as u8;
        // Code
        buf[1] = 0;
        // Checksum (placeholder, calculated separately)
        buf[2] = 0;
        buf[3] = 0;
        // Reserved
        buf[4..8].copy_from_slice(&[0, 0, 0, 0]);
        // Target Address
        buf[8..24].copy_from_slice(&self.target_addr.octets());

        // Source Link-Layer Address option
        if let Some(mac) = &self.source_link_addr {
            buf[24] = NdpOptionType::SourceLinkLayerAddress as u8;
            buf[25] = 1; // Length in units of 8 bytes
            buf[26..32].copy_from_slice(&mac.0);
        }

        buf
    }

    /// Create a new NS for the given target
    pub fn new(target_addr: Ipv6Addr, source_link_addr: Option<MacAddr>) -> Self {
        Self {
            target_addr,
            source_link_addr,
        }
    }
}

/// Neighbor Advertisement message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborAdvertisement {
    pub router_flag: bool,
    pub solicited_flag: bool,
    pub override_flag: bool,
    pub target_addr: Ipv6Addr,
    pub target_link_addr: Option<MacAddr>,
}

impl NeighborAdvertisement {
    /// Parse from ICMPv6 body (after type/code/checksum)
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        // Minimum: 4 (flags/reserved) + 16 (target) = 20 bytes
        if buffer.len() < 20 {
            return Err(Error::Parse("Neighbor Advertisement too short".into()));
        }

        let flags = buffer[0];
        let router_flag = (flags & 0x80) != 0;
        let solicited_flag = (flags & 0x40) != 0;
        let override_flag = (flags & 0x20) != 0;

        let target_bytes: [u8; 16] = buffer[4..20].try_into().unwrap();
        let target_addr = Ipv6Addr::from(target_bytes);

        // Parse options
        let target_link_addr =
            parse_link_layer_option(&buffer[20..], NdpOptionType::TargetLinkLayerAddress);

        Ok(Self {
            router_flag,
            solicited_flag,
            override_flag,
            target_addr,
            target_link_addr,
        })
    }

    /// Build NA message bytes (ICMPv6 payload, without IPv6 header)
    pub fn to_bytes(&self) -> Vec<u8> {
        let option_len = if self.target_link_addr.is_some() {
            8
        } else {
            0
        };
        let mut buf = vec![0u8; NDP_MSG_SIZE + option_len];

        // Type
        buf[0] = Icmpv6Type::NeighborAdvertisement as u8;
        // Code
        buf[1] = 0;
        // Checksum (placeholder)
        buf[2] = 0;
        buf[3] = 0;
        // Flags
        let mut flags: u8 = 0;
        if self.router_flag {
            flags |= 0x80;
        }
        if self.solicited_flag {
            flags |= 0x40;
        }
        if self.override_flag {
            flags |= 0x20;
        }
        buf[4] = flags;
        // Reserved
        buf[5..8].copy_from_slice(&[0, 0, 0]);
        // Target Address
        buf[8..24].copy_from_slice(&self.target_addr.octets());

        // Target Link-Layer Address option
        if let Some(mac) = &self.target_link_addr {
            buf[24] = NdpOptionType::TargetLinkLayerAddress as u8;
            buf[25] = 1; // Length in units of 8 bytes
            buf[26..32].copy_from_slice(&mac.0);
        }

        buf
    }

    /// Create a new NA (reply to NS)
    pub fn new(
        target_addr: Ipv6Addr,
        target_link_addr: Option<MacAddr>,
        router_flag: bool,
        solicited_flag: bool,
        override_flag: bool,
    ) -> Self {
        Self {
            router_flag,
            solicited_flag,
            override_flag,
            target_addr,
            target_link_addr,
        }
    }

    /// Create a solicited NA (reply to NS for our address)
    pub fn solicited_reply(target_addr: Ipv6Addr, target_link_addr: MacAddr) -> Self {
        Self {
            router_flag: false,
            solicited_flag: true,
            override_flag: true,
            target_addr,
            target_link_addr: Some(target_link_addr),
        }
    }
}

/// Prefix Information option (RFC 4861 Section 4.6.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixInformation {
    pub prefix_length: u8,
    pub on_link_flag: bool,
    pub autonomous_flag: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix: Ipv6Addr,
}

/// Prefix Information option size (32 bytes including type and length)
pub const PREFIX_INFO_SIZE: usize = 32;

impl PrefixInformation {
    /// Parse from option data (including type and length bytes)
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < PREFIX_INFO_SIZE {
            return Err(Error::Parse("Prefix Information option too short".into()));
        }

        // Type must be 3, Length must be 4 (32 bytes / 8)
        if data[0] != NdpOptionType::PrefixInformation as u8 || data[1] != 4 {
            return Err(Error::Parse("Invalid Prefix Information option".into()));
        }

        let prefix_length = data[2];
        let flags = data[3];
        let on_link_flag = (flags & 0x80) != 0;
        let autonomous_flag = (flags & 0x40) != 0;
        let valid_lifetime = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let preferred_lifetime = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        // Bytes 12-15 are reserved
        let prefix_bytes: [u8; 16] = data[16..32].try_into().unwrap();
        let prefix = Ipv6Addr::from(prefix_bytes);

        Ok(Self {
            prefix_length,
            on_link_flag,
            autonomous_flag,
            valid_lifetime,
            preferred_lifetime,
            prefix,
        })
    }

    /// Serialize to bytes (32 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; PREFIX_INFO_SIZE];

        buf[0] = NdpOptionType::PrefixInformation as u8;
        buf[1] = 4; // Length in 8-byte units
        buf[2] = self.prefix_length;

        let mut flags: u8 = 0;
        if self.on_link_flag {
            flags |= 0x80;
        }
        if self.autonomous_flag {
            flags |= 0x40;
        }
        buf[3] = flags;

        buf[4..8].copy_from_slice(&self.valid_lifetime.to_be_bytes());
        buf[8..12].copy_from_slice(&self.preferred_lifetime.to_be_bytes());
        // Bytes 12-15 reserved (already zero)
        buf[16..32].copy_from_slice(&self.prefix.octets());

        buf
    }

    /// Create a new Prefix Information option
    pub fn new(
        prefix: Ipv6Addr,
        prefix_length: u8,
        on_link_flag: bool,
        autonomous_flag: bool,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        Self {
            prefix_length,
            on_link_flag,
            autonomous_flag,
            valid_lifetime,
            preferred_lifetime,
            prefix,
        }
    }
}

/// Router Solicitation message (RFC 4861 Section 4.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterSolicitation {
    pub source_link_addr: Option<MacAddr>,
}

impl RouterSolicitation {
    /// Parse from ICMPv6 body (after type/code/checksum)
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        // Minimum: 4 bytes reserved
        if buffer.len() < 4 {
            return Err(Error::Parse("Router Solicitation too short".into()));
        }

        // Parse options (after 4 reserved bytes)
        let source_link_addr = if buffer.len() > 4 {
            parse_link_layer_option(&buffer[4..], NdpOptionType::SourceLinkLayerAddress)
        } else {
            None
        };

        Ok(Self { source_link_addr })
    }

    /// Build RS message bytes (ICMPv6 payload, without IPv6 header)
    pub fn to_bytes(&self) -> Vec<u8> {
        let option_len = if self.source_link_addr.is_some() {
            8
        } else {
            0
        };
        let mut buf = vec![0u8; 8 + option_len]; // 4 header + 4 reserved + options

        // Type
        buf[0] = Icmpv6Type::RouterSolicitation as u8;
        // Code
        buf[1] = 0;
        // Checksum (placeholder)
        buf[2] = 0;
        buf[3] = 0;
        // Reserved (bytes 4-7, already zero)

        // Source Link-Layer Address option
        if let Some(mac) = &self.source_link_addr {
            buf[8] = NdpOptionType::SourceLinkLayerAddress as u8;
            buf[9] = 1; // Length in units of 8 bytes
            buf[10..16].copy_from_slice(&mac.0);
        }

        buf
    }

    /// Create a new RS
    pub fn new(source_link_addr: Option<MacAddr>) -> Self {
        Self { source_link_addr }
    }
}

/// Router Advertisement message (RFC 4861 Section 4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvertisement {
    pub cur_hop_limit: u8,
    pub managed_flag: bool,
    pub other_flag: bool,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub source_link_addr: Option<MacAddr>,
    pub mtu: Option<u32>,
    pub prefixes: Vec<PrefixInformation>,
    pub rdnss: Vec<Ipv6Addr>,
    pub rdnss_lifetime: u32,
}

impl RouterAdvertisement {
    /// Parse from ICMPv6 body (after type/code/checksum)
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        // Minimum: 12 bytes (cur_hop_limit, flags, router_lifetime, reachable_time, retrans_timer)
        if buffer.len() < 12 {
            return Err(Error::Parse("Router Advertisement too short".into()));
        }

        let cur_hop_limit = buffer[0];
        let flags = buffer[1];
        let managed_flag = (flags & 0x80) != 0;
        let other_flag = (flags & 0x40) != 0;
        let router_lifetime = u16::from_be_bytes([buffer[2], buffer[3]]);
        let reachable_time = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let retrans_timer = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);

        // Parse options
        let options = &buffer[12..];
        let (source_link_addr, mtu, prefixes, rdnss, rdnss_lifetime) = parse_ra_options(options);

        Ok(Self {
            cur_hop_limit,
            managed_flag,
            other_flag,
            router_lifetime,
            reachable_time,
            retrans_timer,
            source_link_addr,
            mtu,
            prefixes,
            rdnss,
            rdnss_lifetime,
        })
    }

    /// Build RA message bytes (ICMPv6 payload, without IPv6 header)
    pub fn to_bytes(&self) -> Vec<u8> {
        // Calculate total size
        let slla_len = if self.source_link_addr.is_some() {
            8
        } else {
            0
        };
        let mtu_len = if self.mtu.is_some() { 8 } else { 0 };
        let prefix_len = self.prefixes.len() * PREFIX_INFO_SIZE;
        let rdnss_len = if self.rdnss.is_empty() {
            0
        } else {
            8 + self.rdnss.len() * 16
        };
        let total = 16 + slla_len + mtu_len + prefix_len + rdnss_len;

        let mut buf = vec![0u8; total];

        // Type
        buf[0] = Icmpv6Type::RouterAdvertisement as u8;
        // Code
        buf[1] = 0;
        // Checksum (placeholder)
        buf[2] = 0;
        buf[3] = 0;
        // Cur Hop Limit
        buf[4] = self.cur_hop_limit;
        // Flags
        let mut flags: u8 = 0;
        if self.managed_flag {
            flags |= 0x80;
        }
        if self.other_flag {
            flags |= 0x40;
        }
        buf[5] = flags;
        // Router Lifetime
        buf[6..8].copy_from_slice(&self.router_lifetime.to_be_bytes());
        // Reachable Time
        buf[8..12].copy_from_slice(&self.reachable_time.to_be_bytes());
        // Retrans Timer
        buf[12..16].copy_from_slice(&self.retrans_timer.to_be_bytes());

        let mut offset = 16;

        // Source Link-Layer Address option
        if let Some(mac) = &self.source_link_addr {
            buf[offset] = NdpOptionType::SourceLinkLayerAddress as u8;
            buf[offset + 1] = 1;
            buf[offset + 2..offset + 8].copy_from_slice(&mac.0);
            offset += 8;
        }

        // MTU option
        if let Some(mtu) = self.mtu {
            buf[offset] = NdpOptionType::Mtu as u8;
            buf[offset + 1] = 1;
            // Reserved 2 bytes (already zero)
            buf[offset + 4..offset + 8].copy_from_slice(&mtu.to_be_bytes());
            offset += 8;
        }

        // Prefix Information options
        for prefix in &self.prefixes {
            let prefix_bytes = prefix.to_bytes();
            buf[offset..offset + PREFIX_INFO_SIZE].copy_from_slice(&prefix_bytes);
            offset += PREFIX_INFO_SIZE;
        }

        // RDNSS option (RFC 8106)
        if !self.rdnss.is_empty() {
            buf[offset] = NdpOptionType::Rdnss as u8;
            let rdnss_opt_len = 1 + self.rdnss.len() * 2; // in 8-byte units
            buf[offset + 1] = rdnss_opt_len as u8;
            // Reserved 2 bytes (already zero)
            buf[offset + 4..offset + 8].copy_from_slice(&self.rdnss_lifetime.to_be_bytes());
            let mut addr_offset = offset + 8;
            for addr in &self.rdnss {
                buf[addr_offset..addr_offset + 16].copy_from_slice(&addr.octets());
                addr_offset += 16;
            }
        }

        buf
    }

    /// Create a new RA
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cur_hop_limit: u8,
        managed_flag: bool,
        other_flag: bool,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
    ) -> Self {
        Self {
            cur_hop_limit,
            managed_flag,
            other_flag,
            router_lifetime,
            reachable_time,
            retrans_timer,
            source_link_addr: None,
            mtu: None,
            prefixes: Vec::new(),
            rdnss: Vec::new(),
            rdnss_lifetime: 0,
        }
    }

    /// Set source link-layer address
    pub fn with_source_link_addr(mut self, mac: MacAddr) -> Self {
        self.source_link_addr = Some(mac);
        self
    }

    /// Set MTU
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Add a prefix
    pub fn with_prefix(mut self, prefix: PrefixInformation) -> Self {
        self.prefixes.push(prefix);
        self
    }

    /// Set RDNSS (DNS servers)
    pub fn with_rdnss(mut self, servers: Vec<Ipv6Addr>, lifetime: u32) -> Self {
        self.rdnss = servers;
        self.rdnss_lifetime = lifetime;
        self
    }
}

/// Parse RA options
fn parse_ra_options(
    options: &[u8],
) -> (
    Option<MacAddr>,
    Option<u32>,
    Vec<PrefixInformation>,
    Vec<Ipv6Addr>,
    u32,
) {
    let mut source_link_addr = None;
    let mut mtu = None;
    let mut prefixes = Vec::new();
    let mut rdnss = Vec::new();
    let mut rdnss_lifetime = 0u32;

    let mut offset = 0;
    while offset + 2 <= options.len() {
        let opt_type = options[offset];
        let opt_len = options[offset + 1] as usize * 8;

        if opt_len == 0 || offset + opt_len > options.len() {
            break;
        }

        match opt_type {
            1 => {
                // Source Link-Layer Address
                if opt_len >= 8 {
                    let mac_bytes: [u8; 6] = options[offset + 2..offset + 8].try_into().unwrap();
                    source_link_addr = Some(MacAddr(mac_bytes));
                }
            }
            5 => {
                // MTU
                if opt_len >= 8 {
                    mtu = Some(u32::from_be_bytes([
                        options[offset + 4],
                        options[offset + 5],
                        options[offset + 6],
                        options[offset + 7],
                    ]));
                }
            }
            3 => {
                // Prefix Information
                if opt_len >= PREFIX_INFO_SIZE {
                    if let Ok(prefix) = PrefixInformation::parse(&options[offset..offset + opt_len])
                    {
                        prefixes.push(prefix);
                    }
                }
            }
            25 => {
                // RDNSS (RFC 8106)
                if opt_len >= 24 {
                    rdnss_lifetime = u32::from_be_bytes([
                        options[offset + 4],
                        options[offset + 5],
                        options[offset + 6],
                        options[offset + 7],
                    ]);
                    // Each address is 16 bytes, starting at offset + 8
                    let num_addrs = (opt_len - 8) / 16;
                    for i in 0..num_addrs {
                        let addr_start = offset + 8 + i * 16;
                        let addr_bytes: [u8; 16] =
                            options[addr_start..addr_start + 16].try_into().unwrap();
                        rdnss.push(Ipv6Addr::from(addr_bytes));
                    }
                }
            }
            _ => {}
        }

        offset += opt_len;
    }

    (source_link_addr, mtu, prefixes, rdnss, rdnss_lifetime)
}

/// Parse link-layer address option from NDP options
fn parse_link_layer_option(options: &[u8], expected_type: NdpOptionType) -> Option<MacAddr> {
    let mut offset = 0;
    while offset + 2 <= options.len() {
        let opt_type = options[offset];
        let opt_len = options[offset + 1] as usize * 8; // Length in units of 8 bytes

        if opt_len == 0 {
            break; // Invalid length, stop parsing
        }

        if offset + opt_len > options.len() {
            break; // Truncated option
        }

        if opt_type == expected_type as u8 && opt_len >= 8 {
            // Link-layer address is at offset+2, 6 bytes for Ethernet
            let mac_bytes: [u8; 6] = options[offset + 2..offset + 8].try_into().ok()?;
            return Some(MacAddr(mac_bytes));
        }

        offset += opt_len;
    }
    None
}

/// Calculate ICMPv6 checksum with IPv6 pseudo-header
pub fn calculate_checksum(src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr, icmpv6_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address (16 bytes)
    for chunk in src_addr.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Pseudo-header: destination address (16 bytes)
    for chunk in dst_addr.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Pseudo-header: upper-layer packet length (4 bytes)
    let length = icmpv6_data.len() as u32;
    sum = sum.wrapping_add(length >> 16);
    sum = sum.wrapping_add(length & 0xFFFF);

    // Pseudo-header: next header (ICMPv6 = 58)
    sum = sum.wrapping_add(58);

    // ICMPv6 message (with checksum field zeroed)
    for i in (0..icmpv6_data.len()).step_by(2) {
        let word = if i + 1 < icmpv6_data.len() {
            // Skip checksum field (bytes 2-3)
            if i == 2 {
                0
            } else {
                u16::from_be_bytes([icmpv6_data[i], icmpv6_data[i + 1]])
            }
        } else {
            u16::from_be_bytes([icmpv6_data[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Set checksum in ICMPv6 message buffer
pub fn set_checksum(buffer: &mut [u8], src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr) {
    // Zero out checksum field first
    buffer[2] = 0;
    buffer[3] = 0;

    let checksum = calculate_checksum(src_addr, dst_addr, buffer);
    buffer[2..4].copy_from_slice(&checksum.to_be_bytes());
}

/// Validate ICMPv6 checksum
pub fn validate_checksum(src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr, icmpv6_data: &[u8]) -> bool {
    let mut sum: u32 = 0;

    // Pseudo-header: source address
    for chunk in src_addr.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Pseudo-header: destination address
    for chunk in dst_addr.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Pseudo-header: length
    let length = icmpv6_data.len() as u32;
    sum = sum.wrapping_add(length >> 16);
    sum = sum.wrapping_add(length & 0xFFFF);

    // Pseudo-header: next header
    sum = sum.wrapping_add(58);

    // ICMPv6 message (including checksum)
    for i in (0..icmpv6_data.len()).step_by(2) {
        let word = if i + 1 < icmpv6_data.len() {
            u16::from_be_bytes([icmpv6_data[i], icmpv6_data[i + 1]])
        } else {
            u16::from_be_bytes([icmpv6_data[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum == 0xFFFF
}

/// ICMPv6 Echo header size (type + code + checksum + identifier + sequence)
pub const ECHO_HEADER_SIZE: usize = 8;

/// Build an ICMPv6 Echo Reply from an Echo Request
///
/// Takes the raw ICMPv6 Echo Request bytes and returns Echo Reply bytes.
/// Checksum must be calculated separately with set_checksum().
pub fn build_echo_reply(request: &[u8]) -> Result<Vec<u8>> {
    if request.len() < ECHO_HEADER_SIZE {
        return Err(Error::Parse("ICMPv6 Echo Request too short".into()));
    }

    let mut reply = request.to_vec();

    // Change type from Echo Request (128) to Echo Reply (129)
    reply[0] = Icmpv6Type::EchoReply as u8;

    // Clear checksum field (will be recalculated with set_checksum)
    reply[2] = 0;
    reply[3] = 0;

    Ok(reply)
}

/// Build an ICMPv6 Destination Unreachable message (type 1)
///
/// # Arguments
/// * `code` - The unreachable code (see `dest_unreachable` module)
/// * `src_addr` - Source IPv6 address (for checksum calculation)
/// * `dst_addr` - Destination IPv6 address (for checksum calculation)
/// * `original_packet` - The original IPv6 packet that caused the error
///
/// Returns the complete ICMPv6 message with checksum set
pub fn build_destination_unreachable(
    code: u8,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    original_packet: &[u8],
) -> Vec<u8> {
    // ICMPv6 Destination Unreachable format:
    // Type (1) + Code (1) + Checksum (2) + Unused (4) + As much of invoking packet as possible
    // RFC 4443: should not exceed minimum IPv6 MTU (1280)
    let max_original = 1280 - 40 - 8; // MTU - IPv6 header - ICMPv6 header
    let original_len = original_packet.len().min(max_original);
    let total_len = 8 + original_len;
    let mut packet = vec![0u8; total_len];

    // Type: Destination Unreachable (1)
    packet[0] = Icmpv6Type::DestinationUnreachable as u8;
    // Code
    packet[1] = code;
    // Checksum: will be calculated later
    packet[2] = 0;
    packet[3] = 0;
    // Unused (4 bytes, already zero)

    // Copy original packet
    packet[8..8 + original_len].copy_from_slice(&original_packet[..original_len]);

    // Calculate and set checksum
    set_checksum(&mut packet, src_addr, dst_addr);

    packet
}

/// Build an ICMPv6 Packet Too Big message (type 2)
///
/// # Arguments
/// * `mtu` - The Maximum Transmission Unit of the next-hop link
/// * `src_addr` - Source IPv6 address (for checksum calculation)
/// * `dst_addr` - Destination IPv6 address (for checksum calculation)
/// * `original_packet` - The original IPv6 packet that caused the error
///
/// Returns the complete ICMPv6 message with checksum set
pub fn build_packet_too_big(
    mtu: u32,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    original_packet: &[u8],
) -> Vec<u8> {
    // ICMPv6 Packet Too Big format:
    // Type (1) + Code (1) + Checksum (2) + MTU (4) + As much of invoking packet as possible
    let max_original = 1280 - 40 - 8;
    let original_len = original_packet.len().min(max_original);
    let total_len = 8 + original_len;
    let mut packet = vec![0u8; total_len];

    // Type: Packet Too Big (2)
    packet[0] = Icmpv6Type::PacketTooBig as u8;
    // Code: 0
    packet[1] = 0;
    // Checksum: will be calculated later
    packet[2] = 0;
    packet[3] = 0;
    // MTU (4 bytes)
    packet[4..8].copy_from_slice(&mtu.to_be_bytes());

    // Copy original packet
    packet[8..8 + original_len].copy_from_slice(&original_packet[..original_len]);

    // Calculate and set checksum
    set_checksum(&mut packet, src_addr, dst_addr);

    packet
}

/// Build an ICMPv6 Time Exceeded message (type 3)
///
/// # Arguments
/// * `code` - The time exceeded code (see `time_exceeded` module)
/// * `src_addr` - Source IPv6 address (for checksum calculation)
/// * `dst_addr` - Destination IPv6 address (for checksum calculation)
/// * `original_packet` - The original IPv6 packet that caused the error
///
/// Returns the complete ICMPv6 message with checksum set
pub fn build_time_exceeded(
    code: u8,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    original_packet: &[u8],
) -> Vec<u8> {
    // ICMPv6 Time Exceeded format:
    // Type (1) + Code (1) + Checksum (2) + Unused (4) + As much of invoking packet as possible
    let max_original = 1280 - 40 - 8;
    let original_len = original_packet.len().min(max_original);
    let total_len = 8 + original_len;
    let mut packet = vec![0u8; total_len];

    // Type: Time Exceeded (3)
    packet[0] = Icmpv6Type::TimeExceeded as u8;
    // Code
    packet[1] = code;
    // Checksum: will be calculated later
    packet[2] = 0;
    packet[3] = 0;
    // Unused (4 bytes, already zero)

    // Copy original packet
    packet[8..8 + original_len].copy_from_slice(&original_packet[..original_len]);

    // Calculate and set checksum
    set_checksum(&mut packet, src_addr, dst_addr);

    packet
}

/// Build an ICMPv6 Parameter Problem message (type 4)
///
/// # Arguments
/// * `code` - The parameter problem code (see `parameter_problem` module)
/// * `pointer` - Byte offset in the original packet where the error was detected
/// * `src_addr` - Source IPv6 address (for checksum calculation)
/// * `dst_addr` - Destination IPv6 address (for checksum calculation)
/// * `original_packet` - The original IPv6 packet that caused the error
///
/// Returns the complete ICMPv6 message with checksum set
pub fn build_parameter_problem(
    code: u8,
    pointer: u32,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    original_packet: &[u8],
) -> Vec<u8> {
    // ICMPv6 Parameter Problem format:
    // Type (1) + Code (1) + Checksum (2) + Pointer (4) + As much of invoking packet as possible
    let max_original = 1280 - 40 - 8;
    let original_len = original_packet.len().min(max_original);
    let total_len = 8 + original_len;
    let mut packet = vec![0u8; total_len];

    // Type: Parameter Problem (4)
    packet[0] = Icmpv6Type::ParameterProblem as u8;
    // Code
    packet[1] = code;
    // Checksum: will be calculated later
    packet[2] = 0;
    packet[3] = 0;
    // Pointer (4 bytes)
    packet[4..8].copy_from_slice(&pointer.to_be_bytes());

    // Copy original packet
    packet[8..8 + original_len].copy_from_slice(&original_packet[..original_len]);

    // Calculate and set checksum
    set_checksum(&mut packet, src_addr, dst_addr);

    packet
}

/// Builder for ICMPv6 Echo Request packets
#[derive(Debug, Clone)]
pub struct EchoRequestBuilder {
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

impl EchoRequestBuilder {
    /// Create a new Echo Request builder
    pub fn new(identifier: u16, sequence: u16) -> Self {
        Self {
            identifier,
            sequence,
            payload: Vec::new(),
        }
    }

    /// Set the payload data
    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    /// Build the ICMPv6 Echo Request packet (without checksum)
    ///
    /// Call set_checksum() on the result to set the checksum
    pub fn build(self) -> Vec<u8> {
        let total_len = ECHO_HEADER_SIZE + self.payload.len();
        let mut packet = vec![0u8; total_len];

        // Type: Echo Request (128)
        packet[0] = Icmpv6Type::EchoRequest as u8;
        // Code: 0
        packet[1] = 0;
        // Checksum: placeholder (will be set by set_checksum)
        packet[2] = 0;
        packet[3] = 0;
        // Identifier
        packet[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        // Sequence number
        packet[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        // Payload
        packet[8..].copy_from_slice(&self.payload);

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ns_packet() -> Vec<u8> {
        // Neighbor Solicitation for 2001:db8::1 with source link-layer address
        vec![
            0x87, // Type: NS (135)
            0x00, // Code: 0
            0x00, 0x00, // Checksum (placeholder)
            0x00, 0x00, 0x00, 0x00, // Reserved
            // Target: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Option: Source Link-Layer Address
            0x01, // Type: 1
            0x01, // Length: 1 (8 bytes)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC
        ]
    }

    fn make_na_packet() -> Vec<u8> {
        // Neighbor Advertisement for 2001:db8::1 with flags R=0, S=1, O=1
        vec![
            0x88, // Type: NA (136)
            0x00, // Code: 0
            0x00, 0x00, // Checksum (placeholder)
            0x60, // Flags: S=1, O=1 (0b01100000)
            0x00, 0x00, 0x00, // Reserved
            // Target: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Option: Target Link-Layer Address
            0x02, // Type: 2
            0x01, // Length: 1 (8 bytes)
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // MAC
        ]
    }

    // Icmpv6Type tests
    #[test]
    fn test_icmpv6_type_from_u8() {
        assert_eq!(
            Icmpv6Type::from_u8(1),
            Some(Icmpv6Type::DestinationUnreachable)
        );
        assert_eq!(Icmpv6Type::from_u8(128), Some(Icmpv6Type::EchoRequest));
        assert_eq!(Icmpv6Type::from_u8(129), Some(Icmpv6Type::EchoReply));
        assert_eq!(
            Icmpv6Type::from_u8(135),
            Some(Icmpv6Type::NeighborSolicitation)
        );
        assert_eq!(
            Icmpv6Type::from_u8(136),
            Some(Icmpv6Type::NeighborAdvertisement)
        );
        assert_eq!(Icmpv6Type::from_u8(255), None);
    }

    // NdpOptionType tests
    #[test]
    fn test_ndp_option_type_from_u8() {
        assert_eq!(
            NdpOptionType::from_u8(1),
            Some(NdpOptionType::SourceLinkLayerAddress)
        );
        assert_eq!(
            NdpOptionType::from_u8(2),
            Some(NdpOptionType::TargetLinkLayerAddress)
        );
        assert_eq!(
            NdpOptionType::from_u8(3),
            Some(NdpOptionType::PrefixInformation)
        );
        assert_eq!(NdpOptionType::from_u8(99), None);
    }

    // Icmpv6Packet tests
    #[test]
    fn test_icmpv6_parse() {
        let data = make_ns_packet();
        let pkt = Icmpv6Packet::parse(&data).unwrap();

        assert_eq!(pkt.msg_type(), 135);
        assert_eq!(pkt.code(), 0);
        assert_eq!(pkt.body().len(), 28); // 32 - 4
    }

    #[test]
    fn test_icmpv6_parse_too_short() {
        let short = vec![0u8; 3];
        assert!(Icmpv6Packet::parse(&short).is_err());
    }

    // NeighborSolicitation tests
    #[test]
    fn test_ns_parse() {
        let data = make_ns_packet();
        let ns = NeighborSolicitation::parse(&data[4..]).unwrap(); // Skip ICMPv6 header

        assert_eq!(ns.target_addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            ns.source_link_addr,
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
    }

    #[test]
    fn test_ns_parse_no_option() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // Reserved
            // Target: ::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let ns = NeighborSolicitation::parse(&data).unwrap();

        assert_eq!(ns.target_addr, "::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ns.source_link_addr, None);
    }

    #[test]
    fn test_ns_parse_too_short() {
        let short = vec![0u8; 19];
        assert!(NeighborSolicitation::parse(&short).is_err());
    }

    #[test]
    fn test_ns_to_bytes() {
        let ns = NeighborSolicitation::new(
            "2001:db8::1".parse().unwrap(),
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        );

        let bytes = ns.to_bytes();
        assert_eq!(bytes[0], 135); // Type
        assert_eq!(bytes[1], 0); // Code
        assert_eq!(
            &bytes[8..24],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(bytes[24], 1); // Option type
        assert_eq!(bytes[25], 1); // Option length
        assert_eq!(&bytes[26..32], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_ns_roundtrip() {
        let original = NeighborSolicitation::new(
            "fe80::1".parse().unwrap(),
            Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
        );

        let bytes = original.to_bytes();
        let parsed = NeighborSolicitation::parse(&bytes[4..]).unwrap(); // Skip header

        assert_eq!(parsed.target_addr, original.target_addr);
        assert_eq!(parsed.source_link_addr, original.source_link_addr);
    }

    // NeighborAdvertisement tests
    #[test]
    fn test_na_parse() {
        let data = make_na_packet();
        let na = NeighborAdvertisement::parse(&data[4..]).unwrap(); // Skip ICMPv6 header

        assert!(!na.router_flag);
        assert!(na.solicited_flag);
        assert!(na.override_flag);
        assert_eq!(na.target_addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            na.target_link_addr,
            Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        );
    }

    #[test]
    fn test_na_parse_router_flag() {
        let mut data = make_na_packet();
        data[4] = 0xE0; // R=1, S=1, O=1
        let na = NeighborAdvertisement::parse(&data[4..]).unwrap();

        assert!(na.router_flag);
        assert!(na.solicited_flag);
        assert!(na.override_flag);
    }

    #[test]
    fn test_na_parse_too_short() {
        let short = vec![0u8; 19];
        assert!(NeighborAdvertisement::parse(&short).is_err());
    }

    #[test]
    fn test_na_to_bytes() {
        let na = NeighborAdvertisement::new(
            "2001:db8::1".parse().unwrap(),
            Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            true,  // router
            true,  // solicited
            false, // override
        );

        let bytes = na.to_bytes();
        assert_eq!(bytes[0], 136); // Type
        assert_eq!(bytes[1], 0); // Code
        assert_eq!(bytes[4], 0xC0); // Flags: R=1, S=1, O=0
        assert_eq!(
            &bytes[8..24],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(bytes[24], 2); // Option type
    }

    #[test]
    fn test_na_solicited_reply() {
        let na = NeighborAdvertisement::solicited_reply(
            "fe80::1".parse().unwrap(),
            MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        );

        assert!(!na.router_flag);
        assert!(na.solicited_flag);
        assert!(na.override_flag);
        assert_eq!(na.target_addr, "fe80::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            na.target_link_addr,
            Some(MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]))
        );
    }

    #[test]
    fn test_na_roundtrip() {
        let original = NeighborAdvertisement::new(
            "2001:db8::abcd".parse().unwrap(),
            Some(MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])),
            true,
            false,
            true,
        );

        let bytes = original.to_bytes();
        let parsed = NeighborAdvertisement::parse(&bytes[4..]).unwrap();

        assert_eq!(parsed.router_flag, original.router_flag);
        assert_eq!(parsed.solicited_flag, original.solicited_flag);
        assert_eq!(parsed.override_flag, original.override_flag);
        assert_eq!(parsed.target_addr, original.target_addr);
        assert_eq!(parsed.target_link_addr, original.target_link_addr);
    }

    // Checksum tests
    #[test]
    fn test_checksum_calculation() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();

        let ns = NeighborSolicitation::new(
            "fe80::2".parse().unwrap(),
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        );
        let mut bytes = ns.to_bytes();

        set_checksum(&mut bytes, &src, &dst);

        // Verify checksum is valid
        assert!(validate_checksum(&src, &dst, &bytes));
    }

    #[test]
    fn test_checksum_invalid() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();

        let ns = NeighborSolicitation::new("fe80::2".parse().unwrap(), None);
        let mut bytes = ns.to_bytes();

        set_checksum(&mut bytes, &src, &dst);

        // Corrupt the checksum
        bytes[2] ^= 0xFF;

        assert!(!validate_checksum(&src, &dst, &bytes));
    }

    #[test]
    fn test_checksum_different_addresses() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let na = NeighborAdvertisement::solicited_reply(
            "2001:db8::1".parse().unwrap(),
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );
        let mut bytes = na.to_bytes();

        set_checksum(&mut bytes, &src, &dst);

        // Valid with correct addresses
        assert!(validate_checksum(&src, &dst, &bytes));

        // Invalid with wrong source
        let wrong_src: Ipv6Addr = "2001:db8::99".parse().unwrap();
        assert!(!validate_checksum(&wrong_src, &dst, &bytes));
    }

    // Option parsing edge cases
    #[test]
    fn test_parse_option_zero_length() {
        // Option with length 0 should stop parsing
        let options = vec![
            0x01, 0x00, // Type 1, Length 0 (invalid)
            0x02, 0x01, // Type 2, Length 1
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let result = parse_link_layer_option(&options, NdpOptionType::TargetLinkLayerAddress);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_option_truncated() {
        // Option claims length but data is truncated
        let options = vec![
            0x01, 0x02, // Type 1, Length 2 (16 bytes)
            0x00, 0x11, 0x22, 0x33, // Only 4 bytes of data
        ];
        let result = parse_link_layer_option(&options, NdpOptionType::SourceLinkLayerAddress);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_multiple_options() {
        // Multiple options, target one is second
        let options = vec![
            // First option: MTU (type 5)
            0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDC, // MTU = 1500
            // Second option: Target Link-Layer Address
            0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ];
        let result = parse_link_layer_option(&options, NdpOptionType::TargetLinkLayerAddress);
        assert_eq!(result, Some(MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])));
    }

    // ==================== Code constants tests ====================

    #[test]
    fn test_dest_unreachable_codes() {
        assert_eq!(dest_unreachable::NO_ROUTE, 0);
        assert_eq!(dest_unreachable::ADMIN_PROHIBITED, 1);
        assert_eq!(dest_unreachable::BEYOND_SCOPE, 2);
        assert_eq!(dest_unreachable::ADDRESS_UNREACHABLE, 3);
        assert_eq!(dest_unreachable::PORT_UNREACHABLE, 4);
        assert_eq!(dest_unreachable::FAILED_POLICY, 5);
        assert_eq!(dest_unreachable::REJECT_ROUTE, 6);
    }

    #[test]
    fn test_time_exceeded_codes() {
        assert_eq!(time_exceeded::HOP_LIMIT_EXCEEDED, 0);
        assert_eq!(time_exceeded::FRAGMENT_REASSEMBLY, 1);
    }

    #[test]
    fn test_parameter_problem_codes() {
        assert_eq!(parameter_problem::ERRONEOUS_HEADER, 0);
        assert_eq!(parameter_problem::UNRECOGNIZED_NEXT_HEADER, 1);
        assert_eq!(parameter_problem::UNRECOGNIZED_OPTION, 2);
    }

    // ==================== Icmpv6Packet helper methods tests ====================

    fn make_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 8 + payload.len()];
        packet[0] = Icmpv6Type::EchoRequest as u8;
        packet[1] = 0;
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        packet[8..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn test_icmpv6_packet_identifier() {
        let data = make_echo_request(0x1234, 0x0001, b"hello");
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert_eq!(pkt.identifier(), 0x1234);
    }

    #[test]
    fn test_icmpv6_packet_sequence() {
        let data = make_echo_request(0x1234, 0x5678, b"test");
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert_eq!(pkt.sequence(), 0x5678);
    }

    #[test]
    fn test_icmpv6_packet_payload() {
        let data = make_echo_request(0x1234, 0x0001, b"payload");
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert_eq!(pkt.payload(), b"payload");
    }

    #[test]
    fn test_icmpv6_packet_mtu() {
        // Packet Too Big with MTU = 1280
        let mut data = vec![0u8; 8];
        data[0] = Icmpv6Type::PacketTooBig as u8;
        data[4..8].copy_from_slice(&1280u32.to_be_bytes());
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert_eq!(pkt.mtu(), 1280);
    }

    #[test]
    fn test_icmpv6_packet_is_echo_request() {
        let data = make_echo_request(0, 0, &[]);
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert!(pkt.is_echo_request());
        assert!(!pkt.is_echo_reply());
    }

    #[test]
    fn test_icmpv6_packet_is_echo_reply() {
        let mut data = make_echo_request(0, 0, &[]);
        data[0] = Icmpv6Type::EchoReply as u8;
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert!(pkt.is_echo_reply());
        assert!(!pkt.is_echo_request());
    }

    #[test]
    fn test_icmpv6_packet_is_error() {
        // Error messages (type < 128)
        let mut data = vec![0u8; 8];
        data[0] = Icmpv6Type::DestinationUnreachable as u8;
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert!(pkt.is_error());

        // Informational messages (type >= 128)
        data[0] = Icmpv6Type::EchoRequest as u8;
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert!(!pkt.is_error());
    }

    #[test]
    fn test_icmpv6_packet_message_type() {
        let data = make_echo_request(0, 0, &[]);
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert_eq!(pkt.message_type(), Some(Icmpv6Type::EchoRequest));
    }

    // ==================== Echo Request/Reply tests ====================

    #[test]
    fn test_echo_request_builder_basic() {
        let packet = EchoRequestBuilder::new(0x1234, 0x0001).build();

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.msg_type(), Icmpv6Type::EchoRequest as u8);
        assert_eq!(parsed.code(), 0);
        assert_eq!(parsed.identifier(), 0x1234);
        assert_eq!(parsed.sequence(), 0x0001);
        assert!(parsed.payload().is_empty());
    }

    #[test]
    fn test_echo_request_builder_with_payload() {
        let payload = b"ping test data";
        let packet = EchoRequestBuilder::new(0xABCD, 0x0005)
            .payload(payload)
            .build();

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.identifier(), 0xABCD);
        assert_eq!(parsed.sequence(), 0x0005);
        assert_eq!(parsed.payload(), payload);
    }

    #[test]
    fn test_echo_request_builder_with_checksum() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();

        let mut packet = EchoRequestBuilder::new(0x1234, 0x0001)
            .payload(b"test")
            .build();
        set_checksum(&mut packet, &src, &dst);

        assert!(validate_checksum(&src, &dst, &packet));
    }

    #[test]
    fn test_build_echo_reply() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();

        let mut request = EchoRequestBuilder::new(0x1234, 0x0001)
            .payload(b"hello")
            .build();
        set_checksum(&mut request, &src, &dst);

        let mut reply = build_echo_reply(&request).unwrap();
        // Set checksum with swapped addresses (reply goes back)
        set_checksum(&mut reply, &dst, &src);

        let parsed = Icmpv6Packet::parse(&reply).unwrap();
        assert_eq!(parsed.msg_type(), Icmpv6Type::EchoReply as u8);
        assert_eq!(parsed.identifier(), 0x1234);
        assert_eq!(parsed.sequence(), 0x0001);
        assert_eq!(parsed.payload(), b"hello");
        assert!(validate_checksum(&dst, &src, &reply));
    }

    #[test]
    fn test_build_echo_reply_too_short() {
        let short = vec![0u8; 7];
        assert!(build_echo_reply(&short).is_err());
    }

    #[test]
    fn test_echo_roundtrip() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let mut request = EchoRequestBuilder::new(0x5678, 0x000A)
            .payload(b"roundtrip test")
            .build();
        set_checksum(&mut request, &src, &dst);

        let mut reply = build_echo_reply(&request).unwrap();
        set_checksum(&mut reply, &dst, &src);

        let parsed_reply = Icmpv6Packet::parse(&reply).unwrap();
        assert!(parsed_reply.is_echo_reply());
        assert_eq!(parsed_reply.identifier(), 0x5678);
        assert_eq!(parsed_reply.sequence(), 0x000A);
        assert_eq!(parsed_reply.payload(), b"roundtrip test");
        assert!(validate_checksum(&dst, &src, &reply));
    }

    // ==================== Destination Unreachable tests ====================

    fn make_ipv6_packet() -> Vec<u8> {
        // Minimal IPv6 header (40 bytes) + 8 bytes payload
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60; // Version 6
        packet[4] = 0; // Payload length high
        packet[5] = 8; // Payload length low
        packet[6] = 58; // Next header: ICMPv6
        packet[7] = 64; // Hop limit
                        // Source: 2001:db8::1
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        // Dest: 2001:db8::2
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        // Payload
        packet[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        packet
    }

    #[test]
    fn test_build_destination_unreachable_no_route() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        let original = make_ipv6_packet();

        let packet =
            build_destination_unreachable(dest_unreachable::NO_ROUTE, &src, &dst, &original);

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.msg_type(), Icmpv6Type::DestinationUnreachable as u8);
        assert_eq!(parsed.code(), dest_unreachable::NO_ROUTE);
        assert!(parsed.is_error());
        assert!(validate_checksum(&src, &dst, &packet));

        // Check original packet is included
        assert_eq!(parsed.original_packet(), &original[..]);
    }

    #[test]
    fn test_build_destination_unreachable_port() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let original = make_ipv6_packet();

        let packet = build_destination_unreachable(
            dest_unreachable::PORT_UNREACHABLE,
            &src,
            &dst,
            &original,
        );

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.code(), dest_unreachable::PORT_UNREACHABLE);
        assert!(validate_checksum(&src, &dst, &packet));
    }

    #[test]
    fn test_build_destination_unreachable_truncates_large_original() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        let original = vec![0u8; 2000]; // Large packet

        let packet =
            build_destination_unreachable(dest_unreachable::NO_ROUTE, &src, &dst, &original);

        // Max size: 1280 - 40 - 8 = 1232 bytes of original
        assert_eq!(packet.len(), 8 + 1232);
        assert!(validate_checksum(&src, &dst, &packet));
    }

    // ==================== Packet Too Big tests ====================

    #[test]
    fn test_build_packet_too_big() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        let original = make_ipv6_packet();
        let mtu = 1280u32;

        let packet = build_packet_too_big(mtu, &src, &dst, &original);

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.msg_type(), Icmpv6Type::PacketTooBig as u8);
        assert_eq!(parsed.code(), 0); // Always 0 for Packet Too Big
        assert_eq!(parsed.mtu(), mtu);
        assert!(parsed.is_error());
        assert!(validate_checksum(&src, &dst, &packet));
    }

    #[test]
    fn test_build_packet_too_big_with_different_mtu() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let original = vec![0u8; 40];

        let packet = build_packet_too_big(1500, &src, &dst, &original);

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.mtu(), 1500);
        assert!(validate_checksum(&src, &dst, &packet));
    }

    // ==================== Time Exceeded tests ====================

    #[test]
    fn test_build_time_exceeded_hop_limit() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        let original = make_ipv6_packet();

        let packet = build_time_exceeded(time_exceeded::HOP_LIMIT_EXCEEDED, &src, &dst, &original);

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.msg_type(), Icmpv6Type::TimeExceeded as u8);
        assert_eq!(parsed.code(), time_exceeded::HOP_LIMIT_EXCEEDED);
        assert!(parsed.is_error());
        assert!(validate_checksum(&src, &dst, &packet));
    }

    #[test]
    fn test_build_time_exceeded_fragment_reassembly() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let original = make_ipv6_packet();

        let packet = build_time_exceeded(time_exceeded::FRAGMENT_REASSEMBLY, &src, &dst, &original);

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.code(), time_exceeded::FRAGMENT_REASSEMBLY);
        assert!(validate_checksum(&src, &dst, &packet));
    }

    // ==================== Parameter Problem tests ====================

    #[test]
    fn test_build_parameter_problem_erroneous_header() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        let original = make_ipv6_packet();
        let pointer = 6u32; // Pointing to next header field

        let packet = build_parameter_problem(
            parameter_problem::ERRONEOUS_HEADER,
            pointer,
            &src,
            &dst,
            &original,
        );

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.msg_type(), Icmpv6Type::ParameterProblem as u8);
        assert_eq!(parsed.code(), parameter_problem::ERRONEOUS_HEADER);
        assert!(parsed.is_error());
        assert!(validate_checksum(&src, &dst, &packet));

        // Check pointer (stored in MTU field position for Parameter Problem)
        let raw = parsed.as_bytes();
        let stored_pointer = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        assert_eq!(stored_pointer, pointer);
    }

    #[test]
    fn test_build_parameter_problem_unrecognized_next_header() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let original = make_ipv6_packet();

        let packet = build_parameter_problem(
            parameter_problem::UNRECOGNIZED_NEXT_HEADER,
            40,
            &src,
            &dst,
            &original,
        );

        let parsed = Icmpv6Packet::parse(&packet).unwrap();
        assert_eq!(parsed.code(), parameter_problem::UNRECOGNIZED_NEXT_HEADER);
        assert!(validate_checksum(&src, &dst, &packet));
    }

    // ==================== Edge cases ====================

    #[test]
    fn test_empty_original_packet() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        let original: [u8; 0] = [];

        let packet = build_time_exceeded(time_exceeded::HOP_LIMIT_EXCEEDED, &src, &dst, &original);

        assert_eq!(packet.len(), 8); // Just the ICMPv6 header
        assert!(validate_checksum(&src, &dst, &packet));
    }

    #[test]
    fn test_large_payload_echo() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        let payload = vec![0xAA; 1000];

        let mut request = EchoRequestBuilder::new(1, 1).payload(&payload).build();
        set_checksum(&mut request, &src, &dst);

        let parsed = Icmpv6Packet::parse(&request).unwrap();
        assert_eq!(parsed.payload().len(), 1000);
        assert!(validate_checksum(&src, &dst, &request));
    }

    // ==================== Router Solicitation tests ====================

    #[test]
    fn test_rs_parse_minimal() {
        // Minimal RS: 4 reserved bytes only
        let data = vec![0u8; 4];
        let rs = RouterSolicitation::parse(&data).unwrap();
        assert!(rs.source_link_addr.is_none());
    }

    #[test]
    fn test_rs_parse_with_slla() {
        // RS with Source Link-Layer Address option
        let mut data = vec![0u8; 12];
        // Reserved 4 bytes, already zero
        // SLLA option
        data[4] = 1; // Type
        data[5] = 1; // Length
        data[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let rs = RouterSolicitation::parse(&data).unwrap();
        assert_eq!(
            rs.source_link_addr,
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
    }

    #[test]
    fn test_rs_parse_too_short() {
        let short = vec![0u8; 3];
        assert!(RouterSolicitation::parse(&short).is_err());
    }

    #[test]
    fn test_rs_to_bytes_minimal() {
        let rs = RouterSolicitation::new(None);
        let bytes = rs.to_bytes();

        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], Icmpv6Type::RouterSolicitation as u8);
        assert_eq!(bytes[1], 0);
    }

    #[test]
    fn test_rs_to_bytes_with_slla() {
        let rs = RouterSolicitation::new(Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])));
        let bytes = rs.to_bytes();

        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], Icmpv6Type::RouterSolicitation as u8);
        assert_eq!(bytes[8], 1); // SLLA type
        assert_eq!(bytes[9], 1); // Length
        assert_eq!(&bytes[10..16], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_rs_roundtrip() {
        let original = RouterSolicitation::new(Some(MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])));
        let bytes = original.to_bytes();
        let parsed = RouterSolicitation::parse(&bytes[4..]).unwrap(); // Skip ICMPv6 header

        assert_eq!(parsed.source_link_addr, original.source_link_addr);
    }

    // ==================== Router Advertisement tests ====================

    #[test]
    fn test_ra_parse_minimal() {
        // Minimal RA: 12 bytes (cur_hop_limit, flags, router_lifetime, reachable_time, retrans_timer)
        let mut data = vec![0u8; 12];
        data[0] = 64; // cur_hop_limit
        data[1] = 0xC0; // M=1, O=1
        data[2..4].copy_from_slice(&1800u16.to_be_bytes()); // router_lifetime
        data[4..8].copy_from_slice(&30000u32.to_be_bytes()); // reachable_time
        data[8..12].copy_from_slice(&1000u32.to_be_bytes()); // retrans_timer

        let ra = RouterAdvertisement::parse(&data).unwrap();

        assert_eq!(ra.cur_hop_limit, 64);
        assert!(ra.managed_flag);
        assert!(ra.other_flag);
        assert_eq!(ra.router_lifetime, 1800);
        assert_eq!(ra.reachable_time, 30000);
        assert_eq!(ra.retrans_timer, 1000);
        assert!(ra.source_link_addr.is_none());
        assert!(ra.mtu.is_none());
        assert!(ra.prefixes.is_empty());
        assert!(ra.rdnss.is_empty());
    }

    #[test]
    fn test_ra_parse_with_options() {
        let mut data = vec![0u8; 12 + 8 + 8 + 32]; // header + SLLA + MTU + Prefix

        // Header
        data[0] = 64;
        data[1] = 0x40; // O=1

        // SLLA option
        data[12] = 1; // Type
        data[13] = 1; // Length
        data[14..20].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // MTU option
        data[20] = 5; // Type
        data[21] = 1; // Length
        data[24..28].copy_from_slice(&1500u32.to_be_bytes());

        // Prefix Information
        data[28] = 3; // Type
        data[29] = 4; // Length (32 bytes / 8)
        data[30] = 64; // Prefix length
        data[31] = 0xC0; // L=1, A=1
        data[32..36].copy_from_slice(&2592000u32.to_be_bytes()); // Valid lifetime
        data[36..40].copy_from_slice(&604800u32.to_be_bytes()); // Preferred lifetime
                                                                // Reserved 4 bytes (40-43)
        data[44..60].copy_from_slice(&"2001:db8::".parse::<Ipv6Addr>().unwrap().octets());

        let ra = RouterAdvertisement::parse(&data).unwrap();

        assert_eq!(
            ra.source_link_addr,
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(ra.mtu, Some(1500));
        assert_eq!(ra.prefixes.len(), 1);
        assert_eq!(ra.prefixes[0].prefix_length, 64);
        assert!(ra.prefixes[0].on_link_flag);
        assert!(ra.prefixes[0].autonomous_flag);
    }

    #[test]
    fn test_ra_parse_with_rdnss() {
        let mut data = vec![0u8; 12 + 24]; // header + RDNSS with 1 address

        // Header
        data[0] = 64;

        // RDNSS option
        data[12] = 25; // Type
        data[13] = 3; // Length (24 bytes / 8)
        data[16..20].copy_from_slice(&3600u32.to_be_bytes()); // Lifetime
        data[20..36].copy_from_slice(&"2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap().octets());

        let ra = RouterAdvertisement::parse(&data).unwrap();

        assert_eq!(ra.rdnss.len(), 1);
        assert_eq!(
            ra.rdnss[0],
            "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(ra.rdnss_lifetime, 3600);
    }

    #[test]
    fn test_ra_parse_too_short() {
        let short = vec![0u8; 11];
        assert!(RouterAdvertisement::parse(&short).is_err());
    }

    #[test]
    fn test_ra_to_bytes_minimal() {
        let ra = RouterAdvertisement::new(64, false, true, 1800, 0, 0);
        let bytes = ra.to_bytes();

        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], Icmpv6Type::RouterAdvertisement as u8);
        assert_eq!(bytes[1], 0); // Code
        assert_eq!(bytes[4], 64); // cur_hop_limit
        assert_eq!(bytes[5], 0x40); // O=1
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1800);
    }

    #[test]
    fn test_ra_to_bytes_full() {
        let prefix = PrefixInformation::new(
            "2001:db8::".parse().unwrap(),
            64,
            true,
            true,
            2592000,
            604800,
        );

        let ra = RouterAdvertisement::new(64, true, true, 1800, 30000, 1000)
            .with_source_link_addr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
            .with_mtu(1500)
            .with_prefix(prefix)
            .with_rdnss(vec!["2001:4860:4860::8888".parse().unwrap()], 3600);

        let bytes = ra.to_bytes();

        // 16 (header) + 8 (SLLA) + 8 (MTU) + 32 (prefix) + 24 (RDNSS)
        assert_eq!(bytes.len(), 88);
        assert_eq!(bytes[0], Icmpv6Type::RouterAdvertisement as u8);
        assert_eq!(bytes[5], 0xC0); // M=1, O=1
    }

    #[test]
    fn test_ra_roundtrip() {
        let prefix = PrefixInformation::new(
            "2001:db8:1::".parse().unwrap(),
            64,
            true,
            true,
            2592000,
            604800,
        );

        let original = RouterAdvertisement::new(64, false, true, 1800, 30000, 1000)
            .with_source_link_addr(MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]))
            .with_mtu(1280)
            .with_prefix(prefix);

        let bytes = original.to_bytes();
        let parsed = RouterAdvertisement::parse(&bytes[4..]).unwrap(); // Skip ICMPv6 header

        assert_eq!(parsed.cur_hop_limit, original.cur_hop_limit);
        assert_eq!(parsed.managed_flag, original.managed_flag);
        assert_eq!(parsed.other_flag, original.other_flag);
        assert_eq!(parsed.router_lifetime, original.router_lifetime);
        assert_eq!(parsed.source_link_addr, original.source_link_addr);
        assert_eq!(parsed.mtu, original.mtu);
        assert_eq!(parsed.prefixes.len(), 1);
        assert_eq!(parsed.prefixes[0].prefix_length, 64);
    }

    // ==================== Prefix Information tests ====================

    #[test]
    fn test_prefix_info_parse() {
        let mut data = vec![0u8; 32];
        data[0] = 3; // Type
        data[1] = 4; // Length
        data[2] = 64; // Prefix length
        data[3] = 0xC0; // L=1, A=1
        data[4..8].copy_from_slice(&2592000u32.to_be_bytes());
        data[8..12].copy_from_slice(&604800u32.to_be_bytes());
        data[16..32].copy_from_slice(&"2001:db8::".parse::<Ipv6Addr>().unwrap().octets());

        let prefix = PrefixInformation::parse(&data).unwrap();

        assert_eq!(prefix.prefix_length, 64);
        assert!(prefix.on_link_flag);
        assert!(prefix.autonomous_flag);
        assert_eq!(prefix.valid_lifetime, 2592000);
        assert_eq!(prefix.preferred_lifetime, 604800);
        assert_eq!(prefix.prefix, "2001:db8::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_prefix_info_to_bytes() {
        let prefix = PrefixInformation::new(
            "2001:db8:abcd::".parse().unwrap(),
            48,
            true,
            false,
            1000000,
            500000,
        );

        let bytes = prefix.to_bytes();

        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 3); // Type
        assert_eq!(bytes[1], 4); // Length
        assert_eq!(bytes[2], 48); // Prefix length
        assert_eq!(bytes[3], 0x80); // L=1, A=0
    }

    #[test]
    fn test_prefix_info_roundtrip() {
        let original = PrefixInformation::new(
            "fd00:1234::".parse().unwrap(),
            64,
            false,
            true,
            86400,
            43200,
        );

        let bytes = original.to_bytes();
        let parsed = PrefixInformation::parse(&bytes).unwrap();

        assert_eq!(parsed.prefix_length, original.prefix_length);
        assert_eq!(parsed.on_link_flag, original.on_link_flag);
        assert_eq!(parsed.autonomous_flag, original.autonomous_flag);
        assert_eq!(parsed.valid_lifetime, original.valid_lifetime);
        assert_eq!(parsed.preferred_lifetime, original.preferred_lifetime);
        assert_eq!(parsed.prefix, original.prefix);
    }

    #[test]
    fn test_prefix_info_parse_too_short() {
        let short = vec![0u8; 31];
        assert!(PrefixInformation::parse(&short).is_err());
    }

    #[test]
    fn test_prefix_info_parse_invalid_type() {
        let mut data = vec![0u8; 32];
        data[0] = 4; // Wrong type
        data[1] = 4;
        assert!(PrefixInformation::parse(&data).is_err());
    }

    // ==================== RS/RA checksum tests ====================

    #[test]
    fn test_rs_checksum() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::2".parse().unwrap(); // All-routers

        let rs = RouterSolicitation::new(Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])));
        let mut bytes = rs.to_bytes();
        set_checksum(&mut bytes, &src, &dst);

        assert!(validate_checksum(&src, &dst, &bytes));
    }

    #[test]
    fn test_ra_checksum() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1".parse().unwrap(); // All-nodes

        let ra = RouterAdvertisement::new(64, false, false, 1800, 0, 0)
            .with_source_link_addr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        let mut bytes = ra.to_bytes();
        set_checksum(&mut bytes, &src, &dst);

        assert!(validate_checksum(&src, &dst, &bytes));
    }
}

//! OSPFv2 packet parsing and serialization.
//!
//! Implements the five OSPFv2 packet types:
//! - Hello (Type 1)
//! - Database Description (Type 2)
//! - Link State Request (Type 3)
//! - Link State Update (Type 4)
//! - Link State Acknowledgment (Type 5)
//!
//! RFC-REF: RFC 2328 Appendix A.3
//! "OSPF packet formats" — defines the header and per-type layouts.

use std::fmt;

// ── Constants ───────────────────────────────────────────────────────

/// OSPF protocol number in the IP header.
///
/// RFC-REF: RFC 2328 Section 8.2
/// "OSPF runs directly over IP, using IP protocol 89."
pub const OSPF_IP_PROTOCOL: u8 = 89;

/// AllSPFRouters multicast address: 224.0.0.5.
///
/// RFC-REF: RFC 2328 Section 8.1
/// "Hello packets are sent to the AllSPFRouters multicast address."
pub const ALL_SPF_ROUTERS: [u8; 4] = [224, 0, 0, 5];

/// AllDRouters multicast address: 224.0.0.6.
///
/// RFC-REF: RFC 2328 Section 9.5
/// "On multi-access networks, updates are sent to AllDRouters."
pub const ALL_DR_ROUTERS: [u8; 4] = [224, 0, 0, 6];

/// OSPFv2 version number.
pub const OSPF_VERSION: u8 = 2;

/// OSPF header length in bytes.
///
/// RFC-REF: RFC 2328 Appendix A.3.1
/// "Every OSPF packet starts with a standard 24-byte header."
pub const OSPF_HEADER_LEN: usize = 24;

/// Minimum Hello packet body length (without neighbors list).
/// 20 bytes: network_mask(4) + hello_interval(2) + options(1) +
/// priority(1) + dead_interval(4) + dr(4) + bdr(4).
pub const HELLO_BODY_MIN_LEN: usize = 20;

// ── OSPF packet type ────────────────────────────────────────────────

/// OSPF packet type codes.
///
/// RFC-REF: RFC 2328 Appendix A.3.1
/// "Type   Description
///  1      Hello
///  2      Database Description
///  3      Link State Request
///  4      Link State Update
///  5      Link State Acknowledgment"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OspfPacketType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAck = 5,
}

impl OspfPacketType {
    /// Convert a raw byte to an OSPF packet type.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Hello),
            2 => Some(Self::DatabaseDescription),
            3 => Some(Self::LinkStateRequest),
            4 => Some(Self::LinkStateUpdate),
            5 => Some(Self::LinkStateAck),
            _ => None,
        }
    }
}

impl fmt::Display for OspfPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello => write!(f, "Hello"),
            Self::DatabaseDescription => write!(f, "DD"),
            Self::LinkStateRequest => write!(f, "LSR"),
            Self::LinkStateUpdate => write!(f, "LSU"),
            Self::LinkStateAck => write!(f, "LSAck"),
        }
    }
}

// ── OSPF common header ──────────────────────────────────────────────

/// OSPF packet header (24 bytes).
///
/// RFC-REF: RFC 2328 Appendix A.3.1
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Version #   |     Type      |         Packet length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Router ID                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Area ID                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |             AuType            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Authentication                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Authentication                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfHeader {
    /// Protocol version (must be 2).
    pub version: u8,
    /// Packet type.
    pub packet_type: OspfPacketType,
    /// Total packet length including header.
    pub packet_length: u16,
    /// Router ID of the packet's source.
    pub router_id: [u8; 4],
    /// Area ID.
    pub area_id: [u8; 4],
    /// Checksum (IP-style one's complement).
    pub checksum: u16,
    /// Authentication type (0 = null, 1 = simple, 2 = crypto).
    pub auth_type: u16,
    /// Authentication data (8 bytes).
    pub auth_data: [u8; 8],
}

// ── Hello packet body ───────────────────────────────────────────────

/// OSPF Hello packet body.
///
/// RFC-REF: RFC 2328 Appendix A.3.2
/// "Hello packets are Type 1 OSPF packets. These packets are sent
/// periodically on all interfaces."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPacket {
    /// Common OSPF header.
    pub header: OspfHeader,
    /// Network mask of the interface.
    pub network_mask: [u8; 4],
    /// Seconds between Hello transmissions.
    pub hello_interval: u16,
    /// OSPF options field.
    pub options: u8,
    /// Router priority for DR election.
    pub router_priority: u8,
    /// Seconds before declaring a neighbor down.
    pub router_dead_interval: u32,
    /// Designated Router IP address.
    pub designated_router: [u8; 4],
    /// Backup Designated Router IP address.
    pub backup_designated_router: [u8; 4],
    /// List of Router IDs of neighbors from which Hellos have been
    /// recently received.
    pub neighbors: Vec<[u8; 4]>,
}

// ── Database Description packet ─────────────────────────────────────

/// OSPF Database Description (DD) packet body.
///
/// RFC-REF: RFC 2328 Appendix A.3.3
/// "Database Description packets are OSPF packet type 2."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseDescriptionPacket {
    /// Common OSPF header.
    pub header: OspfHeader,
    /// Interface MTU.
    pub interface_mtu: u16,
    /// Options field.
    pub options: u8,
    /// DD flags: I (Init), M (More), MS (Master/Slave).
    pub flags: u8,
    /// DD sequence number.
    pub dd_sequence_number: u32,
    /// LSA headers included in this DD packet.
    pub lsa_headers: Vec<LsaHeader>,
}

/// DD flag bits.
pub const DD_FLAG_MS: u8 = 0x01; // Master/Slave
pub const DD_FLAG_M: u8 = 0x02; // More
pub const DD_FLAG_I: u8 = 0x04; // Init

// ── Link State Request packet ───────────────────────────────────────

/// OSPF Link State Request packet body.
///
/// RFC-REF: RFC 2328 Appendix A.3.4
/// "Link State Request packets are OSPF packet type 3."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStateRequestPacket {
    /// Common OSPF header.
    pub header: OspfHeader,
    /// Requested LSAs (identified by type, LS ID, and advertising router).
    pub requests: Vec<LsaRequest>,
}

/// A single LSA request entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaRequest {
    /// LS Type.
    pub ls_type: u32,
    /// Link State ID.
    pub link_state_id: [u8; 4],
    /// Advertising Router.
    pub advertising_router: [u8; 4],
}

// ── Link State Update packet ────────────────────────────────────────

/// OSPF Link State Update packet body.
///
/// RFC-REF: RFC 2328 Appendix A.3.5
/// "Link State Update packets are OSPF packet type 4. These packets
/// are used to implement the flooding procedure."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStateUpdatePacket {
    /// Common OSPF header.
    pub header: OspfHeader,
    /// Number of LSAs.
    pub num_lsas: u32,
    /// Full LSAs included in this update.
    pub lsas: Vec<Lsa>,
}

// ── Link State Acknowledgment packet ────────────────────────────────

/// OSPF Link State Acknowledgment packet body.
///
/// RFC-REF: RFC 2328 Appendix A.3.6
/// "Link State Acknowledgment Packets are OSPF packet type 5."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStateAckPacket {
    /// Common OSPF header.
    pub header: OspfHeader,
    /// Acknowledged LSA headers.
    pub lsa_headers: Vec<LsaHeader>,
}

// ── LSA types ───────────────────────────────────────────────────────

/// LSA type codes.
///
/// RFC-REF: RFC 2328 Appendix A.4.1
/// "LS type   Description
///  1         Router-LSAs
///  2         Network-LSAs"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LsaType {
    Router = 1,
    Network = 2,
}

impl LsaType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Router),
            2 => Some(Self::Network),
            _ => None,
        }
    }
}

impl fmt::Display for LsaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Router => write!(f, "Router-LSA"),
            Self::Network => write!(f, "Network-LSA"),
        }
    }
}

// ── LSA header ──────────────────────────────────────────────────────

/// LSA header (20 bytes).
///
/// RFC-REF: RFC 2328 Appendix A.4.1
/// "All LSAs begin with a common 20 byte header."
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LsaHeader {
    /// LS Age (seconds since the LSA was originated).
    pub ls_age: u16,
    /// Options field.
    pub options: u8,
    /// LS Type.
    pub ls_type: u8,
    /// Link State ID.
    pub link_state_id: [u8; 4],
    /// Advertising Router.
    pub advertising_router: [u8; 4],
    /// LS Sequence Number.
    pub ls_sequence_number: u32,
    /// LS Checksum.
    pub ls_checksum: u16,
    /// Total length of the LSA including header.
    pub length: u16,
}

/// LSA header length in bytes.
pub const LSA_HEADER_LEN: usize = 20;

// ── LSA body (Router-LSA / Network-LSA) ─────────────────────────────

/// A complete LSA (header + body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsa {
    /// LSA header.
    pub header: LsaHeader,
    /// LSA body.
    pub body: LsaBody,
}

/// LSA body variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBody {
    /// Router-LSA (Type 1).
    ///
    /// RFC-REF: RFC 2328 Appendix A.4.2
    /// "Router-LSAs have LS type equal to 1."
    Router(RouterLsa),
    /// Network-LSA (Type 2).
    ///
    /// RFC-REF: RFC 2328 Appendix A.4.3
    /// "Network-LSAs have LS type equal to 2."
    Network(NetworkLsa),
}

/// Router-LSA body.
///
/// RFC-REF: RFC 2328 Section 12.4.1
/// "Router-LSAs describe the collected states of the router's
/// interfaces to an area."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsa {
    /// Flags: V (Virtual link), E (ASBR), B (ABR).
    pub flags: u8,
    /// Router links.
    pub links: Vec<RouterLink>,
}

/// A single link in a Router-LSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLink {
    /// Link ID (depends on link type).
    pub link_id: [u8; 4],
    /// Link Data (depends on link type).
    pub link_data: [u8; 4],
    /// Link type.
    pub link_type: u8,
    /// Number of TOS metrics (always 0 for us).
    pub num_tos: u8,
    /// Metric (cost) of this link.
    pub metric: u16,
}

/// Router link type codes.
///
/// RFC-REF: RFC 2328 Appendix A.4.2
pub const LINK_TYPE_P2P: u8 = 1;
pub const LINK_TYPE_TRANSIT: u8 = 2;
pub const LINK_TYPE_STUB: u8 = 3;

/// Network-LSA body.
///
/// RFC-REF: RFC 2328 Section 12.4.2
/// "Network-LSAs are originated by Designated Routers."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsa {
    /// Network mask.
    pub network_mask: [u8; 4],
    /// Attached routers (Router IDs).
    pub attached_routers: Vec<[u8; 4]>,
}

// ── Parsing ─────────────────────────────────────────────────────────

/// Errors that can occur during OSPF packet parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Packet too short for the OSPF header.
    TooShort,
    /// Invalid OSPF version (expected 2).
    BadVersion(u8),
    /// Unknown packet type.
    UnknownType(u8),
    /// Packet length field does not match actual data length.
    LengthMismatch { expected: u16, actual: usize },
    /// Hello body too short.
    HelloTooShort,
    /// Neighbor list length is not a multiple of 4.
    BadNeighborList,
    /// LSA header too short.
    LsaHeaderTooShort,
    /// LSA body too short.
    LsaBodyTooShort,
    /// Unknown LSA type.
    UnknownLsaType(u8),
    /// DD body too short.
    DdTooShort,
    /// LSR body not a multiple of 12.
    BadLsrBody,
    /// LSU body too short.
    LsuTooShort,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "packet too short for OSPF header"),
            Self::BadVersion(v) => write!(f, "bad OSPF version: {v}, expected 2"),
            Self::UnknownType(t) => write!(f, "unknown OSPF packet type: {t}"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "length mismatch: header says {expected}, got {actual}")
            }
            Self::HelloTooShort => write!(f, "Hello packet body too short"),
            Self::BadNeighborList => write!(f, "neighbor list length not a multiple of 4"),
            Self::LsaHeaderTooShort => write!(f, "LSA header too short"),
            Self::LsaBodyTooShort => write!(f, "LSA body too short"),
            Self::UnknownLsaType(t) => write!(f, "unknown LSA type: {t}"),
            Self::DdTooShort => write!(f, "DD packet body too short"),
            Self::BadLsrBody => write!(f, "LSR body not a multiple of 12"),
            Self::LsuTooShort => write!(f, "LSU packet body too short"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a raw OSPF header from a byte slice.
pub fn parse_ospf_header(data: &[u8]) -> Result<OspfHeader, ParseError> {
    if data.len() < OSPF_HEADER_LEN {
        return Err(ParseError::TooShort);
    }
    let version = data[0];
    if version != OSPF_VERSION {
        return Err(ParseError::BadVersion(version));
    }
    let packet_type_raw = data[1];
    let _packet_type =
        OspfPacketType::from_u8(packet_type_raw).ok_or(ParseError::UnknownType(packet_type_raw))?;
    let packet_length = u16::from_be_bytes([data[2], data[3]]);
    let router_id = [data[4], data[5], data[6], data[7]];
    let area_id = [data[8], data[9], data[10], data[11]];
    let checksum = u16::from_be_bytes([data[12], data[13]]);
    let auth_type = u16::from_be_bytes([data[14], data[15]]);
    let mut auth_data = [0u8; 8];
    auth_data.copy_from_slice(&data[16..24]);

    Ok(OspfHeader {
        version,
        packet_type: OspfPacketType::from_u8(packet_type_raw).unwrap(),
        packet_length,
        router_id,
        area_id,
        checksum,
        auth_type,
        auth_data,
    })
}

/// Parse an OSPF Hello packet from raw bytes (starting at the OSPF header).
pub fn parse_hello(data: &[u8]) -> Result<HelloPacket, ParseError> {
    let header = parse_ospf_header(data)?;
    let body = &data[OSPF_HEADER_LEN..];
    if body.len() < HELLO_BODY_MIN_LEN {
        return Err(ParseError::HelloTooShort);
    }
    let network_mask = [body[0], body[1], body[2], body[3]];
    let hello_interval = u16::from_be_bytes([body[4], body[5]]);
    let options = body[6];
    let router_priority = body[7];
    let router_dead_interval = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let designated_router = [body[12], body[13], body[14], body[15]];
    let backup_designated_router = [body[16], body[17], body[18], body[19]];

    let neighbor_data = &body[HELLO_BODY_MIN_LEN..];
    if !neighbor_data.len().is_multiple_of(4) {
        return Err(ParseError::BadNeighborList);
    }
    let neighbors: Vec<[u8; 4]> = neighbor_data
        .chunks_exact(4)
        .map(|c| [c[0], c[1], c[2], c[3]])
        .collect();

    Ok(HelloPacket {
        header,
        network_mask,
        hello_interval,
        options,
        router_priority,
        router_dead_interval,
        designated_router,
        backup_designated_router,
        neighbors,
    })
}

/// Parse an LSA header from raw bytes.
pub fn parse_lsa_header(data: &[u8]) -> Result<LsaHeader, ParseError> {
    if data.len() < LSA_HEADER_LEN {
        return Err(ParseError::LsaHeaderTooShort);
    }
    Ok(LsaHeader {
        ls_age: u16::from_be_bytes([data[0], data[1]]),
        options: data[2],
        ls_type: data[3],
        link_state_id: [data[4], data[5], data[6], data[7]],
        advertising_router: [data[8], data[9], data[10], data[11]],
        ls_sequence_number: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        ls_checksum: u16::from_be_bytes([data[16], data[17]]),
        length: u16::from_be_bytes([data[18], data[19]]),
    })
}

/// Parse a full LSA (header + body) from raw bytes.
pub fn parse_lsa(data: &[u8]) -> Result<(Lsa, usize), ParseError> {
    let header = parse_lsa_header(data)?;
    let total_len = header.length as usize;
    if data.len() < total_len {
        return Err(ParseError::LsaBodyTooShort);
    }

    let body_data = &data[LSA_HEADER_LEN..total_len];
    let ls_type =
        LsaType::from_u8(header.ls_type).ok_or(ParseError::UnknownLsaType(header.ls_type))?;

    let body = match ls_type {
        LsaType::Router => {
            if body_data.len() < 4 {
                return Err(ParseError::LsaBodyTooShort);
            }
            let flags = body_data[1];
            let num_links = u16::from_be_bytes([body_data[2], body_data[3]]) as usize;
            let links_data = &body_data[4..];
            // Each router link is 12 bytes.
            if links_data.len() < num_links * 12 {
                return Err(ParseError::LsaBodyTooShort);
            }
            let mut links = Vec::with_capacity(num_links);
            for i in 0..num_links {
                let offset = i * 12;
                let ld = &links_data[offset..offset + 12];
                links.push(RouterLink {
                    link_id: [ld[0], ld[1], ld[2], ld[3]],
                    link_data: [ld[4], ld[5], ld[6], ld[7]],
                    link_type: ld[8],
                    num_tos: ld[9],
                    metric: u16::from_be_bytes([ld[10], ld[11]]),
                });
            }
            LsaBody::Router(RouterLsa { flags, links })
        }
        LsaType::Network => {
            if body_data.len() < 4 {
                return Err(ParseError::LsaBodyTooShort);
            }
            let network_mask = [body_data[0], body_data[1], body_data[2], body_data[3]];
            let routers_data = &body_data[4..];
            if !routers_data.len().is_multiple_of(4) {
                return Err(ParseError::LsaBodyTooShort);
            }
            let attached_routers: Vec<[u8; 4]> = routers_data
                .chunks_exact(4)
                .map(|c| [c[0], c[1], c[2], c[3]])
                .collect();
            LsaBody::Network(NetworkLsa {
                network_mask,
                attached_routers,
            })
        }
    };

    Ok((Lsa { header, body }, total_len))
}

/// Parse a Database Description packet from raw bytes.
pub fn parse_dd(data: &[u8]) -> Result<DatabaseDescriptionPacket, ParseError> {
    let header = parse_ospf_header(data)?;
    let body = &data[OSPF_HEADER_LEN..];
    if body.len() < 8 {
        return Err(ParseError::DdTooShort);
    }
    let interface_mtu = u16::from_be_bytes([body[0], body[1]]);
    let options = body[2];
    let flags = body[3];
    let dd_sequence_number = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);

    let lsa_data = &body[8..];
    let mut lsa_headers = Vec::new();
    let mut offset = 0;
    while offset + LSA_HEADER_LEN <= lsa_data.len() {
        lsa_headers.push(parse_lsa_header(&lsa_data[offset..])?);
        offset += LSA_HEADER_LEN;
    }

    Ok(DatabaseDescriptionPacket {
        header,
        interface_mtu,
        options,
        flags,
        dd_sequence_number,
        lsa_headers,
    })
}

/// Parse a Link State Request packet from raw bytes.
pub fn parse_lsr(data: &[u8]) -> Result<LinkStateRequestPacket, ParseError> {
    let header = parse_ospf_header(data)?;
    let body = &data[OSPF_HEADER_LEN..];
    if !body.len().is_multiple_of(12) {
        return Err(ParseError::BadLsrBody);
    }
    let requests: Vec<LsaRequest> = body
        .chunks_exact(12)
        .map(|c| LsaRequest {
            ls_type: u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
            link_state_id: [c[4], c[5], c[6], c[7]],
            advertising_router: [c[8], c[9], c[10], c[11]],
        })
        .collect();

    Ok(LinkStateRequestPacket { header, requests })
}

/// Parse a Link State Update packet from raw bytes.
pub fn parse_lsu(data: &[u8]) -> Result<LinkStateUpdatePacket, ParseError> {
    let header = parse_ospf_header(data)?;
    let body = &data[OSPF_HEADER_LEN..];
    if body.len() < 4 {
        return Err(ParseError::LsuTooShort);
    }
    let num_lsas = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let mut lsas = Vec::new();
    let mut offset = 4;
    for _ in 0..num_lsas {
        if offset >= body.len() {
            break;
        }
        let (lsa, consumed) = parse_lsa(&body[offset..])?;
        lsas.push(lsa);
        offset += consumed;
    }

    Ok(LinkStateUpdatePacket {
        header,
        num_lsas,
        lsas,
    })
}

/// Parse a Link State Acknowledgment packet from raw bytes.
pub fn parse_lsack(data: &[u8]) -> Result<LinkStateAckPacket, ParseError> {
    let header = parse_ospf_header(data)?;
    let body = &data[OSPF_HEADER_LEN..];
    let mut lsa_headers = Vec::new();
    let mut offset = 0;
    while offset + LSA_HEADER_LEN <= body.len() {
        lsa_headers.push(parse_lsa_header(&body[offset..])?);
        offset += LSA_HEADER_LEN;
    }

    Ok(LinkStateAckPacket {
        header,
        lsa_headers,
    })
}

// ── Serialization ───────────────────────────────────────────────────

/// Serialize an OSPF header to bytes.
pub fn serialize_ospf_header(header: &OspfHeader) -> [u8; OSPF_HEADER_LEN] {
    let mut buf = [0u8; OSPF_HEADER_LEN];
    buf[0] = header.version;
    buf[1] = header.packet_type as u8;
    buf[2..4].copy_from_slice(&header.packet_length.to_be_bytes());
    buf[4..8].copy_from_slice(&header.router_id);
    buf[8..12].copy_from_slice(&header.area_id);
    buf[12..14].copy_from_slice(&header.checksum.to_be_bytes());
    buf[14..16].copy_from_slice(&header.auth_type.to_be_bytes());
    buf[16..24].copy_from_slice(&header.auth_data);
    buf
}

/// Serialize a Hello packet to bytes.
pub fn serialize_hello(hello: &HelloPacket) -> Vec<u8> {
    let body_len = HELLO_BODY_MIN_LEN + hello.neighbors.len() * 4;
    let total_len = OSPF_HEADER_LEN + body_len;

    let mut header = hello.header.clone();
    header.packet_length = total_len as u16;

    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(&serialize_ospf_header(&header));
    buf.extend_from_slice(&hello.network_mask);
    buf.extend_from_slice(&hello.hello_interval.to_be_bytes());
    buf.push(hello.options);
    buf.push(hello.router_priority);
    buf.extend_from_slice(&hello.router_dead_interval.to_be_bytes());
    buf.extend_from_slice(&hello.designated_router);
    buf.extend_from_slice(&hello.backup_designated_router);
    for neighbor in &hello.neighbors {
        buf.extend_from_slice(neighbor);
    }

    // Update checksum.
    let checksum = compute_ospf_checksum(&buf);
    buf[12..14].copy_from_slice(&checksum.to_be_bytes());

    buf
}

/// Serialize an LSA header to bytes.
pub fn serialize_lsa_header(header: &LsaHeader) -> [u8; LSA_HEADER_LEN] {
    let mut buf = [0u8; LSA_HEADER_LEN];
    buf[0..2].copy_from_slice(&header.ls_age.to_be_bytes());
    buf[2] = header.options;
    buf[3] = header.ls_type;
    buf[4..8].copy_from_slice(&header.link_state_id);
    buf[8..12].copy_from_slice(&header.advertising_router);
    buf[12..16].copy_from_slice(&header.ls_sequence_number.to_be_bytes());
    buf[16..18].copy_from_slice(&header.ls_checksum.to_be_bytes());
    buf[18..20].copy_from_slice(&header.length.to_be_bytes());
    buf
}

/// Compute the OSPF checksum for a packet.
///
/// RFC-REF: RFC 2328 Appendix A.3.1
/// "The standard IP checksum of the entire contents of the packet,
/// starting with the OSPF packet header but excluding the 64-bit
/// authentication field."
///
/// RFC-DEVIATION:
/// reason: Authentication is not implemented; we zero the auth field
///         before computing the checksum and accept any auth type.
/// impact: Interop with routers requiring MD5/simple auth will fail.
/// issue: #157
/// plan: Add authentication support in a future version.
pub fn compute_ospf_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        // Skip the authentication field (bytes 16..24) and the
        // checksum field (bytes 12..14).
        if (12..14).contains(&i) || (16..24).contains(&i) {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    // Handle odd-length data (shouldn't happen for valid OSPF packets).
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    // Fold 32-bit sum to 16-bit.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper to build a minimal Hello packet ──────────────────────

    fn make_hello_bytes(neighbors: &[[u8; 4]]) -> Vec<u8> {
        let body_len = HELLO_BODY_MIN_LEN + neighbors.len() * 4;
        let total_len = OSPF_HEADER_LEN + body_len;
        let mut buf = vec![0u8; total_len];

        // Header
        buf[0] = OSPF_VERSION; // version
        buf[1] = OspfPacketType::Hello as u8; // type
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes()); // length
        buf[4..8].copy_from_slice(&[1, 1, 1, 1]); // router_id
        buf[8..12].copy_from_slice(&[0, 0, 0, 0]); // area_id

        // Hello body
        let body = &mut buf[OSPF_HEADER_LEN..];
        body[0..4].copy_from_slice(&[255, 255, 255, 0]); // network_mask
        body[4..6].copy_from_slice(&10u16.to_be_bytes()); // hello_interval
        body[6] = 0x02; // options (E-bit)
        body[7] = 1; // priority
        body[8..12].copy_from_slice(&40u32.to_be_bytes()); // dead_interval
        body[12..16].copy_from_slice(&[0, 0, 0, 0]); // DR
        body[16..20].copy_from_slice(&[0, 0, 0, 0]); // BDR

        for (i, n) in neighbors.iter().enumerate() {
            let offset = HELLO_BODY_MIN_LEN + i * 4;
            body[offset..offset + 4].copy_from_slice(n);
        }

        buf
    }

    // ── Header parsing tests ────────────────────────────────────────

    #[test]
    fn parse_header_too_short() {
        let result = parse_ospf_header(&[0u8; 10]);
        assert_eq!(result, Err(ParseError::TooShort));
    }

    #[test]
    fn parse_header_bad_version() {
        let mut buf = [0u8; OSPF_HEADER_LEN];
        buf[0] = 3; // version 3 (OSPFv3)
        buf[1] = 1; // Hello
        let result = parse_ospf_header(&buf);
        assert_eq!(result, Err(ParseError::BadVersion(3)));
    }

    #[test]
    fn parse_header_unknown_type() {
        let mut buf = [0u8; OSPF_HEADER_LEN];
        buf[0] = OSPF_VERSION;
        buf[1] = 99;
        let result = parse_ospf_header(&buf);
        assert_eq!(result, Err(ParseError::UnknownType(99)));
    }

    #[test]
    fn parse_header_valid() {
        let buf = make_hello_bytes(&[]);
        let header = parse_ospf_header(&buf).unwrap();
        assert_eq!(header.version, OSPF_VERSION);
        assert_eq!(header.packet_type, OspfPacketType::Hello);
        assert_eq!(header.router_id, [1, 1, 1, 1]);
        assert_eq!(header.area_id, [0, 0, 0, 0]);
    }

    // ── Hello parsing tests ─────────────────────────────────────────

    #[test]
    fn parse_hello_no_neighbors() {
        let buf = make_hello_bytes(&[]);
        let hello = parse_hello(&buf).unwrap();
        assert_eq!(hello.network_mask, [255, 255, 255, 0]);
        assert_eq!(hello.hello_interval, 10);
        assert_eq!(hello.options, 0x02);
        assert_eq!(hello.router_priority, 1);
        assert_eq!(hello.router_dead_interval, 40);
        assert!(hello.neighbors.is_empty());
    }

    #[test]
    fn parse_hello_with_neighbors() {
        let buf = make_hello_bytes(&[[2, 2, 2, 2], [3, 3, 3, 3]]);
        let hello = parse_hello(&buf).unwrap();
        assert_eq!(hello.neighbors.len(), 2);
        assert_eq!(hello.neighbors[0], [2, 2, 2, 2]);
        assert_eq!(hello.neighbors[1], [3, 3, 3, 3]);
    }

    #[test]
    fn parse_hello_body_too_short() {
        let mut buf = make_hello_bytes(&[]);
        // Truncate the body.
        buf.truncate(OSPF_HEADER_LEN + 10);
        let result = parse_hello(&buf);
        assert_eq!(result, Err(ParseError::HelloTooShort));
    }

    // ── Hello round-trip test ───────────────────────────────────────

    #[test]
    fn hello_serialize_parse_roundtrip() {
        let hello = HelloPacket {
            header: OspfHeader {
                version: OSPF_VERSION,
                packet_type: OspfPacketType::Hello,
                packet_length: 0, // will be set by serialize
                router_id: [10, 0, 0, 1],
                area_id: [0, 0, 0, 0],
                checksum: 0,
                auth_type: 0,
                auth_data: [0; 8],
            },
            network_mask: [255, 255, 255, 0],
            hello_interval: 10,
            options: 0x02,
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: [0, 0, 0, 0],
            backup_designated_router: [0, 0, 0, 0],
            neighbors: vec![[2, 2, 2, 2], [3, 3, 3, 3]],
        };

        let bytes = serialize_hello(&hello);
        let parsed = parse_hello(&bytes).unwrap();

        assert_eq!(parsed.header.router_id, hello.header.router_id);
        assert_eq!(parsed.network_mask, hello.network_mask);
        assert_eq!(parsed.hello_interval, hello.hello_interval);
        assert_eq!(parsed.router_dead_interval, hello.router_dead_interval);
        assert_eq!(parsed.neighbors, hello.neighbors);
    }

    // ── LSA header parsing test ─────────────────────────────────────

    #[test]
    fn parse_lsa_header_valid() {
        let mut buf = [0u8; LSA_HEADER_LEN];
        buf[0..2].copy_from_slice(&100u16.to_be_bytes()); // age
        buf[2] = 0x02; // options
        buf[3] = 1; // type (Router)
        buf[4..8].copy_from_slice(&[1, 1, 1, 1]); // LS ID
        buf[8..12].copy_from_slice(&[1, 1, 1, 1]); // adv router
        buf[12..16].copy_from_slice(&0x80000001u32.to_be_bytes()); // seq
        buf[16..18].copy_from_slice(&0u16.to_be_bytes()); // checksum
        buf[18..20].copy_from_slice(&(LSA_HEADER_LEN as u16).to_be_bytes()); // length

        let header = parse_lsa_header(&buf).unwrap();
        assert_eq!(header.ls_age, 100);
        assert_eq!(header.ls_type, 1);
        assert_eq!(header.link_state_id, [1, 1, 1, 1]);
        assert_eq!(header.ls_sequence_number, 0x80000001);
    }

    #[test]
    fn parse_lsa_header_too_short() {
        let result = parse_lsa_header(&[0u8; 10]);
        assert_eq!(result, Err(ParseError::LsaHeaderTooShort));
    }

    // ── Router-LSA round-trip test ──────────────────────────────────

    #[test]
    fn parse_router_lsa_valid() {
        // Build a Router-LSA with one stub link.
        let mut buf = Vec::new();
        // LSA header (20 bytes)
        let header_len: u16 = 20 + 4 + 12; // header + flags/num_links + 1 link
        buf.extend_from_slice(&0u16.to_be_bytes()); // age
        buf.push(0x02); // options
        buf.push(1); // type
        buf.extend_from_slice(&[1, 1, 1, 1]); // LS ID
        buf.extend_from_slice(&[1, 1, 1, 1]); // adv router
        buf.extend_from_slice(&0x80000001u32.to_be_bytes()); // seq
        buf.extend_from_slice(&0u16.to_be_bytes()); // checksum
        buf.extend_from_slice(&header_len.to_be_bytes()); // length

        // Router-LSA body
        buf.push(0); // reserved
        buf.push(0); // flags
        buf.extend_from_slice(&1u16.to_be_bytes()); // num_links = 1
                                                    // Link: stub network 192.168.1.0, mask 255.255.255.0, metric 10
        buf.extend_from_slice(&[192, 168, 1, 0]); // link_id
        buf.extend_from_slice(&[255, 255, 255, 0]); // link_data
        buf.push(LINK_TYPE_STUB); // link_type
        buf.push(0); // num_tos
        buf.extend_from_slice(&10u16.to_be_bytes()); // metric

        let (lsa, consumed) = parse_lsa(&buf).unwrap();
        assert_eq!(consumed, header_len as usize);
        assert_eq!(lsa.header.ls_type, 1);
        match &lsa.body {
            LsaBody::Router(rlsa) => {
                assert_eq!(rlsa.links.len(), 1);
                assert_eq!(rlsa.links[0].link_id, [192, 168, 1, 0]);
                assert_eq!(rlsa.links[0].link_type, LINK_TYPE_STUB);
                assert_eq!(rlsa.links[0].metric, 10);
            }
            _ => panic!("expected Router-LSA"),
        }
    }

    // ── Checksum test ───────────────────────────────────────────────

    #[test]
    fn checksum_nonzero() {
        let buf = make_hello_bytes(&[]);
        let checksum = compute_ospf_checksum(&buf);
        // The checksum should not be zero for a typical packet.
        // (It could be 0xFFFF in some cases but that's valid.)
        assert_ne!(checksum, 0);
    }

    // ── Packet type display ─────────────────────────────────────────

    #[test]
    fn packet_type_display() {
        assert_eq!(format!("{}", OspfPacketType::Hello), "Hello");
        assert_eq!(format!("{}", OspfPacketType::DatabaseDescription), "DD");
        assert_eq!(format!("{}", OspfPacketType::LinkStateRequest), "LSR");
        assert_eq!(format!("{}", OspfPacketType::LinkStateUpdate), "LSU");
        assert_eq!(format!("{}", OspfPacketType::LinkStateAck), "LSAck");
    }

    #[test]
    fn packet_type_from_u8() {
        assert_eq!(OspfPacketType::from_u8(1), Some(OspfPacketType::Hello));
        assert_eq!(
            OspfPacketType::from_u8(2),
            Some(OspfPacketType::DatabaseDescription)
        );
        assert_eq!(
            OspfPacketType::from_u8(3),
            Some(OspfPacketType::LinkStateRequest)
        );
        assert_eq!(
            OspfPacketType::from_u8(4),
            Some(OspfPacketType::LinkStateUpdate)
        );
        assert_eq!(
            OspfPacketType::from_u8(5),
            Some(OspfPacketType::LinkStateAck)
        );
        assert_eq!(OspfPacketType::from_u8(0), None);
        assert_eq!(OspfPacketType::from_u8(6), None);
    }

    // ── DD parsing test ─────────────────────────────────────────────

    #[test]
    fn parse_dd_valid() {
        let total_len = OSPF_HEADER_LEN + 8; // header + DD body (no LSA headers)
        let mut buf = vec![0u8; total_len];
        buf[0] = OSPF_VERSION;
        buf[1] = OspfPacketType::DatabaseDescription as u8;
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[4..8].copy_from_slice(&[1, 1, 1, 1]);
        // DD body
        let body_start = OSPF_HEADER_LEN;
        buf[body_start..body_start + 2].copy_from_slice(&1500u16.to_be_bytes()); // MTU
        buf[body_start + 2] = 0x02; // options
        buf[body_start + 3] = DD_FLAG_I | DD_FLAG_M | DD_FLAG_MS; // flags
        buf[body_start + 4..body_start + 8].copy_from_slice(&42u32.to_be_bytes()); // seq

        let dd = parse_dd(&buf).unwrap();
        assert_eq!(dd.interface_mtu, 1500);
        assert_eq!(dd.flags, DD_FLAG_I | DD_FLAG_M | DD_FLAG_MS);
        assert_eq!(dd.dd_sequence_number, 42);
        assert!(dd.lsa_headers.is_empty());
    }

    // ── LSR parsing test ────────────────────────────────────────────

    #[test]
    fn parse_lsr_valid() {
        let total_len = OSPF_HEADER_LEN + 12; // header + one request
        let mut buf = vec![0u8; total_len];
        buf[0] = OSPF_VERSION;
        buf[1] = OspfPacketType::LinkStateRequest as u8;
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[4..8].copy_from_slice(&[1, 1, 1, 1]);
        // LSR body: one request
        let body_start = OSPF_HEADER_LEN;
        buf[body_start..body_start + 4].copy_from_slice(&1u32.to_be_bytes()); // type 1
        buf[body_start + 4..body_start + 8].copy_from_slice(&[2, 2, 2, 2]); // LS ID
        buf[body_start + 8..body_start + 12].copy_from_slice(&[1, 1, 1, 1]); // adv router

        let lsr = parse_lsr(&buf).unwrap();
        assert_eq!(lsr.requests.len(), 1);
        assert_eq!(lsr.requests[0].ls_type, 1);
        assert_eq!(lsr.requests[0].link_state_id, [2, 2, 2, 2]);
    }
}

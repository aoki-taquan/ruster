//! PPP in PPPoE session frames, and the packets and options of PPP's control
//! protocols.
//!
//! # Standards
//!
//! - RFC 2516 section 6: the session frame (Ethernet type 0x8864, version 1, type
//!   1, code 0) with the PPP protocol number and information after it. The length
//!   is that of the PPP part; Ethernet padding after it is not read.
//! - RFC 1661 section 2: the two-byte protocol field. Section 5: the control packet
//!   (code, identifier, length, data); octets after the length are padding and
//!   ignored, a length shorter than the header or past the information makes the
//!   packet invalid. Section 6: the options (type, length, data), each at least two
//!   octets long.
//!
//! Deviations: no protocol-field compression (RFC 1661 section 6.5; the FE reads
//! two-byte protocol numbers), and no HDLC framing, which PPPoE does not use.

use crate::Mac;

/// The Ethernet type of PPPoE session frames.
pub const ETHERTYPE: [u8; 2] = [0x88, 0x64];
const ETHERNET: usize = 14;
const HEADER: usize = 6;

/// PPP protocol numbers.
pub mod protocol {
    pub const IPV4: u16 = 0x0021;
    pub const IPV6: u16 = 0x0057;
    pub const IPCP: u16 = 0x8021;
    pub const IPV6CP: u16 = 0x8057;
    pub const LCP: u16 = 0xc021;
    pub const PAP: u16 = 0xc023;
    pub const CHAP: u16 = 0xc223;
}

/// A PPP packet in a PPPoE session frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionFrame<'a> {
    pub destination: Mac,
    pub source: Mac,
    pub session: u16,
    pub protocol: u16,
    pub information: &'a [u8],
}

impl<'a> SessionFrame<'a> {
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        let header = frame.get(ETHERNET..ETHERNET + HEADER)?;
        if frame[12..14] != ETHERTYPE || header[0] != 0x11 || header[1] != 0 {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let ppp = frame.get(ETHERNET + HEADER..ETHERNET + HEADER + length)?;
        let protocol = ppp.get(..2)?;
        Some(Self {
            destination: frame[0..6].try_into().ok()?,
            source: frame[6..12].try_into().ok()?,
            session: u16::from_be_bytes([header[2], header[3]]),
            protocol: u16::from_be_bytes([protocol[0], protocol[1]]),
            information: &ppp[2..],
        })
    }
}

/// A session frame carrying `information` of `protocol`.
pub fn session_frame(
    destination: Mac,
    source: Mac,
    session: u16,
    protocol: u16,
    information: &[u8],
) -> Vec<u8> {
    let length = u16::try_from(2 + information.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(ETHERNET + HEADER + 2 + information.len());
    out.extend_from_slice(&destination);
    out.extend_from_slice(&source);
    out.extend_from_slice(&ETHERTYPE);
    out.extend_from_slice(&[0x11, 0]);
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&protocol.to_be_bytes());
    out.extend_from_slice(information);
    out
}

/// A control packet (LCP, an NCP, PAP or CHAP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub code: u8,
    pub id: u8,
    pub data: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn parse(information: &'a [u8]) -> Option<Self> {
        let header = information.get(..4)?;
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if length < 4 {
            return None;
        }
        Some(Self {
            code: header[0],
            id: header[1],
            data: information.get(4..length)?,
        })
    }
}

/// The bytes of a control packet.
pub fn packet(code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let length = u16::try_from(4 + data.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&[code, id]);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// One configuration option: its type and its data (without the two header
/// octets).
pub type Opt<'a> = (u8, &'a [u8]);

/// Reads the options of a Configure packet. `None` when one is shorter than two
/// octets or runs past the end.
pub fn options(data: &[u8]) -> Option<Vec<Opt<'_>>> {
    let mut options = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let length = usize::from(*rest.get(1)?);
        if length < 2 {
            return None;
        }
        let option = rest.get(..length)?;
        options.push((option[0], &option[2..]));
        rest = &rest[length..];
    }
    Some(options)
}

/// Appends an option. `value` must be at most 253 octets.
pub fn push_option(out: &mut Vec<u8>, kind: u8, value: &[u8]) {
    out.push(kind);
    out.push(u8::try_from(2 + value.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(value);
}

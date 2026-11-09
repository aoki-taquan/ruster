//! Frames passed between the FE and a CE process (`docs/design/control-protocol.md`,
//! "パケットの受け渡し").
//!
//! One datagram on a Unix datagram socket carries one frame with a small header:
//!
//! ```text
//! version u8 = 1 | direction u8 | reason u16 | name length u8 | interface name | frame
//! ```
//!
//! The interface is named, not numbered, so the CE does not need the FE's port
//! numbering. Unix datagram sockets keep message boundaries and, on Linux, do not
//! drop silently: a full socket refuses the send, and the sender counts the drop.
//!
//! # Standards
//!
//! None: the format is ruster's own. The frames it carries keep their own standards
//! (ARP is RFC 826).

use std::fmt;

pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// From the FE to a CE process.
    ToControl = 1,
    /// From a CE process to be sent by the FE.
    FromControl = 2,
}

/// Why the FE passed the frame, or what the CE sends.
pub mod reason {
    /// An ARP packet: the 28-byte ARP body (`ToControl`) or a whole Ethernet
    /// frame to send (`FromControl`).
    pub const ARP: u16 = 1;
    /// IPv6 Neighbor Discovery (ICMPv6 types 133 to 137): a whole Ethernet frame in
    /// both directions.
    pub const ND: u16 = 2;
    /// The neighbors packets went to (`docs/design/ce-processes.md`, "近隣がまだ使われて
    /// いるか"). `FromControl`, with no frame and any interface name: the neighbor
    /// process asks for them. `ToControl`: one neighbor used since the last ask, the
    /// frame being its address (4 or 16 bytes) on the named interface; the FE then
    /// clears its marks.
    pub const NEIGHBOR_USED: u16 = 3;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Punt<'a> {
    pub direction: Direction,
    pub reason: u16,
    pub interface: &'a str,
    pub frame: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PuntError {
    Truncated,
    Version(u8),
    Direction(u8),
    InterfaceName,
}

impl fmt::Display for PuntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad punt message: {self:?}")
    }
}

impl std::error::Error for PuntError {}

impl<'a> Punt<'a> {
    /// Appends the message to `out`. The interface name must be 1 to 255 bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), PuntError> {
        let name_len = u8::try_from(self.interface.len())
            .ok()
            .filter(|&len| len > 0)
            .ok_or(PuntError::InterfaceName)?;
        out.push(VERSION);
        out.push(self.direction as u8);
        out.extend_from_slice(&self.reason.to_be_bytes());
        out.push(name_len);
        out.extend_from_slice(self.interface.as_bytes());
        out.extend_from_slice(self.frame);
        Ok(())
    }

    pub fn decode(buf: &'a [u8]) -> Result<Self, PuntError> {
        let header = buf.get(..HEADER_LEN).ok_or(PuntError::Truncated)?;
        if header[0] != VERSION {
            return Err(PuntError::Version(header[0]));
        }
        let direction = match header[1] {
            1 => Direction::ToControl,
            2 => Direction::FromControl,
            other => return Err(PuntError::Direction(other)),
        };
        let reason = u16::from_be_bytes([header[2], header[3]]);
        let name_len = usize::from(header[4]);
        let name = buf
            .get(HEADER_LEN..HEADER_LEN + name_len)
            .ok_or(PuntError::Truncated)?;
        let interface = std::str::from_utf8(name).map_err(|_| PuntError::InterfaceName)?;
        if interface.is_empty() {
            return Err(PuntError::InterfaceName);
        }
        Ok(Self {
            direction,
            reason,
            interface,
            frame: &buf[HEADER_LEN + name_len..],
        })
    }
}

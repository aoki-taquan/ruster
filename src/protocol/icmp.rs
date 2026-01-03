//! ICMP (Internet Control Message Protocol) - RFC 792

use crate::{Error, Result};

/// ICMP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    Redirect = 5,
    EchoRequest = 8,
    TimeExceeded = 11,
}

impl IcmpType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(IcmpType::EchoReply),
            3 => Some(IcmpType::DestinationUnreachable),
            5 => Some(IcmpType::Redirect),
            8 => Some(IcmpType::EchoRequest),
            11 => Some(IcmpType::TimeExceeded),
            _ => None,
        }
    }
}

/// Parsed ICMP message
#[derive(Debug)]
pub struct IcmpPacket<'a> {
    buffer: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Parse("ICMP packet too short".into()));
        }

        Ok(Self { buffer })
    }

    pub fn icmp_type(&self) -> u8 {
        self.buffer[0]
    }

    pub fn code(&self) -> u8 {
        self.buffer[1]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// For Echo Request/Reply: identifier
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    /// For Echo Request/Reply: sequence number
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    pub fn payload(&self) -> &[u8] {
        &self.buffer[8..]
    }
}

/// Build an ICMP Echo Reply from an Echo Request
pub fn build_echo_reply(request: &[u8]) -> Result<Vec<u8>> {
    if request.len() < 8 {
        return Err(Error::Parse("ICMP request too short".into()));
    }

    let mut reply = request.to_vec();

    // Change type from Echo Request (8) to Echo Reply (0)
    reply[0] = IcmpType::EchoReply as u8;

    // Clear checksum field
    reply[2] = 0;
    reply[3] = 0;

    // Calculate new checksum
    let checksum = icmp_checksum(&reply);
    reply[2..4].copy_from_slice(&checksum.to_be_bytes());

    Ok(reply)
}

/// Calculate ICMP checksum
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            u16::from_be_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

//! IPv4 protocol - RFC 791

use crate::{Error, Result};
use std::net::Ipv4Addr;

/// Minimum IPv4 header size (without options)
pub const MIN_HEADER_SIZE: usize = 20;

/// IPv4 protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
}

impl Protocol {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Protocol::Icmp),
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            58 => Some(Protocol::Icmpv6),
            _ => None,
        }
    }
}

/// Parsed IPv4 header (zero-copy reference)
#[derive(Debug)]
pub struct Ipv4Header<'a> {
    buffer: &'a [u8],
    header_len: usize,
}

impl<'a> Ipv4Header<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < MIN_HEADER_SIZE {
            return Err(Error::Parse("IPv4 header too short".into()));
        }

        let version = buffer[0] >> 4;
        if version != 4 {
            return Err(Error::Parse("not an IPv4 packet".into()));
        }

        let ihl = (buffer[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if buffer.len() < header_len {
            return Err(Error::Parse("IPv4 header truncated".into()));
        }

        Ok(Self { buffer, header_len })
    }

    pub fn version(&self) -> u8 {
        self.buffer[0] >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.buffer[0] & 0x0F
    }

    pub fn dscp(&self) -> u8 {
        self.buffer[1] >> 2
    }

    pub fn ecn(&self) -> u8 {
        self.buffer[1] & 0x03
    }

    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.buffer[4], self.buffer[5]])
    }

    pub fn flags(&self) -> u8 {
        self.buffer[6] >> 5
    }

    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6] & 0x1F, self.buffer[7]])
    }

    pub fn ttl(&self) -> u8 {
        self.buffer[8]
    }

    pub fn protocol(&self) -> u8 {
        self.buffer[9]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buffer[10], self.buffer[11]])
    }

    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[12],
            self.buffer[13],
            self.buffer[14],
            self.buffer[15],
        )
    }

    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer[16],
            self.buffer[17],
            self.buffer[18],
            self.buffer[19],
        )
    }

    pub fn header_len(&self) -> usize {
        self.header_len
    }

    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.header_len..]
    }
}

/// Calculate IPv4 header checksum
pub fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };

        // Skip the checksum field itself (bytes 10-11)
        if i != 10 {
            sum = sum.wrapping_add(word as u32);
        }
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

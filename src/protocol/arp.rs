//! ARP (Address Resolution Protocol) - RFC 826

use super::MacAddr;
use crate::{Error, Result};
use std::net::Ipv4Addr;

/// ARP packet size (for Ethernet/IPv4)
pub const ARP_PACKET_SIZE: usize = 28;

/// ARP operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ArpOp {
    Request = 1,
    Reply = 2,
}

impl ArpOp {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(ArpOp::Request),
            2 => Some(ArpOp::Reply),
            _ => None,
        }
    }
}

/// ARP packet (Ethernet/IPv4)
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub operation: ArpOp,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Parse an ARP packet from buffer
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < ARP_PACKET_SIZE {
            return Err(Error::Parse("ARP packet too short".into()));
        }

        // Hardware type (Ethernet = 1)
        let htype = u16::from_be_bytes([buffer[0], buffer[1]]);
        if htype != 1 {
            return Err(Error::Parse("unsupported hardware type".into()));
        }

        // Protocol type (IPv4 = 0x0800)
        let ptype = u16::from_be_bytes([buffer[2], buffer[3]]);
        if ptype != 0x0800 {
            return Err(Error::Parse("unsupported protocol type".into()));
        }

        // Hardware address length (6 for Ethernet)
        if buffer[4] != 6 {
            return Err(Error::Parse("invalid hardware address length".into()));
        }

        // Protocol address length (4 for IPv4)
        if buffer[5] != 4 {
            return Err(Error::Parse("invalid protocol address length".into()));
        }

        let operation = u16::from_be_bytes([buffer[6], buffer[7]]);
        let operation = ArpOp::from_u16(operation)
            .ok_or_else(|| Error::Parse("invalid ARP operation".into()))?;

        let sender_mac = MacAddr(buffer[8..14].try_into().unwrap());
        let sender_ip = Ipv4Addr::new(buffer[14], buffer[15], buffer[16], buffer[17]);
        let target_mac = MacAddr(buffer[18..24].try_into().unwrap());
        let target_ip = Ipv4Addr::new(buffer[24], buffer[25], buffer[26], buffer[27]);

        Ok(Self {
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    /// Serialize ARP packet to bytes
    pub fn to_bytes(&self) -> [u8; ARP_PACKET_SIZE] {
        let mut buf = [0u8; ARP_PACKET_SIZE];

        // Hardware type (Ethernet)
        buf[0..2].copy_from_slice(&1u16.to_be_bytes());
        // Protocol type (IPv4)
        buf[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        // Hardware address length
        buf[4] = 6;
        // Protocol address length
        buf[5] = 4;
        // Operation
        buf[6..8].copy_from_slice(&(self.operation as u16).to_be_bytes());
        // Sender hardware address
        buf[8..14].copy_from_slice(&self.sender_mac.0);
        // Sender protocol address
        buf[14..18].copy_from_slice(&self.sender_ip.octets());
        // Target hardware address
        buf[18..24].copy_from_slice(&self.target_mac.0);
        // Target protocol address
        buf[24..28].copy_from_slice(&self.target_ip.octets());

        buf
    }

    /// Create an ARP request
    pub fn request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        Self {
            operation: ArpOp::Request,
            sender_mac,
            sender_ip,
            target_mac: MacAddr::ZERO,
            target_ip,
        }
    }

    /// Create an ARP reply
    pub fn reply(
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
    ) -> Self {
        Self {
            operation: ArpOp::Reply,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }
}

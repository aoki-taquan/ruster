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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Create a Gratuitous ARP (announce own IP/MAC binding)
    pub fn gratuitous(mac: MacAddr, ip: Ipv4Addr) -> Self {
        Self {
            operation: ArpOp::Request,
            sender_mac: mac,
            sender_ip: ip,
            target_mac: MacAddr::ZERO,
            target_ip: ip, // Target IP == Sender IP for GARP
        }
    }

    /// Check if this is a Gratuitous ARP
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip == self.target_ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arp_request() -> [u8; ARP_PACKET_SIZE] {
        let mut buf = [0u8; ARP_PACKET_SIZE];
        // Hardware type: Ethernet (1)
        buf[0..2].copy_from_slice(&1u16.to_be_bytes());
        // Protocol type: IPv4 (0x0800)
        buf[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        // Hardware address length: 6
        buf[4] = 6;
        // Protocol address length: 4
        buf[5] = 4;
        // Operation: Request (1)
        buf[6..8].copy_from_slice(&1u16.to_be_bytes());
        // Sender MAC: 00:11:22:33:44:55
        buf[8..14].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Sender IP: 192.168.1.1
        buf[14..18].copy_from_slice(&[192, 168, 1, 1]);
        // Target MAC: 00:00:00:00:00:00
        buf[18..24].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Target IP: 192.168.1.2
        buf[24..28].copy_from_slice(&[192, 168, 1, 2]);
        buf
    }

    fn make_arp_reply() -> [u8; ARP_PACKET_SIZE] {
        let mut buf = [0u8; ARP_PACKET_SIZE];
        buf[0..2].copy_from_slice(&1u16.to_be_bytes());
        buf[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        buf[4] = 6;
        buf[5] = 4;
        // Operation: Reply (2)
        buf[6..8].copy_from_slice(&2u16.to_be_bytes());
        // Sender MAC: aa:bb:cc:dd:ee:ff
        buf[8..14].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // Sender IP: 192.168.1.2
        buf[14..18].copy_from_slice(&[192, 168, 1, 2]);
        // Target MAC: 00:11:22:33:44:55
        buf[18..24].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Target IP: 192.168.1.1
        buf[24..28].copy_from_slice(&[192, 168, 1, 1]);
        buf
    }

    #[test]
    fn test_arp_op_from_u16() {
        assert_eq!(ArpOp::from_u16(1), Some(ArpOp::Request));
        assert_eq!(ArpOp::from_u16(2), Some(ArpOp::Reply));
        assert_eq!(ArpOp::from_u16(0), None);
        assert_eq!(ArpOp::from_u16(3), None);
    }

    #[test]
    fn test_parse_arp_request() {
        let data = make_arp_request();
        let pkt = ArpPacket::parse(&data).unwrap();

        assert_eq!(pkt.operation, ArpOp::Request);
        assert_eq!(
            pkt.sender_mac,
            MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(pkt.sender_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(pkt.target_mac, MacAddr::ZERO);
        assert_eq!(pkt.target_ip, Ipv4Addr::new(192, 168, 1, 2));
    }

    #[test]
    fn test_parse_arp_reply() {
        let data = make_arp_reply();
        let pkt = ArpPacket::parse(&data).unwrap();

        assert_eq!(pkt.operation, ArpOp::Reply);
        assert_eq!(
            pkt.sender_mac,
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(pkt.sender_ip, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(
            pkt.target_mac,
            MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(pkt.target_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_parse_too_short() {
        let short = [0u8; 27];
        assert!(ArpPacket::parse(&short).is_err());
    }

    #[test]
    fn test_parse_invalid_hardware_type() {
        let mut data = make_arp_request();
        // Set hardware type to 2 (not Ethernet)
        data[0..2].copy_from_slice(&2u16.to_be_bytes());
        assert!(ArpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_protocol_type() {
        let mut data = make_arp_request();
        // Set protocol type to IPv6
        data[2..4].copy_from_slice(&0x86DDu16.to_be_bytes());
        assert!(ArpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_hardware_len() {
        let mut data = make_arp_request();
        data[4] = 8; // Not 6
        assert!(ArpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_protocol_len() {
        let mut data = make_arp_request();
        data[5] = 16; // Not 4
        assert!(ArpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_operation() {
        let mut data = make_arp_request();
        data[6..8].copy_from_slice(&99u16.to_be_bytes());
        assert!(ArpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_to_bytes() {
        let pkt = ArpPacket {
            operation: ArpOp::Request,
            sender_mac: MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            sender_ip: Ipv4Addr::new(192, 168, 1, 1),
            target_mac: MacAddr::ZERO,
            target_ip: Ipv4Addr::new(192, 168, 1, 2),
        };

        let bytes = pkt.to_bytes();
        assert_eq!(bytes, make_arp_request());
    }

    #[test]
    fn test_roundtrip_request() {
        let original = make_arp_request();
        let pkt = ArpPacket::parse(&original).unwrap();
        let serialized = pkt.to_bytes();
        assert_eq!(original, serialized);
    }

    #[test]
    fn test_roundtrip_reply() {
        let original = make_arp_reply();
        let pkt = ArpPacket::parse(&original).unwrap();
        let serialized = pkt.to_bytes();
        assert_eq!(original, serialized);
    }

    #[test]
    fn test_request_helper() {
        let sender_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let sender_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 2);

        let pkt = ArpPacket::request(sender_mac, sender_ip, target_ip);

        assert_eq!(pkt.operation, ArpOp::Request);
        assert_eq!(pkt.sender_mac, sender_mac);
        assert_eq!(pkt.sender_ip, sender_ip);
        assert_eq!(pkt.target_mac, MacAddr::ZERO);
        assert_eq!(pkt.target_ip, target_ip);
    }

    #[test]
    fn test_reply_helper() {
        let sender_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let sender_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);

        let pkt = ArpPacket::reply(sender_mac, sender_ip, target_mac, target_ip);

        assert_eq!(pkt.operation, ArpOp::Reply);
        assert_eq!(pkt.sender_mac, sender_mac);
        assert_eq!(pkt.sender_ip, sender_ip);
        assert_eq!(pkt.target_mac, target_mac);
        assert_eq!(pkt.target_ip, target_ip);
    }

    #[test]
    fn test_gratuitous_arp() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ip = Ipv4Addr::new(192, 168, 1, 1);

        let pkt = ArpPacket::gratuitous(mac, ip);

        assert_eq!(pkt.operation, ArpOp::Request);
        assert_eq!(pkt.sender_mac, mac);
        assert_eq!(pkt.sender_ip, ip);
        assert_eq!(pkt.target_mac, MacAddr::ZERO);
        assert_eq!(pkt.target_ip, ip); // Same as sender_ip
        assert!(pkt.is_gratuitous());
    }

    #[test]
    fn test_is_gratuitous() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let garp = ArpPacket::gratuitous(mac, Ipv4Addr::new(192, 168, 1, 1));
        assert!(garp.is_gratuitous());

        let normal = ArpPacket::request(
            mac,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
        );
        assert!(!normal.is_gratuitous());
    }
}

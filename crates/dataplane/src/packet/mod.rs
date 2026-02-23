//! Packet parsing infrastructure for the ruster dataplane.
//!
//! This module provides zero-copy parsers for Ethernet, ARP, IPv4, TCP, UDP,
//! and ICMP protocols. The main entry point is [`parse_packet()`], which
//! dispatches through L2 -> L3 -> L4 layers and produces a [`PacketMeta`]
//! structure that downstream stages (bridging, routing, NAT, firewall) can
//! use for forwarding decisions.

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod tcp;
pub mod udp;

use std::fmt;

// ── EtherType constants ────────────────────────────────────────────
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;

// ── IPv4 protocol constants ────────────────────────────────────────
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

// ── Core types ─────────────────────────────────────────────────────

/// Parsed packet metadata.
///
/// Downstream processing stages (L2 bridge, L3 forwarding, NAT, firewall)
/// can make forwarding decisions based solely on this structure, without
/// re-parsing the raw packet bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketMeta {
    /// Receive interface name (set by the caller, not the parser).
    pub in_ifname: String,
    /// L2 (Ethernet) information.
    pub l2: L2Info,
    /// L3 information (parsed from the Ethernet payload), if applicable.
    pub l3: Option<L3Info>,
    /// L4 information (parsed from the IPv4 payload), if applicable.
    pub l4: Option<L4Info>,
    /// Total length of the original raw packet in bytes.
    pub raw_len: usize,
}

/// L2 (Ethernet) header information.
#[derive(Debug, Clone, PartialEq)]
pub struct L2Info {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

/// L3 protocol information.
#[derive(Debug, Clone, PartialEq)]
pub enum L3Info {
    Ipv4(Ipv4Info),
    Arp(ArpInfo),
}

/// Parsed IPv4 header fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4Info {
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
    pub ttl: u8,
    pub protocol: u8,
    /// Header length in bytes (IHL * 4).
    pub header_len: usize,
    /// Total length of the IP datagram (header + data).
    pub total_len: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub checksum: u16,
    /// Byte offset from the start of the raw packet to the IPv4 payload.
    pub payload_offset: usize,
}

/// Parsed ARP message fields.
#[derive(Debug, Clone, PartialEq)]
pub struct ArpInfo {
    /// ARP operation: 1 = request, 2 = reply.
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

/// L4 protocol information.
#[derive(Debug, Clone, PartialEq)]
pub enum L4Info {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
}

/// Parsed TCP header fields.
#[derive(Debug, Clone, PartialEq)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    /// Data offset: header length in 32-bit words.
    pub data_offset: u8,
    /// TCP flags (FIN, SYN, RST, PSH, ACK, URG).
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
}

/// Parsed UDP header fields.
#[derive(Debug, Clone, PartialEq)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    /// Length of the UDP datagram (header + data) in bytes.
    pub length: u16,
    pub checksum: u16,
}

/// Parsed ICMP message fields.
#[derive(Debug, Clone, PartialEq)]
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    /// Type-specific data. For Echo Request/Reply, this contains
    /// Identifier (2 bytes) + Sequence Number (2 bytes).
    pub rest_of_header: [u8; 4],
}

// ── DropReason ─────────────────────────────────────────────────────

/// Reason a packet was dropped during parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Packet is shorter than the minimum required length.
    TooShort,
    /// Unrecognized or unsupported EtherType.
    InvalidEthertype,
    /// IPv4 header is malformed (bad version, IHL, or total length).
    InvalidIpv4Header,
    /// IPv4 header checksum verification failed.
    Ipv4ChecksumError,
    /// IPv4 TTL has reached zero.
    Ipv4TtlExpired,
    /// L3 payload is truncated (not enough bytes for the declared header).
    TruncatedL3,
    /// L4 payload is truncated (not enough bytes for the declared header).
    TruncatedL4,
    /// L3 protocol not supported by this parser.
    UnsupportedL3Protocol,
    /// L4 protocol not supported by this parser.
    UnsupportedL4Protocol,
    /// ARP message is malformed.
    InvalidArp,
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropReason::TooShort => write!(f, "packet too short"),
            DropReason::InvalidEthertype => write!(f, "invalid EtherType"),
            DropReason::InvalidIpv4Header => write!(f, "invalid IPv4 header"),
            DropReason::Ipv4ChecksumError => write!(f, "IPv4 checksum error"),
            DropReason::Ipv4TtlExpired => write!(f, "IPv4 TTL expired"),
            DropReason::TruncatedL3 => write!(f, "truncated L3 payload"),
            DropReason::TruncatedL4 => write!(f, "truncated L4 payload"),
            DropReason::UnsupportedL3Protocol => write!(f, "unsupported L3 protocol"),
            DropReason::UnsupportedL4Protocol => write!(f, "unsupported L4 protocol"),
            DropReason::InvalidArp => write!(f, "invalid ARP message"),
        }
    }
}

// ── Main dispatch function ─────────────────────────────────────────

/// Parse a raw packet byte slice into structured metadata.
///
/// The parsing proceeds layer by layer:
/// 1. Ethernet header (minimum 14 bytes)
/// 2. L3 dispatch based on EtherType:
///    - `0x0806` -> ARP
///    - `0x0800` -> IPv4
///    - other    -> L3 = None (not dropped; left for downstream)
/// 3. If IPv4, L4 dispatch based on protocol number:
///    - `1`  -> ICMP
///    - `6`  -> TCP
///    - `17` -> UDP
///    - other -> L4 = None
///
/// # Errors
///
/// Returns [`DropReason`] if the packet is malformed at any layer.
pub fn parse_packet(data: &[u8], in_ifname: &str) -> Result<PacketMeta, DropReason> {
    // ── L2: Ethernet ───────────────────────────────────────────────
    let (l2, eth_payload_offset) = ethernet::parse_ethernet(data)?;
    let eth_payload = &data[eth_payload_offset..];

    // ── L3 dispatch ────────────────────────────────────────────────
    let (l3, l4) = match l2.ethertype {
        ETHERTYPE_ARP => {
            let arp_info = arp::parse_arp(eth_payload)?;
            (Some(L3Info::Arp(arp_info)), None)
        }
        ETHERTYPE_IPV4 => {
            let ipv4_info = ipv4::parse_ipv4(eth_payload, eth_payload_offset)?;

            // ── L4 dispatch ────────────────────────────────────────
            let l4_offset = ipv4_info.payload_offset;
            let l4_data = &data[l4_offset..];
            let l4 = match ipv4_info.protocol {
                IP_PROTO_TCP => Some(L4Info::Tcp(tcp::parse_tcp(l4_data)?)),
                IP_PROTO_UDP => Some(L4Info::Udp(udp::parse_udp(l4_data)?)),
                IP_PROTO_ICMP => Some(L4Info::Icmp(icmp::parse_icmp(l4_data)?)),
                _ => None,
            };

            (Some(L3Info::Ipv4(ipv4_info)), l4)
        }
        // Unknown EtherType: do not drop, let downstream decide.
        _ => (None, None),
    };

    Ok(PacketMeta {
        in_ifname: in_ifname.to_string(),
        l2,
        l3,
        l4,
        raw_len: data.len(),
    })
}

// ── Integration tests ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: compute IPv4 header checksum and write it into the header.
    fn set_ipv4_checksum(hdr: &mut [u8]) {
        // Zero out checksum field first
        hdr[10] = 0x00;
        hdr[11] = 0x00;
        let mut sum: u32 = 0;
        for i in (0..hdr.len()).step_by(2) {
            let word = if i + 1 < hdr.len() {
                u16::from_be_bytes([hdr[i], hdr[i + 1]])
            } else {
                u16::from_be_bytes([hdr[i], 0])
            };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = (cksum & 0xFF) as u8;
    }

    /// Build a full Ethernet + IPv4 + TCP packet.
    fn make_full_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        // ── Ethernet header (14 bytes) ───────────────────────────
        // dst MAC
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // src MAC
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        // EtherType: IPv4
        pkt.extend_from_slice(&[0x08, 0x00]);

        // ── IPv4 header (20 bytes) ───────────────────────────────
        let ipv4_start = pkt.len();
        pkt.push(0x45); // Version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
                        // Total Length: 20 (IPv4) + 20 (TCP) = 40
        pkt.extend_from_slice(&[0x00, 0x28]);
        // Identification
        pkt.extend_from_slice(&[0x00, 0x01]);
        // Flags + Fragment Offset: DF
        pkt.extend_from_slice(&[0x40, 0x00]);
        // TTL: 64
        pkt.push(64);
        // Protocol: TCP (6)
        pkt.push(6);
        // Checksum placeholder
        pkt.extend_from_slice(&[0x00, 0x00]);
        // Source: 192.168.1.100
        pkt.extend_from_slice(&[192, 168, 1, 100]);
        // Destination: 10.0.0.1
        pkt.extend_from_slice(&[10, 0, 0, 1]);

        // Compute IPv4 checksum
        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // ── TCP header (20 bytes) ────────────────────────────────
        // Source Port: 49152
        pkt.extend_from_slice(&[0xC0, 0x00]);
        // Destination Port: 80
        pkt.extend_from_slice(&[0x00, 0x50]);
        // Sequence Number: 1000
        pkt.extend_from_slice(&[0x00, 0x00, 0x03, 0xE8]);
        // Acknowledgment Number: 0
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Data Offset: 5, Reserved: 0
        pkt.push(0x50);
        // Flags: SYN
        pkt.push(tcp::TCP_SYN);
        // Window: 65535
        pkt.extend_from_slice(&[0xFF, 0xFF]);
        // Checksum
        pkt.extend_from_slice(&[0x00, 0x00]);
        // Urgent Pointer
        pkt.extend_from_slice(&[0x00, 0x00]);

        pkt
    }

    /// Build a full Ethernet + IPv4 + UDP packet.
    fn make_full_udp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        // ── Ethernet header (14 bytes) ───────────────────────────
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // ── IPv4 header (20 bytes) ───────────────────────────────
        let ipv4_start = pkt.len();
        pkt.push(0x45); // Version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
                        // Total Length: 20 (IPv4) + 8 (UDP) = 28
        pkt.extend_from_slice(&[0x00, 0x1C]);
        // Identification
        pkt.extend_from_slice(&[0x00, 0x02]);
        // Flags + Fragment Offset
        pkt.extend_from_slice(&[0x00, 0x00]);
        // TTL: 128
        pkt.push(128);
        // Protocol: UDP (17)
        pkt.push(17);
        // Checksum placeholder
        pkt.extend_from_slice(&[0x00, 0x00]);
        // Source: 10.0.0.5
        pkt.extend_from_slice(&[10, 0, 0, 5]);
        // Destination: 10.0.0.1
        pkt.extend_from_slice(&[10, 0, 0, 1]);

        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // ── UDP header (8 bytes) ─────────────────────────────────
        // Source Port: 12345
        pkt.extend_from_slice(&[0x30, 0x39]);
        // Destination Port: 53
        pkt.extend_from_slice(&[0x00, 0x35]);
        // Length: 8
        pkt.extend_from_slice(&[0x00, 0x08]);
        // Checksum: 0
        pkt.extend_from_slice(&[0x00, 0x00]);

        pkt
    }

    /// Build a full Ethernet + ARP packet.
    fn make_full_arp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        // ── Ethernet header (14 bytes) ───────────────────────────
        // dst: broadcast
        pkt.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // src
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // EtherType: ARP
        pkt.extend_from_slice(&[0x08, 0x06]);

        // ── ARP payload (28 bytes) ───────────────────────────────
        pkt.extend_from_slice(&[0x00, 0x01]); // HW Type: Ethernet
        pkt.extend_from_slice(&[0x08, 0x00]); // Proto Type: IPv4
        pkt.push(0x06); // HW Addr Len: 6
        pkt.push(0x04); // Proto Addr Len: 4
        pkt.extend_from_slice(&[0x00, 0x01]); // Operation: Request
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Sender MAC
        pkt.extend_from_slice(&[192, 168, 1, 1]); // Sender IP
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Target MAC
        pkt.extend_from_slice(&[192, 168, 1, 2]); // Target IP

        pkt
    }

    #[test]
    fn full_tcp_packet() {
        let pkt = make_full_tcp_packet();
        let meta = parse_packet(&pkt, "eth0").unwrap();

        assert_eq!(meta.in_ifname, "eth0");
        assert_eq!(meta.raw_len, pkt.len());

        // L2
        assert_eq!(meta.l2.dst_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(meta.l2.src_mac, [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        assert_eq!(meta.l2.ethertype, ETHERTYPE_IPV4);

        // L3 - IPv4
        let l3 = meta.l3.as_ref().unwrap();
        match l3 {
            L3Info::Ipv4(ipv4) => {
                assert_eq!(ipv4.src_addr, [192, 168, 1, 100]);
                assert_eq!(ipv4.dst_addr, [10, 0, 0, 1]);
                assert_eq!(ipv4.ttl, 64);
                assert_eq!(ipv4.protocol, 6);
                assert_eq!(ipv4.total_len, 40);
                assert_eq!(ipv4.payload_offset, 34); // 14 + 20
            }
            _ => panic!("expected Ipv4Info"),
        }

        // L4 - TCP
        let l4 = meta.l4.as_ref().unwrap();
        match l4 {
            L4Info::Tcp(tcp_info) => {
                assert_eq!(tcp_info.src_port, 49152);
                assert_eq!(tcp_info.dst_port, 80);
                assert_eq!(tcp_info.seq_num, 1000);
                assert_eq!(tcp_info.flags, tcp::TCP_SYN);
            }
            _ => panic!("expected TcpInfo"),
        }
    }

    #[test]
    fn full_udp_packet() {
        let pkt = make_full_udp_packet();
        let meta = parse_packet(&pkt, "wan0").unwrap();

        assert_eq!(meta.in_ifname, "wan0");
        assert_eq!(meta.raw_len, pkt.len());

        // L2
        assert_eq!(meta.l2.ethertype, ETHERTYPE_IPV4);

        // L3 - IPv4
        match meta.l3.as_ref().unwrap() {
            L3Info::Ipv4(ipv4) => {
                assert_eq!(ipv4.src_addr, [10, 0, 0, 5]);
                assert_eq!(ipv4.dst_addr, [10, 0, 0, 1]);
                assert_eq!(ipv4.ttl, 128);
                assert_eq!(ipv4.protocol, 17);
                assert_eq!(ipv4.total_len, 28);
            }
            _ => panic!("expected Ipv4Info"),
        }

        // L4 - UDP
        match meta.l4.as_ref().unwrap() {
            L4Info::Udp(udp_info) => {
                assert_eq!(udp_info.src_port, 12345);
                assert_eq!(udp_info.dst_port, 53);
                assert_eq!(udp_info.length, 8);
            }
            _ => panic!("expected UdpInfo"),
        }
    }

    #[test]
    fn full_arp_packet() {
        let pkt = make_full_arp_packet();
        let meta = parse_packet(&pkt, "lan0").unwrap();

        assert_eq!(meta.in_ifname, "lan0");
        assert_eq!(meta.raw_len, pkt.len());

        // L2
        assert_eq!(meta.l2.dst_mac, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(meta.l2.ethertype, ETHERTYPE_ARP);

        // L3 - ARP
        match meta.l3.as_ref().unwrap() {
            L3Info::Arp(arp_info) => {
                assert_eq!(arp_info.operation, 1);
                assert_eq!(arp_info.sender_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                assert_eq!(arp_info.sender_ip, [192, 168, 1, 1]);
                assert_eq!(arp_info.target_ip, [192, 168, 1, 2]);
            }
            _ => panic!("expected ArpInfo"),
        }

        // L4 - None (ARP has no L4)
        assert!(meta.l4.is_none());
    }

    #[test]
    fn parse_packet_too_short() {
        let data = [0u8; 10];
        assert_eq!(parse_packet(&data, "eth0"), Err(DropReason::TooShort));
    }

    #[test]
    fn parse_packet_unknown_ethertype() {
        // 14-byte Ethernet frame with unknown EtherType (0x9999)
        let frame: [u8; 14] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // src
            0x99, 0x99, // EtherType: unknown
        ];
        let meta = parse_packet(&frame, "eth0").unwrap();
        assert!(meta.l3.is_none());
        assert!(meta.l4.is_none());
        assert_eq!(meta.l2.ethertype, 0x9999);
    }

    #[test]
    fn full_ipv4_icmp_packet() {
        let mut pkt = Vec::new();

        // ── Ethernet header (14 bytes) ───────────────────────────
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // src
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // ── IPv4 header (20 bytes) ───────────────────────────────
        let ipv4_start = pkt.len();
        pkt.push(0x45); // Version=4, IHL=5
        pkt.push(0x00);
        // Total Length: 20 (IPv4) + 8 (ICMP) = 28
        pkt.extend_from_slice(&[0x00, 0x1C]);
        pkt.extend_from_slice(&[0x00, 0x03]); // Identification
        pkt.extend_from_slice(&[0x00, 0x00]); // Flags
        pkt.push(64); // TTL
        pkt.push(1); // Protocol: ICMP
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        pkt.extend_from_slice(&[192, 168, 1, 1]); // Source
        pkt.extend_from_slice(&[192, 168, 1, 2]); // Destination

        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // ── ICMP (8 bytes) ───────────────────────────────────────
        pkt.push(0x08); // Type: Echo Request
        pkt.push(0x00); // Code: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[0x00, 0x01]); // Identifier
        pkt.extend_from_slice(&[0x00, 0x01]); // Sequence

        let meta = parse_packet(&pkt, "eth0").unwrap();

        match meta.l3.as_ref().unwrap() {
            L3Info::Ipv4(ipv4) => {
                assert_eq!(ipv4.protocol, 1);
            }
            _ => panic!("expected Ipv4Info"),
        }

        match meta.l4.as_ref().unwrap() {
            L4Info::Icmp(icmp_info) => {
                assert_eq!(icmp_info.icmp_type, 8); // Echo Request
                assert_eq!(icmp_info.icmp_code, 0);
                assert_eq!(icmp_info.rest_of_header, [0x00, 0x01, 0x00, 0x01]);
            }
            _ => panic!("expected IcmpInfo"),
        }
    }

    #[test]
    fn ipv4_unknown_l4_protocol() {
        let mut pkt = Vec::new();

        // Ethernet header
        pkt.extend_from_slice(&[0x00; 6]); // dst
        pkt.extend_from_slice(&[0x00; 6]); // src
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

        // IPv4 header with protocol=99 (unknown)
        let ipv4_start = pkt.len();
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x14]); // Total len = 20
        pkt.extend_from_slice(&[0x00, 0x00]); // ID
        pkt.extend_from_slice(&[0x00, 0x00]); // Flags
        pkt.push(64); // TTL
        pkt.push(99); // Protocol: unknown
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Src
        pkt.extend_from_slice(&[10, 0, 0, 2]); // Dst

        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        let meta = parse_packet(&pkt, "eth0").unwrap();
        assert!(meta.l3.is_some());
        assert!(meta.l4.is_none()); // Unknown protocol -> L4 = None
    }
}

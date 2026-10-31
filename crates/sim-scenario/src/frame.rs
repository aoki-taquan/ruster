//! Cold-side typed frame builders producing exact wire bytes.
//!
//! Builders never pad to the Ethernet minimum, never add IPv4 or TCP options,
//! and always compute IPv4 header, ICMPv4, UDP, and TCP checksums unless a
//! spec explicitly asks for UDP checksum zero (RFC 768 "no checksum").

use std::net::Ipv4Addr;

use ruster_core::{internet_checksum, MacAddress, ARP_ETHERTYPE, IPV4_ETHERTYPE};

/// Largest frame a scenario may build or inject, in bytes.
pub const MAX_FRAME_LEN: usize = 9216;
/// Largest IPv4 fragment offset expressible in 13 bits (8-octet units).
pub const MAX_FRAGMENT_OFFSET: u16 = 0x1fff;

const ETHERNET_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const ICMP_ECHO_LEN: usize = 8;
const UDP_LEN: usize = 8;
const TCP_LEN: usize = 20;
const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

/// Ethernet II addressing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetSpec {
    pub destination: MacAddress,
    pub source: MacAddress,
}

/// An options-free IPv4 header. Total length, protocol, and checksum are derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Spec {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub ttl: u8,
    pub identification: u16,
    /// The full former TOS octet (DSCP and ECN).
    pub tos: u8,
    pub reserved_flag: bool,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Fragment offset in 8-octet units; at most [`MAX_FRAGMENT_OFFSET`].
    pub fragment_offset: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpOperation {
    Request,
    Reply,
}

/// An Ethernet/IPv4 ARP packet (RFC 826).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpSpec {
    pub ethernet: EthernetSpec,
    pub operation: ArpOperation,
    pub sender_mac: MacAddress,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddress,
    pub target_ip: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpEchoKind {
    /// Type 8.
    Request,
    /// Type 0.
    Reply,
}

/// The TCP control bits a scenario can set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

impl TcpFlags {
    #[must_use]
    pub const fn bits(self) -> u8 {
        (self.fin as u8)
            | (self.syn as u8) << 1
            | (self.rst as u8) << 2
            | (self.psh as u8) << 3
            | (self.ack as u8) << 4
    }
}

/// A typed description of one frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameSpec {
    /// Exact bytes, including any deliberately invalid content.
    Raw(Vec<u8>),
    Ethernet {
        ethernet: EthernetSpec,
        ether_type: u16,
        payload: Vec<u8>,
    },
    Arp(ArpSpec),
    /// IPv4 with an arbitrary protocol number and opaque payload.
    Ipv4 {
        ethernet: EthernetSpec,
        ipv4: Ipv4Spec,
        protocol: u8,
        payload: Vec<u8>,
    },
    IcmpEcho {
        ethernet: EthernetSpec,
        ipv4: Ipv4Spec,
        kind: IcmpEchoKind,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    Udp {
        ethernet: EthernetSpec,
        ipv4: Ipv4Spec,
        source_port: u16,
        destination_port: u16,
        /// Transmit checksum zero instead of the computed checksum.
        zero_checksum: bool,
        payload: Vec<u8>,
    },
    /// Options-free TCP (data offset 5, urgent pointer zero).
    Tcp {
        ethernet: EthernetSpec,
        ipv4: Ipv4Spec,
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: TcpFlags,
        window: u16,
        payload: Vec<u8>,
    },
}

/// Which builder produced a [`Frame`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FrameKind {
    Raw,
    Ethernet,
    Arp,
    Ipv4,
    IcmpEcho,
    Udp,
    Tcp,
}

/// A built frame and its exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    kind: FrameKind,
    bytes: Vec<u8>,
}

impl Frame {
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// A value-free frame construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FrameBuildError {
    TooLong { limit: usize, actual: usize },
    FragmentOffsetOutOfRange,
}

impl FrameSpec {
    /// Builds the exact frame bytes.
    ///
    /// # Errors
    ///
    /// Rejects frames longer than [`MAX_FRAME_LEN`] and fragment offsets that
    /// do not fit 13 bits.
    pub fn build(&self) -> Result<Frame, FrameBuildError> {
        let (kind, bytes) = match self {
            Self::Raw(bytes) => {
                check_len(bytes.len())?;
                (FrameKind::Raw, bytes.clone())
            }
            Self::Ethernet {
                ethernet,
                ether_type,
                payload,
            } => {
                let mut frame = ethernet_header(*ethernet, *ether_type, payload.len())?;
                frame.extend_from_slice(payload);
                (FrameKind::Ethernet, frame)
            }
            Self::Arp(arp) => (FrameKind::Arp, build_arp(arp)?),
            Self::Ipv4 {
                ethernet,
                ipv4,
                protocol,
                payload,
            } => (
                FrameKind::Ipv4,
                ipv4_frame(*ethernet, ipv4, *protocol, payload.clone())?,
            ),
            Self::IcmpEcho {
                ethernet,
                ipv4,
                kind,
                identifier,
                sequence,
                payload,
            } => {
                let mut icmp = Vec::with_capacity(ICMP_ECHO_LEN + payload.len());
                icmp.push(match kind {
                    IcmpEchoKind::Request => 8,
                    IcmpEchoKind::Reply => 0,
                });
                icmp.extend_from_slice(&[0, 0, 0]);
                icmp.extend_from_slice(&identifier.to_be_bytes());
                icmp.extend_from_slice(&sequence.to_be_bytes());
                icmp.extend_from_slice(payload);
                let checksum = internet_checksum(&icmp);
                icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
                (
                    FrameKind::IcmpEcho,
                    ipv4_frame(*ethernet, ipv4, PROTOCOL_ICMP, icmp)?,
                )
            }
            Self::Udp {
                ethernet,
                ipv4,
                source_port,
                destination_port,
                zero_checksum,
                payload,
            } => {
                let length = transport_len(UDP_LEN, payload.len())?;
                let mut udp = Vec::with_capacity(usize::from(length));
                udp.extend_from_slice(&source_port.to_be_bytes());
                udp.extend_from_slice(&destination_port.to_be_bytes());
                udp.extend_from_slice(&length.to_be_bytes());
                udp.extend_from_slice(&[0, 0]);
                udp.extend_from_slice(payload);
                if !zero_checksum {
                    let checksum = match pseudo_checksum(ipv4, PROTOCOL_UDP, &udp) {
                        0 => 0xffff,
                        checksum => checksum,
                    };
                    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
                }
                (
                    FrameKind::Udp,
                    ipv4_frame(*ethernet, ipv4, PROTOCOL_UDP, udp)?,
                )
            }
            Self::Tcp {
                ethernet,
                ipv4,
                source_port,
                destination_port,
                sequence,
                acknowledgment,
                flags,
                window,
                payload,
            } => {
                let length = transport_len(TCP_LEN, payload.len())?;
                let mut tcp = Vec::with_capacity(usize::from(length));
                tcp.extend_from_slice(&source_port.to_be_bytes());
                tcp.extend_from_slice(&destination_port.to_be_bytes());
                tcp.extend_from_slice(&sequence.to_be_bytes());
                tcp.extend_from_slice(&acknowledgment.to_be_bytes());
                tcp.push(5 << 4);
                tcp.push(flags.bits());
                tcp.extend_from_slice(&window.to_be_bytes());
                tcp.extend_from_slice(&[0, 0, 0, 0]);
                tcp.extend_from_slice(payload);
                let checksum = pseudo_checksum(ipv4, PROTOCOL_TCP, &tcp);
                tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
                (
                    FrameKind::Tcp,
                    ipv4_frame(*ethernet, ipv4, PROTOCOL_TCP, tcp)?,
                )
            }
        };
        Ok(Frame { kind, bytes })
    }
}

fn check_len(actual: usize) -> Result<(), FrameBuildError> {
    if actual > MAX_FRAME_LEN {
        Err(FrameBuildError::TooLong {
            limit: MAX_FRAME_LEN,
            actual,
        })
    } else {
        Ok(())
    }
}

fn transport_len(header: usize, payload: usize) -> Result<u16, FrameBuildError> {
    let actual = ETHERNET_LEN + IPV4_LEN + header + payload;
    check_len(actual)?;
    // MAX_FRAME_LEN is far below u16::MAX, so this cannot truncate.
    Ok(u16::try_from(header + payload).unwrap_or(u16::MAX))
}

fn ethernet_header(
    ethernet: EthernetSpec,
    ether_type: u16,
    payload_len: usize,
) -> Result<Vec<u8>, FrameBuildError> {
    let total = ETHERNET_LEN + payload_len;
    check_len(total)?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&ethernet.destination.0);
    frame.extend_from_slice(&ethernet.source.0);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    Ok(frame)
}

fn build_arp(arp: &ArpSpec) -> Result<Vec<u8>, FrameBuildError> {
    let mut frame = ethernet_header(arp.ethernet, ARP_ETHERTYPE, 28)?;
    frame.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0]);
    frame.push(match arp.operation {
        ArpOperation::Request => 1,
        ArpOperation::Reply => 2,
    });
    frame.extend_from_slice(&arp.sender_mac.0);
    frame.extend_from_slice(&arp.sender_ip.octets());
    frame.extend_from_slice(&arp.target_mac.0);
    frame.extend_from_slice(&arp.target_ip.octets());
    Ok(frame)
}

fn ipv4_frame(
    ethernet: EthernetSpec,
    ipv4: &Ipv4Spec,
    protocol: u8,
    payload: Vec<u8>,
) -> Result<Vec<u8>, FrameBuildError> {
    if ipv4.fragment_offset > MAX_FRAGMENT_OFFSET {
        return Err(FrameBuildError::FragmentOffsetOutOfRange);
    }
    let mut frame = ethernet_header(ethernet, IPV4_ETHERTYPE, IPV4_LEN + payload.len())?;
    let total_len = u16::try_from(IPV4_LEN + payload.len()).unwrap_or(u16::MAX);
    let flags = u16::from(ipv4.reserved_flag) << 15
        | u16::from(ipv4.dont_fragment) << 14
        | u16::from(ipv4.more_fragments) << 13
        | ipv4.fragment_offset;
    let header_start = frame.len();
    frame.extend_from_slice(&[0x45, ipv4.tos]);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&ipv4.identification.to_be_bytes());
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(&[ipv4.ttl, protocol, 0, 0]);
    frame.extend_from_slice(&ipv4.source.octets());
    frame.extend_from_slice(&ipv4.destination.octets());
    let checksum = internet_checksum(&frame[header_start..]);
    frame[header_start + 10..header_start + 12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// RFC 768 / RFC 793 checksum over the IPv4 pseudo-header and segment.
fn pseudo_checksum(ipv4: &Ipv4Spec, protocol: u8, segment: &[u8]) -> u16 {
    let length = u16::try_from(segment.len()).unwrap_or(u16::MAX);
    let mut covered = Vec::with_capacity(12 + segment.len());
    covered.extend_from_slice(&ipv4.source.octets());
    covered.extend_from_slice(&ipv4.destination.octets());
    covered.extend_from_slice(&[0, protocol]);
    covered.extend_from_slice(&length.to_be_bytes());
    covered.extend_from_slice(segment);
    internet_checksum(&covered)
}

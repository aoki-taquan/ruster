//! Typed UDP/TCP frames for the R16 state and publication targets.
//!
//! Frames are built through the public `ruster-sim-scenario` builders, which
//! compute every checksum from scratch. Expected translated frames are built
//! the same way, so a router's incremental checksum update is compared with
//! an independent full computation.

use std::net::Ipv4Addr;

use ruster_core::{Ipv4Address, MacAddress};
use ruster_sim_scenario::{EthernetSpec, FrameSpec, Ipv4Spec, TcpFlags};

use super::targets::CaseFailure;

pub const ETHERNET_IPV4: [u8; 2] = [0x08, 0x00];
pub const IP_ID_OFFSET: usize = 18;
pub const SOURCE_PORT_OFFSET: usize = 34;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Proto {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Segment {
    pub proto: Proto,
    pub eth_source: MacAddress,
    pub eth_destination: MacAddress,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub source_port: u16,
    pub destination_port: u16,
    pub identification: u16,
    pub ttl: u8,
    pub flags: TcpFlags,
}

pub const SYN: TcpFlags = TcpFlags {
    fin: false,
    syn: true,
    rst: false,
    psh: false,
    ack: false,
};
pub const SYN_ACK: TcpFlags = TcpFlags {
    syn: true,
    ack: true,
    ..SYN
};
pub const ACK: TcpFlags = TcpFlags {
    syn: false,
    ack: true,
    ..SYN
};
pub const RST_ACK: TcpFlags = TcpFlags {
    syn: false,
    rst: true,
    ack: true,
    ..SYN
};

impl Segment {
    pub fn build(&self) -> Result<Vec<u8>, CaseFailure> {
        let ethernet = EthernetSpec {
            destination: self.eth_destination,
            source: self.eth_source,
        };
        let ipv4 = Ipv4Spec {
            source: Ipv4Addr::from(self.source.octets()),
            destination: Ipv4Addr::from(self.destination.octets()),
            ttl: self.ttl,
            identification: self.identification,
            tos: 0,
            reserved_flag: false,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
        };
        let mut payload = b"r16-".to_vec();
        payload.extend_from_slice(&self.identification.to_be_bytes());
        let spec = match self.proto {
            Proto::Udp => FrameSpec::Udp {
                ethernet,
                ipv4,
                source_port: self.source_port,
                destination_port: self.destination_port,
                zero_checksum: false,
                payload,
            },
            Proto::Tcp => FrameSpec::Tcp {
                ethernet,
                ipv4,
                source_port: self.source_port,
                destination_port: self.destination_port,
                sequence: 1_000 + u32::from(self.identification),
                acknowledgment: if self.flags.ack { 7_000 } else { 0 },
                flags: self.flags,
                window: 4_096,
                payload,
            },
        };
        spec.build()
            .map(ruster_sim_scenario::Frame::into_bytes)
            .map_err(|error| CaseFailure::new(format!("frame build: {error:?}")))
    }
}

/// IPv4 identification of a forwarded IPv4 frame, if it is one.
pub fn identification(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 34 || bytes[12..14] != ETHERNET_IPV4 {
        return None;
    }
    Some(u16::from_be_bytes([
        bytes[IP_ID_OFFSET],
        bytes[IP_ID_OFFSET + 1],
    ]))
}

pub fn source_port(bytes: &[u8]) -> Option<u16> {
    let word = bytes.get(SOURCE_PORT_OFFSET..SOURCE_PORT_OFFSET + 2)?;
    Some(u16::from_be_bytes([word[0], word[1]]))
}

/// Corruptions that a router must reject before any state lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Corruption {
    TransportChecksum,
    Ipv4HeaderChecksum,
}

pub fn corrupt(bytes: &mut [u8], corruption: Corruption) {
    match corruption {
        // The last payload octet; the transport checksum no longer matches.
        Corruption::TransportChecksum => {
            if let Some(last) = bytes.last_mut() {
                *last ^= 0x01;
            }
        }
        Corruption::Ipv4HeaderChecksum => bytes[24] ^= 0x01,
    }
}

//! The Ethernet frames that carry the client's messages, to and from the FE.
//!
//! [`ipv4`] and [`ipv6`] wrap a message in UDP, IP and Ethernet; [`read`] takes a
//! frame the FE handed over and gives the UDP payload to the client's port, with
//! where it came from.
//!
//! # Standards
//!
//! - RFC 791 and RFC 768: an IPv4 header of 20 bytes with its checksum, TTL 64, and
//!   UDP with its checksum over the pseudo-header. RFC 2131 section 4.1: a
//!   broadcast goes to 255.255.255.255 and ff:ff:ff:ff:ff:ff.
//! - RFC 8200 and RFC 768 (RFC 8200 section 8.1: the UDP checksum is required over
//!   IPv6). RFC 8415 section 7.1 and RFC 2464 section 7: ff02::1:2 is sent to the
//!   Ethernet address 33:33:00:01:00:02; hop limit 1, as the message is for the
//!   link (the relay or server is on it).
//!
//! Deviations: frames with a VLAN tag, IPv4 options or IPv4 fragments and IPv6
//! extension headers are not read; the UDP checksum of a frame read is not checked
//! (the FE checked the IP header, and a server's message is checked by its own
//! format).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const ETHERNET: usize = 14;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// One's complement sum of 16-bit words.
fn sum(mut acc: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        acc += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn udp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&source_port.to_be_bytes());
    out.extend_from_slice(&destination_port.to_be_bytes());
    out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

fn ethernet(to: [u8; 6], from: [u8; 6], ethertype: [u8; 2]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1_514);
    out.extend_from_slice(&to);
    out.extend_from_slice(&from);
    out.extend_from_slice(&ethertype);
    out
}

/// A UDP datagram from port 68 to port 67 in IPv4 and Ethernet. `to_mac` is the
/// broadcast address when `to` is 255.255.255.255.
pub fn ipv4(
    mac: [u8; 6],
    to_mac: Option<[u8; 6]>,
    from: Ipv4Addr,
    to: Ipv4Addr,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = udp(
        crate::dhcp4::CLIENT_PORT,
        crate::dhcp4::SERVER_PORT,
        payload,
    );
    let len = segment.len() as u16;
    let mut pseudo = sum(0, &from.octets());
    pseudo = sum(pseudo, &to.octets());
    pseudo += 17 + u32::from(len);
    let check = match fold(sum(pseudo, &segment)) {
        0 => 0xffff,
        c => c,
    };
    segment[6..8].copy_from_slice(&check.to_be_bytes());
    let mut header = [0_u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&(20 + len).to_be_bytes());
    header[8] = 64;
    header[9] = 17;
    header[12..16].copy_from_slice(&from.octets());
    header[16..20].copy_from_slice(&to.octets());
    let check = fold(sum(0, &header));
    header[10..12].copy_from_slice(&check.to_be_bytes());
    let mut out = ethernet(to_mac.unwrap_or(BROADCAST_MAC), mac, [0x08, 0x00]);
    out.extend_from_slice(&header);
    out.extend_from_slice(&segment);
    out
}

/// A UDP datagram from port 546 of `from` to ff02::1:2 port 547.
pub fn ipv6(mac: [u8; 6], from: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let to = crate::dhcp6::ALL_SERVERS;
    let mut segment = udp(
        crate::dhcp6::CLIENT_PORT,
        crate::dhcp6::SERVER_PORT,
        payload,
    );
    let len = segment.len() as u32;
    let mut pseudo = sum(0, &from.octets());
    pseudo = sum(pseudo, &to.octets());
    pseudo += len + 17;
    let check = match fold(sum(pseudo, &segment)) {
        0 => 0xffff,
        c => c,
    };
    segment[6..8].copy_from_slice(&check.to_be_bytes());
    let to_octets = to.octets();
    let multicast = [
        0x33,
        0x33,
        to_octets[12],
        to_octets[13],
        to_octets[14],
        to_octets[15],
    ];
    let mut out = ethernet(multicast, mac, [0x86, 0xdd]);
    out.extend_from_slice(&[0x60, 0, 0, 0]);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.push(17);
    out.push(1);
    out.extend_from_slice(&from.octets());
    out.extend_from_slice(&to_octets);
    out.extend_from_slice(&segment);
    out
}

/// What a frame the FE handed over carries to a client port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received<'a> {
    /// The Ethernet source: the server's, or the relay's or router's before it.
    pub from_mac: [u8; 6],
    pub from: IpAddr,
    /// The UDP destination port: 68 or 546.
    pub port: u16,
    pub payload: &'a [u8],
}

/// Reads an IPv4 or IPv6 frame with UDP right after the IP header.
pub fn read(frame: &[u8]) -> Option<Received<'_>> {
    let from_mac: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    let ip = frame.get(ETHERNET..)?;
    let (from, udp) = match frame.get(12..14)? {
        [0x08, 0x00] => {
            if ip.first()? != &0x45 || ip.get(9)? != &17 {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
            let flags = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]);
            if flags & 0x3fff != 0 || total < 20 {
                return None;
            }
            let from: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
            (IpAddr::from(from), ip.get(20..total)?)
        }
        [0x86, 0xdd] => {
            if ip.first()? >> 4 != 6 || ip.get(6)? != &17 {
                return None;
            }
            let len = usize::from(u16::from_be_bytes([*ip.get(4)?, *ip.get(5)?]));
            let from: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            (IpAddr::from(from), ip.get(40..40 + len)?)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]);
    let len = usize::from(u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]));
    if len < 8 {
        return None;
    }
    Some(Received {
        from_mac,
        from,
        port,
        payload: udp.get(8..len)?,
    })
}

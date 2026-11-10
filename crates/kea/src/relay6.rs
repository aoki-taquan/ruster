//! The DHCPv6 relay agent: a client's message in a frame from the FE becomes a
//! Relay-forward message to Kea, and Kea's Relay-reply becomes a frame to the
//! client.
//!
//! [`request`] takes the whole Ethernet frame the FE handed over (a client's
//! message to UDP port 547, sent to ff02::1:2) and gives the Relay-forward message
//! to send to Kea from the interface's global address, port 547: hop-count 0, the
//! interface's global address as link-address, the client's address as
//! peer-address, and the options Relay Message, Interface-Id (the interface's
//! name) and Client Link-Layer Address (the frame's source MAC). It also gives the
//! client's address and MAC, so the reply can be sent to it. [`reply`] takes the
//! Relay-reply Kea sent back and gives the client's address and the message in it;
//! [`frame`] puts that message in a frame from the interface's link-local address
//! and MAC, port 547, to the client's address and MAC, port 546.
//!
//! All of them read untrusted bytes and return an error for anything they cannot
//! read; the caller drops it. None panics on any input.
//!
//! # Standards
//!
//! - RFC 8415 section 7.1 and 7.2: the ports (546 for clients, 547 for servers and
//!   relay agents) and All_DHCP_Relay_Agents_and_Servers (ff02::1:2); section 8: a
//!   message is its type, then a transaction ID; section 9: the relay message
//!   format; section 21.1: options are a 16-bit code and length.
//! - RFC 8415 section 19.1.1: a message from a client is relayed in a
//!   Relay-forward with hop-count 0, link-address a global address of the
//!   interface, peer-address the client's source address, and a Relay Message
//!   option (21.10). Section 21.18: the Interface-Id option names the interface,
//!   and the server copies it into its Relay-reply. Section 19.2: the message in a
//!   Relay-reply's Relay Message option goes to peer-address, port 546, on the
//!   interface Interface-Id names.
//! - RFC 6939: the Client Link-Layer Address option (79) with the link-layer type of
//!   Ethernet (1) and the client's MAC.
//! - RFC 8200 and RFC 768: the UDP checksum is required over IPv6, checked on
//!   requests and computed on replies (RFC 8200 section 8.1).
//!
//! Deviations: a Relay-forward from another relay agent on the LAN is dropped (the
//! router is the only one), and so are messages a client never sends (Advertise,
//! Reply, Reconfigure, Relay-reply; RFC 8415 section 16); IPv6 with extension
//! headers is dropped; a Relay-reply is taken only with hop-count 0 and the link's
//! global address as link-address, and a reply only of a type a server sends to a
//! client (Advertise, Reply, Reconfigure); a reply is sent with Hop Limit 64 and at
//! most 1500 bytes of IPv6; the destination MAC is the one the client's last message
//! came from, not found by Neighbor Discovery.

use std::net::Ipv6Addr;

/// One interface the relay agent serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link6 {
    pub interface: String,
    pub mac: [u8; 6],
    /// The source of the replies to clients.
    pub link_local: Ipv6Addr,
    /// The link-address, and the source of the Relay-forwards to Kea.
    pub address: Ipv6Addr,
}

/// The DHCPv6 client and server ports (RFC 8415 section 7.2).
pub const CLIENT_PORT: u16 = 546;
pub const SERVER_PORT: u16 = 547;
/// The largest IPv6 packet a reply is sent in: Ethernet's MTU.
pub const MAX_PACKET: usize = 1_500;

const ETHERNET: usize = 14;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const UDP: u8 = 17;
const HOP_LIMIT: u8 = 64;
/// The fixed part of a relay message: type, hop-count, link- and peer-address.
const RELAY_HEADER: usize = 34;

// Message types (RFC 8415 section 7.3).
const ADVERTISE: u8 = 2;
const REPLY: u8 = 7;
const RECONFIGURE: u8 = 10;
const RELAY_FORW: u8 = 12;
const RELAY_REPL: u8 = 13;

// Option codes (RFC 8415 section 24, RFC 6939).
const OPTION_RELAY_MSG: u16 = 9;
const OPTION_INTERFACE_ID: u16 = 18;
const OPTION_CLIENT_LINKLAYER_ADDR: u16 = 79;
const ETHERNET_TYPE: u16 = 1;

/// Why a message is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// Not an IPv6 UDP packet to port 547 that can be read whole.
    NotDhcp,
    /// A bad UDP checksum, or none.
    Checksum,
    /// A message type the relay agent does not pass on this way.
    Type,
    /// Too short, or options that run past the end.
    Malformed,
    /// A source address a reply cannot go to.
    Source,
    /// A Relay-reply for another link, or nested.
    Link,
    /// A reply that does not fit in one packet.
    TooLong,
}

impl std::fmt::Display for Dropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NotDhcp => "not a DHCPv6 message",
            Self::Checksum => "bad checksum",
            Self::Type => "wrong message type",
            Self::Malformed => "malformed",
            Self::Source => "bad source address",
            Self::Link => "for another link",
            Self::TooLong => "too long",
        };
        f.write_str(text)
    }
}

/// A relayed request: the Relay-forward for Kea, and the client it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relayed {
    pub message: Vec<u8>,
    pub client: Ipv6Addr,
    pub client_mac: [u8; 6],
}

/// The Relay-forward for Kea, from a client's message in `frame` (Ethernet, no
/// VLAN tag) that came in on `link`.
pub fn request(link: &Link6, frame: &[u8]) -> Result<Relayed, Dropped> {
    let (source, message) = udp_payload(frame)?;
    if source.is_multicast() || source.is_unspecified() || source.is_loopback() {
        return Err(Dropped::Source);
    }
    let Some(&kind) = message.first() else {
        return Err(Dropped::Malformed);
    };
    // A message and its transaction ID (RFC 8415 section 8).
    if message.len() < 4 {
        return Err(Dropped::Malformed);
    }
    if matches!(
        kind,
        ADVERTISE | REPLY | RECONFIGURE | RELAY_FORW | RELAY_REPL
    ) {
        return Err(Dropped::Type);
    }
    let mut client_mac = [0; 6];
    client_mac.copy_from_slice(&frame[6..12]);
    let name = link.interface.as_bytes();
    let mut out = Vec::with_capacity(RELAY_HEADER + 4 + message.len() + 4 + name.len() + 12);
    out.extend_from_slice(&[RELAY_FORW, 0]);
    out.extend_from_slice(&link.address.octets());
    out.extend_from_slice(&source.octets());
    option(&mut out, OPTION_INTERFACE_ID, name);
    let mut link_layer = ETHERNET_TYPE.to_be_bytes().to_vec();
    link_layer.extend_from_slice(&client_mac);
    option(&mut out, OPTION_CLIENT_LINKLAYER_ADDR, &link_layer);
    option(&mut out, OPTION_RELAY_MSG, message);
    Ok(Relayed {
        message: out,
        client: source,
        client_mac,
    })
}

/// The client's address and the message for it, from Kea's Relay-reply `message`
/// for `link`.
pub fn reply<'a>(link: &Link6, message: &'a [u8]) -> Result<(Ipv6Addr, &'a [u8]), Dropped> {
    if message.len() < RELAY_HEADER {
        return Err(Dropped::Malformed);
    }
    if message[0] != RELAY_REPL {
        return Err(Dropped::Type);
    }
    if message[1] != 0 || address(&message[2..18]) != link.address {
        return Err(Dropped::Link);
    }
    let peer = address(&message[18..34]);
    if peer.is_multicast() || peer.is_unspecified() || peer.is_loopback() {
        return Err(Dropped::Source);
    }
    let mut inner = None;
    let mut options = &message[RELAY_HEADER..];
    while !options.is_empty() {
        if options.len() < 4 {
            return Err(Dropped::Malformed);
        }
        let code = u16::from_be_bytes([options[0], options[1]]);
        let len = usize::from(u16::from_be_bytes([options[2], options[3]]));
        let Some(value) = options.get(4..4 + len) else {
            return Err(Dropped::Malformed);
        };
        match code {
            OPTION_RELAY_MSG => inner = Some(value),
            OPTION_INTERFACE_ID if value != link.interface.as_bytes() => return Err(Dropped::Link),
            _ => {}
        }
        options = &options[4 + len..];
    }
    let inner = inner.ok_or(Dropped::Malformed)?;
    match inner.first() {
        Some(&(ADVERTISE | REPLY | RECONFIGURE)) if inner.len() >= 4 => Ok((peer, inner)),
        Some(_) if inner.len() >= 4 => Err(Dropped::Type),
        _ => Err(Dropped::Malformed),
    }
}

/// An Ethernet frame of an IPv6 UDP packet from `link`'s link-local address, port
/// 547, to `to` at `mac`, port 546.
pub fn frame(link: &Link6, mac: [u8; 6], to: Ipv6Addr, payload: &[u8]) -> Result<Vec<u8>, Dropped> {
    let udp_len = UDP_HEADER + payload.len();
    if IPV6_HEADER + udp_len > MAX_PACKET {
        return Err(Dropped::TooLong);
    }
    let mut out = Vec::with_capacity(ETHERNET + IPV6_HEADER + udp_len);
    out.extend_from_slice(&mac);
    out.extend_from_slice(&link.mac);
    out.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    // At most 1500 bytes: the lengths fit in 16 bits.
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[UDP, HOP_LIMIT]);
    out.extend_from_slice(&link.link_local.octets());
    out.extend_from_slice(&to.octets());
    let udp = out.len();
    out.extend_from_slice(&SERVER_PORT.to_be_bytes());
    out.extend_from_slice(&CLIENT_PORT.to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let sum = match checksum(link.link_local, to, &out[udp..]) {
        // RFC 768: a computed zero is sent as all ones.
        0 => 0xffff,
        sum => sum,
    };
    out[udp + 6..udp + 8].copy_from_slice(&sum.to_be_bytes());
    Ok(out)
}

fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    // A frame's payload is far below 65 536 bytes.
    let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&value[..usize::from(len)]);
}

fn address(bytes: &[u8]) -> Ipv6Addr {
    let mut out = [0; 16];
    out.copy_from_slice(&bytes[..16]);
    Ipv6Addr::from(out)
}

/// The source address and UDP payload of an IPv6 packet to port 547 in `frame`,
/// its checksum checked.
fn udp_payload(frame: &[u8]) -> Result<(Ipv6Addr, &[u8]), Dropped> {
    if frame.get(12..14) != Some(&[0x86, 0xdd][..]) || frame.len() < ETHERNET + IPV6_HEADER {
        return Err(Dropped::NotDhcp);
    }
    let ip = &frame[ETHERNET..];
    let payload_len = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
    if ip[0] >> 4 != 6 || ip[6] != UDP || IPV6_HEADER + payload_len > ip.len() {
        return Err(Dropped::NotDhcp);
    }
    let source = address(&ip[8..24]);
    let destination = address(&ip[24..40]);
    let udp = &ip[IPV6_HEADER..IPV6_HEADER + payload_len];
    if udp.len() < UDP_HEADER {
        return Err(Dropped::NotDhcp);
    }
    let length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    let to = u16::from_be_bytes([udp[2], udp[3]]);
    if to != SERVER_PORT || length < UDP_HEADER || length > udp.len() {
        return Err(Dropped::NotDhcp);
    }
    let udp = &udp[..length];
    if udp[6..8] == [0, 0] || checksum(source, destination, udp) != 0 {
        return Err(Dropped::Checksum);
    }
    Ok((source, &udp[UDP_HEADER..]))
}

/// The UDP checksum over IPv6 (RFC 8200 section 8.1) of `udp` between the two
/// addresses.
fn checksum(source: Ipv6Addr, destination: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut add = |bytes: &[u8]| {
        let mut chunks = bytes.chunks_exact(2);
        for word in chunks.by_ref() {
            sum += u64::from(u16::from_be_bytes([word[0], word[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u64::from(last) << 8;
        }
    };
    add(&source.octets());
    add(&destination.octets());
    add(&(udp.len() as u32).to_be_bytes());
    add(&[0, 0, 0, UDP]);
    add(udp);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

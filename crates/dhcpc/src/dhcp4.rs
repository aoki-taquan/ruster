//! DHCPv4 messages as a client sends and reads them (the UDP payload).
//!
//! [`Request`] builds what the client sends: DHCPDISCOVER, DHCPREQUEST,
//! DHCPDECLINE and DHCPRELEASE. [`Reply::parse`] reads a server's DHCPOFFER, DHCPACK
//! or DHCPNAK and keeps the options the client uses.
//!
//! # Standards
//!
//! - RFC 2131 section 2: the fixed fields and the magic cookie 99.130.83.99;
//!   section 4.1: the client sets the BROADCAST flag, so that a server answers to
//!   255.255.255.255 while the client has no address (the FE picks those out, but
//!   not a unicast to an address the router does not have yet). Table 5: which
//!   fields and options each message the client sends carries.
//! - RFC 2132: options 1 (subnet mask), 3 (router), 6 (DNS servers), 50 (requested
//!   address), 51 (lease time), 53 (message type), 54 (server identifier), 55
//!   (parameter request list), 57 (maximum message size), 58 and 59 (T1 and T2); pad
//!   (0) and end (255).
//!
//! Deviations: option overload (52) is not read, so options in `sname` and `file`
//! are not seen; an option given twice keeps its last value instead of being joined
//! (RFC 3396). No client identifier (61) is sent; servers then know the client by
//! its hardware address.

use std::net::Ipv4Addr;

/// The client's and the server's UDP ports.
pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;

const COOKIE: [u8; 4] = [99, 130, 83, 99];
/// The fixed part before the cookie.
const FIXED: usize = 236;
/// The BROADCAST flag.
const BROADCAST: u16 = 0x8000;
/// The largest message we take (RFC 2132 section 9.10): a whole Ethernet frame's
/// IP datagram.
pub const MAX_MESSAGE: u16 = 1_500;

/// Message types (option 53).
pub mod kind {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const DECLINE: u8 = 4;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
    pub const RELEASE: u8 = 7;
}

/// Option codes.
mod option {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const REQUESTED_ADDRESS: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETERS: u8 = 55;
    pub const MAX_SIZE: u8 = 57;
    pub const T1: u8 = 58;
    pub const T2: u8 = 59;
    pub const END: u8 = 255;
}

/// A message the client sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub kind: u8,
    pub xid: u32,
    /// Seconds since the client began the exchange.
    pub secs: u16,
    pub mac: [u8; 6],
    /// The client's address, in BOUND, RENEWING and REBINDING (and in a RELEASE).
    pub ciaddr: Ipv4Addr,
    /// Option 50.
    pub requested: Option<Ipv4Addr>,
    /// Option 54.
    pub server: Option<Ipv4Addr>,
}

impl Request {
    /// The message as the UDP payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; FIXED];
        out[0] = 1; // BOOTREQUEST
        out[1] = 1; // Ethernet
        out[2] = 6;
        out[4..8].copy_from_slice(&self.xid.to_be_bytes());
        out[8..10].copy_from_slice(&self.secs.to_be_bytes());
        // RFC 2131 section 4.4.4: DECLINE and RELEASE carry no flags.
        let flags = match self.kind {
            kind::DISCOVER | kind::REQUEST => BROADCAST,
            _ => 0,
        };
        out[10..12].copy_from_slice(&flags.to_be_bytes());
        out[12..16].copy_from_slice(&self.ciaddr.octets());
        out[28..34].copy_from_slice(&self.mac);
        out.extend_from_slice(&COOKIE);
        out.extend_from_slice(&[option::MESSAGE_TYPE, 1, self.kind]);
        if let Some(address) = self.requested {
            out.extend_from_slice(&[option::REQUESTED_ADDRESS, 4]);
            out.extend_from_slice(&address.octets());
        }
        if let Some(server) = self.server {
            out.extend_from_slice(&[option::SERVER_ID, 4]);
            out.extend_from_slice(&server.octets());
        }
        if matches!(self.kind, kind::DISCOVER | kind::REQUEST) {
            out.extend_from_slice(&[option::MAX_SIZE, 2]);
            out.extend_from_slice(&MAX_MESSAGE.to_be_bytes());
            out.extend_from_slice(&[
                option::PARAMETERS,
                6,
                option::SUBNET_MASK,
                option::ROUTER,
                option::DNS,
                option::LEASE_TIME,
                option::T1,
                option::T2,
            ]);
        }
        out.push(option::END);
        // BOOTP's least message size (RFC 1542 section 3.2.1), which some servers
        // and relays still want.
        if out.len() < 300 {
            out.resize(300, option::PAD);
        }
        out
    }
}

/// A server's reply, with the options the client uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub kind: u8,
    pub xid: u32,
    /// The address offered or leased.
    pub yiaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    pub server: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: Option<u32>,
    pub t1: Option<u32>,
    pub t2: Option<u32>,
}

impl Reply {
    /// Reads a BOOTREPLY with Ethernet addresses and a message type. `None` for
    /// anything else, or anything cut short.
    pub fn parse(payload: &[u8]) -> Option<Self> {
        let fixed = payload.get(..FIXED)?;
        if fixed[0] != 2 || fixed[1] != 1 || fixed[2] != 6 {
            return None;
        }
        if payload.get(FIXED..FIXED + 4)? != COOKIE {
            return None;
        }
        let mut reply = Reply {
            kind: 0,
            xid: u32::from_be_bytes(fixed[4..8].try_into().ok()?),
            yiaddr: address(&fixed[16..20]),
            chaddr: fixed[28..34].try_into().ok()?,
            server: None,
            subnet_mask: None,
            routers: Vec::new(),
            dns: Vec::new(),
            lease_time: None,
            t1: None,
            t2: None,
        };
        let mut rest = &payload[FIXED + 4..];
        loop {
            let (&code, after) = rest.split_first()?;
            match code {
                option::PAD => {
                    rest = after;
                    continue;
                }
                option::END => break,
                _ => {}
            }
            let (&len, after) = after.split_first()?;
            let value = after.get(..usize::from(len))?;
            rest = &after[usize::from(len)..];
            let one = || (value.len() == 4).then(|| address(value));
            let seconds = || value.try_into().ok().map(u32::from_be_bytes);
            match code {
                option::MESSAGE_TYPE if value.len() == 1 => reply.kind = value[0],
                option::SERVER_ID => reply.server = one(),
                option::SUBNET_MASK => reply.subnet_mask = one(),
                option::ROUTER => reply.routers = list(value),
                option::DNS => reply.dns = list(value),
                option::LEASE_TIME => reply.lease_time = seconds(),
                option::T1 => reply.t1 = seconds(),
                option::T2 => reply.t2 = seconds(),
                _ => {}
            }
        }
        (reply.kind != 0).then_some(reply)
    }
}

fn address(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

/// A list of addresses: a length that is not a multiple of 4 gives none.
fn list(value: &[u8]) -> Vec<Ipv4Addr> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return Vec::new();
    }
    value.chunks(4).map(address).collect()
}

/// The prefix length of a subnet mask, if its ones are contiguous.
pub fn mask_len(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let len = bits.leading_ones();
    (bits.checked_shl(len).unwrap_or(0) == 0).then_some(len as u8)
}

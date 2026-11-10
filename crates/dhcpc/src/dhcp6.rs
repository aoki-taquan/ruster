//! DHCPv6 messages as a client sends and reads them (the UDP payload).
//!
//! [`Request`] builds Solicit, Request, Renew, Rebind and Release; [`Reply::parse`]
//! reads an Advertise or Reply and keeps what the client uses.
//!
//! # Standards
//!
//! - RFC 8415 section 8: the message header (type, 3-byte transaction ID) and
//!   section 21.1 the option format. Options: Client Identifier (1) and Server
//!   Identifier (2), IA_NA (3) with IA Address (5), Option Request (6), Preference
//!   (7), Elapsed Time (8), Status Code (13), IA_PD (25) with IA Prefix (26).
//!   Section 11.4: the client's DUID is a DUID-LL (type 3) of the interface's MAC.
//! - RFC 3646 section 3: DNS Recursive Name Server (23), which the client asks for
//!   in its Option Request option.
//! - RFC 8415 section 7.1 and 7.2: the client sends from port 546 to
//!   All_DHCP_Relay_Agents_and_Servers (ff02::1:2) port 547.
//!
//! Deviations: only the first IA_NA and IA_PD of a reply, and their first address
//! and prefix, are kept (the client asks for one of each). The AFTR name (RFC 6334)
//! is not asked for: a name would need resolving first.

use std::net::Ipv6Addr;

pub const CLIENT_PORT: u16 = 546;
pub const SERVER_PORT: u16 = 547;
/// All_DHCP_Relay_Agents_and_Servers.
pub const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
/// The identity association ID the client uses for its IA_NA and its IA_PD.
pub const IAID: u32 = 1;

/// Message types.
pub mod kind {
    pub const SOLICIT: u8 = 1;
    pub const ADVERTISE: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const RENEW: u8 = 5;
    pub const REBIND: u8 = 6;
    pub const REPLY: u8 = 7;
    pub const RELEASE: u8 = 8;
}

/// Status codes (RFC 8415 section 21.13).
pub mod status {
    pub const SUCCESS: u16 = 0;
    pub const NO_ADDRS_AVAIL: u16 = 2;
    pub const NO_BINDING: u16 = 3;
    pub const NO_PREFIX_AVAIL: u16 = 6;
}

mod option {
    pub const CLIENT_ID: u16 = 1;
    pub const SERVER_ID: u16 = 2;
    pub const IA_NA: u16 = 3;
    pub const IA_ADDRESS: u16 = 5;
    pub const ORO: u16 = 6;
    pub const PREFERENCE: u16 = 7;
    pub const ELAPSED_TIME: u16 = 8;
    pub const STATUS_CODE: u16 = 13;
    pub const DNS_SERVERS: u16 = 23;
    pub const IA_PD: u16 = 25;
    pub const IA_PREFIX: u16 = 26;
}

/// A DUID-LL of a MAC address (RFC 8415 section 11.4): type 3, hardware type 1.
pub fn duid(mac: [u8; 6]) -> Vec<u8> {
    let mut out = vec![0, 3, 0, 1];
    out.extend_from_slice(&mac);
    out
}

/// An address of an IA_NA, with its lifetimes in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IaAddress {
    pub address: Ipv6Addr,
    pub preferred: u32,
    pub valid: u32,
}

/// A prefix of an IA_PD, with its lifetimes in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IaPrefix {
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub preferred: u32,
    pub valid: u32,
}

/// An IA_NA or IA_PD of a reply: its T1 and T2, its status, and what it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ia<T> {
    pub t1: u32,
    pub t2: u32,
    pub status: u16,
    pub lease: Option<T>,
}

/// A message the client sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub kind: u8,
    pub xid: u32,
    /// Hundredths of a second since the exchange began.
    pub elapsed: u16,
    pub client_id: &'a [u8],
    pub server_id: Option<&'a [u8]>,
    /// Whether to carry an IA_NA, and the address it holds.
    pub ia_na: Option<Option<IaAddress>>,
    /// Whether to carry an IA_PD, and the prefix it holds.
    pub ia_pd: Option<Option<IaPrefix>>,
}

fn put(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

impl Request<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.kind];
        out.extend_from_slice(&self.xid.to_be_bytes()[1..]);
        put(&mut out, option::CLIENT_ID, self.client_id);
        if let Some(server) = self.server_id {
            put(&mut out, option::SERVER_ID, server);
        }
        put(&mut out, option::ELAPSED_TIME, &self.elapsed.to_be_bytes());
        if self.kind != kind::RELEASE {
            put(&mut out, option::ORO, &option::DNS_SERVERS.to_be_bytes());
        }
        // RFC 8415 section 21.4 and 21.21: the client sets T1 and T2 to 0, and
        // the lifetimes of what it holds to 0 too (the server decides them).
        let ia = |held: Option<Vec<u8>>, held_code: u16| {
            let mut value = IAID.to_be_bytes().to_vec();
            value.extend_from_slice(&[0; 8]);
            if let Some(held) = held {
                put(&mut value, held_code, &held);
            }
            value
        };
        if let Some(address) = self.ia_na {
            let held = address.map(|a| {
                let mut v = a.address.octets().to_vec();
                v.extend_from_slice(&[0; 8]);
                v
            });
            put(&mut out, option::IA_NA, &ia(held, option::IA_ADDRESS));
        }
        if let Some(prefix) = self.ia_pd {
            let held = prefix.map(|p| {
                let mut v = vec![0; 8];
                v.push(p.len);
                v.extend_from_slice(&p.prefix.octets());
                v
            });
            put(&mut out, option::IA_PD, &ia(held, option::IA_PREFIX));
        }
        out
    }
}

/// An Advertise or Reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub kind: u8,
    pub xid: u32,
    pub client_id: Option<Vec<u8>>,
    pub server_id: Option<Vec<u8>>,
    pub preference: u8,
    /// The message's Status Code; Success when it has none.
    pub status: u16,
    pub ia_na: Option<Ia<IaAddress>>,
    pub ia_pd: Option<Ia<IaPrefix>>,
    pub dns: Vec<Ipv6Addr>,
}

/// The options in `bytes` as (code, value); `None` when one runs past the end.
fn options(mut bytes: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let header = bytes.get(..4)?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        out.push((code, bytes.get(4..4 + len)?));
        bytes = &bytes[4 + len..];
    }
    Some(out)
}

fn status_of(options: &[(u16, &[u8])]) -> u16 {
    options
        .iter()
        .find(|(code, _)| *code == option::STATUS_CODE)
        .and_then(|(_, v)| v.get(..2))
        .map_or(status::SUCCESS, |v| u16::from_be_bytes([v[0], v[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn address_at(bytes: &[u8], at: usize) -> Ipv6Addr {
    let octets: [u8; 16] = bytes[at..at + 16].try_into().expect("16 bytes");
    Ipv6Addr::from(octets)
}

/// An IA_NA or IA_PD whose IAID is ours, with the first of what it holds that
/// `read` takes; `None` when it is malformed or another IA's.
fn ia<T>(value: &[u8], held_code: u16, read: impl Fn(&[u8]) -> Option<T>) -> Option<Ia<T>> {
    if value.len() < 12 || u32_at(value, 0) != IAID {
        return None;
    }
    let inner = options(&value[12..])?;
    Some(Ia {
        t1: u32_at(value, 4),
        t2: u32_at(value, 8),
        status: status_of(&inner),
        lease: inner
            .iter()
            .filter(|(code, _)| *code == held_code)
            .find_map(|(_, v)| read(v)),
    })
}

impl Reply {
    /// Reads an Advertise or Reply; `None` for another message, or a malformed one.
    pub fn parse(payload: &[u8]) -> Option<Self> {
        let (&kind, rest) = payload.split_first()?;
        if kind != kind::ADVERTISE && kind != kind::REPLY {
            return None;
        }
        let xid = u32::from_be_bytes([0, *rest.first()?, *rest.get(1)?, *rest.get(2)?]);
        let list = options(&rest[3..])?;
        let mut reply = Reply {
            kind,
            xid,
            client_id: None,
            server_id: None,
            preference: 0,
            status: status_of(&list),
            ia_na: None,
            ia_pd: None,
            dns: Vec::new(),
        };
        for (code, value) in list {
            match code {
                option::CLIENT_ID => reply.client_id = Some(value.to_vec()),
                option::SERVER_ID => reply.server_id = Some(value.to_vec()),
                option::PREFERENCE if value.len() == 1 => reply.preference = value[0],
                option::DNS_SERVERS if value.len() % 16 == 0 => {
                    reply.dns = (0..value.len() / 16)
                        .map(|i| address_at(value, i * 16))
                        .collect();
                }
                option::IA_NA if reply.ia_na.is_none() => {
                    reply.ia_na = ia(value, option::IA_ADDRESS, |v| {
                        (v.len() >= 24).then(|| IaAddress {
                            address: address_at(v, 0),
                            preferred: u32_at(v, 16),
                            valid: u32_at(v, 20),
                        })
                    });
                }
                option::IA_PD if reply.ia_pd.is_none() => {
                    reply.ia_pd = ia(value, option::IA_PREFIX, |v| {
                        (v.len() >= 25 && v[8] <= 128).then(|| IaPrefix {
                            preferred: u32_at(v, 0),
                            valid: u32_at(v, 4),
                            len: v[8],
                            prefix: address_at(v, 9),
                        })
                    });
                }
                _ => {}
            }
        }
        Some(reply)
    }
}

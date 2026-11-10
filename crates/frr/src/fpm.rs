//! Reading what zebra sends on FPM: the frames, and the netlink route messages in
//! them.
//!
//! zebra's `dplane_fpm_nl` connects over TCP and sends each change to its forwarding
//! table as a frame: a 4-byte header (version 1, type 1 for netlink, and the frame's
//! length with the header, in network byte order), then one or more netlink messages
//! (an update is sent as RTM_DELROUTE and RTM_NEWROUTE in one frame). Each message
//! is a `struct nlmsghdr`, a `struct rtmsg` and route attributes, in the host's
//! byte order as with the kernel.
//!
//! The input comes from a TCP socket, so nothing in it is trusted: every length is
//! checked against what is left before it is used, a frame that is not version 1
//! netlink ends the connection ([`next_frame`]), and a message that cannot be read
//! is skipped with the reason ([`messages`]). What a route needs is kept, the rest
//! (metrics, encapsulation, MPLS) is passed over.
//!
//! # Standards
//!
//! - RFC 3549 section 2.3.2: the netlink message header, with its length aligned to 4
//!   bytes; section 3.1.1: `rtmsg` and the route attributes RTA_DST, RTA_OIF,
//!   RTA_GATEWAY, RTA_MULTIPATH (a list of `rtnexthop`, each with its own attributes)
//!   and RTA_TABLE. The values are Linux's (`linux/rtnetlink.h`).
//! - FRR's FPM framing (`fpm/fpm.h`): version 1, message type 1 (netlink).
//!
//! Deviations: only IPv4 and IPv6 routes with no source prefix are read; next-hop
//! objects (RTA_NH_ID, `fpm use-next-hop-groups`) are not, so a route that names one
//! instead of its next hops is refused; RTA_VIA (a next hop of the other family) is
//! passed over.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The FPM header's length.
pub const HEADER: usize = 4;
/// FPM version 1, and message type 1: netlink.
const VERSION: u8 = 1;
const TYPE_NETLINK: u8 = 1;

/// The netlink message types and flags used here.
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const NLMSG_HEADER: usize = 16;
const RTMSG: usize = 12;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;
const RTA_NH_ID: u16 = 30;
/// The kernel's route types.
const RTN_UNICAST: u8 = 1;
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;
/// An `rtnexthop`: length, flags, hops, ifindex.
const RTNH: usize = 8;
/// The most next hops of one route kept.
pub const HOPS_MAX: usize = 64;

/// A frame's netlink messages, or why the stream cannot be read on.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Not version 1, or not netlink.
    Kind { version: u8, kind: u8 },
    /// A length shorter than the header.
    Length(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kind { version, kind } => {
                write!(
                    f,
                    "FPM version {version} type {kind}; only version 1 netlink is read"
                )
            }
            Self::Length(len) => write!(f, "FPM frame length {len} is shorter than its header"),
        }
    }
}

/// The first frame in `buf`: its netlink messages and the bytes it takes, or `None`
/// while the frame is not all there.
pub fn next_frame(buf: &[u8]) -> Result<Option<(&[u8], usize)>, FrameError> {
    let Some(header) = buf.get(..HEADER) else {
        return Ok(None);
    };
    if header[0] != VERSION || header[1] != TYPE_NETLINK {
        return Err(FrameError::Kind {
            version: header[0],
            kind: header[1],
        });
    }
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if len < HEADER {
        return Err(FrameError::Length(len));
    }
    Ok(buf.get(HEADER..len).map(|messages| (messages, len)))
}

/// One route message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// RTM_NEWROUTE (true) or RTM_DELROUTE.
    pub new: bool,
    pub prefix: IpAddr,
    pub len: u8,
    /// The routing table: RTA_TABLE, or `rtm_table` without it.
    pub table: u32,
    pub kind: Kind,
    /// RTA_GATEWAY and RTA_OIF, or each `rtnexthop` of RTA_MULTIPATH.
    pub hops: Vec<Hop>,
}

/// What a route does with its packets (`rtm_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Unicast,
    /// Dropped silently.
    Blackhole,
    /// Dropped with a Destination Unreachable.
    Unreachable,
    /// Any other type (local, broadcast, multicast, ...).
    Other(u8),
}

/// One next hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hop {
    pub gateway: Option<IpAddr>,
    /// The kernel's interface index; in the router's namespace, a TUN device.
    pub oif: Option<u32>,
}

/// A message of a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Route(Route),
    /// Another message type or family, or a route with a source prefix: nothing
    /// for the FE.
    Ignored,
}

/// The netlink messages of one frame, in order; each is read on its own, so one
/// that cannot be read gives its reason and the rest are still read, up to where the
/// lengths stop making sense.
pub fn messages(mut bytes: &[u8]) -> Vec<Result<Message, String>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let Some(header) = bytes.get(..NLMSG_HEADER) else {
            out.push(Err(format!(
                "{} bytes left, not a netlink header",
                bytes.len()
            )));
            break;
        };
        let len = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let kind = u16::from_ne_bytes([header[4], header[5]]);
        let Some(message) = bytes.get(NLMSG_HEADER..len).filter(|_| len >= NLMSG_HEADER) else {
            out.push(Err(format!(
                "netlink length {len} does not fit the {} bytes left",
                bytes.len()
            )));
            break;
        };
        out.push(match kind {
            RTM_NEWROUTE | RTM_DELROUTE => route(kind == RTM_NEWROUTE, message),
            _ => Ok(Message::Ignored),
        });
        bytes = bytes.get(align(len)..).unwrap_or_default();
    }
    out
}

fn align(len: usize) -> usize {
    len.saturating_add(3) & !3
}

/// The attributes in `bytes`: type and value, or why they cannot be read.
fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, String> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let header = bytes
            .get(..4)
            .ok_or_else(|| format!("{} bytes left, not an attribute", bytes.len()))?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        // The top bits are NLA_F_NESTED and NLA_F_NET_BYTEORDER.
        let kind = u16::from_ne_bytes([header[2], header[3]]) & 0x3fff;
        let value = bytes
            .get(4..len)
            .filter(|_| len >= 4)
            .ok_or_else(|| format!("attribute {kind} of length {len} does not fit"))?;
        out.push((kind, value));
        bytes = bytes.get(align(len)..).unwrap_or_default();
    }
    Ok(out)
}

fn address(family: u8, value: &[u8], what: &str) -> Result<IpAddr, String> {
    match (family, value.len()) {
        (AF_INET, 4) => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(value).expect("4"),
        ))),
        (AF_INET6, 16) => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(value).expect("16"),
        ))),
        _ => Err(format!(
            "{what} of {} bytes in family {family}",
            value.len()
        )),
    }
}

fn u32_of(value: &[u8], what: &str) -> Result<u32, String> {
    <[u8; 4]>::try_from(value)
        .map(u32::from_ne_bytes)
        .map_err(|_| format!("{what} of {} bytes", value.len()))
}

/// RTM_NEWROUTE or RTM_DELROUTE after its netlink header.
fn route(new: bool, bytes: &[u8]) -> Result<Message, String> {
    let rtm = bytes
        .get(..RTMSG)
        .ok_or_else(|| format!("a route message of {} bytes", bytes.len()))?;
    let (family, len, source_len, rtm_table, rtm_type) = (rtm[0], rtm[1], rtm[2], rtm[4], rtm[7]);
    let max = match family {
        AF_INET => 32,
        AF_INET6 => 128,
        _ => return Ok(Message::Ignored),
    };
    if source_len != 0 {
        return Ok(Message::Ignored);
    }
    if len > max {
        return Err(format!("prefix length {len} in family {family}"));
    }
    let mut prefix = None;
    let mut table = u32::from(rtm_table);
    let mut gateway = None;
    let mut oif = None;
    let mut multipath = None;
    let mut object = false;
    for (kind, value) in attributes(&bytes[RTMSG..])? {
        match kind {
            RTA_DST => prefix = Some(address(family, value, "RTA_DST")?),
            RTA_TABLE => table = u32_of(value, "RTA_TABLE")?,
            RTA_GATEWAY => gateway = Some(address(family, value, "RTA_GATEWAY")?),
            RTA_OIF => oif = Some(u32_of(value, "RTA_OIF")?),
            RTA_MULTIPATH => multipath = Some(value),
            RTA_NH_ID => object = true,
            _ => {}
        }
    }
    let prefix = match prefix {
        Some(prefix) => prefix,
        None if len == 0 && family == AF_INET => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        None if len == 0 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        None => return Err(format!("no RTA_DST for a /{len}")),
    };
    if ruster_proto::table::network(prefix, len) != prefix {
        return Err(format!("{prefix}/{len} has host bits"));
    }
    let mut hops = Vec::new();
    if let Some(list) = multipath {
        hops = next_hops(family, list)?;
    } else if gateway.is_some() || oif.is_some() {
        hops.push(Hop { gateway, oif });
    }
    if new && object && hops.is_empty() {
        return Err(format!(
            "{prefix}/{len} names a next-hop object (RTA_NH_ID); set `no fpm use-next-hop-groups`"
        ));
    }
    let kind = match rtm_type {
        RTN_UNICAST => Kind::Unicast,
        RTN_BLACKHOLE => Kind::Blackhole,
        RTN_UNREACHABLE | RTN_PROHIBIT => Kind::Unreachable,
        other => Kind::Other(other),
    };
    Ok(Message::Route(Route {
        new,
        prefix,
        len,
        table,
        kind,
        hops,
    }))
}

/// The `rtnexthop`s of RTA_MULTIPATH.
fn next_hops(family: u8, mut bytes: &[u8]) -> Result<Vec<Hop>, String> {
    let mut hops = Vec::new();
    while !bytes.is_empty() {
        let header = bytes
            .get(..RTNH)
            .ok_or_else(|| format!("{} bytes left, not an rtnexthop", bytes.len()))?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let ifindex = u32::from_ne_bytes([header[4], header[5], header[6], header[7]]);
        let inner = bytes
            .get(RTNH..len)
            .filter(|_| len >= RTNH)
            .ok_or_else(|| format!("rtnexthop of length {len} does not fit"))?;
        let mut gateway = None;
        for (kind, value) in attributes(inner)? {
            if kind == RTA_GATEWAY {
                gateway = Some(address(family, value, "RTA_GATEWAY")?);
            }
        }
        if hops.len() == HOPS_MAX {
            return Err(format!("more than {HOPS_MAX} next hops"));
        }
        hops.push(Hop {
            gateway,
            oif: (ifindex != 0).then_some(ifindex),
        });
        bytes = bytes.get(align(len)..).unwrap_or_default();
    }
    Ok(hops)
}

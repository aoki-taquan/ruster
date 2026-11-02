//! rtnetlink queries of `ruster run` (cold path only).
//!
//! - Kernel address counts of one interface through one `RTM_GETADDR`
//!   dump ([`Dump::Addresses`]). Unlike `SIOCGIFADDR`, which matches only
//!   addresses whose label equals the device name, the dump sees every
//!   address of the interface index, labelled or not. IPv4 counts every
//!   address; IPv6 counts every address outside `fe80::/10`
//!   ([`address_matches`]).
//! - Kernel route counts out of one interface through one `RTM_GETROUTE`
//!   dump of every table ([`Dump::Routes`]): a route counts if its
//!   `RTA_OIF` or any `RTA_MULTIPATH` nexthop is the interface (see
//!   [`route_matches`] for the IPv6 exclusions).
//!
//! The socket sets `NETLINK_GET_STRICT_CHK` (Linux 4.20+; `ruster run`
//! needs 5.9), so the kernel validates every request strictly and filters
//! the dumps itself: address dumps by `ifa_index`, route dumps by an
//! `RTA_OIF` attribute (which the kernel matches against every nexthop,
//! multipath and nexthop objects included, `fib_info_nh_uses_dev` and
//! `fib6_info_uses_dev`). The userspace match below still runs on every
//! message (defense in depth). After any failed query the socket is
//! replaced, so an aborted dump never leaves a running dump behind that
//! would make the next request fail with `EBUSY`.
//! - Link facts of one interface index through one `RTM_GETLINK` request
//!   ([`LinkProbe`]): MTU, `IFLA_NUM_RX_QUEUES`, and the `IFF_UP` /
//!   `IFF_LOWER_UP` flags, in the caller's network namespace (a netlink
//!   socket always talks to its own namespace, unlike a sysfs mount). Used
//!   by the startup check and by the run-time link watch, which reuses one
//!   socket and one preallocated buffer so a probe never allocates.
//!
//! The FFI is five C library calls (`socket`, `send`, `getsockname`,
//! `recvfrom`, and `close` through [`std::os::fd::OwnedFd`]) in `sys`;
//! everything else parses a byte slice and is unit tested. Every datagram
//! must come from the kernel (`nl_pid == 0` from `recvfrom`), every
//! message of this request must carry this socket's port id (`nlmsg_pid`),
//! so no other process can answer for the kernel, a datagram cut by the
//! receive buffer (`MSG_TRUNC`) is refused, and an `NLMSG_DONE` with a
//! negative status fails closed.

use std::fmt;

/// `AF_INET`.
const AF_INET: u8 = 2;
/// `AF_INET6`.
const AF_INET6: u8 = 10;
/// `RTM_NEWROUTE`.
const RTM_NEWROUTE: u16 = 24;
/// `RTM_GETROUTE`.
const RTM_GETROUTE: u16 = 26;
/// `sizeof(struct rtmsg)`.
const RTMSG_LEN: usize = 12;
/// `RTA_DST`: the destination prefix (4 or 16 bytes).
const RTA_DST: u16 = 1;
/// `RTA_OIF`: the output interface index (`u32`).
const RTA_OIF: u16 = 4;
/// `RTA_MULTIPATH`: a sequence of `struct rtnexthop`.
const RTA_MULTIPATH: u16 = 9;
/// `RTA_TABLE`: the table id (`u32`, also for ids above 255).
const RTA_TABLE: u16 = 15;
/// `RTA_NH_ID`: a nexthop object id (`u32`).
const RTA_NH_ID: u16 = 30;
/// `sizeof(struct rtnexthop)`: `rtnh_len` (`u16`), `rtnh_flags`,
/// `rtnh_hops`, `rtnh_ifindex` (`int`).
const RTNEXTHOP_LEN: usize = 8;
/// `IFA_ADDRESS`: the address, or the peer of a point-to-point address.
const IFA_ADDRESS: u16 = 1;
/// `IFA_LOCAL`: the local address when a peer is set.
const IFA_LOCAL: u16 = 2;
/// `NLMSG_ERROR`.
const NLMSG_ERROR: u16 = 2;
/// `NLMSG_DONE`.
const NLMSG_DONE: u16 = 3;
/// `RTM_NEWADDR`.
const RTM_NEWADDR: u16 = 20;
/// `RTM_GETADDR`.
const RTM_GETADDR: u16 = 22;
/// `RTM_NEWLINK`.
const RTM_NEWLINK: u16 = 16;
/// `RTM_GETLINK`.
const RTM_GETLINK: u16 = 18;
/// `sizeof(struct ifinfomsg)`.
const IFINFOMSG_LEN: usize = 16;
/// `IFLA_MTU` (`u32`).
const IFLA_MTU: u16 = 4;
/// `IFLA_NUM_RX_QUEUES` (`u32`, `dev->num_rx_queues`; absent without
/// `CONFIG_RPS`).
const IFLA_NUM_RX_QUEUES: u16 = 32;
/// Attribute type bits (`NLA_TYPE_MASK`: without `NLA_F_NESTED` and
/// `NLA_F_NET_BYTEORDER`).
const NLA_TYPE_MASK: u16 = 0x3fff;
/// `IFF_UP`: administratively up.
const IFF_UP: u32 = 0x1;
/// `IFF_LOWER_UP`: the driver reports carrier.
const IFF_LOWER_UP: u32 = 0x1_0000;
/// `ENODEV` as the kernel reports it in `NLMSG_ERROR`.
pub const KERNEL_ENODEV: i32 = -19;
/// `NLM_F_REQUEST`.
const NLM_F_REQUEST: u16 = 0x1;
/// `NLM_F_DUMP` (`NLM_F_ROOT | NLM_F_MATCH`).
const NLM_F_DUMP: u16 = 0x300;
/// `NLM_F_DUMP_INTR`: the dump raced a change; its result is not
/// consistent.
const NLM_F_DUMP_INTR: u16 = 0x10;
/// `sizeof(struct nlmsghdr)`.
const HEADER_LEN: usize = 16;
/// `sizeof(struct ifaddrmsg)`.
const IFADDRMSG_LEN: usize = 8;
/// Receive buffer: the kernel sizes dump skbs to at most 32 KiB
/// (`netlink_dump` caps `max_recvmsg_len` there).
pub const RECEIVE_BUFFER: usize = 32 * 1024;
/// Dumps retried after `NLM_F_DUMP_INTR`.
const DUMP_ATTEMPTS: u32 = 3;

/// Why the dump failed. Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetlinkError {
    /// A socket call failed with this errno.
    Errno(i32),
    /// A message did not fit the receive buffer.
    Truncated,
    /// A message header or payload was malformed.
    Malformed,
    /// The kernel answered the request with this (negative) error.
    Kernel(i32),
    /// Every attempt raced a concurrent change (`NLM_F_DUMP_INTR`).
    Interrupted,
    /// The socket ended before `NLMSG_DONE`.
    EndOfStream,
    /// A datagram did not come from the kernel (sender `nl_pid != 0`, or
    /// not a netlink address).
    NotFromKernel,
    /// A message of the dump named another port id than this socket's.
    UnexpectedPort,
    /// A link reply described another interface index than requested.
    UnexpectedLink,
}

impl NetlinkError {
    /// Whether the kernel said the interface index does not exist
    /// (`ENODEV`): the device was removed from this namespace.
    pub const fn is_no_device(self) -> bool {
        matches!(self, Self::Kernel(KERNEL_ENODEV))
    }
}

impl fmt::Display for NetlinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// An address family of the dumps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    const fn af(self) -> u8 {
        match self {
            Self::Ipv4 => AF_INET,
            Self::Ipv6 => AF_INET6,
        }
    }

    /// Bytes of an address.
    const fn address_len(self) -> usize {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 16,
        }
    }
}

/// What one dump counts for one interface index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dump {
    /// `RTM_GETADDR`: addresses on the interface ([`address_matches`]).
    Addresses(Family),
    /// `RTM_GETROUTE` of every table: routes out of the interface
    /// ([`route_matches`]).
    Routes(Family),
}

/// Longest dump request: header, `rtmsg`, and one `RTA_OIF`.
pub const REQUEST_LEN: usize = HEADER_LEN + RTMSG_LEN + 8;

/// The dump request of `dump` for `ifindex`, at the front of the returned
/// array, and its length: 24 bytes for addresses (`ifaddrmsg` with
/// `ifa_index`, the strict-check filter), 36 for routes (`rtmsg` and an
/// `RTA_OIF` attribute, the strict-check device filter). Every other header
/// field is zero, as strict checking requires: every table (no `RTA_TABLE`),
/// no cached route (`RTM_F_CLONED` clear). The kernel answers an index that
/// does not exist with `ENODEV`.
pub fn dump_request(dump: Dump, sequence: u32, ifindex: u32) -> ([u8; REQUEST_LEN], usize) {
    let (kind, family, body) = match dump {
        Dump::Addresses(family) => (RTM_GETADDR, family, IFADDRMSG_LEN),
        Dump::Routes(family) => (RTM_GETROUTE, family, RTMSG_LEN + 8),
    };
    let mut request = [0_u8; REQUEST_LEN];
    let len = HEADER_LEN + body;
    let len32 = u32::try_from(len).unwrap_or(u32::MAX);
    request[0..4].copy_from_slice(&len32.to_ne_bytes());
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    // nlmsg_pid 0: addressed to the kernel. The family is the first byte
    // of both `ifaddrmsg` and `rtmsg`.
    request[HEADER_LEN] = family.af();
    match dump {
        Dump::Addresses(_) => {
            request[HEADER_LEN + 4..HEADER_LEN + 8].copy_from_slice(&ifindex.to_ne_bytes());
        }
        Dump::Routes(_) => {
            let at = HEADER_LEN + RTMSG_LEN;
            request[at..at + 2].copy_from_slice(&8_u16.to_ne_bytes());
            request[at + 2..at + 4].copy_from_slice(&RTA_OIF.to_ne_bytes());
            request[at + 4..at + 8].copy_from_slice(&ifindex.to_ne_bytes());
        }
    }
    (request, len)
}

/// Result of parsing one received datagram.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Chunk {
    /// Messages of this datagram that matched (addresses on, or routes out
    /// of, the interface).
    pub count: u32,
    /// `NLMSG_DONE` was seen.
    pub done: bool,
    /// A message carried `NLM_F_DUMP_INTR`.
    pub interrupted: bool,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let raw = bytes.get(at..at + 2)?;
    Some(u16::from_ne_bytes([raw[0], raw[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let raw = bytes.get(at..at + 4)?;
    Some(u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Parses one datagram of the dump `dump` answering `sequence` on the
/// socket with port id `port`, counting the messages that match `ifindex`
/// ([`address_matches`], [`route_matches`]). Messages of another sequence
/// are skipped, and so are other message types and families (a kernel
/// without the family answers through `rtnl_dump_all` with every family);
/// a message of this sequence for another port id fails closed.
/// `NLMSG_DONE` carrying a negative error (an aborted dump) fails closed
/// too.
pub fn parse_chunk(
    datagram: &[u8],
    sequence: u32,
    port: u32,
    dump: Dump,
    ifindex: u32,
) -> Result<Chunk, NetlinkError> {
    let mut chunk = Chunk::default();
    let mut at = 0;
    while at < datagram.len() {
        let rest = &datagram[at..];
        let len = u32_at(rest, 0).ok_or(NetlinkError::Malformed)? as usize;
        if len < HEADER_LEN || len > rest.len() {
            return Err(NetlinkError::Malformed);
        }
        let kind = u16_at(rest, 4).ok_or(NetlinkError::Malformed)?;
        let flags = u16_at(rest, 6).ok_or(NetlinkError::Malformed)?;
        let seq = u32_at(rest, 8).ok_or(NetlinkError::Malformed)?;
        let pid = u32_at(rest, 12).ok_or(NetlinkError::Malformed)?;
        let message = &rest[..len];
        if seq == sequence {
            if pid != port {
                return Err(NetlinkError::UnexpectedPort);
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                chunk.interrupted = true;
            }
            match kind {
                NLMSG_DONE => {
                    // Linux puts the dump's final status (an `int`) in the
                    // payload; negative means the dump was aborted.
                    if len >= HEADER_LEN + 4 {
                        let status = u32_at(message, HEADER_LEN).ok_or(NetlinkError::Malformed)?;
                        let status = i32::from_ne_bytes(status.to_ne_bytes());
                        if status < 0 {
                            return Err(NetlinkError::Kernel(status));
                        }
                    }
                    chunk.done = true;
                    return Ok(chunk);
                }
                NLMSG_ERROR => {
                    let error = u32_at(message, HEADER_LEN).ok_or(NetlinkError::Malformed)?;
                    let error = i32::from_ne_bytes(error.to_ne_bytes());
                    if error != 0 {
                        return Err(NetlinkError::Kernel(error));
                    }
                }
                RTM_NEWADDR => {
                    if let Dump::Addresses(family) = dump {
                        if address_matches(message, family, ifindex)? {
                            chunk.count = chunk.count.saturating_add(1);
                        }
                    }
                }
                RTM_NEWROUTE => {
                    if let Dump::Routes(family) = dump {
                        if route_matches(message, family, ifindex)? {
                            chunk.count = chunk.count.saturating_add(1);
                        }
                    }
                }
                _ => {}
            }
        }
        // NLMSG_ALIGN: 4-byte alignment between messages.
        let advance = len.div_ceil(4) * 4;
        if advance >= rest.len() {
            break;
        }
        at += advance;
    }
    Ok(chunk)
}

/// The attributes of `message` from byte `at` on, as `(type, payload)`
/// with the type bits only (`NLA_TYPE_MASK`). An attribute shorter than
/// its header or running past the message fails closed.
fn attributes<'m>(
    message: &'m [u8],
    mut at: usize,
    mut visit: impl FnMut(u16, &'m [u8]) -> Result<(), NetlinkError>,
) -> Result<(), NetlinkError> {
    while at < message.len() {
        let attr_len = usize::from(u16_at(message, at).ok_or(NetlinkError::Malformed)?);
        let attr_kind = u16_at(message, at + 2).ok_or(NetlinkError::Malformed)? & NLA_TYPE_MASK;
        if attr_len < 4 || at + attr_len > message.len() {
            return Err(NetlinkError::Malformed);
        }
        visit(attr_kind, &message[at + 4..at + attr_len])?;
        // NLA_ALIGN.
        at += attr_len.div_ceil(4) * 4;
    }
    Ok(())
}

/// Stores `payload` in an empty `slot`: a second copy of the attribute
/// fails closed.
fn once<'m>(slot: &mut Option<&'m [u8]>, payload: &'m [u8]) -> Result<(), NetlinkError> {
    if slot.replace(payload).is_some() {
        return Err(NetlinkError::Malformed);
    }
    Ok(())
}

/// A `u32` attribute payload of exactly four bytes.
fn u32_payload(payload: &[u8]) -> Result<u32, NetlinkError> {
    let value: [u8; 4] = payload.try_into().map_err(|_| NetlinkError::Malformed)?;
    Ok(u32::from_ne_bytes(value))
}

/// Whether the `RTM_NEWADDR` `message` is an address of `family` on
/// `ifindex` that counts: every IPv4 address, and every IPv6 address
/// outside the link-local `fe80::/10`. The kernel creates a link-local
/// address on every IPv6 device, and a router never forwards a packet
/// with a link-local source or destination (RFC 4291 2.5.6), so one alone
/// cannot carry traffic between the ports. The IPv6 address is
/// `IFA_LOCAL` if present (a point-to-point address, whose `IFA_ADDRESS`
/// is the peer), otherwise `IFA_ADDRESS`; neither, a duplicate, or a
/// wrong size fails closed. A message shorter than `ifaddrmsg` fails
/// closed; another family or index does not count.
pub fn address_matches(message: &[u8], family: Family, ifindex: u32) -> Result<bool, NetlinkError> {
    if message.len() < HEADER_LEN + IFADDRMSG_LEN {
        return Err(NetlinkError::Malformed);
    }
    let index = u32_at(message, HEADER_LEN + 4).ok_or(NetlinkError::Malformed)?;
    if message[HEADER_LEN] != family.af() || index != ifindex {
        return Ok(false);
    }
    if family == Family::Ipv4 {
        return Ok(true);
    }
    let mut address = None;
    let mut local = None;
    attributes(
        message,
        HEADER_LEN + IFADDRMSG_LEN,
        |kind, payload| match kind {
            IFA_ADDRESS => once(&mut address, payload),
            IFA_LOCAL => once(&mut local, payload),
            _ => Ok(()),
        },
    )?;
    for payload in [address, local].into_iter().flatten() {
        if payload.len() != family.address_len() {
            return Err(NetlinkError::Malformed);
        }
    }
    let own = local.or(address).ok_or(NetlinkError::Malformed)?;
    Ok(!is_ipv6_link_local(own, 128))
}

/// Whether the IPv6 prefix `bytes`/`len` lies inside `fe80::/10`.
fn is_ipv6_link_local(bytes: &[u8], len: u8) -> bool {
    len >= 10 && bytes.first() == Some(&0xfe) && bytes.get(1).is_some_and(|b| b & 0xc0 == 0x80)
}

/// Whether the IPv6 prefix `bytes`/`len` lies inside `ff00::/8`.
fn is_ipv6_multicast(bytes: &[u8], len: u8) -> bool {
    len >= 8 && bytes.first() == Some(&0xff)
}

/// Whether the `RTM_NEWROUTE` `message` is a route of `family` out of
/// `ifindex`, in any table (main, local, and every policy-routing table:
/// the dump has no table filter): its `RTA_OIF` is `ifindex`, or one
/// `rtnexthop` of its `RTA_MULTIPATH` is.
///
/// IPv4 counts every route type: a `local` or `broadcast` route on the
/// port exists only with an address there (refused first), and a
/// hand-made one still makes the kernel answer ARP for it.
///
/// IPv6 excludes destinations inside `fe80::/10` (the `fe80::/64` route,
/// the `local` routes of link-local addresses, and the `fe80::` anycast
/// route the kernel adds with forwarding on: link-local traffic is never
/// forwarded, RFC 4291 2.5.6) and inside `ff00::/8` (the
/// `multicast ff00::/8` route the kernel adds on every IPv6 device: it
/// selects the device for sending multicast; forwarding multicast needs a
/// multicast routing daemon, and unicast forwarding never uses it). Every
/// other IPv6 route out of the port counts, the default route learnt from
/// a Router Advertisement included.
///
/// Fails closed: a message shorter than `rtmsg`; a prefix length beyond
/// the family; a duplicated `RTA_DST`, `RTA_OIF`, `RTA_MULTIPATH`,
/// `RTA_TABLE`, or `RTA_NH_ID`; a wrongly sized one; an `rtnexthop`
/// shorter than 8 bytes or running past `RTA_MULTIPATH`; an empty
/// `RTA_MULTIPATH`; and an IPv6 prefix without `RTA_DST`. `RTA_TABLE` and
/// `RTA_NH_ID` are only size-checked. Another family does not count.
///
/// A route that names only a nexthop object (`RTA_NH_ID`, no `RTA_OIF` or
/// `RTA_MULTIPATH`: `net.ipv4.nexthop_compat_mode = 0`) counts: the request
/// filtered on `ifindex`, so the kernel returned it because one of its
/// nexthops uses the device, and userspace cannot tell otherwise (fail
/// closed; resolving the id through `RTM_GETNEXTHOP` is a follow-up).
pub fn route_matches(message: &[u8], family: Family, ifindex: u32) -> Result<bool, NetlinkError> {
    if message.len() < HEADER_LEN + RTMSG_LEN {
        return Err(NetlinkError::Malformed);
    }
    if message[HEADER_LEN] != family.af() {
        return Ok(false);
    }
    let dst_len = message[HEADER_LEN + 1];
    if usize::from(dst_len) > family.address_len() * 8 {
        return Err(NetlinkError::Malformed);
    }
    let mut dst = None;
    let mut oif = None;
    let mut multipath = None;
    let mut table = None;
    let mut nexthop_object = None;
    attributes(
        message,
        HEADER_LEN + RTMSG_LEN,
        |kind, payload| match kind {
            RTA_DST => once(&mut dst, payload),
            RTA_OIF => once(&mut oif, payload),
            RTA_MULTIPATH => once(&mut multipath, payload),
            RTA_TABLE => once(&mut table, payload),
            RTA_NH_ID => once(&mut nexthop_object, payload),
            _ => Ok(()),
        },
    )?;
    if dst.is_some_and(|dst| dst.len() != family.address_len()) {
        return Err(NetlinkError::Malformed);
    }
    for payload in [table, nexthop_object].into_iter().flatten() {
        u32_payload(payload)?;
    }
    let oif = oif.map(u32_payload).transpose()?;
    let mut through = oif == Some(ifindex);
    if let Some(nexthops) = multipath {
        through |= multipath_through(nexthops, ifindex)?;
    }
    if oif.is_none() && multipath.is_none() && nexthop_object.is_some() {
        through = true;
    }
    if family == Family::Ipv6 && dst_len != 0 {
        let dst = dst.ok_or(NetlinkError::Malformed)?;
        if is_ipv6_link_local(dst, dst_len) || is_ipv6_multicast(dst, dst_len) {
            return Ok(false);
        }
    }
    Ok(through)
}

/// Whether one `rtnexthop` of an `RTA_MULTIPATH` payload names
/// `ifindex`. Each is at least 8 bytes, inside the payload, and
/// `RTNH_ALIGN`ed (4 bytes) to the next; its nested attributes are
/// skipped.
fn multipath_through(nexthops: &[u8], ifindex: u32) -> Result<bool, NetlinkError> {
    if nexthops.is_empty() {
        return Err(NetlinkError::Malformed);
    }
    let mut through = false;
    let mut at = 0;
    while at < nexthops.len() {
        let len = usize::from(u16_at(nexthops, at).ok_or(NetlinkError::Malformed)?);
        if len < RTNEXTHOP_LEN || at + len > nexthops.len() {
            return Err(NetlinkError::Malformed);
        }
        through |= u32_at(nexthops, at + 4).ok_or(NetlinkError::Malformed)? == ifindex;
        at += len.div_ceil(4) * 4;
    }
    Ok(through)
}

/// Link facts of one interface from an `RTM_NEWLINK` reply.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkFacts {
    /// `IFLA_MTU`.
    pub mtu: u32,
    /// `IFLA_NUM_RX_QUEUES` (`dev->num_rx_queues`, the allocated RX queue
    /// count, never below the active one); `None` if the kernel omitted it.
    pub rx_queues: Option<u32>,
    /// `IFF_UP`.
    pub admin_up: bool,
    /// `IFF_LOWER_UP` (carrier).
    pub lower_up: bool,
}

impl LinkFacts {
    /// Up and with carrier: frames can pass.
    pub const fn is_up(self) -> bool {
        self.admin_up && self.lower_up
    }
}

/// The 32-byte `RTM_GETLINK` request for one interface index (not a
/// dump: the kernel answers with exactly one `RTM_NEWLINK` or an
/// `NLMSG_ERROR`, `ENODEV` if the index does not exist).
pub fn link_request(sequence: u32, ifindex: u32) -> [u8; HEADER_LEN + IFINFOMSG_LEN] {
    let mut request = [0_u8; HEADER_LEN + IFINFOMSG_LEN];
    let len = u32::try_from(request.len()).unwrap_or(u32::MAX);
    request[0..4].copy_from_slice(&len.to_ne_bytes());
    request[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
    request[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    // nlmsg_pid 0: addressed to the kernel. ifinfomsg: AF_UNSPEC, the
    // index, no flag filter.
    request[HEADER_LEN + 4..HEADER_LEN + 8].copy_from_slice(&ifindex.to_ne_bytes());
    request
}

/// Parses one datagram answering the `RTM_GETLINK` request `sequence` for
/// `ifindex` on the socket with port id `port`. `Ok(None)` if the datagram
/// holds no message of this request (a late answer to an earlier one).
///
/// Fails closed: a message of this request for another port id
/// ([`NetlinkError::UnexpectedPort`]) or another index
/// ([`NetlinkError::UnexpectedLink`]); an `NLMSG_ERROR` (including a bare
/// acknowledgement, which a request without `NLM_F_ACK` never gets); an
/// `NLMSG_DONE` (negative status as [`NetlinkError::Kernel`], otherwise
/// malformed: a single request has no dump end); any other message type; a
/// short header, `ifinfomsg`, or attribute; an attribute running past its
/// message; a duplicated or wrongly sized `IFLA_MTU`/`IFLA_NUM_RX_QUEUES`;
/// and a reply without `IFLA_MTU`.
pub fn parse_link_reply(
    datagram: &[u8],
    sequence: u32,
    port: u32,
    ifindex: u32,
) -> Result<Option<LinkFacts>, NetlinkError> {
    let mut at = 0;
    while at < datagram.len() {
        let rest = &datagram[at..];
        let len = u32_at(rest, 0).ok_or(NetlinkError::Malformed)? as usize;
        if len < HEADER_LEN || len > rest.len() {
            return Err(NetlinkError::Malformed);
        }
        let kind = u16_at(rest, 4).ok_or(NetlinkError::Malformed)?;
        let seq = u32_at(rest, 8).ok_or(NetlinkError::Malformed)?;
        let pid = u32_at(rest, 12).ok_or(NetlinkError::Malformed)?;
        let message = &rest[..len];
        if seq == sequence {
            if pid != port {
                return Err(NetlinkError::UnexpectedPort);
            }
            return match kind {
                NLMSG_ERROR => {
                    let error = u32_at(message, HEADER_LEN).ok_or(NetlinkError::Malformed)?;
                    let error = i32::from_ne_bytes(error.to_ne_bytes());
                    Err(if error == 0 {
                        NetlinkError::Malformed
                    } else {
                        NetlinkError::Kernel(error)
                    })
                }
                NLMSG_DONE => {
                    let status = u32_at(message, HEADER_LEN)
                        .map(|status| i32::from_ne_bytes(status.to_ne_bytes()));
                    Err(match status {
                        Some(status) if status < 0 => NetlinkError::Kernel(status),
                        _ => NetlinkError::Malformed,
                    })
                }
                RTM_NEWLINK => parse_link(message, ifindex).map(Some),
                _ => Err(NetlinkError::Malformed),
            };
        }
        let advance = len.div_ceil(4) * 4;
        if advance >= rest.len() {
            break;
        }
        at += advance;
    }
    Ok(None)
}

/// One `RTM_NEWLINK` message: `ifinfomsg`, then attributes.
fn parse_link(message: &[u8], ifindex: u32) -> Result<LinkFacts, NetlinkError> {
    if message.len() < HEADER_LEN + IFINFOMSG_LEN {
        return Err(NetlinkError::Malformed);
    }
    let index = u32_at(message, HEADER_LEN + 4).ok_or(NetlinkError::Malformed)?;
    if index != ifindex {
        return Err(NetlinkError::UnexpectedLink);
    }
    let flags = u32_at(message, HEADER_LEN + 8).ok_or(NetlinkError::Malformed)?;
    let mut mtu = None;
    let mut rx_queues = None;
    attributes(message, HEADER_LEN + IFINFOMSG_LEN, |kind, payload| {
        let slot = match kind {
            IFLA_MTU => &mut mtu,
            IFLA_NUM_RX_QUEUES => &mut rx_queues,
            _ => return Ok(()),
        };
        if slot.replace(u32_payload(payload)?).is_some() {
            return Err(NetlinkError::Malformed);
        }
        Ok(())
    })?;
    Ok(LinkFacts {
        mtu: mtu.ok_or(NetlinkError::Malformed)?,
        rx_queues,
        admin_up: flags & IFF_UP != 0,
        lower_up: flags & IFF_LOWER_UP != 0,
    })
}

/// Datagrams read per link query before giving up: earlier queries' late
/// answers are skipped by sequence, and the kernel answers a request while
/// handling the `send`, so a few suffice.
#[cfg(target_os = "linux")]
const LINK_DATAGRAMS: u32 = 8;

/// One reusable `NETLINK_ROUTE` socket and receive buffer for link
/// queries. Opening allocates the buffer once; [`Self::query`] performs a
/// `send` and non-blocking `recvfrom` calls only, never an allocation.
#[cfg(target_os = "linux")]
pub struct LinkProbe {
    socket: sys::RouteSocket,
    buffer: Vec<u8>,
    port: Option<u32>,
    sequence: u32,
    /// Sockets replaced after a failed query.
    reopened: u32,
}

#[cfg(target_os = "linux")]
impl LinkProbe {
    /// Opens the socket, turns on strict checking, and connects it to the
    /// kernel (`nl_pid` 0).
    pub fn open() -> Result<Self, NetlinkError> {
        Ok(Self {
            socket: Self::socket()?,
            buffer: vec![0_u8; RECEIVE_BUFFER],
            port: None,
            sequence: 0,
            reopened: 0,
        })
    }

    fn socket() -> Result<sys::RouteSocket, NetlinkError> {
        let socket = sys::RouteSocket::open()?;
        socket.strict_check()?;
        socket.connect_kernel()?;
        Ok(socket)
    }

    /// After a failed query: replaces the socket (closing the old one ends
    /// any dump the kernel still runs on it and drops queued answers), so
    /// the next query never meets `EBUSY` or a stale chunk. If a new socket
    /// cannot be opened the old one stays and the next failure tries
    /// again. No allocation (one `socket`, `setsockopt`, `connect`).
    fn recover<T>(&mut self, result: Result<T, NetlinkError>) -> Result<T, NetlinkError> {
        if result.is_err() {
            if let Ok(socket) = Self::socket() {
                self.socket = socket;
                self.port = None;
                self.reopened = self.reopened.saturating_add(1);
            }
        }
        result
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        self.sequence
    }

    /// What `dump` counts for `ifindex` (addresses on it, routes out of
    /// it), through one dump on the reused socket and buffer (no
    /// allocation; non-blocking receives: the kernel queues each next dump
    /// chunk while handing out the previous one). A dump that raced a
    /// change is retried at most [`DUMP_ATTEMPTS`] times.
    pub fn count(&mut self, dump: Dump, ifindex: u32) -> Result<u32, NetlinkError> {
        let result = self.count_once(dump, ifindex);
        self.recover(result)
    }

    fn count_once(&mut self, dump: Dump, ifindex: u32) -> Result<u32, NetlinkError> {
        for _ in 0..DUMP_ATTEMPTS {
            let sequence = self.next_sequence();
            if let Some(total) = dump_once(&self.socket, &mut self.buffer, sequence, dump, ifindex)?
            {
                return Ok(total);
            }
        }
        Err(NetlinkError::Interrupted)
    }

    /// Kernel IPv4 addresses of `ifindex` ([`Self::count`]).
    pub fn ipv4_addresses(&mut self, ifindex: u32) -> Result<u32, NetlinkError> {
        self.count(Dump::Addresses(Family::Ipv4), ifindex)
    }

    /// Link facts of `ifindex` in this socket's (the caller's) network
    /// namespace. `ENODEV` ([`NetlinkError::is_no_device`]) means the index
    /// is gone. The receive never blocks: the kernel queues its answer
    /// while handling the `send`, so an empty queue (`EAGAIN`) is an error
    /// of this query.
    pub fn query(&mut self, ifindex: u32) -> Result<LinkFacts, NetlinkError> {
        let result = self.query_once(ifindex);
        self.recover(result)
    }

    fn query_once(&mut self, ifindex: u32) -> Result<LinkFacts, NetlinkError> {
        let sequence = self.next_sequence();
        self.socket.send(&link_request(sequence, ifindex))?;
        let port = match self.port {
            Some(port) => port,
            None => {
                let port = self.socket.port_id()?;
                self.port = Some(port);
                port
            }
        };
        for _ in 0..LINK_DATAGRAMS {
            let received = self.socket.receive(&mut self.buffer, true)?;
            if received == 0 {
                return Err(NetlinkError::EndOfStream);
            }
            if received > self.buffer.len() {
                return Err(NetlinkError::Truncated);
            }
            if let Some(facts) =
                parse_link_reply(&self.buffer[..received], sequence, port, ifindex)?
            {
                return Ok(facts);
            }
        }
        Err(NetlinkError::EndOfStream)
    }
}

/// One dump on `socket`: `Ok(None)` if it raced a change
/// (`NLM_F_DUMP_INTR`). Messages of other sequences are skipped.
#[cfg(target_os = "linux")]
fn dump_once(
    socket: &sys::RouteSocket,
    buffer: &mut [u8],
    sequence: u32,
    dump: Dump,
    ifindex: u32,
) -> Result<Option<u32>, NetlinkError> {
    let (request, len) = dump_request(dump, sequence, ifindex);
    socket.send(&request[..len])?;
    // The connect bound the socket; its port id names our replies.
    let port = socket.port_id()?;
    let mut total = 0_u32;
    let mut interrupted = false;
    loop {
        let received = socket.receive(buffer, true)?;
        if received == 0 {
            return Err(NetlinkError::EndOfStream);
        }
        if received > buffer.len() {
            return Err(NetlinkError::Truncated);
        }
        let chunk = parse_chunk(&buffer[..received], sequence, port, dump, ifindex)?;
        total = total.saturating_add(chunk.count);
        interrupted |= chunk.interrupted;
        if chunk.done {
            return Ok((!interrupted).then_some(total));
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::raw::{c_int, c_void};

    use super::NetlinkError;

    const AF_NETLINK: c_int = 16;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2_000_000;
    const NETLINK_ROUTE: c_int = 0;
    /// `MSG_TRUNC` on receive: return the real datagram length.
    const MSG_TRUNC: c_int = 0x20;
    /// `MSG_DONTWAIT`: fail with `EAGAIN` instead of blocking.
    const MSG_DONTWAIT: c_int = 0x40;
    const EINTR: i32 = 4;
    /// `SOL_NETLINK`.
    const SOL_NETLINK: c_int = 270;
    /// `NETLINK_GET_STRICT_CHK` (Linux 4.20+).
    const NETLINK_GET_STRICT_CHK: c_int = 12;
    const AF_NETLINK_FAMILY: u16 = 16;

    /// Linux `struct sockaddr_nl` (12 bytes).
    #[repr(C)]
    #[derive(Default)]
    struct SockAddrNl {
        family: u16,
        pad: u16,
        pid: u32,
        groups: u32,
    }

    const SOCKADDR_NL_LEN: u32 = std::mem::size_of::<SockAddrNl>() as u32;
    const _: () = assert!(SOCKADDR_NL_LEN == 12);

    extern "C" {
        // From the C library std already links (glibc or musl), with the
        // POSIX prototypes: `int socket(int, int, int)`,
        // `ssize_t send(int, const void *, size_t, int)`,
        // `int getsockname(int, struct sockaddr *, socklen_t *)`, and
        // `ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *,
        // socklen_t *)`; `socklen_t` is a 32-bit unsigned integer.
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn send(fd: c_int, buffer: *const c_void, len: usize, flags: c_int) -> isize;
        fn getsockname(fd: c_int, address: *mut c_void, len: *mut u32) -> c_int;
        // `int connect(int, const struct sockaddr *, socklen_t)`.
        fn connect(fd: c_int, address: *const c_void, len: u32) -> c_int;
        // `int setsockopt(int, int, int, const void *, socklen_t)`.
        fn setsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            len: u32,
        ) -> c_int;
        fn recvfrom(
            fd: c_int,
            buffer: *mut c_void,
            len: usize,
            flags: c_int,
            address: *mut c_void,
            address_len: *mut u32,
        ) -> isize;
    }

    fn last_errno() -> NetlinkError {
        NetlinkError::Errno(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// One `NETLINK_ROUTE` socket, closed exactly once by [`OwnedFd`].
    pub struct RouteSocket {
        fd: OwnedFd,
    }

    impl RouteSocket {
        pub fn open() -> Result<Self, NetlinkError> {
            // SAFETY: `socket` takes three integers and returns a new fd or
            // -1; no memory is passed.
            let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
            if fd < 0 {
                return Err(last_errno());
            }
            // SAFETY: `fd` was just returned by `socket`, is open, and is
            // owned by nothing else, so `OwnedFd` may take it and close it
            // once on drop.
            Ok(Self {
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
            })
        }

        /// Turns on `NETLINK_GET_STRICT_CHK`: the kernel validates every
        /// request header and attribute and applies the dump filters.
        pub fn strict_check(&self) -> Result<(), NetlinkError> {
            let on: c_int = 1;
            // SAFETY: `on` is a live, initialized `int` that the call only
            // reads, and the length is its size (4); the fd is open (owned
            // by `self`).
            let result = unsafe {
                setsockopt(
                    self.fd.as_raw_fd(),
                    SOL_NETLINK,
                    NETLINK_GET_STRICT_CHK,
                    (&raw const on).cast(),
                    std::mem::size_of::<c_int>() as u32,
                )
            };
            if result != 0 {
                return Err(last_errno());
            }
            Ok(())
        }

        /// Connects the socket to the kernel (`nl_pid` 0, no groups), so
        /// its default destination is fixed to the kernel for its whole
        /// life (the long-lived link watch socket).
        pub fn connect_kernel(&self) -> Result<(), NetlinkError> {
            let address = SockAddrNl {
                family: AF_NETLINK_FAMILY,
                ..SockAddrNl::default()
            };
            // SAFETY: `address` is a live, initialized 12-byte `repr(C)`
            // `sockaddr_nl` that the call only reads, and `SOCKADDR_NL_LEN`
            // is its size; the fd is open (owned by `self`).
            let result = unsafe {
                connect(
                    self.fd.as_raw_fd(),
                    (&raw const address).cast(),
                    SOCKADDR_NL_LEN,
                )
            };
            if result != 0 {
                return Err(last_errno());
            }
            Ok(())
        }

        /// Sends one request datagram (to the kernel: the socket is
        /// unconnected and unbound, which netlink addresses to pid 0, or
        /// connected to pid 0).
        pub fn send(&self, request: &[u8]) -> Result<(), NetlinkError> {
            loop {
                // SAFETY: `request` is a live, initialized slice of
                // `request.len()` bytes for the duration of the call, which
                // only reads it; the fd is open (owned by `self`).
                let sent = unsafe {
                    send(
                        self.fd.as_raw_fd(),
                        request.as_ptr().cast(),
                        request.len(),
                        0,
                    )
                };
                if sent >= 0 {
                    return if sent as usize == request.len() {
                        Ok(())
                    } else {
                        Err(NetlinkError::Truncated)
                    };
                }
                let error = last_errno();
                if error != NetlinkError::Errno(EINTR) {
                    return Err(error);
                }
            }
        }

        /// The socket's netlink port id (auto-bound by the first send).
        pub fn port_id(&self) -> Result<u32, NetlinkError> {
            let mut address = SockAddrNl::default();
            let mut len = SOCKADDR_NL_LEN;
            // SAFETY: `address` is a live, exclusively borrowed 12-byte
            // `repr(C)` `sockaddr_nl` and `len` holds its size; the kernel
            // writes at most `len` bytes there and the actual size to `len`.
            // The fd is open.
            let result = unsafe {
                getsockname(self.fd.as_raw_fd(), (&raw mut address).cast(), &raw mut len)
            };
            if result != 0 {
                return Err(last_errno());
            }
            if len != SOCKADDR_NL_LEN || address.family != AF_NETLINK_FAMILY {
                return Err(NetlinkError::Malformed);
            }
            Ok(address.pid)
        }

        /// Receives one datagram into `buffer` and returns its full length
        /// (`MSG_TRUNC`), which exceeds `buffer.len()` if it was cut. A
        /// datagram from anyone but the kernel is refused. `nonblocking`
        /// adds `MSG_DONTWAIT` (an empty queue is `Errno(EAGAIN)`).
        pub fn receive(&self, buffer: &mut [u8], nonblocking: bool) -> Result<usize, NetlinkError> {
            let flags = if nonblocking {
                MSG_TRUNC | MSG_DONTWAIT
            } else {
                MSG_TRUNC
            };
            loop {
                let mut address = SockAddrNl::default();
                let mut len = SOCKADDR_NL_LEN;
                // SAFETY: `buffer` is a live, exclusively borrowed slice of
                // `buffer.len()` writable bytes, `address` a live 12-byte
                // `repr(C)` `sockaddr_nl` whose size `len` holds, all for the
                // duration of the call; the kernel writes at most those
                // sizes. The fd is open.
                let received = unsafe {
                    recvfrom(
                        self.fd.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        flags,
                        (&raw mut address).cast(),
                        &raw mut len,
                    )
                };
                if received >= 0 {
                    if len != SOCKADDR_NL_LEN
                        || address.family != AF_NETLINK_FAMILY
                        || address.pid != 0
                    {
                        return Err(NetlinkError::NotFromKernel);
                    }
                    return Ok(received as usize);
                }
                let error = last_errno();
                if error != NetlinkError::Errno(EINTR) {
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u32 = 4242;
    const V4A: Dump = Dump::Addresses(Family::Ipv4);
    const V6A: Dump = Dump::Addresses(Family::Ipv6);
    const V4R: Dump = Dump::Routes(Family::Ipv4);
    const V6R: Dump = Dump::Routes(Family::Ipv6);

    fn message(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        message_for(PORT, kind, flags, sequence, payload)
    }

    fn message_for(port: u32, kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let len = HEADER_LEN + payload.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&port.to_ne_bytes());
        bytes.extend_from_slice(payload);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes
    }

    fn address(family: u8, index: u32) -> Vec<u8> {
        let mut payload = vec![family, 24, 0, 0];
        payload.extend_from_slice(&index.to_ne_bytes());
        // An IFA_ADDRESS attribute (not interpreted), length 8.
        payload.extend_from_slice(&8_u16.to_ne_bytes());
        payload.extend_from_slice(&1_u16.to_ne_bytes());
        payload.extend_from_slice(&[192, 0, 2, 1]);
        message(RTM_NEWADDR, 0x2, 7, &payload)
    }

    #[test]
    fn request_is_an_af_inet_dump() {
        let (request, len) = dump_request(V4A, 9, 0x0102_0304);
        assert_eq!(len, 24);
        assert_eq!(&request[0..4], &24_u32.to_ne_bytes());
        assert_eq!(&request[4..6], &22_u16.to_ne_bytes());
        assert_eq!(&request[6..8], &0x301_u16.to_ne_bytes());
        assert_eq!(&request[8..12], &9_u32.to_ne_bytes());
        assert_eq!(request[16], 2);
        // prefixlen, flags, scope zero (strict checking); ifa_index is the
        // kernel's filter.
        assert_eq!(&request[17..20], &[0; 3]);
        assert_eq!(&request[20..24], &0x0102_0304_u32.to_ne_bytes());
        assert!(request[24..].iter().all(|byte| *byte == 0));
    }

    /// Route dumps carry a zero `rtmsg` but for the family (every table:
    /// `rtm_table` 0, no `RTA_TABLE`; no cached routes: `RTM_F_CLONED`
    /// clear) and one `RTA_OIF`, the kernel's device filter.
    #[test]
    fn route_and_ipv6_requests_dump_every_table() {
        for (dump, kind, len, family) in [
            (V4R, 26_u16, 36_usize, 2_u8),
            (V6R, 26, 36, 10),
            (V6A, 22, 24, 10),
        ] {
            let (request, got) = dump_request(dump, 3, 5);
            assert_eq!(got, len);
            assert_eq!(&request[0..4], &u32::try_from(len).unwrap().to_ne_bytes());
            assert_eq!(&request[4..6], &kind.to_ne_bytes());
            assert_eq!(&request[6..8], &0x301_u16.to_ne_bytes());
            assert_eq!(&request[8..12], &3_u32.to_ne_bytes());
            assert_eq!(&request[12..16], &[0; 4], "to the kernel");
            assert_eq!(request[16], family);
            if kind == 26 {
                assert!(request[17..28].iter().all(|byte| *byte == 0), "{dump:?}");
                assert_eq!(&request[28..36], &oif(5)[..], "{dump:?}");
            } else {
                assert_eq!(&request[20..24], &5_u32.to_ne_bytes());
            }
        }
    }

    fn ipv6(text: &str) -> [u8; 16] {
        text.parse::<std::net::Ipv6Addr>()
            .expect("address")
            .octets()
    }

    /// An `RTM_NEWADDR` of `family`/`index` with the given attributes.
    fn address_with(family: u8, index: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = vec![family, 64, 0, 0];
        payload.extend_from_slice(&index.to_ne_bytes());
        for attribute in attributes {
            payload.extend_from_slice(attribute);
        }
        message(RTM_NEWADDR, 0x2, 7, &payload)
    }

    /// An `RTM_NEWROUTE` of `family` with `dst_len` and attributes.
    fn route(family: u8, dst_len: u8, table: u8, attributes: &[Vec<u8>]) -> Vec<u8> {
        // rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
        // type, flags.
        let mut payload = vec![family, dst_len, 0, 0, table, 4, 0, 1];
        payload.extend_from_slice(&0_u32.to_ne_bytes());
        for attribute in attributes {
            payload.extend_from_slice(attribute);
        }
        message(RTM_NEWROUTE, 0x2, 7, &payload)
    }

    fn oif(index: u32) -> Vec<u8> {
        attribute(RTA_OIF, &index.to_ne_bytes())
    }

    /// One `rtnexthop` for `index` with a nested `RTA_GATEWAY`.
    fn nexthop(index: u32) -> Vec<u8> {
        let gateway = attribute(5, &[192, 0, 2, 1]);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u16::try_from(8 + gateway.len()).unwrap().to_ne_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&index.to_ne_bytes());
        bytes.extend(gateway);
        bytes
    }

    fn multipath(nexthops: &[Vec<u8>]) -> Vec<u8> {
        attribute(RTA_MULTIPATH, &nexthops.concat())
    }

    fn count(datagram: &[u8], dump: Dump) -> Result<u32, NetlinkError> {
        parse_chunk(datagram, 7, PORT, dump, 5).map(|chunk| chunk.count)
    }

    /// Routes in every table count (main 254, local 255, a policy-routing
    /// table above 255 through `RTA_TABLE`), by `RTA_OIF` or by one
    /// multipath nexthop; routes elsewhere, without a device (blackhole),
    /// and of the other family do not.
    #[test]
    fn routes_out_of_the_port_count_in_every_table() {
        let table = |id: u32| attribute(RTA_TABLE, &id.to_ne_bytes());
        let dst4 = attribute(RTA_DST, &[10, 0, 0, 0]);
        let mut datagram = Vec::new();
        datagram.extend(route(2, 8, 254, &[table(254), dst4.clone(), oif(5)]));
        datagram.extend(route(2, 32, 255, &[table(255), dst4.clone(), oif(5)]));
        datagram.extend(route(2, 0, 252, &[table(1000), oif(5)]));
        datagram.extend(route(2, 0, 100, &[multipath(&[nexthop(6), nexthop(5)])]));
        datagram.extend(route(2, 8, 254, &[dst4.clone(), oif(6)]));
        datagram.extend(route(2, 8, 254, &[multipath(&[nexthop(6), nexthop(7)])]));
        datagram.extend(route(2, 8, 254, std::slice::from_ref(&dst4)));
        datagram.extend(route(10, 0, 254, &[oif(5)]));
        assert_eq!(count(&datagram, V4R), Ok(4));
        // The same datagram answers nothing to an address dump.
        assert_eq!(count(&datagram, V4A), Ok(0));
        // IPv4 counts local and broadcast routes and a nexthop object
        // whose device the kernel reports (nexthop_compat_mode 1).
        let nh_id = attribute(RTA_NH_ID, &9_u32.to_ne_bytes());
        let with_object = route(2, 8, 254, &[dst4, nh_id.clone(), oif(5)]);
        assert_eq!(count(&with_object, V4R), Ok(1));
        // A nexthop object without its device (nexthop_compat_mode 0)
        // came through the kernel's device filter: counted (fail closed).
        let bare_object = route(2, 0, 254, &[nh_id]);
        assert_eq!(count(&bare_object, V4R), Ok(1));
    }

    /// IPv6: the kernel's automatic link-local and multicast routes are
    /// excluded; the default route (from a Router Advertisement), a global
    /// prefix, and a site-local or ULA prefix count.
    #[test]
    fn ipv6_routes_exclude_link_local_and_multicast() {
        let dst = |text: &str| attribute(RTA_DST, &ipv6(text));
        let excluded = [
            route(10, 64, 254, &[dst("fe80::"), oif(5)]),
            route(10, 128, 255, &[dst("fe80::1"), oif(5)]),
            route(10, 128, 255, &[dst("fe80::"), oif(5)]),
            route(10, 10, 254, &[dst("fe80::"), oif(5)]),
            route(10, 8, 255, &[dst("ff00::"), oif(5)]),
            route(10, 16, 252, &[dst("ff02::"), oif(5)]),
        ];
        for message in &excluded {
            assert_eq!(count(message, V6R), Ok(0), "{message:?}");
        }
        let counted = [
            route(10, 0, 254, &[oif(5)]),
            route(10, 64, 254, &[dst("2001:db8::"), oif(5)]),
            route(10, 9, 254, &[dst("fe80::"), oif(5)]),
            route(10, 64, 254, &[dst("fec0::"), oif(5)]),
            route(10, 48, 254, &[dst("fd00::"), multipath(&[nexthop(5)])]),
            route(10, 128, 255, &[dst("2001:db8::1"), oif(5)]),
        ];
        for message in &counted {
            assert_eq!(count(message, V6R), Ok(1), "{message:?}");
        }
        // Another device, and IPv4 messages in an IPv6 dump.
        assert_eq!(count(&route(10, 0, 254, &[oif(6)]), V6R), Ok(0));
        assert_eq!(count(&route(2, 0, 254, &[oif(5)]), V6R), Ok(0));
    }

    /// Hostile route messages fail closed.
    #[test]
    fn hostile_route_messages_fail_closed() {
        let dst4 = attribute(RTA_DST, &[10, 0, 0, 0]);
        let table = attribute(RTA_TABLE, &254_u32.to_ne_bytes());
        let nh_id = attribute(RTA_NH_ID, &1_u32.to_ne_bytes());
        let malformed = [
            // Shorter than rtmsg.
            message(RTM_NEWROUTE, 0x2, 7, &[2, 0, 0, 0, 254, 0, 0, 1]),
            // A prefix length beyond the family.
            route(2, 33, 254, &[oif(5)]),
            route(10, 129, 254, &[oif(5)]),
            // Duplicates.
            route(2, 8, 254, &[oif(5), oif(5)]),
            route(2, 8, 254, &[oif(6), oif(5)]),
            route(2, 8, 254, &[dst4.clone(), dst4.clone(), oif(5)]),
            route(2, 8, 254, &[table.clone(), table.clone(), oif(5)]),
            route(2, 8, 254, &[nh_id.clone(), nh_id.clone(), oif(5)]),
            route(
                2,
                8,
                254,
                &[multipath(&[nexthop(5)]), multipath(&[nexthop(6)])],
            ),
            // Wrong sizes.
            route(2, 8, 254, &[attribute(RTA_OIF, &5_u16.to_ne_bytes())]),
            route(2, 8, 254, &[attribute(RTA_OIF, &[5, 0, 0, 0, 0, 0, 0, 0])]),
            route(2, 8, 254, &[attribute(RTA_TABLE, &[254]), oif(5)]),
            route(2, 8, 254, &[attribute(RTA_TABLE, &[0; 8]), oif(5)]),
            route(2, 8, 254, &[attribute(RTA_NH_ID, &[1, 0]), oif(5)]),
            route(
                2,
                8,
                254,
                &[attribute(RTA_DST, &ipv6("2001:db8::")), oif(5)],
            ),
            route(10, 64, 254, &[attribute(RTA_DST, &[10, 0, 0, 0]), oif(5)]),
            // An IPv6 prefix without RTA_DST.
            route(10, 64, 254, &[oif(5)]),
            // Empty multipath, a short nexthop, one past the attribute.
            route(2, 8, 254, &[attribute(RTA_MULTIPATH, &[])]),
            route(2, 8, 254, &[attribute(RTA_MULTIPATH, &[4, 0, 0, 0])]),
            route(
                2,
                8,
                254,
                &[attribute(RTA_MULTIPATH, &{
                    let mut short = nexthop(5);
                    short[0..2].copy_from_slice(&7_u16.to_ne_bytes());
                    short
                })],
            ),
            route(
                2,
                8,
                254,
                &[attribute(RTA_MULTIPATH, &{
                    let mut long = nexthop(5);
                    long[0..2].copy_from_slice(&64_u16.to_ne_bytes());
                    long
                })],
            ),
            route(
                2,
                8,
                254,
                &[attribute(RTA_MULTIPATH, &{
                    let mut cut = nexthop(5);
                    cut.extend_from_slice(&[16, 0]);
                    cut
                })],
            ),
        ];
        for message in &malformed {
            assert_eq!(
                count(message, V4R).and(count(message, V6R)),
                Err(NetlinkError::Malformed),
                "{message:?}"
            );
        }
        // An attribute shorter than its header or past its message.
        let mut short = route(2, 8, 254, &[oif(5)]);
        let at = short.len() - 8;
        short[at..at + 2].copy_from_slice(&2_u16.to_ne_bytes());
        assert_eq!(count(&short, V4R), Err(NetlinkError::Malformed));
        let mut long = route(2, 8, 254, &[oif(5)]);
        let at = long.len() - 8;
        long[at..at + 2].copy_from_slice(&64_u16.to_ne_bytes());
        assert_eq!(count(&long, V4R), Err(NetlinkError::Malformed));
        // Flag bits of the attribute type are masked.
        let flagged = route(
            2,
            8,
            254,
            &[attribute(0x8000 | RTA_OIF, &5_u32.to_ne_bytes())],
        );
        assert_eq!(count(&flagged, V4R), Ok(1));
        // Another sequence is skipped unparsed; a foreign port id fails.
        let mut other = malformed[1].clone();
        other[8..12].copy_from_slice(&8_u32.to_ne_bytes());
        assert_eq!(count(&other, V4R), Ok(0));
        let mut foreign = route(2, 8, 254, &[oif(5)]);
        foreign[12..16].copy_from_slice(&(PORT + 1).to_ne_bytes());
        assert_eq!(count(&foreign, V4R), Err(NetlinkError::UnexpectedPort));
    }

    /// IPv6 addresses: link-local does not count, everything else does;
    /// a point-to-point address is its `IFA_LOCAL`.
    #[test]
    fn ipv6_addresses_count_all_but_link_local() {
        let addr = |text: &str| attribute(IFA_ADDRESS, &ipv6(text));
        let local = |text: &str| attribute(IFA_LOCAL, &ipv6(text));
        let mut datagram = Vec::new();
        datagram.extend(address_with(10, 5, &[addr("fe80::1")]));
        datagram.extend(address_with(10, 5, &[addr("febf::1")]));
        datagram.extend(address_with(10, 5, &[addr("2001:db8::1")]));
        datagram.extend(address_with(10, 5, &[addr("fd00::1")]));
        datagram.extend(address_with(10, 5, &[addr("fec0::1")]));
        datagram.extend(address_with(10, 6, &[addr("2001:db8::2")]));
        // Peer fe80::2, own address global: counts. Peer global, own
        // link-local: does not.
        let global_with_peer = address_with(10, 5, &[addr("fe80::2"), local("2001:db8::3")]);
        let link_local_with_peer = address_with(10, 5, &[addr("2001:db8::4"), local("fe80::4")]);
        assert_eq!(count(&global_with_peer, V6A), Ok(1));
        assert_eq!(count(&link_local_with_peer, V6A), Ok(0));
        datagram.extend(global_with_peer);
        datagram.extend(link_local_with_peer);
        // IPv4 messages in an IPv6 dump.
        datagram.extend(address(2, 5));
        assert_eq!(count(&datagram, V6A), Ok(4));
        assert_eq!(count(&datagram, V4A), Ok(1));
        let malformed = [
            address_with(10, 5, &[]),
            address_with(10, 5, &[addr("2001:db8::1"), addr("2001:db8::1")]),
            address_with(10, 5, &[local("2001:db8::1"), local("2001:db8::1")]),
            address_with(10, 5, &[attribute(IFA_ADDRESS, &[192, 0, 2, 1])]),
            address_with(10, 5, &[addr("fe80::1"), attribute(IFA_LOCAL, &[0; 4])]),
            address_with(10, 5, &[attribute(IFA_ADDRESS, &[0; 17])]),
            message(RTM_NEWADDR, 0x2, 7, &[10, 64, 0, 0]),
        ];
        for message in &malformed {
            assert_eq!(
                count(message, V6A),
                Err(NetlinkError::Malformed),
                "{message:?}"
            );
        }
        // Another interface is not parsed beyond its header.
        assert_eq!(count(&address_with(10, 6, &[]), V6A), Ok(0));
    }

    #[test]
    fn addresses_of_the_interface_are_counted_until_done() {
        let mut datagram = Vec::new();
        datagram.extend(address(2, 5));
        datagram.extend(address(2, 6));
        datagram.extend(address(10, 5)); // AF_INET6 is not counted
        datagram.extend(address(2, 5));
        assert_eq!(
            parse_chunk(&datagram, 7, PORT, V4A, 5),
            Ok(Chunk {
                count: 2,
                done: false,
                interrupted: false
            })
        );
        datagram.extend(message(NLMSG_DONE, 0x2, 7, &0_i32.to_ne_bytes()));
        // Anything after DONE is ignored.
        datagram.extend(address(2, 5));
        assert_eq!(
            parse_chunk(&datagram, 7, PORT, V4A, 5),
            Ok(Chunk {
                count: 2,
                done: true,
                interrupted: false
            })
        );
        // Another sequence is skipped entirely.
        assert_eq!(
            parse_chunk(&datagram, 8, PORT, V4A, 5),
            Ok(Chunk::default())
        );
    }

    #[test]
    fn errors_interruptions_and_malformed_input_are_typed() {
        let error = message(NLMSG_ERROR, 0, 7, &(-1_i32).to_ne_bytes());
        assert_eq!(
            parse_chunk(&error, 7, PORT, V4A, 1),
            Err(NetlinkError::Kernel(-1))
        );
        let ack = message(NLMSG_ERROR, 0, 7, &0_i32.to_ne_bytes());
        assert_eq!(parse_chunk(&ack, 7, PORT, V4A, 1), Ok(Chunk::default()));
        let interrupted = message(RTM_NEWADDR, NLM_F_DUMP_INTR, 7, &[2, 0, 0, 0, 1, 0, 0, 0]);
        let chunk = parse_chunk(&interrupted, 7, PORT, V4A, 1).expect("parsed");
        assert!(chunk.interrupted);
        assert_eq!(chunk.count, 1);
        // Length below the header, beyond the datagram, short payload.
        let mut short = address(2, 1);
        short[0..4].copy_from_slice(&8_u32.to_ne_bytes());
        assert_eq!(
            parse_chunk(&short, 7, PORT, V4A, 1),
            Err(NetlinkError::Malformed)
        );
        let mut long = address(2, 1);
        long[0..4].copy_from_slice(&4096_u32.to_ne_bytes());
        assert_eq!(
            parse_chunk(&long, 7, PORT, V4A, 1),
            Err(NetlinkError::Malformed)
        );
        let truncated = message(RTM_NEWADDR, 0, 7, &[2, 0]);
        assert_eq!(
            parse_chunk(&truncated, 7, PORT, V4A, 1),
            Err(NetlinkError::Malformed)
        );
        assert_eq!(
            parse_chunk(&[1, 2, 3], 7, PORT, V4A, 1),
            Err(NetlinkError::Malformed)
        );
        assert_eq!(parse_chunk(&[], 7, PORT, V4A, 1), Ok(Chunk::default()));
    }

    #[test]
    fn an_aborted_dump_or_a_foreign_port_fails_closed() {
        // NLMSG_DONE with a negative status (for example -EINTR): the dump
        // was cut short, its count is not trustworthy.
        let mut datagram = address(2, 5);
        datagram.extend(message(NLMSG_DONE, 0x2, 7, &(-4_i32).to_ne_bytes()));
        assert_eq!(
            parse_chunk(&datagram, 7, PORT, V4A, 5),
            Err(NetlinkError::Kernel(-4))
        );
        // A short DONE (no status) and a zero status complete the dump.
        let bare = message(NLMSG_DONE, 0x2, 7, &[]);
        assert!(parse_chunk(&bare, 7, PORT, V4A, 5).expect("done").done);
        let zero = message(NLMSG_DONE, 0x2, 7, &0_i32.to_ne_bytes());
        assert!(parse_chunk(&zero, 7, PORT, V4A, 5).expect("done").done);
        // A message of this dump for another port id.
        let foreign = message_for(PORT + 1, RTM_NEWADDR, 0x2, 7, &[2, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(
            parse_chunk(&foreign, 7, PORT, V4A, 5),
            Err(NetlinkError::UnexpectedPort)
        );
        // Another sequence is skipped whatever its port id.
        let other = message_for(PORT + 1, RTM_NEWADDR, 0x2, 8, &[2, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(parse_chunk(&other, 7, PORT, V4A, 5), Ok(Chunk::default()));
    }

    fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u16::try_from(4 + payload.len()).unwrap().to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(payload);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes
    }

    fn ifinfo(index: u32, flags: u32) -> Vec<u8> {
        let mut payload = vec![0, 0, 1, 0];
        payload.extend_from_slice(&index.to_ne_bytes());
        payload.extend_from_slice(&flags.to_ne_bytes());
        payload.extend_from_slice(&0_u32.to_ne_bytes());
        payload
    }

    fn link(index: u32, flags: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = ifinfo(index, flags);
        // IFLA_IFNAME and a nested attribute that is skipped.
        payload.extend(attribute(3, b"ra\0"));
        payload.extend(attribute(0x8000 | 18, &attribute(1, b"veth\0")));
        for attribute in attributes {
            payload.extend_from_slice(attribute);
        }
        message(RTM_NEWLINK, 0, 7, &payload)
    }

    const UP: u32 = IFF_UP | 0x40 | IFF_LOWER_UP;

    #[test]
    fn link_request_names_one_index() {
        let request = link_request(9, 0x0102_0304);
        assert_eq!(&request[0..4], &32_u32.to_ne_bytes());
        assert_eq!(&request[4..6], &18_u16.to_ne_bytes());
        assert_eq!(&request[6..8], &1_u16.to_ne_bytes(), "no dump, no ack");
        assert_eq!(&request[8..12], &9_u32.to_ne_bytes());
        assert_eq!(&request[12..16], &[0; 4], "to the kernel");
        assert_eq!(&request[16..20], &[0; 4], "AF_UNSPEC");
        assert_eq!(&request[20..24], &0x0102_0304_u32.to_ne_bytes());
        assert_eq!(&request[24..], &[0; 8]);
    }

    #[test]
    fn link_replies_parse_mtu_queues_and_state() {
        let mtu = attribute(IFLA_MTU, &1500_u32.to_ne_bytes());
        let queues = attribute(IFLA_NUM_RX_QUEUES, &4_u32.to_ne_bytes());
        let reply = link(5, UP, &[mtu.clone(), queues.clone()]);
        assert_eq!(
            parse_link_reply(&reply, 7, PORT, 5),
            Ok(Some(LinkFacts {
                mtu: 1500,
                rx_queues: Some(4),
                admin_up: true,
                lower_up: true,
            }))
        );
        // Administratively up without carrier, and down: not up.
        let no_carrier = parse_link_reply(&link(5, IFF_UP, std::slice::from_ref(&mtu)), 7, PORT, 5)
            .expect("parsed")
            .expect("facts");
        assert!(no_carrier.admin_up && !no_carrier.lower_up && !no_carrier.is_up());
        assert_eq!(no_carrier.rx_queues, None, "CONFIG_RPS off");
        let down = parse_link_reply(&link(5, 0, std::slice::from_ref(&mtu)), 7, PORT, 5)
            .expect("parsed")
            .expect("facts");
        assert!(!down.is_up());
        // A late answer of an earlier request is skipped, also when
        // followed by this one in the same datagram.
        let mut late = link(5, UP, std::slice::from_ref(&mtu));
        late[8..12].copy_from_slice(&6_u32.to_ne_bytes());
        assert_eq!(parse_link_reply(&late, 7, PORT, 5), Ok(None));
        late.extend(reply.clone());
        assert!(parse_link_reply(&late, 7, PORT, 5).expect("ok").is_some());
        assert_eq!(parse_link_reply(&[], 7, PORT, 5), Ok(None));
    }

    #[test]
    fn hostile_link_replies_fail_closed() {
        let mtu = attribute(IFLA_MTU, &1500_u32.to_ne_bytes());
        // Removed device.
        let enodev = message(NLMSG_ERROR, 0, 7, &(-19_i32).to_ne_bytes());
        let error = parse_link_reply(&enodev, 7, PORT, 5).expect_err("error");
        assert!(error.is_no_device());
        assert!(!NetlinkError::Kernel(-1).is_no_device());
        // A bare ack, a DONE (with and without a negative status), and an
        // unrelated message type of this request.
        let ack = message(NLMSG_ERROR, 0, 7, &0_i32.to_ne_bytes());
        assert_eq!(
            parse_link_reply(&ack, 7, PORT, 5),
            Err(NetlinkError::Malformed)
        );
        let done = message(NLMSG_DONE, 0x2, 7, &(-4_i32).to_ne_bytes());
        assert_eq!(
            parse_link_reply(&done, 7, PORT, 5),
            Err(NetlinkError::Kernel(-4))
        );
        let done = message(NLMSG_DONE, 0x2, 7, &0_i32.to_ne_bytes());
        assert_eq!(
            parse_link_reply(&done, 7, PORT, 5),
            Err(NetlinkError::Malformed)
        );
        // Another message type, even one shaped exactly like a valid link
        // reply, is never read as link facts.
        let mut address = link(5, UP, std::slice::from_ref(&mtu));
        address[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
        assert_eq!(
            parse_link_reply(&address, 7, PORT, 5),
            Err(NetlinkError::Malformed)
        );
        // Another sender's port id, another index.
        let mut foreign = link(5, UP, std::slice::from_ref(&mtu));
        foreign[12..16].copy_from_slice(&(PORT + 1).to_ne_bytes());
        assert_eq!(
            parse_link_reply(&foreign, 7, PORT, 5),
            Err(NetlinkError::UnexpectedPort)
        );
        assert_eq!(
            parse_link_reply(&link(6, UP, std::slice::from_ref(&mtu)), 7, PORT, 5),
            Err(NetlinkError::UnexpectedLink)
        );
        // Missing, duplicated, and wrongly sized attributes.
        for attributes in [
            vec![],
            vec![mtu.clone(), mtu.clone()],
            vec![attribute(IFLA_MTU, &1500_u16.to_ne_bytes())],
            vec![attribute(IFLA_MTU, &[0; 8])],
            vec![
                mtu.clone(),
                attribute(IFLA_NUM_RX_QUEUES, &1_u32.to_ne_bytes()),
                attribute(IFLA_NUM_RX_QUEUES, &1_u32.to_ne_bytes()),
            ],
        ] {
            assert_eq!(
                parse_link_reply(&link(5, UP, &attributes), 7, PORT, 5),
                Err(NetlinkError::Malformed),
                "{attributes:?}"
            );
        }
        // An attribute shorter than its header or running past its
        // message; a message shorter than ifinfomsg; a cut header.
        let mut short = link(5, UP, std::slice::from_ref(&mtu));
        let at = short.len() - 8;
        short[at..at + 2].copy_from_slice(&2_u16.to_ne_bytes());
        assert_eq!(
            parse_link_reply(&short, 7, PORT, 5),
            Err(NetlinkError::Malformed)
        );
        let mut long = link(5, UP, std::slice::from_ref(&mtu));
        let at = long.len() - 8;
        long[at..at + 2].copy_from_slice(&64_u16.to_ne_bytes());
        assert_eq!(
            parse_link_reply(&long, 7, PORT, 5),
            Err(NetlinkError::Malformed)
        );
        let tiny = message(RTM_NEWLINK, 0, 7, &[0; 8]);
        assert_eq!(
            parse_link_reply(&tiny, 7, PORT, 5),
            Err(NetlinkError::Malformed)
        );
        let mut overlong = link(5, UP, &[mtu]);
        overlong[0..4].copy_from_slice(&4096_u32.to_ne_bytes());
        assert_eq!(
            parse_link_reply(&overlong, 7, PORT, 5),
            Err(NetlinkError::Malformed)
        );
        assert_eq!(
            parse_link_reply(&[1, 2, 3], 7, PORT, 5),
            Err(NetlinkError::Malformed)
        );
    }

    /// The live query works unprivileged: loopback is ifindex 1 in every
    /// network namespace, and a huge index does not exist.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_link_query_answers() {
        let mut probe = LinkProbe::open().expect("socket");
        let facts = probe.query(1).expect("loopback");
        assert!(facts.mtu > 0);
        assert!(probe
            .query(i32::MAX as u32)
            .expect_err("no such index")
            .is_no_device());
        // The socket is reused, also for address dumps (connected to the
        // kernel); loopback's 127.0.0.1 may have been removed, so only
        // success is asserted, and a missing index has no address.
        assert_eq!(probe.query(1).map(|facts| facts.mtu), Ok(facts.mtu));
        assert!(probe.ipv4_addresses(1).is_ok());
        // Strict checking: the kernel filters by index and refuses one
        // that does not exist.
        assert!(probe
            .ipv4_addresses(i32::MAX as u32)
            .expect_err("filtered on a missing index")
            .is_no_device());
        assert_eq!(probe.query(1).map(|facts| facts.mtu), Ok(facts.mtu));
        // Route and IPv6 dumps of every table on the same socket (IPv6
        // only if this kernel has it).
        let has_ipv6 = std::path::Path::new("/proc/sys/net/ipv6").exists();
        for family in [Family::Ipv4, Family::Ipv6] {
            if family == Family::Ipv6 && !has_ipv6 {
                continue;
            }
            for dump in [Dump::Addresses(family), Dump::Routes(family)] {
                assert!(probe.count(dump, 1).is_ok(), "{dump:?}");
                assert!(
                    probe
                        .count(dump, i32::MAX as u32)
                        .expect_err("missing index")
                        .is_no_device(),
                    "{dump:?}"
                );
            }
        }
        assert_eq!(probe.query(1).map(|facts| facts.mtu), Ok(facts.mtu));
    }

    /// A query that fails mid-dump (here: every datagram is cut by a
    /// 16-byte buffer) replaces the socket, so whatever the kernel still
    /// had running or queued on the old one cannot wedge the next query
    /// (`EBUSY`) or answer it; with the buffer back, the next dump and link
    /// query succeed on the new socket.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_dump_replaces_the_socket() {
        let mut probe = LinkProbe::open().expect("socket");
        assert!(probe.ipv4_addresses(1).is_ok());
        let before = probe.socket.port_id().expect("port id");
        probe.buffer = vec![0_u8; 16];
        assert_eq!(
            probe.count(Dump::Routes(Family::Ipv4), 1),
            Err(NetlinkError::Truncated)
        );
        assert_eq!(probe.reopened, 1);
        probe.buffer = vec![0_u8; RECEIVE_BUFFER];
        assert!(probe.count(Dump::Routes(Family::Ipv4), 1).is_ok());
        assert_ne!(
            probe.socket.port_id().expect("port id"),
            before,
            "new socket"
        );
        assert!(probe.query(1).is_ok());
        // A link query failure replaces it too.
        assert!(probe.query(i32::MAX as u32).is_err());
        assert_eq!(probe.reopened, 2);
        assert!(probe.query(1).is_ok());
        assert_eq!(probe.reopened, 2, "success keeps the socket");
    }

    /// The live dump works unprivileged in any network namespace; the
    /// loopback device (ifindex 1) of the test host's namespace has
    /// 127.0.0.1 and local routes unless they were removed, so only
    /// success is asserted.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_dump_answers() {
        let mut probe = LinkProbe::open().expect("socket");
        assert!(probe.ipv4_addresses(1).is_ok());
        assert!(probe.count(Dump::Routes(Family::Ipv4), 1).is_ok());
        assert!(probe
            .count(Dump::Routes(Family::Ipv4), u32::MAX)
            .expect_err("missing index")
            .is_no_device());
    }
}

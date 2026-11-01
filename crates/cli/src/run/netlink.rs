//! rtnetlink queries of `ruster run` (cold path only).
//!
//! - Kernel IPv4 address count of one interface through one `RTM_GETADDR`
//!   dump (startup check). Unlike `SIOCGIFADDR`, which matches only
//!   addresses whose label equals the device name, the dump sees every IPv4
//!   address of the interface index, labelled or not.
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

/// The 24-byte `RTM_GETADDR` dump request for `AF_INET`.
pub fn dump_request(sequence: u32) -> [u8; HEADER_LEN + IFADDRMSG_LEN] {
    let mut request = [0_u8; HEADER_LEN + IFADDRMSG_LEN];
    let len = u32::try_from(request.len()).unwrap_or(u32::MAX);
    request[0..4].copy_from_slice(&len.to_ne_bytes());
    request[4..6].copy_from_slice(&RTM_GETADDR.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    // nlmsg_pid 0: addressed to the kernel.
    request[HEADER_LEN] = AF_INET;
    request
}

/// Result of parsing one received datagram.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Chunk {
    /// IPv4 addresses of the interface in this datagram.
    pub addresses: u32,
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

/// Parses one datagram of the dump answering `sequence` on the socket with
/// port id `port`, counting `AF_INET` addresses of `ifindex`. Messages of
/// another sequence are skipped; a message of this sequence for another
/// port id fails closed. `NLMSG_DONE` carrying a negative error (an
/// aborted dump) fails closed too.
pub fn parse_chunk(
    datagram: &[u8],
    sequence: u32,
    port: u32,
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
                    let family = *message.get(HEADER_LEN).ok_or(NetlinkError::Malformed)?;
                    let index = u32_at(message, HEADER_LEN + 4).ok_or(NetlinkError::Malformed)?;
                    if family == AF_INET && index == ifindex {
                        chunk.addresses = chunk.addresses.saturating_add(1);
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
    let mut at = HEADER_LEN + IFINFOMSG_LEN;
    while at < message.len() {
        let attr_len = usize::from(u16_at(message, at).ok_or(NetlinkError::Malformed)?);
        let attr_kind = u16_at(message, at + 2).ok_or(NetlinkError::Malformed)? & NLA_TYPE_MASK;
        if attr_len < 4 || at + attr_len > message.len() {
            return Err(NetlinkError::Malformed);
        }
        let payload = &message[at + 4..at + attr_len];
        let slot = match attr_kind {
            IFLA_MTU => Some(&mut mtu),
            IFLA_NUM_RX_QUEUES => Some(&mut rx_queues),
            _ => None,
        };
        if let Some(slot) = slot {
            let value: [u8; 4] = payload.try_into().map_err(|_| NetlinkError::Malformed)?;
            if slot.replace(u32::from_ne_bytes(value)).is_some() {
                return Err(NetlinkError::Malformed);
            }
        }
        // NLA_ALIGN.
        at += attr_len.div_ceil(4) * 4;
    }
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
}

#[cfg(target_os = "linux")]
impl LinkProbe {
    pub fn open() -> Result<Self, NetlinkError> {
        Ok(Self {
            socket: sys::RouteSocket::open()?,
            buffer: vec![0_u8; RECEIVE_BUFFER],
            port: None,
            sequence: 0,
        })
    }

    /// Link facts of `ifindex` in this socket's (the caller's) network
    /// namespace. `ENODEV` ([`NetlinkError::is_no_device`]) means the index
    /// is gone. The receive never blocks: the kernel queues its answer
    /// while handling the `send`, so an empty queue (`EAGAIN`) is an error
    /// of this query.
    pub fn query(&mut self, ifindex: u32) -> Result<LinkFacts, NetlinkError> {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let sequence = self.sequence;
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

/// Counts the kernel IPv4 addresses of `ifindex` in the caller's network
/// namespace, retrying a dump that raced a change at most
/// [`DUMP_ATTEMPTS`] times.
#[cfg(target_os = "linux")]
pub fn ipv4_address_count(ifindex: u32) -> Result<u32, NetlinkError> {
    let mut buffer = vec![0_u8; RECEIVE_BUFFER];
    for attempt in 0..DUMP_ATTEMPTS {
        let socket = sys::RouteSocket::open()?;
        let sequence = attempt + 1;
        socket.send(&dump_request(sequence))?;
        // The send auto-bound the socket; its port id names our replies.
        let port = socket.port_id()?;
        let mut total = 0_u32;
        let mut interrupted = false;
        loop {
            let received = socket.receive(&mut buffer, false)?;
            if received == 0 {
                return Err(NetlinkError::EndOfStream);
            }
            if received > buffer.len() {
                return Err(NetlinkError::Truncated);
            }
            let chunk = parse_chunk(&buffer[..received], sequence, port, ifindex)?;
            total = total.saturating_add(chunk.addresses);
            interrupted |= chunk.interrupted;
            if chunk.done {
                break;
            }
        }
        if !interrupted {
            return Ok(total);
        }
    }
    Err(NetlinkError::Interrupted)
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

        /// Sends one request datagram (to the kernel: the socket is
        /// unconnected and unbound, which netlink addresses to pid 0).
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
        let request = dump_request(9);
        assert_eq!(&request[0..4], &24_u32.to_ne_bytes());
        assert_eq!(&request[4..6], &22_u16.to_ne_bytes());
        assert_eq!(&request[6..8], &0x301_u16.to_ne_bytes());
        assert_eq!(&request[8..12], &9_u32.to_ne_bytes());
        assert_eq!(request[16], 2);
        assert!(request[17..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn addresses_of_the_interface_are_counted_until_done() {
        let mut datagram = Vec::new();
        datagram.extend(address(2, 5));
        datagram.extend(address(2, 6));
        datagram.extend(address(10, 5)); // AF_INET6 is not counted
        datagram.extend(address(2, 5));
        assert_eq!(
            parse_chunk(&datagram, 7, PORT, 5),
            Ok(Chunk {
                addresses: 2,
                done: false,
                interrupted: false
            })
        );
        datagram.extend(message(NLMSG_DONE, 0x2, 7, &0_i32.to_ne_bytes()));
        // Anything after DONE is ignored.
        datagram.extend(address(2, 5));
        assert_eq!(
            parse_chunk(&datagram, 7, PORT, 5),
            Ok(Chunk {
                addresses: 2,
                done: true,
                interrupted: false
            })
        );
        // Another sequence is skipped entirely.
        assert_eq!(parse_chunk(&datagram, 8, PORT, 5), Ok(Chunk::default()));
    }

    #[test]
    fn errors_interruptions_and_malformed_input_are_typed() {
        let error = message(NLMSG_ERROR, 0, 7, &(-1_i32).to_ne_bytes());
        assert_eq!(
            parse_chunk(&error, 7, PORT, 1),
            Err(NetlinkError::Kernel(-1))
        );
        let ack = message(NLMSG_ERROR, 0, 7, &0_i32.to_ne_bytes());
        assert_eq!(parse_chunk(&ack, 7, PORT, 1), Ok(Chunk::default()));
        let interrupted = message(RTM_NEWADDR, NLM_F_DUMP_INTR, 7, &[2, 0, 0, 0, 1, 0, 0, 0]);
        let chunk = parse_chunk(&interrupted, 7, PORT, 1).expect("parsed");
        assert!(chunk.interrupted);
        assert_eq!(chunk.addresses, 1);
        // Length below the header, beyond the datagram, short payload.
        let mut short = address(2, 1);
        short[0..4].copy_from_slice(&8_u32.to_ne_bytes());
        assert_eq!(
            parse_chunk(&short, 7, PORT, 1),
            Err(NetlinkError::Malformed)
        );
        let mut long = address(2, 1);
        long[0..4].copy_from_slice(&4096_u32.to_ne_bytes());
        assert_eq!(parse_chunk(&long, 7, PORT, 1), Err(NetlinkError::Malformed));
        let truncated = message(RTM_NEWADDR, 0, 7, &[2, 0]);
        assert_eq!(
            parse_chunk(&truncated, 7, PORT, 1),
            Err(NetlinkError::Malformed)
        );
        assert_eq!(
            parse_chunk(&[1, 2, 3], 7, PORT, 1),
            Err(NetlinkError::Malformed)
        );
        assert_eq!(parse_chunk(&[], 7, PORT, 1), Ok(Chunk::default()));
    }

    #[test]
    fn an_aborted_dump_or_a_foreign_port_fails_closed() {
        // NLMSG_DONE with a negative status (for example -EINTR): the dump
        // was cut short, its count is not trustworthy.
        let mut datagram = address(2, 5);
        datagram.extend(message(NLMSG_DONE, 0x2, 7, &(-4_i32).to_ne_bytes()));
        assert_eq!(
            parse_chunk(&datagram, 7, PORT, 5),
            Err(NetlinkError::Kernel(-4))
        );
        // A short DONE (no status) and a zero status complete the dump.
        let bare = message(NLMSG_DONE, 0x2, 7, &[]);
        assert!(parse_chunk(&bare, 7, PORT, 5).expect("done").done);
        let zero = message(NLMSG_DONE, 0x2, 7, &0_i32.to_ne_bytes());
        assert!(parse_chunk(&zero, 7, PORT, 5).expect("done").done);
        // A message of this dump for another port id.
        let foreign = message_for(PORT + 1, RTM_NEWADDR, 0x2, 7, &[2, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(
            parse_chunk(&foreign, 7, PORT, 5),
            Err(NetlinkError::UnexpectedPort)
        );
        // Another sequence is skipped whatever its port id.
        let other = message_for(PORT + 1, RTM_NEWADDR, 0x2, 8, &[2, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(parse_chunk(&other, 7, PORT, 5), Ok(Chunk::default()));
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
        let address = message(RTM_NEWADDR, 0, 7, &[2, 0, 0, 0, 5, 0, 0, 0]);
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
        // The socket is reused.
        assert_eq!(probe.query(1).map(|facts| facts.mtu), Ok(facts.mtu));
    }

    /// The live dump works unprivileged in any network namespace; the
    /// loopback device (ifindex 1) of the test host's namespace has
    /// 127.0.0.1 unless it was removed, so only success is asserted.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_dump_answers() {
        assert!(ipv4_address_count(1).is_ok());
        assert_eq!(ipv4_address_count(u32::MAX), Ok(0));
    }
}

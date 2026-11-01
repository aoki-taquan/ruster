//! Kernel IPv4 address count of one interface through one rtnetlink
//! `RTM_GETADDR` dump (cold path, startup only).
//!
//! The FFI is five C library calls (`socket`, `send`, `getsockname`,
//! `recvfrom`, and `close` through [`std::os::fd::OwnedFd`]) in `sys`;
//! everything else parses a byte slice and is unit tested. Every datagram
//! must come from the kernel (`nl_pid == 0` from `recvfrom`), and every
//! message of the dump must carry this socket's port id (`nlmsg_pid`), so
//! no other process can answer for the kernel. Unlike `SIOCGIFADDR`, which matches only addresses
//! whose label equals the device name, the dump sees every IPv4 address of
//! the interface index, labelled or not.

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
            let received = socket.receive(&mut buffer)?;
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
        /// datagram from anyone but the kernel is refused.
        pub fn receive(&self, buffer: &mut [u8]) -> Result<usize, NetlinkError> {
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
                        MSG_TRUNC,
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

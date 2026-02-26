//! AF_PACKET raw socket I/O backend for Linux.
//!
//! Provides real packet I/O using Linux AF_PACKET raw sockets.
//! Each interface gets its own socket bound to a specific interface
//! via `bind()` with `sockaddr_ll`.
//! Sockets are set to non-blocking mode.
//!
//! This module is only compiled on Linux (`cfg(target_os = "linux")`).

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::io::{IoError, PacketIo, RawPacket};

// ── Linux constants ──────────────────────────────────────────────────

const AF_PACKET: i32 = 17;
const SOCK_RAW: i32 = 3;
const ETH_P_ALL: i32 = 0x0003;
const SOL_PACKET: i32 = 263;
const PACKET_IGNORE_OUTGOING: i32 = 23;
const O_NONBLOCK: i32 = 2048;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const MSG_DONTWAIT: i32 = 0x40;

/// Maximum Ethernet frame size we'll receive.
const MAX_FRAME_SIZE: usize = 9216;

// ── Raw libc FFI ─────────────────────────────────────────────────────

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const SockaddrLl, addrlen: u32) -> i32;
    fn setsockopt(
        sockfd: i32,
        level: i32,
        optname: i32,
        optval: *const std::ffi::c_void,
        optlen: u32,
    ) -> i32;
    fn recv(sockfd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn sendto(
        sockfd: i32,
        buf: *const u8,
        len: usize,
        flags: i32,
        dest_addr: *const SockaddrLl,
        addrlen: u32,
    ) -> isize;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn if_nametoindex(ifname: *const u8) -> u32;
}

// ── sockaddr_ll ──────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

impl SockaddrLl {
    fn new(ifindex: i32, dst_mac: &[u8]) -> Self {
        let mut addr = Self {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };
        if dst_mac.len() >= 6 {
            addr.sll_addr[..6].copy_from_slice(&dst_mac[..6]);
        }
        addr
    }

    /// Create a sockaddr_ll for binding (no MAC address needed).
    fn for_bind(ifindex: i32) -> Self {
        Self {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        }
    }
}

// ── IfSocket ─────────────────────────────────────────────────────────

/// Per-interface socket state.
struct IfSocket {
    fd: OwnedFd,
    ifindex: i32,
}

// ── AfPacketIo ───────────────────────────────────────────────────────

/// AF_PACKET raw socket I/O backend.
///
/// Creates one raw socket per interface, bound to the Linux device via
/// `bind()` with `sockaddr_ll`. Sockets are set to non-blocking mode.
pub struct AfPacketIo {
    sockets: HashMap<String, IfSocket>,
    rx_ifaces: Vec<String>,
}

impl AfPacketIo {
    /// Create a new AF_PACKET I/O backend.
    ///
    /// `iface_map` is a list of `(logical_name, linux_device_name)` pairs.
    ///
    /// # Errors
    ///
    /// Returns `IoError::TxFailed` if socket creation or binding fails
    /// (typically requires `CAP_NET_RAW` or root).
    pub fn new(iface_map: &[(String, String)]) -> Result<Self, IoError> {
        let mut sockets = HashMap::new();
        let mut rx_ifaces = Vec::new();

        for (logical_name, linux_name) in iface_map {
            // Get ifindex first (needed for bind).
            let mut name_buf = Vec::with_capacity(linux_name.len() + 1);
            name_buf.extend_from_slice(linux_name.as_bytes());
            name_buf.push(0); // NUL terminator
            let ifidx = unsafe { if_nametoindex(name_buf.as_ptr()) };
            if ifidx == 0 {
                return Err(IoError::TxFailed(format!(
                    "if_nametoindex({}) for {}: {}",
                    linux_name,
                    logical_name,
                    std::io::Error::last_os_error()
                )));
            }

            // Create AF_PACKET, SOCK_RAW, ETH_P_ALL socket.
            let raw_fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
            if raw_fd < 0 {
                return Err(IoError::TxFailed(format!(
                    "socket(AF_PACKET) for {}: errno={}",
                    linux_name,
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: socket() returned a valid fd.
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

            // Set non-blocking mode.
            unsafe {
                let flags = fcntl(fd.as_raw_fd(), F_GETFL);
                fcntl(fd.as_raw_fd(), F_SETFL, flags | O_NONBLOCK);
            }

            // Bind to the specific interface using sockaddr_ll.
            // This is the canonical way to restrict AF_PACKET to one device.
            let bind_addr = SockaddrLl::for_bind(ifidx as i32);
            let ret = unsafe {
                bind(
                    fd.as_raw_fd(),
                    &bind_addr,
                    std::mem::size_of::<SockaddrLl>() as u32,
                )
            };
            if ret < 0 {
                return Err(IoError::TxFailed(format!(
                    "bind(AF_PACKET) to {} for {}: {}",
                    linux_name,
                    logical_name,
                    std::io::Error::last_os_error()
                )));
            }

            // PACKET_IGNORE_OUTGOING (Linux 4.20+): don't deliver our own
            // transmitted packets back to the RX path. Ignore errors on
            // older kernels.
            unsafe {
                let val: i32 = 1;
                setsockopt(
                    fd.as_raw_fd(),
                    SOL_PACKET,
                    PACKET_IGNORE_OUTGOING,
                    &val as *const i32 as *const std::ffi::c_void,
                    std::mem::size_of::<i32>() as u32,
                );
            }

            sockets.insert(
                logical_name.clone(),
                IfSocket {
                    fd,
                    ifindex: ifidx as i32,
                },
            );
            rx_ifaces.push(logical_name.clone());
        }

        Ok(Self { sockets, rx_ifaces })
    }
}

// SAFETY: The OwnedFd handles are not shared across threads without
// synchronization, and the HashMap is only read (never modified) after
// construction. The run loop calls rx()/tx() from a single thread.
unsafe impl Send for AfPacketIo {}
unsafe impl Sync for AfPacketIo {}

impl PacketIo for AfPacketIo {
    fn rx(&self) -> Vec<RawPacket> {
        let mut batch = Vec::new();
        let mut buf = [0u8; MAX_FRAME_SIZE];

        for iface_name in &self.rx_ifaces {
            let if_sock = match self.sockets.get(iface_name) {
                Some(s) => s,
                None => continue,
            };

            let n = unsafe {
                recv(
                    if_sock.fd.as_raw_fd(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    MSG_DONTWAIT,
                )
            };

            if n > 0 {
                batch.push(RawPacket {
                    ingress_iface: iface_name.clone(),
                    data: buf[..n as usize].to_vec(),
                });
            }
            // n <= 0: EAGAIN/EWOULDBLOCK or error, skip silently.
        }

        batch
    }

    fn tx(&self, iface: &str, packet: &RawPacket) -> Result<(), IoError> {
        let if_sock = self
            .sockets
            .get(iface)
            .ok_or_else(|| IoError::InterfaceNotFound(iface.to_string()))?;

        let addr = SockaddrLl::new(if_sock.ifindex, &packet.data);

        let n = unsafe {
            sendto(
                if_sock.fd.as_raw_fd(),
                packet.data.as_ptr(),
                packet.data.len(),
                0,
                &addr,
                std::mem::size_of::<SockaddrLl>() as u32,
            )
        };

        if n < 0 {
            Err(IoError::TxFailed(format!(
                "sendto on {}: {}",
                iface,
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }
}

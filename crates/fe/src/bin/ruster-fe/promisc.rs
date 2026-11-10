//! Promiscuous mode on the ports that are bridge members, or parents of VLAN
//! sub-interfaces that are (`docs/design/overlay.md` section 1), through a minimal
//! private FFI (`socket`, `setsockopt`).
//!
//! A real NIC drops frames to MAC addresses other than its own before XDP or a
//! packet socket sees them; a member must also take the frames to the hosts behind
//! it and to the IRB. For each such port the FE holds one AF_PACKET socket open with
//! a `PACKET_MR_PROMISC` membership (packet(7)). The socket names no protocol, so it
//! receives nothing and the FE never reads it. Linux counts the users of promiscuous
//! mode per device: closing the socket takes back only this one, also when the FE
//! dies, and leaves what others asked for (`ip link set promisc on`, tcpdump).
//! `SIOCSIFFLAGS` with `IFF_PROMISC` was not chosen: that is one flag shared with
//! the operator, and it stays set when the FE dies.
//!
//! # Standards
//!
//! - IEEE 802.1Q clause 8.6: a Bridge Port takes in every frame on its LAN, whatever
//!   its destination address; the forwarding process decides where it goes.
//!
//! Deviations: none.

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

/// The sockets that keep ports in promiscuous mode, by port name.
#[derive(Default)]
pub struct Promiscuous {
    /// The socket of each port, with the device's index when it was opened: a
    /// device made again under the same name lost the membership.
    held: BTreeMap<String, (u32, OwnedFd)>,
    /// The last error for each port, written once until it changes.
    errors: BTreeMap<String, String>,
}

impl Promiscuous {
    /// Keeps exactly the ports `wanted` in promiscuous mode.
    pub fn keep(&mut self, wanted: &[String]) {
        self.held.retain(|port, (index, _)| {
            let keep = wanted.contains(port) && crate::if_index(port).ok() == Some(*index);
            if !keep {
                eprintln!("ruster-fe: {port} leaves promiscuous mode");
            }
            keep
        });
        self.errors.retain(|port, _| wanted.contains(port));
        for port in wanted {
            if self.held.contains_key(port) {
                continue;
            }
            let held = crate::if_index(port).and_then(|index| {
                let socket = imp::hold(index).map_err(|error| error.to_string())?;
                Ok((index, socket))
            });
            match held {
                Ok(held) => {
                    eprintln!("ruster-fe: {port} is in promiscuous mode");
                    self.held.insert(port.clone(), held);
                    self.errors.remove(port);
                }
                Err(text) => {
                    if self.errors.get(port) != Some(&text) {
                        eprintln!("ruster-fe: promiscuous mode on {port}: {text}");
                        self.errors.insert(port.clone(), text);
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod imp {
    use std::io;
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::raw::{c_int, c_void};

    // The same on every Linux architecture ruster builds for (x86_64 and aarch64).
    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2_000_000;
    const SOL_PACKET: c_int = 263;
    const PACKET_ADD_MEMBERSHIP: c_int = 1;
    const PACKET_MR_PROMISC: u16 = 1;

    /// `struct packet_mreq` (`linux/if_packet.h`).
    #[repr(C)]
    struct PacketMreq {
        ifindex: c_int,
        kind: u16,
        address_len: u16,
        address: [u8; 8],
    }

    extern "C" {
        // From the C library std links.
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn setsockopt(
            socket: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            length: u32,
        ) -> c_int;
    }

    /// A packet socket that receives nothing and keeps device `if_index` in
    /// promiscuous mode until it is closed.
    pub fn hold(if_index: u32) -> Result<OwnedFd, io::Error> {
        let ifindex = c_int::try_from(if_index)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface index"))?;
        // SAFETY: `socket` is the C library function with the declared ABI and takes
        // no pointers. Protocol 0 binds the socket to no frames, so it never queues any.
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a new descriptor, open and owned by nothing else; the
        // `OwnedFd` closes it exactly once, also on the error path below.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let request = PacketMreq {
            ifindex,
            kind: PACKET_MR_PROMISC,
            address_len: 0,
            address: [0; 8],
        };
        // SAFETY: `setsockopt` is the C library function with the declared ABI. The
        // descriptor is open for the call. The pointer and length name `request`,
        // a live, initialised `struct packet_mreq` (16 bytes) that Linux only reads
        // during the call and does not keep.
        let status = unsafe {
            setsockopt(
                socket.as_raw_fd(),
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                std::ptr::addr_of!(request).cast::<c_void>(),
                size_of::<PacketMreq>() as u32,
            )
        };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    const _: () = assert!(size_of::<PacketMreq>() == 16);
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub fn hold(_if_index: u32) -> Result<std::os::fd::OwnedFd, std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "promiscuous mode needs Linux",
        ))
    }
}

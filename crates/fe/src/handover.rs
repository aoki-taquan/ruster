//! The handover role of `docs/design/fe-internals.md`: the FE's ends of the
//! connections that carry traffic addressed to the router. Each VRF's pipe to the
//! kernel (TUN), the TAP devices of IS-IS and OSPF, the punt socket of the
//! neighbor process, and the sockets of the other control processes.
//!
//! It only writes and reads them. What goes where, the rate limits and the counts
//! are the worker's. The worker leaves what is to be written ([`Out`]) and the
//! handover writes it ([`Handover::write`]), each write's result going back to be
//! counted ([`Count`]).
//!
//! # Standards
//!
//! None: the messages are ruster's own ([`ruster_proto::punt`]).

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

use ruster_core::IfId;

use crate::control::Controls;
use crate::LocalPipe;

/// Where a write the worker left goes, by the worker's tables of the step it was
/// left in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Where {
    /// The neighbor process, an encoded punt message; counted with the ARP
    /// counters and, if any, those of the punt class.
    Neighbor(Option<usize>),
    /// The control process of the punt class, an encoded punt message.
    Control(usize),
    /// The TAP device of the interface, a frame of the punt class.
    Tap(IfId, usize),
    /// The pipe to the kernel of the VRF at this index, an IP packet of the punt
    /// class.
    Kernel(usize, usize),
    /// The same, a packet the FE sends out of the VRF's kernel interface.
    Generated(usize),
}

/// One write the worker left to the handover.
pub(crate) struct Out {
    pub(crate) to: Where,
    pub(crate) bytes: Vec<u8>,
}

/// Where a write goes, by name.
pub(crate) enum To<'a> {
    Neighbor,
    Control(&'a str),
    Tap(&'a str),
    Kernel(&'a str),
}

#[derive(Default)]
pub(crate) struct Handover {
    /// Each VRF's pipe to the kernel, by VRF name.
    local: BTreeMap<String, Box<dyn LocalPipe>>,
    /// The TAP device of each interface that runs IS-IS or OSPF, by interface name.
    taps: BTreeMap<String, Box<dyn LocalPipe>>,
    /// The neighbor process's socket.
    punt: Option<UnixDatagram>,
    /// Where ARP goes when the punt socket is not connected to one peer.
    punt_peer: Option<PathBuf>,
    /// The sockets to the other control processes the punt classes name.
    pub(crate) controls: Controls,
}

/// What a datagram read from the punt socket was.
pub(crate) enum FromPunt {
    /// Its length in the buffer.
    Taken(usize),
    /// From someone other than the fixed peer, or too long.
    Refused,
}

impl Handover {
    /// Uses `socket` for the neighbor process; with `peer`, sends to that path and
    /// takes frames only from it.
    pub(crate) fn attach_punt(&mut self, socket: UnixDatagram, peer: Option<PathBuf>) {
        self.punt = Some(socket);
        self.punt_peer = peer;
    }

    pub(crate) fn attach_local(&mut self, vrf: &str, pipe: Box<dyn LocalPipe>) {
        self.local.insert(vrf.to_owned(), pipe);
    }

    pub(crate) fn detach_local(&mut self, vrf: &str) {
        self.local.remove(vrf);
    }

    /// Whether VRF `vrf` has a pipe to the kernel.
    pub(crate) fn has_local(&self, vrf: &str) -> bool {
        self.local.contains_key(vrf)
    }

    pub(crate) fn attach_tap(&mut self, interface: &str, pipe: Box<dyn LocalPipe>) {
        self.taps.insert(interface.to_owned(), pipe);
    }

    pub(crate) fn detach_tap(&mut self, interface: &str) {
        self.taps.remove(interface);
    }

    /// Whether there is a socket to the neighbor process.
    pub(crate) fn has_punt(&self) -> bool {
        self.punt.is_some()
    }

    /// Whether `interface` has a TAP device.
    pub(crate) fn has_tap(&self, interface: &str) -> bool {
        self.taps.contains_key(interface)
    }

    /// Sends an encoded punt message to the neighbor process: `None` without a
    /// punt socket, else whether it went.
    pub(crate) fn send_punt(&self, message: &[u8]) -> Option<bool> {
        let socket = self.punt.as_ref()?;
        let sent = match &self.punt_peer {
            Some(peer) => socket.send_to(message, peer),
            None => socket.send(message),
        };
        Some(sent.is_ok())
    }

    /// Reads one datagram from the neighbor process into `buf`; `None` when there
    /// is none (or no socket). `buf` is one byte longer than the longest taken.
    pub(crate) fn recv_punt(&self, buf: &mut [u8]) -> Option<FromPunt> {
        let socket = self.punt.as_ref()?;
        match socket.recv_from(buf) {
            // With a fixed peer path, only frames from that path are taken.
            Ok((_, from))
                if self
                    .punt_peer
                    .as_deref()
                    .is_some_and(|peer| from.as_pathname() != Some(peer)) =>
            {
                Some(FromPunt::Refused)
            }
            Ok((n, _)) if n < buf.len() => Some(FromPunt::Taken(n)),
            Ok(_) => Some(FromPunt::Refused),
            Err(error) if error.kind() == ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    /// Writes `frame` to the TAP device of `interface`: `None` without one, else
    /// whether it went.
    pub(crate) fn send_tap(&self, interface: &str, frame: &[u8]) -> Option<bool> {
        Some(self.taps.get(interface)?.send(frame).is_ok())
    }

    /// The interfaces with a TAP device.
    pub(crate) fn tap_names(&self) -> Vec<String> {
        self.taps.keys().cloned().collect()
    }

    /// Reads one frame from the TAP device of `interface`; `None` when there is
    /// none (or no device).
    pub(crate) fn recv_tap(&self, interface: &str, buf: &mut [u8]) -> Option<usize> {
        match self.taps.get(interface)?.recv(buf) {
            Ok(n) if n > 0 => Some(n),
            _ => None,
        }
    }

    /// Writes `packet` to VRF `vrf`'s pipe to the kernel: `None` without one, else
    /// whether it went.
    pub(crate) fn send_kernel(&self, vrf: &str, packet: &[u8]) -> Option<bool> {
        Some(self.local.get(vrf)?.send(packet).is_ok())
    }

    /// Whether any VRF has a pipe to the kernel.
    pub(crate) fn any_local(&self) -> bool {
        !self.local.is_empty()
    }

    /// Reads one packet from VRF `vrf`'s pipe to the kernel; `None` when there is
    /// none (or no pipe).
    pub(crate) fn recv_kernel(&self, vrf: &str, buf: &mut [u8]) -> Option<usize> {
        match self.local.get(vrf)?.recv(buf) {
            Ok(n) if n > 0 => Some(n),
            _ => None,
        }
    }

    /// Writes `bytes` to `to`: whether it went.
    pub(crate) fn write(&self, to: To<'_>, bytes: &[u8]) -> bool {
        let sent = match to {
            To::Neighbor => self.send_punt(bytes),
            To::Control(name) => Some(self.controls.send(name, bytes)),
            To::Tap(interface) => self.send_tap(interface, bytes),
            To::Kernel(vrf) => self.send_kernel(vrf, bytes),
        };
        sent == Some(true)
    }

    /// Binds the sockets to the control processes under `dir`.
    pub(crate) fn set_control_dir(&mut self, dir: PathBuf) {
        self.controls.set_dir(dir);
    }

    pub(crate) fn attach_control(&mut self, name: &str, socket: UnixDatagram) -> io::Result<()> {
        self.controls.attach(name, socket)
    }
}

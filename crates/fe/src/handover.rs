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
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::time::Duration;

use ruster_core::IfId;
use ruster_proto::task::{Progress, Task};

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

/// The names [`Where`] is resolved by: those of one version of the worker's
/// tables.
#[derive(Clone, Default)]
pub(crate) struct Names {
    /// Every interface's name by id (an empty name is an id no interface has).
    pub(crate) interfaces: Vec<String>,
    /// The VRFs' names, in the worker's order.
    pub(crate) vrfs: Vec<String>,
    /// For each punt class, the control process it goes to, if it is one.
    pub(crate) controls: Vec<Option<String>>,
}

impl Names {
    pub(crate) fn resolve(&self, to: Where) -> Option<To<'_>> {
        fn named(name: &str) -> Option<&str> {
            Some(name).filter(|name| !name.is_empty())
        }
        match to {
            Where::Neighbor(_) => Some(To::Neighbor),
            Where::Control(class) => self.controls.get(class)?.as_deref().map(To::Control),
            Where::Tap(id, _) => named(self.interfaces.get(usize::from(id.0))?).map(To::Tap),
            Where::Kernel(at, _) | Where::Generated(at) => {
                named(self.vrfs.get(at)?).map(To::Kernel)
            }
        }
    }
}

/// What the worker sends a handover on another thread, in order.
pub(crate) enum ToWriter {
    /// The names of the next writes.
    Names(Names),
    /// Every endpoint, again, after one was attached or taken away.
    Endpoints(Box<Handover>),
    /// Writes left in one step of the worker under the tables of this version.
    Write(u64, Vec<Out>),
}

/// The writes of one [`ToWriter::Write`], back to the worker with whether each
/// went (their buffers to be used again).
pub(crate) struct Written {
    pub(crate) version: u64,
    pub(crate) outs: Vec<Out>,
    pub(crate) sent: Vec<bool>,
}

/// The handover's writes on a thread of their own ([`crate::Fe::detach_handover`]):
/// what goes to the kernel, the TAP devices and the control processes is written
/// there, not on the worker's thread.
pub struct HandoverTask {
    handover: Handover,
    names: Names,
    from_worker: Receiver<ToWriter>,
    to_worker: Sender<Written>,
    worker_gone: bool,
}

// A thread can be given it.
const _: fn() = || {
    fn is_send<T: Send>() {}
    is_send::<HandoverTask>();
};

impl HandoverTask {
    pub(crate) fn new(
        handover: Handover,
        names: Names,
        from_worker: Receiver<ToWriter>,
        to_worker: Sender<Written>,
    ) -> Self {
        Self {
            handover,
            names,
            from_worker,
            to_worker,
            worker_gone: false,
        }
    }

    /// Whether the FE it writes for is gone.
    pub fn fe_gone(&self) -> bool {
        self.worker_gone
    }

    /// Waits at most `longest` for something to write, and writes it.
    pub fn wait(&mut self, longest: Duration) {
        match self.from_worker.recv_timeout(longest) {
            Ok(message) => self.on(message),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => self.worker_gone = true,
        }
    }

    fn on(&mut self, message: ToWriter) {
        match message {
            ToWriter::Names(names) => self.names = names,
            ToWriter::Endpoints(handover) => self.handover = *handover,
            ToWriter::Write(version, outs) => {
                let sent = outs
                    .iter()
                    .map(|out| self.handover.write_out(&self.names, out))
                    .collect();
                let written = Written {
                    version,
                    outs,
                    sent,
                };
                self.worker_gone |= self.to_worker.send(written).is_err();
            }
        }
    }
}

impl Task for HandoverTask {
    fn step(&mut self, _now_ms: u64) -> Progress {
        let mut busy = false;
        loop {
            match self.from_worker.try_recv() {
                Ok(message) => {
                    busy = true;
                    self.on(message);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.worker_gone = true;
                    break;
                }
            }
        }
        Progress::busy(busy)
    }
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

    /// A second handle on every endpoint, for writing from another thread.
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        let pipes = |pipes: &BTreeMap<String, Box<dyn LocalPipe>>| {
            pipes
                .iter()
                .map(|(name, pipe)| Ok((name.clone(), pipe.try_clone()?)))
                .collect::<io::Result<BTreeMap<_, _>>>()
        };
        Ok(Self {
            local: pipes(&self.local)?,
            taps: pipes(&self.taps)?,
            punt: self
                .punt
                .as_ref()
                .map(UnixDatagram::try_clone)
                .transpose()?,
            punt_peer: self.punt_peer.clone(),
            controls: self.controls.try_clone()?,
        })
    }

    /// Writes `out` to where `names` say: whether it went.
    pub(crate) fn write_out(&self, names: &Names, out: &Out) -> bool {
        names
            .resolve(out.to)
            .is_some_and(|to| self.write(to, &out.bytes))
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

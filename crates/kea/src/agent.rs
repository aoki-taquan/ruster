//! The relay agent's sockets: the FE's frames on `<run>/kea/punt.sock`, and a UDP
//! socket per interface, bound to the interface's address and port 67, from which
//! requests go to Kea and on which Kea's replies come back (Kea sends a relayed
//! reply to `giaddr`, port 67).
//!
//! A reply is taken only from Kea's address and port 67: the socket also gets what
//! any host sends to the router's address and port 67 through the kernel. A frame
//! is taken only from the FE's socket for `kea`. An interface's socket is bound
//! once the kernel has the address (confd puts it on the TUN device), tried again
//! every second until then.
//!
//! # Standards
//!
//! None beyond [`crate::relay`]'s.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

use ruster_proto::punt::{reason, Direction, Punt};
use ruster_proto::task::Progress;

use crate::relay::{self, Link, SERVER_PORT};

/// How often a socket that could not be bound is tried again.
pub const BIND_RETRY_MS: u64 = 1_000;
/// At most this many messages are read from each socket in one step.
const PER_STEP: usize = 64;
/// The largest message read: an Ethernet frame and the punt header.
const MAX_MESSAGE: usize = 2_048;

/// What the relay agent did, for its log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub requests: u64,
    pub replies: u64,
    /// Requests and replies dropped: unreadable, from a stranger, or for no link.
    pub dropped: u64,
}

struct Served {
    link: Link,
    socket: Option<UdpSocket>,
}

pub struct Agent {
    punt: UnixDatagram,
    fe: PathBuf,
    kea: SocketAddrV4,
    links: Vec<Served>,
    retry_at: u64,
    pub counters: Counters,
    buf: Vec<u8>,
    message: Vec<u8>,
}

impl Agent {
    /// With the bound, non-blocking `punt` socket, the FE's socket for `kea` at
    /// `fe`, and Kea at `kea`, port 67.
    pub fn new(punt: UnixDatagram, fe: PathBuf, kea: Ipv4Addr) -> Self {
        Self {
            punt,
            fe,
            kea: SocketAddrV4::new(kea, SERVER_PORT),
            links: Vec::new(),
            retry_at: 0,
            counters: Counters::default(),
            buf: vec![0; MAX_MESSAGE],
            message: Vec::new(),
        }
    }

    /// Serves `links` from now on; a socket for an address served before is kept.
    pub fn set_links(&mut self, links: Vec<Link>) {
        let mut old = std::mem::take(&mut self.links);
        for link in links {
            let socket = old
                .iter()
                .position(|s| s.link.address == link.address)
                .and_then(|at| old.swap_remove(at).socket);
            self.links.push(Served { link, socket });
        }
        self.retry_at = 0;
    }

    /// The interfaces whose socket is bound.
    pub fn bound(&self) -> Vec<&str> {
        self.links
            .iter()
            .filter(|s| s.socket.is_some())
            .map(|s| s.link.interface.as_str())
            .collect()
    }

    pub fn step(&mut self, now_ms: u64) -> Progress {
        let mut busy = false;
        if now_ms >= self.retry_at && self.links.iter().any(|s| s.socket.is_none()) {
            for served in self.links.iter_mut().filter(|s| s.socket.is_none()) {
                let at = SocketAddrV4::new(served.link.address, SERVER_PORT);
                match UdpSocket::bind(at).and_then(|s| s.set_nonblocking(true).map(|()| s)) {
                    Ok(socket) => {
                        eprintln!(
                            "ruster-kea: relaying for {} from {at}",
                            served.link.interface
                        );
                        served.socket = Some(socket);
                        busy = true;
                    }
                    // Tried again later: the kernel may not have the address yet.
                    Err(error) if error.kind() == ErrorKind::AddrNotAvailable => {}
                    Err(error) => eprintln!("ruster-kea: binding {at}: {error}"),
                }
            }
            self.retry_at = now_ms + BIND_RETRY_MS;
        }
        busy |= self.requests();
        busy |= self.replies();
        Progress {
            busy,
            wake_at: self
                .links
                .iter()
                .any(|s| s.socket.is_none())
                .then_some(self.retry_at),
        }
    }

    /// The clients' requests: relayed to Kea.
    fn requests(&mut self) -> bool {
        let mut busy = false;
        for _ in 0..PER_STEP {
            let (n, from) = match self.punt.recv_from(&mut self.buf) {
                Ok(got) => got,
                Err(_) => break,
            };
            busy = true;
            if from.as_pathname() != Some(self.fe.as_path()) {
                self.counters.dropped += 1;
                continue;
            }
            let relayed = Punt::decode(&self.buf[..n])
                .ok()
                .filter(|p| p.direction == Direction::ToControl && p.reason == reason::IP)
                .and_then(|p| {
                    let served = self
                        .links
                        .iter()
                        .find(|s| s.link.interface == p.interface)?;
                    let socket = served.socket.as_ref()?;
                    Some((socket, relay::request(&served.link, p.frame).ok()?))
                });
            match relayed {
                Some((socket, message)) if socket.send_to(&message, self.kea).is_ok() => {
                    self.counters.requests += 1;
                }
                _ => self.counters.dropped += 1,
            }
        }
        busy
    }

    /// Kea's replies: sent to the clients through the FE.
    fn replies(&mut self) -> bool {
        let mut busy = false;
        for served in &self.links {
            let Some(socket) = &served.socket else {
                continue;
            };
            for _ in 0..PER_STEP {
                let (n, from) = match socket.recv_from(&mut self.buf) {
                    Ok(got) => got,
                    Err(_) => break,
                };
                busy = true;
                let frame = (from == SocketAddr::V4(self.kea))
                    .then(|| relay::reply(&served.link, &self.buf[..n]).ok())
                    .flatten();
                let Some(frame) = frame else {
                    self.counters.dropped += 1;
                    continue;
                };
                self.message.clear();
                let encoded = Punt {
                    direction: Direction::FromControl,
                    reason: reason::IP,
                    interface: &served.link.interface,
                    frame: &frame,
                }
                .encode(&mut self.message);
                if encoded.is_ok() && self.punt.send_to(&self.message, &self.fe).is_ok() {
                    self.counters.replies += 1;
                } else {
                    self.counters.dropped += 1;
                }
            }
        }
        busy
    }
}

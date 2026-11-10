//! The relay agent's sockets: the FE's frames on `<run>/kea/punt.sock`, and a UDP
//! socket per interface, bound to the interface's address and port 67, from which
//! requests go to Kea and on which Kea's replies come back (Kea sends a relayed
//! reply to `giaddr`, port 67). For DHCPv6 likewise, bound to the interface's
//! global address and port 547, to which Kea sends its Relay-replies.
//!
//! A reply is taken only from Kea's address and port 67 (547): the socket also gets
//! what any host sends to the router's address and that port through the kernel. A
//! frame is taken only from the FE's socket for `kea`; its Ethernet type tells
//! DHCPv4 from DHCPv6. An interface's socket is bound once the kernel has the
//! address (confd puts it on the TUN device), tried again every second until then.
//!
//! A DHCPv6 reply goes to the MAC address the client's last message came from:
//! the agent keeps the last [`CLIENTS_MAX`] clients' addresses and MACs, and a reply
//! to one it does not know is dropped. A LAN host that sends a message from another
//! client's address gets the replies to it, as with a forged Neighbor Advertisement.
//!
//! # Standards
//!
//! None beyond [`crate::relay`]'s and [`crate::relay6`]'s.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

use ruster_proto::punt::{reason, Direction, Punt};
use ruster_proto::task::Progress;

use crate::relay::{self, Link, SERVER_PORT};
use crate::relay6::{self, Link6};

/// How often a socket that could not be bound is tried again.
pub const BIND_RETRY_MS: u64 = 1_000;
/// At most this many messages are read from each socket in one step.
const PER_STEP: usize = 64;
/// The largest message read: an Ethernet frame and the punt header.
const MAX_MESSAGE: usize = 2_048;
/// The DHCPv6 clients whose MAC address is kept, at most.
pub const CLIENTS_MAX: usize = 4_096;

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

struct Served6 {
    link: Link6,
    socket: Option<UdpSocket>,
}

pub struct Agent {
    punt: UnixDatagram,
    fe: PathBuf,
    kea: SocketAddrV4,
    kea6: SocketAddrV6,
    links: Vec<Served>,
    links6: Vec<Served6>,
    /// Each DHCPv6 client's MAC address, and when its last message came, by
    /// interface and address.
    clients: BTreeMap<(String, Ipv6Addr), ([u8; 6], u64)>,
    now_ms: u64,
    retry_at: u64,
    pub counters: Counters,
    buf: Vec<u8>,
    message: Vec<u8>,
}

impl Agent {
    /// With the bound, non-blocking `punt` socket, the FE's socket for `kea` at
    /// `fe`, Kea's DHCPv4 at `kea`, port 67, and its DHCPv6 at `kea6`, port 547.
    pub fn new(punt: UnixDatagram, fe: PathBuf, kea: Ipv4Addr, kea6: Ipv6Addr) -> Self {
        Self {
            punt,
            fe,
            kea: SocketAddrV4::new(kea, SERVER_PORT),
            kea6: SocketAddrV6::new(kea6, relay6::SERVER_PORT, 0, 0),
            links: Vec::new(),
            links6: Vec::new(),
            clients: BTreeMap::new(),
            now_ms: 0,
            retry_at: 0,
            counters: Counters::default(),
            buf: vec![0; MAX_MESSAGE],
            message: Vec::new(),
        }
    }

    /// Serves `links` and `links6` from now on; a socket for an address served
    /// before is kept.
    pub fn set_links(&mut self, links: Vec<Link>, links6: Vec<Link6>) {
        let mut old = std::mem::take(&mut self.links);
        for link in links {
            let socket = old
                .iter()
                .position(|s| s.link.address == link.address)
                .and_then(|at| old.swap_remove(at).socket);
            self.links.push(Served { link, socket });
        }
        let mut old = std::mem::take(&mut self.links6);
        for link in links6 {
            let socket = old
                .iter()
                .position(|s| s.link.address == link.address)
                .and_then(|at| old.swap_remove(at).socket);
            self.links6.push(Served6 { link, socket });
        }
        let served: Vec<&str> = self
            .links6
            .iter()
            .map(|s| s.link.interface.as_str())
            .collect();
        self.clients
            .retain(|(interface, _), _| served.contains(&interface.as_str()));
        self.retry_at = 0;
    }

    /// The interfaces whose socket is bound.
    pub fn bound(&self) -> Vec<&str> {
        let v4 = self
            .links
            .iter()
            .filter(|s| s.socket.is_some())
            .map(|s| &s.link.interface);
        let v6 = self
            .links6
            .iter()
            .filter(|s| s.socket.is_some())
            .map(|s| &s.link.interface);
        v4.chain(v6).map(String::as_str).collect()
    }

    fn unbound(&self) -> bool {
        self.links.iter().any(|s| s.socket.is_none())
            || self.links6.iter().any(|s| s.socket.is_none())
    }

    pub fn step(&mut self, now_ms: u64) -> Progress {
        self.now_ms = now_ms;
        let mut busy = false;
        if now_ms >= self.retry_at && self.unbound() {
            let v4 = self
                .links
                .iter_mut()
                .filter(|s| s.socket.is_none())
                .map(|s| {
                    let at = SocketAddr::V4(SocketAddrV4::new(s.link.address, SERVER_PORT));
                    (&s.link.interface, at, &mut s.socket)
                });
            let v6 = self
                .links6
                .iter_mut()
                .filter(|s| s.socket.is_none())
                .map(|s| {
                    let at = SocketAddrV6::new(s.link.address, relay6::SERVER_PORT, 0, 0);
                    (&s.link.interface, SocketAddr::V6(at), &mut s.socket)
                });
            for (interface, at, slot) in v4.chain(v6) {
                match UdpSocket::bind(at).and_then(|s| s.set_nonblocking(true).map(|()| s)) {
                    Ok(socket) => {
                        eprintln!("ruster-kea: relaying for {interface} from {at}");
                        *slot = Some(socket);
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
        busy |= self.replies6();
        Progress {
            busy,
            wake_at: self.unbound().then_some(self.retry_at),
        }
    }

    /// A client's DHCPv6 message in `frame` on `interface`: relayed to Kea, and the
    /// client's MAC kept.
    fn request6(&mut self, interface: &str, frame: &[u8]) -> bool {
        let Some(served) = self.links6.iter().find(|s| s.link.interface == interface) else {
            return false;
        };
        let (Some(socket), Ok(relayed)) = (&served.socket, relay6::request(&served.link, frame))
        else {
            return false;
        };
        if socket.send_to(&relayed.message, self.kea6).is_err() {
            return false;
        }
        let key = (interface.to_owned(), relayed.client);
        if !self.clients.contains_key(&key) && self.clients.len() >= CLIENTS_MAX {
            // The one heard from longest ago makes room.
            let oldest = self
                .clients
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.clients.remove(&oldest);
            }
        }
        self.clients.insert(key, (relayed.client_mac, self.now_ms));
        true
    }

    /// Kea's DHCPv6 Relay-replies: sent to the clients through the FE.
    fn replies6(&mut self) -> bool {
        let mut busy = false;
        for served in &self.links6 {
            let Some(socket) = &served.socket else {
                continue;
            };
            for _ in 0..PER_STEP {
                let (n, from) = match socket.recv_from(&mut self.buf) {
                    Ok(got) => got,
                    Err(_) => break,
                };
                busy = true;
                let from_kea = matches!(from, SocketAddr::V6(a)
                    if *a.ip() == *self.kea6.ip() && a.port() == self.kea6.port());
                let frame = from_kea
                    .then(|| relay6::reply(&served.link, &self.buf[..n]).ok())
                    .flatten()
                    .and_then(|(to, message)| {
                        let key = (served.link.interface.clone(), to);
                        let (mac, _) = self.clients.get(&key)?;
                        relay6::frame(&served.link, *mac, to, message).ok()
                    });
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
            let punt = Punt::decode(&self.buf[..n])
                .ok()
                .filter(|p| p.direction == Direction::ToControl && p.reason == reason::IP);
            // DHCPv6, by its Ethernet type.
            if let Some(p) = punt
                .as_ref()
                .filter(|p| p.frame.get(12..14) == Some(&[0x86, 0xdd]))
            {
                let (interface, frame) = (p.interface.to_owned(), p.frame.to_vec());
                if self.request6(&interface, &frame) {
                    self.counters.requests += 1;
                } else {
                    self.counters.dropped += 1;
                }
                continue;
            }
            let relayed = punt.and_then(|p| {
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

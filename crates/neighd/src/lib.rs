#![forbid(unsafe_code)]
//! The neighbor process: ARP for IPv4 (`docs/design/ce-processes.md`).
//!
//! - It learns the router's own interfaces and addresses from confd, which writes them
//!   to neighd's own small table server.
//! - It answers ARP requests for those addresses.
//! - When the FE reports a next hop missing from its neighbor table, neighd sends ARP
//!   requests (three, one second apart) and writes the answer to the FE.
//! - On start it reads the neighbor table the FE already holds and keeps it, so a
//!   restart does not remove a single neighbor from forwarding.
//!
//! Skeleton limits: no aging or re-checking of learned neighbors, no ND (IPv6), no
//! announcements or duplicate address detection.
//!
//! # Standards
//!
//! - RFC 826: the packet format and the receive rules (update a known sender, add the
//!   sender when the target is us, answer requests for our addresses).
//! - RFC 1122 section 2.3.2.1: at most one request per second per next hop.
//! - RFC 5227 section 2.4: a packet whose sender claims our own address is not learned
//!   or answered.
//!
//! Deviations from RFC 826: a sender that targets us is added only if it is a host on
//! that interface's subnet, and at most 4096 neighbors are kept. A packet waiting for a
//! next hop is dropped, not queued (RFC 1122 section 2.3.2.2 says to keep at least
//! one). Conflicts are not announced or defended (RFC 5227 section 2.4).

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::net::Ipv4Addr;
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_proto::cbor::Decoder;
use ruster_proto::coap::Code;
use ruster_proto::punt::{self, Direction, Punt};
use ruster_proto::session::{decode_changes, Client, Event, Hook, Server, Store};
use ruster_proto::table::{Change, Key, ResolveRequest, Value};
use ruster_proto::task::{Progress, Task};

/// The tables confd writes to neighd.
pub const CONFIG_TABLES: &[u64] = &[ruster_proto::sid::INTERFACE, ruster_proto::sid::ADDRESS];

const RETRY_MS: u64 = 1_000;
const ATTEMPTS: u32 = 3;
const PUNTS_PER_STEP: usize = 64;
const ARP_BODY_LEN: usize = 28;
/// Ethernet, IPv4, 6-byte and 4-byte addresses (RFC 826).
const ARP_ETHERNET_IPV4: [u8; 6] = [0, 1, 8, 0, 6, 4];
/// Neighbors remembered at most; further new ones are not learned.
const KNOWN_MAX: usize = 4_096;
/// How long to wait for the FE's neighbor table before going on without it.
const ADOPT_TIMEOUT_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeighdCounters {
    pub requests_sent: u64,
    pub replies_sent: u64,
    pub learned: u64,
    pub adopted: u64,
    pub given_up: u64,
    pub bad_punts: u64,
    pub not_learned: u64,
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    attempts: u32,
    next_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FeState {
    /// Waiting for the answer to the GET of the FE's neighbor table.
    Adopting(u32),
    Running {
        observe: u32,
    },
}

pub struct Neighd {
    local: Server,
    fe: Client,
    fe_state: FeState,
    adopt_since: Option<u64>,
    punt: UnixDatagram,
    known: BTreeMap<(String, Ipv4Addr), [u8; 6]>,
    pending: BTreeMap<(String, Ipv4Addr), Pending>,
    counters: NeighdCounters,
}

impl std::fmt::Debug for Neighd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Neighd")
            .field("known", &self.known.len())
            .field("pending", &self.pending.len())
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

/// neighd accepts whatever confd writes; it only reads it.
struct AcceptAll;

impl Hook for AcceptAll {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }

    fn committed(&mut self, _store: &Store) {}
}

impl Neighd {
    /// `fe` is a connection to the FE allowed to write the neighbor table; `punt` is
    /// the FE's ARP socket.
    pub fn new(fe: UnixStream, punt: UnixDatagram) -> io::Result<Self> {
        punt.set_nonblocking(true)?;
        let mut fe = Client::new(fe)?;
        let token = fe.get_all();
        Ok(Self {
            local: Server::new(),
            fe,
            fe_state: FeState::Adopting(token),
            adopt_since: None,
            punt,
            known: BTreeMap::new(),
            pending: BTreeMap::new(),
            counters: NeighdCounters::default(),
        })
    }

    /// Accepts the connection confd writes interfaces and addresses on.
    pub fn attach_config(&mut self, stream: UnixStream) -> io::Result<()> {
        self.local.attach(stream, CONFIG_TABLES)
    }

    pub fn counters(&self) -> NeighdCounters {
        self.counters
    }

    pub fn known(&self) -> usize {
        self.known.len()
    }

    fn local_mac(&self, interface: &str) -> Option<[u8; 6]> {
        match self.local.store().get(&Key::Interface {
            name: interface.to_owned(),
        }) {
            Some(Value::Interface {
                enabled: true, mac, ..
            }) => Some(*mac),
            _ => None,
        }
    }

    /// The router's addresses on `interface` with their prefix lengths.
    fn local_addresses(&self, interface: &str) -> Vec<(Ipv4Addr, u8)> {
        self.local
            .store()
            .iter()
            .filter_map(|(key, value)| match (key, value) {
                (
                    Key::Address {
                        interface: name,
                        address,
                    },
                    Value::Address { prefix_len },
                ) if name == interface => Some((*address, *prefix_len)),
                _ => None,
            })
            .collect()
    }

    /// The address to ask from: the one whose prefix holds `target`, else the first.
    fn local_address(&self, interface: &str, target: Ipv4Addr) -> Option<Ipv4Addr> {
        let addresses = self.local_addresses(interface);
        addresses
            .iter()
            .find(|&&(address, len)| same_subnet(address, target, len))
            .or(addresses.first())
            .map(|&(address, _)| address)
    }

    /// A host address on one of the interface's subnets (not its network or broadcast
    /// address), so a neighbor there is possible.
    fn on_link_host(&self, interface: &str, sender: Ipv4Addr) -> bool {
        self.local_addresses(interface)
            .iter()
            .any(|&(address, len)| {
                if !same_subnet(address, sender, len) {
                    return false;
                }
                if len >= 31 {
                    return true;
                }
                let host = u32::from(sender) & !mask(len);
                host != 0 && host != !mask(len)
            })
    }

    fn is_local(&self, interface: &str, address: Ipv4Addr) -> bool {
        self.local
            .store()
            .get(&Key::Address {
                interface: interface.to_owned(),
                address,
            })
            .is_some()
    }

    fn handle_fe(&mut self, events: Vec<Event>, now_ms: u64) {
        for event in events {
            match event {
                Event::Response {
                    token,
                    code,
                    payload,
                } if self.fe_state == FeState::Adopting(token) => {
                    if code == Code::CONTENT {
                        for change in decode_changes(&payload).unwrap_or_default() {
                            if let (
                                Key::Neighbor { interface, address },
                                Some(Value::Neighbor { mac }),
                            ) = (change.key, change.value)
                            {
                                self.known.insert((interface, address), mac);
                                self.counters.adopted += 1;
                            }
                        }
                    }
                    self.start_running();
                }
                Event::Notification { payload } => {
                    let mut d = Decoder::new(&payload);
                    if let Ok(request) = ResolveRequest::decode(&mut d) {
                        self.resolve(request.interface, request.address, now_ms);
                    }
                }
                // A refused Observe registration is tried again.
                Event::Response { token, code, .. }
                    if self.fe_state == (FeState::Running { observe: token })
                        && code.class() != 2 =>
                {
                    self.start_running();
                }
                Event::Response { .. } => {}
            }
        }
    }

    fn start_running(&mut self) {
        let observe = self.fe.observe();
        self.fe_state = FeState::Running { observe };
    }

    fn resolve(&mut self, interface: String, address: Ipv4Addr, now_ms: u64) {
        let key = (interface, address);
        if self.known.contains_key(&key) || self.pending.contains_key(&key) {
            return;
        }
        self.pending.insert(
            key,
            Pending {
                attempts: 0,
                next_at: now_ms,
            },
        );
    }

    fn retry(&mut self, now_ms: u64) -> Progress {
        let due: Vec<(String, Ipv4Addr)> = self
            .pending
            .iter()
            .filter(|(_, p)| p.next_at <= now_ms)
            .map(|(key, _)| key.clone())
            .collect();
        let busy = !due.is_empty();
        for key in due {
            let attempts = self.pending[&key].attempts;
            if attempts >= ATTEMPTS {
                self.pending.remove(&key);
                self.counters.given_up += 1;
                continue;
            }
            let (interface, target) = &key;
            if let (Some(mac), Some(source)) = (
                self.local_mac(interface),
                self.local_address(interface, *target),
            ) {
                let frame = arp_frame(1, mac, source, [0xff; 6], [0; 6], *target);
                self.send(interface, &frame);
                self.counters.requests_sent += 1;
            }
            let pending = self.pending.get_mut(&key).expect("still pending");
            pending.attempts += 1;
            pending.next_at = now_ms + RETRY_MS;
        }
        Progress {
            busy,
            wake_at: self.pending.values().map(|p| p.next_at).min(),
        }
    }

    fn receive_punts(&mut self) -> bool {
        let mut buf = [0_u8; 512];
        let mut busy = false;
        for _ in 0..PUNTS_PER_STEP {
            let n = match self.punt.recv(&mut buf) {
                Ok(n) => n,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            busy = true;
            let message = buf[..n].to_vec();
            match Punt::decode(&message) {
                Ok(punt)
                    if punt.direction == Direction::ToControl
                        && punt.reason == punt::reason::ARP
                        && valid_arp_body(punt.frame) =>
                {
                    let interface = punt.interface.to_owned();
                    self.arp(&interface, punt.frame);
                }
                _ => self.counters.bad_punts += 1,
            }
        }
        busy
    }

    fn arp(&mut self, interface: &str, body: &[u8]) {
        let opcode = u16::from_be_bytes([body[6], body[7]]);
        let mut sender_mac = [0; 6];
        sender_mac.copy_from_slice(&body[8..14]);
        let sender = Ipv4Addr::new(body[14], body[15], body[16], body[17]);
        let target = Ipv4Addr::new(body[24], body[25], body[26], body[27]);
        let for_us = self.is_local(interface, target);
        // Our own address as sender is a conflict, not a neighbor; do not answer it.
        if self.is_local(interface, sender) {
            self.counters.not_learned += 1;
            return;
        }

        // RFC 826: update a neighbor we know or are resolving; add one that is asking
        // for us, if it can be a neighbor on this link.
        let key = (interface.to_owned(), sender);
        let known = self.known.contains_key(&key) || self.pending.contains_key(&key);
        let addable =
            for_us && self.on_link_host(interface, sender) && self.known.len() < KNOWN_MAX;
        if !known && for_us && !addable {
            self.counters.not_learned += 1;
        }
        if (known || addable) && self.known.get(&key) != Some(&sender_mac) {
            self.known.insert(key.clone(), sender_mac);
            self.pending.remove(&key);
            let _ = self.fe.patch(&[Change::set(
                Key::Neighbor {
                    interface: key.0.clone(),
                    address: sender,
                },
                Value::Neighbor { mac: sender_mac },
            )]);
            self.counters.learned += 1;
        }

        if opcode == 1 && for_us {
            if let Some(mac) = self.local_mac(interface) {
                let frame = arp_frame(2, mac, target, sender_mac, sender_mac, sender);
                self.send(interface, &frame);
                self.counters.replies_sent += 1;
            }
        }
    }

    fn send(&mut self, interface: &str, frame: &[u8]) {
        let mut message = Vec::with_capacity(frame.len() + 16);
        let punt = Punt {
            direction: Direction::FromControl,
            reason: punt::reason::ARP,
            interface,
            frame,
        };
        if punt.encode(&mut message).is_ok() {
            let _ = self.punt.send(&message);
        }
    }
}

impl Task for Neighd {
    fn step(&mut self, now_ms: u64) -> Progress {
        let local = self.local.step(&mut AcceptAll);
        let (fe, events) = self.fe.poll();
        let had_events = !events.is_empty();
        self.handle_fe(events, now_ms);
        if let FeState::Adopting(_) = self.fe_state {
            let since = *self.adopt_since.get_or_insert(now_ms);
            if now_ms.saturating_sub(since) >= ADOPT_TIMEOUT_MS {
                self.start_running();
            }
        }
        let punts = self.receive_punts();
        let timers = self.retry(now_ms);
        let (flushed, late) = self.fe.poll();
        self.handle_fe(late, now_ms);
        local
            .and(fe)
            .and(timers)
            .and(flushed)
            .and(Progress::busy(had_events || punts))
    }
}

/// An Ethernet ARP frame.
fn arp_frame(
    opcode: u16,
    sender_mac: [u8; 6],
    sender: Ipv4Addr,
    destination_mac: [u8; 6],
    target_mac: [u8; 6],
    target: Ipv4Addr,
) -> [u8; 42] {
    let mut frame = [0_u8; 42];
    frame[0..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&opcode.to_be_bytes());
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender.octets());
    frame[32..38].copy_from_slice(&target_mac);
    frame[38..42].copy_from_slice(&target.octets());
    frame
}

/// An Ethernet/IPv4 ARP request or reply from a unicast sender MAC.
fn valid_arp_body(body: &[u8]) -> bool {
    if body.len() < ARP_BODY_LEN || body[0..6] != ARP_ETHERNET_IPV4 {
        return false;
    }
    let opcode = u16::from_be_bytes([body[6], body[7]]);
    let sender_mac = &body[8..14];
    matches!(opcode, 1 | 2) && sender_mac != [0; 6] && sender_mac[0] & 1 == 0
}

fn mask(len: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, len: u8) -> bool {
    (u32::from(a) ^ u32::from(b)) & mask(len) == 0
}

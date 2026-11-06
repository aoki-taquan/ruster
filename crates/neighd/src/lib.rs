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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeighdCounters {
    pub requests_sent: u64,
    pub replies_sent: u64,
    pub learned: u64,
    pub adopted: u64,
    pub given_up: u64,
    pub bad_punts: u64,
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
    Running,
}

pub struct Neighd {
    local: Server,
    fe: Client,
    fe_state: FeState,
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

    fn local_address(&self, interface: &str) -> Option<Ipv4Addr> {
        self.local.store().iter().find_map(|(key, _)| match key {
            Key::Address {
                interface: name,
                address,
            } if name == interface => Some(*address),
            _ => None,
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
                    self.fe_state = FeState::Running;
                    self.fe.observe();
                }
                Event::Notification { payload } => {
                    let mut d = Decoder::new(&payload);
                    if let Ok(request) = ResolveRequest::decode(&mut d) {
                        self.resolve(request.interface, request.address, now_ms);
                    }
                }
                Event::Response { .. } => {}
            }
        }
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
            if let (Some(mac), Some(source)) =
                (self.local_mac(interface), self.local_address(interface))
            {
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
                        && punt.frame.len() >= ARP_BODY_LEN =>
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

        // RFC 826: update a neighbor we know or are resolving; add one that is asking
        // for us.
        let key = (interface.to_owned(), sender);
        let wanted = self.known.contains_key(&key) || self.pending.contains_key(&key) || for_us;
        if wanted && !sender.is_unspecified() && self.known.get(&key) != Some(&sender_mac) {
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
        let punts = self.receive_punts();
        let timers = self.retry(now_ms);
        let (flushed, _) = self.fe.poll();
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

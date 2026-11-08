#![forbid(unsafe_code)]
//! The neighbor process: ARP for IPv4 and Neighbor Discovery for IPv6
//! (`docs/design/ce-processes.md`).
//!
//! - It learns the router's own interfaces and addresses from confd, which writes them
//!   to neighd's own small table server.
//! - It answers ARP requests and Neighbor Solicitations for those addresses.
//! - When the FE reports a next hop missing from its neighbor table, neighd sends ARP
//!   requests or Neighbor Solicitations (three, one second apart) and writes the
//!   answer to the FE.
//! - On start it reads the neighbor table the FE already holds and keeps it, so a
//!   restart does not remove a single neighbor from forwarding.
//!
//! - Neighbors packets go to are checked again; those packets no longer go to are
//!   forgotten (`docs/design/ce-processes.md`, "近隣がまだ使われているか"). Every
//!   [`CHECK_MS`] neighd reads the FE's "used" marks (the punt socket's
//!   `NEIGHBOR_USED`). A used neighbor not confirmed for [`REACHABLE_MS`] is probed
//!   with three requests sent to it alone, one second apart, and forgotten when it
//!   does not answer; one not used for [`UNUSED_MS`] is forgotten.
//!
//! Skeleton limits: no announcements or duplicate address detection of our own
//! addresses. Router Solicitations and Advertisements are not neighd's.
//!
//! # Standards
//!
//! - RFC 826: the packet format and the receive rules (update a known sender, add the
//!   sender when the target is us, answer requests for our addresses).
//! - RFC 1122 section 2.3.2.1: at most one request per second per next hop.
//! - RFC 5227 section 2.4: a packet whose sender claims our own address is not learned
//!   or answered.
//! - RFC 4861 section 7.2.3: a Neighbor Solicitation's Source Link-Layer Address is
//!   recorded, and one for our address is answered with a solicited Advertisement
//!   (to all nodes, unsolicited, when the asker is doing duplicate address detection).
//!   A solicitation for another node's address is discarded, not learned from.
//!   Section 7.2.5: an Advertisement updates a neighbor neighd is resolving or knows.
//!   Section 7.2.2: three solicitations one second apart (MAX_MULTICAST_SOLICIT,
//!   RETRANS_TIMER) to the target's solicited-node group. Message checks in `nd.rs`.
//!
//! - RFC 1122 section 2.3.2.1 and RFC 4861 section 7.3: learned neighbors time out;
//!   one still in use is confirmed by a unicast request (ARP's "unicast poll", ND's
//!   PROBE) and removed when it does not answer.
//!
//! Deviations from RFC 826: a sender that targets us is added only if it is a host on
//! that interface's subnet, and at most 4096 neighbors are kept. A packet waiting for a
//! next hop is dropped, not queued (RFC 1122 section 2.3.2.2 says to keep at least
//! one). Conflicts are not announced or defended (RFC 5227 section 2.4). Deviations
//! from RFC 4861: the neighbor states are kept only as far as above (confirmed when
//! learned or answered, probed when used and not confirmed for [`REACHABLE_MS`], a
//! fixed time rather than a random one, with no DELAY state); upper-layer
//! confirmation is not used; an Advertisement always replaces the link-layer address regardless
//! of its Override flag; a solicitation's source is recorded only if it is link-local
//! or on one of the interface's prefixes.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_proto::cbor::Decoder;
use ruster_proto::coap::Code;
use ruster_proto::punt::{self, Direction, Punt};
use ruster_proto::session::{decode_changes, Client, Event, Hook, Server, Store};
use ruster_proto::table::{network, Change, Key, ResolveRequest, Value};
use ruster_proto::task::{Progress, Task};

mod nd;

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
/// How often the FE's "used" marks are read.
pub const CHECK_MS: u64 = 5_000;
/// A used neighbor not confirmed for this long is probed (RFC 4861's REACHABLE_TIME).
pub const REACHABLE_MS: u64 = 30_000;
/// A neighbor no packet went to for this long is forgotten.
pub const UNUSED_MS: u64 = 600_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeighdCounters {
    pub requests_sent: u64,
    pub replies_sent: u64,
    pub learned: u64,
    pub adopted: u64,
    pub given_up: u64,
    pub bad_punts: u64,
    pub not_learned: u64,
    /// Unicast requests sent to confirm a used neighbor, and neighbors forgotten (not
    /// answering those, or not used).
    pub probes_sent: u64,
    pub forgotten: u64,
    /// Router Solicitations and Advertisements and Redirects, which are not neighd's,
    /// and Neighbor Solicitations for other nodes' addresses.
    pub not_for_neighd: u64,
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
    known: BTreeMap<(String, IpAddr), [u8; 6]>,
    pending: BTreeMap<(String, IpAddr), Pending>,
    /// When each known neighbor was last confirmed (learned or answered), and last
    /// used (a packet went to it).
    confirmed: BTreeMap<(String, IpAddr), u64>,
    used: BTreeMap<(String, IpAddr), u64>,
    /// Known neighbors being probed.
    probing: BTreeMap<(String, IpAddr), Pending>,
    next_check: u64,
    /// When the marks were last asked for: the FE's answers say a packet went to
    /// the neighbor by then.
    asked_at: u64,
    now_ms: u64,
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
            confirmed: BTreeMap::new(),
            used: BTreeMap::new(),
            probing: BTreeMap::new(),
            next_check: 0,
            asked_at: 0,
            now_ms: 0,
            counters: NeighdCounters::default(),
        })
    }

    /// Accepts the connection confd writes interfaces and addresses on.
    pub fn attach_config(&mut self, stream: UnixStream) -> io::Result<()> {
        self.local.attach(stream, CONFIG_TABLES)
    }

    /// True once the FE connection closed (the FE stopped or restarted).
    pub fn fe_closed(&self) -> bool {
        self.fe.is_closed()
    }

    /// Replaces a closed FE connection and its punt socket, and gives the FE every
    /// neighbor neighd knows again (a restarted FE starts with an empty table).
    pub fn reconnect_fe(&mut self, fe: UnixStream, punt: UnixDatagram) -> io::Result<()> {
        punt.set_nonblocking(true)?;
        let mut fe = Client::new(fe)?;
        fe.resync_begin();
        let changes: Vec<Change> = self
            .known
            .iter()
            .map(|((interface, address), mac)| {
                Change::set(
                    Key::Neighbor {
                        interface: interface.clone(),
                        address: *address,
                    },
                    Value::Neighbor { mac: *mac },
                )
            })
            .collect();
        if !changes.is_empty() {
            fe.patch(&changes).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"))
            })?;
        }
        fe.resync_end();
        self.fe = fe;
        self.punt = punt;
        self.adopt_since = None;
        self.start_running();
        Ok(())
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
                ) if name == interface => match address {
                    IpAddr::V4(address) => Some((*address, *prefix_len)),
                    IpAddr::V6(_) => None,
                },
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

    /// The IPv6 address to ask from: link-local for a link-local target, else one on
    /// the target's prefix, else link-local, else any (RFC 6724 in its simplest form).
    fn local_address_v6(&self, interface: &str, target: Ipv6Addr) -> Option<Ipv6Addr> {
        let addresses: Vec<(Ipv6Addr, u8)> = self
            .local
            .store()
            .iter()
            .filter_map(|(key, value)| match (key, value) {
                (
                    Key::Address {
                        interface: name,
                        address: IpAddr::V6(address),
                    },
                    Value::Address { prefix_len },
                ) if name == interface => Some((*address, *prefix_len)),
                _ => None,
            })
            .collect();
        let link_local = addresses
            .iter()
            .map(|&(a, _)| a)
            .find(Ipv6Addr::is_unicast_link_local);
        if target.is_unicast_link_local() {
            return link_local;
        }
        let on_prefix = addresses
            .iter()
            .find(|&&(a, len)| network(IpAddr::V6(a), len) == network(IpAddr::V6(target), len));
        on_prefix
            .map(|&(a, _)| a)
            .or(link_local)
            .or(addresses.first().map(|&(a, _)| a))
    }

    /// Link-local, or on one of the interface's IPv6 prefixes.
    fn on_link_v6(&self, interface: &str, address: Ipv6Addr) -> bool {
        address.is_unicast_link_local()
            || self.local.store().iter().any(|(key, value)| {
                matches!(
                    (key, value),
                    (
                        Key::Address {
                            interface: name,
                            address: IpAddr::V6(local),
                        },
                        Value::Address { prefix_len },
                    ) if name == interface
                        && network(IpAddr::V6(*local), *prefix_len)
                            == network(IpAddr::V6(address), *prefix_len)
                )
            })
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

    fn is_local(&self, interface: &str, address: impl Into<IpAddr>) -> bool {
        self.local
            .store()
            .get(&Key::Address {
                interface: interface.to_owned(),
                address: address.into(),
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
                                let key = (interface, address);
                                self.confirmed.insert(key.clone(), now_ms);
                                self.known.insert(key, mac);
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

    fn resolve(&mut self, interface: String, address: IpAddr, now_ms: u64) {
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
        let due: Vec<(String, IpAddr)> = self
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
            let request = match (self.local_mac(interface), *target) {
                (Some(mac), IpAddr::V4(target)) => {
                    self.local_address(interface, target).map(|source| {
                        let frame = arp_frame(1, mac, source, [0xff; 6], [0; 6], target);
                        (punt::reason::ARP, frame.to_vec())
                    })
                }
                (Some(mac), IpAddr::V6(target)) => self
                    .local_address_v6(interface, target)
                    .map(|source| (punt::reason::ND, nd::solicitation(mac, source, target))),
                (None, _) => None,
            };
            if let Some((reason, frame)) = request {
                self.send(interface, reason, &frame);
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

    fn confirm(&mut self, key: &(String, IpAddr)) {
        self.confirmed.insert(key.clone(), self.now_ms);
        self.probing.remove(key);
    }

    /// Removes a known neighbor, here and in the FE.
    fn forget(&mut self, key: &(String, IpAddr)) {
        self.known.remove(key);
        self.confirmed.remove(key);
        self.used.remove(key);
        self.probing.remove(key);
        let _ = self.fe.patch(&[Change::delete(Key::Neighbor {
            interface: key.0.clone(),
            address: key.1,
        })]);
        self.counters.forgotten += 1;
    }

    /// Reads the FE's "used" marks every [`CHECK_MS`], probes the used neighbors that
    /// are not confirmed, forgets those not used and those not answering.
    fn check(&mut self, now_ms: u64) -> Progress {
        let mut busy = false;
        if now_ms >= self.next_check
            && !self.known.is_empty()
            && matches!(self.fe_state, FeState::Running { .. })
        {
            self.next_check = now_ms + CHECK_MS;
            self.asked_at = now_ms;
            self.send("-", punt::reason::NEIGHBOR_USED, &[]);
            let keys: Vec<_> = self.known.keys().cloned().collect();
            for key in keys {
                let confirmed = self.confirmed.get(&key).copied().unwrap_or(now_ms);
                let used = self.used.get(&key).copied();
                let last = used.map_or(confirmed, |used| used.max(confirmed));
                if now_ms.saturating_sub(last) >= UNUSED_MS {
                    self.forget(&key);
                    busy = true;
                } else if used.is_some_and(|used| used > confirmed)
                    && now_ms.saturating_sub(confirmed) >= REACHABLE_MS
                    && !self.probing.contains_key(&key)
                {
                    self.probing.insert(
                        key,
                        Pending {
                            attempts: 0,
                            next_at: now_ms,
                        },
                    );
                }
            }
        }
        let due: Vec<_> = self
            .probing
            .iter()
            .filter(|(_, p)| p.next_at <= now_ms)
            .map(|(key, _)| key.clone())
            .collect();
        for key in due {
            busy = true;
            if self.probing[&key].attempts >= ATTEMPTS {
                self.forget(&key);
                continue;
            }
            let (interface, target) = &key;
            let neighbor = self.known[&key];
            let probe = match (self.local_mac(interface), *target) {
                (Some(mac), IpAddr::V4(target)) => {
                    self.local_address(interface, target).map(|source| {
                        let frame = arp_frame(1, mac, source, neighbor, [0; 6], target);
                        (punt::reason::ARP, frame.to_vec())
                    })
                }
                (Some(mac), IpAddr::V6(target)) => {
                    self.local_address_v6(interface, target).map(|source| {
                        (
                            punt::reason::ND,
                            nd::solicitation_to(mac, source, target, neighbor),
                        )
                    })
                }
                (None, _) => None,
            };
            if let Some((reason, frame)) = probe {
                let interface = interface.clone();
                self.send(&interface, reason, &frame);
                self.counters.probes_sent += 1;
            }
            let probing = self.probing.get_mut(&key).expect("still probing");
            probing.attempts += 1;
            probing.next_at = now_ms + RETRY_MS;
        }
        let wake = self.probing.values().map(|p| p.next_at).min();
        let check_at = (!self.known.is_empty()).then_some(self.next_check);
        Progress {
            busy,
            wake_at: match (wake, check_at) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
        }
    }

    fn receive_punts(&mut self) -> bool {
        let mut buf = [0_u8; 2_048];
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
                Ok(punt)
                    if punt.direction == Direction::ToControl
                        && punt.reason == punt::reason::NEIGHBOR_USED =>
                {
                    let address = match punt.frame.len() {
                        4 => <[u8; 4]>::try_from(punt.frame).ok().map(IpAddr::from),
                        16 => <[u8; 16]>::try_from(punt.frame).ok().map(IpAddr::from),
                        _ => None,
                    };
                    match address {
                        Some(address) => {
                            let key = (punt.interface.to_owned(), address);
                            if self.known.contains_key(&key) {
                                self.used.insert(key, self.asked_at);
                            }
                        }
                        None => self.counters.bad_punts += 1,
                    }
                }
                Ok(punt)
                    if punt.direction == Direction::ToControl
                        && punt.reason == punt::reason::ND =>
                {
                    let interface = punt.interface.to_owned();
                    match nd::parse(punt.frame) {
                        Ok(message) => self.nd(&interface, message),
                        Err(nd::Refused::NotForNeighd) => self.counters.not_for_neighd += 1,
                        Err(nd::Refused::Invalid) => self.counters.bad_punts += 1,
                    }
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
        let key = (interface.to_owned(), IpAddr::V4(sender));
        let known = self.known.contains_key(&key) || self.pending.contains_key(&key);
        let addable =
            for_us && self.on_link_host(interface, sender) && self.known.len() < KNOWN_MAX;
        if !known && for_us && !addable {
            self.counters.not_learned += 1;
        }
        if self.known.contains_key(&key) {
            self.confirm(&key);
        }
        if (known || addable) && self.known.get(&key) != Some(&sender_mac) {
            self.known.insert(key.clone(), sender_mac);
            self.confirm(&key);
            self.pending.remove(&key);
            let _ = self.fe.patch(&[Change::set(
                Key::Neighbor {
                    interface: key.0.clone(),
                    address: sender.into(),
                },
                Value::Neighbor { mac: sender_mac },
            )]);
            self.counters.learned += 1;
        }

        if opcode == 1 && for_us {
            if let Some(mac) = self.local_mac(interface) {
                let frame = arp_frame(2, mac, target, sender_mac, sender_mac, sender);
                self.send(interface, punt::reason::ARP, &frame);
                self.counters.replies_sent += 1;
            }
        }
    }

    /// Records `mac` for a neighbor and writes it to the FE if it changed.
    fn learn(&mut self, key: (String, IpAddr), mac: [u8; 6]) {
        self.pending.remove(&key);
        self.confirm(&key);
        if self.known.get(&key) == Some(&mac) {
            return;
        }
        let _ = self.fe.patch(&[Change::set(
            Key::Neighbor {
                interface: key.0.clone(),
                address: key.1,
            },
            Value::Neighbor { mac },
        )]);
        self.known.insert(key, mac);
        self.counters.learned += 1;
    }

    /// RFC 4861 sections 7.2.3 to 7.2.5, for a router with no Neighbor Unreachability
    /// Detection yet.
    fn nd(&mut self, interface: &str, message: nd::Message) {
        let Some(mac) = self.local_mac(interface) else {
            return;
        };
        match message.kind {
            nd::Kind::Solicitation {
                target,
                source_link_layer,
            } => {
                // Our own address as source is a duplicate, not a neighbor.
                if self.is_local(interface, message.source) {
                    self.counters.not_learned += 1;
                    return;
                }
                // One for another node's address is not ours to learn from or answer
                // (RFC 4861 7.2.3: silently discarded).
                if !self.is_local(interface, target) {
                    self.counters.not_for_neighd += 1;
                    return;
                }
                if let Some(link_layer) = source_link_layer {
                    if !message.source.is_unspecified()
                        && self.on_link_v6(interface, message.source)
                    {
                        let key = (interface.to_owned(), IpAddr::V6(message.source));
                        if self.known.contains_key(&key) || self.known.len() < KNOWN_MAX {
                            self.learn(key, link_layer);
                        } else {
                            self.counters.not_learned += 1;
                        }
                    }
                }
                let to = if message.source.is_unspecified() {
                    None
                } else {
                    Some((
                        message.source,
                        source_link_layer.unwrap_or(message.source_mac),
                    ))
                };
                let frame = nd::advertisement(mac, target, to);
                self.send(interface, punt::reason::ND, &frame);
                self.counters.replies_sent += 1;
            }
            nd::Kind::Advertisement {
                target,
                target_link_layer,
                solicited,
                ..
            } => {
                if self.is_local(interface, target) {
                    // Someone else claims our address.
                    self.counters.not_learned += 1;
                    return;
                }
                let key = (interface.to_owned(), IpAddr::V6(target));
                // A solicited Advertisement confirms reachability (RFC 4861 7.3.3).
                if solicited && self.known.contains_key(&key) {
                    self.confirm(&key);
                }
                let wanted = self.pending.contains_key(&key) || self.known.contains_key(&key);
                match target_link_layer {
                    Some(link_layer) if wanted => self.learn(key, link_layer),
                    _ => self.counters.not_learned += 1,
                }
            }
        }
    }

    fn send(&mut self, interface: &str, reason: u16, frame: &[u8]) {
        let mut message = Vec::with_capacity(frame.len() + 16);
        let punt = Punt {
            direction: Direction::FromControl,
            reason,
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
        self.now_ms = now_ms;
        let punts = self.receive_punts();
        let timers = self.retry(now_ms);
        let checks = self.check(now_ms);
        let (flushed, late) = self.fe.poll();
        self.handle_fe(late, now_ms);
        local
            .and(fe)
            .and(timers)
            .and(checks)
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

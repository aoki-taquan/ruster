#![forbid(unsafe_code)]
//! The configuration process (`docs/design/ce-processes.md`, "ruster-confd").
//!
//! confd holds the router's configuration and turns it into what each process needs:
//!
//! | To | What |
//! |---|---|
//! | FE | interfaces, addresses, and the default VRF's firewall rules and NAT |
//! | neighd | interfaces and addresses (to answer ARP and choose source addresses) |
//! | ribd | static routes out of usable interfaces and the connected routes of the addresses, as source `confd` |
//!
//! On every (re)connection confd sends everything between resync-begin and resync-end,
//! so entries it no longer has are removed, and tells ribd `sync-done`. After that it
//! sends only what changed.
//!
//! The configuration file is TOML ([`file`](mod@file)). Every interface also gets an IPv6
//! link-local address from its MAC address ([`link_local`]). Connected routes come from
//! the IPv4 and global IPv6 prefixes of enabled interfaces. Limits: one IPv4 address per
//! interface, no dynamic values from other daemons yet.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Client, Event};
use ruster_proto::table::{network, Change, Key, NextHop, RouteAction, Value};
use ruster_proto::task::{Progress, Task};

pub mod apply;
pub mod file;
pub mod kernel;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: String,
    pub mac: [u8; 6],
    pub mtu: u16,
    pub enabled: bool,
    /// The interface's IPv4 address and prefix length.
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// The interface's IPv6 addresses and prefix lengths, besides the link-local
    /// address confd adds from the MAC address.
    pub ipv6: Vec<(Ipv6Addr, u8)>,
    /// The VRF the interface belongs to; its connected routes are in it.
    pub vrf: String,
    /// For a VLAN sub-interface: its parent interface and VLAN ID.
    pub vlan: Option<(String, u16)>,
    /// For an IPv4 in IPv6 tunnel: its local and remote IPv6 addresses.
    pub tunnel: Option<(Ipv6Addr, Ipv6Addr)>,
    /// For a PPPoE session: its parent interface, session ID and peer MAC.
    pub pppoe: Option<(String, u16, [u8; 6])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRoute {
    /// The VRF the route is in.
    pub vrf: String,
    pub prefix: IpAddr,
    pub len: u8,
    pub target: RouteTarget,
}

/// Where a static route sends its packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteTarget {
    /// Out of `interface` (which may be in another VRF), to `via` or, when it is
    /// `None`, to the destination on the link.
    Next {
        interface: String,
        via: Option<IpAddr>,
    },
    /// Looked up again in another VRF.
    LookupVrf(String),
    /// Dropped silently.
    Discard,
    /// Dropped with a Destination Unreachable.
    Reject,
}

/// A WireGuard interface (also an entry of `interfaces`, which has its MAC address,
/// MTU and addresses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardConfig {
    pub name: String,
    pub listen_port: u16,
    /// The IPv4 address the outer packets are sent from.
    pub local: Ipv4Addr,
    pub peers: Vec<WireguardPeerConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardPeerConfig {
    pub name: String,
    pub endpoint: (Ipv4Addr, u16),
    pub allowed: Vec<(Ipv4Addr, u8)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub interfaces: Vec<InterfaceConfig>,
    pub wireguard: Vec<WireguardConfig>,
    pub static_routes: Vec<StaticRoute>,
    /// The default VRF's forward firewall rules, in order.
    pub firewall: Vec<ruster_proto::table::FirewallRule>,
    /// How the default VRF's forward firewall filters where no rule decides.
    pub firewall_filtering: ruster_proto::table::NatFiltering,
    /// The ICMP error rate limits (IPv4 interval, IPv6 burst and interval), when set.
    pub icmp_errors: Option<(u32, u32, u32)>,
    /// The default VRF's NAPT.
    pub nat: Option<ruster_proto::table::Nat>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfdCounters {
    pub patches_sent: u64,
    pub patches_refused: u64,
    /// Notifications from the FE that a WireGuard peer needs its key exchange.
    pub key_exchange_requests: u64,
}

/// The most key exchange requests confd keeps for whoever does the exchange.
const KEY_REQUESTS_KEPT: usize = 64;

/// A process confd writes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKind {
    Fe,
    Ribd,
    Neighd,
}

impl std::fmt::Display for PeerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Fe => "the FE",
            Self::Ribd => "ribd",
            Self::Neighd => "neighd",
        })
    }
}

/// One process confd writes to, and what it accepted.
struct Peer {
    client: Client,
    /// What the peer holds from confd, as far as its answers tell.
    sent: BTreeMap<Key, Value>,
    /// Patches waiting for an answer, each with the configuration generation it came
    /// from and what the peer holds once it is accepted.
    in_flight: Vec<(u32, u64, BTreeMap<Key, Value>)>,
    /// resync-begin was sent; resync-end follows once a full send is accepted, so a
    /// refused send never deletes what the peer holds.
    resync_open: bool,
    /// ribd wants `sync-done` after each accepted send.
    says_done: bool,
    /// The resync-end waiting for an answer. When it is refused, what the peer holds
    /// stays marked stale, and resync-end goes again after the next accepted change.
    resync_end: Option<u32>,
}

impl Peer {
    /// What the peer will hold once every patch in flight is accepted.
    fn expected(&self) -> &BTreeMap<Key, Value> {
        self.in_flight
            .last()
            .map_or(&self.sent, |(_, _, held)| held)
    }

    /// Handles one answer from the peer.
    fn answer(&mut self, token: u32, accepted: bool) {
        if self.resync_end == Some(token) {
            self.resync_end = None;
            self.resync_open |= !accepted;
            return;
        }
        let Some(at) = self.in_flight.iter().position(|(t, _, _)| *t == token) else {
            return;
        };
        let (_, _, held) = self.in_flight.remove(at);
        if accepted {
            self.sent = held;
            if self.in_flight.is_empty() {
                if self.resync_open {
                    self.resync_end = Some(self.client.resync_end());
                    self.resync_open = false;
                }
                if self.says_done {
                    self.client.sync_done();
                }
            }
        } else {
            // Unknown what the peer holds now: send everything with the next change
            // and remove the rest then.
            // resync-begin again even if one is open: patches sent after the refused
            // one may have been accepted, and this marks what they wrote as stale.
            self.in_flight.clear();
            self.sent.clear();
            self.client.resync_begin();
            self.resync_open = true;
        }
    }
}

pub struct Confd {
    config: Config,
    fe: Option<Peer>,
    ribd: Option<Peer>,
    neighd: Option<Peer>,
    counters: ConfdCounters,
    /// Counts [`Confd::set_config`] calls; each patch carries the one it came from.
    generation: u64,
    /// The last refused patch: its process, reason and generation.
    last_refusal: Option<(PeerKind, String, u64)>,
    /// WireGuard peers the FE says need a key exchange, until taken.
    key_requests: Vec<ruster_proto::table::KeyExchangeRequest>,
}

impl std::fmt::Debug for Confd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Confd")
            .field("config", &self.config)
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl Confd {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            fe: None,
            ribd: None,
            neighd: None,
            counters: ConfdCounters::default(),
            generation: 0,
            last_refusal: None,
            key_requests: Vec::new(),
        }
    }

    /// Connects to the FE as the writer of interfaces, addresses, firewall rules and NAT.
    pub fn connect_fe(&mut self, stream: UnixStream) -> io::Result<()> {
        let mut peer = self.full_send(stream, Self::fe_tables, false)?;
        // The FE tells when a WireGuard peer needs its key exchange.
        peer.client.observe();
        self.fe = Some(peer);
        Ok(())
    }

    /// Connects to ribd as the route source `confd`.
    pub fn connect_ribd(&mut self, stream: UnixStream) -> io::Result<()> {
        self.ribd = Some(self.full_send(stream, Self::routes, true)?);
        Ok(())
    }

    /// Connects to neighd's configuration table server.
    pub fn connect_neighd(&mut self, stream: UnixStream) -> io::Result<()> {
        self.neighd = Some(self.full_send(stream, Self::interface_tables, false)?);
        Ok(())
    }

    /// The peers whose connection closed. Connecting again sends everything again.
    pub fn closed(&self) -> Vec<PeerKind> {
        [
            (PeerKind::Fe, &self.fe),
            (PeerKind::Ribd, &self.ribd),
            (PeerKind::Neighd, &self.neighd),
        ]
        .into_iter()
        .filter(|(_, peer)| peer.as_ref().is_some_and(|peer| peer.client.is_closed()))
        .map(|(kind, _)| kind)
        .collect()
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn counters(&self) -> ConfdCounters {
        self.counters
    }

    /// The WireGuard peers the FE has asked a key exchange for since the last call.
    /// A key exchange daemon outside ruster does it and gives confd the session.
    pub fn take_key_exchange_requests(&mut self) -> Vec<ruster_proto::table::KeyExchangeRequest> {
        std::mem::take(&mut self.key_requests)
    }

    /// The generation of the configuration now held; each [`Confd::set_config`] adds one.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The process that last refused a patch of generation `generation` or later, and
    /// the reason it gave.
    pub fn refused_since(&self, generation: u64) -> Option<(PeerKind, &str)> {
        self.last_refusal
            .as_ref()
            .filter(|(_, _, g)| *g >= generation)
            .map(|(kind, reason, _)| (*kind, reason.as_str()))
    }

    /// True when every connected process has answered every change sent to it, and
    /// the resync-end after them.
    pub fn settled(&self) -> bool {
        [&self.fe, &self.ribd, &self.neighd]
            .into_iter()
            .flatten()
            .all(|peer| {
                peer.client.is_closed() || (peer.in_flight.is_empty() && peer.resync_end.is_none())
            })
    }

    /// The processes that are not connected now.
    pub fn absent(&self) -> Vec<PeerKind> {
        [
            (PeerKind::Fe, &self.fe),
            (PeerKind::Ribd, &self.ribd),
            (PeerKind::Neighd, &self.neighd),
        ]
        .into_iter()
        .filter(|(_, peer)| peer.as_ref().is_none_or(|peer| peer.client.is_closed()))
        .map(|(kind, _)| kind)
        .collect()
    }

    /// Replaces the configuration; only the differences are sent.
    pub fn set_config(&mut self, config: Config) {
        self.config = config;
        self.generation += 1;
        let generation = self.generation;
        let interfaces = self.interface_tables();
        let fe = self.fe_tables();
        let routes = self.routes();
        let counters = &mut self.counters;
        for (peer, desired) in [
            (&mut self.fe, &fe),
            (&mut self.neighd, &interfaces),
            (&mut self.ribd, &routes),
        ] {
            if let Some(peer) = peer {
                send_diff(peer, desired, generation, counters);
            }
        }
    }

    fn full_send(
        &mut self,
        stream: UnixStream,
        desired: fn(&Self) -> BTreeMap<Key, Value>,
        says_done: bool,
    ) -> io::Result<Peer> {
        let mut client = Client::new(stream)?;
        let desired = desired(self);
        client.resync_begin();
        let mut peer = Peer {
            client,
            sent: BTreeMap::new(),
            in_flight: Vec::new(),
            resync_open: true,
            says_done,
            resync_end: None,
        };
        if desired.is_empty() {
            peer.resync_end = Some(peer.client.resync_end());
            peer.resync_open = false;
            if says_done {
                peer.client.sync_done();
            }
        } else {
            send_diff(&mut peer, &desired, self.generation, &mut self.counters);
        }
        Ok(peer)
    }

    /// The interfaces outside the network the firewall guards: NAT's outside and
    /// those the default VRF's default routes leave through (RFC 6092's exterior).
    fn firewall_outside(&self) -> Vec<String> {
        let mut outside: Vec<String> = self
            .config
            .nat
            .iter()
            .map(|nat| nat.outside.clone())
            .chain(
                self.config
                    .static_routes
                    .iter()
                    .filter_map(|route| match &route.target {
                        RouteTarget::Next { interface, .. }
                            if route.vrf == ruster_proto::table::DEFAULT_VRF && route.len == 0 =>
                        {
                            Some(interface.clone())
                        }
                        _ => None,
                    }),
            )
            .collect();
        outside.sort();
        outside.dedup();
        outside
    }

    /// The interface tables, the firewall rules (numbered from 1 in order) and NAT.
    fn fe_tables(&self) -> BTreeMap<Key, Value> {
        let mut out = self.interface_tables();
        if let Some((ipv4_interval_ms, ipv6_burst, ipv6_interval_ms)) = self.config.icmp_errors {
            out.insert(
                Key::IcmpErrors {
                    vrf: ruster_proto::table::DEFAULT_VRF.to_owned(),
                },
                Value::IcmpErrors {
                    ipv4_interval_ms,
                    ipv6_burst,
                    ipv6_interval_ms,
                },
            );
        }
        if !self.config.firewall.is_empty() {
            out.insert(
                Key::FirewallPolicy {
                    vrf: ruster_proto::table::DEFAULT_VRF.to_owned(),
                },
                Value::FirewallPolicy {
                    filtering: self.config.firewall_filtering,
                    outside: self.firewall_outside(),
                },
            );
        }
        for (id, rule) in (1..).zip(&self.config.firewall) {
            out.insert(
                Key::FirewallRule {
                    vrf: ruster_proto::table::DEFAULT_VRF.to_owned(),
                    id,
                },
                Value::FirewallRule(rule.clone()),
            );
        }
        for wireguard in &self.config.wireguard {
            out.insert(
                Key::Wireguard {
                    interface: wireguard.name.clone(),
                },
                Value::Wireguard(ruster_proto::table::Wireguard {
                    listen_port: wireguard.listen_port,
                    local: wireguard.local,
                }),
            );
            for peer in &wireguard.peers {
                out.insert(
                    Key::WireguardPeer {
                        interface: wireguard.name.clone(),
                        peer: peer.name.clone(),
                    },
                    Value::WireguardPeer(ruster_proto::table::WireguardPeer {
                        endpoint: peer.endpoint.0,
                        port: peer.endpoint.1,
                        allowed: peer.allowed.clone(),
                    }),
                );
            }
        }
        if let Some(nat) = &self.config.nat {
            out.insert(
                Key::Nat {
                    vrf: ruster_proto::table::DEFAULT_VRF.to_owned(),
                },
                Value::Nat(nat.clone()),
            );
        }
        out
    }

    fn interface_tables(&self) -> BTreeMap<Key, Value> {
        let mut out = BTreeMap::new();
        for interface in &self.config.interfaces {
            out.insert(
                Key::Interface {
                    name: interface.name.clone(),
                },
                Value::Interface {
                    enabled: interface.enabled,
                    mac: interface.mac,
                    mtu: interface.mtu,
                    vrf: interface.vrf.clone(),
                    vlan: interface
                        .vlan
                        .as_ref()
                        .map(|(parent, id)| ruster_proto::table::Vlan {
                            parent: parent.clone(),
                            id: *id,
                        }),
                    tunnel: interface
                        .tunnel
                        .map(|(local, remote)| ruster_proto::table::Tunnel { local, remote }),
                    pppoe: interface.pppoe.as_ref().map(|(parent, session, peer)| {
                        ruster_proto::table::Pppoe {
                            parent: parent.clone(),
                            session: *session,
                            peer: *peer,
                        }
                    }),
                },
            );
            let link_local = (IpAddr::V6(link_local(interface.mac)), 64);
            let addresses = interface
                .ipv4
                .map(|(a, len)| (IpAddr::V4(a), len))
                .into_iter()
                .chain(std::iter::once(link_local))
                .chain(interface.ipv6.iter().map(|&(a, len)| (IpAddr::V6(a), len)));
            for (address, prefix_len) in addresses {
                out.insert(
                    Key::Address {
                        interface: interface.name.clone(),
                        address,
                    },
                    Value::Address { prefix_len },
                );
            }
        }
        out
    }

    /// Whether packets can leave through `name`: it is enabled, and so is the parent
    /// a VLAN sub-interface or PPPoE session runs on.
    fn usable(&self, name: &str) -> bool {
        let find = |name: &str| self.config.interfaces.iter().find(|i| i.name == name);
        let Some(interface) = find(name) else {
            return false;
        };
        let parent = interface
            .vlan
            .as_ref()
            .map(|(parent, _)| parent)
            .or(interface.pppoe.as_ref().map(|(parent, _, _)| parent));
        interface.enabled && parent.is_none_or(|parent| self.usable(parent))
    }

    /// Connected routes of enabled interfaces, then static routes. A static route for
    /// a connected prefix is left out: the connected route wins, as on most routers.
    fn routes(&self) -> BTreeMap<Key, Value> {
        let mut out = BTreeMap::new();
        for interface in self.config.interfaces.iter().filter(|i| i.enabled) {
            // Link-local prefixes are on every link and never forwarded.
            let prefixes = interface
                .ipv4
                .map(|(a, len)| (IpAddr::V4(a), len))
                .into_iter()
                .chain(
                    interface
                        .ipv6
                        .iter()
                        .filter(|(a, _)| !a.is_unicast_link_local())
                        .map(|&(a, len)| (IpAddr::V6(a), len)),
                );
            for (address, len) in prefixes {
                out.insert(
                    route_key(&interface.vrf, network(address, len), len),
                    Value::Route(RouteAction::Forward(vec![NextHop {
                        interface: interface.name.clone(),
                        address: None,
                    }])),
                );
            }
        }
        for route in &self.config.static_routes {
            // A static route out of a disabled interface cannot be used: it is not
            // offered, so that another source's route for the prefix is chosen.
            if let RouteTarget::Next { interface, .. } = &route.target {
                if !self.usable(interface) {
                    continue;
                }
            }
            let action = match &route.target {
                RouteTarget::Next { interface, via } => RouteAction::Forward(vec![NextHop {
                    interface: interface.clone(),
                    address: *via,
                }]),
                RouteTarget::LookupVrf(vrf) => RouteAction::LookupVrf(vrf.clone()),
                RouteTarget::Discard => RouteAction::Discard,
                RouteTarget::Reject => RouteAction::Reject,
            };
            out.entry(route_key(&route.vrf, route.prefix, route.len))
                .or_insert(Value::Route(action));
        }
        out
    }
}

fn route_key(vrf: &str, prefix: IpAddr, len: u8) -> Key {
    Key::Route {
        vrf: vrf.to_owned(),
        prefix,
        len,
    }
}

/// The link-local address of an interface: fe80::/64 with the modified EUI-64 interface
/// identifier of its MAC address (RFC 4291 appendix A, RFC 4862 section 5.3).
pub fn link_local(mac: [u8; 6]) -> Ipv6Addr {
    Ipv6Addr::from([
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ])
}

fn send_diff(
    peer: &mut Peer,
    desired: &BTreeMap<Key, Value>,
    generation: u64,
    counters: &mut ConfdCounters,
) {
    let expected = peer.expected();
    let mut changes = Vec::new();
    for (key, value) in desired {
        if expected.get(key) != Some(value) {
            changes.push(Change::set(key.clone(), value.clone()));
        }
    }
    for key in expected.keys() {
        if !desired.contains_key(key) {
            changes.push(Change::delete(key.clone()));
        }
    }
    if changes.is_empty() {
        return;
    }
    if let Ok(token) = peer.client.patch(&changes) {
        counters.patches_sent += 1;
        peer.in_flight.push((token, generation, desired.clone()));
    }
}

impl Task for Confd {
    fn step(&mut self, _now_ms: u64) -> Progress {
        let mut progress = Progress::IDLE;
        // Peers that refused a patch older than the configuration now held: a refusal
        // drops every patch in flight, the newer ones too, so they get it all again.
        let mut resend = Vec::new();
        for (kind, peer) in [
            (PeerKind::Fe, &mut self.fe),
            (PeerKind::Ribd, &mut self.ribd),
            (PeerKind::Neighd, &mut self.neighd),
        ] {
            let Some(peer) = peer else { continue };
            let (polled, events) = peer.client.poll();
            progress = progress.and(polled);
            for event in events {
                if let (PeerKind::Fe, Event::Notification { payload }) = (kind, &event) {
                    let mut d = ruster_proto::cbor::Decoder::new(payload);
                    if let Ok(request) = ruster_proto::table::KeyExchangeRequest::decode(&mut d) {
                        self.counters.key_exchange_requests += 1;
                        if self.key_requests.len() < KEY_REQUESTS_KEPT
                            && !self.key_requests.contains(&request)
                        {
                            self.key_requests.push(request);
                        }
                    }
                    continue;
                }
                if let Event::Response {
                    token,
                    code,
                    payload,
                } = event
                {
                    let accepted = code.class() == 2;
                    if !accepted {
                        self.counters.patches_refused += 1;
                        if let Some(&(_, generation, _)) =
                            peer.in_flight.iter().find(|(t, _, _)| *t == token)
                        {
                            let newer = self
                                .last_refusal
                                .as_ref()
                                .is_some_and(|(_, _, g)| *g > generation);
                            if !newer {
                                self.last_refusal = Some((
                                    kind,
                                    String::from_utf8_lossy(&payload).into_owned(),
                                    generation,
                                ));
                            }
                            if generation < self.generation && !resend.contains(&kind) {
                                resend.push(kind);
                            }
                        }
                    }
                    peer.answer(token, accepted);
                }
            }
        }
        for kind in resend {
            let (desired, peer) = match kind {
                PeerKind::Fe => (self.fe_tables(), &mut self.fe),
                PeerKind::Ribd => (self.routes(), &mut self.ribd),
                PeerKind::Neighd => (self.interface_tables(), &mut self.neighd),
            };
            if let Some(peer) = peer {
                send_diff(peer, &desired, self.generation, &mut self.counters);
                progress = progress.and(Progress::busy(true));
            }
        }
        progress
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_static_route_for_a_connected_prefix_does_not_replace_it() {
        let lan = InterfaceConfig {
            name: "lan".into(),
            mac: [2, 0, 0, 0, 0, 1],
            mtu: 1500,
            enabled: true,
            ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 24)),
            ipv6: Vec::new(),
            vrf: "default".into(),
            vlan: None,
            tunnel: None,
            pppoe: None,
        };
        let route = |len| StaticRoute {
            vrf: "default".into(),
            prefix: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            len,
            target: RouteTarget::Discard,
        };
        let confd = Confd::new(Config {
            wireguard: Vec::new(),
            interfaces: vec![lan],
            static_routes: vec![route(24), route(25)],
            firewall: Vec::new(),
            firewall_filtering: Default::default(),
            icmp_errors: None,
            nat: None,
        });
        let routes = confd.routes();
        let connected = Value::Route(RouteAction::Forward(vec![NextHop {
            interface: "lan".into(),
            address: None,
        }]));
        let key = |len| route_key("default", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), len);
        assert_eq!(routes.get(&key(24)), Some(&connected));
        assert_eq!(
            routes.get(&key(25)),
            Some(&Value::Route(RouteAction::Discard))
        );
    }
}

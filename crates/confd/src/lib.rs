#![forbid(unsafe_code)]
//! The configuration process (`docs/design/ce-processes.md`, "ruster-confd").
//!
//! confd holds the router's configuration and turns it into what each process needs:
//!
//! | To | What |
//! |---|---|
//! | FE | interfaces, addresses, the default VRF's firewall rules and NAT, and the punt classes that hand DHCP and DHCPv6 to `ruster-kea` |
//! | neighd | interfaces and addresses (to answer ARP and choose source addresses); the `ra` part on `confd/part/ra/part.sock` |
//! | ribd | static routes out of usable interfaces and the connected routes of the addresses, as source `confd` |
//! | a process for a module (`ruster-unbound` for `dns`, `ruster-kea` for `dhcp`, `ruster-pppoed` for `pppoe`, `ruster-frr` for `frr`, `ruster-dhcpc` for `dhcpc`) | that module's part of the lock form, on `confd/part/<module>/part.sock` ([`part`]) |
//!
//! On every (re)connection confd sends everything between resync-begin and resync-end,
//! so entries it no longer has are removed, and tells ribd `sync-done`. After that it
//! sends only what changed.
//!
//! The configuration file is TOML ([`file`](mod@file)). Every interface also gets an IPv6
//! link-local address from its MAC address ([`link_local`]). Connected routes come from
//! the IPv4 and global IPv6 prefixes of enabled interfaces. Limits: one IPv4 address per
//! interface. Daemons send values found at run time as sources ([`source`]); confd
//! makes tables from them with the configuration, and after it starts, waits for them
//! before the FE, ribd and neighd drop what they hold from before.
//!
//! A PPPoE interface is in the FE (and neighd) only while its source has a session,
//! with the session's ID, AC and MTU (at most the configured one) and the IPv4
//! address the source has; routes out of it are offered to ribd only then, and NAT
//! with it as the outside (and no `external`) is left out while it has no address.
//! An interface with `ipv4-from` is always there, with the IPv4 address its source
//! (a DHCP client) has while it has one; as NAT's outside (with no `external`), NAT
//! and the IPv4 routes out of it wait for that address (its IPv6 routes do not).

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Client, Event};
use ruster_proto::table::{network, Change, Key, NextHop, RouteAction, Value};
use ruster_proto::task::{Progress, Task};

pub mod apply;
pub mod bridge;
pub mod bgp;
pub mod delegated;
pub mod dhcp6;
pub mod dhcp_client;
pub mod diff;
pub mod file;
pub mod kernel;
pub mod part;
pub mod pppoe;
pub mod ra;
pub mod source;
pub mod versions;

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
    /// For a PPPoE session: its parent interface and the source that sends the
    /// session and its IPv4 address. The interface is in the FE only while the
    /// source has a session, with the IPv4 address it has (if any) instead of `ipv4`.
    pub pppoe: Option<(String, String)>,
    /// The source (of kind `dhcp-client`) whose IPv4 address the interface has
    /// while the source has one, instead of `ipv4`.
    pub ipv4_from: Option<String>,
    /// The source (of kind `dhcpv6-client`) and subnet ID of the /64 of a
    /// delegated prefix the interface also has while the source has one
    /// ([`delegated`]).
    pub ipv6_from: Option<(String, u32)>,
}

impl InterfaceConfig {
    /// The source the interface's IPv4 address comes from: a PPPoE session's, or
    /// `ipv4_from`.
    pub fn ipv4_source(&self) -> Option<&str> {
        self.pppoe
            .as_ref()
            .map(|(_, source)| source.as_str())
            .or(self.ipv4_from.as_deref())
    }

    /// Whether the interface's IPv4 address comes from a source.
    pub fn address_from_source(&self) -> bool {
        self.ipv4_source().is_some()
    }
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub interfaces: Vec<InterfaceConfig>,
    pub static_routes: Vec<StaticRoute>,
    /// The default VRF's forward firewall rules, in order.
    pub firewall: Vec<ruster_proto::table::FirewallRule>,
    /// How the default VRF's forward firewall filters where no rule decides.
    pub firewall_filtering: ruster_proto::table::NatFiltering,
    /// The firewall's outside interfaces as the file names them; when `None`, NAT's
    /// outside and the interfaces of the default VRF's static default routes.
    pub firewall_outside: Option<Vec<String>>,
    /// The ICMP error rate limits (IPv4 interval, IPv6 burst and interval), when set.
    pub icmp_errors: Option<(u32, u32, u32)>,
    /// The default VRF's NAPT.
    pub nat: Option<ruster_proto::table::Nat>,
    /// The DNS server for the LAN, checked; confd hands it to `ruster-unbound`.
    pub dns: Option<ruster_config::Dns>,
    /// The DHCP servers, one per interface, checked; confd hands them to `ruster-kea`.
    pub dhcp: Vec<ruster_config::Dhcp>,
    /// The DHCPv6 servers, one per interface, checked; confd hands them to
    /// `ruster-kea` with `dhcp`.
    pub dhcp6: Vec<ruster_config::Dhcp6>,
    /// The Router Advertisements, one per interface, checked; confd hands them to
    /// neighd.
    pub ra: Vec<ruster_config::Ra>,
    /// The daemons that send values found at run time ([`source`]).
    pub sources: Vec<source::Spec>,
    /// The PPPoE clients, checked; confd hands them to `ruster-pppoed` ([`pppoe`]).
    pub pppoe: Vec<ruster_config::Pppoe>,
    /// The WAN side's DHCP clients, checked; confd hands them to `ruster-dhcpc`
    /// ([`dhcp_client`]).
    pub dhcp_client: Vec<ruster_config::DhcpClient>,
    /// A MAP-E CE whose end-user prefix a source (of kind `dhcpv6-client`)
    /// has delegated: its settings, checked, and the source. Its tunnel, NAT and
    /// routes are there only while the source has a prefix ([`delegated`]).
    pub map_e_from: Option<(ruster_config::MapE, String)>,
    /// The DNS servers the sources of `dns`'s `upstream-from` have now, in order
    /// and once each: a value found at run time ([`delegated`]), which confd hands
    /// `ruster-unbound` beside the `dns` part.
    pub dns_found: Vec<IpAddr>,
    /// BGP, checked; confd hands it to `ruster-frr` ([`bgp`]).
    pub bgp: Option<ruster_config::Bgp>,
    /// The bridges, checked; their own interfaces are in `interfaces` ([`bridge`]).
    pub bridges: Vec<bridge::Bridge>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfdCounters {
    pub patches_sent: u64,
    pub patches_refused: u64,
}

/// A process confd writes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKind {
    Fe,
    Ribd,
    Neighd,
    /// The process that takes a module's part ([`part`]); it connects to confd.
    Part(part::Module),
}

impl std::fmt::Display for PeerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fe => f.write_str("the FE"),
            Self::Ribd => f.write_str("ribd"),
            Self::Neighd => f.write_str("neighd"),
            Self::Part(module) => write!(f, "the process for {module}"),
        }
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
    /// confd started and waits for its sources: resync-end and `sync-done` are held
    /// back, so the peer keeps what it holds from before ([`source`]).
    held: bool,
    /// The resync-end waiting for an answer. When it is refused, what the peer holds
    /// stays marked stale, and resync-end goes again after the next accepted change.
    resync_end: Option<u32>,
    /// The peer refused resync-end; when that was first seen. It is sent again
    /// after the next accepted change, or [`RESYNC_END_RETRY_MS`] after this.
    resync_end_refused: Option<Option<u64>>,
    /// The peer refused a patch; when that was first seen. Everything is sent again
    /// with the next change, or [`RESYNC_END_RETRY_MS`] after this (what the peer
    /// refused for may have gone).
    patch_refused: Option<Option<u64>>,
}

/// The control process (`<run>/kea/punt.sock`) that DHCP frames are handed to.
pub const DHCP_CONTROL: &str = "kea";
/// The punt class of one interface's DHCP: `dhcp-<interface>`.
pub const DHCP_CLASS_PREFIX: &str = "dhcp-";
/// The DHCP server port.
pub const DHCP_SERVER_PORT: u16 = 67;
/// The punt class of one interface's DHCPv6: `dhcp6-<interface>`.
pub const DHCP6_CLASS_PREFIX: &str = "dhcp6-";
/// The DHCPv6 server and relay agent port (RFC 8415 section 7.2).
pub const DHCP6_SERVER_PORT: u16 = 547;

/// A refused resync-end is sent again at least this often.
pub const RESYNC_END_RETRY_MS: u64 = 10_000;

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
            if !accepted {
                self.resync_end_refused = Some(None);
            }
            return;
        }
        let Some(at) = self.in_flight.iter().position(|(t, _, _)| *t == token) else {
            return;
        };
        let (_, _, held) = self.in_flight.remove(at);
        if accepted {
            self.sent = held;
            self.patch_refused = None;
            if self.in_flight.is_empty() && !self.held {
                if self.resync_open {
                    self.resync_end = Some(self.client.resync_end());
                    self.resync_end_refused = None;
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
            // Nothing is accepted since this resync-begin: resync-end waits for the
            // next accepted full send, not for the clock.
            self.resync_end_refused = None;
            self.patch_refused.get_or_insert(None);
        }
    }

    /// confd stopped waiting for its sources: what was held back goes now, or after
    /// the patches in flight are answered.
    fn release(&mut self) {
        self.held = false;
        // After a refusal, resync-end waits for the next accepted full send
        // ([`Peer::answer`]).
        if !self.in_flight.is_empty() || self.patch_refused.is_some() {
            return;
        }
        if self.resync_open && self.resync_end.is_none() {
            self.resync_end = Some(self.client.resync_end());
            self.resync_end_refused = None;
            self.resync_open = false;
        }
        if self.says_done {
            self.client.sync_done();
        }
    }
}

pub struct Confd {
    /// The configuration as given.
    config: Config,
    /// The configuration in use: `config` with the delegated prefixes now
    /// ([`delegated`]). The tables and parts are made from it.
    current: Config,
    fe: Option<Peer>,
    ribd: Option<Peer>,
    neighd: Option<Peer>,
    parts: part::Parts,
    sources: source::Sources,
    /// Counts the changes of the sources' values.
    values_changed: u64,
    counters: ConfdCounters,
    /// Counts [`Confd::set_config`] calls; each patch carries the one it came from.
    generation: u64,
    /// The last refused patch: its process, reason and generation.
    last_refusal: Option<(PeerKind, String, u64)>,
}

impl std::fmt::Debug for Confd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Confd")
            .field("config", &self.current)
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl Confd {
    pub fn new(config: Config) -> Self {
        Self {
            sources: source::Sources::new(&config.sources),
            values_changed: 0,
            current: config.clone(),
            config,
            fe: None,
            ribd: None,
            neighd: None,
            parts: part::Parts::default(),
            counters: ConfdCounters::default(),
            generation: 0,
            last_refusal: None,
        }
    }

    /// Connects to the FE as the writer of interfaces, addresses, firewall rules and NAT.
    pub fn connect_fe(&mut self, stream: UnixStream) -> io::Result<()> {
        self.fe = Some(self.full_send(stream, Self::fe_tables, false)?);
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

    /// Takes a connection on `module`'s socket, `confd/part/<module>/part.sock`
    /// ([`part`]).
    pub fn attach_part(&mut self, module: part::Module, stream: UnixStream) -> io::Result<()> {
        self.parts.attach(module, stream)
    }

    /// Asks each process that takes a part to check its part of `candidate`, with
    /// the values the sources have now, without taking it ([`part`]). The answers
    /// come in [`Confd::part_checks`] as the steps go.
    pub fn check_parts(&mut self, candidate: &Config) {
        let with = delegated::with_delegated(candidate, &self.sources);
        self.parts.check(&with);
    }

    /// The answers to the last [`Confd::check_parts`] so far, by module: the modules
    /// a process takes now, and those the candidate has that none takes.
    pub fn part_checks(&self) -> &BTreeMap<part::Module, part::Checked> {
        self.parts.checked()
    }

    /// Takes a connection on `confd/source/<name>/source.sock` ([`source`]).
    pub fn attach_source(&mut self, name: &str, stream: UnixStream) -> io::Result<()> {
        self.sources.attach(name, stream)
    }

    /// The names of the sources of the configuration, each with its socket.
    pub fn source_names(&self) -> Vec<String> {
        self.sources.names()
    }

    /// True while confd waits for its sources after it started.
    pub fn waiting_for_sources(&self) -> bool {
        self.sources.waiting()
    }

    /// The PPPoE session the source `name` has sent and that has not run out: its
    /// ID, the access concentrator's MAC and the MTU.
    pub fn source_pppoe(&self, name: &str) -> Option<(u16, [u8; 6], u16)> {
        self.sources.pppoe(name)
    }

    /// The IPv4 address and prefix length the source `name` has sent and that has
    /// not run out.
    pub fn source_ipv4(&self, name: &str) -> Option<(Ipv4Addr, u8)> {
        self.sources.ipv4(name)
    }

    /// The delegated prefix the source `name` has sent and that has not run out:
    /// the prefix, its length, and its preferred and valid lifetimes.
    pub fn source_prefix(&self, name: &str) -> Option<(Ipv6Addr, u8, u32, u32)> {
        self.sources.prefix(name)
    }

    /// The IPv6 address and prefix length the source `name` has sent and that has
    /// not run out.
    pub fn source_ipv6(&self, name: &str) -> Option<(Ipv6Addr, u8)> {
        self.sources.ipv6(name)
    }

    /// The DNS servers the source `name` has sent and that have not run out.
    pub fn source_dns(&self, name: &str) -> &[IpAddr] {
        self.sources.dns(name)
    }

    /// The peers whose connection closed. Connecting again sends everything again;
    /// a [`PeerKind::Part`] process connects again by itself.
    pub fn closed(&self) -> Vec<PeerKind> {
        [
            (PeerKind::Fe, &self.fe),
            (PeerKind::Ribd, &self.ribd),
            (PeerKind::Neighd, &self.neighd),
        ]
        .into_iter()
        .filter(|(_, peer)| peer.as_ref().is_some_and(|peer| peer.client.is_closed()))
        .map(|(kind, _)| kind)
        .chain(self.parts.closed().into_iter().map(PeerKind::Part))
        .collect()
    }

    /// The configuration as given (without the values found at run time).
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn counters(&self) -> ConfdCounters {
        self.counters
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
            && self.parts.settled()
    }

    /// The processes that are not connected now: of those that take a module's
    /// part, the ones whose module is in the configuration.
    pub fn absent(&self) -> Vec<PeerKind> {
        [
            (PeerKind::Fe, &self.fe),
            (PeerKind::Ribd, &self.ribd),
            (PeerKind::Neighd, &self.neighd),
        ]
        .into_iter()
        .filter(|(_, peer)| peer.as_ref().is_none_or(|peer| peer.client.is_closed()))
        .map(|(kind, _)| kind)
        .chain(
            part::Module::ALL
                .into_iter()
                .filter(|m| m.configured(&self.current) && !self.parts.connected(*m))
                .map(PeerKind::Part),
        )
        .collect()
    }

    /// Replaces the configuration; only the differences are sent.
    pub fn set_config(&mut self, config: Config) {
        self.generation += 1;
        self.sources.set_specs(&config.sources);
        self.current = delegated::with_delegated(&config, &self.sources);
        self.config = config;
        self.send_tables();
        self.parts.send(&self.current, self.generation);
    }

    /// Sends the FE, neighd and ribd what changed in their tables.
    fn send_tables(&mut self) {
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
            held: self.sources.waiting(),
            resync_end: None,
            resync_end_refused: None,
            patch_refused: None,
        };
        if peer.held {
            if !desired.is_empty() {
                send_diff(&mut peer, &desired, self.generation, &mut self.counters);
            }
        } else if desired.is_empty() {
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
        if let Some(outside) = &self.current.firewall_outside {
            let mut outside = outside.clone();
            outside.sort();
            outside.dedup();
            return outside;
        }
        let mut outside: Vec<String> = self
            .current
            .nat
            .iter()
            .map(|nat| nat.outside.clone())
            .chain(
                self.current
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

    /// What confd writes now, and what `config` would make it write with the values
    /// the sources have now, without sending anything (`ruster diff`): the FE's
    /// tables, and the routes it offers ribd.
    pub fn tables_now_and_with(&mut self, config: &Config) -> [[BTreeMap<Key, Value>; 2]; 2] {
        let now = [self.fe_tables(), self.routes()];
        let with = delegated::with_delegated(config, &self.sources);
        let saved = std::mem::replace(&mut self.current, with);
        let then = [self.fe_tables(), self.routes()];
        self.current = saved;
        let [fe_now, routes_now] = now;
        let [fe_then, routes_then] = then;
        [[fe_now, fe_then], [routes_now, routes_then]]
    }

    /// The interface tables, the firewall rules (numbered from 1 in order) and NAT.
    fn fe_tables(&self) -> BTreeMap<Key, Value> {
        let mut out = self.interface_tables();
        bridge::tables(&self.current.bridges, &mut out);
        if let Some((ipv4_interval_ms, ipv6_burst, ipv6_interval_ms)) = self.current.icmp_errors {
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
        if !self.current.firewall.is_empty() {
            out.insert(
                Key::FirewallPolicy {
                    vrf: ruster_proto::table::DEFAULT_VRF.to_owned(),
                },
                Value::FirewallPolicy {
                    filtering: self.current.firewall_filtering,
                    outside: self.firewall_outside(),
                },
            );
        }
        // The DHCP clients' rules go first, so that no rule drops the replies.
        let client_rules = if self.current.firewall.is_empty() {
            Vec::new()
        } else {
            dhcp_client::firewall_rules(&self.current.dhcp_client)
        };
        for (id, rule) in (1..).zip(client_rules.iter().chain(&self.current.firewall)) {
            out.insert(
                Key::FirewallRule {
                    vrf: ruster_proto::table::DEFAULT_VRF.to_owned(),
                    id,
                },
                Value::FirewallRule(rule.clone()),
            );
        }
        // NAT takes its public address from the outside: a PPPoE session's comes
        // with the session, and NAT waits for it.
        let outside_ready = |nat: &&ruster_proto::table::Nat| {
            nat.external.is_some()
                || self
                    .current
                    .interfaces
                    .iter()
                    .find(|i| i.name == nat.outside)
                    .is_none_or(|i| !i.address_from_source() || self.ipv4(i).is_some())
        };
        if let Some(nat) = self.current.nat.as_ref().filter(outside_ready) {
            out.insert(
                Key::Nat {
                    vrf: ruster_proto::table::DEFAULT_VRF.to_owned(),
                },
                Value::Nat(nat.clone()),
            );
        }
        // Each DHCP interface's requests to the server port go to ruster-kea: the
        // broadcasts before forwarding, and those to the router's address (renewals)
        // after the input firewall.
        // Each DHCPv6 interface's messages to ff02::1:2, port 547, likewise.
        let v4 = self.current.dhcp.iter().map(|d| {
            let class = (DHCP_CLASS_PREFIX, DHCP_SERVER_PORT);
            (class, &d.interface, d.punt_rate, d.punt_burst)
        });
        let v6 = self.current.dhcp6.iter().map(|d| {
            let class = (DHCP6_CLASS_PREFIX, DHCP6_SERVER_PORT);
            (class, &d.interface, d.punt_rate, d.punt_burst)
        });
        for ((prefix, port), interface, rate, burst) in v4.chain(v6) {
            out.insert(
                Key::Punt {
                    class: format!("{prefix}{interface}"),
                },
                Value::Punt(ruster_proto::table::PuntClass {
                    matches: ruster_proto::table::PuntMatch::Ip {
                        protocol: 17,
                        ports: Some((port, port)),
                    },
                    interface: Some(interface.clone()),
                    destination: ruster_proto::table::PuntDestination::Control(
                        DHCP_CONTROL.to_owned(),
                    ),
                    rate,
                    burst,
                }),
            );
        }
        pppoe::punt_classes(&self.current.pppoe, &mut out);
        dhcp_client::punt_classes(&self.current.dhcp_client, &mut out);
        out
    }

    /// A PPPoE interface's session now, from its source: the session ID, the AC's
    /// MAC and the MTU. `None` for an interface that is not a session.
    fn session(&self, interface: &InterfaceConfig) -> Option<(u16, [u8; 6], u16)> {
        let (_, source) = interface.pppoe.as_ref()?;
        self.sources.pppoe(source)
    }

    /// An interface's IPv4 address now: a PPPoE session's from its source while it
    /// is up.
    fn ipv4(&self, interface: &InterfaceConfig) -> Option<(Ipv4Addr, u8)> {
        self.ipv4_in(&self.current, interface)
    }

    /// An interface's IPv4 address now, among the interfaces of `config`. A
    /// session's address is left out when its prefix overlaps the prefix of another
    /// interface's address in the VRF (one given, or another session's), or when it
    /// is its prefix's network or broadcast address: the same checks as for an
    /// address in the configuration ([`file`](mod@file)).
    fn ipv4_in(&self, config: &Config, interface: &InterfaceConfig) -> Option<(Ipv4Addr, u8)> {
        let Some(source) = interface.ipv4_source() else {
            return interface.ipv4;
        };
        if interface.pppoe.is_some() {
            self.session(interface)?;
        }
        let (address, len) = self.sources.ipv4(source)?;
        let host_mask = u32::MAX.checked_shr(u32::from(len)).unwrap_or(0);
        let host = u32::from(address) & host_mask;
        if len <= 30 && (host == 0 || host == host_mask) {
            return None;
        }
        let overlaps = |(other, other_len): (Ipv4Addr, u8)| {
            let len = len.min(other_len);
            network(IpAddr::V4(address), len) == network(IpAddr::V4(other), len)
        };
        let taken = config
            .interfaces
            .iter()
            .filter(|i| i.name != interface.name && i.vrf == interface.vrf)
            .filter_map(|i| match i.ipv4_source() {
                None => i.ipv4,
                Some(other) => self.sources.ipv4(other),
            })
            .any(overlaps);
        (!taken).then_some((address, len))
    }

    /// The configuration with the IPv4 address now of each interface that takes it
    /// from a source, for the kernel side ([`kernel`]).
    pub fn with_values(&self) -> Config {
        self.with_values_of(&self.config)
    }

    /// `config` with the values the sources have now: the IPv4 address of each
    /// interface that takes it from a source, and the delegated prefixes.
    pub fn with_values_of(&self, config: &Config) -> Config {
        let config = &delegated::with_delegated(config, &self.sources);
        let mut out = config.clone();
        for interface in &mut out.interfaces {
            if interface.address_from_source() {
                interface.ipv4 = self.ipv4_in(config, interface);
            }
        }
        out
    }

    /// An interface's MTU now: a session's is at most what the session takes, and a
    /// tunnel's at most what the interface of its local address takes less 40.
    fn mtu(&self, interface: &InterfaceConfig) -> u16 {
        if let Some((_, _, mtu)) = self.session(interface) {
            return mtu.min(interface.mtu);
        }
        let Some((local, _)) = interface.tunnel else {
            return interface.mtu;
        };
        self.current
            .interfaces
            .iter()
            .find(|i| i.pppoe.is_some() && i.ipv6.iter().any(|&(a, _)| a == local))
            .and_then(|owner| self.session(owner).map(|_| self.mtu(owner)))
            .map_or(interface.mtu, |owner| {
                interface.mtu.min(owner.saturating_sub(40))
            })
    }

    /// Counts the changes of the values from the sources.
    pub fn values_changed(&self) -> u64 {
        self.values_changed
    }

    fn interface_tables(&self) -> BTreeMap<Key, Value> {
        let mut out = BTreeMap::new();
        for interface in &self.current.interfaces {
            // A PPPoE session is there only while it is up.
            let session = self.session(interface);
            if interface.pppoe.is_some() && session.is_none() {
                continue;
            }
            out.insert(
                Key::Interface {
                    name: interface.name.clone(),
                },
                Value::Interface {
                    enabled: interface.enabled,
                    mac: interface.mac,
                    mtu: self.mtu(interface),
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
                    pppoe: interface.pppoe.as_ref().zip(session).map(
                        |((parent, _), (session, peer, _))| ruster_proto::table::Pppoe {
                            parent: parent.clone(),
                            session,
                            peer,
                        },
                    ),
                },
            );
            // A bridge member has no address, not even a link-local one.
            if bridge::is_member(&self.current.bridges, &interface.name) {
                continue;
            }
            let link_local = (IpAddr::V6(link_local(interface.mac)), 64);
            let addresses = self
                .ipv4(interface)
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
        let find = |name: &str| self.current.interfaces.iter().find(|i| i.name == name);
        let Some(interface) = find(name) else {
            return false;
        };
        let parent = interface
            .vlan
            .as_ref()
            .map(|(parent, _)| parent)
            .or(interface.pppoe.as_ref().map(|(parent, _)| parent));
        // NAT's outside session needs its address before anything leaves through it,
        // or the LAN's would leave untranslated.
        let nat_outside = self
            .current
            .nat
            .as_ref()
            .is_some_and(|nat| nat.outside == interface.name && nat.external.is_none());
        let up = match &interface.pppoe {
            None => true,
            Some(_) if nat_outside => self.ipv4(interface).is_some(),
            Some(_) => self.session(interface).is_some(),
        };
        interface.enabled && up && parent.is_none_or(|parent| self.usable(parent))
    }

    /// Whether `name` is NAT's outside (with no `external`), takes its IPv4 address
    /// from a DHCP client, and has none now.
    fn waits_for_address(&self, name: &str) -> bool {
        let Some(interface) = self.current.interfaces.iter().find(|i| i.name == name) else {
            return false;
        };
        interface.ipv4_from.is_some()
            && self
                .current
                .nat
                .as_ref()
                .is_some_and(|nat| nat.outside == name && nat.external.is_none())
            && self.ipv4(interface).is_none()
    }

    /// Connected routes of usable interfaces (enabled, on an enabled parent), then
    /// static routes. A static route for a connected prefix is left out: the connected
    /// route wins, as on most routers.
    fn routes(&self) -> BTreeMap<Key, Value> {
        let mut out = BTreeMap::new();
        for interface in self
            .current
            .interfaces
            .iter()
            .filter(|i| self.usable(&i.name))
        {
            // Link-local prefixes are on every link and never forwarded.
            let prefixes = self
                .ipv4(interface)
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
        for route in &self.current.static_routes {
            // A static route out of a disabled interface cannot be used: it is not
            // offered, so that another source's route for the prefix is chosen.
            if let RouteTarget::Next { interface, .. } = &route.target {
                if !self.usable(interface) {
                    continue;
                }
                // NAT's outside waits for its leased address before IPv4 leaves
                // through it, or the LAN's would leave untranslated. IPv6 and the
                // VLANs on it do not wait.
                if route.prefix.is_ipv4() && self.waits_for_address(interface) {
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
    fn step(&mut self, now_ms: u64) -> Progress {
        let waiting = self.sources.waiting();
        let (mut progress, changed) = self.sources.step(now_ms);
        if changed {
            self.values_changed += 1;
            self.current = delegated::with_delegated(&self.config, &self.sources);
            self.send_tables();
            // Generation 0: a refusal of a part the values changed is not the
            // refusal of a configuration `ruster apply` waits on.
            self.parts.send(&self.current, 0);
        }
        if waiting && !self.sources.waiting() {
            for peer in [&mut self.fe, &mut self.ribd, &mut self.neighd]
                .into_iter()
                .flatten()
            {
                peer.release();
            }
        }
        // A refused patch is sent again, in full, after a while, though nothing
        // changed.
        let mut resend = Vec::new();
        for (kind, peer) in [
            (PeerKind::Fe, &mut self.fe),
            (PeerKind::Ribd, &mut self.ribd),
            (PeerKind::Neighd, &mut self.neighd),
        ] {
            let Some(peer) = peer else { continue };
            let Some(seen) = peer.patch_refused.as_mut() else {
                continue;
            };
            let at = *seen.get_or_insert(now_ms);
            let retry_at = at.saturating_add(RESYNC_END_RETRY_MS);
            if now_ms < retry_at {
                progress = progress.and(Progress {
                    busy: false,
                    wake_at: Some(retry_at),
                });
            } else if peer.in_flight.is_empty() {
                peer.patch_refused = None;
                resend.push(kind);
            }
        }
        // A refused resync-end goes again after a while, though nothing changed.
        for peer in [&mut self.fe, &mut self.ribd, &mut self.neighd]
            .into_iter()
            .flatten()
        {
            let Some(seen) = peer.resync_end_refused.as_mut() else {
                continue;
            };
            let at = *seen.get_or_insert(now_ms);
            let retry_at = at.saturating_add(RESYNC_END_RETRY_MS);
            if now_ms < retry_at {
                progress = progress.and(Progress {
                    busy: false,
                    wake_at: Some(retry_at),
                });
            } else if peer.in_flight.is_empty() && peer.resync_end.is_none() && !peer.held {
                peer.resync_end = Some(peer.client.resync_end());
                peer.resync_open = false;
                peer.resync_end_refused = None;
                progress.busy = true;
            }
        }
        // Peers that refused a patch older than the configuration now held: a refusal
        // drops every patch in flight, the newer ones too, so they get it all again.
        for (kind, peer) in [
            (PeerKind::Fe, &mut self.fe),
            (PeerKind::Ribd, &mut self.ribd),
            (PeerKind::Neighd, &mut self.neighd),
        ] {
            let Some(peer) = peer else { continue };
            let (polled, events) = peer.client.poll();
            progress = progress.and(polled);
            for event in events {
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
        let (polled, refusals) = self.parts.step(&self.current, self.generation);
        progress = progress.and(polled);
        for (module, reason, generation) in refusals {
            self.counters.patches_refused += 1;
            let newer = self
                .last_refusal
                .as_ref()
                .is_some_and(|(_, _, g)| *g > generation);
            if !newer {
                self.last_refusal = Some((PeerKind::Part(module), reason, generation));
            }
        }
        for kind in resend {
            let (desired, peer) = match kind {
                PeerKind::Fe => (self.fe_tables(), &mut self.fe),
                PeerKind::Ribd => (self.routes(), &mut self.ribd),
                PeerKind::Neighd => (self.interface_tables(), &mut self.neighd),
                // A part is put whole each time; nothing to send again.
                PeerKind::Part(_) => continue,
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
            ipv4_from: None,
            ipv6_from: None,
        };
        let route = |len| StaticRoute {
            vrf: "default".into(),
            prefix: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            len,
            target: RouteTarget::Discard,
        };
        let confd = Confd::new(Config {
            interfaces: vec![lan],
            static_routes: vec![route(24), route(25)],
            firewall: Vec::new(),
            firewall_filtering: Default::default(),
            firewall_outside: None,
            icmp_errors: None,
            nat: None,
            dns: None,
            dhcp: Vec::new(),
            dhcp6: Vec::new(),
            ra: Vec::new(),
            sources: Vec::new(),
            pppoe: Vec::new(),
            dhcp_client: Vec::new(),
            map_e_from: None,
            dns_found: Vec::new(),
            bgp: None,
            bridges: Vec::new(),
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

    #[test]
    fn routes_out_of_a_vlan_on_a_disabled_parent_are_not_offered() {
        let interface = |name: &str, enabled, ipv4, vlan| InterfaceConfig {
            name: name.into(),
            mac: [2, 0, 0, 0, 0, 1],
            mtu: 1500,
            enabled,
            ipv4,
            ipv6: Vec::new(),
            vrf: "default".into(),
            vlan,
            tunnel: None,
            pppoe: None,
            ipv4_from: None,
            ipv6_from: None,
        };
        let config = |trunk_enabled| Config {
            interfaces: vec![
                interface("trunk", trunk_enabled, None, None),
                interface(
                    "trunk.10",
                    true,
                    Some((Ipv4Addr::new(10, 0, 10, 1), 24)),
                    Some(("trunk".into(), 10)),
                ),
            ],
            static_routes: vec![StaticRoute {
                vrf: "default".into(),
                prefix: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                len: 24,
                target: RouteTarget::Next {
                    interface: "trunk.10".into(),
                    via: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 10, 2))),
                },
            }],
            firewall: Vec::new(),
            firewall_filtering: Default::default(),
            firewall_outside: None,
            icmp_errors: None,
            nat: None,
            dns: None,
            dhcp: Vec::new(),
            dhcp6: Vec::new(),
            ra: Vec::new(),
            sources: Vec::new(),
            pppoe: Vec::new(),
            dhcp_client: Vec::new(),
            map_e_from: None,
            dns_found: Vec::new(),
            bgp: None,
            bridges: Vec::new(),
        };
        let connected = route_key("default", IpAddr::V4(Ipv4Addr::new(10, 0, 10, 0)), 24);
        let static_route = route_key("default", IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24);

        let mut confd = Confd::new(config(false));
        assert!(confd.routes().is_empty(), "{:?}", confd.routes());
        confd.set_config(config(true));
        let routes = confd.routes();
        assert!(routes.contains_key(&connected));
        assert!(routes.contains_key(&static_route));
    }

    #[test]
    fn a_named_firewall_outside_is_what_the_fe_is_told() {
        let mut config = Config::default();
        config.firewall.push(ruster_proto::table::FirewallRule {
            ingress: None,
            egress: None,
            source: (Ipv4Addr::UNSPECIFIED.into(), 0),
            destination: (Ipv4Addr::UNSPECIFIED.into(), 0),
            protocol: ruster_proto::table::Protocol::Udp,
            source_ports: (0, 65_535),
            destination_ports: (0, 65_535),
            action: ruster_proto::table::FirewallAction::Accept,
        });
        config.firewall_outside = Some(vec!["wan".into(), "pppoe".into()]);
        let tables = Confd::new(config).fe_tables();
        let policy = tables.iter().find_map(|(key, value)| match (key, value) {
            (Key::FirewallPolicy { .. }, Value::FirewallPolicy { outside, .. }) => Some(outside),
            _ => None,
        });
        assert_eq!(policy, Some(&vec!["pppoe".to_owned(), "wan".to_owned()]));
    }
}

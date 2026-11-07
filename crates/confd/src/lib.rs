#![forbid(unsafe_code)]
//! The configuration process (`docs/design/ce-processes.md`, "ruster-confd").
//!
//! confd holds the router's configuration and turns it into what each process needs:
//!
//! | To | What |
//! |---|---|
//! | FE | interfaces and addresses |
//! | neighd | interfaces and addresses (to answer ARP and choose source addresses) |
//! | ribd | static routes and the connected routes of the addresses, as source `confd` |
//!
//! On every (re)connection confd sends everything between resync-begin and resync-end,
//! so entries it no longer has are removed, and tells ribd `sync-done`. After that it
//! sends only what changed.
//!
//! The configuration file is TOML ([`file`](mod@file)). Skeleton limits: IPv4 only, one address
//! per interface, no dynamic values from other daemons yet.

use std::collections::BTreeMap;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Client, Event};
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};
use ruster_proto::task::{Progress, Task};

pub mod file;

/// The VRF of everything in the skeleton.
pub const VRF: &str = "default";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: String,
    pub mac: [u8; 6],
    pub mtu: u16,
    pub enabled: bool,
    /// The interface's IPv4 address and prefix length.
    pub ipv4: Option<(Ipv4Addr, u8)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRoute {
    pub prefix: Ipv4Addr,
    pub len: u8,
    pub interface: String,
    /// `None` for an on-link route.
    pub via: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub interfaces: Vec<InterfaceConfig>,
    pub static_routes: Vec<StaticRoute>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfdCounters {
    pub patches_sent: u64,
    pub patches_refused: u64,
}

/// One process confd writes to, and what it was sent.
struct Peer {
    client: Client,
    sent: BTreeMap<Key, Value>,
    /// ribd wants `sync-done` after each full send.
    says_done: bool,
}

pub struct Confd {
    config: Config,
    fe: Option<Peer>,
    ribd: Option<Peer>,
    neighd: Option<Peer>,
    counters: ConfdCounters,
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
        }
    }

    /// Connects to the FE as the writer of interfaces and addresses.
    pub fn connect_fe(&mut self, stream: UnixStream) -> io::Result<()> {
        self.fe = Some(self.full_send(stream, Self::interface_tables, false)?);
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

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn counters(&self) -> ConfdCounters {
        self.counters
    }

    /// Replaces the configuration; only the differences are sent.
    pub fn set_config(&mut self, config: Config) {
        self.config = config;
        let fe = self.interface_tables();
        let routes = self.routes();
        let counters = &mut self.counters;
        for (peer, desired) in [
            (&mut self.fe, &fe),
            (&mut self.neighd, &fe),
            (&mut self.ribd, &routes),
        ] {
            if let Some(peer) = peer {
                send_diff(peer, desired, counters);
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
        let changes: Vec<Change> = desired
            .iter()
            .map(|(key, value)| Change::set(key.clone(), value.clone()))
            .collect();
        if !changes.is_empty() {
            client
                .patch(&changes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            self.counters.patches_sent += 1;
        }
        client.resync_end();
        if says_done {
            client.sync_done();
        }
        Ok(Peer {
            client,
            sent: desired,
            says_done,
        })
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
                },
            );
            if let Some((address, prefix_len)) = interface.ipv4 {
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

    /// Connected routes of enabled interfaces, then static routes (a static route for
    /// the same prefix replaces the connected one).
    fn routes(&self) -> BTreeMap<Key, Value> {
        let mut out = BTreeMap::new();
        for interface in self.config.interfaces.iter().filter(|i| i.enabled) {
            if let Some((address, len)) = interface.ipv4 {
                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                out.insert(
                    route_key(Ipv4Addr::from(u32::from(address) & mask), len),
                    Value::Route(RouteAction::Forward(vec![NextHop {
                        interface: interface.name.clone(),
                        address: None,
                    }])),
                );
            }
        }
        for route in &self.config.static_routes {
            out.insert(
                route_key(route.prefix, route.len),
                Value::Route(RouteAction::Forward(vec![NextHop {
                    interface: route.interface.clone(),
                    address: route.via,
                }])),
            );
        }
        out
    }
}

fn route_key(prefix: Ipv4Addr, len: u8) -> Key {
    Key::Route {
        vrf: VRF.into(),
        prefix,
        len,
    }
}

fn send_diff(peer: &mut Peer, desired: &BTreeMap<Key, Value>, counters: &mut ConfdCounters) {
    let mut changes = Vec::new();
    for (key, value) in desired {
        if peer.sent.get(key) != Some(value) {
            changes.push(Change::set(key.clone(), value.clone()));
        }
    }
    for key in peer.sent.keys() {
        if !desired.contains_key(key) {
            changes.push(Change::delete(key.clone()));
        }
    }
    if changes.is_empty() {
        return;
    }
    if peer.client.patch(&changes).is_ok() {
        counters.patches_sent += 1;
        peer.sent = desired.clone();
        if peer.says_done {
            peer.client.sync_done();
        }
    }
}

impl Task for Confd {
    fn step(&mut self, _now_ms: u64) -> Progress {
        let mut progress = Progress::IDLE;
        for peer in [&mut self.fe, &mut self.ribd, &mut self.neighd]
            .into_iter()
            .flatten()
        {
            let (polled, events) = peer.client.poll();
            progress = progress.and(polled);
            for event in events {
                if let Event::Response { code, .. } = event {
                    if code.class() != 2 {
                        self.counters.patches_refused += 1;
                    }
                }
            }
        }
        progress
    }
}

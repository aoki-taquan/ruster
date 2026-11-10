//! The routes zebra gives over FPM, as ribd's routes of source `frr`.
//!
//! zebra runs in the router's kernel namespace, where the FE's interfaces are one
//! TUN device per VRF with the router's addresses, and a TAP device
//! `rp-<interface>` for each interface that runs IS-IS or OSPF
//! (`docs/design/overlay.md` section 6). A next hop through a TAP device is on that
//! FE interface: it goes to ribd as the interface and the gateway, a link-local one
//! too ([`Routes::set_taps`] says which index is which TAP). A next hop through the
//! TUN device is a gateway address only. When every such gateway of a route is on
//! an interface's prefix (from confd's `frr` part, [`ruster_config::Connected`]),
//! the next hops go to ribd as the interface of the longest such prefix and the
//! gateway. Otherwise (a BGP neighbor more than one hop away, whose next hop zebra
//! resolved through the kernel's default route) the route goes to ribd with its
//! gateways only, and ribd resolves them through its own routes
//! (`ruster_ribd::resolve`). A link-local gateway not through a TAP, which says
//! nothing of its link, or none at all (a connected route, which confd gives ribd
//! itself) is left out, and a route with no next hop left is not given to ribd.
//!
//! Only the main table (the default VRF) is read. A blackhole route is a discard
//! route, an unreachable or prohibit route a reject route; other route types are
//! not given.
//!
//! zebra gives an IPv6 route learned from a neighbor on the link with the
//! neighbor's link-local address as the next hop, unless told to prefer the global
//! one; `ruster-frr` tells bgpd so in the configuration it writes.
//!
//! zebra sends every route again when it connects; nothing marks the end. When FPM
//! connects again the routes held are marked stale ([`Routes::mark_stale`]); each
//! route sent again is no longer stale, and the owner removes the rest
//! ([`Routes::sweep`]) once zebra has been quiet for a while.
//!
//! # Standards
//!
//! - RFC 8349 (`ietf-routing`): a route has next hops with an outgoing interface and
//!   an address, or is a blackhole (discard) or unreachable (reject) route.
//!
//! Deviations: only the default VRF; a prohibit
//! route rejects with the same Destination Unreachable as an unreachable one.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ruster_config::Connected;
use ruster_proto::table::{network, Change, Key, NextHop, RouteAction, Value, DEFAULT_VRF};

use crate::fpm::{Kind, Route};

fn is_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(a) if a.is_unicast_link_local())
}

/// The TAP devices in this namespace (`rp-<interface>`): each one's index, with
/// the FE interface it stands for.
pub fn tap_indexes() -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    let Ok(devices) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for device in devices.flatten() {
        let name = device.file_name().to_string_lossy().into_owned();
        let Some(interface) = name.strip_prefix(ruster_config::TAP_PREFIX) else {
            continue;
        };
        let index = std::fs::read_to_string(device.path().join("ifindex"))
            .ok()
            .and_then(|t| t.trim().parse().ok());
        if let Some(index) = index {
            out.insert(index, interface.to_owned());
        }
    }
    out
}

/// The kernel's main table: the default VRF's.
pub const MAIN_TABLE: u32 = 254;
/// The most routes held; zebra's further prefixes are refused.
pub const ROUTES_MAX: usize = 1_000_000;

/// What zebra holds for one prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Held {
    /// The gateways of its next hops, with the kernel's interface index.
    Forward(Vec<(IpAddr, Option<u32>)>),
    Discard,
    Reject,
}

/// zebra's routes, and the interfaces that map their next hops.
#[derive(Debug, Default)]
pub struct Routes {
    /// Network, prefix length, interface.
    connected: Vec<(IpAddr, u8, String)>,
    held: BTreeMap<(IpAddr, u8), Held>,
    /// The TAP devices' indexes, with the FE interface each stands for.
    taps: BTreeMap<u32, String>,
    stale: BTreeSet<(IpAddr, u8)>,
    /// Routes not taken: another table or type, or past [`ROUTES_MAX`].
    pub passed_over: u64,
    /// Next hops left out: no gateway, or a link-local one.
    pub hops_left_out: u64,
}

fn key(prefix: IpAddr, len: u8) -> Key {
    Key::Route {
        vrf: DEFAULT_VRF.to_owned(),
        prefix,
        len,
    }
}

impl Routes {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many prefixes are held.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Takes the TAP devices' indexes and the FE interfaces they stand for; the
    /// changes for ribd of every route whose next hops map differently now.
    pub fn set_taps(&mut self, taps: BTreeMap<u32, String>) -> Vec<Change> {
        if taps == self.taps {
            return Vec::new();
        }
        let keys: Vec<(IpAddr, u8)> = self.held.keys().copied().collect();
        let before: Vec<Change> = keys.iter().map(|&k| self.change(k)).collect();
        self.taps = taps;
        keys.into_iter()
            .zip(before)
            .map(|(k, before)| (self.change(k), before))
            .filter(|(now, before)| now != before)
            .map(|(now, _)| now)
            .collect()
    }

    /// Takes the interfaces' prefixes; the changes for ribd of every route whose
    /// next hops map differently now.
    pub fn set_connected(&mut self, connected: &[Connected]) -> Vec<Change> {
        let connected: Vec<(IpAddr, u8, String)> = connected
            .iter()
            .filter_map(|c| {
                let (address, len) = c.prefix.split_once('/')?;
                let address: IpAddr = address.parse().ok()?;
                let len: u8 = len.parse().ok()?;
                let max = if address.is_ipv4() { 32 } else { 128 };
                (len <= max).then(|| (network(address, len), len, c.interface.clone()))
            })
            .collect();
        let keys: Vec<(IpAddr, u8)> = self.held.keys().copied().collect();
        let before: Vec<Change> = keys.iter().map(|&k| self.change(k)).collect();
        self.connected = connected;
        // Longest first, so the first that holds a gateway is the longest match.
        self.connected.sort_by_key(|c| std::cmp::Reverse(c.1));
        keys.into_iter()
            .zip(before)
            .map(|(k, before)| (self.change(k), before))
            .filter(|(now, before)| now != before)
            .map(|(now, _)| now)
            .collect()
    }

    /// The interface whose prefix holds `gateway`.
    fn interface(&self, gateway: IpAddr) -> Option<&str> {
        self.connected
            .iter()
            .find(|(n, len, _)| n.is_ipv4() == gateway.is_ipv4() && network(gateway, *len) == *n)
            .map(|(_, _, name)| name.as_str())
    }

    /// The change for ribd that makes it hold what is held for `at`.
    fn change(&self, at: (IpAddr, u8)) -> Change {
        let action = match self.held.get(&at) {
            None => None,
            Some(Held::Discard) => Some(RouteAction::Discard),
            Some(Held::Reject) => Some(RouteAction::Reject),
            Some(Held::Forward(gateways)) => {
                // Through a TAP device, the FE interface it stands for; else by
                // the prefix the gateway is on. A link-local one only through a TAP.
                let interface = |gateway: IpAddr, oif: Option<u32>| {
                    oif.and_then(|i| self.taps.get(&i))
                        .map(String::as_str)
                        .or_else(|| self.interface(gateway).filter(|_| !is_link_local(gateway)))
                };
                let usable: Vec<(IpAddr, Option<u32>)> = gateways
                    .iter()
                    .copied()
                    .filter(|&(g, oif)| !is_link_local(g) || interface(g, oif).is_some())
                    .collect();
                let hops: Option<Vec<NextHop>> = usable
                    .iter()
                    .map(|&(gateway, oif)| {
                        Some(NextHop {
                            interface: interface(gateway, oif)?.to_owned(),
                            address: Some(gateway),
                        })
                    })
                    .collect();
                match hops {
                    _ if usable.is_empty() => None,
                    Some(hops) => Some(RouteAction::Forward(hops)),
                    None => {
                        let mut only: Vec<IpAddr> = Vec::new();
                        // ribd resolves these through its own routes; a link-local
                        // gateway says nothing of its link there.
                        for &(g, _) in &usable {
                            if !is_link_local(g) && !only.contains(&g) {
                                only.push(g);
                            }
                        }
                        (!only.is_empty()).then_some(RouteAction::Gateways(only))
                    }
                }
            }
        };
        match action {
            Some(action) => Change::set(key(at.0, at.1), Value::Route(action)),
            None => Change::delete(key(at.0, at.1)),
        }
    }

    /// Takes the route messages of one frame; the changes for ribd, one per prefix
    /// at most: zebra sends an update as a delete and the new route in one frame,
    /// and ribd gets only the new route, so it never goes without it in between.
    pub fn take_frame(&mut self, routes: &[Route]) -> Vec<Change> {
        let mut out: Vec<Change> = Vec::new();
        for route in routes {
            if let Some(change) = self.take(route) {
                match out.iter_mut().find(|c| c.key == change.key) {
                    Some(earlier) => *earlier = change,
                    None => out.push(change),
                }
            }
        }
        out
    }

    /// Takes one route message; the change for ribd, if it is one ribd may care
    /// about.
    pub fn take(&mut self, route: &Route) -> Option<Change> {
        if route.table != MAIN_TABLE {
            self.passed_over += 1;
            return None;
        }
        let at = (route.prefix, route.len);
        let given_before = self.held.contains_key(&at) && self.change(at).value.is_some();
        self.stale.remove(&at);
        let held = match (route.new, route.kind) {
            (false, _) => None,
            (true, Kind::Blackhole) => Some(Held::Discard),
            (true, Kind::Unreachable) => Some(Held::Reject),
            (true, Kind::Unicast) => {
                let mut gateways: Vec<(IpAddr, Option<u32>)> = Vec::new();
                for hop in &route.hops {
                    match hop.gateway {
                        Some(g) if gateways.contains(&(g, hop.oif)) => {}
                        // Kept: a TAP device may be known later.
                        Some(g)
                            if is_link_local(g)
                                && !hop.oif.is_some_and(|i| self.taps.contains_key(&i)) =>
                        {
                            self.hops_left_out += 1;
                            gateways.push((g, hop.oif));
                        }
                        Some(g) => gateways.push((g, hop.oif)),
                        None => self.hops_left_out += 1,
                    }
                }
                (!gateways.is_empty()).then_some(Held::Forward(gateways))
            }
            (true, Kind::Other(_)) => {
                self.passed_over += 1;
                None
            }
        };
        match held {
            Some(held) => {
                if !self.held.contains_key(&at) && self.held.len() >= ROUTES_MAX {
                    self.passed_over += 1;
                    return None;
                }
                self.held.insert(at, held);
            }
            None => {
                self.held.remove(&at)?;
            }
        }
        // Nothing to take back from ribd for a route it was never given.
        let change = self.change(at);
        (given_before || change.value.is_some()).then_some(change)
    }

    /// Marks every route held as stale: zebra connected again and sends them anew.
    pub fn mark_stale(&mut self) {
        self.stale = self.held.keys().copied().collect();
    }

    /// Removes the routes zebra did not send again; their deletes for ribd.
    pub fn sweep(&mut self) -> Vec<Change> {
        let stale = std::mem::take(&mut self.stale);
        stale
            .into_iter()
            .filter(|at| self.held.remove(at).is_some())
            .map(|(prefix, len)| Change::delete(key(prefix, len)))
            .collect()
    }

    /// Removes every route; their deletes for ribd.
    pub fn clear(&mut self) -> Vec<Change> {
        self.stale.clear();
        std::mem::take(&mut self.held)
            .into_keys()
            .map(|(prefix, len)| Change::delete(key(prefix, len)))
            .collect()
    }
}

//! The routes zebra gives over FPM, as ribd's routes of source `frr`.
//!
//! zebra runs in the router's kernel namespace, where every interface of the FE is
//! one TUN device per VRF with the router's addresses. So a next hop from zebra is a
//! gateway address and the TUN's index, and the FE's interface is not in it. When
//! every gateway of a route is on an interface's prefix (from confd's `frr` part,
//! [`ruster_config::Connected`]), the next hops go to ribd as the interface of the
//! longest such prefix and the gateway. Otherwise (a BGP neighbor more than one hop
//! away, whose next hop zebra resolved through the kernel's default route) the
//! route goes to ribd with its gateways only, and ribd resolves them through its
//! own routes (`ruster_ribd::resolve`). A link-local gateway, which says nothing of
//! its link, or none at all (a connected route, which confd gives ribd itself) is
//! left out, and a route with no next hop left is not given to ribd.
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

/// The kernel's main table: the default VRF's.
pub const MAIN_TABLE: u32 = 254;
/// The most routes held; zebra's further prefixes are refused.
pub const ROUTES_MAX: usize = 1_000_000;

/// What zebra holds for one prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Held {
    /// The gateways of its next hops.
    Forward(Vec<IpAddr>),
    Discard,
    Reject,
}

/// zebra's routes, and the interfaces that map their next hops.
#[derive(Debug, Default)]
pub struct Routes {
    /// Network, prefix length, interface.
    connected: Vec<(IpAddr, u8, String)>,
    held: BTreeMap<(IpAddr, u8), Held>,
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
                let hops: Option<Vec<NextHop>> = gateways
                    .iter()
                    .map(|&gateway| {
                        Some(NextHop {
                            interface: self.interface(gateway)?.to_owned(),
                            address: Some(gateway),
                        })
                    })
                    .collect();
                Some(match hops {
                    Some(hops) => RouteAction::Forward(hops),
                    None => RouteAction::Gateways(gateways.clone()),
                })
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
        self.stale.remove(&at);
        let held = match (route.new, route.kind) {
            (false, _) => None,
            (true, Kind::Blackhole) => Some(Held::Discard),
            (true, Kind::Unreachable) => Some(Held::Reject),
            (true, Kind::Unicast) => {
                let mut gateways: Vec<IpAddr> = Vec::new();
                for hop in &route.hops {
                    match hop.gateway {
                        Some(g) if gateways.contains(&g) => {}
                        Some(IpAddr::V6(g)) if g.is_unicast_link_local() => {
                            self.hops_left_out += 1;
                        }
                        Some(g) => gateways.push(g),
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
        Some(self.change(at))
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

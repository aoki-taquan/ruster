//! Turning the FE's tables into core's tables, one set per VRF.
//!
//! Every VRF gets the enabled interfaces and every neighbor (they belong to
//! interfaces, not VRFs), and its own routes and router addresses. A route whose next
//! hop leaves through an interface of another VRF is kept as it is: core sends it out
//! of that interface. A `lookup-vrf` route is expanded here into the routes of the
//! other VRF it covers (see [`expand_lookups`]).
//!
//! Entries that point at something missing (a port the FE does not have, a disabled
//! interface, an unknown VRF) are kept in the tables but left out here.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ruster_core::{
    FirewallAction, FirewallInterface, FirewallIpv4Prefix, FirewallPortRange, FirewallProtocol,
    FirewallRule, FirewallRuleId, IfId, Interface, Ipv4Address, Ipv4InIpv6Tunnel, Ipv4OriginPolicy,
    Ipv4Routes, Ipv6Fib, Ipv6Local, Ipv6Neighbor, Ipv6Route, Ipv6RouteTree, LocalIpv4Binding,
    MacAddress, Neighbor, PortSet, PppoeSession, Route, ValidatedForwardingOwner, VlanBinding,
};
use ruster_proto::session::Store;
use ruster_proto::sid;
use ruster_proto::table::{self, network, Key, RouteAction, Value, DEFAULT_VRF};

/// Core's tables of one VRF.
pub(crate) struct Vrf {
    pub(crate) owner: ValidatedForwardingOwner,
    pub(crate) ipv6: Ipv6Fib,
}

/// Core's tables for every VRF.
pub(crate) struct Built {
    /// The default VRF first.
    pub(crate) vrfs: Vec<Vrf>,
    /// The VRF names, in the order of `vrfs`.
    pub(crate) names: Vec<String>,
    /// For each port, the index in `vrfs` of its interface's VRF.
    pub(crate) by_ingress: Vec<u16>,
    /// The enabled ports and sub-interfaces.
    pub(crate) active: Vec<IfId>,
    /// The name of every interface by id: the ports, then the others, each keeping
    /// its id across table changes; an empty name is an id no interface has.
    pub(crate) interface_names: Vec<String>,
    /// The VLAN sub-interfaces of enabled ports.
    pub(crate) vlans: Vec<VlanBinding>,
    /// The enabled IPv4 in IPv6 tunnels.
    pub(crate) tunnels: Vec<Ipv4InIpv6Tunnel>,
    /// The enabled bridge members that carry frames inside IP (EtherIP).
    pub(crate) overlays: Vec<ruster_core::Overlay>,
    /// IPv4 next hops the neighbor process could not resolve (written with an
    /// all-zero MAC address).
    pub(crate) unreachable: Vec<(IfId, Ipv4Address)>,
    /// The PPPoE sessions on enabled interfaces.
    pub(crate) pppoe: Vec<PppoeSession>,
    /// Each VRF's kernel interface, in the order of `vrfs`: the router's own
    /// packets come in through it ([`crate::kernel`]).
    pub(crate) kernel: Vec<IfId>,
    /// The default VRF's forward firewall rules, in rule id order, without those
    /// naming an interface that is missing or disabled.
    pub(crate) firewall: Vec<FirewallRule>,
    /// Whether the tables have any firewall rule. Then the firewall is on even if
    /// none of them is in `firewall`, and drops everything.
    pub(crate) firewall_on: bool,
    /// The ICMP error rate limits (IPv4 interval, IPv6 burst and interval), when
    /// set.
    pub(crate) icmp_errors: Option<(u32, u32, u32)>,
    /// How the forward firewall filters where no rule decides, and between which
    /// interfaces (inside, outside).
    pub(crate) firewall_filtering: ruster_core::FirewallFiltering,
    pub(crate) firewall_interfaces: (
        ruster_core::FirewallInterfaceSet,
        ruster_core::FirewallInterfaceSet,
    ),
    /// The default VRF's NAPT, when the tables have one and both its interfaces
    /// are enabled.
    pub(crate) nat: Option<Nat>,
    /// The classes of the punt table.
    pub(crate) punt: crate::punt_table::Classes,
    /// The bridges by name, in name order, and the static entries of their MAC
    /// address tables (bridge index, address, member).
    pub(crate) bridges: Vec<(String, ruster_core::BridgeConfig)>,
    pub(crate) bridge_statics: Vec<(u16, [u8; 6], IfId)>,
    /// The router's SRv6 SIDs and SR policies.
    pub(crate) srv6: ruster_core::Srv6Table,
}

/// NAPT from `inside` to `outside`, with `public` and `ports`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nat {
    pub(crate) inside: IfId,
    pub(crate) outside: IfId,
    pub(crate) public: Ipv4Address,
    pub(crate) ports: PortSet,
    pub(crate) filtering: ruster_core::Nat44Filtering,
    /// Whether the IPv4 IDs of translated datagrams are rate limited.
    pub(crate) ipv4_id_rate_limit: bool,
    /// The per-host limits (0 for none): public ports, and state.
    pub(crate) ports_per_host: u16,
    pub(crate) state_per_host: u16,
}

/// One forwarding route before it becomes core's.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Forward {
    prefix: IpAddr,
    len: u8,
    egress: IfId,
    next_hop: Option<IpAddr>,
}

/// A route of one VRF: forward, or look up again in another VRF.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Forward(Forward),
    Lookup {
        prefix: IpAddr,
        len: u8,
        vrf: String,
    },
}

impl Entry {
    #[cfg(test)]
    fn prefix(&self) -> (IpAddr, u8) {
        match self {
            Self::Forward(f) => (f.prefix, f.len),
            Self::Lookup { prefix, len, .. } => (*prefix, *len),
        }
    }
}

/// The entries an iPATCH touched, each with the value it held before
/// ([`ruster_proto::session::Hook::check_patch`]).
pub(crate) type Changed<'a> = &'a [(&'a Key, Option<&'a Value>)];

/// Each VRF's entries by prefix: in the order of the route keys of the tables.
type Entries = BTreeMap<String, BTreeMap<(IpAddr, u8), Entry>>;

/// What the routes of the tables came to in a build, kept for the next one: a change
/// of routes alone is then made to this, and the routes are not all read again (with
/// many routes that is most of a build's time).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Routes {
    /// How many routes each VRF that has any holds.
    counts: BTreeMap<String, usize>,
    /// The entries of every VRF of the tables (also of one without routes).
    entries: Entries,
    /// Whether a route is an SRv6 SID or policy. Those make SIDs and interfaces of
    /// the FE's own too, so with one every build reads the routes again.
    srv6: bool,
    /// How many of the entries look up in another VRF. With one, a VRF's routes
    /// for core come from another VRF's too, and are all made again.
    lookups: usize,
    /// Core's routes of each VRF, as the build gave them to core. The next build
    /// makes its change to these and shares the rest with this one.
    tables: BTreeMap<String, Tables>,
}

/// Core's routes of one VRF.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Tables {
    v4: Ipv4Routes,
    v6: Ipv6RouteTree<Ipv6Route>,
}

impl Tables {
    fn set(&mut self, route: &Forward, vrf: &str) -> Result<(), String> {
        let failed = |error| format!("route {}/{} in {vrf}: {error}", route.prefix, route.len);
        match route.prefix {
            IpAddr::V4(prefix) => {
                let route = Route::new(
                    Ipv4Address::from_octets(prefix.octets()),
                    route.len,
                    route.egress,
                    route.next_hop.and_then(v4),
                )
                .map_err(|e| failed(format!("{e:?}")))?;
                self.v4.set(route);
            }
            IpAddr::V6(prefix) => {
                let len = route.len;
                let route = Ipv6Route::new(
                    prefix.octets(),
                    len,
                    route.egress,
                    route.next_hop.and_then(v6),
                )
                .map_err(|e| failed(format!("{e:?}")))?;
                self.v6.insert(&prefix.octets(), len, route);
            }
        }
        Ok(())
    }

    fn remove(&mut self, prefix: IpAddr, len: u8) {
        match prefix {
            // A length no route has: there is none to take out.
            IpAddr::V4(_) if len > 32 => {}
            IpAddr::V6(_) if len > 128 => {}
            IpAddr::V4(prefix) => {
                self.v4
                    .remove(Ipv4Address::from_octets(prefix.octets()), len);
            }
            IpAddr::V6(prefix) => {
                self.v6.remove(&prefix.octets(), len);
            }
        }
    }
}

impl Routes {
    /// Whether these, made for the tables before a change, can be brought to
    /// `store` by making the change to them: `changed` (each entry touched and what
    /// it held before) has no entry that makes or changes an interface, none of
    /// its routes is an SRv6 one, and every VRF the routes are in has routes
    /// before and after (so the VRFs, and with them the interfaces' ids, stay the
    /// same).
    ///
    /// What a route comes to depends on the interfaces alone ([`forwarding`]):
    /// the interface table and the tunnel and bridge tables, which make
    /// interfaces too. The other tables (addresses, neighbors, NAT, firewall,
    /// what goes to the control processes, the bridges' members and static
    /// addresses) change no route, and are read from the tables in every build.
    ///
    /// When they do, the route each changed entry holds now (`None` for one that
    /// is gone or is not a route), in the order of `changed`, so that the build
    /// does not look each up again.
    fn follows<'s>(
        &self,
        changed: Changed<'_>,
        store: &'s Store,
    ) -> Option<Vec<Option<&'s RouteAction>>> {
        if self.srv6 {
            return None;
        }
        let mut growth: BTreeMap<&str, isize> = BTreeMap::new();
        let mut afters = Vec::with_capacity(changed.len());
        for (key, before) in changed {
            let vrf = match key {
                Key::Route { vrf, .. } => vrf,
                Key::Address { .. }
                | Key::Neighbor { .. }
                | Key::Nat { .. }
                | Key::FirewallPolicy { .. }
                | Key::IcmpErrors { .. }
                | Key::FirewallRule { .. }
                | Key::Punt { .. }
                | Key::SourcePppoe { .. }
                | Key::SourceIpv4 { .. }
                | Key::SourcePrefix { .. }
                | Key::SourceIpv6 { .. }
                | Key::SourceDns { .. }
                | Key::BridgePort { .. }
                | Key::BridgeMac { .. } => {
                    afters.push(None);
                    continue;
                }
                // Each of these makes or changes an interface. (No wildcard: a
                // kind added later must be put on one side or the other.)
                Key::Interface { .. }
                | Key::EtherIp { .. }
                | Key::Vxlan { .. }
                | Key::Bridge { .. } => return None,
            };
            let after = match store.get(key) {
                None => None,
                Some(Value::Route(
                    action @ (RouteAction::Forward(_)
                    | RouteAction::LookupVrf(_)
                    | RouteAction::Discard
                    | RouteAction::Reject
                    | RouteAction::Local),
                )) => Some(action),
                Some(_) => return None,
            };
            *growth.entry(vrf.as_str()).or_default() +=
                isize::from(after.is_some()) - isize::from(before.is_some());
            afters.push(after);
        }
        let kept = growth.iter().all(|(vrf, by)| {
            self.counts
                .get(*vrf)
                .is_some_and(|&had| had.checked_add_signed(*by).is_some_and(|has| has > 0))
        });
        kept.then_some(afters)
    }
}

/// The entry of a route that only says where packets go, or `None` when it makes
/// none: no next hop on an enabled interface, or a route to the router itself.
/// (`None` too for the kinds that are more than that; the callers take those first.)
fn forwarding(
    prefix: IpAddr,
    len: u8,
    action: &RouteAction,
    active: &BTreeMap<&str, (IfId, &str)>,
) -> Option<Entry> {
    match action {
        RouteAction::Forward(hops) => {
            let (egress, hop) = hops
                .iter()
                .find_map(|hop| active.get(hop.interface.as_str()).map(|&(id, _)| (id, hop)))?;
            Some(Entry::Forward(Forward {
                prefix,
                len,
                egress,
                next_hop: hop.address,
            }))
        }
        RouteAction::LookupVrf(other) => Some(Entry::Lookup {
            prefix,
            len,
            vrf: other.clone(),
        }),
        RouteAction::Discard | RouteAction::Reject => Some(Entry::Forward(Forward {
            prefix,
            len,
            egress: if *action == RouteAction::Discard {
                IfId::DISCARD
            } else {
                IfId::REJECT
            },
            next_hop: None,
        })),
        _ => None,
    }
}

/// Whether `inner` is within `outer` (same family, at least as long, same bits).
fn within((inner, inner_len): (IpAddr, u8), (outer, outer_len): (IpAddr, u8)) -> bool {
    inner.is_ipv4() == outer.is_ipv4()
        && inner_len >= outer_len
        && network(inner, outer_len) == outer
}

/// Replaces each `lookup-vrf` route of a VRF with forward routes that give the same
/// longest-prefix result, from the other VRF's forward routes (one level: a lookup
/// in the other VRF is not followed):
///
/// - a route of the other VRF inside the lookup prefix, unless this VRF has a route
///   longer than the lookup prefix that holds it (that route wins for it anyway);
/// - the longest route of the other VRF that holds the whole lookup prefix, as the
///   lookup prefix itself.
///
/// Deviation: where the other VRF has no route, a lookup should drop the packet; here
/// the packet falls to this VRF's shorter routes (not yet made a discard route).
fn expand_lookups(vrfs: &Entries) -> BTreeMap<String, Vec<Forward>> {
    let forwards = |entries: &BTreeMap<(IpAddr, u8), Entry>| -> Vec<Forward> {
        entries
            .values()
            .filter_map(|e| match e {
                Entry::Forward(f) => Some(f.clone()),
                Entry::Lookup { .. } => None,
            })
            .collect()
    };
    let no_entries = BTreeMap::new();
    let mut out = BTreeMap::new();
    for (name, entries) in vrfs {
        let mut own = forwards(entries);
        // The prefixes in `own`, to leave out an expanded route that one of them
        // (or an earlier expanded one) already has.
        let mut taken: BTreeSet<(IpAddr, u8)> = own.iter().map(|r| (r.prefix, r.len)).collect();
        for entry in entries.values() {
            let Entry::Lookup { prefix, len, vrf } = entry else {
                continue;
            };
            let lookup = (*prefix, *len);
            let other = vrfs.get(vrf).unwrap_or(&no_entries);
            let mut added = Vec::new();
            // The other VRF's routes inside the lookup prefix: those whose address
            // lies in it (the map is in address order).
            let last = last_address(lookup);
            for (&at, other_entry) in other.range((lookup.0, 0)..=(last, u8::MAX)) {
                let Entry::Forward(route) = other_entry else {
                    continue;
                };
                if !within(at, lookup) {
                    continue;
                }
                // Shadowed by a route of this VRF longer than the lookup prefix
                // that holds it: one per length in between, looked up.
                let shadowed = (lookup.1 + 1..=at.1)
                    .any(|len| entries.contains_key(&(network(at.0, len), len)));
                if !shadowed {
                    added.push(route.clone());
                }
            }
            // The longest route of the other VRF that holds the whole lookup
            // prefix (shorter than it), as the lookup prefix itself.
            let covering = (0..lookup.1).rev().find_map(|len| {
                match other.get(&(network(lookup.0, len), len)) {
                    Some(Entry::Forward(route)) => Some(route),
                    _ => None,
                }
            });
            if let Some(covering) = covering {
                added.push(Forward {
                    prefix: lookup.0,
                    len: lookup.1,
                    ..covering.clone()
                });
            }
            // This VRF's own routes win over expanded ones for the same prefix.
            for route in added {
                if taken.insert((route.prefix, route.len)) {
                    own.push(route);
                }
            }
        }
        out.insert(name.clone(), own);
    }
    out
}

/// The last address of a prefix (all host bits set).
fn last_address((address, len): (IpAddr, u8)) -> IpAddr {
    match address {
        IpAddr::V4(a) => {
            let host = u32::MAX.checked_shr(u32::from(len)).unwrap_or(0);
            IpAddr::V4((u32::from(a) | host).into())
        }
        IpAddr::V6(a) => {
            let host = u128::MAX.checked_shr(u32::from(len)).unwrap_or(0);
            IpAddr::V6((u128::from(a) | host).into())
        }
    }
}

fn v4(address: IpAddr) -> Option<Ipv4Address> {
    match address {
        IpAddr::V4(a) => Some(Ipv4Address::from_octets(a.octets())),
        IpAddr::V6(_) => None,
    }
}

fn v6(address: IpAddr) -> Option<[u8; 16]> {
    match address {
        IpAddr::V6(a) => Some(a.octets()),
        IpAddr::V4(_) => None,
    }
}

/// The name of the default VRF's kernel interface, for the firewall's rules.
pub(crate) const KERNEL_INTERFACE: &str = "rt-default";

/// The MTU of a kernel interface: that of the TUN devices confd makes.
const KERNEL_MTU: u16 = 1500;

/// The ids of the interfaces: the ports first, then the others, each where it was
/// in `previous` when that is free, else in the first free place.
struct Ids<'p> {
    /// The name of each id; an empty name is a free id.
    names: Vec<String>,
    previous: &'p [String],
    ports: usize,
}

impl Ids<'_> {
    fn take(&mut self, name: &str) -> Result<IfId, String> {
        let free = |names: &[String], at: usize| names.get(at).is_none_or(String::is_empty);
        let kept = self
            .previous
            .iter()
            .position(|n| n == name)
            .filter(|&at| at >= self.ports && free(&self.names, at));
        // Not one another interface had before, so that it can still take it.
        let at = kept.unwrap_or_else(|| {
            (self.ports..)
                .find(|&at| {
                    free(&self.names, at) && self.previous.get(at).is_none_or(String::is_empty)
                })
                .expect("an unbounded range")
        });
        let id = u16::try_from(at)
            .map(IfId)
            .map_err(|_| "too many interfaces".to_owned())?;
        if self.names.len() <= at {
            self.names.resize(at + 1, String::new());
        }
        self.names[at] = name.to_owned();
        Ok(id)
    }
}

/// Core's tables for `store`. `previous` names the interface of each id in the
/// tables in use, so that the interfaces that stay keep their ids.
///
/// `kept` is what the routes came to in the build for the tables before, when
/// `store` is those tables with an iPATCH made that touched `changed`: a change the
/// kept routes can follow ([`Routes::follows`]) is made to them. Otherwise, and
/// with `None`, the routes are all read. Either way the result is the same; the
/// routes it came to are returned for the next build.
pub(crate) fn build(
    ports: &[String],
    store: &Store,
    previous: &[String],
    kept: Option<(Routes, Changed<'_>)>,
) -> Result<(Built, Routes), String> {
    let kept = kept.and_then(|(routes, changed)| {
        let afters = routes.follows(changed, store)?;
        Some((routes, changed, afters))
    });
    // Core's routes of the build before, when no entry looked up in another VRF.
    let mut kept_tables = None;
    let mut lookups = 0;
    let (kept_names, mut counts, kept_entries, changed, afters): (Vec<String>, _, _, _, _) =
        match kept {
            Some((routes, changed, afters)) => {
                lookups = routes.lookups;
                kept_tables = (routes.lookups == 0).then_some(routes.tables);
                (
                    routes.counts.keys().cloned().collect(),
                    routes.counts,
                    Some(routes.entries),
                    changed,
                    afters,
                )
            }
            None => (Vec::new(), BTreeMap::new(), None, &[][..], Vec::new()),
        };
    let port = |name: &str| {
        let index = ports.iter().position(|p| p == name)?;
        u16::try_from(index).ok().map(IfId)
    };
    // Enabled interfaces and their VRFs.
    let mut interfaces = Vec::new();
    let mut active: BTreeMap<&str, (IfId, &str)> = BTreeMap::new();
    for (key, value) in store.table(sid::INTERFACE) {
        if let (
            Key::Interface { name },
            Value::Interface {
                enabled: true,
                mac,
                mtu,
                vrf,
                vlan: None,
                tunnel: None,
                pppoe: None,
            },
        ) = (key, value)
        {
            if let Some(id) = port(name) {
                interfaces.push(Interface {
                    id,
                    mac: MacAddress(*mac),
                    mtu: *mtu,
                });
                active.insert(name.as_str(), (id, vrf.as_str()));
            }
        }
    }
    // Interfaces that are not ports get ids after the ports, and keep the id they
    // had in the tables before: flows carried across a table change name their
    // interfaces by id.
    let mut ids = Ids {
        names: ports.to_vec(),
        previous,
        ports: ports.len(),
    };
    let mut vlans = Vec::new();
    for (key, value) in store.table(sid::INTERFACE) {
        if let (
            Key::Interface { name },
            Value::Interface {
                enabled: true,
                mac,
                mtu,
                vrf,
                vlan: Some(vlan),
                ..
            },
        ) = (key, value)
        {
            if ports.iter().any(|port| port == name) {
                return Err(format!("VLAN sub-interface {name} has the name of a port"));
            }
            let parent = active.get(vlan.parent.as_str()).map(|&(id, _)| id);
            let Some(parent) = parent.filter(|id| usize::from(id.0) < ports.len()) else {
                continue;
            };
            if vlans
                .iter()
                .any(|b: &VlanBinding| b.parent == parent && b.vid == vlan.id)
            {
                return Err(format!(
                    "VLAN {} on {} is given twice",
                    vlan.id, vlan.parent
                ));
            }
            let id = ids.take(name)?;
            interfaces.push(Interface {
                id,
                mac: MacAddress(*mac),
                mtu: *mtu,
            });
            vlans.push(VlanBinding {
                parent,
                vid: vlan.id,
                sub: id,
            });
            active.insert(name.as_str(), (id, vrf.as_str()));
        }
    }
    // Tunnel interfaces get the ids after those.
    let mut tunnels = Vec::new();
    for (key, value) in store.table(sid::INTERFACE) {
        if let (
            Key::Interface { name },
            Value::Interface {
                enabled: true,
                mac,
                mtu,
                vrf,
                tunnel: Some(tunnel),
                ..
            },
        ) = (key, value)
        {
            if ports.iter().any(|port| port == name) {
                return Err(format!("tunnel {name} has the name of a port"));
            }
            let id = ids.take(name)?;
            interfaces.push(Interface {
                id,
                mac: MacAddress(*mac),
                mtu: *mtu,
            });
            tunnels.push(Ipv4InIpv6Tunnel {
                interface: id,
                local: tunnel.local.octets(),
                remote: tunnel.remote.octets(),
            });
            active.insert(name.as_str(), (id, vrf.as_str()));
        }
    }
    // PPPoE sessions get the ids after those; their parent is an enabled port or
    // VLAN sub-interface.
    let mut pppoe = Vec::new();
    for (key, value) in store.table(sid::INTERFACE) {
        if let (
            Key::Interface { name },
            Value::Interface {
                enabled: true,
                mac,
                mtu,
                vrf,
                pppoe: Some(session),
                ..
            },
        ) = (key, value)
        {
            if ports.iter().any(|port| port == name) {
                return Err(format!("PPPoE interface {name} has the name of a port"));
            }
            // Only a port or VLAN sub-interface carries a session.
            let Some(&(parent, _)) = active.get(session.parent.as_str()).filter(|(id, _)| {
                usize::from(id.0) < ports.len() || vlans.iter().any(|b| b.sub == *id)
            }) else {
                continue;
            };
            if pppoe
                .iter()
                .any(|s: &PppoeSession| s.parent == parent && s.session == session.session)
            {
                return Err(format!(
                    "PPPoE session {} on {} is given twice",
                    session.session, session.parent
                ));
            }
            let parent_mtu = interfaces
                .iter()
                .find(|i| i.id == parent)
                .map_or(0, |i| i.mtu);
            if *mtu > parent_mtu.saturating_sub(8) {
                return Err(format!(
                    "PPPoE interface {name}: mtu must be at most {} ({}'s less 8)",
                    parent_mtu.saturating_sub(8),
                    session.parent
                ));
            }
            let id = ids.take(name)?;
            interfaces.push(Interface {
                id,
                mac: MacAddress(*mac),
                mtu: *mtu,
            });
            pppoe.push(PppoeSession {
                interface: id,
                parent,
                session: session.session,
                peer: MacAddress(session.peer),
            });
            active.insert(name.as_str(), (id, vrf.as_str()));
        }
    }
    // EtherIP and VXLAN interfaces get the ids after those: an interface row of the
    // name, with no VLAN, tunnel or PPPoE session, and the EtherIP or VXLAN row.
    let mut overlays = Vec::new();
    for (key, value) in store.table(sid::ETHERIP).chain(store.table(sid::VXLAN)) {
        let (name, local, kind) = match (key, value) {
            (Key::EtherIp { interface }, Value::EtherIp { local, remote }) => (
                interface,
                *local,
                ruster_core::OverlayKind::EtherIp { remote: *remote },
            ),
            (
                Key::Vxlan { interface },
                Value::Vxlan {
                    vni,
                    local,
                    remotes,
                },
            ) => (
                interface,
                *local,
                ruster_core::OverlayKind::Vxlan {
                    vni: *vni,
                    remotes: remotes.clone(),
                },
            ),
            _ => continue,
        };
        {
            let Some(Value::Interface {
                enabled: true,
                mac,
                mtu,
                vrf,
                vlan: None,
                tunnel: None,
                pppoe: None,
            }) = store.get(&Key::Interface { name: name.clone() })
            else {
                continue;
            };
            if ports.iter().any(|port| port == name) {
                return Err(format!("overlay interface {name} has the name of a port"));
            }
            if active.contains_key(name.as_str()) {
                return Err(format!("{name} is both an EtherIP and a VXLAN interface"));
            }
            let id = ids.take(name)?;
            interfaces.push(Interface {
                id,
                mac: MacAddress(*mac),
                mtu: *mtu,
            });
            overlays.push(ruster_core::Overlay {
                interface: id,
                local,
                kind,
            });
            active.insert(name.as_str(), (id, vrf.as_str()));
        }
    }
    // Each bridge's own interface (IRB) is the interface of its name; its members
    // are enabled ports, VLAN sub-interfaces and overlays.
    let mut bridges: Vec<(String, ruster_core::BridgeConfig)> = Vec::new();
    for (key, value) in store.table(sid::BRIDGE) {
        if let (
            Key::Bridge { name },
            Value::Bridge {
                aging_s,
                max_learned,
            },
        ) = (key, value)
        {
            if store
                .get(&Key::EtherIp {
                    interface: name.clone(),
                })
                .is_some()
                || store
                    .get(&Key::Vxlan {
                        interface: name.clone(),
                    })
                    .is_some()
            {
                return Err(format!(
                    "bridge {name} has the name of an EtherIP or VXLAN interface"
                ));
            }
            let limits = ruster_core::BridgeLimits {
                aging_ms: u64::from(*aging_s) * 1_000,
                max_macs: *max_learned,
            };
            let irb = match store.get(&Key::Interface { name: name.clone() }) {
                Some(Value::Interface {
                    enabled: true,
                    mac,
                    mtu,
                    vrf,
                    vlan: None,
                    tunnel: None,
                    pppoe: None,
                }) => {
                    if ports.iter().any(|port| port == name) {
                        return Err(format!("bridge {name} has the name of a port"));
                    }
                    let id = ids.take(name)?;
                    interfaces.push(Interface {
                        id,
                        mac: MacAddress(*mac),
                        mtu: *mtu,
                    });
                    active.insert(name.as_str(), (id, vrf.as_str()));
                    Some((id, *mac))
                }
                _ => None,
            };
            bridges.push((
                name.clone(),
                ruster_core::BridgeConfig {
                    limits,
                    irb,
                    members: Vec::new(),
                },
            ));
        }
    }
    let bridge_names: Vec<String> = bridges.iter().map(|(name, _)| name.clone()).collect();
    let bridge_at = |name: &str| bridge_names.iter().position(|n| n == name);
    let mut bridge_statics = Vec::new();
    let mut members: Vec<(usize, IfId)> = Vec::new();
    for (key, value) in store.table(sid::BRIDGE_PORT) {
        if let (Key::BridgePort { interface }, Value::BridgePort { bridge }) = (key, value) {
            let member = active
                .get(interface.as_str())
                .map(|&(id, _)| id)
                .filter(|id| {
                    usize::from(id.0) < ports.len()
                        || vlans.iter().any(|b| b.sub == *id)
                        || overlays.iter().any(|o| o.interface == *id)
                });
            if let (Some(at), Some(member)) = (bridge_at(bridge), member) {
                members.push((at, member));
            }
        }
    }
    for (at, member) in members {
        bridges[at].1.members.push(member);
    }
    for (key, value) in store.table(sid::BRIDGE_MAC) {
        if let (Key::BridgeMac { bridge, mac }, Value::BridgeMac { interface }) = (key, value) {
            let member = active.get(interface.as_str()).map(|&(id, _)| id);
            if let (Some(at), Some(member)) = (bridge_at(bridge), member) {
                if bridges[at].1.members.contains(&member) {
                    bridge_statics.push((u16::try_from(at).unwrap_or(u16::MAX), *mac, member));
                }
            }
        }
    }
    let mut names: BTreeSet<&str> = active.values().map(|&(_, vrf)| vrf).collect();
    if kept_entries.is_some() {
        // The VRFs the routes are in, as before: the change kept them.
        names.extend(kept_names.iter().map(String::as_str));
    } else {
        for (key, value) in store.table(sid::ROUTE) {
            if let Key::Route { vrf, .. } = key {
                names.insert(vrf.as_str());
            }
            // The VRF of an End.DT4 or End.DT6 SID, even with nothing else in it.
            if let Value::Route(RouteAction::Srv6Local(
                table::Srv6Local::EndDt4 { vrf } | table::Srv6Local::EndDt6 { vrf },
            )) = value
            {
                names.insert(vrf.as_str());
            }
        }
    }
    names.remove(DEFAULT_VRF);
    let order: Vec<&str> = std::iter::once(DEFAULT_VRF).chain(names).collect();
    let index_of = |vrf: &str| order.iter().position(|v| *v == vrf);
    // Each VRF's kernel interface.
    let mut kernel = Vec::with_capacity(order.len());
    for (at, vrf) in order.iter().enumerate() {
        let id = ids.take(&format!("rt-{vrf}"))?;
        interfaces.push(Interface {
            id,
            mac: crate::kernel::interface_mac(at),
            mtu: KERNEL_MTU,
        });
        kernel.push(id);
    }

    // Without the kept routes every route is read below; with them, none.
    let all_routes = kept_entries.is_none();
    let mut srv6_routes = false;
    let mut entries: Entries = kept_entries.unwrap_or_else(|| {
        order
            .iter()
            .map(|v| ((*v).to_owned(), BTreeMap::new()))
            .collect()
    });
    let mut neighbors = Vec::new();
    let mut neighbors6 = Vec::new();
    let mut unreachable = Vec::new();
    let mut unreachable6 = Vec::new();
    let mut bindings: Vec<Vec<LocalIpv4Binding>> = vec![Vec::new(); order.len()];
    let mut local6: Vec<Vec<Ipv6Local>> = vec![Vec::new(); order.len()];
    let mut sids = Vec::new();
    let mut policies = Vec::new();
    // Each SR policy's interface and the index of its VRF.
    let mut policy_vrfs: Vec<(IfId, usize)> = Vec::new();
    let mut firewall = Vec::new();
    let mut firewall_on = false;
    let mut firewall_filtering = table::NatFiltering::default();
    let mut firewall_outside: Vec<String> = Vec::new();
    let mut icmp_errors = None;
    let mut nat_entry = None;
    let read: Box<dyn Iterator<Item = (&Key, &Value)>> = if all_routes {
        Box::new(store.iter())
    } else {
        Box::new(store.iter_without(sid::ROUTE))
    };
    for (key, value) in read {
        match (key, value) {
            (Key::Address { interface, address }, Value::Address { .. }) => {
                let Some(&(id, vrf)) = active.get(interface.as_str()) else {
                    continue;
                };
                let at = index_of(vrf).expect("every interface VRF is listed");
                match *address {
                    IpAddr::V4(_) => {
                        // Core keeps one IPv4 address per interface for now.
                        if bindings[at].iter().all(|b| b.interface != id) {
                            bindings[at].push(LocalIpv4Binding {
                                interface: id,
                                address: v4(*address).expect("IPv4"),
                            });
                        }
                    }
                    IpAddr::V6(a) => local6[at].push(Ipv6Local {
                        interface: id,
                        address: a.octets(),
                    }),
                }
            }
            (Key::Route { vrf, prefix, len }, Value::Route(action)) => {
                match counts.get_mut(vrf.as_str()) {
                    Some(count) => *count += 1,
                    None => {
                        counts.insert(vrf.clone(), 1);
                    }
                }
                let entry = match action {
                    RouteAction::Srv6Local(local) => {
                        srv6_routes = true;
                        if let Some(sid) = srv6_sid(*prefix, *len, local, &active, index_of)? {
                            sids.push(sid);
                        }
                        continue;
                    }
                    RouteAction::Srv6Encap(encap) => {
                        // An interface of the FE's own for the policy: the route
                        // leaves through it, and core wraps what it sends.
                        srv6_routes = true;
                        let id = ids.take(&format!("srv6 {vrf} {prefix}/{len}"))?;
                        interfaces.push(Interface {
                            id,
                            mac: MacAddress([0x02, 0x73, 0x72, 0x76, 0x36, 0x00]),
                            mtu: u16::MAX,
                        });
                        policy_vrfs.push((id, index_of(vrf).expect("every route VRF is listed")));
                        policies.push(
                            ruster_core::Srv6Policy::new(
                                id,
                                encap.source.octets(),
                                encap.segments.iter().map(|s| s.octets()).collect(),
                                encap.reduced,
                            )
                            .map_err(|e| format!("route {vrf} {prefix}/{len}: {e:?}"))?,
                        );
                        Entry::Forward(Forward {
                            prefix: *prefix,
                            len: *len,
                            egress: id,
                            next_hop: None,
                        })
                    }
                    RouteAction::Gateways(_) => {
                        return Err(format!(
                            "route {vrf} {prefix}/{len}: next hops without an interface (ribd resolves them)"
                        ));
                    }
                    plain => match forwarding(*prefix, *len, plain, &active) {
                        Some(entry) => entry,
                        None => continue,
                    },
                };
                if let Some(list) = entries.get_mut(vrf) {
                    list.insert((*prefix, *len), entry);
                }
            }
            (Key::Neighbor { interface, address }, Value::Neighbor { mac }) => {
                let Some(&(id, _)) = active.get(interface.as_str()) else {
                    continue;
                };
                // An all-zero MAC address: the neighbor process gave up on it.
                let failed = *mac == [0; 6];
                match *address {
                    IpAddr::V4(_) if failed => {
                        unreachable.push((id, v4(*address).expect("IPv4")));
                    }
                    IpAddr::V6(a) if failed => unreachable6.push((id, a.octets())),
                    IpAddr::V4(_) => neighbors.push(Neighbor {
                        interface: id,
                        target: v4(*address).expect("IPv4"),
                        mac: MacAddress(*mac),
                    }),
                    IpAddr::V6(a) => neighbors6.push(Ipv6Neighbor {
                        interface: id,
                        target: a.octets(),
                        mac: MacAddress(*mac),
                    }),
                }
            }
            (Key::Nat { vrf }, Value::Nat(nat)) => {
                if vrf != DEFAULT_VRF {
                    return Err(format!("nat in {vrf}: only the default VRF has NAT"));
                }
                nat_entry = Some(nat);
            }
            (
                Key::IcmpErrors { vrf },
                Value::IcmpErrors {
                    ipv4_interval_ms,
                    ipv6_burst,
                    ipv6_interval_ms,
                },
            ) => {
                // The limits are the FE's, for every VRF.
                if vrf != DEFAULT_VRF {
                    return Err(format!(
                        "icmp-errors in {vrf}: the limits are set in the default VRF for all"
                    ));
                }
                icmp_errors = Some((*ipv4_interval_ms, *ipv6_burst, *ipv6_interval_ms));
            }
            (Key::FirewallPolicy { vrf }, Value::FirewallPolicy { filtering, outside }) => {
                if vrf != DEFAULT_VRF {
                    return Err(format!(
                        "firewall policy in {vrf}: only the default VRF has a firewall"
                    ));
                }
                firewall_filtering = *filtering;
                firewall_outside.clone_from(outside);
            }
            (Key::FirewallRule { vrf, id }, Value::FirewallRule(rule)) => {
                if vrf != DEFAULT_VRF {
                    return Err(format!(
                        "firewall rule {id} in {vrf}: only the default VRF has a firewall"
                    ));
                }
                firewall_on = true;
                // A rule naming an interface that is missing or disabled matches no
                // packet, so it is left out.
                if let Some(rule) = firewall_rule(*id, rule, &active, kernel[0])? {
                    firewall.push(rule);
                }
            }
            _ => {}
        }
    }

    // The change, made to the kept routes (none without them).
    for ((key, before), &after) in changed.iter().zip(&afters) {
        let Key::Route { vrf, prefix, len } = key else {
            continue;
        };
        if let Some(count) = counts.get_mut(vrf.as_str()) {
            match (before.is_some(), after.is_some()) {
                (false, true) => *count += 1,
                (true, false) => *count -= 1,
                _ => {}
            }
        }
        let Some(list) = entries.get_mut(vrf) else {
            continue;
        };
        let is_lookup = |entry: &Option<Entry>| matches!(entry, Some(Entry::Lookup { .. }));
        let entry = after.and_then(|action| forwarding(*prefix, *len, action, &active));
        let had = match entry.clone() {
            Some(entry) => list.insert((*prefix, *len), entry),
            None => list.remove(&(*prefix, *len)),
        };
        lookups = lookups + usize::from(is_lookup(&entry)) - usize::from(is_lookup(&had));
    }
    if all_routes {
        lookups = entries
            .values()
            .flat_map(BTreeMap::values)
            .filter(|entry| matches!(entry, Entry::Lookup { .. }))
            .count();
    }

    firewall.sort_by_key(|rule| rule.id());
    let nat = match nat_entry {
        Some(entry) => nat(entry, &active, &bindings[0])?,
        None => None,
    };
    // Core's routes of each VRF. With those of the build before, and no entry
    // that looks up in another VRF before or now, only the change is made to
    // them. Otherwise they are made from every entry.
    let mut tables = match kept_tables.filter(|_| lookups == 0) {
        Some(mut tables) => {
            for (key, _) in changed {
                let Key::Route { vrf, prefix, len } = key else {
                    continue;
                };
                let Some(list) = entries.get(vrf) else {
                    continue;
                };
                let table = tables.entry(vrf.clone()).or_default();
                match list.get(&(*prefix, *len)) {
                    Some(Entry::Forward(route)) => table.set(route, vrf)?,
                    Some(Entry::Lookup { .. }) => unreachable!("no entry looks up"),
                    None => table.remove(*prefix, *len),
                }
            }
            tables
        }
        None => {
            let mut tables = BTreeMap::new();
            for (name, routes) in expand_lookups(&entries) {
                let mut table = Tables::default();
                for route in &routes {
                    table.set(route, &name)?;
                }
                tables.insert(name, table);
            }
            tables
        }
    };
    let mut vrfs = Vec::with_capacity(order.len());
    for (at, name) in order.iter().enumerate() {
        let table = tables.entry((*name).to_owned()).or_default().clone();
        let owner = ValidatedForwardingOwner::with_routes(
            table.v4,
            interfaces.clone().into(),
            neighbors.clone().into(),
            std::mem::take(&mut bindings[at]).into(),
            Ipv4OriginPolicy::default(),
        )
        .map_err(|error| format!("{name}: {error:?}"))?;
        let ipv6 = Ipv6Fib::with_routes(
            table.v6,
            neighbors6.clone(),
            std::mem::take(&mut local6[at]),
        )
        .map_err(|error| format!("{name}: IPv6: {error:?}"))?
        .with_unreachable(unreachable6.clone());
        vrfs.push(Vrf { owner, ipv6 });
    }
    let interface_names = ids.names;
    let by_ingress = (0..interface_names.len())
        .map(|index| {
            active
                .values()
                .find(|(id, _)| usize::from(id.0) == index)
                .and_then(|&(_, vrf)| index_of(vrf))
                .and_then(|at| u16::try_from(at).ok())
                .unwrap_or(0)
        })
        .collect::<Vec<u16>>();
    let mut by_ingress = by_ingress;
    for (at, id) in kernel.iter().enumerate() {
        by_ingress[usize::from(id.0)] = u16::try_from(at).unwrap_or(0);
    }
    // A policy's interface counts as its VRF's (for the firewall).
    for &(id, at) in &policy_vrfs {
        by_ingress[usize::from(id.0)] = u16::try_from(at).unwrap_or(0);
    }
    let enabled = interfaces
        .iter()
        .map(|i| i.id)
        .filter(|id| !kernel.contains(id) && policy_vrfs.iter().all(|&(p, _)| p != *id))
        .collect();
    let srv6 = ruster_core::Srv6Table::new(sids)
        .and_then(|table| table.with_policies(policies))
        .map_err(|error| format!("srv6: {error:?}"))?;
    let punt =
        crate::punt_table::Classes::build(store, |name| active.get(name).map(|&(id, _)| id))?;
    let built = Built {
        srv6,
        bridges,
        bridge_statics,
        punt,
        vrfs,
        names: order.iter().map(|v| (*v).to_owned()).collect(),
        by_ingress,
        active: enabled,
        interface_names,
        vlans,
        tunnels,
        overlays,
        unreachable,
        pppoe,
        kernel,
        firewall,
        firewall_on,
        // Outside: the interfaces the configuration names. Inside: the default VRF's
        // other interfaces (the router's own kernel interfaces are neither).
        icmp_errors,
        firewall_interfaces: {
            let outside: Vec<IfId> = firewall_outside
                .iter()
                .filter_map(|name| active.get(name.as_str()).map(|&(id, _)| id))
                .collect();
            let inside: Vec<IfId> = active
                .values()
                .filter(|&&(id, vrf)| vrf == DEFAULT_VRF && !outside.contains(&id))
                .map(|&(id, _)| id)
                .collect();
            (
                ruster_core::FirewallInterfaceSet::of(&inside),
                ruster_core::FirewallInterfaceSet::of(&outside),
            )
        },
        firewall_filtering: match firewall_filtering {
            table::NatFiltering::EndpointIndependent => {
                ruster_core::FirewallFiltering::EndpointIndependent
            }
            table::NatFiltering::AddressDependent => {
                ruster_core::FirewallFiltering::AddressDependent
            }
            table::NatFiltering::AddressAndPortDependent => {
                ruster_core::FirewallFiltering::AddressAndPortDependent
            }
        },
        nat,
    };
    let routes = Routes {
        counts,
        entries,
        srv6: srv6_routes,
        lookups,
        tables,
    };
    Ok((built, routes))
}

/// Core's SID for an SRv6 SID route, or `None` when it names an interface that is
/// missing or disabled.
fn srv6_sid(
    prefix: IpAddr,
    len: u8,
    local: &table::Srv6Local,
    active: &BTreeMap<&str, (IfId, &str)>,
    index_of: impl Fn(&str) -> Option<usize>,
) -> Result<Option<ruster_core::Srv6Sid>, String> {
    use ruster_core::Srv6Behaviour;
    let vrf = |name: &str| {
        index_of(name)
            .and_then(|at| u16::try_from(at).ok())
            .ok_or_else(|| format!("SRv6 SID {prefix}/{len}: VRF {name}"))
    };
    let behaviour = match local {
        table::Srv6Local::End => Srv6Behaviour::End,
        table::Srv6Local::EndX {
            interface,
            next_hop,
        } => match active.get(interface.as_str()) {
            Some(&(egress, _)) => Srv6Behaviour::EndX {
                egress,
                next_hop: next_hop.octets(),
            },
            None => return Ok(None),
        },
        table::Srv6Local::EndDt4 { vrf: name } => Srv6Behaviour::EndDt4 { vrf: vrf(name)? },
        table::Srv6Local::EndDt6 { vrf: name } => Srv6Behaviour::EndDt6 { vrf: vrf(name)? },
    };
    let prefix = v6(prefix).ok_or_else(|| format!("SRv6 SID {prefix}/{len}: not IPv6"))?;
    ruster_core::Srv6Sid::new(prefix, len, behaviour)
        .map(Some)
        .map_err(|e| format!("SRv6 SID {len}: {e:?}"))
}

/// Core's NAPT for the table's entry, or `None` when one of its interfaces is
/// missing or disabled (no traffic then crosses it).
fn nat(
    entry: &table::Nat,
    active: &BTreeMap<&str, (IfId, &str)>,
    bindings: &[LocalIpv4Binding],
) -> Result<Option<Nat>, String> {
    let interface = |name: &str| -> Result<Option<IfId>, String> {
        match active.get(name) {
            None => Ok(None),
            Some(&(id, vrf)) if vrf == DEFAULT_VRF => Ok(Some(id)),
            Some(&(_, vrf)) => Err(format!("nat: interface {name} is in {vrf}, not default")),
        }
    };
    let (Some(inside), Some(outside)) = (interface(&entry.inside)?, interface(&entry.outside)?)
    else {
        return Ok(None);
    };
    let public = match entry.external {
        Some(address) => Ipv4Address::from_octets(address.octets()),
        None => bindings
            .iter()
            .find(|b| b.interface == outside)
            .map(|b| b.address)
            .ok_or_else(|| format!("nat: {} has no IPv4 address", entry.outside))?,
    };
    Ok(Some(Nat {
        inside,
        outside,
        public,
        ports: match entry.ports {
            table::NatPorts::Range { first, last } => PortSet::range(first, last),
            table::NatPorts::Psid {
                offset,
                length,
                psid,
            } => PortSet::psid(offset, length, psid),
        }
        .map_err(|e| format!("nat ports: {e:?}"))?,
        filtering: match entry.filtering {
            table::NatFiltering::EndpointIndependent => {
                ruster_core::Nat44Filtering::EndpointIndependent
            }
            table::NatFiltering::AddressDependent => ruster_core::Nat44Filtering::AddressDependent,
            table::NatFiltering::AddressAndPortDependent => {
                ruster_core::Nat44Filtering::AddressAndPortDependent
            }
        },
        ipv4_id_rate_limit: entry.ipv4_id_rate_limit,
        ports_per_host: entry.ports_per_host,
        state_per_host: entry.state_per_host,
    }))
}

/// Core's rule for the table's rule `id`, or `None` when it names an interface that
/// is missing or disabled.
fn firewall_rule(
    id: u32,
    rule: &table::FirewallRule,
    active: &BTreeMap<&str, (IfId, &str)>,
    kernel: IfId,
) -> Result<Option<FirewallRule>, String> {
    let interface = |name: &Option<String>| match name {
        None => Some(FirewallInterface::Any),
        // The default VRF's kernel interface: the router's own packets come in and
        // go out through it, as a host's through a port.
        Some(name) if name == KERNEL_INTERFACE => Some(FirewallInterface::Interface(kernel)),
        Some(name) => active
            .get(name.as_str())
            .map(|&(id, _)| FirewallInterface::Interface(id)),
    };
    let (Some(ingress), Some(egress)) = (interface(&rule.ingress), interface(&rule.egress)) else {
        return Ok(None);
    };
    let failed = |error: String| format!("firewall rule {id}: {error}");
    if id == 0 {
        return Err(failed("the id must not be 0".into()));
    }
    let prefix = |(address, len): (IpAddr, u8)| -> Result<ruster_core::FirewallPrefix, String> {
        match address {
            IpAddr::V4(v4) => {
                FirewallIpv4Prefix::new(Ipv4Address::from_octets(v4.octets()), len).map(Into::into)
            }
            IpAddr::V6(v6) => {
                ruster_core::FirewallIpv6Prefix::new(v6.octets(), len).map(Into::into)
            }
        }
        .map_err(|e| failed(format!("{address}/{len}: {e:?}")))
    };
    let ports = |(first, last): (u16, u16)| {
        FirewallPortRange::new(first, last)
            .map_err(|e| failed(format!("ports {first}-{last}: {e:?}")))
    };
    Ok(Some(FirewallRule::new(
        FirewallRuleId(id),
        ingress,
        egress,
        prefix(rule.source)?,
        prefix(rule.destination)?,
        match rule.protocol {
            table::Protocol::Tcp => FirewallProtocol::Tcp,
            table::Protocol::Udp => FirewallProtocol::Udp,
            table::Protocol::Icmp => FirewallProtocol::Icmp,
            table::Protocol::Icmpv6 => FirewallProtocol::Icmpv6,
        },
        ports(rule.source_ports)?,
        ports(rule.destination_ports)?,
        match rule.action {
            table::FirewallAction::Accept => FirewallAction::AllowStateful,
            table::FirewallAction::Drop => FirewallAction::Deny,
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(prefix: &str, len: u8, egress: u16) -> Entry {
        Entry::Forward(Forward {
            prefix: prefix.parse().unwrap(),
            len,
            egress: IfId(egress),
            next_hop: None,
        })
    }

    fn lookup(prefix: &str, len: u8, vrf: &str) -> Entry {
        Entry::Lookup {
            prefix: prefix.parse().unwrap(),
            len,
            vrf: vrf.into(),
        }
    }

    fn by_prefix(vrfs: BTreeMap<String, Vec<Entry>>) -> Entries {
        vrfs.into_iter()
            .map(|(vrf, list)| (vrf, list.into_iter().map(|e| (e.prefix(), e)).collect()))
            .collect()
    }

    fn prefixes(routes: &[Forward]) -> Vec<(String, u8, u16)> {
        let mut out: Vec<_> = routes
            .iter()
            .map(|r| (r.prefix.to_string(), r.len, r.egress.0))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn a_lookup_takes_the_other_vrf_s_routes_inside_it_and_the_one_covering_it() {
        let mut vrfs = BTreeMap::new();
        vrfs.insert(
            "red".to_owned(),
            vec![
                lookup("10.0.0.0", 8, "default"),
                // red's own route inside the lookup: B's routes under it stay out.
                fwd("10.1.0.0", 16, 1),
            ],
        );
        vrfs.insert(
            "default".to_owned(),
            vec![
                fwd("0.0.0.0", 0, 2),
                fwd("10.2.0.0", 16, 3),
                fwd("10.1.2.0", 24, 4),
                fwd("192.0.2.0", 24, 5),
            ],
        );
        let out = expand_lookups(&by_prefix(vrfs));
        assert_eq!(
            prefixes(&out["red"]),
            [
                ("10.0.0.0".to_owned(), 8, 2),
                ("10.1.0.0".to_owned(), 16, 1),
                ("10.2.0.0".to_owned(), 16, 3),
            ]
        );
        assert_eq!(out["default"].len(), 4, "the other VRF is unchanged");
    }

    #[test]
    fn a_lookup_into_a_vrf_without_routes_adds_nothing() {
        let mut vrfs = BTreeMap::new();
        vrfs.insert("red".to_owned(), vec![lookup("::", 0, "blue")]);
        assert!(expand_lookups(&by_prefix(vrfs))["red"].is_empty());
    }

    /// The expansion as it was first written: each route of the other VRF
    /// against each of this VRF's, quadratic, kept as the reference.
    fn expand_lookups_reference(vrfs: &Entries) -> BTreeMap<String, Vec<Forward>> {
        let forwards = |vrf: &str| -> Vec<Forward> {
            vrfs.get(vrf)
                .map(|entries| {
                    entries
                        .values()
                        .filter_map(|e| match e {
                            Entry::Forward(f) => Some(f.clone()),
                            Entry::Lookup { .. } => None,
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut out = BTreeMap::new();
        for (name, entries) in vrfs {
            let mut own = forwards(name);
            let mut added = Vec::new();
            for entry in entries.values() {
                let Entry::Lookup { prefix, len, vrf } = entry else {
                    continue;
                };
                let lookup = (*prefix, *len);
                let other = forwards(vrf);
                for route in &other {
                    let at = (route.prefix, route.len);
                    if !within(at, lookup) {
                        continue;
                    }
                    let shadowed = entries.values().any(|e| {
                        let q = e.prefix();
                        q.1 > lookup.1 && within(q, lookup) && within(at, q)
                    });
                    if !shadowed {
                        added.push(route.clone());
                    }
                }
                if let Some(covering) = other
                    .iter()
                    .filter(|r| r.len < lookup.1 && within(lookup, (r.prefix, r.len)))
                    .max_by_key(|r| r.len)
                {
                    added.push(Forward {
                        prefix: lookup.0,
                        len: lookup.1,
                        ..covering.clone()
                    });
                }
            }
            for route in added {
                if !own
                    .iter()
                    .any(|r| r.prefix == route.prefix && r.len == route.len)
                {
                    own.push(route);
                }
            }
            out.insert(name.clone(), own);
        }
        out
    }

    /// Random VRFs of forward and lookup routes, IPv4 and IPv6, nested at every
    /// length: the expansion gives what the reference gives, in the same order.
    #[test]
    fn the_expansion_gives_what_the_reference_gives() {
        let mut rng = Rng(0x6c6f_6f6b_7570);
        let names = ["default", "red", "blue"];
        let mut added = 0;
        for _ in 0..300 {
            let mut vrfs: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
            for name in names {
                let mut list = Vec::new();
                for _ in 0..rng.below(40) {
                    let v6 = rng.below(4) == 0;
                    let len = if v6 { rng.below(129) } else { rng.below(33) } as u8;
                    // Few distinct high bits, so that prefixes nest.
                    let bits = rng.below(8) << 61 | rng.below(1 << 20);
                    let address: IpAddr = if v6 {
                        std::net::Ipv6Addr::from(u128::from(bits) << 64).into()
                    } else {
                        std::net::Ipv4Addr::from((bits >> 32) as u32).into()
                    };
                    let prefix = network(address, len);
                    let entry = if rng.below(6) == 0 {
                        Entry::Lookup {
                            prefix,
                            len,
                            vrf: rng.pick(&names).into(),
                        }
                    } else {
                        Entry::Forward(Forward {
                            prefix,
                            len,
                            egress: IfId(rng.below(4) as u16),
                            next_hop: None,
                        })
                    };
                    list.push(entry);
                }
                vrfs.insert(name.into(), list);
            }
            let entries = by_prefix(vrfs);
            let expanded = expand_lookups(&entries);
            assert_eq!(expanded, expand_lookups_reference(&entries));
            let forwards = entries
                .values()
                .flat_map(BTreeMap::values)
                .filter(|entry| matches!(entry, Entry::Forward(_)))
                .count();
            added += expanded.values().map(Vec::len).sum::<usize>() - forwards;
        }
        // The lookups did bring routes in.
        assert!(added > 1_000, "{added}");
    }

    use std::os::unix::net::UnixStream;

    use ruster_proto::session::{Client, Hook, Server};
    use ruster_proto::table::{Change, NextHop};

    /// Builds for every change both ways, from the kept routes and reading every
    /// route, and has them agree.
    #[derive(Default)]
    struct BothWays {
        ports: Vec<String>,
        names: Vec<String>,
        kept: Option<Routes>,
        /// The builds that made the change to the kept routes, and those that could
        /// not.
        followed: usize,
        read_all: usize,
        refused: usize,
        /// The builds that made the change to core's routes of the build before.
        shared: usize,
        /// The builds that kept the routes for a change of neighbors alone.
        neighbors_only: usize,
        /// The builds that kept the routes for a change of addresses alone.
        addresses_only: usize,
    }

    impl Hook for BothWays {
        fn check(&mut self, next: &Store) -> Result<(), String> {
            let (built, routes) = build(&self.ports, next, &self.names, None)?;
            self.names = built.interface_names;
            self.kept = Some(routes);
            Ok(())
        }

        fn check_patch(
            &mut self,
            next: &Store,
            changed: &[(&Key, Option<&Value>)],
        ) -> Result<(), String> {
            let follows = self
                .kept
                .as_ref()
                .is_some_and(|routes| routes.follows(changed, next).is_some());
            let no_lookup_before = self.kept.as_ref().is_some_and(|r| r.lookups == 0);
            let all = build(&self.ports, next, &self.names, None);
            let kept = self.kept.take().map(|routes| (routes, changed));
            let made = build(&self.ports, next, &self.names, kept);
            match (all, made) {
                (Ok((all, all_routes)), Ok((made, made_routes))) => {
                    assert_eq!(made_routes, all_routes);
                    assert_eq!(made.names, all.names);
                    assert_eq!(made.interface_names, all.interface_names);
                    assert_eq!(made.by_ingress, all.by_ingress);
                    assert_eq!(made.vrfs.len(), all.vrfs.len());
                    // What a neighbor does change is the same both ways.
                    assert_eq!(made.unreachable, all.unreachable);
                    for (made, all) in made.vrfs.iter().zip(&all.vrfs) {
                        assert_eq!(made.owner.routes(), all.owner.routes());
                        assert_eq!(made.owner.neighbors(), all.owner.neighbors());
                        assert_eq!(made.owner.local_ipv4(), all.owner.local_ipv4());
                        assert_eq!(made.owner.interfaces(), all.owner.interfaces());
                        assert_eq!(made.ipv6, all.ipv6);
                    }
                    let no_route = !changed
                        .iter()
                        .any(|(key, _)| matches!(key, Key::Route { .. }));
                    if follows && no_route {
                        if changed
                            .iter()
                            .all(|(key, _)| matches!(key, Key::Address { .. }))
                        {
                            self.addresses_only += 1;
                        } else {
                            self.neighbors_only += 1;
                        }
                    }
                    if follows && no_lookup_before && made_routes.lookups == 0 {
                        self.shared += 1;
                    }
                    if follows {
                        self.followed += 1;
                    } else {
                        self.read_all += 1;
                    }
                    self.names = made.interface_names;
                    self.kept = Some(made_routes);
                    Ok(())
                }
                (Err(all), Err(made)) => {
                    assert_eq!(made, all);
                    self.refused += 1;
                    Err(all)
                }
                (all, made) => panic!(
                    "reading every route: {:?}; from the kept routes: {:?}",
                    all.map(|_| ()),
                    made.map(|_| ())
                ),
            }
        }

        fn committed(&mut self, _store: &Store) {}
    }

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, bound: u64) -> u64 {
            // SplitMix64.
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (value ^ (value >> 31)) % bound
        }

        fn pick<T: Copy>(&mut self, of: &[T]) -> T {
            of[self.below(of.len() as u64) as usize]
        }
    }

    fn interface(name: &str, enabled: bool, vrf: &str) -> Change {
        Change::set(
            Key::Interface { name: name.into() },
            Value::Interface {
                enabled,
                mac: [2, 0, 0, 0, 0, 1],
                mtu: 1500,
                vrf: vrf.into(),
                vlan: None,
                tunnel: None,
                pppoe: None,
            },
        )
    }

    const VRFS: [&str; 3] = [DEFAULT_VRF, "red", "blue"];

    /// A route key out of few, so that routes are changed and removed again: the
    /// prefixes are inside one another, of both families.
    fn route_key(rng: &mut Rng) -> Key {
        let (prefix, len) = rng.pick(&[
            ("0.0.0.0", 0),
            ("10.0.0.0", 8),
            ("10.1.0.0", 16),
            ("10.1.2.0", 24),
            ("192.0.2.0", 24),
            ("::", 0),
            ("2001:db8::", 32),
            ("2001:db8:1::", 48),
        ]);
        Key::Route {
            vrf: rng.pick(&VRFS).into(),
            prefix: prefix.parse().unwrap(),
            len,
        }
    }

    fn route_change(rng: &mut Rng, lookups: bool) -> Change {
        let key = route_key(rng);
        let v6 = matches!(&key, Key::Route { prefix, .. } if prefix.is_ipv6());
        let default = matches!(&key, Key::Route { vrf, .. } if vrf == DEFAULT_VRF);
        let hop = |rng: &mut Rng| NextHop {
            // "gone" is no interface; "p1" is at times disabled.
            interface: rng.pick(&["p0", "p1", "p2", "gone"]).into(),
            address: match (rng.below(2), v6) {
                (0, _) => None,
                (_, false) => Some("192.0.2.1".parse().unwrap()),
                (_, true) => Some("fe80::1".parse().unwrap()),
            },
        };
        let action = match rng.below(40) {
            0..=7 => return Change::delete(key),
            8..=24 => RouteAction::Forward((0..1 + rng.below(2)).map(|_| hop(rng)).collect()),
            25..=27 => RouteAction::Discard,
            28..=30 => RouteAction::Reject,
            31..=32 => RouteAction::Local,
            33..=36 if lookups => RouteAction::LookupVrf(rng.pick(&VRFS).into()),
            33..=36 => RouteAction::Discard,
            // The kinds the kept routes cannot follow.
            37 if v6 => RouteAction::Gateways(vec!["2001:db8::1".parse().unwrap()]),
            37 => RouteAction::Gateways(vec!["192.0.2.1".parse().unwrap()]),
            _ if v6 && default => RouteAction::Srv6Local(table::Srv6Local::End),
            _ => RouteAction::Discard,
        };
        Change::set(key, Value::Route(action))
    }

    /// Which kinds of entry a change may touch for the kept routes to follow it.
    #[test]
    fn the_kept_routes_follow_every_table_but_those_that_make_interfaces() {
        let routes = Routes {
            counts: BTreeMap::from([(DEFAULT_VRF.to_owned(), 1)]),
            entries: Entries::new(),
            srv6: false,
            lookups: 0,
            tables: BTreeMap::new(),
        };
        let store = Store::default();
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let name = || String::from("p0");
        let follows = |key: Key| routes.follows(&[(&key, None)], &store).is_some();
        for key in [
            Key::Address {
                interface: name(),
                address: v4,
            },
            Key::Neighbor {
                interface: name(),
                address: v4,
            },
            Key::Nat { vrf: name() },
            Key::FirewallPolicy { vrf: name() },
            Key::IcmpErrors { vrf: name() },
            Key::BridgePort { interface: name() },
        ] {
            assert!(follows(key.clone()), "{key:?}");
        }
        for key in [
            Key::Interface { name: name() },
            Key::EtherIp { interface: name() },
            Key::Vxlan { interface: name() },
            Key::Bridge { name: name() },
        ] {
            assert!(!follows(key.clone()), "{key:?}");
        }
    }

    #[test]
    fn a_change_made_to_the_kept_routes_gives_what_reading_every_route_gives() {
        // With routes that look up in another VRF, core's routes are made from
        // every entry; without, the change is made to those of the build before.
        let with_lookups = changes_both_ways(0x726f_7574_6573, true);
        assert!(with_lookups.shared > 5, "{}", with_lookups.shared);
        assert!(with_lookups.shared < with_lookups.followed / 2);
        let without = changes_both_ways(0x726f_7574_6574, false);
        assert_eq!(without.shared, without.followed);
    }

    fn changes_both_ways(seed: u64, lookups: bool) -> BothWays {
        let mut rng = Rng(seed);
        let mut hook = BothWays {
            ports: vec!["p0".into(), "p1".into(), "p2".into()],
            ..BothWays::default()
        };
        let mut server = Server::new();
        let connect = |server: &mut Server, writes: &[u64]| {
            let (a, b) = UnixStream::pair().unwrap();
            server.attach(a, writes).unwrap();
            Client::new(b).unwrap()
        };
        let mut config = connect(&mut server, &[sid::INTERFACE]);
        let mut routes = connect(&mut server, &[sid::ROUTE]);
        let mut neighbors = connect(&mut server, &[sid::NEIGHBOR]);
        let mut addresses = connect(&mut server, &[sid::ADDRESS]);
        config
            .patch(&[
                interface("p0", true, DEFAULT_VRF),
                interface("p1", true, "red"),
                interface("p2", true, "blue"),
            ])
            .unwrap();
        for _ in 0..400 {
            match rng.below(40) {
                // The interfaces change: the kept routes do not follow that.
                0 => {
                    let change =
                        interface("p1", rng.below(2) == 0, rng.pick(&[DEFAULT_VRF, "red"]));
                    config.patch(&[change]).unwrap();
                }
                // A resync of the routes: what is not sent again goes.
                1 => {
                    routes.resync_begin();
                    let again: Vec<Change> = (0..rng.below(4))
                        .map(|_| route_change(&mut rng, lookups))
                        .filter(|change| change.value.is_some())
                        .collect();
                    routes.patch(&again).unwrap();
                    routes.resync_end();
                }
                // A neighbor comes, changes, is marked unreachable (a MAC of
                // zeros) or goes, IPv4 or IPv6: the kept routes stay as they are,
                // whatever else the tables hold. At times as a resync of the
                // neighbors. (Routes and neighbors have different writers, so
                // one change never holds both.)
                kind @ 2..=11 => {
                    let neighbor = |rng: &mut Rng| {
                        let host = 1 + rng.below(3) as u8;
                        let address: IpAddr = if rng.below(2) == 0 {
                            std::net::Ipv4Addr::new(10, 0, 0, host).into()
                        } else {
                            std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, host.into()).into()
                        };
                        let key = Key::Neighbor {
                            interface: rng.pick(&["p0", "p1", "p2"]).into(),
                            address,
                        };
                        match rng.below(4) {
                            0 => Change::delete(key),
                            1 => Change::set(key, Value::Neighbor { mac: [0; 6] }),
                            _ => {
                                let mac = [2, 0, 0, 0, 0, 1 + rng.below(4) as u8];
                                Change::set(key, Value::Neighbor { mac })
                            }
                        }
                    };
                    match kind {
                        2 => {
                            neighbors.resync_begin();
                            let again: Vec<Change> = (0..rng.below(3))
                                .map(|_| neighbor(&mut rng))
                                .filter(|change| change.value.is_some())
                                .collect();
                            neighbors.patch(&again).unwrap();
                            neighbors.resync_end();
                        }
                        _ => {
                            neighbors.patch(&[neighbor(&mut rng)]).unwrap();
                        }
                    }
                }
                // An address comes or goes, on an interface that is there, is
                // disabled, or is not there.
                12..=15 => {
                    let host = 1 + rng.below(3) as u8;
                    let address: IpAddr = if rng.below(2) == 0 {
                        std::net::Ipv4Addr::new(10, 0, host, 1).into()
                    } else {
                        std::net::Ipv6Addr::new(0xfd00, 0, 0, host.into(), 0, 0, 0, 1).into()
                    };
                    let key = Key::Address {
                        interface: rng.pick(&["p0", "p1", "p2", "p3"]).into(),
                        address,
                    };
                    let change = if rng.below(3) == 0 {
                        Change::delete(key)
                    } else {
                        Change::set(key, Value::Address { prefix_len: 24 })
                    };
                    addresses.patch(&[change]).unwrap();
                }
                // Routes, a few at once, at times the same one twice.
                _ => {
                    let changes: Vec<Change> = (0..1 + rng.below(4))
                        .map(|_| route_change(&mut rng, lookups))
                        .collect();
                    routes.patch(&changes).unwrap();
                }
            }
            for _ in 0..4 {
                config.poll();
                routes.poll();
                neighbors.poll();
                addresses.poll();
                server.step(&mut hook);
            }
        }
        // Each way was taken often enough for the comparison to mean something.
        assert!(hook.followed > 100, "{}", hook.followed);
        assert!(hook.read_all > 20, "{}", hook.read_all);
        assert!(hook.refused > 5, "{}", hook.refused);
        assert!(hook.neighbors_only > 20, "{}", hook.neighbors_only);
        assert!(hook.addresses_only > 20, "{}", hook.addresses_only);
        hook
    }

    /// Builds as the FE does, from the routes kept, and adds up the time.
    #[derive(Default)]
    struct Timed {
        ports: Vec<String>,
        names: Vec<String>,
        kept: Option<Routes>,
        spent: std::time::Duration,
    }

    impl Hook for Timed {
        fn check(&mut self, next: &Store) -> Result<(), String> {
            // Not from a change: every route is read, as the FE does.
            self.kept = None;
            self.check_patch(next, &[])
        }

        fn check_patch(
            &mut self,
            next: &Store,
            changed: &[(&Key, Option<&Value>)],
        ) -> Result<(), String> {
            let started = std::time::Instant::now();
            let kept = self.kept.take().map(|routes| (routes, changed));
            let (built, routes) = build(&self.ports, next, &self.names, kept)?;
            self.spent += started.elapsed();
            self.names = built.interface_names;
            self.kept = Some(routes);
            Ok(())
        }

        fn committed(&mut self, _store: &Store) {}
    }

    /// Release timing of a VRF whose default route looks up in the default VRF,
    /// which holds `count` routes, run on demand:
    /// `cargo test --release -p ruster-fe lookup_timing -- --ignored --nocapture`
    #[test]
    #[ignore = "timing report, not a pass/fail test"]
    fn lookup_timing_up_to_a_full_table() {
        use std::time::Instant;

        let route = |index: u32, vrf: &str, len: u8| {
            Change::set(
                Key::Route {
                    vrf: vrf.into(),
                    prefix: std::net::Ipv4Addr::from(0x1000_0000 + (index << 8)).into(),
                    len,
                },
                Value::Route(RouteAction::Forward(vec![NextHop {
                    interface: "p0".into(),
                    address: Some("192.0.2.1".parse().unwrap()),
                }])),
            )
        };
        for (count, own) in [(16_384_u32, 16_u32), (65_536, 16), (16_384, 4_096)] {
            let mut hook = Timed {
                ports: vec!["p0".into(), "p1".into()],
                ..Timed::default()
            };
            let mut server = Server::new();
            let connect = |server: &mut Server, writes: &[u64]| {
                let (a, b) = UnixStream::pair().unwrap();
                server.attach(a, writes).unwrap();
                Client::new(b).unwrap()
            };
            let mut config = connect(&mut server, &[sid::INTERFACE]);
            let mut routes = connect(&mut server, &[sid::ROUTE]);
            let send =
                |server: &mut Server, client: &mut Client, hook: &mut Timed, changes: &[Change]| {
                    client.patch(changes).unwrap();
                    while client.poll().1.is_empty() {
                        server.step(hook);
                    }
                };
            send(
                &mut server,
                &mut config,
                &mut hook,
                &[
                    interface("p0", true, DEFAULT_VRF),
                    interface("p1", true, "red"),
                ],
            );
            for first in (0..count).step_by(1000) {
                let changes: Vec<Change> = (first..count.min(first + 1000))
                    .map(|index| route(index, DEFAULT_VRF, 24))
                    .collect();
                send(&mut server, &mut routes, &mut hook, &changes);
            }
            // Red's own routes, longer ones inside the default VRF's, and its
            // default route looking up in the default VRF.
            let mut own_routes: Vec<Change> =
                (0..own).map(|index| route(index * 4, "red", 26)).collect();
            own_routes.push(Change::set(
                Key::Route {
                    vrf: "red".into(),
                    prefix: "0.0.0.0".parse().unwrap(),
                    len: 0,
                },
                Value::Route(RouteAction::LookupVrf(DEFAULT_VRF.into())),
            ));
            for chunk in own_routes.chunks(1000) {
                send(&mut server, &mut routes, &mut hook, chunk);
            }
            std::mem::take(&mut hook.spent);
            let started = Instant::now();
            for round in 0..5_u32 {
                send(
                    &mut server,
                    &mut routes,
                    &mut hook,
                    &[route(count + round, DEFAULT_VRF, 24)],
                );
            }
            println!(
                "{count} routes and {own} of red's: one route in {:?} (building {:?})",
                started.elapsed() / 5,
                hook.spent / 5
            );
        }
    }

    /// Release timing, run on demand:
    /// `cargo test --release -p ruster-fe build_timing -- --ignored --nocapture`
    #[test]
    #[ignore = "timing report, not a pass/fail test"]
    fn build_timing_up_to_a_full_table() {
        use std::time::{Duration, Instant};

        let route = |index: u32, interface: &str| {
            Change::set(
                Key::Route {
                    vrf: DEFAULT_VRF.into(),
                    prefix: std::net::Ipv4Addr::from(0x1000_0000 + (index << 8)).into(),
                    len: 24,
                },
                // Through a gateway, as the routes of a routing protocol are.
                Value::Route(RouteAction::Forward(vec![NextHop {
                    interface: interface.into(),
                    address: Some("192.0.2.1".parse().unwrap()),
                }])),
            )
        };
        for count in [131_072u32, 1_048_576] {
            let mut hook = Timed {
                ports: vec!["p0".into(), "p1".into()],
                ..Timed::default()
            };
            let mut server = Server::new();
            let connect = |server: &mut Server, writes: &[u64]| {
                let (a, b) = UnixStream::pair().unwrap();
                server.attach(a, writes).unwrap();
                Client::new(b).unwrap()
            };
            let mut config = connect(&mut server, &[sid::INTERFACE]);
            let mut routes = connect(&mut server, &[sid::ROUTE]);
            let send =
                |server: &mut Server, client: &mut Client, hook: &mut Timed, changes: &[Change]| {
                    client.patch(changes).unwrap();
                    while client.poll().1.is_empty() {
                        server.step(hook);
                    }
                };
            send(
                &mut server,
                &mut config,
                &mut hook,
                &[
                    interface("p0", true, DEFAULT_VRF),
                    interface("p1", true, DEFAULT_VRF),
                ],
            );
            // The whole table arrives 1,000 routes at a time.
            let started = Instant::now();
            for first in (0..count).step_by(1000) {
                let changes: Vec<Change> = (first..count.min(first + 1000))
                    .map(|index| route(index, "p0"))
                    .collect();
                send(&mut server, &mut routes, &mut hook, &changes);
            }
            let load = started.elapsed();
            let load_build = std::mem::take(&mut hook.spent);
            // Then one route changes, 20 times.
            let started = Instant::now();
            for round in 0..20 {
                let interface = ["p1", "p0"][round % 2];
                send(
                    &mut server,
                    &mut routes,
                    &mut hook,
                    &[route(count / 2, interface)],
                );
            }
            let one = started.elapsed() / 20;
            let one_build: Duration = std::mem::take(&mut hook.spent) / 20;
            // Then one neighbor changes, 20 times, as when neighd learns one.
            let mut neighbors = connect(&mut server, &[sid::NEIGHBOR]);
            let started = Instant::now();
            for round in 0..20_u8 {
                let neighbor = Change::set(
                    Key::Neighbor {
                        interface: "p0".into(),
                        address: "192.0.2.1".parse().unwrap(),
                    },
                    Value::Neighbor {
                        mac: [2, 0, 0, 0, 0, round],
                    },
                );
                send(&mut server, &mut neighbors, &mut hook, &[neighbor]);
            }
            let neighbor = started.elapsed() / 20;
            let neighbor_build: Duration = std::mem::take(&mut hook.spent) / 20;
            // Then an address comes and goes, 20 times, as from DHCP or PPPoE.
            let mut addresses = connect(&mut server, &[sid::ADDRESS]);
            let started = Instant::now();
            for round in 0..20 {
                let key = Key::Address {
                    interface: "p1".into(),
                    address: "198.51.100.2".parse().unwrap(),
                };
                let change = if round % 2 == 0 {
                    Change::set(key, Value::Address { prefix_len: 24 })
                } else {
                    Change::delete(key)
                };
                send(&mut server, &mut addresses, &mut hook, &[change]);
            }
            let address = started.elapsed() / 20;
            let address_build: Duration = hook.spent / 20;
            println!(
                "{count} routes: the whole table in {load:?} (building {load_build:?}), \
                 one route in {one:?} (building {one_build:?}), \
                 one neighbor in {neighbor:?} (building {neighbor_build:?}), \
                 one address in {address:?} (building {address_build:?})"
            );
        }
    }
}

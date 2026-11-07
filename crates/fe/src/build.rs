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

use crate::wireguard::{InterfaceBuilt, PeerBuilt};
use ruster_core::wireguard::{AllowedPrefix, SessionKeys};
use ruster_core::{
    FirewallAction, FirewallInterface, FirewallIpv4Prefix, FirewallPortRange, FirewallProtocol,
    FirewallRule, FirewallRuleId, IfId, Interface, Ipv4Address, Ipv4InIpv6Tunnel, Ipv4OriginPolicy,
    Ipv6Fib, Ipv6Local, Ipv6Neighbor, Ipv6Route, LocalIpv4Binding, MacAddress, Neighbor, PortSet,
    PppoeSession, Route, ValidatedForwardingOwner, VlanBinding,
};
use ruster_proto::session::Store;
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
    /// The name of every interface by id: the ports, then the VLAN sub-interfaces.
    pub(crate) interface_names: Vec<String>,
    /// The VLAN sub-interfaces of enabled ports.
    pub(crate) vlans: Vec<VlanBinding>,
    /// The enabled IPv4 in IPv6 tunnels.
    pub(crate) tunnels: Vec<Ipv4InIpv6Tunnel>,
    /// The PPPoE sessions on enabled interfaces.
    pub(crate) pppoe: Vec<PppoeSession>,
    /// The WireGuard interfaces that are enabled, with their peers and sessions.
    pub(crate) wireguard: Vec<InterfaceBuilt>,
    /// The default VRF's forward firewall rules, in rule id order, without those
    /// naming an interface that is missing or disabled.
    pub(crate) firewall: Vec<FirewallRule>,
    /// Whether the tables have any firewall rule. Then the firewall is on even if
    /// none of them is in `firewall`, and drops everything.
    pub(crate) firewall_on: bool,
    /// The default VRF's NAPT, when the tables have one and both its interfaces
    /// are enabled.
    pub(crate) nat: Option<Nat>,
}

/// NAPT from `inside` to `outside`, with `public` and `ports`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nat {
    pub(crate) inside: IfId,
    pub(crate) outside: IfId,
    pub(crate) public: Ipv4Address,
    pub(crate) ports: PortSet,
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
#[derive(Clone, Debug)]
enum Entry {
    Forward(Forward),
    Lookup {
        prefix: IpAddr,
        len: u8,
        vrf: String,
    },
}

impl Entry {
    fn prefix(&self) -> (IpAddr, u8) {
        match self {
            Self::Forward(f) => (f.prefix, f.len),
            Self::Lookup { prefix, len, .. } => (*prefix, *len),
        }
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
/// the packet falls to this VRF's shorter routes, since core has no discard route.
fn expand_lookups(vrfs: &BTreeMap<String, Vec<Entry>>) -> BTreeMap<String, Vec<Forward>> {
    let forwards = |vrf: &str| -> Vec<Forward> {
        vrfs.get(vrf)
            .map(|entries| {
                entries
                    .iter()
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
        for entry in entries {
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
                let shadowed = entries.iter().any(|e| {
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
        // This VRF's own routes win over expanded ones for the same prefix.
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

pub(crate) fn build(ports: &[String], store: &Store) -> Result<Built, String> {
    let port = |name: &str| {
        let index = ports.iter().position(|p| p == name)?;
        u16::try_from(index).ok().map(IfId)
    };
    // Enabled interfaces and their VRFs.
    let mut interfaces = Vec::new();
    let mut active: BTreeMap<&str, (IfId, &str)> = BTreeMap::new();
    for (key, value) in store.iter() {
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
    // VLAN sub-interfaces of enabled ports get the ids after the ports, by name.
    let mut interface_names: Vec<String> = ports.to_vec();
    let mut vlans = Vec::new();
    for (key, value) in store.iter() {
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
            let id = u16::try_from(interface_names.len())
                .map(IfId)
                .map_err(|_| "too many interfaces".to_owned())?;
            interface_names.push(name.clone());
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
    for (key, value) in store.iter() {
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
            let id = u16::try_from(interface_names.len())
                .map(IfId)
                .map_err(|_| "too many interfaces".to_owned())?;
            interface_names.push(name.clone());
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
    for (key, value) in store.iter() {
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
            let id = u16::try_from(interface_names.len())
                .map(IfId)
                .map_err(|_| "too many interfaces".to_owned())?;
            interface_names.push(name.clone());
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
    // WireGuard interfaces get the ids after those: a plain interface entry that has
    // WireGuard settings and is no port.
    let mut wireguard = Vec::new();
    for (key, value) in store.iter() {
        let (Key::Wireguard { interface: name }, Value::Wireguard(settings)) = (key, value) else {
            continue;
        };
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
            return Err(format!("WireGuard interface {name} has the name of a port"));
        }
        let id = u16::try_from(interface_names.len())
            .map(IfId)
            .map_err(|_| "too many interfaces".to_owned())?;
        interface_names.push(name.clone());
        interfaces.push(Interface {
            id,
            mac: MacAddress(*mac),
            mtu: *mtu,
        });
        let mut peers = Vec::new();
        for (key, value) in store.iter() {
            let (Key::WireguardPeer { interface, peer }, Value::WireguardPeer(config)) =
                (key, value)
            else {
                continue;
            };
            if interface != name {
                continue;
            }
            let keys = match store.get(&Key::WireguardSession {
                interface: name.clone(),
                peer: peer.clone(),
            }) {
                Some(Value::WireguardSession(session)) => Some(SessionKeys {
                    send: session.send,
                    receive: session.receive,
                    peer_index: session.peer_index,
                    local_index: session.local_index,
                }),
                _ => None,
            };
            peers.push(PeerBuilt {
                name: peer.clone(),
                endpoint: config.endpoint.octets(),
                port: config.port,
                allowed: config
                    .allowed
                    .iter()
                    .map(|&(address, len)| AllowedPrefix {
                        address: address.octets(),
                        len,
                    })
                    .collect(),
                keys,
            });
        }
        wireguard.push(InterfaceBuilt {
            interface: id,
            name: name.clone(),
            local: settings.local.octets(),
            listen_port: settings.listen_port,
            peers,
        });
        active.insert(name.as_str(), (id, vrf.as_str()));
    }
    let mut names: BTreeSet<&str> = active.values().map(|&(_, vrf)| vrf).collect();
    for (key, _) in store.iter() {
        if let Key::Route { vrf, .. } = key {
            names.insert(vrf.as_str());
        }
    }
    names.remove(DEFAULT_VRF);
    let order: Vec<&str> = std::iter::once(DEFAULT_VRF).chain(names).collect();
    let index_of = |vrf: &str| order.iter().position(|v| *v == vrf);

    let mut entries: BTreeMap<String, Vec<Entry>> = order
        .iter()
        .map(|v| ((*v).to_owned(), Vec::new()))
        .collect();
    let mut neighbors = Vec::new();
    let mut neighbors6 = Vec::new();
    let mut bindings: Vec<Vec<LocalIpv4Binding>> = vec![Vec::new(); order.len()];
    let mut local6: Vec<Vec<Ipv6Local>> = vec![Vec::new(); order.len()];
    let mut firewall = Vec::new();
    let mut firewall_on = false;
    let mut nat_entry = None;
    for (key, value) in store.iter() {
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
                let entry = match action {
                    RouteAction::Forward(hops) => {
                        let Some((egress, hop)) = hops.iter().find_map(|hop| {
                            active.get(hop.interface.as_str()).map(|&(id, _)| (id, hop))
                        }) else {
                            continue;
                        };
                        Entry::Forward(Forward {
                            prefix: *prefix,
                            len: *len,
                            egress,
                            next_hop: hop.address,
                        })
                    }
                    RouteAction::LookupVrf(other) => Entry::Lookup {
                        prefix: *prefix,
                        len: *len,
                        vrf: other.clone(),
                    },
                    RouteAction::Local | RouteAction::Discard | RouteAction::Reject => continue,
                };
                if let Some(list) = entries.get_mut(vrf) {
                    list.push(entry);
                }
            }
            (Key::Neighbor { interface, address }, Value::Neighbor { mac }) => {
                let Some(&(id, _)) = active.get(interface.as_str()) else {
                    continue;
                };
                match *address {
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
            (Key::FirewallRule { vrf, id }, Value::FirewallRule(rule)) => {
                if vrf != DEFAULT_VRF {
                    return Err(format!(
                        "firewall rule {id} in {vrf}: only the default VRF has a firewall"
                    ));
                }
                firewall_on = true;
                // A rule naming an interface that is missing or disabled matches no
                // packet, so it is left out.
                if let Some(rule) = firewall_rule(*id, rule, &active)? {
                    firewall.push(rule);
                }
            }
            _ => {}
        }
    }

    firewall.sort_by_key(|rule| rule.id());
    let nat = match nat_entry {
        Some(entry) => nat(entry, &active, &bindings[0])?,
        None => None,
    };
    let routes = expand_lookups(&entries);
    let mut vrfs = Vec::with_capacity(order.len());
    for (at, name) in order.iter().enumerate() {
        let mut routes4 = Vec::new();
        let mut routes6 = Vec::new();
        for route in &routes[*name] {
            let failed =
                |error| format!("route {}/{} in {name}: {error:?}", route.prefix, route.len);
            match route.prefix {
                IpAddr::V4(_) => routes4.push(
                    Route::new(
                        v4(route.prefix).expect("IPv4"),
                        route.len,
                        route.egress,
                        route.next_hop.and_then(v4),
                    )
                    .map_err(|e| failed(format!("{e:?}")))?,
                ),
                IpAddr::V6(_) => routes6.push(
                    Ipv6Route::new(
                        v6(route.prefix).expect("IPv6"),
                        route.len,
                        route.egress,
                        route.next_hop.and_then(v6),
                    )
                    .map_err(|e| failed(format!("{e:?}")))?,
                ),
            }
        }
        let owner = ValidatedForwardingOwner::new(
            routes4.into(),
            interfaces.clone().into(),
            neighbors.clone().into(),
            std::mem::take(&mut bindings[at]).into(),
            Ipv4OriginPolicy::default(),
        )
        .map_err(|error| format!("{name}: {error:?}"))?;
        let ipv6 = Ipv6Fib::new(routes6, neighbors6.clone(), std::mem::take(&mut local6[at]))
            .map_err(|error| format!("{name}: IPv6: {error:?}"))?;
        vrfs.push(Vrf { owner, ipv6 });
    }
    let by_ingress = (0..interface_names.len())
        .map(|index| {
            active
                .values()
                .find(|(id, _)| usize::from(id.0) == index)
                .and_then(|&(_, vrf)| index_of(vrf))
                .and_then(|at| u16::try_from(at).ok())
                .unwrap_or(0)
        })
        .collect();
    let enabled = interfaces.iter().map(|i| i.id).collect();
    Ok(Built {
        vrfs,
        names: order.iter().map(|v| (*v).to_owned()).collect(),
        by_ingress,
        active: enabled,
        interface_names,
        vlans,
        tunnels,
        pppoe,
        wireguard,
        firewall,
        firewall_on,
        nat,
    })
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
    }))
}

/// Core's rule for the table's rule `id`, or `None` when it names an interface that
/// is missing or disabled.
fn firewall_rule(
    id: u32,
    rule: &table::FirewallRule,
    active: &BTreeMap<&str, (IfId, &str)>,
) -> Result<Option<FirewallRule>, String> {
    let interface = |name: &Option<String>| match name {
        None => Some(FirewallInterface::Any),
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
    let prefix = |(address, len): (std::net::Ipv4Addr, u8)| {
        FirewallIpv4Prefix::new(Ipv4Address::from_octets(address.octets()), len)
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
        let out = expand_lookups(&vrfs);
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
        assert!(expand_lookups(&vrfs)["red"].is_empty());
    }
}

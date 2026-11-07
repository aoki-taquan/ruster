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
    IfId, Interface, Ipv4Address, Ipv4OriginPolicy, Ipv6Fib, Ipv6Local, Ipv6Neighbor, Ipv6Route,
    LocalIpv4Binding, MacAddress, Neighbor, Route, ValidatedForwardingOwner,
};
use ruster_proto::session::Store;
use ruster_proto::table::{network, Key, RouteAction, Value, DEFAULT_VRF};

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
    /// The enabled ports.
    pub(crate) active: Vec<IfId>,
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
            _ => {}
        }
    }

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
    let by_ingress = (0..ports.len())
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
    })
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

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
    Ipv6Fib, Ipv6Local, Ipv6Neighbor, Ipv6Route, LocalIpv4Binding, MacAddress, Neighbor, PortSet,
    PppoeSession, Route, ValidatedForwardingOwner, VlanBinding,
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
/// the packet falls to this VRF's shorter routes (not yet made a discard route).
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

pub(crate) fn build(ports: &[String], store: &Store, previous: &[String]) -> Result<Built, String> {
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

    let mut entries: BTreeMap<String, Vec<Entry>> = order
        .iter()
        .map(|v| ((*v).to_owned(), Vec::new()))
        .collect();
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
                    RouteAction::Discard | RouteAction::Reject => Entry::Forward(Forward {
                        prefix: *prefix,
                        len: *len,
                        egress: if *action == RouteAction::Discard {
                            IfId::DISCARD
                        } else {
                            IfId::REJECT
                        },
                        next_hop: None,
                    }),
                    RouteAction::Local => continue,
                    RouteAction::Srv6Local(local) => {
                        if let Some(sid) = srv6_sid(*prefix, *len, local, &active, index_of)? {
                            sids.push(sid);
                        }
                        continue;
                    }
                    RouteAction::Srv6Encap(encap) => {
                        // An interface of the FE's own for the policy: the route
                        // leaves through it, and core wraps what it sends.
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
                };
                if let Some(list) = entries.get_mut(vrf) {
                    list.push(entry);
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
    Ok(Built {
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
    })
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

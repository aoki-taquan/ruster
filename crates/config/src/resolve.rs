//! `ruster.toml` to the lock form.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use serde::Deserialize;

use ruster_proto::table::DEFAULT_VRF;

use crate::{
    FirewallOutside, FirewallRule, Interface, Kind, Lock, MapE, Nat, Route, Target, B4_ADDRESS,
    FILTERING, ICMP_ERRORS, MTU, NAT_PORTS, PPPOE_OVERHEAD, PSID_OFFSET, TUNNEL_MAC, TUNNEL_MTU,
    VERSION, VLAN_OVERHEAD,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct File {
    #[serde(default)]
    interface: Vec<InterfaceEntry>,
    #[serde(default)]
    route: Vec<RouteEntry>,
    #[serde(default)]
    firewall: Vec<FirewallEntry>,
    firewall_filtering: Option<String>,
    firewall_outside: Option<Vec<String>>,
    icmp_errors: Option<IcmpErrorsEntry>,
    nat: Option<NatEntry>,
    map_e: Option<MapEEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct MapEEntry {
    interface: String,
    inside: String,
    prefix: String,
    rule_ipv6: String,
    rule_ipv4: String,
    ea_length: u8,
    psid_offset: Option<u8>,
    br: String,
    mtu: Option<u16>,
    filtering: Option<String>,
    ipv4_id_rate_limit: Option<bool>,
    ports_per_host: Option<u16>,
    state_per_host: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct IcmpErrorsEntry {
    ipv4_interval_ms: Option<u32>,
    ipv6_burst: Option<u32>,
    ipv6_interval_ms: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct NatEntry {
    inside: String,
    outside: String,
    ports: Option<String>,
    external: Option<String>,
    filtering: Option<String>,
    ipv4_id_rate_limit: Option<bool>,
    ports_per_host: Option<u16>,
    state_per_host: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct FirewallEntry {
    action: String,
    protocol: String,
    ingress: Option<String>,
    egress: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    source_ports: Option<String>,
    destination_ports: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceEntry {
    name: String,
    mac: Option<String>,
    parent: Option<String>,
    vlan: Option<u16>,
    mtu: Option<u16>,
    enabled: Option<bool>,
    ipv4: Option<String>,
    #[serde(default)]
    ipv6: Vec<String>,
    vrf: Option<String>,
    tunnel: Option<TunnelEntry>,
    pppoe: Option<PppoeEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PppoeEntry {
    parent: String,
    session: u16,
    peer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelEntry {
    local: String,
    remote: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RouteEntry {
    vrf: Option<String>,
    prefix: String,
    interface: Option<String>,
    via: Option<String>,
    lookup_vrf: Option<String>,
    action: Option<String>,
}

fn default_vrf(vrf: Option<String>) -> String {
    vrf.unwrap_or_else(|| DEFAULT_VRF.to_owned())
}

fn filtering(text: Option<String>) -> String {
    text.unwrap_or_else(|| FILTERING.to_owned())
}

/// `a.b.c.d/len` as an address and its network, if it is one.
fn ipv4_prefix(text: &str) -> Option<(Ipv4Addr, Ipv4Addr, u8)> {
    let (address, len) = text.split_once('/')?;
    let address: Ipv4Addr = address.parse().ok()?;
    let len: u8 = len.parse().ok().filter(|len| *len <= 32)?;
    let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
    Some((address, Ipv4Addr::from(u32::from(address) & mask), len))
}

/// Reads `ruster.toml` and gives every value it leaves out. Only what a default
/// needs is checked here; the rest is the reader of the lock form's to check.
pub fn resolve(text: &str) -> Result<Lock, String> {
    let file: File = toml::from_str(text).map_err(|error| error.to_string())?;
    let mut interfaces: Vec<Interface> = Vec::with_capacity(file.interface.len());
    // The IPv4 addresses and prefixes so far, per VRF: the B4's address is given
    // only where it is free.
    let mut addresses = BTreeSet::new();
    let mut prefixes = BTreeSet::new();
    for entry in file.interface {
        let at = format!("interface {:?}", entry.name);
        let vrf = default_vrf(entry.vrf);
        let kind = match (entry.parent, entry.vlan, entry.tunnel, entry.pppoe) {
            (None, None, None, None) => Kind::Port,
            (Some(parent), Some(id), None, None) => Kind::Vlan { parent, id },
            (None, None, Some(tunnel), None) => Kind::Tunnel {
                local: tunnel.local,
                remote: tunnel.remote,
            },
            (None, None, None, Some(pppoe)) => Kind::Pppoe {
                parent: pppoe.parent,
                session: pppoe.session,
                peer: pppoe.peer,
            },
            (Some(_), None, ..) | (None, Some(_), ..) => {
                return Err(format!("{at}: give parent and vlan together"))
            }
            (Some(_), Some(_), Some(_), _) => {
                return Err(format!(
                    "{at}: an interface is a VLAN or a tunnel, not both"
                ))
            }
            _ => {
                return Err(format!(
                    "{at}: an interface is one of a VLAN, a tunnel and a PPPoE session"
                ))
            }
        };
        // What a VLAN or a session takes from its parent: its MAC and MTU.
        let parent = match &kind {
            Kind::Vlan { parent, .. } => Some(
                interfaces
                    .iter()
                    .find(|i| i.name == *parent && i.kind == Kind::Port)
                    .map(|i| (i.mac.clone(), i.mtu.saturating_sub(VLAN_OVERHEAD)))
                    .ok_or_else(|| {
                        format!(
                            "{at}: parent {parent:?} must be an interface given before it, not a VLAN"
                        )
                    }),
            ),
            Kind::Pppoe { parent, .. } => Some(
                interfaces
                    .iter()
                    .find(|i| {
                        i.name == *parent && matches!(i.kind, Kind::Port | Kind::Vlan { .. })
                    })
                    .map(|i| (i.mac.clone(), i.mtu.saturating_sub(PPPOE_OVERHEAD)))
                    .ok_or_else(|| {
                        format!("{at}: PPPoE parent {parent:?} must be a port or VLAN given before it")
                    }),
            ),
            _ => None,
        };
        let mac = match (entry.mac, &kind, &parent) {
            (Some(mac), ..) => mac,
            (None, Kind::Tunnel { .. }, _) => TUNNEL_MAC.to_owned(),
            (None, _, Some(parent)) => parent.clone()?.0,
            (None, ..) => return Err(format!("{at}: mac is missing")),
        };
        let mtu = match (entry.mtu, &kind, &parent) {
            (Some(mtu), ..) => mtu,
            (None, Kind::Tunnel { .. }, _) => TUNNEL_MTU,
            (None, _, Some(parent)) => parent.clone()?.1,
            (None, ..) => MTU,
        };
        let ipv4 = match entry.ipv4 {
            Some(text) => vec![text],
            None if matches!(kind, Kind::Tunnel { .. }) => {
                let (address, network, len) = ipv4_prefix(B4_ADDRESS).expect("a prefix");
                let free = !addresses.contains(&(vrf.clone(), address))
                    && !prefixes.contains(&(vrf.clone(), network, len));
                if free {
                    vec![B4_ADDRESS.to_owned()]
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        };
        for (address, network, len) in ipv4.iter().filter_map(|text| ipv4_prefix(text)) {
            addresses.insert((vrf.clone(), address));
            prefixes.insert((vrf.clone(), network, len));
        }
        interfaces.push(Interface {
            name: entry.name,
            mac,
            mtu,
            enabled: entry.enabled.unwrap_or(true),
            vrf,
            ipv4,
            ipv6: entry.ipv6,
            kind,
        });
    }
    let route = file
        .route
        .into_iter()
        .map(route)
        .collect::<Result<_, _>>()?;
    let firewall = file
        .firewall
        .into_iter()
        .map(|entry| FirewallRule {
            action: entry.action,
            protocol: entry.protocol,
            ingress: entry.ingress.into_iter().collect(),
            egress: entry.egress.into_iter().collect(),
            source: entry.source.into_iter().collect(),
            destination: entry.destination.into_iter().collect(),
            source_ports: entry.source_ports.into_iter().collect(),
            destination_ports: entry.destination_ports.into_iter().collect(),
        })
        .collect();
    let icmp_errors = match file.icmp_errors {
        None => ICMP_ERRORS,
        Some(entry) => crate::IcmpErrors {
            ipv4_interval_ms: entry
                .ipv4_interval_ms
                .unwrap_or(ICMP_ERRORS.ipv4_interval_ms),
            ipv6_burst: entry.ipv6_burst.unwrap_or(ICMP_ERRORS.ipv6_burst),
            ipv6_interval_ms: entry
                .ipv6_interval_ms
                .unwrap_or(ICMP_ERRORS.ipv6_interval_ms),
        },
    };
    let nat = file.nat.map(|entry| Nat {
        inside: entry.inside,
        outside: entry.outside,
        ports: entry.ports.unwrap_or_else(|| NAT_PORTS.to_owned()),
        external: entry.external.into_iter().collect(),
        filtering: filtering(entry.filtering),
        ipv4_id_rate_limit: entry.ipv4_id_rate_limit.unwrap_or(true),
        ports_per_host: entry.ports_per_host.unwrap_or(0),
        state_per_host: entry.state_per_host.unwrap_or(0),
    });
    let map_e = file.map_e.map(|entry| MapE {
        interface: entry.interface,
        inside: entry.inside,
        prefix: entry.prefix,
        rule_ipv6: entry.rule_ipv6,
        rule_ipv4: entry.rule_ipv4,
        ea_length: entry.ea_length,
        psid_offset: entry.psid_offset.unwrap_or(PSID_OFFSET),
        br: entry.br,
        mtu: entry.mtu.unwrap_or(TUNNEL_MTU),
        mac: TUNNEL_MAC.to_owned(),
        ports: NAT_PORTS.to_owned(),
        filtering: filtering(entry.filtering),
        ipv4_id_rate_limit: entry.ipv4_id_rate_limit.unwrap_or(true),
        ports_per_host: entry.ports_per_host.unwrap_or(0),
        state_per_host: entry.state_per_host.unwrap_or(0),
    });
    Ok(Lock {
        version: VERSION,
        firewall_filtering: filtering(file.firewall_filtering),
        firewall_outside: match file.firewall_outside {
            None => FirewallOutside::Derive,
            Some(names) => FirewallOutside::Interfaces(names),
        },
        icmp_errors,
        interface: interfaces,
        map_e: map_e.into_iter().collect(),
        nat: nat.into_iter().collect(),
        route,
        firewall,
    })
}

fn route(entry: RouteEntry) -> Result<Route, String> {
    let at = format!("route {:?}", entry.prefix);
    let target = match (entry.action, entry.interface, entry.lookup_vrf, entry.via) {
        (Some(action), interface, lookup_vrf, via) => {
            let target = match action.as_str() {
                "discard" => Target::Discard,
                "reject" => Target::Reject,
                _ => return Err(format!("{at}: action must be \"discard\" or \"reject\"")),
            };
            if interface.is_some() || lookup_vrf.is_some() || via.is_some() {
                return Err(format!(
                    "{at}: a {action} route has no interface, lookup-vrf or via"
                ));
            }
            target
        }
        (None, Some(interface), None, via) => Target::Forward {
            interface,
            via: via.into_iter().collect(),
        },
        (None, None, Some(_), Some(_)) => {
            return Err(format!("{at}: a lookup-vrf route has no via"))
        }
        (None, None, Some(other), None) => Target::LookupVrf(other),
        _ => {
            return Err(format!(
                "{at}: give one of interface, lookup-vrf and action"
            ))
        }
    };
    Ok(Route {
        vrf: default_vrf(entry.vrf),
        prefix: entry.prefix,
        target,
    })
}

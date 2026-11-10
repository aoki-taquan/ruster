//! `ruster.toml` to the lock form.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;

use ruster_proto::table::DEFAULT_VRF;

use crate::{
    Dhcp, Dns, FirewallOutside, FirewallRule, Interface, Kind, Lock, MapE, Nat, Pppoe, Route,
    Source, Target, B4_ADDRESS, DHCP_LEASE_TIME, DHCP_PUNT_BURST, DHCP_PUNT_RATE, FILTERING,
    ICMP_ERRORS, MTU, NAT_PORTS, PPPOE_ECHO_FAILURES, PPPOE_ECHO_INTERVAL, PPPOE_OVERHEAD,
    PSID_OFFSET, SOURCE_KINDS, TUNNEL_MAC, TUNNEL_MTU, VERSION, VLAN_OVERHEAD,
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
    dns: Option<DnsEntry>,
    #[serde(default)]
    dhcp: Vec<DhcpEntry>,
    #[serde(default)]
    dhcp6: Vec<crate::dhcp6::Dhcp6Entry>,
    #[serde(default)]
    ra: Vec<crate::ra::RaEntry>,
    #[serde(default)]
    source: Vec<SourceEntry>,
    #[serde(default)]
    pppoe: Vec<PppoeClientEntry>,
    #[serde(default)]
    dhcp_client: Vec<crate::dhcp_client::DhcpClientEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct PppoeClientEntry {
    source: String,
    user: String,
    password: String,
    service: Option<String>,
    ac_name: Option<String>,
    ipv6: Option<bool>,
    echo_interval: Option<u32>,
    echo_failures: Option<u32>,
    default_route: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SourceEntry {
    name: String,
    kind: String,
    sync_wait: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct DhcpEntry {
    interface: String,
    pool: String,
    lease_time: Option<u32>,
    router: Option<Vec<String>>,
    dns: Option<Vec<String>>,
    punt_rate: Option<u32>,
    punt_burst: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsEntry {
    #[serde(default)]
    upstream: Vec<String>,
    listen: Option<Vec<String>>,
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
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct InterfaceEntry {
    name: String,
    mac: Option<String>,
    parent: Option<String>,
    vlan: Option<u16>,
    mtu: Option<u16>,
    enabled: Option<bool>,
    ipv4: Option<String>,
    ipv4_from: Option<String>,
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
    source: String,
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
            (None, None, None, Some(_)) if entry.ipv4.is_some() => {
                return Err(format!(
                    "{at}: a PPPoE session's ipv4 address comes from its source; give none"
                ))
            }
            (None, None, None, Some(pppoe)) => Kind::Pppoe {
                parent: pppoe.parent,
                source: pppoe.source,
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
        if entry.ipv4_from.is_some() {
            if entry.ipv4.is_some() {
                return Err(format!("{at}: give ipv4 or ipv4-from, not both"));
            }
            if !matches!(kind, Kind::Port | Kind::Vlan { .. }) {
                return Err(format!("{at}: only a port or VLAN takes ipv4-from"));
            }
        }
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
            ipv4_from: entry.ipv4_from.into_iter().collect(),
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
    let dns = file
        .dns
        .map(|entry| dns(entry, &interfaces, nat.as_ref(), map_e.as_ref()))
        .transpose()?;
    let dhcp = file
        .dhcp
        .into_iter()
        .map(|entry| dhcp(entry, &interfaces, dns.as_ref()))
        .collect::<Result<_, _>>()?;
    let dhcp6 = file
        .dhcp6
        .into_iter()
        .map(|entry| crate::dhcp6::resolve(entry, &interfaces, dns.as_ref()))
        .collect::<Result<_, _>>()?;
    let ra = file
        .ra
        .into_iter()
        .map(|entry| crate::ra::resolve(entry, &interfaces, dns.as_ref()))
        .collect::<Result<_, _>>()?;
    let source = file
        .source
        .into_iter()
        .map(|entry| {
            let wait = SOURCE_KINDS
                .iter()
                .find(|(kind, _)| *kind == entry.kind)
                .map(|&(_, wait)| wait)
                .ok_or_else(|| {
                    format!(
                        "source {:?}: kind {:?} is not one of {:?}",
                        entry.name,
                        entry.kind,
                        SOURCE_KINDS.iter().map(|(k, _)| *k).collect::<Vec<_>>()
                    )
                })?;
            Ok(Source {
                name: entry.name,
                kind: entry.kind,
                sync_wait: entry.sync_wait.unwrap_or(wait),
            })
        })
        .collect::<Result<_, String>>()?;
    let pppoe = file
        .pppoe
        .into_iter()
        .map(|entry| pppoe(entry, &interfaces))
        .collect::<Result<_, _>>()?;
    let dhcp_client = file
        .dhcp_client
        .into_iter()
        .map(|entry| crate::dhcp_client::resolve(entry, &interfaces))
        .collect::<Result<_, _>>()?;
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
        dns: dns.into_iter().collect(),
        dhcp,
        dhcp6,
        ra,
        source,
        pppoe,
        dhcp_client,
    })
}

/// `[[pppoe]]`: where the session of its source runs, from the interface that
/// names the source.
fn pppoe(entry: PppoeClientEntry, interfaces: &[Interface]) -> Result<Pppoe, String> {
    let at = format!("pppoe {:?}", entry.source);
    let (interface, parent) = interfaces
        .iter()
        .find_map(|i| match &i.kind {
            Kind::Pppoe { parent, source } if *source == entry.source => Some((i, parent)),
            _ => None,
        })
        .ok_or_else(|| format!("{at}: no PPPoE interface names this source"))?;
    Ok(Pppoe {
        source: entry.source,
        interface: interface.name.clone(),
        vrf: interface.vrf.clone(),
        parent: parent.clone(),
        mac: interface.mac.clone(),
        user: entry.user,
        password: entry.password,
        service: entry.service.unwrap_or_default(),
        ac_name: entry.ac_name.into_iter().collect(),
        ipv6: entry.ipv6.unwrap_or(true),
        echo_interval: entry.echo_interval.unwrap_or(PPPOE_ECHO_INTERVAL),
        echo_failures: entry.echo_failures.unwrap_or(PPPOE_ECHO_FAILURES),
        default_route: entry.default_route.unwrap_or(false),
    })
}

/// `[[dhcp]]`: the interface's MAC and IPv4 address, and the options' defaults.
fn dhcp(entry: DhcpEntry, interfaces: &[Interface], dns: Option<&Dns>) -> Result<Dhcp, String> {
    let at = format!("dhcp {:?}", entry.interface);
    let interface = interfaces
        .iter()
        .find(|i| i.name == entry.interface)
        .ok_or_else(|| format!("{at}: no such interface"))?;
    let address = interface
        .ipv4
        .first()
        .ok_or_else(|| format!("{at}: the interface has no ipv4 address"))?;
    let own = address
        .split_once('/')
        .map_or(address.as_str(), |(address, _)| address)
        .to_owned();
    let listened = dns.is_some_and(|dns| dns.listen.contains(&own));
    Ok(Dhcp {
        interface: entry.interface,
        mac: interface.mac.clone(),
        address: address.clone(),
        pool: entry.pool,
        lease_time: entry.lease_time.unwrap_or(DHCP_LEASE_TIME),
        router: entry.router.unwrap_or_else(|| vec![own.clone()]),
        dns: entry
            .dns
            .unwrap_or_else(|| if listened { vec![own] } else { Vec::new() }),
        punt_rate: entry.punt_rate.unwrap_or(DHCP_PUNT_RATE),
        punt_burst: entry.punt_burst.unwrap_or(DHCP_PUNT_BURST),
    })
}

/// `[dns]`: the addresses and prefixes of the interfaces it listens on.
fn dns(
    entry: DnsEntry,
    interfaces: &[Interface],
    nat: Option<&Nat>,
    map_e: Option<&MapE>,
) -> Result<Dns, String> {
    let names = match entry.listen {
        Some(names) => names,
        None => {
            let inside: Vec<String> = nat
                .map(|nat| nat.inside.clone())
                .into_iter()
                .chain(map_e.map(|map_e| map_e.inside.clone()))
                .collect();
            if inside.is_empty() {
                return Err(
                    "dns: give listen; there is no [nat] or [map-e] inside to answer on".into(),
                );
            }
            inside
        }
    };
    let mut listen = Vec::new();
    let mut allow = Vec::new();
    for name in &names {
        let at = format!("dns: listen {name:?}");
        let interface = interfaces
            .iter()
            .find(|i| i.name == *name)
            .ok_or_else(|| format!("{at}: no such interface"))?;
        if interface.vrf != DEFAULT_VRF {
            return Err(format!("{at}: the interface must be in the default VRF"));
        }
        let before = listen.len();
        for text in interface.ipv4.iter().chain(&interface.ipv6) {
            let (address, network) = address_and_network(text)
                .ok_or_else(|| format!("{at}: {text:?} is not an address and prefix length"))?;
            if matches!(address, IpAddr::V6(a) if a.is_unicast_link_local()) {
                continue;
            }
            listen.push(address.to_string());
            if !allow.contains(&network) {
                allow.push(network);
            }
        }
        if listen.len() == before {
            return Err(format!("{at}: the interface has no address to answer on"));
        }
    }
    Ok(Dns {
        listen,
        allow,
        upstream: entry.upstream,
        upstream_from: Vec::new(),
    })
}

/// `address/len` as the address and its network as `network/len`.
fn address_and_network(text: &str) -> Option<(IpAddr, String)> {
    let (address, len) = text.split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let network = match address {
        IpAddr::V4(a) if len <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            IpAddr::from(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) if len <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            IpAddr::from(std::net::Ipv6Addr::from(u128::from(a) & mask))
        }
        _ => return None,
    };
    Some((address, format!("{network}/{len}")))
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

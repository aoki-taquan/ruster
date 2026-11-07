//! The configuration file, in TOML.
//!
//! ```toml
//! [[interface]]
//! name = "lan"                 # the FE port (the Linux device name)
//! mac = "02:00:00:00:00:01"
//! mtu = 1500                   # optional, 1500 when left out
//! enabled = true               # optional, true when left out
//! ipv4 = "192.0.2.1/24"        # optional
//! ipv6 = ["2001:db8:1::1/64"]  # optional; a link-local address is added by itself
//! vrf = "red"                  # optional, "default" when left out
//!
//! [[interface]]                # a VLAN sub-interface of lan, after lan
//! name = "lan.10"
//! parent = "lan"
//! vlan = 10                    # 1 to 4094; mac is lan's when left out
//! ipv4 = "10.10.0.1/24"
//!
//! [[interface]]                # an IPv4 in IPv6 tunnel (DS-Lite softwire)
//! name = "dslite"
//! tunnel = { local = "2001:db8:1::2", remote = "2001:db8:ff::1" }
//! ipv4 = "192.0.0.2/29"        # optional; RFC 6333 5.7's B4 address
//! # mtu is 1460 when left out; mac is not needed
//!
//! [[route]]
//! prefix = "0.0.0.0/0"         # or an IPv6 prefix such as "::/0"
//! interface = "wan"
//! via = "198.51.100.1"         # optional; left out for an on-link route
//! vrf = "default"              # optional; the interface may be in another VRF
//!
//! [[route]]                    # look the destination up again in another VRF
//! vrf = "red"
//! prefix = "0.0.0.0/0"
//! lookup-vrf = "default"
//!
//! [[firewall]]                 # forward rules of the default VRF, first match wins
//! action = "accept"            # or "drop"; an accepted flow's replies pass too
//! protocol = "udp"             # "tcp", "udp" or "icmp"
//! ingress = "lan"              # optional, any interface when left out
//! egress = "wan"               # optional
//! source = "192.0.2.0/24"      # optional, any address when left out
//! destination = "0.0.0.0/0"    # optional
//! source-ports = "1024-65535"  # optional, tcp and udp only; any when left out
//! destination-ports = "53"     # optional
//!
//! [nat]                        # NAPT of the default VRF
//! inside = "lan"
//! outside = "wan"              # must have an ipv4 address: the public one
//! ports = "1024-32767"         # optional, 1024-32767 when left out
//! external = "198.51.100.2"    # optional; for now only the outside's own address
//! ```
//!
//! The NAT pool must not overlap the ports the router's kernel picks for its own
//! connections (`net.ipv4.ip_local_port_range`, 32768-60999 by default): UDP and TCP
//! to the public address on a port outside the pool are the router's own, and those
//! in it are NAT's (so is a router service listening on a port in the pool). NAT is
//! inactive while `inside` or `outside` is disabled.
//!
//! With any `firewall` rule, what no rule accepts is dropped. The interfaces a rule
//! or `nat` names must be in the default VRF.
//!
//! An address, and the prefix of an interface address, must be unique within a VRF;
//! two VRFs may use the same ones. A static route for an interface's prefix replaces
//! the connected route. A `lookup-vrf` must name a VRF that an interface or a route is
//! in, and that VRF's own `lookup-vrf` routes are not followed, so they are refused.
//!
//! # Standards
//!
//! - RFC 8529 (`ietf-network-instance`): an interface belongs to one VRF, `default`
//!   when not named.
//! - RFC 791: the smallest MTU is 68.
//! - RFC 6333 section 5 (DS-Lite B4): a `tunnel` interface sends IPv4 inside IPv6
//!   from `local`, which must be one of the router's IPv6 addresses in the default
//!   VRF, to the AFTR at `remote`; the outer packets are routed in the default VRF.
//!   Its MTU is at most 1460 (1500 less the IPv6 header), so the outer packets are
//!   never fragmented (RFC 6333 5.3 lets the B4 fragment them instead).
//! - RFC 919 and RFC 922: an IPv4 interface address in a prefix of /30 or shorter is
//!   not the network or broadcast address of the prefix (RFC 3021 /31 is allowed).
//! - RFC 6890 and RFC 1122 section 3.2.1.3: IPv4 interface addresses and next hops
//!   must be usable unicast addresses (not 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4 or
//!   240.0.0.0/4).
//! - RFC 4291 section 2.5: IPv6 interface addresses and next hops must not be
//!   unspecified, loopback or multicast. A link-local next hop is allowed: it is on
//!   the route's interface.
//! - RFC 8519 (`ietf-access-control-list`): a `firewall` rule is an ACE with IPv4,
//!   protocol, port range and interface matches, checked in order, first match wins.
//!   Deviations: IPv4 only (while there are rules, the FE does not forward IPv6
//!   through the default VRF); an accepted flow's replies pass too (stateful, not in
//!   RFC 8519); what no rule accepts is dropped; one rule list for the default VRF,
//!   not ACLs attached per interface.
//! - RFC 4787, RFC 5382 and RFC 5508: `nat` is NAPT for UDP, TCP and ICMP queries
//!   with core's behaviour (endpoint-independent mapping, address-dependent
//!   filtering); see `ruster_core`'s NAT modules for its deviations. One inside and
//!   one outside interface, and the outside interface's address as the public one.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use ruster_proto::table::{FirewallAction, FirewallRule, Nat, NatPorts, Protocol, DEFAULT_VRF};

use crate::{Config, InterfaceConfig, RouteTarget, StaticRoute};

/// The smallest MTU an IPv4 interface may have (RFC 791).
const MIN_MTU: u16 = ruster_proto::table::MIN_MTU;
/// The FE takes Ethernet frames of up to 1514 bytes.
const MAX_MTU: u16 = 1_500;
/// The MAC address of a tunnel that names none.
const TUNNEL_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xfe];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    interface: Vec<InterfaceEntry>,
    #[serde(default)]
    route: Vec<RouteEntry>,
    #[serde(default)]
    firewall: Vec<FirewallEntry>,
    nat: Option<NatEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NatEntry {
    inside: String,
    outside: String,
    ports: Option<String>,
    external: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
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
    /// Optional for a VLAN sub-interface, which then has its parent's.
    mac: Option<String>,
    parent: Option<String>,
    vlan: Option<u16>,
    /// 1500 when left out; for a sub-interface, its parent's less the 4-byte tag.
    mtu: Option<u16>,
    #[serde(default = "default_enabled")]
    enabled: bool,
    ipv4: Option<String>,
    #[serde(default)]
    ipv6: Vec<String>,
    #[serde(default = "default_vrf")]
    vrf: String,
    tunnel: Option<TunnelEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelEntry {
    local: String,
    remote: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
struct RouteEntry {
    #[serde(default = "default_vrf")]
    vrf: String,
    prefix: String,
    interface: Option<String>,
    via: Option<String>,
    lookup_vrf: Option<String>,
}

fn default_vrf() -> String {
    DEFAULT_VRF.to_owned()
}

fn default_mtu() -> u16 {
    1_500
}

fn default_enabled() -> bool {
    true
}

/// What the interfaces of a file have, to check addresses and routes against.
#[derive(Default)]
struct Seen {
    names: BTreeSet<String>,
    /// Each interface's VRF.
    vrf_of: BTreeMap<String, String>,
    /// The router's addresses other than link-local ones, per VRF.
    addresses: BTreeSet<(String, IpAddr)>,
    /// Link-local addresses belong to one link: kept per interface, the automatic one
    /// included.
    link_local: BTreeSet<(String, Ipv6Addr)>,
    /// Connected prefixes (link-local ones are on every interface and not counted).
    connected: BTreeSet<(String, IpAddr, u8)>,
}

impl Seen {
    fn address(
        &mut self,
        at: &str,
        interface: &str,
        address: IpAddr,
        len: u8,
    ) -> Result<(), String> {
        if let IpAddr::V6(a) = address {
            if a.is_unicast_link_local() {
                // The automatic link-local address may be given again; that is the same entry.
                self.link_local.insert((interface.to_owned(), a));
                return Ok(());
            }
        }
        let vrf = self.vrf_of.get(interface).cloned().unwrap_or_default();
        if !self.addresses.insert((vrf.clone(), address)) {
            return Err(format!("{at}: {address} is given twice in VRF {vrf:?}"));
        }
        if !self
            .connected
            .insert((vrf.clone(), network(address, len), len))
        {
            return Err(format!(
                "{at}: the prefix of {address} is already on an interface of VRF {vrf:?}"
            ));
        }
        Ok(())
    }

    /// Whether `via` is one of the router's own addresses, for a route out of `interface`.
    fn is_ours(&self, interface: &str, via: IpAddr) -> bool {
        match via {
            IpAddr::V6(v) if v.is_unicast_link_local() => {
                self.link_local.contains(&(interface.to_owned(), v))
            }
            _ => {
                let vrf = self.vrf_of.get(interface).cloned().unwrap_or_default();
                self.addresses.contains(&(vrf, via))
            }
        }
    }
}

/// Reads a configuration from the text of a configuration file.
pub fn parse(text: &str) -> Result<Config, String> {
    let file: File = toml::from_str(text).map_err(|error| error.to_string())?;
    let mut seen = Seen::default();
    let mut interfaces = Vec::with_capacity(file.interface.len());
    for entry in file.interface {
        let at = format!("interface {:?}", entry.name);
        if entry.name.is_empty() || entry.name.len() > 255 {
            return Err(format!("{at}: the name must be 1 to 255 bytes"));
        }
        if !seen.names.insert(entry.name.clone()) {
            return Err(format!("{at}: given twice"));
        }
        if entry.vrf.is_empty() {
            return Err(format!("{at}: vrf must not be empty"));
        }
        seen.vrf_of.insert(entry.name.clone(), entry.vrf.clone());
        let vlan = match (&entry.parent, entry.vlan) {
            (Some(parent), Some(id)) => {
                if !(1..=4094).contains(&id) {
                    return Err(format!("{at}: vlan must be 1 to 4094"));
                }
                let Some(parent_entry) = interfaces.iter().find(|i: &&InterfaceConfig| {
                    i.name == *parent && i.vlan.is_none() && i.tunnel.is_none()
                }) else {
                    return Err(format!(
                        "{at}: parent {parent:?} must be an interface given before it, not a VLAN"
                    ));
                };
                let taken = interfaces
                    .iter()
                    .any(|i| i.vlan.as_ref() == Some(&(parent.clone(), id)));
                if taken {
                    return Err(format!("{at}: vlan {id} on {parent:?} is given twice"));
                }
                Some((parent.clone(), id, parent_entry.mac))
            }
            (None, None) => None,
            _ => return Err(format!("{at}: give parent and vlan together")),
        };
        let tunnel = match &entry.tunnel {
            None => None,
            Some(_) if vlan.is_some() => {
                return Err(format!(
                    "{at}: an interface is a VLAN or a tunnel, not both"
                ))
            }
            Some(_) if !entry.ipv6.is_empty() => {
                return Err(format!("{at}: a tunnel carries IPv4 only; give it no ipv6"))
            }
            Some(tunnel) => {
                let address = |text: &str, what: &str| -> Result<Ipv6Addr, String> {
                    let address: Ipv6Addr = text
                        .parse()
                        .map_err(|_| format!("{at}: tunnel {what} must be an IPv6 address"))?;
                    if !unicast_v6(address) || address.is_unicast_link_local() {
                        return Err(format!(
                            "{at}: tunnel {what} must be a global unicast address"
                        ));
                    }
                    Ok(address)
                };
                Some((
                    address(&tunnel.local, "local")?,
                    address(&tunnel.remote, "remote")?,
                ))
            }
        };
        let mac = match (&entry.mac, &vlan) {
            (Some(text), _) => {
                mac(text).ok_or_else(|| format!("{at}: mac is not like 02:00:00:00:00:01"))?
            }
            (None, Some((_, _, parent_mac))) => *parent_mac,
            // A tunnel has no link; its MAC address only names it inside the FE.
            (None, None) if tunnel.is_some() => TUNNEL_MAC,
            (None, None) => return Err(format!("{at}: mac is missing")),
        };
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(format!("{at}: mac must be a unicast address"));
        }
        // A sub-interface's frames carry a 4-byte tag on its parent's link.
        let max_mtu = vlan
            .as_ref()
            .and_then(|(parent, _, _)| interfaces.iter().find(|i| i.name == *parent))
            .map_or(MAX_MTU, |parent| parent.mtu - 4);
        // A tunnel's packets carry a 40-byte IPv6 header on the link below.
        let max_mtu = if tunnel.is_some() {
            MAX_MTU - 40
        } else {
            max_mtu
        };
        let mtu = match (entry.mtu, &vlan) {
            (Some(mtu), _) => mtu,
            (None, Some(_)) => max_mtu,
            (None, None) if tunnel.is_some() => max_mtu,
            (None, None) => default_mtu(),
        };
        if !(MIN_MTU..=max_mtu).contains(&mtu) {
            return Err(format!("{at}: mtu must be {MIN_MTU} to {max_mtu}"));
        }
        let ipv4 = match &entry.ipv4 {
            Some(text) => {
                let Some((IpAddr::V4(address), len)) = prefix(text) else {
                    return Err(format!("{at}: ipv4 is not like 192.0.2.1/24"));
                };
                if len == 0 {
                    return Err(format!("{at}: ipv4 needs a prefix length of 1 to 32"));
                }
                if !unicast_v4(address) {
                    return Err(format!("{at}: ipv4 must be a unicast address"));
                }
                // RFC 922 and RFC 919: in a prefix of /30 or shorter, the all-zeros
                // and all-ones host numbers are the network and its broadcast.
                let mask = u32::MAX.checked_shr(u32::from(len)).unwrap_or(0);
                let host = u32::from(address) & mask;
                if len <= 30 && (host == 0 || host == mask) {
                    return Err(format!(
                        "{at}: ipv4 must not be the network or broadcast address of its prefix"
                    ));
                }
                seen.address(&at, &entry.name, address.into(), len)?;
                Some((address, len))
            }
            None => None,
        };
        let mut ipv6 = Vec::with_capacity(entry.ipv6.len());
        for text in &entry.ipv6 {
            let Some((IpAddr::V6(address), len)) = prefix(text) else {
                return Err(format!("{at}: ipv6 {text:?} is not like 2001:db8::1/64"));
            };
            if len == 0 {
                return Err(format!(
                    "{at}: ipv6 {text:?} needs a prefix length of 1 to 128"
                ));
            }
            if !unicast_v6(address) {
                return Err(format!("{at}: ipv6 {text:?} must be a unicast address"));
            }
            seen.address(&at, &entry.name, address.into(), len)?;
            ipv6.push((address, len));
        }
        seen.link_local
            .insert((entry.name.clone(), crate::link_local(mac)));
        interfaces.push(InterfaceConfig {
            name: entry.name,
            mac,
            mtu,
            enabled: entry.enabled,
            ipv4,
            ipv6,
            vrf: entry.vrf,
            vlan: vlan.map(|(parent, id, _)| (parent, id)),
            tunnel,
        });
    }
    // A tunnel is sent from one of the router's own addresses, in the default VRF.
    let mut pairs = BTreeSet::new();
    for interface in &interfaces {
        let Some((local, remote)) = interface.tunnel else {
            continue;
        };
        let at = format!("interface {:?}", interface.name);
        let owner = interfaces.iter().find(|i| {
            i.tunnel.is_none() && i.vrf == DEFAULT_VRF && i.ipv6.iter().any(|&(a, _)| a == local)
        });
        let Some(owner) = owner else {
            return Err(format!(
                "{at}: tunnel local {local} must be an IPv6 address of an interface in the default VRF"
            ));
        };
        // Its packets carry a 40-byte IPv6 header on the owner's link.
        if interface.mtu > owner.mtu.saturating_sub(40) {
            return Err(format!(
                "{at}: mtu must be at most {} ({:?}'s less the IPv6 header)",
                owner.mtu.saturating_sub(40),
                owner.name
            ));
        }
        if !pairs.insert((local, remote)) {
            return Err(format!(
                "{at}: another tunnel has the same local and remote"
            ));
        }
    }
    let mut static_routes = Vec::with_capacity(file.route.len());
    let mut prefixes = BTreeSet::new();
    for entry in file.route {
        let at = format!("route {:?}", entry.prefix);
        let (address, len) = prefix(&entry.prefix)
            .ok_or_else(|| format!("{at}: prefix is not like 10.0.0.0/8 or 2001:db8::/32"))?;
        if network(address, len) != address {
            return Err(format!("{at}: bits are set after the prefix length"));
        }
        if entry.vrf.is_empty() {
            return Err(format!("{at}: vrf must not be empty"));
        }
        if !prefixes.insert((entry.vrf.clone(), address, len)) {
            return Err(format!("{at}: given twice in VRF {:?}", entry.vrf));
        }
        let interface = match (entry.interface, entry.lookup_vrf) {
            (None, Some(other)) => {
                if other.is_empty() || other == entry.vrf {
                    return Err(format!("{at}: lookup-vrf must name another VRF"));
                }
                if entry.via.is_some() {
                    return Err(format!("{at}: a lookup-vrf route has no via"));
                }
                static_routes.push(StaticRoute {
                    vrf: entry.vrf,
                    prefix: address,
                    len,
                    target: RouteTarget::LookupVrf(other),
                });
                continue;
            }
            (Some(interface), None) => interface,
            _ => return Err(format!("{at}: give either interface or lookup-vrf")),
        };
        if !seen.names.contains(&interface) {
            return Err(format!("{at}: no interface {interface:?}"));
        }
        let tunnel = interfaces
            .iter()
            .any(|i| i.name == interface && i.tunnel.is_some());
        if tunnel && address.is_ipv6() {
            return Err(format!("{at}: tunnel {interface:?} carries IPv4 only"));
        }
        let via = match &entry.via {
            Some(text) => {
                let via = text
                    .parse::<IpAddr>()
                    .ok()
                    .filter(|via| via.is_ipv4() == address.is_ipv4())
                    .filter(|via| match via {
                        IpAddr::V4(v) => unicast_v4(*v),
                        IpAddr::V6(v) => unicast_v6(*v),
                    })
                    .filter(|via| !seen.is_ours(&interface, *via));
                Some(via.ok_or_else(|| {
                    format!("{at}: via must be a unicast address of another host, of the prefix's family")
                })?)
            }
            None => None,
        };
        static_routes.push(StaticRoute {
            vrf: entry.vrf,
            prefix: address,
            len,
            target: RouteTarget::Next { interface, via },
        });
    }
    // A lookup must reach a VRF that exists, and is followed one level only.
    let defined: BTreeSet<&str> = seen
        .vrf_of
        .values()
        .map(String::as_str)
        .chain(static_routes.iter().map(|r| r.vrf.as_str()))
        .collect();
    for route in &static_routes {
        let RouteTarget::LookupVrf(other) = &route.target else {
            continue;
        };
        let at = format!(
            "route {}/{} in VRF {:?}",
            route.prefix, route.len, route.vrf
        );
        if !defined.contains(other.as_str()) {
            return Err(format!("{at}: no interface or route is in VRF {other:?}"));
        }
        let chained = static_routes
            .iter()
            .any(|r| r.vrf == *other && matches!(r.target, RouteTarget::LookupVrf(_)));
        if chained {
            return Err(format!(
                "{at}: VRF {other:?} has lookup-vrf routes of its own, which are not followed"
            ));
        }
    }
    let firewall = file
        .firewall
        .into_iter()
        .enumerate()
        .map(|(at, entry)| firewall_rule(&format!("firewall rule {}", at + 1), entry, &seen))
        .collect::<Result<_, _>>()?;
    let nat = file
        .nat
        .map(|entry| nat(entry, &seen, &interfaces))
        .transpose()?;
    Ok(Config {
        interfaces,
        static_routes,
        firewall,
        nat,
    })
}

/// `"53"` or `"1024-65535"`.
fn port_range(text: &str) -> Option<(u16, u16)> {
    let (first, last) = text.split_once('-').unwrap_or((text, text));
    let port = |text: &str| {
        let text = text.trim();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse::<u16>().ok()
    };
    match (port(first)?, port(last)?) {
        (first, last) if first <= last => Some((first, last)),
        _ => None,
    }
}

fn nat(entry: NatEntry, seen: &Seen, interfaces: &[InterfaceConfig]) -> Result<Nat, String> {
    let at = "nat";
    for name in [&entry.inside, &entry.outside] {
        match seen.vrf_of.get(name) {
            None => return Err(format!("{at}: no interface {name:?}")),
            Some(vrf) if vrf != DEFAULT_VRF => {
                return Err(format!(
                    "{at}: interface {name:?} is in VRF {vrf:?}; NAT is for the default VRF"
                ))
            }
            Some(_) => {}
        }
    }
    if entry.inside == entry.outside {
        return Err(format!(
            "{at}: inside and outside must be different interfaces"
        ));
    }
    let (first_port, last_port) = match &entry.ports {
        // Below Linux's default ephemeral ports (32768-60999), which the router's
        // own connections use: UDP and TCP to the public address outside the pool
        // are the router's.
        None => (1_024, 32_767),
        Some(text) => match port_range(text) {
            Some((first, last)) if first > 0 => (first, last),
            _ => {
                return Err(format!(
                    "{at}: ports must be a range such as 1024-65535, not 0"
                ))
            }
        },
    };
    let outside_address = interfaces
        .iter()
        .find(|i| i.name == entry.outside)
        .and_then(|i| i.ipv4)
        .map(|(address, _)| address);
    if outside_address.is_none() {
        return Err(format!("{at}: {:?} has no ipv4 address", entry.outside));
    }
    let external = match &entry.external {
        None => None,
        Some(text) => {
            let address: Ipv4Addr = text
                .parse()
                .map_err(|_| format!("{at}: external must be an IPv4 address"))?;
            if Some(address) != outside_address {
                return Err(format!(
                    "{at}: external must be the ipv4 address of {:?} for now",
                    entry.outside
                ));
            }
            Some(address)
        }
    };
    Ok(Nat {
        inside: entry.inside,
        outside: entry.outside,
        external,
        ports: NatPorts::Range {
            first: first_port,
            last: last_port,
        },
    })
}

fn firewall_rule(at: &str, entry: FirewallEntry, seen: &Seen) -> Result<FirewallRule, String> {
    let action = match entry.action.as_str() {
        "accept" => FirewallAction::Accept,
        "drop" => FirewallAction::Drop,
        _ => return Err(format!("{at}: action must be \"accept\" or \"drop\"")),
    };
    let protocol = match entry.protocol.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        _ => {
            return Err(format!(
                "{at}: protocol must be \"tcp\", \"udp\" or \"icmp\""
            ))
        }
    };
    for name in [&entry.ingress, &entry.egress].into_iter().flatten() {
        match seen.vrf_of.get(name) {
            None => return Err(format!("{at}: no interface {name:?}")),
            Some(vrf) if vrf != DEFAULT_VRF => {
                return Err(format!(
                    "{at}: interface {name:?} is in VRF {vrf:?}; rules are for the default VRF"
                ))
            }
            Some(_) => {}
        }
    }
    let ipv4 = |text: &Option<String>, what: &str| match text {
        None => Ok((Ipv4Addr::UNSPECIFIED, 0)),
        Some(text) => match prefix(text) {
            Some((IpAddr::V4(address), len))
                if network(IpAddr::V4(address), len) == IpAddr::V4(address) =>
            {
                Ok((address, len))
            }
            _ => Err(format!(
                "{at}: {what} must be an IPv4 prefix with no host bits"
            )),
        },
    };
    let ports = |text: &Option<String>, what: &str| {
        let Some(text) = text else {
            return Ok((0, u16::MAX));
        };
        if protocol == Protocol::Icmp {
            return Err(format!("{at}: {what} are for tcp and udp only"));
        }
        port_range(text)
            .ok_or_else(|| format!("{at}: {what} must be a port or a range such as 1024-65535"))
    };
    Ok(FirewallRule {
        source: ipv4(&entry.source, "source")?,
        destination: ipv4(&entry.destination, "destination")?,
        source_ports: ports(&entry.source_ports, "source-ports")?,
        destination_ports: ports(&entry.destination_ports, "destination-ports")?,
        ingress: entry.ingress,
        egress: entry.egress,
        protocol,
        action,
    })
}

fn mac(text: &str) -> Option<[u8; 6]> {
    let mut out = [0_u8; 6];
    let mut parts = text.split(':');
    for byte in &mut out {
        let part = parts.next()?;
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn prefix(text: &str) -> Option<(IpAddr, u8)> {
    let (address, len) = text.split_once('/')?;
    let canonical = !len.is_empty()
        && len.len() <= 3
        && len.bytes().all(|b| b.is_ascii_digit())
        && (len == "0" || !len.starts_with('0'));
    if !canonical {
        return None;
    }
    let len: u8 = len.parse().ok()?;
    let address: IpAddr = address.parse().ok()?;
    (len <= ruster_proto::table::max_len(&address)).then_some((address, len))
}

fn network(address: IpAddr, len: u8) -> IpAddr {
    ruster_proto::table::network(address, len)
}

/// An address a host can have: not unspecified, loopback, multicast, broadcast or
/// reserved (240.0.0.0/4).
fn unicast_v4(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    first != 0 && !address.is_loopback() && first < 224
}

fn unicast_v6(address: Ipv6Addr) -> bool {
    !address.is_unspecified() && !address.is_loopback() && !address.is_multicast()
}

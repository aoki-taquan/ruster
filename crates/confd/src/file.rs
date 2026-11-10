//! The configuration: checks the lock form ([`ruster_config::Lock`]) and turns it
//! into confd's [`Config`]. A `ruster.toml` is resolved to the lock form first; both
//! are described in [`ruster_config`], which also holds every default.
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
//! - RFC 8200 section 5: an interface with IPv6 addresses has an MTU of at least
//!   1280. Deviation: one with only its link-local address may have less.
//! - RFC 8529 (`ietf-network-instance`): an interface belongs to one VRF. A `lookup-vrf` route reaches the other VRF's hosts, not the
//!   router's own addresses in it: traffic from one VRF to the router's address in
//!   another is not delivered.
//! - RFC 791: the smallest MTU is 68.
//! - RFC 4291 sections 2.5.5 and 2.6.1, RFC 3879, RFC 6164: an interface's IPv6
//!   address is not IPv4-mapped, IPv4-compatible, site-local (fec0::/10) or its
//!   prefix's Subnet-Router anycast address (all zero after the prefix, except on a
//!   /127), and a link-local one is a /64.
//! - RFC 6333 section 5 (DS-Lite B4): a `tunnel` interface sends IPv4 inside IPv6
//!   from `local`, which must be one of the router's IPv6 addresses in the default
//!   VRF, to the AFTR at `remote`; the outer packets are routed in the default VRF.
//!   Its MTU is at most 1460 (1500 less the IPv6 header), and at run time at most
//!   what the link below carries less 40, so the outer packets are not fragmented
//!   (RFC 6333 5.3 lets the B4 fragment them instead). Section 5.7: the lock form
//!   gives the first such tunnel of a VRF with no IPv4 address the B4's, so that
//!   ICMP errors can be sent into it.
//! - RFC 7597 (MAP-E), the CE: `[map-e]` derives the shared IPv4 address and the
//!   PSID from the EA bits of the delegated prefix (section 5.2), the CE's IPv6
//!   address from them (section 6, interface ID `0:IPv4:PSID` on the delegated
//!   prefix with subnet ID 0), and makes a tunnel to the BR, NAPT on the PSID's
//!   port set (section 5.1), the default IPv4 route through the tunnel, and a
//!   discard route for the delegated prefix (RFC 7084 WPD-5). The router's own IPv4
//!   from its LAN address is translated into the port set like a LAN host's.
//!   Deviations: one Basic Mapping Rule, no Forwarding Mapping Rules (all traffic
//!   goes through the BR, hub and spoke); an `ea-length` shorter than the IPv4
//!   suffix (an IPv4 prefix per CE) is refused; the IPv4 address with no sharing
//!   (`ea-length` equal to the IPv4 suffix) uses `ports` of the lock form, below the
//!   kernel's; a delegated prefix that is a link's on-link prefix is refused (no one
//!   would answer Neighbor Discovery for the CE's address there); the
//!   interface ID is RFC 7597's, not the older draft's; the unwrapped IPv4
//!   destination is not checked against the CE's address (NAT drops what would go
//!   from the tunnel to the inside without a mapping; one routed elsewhere is
//!   forwarded).
//! - RFC 2516: a `pppoe` interface is one PPPoE session on its parent (a port or
//!   VLAN given before it); the session ID, the access concentrator's MAC and the
//!   IPv4 address come from its source (of kind pppoe, one interface each). Its MTU
//!   is at most the parent's less 8.
//! - RFC 2131: an interface with `ipv4-from` (a port or VLAN) has the IPv4 address
//!   its source, a DHCP client of kind dhcp-client (one interface each), leased.
//! - RFC 919 and RFC 922: an IPv4 interface address in a prefix of /30 or shorter is
//!   not the network or broadcast address of the prefix (RFC 3021 /31 is allowed).
//! - RFC 6890 and RFC 1122 section 3.2.1.3: IPv4 interface addresses and next hops
//!   must be usable unicast addresses (not 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4 or
//!   240.0.0.0/4).
//! - RFC 4291 section 2.5: IPv6 interface addresses and next hops must not be
//!   unspecified, loopback or multicast. A link-local next hop is allowed: it is on
//!   the route's interface.
//! - RFC 8519 (`ietf-access-control-list`): a `firewall` rule is an ACE with IPv4 or
//!   IPv6, protocol, port range and interface matches, checked in order, first match
//!   wins. Deviations: an accepted flow's replies, and ICMP errors about it, pass too
//!   (stateful, not in RFC 8519); what no rule accepts is dropped; one rule list for
//!   the default VRF, not ACLs attached per interface; a rule without addresses whose
//!   protocol has both families is two ACEs, one per family.
//! - RFC 4787, RFC 5382 and RFC 5508: `nat` is NAPT for UDP, TCP and ICMP queries
//!   with core's behaviour (endpoint-independent mapping; filtering as `filtering`
//!   names for UDP and TCP; endpoint-independent by default, which RFC 4787 REQ-8
//!   and RFC 5382 REQ-3 recommend where application transparency matters most);
//!   see `ruster_core`'s NAT modules for its deviations. One inside and
//!   one outside interface, and the outside interface's address as the public one.
//! - RFC 2131 section 4.1 and RFC 1542 section 4: a `dhcp` serves the clients of one
//!   port or VLAN of the default VRF through a relay agent whose address (giaddr) is
//!   the interface's IPv4 address, so the subnet is that address's prefix; the pool
//!   lies within the subnet's hosts and leaves out the router's address. RFC 2132:
//!   `router` is option 3, `dns` option 6, `lease-time` option 51. Deviations: one
//!   pool per interface; a lease is 60 s to 364 days.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ruster_config::{FirewallOutside, Kind, Lock, Target};
use ruster_proto::table::{
    FirewallAction, FirewallRule, Nat, NatFiltering, NatPorts, Protocol, DEFAULT_VRF,
};

use crate::{Config, InterfaceConfig, RouteTarget, StaticRoute};

/// The smallest MTU an IPv4 interface may have (RFC 791).
const MIN_MTU: u16 = ruster_proto::table::MIN_MTU;
/// The least MTU of a link that carries IPv6.
const IPV6_MIN_MTU: u16 = 1_280;
/// The FE takes Ethernet frames of up to 1514 bytes.
const MAX_MTU: u16 = 1_500;
/// The name rules give the router itself (the default VRF's kernel interface).
const ROUTER_INTERFACE: &str = "rt-default";

/// `filtering = "..."` of `nat`, `map-e` or the firewall.
fn filtering(at: &str, text: &str) -> Result<NatFiltering, String> {
    NatFiltering::from_name(&format!("{text}-filtering")).ok_or_else(|| {
        format!(
            "{at}: filtering must be \"endpoint-independent\", \"address-dependent\" or \"address-and-port-dependent\""
        )
    })
}

/// The one value of a list that holds none or one.
fn at_most_one<'a>(at: &str, what: &str, list: &'a [String]) -> Result<Option<&'a String>, String> {
    match list {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        _ => Err(format!("{at}: {what} takes at most one value")),
    }
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

/// Reads a configuration from the text of a configuration file: the lock form when
/// it has a top-level `version`, else a `ruster.toml`, which is resolved first.
pub fn parse(text: &str) -> Result<Config, String> {
    let lock = if ruster_config::is_lock(text)? {
        ruster_config::parse_lock(text)?
    } else {
        ruster_config::resolve(text)?
    };
    config(lock)
}

/// Checks the lock form and makes confd's configuration of it.
pub fn config(lock: Lock) -> Result<Config, String> {
    let sources = crate::source::specs(lock.source)?;
    let mut seen = Seen::default();
    let mut interfaces = Vec::with_capacity(lock.interface.len());
    for entry in lock.interface {
        let at = format!("interface {:?}", entry.name);
        if entry.name.is_empty() || entry.name.len() > 255 {
            return Err(format!("{at}: the name must be 1 to 255 bytes"));
        }
        if !seen.names.insert(entry.name.clone()) {
            return Err(format!("{at}: given twice"));
        }
        vrf_name(&at, &entry.vrf)?;
        seen.vrf_of.insert(entry.name.clone(), entry.vrf.clone());
        let mut vlan = None;
        let mut tunnel = None;
        let mut pppoe = None;
        match &entry.kind {
            Kind::Port => {}
            Kind::Vlan { parent, id } => {
                let id = *id;
                if !(1..=4094).contains(&id) {
                    return Err(format!("{at}: vlan must be 1 to 4094"));
                }
                let Some(parent_entry) = interfaces.iter().find(|i: &&InterfaceConfig| {
                    i.name == *parent && i.vlan.is_none() && i.tunnel.is_none() && i.pppoe.is_none()
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
                vlan = Some((parent.clone(), id, parent_entry.mtu));
            }
            Kind::Tunnel { .. } if !entry.ipv6.is_empty() => {
                return Err(format!("{at}: a tunnel carries IPv4 only; give it no ipv6"))
            }
            Kind::Tunnel { local, remote } => {
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
                tunnel = Some((address(local, "local")?, address(remote, "remote")?));
            }
            // A PPPoE session on a port or VLAN sub-interface given before it, from
            // a source of kind pppoe.
            Kind::Pppoe { parent, source } => {
                let Some(parent) = interfaces.iter().find(|i: &&InterfaceConfig| {
                    i.name == *parent && i.tunnel.is_none() && i.pppoe.is_none()
                }) else {
                    return Err(format!(
                        "{at}: PPPoE parent {parent:?} must be a port or VLAN given before it"
                    ));
                };
                if !sources
                    .iter()
                    .any(|s| s.name == *source && s.kind == crate::source::Kind::Pppoe)
                {
                    return Err(format!(
                        "{at}: PPPoE source {source:?} must be a source of kind pppoe"
                    ));
                }
                if interfaces
                    .iter()
                    .any(|i| i.pppoe.as_ref().is_some_and(|(_, s)| s == source))
                {
                    return Err(format!(
                        "{at}: source {source:?} is the session of another interface"
                    ));
                }
                if !entry.ipv4.is_empty() {
                    return Err(format!(
                        "{at}: a PPPoE session's ipv4 address comes from its source; give none"
                    ));
                }
                pppoe = Some((parent.name.clone(), source.clone(), parent.mtu));
            }
        }
        let mac =
            mac(&entry.mac).ok_or_else(|| format!("{at}: mac is not like 02:00:00:00:00:01"))?;
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(format!("{at}: mac must be a unicast address"));
        }
        // A sub-interface's frames carry a 4-byte tag on its parent's link, a
        // tunnel's packets a 40-byte IPv6 header on the link below, and a session's
        // 8 bytes of PPPoE header on the parent's link.
        let max_mtu = match (&vlan, &tunnel, &pppoe) {
            (Some((_, _, parent_mtu)), _, _) => parent_mtu - 4,
            (_, Some(_), _) => MAX_MTU - 40,
            (_, _, Some((_, _, parent_mtu))) => parent_mtu - 8,
            _ => MAX_MTU,
        };
        let mtu = entry.mtu;
        if !(MIN_MTU..=max_mtu).contains(&mtu) {
            return Err(format!("{at}: mtu must be {MIN_MTU} to {max_mtu}"));
        }
        let ipv4 = match at_most_one(&at, "ipv4", &entry.ipv4)? {
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
        let ipv4_from = match at_most_one(&at, "ipv4-from", &entry.ipv4_from)? {
            None => None,
            Some(_) if ipv4.is_some() => {
                return Err(format!("{at}: give ipv4 or ipv4-from, not both"))
            }
            Some(_) if tunnel.is_some() || pppoe.is_some() => {
                return Err(format!("{at}: only a port or VLAN takes ipv4-from"))
            }
            Some(source) => {
                if !sources
                    .iter()
                    .any(|s| s.name == *source && s.kind == crate::source::Kind::DhcpClient)
                {
                    return Err(format!(
                        "{at}: ipv4-from {source:?} must be a source of kind dhcp-client"
                    ));
                }
                if interfaces
                    .iter()
                    .any(|i: &InterfaceConfig| i.ipv4_from.as_ref() == Some(source))
                {
                    return Err(format!(
                        "{at}: source {source:?} gives the address of another interface"
                    ));
                }
                Some(source.clone())
            }
        };
        if !entry.ipv6.is_empty() && mtu < IPV6_MIN_MTU {
            return Err(format!(
                "{at}: mtu must be at least {IPV6_MIN_MTU} on an interface with ipv6 addresses"
            ));
        }
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
            if let Some(why) = unusable_interface_v6(address, len) {
                return Err(format!("{at}: ipv6 {text:?} {why}"));
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
            pppoe: pppoe.map(|(parent, source, _)| (parent, source)),
            ipv4_from,
        });
    }
    // A MAP-E CE's tunnel is an interface like the others for what follows.
    if lock.map_e.len() > 1 || lock.nat.len() > 1 {
        return Err("give at most one map-e and one nat".into());
    }
    let map_e = match lock.map_e.into_iter().next() {
        Some(entry) => {
            let (tunnel, mapped, delegated) = map_e(entry, &seen)?;
            let at = format!("map-e interface {:?}", tunnel.name);
            if tunnel.name.is_empty() || tunnel.name.len() > 255 {
                return Err(format!("{at}: the name must be 1 to 255 bytes"));
            }
            seen.names.insert(tunnel.name.clone());
            seen.vrf_of
                .insert(tunnel.name.clone(), DEFAULT_VRF.to_owned());
            let (address, len) = tunnel.ipv4.expect("a MAP-E tunnel has its IPv4 address");
            seen.address(&at, &tunnel.name, address.into(), len)?;
            let name = tunnel.name.clone();
            interfaces.push(tunnel);
            Some((name, mapped, delegated))
        }
        None => None,
    };
    // A tunnel is sent from one of the router's own addresses, in the default VRF
    // (a MAP-E CE's from its own address, which needs none).
    let mut pairs = BTreeSet::new();
    for interface in &interfaces {
        let Some((local, remote)) = interface.tunnel else {
            continue;
        };
        if map_e
            .as_ref()
            .is_some_and(|(name, _, _)| *name == interface.name)
        {
            // Sent from the CE's own address, which needs no owner; but no other
            // tunnel may have the same ends.
            if !pairs.insert((local, remote)) {
                return Err(format!(
                    "map-e interface {:?}: another tunnel has the same local and remote",
                    interface.name
                ));
            }
            // An address on an interface's own link would need answering there
            // (Neighbor Discovery), which nothing does for the CE's address.
            if let Some(on_link) = interfaces.iter().find(|i| {
                i.tunnel.is_none()
                    && i.ipv6.iter().any(|&(a, len)| {
                        network(IpAddr::V6(a), len) == network(IpAddr::V6(local), len)
                    })
            }) {
                return Err(format!(
                    "map-e: prefix gives the CE address {local}, which is on {:?}'s link; \
                     the delegated prefix must not be an on-link prefix",
                    on_link.name
                ));
            }
            continue;
        }
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
    let mut static_routes = Vec::with_capacity(lock.route.len());
    let mut prefixes = BTreeSet::new();
    for entry in lock.route {
        let at = format!("route {:?}", entry.prefix);
        let (address, len) = prefix(&entry.prefix)
            .ok_or_else(|| format!("{at}: prefix is not like 10.0.0.0/8 or 2001:db8::/32"))?;
        if network(address, len) != address {
            return Err(format!("{at}: bits are set after the prefix length"));
        }
        vrf_name(&at, &entry.vrf)?;
        if !prefixes.insert((entry.vrf.clone(), address, len)) {
            return Err(format!("{at}: given twice in VRF {:?}", entry.vrf));
        }
        let (interface, via) = match entry.target {
            Target::Discard | Target::Reject => {
                static_routes.push(StaticRoute {
                    vrf: entry.vrf,
                    prefix: address,
                    len,
                    target: if entry.target == Target::Discard {
                        RouteTarget::Discard
                    } else {
                        RouteTarget::Reject
                    },
                });
                continue;
            }
            Target::LookupVrf(other) => {
                if other.is_empty() || other == entry.vrf {
                    return Err(format!("{at}: lookup-vrf must name another VRF"));
                }
                static_routes.push(StaticRoute {
                    vrf: entry.vrf,
                    prefix: address,
                    len,
                    target: RouteTarget::LookupVrf(other),
                });
                continue;
            }
            Target::Forward { interface, via } => {
                let via = at_most_one(&at, "via", &via)?.cloned();
                (interface, via)
            }
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
        let via = match &via {
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
    let firewall_filtering = filtering("firewall-filtering", &lock.firewall_filtering)?;
    let firewall_outside = match lock.firewall_outside {
        FirewallOutside::Derive => None,
        FirewallOutside::Interfaces(names) => Some(names),
    };
    if let Some(outside) = &firewall_outside {
        for name in outside {
            match seen.vrf_of.get(name) {
                None => return Err(format!("firewall-outside: no interface {name:?}")),
                Some(vrf) if vrf != DEFAULT_VRF => {
                    return Err(format!(
                        "firewall-outside: interface {name:?} is in VRF {vrf:?}; the firewall is the default VRF's"
                    ))
                }
                Some(_) => {}
            }
        }
    }
    let firewall = lock
        .firewall
        .into_iter()
        .enumerate()
        .map(|(at, entry)| firewall_rule(&format!("firewall rule {}", at + 1), entry, &seen))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    let mut nat = lock
        .nat
        .into_iter()
        .next()
        .map(|entry| nat(entry, &seen, &interfaces))
        .transpose()?;
    if let Some((tunnel, mapped, (delegated, delegated_len))) = map_e {
        if nat.is_some() {
            return Err("map-e: it makes the NAT itself; give no [nat]".into());
        }
        if static_routes.iter().any(|r| {
            r.vrf == DEFAULT_VRF && r.prefix == IpAddr::V4(Ipv4Addr::UNSPECIFIED) && r.len == 0
        }) {
            return Err("map-e: it makes the default IPv4 route itself; give none".into());
        }
        static_routes.push(StaticRoute {
            vrf: DEFAULT_VRF.to_owned(),
            prefix: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            len: 0,
            target: RouteTarget::Next {
                interface: tunnel,
                via: None,
            },
        });
        nat = Some(mapped);
        // What of the delegated prefix no more specific route holds is dropped, not sent
        // back upstream (RFC 7084 WPD-5).
        if !static_routes.iter().any(|r| {
            r.vrf == DEFAULT_VRF && r.prefix == IpAddr::V6(delegated) && r.len == delegated_len
        }) {
            static_routes.push(StaticRoute {
                vrf: DEFAULT_VRF.to_owned(),
                prefix: IpAddr::V6(delegated),
                len: delegated_len,
                target: RouteTarget::Discard,
            });
        }
    }
    let icmp_errors = {
        let at = "icmp-errors";
        let ruster_config::IcmpErrors {
            ipv4_interval_ms: ipv4,
            ipv6_burst: burst,
            ipv6_interval_ms: ipv6,
        } = lock.icmp_errors;
        if !(1..=60_000).contains(&ipv4) || !(1..=60_000).contains(&ipv6) {
            return Err(format!("{at}: intervals must be 1 to 60000 ms"));
        }
        if !(1..=10_000).contains(&burst) {
            return Err(format!("{at}: ipv6-burst must be 1 to 10000"));
        }
        Some((ipv4, burst, ipv6))
    };
    if lock.dns.len() > 1 {
        return Err("give at most one dns".into());
    }
    let dns = lock
        .dns
        .into_iter()
        .next()
        .map(|entry| dns(entry, &seen))
        .transpose()?;
    // Each is a punt class of the FE, which holds 64 besides its own.
    if lock.dhcp.len() > DHCP_MAX {
        return Err(format!("give at most {DHCP_MAX} dhcp"));
    }
    let mut dhcp = Vec::with_capacity(lock.dhcp.len());
    for entry in lock.dhcp {
        if dhcp
            .iter()
            .any(|d: &ruster_config::Dhcp| d.interface == entry.interface)
        {
            return Err(format!("dhcp {:?}: given twice", entry.interface));
        }
        let entry = dhcp_entry(entry, &interfaces)?;
        // Kea knows a subnet by its address; two subnets of which one holds the
        // other would share it, and the relay addresses could pick either.
        let subnet =
            |d: &ruster_config::Dhcp| prefix(&d.address).map(|(a, len)| (network(a, len), len));
        if let Some((IpAddr::V4(a), len)) = subnet(&entry) {
            let holds = |b: Ipv4Addr, l: u8| {
                let shorter = len.min(l);
                let mask = u32::MAX.checked_shl(32 - u32::from(shorter)).unwrap_or(0);
                u32::from(a) & mask == u32::from(b) & mask
            };
            let other = dhcp.iter().find(|d: &&ruster_config::Dhcp| {
                matches!(subnet(d), Some((IpAddr::V4(b), l)) if holds(b, l))
            });
            if let Some(other) = other {
                return Err(format!(
                    "dhcp {:?}: its subnet overlaps that of dhcp {:?}",
                    entry.interface, other.interface
                ));
            }
        }
        dhcp.push(entry);
    }
    let dhcp6 = crate::dhcp6::check(lock.dhcp6, &interfaces)?;
    let ra = crate::ra::check(lock.ra, &interfaces)?;
    let pppoe = crate::pppoe::check(lock.pppoe, &interfaces, &sources)?;
    let bgp = crate::bgp::check(lock.bgp, &interfaces)?;
    // The FE takes at most this many punt classes besides its own.
    if dhcp.len() + dhcp6.len() + crate::pppoe::class_count(&pppoe) > PUNT_CLASSES_MAX {
        return Err(format!(
            "dhcp, dhcp6 and the parents of pppoe take more than {PUNT_CLASSES_MAX} punt \
             classes (one per dhcp and dhcp6, two per parent)"
        ));
    }
    Ok(Config {
        interfaces,
        static_routes,
        firewall,
        firewall_filtering,
        firewall_outside,
        icmp_errors,
        nat,
        dns,
        dhcp,
        dhcp6,
        ra,
        sources,
        pppoe,
        bgp,
    })
}

/// The most `dhcp` entries: each takes one of the FE's punt classes.
const DHCP_MAX: usize = 32;

/// The most punt classes confd writes: the most entries the FE's punt table takes.
const PUNT_CLASSES_MAX: usize = 64;

/// The longest DHCP lease: a day short of a year, well within what Kea and the
/// 32-bit lease time option (RFC 2132 section 9.2) hold.
const DHCP_LEASE_MAX: u32 = 364 * 24 * 3_600;

/// The highest DHCP punt rate (packets a second) and burst: far above what a LAN
/// needs, and still a limit.
const DHCP_PUNT_MAX: u32 = 100_000;

/// Checks one `dhcp`: it serves a port or VLAN of the default VRF from the
/// interface's IPv4 address and subnet, and leases a pool in the subnet.
fn dhcp_entry(
    entry: ruster_config::Dhcp,
    interfaces: &[InterfaceConfig],
) -> Result<ruster_config::Dhcp, String> {
    let at = format!("dhcp {:?}", entry.interface);
    let interface = interfaces
        .iter()
        .find(|i| i.name == entry.interface)
        .ok_or_else(|| format!("{at}: no such interface"))?;
    if interface.vrf != DEFAULT_VRF {
        return Err(format!("{at}: the interface must be in the default VRF"));
    }
    if interface.tunnel.is_some() || interface.pppoe.is_some() {
        return Err(format!("{at}: the interface must be a port or a VLAN"));
    }
    if mac(&entry.mac) != Some(interface.mac) {
        return Err(format!("{at}: mac must be the interface's"));
    }
    let Some((own, len)) = interface.ipv4 else {
        return Err(format!("{at}: the interface has no ipv4 address"));
    };
    if prefix(&entry.address) != Some((IpAddr::V4(own), len)) {
        return Err(format!(
            "{at}: address must be the interface's, {own}/{len}"
        ));
    }
    if len > 30 {
        return Err(format!(
            "{at}: the interface's prefix has no addresses to lease"
        ));
    }
    let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
    let subnet = u32::from(own) & mask;
    if subnet == 0 {
        return Err(format!("{at}: the subnet must not be 0.0.0.0/{len}"));
    }
    // The hosts of the subnet: neither its network nor its broadcast address.
    let host = |a: Ipv4Addr| {
        u32::from(a) & mask == subnet
            && a != Ipv4Addr::from(subnet)
            && u32::from(a) != subnet | !mask
    };
    let (first, last) = entry
        .pool
        .split_once('-')
        .and_then(|(a, b)| Some((a.parse::<Ipv4Addr>().ok()?, b.parse::<Ipv4Addr>().ok()?)))
        .filter(|(a, b)| a <= b)
        .ok_or_else(|| {
            format!("{at}: pool must be like 192.0.2.100-192.0.2.199, the first not above the last")
        })?;
    if !host(first) || !host(last) {
        return Err(format!(
            "{at}: pool must be within the hosts of {}/{len}",
            Ipv4Addr::from(subnet)
        ));
    }
    if (first..=last).contains(&own) {
        return Err(format!(
            "{at}: pool must not hold the router's address {own}"
        ));
    }
    if !(60..=DHCP_LEASE_MAX).contains(&entry.lease_time) {
        return Err(format!(
            "{at}: lease-time must be 60 to {DHCP_LEASE_MAX} seconds"
        ));
    }
    if !(1..=DHCP_PUNT_MAX).contains(&entry.punt_rate)
        || !(1..=DHCP_PUNT_MAX).contains(&entry.punt_burst)
    {
        return Err(format!(
            "{at}: punt-rate and punt-burst must be 1 to {DHCP_PUNT_MAX}"
        ));
    }
    for (what, list) in [("router", &entry.router), ("dns", &entry.dns)] {
        for text in list {
            let usable = text.parse::<Ipv4Addr>().is_ok_and(unicast_v4);
            if !usable {
                return Err(format!(
                    "{at}: {what} {text:?} must be a unicast IPv4 address"
                ));
            }
        }
    }
    if entry.router.len() > 8 || entry.dns.len() > 8 {
        return Err(format!(
            "{at}: router and dns take at most 8 addresses each"
        ));
    }
    Ok(entry)
}

/// Checks `dns`: it answers on the router's own addresses in the default VRF.
fn dns(entry: ruster_config::Dns, seen: &Seen) -> Result<ruster_config::Dns, String> {
    let at = "dns";
    if entry.listen.is_empty() {
        return Err(format!("{at}: listen needs at least one address"));
    }
    for text in &entry.listen {
        let ours = text
            .parse::<IpAddr>()
            .is_ok_and(|a| seen.addresses.contains(&(DEFAULT_VRF.to_owned(), a)));
        if !ours {
            return Err(format!(
                "{at}: listen {text:?} must be an address of an interface in the default VRF"
            ));
        }
    }
    for text in &entry.allow {
        match prefix(text) {
            Some((address, len)) if network(address, len) == address => {}
            _ => {
                return Err(format!(
                    "{at}: allow {text:?} must be a prefix like 192.0.2.0/24, with no bits after its length"
                ))
            }
        }
    }
    for text in &entry.upstream {
        let usable = text.parse::<IpAddr>().is_ok_and(|a| match a {
            IpAddr::V4(v) => unicast_v4(v),
            IpAddr::V6(v) => unicast_v6(v),
        });
        if !usable {
            return Err(format!("{at}: upstream {text:?} must be a unicast address"));
        }
    }
    if !entry.upstream_from.is_empty() {
        return Err(format!("{at}: upstream-from cannot name a source yet"));
    }
    Ok(entry)
}

/// The MAP-E CE's tunnel interface, its NAT, and the delegated prefix (RFC 7597
/// sections 5.2 and 6).
fn map_e(
    entry: ruster_config::MapE,
    seen: &Seen,
) -> Result<(InterfaceConfig, Nat, (Ipv6Addr, u8)), String> {
    let at = "map-e";
    let v6 = |text: &str, what: &str| match prefix(text) {
        Some((IpAddr::V6(address), len)) => Ok((address, len)),
        _ => Err(format!("{at}: {what} must be an IPv6 prefix")),
    };
    let (delegated, delegated_len) = v6(&entry.prefix, "prefix")?;
    let (rule6, rule6_len) = v6(&entry.rule_ipv6, "rule-ipv6")?;
    let (rule4, rule4_len) = match prefix(&entry.rule_ipv4) {
        Some((IpAddr::V4(address), len))
            if network(IpAddr::V4(address), len) == IpAddr::V4(address) =>
        {
            (address, len)
        }
        _ => return Err(format!("{at}: rule-ipv4 must be an IPv4 prefix")),
    };
    if !unicast_v4(rule4) {
        return Err(format!("{at}: rule-ipv4 must be a unicast prefix"));
    }
    let br: Ipv6Addr = entry
        .br
        .parse()
        .map_err(|_| format!("{at}: br must be an IPv6 address"))?;
    if !unicast_v6(br) || br.is_unicast_link_local() {
        return Err(format!("{at}: br must be a global unicast address"));
    }
    let ea_length = entry.ea_length;
    let suffix = 32 - rule4_len;
    // The EA bits follow the rule IPv6 prefix in the delegated prefix; they hold
    // the IPv4 suffix and then the PSID (RFC 7597 section 5.2).
    if network(IpAddr::V6(rule6), rule6_len) != IpAddr::V6(rule6) {
        return Err(format!(
            "{at}: rule-ipv6 has bits set after its prefix length"
        ));
    }
    if network(IpAddr::V6(delegated), rule6_len) != IpAddr::V6(rule6) {
        return Err(format!("{at}: prefix must be inside rule-ipv6"));
    }
    if ea_length > 48 {
        return Err(format!("{at}: ea-length must be at most 48"));
    }
    if u16::from(rule6_len) + u16::from(ea_length) > u16::from(delegated_len) || delegated_len > 64
    {
        return Err(format!(
            "{at}: prefix must be at most /64 and hold the ea-length bits after rule-ipv6"
        ));
    }
    if ea_length < suffix {
        return Err(format!(
            "{at}: ea-length must cover the {suffix} IPv4 suffix bits of rule-ipv4"
        ));
    }
    let bits = u128::from(delegated);
    let ea = if ea_length == 0 {
        0
    } else {
        ((bits << rule6_len) >> (128 - u32::from(ea_length))) as u64
    };
    let psid_length = ea_length - suffix;
    let psid = (ea & ((1_u64 << psid_length) - 1)) as u16;
    let ipv4 = Ipv4Addr::from(u32::from(rule4) | (ea >> psid_length) as u32);
    if !unicast_v4(ipv4) {
        return Err(format!(
            "{at}: the IPv4 address the prefix gives, {ipv4}, is not a unicast address"
        ));
    }
    let offset = entry.psid_offset;
    if !(1..=15).contains(&offset) {
        return Err(format!("{at}: psid-offset must be 1 to 15"));
    }
    let ports = if psid_length == 0 {
        let (first, last) = nat_ports(at, &entry.ports)?;
        NatPorts::Range { first, last }
    } else {
        if offset == 0 || u16::from(offset) + u16::from(psid_length) >= 16 {
            return Err(format!(
                "{at}: psid-offset plus the {psid_length} PSID bits must be 1 to 15"
            ));
        }
        NatPorts::Psid {
            offset,
            length: psid_length,
            psid,
        }
    };
    // The CE's address: the delegated prefix with subnet ID 0, and the interface
    // ID 0 : IPv4 address : PSID (RFC 7597 section 6).
    let upper = (bits >> 64) << 64;
    let upper = upper & !(u128::MAX >> delegated_len);
    let interface_id = (u128::from(u32::from(ipv4)) << 16) | u128::from(psid);
    let local = Ipv6Addr::from(upper | interface_id);
    let mtu = entry.mtu;
    if !(MIN_MTU..=MAX_MTU - 40).contains(&mtu) {
        return Err(format!("{at}: mtu must be {MIN_MTU} to {}", MAX_MTU - 40));
    }
    if seen.names.contains(&entry.interface) {
        return Err(format!(
            "{at}: interface {:?} is given twice",
            entry.interface
        ));
    }
    match seen.vrf_of.get(&entry.inside) {
        Some(vrf) if vrf == DEFAULT_VRF => {}
        Some(_) => return Err(format!("{at}: inside must be in the default VRF")),
        None => return Err(format!("{at}: no interface {:?}", entry.inside)),
    }
    let mac = mac(&entry.mac)
        .filter(|m| m[0] & 1 == 0 && *m != [0; 6])
        .ok_or_else(|| format!("{at}: mac must be a unicast MAC address"))?;
    let tunnel = InterfaceConfig {
        name: entry.interface.clone(),
        mac,
        mtu,
        enabled: true,
        ipv4: Some((ipv4, 32)),
        ipv6: Vec::new(),
        vrf: DEFAULT_VRF.to_owned(),
        vlan: None,
        tunnel: Some((local, br)),
        pppoe: None,
        ipv4_from: None,
    };
    let nat = Nat {
        filtering: filtering(at, &entry.filtering)?,
        ipv4_id_rate_limit: entry.ipv4_id_rate_limit,
        ports_per_host: entry.ports_per_host,
        state_per_host: entry.state_per_host,
        inside: entry.inside,
        outside: entry.interface,
        external: None,
        ports,
    };
    let delegated = match network(IpAddr::V6(delegated), delegated_len) {
        IpAddr::V6(network) => network,
        IpAddr::V4(_) => unreachable!("an IPv6 network"),
    };
    Ok((tunnel, nat, (delegated, delegated_len)))
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

/// The NAT's ports, `"1024-32767"`.
fn nat_ports(at: &str, text: &str) -> Result<(u16, u16), String> {
    match port_range(text) {
        Some((first, last)) if first > 0 => Ok((first, last)),
        _ => Err(format!(
            "{at}: ports must be a range such as 1024-65535, not 0"
        )),
    }
}

fn nat(
    entry: ruster_config::Nat,
    seen: &Seen,
    interfaces: &[InterfaceConfig],
) -> Result<Nat, String> {
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
    let (first_port, last_port) = nat_ports(at, &entry.ports)?;
    let outside_address = interfaces
        .iter()
        .find(|i| i.name == entry.outside)
        .and_then(|i| i.ipv4)
        .map(|(address, _)| address);
    let session = interfaces
        .iter()
        .any(|i| i.name == entry.outside && i.address_from_source());
    if outside_address.is_none() && !session {
        return Err(format!("{at}: {:?} has no ipv4 address", entry.outside));
    }
    let external = match at_most_one(at, "external", &entry.external)? {
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
        filtering: filtering(at, &entry.filtering)?,
        ipv4_id_rate_limit: entry.ipv4_id_rate_limit,
        ports_per_host: entry.ports_per_host,
        state_per_host: entry.state_per_host,
        inside: entry.inside,
        outside: entry.outside,
        external,
        ports: NatPorts::Range {
            first: first_port,
            last: last_port,
        },
    })
}

/// The table rules of one `[[firewall]]` entry: one for its family, or one for each
/// when neither its addresses nor its protocol says which (IPv4 first).
fn firewall_rule(
    at: &str,
    entry: ruster_config::FirewallRule,
    seen: &Seen,
) -> Result<Vec<FirewallRule>, String> {
    let one =
        |what: &str, list: &[String]| at_most_one(at, what, list).map(Option::<&String>::cloned);
    let ingress = one("ingress", &entry.ingress)?;
    let egress = one("egress", &entry.egress)?;
    let source = one("source", &entry.source)?;
    let destination = one("destination", &entry.destination)?;
    let source_ports = one("source-ports", &entry.source_ports)?;
    let destination_ports = one("destination-ports", &entry.destination_ports)?;
    let action = match entry.action.as_str() {
        "accept" => FirewallAction::Accept,
        "drop" => FirewallAction::Drop,
        _ => return Err(format!("{at}: action must be \"accept\" or \"drop\"")),
    };
    let protocol = match entry.protocol.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "icmpv6" => Protocol::Icmpv6,
        _ => {
            return Err(format!(
                "{at}: protocol must be \"tcp\", \"udp\", \"icmp\" or \"icmpv6\""
            ))
        }
    };
    for name in [&ingress, &egress].into_iter().flatten() {
        // The router itself: its own packets come and go through the default VRF's
        // kernel interface.
        if name == ROUTER_INTERFACE {
            continue;
        }
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
    let given = |text: &Option<String>, what: &str| match text {
        None => Ok(None),
        Some(text) => match prefix(text) {
            Some((address, len)) if network(address, len) == address => Ok(Some((address, len))),
            _ => Err(format!("{at}: {what} must be a prefix with no host bits")),
        },
    };
    let source = given(&source, "source")?;
    let destination = given(&destination, "destination")?;
    // The family: the addresses', else the protocol's, else both.
    let families: Vec<bool> = match (source, destination, protocol) {
        (Some((a, _)), Some((b, _)), _) if a.is_ipv6() != b.is_ipv6() => {
            return Err(format!(
                "{at}: source and destination must be of one family"
            ))
        }
        (Some((a, _)), _, _) | (None, Some((a, _)), _) => vec![a.is_ipv6()],
        (None, None, Protocol::Icmp) => vec![false],
        (None, None, Protocol::Icmpv6) => vec![true],
        (None, None, Protocol::Tcp | Protocol::Udp) => vec![false, true],
    };
    if (protocol == Protocol::Icmp && families == [true])
        || (protocol == Protocol::Icmpv6 && families == [false])
    {
        return Err(format!(
            "{at}: icmp is for IPv4 prefixes and icmpv6 for IPv6 ones"
        ));
    }
    let any = |ipv6: bool| -> (IpAddr, u8) {
        if ipv6 {
            (Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            (Ipv4Addr::UNSPECIFIED.into(), 0)
        }
    };
    let ports = |text: &Option<String>, what: &str| {
        let Some(text) = text else {
            return Ok((0, u16::MAX));
        };
        if matches!(protocol, Protocol::Icmp | Protocol::Icmpv6) {
            return Err(format!("{at}: {what} are for tcp and udp only"));
        }
        port_range(text)
            .ok_or_else(|| format!("{at}: {what} must be a port or a range such as 1024-65535"))
    };
    let source_ports = ports(&source_ports, "source-ports")?;
    let destination_ports = ports(&destination_ports, "destination-ports")?;
    Ok(families
        .into_iter()
        .map(|ipv6| FirewallRule {
            source: source.unwrap_or(any(ipv6)),
            destination: destination.unwrap_or(any(ipv6)),
            source_ports,
            destination_ports,
            ingress: ingress.clone(),
            egress: egress.clone(),
            protocol,
            action,
        })
        .collect())
}

pub(crate) fn mac(text: &str) -> Option<[u8; 6]> {
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

pub(crate) fn prefix(text: &str) -> Option<(IpAddr, u8)> {
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

/// The longest VRF name: its kernel devices `vrf-<name>` and `rt-<name>` must fit
/// Linux's 15-byte interface names.
const VRF_NAME_MAX: usize = 11;

fn vrf_name(at: &str, vrf: &str) -> Result<(), String> {
    if vrf.is_empty() {
        return Err(format!("{at}: vrf must not be empty"));
    }
    if vrf.len() > VRF_NAME_MAX || !vrf.bytes().all(|b| b.is_ascii_graphic() && b != b'/') {
        return Err(format!(
            "{at}: vrf {vrf:?} must be at most {VRF_NAME_MAX} letters, digits or signs other than /"
        ));
    }
    Ok(())
}

/// An address a host can have: not unspecified, loopback, multicast, broadcast or
/// reserved (240.0.0.0/4).
fn unicast_v4(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    first != 0 && !address.is_loopback() && first < 224
}

/// Why `address/len` cannot be an interface's address, if it cannot.
fn unusable_interface_v6(address: Ipv6Addr, len: u8) -> Option<&'static str> {
    let bits = u128::from(address);
    if bits >> 32 == 0xffff {
        return Some("is an IPv4-mapped address");
    }
    if bits >> 32 == 0 {
        return Some("is an IPv4-compatible address");
    }
    if address.segments()[0] & 0xffc0 == 0xfec0 {
        return Some("is a site-local address (fec0::/10)");
    }
    if address.is_unicast_link_local() {
        return (len != 64).then_some("is link-local and needs the prefix length 64");
    }
    // A /127 has no Subnet-Router anycast address; a /128 has no subnet.
    if len < 127 && bits & (u128::MAX >> len) == 0 {
        return Some("is the Subnet-Router anycast address of its prefix");
    }
    None
}

fn unicast_v6(address: Ipv6Addr) -> bool {
    !address.is_unspecified() && !address.is_loopback() && !address.is_multicast()
}

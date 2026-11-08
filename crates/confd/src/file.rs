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
//! [[interface]]                # a PPPoE session (set up by a daemon outside ruster)
//! name = "ppp"
//! pppoe = { parent = "wan", session = 4660, peer = "02:00:00:00:00:ac" }
//! ipv4 = "198.51.100.2/32"     # optional
//! # mac is the parent's and mtu its less 8 when left out
//!
//! [[interface]]                # a WireGuard interface
//! name = "wg0"
//! wireguard = { listen-port = 51820, local = "198.51.100.2" }
//! ipv4 = "10.9.0.1/32"         # optional
//! # mtu is 1420 when left out; mac is not needed
//!
//! [[wireguard-peer]]
//! interface = "wg0"
//! name = "branch"
//! endpoint = "203.0.113.9:51821"
//! allowed = ["10.9.0.0/16"]    # what the peer may send from and be sent to
//! # No session keys here: a fixed key would be used again from counter 0 after
//! # the FE starts again. How sessions reach the FE is not decided yet.
//!
//! [map-e]                      # a MAP-E CE (instead of [nat] and a tunnel)
//! interface = "map"            # the tunnel interface it makes
//! inside = "lan"               # the NAT's inside
//! prefix = "2001:db8:12:3400::/56"  # the delegated (end-user) IPv6 prefix
//! rule-ipv6 = "2001:db8::/40"  # the Basic Mapping Rule
//! rule-ipv4 = "192.0.2.0/24"
//! ea-length = 16
//! psid-offset = 6              # optional, 6 when left out
//! br = "2001:db8:ffff::1"
//! mtu = 1460                   # optional, 1460 when left out
//! filtering = "endpoint-independent"  # optional, as for [nat]
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
//! [[route]]                    # drop the prefix's packets (a longer route still wins)
//! prefix = "10.0.0.0/8"
//! action = "discard"           # silently; "reject": with a Destination Unreachable
//!
//! [[firewall]]                 # forward rules of the default VRF, first match wins
//! action = "accept"            # or "drop"; an accepted flow's replies pass too
//! protocol = "udp"             # "tcp", "udp", "icmp" (IPv4) or "icmpv6" (IPv6)
//! ingress = "lan"              # optional, any interface when left out;
//!                              # "rt-default" is the router itself: as ingress its own
//!                              # packets, as egress the packets to it (SSH, ping, ...)
//! egress = "wan"               # optional
//! source = "192.0.2.0/24"      # optional, any address when left out; IPv4 or IPv6
//! destination = "0.0.0.0/0"    # optional, of the source's family
//! # A tcp or udp rule with neither source nor destination is for IPv4 and IPv6.
//! source-ports = "1024-65535"  # optional, tcp and udp only; any when left out
//! destination-ports = "53"     # optional
//!
//! [nat]                        # NAPT of the default VRF
//! inside = "lan"
//! outside = "wan"              # must have an ipv4 address: the public one
//! ports = "1024-32767"         # optional, 1024-32767 when left out
//! external = "198.51.100.2"    # optional; for now only the outside's own address
//! filtering = "endpoint-independent"  # optional, the default, or
//!                              # "address-dependent", "address-and-port-dependent"
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
//!   Its MTU is at most 1460 (1500 less the IPv6 header), and at run time at most
//!   what the link below carries less 40, so the outer packets are not fragmented
//!   (RFC 6333 5.3 lets the B4 fragment them instead).
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
//!   (`ea-length` equal to the IPv4 suffix) uses ports 1024 to 32767, below the
//!   kernel's; a delegated prefix that is a link's on-link prefix is refused (no one
//!   would answer Neighbor Discovery for the CE's address there); the
//!   interface ID is RFC 7597's, not the older draft's; the unwrapped IPv4
//!   destination is not checked against the CE's address (NAT drops what would go
//!   from the tunnel to the inside without a mapping; one routed elsewhere is
//!   forwarded).
//! - RFC 2516: a `pppoe` interface is one PPPoE session on its parent (a port or
//!   VLAN given before it), with the session ID and the access concentrator's MAC
//!   that the session's daemon found; its MTU is at most the parent's less 8.
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

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use ruster_proto::table::{
    FirewallAction, FirewallRule, Nat, NatFiltering, NatPorts, Protocol, DEFAULT_VRF,
};

use crate::{
    Config, InterfaceConfig, RouteTarget, StaticRoute, WireguardConfig, WireguardPeerConfig,
};

/// The smallest MTU an IPv4 interface may have (RFC 791).
const MIN_MTU: u16 = ruster_proto::table::MIN_MTU;
/// The FE takes Ethernet frames of up to 1514 bytes.
const MAX_MTU: u16 = 1_500;
/// The name rules give the router itself (the default VRF's kernel interface).
const ROUTER_INTERFACE: &str = "rt-default";
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
    #[serde(rename = "map-e")]
    map_e: Option<MapEEntry>,
    #[serde(default, rename = "wireguard-peer")]
    wireguard_peer: Vec<WireguardPeerEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
struct WireguardEntry {
    listen_port: u16,
    local: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireguardPeerEntry {
    interface: String,
    name: String,
    endpoint: String,
    allowed: Vec<String>,
}

/// A MAP-E CE (RFC 7597): one Basic Mapping Rule, the delegated prefix, the BR.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
struct MapEEntry {
    /// The tunnel interface confd makes.
    interface: String,
    /// The NAT's inside interface.
    inside: String,
    /// The end-user IPv6 prefix (the one delegated to the CE).
    prefix: String,
    rule_ipv6: String,
    rule_ipv4: String,
    ea_length: u8,
    psid_offset: Option<u8>,
    br: String,
    mtu: Option<u16>,
    filtering: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NatEntry {
    inside: String,
    outside: String,
    ports: Option<String>,
    external: Option<String>,
    filtering: Option<String>,
}

/// `filtering = "..."` of `[nat]` or `[map-e]`; endpoint-independent when left out.
fn filtering(at: &str, text: Option<&str>) -> Result<NatFiltering, String> {
    match text {
        None => Ok(NatFiltering::default()),
        Some(text) => NatFiltering::from_name(&format!("{text}-filtering"))
            .ok_or_else(|| {
                format!(
                    "{at}: filtering must be \"endpoint-independent\", \"address-dependent\" or \"address-and-port-dependent\""
                )
            }),
    }
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
    pppoe: Option<PppoeEntry>,
    wireguard: Option<WireguardEntry>,
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
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
struct RouteEntry {
    #[serde(default = "default_vrf")]
    vrf: String,
    prefix: String,
    interface: Option<String>,
    via: Option<String>,
    lookup_vrf: Option<String>,
    /// `"discard"` (dropped silently) or `"reject"` (dropped with a Destination
    /// Unreachable), instead of an interface.
    action: Option<String>,
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
    let mut wireguard_interfaces: Vec<WireguardConfig> = Vec::new();
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
        // A PPPoE session on a port or VLAN sub-interface given before it.
        let pppoe = match &entry.pppoe {
            None => None,
            Some(_) if vlan.is_some() || tunnel.is_some() => {
                return Err(format!(
                    "{at}: an interface is one of a VLAN, a tunnel and a PPPoE session"
                ))
            }
            Some(session) => {
                let Some(parent) = interfaces.iter().find(|i: &&InterfaceConfig| {
                    i.name == session.parent && i.tunnel.is_none() && i.pppoe.is_none()
                }) else {
                    return Err(format!(
                        "{at}: PPPoE parent {:?} must be a port or VLAN given before it",
                        session.parent
                    ));
                };
                if session.session == 0 || session.session == 0xffff {
                    return Err(format!("{at}: PPPoE session must be 1 to 65534"));
                }
                let taken = interfaces.iter().any(|i| {
                    i.pppoe
                        .as_ref()
                        .is_some_and(|(p, id, _)| *p == parent.name && *id == session.session)
                });
                if taken {
                    return Err(format!(
                        "{at}: PPPoE session {} on {:?} is given twice",
                        session.session, parent.name
                    ));
                }
                let peer = mac(&session.peer)
                    .filter(|m| m[0] & 1 == 0 && *m != [0; 6])
                    .ok_or_else(|| format!("{at}: PPPoE peer must be a unicast MAC address"))?;
                Some((
                    parent.name.clone(),
                    session.session,
                    peer,
                    parent.mac,
                    parent.mtu,
                ))
            }
        };
        // A WireGuard interface is a plain interface that also has WireGuard settings.
        let wireguard = match &entry.wireguard {
            None => None,
            Some(_) if vlan.is_some() || tunnel.is_some() || pppoe.is_some() => {
                return Err(format!(
                    "{at}: an interface is one of a VLAN, a tunnel, a PPPoE session and a WireGuard interface"
                ))
            }
            Some(settings) => {
                let local: Ipv4Addr = settings
                    .local
                    .parse()
                    .ok()
                    .filter(|a| unicast_v4(*a))
                    .ok_or_else(|| format!("{at}: wireguard local must be a unicast IPv4 address"))?;
                if settings.listen_port == 0 {
                    return Err(format!("{at}: wireguard listen-port must be 1 to 65535"));
                }
                Some((settings.listen_port, local))
            }
        };
        let mac = match (&entry.mac, &vlan) {
            (Some(text), _) => {
                mac(text).ok_or_else(|| format!("{at}: mac is not like 02:00:00:00:00:01"))?
            }
            (None, Some((_, _, parent_mac))) => *parent_mac,
            // A tunnel has no link; its MAC address only names it inside the FE.
            (None, None) if tunnel.is_some() || wireguard.is_some() => TUNNEL_MAC,
            // A session's frames go out with its parent's address.
            (None, None) if pppoe.is_some() => pppoe.as_ref().map(|p| p.3).unwrap(),
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
        // A session's packets carry 8 bytes of PPPoE header on the parent's link.
        let max_mtu = pppoe.as_ref().map_or(max_mtu, |p| p.4 - 8);
        // A WireGuard packet carries 60 bytes (IPv4, UDP and WireGuard's header and
        // tag) on the link below.
        let max_mtu = if wireguard.is_some() {
            MAX_MTU - 60
        } else {
            max_mtu
        };
        let mtu = match (entry.mtu, &vlan) {
            (Some(mtu), _) => mtu,
            (None, Some(_)) => max_mtu,
            (None, None) if tunnel.is_some() || pppoe.is_some() => max_mtu,
            (None, None) if wireguard.is_some() => 1_420,
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
        if let Some((listen_port, local)) = wireguard {
            wireguard_interfaces.push(WireguardConfig {
                name: entry.name.clone(),
                listen_port,
                local,
                peers: Vec::new(),
            });
        }
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
            pppoe: pppoe.map(|(parent, session, peer, _, _)| (parent, session, peer)),
        });
    }
    // A MAP-E CE's tunnel is an interface like the others for what follows.
    let map_e = match file.map_e {
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
        if let Some(action) = &entry.action {
            let target = match action.as_str() {
                "discard" => RouteTarget::Discard,
                "reject" => RouteTarget::Reject,
                _ => return Err(format!("{at}: action must be \"discard\" or \"reject\"")),
            };
            if entry.interface.is_some() || entry.lookup_vrf.is_some() || entry.via.is_some() {
                return Err(format!(
                    "{at}: a {action} route has no interface, lookup-vrf or via"
                ));
            }
            static_routes.push(StaticRoute {
                vrf: entry.vrf,
                prefix: address,
                len,
                target,
            });
            continue;
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
            _ => {
                return Err(format!(
                    "{at}: give one of interface, lookup-vrf and action"
                ))
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
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    let mut nat = file
        .nat
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
    for entry in file.wireguard_peer {
        let at = format!("wireguard-peer {:?} of {:?}", entry.name, entry.interface);
        let Some(wireguard) = wireguard_interfaces
            .iter_mut()
            .find(|w| w.name == entry.interface)
        else {
            return Err(format!("{at}: the interface has no wireguard settings"));
        };
        if entry.name.is_empty() || entry.name.len() > 255 {
            return Err(format!("{at}: the name must be 1 to 255 bytes"));
        }
        if wireguard.peers.iter().any(|p| p.name == entry.name) {
            return Err(format!("{at}: given twice"));
        }
        let endpoint: std::net::SocketAddrV4 = entry
            .endpoint
            .parse()
            .ok()
            .filter(|e: &std::net::SocketAddrV4| unicast_v4(*e.ip()) && e.port() != 0)
            .ok_or_else(|| format!("{at}: endpoint is not like 203.0.113.9:51820"))?;
        if entry.allowed.is_empty()
            || entry.allowed.len() > ruster_proto::table::WIREGUARD_MAX_ALLOWED
        {
            return Err(format!("{at}: allowed needs 1 to 64 prefixes"));
        }
        let mut allowed = Vec::new();
        for text in &entry.allowed {
            let Some((IpAddr::V4(address), len)) = prefix(text) else {
                return Err(format!("{at}: allowed {text:?} is not like 10.9.0.0/16"));
            };
            if network(address.into(), len) != IpAddr::V4(address) {
                return Err(format!("{at}: allowed {text:?} has host bits set"));
            }
            allowed.push((address, len));
        }
        wireguard.peers.push(WireguardPeerConfig {
            name: entry.name,
            endpoint: (*endpoint.ip(), endpoint.port()),
            allowed,
        });
    }
    // The outer packets are sent from one of the router's own addresses in the
    // default VRF.
    for wireguard in &wireguard_interfaces {
        let owned = interfaces.iter().any(|i| {
            i.vrf == DEFAULT_VRF
                && i.ipv4.is_some_and(|(a, _)| a == wireguard.local)
                && !wireguard_interfaces.iter().any(|w| w.name == i.name)
        });
        if !owned {
            return Err(format!(
                "interface {:?}: wireguard local {} must be the IPv4 address of an interface in the default VRF",
                wireguard.name, wireguard.local
            ));
        }
    }
    Ok(Config {
        interfaces,
        wireguard: wireguard_interfaces,
        static_routes,
        firewall,
        nat,
    })
}

/// The tunnel interface and NAT of a MAP-E CE (RFC 7597 sections 5.2 and 6).
/// The MAP-E CE's tunnel interface, its NAT, and the delegated prefix.
fn map_e(entry: MapEEntry, seen: &Seen) -> Result<(InterfaceConfig, Nat, (Ipv6Addr, u8)), String> {
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
    let offset = entry.psid_offset.unwrap_or(6);
    if !(1..=15).contains(&offset) {
        return Err(format!("{at}: psid-offset must be 1 to 15"));
    }
    let ports = if psid_length == 0 {
        NatPorts::Range {
            // Below the kernel's ephemeral ports, as for [nat].
            first: 1_024,
            last: 32_767,
        }
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
    let mtu = entry.mtu.unwrap_or(MAX_MTU - 40);
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
    let tunnel = InterfaceConfig {
        name: entry.interface.clone(),
        mac: TUNNEL_MAC,
        mtu,
        enabled: true,
        ipv4: Some((ipv4, 32)),
        ipv6: Vec::new(),
        vrf: DEFAULT_VRF.to_owned(),
        vlan: None,
        tunnel: Some((local, br)),
        pppoe: None,
    };
    let nat = Nat {
        filtering: filtering(at, entry.filtering.as_deref())?,
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
        filtering: filtering(at, entry.filtering.as_deref())?,
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
fn firewall_rule(at: &str, entry: FirewallEntry, seen: &Seen) -> Result<Vec<FirewallRule>, String> {
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
    for name in [&entry.ingress, &entry.egress].into_iter().flatten() {
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
    let source = given(&entry.source, "source")?;
    let destination = given(&entry.destination, "destination")?;
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
    let source_ports = ports(&entry.source_ports, "source-ports")?;
    let destination_ports = ports(&entry.destination_ports, "destination-ports")?;
    Ok(families
        .into_iter()
        .map(|ipv6| FirewallRule {
            source: source.unwrap_or(any(ipv6)),
            destination: destination.unwrap_or(any(ipv6)),
            source_ports,
            destination_ports,
            ingress: entry.ingress.clone(),
            egress: entry.egress.clone(),
            protocol,
            action,
        })
        .collect())
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

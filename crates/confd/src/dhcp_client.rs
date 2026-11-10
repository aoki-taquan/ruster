//! The WAN side's DHCP client's part (`[[dhcp-client]]`, for `ruster-dhcpc`) and
//! the punt classes that hand it DHCP and DHCPv6.
//!
//! confd hands the entries to `ruster-dhcpc` on `confd/part.sock` (module
//! `dhcpc`), and for each interface writes the FE's punt classes to the control
//! process `dhcpc`: `dhcpc-<interface>` (UDP to port 68) when it runs DHCPv4, and
//! `dhcpc6-<interface>` (UDP to port 546) when it runs DHCPv6. They take the
//! replies to 255.255.255.255 before forwarding, and those to the router's own
//! addresses (a DHCPv4 renewal's answer, every DHCPv6 reply to the link-local
//! address) once the firewall lets them through to the router (`rt-default`).
//! With firewall rules, confd puts rules that accept those replies in front of
//! them ([`firewall_rules`]): the client's requests go out through the punt socket
//! and open no flow for the replies.
//!
//! # Standards
//!
//! - RFC 2131 section 4.1: a server answers a client on port 68, to
//!   255.255.255.255 while the client asks for broadcast, else to its address.
//! - RFC 8415 section 7.2 and 18.3: a server or relay answers a client on port 546,
//!   to the address the client sent from (its link-local address).
//!
//! Deviations: a server's unicast answer to an address the router does not have
//! yet is not handed over; the client asks for broadcast answers instead.

use std::collections::{BTreeMap, BTreeSet};

use ruster_config::DhcpClient;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ruster_proto::table::{
    FirewallAction, FirewallRule, Key, Protocol, PuntClass, PuntDestination, PuntMatch, Value,
    DEFAULT_VRF,
};

use crate::source::{Kind, Spec};
use crate::InterfaceConfig;

/// The control process (`<run>/dhcpc/punt.sock`) DHCP replies are handed to.
pub const DHCP_CLIENT_CONTROL: &str = "dhcpc";
/// The punt classes: `dhcpc-<interface>` and `dhcpc6-<interface>`.
pub const CLASS_PREFIX: &str = "dhcpc-";
pub const CLASS6_PREFIX: &str = "dhcpc6-";
/// The DHCP and DHCPv6 client ports.
pub const CLIENT_PORT: u16 = 68;
pub const CLIENT6_PORT: u16 = 546;
/// The highest punt rate and burst taken.
const PUNT_MAX: u32 = 10_000;

/// Checks the lock form's `[[dhcp-client]]` against the interfaces and sources.
pub fn check(
    entries: Vec<DhcpClient>,
    interfaces: &[InterfaceConfig],
    sources: &[Spec],
) -> Result<Vec<DhcpClient>, String> {
    let mut seen = BTreeSet::new();
    let mut used_sources = BTreeSet::new();
    for entry in &entries {
        let at = format!("dhcp-client {:?}", entry.interface);
        if !seen.insert(entry.interface.as_str()) {
            return Err(format!("{at}: given twice"));
        }
        let interface = interfaces
            .iter()
            .find(|i| i.name == entry.interface)
            .ok_or_else(|| format!("{at}: no such interface"))?;
        if interface.tunnel.is_some() || interface.pppoe.is_some() {
            return Err(format!("{at}: the interface must be a port or a VLAN"));
        }
        if interface.vrf != DEFAULT_VRF || entry.vrf != interface.vrf {
            return Err(format!("{at}: the interface must be in the default VRF"));
        }
        let link_local = crate::link_local(interface.mac).to_string();
        let same_mac = ruster_proto::table::parse_mac(&entry.mac.to_ascii_lowercase())
            .is_ok_and(|m| m == interface.mac);
        if !same_mac || entry.link_local != link_local {
            return Err(format!(
                "{at}: mac and link-local must be the interface's ({}, {link_local})",
                ruster_proto::table::format_mac(&interface.mac)
            ));
        }
        for (what, list, kind) in [
            ("ipv4-source", &entry.ipv4_source, Kind::DhcpClient),
            ("ipv6-source", &entry.ipv6_source, Kind::Dhcpv6Client),
        ] {
            match list.as_slice() {
                [] => {}
                [name] => {
                    if !sources.iter().any(|s| s.name == *name && s.kind == kind) {
                        return Err(format!(
                            "{at}: {what} {name:?} must be a source of kind {}",
                            kind.name()
                        ));
                    }
                    if !used_sources.insert(name.as_str()) {
                        return Err(format!("{at}: source {name:?} is another client's"));
                    }
                }
                _ => return Err(format!("{at}: {what} takes at most one source")),
            }
        }
        if entry.ipv4_source.is_empty() && entry.ipv6_source.is_empty() {
            return Err(format!("{at}: give ipv4-source or ipv6-source"));
        }
        // The leased address must be the interface's, and no other's.
        if let Some(source) = entry.ipv4_source.first() {
            if interface.ipv4_from.as_ref() != Some(source) {
                return Err(format!(
                    "{at}: the interface must take its ipv4 from {source:?} (ipv4-from)"
                ));
            }
        }
        if entry.ipv6_address && entry.ipv6_source.is_empty() {
            return Err(format!("{at}: ipv6-address needs ipv6-source"));
        }
        if !(1..=PUNT_MAX).contains(&entry.punt_rate) || !(1..=PUNT_MAX).contains(&entry.punt_burst)
        {
            return Err(format!(
                "{at}: punt-rate and punt-burst must be 1 to {PUNT_MAX}"
            ));
        }
    }
    Ok(entries)
}

/// How many punt classes the entries take: one per protocol each runs.
pub fn class_count(entries: &[DhcpClient]) -> usize {
    entries
        .iter()
        .map(|e| usize::from(!e.ipv4_source.is_empty()) + usize::from(!e.ipv6_source.is_empty()))
        .sum()
}

/// The punt classes of the entries.
pub fn punt_classes(entries: &[DhcpClient], out: &mut BTreeMap<Key, Value>) {
    for entry in entries {
        for (runs, prefix, port) in [
            (!entry.ipv4_source.is_empty(), CLASS_PREFIX, CLIENT_PORT),
            (!entry.ipv6_source.is_empty(), CLASS6_PREFIX, CLIENT6_PORT),
        ] {
            if !runs {
                continue;
            }
            out.insert(
                Key::Punt {
                    class: format!("{prefix}{}", entry.interface),
                },
                Value::Punt(PuntClass {
                    matches: PuntMatch::Ip {
                        protocol: 17,
                        ports: Some((port, port)),
                    },
                    interface: Some(entry.interface.clone()),
                    destination: PuntDestination::Control(DHCP_CLIENT_CONTROL.to_owned()),
                    rate: entry.punt_rate,
                    burst: entry.punt_burst,
                }),
            );
        }
    }
}

/// The firewall rules that let the servers' replies reach the clients: from the
/// interface to the router, UDP from port 67 to 68 (IPv4) and from 547 to 546
/// (IPv6). The router's own interface is `rt-default`.
pub fn firewall_rules(entries: &[DhcpClient]) -> Vec<FirewallRule> {
    let mut out = Vec::new();
    for entry in entries {
        for (runs, any, from, to) in [
            (
                !entry.ipv4_source.is_empty(),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                67,
                CLIENT_PORT,
            ),
            (
                !entry.ipv6_source.is_empty(),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                547,
                CLIENT6_PORT,
            ),
        ] {
            if runs {
                out.push(FirewallRule {
                    ingress: Some(entry.interface.clone()),
                    egress: Some("rt-default".to_owned()),
                    source: (any, 0),
                    destination: (any, 0),
                    protocol: Protocol::Udp,
                    source_ports: (from, from),
                    destination_ports: (to, to),
                    action: FirewallAction::Accept,
                });
            }
        }
    }
    out
}

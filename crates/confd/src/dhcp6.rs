//! Checks `[[dhcp6]]` of the lock form: a DHCPv6 server for one interface, which
//! `ruster-kea` relays to. confd hands the entries to `ruster-kea` in the `dhcp`
//! part ([`crate::part`]) and writes a punt class per entry that hands the
//! interface's UDP port 547 to `ruster-kea`: what is sent to a link-local multicast
//! group (ff02::1:2, where clients send), and to the router's addresses after the
//! input firewall. As the class does not name a family, IPv4 broadcasts to port 547
//! go there too; ruster-kea drops them.
//!
//! # Standards
//!
//! - RFC 8415 section 19.1.1: the relay's link-address is a global address of the
//!   interface, so the subnet is that address's prefix; the pool lies in it and leaves
//!   out the router's addresses. Section 7.6 and 21.6: the preferred lifetime is not
//!   above the valid lifetime. RFC 3646: `dns` is the DNS Recursive Name Server
//!   option.
//! - RFC 4291 section 2.5.1: the link-local address is the MAC's modified EUI-64.
//!
//! Deviations: one pool per interface; the prefix is at most a /120 (at least 256
//! addresses); a lease is valid for 60 s to 364 days.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};

use ruster_config::Dhcp6;
use ruster_proto::table::{network, DEFAULT_VRF};

use crate::InterfaceConfig;

/// The longest valid lifetime: as for DHCPv4.
const VALID_MAX: u32 = 364 * 24 * 3_600;
/// The most DNS servers.
const DNS_MAX: usize = 8;
/// The highest punt rate and burst.
const PUNT_MAX: u32 = 100_000;

/// Checks every `[[dhcp6]]` against the interfaces.
pub(crate) fn check(
    entries: Vec<Dhcp6>,
    interfaces: &[InterfaceConfig],
) -> Result<Vec<Dhcp6>, String> {
    let mut names = BTreeSet::new();
    let mut subnets: Vec<(Ipv6Addr, u8, &str)> = Vec::new();
    for entry in &entries {
        let at = format!("dhcp6 {:?}", entry.interface);
        if !names.insert(entry.interface.as_str()) {
            return Err(format!("{at}: given twice"));
        }
        let (subnet, len) = one(&at, entry, interfaces)?;
        // Kea picks a subnet by the link-address: two of which one holds the other
        // would be ambiguous.
        let holds = |(b, l): (Ipv6Addr, u8)| {
            let shorter = len.min(l);
            network(IpAddr::V6(subnet), shorter) == network(IpAddr::V6(b), shorter)
        };
        if let Some((_, _, other)) = subnets.iter().find(|(b, l, _)| holds((*b, *l))) {
            return Err(format!("{at}: its subnet overlaps that of dhcp6 {other:?}"));
        }
        subnets.push((subnet, len, &entry.interface));
    }
    Ok(entries)
}

/// Checks one entry; its subnet.
fn one(at: &str, entry: &Dhcp6, interfaces: &[InterfaceConfig]) -> Result<(Ipv6Addr, u8), String> {
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
    if crate::file::mac(&entry.mac) != Some(interface.mac) {
        return Err(format!("{at}: mac must be the interface's"));
    }
    let link_local = crate::link_local(interface.mac);
    if entry.link_local.parse::<Ipv6Addr>() != Ok(link_local) {
        return Err(format!(
            "{at}: link-local must be {link_local}, from the mac"
        ));
    }
    let (own, len) = match crate::file::prefix(&entry.address) {
        Some((IpAddr::V6(a), len)) if interface.ipv6.contains(&(a, len)) => (a, len),
        _ => {
            return Err(format!(
                "{at}: address must be one of the interface's ipv6 addresses"
            ))
        }
    };
    if own.is_unicast_link_local() {
        return Err(format!("{at}: address must not be link-local"));
    }
    if len > 120 {
        return Err(format!(
            "{at}: the interface's prefix must be at most a /120"
        ));
    }
    let subnet = match network(IpAddr::V6(own), len) {
        IpAddr::V6(a) => a,
        IpAddr::V4(_) => unreachable!("an IPv6 network"),
    };
    let (first, last) = entry
        .pool
        .split_once('-')
        .and_then(|(a, b)| Some((a.parse::<Ipv6Addr>().ok()?, b.parse::<Ipv6Addr>().ok()?)))
        .filter(|(a, b)| a <= b)
        .ok_or_else(|| {
            format!(
                "{at}: pool must be like 2001:db8:1::1000-2001:db8:1::1fff, the first not above the last"
            )
        })?;
    let inside = |a: Ipv6Addr| network(IpAddr::V6(a), len) == IpAddr::V6(subnet) && a != subnet;
    if !inside(first) || !inside(last) {
        return Err(format!(
            "{at}: pool must be within {subnet}/{len}, not its first address"
        ));
    }
    if let Some(&(ours, _)) = interface
        .ipv6
        .iter()
        .find(|(a, _)| (first..=last).contains(a))
    {
        return Err(format!(
            "{at}: pool must not hold the router's address {ours}"
        ));
    }
    if !(60..=VALID_MAX).contains(&entry.valid_lifetime) {
        return Err(format!(
            "{at}: valid-lifetime must be 60 to {VALID_MAX} seconds"
        ));
    }
    if entry.preferred_lifetime > entry.valid_lifetime {
        return Err(format!(
            "{at}: preferred-lifetime must not be above valid-lifetime"
        ));
    }
    if entry.dns.len() > DNS_MAX {
        return Err(format!("{at}: dns takes at most {DNS_MAX} addresses"));
    }
    for text in &entry.dns {
        let usable = text
            .parse::<Ipv6Addr>()
            .is_ok_and(|a| !a.is_unspecified() && !a.is_loopback() && !a.is_multicast());
        if !usable {
            return Err(format!("{at}: dns {text:?} must be a unicast IPv6 address"));
        }
    }
    if !(1..=PUNT_MAX).contains(&entry.punt_rate) || !(1..=PUNT_MAX).contains(&entry.punt_burst) {
        return Err(format!(
            "{at}: punt-rate and punt-burst must be 1 to {PUNT_MAX}"
        ));
    }
    Ok((subnet, len))
}

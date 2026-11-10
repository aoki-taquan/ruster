//! Checks `[[ra]]` of the lock form: the Router Advertisements neighd sends on an
//! interface. confd hands them to neighd unchanged, as the `ra` part
//! ([`crate::part`]).
//!
//! # Standards
//!
//! - RFC 4861 section 6.2.1: MaxRtrAdvInterval is 4 to 1800 s, MinRtrAdvInterval
//!   3 s to 0.75 of it, AdvDefaultLifetime 0 or MaxRtrAdvInterval to 9000 s,
//!   AdvReachableTime at most 3600000 ms, AdvLinkMTU at least 1280 (RFC 8200
//!   section 5) and at most the interface's MTU, AdvPreferredLifetime at most
//!   AdvValidLifetime. Section 4.6.2: a prefix is not link-local or multicast.
//! - RFC 4862 section 5.5.3: an autonomous prefix is a /64 (the interface identifier
//!   on Ethernet is 64 bits, RFC 2464).
//! - RFC 8106 section 5.1: the DNS servers are unicast addresses.
//!
//! Deviations: the DNS servers' lifetime must be at least MaxRtrAdvInterval (RFC
//! 6106's bound, which RFC 8106 dropped), so they do not lapse between two
//! advertisements; an interface must have an MTU of at least 1280; a prefix must be the prefix of one of the interface's addresses (the
//! router has a connected route for it); at most [`PREFIX_MAX`] prefixes and
//! [`DNS_MAX`] DNS servers, so an advertisement fits in 1280 bytes. An interface
//! must be a port or VLAN (an Ethernet link).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};

use ruster_config::Ra;
use ruster_proto::table::network;

use crate::InterfaceConfig;

/// The most `[[ra]]` entries.
pub const RA_MAX: usize = 32;
/// The most prefixes in one advertisement.
pub const PREFIX_MAX: usize = 16;
/// The most DNS servers in one advertisement.
pub const DNS_MAX: usize = 8;

/// Checks every `[[ra]]` against the interfaces.
pub(crate) fn check(entries: Vec<Ra>, interfaces: &[InterfaceConfig]) -> Result<Vec<Ra>, String> {
    if entries.len() > RA_MAX {
        return Err(format!("give at most {RA_MAX} ra"));
    }
    let mut names = BTreeSet::new();
    for entry in &entries {
        if !names.insert(entry.interface.as_str()) {
            return Err(format!("ra {:?}: given twice", entry.interface));
        }
        one(entry, interfaces)?;
    }
    Ok(entries)
}

fn one(entry: &Ra, interfaces: &[InterfaceConfig]) -> Result<(), String> {
    let at = format!("ra {:?}", entry.interface);
    let interface = interfaces
        .iter()
        .find(|i| i.name == entry.interface)
        .ok_or_else(|| format!("{at}: no such interface"))?;
    if interface.tunnel.is_some() || interface.pppoe.is_some() {
        return Err(format!("{at}: the interface must be a port or a VLAN"));
    }
    if interface.mtu < 1_280 {
        return Err(format!(
            "{at}: the interface's MTU must be at least 1280 to carry IPv6"
        ));
    }
    let (min, max) = (entry.min_interval, entry.max_interval);
    if !(4..=1_800).contains(&max) {
        return Err(format!("{at}: max-interval must be 4 to 1800 seconds"));
    }
    if min < 3 || u64::from(min) * 4 > u64::from(max) * 3 {
        return Err(format!(
            "{at}: min-interval must be 3 seconds to 0.75 of max-interval"
        ));
    }
    let lifetime = entry.router_lifetime;
    if lifetime != 0 && !(max..=9_000).contains(&lifetime) {
        return Err(format!(
            "{at}: router-lifetime must be 0 or max-interval to 9000 seconds"
        ));
    }
    if entry.reachable_time > 3_600_000 {
        return Err(format!("{at}: reachable-time must be at most 3600000 ms"));
    }
    match entry.mtu[..] {
        [] => {}
        [mtu] if (1_280..=interface.mtu).contains(&mtu) => {}
        [_] => {
            return Err(format!(
                "{at}: mtu must be 1280 to the interface's MTU, {}",
                interface.mtu
            ))
        }
        _ => return Err(format!("{at}: mtu takes at most one value")),
    }
    if entry.dns.len() > DNS_MAX {
        return Err(format!("{at}: dns takes at most {DNS_MAX} addresses"));
    }
    for text in &entry.dns {
        let usable = text
            .parse::<Ipv6Addr>()
            .is_ok_and(|a| !a.is_multicast() && !a.is_unspecified() && !a.is_loopback());
        if !usable {
            return Err(format!("{at}: dns {text:?} must be a unicast IPv6 address"));
        }
    }
    if !entry.dns.is_empty() && entry.dns_lifetime < max {
        return Err(format!("{at}: dns-lifetime must be at least max-interval"));
    }
    // The delegated /64 confd adds at run time is the interface's ipv6-from.
    for source in &entry.prefix_from {
        if interface.ipv6_from.as_ref().map(|(s, _)| s) != Some(source) {
            return Err(format!(
                "{at}: prefix-from {source:?} must be the source of the interface's ipv6-from"
            ));
        }
    }
    if entry.prefix.len() > PREFIX_MAX {
        return Err(format!("{at}: give at most {PREFIX_MAX} prefixes"));
    }
    let mut seen = BTreeSet::new();
    for prefix in &entry.prefix {
        let at = format!("{at}: prefix {:?}", prefix.prefix);
        let (address, len) = prefix
            .prefix
            .split_once('/')
            .and_then(|(a, l)| Some((a.parse::<Ipv6Addr>().ok()?, l.parse::<u8>().ok()?)))
            .filter(|&(a, len)| len <= 128 && network(IpAddr::V6(a), len) == IpAddr::V6(a))
            .ok_or_else(|| {
                format!("{at}: must be like 2001:db8:1::/64, with no bits after its length")
            })?;
        if address.is_unicast_link_local() || address.is_multicast() {
            return Err(format!("{at}: must not be link-local or multicast"));
        }
        if !seen.insert((address, len)) {
            return Err(format!("{at}: given twice"));
        }
        let ours = interface
            .ipv6
            .iter()
            .any(|&(a, l)| l == len && network(IpAddr::V6(a), len) == IpAddr::V6(address));
        if !ours {
            return Err(format!(
                "{at}: must be the prefix of one of the interface's addresses"
            ));
        }
        if prefix.autonomous && len != 64 {
            return Err(format!("{at}: an autonomous prefix must be a /64"));
        }
        if prefix.preferred_lifetime > prefix.valid_lifetime {
            return Err(format!(
                "{at}: preferred-lifetime must not be above valid-lifetime"
            ));
        }
    }
    Ok(())
}

//! Checks `[[bgp]]` of the lock form: BGP in the default VRF, which FRR's bgpd
//! speaks. confd hands it to `ruster-frr` in the `frr` part ([`crate::part`]) with
//! the prefixes of the default VRF's interfaces ([`connected`]), from which
//! `ruster-frr` finds the interface of each next hop FRR gives.
//!
//! # Standards
//!
//! - RFC 4271 section 4.2 and RFC 6793: AS numbers are 4 octets; 0 (RFC 7607) and
//!   23456 (AS_TRANS, RFC 6793 section 9) and 4294967295 (RFC 7300) are not used as the router's or a
//!   neighbor's.
//! - RFC 6286 section 2.1: the BGP Identifier is a non-zero 32-bit number, written
//!   as an IPv4 address.
//! - RFC 4760: a session carries the unicast routes of its neighbor's address family
//!   (IPv4 or IPv6).
//!
//! Deviations: only the default VRF; each neighbor must be on the subnet of one of
//! the default VRF's interfaces (no multihop sessions), so that its next hops are on
//! a link the FE knows; so link-local IPv6 neighbors are not taken either.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use ruster_config::{Bgp, Connected};
use ruster_proto::table::{network, DEFAULT_VRF};

use crate::InterfaceConfig;

/// The most neighbors and announced prefixes.
const NEIGHBORS_MAX: usize = 64;
const NETWORKS_MAX: usize = 256;
/// The longest description FRR takes.
const DESCRIPTION_MAX: usize = 80;
/// The longest include path.
const PATH_MAX: usize = 4_096;
/// AS_TRANS (RFC 6793).
const AS_TRANS: u32 = 23_456;

/// Checks `bgp` (none or one) against the interfaces.
pub(crate) fn check(
    entries: Vec<Bgp>,
    interfaces: &[InterfaceConfig],
) -> Result<Option<Bgp>, String> {
    if entries.len() > 1 {
        return Err("give at most one bgp".into());
    }
    let Some(bgp) = entries.into_iter().next() else {
        return Ok(None);
    };
    let at = "bgp";
    check_as(at, "as", bgp.asn)?;
    let id: Ipv4Addr = bgp
        .router_id
        .parse()
        .map_err(|_| format!("{at}: router-id must be an IPv4 address"))?;
    if id.is_unspecified() {
        return Err(format!("{at}: router-id must not be 0.0.0.0"));
    }
    if bgp.networks.len() > NETWORKS_MAX {
        return Err(format!("{at}: give at most {NETWORKS_MAX} networks"));
    }
    let mut networks = BTreeSet::new();
    for text in &bgp.networks {
        let (address, len) = crate::file::prefix(text)
            .filter(|&(a, len)| network(a, len) == a && unicast(a))
            .ok_or_else(|| {
                format!("{at}: network {text:?} must be a unicast prefix with no host bits")
            })?;
        if !networks.insert((address, len)) {
            return Err(format!("{at}: network {text:?} is given twice"));
        }
    }
    match bgp.include.as_slice() {
        [] => {}
        [path]
            if path.starts_with('/')
                && !path.ends_with('/')
                && path.len() <= PATH_MAX
                && !has_control(path) => {}
        [_] => {
            return Err(format!(
                "{at}: include must be an absolute file path of at most {PATH_MAX} bytes, \
                 without control characters"
            ))
        }
        _ => return Err(format!("{at}: include takes at most one path")),
    }
    if bgp.neighbor.len() > NEIGHBORS_MAX {
        return Err(format!("{at}: give at most {NEIGHBORS_MAX} neighbors"));
    }
    let connected = connected(interfaces);
    let mut seen = BTreeSet::new();
    for neighbor in &bgp.neighbor {
        let at = format!("bgp neighbor {:?}", neighbor.address);
        let address: IpAddr = neighbor
            .address
            .parse()
            .map_err(|_| format!("{at}: not an IP address"))?;
        if !seen.insert(address) {
            return Err(format!("{at}: given twice"));
        }
        check_as(&at, "remote-as", neighbor.remote_as)?;
        if is_own(address, interfaces) {
            return Err(format!("{at}: it is one of the router's addresses"));
        }
        // On the subnet, and not its network or (IPv4) broadcast address.
        let on_link = connected.iter().any(|c| {
            crate::file::prefix(&c.prefix).is_some_and(|(n, len)| {
                let max = if n.is_ipv4() { 32 } else { 128 };
                let broadcast = match (address, n) {
                    (IpAddr::V4(a), IpAddr::V4(_)) if len < 31 => {
                        u32::from(a) | (u32::MAX >> len) == u32::from(a)
                    }
                    _ => false,
                };
                n.is_ipv4() == address.is_ipv4()
                    && network(address, len) == n
                    && (address != n || len >= max - 1)
                    && !broadcast
            })
        });
        if !on_link {
            return Err(format!(
                "{at}: must be on the subnet of an enabled interface of the default VRF"
            ));
        }
        match neighbor.description.as_slice() {
            [] => {}
            [text]
                if !text.starts_with(' ')
                    && !text.ends_with(' ')
                    && !text.is_empty()
                    && text.len() <= DESCRIPTION_MAX
                    && text.bytes().all(|b| (b' '..=b'~').contains(&b)) => {}
            [_] => {
                return Err(format!(
                    "{at}: description must be 1 to {DESCRIPTION_MAX} printable ASCII characters, not starting or ending with a space"
                ))
            }
            _ => return Err(format!("{at}: description takes at most one text")),
        }
    }
    Ok(Some(bgp))
}

fn check_as(at: &str, what: &str, asn: u32) -> Result<(), String> {
    if asn == 0 || asn == AS_TRANS || asn == u32::MAX {
        return Err(format!(
            "{at}: {what} must not be 0, 23456 (AS_TRANS) or 4294967295"
        ));
    }
    Ok(())
}

/// Not multicast, loopback or link-local: a prefix worth announcing.
fn unicast(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(a) => !a.is_multicast() && !a.is_loopback() && !a.is_link_local(),
        IpAddr::V6(a) => !a.is_multicast() && !a.is_loopback() && !a.is_unicast_link_local(),
    }
}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

/// Whether `address` is one of the router's own.
fn is_own(address: IpAddr, interfaces: &[InterfaceConfig]) -> bool {
    interfaces.iter().any(|i| {
        i.ipv4.is_some_and(|(a, _)| IpAddr::V4(a) == address)
            || i.ipv6.iter().any(|&(a, _)| IpAddr::V6(a) == address)
    })
}

/// The IPv4 and global IPv6 prefixes of the enabled ports, VLANs and tunnels of the
/// default VRF (a PPPoE session's address is found at run time, so it has none
/// here).
pub fn connected(interfaces: &[InterfaceConfig]) -> Vec<Connected> {
    let mut out = Vec::new();
    for interface in interfaces
        .iter()
        .filter(|i| i.enabled && i.vrf == DEFAULT_VRF && i.pppoe.is_none())
    {
        let prefixes = interface
            .ipv4
            .map(|(a, len)| (IpAddr::V4(a), len))
            .into_iter()
            .chain(
                interface
                    .ipv6
                    .iter()
                    .filter(|(a, _)| !a.is_unicast_link_local())
                    .map(|&(a, len)| (IpAddr::V6(a), len)),
            );
        for (address, len) in prefixes {
            out.push(Connected {
                interface: interface.name.clone(),
                prefix: format!("{}/{len}", network(address, len)),
                link_local: crate::link_local(interface.mac).to_string(),
            });
        }
    }
    out
}

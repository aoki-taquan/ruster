//! What the client writes: each lease's values to its confd source
//! (`confd/source/<name>.sock`), and the default routes to ribd as the route source
//! `dhcpc` (`docs/design/ce-processes.md`, "送り手").
//!
//! The values carry [`LIFETIME`] and are sent again every [`REFRESH_MS`], so they
//! last while the client runs and run out about a minute after it stops; the
//! lease's own end is the client's to keep ([`crate::client4`],
//! [`crate::client6`]), which deletes them then.
//!
//! # Standards
//!
//! - RFC 2132 section 3.5: the IPv4 default route goes to the first address of the
//!   router option (when it is in the leased address's subnet).
//! - RFC 8415 section 21.22: the delegated prefix is sent with the lifetimes the
//!   server gave.
//!
//! Deviations: the IPv6 default route goes to the address the DHCPv6 replies came
//! from (the ISP's server or relay on the link), not to a router learned from
//! Router Advertisements, which ruster does not read on the WAN side. An IA_NA
//! address is sent as a /128 (RFC 8415 section 21.6 gives no prefix length). A
//! DNS server, prefix or address confd would refuse (not unicast, or a link-local
//! prefix) is left out. The IPv4 default route needs a router in the leased
//! subnet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ruster_proto::table::{network, Change, Key, NextHop, RouteAction, Value, SOURCE_DNS_MAX};

use crate::{client4, client6};

/// How long a value sent to confd lasts, in seconds.
pub const LIFETIME: u32 = 60;
/// How often the values are sent to confd again.
pub const REFRESH_MS: u64 = 20_000;

fn dns(source: &str, servers: Vec<IpAddr>) -> Change {
    let key = Key::SourceDns {
        source: source.to_owned(),
    };
    let mut unique: Vec<IpAddr> = Vec::new();
    for server in servers.into_iter().filter(|&a| usable(a)) {
        if !unique.contains(&server) && unique.len() < SOURCE_DNS_MAX {
            unique.push(server);
        }
    }
    let servers = unique;
    if servers.is_empty() {
        return Change::delete(key);
    }
    Change::set(
        key,
        Value::SourceDns {
            servers,
            lifetime: LIFETIME,
        },
    )
}

/// An address confd takes from a source: unicast (RFC 1122 section 3.2.1.3, RFC
/// 4291 section 2.4), and for a prefix or IA_NA address not link-local. Anything
/// else is left out, so that one bad value does not make confd refuse the rest.
fn usable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => {
            let first = a.octets()[0];
            first != 0 && first != 127 && first < 224
        }
        IpAddr::V6(a) => !(a.is_unspecified() || a.is_loopback() || a.is_multicast()),
    }
}

fn global(address: Ipv6Addr) -> bool {
    usable(address.into()) && !address.is_unicast_link_local()
}

/// A DHCPv4 lease's values for its source: set while bound, deleted when not.
pub fn values4(source: &str, lease: Option<&client4::Lease>) -> Vec<Change> {
    let address = Key::SourceIpv4 {
        source: source.to_owned(),
    };
    let Some(lease) = lease else {
        return vec![Change::delete(address), dns(source, Vec::new())];
    };
    vec![
        Change::set(
            address,
            Value::SourceIpv4 {
                address: lease.address,
                prefix_len: lease.prefix_len,
                lifetime: LIFETIME,
            },
        ),
        dns(source, lease.dns.iter().map(|&a| a.into()).collect()),
    ]
}

/// A DHCPv6 lease's values for its source: set while bound, deleted when not.
pub fn values6(source: &str, lease: Option<&client6::Lease>) -> Vec<Change> {
    let prefix_key = Key::SourcePrefix {
        source: source.to_owned(),
    };
    let address_key = Key::SourceIpv6 {
        source: source.to_owned(),
    };
    let prefix = lease.and_then(|l| l.prefix).filter(|p| global(p.prefix));
    let address = lease.and_then(|l| l.address).filter(|a| global(a.address));
    vec![
        match prefix {
            Some(p) => Change::set(
                prefix_key,
                Value::SourcePrefix {
                    prefix: p.prefix,
                    prefix_len: p.len,
                    preferred: p.preferred,
                    valid: p.valid,
                    lifetime: LIFETIME,
                },
            ),
            None => Change::delete(prefix_key),
        },
        match address {
            Some(a) => Change::set(
                address_key,
                Value::SourceIpv6 {
                    address: a.address,
                    prefix_len: 128,
                    lifetime: LIFETIME,
                },
            ),
            None => Change::delete(address_key),
        },
        dns(
            source,
            lease.map_or_else(Vec::new, |l| l.dns.iter().map(|&a| a.into()).collect()),
        ),
    ]
}

fn default_key(vrf: &str, family: IpAddr) -> Key {
    Key::Route {
        vrf: vrf.to_owned(),
        prefix: family,
        len: 0,
    }
}

/// The IPv4 default route of a lease: out of `interface` to the first router in
/// the leased subnet.
pub fn route4(vrf: &str, interface: &str, lease: Option<&client4::Lease>) -> Change {
    let key = default_key(vrf, Ipv4Addr::UNSPECIFIED.into());
    let router = lease.and_then(|lease| {
        let subnet = network(lease.address.into(), lease.prefix_len);
        lease
            .routers
            .iter()
            .find(|r| network((**r).into(), lease.prefix_len) == subnet && **r != lease.address)
            .copied()
    });
    match router {
        Some(router) => Change::set(key, forward(interface, router.into())),
        None => Change::delete(key),
    }
}

/// The IPv6 default route of a DHCPv6 lease: out of `interface` to `via`, the
/// link-local address the replies came from.
pub fn route6(vrf: &str, interface: &str, via: Option<Ipv6Addr>) -> Change {
    let key = default_key(vrf, Ipv6Addr::UNSPECIFIED.into());
    match via.filter(Ipv6Addr::is_unicast_link_local) {
        Some(via) => Change::set(key, forward(interface, via.into())),
        None => Change::delete(key),
    }
}

fn forward(interface: &str, via: IpAddr) -> Value {
    Value::Route(RouteAction::Forward(vec![NextHop {
        interface: interface.to_owned(),
        address: Some(via),
    }]))
}

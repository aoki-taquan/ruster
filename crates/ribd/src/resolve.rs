//! Resolving next hops that a source gives only as gateway addresses
//! ([`RouteAction::Gateways`], a BGP route's NEXT_HOP), to the outgoing interface and
//! the next hop on that link that the FE needs.
//!
//! ribd resolves every gateway route each time it works out what the FE should
//! hold, from the routes selected at that time. So when a route that a resolution
//! went through changes or goes, the routes resolved through it change with it.
//!
//! The rules, for a gateway route `R` in VRF `V`:
//!
//! 1. Each gateway is looked up by longest prefix match in the routes selected for
//!    `V`, and only there (no other VRF). The match is the one route the gateway
//!    can be resolved through; a less specific route is never tried instead.
//! 2. If the match is `R` itself, the gateway cannot be resolved: once `R` were in
//!    the FE, packets to the gateway would follow `R` (RFC 4271 section 9.1.2.1, a
//!    NEXT_HOP that "would become unresolvable if the route was installed").
//! 3. A match with next hops that name their interface resolves the gateway: each
//!    of its next hops gives the interface, and its address, or the gateway itself
//!    when it has none (the gateway is on that link).
//! 4. A match that is itself a gateway route gives the next hops that it resolves
//!    to. If it resolves to none, the gateway cannot be resolved either.
//! 5. Gateway routes that match each other's gateways in a loop are resolved only
//!    through their gateways that lead out of the loop. A gateway whose match is in
//!    the same loop cannot be resolved: following it would come back to `R`.
//! 6. A gateway whose match goes through [`DEPTH_MAX`] gateway routes already
//!    (counting the match) cannot be resolved.
//! 7. A local, discard, reject or other-VRF route as the match: the gateway cannot
//!    be resolved.
//! 8. The default route (prefix length 0) is used only when ribd is told to
//!    (`--resolve-via-default`); otherwise the gateway cannot be resolved, as RIBs
//!    usually do (FRR's `ip nht resolve-via-default`).
//!
//! A route keeps the next hops its gateways resolve to, without duplicates, in the
//! order of its gateways. A route none of whose gateways resolves is not given to
//! the FE (and is deleted there if it was).
//!
//! The result depends only on the selected routes, not on the order they are
//! worked through. Each distinct gateway is looked up once; the loops are found as
//! the strongly connected components of the gateway routes (Tarjan), so the work
//! grows with the number of routes and gateways.
//!
//! # Standards
//!
//! - RFC 4271 section 5.1.3: a NEXT_HOP that is not on a shared link is resolved
//!   through the routing table to the immediate next hop and the interface.
//! - RFC 4271 section 9.1.2.1: a route whose NEXT_HOP cannot be resolved, or would
//!   become unresolvable once the route were installed, is not used.
//!
//! Deviations: the result is not given back to the source (BGP's next hop tracking
//! comes from FRR's zebra, which sees only the kernel's routes), so BGP may choose
//! a path that ribd then cannot resolve. A gateway route that resolves to nothing
//! still hides less specific routes from the gateways it matches (rule 4), where a
//! RIB that falls back to them would resolve more; and a gateway into a loop is not
//! used even when the route it matches resolves out of the loop (rule 5). Both
//! leave a route out rather than risk a loop.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use ruster_proto::table::{network, Key, NextHop, RouteAction, Value};

/// The most gateway routes one resolution goes through, the route itself included.
pub const DEPTH_MAX: usize = 8;

/// What one gateway matched.
#[derive(Clone, Copy)]
enum Match<'a> {
    /// Nothing it can be resolved through.
    None,
    /// A route with next hops that name their interface.
    Hops(&'a [NextHop]),
    /// The gateway route with this index.
    Gateway(usize),
}

/// Replaces each gateway route in `selected` with the next hops it resolves to, or
/// removes it when it resolves to none.
pub fn resolve(selected: &mut BTreeMap<Key, Value>, via_default: bool) {
    let results = resolved(selected, via_default);
    for (key, hops) in results {
        if hops.is_empty() {
            selected.remove(&key);
        } else {
            selected.insert(key, Value::Route(RouteAction::Forward(hops)));
        }
    }
}

/// Each gateway route of `routes`, and the next hops it resolves to.
fn resolved(routes: &BTreeMap<Key, Value>, via_default: bool) -> Vec<(Key, Vec<NextHop>)> {
    let nodes: Vec<(&Key, &[IpAddr])> = routes
        .iter()
        .filter_map(|(key, value)| match value {
            Value::Route(RouteAction::Gateways(gateways)) => Some((key, gateways.as_slice())),
            _ => None,
        })
        .collect();
    let index: HashMap<&Key, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, (k, _))| (*k, i))
        .collect();
    let mut found: HashMap<(&str, IpAddr), Option<&Key>> = HashMap::new();
    let edges: Vec<Vec<(IpAddr, Match)>> = nodes
        .iter()
        .enumerate()
        .map(|(i, (key, gateways))| {
            let Key::Route { vrf, .. } = key else {
                return Vec::new();
            };
            gateways
                .iter()
                .map(|&gateway| {
                    let hit = *found
                        .entry((vrf.as_str(), gateway))
                        .or_insert_with(|| longest_match(routes, vrf, gateway, via_default));
                    let to = match hit.map(|k| (k, &routes[k])) {
                        Some((_, Value::Route(RouteAction::Forward(hops)))) => Match::Hops(hops),
                        Some((k, Value::Route(RouteAction::Gateways(_)))) if index[k] != i => {
                            Match::Gateway(index[k])
                        }
                        _ => Match::None,
                    };
                    (gateway, to)
                })
                .collect()
        })
        .collect();

    let components = components(&edges);
    let mut component = vec![0; nodes.len()];
    for (c, members) in components.iter().enumerate() {
        for &n in members {
            component[n] = c;
        }
    }
    // Components come out after every component they reach, so the gateway routes
    // a component goes through are done before it. `depth` is how many gateway
    // routes a route's resolution goes through, itself included; 0 for none.
    let mut hops: Vec<Vec<NextHop>> = vec![Vec::new(); nodes.len()];
    let mut depth = vec![0_usize; nodes.len()];
    for members in &components {
        for &n in members {
            let mut out: Vec<NextHop> = Vec::new();
            let mut deepest = 0;
            for &(gateway, to) in &edges[n] {
                let add: Vec<NextHop> = match to {
                    Match::None => continue,
                    Match::Hops(through) => through
                        .iter()
                        .map(|hop| NextHop {
                            interface: hop.interface.clone(),
                            address: Some(hop.address.unwrap_or(gateway)),
                        })
                        .collect(),
                    Match::Gateway(m) => {
                        if component[m] == component[n] || depth[m] == 0 || depth[m] >= DEPTH_MAX {
                            continue;
                        }
                        deepest = deepest.max(depth[m]);
                        hops[m].clone()
                    }
                };
                for hop in add {
                    if !out.contains(&hop) {
                        out.push(hop);
                    }
                }
            }
            if !out.is_empty() {
                depth[n] = deepest + 1;
            }
            hops[n] = out;
        }
    }
    nodes
        .into_iter()
        .zip(hops)
        .map(|((key, _), hops)| (key.clone(), hops))
        .collect()
}

/// The longest match for `gateway` among `routes` of `vrf`, if it is one that may
/// resolve a gateway (not the default route unless `via_default`).
fn longest_match<'a>(
    routes: &'a BTreeMap<Key, Value>,
    vrf: &str,
    gateway: IpAddr,
    via_default: bool,
) -> Option<&'a Key> {
    let max: u8 = if gateway.is_ipv4() { 32 } else { 128 };
    let mut probe = Key::Route {
        vrf: vrf.to_owned(),
        prefix: gateway,
        len: max,
    };
    for len in (1..=max).rev().chain(via_default.then_some(0)) {
        if let Key::Route {
            prefix, len: at, ..
        } = &mut probe
        {
            *prefix = network(gateway, len);
            *at = len;
        }
        if let Some((key, _)) = routes.get_key_value(&probe) {
            return Some(key);
        }
    }
    None
}

/// The strongly connected components of the graph of gateway routes (Tarjan's
/// algorithm, without recursion), each after every component it reaches.
fn components(edges: &[Vec<(IpAddr, Match)>]) -> Vec<Vec<usize>> {
    const UNSEEN: usize = usize::MAX;
    let n = edges.len();
    let mut order = vec![UNSEEN; n];
    let mut low = vec![0; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut out: Vec<Vec<usize>> = Vec::new();
    let mut next = 0;
    for root in 0..n {
        if order[root] != UNSEEN {
            continue;
        }
        // (node, how many of its targets were looked at)
        let mut walk: Vec<(usize, usize)> = vec![(root, 0)];
        order[root] = next;
        low[root] = next;
        next += 1;
        stack.push(root);
        on_stack[root] = true;
        while let Some(&mut (v, ref mut seen)) = walk.last_mut() {
            if let Some(&(_, to)) = edges[v].get(*seen) {
                *seen += 1;
                let Match::Gateway(w) = to else {
                    continue;
                };
                if order[w] == UNSEEN {
                    order[w] = next;
                    low[w] = next;
                    next += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    walk.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(order[w]);
                }
                continue;
            }
            walk.pop();
            if let Some(&(parent, _)) = walk.last() {
                low[parent] = low[parent].min(low[v]);
            }
            if low[v] == order[v] {
                let mut members = Vec::new();
                while let Some(w) = stack.pop() {
                    on_stack[w] = false;
                    members.push(w);
                    if w == v {
                        break;
                    }
                }
                out.push(members);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(text: &str) -> Key {
        let (prefix, len) = text.split_once('/').unwrap();
        Key::Route {
            vrf: "default".into(),
            prefix: prefix.parse().unwrap(),
            len: len.parse().unwrap(),
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn dev(interface: &str, via: Option<&str>) -> Value {
        Value::Route(RouteAction::Forward(vec![NextHop {
            interface: interface.into(),
            address: via.map(ip),
        }]))
    }

    fn gateways(list: &[&str]) -> Value {
        Value::Route(RouteAction::Gateways(list.iter().map(|g| ip(g)).collect()))
    }

    fn hop(interface: &str, via: &str) -> NextHop {
        NextHop {
            interface: interface.into(),
            address: Some(ip(via)),
        }
    }

    fn resolved(routes: &[(&str, Value)], via_default: bool) -> BTreeMap<Key, Value> {
        let mut map: BTreeMap<Key, Value> =
            routes.iter().map(|(k, v)| (key(k), v.clone())).collect();
        resolve(&mut map, via_default);
        map
    }

    fn hops(map: &BTreeMap<Key, Value>, at: &str) -> Option<Vec<NextHop>> {
        match map.get(&key(at))? {
            Value::Route(RouteAction::Forward(hops)) => Some(hops.clone()),
            other => panic!("{at}: {other:?}"),
        }
    }

    #[test]
    fn a_gateway_on_a_link_is_the_next_hop_on_that_link() {
        let map = resolved(
            &[
                ("198.51.100.0/24", dev("wan", None)),
                ("203.0.113.0/24", gateways(&["198.51.100.10"])),
            ],
            false,
        );
        assert_eq!(
            hops(&map, "203.0.113.0/24"),
            Some(vec![hop("wan", "198.51.100.10")])
        );
        assert_eq!(
            hops(&map, "198.51.100.0/24"),
            Some(vec![NextHop {
                interface: "wan".into(),
                address: None
            }])
        );
    }

    #[test]
    fn a_gateway_behind_a_static_route_and_another_gateway_route() {
        // 203.0.113.0/24 via 10.255.0.2, reached by a static route; 192.0.2.0/24
        // via an address in 203.0.113.0/24, two gateway routes deep.
        let map = resolved(
            &[
                ("198.51.100.0/24", dev("wan", None)),
                ("10.255.0.2/32", dev("wan", Some("198.51.100.10"))),
                ("203.0.113.0/24", gateways(&["10.255.0.2"])),
                ("192.0.2.0/24", gateways(&["203.0.113.7"])),
            ],
            false,
        );
        let want = Some(vec![hop("wan", "198.51.100.10")]);
        assert_eq!(hops(&map, "203.0.113.0/24"), want);
        assert_eq!(hops(&map, "192.0.2.0/24"), want);
    }

    #[test]
    fn the_longest_match_wins_and_every_gateway_counts() {
        let map = resolved(
            &[
                ("10.0.0.0/8", dev("a", Some("192.168.1.1"))),
                ("10.1.0.0/16", dev("b", Some("192.168.2.1"))),
                ("192.168.1.0/24", dev("a", None)),
                ("192.168.2.0/24", dev("b", None)),
                (
                    "172.16.0.0/12",
                    gateways(&["10.1.2.3", "10.9.9.9", "10.1.0.1"]),
                ),
            ],
            false,
        );
        assert_eq!(
            hops(&map, "172.16.0.0/12"),
            Some(vec![hop("b", "192.168.2.1"), hop("a", "192.168.1.1")])
        );
    }

    #[test]
    fn an_unresolvable_gateway_is_left_out_and_a_route_with_none_is_not_installed() {
        let map = resolved(
            &[
                ("198.51.100.0/24", dev("wan", None)),
                ("203.0.113.0/24", gateways(&["192.0.2.1", "198.51.100.10"])),
                ("192.0.2.0/24", gateways(&["192.0.2.99"])),
            ],
            false,
        );
        assert_eq!(
            hops(&map, "203.0.113.0/24"),
            Some(vec![hop("wan", "198.51.100.10")])
        );
        assert_eq!(hops(&map, "192.0.2.0/24"), None);
    }

    #[test]
    fn a_route_is_not_resolved_through_itself_nor_a_less_specific_route_under_it() {
        // The gateway is in the route's own prefix: once installed the route would
        // carry the packets to its own gateway, so the /8 is not used either.
        let map = resolved(
            &[
                ("10.0.0.0/8", dev("wan", Some("198.51.100.10"))),
                ("10.1.0.0/16", gateways(&["10.1.0.1"])),
            ],
            false,
        );
        assert_eq!(hops(&map, "10.1.0.0/16"), None);
        assert!(hops(&map, "10.0.0.0/8").is_some());
    }

    #[test]
    fn the_default_route_is_used_only_when_told() {
        let routes = [
            ("0.0.0.0/0", dev("wan", Some("198.51.100.1"))),
            ("203.0.113.0/24", gateways(&["10.255.0.2"])),
        ];
        assert_eq!(hops(&resolved(&routes, false), "203.0.113.0/24"), None);
        assert_eq!(
            hops(&resolved(&routes, true), "203.0.113.0/24"),
            Some(vec![hop("wan", "198.51.100.1")])
        );
    }

    #[test]
    fn local_discard_and_reject_routes_resolve_nothing() {
        for action in [
            RouteAction::Local,
            RouteAction::Discard,
            RouteAction::Reject,
        ] {
            let map = resolved(
                &[
                    ("10.0.0.0/8", dev("wan", Some("198.51.100.10"))),
                    ("10.1.0.0/16", Value::Route(action.clone())),
                    ("203.0.113.0/24", gateways(&["10.1.0.1"])),
                ],
                false,
            );
            assert_eq!(hops(&map, "203.0.113.0/24"), None, "{action:?}");
        }
    }

    #[test]
    fn gateway_routes_in_a_loop_resolve_only_out_of_it_whatever_the_order() {
        // A via an address in B, B via an address in A: neither, and the /8 under
        // both is not used instead.
        for with_wider in [false, true] {
            let mut routes = vec![
                ("10.1.0.0/16", gateways(&["10.2.0.1"])),
                ("10.2.0.0/16", gateways(&["10.1.0.1"])),
            ];
            if with_wider {
                routes.push(("10.0.0.0/8", dev("wan", Some("198.51.100.10"))));
            }
            let map = resolved(&routes, false);
            assert_eq!(hops(&map, "10.1.0.0/16"), None);
            assert_eq!(hops(&map, "10.2.0.0/16"), None);
        }

        // A also has a gateway on a link: A resolves through that one only, and B,
        // whose one gateway leads back into the loop, not at all; whichever sorts
        // first, and with the /8 there too.
        for (a, b) in [
            ("10.1.0.0/16", "10.2.0.0/16"),
            ("10.2.0.0/16", "10.1.0.0/16"),
        ] {
            let first = a.replace(".0.0/16", ".0.1");
            let second = b.replace(".0.0/16", ".0.1");
            let map = resolved(
                &[
                    ("10.0.0.0/8", dev("wan", Some("198.51.100.10"))),
                    ("192.168.1.0/24", dev("lan", None)),
                    (a, gateways(&[&second, "192.168.1.1"])),
                    (b, gateways(&[&first])),
                    // Outside the loop, through A.
                    ("203.0.113.0/24", gateways(&[&first])),
                ],
                false,
            );
            let lan = Some(vec![hop("lan", "192.168.1.1")]);
            assert_eq!(hops(&map, a), lan, "{a}");
            assert_eq!(hops(&map, b), None, "{b}");
            assert_eq!(hops(&map, "203.0.113.0/24"), lan);
        }
    }

    #[test]
    fn a_gateway_route_that_resolves_to_nothing_is_not_passed_over() {
        let map = resolved(
            &[
                ("10.0.0.0/8", dev("wan", Some("198.51.100.10"))),
                ("10.1.0.0/16", gateways(&["192.0.2.1"])),
                ("203.0.113.0/24", gateways(&["10.1.0.1"])),
            ],
            false,
        );
        assert_eq!(hops(&map, "10.1.0.0/16"), None);
        assert_eq!(hops(&map, "203.0.113.0/24"), None);
    }

    #[test]
    fn resolution_stops_at_the_depth_limit_however_the_chain_sorts() {
        // A chain of gateway routes, each through the next, ending on a link. The
        // head sorts first, or last.
        let chain = |length: usize, head_first: bool| {
            let at = |i: usize| if head_first { i } else { length - 1 - i };
            let mut routes = vec![("192.168.1.0/24".to_owned(), dev("lan", None))];
            for i in 0..length {
                let gateway = if i + 1 == length {
                    "192.168.1.1".to_owned()
                } else {
                    format!("10.{}.0.1", at(i + 1))
                };
                routes.push((format!("10.{}.0.0/16", at(i)), gateways(&[&gateway])));
            }
            let mut map: BTreeMap<Key, Value> =
                routes.iter().map(|(k, v)| (key(k), v.clone())).collect();
            resolve(&mut map, false);
            (
                map,
                format!("10.{}.0.0/16", at(0)),
                format!("10.{}.0.0/16", at(1)),
            )
        };
        for head_first in [true, false] {
            let (map, head, _) = chain(DEPTH_MAX, head_first);
            assert!(hops(&map, &head).is_some());
            let (map, head, second) = chain(DEPTH_MAX + 1, head_first);
            assert_eq!(hops(&map, &head), None, "{head_first}");
            assert!(hops(&map, &second).is_some());
        }
    }

    #[test]
    fn many_gateway_routes_through_each_other_take_little_work() {
        // Each of 200 routes has gateways in every other one: one big loop, with
        // a way out only from the last.
        let n = 200;
        let mut map = BTreeMap::new();
        map.insert(key("192.168.1.0/24"), dev("lan", None));
        for i in 0..n {
            let mut list: Vec<IpAddr> = (0..n)
                .filter(|&j| j != i)
                .map(|j| IpAddr::from(Ipv4Addr::new(10, (j / 256) as u8, (j % 256) as u8, 1)))
                .collect();
            if i == n - 1 {
                list.push(ip("192.168.1.1"));
            }
            map.insert(
                Key::Route {
                    vrf: "default".into(),
                    prefix: Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 0).into(),
                    len: 24,
                },
                Value::Route(RouteAction::Gateways(list)),
            );
        }
        resolve(&mut map, false);
        assert_eq!(map.len(), 2, "the link, and the last route out of the loop");
    }

    #[test]
    fn an_ipv6_next_hop_is_resolved_the_same_way() {
        // RFC 4271 5.1.3 (and RFC 4760 for IPv6): a global NEXT_HOP on a connected
        // /64 is the immediate next hop; one reached through a static route takes
        // that route's next hop and interface.
        let map = resolved(
            &[
                ("2001:db8:1::/64", dev("wan", None)),
                ("2001:db8:ff::/48", dev("wan", Some("fe80::1"))),
                ("2001:db8:a::/48", gateways(&["2001:db8:1::2"])),
                ("2001:db8:b::/48", gateways(&["2001:db8:ff::9"])),
            ],
            false,
        );
        assert_eq!(
            hops(&map, "2001:db8:a::/48"),
            Some(vec![hop("wan", "2001:db8:1::2")])
        );
        assert_eq!(
            hops(&map, "2001:db8:b::/48"),
            Some(vec![hop("wan", "fe80::1")])
        );
    }

    #[test]
    fn a_host_route_through_its_own_address_is_not_used() {
        // RFC 4271 9.1.2.1: the NEXT_HOP would become unresolvable once the route
        // were installed (the /32 would carry the packets to its own gateway).
        let map = resolved(
            &[
                ("10.0.0.0/8", dev("wan", Some("198.51.100.10"))),
                ("10.1.2.3/32", gateways(&["10.1.2.3"])),
            ],
            false,
        );
        assert_eq!(hops(&map, "10.1.2.3/32"), None);
    }

    #[test]
    fn several_next_hops_of_the_match_are_all_kept_in_order() {
        // RFC 4271 5.1.3: the immediate next hops are those of the route the
        // NEXT_HOP resolves through; an ECMP static route gives all of them.
        let map = resolved(
            &[
                (
                    "10.255.0.0/16",
                    Value::Route(RouteAction::Forward(vec![
                        hop("a", "192.168.1.1"),
                        hop("b", "192.168.2.1"),
                    ])),
                ),
                ("203.0.113.0/24", gateways(&["10.255.0.2"])),
            ],
            false,
        );
        assert_eq!(
            hops(&map, "203.0.113.0/24"),
            Some(vec![hop("a", "192.168.1.1"), hop("b", "192.168.2.1")])
        );
    }

    #[test]
    fn routes_are_resolved_in_their_own_vrf_only() {
        let mut map = BTreeMap::new();
        map.insert(
            Key::Route {
                vrf: "blue".into(),
                prefix: Ipv4Addr::new(198, 51, 100, 0).into(),
                len: 24,
            },
            dev("wan-blue", None),
        );
        map.insert(key("203.0.113.0/24"), gateways(&["198.51.100.10"]));
        resolve(&mut map, false);
        assert_eq!(map.len(), 1);
    }
}

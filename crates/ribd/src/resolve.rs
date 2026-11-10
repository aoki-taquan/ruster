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
//!    `V`, and only there (no other VRF).
//! 2. If the match is `R` itself, the gateway cannot be resolved, and no less
//!    specific route is tried: once `R` were in the FE, packets to the gateway would
//!    follow `R`, a loop (RFC 4271 section 9.1.2.1, a NEXT_HOP that "would become
//!    unresolvable if the route was installed").
//! 3. A match with next hops that name their interface resolves the gateway: each
//!    of its next hops gives the interface, and its address, or the gateway itself
//!    when it has none (the gateway is on that link).
//! 4. A match that is itself a gateway route is resolved first, the same way, and
//!    its result is used. If it resolves to nothing, it would not be in the FE, so
//!    the next less specific route is tried, as if it were not there. A route met
//!    again while resolving it (a loop between gateway routes) counts as resolving
//!    to nothing; so does going deeper than [`DEPTH_MAX`] gateway routes.
//! 5. A local, discard, reject or other-VRF route stops the lookup: the gateway
//!    cannot be resolved.
//! 6. The default route (prefix length 0) is used only when ribd is told to
//!    (`--resolve-via-default`); otherwise reaching it means the gateway cannot be
//!    resolved, as RIBs usually do (FRR's `ip nht resolve-via-default`).
//!
//! A route keeps the next hops its gateways resolve to, without duplicates, in the
//! order of its gateways. A route none of whose gateways resolves is not given to
//! the FE (and is deleted there if it was).
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
//! a path that ribd then cannot resolve.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use ruster_proto::table::{network, Key, NextHop, RouteAction, Value};

/// The most gateway routes one resolution goes through, the route itself included.
pub const DEPTH_MAX: usize = 8;

/// Replaces each gateway route in `selected` with the next hops it resolves to, or
/// removes it when it resolves to none.
pub fn resolve(selected: &mut BTreeMap<Key, Value>, via_default: bool) {
    let routes = &*selected;
    let mut resolver = Resolver {
        routes,
        via_default,
        done: HashMap::new(),
    };
    let mut results = Vec::new();
    for (key, value) in routes {
        if matches!(value, Value::Route(RouteAction::Gateways(_))) {
            let (hops, _) = resolver.route(key, &mut Vec::new());
            results.push((key.clone(), hops));
        }
    }
    for (key, hops) in results {
        if hops.is_empty() {
            selected.remove(&key);
        } else {
            selected.insert(key, Value::Route(RouteAction::Forward(hops)));
        }
    }
}

struct Resolver<'a> {
    routes: &'a BTreeMap<Key, Value>,
    via_default: bool,
    /// Gateway routes already resolved, with results that did not depend on where
    /// the resolution started (no loop or depth limit met on the way).
    done: HashMap<&'a Key, Vec<NextHop>>,
}

impl<'a> Resolver<'a> {
    /// The next hops of the route at `key`, and whether the result depends on the
    /// gateway routes being resolved (`stack`) and so may not be kept.
    fn route(&mut self, key: &'a Key, stack: &mut Vec<&'a Key>) -> (Vec<NextHop>, bool) {
        if let Some(hops) = self.done.get(key) {
            return (hops.clone(), false);
        }
        let Some(Value::Route(RouteAction::Gateways(gateways))) = self.routes.get(key) else {
            return (Vec::new(), false);
        };
        if stack.contains(&key) || stack.len() >= DEPTH_MAX {
            return (Vec::new(), true);
        }
        let Key::Route { vrf, .. } = key else {
            return (Vec::new(), false);
        };
        stack.push(key);
        let mut hops: Vec<NextHop> = Vec::new();
        let mut depends = false;
        for &gateway in gateways {
            let (found, d) = self.gateway(vrf, gateway, key, stack);
            depends |= d;
            for hop in found {
                if !hops.contains(&hop) {
                    hops.push(hop);
                }
            }
        }
        stack.pop();
        if !depends {
            self.done.insert(key, hops.clone());
        }
        (hops, depends)
    }

    /// The next hops `gateway` resolves to for the route at `own`.
    fn gateway(
        &mut self,
        vrf: &str,
        gateway: IpAddr,
        own: &'a Key,
        stack: &mut Vec<&'a Key>,
    ) -> (Vec<NextHop>, bool) {
        let max: u8 = if gateway.is_ipv4() { 32 } else { 128 };
        let mut probe = Key::Route {
            vrf: vrf.to_owned(),
            prefix: gateway,
            len: max,
        };
        let mut depends = false;
        for len in (0..=max).rev() {
            if len == 0 && !self.via_default {
                break;
            }
            if let Key::Route {
                prefix, len: at, ..
            } = &mut probe
            {
                *prefix = network(gateway, len);
                *at = len;
            }
            let Some((key, Value::Route(action))) = self.routes.get_key_value(&probe) else {
                continue;
            };
            if key == own {
                break;
            }
            match action {
                RouteAction::Forward(through) => {
                    let hops = through
                        .iter()
                        .map(|hop| NextHop {
                            interface: hop.interface.clone(),
                            address: Some(hop.address.unwrap_or(gateway)),
                        })
                        .collect();
                    return (hops, depends);
                }
                RouteAction::Gateways(_) => {
                    let (hops, d) = self.route(key, stack);
                    depends |= d;
                    if !hops.is_empty() {
                        return (hops, depends);
                    }
                }
                RouteAction::Local
                | RouteAction::Discard
                | RouteAction::Reject
                | RouteAction::LookupVrf(_) => break,
            }
        }
        (Vec::new(), depends)
    }
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
    fn gateway_routes_in_a_loop_resolve_to_nothing_whatever_the_order() {
        // A via an address in B, B via an address in A.
        let map = resolved(
            &[
                ("10.1.0.0/16", gateways(&["10.2.0.1"])),
                ("10.2.0.0/16", gateways(&["10.1.0.1"])),
            ],
            false,
        );
        assert!(map.is_empty());

        // A also has a gateway on a link: A resolves through it, and B through A,
        // whichever is resolved first.
        for (a, b) in [
            ("10.1.0.0/16", "10.2.0.0/16"),
            ("10.2.0.0/16", "10.1.0.0/16"),
        ] {
            let first = a.replace(".0.0/16", ".0.1");
            let second = b.replace(".0.0/16", ".0.1");
            let map = resolved(
                &[
                    ("192.168.1.0/24", dev("lan", None)),
                    (a, gateways(&[&second, "192.168.1.1"])),
                    (b, gateways(&[&first])),
                ],
                false,
            );
            assert_eq!(hops(&map, a), Some(vec![hop("lan", "192.168.1.1")]), "{a}");
            assert_eq!(hops(&map, b), Some(vec![hop("lan", "192.168.1.1")]), "{b}");
        }
    }

    #[test]
    fn a_gateway_route_that_resolves_to_nothing_lets_a_less_specific_route_resolve() {
        let map = resolved(
            &[
                ("10.0.0.0/8", dev("wan", Some("198.51.100.10"))),
                ("10.1.0.0/16", gateways(&["192.0.2.1"])),
                ("203.0.113.0/24", gateways(&["10.1.0.1"])),
            ],
            false,
        );
        assert_eq!(hops(&map, "10.1.0.0/16"), None);
        assert_eq!(
            hops(&map, "203.0.113.0/24"),
            Some(vec![hop("wan", "198.51.100.10")])
        );
    }

    #[test]
    fn resolution_stops_at_the_depth_limit() {
        // A chain of gateway routes, each through the next, ending on a link.
        let chain = |length: usize| {
            let mut routes = vec![("192.168.1.0/24".to_owned(), dev("lan", None))];
            for i in 0..length {
                let gateway = if i + 1 == length {
                    "192.168.1.1".to_owned()
                } else {
                    format!("10.{}.0.1", i + 1)
                };
                routes.push((format!("10.{i}.0.0/16"), gateways(&[&gateway])));
            }
            let mut map: BTreeMap<Key, Value> =
                routes.iter().map(|(k, v)| (key(k), v.clone())).collect();
            resolve(&mut map, false);
            map
        };
        assert!(hops(&chain(DEPTH_MAX), "10.0.0.0/16").is_some());
        let map = chain(DEPTH_MAX + 1);
        assert_eq!(hops(&map, "10.0.0.0/16"), None);
        assert!(hops(&map, "10.1.0.0/16").is_some());
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

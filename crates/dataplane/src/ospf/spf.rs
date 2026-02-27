//! Shortest Path First (SPF) / Dijkstra algorithm for OSPF.
//!
//! Computes the shortest-path tree rooted at the local router using
//! the LSDB, then extracts routes for installation in the RIB.
//!
//! RFC-REF: RFC 2328 Section 16.1
//! "The shortest-path tree is computed using Dijkstra's algorithm."

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use super::lsdb::Lsdb;
use super::packet::{LsaBody, LINK_TYPE_P2P, LINK_TYPE_STUB, LINK_TYPE_TRANSIT};
use crate::routing::protocol::ProtocolSource;
use crate::routing::rib::RibEntry;

/// A route computed by the SPF algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfRoute {
    /// Destination prefix.
    pub prefix: [u8; 4],
    /// Prefix length.
    pub prefix_len: u8,
    /// Next-hop IP address toward the destination.
    pub next_hop: [u8; 4],
    /// Outgoing interface name.
    pub out_ifname: String,
    /// Total metric (cost) to reach this destination.
    pub cost: u32,
}

/// Result of an SPF computation.
#[derive(Debug, Clone)]
pub struct SpfResult {
    /// Routes computed from the SPF tree.
    pub routes: Vec<SpfRoute>,
}

/// SPF vertex: represents a node in the shortest-path tree.
#[derive(Debug, Clone)]
struct SpfVertex {
    /// Cost from the root to this vertex.
    cost: u32,
    /// Next-hop toward this vertex (None for root).
    next_hop: Option<[u8; 4]>,
    /// Outgoing interface toward this vertex (None for root).
    out_ifname: Option<String>,
}

/// Interface info passed to the SPF algorithm.
#[derive(Debug, Clone)]
pub struct SpfInterface {
    /// Interface name.
    pub name: String,
    /// Interface IP address.
    pub ip_addr: [u8; 4],
    /// Network mask.
    pub network_mask: [u8; 4],
    /// Neighbor IP addresses reachable through this interface
    /// and their Router IDs.
    pub neighbor_ips: Vec<([u8; 4], [u8; 4])>, // (router_id, ip_addr)
}

/// A stub network link discovered in a Router-LSA.
struct StubLink {
    /// Stub prefix.
    prefix: [u8; 4],
    /// Stub mask.
    mask: [u8; 4],
    /// Metric to the stub network.
    cost: u32,
}

/// Run the SPF algorithm on the LSDB.
///
/// RFC-REF: RFC 2328 Section 16.1
/// "The following algorithm is used to calculate the shortest-path
/// tree for an area."
///
/// This is a minimal Dijkstra implementation that processes
/// Router-LSAs only (Network-LSA transit support is simplified).
///
/// RFC-DEVIATION:
/// reason: Network-LSAs and transit network SPF are simplified.
///         We only process Router-LSA stub links and point-to-point
///         links for route computation.
/// impact: Transit networks with DR will not be optimally routed.
/// issue: #157
/// plan: Add full Network-LSA SPF processing in a future version.
pub fn run_spf(lsdb: &Lsdb, our_router_id: [u8; 4], interfaces: &[SpfInterface]) -> SpfResult {
    // Build adjacency graph from Router-LSAs.
    // Map: router_id -> Vec<(neighbor_router_id, cost)>
    let mut adj: HashMap<[u8; 4], Vec<([u8; 4], u32)>> = HashMap::new();
    // Map: router_id -> Vec<StubLink>
    let mut stubs: HashMap<[u8; 4], Vec<StubLink>> = HashMap::new();

    for lsa in lsdb.router_lsas() {
        let router_id = lsa.header.advertising_router;
        if let LsaBody::Router(rlsa) = &lsa.body {
            for link in &rlsa.links {
                match link.link_type {
                    LINK_TYPE_P2P => {
                        // Point-to-point link to another router.
                        adj.entry(router_id)
                            .or_default()
                            .push((link.link_id, link.metric as u32));
                    }
                    LINK_TYPE_TRANSIT => {
                        // Transit network — link_id is the DR's IP.
                        // For simplicity, we treat transit links similarly
                        // to P2P by looking up the DR's network-LSA.
                        adj.entry(router_id)
                            .or_default()
                            .push((link.link_id, link.metric as u32));
                    }
                    LINK_TYPE_STUB => {
                        // Stub network.
                        stubs.entry(router_id).or_default().push(StubLink {
                            prefix: link.link_id,
                            mask: link.link_data,
                            cost: link.metric as u32,
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    // Build a lookup map: router_id -> interface IP and name for
    // determining next-hop for directly connected neighbors.
    let mut neighbor_to_iface: HashMap<[u8; 4], (String, [u8; 4])> = HashMap::new();
    for iface in interfaces {
        for (nbr_router_id, nbr_ip) in &iface.neighbor_ips {
            neighbor_to_iface.insert(*nbr_router_id, (iface.name.clone(), *nbr_ip));
        }
    }

    // Dijkstra's algorithm.
    // Priority queue: (cost, router_id)
    let mut dist: HashMap<[u8; 4], SpfVertex> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(u32, [u8; 4])>> = BinaryHeap::new();

    // Root vertex.
    dist.insert(
        our_router_id,
        SpfVertex {
            cost: 0,
            next_hop: None,
            out_ifname: None,
        },
    );
    heap.push(Reverse((0, our_router_id)));

    while let Some(Reverse((cost, vertex_id))) = heap.pop() {
        // Skip if we already found a shorter path.
        if let Some(existing) = dist.get(&vertex_id) {
            if cost > existing.cost {
                continue;
            }
        }

        // Explore neighbors.
        if let Some(neighbors) = adj.get(&vertex_id) {
            for &(nbr_id, link_cost) in neighbors {
                let new_cost = cost + link_cost;

                let should_update = match dist.get(&nbr_id) {
                    Some(existing) => new_cost < existing.cost,
                    None => true,
                };

                if should_update {
                    // Determine next-hop.
                    let (next_hop, out_ifname) = if vertex_id == our_router_id {
                        // Direct neighbor: use the neighbor's IP as next-hop.
                        if let Some((iface_name, nbr_ip)) = neighbor_to_iface.get(&nbr_id) {
                            (Some(*nbr_ip), Some(iface_name.clone()))
                        } else {
                            // Neighbor not directly connected — skip.
                            continue;
                        }
                    } else {
                        // Inherit next-hop from parent vertex.
                        let parent = dist.get(&vertex_id).unwrap();
                        (parent.next_hop, parent.out_ifname.clone())
                    };

                    dist.insert(
                        nbr_id,
                        SpfVertex {
                            cost: new_cost,
                            next_hop,
                            out_ifname,
                        },
                    );
                    heap.push(Reverse((new_cost, nbr_id)));
                }
            }
        }
    }

    // Extract routes from stub networks.
    let mut routes = Vec::new();

    for (router_id, stub_list) in &stubs {
        if let Some(vertex) = dist.get(router_id) {
            for stub in stub_list {
                let total_cost = vertex.cost + stub.cost;
                let prefix_len = mask_to_prefix_len(&stub.mask);

                // Skip our own directly connected networks.
                if *router_id == our_router_id {
                    continue;
                }

                if let (Some(nh), Some(ref ifname)) = (vertex.next_hop, &vertex.out_ifname) {
                    routes.push(SpfRoute {
                        prefix: stub.prefix,
                        prefix_len,
                        next_hop: nh,
                        out_ifname: ifname.clone(),
                        cost: total_cost,
                    });
                }
            }
        }
    }

    SpfResult { routes }
}

/// Convert SPF routes to RIB entries.
pub fn spf_routes_to_rib(routes: &[SpfRoute]) -> Vec<RibEntry> {
    routes
        .iter()
        .map(|r| RibEntry {
            prefix: r.prefix,
            prefix_len: r.prefix_len,
            next_hop: r.next_hop,
            out_ifname: r.out_ifname.clone(),
            metric: r.cost,
            source: ProtocolSource::Ospf,
            admin_distance: ProtocolSource::Ospf.default_admin_distance(),
        })
        .collect()
}

/// Convert a network mask to a prefix length.
fn mask_to_prefix_len(mask: &[u8; 4]) -> u8 {
    let mask_u32 = u32::from_be_bytes(*mask);
    mask_u32.leading_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ospf::lsdb::{Lsdb, INITIAL_SEQUENCE_NUMBER};
    use crate::ospf::packet::{
        Lsa, LsaBody, LsaHeader, LsaType, RouterLink, RouterLsa, LINK_TYPE_P2P, LINK_TYPE_STUB,
    };

    fn make_router_lsa_with_links(router_id: [u8; 4], links: Vec<RouterLink>) -> Lsa {
        let num_links = links.len();
        Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaType::Router as u8,
                link_state_id: router_id,
                advertising_router: router_id,
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: (20 + 4 + num_links * 12) as u16,
            },
            body: LsaBody::Router(RouterLsa { flags: 0, links }),
        }
    }

    fn p2p_link(neighbor_id: [u8; 4], iface_ip: [u8; 4], metric: u16) -> RouterLink {
        RouterLink {
            link_id: neighbor_id,
            link_data: iface_ip,
            link_type: LINK_TYPE_P2P,
            num_tos: 0,
            metric,
        }
    }

    fn stub_link(prefix: [u8; 4], mask: [u8; 4], metric: u16) -> RouterLink {
        RouterLink {
            link_id: prefix,
            link_data: mask,
            link_type: LINK_TYPE_STUB,
            num_tos: 0,
            metric,
        }
    }

    // ── mask_to_prefix_len tests ────────────────────────────────────

    #[test]
    fn mask_to_prefix_len_common() {
        assert_eq!(mask_to_prefix_len(&[255, 255, 255, 0]), 24);
        assert_eq!(mask_to_prefix_len(&[255, 255, 0, 0]), 16);
        assert_eq!(mask_to_prefix_len(&[255, 0, 0, 0]), 8);
        assert_eq!(mask_to_prefix_len(&[0, 0, 0, 0]), 0);
        assert_eq!(mask_to_prefix_len(&[255, 255, 255, 255]), 32);
        assert_eq!(mask_to_prefix_len(&[255, 255, 255, 128]), 25);
    }

    // ── Simple 2-node topology ──────────────────────────────────────
    //
    //  R1 (1.1.1.1) ---[cost 10]--- R2 (2.2.2.2)
    //       |                            |
    //  10.0.0.0/24 (stub)          192.168.1.0/24 (stub)

    #[test]
    fn spf_two_node_topology() {
        let mut lsdb = Lsdb::new();

        // R1's Router-LSA.
        let r1_lsa = make_router_lsa_with_links(
            [1, 1, 1, 1],
            vec![
                p2p_link([2, 2, 2, 2], [10, 0, 0, 1], 10),
                stub_link([10, 0, 0, 0], [255, 255, 255, 0], 1),
            ],
        );
        lsdb.install(r1_lsa, 0);

        // R2's Router-LSA.
        let r2_lsa = make_router_lsa_with_links(
            [2, 2, 2, 2],
            vec![
                p2p_link([1, 1, 1, 1], [10, 0, 0, 2], 10),
                stub_link([192, 168, 1, 0], [255, 255, 255, 0], 1),
            ],
        );
        lsdb.install(r2_lsa, 0);

        let interfaces = vec![SpfInterface {
            name: "eth0".to_string(),
            ip_addr: [10, 0, 0, 1],
            network_mask: [255, 255, 255, 0],
            neighbor_ips: vec![([2, 2, 2, 2], [10, 0, 0, 2])],
        }];

        let result = run_spf(&lsdb, [1, 1, 1, 1], &interfaces);

        // R1 should learn about R2's stub network 192.168.1.0/24.
        assert_eq!(result.routes.len(), 1);
        let route = &result.routes[0];
        assert_eq!(route.prefix, [192, 168, 1, 0]);
        assert_eq!(route.prefix_len, 24);
        assert_eq!(route.next_hop, [10, 0, 0, 2]);
        assert_eq!(route.out_ifname, "eth0");
        assert_eq!(route.cost, 11); // 10 (P2P) + 1 (stub)
    }

    // ── 3-node linear topology ──────────────────────────────────────
    //
    //  R1 ---[10]--- R2 ---[10]--- R3
    //                                |
    //                           172.16.0.0/16 (stub)

    #[test]
    fn spf_three_node_linear() {
        let mut lsdb = Lsdb::new();

        let r1_lsa = make_router_lsa_with_links(
            [1, 1, 1, 1],
            vec![
                p2p_link([2, 2, 2, 2], [10, 0, 0, 1], 10),
                stub_link([10, 0, 0, 0], [255, 255, 255, 0], 1),
            ],
        );
        lsdb.install(r1_lsa, 0);

        let r2_lsa = make_router_lsa_with_links(
            [2, 2, 2, 2],
            vec![
                p2p_link([1, 1, 1, 1], [10, 0, 0, 2], 10),
                p2p_link([3, 3, 3, 3], [10, 0, 1, 1], 10),
                stub_link([10, 0, 1, 0], [255, 255, 255, 0], 1),
            ],
        );
        lsdb.install(r2_lsa, 0);

        let r3_lsa = make_router_lsa_with_links(
            [3, 3, 3, 3],
            vec![
                p2p_link([2, 2, 2, 2], [10, 0, 1, 2], 10),
                stub_link([172, 16, 0, 0], [255, 255, 0, 0], 5),
            ],
        );
        lsdb.install(r3_lsa, 0);

        let interfaces = vec![SpfInterface {
            name: "eth0".to_string(),
            ip_addr: [10, 0, 0, 1],
            network_mask: [255, 255, 255, 0],
            neighbor_ips: vec![([2, 2, 2, 2], [10, 0, 0, 2])],
        }];

        let result = run_spf(&lsdb, [1, 1, 1, 1], &interfaces);

        // Should learn: R2's stub (10.0.1.0/24), R3's stub (172.16.0.0/16).
        assert_eq!(result.routes.len(), 2);

        let r2_stub = result
            .routes
            .iter()
            .find(|r| r.prefix == [10, 0, 1, 0])
            .expect("should have R2's stub route");
        assert_eq!(r2_stub.cost, 11); // 10 + 1
        assert_eq!(r2_stub.next_hop, [10, 0, 0, 2]);

        let r3_stub = result
            .routes
            .iter()
            .find(|r| r.prefix == [172, 16, 0, 0])
            .expect("should have R3's stub route");
        assert_eq!(r3_stub.cost, 25); // 10 + 10 + 5
        assert_eq!(r3_stub.next_hop, [10, 0, 0, 2]); // via R2
    }

    // ── Empty LSDB ──────────────────────────────────────────────────

    #[test]
    fn spf_empty_lsdb() {
        let lsdb = Lsdb::new();
        let result = run_spf(&lsdb, [1, 1, 1, 1], &[]);
        assert!(result.routes.is_empty());
    }

    // ── spf_routes_to_rib test ──────────────────────────────────────

    #[test]
    fn spf_routes_convert_to_rib() {
        let routes = vec![SpfRoute {
            prefix: [192, 168, 1, 0],
            prefix_len: 24,
            next_hop: [10, 0, 0, 2],
            out_ifname: "eth0".to_string(),
            cost: 11,
        }];

        let rib_entries = spf_routes_to_rib(&routes);
        assert_eq!(rib_entries.len(), 1);
        assert_eq!(rib_entries[0].prefix, [192, 168, 1, 0]);
        assert_eq!(rib_entries[0].prefix_len, 24);
        assert_eq!(rib_entries[0].next_hop, [10, 0, 0, 2]);
        assert_eq!(rib_entries[0].source, ProtocolSource::Ospf);
        assert_eq!(rib_entries[0].admin_distance, 110);
        assert_eq!(rib_entries[0].metric, 11);
    }
}

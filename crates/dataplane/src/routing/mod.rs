//! IPv4 routing and L3 forwarding engine with RIB/FIB separation.
//!
//! This module implements the L3 forwarding decision pipeline:
//! 1. Extract IPv4 info from the packet (or drop non-IPv4).
//! 2. Check if the destination is one of our local IPs (local delivery).
//! 3. Verify TTL is sufficient for forwarding.
//! 4. Perform longest-prefix-match route lookup via the FIB.
//! 5. Return a forwarding decision with the decremented TTL.
//!
//! # Architecture: RIB / FIB separation
//!
//! The **RIB** (Routing Information Base) stores all routes from every
//! protocol source (static, connected, OSPF, BGP).  The **FIB**
//! (Forwarding Information Base) is derived from the RIB via best-path
//! selection and is optimized for LPM lookups in the forwarding path.
//!
//! New routing protocols can be added by implementing the
//! [`protocol::RoutingProtocol`] trait and injecting routes into the RIB
//! via [`L3Engine::update_rib`].
//!
//! # Validated-input contract
//!
//! [`L3Engine::from_config`] assumes its inputs have been validated by the
//! config layer.  It returns a [`Result`] so that any parse failures
//! (indicating a bug or unvalidated usage) surface immediately rather than
//! being silently dropped.
//!
//! RFC-REF: RFC 791 Section 3.2
//! "The internet module determines the destination address [...] and makes
//! a routing decision to forward the datagram to the next gateway or
//! directly to the destination host."

pub mod fib;
pub mod ipv6_table;
pub mod protocol;
pub mod rib;
pub mod table;

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::packet::{L3Info, PacketMeta};
use ruster_config::model::{InterfaceConfig, RoutingConfig};
use table::RouteError;

use fib::Fib;
use protocol::ProtocolSource;
use rib::{Rib, RibEntry};

/// Error returned when [`L3Engine::from_config`] encounters invalid
/// configuration entries (route table entries or local IP address strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L3ConfigError {
    /// One or more static route entries could not be parsed.
    InvalidRoutes(Vec<RouteError>),
    /// One or more interface IPv4 address strings could not be parsed.
    ///
    /// Each element is `(interface_name, raw_addr_string)`.
    InvalidLocalAddrs(Vec<(String, String)>),
}

impl fmt::Display for L3ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoutes(errs) => {
                write!(f, "invalid route entries: ")?;
                for (i, e) in errs.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
            Self::InvalidLocalAddrs(addrs) => {
                write!(f, "invalid local addresses: ")?;
                for (i, (iface, addr)) in addrs.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{iface}: \"{addr}\"")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for L3ConfigError {}

/// Reason an L3 packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3DropReason {
    /// The packet is not IPv4 (e.g. ARP-only, unknown EtherType).
    NotIpv4,
    /// TTL has expired (TTL <= 1); the packet cannot be forwarded.
    ///
    /// RFC-REF: RFC 791 Section 3.2
    /// "If this gateway determines that the time-to-live field is zero
    /// it must discard the datagram."
    TtlExpired,
    /// No route matched the destination address.
    NoRoute,
}

/// L3 forwarding decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L3Decision {
    /// Forward the packet to the next hop via the specified interface.
    Forward {
        /// Outgoing interface name.
        out_ifname: String,
        /// Next-hop IPv4 address.
        next_hop: [u8; 4],
        /// TTL after decrement (the caller must rewrite the IP header).
        ///
        /// RFC-REF: RFC 791 Section 3.2
        /// "The time-to-live is decremented at each point that the internet
        /// header is processed."
        new_ttl: u8,
    },
    /// The destination is one of our local IPs. Hand off to the
    /// upper-layer protocol handler (e.g. ICMP echo, TCP stack).
    LocalDelivery,
    /// Drop the packet with the given reason.
    Drop {
        /// Why the packet was dropped.
        reason: L3DropReason,
    },
}

/// The L3 forwarding engine.
///
/// Combines a RIB (all routes from all sources), a FIB (best-path
/// forwarding table), and local IP knowledge to make per-packet
/// forwarding decisions.
///
/// The RIB holds routes from static config, connected interfaces, and
/// (in future) dynamic protocols.  The FIB is derived from the RIB
/// and used for fast LPM lookups in the forwarding path.
#[derive(Debug)]
pub struct L3Engine {
    /// The Routing Information Base — all routes from all sources.
    rib: Rib,
    /// The Forwarding Information Base — best-path, LPM-optimized.
    fib: Fib,
    /// Set of IPv4 addresses assigned to our interfaces. Packets
    /// destined to any of these are handed to local delivery.
    local_ips: HashSet<[u8; 4]>,
    /// Map from interface name to its first IPv4 address.
    /// Used to source ICMP error messages from the correct router IP.
    iface_ips: HashMap<String, [u8; 4]>,
}

impl L3Engine {
    /// Build an L3 engine from configuration.
    ///
    /// Parses static routes from `routing_config` into the RIB, then
    /// derives the FIB.  Collects all IPv4 addresses from `interfaces`
    /// for local delivery checks.
    ///
    /// # Errors
    ///
    /// Returns an [`L3ConfigError`] if any route entry or local IP
    /// address string cannot be parsed.  Route errors are reported via
    /// [`L3ConfigError::InvalidRoutes`]; local address errors via
    /// [`L3ConfigError::InvalidLocalAddrs`].
    ///
    /// # Validated-input contract
    ///
    /// Callers that run config validation via `ruster-config` before
    /// reaching this point can expect `from_config` to always succeed.
    pub fn from_config(
        routing_config: &RoutingConfig,
        interfaces: &[InterfaceConfig],
    ) -> Result<Self, L3ConfigError> {
        // Parse and validate static routes via the shared helper.
        let rib_entries =
            parse_static_routes(routing_config).map_err(L3ConfigError::InvalidRoutes)?;

        let mut rib = Rib::new();
        for entry in rib_entries {
            rib.insert(entry);
        }

        // Collect local IPs, tracking any parse failures.
        let mut local_ips: HashSet<[u8; 4]> = HashSet::new();
        let mut iface_ips: HashMap<String, [u8; 4]> = HashMap::new();
        let mut addr_errors: Vec<(String, String)> = Vec::new();

        for iface in interfaces {
            for (idx, addr_str) in iface.ipv4_addrs.iter().enumerate() {
                match parse_ipv4_addr(addr_str) {
                    Some(ip) => {
                        local_ips.insert(ip);
                        // Store the first IPv4 address for each interface.
                        if idx == 0 {
                            iface_ips.insert(iface.name.clone(), ip);
                        }
                    }
                    None => {
                        addr_errors.push((iface.name.clone(), addr_str.clone()));
                    }
                }
            }
        }

        if !addr_errors.is_empty() {
            return Err(L3ConfigError::InvalidLocalAddrs(addr_errors));
        }

        // Build the FIB from the RIB.
        let fib = Fib::from_rib(&rib);

        Ok(Self {
            rib,
            fib,
            local_ips,
            iface_ips,
        })
    }

    /// Make a forwarding decision for the given packet.
    ///
    /// The pipeline is:
    /// 1. Extract IPv4 info; drop if not IPv4.
    /// 2. Check for local delivery (destination is one of our IPs).
    /// 3. Check TTL; drop if expired (TTL <= 1).
    /// 4. Perform LPM route lookup via the FIB; drop if no route.
    /// 5. Return `Forward` with the decremented TTL.
    pub fn process(&self, meta: &PacketMeta) -> L3Decision {
        // Step 1: Extract IPv4 info.
        let ipv4 = match &meta.l3 {
            Some(L3Info::Ipv4(info)) => info,
            _ => {
                return L3Decision::Drop {
                    reason: L3DropReason::NotIpv4,
                }
            }
        };

        // Step 2: Check for local delivery.
        if self.local_ips.contains(&ipv4.dst_addr) {
            return L3Decision::LocalDelivery;
        }

        // Step 3: Check TTL.
        // RFC-REF: RFC 791 Section 3.2
        // "If this gateway determines that the time-to-live field is zero
        // it must discard the datagram. [...] The gateway must also
        // decrement the time-to-live by at least one even if it forwards
        // the datagram without routing changes."
        if ipv4.ttl <= 1 {
            return L3Decision::Drop {
                reason: L3DropReason::TtlExpired,
            };
        }

        // Step 4: Route lookup (LPM) via the FIB.
        let fib_entry = match self.fib.lookup(&ipv4.dst_addr) {
            Some(entry) => entry,
            None => {
                return L3Decision::Drop {
                    reason: L3DropReason::NoRoute,
                }
            }
        };

        // Step 5: Forward with decremented TTL.
        L3Decision::Forward {
            out_ifname: fib_entry.out_ifname.clone(),
            next_hop: fib_entry.next_hop,
            new_ttl: ipv4.ttl - 1,
        }
    }

    /// Update the RIB with routes from a protocol source and rebuild
    /// the FIB.
    ///
    /// This first removes all existing routes from the given `source`,
    /// then inserts the new `entries`.  Finally, the FIB is rebuilt
    /// from the updated RIB.
    ///
    /// # Usage
    ///
    /// ```ignore
    /// // Future OSPF adapter pushes new routes:
    /// engine.update_rib(ospf_routes, ProtocolSource::Ospf);
    /// ```
    pub fn update_rib(&mut self, entries: Vec<RibEntry>, source: ProtocolSource) {
        // Remove old routes from this source.
        self.rib.remove_by_source(source);
        // Insert new routes.
        for entry in entries {
            self.rib.insert(entry);
        }
        // Rebuild the FIB.
        self.rebuild_fib();
    }

    /// Rebuild the FIB from the current RIB state.
    ///
    /// Called automatically after RIB mutations via [`Self::update_rib`].
    /// Can also be called directly if the RIB was mutated through
    /// direct access.
    pub fn rebuild_fib(&mut self) {
        self.fib = Fib::from_rib(&self.rib);
    }

    /// Returns a reference to the RIB.
    pub fn rib(&self) -> &Rib {
        &self.rib
    }

    /// Returns a reference to the FIB.
    pub fn fib(&self) -> &Fib {
        &self.fib
    }

    /// Return the router's IPv4 address for the given interface.
    ///
    /// Used as the source IP for ICMP error messages generated by the
    /// router in response to packets received on this interface.
    pub fn router_ip_for_iface(&self, ifname: &str) -> Option<[u8; 4]> {
        self.iface_ips.get(ifname).copied()
    }

    /// Check whether the given IPv4 address is one of the router's
    /// local (interface) addresses.
    ///
    /// Used by the L2 pipeline to decide whether a packet in a bridge
    /// domain should be handed off to L3 processing (local delivery)
    /// rather than being L2-forwarded/flooded.
    pub fn is_local_ip(&self, ip: &[u8; 4]) -> bool {
        self.local_ips.contains(ip)
    }
}

/// Parse static routes from a [`RoutingConfig`] into [`RibEntry`] values.
///
/// This is the shared helper used by both [`L3Engine::from_config`] and
/// (potentially) [`table::RouteTable::from_config`] so that route-parsing
/// logic is not duplicated.
///
/// Returns `Ok(entries)` on success, or `Err(errors)` listing every
/// invalid entry found.
fn parse_static_routes(config: &RoutingConfig) -> Result<Vec<RibEntry>, Vec<RouteError>> {
    let mut entries = Vec::with_capacity(config.ipv4_static_routes.len());
    let mut errors: Vec<RouteError> = Vec::new();

    for (index, sr) in config.ipv4_static_routes.iter().enumerate() {
        let prefix_result = table::parse_prefix(&sr.prefix);
        let next_hop_result = parse_ipv4_addr(&sr.next_hop);

        if prefix_result.is_none() {
            errors.push(RouteError {
                index,
                kind: table::RouteErrorKind::InvalidPrefix,
                raw_value: sr.prefix.clone(),
            });
        }
        if next_hop_result.is_none() {
            errors.push(RouteError {
                index,
                kind: table::RouteErrorKind::InvalidNextHop,
                raw_value: sr.next_hop.clone(),
            });
        }

        if let (Some((prefix, prefix_len)), Some(next_hop)) = (prefix_result, next_hop_result) {
            entries.push(RibEntry {
                prefix,
                prefix_len,
                next_hop,
                out_ifname: sr.out_if.clone(),
                metric: sr.metric,
                source: ProtocolSource::Static,
                admin_distance: ProtocolSource::Static.default_admin_distance(),
            });
        }
    }

    if errors.is_empty() {
        Ok(entries)
    } else {
        Err(errors)
    }
}

/// Parse an IPv4 address string, stripping an optional CIDR prefix length.
///
/// Accepts "192.168.1.1" or "192.168.1.1/24". Returns `None` if the
/// string cannot be parsed.
fn parse_ipv4_addr(addr_str: &str) -> Option<[u8; 4]> {
    let ip_part = addr_str.split('/').next()?;
    let parts: Vec<&str> = ip_part.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        ip[i] = part.parse::<u8>().ok()?;
    }
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Ipv4Info, L2Info, L3Info, PacketMeta};
    use ruster_config::model::{
        InterfaceConfig, InterfaceRole, InterfaceZone, RoutingConfig, StaticRoute,
    };

    // ── Test helpers ──────────────────────────────────────────────────

    fn make_routing_config() -> RoutingConfig {
        RoutingConfig {
            ipv4_static_routes: vec![
                StaticRoute {
                    prefix: "0.0.0.0/0".to_string(),
                    next_hop: "10.0.0.1".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
                StaticRoute {
                    prefix: "192.168.1.0/24".to_string(),
                    next_hop: "0.0.0.0".to_string(),
                    out_if: "lan0".to_string(),
                    metric: 10,
                },
            ],
            ipv6_static_routes: vec![],
        }
    }

    fn make_interfaces() -> Vec<InterfaceConfig> {
        vec![
            InterfaceConfig {
                name: "wan0".to_string(),
                port_id: 0,
                role: InterfaceRole::Wan,
                admin_up: true,
                mtu: 1500,
                mac: "00:11:22:33:44:55".to_string(),
                ipv4_addrs: vec!["10.0.0.2/24".to_string()],
                ipv6_addrs: vec![],
                zone: InterfaceZone::Wan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "lan0".to_string(),
                port_id: 1,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "00:AA:BB:CC:DD:EE".to_string(),
                ipv4_addrs: vec!["192.168.1.1/24".to_string()],
                ipv6_addrs: vec![],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
        ]
    }

    fn make_engine() -> L3Engine {
        L3Engine::from_config(&make_routing_config(), &make_interfaces()).unwrap()
    }

    fn make_ipv4_meta(
        in_ifname: &str,
        src_addr: [u8; 4],
        dst_addr: [u8; 4],
        ttl: u8,
    ) -> PacketMeta {
        PacketMeta {
            in_ifname: in_ifname.to_string(),
            l2: L2Info {
                dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                ethertype: 0x0800,
            },
            l3: Some(L3Info::Ipv4(Ipv4Info {
                src_addr,
                dst_addr,
                ttl,
                protocol: 6, // TCP
                header_len: 20,
                total_len: 40,
                identification: 1,
                flags: 0x40, // DF
                fragment_offset: 0,
                checksum: 0,
                payload_offset: 34,
            })),
            l4: None,
            raw_len: 54,
        }
    }

    fn make_non_ipv4_meta() -> PacketMeta {
        PacketMeta {
            in_ifname: "lan0".to_string(),
            l2: L2Info {
                dst_mac: [0xFF; 6],
                src_mac: [0xAA; 6],
                ethertype: 0x0806,
            },
            l3: None,
            l4: None,
            raw_len: 42,
        }
    }

    // ── L3Engine construction tests ───────────────────────────────────

    #[test]
    fn engine_from_config_collects_local_ips() {
        let engine = make_engine();
        assert!(engine.local_ips.contains(&[10, 0, 0, 2]));
        assert!(engine.local_ips.contains(&[192, 168, 1, 1]));
        assert!(!engine.local_ips.contains(&[8, 8, 8, 8]));
    }

    #[test]
    fn engine_from_config_loads_routes_into_rib() {
        let engine = make_engine();
        assert_eq!(engine.rib.len(), 2);
        assert_eq!(engine.fib.len(), 2);
    }

    #[test]
    fn engine_rib_contains_static_routes() {
        let engine = make_engine();
        let static_routes = engine.rib.routes_by_source(ProtocolSource::Static);
        assert_eq!(static_routes.len(), 2);
    }

    // ── Forwarding tests ──────────────────────────────────────────────

    #[test]
    fn forward_via_default_route() {
        let engine = make_engine();

        // Packet to 8.8.8.8 should go via default route (wan0, next_hop 10.0.0.1).
        let meta = make_ipv4_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let decision = engine.process(&meta);

        assert_eq!(
            decision,
            L3Decision::Forward {
                out_ifname: "wan0".to_string(),
                next_hop: [10, 0, 0, 1],
                new_ttl: 63,
            }
        );
    }

    #[test]
    fn forward_via_specific_route() {
        let engine = make_engine();

        // Packet to 192.168.1.50 should match the /24 LAN route.
        let meta = make_ipv4_meta("wan0", [10, 0, 0, 5], [192, 168, 1, 50], 128);
        let decision = engine.process(&meta);

        assert_eq!(
            decision,
            L3Decision::Forward {
                out_ifname: "lan0".to_string(),
                next_hop: [0, 0, 0, 0],
                new_ttl: 127,
            }
        );
    }

    // ── Local delivery tests ──────────────────────────────────────────

    #[test]
    fn local_delivery_wan_ip() {
        let engine = make_engine();

        // Packet destined to our WAN IP -> local delivery.
        let meta = make_ipv4_meta("wan0", [10, 0, 0, 5], [10, 0, 0, 2], 64);
        let decision = engine.process(&meta);

        assert_eq!(decision, L3Decision::LocalDelivery);
    }

    #[test]
    fn local_delivery_lan_ip() {
        let engine = make_engine();

        // Packet destined to our LAN IP -> local delivery.
        let meta = make_ipv4_meta("lan0", [192, 168, 1, 100], [192, 168, 1, 1], 64);
        let decision = engine.process(&meta);

        assert_eq!(decision, L3Decision::LocalDelivery);
    }

    // ── TTL expired tests ─────────────────────────────────────────────

    #[test]
    fn drop_ttl_expired_zero() {
        let engine = make_engine();

        // TTL = 0: should be dropped (in practice, parser may already
        // catch this, but the forwarding engine must also enforce it).
        let meta = make_ipv4_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 0);
        let decision = engine.process(&meta);

        assert_eq!(
            decision,
            L3Decision::Drop {
                reason: L3DropReason::TtlExpired,
            }
        );
    }

    #[test]
    fn drop_ttl_expired_one() {
        let engine = make_engine();

        // TTL = 1: after decrement would be 0, so drop.
        // RFC-REF: RFC 791 Section 3.2
        // "The gateway must [...] decrement the time-to-live by at least one."
        let meta = make_ipv4_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 1);
        let decision = engine.process(&meta);

        assert_eq!(
            decision,
            L3Decision::Drop {
                reason: L3DropReason::TtlExpired,
            }
        );
    }

    // ── No route tests ────────────────────────────────────────────────

    #[test]
    fn drop_no_route() {
        // Engine with no default route, only a /24 LAN route.
        let config = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "192.168.1.0/24".to_string(),
                next_hop: "0.0.0.0".to_string(),
                out_if: "lan0".to_string(),
                metric: 10,
            }],
            ipv6_static_routes: vec![],
        };
        let engine = L3Engine::from_config(&config, &make_interfaces()).unwrap();

        // Packet to 8.8.8.8 has no matching route.
        let meta = make_ipv4_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let decision = engine.process(&meta);

        assert_eq!(
            decision,
            L3Decision::Drop {
                reason: L3DropReason::NoRoute,
            }
        );
    }

    // ── Non-IPv4 tests ────────────────────────────────────────────────

    #[test]
    fn drop_not_ipv4() {
        let engine = make_engine();
        let meta = make_non_ipv4_meta();
        let decision = engine.process(&meta);

        assert_eq!(
            decision,
            L3Decision::Drop {
                reason: L3DropReason::NotIpv4,
            }
        );
    }

    #[test]
    fn drop_not_ipv4_arp() {
        let engine = make_engine();

        // ARP packet (has L3Info::Arp, not Ipv4).
        let meta = PacketMeta {
            in_ifname: "lan0".to_string(),
            l2: L2Info {
                dst_mac: [0xFF; 6],
                src_mac: [0xAA; 6],
                ethertype: 0x0806,
            },
            l3: Some(L3Info::Arp(crate::packet::ArpInfo {
                operation: 1,
                sender_mac: [0xAA; 6],
                sender_ip: [192, 168, 1, 100],
                target_mac: [0; 6],
                target_ip: [192, 168, 1, 1],
            })),
            l4: None,
            raw_len: 42,
        };

        let decision = engine.process(&meta);
        assert_eq!(
            decision,
            L3Decision::Drop {
                reason: L3DropReason::NotIpv4,
            }
        );
    }

    // ── Local delivery takes precedence over TTL ──────────────────────

    #[test]
    fn local_delivery_even_with_ttl_one() {
        let engine = make_engine();

        // Packet to our IP with TTL=1 should still be local delivery
        // (local delivery check happens before TTL check).
        let meta = make_ipv4_meta("lan0", [192, 168, 1, 100], [192, 168, 1, 1], 1);
        let decision = engine.process(&meta);

        assert_eq!(decision, L3Decision::LocalDelivery);
    }

    // ── Interface IP lookup tests ────────────────────────────────────

    #[test]
    fn router_ip_for_known_iface() {
        let engine = make_engine();
        assert_eq!(engine.router_ip_for_iface("wan0"), Some([10, 0, 0, 2]));
        assert_eq!(engine.router_ip_for_iface("lan0"), Some([192, 168, 1, 1]));
    }

    #[test]
    fn router_ip_for_unknown_iface() {
        let engine = make_engine();
        assert_eq!(engine.router_ip_for_iface("unknown"), None);
    }

    // ── RIB/FIB integration tests ────────────────────────────────────

    #[test]
    fn update_rib_adds_dynamic_routes() {
        let mut engine = make_engine();

        // Initially: 2 static routes.
        assert_eq!(engine.rib.len(), 2);

        // Inject OSPF routes.
        let ospf_routes = vec![RibEntry {
            prefix: [172, 16, 0, 0],
            prefix_len: 12,
            next_hop: [10, 0, 0, 3],
            out_ifname: "wan0".to_string(),
            metric: 50,
            source: ProtocolSource::Ospf,
            admin_distance: ProtocolSource::Ospf.default_admin_distance(),
        }];
        engine.update_rib(ospf_routes, ProtocolSource::Ospf);

        assert_eq!(engine.rib.len(), 3);
        assert_eq!(engine.fib.len(), 3);

        // New route should be in the FIB.
        let result = engine.fib.lookup(&[172, 16, 1, 1]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().next_hop, [10, 0, 0, 3]);
    }

    #[test]
    fn update_rib_replaces_source_routes() {
        let mut engine = make_engine();

        // Add OSPF route.
        engine.update_rib(
            vec![RibEntry {
                prefix: [172, 16, 0, 0],
                prefix_len: 12,
                next_hop: [10, 0, 0, 3],
                out_ifname: "wan0".to_string(),
                metric: 50,
                source: ProtocolSource::Ospf,
                admin_distance: ProtocolSource::Ospf.default_admin_distance(),
            }],
            ProtocolSource::Ospf,
        );
        assert_eq!(engine.rib.len(), 3);

        // Replace OSPF routes with a different set.
        engine.update_rib(
            vec![RibEntry {
                prefix: [10, 10, 0, 0],
                prefix_len: 16,
                next_hop: [10, 0, 0, 4],
                out_ifname: "wan0".to_string(),
                metric: 30,
                source: ProtocolSource::Ospf,
                admin_distance: ProtocolSource::Ospf.default_admin_distance(),
            }],
            ProtocolSource::Ospf,
        );

        // Old OSPF route should be gone, new one present.
        assert_eq!(engine.rib.len(), 3);
        assert!(engine.fib.lookup(&[172, 16, 1, 1]).is_some()); // falls through to default
        let result = engine.fib.lookup(&[10, 10, 1, 1]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().next_hop, [10, 0, 0, 4]);
    }

    #[test]
    fn admin_distance_selects_best_in_fib() {
        let mut engine = make_engine();

        // Add an OSPF default route with lower metric but higher AD.
        engine.update_rib(
            vec![RibEntry {
                prefix: [0, 0, 0, 0],
                prefix_len: 0,
                next_hop: [10, 0, 0, 99],
                out_ifname: "wan0".to_string(),
                metric: 1, // much lower metric
                source: ProtocolSource::Ospf,
                admin_distance: ProtocolSource::Ospf.default_admin_distance(), // AD=110
            }],
            ProtocolSource::Ospf,
        );

        // Static default route (AD=1) should still win over OSPF (AD=110).
        let meta = make_ipv4_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let decision = engine.process(&meta);
        assert_eq!(
            decision,
            L3Decision::Forward {
                out_ifname: "wan0".to_string(),
                next_hop: [10, 0, 0, 1], // static next_hop, not OSPF's
                new_ttl: 63,
            }
        );
    }

    #[test]
    fn static_and_dynamic_coexist_in_rib() {
        let mut engine = make_engine();

        // Add routes from multiple dynamic sources.
        engine.update_rib(
            vec![RibEntry {
                prefix: [172, 16, 0, 0],
                prefix_len: 12,
                next_hop: [10, 0, 0, 3],
                out_ifname: "wan0".to_string(),
                metric: 50,
                source: ProtocolSource::Ospf,
                admin_distance: ProtocolSource::Ospf.default_admin_distance(),
            }],
            ProtocolSource::Ospf,
        );
        engine.update_rib(
            vec![RibEntry {
                prefix: [172, 20, 0, 0],
                prefix_len: 14,
                next_hop: [10, 0, 0, 5],
                out_ifname: "wan0".to_string(),
                metric: 100,
                source: ProtocolSource::Bgp,
                admin_distance: ProtocolSource::Bgp.default_admin_distance(),
            }],
            ProtocolSource::Bgp,
        );

        // RIB has: 2 static + 1 OSPF + 1 BGP = 4
        assert_eq!(engine.rib.len(), 4);

        // All protocols' routes are reachable through FIB.
        assert_eq!(engine.fib.len(), 4);

        let static_routes = engine.rib.routes_by_source(ProtocolSource::Static);
        assert_eq!(static_routes.len(), 2);

        let ospf_routes = engine.rib.routes_by_source(ProtocolSource::Ospf);
        assert_eq!(ospf_routes.len(), 1);

        let bgp_routes = engine.rib.routes_by_source(ProtocolSource::Bgp);
        assert_eq!(bgp_routes.len(), 1);
    }

    #[test]
    fn fib_rebuild_removes_withdrawn_routes() {
        let mut engine = make_engine();

        // Add OSPF route.
        engine.update_rib(
            vec![RibEntry {
                prefix: [172, 16, 0, 0],
                prefix_len: 12,
                next_hop: [10, 0, 0, 3],
                out_ifname: "wan0".to_string(),
                metric: 50,
                source: ProtocolSource::Ospf,
                admin_distance: ProtocolSource::Ospf.default_admin_distance(),
            }],
            ProtocolSource::Ospf,
        );
        assert_eq!(engine.fib.len(), 3);

        // OSPF withdraws all routes (empty update).
        engine.update_rib(vec![], ProtocolSource::Ospf);
        assert_eq!(engine.fib.len(), 2); // only static routes remain
    }

    // ── Error handling (backward compatibility) ──────────────────────

    #[test]
    fn from_config_rejects_invalid_routes() {
        let config = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "invalid/24".to_string(),
                next_hop: "10.0.0.1".to_string(),
                out_if: "wan0".to_string(),
                metric: 100,
            }],
            ipv6_static_routes: vec![],
        };
        let result = L3Engine::from_config(&config, &make_interfaces());
        assert!(result.is_err());
        match result.unwrap_err() {
            L3ConfigError::InvalidRoutes(errs) => {
                assert_eq!(errs.len(), 1);
                assert_eq!(errs[0].kind, table::RouteErrorKind::InvalidPrefix);
            }
            other => panic!("expected InvalidRoutes, got {:?}", other),
        }
    }

    #[test]
    fn from_config_collects_all_errors() {
        let config = RoutingConfig {
            ipv4_static_routes: vec![
                StaticRoute {
                    prefix: "bad/99".to_string(),
                    next_hop: "also_bad".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
                StaticRoute {
                    prefix: "10.0.0.0/8".to_string(),
                    next_hop: "not_an_ip".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 50,
                },
            ],
            ipv6_static_routes: vec![],
        };
        let result = L3Engine::from_config(&config, &make_interfaces());
        assert!(result.is_err());
        match result.unwrap_err() {
            L3ConfigError::InvalidRoutes(errs) => {
                // Entry 0: invalid prefix AND invalid next_hop (2 errors).
                // Entry 1: valid prefix, invalid next_hop (1 error).
                assert_eq!(errs.len(), 3);
            }
            other => panic!("expected InvalidRoutes, got {:?}", other),
        }
    }
}

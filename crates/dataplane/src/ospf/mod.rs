//! OSPFv2 minimal implementation.
//!
//! This module provides a minimal-but-functional OSPFv2 routing
//! protocol engine for the ruster software router.  It handles:
//!
//! - Hello exchange and neighbor discovery
//! - Neighbor state machine (Down → Init → 2-Way → ExStart →
//!   Exchange → Loading → Full)
//! - Link State Database (LSDB) management
//! - SPF (Dijkstra) computation
//! - Route installation into the RIB/FIB
//!
//! # Architecture
//!
//! The [`OspfEngine`] is the top-level entry point.  It owns:
//! - A set of [`interface::OspfInterface`]s, each with its own
//!   neighbor list and Hello timer.
//! - A [`lsdb::Lsdb`] storing all LSAs for the backbone area.
//! - Configuration including the Router ID and area parameters.
//!
//! The engine integrates with the existing routing infrastructure
//! via [`crate::routing::L3Engine::update_rib`], pushing OSPF-computed
//! routes into the RIB with admin distance 110.
//!
//! # Limitations (v0.2)
//!
//! RFC-DEVIATION:
//! reason: This is a minimal implementation focused on correctness
//!         of the core state machine and SPF algorithm.
//! impact: The following features are not implemented:
//!         - DR/BDR election (all links treated as point-to-point)
//!         - Multi-area OSPF (backbone only)
//!         - Authentication (null auth only)
//!         - OSPF options negotiation
//!         - LSA retransmission / reliable flooding
//!         - Virtual links
//!         - NSSA / stub areas
//! issue: #157
//! plan: Incrementally add features in future issues.
//!
//! RFC-REF: RFC 2328
//! "OSPF Version 2" — the primary reference for this implementation.

pub mod config;
pub mod interface;
pub mod lsdb;
pub mod neighbor;
pub mod packet;
pub mod spf;

use config::OspfConfig;
use interface::OspfInterface;
use lsdb::{Lsdb, INITIAL_SEQUENCE_NUMBER};
use neighbor::NeighborEvent;
use packet::{HelloPacket, OspfHeader, OspfPacketType, OSPF_VERSION};
use spf::{SpfInterface, SpfRoute};

use crate::routing::rib::RibEntry;

/// The OSPF engine: top-level coordinator for OSPF protocol processing.
///
/// Manages interfaces, the LSDB, neighbor relationships, and
/// periodic tasks (Hello sending, dead-neighbor expiration, SPF).
#[derive(Debug)]
pub struct OspfEngine {
    /// Our Router ID.
    router_id: [u8; 4],
    /// OSPF interfaces.
    interfaces: Vec<OspfInterface>,
    /// Link State Database (backbone area).
    lsdb: Lsdb,
    /// Current LS sequence number for self-originated LSAs.
    ls_seq: u32,
    /// Whether a full SPF recomputation is needed.
    spf_needed: bool,
    /// Last computed routes from SPF.
    last_routes: Vec<SpfRoute>,
}

impl OspfEngine {
    /// Create a new OSPF engine from configuration.
    ///
    /// # Arguments
    ///
    /// * `config` — OSPF configuration (router ID, areas, interfaces).
    /// * `iface_ips` — Map of interface name to (IP, network mask) for
    ///   each interface that should participate in OSPF.
    pub fn new(config: &OspfConfig, iface_ips: &[(&str, [u8; 4], [u8; 4])]) -> Self {
        let mut interfaces = Vec::new();

        for area in &config.areas {
            for iface_config in &area.interfaces {
                // Look up the interface's IP and mask.
                if let Some(&(_, ip, mask)) = iface_ips
                    .iter()
                    .find(|&&(name, _, _)| name == iface_config.name)
                {
                    interfaces.push(OspfInterface::new(iface_config, ip, mask, area.id));
                }
            }
        }

        Self {
            router_id: config.router_id,
            interfaces,
            lsdb: Lsdb::new(),
            ls_seq: INITIAL_SEQUENCE_NUMBER,
            spf_needed: false,
            last_routes: Vec::new(),
        }
    }

    /// Return the Router ID.
    pub fn router_id(&self) -> [u8; 4] {
        self.router_id
    }

    /// Return a reference to the LSDB.
    pub fn lsdb(&self) -> &Lsdb {
        &self.lsdb
    }

    /// Return a reference to the interfaces.
    pub fn interfaces(&self) -> &[OspfInterface] {
        &self.interfaces
    }

    /// Return the last computed SPF routes.
    pub fn last_routes(&self) -> &[SpfRoute] {
        &self.last_routes
    }

    /// Bring all configured OSPF interfaces up.
    pub fn start(&mut self) {
        for iface in &mut self.interfaces {
            iface.up();
        }
        // Originate our initial Router-LSA.
        self.originate_router_lsa(0);
        self.spf_needed = true;
    }

    /// Bring all OSPF interfaces down and clear state.
    pub fn stop(&mut self) {
        for iface in &mut self.interfaces {
            iface.down();
        }
        self.lsdb = Lsdb::new();
        self.last_routes.clear();
        self.spf_needed = false;
    }

    /// Build a Hello packet for the given interface.
    ///
    /// RFC-REF: RFC 2328 Section 9.5
    /// "Hello packets are sent periodically on all interfaces."
    pub fn build_hello(&self, iface_name: &str) -> Option<HelloPacket> {
        let iface = self.interfaces.iter().find(|i| i.name == iface_name)?;
        if !iface.is_up() {
            return None;
        }

        // List all neighbor Router IDs that we have seen.
        let neighbors: Vec<[u8; 4]> = iface.neighbors.iter().map(|n| n.router_id).collect();

        Some(HelloPacket {
            header: OspfHeader {
                version: OSPF_VERSION,
                packet_type: OspfPacketType::Hello,
                packet_length: 0, // Set during serialization.
                router_id: self.router_id,
                area_id: iface.area_id,
                checksum: 0,
                auth_type: 0,
                auth_data: [0; 8],
            },
            network_mask: iface.network_mask,
            hello_interval: iface.hello_interval,
            options: 0x02, // E-bit (external routing capability)
            router_priority: 1,
            router_dead_interval: iface.dead_interval as u32,
            designated_router: [0; 4],
            backup_designated_router: [0; 4],
            neighbors,
        })
    }

    /// Process a received Hello packet.
    ///
    /// Returns the new neighbor state after processing.
    pub fn process_hello(
        &mut self,
        iface_name: &str,
        hello: &HelloPacket,
        source_ip: [u8; 4],
        now_secs: u64,
    ) -> Option<neighbor::NeighborState> {
        let iface = self.interfaces.iter_mut().find(|i| i.name == iface_name)?;
        let old_count = iface.full_neighbor_count();

        let state = iface.process_hello(hello, source_ip, self.router_id, now_secs);

        // If adjacency changed, schedule SPF recomputation.
        let new_count = iface.full_neighbor_count();
        if old_count != new_count {
            self.spf_needed = true;
        }

        Some(state)
    }

    /// Drive a neighbor to the next state (for adjacency formation).
    ///
    /// In a full implementation, this would be driven by DD/LSR/LSU
    /// exchange.  For the minimal implementation, this provides a
    /// way to manually progress the state machine.
    pub fn advance_neighbor(
        &mut self,
        iface_name: &str,
        router_id: &[u8; 4],
        event: NeighborEvent,
    ) -> Option<neighbor::NeighborState> {
        let iface = self.interfaces.iter_mut().find(|i| i.name == iface_name)?;
        let nbr = iface.get_neighbor_mut(router_id)?;
        let old_state = nbr.state;
        let new_state = nbr.handle_event(event);

        if old_state != new_state {
            self.spf_needed = true;
        }

        Some(new_state)
    }

    /// Install an LSA into the LSDB.
    ///
    /// Returns `true` if the LSA was installed (new or newer).
    pub fn install_lsa(&mut self, lsa: packet::Lsa, now_secs: u64) -> bool {
        let installed = self.lsdb.install(lsa, now_secs);
        if installed {
            self.spf_needed = true;
        }
        installed
    }

    /// Run periodic tasks: expire dead neighbors, age LSAs,
    /// recompute SPF if needed.
    ///
    /// Returns `true` if routes changed (caller should update the RIB).
    pub fn tick(&mut self, now_secs: u64) -> bool {
        // Expire dead neighbors.
        let mut neighbors_changed = false;
        for iface in &mut self.interfaces {
            let dead = iface.expire_dead_neighbors(now_secs);
            if !dead.is_empty() {
                neighbors_changed = true;
            }
        }
        if neighbors_changed {
            self.spf_needed = true;
        }

        // Age LSAs.
        let flushed = self.lsdb.age_lsas(now_secs);
        if !flushed.is_empty() {
            self.spf_needed = true;
        }

        // Re-originate our Router-LSA periodically.
        self.originate_router_lsa(now_secs);

        // Run SPF if needed.
        if self.spf_needed {
            self.run_spf();
            self.spf_needed = false;
            return true;
        }

        false
    }

    /// Get the list of interfaces that need to send Hello packets.
    pub fn interfaces_needing_hello(&self, now_secs: u64) -> Vec<String> {
        self.interfaces
            .iter()
            .filter(|i| i.should_send_hello(now_secs))
            .map(|i| i.name.clone())
            .collect()
    }

    /// Record that a Hello was sent on the given interface.
    pub fn mark_hello_sent(&mut self, iface_name: &str, now_secs: u64) {
        if let Some(iface) = self.interfaces.iter_mut().find(|i| i.name == iface_name) {
            iface.last_hello_sent = now_secs;
        }
    }

    /// Convert the last SPF routes to RIB entries for installation.
    pub fn routes_as_rib_entries(&self) -> Vec<RibEntry> {
        spf::spf_routes_to_rib(&self.last_routes)
    }

    /// Originate (or refresh) our Router-LSA.
    fn originate_router_lsa(&mut self, now_secs: u64) {
        let mut links = Vec::new();

        for iface in &self.interfaces {
            if !iface.is_up() {
                continue;
            }

            // Add a stub link for the interface's connected network.
            links.push(packet::RouterLink {
                link_id: apply_mask(&iface.ip_addr, &iface.network_mask),
                link_data: iface.network_mask,
                link_type: packet::LINK_TYPE_STUB,
                num_tos: 0,
                metric: 1, // Default cost.
            });

            // Add P2P links for each neighbor in Full state.
            for nbr in &iface.neighbors {
                if nbr.is_full() {
                    links.push(packet::RouterLink {
                        link_id: nbr.router_id,
                        link_data: iface.ip_addr,
                        link_type: packet::LINK_TYPE_P2P,
                        num_tos: 0,
                        metric: 10, // Default P2P cost.
                    });
                }
            }
        }

        let lsa = lsdb::originate_router_lsa(
            self.router_id,
            [0, 0, 0, 0], // backbone area
            links,
            self.ls_seq,
        );

        self.lsdb.install(lsa, now_secs);
        self.ls_seq = self.ls_seq.wrapping_add(1);
    }

    /// Run SPF and update the last_routes.
    fn run_spf(&mut self) {
        let spf_interfaces: Vec<SpfInterface> = self
            .interfaces
            .iter()
            .filter(|i| i.is_up())
            .map(|iface| SpfInterface {
                name: iface.name.clone(),
                ip_addr: iface.ip_addr,
                network_mask: iface.network_mask,
                neighbor_ips: iface
                    .neighbors
                    .iter()
                    .filter(|n| n.is_full())
                    .map(|n| (n.router_id, n.ip_addr))
                    .collect(),
            })
            .collect();

        let result = spf::run_spf(&self.lsdb, self.router_id, &spf_interfaces);
        self.last_routes = result.routes;
    }
}

/// Apply a network mask to an IP address.
fn apply_mask(ip: &[u8; 4], mask: &[u8; 4]) -> [u8; 4] {
    [
        ip[0] & mask[0],
        ip[1] & mask[1],
        ip[2] & mask[2],
        ip[3] & mask[3],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::protocol::ProtocolSource;
    use config::{AreaConfig, OspfConfig, OspfInterfaceConfig};
    use neighbor::NeighborState;

    fn make_config() -> OspfConfig {
        OspfConfig {
            router_id: [1, 1, 1, 1],
            areas: vec![AreaConfig {
                id: [0, 0, 0, 0],
                interfaces: vec![OspfInterfaceConfig {
                    name: "eth0".to_string(),
                    hello_interval: 10,
                    dead_interval: 40,
                }],
            }],
        }
    }

    fn make_engine() -> OspfEngine {
        let config = make_config();
        let iface_ips = vec![("eth0", [10, 0, 0, 1], [255, 255, 255, 0])];
        OspfEngine::new(&config, &iface_ips)
    }

    fn make_hello_from_neighbor(
        nbr_router_id: [u8; 4],
        our_in_list: bool,
        our_router_id: [u8; 4],
    ) -> HelloPacket {
        let mut neighbors = Vec::new();
        if our_in_list {
            neighbors.push(our_router_id);
        }
        HelloPacket {
            header: OspfHeader {
                version: OSPF_VERSION,
                packet_type: OspfPacketType::Hello,
                packet_length: 0,
                router_id: nbr_router_id,
                area_id: [0, 0, 0, 0],
                checksum: 0,
                auth_type: 0,
                auth_data: [0; 8],
            },
            network_mask: [255, 255, 255, 0],
            hello_interval: 10,
            options: 0x02,
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: [0; 4],
            backup_designated_router: [0; 4],
            neighbors,
        }
    }

    // ── Engine creation ─────────────────────────────────────────────

    #[test]
    fn engine_creation() {
        let engine = make_engine();
        assert_eq!(engine.router_id(), [1, 1, 1, 1]);
        assert_eq!(engine.interfaces().len(), 1);
        assert_eq!(engine.interfaces()[0].name, "eth0");
        assert!(engine.lsdb().is_empty());
    }

    // ── Start / stop ────────────────────────────────────────────────

    #[test]
    fn start_brings_interfaces_up() {
        let mut engine = make_engine();
        engine.start();
        assert!(engine.interfaces()[0].is_up());
        // Starting originates a Router-LSA.
        assert!(!engine.lsdb().is_empty());
    }

    #[test]
    fn stop_clears_state() {
        let mut engine = make_engine();
        engine.start();
        engine.stop();
        assert!(!engine.interfaces()[0].is_up());
        assert!(engine.lsdb().is_empty());
        assert!(engine.last_routes().is_empty());
    }

    // ── Hello building ──────────────────────────────────────────────

    #[test]
    fn build_hello_for_up_interface() {
        let mut engine = make_engine();
        engine.start();

        let hello = engine.build_hello("eth0");
        assert!(hello.is_some());
        let hello = hello.unwrap();
        assert_eq!(hello.header.router_id, [1, 1, 1, 1]);
        assert_eq!(hello.network_mask, [255, 255, 255, 0]);
        assert_eq!(hello.hello_interval, 10);
        assert_eq!(hello.router_dead_interval, 40);
    }

    #[test]
    fn build_hello_for_down_interface() {
        let engine = make_engine();
        // Interface is down — no Hello.
        assert!(engine.build_hello("eth0").is_none());
    }

    #[test]
    fn build_hello_unknown_interface() {
        let engine = make_engine();
        assert!(engine.build_hello("nonexistent").is_none());
    }

    // ── Hello processing ────────────────────────────────────────────

    #[test]
    fn process_hello_init() {
        let mut engine = make_engine();
        engine.start();

        let hello = make_hello_from_neighbor([2, 2, 2, 2], false, [1, 1, 1, 1]);
        let state = engine.process_hello("eth0", &hello, [10, 0, 0, 2], 100);
        assert_eq!(state, Some(NeighborState::Init));
    }

    #[test]
    fn process_hello_bidirectional() {
        let mut engine = make_engine();
        engine.start();

        // First Hello: one-directional.
        let hello = make_hello_from_neighbor([2, 2, 2, 2], false, [1, 1, 1, 1]);
        engine.process_hello("eth0", &hello, [10, 0, 0, 2], 100);

        // Second Hello: bidirectional (our ID in their list).
        let hello = make_hello_from_neighbor([2, 2, 2, 2], true, [1, 1, 1, 1]);
        let state = engine.process_hello("eth0", &hello, [10, 0, 0, 2], 101);
        assert_eq!(state, Some(NeighborState::ExStart));
    }

    // ── Neighbor advancement ────────────────────────────────────────

    #[test]
    fn advance_neighbor_to_full() {
        let mut engine = make_engine();
        engine.start();

        // Establish bidirectional.
        let hello = make_hello_from_neighbor([2, 2, 2, 2], true, [1, 1, 1, 1]);
        engine.process_hello("eth0", &hello, [10, 0, 0, 2], 100);

        // Drive through DD exchange.
        engine.advance_neighbor("eth0", &[2, 2, 2, 2], NeighborEvent::NegotiationDone);
        engine.advance_neighbor("eth0", &[2, 2, 2, 2], NeighborEvent::ExchangeDone);
        let state = engine.advance_neighbor("eth0", &[2, 2, 2, 2], NeighborEvent::LoadingDone);
        assert_eq!(state, Some(NeighborState::Full));
    }

    // ── Tick / SPF ──────────────────────────────────────────────────

    #[test]
    fn tick_runs_spf_when_needed() {
        let mut engine = make_engine();
        engine.start();

        // Force SPF by establishing a neighbor and installing an LSA.
        let hello = make_hello_from_neighbor([2, 2, 2, 2], true, [1, 1, 1, 1]);
        engine.process_hello("eth0", &hello, [10, 0, 0, 2], 100);
        engine.advance_neighbor("eth0", &[2, 2, 2, 2], NeighborEvent::NegotiationDone);
        engine.advance_neighbor("eth0", &[2, 2, 2, 2], NeighborEvent::ExchangeDone);
        engine.advance_neighbor("eth0", &[2, 2, 2, 2], NeighborEvent::LoadingDone);

        // Install R2's Router-LSA.
        let r2_lsa = packet::Lsa {
            header: packet::LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: packet::LsaType::Router as u8,
                link_state_id: [2, 2, 2, 2],
                advertising_router: [2, 2, 2, 2],
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 36,
            },
            body: packet::LsaBody::Router(packet::RouterLsa {
                flags: 0,
                links: vec![packet::RouterLink {
                    link_id: [192, 168, 1, 0],
                    link_data: [255, 255, 255, 0],
                    link_type: packet::LINK_TYPE_STUB,
                    num_tos: 0,
                    metric: 1,
                }],
            }),
        };
        engine.install_lsa(r2_lsa, 100);

        let routes_changed = engine.tick(101);
        assert!(routes_changed);

        // Should have a route to R2's stub network.
        let routes = engine.last_routes();
        assert!(!routes.is_empty());

        // Verify RIB entry conversion.
        let rib = engine.routes_as_rib_entries();
        assert!(!rib.is_empty());
        assert_eq!(rib[0].source, ProtocolSource::Ospf);
        assert_eq!(rib[0].admin_distance, 110);
    }

    // ── Dead neighbor expiration ────────────────────────────────────

    #[test]
    fn tick_expires_dead_neighbors() {
        let mut engine = make_engine();
        engine.start();

        // Establish neighbor.
        let hello = make_hello_from_neighbor([2, 2, 2, 2], true, [1, 1, 1, 1]);
        engine.process_hello("eth0", &hello, [10, 0, 0, 2], 100);

        // Wait beyond dead interval.
        let changed = engine.tick(200); // 100s > dead_interval(40)
        assert!(changed);

        // Neighbor should be gone.
        assert!(engine.interfaces()[0].neighbors.is_empty());
    }

    // ── Hello timing ────────────────────────────────────────────────

    #[test]
    fn interfaces_needing_hello() {
        let mut engine = make_engine();
        engine.start();
        engine.mark_hello_sent("eth0", 100);

        // Not yet time.
        assert!(engine.interfaces_needing_hello(105).is_empty());

        // Time to send.
        let needing = engine.interfaces_needing_hello(110);
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0], "eth0");
    }

    // ── apply_mask test ─────────────────────────────────────────────

    #[test]
    fn test_apply_mask() {
        assert_eq!(
            apply_mask(&[10, 0, 0, 1], &[255, 255, 255, 0]),
            [10, 0, 0, 0]
        );
        assert_eq!(
            apply_mask(&[192, 168, 1, 100], &[255, 255, 0, 0]),
            [192, 168, 0, 0]
        );
    }
}

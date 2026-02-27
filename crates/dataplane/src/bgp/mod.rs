//! BGP-4 minimal implementation (eBGP peer + IPv4 unicast).
//!
//! This module implements a minimal BGP-4 speaker for eBGP peering
//! with IPv4 unicast AFI/SAFI.  It provides:
//!
//! - OPEN/KEEPALIVE/UPDATE/NOTIFICATION message parsing and serialization
//! - BGP Finite State Machine (FSM) per peer
//! - Adj-RIB-In per peer with best-path selection
//! - Minimal import/export policy (prefix-list filter)
//! - Integration with the existing RIB/FIB infrastructure
//!
//! RFC-REF: RFC 4271 Section 1
//! "The primary function of a BGP speaking system is to exchange network
//! reachability information with other BGP systems."
//!
//! # Limitations (v0.2)
//!
//! RFC-DEVIATION:
//! reason: minimal eBGP-only implementation for home-lab use
//! impact: no iBGP, no route refresh, no graceful restart, no MP-BGP
//! issue: #158
//! plan: incrementally add iBGP and MP-BGP in v0.3+

pub mod config;
pub mod fsm;
pub mod packet;
pub mod path;
pub mod peer;
pub mod policy;
pub mod rib_in;

use std::collections::HashMap;

use config::{BgpConfigError, BgpEngineConfig};
use fsm::{FsmAction, FsmEvent};
use packet::{
    NotificationMessage, OpenMessage, UpdateMessage, BGP_VERSION, ERR_OPEN_MSG,
    OPEN_SUB_BAD_PEER_AS, OPEN_SUB_UNSUPPORTED_VERSION,
};
use path::compare_paths;
use peer::BgpPeer;
use policy::{ExportPolicy, ImportPolicy};
use rib_in::{AdjRibIn, AdjRibInEntry};

use crate::routing::protocol::ProtocolSource;
use crate::routing::rib::RibEntry;

/// The BGP engine managing all peer sessions and route processing.
///
/// Coordinates the FSMs, Adj-RIB-Ins, and policy evaluation for all
/// configured eBGP peers.  Produces RIB entries that can be installed
/// into the router's main RIB via [`BgpEngine::rib_entries`].
#[derive(Debug)]
pub struct BgpEngine {
    /// Local configuration (ASN, router-id, etc.).
    config: BgpEngineConfig,
    /// Per-peer state (FSM, stats).
    peers: HashMap<[u8; 4], BgpPeer>,
    /// Per-peer Adj-RIB-In.
    adj_rib_in: HashMap<[u8; 4], AdjRibIn>,
    /// Import policy applied to received routes.
    import_policy: ImportPolicy,
    /// Export policy applied to advertised routes.
    export_policy: ExportPolicy,
}

impl BgpEngine {
    /// Create a new BGP engine from parsed configuration.
    pub fn new(config: BgpEngineConfig) -> Self {
        let mut peers = HashMap::new();
        let mut adj_rib_in = HashMap::new();

        for peer_cfg in &config.peers {
            let peer = BgpPeer::new(peer_cfg.clone());
            peers.insert(peer_cfg.address, peer);
            adj_rib_in.insert(peer_cfg.address, AdjRibIn::new());
        }

        Self {
            config,
            peers,
            adj_rib_in,
            import_policy: ImportPolicy::permit_all(),
            export_policy: ExportPolicy::permit_all(),
        }
    }

    /// Create a BGP engine from the config model.
    ///
    /// # Errors
    ///
    /// Returns [`BgpConfigError`] if the config model cannot be parsed.
    pub fn from_model(cfg: &ruster_config::model::BgpConfig) -> Result<Self, BgpConfigError> {
        let engine_config = BgpEngineConfig::from_model(cfg)?;
        Ok(Self::new(engine_config))
    }

    /// Return the local AS number.
    pub fn local_as(&self) -> u32 {
        self.config.local_as
    }

    /// Return the local router-id.
    pub fn router_id(&self) -> [u8; 4] {
        self.config.router_id
    }

    /// Set the import policy.
    pub fn set_import_policy(&mut self, policy: ImportPolicy) {
        self.import_policy = policy;
    }

    /// Set the export policy.
    pub fn set_export_policy(&mut self, policy: ExportPolicy) {
        self.export_policy = policy;
    }

    /// Return a reference to a peer by address.
    pub fn peer(&self, addr: &[u8; 4]) -> Option<&BgpPeer> {
        self.peers.get(addr)
    }

    /// Return a mutable reference to a peer by address.
    pub fn peer_mut(&mut self, addr: &[u8; 4]) -> Option<&mut BgpPeer> {
        self.peers.get_mut(addr)
    }

    /// Return all peers.
    pub fn peers(&self) -> &HashMap<[u8; 4], BgpPeer> {
        &self.peers
    }

    /// Build an OPEN message to send to a peer.
    ///
    /// RFC-REF: RFC 4271 Section 4.2
    /// "After a TCP connection is established, the first message sent by
    /// each side is an OPEN message."
    pub fn build_open(&self) -> OpenMessage {
        // RFC-DEVIATION:
        // reason: 4-byte ASN capability not yet advertised in OPEN
        // impact: peers with 4-byte ASNs will see AS_TRANS (23456) in OPEN
        // issue: #158
        // plan: implement 4-byte AS capability (RFC 6793) in v0.2
        OpenMessage {
            version: BGP_VERSION,
            my_as: if self.config.local_as > 65535 {
                23456
            } else {
                self.config.local_as as u16
            },
            hold_time: self.config.peers.first().map(|p| p.hold_time).unwrap_or(90),
            bgp_id: self.config.router_id,
            capabilities: vec![],
        }
    }

    /// Build an OPEN message for a specific peer.
    pub fn build_open_for_peer(&self, peer_addr: &[u8; 4]) -> Option<OpenMessage> {
        let peer = self.peers.get(peer_addr)?;
        // RFC-DEVIATION:
        // reason: 4-byte ASN capability not yet advertised in OPEN
        // impact: peers with 4-byte ASNs will see AS_TRANS (23456) in OPEN
        // issue: #158
        // plan: implement 4-byte AS capability (RFC 6793) in v0.2
        Some(OpenMessage {
            version: BGP_VERSION,
            my_as: if self.config.local_as > 65535 {
                23456
            } else {
                self.config.local_as as u16
            },
            hold_time: peer.config.hold_time,
            bgp_id: self.config.router_id,
            capabilities: vec![],
        })
    }

    /// Validate a received OPEN message from a peer.
    ///
    /// Returns `Ok(())` if the OPEN is valid, or a NOTIFICATION message
    /// to send back if it is not.
    ///
    /// RFC-REF: RFC 4271 Section 6.2
    /// "Upon receipt of an OPEN message, a BGP speaker MUST calculate
    /// the value of the Hold Timer."
    pub fn validate_open(
        &self,
        peer_addr: &[u8; 4],
        open: &OpenMessage,
    ) -> Result<(), NotificationMessage> {
        // Check BGP version.
        if open.version != BGP_VERSION {
            return Err(NotificationMessage {
                error_code: ERR_OPEN_MSG,
                error_subcode: OPEN_SUB_UNSUPPORTED_VERSION,
                data: vec![0, BGP_VERSION],
            });
        }

        // Check peer AS matches configuration.
        if let Some(peer) = self.peers.get(peer_addr) {
            if open.my_as as u32 != peer.config.remote_as {
                return Err(NotificationMessage {
                    error_code: ERR_OPEN_MSG,
                    error_subcode: OPEN_SUB_BAD_PEER_AS,
                    data: vec![],
                });
            }
        }

        Ok(())
    }

    /// Process a received UPDATE message from a peer.
    ///
    /// Updates the peer's Adj-RIB-In and returns the resulting RIB
    /// entries after import policy filtering and best-path selection.
    ///
    /// RFC-REF: RFC 4271 Section 4.3
    /// "An UPDATE message is used to advertise feasible routes that
    /// share a common set of path attributes to a peer, or to withdraw
    /// multiple unfeasible routes from service."
    pub fn process_update(&mut self, peer_addr: &[u8; 4], update: &UpdateMessage) -> Vec<RibEntry> {
        let peer_router_id = self
            .peers
            .get(peer_addr)
            .and_then(|p| p.fsm.peer_open())
            .map(|o| o.bgp_id)
            .unwrap_or(*peer_addr);

        // Get or create Adj-RIB-In for this peer.
        let rib_in = self.adj_rib_in.entry(*peer_addr).or_default();

        // Process withdrawn routes.
        for &(prefix, prefix_len) in &update.withdrawn_routes {
            rib_in.withdraw(&prefix, prefix_len);
        }

        // Process NLRI (new/updated routes).
        // RFC-REF: RFC 4271 Section 9
        // "If the local AS number is found in the AS path of the route,
        // that route MUST NOT be accepted."
        for &(prefix, prefix_len) in &update.nlri {
            // AS loop detection.
            if update
                .path_attributes
                .as_path
                .contains_asn(self.config.local_as)
            {
                continue;
            }

            rib_in.insert(AdjRibInEntry {
                prefix,
                prefix_len,
                attributes: update.path_attributes.clone(),
                peer_router_id,
            });
        }

        if let Some(peer) = self.peers.get_mut(peer_addr) {
            peer.stats.updates_received += 1;
            peer.stats.prefixes_received = rib_in.len() as u64;
        }

        // Run best-path selection across all peers and produce RIB entries.
        self.compute_best_paths()
    }

    /// Process a session becoming Established for a peer.
    pub fn on_session_established(&mut self, peer_addr: &[u8; 4]) {
        if let Some(peer) = self.peers.get_mut(peer_addr) {
            peer.stats.established_transitions += 1;
        }
    }

    /// Process a session going down for a peer.
    ///
    /// Clears the peer's Adj-RIB-In and returns the updated RIB entries.
    pub fn on_session_down(&mut self, peer_addr: &[u8; 4]) -> Vec<RibEntry> {
        if let Some(rib_in) = self.adj_rib_in.get_mut(peer_addr) {
            rib_in.clear();
        }
        self.compute_best_paths()
    }

    /// Compute the best BGP routes from all Adj-RIB-In tables.
    ///
    /// Applies import policy, performs best-path selection, and
    /// produces RIB entries ready for installation.
    ///
    /// RFC-REF: RFC 4271 Section 9.1
    /// "The Decision Process selects routes for subsequent advertisement
    /// by applying the policies in the local Policy Information Base (PIB)
    /// to the routes stored in its Adj-RIBs-In."
    pub fn compute_best_paths(&self) -> Vec<RibEntry> {
        // Collect all routes from all peers' Adj-RIB-Ins.
        let mut all_entries: Vec<&AdjRibInEntry> = Vec::new();
        for rib_in in self.adj_rib_in.values() {
            let accepted = self.import_policy.apply(rib_in.entries());
            all_entries.extend(accepted);
        }

        // Group by (prefix, prefix_len) and select best path.
        let mut groups: HashMap<([u8; 4], u8), Vec<&AdjRibInEntry>> = HashMap::new();
        for entry in &all_entries {
            groups
                .entry((entry.prefix, entry.prefix_len))
                .or_default()
                .push(entry);
        }

        let mut rib_entries = Vec::new();
        for ((_prefix, _prefix_len), candidates) in &groups {
            if candidates.is_empty() {
                continue;
            }

            // Select the best path among candidates.
            let best = candidates.iter().copied().min_by(|a, b| {
                compare_paths(
                    &a.attributes,
                    a.peer_router_id,
                    &b.attributes,
                    b.peer_router_id,
                )
            });

            if let Some(best_entry) = best {
                // Determine the outgoing interface for the next-hop.
                // For eBGP, the next-hop is the peer address; the
                // actual out_ifname resolution is done at FIB level.
                rib_entries.push(RibEntry {
                    prefix: best_entry.prefix,
                    prefix_len: best_entry.prefix_len,
                    next_hop: best_entry.attributes.next_hop,
                    out_ifname: String::new(), // Resolved at FIB level
                    metric: best_entry.attributes.med.unwrap_or(0),
                    source: ProtocolSource::Bgp,
                    admin_distance: ProtocolSource::Bgp.default_admin_distance(),
                });
            }
        }

        rib_entries
    }

    /// Return all current BGP RIB entries (for initial RIB population).
    pub fn rib_entries(&self) -> Vec<RibEntry> {
        self.compute_best_paths()
    }

    /// Check if a prefix should be advertised to peers (export policy).
    pub fn should_advertise(&self, prefix: &[u8; 4], prefix_len: u8) -> bool {
        self.export_policy.should_advertise(prefix, prefix_len)
    }

    /// Return the number of configured peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Return the number of established peers.
    pub fn established_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_established()).count()
    }

    /// Drive a peer's FSM with an event and return the actions.
    pub fn process_fsm_event(&mut self, peer_addr: &[u8; 4], event: FsmEvent) -> Vec<FsmAction> {
        if let Some(peer) = self.peers.get_mut(peer_addr) {
            peer.fsm.process_event(event)
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::config::BgpPeerConfig;
    use crate::bgp::fsm::BgpState;
    use crate::bgp::packet::{
        BGP_VERSION, ERR_OPEN_MSG, OPEN_SUB_BAD_PEER_AS, OPEN_SUB_UNSUPPORTED_VERSION,
    };
    use crate::bgp::path::{AsPath, AsPathSegment, Origin, PathAttributes};
    use crate::routing::protocol::ProtocolSource;

    fn make_config() -> BgpEngineConfig {
        BgpEngineConfig {
            local_as: 65001,
            router_id: [10, 0, 0, 1],
            peers: vec![BgpPeerConfig {
                address: [10, 0, 0, 2],
                remote_as: 65002,
                hold_time: 90,
            }],
        }
    }

    fn make_engine() -> BgpEngine {
        BgpEngine::new(make_config())
    }

    fn make_update(
        nlri: Vec<([u8; 4], u8)>,
        as_path: Vec<u32>,
        next_hop: [u8; 4],
    ) -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: vec![],
            path_attributes: PathAttributes {
                origin: Origin::Igp,
                as_path: AsPath {
                    segments: vec![AsPathSegment::AsSequence(as_path)],
                },
                next_hop,
                med: None,
                local_pref: Some(100),
            },
            nlri,
        }
    }

    // ── Engine construction ──────────────────────────────────────────

    #[test]
    fn engine_new() {
        let engine = make_engine();
        assert_eq!(engine.local_as(), 65001);
        assert_eq!(engine.router_id(), [10, 0, 0, 1]);
        assert_eq!(engine.peer_count(), 1);
        assert_eq!(engine.established_count(), 0);
    }

    #[test]
    fn engine_peer_lookup() {
        let engine = make_engine();
        assert!(engine.peer(&[10, 0, 0, 2]).is_some());
        assert!(engine.peer(&[10, 0, 0, 3]).is_none());
    }

    // ── OPEN message building ────────────────────────────────────────

    #[test]
    fn build_open_message() {
        let engine = make_engine();
        let open = engine.build_open();
        assert_eq!(open.version, BGP_VERSION);
        assert_eq!(open.my_as, 65001);
        assert_eq!(open.bgp_id, [10, 0, 0, 1]);
    }

    #[test]
    fn build_open_for_peer() {
        let engine = make_engine();
        let open = engine.build_open_for_peer(&[10, 0, 0, 2]).unwrap();
        assert_eq!(open.hold_time, 90);
    }

    // ── OPEN validation ──────────────────────────────────────────────

    #[test]
    fn validate_open_valid() {
        let engine = make_engine();
        let open = OpenMessage {
            version: BGP_VERSION,
            my_as: 65002,
            hold_time: 90,
            bgp_id: [10, 0, 0, 2],
            capabilities: vec![],
        };
        assert!(engine.validate_open(&[10, 0, 0, 2], &open).is_ok());
    }

    #[test]
    fn validate_open_wrong_version() {
        let engine = make_engine();
        let open = OpenMessage {
            version: 3,
            my_as: 65002,
            hold_time: 90,
            bgp_id: [10, 0, 0, 2],
            capabilities: vec![],
        };
        let err = engine.validate_open(&[10, 0, 0, 2], &open).unwrap_err();
        assert_eq!(err.error_code, ERR_OPEN_MSG);
        assert_eq!(err.error_subcode, OPEN_SUB_UNSUPPORTED_VERSION);
    }

    #[test]
    fn validate_open_wrong_as() {
        let engine = make_engine();
        let open = OpenMessage {
            version: BGP_VERSION,
            my_as: 65099,
            hold_time: 90,
            bgp_id: [10, 0, 0, 2],
            capabilities: vec![],
        };
        let err = engine.validate_open(&[10, 0, 0, 2], &open).unwrap_err();
        assert_eq!(err.error_code, ERR_OPEN_MSG);
        assert_eq!(err.error_subcode, OPEN_SUB_BAD_PEER_AS);
    }

    // ── UPDATE processing ────────────────────────────────────────────

    #[test]
    fn process_update_installs_routes() {
        let mut engine = make_engine();
        let update = make_update(vec![([192, 168, 1, 0], 24)], vec![65002], [10, 0, 0, 2]);

        let rib_entries = engine.process_update(&[10, 0, 0, 2], &update);
        assert_eq!(rib_entries.len(), 1);
        assert_eq!(rib_entries[0].prefix, [192, 168, 1, 0]);
        assert_eq!(rib_entries[0].prefix_len, 24);
        assert_eq!(rib_entries[0].next_hop, [10, 0, 0, 2]);
        assert_eq!(rib_entries[0].source, ProtocolSource::Bgp);
        assert_eq!(rib_entries[0].admin_distance, 20);
    }

    #[test]
    fn process_update_multiple_nlri() {
        let mut engine = make_engine();
        let update = make_update(
            vec![([192, 168, 1, 0], 24), ([10, 0, 0, 0], 8)],
            vec![65002],
            [10, 0, 0, 2],
        );

        let rib_entries = engine.process_update(&[10, 0, 0, 2], &update);
        assert_eq!(rib_entries.len(), 2);
    }

    #[test]
    fn process_update_withdraw() {
        let mut engine = make_engine();

        // First, advertise a route.
        let update = make_update(vec![([192, 168, 1, 0], 24)], vec![65002], [10, 0, 0, 2]);
        engine.process_update(&[10, 0, 0, 2], &update);

        // Now withdraw it.
        let withdraw = UpdateMessage {
            withdrawn_routes: vec![([192, 168, 1, 0], 24)],
            path_attributes: PathAttributes::default(),
            nlri: vec![],
        };
        let rib_entries = engine.process_update(&[10, 0, 0, 2], &withdraw);
        assert!(rib_entries.is_empty());
    }

    #[test]
    fn process_update_as_loop_detection() {
        let mut engine = make_engine();

        // UPDATE with our own ASN in the AS_PATH => should be rejected.
        let update = make_update(
            vec![([192, 168, 1, 0], 24)],
            vec![65002, 65001], // contains our local_as
            [10, 0, 0, 2],
        );

        let rib_entries = engine.process_update(&[10, 0, 0, 2], &update);
        assert!(rib_entries.is_empty());
    }

    // ── Session lifecycle ────────────────────────────────────────────

    #[test]
    fn session_down_clears_routes() {
        let mut engine = make_engine();

        // Advertise routes.
        let update = make_update(vec![([192, 168, 1, 0], 24)], vec![65002], [10, 0, 0, 2]);
        engine.process_update(&[10, 0, 0, 2], &update);
        assert_eq!(engine.rib_entries().len(), 1);

        // Session goes down.
        let rib_entries = engine.on_session_down(&[10, 0, 0, 2]);
        assert!(rib_entries.is_empty());
    }

    #[test]
    fn session_established_increments_counter() {
        let mut engine = make_engine();
        engine.on_session_established(&[10, 0, 0, 2]);
        assert_eq!(
            engine
                .peer(&[10, 0, 0, 2])
                .unwrap()
                .stats
                .established_transitions,
            1
        );
    }

    // ── Import policy filtering ──────────────────────────────────────

    #[test]
    fn import_policy_filters_routes() {
        let mut engine = make_engine();

        // Set import policy to deny 10.0.0.0/8 and subnets.
        let mut pl = policy::PrefixList::new(policy::PolicyAction::Permit);
        pl.entries.push(policy::PrefixListEntry {
            prefix: [10, 0, 0, 0],
            prefix_len: 8,
            exact: false,
            action: policy::PolicyAction::Deny,
        });
        engine.set_import_policy(ImportPolicy::new(pl));

        let update = make_update(
            vec![([10, 1, 0, 0], 16), ([192, 168, 1, 0], 24)],
            vec![65002],
            [10, 0, 0, 2],
        );

        let rib_entries = engine.process_update(&[10, 0, 0, 2], &update);
        assert_eq!(rib_entries.len(), 1);
        assert_eq!(rib_entries[0].prefix, [192, 168, 1, 0]);
    }

    // ── Best-path selection across peers ─────────────────────────────

    #[test]
    fn best_path_across_two_peers() {
        let config = BgpEngineConfig {
            local_as: 65001,
            router_id: [10, 0, 0, 1],
            peers: vec![
                BgpPeerConfig {
                    address: [10, 0, 0, 2],
                    remote_as: 65002,
                    hold_time: 90,
                },
                BgpPeerConfig {
                    address: [10, 0, 0, 3],
                    remote_as: 65003,
                    hold_time: 90,
                },
            ],
        };
        let mut engine = BgpEngine::new(config);

        // Peer 1 advertises 192.168.1.0/24 with AS_PATH length 2.
        let update1 = make_update(
            vec![([192, 168, 1, 0], 24)],
            vec![65002, 65010],
            [10, 0, 0, 2],
        );
        engine.process_update(&[10, 0, 0, 2], &update1);

        // Peer 2 advertises same prefix with AS_PATH length 1 (shorter = better).
        let update2 = make_update(vec![([192, 168, 1, 0], 24)], vec![65003], [10, 0, 0, 3]);
        let rib_entries = engine.process_update(&[10, 0, 0, 3], &update2);

        // Should select peer 2's route (shorter AS_PATH).
        assert_eq!(rib_entries.len(), 1);
        assert_eq!(rib_entries[0].next_hop, [10, 0, 0, 3]);
    }

    // ── FSM event processing ─────────────────────────────────────────

    #[test]
    fn fsm_event_processing() {
        let mut engine = make_engine();

        let actions = engine.process_fsm_event(&[10, 0, 0, 2], FsmEvent::ManualStart);
        assert!(!actions.is_empty());
        assert_eq!(
            engine.peer(&[10, 0, 0, 2]).unwrap().state(),
            BgpState::Connect
        );
    }

    #[test]
    fn fsm_event_unknown_peer() {
        let mut engine = make_engine();
        let actions = engine.process_fsm_event(&[10, 0, 0, 99], FsmEvent::ManualStart);
        assert!(actions.is_empty());
    }
}

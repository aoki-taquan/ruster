//! BGP integration tests.
//!
//! These tests exercise the BGP engine at a higher level than the
//! unit tests in `bgp/mod.rs`.  Since BGP has no TCP transport yet,
//! we test the full lifecycle using mock FSM events:
//!
//! - Full session lifecycle (Idle → Established)
//! - UPDATE processing and route installation
//! - Best-path selection with multiple peers
//! - Session teardown and route withdrawal
//! - AS loop detection
//! - OPEN validation errors (version, AS mismatch)

use ruster_dataplane::bgp::config::{BgpEngineConfig, BgpPeerConfig};
use ruster_dataplane::bgp::fsm::{BgpState, FsmAction, FsmEvent};
use ruster_dataplane::bgp::packet::{
    OpenMessage, UpdateMessage, BGP_VERSION, ERR_OPEN_MSG, OPEN_SUB_BAD_PEER_AS,
    OPEN_SUB_UNSUPPORTED_VERSION,
};
use ruster_dataplane::bgp::path::{AsPath, AsPathSegment, Origin, PathAttributes};
use ruster_dataplane::bgp::BgpEngine;
use ruster_dataplane::routing::protocol::ProtocolSource;

// ── Helpers ──────────────────────────────────────────────────────────

fn make_single_peer_config() -> BgpEngineConfig {
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

fn make_two_peer_config() -> BgpEngineConfig {
    BgpEngineConfig {
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
    }
}

fn make_update(nlri: Vec<([u8; 4], u8)>, as_path: Vec<u32>, next_hop: [u8; 4]) -> UpdateMessage {
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

fn make_peer_open(peer_as: u16, bgp_id: [u8; 4]) -> OpenMessage {
    OpenMessage {
        version: BGP_VERSION,
        my_as: peer_as,
        hold_time: 90,
        bgp_id,
        capabilities: vec![],
    }
}

/// Drive a peer's FSM through Idle → Connect → OpenSent → OpenConfirm → Established.
fn establish_session(engine: &mut BgpEngine, peer_addr: &[u8; 4], peer_as: u16) {
    // ManualStart: Idle → Connect
    let actions = engine.process_fsm_event(peer_addr, FsmEvent::ManualStart);
    assert!(
        actions.iter().any(|a| matches!(a, FsmAction::TcpConnect)),
        "ManualStart should produce TcpConnect action"
    );
    assert_eq!(engine.peer(peer_addr).unwrap().state(), BgpState::Connect);

    // TcpConnectionConfirmed: Connect → OpenSent
    let actions = engine.process_fsm_event(peer_addr, FsmEvent::TcpConnectionConfirmed);
    assert!(
        actions.iter().any(|a| matches!(a, FsmAction::SendOpen)),
        "TcpConnectionConfirmed should produce SendOpen action"
    );
    assert_eq!(engine.peer(peer_addr).unwrap().state(), BgpState::OpenSent);

    // BgpOpenReceived: OpenSent → OpenConfirm
    let peer_open = make_peer_open(peer_as, *peer_addr);
    let actions = engine.process_fsm_event(peer_addr, FsmEvent::BgpOpenReceived(peer_open));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendKeepalive)),
        "BgpOpenReceived should produce SendKeepalive action"
    );
    assert_eq!(
        engine.peer(peer_addr).unwrap().state(),
        BgpState::OpenConfirm
    );

    // BgpKeepaliveReceived: OpenConfirm → Established
    let actions = engine.process_fsm_event(peer_addr, FsmEvent::BgpKeepaliveReceived);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::SessionEstablished)),
        "BgpKeepaliveReceived should produce SessionEstablished action"
    );
    assert_eq!(
        engine.peer(peer_addr).unwrap().state(),
        BgpState::Established
    );

    // Notify the engine of session establishment.
    engine.on_session_established(peer_addr);
}

// ── Tests ────────────────────────────────────────────────────────────

/// Full BGP session lifecycle: Idle → Connect → OpenSent → OpenConfirm → Established.
///
/// Verifies each FSM transition and the corresponding actions produced.
#[test]
fn full_session_lifecycle() {
    let mut engine = BgpEngine::new(make_single_peer_config());
    let peer = [10, 0, 0, 2];

    // Initially Idle.
    assert_eq!(engine.peer(&peer).unwrap().state(), BgpState::Idle);
    assert_eq!(engine.established_count(), 0);

    establish_session(&mut engine, &peer, 65002);

    assert_eq!(engine.established_count(), 1);
    assert!(engine.peer(&peer).unwrap().is_established());
    assert_eq!(engine.peer(&peer).unwrap().stats.established_transitions, 1);
}

/// UPDATE message processing installs routes with correct attributes.
///
/// After session establishment, an UPDATE advertising 192.168.1.0/24
/// should produce a RibEntry with source=Bgp and admin_distance=20.
#[test]
fn update_route_installation() {
    let mut engine = BgpEngine::new(make_single_peer_config());
    let peer = [10, 0, 0, 2];

    establish_session(&mut engine, &peer, 65002);

    let update = make_update(vec![([192, 168, 1, 0], 24)], vec![65002], [10, 0, 0, 2]);
    let rib_entries = engine.process_update(&peer, &update);

    assert_eq!(rib_entries.len(), 1);

    let entry = &rib_entries[0];
    assert_eq!(entry.prefix, [192, 168, 1, 0]);
    assert_eq!(entry.prefix_len, 24);
    assert_eq!(entry.next_hop, [10, 0, 0, 2]);
    assert_eq!(entry.source, ProtocolSource::Bgp);
    assert_eq!(entry.admin_distance, 20);

    // rib_entries() should return the same result.
    let all_rib = engine.rib_entries();
    assert_eq!(all_rib.len(), 1);
    assert_eq!(all_rib[0].prefix, [192, 168, 1, 0]);
}

/// Best-path selection: shorter AS_PATH wins.
///
/// Two peers advertise the same prefix.  The peer with a shorter
/// AS_PATH should be selected as the best path.
#[test]
fn best_path_shorter_as_path() {
    let mut engine = BgpEngine::new(make_two_peer_config());
    let peer1 = [10, 0, 0, 2];
    let peer2 = [10, 0, 0, 3];

    establish_session(&mut engine, &peer1, 65002);
    establish_session(&mut engine, &peer2, 65003);

    // Peer 1: AS_PATH = [65002, 65010] (length 2).
    let update1 = make_update(
        vec![([192, 168, 1, 0], 24)],
        vec![65002, 65010],
        [10, 0, 0, 2],
    );
    engine.process_update(&peer1, &update1);

    // Peer 2: AS_PATH = [65003] (length 1 — shorter, should win).
    let update2 = make_update(vec![([192, 168, 1, 0], 24)], vec![65003], [10, 0, 0, 3]);
    let rib_entries = engine.process_update(&peer2, &update2);

    assert_eq!(rib_entries.len(), 1);
    assert_eq!(
        rib_entries[0].next_hop,
        [10, 0, 0, 3],
        "Shorter AS_PATH (peer2) should be selected"
    );
}

/// Session teardown clears all routes from the peer.
///
/// After `on_session_down()`, the peer's Adj-RIB-In is cleared and
/// compute_best_paths returns no routes for that peer's prefixes.
#[test]
fn session_down_clears_routes() {
    let mut engine = BgpEngine::new(make_single_peer_config());
    let peer = [10, 0, 0, 2];

    establish_session(&mut engine, &peer, 65002);

    // Advertise routes.
    let update = make_update(
        vec![([192, 168, 1, 0], 24), ([10, 1, 0, 0], 16)],
        vec![65002],
        [10, 0, 0, 2],
    );
    engine.process_update(&peer, &update);
    assert_eq!(engine.rib_entries().len(), 2);

    // Session goes down.
    let remaining = engine.on_session_down(&peer);
    assert!(
        remaining.is_empty(),
        "All routes should be withdrawn after session down"
    );
    assert!(engine.rib_entries().is_empty());
}

/// AS loop detection: UPDATE with local AS in AS_PATH is rejected.
///
/// RFC 4271 Section 9: "If the local AS number is found in the AS path
/// of the route, that route MUST NOT be accepted."
#[test]
fn as_loop_detection() {
    let mut engine = BgpEngine::new(make_single_peer_config());
    let peer = [10, 0, 0, 2];

    establish_session(&mut engine, &peer, 65002);

    // UPDATE with our own AS (65001) in the path → reject.
    let update = make_update(
        vec![([192, 168, 1, 0], 24)],
        vec![65002, 65001], // contains local AS
        [10, 0, 0, 2],
    );
    let rib_entries = engine.process_update(&peer, &update);
    assert!(
        rib_entries.is_empty(),
        "Route with local AS in AS_PATH should be rejected"
    );
}

/// OPEN validation: unsupported BGP version triggers NOTIFICATION.
///
/// An OPEN with version != 4 should produce an error code 2 (OPEN)
/// subcode 1 (Unsupported Version Number).
#[test]
fn open_validation_wrong_version() {
    let engine = BgpEngine::new(make_single_peer_config());
    let peer = [10, 0, 0, 2];

    let bad_open = OpenMessage {
        version: 3,
        my_as: 65002,
        hold_time: 90,
        bgp_id: [10, 0, 0, 2],
        capabilities: vec![],
    };

    let result = engine.validate_open(&peer, &bad_open);
    assert!(result.is_err());

    let notification = result.unwrap_err();
    assert_eq!(notification.error_code, ERR_OPEN_MSG);
    assert_eq!(notification.error_subcode, OPEN_SUB_UNSUPPORTED_VERSION);
}

/// OPEN validation: wrong peer AS triggers NOTIFICATION.
///
/// An OPEN with an AS that does not match the configured remote AS
/// should produce error code 2 (OPEN) subcode 2 (Bad Peer AS).
#[test]
fn open_validation_wrong_as() {
    let engine = BgpEngine::new(make_single_peer_config());
    let peer = [10, 0, 0, 2];

    let bad_open = OpenMessage {
        version: BGP_VERSION,
        my_as: 65099, // configured as 65002
        hold_time: 90,
        bgp_id: [10, 0, 0, 2],
        capabilities: vec![],
    };

    let result = engine.validate_open(&peer, &bad_open);
    assert!(result.is_err());

    let notification = result.unwrap_err();
    assert_eq!(notification.error_code, ERR_OPEN_MSG);
    assert_eq!(notification.error_subcode, OPEN_SUB_BAD_PEER_AS);
}

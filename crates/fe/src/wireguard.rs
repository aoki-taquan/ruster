//! WireGuard interfaces: core's views of the tables, the peers' session state that
//! outlives a table change, and the staging area of sealed frames.
//!
//! A table change that leaves a peer's session as it was keeps its counters and
//! replay window; a new session (other keys or indexes) starts them over, and a
//! deleted one stops the peer.
//!
//! # Standards
//!
//! See [`ruster_core::wireguard`]. The handshake is not here: the session comes in
//! the tables.
//!
//! Deviations: the views for core are made for each batch (two small vectors),
//! only when the router has a WireGuard interface.

use ruster_core::wireguard::{
    AllowedPrefix, InterfaceConfig, PeerConfig, PeerState, SessionKeys, WireguardInterface,
    WireguardSendRuntime, WireguardStagedFrame,
};
use ruster_core::IfId;

/// Frames sealed and waiting to be sent after a batch.
const STAGED_FRAMES: usize = 64;
/// Bytes of one staged frame: an Ethernet frame of the largest MTU the FE has.
const STAGED_BYTES: usize = 2_048;
/// Sealed frames sent per batch.
pub(crate) const FRAMES_PER_BATCH: usize = 64;

/// One peer as the tables give it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerBuilt {
    pub(crate) name: String,
    pub(crate) endpoint: [u8; 4],
    pub(crate) port: u16,
    pub(crate) allowed: Vec<AllowedPrefix>,
    pub(crate) keys: Option<SessionKeys>,
}

/// One WireGuard interface as the tables give it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InterfaceBuilt {
    pub(crate) interface: IfId,
    pub(crate) name: String,
    pub(crate) local: [u8; 4],
    pub(crate) listen_port: u16,
    pub(crate) peers: Vec<PeerBuilt>,
}

pub(crate) struct Wireguard {
    pub(crate) config: Vec<InterfaceBuilt>,
    /// The peers' state, in the order of `config`'s interfaces and their peers.
    pub(crate) states: Vec<PeerState>,
    /// The session each of `states` was started with, by interface and peer name.
    applied: Vec<(String, String, Option<SessionKeys>)>,
    pub(crate) send: WireguardSendRuntime<'static>,
}

impl Wireguard {
    pub(crate) fn new() -> Self {
        let slots =
            Box::leak(vec![WireguardStagedFrame::default(); STAGED_FRAMES].into_boxed_slice());
        let bytes = Box::leak(vec![0_u8; STAGED_FRAMES * STAGED_BYTES].into_boxed_slice());
        Self {
            config: Vec::new(),
            states: Vec::new(),
            applied: Vec::new(),
            send: WireguardSendRuntime::new(slots, bytes).expect("WireGuard staging storage"),
        }
    }

    /// Uses `built`: peers that were there keep their state unless their session
    /// changed.
    pub(crate) fn publish(&mut self, built: Vec<InterfaceBuilt>) {
        let mut states = Vec::new();
        let mut applied = Vec::new();
        for interface in &built {
            for peer in &interface.peers {
                let before = self
                    .applied
                    .iter()
                    .position(|(i, p, _)| *i == interface.name && *p == peer.name);
                let mut state = match before {
                    Some(at) if self.applied[at].2 == peer.keys => self.states[at].clone(),
                    _ => PeerState::default(),
                };
                if before.is_none_or(|at| self.applied[at].2 != peer.keys) {
                    match peer.keys {
                        Some(keys) => state.set_keys(keys),
                        None => state.clear_keys(),
                    }
                }
                states.push(state);
                applied.push((interface.name.clone(), peer.name.clone(), peer.keys));
            }
        }
        self.config = built;
        self.states = states;
        self.applied = applied;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.config.is_empty()
    }
}

/// The peers of every interface, for core.
pub(crate) fn peer_configs(config: &[InterfaceBuilt]) -> Vec<PeerConfig<'_>> {
    config
        .iter()
        .flat_map(|i| &i.peers)
        .map(|p| PeerConfig {
            endpoint: p.endpoint,
            endpoint_port: p.port,
            allowed: &p.allowed,
        })
        .collect()
}

/// The interfaces, over `peers` from [`peer_configs`].
pub(crate) fn interfaces<'a>(
    config: &'a [InterfaceBuilt],
    peers: &'a [PeerConfig<'a>],
) -> Vec<WireguardInterface<'a>> {
    let mut first_peer = 0;
    config
        .iter()
        .map(|i| {
            let view = WireguardInterface {
                interface: i.interface,
                config: InterfaceConfig {
                    local: i.local,
                    listen_port: i.listen_port,
                    peers: &peers[first_peer..first_peer + i.peers.len()],
                },
                first_peer,
            };
            first_peer += i.peers.len();
            view
        })
        .collect()
}

//! WireGuard interfaces: core's views of the tables, the peers' session state that
//! outlives a table change, and the staging area of sealed frames.
//!
//! A table change that leaves a peer's session as it was keeps its counters and
//! replay window; a deleted session stops the peer. A session with a send key that
//! was used before goes on from that key's counter, never back to 0.
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
/// Stopped sessions whose counters are remembered.
const RETIRED: usize = 64;
/// Sealed frames sent per batch (the staging area holds as many).
pub(crate) const FRAMES_PER_BATCH: usize = STAGED_FRAMES;

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
    /// The states of sessions that stopped, the oldest first.
    retired: Vec<PeerState>,
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
            retired: Vec::new(),
            send: WireguardSendRuntime::new(slots, bytes).expect("WireGuard staging storage"),
        }
    }

    /// Uses `built`: a peer whose session is as it was keeps its state. A session
    /// that is new starts from the state of an earlier one that had the same send
    /// key (its counter goes on: a key must never seal two messages with one
    /// counter) or the same receive key (its replay window goes on, so captured
    /// packets stay refused). The states of sessions that stopped are kept, a
    /// few, for that.
    pub(crate) fn publish(&mut self, built: Vec<InterfaceBuilt>) {
        let mut old: Vec<(String, String, Option<SessionKeys>, PeerState)> =
            std::mem::take(&mut self.applied)
                .into_iter()
                .zip(std::mem::take(&mut self.states))
                .map(|((interface, peer, keys), state)| (interface, peer, keys, state))
                .collect();
        let mut states = Vec::new();
        let mut applied = Vec::new();
        for interface in &built {
            for peer in &interface.peers {
                let before = old
                    .iter()
                    .position(|(i, p, _, _)| *i == interface.name && *p == peer.name)
                    .map(|at| old.remove(at));
                let state = match before {
                    Some((_, _, keys, state)) if keys == peer.keys => state,
                    other => {
                        let mut state = PeerState::default();
                        if let Some((_, _, _, before)) = other {
                            self.retire(before);
                        }
                        if let Some(keys) = peer.keys {
                            let candidates =
                                old.iter().map(|(_, _, _, s)| s).chain(self.retired.iter());
                            let (mut counter, mut replay) = (0, None);
                            for earlier in candidates {
                                let Some(used) = earlier.keys() else { continue };
                                if used.send == keys.send {
                                    counter = counter.max(earlier.send_counter());
                                }
                                if used.receive == keys.receive && replay.is_none() {
                                    replay = Some(earlier.replay_window().clone());
                                }
                            }
                            state.set_keys_continuing(keys, counter, replay);
                        }
                        state
                    }
                };
                states.push(state);
                applied.push((interface.name.clone(), peer.name.clone(), peer.keys));
            }
        }
        for (_, _, _, state) in old {
            self.retire(state);
        }
        self.config = built;
        self.states = states;
        self.applied = applied;
    }

    /// Remembers the state of a session that stopped.
    fn retire(&mut self, state: PeerState) {
        if state.keys().is_none() {
            return;
        }
        if self.retired.len() == RETIRED {
            self.retired.remove(0);
        }
        self.retired.push(state);
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

//! BGP peer state and management.
//!
//! Each configured eBGP neighbor is represented by a [`BgpPeer`] struct
//! that holds the peer configuration, the FSM instance, and session
//! statistics.
//!
//! RFC-REF: RFC 4271 Section 3
//! "Two systems form a transport protocol connection between one another.
//! They exchange messages to open and confirm the connection parameters."

use std::fmt;
use std::time::Instant;

use super::config::BgpPeerConfig;
use super::fsm::{BgpFsm, BgpState};

/// Default connect retry interval in seconds.
const DEFAULT_CONNECT_RETRY_SECS: u64 = 30;

/// BGP peer session statistics.
#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    /// Number of OPEN messages sent.
    pub opens_sent: u64,
    /// Number of OPEN messages received.
    pub opens_received: u64,
    /// Number of UPDATE messages sent.
    pub updates_sent: u64,
    /// Number of UPDATE messages received.
    pub updates_received: u64,
    /// Number of KEEPALIVE messages sent.
    pub keepalives_sent: u64,
    /// Number of KEEPALIVE messages received.
    pub keepalives_received: u64,
    /// Number of NOTIFICATION messages sent.
    pub notifications_sent: u64,
    /// Number of NOTIFICATION messages received.
    pub notifications_received: u64,
    /// Number of times the session has been established.
    pub established_transitions: u64,
    /// Number of prefixes received from this peer.
    pub prefixes_received: u64,
}

/// A BGP peer instance.
///
/// Wraps the FSM, configuration, and statistics for a single eBGP
/// neighbor.
#[derive(Debug)]
pub struct BgpPeer {
    /// Peer configuration (address, remote AS, hold time).
    pub config: BgpPeerConfig,
    /// The FSM driving this peer's session lifecycle.
    pub fsm: BgpFsm,
    /// Session statistics.
    pub stats: PeerStats,
    /// Timestamp when this peer was created.
    pub created_at: Instant,
}

impl BgpPeer {
    /// Create a new peer from its configuration.
    pub fn new(config: BgpPeerConfig) -> Self {
        let hold_time = config.hold_time;
        Self {
            config,
            fsm: BgpFsm::new(hold_time, DEFAULT_CONNECT_RETRY_SECS),
            stats: PeerStats::default(),
            created_at: Instant::now(),
        }
    }

    /// Return the peer's IPv4 address.
    pub fn address(&self) -> [u8; 4] {
        self.config.address
    }

    /// Return the peer's remote AS number.
    pub fn remote_as(&self) -> u32 {
        self.config.remote_as
    }

    /// Return the current FSM state.
    pub fn state(&self) -> BgpState {
        self.fsm.state()
    }

    /// Return whether this peer's session is Established.
    pub fn is_established(&self) -> bool {
        self.fsm.state() == BgpState::Established
    }

    /// Format the peer address as a dotted-decimal string.
    pub fn address_str(&self) -> String {
        let a = self.config.address;
        format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
    }
}

impl fmt::Display for BgpPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer {} AS{} state={}",
            self.address_str(),
            self.config.remote_as,
            self.fsm.state()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer() -> BgpPeer {
        BgpPeer::new(BgpPeerConfig {
            address: [10, 0, 0, 2],
            remote_as: 65002,
            hold_time: 90,
        })
    }

    #[test]
    fn new_peer_starts_idle() {
        let peer = make_peer();
        assert_eq!(peer.state(), BgpState::Idle);
        assert!(!peer.is_established());
    }

    #[test]
    fn peer_address_and_remote_as() {
        let peer = make_peer();
        assert_eq!(peer.address(), [10, 0, 0, 2]);
        assert_eq!(peer.remote_as(), 65002);
    }

    #[test]
    fn peer_address_str() {
        let peer = make_peer();
        assert_eq!(peer.address_str(), "10.0.0.2");
    }

    #[test]
    fn peer_display() {
        let peer = make_peer();
        let display = format!("{peer}");
        assert!(display.contains("10.0.0.2"));
        assert!(display.contains("AS65002"));
        assert!(display.contains("Idle"));
    }

    #[test]
    fn peer_stats_default() {
        let peer = make_peer();
        assert_eq!(peer.stats.opens_sent, 0);
        assert_eq!(peer.stats.updates_received, 0);
        assert_eq!(peer.stats.established_transitions, 0);
    }
}

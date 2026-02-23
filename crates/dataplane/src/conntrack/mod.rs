//! Connection tracking engine for NAT and stateful firewall.
//!
//! This module implements a 5-tuple based session table that tracks
//! active connections through the router. Both the NAT engine and the
//! stateful firewall share this common session state.
//!
//! RFC-REF: RFC 7857 Section 2
//! "A NAT session is defined as the association between a binding and
//! a specific transport-layer session."
//!
//! RFC-REF: RFC 6146 Section 3.5
//! "The NAT64 maintains session state in a session table. [...]
//! Each entry [...] has an associated timer that, upon expiration,
//! causes the entry to be deleted."

pub mod session;

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use ruster_config::model::NatConfig;

use crate::packet::tcp::{TCP_ACK, TCP_FIN, TCP_RST};

pub use session::{
    NatDirection, NatTranslation, Session, SessionKey, SessionProto, SessionState, TcpState,
};

// ── Configuration ────────────────────────────────────────────────────

/// Connection tracking configuration.
///
/// Extracted from [`NatConfig`] — the conntrack engine does not depend
/// on NAT-specific fields (mode, external_if, port_forwards, etc.).
#[derive(Debug, Clone)]
pub struct ConntrackConfig {
    pub max_sessions: usize,
    pub tcp_established_timeout_sec: u64,
    pub tcp_transitory_timeout_sec: u64,
    pub udp_timeout_sec: u64,
    pub icmp_timeout_sec: u64,
}

impl ConntrackConfig {
    /// Build a conntrack config from the NAT configuration section.
    pub fn from_nat_config(nat: &NatConfig) -> Self {
        Self {
            max_sessions: nat.session_table_max_entries as usize,
            tcp_established_timeout_sec: u64::from(nat.tcp_established_timeout_sec),
            tcp_transitory_timeout_sec: u64::from(nat.tcp_transitory_timeout_sec),
            udp_timeout_sec: u64::from(nat.udp_timeout_sec),
            icmp_timeout_sec: u64::from(nat.icmp_timeout_sec),
        }
    }
}

// ── Error ────────────────────────────────────────────────────────────

/// Errors returned by the conntrack engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackError {
    /// The session table is full. The new session was not created.
    ///
    /// RFC-REF: RFC 7857 Section 3
    /// "When the NAT runs out of resources [...] it has no choice but
    /// to drop the packet."
    TableFull,
}

impl fmt::Display for ConntrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConntrackError::TableFull => write!(f, "conntrack session table full"),
        }
    }
}

impl std::error::Error for ConntrackError {}

// ── Statistics ───────────────────────────────────────────────────────

/// Connection tracking statistics.
///
/// Lifetime counters for session creation and deletion. The active
/// session count is derived (created - deleted).
#[derive(Debug, Clone, Default)]
pub struct ConntrackStats {
    /// Total sessions created since engine start.
    pub created: u64,
    /// Total sessions deleted (GC, explicit remove) since engine start.
    pub deleted: u64,
}

impl ConntrackStats {
    /// Number of currently active sessions.
    pub fn active(&self) -> u64 {
        self.created - self.deleted
    }
}

// ── Engine ───────────────────────────────────────────────────────────

/// The connection tracking engine.
///
/// Manages a table of active sessions keyed by 5-tuple. Provides
/// create/lookup/update/delete operations and periodic garbage
/// collection of timed-out sessions.
#[derive(Debug)]
pub struct ConntrackEngine {
    sessions: HashMap<SessionKey, Session>,
    config: ConntrackConfig,
    stats: ConntrackStats,
}

impl ConntrackEngine {
    /// Create a new conntrack engine with the given configuration.
    pub fn new(config: ConntrackConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            config,
            stats: ConntrackStats::default(),
        }
    }

    /// Create a conntrack engine directly from the NAT configuration.
    pub fn from_nat_config(nat_config: &NatConfig) -> Self {
        Self::new(ConntrackConfig::from_nat_config(nat_config))
    }

    /// Look up a session by its 5-tuple key.
    pub fn lookup(&self, key: &SessionKey) -> Option<&Session> {
        self.sessions.get(key)
    }

    /// Look up a session mutably by its 5-tuple key.
    pub fn lookup_mut(&mut self, key: &SessionKey) -> Option<&mut Session> {
        self.sessions.get_mut(key)
    }

    /// Create a new session in the table.
    ///
    /// Returns an error if the table has reached `max_sessions`. On
    /// success, the `created` counter is incremented and a reference
    /// to the new session is returned.
    ///
    /// RFC-REF: RFC 7857 Section 3
    /// "When the NAT runs out of resources [...] it has no choice but
    /// to drop the packet."
    pub fn create_session(
        &mut self,
        key: SessionKey,
        state: SessionState,
    ) -> Result<&Session, ConntrackError> {
        if self.sessions.len() >= self.config.max_sessions {
            return Err(ConntrackError::TableFull);
        }

        let now = Instant::now();
        let session = Session {
            key,
            state,
            created_at: now,
            last_seen: now,
            nat_info: None,
        };

        self.sessions.insert(key, session);
        self.stats.created += 1;

        Ok(self.sessions.get(&key).unwrap())
    }

    /// Update the TCP state machine for an existing session.
    ///
    /// The simplified state transitions are:
    /// - `SynSent` + ACK -> `Established`
    /// - `Established` + FIN -> `FinWait`
    /// - `FinWait` + FIN -> `Closed`
    /// - Any state + RST -> `Closed`
    ///
    /// RFC-REF: RFC 6146 Section 3.5.2.2
    /// "The NAT64 uses a simplified version of the TCP state machine
    /// to track the state of TCP sessions."
    pub fn update_tcp_state(&mut self, key: &SessionKey, flags: u8) {
        let session = match self.sessions.get_mut(key) {
            Some(s) => s,
            None => return,
        };

        let tcp_state = match &mut session.state {
            SessionState::Tcp(state) => state,
            _ => return,
        };

        // RST always transitions to Closed regardless of current state.
        if flags & TCP_RST != 0 {
            *tcp_state = TcpState::Closed;
            return;
        }

        *tcp_state = match *tcp_state {
            TcpState::SynSent if flags & TCP_ACK != 0 => TcpState::Established,
            TcpState::Established if flags & TCP_FIN != 0 => TcpState::FinWait,
            TcpState::FinWait if flags & TCP_FIN != 0 => TcpState::Closed,
            other => other,
        };
    }

    /// Refresh the `last_seen` timestamp for a session.
    ///
    /// Called on every packet that matches an existing session to
    /// prevent it from being garbage-collected.
    pub fn touch(&mut self, key: &SessionKey) {
        if let Some(session) = self.sessions.get_mut(key) {
            session.last_seen = Instant::now();
        }
    }

    /// Remove a session from the table.
    ///
    /// Returns the removed session, or `None` if the key was not found.
    /// Increments the `deleted` counter on success.
    pub fn remove(&mut self, key: &SessionKey) -> Option<Session> {
        let session = self.sessions.remove(key);
        if session.is_some() {
            self.stats.deleted += 1;
        }
        session
    }

    /// Garbage-collect timed-out sessions.
    ///
    /// Each session's applicable timeout depends on its protocol and
    /// state:
    /// - TCP `Established` -> `tcp_established_timeout_sec`
    /// - TCP other states -> `tcp_transitory_timeout_sec`
    /// - UDP -> `udp_timeout_sec`
    /// - ICMP -> `icmp_timeout_sec`
    ///
    /// Returns the number of sessions removed.
    ///
    /// RFC-REF: RFC 7857 Section 4
    /// "It is RECOMMENDED that [...] the value of the transitory
    /// connection idle-timeout is at least 120 seconds."
    pub fn gc(&mut self) -> usize {
        let now = Instant::now();
        let config = &self.config;

        let before = self.sessions.len();

        self.sessions.retain(|_, session| {
            let timeout = session_timeout(session, config);
            now.duration_since(session.last_seen) < timeout
        });

        let removed = before - self.sessions.len();
        self.stats.deleted += removed as u64;
        removed
    }

    /// Return the current number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Return a reference to the statistics.
    pub fn stats(&self) -> &ConntrackStats {
        &self.stats
    }
}

/// Determine the applicable timeout for a session based on its state.
fn session_timeout(session: &Session, config: &ConntrackConfig) -> Duration {
    let secs = match &session.state {
        SessionState::Tcp(TcpState::Established) => config.tcp_established_timeout_sec,
        SessionState::Tcp(_) => config.tcp_transitory_timeout_sec,
        SessionState::Udp => config.udp_timeout_sec,
        SessionState::Icmp => config.icmp_timeout_sec,
    };
    Duration::from_secs(secs)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // ── Helpers ────────────────────────────────────────────────────

    fn default_config() -> ConntrackConfig {
        ConntrackConfig {
            max_sessions: 1000,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
        }
    }

    fn tcp_key(src_port: u16, dst_port: u16) -> SessionKey {
        SessionKey {
            src_ip: [192, 168, 1, 100],
            dst_ip: [10, 0, 0, 1],
            proto: SessionProto::Tcp { src_port, dst_port },
        }
    }

    fn udp_key(src_port: u16, dst_port: u16) -> SessionKey {
        SessionKey {
            src_ip: [192, 168, 1, 100],
            dst_ip: [10, 0, 0, 1],
            proto: SessionProto::Udp { src_port, dst_port },
        }
    }

    fn icmp_key(id: u16) -> SessionKey {
        SessionKey {
            src_ip: [192, 168, 1, 1],
            dst_ip: [192, 168, 1, 2],
            proto: SessionProto::Icmp { id },
        }
    }

    // ── create_session tests ───────────────────────────────────────

    #[test]
    fn create_session_success() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);

        let session = engine
            .create_session(key, SessionState::Tcp(TcpState::SynSent))
            .unwrap();

        assert_eq!(session.key, key);
        assert_eq!(session.state, SessionState::Tcp(TcpState::SynSent));
        assert!(session.nat_info.is_none());
        assert_eq!(engine.session_count(), 1);
        assert_eq!(engine.stats().created, 1);
        assert_eq!(engine.stats().deleted, 0);
        assert_eq!(engine.stats().active(), 1);
    }

    #[test]
    fn create_session_table_full() {
        let config = ConntrackConfig {
            max_sessions: 2,
            ..default_config()
        };
        let mut engine = ConntrackEngine::new(config);

        engine
            .create_session(tcp_key(1000, 80), SessionState::Tcp(TcpState::SynSent))
            .unwrap();
        engine
            .create_session(tcp_key(1001, 80), SessionState::Tcp(TcpState::SynSent))
            .unwrap();

        // Third session should fail.
        let result = engine.create_session(tcp_key(1002, 80), SessionState::Tcp(TcpState::SynSent));
        assert!(matches!(result, Err(ConntrackError::TableFull)));
        assert_eq!(engine.session_count(), 2);
        assert_eq!(engine.stats().created, 2);
    }

    // ── lookup tests ───────────────────────────────────────────────

    #[test]
    fn lookup_existing_session() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);
        engine
            .create_session(key, SessionState::Tcp(TcpState::Established))
            .unwrap();

        let session = engine.lookup(&key).unwrap();
        assert_eq!(session.state, SessionState::Tcp(TcpState::Established));
    }

    #[test]
    fn lookup_missing_session() {
        let engine = ConntrackEngine::new(default_config());
        assert!(engine.lookup(&tcp_key(49152, 80)).is_none());
    }

    // ── TCP state machine tests ────────────────────────────────────

    #[test]
    fn tcp_syn_sent_to_established() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);
        engine
            .create_session(key, SessionState::Tcp(TcpState::SynSent))
            .unwrap();

        // SYN-ACK received -> Established
        engine.update_tcp_state(&key, TCP_ACK);

        let session = engine.lookup(&key).unwrap();
        assert_eq!(session.state, SessionState::Tcp(TcpState::Established));
    }

    #[test]
    fn tcp_established_to_fin_wait() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);
        engine
            .create_session(key, SessionState::Tcp(TcpState::Established))
            .unwrap();

        engine.update_tcp_state(&key, TCP_FIN);

        let session = engine.lookup(&key).unwrap();
        assert_eq!(session.state, SessionState::Tcp(TcpState::FinWait));
    }

    #[test]
    fn tcp_fin_wait_to_closed() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);
        engine
            .create_session(key, SessionState::Tcp(TcpState::FinWait))
            .unwrap();

        // Second FIN from the other side.
        engine.update_tcp_state(&key, TCP_FIN);

        let session = engine.lookup(&key).unwrap();
        assert_eq!(session.state, SessionState::Tcp(TcpState::Closed));
    }

    #[test]
    fn tcp_rst_transitions_to_closed() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);
        engine
            .create_session(key, SessionState::Tcp(TcpState::Established))
            .unwrap();

        engine.update_tcp_state(&key, TCP_RST);

        let session = engine.lookup(&key).unwrap();
        assert_eq!(session.state, SessionState::Tcp(TcpState::Closed));
    }

    #[test]
    fn tcp_syn_sent_rst_to_closed() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);
        engine
            .create_session(key, SessionState::Tcp(TcpState::SynSent))
            .unwrap();

        engine.update_tcp_state(&key, TCP_RST);

        let session = engine.lookup(&key).unwrap();
        assert_eq!(session.state, SessionState::Tcp(TcpState::Closed));
    }

    #[test]
    fn tcp_state_no_transition_on_irrelevant_flags() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);
        engine
            .create_session(key, SessionState::Tcp(TcpState::SynSent))
            .unwrap();

        // A FIN during SynSent should not change state (no transition defined).
        engine.update_tcp_state(&key, TCP_FIN);

        let session = engine.lookup(&key).unwrap();
        assert_eq!(session.state, SessionState::Tcp(TcpState::SynSent));
    }

    #[test]
    fn update_tcp_state_on_non_tcp_session_is_noop() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = udp_key(12345, 53);
        engine.create_session(key, SessionState::Udp).unwrap();

        // Should not panic or change state.
        engine.update_tcp_state(&key, TCP_ACK);

        let session = engine.lookup(&key).unwrap();
        assert_eq!(session.state, SessionState::Udp);
    }

    // ── touch tests ────────────────────────────────────────────────

    #[test]
    fn touch_refreshes_last_seen() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = udp_key(12345, 53);
        engine.create_session(key, SessionState::Udp).unwrap();

        let first_seen = engine.lookup(&key).unwrap().last_seen;

        // Sleep briefly to ensure measurable time difference.
        thread::sleep(Duration::from_millis(10));

        engine.touch(&key);
        let second_seen = engine.lookup(&key).unwrap().last_seen;

        assert!(second_seen > first_seen);
    }

    // ── remove tests ───────────────────────────────────────────────

    #[test]
    fn remove_session() {
        let mut engine = ConntrackEngine::new(default_config());
        let key = tcp_key(49152, 80);
        engine
            .create_session(key, SessionState::Tcp(TcpState::Established))
            .unwrap();

        let removed = engine.remove(&key);
        assert!(removed.is_some());
        assert_eq!(engine.session_count(), 0);
        assert_eq!(engine.stats().created, 1);
        assert_eq!(engine.stats().deleted, 1);
        assert_eq!(engine.stats().active(), 0);
    }

    #[test]
    fn remove_nonexistent_session() {
        let mut engine = ConntrackEngine::new(default_config());
        let result = engine.remove(&tcp_key(49152, 80));
        assert!(result.is_none());
        assert_eq!(engine.stats().deleted, 0);
    }

    // ── GC tests ───────────────────────────────────────────────────

    #[test]
    fn gc_removes_timed_out_sessions() {
        let config = ConntrackConfig {
            max_sessions: 100,
            tcp_established_timeout_sec: 0, // expire immediately
            tcp_transitory_timeout_sec: 0,
            udp_timeout_sec: 0,
            icmp_timeout_sec: 0,
        };
        let mut engine = ConntrackEngine::new(config);

        engine
            .create_session(tcp_key(1000, 80), SessionState::Tcp(TcpState::Established))
            .unwrap();
        engine
            .create_session(udp_key(2000, 53), SessionState::Udp)
            .unwrap();
        engine
            .create_session(icmp_key(0x1234), SessionState::Icmp)
            .unwrap();

        // Let some time pass so all sessions expire.
        thread::sleep(Duration::from_millis(10));

        let removed = engine.gc();
        assert_eq!(removed, 3);
        assert_eq!(engine.session_count(), 0);
        assert_eq!(engine.stats().created, 3);
        assert_eq!(engine.stats().deleted, 3);
        assert_eq!(engine.stats().active(), 0);
    }

    #[test]
    fn gc_keeps_fresh_sessions() {
        let config = ConntrackConfig {
            max_sessions: 100,
            tcp_established_timeout_sec: 3600,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
        };
        let mut engine = ConntrackEngine::new(config);

        engine
            .create_session(tcp_key(1000, 80), SessionState::Tcp(TcpState::Established))
            .unwrap();
        engine
            .create_session(udp_key(2000, 53), SessionState::Udp)
            .unwrap();

        let removed = engine.gc();
        assert_eq!(removed, 0);
        assert_eq!(engine.session_count(), 2);
    }

    #[test]
    fn gc_tcp_established_vs_transitory_timeout() {
        // Established sessions use a longer timeout than transitory ones.
        let config = ConntrackConfig {
            max_sessions: 100,
            tcp_established_timeout_sec: 3600, // keep established
            tcp_transitory_timeout_sec: 0,     // expire transitory immediately
            udp_timeout_sec: 3600,
            icmp_timeout_sec: 3600,
        };
        let mut engine = ConntrackEngine::new(config);

        engine
            .create_session(tcp_key(1000, 80), SessionState::Tcp(TcpState::Established))
            .unwrap();
        engine
            .create_session(tcp_key(1001, 80), SessionState::Tcp(TcpState::SynSent))
            .unwrap();
        engine
            .create_session(tcp_key(1002, 80), SessionState::Tcp(TcpState::FinWait))
            .unwrap();
        engine
            .create_session(tcp_key(1003, 80), SessionState::Tcp(TcpState::Closed))
            .unwrap();

        thread::sleep(Duration::from_millis(10));

        let removed = engine.gc();
        // SynSent, FinWait, Closed should be removed (transitory timeout=0).
        // Established should remain (timeout=3600).
        assert_eq!(removed, 3);
        assert_eq!(engine.session_count(), 1);

        // The remaining session should be the established one.
        let remaining = engine.lookup(&tcp_key(1000, 80));
        assert!(remaining.is_some());
        assert_eq!(
            remaining.unwrap().state,
            SessionState::Tcp(TcpState::Established)
        );
    }

    #[test]
    fn gc_udp_timeout() {
        let config = ConntrackConfig {
            max_sessions: 100,
            tcp_established_timeout_sec: 3600,
            tcp_transitory_timeout_sec: 3600,
            udp_timeout_sec: 0, // expire UDP immediately
            icmp_timeout_sec: 3600,
        };
        let mut engine = ConntrackEngine::new(config);

        engine
            .create_session(udp_key(2000, 53), SessionState::Udp)
            .unwrap();
        engine
            .create_session(tcp_key(1000, 80), SessionState::Tcp(TcpState::Established))
            .unwrap();

        thread::sleep(Duration::from_millis(10));

        let removed = engine.gc();
        assert_eq!(removed, 1);
        assert_eq!(engine.session_count(), 1);
        // TCP should remain, UDP should be gone.
        assert!(engine.lookup(&udp_key(2000, 53)).is_none());
        assert!(engine.lookup(&tcp_key(1000, 80)).is_some());
    }

    #[test]
    fn gc_icmp_timeout() {
        let config = ConntrackConfig {
            max_sessions: 100,
            tcp_established_timeout_sec: 3600,
            tcp_transitory_timeout_sec: 3600,
            udp_timeout_sec: 3600,
            icmp_timeout_sec: 0, // expire ICMP immediately
        };
        let mut engine = ConntrackEngine::new(config);

        engine
            .create_session(icmp_key(0x1234), SessionState::Icmp)
            .unwrap();
        engine
            .create_session(tcp_key(1000, 80), SessionState::Tcp(TcpState::Established))
            .unwrap();

        thread::sleep(Duration::from_millis(10));

        let removed = engine.gc();
        assert_eq!(removed, 1);
        assert_eq!(engine.session_count(), 1);
        // TCP should remain, ICMP should be gone.
        assert!(engine.lookup(&icmp_key(0x1234)).is_none());
        assert!(engine.lookup(&tcp_key(1000, 80)).is_some());
    }

    // ── from_nat_config test ───────────────────────────────────────

    #[test]
    fn from_nat_config() {
        let nat_config = NatConfig {
            enabled: true,
            mode: ruster_config::model::NatMode::Napt44,
            external_if: "wan0".to_string(),
            hairpin: false,
            session_table_max_entries: 65536,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
            port_forwards: vec![],
        };

        let engine = ConntrackEngine::from_nat_config(&nat_config);
        assert_eq!(engine.config.max_sessions, 65536);
        assert_eq!(engine.config.tcp_established_timeout_sec, 7200);
        assert_eq!(engine.config.tcp_transitory_timeout_sec, 120);
        assert_eq!(engine.config.udp_timeout_sec, 300);
        assert_eq!(engine.config.icmp_timeout_sec, 30);
        assert_eq!(engine.session_count(), 0);
        assert_eq!(engine.stats().created, 0);
    }

    // ── Stats tracking test ────────────────────────────────────────

    #[test]
    fn stats_track_lifecycle() {
        let mut engine = ConntrackEngine::new(default_config());

        assert_eq!(engine.stats().created, 0);
        assert_eq!(engine.stats().deleted, 0);
        assert_eq!(engine.stats().active(), 0);

        // Create two sessions.
        engine
            .create_session(tcp_key(1000, 80), SessionState::Tcp(TcpState::SynSent))
            .unwrap();
        engine
            .create_session(udp_key(2000, 53), SessionState::Udp)
            .unwrap();

        assert_eq!(engine.stats().created, 2);
        assert_eq!(engine.stats().deleted, 0);
        assert_eq!(engine.stats().active(), 2);

        // Remove one.
        engine.remove(&tcp_key(1000, 80));

        assert_eq!(engine.stats().created, 2);
        assert_eq!(engine.stats().deleted, 1);
        assert_eq!(engine.stats().active(), 1);
    }
}

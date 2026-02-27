//! BGP Finite State Machine (FSM).
//!
//! Implements the BGP FSM as defined in RFC 4271 Section 8.  The FSM
//! governs the lifecycle of a BGP peer session, from initial TCP
//! connection through to the Established state where routes are
//! exchanged.
//!
//! RFC-REF: RFC 4271 Section 8.2.2
//! "The BGP FSM described in this document has six states:
//! 1 - Idle
//! 2 - Connect
//! 3 - Active
//! 4 - OpenSent
//! 5 - OpenConfirm
//! 6 - Established"
//!
//! # Simplified FSM
//!
//! This is a minimal eBGP implementation. The Active state is merged
//! with Connect (we always actively connect, never passively listen).
//!
//! RFC-DEVIATION:
//! reason: minimal implementation omits Active state and passive listen
//! impact: cannot accept incoming BGP connections from peers
//! issue: #158
//! plan: add passive listen and Active state in v0.3

use std::fmt;
use std::time::{Duration, Instant};

use super::packet::{NotificationMessage, OpenMessage, ERR_CEASE, ERR_FSM, ERR_HOLD_TIMER_EXPIRED};

/// BGP FSM states.
///
/// RFC-REF: RFC 4271 Section 8.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BgpState {
    /// No BGP resources allocated; waiting for a Start event.
    Idle,
    /// TCP connection attempt in progress.
    Connect,
    /// OPEN message sent; waiting for peer's OPEN.
    OpenSent,
    /// OPEN received and validated; waiting for KEEPALIVE or NOTIFICATION.
    OpenConfirm,
    /// BGP session fully established; route exchange active.
    Established,
}

impl fmt::Display for BgpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Connect => write!(f, "Connect"),
            Self::OpenSent => write!(f, "OpenSent"),
            Self::OpenConfirm => write!(f, "OpenConfirm"),
            Self::Established => write!(f, "Established"),
        }
    }
}

/// Events that drive the FSM transitions.
///
/// RFC-REF: RFC 4271 Section 8.1
/// "The following events can occur in the BGP FSM."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmEvent {
    /// Administrative start (manual or config-driven).
    ManualStart,
    /// Administrative stop.
    ManualStop,
    /// TCP connection established successfully.
    TcpConnectionConfirmed,
    /// TCP connection failed.
    TcpConnectionFails,
    /// Received a valid OPEN message from the peer.
    BgpOpenReceived(OpenMessage),
    /// Received a KEEPALIVE from the peer.
    BgpKeepaliveReceived,
    /// Received a NOTIFICATION from the peer.
    BgpNotificationReceived(NotificationMessage),
    /// Received an UPDATE from the peer.
    BgpUpdateReceived,
    /// Hold timer expired.
    HoldTimerExpired,
    /// Keepalive timer expired (time to send a KEEPALIVE).
    KeepaliveTimerExpired,
    /// Connect retry timer expired.
    ConnectRetryTimerExpired,
}

/// Actions the FSM requests the engine to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmAction {
    /// Initiate a TCP connection to the peer.
    TcpConnect,
    /// Send an OPEN message.
    SendOpen,
    /// Send a KEEPALIVE message.
    SendKeepalive,
    /// Send a NOTIFICATION and close the session.
    SendNotification(NotificationMessage),
    /// Close the TCP connection.
    CloseTcp,
    /// Start the hold timer with the given duration.
    StartHoldTimer(Duration),
    /// Start the keepalive timer with the given duration.
    StartKeepaliveTimer(Duration),
    /// Start the connect retry timer.
    StartConnectRetryTimer(Duration),
    /// Stop all timers.
    StopTimers,
    /// Notify the engine that the session is Established.
    SessionEstablished,
    /// Notify the engine that the session has been torn down.
    SessionDown,
}

/// The BGP FSM for a single peer session.
///
/// Maintains the current state and timer state, and processes events
/// to produce a list of actions for the engine to execute.
#[derive(Debug)]
pub struct BgpFsm {
    /// Current FSM state.
    state: BgpState,
    /// Configured hold time (our side).
    configured_hold_time: u16,
    /// Negotiated hold time (min of ours and peer's).
    negotiated_hold_time: u16,
    /// Connect retry interval.
    connect_retry_interval: Duration,
    /// Peer's OPEN message, stored after validation.
    peer_open: Option<OpenMessage>,
    /// Timestamp of last state change (for diagnostics).
    last_state_change: Instant,
}

impl BgpFsm {
    /// Create a new FSM in the Idle state.
    pub fn new(hold_time: u16, connect_retry_secs: u64) -> Self {
        Self {
            state: BgpState::Idle,
            configured_hold_time: hold_time,
            negotiated_hold_time: hold_time,
            connect_retry_interval: Duration::from_secs(connect_retry_secs),
            peer_open: None,
            last_state_change: Instant::now(),
        }
    }

    /// Return the current FSM state.
    pub fn state(&self) -> BgpState {
        self.state
    }

    /// Return the negotiated hold time.
    pub fn negotiated_hold_time(&self) -> u16 {
        self.negotiated_hold_time
    }

    /// Return the peer's OPEN message, if received.
    pub fn peer_open(&self) -> Option<&OpenMessage> {
        self.peer_open.as_ref()
    }

    /// Return the duration since the last state change.
    pub fn uptime(&self) -> Duration {
        self.last_state_change.elapsed()
    }

    /// Process an event and return the resulting actions.
    ///
    /// This is the core FSM transition function. Each call may produce
    /// zero or more actions that the engine must execute.
    ///
    /// RFC-REF: RFC 4271 Section 8.2.2
    pub fn process_event(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match self.state {
            BgpState::Idle => self.handle_idle(event),
            BgpState::Connect => self.handle_connect(event),
            BgpState::OpenSent => self.handle_open_sent(event),
            BgpState::OpenConfirm => self.handle_open_confirm(event),
            BgpState::Established => self.handle_established(event),
        }
    }

    /// Transition to a new state, recording the timestamp.
    fn transition(&mut self, new_state: BgpState) {
        self.state = new_state;
        self.last_state_change = Instant::now();
    }

    // ── State handlers ───────────────────────────────────────────────

    /// Handle events in Idle state.
    ///
    /// RFC-REF: RFC 4271 Section 8.2.2 (Idle state)
    /// "In response to ManualStart event [...] the local system
    /// initializes all BGP resources, starts the ConnectRetryTimer."
    fn handle_idle(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::ManualStart | FsmEvent::ConnectRetryTimerExpired => {
                self.transition(BgpState::Connect);
                vec![
                    FsmAction::StartConnectRetryTimer(self.connect_retry_interval),
                    FsmAction::TcpConnect,
                ]
            }
            _ => {
                // All other events in Idle are ignored.
                vec![]
            }
        }
    }

    /// Handle events in Connect state.
    ///
    /// RFC-REF: RFC 4271 Section 8.2.2 (Connect state)
    fn handle_connect(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::TcpConnectionConfirmed => {
                self.transition(BgpState::OpenSent);
                vec![FsmAction::SendOpen]
            }
            FsmEvent::TcpConnectionFails => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::StopTimers,
                    FsmAction::StartConnectRetryTimer(self.connect_retry_interval),
                ]
            }
            FsmEvent::ConnectRetryTimerExpired => {
                // Retry the connection.
                vec![
                    FsmAction::StartConnectRetryTimer(self.connect_retry_interval),
                    FsmAction::TcpConnect,
                ]
            }
            FsmEvent::ManualStop => {
                self.transition(BgpState::Idle);
                vec![FsmAction::StopTimers, FsmAction::CloseTcp]
            }
            _ => {
                // Unexpected event: go to Idle.
                self.transition(BgpState::Idle);
                vec![FsmAction::StopTimers, FsmAction::CloseTcp]
            }
        }
    }

    /// Handle events in OpenSent state.
    ///
    /// RFC-REF: RFC 4271 Section 8.2.2 (OpenSent state)
    /// "An OPEN message has been sent to the peer."
    fn handle_open_sent(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::BgpOpenReceived(open) => {
                // Validate the OPEN and negotiate hold time.
                // RFC-REF: RFC 4271 Section 4.2
                // "If the negotiated hold time value is zero, then the Hold
                // Time timer and KeepaliveTimer are not started."
                self.negotiated_hold_time =
                    std::cmp::min(self.configured_hold_time, open.hold_time);
                self.peer_open = Some(open);

                self.transition(BgpState::OpenConfirm);

                let mut actions = vec![FsmAction::SendKeepalive];

                if self.negotiated_hold_time > 0 {
                    let hold_dur = Duration::from_secs(self.negotiated_hold_time as u64);
                    let keepalive_dur = Duration::from_secs(self.negotiated_hold_time as u64 / 3);
                    actions.push(FsmAction::StartHoldTimer(hold_dur));
                    actions.push(FsmAction::StartKeepaliveTimer(keepalive_dur));
                }

                actions
            }
            FsmEvent::BgpNotificationReceived(_) => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::TcpConnectionFails => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::StopTimers,
                    FsmAction::StartConnectRetryTimer(self.connect_retry_interval),
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::HoldTimerExpired => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_HOLD_TIMER_EXPIRED,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::ManualStop => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_CEASE,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            _ => {
                // Unexpected event: send NOTIFICATION and go to Idle.
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_FSM,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
        }
    }

    /// Handle events in OpenConfirm state.
    ///
    /// RFC-REF: RFC 4271 Section 8.2.2 (OpenConfirm state)
    /// "In this state, the BGP FSM waits for a KEEPALIVE or
    /// NOTIFICATION message."
    fn handle_open_confirm(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::BgpKeepaliveReceived => {
                self.transition(BgpState::Established);
                let mut actions = vec![FsmAction::SessionEstablished];
                if self.negotiated_hold_time > 0 {
                    let hold_dur = Duration::from_secs(self.negotiated_hold_time as u64);
                    actions.push(FsmAction::StartHoldTimer(hold_dur));
                }
                actions
            }
            FsmEvent::BgpNotificationReceived(_) => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::HoldTimerExpired => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_HOLD_TIMER_EXPIRED,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::KeepaliveTimerExpired => {
                vec![FsmAction::SendKeepalive]
            }
            FsmEvent::TcpConnectionFails => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::StopTimers,
                    FsmAction::StartConnectRetryTimer(self.connect_retry_interval),
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::ManualStop => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_CEASE,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            _ => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_FSM,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
        }
    }

    /// Handle events in Established state.
    ///
    /// RFC-REF: RFC 4271 Section 8.2.2 (Established state)
    /// "In the Established state, the BGP FSM can exchange UPDATE,
    /// NOTIFICATION, and KEEPALIVE messages with its peer."
    fn handle_established(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::BgpKeepaliveReceived | FsmEvent::BgpUpdateReceived => {
                // Reset hold timer on any valid message.
                let mut actions = Vec::new();
                if self.negotiated_hold_time > 0 {
                    let hold_dur = Duration::from_secs(self.negotiated_hold_time as u64);
                    actions.push(FsmAction::StartHoldTimer(hold_dur));
                }
                actions
            }
            FsmEvent::KeepaliveTimerExpired => {
                vec![FsmAction::SendKeepalive]
            }
            FsmEvent::HoldTimerExpired => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_HOLD_TIMER_EXPIRED,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::BgpNotificationReceived(_) => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::TcpConnectionFails => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::StopTimers,
                    FsmAction::StartConnectRetryTimer(self.connect_retry_interval),
                    FsmAction::SessionDown,
                ]
            }
            FsmEvent::ManualStop => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_CEASE,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
            _ => {
                self.transition(BgpState::Idle);
                vec![
                    FsmAction::SendNotification(NotificationMessage {
                        error_code: ERR_FSM,
                        error_subcode: 0,
                        data: vec![],
                    }),
                    FsmAction::StopTimers,
                    FsmAction::CloseTcp,
                    FsmAction::SessionDown,
                ]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fsm() -> BgpFsm {
        BgpFsm::new(90, 30)
    }

    fn make_peer_open() -> OpenMessage {
        OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: [10, 0, 0, 2],
            capabilities: vec![],
        }
    }

    // ── Basic lifecycle: Idle → Connect → OpenSent → OpenConfirm → Established ──

    #[test]
    fn idle_to_connect_on_manual_start() {
        let mut fsm = make_fsm();
        assert_eq!(fsm.state(), BgpState::Idle);

        let actions = fsm.process_event(FsmEvent::ManualStart);
        assert_eq!(fsm.state(), BgpState::Connect);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::TcpConnect)));
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::StartConnectRetryTimer(_))));
    }

    #[test]
    fn connect_to_open_sent_on_tcp_confirmed() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        assert_eq!(fsm.state(), BgpState::Connect);

        let actions = fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), BgpState::OpenSent);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendOpen)));
    }

    #[test]
    fn open_sent_to_open_confirm_on_open_received() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), BgpState::OpenSent);

        let actions = fsm.process_event(FsmEvent::BgpOpenReceived(make_peer_open()));
        assert_eq!(fsm.state(), BgpState::OpenConfirm);
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendKeepalive)));
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::StartHoldTimer(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::StartKeepaliveTimer(_))));
    }

    #[test]
    fn open_confirm_to_established_on_keepalive() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        fsm.process_event(FsmEvent::BgpOpenReceived(make_peer_open()));
        assert_eq!(fsm.state(), BgpState::OpenConfirm);

        let actions = fsm.process_event(FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::SessionEstablished)));
    }

    // ── Hold timer negotiation ───────────────────────────────────────

    #[test]
    fn hold_time_negotiated_to_minimum() {
        let mut fsm = BgpFsm::new(90, 30);
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);

        // Peer offers lower hold time.
        let mut open = make_peer_open();
        open.hold_time = 30;
        fsm.process_event(FsmEvent::BgpOpenReceived(open));

        assert_eq!(fsm.negotiated_hold_time(), 30);
    }

    #[test]
    fn hold_time_zero_disables_timers() {
        let mut fsm = BgpFsm::new(0, 30);
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);

        let mut open = make_peer_open();
        open.hold_time = 0;
        let actions = fsm.process_event(FsmEvent::BgpOpenReceived(open));

        assert_eq!(fsm.negotiated_hold_time(), 0);
        // No hold/keepalive timers should be started.
        assert!(!actions
            .iter()
            .any(|a| matches!(a, FsmAction::StartHoldTimer(_))));
        assert!(!actions
            .iter()
            .any(|a| matches!(a, FsmAction::StartKeepaliveTimer(_))));
    }

    // ── Error handling ───────────────────────────────────────────────

    #[test]
    fn connect_tcp_fails_goes_idle() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        assert_eq!(fsm.state(), BgpState::Connect);

        let actions = fsm.process_event(FsmEvent::TcpConnectionFails);
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::StopTimers)));
    }

    #[test]
    fn open_sent_hold_timer_expired() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), BgpState::OpenSent);

        let actions = fsm.process_event(FsmEvent::HoldTimerExpired);
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendNotification(_))));
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SessionDown)));
    }

    #[test]
    fn established_hold_timer_expired() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        fsm.process_event(FsmEvent::BgpOpenReceived(make_peer_open()));
        fsm.process_event(FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);

        let actions = fsm.process_event(FsmEvent::HoldTimerExpired);
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendNotification(_))));
    }

    #[test]
    fn established_notification_received_goes_idle() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        fsm.process_event(FsmEvent::BgpOpenReceived(make_peer_open()));
        fsm.process_event(FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);

        let notif = NotificationMessage {
            error_code: ERR_CEASE,
            error_subcode: 0,
            data: vec![],
        };
        let actions = fsm.process_event(FsmEvent::BgpNotificationReceived(notif));
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SessionDown)));
    }

    #[test]
    fn established_manual_stop() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        fsm.process_event(FsmEvent::BgpOpenReceived(make_peer_open()));
        fsm.process_event(FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);

        let actions = fsm.process_event(FsmEvent::ManualStop);
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendNotification(_))));
        assert!(actions.iter().any(|a| matches!(a, FsmAction::CloseTcp)));
    }

    // ── Keepalive in Established ─────────────────────────────────────

    #[test]
    fn established_keepalive_timer_expired_sends_keepalive() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        fsm.process_event(FsmEvent::BgpOpenReceived(make_peer_open()));
        fsm.process_event(FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);

        let actions = fsm.process_event(FsmEvent::KeepaliveTimerExpired);
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendKeepalive)));
    }

    #[test]
    fn established_keepalive_received_resets_hold_timer() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        fsm.process_event(FsmEvent::BgpOpenReceived(make_peer_open()));
        fsm.process_event(FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);

        let actions = fsm.process_event(FsmEvent::BgpKeepaliveReceived);
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::StartHoldTimer(_))));
    }

    // ── OpenConfirm keepalive timer ──────────────────────────────────

    #[test]
    fn open_confirm_keepalive_timer_sends_keepalive() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        fsm.process_event(FsmEvent::BgpOpenReceived(make_peer_open()));
        assert_eq!(fsm.state(), BgpState::OpenConfirm);

        let actions = fsm.process_event(FsmEvent::KeepaliveTimerExpired);
        assert!(actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendKeepalive)));
    }

    // ── Idle ignores non-start events ────────────────────────────────

    #[test]
    fn idle_ignores_keepalive() {
        let mut fsm = make_fsm();
        let actions = fsm.process_event(FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(actions.is_empty());
    }

    #[test]
    fn idle_ignores_tcp_connection() {
        let mut fsm = make_fsm();
        let actions = fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(actions.is_empty());
    }

    // ── Connect retry ────────────────────────────────────────────────

    #[test]
    fn connect_retry_timer_in_idle() {
        let mut fsm = make_fsm();
        let actions = fsm.process_event(FsmEvent::ConnectRetryTimerExpired);
        assert_eq!(fsm.state(), BgpState::Connect);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::TcpConnect)));
    }

    #[test]
    fn connect_retry_timer_in_connect() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        assert_eq!(fsm.state(), BgpState::Connect);

        let actions = fsm.process_event(FsmEvent::ConnectRetryTimerExpired);
        assert_eq!(fsm.state(), BgpState::Connect); // stays in Connect
        assert!(actions.iter().any(|a| matches!(a, FsmAction::TcpConnect)));
    }

    // ── TCP failure in OpenSent ──────────────────────────────────────

    #[test]
    fn open_sent_tcp_fails_goes_idle() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), BgpState::OpenSent);

        let actions = fsm.process_event(FsmEvent::TcpConnectionFails);
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SessionDown)));
    }

    // ── Peer OPEN stored ─────────────────────────────────────────────

    #[test]
    fn peer_open_stored_after_open_received() {
        let mut fsm = make_fsm();
        fsm.process_event(FsmEvent::ManualStart);
        fsm.process_event(FsmEvent::TcpConnectionConfirmed);
        assert!(fsm.peer_open().is_none());

        let open = make_peer_open();
        fsm.process_event(FsmEvent::BgpOpenReceived(open.clone()));
        assert_eq!(fsm.peer_open(), Some(&open));
    }
}

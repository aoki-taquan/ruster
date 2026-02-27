//! OSPF neighbor state machine.
//!
//! Implements the full neighbor state transitions as defined in
//! RFC 2328 Section 10.  The neighbor state machine is the core of
//! OSPF adjacency formation.
//!
//! RFC-REF: RFC 2328 Section 10
//! "Each OSPF router maintains a neighbor data structure for every
//! router in every attached network."

use std::fmt;

// ── Neighbor state ──────────────────────────────────────────────────

/// Neighbor state machine states.
///
/// RFC-REF: RFC 2328 Section 10.1
/// "The various neighbor states are listed in order of progressing
/// functionality."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NeighborState {
    /// Initial state; no information has been received from this neighbor.
    Down,
    /// A Hello has been received from the neighbor, but bidirectional
    /// communication has not yet been established.
    Init,
    /// Bidirectional communication established (our Router ID appears
    /// in the neighbor's Hello).
    TwoWay,
    /// First step of adjacency formation.  The master/slave
    /// relationship is being negotiated.
    ExStart,
    /// Database Description packets are being exchanged.
    Exchange,
    /// Link State Request packets are being sent to the neighbor.
    Loading,
    /// The neighbor is fully adjacent; databases are synchronized.
    Full,
}

impl fmt::Display for NeighborState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Down => write!(f, "Down"),
            Self::Init => write!(f, "Init"),
            Self::TwoWay => write!(f, "2-Way"),
            Self::ExStart => write!(f, "ExStart"),
            Self::Exchange => write!(f, "Exchange"),
            Self::Loading => write!(f, "Loading"),
            Self::Full => write!(f, "Full"),
        }
    }
}

// ── Neighbor events ─────────────────────────────────────────────────

/// Events that drive neighbor state transitions.
///
/// RFC-REF: RFC 2328 Section 10.2
/// "Neighbor state changes are caused by the receipt of OSPF packets,
/// expiration of timers, and certain external events."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborEvent {
    /// A Hello packet was received from the neighbor.
    HelloReceived,
    /// The neighbor's Hello lists our Router ID (bidirectional).
    TwoWayReceived,
    /// Negotiation of the master/slave relationship is done.
    NegotiationDone,
    /// A DD packet with the neighbor's database summary was received
    /// and processed.
    ExchangeDone,
    /// All Link State Requests have been satisfied.
    LoadingDone,
    /// An adjacency should be formed (DR/BDR or point-to-point).
    AdjOk,
    /// The router dead interval has expired with no Hello received.
    InactivityTimer,
    /// A sequence number mismatch or other error was detected.
    SeqNumberMismatch,
    /// A bad Link State Request was received.
    BadLsReq,
    /// A lower-level indication that communication is not possible.
    KillNbr,
    /// One-way communication detected.
    OneWay,
}

impl fmt::Display for NeighborEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelloReceived => write!(f, "HelloReceived"),
            Self::TwoWayReceived => write!(f, "2-WayReceived"),
            Self::NegotiationDone => write!(f, "NegotiationDone"),
            Self::ExchangeDone => write!(f, "ExchangeDone"),
            Self::LoadingDone => write!(f, "LoadingDone"),
            Self::AdjOk => write!(f, "AdjOK?"),
            Self::InactivityTimer => write!(f, "InactivityTimer"),
            Self::SeqNumberMismatch => write!(f, "SeqNumberMismatch"),
            Self::BadLsReq => write!(f, "BadLSReq"),
            Self::KillNbr => write!(f, "KillNbr"),
            Self::OneWay => write!(f, "1-Way"),
        }
    }
}

// ── Neighbor data structure ─────────────────────────────────────────

/// OSPF neighbor data structure.
///
/// RFC-REF: RFC 2328 Section 10
/// "Each OSPF router maintains a neighbor data structure for every
/// router in every attached network."
#[derive(Debug, Clone)]
pub struct Neighbor {
    /// Neighbor's Router ID.
    pub router_id: [u8; 4],
    /// Current state of the neighbor.
    pub state: NeighborState,
    /// Neighbor's IP address (source of Hello packets).
    pub ip_addr: [u8; 4],
    /// Neighbor's Router Priority (from Hello).
    pub priority: u8,
    /// Neighbor's Designated Router (from Hello).
    pub designated_router: [u8; 4],
    /// Neighbor's Backup Designated Router (from Hello).
    pub backup_designated_router: [u8; 4],
    /// Whether this neighbor is the master in DD exchange.
    pub is_master: bool,
    /// DD sequence number for this adjacency.
    pub dd_seq_number: u32,
    /// Timestamp of last Hello received (as epoch seconds).
    pub last_hello: u64,
    /// The interface on which this neighbor was discovered.
    pub interface_name: String,
}

impl Neighbor {
    /// Create a new neighbor in the Down state.
    pub fn new(router_id: [u8; 4], ip_addr: [u8; 4], interface_name: String) -> Self {
        Self {
            router_id,
            state: NeighborState::Down,
            ip_addr,
            priority: 0,
            designated_router: [0; 4],
            backup_designated_router: [0; 4],
            is_master: false,
            dd_seq_number: 0,
            last_hello: 0,
            interface_name,
        }
    }

    /// Process a neighbor event and transition state.
    ///
    /// Returns the new state after processing the event.
    ///
    /// RFC-REF: RFC 2328 Section 10.3 (state transitions table)
    /// The state machine is implemented as a match on (current_state, event).
    pub fn handle_event(&mut self, event: NeighborEvent) -> NeighborState {
        let new_state = match (self.state, event) {
            // ── Down state ──────────────────────────────────────
            // RFC-REF: RFC 2328 Section 10.3
            // "State(s):  Down
            //  Event:     HelloReceived
            //  New state: Init"
            (NeighborState::Down, NeighborEvent::HelloReceived) => NeighborState::Init,

            // ── Init state ──────────────────────────────────────
            // RFC-REF: RFC 2328 Section 10.3
            // "State(s):  Init
            //  Event:     2-WayReceived
            //  New state: depends on whether adjacency should form"
            (NeighborState::Init, NeighborEvent::TwoWayReceived) => {
                // RFC-DEVIATION:
                // reason: We always form adjacency (no DR election).
                //         In a full implementation, 2-WayReceived on
                //         broadcast networks would check DR/BDR status.
                // impact: On broadcast networks with many routers, all
                //         routers will form full adjacency with all
                //         neighbors, which is inefficient.
                // issue: #157
                // plan: Implement DR election in a future version.
                NeighborState::ExStart
            }
            (NeighborState::Init, NeighborEvent::HelloReceived) => NeighborState::Init,

            // ── 2-Way state ─────────────────────────────────────
            (NeighborState::TwoWay, NeighborEvent::AdjOk) => NeighborState::ExStart,
            (NeighborState::TwoWay, NeighborEvent::HelloReceived) => NeighborState::TwoWay,

            // ── ExStart state ───────────────────────────────────
            // RFC-REF: RFC 2328 Section 10.3
            // "State(s):  ExStart
            //  Event:     NegotiationDone
            //  New state: Exchange"
            (NeighborState::ExStart, NeighborEvent::NegotiationDone) => NeighborState::Exchange,
            (NeighborState::ExStart, NeighborEvent::HelloReceived) => NeighborState::ExStart,

            // ── Exchange state ──────────────────────────────────
            // RFC-REF: RFC 2328 Section 10.3
            // "State(s):  Exchange
            //  Event:     ExchangeDone
            //  New state: Loading or Full"
            (NeighborState::Exchange, NeighborEvent::ExchangeDone) => {
                // If there are no LSAs to request, go directly to Full.
                // In our minimal implementation, we go to Loading first.
                NeighborState::Loading
            }
            (NeighborState::Exchange, NeighborEvent::HelloReceived) => NeighborState::Exchange,

            // ── Loading state ───────────────────────────────────
            // RFC-REF: RFC 2328 Section 10.3
            // "State(s):  Loading
            //  Event:     LoadingDone
            //  New state: Full"
            (NeighborState::Loading, NeighborEvent::LoadingDone) => NeighborState::Full,
            (NeighborState::Loading, NeighborEvent::HelloReceived) => NeighborState::Loading,

            // ── Full state ──────────────────────────────────────
            (NeighborState::Full, NeighborEvent::HelloReceived) => NeighborState::Full,

            // ── Error / reset events (from any state >= Init) ───
            // RFC-REF: RFC 2328 Section 10.3
            // "State(s):  Any state >= ExStart
            //  Event:     SeqNumberMismatch / BadLSReq
            //  New state: ExStart"
            (state, NeighborEvent::SeqNumberMismatch) if state >= NeighborState::ExStart => {
                self.dd_seq_number = self.dd_seq_number.wrapping_add(1);
                NeighborState::ExStart
            }
            (state, NeighborEvent::BadLsReq) if state >= NeighborState::ExStart => {
                self.dd_seq_number = self.dd_seq_number.wrapping_add(1);
                NeighborState::ExStart
            }

            // ── Kill / inactivity events (from any state) ───────
            // RFC-REF: RFC 2328 Section 10.3
            // "State(s):  Any
            //  Event:     KillNbr / InactivityTimer / LLDown
            //  New state: Down"
            (_, NeighborEvent::KillNbr) => NeighborState::Down,
            (_, NeighborEvent::InactivityTimer) => NeighborState::Down,

            // ── OneWay (from >= 2-Way) ──────────────────────────
            // RFC-REF: RFC 2328 Section 10.3
            // "State(s):  >= 2-Way
            //  Event:     1-Way
            //  New state: Init"
            (state, NeighborEvent::OneWay) if state >= NeighborState::TwoWay => NeighborState::Init,

            // All other (state, event) combinations: no transition.
            (state, _) => state,
        };

        self.state = new_state;
        new_state
    }

    /// Check if this neighbor has formed a full adjacency.
    pub fn is_full(&self) -> bool {
        self.state == NeighborState::Full
    }

    /// Check if this neighbor is at least 2-Way.
    pub fn is_bidirectional(&self) -> bool {
        self.state >= NeighborState::TwoWay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_neighbor() -> Neighbor {
        Neighbor::new([2, 2, 2, 2], [10, 0, 0, 2], "eth0".to_string())
    }

    // ── Basic state progression: Down -> Full ───────────────────────

    #[test]
    fn down_to_init_on_hello() {
        let mut nbr = make_neighbor();
        assert_eq!(nbr.state, NeighborState::Down);
        let new = nbr.handle_event(NeighborEvent::HelloReceived);
        assert_eq!(new, NeighborState::Init);
    }

    #[test]
    fn init_to_exstart_on_two_way() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        let new = nbr.handle_event(NeighborEvent::TwoWayReceived);
        assert_eq!(new, NeighborState::ExStart);
    }

    #[test]
    fn exstart_to_exchange_on_negotiation_done() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        let new = nbr.handle_event(NeighborEvent::NegotiationDone);
        assert_eq!(new, NeighborState::Exchange);
    }

    #[test]
    fn exchange_to_loading_on_exchange_done() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        nbr.handle_event(NeighborEvent::NegotiationDone);
        let new = nbr.handle_event(NeighborEvent::ExchangeDone);
        assert_eq!(new, NeighborState::Loading);
    }

    #[test]
    fn loading_to_full_on_loading_done() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        nbr.handle_event(NeighborEvent::NegotiationDone);
        nbr.handle_event(NeighborEvent::ExchangeDone);
        let new = nbr.handle_event(NeighborEvent::LoadingDone);
        assert_eq!(new, NeighborState::Full);
    }

    #[test]
    fn full_progression_complete() {
        let mut nbr = make_neighbor();
        // Walk through the entire state progression.
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        nbr.handle_event(NeighborEvent::NegotiationDone);
        nbr.handle_event(NeighborEvent::ExchangeDone);
        nbr.handle_event(NeighborEvent::LoadingDone);
        assert!(nbr.is_full());
        assert!(nbr.is_bidirectional());
    }

    // ── Reset events ────────────────────────────────────────────────

    #[test]
    fn inactivity_timer_resets_to_down() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        nbr.handle_event(NeighborEvent::NegotiationDone);
        assert_eq!(nbr.state, NeighborState::Exchange);

        let new = nbr.handle_event(NeighborEvent::InactivityTimer);
        assert_eq!(new, NeighborState::Down);
    }

    #[test]
    fn kill_nbr_resets_to_down_from_any_state() {
        for start_event_chain in [
            vec![],
            vec![NeighborEvent::HelloReceived],
            vec![NeighborEvent::HelloReceived, NeighborEvent::TwoWayReceived],
        ] {
            let mut nbr = make_neighbor();
            for event in &start_event_chain {
                nbr.handle_event(*event);
            }
            let new = nbr.handle_event(NeighborEvent::KillNbr);
            assert_eq!(new, NeighborState::Down);
        }
    }

    #[test]
    fn seq_mismatch_resets_to_exstart_from_exchange() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        nbr.handle_event(NeighborEvent::NegotiationDone);
        assert_eq!(nbr.state, NeighborState::Exchange);

        let new = nbr.handle_event(NeighborEvent::SeqNumberMismatch);
        assert_eq!(new, NeighborState::ExStart);
    }

    #[test]
    fn bad_ls_req_resets_to_exstart_from_loading() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        nbr.handle_event(NeighborEvent::NegotiationDone);
        nbr.handle_event(NeighborEvent::ExchangeDone);
        assert_eq!(nbr.state, NeighborState::Loading);

        let new = nbr.handle_event(NeighborEvent::BadLsReq);
        assert_eq!(new, NeighborState::ExStart);
    }

    #[test]
    fn one_way_from_full_resets_to_init() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        nbr.handle_event(NeighborEvent::NegotiationDone);
        nbr.handle_event(NeighborEvent::ExchangeDone);
        nbr.handle_event(NeighborEvent::LoadingDone);
        assert_eq!(nbr.state, NeighborState::Full);

        let new = nbr.handle_event(NeighborEvent::OneWay);
        assert_eq!(new, NeighborState::Init);
    }

    // ── Hello in stable states stays in same state ──────────────────

    #[test]
    fn hello_in_full_stays_full() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        nbr.handle_event(NeighborEvent::NegotiationDone);
        nbr.handle_event(NeighborEvent::ExchangeDone);
        nbr.handle_event(NeighborEvent::LoadingDone);
        let new = nbr.handle_event(NeighborEvent::HelloReceived);
        assert_eq!(new, NeighborState::Full);
    }

    // ── Display tests ───────────────────────────────────────────────

    #[test]
    fn state_display() {
        assert_eq!(format!("{}", NeighborState::Down), "Down");
        assert_eq!(format!("{}", NeighborState::Init), "Init");
        assert_eq!(format!("{}", NeighborState::TwoWay), "2-Way");
        assert_eq!(format!("{}", NeighborState::ExStart), "ExStart");
        assert_eq!(format!("{}", NeighborState::Exchange), "Exchange");
        assert_eq!(format!("{}", NeighborState::Loading), "Loading");
        assert_eq!(format!("{}", NeighborState::Full), "Full");
    }

    #[test]
    fn event_display() {
        assert_eq!(format!("{}", NeighborEvent::HelloReceived), "HelloReceived");
        assert_eq!(
            format!("{}", NeighborEvent::TwoWayReceived),
            "2-WayReceived"
        );
        assert_eq!(
            format!("{}", NeighborEvent::InactivityTimer),
            "InactivityTimer"
        );
    }

    // ── Helper method tests ─────────────────────────────────────────

    #[test]
    fn is_bidirectional_false_for_init() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        assert!(!nbr.is_bidirectional());
    }

    #[test]
    fn is_bidirectional_true_for_two_way_and_above() {
        let mut nbr = make_neighbor();
        nbr.handle_event(NeighborEvent::HelloReceived);
        nbr.handle_event(NeighborEvent::TwoWayReceived);
        // State is now ExStart (>= 2-Way).
        assert!(nbr.is_bidirectional());
    }
}

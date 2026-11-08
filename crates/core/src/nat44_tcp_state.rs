//! Minimal TCP connection tracking for the TCP NAT44 session timers.
//!
//! A TCP connection has three phases, each with a floor for its idle timeout:
//! the partially open phase ("initiated by the first SYN for the connection
//! and extends until both endpoints have sent a packet with the ACK flag
//! set") and the closing phase ("when both endpoints have terminated their
//! half of the connection by sending a FIN packet") use the transitory
//! connection idle-timeout (at least 4 minutes); the established phase in
//! between uses the established connection idle-timeout (at least 2 hours 4
//! minutes). A RST is translated and keeps the session for 4 minutes of
//! idleness instead of deleting it; a later non-RST packet returns the
//! connection to its previous phase.
//!
//! The session records which flags each direction has sent: SYN, ACK, and
//! FIN outbound (inside to outside) and inbound, whether a RST is pending,
//! and (only under [`Nat44TcpInboundRst::Corroborate`]) whether an inbound
//! FIN still awaits outbound corroboration. The phase is a pure function of
//! those bits ([`phase_of`]):
//!
//! - closing: a RST is pending, or FIN has been seen (and corroborated) in
//!   both directions;
//! - established: ACK seen in both directions and a SYN in at least one.
//!   This is the wording quoted above (a connection starts with a SYN). It
//!   is deliberately weaker than the state machine's "Server SYN" (see
//!   # Standards): requiring a SYN from each side let an injected RST plus a
//!   remote SYN (answered by a challenge ACK) leave an established
//!   connection on the opening timer for good;
//! - opening: anything else. A FIN in one direction keeps the phase, as the
//!   state machine's V4/V6 FIN RCV states do.
//!
//! No sequence numbers are tracked, so no segment is validated beyond the
//! exact session 5-tuple the NAT already requires. That is why the phase
//! never drops a session at once: a RST, genuine or injected, only moves it
//! to the closing timer (never below the transitory idle-timeout), and any
//! later non-RST segment restores the phase its flags describe.
//!
//! # Standards
//!
//! - RFC 5382 section 5 (REQ-5): the three phases and their idle timeouts, in
//!   the words quoted above. The floors are checked by the TCP NAT policy.
//! - RFC 7857 section 2 (Figure 1, adapted from RFC 6146 section 3.5.2.2):
//!   the state machine. Section 2.2: a RST moves the session to the
//!   transitory timeout instead of deleting it, and a later non-RST packet
//!   moves it back (RFC 6146's TRANS state).
//! - RFC 5961 section 4: the challenge ACK that the established rule allows
//!   for.
//! - RFC 1122 section 4.2.2.13: a new connection on the 5-tuple of one closed
//!   by FIN in both directions starts over.
//!
//! Deviations: a connection is established once both sides sent an ACK and
//! one sent a SYN, not on Figure 1's "Server SYN". No sequence numbers are
//! checked, so a RST is not checked against the window. A repeated RST
//! restarts the closing timer, which RFC 6146 does not do in TRANS. Under
//! [`Nat44TcpInboundRst::Corroborate`], an operator choice, inbound RSTs and
//! FINs alone do not move a session toward closing.

/// Phase of a TCP NAT session, which selects its idle timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Nat44TcpSessionPhase {
    /// Partially open: ACK not yet seen in both directions. Uses the
    /// opening (transitory) idle timeout.
    Opening,
    /// Established: ACK seen in both directions after a SYN, FIN in at most
    /// one, and no RST pending. Uses the established idle timeout.
    Established,
    /// Closing: FIN seen in both directions, or a RST was the last segment.
    /// Uses the closing (transitory) idle timeout.
    Closing,
}

impl Nat44TcpSessionPhase {
    /// Number of phases (and of session activity lists).
    pub(crate) const COUNT: usize = 3;

    /// Index of this phase's session activity list.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Opening => 0,
            Self::Established => 1,
            Self::Closing => 2,
        }
    }
}

/// What inbound (outside to inside) close signals and handshake ACKs do to
/// a TCP NAT session's phase. Inbound segments can be spoofed off-path
/// once the 5-tuple is guessed; the NAT does not track sequence numbers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Nat44TcpInboundRst {
    /// The standard behavior (the default): an inbound RST moves the session to the
    /// closing timeout and an inbound FIN counts toward the closing phase,
    /// exactly like outbound ones.
    #[default]
    Closing,
    /// Local security policy: inbound segments alone never move a session
    /// toward closing or into the established phase. An inbound RST is
    /// translated but leaves the phase unchanged; an inbound FIN after an
    /// outbound FIN closes only once an outbound FIN or RST corroborates
    /// it; the outbound ACK that establishes a connection must be a segment
    /// without SYN (so an inside SYN-ACK to a spoofed SYN, answered by a
    /// blind spoofed ACK, stays opening). The cost: a connection the inside
    /// host closes first, or an inbound-initiated connection on which the
    /// inside host sends nothing after its SYN-ACK, keeps a longer (resp.
    /// the opening) timeout.
    Corroborate,
}

impl Nat44TcpInboundRst {
    /// The declarative-config spelling (`inbound-rst = "..."`).
    #[must_use]
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::Closing => "closing",
            Self::Corroborate => "corroborate",
        }
    }
}

/// Which side sent a segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Nat44TcpDirection {
    /// Inside to outside (including the outbound half of a hairpin).
    Outbound,
    /// Outside to inside (including the inbound half of a hairpin).
    Inbound,
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// The control flags of one TCP segment that drive session tracking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Nat44TcpSegment {
    flags: u8,
}

impl Nat44TcpSegment {
    /// A bare initial SYN (SYN=1, ACK/RST/FIN=0).
    pub(crate) const INITIAL_SYN: Self = Self { flags: TCP_SYN };

    /// From the TCP header flags byte (offset 13).
    pub(crate) const fn from_flags(flags: u8) -> Self {
        Self { flags }
    }

    /// SYN=1 with ACK, RST, and FIN all 0: the only segment that may create
    /// a mapping or session.
    pub(crate) const fn is_initial_syn(self) -> bool {
        self.flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN) == TCP_SYN
    }

    const fn has(self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Tests write segments as booleans: `true` is an initial SYN, `false` a
/// bare ACK.
#[cfg(test)]
impl From<bool> for Nat44TcpSegment {
    fn from(initial_syn: bool) -> Self {
        Self::from_flags(if initial_syn { TCP_SYN } else { TCP_ACK })
    }
}

/// Bits of the per-session state byte.
pub(crate) const STATE_SYN_OUT: u8 = 0x01;
pub(crate) const STATE_SYN_IN: u8 = 0x02;
pub(crate) const STATE_ACK_OUT: u8 = 0x04;
pub(crate) const STATE_ACK_IN: u8 = 0x08;
pub(crate) const STATE_FIN_OUT: u8 = 0x10;
pub(crate) const STATE_FIN_IN: u8 = 0x20;
pub(crate) const STATE_RESET: u8 = 0x40;
/// Under [`Nat44TcpInboundRst::Corroborate`]: the inbound FIN arrived after
/// the outbound one and no outbound FIN or RST has corroborated it yet.
pub(crate) const STATE_FIN_IN_UNCONFIRMED: u8 = 0x80;
const STATE_ACK_BOTH: u8 = STATE_ACK_OUT | STATE_ACK_IN;
const STATE_SYN_ANY: u8 = STATE_SYN_OUT | STATE_SYN_IN;
const STATE_FIN_BOTH: u8 = STATE_FIN_OUT | STATE_FIN_IN;

/// FIN seen and corroborated in both directions.
pub(crate) const fn fin_closed(state: u8) -> bool {
    state & STATE_FIN_BOTH == STATE_FIN_BOTH && state & STATE_FIN_IN_UNCONFIRMED == 0
}

/// The phase a session state byte describes.
pub(crate) const fn phase_of(state: u8) -> Nat44TcpSessionPhase {
    if state & STATE_RESET != 0 || fin_closed(state) {
        Nat44TcpSessionPhase::Closing
    } else if state & STATE_ACK_BOTH == STATE_ACK_BOTH && state & STATE_SYN_ANY != 0 {
        Nat44TcpSessionPhase::Established
    } else {
        Nat44TcpSessionPhase::Opening
    }
}

/// The state after one committed segment and whether it restarted the
/// session as a new connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Nat44TcpTransition {
    pub(crate) state: u8,
    /// The segment restarted a session closed by FIN in both directions as
    /// a new connection on the same 5-tuple; the value is the side that
    /// initiated it: `Outbound` for an outbound initial SYN (the inside host
    /// reconnects), `Inbound` for an outbound SYN-ACK (the inside host
    /// accepted a new SYN from the remote).
    pub(crate) restart: Option<Nat44TcpDirection>,
}

/// The session state after `segment` from `direction` is committed on a
/// session in `state` (`0` for a session this segment creates).
///
/// - RST: sets the reset bit and nothing else (the closing timer; the
///   ESTABLISHED to TRANS move). Other flags on a RST segment are
///   ignored, so a RST never establishes or closes a connection by itself.
///   A repeated RST keeps the reset bit and, as every committed segment,
///   restarts the closing timer (TRANS is not refreshed by a RST in the
///   state machine; REQ-5 measures idle time, so a RST is activity). Under
///   [`Nat44TcpInboundRst::Corroborate`] an inbound RST changes nothing.
/// - Any other segment clears the reset bit (TRANS: "If a packet
///   other than a RST packet is received ... The state is moved to
///   ESTABLISHED"; here: back to the phase the flags describe, SYN
///   included).
/// - On a session closed by FIN in both directions, a new connection on
///   the same 5-tuple (reopen from TIME-WAIT) clears
///   the flags first, but only on evidence from the inside host: an
///   outbound initial SYN (the inside reconnects), or an outbound SYN-ACK
///   (the inside accepted a new SYN from the remote; the remote's SYN is
///   recorded for the new connection). Inbound segments alone never
///   restart a session: they can be spoofed.
/// - SYN, ACK, and FIN are recorded for the sending direction (with the
///   corroboration rules of [`Nat44TcpInboundRst::Corroborate`]: there an
///   inbound FIN is unconfirmed until a later outbound FIN or RST, whatever
///   the order of the two FINs).
pub(crate) const fn next_state(
    state: u8,
    segment: Nat44TcpSegment,
    direction: Nat44TcpDirection,
    inbound_rst: Nat44TcpInboundRst,
) -> Nat44TcpTransition {
    let outbound = matches!(direction, Nat44TcpDirection::Outbound);
    let corroborate = matches!(inbound_rst, Nat44TcpInboundRst::Corroborate);
    if segment.has(TCP_RST) {
        let state = if outbound {
            (state | STATE_RESET) & !STATE_FIN_IN_UNCONFIRMED
        } else if corroborate {
            state
        } else {
            state | STATE_RESET
        };
        return Nat44TcpTransition {
            state,
            restart: None,
        };
    }
    let mut next = state & !STATE_RESET;
    let syn_ack = segment.flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN) == TCP_SYN | TCP_ACK;
    let restart = if !outbound || !fin_closed(next) {
        None
    } else if segment.is_initial_syn() {
        next = 0;
        Some(Nat44TcpDirection::Outbound)
    } else if syn_ack {
        next = STATE_SYN_IN;
        Some(Nat44TcpDirection::Inbound)
    } else {
        None
    };
    let (syn, ack, fin) = if outbound {
        (STATE_SYN_OUT, STATE_ACK_OUT, STATE_FIN_OUT)
    } else {
        (STATE_SYN_IN, STATE_ACK_IN, STATE_FIN_IN)
    };
    if segment.has(TCP_SYN) {
        next |= syn;
    }
    if segment.has(TCP_ACK) && !(corroborate && outbound && segment.has(TCP_SYN)) {
        next |= ack;
    }
    if segment.has(TCP_FIN) {
        if outbound {
            next = (next | fin) & !STATE_FIN_IN_UNCONFIRMED;
        } else if next & STATE_FIN_IN == 0 {
            // The first inbound FIN. A repeated one never re-arms the
            // confirmation of a confirmed FIN and leaves an unconfirmed one
            // waiting for the same outbound FIN or RST.
            next |= fin;
            if corroborate {
                next |= STATE_FIN_IN_UNCONFIRMED;
            }
        }
    }
    Nat44TcpTransition {
        state: next,
        restart,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Nat44TcpDirection::{Inbound, Outbound};
    use Nat44TcpSessionPhase::{Closing, Established, Opening};

    const SYN: u8 = TCP_SYN;
    const SYN_ACK: u8 = TCP_SYN | TCP_ACK;
    const ACK: u8 = TCP_ACK;
    const FIN_ACK: u8 = TCP_FIN | TCP_ACK;
    const RST: u8 = TCP_RST;
    const RST_ACK: u8 = TCP_RST | TCP_ACK;
    const RFC: Nat44TcpInboundRst = Nat44TcpInboundRst::Closing;
    const STRICT: Nat44TcpInboundRst = Nat44TcpInboundRst::Corroborate;

    fn run(
        policy: Nat44TcpInboundRst,
        segments: &[(u8, Nat44TcpDirection)],
    ) -> (Vec<Nat44TcpSessionPhase>, u8) {
        let mut state = 0;
        let phases = segments
            .iter()
            .map(|&(flags, direction)| {
                state =
                    next_state(state, Nat44TcpSegment::from_flags(flags), direction, policy).state;
                phase_of(state)
            })
            .collect();
        (phases, state)
    }

    /// Replays segments on a new session under the default (RFC) policy
    /// and returns the phase after each.
    fn phases(segments: &[(u8, Nat44TcpDirection)]) -> Vec<Nat44TcpSessionPhase> {
        run(RFC, segments).0
    }

    const OPEN_OUT: [(u8, Nat44TcpDirection); 3] =
        [(SYN, Outbound), (SYN_ACK, Inbound), (ACK, Outbound)];

    #[test]
    fn three_way_handshake_establishes_on_the_final_ack() {
        for policy in [RFC, STRICT] {
            assert_eq!(run(policy, &OPEN_OUT).0, [Opening, Opening, Established]);
            // Simultaneous open (RFC 9293 figure 8) then data.
            assert_eq!(
                run(
                    policy,
                    &[
                        (SYN, Outbound),
                        (SYN, Inbound),
                        (SYN_ACK, Outbound),
                        (SYN_ACK, Inbound),
                        (ACK, Outbound)
                    ]
                )
                .0[4],
                Established
            );
        }
        // Inbound-initiated: under the RFC policy the inside SYN-ACK is the
        // inside's ACK; under corroboration a later outbound ACK is needed.
        let inbound = [
            (SYN, Inbound),
            (SYN_ACK, Outbound),
            (ACK, Inbound),
            (ACK, Outbound),
        ];
        assert_eq!(
            phases(&inbound),
            [Opening, Opening, Established, Established]
        );
        assert_eq!(
            run(STRICT, &inbound).0,
            [Opening, Opening, Opening, Established]
        );
    }

    #[test]
    fn established_needs_acks_both_ways_and_a_syn() {
        // RFC 5382 §5: ACK from both endpoints after a SYN.
        assert_eq!(
            phases(&[(SYN, Outbound), (ACK, Inbound), (ACK, Outbound)]),
            [Opening, Opening, Established]
        );
        // A spoofed SYN answered by the inside only stays opening.
        assert_eq!(
            phases(&[
                (SYN, Inbound),
                (SYN_ACK, Outbound),
                (SYN_ACK, Outbound),
                (SYN, Inbound)
            ]),
            [Opening; 4]
        );
        assert_eq!(phase_of(STATE_ACK_BOTH), Opening);
        assert_eq!(phase_of(STATE_ACK_BOTH | STATE_SYN_IN), Established);
        assert_eq!(phase_of(STATE_ACK_BOTH | STATE_SYN_OUT), Established);
    }

    /// The adaptive blind spoof: SYN, the inside SYN-ACK, a blind ACK, the
    /// inside RST for the unacceptable ACK, another blind ACK. The RFC
    /// policy cannot tell this from a real handshake; corroboration can.
    #[test]
    fn a_blind_spoofed_handshake_establishes_only_under_the_rfc_policy() {
        let spoof = [
            (SYN, Inbound),
            (SYN_ACK, Outbound),
            (ACK, Inbound),
            (RST, Outbound),
            (ACK, Inbound),
        ];
        assert_eq!(phases(&spoof)[4], Established);
        assert_eq!(
            run(STRICT, &spoof).0,
            [Opening, Opening, Opening, Closing, Opening]
        );
    }

    #[test]
    fn fin_in_both_directions_closes_and_one_fin_keeps_the_phase() {
        for (first, second) in [(Outbound, Inbound), (Inbound, Outbound)] {
            let mut segments = OPEN_OUT.to_vec();
            segments.extend([
                (FIN_ACK, first),
                (ACK, second),
                (FIN_ACK, second),
                (ACK, first),
            ]);
            assert_eq!(
                phases(&segments)[2..],
                [Established, Established, Established, Closing, Closing]
            );
        }
        assert_eq!(
            phases(&[(SYN, Outbound), (FIN_ACK, Outbound), (FIN_ACK, Inbound)]),
            [Opening, Opening, Closing]
        );
    }

    #[test]
    fn corroboration_needs_an_outbound_fin_or_rst_after_an_inbound_fin() {
        // Remote closes first: the inside FIN corroborates at once.
        let mut remote_first = OPEN_OUT.to_vec();
        remote_first.extend([(FIN_ACK, Inbound), (FIN_ACK, Outbound)]);
        assert_eq!(run(STRICT, &remote_first).0[3..], [Established, Closing]);
        // Inside closes first: the inbound FIN alone does not close...
        let mut inside_first = OPEN_OUT.to_vec();
        inside_first.extend([(FIN_ACK, Outbound), (FIN_ACK, Inbound), (ACK, Outbound)]);
        let (phases_seen, state) = run(STRICT, &inside_first);
        assert_eq!(phases_seen[3..], [Established, Established, Established]);
        assert_ne!(state & STATE_FIN_IN_UNCONFIRMED, 0);
        // ...until an outbound FIN (retransmission) or RST corroborates it.
        for corroboration in [FIN_ACK, RST] {
            let mut segments = inside_first.to_vec();
            segments.push((corroboration, Outbound));
            let (phases_seen, state) = run(STRICT, &segments);
            assert_eq!(phases_seen[6], Closing);
            assert_eq!(state & STATE_FIN_IN_UNCONFIRMED, 0);
        }
        // A retransmitted inbound FIN never re-arms the confirmation.
        let mut retransmit = remote_first.to_vec();
        retransmit.push((FIN_ACK, Inbound));
        assert_eq!(run(STRICT, &retransmit).0[5], Closing);
        // The RFC policy closes on the inbound FIN.
        assert_eq!(phases(&inside_first)[4], Closing);
    }

    #[test]
    fn rst_moves_to_closing_and_a_later_segment_restores_the_phase() {
        for direction in [Outbound, Inbound] {
            for rst in [RST, RST_ACK, RST | TCP_FIN, RST | TCP_SYN] {
                let mut segments = OPEN_OUT.to_vec();
                segments.extend([(rst, direction), (rst, direction), (ACK, Inbound)]);
                assert_eq!(
                    phases(&segments)[2..],
                    [Established, Closing, Closing, Established],
                    "{rst:#x} {direction:?}"
                );
            }
        }
        // Corroborate: an inbound RST changes nothing, an outbound one closes.
        let mut segments = OPEN_OUT.to_vec();
        segments.extend([(RST, Inbound), (RST, Outbound), (ACK, Outbound)]);
        assert_eq!(
            run(STRICT, &segments).0[2..],
            [Established, Established, Closing, Established]
        );
        // RST|ACK while opening: closing, and the ACK is not recorded.
        assert_eq!(
            phases(&[
                (SYN, Outbound),
                (SYN_ACK, Inbound),
                (RST_ACK, Outbound),
                (SYN_ACK, Inbound)
            ]),
            [Opening, Opening, Closing, Opening]
        );
    }

    /// Review M1: an injected RST and a remote SYN on an established
    /// connection, answered by the inside challenge ACK (RFC 5961 §4), must
    /// leave it established, not reset to opening.
    #[test]
    fn a_spoofed_rst_and_syn_never_downgrade_an_established_connection() {
        let mut segments = OPEN_OUT.to_vec();
        segments.extend([
            (RST, Inbound),
            (SYN, Inbound),
            (ACK, Outbound),
            (ACK, Inbound),
        ]);
        assert_eq!(
            phases(&segments)[2..],
            [Established, Closing, Established, Established, Established]
        );
    }

    #[test]
    fn only_an_outbound_initial_syn_restarts_a_fin_closed_session() {
        let mut closed = OPEN_OUT.to_vec();
        closed.extend([(FIN_ACK, Outbound), (FIN_ACK, Inbound)]);
        for policy in [RFC, STRICT] {
            let mut segments = closed.to_vec();
            segments.push((SYN, Outbound));
            let mut state = 0;
            let mut restarts = Vec::new();
            for &(flags, direction) in &segments {
                let transition =
                    next_state(state, Nat44TcpSegment::from_flags(flags), direction, policy);
                state = transition.state;
                restarts.push(transition.restart);
            }
            if policy == RFC {
                assert_eq!(restarts, [None, None, None, None, None, Some(Outbound)]);
                assert_eq!(state, STATE_SYN_OUT);
            } else {
                // Inside closed first: the inbound FIN is unconfirmed, so
                // the session is not closed and the SYN does not restart.
                assert_eq!(restarts[5], None);
            }
        }
        // An inbound SYN alone never restarts (it can be spoofed).
        let mut segments = closed.to_vec();
        segments.push((SYN, Inbound));
        assert_eq!(phases(&segments)[5], Closing);
        // After a RST (not FIN), an outbound SYN recovers without a restart.
        let mut segments = OPEN_OUT.to_vec();
        segments.extend([(RST, Inbound), (SYN, Outbound)]);
        let (phases_seen, state) = run(RFC, &segments);
        assert_eq!(phases_seen[3..], [Closing, Established]);
        assert_ne!(state & STATE_ACK_BOTH, 0);
    }

    /// Review L-new-2: a remote reconnect on the same 5-tuple after a FIN
    /// close restarts when the inside host answers with a SYN-ACK (the
    /// inbound SYN alone does not), and the new connection establishes.
    #[test]
    fn an_inside_syn_ack_restarts_a_fin_closed_session_for_a_remote_reconnect() {
        let mut segments = OPEN_OUT.to_vec();
        segments.extend([(FIN_ACK, Outbound), (FIN_ACK, Inbound), (ACK, Outbound)]);
        segments.extend([(SYN, Inbound), (SYN_ACK, Outbound), (ACK, Inbound)]);
        assert_eq!(
            phases(&segments)[5..],
            [Closing, Closing, Opening, Established]
        );
        let mut state = 0;
        for &(flags, direction) in &segments[..6] {
            state = next_state(state, Nat44TcpSegment::from_flags(flags), direction, RFC).state;
        }
        let transition = next_state(state, Nat44TcpSegment::from_flags(SYN_ACK), Outbound, RFC);
        assert_eq!(transition.restart, Some(Inbound));
        assert_eq!(
            transition.state,
            STATE_SYN_IN | STATE_SYN_OUT | STATE_ACK_OUT
        );
        // Corroborate: the remote-first close is confirmed by the inside
        // FIN, the restart works the same, and establishing needs an inside
        // ACK without SYN.
        let mut segments = OPEN_OUT.to_vec();
        segments.extend([(FIN_ACK, Inbound), (FIN_ACK, Outbound), (ACK, Inbound)]);
        segments.extend([
            (SYN, Inbound),
            (SYN_ACK, Outbound),
            (ACK, Inbound),
            (ACK, Outbound),
        ]);
        assert_eq!(
            run(STRICT, &segments).0[5..],
            [Closing, Closing, Opening, Opening, Established]
        );
    }

    /// Review L-new-1: under corroboration every inbound FIN is unconfirmed
    /// until an outbound FIN or RST follows, whichever side closed first; a
    /// later real FIN is not lost behind the first one. Without sequence
    /// numbers an early spoofed FIN followed by a genuine inside half-close
    /// looks exactly like a remote-first close (inbound FIN, then outbound
    /// FIN), so it still closes: that ordering is the documented residual.
    #[test]
    fn under_corroboration_every_inbound_fin_waits_for_an_outbound_fin_or_rst() {
        let mut spoofed = OPEN_OUT.to_vec();
        spoofed.push((FIN_ACK, Inbound));
        let (phases_seen, state) = run(STRICT, &spoofed);
        assert_eq!(phases_seen[3], Established);
        assert_ne!(state & STATE_FIN_IN_UNCONFIRMED, 0);
        // Data and ACKs in both directions do not confirm it.
        let mut traffic = spoofed.to_vec();
        traffic.extend([(ACK, Outbound), (ACK, Inbound), (ACK, Inbound)]);
        let (phases_seen, state) = run(STRICT, &traffic);
        assert_eq!(phases_seen[6], Established);
        assert_ne!(state & STATE_FIN_IN_UNCONFIRMED, 0);
        // The remote's later real FIN keeps waiting; the inside FIN closes.
        let mut real = traffic.to_vec();
        real.extend([(FIN_ACK, Inbound), (FIN_ACK, Outbound)]);
        assert_eq!(run(STRICT, &real).0[7..], [Established, Closing]);
        // The documented residual: the early spoofed FIN, then a genuine
        // inside half-close, is a remote-first close for the NAT.
        let mut half_close = spoofed.to_vec();
        half_close.push((FIN_ACK, Outbound));
        assert_eq!(run(STRICT, &half_close).0[4], Closing);
    }

    #[test]
    fn the_transition_is_total_and_rst_handling_holds_in_every_reachable_state() {
        for policy in [RFC, STRICT] {
            let mut reachable = vec![0_u8];
            let mut seen = [false; 256];
            seen[0] = true;
            while let Some(state) = reachable.pop() {
                for flags in 0..=u8::MAX {
                    for direction in [Outbound, Inbound] {
                        let segment = Nat44TcpSegment::from_flags(flags);
                        let transition = next_state(state, segment, direction, policy);
                        let next = transition.state;
                        if flags & TCP_RST != 0 {
                            // Never clears a flag; sets reset unless an
                            // inbound RST under corroboration.
                            assert_eq!(
                                next & state & !STATE_FIN_IN_UNCONFIRMED,
                                state & !STATE_FIN_IN_UNCONFIRMED
                            );
                            let expect_reset = direction == Outbound || policy == RFC;
                            assert_eq!(
                                next & STATE_RESET != 0,
                                expect_reset || state & STATE_RESET != 0
                            );
                        } else {
                            assert_eq!(next & STATE_RESET, 0);
                        }
                        // A restart is only an outbound initial SYN or
                        // SYN-ACK on a FIN-closed session.
                        let closed = direction == Outbound
                            && flags & TCP_RST == 0
                            && fin_closed(state & !STATE_RESET);
                        let control = flags & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN);
                        let expected = if closed && control == TCP_SYN {
                            Some(Outbound)
                        } else if closed && control == TCP_SYN | TCP_ACK {
                            Some(Inbound)
                        } else {
                            None
                        };
                        assert_eq!(transition.restart, expected);
                        // An established session never leaves the
                        // established phase for opening without a restart.
                        if phase_of(state & !STATE_RESET) == Established
                            && transition.restart.is_none()
                        {
                            assert_ne!(phase_of(next), Opening);
                        }
                        if policy == RFC {
                            assert_eq!(next & STATE_FIN_IN_UNCONFIRMED, 0);
                        }
                        if !seen[usize::from(next)] {
                            seen[usize::from(next)] = true;
                            reachable.push(next);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn booleans_map_to_initial_syn_and_bare_ack() {
        assert!(Nat44TcpSegment::from(true).is_initial_syn());
        assert!(Nat44TcpSegment::INITIAL_SYN.is_initial_syn());
        assert!(!Nat44TcpSegment::from(false).is_initial_syn());
        for flags in [SYN_ACK, SYN | RST, SYN | TCP_FIN, ACK] {
            assert!(!Nat44TcpSegment::from_flags(flags).is_initial_syn());
        }
        // ECE/CWR/PSH do not change the initial-SYN predicate.
        assert!(Nat44TcpSegment::from_flags(SYN | 0xc8).is_initial_syn());
    }
}

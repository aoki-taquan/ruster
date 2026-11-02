//! Minimal TCP connection tracking for the TCP NAT44 session timers.
//!
//! RFC 5382 §5 divides a TCP connection into three phases and REQ-5 gives
//! each a floor for its idle timeout: the partially open phase ("initiated
//! by the first SYN for the connection and extends until both endpoints
//! have sent a packet with the ACK flag set") and the closing phase ("when
//! both endpoints have terminated their half of the connection by sending a
//! FIN packet") use the transitory connection idle-timeout (at least 4
//! minutes); the established phase in between uses the established
//! connection idle-timeout (at least 2 hours 4 minutes). RFC 7857 §2
//! (Figure 1, adapted from RFC 6146 §3.5.2.2) gives the state machine and
//! §2.2 the RST rule: translate the RST and keep the session for 4 minutes
//! of idleness instead of deleting it; a later non-RST packet returns the
//! connection to its previous phase (RFC 6146 TRANS state).
//!
//! The session records which flags each direction has sent: SYN, ACK, and
//! FIN outbound (inside to outside) and inbound, and whether the last
//! committed segment was a RST. The phase is a pure function of those bits
//! ([`phase_of`]): a RST pending, or FIN in both directions, is closing;
//! SYN and ACK in both directions is established (both RFC 7857's "Server
//! SYN" and RFC 5382's "both endpoints have sent a packet with the ACK
//! flag"); anything else is opening. A FIN in one direction only keeps the
//! established (or opening) phase, as RFC 6146's V4/V6 FIN RCV states do.
//!
//! No sequence numbers are tracked, so no segment is validated beyond the
//! exact session 5-tuple the NAT already requires. That is why the phase
//! never drops a session at once: a RST, genuine or injected, only moves it
//! to the closing timer (never below the transitory idle-timeout), and any
//! later non-RST segment restores the phase its flags describe.

/// RFC 5382 §5 phase of a TCP NAT session, which selects its idle timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Nat44TcpSessionPhase {
    /// Partially open: SYN and ACK not yet seen in both directions. Uses
    /// the opening (transitory) idle timeout.
    Opening,
    /// Established: SYN and ACK seen in both directions, FIN in at most one,
    /// and no RST pending. Uses the established idle timeout.
    Established,
    /// Closing: FIN seen in both directions, or a RST was the last segment
    /// (RFC 7857 §2.2). Uses the closing (transitory) idle timeout.
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
const STATE_HANDSHAKE: u8 = STATE_SYN_OUT | STATE_SYN_IN | STATE_ACK_OUT | STATE_ACK_IN;
const STATE_FIN_BOTH: u8 = STATE_FIN_OUT | STATE_FIN_IN;

/// The phase a session state byte describes.
pub(crate) const fn phase_of(state: u8) -> Nat44TcpSessionPhase {
    if state & STATE_RESET != 0 || state & STATE_FIN_BOTH == STATE_FIN_BOTH {
        Nat44TcpSessionPhase::Closing
    } else if state & STATE_HANDSHAKE == STATE_HANDSHAKE {
        Nat44TcpSessionPhase::Established
    } else {
        Nat44TcpSessionPhase::Opening
    }
}

/// The session state after `segment` from `direction` is committed on a
/// session in `state` (`0` for a session this segment creates).
///
/// - RST: sets the reset bit and nothing else (the closing timer; RFC 7857
///   §2.2, RFC 6146 ESTABLISHED/TRANS). Other flags on a RST segment are
///   ignored, so a RST never establishes or closes a connection by itself.
/// - Any other segment clears the reset bit (RFC 6146 TRANS: "If a packet
///   other than a RST packet is received ... The state is moved to
///   ESTABLISHED"; here: back to the phase the flags describe).
/// - An initial SYN on a session in the closing phase starts a new
///   connection on the same 5-tuple (port reuse after TIME_WAIT, or a
///   reconnect after a reset): the recorded flags are cleared first, so the
///   new connection is opening, not stuck on the closing timer.
/// - SYN, ACK, and FIN are recorded for the sending direction.
pub(crate) const fn next_state(
    state: u8,
    segment: Nat44TcpSegment,
    direction: Nat44TcpDirection,
) -> u8 {
    if segment.has(TCP_RST) {
        return state | STATE_RESET;
    }
    let mut next =
        if segment.is_initial_syn() && matches!(phase_of(state), Nat44TcpSessionPhase::Closing) {
            0
        } else {
            state & !STATE_RESET
        };
    let (syn, ack, fin) = match direction {
        Nat44TcpDirection::Outbound => (STATE_SYN_OUT, STATE_ACK_OUT, STATE_FIN_OUT),
        Nat44TcpDirection::Inbound => (STATE_SYN_IN, STATE_ACK_IN, STATE_FIN_IN),
    };
    if segment.has(TCP_SYN) {
        next |= syn;
    }
    if segment.has(TCP_ACK) {
        next |= ack;
    }
    if segment.has(TCP_FIN) {
        next |= fin;
    }
    next
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

    /// Replays segments on a new session and returns the phase after each.
    fn phases(segments: &[(u8, Nat44TcpDirection)]) -> Vec<Nat44TcpSessionPhase> {
        let mut state = 0;
        segments
            .iter()
            .map(|&(flags, direction)| {
                state = next_state(state, Nat44TcpSegment::from_flags(flags), direction);
                phase_of(state)
            })
            .collect()
    }

    #[test]
    fn three_way_handshake_establishes_on_the_final_ack_in_both_directions() {
        // Outbound-initiated.
        assert_eq!(
            phases(&[(SYN, Outbound), (SYN_ACK, Inbound), (ACK, Outbound)]),
            [Opening, Opening, Established]
        );
        // Inbound-initiated (an admitted external SYN).
        assert_eq!(
            phases(&[(SYN, Inbound), (SYN_ACK, Outbound), (ACK, Inbound)]),
            [Opening, Opening, Established]
        );
        // Simultaneous open (RFC 9293 §3.5 figure 8).
        assert_eq!(
            phases(&[
                (SYN, Outbound),
                (SYN, Inbound),
                (SYN_ACK, Outbound),
                (SYN_ACK, Inbound)
            ]),
            [Opening, Opening, Opening, Established]
        );
    }

    #[test]
    fn a_spoofed_syn_answered_only_by_the_inside_stays_opening() {
        // An off-path SYN, the inside SYN-ACK and its retransmissions: the
        // remote never ACKs, so the session keeps the transitory timer.
        assert_eq!(
            phases(&[
                (SYN, Inbound),
                (SYN_ACK, Outbound),
                (SYN_ACK, Outbound),
                (SYN, Inbound)
            ]),
            [Opening; 4]
        );
        // Acks without SYNs in both directions never establish.
        assert_eq!(
            phases(&[(SYN, Outbound), (ACK, Inbound), (ACK, Outbound)]),
            [Opening; 3]
        );
    }

    #[test]
    fn fin_in_both_directions_closes_and_one_fin_keeps_the_phase() {
        let open = [(SYN, Outbound), (SYN_ACK, Inbound), (ACK, Outbound)];
        for (first, second) in [(Outbound, Inbound), (Inbound, Outbound)] {
            let mut segments = open.to_vec();
            segments.extend([(FIN_ACK, first), (ACK, second), (ACK, second)]);
            segments.extend([(FIN_ACK, second), (ACK, first), (ACK, second)]);
            assert_eq!(
                phases(&segments)[2..],
                [
                    Established,
                    Established,
                    Established,
                    Established,
                    Closing,
                    Closing,
                    Closing
                ]
            );
        }
        // A FIN during the handshake keeps it opening until both sides FIN.
        assert_eq!(
            phases(&[(SYN, Outbound), (FIN_ACK, Outbound), (FIN_ACK, Inbound)]),
            [Opening, Opening, Closing]
        );
    }

    #[test]
    fn rst_moves_to_closing_and_a_later_segment_restores_the_phase() {
        let open = [(SYN, Outbound), (SYN_ACK, Inbound), (ACK, Outbound)];
        for direction in [Outbound, Inbound] {
            for rst in [RST, RST_ACK, RST | TCP_FIN, RST | TCP_SYN] {
                let mut segments = open.to_vec();
                segments.extend([(rst, direction), (rst, direction), (ACK, Inbound)]);
                assert_eq!(
                    phases(&segments)[2..],
                    [Established, Closing, Closing, Established],
                    "{rst:#x} {direction:?}"
                );
            }
        }
        // A RST while opening also uses the closing timer and records no
        // other flag: RST|ACK does not count as the handshake ACK.
        assert_eq!(
            phases(&[
                (SYN, Outbound),
                (SYN_ACK, Inbound),
                (RST_ACK, Outbound),
                (SYN_ACK, Inbound)
            ]),
            [Opening, Opening, Closing, Opening]
        );
        // After FIN in both directions, a RST stays closing and a later ACK
        // returns to closing (the FINs are still recorded).
        assert_eq!(
            phases(&[
                (SYN, Outbound),
                (SYN_ACK, Inbound),
                (ACK, Outbound),
                (FIN_ACK, Outbound),
                (FIN_ACK, Inbound),
                (RST, Inbound),
                (ACK, Outbound)
            ])[4..],
            [Closing, Closing, Closing]
        );
    }

    #[test]
    fn an_initial_syn_restarts_only_a_closing_session() {
        let closed = [
            (SYN, Outbound),
            (SYN_ACK, Inbound),
            (ACK, Outbound),
            (FIN_ACK, Outbound),
            (FIN_ACK, Inbound),
        ];
        for direction in [Outbound, Inbound] {
            let mut segments = closed.to_vec();
            segments.push((SYN, direction));
            assert_eq!(phases(&segments)[5], Opening);
            let mut state = 0;
            for &(flags, dir) in &segments {
                state = next_state(state, Nat44TcpSegment::from_flags(flags), dir);
            }
            let expected = match direction {
                Outbound => STATE_SYN_OUT,
                Inbound => STATE_SYN_IN,
            };
            assert_eq!(state, expected);
        }
        // After a reset too.
        assert_eq!(
            phases(&[
                (SYN, Outbound),
                (SYN_ACK, Inbound),
                (ACK, Outbound),
                (RST, Inbound),
                (SYN, Outbound)
            ])[3..],
            [Closing, Opening]
        );
        // A SYN on an established session does not reset it.
        assert_eq!(
            phases(&[
                (SYN, Outbound),
                (SYN_ACK, Inbound),
                (ACK, Outbound),
                (SYN, Outbound)
            ])[3],
            Established
        );
    }

    #[test]
    fn the_transition_is_total_and_phase_depends_only_on_the_bits() {
        // Every state byte reachable from 0, every flags byte, both
        // directions: the result keeps only defined bits, and a RST never
        // clears a bit.
        let defined = STATE_HANDSHAKE | STATE_FIN_BOTH | STATE_RESET;
        let mut reachable = vec![0_u8];
        let mut seen = [false; 256];
        seen[0] = true;
        while let Some(state) = reachable.pop() {
            for flags in 0..=u8::MAX {
                for direction in [Outbound, Inbound] {
                    let next = next_state(state, Nat44TcpSegment::from_flags(flags), direction);
                    assert_eq!(next & !defined, 0);
                    if flags & TCP_RST != 0 {
                        assert_eq!(next, state | STATE_RESET);
                    } else {
                        assert_eq!(next & STATE_RESET, 0);
                    }
                    if !seen[usize::from(next)] {
                        seen[usize::from(next)] = true;
                        reachable.push(next);
                    }
                }
            }
        }
        assert_eq!(seen.iter().filter(|seen| **seen).count(), 128);
        assert_eq!(phase_of(STATE_HANDSHAKE), Established);
        assert_eq!(phase_of(STATE_HANDSHAKE | STATE_FIN_OUT), Established);
        assert_eq!(phase_of(STATE_HANDSHAKE | STATE_FIN_IN), Established);
        assert_eq!(phase_of(STATE_FIN_BOTH), Closing);
        assert_eq!(phase_of(STATE_RESET), Closing);
        for missing in [STATE_SYN_OUT, STATE_SYN_IN, STATE_ACK_OUT, STATE_ACK_IN] {
            assert_eq!(phase_of(STATE_HANDSHAKE & !missing), Opening);
        }
    }

    #[test]
    fn booleans_map_to_initial_syn_and_bare_ack() {
        assert!(Nat44TcpSegment::from(true).is_initial_syn());
        assert!(!Nat44TcpSegment::from(false).is_initial_syn());
        for flags in [SYN_ACK, SYN | RST, SYN | TCP_FIN, ACK] {
            assert!(!Nat44TcpSegment::from_flags(flags).is_initial_syn());
        }
        // ECE/CWR/URG/PSH do not change the initial-SYN predicate.
        assert!(Nat44TcpSegment::from_flags(SYN | 0xc8).is_initial_syn());
    }
}

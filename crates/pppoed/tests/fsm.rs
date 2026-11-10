//! The option negotiation automaton against the RFC 1661 section 4 transition table.

use ruster_pppoed::fsm::{code, Action, Fsm, Limits, Negotiation, Reply, State};
use ruster_pppoed::ppp::{self, Opt};

/// A protocol with one option (type 1, one octet). We ask for `value`; the peer's
/// must be 7.
#[derive(Debug, Default)]
struct Toy {
    value: u8,
    rejected: bool,
}

impl Negotiation for Toy {
    fn request(&mut self) -> Vec<u8> {
        if self.rejected {
            Vec::new()
        } else {
            vec![1, 3, self.value]
        }
    }
    fn check(&mut self, options: &[Opt<'_>], nak: bool) -> Reply {
        let mut naks = Vec::new();
        let mut rejects = Vec::new();
        for &(kind, value) in options {
            match (kind, value) {
                (1, [7]) => {}
                (1, _) if nak => naks.extend_from_slice(&[1, 3, 7]),
                _ => {
                    rejects.extend_from_slice(&[kind, 2 + value.len() as u8]);
                    rejects.extend_from_slice(value);
                }
            }
        }
        if !rejects.is_empty() {
            Reply::Reject(rejects)
        } else if !naks.is_empty() {
            Reply::Nak(naks)
        } else {
            Reply::Ack
        }
    }
    fn naked(&mut self, options: &[Opt<'_>]) {
        if let Some((_, [v])) = options.iter().find(|(k, _)| *k == 1) {
            self.value = *v;
        }
    }
    fn rejected(&mut self, _: &[Opt<'_>]) {
        self.rejected = true;
    }
}

fn fsm() -> Fsm<Toy> {
    Fsm::new(Toy::default(), Limits::default())
}

/// The packets among the actions, as (code, id, data).
fn sent(actions: &[Action]) -> Vec<(u8, u8, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(bytes) => {
                let p = ppp::Packet::parse(bytes).unwrap();
                Some((p.code, p.id, p.data.to_vec()))
            }
            _ => None,
        })
        .collect()
}

fn layer(actions: &[Action]) -> Vec<Action> {
    actions
        .iter()
        .filter(|a| !matches!(a, Action::Send(_)))
        .cloned()
        .collect()
}

/// Starts the automaton: Up and Open, giving the identifier of its request.
fn started(f: &mut Fsm<Toy>) -> u8 {
    let mut out = Vec::new();
    f.up(0, &mut out);
    assert_eq!(f.state(), State::Closed);
    f.open(0, &mut out);
    assert_eq!(f.state(), State::RequestSent);
    let s = sent(&out);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].0, code::CONFIGURE_REQUEST);
    assert_eq!(s[0].2, [1, 3, 0]);
    s[0].1
}

fn rx(f: &mut Fsm<Toy>, now: u64, code: u8, id: u8, data: &[u8]) -> Vec<Action> {
    let mut out = Vec::new();
    f.receive(now, &ppp::packet(code, id, data), &mut out);
    out
}

#[test]
fn open_with_our_ack_first_and_then_theirs() {
    let mut f = fsm();
    let id = started(&mut f);
    // RCA in Request-Sent: irc, to Ack-Received.
    let out = rx(&mut f, 1, code::CONFIGURE_ACK, id, &[1, 3, 0]);
    assert!(out.is_empty());
    assert_eq!(f.state(), State::AckReceived);
    // RCR+ in Ack-Received: sca, tlu, to Opened.
    let out = rx(&mut f, 2, code::CONFIGURE_REQUEST, 9, &[1, 3, 7]);
    assert_eq!(sent(&out), [(code::CONFIGURE_ACK, 9, vec![1, 3, 7])]);
    assert_eq!(layer(&out), [Action::Up]);
    assert_eq!(f.state(), State::Opened);
    assert_eq!(f.next_timer(), None);
}

#[test]
fn open_with_their_request_first() {
    let mut f = fsm();
    let id = started(&mut f);
    // RCR+ in Request-Sent: sca, to Ack-Sent.
    let out = rx(&mut f, 1, code::CONFIGURE_REQUEST, 9, &[1, 3, 7]);
    assert_eq!(sent(&out), [(code::CONFIGURE_ACK, 9, vec![1, 3, 7])]);
    assert_eq!(f.state(), State::AckSent);
    // RCA in Ack-Sent: irc, tlu, to Opened.
    let out = rx(&mut f, 2, code::CONFIGURE_ACK, id, &[1, 3, 0]);
    assert_eq!(layer(&out), [Action::Up]);
    assert_eq!(f.state(), State::Opened);
}

#[test]
fn ack_with_another_id_or_other_options_is_discarded() {
    let mut f = fsm();
    let id = started(&mut f);
    assert!(rx(
        &mut f,
        1,
        code::CONFIGURE_ACK,
        id.wrapping_add(1),
        &[1, 3, 0]
    )
    .is_empty());
    assert!(rx(&mut f, 1, code::CONFIGURE_ACK, id, &[1, 3, 1]).is_empty());
    assert_eq!(f.state(), State::RequestSent);
}

#[test]
fn nak_makes_a_new_request_and_max_failure_turns_naks_into_rejects() {
    let mut f = fsm();
    let id = started(&mut f);
    // RCN in Request-Sent: irc, scr with the Nak'd value and a new identifier.
    let out = rx(&mut f, 1, code::CONFIGURE_NAK, id, &[1, 3, 5]);
    let s = sent(&out);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].0, code::CONFIGURE_REQUEST);
    assert_ne!(s[0].1, id);
    assert_eq!(s[0].2, [1, 3, 5]);
    assert_eq!(f.state(), State::RequestSent);

    // RCR-: scn. After Max-Failure (5) Naks the sixth is a Reject.
    for i in 0..5 {
        let out = rx(&mut f, 2, code::CONFIGURE_REQUEST, i, &[1, 3, 1]);
        assert_eq!(sent(&out), [(code::CONFIGURE_NAK, i, vec![1, 3, 7])]);
    }
    let out = rx(&mut f, 2, code::CONFIGURE_REQUEST, 6, &[1, 3, 1]);
    assert_eq!(sent(&out), [(code::CONFIGURE_REJECT, 6, vec![1, 3, 1])]);
}

#[test]
fn reject_must_name_options_we_sent() {
    let mut f = fsm();
    let id = started(&mut f);
    assert!(rx(&mut f, 1, code::CONFIGURE_REJECT, id, &[2, 2]).is_empty());
    assert!(rx(&mut f, 1, code::CONFIGURE_REJECT, id, &[1, 3, 9]).is_empty());
    let out = rx(&mut f, 1, code::CONFIGURE_REJECT, id, &[1, 3, 0]);
    let s = sent(&out);
    assert_eq!(s[0].0, code::CONFIGURE_REQUEST);
    assert!(s[0].2.is_empty());
}

#[test]
fn request_is_sent_again_with_the_same_id_until_max_configure() {
    let mut f = fsm();
    let id = started(&mut f);
    let mut now = 0;
    let mut out = Vec::new();
    // Early: nothing.
    f.timeout(2_999, &mut out);
    assert!(out.is_empty());
    for _ in 1..10 {
        now = f.next_timer().unwrap();
        assert_eq!(now % 3_000, 0);
        f.timeout(now, &mut out);
    }
    let s = sent(&out);
    assert_eq!(s.len(), 9);
    assert!(s
        .iter()
        .all(|p| p.0 == code::CONFIGURE_REQUEST && p.1 == id));
    // The tenth timeout is TO-: tlf, to Stopped.
    out.clear();
    f.timeout(now + 3_000, &mut out);
    assert_eq!(out, [Action::Finished]);
    assert_eq!(f.state(), State::Stopped);
    assert_eq!(f.next_timer(), None);
}

fn opened() -> Fsm<Toy> {
    let mut f = fsm();
    let id = started(&mut f);
    rx(&mut f, 1, code::CONFIGURE_REQUEST, 9, &[1, 3, 7]);
    rx(&mut f, 1, code::CONFIGURE_ACK, id, &[1, 3, 0]);
    assert_eq!(f.state(), State::Opened);
    f
}

#[test]
fn terminate_request_from_the_peer() {
    let mut f = opened();
    // RTR in Opened: tld, zrc, sta, to Stopping.
    let out = rx(&mut f, 10, code::TERMINATE_REQUEST, 4, &[]);
    assert_eq!(sent(&out), [(code::TERMINATE_ACK, 4, vec![])]);
    assert_eq!(layer(&out), [Action::Down]);
    assert_eq!(f.state(), State::Stopping);
    // The zeroed counter: one restart period, then TO-: tlf, to Stopped.
    assert_eq!(f.next_timer(), Some(3_010));
    let mut out = Vec::new();
    f.timeout(3_010, &mut out);
    assert_eq!(out, [Action::Finished]);
    assert_eq!(f.state(), State::Stopped);
}

#[test]
fn close_sends_terminate_request_max_terminate_times() {
    let mut f = opened();
    let mut out = Vec::new();
    f.close(10, &mut out);
    assert_eq!(layer(&out), [Action::Down]);
    assert_eq!(sent(&out)[0].0, code::TERMINATE_REQUEST);
    assert_eq!(f.state(), State::Closing);
    out.clear();
    f.timeout(3_010, &mut out);
    assert_eq!(sent(&out)[0].0, code::TERMINATE_REQUEST);
    out.clear();
    f.timeout(6_010, &mut out);
    assert_eq!(out, [Action::Finished]);
    assert_eq!(f.state(), State::Closed);

    // RTA in Closing: tlf, to Closed.
    let mut f = opened();
    f.close(10, &mut Vec::new());
    let out = rx(&mut f, 11, code::TERMINATE_ACK, 0, &[]);
    assert_eq!(out, [Action::Finished]);
    assert_eq!(f.state(), State::Closed);
    // RCR in Closed: sta.
    let out = rx(&mut f, 12, code::CONFIGURE_REQUEST, 3, &[1, 3, 7]);
    assert_eq!(sent(&out), [(code::TERMINATE_ACK, 3, vec![])]);
}

#[test]
fn configure_request_in_opened_renegotiates() {
    let mut f = opened();
    // RCR+ in Opened: tld, scr, sca, to Ack-Sent.
    let out = rx(&mut f, 20, code::CONFIGURE_REQUEST, 5, &[1, 3, 7]);
    assert_eq!(layer(&out), [Action::Down]);
    let s = sent(&out);
    assert_eq!(s[0].0, code::CONFIGURE_REQUEST);
    assert_eq!(s[1], (code::CONFIGURE_ACK, 5, vec![1, 3, 7]));
    assert_eq!(f.state(), State::AckSent);
}

#[test]
fn unknown_code_and_code_reject() {
    let mut f = opened();
    // RUC: scj with the whole packet.
    let out = rx(&mut f, 1, 42, 8, &[1, 2, 3]);
    let s = sent(&out);
    assert_eq!(s[0].0, code::CODE_REJECT);
    assert_eq!(s[0].2, [42, 8, 0, 7, 1, 2, 3]);
    assert_eq!(f.state(), State::Opened);
    // RXJ+ (a code beyond 7 rejected) keeps it open.
    assert!(rx(&mut f, 1, code::CODE_REJECT, 1, &[12, 0, 0, 4]).is_empty());
    assert_eq!(f.state(), State::Opened);
    // RXJ- (Configure-Request rejected) in Opened: tld, irc, str, to Stopping.
    let out = rx(&mut f, 1, code::CODE_REJECT, 2, &[1, 0, 0, 4]);
    assert_eq!(layer(&out), [Action::Down]);
    assert_eq!(sent(&out)[0].0, code::TERMINATE_REQUEST);
    assert_eq!(f.state(), State::Stopping);
}

#[test]
fn lower_layer_down_and_up_again() {
    let mut f = opened();
    let mut out = Vec::new();
    f.down(&mut out);
    assert_eq!(out, [Action::Down]);
    assert_eq!(f.state(), State::Starting);
    out.clear();
    f.up(5, &mut out);
    assert_eq!(f.state(), State::RequestSent);
    assert_eq!(sent(&out)[0].0, code::CONFIGURE_REQUEST);
    // Open from Initial: tls, to Starting.
    let mut f = fsm();
    let mut out = Vec::new();
    f.open(0, &mut out);
    assert_eq!(out, [Action::Started]);
    assert_eq!(f.state(), State::Starting);
    // Close in Starting: tlf, to Initial.
    out.clear();
    f.close(0, &mut out);
    assert_eq!(out, [Action::Finished]);
    assert_eq!(f.state(), State::Initial);
}

#[test]
fn malformed_packets_are_dropped() {
    let mut f = opened();
    let mut out = Vec::new();
    // Shorter than its header, length past the data, an option of length 1.
    f.receive(1, &[1, 1, 0], &mut out);
    f.receive(1, &[1, 1, 0, 9, 1, 3], &mut out);
    f.receive(1, &[1, 1, 0, 3], &mut out);
    f.receive(
        1,
        &ppp::packet(code::CONFIGURE_REQUEST, 1, &[1, 1]),
        &mut out,
    );
    f.receive(
        1,
        &ppp::packet(code::CONFIGURE_REQUEST, 1, &[1, 4, 7]),
        &mut out,
    );
    assert!(out.is_empty());
    assert_eq!(f.state(), State::Opened);
}

#[test]
fn request_sent_again_after_an_ack_gets_a_new_id() {
    let mut f = fsm();
    let id = started(&mut f);
    rx(&mut f, 1, code::CONFIGURE_ACK, id, &[1, 3, 0]);
    assert_eq!(f.state(), State::AckReceived);
    let mut out = Vec::new();
    f.timeout(3_000, &mut out);
    let s = sent(&out);
    assert_eq!(s[0].0, code::CONFIGURE_REQUEST);
    assert_ne!(s[0].1, id);
    assert_eq!(f.state(), State::RequestSent);
}

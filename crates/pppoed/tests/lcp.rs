//! LCP options, the LCP-only codes and the echo keepalive (RFC 1661, RFC 2516
//! section 7).

use ruster_pppoed::fsm::{code, Action, Limits, Negotiation, Reply, State};
use ruster_pppoed::lcp::{self, Auth, Echo, Lcp, LcpOptions, Notice};
use ruster_pppoed::ppp::{self, protocol};
use ruster_pppoed::Rng;

fn options(bytes: &[u8]) -> Vec<(u8, &[u8])> {
    ppp::options(bytes).unwrap()
}

#[test]
fn request_asks_for_mru_1492_and_a_magic_number() {
    let mut o = LcpOptions::new(Rng::new(1));
    let request = o.request();
    let magic = o.magic.to_be_bytes();
    assert_ne!(o.magic, 0);
    assert_eq!(request, [&[1, 4, 0x05, 0xd4, 5, 6][..], &magic].concat());
    // A Nak'd MRU within range is taken; a Nak'd magic number is picked again.
    o.naked(&options(&[1, 4, 0x05, 0xc8, 5, 6, 0, 0, 0, 1]));
    assert_eq!(o.mru, 1480);
    assert_ne!(o.magic.to_be_bytes(), magic);
    // An MRU above 1492 is not taken.
    o.naked(&options(&[1, 4, 0x05, 0xdc]));
    assert_eq!(o.mru, 1480);
    // Rejected options are not asked for again.
    o.rejected(&options(&[1, 4, 0x05, 0xc8, 5, 6, 0, 0, 0, 1]));
    assert!(o.request().is_empty());
}

#[test]
fn peer_options() {
    let mut o = LcpOptions::new(Rng::new(1));
    let ours = o.magic;
    // MRU 1492, PAP, a magic number: all taken.
    let good = [
        1, 4, 0x05, 0xd4, 3, 4, 0xc0, 0x23, 5, 6, 0x12, 0x34, 0x56, 0x78,
    ];
    assert_eq!(o.check(&options(&good), true), Reply::Ack);
    assert_eq!(o.peer_mru, 1492);
    assert_eq!(o.auth, Some(Auth::Pap));
    assert_eq!(o.peer_magic, 0x1234_5678);
    // CHAP with MD5.
    assert_eq!(o.check(&options(&[3, 5, 0xc2, 0x23, 5]), true), Reply::Ack);
    assert_eq!(o.auth, Some(Auth::ChapMd5));
    // No options: the defaults, no authentication.
    assert_eq!(o.check(&[], true), Reply::Ack);
    assert_eq!((o.peer_mru, o.auth), (1492, None));

    // MRU 1500 is above what PPPoE carries: Nak with 1492.
    assert_eq!(
        o.check(&options(&[1, 4, 0x05, 0xdc]), true),
        Reply::Nak(vec![1, 4, 0x05, 0xd4])
    );
    // MS-CHAPv2: Nak with CHAP-MD5.
    assert_eq!(
        o.check(&options(&[3, 5, 0xc2, 0x23, 0x81]), true),
        Reply::Nak(vec![3, 5, 0xc2, 0x23, 5])
    );
    // EAP: the same.
    assert_eq!(
        o.check(&options(&[3, 4, 0xc2, 0x27]), true),
        Reply::Nak(vec![3, 5, 0xc2, 0x23, 5])
    );
    // ACCM, PFC and ACFC are rejected (RFC 2516 section 7), with anything Nak'd
    // left out.
    let request = [1, 4, 0x05, 0xdc, 2, 6, 0, 0, 0, 0, 7, 2, 8, 2];
    assert_eq!(
        o.check(&options(&request), true),
        Reply::Reject(vec![2, 6, 0, 0, 0, 0, 7, 2, 8, 2])
    );
    // A Nak does not take the values in.
    assert_eq!(o.peer_mru, 1492);
    // Our own magic number: Nak with another; ours changes only on a Nak.
    let looped = [&[5, 6][..], &ours.to_be_bytes()].concat();
    let Reply::Nak(nak) = o.check(&options(&looped), true) else {
        panic!("not a Nak");
    };
    assert_eq!(nak[..2], [5, 6]);
    assert_ne!(nak[2..], ours.to_be_bytes());
    assert_eq!(o.magic, ours);
    // An MRU below the smallest we take: Nak with that smallest.
    assert_eq!(
        o.check(&options(&[1, 4, 0, 100]), true),
        Reply::Nak(vec![1, 4, 0, 128])
    );
    // After Max-Failure, what would be Nak'd is rejected.
    assert_eq!(
        o.check(&options(&[1, 4, 0x05, 0xdc]), false),
        Reply::Reject(vec![1, 4, 0x05, 0xdc])
    );
}

const PEER_MAGIC: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

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

/// An LCP that has reached Opened at time 0.
fn opened(echo: Echo) -> Lcp {
    let mut l = Lcp::new(Rng::new(3), Limits::default(), echo);
    let mut out = Vec::new();
    l.fsm.up(0, &mut out);
    l.fsm.open(0, &mut out);
    let (_, id, data) = sent(&out).remove(0);
    let peer = [&[5, 6][..], &PEER_MAGIC].concat();
    l.receive(0, &ppp::packet(code::CONFIGURE_REQUEST, 1, &peer), &mut out);
    l.receive(0, &ppp::packet(code::CONFIGURE_ACK, id, &data), &mut out);
    assert!(l.opened());
    l
}

#[test]
fn echo_request_is_answered_with_our_magic_number() {
    let mut l = opened(Echo::default());
    let magic = l.fsm.negotiation.magic.to_be_bytes();
    let mut out = Vec::new();
    let request = [&PEER_MAGIC[..], b"hi"].concat();
    l.receive(
        1,
        &ppp::packet(lcp::code::ECHO_REQUEST, 7, &request),
        &mut out,
    );
    assert_eq!(
        sent(&out),
        [(lcp::code::ECHO_REPLY, 7, [&magic[..], b"hi"].concat())]
    );
    // One with our own magic number (looped back), or too short, is dropped; so
    // is Discard-Request.
    out.clear();
    l.receive(
        1,
        &ppp::packet(lcp::code::ECHO_REQUEST, 8, &magic),
        &mut out,
    );
    l.receive(
        1,
        &ppp::packet(lcp::code::ECHO_REQUEST, 8, &[1, 2]),
        &mut out,
    );
    l.receive(
        1,
        &ppp::packet(lcp::code::DISCARD_REQUEST, 8, &PEER_MAGIC),
        &mut out,
    );
    assert!(out.is_empty());
}

#[test]
fn echo_request_before_opened_is_dropped() {
    let mut l = Lcp::new(Rng::new(3), Limits::default(), Echo::default());
    let mut out = Vec::new();
    l.fsm.up(0, &mut out);
    l.fsm.open(0, &mut out);
    out.clear();
    l.receive(
        1,
        &ppp::packet(lcp::code::ECHO_REQUEST, 7, &PEER_MAGIC),
        &mut out,
    );
    assert!(out.is_empty());
    assert_eq!(l.protocol_reject(0x80fd, &[1, 2, 3, 4]), None);
}

#[test]
fn keepalive_declares_the_link_dead_after_the_misses() {
    let echo = Echo {
        interval_ms: 1_000,
        failures: 3,
    };
    let mut l = opened(echo);
    let magic = l.fsm.negotiation.magic.to_be_bytes();
    assert_eq!(l.next_timer(), Some(1_000));
    let mut out = Vec::new();
    // Two requests unanswered, then a reply resets the count.
    for t in [1_000, 2_000] {
        assert_eq!(l.timeout(t, &mut out), None);
    }
    let s = sent(&out);
    assert_eq!(s.len(), 2);
    assert!(s
        .iter()
        .all(|p| p.0 == lcp::code::ECHO_REQUEST && p.2 == magic));
    l.receive(
        2_500,
        &ppp::packet(lcp::code::ECHO_REPLY, s[1].1, &PEER_MAGIC),
        &mut out,
    );
    out.clear();
    for t in [3_000, 4_000, 5_000] {
        assert_eq!(l.timeout(t, &mut out), None);
    }
    assert_eq!(sent(&out).len(), 3);
    assert_eq!(l.timeout(6_000, &mut out), Some(Notice::NoEcho));
    assert_eq!(l.next_timer(), None);
}

#[test]
fn peer_that_code_rejects_echo_gets_no_more() {
    let mut l = opened(Echo::default());
    let mut out = Vec::new();
    l.timeout(10_000, &mut out);
    let (_, id, data) = sent(&out).remove(0);
    let rejected = ppp::packet(lcp::code::ECHO_REQUEST, id, &data);
    l.receive(
        10_001,
        &ppp::packet(code::CODE_REJECT, 1, &rejected),
        &mut out,
    );
    assert!(l.opened());
    assert_eq!(l.next_timer(), None);
}

#[test]
fn protocol_reject() {
    let mut l = opened(Echo::default());
    // We send one for a protocol we do not run, the packet after the protocol.
    let reject = l.protocol_reject(0x80fd, &[1, 1, 0, 4]).unwrap();
    let p = ppp::Packet::parse(&reject).unwrap();
    assert_eq!(p.code, lcp::code::PROTOCOL_REJECT);
    assert_eq!(p.data, [0x80, 0xfd, 1, 1, 0, 4]);
    // A long packet is cut to fit the peer's MRU.
    let long = vec![0; 3_000];
    let reject = l.protocol_reject(0x80fd, &long).unwrap();
    assert_eq!(reject.len(), 1492);

    // The peer's for IPv6CP: RXJ+ for LCP, reported.
    let mut out = Vec::new();
    let notice = l.receive(
        1,
        &ppp::packet(lcp::code::PROTOCOL_REJECT, 2, &[0x80, 0x57, 1, 1, 0, 4]),
        &mut out,
    );
    assert_eq!(notice, Some(Notice::ProtocolRejected(protocol::IPV6CP)));
    assert!(l.opened());
    // The peer's for LCP itself: RXJ-.
    let notice = l.receive(
        2,
        &ppp::packet(lcp::code::PROTOCOL_REJECT, 3, &[0xc0, 0x21]),
        &mut out,
    );
    assert_eq!(notice, Some(Notice::ProtocolRejected(protocol::LCP)));
    assert_eq!(l.fsm.state(), State::Stopping);
}

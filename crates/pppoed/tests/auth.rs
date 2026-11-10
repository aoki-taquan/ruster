//! PAP (RFC 1334) and CHAP with MD5 (RFC 1994).

use ruster_pppoed::auth::{chap, pap, Client, Outcome, PAP_RESTART_MS, PAP_TRIES};
use ruster_pppoed::lcp::Auth;
use ruster_pppoed::ppp::{self, protocol};

fn parsed(bytes: &[u8]) -> (u8, u8, Vec<u8>) {
    let p = ppp::Packet::parse(bytes).unwrap();
    (p.code, p.id, p.data.to_vec())
}

#[test]
fn pap_request_ack() {
    let mut c = Client::new(Auth::Pap, b"user", b"pass");
    assert_eq!(c.protocol(), protocol::PAP);
    let mut out = Vec::new();
    c.start(0, &mut out);
    // RFC 1334 section 2.2.1: Peer-ID-Length, Peer-ID, Passwd-Length, Password.
    let (code, id, data) = parsed(&out[0]);
    assert_eq!(code, pap::REQUEST);
    assert_eq!(data, b"\x04user\x04pass");
    // An Ack for another identifier, or with a Msg-Length past the end, is dropped.
    assert_eq!(
        c.receive(&ppp::packet(pap::ACK, id + 1, &[0]), &mut out),
        None
    );
    assert_eq!(
        c.receive(&ppp::packet(pap::ACK, id, &[5, b'o']), &mut out),
        None
    );
    assert_eq!(
        c.receive(&ppp::packet(pap::ACK, id, b"\x02ok"), &mut out),
        Some(Outcome::Success)
    );
    assert_eq!(c.next_timer(), None);
}

#[test]
fn pap_nak_and_retries() {
    let mut c = Client::new(Auth::Pap, b"user", b"pass");
    let mut out = Vec::new();
    c.start(0, &mut out);
    let mut ids = vec![parsed(&out[0]).1];
    for i in 1..PAP_TRIES {
        let now = u64::from(i) * PAP_RESTART_MS;
        assert_eq!(c.next_timer(), Some(now));
        assert_eq!(c.timeout(now, &mut out), None);
        ids.push(parsed(out.last().unwrap()).1);
    }
    // A new identifier for each request.
    ids.dedup();
    assert_eq!(ids.len(), PAP_TRIES as usize);
    let last = *ids.last().unwrap();
    // A Nak for an earlier request is not ours any more.
    assert_eq!(
        c.receive(&ppp::packet(pap::NAK, ids[0], &[0]), &mut out),
        None
    );
    assert_eq!(
        c.receive(&ppp::packet(pap::NAK, last, &[0]), &mut out),
        Some(Outcome::Failure)
    );
    // With no answer at all, the last timeout fails.
    let mut c = Client::new(Auth::Pap, b"user", b"pass");
    c.start(0, &mut out);
    let mut outcome = None;
    while let Some(at) = c.next_timer() {
        outcome = c.timeout(at, &mut out);
    }
    assert_eq!(outcome, Some(Outcome::Failure));
}

#[test]
fn chap_md5_response() {
    let mut c = Client::new(Auth::ChapMd5, b"user", b"secret");
    assert_eq!(c.protocol(), protocol::CHAP);
    let mut out = Vec::new();
    c.start(0, &mut out);
    assert!(out.is_empty());
    let challenge: Vec<u8> = (0..16).collect();
    let data = [&[16][..], &challenge, b"ac"].concat();
    assert_eq!(
        c.receive(&ppp::packet(chap::CHALLENGE, 0x2a, &data), &mut out),
        None
    );
    // RFC 1994 section 4.1: MD5(identifier, secret, challenge), then our name.
    // The hash is that of Python's hashlib.md5(b"\x2a" + b"secret" + bytes(range(16))).
    let expected = [
        0x03, 0xdc, 0x98, 0xc5, 0xa8, 0x32, 0x69, 0x2b, 0x49, 0xdf, 0x73, 0xcf, 0x48, 0xfc, 0xb4,
        0xe9,
    ];
    let (code, id, data) = parsed(&out[0]);
    assert_eq!((code, id), (chap::RESPONSE, 0x2a));
    assert_eq!(data, [&[16][..], &expected, b"user"].concat());
    // Success with another identifier is dropped.
    assert_eq!(
        c.receive(&ppp::packet(chap::SUCCESS, 0x2b, b""), &mut out),
        None
    );
    assert_eq!(
        c.receive(&ppp::packet(chap::SUCCESS, 0x2a, b"welcome"), &mut out),
        Some(Outcome::Success)
    );
    // A later challenge is answered; its Failure ends the link.
    out.clear();
    c.receive(
        &ppp::packet(chap::CHALLENGE, 0x30, &data_of(&[7; 8])),
        &mut out,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(
        c.receive(&ppp::packet(chap::FAILURE, 0x30, b""), &mut out),
        Some(Outcome::Failure)
    );
}

fn data_of(value: &[u8]) -> Vec<u8> {
    [&[value.len() as u8][..], value].concat()
}

#[test]
fn chap_bad_challenges_are_dropped() {
    let mut c = Client::new(Auth::ChapMd5, b"user", b"secret");
    let mut out = Vec::new();
    // Value-Size 0, Value-Size past the end, no data.
    c.receive(&ppp::packet(chap::CHALLENGE, 1, &[0, b'a']), &mut out);
    c.receive(&ppp::packet(chap::CHALLENGE, 1, &[9, 1, 2]), &mut out);
    c.receive(&ppp::packet(chap::CHALLENGE, 1, &[]), &mut out);
    assert!(out.is_empty());
    // Success with no Response sent yet is not ours.
    assert_eq!(
        c.receive(&ppp::packet(chap::SUCCESS, 1, b""), &mut out),
        None
    );
}

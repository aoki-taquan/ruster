//! Session frames, control packets and options (RFC 2516 section 6, RFC 1661
//! sections 2, 5 and 6).

use ruster_pppoed::ppp::{
    self, options, protocol, push_option, session_frame, Packet, SessionFrame,
};

const HOST: [u8; 6] = [2, 0, 0, 0, 0, 2];
const AC: [u8; 6] = [2, 0, 0, 0, 0, 0xac];

#[test]
fn session_frame_both_ways() {
    let lcp = ppp::packet(1, 7, &[1, 4, 0x05, 0xd4]);
    let frame = session_frame(AC, HOST, 0x1234, protocol::LCP, &lcp);
    assert_eq!(
        frame,
        [
            &AC[..],
            &HOST,
            &[0x88, 0x64, 0x11, 0x00, 0x12, 0x34, 0x00, 0x0a, 0xc0, 0x21],
            &[1, 7, 0, 8, 1, 4, 0x05, 0xd4],
        ]
        .concat()
    );
    let parsed = SessionFrame::parse(&frame).unwrap();
    assert_eq!(
        (
            parsed.destination,
            parsed.source,
            parsed.session,
            parsed.protocol
        ),
        (AC, HOST, 0x1234, protocol::LCP)
    );
    assert_eq!(parsed.information, lcp);
    // Ethernet padding after the PPPoE length is not information.
    let mut padded = frame.clone();
    padded.extend_from_slice(&[0; 30]);
    assert_eq!(SessionFrame::parse(&padded).unwrap().information, lcp);
}

#[test]
fn bad_session_frames() {
    let frame = session_frame(AC, HOST, 1, protocol::LCP, &[1, 1, 0, 4]);
    for n in 0..frame.len() {
        assert_eq!(SessionFrame::parse(&frame[..n]), None, "cut at {n}");
    }
    let changed = |i: usize, v: u8| {
        let mut f = frame.clone();
        f[i] = v;
        SessionFrame::parse(&f).is_some()
    };
    // Discovery's Ethernet type, version 2, a code, a length of 1 (no protocol).
    assert!(!changed(13, 0x63));
    assert!(!changed(14, 0x21));
    assert!(!changed(15, 0x09));
    assert!(!changed(19, 1));
}

#[test]
fn control_packets() {
    let p = Packet::parse(&[9, 3, 0, 8, 1, 2, 3, 4, 0xee, 0xee]).unwrap();
    assert_eq!((p.code, p.id, p.data), (9, 3, &[1, 2, 3, 4][..]));
    // Shorter than the header, a length below 4, a length past the end.
    assert_eq!(Packet::parse(&[9, 3, 0]), None);
    assert_eq!(Packet::parse(&[9, 3, 0, 3]), None);
    assert_eq!(Packet::parse(&[9, 3, 0, 9, 1, 2, 3, 4]), None);
}

#[test]
fn option_lists() {
    let mut out = Vec::new();
    push_option(&mut out, 1, &[0x05, 0xd4]);
    push_option(&mut out, 7, &[]);
    assert_eq!(out, [1, 4, 0x05, 0xd4, 7, 2]);
    assert_eq!(
        options(&out),
        Some(vec![(1, &[0x05, 0xd4][..]), (7, &[][..])])
    );
    assert_eq!(options(&[]), Some(vec![]));
    // A length of 0 or 1, or past the end.
    assert_eq!(options(&[1, 0]), None);
    assert_eq!(options(&[1, 1]), None);
    assert_eq!(options(&[1, 5, 0]), None);
    assert_eq!(options(&[1]), None);
}

#[test]
fn protocol_numbers_and_codes_are_those_of_the_rfcs() {
    use ruster_pppoed::auth::{chap, pap};
    use ruster_pppoed::fsm::code;
    use ruster_pppoed::lcp;
    // RFC 1332 section 2 and 5072 section 2 (0x0021, 0x8021; 0x0057, 0x8057),
    // RFC 1661 section 2 (LCP 0xc021), RFC 1334 section 2.2 (PAP 0xc023), RFC 1994
    // section 4 (CHAP 0xc223).
    assert_eq!(
        [
            protocol::IPV4,
            protocol::IPCP,
            protocol::IPV6,
            protocol::IPV6CP,
            protocol::LCP,
            protocol::PAP,
            protocol::CHAP,
        ],
        [0x0021, 0x8021, 0x0057, 0x8057, 0xc021, 0xc023, 0xc223]
    );
    // RFC 1661 section 5: codes 1 to 11.
    assert_eq!(
        [
            code::CONFIGURE_REQUEST,
            code::CONFIGURE_ACK,
            code::CONFIGURE_NAK,
            code::CONFIGURE_REJECT,
            code::TERMINATE_REQUEST,
            code::TERMINATE_ACK,
            code::CODE_REJECT,
            lcp::code::PROTOCOL_REJECT,
            lcp::code::ECHO_REQUEST,
            lcp::code::ECHO_REPLY,
            lcp::code::DISCARD_REQUEST,
        ],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    );
    // RFC 1334 section 2.2: PAP codes. RFC 1994 section 4: CHAP codes.
    assert_eq!([pap::REQUEST, pap::ACK, pap::NAK], [1, 2, 3]);
    assert_eq!(
        [
            chap::CHALLENGE,
            chap::RESPONSE,
            chap::SUCCESS,
            chap::FAILURE
        ],
        [1, 2, 3, 4]
    );
}

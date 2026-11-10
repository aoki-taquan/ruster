//! PPPoE Discovery against hand-built frames (RFC 2516 section 5).

use ruster_pppoed::discovery::{
    code, frame, tag, Discovery, Event, Packet, Settings, Tags, FIRST_WAIT_MS, PADR_TRIES,
};
use ruster_pppoed::Mac;

const HOST: Mac = [0x02, 0, 0, 0, 0, 0x02];
const AC: Mac = [0x02, 0, 0, 0, 0, 0xac];
const OTHER_AC: Mac = [0x02, 0, 0, 0, 0, 0xad];
const UNIQ: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn discovery(service: &[u8], ac_name: Option<&[u8]>) -> Discovery {
    Discovery::new(
        Settings {
            mac: HOST,
            service: service.to_vec(),
            ac_name: ac_name.map(<[u8]>::to_vec),
        },
        UNIQ,
    )
}

fn pado(from: Mac, tags: &[(u16, &[u8])]) -> Vec<u8> {
    frame(HOST, from, code::PADO, 0, tags)
}

fn usual_pado(from: Mac) -> Vec<u8> {
    pado(
        from,
        &[
            (tag::AC_NAME, b"isp-ac"),
            (tag::SERVICE_NAME, b""),
            (tag::HOST_UNIQ, &UNIQ),
            (tag::AC_COOKIE, b"cookie"),
        ],
    )
}

fn tags_of(frame: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let packet = Packet::parse(frame).unwrap();
    let mut tags = Vec::new();
    let mut rest = packet.payload;
    while !rest.is_empty() {
        let kind = u16::from_be_bytes([rest[0], rest[1]]);
        let length = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        tags.push((kind, rest[4..4 + length].to_vec()));
        rest = &rest[4 + length..];
    }
    tags
}

#[test]
fn padi_is_broadcast_with_one_service_name_and_host_uniq() {
    let mut d = discovery(b"", None);
    let mut out = Vec::new();
    d.start(0, &mut out);
    assert_eq!(out.len(), 1);
    let padi = &out[0];
    // RFC 2516 section 5.1: broadcast, code 0x09, session 0.
    assert_eq!(
        padi[..22],
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 2, 0x88, 0x63, 0x11, 0x09, 0, 0, 0,
            16, 0x01, 0x01
        ]
    );
    assert_eq!(
        tags_of(padi),
        vec![(tag::SERVICE_NAME, vec![]), (tag::HOST_UNIQ, UNIQ.to_vec())]
    );
    assert_eq!(d.next_timer(), Some(FIRST_WAIT_MS));
}

#[test]
fn full_exchange_gives_the_session() {
    let mut d = discovery(b"", None);
    let mut out = Vec::new();
    d.start(0, &mut out);
    out.clear();
    assert_eq!(d.receive(10, &usual_pado(AC), &mut out), None);
    // RFC 2516 section 5.3: PADR to the AC, the cookie returned.
    let padr = &out[0];
    assert_eq!(padr[..6], AC);
    assert_eq!(padr[15], code::PADR);
    assert_eq!(
        tags_of(padr),
        vec![
            (tag::SERVICE_NAME, vec![]),
            (tag::HOST_UNIQ, UNIQ.to_vec()),
            (tag::AC_COOKIE, b"cookie".to_vec()),
        ]
    );
    out.clear();
    // A second PADO is ignored once one was taken.
    assert_eq!(d.receive(11, &usual_pado(OTHER_AC), &mut out), None);
    assert!(out.is_empty());
    let pads = frame(
        HOST,
        AC,
        code::PADS,
        0x1234,
        &[(tag::SERVICE_NAME, b""), (tag::HOST_UNIQ, &UNIQ)],
    );
    assert_eq!(
        d.receive(20, &pads, &mut out),
        Some(Event::Session { id: 0x1234, ac: AC })
    );
    assert_eq!(d.session(), Some((0x1234, AC)));
    assert_eq!(d.next_timer(), None);

    // Section 5.5: our PADT carries the session ID, no tags.
    let mut d2 = d.clone();
    d2.terminate(&mut out);
    assert_eq!(
        out[0],
        [
            &AC[..],
            &HOST[..],
            &[0x88, 0x63, 0x11, 0xa7, 0x12, 0x34, 0, 0]
        ]
        .concat()
    );
    assert_eq!(d2.session(), None);

    // A PADT from the AC for another session or from another MAC is ignored.
    let padt = |from, id| frame(HOST, from, code::PADT, id, &[]);
    assert_eq!(d.receive(30, &padt(AC, 0x1235), &mut out), None);
    assert_eq!(d.receive(30, &padt(OTHER_AC, 0x1234), &mut out), None);
    assert_eq!(
        d.receive(30, &padt(AC, 0x1234), &mut out),
        Some(Event::Terminated)
    );
    assert_eq!(d.session(), None);
}

#[test]
fn relay_session_id_is_returned() {
    let mut d = discovery(b"", None);
    let mut out = Vec::new();
    d.start(0, &mut out);
    out.clear();
    let offer = pado(
        AC,
        &[
            (tag::AC_NAME, b"ac"),
            (tag::SERVICE_NAME, b""),
            (tag::RELAY_SESSION_ID, b"relay"),
            (tag::HOST_UNIQ, &UNIQ),
        ],
    );
    d.receive(1, &offer, &mut out);
    assert_eq!(
        tags_of(&out[0]),
        vec![
            (tag::SERVICE_NAME, vec![]),
            (tag::HOST_UNIQ, UNIQ.to_vec()),
            (tag::RELAY_SESSION_ID, b"relay".to_vec()),
        ]
    );
}

#[test]
fn offers_that_do_not_fit_are_ignored() {
    let cases: Vec<Vec<u8>> = vec![
        // Another Host-Uniq: another session's offer.
        pado(
            AC,
            &[
                (tag::AC_NAME, b"isp-ac"),
                (tag::SERVICE_NAME, b"inet"),
                (tag::HOST_UNIQ, &[9; 8]),
            ],
        ),
        // No Host-Uniq.
        pado(
            AC,
            &[(tag::AC_NAME, b"isp-ac"), (tag::SERVICE_NAME, b"inet")],
        ),
        // No AC-Name.
        pado(AC, &[(tag::SERVICE_NAME, b"inet"), (tag::HOST_UNIQ, &UNIQ)]),
        // Another service.
        pado(
            AC,
            &[
                (tag::AC_NAME, b"isp-ac"),
                (tag::SERVICE_NAME, b"tv"),
                (tag::HOST_UNIQ, &UNIQ),
            ],
        ),
        // Another AC name.
        pado(
            AC,
            &[
                (tag::AC_NAME, b"other"),
                (tag::SERVICE_NAME, b"inet"),
                (tag::HOST_UNIQ, &UNIQ),
            ],
        ),
        // An error tag.
        pado(
            AC,
            &[
                (tag::AC_NAME, b"isp-ac"),
                (tag::SERVICE_NAME, b"inet"),
                (tag::HOST_UNIQ, &UNIQ),
                (tag::AC_SYSTEM_ERROR, b"busy"),
            ],
        ),
        // A multicast source.
        pado(
            [0x03, 0, 0, 0, 0, 1],
            &[
                (tag::AC_NAME, b"isp-ac"),
                (tag::SERVICE_NAME, b"inet"),
                (tag::HOST_UNIQ, &UNIQ),
            ],
        ),
        // Not to us.
        frame(
            OTHER_AC,
            AC,
            code::PADO,
            0,
            &[
                (tag::AC_NAME, b"isp-ac"),
                (tag::SERVICE_NAME, b"inet"),
                (tag::HOST_UNIQ, &UNIQ),
            ],
        ),
        // A session ID that is not 0.
        frame(
            HOST,
            AC,
            code::PADO,
            7,
            &[
                (tag::AC_NAME, b"isp-ac"),
                (tag::SERVICE_NAME, b"inet"),
                (tag::HOST_UNIQ, &UNIQ),
            ],
        ),
    ];
    for (i, offer) in cases.iter().enumerate() {
        let mut d = discovery(b"inet", Some(b"isp-ac"));
        let mut out = Vec::new();
        d.start(0, &mut out);
        out.clear();
        d.receive(1, offer, &mut out);
        assert!(out.is_empty(), "case {i} was taken");
    }
    // The same offer with everything right is taken; one of several service names is
    // enough.
    let mut d = discovery(b"inet", Some(b"isp-ac"));
    let mut out = Vec::new();
    d.start(0, &mut out);
    out.clear();
    let good = pado(
        AC,
        &[
            (tag::AC_NAME, b"isp-ac"),
            (tag::SERVICE_NAME, b"tv"),
            (tag::SERVICE_NAME, b"inet"),
            (tag::HOST_UNIQ, &UNIQ),
        ],
    );
    d.receive(1, &good, &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(tags_of(&out[0])[0], (tag::SERVICE_NAME, b"inet".to_vec()));
}

#[test]
fn refused_pads() {
    for (pads_tags, id, expected) in [
        (
            vec![(tag::SERVICE_NAME_ERROR, &b"no"[..])],
            0,
            tag::SERVICE_NAME_ERROR,
        ),
        (vec![], 0, 0),
    ] {
        let mut d = discovery(b"", None);
        let mut out = Vec::new();
        d.start(0, &mut out);
        d.receive(1, &usual_pado(AC), &mut out);
        let mut tags: Vec<(u16, &[u8])> = vec![(tag::HOST_UNIQ, &UNIQ)];
        tags.extend(pads_tags);
        let pads = frame(HOST, AC, code::PADS, id, &tags);
        assert_eq!(
            d.receive(2, &pads, &mut out),
            Some(Event::Refused(expected))
        );
        assert_eq!(d.next_timer(), None);
    }
}

#[test]
fn pads_from_another_ac_or_session_is_ignored() {
    let mut d = discovery(b"", None);
    let mut out = Vec::new();
    d.start(0, &mut out);
    d.receive(1, &usual_pado(AC), &mut out);
    let other = frame(HOST, OTHER_AC, code::PADS, 5, &[(tag::HOST_UNIQ, &UNIQ)]);
    assert_eq!(d.receive(2, &other, &mut out), None);
    let wrong_uniq = frame(HOST, AC, code::PADS, 5, &[(tag::HOST_UNIQ, &[0; 8])]);
    assert_eq!(d.receive(2, &wrong_uniq, &mut out), None);
    assert_eq!(d.session(), None);
}

#[test]
fn padi_and_padr_are_sent_again_with_the_wait_doubled() {
    let mut d = discovery(b"", None);
    let mut out = Vec::new();
    d.start(0, &mut out);
    let mut at = d.next_timer().unwrap();
    assert_eq!(at, 2_000);
    // Early: nothing.
    d.timeout(at - 1, &mut out);
    assert_eq!(out.len(), 1);
    let mut waits = Vec::new();
    for _ in 0..6 {
        d.timeout(at, &mut out);
        let next = d.next_timer().unwrap();
        waits.push(next - at);
        at = next;
    }
    assert_eq!(waits, [4_000, 8_000, 16_000, 32_000, 32_000, 32_000]);
    assert!(out.iter().all(|f| f[15] == code::PADI));
    assert_eq!(out.len(), 7);

    out.clear();
    d.receive(at, &usual_pado(AC), &mut out);
    assert_eq!(d.next_timer(), Some(at + 2_000));
    for _ in 1..PADR_TRIES {
        let now = d.next_timer().unwrap();
        d.timeout(now, &mut out);
    }
    assert_eq!(out.len(), PADR_TRIES as usize);
    assert!(out.iter().all(|f| f[15] == code::PADR));
    // After the last PADR, back to the PADI.
    out.clear();
    let now = d.next_timer().unwrap();
    d.timeout(now, &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0][15], code::PADI);
    assert_eq!(d.next_timer(), Some(now + FIRST_WAIT_MS));
}

#[test]
fn malformed_frames_are_refused() {
    let good = usual_pado(AC);
    // Every truncation of a good frame either parses as a shorter valid packet or
    // is refused; none panics.
    for n in 0..good.len() {
        let _ = Packet::parse(&good[..n]).map(|p| Tags::parse(p.payload));
    }
    // A length past the frame.
    let mut long = good.clone();
    long[18] = 0xff;
    assert_eq!(Packet::parse(&long), None);
    // Another version.
    let mut version = good.clone();
    version[14] = 0x21;
    assert_eq!(Packet::parse(&version), None);
    // A tag running past the payload.
    let bad_tag = pado(AC, &[]);
    let mut bad_tag = bad_tag;
    bad_tag.extend_from_slice(&[0x01, 0x02, 0x00, 0x09, b'x']);
    bad_tag[19] = 5;
    let packet = Packet::parse(&bad_tag).unwrap();
    assert_eq!(Tags::parse(packet.payload), None);
    // Ethernet padding after the length is not read as tags.
    let mut padded = good.clone();
    padded.extend_from_slice(&[0xff; 20]);
    assert_eq!(
        Packet::parse(&padded).unwrap().payload,
        Packet::parse(&good).unwrap().payload
    );
    // End-Of-List stops the tags.
    let ended = pado(
        AC,
        &[
            (tag::AC_NAME, b"a"),
            (tag::END_OF_LIST, b""),
            (tag::HOST_UNIQ, &UNIQ),
        ],
    );
    let tags = Tags::parse(Packet::parse(&ended).unwrap().payload).unwrap();
    assert_eq!(tags.ac_name, Some(&b"a"[..]));
    assert_eq!(tags.host_uniq, None);
}

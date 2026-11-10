//! A whole session against a small scripted access concentrator: Discovery, LCP,
//! PAP or CHAP, IPCP and IPv6CP, and the ways a session ends.

use std::net::Ipv4Addr;

use ruster_pppoed::discovery::{self, code as pado, tag, Packet, Tags};
use ruster_pppoed::fsm::code;
use ruster_pppoed::lcp::{self, Echo};
use ruster_pppoed::ppp::{self, protocol, SessionFrame};
use ruster_pppoed::session::{
    Event, FrameKind, Output, Reason, Session, SessionDown, SessionUp, Settings,
};
use ruster_pppoed::Mac;

const HOST: Mac = [0x02, 0, 0, 0, 0, 0x02];
const AC: Mac = [0x02, 0, 0, 0, 0, 0xac];
const SESSION: u16 = 0x1234;
const AC_MAGIC: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
const AC_ID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

#[derive(Clone, Copy, PartialEq)]
enum AcAuth {
    None,
    Pap,
    Chap,
}

/// The access concentrator's side, just enough to bring a session up.
struct Ac {
    auth: AcAuth,
    password: &'static [u8],
    ipv6cp: bool,
    answer_echo: bool,
    lcp_acked_by_host: bool,
    lcp_acked_host: bool,
    network_started: bool,
    seen: Vec<(u16, u8)>,
}

impl Ac {
    fn new(auth: AcAuth) -> Self {
        Self {
            auth,
            password: b"secret",
            ipv6cp: true,
            answer_echo: true,
            lcp_acked_by_host: false,
            lcp_acked_host: false,
            network_started: false,
            seen: Vec::new(),
        }
    }

    fn session(&self, protocol: u16, code: u8, id: u8, data: &[u8]) -> (FrameKind, Vec<u8>) {
        let packet = ppp::packet(code, id, data);
        (
            FrameKind::Control,
            ppp::session_frame(HOST, AC, SESSION, protocol, &packet),
        )
    }

    fn handle(&mut self, kind: FrameKind, frame: &[u8]) -> Vec<(FrameKind, Vec<u8>)> {
        let mut out = Vec::new();
        if kind == FrameKind::Discovery {
            let packet = Packet::parse(frame).unwrap();
            let tags = Tags::parse(packet.payload).unwrap();
            self.seen.push((0, packet.code));
            let Some(uniq) = tags.host_uniq.map(<[u8]>::to_vec) else {
                return out;
            };
            match packet.code {
                pado::PADI => out.push((
                    FrameKind::Discovery,
                    discovery::frame(
                        HOST,
                        AC,
                        pado::PADO,
                        0,
                        &[
                            (tag::AC_NAME, b"ac"),
                            (tag::SERVICE_NAME, b""),
                            (tag::HOST_UNIQ, &uniq),
                        ],
                    ),
                )),
                pado::PADR => {
                    out.push((
                        FrameKind::Discovery,
                        discovery::frame(
                            HOST,
                            AC,
                            pado::PADS,
                            SESSION,
                            &[(tag::SERVICE_NAME, b""), (tag::HOST_UNIQ, &uniq)],
                        ),
                    ));
                    let mut options = vec![1, 4, 0x05, 0xd4];
                    match self.auth {
                        AcAuth::None => {}
                        AcAuth::Pap => options.extend_from_slice(&[3, 4, 0xc0, 0x23]),
                        AcAuth::Chap => options.extend_from_slice(&[3, 5, 0xc2, 0x23, 5]),
                    }
                    options.extend_from_slice(&[5, 6]);
                    options.extend_from_slice(&AC_MAGIC);
                    out.push(self.session(protocol::LCP, code::CONFIGURE_REQUEST, 1, &options));
                }
                _ => {}
            }
            return out;
        }
        let f = SessionFrame::parse(frame).unwrap();
        assert_eq!((f.session, f.destination, f.source), (SESSION, AC, HOST));
        let p = ppp::Packet::parse(f.information).unwrap();
        self.seen.push((f.protocol, p.code));
        match (f.protocol, p.code) {
            (protocol::LCP, code::CONFIGURE_REQUEST) => {
                out.push(self.session(protocol::LCP, code::CONFIGURE_ACK, p.id, p.data));
                self.lcp_acked_host = true;
            }
            (protocol::LCP, code::CONFIGURE_ACK) => self.lcp_acked_by_host = true,
            (protocol::LCP, lcp::code::ECHO_REQUEST) if self.answer_echo => {
                out.push(self.session(protocol::LCP, lcp::code::ECHO_REPLY, p.id, &AC_MAGIC));
            }
            (protocol::LCP, code::TERMINATE_REQUEST) => {
                out.push(self.session(protocol::LCP, code::TERMINATE_ACK, p.id, &[]));
            }
            (protocol::PAP, 1) => {
                let user_len = usize::from(p.data[0]);
                let password = &p.data[2 + user_len..];
                if password == self.password {
                    out.push(self.session(protocol::PAP, 2, p.id, &[0]));
                    self.start_network(&mut out);
                } else {
                    out.push(self.session(protocol::PAP, 3, p.id, &[0]));
                }
            }
            (protocol::CHAP, 2) => {
                assert_eq!(p.data[0], 16);
                assert_eq!(&p.data[17..], b"user");
                out.push(self.session(protocol::CHAP, 3, p.id, b"ok"));
                self.start_network(&mut out);
            }
            (protocol::IPCP, code::CONFIGURE_REQUEST) => {
                let wanted = [
                    3, 6, 198, 51, 100, 2, 129, 6, 192, 0, 2, 53, 131, 6, 192, 0, 2, 54,
                ];
                let reply = if p.data == wanted {
                    code::CONFIGURE_ACK
                } else {
                    code::CONFIGURE_NAK
                };
                let data = if reply == code::CONFIGURE_ACK {
                    p.data
                } else {
                    &wanted
                };
                out.push(self.session(protocol::IPCP, reply, p.id, data));
            }
            (protocol::IPV6CP, code::CONFIGURE_REQUEST) if self.ipv6cp => {
                out.push(self.session(protocol::IPV6CP, code::CONFIGURE_ACK, p.id, p.data));
            }
            (protocol::IPV6CP, _) if !self.ipv6cp => {
                let mut data = protocol::IPV6CP.to_be_bytes().to_vec();
                data.extend_from_slice(f.information);
                out.push(self.session(protocol::LCP, lcp::code::PROTOCOL_REJECT, 9, &data));
            }
            _ => {}
        }
        if self.lcp_acked_by_host && self.lcp_acked_host && !self.network_started {
            match self.auth {
                AcAuth::Chap => {
                    let challenge = [&[8][..], &[7; 8], b"ac"].concat();
                    out.push(self.session(protocol::CHAP, 1, 3, &challenge));
                    self.network_started = true;
                }
                AcAuth::None => self.start_network(&mut out),
                AcAuth::Pap => {}
            }
        }
        out
    }

    fn start_network(&mut self, out: &mut Vec<(FrameKind, Vec<u8>)>) {
        self.network_started = true;
        out.push(self.session(
            protocol::IPCP,
            code::CONFIGURE_REQUEST,
            1,
            &[3, 6, 198, 51, 100, 1],
        ));
        if self.ipv6cp {
            let data = [&[1, 10][..], &AC_ID].concat();
            out.push(self.session(protocol::IPV6CP, code::CONFIGURE_REQUEST, 1, &data));
        }
    }
}

fn settings(password: &[u8]) -> Settings {
    Settings {
        interface: "wan".into(),
        mac: HOST,
        user: b"user".to_vec(),
        password: password.to_vec(),
        service: Vec::new(),
        ac_name: None,
        echo: Echo::default(),
        ipv6: true,
    }
}

/// Passes frames both ways until neither side has more; returns the events.
fn exchange(s: &mut Session, ac: &mut Ac, now: u64, mut out: Output) -> Vec<Event> {
    let mut events = std::mem::take(&mut out.events);
    let mut to_ac = out.frames;
    for _ in 0..100 {
        if to_ac.is_empty() {
            return events;
        }
        let mut to_host = Vec::new();
        for (kind, frame) in to_ac.drain(..) {
            to_host.extend(ac.handle(kind, &frame));
        }
        for (kind, frame) in to_host {
            let mut o = Output::default();
            s.receive(now, kind, &frame, &mut o);
            events.extend(o.events);
            to_ac.extend(o.frames);
        }
    }
    panic!("the exchange does not end");
}

fn start(s: &mut Session, ac: &mut Ac, now: u64) -> Vec<Event> {
    let mut out = Output::default();
    s.timeout(now, &mut out);
    exchange(s, ac, now, out)
}

fn expected_up(ipv6_local: Option<[u8; 8]>) -> SessionUp {
    SessionUp {
        session_id: SESSION,
        ac: AC,
        mtu: 1492,
        ipv4: Some(Ipv4Addr::new(198, 51, 100, 2)),
        peer_ipv4: Some(Ipv4Addr::new(198, 51, 100, 1)),
        dns: vec![Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)],
        ipv6_local_id: ipv6_local,
        ipv6_peer_id: Some(AC_ID),
    }
}

#[test]
fn chap_session_comes_up_with_every_value() {
    let mut s = Session::new(settings(b"secret"), 42);
    let mut ac = Ac::new(AcAuth::Chap);
    let events = start(&mut s, &mut ac, 0);
    let up = s.up().cloned().expect("the session is up");
    assert_eq!(up, expected_up(up.ipv6_local_id));
    assert!(up.ipv6_local_id.is_some_and(|id| id != [0; 8]));
    // The last event is the whole of it.
    assert_eq!(events.last(), Some(&Event::Up(up)));
    assert!(events.iter().all(|e| matches!(e, Event::Up(_))));
}

#[test]
fn pap_session_without_ipv6cp_at_the_peer() {
    let mut s = Session::new(settings(b"secret"), 1);
    let mut ac = Ac::new(AcAuth::Pap);
    ac.ipv6cp = false;
    start(&mut s, &mut ac, 0);
    let up = s.up().cloned().unwrap();
    assert_eq!(
        up,
        SessionUp {
            ipv6_local_id: None,
            ipv6_peer_id: None,
            ..expected_up(None)
        }
    );
}

#[test]
fn no_authentication() {
    let mut s = Session::new(settings(b""), 7);
    let mut ac = Ac::new(AcAuth::None);
    start(&mut s, &mut ac, 0);
    assert!(s.up().is_some());
    assert!(!ac
        .seen
        .iter()
        .any(|(p, _)| *p == protocol::PAP || *p == protocol::CHAP));
}

#[test]
fn wrong_password_ends_the_attempt_and_starts_again_later() {
    let mut s = Session::new(settings(b"wrong"), 1);
    let mut ac = Ac::new(AcAuth::Pap);
    let events = start(&mut s, &mut ac, 0);
    assert_eq!(events, [Event::Failed(Reason::AuthFailed)]);
    assert!(s.up().is_none());
    // LCP Terminate-Request, then (after the Terminate-Ack) a PADT.
    let tail: Vec<_> = ac.seen.iter().rev().take(2).copied().collect();
    assert_eq!(
        tail,
        [(0, pado::PADT), (protocol::LCP, code::TERMINATE_REQUEST)]
    );
    // It starts again with a PADI after the wait, which doubles.
    assert_eq!(s.next_timer(), Some(3_000));
    ac.seen.clear();
    let events = start(&mut s, &mut ac, 3_000);
    assert_eq!(ac.seen[0], (0, pado::PADI));
    assert_eq!(events, [Event::Failed(Reason::AuthFailed)]);
    assert_eq!(s.next_timer(), Some(3_000 + 6_000));
}

#[test]
fn padt_from_the_ac_brings_the_session_down() {
    let mut s = Session::new(settings(b"secret"), 2);
    let mut ac = Ac::new(AcAuth::Chap);
    start(&mut s, &mut ac, 0);
    assert!(s.up().is_some());
    let padt = discovery::frame(HOST, AC, pado::PADT, SESSION, &[]);
    let mut out = Output::default();
    s.receive(100, FrameKind::Discovery, &padt, &mut out);
    assert_eq!(
        out.events,
        [Event::Down(SessionDown {
            reason: Reason::AcTerminated
        })]
    );
    // Nothing is sent to a session that is gone.
    assert!(out.frames.is_empty());
    assert!(s.up().is_none());
    assert_eq!(s.next_timer(), Some(3_100));
}

#[test]
fn unanswered_echoes_end_the_session_with_a_padt() {
    let mut s = Session::new(settings(b"secret"), 3);
    let mut ac = Ac::new(AcAuth::Chap);
    start(&mut s, &mut ac, 0);
    ac.answer_echo = false;
    let mut events = Vec::new();
    let mut now = 0;
    while s.up().is_some() {
        now = s.next_timer().unwrap();
        let mut out = Output::default();
        s.timeout(now, &mut out);
        events.extend(exchange(&mut s, &mut ac, now, out));
    }
    // Three Echo-Requests ten seconds apart, then down at the fourth interval.
    assert_eq!(now, 40_000);
    assert_eq!(
        events,
        [Event::Down(SessionDown {
            reason: Reason::NoEcho
        })]
    );
    assert_eq!(ac.seen.last(), Some(&(0, pado::PADT)));
}

#[test]
fn echoes_answered_keep_the_session() {
    let mut s = Session::new(settings(b"secret"), 3);
    let mut ac = Ac::new(AcAuth::Chap);
    start(&mut s, &mut ac, 0);
    for _ in 0..10 {
        let now = s.next_timer().unwrap();
        let mut out = Output::default();
        s.timeout(now, &mut out);
        assert!(exchange(&mut s, &mut ac, now, out).is_empty());
    }
    assert!(s.up().is_some());
}

#[test]
fn peer_terminate_request() {
    let mut s = Session::new(settings(b"secret"), 4);
    let mut ac = Ac::new(AcAuth::Chap);
    start(&mut s, &mut ac, 0);
    let (_, frame) = ac.session(protocol::LCP, code::TERMINATE_REQUEST, 50, &[]);
    let mut out = Output::default();
    s.receive(10, FrameKind::Control, &frame, &mut out);
    // The Terminate-Ack goes out at once; the session is down.
    assert_eq!(out.frames.len(), 1);
    assert!(s.up().is_none());
    assert_eq!(
        out.events,
        [Event::Down(SessionDown {
            reason: Reason::PeerTerminated
        })]
    );
    // After one restart period LCP finishes and the host sends a PADT.
    let mut out = Output::default();
    s.timeout(3_010, &mut out);
    assert_eq!(out.frames.len(), 1);
    assert_eq!(out.frames[0].1[15], pado::PADT);
    assert!(out.events.is_empty());
}

#[test]
fn unknown_protocol_is_protocol_rejected_and_strangers_are_ignored() {
    let mut s = Session::new(settings(b"secret"), 5);
    let mut ac = Ac::new(AcAuth::Chap);
    start(&mut s, &mut ac, 0);
    // CCP: a Protocol-Reject with the packet after the protocol.
    let (_, frame) = ac.session(0x80fd, code::CONFIGURE_REQUEST, 1, &[]);
    let mut out = Output::default();
    s.receive(1, FrameKind::Control, &frame, &mut out);
    assert_eq!(out.frames.len(), 1);
    let reply = SessionFrame::parse(&out.frames[0].1).unwrap();
    assert_eq!(reply.protocol, protocol::LCP);
    let p = ppp::Packet::parse(reply.information).unwrap();
    assert_eq!(p.code, lcp::code::PROTOCOL_REJECT);
    assert_eq!(p.data, [0x80, 0xfd, 1, 1, 0, 4]);

    // Another session ID, another source, or not to us: ignored.
    let packet = ppp::packet(code::TERMINATE_REQUEST, 1, &[]);
    for frame in [
        ppp::session_frame(HOST, AC, SESSION + 1, protocol::LCP, &packet),
        ppp::session_frame(HOST, [2, 0, 0, 0, 0, 0xad], SESSION, protocol::LCP, &packet),
        ppp::session_frame([2, 0, 0, 0, 0, 9], AC, SESSION, protocol::LCP, &packet),
    ] {
        let mut out = Output::default();
        s.receive(2, FrameKind::Control, &frame, &mut out);
        assert_eq!(out, Output::default());
    }
    assert!(s.up().is_some());
}

#[test]
fn network_packets_before_authentication_are_dropped() {
    let mut s = Session::new(settings(b"secret"), 6);
    let mut ac = Ac::new(AcAuth::Pap);
    ac.password = b"never";
    // Run up to the PAP request and keep the Nak back: no answer at all.
    let mut out = Output::default();
    s.timeout(0, &mut out);
    let mut to_ac = out.frames;
    for _ in 0..10 {
        let mut next = Vec::new();
        for (kind, frame) in to_ac.drain(..) {
            for (k, f) in ac.handle(kind, &frame) {
                let pap_answer =
                    SessionFrame::parse(&f).is_some_and(|x| x.protocol == protocol::PAP);
                if pap_answer {
                    continue;
                }
                let mut o = Output::default();
                s.receive(0, k, &f, &mut o);
                next.extend(o.frames);
            }
        }
        to_ac = next;
    }
    let (_, frame) = ac.session(
        protocol::IPCP,
        code::CONFIGURE_REQUEST,
        1,
        &[3, 6, 198, 51, 100, 1],
    );
    let mut out = Output::default();
    s.receive(1, FrameKind::Control, &frame, &mut out);
    assert!(out.frames.is_empty());
    // Nor is another control protocol answered with a Protocol-Reject yet.
    let (_, frame) = ac.session(0x80fd, code::CONFIGURE_REQUEST, 1, &[]);
    s.receive(1, FrameKind::Control, &frame, &mut out);
    assert!(out.frames.is_empty());
}

#[test]
fn sessions_on_one_interface_take_only_their_own_offers() {
    let mut a = Session::new(settings(b"secret"), 10);
    let mut b = Session::new(settings(b"secret"), 11);
    let mut out_a = Output::default();
    let mut out_b = Output::default();
    a.timeout(0, &mut out_a);
    b.timeout(0, &mut out_b);
    // The AC answers a's PADI; b ignores the offer.
    let mut ac = Ac::new(AcAuth::Chap);
    let offer = ac.handle(FrameKind::Discovery, &out_a.frames[0].1);
    let mut o = Output::default();
    b.receive(1, FrameKind::Discovery, &offer[0].1, &mut o);
    assert!(o.frames.is_empty());
    a.receive(1, FrameKind::Discovery, &offer[0].1, &mut o);
    assert_eq!(o.frames.len(), 1);
}

#[test]
fn settings_debug_hides_the_password() {
    let shown = format!("{:?}", settings(b"hunter2"));
    assert!(
        !shown.contains("hunter2") && !shown.contains("104, 117"),
        "{shown}"
    );
    assert!(shown.contains("user"), "{shown}");
}

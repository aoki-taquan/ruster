//! A WireGuard interface from the configuration file to the wire: confd reads the
//! file and writes the tables, the FE seals what is routed to the interface and sends
//! it to the peer, and opens what the peer sends. The endpoint's next hop is
//! resolved by neighd through ARP.

use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_confd::{file, Confd};
use ruster_core::wireguard::{
    decapsulate, encapsulate, AllowedPrefix, InterfaceConfig, PeerConfig, PeerState, Received,
    SessionKeys,
};
use ruster_core::{ipv4_header_checksum, IfId};
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_neighd::Neighd;
use ruster_proto::cbor::Decoder;
use ruster_proto::session::{Client, Event};
use ruster_proto::table::{Change, Key, KeyExchangeRequest, Value, WireguardSession};
use ruster_proto::task::Task;
use ruster_ribd::{Ribd, SourceSpec};

const LAN: IfId = IfId(0);
const WAN: IfId = IfId(1);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const WAN_IP: [u8; 4] = [198, 51, 100, 2];
const HOST: [u8; 4] = [192, 0, 2, 10];
const GATEWAY: [u8; 4] = [198, 51, 100, 1];
const ENDPOINT: [u8; 4] = [203, 0, 113, 9];

const FILE: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.2/24"

[[interface]]
name = "wg0"
wireguard = { listen-port = 51820, local = "198.51.100.2" }
ipv4 = "10.9.0.1/32"

[[wireguard-peer]]
interface = "wg0"
name = "branch"
endpoint = "203.0.113.9:51821"
allowed = ["10.9.0.0/16"]

[[route]]
prefix = "0.0.0.0/0"
interface = "wan"
via = "198.51.100.1"

[[route]]
prefix = "10.9.0.0/16"
interface = "wg0"
"#;

struct Router {
    fe: Fe<SimIo>,
    confd: Confd,
    ribd: Ribd,
    neighd: Neighd,
    /// The key exchange daemon's connection to confd.
    keys: Client,
    /// What the daemon got from confd.
    key_events: Vec<Event>,
}

impl Router {
    fn start() -> Self {
        let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
        let mut confd = Confd::new(file::parse(FILE).expect("the file reads"));
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writers::CONFIG).unwrap();
        confd.connect_fe(b).unwrap();

        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writers::ROUTE).unwrap();
        let mut ribd = Ribd::new(
            b,
            vec![SourceSpec {
                name: "confd".into(),
                preference: 1,
                hold_ms: 5_000,
            }],
        )
        .unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        ribd.attach_source("confd", a).unwrap();
        confd.connect_ribd(b).unwrap();

        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writers::NEIGHBOR).unwrap();
        let (fe_punt, neighd_punt) = UnixDatagram::pair().unwrap();
        fe.attach_punt(fe_punt).unwrap();
        let mut neighd = Neighd::new(b, neighd_punt).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        neighd.attach_config(a).unwrap();
        confd.connect_neighd(b).unwrap();

        let (a, b) = UnixStream::pair().unwrap();
        confd.attach_keys(a).unwrap();
        let mut keys = Client::new(b).unwrap();
        keys.observe();

        let mut router = Self {
            fe,
            confd,
            ribd,
            neighd,
            keys,
            key_events: Vec::new(),
        };
        router.settle();
        router
    }

    fn settle(&mut self) {
        for _ in 0..1_000 {
            let busy = self.fe.step(0).busy
                | self.confd.step(0).busy
                | self.ribd.step(0).busy
                | self.neighd.step(0).busy;
            let (progress, mut events) = self.keys.poll();
            self.key_events.append(&mut events);
            if !(busy | progress.busy) {
                return;
            }
        }
        panic!("the router never settled");
    }

    /// Gives confd a session, as the key exchange daemon does.
    fn give_session(&mut self, send: u8, receive: u8) {
        let change = Change::set(
            Key::WireguardSession {
                interface: "wg0".into(),
                peer: "branch".into(),
            },
            Value::WireguardSession(WireguardSession {
                send: [send; 32],
                receive: [receive; 32],
                peer_index: 22,
                local_index: 11,
            }),
        );
        self.keys.patch(&[change]).unwrap();
        self.settle();
    }

    /// Replaces the FE with a new, empty one that knows nothing of what it sealed,
    /// and connects the control processes to it again.
    fn restart_fe(&mut self) {
        self.fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
        self.settle();
        let (a, b) = UnixStream::pair().unwrap();
        self.fe.attach(a, writers::CONFIG).unwrap();
        self.confd.connect_fe(b).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        self.fe.attach(a, writers::ROUTE).unwrap();
        self.ribd.reconnect_fe(b).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        self.fe.attach(a, writers::NEIGHBOR).unwrap();
        let (fe_punt, neighd_punt) = UnixDatagram::pair().unwrap();
        self.fe.attach_punt(fe_punt).unwrap();
        self.neighd.reconnect_fe(b, neighd_punt).unwrap();
        self.settle();
    }

    fn tx(&mut self) -> Vec<(IfId, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(frame) = self.fe.io_mut().pop_tx() {
            out.push((frame.egress, frame.bytes));
        }
        out
    }

    /// Answers the ARP requests the router sent, as the gateway and the host would.
    fn answer_arp(&mut self, requests: &[(IfId, Vec<u8>)]) {
        for (port, request) in requests {
            assert_eq!(&request[12..14], &[0x08, 0x06], "an ARP frame");
            let asked: [u8; 4] = request[38..42].try_into().unwrap();
            let router_mac: [u8; 6] = request[22..28].try_into().unwrap();
            let from: [u8; 4] = request[28..32].try_into().unwrap();
            let mac = match asked {
                GATEWAY => GATEWAY_MAC,
                HOST => HOST_MAC,
                other => panic!("unexpected ARP for {other:?}"),
            };
            let mut reply = vec![0_u8; 42];
            reply[0..6].copy_from_slice(&router_mac);
            reply[6..12].copy_from_slice(&mac);
            reply[12..14].copy_from_slice(&[0x08, 0x06]);
            reply[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
            reply[22..28].copy_from_slice(&mac);
            reply[28..32].copy_from_slice(&asked);
            reply[32..38].copy_from_slice(&router_mac);
            reply[38..42].copy_from_slice(&from);
            self.fe.io_mut().inject(*port, reply);
        }
        self.settle();
    }
}

fn ipv4(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0_u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40_u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&source);
    p[16..20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&p[..20]);
    p[10..12].copy_from_slice(&checksum.to_be_bytes());
    p
}

fn frame(dst_mac: [u8; 6], src_mac: [u8; 6], packet: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(packet);
    f
}

/// The peer's end of the session.
struct Remote {
    allowed: Vec<AllowedPrefix>,
    state: Vec<PeerState>,
}

impl Remote {
    fn new() -> Self {
        let mut state = vec![PeerState::default()];
        state[0].set_keys(SessionKeys {
            send: [2; 32],
            receive: [1; 32],
            peer_index: 11,
            local_index: 22,
        });
        Self {
            allowed: vec![AllowedPrefix {
                address: [192, 0, 2, 0],
                len: 24,
            }],
            state,
        }
    }
}

#[test]
fn the_file_makes_a_router_that_seals_to_the_peer_and_opens_from_it() {
    let mut router = Router::start();
    router.give_session(1, 2);

    // Out: the first packet finds the endpoint's next hop unknown; neighd asks for it.
    let to_peer = frame(LAN_MAC, HOST_MAC, &ipv4(HOST, [10, 9, 0, 5]));
    router.fe.io_mut().inject(LAN, to_peer.clone());
    router.settle();
    let requests = router.tx();
    assert_eq!(
        requests.len(),
        1,
        "an ARP request for the gateway: {requests:?}"
    );
    assert_eq!(requests[0].0, WAN);
    router.answer_arp(&requests);
    assert!(router.tx().is_empty());
    router.fe.io_mut().inject(LAN, to_peer);
    router.settle();
    let sent = router.tx();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (egress, bytes) = &sent[0];
    assert_eq!(*egress, WAN);
    assert_eq!(&bytes[0..6], &GATEWAY_MAC);
    assert_eq!(&bytes[26..30], &WAN_IP);
    assert_eq!(&bytes[30..34], &ENDPOINT);

    let mut remote = Remote::new();
    let peers = [PeerConfig {
        endpoint: WAN_IP,
        endpoint_port: 51820,
        allowed: &remote.allowed,
    }];
    let interface = InterfaceConfig {
        local: ENDPOINT,
        listen_port: 51821,
        peers: &peers,
    };
    let mut wire = bytes[14..].to_vec();
    let Received::Data { inner, .. } =
        decapsulate(&interface, &mut remote.state, &mut wire).unwrap()
    else {
        panic!("not data")
    };
    assert_eq!(&wire[inner.start + 16..inner.start + 20], &[10, 9, 0, 5]);
    assert_eq!(wire[inner.start + 8], 63);

    // In: the peer sends to the LAN host; the host's MAC is resolved the same way.
    let mut out = vec![0_u8; 14 + 28 + 16 + 64 + 16];
    let packet = ipv4([10, 9, 0, 7], HOST);
    let (_, len) = encapsulate(&interface, &mut remote.state, &packet, &mut out[14..]).unwrap();
    out.truncate(14 + len);
    out[0..6].copy_from_slice(&WAN_MAC);
    out[6..12].copy_from_slice(&GATEWAY_MAC);
    out[12..14].copy_from_slice(&[0x08, 0x00]);
    router.fe.io_mut().inject(WAN, out);
    router.settle();
    let requests = router.tx();
    assert_eq!(
        requests.len(),
        1,
        "an ARP request for the host: {requests:?}"
    );
    assert_eq!(requests[0].0, LAN);
    router.answer_arp(&requests);

    let mut again = vec![0_u8; 14 + 28 + 16 + 64 + 16];
    let (_, len) = encapsulate(&interface, &mut remote.state, &packet, &mut again[14..]).unwrap();
    again.truncate(14 + len);
    again[0..6].copy_from_slice(&WAN_MAC);
    again[6..12].copy_from_slice(&GATEWAY_MAC);
    again[12..14].copy_from_slice(&[0x08, 0x00]);
    router.fe.io_mut().inject(WAN, again);
    router.settle();
    let forwarded = router.tx();
    assert_eq!(forwarded.len(), 1, "{forwarded:?}");
    assert_eq!(forwarded[0].0, LAN);
    assert_eq!(&forwarded[0].1[0..6], &HOST_MAC);
    assert_eq!(&forwarded[0].1[26..30], &[10, 9, 0, 7]);
}

/// Makes the FE resolve the gateway, with the packet that asks for it dropped.
fn resolve_gateway(router: &mut Router, packet: &[u8]) {
    router.fe.io_mut().inject(LAN, packet.to_vec());
    router.settle();
    let requests = router.tx();
    router.answer_arp(&requests);
}

/// The key exchange requests that reached the daemon.
fn asked(router: &mut Router) -> Vec<KeyExchangeRequest> {
    std::mem::take(&mut router.key_events)
        .into_iter()
        .filter_map(|event| match event {
            Event::Notification { payload } => {
                KeyExchangeRequest::decode(&mut Decoder::new(&payload)).ok()
            }
            _ => None,
        })
        .collect()
}

fn branch() -> KeyExchangeRequest {
    KeyExchangeRequest {
        interface: "wg0".into(),
        peer: "branch".into(),
    }
}

#[test]
fn a_peer_without_a_session_makes_the_fe_ask_the_daemon_for_a_key_exchange() {
    let mut router = Router::start();
    let to_peer = frame(LAN_MAC, HOST_MAC, &ipv4(HOST, [10, 9, 0, 5]));
    resolve_gateway(&mut router, &to_peer);
    assert!(asked(&mut router).is_empty());

    // Now it is the session that is missing: the FE tells confd, once, and confd
    // tells the daemon.
    for _ in 0..3 {
        router.fe.io_mut().inject(LAN, to_peer.clone());
    }
    router.settle();
    assert!(router.tx().is_empty(), "nothing is sent without a session");
    assert_eq!(asked(&mut router), [branch()]);
    assert_eq!(router.fe.counters().key_exchange_requests, 1);
    assert_eq!(router.confd.take_key_exchange_requests(), [branch()]);

    // The daemon's session makes it go.
    router.give_session(1, 2);
    router.fe.io_mut().inject(LAN, to_peer);
    router.settle();
    assert_eq!(router.tx().len(), 1);
}

#[test]
fn a_restarted_fe_does_not_get_the_old_session_and_never_seals_with_its_counters() {
    let mut router = Router::start();
    router.give_session(1, 2);
    let to_peer = frame(LAN_MAC, HOST_MAC, &ipv4(HOST, [10, 9, 0, 5]));
    resolve_gateway(&mut router, &to_peer);
    router.fe.io_mut().inject(LAN, to_peer.clone());
    router.settle();
    let first = router.tx();
    assert_eq!(first.len(), 1, "sealed with the session");

    // The FE starts again: its counter is gone. It must not seal with that key.
    router.restart_fe();
    resolve_gateway(&mut router, &to_peer);
    router.fe.io_mut().inject(LAN, to_peer.clone());
    router.settle();
    assert!(router.tx().is_empty(), "the old session is not used");
    assert_eq!(asked(&mut router), [branch()]);

    // Even if the daemon repeats the same session.
    router.give_session(1, 2);
    router.fe.io_mut().inject(LAN, to_peer.clone());
    router.settle();
    assert!(router.tx().is_empty(), "the same key stays unused");

    // A new session works, from counter 0 with a new key.
    router.give_session(3, 4);
    router.fe.io_mut().inject(LAN, to_peer);
    router.settle();
    let sent = router.tx();
    assert_eq!(sent.len(), 1);
    let counter = &sent[0].1[14 + 28 + 8..14 + 28 + 16];
    assert_eq!(counter, 0_u64.to_le_bytes());
}

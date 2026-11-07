//! WireGuard data messages arriving at the router: opened, and the packet inside
//! forwarded like any packet that arrived on the WireGuard interface.

use ruster_core::wireguard::{
    decapsulate, encapsulate, execute_one_wireguard_send, AllowedPrefix, InterfaceConfig,
    PeerConfig, PeerState, SessionKeys, WireguardInterface, WireguardSendRuntime,
    WireguardStagedFrame,
};
use ruster_core::{
    forward_batch_with_control, internet_checksum, ipv4_header_checksum, ControlQueue, DropReason,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress, Neighbor,
    PacketIo, Route, Services, TraceEvent, TraceSink,
};
use ruster_io_sim::SimIo;

const WAN: IfId = IfId(0);
const LAN: IfId = IfId(1);
const WG: IfId = IfId(2);

const ROUTER: [u8; 4] = [192, 0, 2, 1];
const PEER: [u8; 4] = [198, 51, 100, 7];

fn mac(last: u8) -> MacAddress {
    MacAddress([2, 0, 0, 0, 0, last])
}

fn a(octets: [u8; 4]) -> Ipv4Address {
    Ipv4Address::from_octets(octets)
}

#[derive(Default)]
struct Drops(Vec<DropReason>);

impl TraceSink for Drops {
    fn record(&mut self, event: TraceEvent) {
        if let TraceEvent::Dropped { reason, .. } = event {
            self.0.push(reason);
        }
    }
}

fn inner_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 48];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&48u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&source);
    p[16..20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&p[..20]);
    p[10..12].copy_from_slice(&checksum.to_be_bytes());
    p
}

/// The peer's end: a frame to the router carrying `inner` sealed with counter
/// `index` of its session.
struct Peer {
    config_allowed: Vec<AllowedPrefix>,
    state: Vec<PeerState>,
}

impl Peer {
    fn new() -> Self {
        let mut state = vec![PeerState::default()];
        state[0].set_keys(SessionKeys {
            send: [1; 32],
            receive: [2; 32],
            peer_index: 11,
            local_index: 22,
        });
        Self {
            config_allowed: vec![AllowedPrefix {
                address: [10, 2, 0, 0],
                len: 16,
            }],
            state,
        }
    }

    fn frame(&mut self, inner: &[u8]) -> Vec<u8> {
        let peers = [PeerConfig {
            endpoint: ROUTER,
            endpoint_port: 51820,
            allowed: &self.config_allowed,
        }];
        let interface = InterfaceConfig {
            local: PEER,
            listen_port: 51820,
            peers: &peers,
        };
        let mut out = vec![0u8; 14 + 28 + 16 + 96 + 16];
        let (_, len) = encapsulate(&interface, &mut self.state, inner, &mut out[14..]).unwrap();
        out.truncate(14 + len);
        out[0..6].copy_from_slice(&mac(1).0);
        out[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 0x99]);
        out[12..14].copy_from_slice(&[0x08, 0x00]);
        out
    }
}

fn run(frames: Vec<Vec<u8>>) -> (SimIo, Drops, Vec<PeerState>) {
    run_on(frames.into_iter().map(|f| (WAN, f)).collect(), None)
}

fn run_on(
    frames: Vec<(IfId, Vec<u8>)>,
    send: Option<&mut WireguardSendRuntime<'_>>,
) -> (SimIo, Drops, Vec<PeerState>) {
    let interfaces = [
        Interface {
            id: WAN,
            mac: mac(1),
            mtu: 1500,
        },
        Interface {
            id: LAN,
            mac: mac(2),
            mtu: 1500,
        },
        Interface {
            id: WG,
            mac: mac(3),
            mtu: 1420,
        },
    ];
    let neighbors = [
        Neighbor {
            interface: LAN,
            target: a([10, 2, 0, 5]),
            mac: mac(0x55),
        },
        Neighbor {
            interface: WAN,
            target: a(PEER),
            mac: mac(0x77),
        },
    ];
    let routes = [
        Route::new(a([10, 2, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(a([10, 1, 0, 0]), 16, WG, None).unwrap(),
        Route::new(a([198, 51, 100, 0]), 24, WAN, None).unwrap(),
    ];
    let bindings = [LocalIpv4Binding {
        interface: WAN,
        address: a(ROUTER),
    }];
    let allowed = [AllowedPrefix {
        address: [10, 1, 0, 0],
        len: 16,
    }];
    let peers = [PeerConfig {
        endpoint: PEER,
        endpoint_port: 51820,
        allowed: &allowed,
    }];
    let wireguard = [WireguardInterface {
        interface: WG,
        config: InterfaceConfig {
            local: ROUTER,
            listen_port: 51820,
            peers: &peers,
        },
        first_peer: 0,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .unwrap()
        .with_wireguard(&wireguard);
    let mut states = vec![PeerState::default()];
    states[0].set_keys(SessionKeys {
        send: [2; 32],
        receive: [1; 32],
        peer_index: 22,
        local_index: 11,
    });
    let mut io = SimIo::new();
    for (port, frame) in frames {
        io.inject(port, frame);
    }
    let mut drops = Drops::default();
    let mut queue = ControlQueue::new(4);
    let batch = io.receive(16).unwrap();
    let services = Services {
        wireguard: Some(&mut states),
        wireguard_send: send,
        ..Services::default()
    };
    forward_batch_with_control(batch, &snapshot, &mut queue, services, &mut drops);
    (io, drops, states)
}

#[test]
fn a_data_message_is_opened_and_its_packet_forwarded() {
    let inner = inner_packet([10, 1, 0, 9], [10, 2, 0, 5]);
    let mut peer = Peer::new();
    let (mut io, drops, _) = run(vec![peer.frame(&inner)]);
    assert!(drops.0.is_empty(), "{:?}", drops.0);
    let tx = io.pop_tx().expect("forwarded");
    assert_eq!(tx.egress, LAN);
    assert_eq!(&tx.bytes[0..6], &mac(0x55).0);
    assert_eq!(&tx.bytes[6..12], &mac(2).0);
    assert_eq!(&tx.bytes[12..14], &[0x08, 0x00]);
    // The inner packet, one hop on: TTL 63, a valid header checksum, nothing after
    // it (the padding and the tag are cut).
    assert_eq!(tx.bytes.len(), 14 + 48);
    assert_eq!(tx.bytes[22], 63);
    assert_eq!(internet_checksum(&tx.bytes[14..34]), 0);
    assert_eq!(&tx.bytes[26..34], &inner[12..20]);
    assert_eq!(&tx.bytes[34..], &inner[20..]);
}

#[test]
fn a_replayed_forged_or_foreign_message_is_dropped() {
    let inner = inner_packet([10, 1, 0, 9], [10, 2, 0, 5]);
    let mut peer = Peer::new();
    let good = peer.frame(&inner);
    let mut forged = peer.frame(&inner);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let (mut io, drops, _) = run(vec![good.clone(), good, forged]);
    assert!(io.pop_tx().is_some());
    assert!(io.pop_tx().is_none());
    assert_eq!(
        drops.0,
        [
            DropReason::WireguardReplay,
            DropReason::WireguardAuthentication
        ]
    );

    // From an address that is not the peer's endpoint.
    let mut peer = Peer::new();
    let mut spoofed = peer.frame(&inner);
    spoofed[14 + 12..14 + 16].copy_from_slice(&[203, 0, 113, 1]);
    spoofed[14 + 10..14 + 12].fill(0);
    let sum = ipv4_header_checksum(&spoofed[14..34]);
    spoofed[14 + 10..14 + 12].copy_from_slice(&sum.to_be_bytes());
    let (mut io, drops, _) = run(vec![spoofed]);
    assert!(io.pop_tx().is_none());
    assert_eq!(drops.0, [DropReason::WireguardWrongEndpoint]);
}

#[test]
fn an_inner_source_outside_the_allowed_addresses_is_dropped() {
    let inner = inner_packet([172, 16, 0, 9], [10, 2, 0, 5]);
    let mut peer = Peer::new();
    peer.config_allowed = vec![AllowedPrefix {
        address: [0, 0, 0, 0],
        len: 0,
    }];
    let (mut io, drops, _) = run(vec![peer.frame(&inner)]);
    assert!(io.pop_tx().is_none());
    assert_eq!(drops.0, [DropReason::WireguardNotAllowed]);
}

#[test]
fn a_keepalive_is_taken_and_a_handshake_goes_on_as_local_traffic() {
    let mut peer = Peer::new();
    // Built by hand: the sender's keepalive is an empty sealed message.
    let mut keepalive = peer.frame(&inner_packet([10, 1, 0, 9], [10, 2, 0, 5]));
    keepalive.truncate(14 + 28 + 32);
    ruster_core::wireguard::seal(&[1; 32], 11, 7, &mut keepalive[14 + 28..], 0).unwrap();
    let total = (keepalive.len() - 14) as u16;
    keepalive[16..18].copy_from_slice(&total.to_be_bytes());
    keepalive[14 + 24..14 + 26].copy_from_slice(&(total - 20).to_be_bytes());
    keepalive[24..26].fill(0);
    let sum = ipv4_header_checksum(&keepalive[14..34]);
    keepalive[24..26].copy_from_slice(&sum.to_be_bytes());
    let (mut io, drops, _) = run(vec![keepalive]);
    assert!(io.pop_tx().is_none());
    assert_eq!(drops.0, [DropReason::WireguardKeepalive]);

    let mut handshake = peer.frame(&inner_packet([10, 1, 0, 9], [10, 2, 0, 5]));
    handshake[14 + 28] = 1;
    let (mut io, drops, _) = run(vec![handshake]);
    assert!(io.pop_tx().is_none());
    assert!(
        !drops
            .0
            .iter()
            .any(|r| format!("{r:?}").starts_with("Wireguard")),
        "{:?}",
        drops.0
    );
}

fn lan_frame(destination: [u8; 4]) -> Vec<u8> {
    let inner = inner_packet([10, 2, 0, 5], destination);
    let mut frame = vec![0u8; 14];
    frame[0..6].copy_from_slice(&mac(2).0);
    frame[6..12].copy_from_slice(&mac(0x55).0);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&inner);
    frame
}

#[test]
fn a_packet_routed_to_the_interface_is_sealed_and_sent_to_the_peer() {
    let mut slots = [WireguardStagedFrame::default(); 4];
    let mut bytes = [0u8; 4 * 256];
    let mut runtime = WireguardSendRuntime::new(&mut slots, &mut bytes).unwrap();
    let (mut io, drops, _) = run_on(vec![(LAN, lan_frame([10, 1, 0, 9]))], Some(&mut runtime));
    assert!(drops.0.is_empty(), "{:?}", drops.0);
    assert!(
        io.pop_tx().is_none(),
        "nothing leaves before the staged frame is sent"
    );
    assert_eq!(runtime.pending(), 1);

    let mut budget = 8;
    let report = execute_one_wireguard_send(&mut io, &mut runtime, &mut budget).unwrap();
    assert!(report.sent);
    assert_eq!(budget, 7);
    assert!(execute_one_wireguard_send(&mut io, &mut runtime, &mut budget).is_none());
    let tx = io.pop_tx().expect("sent");
    assert_eq!(tx.egress, WAN);
    assert_eq!(&tx.bytes[0..6], &mac(0x77).0);
    assert_eq!(&tx.bytes[6..12], &mac(1).0);
    assert_eq!(&tx.bytes[12..14], &[0x08, 0x00]);
    // Outer IPv4: router to peer, UDP, a valid header.
    assert_eq!(&tx.bytes[26..30], &ROUTER);
    assert_eq!(&tx.bytes[30..34], &PEER);
    assert_eq!(tx.bytes[23], 17);
    assert_eq!(internet_checksum(&tx.bytes[14..34]), 0);

    // The peer opens it and finds the packet, one hop on.
    let mut peer = Peer::new();
    let allowed = [AllowedPrefix {
        address: [10, 2, 0, 0],
        len: 16,
    }];
    let peers = [PeerConfig {
        endpoint: ROUTER,
        endpoint_port: 51820,
        allowed: &allowed,
    }];
    let interface = InterfaceConfig {
        local: PEER,
        listen_port: 51820,
        peers: &peers,
    };
    let mut wire = tx.bytes[14..].to_vec();
    let received = decapsulate(&interface, &mut peer.state, &mut wire).unwrap();
    let ruster_core::wireguard::Received::Data { inner, .. } = received else {
        panic!("{received:?}")
    };
    let want = inner_packet([10, 2, 0, 5], [10, 1, 0, 9]);
    assert_eq!(wire[inner.clone()][..8], want[..8]);
    assert_eq!(wire[inner.start + 8], 63);
    assert_eq!(wire[inner.start + 12..inner.end], want[12..]);
}

#[test]
fn without_a_session_a_runtime_or_room_the_packet_is_dropped() {
    // No send runtime.
    let (mut io, drops, _) = run_on(vec![(LAN, lan_frame([10, 1, 0, 9]))], None);
    assert!(io.pop_tx().is_none());
    assert_eq!(drops.0, [DropReason::WireguardNoSession]);

    // A full staging area.
    let mut slots = [WireguardStagedFrame::default(); 1];
    let mut bytes = [0u8; 256];
    let mut runtime = WireguardSendRuntime::new(&mut slots, &mut bytes).unwrap();
    let frames = vec![
        (LAN, lan_frame([10, 1, 0, 9])),
        (LAN, lan_frame([10, 1, 0, 10])),
    ];
    let (_, drops, _) = run_on(frames, Some(&mut runtime));
    assert_eq!(drops.0, [DropReason::WireguardQueueFull]);
    assert_eq!(runtime.pending(), 1);

    // The over-budget frame is dropped, not sent.
    let mut io = SimIo::new();
    let mut budget = 0;
    let report = execute_one_wireguard_send(&mut io, &mut runtime, &mut budget).unwrap();
    assert!(!report.sent && report.completion.is_none());
    assert_eq!(runtime.counters().dropped_over_budget, 1);
    assert!(io.pop_tx().is_none());
}

#[test]
fn the_staging_storage_must_be_equal_slots_that_fit_a_frame() {
    let mut slots = [WireguardStagedFrame::default(); 2];
    let mut odd = [0u8; 2 * 256 + 1];
    assert!(WireguardSendRuntime::new(&mut slots, &mut odd).is_err());
    let mut small = [0u8; 2 * 40];
    assert!(WireguardSendRuntime::new(&mut slots, &mut small).is_err());
}

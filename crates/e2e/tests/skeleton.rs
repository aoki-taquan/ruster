//! The skeleton end to end (docs/design/implementation-plan.md, 段階1 1-11).
//!
//! The FE, confd, ribd and neighd are connected over Unix sockets as separate processes
//! would be, and run on one runner in a fixed order. IPv4 crosses the router in both
//! directions, every next hop resolved by neighd through ARP. Then each control process
//! is stopped and started again, alone and all together, while packets keep flowing.

use std::net::Ipv4Addr;
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_confd::{Confd, Config, InterfaceConfig, PeerKind, RouteTarget, StaticRoute};
use ruster_core::{ipv4_header_checksum, IfId};
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_neighd::Neighd;
use ruster_proto::table::Key;
use ruster_proto::task::Task;
use ruster_ribd::{Ribd, SourceSpec};

const LAN: IfId = IfId(0);
const WAN: IfId = IfId(1);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const LAN_IP: [u8; 4] = [192, 0, 2, 1];
const WAN_IP: [u8; 4] = [198, 51, 100, 2];
const HOST: [u8; 4] = [192, 0, 2, 10];
const GATEWAY: [u8; 4] = [198, 51, 100, 1];
const INTERNET: [u8; 4] = [203, 0, 113, 7];

fn config() -> Config {
    Config {
        interfaces: vec![
            InterfaceConfig {
                name: "lan".into(),
                mac: LAN_MAC,
                mtu: 1500,
                enabled: true,
                ipv4: Some((Ipv4Addr::from(LAN_IP), 24)),
                ipv6: Vec::new(),
                vrf: "default".into(),
                vlan: None,
                tunnel: None,
                pppoe: None,
                ipv4_from: None,
                ipv6_from: None,
            },
            InterfaceConfig {
                name: "wan".into(),
                mac: WAN_MAC,
                mtu: 1500,
                enabled: true,
                ipv4: Some((Ipv4Addr::from(WAN_IP), 24)),
                ipv6: Vec::new(),
                vrf: "default".into(),
                vlan: None,
                tunnel: None,
                pppoe: None,
                ipv4_from: None,
                ipv6_from: None,
            },
        ],
        static_routes: vec![StaticRoute {
            vrf: "default".into(),
            prefix: Ipv4Addr::UNSPECIFIED.into(),
            len: 0,
            target: RouteTarget::Next {
                interface: "wan".into(),
                via: Some(Ipv4Addr::from(GATEWAY).into()),
            },
        }],
        firewall: Vec::new(),
        firewall_filtering: Default::default(),
        firewall_outside: None,
        icmp_errors: None,
        nat: None,
        dns: None,
        dhcp: Vec::new(),
        dhcp6: Vec::new(),
        ra: Vec::new(),
        sources: Vec::new(),
        pppoe: Vec::new(),
        dhcp_client: Vec::new(),
        map_e_from: None,
        dns_found: Vec::new(),
        bgp: None,
    }
}

/// The router: the FE always runs; the control processes come and go.
struct Router {
    fe: Fe<SimIo>,
    confd: Option<Confd>,
    ribd: Option<Ribd>,
    neighd: Option<Neighd>,
    /// The configuration confd starts with.
    config: Config,
    now: u64,
}

impl Router {
    fn new() -> Self {
        Self {
            fe: Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]),
            confd: None,
            ribd: None,
            neighd: None,
            config: config(),
            now: 0,
        }
    }

    /// Starts the processes in the order systemd would.
    fn start_all(&mut self) {
        self.start_confd();
        self.start_ribd();
        self.start_neighd();
        self.settle();
    }

    fn start_confd(&mut self) {
        let mut confd = Confd::new(self.config.clone());
        let (fe_end, confd_end) = UnixStream::pair().unwrap();
        self.fe.attach(fe_end, writers::CONFIG).unwrap();
        confd.connect_fe(confd_end).unwrap();
        if let Some(ribd) = &mut self.ribd {
            let (a, b) = UnixStream::pair().unwrap();
            ribd.attach_source("confd", a).unwrap();
            confd.connect_ribd(b).unwrap();
        }
        if let Some(neighd) = &mut self.neighd {
            let (a, b) = UnixStream::pair().unwrap();
            neighd.attach_config(a).unwrap();
            confd.connect_neighd(b).unwrap();
        }
        self.confd = Some(confd);
    }

    fn start_ribd(&mut self) {
        let (fe_end, ribd_end) = UnixStream::pair().unwrap();
        self.fe.attach(fe_end, writers::ROUTE).unwrap();
        let mut ribd = Ribd::new(
            ribd_end,
            vec![SourceSpec {
                name: "confd".into(),
                preference: 1,
                hold_ms: 5_000,
            }],
        )
        .unwrap();
        if let Some(confd) = &mut self.confd {
            let (a, b) = UnixStream::pair().unwrap();
            ribd.attach_source("confd", a).unwrap();
            confd.connect_ribd(b).unwrap();
        }
        self.ribd = Some(ribd);
    }

    fn start_neighd(&mut self) {
        let (fe_end, neighd_end) = UnixStream::pair().unwrap();
        self.fe.attach(fe_end, writers::NEIGHBOR).unwrap();
        let (fe_punt, neighd_punt) = UnixDatagram::pair().unwrap();
        self.fe.attach_punt(fe_punt).unwrap();
        let mut neighd = Neighd::new(neighd_end, neighd_punt).unwrap();
        if let Some(confd) = &mut self.confd {
            let (a, b) = UnixStream::pair().unwrap();
            neighd.attach_config(a).unwrap();
            confd.connect_neighd(b).unwrap();
        }
        self.neighd = Some(neighd);
    }

    /// Replaces the FE with a new, empty one, and lets each control process notice
    /// its closed connection and connect again, as their programs do.
    fn restart_fe(&mut self) {
        self.fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
        self.settle();
        if let Some(confd) = &mut self.confd {
            assert_eq!(confd.closed(), vec![PeerKind::Fe]);
            let (fe_end, confd_end) = UnixStream::pair().unwrap();
            self.fe.attach(fe_end, writers::CONFIG).unwrap();
            confd.connect_fe(confd_end).unwrap();
        }
        if let Some(ribd) = &mut self.ribd {
            assert!(ribd.fe_closed());
            let (fe_end, ribd_end) = UnixStream::pair().unwrap();
            self.fe.attach(fe_end, writers::ROUTE).unwrap();
            ribd.reconnect_fe(ribd_end).unwrap();
        }
        if let Some(neighd) = &mut self.neighd {
            assert!(neighd.fe_closed());
            let (fe_end, neighd_end) = UnixStream::pair().unwrap();
            self.fe.attach(fe_end, writers::NEIGHBOR).unwrap();
            let (fe_punt, neighd_punt) = UnixDatagram::pair().unwrap();
            self.fe.attach_punt(fe_punt).unwrap();
            neighd.reconnect_fe(neighd_end, neighd_punt).unwrap();
        }
        self.settle();
    }

    /// Steps everything that runs until nothing is busy.
    fn settle(&mut self) {
        for _ in 0..1_000 {
            let mut busy = self.fe.step(self.now).busy;
            if let Some(confd) = &mut self.confd {
                busy |= confd.step(self.now).busy;
            }
            if let Some(ribd) = &mut self.ribd {
                busy |= ribd.step(self.now).busy;
            }
            if let Some(neighd) = &mut self.neighd {
                busy |= neighd.step(self.now).busy;
            }
            if !busy {
                return;
            }
        }
        panic!("the router never settled");
    }

    /// The frames sent, without neighd's probes and announcements of the router's
    /// own addresses (RFC 5227), which go out whenever an address appears.
    fn tx(&mut self) -> Vec<(IfId, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(frame) = self.fe.io_mut().pop_tx() {
            let bytes = &frame.bytes;
            let claim = bytes.get(12..14) == Some(&[0x08, 0x06][..])
                && bytes.len() >= 42
                && (bytes[28..32] == [0; 4] || bytes[28..32] == bytes[38..42]);
            if !claim {
                out.push((frame.egress, frame.bytes));
            }
        }
        out
    }

    /// Sends one packet each way through the FE alone (no control process stepped)
    /// and checks both were forwarded to the right neighbor.
    fn assert_forwards(&mut self) {
        self.fe.io_mut().inject(LAN, outbound());
        self.fe.io_mut().inject(WAN, inbound());
        self.fe.step(self.now);
        let tx = self.tx();
        assert_eq!(tx.len(), 2, "both packets forwarded: {tx:?}");
        let out = tx
            .iter()
            .find(|(egress, _)| *egress == WAN)
            .expect("outbound");
        assert_eq!(&out.1[0..6], &GATEWAY_MAC);
        assert_eq!(&out.1[6..12], &WAN_MAC);
        let back = tx
            .iter()
            .find(|(egress, _)| *egress == LAN)
            .expect("inbound");
        assert_eq!(&back.1[0..6], &HOST_MAC);
        assert_eq!(&back.1[6..12], &LAN_MAC);
    }
}

fn udp(dst_mac: [u8; 6], src_mac: [u8; 6], source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&46_u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 17;
    frame[ip + 12..ip + 16].copy_from_slice(&source);
    frame[ip + 16..ip + 20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    frame[ip + 24..ip + 26].copy_from_slice(&26_u16.to_be_bytes());
    frame
}

/// From the LAN host to the internet.
fn outbound() -> Vec<u8> {
    udp(LAN_MAC, HOST_MAC, HOST, INTERNET)
}

/// From the internet back to the LAN host, through the WAN gateway.
fn inbound() -> Vec<u8> {
    udp(WAN_MAC, GATEWAY_MAC, INTERNET, HOST)
}

fn arp_reply(sender_mac: [u8; 6], sender: [u8; 4], to_mac: [u8; 6], to: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 42];
    frame[0..6].copy_from_slice(&to_mac);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&2_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender);
    frame[32..38].copy_from_slice(&to_mac);
    frame[38..42].copy_from_slice(&to);
    frame
}

/// Answers an ARP request the router sent, as the asked host would.
fn answer(router: &mut Router, request: &[u8]) {
    assert_eq!(&request[12..14], &0x0806_u16.to_be_bytes(), "an ARP frame");
    assert_eq!(&request[20..22], &1_u16.to_be_bytes(), "a request");
    let asked: [u8; 4] = request[38..42].try_into().unwrap();
    let from: [u8; 4] = request[28..32].try_into().unwrap();
    let router_mac: [u8; 6] = request[22..28].try_into().unwrap();
    let (port, mac) = match asked {
        GATEWAY => (WAN, GATEWAY_MAC),
        HOST => (LAN, HOST_MAC),
        other => panic!("unexpected ARP for {other:?}"),
    };
    router
        .fe
        .io_mut()
        .inject(port, arp_reply(mac, asked, router_mac, from));
}

/// Starts the router and resolves both next hops through neighd.
fn running_router() -> Router {
    let mut router = Router::new();
    router.start_all();

    // Nothing is known yet: both packets are held back and neighd asks for both
    // next hops.
    router.fe.io_mut().inject(LAN, outbound());
    router.fe.io_mut().inject(WAN, inbound());
    router.settle();
    let requests = router.tx();
    assert_eq!(
        requests.len(),
        2,
        "one ARP request per next hop: {requests:?}"
    );
    for (egress, request) in &requests {
        let asked: [u8; 4] = request[38..42].try_into().unwrap();
        assert_eq!(*egress, if asked == GATEWAY { WAN } else { LAN });
        answer(&mut router, request);
    }
    router.settle();
    assert!(router.tx().is_empty(), "the replies are consumed");

    router.assert_forwards();
    router
}

#[test]
fn ipv4_crosses_the_router_both_ways() {
    running_router();
}

#[test]
fn forwarding_does_not_stop_when_confd_restarts() {
    let mut router = running_router();
    router.confd = None;
    router.settle();
    router.assert_forwards();
    router.start_confd();
    router.assert_forwards();
    router.settle();
    router.assert_forwards();
}

#[test]
fn forwarding_does_not_stop_when_ribd_restarts() {
    let mut router = running_router();
    router.ribd = None;
    router.settle();
    router.assert_forwards();
    router.start_ribd();
    router.assert_forwards();
    router.settle();
    router.assert_forwards();
    assert!(
        router.ribd.as_ref().unwrap().synced(),
        "confd said sync-done"
    );
}

#[test]
fn forwarding_does_not_stop_when_neighd_restarts() {
    let mut router = running_router();
    router.neighd = None;
    router.settle();
    router.assert_forwards();
    router.start_neighd();
    router.assert_forwards();
    router.settle();
    router.assert_forwards();
    assert_eq!(
        router.neighd.as_ref().unwrap().counters().adopted,
        2,
        "the new neighd kept both neighbors"
    );
    assert_eq!(
        router.neighd.as_ref().unwrap().counters().requests_sent,
        0,
        "nothing had to be resolved again"
    );
}

#[test]
fn forwarding_does_not_stop_when_every_control_process_restarts_at_once() {
    let mut router = running_router();
    router.confd = None;
    router.ribd = None;
    router.neighd = None;
    for now in 1..=10 {
        router.now = now;
        router.settle();
        router.assert_forwards();
    }
    router.start_confd();
    router.assert_forwards();
    router.start_ribd();
    router.assert_forwards();
    router.start_neighd();
    router.assert_forwards();
    router.settle();
    router.assert_forwards();
}

#[test]
fn configuration_changes_still_apply_after_restarts() {
    let mut router = running_router();
    router.confd = None;
    router.ribd = None;
    router.settle();
    router.start_ribd();
    router.start_confd();
    router.settle();

    // A new static route, sent after both restarts.
    let mut config = router.config.clone();
    config.static_routes.push(StaticRoute {
        vrf: "default".into(),
        prefix: Ipv4Addr::new(10, 99, 0, 0).into(),
        len: 16,
        target: RouteTarget::Next {
            interface: "lan".into(),
            via: Some(Ipv4Addr::from(HOST).into()),
        },
    });
    router.confd.as_mut().unwrap().set_config(config);
    router.settle();
    router
        .fe
        .io_mut()
        .inject(WAN, udp(WAN_MAC, GATEWAY_MAC, INTERNET, [10, 99, 1, 1]));
    router.fe.step(router.now);
    let tx = router.tx();
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].0, LAN);
    assert_eq!(&tx[0].1[0..6], &HOST_MAC);

    // A confd that restarts without the route removes it everywhere.
    router.confd = None;
    router.settle();
    router.start_confd();
    router.settle();
    router
        .fe
        .io_mut()
        .inject(WAN, udp(WAN_MAC, GATEWAY_MAC, INTERNET, [10, 99, 1, 1]));
    router.fe.step(router.now);
    let tx = router.tx();
    assert!(
        tx.iter().all(|(egress, _)| *egress == WAN),
        "10.99/16 now follows the default route back out: {tx:?}"
    );
    router.assert_forwards();
}

#[test]
fn a_restarted_fe_is_filled_again_by_the_control_processes() {
    let mut router = running_router();
    let requests = router.neighd.as_ref().unwrap().counters().requests_sent;
    router.restart_fe();
    router.assert_forwards();
    assert_eq!(
        router.neighd.as_ref().unwrap().counters().requests_sent,
        requests,
        "neighd gave the new FE the neighbors it knew"
    );
    assert!(
        router.fe.store().len() >= 7,
        "interfaces, addresses, routes and neighbors"
    );
}

#[test]
fn routes_removed_while_the_fe_was_down_are_gone_from_the_new_fe() {
    let mut router = running_router();
    let routes_before = router
        .fe
        .store()
        .iter()
        .filter(|(key, _)| matches!(key, Key::Route { .. }))
        .count();
    router.fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut config = router.config.clone();
    config.static_routes.clear();
    router.confd.as_mut().unwrap().set_config(config);
    router.restart_fe();
    let routes_after = router
        .fe
        .store()
        .iter()
        .filter(|(key, _)| matches!(key, Key::Route { .. }))
        .count();
    assert_eq!(
        routes_after,
        routes_before - 1,
        "only the static route is gone"
    );
}

fn has(router: &Router, key: &Key) -> bool {
    router.fe.store().get(key).is_some()
}

#[test]
fn a_restarted_ribd_removes_the_routes_dropped_while_it_was_down() {
    let mut router = running_router();
    let default_route = Key::Route {
        vrf: "default".into(),
        prefix: Ipv4Addr::UNSPECIFIED.into(),
        len: 0,
    };
    let lan_route = Key::Route {
        vrf: "default".into(),
        prefix: Ipv4Addr::new(192, 0, 2, 0).into(),
        len: 24,
    };
    assert!(has(&router, &default_route));

    // The FE keeps its tables; only ribd's connection goes. The static route is
    // removed while ribd is down.
    router.ribd = None;
    router.settle();
    let mut config = router.config.clone();
    config.static_routes.clear();
    router.confd.as_mut().unwrap().set_config(config);
    router.settle();
    assert!(has(&router, &default_route), "kept while ribd is down");

    router.start_ribd();
    router.settle();
    assert!(!has(&router, &default_route), "resync-end removed it");
    assert!(has(&router, &lan_route), "what was sent again stays");
}

#[test]
fn a_restarted_confd_removes_what_its_new_configuration_left_out() {
    let mut router = running_router();
    let address = |ip: [u8; 4]| Key::Address {
        interface: "wan".into(),
        address: Ipv4Addr::from(ip).into(),
    };
    assert!(has(&router, &address(WAN_IP)));

    // The FE keeps its tables; confd starts again with another WAN address.
    router.confd = None;
    router.settle();
    router.config.interfaces[1].ipv4 = Some((Ipv4Addr::new(198, 51, 100, 3), 24));
    router.start_confd();
    router.settle();
    assert!(!has(&router, &address(WAN_IP)), "resync-end removed it");
    assert!(has(&router, &address([198, 51, 100, 3])));
    assert!(has(&router, &Key::Interface { name: "lan".into() }));
}

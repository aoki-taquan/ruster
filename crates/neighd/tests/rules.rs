//! neighd's learning and input rules, against a stand-in FE whose sockets the test holds.

use std::net::Ipv4Addr;
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_neighd::Neighd;
use ruster_proto::cbor::Encoder;
use ruster_proto::punt::{self, Direction, Punt};
use ruster_proto::session::{Client, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, ResolveRequest, Value};
use ruster_proto::task::Task;

const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const LAN_IP: [u8; 4] = [192, 0, 2, 1];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];

struct Accept;
impl Hook for Accept {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
}

struct Lab {
    fe: Server,
    fe_punt: UnixDatagram,
    neighd: Neighd,
    confd: Client,
    now: u64,
}

impl Lab {
    fn new() -> Self {
        let mut fe = Server::new();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::NEIGHBOR]).unwrap();
        let (fe_punt, neighd_punt) = UnixDatagram::pair().unwrap();
        fe_punt.set_nonblocking(true).unwrap();
        let mut neighd = Neighd::new(b, neighd_punt).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        neighd.attach_config(a).unwrap();
        let mut confd = Client::new(b).unwrap();
        confd
            .patch(&[
                Change::set(
                    Key::Interface { name: "lan".into() },
                    Value::Interface {
                        enabled: true,
                        mac: LAN_MAC,
                        mtu: 1500,
                    },
                ),
                Change::set(
                    Key::Address {
                        interface: "lan".into(),
                        address: Ipv4Addr::from(LAN_IP).into(),
                    },
                    Value::Address { prefix_len: 24 },
                ),
            ])
            .unwrap();
        let mut lab = Self {
            fe,
            fe_punt,
            neighd,
            confd,
            now: 0,
        };
        lab.settle(true);
        lab
    }

    fn settle(&mut self, step_fe: bool) {
        for _ in 0..1_000 {
            let mut busy = false;
            if step_fe {
                busy |= self.fe.step(&mut Accept).busy;
            }
            busy |= self.neighd.step(self.now).busy;
            busy |= self.confd.poll().0.busy;
            if !busy {
                return;
            }
        }
        panic!("never settled");
    }

    fn arp_in(&mut self, body: &[u8]) {
        let mut message = Vec::new();
        Punt {
            direction: Direction::ToControl,
            reason: punt::reason::ARP,
            interface: "lan",
            frame: body,
        }
        .encode(&mut message)
        .unwrap();
        self.fe_punt.send(&message).unwrap();
        self.settle(true);
    }

    fn frames_out(&self) -> usize {
        let mut buf = [0_u8; 512];
        let mut count = 0;
        while self.fe_punt.recv(&mut buf).is_ok() {
            count += 1;
        }
        count
    }
}

fn body(opcode: u16, sender_mac: [u8; 6], sender: [u8; 4], target: [u8; 4]) -> Vec<u8> {
    let mut body = vec![0, 1, 8, 0, 6, 4];
    body.extend_from_slice(&opcode.to_be_bytes());
    body.extend_from_slice(&sender_mac);
    body.extend_from_slice(&sender);
    body.extend_from_slice(&[0; 6]);
    body.extend_from_slice(&target);
    body
}

#[test]
fn a_request_for_us_from_an_on_link_host_is_learned_and_answered() {
    let mut lab = Lab::new();
    lab.arp_in(&body(1, HOST_MAC, [192, 0, 2, 10], LAN_IP));
    assert_eq!(lab.neighd.counters().learned, 1);
    assert_eq!(lab.frames_out(), 1);
    assert_eq!(lab.fe.store().len(), 1);
}

#[test]
fn packets_not_for_us_from_unknown_hosts_are_not_learned() {
    // RFC 826 adds a sender only when we are the target (request or reply).
    let mut lab = Lab::new();
    lab.arp_in(&body(2, HOST_MAC, [192, 0, 2, 10], [192, 0, 2, 99]));
    lab.arp_in(&body(1, HOST_MAC, [192, 0, 2, 10], [192, 0, 2, 99]));
    assert_eq!(lab.neighd.known(), 0);
    assert_eq!(lab.frames_out(), 0);
}

#[test]
fn senders_that_cannot_be_neighbors_are_not_learned() {
    let mut lab = Lab::new();
    for sender in [[10, 0, 0, 1], [192, 0, 2, 0], [192, 0, 2, 255], LAN_IP] {
        lab.arp_in(&body(1, HOST_MAC, sender, LAN_IP));
    }
    assert_eq!(lab.neighd.known(), 0);
    assert!(lab.fe.store().is_empty());
    // RFC 826 answers any asker; only one claiming our own address is not answered.
    assert_eq!(lab.frames_out(), 3);
    assert_eq!(lab.neighd.counters().not_learned, 4);
}

#[test]
fn malformed_bodies_are_counted_and_ignored() {
    let mut lab = Lab::new();
    let mut wrong_type = body(1, HOST_MAC, [192, 0, 2, 10], LAN_IP);
    wrong_type[1] = 6;
    let bad_opcode = body(3, HOST_MAC, [192, 0, 2, 10], LAN_IP);
    let multicast_sender = body(1, [1, 0, 0x5e, 0, 0, 1], [192, 0, 2, 10], LAN_IP);
    let zero_sender = body(1, [0; 6], [192, 0, 2, 10], LAN_IP);
    let short = vec![0, 1, 8, 0, 6, 4, 0, 1];
    for bad in [wrong_type, bad_opcode, multicast_sender, zero_sender, short] {
        lab.arp_in(&bad);
    }
    assert_eq!(lab.neighd.counters().bad_punts, 5);
    assert_eq!(lab.neighd.known(), 0);
    assert_eq!(lab.frames_out(), 0);
}

#[test]
fn a_silent_fe_does_not_stop_neighd_from_serving_resolve_requests() {
    let mut fe = Server::new();
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::NEIGHBOR]).unwrap();
    let (fe_punt, neighd_punt) = UnixDatagram::pair().unwrap();
    fe_punt.set_nonblocking(true).unwrap();
    let mut neighd = Neighd::new(b, neighd_punt).unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    neighd.attach_config(a).unwrap();
    let mut confd = Client::new(b).unwrap();
    confd
        .patch(&[
            Change::set(
                Key::Interface { name: "lan".into() },
                Value::Interface {
                    enabled: true,
                    mac: LAN_MAC,
                    mtu: 1500,
                },
            ),
            Change::set(
                Key::Address {
                    interface: "lan".into(),
                    address: Ipv4Addr::from(LAN_IP).into(),
                },
                Value::Address { prefix_len: 24 },
            ),
        ])
        .unwrap();
    // The FE does not answer the start-up GET for a while.
    for now in [0, 500, 1_000] {
        for _ in 0..10 {
            neighd.step(now);
            confd.poll();
        }
    }
    // Now it runs; neighd registered for notifications without the GET answer.
    for _ in 0..20 {
        fe.step(&mut Accept);
        neighd.step(1_000);
    }
    let mut payload = Vec::new();
    ResolveRequest {
        interface: "lan".into(),
        address: Ipv4Addr::new(192, 0, 2, 20).into(),
    }
    .encode(&mut Encoder::new(&mut payload));
    fe.notify(&payload);
    for _ in 0..20 {
        fe.step(&mut Accept);
        neighd.step(1_000);
    }
    assert_eq!(neighd.counters().requests_sent, 1);
}

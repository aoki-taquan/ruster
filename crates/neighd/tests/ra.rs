//! Router Advertisements: neighd with a real FE over Unix sockets, packets through
//! `SimIo`.

use std::net::{IpAddr, Ipv6Addr};
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_core::IfId;
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_neighd::Neighd;
use ruster_proto::session::Client;
use ruster_proto::table::{Change, Key, Value};
use ruster_proto::task::Task;

const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];

fn ip(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

fn tables(lan_enabled: bool) -> Vec<Change> {
    let iface = |name: &str, mac, enabled| {
        Change::set(
            Key::Interface { name: name.into() },
            Value::Interface {
                enabled,
                mac,
                mtu: 1500,
                vrf: ruster_proto::table::DEFAULT_VRF.into(),
                vlan: None,
                tunnel: None,
                pppoe: None,
            },
        )
    };
    let address = |name: &str, address: &str| {
        Change::set(
            Key::Address {
                interface: name.into(),
                address: IpAddr::V6(ip(address)),
            },
            Value::Address { prefix_len: 64 },
        )
    };
    vec![
        iface("lan", LAN_MAC, lan_enabled),
        iface("wan", WAN_MAC, true),
        address("lan", "2001:db8:1::1"),
        address("lan", "fe80::1"),
        address("wan", "fe80::2"),
    ]
}

/// The `ra` part for lan, as confd puts it.
fn part(lan: bool) -> String {
    let text = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
"#;
    let with = if lan {
        format!("{text}\n[[ra]]\ninterface = \"lan\"\n")
    } else {
        text.to_owned()
    };
    ruster_config::ra_part(&ruster_config::resolve(&with).unwrap().ra)
}

struct Lab {
    fe: Fe<SimIo>,
    neighd: Neighd,
    fe_config: Client,
    confd: Client,
    now: u64,
}

impl Lab {
    fn new() -> Self {
        let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writers::CONFIG).unwrap();
        let mut fe_config = Client::new(b).unwrap();
        fe_config.patch(&tables(true)).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writers::NEIGHBOR).unwrap();
        let (fe_punt, neighd_punt) = UnixDatagram::pair().unwrap();
        fe.attach_punt(fe_punt).unwrap();
        let mut neighd = Neighd::new(b, neighd_punt).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        neighd.attach_config(a).unwrap();
        let mut confd = Client::new(b).unwrap();
        confd.patch(&tables(true)).unwrap();
        let mut lab = Self {
            fe,
            neighd,
            fe_config,
            confd,
            now: 0,
        };
        lab.settle();
        lab
    }

    fn settle(&mut self) {
        for _ in 0..1_000 {
            let mut busy = self.fe.step(self.now).busy;
            busy |= self.neighd.step(self.now).busy;
            busy |= self.fe_config.poll().0.busy;
            busy |= self.confd.poll().0.busy;
            if !busy {
                return;
            }
        }
        panic!("never settled");
    }

    /// Moves the clock on to `to`, a quarter of a second at a time.
    fn run_to(&mut self, to: u64) {
        while self.now < to {
            self.now = (self.now + 250).min(to);
            self.settle();
        }
    }

    /// The Router Advertisements sent since last asked: egress and frame.
    fn advertisements(&mut self) -> Vec<(IfId, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(frame) = self.fe.io_mut().pop_tx() {
            if frame.bytes.len() > 54 && frame.bytes[54] == 134 {
                out.push((frame.egress, frame.bytes));
            }
        }
        out
    }
}

fn router_lifetime(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[54 + 6], frame[54 + 7]])
}

/// A Router Solicitation from the host's link-local address, with its link-layer
/// address.
fn solicitation() -> Vec<u8> {
    let source = ip("fe80::10");
    let all_routers = ip("ff02::2");
    let mut icmp = vec![133, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    icmp.extend_from_slice(&HOST_MAC);
    let mut sum: u32 = 0;
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&all_routers.octets());
    pseudo.extend_from_slice(&u32::try_from(icmp.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&icmp);
    for pair in pseudo.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    icmp[2..4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    let mut frame = vec![0x33, 0x33, 0, 0, 0, 2];
    frame.extend_from_slice(&HOST_MAC);
    frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(icmp.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[58, 255]);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&all_routers.octets());
    frame.extend_from_slice(&icmp);
    frame
}

#[test]
fn an_advertising_interface_sends_unsolicited_and_solicited_ones_and_then_final_ones() {
    let mut lab = Lab::new();
    lab.neighd.take_ra(&part(true)).unwrap();
    lab.settle();
    let first = lab.advertisements();
    assert_eq!(first.len(), 1, "the first goes at once");
    let (egress, frame) = &first[0];
    assert_eq!(*egress, IfId(0), "on lan only");
    assert_eq!(&frame[0..6], &[0x33, 0x33, 0, 0, 0, 1]);
    assert_eq!(&frame[6..12], &LAN_MAC);
    assert_eq!(&frame[22..38], &ip("fe80::1").octets(), "from link-local");
    assert_eq!(&frame[38..54], &ip("ff02::1").octets());
    assert_eq!(router_lifetime(frame), 1_800);
    assert!(
        frame.windows(16).any(|w| w == ip("2001:db8:1::").octets()),
        "the prefix"
    );

    // The next two within 16 s each.
    lab.run_to(16_000);
    assert_eq!(lab.advertisements().len(), 1);
    lab.run_to(32_000);
    assert_eq!(lab.advertisements().len(), 1);

    // A solicitation is answered within 500 ms (3 s after the last one at most).
    lab.run_to(40_000);
    lab.advertisements();
    lab.fe.io_mut().inject(IfId(0), solicitation());
    lab.settle();
    lab.run_to(40_500);
    assert_eq!(lab.advertisements().len(), 1, "answered");
    assert_eq!(lab.neighd.counters().router_solicitations, 1);
    assert_eq!(lab.neighd.known(), 1, "the soliciting host is learned");
    // A second at once waits for 3 s after that answer.
    lab.fe.io_mut().inject(IfId(0), solicitation());
    lab.settle();
    lab.run_to(42_500);
    assert!(lab.advertisements().is_empty(), "not within 3 s");
    lab.run_to(44_000);
    assert_eq!(lab.advertisements().len(), 1);

    // Stopping: three final ones with a router lifetime of 0, then nothing.
    lab.neighd.take_ra(&part(false)).unwrap();
    lab.run_to(60_000);
    let last = lab.advertisements();
    assert_eq!(last.len(), 3);
    assert!(last.iter().all(|(_, f)| router_lifetime(f) == 0));
    lab.run_to(120_000);
    assert!(lab.advertisements().is_empty());
}

#[test]
fn an_interface_without_ra_or_disabled_sends_none() {
    let mut lab = Lab::new();
    lab.fe.io_mut().inject(IfId(0), solicitation());
    lab.settle();
    lab.run_to(5_000);
    assert!(lab.advertisements().is_empty());
    assert_eq!(lab.neighd.counters().not_for_neighd, 1);

    // Disabled, it does not advertise, and sends no final one when it leaves the
    // part; enabled again, it starts.
    lab.confd.patch(&tables(false)).unwrap();
    lab.settle();
    lab.neighd.take_ra(&part(true)).unwrap();
    lab.run_to(10_000);
    assert!(lab.advertisements().is_empty());
    lab.confd.patch(&tables(true)).unwrap();
    lab.run_to(11_000);
    assert_eq!(lab.advertisements().len(), 1);
    assert!(lab.neighd.take_ra("version = 1\nra = 3\n").is_err());
    // Intervals that would flood the link are refused, and so is an interface twice.
    let good = part(true);
    for bad in [
        good.replace("max-interval = 600", "max-interval = 0"),
        good.replace("min-interval = 198", "min-interval = 0"),
        format!("{good}\n{}", &good[good.find("[[ra]]").unwrap()..]),
    ] {
        assert!(lab.neighd.take_ra(&bad).is_err(), "{bad}");
    }
}

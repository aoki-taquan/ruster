//! VLAN sub-interfaces (`ForwardingSnapshot::with_vlans`).

use ruster_core::{
    forward_batch, ipv4_header_checksum, DropReason, ForwardingSnapshot, IfId, Interface,
    Ipv4Address, LocalIpv4Binding, MacAddress, Neighbor, PacketIo, Route, TraceEvent, TraceSink,
    VlanBinding,
};
use ruster_io_sim::SimIo;

const TRUNK: IfId = IfId(0);
const UPLINK: IfId = IfId(1);
/// VLAN 10 on the trunk.
const VLAN10: IfId = IfId(2);

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

fn udp(dst_mac: MacAddress, source: [u8; 4], destination: [u8; 4], vid: Option<u16>) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&dst_mac.0);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 0x99]);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&46_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source);
    frame[30..34].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    if let Some(vid) = vid {
        let mut tagged = frame[..12].to_vec();
        tagged.extend_from_slice(&[0x81, 0x00]);
        tagged.extend_from_slice(&vid.to_be_bytes());
        tagged.extend_from_slice(&frame[12..]);
        frame = tagged;
    }
    frame
}

fn run(frames: Vec<(IfId, Vec<u8>)>) -> (SimIo, Drops) {
    let interfaces = [
        Interface {
            id: TRUNK,
            mac: mac(1),
            mtu: 1500,
        },
        Interface {
            id: UPLINK,
            mac: mac(2),
            mtu: 1500,
        },
        Interface {
            id: VLAN10,
            mac: mac(1),
            mtu: 1500,
        },
    ];
    let neighbors = [
        Neighbor {
            interface: VLAN10,
            target: a([10, 10, 0, 5]),
            mac: mac(0x55),
        },
        Neighbor {
            interface: UPLINK,
            target: a([198, 51, 100, 1]),
            mac: mac(0x66),
        },
    ];
    let routes = [
        Route::new(a([10, 10, 0, 0]), 24, VLAN10, None).unwrap(),
        Route::new(a([0, 0, 0, 0]), 0, UPLINK, Some(a([198, 51, 100, 1]))).unwrap(),
    ];
    let bindings: [LocalIpv4Binding; 0] = [];
    let vlans = [VlanBinding {
        parent: TRUNK,
        vid: 10,
        sub: VLAN10,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .unwrap()
        .with_vlans(&vlans);
    let mut io = SimIo::new();
    for (port, frame) in frames {
        io.inject(port, frame);
    }
    let mut drops = Drops::default();
    let batch = io.receive(16).unwrap();
    forward_batch(batch, &snapshot, &mut drops);
    (io, drops)
}

#[test]
fn a_tagged_frame_arrives_on_its_sub_interface_and_leaves_untagged() {
    let (mut io, drops) = run(vec![(
        TRUNK,
        udp(mac(1), [10, 10, 0, 5], [203, 0, 113, 7], Some(10)),
    )]);
    assert!(drops.0.is_empty(), "{:?}", drops.0);
    let tx = io.pop_tx().expect("forwarded");
    assert_eq!(tx.egress, UPLINK);
    assert_eq!(&tx.bytes[0..6], &mac(0x66).0);
    assert_eq!(&tx.bytes[12..14], &[0x08, 0x00], "no tag");
    assert_eq!(tx.bytes.len(), 60);
}

#[test]
fn a_frame_to_a_sub_interface_leaves_its_parent_tagged() {
    let (mut io, drops) = run(vec![(
        UPLINK,
        udp(mac(2), [203, 0, 113, 7], [10, 10, 0, 5], None),
    )]);
    assert!(drops.0.is_empty(), "{:?}", drops.0);
    let tx = io.pop_tx().expect("forwarded");
    assert_eq!(tx.egress, TRUNK);
    assert_eq!(&tx.bytes[0..6], &mac(0x55).0);
    assert_eq!(&tx.bytes[6..12], &mac(1).0);
    assert_eq!(&tx.bytes[12..16], &[0x81, 0x00, 0x00, 0x0a], "VLAN 10");
    assert_eq!(&tx.bytes[16..18], &[0x08, 0x00]);
    assert_eq!(tx.bytes.len(), 64);
}

#[test]
fn an_unknown_vlan_is_dropped() {
    let (mut io, drops) = run(vec![(
        TRUNK,
        udp(mac(1), [10, 10, 0, 5], [203, 0, 113, 7], Some(20)),
    )]);
    assert!(io.pop_tx().is_none());
    assert_eq!(drops.0, [DropReason::VlanUnknown]);
}

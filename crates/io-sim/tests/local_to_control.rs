//! Traffic addressed to the router handed to the control side whole
//! (`ForwardingSnapshot::with_local_to_control`).

use ruster_core::{
    forward_batch_with_control, ipv4_header_checksum, ConsumeReason, ControlKind, ControlQueue,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, Ipv6Fib, Ipv6Local, LocalIpv4Binding,
    MacAddress, NoTrace, PacketIo,
};
use ruster_io_sim::{RecycleCause, SimIo};

const LAN: IfId = IfId(0);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];

fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0_u8; 34];
    frame[0..6].copy_from_slice(&LAN_MAC);
    frame[6..12].copy_from_slice(&HOST_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    let total = u16::try_from(20 + payload.len()).unwrap();
    frame[16..18].copy_from_slice(&total.to_be_bytes());
    frame[22] = 64;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&[192, 0, 2, 10]);
    frame[30..34].copy_from_slice(&[192, 0, 2, 1]);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn echo_request() -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0, 1, 0, 1];
    let sum = ruster_core::internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv4(1, &icmp)
}

fn ipv6_to_router() -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&LAN_MAC);
    frame.extend_from_slice(&HOST_MAC);
    frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0, 0, 8, 17, 64]);
    frame.extend_from_slice(
        &"2001:db8::10"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame.extend_from_slice(&[0; 8]);
    frame
}

fn run(local_to_control: bool, frames: &[Vec<u8>]) -> (SimIo, ControlQueue) {
    let interfaces = [Interface {
        id: LAN,
        mac: MacAddress(LAN_MAC),
        mtu: 1500,
    }];
    let bindings = [LocalIpv4Binding {
        interface: LAN,
        address: Ipv4Address::from_octets([192, 0, 2, 1]),
    }];
    let fib = Ipv6Fib::new(
        vec![],
        vec![],
        vec![Ipv6Local {
            interface: LAN,
            address: "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        }],
    )
    .unwrap();
    let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &bindings)
        .unwrap()
        .with_ipv6(&fib)
        .with_local_to_control(local_to_control);
    let mut io = SimIo::new();
    for frame in frames {
        io.inject(LAN, frame.clone());
    }
    let mut queue = ControlQueue::new(8);
    let batch = io.receive(16).unwrap();
    forward_batch_with_control(batch, &snapshot, &mut queue, None, &mut NoTrace);
    (io, queue)
}

#[test]
fn traffic_to_the_router_goes_to_the_control_queue_unanswered() {
    let tcp_syn = ipv4(6, &[0; 20]);
    let frames = [tcp_syn, echo_request(), ipv6_to_router()];
    let (mut io, queue) = run(true, &frames);
    assert!(io.pop_tx().is_none(), "no Echo Reply from core");
    let got: Vec<_> = queue
        .frames()
        .iter()
        .map(|f| (f.kind, f.ingress, f.bytes().to_vec()))
        .collect();
    let expected: Vec<_> = frames
        .iter()
        .map(|f| (ControlKind::Local, LAN, f.clone()))
        .collect();
    assert_eq!(got, expected);
    for _ in 0..3 {
        assert_eq!(
            io.pop_recycled().map(|frame| frame.cause),
            Some(RecycleCause::Consumed(ConsumeReason::LocalToControl))
        );
    }
}

#[test]
fn without_the_switch_core_answers_echo_itself() {
    let (mut io, queue) = run(false, &[echo_request()]);
    assert!(queue.frames().is_empty());
    let reply = io.pop_tx().expect("Echo Reply");
    assert_eq!(reply.bytes[34], 0);
}

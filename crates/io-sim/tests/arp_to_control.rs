//! ARP handed to the control side (`ForwardingSnapshot::with_arp_to_control`).

use ruster_core::{
    ArpOpcode, ConsumeReason, ForwardingSnapshot, IfId, Interface, Ipv4Address, LocalIpv4Binding,
    MacAddress, Route, TraceEvent, TraceSink,
};
use ruster_io_sim::{RecycleCause, SimIo};

const LAN: IfId = IfId(0);
const LOCAL: [u8; 4] = [192, 0, 2, 1];
const HOST: [u8; 4] = [192, 0, 2, 10];
const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x10];

#[derive(Default)]
struct Recorder(Vec<TraceEvent>);

impl TraceSink for Recorder {
    fn record(&mut self, event: TraceEvent) {
        if matches!(event, TraceEvent::ArpToControl { .. }) {
            self.0.push(event);
        }
    }
}

fn arp(opcode: u16, sender_hardware: [u8; 6], target: [u8; 4]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 42];
    bytes[0..6].copy_from_slice(&[0xff; 6]);
    bytes[6..12].copy_from_slice(&sender_hardware);
    bytes[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    bytes[14..16].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[18] = 6;
    bytes[19] = 4;
    bytes[20..22].copy_from_slice(&opcode.to_be_bytes());
    bytes[22..28].copy_from_slice(&sender_hardware);
    bytes[28..32].copy_from_slice(&HOST);
    bytes[38..42].copy_from_slice(&target);
    bytes
}

fn tables() -> ([Route; 1], [Interface; 1], [LocalIpv4Binding; 1]) {
    (
        [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap()],
        [Interface {
            id: LAN,
            mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
            mtu: 1500,
        }],
        [LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets(LOCAL),
        }],
    )
}

#[test]
fn request_for_a_local_address_goes_to_control_without_a_reply() {
    let (routes, interfaces, bindings) = tables();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings)
        .unwrap()
        .with_arp_to_control(true);
    let mut io = SimIo::new();
    io.inject(LAN, arp(1, HOST_MAC, LOCAL));
    let mut trace = Recorder::default();
    let report = io.run_once(8, &snapshot, &mut trace).unwrap();

    assert_eq!(io.pending_tx(), 0, "the control side answers, not core");
    assert_eq!(report.consumed, 1);
    assert_eq!(
        io.pop_recycled().map(|frame| frame.cause),
        Some(RecycleCause::Consumed(ConsumeReason::ArpControl))
    );
    assert_eq!(
        trace.0,
        [TraceEvent::ArpToControl {
            ingress: LAN,
            opcode: ArpOpcode::Request,
            sender_hardware: MacAddress(HOST_MAC),
            sender_protocol: Ipv4Address::from_octets(HOST),
            target_protocol: Ipv4Address::from_octets(LOCAL),
        }]
    );
}

#[test]
fn replies_and_foreign_requests_go_to_control_too() {
    let (routes, interfaces, bindings) = tables();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings)
        .unwrap()
        .with_arp_to_control(true);
    let mut io = SimIo::new();
    io.inject(LAN, arp(2, HOST_MAC, LOCAL));
    io.inject(LAN, arp(1, HOST_MAC, [192, 0, 2, 99]));
    let mut trace = Recorder::default();
    io.run_once(8, &snapshot, &mut trace).unwrap();
    assert_eq!(trace.0.len(), 2);
    assert_eq!(io.pending_tx(), 0);
}

#[test]
fn invalid_senders_are_still_dropped_in_core() {
    let (routes, interfaces, bindings) = tables();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings)
        .unwrap()
        .with_arp_to_control(true);
    let mut io = SimIo::new();
    io.inject(LAN, arp(1, [0xff; 6], LOCAL));
    let mut trace = Recorder::default();
    io.run_once(8, &snapshot, &mut trace).unwrap();
    assert!(trace.0.is_empty());
}

#[test]
fn without_the_switch_core_still_replies() {
    let (routes, interfaces, bindings) = tables();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut io = SimIo::new();
    io.inject(LAN, arp(1, HOST_MAC, LOCAL));
    let mut trace = Recorder::default();
    io.run_once(8, &snapshot, &mut trace).unwrap();
    assert!(trace.0.is_empty());
    assert_eq!(io.pending_tx(), 1);
}

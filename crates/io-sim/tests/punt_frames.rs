//! Frames for the control side picked out before forwarding
//! (`ForwardingSnapshot::with_punt_frames`).

use ruster_core::{
    forward_batch_with_control, ConsumeReason, ControlKind, ControlQueue, ForwardingSnapshot, IfId,
    Interface, MacAddress, NoTrace, PacketIo, PppoeSession, PuntFrameKind, PuntFrameMatch,
    Services,
};
use ruster_io_sim::{RecycleCause, SimIo};

const WAN: IfId = IfId(0);
const SESSION: IfId = IfId(1);
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xac];

/// A PPPoE session frame of session 7 from the peer, with PPP protocol `protocol`.
fn session_frame(protocol: u16) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 8 + 20];
    frame[0..6].copy_from_slice(&WAN_MAC);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&[0x88, 0x64]);
    frame[14] = 0x11;
    frame[16..18].copy_from_slice(&7_u16.to_be_bytes());
    frame[18..20].copy_from_slice(&22_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&protocol.to_be_bytes());
    frame
}

fn run(frames: &[Vec<u8>], capacity: usize) -> (SimIo, ControlQueue) {
    let interfaces = [
        Interface {
            id: WAN,
            mac: MacAddress(WAN_MAC),
            mtu: 1500,
        },
        Interface {
            id: SESSION,
            mac: MacAddress(WAN_MAC),
            mtu: 1492,
        },
    ];
    let sessions = [PppoeSession {
        interface: SESSION,
        parent: WAN,
        session: 7,
        peer: MacAddress(PEER_MAC),
    }];
    let punt = [
        PuntFrameMatch {
            ingress: Some(WAN),
            kind: PuntFrameKind::PppoeDiscovery,
            class: 20,
        },
        PuntFrameMatch {
            ingress: Some(WAN),
            kind: PuntFrameKind::PppControl,
            class: 21,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &[])
        .unwrap()
        .with_pppoe(&sessions)
        .with_punt_frames(&punt);
    let mut io = SimIo::new();
    for frame in frames {
        io.inject(WAN, frame.clone());
    }
    let mut queue = ControlQueue::new(capacity);
    let batch = io.receive(16).unwrap();
    forward_batch_with_control(
        batch,
        &snapshot,
        &mut queue,
        Services::default(),
        &mut NoTrace,
    );
    (io, queue)
}

#[test]
fn pppoe_control_goes_to_the_control_queue_and_session_data_does_not() {
    let mut padi = vec![0xff_u8; 6];
    padi.extend_from_slice(&PEER_MAC);
    padi.extend_from_slice(&[0x88, 0x63, 0x11, 0x09, 0, 0, 0, 0]);
    let lcp = session_frame(0xc021);
    // An LCP frame of a session not set up yet is the daemon's too.
    let mut unknown = session_frame(0xc021);
    unknown[16..18].copy_from_slice(&9_u16.to_be_bytes());
    let data = session_frame(0x0021);
    let (mut io, queue) = run(&[padi.clone(), lcp.clone(), unknown.clone(), data], 8);
    let got: Vec<_> = queue
        .frames()
        .iter()
        .map(|f| (f.kind, f.ingress, f.bytes().to_vec()))
        .collect();
    assert_eq!(
        got,
        [
            (ControlKind::Punt(20), WAN, padi),
            (ControlKind::Punt(21), WAN, lcp),
            (ControlKind::Punt(21), WAN, unknown),
        ]
    );
    for _ in 0..3 {
        assert_eq!(
            io.pop_recycled().map(|frame| frame.cause),
            Some(RecycleCause::Consumed(ConsumeReason::PuntToControl))
        );
    }
    // The IPv4 data frame went on as a session's packet, not to the queue.
    assert!(!matches!(
        io.pop_recycled().map(|frame| frame.cause),
        Some(RecycleCause::Consumed(ConsumeReason::PuntToControl))
    ));
}

#[test]
fn a_full_control_queue_drops_the_frame() {
    let (mut io, queue) = run(&[session_frame(0xc021), session_frame(0xc023)], 1);
    assert_eq!(queue.frames().len(), 1);
    assert_eq!(
        io.pop_recycled().map(|frame| frame.cause),
        Some(RecycleCause::Consumed(ConsumeReason::PuntToControl))
    );
    assert!(matches!(
        io.pop_recycled().map(|frame| frame.cause),
        Some(RecycleCause::Forwarding(
            ruster_core::DropReason::Ipv6ControlQueueFull
        ))
    ));
}

//! Packets the router's own stack sends through the kernel's interface
//! (`docs/design/fe-ce-split.md`, "IPの通信: kernelは内側のホスト"): forwarded like a
//! host's, but their TTL and Hop Limit stay, the router's addresses are valid sources,
//! and errors about them go back to the kernel's interface.

use ruster_core::{
    execute_one_icmpv4_error, forward_batch_with_control, ipv4_header_checksum, ControlQueue,
    DropReason, ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime,
    Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, Ipv6Fib, Ipv6Local, Ipv6Neighbor,
    Ipv6Route, LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, NoGeneratedIcmpv4Trace,
    NoTrace, PacketIo, Route, Services,
};
use ruster_io_sim::{RecycleCause, SimIo};

const WAN: IfId = IfId(0);
const KERNEL: IfId = IfId(1);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const KERNEL_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xfe]);
/// The source MAC address of frames made from the kernel's packets.
const STACK_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xff]);
const GATEWAY_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x10]);
const ROUTER: [u8; 4] = [198, 51, 100, 2];
const GATEWAY: [u8; 4] = [198, 51, 100, 1];
const REMOTE: [u8; 4] = [203, 0, 113, 7];
const WAN_MTU: u16 = 1400;

fn ip6(text: &str) -> [u8; 16] {
    text.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

/// A UDP datagram of `len` IP bytes from the kernel, with DF set.
fn ipv4(source: [u8; 4], ttl: u8, len: usize) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + len];
    frame[0..6].copy_from_slice(&KERNEL_MAC.0);
    frame[6..12].copy_from_slice(&STACK_MAC.0);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    frame[20] = 0x40;
    frame[22] = ttl;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source);
    frame[30..34].copy_from_slice(&REMOTE);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[38..40].copy_from_slice(&u16::try_from(len - 20).unwrap().to_be_bytes());
    frame
}

/// A UDP datagram of `len` IP bytes from the kernel's IPv6 address.
fn ipv6(hop_limit: u8, len: usize) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + len];
    frame[0..6].copy_from_slice(&KERNEL_MAC.0);
    frame[6..12].copy_from_slice(&STACK_MAC.0);
    frame[12..14].copy_from_slice(&[0x86, 0xdd]);
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&u16::try_from(len - 40).unwrap().to_be_bytes());
    frame[20] = 17;
    frame[21] = hop_limit;
    frame[22..38].copy_from_slice(&ip6("2001:db8:1::2"));
    frame[38..54].copy_from_slice(&ip6("2001:db8:ff::7"));
    frame
}

struct Tables {
    interfaces: [Interface; 2],
    routes: [Route; 2],
    neighbors: [Neighbor; 1],
    bindings: [LocalIpv4Binding; 1],
    ipv6: Ipv6Fib,
}

fn tables() -> Tables {
    let a = Ipv4Address::from_octets;
    Tables {
        interfaces: [(WAN, WAN_MAC, WAN_MTU), (KERNEL, KERNEL_MAC, 1500)]
            .map(|(id, mac, mtu)| Interface { id, mac, mtu }),
        routes: [
            Route::new(a([198, 51, 100, 0]), 24, WAN, None).unwrap(),
            Route::new(a([0, 0, 0, 0]), 0, WAN, Some(a(GATEWAY))).unwrap(),
        ],
        neighbors: [Neighbor {
            interface: WAN,
            target: a(GATEWAY),
            mac: GATEWAY_MAC,
        }],
        bindings: [LocalIpv4Binding {
            interface: WAN,
            address: a(ROUTER),
        }],
        ipv6: Ipv6Fib::new(
            vec![
                Ipv6Route::new(ip6("2001:db8:1::"), 64, WAN, None).unwrap(),
                Ipv6Route::new(ip6("::"), 0, WAN, Some(ip6("2001:db8:1::1"))).unwrap(),
            ],
            vec![Ipv6Neighbor {
                interface: WAN,
                target: ip6("2001:db8:1::1"),
                mac: GATEWAY_MAC,
            }],
            vec![Ipv6Local {
                interface: WAN,
                address: ip6("2001:db8:1::2"),
            }],
        )
        .unwrap(),
    }
}

/// Forwards one frame from `ingress`; returns what was sent, the drop reasons
/// and the ICMPv6 errors queued.
struct Run {
    sent: Option<(IfId, Vec<u8>)>,
    icmpv4: Option<(IfId, Vec<u8>)>,
    icmpv6: Vec<(IfId, Vec<u8>)>,
    dropped: Vec<DropReason>,
}

fn run(tables: &Tables, kernel: bool, frame: Vec<u8>) -> Run {
    let kernel_ingress = [KERNEL];
    let snapshot = ForwardingSnapshot::new(
        &tables.routes,
        &tables.interfaces,
        &tables.neighbors,
        &tables.bindings,
    )
    .unwrap()
    .with_ipv6(&tables.ipv6)
    .with_kernel_ingress(if kernel { &kernel_ingress } else { &[] })
    .with_now(MonotonicMillis(1));
    let mut states = [Icmpv4ErrorStateSlot::EMPTY; 4];
    let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 4];
    let mut errors =
        Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(KERNEL, frame);
    let batch = io.receive(1).unwrap();
    let mut control = ControlQueue::new(4).with_icmpv6_errors(4);
    control.set_clock(MonotonicMillis(1));
    forward_batch_with_control(
        batch,
        &snapshot,
        &mut control,
        Services {
            icmpv4_errors: Some(&mut errors),
            ..Services::default()
        },
        &mut NoTrace,
    );
    let sent = io.pop_tx().map(|tx| (tx.egress, tx.bytes));
    let mut dropped = Vec::new();
    while let Some(recycled) = io.pop_recycled() {
        if let RecycleCause::Forwarding(reason) = recycled.cause {
            dropped.push(reason);
        }
    }
    let _ = execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(1),
        &mut NoGeneratedIcmpv4Trace,
    );
    let icmpv4 = io.pop_tx().map(|tx| (tx.egress, tx.bytes));
    let icmpv6 = control
        .errors()
        .iter()
        .map(|e| (e.ingress, e.bytes().to_vec()))
        .collect();
    Run {
        sent,
        icmpv4,
        icmpv6,
        dropped,
    }
}

#[test]
fn the_router_s_own_ipv4_keeps_its_ttl() {
    for ttl in [255, 64, 1] {
        let run = run(&tables(), true, ipv4(ROUTER, ttl, 28));
        let (egress, frame) = run.sent.expect("sent");
        assert_eq!(egress, WAN);
        assert_eq!(&frame[0..6], &GATEWAY_MAC.0);
        assert_eq!(&frame[6..12], &WAN_MAC.0);
        assert_eq!(frame[22], ttl, "TTL {ttl} stays");
        assert_eq!(ipv4_header_checksum(&frame[14..34]), 0);
    }
}

#[test]
fn only_the_kernel_s_interface_may_send_from_the_router_s_address() {
    let run = run(&tables(), false, ipv4(ROUTER, 64, 28));
    assert!(run.sent.is_none());
    assert_eq!(run.dropped, [DropReason::Ipv4SourceLocalAddress]);
}

#[test]
fn a_too_big_ipv4_gets_fragmentation_needed_back_through_the_kernel_s_interface() {
    let packet = ipv4(ROUTER, 64, usize::from(WAN_MTU) + 1);
    let run = run(&tables(), true, packet.clone());
    assert!(run.sent.is_none());
    let (egress, error) = run.icmpv4.expect("an error");
    assert_eq!(egress, KERNEL);
    assert_eq!(&error[0..6], &STACK_MAC.0);
    assert_eq!(&error[6..12], &KERNEL_MAC.0);
    assert_eq!(&error[26..30], &REMOTE, "from the packet's destination");
    assert_eq!(&error[30..34], &ROUTER);
    assert_eq!((error[34], error[35]), (3, 4), "fragmentation needed");
    assert_eq!(u16::from_be_bytes([error[40], error[41]]), WAN_MTU);
    assert_eq!(&error[42..62], &packet[14..34], "the quote");
}

#[test]
fn the_router_s_own_ipv6_keeps_its_hop_limit_and_hears_packet_too_big() {
    for hop_limit in [255, 1] {
        let run = run(&tables(), true, ipv6(hop_limit, 48));
        let (egress, frame) = run.sent.expect("sent");
        assert_eq!(egress, WAN);
        assert_eq!(frame[21], hop_limit);
    }
    let run = run(&tables(), true, ipv6(64, usize::from(WAN_MTU) + 1));
    assert!(run.sent.is_none());
    let [(egress, error)] = run.icmpv6.as_slice() else {
        panic!("one error: {:?}", run.dropped);
    };
    assert_eq!(*egress, KERNEL);
    assert_eq!(&error[0..6], &STACK_MAC.0);
    assert_eq!(
        &error[22..38],
        &ip6("2001:db8:ff::7"),
        "from the destination"
    );
    assert_eq!(&error[38..54], &ip6("2001:db8:1::2"));
    assert_eq!(error[54], 2, "packet too big");
    assert_eq!(
        u32::from_be_bytes([error[58], error[59], error[60], error[61]]),
        u32::from(WAN_MTU)
    );
}

/// A later fragment of the router's own datagram keeps its TTL too, even 1.
#[test]
fn the_router_s_own_fragments_keep_their_ttl() {
    let tables = tables();
    let kernel_ingress = [KERNEL];
    let snapshot = ForwardingSnapshot::new(
        &tables.routes,
        &tables.interfaces,
        &tables.neighbors,
        &tables.bindings,
    )
    .unwrap()
    .with_kernel_ingress(&kernel_ingress)
    .with_now(MonotonicMillis(1));
    let fragment = |offset: u16, more: bool| {
        let mut frame = ipv4([192, 0, 2, 9], 1, 28);
        frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
        let flags = (u16::from(more) << 13) | (offset / 8);
        frame[20..22].copy_from_slice(&flags.to_be_bytes());
        frame[24..26].copy_from_slice(&[0, 0]);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    };
    let mut tracking = tracker();
    let mut io = SimIo::new();
    io.inject(KERNEL, fragment(0, true));
    io.inject(KERNEL, fragment(8, false));
    let batch = io.receive(2).unwrap();
    let mut control = ControlQueue::new(4);
    forward_batch_with_control(
        batch,
        &snapshot,
        &mut control,
        Services {
            fragment_tracking: Some(&mut tracking),
            ..Services::default()
        },
        &mut NoTrace,
    );
    for _ in 0..2 {
        let tx = io.pop_tx().expect("both fragments are sent");
        assert_eq!(tx.egress, WAN);
        assert_eq!(tx.bytes[22], 1, "TTL 1 stays");
        assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
    }
}

fn tracker() -> ruster_core::Ipv4FragmentTracker<'static> {
    use ruster_core::*;
    let (entries, held) = (4, 4);
    let buckets = ipv4_fragment_tracking_buckets(entries);
    let tombstones = ipv4_fragment_tracking_tombstones(entries);
    Ipv4FragmentTracker::new(
        Ipv4FragmentTrackingPolicy::new(5_000, 4, 4).unwrap(),
        Ipv4FragmentTrackingStorage {
            entries: Vec::leak(vec![Ipv4FragmentEntrySlot::EMPTY; entries]),
            entry_buckets: Vec::leak(vec![DirectoryBucket::default(); buckets]),
            entry_nodes: Vec::leak(vec![DirectoryNode::default(); entries]),
            hosts: Vec::leak(vec![Ipv4FragmentHostSlot::EMPTY; entries]),
            host_buckets: Vec::leak(vec![DirectoryBucket::default(); buckets]),
            host_nodes: Vec::leak(vec![DirectoryNode::default(); entries]),
            tombstones: Vec::leak(vec![Ipv4FragmentTombstoneSlot::EMPTY; tombstones]),
            tombstone_buckets: Vec::leak(vec![
                DirectoryBucket::default();
                ipv4_fragment_tracking_buckets(tombstones)
            ]),
            tombstone_nodes: Vec::leak(vec![DirectoryNode::default(); tombstones]),
            held: Vec::leak(vec![Ipv4FragmentHeldSlot::EMPTY; held]),
            held_bytes: Vec::leak(vec![0; held * ipv4_fragment_slot_bytes(1500)]),
        },
        ResolutionHashKey::new(0x1111, 0x2222).unwrap(),
    )
    .unwrap()
}

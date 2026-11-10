//! SRv6 local SIDs (RFC 8754 section 4.3, RFC 8986 section 4): End, End.X, End.DT4
//! and End.DT6, and the ICMPv6 errors they send.

use ruster_core::{
    forward_batch_with_control, ipv4_header_checksum, ControlQueue, ForwardingSnapshot, IfId,
    Interface, Ipv4Address, Ipv6Fib, Ipv6Local, Ipv6Neighbor, Ipv6Route, LocalIpv4Binding,
    MacAddress, MonotonicMillis, Neighbor, NoTrace, PacketIo, Route, Services, Srv6Behaviour,
    Srv6Sid, Srv6Table,
};
use ruster_io_sim::SimIo;

/// The core side (default VRF).
const CORE: IfId = IfId(0);
/// A second link of the default VRF, for End.X.
const SIDE: IfId = IfId(1);
/// The customer side (VRF "red", index 1).
const LAN: IfId = IfId(2);
const CORE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const SIDE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 3]);
const PEER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xfe]);
const SIDE_PEER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xfd]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x10]);
const HOST4: [u8; 4] = [192, 168, 0, 10];
const REMOTE4: [u8; 4] = [198, 51, 100, 7];

fn ip6(text: &str) -> [u8; 16] {
    text.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

const END: &str = "fc00:1::1";
const END_X: &str = "fc00:1::2";
const DT4: &str = "fc00:1::4";
const DT6: &str = "fc00:1::6";

struct Tables {
    interfaces: [Interface; 3],
    neighbors: [Neighbor; 1],
    default6: Ipv6Fib,
    red6: Ipv6Fib,
    red4: [Route; 1],
    srv6: Srv6Table,
}

fn tables() -> Tables {
    let a = Ipv4Address::from_octets;
    let neighbors6 = vec![
        Ipv6Neighbor {
            interface: CORE,
            target: ip6("fe80::fe"),
            mac: PEER_MAC,
        },
        Ipv6Neighbor {
            interface: SIDE,
            target: ip6("fe80::fd"),
            mac: SIDE_PEER_MAC,
        },
        Ipv6Neighbor {
            interface: LAN,
            target: ip6("2001:db8:a::10"),
            mac: HOST_MAC,
        },
    ];
    let sid = |text, behaviour| Srv6Sid::new(ip6(text), 128, behaviour).unwrap();
    Tables {
        interfaces: [
            Interface {
                id: CORE,
                mac: CORE_MAC,
                mtu: 1500,
            },
            Interface {
                id: SIDE,
                mac: SIDE_MAC,
                mtu: 1500,
            },
            Interface {
                id: LAN,
                mac: LAN_MAC,
                mtu: 1500,
            },
        ],
        neighbors: [Neighbor {
            interface: LAN,
            target: a(HOST4),
            mac: HOST_MAC,
        }],
        default6: Ipv6Fib::new(
            vec![Ipv6Route::new(ip6("::"), 0, CORE, Some(ip6("fe80::fe"))).unwrap()],
            neighbors6.clone(),
            vec![Ipv6Local {
                interface: CORE,
                address: ip6("2001:db8::1"),
            }],
        )
        .unwrap(),
        red6: Ipv6Fib::new(
            vec![Ipv6Route::new(ip6("2001:db8:a::"), 64, LAN, None).unwrap()],
            neighbors6,
            vec![],
        )
        .unwrap(),
        red4: [Route::new(a([192, 168, 0, 0]), 24, LAN, None).unwrap()],
        srv6: Srv6Table::new(vec![
            sid(END, Srv6Behaviour::End),
            sid(
                END_X,
                Srv6Behaviour::EndX {
                    egress: SIDE,
                    next_hop: ip6("fe80::fd"),
                },
            ),
            sid(DT4, Srv6Behaviour::EndDt4 { vrf: 1 }),
            sid(DT6, Srv6Behaviour::EndDt6 { vrf: 1 }),
        ])
        .unwrap(),
    }
}

/// What was sent, and the ICMPv6 errors built.
type Ran = (Option<(IfId, Vec<u8>)>, Vec<Vec<u8>>);

/// Runs `frame` in on `ingress`.
fn run(tables: &Tables, ingress: IfId, frame: Vec<u8>) -> Ran {
    let none: [Route; 0] = [];
    let bindings: [LocalIpv4Binding; 0] = [];
    let default = ForwardingSnapshot::new(&none, &tables.interfaces, &tables.neighbors, &bindings)
        .unwrap()
        .with_ipv6(&tables.default6);
    let red = ForwardingSnapshot::new(
        &tables.red4,
        &tables.interfaces,
        &tables.neighbors,
        &bindings,
    )
    .unwrap()
    .with_ipv6(&tables.red6);
    let vrfs = [default, red];
    let by_ingress = [0, 0, 1];
    let snapshot = default
        .with_vrfs(&vrfs, &by_ingress)
        .with_srv6(&tables.srv6)
        .with_now(MonotonicMillis(1));
    let mut io = SimIo::new();
    io.inject(ingress, frame);
    let batch = io.receive(1).unwrap();
    let mut control = ControlQueue::new(4).with_icmpv6_errors(4);
    forward_batch_with_control(
        batch,
        &snapshot,
        &mut control,
        Services::default(),
        &mut NoTrace,
    );
    let errors = control
        .errors()
        .iter()
        .map(|e| e.bytes().to_vec())
        .collect();
    (io.pop_tx().map(|tx| (tx.egress, tx.bytes)), errors)
}

fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut ip = vec![0_u8; 28];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&28_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&source);
    ip[16..20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip[20..22].copy_from_slice(&1000_u16.to_be_bytes());
    ip[22..24].copy_from_slice(&53_u16.to_be_bytes());
    ip[24..26].copy_from_slice(&8_u16.to_be_bytes());
    ip
}

fn ipv6_packet(source: [u8; 16], destination: [u8; 16], hop_limit: u8) -> Vec<u8> {
    let mut ip = vec![0_u8; 48];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&8_u16.to_be_bytes());
    ip[6] = 17;
    ip[7] = hop_limit;
    ip[8..24].copy_from_slice(&source);
    ip[24..40].copy_from_slice(&destination);
    ip
}

/// A Segment Routing Header with `segments` (Segment List[0] first).
fn srh(next: u8, left: u8, last_entry: u8, segments: &[&str]) -> Vec<u8> {
    let mut header = vec![next, u8::try_from(segments.len() * 2).unwrap(), 4, left];
    header.extend_from_slice(&[last_entry, 0, 0, 0]);
    for segment in segments {
        header.extend_from_slice(&ip6(segment));
    }
    header
}

/// An Ethernet frame to the router on the core side: IPv6 from `source` to
/// `destination`, then `headers` (an SRH, or nothing), then `inner` of type `next`.
fn outer(destination: &str, hop_limit: u8, next: u8, headers: &[u8], inner: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&CORE_MAC.0);
    frame.extend_from_slice(&PEER_MAC.0);
    frame.extend_from_slice(&0x86dd_u16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    let payload = u16::try_from(headers.len() + inner.len()).unwrap();
    frame.extend_from_slice(&payload.to_be_bytes());
    frame.push(if headers.is_empty() { next } else { 43 });
    frame.push(hop_limit);
    frame.extend_from_slice(&ip6("2001:db8:ff::9"));
    frame.extend_from_slice(&ip6(destination));
    frame.extend_from_slice(headers);
    frame.extend_from_slice(inner);
    frame
}

/// The type, code and parameter of the one ICMPv6 error in `errors`.
fn icmpv6(errors: &[Vec<u8>]) -> (u8, u8, u32) {
    assert_eq!(errors.len(), 1, "one error");
    let error = &errors[0];
    assert_eq!(error[14 + 6], 58);
    assert_eq!(
        &error[14 + 24..14 + 40],
        &ip6("2001:db8:ff::9"),
        "to the source"
    );
    let icmp = 14 + 40;
    let parameter = u32::from_be_bytes(error[icmp + 4..icmp + 8].try_into().unwrap());
    (error[icmp], error[icmp + 1], parameter)
}

#[test]
fn end_moves_to_the_next_segment_and_routes_it() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let headers = srh(41, 1, 1, &["fc00:2::6", END]);
    let (sent, errors) = run(&tables, CORE, outer(END, 64, 41, &headers, &inner));
    assert!(errors.is_empty());
    let (egress, frame) = sent.expect("sent");
    assert_eq!(egress, CORE);
    assert_eq!(&frame[0..6], &PEER_MAC.0);
    assert_eq!(frame[14 + 7], 63, "Hop Limit decremented once");
    assert_eq!(
        &frame[14 + 24..14 + 40],
        &ip6("fc00:2::6"),
        "the next segment"
    );
    assert_eq!(frame[54 + 3], 0, "Segments Left decremented");
}

#[test]
fn end_x_leaves_through_its_own_adjacency() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let headers = srh(41, 1, 1, &["fc00:2::6", END_X]);
    let (sent, _) = run(&tables, CORE, outer(END_X, 64, 41, &headers, &inner));
    let (egress, frame) = sent.expect("sent");
    assert_eq!(egress, SIDE);
    assert_eq!(&frame[0..6], &SIDE_PEER_MAC.0);
    assert_eq!(&frame[6..12], &SIDE_MAC.0);
    assert_eq!(&frame[14 + 24..14 + 40], &ip6("fc00:2::6"));
    assert_eq!(frame[14 + 7], 63);
}

#[test]
fn two_local_segments_in_a_row_end_in_the_last_one_s_vrf() {
    let tables = tables();
    let inner = ipv4_packet(REMOTE4, HOST4);
    let headers = srh(4, 1, 1, &[DT4, END]);
    let (sent, errors) = run(&tables, CORE, outer(END, 64, 4, &headers, &inner));
    assert!(errors.is_empty());
    let (egress, frame) = sent.expect("sent");
    assert_eq!(egress, LAN);
    assert_eq!(&frame[12..14], &[0x08, 0x00]);
    assert_eq!(frame[14 + 8], 63);
}

#[test]
fn end_dt4_without_a_header_unwraps_into_its_vrf() {
    let tables = tables();
    let inner = ipv4_packet(REMOTE4, HOST4);
    let (sent, _) = run(&tables, CORE, outer(DT4, 64, 4, &[], &inner));
    let (egress, frame) = sent.expect("sent");
    assert_eq!(egress, LAN);
    assert_eq!(&frame[0..6], &HOST_MAC.0);
    assert_eq!(&frame[6..12], &LAN_MAC.0);
    assert_eq!(&frame[12..14], &[0x08, 0x00]);
    assert_eq!(&frame[14 + 16..14 + 20], &HOST4);
    assert_eq!(frame[14 + 8], 63, "inner TTL decremented as forwarded");
    assert_eq!(frame.len(), 14 + 28);
}

#[test]
fn end_dt6_with_no_segments_left_unwraps_into_its_vrf() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let headers = srh(41, 0, 1, &[DT6, END]);
    let (sent, _) = run(&tables, CORE, outer(DT6, 64, 41, &headers, &inner));
    let (egress, frame) = sent.expect("sent");
    assert_eq!(egress, LAN);
    assert_eq!(&frame[0..6], &HOST_MAC.0);
    assert_eq!(&frame[14 + 24..14 + 40], &ip6("2001:db8:a::10"));
    assert_eq!(frame[14 + 7], 63);
    assert_eq!(frame.len(), 14 + 48);
}

#[test]
fn end_dt4_with_segments_left_is_a_parameter_problem_at_segments_left() {
    let tables = tables();
    let inner = ipv4_packet(REMOTE4, HOST4);
    let headers = srh(4, 1, 1, &["fc00:2::4", DT4]);
    let (sent, errors) = run(&tables, CORE, outer(DT4, 64, 4, &headers, &inner));
    assert!(sent.is_none_or(|(egress, _)| egress != LAN));
    assert_eq!(icmpv6(&errors), (4, 0, 43));
}

#[test]
fn end_dt4_with_ipv6_inside_is_an_upper_layer_error() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let (_, errors) = run(&tables, CORE, outer(DT4, 64, 41, &[], &inner));
    assert_eq!(icmpv6(&errors), (4, 4, 40));
}

#[test]
fn end_with_no_segments_left_is_an_upper_layer_error_at_the_upper_layer() {
    let tables = tables();
    let udp = [0_u8; 8];
    let headers = srh(17, 0, 1, &[END, "fc00:2::1"]);
    let (_, errors) = run(&tables, CORE, outer(END, 64, 17, &headers, &udp));
    assert_eq!(icmpv6(&errors), (4, 4, 40 + 40));
}

#[test]
fn segments_left_beyond_last_entry_is_a_parameter_problem() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let headers = srh(41, 3, 1, &[DT6, END]);
    let (sent, errors) = run(&tables, CORE, outer(END, 64, 41, &headers, &inner));
    assert!(sent.is_none());
    assert_eq!(icmpv6(&errors), (4, 0, 43));
}

#[test]
fn last_entry_beyond_the_header_is_a_parameter_problem() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let headers = srh(41, 1, 2, &[DT6, END]);
    let (_, errors) = run(&tables, CORE, outer(END, 64, 41, &headers, &inner));
    assert_eq!(icmpv6(&errors), (4, 0, 43));
}

#[test]
fn end_with_hop_limit_one_is_time_exceeded() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let headers = srh(41, 1, 1, &[DT6, END]);
    let (sent, errors) = run(&tables, CORE, outer(END, 1, 41, &headers, &inner));
    assert!(sent.is_none());
    assert_eq!(icmpv6(&errors), (3, 0, 0));
    let quoted = &errors[0][14 + 48..];
    assert_eq!(&quoted[24..40], &ip6(END), "quoted as received");
}

#[test]
fn another_routing_type_with_segments_left_points_at_its_type() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let mut headers = srh(41, 1, 1, &[DT6, END]);
    headers[2] = 3;
    let (_, errors) = run(&tables, CORE, outer(END, 64, 41, &headers, &inner));
    assert_eq!(icmpv6(&errors), (4, 0, 42));
}

#[test]
fn a_packet_with_a_segment_routing_header_to_another_node_is_routed_untouched() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let headers = srh(41, 1, 1, &["fc00:2::6", "fc00:3::1"]);
    let frame = outer("fc00:3::1", 64, 41, &headers, &inner);
    let (sent, _) = run(&tables, CORE, frame.clone());
    let (egress, out) = sent.expect("sent");
    assert_eq!(egress, CORE);
    assert_eq!(
        &out[14 + 24..],
        &frame[14 + 24..],
        "only the Hop Limit changes"
    );
    assert_eq!(out[14 + 7], 63);
}

#[test]
fn a_sid_is_not_handled_from_another_vrf() {
    let tables = tables();
    let inner = ipv4_packet(REMOTE4, HOST4);
    let mut frame = outer(DT4, 64, 4, &[], &inner);
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    let (sent, _) = run(&tables, LAN, frame);
    assert!(sent.is_none_or(|(egress, _)| egress != LAN));
}

#[test]
fn a_packet_after_the_outer_one_is_not_unwrapped() {
    let tables = tables();
    // Payload Length 0: the IPv4 packet that follows is not inside.
    let mut frame = outer(DT4, 64, 4, &[], &[]);
    frame.extend_from_slice(&ipv4_packet(REMOTE4, HOST4));
    let (sent, _) = run(&tables, CORE, frame);
    assert!(sent.is_none());
}

#[test]
fn an_unwrapped_packet_for_the_router_is_dropped() {
    let mut tables = tables();
    tables.red6 = Ipv6Fib::new(
        vec![Ipv6Route::new(ip6("2001:db8:a::"), 64, LAN, None).unwrap()],
        vec![],
        vec![Ipv6Local {
            interface: LAN,
            address: ip6("2001:db8:a::1"),
        }],
    )
    .unwrap();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::1"), 64);
    let (sent, errors) = run(&tables, CORE, outer(DT6, 64, 41, &[], &inner));
    assert!(sent.is_none());
    assert!(errors.is_empty());
}

#[test]
fn a_sid_of_a_vrf_not_in_the_tables_drops() {
    let mut tables = tables();
    tables.srv6 = Srv6Table::new(vec![Srv6Sid::new(
        ip6(DT4),
        128,
        Srv6Behaviour::EndDt4 { vrf: 7 },
    )
    .unwrap()])
    .unwrap();
    let inner = ipv4_packet(REMOTE4, HOST4);
    let (sent, _) = run(&tables, CORE, outer(DT4, 64, 4, &[], &inner));
    assert!(sent.is_none());
}

#[test]
fn the_second_sid_in_a_row_counts_the_hop_limit_too() {
    let tables = tables();
    let inner = ipv6_packet(ip6("2001:db8:b::1"), ip6("2001:db8:a::10"), 64);
    let headers = srh(41, 2, 2, &["fc00:2::6", END, END]);
    let (sent, errors) = run(&tables, CORE, outer(END, 2, 41, &headers, &inner));
    assert!(sent.is_none());
    assert_eq!(icmpv6(&errors), (3, 0, 0));
    let (sent, _) = run(&tables, CORE, outer(END, 3, 41, &headers, &inner));
    assert_eq!(sent.expect("sent").1[14 + 7], 1);
}

//! SRv6 H.Encaps and H.Encaps.Red (RFC 8986 section 5.1 and 5.2): packets routed to
//! an SR policy's interface leave inside an outer IPv6 header and a Segment Routing
//! Header, and those too long once wrapped get Packet Too Big.

use ruster_core::{
    forward_batch_with_control, ipv4_header_checksum, ControlQueue, ForwardingSnapshot, IfId,
    Interface, Ipv4Address, Ipv6Fib, Ipv6Local, Ipv6Neighbor, Ipv6Route, LocalIpv4Binding,
    MacAddress, MonotonicMillis, Neighbor, NoTrace, PacketIo, Route, Services, Srv6Policy,
    Srv6Table,
};
use ruster_io_sim::SimIo;

/// The core side (default VRF).
const CORE: IfId = IfId(0);
/// The customer side (VRF "red", index 1).
const LAN: IfId = IfId(1);
/// The SR policy's interface, in "red".
const POLICY: IfId = IfId(2);
const CORE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 3]);
const PEER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xfe]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x10]);
const HOST4: [u8; 4] = [192, 168, 0, 10];
const REMOTE4: [u8; 4] = [10, 2, 0, 7];

fn ip6(text: &str) -> [u8; 16] {
    text.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

const SOURCE: &str = "2001:db8::1";

struct Tables {
    interfaces: [Interface; 3],
    neighbors: [Neighbor; 1],
    default6: Ipv6Fib,
    red6: Ipv6Fib,
    red4: [Route; 2],
    srv6: Srv6Table,
}

fn tables(segments: &[&str], reduced: bool) -> Tables {
    let a = Ipv4Address::from_octets;
    Tables {
        interfaces: [
            Interface {
                id: CORE,
                mac: CORE_MAC,
                mtu: 1500,
            },
            Interface {
                id: LAN,
                mac: LAN_MAC,
                mtu: 1500,
            },
            Interface {
                id: POLICY,
                mac: MacAddress([2, 0, 0, 0, 0, 9]),
                mtu: 9000,
            },
        ],
        neighbors: [Neighbor {
            interface: LAN,
            target: a(HOST4),
            mac: HOST_MAC,
        }],
        default6: Ipv6Fib::new(
            vec![Ipv6Route::new(ip6("::"), 0, CORE, Some(ip6("fe80::fe"))).unwrap()],
            vec![Ipv6Neighbor {
                interface: CORE,
                target: ip6("fe80::fe"),
                mac: PEER_MAC,
            }],
            vec![],
        )
        .unwrap(),
        red6: Ipv6Fib::new(
            vec![
                Ipv6Route::new(ip6("2001:db8:c::"), 48, POLICY, None).unwrap(),
                Ipv6Route::new(ip6("2001:db8:a::"), 64, LAN, None).unwrap(),
            ],
            vec![Ipv6Neighbor {
                interface: LAN,
                target: ip6("2001:db8:a::10"),
                mac: HOST_MAC,
            }],
            vec![Ipv6Local {
                interface: LAN,
                address: ip6("2001:db8:a::1"),
            }],
        )
        .unwrap(),
        red4: [
            Route::new(a([192, 168, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(a([10, 2, 0, 0]), 16, POLICY, None).unwrap(),
        ],
        srv6: Srv6Table::new(vec![])
            .unwrap()
            .with_policies(vec![Srv6Policy::new(
                POLICY,
                ip6(SOURCE),
                segments.iter().map(|s| ip6(s)).collect(),
                reduced,
            )
            .unwrap()])
            .unwrap(),
    }
}

/// What was sent, and the ICMPv6 errors built.
type Ran = (Option<(IfId, Vec<u8>)>, Vec<Vec<u8>>);

fn run(tables: &Tables, frame: Vec<u8>) -> Ran {
    let none: [Route; 0] = [];
    let bindings: [LocalIpv4Binding; 0] = [];
    let default = ForwardingSnapshot::new(&none, &tables.interfaces, &tables.neighbors, &bindings)
        .unwrap()
        .with_ipv6(&tables.default6)
        .with_srv6(&tables.srv6);
    let red = ForwardingSnapshot::new(
        &tables.red4,
        &tables.interfaces,
        &tables.neighbors,
        &bindings,
    )
    .unwrap()
    .with_ipv6(&tables.red6)
    .with_srv6(&tables.srv6);
    let vrfs = [default, red];
    let by_ingress = [0, 1, 1];
    let snapshot = default
        .with_vrfs(&vrfs, &by_ingress)
        .with_now(MonotonicMillis(1));
    let mut io = SimIo::new();
    io.inject(LAN, frame);
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

/// An IPv4 UDP datagram from the host, `len` bytes long, TOS 0xb8.
fn ipv4(len: usize, df: bool) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + len];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    let ip = &mut frame[14..];
    ip[0] = 0x45;
    ip[1] = 0xb8;
    ip[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    if df {
        ip[6] = 0x40;
    }
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&HOST4);
    ip[16..20].copy_from_slice(&REMOTE4);
    let checksum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip[20..22].copy_from_slice(&1000_u16.to_be_bytes());
    ip[22..24].copy_from_slice(&53_u16.to_be_bytes());
    ip[24..26].copy_from_slice(&u16::try_from(len - 20).unwrap().to_be_bytes());
    frame
}

/// An IPv6 UDP packet from a host, `payload` bytes after the header.
fn ipv6(payload: usize) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + payload];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&[0x86, 0xdd]);
    let ip = &mut frame[14..];
    ip[0] = 0x60 | 0x0b;
    ip[1] = 0x80;
    ip[4..6].copy_from_slice(&u16::try_from(payload).unwrap().to_be_bytes());
    ip[6] = 17;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&ip6("2001:db8:a::10"));
    ip[24..40].copy_from_slice(&ip6("2001:db8:c::5"));
    frame
}

#[test]
fn ipv4_leaves_inside_ipv6_with_a_segment_routing_header() {
    let tables = tables(&["fc00:2::1", "fc00:3::1", "fc00:4::4"], false);
    let (sent, _) = run(&tables, ipv4(28, false));
    let (egress, frame) = sent.expect("sent");
    assert_eq!(egress, CORE);
    assert_eq!(&frame[0..6], &PEER_MAC.0);
    assert_eq!(&frame[6..12], &CORE_MAC.0);
    assert_eq!(&frame[12..14], &[0x86, 0xdd]);
    let ip = 14;
    assert_eq!(frame[ip] >> 4, 6);
    assert_eq!(
        ((frame[ip] & 0x0f) << 4) | (frame[ip + 1] >> 4),
        0xb8,
        "TOS copied"
    );
    let flow = u32::from_be_bytes([0, frame[ip + 1] & 0x0f, frame[ip + 2], frame[ip + 3]]);
    assert_ne!(flow, 0, "a flow label");
    let srh_len = 8 + 3 * 16;
    assert_eq!(
        usize::from(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]])),
        srh_len + 28
    );
    assert_eq!(frame[ip + 6], 43);
    assert_eq!(frame[ip + 7], 64);
    assert_eq!(&frame[ip + 8..ip + 24], &ip6(SOURCE));
    assert_eq!(
        &frame[ip + 24..ip + 40],
        &ip6("fc00:2::1"),
        "the first segment"
    );
    let srh = ip + 40;
    assert_eq!(&frame[srh..srh + 8], &[4, 6, 4, 2, 2, 0, 0, 0]);
    assert_eq!(
        &frame[srh + 8..srh + 24],
        &ip6("fc00:4::4"),
        "the last first"
    );
    assert_eq!(&frame[srh + 24..srh + 40], &ip6("fc00:3::1"));
    assert_eq!(&frame[srh + 40..srh + 56], &ip6("fc00:2::1"));
    let inner = srh + srh_len;
    assert_eq!(frame[inner] >> 4, 4);
    assert_eq!(frame[inner + 8], 63, "inner TTL decremented");
    assert_eq!(frame.len(), inner + 28);
}

#[test]
fn reduced_leaves_the_first_segment_out_of_the_header() {
    let tables = tables(&["fc00:2::1", "fc00:3::1", "fc00:4::4"], true);
    let (sent, _) = run(&tables, ipv4(28, false));
    let (_, frame) = sent.expect("sent");
    let srh = 14 + 40;
    assert_eq!(&frame[14 + 24..14 + 40], &ip6("fc00:2::1"));
    assert_eq!(&frame[srh..srh + 8], &[4, 4, 4, 2, 1, 0, 0, 0]);
    assert_eq!(&frame[srh + 8..srh + 24], &ip6("fc00:4::4"));
    assert_eq!(&frame[srh + 24..srh + 40], &ip6("fc00:3::1"));
    assert_eq!(frame[srh + 40] >> 4, 4, "then the inner packet");
}

#[test]
fn one_segment_needs_no_header() {
    let tables = tables(&["fc00:4::6"], false);
    let (sent, _) = run(&tables, ipv6(8));
    let (egress, frame) = sent.expect("sent");
    assert_eq!(egress, CORE);
    let ip = 14;
    assert_eq!(
        ((frame[ip] & 0x0f) << 4) | (frame[ip + 1] >> 4),
        0xb8,
        "class copied"
    );
    assert_eq!(frame[ip + 6], 41);
    assert_eq!(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]), 48);
    assert_eq!(&frame[ip + 24..ip + 40], &ip6("fc00:4::6"));
    assert_eq!(frame[ip + 40 + 7], 63, "inner Hop Limit decremented");
}

#[test]
fn ipv6_too_long_once_wrapped_gets_packet_too_big() {
    let tables = tables(&["fc00:2::1", "fc00:4::6"], false);
    // 1500 less the outer IPv6 (40) and an SRH of two (40): 1420 fits.
    let (sent, errors) = run(&tables, ipv6(1420 - 40));
    assert!(sent.is_some());
    assert!(errors.is_empty());
    let (sent, errors) = run(&tables, ipv6(1421 - 40));
    assert!(sent.is_none());
    assert_eq!(errors.len(), 1);
    let error = &errors[0];
    let icmp = 14 + 40;
    assert_eq!(error[icmp], 2, "Packet Too Big");
    assert_eq!(
        u32::from_be_bytes(error[icmp + 4..icmp + 8].try_into().unwrap()),
        1420
    );
}

#[test]
fn ipv4_too_long_once_wrapped_with_df_is_not_sent() {
    let tables = tables(&["fc00:2::1", "fc00:4::6"], false);
    assert!(run(&tables, ipv4(1420, true)).0.is_some());
    assert!(run(&tables, ipv4(1421, true)).0.is_none());
}

#[test]
fn a_generated_frame_is_wrapped_too() {
    let tables = tables(&["fc00:2::1", "fc00:4::6"], false);
    let none: [Route; 0] = [];
    let bindings: [LocalIpv4Binding; 0] = [];
    let default = ForwardingSnapshot::new(&none, &tables.interfaces, &tables.neighbors, &bindings)
        .unwrap()
        .with_ipv6(&tables.default6)
        .with_srv6(&tables.srv6);
    let (egress, frame) = default
        .srv6_frame(POLICY, &ipv4(28, false))
        .expect("a policy")
        .expect("wrapped");
    assert_eq!(egress, CORE);
    assert_eq!(frame.len(), 14 + 40 + 40 + 28);
    assert_eq!(frame[14 + 6], 43);
    assert!(default.srv6_frame(LAN, &ipv4(28, false)).is_none());
}

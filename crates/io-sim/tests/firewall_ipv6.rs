//! The forward firewall on IPv6: the same rules and state table as IPv4.

use ruster_core::{
    forward_batch_with_control, ControlQueue, DropReason, FirewallAction, FirewallConfig,
    FirewallHashKey, FirewallInterface, FirewallIpv4Prefix, FirewallIpv6Prefix, FirewallPolicy,
    FirewallPortRange, FirewallProtocol, FirewallRule, FirewallRuleId, FirewallRuntime,
    FirewallStateSlot, ForwardingSnapshot, IfId, Interface, Ipv4Address, Ipv6Fib, Ipv6Local,
    Ipv6Neighbor, Ipv6Route, MacAddress, MonotonicMillis, PacketIo, Services, TraceEvent,
    TraceSink,
};
use ruster_io_sim::SimIo;

const LAN: IfId = IfId(0);
const WAN: IfId = IfId(1);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const HOST: &str = "2001:db8:1::10";
const REMOTE: &str = "2001:db8:ff::20";

fn ip(text: &str) -> [u8; 16] {
    text.parse::<std::net::Ipv6Addr>().unwrap().octets()
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

fn interfaces() -> [Interface; 2] {
    [
        Interface {
            id: LAN,
            mac: MacAddress(LAN_MAC),
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: MacAddress(WAN_MAC),
            mtu: 1500,
        },
    ]
}

fn fib() -> Ipv6Fib {
    Ipv6Fib::new(
        vec![
            Ipv6Route::new(ip("2001:db8:1::"), 64, LAN, None).unwrap(),
            Ipv6Route::new(ip("::"), 0, WAN, Some(ip("fe80::1"))).unwrap(),
        ],
        vec![
            Ipv6Neighbor {
                interface: LAN,
                target: ip(HOST),
                mac: MacAddress(HOST_MAC),
            },
            Ipv6Neighbor {
                interface: WAN,
                target: ip("fe80::1"),
                mac: MacAddress(GATEWAY_MAC),
            },
        ],
        vec![Ipv6Local {
            interface: LAN,
            address: ip("2001:db8:1::1"),
        }],
    )
    .unwrap()
}

fn ipv6(inbound: bool, source: &str, destination: &str, next: u8, payload: &[u8]) -> Vec<u8> {
    let (dst_mac, src_mac) = if inbound {
        (WAN_MAC, GATEWAY_MAC)
    } else {
        (LAN_MAC, HOST_MAC)
    };
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x86dd_u16.to_be_bytes());
    frame.extend_from_slice(&ipv6_header(source, destination, next, payload.len()));
    frame.extend_from_slice(payload);
    frame
}

fn ipv6_header(source: &str, destination: &str, next: u8, payload: usize) -> Vec<u8> {
    let mut header = vec![0x60, 0, 0, 0];
    header.extend_from_slice(&u16::try_from(payload).unwrap().to_be_bytes());
    header.push(next);
    header.push(64);
    header.extend_from_slice(&ip(source));
    header.extend_from_slice(&ip(destination));
    header
}

fn tcp(source_port: u16, destination_port: u16, flags: u8) -> Vec<u8> {
    let mut tcp = vec![0; 20];
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp
}

fn echo(kind: u8, identifier: u16) -> Vec<u8> {
    let mut icmp = vec![kind, 0, 0, 0, 0, 0, 0, 1];
    icmp[4..6].copy_from_slice(&identifier.to_be_bytes());
    icmp
}

fn rule(id: u32, protocol: FirewallProtocol, v6: bool) -> FirewallRule {
    let (source, destination) = if v6 {
        let any = FirewallIpv6Prefix::new([0; 16], 0).unwrap();
        (any.into(), any.into())
    } else {
        let any = FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap();
        (any.into(), any.into())
    };
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(LAN),
        FirewallInterface::Interface(WAN),
        source,
        destination,
        protocol,
        FirewallPortRange::new(0, u16::MAX).unwrap(),
        FirewallPortRange::new(0, u16::MAX).unwrap(),
        FirewallAction::AllowStateful,
    )
}

/// Runs each batch of `(port, frame)` through a router with `rules`, keeping the
/// state between batches. Returns what left and the drops, per batch.
fn run(
    rules: &[FirewallRule],
    batches: Vec<Vec<(IfId, Vec<u8>)>>,
) -> Vec<(Vec<IfId>, Vec<DropReason>)> {
    let interfaces = interfaces();
    let fib = fib();
    let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &[])
        .unwrap()
        .with_ipv6(&fib);
    let config = FirewallConfig::new(
        &snapshot,
        rules,
        FirewallPolicy::default(),
        1,
        FirewallHashKey::new(1, 2).unwrap(),
    )
    .unwrap();
    let mut slots = [FirewallStateSlot::default(); 16];
    let mut runtime = FirewallRuntime::new(config, &mut slots);
    let mut io = SimIo::new();
    let mut queue = ControlQueue::new(4);
    let mut out = Vec::new();
    for (now, frames) in batches.into_iter().enumerate() {
        for (port, frame) in frames {
            io.inject(port, frame);
        }
        let snapshot = snapshot.with_now(MonotonicMillis(now as u64 * 10));
        let mut drops = Drops::default();
        let batch = io.receive(16).unwrap();
        let services = Services {
            firewall: Some((&config, &mut runtime)),
            ..Services::default()
        };
        forward_batch_with_control(batch, &snapshot, &mut queue, services, &mut drops);
        let mut sent = Vec::new();
        while let Some(tx) = io.pop_tx() {
            sent.push(tx.egress);
        }
        out.push((sent, drops.0));
    }
    out
}

#[test]
fn tcp_goes_out_by_a_rule_and_only_its_replies_come_back() {
    let rules = [rule(1, FirewallProtocol::Tcp, true)];
    let result = run(
        &rules,
        vec![
            // An unsolicited connection from outside first: nothing lets it in.
            vec![(WAN, ipv6(true, REMOTE, HOST, 6, &tcp(80, 4000, 0x02)))],
            vec![(LAN, ipv6(false, HOST, REMOTE, 6, &tcp(4000, 80, 0x02)))],
            vec![(WAN, ipv6(true, REMOTE, HOST, 6, &tcp(80, 4000, 0x12)))],
            // Another port is another flow.
            vec![(WAN, ipv6(true, REMOTE, HOST, 6, &tcp(81, 4000, 0x12)))],
        ],
    );
    assert_eq!(result[0], (vec![], vec![DropReason::FirewallDefaultDenied]));
    assert_eq!(result[1], (vec![WAN], vec![]));
    assert_eq!(result[2], (vec![LAN], vec![]), "the reply of the flow");
    assert_eq!(result[3], (vec![], vec![DropReason::FirewallDefaultDenied]));
}

#[test]
fn an_echo_reply_passes_only_for_a_request_that_went_out() {
    let rules = [rule(1, FirewallProtocol::Icmpv6, true)];
    let result = run(
        &rules,
        vec![
            vec![(WAN, ipv6(true, REMOTE, HOST, 58, &echo(129, 7)))],
            vec![(LAN, ipv6(false, HOST, REMOTE, 58, &echo(128, 7)))],
            vec![(WAN, ipv6(true, REMOTE, HOST, 58, &echo(129, 7)))],
            vec![(WAN, ipv6(true, REMOTE, HOST, 58, &echo(129, 8)))],
        ],
    );
    assert_eq!(result[0].0, Vec::<IfId>::new());
    assert_eq!(result[1], (vec![WAN], vec![]));
    assert_eq!(result[2], (vec![LAN], vec![]));
    assert_eq!(result[3].0, Vec::<IfId>::new(), "another identifier");
}

/// An ICMPv6 error of `kind` from a router on the path, quoting `quoted`.
fn error_about(kind: u8, quoted: &[u8]) -> Vec<u8> {
    let mut icmp = vec![kind, 0, 0, 0, 0, 0, 0x05, 0x00];
    icmp.extend_from_slice(quoted);
    ipv6(true, "2001:db8:ee::1", HOST, 58, &icmp)
}

#[test]
fn an_error_about_a_flow_passes_and_one_about_nothing_does_not() {
    let rules = [rule(1, FirewallProtocol::Tcp, true)];
    let out = tcp(4000, 80, 0x02);
    let mut quoted = ipv6_header(HOST, REMOTE, 6, out.len());
    quoted.extend_from_slice(&out);
    let mut stranger = ipv6_header(HOST, REMOTE, 6, 20);
    stranger.extend_from_slice(&tcp(4001, 80, 0x02));
    let result = run(
        &rules,
        vec![
            vec![(LAN, ipv6(false, HOST, REMOTE, 6, &out))],
            // Packet Too Big (2) about it: the host learns the path MTU.
            vec![(WAN, error_about(2, &quoted))],
            // Destination Unreachable (1) cut short after the ports.
            vec![(WAN, error_about(1, &quoted[..44]))],
            vec![(WAN, error_about(2, &stranger))],
            // Not one of the four errors (Router Advertisement).
            vec![(WAN, error_about(134, &quoted))],
        ],
    );
    assert_eq!(result[1], (vec![LAN], vec![]));
    assert_eq!(result[2], (vec![LAN], vec![]));
    assert_eq!(
        result[3],
        (vec![], vec![DropReason::FirewallIcmpv6Unrelated])
    );
    assert_eq!(
        result[4],
        (vec![], vec![DropReason::FirewallUnsupportedProtocol])
    );
}

/// A UDP packet in a Fragment header (and a Hop-by-Hop header before it).
fn fragment(offset_units: u16, more: bool) -> Vec<u8> {
    let mut payload = vec![44, 0, 1, 4, 0, 0, 0, 0]; // Hop-by-Hop: PadN
    let mut fragment = vec![17, 0, 0, 0, 0, 0, 0, 9];
    let flags = (offset_units << 3) | u16::from(more);
    fragment[2..4].copy_from_slice(&flags.to_be_bytes());
    payload.extend_from_slice(&fragment);
    let mut udp = vec![0; 8];
    udp[0..2].copy_from_slice(&5000_u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53_u16.to_be_bytes());
    payload.extend_from_slice(&udp);
    ipv6(false, HOST, REMOTE, 0, &payload)
}

#[test]
fn extension_headers_are_stepped_over_and_later_fragments_dropped() {
    let rules = [rule(1, FirewallProtocol::Udp, true)];
    let result = run(
        &rules,
        vec![
            vec![(LAN, fragment(0, true))],
            vec![(LAN, fragment(185, false))],
        ],
    );
    assert_eq!(
        result[0],
        (vec![WAN], vec![]),
        "the first fragment has the ports"
    );
    assert_eq!(
        result[1],
        (vec![], vec![DropReason::FirewallFragmentUnsupported])
    );
}

#[test]
fn ipv4_rules_do_not_let_ipv6_through() {
    let rules = [rule(1, FirewallProtocol::Tcp, false)];
    let result = run(
        &rules,
        vec![vec![(
            LAN,
            ipv6(false, HOST, REMOTE, 6, &tcp(4000, 80, 0x02)),
        )]],
    );
    assert_eq!(result[0], (vec![], vec![DropReason::FirewallDefaultDenied]));
}

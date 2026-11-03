//! ICMP-ERR: the RFC 1812 ICMPv4 errors about datagrams addressed to the
//! router (Protocol Unreachable, the router's own UDP Port Unreachable, the
//! silent TCP drop) and about IPv4 headers the router cannot process
//! (Parameter Problem). Every error is checked byte for byte against an
//! independently built expected frame.

use ruster_core::{
    execute_one_icmpv4_error, forward_batch_with_resolution_and_icmpv4_errors, internet_checksum,
    ipv4_header_checksum, ConsumeReason, DropReason, ForwardingSnapshot, Icmpv4ErrorActionSlot,
    Icmpv4ErrorCounters, Icmpv4ErrorDisposition, Icmpv4ErrorKind, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, LocalIpv4Binding,
    MacAddress, MonotonicMillis, Neighbor, NoGeneratedIcmpv4Trace, PacketIo, ResolutionActionSlot,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route, TraceEvent,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const SOURCE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xbb]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const SOURCE: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 9]);
const ROUTED: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 9]);
const MISSING: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 9]);
const TOS: u8 = 0x2e;

fn interfaces() -> [Interface; 2] {
    [
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: 1500,
        },
    ]
}

fn bindings() -> [LocalIpv4Binding; 2] {
    [
        LocalIpv4Binding {
            interface: LAN,
            address: LAN_IP,
        },
        LocalIpv4Binding {
            interface: WAN,
            address: WAN_IP,
        },
    ]
}

fn routes() -> [Route; 2] {
    [
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap(),
    ]
}

fn neighbors() -> [Neighbor; 1] {
    [Neighbor {
        interface: LAN,
        target: SOURCE,
        mac: SOURCE_MAC,
    }]
}

/// An Ethernet frame from SOURCE on the LAN carrying an IPv4 datagram with
/// `options` and `payload`, followed by `padding` link bytes.
fn frame(
    destination: Ipv4Address,
    protocol: u8,
    flags_fragment: u16,
    options: &[u8],
    payload: &[u8],
    padding: usize,
) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let header_len = 20 + options.len();
    let total_len = header_len + payload.len();
    let mut frame = vec![0_u8; 14 + total_len + padding];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&SOURCE_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x40 | u8::try_from(header_len / 4).unwrap();
    frame[15] = TOS;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x5a5a_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = 64;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&SOURCE.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..14 + header_len].copy_from_slice(options);
    frame[14 + header_len..14 + total_len].copy_from_slice(payload);
    frame[14 + total_len..].fill(0xa5);
    let checksum = ipv4_header_checksum(&frame[14..14 + header_len]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// A UDP datagram SOURCE:40000 -> `destination`:`port` with a valid (or,
/// `checksum = false`, zero) checksum.
fn udp(destination: Ipv4Address, port: u16, checksum: bool) -> Vec<u8> {
    let mut segment = vec![0_u8; 12];
    segment[0..2].copy_from_slice(&40_000_u16.to_be_bytes());
    segment[2..4].copy_from_slice(&port.to_be_bytes());
    segment[4..6].copy_from_slice(&12_u16.to_be_bytes());
    segment[8..12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    if checksum {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&SOURCE.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(&[0, 17, 0, 12]);
        pseudo.extend_from_slice(&segment);
        let sum = internet_checksum(&pseudo);
        segment[6..8].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    }
    frame(destination, 17, 0x4000, &[], &segment, 4)
}

/// `frame` claiming `extra` more bytes in Total Length than it carries,
/// with a valid header checksum (unless `bad_checksum`).
fn truncated(mut frame: Vec<u8>, extra: u16, bad_checksum: bool) -> Vec<u8> {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    // Drop the link padding so the frame ends at the datagram's last byte.
    let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    frame.truncate(14 + total);
    let claimed = u16::try_from(total).unwrap() + extra;
    frame[16..18].copy_from_slice(&claimed.to_be_bytes());
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..14 + header_len]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    if bad_checksum {
        frame[25] ^= 1;
    }
    frame
}

/// The expected generated error toward SOURCE from LAN_IP, built without
/// the core builder: RFC 792 layout, RFC 1812 §4.3.2.5 TOS, DF, TTL 64.
fn expected_error(icmp_type: u8, code: u8, word: [u8; 4], quote: &[u8]) -> Vec<u8> {
    let total_len = 28 + quote.len();
    let mut frame = vec![0_u8; (14 + total_len).max(60)];
    frame[0..6].copy_from_slice(&SOURCE_MAC.0);
    frame[6..12].copy_from_slice(&LAN_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = (TOS & 0x1e) | 0xc0;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&LAN_IP.octets());
    frame[30..34].copy_from_slice(&SOURCE.octets());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34] = icmp_type;
    frame[35] = code;
    frame[38..42].copy_from_slice(&word);
    frame[42..42 + quote.len()].copy_from_slice(quote);
    let checksum = internet_checksum(&frame[34..42 + quote.len()]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// The IPv4 datagram of `frame` as received (no link padding).
fn datagram(frame: &[u8]) -> &[u8] {
    let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    &frame[14..(14 + total).min(frame.len())]
}

struct Outcome {
    recycle: RecycleCause,
    unchanged: bool,
    disposition: Option<Icmpv4ErrorDisposition>,
    counters: Icmpv4ErrorCounters,
    generated: Option<Vec<u8>>,
}

fn run(frames: &[Vec<u8>], policy: Icmpv4ErrorPolicy) -> Vec<Outcome> {
    let routes = routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 2];
    let mut ra = [ResolutionActionSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut rs,
        &mut ra,
    );
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 2];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 2];
    let mut errors = Icmpv4ErrorRuntime::new(policy, &mut es, &mut ea);
    let mut io = SimIo::new();
    let mut outcomes = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let now = MonotonicMillis(10 + index as u64);
        io.inject(LAN, frame.clone());
        let mut trace = VecTrace::default();
        let report = forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            &mut errors,
            now,
            &mut trace,
        );
        assert!(report.invariants_hold());
        assert_eq!(report.tx_requested, 0);
        let recycled = io.pop_recycled().unwrap();
        let disposition = trace.events().iter().find_map(|event| match event {
            TraceEvent::Icmpv4DestinationUnreachableDisposition { disposition, .. }
            | TraceEvent::Icmpv4ParameterProblemDisposition { disposition, .. } => {
                Some(*disposition)
            }
            _ => None,
        });
        outcomes.push(Outcome {
            recycle: recycled.cause,
            unchanged: recycled.bytes == *frame,
            disposition,
            counters: errors.counters(),
            generated: None,
        });
    }
    // Drain the generated phase once, after every frame: errors queued at
    // the same egress are limited to one at a time.
    let now = MonotonicMillis(10 + frames.len() as u64);
    let mut index = 0;
    while let Some(report) =
        execute_one_icmpv4_error(&mut io, &mut errors, now, &mut NoGeneratedIcmpv4Trace).unwrap()
    {
        assert_eq!(report.completion.accepted, 1);
        let tx = io.pop_tx().unwrap();
        assert_eq!(tx.egress, LAN);
        while outcomes[index].disposition.is_none_or(|d| !queued(d)) {
            index += 1;
        }
        outcomes[index].generated = Some(tx.bytes);
        index += 1;
    }
    assert!(io.pop_tx().is_none(), "no ARP or other frame is emitted");
    outcomes
}

fn queued(disposition: Icmpv4ErrorDisposition) -> bool {
    matches!(
        disposition,
        Icmpv4ErrorDisposition::ProtocolUnreachableQueued { .. }
            | Icmpv4ErrorDisposition::LocalPortUnreachableQueued { .. }
            | Icmpv4ErrorDisposition::ParameterProblemQueued { .. }
            | Icmpv4ErrorDisposition::AdministrativelyProhibitedQueued { .. }
    )
}

fn one(frame: Vec<u8>, policy: Icmpv4ErrorPolicy) -> Outcome {
    run(&[frame], policy).pop().unwrap()
}

fn assert_dropped(outcome: &Outcome, reason: DropReason) {
    assert_eq!(outcome.recycle, RecycleCause::Forwarding(reason));
    assert!(outcome.unchanged, "the drop leaves the frame unchanged");
}

#[test]
fn udp_to_the_router_gets_an_exact_port_unreachable() {
    for checksum in [true, false] {
        let received = udp(LAN_IP, 4242, checksum);
        let outcome = one(received.clone(), Icmpv4ErrorPolicy::default());
        assert_dropped(&outcome, DropReason::Ipv4LocalUdpPortUnreachable);
        assert_eq!(
            outcome.disposition,
            Some(Icmpv4ErrorDisposition::LocalPortUnreachableQueued {
                egress: LAN,
                quote_len: 32,
            })
        );
        assert_eq!(
            outcome.generated.unwrap(),
            expected_error(3, 3, [0; 4], datagram(&received))
        );
        assert_eq!(outcome.counters.queued_udp_port_unreachable, 1);
        assert_eq!(outcome.counters.queued_port_unreachable, 0);
    }
}

#[test]
fn an_unimplemented_protocol_gets_protocol_unreachable() {
    let received = frame(LAN_IP, 47, 0, &[], &[0, 0, 0x08, 0, 1, 2, 3, 4], 0);
    let outcome = one(received.clone(), Icmpv4ErrorPolicy::default());
    assert_dropped(&outcome, DropReason::Ipv4LocalProtocolUnreachable);
    assert_eq!(
        outcome.generated.unwrap(),
        expected_error(3, 2, [0; 4], datagram(&received))
    );
    assert_eq!(outcome.counters.queued_protocol_unreachable, 1);
    assert_eq!(outcome.counters.dequeued_protocol_unreachable, 0);
}

#[test]
fn tcp_and_invalid_udp_to_the_router_are_silent_drops() {
    let mut bad_checksum = udp(LAN_IP, 53, true);
    bad_checksum[41] ^= 1;
    let mut short_length = udp(LAN_IP, 53, false);
    short_length[38..40].copy_from_slice(&7_u16.to_be_bytes());
    let mut long_length = udp(LAN_IP, 53, false);
    long_length[38..40].copy_from_slice(&13_u16.to_be_bytes());
    let header_only = frame(LAN_IP, 17, 0, &[], &[0, 1, 0, 2], 0);
    let tcp = frame(LAN_IP, 6, 0x4000, &[], &[0; 20], 0);
    for (received, reason) in [
        (bad_checksum, DropReason::Ipv4LocalUdpInvalid),
        (short_length, DropReason::Ipv4LocalUdpInvalid),
        (long_length, DropReason::Ipv4LocalUdpInvalid),
        (header_only, DropReason::Ipv4LocalUdpInvalid),
        (tcp, DropReason::Ipv4LocalTcpUnsupported),
    ] {
        let outcome = one(received, Icmpv4ErrorPolicy::default());
        assert_dropped(&outcome, reason);
        assert_eq!(outcome.disposition, None);
        assert_eq!(outcome.counters, Icmpv4ErrorCounters::default());
        assert!(outcome.generated.is_none());
    }
}

#[test]
fn local_fragments_stay_consumed_without_an_error() {
    for flags_fragment in [0x2000, 0x0001, 0x2001] {
        let received = frame(LAN_IP, 17, flags_fragment, &[], &[0; 16], 0);
        let outcome = one(received, Icmpv4ErrorPolicy::default());
        assert_eq!(
            outcome.recycle,
            RecycleCause::Consumed(ConsumeReason::Ipv4LocalUnsupported)
        );
        assert!(outcome.unchanged);
        assert_eq!(outcome.counters, Icmpv4ErrorCounters::default());
    }
}

#[test]
fn local_switches_drop_silently_with_their_own_counters() {
    let cases = [
        (
            Icmpv4ErrorKind::DestinationUnreachableLocalPort,
            udp(LAN_IP, 9, true),
            DropReason::Ipv4LocalUdpPortUnreachable,
        ),
        (
            Icmpv4ErrorKind::DestinationUnreachableProtocol,
            frame(LAN_IP, 132, 0, &[], &[0; 12], 0),
            DropReason::Ipv4LocalProtocolUnreachable,
        ),
        (
            Icmpv4ErrorKind::ParameterProblem,
            truncated(udp(LAN_IP, 9, true), 8, false),
            DropReason::Ipv4TotalLengthExceedsPacket,
        ),
    ];
    for (kind, received, reason) in cases {
        let policy = Icmpv4ErrorPolicy::default().with_generation(kind, false);
        assert!(!policy.generates(kind));
        let outcome = one(received, policy);
        assert_dropped(&outcome, reason);
        assert_eq!(
            outcome.disposition,
            Some(Icmpv4ErrorDisposition::GenerationDisabled { kind })
        );
        let counters = outcome.counters;
        let disabled = match kind {
            Icmpv4ErrorKind::DestinationUnreachableLocalPort => {
                counters.disabled_udp_port_unreachable
            }
            Icmpv4ErrorKind::DestinationUnreachableProtocol => {
                counters.disabled_protocol_unreachable
            }
            _ => counters.disabled_parameter_problem,
        };
        assert_eq!((disabled, counters.queued), (1, 0));
        assert!(outcome.generated.is_none());
    }
}

#[test]
fn the_new_kinds_share_the_class_zero_limiter_of_the_egress() {
    // Back to back on the same egress: the second waits behind the first.
    let outcomes = run(
        &[udp(LAN_IP, 1, true), frame(LAN_IP, 47, 0, &[], &[0; 8], 0)],
        Icmpv4ErrorPolicy::default(),
    );
    assert_eq!(
        outcomes[1].disposition,
        Some(Icmpv4ErrorDisposition::Pending { egress: LAN })
    );
    assert!(outcomes[0].generated.is_some());
    assert!(outcomes[1].generated.is_none());
    assert_eq!(outcomes[1].counters.pending, 1);
}

#[test]
fn a_truncated_datagram_gets_parameter_problem_at_total_length() {
    for destination in [LAN_IP, ROUTED] {
        let received = truncated(udp(destination, 7, true), 10, false);
        let outcome = one(received.clone(), Icmpv4ErrorPolicy::default());
        assert_dropped(&outcome, DropReason::Ipv4TotalLengthExceedsPacket);
        assert_eq!(
            outcome.disposition,
            Some(Icmpv4ErrorDisposition::ParameterProblemQueued {
                egress: LAN,
                quote_len: 32,
                pointer: 2,
            })
        );
        // The quote is what arrived: the claimed Total Length included.
        assert_eq!(
            outcome.generated.unwrap(),
            expected_error(12, 0, [2, 0, 0, 0], &received[14..])
        );
        assert_eq!(outcome.counters.queued_parameter_problem, 1);
    }
}

#[test]
fn truncated_datagrams_without_a_route_or_a_valid_checksum_stay_silent() {
    for (received, reason) in [
        (
            truncated(udp(MISSING, 7, true), 10, false),
            DropReason::Ipv4TotalLengthExceedsPacket,
        ),
        (
            truncated(udp(LAN_IP, 7, true), 10, true),
            DropReason::Ipv4TotalLengthExceedsPacket,
        ),
    ] {
        let outcome = one(received, Icmpv4ErrorPolicy::default());
        assert_dropped(&outcome, reason);
        assert_eq!(outcome.disposition, None);
        assert_eq!(outcome.counters, Icmpv4ErrorCounters::default());
    }
}

#[test]
fn a_truncated_icmp_error_is_never_answered() {
    let mut message = vec![3, 1, 0, 0, 0, 0, 0, 0];
    message.extend_from_slice(&[0x45; 28]);
    let checksum = internet_checksum(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    let received = truncated(frame(ROUTED, 1, 0, &[], &message, 0), 4, false);
    let outcome = one(received, Icmpv4ErrorPolicy::default());
    assert_dropped(&outcome, DropReason::Ipv4TotalLengthExceedsPacket);
    assert_eq!(
        outcome.disposition,
        Some(Icmpv4ErrorDisposition::IcmpErrorMessage)
    );
}

#[test]
fn malformed_options_get_parameter_problem_at_the_offending_octet() {
    let address = ROUTED.octets();
    let cases: [(Ipv4Address, Vec<u8>, u8); 4] = [
        // Record Route whose length runs past the header: the length.
        (LAN_IP, vec![7, 36, 4, 0], 21),
        // An option length below 2 after a NOP: the length.
        (ROUTED, vec![1, 68, 1, 0], 22),
        // A second source route: its first octet (RFC 1812 §5.2.4.1).
        (LAN_IP, vec![131, 3, 4, 131, 3, 4, 0, 0], 23),
        // Strict source route in a datagram not for the router: the
        // destination address (RFC 1812 §5.2.2).
        (
            ROUTED,
            vec![137, 7, 4, address[0], address[1], address[2], address[3], 0],
            16,
        ),
    ];
    for (destination, options, pointer) in cases {
        let received = frame(destination, 17, 0x4000, &options, &[0; 12], 2);
        let outcome = one(received.clone(), Icmpv4ErrorPolicy::default());
        assert_dropped(&outcome, DropReason::Ipv4OptionsUnsupported);
        assert_eq!(
            outcome.generated.unwrap(),
            expected_error(12, 0, [pointer, 0, 0, 0], datagram(&received)),
            "pointer {pointer}"
        );
    }
}

#[test]
fn well_formed_options_and_problems_after_a_source_route_stay_silent() {
    for options in [
        vec![1, 1, 1, 0],
        vec![131, 7, 4, 192, 0, 2, 7, 0],
        // Malformed after a source route: the error would need the
        // reversed route (RFC 1812 §4.3.2.6), so none is sent.
        vec![131, 3, 4, 7, 0, 0, 0, 0],
    ] {
        for destination in [LAN_IP, ROUTED] {
            let received = frame(destination, 17, 0x4000, &options, &[0; 12], 0);
            let outcome = one(received, Icmpv4ErrorPolicy::default());
            assert_dropped(&outcome, DropReason::Ipv4OptionsUnsupported);
            assert_eq!(outcome.disposition, None);
            assert_eq!(outcome.counters, Icmpv4ErrorCounters::default());
        }
    }
}

/// `frame` with its IPv4 source replaced (header checksum recomputed).
fn from_source(mut frame: Vec<u8>, source: Ipv4Address) -> Vec<u8> {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    frame[26..30].copy_from_slice(&source.octets());
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..14 + header_len]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

#[test]
fn broadcast_destinations_never_get_port_unreachable() {
    let limited = udp(Ipv4Address::from_octets([255; 4]), 9, true);
    let directed = udp(Ipv4Address::from_octets([192, 0, 2, 255]), 9, true);
    let mut link_broadcast = udp(LAN_IP, 9, true);
    link_broadcast[0..6].fill(0xff);
    for (received, reason) in [
        (limited, DropReason::Ipv4DestinationLimitedBroadcast),
        (directed, DropReason::Ipv4DestinationDirectedBroadcast),
        (link_broadcast, DropReason::Ipv4EthernetDestinationBroadcast),
    ] {
        let outcome = one(received, Icmpv4ErrorPolicy::default());
        assert_dropped(&outcome, reason);
        assert_eq!(outcome.disposition, None);
        assert_eq!(outcome.counters, Icmpv4ErrorCounters::default());
        assert!(outcome.generated.is_none());
    }
}

#[test]
fn non_host_sources_never_get_an_icmp_err_error() {
    let sources = [
        (
            Ipv4Address::from_octets([0, 1, 2, 3]),
            DropReason::Ipv4SourceUnspecifiedNetwork,
        ),
        (
            Ipv4Address::from_octets([127, 0, 0, 1]),
            DropReason::Ipv4SourceLoopback,
        ),
        (
            Ipv4Address::from_octets([240, 0, 0, 1]),
            DropReason::Ipv4SourceClassE,
        ),
        (
            Ipv4Address::from_octets([224, 0, 0, 1]),
            DropReason::Ipv4SourceMulticast,
        ),
        (
            Ipv4Address::from_octets([192, 0, 2, 255]),
            DropReason::Ipv4SourceDirectedBroadcast,
        ),
    ];
    for (source, reason) in sources {
        let datagrams = [
            (udp(LAN_IP, 9, false), reason),
            (frame(LAN_IP, 47, 0, &[], &[0; 8], 0), reason),
            (
                frame(LAN_IP, 17, 0x4000, &[7, 36, 4, 0], &[0; 12], 0),
                reason,
            ),
            (
                frame(ROUTED, 17, 0x4000, &[7, 36, 4, 0], &[0; 12], 0),
                reason,
            ),
        ];
        for (received, reason) in datagrams {
            let outcome = one(from_source(received, source), Icmpv4ErrorPolicy::default());
            assert_dropped(&outcome, reason);
            assert_eq!(
                outcome.counters,
                Icmpv4ErrorCounters::default(),
                "{source:?}"
            );
        }
        // A truncated datagram is refused for its length; the source check
        // still keeps it silent.
        let truncated = truncated(from_source(udp(LAN_IP, 9, false), source), 8, false);
        let outcome = one(truncated, Icmpv4ErrorPolicy::default());
        assert_dropped(&outcome, DropReason::Ipv4TotalLengthExceedsPacket);
        assert_eq!(
            outcome.counters,
            Icmpv4ErrorCounters::default(),
            "{source:?}"
        );
    }
}

#[test]
fn source_route_and_record_route_bodies_are_checked() {
    let address = ROUTED.octets();
    let cases: [(Vec<u8>, u8); 5] = [
        // Record Route of length 4 (not 3 plus whole addresses): the length.
        (vec![7, 4, 4, 0], 21),
        // Loose source route with pointer 3: the pointer.
        (
            vec![131, 7, 3, address[0], address[1], address[2], address[3], 0],
            22,
        ),
        // Record Route of length 2: the length.
        (vec![7, 2, 1, 0], 21),
        // Timestamp with pointer 4: the pointer.
        (vec![68, 4, 4, 0], 22),
        // Timestamp of length 3: the length.
        (vec![68, 3, 5, 0], 21),
    ];
    for (options, pointer) in cases {
        let received = frame(LAN_IP, 17, 0x4000, &options, &[0; 12], 0);
        let outcome = one(received.clone(), Icmpv4ErrorPolicy::default());
        assert_dropped(&outcome, DropReason::Ipv4OptionsUnsupported);
        assert_eq!(
            outcome.generated.unwrap(),
            expected_error(12, 0, [pointer, 0, 0, 0], datagram(&received)),
            "options {options:?}"
        );
    }
}

#[test]
fn a_strict_source_route_to_another_router_address_is_for_the_router() {
    // WAN_IP is the router's, though not on the LAN ingress (ICMP4-001):
    // no "not for the router" Parameter Problem, a well-formed option.
    let address = ROUTED.octets();
    let options = vec![137, 7, 4, address[0], address[1], address[2], address[3], 0];
    let outcome = one(
        frame(WAN_IP, 17, 0x4000, &options, &[0; 12], 0),
        Icmpv4ErrorPolicy::default(),
    );
    assert_dropped(&outcome, DropReason::Ipv4OptionsUnsupported);
    assert_eq!(outcome.counters, Icmpv4ErrorCounters::default());
}

#[test]
fn without_port_unreachable_the_udp_checksum_is_not_read() {
    let mut bad_checksum = udp(LAN_IP, 53, true);
    bad_checksum[41] ^= 1;
    let policy = Icmpv4ErrorPolicy::default()
        .with_generation(Icmpv4ErrorKind::DestinationUnreachableLocalPort, false);
    let outcome = one(bad_checksum, policy);
    assert_dropped(&outcome, DropReason::Ipv4LocalUdpPortUnreachable);
    assert_eq!(outcome.counters.disabled_udp_port_unreachable, 1);
    assert!(outcome.generated.is_none());
    // A broken header is still refused as invalid.
    let header_only = frame(LAN_IP, 17, 0, &[], &[0, 1, 0, 2], 0);
    assert_dropped(&one(header_only, policy), DropReason::Ipv4LocalUdpInvalid);
}

#[test]
fn admin_prohibited_is_the_only_kind_off_by_default() {
    let policy = Icmpv4ErrorPolicy::default();
    for kind in [
        Icmpv4ErrorKind::TimeExceededTtl,
        Icmpv4ErrorKind::DestinationUnreachableNetwork,
        Icmpv4ErrorKind::DestinationUnreachableHost,
        Icmpv4ErrorKind::DestinationUnreachablePort,
        Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded,
        Icmpv4ErrorKind::DestinationUnreachableProtocol,
        Icmpv4ErrorKind::DestinationUnreachableLocalPort,
        Icmpv4ErrorKind::ParameterProblem,
    ] {
        assert!(policy.generates(kind), "{kind:?}");
    }
    assert!(!policy.generates(Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited));
    assert_eq!(Icmpv4ErrorPolicy::new(100, 60_000).unwrap(), policy);
}

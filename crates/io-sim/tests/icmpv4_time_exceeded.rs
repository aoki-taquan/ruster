use std::convert::Infallible;

use ruster_core::{
    execute_one_arp_request, execute_one_icmpv4_time_exceeded,
    forward_batch_with_resolution_and_icmpv4_errors, internet_checksum, ipv4_header_checksum,
    DropReason, DynamicNeighborSlot, ForwardingSnapshot, GeneratedAllocationError,
    GeneratedBatchCompletion, GeneratedIcmpv4Trace, GeneratedPacketBatch, GeneratedPacketIo,
    GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, Icmpv4ErrorActionSlot,
    Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, Icmpv4TimeExceededBuildError,
    Icmpv4TimeExceededDisposition, IfId, Interface, Ipv4Mtu, Ipv4Address, Ipv4OriginPolicy,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, NoGeneratedIcmpv4Trace,
    NoGeneratedTrace, NoTrace, PacketIo, ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime,
    ResolutionStateSlot, Route, TraceEvent,
};
use ruster_io_sim::{
    FrameOrigin, GeneratedRecycleCause, RecycleCause, SimIo, VecGeneratedIcmpv4Trace, VecTrace,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const PREVIOUS_HOP_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xaa];
const REVERSE_GATEWAY_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0xbb]);
const FORWARD_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0xcc]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const SOURCE: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 9]);
const DESTINATION: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 9]);
const REVERSE_GATEWAY: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 254]);

fn interfaces() -> [Interface; 2] {
    [
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
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

fn routes() -> [Route; 3] {
    [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, WAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([203, 0, 113, 0]),
            24,
            WAN,
            Some(REVERSE_GATEWAY),
        )
        .unwrap(),
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap(),
    ]
}

fn neighbors() -> [Neighbor; 2] {
    [
        Neighbor {
            interface: WAN,
            target: REVERSE_GATEWAY,
            mac: REVERSE_GATEWAY_MAC,
        },
        Neighbor {
            interface: WAN,
            target: DESTINATION,
            mac: FORWARD_MAC,
        },
    ]
}

#[allow(clippy::too_many_arguments)]
fn frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    ttl: u8,
    protocol: u8,
    flags_fragment: u16,
    tos: u8,
    body: &[u8],
    padding: &[u8],
) -> Vec<u8> {
    let total_len = 20 + body.len();
    let mut bytes = vec![0; 14 + total_len + padding.len()];
    bytes[0..6].copy_from_slice(&LAN_MAC.0);
    bytes[6..12].copy_from_slice(&PREVIOUS_HOP_MAC);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[15] = tos;
    bytes[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    bytes[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    bytes[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    bytes[22] = ttl;
    bytes[23] = protocol;
    bytes[26..30].copy_from_slice(&source.octets());
    bytes[30..34].copy_from_slice(&destination.octets());
    bytes[34..34 + body.len()].copy_from_slice(body);
    bytes[34 + body.len()..].copy_from_slice(padding);
    let checksum = ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn replace_ipv4_word(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    bytes[24..26].fill(0);
    let header_len = usize::from(bytes[14] & 0x0f) * 4;
    let checksum = ipv4_header_checksum(&bytes[14..14 + header_len]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
}

fn resolution_policy() -> ResolutionPolicy {
    ResolutionPolicy::new(1_000, 60_000).unwrap()
}

fn error_disposition(
    snapshot: &ForwardingSnapshot<'_>,
    packet: Vec<u8>,
) -> Icmpv4TimeExceededDisposition {
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, packet);
    let mut trace = VecTrace::default();
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut trace,
    );
    trace
        .events()
        .iter()
        .find_map(|event| match event {
            TraceEvent::Icmpv4TimeExceededDisposition { disposition, .. } => Some(*disposition),
            _ => None,
        })
        .expect("TTL-expired packet has a typed ICMP disposition")
}

fn forwarding_drop_reason(snapshot: &ForwardingSnapshot<'_>, packet: Vec<u8>) -> DropReason {
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, packet);
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    match io.pop_recycled().unwrap().cause {
        RecycleCause::Forwarding(reason) => reason,
        cause => panic!("expected forwarding drop, got {cause:?}"),
    }
}

#[test]
fn ttl_expiry_is_atomic_and_generates_exact_asymmetric_static_reply() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::with_ipv4_origin_policy(
        &routes,
        &interfaces,
        &neighbors,
        &bindings,
        Ipv4OriginPolicy::new(37).unwrap(),
    )
    .unwrap();
    let original = frame(
        SOURCE,
        DESTINATION,
        1,
        17,
        0,
        0x2f,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9],
        &[0xde, 0xad],
    );
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors(
        resolution_policy(),
        &mut resolution_states,
        &mut resolution_actions,
        &mut dynamic,
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();
    io.inject(LAN, original.clone());
    let mut trace = VecTrace::default();
    let batch = io.receive(1).unwrap();

    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(1_000),
        &mut trace,
    );

    assert_eq!(
        (report.received, report.dropped, report.tx_requested),
        (1, 1, 0)
    );
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Ipv4TtlExpired)
    );
    assert_eq!(recycled.bytes, original);
    assert_eq!(errors.pending_actions(), 1);
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::Ipv4Validated {
                ingress: LAN,
                destination: DESTINATION
            },
            TraceEvent::Icmpv4TimeExceededDisposition {
                ingress: LAN,
                disposition: Icmpv4TimeExceededDisposition::Queued {
                    egress: WAN,
                    quote_len: 29
                }
            },
            TraceEvent::Dropped {
                ingress: LAN,
                reason: DropReason::Ipv4TtlExpired
            },
            TraceEvent::BatchCompleted {
                tx_accepted: 0,
                tx_rejected: 0
            }
        ]
    ));

    let mut generated_trace = VecGeneratedIcmpv4Trace::default();
    let generated = execute_one_icmpv4_time_exceeded(
        &mut io,
        &mut errors,
        MonotonicMillis(1_000),
        &mut generated_trace,
    )
    .unwrap()
    .unwrap();
    assert!(generated.completion.invariants_hold());
    assert_eq!(
        (generated.completion.accepted, generated.completion.rejected),
        (1, 0)
    );
    assert_eq!(
        generated_trace.events(),
        [
            GeneratedIcmpv4Trace::TxRequested {
                egress: WAN,
                destination: SOURCE
            },
            GeneratedIcmpv4Trace::BatchCompleted {
                accepted: 1,
                rejected: 0
            }
        ]
    );
    let tx = io.pop_tx().unwrap();
    assert_eq!(tx.origin, FrameOrigin::Generated);
    assert_eq!((tx.ingress, tx.egress), (WAN, WAN));
    assert_eq!(tx.bytes.len(), 71);
    assert_eq!(&tx.bytes[0..6], &REVERSE_GATEWAY_MAC.0);
    assert_eq!(&tx.bytes[6..12], &WAN_MAC.0);
    assert_ne!(&tx.bytes[0..6], &PREVIOUS_HOP_MAC);
    assert_eq!(tx.bytes[14], 0x45);
    assert_eq!(tx.bytes[15], 0xce);
    assert_eq!(u16::from_be_bytes([tx.bytes[16], tx.bytes[17]]), 57);
    assert_eq!(&tx.bytes[18..20], &[0, 0]);
    assert_eq!(&tx.bytes[20..22], &0x4000_u16.to_be_bytes());
    assert_eq!(tx.bytes[22], 37);
    assert_eq!(tx.bytes[23], 1);
    assert_eq!(&tx.bytes[26..30], &WAN_IP.octets());
    assert_eq!(&tx.bytes[30..34], &SOURCE.octets());
    assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
    assert_eq!(
        &tx.bytes[34..42],
        &[11, 0, tx.bytes[36], tx.bytes[37], 0, 0, 0, 0]
    );
    assert_eq!(internet_checksum(&tx.bytes[34..]), 0);
    assert_eq!(&tx.bytes[42..], &original[14..43]);
}

#[test]
fn selected_gateway_prefix_suppresses_remote_boundaries_but_lpm_host_routes_win() {
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = neighbors();
    let gateway_destination = Route::new(
        Ipv4Address::from_octets([172, 16, 1, 0]),
        24,
        WAN,
        Some(REVERSE_GATEWAY),
    )
    .unwrap();
    let base_routes = [gateway_destination, routes()[1], routes()[2]];
    let base = ForwardingSnapshot::new(&base_routes, &interfaces, &neighbors, &bindings).unwrap();
    assert_eq!(
        forwarding_drop_reason(
            &base,
            frame(
                SOURCE,
                Ipv4Address::from_octets([172, 16, 1, 255]),
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
        ),
        DropReason::Ipv4DestinationDirectedBroadcast
    );
    assert_eq!(
        forwarding_drop_reason(
            &base,
            frame(
                SOURCE,
                Ipv4Address::from_octets([172, 16, 1, 0]),
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
        ),
        DropReason::Ipv4DestinationNetworkAddress
    );
    for source in [
        Ipv4Address::from_octets([203, 0, 113, 0]),
        Ipv4Address::from_octets([203, 0, 113, 255]),
    ] {
        assert_eq!(
            forwarding_drop_reason(
                &base,
                frame(
                    source,
                    Ipv4Address::from_octets([172, 16, 1, 1]),
                    1,
                    17,
                    0,
                    0,
                    &[],
                    &[],
                ),
            ),
            if source == Ipv4Address::from_octets([203, 0, 113, 0]) {
                DropReason::Ipv4SourceNetworkAddress
            } else {
                DropReason::Ipv4SourceDirectedBroadcast
            }
        );
    }

    let host_destination_routes = [
        gateway_destination,
        Route::new(
            Ipv4Address::from_octets([172, 16, 1, 0]),
            32,
            WAN,
            Some(REVERSE_GATEWAY),
        )
        .unwrap(),
        Route::new(
            Ipv4Address::from_octets([172, 16, 1, 255]),
            32,
            WAN,
            Some(REVERSE_GATEWAY),
        )
        .unwrap(),
        routes()[1],
        routes()[2],
    ];
    let host_destination =
        ForwardingSnapshot::new(&host_destination_routes, &interfaces, &neighbors, &bindings)
            .unwrap();
    for destination in [
        Ipv4Address::from_octets([172, 16, 1, 0]),
        Ipv4Address::from_octets([172, 16, 1, 255]),
    ] {
        assert!(matches!(
            error_disposition(
                &host_destination,
                frame(SOURCE, destination, 1, 17, 0, 0, &[], &[]),
            ),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
    }

    let point_to_point_destination_routes = [
        gateway_destination,
        Route::new(
            Ipv4Address::from_octets([172, 16, 1, 254]),
            31,
            WAN,
            Some(REVERSE_GATEWAY),
        )
        .unwrap(),
        routes()[1],
        routes()[2],
    ];
    let point_to_point_destination = ForwardingSnapshot::new(
        &point_to_point_destination_routes,
        &interfaces,
        &neighbors,
        &bindings,
    )
    .unwrap();
    for destination in [
        Ipv4Address::from_octets([172, 16, 1, 254]),
        Ipv4Address::from_octets([172, 16, 1, 255]),
    ] {
        assert!(matches!(
            error_disposition(
                &point_to_point_destination,
                frame(SOURCE, destination, 1, 17, 0, 0, &[], &[]),
            ),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
    }

    let host_source = Ipv4Address::from_octets([203, 0, 113, 0]);
    let host_source_routes = [
        gateway_destination,
        routes()[1],
        Route::new(host_source, 32, WAN, Some(REVERSE_GATEWAY)).unwrap(),
        routes()[2],
    ];
    let host_source_snapshot =
        ForwardingSnapshot::new(&host_source_routes, &interfaces, &neighbors, &bindings).unwrap();
    assert!(matches!(
        error_disposition(
            &host_source_snapshot,
            frame(
                host_source,
                Ipv4Address::from_octets([172, 16, 1, 1]),
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
        ),
        Icmpv4TimeExceededDisposition::Queued { .. }
    ));

    let point_to_point_source = Ipv4Address::from_octets([203, 0, 113, 0]);
    let point_to_point_routes = [
        gateway_destination,
        Route::new(
            Ipv4Address::from_octets([203, 0, 113, 0]),
            31,
            WAN,
            Some(REVERSE_GATEWAY),
        )
        .unwrap(),
        routes()[2],
    ];
    let point_to_point =
        ForwardingSnapshot::new(&point_to_point_routes, &interfaces, &neighbors, &bindings)
            .unwrap();
    for source in [
        point_to_point_source,
        Ipv4Address::from_octets([203, 0, 113, 1]),
    ] {
        assert!(matches!(
            error_disposition(
                &point_to_point,
                frame(
                    source,
                    Ipv4Address::from_octets([172, 16, 1, 1]),
                    1,
                    17,
                    0,
                    0,
                    &[],
                    &[],
                ),
            ),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
    }
}

#[test]
fn quote_boundaries_exclude_padding_and_zero_generated_padding() {
    for (total_len, padding_len, expected_quote, expected_frame) in [
        (20, 7, 20, 62),
        (28, 3, 28, 70),
        (29, 0, 29, 71),
        (548, 0, 548, 590),
        (549, 11, 548, 590),
        (700, 0, 548, 590),
    ] {
        let interfaces = interfaces();
        let bindings = bindings();
        let routes = routes();
        let neighbors = neighbors();
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let body = vec![0x5a; total_len - 20];
        let padding = vec![0xee; padding_len];
        let original = frame(SOURCE, DESTINATION, 0, 6, 0, 0, &body, &padding);
        let mut rs = [ResolutionStateSlot::EMPTY; 1];
        let mut ra = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
        let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
        let mut io = SimIo::new();
        io.inject(LAN, original.clone());
        let batch = io.receive(1).unwrap();
        forward_batch_with_resolution_and_icmpv4_errors(
            batch,
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(0),
            &mut NoTrace,
        );
        let generated = execute_one_icmpv4_time_exceeded(
            &mut io,
            &mut errors,
            MonotonicMillis(0),
            &mut NoGeneratedIcmpv4Trace,
        )
        .unwrap()
        .unwrap();
        assert_eq!(generated.action.quote_len(), expected_quote);
        let tx = io.pop_tx().unwrap();
        assert_eq!(tx.bytes.len(), expected_frame);
        assert_eq!(
            &tx.bytes[42..42 + expected_quote],
            &original[14..14 + expected_quote]
        );
        let outer_total = usize::from(u16::from_be_bytes([tx.bytes[16], tx.bytes[17]]));
        assert!(tx.bytes[14 + outer_total..].iter().all(|byte| *byte == 0));
        assert_eq!(internet_checksum(&tx.bytes[34..14 + outer_total]), 0);
    }
}

#[test]
fn ttl_two_forwards_normally_while_zero_generates() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, frame(SOURCE, DESTINATION, 0, 17, 0, 0, &[], &[]));
    io.inject(LAN, frame(SOURCE, DESTINATION, 2, 17, 0, 0, &[], &[]));
    let batch = io.receive(2).unwrap();
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!((report.dropped, report.tx_requested), (1, 1));
    let forwarded = io.pop_tx().unwrap();
    assert_eq!(forwarded.bytes[22], 1);
    assert_eq!(errors.pending_actions(), 1);
}

#[test]
fn rfc1812_suppression_matrix_is_typed_and_byte_atomic() {
    let cases = [
        (
            frame(
                Ipv4Address::from_octets([0, 1, 2, 3]),
                DESTINATION,
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::SourceNotUnicast,
        ),
        (
            frame(
                Ipv4Address::from_octets([127, 0, 0, 1]),
                DESTINATION,
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::SourceNotUnicast,
        ),
        (
            frame(
                Ipv4Address::from_octets([224, 0, 0, 1]),
                DESTINATION,
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::SourceNotUnicast,
        ),
        (
            frame(
                Ipv4Address::from_octets([240, 0, 0, 1]),
                DESTINATION,
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::SourceNotUnicast,
        ),
        (
            frame(
                Ipv4Address::from_octets([255; 4]),
                DESTINATION,
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::SourceNotUnicast,
        ),
        (
            frame(
                Ipv4Address::from_octets([192, 0, 2, 0]),
                DESTINATION,
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::SourceNotUnicast,
        ),
        (
            frame(
                Ipv4Address::from_octets([192, 0, 2, 255]),
                DESTINATION,
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::SourceNotUnicast,
        ),
        (
            frame(LAN_IP, DESTINATION, 1, 17, 0, 0, &[], &[]),
            Icmpv4TimeExceededDisposition::SourceIsLocal,
        ),
        (
            frame(
                SOURCE,
                Ipv4Address::from_octets([224, 0, 0, 1]),
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::DestinationMulticast,
        ),
        (
            frame(
                SOURCE,
                Ipv4Address::from_octets([255; 4]),
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::DestinationLimitedBroadcast,
        ),
        (
            frame(
                SOURCE,
                Ipv4Address::from_octets([10, 0, 0, 0]),
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::DestinationNetworkAddress,
        ),
        (
            frame(
                SOURCE,
                Ipv4Address::from_octets([10, 0, 0, 255]),
                1,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4TimeExceededDisposition::DestinationDirectedBroadcast,
        ),
        (
            frame(SOURCE, DESTINATION, 1, 17, 1, 0, &[], &[]),
            Icmpv4TimeExceededDisposition::NonInitialFragment,
        ),
        (
            frame(SOURCE, DESTINATION, 1, 1, 0, 0, &[3, 0, 0, 0], &[]),
            Icmpv4TimeExceededDisposition::IcmpErrorMessage,
        ),
        (
            frame(SOURCE, DESTINATION, 1, 1, 0, 0, &[4], &[]),
            Icmpv4TimeExceededDisposition::IcmpErrorMessage,
        ),
        (
            frame(SOURCE, DESTINATION, 1, 1, 0, 0, &[5], &[]),
            Icmpv4TimeExceededDisposition::IcmpErrorMessage,
        ),
        (
            frame(SOURCE, DESTINATION, 1, 1, 0, 0, &[11], &[]),
            Icmpv4TimeExceededDisposition::IcmpErrorMessage,
        ),
        (
            frame(SOURCE, DESTINATION, 1, 1, 0, 0, &[12], &[]),
            Icmpv4TimeExceededDisposition::IcmpErrorMessage,
        ),
        (
            frame(SOURCE, DESTINATION, 1, 1, 0, 0, &[], &[]),
            Icmpv4TimeExceededDisposition::IcmpTypeMissing,
        ),
    ];
    for (mut original, expected) in cases {
        let admission_reason = match expected {
            Icmpv4TimeExceededDisposition::SourceNotUnicast => {
                if original[26..30] == [255; 4] {
                    Some(DropReason::Ipv4SourceLimitedBroadcast)
                } else {
                    match original[26] {
                        0 => Some(DropReason::Ipv4SourceUnspecifiedNetwork),
                        127 => Some(DropReason::Ipv4SourceLoopback),
                        224..=239 => Some(DropReason::Ipv4SourceMulticast),
                        240..=255 => Some(DropReason::Ipv4SourceClassE),
                        _ if original[26..30] == [192, 0, 2, 0] => {
                            Some(DropReason::Ipv4SourceNetworkAddress)
                        }
                        _ => Some(DropReason::Ipv4SourceDirectedBroadcast),
                    }
                }
            }
            Icmpv4TimeExceededDisposition::SourceIsLocal => {
                Some(DropReason::Ipv4SourceLocalAddress)
            }
            Icmpv4TimeExceededDisposition::DestinationMulticast => {
                Some(DropReason::Ipv4DestinationMulticast)
            }
            Icmpv4TimeExceededDisposition::DestinationLimitedBroadcast => {
                Some(DropReason::Ipv4DestinationLimitedBroadcast)
            }
            Icmpv4TimeExceededDisposition::DestinationNetworkAddress => {
                Some(DropReason::Ipv4DestinationNetworkAddress)
            }
            Icmpv4TimeExceededDisposition::DestinationDirectedBroadcast => {
                Some(DropReason::Ipv4DestinationDirectedBroadcast)
            }
            _ => None,
        };
        if matches!(
            expected,
            Icmpv4TimeExceededDisposition::DestinationMulticast
                | Icmpv4TimeExceededDisposition::DestinationLimitedBroadcast
        ) {
            original[0..6].copy_from_slice(&LAN_MAC.0);
        }
        let interfaces = interfaces();
        let bindings = bindings();
        let routes = routes();
        let neighbors = neighbors();
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let mut rs = [ResolutionStateSlot::EMPTY; 1];
        let mut ra = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
        let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
        let mut io = SimIo::new();
        io.inject(LAN, original.clone());
        let mut trace = VecTrace::default();
        let batch = io.receive(1).unwrap();
        forward_batch_with_resolution_and_icmpv4_errors(
            batch,
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(0),
            &mut trace,
        );
        assert_eq!(errors.pending_actions(), 0, "{expected:?}");
        let recycled = io.pop_recycled().unwrap();
        assert_eq!(recycled.bytes, original);
        if let Some(reason) = admission_reason {
            assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
            assert!(!trace.events().iter().any(|event| matches!(
                event,
                TraceEvent::Icmpv4TimeExceededDisposition { .. }
                    | TraceEvent::Icmpv4DestinationUnreachableDisposition { .. }
            )));
            continue;
        }
        assert!(trace.events().iter().any(|event| {
            matches!(
                event,
                TraceEvent::Icmpv4TimeExceededDisposition { disposition, .. }
                    | TraceEvent::Icmpv4DestinationUnreachableDisposition { disposition, .. }
                    if *disposition == expected
            )
        }));
    }

    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut first_fragment = frame(SOURCE, DESTINATION, 1, 1, 0x2000, 0, &[8], &[]);
    first_fragment[0..6].copy_from_slice(&LAN_MAC.0);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, first_fragment);
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(
        errors.pending_actions(),
        1,
        "first fragment/query is eligible"
    );
}

#[test]
fn ethernet_group_destination_and_options_suppress_without_mutation() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut group = frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]);
    group[0] = 0x01;
    let mut options = frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]);
    options.splice(34..34, [0, 0, 0, 0]);
    options[14] = 0x46;
    replace_ipv4_word(&mut options, 16, 24);
    for (original, reason) in [
        (group, DropReason::Ipv4EthernetDestinationMulticast),
        (options, DropReason::Ipv4OptionsUnsupported),
    ] {
        let mut rs = [ResolutionStateSlot::EMPTY; 1];
        let mut ra = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
        let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
        let mut io = SimIo::new();
        io.inject(LAN, original.clone());
        let batch = io.receive(1).unwrap();
        forward_batch_with_resolution_and_icmpv4_errors(
            batch,
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(0),
            &mut NoTrace,
        );
        let recycled = io.pop_recycled().unwrap();
        assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
        assert_eq!(recycled.bytes, original);
        assert_eq!(errors.pending_actions(), 0);
    }
}

#[test]
fn reverse_route_binding_target_and_clock_failures_are_typed_without_actions() {
    let interfaces = interfaces();
    let bindings = bindings();
    let all_routes = routes();
    let reverse_gateway_neighbor = [Neighbor {
        interface: WAN,
        target: REVERSE_GATEWAY,
        mac: REVERSE_GATEWAY_MAC,
    }];
    let no_reverse_routes = [all_routes[0], all_routes[2]];
    let no_reverse = ForwardingSnapshot::new(
        &no_reverse_routes,
        &interfaces,
        &reverse_gateway_neighbor,
        &bindings,
    )
    .unwrap();
    let no_wan_binding = [bindings[0]];
    let no_binding = ForwardingSnapshot::new(
        &all_routes,
        &interfaces,
        &reverse_gateway_neighbor,
        &no_wan_binding,
    )
    .unwrap();
    let forbidden_routes = [
        all_routes[0],
        Route::new(
            Ipv4Address::from_octets([203, 0, 113, 0]),
            24,
            WAN,
            Some(WAN_IP),
        )
        .unwrap(),
        all_routes[2],
    ];
    let forbidden =
        ForwardingSnapshot::new(&forbidden_routes, &interfaces, &[], &bindings).unwrap();
    for (snapshot, expected) in [
        (&no_reverse, Icmpv4TimeExceededDisposition::ReverseRouteMiss),
        (
            &no_binding,
            Icmpv4TimeExceededDisposition::ReverseBindingMiss { egress: WAN },
        ),
        (
            &forbidden,
            Icmpv4TimeExceededDisposition::ReverseTargetForbidden {
                egress: WAN,
                target: WAN_IP,
            },
        ),
    ] {
        let mut rs = [ResolutionStateSlot::EMPTY; 1];
        let mut ra = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
        let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
        let mut io = SimIo::new();
        io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
        let mut trace = VecTrace::default();
        let batch = io.receive(1).unwrap();
        forward_batch_with_resolution_and_icmpv4_errors(
            batch,
            snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(10),
            &mut trace,
        );
        assert_eq!(errors.pending_actions(), 0);
        assert!(trace.events().iter().any(|event| matches!(
            event,
            TraceEvent::Icmpv4TimeExceededDisposition { disposition, .. }
                if *disposition == expected
        )));
    }

    let neighbors = neighbors();
    let valid = ForwardingSnapshot::new(&all_routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &valid,
        &mut resolution,
        &mut errors,
        MonotonicMillis(20),
        &mut NoTrace,
    );
    execute_one_icmpv4_time_exceeded(
        &mut io,
        &mut errors,
        MonotonicMillis(20),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap();
    io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    let mut trace = VecTrace::default();
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &valid,
        &mut resolution,
        &mut errors,
        MonotonicMillis(19),
        &mut trace,
    );
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::Icmpv4TimeExceededDisposition {
            disposition: Icmpv4TimeExceededDisposition::ClockRegression,
            ..
        }
    )));
    assert_eq!(errors.pending_actions(), 0);
}

fn arp_reply() -> Vec<u8> {
    let mut frame = vec![0; 60];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&REVERSE_GATEWAY_MAC.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18..22].copy_from_slice(&[6, 4, 0, 2]);
    frame[22..28].copy_from_slice(&REVERSE_GATEWAY_MAC.0);
    frame[28..32].copy_from_slice(&REVERSE_GATEWAY.octets());
    frame[32..38].copy_from_slice(&WAN_MAC.0);
    frame[38..42].copy_from_slice(&WAN_IP.octets());
    frame
}

#[test]
fn unresolved_reverse_neighbor_queues_only_arp_and_same_batch_learning_is_ordered() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 2];
    let mut ra = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors(
        resolution_policy(),
        &mut rs,
        &mut ra,
        &mut dynamic,
    );
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(errors.pending_actions(), 0);
    assert_eq!(resolution.pending_actions(), 1);
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap()
    .unwrap();
    let generated_arp = io.pop_tx().unwrap();
    assert_eq!(generated_arp.egress, WAN);
    assert_eq!(&generated_arp.bytes[38..42], &REVERSE_GATEWAY.octets());

    io.inject(WAN, arp_reply());
    io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    let batch = io.receive(2).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(1),
        &mut NoTrace,
    );
    assert_eq!(errors.pending_actions(), 1);

    let mut rs2 = [ResolutionStateSlot::EMPTY; 2];
    let mut ra2 = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic2 = [DynamicNeighborSlot::EMPTY; 1];
    let mut resolution2 = ResolutionRuntime::with_dynamic_neighbors(
        resolution_policy(),
        &mut rs2,
        &mut ra2,
        &mut dynamic2,
    );
    let mut es2 = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea2 = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors2 = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es2, &mut ea2);
    let mut io2 = SimIo::new();
    io2.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    io2.inject(WAN, arp_reply());
    let batch = io2.receive(2).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution2,
        &mut errors2,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(errors2.pending_actions(), 0, "later ARP is not retroactive");
}

#[test]
fn connected_reverse_route_uses_original_source_as_neighbor_target() {
    let interfaces = interfaces();
    let bindings = bindings();
    let connected_routes = [
        routes()[0],
        Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, WAN, None).unwrap(),
        routes()[2],
    ];
    let source_mac = MacAddress([0x02, 0, 0, 0, 0, 0xdd]);
    let neighbors = [Neighbor {
        interface: WAN,
        target: SOURCE,
        mac: source_mac,
    }];
    let snapshot =
        ForwardingSnapshot::new(&connected_routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    execute_one_icmpv4_time_exceeded(
        &mut io,
        &mut errors,
        MonotonicMillis(0),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap();
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &source_mac.0);
}

#[test]
fn allocation_build_and_backend_reject_lifecycles_are_exact() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::new(100, 1_000).unwrap(),
        &mut es,
        &mut ea,
    );
    let mut io = SimIo::new();
    io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    io.set_generated_budget(0);
    let failed = execute_one_icmpv4_time_exceeded(
        &mut io,
        &mut errors,
        MonotonicMillis(0),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        failed.allocation_error,
        Some(GeneratedAllocationError::Unavailable)
    );
    assert!(failed.completion.invariants_hold());
    assert_eq!(errors.pending_actions(), 1);

    let built = execute_one_icmpv4_time_exceeded(
        &mut ShortBufferIo,
        &mut errors,
        MonotonicMillis(0),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        built.build_error,
        Some(Icmpv4TimeExceededBuildError::ExactLengthRequired)
    );
    assert_eq!(built.completion.cancelled, 1);
    assert!(built.completion.invariants_hold());
    assert_eq!(errors.pending_actions(), 1);

    io.set_generated_budget(1);
    io.set_generated_accept_budget(0);
    io.fail_next_generated_finish();
    let rejected = execute_one_icmpv4_time_exceeded(
        &mut io,
        &mut errors,
        MonotonicMillis(0),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        (rejected.completion.accepted, rejected.completion.rejected),
        (0, 1)
    );
    assert!(rejected.completion.error.is_some());
    assert_eq!(errors.pending_actions(), 0);
    assert_eq!(
        io.pop_generated_recycled().unwrap().cause,
        GeneratedRecycleCause::TxRejected
    );

    io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    let batch = io.receive(1).unwrap();
    let mut trace = VecTrace::default();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(99),
        &mut trace,
    );
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::Icmpv4TimeExceededDisposition {
            disposition: Icmpv4TimeExceededDisposition::RateLimited { egress: WAN },
            ..
        }
    )));
    io.inject(LAN, frame(SOURCE, DESTINATION, 1, 17, 0, 0, &[], &[]));
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(100),
        &mut NoTrace,
    );
    assert_eq!(errors.pending_actions(), 1);
}

struct ShortBufferIo;

struct ShortBufferBatch {
    cancelled: usize,
    abandoned: usize,
}

struct ShortBufferSlot<'a> {
    bytes: Vec<u8>,
    cancelled: &'a mut usize,
    abandoned: &'a mut usize,
}

impl GeneratedPacketIo for ShortBufferIo {
    type Error = Infallible;
    type Batch<'a> = ShortBufferBatch;

    fn begin_generated(&mut self, _egress: IfId) -> Self::Batch<'_> {
        ShortBufferBatch {
            cancelled: 0,
            abandoned: 0,
        }
    }
}

impl GeneratedPacketBatch for ShortBufferBatch {
    type Error = Infallible;
    type Slot<'a>
        = ShortBufferSlot<'a>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        Ok(GeneratedPacketLease::new(ShortBufferSlot {
            bytes: vec![0; frame_len - 1],
            cancelled: &mut self.cancelled,
            abandoned: &mut self.abandoned,
        }))
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        GeneratedBatchCompletion {
            attempts: 1,
            allocated: 1,
            failed: 0,
            requested: 0,
            cancelled: self.cancelled,
            abandoned: self.abandoned,
            accepted: 0,
            rejected: 0,
            error: None,
        }
    }
}

impl GeneratedPacketSlot for ShortBufferSlot<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        match completion {
            GeneratedSlotCompletion::Cancelled => *self.cancelled += 1,
            GeneratedSlotCompletion::Abandoned => *self.abandoned += 1,
            GeneratedSlotCompletion::Transmit => panic!("short buffer cannot be transmitted"),
        }
    }
}

use ruster_core::{
    execute_one_arp_request, execute_one_icmpv4_error, execute_one_icmpv4_time_exceeded,
    forward_batch, forward_batch_with_resolution, forward_batch_with_resolution_and_icmpv4_errors,
    internet_checksum, ipv4_header_checksum, DropReason, DynamicNeighborSlot, ExecuteIcmpv4Error,
    ForwardingSnapshot, GeneratedAllocationError, GeneratedIcmpv4Trace, Icmpv4ErrorActionSlot,
    Icmpv4ErrorDisposition, Icmpv4ErrorKind, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime,
    Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, Ipv4OriginPolicy, LocalIpv4Binding,
    MacAddress, MonotonicMillis, Neighbor, NoGeneratedIcmpv4Trace, NoTrace, PacketIo,
    ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
    TraceEvent,
};
use ruster_io_sim::{FrameOrigin, RecycleCause, SimIo, VecGeneratedIcmpv4Trace, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOP_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xaa];
const SOURCE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xbb]);
const GATEWAY_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xcc]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const SOURCE: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 9]);
const MISSING: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 9]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 254]);

fn interfaces() -> [Interface; 2] {
    [
        Interface {
            id: LAN,
            mac: LAN_MAC,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
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

fn reverse_connected() -> Route {
    Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, WAN, None).unwrap()
}

fn reverse_gateway() -> Route {
    Route::new(
        Ipv4Address::from_octets([203, 0, 113, 0]),
        24,
        WAN,
        Some(GATEWAY),
    )
    .unwrap()
}

fn forward_route() -> Route {
    Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, WAN, None).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn ipv4_frame(
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
    let mut frame = vec![0; 14 + total_len + padding.len()];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOP_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = tos;
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = ttl;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..34 + body.len()].copy_from_slice(body);
    frame[34 + body.len()..].copy_from_slice(padding);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn options_frame() -> Vec<u8> {
    let mut frame = ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &[], &[]);
    frame.splice(34..34, [0, 0, 0, 0]);
    frame[14] = 0x46;
    frame[16..18].copy_from_slice(&24_u16.to_be_bytes());
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..38]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn arp_reply(target: Ipv4Address, mac: MacAddress) -> Vec<u8> {
    let mut frame = vec![0; 60];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&mac.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18..22].copy_from_slice(&[6, 4, 0, 2]);
    frame[22..28].copy_from_slice(&mac.0);
    frame[28..32].copy_from_slice(&target.octets());
    frame[32..38].copy_from_slice(&WAN_MAC.0);
    frame[38..42].copy_from_slice(&WAN_IP.octets());
    frame
}

fn resolution_policy() -> ResolutionPolicy {
    ResolutionPolicy::new(1_000, 60_000).unwrap()
}

#[test]
fn route_miss_is_atomic_and_generates_exact_type3_code0() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = [reverse_gateway()];
    let neighbors = [Neighbor {
        interface: WAN,
        target: GATEWAY,
        mac: GATEWAY_MAC,
    }];
    let snapshot = ForwardingSnapshot::with_ipv4_origin_policy(
        &routes,
        &interfaces,
        &neighbors,
        &bindings,
        Ipv4OriginPolicy::new(37).unwrap(),
    )
    .unwrap();
    let original = ipv4_frame(
        SOURCE,
        MISSING,
        1,
        17,
        0,
        0x2f,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9],
        &[0xde, 0xad],
    );
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
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(10),
        &mut trace,
    );
    assert_eq!((report.dropped, report.tx_requested), (1, 0));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::RouteMiss)
    );
    assert_eq!(recycled.bytes, original);
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::Icmpv4DestinationUnreachableDisposition {
            disposition: Icmpv4ErrorDisposition::DestinationUnreachableQueued {
                egress: WAN,
                quote_len: 29,
            },
            ..
        }
    )));
    assert!(!trace
        .events()
        .iter()
        .any(|event| matches!(event, TraceEvent::Icmpv4TimeExceededDisposition { .. })));

    let mut generated_trace = VecGeneratedIcmpv4Trace::default();
    let generated = execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(10),
        &mut generated_trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        generated.action.kind,
        Icmpv4ErrorKind::DestinationUnreachableNetwork
    );
    assert_eq!(
        generated_trace.events(),
        [
            GeneratedIcmpv4Trace::DestinationUnreachableTxRequested {
                egress: WAN,
                destination: SOURCE,
            },
            GeneratedIcmpv4Trace::DestinationUnreachableBatchCompleted {
                accepted: 1,
                rejected: 0,
            }
        ]
    );
    let tx = io.pop_tx().unwrap();
    assert_eq!(tx.origin, FrameOrigin::Generated);
    assert_eq!(tx.bytes.len(), 71);
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC.0);
    assert_eq!(&tx.bytes[6..12], &WAN_MAC.0);
    assert_eq!(tx.bytes[15], 0xce);
    assert_eq!(u16::from_be_bytes([tx.bytes[16], tx.bytes[17]]), 57);
    assert_eq!(&tx.bytes[18..20], &[0, 0]);
    assert_eq!(&tx.bytes[20..22], &0x4000_u16.to_be_bytes());
    assert_eq!((tx.bytes[22], tx.bytes[23]), (37, 1));
    assert_eq!(&tx.bytes[26..30], &WAN_IP.octets());
    assert_eq!(&tx.bytes[30..34], &SOURCE.octets());
    assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
    assert_eq!(
        &tx.bytes[34..42],
        &[3, 0, tx.bytes[36], tx.bytes[37], 0, 0, 0, 0]
    );
    assert_eq!(internet_checksum(&tx.bytes[34..]), 0);
    assert_eq!(&tx.bytes[42..], &original[14..43]);
}

#[test]
fn destination_lookup_precedes_ttl_and_old_forwarding_apis_remain_opt_in() {
    let interfaces = interfaces();
    let bindings = bindings();
    let reverse = reverse_gateway();
    let forward = forward_route();
    let default = Route::new(
        Ipv4Address::from_octets([0, 0, 0, 0]),
        0,
        WAN,
        Some(GATEWAY),
    )
    .unwrap();
    let neighbors = [
        Neighbor {
            interface: WAN,
            target: GATEWAY,
            mac: GATEWAY_MAC,
        },
        Neighbor {
            interface: WAN,
            target: MISSING,
            mac: SOURCE_MAC,
        },
    ];

    for routes in [
        &[reverse][..],
        &[reverse, forward][..],
        &[reverse, default][..],
    ] {
        let snapshot = ForwardingSnapshot::new(routes, &interfaces, &neighbors, &bindings).unwrap();
        let original = ipv4_frame(SOURCE, MISSING, 1, 17, 0, 0, &[], &[]);
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
        let reason = if routes.len() == 1 {
            DropReason::RouteMiss
        } else {
            DropReason::Ipv4TtlExpired
        };
        assert_eq!(
            io.pop_recycled().unwrap().cause,
            RecycleCause::Forwarding(reason)
        );
        assert_eq!(errors.pending_actions(), 1);
        assert_eq!(
            trace
                .events()
                .iter()
                .filter(|event| matches!(
                    event,
                    TraceEvent::Icmpv4DestinationUnreachableDisposition { .. }
                ))
                .count(),
            usize::from(routes.len() == 1)
        );
        assert_eq!(
            trace
                .events()
                .iter()
                .filter(|event| matches!(event, TraceEvent::Icmpv4TimeExceededDisposition { .. }))
                .count(),
            usize::from(routes.len() == 2)
        );
    }

    let routes = [reverse];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let packet = ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &[], &[]);
    let mut io = SimIo::new();
    io.inject(LAN, packet.clone());
    forward_batch(io.receive(1).unwrap(), &snapshot, &mut NoTrace);
    assert_eq!(
        io.pop_recycled().unwrap().cause,
        RecycleCause::Forwarding(DropReason::RouteMiss)
    );
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    io.inject(LAN, packet);
    forward_batch_with_resolution(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(
        io.pop_recycled().unwrap().cause,
        RecycleCause::Forwarding(DropReason::RouteMiss)
    );
}

#[test]
fn reverse_connected_static_and_gateway_dynamic_neighbors_are_authoritative() {
    let interfaces = interfaces();
    let bindings = bindings();
    let connected_routes = [reverse_connected()];
    let connected_neighbors = [Neighbor {
        interface: WAN,
        target: SOURCE,
        mac: SOURCE_MAC,
    }];
    let connected = ForwardingSnapshot::new(
        &connected_routes,
        &interfaces,
        &connected_neighbors,
        &bindings,
    )
    .unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 2];
    let mut ra = [ResolutionActionSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &[], &[]));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &connected,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(0),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap();
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &SOURCE_MAC.0);

    let gateway_routes = [reverse_gateway()];
    let gateway = ForwardingSnapshot::new(&gateway_routes, &interfaces, &[], &bindings).unwrap();
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
    io.inject(WAN, arp_reply(GATEWAY, GATEWAY_MAC));
    io.inject(LAN, ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &[], &[]));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(2).unwrap(),
        &gateway,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(errors.pending_actions(), 1);
    execute_one_icmpv4_time_exceeded(
        &mut io,
        &mut errors,
        MonotonicMillis(0),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap();
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &GATEWAY_MAC.0);
}

#[test]
fn unresolved_reverse_neighbor_only_schedules_arp_and_fresh_packet_is_required() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = [reverse_gateway()];
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
    io.inject(LAN, ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &[], &[]));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(
        (errors.pending_actions(), resolution.pending_actions()),
        (0, 1)
    );
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut ruster_core::NoGeneratedTrace,
    )
    .unwrap();
    let arp = io.pop_tx().unwrap();
    assert_eq!(&arp.bytes[38..42], &GATEWAY.octets());

    io.inject(WAN, arp_reply(GATEWAY, GATEWAY_MAC));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(1),
        &mut NoTrace,
    );
    assert_eq!(errors.pending_actions(), 0, "learning is not retroactive");
    io.inject(LAN, ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &[], &[]));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(2),
        &mut NoTrace,
    );
    assert_eq!(errors.pending_actions(), 1);
}

#[test]
fn route_miss_suppression_matrix_and_options_are_atomic() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = [reverse_gateway()];
    let neighbors = [Neighbor {
        interface: WAN,
        target: GATEWAY,
        mac: GATEWAY_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut cases = vec![
        (
            ipv4_frame(
                Ipv4Address::from_octets([0, 1, 2, 3]),
                MISSING,
                64,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4ErrorDisposition::SourceNotUnicast,
        ),
        (
            ipv4_frame(WAN_IP, MISSING, 64, 17, 0, 0, &[], &[]),
            Icmpv4ErrorDisposition::SourceIsLocal,
        ),
        (
            ipv4_frame(
                SOURCE,
                Ipv4Address::from_octets([224, 0, 0, 1]),
                64,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4ErrorDisposition::DestinationMulticast,
        ),
        (
            ipv4_frame(
                SOURCE,
                Ipv4Address::from_octets([255; 4]),
                64,
                17,
                0,
                0,
                &[],
                &[],
            ),
            Icmpv4ErrorDisposition::DestinationLimitedBroadcast,
        ),
        (
            ipv4_frame(SOURCE, MISSING, 64, 17, 1, 0, &[], &[]),
            Icmpv4ErrorDisposition::NonInitialFragment,
        ),
        (
            ipv4_frame(SOURCE, MISSING, 64, 1, 0, 0, &[3], &[]),
            Icmpv4ErrorDisposition::IcmpErrorMessage,
        ),
        (
            ipv4_frame(SOURCE, MISSING, 64, 1, 0, 0, &[], &[]),
            Icmpv4ErrorDisposition::IcmpTypeMissing,
        ),
    ];
    let mut group = ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &[], &[]);
    group[0] = 1;
    cases.push((group, Icmpv4ErrorDisposition::EthernetDestinationGroup));

    for (original, expected) in cases {
        let admission_reason = match expected {
            Icmpv4ErrorDisposition::SourceNotUnicast => {
                Some(DropReason::Ipv4SourceUnspecifiedNetwork)
            }
            Icmpv4ErrorDisposition::DestinationMulticast => {
                Some(DropReason::Ipv4DestinationMulticast)
            }
            Icmpv4ErrorDisposition::DestinationLimitedBroadcast => {
                Some(DropReason::Ipv4DestinationLimitedBroadcast)
            }
            Icmpv4ErrorDisposition::EthernetDestinationGroup => {
                Some(DropReason::Ipv4EthernetDestinationMulticast)
            }
            _ => None,
        };
        let mut rs = [ResolutionStateSlot::EMPTY; 1];
        let mut ra = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
        let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
        let mut io = SimIo::new();
        io.inject(LAN, original.clone());
        let mut trace = VecTrace::default();
        forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
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
                TraceEvent::Icmpv4DestinationUnreachableDisposition { .. }
            )));
            continue;
        }
        assert!(trace.events().iter().any(|event| matches!(
            event,
            TraceEvent::Icmpv4DestinationUnreachableDisposition { disposition, .. }
                if *disposition == expected
        )));
    }

    let first = ipv4_frame(SOURCE, MISSING, 64, 1, 0x2000, 0, &[8], &[]);
    let options = options_frame();
    for (original, expected_pending, expected_reason) in [
        (first, 1, DropReason::RouteMiss),
        (options, 0, DropReason::Ipv4OptionsUnsupported),
    ] {
        let mut rs = [ResolutionStateSlot::EMPTY; 1];
        let mut ra = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
        let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
        let mut io = SimIo::new();
        io.inject(LAN, original.clone());
        forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(0),
            &mut NoTrace,
        );
        let recycled = io.pop_recycled().unwrap();
        assert_eq!(recycled.cause, RecycleCause::Forwarding(expected_reason));
        assert_eq!(recycled.bytes, original);
        assert_eq!(errors.pending_actions(), expected_pending);
    }
}

#[test]
fn destination_unreachable_quote_bounds_exclude_padding_and_checksum_odd_lengths() {
    for (total_len, padding_len, expected_quote, expected_frame) in [
        (20, 7, 20, 62),
        (29, 11, 29, 71),
        (548, 9, 548, 590),
        (549, 5, 548, 590),
    ] {
        let interfaces = interfaces();
        let bindings = bindings();
        let routes = [reverse_connected()];
        let neighbors = [Neighbor {
            interface: WAN,
            target: SOURCE,
            mac: SOURCE_MAC,
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let body = vec![0x5a; total_len - 20];
        let padding = vec![0xee; padding_len];
        let original = ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &body, &padding);
        let mut rs = [ResolutionStateSlot::EMPTY; 1];
        let mut ra = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
        let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
        let mut io = SimIo::new();
        io.inject(LAN, original.clone());
        forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(0),
            &mut NoTrace,
        );
        let generated = execute_one_icmpv4_error(
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
        let outer_len = usize::from(u16::from_be_bytes([tx.bytes[16], tx.bytes[17]]));
        assert_eq!(internet_checksum(&tx.bytes[34..14 + outer_len]), 0);
        assert!(tx.bytes[14 + outer_len..].iter().all(|byte| *byte == 0));
    }
}

#[test]
fn destination_unreachable_allocation_reject_finish_and_clock_lifecycle_is_exact() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = [reverse_connected()];
    let neighbors = [Neighbor {
        interface: WAN,
        target: SOURCE,
        mac: SOURCE_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let packet = ipv4_frame(SOURCE, MISSING, 64, 17, 0, 0, &[], &[]);
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
    io.inject(LAN, packet.clone());
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(10),
        &mut NoTrace,
    );

    io.set_generated_budget(0);
    let mut trace = VecGeneratedIcmpv4Trace::default();
    let failed = execute_one_icmpv4_error(&mut io, &mut errors, MonotonicMillis(10), &mut trace)
        .unwrap()
        .unwrap();
    assert_eq!(
        failed.allocation_error,
        Some(GeneratedAllocationError::Unavailable)
    );
    assert_eq!(errors.pending_actions(), 1);
    assert!(matches!(
        trace.events(),
        [
            GeneratedIcmpv4Trace::DestinationUnreachableAllocationFailed(
                GeneratedAllocationError::Unavailable
            ),
            GeneratedIcmpv4Trace::DestinationUnreachableBatchCompleted {
                accepted: 0,
                rejected: 0
            }
        ]
    ));

    let mut clock_trace = VecGeneratedIcmpv4Trace::default();
    assert_eq!(
        execute_one_icmpv4_error(&mut io, &mut errors, MonotonicMillis(9), &mut clock_trace,),
        Err(ExecuteIcmpv4Error::ClockRegression)
    );
    assert_eq!(
        clock_trace.events(),
        [GeneratedIcmpv4Trace::DestinationUnreachableClockRegression]
    );
    assert_eq!(errors.pending_actions(), 1);

    io.set_generated_budget(1);
    io.set_generated_accept_budget(0);
    io.fail_next_generated_finish();
    let mut reject_trace = VecGeneratedIcmpv4Trace::default();
    let rejected =
        execute_one_icmpv4_error(&mut io, &mut errors, MonotonicMillis(10), &mut reject_trace)
            .unwrap()
            .unwrap();
    assert_eq!(
        (rejected.completion.accepted, rejected.completion.rejected),
        (0, 1)
    );
    assert!(rejected.completion.error.is_some());
    assert_eq!(errors.pending_actions(), 0);
    assert!(matches!(
        reject_trace.events(),
        [
            GeneratedIcmpv4Trace::DestinationUnreachableTxRequested { .. },
            GeneratedIcmpv4Trace::DestinationUnreachableBatchCompleted {
                accepted: 0,
                rejected: 1
            }
        ]
    ));

    for (now, expected_pending) in [(109, 0), (110, 1)] {
        io.inject(LAN, packet.clone());
        forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(now),
            &mut NoTrace,
        );
        assert_eq!(errors.pending_actions(), expected_pending);
    }
}

use ruster_core::{
    execute_one_icmpv4_error, forward_batch_with_resolution_and_icmpv4_errors, internet_checksum,
    ipv4_header_checksum, DropReason, ForwardingSnapshot, Icmpv4ErrorActionSlot,
    Icmpv4ErrorDisposition, Icmpv4ErrorKind, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime,
    Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, Ipv4Mtu, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Neighbor, NoGeneratedIcmpv4Trace, NoTrace, PacketIo, ResolutionActionSlot,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route, TraceEvent,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};

const LAN: IfId = IfId(1);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xaa];
const HOST_MAC_ADDR: MacAddress = MacAddress(HOST_MAC);
const GATEWAY_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xcc]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const HOST: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 50]);
const BETTER_GATEWAY: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 99]);
const REMOTE_NET: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 0]);
const REMOTE_DESTINATION: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 5]);

fn interfaces() -> [Interface; 1] {
    [Interface {
        id: LAN,
        mac: LAN_MAC,
        mtu: Ipv4Mtu::ETHERNET,
    }]
}

fn bindings() -> [LocalIpv4Binding; 1] {
    [LocalIpv4Binding {
        interface: LAN,
        address: LAN_IP,
    }]
}

fn connected_route() -> Route {
    Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap()
}

fn gateway_route() -> Route {
    Route::new(REMOTE_NET, 24, LAN, Some(BETTER_GATEWAY)).unwrap()
}

fn resolution_policy() -> ResolutionPolicy {
    ResolutionPolicy::new(1_000, 60_000).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn ipv4_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    ttl: u8,
    protocol: u8,
    body: &[u8],
) -> Vec<u8> {
    let total_len = 20 + body.len();
    let mut frame = vec![0; 14 + total_len];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&0_u16.to_be_bytes());
    frame[22] = ttl;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..34 + body.len()].copy_from_slice(body);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// RFC 1812 §5.2.7.2: a datagram forwarded back out the interface it arrived
/// on, toward a next hop on the sender's own subnet, draws a Redirect for
/// host (code 1) naming that next hop as the better gateway. The original
/// datagram is still forwarded unchanged.
#[test]
fn same_interface_forward_to_a_connected_gateway_generates_exact_type5_code1() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = [connected_route(), gateway_route()];
    let neighbors = [
        Neighbor {
            interface: LAN,
            target: BETTER_GATEWAY,
            mac: GATEWAY_MAC,
        },
        Neighbor {
            interface: LAN,
            target: HOST,
            mac: HOST_MAC_ADDR,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let original = ipv4_frame(HOST, REMOTE_DESTINATION, 64, 17, &[0; 8]);
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

    // The datagram is still forwarded normally; the Redirect is advisory.
    assert_eq!((report.tx_requested, report.dropped), (1, 0));
    let forwarded = io.pop_tx().unwrap();
    assert_eq!(&forwarded.bytes[0..6], &GATEWAY_MAC.0);
    assert_eq!(&forwarded.bytes[30..34], &REMOTE_DESTINATION.octets());

    assert_eq!(errors.pending_actions(), 1);
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::Icmpv4TimeExceededDisposition {
            disposition: Icmpv4ErrorDisposition::RedirectQueued { egress: LAN, .. },
            ..
        }
    )));

    let generated = execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(10),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        generated.action.kind,
        Icmpv4ErrorKind::Redirect {
            gateway: BETTER_GATEWAY
        }
    );
    let tx = io.pop_tx().unwrap();
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(&tx.bytes[6..12], &LAN_MAC.0);
    assert_eq!(&tx.bytes[26..30], &LAN_IP.octets());
    assert_eq!(&tx.bytes[30..34], &HOST.octets());
    assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
    assert_eq!(tx.bytes[34], 5, "ICMP Redirect");
    assert_eq!(tx.bytes[35], 1, "code 1: redirect for host");
    assert_eq!(&tx.bytes[38..42], &BETTER_GATEWAY.octets());
    assert_eq!(internet_checksum(&tx.bytes[34..]), 0);
    assert_eq!(&tx.bytes[42..], &original[14..42]);
}

/// No Redirect is generated when the datagram leaves by a different
/// interface than the one it arrived on.
#[test]
fn different_egress_interface_never_generates_a_redirect() {
    let wan = IfId(2);
    let wan_mac = MacAddress([2, 0, 0, 0, 0, 2]);
    let mut interfaces_vec = interfaces().to_vec();
    interfaces_vec.push(Interface {
        id: wan,
        mac: wan_mac,
        mtu: Ipv4Mtu::ETHERNET,
    });
    let mut bindings_vec = bindings().to_vec();
    bindings_vec.push(LocalIpv4Binding {
        interface: wan,
        address: Ipv4Address::from_octets([198, 51, 100, 1]),
    });
    let routes = [
        connected_route(),
        Route::new(REMOTE_NET, 24, wan, Some(BETTER_GATEWAY)).unwrap(),
    ];
    let neighbors = [Neighbor {
        interface: wan,
        target: BETTER_GATEWAY,
        mac: GATEWAY_MAC,
    }];
    let snapshot =
        ForwardingSnapshot::new(&routes, &interfaces_vec, &neighbors, &bindings_vec).unwrap();
    let original = ipv4_frame(HOST, REMOTE_DESTINATION, 64, 17, &[0; 8]);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, original);
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(10),
        &mut NoTrace,
    );
    assert_eq!((report.tx_requested, report.dropped), (1, 0));
    assert_eq!(errors.pending_actions(), 0);
}

/// No Redirect is generated when the next hop is not on the same subnet as
/// the datagram's source, even though the egress interface matches ingress.
#[test]
fn next_hop_outside_the_sources_subnet_never_generates_a_redirect() {
    let interfaces = interfaces();
    let bindings = bindings();
    // The gateway route's next hop is outside the 192.0.2.0/24 subnet the
    // sending host and the router's own address share.
    let far_gateway = Ipv4Address::from_octets([192, 0, 3, 99]);
    let routes = [
        connected_route(),
        Route::new(Ipv4Address::from_octets([192, 0, 3, 0]), 24, LAN, None).unwrap(),
        Route::new(REMOTE_NET, 24, LAN, Some(far_gateway)).unwrap(),
    ];
    let neighbors = [
        Neighbor {
            interface: LAN,
            target: far_gateway,
            mac: GATEWAY_MAC,
        },
        Neighbor {
            interface: LAN,
            target: HOST,
            mac: HOST_MAC_ADDR,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let original = ipv4_frame(HOST, REMOTE_DESTINATION, 64, 17, &[0; 8]);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, original);
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(10),
        &mut NoTrace,
    );
    assert_eq!((report.tx_requested, report.dropped), (1, 0));
    assert_eq!(errors.pending_actions(), 0);
}

/// No Redirect is generated when the "better" next hop is the router's own
/// address.
#[test]
fn next_hop_that_is_the_router_itself_never_generates_a_redirect() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = [
        connected_route(),
        Route::new(REMOTE_NET, 24, LAN, Some(LAN_IP)).unwrap(),
    ];
    let neighbors = [
        Neighbor {
            interface: LAN,
            target: HOST,
            mac: HOST_MAC_ADDR,
        },
        Neighbor {
            interface: LAN,
            target: LAN_IP,
            mac: GATEWAY_MAC,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let original = ipv4_frame(HOST, REMOTE_DESTINATION, 64, 17, &[0; 8]);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, original);
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(10),
        &mut NoTrace,
    );
    assert_eq!((report.tx_requested, report.dropped), (1, 0));
    assert_eq!(errors.pending_actions(), 0);
}

/// RFC 1812 §5.2.7.2: a Redirect is never sent for a datagram carrying a
/// source route. This router refuses source routing outright (RFC 792
/// Source Route Failed), so the Redirect check is never reached at all.
#[test]
fn a_source_routed_datagram_never_reaches_the_redirect_check() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = [connected_route(), gateway_route()];
    let neighbors = [
        Neighbor {
            interface: LAN,
            target: BETTER_GATEWAY,
            mac: GATEWAY_MAC,
        },
        Neighbor {
            interface: LAN,
            target: HOST,
            mac: HOST_MAC_ADDR,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut original = ipv4_frame(HOST, REMOTE_DESTINATION, 64, 17, &[0; 8]);
    // Splice in a 4-byte loose source route option (type 131) after the
    // fixed header, and grow the IHL to cover it.
    original.splice(34..34, [131, 4, 4, 0]);
    original[14] = 0x46;
    original[16..18].copy_from_slice(&24_u16.to_be_bytes());
    original[24..26].fill(0);
    let checksum = ipv4_header_checksum(&original[14..38]);
    original[24..26].copy_from_slice(&checksum.to_be_bytes());

    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(resolution_policy(), &mut rs, &mut ra);
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, original.clone());
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(10),
        &mut NoTrace,
    );
    assert_eq!((report.dropped, report.tx_requested), (1, 0));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Ipv4SourceRouteUnsupported)
    );
    // The refusal itself still generates its own ICMP (Source Route
    // Failed), not a Redirect.
    assert_eq!(errors.pending_actions(), 1);
    let generated = execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(10),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        generated.action.kind,
        Icmpv4ErrorKind::DestinationUnreachableSourceRouteFailed
    );
}

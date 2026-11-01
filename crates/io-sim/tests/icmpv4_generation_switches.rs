//! Operator switches for router-originated ICMPv4 (RFC 1812 §§1.1.3,
//! 4.3.3.6, 5.2.7.1, 5.3.1): every class is on by default, and a disabled
//! class drops byte-unchanged with a distinguishable counter or reason and
//! emits nothing on the wire.

use ruster_core::{
    dispatch_host_unreachable_failures, execute_one_arp_request, execute_one_icmpv4_error,
    forward_batch_with_resolution_and_icmpv4_errors, internet_checksum, ipv4_header_checksum,
    poll_resolution_timers, DropReason, DynamicNeighborSlot, ForwardingSnapshot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorCounters, Icmpv4ErrorDisposition, Icmpv4ErrorKind,
    Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address,
    Ipv4OriginPolicy, LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor,
    NoGeneratedIcmpv4Trace, NoGeneratedTrace, NoResolutionTimerTrace, NoTrace, PacketIo,
    ResolutionActionSlot, ResolutionFailureHoldSlot, ResolutionFailureTrace,
    ResolutionFailureTraceSink, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
    TraceEvent,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOP_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xaa];
const SOURCE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xbb]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const SOURCE: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 9]);
const ROUTED: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 9]);
const MISSING: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 9]);

const ALL_KINDS: [Icmpv4ErrorKind; 3] = [
    Icmpv4ErrorKind::TimeExceededTtl,
    Icmpv4ErrorKind::DestinationUnreachableNetwork,
    Icmpv4ErrorKind::DestinationUnreachableHost,
];

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

fn udp_frame(destination: Ipv4Address, ttl: u8) -> Vec<u8> {
    let body = [0x13, 0x88, 0x00, 0x35, 0x00, 0x0a, 0x00, 0x00, 0xab, 0xcd];
    let total_len = 20 + body.len();
    let mut frame = vec![0; 14 + total_len];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOP_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[22] = ttl;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&SOURCE.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..].copy_from_slice(&body);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn echo_request(valid_checksum: bool) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x45, 0x67, 0x89, 0xab, 1, 2, 3, 4];
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    if !valid_checksum {
        icmp[3] ^= 1;
    }
    let mut frame = udp_frame(LAN_IP, 64);
    frame.truncate(34);
    frame.extend_from_slice(&icmp);
    frame[16..18].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    frame[23] = 1;
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn policy_with(kind: Icmpv4ErrorKind, enabled: bool) -> Icmpv4ErrorPolicy {
    Icmpv4ErrorPolicy::default().with_generation(kind, enabled)
}

struct Outcome {
    reason: DropReason,
    recycled_unchanged: bool,
    disposition: Option<Icmpv4ErrorDisposition>,
    counters: Icmpv4ErrorCounters,
    generated: Option<Icmpv4ErrorKind>,
}

/// Forwards one LAN frame through the resolution + ICMP error composition
/// and drains the generated-error queue.
fn forward_one(frame: Vec<u8>, policy: Icmpv4ErrorPolicy) -> Outcome {
    let routes = routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut rs,
        &mut ra,
    );
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 2];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 2];
    let mut errors = Icmpv4ErrorRuntime::new(policy, &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, frame.clone());
    let mut trace = VecTrace::default();
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(10),
        &mut trace,
    );
    assert_eq!((report.dropped, report.tx_requested), (1, 0));
    let recycled = io.pop_recycled().unwrap();
    let RecycleCause::Forwarding(reason) = recycled.cause else {
        panic!("forwarding drop expected");
    };
    let disposition = trace.events().iter().find_map(|event| match event {
        TraceEvent::Icmpv4TimeExceededDisposition { disposition, .. }
        | TraceEvent::Icmpv4DestinationUnreachableDisposition { disposition, .. } => {
            Some(*disposition)
        }
        _ => None,
    });
    let counters = errors.counters();
    let generated = execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(10),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap()
    .map(|report| report.action.kind);
    if generated.is_some() {
        assert!(io.pop_tx().is_some());
    }
    assert!(io.pop_tx().is_none(), "no ARP or other frame is emitted");
    Outcome {
        reason,
        recycled_unchanged: recycled.bytes == frame,
        disposition,
        counters,
        generated,
    }
}

#[test]
fn every_generation_class_defaults_to_rfc_behavior() {
    let policy = Icmpv4ErrorPolicy::default();
    assert!(ALL_KINDS.into_iter().all(|kind| policy.generates(kind)));
    let built = Icmpv4ErrorPolicy::new(100, 60_000).unwrap();
    assert_eq!(built, policy);
    assert!(Ipv4OriginPolicy::default().echo_reply());
    assert!(Ipv4OriginPolicy::new(64).unwrap().echo_reply());

    let ttl = forward_one(udp_frame(ROUTED, 1), policy);
    assert_eq!(ttl.reason, DropReason::Ipv4TtlExpired);
    assert_eq!(ttl.generated, Some(Icmpv4ErrorKind::TimeExceededTtl));
    let miss = forward_one(udp_frame(MISSING, 64), policy);
    assert_eq!(miss.reason, DropReason::RouteMiss);
    assert_eq!(
        miss.generated,
        Some(Icmpv4ErrorKind::DestinationUnreachableNetwork)
    );
}

#[test]
fn switches_are_independent_and_reversible() {
    for disabled in ALL_KINDS {
        let policy = policy_with(disabled, false);
        for kind in ALL_KINDS {
            assert_eq!(policy.generates(kind), kind != disabled);
        }
        assert_eq!(
            policy.with_generation(disabled, true),
            Icmpv4ErrorPolicy::default()
        );
        assert_eq!(policy.interval_ms(), 100);
        assert_eq!(policy.state_ttl_ms(), 60_000);
    }
}

#[test]
fn disabled_time_exceeded_drops_silently_with_its_own_counter() {
    let off = forward_one(
        udp_frame(ROUTED, 1),
        policy_with(Icmpv4ErrorKind::TimeExceededTtl, false),
    );
    assert_eq!(off.reason, DropReason::Ipv4TtlExpired);
    assert!(off.recycled_unchanged);
    assert_eq!(
        off.disposition,
        Some(Icmpv4ErrorDisposition::GenerationDisabled {
            kind: Icmpv4ErrorKind::TimeExceededTtl
        })
    );
    assert_eq!(off.generated, None);
    assert_eq!(
        off.counters,
        Icmpv4ErrorCounters {
            disabled_time_exceeded: 1,
            ..Icmpv4ErrorCounters::default()
        }
    );

    // Disabling Time Exceeded leaves Network Unreachable untouched.
    let miss = forward_one(
        udp_frame(MISSING, 64),
        policy_with(Icmpv4ErrorKind::TimeExceededTtl, false),
    );
    assert_eq!(
        miss.generated,
        Some(Icmpv4ErrorKind::DestinationUnreachableNetwork)
    );
}

#[test]
fn disabled_net_unreachable_drops_silently_with_its_own_counter() {
    let off = forward_one(
        udp_frame(MISSING, 64),
        policy_with(Icmpv4ErrorKind::DestinationUnreachableNetwork, false),
    );
    assert_eq!(off.reason, DropReason::RouteMiss);
    assert!(off.recycled_unchanged);
    assert_eq!(
        off.disposition,
        Some(Icmpv4ErrorDisposition::GenerationDisabled {
            kind: Icmpv4ErrorKind::DestinationUnreachableNetwork
        })
    );
    assert_eq!(off.generated, None);
    assert_eq!(
        off.counters,
        Icmpv4ErrorCounters {
            disabled_destination_unreachable: 1,
            ..Icmpv4ErrorCounters::default()
        }
    );

    let ttl = forward_one(
        udp_frame(ROUTED, 1),
        policy_with(Icmpv4ErrorKind::DestinationUnreachableNetwork, false),
    );
    assert_eq!(ttl.generated, Some(Icmpv4ErrorKind::TimeExceededTtl));
}

#[test]
fn disabled_kind_does_not_consume_the_shared_limiter() {
    let routes = routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut rs,
        &mut ra,
    );
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        policy_with(Icmpv4ErrorKind::TimeExceededTtl, false),
        &mut es,
        &mut ea,
    );
    let mut io = SimIo::new();
    // Both errors would reverse-route to LAN and share its limiter; the
    // disabled Time Exceeded must not occupy it.
    io.inject(LAN, udp_frame(ROUTED, 1));
    io.inject(LAN, udp_frame(MISSING, 64));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(2).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(10),
        &mut NoTrace,
    );
    let counters = errors.counters();
    assert_eq!(
        (
            counters.disabled_time_exceeded,
            counters.queued_destination_unreachable,
            counters.pending,
            counters.rate_limited,
        ),
        (1, 1, 0, 0)
    );
    assert_eq!(errors.pending_actions(), 1);
}

#[derive(Default)]
struct FailureTrace {
    events: Vec<ResolutionFailureTrace>,
}

impl ResolutionFailureTraceSink for FailureTrace {
    fn record_resolution_failure(&mut self, event: ResolutionFailureTrace) {
        self.events.push(event);
    }
}

/// Runs a directly connected WAN host through a fruitless ARP generation
/// and one failure dispatch; returns the dispatch outcome.
fn host_unreachable_with(
    policy: Icmpv4ErrorPolicy,
) -> (
    ruster_core::ResolutionFailureDispatchReport,
    Vec<ResolutionFailureTrace>,
    Icmpv4ErrorCounters,
    usize,
    usize,
) {
    let routes = routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        ResolutionPolicy::with_retry(1_000, 60_000, 1).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut holds,
    );
    let mut es = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(policy, &mut es, &mut ea);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(ROUTED, 64));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(
        io.pop_recycled().unwrap().cause,
        RecycleCause::Forwarding(DropReason::NeighborUnresolved)
    );
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap()
    .unwrap();
    assert!(io.pop_tx().is_some(), "forward ARP Request");
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(1_000),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    let mut trace = FailureTrace::default();
    let report = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        1,
        &mut trace,
    )
    .unwrap();
    let pending = errors.pending_actions();
    let generated = execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(1_000),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap();
    assert_eq!(generated.is_some(), pending == 1);
    let mut emitted = 0;
    while io.pop_tx().is_some() {
        emitted += 1;
    }
    let mut arp_emitted = 0;
    while execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(1_000),
        &mut NoGeneratedTrace,
    )
    .unwrap()
    .is_some()
    {
        arp_emitted += 1;
    }
    assert_eq!(resolution.pending_failure_holds(), 0);
    (
        report,
        trace.events,
        errors.counters(),
        pending,
        emitted + arp_emitted,
    )
}

#[test]
fn host_unreachable_switch_retires_the_hold_without_reverse_work() {
    let (on, on_trace, on_counters, on_pending, on_emitted) =
        host_unreachable_with(Icmpv4ErrorPolicy::default());
    assert_eq!(
        (on.queued, on.retired, on_pending, on_emitted),
        (1, 0, 1, 1)
    );
    assert!(matches!(
        on_trace.as_slice(),
        [ResolutionFailureTrace::Queued { .. }]
    ));
    assert_eq!(on_counters.disabled_host_unreachable, 0);

    let (off, off_trace, off_counters, off_pending, off_emitted) = host_unreachable_with(
        policy_with(Icmpv4ErrorKind::DestinationUnreachableHost, false),
    );
    assert_eq!(
        (off.queued, off.retired, off_pending, off_emitted),
        (0, 1, 0, 0)
    );
    assert!(matches!(
        off_trace.as_slice(),
        [ResolutionFailureTrace::GenerationDisabled { .. }]
    ));
    assert_eq!(
        off_counters,
        Icmpv4ErrorCounters {
            disabled_host_unreachable: 1,
            ..Icmpv4ErrorCounters::default()
        }
    );
}

fn echo_with(origin: Ipv4OriginPolicy, frame: Vec<u8>) -> (SimIo, usize) {
    let routes = routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::with_ipv4_origin_policy(
        &routes,
        &interfaces,
        &neighbors,
        &bindings,
        origin,
    )
    .unwrap();
    let mut io = SimIo::new();
    io.inject(LAN, frame);
    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    (io, report.tx_requested)
}

#[test]
fn echo_reply_switch_drops_valid_requests_with_a_typed_reason() {
    let (mut on, sent) = echo_with(Ipv4OriginPolicy::default(), echo_request(true));
    assert_eq!(sent, 1);
    let reply = on.pop_tx().unwrap();
    assert_eq!(reply.bytes[34], 0, "Echo Reply");

    let request = echo_request(true);
    let disabled = Ipv4OriginPolicy::new(64).unwrap().with_echo_reply(false);
    assert!(!disabled.echo_reply());
    assert_eq!(disabled.default_ttl(), 64);
    let (mut off, sent) = echo_with(disabled, request.clone());
    assert_eq!(sent, 0);
    assert!(off.pop_tx().is_none());
    let recycled = off.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Icmpv4EchoDisabled)
    );
    assert_eq!(recycled.bytes, request);

    // Validation still precedes the switch: a corrupt request keeps its
    // precise reason.
    let (mut corrupt, _) = echo_with(disabled, echo_request(false));
    assert_eq!(
        corrupt.pop_recycled().unwrap().cause,
        RecycleCause::Forwarding(DropReason::Icmpv4ChecksumInvalid)
    );
    assert_eq!(
        DropReason::Icmpv4EchoDisabled.code(),
        "ICMPV4_ECHO_DISABLED"
    );
}

/// The early gate in the forwarding decision must precede the reverse
/// neighbor lookup: with an unresolved reverse next-hop, a disabled kind must
/// not start a reverse ARP or observe the clock.
#[test]
fn disabled_kind_never_starts_reverse_arp_or_moves_the_clock() {
    for (disabled, frame, other) in [
        (
            Icmpv4ErrorKind::TimeExceededTtl,
            udp_frame(ROUTED, 1),
            udp_frame(MISSING, 64),
        ),
        (
            Icmpv4ErrorKind::DestinationUnreachableNetwork,
            udp_frame(MISSING, 64),
            udp_frame(ROUTED, 1),
        ),
    ] {
        let routes = routes();
        let interfaces = interfaces();
        let bindings = bindings();
        // No neighbor for SOURCE: the reverse next-hop is unresolved.
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let mut rs = [ResolutionStateSlot::EMPTY; 2];
        let mut ra = [ResolutionActionSlot::EMPTY; 2];
        let mut resolution = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 60_000).unwrap(),
            &mut rs,
            &mut ra,
        );
        let mut es = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut errors = Icmpv4ErrorRuntime::new(policy_with(disabled, false), &mut es, &mut ea);
        let mut io = SimIo::new();
        io.inject(LAN, frame.clone());
        let mut trace = VecTrace::default();
        forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(10),
            &mut trace,
        );
        assert_eq!(io.pop_recycled().unwrap().bytes, frame);
        let dispositions: Vec<_> = trace
            .events()
            .iter()
            .filter_map(|event| match event {
                TraceEvent::Icmpv4TimeExceededDisposition { disposition, .. }
                | TraceEvent::Icmpv4DestinationUnreachableDisposition { disposition, .. } => {
                    Some(*disposition)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            dispositions,
            [Icmpv4ErrorDisposition::GenerationDisabled { kind: disabled }],
            "{disabled:?}"
        );
        assert!(!trace
            .events()
            .iter()
            .any(|event| matches!(event, TraceEvent::NeighborResolution { .. })));
        assert_eq!(resolution.pending_actions(), 0, "{disabled:?}");
        assert!(execute_one_arp_request(
            &mut io,
            &mut resolution,
            MonotonicMillis(10),
            &mut NoGeneratedTrace,
        )
        .unwrap()
        .is_none());
        assert!(execute_one_icmpv4_error(
            &mut io,
            &mut errors,
            MonotonicMillis(10),
            &mut NoGeneratedIcmpv4Trace,
        )
        .unwrap()
        .is_none());
        assert!(io.pop_tx().is_none(), "{disabled:?}: nothing on the wire");
        let counters = errors.counters();
        assert_eq!(
            (
                counters.disabled_time_exceeded,
                counters.disabled_destination_unreachable,
                counters.reverse_neighbor_unresolved,
                counters.clock_regressions,
            ),
            if disabled == Icmpv4ErrorKind::TimeExceededTtl {
                (1, 0, 0, 0)
            } else {
                (0, 1, 0, 0)
            }
        );

        // The disabled attempt observed no time: an enabled kind at an
        // earlier instant is not a clock regression.
        io.inject(LAN, other);
        let mut trace = VecTrace::default();
        forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(5),
            &mut trace,
        );
        assert!(trace.events().iter().any(|event| matches!(
            event,
            TraceEvent::Icmpv4TimeExceededDisposition {
                disposition: Icmpv4ErrorDisposition::ReverseNeighborUnresolved { .. },
                ..
            } | TraceEvent::Icmpv4DestinationUnreachableDisposition {
                disposition: Icmpv4ErrorDisposition::ReverseNeighborUnresolved { .. },
                ..
            }
        )));
        assert_eq!(errors.counters().clock_regressions, 0);
    }
}

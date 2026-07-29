use ruster_core::{
    dispatch_host_unreachable_failures, execute_one_arp_request, execute_one_icmpv4_error,
    forward_batch_with_resolution, forward_batch_with_resolution_and_icmpv4_errors,
    internet_checksum, ipv4_header_checksum, poll_resolution_timers, DynamicNeighborSlot,
    ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorKind, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, Ipv4OriginPolicy,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, NoGeneratedIcmpv4Trace,
    NoGeneratedTrace, NoResolutionFailureTrace, NoResolutionTimerTrace, NoTrace, PacketIo,
    ResolutionActionSlot, ResolutionFailureDispatchError, ResolutionFailureHoldPhase,
    ResolutionFailureHoldSlot, ResolutionFailureTrace, ResolutionFailureTraceSink, ResolutionPhase,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
};
use ruster_io_sim::{FrameOrigin, RecycleCause, SimIo};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOP_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xaa];
const REVERSE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xbb]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const SOURCE: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 9]);
const DESTINATION: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 9]);

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

fn direct_routes() -> [Route; 2] {
    [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, WAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, LAN, None).unwrap(),
    ]
}

fn frame(body: &[u8], flags_fragment: u16, protocol: u8) -> Vec<u8> {
    let total_len = 20 + body.len();
    let mut bytes = vec![0; 14 + total_len + 3];
    bytes[0..6].copy_from_slice(&LAN_MAC.0);
    bytes[6..12].copy_from_slice(&HOP_MAC);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[15] = 0x2f;
    bytes[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    bytes[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    bytes[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = protocol;
    bytes[26..30].copy_from_slice(&SOURCE.octets());
    bytes[30..34].copy_from_slice(&DESTINATION.octets());
    bytes[34..34 + body.len()].copy_from_slice(body);
    bytes[34 + body.len()..].copy_from_slice(&[0xde, 0xad, 0xbe]);
    let checksum = ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn frame_to(destination: Ipv4Address, body: &[u8]) -> Vec<u8> {
    let mut bytes = frame(body, 0, 17);
    bytes[30..34].copy_from_slice(&destination.octets());
    bytes[24..26].fill(0);
    let checksum = ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn arp_reply(sender: Ipv4Address, sender_mac: MacAddress, target: Ipv4Address) -> Vec<u8> {
    let mut bytes = vec![0; 60];
    bytes[0..6].copy_from_slice(&LAN_MAC.0);
    bytes[6..12].copy_from_slice(&sender_mac.0);
    bytes[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    bytes[14..16].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[18..22].copy_from_slice(&[6, 4, 0, 2]);
    bytes[22..28].copy_from_slice(&sender_mac.0);
    bytes[28..32].copy_from_slice(&sender.octets());
    bytes[32..38].copy_from_slice(&LAN_MAC.0);
    bytes[38..42].copy_from_slice(&target.octets());
    bytes
}

fn forward_arp_reply() -> Vec<u8> {
    let mut bytes = arp_reply(DESTINATION, REVERSE_MAC, WAN_IP);
    bytes[0..6].copy_from_slice(&WAN_MAC.0);
    bytes[32..38].copy_from_slice(&WAN_MAC.0);
    bytes
}

fn retry_policy() -> ResolutionPolicy {
    ResolutionPolicy::with_retry(1_000, 60_000, 1).unwrap()
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

#[test]
fn direct_timeout_after_accepted_arp_generates_exact_type3_code1() {
    let routes = direct_routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = [Neighbor {
        interface: LAN,
        target: SOURCE,
        mac: REVERSE_MAC,
    }];
    let snapshot = ForwardingSnapshot::with_ipv4_origin_policy(
        &routes,
        &interfaces,
        &neighbors,
        &bindings,
        Ipv4OriginPolicy::new(37).unwrap(),
    )
    .unwrap();
    let original = frame(&[1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 17);
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        retry_policy(),
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut holds,
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
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!((report.dropped, errors.pending_actions()), (1, 0));
    assert_eq!(
        io.pop_recycled().unwrap().cause,
        RecycleCause::Forwarding(ruster_core::DropReason::NeighborUnresolved)
    );
    assert_eq!(resolution.pending_failure_holds(), 1);

    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap()
    .unwrap();
    let arp_tx = io.pop_tx().unwrap();
    assert_eq!(&arp_tx.bytes[0..6], &[0xff; 6]);
    assert_eq!(
        resolution
            .status(WAN, DESTINATION)
            .unwrap()
            .accepted_attempts,
        1
    );
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(999),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    assert_eq!(
        resolution.status(WAN, DESTINATION).unwrap().phase,
        ResolutionPhase::Waiting
    );
    assert_eq!(errors.pending_actions(), 0);
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(1_000),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    assert_eq!(
        dispatch_host_unreachable_failures(
            &mut resolution,
            &mut errors,
            &snapshot,
            MonotonicMillis(999),
            1,
            &mut NoResolutionFailureTrace,
        ),
        Err(ResolutionFailureDispatchError::ClockRegression)
    );
    assert_eq!(
        (resolution.pending_failure_holds(), errors.pending_actions()),
        (1, 0)
    );
    let dispatched = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        1,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!((dispatched.queued, dispatched.pending), (1, 0));

    let generated = execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(1_000),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        generated.action.kind,
        Icmpv4ErrorKind::DestinationUnreachableHost
    );
    let tx = io.pop_tx().unwrap();
    assert_eq!(tx.origin, FrameOrigin::Generated);
    assert_eq!(&tx.bytes[0..6], &REVERSE_MAC.0);
    assert_eq!(&tx.bytes[6..12], &LAN_MAC.0);
    assert_eq!((tx.bytes[15], tx.bytes[22]), (0xce, 37));
    assert_eq!(&tx.bytes[18..20], &[0, 0]);
    assert_eq!(&tx.bytes[20..22], &0x4000_u16.to_be_bytes());
    assert_eq!(&tx.bytes[34..36], &[3, 1]);
    assert_eq!(&tx.bytes[38..42], &[0; 4]);
    assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
    let icmp_len = 8 + (20 + 9);
    assert_eq!(internet_checksum(&tx.bytes[34..34 + icmp_len]), 0);
    assert_eq!(&tx.bytes[42..42 + 29], &original[14..43]);
    assert!(!tx.bytes[42..].ends_with(&[0xde, 0xad, 0xbe]));
}

#[test]
fn rejected_arp_never_generates_but_mixed_acceptance_is_eligible() {
    for (accept, expected) in [(0, 0), (1, 1)] {
        let routes = direct_routes();
        let interfaces = interfaces();
        let bindings = bindings();
        let neighbors = [Neighbor {
            interface: LAN,
            target: SOURCE,
            mac: REVERSE_MAC,
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 2];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            retry_policy(),
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            &mut error_states,
            &mut error_actions,
        );
        let mut io = SimIo::new();
        io.inject(LAN, frame(&[accept as u8; 8], 0, 17));
        forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(0),
            &mut NoTrace,
        );
        io.set_generated_accept_budget(accept);
        execute_one_arp_request(
            &mut io,
            &mut resolution,
            MonotonicMillis(0),
            &mut NoGeneratedTrace,
        )
        .unwrap()
        .unwrap();
        let timer = poll_resolution_timers(
            &mut resolution,
            MonotonicMillis(1_000),
            2,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!(timer.no_accepted_arp_request, usize::from(accept == 0));
        dispatch_host_unreachable_failures(
            &mut resolution,
            &mut errors,
            &snapshot,
            MonotonicMillis(1_000),
            1,
            &mut NoResolutionFailureTrace,
        )
        .unwrap();
        assert_eq!(errors.pending_actions(), expected);
        assert_eq!(
            resolution.failure_counters().no_accepted_arp_request,
            usize::from(accept == 0)
        );
    }

    let routes = direct_routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = [Neighbor {
        interface: LAN,
        target: SOURCE,
        mac: REVERSE_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mixed_policy = ResolutionPolicy::with_retry(1_000, 60_000, 2).unwrap();
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        mixed_policy,
        &mut states,
        &mut actions,
        &mut [],
        &mut holds,
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();
    io.inject(LAN, frame(&[9; 8], 0, 17));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    io.set_generated_accept_budget(0);
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(1_000),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    io.set_generated_accept_budget(1);
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(1_000),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    assert_eq!(
        (
            resolution.status(WAN, DESTINATION).unwrap().attempts,
            resolution
                .status(WAN, DESTINATION)
                .unwrap()
                .accepted_attempts
        ),
        (2, 1)
    );
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(2_000),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(2_000),
        1,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!(errors.pending_actions(), 1);
}

#[test]
fn first_eligible_candidate_wins_and_suppressed_first_can_be_filled() {
    let routes = direct_routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = [Neighbor {
        interface: LAN,
        target: SOURCE,
        mac: REVERSE_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        retry_policy(),
        &mut states,
        &mut actions,
        &mut [],
        &mut holds,
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();
    let mut suppressed = frame(&[0x11; 8], 0, 1);
    suppressed[34] = 3;
    io.inject(LAN, suppressed);
    io.inject(LAN, frame(&[0x22; 9], 0, 17));
    io.inject(LAN, frame(&[0x33; 10], 0, 17));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(3).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(resolution.pending_failure_holds(), 1);
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(1_000),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        1,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    let generated = execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(1_000),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(generated.action.quote().len(), 29);
    assert_eq!(&generated.action.quote()[20..], &[0x22; 9]);
}

#[test]
fn gateway_failure_and_zero_hold_capacity_never_queue_code1() {
    let interfaces = interfaces();
    let bindings = bindings();
    let gateway = Ipv4Address::from_octets([198, 51, 100, 254]);
    let routes = [
        Route::new(
            Ipv4Address::from_octets([10, 0, 0, 0]),
            24,
            WAN,
            Some(gateway),
        )
        .unwrap(),
        direct_routes()[1],
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        retry_policy(),
        &mut states,
        &mut actions,
        &mut [],
        &mut [],
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();
    io.inject(LAN, frame(&[1; 8], 0, 17));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(1_000),
        1,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    assert_eq!(resolution.pending_failure_holds(), 0);
    assert_eq!(errors.pending_actions(), 0);

    let direct = direct_routes();
    let direct_snapshot = ForwardingSnapshot::new(&direct, &interfaces, &[], &bindings).unwrap();
    let mut direct_states = [ResolutionStateSlot::EMPTY; 1];
    let mut direct_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut direct_resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        retry_policy(),
        &mut direct_states,
        &mut direct_actions,
        &mut [],
        &mut [],
    );
    io.inject(LAN, frame(&[2; 8], 0, 17));
    forward_batch_with_resolution(
        io.receive(1).unwrap(),
        &direct_snapshot,
        &mut direct_resolution,
        MonotonicMillis(2_000),
        &mut NoTrace,
    );
    assert_eq!(direct_resolution.pending_actions(), 1);
    assert_eq!(direct_resolution.pending_failure_holds(), 0);
    assert_eq!(direct_resolution.failure_counters().capture_full, 1);
}

#[test]
fn reverse_miss_survives_arp_then_learning_queues_once() {
    let routes = direct_routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        retry_policy(),
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut holds,
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();
    io.inject(LAN, frame(&[7; 8], 0, 17));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(1_000),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    let mut failure_trace = FailureTrace::default();
    let first = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        1,
        &mut failure_trace,
    )
    .unwrap();
    assert_eq!(
        (first.reverse_arp_scheduled, errors.pending_actions()),
        (1, 0)
    );
    assert_eq!(
        resolution.status(LAN, SOURCE).unwrap().phase,
        ResolutionPhase::InitialQueued
    );
    assert!(matches!(
        failure_trace.events.as_slice(),
        [ResolutionFailureTrace::ReverseArpScheduled { .. }]
    ));
    let queued_wait = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        1,
        &mut failure_trace,
    )
    .unwrap();
    assert_eq!(
        (
            queued_wait.reverse_arp_scheduled,
            queued_wait.reverse_arp_pending,
            resolution.pending_actions(),
            resolution.failure_counters().reverse_arp_scheduled
        ),
        (0, 1, 1, 1)
    );
    assert!(matches!(
        failure_trace.events.last(),
        Some(ResolutionFailureTrace::ReverseArpPending { .. })
    ));
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(1_000),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    let committed_wait = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        1,
        &mut failure_trace,
    )
    .unwrap();
    assert_eq!(
        (
            committed_wait.reverse_arp_scheduled,
            committed_wait.reverse_arp_pending,
            resolution.pending_actions(),
            resolution.failure_counters().reverse_arp_scheduled
        ),
        (0, 1, 0, 1)
    );
    assert!(matches!(
        failure_trace.events.last(),
        Some(ResolutionFailureTrace::ReverseArpPending { .. })
    ));
    io.inject(LAN, arp_reply(SOURCE, REVERSE_MAC, LAN_IP));
    forward_batch_with_resolution(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        MonotonicMillis(1_000),
        &mut NoTrace,
    );
    let second = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        1,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!((second.queued, second.pending), (1, 0));
    assert_eq!(errors.pending_actions(), 1);
}

#[test]
fn reverse_terminal_failure_retires_without_recursive_icmp() {
    let routes = direct_routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        retry_policy(),
        &mut states,
        &mut actions,
        &mut [],
        &mut holds,
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();
    io.inject(LAN, frame(&[6; 8], 0, 17));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(1).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(1_000),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        1,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(1_000),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(2_000),
        2,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    let retired = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(2_000),
        1,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!(
        (
            retired.retired,
            retired.pending,
            resolution.pending_actions(),
            errors.pending_actions()
        ),
        (1, 0, 0, 0)
    );
    assert_eq!(resolution.failure_counters().reverse_resolution_failed, 1);
}

#[test]
fn publication_and_learning_cancel_unqueued_holds_and_storage_recreation_zeroes_it() {
    let routes = direct_routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    {
        let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            retry_policy(),
            &mut states,
            &mut actions,
            &mut dynamic,
            &mut holds,
        );
        let mut io = SimIo::new();
        io.inject(LAN, frame(&[0xa5; 32], 0, 17));
        forward_batch_with_resolution(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            MonotonicMillis(0),
            &mut NoTrace,
        );
        assert_eq!(resolution.pending_failure_holds(), 1);
        let static_neighbors = [Neighbor {
            interface: WAN,
            target: DESTINATION,
            mac: REVERSE_MAC,
        }];
        let published =
            ForwardingSnapshot::new(&routes, &interfaces, &static_neighbors, &bindings).unwrap();
        resolution.reconcile_publication(&published);
        assert_eq!(resolution.pending_failure_holds(), 0);
    }
    holds[0] = ResolutionFailureHoldSlot::EMPTY;
    let recreated = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        retry_policy(),
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut holds,
    );
    assert_eq!(recreated.pending_failure_holds(), 0);
    assert_eq!(holds[0].phase(), ResolutionFailureHoldPhase::Empty);
}

#[test]
fn learning_at_timeout_wins_before_or_after_timer_poll() {
    for learn_before_poll in [false, true] {
        let routes = direct_routes();
        let interfaces = interfaces();
        let bindings = bindings();
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 2];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            retry_policy(),
            &mut states,
            &mut actions,
            &mut dynamic,
            &mut holds,
        );
        let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            &mut error_states,
            &mut error_actions,
        );
        let mut io = SimIo::new();
        io.inject(LAN, frame(&[4; 8], 0, 17));
        forward_batch_with_resolution_and_icmpv4_errors(
            io.receive(1).unwrap(),
            &snapshot,
            &mut resolution,
            &mut errors,
            MonotonicMillis(0),
            &mut NoTrace,
        );
        execute_one_arp_request(
            &mut io,
            &mut resolution,
            MonotonicMillis(0),
            &mut NoGeneratedTrace,
        )
        .unwrap();
        if learn_before_poll {
            io.inject(WAN, forward_arp_reply());
            forward_batch_with_resolution(
                io.receive(1).unwrap(),
                &snapshot,
                &mut resolution,
                MonotonicMillis(1_000),
                &mut NoTrace,
            );
        }
        poll_resolution_timers(
            &mut resolution,
            MonotonicMillis(1_000),
            2,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        if !learn_before_poll {
            io.inject(WAN, forward_arp_reply());
            forward_batch_with_resolution(
                io.receive(1).unwrap(),
                &snapshot,
                &mut resolution,
                MonotonicMillis(1_000),
                &mut NoTrace,
            );
        }
        let dispatch = dispatch_host_unreachable_failures(
            &mut resolution,
            &mut errors,
            &snapshot,
            MonotonicMillis(1_000),
            1,
            &mut NoResolutionFailureTrace,
        )
        .unwrap();
        assert_eq!(
            (
                dispatch.queued,
                resolution.pending_failure_holds(),
                errors.pending_actions()
            ),
            (0, 0, 0)
        );
    }
}

#[test]
fn round_robin_and_icmp_pressure_retain_candidates_until_each_queues() {
    let second_destination = Ipv4Address::from_octets([10, 0, 0, 10]);
    let routes = direct_routes();
    let interfaces = interfaces();
    let bindings = bindings();
    let neighbors = [Neighbor {
        interface: LAN,
        target: SOURCE,
        mac: REVERSE_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 3];
    let mut actions = [ResolutionActionSlot::EMPTY; 3];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        retry_policy(),
        &mut states,
        &mut actions,
        &mut [],
        &mut holds,
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();
    io.inject(LAN, frame(&[1; 8], 0, 17));
    io.inject(LAN, frame_to(second_destination, &[2; 8]));
    forward_batch_with_resolution_and_icmpv4_errors(
        io.receive(2).unwrap(),
        &snapshot,
        &mut resolution,
        &mut errors,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    execute_one_arp_request(
        &mut io,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoGeneratedTrace,
    )
    .unwrap();
    poll_resolution_timers(
        &mut resolution,
        MonotonicMillis(1_000),
        3,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();

    let first = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_000),
        2,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!((first.queued, first.retained, first.pending), (1, 1, 1));
    execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(1_000),
        &mut NoGeneratedIcmpv4Trace,
    )
    .unwrap();
    let limited = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_099),
        2,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!(
        (limited.queued, limited.retained, limited.pending),
        (0, 1, 1)
    );
    let final_dispatch = dispatch_host_unreachable_failures(
        &mut resolution,
        &mut errors,
        &snapshot,
        MonotonicMillis(1_100),
        2,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!(
        (
            final_dispatch.queued,
            final_dispatch.pending,
            errors.pending_actions()
        ),
        (1, 0, 1)
    );
}

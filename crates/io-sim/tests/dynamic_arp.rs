use ruster_core::{
    execute_one_arp_request, forward_batch_with_resolution, ipv4_header_checksum, BatchReport,
    ConsumeReason, ControlDisposition, DropReason, DynamicNeighborSlot, ForwardingSnapshot, IfId,
    Interface, Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor,
    NoGeneratedTrace, PacketIo, ResolutionActionSlot, ResolutionPolicy, ResolutionPolicyError,
    ResolutionRuntime, ResolutionStateSlot, Route, TraceEvent,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};

const IFACE: IfId = IfId(1);
const LOCAL: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const PEER: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 20]);
const OTHER: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 21]);
const THIRD: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 22]);
const LOCAL_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const PEER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const NEW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 30]);

fn snapshot<'a>(
    routes: &'a [Route],
    interfaces: &'a [Interface],
    neighbors: &'a [Neighbor],
    bindings: &'a [LocalIpv4Binding],
) -> ForwardingSnapshot<'a> {
    ForwardingSnapshot::new(routes, interfaces, neighbors, bindings).unwrap()
}

fn base() -> ([Route; 1], [Interface; 1], [LocalIpv4Binding; 1]) {
    (
        [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, IFACE, None).unwrap()],
        [Interface {
            id: IFACE,
            mac: LOCAL_MAC,
        }],
        [LocalIpv4Binding {
            interface: IFACE,
            address: LOCAL,
        }],
    )
}

fn arp(
    opcode: u16,
    spa: Ipv4Address,
    tpa: Ipv4Address,
    sha: MacAddress,
    ethernet_source: MacAddress,
) -> Vec<u8> {
    let mut bytes = vec![0; 60];
    bytes[0..6].copy_from_slice(&LOCAL_MAC.0);
    bytes[6..12].copy_from_slice(&ethernet_source.0);
    bytes[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    bytes[14..16].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[18..22].copy_from_slice(&[6, 4, (opcode >> 8) as u8, opcode as u8]);
    bytes[22..28].copy_from_slice(&sha.0);
    bytes[28..32].copy_from_slice(&spa.octets());
    bytes[38..42].copy_from_slice(&tpa.octets());
    bytes
}

fn ipv4(destination: Ipv4Address) -> Vec<u8> {
    let mut bytes = vec![0; 34];
    bytes[0..6].copy_from_slice(&LOCAL_MAC.0);
    bytes[6..12].copy_from_slice(&[8; 6]);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&20_u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[198, 51, 100, 1]);
    bytes[30..34].copy_from_slice(&destination.octets());
    let checksum = ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn run<'a>(
    io: &mut SimIo,
    runtime: &mut ResolutionRuntime<'a>,
    snapshot: &ForwardingSnapshot<'_>,
    now: u64,
    budget: usize,
    trace: &mut VecTrace,
) -> BatchReport<std::convert::Infallible> {
    let batch = io.receive(budget).unwrap();
    forward_batch_with_resolution(batch, snapshot, runtime, MonotonicMillis(now), trace)
}

macro_rules! runtime {
    ($policy:expr, $states:ident, $actions:ident, $cache:ident) => {
        ResolutionRuntime::with_dynamic_neighbors($policy, &mut $states, &mut $actions, &mut $cache)
    };
}

#[test]
fn miss_request_reply_consume_then_reinjected_ipv4_forwards() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut cache = [DynamicNeighborSlot::EMPTY; 2];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    io.inject(IFACE, ipv4(PEER));
    assert_eq!(
        run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default()).dropped,
        1
    );
    io.pop_recycled();
    execute_one_arp_request(&mut io, &mut rt, MonotonicMillis(0), &mut NoGeneratedTrace)
        .unwrap()
        .unwrap();
    io.pop_tx().unwrap();
    io.inject(IFACE, arp(2, PEER, LOCAL, PEER_MAC, PEER_MAC));
    let reply = run(&mut io, &mut rt, &s, 1, 1, &mut VecTrace::default());
    assert_eq!((reply.consumed, reply.dropped), (1, 0));
    assert_eq!(
        io.pop_recycled().unwrap().cause,
        RecycleCause::Consumed(ConsumeReason::ArpControl)
    );
    io.inject(IFACE, ipv4(PEER));
    assert_eq!(
        run(&mut io, &mut rt, &s, 1, 1, &mut VecTrace::default()).tx_requested,
        1
    );
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &PEER_MAC.0);
}

#[test]
fn unsolicited_local_reply_learns_while_nonlocal_absent_is_ignored() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    io.inject(IFACE, arp(2, PEER, OTHER, PEER_MAC, PEER_MAC));
    let mut trace = VecTrace::default();
    let ignored = run(&mut io, &mut rt, &s, 0, 1, &mut trace);
    assert_eq!((ignored.consumed, ignored.dropped), (1, 0));
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::ArpControl {
            disposition: ControlDisposition::Ignored,
            ..
        }
    )));
    io.inject(IFACE, arp(1, OTHER, OTHER, NEW_MAC, NEW_MAC));
    run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    assert_eq!(rt.dynamic_neighbor_count(), 0);
    io.inject(IFACE, arp(2, PEER, LOCAL, PEER_MAC, PEER_MAC));
    let report = run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    assert_eq!((report.tx_requested, report.consumed), (0, 1));
    assert_eq!(rt.dynamic_neighbor_count(), 1);
}

#[test]
fn existing_mapping_merge_precedes_target_and_opcode_and_garp_refreshes() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let policy = ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 2_000, 100).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(policy, states, actions, cache);
    let mut io = SimIo::new();
    for (now, opcode, tpa, mac) in [
        (0, 2, LOCAL, PEER_MAC),
        (40, 2, OTHER, NEW_MAC),
        (80, 1, OTHER, PEER_MAC),
        (120, 1, PEER, NEW_MAC),
    ] {
        io.inject(IFACE, arp(opcode, PEER, tpa, mac, MacAddress([9; 6])));
        run(&mut io, &mut rt, &s, now, 1, &mut VecTrace::default());
        io.pop_recycled();
        io.inject(IFACE, ipv4(PEER));
        run(&mut io, &mut rt, &s, now, 1, &mut VecTrace::default());
        assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &mac.0);
    }
    io.inject(IFACE, ipv4(PEER));
    run(&mut io, &mut rt, &s, 219, 1, &mut VecTrace::default());
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &NEW_MAC.0);
}

#[test]
fn local_request_learns_sha_even_when_ethernet_source_differs_and_probe_does_not() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    io.inject(
        IFACE,
        arp(1, PEER, LOCAL, PEER_MAC, MacAddress([2, 9, 9, 9, 9, 9])),
    );
    let learned = run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    assert_eq!((learned.tx_requested, learned.consumed), (1, 0));
    io.pop_tx();
    io.inject(
        IFACE,
        arp(1, Ipv4Address::from_octets([0; 4]), LOCAL, NEW_MAC, NEW_MAC),
    );
    assert_eq!(
        run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default()).tx_requested,
        1
    );
    assert_eq!(rt.dynamic_neighbor_count(), 1);
    io.pop_tx();
    io.inject(IFACE, ipv4(PEER));
    run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &PEER_MAC.0);
}

#[test]
fn invalid_sender_hardware_drops_atomically_without_cache_or_action_mutation() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    io.inject(IFACE, ipv4(PEER));
    run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    io.pop_recycled();
    for (sha, reason) in [
        (MacAddress([0; 6]), DropReason::ArpSenderHardwareZero),
        (
            MacAddress([0xff; 6]),
            DropReason::ArpSenderHardwareBroadcast,
        ),
        (
            MacAddress([1, 0, 0, 0, 0, 1]),
            DropReason::ArpSenderHardwareMulticast,
        ),
    ] {
        let packet = arp(2, PEER, LOCAL, sha, PEER_MAC);
        io.inject(IFACE, packet.clone());
        let report = run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
        assert_eq!((report.dropped, report.consumed), (1, 0));
        let recycled = io.pop_recycled().unwrap();
        assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
        assert_eq!(recycled.bytes, packet);
        assert_eq!((rt.dynamic_neighbor_count(), rt.pending_actions()), (0, 1));
    }
}

#[test]
fn non_host_sender_protocol_addresses_are_consumed_without_learning() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    for sender in [
        Ipv4Address::from_octets([224, 0, 0, 1]),
        Ipv4Address::from_octets([255; 4]),
        Ipv4Address::from_octets([192, 0, 2, 255]),
    ] {
        io.inject(IFACE, arp(2, sender, LOCAL, PEER_MAC, PEER_MAC));
    }
    let mut trace = VecTrace::default();
    let report = run(&mut io, &mut rt, &s, 0, 3, &mut trace);
    assert_eq!((report.consumed, report.dropped), (3, 0));
    assert_eq!(rt.dynamic_neighbor_count(), 0);
    assert_eq!(
        trace
            .events()
            .iter()
            .filter(|event| matches!(
                event,
                TraceEvent::ArpControl {
                    disposition: ControlDisposition::SenderNotHost,
                    ..
                }
            ))
            .count(),
        3
    );
}

#[test]
fn foreign_local_spa_cannot_poison_and_static_mapping_has_priority() {
    let (routes, interfaces, bindings) = base();
    let static_mac = MacAddress([2, 7, 7, 7, 7, 7]);
    let neighbor = Neighbor {
        interface: IFACE,
        target: PEER,
        mac: static_mac,
    };
    let neighbors = [neighbor];
    let s = snapshot(&routes, &interfaces, &neighbors, &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    io.inject(IFACE, arp(1, LOCAL, LOCAL, NEW_MAC, NEW_MAC));
    assert_eq!(
        run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default()).tx_requested,
        1
    );
    io.pop_tx();
    io.inject(IFACE, arp(2, PEER, LOCAL, NEW_MAC, NEW_MAC));
    let mut trace = VecTrace::default();
    let static_reply = run(&mut io, &mut rt, &s, 0, 1, &mut trace);
    assert_eq!((static_reply.consumed, static_reply.dropped), (1, 0));
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::ArpControl {
            disposition: ControlDisposition::StaticPreserved,
            ..
        }
    )));
    assert_eq!(rt.dynamic_neighbor_count(), 0);
    io.inject(IFACE, ipv4(PEER));
    run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &static_mac.0);
}

#[test]
fn ttl_boundary_refresh_expired_reuse_and_cache_full_are_exact() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let policy = ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 2_000, 100).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(policy, states, actions, cache);
    let mut io = SimIo::new();
    io.inject(IFACE, ipv4(OTHER));
    run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    io.pop_recycled();
    io.inject(IFACE, arp(2, PEER, LOCAL, PEER_MAC, PEER_MAC));
    run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    io.inject(IFACE, arp(2, OTHER, LOCAL, NEW_MAC, NEW_MAC));
    let mut trace = VecTrace::default();
    let full = run(&mut io, &mut rt, &s, 99, 1, &mut trace);
    assert_eq!((full.consumed, full.dropped), (1, 0));
    assert_eq!(rt.pending_actions(), 1);
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::ArpControl {
            disposition: ControlDisposition::CacheFull,
            ..
        }
    )));
    io.inject(IFACE, ipv4(PEER));
    assert_eq!(
        run(&mut io, &mut rt, &s, 99, 1, &mut VecTrace::default()).tx_requested,
        1
    );
    io.pop_tx();
    io.inject(IFACE, ipv4(PEER));
    assert_eq!(
        run(&mut io, &mut rt, &s, 100, 1, &mut VecTrace::default()).dropped,
        1
    );
    io.inject(IFACE, arp(2, OTHER, LOCAL, NEW_MAC, NEW_MAC));
    run(&mut io, &mut rt, &s, 100, 1, &mut VecTrace::default());
    assert_eq!(rt.dynamic_neighbor_count(), 1);
    assert_eq!(
        rt.pending_actions(),
        1,
        "only the expired peer miss remains"
    );
}

#[test]
fn clock_regression_does_not_mutate_cache_and_later_equal_time_recovers() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    io.inject(IFACE, ipv4(OTHER));
    run(&mut io, &mut rt, &s, 100, 1, &mut VecTrace::default());
    io.pop_recycled();
    io.inject(IFACE, arp(2, PEER, LOCAL, PEER_MAC, PEER_MAC));
    run(&mut io, &mut rt, &s, 100, 1, &mut VecTrace::default());
    io.inject(IFACE, arp(2, PEER, LOCAL, NEW_MAC, NEW_MAC));
    let mut trace = VecTrace::default();
    run(&mut io, &mut rt, &s, 99, 1, &mut trace);
    assert_eq!(rt.pending_actions(), 1);
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::ArpControl {
            disposition: ControlDisposition::ClockRegression,
            ..
        }
    )));
    io.inject(IFACE, ipv4(PEER));
    run(&mut io, &mut rt, &s, 100, 1, &mut VecTrace::default());
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &PEER_MAC.0);
}

#[test]
fn reply_before_generated_execution_cancels_only_matching_fifo_action() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let second_if = IfId(2);
    let second_routes = [Route::new(
        Ipv4Address::from_octets([192, 0, 2, 20]),
        32,
        second_if,
        None,
    )
    .unwrap()];
    let second_interfaces = [Interface {
        id: second_if,
        mac: NEW_MAC,
    }];
    let second_bindings = [LocalIpv4Binding {
        interface: second_if,
        address: Ipv4Address::from_octets([198, 51, 100, 2]),
    }];
    let second = snapshot(&second_routes, &second_interfaces, &[], &second_bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 3];
    let mut actions = [ResolutionActionSlot::EMPTY; 3];
    let mut cache = [DynamicNeighborSlot::EMPTY; 3];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    for target in [PEER, OTHER] {
        io.inject(IFACE, ipv4(target));
    }
    run(&mut io, &mut rt, &s, 0, 2, &mut VecTrace::default());
    io.inject(second_if, ipv4(PEER));
    run(&mut io, &mut rt, &second, 0, 1, &mut VecTrace::default());
    assert_eq!(rt.pending_actions(), 3);
    io.inject(IFACE, arp(2, PEER, LOCAL, PEER_MAC, PEER_MAC));
    run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    assert_eq!(rt.pending_actions(), 2);
    io.inject(IFACE, ipv4(THIRD));
    run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default());
    assert_eq!(rt.pending_actions(), 3, "cancelled capacity is reusable");
    execute_one_arp_request(&mut io, &mut rt, MonotonicMillis(0), &mut NoGeneratedTrace)
        .unwrap()
        .unwrap();
    let request = io.pop_tx().unwrap();
    assert_eq!(&request.bytes[38..42], &OTHER.octets());
    execute_one_arp_request(&mut io, &mut rt, MonotonicMillis(0), &mut NoGeneratedTrace)
        .unwrap()
        .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, second_if);
}

#[test]
fn mixed_reply_then_ipv4_uses_dynamic_mapping_in_same_batch() {
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    let mut io = SimIo::new();
    io.inject(IFACE, arp(2, PEER, LOCAL, PEER_MAC, PEER_MAC));
    io.inject(IFACE, ipv4(PEER));
    let mut trace = VecTrace::default();
    let report = run(&mut io, &mut rt, &s, 0, 2, &mut trace);
    assert_eq!(
        (
            report.received,
            report.consumed,
            report.tx_requested,
            report.dropped
        ),
        (2, 1, 1, 0)
    );
    assert_eq!(report.completion.recycled, 1);
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &PEER_MAC.0);
    assert_eq!(
        io.pop_recycled().unwrap().cause,
        RecycleCause::Consumed(ConsumeReason::ArpControl)
    );
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::ArpReplyValidated { .. },
            TraceEvent::ArpControl {
                disposition: ControlDisposition::Inserted,
                ..
            },
            TraceEvent::Consumed {
                reason: ConsumeReason::ArpControl,
                disposition: ControlDisposition::Inserted,
                ..
            },
            TraceEvent::Ipv4Validated { .. },
            TraceEvent::Routed { .. },
            TraceEvent::TxRequested { .. },
            TraceEvent::BatchCompleted {
                tx_accepted: 1,
                tx_rejected: 0
            }
        ]
    ));
}

#[test]
fn zero_capacity_and_runtime_recreation_are_safe() {
    assert_eq!(
        ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 2_000, 0),
        Err(ResolutionPolicyError::DynamicNeighborTtlZero)
    );
    let (routes, interfaces, bindings) = base();
    let s = snapshot(&routes, &interfaces, &[], &bindings);
    let mut states = [];
    let mut actions = [];
    let mut cache = [];
    let mut io = SimIo::new();
    {
        let mut rt = runtime!(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            states,
            actions,
            cache
        );
        io.inject(IFACE, arp(2, PEER, LOCAL, PEER_MAC, PEER_MAC));
        assert_eq!(
            run(&mut io, &mut rt, &s, 0, 1, &mut VecTrace::default()).consumed,
            1
        );
        assert_eq!(rt.dynamic_neighbor_count(), 0);
    }
    let rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    assert_eq!((rt.dynamic_neighbor_count(), rt.pending_actions()), (0, 0));

    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    {
        let mut rt = runtime!(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            states,
            actions,
            cache
        );
        io.inject(IFACE, arp(2, PEER, LOCAL, PEER_MAC, PEER_MAC));
        run(&mut io, &mut rt, &s, 1, 1, &mut VecTrace::default());
        assert_eq!(rt.dynamic_neighbor_count(), 1);
    }
    let rt = runtime!(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        cache
    );
    assert_eq!(rt.dynamic_neighbor_count(), 0);
}

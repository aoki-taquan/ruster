use std::convert::Infallible;

use ruster_core::{
    execute_one_arp_request, forward_batch_with_resolution, ipv4_header_checksum,
    ArpRequestBuildError, BatchCompletion, DropReason, ExecuteArpRequestError, ForwardingSnapshot,
    GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo,
    GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, IfId, Interface,
    Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, NoTrace, PacketIo,
    ResolutionActionSlot, ResolutionPolicy, ResolutionPolicyError, ResolutionResult,
    ResolutionRuntime, ResolutionStateSlot, Route, TraceEvent, ETHERNET_HEADER_LEN,
};
use ruster_io_sim::{
    FrameOrigin, GeneratedRecycleCause, RecycleCause, SimGeneratedError, SimIo, VecGeneratedTrace,
    VecTrace,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const ROUTER_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const LOCAL_IP: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 2]);
const TARGET: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

fn frame(destination: Ipv4Address) -> Vec<u8> {
    let mut bytes = vec![0_u8; ETHERNET_HEADER_LEN + 20];
    bytes[0..6].copy_from_slice(&[9; 6]);
    bytes[6..12].copy_from_slice(&[1; 6]);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&20_u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[192, 0, 2, 10]);
    bytes[30..34].copy_from_slice(&destination.octets());
    let checksum = ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn interface() -> Interface {
    Interface {
        id: WAN,
        mac: ROUTER_MAC,
    }
}

fn binding() -> LocalIpv4Binding {
    LocalIpv4Binding {
        interface: WAN,
        address: LOCAL_IP,
    }
}

fn gateway_route() -> Route {
    Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(TARGET)).unwrap()
}

fn policy() -> ResolutionPolicy {
    ResolutionPolicy::new(1_000, 2_000).unwrap()
}

#[test]
fn resolution_policy_rejects_short_interval_and_state_ttl() {
    assert_eq!(
        ResolutionPolicy::new(999, 2_000),
        Err(ResolutionPolicyError::IntervalTooShort)
    );
    assert_eq!(
        ResolutionPolicy::new(1_000, 999),
        Err(ResolutionPolicyError::StateTtlTooShort)
    );
}

#[test]
fn recreating_runtime_clears_caller_state_and_queued_actions() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut io = SimIo::new();
    let destination = Ipv4Address::from_octets([198, 51, 100, 20]);
    {
        let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
        run_miss(
            &mut io,
            &snapshot,
            &mut runtime,
            0,
            destination,
            &mut VecTrace::default(),
        );
        assert_eq!(runtime.pending_actions(), 1);
    }
    let mut recreated = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    assert_eq!(recreated.pending_actions(), 0);
    run_miss(
        &mut io,
        &snapshot,
        &mut recreated,
        0,
        destination,
        &mut VecTrace::default(),
    );
    assert_eq!(recreated.pending_actions(), 1);
    assert_eq!(recreated.counters().queued, 1);
    assert_eq!(recreated.counters().suppressed, 0);
}

fn run_miss(
    io: &mut SimIo,
    snapshot: &ForwardingSnapshot<'_>,
    runtime: &mut ResolutionRuntime<'_>,
    now: u64,
    destination: Ipv4Address,
    trace: &mut VecTrace,
) {
    let original = frame(destination);
    io.inject(LAN, original.clone());
    let batch = io.receive(1).unwrap();
    let report =
        forward_batch_with_resolution(batch, snapshot, runtime, MonotonicMillis(now), trace);
    assert_eq!(report.dropped, 1);
    assert_eq!(
        report.completion,
        BatchCompletion {
            tx_requested: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            recycled: 1,
            error: None,
        }
    );
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::NeighborUnresolved)
    );
    assert_eq!(recycled.bytes, original);
}

#[test]
fn unresolved_neighbor_generates_broadcast_arp_request_and_recycles_trigger_atomically() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut rx_trace = VecTrace::default();
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        10,
        Ipv4Address::from_octets([198, 51, 100, 20]),
        &mut rx_trace,
    );
    assert!(matches!(
        rx_trace.events(),
        [
            TraceEvent::Ipv4Validated { .. },
            TraceEvent::NeighborResolution {
                result: ResolutionResult::Queued,
                ..
            },
            TraceEvent::Dropped {
                reason: DropReason::NeighborUnresolved,
                ..
            },
            TraceEvent::BatchCompleted { .. }
        ]
    ));

    let mut generated_trace = VecGeneratedTrace::default();
    let report = execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(10),
        &mut generated_trace,
    )
    .unwrap()
    .unwrap();
    assert!(report.completion.invariants_hold());
    assert_eq!(report.completion.requested, 1);
    assert_eq!(report.completion.accepted, 1);
    assert_eq!(runtime.counters().dequeued, 1);
    assert!(matches!(
        generated_trace.events(),
        [
            ruster_core::GeneratedArpTrace::TxRequested { .. },
            ruster_core::GeneratedArpTrace::BatchCompleted {
                accepted: 1,
                rejected: 0
            }
        ]
    ));
    let tx = io.pop_tx().unwrap();
    assert_eq!(tx.origin, FrameOrigin::Generated);
    assert_eq!(tx.egress, WAN);
    assert_eq!(tx.bytes.len(), 60);
    assert_eq!(&tx.bytes[0..6], &[0xff; 6]);
    assert_eq!(&tx.bytes[6..12], &ROUTER_MAC.0);
    assert_eq!(&tx.bytes[12..14], &0x0806_u16.to_be_bytes());
    assert_eq!(&tx.bytes[14..16], &1_u16.to_be_bytes());
    assert_eq!(&tx.bytes[16..18], &0x0800_u16.to_be_bytes());
    assert_eq!(&tx.bytes[18..22], &[6, 4, 0, 1]);
    assert_eq!(&tx.bytes[22..28], &ROUTER_MAC.0);
    assert_eq!(&tx.bytes[28..32], &LOCAL_IP.octets());
    assert_eq!(&tx.bytes[32..38], &[0; 6]);
    assert_eq!(&tx.bytes[38..42], &TARGET.octets());
    assert_eq!(&tx.bytes[42..60], &[0; 18]);
}

#[test]
fn ordinary_resolution_request_is_not_probe_or_announcement() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 20]),
        &mut VecTrace::default(),
    );
    execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(0),
        &mut VecGeneratedTrace::default(),
    )
    .unwrap()
    .unwrap();
    let request = io.pop_tx().unwrap().bytes;
    assert_eq!(&request[0..6], &[0xff; 6]);
    assert_eq!(&request[20..22], &1_u16.to_be_bytes());
    assert_eq!(&request[28..32], &LOCAL_IP.octets());
    assert_ne!(&request[28..32], &[0; 4], "not an ARP Probe");
    assert_eq!(&request[32..38], &[0; 6]);
    assert_eq!(&request[38..42], &TARGET.octets());
    assert_ne!(&request[28..32], &request[38..42], "not an Announcement");
}

#[test]
fn same_target_is_rate_limited_to_one_request_per_second_at_exact_deadline() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    let dst = Ipv4Address::from_octets([198, 51, 100, 20]);

    run_miss(&mut io, &snapshot, &mut runtime, 0, dst, &mut trace);
    io.set_generated_accept_budget(0);
    let first_request = execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(0),
        &mut VecGeneratedTrace::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(first_request.completion.rejected, 1);
    run_miss(&mut io, &snapshot, &mut runtime, 999, dst, &mut trace);
    assert_eq!(runtime.pending_actions(), 0);
    run_miss(&mut io, &snapshot, &mut runtime, 1_000, dst, &mut trace);
    assert_eq!(runtime.pending_actions(), 1);
    assert_eq!(runtime.counters().queued, 2);
    assert_eq!(runtime.counters().suppressed, 1);
}

#[test]
fn suppression_deadline_starts_at_generated_commit_time() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    let destination = Ipv4Address::from_octets([198, 51, 100, 20]);
    run_miss(&mut io, &snapshot, &mut runtime, 0, destination, &mut trace);
    execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(700),
        &mut VecGeneratedTrace::default(),
    )
    .unwrap()
    .unwrap();
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        1_699,
        destination,
        &mut trace,
    );
    assert_eq!(runtime.pending_actions(), 0);
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        1_700,
        destination,
        &mut trace,
    );
    assert_eq!(runtime.pending_actions(), 1);
    assert_eq!(runtime.counters().suppressed, 1);
}

#[test]
fn resolution_keys_are_independent_by_interface_and_target() {
    let direct = Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap();
    let routes = [direct];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 3];
    let mut actions = [ResolutionActionSlot::EMPTY; 3];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 10]),
        &mut trace,
    );
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 11]),
        &mut trace,
    );
    assert_eq!(runtime.pending_actions(), 2);

    let other_interface = Interface {
        id: IfId(3),
        mac: MacAddress([3; 6]),
    };
    let other_route = Route::new(
        Ipv4Address::from_octets([198, 51, 100, 10]),
        32,
        IfId(3),
        None,
    )
    .unwrap();
    let other_binding = LocalIpv4Binding {
        interface: IfId(3),
        address: Ipv4Address::from_octets([198, 18, 0, 1]),
    };
    let routes = [other_route];
    let interfaces = [other_interface];
    let bindings = [other_binding];
    let other = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    run_miss(
        &mut io,
        &other,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 10]),
        &mut trace,
    );
    assert_eq!(runtime.pending_actions(), 3);
}

#[test]
fn clock_regression_is_typed_and_does_not_mutate_queue() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    let dst = Ipv4Address::from_octets([198, 51, 100, 20]);
    run_miss(&mut io, &snapshot, &mut runtime, 100, dst, &mut trace);
    run_miss(&mut io, &snapshot, &mut runtime, 99, dst, &mut trace);
    assert_eq!(runtime.pending_actions(), 1);
    assert_eq!(runtime.counters().clock_regressions, 1);
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::NeighborResolution {
            result: ResolutionResult::ClockRegression,
            ..
        }
    )));
}

#[test]
fn generated_commit_clock_regression_retains_action() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        100,
        Ipv4Address::from_octets([198, 51, 100, 20]),
        &mut VecTrace::default(),
    );
    assert_eq!(
        execute_one_arp_request(
            &mut io,
            &mut runtime,
            MonotonicMillis(99),
            &mut VecGeneratedTrace::default(),
        ),
        Err(ExecuteArpRequestError::ClockRegression)
    );
    assert_eq!(runtime.pending_actions(), 1);
    assert_eq!(io.pending_tx(), 0);
}

#[test]
fn state_full_never_evicts_live_entry_and_ttl_allows_reuse() {
    let direct = Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap();
    let routes = [direct];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    let first = Ipv4Address::from_octets([198, 51, 100, 10]);
    let second = Ipv4Address::from_octets([198, 51, 100, 11]);
    run_miss(&mut io, &snapshot, &mut runtime, 0, first, &mut trace);
    execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(0),
        &mut VecGeneratedTrace::default(),
    )
    .unwrap()
    .unwrap();
    run_miss(&mut io, &snapshot, &mut runtime, 1_999, second, &mut trace);
    assert_eq!(runtime.counters().state_full, 1);
    run_miss(&mut io, &snapshot, &mut runtime, 2_000, second, &mut trace);
    assert_eq!(runtime.pending_actions(), 1);
}

#[test]
fn action_full_does_not_create_phantom_suppression() {
    let direct = Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap();
    let routes = [direct];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    let first = Ipv4Address::from_octets([198, 51, 100, 10]);
    let second = Ipv4Address::from_octets([198, 51, 100, 11]);
    run_miss(&mut io, &snapshot, &mut runtime, 0, first, &mut trace);
    run_miss(&mut io, &snapshot, &mut runtime, 0, second, &mut trace);
    assert_eq!(runtime.counters().action_full, 1);
    execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(0),
        &mut VecGeneratedTrace::default(),
    )
    .unwrap()
    .unwrap();
    run_miss(&mut io, &snapshot, &mut runtime, 0, second, &mut trace);
    assert_eq!(runtime.pending_actions(), 1);
    assert_eq!(runtime.counters().suppressed, 0);
}

#[test]
fn local_binding_missing_and_forbidden_targets_generate_nothing() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let no_binding = ForwardingSnapshot::new(&routes, &interfaces, &[], &[]).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 4];
    let mut actions = [ResolutionActionSlot::EMPTY; 4];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    run_miss(
        &mut io,
        &no_binding,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 20]),
        &mut trace,
    );
    assert_eq!(runtime.pending_actions(), 0);

    for target in [[0, 0, 0, 0], [224, 0, 0, 1], [255, 255, 255, 255]] {
        let target = Ipv4Address::from_octets(target);
        let route = Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(target)).unwrap();
        let routes = [route];
        let bindings = [binding()];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        run_miss(
            &mut io,
            &snapshot,
            &mut runtime,
            0,
            Ipv4Address::from_octets([198, 51, 100, 20]),
            &mut trace,
        );
    }
    let direct = Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap();
    let routes = [direct];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 255]),
        &mut trace,
    );
    assert_eq!(runtime.pending_actions(), 0);
    assert_eq!(runtime.counters().forbidden_target, 4);
    assert_eq!(
        trace
            .events()
            .iter()
            .filter(|event| matches!(
                event,
                TraceEvent::NeighborResolution {
                    result: ResolutionResult::ForbiddenTarget,
                    ..
                }
            ))
            .count(),
        4
    );
}

#[test]
fn local_source_ip_is_forbidden_as_connected_or_gateway_target() {
    let interfaces = [interface()];
    let bindings = [binding()];
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();

    let connected = Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, WAN, None).unwrap();
    let routes = [connected];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    run_miss(&mut io, &snapshot, &mut runtime, 0, LOCAL_IP, &mut trace);

    let gateway = Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(LOCAL_IP)).unwrap();
    let routes = [gateway];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 20]),
        &mut trace,
    );
    assert_eq!(runtime.pending_actions(), 0);
    assert_eq!(runtime.counters().forbidden_target, 2);
}

#[test]
fn gateway_target_matching_same_egress_connected_broadcast_is_forbidden() {
    let connected = Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, WAN, None).unwrap();
    let default = Route::new(
        Ipv4Address::from_octets([0; 4]),
        0,
        WAN,
        Some(Ipv4Address::from_octets([203, 0, 113, 255])),
    )
    .unwrap();
    let routes = [connected, default];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    run_miss(
        &mut io,
        &snapshot,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 20]),
        &mut trace,
    );
    assert_eq!(runtime.pending_actions(), 0);
    assert_eq!(runtime.counters().forbidden_target, 1);
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::NeighborResolution {
            target,
            result: ResolutionResult::ForbiddenTarget,
            ..
        } if *target == Ipv4Address::from_octets([203, 0, 113, 255])
    )));
}

#[test]
fn static_neighbor_hit_leaves_resolution_runtime_untouched() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let neighbors = [Neighbor {
        interface: WAN,
        target: TARGET,
        mac: MacAddress([4; 6]),
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, frame(Ipv4Address::from_octets([198, 51, 100, 20])));
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut runtime,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(report.tx_requested, 1);
    assert_eq!(runtime.counters(), Default::default());
    assert_eq!(runtime.pending_actions(), 0);
}

#[test]
fn generated_lease_commit_cancel_abandon_and_allocation_failures_are_exact() {
    let mut io = SimIo::new();
    io.set_generated_max_frame(60);
    let (completion, committed_allocation) = {
        let mut batch = io.begin_generated(WAN);
        assert_eq!(
            batch.allocate(0).err(),
            Some(GeneratedAllocationError::ZeroLength)
        );
        assert_eq!(
            batch.allocate(61).err(),
            Some(GeneratedAllocationError::FrameTooLarge)
        );
        let mut committed = batch.allocate(60).unwrap();
        let committed_allocation = committed.bytes_mut().as_ptr();
        committed.commit();
        batch.allocate(60).unwrap().cancel();
        drop(batch.allocate(60).unwrap());
        (batch.finish(), committed_allocation)
    };
    assert!(completion.invariants_hold());
    assert_eq!(completion.attempts, 5);
    assert_eq!(completion.allocated, 3);
    assert_eq!(completion.failed, 2);
    assert_eq!(completion.requested, 1);
    assert_eq!(completion.cancelled, 1);
    assert_eq!(completion.abandoned, 1);
    assert_eq!(
        io.pop_tx().unwrap().bytes.as_ptr(),
        committed_allocation,
        "backend allocation must move into TX without cloning"
    );
    assert_eq!(
        io.pop_generated_recycled().unwrap().cause,
        GeneratedRecycleCause::Cancelled
    );
    assert_eq!(
        io.pop_generated_recycled().unwrap().cause,
        GeneratedRecycleCause::Abandoned
    );

    io.set_generated_budget(0);
    let completion = {
        let mut batch = io.begin_generated(WAN);
        assert_eq!(
            batch.allocate(60).err(),
            Some(GeneratedAllocationError::Unavailable)
        );
        batch.finish()
    };
    assert!(completion.invariants_hold());
    assert_eq!(completion.allocated, 0, "failure transfers no ownership");
}

#[test]
fn generated_partial_tx_error_preserves_invariants_and_recycles_rejects() {
    let mut io = SimIo::new();
    io.set_generated_accept_budget(1);
    io.fail_next_generated_finish();
    let completion = {
        let mut batch = io.begin_generated(WAN);
        batch.allocate(60).unwrap().commit();
        batch.allocate(60).unwrap().commit();
        batch.finish()
    };
    assert!(completion.invariants_hold());
    assert_eq!(completion.accepted, 1);
    assert_eq!(completion.rejected, 1);
    assert_eq!(completion.error, Some(SimGeneratedError::Injected));
    assert_eq!(
        io.pop_generated_recycled().unwrap().cause,
        GeneratedRecycleCause::TxRejected
    );
}

#[test]
fn allocation_failure_retains_action_and_does_not_start_deadline() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    let dst = Ipv4Address::from_octets([198, 51, 100, 20]);
    run_miss(&mut io, &snapshot, &mut runtime, 0, dst, &mut trace);
    io.set_generated_budget(0);
    let mut generated_trace = VecGeneratedTrace::default();
    let failed = execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(500),
        &mut generated_trace,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        failed.allocation_error,
        Some(GeneratedAllocationError::Unavailable)
    );
    assert!(matches!(
        generated_trace.events(),
        [
            ruster_core::GeneratedArpTrace::AllocationFailed(GeneratedAllocationError::Unavailable),
            ruster_core::GeneratedArpTrace::BatchCompleted {
                accepted: 0,
                rejected: 0
            }
        ]
    ));
    assert_eq!(runtime.pending_actions(), 1);
    io.set_generated_budget(1);
    execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(700),
        &mut VecGeneratedTrace::default(),
    )
    .unwrap()
    .unwrap();
    run_miss(&mut io, &snapshot, &mut runtime, 1_699, dst, &mut trace);
    assert_eq!(runtime.pending_actions(), 0);
    run_miss(&mut io, &snapshot, &mut runtime, 1_700, dst, &mut trace);
    assert_eq!(runtime.pending_actions(), 1);
}

#[test]
fn builder_failure_cancels_lease_and_retains_action() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut rx = SimIo::new();
    run_miss(
        &mut rx,
        &snapshot,
        &mut runtime,
        0,
        Ipv4Address::from_octets([198, 51, 100, 20]),
        &mut VecTrace::default(),
    );
    let report = execute_one_arp_request(
        &mut ShortBufferIo,
        &mut runtime,
        MonotonicMillis(0),
        &mut VecGeneratedTrace::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        report.build_error,
        Some(ArpRequestBuildError::ExactLengthRequired)
    );
    assert!(report.completion.invariants_hold());
    assert_eq!(report.completion.cancelled, 1);
    assert_eq!(runtime.pending_actions(), 1);
}

struct ShortBufferIo;

struct ShortBufferBatch {
    allocated: usize,
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
            allocated: 0,
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
        self.allocated += 1;
        Ok(GeneratedPacketLease::new(ShortBufferSlot {
            bytes: vec![0; frame_len - 1],
            cancelled: &mut self.cancelled,
            abandoned: &mut self.abandoned,
        }))
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        GeneratedBatchCompletion {
            attempts: 1,
            allocated: self.allocated,
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
            GeneratedSlotCompletion::Transmit => panic!("short buffer must not be transmitted"),
        }
    }
}

#[test]
fn mixed_rx_and_generated_tx_are_fifo_budgeted_and_origin_typed() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let bindings = [binding()];
    let neighbors = [Neighbor {
        interface: WAN,
        target: TARGET,
        mac: MacAddress([4; 6]),
    }];
    let hit = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let miss = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::new(policy(), &mut states, &mut actions);
    let mut io = SimIo::new();
    io.set_generated_budget(1);
    io.inject(LAN, frame(Ipv4Address::from_octets([198, 51, 100, 10])));
    io.inject(LAN, frame(Ipv4Address::from_octets([198, 51, 100, 11])));
    let first = io.receive(1).unwrap();
    forward_batch_with_resolution(first, &hit, &mut runtime, MonotonicMillis(0), &mut NoTrace);
    let second = io.receive(1).unwrap();
    forward_batch_with_resolution(
        second,
        &miss,
        &mut runtime,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    execute_one_arp_request(
        &mut io,
        &mut runtime,
        MonotonicMillis(0),
        &mut VecGeneratedTrace::default(),
    )
    .unwrap()
    .unwrap();
    let rx_tx = io.pop_tx().unwrap();
    let generated_tx = io.pop_tx().unwrap();
    assert_eq!(rx_tx.sequence, 0);
    assert_eq!(rx_tx.origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(generated_tx.sequence, 2);
    assert_eq!(generated_tx.origin, FrameOrigin::Generated);
}

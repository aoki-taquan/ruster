use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    num::NonZeroU64,
};

use ruster_config::{parse, validate, ValidatedConfig, ValidationLimits};
use ruster_control::{
    plan_full_service_v1, plan_successor, FullServiceCandidateV1, FullServicePlanInputs,
    PlanOutcome, PlanRestartRequired, SuccessorError,
};
use ruster_core::{
    bind_publication_backend, internet_checksum, ipv4_header_checksum, FirewallHashKey,
    GeneratedArpTrace, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink, GeneratedTraceSink, IfId,
    Ipv4Address, MonotonicMillis, Nat44TcpHashKey, Nat44UdpHashKey, ResolutionFailureTrace,
    ResolutionFailureTraceSink, ResolutionTimerTrace, ResolutionTimerTraceSink, TraceEvent,
    TraceSink,
};
use ruster_integration::{activate_initial, FullServiceRuntimeStorage};
use ruster_io_sim::{BoundSimIoControl, SimIo};
use ruster_runtime::{
    run_tick, PublicationOutcome, RxPhaseReport, TickPhaseTrace, TickPhaseTraceSink,
};

const FULL_SERVICE: &str = include_str!("full-service.toml");
const LAN: IfId = IfId(1);
const LAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 4];
const HOST: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 20]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 20]);

struct CountingAllocator;

thread_local! {
    static ALLOCATION_COUNT: Cell<u64> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout`はallocator contractから渡されます。
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            increment_count();
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer`と`layout`はこのallocatorから取得されています。
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout`はallocator contractから渡されます。
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            increment_count();
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: `pointer`と`layout`はこのallocatorから取得されています。
        let new_pointer = unsafe { System.realloc(pointer, layout, size) };
        if !new_pointer.is_null() {
            increment_count();
        }
        new_pointer
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn increment_count() {
    ALLOCATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

fn reset_allocation_count() {
    ALLOCATION_COUNT.with(|count| count.set(0));
}

fn allocation_count() -> u64 {
    ALLOCATION_COUNT.with(Cell::get)
}

fn candidate(source: &str, generation: u64, seed: u64) -> FullServiceCandidateV1 {
    let parsed = parse(source.as_bytes()).expect("syntax fixture");
    let config = match validate(
        parsed,
        ValidationLimits {
            max_slots_per_table: 1_048_576,
            max_runtime_bytes: 1 << 30,
        },
    )
    .expect("semantic fixture")
    {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("fixture selects schema V1"),
    };
    let inputs = FullServicePlanInputs::new(
        NonZeroU64::new(generation).expect("nonzero generation"),
        Nat44UdpHashKey::new(seed, seed + 1).expect("nonzero UDP key"),
        Nat44TcpHashKey::new(seed + 2, seed + 3).expect("nonzero TCP key"),
        FirewallHashKey::new(seed + 4, seed + 5).expect("nonzero firewall key"),
    );
    let plan = match plan_full_service_v1(config, inputs) {
        Ok(plan) => plan,
        Err(failure) => panic!("full-service fixture must plan: {:?}", failure.error()),
    };
    plan.into_candidate()
        .expect("planned fixture must mint a candidate")
}

#[test]
fn activated_owner_static_plan_delegation_is_allocation_free_for_all_outcomes() {
    let base = FULL_SERVICE.to_owned();
    let interface_source = base.replacen("device = \"eth1\"", "device = \"eth9\"", 1);
    let storage_source = base.replacen("states = 11", "states = 12", 1);
    let policy_source = base.replacen("interval-ms = 1000", "interval-ms = 1001", 1);

    let initial = candidate(FULL_SERVICE, 1, 10);
    let initial_probe = candidate(FULL_SERVICE, 1, 10);
    reset_allocation_count();
    let initial_outcome = plan_successor(None, &initial_probe);
    assert_eq!(allocation_count(), 0, "initial plan must not allocate");
    assert!(matches!(
        initial_outcome,
        PlanOutcome::InitialActivation { .. }
    ));

    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let owner = match activate_initial(&mut storage, initial) {
        Ok(owner) => owner,
        Err(failure) => panic!("valid fixture must activate: {:?}", failure.error()),
    };
    let (owner_binding, mut io) =
        bind_publication_backend(SimIo::new()).expect("test process has binding identities");
    let owner = match owner.bind_backend(owner_binding, &mut io) {
        Ok(owner) => owner,
        Err(_) => panic!("cold simulated backend must bind"),
    };

    let candidates = [
        ("in-place", candidate(FULL_SERVICE, 2, 100)),
        ("interface restart", candidate(&interface_source, 2, 100)),
        ("storage restart", candidate(&storage_source, 2, 100)),
        ("rejected generation", candidate(FULL_SERVICE, 1, 100)),
        (
            "resolution policy restart",
            candidate(&policy_source, 2, 100),
        ),
    ];
    for (label, next) in candidates {
        reset_allocation_count();
        let outcome = owner.plan_successor(&next);
        assert_eq!(
            allocation_count(),
            0,
            "{label} owner plan must not allocate"
        );
        match label {
            "in-place" => assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. })),
            "interface restart" => assert!(matches!(
                outcome,
                PlanOutcome::RestartRequired {
                    reason: PlanRestartRequired::InterfaceBindingsChanged,
                    ..
                }
            )),
            "storage restart" => assert!(matches!(
                outcome,
                PlanOutcome::RestartRequired {
                    reason: PlanRestartRequired::RuntimeStorageShapeChanged,
                    ..
                }
            )),
            "rejected generation" => assert_eq!(
                outcome.rejection_error(),
                Some(SuccessorError::GenerationNotIncreasing)
            ),
            "resolution policy restart" => assert!(matches!(
                outcome,
                PlanOutcome::RestartRequired {
                    reason: PlanRestartRequired::ResolutionPolicyChanged,
                    ..
                }
            )),
            _ => unreachable!("all allocation cases are named above"),
        }
    }
}

fn udp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    const PAYLOAD: [u8; 3] = [0xa5, 0x5a, 0x11];
    let udp_len = 8 + PAYLOAD.len();
    let total_len = 20 + udp_len;
    let mut frame = vec![0_u8; 14 + total_len + 3];
    frame[0..6].copy_from_slice(&LAN_MAC);
    frame[6..12].copy_from_slice(&HOST_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(
        &u16::try_from(total_len)
            .expect("small UDP fixture")
            .to_be_bytes(),
    );
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..40].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("small UDP fixture")
            .to_be_bytes(),
    );
    frame[42..42 + PAYLOAD.len()].copy_from_slice(&PAYLOAD);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn tcp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + 3];
    frame[0..6].copy_from_slice(&LAN_MAC);
    frame[6..12].copy_from_slice(&HOST_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
    frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
    frame[46] = 5 << 4;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());

    let mut pseudo_header = Vec::with_capacity(32);
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&[0, 6]);
    pseudo_header.extend_from_slice(&20_u16.to_be_bytes());
    pseudo_header.extend_from_slice(&frame[34..54]);
    let checksum = internet_checksum(&pseudo_header);
    frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

struct NoTrace;

impl TickPhaseTraceSink for NoTrace {
    fn record_tick_phase(&mut self, _event: TickPhaseTrace) {}
}

impl TraceSink for NoTrace {
    fn record(&mut self, _event: TraceEvent) {}
}

impl ResolutionTimerTraceSink for NoTrace {
    fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
}

impl ResolutionFailureTraceSink for NoTrace {
    fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
}

impl GeneratedTraceSink for NoTrace {
    fn record_generated(&mut self, _event: GeneratedArpTrace) {}
}

impl GeneratedIcmpv4TraceSink for NoTrace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

#[test]
fn checked_initial_backend_bind_is_allocation_free() {
    let initial = candidate(FULL_SERVICE, 1, 10);
    let generation = initial.generation();
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let owner = match activate_initial(&mut storage, initial) {
        Ok(owner) => owner,
        Err(failure) => panic!("valid fixture must activate: {:?}", failure.error()),
    };
    let (owner_binding, mut io) =
        bind_publication_backend(SimIo::new()).expect("test process has binding identities");

    reset_allocation_count();
    let owner = match owner.bind_backend(owner_binding, &mut io) {
        Ok(owner) => owner,
        Err(_) => panic!("cold simulated backend must bind"),
    };
    let bind_allocations = allocation_count();

    assert_eq!(bind_allocations, 0);
    assert_eq!(owner.generation(), generation);
}

#[test]
fn activated_owner_steady_ticks_are_allocation_free() {
    let source = FULL_SERVICE.replacen("action = \"deny\"", "action = \"allow-stateful\"", 1);
    assert_ne!(source, FULL_SERVICE, "fixture must allow stateful UDP");
    let initial = candidate(&source, 1, 10);
    let initial_generation = initial.generation();
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let owner = match activate_initial(&mut storage, initial) {
        Ok(owner) => owner,
        Err(failure) => panic!("valid fixture must activate: {:?}", failure.error()),
    };
    let (owner_binding, mut io) =
        bind_publication_backend(SimIo::new()).expect("test process has binding identities");
    let mut owner = match owner.bind_backend(owner_binding, &mut io) {
        Ok(owner) => owner,
        Err(_) => panic!("cold simulated backend must bind"),
    };
    let successors = [
        candidate(&source, 2, 100),
        candidate(&source, 3, 200),
        candidate(&source, 4, 300),
    ];
    let final_candidate = successors.last().expect("successor fixture");
    let final_generation = final_candidate.generation();
    let final_tick = final_candidate.tick();
    let final_required_runtime_bytes = final_candidate.required_runtime_bytes();
    let final_storage_shape = final_candidate.storage_shape();
    let mut trace = NoTrace;
    let mut now = 0_u64;
    let mut expected_previous_generation = initial_generation;

    {
        let udp_sequence = io.inject(LAN, udp_frame(HOST, REMOTE, 12_345, 53));
        let tcp_sequence = io.inject(LAN, tcp_frame(HOST, REMOTE, 12_346, 443, 0x02));
        let report = run_tick(&mut owner, None, &mut io, MonotonicMillis(now), &mut trace);
        assert!(matches!(&report.publication, PublicationOutcome::Unchanged));
        let RxPhaseReport::Completed(rx) = report.rx else {
            panic!("dirtying packet batch must complete: {:?}", report.rx);
        };
        assert_eq!(rx.received, 2);
        assert_eq!(rx.tx_requested, 2);
        assert_eq!(rx.completion.tx_accepted, 2);
        assert!(rx.invariants_hold());

        let udp_outbound = io.pop_tx().expect("UDP flow must be transmitted");
        assert_eq!(udp_outbound.sequence, udp_sequence);
        assert_eq!(udp_outbound.bytes[23], 17);
        let tcp_outbound = io.pop_tx().expect("TCP SYN must be transmitted");
        assert_eq!(tcp_outbound.sequence, tcp_sequence);
        assert_eq!(tcp_outbound.bytes[23], 6);
        assert!(io.pop_tx().is_none());
    }
    now += 1;

    reset_allocation_count();
    for successor in successors {
        let expected_generation = successor.generation();
        let report = run_tick(
            &mut owner,
            Some(successor),
            &mut io,
            MonotonicMillis(now),
            &mut trace,
        );
        let apply = match &report.publication {
            PublicationOutcome::Applied(report) => report,
            other => panic!("fresh same-shape successor must apply: {other:?}"),
        };
        assert_eq!(apply.previous_generation(), expected_previous_generation);
        assert_eq!(apply.generation(), expected_generation);
        if expected_previous_generation == initial_generation {
            assert_eq!(apply.nat44_udp().mappings_flushed, 1);
            assert_eq!(apply.nat44_udp().peers_flushed, 1);
            assert_eq!(apply.nat44_tcp().mappings_flushed, 1);
            assert_eq!(apply.nat44_tcp().sessions_flushed, 1);
            assert_eq!(apply.firewall().states_flushed, 2);
        }
        assert!(report.active);
        expected_previous_generation = expected_generation;
        now += 1;
    }
    for _ in 0..1_024 {
        let report = run_tick(&mut owner, None, &mut io, MonotonicMillis(now), &mut trace);
        assert!(matches!(&report.publication, PublicationOutcome::Unchanged));
        assert!(report.active);
        now += 1;
    }
    let steady_allocations = allocation_count();

    assert_eq!(steady_allocations, 0);
    assert_eq!(owner.generation(), final_generation);
    assert_eq!(owner.tick(), final_tick);
    assert_eq!(owner.required_runtime_bytes(), final_required_runtime_bytes);
    assert_eq!(owner.storage_shape(), final_storage_shape);
}

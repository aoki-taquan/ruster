//! R15 observability evidence: real traffic produces a coherent,
//! generation-tagged, allocation-free snapshot, and the backend statistics
//! extension point is exercised with a concrete Sim implementation.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    num::NonZeroU64,
};

use ruster_config::{parse, validate, ValidatedConfig, ValidationLimits};
use ruster_control::{plan_full_service_v1, FullServiceCandidateV1, FullServicePlanInputs};
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
    observability::{BackendObservabilityStats, ObservabilityRecorder, Readiness},
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

/// A concrete Sim implementation of the backend statistics extension point.
/// `ruster-integration` never depends on `ruster-io-sim` in production code,
/// so this lives here in dev-dependency territory alongside the rest of the
/// Sim-backed test harness.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SimBackendObservabilityStats {
    pending_tx: u32,
    pending_tx_high_watermark: u32,
}

impl BackendObservabilityStats for SimBackendObservabilityStats {
    fn zero() -> Self {
        Self::default()
    }
}

fn sim_backend_stats(
    io: &impl BoundSimIoControl,
    previous_high_watermark: u32,
) -> SimBackendObservabilityStats {
    let pending_tx = u32::try_from(io.pending_tx()).unwrap_or(u32::MAX);
    SimBackendObservabilityStats {
        pending_tx,
        pending_tx_high_watermark: previous_high_watermark.max(pending_tx),
    }
}

#[test]
fn real_traffic_produces_a_coherent_generation_tagged_snapshot() {
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

    let mut recorder: ObservabilityRecorder<SimBackendObservabilityStats> =
        ObservabilityRecorder::new();
    let mut trace = NoTrace;
    let mut now = 0_u64;
    let mut backend_high_watermark = 0_u32;

    // A cold snapshot before any traffic: readiness is Ready (the owner is
    // already bound and healthy) and every counter starts at zero.
    let cold = owner.observability_snapshot(
        &mut recorder,
        sim_backend_stats(&io, backend_high_watermark),
    );
    assert_eq!(cold.generation, initial_generation);
    assert_eq!(cold.readiness, Readiness::Ready);
    assert_eq!(cold.core.nat44_udp.processed.get(), 0);
    assert_eq!(cold.core.firewall.processed.get(), 0);

    // Real allowed UDP + TCP traffic through one tick.
    io.inject(LAN, udp_frame(HOST, REMOTE, 12_345, 53));
    io.inject(LAN, tcp_frame(HOST, REMOTE, 12_346, 443, 0x02));
    let report = run_tick(&mut owner, None, &mut io, MonotonicMillis(now), &mut trace);
    assert!(matches!(&report.publication, PublicationOutcome::Unchanged));
    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!("dirtying packet batch must complete: {:?}", report.rx);
    };
    assert_eq!(rx.received, 2);
    now += 1;
    backend_high_watermark = backend_high_watermark.max(u32::try_from(io.pending_tx()).unwrap());

    let after_traffic = owner.observability_snapshot(
        &mut recorder,
        sim_backend_stats(&io, backend_high_watermark),
    );
    assert_eq!(after_traffic.generation, initial_generation);
    assert_eq!(after_traffic.readiness, Readiness::Ready);
    // The UDP flow was allowed-stateful and forwarded: at least one
    // processed event landed in this tick's high watermark.
    assert!(after_traffic.core.nat44_udp.processed.get() >= 1);
    assert!(
        after_traffic
            .core
            .nat44_udp
            .processed_per_tick_high_watermark
            .get()
            >= 1
    );
    assert!(after_traffic.core.firewall.processed.get() >= 1);
    assert!(after_traffic.backend.pending_tx_high_watermark >= after_traffic.backend.pending_tx);

    io.pop_tx();
    io.pop_tx();
    assert!(io.pop_tx().is_none());

    // A later candidate-free tick with no new traffic: cumulative totals and
    // high watermarks never fall below their prior peak.
    let report = run_tick(&mut owner, None, &mut io, MonotonicMillis(now), &mut trace);
    assert!(matches!(&report.publication, PublicationOutcome::Unchanged));
    let quiet = owner.observability_snapshot(
        &mut recorder,
        sim_backend_stats(&io, backend_high_watermark),
    );
    assert_eq!(
        quiet.core.nat44_udp.processed.get(),
        after_traffic.core.nat44_udp.processed.get()
    );
    assert_eq!(
        quiet.core.nat44_udp.processed_per_tick_high_watermark.get(),
        after_traffic
            .core
            .nat44_udp
            .processed_per_tick_high_watermark
            .get()
    );
}

#[test]
fn steady_snapshots_are_allocation_free() {
    let source = FULL_SERVICE.replacen("action = \"deny\"", "action = \"allow-stateful\"", 1);
    let initial = candidate(&source, 1, 10);
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
    let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
    let mut trace = NoTrace;

    reset_allocation_count();
    for tick in 0..1_024_u64 {
        let report = run_tick(&mut owner, None, &mut io, MonotonicMillis(tick), &mut trace);
        assert!(matches!(&report.publication, PublicationOutcome::Unchanged));
        let snapshot = owner.observability_snapshot(&mut recorder, ());
        assert_eq!(snapshot.core.nat44_udp.processed.get(), 0);
    }
    assert_eq!(allocation_count(), 0);
}

#[test]
fn unbound_owner_reports_cold_readiness_before_any_backend_is_bound() {
    let source = FULL_SERVICE.replacen("action = \"deny\"", "action = \"allow-stateful\"", 1);
    let initial = candidate(&source, 1, 10);
    let initial_generation = initial.generation();
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let mut owner = match activate_initial(&mut storage, initial) {
        Ok(owner) => owner,
        Err(failure) => panic!("valid fixture must activate: {:?}", failure.error()),
    };

    // No backend has ever been bound to this owner yet: there is no I/O to
    // continue, so readiness must be Cold rather than Ready even though the
    // active-failure latch is unset (the same latch state a freshly bound,
    // healthy owner also has).
    let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
    let snapshot = owner.observability_snapshot(&mut recorder, ());
    assert_eq!(snapshot.generation, initial_generation);
    assert_eq!(snapshot.readiness, Readiness::Cold);
    assert!(!snapshot.readiness.is_ready());
    assert_eq!(snapshot.core.nat44_udp.processed.get(), 0);
    assert_eq!(snapshot.core.firewall.processed.get(), 0);

    // Once bound, the same owner (now a distinct bound typestate) reports
    // Ready instead.
    let (owner_binding, mut io) =
        bind_publication_backend(SimIo::new()).expect("test process has binding identities");
    let mut owner = match owner.bind_backend(owner_binding, &mut io) {
        Ok(owner) => owner,
        Err(_) => panic!("cold simulated backend must bind"),
    };
    let bound_snapshot = owner.observability_snapshot(&mut recorder, ());
    assert_eq!(bound_snapshot.readiness, Readiness::Ready);
}

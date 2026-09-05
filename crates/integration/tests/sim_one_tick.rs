use std::num::NonZeroU64;

use ruster_config::{parse, validate, ValidatedConfig, ValidationLimits};
use ruster_control::{plan_full_service_v1, FullServiceCandidateV1, FullServicePlanInputs};
use ruster_core::{
    bind_publication_backend, FirewallHashKey, GeneratedArpTrace, GeneratedIcmpv4Trace,
    GeneratedIcmpv4TraceSink, GeneratedTraceSink, Icmpv4TimestampClock, IfId, MonotonicMillis,
    Nat44TcpHashKey, Nat44UdpHashKey, ResolutionFailureTrace, ResolutionFailureTraceSink,
    ResolutionTimerTrace, ResolutionTimerTraceSink, TraceEvent, TraceSink,
};
use ruster_integration::{activate_initial, FullServiceRuntimeStorage};
use ruster_io_sim::{BoundSimIoControl, FrameOrigin, SimIo};
use ruster_runtime::{
    run_tick, PublicationOutcome, RxPhaseReport, TickPhaseTrace, TickPhaseTraceSink,
};

const FULL_SERVICE: &str = include_str!("full-service.toml");
const LAN: IfId = IfId(1);
const LAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 4];
const LAN_IP: [u8; 4] = [192, 0, 2, 1];
const HOST_IP: [u8; 4] = [192, 0, 2, 20];

#[derive(Default)]
struct TestTrace {
    phases: Vec<TickPhaseTrace>,
}

impl TickPhaseTraceSink for TestTrace {
    fn record_tick_phase(&mut self, event: TickPhaseTrace) {
        self.phases.push(event);
    }
}

impl TraceSink for TestTrace {
    fn record(&mut self, _event: TraceEvent) {}
}

impl ResolutionTimerTraceSink for TestTrace {
    fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
}

impl ResolutionFailureTraceSink for TestTrace {
    fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
}

impl GeneratedTraceSink for TestTrace {
    fn record_generated(&mut self, _event: GeneratedArpTrace) {}
}

impl GeneratedIcmpv4TraceSink for TestTrace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

fn planned_candidate(generation: u64, seed: u64) -> FullServiceCandidateV1 {
    let parsed = parse(FULL_SERVICE.as_bytes()).expect("syntax fixture");
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

fn arp_request() -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&HOST_MAC);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&HOST_MAC);
    frame[28..32].copy_from_slice(&HOST_IP);
    frame[38..42].copy_from_slice(&LAN_IP);
    frame
}

#[test]
fn planned_initial_activation_runs_one_rootless_sim_tick() {
    let initial = planned_candidate(7, 11);
    let initial_generation = initial.generation();
    let successor = planned_candidate(8, 21);
    let generation = successor.generation();
    let candidate_tick = successor.tick();

    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let publication = match activate_initial(&mut storage, initial) {
        Ok(publication) => publication,
        Err(failure) => panic!("planned candidate must activate: {:?}", failure.error()),
    };
    let (owner_binding, mut io) =
        bind_publication_backend(SimIo::new()).expect("test process has binding identities");
    let mut publication = match publication.bind_backend(owner_binding, &mut io) {
        Ok(publication) => publication,
        Err(_) => panic!("cold simulated backend must bind"),
    };
    assert_eq!(publication.generation(), initial_generation);

    let sequence = io.inject(LAN, arp_request());
    let mut trace = TestTrace::default();
    let report = run_tick(
        &mut publication,
        Some(successor),
        &mut io,
        MonotonicMillis(0),
        Icmpv4TimestampClock(0),
        &mut trace,
    );

    let apply = match &report.publication {
        PublicationOutcome::Applied(report) => report,
        other => panic!("successor must apply before packet I/O: {other:?}"),
    };
    assert_eq!(apply.previous_generation(), initial_generation);
    assert_eq!(apply.generation(), generation);
    assert!(report.active);
    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!("active composition must complete RX: {:?}", report.rx);
    };
    assert_eq!(rx.received, 1);
    assert_eq!(rx.tx_requested, 1);
    assert_eq!(rx.completion.tx_accepted, 1);
    assert!(rx.invariants_hold());
    assert_eq!(publication.generation(), generation);
    let active_budgets = publication.active_view().tick_budgets();
    assert_eq!(
        active_budgets.rx,
        usize::try_from(candidate_tick.rx).expect("validated u32 fits usize")
    );
    assert_eq!(
        active_budgets.resolution_timer_scans,
        usize::try_from(candidate_tick.resolution_timer_scans).expect("validated u32 fits usize")
    );
    assert_eq!(
        active_budgets.failure_dispatch_scans,
        usize::try_from(candidate_tick.failure_dispatch_scans).expect("validated u32 fits usize")
    );
    assert_eq!(
        active_budgets.generated_arp,
        usize::try_from(candidate_tick.generated_arp).expect("validated u32 fits usize")
    );
    assert_eq!(
        active_budgets.generated_icmpv4,
        usize::try_from(candidate_tick.generated_icmpv4).expect("validated u32 fits usize")
    );
    assert_eq!(
        active_budgets.rx, 64,
        "fixture budget must reach the packet path"
    );
    assert_eq!(io.pending_rx(), 0);
    assert_eq!(io.pending_tx(), 1);

    let tx = io.pop_tx().expect("local ARP request must emit one reply");
    assert_eq!(tx.sequence, sequence);
    assert_eq!(tx.ingress, LAN);
    assert_eq!(tx.egress, LAN);
    assert_eq!(tx.origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(&tx.bytes[6..12], &LAN_MAC);
    assert_eq!(&tx.bytes[12..14], &0x0806_u16.to_be_bytes());
    assert_eq!(&tx.bytes[20..22], &2_u16.to_be_bytes());
    assert_eq!(&tx.bytes[22..28], &LAN_MAC);
    assert_eq!(&tx.bytes[28..32], &LAN_IP);
    assert_eq!(&tx.bytes[32..38], &HOST_MAC);
    assert_eq!(&tx.bytes[38..42], &HOST_IP);

    assert_eq!(trace.phases.first(), Some(&TickPhaseTrace::TickStarted));
    assert_eq!(trace.phases.last(), Some(&TickPhaseTrace::TickFinished));
}

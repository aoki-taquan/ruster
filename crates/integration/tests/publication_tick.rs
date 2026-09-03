use std::{convert::Infallible, mem, num::NonZeroU64};

use ruster_config::{
    parse, validate, AfXdpResourceV1, BackendV1, TickBudgetsV1, ValidatedConfig, ValidatedConfigV1,
    ValidationLimits, XdpAttachModeV1, XdpRingsV1, XdpUmemV1,
};
use ruster_control::{
    classify_successor, plan_full_service_v1, plan_successor, FullServiceCandidateV1,
    FullServicePlanInputs, FullServiceStorageShape, FullServiceSuccessorClassification,
    PlanRestartRequired, SuccessorError,
};
use ruster_core::{
    bind_publication_backend, internet_checksum, ipv4_header_checksum, BoundPublicationBackend,
    DropReason, FirewallHashKey, GeneratedArpTrace, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
    GeneratedTraceSink, IfId, Ipv4Address, MonotonicMillis, Nat44TcpConfig, Nat44TcpHashKey,
    Nat44UdpConfig, Nat44UdpHashKey, PacketBatch, PacketIo, PublicationQuiescence,
    PublicationQuiescenceDisposition, ResolutionFailureTrace, ResolutionFailureTraceSink,
    ResolutionTimerTrace, ResolutionTimerTraceSink, TraceEvent, TraceSink,
};
use ruster_integration::{
    activate_initial, BoundFullServicePublicationOwner, FullServicePublishError,
    FullServiceRestartRequired, FullServiceRuntimeStorage,
};
use ruster_io_sim::{
    BoundSimIoControl, FrameOrigin, RecycleCause, SimIo, SimPublicationQuiescenceError,
};
use ruster_runtime::{
    run_tick, try_publish_candidate, ActivePublicationStatus, PhaseReport, PublicationAttemptError,
    PublicationOutcome, RxPhaseReport, TickPhaseSkip, TickPhaseTrace, TickPhaseTraceSink,
};

const FULL_SERVICE: &str = include_str!("full-service.toml");
type SimBackend = BoundPublicationBackend<SimIo>;

fn candidate(generation: u64, seed: u64) -> FullServiceCandidateV1 {
    candidate_from_source(FULL_SERVICE, generation, seed)
}

fn candidate_from_source(source: &str, generation: u64, seed: u64) -> FullServiceCandidateV1 {
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
    candidate_from_validated_config(config, generation, seed)
}

fn candidate_from_validated_config(
    config: ValidatedConfigV1,
    generation: u64,
    seed: u64,
) -> FullServiceCandidateV1 {
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

fn af_xdp_backend() -> BackendV1 {
    BackendV1::AfXdp {
        resources: vec![
            AfXdpResourceV1 {
                interface: "wan".to_owned(),
                queue_id: 0,
            },
            AfXdpResourceV1 {
                interface: "lan".to_owned(),
                queue_id: 1,
            },
        ],
        xskmap_max_entries: 2,
        bind_flags: 1 << 3,
        attach_mode: XdpAttachModeV1::Skb,
        umem: XdpUmemV1 {
            frame_count: 2,
            frame_size: 2_048,
            headroom: 256,
            rx_frames: 1,
            generated_frames: 1,
            raw_flags: 0,
        },
        rings: XdpRingsV1 {
            fill: 4,
            rx: 4,
            tx: 4,
            completion: 4,
        },
    }
}

fn af_xdp_candidate(generation: u64, seed: u64) -> FullServiceCandidateV1 {
    let parsed = parse(generation_one_source().as_bytes()).expect("syntax fixture");
    let ruster_config::VersionedConfig::V1(mut source_config) = parsed else {
        unreachable!("fixture selects schema V1")
    };
    source_config.backend = Some(af_xdp_backend());
    let ValidatedConfig::V1(config) = validate(
        ruster_config::VersionedConfig::V1(source_config),
        ValidationLimits {
            max_slots_per_table: 1_048_576,
            max_runtime_bytes: 1 << 30,
        },
    )
    .expect("semantic fixture") else {
        unreachable!("fixture selects schema V1")
    };
    candidate_from_validated_config(config, generation, seed)
}

fn activated<'storage>(
    storage: &'storage mut FullServiceRuntimeStorage,
    candidate: FullServiceCandidateV1,
) -> (
    BoundFullServicePublicationOwner<'storage, SimIo>,
    SimBackend,
) {
    let owner = match activate_initial(storage, candidate) {
        Ok(owner) => owner,
        Err(failure) => panic!("valid fixture must activate: {:?}", failure.error()),
    };
    let (owner_binding, mut io) =
        bind_publication_backend(SimIo::new()).expect("test process has binding identities");
    let owner = match owner.bind_backend(owner_binding, &mut io) {
        Ok(owner) => owner,
        Err(_) => panic!("cold simulated backend must bind"),
    };
    (owner, io)
}

struct CandidateEvidence {
    generation: NonZeroU64,
    interfaces_pointer: usize,
    interface_name_pointers: [usize; 2],
    interface_device_pointers: [usize; 2],
    tick: TickBudgetsV1,
    required_runtime_bytes: usize,
    storage_shape: FullServiceStorageShape,
    firewall_rules_pointer: usize,
    udp_key: Nat44UdpHashKey,
    tcp_key: Nat44TcpHashKey,
    firewall_key: FirewallHashKey,
}

impl CandidateEvidence {
    fn capture(candidate: &FullServiceCandidateV1) -> Self {
        let interfaces = candidate.interfaces();
        assert_eq!(interfaces.len(), 2, "fixture interface identity width");
        let authority = candidate.authority();
        let firewall = authority.firewall_config();
        Self {
            generation: candidate.generation(),
            interfaces_pointer: interfaces.as_ptr() as usize,
            interface_name_pointers: [
                interfaces[0].name().as_ptr() as usize,
                interfaces[1].name().as_ptr() as usize,
            ],
            interface_device_pointers: [
                interfaces[0].device().as_ptr() as usize,
                interfaces[1].device().as_ptr() as usize,
            ],
            tick: candidate.tick(),
            required_runtime_bytes: candidate.required_runtime_bytes(),
            storage_shape: candidate.storage_shape(),
            firewall_rules_pointer: firewall.rules().as_ptr() as usize,
            udp_key: authority.nat44_udp_hash_key(),
            tcp_key: authority.nat44_tcp_hash_key(),
            firewall_key: firewall.hash_key(),
        }
    }

    fn assert_matches(&self, candidate: &FullServiceCandidateV1) {
        let actual = Self::capture(candidate);
        assert_eq!(actual.generation, self.generation);
        assert_eq!(actual.interfaces_pointer, self.interfaces_pointer);
        assert_eq!(actual.interface_name_pointers, self.interface_name_pointers);
        assert_eq!(
            actual.interface_device_pointers,
            self.interface_device_pointers
        );
        assert_eq!(actual.tick, self.tick);
        assert_eq!(actual.required_runtime_bytes, self.required_runtime_bytes);
        assert_eq!(actual.storage_shape, self.storage_shape);
        assert_eq!(actual.firewall_rules_pointer, self.firewall_rules_pointer);
        assert_eq!(actual.udp_key, self.udp_key);
        assert_eq!(actual.tcp_key, self.tcp_key);
        assert_eq!(actual.firewall_key, self.firewall_key);
    }
}

struct ActiveEvidence {
    generation: NonZeroU64,
    interfaces_pointer: usize,
    interface_name_pointers: [usize; 2],
    interface_device_pointers: [usize; 2],
    tick: TickBudgetsV1,
    required_runtime_bytes: usize,
    storage_shape: FullServiceStorageShape,
    udp_config: Nat44UdpConfig,
    tcp_config: Nat44TcpConfig,
    firewall_rules_pointer: usize,
    firewall_rule_count: usize,
    firewall_key: FirewallHashKey,
    runtimes_present: [bool; 3],
}

impl ActiveEvidence {
    fn capture(owner: &mut BoundFullServicePublicationOwner<'_, SimIo>) -> Self {
        let generation = owner.generation();
        let interfaces = owner.interfaces();
        assert_eq!(interfaces.len(), 2, "fixture interface identity width");
        let interfaces_pointer = interfaces.as_ptr() as usize;
        let interface_name_pointers = [
            interfaces[0].name().as_ptr() as usize,
            interfaces[1].name().as_ptr() as usize,
        ];
        let interface_device_pointers = [
            interfaces[0].device().as_ptr() as usize,
            interfaces[1].device().as_ptr() as usize,
        ];
        let tick = owner.tick();
        let required_runtime_bytes = owner.required_runtime_bytes();
        let storage_shape = owner.storage_shape();
        let view = owner.active_view();
        let firewall = view.firewall_config();
        Self {
            generation,
            interfaces_pointer,
            interface_name_pointers,
            interface_device_pointers,
            tick,
            required_runtime_bytes,
            storage_shape,
            udp_config: view.nat44_udp_config(),
            tcp_config: view.nat44_tcp_config(),
            firewall_rules_pointer: firewall.rules().as_ptr() as usize,
            firewall_rule_count: firewall.rules().len(),
            firewall_key: firewall.hash_key(),
            runtimes_present: [
                view.has_nat44_udp_runtime(),
                view.has_nat44_tcp_runtime(),
                view.has_firewall_runtime(),
            ],
        }
    }

    fn assert_matches(&self, owner: &mut BoundFullServicePublicationOwner<'_, SimIo>) {
        let actual = Self::capture(owner);
        assert_eq!(actual.generation, self.generation);
        assert_eq!(actual.interfaces_pointer, self.interfaces_pointer);
        assert_eq!(actual.interface_name_pointers, self.interface_name_pointers);
        assert_eq!(
            actual.interface_device_pointers,
            self.interface_device_pointers
        );
        assert_eq!(actual.tick, self.tick);
        assert_eq!(actual.required_runtime_bytes, self.required_runtime_bytes);
        assert_eq!(actual.storage_shape, self.storage_shape);
        assert_eq!(actual.udp_config, self.udp_config);
        assert_eq!(actual.tcp_config, self.tcp_config);
        assert_eq!(actual.firewall_rules_pointer, self.firewall_rules_pointer);
        assert_eq!(actual.firewall_rule_count, self.firewall_rule_count);
        assert_eq!(actual.firewall_key, self.firewall_key);
        assert_eq!(actual.runtimes_present, self.runtimes_present);
    }
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

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const GATEWAY_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 3];
const NEW_GATEWAY_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 5];
const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 4];
const HOST: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 20]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 10]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 20]);
const OLD_PUBLIC_PORTS: std::ops::RangeInclusive<u16> = 40_000..=40_012;
const NEW_PUBLIC_PORTS: std::ops::RangeInclusive<u16> = 41_000..=41_012;

fn tcp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + 3];
    let (destination_mac, source_mac) = if source == HOST {
        (LAN_MAC, HOST_MAC)
    } else {
        (WAN_MAC, GATEWAY_MAC)
    };
    frame[0..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&source_mac);
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

fn generation_one_source() -> String {
    FULL_SERVICE.replacen("rx = 64", "rx = 1", 1)
}

fn same_shape_successor_source() -> String {
    generation_one_source()
        .replacen("first = 40000", "first = 41000", 1)
        .replacen("last = 40012", "last = 41012", 1)
        .replacen("first = 443", "first = 8443", 1)
        .replacen("last = 443", "last = 8443", 1)
        .replacen("via = \"198.51.100.1\"", "via = \"198.51.100.2\"", 1)
        .replacen(
            "address = \"198.51.100.1\"",
            "address = \"198.51.100.2\"",
            1,
        )
        .replacen(
            "mac = \"02:00:00:00:00:03\"",
            "mac = \"02:00:00:00:00:05\"",
            1,
        )
        .replacen("rx = 1", "rx = 2", 1)
}

fn actual_static_classification(
    current: FullServiceCandidateV1,
    next: FullServiceCandidateV1,
) -> FullServiceSuccessorClassification {
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&current).expect("small fixed allocation");
    let (mut owner, mut io) = activated(&mut storage, current);
    let guard = io
        .try_publication_quiescence()
        .expect("fresh simulated backend must be quiescent");

    match try_publish_candidate(&mut owner, next, guard) {
        Ok(_) => FullServiceSuccessorClassification::InPlaceEligible,
        Err(PublicationAttemptError::BackendMismatch { .. }) => {
            panic!("fresh owner/backend pair must not mismatch")
        }
        Err(PublicationAttemptError::Rejected(rejection)) => {
            let (_, error) = rejection.into_parts();
            match error {
                FullServicePublishError::InvalidSuccessor(error) => {
                    FullServiceSuccessorClassification::Rejected(error)
                }
                FullServicePublishError::RestartRequired(reason) => {
                    let reason = match reason {
                        FullServiceRestartRequired::InterfaceBindingsChanged => {
                            PlanRestartRequired::InterfaceBindingsChanged
                        }
                        FullServiceRestartRequired::BackendChanged => {
                            PlanRestartRequired::BackendChanged
                        }
                        FullServiceRestartRequired::RuntimeStorageShapeChanged => {
                            PlanRestartRequired::RuntimeStorageShapeChanged
                        }
                        FullServiceRestartRequired::ResolutionPolicyChanged => {
                            PlanRestartRequired::ResolutionPolicyChanged
                        }
                        FullServiceRestartRequired::Icmpv4ErrorPolicyChanged => {
                            PlanRestartRequired::Icmpv4ErrorPolicyChanged
                        }
                        FullServiceRestartRequired::Unsupported => {
                            panic!("current control classifier must not map to unsupported")
                        }
                        _ => panic!("unknown integration restart reason"),
                    };
                    FullServiceSuccessorClassification::RestartRequired(reason)
                }
                FullServicePublishError::ResolutionPublication(_)
                | FullServicePublishError::Icmpv4ErrorPublication(_)
                | FullServicePublishError::Nat44UdpReconcile(_)
                | FullServicePublishError::Nat44TcpReconcile(_)
                | FullServicePublishError::FirewallReconcile(_) => {
                    panic!("fresh runtime must not reach a dynamic preflight failure")
                }
                FullServicePublishError::UnsupportedStaticClassification => {
                    panic!("current control classifier must not be unsupported")
                }
                _ => panic!("unknown integration publication error"),
            }
        }
    }
}

#[test]
fn control_static_classifier_matches_integration_static_publication_mapping() {
    let base = generation_one_source();
    let interface_and_runtime_changes = base
        .replacen("device = \"eth1\"", "device = \"eth9\"", 1)
        .replacen("via = \"198.51.100.1\"", "via = \"198.51.100.2\"", 1)
        .replacen(
            "address = \"198.51.100.1\"",
            "address = \"198.51.100.2\"",
            1,
        )
        .replacen("rx = 1", "rx = 2", 1);
    let storage_and_interface_changes = base
        .replacen("device = \"eth1\"", "device = \"eth9\"", 1)
        .replacen("states = 11", "states = 12", 1);
    let storage_and_policy_changes = base.replacen("states = 11", "states = 12", 1).replacen(
        "interval-ms = 1000",
        "interval-ms = 1001",
        1,
    );
    let policy_change = base.replacen("interval-ms = 1000", "interval-ms = 1001", 1);
    let icmp_policy_change = base.replacen(
        "interval-ms = 100\nstate-ttl-ms",
        "interval-ms = 101\nstate-ttl-ms",
        1,
    );
    let both_policy_changes = policy_change.clone().replacen(
        "interval-ms = 100\nstate-ttl-ms",
        "interval-ms = 101\nstate-ttl-ms",
        1,
    );

    let cases = [
        (
            "in-place static eligibility",
            base.clone(),
            2,
            100,
            FullServiceSuccessorClassification::InPlaceEligible,
        ),
        (
            "interface restart",
            interface_and_runtime_changes,
            2,
            100,
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::InterfaceBindingsChanged,
            ),
        ),
        (
            "storage restart",
            base.replacen("states = 11", "states = 12", 1),
            2,
            100,
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::RuntimeStorageShapeChanged,
            ),
        ),
        (
            "generation rejection",
            base.clone(),
            1,
            100,
            FullServiceSuccessorClassification::Rejected(SuccessorError::GenerationNotIncreasing),
        ),
        (
            "hash-key rejection",
            base.clone(),
            2,
            10,
            FullServiceSuccessorClassification::Rejected(SuccessorError::Nat44UdpHashKeyReused),
        ),
        (
            "resolution policy restart",
            policy_change,
            2,
            100,
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::ResolutionPolicyChanged,
            ),
        ),
        (
            "icmp policy restart",
            icmp_policy_change,
            2,
            100,
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::Icmpv4ErrorPolicyChanged,
            ),
        ),
        (
            "resolution before icmp policy",
            both_policy_changes,
            2,
            100,
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::ResolutionPolicyChanged,
            ),
        ),
        (
            "storage precedes interface",
            storage_and_interface_changes,
            2,
            100,
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::RuntimeStorageShapeChanged,
            ),
        ),
        (
            "storage precedes policy",
            storage_and_policy_changes,
            2,
            100,
            FullServiceSuccessorClassification::RestartRequired(
                PlanRestartRequired::RuntimeStorageShapeChanged,
            ),
        ),
    ];

    for (label, next_source, generation, seed, expected) in cases {
        let current = candidate_from_source(&base, 1, 10);
        let next = candidate_from_source(&next_source, generation, seed);
        let control = classify_successor(&current, &next);
        assert_eq!(control, expected, "control classifier: {label}");

        let actual = actual_static_classification(current, next);
        assert_eq!(actual, control, "integration mapping: {label}");
    }
}

#[test]
fn backend_change_is_restart_required_in_control_and_runtime_publication() {
    let current = candidate(1, 10);
    let next = af_xdp_candidate(2, 100);
    let expected =
        FullServiceSuccessorClassification::RestartRequired(PlanRestartRequired::BackendChanged);
    assert_eq!(classify_successor(&current, &next), expected);

    let current = candidate(1, 10);
    let next = af_xdp_candidate(2, 100);
    assert_eq!(actual_static_classification(current, next), expected);
}

#[test]
fn activated_owner_public_plan_successor_delegates_the_static_report_read_only() {
    let current = candidate(1, 10);
    let next = candidate_from_source(&same_shape_successor_source(), 2, 100);
    let expected = plan_successor(Some(&current), &next);
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&current).expect("small fixed allocation");
    let (owner, _io) = activated(&mut storage, current);

    let generation_before = owner.generation();
    let tick_before = owner.tick();
    let actual = owner.plan_successor(&next);

    assert_eq!(actual, expected);
    assert_eq!(owner.generation(), generation_before);
    assert_eq!(owner.tick(), tick_before);
    assert_eq!(actual.previous_generation(), Some(generation_before));
    assert_eq!(actual.next_generation(), next.generation());
}

fn seed_live_tcp_state(
    owner: &mut BoundFullServicePublicationOwner<'_, SimIo>,
    io: &mut SimBackend,
    trace: &mut NoTrace,
    now: MonotonicMillis,
) -> u16 {
    io.inject(LAN, tcp_frame(HOST, REMOTE, 12_345, 443, 0x02));
    let report = run_tick(owner, None, io, now, trace);
    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!("outbound SYN must complete: {:?}", report.rx);
    };
    assert_eq!(rx.received, 1);
    assert_eq!(rx.completion.tx_accepted, 1);
    let outbound = io.pop_tx().expect("outbound SYN must be translated");
    assert_eq!(outbound.egress, WAN);
    assert_eq!(outbound.origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(&outbound.bytes[0..6], &GATEWAY_MAC);
    assert_eq!(&outbound.bytes[6..12], &WAN_MAC);
    assert_eq!(&outbound.bytes[26..30], &PUBLIC.octets());
    assert_eq!(&outbound.bytes[30..34], &REMOTE.octets());
    let public_port = u16::from_be_bytes(outbound.bytes[34..36].try_into().unwrap());
    assert!(OLD_PUBLIC_PORTS.contains(&public_port));
    public_port
}

fn assert_preserved_reply(
    io: &mut SimBackend,
    expected_sequence: u64,
    expected_internal_port: u16,
) {
    let inbound = io
        .pop_tx()
        .expect("preserved NAT mapping/session/firewall state must pass SYN-ACK");
    assert_eq!(inbound.sequence, expected_sequence);
    assert_eq!(inbound.egress, LAN);
    assert_eq!(inbound.origin, FrameOrigin::Received { ingress: WAN });
    assert_eq!(&inbound.bytes[0..6], &HOST_MAC);
    assert_eq!(&inbound.bytes[6..12], &LAN_MAC);
    assert_eq!(&inbound.bytes[26..30], &REMOTE.octets());
    assert_eq!(&inbound.bytes[30..34], &HOST.octets());
    assert_eq!(
        u16::from_be_bytes(inbound.bytes[36..38].try_into().unwrap()),
        expected_internal_port
    );
}

#[test]
fn run_tick_applies_same_interface_same_shape_successor_and_uses_new_authority_same_tick() {
    let initial_source = generation_one_source();
    let initial = candidate_from_source(&initial_source, 1, 10);
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let (mut owner, mut io) = activated(&mut storage, initial);
    let mut trace = NoTrace;
    let old_public_port = seed_live_tcp_state(&mut owner, &mut io, &mut trace, MonotonicMillis(1));

    let successor_source = same_shape_successor_source();
    let successor = candidate_from_source(&successor_source, 2, 100);
    assert!(successor.interfaces() == owner.interfaces());
    assert_eq!(successor.storage_shape(), owner.storage_shape());
    assert_eq!(successor.tick().rx, 2);

    let old_reply_sequence = io.inject(WAN, tcp_frame(REMOTE, PUBLIC, 443, old_public_port, 0x12));
    let new_outbound_sequence = io.inject(LAN, tcp_frame(HOST, REMOTE, 12_346, 8443, 0x02));
    let report = run_tick(
        &mut owner,
        Some(successor),
        &mut io,
        MonotonicMillis(2),
        &mut trace,
    );

    let applied = match report.publication {
        PublicationOutcome::Applied(applied) => applied,
        other => panic!("same-interface/same-shape successor must apply: {other:?}"),
    };
    assert_eq!(applied.previous_generation(), NonZeroU64::new(1).unwrap());
    assert_eq!(applied.generation(), NonZeroU64::new(2).unwrap());
    assert_eq!(applied.resolution().states_flushed, 0);
    assert_eq!(applied.resolution().actions_flushed, 0);
    assert_eq!(applied.resolution().dynamic_neighbors_flushed, 0);
    assert_eq!(applied.resolution().failure_holds_flushed, 0);
    assert_eq!(applied.icmpv4_errors().states_flushed, 0);
    assert_eq!(applied.icmpv4_errors().actions_flushed, 0);
    assert_eq!(applied.nat44_udp().mappings_flushed, 0);
    assert_eq!(applied.nat44_udp().peers_flushed, 0);
    assert_eq!(applied.nat44_tcp().mappings_flushed, 1);
    assert_eq!(applied.nat44_tcp().sessions_flushed, 1);
    assert_eq!(applied.firewall().states_flushed, 1);

    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!("new generation must process RX: {:?}", report.rx);
    };
    assert_eq!(rx.received, 2, "the newly active rx=2 budget must be used");
    assert_eq!(rx.tx_requested, 1);
    assert_eq!(rx.dropped, 1);
    assert_eq!(rx.completion.tx_accepted, 1);
    assert_eq!(io.pending_rx(), 0);
    assert_eq!(io.pending_tx(), 1);

    let dropped_reply = io
        .pop_recycled()
        .expect("the old-generation reply must be terminally dropped");
    assert_eq!(dropped_reply.sequence, old_reply_sequence);
    assert_eq!(
        dropped_reply.cause,
        RecycleCause::Forwarding(DropReason::Nat44TcpMappingMiss)
    );

    let outbound = io
        .pop_tx()
        .expect("only the new-generation outbound SYN must be transmitted");
    assert_eq!(outbound.sequence, new_outbound_sequence);
    assert_eq!(outbound.egress, WAN);
    assert_eq!(outbound.origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(&outbound.bytes[0..6], &NEW_GATEWAY_MAC);
    assert_eq!(&outbound.bytes[6..12], &WAN_MAC);
    assert_eq!(&outbound.bytes[26..30], &PUBLIC.octets());
    assert_eq!(&outbound.bytes[30..34], &REMOTE.octets());
    assert_eq!(
        u16::from_be_bytes(outbound.bytes[36..38].try_into().unwrap()),
        8443
    );
    let new_public_port = u16::from_be_bytes(outbound.bytes[34..36].try_into().unwrap());
    assert!(NEW_PUBLIC_PORTS.contains(&new_public_port));
    assert!(!OLD_PUBLIC_PORTS.contains(&new_public_port));
    assert!(
        io.pop_tx().is_none(),
        "the flushed reply must not be forwarded"
    );
    assert_eq!(owner.generation(), NonZeroU64::new(2).unwrap());
    assert_eq!(owner.tick().rx, 2);
}

/// R10: re-planning an earlier config source under a fresh, higher generation
/// is the rollback mechanism. No dedicated "rollback" API exists or is
/// needed: the same `parse -> validate -> plan` pipeline used for any other
/// successor accepts a candidate whose *content* matches a prior generation,
/// as long as its generation number and hash keys move forward from the
/// current active generation. This test proves that mechanism actually
/// restores prior behavior (not just prior metadata) and that all-or-nothing
/// atomicity still holds immediately after a rollback.
#[test]
fn run_tick_rollback_to_prior_generation_source_restores_behavior_and_rejects_regression() {
    let original_source = generation_one_source();
    let original = candidate_from_source(&original_source, 1, 10);
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&original).expect("small fixed allocation");
    let (mut owner, mut io) = activated(&mut storage, original);
    let mut trace = NoTrace;
    let original_port = seed_live_tcp_state(&mut owner, &mut io, &mut trace, MonotonicMillis(1));
    assert!(OLD_PUBLIC_PORTS.contains(&original_port));

    // Generation 2: a same-interface/same-shape successor with genuinely
    // different NAT/address content (the changed config, "B").
    let changed_source = same_shape_successor_source();
    let changed = candidate_from_source(&changed_source, 2, 100);
    let report = run_tick(
        &mut owner,
        Some(changed),
        &mut io,
        MonotonicMillis(2),
        &mut trace,
    );
    match report.publication {
        PublicationOutcome::Applied(applied) => {
            assert_eq!(applied.generation(), NonZeroU64::new(2).unwrap());
        }
        other => panic!("changed successor must apply: {other:?}"),
    }
    // Generation 2 remapped NAT/firewall to port 8443 (not 443), so a fresh
    // probe must target the changed port to prove the new content is live.
    io.inject(LAN, tcp_frame(HOST, REMOTE, 12_346, 8443, 0x02));
    let report = run_tick(&mut owner, None, &mut io, MonotonicMillis(3), &mut trace);
    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!("generation-2 SYN must complete: {:?}", report.rx);
    };
    assert_eq!(rx.completion.tx_accepted, 1);
    let outbound = io
        .pop_tx()
        .expect("generation-2 SYN must be translated with the changed authority");
    assert_eq!(&outbound.bytes[0..6], &NEW_GATEWAY_MAC);
    assert_eq!(
        u16::from_be_bytes(outbound.bytes[36..38].try_into().unwrap()),
        8443
    );
    let changed_port = u16::from_be_bytes(outbound.bytes[34..36].try_into().unwrap());
    assert!(NEW_PUBLIC_PORTS.contains(&changed_port));

    // Generation 3: re-plan the *original* source content again ("rollback").
    // Nothing but the generation and hash-key seed differs from generation 1.
    let rollback = candidate_from_source(&original_source, 3, 200);
    let report = run_tick(
        &mut owner,
        Some(rollback),
        &mut io,
        MonotonicMillis(4),
        &mut trace,
    );
    match report.publication {
        PublicationOutcome::Applied(applied) => {
            assert_eq!(applied.previous_generation(), NonZeroU64::new(2).unwrap());
            assert_eq!(applied.generation(), NonZeroU64::new(3).unwrap());
        }
        other => panic!("rollback successor must apply: {other:?}"),
    }
    assert_eq!(owner.generation(), NonZeroU64::new(3).unwrap());
    assert_eq!(
        owner.tick().rx,
        1,
        "rolled-back rx budget must match generation 1"
    );

    // Behavioral proof: traffic now takes the original path again, not the
    // generation-2 path, even though only content (not metadata) rolled back.
    let rolled_back_port = seed_live_tcp_state(&mut owner, &mut io, &mut trace, MonotonicMillis(5));
    assert!(
        OLD_PUBLIC_PORTS.contains(&rolled_back_port),
        "rollback must restore the original NAT port range"
    );
    assert!(!NEW_PUBLIC_PORTS.contains(&rolled_back_port));

    // All-or-nothing: an invalid apply attempted right after the rollback
    // must not disturb the rolled-back active state.
    let active_after_rollback = ActiveEvidence::capture(&mut owner);
    let regression = candidate_from_source(&changed_source, 2, 300);
    let regression_evidence = CandidateEvidence::capture(&regression);
    let report = run_tick(
        &mut owner,
        Some(regression),
        &mut io,
        MonotonicMillis(6),
        &mut trace,
    );
    let rejection = match report.publication {
        PublicationOutcome::Rejected {
            rejection,
            status: disposition,
        } => {
            assert_eq!(disposition, ActivePublicationStatus::ContinueOldIo);
            rejection
        }
        other => panic!("generation regression after rollback must reject: {other:?}"),
    };
    let expected =
        FullServicePublishError::InvalidSuccessor(SuccessorError::GenerationNotIncreasing);
    assert_eq!(rejection.error(), &expected);
    let (regression, error) = rejection.into_parts();
    assert_eq!(error, expected);
    regression_evidence.assert_matches(&regression);
    active_after_rollback.assert_matches(&mut owner);
    assert_eq!(owner.generation(), NonZeroU64::new(3).unwrap());
}

#[test]
fn direct_safe_gate_rejects_foreign_guard_with_exact_candidate_and_unchanged_active_state() {
    let initial = candidate(1, 10);
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let (mut owner, _paired_io) = activated(&mut storage, initial);
    let active_before = ActiveEvidence::capture(&mut owner);
    let (_foreign_binding, mut foreign_io) =
        bind_publication_backend(SimIo::new()).expect("test process has binding identities");
    let raw = foreign_io
        .try_publication_quiescence()
        .expect("fresh simulator is quiescent");

    let successor = candidate(2, 100);
    let successor_evidence = CandidateEvidence::capture(&successor);
    let error = try_publish_candidate(&mut owner, successor, raw)
        .expect_err("foreign raw guard must fail the safe final gate");
    let successor = match error {
        PublicationAttemptError::BackendMismatch { candidate } => candidate,
        PublicationAttemptError::Rejected(_) => {
            panic!("foreign raw guard must be rejected as a backend mismatch")
        }
    };

    successor_evidence.assert_matches(&successor);
    active_before.assert_matches(&mut owner);
    assert_eq!(owner.generation(), NonZeroU64::new(1).unwrap());
}

#[test]
fn run_tick_foreign_backend_some_and_none_preserve_queues_and_skip_data_phases() {
    let initial = candidate(1, 10);
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let (mut owner, mut paired_io) = activated(&mut storage, initial);
    let mut trace = NoTrace;
    let public_port =
        seed_live_tcp_state(&mut owner, &mut paired_io, &mut trace, MonotonicMillis(0));
    let active_before = ActiveEvidence::capture(&mut owner);
    let (_foreign_binding, mut foreign_io) =
        bind_publication_backend(SimIo::new()).expect("test process has binding identities");

    foreign_io.inject(LAN, vec![0; 64]);
    let mut batch = foreign_io.receive(1).expect("infallible simulated RX");
    let lease = batch.next_packet().expect("one injected frame");
    lease.commit(WAN);
    let completion = batch.finish();
    assert_eq!(completion.tx_accepted, 1);
    assert_eq!(foreign_io.pending_tx(), 1);
    foreign_io.inject(LAN, vec![0; 64]);
    assert_eq!(foreign_io.pending_rx(), 1);

    let successor = candidate(2, 100);
    let successor_evidence = CandidateEvidence::capture(&successor);
    let report = run_tick(
        &mut owner,
        Some(successor),
        &mut foreign_io,
        MonotonicMillis(1),
        &mut trace,
    );
    let successor = match report.publication {
        PublicationOutcome::BackendMismatch {
            candidate: Some(candidate),
        } => candidate,
        other => panic!("foreign backend must outrank quiescence failure: {other:?}"),
    };
    successor_evidence.assert_matches(&successor);
    assert!(report.active);
    assert_eq!(
        report.rx,
        RxPhaseReport::<Infallible>::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    );
    assert_eq!(
        report.resolution_timers,
        PhaseReport::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    );
    assert_eq!(
        report.failure_dispatch,
        PhaseReport::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    );
    assert!(matches!(
        report.generated_arp,
        PhaseReport::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    ));
    assert!(matches!(
        report.generated_icmpv4,
        PhaseReport::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    ));
    assert_eq!(foreign_io.pending_tx(), 1);
    assert_eq!(foreign_io.pending_rx(), 1);
    active_before.assert_matches(&mut owner);

    foreign_io.inject(LAN, vec![0; 64]);
    assert_eq!(foreign_io.pending_rx(), 2);
    let report = run_tick(
        &mut owner,
        None,
        &mut foreign_io,
        MonotonicMillis(2),
        &mut trace,
    );
    assert!(matches!(
        report.publication,
        PublicationOutcome::BackendMismatch { candidate: None }
    ));
    assert!(report.active);
    assert_eq!(
        report.rx,
        RxPhaseReport::<Infallible>::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    );
    assert_eq!(
        report.resolution_timers,
        PhaseReport::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    );
    assert_eq!(
        report.failure_dispatch,
        PhaseReport::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    );
    assert!(matches!(
        report.generated_arp,
        PhaseReport::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    ));
    assert!(matches!(
        report.generated_icmpv4,
        PhaseReport::Skipped(TickPhaseSkip::BackendInstanceMismatch)
    ));
    assert_eq!(foreign_io.pending_tx(), 1);
    assert_eq!(foreign_io.pending_rx(), 2);
    active_before.assert_matches(&mut owner);

    let reply_sequence = paired_io.inject(WAN, tcp_frame(REMOTE, PUBLIC, 443, public_port, 0x12));
    let report = run_tick(
        &mut owner,
        None,
        &mut paired_io,
        MonotonicMillis(3),
        &mut trace,
    );
    assert!(matches!(report.publication, PublicationOutcome::Unchanged));
    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!(
            "foreign mismatch must not poison the paired backend: {:?}",
            report.rx
        );
    };
    assert_eq!(rx.received, 1);
    assert_eq!(rx.completion.tx_accepted, 1);
    assert_preserved_reply(&mut paired_io, reply_sequence, 12_345);
    assert!(report.active);
    active_before.assert_matches(&mut owner);
}

#[test]
fn run_tick_invalid_successor_keeps_exact_candidate_old_budget_and_live_state() {
    let initial_source = generation_one_source();
    let initial = candidate_from_source(&initial_source, 1, 10);
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let (mut owner, mut io) = activated(&mut storage, initial);
    let mut trace = NoTrace;
    let public_port = seed_live_tcp_state(&mut owner, &mut io, &mut trace, MonotonicMillis(1));
    let active_before = ActiveEvidence::capture(&mut owner);

    let invalid_source = same_shape_successor_source();
    let invalid = candidate_from_source(&invalid_source, 1, 200);
    assert_eq!(invalid.tick().rx, 2);
    let invalid_evidence = CandidateEvidence::capture(&invalid);
    let reply_sequence = io.inject(WAN, tcp_frame(REMOTE, PUBLIC, 443, public_port, 0x12));
    io.inject(LAN, tcp_frame(HOST, REMOTE, 12_346, 8443, 0x02));
    let report = run_tick(
        &mut owner,
        Some(invalid),
        &mut io,
        MonotonicMillis(2),
        &mut trace,
    );

    let rejection = match report.publication {
        PublicationOutcome::Rejected {
            rejection,
            status: disposition,
        } => {
            assert_eq!(disposition, ActivePublicationStatus::ContinueOldIo);
            rejection
        }
        other => panic!("non-increasing successor must reject: {other:?}"),
    };
    let expected =
        FullServicePublishError::InvalidSuccessor(SuccessorError::GenerationNotIncreasing);
    assert_eq!(rejection.error(), &expected);
    let (invalid, error) = rejection.into_parts();
    assert_eq!(error, expected);
    invalid_evidence.assert_matches(&invalid);

    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!("reply must use preserved live state: {:?}", report.rx);
    };
    assert_eq!(rx.received, 1, "rejection must retain the old rx=1 budget");
    assert_eq!(rx.completion.tx_accepted, 1);
    assert_eq!(io.pending_rx(), 1);
    assert_preserved_reply(&mut io, reply_sequence, 12_345);
    assert!(report.active);
    assert_eq!(owner.tick().rx, 1);
    active_before.assert_matches(&mut owner);
}

#[test]
fn run_tick_restart_required_table_keeps_exact_candidate_old_budget_and_live_state() {
    let base = generation_one_source();
    let resolution_policy_source = base
        .replacen("interval-ms = 1000", "interval-ms = 1001", 1)
        .replacen("rx = 1", "rx = 2", 1);
    let icmp_policy_source = base
        .replacen(
            "interval-ms = 100\nstate-ttl-ms",
            "interval-ms = 101\nstate-ttl-ms",
            1,
        )
        .replacen("rx = 1", "rx = 2", 1);
    let cases = [
        (
            "interface binding changed",
            base.replacen("device = \"eth1\"", "device = \"eth9\"", 1)
                .replacen("rx = 1", "rx = 2", 1),
            FullServiceRestartRequired::InterfaceBindingsChanged,
        ),
        (
            "runtime storage shape changed",
            base.replacen("states = 11", "states = 12", 1)
                .replacen("rx = 1", "rx = 2", 1),
            FullServiceRestartRequired::RuntimeStorageShapeChanged,
        ),
        (
            "resolution policy changed",
            resolution_policy_source,
            FullServiceRestartRequired::ResolutionPolicyChanged,
        ),
        (
            "icmpv4 error policy changed",
            icmp_policy_source,
            FullServiceRestartRequired::Icmpv4ErrorPolicyChanged,
        ),
    ];

    for (case_name, successor_source, reason) in cases {
        let initial = candidate_from_source(&base, 1, 10);
        let mut storage =
            FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
        let (mut owner, mut io) = activated(&mut storage, initial);
        let mut trace = NoTrace;
        let public_port = seed_live_tcp_state(&mut owner, &mut io, &mut trace, MonotonicMillis(1));
        let active_before = ActiveEvidence::capture(&mut owner);

        let successor = candidate_from_source(&successor_source, 2, 100);
        assert_eq!(successor.tick().rx, 2, "{case_name}");
        let successor_evidence = CandidateEvidence::capture(&successor);
        let reply_sequence = io.inject(WAN, tcp_frame(REMOTE, PUBLIC, 443, public_port, 0x12));
        io.inject(LAN, tcp_frame(HOST, REMOTE, 12_346, 443, 0x02));
        let report = run_tick(
            &mut owner,
            Some(successor),
            &mut io,
            MonotonicMillis(2),
            &mut trace,
        );

        let rejection = match report.publication {
            PublicationOutcome::Rejected {
                rejection,
                status: disposition,
            } => {
                assert_eq!(
                    disposition,
                    ActivePublicationStatus::ContinueOldIo,
                    "{case_name}"
                );
                rejection
            }
            other => panic!("{case_name} must require restart: {other:?}"),
        };
        let expected = FullServicePublishError::RestartRequired(reason);
        assert_eq!(rejection.error(), &expected, "{case_name}");
        let (successor, error) = rejection.into_parts();
        assert_eq!(error, expected, "{case_name}");
        successor_evidence.assert_matches(&successor);

        let RxPhaseReport::Completed(rx) = report.rx else {
            panic!(
                "{case_name} must continue with old live state: {:?}",
                report.rx
            );
        };
        assert_eq!(rx.received, 1, "{case_name} must retain old rx=1 budget");
        assert_eq!(rx.completion.tx_accepted, 1, "{case_name}");
        assert_eq!(io.pending_rx(), 1, "{case_name}");
        assert_preserved_reply(&mut io, reply_sequence, 12_345);
        assert!(report.active, "{case_name}");
        assert_eq!(owner.tick().rx, 1, "{case_name}");
        active_before.assert_matches(&mut owner);
    }
}

#[test]
fn run_tick_continue_old_io_defer_uses_old_budget_then_retries_same_candidate_applied() {
    let initial_source = generation_one_source();
    let initial = candidate_from_source(&initial_source, 1, 10);
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let (mut owner, mut io) = activated(&mut storage, initial);
    let active_before = ActiveEvidence::capture(&mut owner);
    io.inject(LAN, vec![0; 64]);
    let mut batch = io.receive(1).expect("infallible simulated RX");
    let lease = batch.next_packet().expect("one injected frame");
    lease.commit(WAN);
    let completion = batch.finish();
    assert_eq!(completion.tx_accepted, 1);
    assert_eq!(io.pending_tx(), 1);
    io.inject(LAN, vec![0; 64]);
    io.inject(LAN, vec![0; 64]);

    let successor_source = initial_source.replacen("rx = 1", "rx = 2", 1);
    let successor = candidate_from_source(&successor_source, 2, 100);
    let evidence = CandidateEvidence::capture(&successor);
    let static_plan = owner.plan_successor(&successor);
    assert!(matches!(
        static_plan,
        ruster_control::PlanOutcome::InPlaceEligible { .. }
    ));
    let mut trace = NoTrace;
    let report = run_tick(
        &mut owner,
        Some(successor),
        &mut io,
        MonotonicMillis(1),
        &mut trace,
    );
    let successor = match report.publication {
        PublicationOutcome::Deferred {
            candidate,
            error,
            disposition,
        } => {
            assert_eq!(error, SimPublicationQuiescenceError::TxCompletionPending);
            assert_eq!(disposition, PublicationQuiescenceDisposition::ContinueOldIo);
            candidate
        }
        other => panic!("pending TX must defer publication: {other:?}"),
    };
    evidence.assert_matches(&successor);
    assert!(report.active);
    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!("ContinueOldIo must run old RX: {:?}", report.rx);
    };
    assert_eq!(rx.received, 1, "defer must retain the old rx=1 budget");
    assert_eq!(io.pending_rx(), 1);
    assert_eq!(io.pending_tx(), 1);
    active_before.assert_matches(&mut owner);
    assert!(io.pop_tx().is_some(), "explicitly complete accepted TX");

    io.inject(LAN, vec![0; 64]);
    let report = run_tick(
        &mut owner,
        Some(successor),
        &mut io,
        MonotonicMillis(2),
        &mut trace,
    );
    let applied = match report.publication {
        PublicationOutcome::Applied(applied) => applied,
        other => panic!("the recovered candidate must apply on retry: {other:?}"),
    };
    assert_eq!(applied.previous_generation(), NonZeroU64::new(1).unwrap());
    assert_eq!(applied.generation(), NonZeroU64::new(2).unwrap());
    let RxPhaseReport::Completed(rx) = report.rx else {
        panic!("applied successor must run new RX: {:?}", report.rx);
    };
    assert_eq!(rx.received, 2, "retry must use the new rx=2 budget");
    assert_eq!(io.pending_rx(), 0);
    assert_eq!(owner.generation(), NonZeroU64::new(2).unwrap());
    assert_eq!(owner.tick().rx, 2);
}

#[test]
fn run_tick_skip_io_defer_preserves_exact_candidate_and_skips_data_phases() {
    let initial = candidate(1, 10);
    let mut storage =
        FullServiceRuntimeStorage::try_for_candidate(&initial).expect("small fixed allocation");
    let (mut owner, mut io) = activated(&mut storage, initial);
    let active_before = ActiveEvidence::capture(&mut owner);
    let unfinished_batch = io.receive(0).expect("infallible simulated RX");
    mem::forget(unfinished_batch);

    let successor = candidate(2, 100);
    let evidence = CandidateEvidence::capture(&successor);
    let mut trace = NoTrace;
    let report = run_tick(
        &mut owner,
        Some(successor),
        &mut io,
        MonotonicMillis(1),
        &mut trace,
    );
    let candidate = match report.publication {
        PublicationOutcome::Deferred {
            candidate,
            error,
            disposition,
        } => {
            assert_eq!(error, SimPublicationQuiescenceError::RxBatchNotFinished);
            assert_eq!(disposition, PublicationQuiescenceDisposition::SkipIo);
            candidate
        }
        other => panic!("unfinished RX must defer publication: {other:?}"),
    };
    evidence.assert_matches(&candidate);
    assert!(report.active);
    assert_eq!(
        report.rx,
        RxPhaseReport::<Infallible>::Skipped(TickPhaseSkip::BackendIoNotReentrant)
    );
    assert_eq!(
        report.resolution_timers,
        PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
    );
    assert_eq!(
        report.failure_dispatch,
        PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
    );
    assert!(matches!(
        report.generated_arp,
        PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
    ));
    assert!(matches!(
        report.generated_icmpv4,
        PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
    ));
    active_before.assert_matches(&mut owner);
}

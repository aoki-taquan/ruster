use std::num::NonZeroU64;

use ruster_config::{parse, validate, ValidatedConfig, ValidatedConfigV1, ValidationLimits};
use ruster_core::{
    internet_checksum, ipv4_header_checksum, FirewallCounters, FirewallReconcileError,
    FirewallStateSlot, GeneratedArpTrace, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
    GeneratedTraceSink, Icmpv4ErrorCounters, Icmpv4ErrorPublicationError, IfId, Ipv4Address,
    MonotonicMillis, Nat44TcpCounters, Nat44TcpMappingSlot, Nat44TcpReconcileError,
    Nat44TcpSessionSlot, Nat44UdpCounters, Nat44UdpMappingSlot, Nat44UdpPeerSlot,
    Nat44UdpReconcileError, ResolutionCounters, ResolutionFailureCounters, ResolutionFailureTrace,
    ResolutionFailureTraceSink, ResolutionPublicationError, ResolutionTimerTrace,
    ResolutionTimerTraceSink, TraceEvent, TraceSink,
};
use ruster_io_sim::{SimIo, SimPublicationQuiescenceError};
use ruster_runtime::{
    run_tick, PublicationOutcome, TickBudgets, TickPhaseTrace, TickPhaseTraceSink,
};

use super::{
    ActivationError, ActivePublication, ApplyError, ApplyStage, FullServiceStorage, RestartRequired,
};
use crate::{
    candidate_from_config, KeySourceError, KeySourceKind, PublicationKeySource, PublicationKeys,
    SimDeterministicKeySource, SuccessorError, ValidatedCandidate,
};

pub(crate) const SEED: u64 = 0x5eed_0bad_cafe_f00d;
const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const GATEWAY_A_MAC: [u8; 6] = [2, 0, 0, 0, 0, 3];
const GATEWAY_B_MAC: [u8; 6] = [2, 0, 0, 0, 0, 4];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x32];
const LEARNED_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x3c];
const ROUTER_LAN: [u8; 4] = [192, 0, 2, 1];
const HOST: [u8; 4] = [192, 0, 2, 50];
const LEARNED_HOST: [u8; 4] = [192, 0, 2, 60];
const PUBLIC: [u8; 4] = [198, 51, 100, 10];
const UNRESOLVED_WAN: [u8; 4] = [198, 51, 100, 77];
const REMOTE: [u8; 4] = [203, 0, 113, 20];

pub(crate) const LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1 << 16,
    max_runtime_bytes: 1 << 26,
};

pub(crate) struct Variant {
    gateway: &'static str,
    wan_mac: &'static str,
    resolution_interval_ms: u32,
    icmp_interval_ms: u32,
    firewall_states: u32,
}

pub(crate) const V1: Variant = Variant {
    gateway: "198.51.100.1",
    wan_mac: "02:00:00:00:00:02",
    resolution_interval_ms: 1000,
    icmp_interval_ms: 100,
    firewall_states: 16,
};

const V2: Variant = Variant {
    gateway: "198.51.100.2",
    ..V1
};

pub(crate) fn config_text(variant: &Variant) -> String {
    format!(
        r#"
schema-version = 1

[[interfaces]]
id = 1
name = "lan"
device = "eth0"
mac = "02:00:00:00:00:01"

[[interfaces]]
id = 2
name = "wan"
device = "eth1"
mac = "{wan_mac}"

[[addresses]]
interface = "lan"
ipv4 = "192.0.2.1/24"

[[addresses]]
interface = "wan"
ipv4 = "198.51.100.10/24"

[[routes]]
prefix = "0.0.0.0/0"
egress = "wan"
via = "{gateway}"

[[neighbors]]
interface = "wan"
address = "198.51.100.1"
mac = "02:00:00:00:00:03"

[[neighbors]]
interface = "wan"
address = "198.51.100.2"
mac = "02:00:00:00:00:04"

[[neighbors]]
interface = "lan"
address = "192.0.2.50"
mac = "02:00:00:00:00:32"

[resolution.policy]
interval-ms = {resolution_interval}
state-ttl-ms = 3000
dynamic-neighbor-ttl-ms = 60000
max-attempts = 3

[resolution.capacity]
states = 4
actions = 4
dynamic-neighbors = 4
failure-holds = 4

[icmpv4-errors.policy]
interval-ms = {icmp_interval}
state-ttl-ms = 60000

[icmpv4-errors.capacity]
states = 4
actions = 4

[nat44.realm]
inside = "lan"
outside = "wan"
public-address = "198.51.100.10"

[nat44.realm.ports]
first = 40000
last = 40015

[nat44.udp]
idle-ttl-ms = 300000
allocator-seed = "7"
icmpv4-errors = "external-only"

[nat44.udp.capacity]
mappings = 4
peers = 8

[nat44.tcp]
idle-ttl-ms = 7440000
allocator-seed = "11"
icmpv4-errors = "disabled"

[nat44.tcp.capacity]
mappings = 4
sessions = 8

[firewall.policy]
udp-idle-ttl-ms = 300000
tcp-opening-idle-ttl-ms = 240000
tcp-active-idle-ttl-ms = 7440000

[firewall.capacity]
states = {firewall_states}

[[firewall.rules]]
id = 1
ingress = "lan"
egress = "wan"
source = "192.0.2.0/24"
destination = "0.0.0.0/0"
protocol = "udp"
action = "allow-stateful"

[firewall.rules.source-ports]
first = 0
last = 65535

[firewall.rules.destination-ports]
first = 0
last = 65535

[[firewall.rules]]
id = 2
ingress = "lan"
egress = "wan"
source = "192.0.2.0/24"
destination = "0.0.0.0/0"
protocol = "tcp"
action = "allow-stateful"

[firewall.rules.source-ports]
first = 0
last = 65535

[firewall.rules.destination-ports]
first = 0
last = 65535

[[firewall.rules]]
id = 3
ingress = "lan"
egress = "lan"
source = "192.0.2.0/24"
destination = "192.0.2.0/24"
protocol = "udp"
action = "allow-stateful"

[firewall.rules.source-ports]
first = 0
last = 65535

[firewall.rules.destination-ports]
first = 0
last = 65535
"#,
        gateway = variant.gateway,
        wan_mac = variant.wan_mac,
        resolution_interval = variant.resolution_interval_ms,
        icmp_interval = variant.icmp_interval_ms,
        firewall_states = variant.firewall_states,
    )
}

fn validated(variant: &Variant) -> ValidatedConfigV1 {
    match validate(
        parse(config_text(variant).as_bytes()).expect("syntax"),
        LIMITS,
    )
    .expect("semantics")
    {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("fixture selects schema V1"),
    }
}

fn candidate(variant: &Variant, generation: u64) -> ValidatedCandidate {
    candidate_from_config(
        &validated(variant),
        NonZeroU64::new(generation).unwrap(),
        &mut SimDeterministicKeySource::new(SEED),
    )
    .expect("candidate")
}

/// Returns the keys of a fixed generation, so a successor reuses them.
struct StaleKeys(NonZeroU64);

impl PublicationKeySource for StaleKeys {
    const KIND: KeySourceKind = KeySourceKind::DeterministicSimulation;

    fn publication_keys(&mut self, _: NonZeroU64) -> Result<PublicationKeys, KeySourceError> {
        SimDeterministicKeySource::new(SEED).publication_keys(self.0)
    }
}

struct Quiet;

impl TickPhaseTraceSink for Quiet {
    fn record_tick_phase(&mut self, _: TickPhaseTrace) {}
}
impl TraceSink for Quiet {
    fn record(&mut self, _: TraceEvent) {}
}
impl ResolutionTimerTraceSink for Quiet {
    fn record_resolution_timer(&mut self, _: ResolutionTimerTrace) {}
}
impl ResolutionFailureTraceSink for Quiet {
    fn record_resolution_failure(&mut self, _: ResolutionFailureTrace) {}
}
impl GeneratedTraceSink for Quiet {
    fn record_generated(&mut self, _: GeneratedArpTrace) {}
}
impl GeneratedIcmpv4TraceSink for Quiet {
    fn record_generated_icmpv4(&mut self, _: GeneratedIcmpv4Trace) {}
}

/// Generated ARP/ICMPv4 budgets are zero so queued actions stay live state.
const BUDGETS: TickBudgets = TickBudgets {
    rx: 32,
    resolution_timer_scans: 8,
    failure_dispatch_scans: 8,
    generated_arp: 0,
    generated_icmpv4: 0,
};

type Report = ruster_runtime::TickReport<
    ApplyError,
    SimPublicationQuiescenceError,
    core::convert::Infallible,
    ruster_io_sim::SimGeneratedError,
>;

fn tick(
    active: &mut ActivePublication<'_, SimIo>,
    io: &mut SimIo,
    now: u64,
    successor: Option<ValidatedCandidate>,
) -> Report {
    run_tick(
        active,
        successor,
        io,
        MonotonicMillis(now),
        BUDGETS,
        &mut Quiet,
    )
}

fn ipv4(frame: &mut [u8], protocol: u8, ttl: u8, source: [u8; 4], destination: [u8; 4]) {
    let total = u16::try_from(frame.len() - 14).unwrap();
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&total.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = ttl;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&source);
    frame[30..34].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

fn ethernet(length: usize, destination: [u8; 6], source: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0_u8; length];
    frame[0..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&source);
    frame
}

fn udp(
    l2: ([u8; 6], [u8; 6]),
    source: ([u8; 4], u16),
    destination: ([u8; 4], u16),
    ttl: u8,
) -> Vec<u8> {
    let mut frame = ethernet(14 + 28, l2.0, l2.1);
    frame[34..36].copy_from_slice(&source.1.to_be_bytes());
    frame[36..38].copy_from_slice(&destination.1.to_be_bytes());
    frame[38..40].copy_from_slice(&8_u16.to_be_bytes());
    ipv4(&mut frame, 17, ttl, source.0, destination.0);
    frame
}

fn lan_udp(source_port: u16, destination: [u8; 4], ttl: u8) -> Vec<u8> {
    udp(
        (LAN_MAC, HOST_MAC),
        (HOST, source_port),
        (destination, 53),
        ttl,
    )
}

fn wan_udp_reply(public_port: u16) -> Vec<u8> {
    udp(
        (WAN_MAC, GATEWAY_A_MAC),
        (REMOTE, 53),
        (PUBLIC, public_port),
        64,
    )
}

fn tcp(
    l2: ([u8; 6], [u8; 6]),
    source: ([u8; 4], u16),
    destination: ([u8; 4], u16),
    flags: u8,
) -> Vec<u8> {
    let mut frame = ethernet(14 + 40, l2.0, l2.1);
    frame[34..36].copy_from_slice(&source.1.to_be_bytes());
    frame[36..38].copy_from_slice(&destination.1.to_be_bytes());
    frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
    if flags & 0x10 != 0 {
        frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
    }
    frame[46] = 5 << 4;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&65_535_u16.to_be_bytes());
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&source.0);
    pseudo.extend_from_slice(&destination.0);
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&frame[34..54]);
    let checksum = internet_checksum(&pseudo);
    frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    ipv4(&mut frame, 6, 64, source.0, destination.0);
    frame
}

fn lan_tcp_syn(source_port: u16) -> Vec<u8> {
    tcp(
        (LAN_MAC, HOST_MAC),
        (HOST, source_port),
        (REMOTE, 443),
        0x02,
    )
}

fn wan_tcp_syn_ack(public_port: u16) -> Vec<u8> {
    tcp(
        (WAN_MAC, GATEWAY_A_MAC),
        (REMOTE, 443),
        (PUBLIC, public_port),
        0x12,
    )
}

fn arp_request(sender_mac: [u8; 6], sender: [u8; 4], target: [u8; 4]) -> Vec<u8> {
    let mut frame = ethernet(60, [0xff; 6], sender_mac);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender);
    frame[38..42].copy_from_slice(&target);
    frame
}

fn drain(io: &mut SimIo) -> Vec<ruster_io_sim::TxFrame> {
    while io.pop_recycled().is_some() {}
    std::iter::from_fn(|| io.pop_tx()).collect()
}

/// Forwards one outbound UDP packet and returns (egress, destination MAC,
/// translated source port).
fn forward_once(
    active: &mut ActivePublication<'_, SimIo>,
    io: &mut SimIo,
    now: u64,
    source_port: u16,
) -> (IfId, [u8; 6], u16) {
    io.inject(LAN, lan_udp(source_port, REMOTE, 64));
    let report = tick(active, io, now, None);
    assert!(report.active);
    let sent = drain(io);
    assert_eq!(sent.len(), 1, "exactly one forwarded frame");
    let frame = &sent[0].bytes;
    assert_eq!(
        frame[26..30],
        PUBLIC,
        "source translated to the public address"
    );
    (
        sent[0].egress,
        frame[0..6].try_into().unwrap(),
        u16::from_be_bytes([frame[34], frame[35]]),
    )
}

/// Returns whether an inbound reply to `public_port` is translated back.
fn reply_reaches_host(
    active: &mut ActivePublication<'_, SimIo>,
    io: &mut SimIo,
    now: u64,
    public_port: u16,
) -> bool {
    io.inject(WAN, wan_udp_reply(public_port));
    tick(active, io, now, None);
    let sent = drain(io);
    sent.iter()
        .any(|frame| frame.egress == LAN && frame.bytes[30..34] == HOST)
}

/// Every runtime field observable without mutation, plus the exact
/// publication binding (config and hash key) of NAT and firewall runtimes.
/// Internal directories, port owners, epochs, and watermarks have no
/// read accessor; they are covered behaviourally after the failure loop.
#[derive(PartialEq)]
struct Observed {
    generation: NonZeroU64,
    bindings: [bool; 3],
    policies: (
        ruster_core::ResolutionPolicy,
        ruster_core::Icmpv4ErrorPolicy,
    ),
    shapes: (
        ruster_core::Nat44UdpStorageShape,
        ruster_core::Nat44TcpStorageShape,
        usize,
    ),
    last_apply: Option<super::ApplyReport>,
    resolution: (ResolutionCounters, ResolutionFailureCounters),
    resolution_occupancy: [usize; 5],
    learned: Option<ruster_core::ResolutionStatus>,
    icmpv4: (Icmpv4ErrorCounters, usize),
    udp: (
        Nat44UdpCounters,
        Vec<Nat44UdpMappingSlot>,
        Vec<Nat44UdpPeerSlot>,
    ),
    tcp: (
        Nat44TcpCounters,
        Vec<Nat44TcpMappingSlot>,
        Vec<Nat44TcpSessionSlot>,
    ),
    firewall: (FirewallCounters, Vec<FirewallStateSlot>),
}

fn observe(active: &ActivePublication<'_, SimIo>) -> Observed {
    let resolution = active.resolution();
    let authority = active.candidate.authority();
    Observed {
        generation: active.generation(),
        bindings: [
            active.nat44_udp().publication_binding_matches(
                authority.nat44_udp_config(),
                authority.nat44_udp_hash_key(),
            ),
            active.nat44_tcp().publication_binding_matches(
                authority.nat44_tcp_config(),
                authority.nat44_tcp_hash_key(),
            ),
            active
                .firewall()
                .config_matches(&authority.firewall_config()),
        ],
        policies: (resolution.policy(), active.icmpv4_errors().policy()),
        shapes: (
            active.nat44_udp().storage_shape(),
            active.nat44_tcp().storage_shape(),
            active.firewall().usable_capacity(),
        ),
        last_apply: active.last_apply(),
        resolution: (resolution.counters(), resolution.failure_counters()),
        resolution_occupancy: [
            resolution.pending_actions(),
            resolution.pending_states(),
            resolution.pending_failure_holds(),
            resolution.dynamic_neighbor_count(),
            resolution.cooldown_count(),
        ],
        learned: resolution.status(WAN, Ipv4Address::from_octets(UNRESOLVED_WAN)),
        icmpv4: (
            active.icmpv4_errors().counters(),
            active.icmpv4_errors().pending_actions(),
        ),
        udp: (
            active.nat44_udp().counters(),
            active.nat44_udp().mappings().to_vec(),
            active.nat44_udp().peers().to_vec(),
        ),
        tcp: (
            active.nat44_tcp().counters(),
            active.nat44_tcp().mappings().to_vec(),
            active.nat44_tcp().sessions().to_vec(),
        ),
        firewall: (
            active.firewall().counters(),
            active.firewall().states().to_vec(),
        ),
    }
}

fn occupied<T: PartialEq + Default>(slots: &[T]) -> usize {
    slots.iter().filter(|slot| **slot != T::default()).count()
}

struct Live {
    public_udp_port: u16,
    public_tcp_port: u16,
}

/// Installs live ARP, resolution, ICMPv4, NAT UDP/TCP, and firewall state.
fn populate(active: &mut ActivePublication<'_, SimIo>, io: &mut SimIo) -> Live {
    let (egress, mac, public_udp_port) = forward_once(active, io, 1_000, 5_000);
    assert_eq!((egress, mac), (WAN, GATEWAY_A_MAC));
    io.inject(LAN, arp_request(LEARNED_MAC, LEARNED_HOST, ROUTER_LAN));
    io.inject(LAN, lan_tcp_syn(6_000));
    io.inject(LAN, lan_udp(5_001, UNRESOLVED_WAN, 64));
    io.inject(LAN, lan_udp(5_002, REMOTE, 1));
    let report = tick(active, io, 1_001, None);
    assert!(report.active);
    let sent = drain(io);
    let syn = sent
        .iter()
        .find(|frame| frame.egress == WAN && frame.bytes[23] == 6)
        .expect("translated TCP SYN");
    let public_tcp_port = u16::from_be_bytes([syn.bytes[34], syn.bytes[35]]);

    let resolution = active.resolution();
    assert_eq!(resolution.dynamic_neighbor_count(), 1, "learned ARP entry");
    assert!(resolution.pending_actions() >= 1, "queued ARP request");
    assert!(
        active.icmpv4_errors().pending_actions() >= 1,
        "queued ICMPv4"
    );
    assert!(occupied(active.nat44_udp().mappings()) >= 1, "UDP mapping");
    assert_eq!(occupied(active.nat44_tcp().mappings()), 1, "TCP mapping");
    assert!(occupied(active.firewall().states()) >= 2, "firewall flows");
    assert!(observe(active).bindings.iter().all(|matches| *matches));
    Live {
        public_udp_port,
        public_tcp_port,
    }
}

fn injected(stage: ApplyStage) -> ApplyError {
    match stage {
        ApplyStage::Successor => ApplyError::Successor(SuccessorError::GenerationExhausted),
        ApplyStage::Resolution => {
            ApplyError::Resolution(ResolutionPublicationError::RuntimeEpochExhausted)
        }
        ApplyStage::Icmpv4Errors => {
            ApplyError::Icmpv4Errors(Icmpv4ErrorPublicationError::RuntimeEpochExhausted)
        }
        ApplyStage::Nat44Udp => ApplyError::Nat44Udp(Nat44UdpReconcileError::RuntimeEpochExhausted),
        ApplyStage::Nat44Tcp => ApplyError::Nat44Tcp(Nat44TcpReconcileError::RuntimeEpochExhausted),
        ApplyStage::Firewall => ApplyError::Firewall(FirewallReconcileError::RuntimeEpochExhausted),
    }
}

#[test]
fn failure_at_every_apply_stage_leaves_live_runtimes_unchanged() {
    let first = candidate(&V1, 1);
    let mut storage = FullServiceStorage::new(first.storage_shape()).unwrap();
    let mut active = ActivePublication::<SimIo>::new(&mut storage, first).unwrap();
    let mut io = SimIo::new();
    let live = populate(&mut active, &mut io);

    for stage in [
        ApplyStage::Successor,
        ApplyStage::Resolution,
        ApplyStage::Icmpv4Errors,
        ApplyStage::Nat44Udp,
        ApplyStage::Nat44Tcp,
        ApplyStage::Firewall,
    ] {
        let before = observe(&active);
        let mut reached = Vec::new();
        let result = active.apply_with(candidate(&V2, 2), |at| {
            reached.push(at);
            (at == stage).then(|| injected(stage))
        });
        assert_eq!(result, Err(injected(stage)));
        assert_eq!(
            reached.last(),
            Some(&stage),
            "every earlier permit was held"
        );
        assert!(
            observe(&active) == before,
            "{stage:?} changed runtime state"
        );
    }

    // The old generation, snapshot route, and live NAT/firewall state still
    // serve traffic. Inbound UDP and TCP replies use the pre-existing
    // mappings, which exercises the NAT directories, port owners, hash
    // keys, and firewall reverse lookups.
    assert_eq!(active.generation().get(), 1);
    assert!(reply_reaches_host(
        &mut active,
        &mut io,
        1_002,
        live.public_udp_port
    ));
    io.inject(WAN, wan_tcp_syn_ack(live.public_tcp_port));
    tick(&mut active, &mut io, 1_002, None);
    let sent = drain(&mut io);
    assert!(
        sent.iter().any(|frame| frame.egress == LAN
            && frame.bytes[23] == 6
            && frame.bytes[30..34] == HOST
            && frame.bytes[36..38] == 6_000_u16.to_be_bytes()),
        "old TCP mapping still translates its reply"
    );

    // The learned dynamic neighbor is still used, without a new ARP request.
    let queued = active.resolution().counters().queued;
    let pending = active.resolution().pending_actions();
    io.inject(
        LAN,
        udp((LAN_MAC, HOST_MAC), (HOST, 7_000), (LEARNED_HOST, 9), 64),
    );
    tick(&mut active, &mut io, 1_002, None);
    let sent = drain(&mut io);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        (sent[0].egress, &sent[0].bytes[0..6]),
        (LAN, &LEARNED_MAC[..])
    );
    assert_eq!(active.resolution().counters().queued, queued);
    assert_eq!(active.resolution().pending_actions(), pending);
    assert_eq!(
        forward_once(&mut active, &mut io, 1_003, 5_000),
        (WAN, GATEWAY_A_MAC, live.public_udp_port)
    );
}

#[test]
fn natural_successor_rejections_are_typed_and_leave_state_unchanged() {
    let first = candidate(&V1, 1);
    let mut storage = FullServiceStorage::new(first.storage_shape()).unwrap();
    let mut active = ActivePublication::<SimIo>::new(&mut storage, first).unwrap();
    let mut io = SimIo::new();
    populate(&mut active, &mut io);

    let reused_keys = candidate_from_config(
        &validated(&V2),
        NonZeroU64::new(2).unwrap(),
        &mut StaleKeys(NonZeroU64::new(1).unwrap()),
    )
    .unwrap();
    let cases = [
        (
            candidate(&V2, 1),
            ApplyError::Successor(SuccessorError::GenerationNotIncreasing),
        ),
        (
            reused_keys,
            ApplyError::Successor(SuccessorError::Nat44UdpHashKeyReused),
        ),
        (
            candidate(
                &Variant {
                    firewall_states: 32,
                    ..V2
                },
                2,
            ),
            ApplyError::RestartRequired(RestartRequired::StorageShape),
        ),
        (
            candidate(
                &Variant {
                    resolution_interval_ms: 2000,
                    ..V2
                },
                2,
            ),
            ApplyError::RestartRequired(RestartRequired::ResolutionPolicy),
        ),
        (
            candidate(
                &Variant {
                    icmp_interval_ms: 200,
                    ..V2
                },
                2,
            ),
            ApplyError::RestartRequired(RestartRequired::Icmpv4ErrorPolicy),
        ),
        (
            candidate(
                &Variant {
                    wan_mac: "02:00:00:00:00:22",
                    ..V2
                },
                2,
            ),
            ApplyError::RestartRequired(RestartRequired::Interfaces),
        ),
    ];
    for (successor, expected) in cases {
        let before = observe(&active);
        // Same transaction that `publish_candidate` runs inside `run_tick`.
        let result = active.apply_with(successor, |_| None).map(|_| ());
        assert_eq!(result, Err(expected));
        assert!(observe(&active) == before, "{expected:?} changed state");
    }
}

#[test]
fn run_tick_applies_successor_at_tick_boundary_with_reconcile_semantics() {
    let first = candidate(&V1, 1);
    let mut storage = FullServiceStorage::new(first.storage_shape()).unwrap();
    let mut active = ActivePublication::<SimIo>::new(&mut storage, first).unwrap();
    let mut io = SimIo::new();
    let live = populate(&mut active, &mut io);
    let before = observe(&active);

    // A rejected candidate continues the old generation in the same tick.
    io.inject(LAN, lan_udp(5_000, REMOTE, 64));
    let report = tick(&mut active, &mut io, 1_010, Some(candidate(&V2, 1)));
    assert_eq!(
        report.publication,
        PublicationOutcome::Rejected(ApplyError::Successor(
            SuccessorError::GenerationNotIncreasing
        ))
    );
    let sent = drain(&mut io);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].bytes[0..6], GATEWAY_A_MAC);
    assert_eq!(active.generation().get(), 1);

    // An unfinished TX completion defers the candidate before publication.
    io.inject(LAN, lan_udp(5_000, REMOTE, 64));
    tick(&mut active, &mut io, 1_011, None);
    assert_eq!(io.pending_tx(), 1);
    let report = tick(&mut active, &mut io, 1_012, Some(candidate(&V2, 2)));
    assert!(matches!(
        report.publication,
        PublicationOutcome::Deferred {
            error: SimPublicationQuiescenceError::TxCompletionPending,
            ..
        }
    ));
    assert_eq!(active.generation().get(), 1);
    drain(&mut io);

    // Apply at a tick boundary. In the same tick, a reply to the flushed
    // mapping is no longer translated, and a new outbound packet uses the
    // new route.
    io.inject(WAN, wan_udp_reply(live.public_udp_port));
    io.inject(LAN, lan_udp(5_000, REMOTE, 64));
    let report = tick(&mut active, &mut io, 1_020, Some(candidate(&V2, 2)));
    assert_eq!(report.publication, PublicationOutcome::Applied);
    assert_eq!(active.generation().get(), 2);
    let sent = drain(&mut io);
    assert_eq!(sent.len(), 1, "the stale reply was dropped");
    assert_eq!(sent[0].egress, WAN);
    assert_eq!(
        sent[0].bytes[0..6],
        GATEWAY_B_MAC,
        "route change took effect"
    );

    let applied = active.last_apply().expect("apply report");
    assert_eq!(applied.previous_generation.get(), 1);
    assert_eq!(applied.generation.get(), 2);
    assert_eq!(applied.nat44_udp.mappings_flushed, occupied(&before.udp.1));
    assert_eq!(applied.nat44_udp.peers_flushed, occupied(&before.udp.2));
    assert_eq!(applied.nat44_tcp.mappings_flushed, 1);
    assert_eq!(
        applied.firewall.states_flushed,
        occupied(&before.firewall.1)
    );
    assert_eq!(applied.resolution.dynamic_neighbors_flushed, 1);
    assert_eq!(
        applied.resolution.actions_flushed,
        before.resolution_occupancy[0]
    );
    assert_eq!(applied.icmpv4_errors.actions_flushed, before.icmpv4.1);

    // Publication-bound state was flushed and rebuilt under the new keys;
    // cumulative counters survived the reconcile.
    let after = active.resolution();
    assert_eq!(after.dynamic_neighbor_count(), 0);
    assert_eq!(after.pending_actions(), 0);
    assert_eq!(active.icmpv4_errors().pending_actions(), 0);
    assert_eq!(occupied(active.nat44_tcp().mappings()), 0);
    assert_eq!(occupied(active.nat44_udp().mappings()), 1, "fresh mapping");
    assert!(active.nat44_udp().counters().reconciliations >= 1);
    assert!(active.firewall().counters().reconciliations >= 1);
    assert!(
        active.resolution().counters().queued >= before.resolution.0.queued,
        "cumulative counters are preserved"
    );

    // The fresh mapping created under the new keys translates replies.
    let (_, _, fresh_port) = forward_once(&mut active, &mut io, 1_021, 5_000);
    assert!(reply_reaches_host(&mut active, &mut io, 1_022, fresh_port));
}

#[test]
fn activation_rejects_mismatched_storage_and_storage_is_reusable() {
    let first = candidate(&V1, 1);
    let other_shape = candidate(
        &Variant {
            firewall_states: 32,
            ..V1
        },
        1,
    )
    .storage_shape();
    let mut storage = FullServiceStorage::new(other_shape).unwrap();
    assert_eq!(storage.shape(), other_shape);
    assert_eq!(
        ActivePublication::<SimIo>::new(&mut storage, first).err(),
        Some(ActivationError::StorageShapeMismatch)
    );

    // Restart-required path: drop the publication, then re-activate. The
    // runtime constructors clear every slot left by the previous owner.
    let mut storage = FullServiceStorage::new(candidate(&V1, 1).storage_shape()).unwrap();
    let mut io = SimIo::new();
    {
        let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate(&V1, 1)).unwrap();
        populate(&mut active, &mut io);
    }
    let active = ActivePublication::<SimIo>::new(&mut storage, candidate(&V1, 5)).unwrap();
    assert_eq!(active.generation().get(), 5);
    assert!(active.resolution().is_pristine());
    assert!(active.icmpv4_errors().is_pristine());
    assert!(active.firewall().is_pristine());
    assert_eq!(occupied(active.nat44_udp().mappings()), 0);
    assert_eq!(occupied(active.nat44_tcp().sessions()), 0);
}

fn exact(count: usize) -> crate::FlushCount {
    crate::FlushCount::Exact(count)
}

#[test]
fn check_successor_is_a_side_effect_free_dry_run_that_predicts_apply() {
    // The dry-run does not raise the storage generation floor either.
    {
        let mut storage = FullServiceStorage::new(candidate(&V1, 1).storage_shape()).unwrap();
        let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate(&V1, 1)).unwrap();
        for generation in [2, 3, 9] {
            assert!(active.check_successor(&candidate(&V2, generation)).is_ok());
        }
        drop(active);
        assert_eq!(storage.generation_floor().map(NonZeroU64::get), Some(1));
        assert!(ActivePublication::<SimIo>::new(&mut storage, candidate(&V1, 2)).is_ok());
    }

    let first = candidate(&V1, 1);
    let mut storage = FullServiceStorage::new(first.storage_shape()).unwrap();
    let mut active = ActivePublication::<SimIo>::new(&mut storage, first).unwrap();
    let mut io = SimIo::new();
    let live = populate(&mut active, &mut io);
    let before = observe(&active);

    // Rejections are the exact errors apply returns, and change nothing.
    for (successor, expected) in [
        (
            candidate(&V2, 1),
            ApplyError::Successor(SuccessorError::GenerationNotIncreasing),
        ),
        (
            candidate(
                &Variant {
                    firewall_states: 32,
                    ..V2
                },
                2,
            ),
            ApplyError::RestartRequired(RestartRequired::StorageShape),
        ),
    ] {
        assert_eq!(active.check_successor(&successor), Err(expected));
        assert!(observe(&active) == before);
    }

    // Repeated successful dry-runs hold and drop all five permits without
    // committing anything.
    let successor = candidate(&V2, 2);
    let check = active.check_successor(&successor).expect("dry-run");
    for _ in 0..64 {
        assert_eq!(active.check_successor(&successor), Ok(check));
    }
    assert!(observe(&active) == before, "dry-run changed runtime state");
    assert_eq!(
        (check.previous_generation.get(), check.generation.get()),
        (1, 2)
    );
    let flush = check.flush;
    assert_eq!(flush.dynamic_neighbors, exact(1));
    assert_eq!(
        flush.resolution_actions,
        exact(before.resolution_occupancy[0])
    );
    assert_eq!(flush.icmpv4_error_actions, exact(before.icmpv4.1));
    assert_eq!(flush.icmpv4_error_states, crate::FlushCount::All);
    assert_eq!(flush.nat44_udp_mappings, exact(occupied(&before.udp.1)));
    assert_eq!(flush.nat44_tcp_mappings, exact(1));
    assert_eq!(flush.firewall_flows, exact(occupied(&before.firewall.1)));

    // Old state still serves traffic (directories, port owners, keys).
    assert!(reply_reaches_host(
        &mut active,
        &mut io,
        1_002,
        live.public_udp_port
    ));
    let check = active.check_successor(&successor).unwrap();

    // The real apply flushes exactly what the dry-run predicted.
    let report = tick(&mut active, &mut io, 1_003, Some(successor));
    assert_eq!(report.publication, PublicationOutcome::Applied);
    let applied = active.last_apply().unwrap();
    let predicted = check.flush;
    assert_eq!(
        [
            predicted.resolution_states,
            predicted.resolution_actions,
            predicted.dynamic_neighbors,
            predicted.failure_holds,
            predicted.icmpv4_error_actions,
            predicted.nat44_udp_mappings,
            predicted.nat44_udp_peers,
            predicted.nat44_tcp_mappings,
            predicted.nat44_tcp_sessions,
            predicted.firewall_flows,
        ],
        [
            applied.resolution.states_flushed,
            applied.resolution.actions_flushed,
            applied.resolution.dynamic_neighbors_flushed,
            applied.resolution.failure_holds_flushed,
            applied.icmpv4_errors.actions_flushed,
            applied.nat44_udp.mappings_flushed,
            applied.nat44_udp.peers_flushed,
            applied.nat44_tcp.mappings_flushed,
            applied.nat44_tcp.sessions_flushed,
            applied.firewall.states_flushed,
        ]
        .map(exact)
    );
}

#[test]
fn plan_restart_classification_matches_live_apply_rejection() {
    use crate::plan::tests::{
        config, ECHO_REPLY_CHANGE, ICMPV4_GENERATION_CHANGE, ICMPV4_POLICY_CHANGE,
        INTERFACE_CHANGE, NAT_FILTERING_CHANGE, PORT_CHANGE, PORT_SHIFT, RESOLUTION_POLICY_CHANGE,
        ROUTE_CHANGE, SHAPE_CHANGE,
    };
    use crate::{ApplyPlan, PublicationSequencer};

    let current = config(&[]);
    let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(SEED));
    let first = sequencer.candidate(&current).unwrap();
    let mut storage = FullServiceStorage::new(first.storage_shape()).unwrap();
    let mut active = ActivePublication::<SimIo>::new(&mut storage, first).unwrap();
    let mut io = SimIo::new();
    populate(&mut active, &mut io);

    let cases: &[&[(&str, &str)]] = &[
        &[SHAPE_CHANGE],
        &[PORT_CHANGE],
        &[RESOLUTION_POLICY_CHANGE],
        &[ICMPV4_POLICY_CHANGE],
        &[ICMPV4_GENERATION_CHANGE],
        &[INTERFACE_CHANGE],
        &[INTERFACE_CHANGE, ICMPV4_POLICY_CHANGE],
        &[INTERFACE_CHANGE, RESOLUTION_POLICY_CHANGE, SHAPE_CHANGE],
    ];
    let mut now = 2_000;
    for edits in cases {
        let next = config(edits);
        let successor = sequencer.candidate(&next).unwrap();
        let plan = ApplyPlan::for_active(&mut active, &current, &next, &successor).unwrap();
        let expected = ApplyError::RestartRequired(plan.restart_required()[0]);
        assert_eq!(plan.dry_run(), Some(Err(expected)));
        assert_eq!(plan.flush(), crate::StateFlush::ALL);
        let before = observe(&active);
        now += 1;
        let report = tick(&mut active, &mut io, now, Some(successor));
        assert_eq!(report.publication, PublicationOutcome::Rejected(expected));
        assert!(observe(&active) == before);
    }

    // No restart reason: the dry-run and the apply both succeed. A
    // same-size NAT port pool shift keeps the storage shape and reloads, and
    // so do the Echo responder switch and the NAT filtering modes.
    let next = config(&[
        ROUTE_CHANGE,
        PORT_SHIFT,
        ECHO_REPLY_CHANGE,
        NAT_FILTERING_CHANGE[0],
        NAT_FILTERING_CHANGE[1],
    ]);
    let successor = sequencer.candidate(&next).unwrap();
    let plan = ApplyPlan::for_active(&mut active, &current, &next, &successor).unwrap();
    assert!(!plan.requires_restart());
    let Some(Ok(check)) = plan.dry_run() else {
        panic!("dry-run accepted");
    };
    assert_eq!(plan.flush(), check.flush);
    assert_eq!(check.generation, successor.generation());
    let report = tick(&mut active, &mut io, now + 1, Some(successor));
    assert_eq!(report.publication, PublicationOutcome::Applied);
    let (_, mac, port) = forward_once(&mut active, &mut io, now + 2, 5_000);
    assert_eq!(mac, GATEWAY_B_MAC);
    assert!((40016..=40031).contains(&port), "shifted pool in use");
    assert!(reply_reaches_host(&mut active, &mut io, now + 3, port));
}

#[test]
fn rollback_reapplies_old_document_as_new_generation_with_new_keys() {
    use crate::plan::tests::{config, ROUTE_CHANGE};
    use crate::{ApplyPlan, PublicationSequencer};

    let a = config(&[]);
    let b = config(&[ROUTE_CHANGE]);
    let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(SEED));
    let first = sequencer.candidate(&a).unwrap();
    let keys = |active: &ActivePublication<'_, SimIo>| {
        let authority = active.candidate.authority();
        (
            authority.nat44_udp_hash_key(),
            authority.nat44_tcp_hash_key(),
            authority.firewall_config().hash_key(),
        )
    };
    let mut storage = FullServiceStorage::new(first.storage_shape()).unwrap();
    let mut active = ActivePublication::<SimIo>::new(&mut storage, first).unwrap();
    let mut io = SimIo::new();
    let key_a = keys(&active);
    assert_eq!(
        forward_once(&mut active, &mut io, 1_000, 5_000).1,
        GATEWAY_A_MAC
    );

    let report = tick(
        &mut active,
        &mut io,
        1_001,
        Some(sequencer.candidate(&b).unwrap()),
    );
    assert_eq!(report.publication, PublicationOutcome::Applied);
    let key_b = keys(&active);
    let (_, mac, port_b) = forward_once(&mut active, &mut io, 1_002, 5_000);
    assert_eq!(mac, GATEWAY_B_MAC);

    // Rollback: plan B→A, then apply the re-validated A as generation 3.
    let rollback = sequencer.candidate(&a).unwrap();
    let plan = ApplyPlan::for_active(&mut active, &b, &a, &rollback).unwrap();
    assert!(matches!(plan.routes(), [crate::Change::Changed(_)]));
    assert_eq!(plan.flush().nat44_udp_mappings, exact(1));
    let report = tick(&mut active, &mut io, 1_003, Some(rollback));
    assert_eq!(report.publication, PublicationOutcome::Applied);
    assert_eq!(active.generation().get(), 3);
    let key_rollback = keys(&active);
    for earlier in [key_a, key_b] {
        assert!(earlier.0 != key_rollback.0);
        assert!(earlier.1 != key_rollback.1);
        assert!(earlier.2 != key_rollback.2);
    }
    // The flushed generation-2 mapping is gone; traffic uses route A again.
    assert!(!reply_reaches_host(&mut active, &mut io, 1_004, port_b));
    let (_, mac, port) = forward_once(&mut active, &mut io, 1_005, 5_000);
    assert_eq!(mac, GATEWAY_A_MAC);
    assert!(reply_reaches_host(&mut active, &mut io, 1_006, port));
}

#[test]
fn storage_reactivation_requires_generation_above_every_served_one() {
    let mut storage = FullServiceStorage::new(candidate(&V1, 1).storage_shape()).unwrap();
    assert_eq!(storage.generation_floor(), None);
    let mut io = SimIo::new();
    {
        let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate(&V1, 5)).unwrap();
        let report = tick(&mut active, &mut io, 1_000, Some(candidate(&V2, 7)));
        assert_eq!(report.publication, PublicationOutcome::Applied);
    }
    assert_eq!(storage.generation_floor().map(NonZeroU64::get), Some(7));
    for stale in [1, 5, 7] {
        assert_eq!(
            ActivePublication::<SimIo>::new(&mut storage, candidate(&V1, stale)).err(),
            Some(ActivationError::GenerationNotAboveFloor),
            "generation {stale}"
        );
    }
    let active = ActivePublication::<SimIo>::new(&mut storage, candidate(&V1, 8)).unwrap();
    assert_eq!(active.generation().get(), 8);
    drop(active);
    assert_eq!(storage.generation_floor().map(NonZeroU64::get), Some(8));
}

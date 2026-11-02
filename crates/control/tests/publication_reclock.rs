//! A tick that publishes a candidate reads the clock again after the
//! publication phase (`run_tick_reclocked`), so RX in that tick, and every
//! timer it starts, uses a reading taken after the (possibly slow) apply.
//! RFC 5382 REQ-4: an unsolicited SYN that lands in the RX ring while a
//! successor is applied must not get a hold deadline from the earlier
//! reading (NAT44-038).

use std::cell::Cell;
use std::num::NonZeroU64;

use ruster_control::{
    ActivePublication, FirewallPublicationInput, FullServiceStorage, FullServiceStorageShape,
    Icmpv4ErrorStorageShape, Nat44TcpPublicationInput, Nat44TcpStoragePlan,
    Nat44UdpPublicationInput, Nat44UdpStoragePlan, PublicationPlan, ResolutionStorageShape,
    ValidatedCandidate,
};
use ruster_core::{
    internet_checksum, ipv4_header_checksum, FirewallAction, FirewallHashKey, FirewallInterface,
    FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange, FirewallProtocol, FirewallRule,
    FirewallRuleId, GeneratedArpTrace, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
    GeneratedTraceSink, Icmpv4ErrorPolicy, IfId, Interface, Ipv4Address, Ipv4OriginPolicy,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44TcpHashKey, Nat44TcpPolicy,
    Nat44TcpUnsolicitedSynDisposition, Nat44UdpHashKey, Nat44UdpPolicy, ResolutionFailureTrace,
    ResolutionFailureTraceSink, ResolutionPolicy, ResolutionTimerTrace, ResolutionTimerTraceSink,
    Route, TraceEvent, TraceSink, NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS,
    NAT44_TCP_UNSOLICITED_SYN_HOLD_MS,
};
use ruster_io_sim::SimIo;
use ruster_runtime::{
    run_tick_reclocked, PublicationOutcome, TickBudgets, TickPhaseTrace, TickPhaseTraceSink,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 3];
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const BUDGETS: TickBudgets = TickBudgets {
    rx: 32,
    resolution_timer_scans: 8,
    failure_dispatch_scans: 8,
    generated_arp: 8,
    generated_icmpv4: 8,
};

/// Records the unsolicited-SYN dispositions.
#[derive(Default)]
struct Holds(Vec<Nat44TcpUnsolicitedSynDisposition>);

impl TickPhaseTraceSink for Holds {
    fn record_tick_phase(&mut self, _: TickPhaseTrace) {}
}
impl TraceSink for Holds {
    fn record(&mut self, event: TraceEvent) {
        if let TraceEvent::Nat44TcpUnsolicitedSyn { disposition } = event {
            self.0.push(disposition);
        }
    }
}
impl ResolutionTimerTraceSink for Holds {
    fn record_resolution_timer(&mut self, _: ResolutionTimerTrace) {}
}
impl ResolutionFailureTraceSink for Holds {
    fn record_resolution_failure(&mut self, _: ResolutionFailureTrace) {}
}
impl GeneratedTraceSink for Holds {
    fn record_generated(&mut self, _: GeneratedArpTrace) {}
}
impl GeneratedIcmpv4TraceSink for Holds {
    fn record_generated_icmpv4(&mut self, _: GeneratedIcmpv4Trace) {}
}

/// LAN 10.0.0.0/24, default route out of WAN, TCP NAT with four
/// unsolicited-SYN hold slots (switch on by default), and a firewall that
/// admits new WAN -> LAN TCP flows to every inside destination, so an
/// unsolicited SYN is held (RFC 5382 REQ-4 a).
fn candidate(generation: u64) -> ValidatedCandidate {
    let key = generation * 8;
    let routes = [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([0; 4]),
            0,
            WAN,
            Some(Ipv4Address::from_octets([203, 0, 113, 1])),
        )
        .unwrap(),
    ];
    let interfaces = [
        Interface {
            id: LAN,
            mac: MacAddress(LAN_MAC),
        },
        Interface {
            id: WAN,
            mac: MacAddress(WAN_MAC),
        },
    ];
    let bindings = [
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
    ];
    let shape = FullServiceStorageShape::new(
        ResolutionStorageShape::new(4, 4, 4, 4),
        Icmpv4ErrorStorageShape::new(4, 4),
        Nat44UdpStoragePlan::new(4, 8, 4, 4, 8, 8, 8),
        Nat44TcpStoragePlan::new(4, 8, 4, 4, 8, 8, 8).with_unsolicited_syn_hold_slots(4),
        16,
    );
    let plan = PublicationPlan::new(
        NonZeroU64::new(generation).unwrap(),
        shape,
        routes.into(),
        interfaces.into(),
        Vec::new().into_boxed_slice(),
        bindings.into(),
        Ipv4OriginPolicy::default(),
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        Icmpv4ErrorPolicy::default(),
    )
    .with_nat44_udp(Nat44UdpPublicationInput::new(
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_007,
        Nat44UdpPolicy::default(),
        Nat44UdpHashKey::new(key + 1, key + 2).unwrap(),
    ))
    .with_nat44_tcp(Nat44TcpPublicationInput::new(
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_007,
        Nat44TcpPolicy::default(),
        Nat44TcpHashKey::new(key + 3, key + 4).unwrap(),
    ))
    .with_firewall(FirewallPublicationInput::new(
        vec![FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(WAN),
            FirewallInterface::Interface(LAN),
            FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap(),
            FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap(),
            FirewallProtocol::Tcp,
            FirewallPortRange::new(1, u16::MAX).unwrap(),
            FirewallPortRange::new(1, u16::MAX).unwrap(),
            FirewallAction::AllowStateful,
        )]
        .into_boxed_slice(),
        FirewallPolicy::default(),
        FirewallHashKey::new(key + 5, key + 6).unwrap(),
    ))
    .with_resolution_hash_key(ruster_core::ResolutionHashKey::new(key + 7, key + 8).unwrap());
    ValidatedCandidate::new(plan).unwrap()
}

/// An unsolicited SYN from `REMOTE:remote_port` to `PUBLIC:40003` (no
/// mapping) arriving on WAN.
fn wan_syn(remote_port: u16) -> Vec<u8> {
    let mut frame = vec![0_u8; 54];
    frame[0..6].copy_from_slice(&WAN_MAC);
    frame[6..12].copy_from_slice(&GATEWAY_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&REMOTE.octets());
    frame[30..34].copy_from_slice(&PUBLIC.octets());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34..36].copy_from_slice(&remote_port.to_be_bytes());
    frame[36..38].copy_from_slice(&40_003_u16.to_be_bytes());
    frame[38..42].copy_from_slice(&0x1234_u32.to_be_bytes());
    frame[46] = 5 << 4;
    frame[47] = 0x02;
    frame[48..50].copy_from_slice(&8_192_u16.to_be_bytes());
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&REMOTE.octets());
    pseudo.extend_from_slice(&PUBLIC.octets());
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&frame[34..54]);
    let checksum = internet_checksum(&pseudo);
    frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    frame
}

const HOLD: u64 = NAT44_TCP_UNSOLICITED_SYN_HOLD_MS + NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS;

#[test]
fn a_slow_publication_tick_stamps_its_rx_with_the_post_publication_reading() {
    let mut storage = FullServiceStorage::new(candidate(1).storage_shape()).unwrap();
    let mut active = ActivePublication::new(&mut storage, candidate(1)).unwrap();
    let mut io = SimIo::new();
    let mut trace = Holds::default();
    let reads = Cell::new(0_u32);
    let reads = &reads;
    let clock = |reading: u64| {
        move || {
            reads.set(reads.get() + 1);
            MonotonicMillis(reading)
        }
    };

    // A steady tick never reads the clock again, and stamps RX with `now`.
    io.inject(WAN, wan_syn(1_000));
    let report = run_tick_reclocked(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(100),
        clock(u64::MAX),
        BUDGETS,
        &mut trace,
    );
    assert!(report.active);
    assert_eq!(reads.get(), 0);
    assert_eq!(
        trace.0,
        [Nat44TcpUnsolicitedSynDisposition::Held {
            public_port: 40_003,
            deadline_ms: 100 + HOLD,
        }]
    );

    // The successor's apply takes 250 ms (the tick read 1_000 before it,
    // the clock reads 1_250 after it); the SYN in the ring is received in
    // the same tick and its hold runs from 1_250, not 1_000.
    trace.0.clear();
    io.inject(WAN, wan_syn(2_000));
    let report = run_tick_reclocked(
        &mut active,
        Some(candidate(2)),
        &mut io,
        MonotonicMillis(1_000),
        clock(1_250),
        BUDGETS,
        &mut trace,
    );
    assert_eq!(report.publication, PublicationOutcome::Applied);
    assert_eq!(active.generation().get(), 2);
    assert_eq!(
        trace.0,
        [Nat44TcpUnsolicitedSynDisposition::Held {
            public_port: 40_003,
            deadline_ms: 1_250 + HOLD,
        }]
    );
    assert_eq!(reads.get(), 1, "one extra reading on a publication tick");

    // A reading behind `now` never moves the tick clock backwards.
    trace.0.clear();
    io.inject(WAN, wan_syn(3_000));
    let report = run_tick_reclocked(
        &mut active,
        Some(candidate(3)),
        &mut io,
        MonotonicMillis(2_000),
        clock(1_999),
        BUDGETS,
        &mut trace,
    );
    assert_eq!(report.publication, PublicationOutcome::Applied);
    assert_eq!(reads.get(), 2);
    assert_eq!(
        trace.0,
        [Nat44TcpUnsolicitedSynDisposition::Held {
            public_port: 40_003,
            deadline_ms: 2_000 + HOLD,
        }]
    );

    // A rejected candidate (a generation already served) still did work in
    // the publication phase: one more reading, and the old generation's
    // RX runs from it.
    trace.0.clear();
    io.inject(WAN, wan_syn(4_000));
    let report = run_tick_reclocked(
        &mut active,
        Some(candidate(3)),
        &mut io,
        MonotonicMillis(3_000),
        clock(3_040),
        BUDGETS,
        &mut trace,
    );
    assert!(
        matches!(report.publication, PublicationOutcome::Rejected(_)),
        "{:?}",
        report.publication
    );
    assert_eq!(active.generation().get(), 3);
    assert_eq!(
        trace.0,
        [Nat44TcpUnsolicitedSynDisposition::Held {
            public_port: 40_003,
            deadline_ms: 3_040 + HOLD,
        }]
    );
    assert_eq!(reads.get(), 3);
}

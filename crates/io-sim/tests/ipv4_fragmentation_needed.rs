//! MTU1: the egress MTU rule of RFC 1812 §4.2.2.7 for routed (not
//! translated) IPv4 and the ICMP Destination Unreachable, Fragmentation
//! Needed and DF Set error of RFC 1812 §5.2.7.1 with the Next-Hop MTU of
//! RFC 1191 §4. NAT, hairpin, firewall, and the config path are covered by
//! `fixtures/mtu1` (sim-scenario) and `nat44_hairpin`.
//!
//! Expected wire bytes are built here from the RFC field layout with a
//! local checksum, not with the router's builders.

use ruster_core::{
    execute_one_icmpv4_error, forward_batch_with_resolution_and_icmpv4_errors, DropReason,
    ForwardingSnapshot, GeneratedIcmpv4Trace, Icmpv4ErrorActionSlot, Icmpv4ErrorDisposition,
    Icmpv4ErrorKind, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface,
    Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, PacketIo,
    ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
    SnapshotError, TraceEvent,
};
use ruster_io_sim::{FrameOrigin, RecycleCause, SimIo, VecGeneratedIcmpv4Trace, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x10]);
const SERVER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x20]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const HOST: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 10]);
const SERVER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const DF: u16 = 0x4000;

/// RFC 1071 one's-complement sum, independent of `ruster_core`.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

struct Net {
    routes: [Route; 2],
    interfaces: [Interface; 2],
    neighbors: [Neighbor; 2],
    bindings: [LocalIpv4Binding; 2],
}

impl Net {
    fn new(lan_mtu: u16, wan_mtu: u16) -> Self {
        Self {
            routes: [
                Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap(),
                Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap(),
            ],
            interfaces: [
                Interface {
                    id: LAN,
                    mac: LAN_MAC,
                    mtu: lan_mtu,
                },
                Interface {
                    id: WAN,
                    mac: WAN_MAC,
                    mtu: wan_mtu,
                },
            ],
            neighbors: [
                Neighbor {
                    interface: LAN,
                    target: HOST,
                    mac: HOST_MAC,
                },
                Neighbor {
                    interface: WAN,
                    target: SERVER,
                    mac: SERVER_MAC,
                },
            ],
            bindings: [
                LocalIpv4Binding {
                    interface: LAN,
                    address: LAN_IP,
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: WAN_IP,
                },
            ],
        }
    }

    fn snapshot(&self) -> ForwardingSnapshot<'_> {
        ForwardingSnapshot::new(
            &self.routes,
            &self.interfaces,
            &self.neighbors,
            &self.bindings,
        )
        .unwrap()
    }
}

/// HOST -> SERVER IPv4 datagram of `total_len` bytes, received on LAN.
fn datagram(total_len: usize, flags_fragment: u16, protocol: u8, tos: u8) -> Vec<u8> {
    let mut frame = vec![0; 14 + total_len];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = tos;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = 64;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&HOST.octets());
    frame[30..34].copy_from_slice(&SERVER.octets());
    for (index, byte) in frame[34..].iter_mut().enumerate() {
        *byte = (index * 13) as u8;
    }
    let header = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&header.to_be_bytes());
    frame
}

/// The exact Fragmentation Needed frame the router must send to HOST about
/// `original` (RFC 792 layout, RFC 1191 §4 Next-Hop MTU, RFC 1812
/// §4.3.2.3 quote of at most 576 bytes cut further to the LAN MTU).
fn expected_error(original: &[u8], next_hop_mtu: u16, lan_mtu: u16, outer_ttl: u8) -> Vec<u8> {
    let quote_len = (original.len() - 14)
        .min(548)
        .min(usize::from(lan_mtu) - 28);
    let total = 28 + quote_len;
    let mut frame = vec![0; 14 + total];
    frame[0..6].copy_from_slice(&HOST_MAC.0);
    frame[6..12].copy_from_slice(&LAN_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = (original[15] & 0x1e) | 0xc0;
    frame[16..18].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    frame[20..22].copy_from_slice(&DF.to_be_bytes());
    frame[22] = outer_ttl;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&LAN_IP.octets());
    frame[30..34].copy_from_slice(&HOST.octets());
    let header = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&header.to_be_bytes());
    frame[34] = 3;
    frame[35] = 4;
    frame[40..42].copy_from_slice(&next_hop_mtu.to_be_bytes());
    frame[42..].copy_from_slice(&original[14..14 + quote_len]);
    let icmp = checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&icmp.to_be_bytes());
    frame
}

struct Runtimes {
    resolution_states: [ResolutionStateSlot; 2],
    resolution_actions: [ResolutionActionSlot; 2],
    error_states: [Icmpv4ErrorStateSlot; 4],
    error_actions: [Icmpv4ErrorActionSlot; 4],
}

impl Runtimes {
    fn new() -> Self {
        Self {
            resolution_states: [ResolutionStateSlot::EMPTY; 2],
            resolution_actions: [ResolutionActionSlot::EMPTY; 2],
            error_states: [Icmpv4ErrorStateSlot::EMPTY; 4],
            error_actions: [Icmpv4ErrorActionSlot::EMPTY; 4],
        }
    }
}

/// Forwards `frames` (received on LAN) at `now` and returns the trace.
fn forward(
    io: &mut SimIo,
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    errors: &mut Icmpv4ErrorRuntime<'_>,
    frames: &[Vec<u8>],
    now: u64,
) -> VecTrace {
    for frame in frames {
        io.inject(LAN, frame.clone());
    }
    let mut trace = VecTrace::default();
    let batch = io.receive(frames.len()).unwrap();
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        snapshot,
        resolution,
        errors,
        MonotonicMillis(now),
        &mut trace,
    );
    assert_eq!(report.received, frames.len());
    trace
}

fn dispositions(trace: &VecTrace) -> Vec<Icmpv4ErrorDisposition> {
    trace
        .events()
        .iter()
        .filter_map(|event| match event {
            TraceEvent::Icmpv4FragmentationNeededDisposition {
                ingress,
                disposition,
            } => {
                assert_eq!(*ingress, LAN);
                Some(*disposition)
            }
            _ => None,
        })
        .collect()
}

fn assert_dropped(io: &mut SimIo, reason: DropReason, original: &[u8]) {
    let recycled = io.pop_recycled().expect("dropped");
    assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
    assert_eq!(recycled.bytes, original, "drops are byte-unchanged");
}

/// A DF datagram one byte above the WAN MTU is discarded byte-unchanged
/// and answered with exactly one Type 3/Code 4 error carrying the WAN MTU,
/// from the LAN address to the source, quoting 548 bytes (576 in all);
/// one of exactly the MTU is forwarded.
#[test]
fn df_datagram_above_the_egress_mtu_gets_exact_fragmentation_needed() {
    let net = Net::new(1500, 1400);
    let snapshot = net.snapshot();
    let mut storage = Runtimes::new();
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut storage.resolution_states,
        &mut storage.resolution_actions,
    );
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut storage.error_states,
        &mut storage.error_actions,
    );
    let mut io = SimIo::new();

    let fits = datagram(1400, DF, 17, 0);
    forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&fits),
        0,
    );
    let tx = io.pop_tx().expect("exactly the MTU is forwarded");
    assert_eq!((tx.egress, tx.bytes.len()), (WAN, fits.len()));
    assert_eq!(tx.bytes[22], 63);

    let original = datagram(1401, DF, 17, 0x2f);
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&original),
        10,
    );
    assert_dropped(&mut io, DropReason::Ipv4FragmentationNeeded, &original);
    assert!(io.pop_tx().is_none());
    assert_eq!(
        dispositions(&trace),
        [Icmpv4ErrorDisposition::FragmentationNeededQueued {
            egress: LAN,
            quote_len: 548,
            next_hop_mtu: 1400,
        }]
    );

    let mut generated = VecGeneratedIcmpv4Trace::default();
    let report =
        execute_one_icmpv4_error(&mut io, &mut errors, MonotonicMillis(10), &mut generated)
            .unwrap()
            .unwrap();
    assert_eq!(
        report.action.kind,
        Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded
    );
    assert_eq!(report.action.next_hop_mtu(), 1400);
    assert_eq!(
        generated.events(),
        [
            GeneratedIcmpv4Trace::FragmentationNeededTxRequested {
                egress: LAN,
                destination: HOST,
                next_hop_mtu: 1400,
            },
            GeneratedIcmpv4Trace::FragmentationNeededBatchCompleted {
                accepted: 1,
                rejected: 0,
            },
        ]
    );
    let tx = io.pop_tx().unwrap();
    assert_eq!((tx.egress, tx.origin), (LAN, FrameOrigin::Generated));
    assert_eq!(tx.bytes, expected_error(&original, 1400, 1500, 64));
    assert_eq!(tx.bytes.len(), 14 + 576);
    let counters = errors.counters();
    assert_eq!(
        (
            counters.queued,
            counters.queued_fragmentation_needed,
            counters.dequeued_fragmentation_needed
        ),
        (1, 1, 1)
    );
}

/// Without DF the datagram would have to be fragmented (RFC 1812 §4.2.2.7),
/// which is not implemented (NAT44-019L): a typed, counted drop and no
/// error, since Type 3/Code 4 claims DF was set.
#[test]
fn df_clear_datagram_above_the_egress_mtu_is_a_typed_drop_without_error() {
    let net = Net::new(1500, 576);
    let snapshot = net.snapshot();
    let mut storage = Runtimes::new();
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut storage.resolution_states,
        &mut storage.resolution_actions,
    );
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut storage.error_states,
        &mut storage.error_actions,
    );
    let mut io = SimIo::new();
    for flags in [0, 0x2000] {
        let original = datagram(577, flags, 17, 0);
        let trace = forward(
            &mut io,
            &snapshot,
            &mut resolution,
            &mut errors,
            std::slice::from_ref(&original),
            0,
        );
        assert_dropped(&mut io, DropReason::Ipv4FragmentationRequired, &original);
        assert!(dispositions(&trace).is_empty());
    }
    let fits = datagram(576, 0, 17, 0);
    forward(&mut io, &snapshot, &mut resolution, &mut errors, &[fits], 0);
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(errors.counters(), Default::default());
    assert_eq!(errors.pending_actions(), 0);
}

/// RFC 1812 §4.3.2.7: no error about an ICMP error or a non-initial
/// fragment; the datagram is still discarded as Fragmentation Needed. An
/// Echo Request is not an error and is answered.
#[test]
fn suppression_rules_apply_to_fragmentation_needed() {
    let net = Net::new(1500, 576);
    let snapshot = net.snapshot();
    let mut storage = Runtimes::new();
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut storage.resolution_states,
        &mut storage.resolution_actions,
    );
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut storage.error_states,
        &mut storage.error_actions,
    );
    let mut io = SimIo::new();
    let mut time_exceeded = datagram(600, DF, 1, 0);
    time_exceeded[34] = 11;
    time_exceeded[24..26].fill(0);
    let header = checksum(&time_exceeded[14..34]);
    time_exceeded[24..26].copy_from_slice(&header.to_be_bytes());
    let fragment = datagram(600, DF | 0x0010, 17, 0);
    let mut echo = datagram(600, DF, 1, 0);
    echo[34..38].copy_from_slice(&[8, 0, 0, 0]);
    let icmp = checksum(&echo[34..]);
    echo[36..38].copy_from_slice(&icmp.to_be_bytes());
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        &[time_exceeded.clone(), fragment.clone(), echo.clone()],
        0,
    );
    assert_dropped(&mut io, DropReason::Ipv4FragmentationNeeded, &time_exceeded);
    assert_dropped(&mut io, DropReason::Ipv4FragmentationNeeded, &fragment);
    assert_dropped(&mut io, DropReason::Ipv4FragmentationNeeded, &echo);
    assert_eq!(
        dispositions(&trace),
        [
            Icmpv4ErrorDisposition::IcmpErrorMessage,
            Icmpv4ErrorDisposition::NonInitialFragment,
            Icmpv4ErrorDisposition::FragmentationNeededQueued {
                egress: LAN,
                quote_len: 548,
                next_hop_mtu: 576,
            },
        ]
    );
}

/// The generation switch (RFC 1812 §1.1.3 option) suppresses the error
/// before the limiter; with it on, the per-egress limiter (RFC 1812
/// §4.3.2.8) holds a second error while one is queued and rate limits one
/// inside its own interval (`fragmentation-needed-interval-ms`, 100 here).
#[test]
fn switch_and_limiter_govern_fragmentation_needed() {
    let net = Net::new(1500, 576);
    let snapshot = net.snapshot();
    let original = datagram(577, DF, 17, 0);

    let mut storage = Runtimes::new();
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut storage.resolution_states,
        &mut storage.resolution_actions,
    );
    let off = Icmpv4ErrorPolicy::default().with_generation(
        Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded,
        false,
    );
    assert!(off.generates(Icmpv4ErrorKind::TimeExceededTtl));
    let mut errors =
        Icmpv4ErrorRuntime::new(off, &mut storage.error_states, &mut storage.error_actions);
    let mut io = SimIo::new();
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&original),
        0,
    );
    assert_dropped(&mut io, DropReason::Ipv4FragmentationNeeded, &original);
    assert_eq!(
        dispositions(&trace),
        [Icmpv4ErrorDisposition::GenerationDisabled {
            kind: Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded
        }]
    );
    assert_eq!(errors.counters().disabled_fragmentation_needed, 1);
    assert_eq!(errors.pending_actions(), 0);

    let mut storage = Runtimes::new();
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut storage.resolution_states,
        &mut storage.resolution_actions,
    );
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::new(100, 60_000)
            .unwrap()
            .with_fragmentation_needed_interval_ms(100)
            .unwrap(),
        &mut storage.error_states,
        &mut storage.error_actions,
    );
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        &[original.clone(), original.clone()],
        0,
    );
    assert!(matches!(
        dispositions(&trace)[..],
        [
            Icmpv4ErrorDisposition::FragmentationNeededQueued { .. },
            Icmpv4ErrorDisposition::Pending { egress: LAN },
        ]
    ));
    execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(0),
        &mut VecGeneratedIcmpv4Trace::default(),
    )
    .unwrap()
    .unwrap();
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&original),
        99,
    );
    assert_eq!(
        dispositions(&trace),
        [Icmpv4ErrorDisposition::RateLimited { egress: LAN }]
    );
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&original),
        100,
    );
    assert!(matches!(
        dispositions(&trace)[..],
        [Icmpv4ErrorDisposition::FragmentationNeededQueued { .. }]
    ));
    let counters = errors.counters();
    assert_eq!(
        (
            counters.queued_fragmentation_needed,
            counters.pending,
            counters.rate_limited
        ),
        (2, 1, 1)
    );
}

/// Every error fits the MTU of the interface it leaves: with a LAN MTU of
/// 100 the error about a 201-byte datagram (WAN MTU 200) quotes 72 bytes
/// and is exactly 100 bytes of IPv4. Time Exceeded is cut the same way.
#[test]
fn errors_are_cut_to_the_mtu_of_the_reverse_egress() {
    let net = Net::new(100, 200);
    let snapshot = net.snapshot();
    let mut storage = Runtimes::new();
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut storage.resolution_states,
        &mut storage.resolution_actions,
    );
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut storage.error_states,
        &mut storage.error_actions,
    );
    let mut io = SimIo::new();
    let original = datagram(201, DF, 17, 0);
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&original),
        0,
    );
    assert_dropped(&mut io, DropReason::Ipv4FragmentationNeeded, &original);
    assert_eq!(
        dispositions(&trace),
        [Icmpv4ErrorDisposition::FragmentationNeededQueued {
            egress: LAN,
            quote_len: 72,
            next_hop_mtu: 200,
        }]
    );
    execute_one_icmpv4_error(
        &mut io,
        &mut errors,
        MonotonicMillis(0),
        &mut VecGeneratedIcmpv4Trace::default(),
    )
    .unwrap()
    .unwrap();
    let tx = io.pop_tx().unwrap();
    assert_eq!(tx.bytes, expected_error(&original, 200, 100, 64));
    assert_eq!(tx.bytes.len(), 14 + 100);

    let mut expired = datagram(150, DF, 17, 0);
    expired[22] = 1;
    expired[24..26].fill(0);
    let header = checksum(&expired[14..34]);
    expired[24..26].copy_from_slice(&header.to_be_bytes());
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        &[expired.clone()],
        1_000,
    );
    assert_dropped(&mut io, DropReason::Ipv4TtlExpired, &expired);
    assert!(trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::Icmpv4TimeExceededDisposition {
            disposition: Icmpv4ErrorDisposition::Queued {
                egress: LAN,
                quote_len: 72
            },
            ..
        }
    )));
}

/// RFC 791: every link carries 68 octets. A snapshot refuses a smaller
/// interface MTU and accepts exactly 68.
#[test]
fn snapshot_refuses_an_mtu_below_68() {
    let net = Net::new(67, 1500);
    assert_eq!(
        ForwardingSnapshot::new(&net.routes, &net.interfaces, &net.neighbors, &net.bindings)
            .unwrap_err(),
        SnapshotError::InterfaceMtuBelowMinimum
    );
    let net = Net::new(68, 1500);
    assert!(
        ForwardingSnapshot::new(&net.routes, &net.interfaces, &net.neighbors, &net.bindings)
            .is_ok()
    );
}

/// MTU1 review M1: Fragmentation Needed has its own limiter class, so a TTL
/// sweep toward the same reverse egress (a Time Exceeded every 10 ms,
/// faster than the shared 100 ms interval) never starves Path MTU
/// Discovery: every oversized DF datagram 10 ms apart (the default
/// Fragmentation Needed interval) gets its error, and the Time Exceeded
/// errors are limited only by their own class.
#[test]
fn a_ttl_flood_on_the_same_egress_does_not_starve_fragmentation_needed() {
    use ruster_core::ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS;
    assert_eq!(ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS, 10);
    let net = Net::new(1500, 576);
    let snapshot = net.snapshot();
    let mut storage = Runtimes::new();
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut storage.resolution_states,
        &mut storage.resolution_actions,
    );
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut storage.error_states,
        &mut storage.error_actions,
    );
    let mut io = SimIo::new();
    let mut expired = datagram(100, DF, 17, 0);
    expired[22] = 1;
    expired[24..26].fill(0);
    let header = checksum(&expired[14..34]);
    expired[24..26].copy_from_slice(&header.to_be_bytes());
    let oversized = datagram(577, DF, 17, 0);
    let rounds = 50;
    let mut sent = 0;
    for round in 0..rounds {
        let now = round * 10;
        // The expiring datagram first, so its error takes the shared state.
        forward(
            &mut io,
            &snapshot,
            &mut resolution,
            &mut errors,
            &[expired.clone(), oversized.clone()],
            now,
        );
        while let Some(report) = execute_one_icmpv4_error(
            &mut io,
            &mut errors,
            MonotonicMillis(now),
            &mut VecGeneratedIcmpv4Trace::default(),
        )
        .unwrap()
        {
            if report.action.kind == Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded {
                sent += 1;
            }
        }
        while io.pop_tx().is_some() {}
        while io.pop_recycled().is_some() {}
    }
    let counters = errors.counters();
    assert_eq!(sent, rounds);
    assert_eq!(counters.queued_fragmentation_needed, 50);
    assert_eq!(counters.dequeued_fragmentation_needed, 50);
    // Time Exceeded: one per 100 ms of its own class, the rest limited.
    assert_eq!(counters.queued_time_exceeded, 5);
    assert_eq!(counters.rate_limited, 45);
}

/// MTU1 review L1: the backend sends the whole frame, so a datagram within
/// the egress MTU whose frame carries bytes after its Total Length beyond
/// that MTU is IPV4_FRAME_EXCEEDS_MTU, byte-unchanged and without an error;
/// up to exactly the MTU of Ethernet payload, and minimum Ethernet padding,
/// it is forwarded.
#[test]
fn trailing_bytes_beyond_the_egress_mtu_are_a_typed_drop() {
    let net = Net::new(1500, 576);
    let snapshot = net.snapshot();
    let mut storage = Runtimes::new();
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut storage.resolution_states,
        &mut storage.resolution_actions,
    );
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut storage.error_states,
        &mut storage.error_actions,
    );
    let mut io = SimIo::new();
    let mut trailing = datagram(500, DF, 17, 0);
    trailing.resize(14 + 577, 0xee);
    let trace = forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&trailing),
        0,
    );
    assert_dropped(&mut io, DropReason::Ipv4FrameExceedsMtu, &trailing);
    assert!(dispositions(&trace).is_empty());
    assert_eq!(errors.counters(), Default::default());
    trailing.truncate(14 + 576);
    forward(
        &mut io,
        &snapshot,
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&trailing),
        0,
    );
    assert_eq!(io.pop_tx().unwrap().bytes.len(), 14 + 576);
    let mut padded = datagram(28, DF, 17, 0);
    padded.resize(60, 0);
    let tiny = Net::new(1500, 68);
    forward(
        &mut io,
        &tiny.snapshot(),
        &mut resolution,
        &mut errors,
        std::slice::from_ref(&padded),
        0,
    );
    assert_eq!(io.pop_tx().unwrap().bytes.len(), 60);
}

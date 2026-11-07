//! ICMP-REDIRECT: RFC 1812 §5.2.7.2 Redirect for Host (Type 5, Code 1).
//!
//! The LAN 192.0.2.0/24 holds the router (192.0.2.1), the hosts A (.9) and
//! B (.20), and a second router G (.254) that reaches 203.0.113.0/24. A
//! datagram A sends through the router to B or to 203.0.113.0/24 leaves
//! through the interface it arrived on, toward a next hop on A's subnet, so
//! A gets a Redirect naming that next hop, and the datagram is still
//! forwarded. Every expected frame is built here from RFC 791/792 with this
//! file's own checksum, independently of the router.

mod support;

use ruster_core::{
    execute_one_icmpv4_error, DropReason, ForwardingSnapshot, Icmpv4ErrorActionSlot,
    Icmpv4ErrorCounters, Icmpv4ErrorDisposition, Icmpv4ErrorKind, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, LocalIpv4Binding,
    MacAddress, MonotonicMillis, Nat44Filtering, Nat44UdpConfig, Nat44UdpMappingSlot,
    Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, NoGeneratedIcmpv4Trace, PacketIo,
    Route, SourceValidation, SourceValidationBinding, TraceEvent,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};
use support::UdpTestIndexes;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const A_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x0a]);
const B_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x0b]);
const G_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xfe]);
const W_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xee]);
const LAN_IP: [u8; 4] = [192, 0, 2, 1];
const WAN_IP: [u8; 4] = [198, 51, 100, 1];
const A: [u8; 4] = [192, 0, 2, 9];
const B: [u8; 4] = [192, 0, 2, 20];
const G: [u8; 4] = [192, 0, 2, 254];
/// The WAN gateway (default route of the NAT world).
const W: [u8; 4] = [198, 51, 100, 254];
/// Behind G.
const BEHIND_G: [u8; 4] = [203, 0, 113, 7];
/// A source on a network behind G, not on the LAN subnet.
const OFF_LINK_SOURCE: [u8; 4] = [10, 5, 5, 5];
/// On an interface route of the LAN that is not its connected subnet.
const OTHER_LAN_PREFIX: [u8; 4] = [172, 16, 0, 5];
const REMOTE: [u8; 4] = [8, 8, 8, 8];
/// A host on the WAN subnet.
const WAN_HOST: [u8; 4] = [198, 51, 100, 50];
const WAN_HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x50]);
const TOS: u8 = 0x2e;
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;

fn ip(octets: [u8; 4]) -> Ipv4Address {
    Ipv4Address::from_octets(octets)
}

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

// ------------------------------------------------------------ builders ----

/// RFC 1071 one's-complement checksum, independent of the router's.
fn sum16(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An Ethernet frame to the router's LAN MAC from `source_mac` carrying
/// an option-free IPv4 datagram.
fn frame(
    source_mac: MacAddress,
    source: [u8; 4],
    destination: [u8; 4],
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut frame = vec![0_u8; 14 + total_len];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = TOS;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x5a5a_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = ttl;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&source);
    frame[30..34].copy_from_slice(&destination);
    let checksum = sum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34..].copy_from_slice(payload);
    frame
}

/// A UDP datagram (ports 40000 -> 53) from A; the UDP checksum is 0
/// (none), so the payload needs no pseudo header.
fn udp_payload() -> Vec<u8> {
    let mut segment = vec![0_u8; 16];
    segment[0..2].copy_from_slice(&40_000_u16.to_be_bytes());
    segment[2..4].copy_from_slice(&53_u16.to_be_bytes());
    segment[4..6].copy_from_slice(&16_u16.to_be_bytes());
    segment[8..16].copy_from_slice(b"redirect");
    segment
}

fn from_a(destination: [u8; 4]) -> Vec<u8> {
    frame(A_MAC, A, destination, DF, 64, 17, &udp_payload())
}

/// `received` as the router forwards it to `next_hop_mac` out of the LAN:
/// new MACs, TTL - 1, the header checksum recomputed from scratch.
fn forwarded(received: &[u8], next_hop_mac: MacAddress) -> Vec<u8> {
    let mut out = received.to_vec();
    out[0..6].copy_from_slice(&next_hop_mac.0);
    out[6..12].copy_from_slice(&LAN_MAC.0);
    out[22] -= 1;
    out[24..26].fill(0);
    let checksum = sum16(&out[14..34]);
    out[24..26].copy_from_slice(&checksum.to_be_bytes());
    out
}

/// The Redirect for Host to A from the router's LAN address naming
/// `gateway`, quoting `received`'s datagram as it arrived (RFC 792; RFC
/// 1812 §4.3.2.5 TOS, DF, TTL 64).
fn expected_redirect(gateway: [u8; 4], received: &[u8]) -> Vec<u8> {
    // RFC 1812 §4.3.2.3: at most 576 bytes of error datagram, so at most
    // 548 quoted bytes.
    let quote = &received[14..received.len().min(14 + 548)];
    let total_len = 28 + quote.len();
    let mut frame = vec![0_u8; (14 + total_len).max(60)];
    frame[0..6].copy_from_slice(&A_MAC.0);
    frame[6..12].copy_from_slice(&LAN_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = (TOS & 0x1e) | 0xc0;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[20..22].copy_from_slice(&DF.to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&LAN_IP);
    frame[30..34].copy_from_slice(&A);
    let checksum = sum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34] = 5;
    frame[35] = 1;
    frame[38..42].copy_from_slice(&gateway);
    frame[42..42 + quote.len()].copy_from_slice(quote);
    let checksum = sum16(&frame[34..42 + quote.len()]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
    frame
}

// --------------------------------------------------------------- world ----

fn snapshot() -> ForwardingSnapshot<'static> {
    snapshot_with(&[], &[], 1500)
}

/// The base topology plus `extra_routes` and `extra_neighbors`, with the
/// LAN MTU `lan_mtu`.
fn snapshot_with(
    extra_routes: &[Route],
    extra_neighbors: &[Neighbor],
    lan_mtu: u16,
) -> ForwardingSnapshot<'static> {
    let mut routes = vec![
        Route::new(ip([192, 0, 2, 0]), 24, LAN, None).unwrap(),
        Route::new(ip([198, 51, 100, 0]), 24, WAN, None).unwrap(),
        Route::new(ip([203, 0, 113, 0]), 24, LAN, Some(ip(G))).unwrap(),
        Route::new(ip([10, 5, 0, 0]), 16, LAN, Some(ip(G))).unwrap(),
        // An interface route without a gateway: on the LAN link, but not
        // A's logical subnet.
        Route::new(ip([172, 16, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(ip([0; 4]), 0, WAN, Some(ip(W))).unwrap(),
    ];
    routes.extend_from_slice(extra_routes);
    let routes = routes.leak();
    let interfaces = leak([
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: lan_mtu,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: 1500,
        },
    ]);
    let mut neighbors = vec![
        Neighbor {
            interface: LAN,
            target: ip(A),
            mac: A_MAC,
        },
        Neighbor {
            interface: LAN,
            target: ip(B),
            mac: B_MAC,
        },
        Neighbor {
            interface: LAN,
            target: ip(G),
            mac: G_MAC,
        },
        Neighbor {
            interface: LAN,
            target: ip(OTHER_LAN_PREFIX),
            mac: B_MAC,
        },
        Neighbor {
            interface: WAN,
            target: ip(W),
            mac: W_MAC,
        },
        Neighbor {
            interface: WAN,
            target: ip(WAN_HOST),
            mac: WAN_HOST_MAC,
        },
    ];
    neighbors.extend_from_slice(extra_neighbors);
    let neighbors = neighbors.leak();
    let bindings = leak([
        LocalIpv4Binding {
            interface: LAN,
            address: ip(LAN_IP),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: ip(WAN_IP),
        },
    ]);
    ForwardingSnapshot::new(&routes[..], &interfaces[..], &neighbors[..], &bindings[..]).unwrap()
}

/// The result of one forwarded frame.
struct Step {
    /// The forwarded frame (egress, bytes), if the router sent it on.
    sent: Option<(IfId, Vec<u8>)>,
    drop: Option<DropReason>,
    redirect: Option<Icmpv4ErrorDisposition>,
    time_exceeded: Option<Icmpv4ErrorDisposition>,
}

struct World {
    snapshot: ForwardingSnapshot<'static>,
    errors: Icmpv4ErrorRuntime<'static>,
    nat: Option<(Nat44UdpConfig, Nat44UdpRuntime<'static>)>,
    io: SimIo,
}

impl World {
    fn new(policy: Icmpv4ErrorPolicy) -> Self {
        Self::on(snapshot(), policy)
    }

    fn on(snapshot: ForwardingSnapshot<'static>, policy: Icmpv4ErrorPolicy) -> Self {
        Self {
            snapshot,
            errors: Icmpv4ErrorRuntime::new(
                policy,
                leak([Icmpv4ErrorStateSlot::EMPTY; 4]),
                leak([Icmpv4ErrorActionSlot::EMPTY; 4]),
            ),
            nat: None,
            io: SimIo::new(),
        }
    }

    /// The same LAN with UDP NAPT from the LAN (inside) to the WAN address
    /// (outside), endpoint-independent filtering, hairpinning on.
    fn with_nat() -> Self {
        let mut world = Self::new(Icmpv4ErrorPolicy::default());
        let config = Nat44UdpConfig::new(
            &world.snapshot,
            LAN,
            WAN,
            ip(WAN_IP),
            40_000,
            40_015,
            Nat44UdpPolicy::default()
                .with_filtering(Nat44Filtering::EndpointIndependent)
                .with_hairpinning(true),
        )
        .unwrap();
        let indexes = leak(UdpTestIndexes::new(config, 4, 8));
        let runtime = indexes.runtime(
            config,
            leak([Nat44UdpMappingSlot::default(); 4]),
            leak([Nat44UdpPeerSlot::default(); 8]),
        );
        world.nat = Some((config, runtime));
        world
    }

    fn forward(&mut self, ingress: IfId, received: &[u8], now: u64) -> Step {
        self.io.inject(ingress, received.to_vec());
        let mut trace = VecTrace::default();
        let batch = self.io.receive(1).unwrap();
        let report = match self.nat.as_mut() {
            Some((config, runtime)) => support::forward(
                batch,
                &self.snapshot,
                MonotonicMillis(now),
                ruster_core::Services {
                    icmpv4_errors: Some(&mut self.errors),
                    nat44_udp: Some((&*config, runtime)),
                    ..ruster_core::Services::default()
                },
                &mut trace,
            ),
            None => support::forward_with_errors(
                batch,
                &self.snapshot,
                &mut self.errors,
                MonotonicMillis(now),
                &mut trace,
            ),
        };
        assert!(report.invariants_hold());
        let sent = self.io.pop_tx().map(|tx| (tx.egress, tx.bytes));
        assert!(self.io.pop_tx().is_none());
        let drop = self.io.pop_recycled().map(|recycled| match recycled.cause {
            RecycleCause::Forwarding(reason) => reason,
            other => panic!("unexpected recycle {other:?}"),
        });
        let find = |wanted: fn(&TraceEvent) -> Option<Icmpv4ErrorDisposition>| {
            trace.events().iter().find_map(wanted)
        };
        Step {
            sent,
            drop,
            redirect: find(|event| match event {
                TraceEvent::Icmpv4RedirectDisposition { disposition, .. } => Some(*disposition),
                _ => None,
            }),
            time_exceeded: find(|event| match event {
                TraceEvent::Icmpv4TimeExceededDisposition { disposition, .. } => Some(*disposition),
                _ => None,
            }),
        }
    }

    /// Runs the generated ICMPv4 phase at `now`; returns what it sent.
    fn generated(&mut self, now: u64) -> Vec<(IfId, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(report) = execute_one_icmpv4_error(
            &mut self.io,
            &mut self.errors,
            MonotonicMillis(now),
            &mut NoGeneratedIcmpv4Trace,
        )
        .unwrap()
        {
            assert_eq!(report.completion.accepted, 1);
            let tx = self.io.pop_tx().unwrap();
            out.push((tx.egress, tx.bytes));
        }
        out
    }

    fn counters(&self) -> Icmpv4ErrorCounters {
        self.errors.counters()
    }
}

fn queued(gateway: [u8; 4], received: &[u8]) -> Option<Icmpv4ErrorDisposition> {
    Some(Icmpv4ErrorDisposition::RedirectQueued {
        egress: LAN,
        quote_len: (received.len() - 14).min(548),
        gateway: ip(gateway),
    })
}

// --------------------------------------------------------------- tests ----

/// A to B through the router: B is on A's subnet, so A gets a Redirect
/// for Host naming B itself, byte for byte (type 5, code 1, the gateway
/// field, both checksums), and the datagram still goes on to B.
#[test]
fn a_datagram_between_two_lan_hosts_is_forwarded_and_redirected() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let received = from_a(B);
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&received, B_MAC))));
    assert_eq!(step.drop, None);
    assert_eq!(step.redirect, queued(B, &received));
    let generated = world.generated(10);
    assert_eq!(generated, [(LAN, expected_redirect(B, &received))]);
    // The ICMP checksum covers the gateway field: the frame's own check.
    let (_, redirect) = &generated[0];
    assert_eq!(sum16(&redirect[34..]), 0);
    assert_eq!(sum16(&redirect[14..34]), 0);
    let counters = world.counters();
    assert_eq!(
        (
            counters.queued,
            counters.queued_redirect,
            counters.dequeued_redirect,
            counters.disabled_redirect
        ),
        (1, 1, 1, 0)
    );
}

/// A to a network behind G: the next hop G is on A's subnet, so the
/// Redirect names G, not the destination.
#[test]
fn the_gateway_field_is_the_next_hop() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let received = from_a(BEHIND_G);
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&received, G_MAC))));
    assert_eq!(step.redirect, queued(G, &received));
    let generated = world.generated(10);
    assert_eq!(generated, [(LAN, expected_redirect(G, &received))]);
    assert_eq!(&generated[0].1[38..42], &G);
}

/// A source that is not on the LAN subnet (reached through G) gets no
/// Redirect: a Redirect only goes to a source on the subnet it names a
/// first hop on (RFC 1812 §5.2.7.2). The datagram is forwarded.
#[test]
fn no_redirect_when_the_source_is_not_on_link() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let received = frame(G_MAC, OFF_LINK_SOURCE, B, DF, 64, 17, &udp_payload());
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&received, B_MAC))));
    assert_eq!(step.redirect, None);
    assert!(world.generated(10).is_empty());
    assert_eq!(world.counters(), Icmpv4ErrorCounters::default());
}

/// A next hop on the LAN link but outside A's subnet (an interface route
/// of the LAN without a gateway) gets no Redirect: A could not use it as a
/// first hop.
#[test]
fn no_redirect_when_the_next_hop_is_off_link() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let received = from_a(OTHER_LAN_PREFIX);
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&received, B_MAC))));
    assert_eq!(step.redirect, None);
    assert!(world.generated(10).is_empty());
    assert_eq!(world.counters(), Icmpv4ErrorCounters::default());
}

/// A datagram that leaves through another interface is never a Redirect
/// case, even from an on-link source.
#[test]
fn no_redirect_when_the_datagram_leaves_through_another_interface() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let received = from_a(REMOTE);
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent.map(|(egress, _)| egress), Some(WAN));
    assert_eq!(step.redirect, None);
    assert_eq!(world.counters(), Icmpv4ErrorCounters::default());
}

/// `redirect = false`: the datagram is forwarded exactly as before, no
/// Redirect is queued, and the disabled counter records the one that
/// would have been sent. The switch does not touch the limiter.
#[test]
fn the_switch_turns_redirects_off_and_forwarding_stays() {
    let policy = Icmpv4ErrorPolicy::default().with_generation(Icmpv4ErrorKind::RedirectHost, false);
    assert!(!policy.generates(Icmpv4ErrorKind::RedirectHost));
    assert!(Icmpv4ErrorPolicy::default().generates(Icmpv4ErrorKind::RedirectHost));
    let mut world = World::new(policy);
    let received = from_a(B);
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&received, B_MAC))));
    assert_eq!(
        step.redirect,
        Some(Icmpv4ErrorDisposition::GenerationDisabled {
            kind: Icmpv4ErrorKind::RedirectHost
        })
    );
    assert!(world.generated(10).is_empty());
    let counters = world.counters();
    assert_eq!((counters.queued, counters.disabled_redirect), (0, 1));
    // The limiter is untouched: a TTL expiry right after still gets its
    // Time Exceeded.
    let expired = frame(A_MAC, A, B, DF, 1, 17, &udp_payload());
    let step = world.forward(LAN, &expired, 11);
    assert!(matches!(
        step.time_exceeded,
        Some(Icmpv4ErrorDisposition::Queued { .. })
    ));
}

/// A hairpinned datagram (A to the NAT public address, translated back to
/// B on the LAN) is NAT traffic and never gets a Redirect: A must keep
/// sending through the router. A plain LAN-to-LAN datagram in the same NAT
/// world still does.
#[test]
fn nat_traffic_never_gets_a_redirect() {
    let mut world = World::with_nat();
    // B's mapping, through the WAN.
    let outbound = frame(B_MAC, B, REMOTE, DF, 64, 17, &udp_payload());
    let step = world.forward(LAN, &outbound, 10);
    let (egress, translated) = step.sent.unwrap();
    assert_eq!(egress, WAN);
    assert_eq!(step.redirect, None);
    let public_port = u16::from_be_bytes([translated[34], translated[35]]);

    // A to the public address and B's public port: hairpinned to B.
    let mut payload = udp_payload();
    payload[2..4].copy_from_slice(&public_port.to_be_bytes());
    let hairpin = frame(A_MAC, A, WAN_IP, DF, 64, 17, &payload);
    let step = world.forward(LAN, &hairpin, 20);
    let (egress, delivered) = step.sent.expect("hairpinned");
    assert_eq!(egress, LAN);
    assert_eq!(&delivered[0..6], &B_MAC.0);
    assert_eq!(&delivered[30..34], &B);
    assert_eq!(step.redirect, None);
    assert!(world.generated(20).is_empty());
    assert_eq!(world.counters().queued_redirect, 0);

    // Plain LAN-to-LAN is not NAT traffic.
    let plain = from_a(B);
    let step = world.forward(LAN, &plain, 30);
    assert_eq!(step.sent, Some((LAN, forwarded(&plain, B_MAC))));
    assert_eq!(step.redirect, queued(B, &plain));
}

/// Redirects have their own per-egress limiter class 3 (interval
/// `interval-ms`, default 100 ms): a second one inside the interval is rate
/// limited while both datagrams are forwarded, a Time Exceeded inside that
/// interval is not (it is class 0), and a Redirect after the interval is
/// sent.
#[test]
fn redirects_have_their_own_limiter_class() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let first = from_a(B);
    assert_eq!(world.forward(LAN, &first, 10).redirect, queued(B, &first));
    assert_eq!(world.generated(10).len(), 1);

    let second = from_a(BEHIND_G);
    let step = world.forward(LAN, &second, 50);
    assert!(step.sent.is_some(), "the datagram is forwarded");
    assert_eq!(
        step.redirect,
        Some(Icmpv4ErrorDisposition::RateLimited { egress: LAN })
    );
    let expired = frame(A_MAC, A, BEHIND_G, DF, 1, 17, &udp_payload());
    assert!(matches!(
        world.forward(LAN, &expired, 60).time_exceeded,
        Some(Icmpv4ErrorDisposition::Queued { .. })
    ));
    assert_eq!(world.generated(60).len(), 1, "the Time Exceeded");

    let third = from_a(BEHIND_G);
    assert_eq!(world.forward(LAN, &third, 110).redirect, queued(G, &third));
    assert_eq!(world.generated(110), [(LAN, expected_redirect(G, &third))]);
    assert_eq!(world.counters().rate_limited, 1);
}

/// Review sec M1: a LAN host that ignores Redirects (accept_redirects=0)
/// and keeps sending to a LAN peer through the router gets one Redirect per
/// interval, and never delays another LAN host's Time Exceeded (traceroute
/// keeps working on that LAN).
#[test]
fn a_host_that_ignores_redirects_never_starves_time_exceeded_for_another_host() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let mut redirects = 0;
    let mut time_exceeded = 0;
    for now in (10..=1_000).step_by(10) {
        let step = world.forward(LAN, &from_a(B), now);
        assert!(step.sent.is_some(), "A's datagram is forwarded");
        // B's traceroute probe once per interval, 50 ms after each
        // Redirect (TTL 1, through the router): with a shared class every
        // one would be RateLimited.
        if now % 100 == 50 {
            let probe = frame(B_MAC, B, REMOTE, DF, 1, 17, &udp_payload());
            let step = world.forward(LAN, &probe, now);
            assert!(
                matches!(
                    step.time_exceeded,
                    Some(Icmpv4ErrorDisposition::Queued { .. })
                ),
                "B's probe at {now} ms: {:?}",
                step.time_exceeded
            );
        }
        for (_, generated) in world.generated(now) {
            match generated[34] {
                5 => redirects += 1,
                11 => time_exceeded += 1,
                other => panic!("unexpected ICMP type {other}"),
            }
        }
    }
    assert_eq!(time_exceeded, 10, "every probe answered");
    assert_eq!(redirects, 10, "one Redirect per 100 ms interval");
}

/// Review sec L2: a datagram that arrives on the NAT outside interface and
/// leaves through it gets no Redirect (the router never tells the outside
/// about first hops); without NAT the same datagram gets one.
#[test]
fn no_redirect_on_the_nat_outside_interface() {
    let mut wan = frame(WAN_HOST_MAC, WAN_HOST, W, DF, 64, 17, &udp_payload());
    wan[0..6].copy_from_slice(&WAN_MAC.0);
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let step = world.forward(WAN, &wan, 10);
    assert_eq!(step.sent.map(|(egress, _)| egress), Some(WAN));
    assert!(matches!(
        step.redirect,
        Some(Icmpv4ErrorDisposition::RedirectQueued { egress: WAN, .. })
    ));

    let mut world = World::with_nat();
    let step = world.forward(WAN, &wan, 10);
    assert_eq!(step.sent.map(|(egress, _)| egress), Some(WAN));
    assert_eq!(step.redirect, None);
    assert_eq!(world.counters(), Icmpv4ErrorCounters::default());
}

/// Review core L1: the source's route must be the ingress interface's own
/// connected route. A wider direct route on the LAN (192.0.0.0/16) that
/// covers the router's address is not the source's logical subnet, and a
/// more specific route for the source through another interface means the
/// source is not on the LAN subnet at all: neither gets a Redirect.
#[test]
fn only_the_connected_subnet_counts_as_the_sources_subnet() {
    let snapshot = snapshot_with(
        &[
            Route::new(ip([192, 0, 0, 0]), 16, LAN, None).unwrap(),
            Route::new(ip([192, 0, 2, 128]), 25, WAN, Some(ip(W))).unwrap(),
        ],
        &[],
        1500,
    );
    let mut world = World::on(snapshot, Icmpv4ErrorPolicy::default());
    for source in [[192, 0, 5, 5], [192, 0, 2, 130]] {
        let received = frame(A_MAC, source, B, DF, 64, 17, &udp_payload());
        let step = world.forward(LAN, &received, 10);
        assert_eq!(step.sent, Some((LAN, forwarded(&received, B_MAC))));
        assert_eq!(step.redirect, None, "{source:?}");
    }
    // A itself (on the connected /24) still gets one.
    let received = from_a(B);
    assert_eq!(
        world.forward(LAN, &received, 10).redirect,
        queued(B, &received)
    );
    assert_eq!(world.counters().queued, 1);
}

/// Review core L2: a route whose gateway is one of the router's own
/// addresses never yields a Redirect naming the router.
#[test]
fn no_redirect_naming_a_router_address() {
    let snapshot = snapshot_with(
        &[Route::new(ip([100, 64, 0, 0]), 24, LAN, Some(ip(LAN_IP))).unwrap()],
        &[Neighbor {
            interface: LAN,
            target: ip(LAN_IP),
            mac: G_MAC,
        }],
        1500,
    );
    let mut world = World::on(snapshot, Icmpv4ErrorPolicy::default());
    let received = from_a([100, 64, 0, 7]);
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&received, G_MAC))));
    assert_eq!(step.redirect, None);
    assert_eq!(world.counters(), Icmpv4ErrorCounters::default());
}

/// The quote of a Redirect about a large datagram stops at 548 bytes
/// (RFC 1812 §4.3.2.3: the error datagram is at most 576 bytes).
#[test]
fn a_large_datagram_is_quoted_up_to_548_bytes() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let received = frame(A_MAC, A, B, DF, 64, 17, &[0x5a; 1400]);
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&received, B_MAC))));
    assert_eq!(step.redirect, queued(B, &received));
    let generated = world.generated(10);
    assert_eq!(generated, [(LAN, expected_redirect(B, &received))]);
    assert_eq!(generated[0].1.len(), 14 + 576);
}

/// A datagram the router drops never gets a Redirect: URPF (strict on the
/// LAN, a spoofed source routed out of the WAN), DF above the egress MTU
/// (Fragmentation Needed instead), DF clear above it without a
/// fragmentation runtime.
#[test]
fn dropped_datagrams_never_get_a_redirect() {
    let bindings = leak([SourceValidationBinding {
        interface: LAN,
        mode: SourceValidation::Strict,
    }]);
    let strict = snapshot().with_source_validation(&bindings[..]).unwrap();
    let mut world = World::on(strict, Icmpv4ErrorPolicy::default());
    let spoofed = frame(A_MAC, [10, 9, 9, 9], B, DF, 64, 17, &udp_payload());
    let step = world.forward(LAN, &spoofed, 10);
    assert_eq!(step.drop, Some(DropReason::Ipv4SourceValidationFailed));
    assert_eq!(step.redirect, None);
    // A on the LAN still passes strict and gets its Redirect.
    let received = from_a(B);
    assert_eq!(
        world.forward(LAN, &received, 20).redirect,
        queued(B, &received)
    );

    let mut world = World::on(snapshot_with(&[], &[], 576), Icmpv4ErrorPolicy::default());
    for (flags, reason) in [
        (DF, DropReason::Ipv4FragmentationNeeded),
        (0, DropReason::Ipv4FragmentationRequired),
    ] {
        let large = frame(A_MAC, A, B, flags, 64, 17, &[0x5a; 1000]);
        let step = world.forward(LAN, &large, 10);
        assert_eq!(step.drop, Some(reason));
        assert_eq!(step.redirect, None);
    }
    assert_eq!(world.counters().queued_redirect, 0);
    assert_eq!(world.counters().queued_fragmentation_needed, 1);
}

/// TTL 1 (and 0): the datagram is not forwarded, so it gets Time Exceeded
/// and never a Redirect.
#[test]
fn ttl_one_gets_time_exceeded_not_a_redirect() {
    for ttl in [0, 1] {
        let mut world = World::new(Icmpv4ErrorPolicy::default());
        let received = frame(A_MAC, A, B, DF, ttl, 17, &udp_payload());
        let step = world.forward(LAN, &received, 10);
        assert_eq!(step.sent, None);
        assert_eq!(step.drop, Some(DropReason::Ipv4TtlExpired));
        assert_eq!(step.redirect, None);
        assert!(matches!(
            step.time_exceeded,
            Some(Icmpv4ErrorDisposition::Queued { .. })
        ));
        let generated = world.generated(10);
        assert_eq!(generated.len(), 1);
        assert_eq!(generated[0].1[34], 11, "Time Exceeded");
        assert_eq!(world.counters().queued_redirect, 0);
    }
}

/// Only the first fragment of a datagram can get a Redirect (RFC 1812
/// §4.3.2.7); a later fragment is forwarded and suppressed.
#[test]
fn only_the_first_fragment_gets_a_redirect() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let first = frame(A_MAC, A, B, MF, 64, 17, &udp_payload());
    let step = world.forward(LAN, &first, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&first, B_MAC))));
    assert_eq!(step.redirect, queued(B, &first));
    assert_eq!(world.generated(10), [(LAN, expected_redirect(B, &first))]);

    let mut world = World::new(Icmpv4ErrorPolicy::default());
    for flags in [MF | 2, 2] {
        let later = frame(A_MAC, A, B, flags, 64, 17, b"later fragment..");
        let step = world.forward(LAN, &later, 10);
        assert_eq!(step.sent, Some((LAN, forwarded(&later, B_MAC))));
        assert_eq!(
            step.redirect,
            Some(Icmpv4ErrorDisposition::NonInitialFragment)
        );
    }
    assert!(world.generated(10).is_empty());
    assert_eq!(world.counters().queued_redirect, 0);
}

/// An ICMP error A forwards to B through the router gets no Redirect (no
/// error about an error, RFC 1812 §4.3.2.7); an Echo Request does.
#[test]
fn an_icmp_error_never_gets_a_redirect() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let mut unreachable = vec![3, 1, 0, 0, 0, 0, 0, 0];
    unreachable.extend_from_slice(&from_a(B)[14..42]);
    let checksum = sum16(&unreachable);
    unreachable[2..4].copy_from_slice(&checksum.to_be_bytes());
    let error = frame(A_MAC, A, B, DF, 64, 1, &unreachable);
    let step = world.forward(LAN, &error, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&error, B_MAC))));
    assert_eq!(
        step.redirect,
        Some(Icmpv4ErrorDisposition::IcmpErrorMessage)
    );

    let mut echo = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
    let checksum = sum16(&echo);
    echo[2..4].copy_from_slice(&checksum.to_be_bytes());
    let request = frame(A_MAC, A, B, DF, 64, 1, &echo);
    let step = world.forward(LAN, &request, 200);
    assert_eq!(step.redirect, queued(B, &request));
}

/// A datagram sent back to its own source through the router (a route
/// whose next hop is the source) is not a Redirect case: naming the source
/// as its own first hop helps nobody.
#[test]
fn no_redirect_that_names_the_source_itself() {
    let mut world = World::new(Icmpv4ErrorPolicy::default());
    let received = frame(G_MAC, G, BEHIND_G, DF, 64, 17, &udp_payload());
    let step = world.forward(LAN, &received, 10);
    assert_eq!(step.sent, Some((LAN, forwarded(&received, G_MAC))));
    assert_eq!(step.redirect, None);
    assert_eq!(world.counters(), Icmpv4ErrorCounters::default());
}

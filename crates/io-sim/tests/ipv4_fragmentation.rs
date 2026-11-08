//! MTU2 part B (RFC 791 §3.2, RFC 1812 §§4.2.2.7, 5.2.7, NAT44-019L): a
//! forwarded DF-clear datagram above its egress MTU is fragmented, in plain
//! routing, through the NAT (outbound, inbound, hairpin), and for TCP, UDP
//! and ICMP, after every decision and with nothing committed on a refusal.
//!
//! Every expected frame is built here: the whole forwarded datagram from
//! the RFC 791/768/793/792 layouts with recomputed checksums, then cut into
//! fragments by this file's own RFC 791 procedure. The generated NAT ID is
//! taken from the transmitted fragments (they must all carry the same one);
//! the reassembled datagram must equal the expected whole datagram.

mod support;

use ruster_core::{
    execute_one_ipv4_fragmentation, internet_checksum, ConsumeReason, DropReason, FirewallAction,
    FirewallConfig, FirewallHashKey, FirewallInterface, FirewallIpv4Prefix, FirewallPolicy,
    FirewallPortRange, FirewallProtocol, FirewallRule, FirewallRuleId, FirewallRuntime,
    FirewallStateSlot, ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, Ipv4FragmentOutcome,
    Ipv4FragmentSlot, Ipv4FragmentationCounters, Ipv4FragmentationPolicy, Ipv4FragmentationRuntime,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44Filtering, Nat44IcmpConfig,
    Nat44IcmpPolicy, Nat44IcmpRuntime, Nat44TcpConfig, Nat44TcpMappingSlot, Nat44TcpPolicy,
    Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpMappingSlot, Nat44UdpPeerSlot,
    Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, PacketIo, Route,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};
use support::UdpTestIndexes;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const DMZ: IfId = IfId(3);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const DMZ_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 3]);
const H1_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 10]);
const H2_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 11]);
const GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const D_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 30]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const H1: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const H2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
const D: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 50]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const P1: u16 = 40_000;
const P2: u16 = 40_001;
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const UDP: u8 = 17;
const TCP: u8 = 6;
const ICMP: u8 = 1;

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

fn snapshot(lan_mtu: u16, wan_mtu: u16, dmz_mtu: u16) -> ForwardingSnapshot<'static> {
    let routes = leak([
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, DMZ, None).unwrap(),
        Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GW)).unwrap(),
    ]);
    let interfaces = leak([
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
        Interface {
            id: DMZ,
            mac: DMZ_MAC,
            mtu: dmz_mtu,
        },
    ]);
    let neighbors = leak([
        Neighbor {
            interface: LAN,
            target: H1,
            mac: H1_MAC,
        },
        Neighbor {
            interface: LAN,
            target: H2,
            mac: H2_MAC,
        },
        Neighbor {
            interface: WAN,
            target: GW,
            mac: GW_MAC,
        },
        Neighbor {
            interface: DMZ,
            target: D,
            mac: D_MAC,
        },
    ]);
    let bindings = leak([
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
        LocalIpv4Binding {
            interface: DMZ,
            address: Ipv4Address::from_octets([192, 0, 2, 1]),
        },
    ]);
    ForwardingSnapshot::new(&routes[..], &interfaces[..], &neighbors[..], &bindings[..]).unwrap()
}

fn rule(id: u32, protocol: FirewallProtocol, action: FirewallAction) -> FirewallRule {
    let full = FirewallPortRange::new(0, u16::MAX).unwrap();
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(LAN),
        FirewallInterface::Any,
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 8)
            .unwrap()
            .into(),
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0)
            .unwrap()
            .into(),
        protocol,
        full,
        full,
        action,
    )
}

struct Setup {
    lan_mtu: u16,
    wan_mtu: u16,
    dmz_mtu: u16,
    /// `None`: no firewall; `Some(deny_udp)`.
    firewall: Option<bool>,
    policy: Option<Ipv4FragmentationPolicy>,
    datagrams: usize,
    slot_mtu: u16,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            lan_mtu: 1500,
            wan_mtu: 1500,
            dmz_mtu: 1500,
            firewall: None,
            policy: Some(Ipv4FragmentationPolicy::DEFAULT),
            datagrams: 4,
            slot_mtu: 1500,
        }
    }
}

struct World {
    snapshot: ForwardingSnapshot<'static>,
    udp_config: Nat44UdpConfig,
    tcp_config: Nat44TcpConfig,
    icmp_config: Nat44IcmpConfig,
    udp: Nat44UdpRuntime<'static>,
    tcp: Nat44TcpRuntime<'static>,
    icmp: Nat44IcmpRuntime<'static>,
    firewall_config: FirewallConfig<'static>,
    firewall: FirewallRuntime<'static>,
    errors: Icmpv4ErrorRuntime<'static>,
    fragmentation: Option<Ipv4FragmentationRuntime<'static>>,
    io: SimIo,
    trace: VecTrace,
}

/// What one injected batch produced.
#[derive(Debug, Default)]
struct Outcome {
    tx: Vec<(IfId, Vec<u8>)>,
    drops: Vec<DropReason>,
    consumed: Vec<ConsumeReason>,
    fragment_outcomes: Vec<Ipv4FragmentOutcome>,
}

impl World {
    fn new(setup: Setup) -> Self {
        let snapshot = snapshot(setup.lan_mtu, setup.wan_mtu, setup.dmz_mtu);
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            P1,
            P1 + 15,
            Nat44UdpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            P1,
            P1 + 15,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let icmp_config = Nat44IcmpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            P1,
            P1 + 15,
            Nat44IcmpPolicy::default(),
        )
        .unwrap();
        let indexes = leak(UdpTestIndexes::new(udp_config, 4, 8));
        let udp = indexes.runtime(
            udp_config,
            leak([Nat44UdpMappingSlot::default(); 4]),
            leak([Nat44UdpPeerSlot::default(); 8]),
        );
        let tcp = support::tcp_runtime(
            tcp_config,
            leak([Nat44TcpMappingSlot::default(); 4]),
            leak([Nat44TcpSessionSlot::default(); 8]),
        );
        let icmp = support::icmp_runtime(icmp_config, 4, 8);
        // Without a firewall section the tests use an allow-everything rule
        // set, so the firewall still evaluates (and commits) every flow.
        let deny_udp = setup.firewall.unwrap_or(false);
        let udp_action = if deny_udp {
            FirewallAction::Deny
        } else {
            FirewallAction::AllowStateful
        };
        let firewall_config = FirewallConfig::new(
            &snapshot,
            Vec::leak(vec![
                rule(20, FirewallProtocol::Udp, udp_action),
                rule(30, FirewallProtocol::Tcp, FirewallAction::AllowStateful),
                rule(40, FirewallProtocol::Icmp, FirewallAction::AllowStateful),
            ]),
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
        )
        .unwrap();
        let firewall =
            FirewallRuntime::new(firewall_config, leak([FirewallStateSlot::default(); 16]));
        let fragmentation = setup.policy.map(|policy| {
            Ipv4FragmentationRuntime::new(
                policy,
                Vec::leak(vec![Ipv4FragmentSlot::EMPTY; setup.datagrams]),
                Vec::leak(vec![
                    0;
                    setup.datagrams
                        * ruster_core::ipv4_fragment_slot_bytes(
                            setup.slot_mtu
                        )
                ]),
            )
            .unwrap()
        });
        let mut io = SimIo::new();
        io.set_generated_max_frame(14 + 9000);
        Self {
            snapshot,
            udp_config,
            tcp_config,
            icmp_config,
            udp,
            tcp,
            icmp,
            firewall_config,
            firewall,
            errors: Icmpv4ErrorRuntime::new(
                Icmpv4ErrorPolicy::default(),
                leak([Icmpv4ErrorStateSlot::EMPTY; 6]),
                leak([Icmpv4ErrorActionSlot::EMPTY; 6]),
            ),
            fragmentation,
            io,
            trace: VecTrace::default(),
        }
    }

    /// Injects `frames` as one RX batch, then sends every staged datagram
    /// as the generated fragment phase of a tick does.
    fn run(&mut self, frames: &[(IfId, Vec<u8>)]) -> Outcome {
        for (ingress, frame) in frames {
            self.io.inject(*ingress, frame.clone());
        }
        let batch = self.io.receive(frames.len()).unwrap();
        let report = support::forward(
            batch,
            &self.snapshot,
            MonotonicMillis(1_000),
            ruster_core::Services {
                icmpv4_errors: Some(&mut self.errors),
                nat44_udp: (Some(&mut self.udp)).map(|runtime| (&self.udp_config, runtime)),
                nat44_tcp: (Some(&mut self.tcp)).map(|runtime| (&self.tcp_config, runtime)),
                nat44_icmp: (Some((&self.icmp_config, Some(&mut self.icmp))))
                    .and_then(|(config, runtime)| runtime.map(|runtime| (config, runtime))),
                firewall: (Some(&mut self.firewall))
                    .map(|runtime| (&self.firewall_config, runtime)),
                firewall_audit: None,
                fragmentation: self.fragmentation.as_mut(),
                ..ruster_core::Services::default()
            },
            &mut self.trace,
        );
        assert!(report.invariants_hold());
        let mut outcome = Outcome::default();
        while let Some(recycled) = self.io.pop_recycled() {
            match recycled.cause {
                RecycleCause::Forwarding(reason) => outcome.drops.push(reason),
                RecycleCause::Consumed(reason) => outcome.consumed.push(reason),
                other => panic!("unexpected recycle {other:?}"),
            }
        }
        if let Some(runtime) = self.fragmentation.as_mut() {
            while let Some(report) =
                execute_one_ipv4_fragmentation(&mut self.io, runtime, &mut { usize::MAX })
            {
                outcome.fragment_outcomes.push(report.outcome);
            }
            assert_eq!(runtime.pending(), 0);
        }
        while let Some(tx) = self.io.pop_tx() {
            outcome.tx.push((tx.egress, tx.bytes));
        }
        outcome
    }

    fn counters(&self) -> Ipv4FragmentationCounters {
        self.fragmentation.as_ref().unwrap().counters()
    }

    /// UDP mappings, UDP peers, TCP mappings, TCP sessions, ICMP mappings,
    /// firewall states.
    fn state(&self) -> [usize; 6] {
        let udp = self.udp.occupancy();
        let tcp = self.tcp.occupancy();
        [
            udp.mappings.occupied(),
            udp.peers.occupied(),
            tcp.mappings.occupied(),
            tcp.sessions.occupied(),
            self.icmp.occupancy().mappings.occupied(),
            self.firewall.occupancy().occupied(),
        ]
    }
}

// ----------------------------------------------------------- builders ----

/// RFC 1071 checksum, independent of the production helper.
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

/// Ethernet II + RFC 791 header (IHL 5) with a computed checksum.
#[allow(clippy::too_many_arguments)]
fn ipv4_frame(
    macs: (MacAddress, MacAddress),
    source: Ipv4Address,
    destination: Ipv4Address,
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut frame = vec![0_u8; 14 + total];
    frame[0..6].copy_from_slice(&macs.0 .0);
    frame[6..12].copy_from_slice(&macs.1 .0);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&id.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = ttl;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    let checksum = sum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34..].copy_from_slice(payload);
    frame
}

fn pseudo_checksum(
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[0, protocol]);
    bytes.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(segment);
    sum16(&bytes)
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 13 + 7) as u8).collect()
}

fn udp_segment(
    source: Ipv4Address,
    destination: Ipv4Address,
    ports: (u16, u16),
    len: usize,
) -> Vec<u8> {
    let mut segment = vec![0_u8; 8];
    segment[0..2].copy_from_slice(&ports.0.to_be_bytes());
    segment[2..4].copy_from_slice(&ports.1.to_be_bytes());
    segment.extend_from_slice(&data(len));
    let length = u16::try_from(segment.len()).unwrap();
    segment[4..6].copy_from_slice(&length.to_be_bytes());
    let checksum = match pseudo_checksum(source, destination, UDP, &segment) {
        0 => 0xffff,
        checksum => checksum,
    };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// A TCP ACK segment with `len` data bytes.
fn tcp_segment(
    source: Ipv4Address,
    destination: Ipv4Address,
    ports: (u16, u16),
    flags: u8,
    len: usize,
) -> Vec<u8> {
    let mut segment = vec![0_u8; 20];
    segment[0..2].copy_from_slice(&ports.0.to_be_bytes());
    segment[2..4].copy_from_slice(&ports.1.to_be_bytes());
    segment[4..8].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&65_535_u16.to_be_bytes());
    segment.extend_from_slice(&data(len));
    let checksum = pseudo_checksum(source, destination, TCP, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// An ICMP Echo Request (RFC 792) with `len` data bytes.
fn echo_request(identifier: u16, len: usize) -> Vec<u8> {
    let mut message = vec![8, 0, 0, 0];
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&data(len));
    let checksum = sum16(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

/// The fragments of `whole` (a frame with a 20-byte header) for `mtu`, per
/// RFC 791 §3.2: NFB = (MTU - IHL*4) / 8 blocks in every fragment but the
/// last, MF on all but the last (which keeps the datagram's MF), offsets in
/// 8-byte units from the datagram's offset, a fresh header checksum.
fn rfc791_fragments(whole: &[u8], mtu: u16) -> Vec<Vec<u8>> {
    let nfb = (usize::from(mtu) - 20) / 8;
    let total = usize::from(u16::from_be_bytes([whole[16], whole[17]]));
    let word = u16::from_be_bytes([whole[20], whole[21]]);
    let mut fragments = Vec::new();
    let mut start = 0;
    let data_len = total - 20;
    while start < data_len {
        let len = (nfb * 8).min(data_len - start);
        let last = start + len == data_len;
        let mut frame = whole[..34].to_vec();
        let offset = (word & 0x1fff) + u16::try_from(start / 8).unwrap();
        let more = if last { word & MF } else { MF };
        let flags = (word & 0x8000) | more | offset;
        frame[16..18].copy_from_slice(&u16::try_from(20 + len).unwrap().to_be_bytes());
        frame[20..22].copy_from_slice(&flags.to_be_bytes());
        frame[24..26].fill(0);
        let checksum = sum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&whole[34 + start..34 + start + len]);
        fragments.push(frame);
        start += len;
    }
    fragments
}

/// Reassembles fragments (in order) into the whole frame: data in offset
/// order, the first fragment's header with the datagram's length.
fn reassemble(fragments: &[Vec<u8>]) -> Vec<u8> {
    let mut whole = fragments[0][..34].to_vec();
    for fragment in fragments {
        let offset = usize::from(u16::from_be_bytes([fragment[20], fragment[21]]) & 0x1fff) * 8;
        let base =
            usize::from(u16::from_be_bytes([fragments[0][20], fragments[0][21]]) & 0x1fff) * 8;
        assert_eq!(34 + offset - base, whole.len(), "contiguous fragments");
        whole.extend_from_slice(&fragment[34..]);
    }
    let total = u16::try_from(whole.len() - 14).unwrap();
    whole[16..18].copy_from_slice(&total.to_be_bytes());
    let word = u16::from_be_bytes([fragments.last().unwrap()[20], fragments.last().unwrap()[21]]);
    let first = u16::from_be_bytes([fragments[0][20], fragments[0][21]]);
    whole[20..22].copy_from_slice(&((first & 0x9fff & !MF) | (word & MF)).to_be_bytes());
    whole[24..26].fill(0);
    let checksum = sum16(&whole[14..34]);
    whole[24..26].copy_from_slice(&checksum.to_be_bytes());
    whole
}

fn id_of(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[18], frame[19]])
}

fn frames_to(outcome: &Outcome, egress: IfId) -> Vec<Vec<u8>> {
    assert!(
        outcome.tx.iter().all(|(out, _)| *out == egress),
        "{:?}",
        outcome.tx.iter().map(|t| t.0).collect::<Vec<_>>()
    );
    outcome.tx.iter().map(|(_, bytes)| bytes.clone()).collect()
}

/// Checks the RFC 791 invariants of every fragment of one set.
fn assert_fragment_set(fragments: &[Vec<u8>], mtu: u16) {
    assert!(fragments.len() >= 2);
    let id = id_of(&fragments[0]);
    for (index, fragment) in fragments.iter().enumerate() {
        let total = usize::from(u16::from_be_bytes([fragment[16], fragment[17]]));
        assert_eq!(fragment.len(), 14 + total, "no padding");
        assert!(total <= usize::from(mtu), "fragment {index} within the MTU");
        assert_eq!(sum16(&fragment[14..34]), 0, "header checksum");
        assert_eq!(id_of(fragment), id, "one ID");
        let word = u16::from_be_bytes([fragment[20], fragment[21]]);
        assert_eq!(word & DF, 0);
        if index + 1 < fragments.len() {
            assert_eq!(word & MF, MF);
            assert_eq!((total - 20) % 8, 0, "8-byte multiple");
        }
    }
}

// -------------------------------------------------------------- tests ----

#[test]
fn plain_routing_fragments_a_df_clear_datagram_exactly() {
    // LAN -> DMZ is not translated. 1500 bytes into a 576-byte DMZ.
    let mut world = World::new(Setup {
        dmz_mtu: 576,
        ..Setup::default()
    });
    let segment = udp_segment(H1, D, (5000, 53), 1472);
    let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, D, 0x4242, 0, 64, UDP, &segment);
    assert_eq!(sent.len(), 14 + 1500);
    let outcome = world.run(&[(LAN, sent)]);
    assert_eq!(outcome.consumed, [ConsumeReason::Ipv4Fragmented]);
    assert!(outcome.drops.is_empty());
    assert_eq!(outcome.fragment_outcomes, [Ipv4FragmentOutcome::Sent]);
    let forwarded = ipv4_frame((D_MAC, DMZ_MAC), H1, D, 0x4242, 0, 63, UDP, &segment);
    let fragments = frames_to(&outcome, DMZ);
    assert_eq!(fragments, rfc791_fragments(&forwarded, 576));
    assert_eq!(fragments.len(), 3);
    assert_fragment_set(&fragments, 576);
    assert_eq!(reassemble(&fragments), forwarded);
    // The ID is the source's: no NAT, no rewrite.
    assert_eq!(id_of(&fragments[0]), 0x4242);
    assert_eq!(
        world.counters(),
        Ipv4FragmentationCounters {
            queued: 1,
            fragmented: 1,
            fragments: 3,
            ..Ipv4FragmentationCounters::default()
        }
    );
}

#[test]
fn the_exact_mtu_is_forwarded_whole_and_one_byte_more_is_fragmented() {
    let mut world = World::new(Setup {
        dmz_mtu: 1280,
        ..Setup::default()
    });
    let exact = udp_segment(H1, D, (5000, 53), 1280 - 28);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, D, 1, 0, 64, UDP, &exact),
    )]);
    assert!(outcome.consumed.is_empty());
    assert_eq!(
        frames_to(&outcome, DMZ),
        [ipv4_frame((D_MAC, DMZ_MAC), H1, D, 1, 0, 63, UDP, &exact)]
    );
    let over = udp_segment(H1, D, (5000, 53), 1280 - 27);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, D, 2, 0, 64, UDP, &over),
    )]);
    let forwarded = ipv4_frame((D_MAC, DMZ_MAC), H1, D, 2, 0, 63, UDP, &over);
    let fragments = frames_to(&outcome, DMZ);
    assert_eq!(fragments, rfc791_fragments(&forwarded, 1280));
    // 1256 data bytes, then the last 1 + 8 - 8... 1261 - 1256 = 5 bytes.
    assert_eq!(fragments.len(), 2);
    assert_eq!(fragments[1].len(), 14 + 20 + 5);
}

/// Without the fragment association table (this composition, or `[fragment-
/// tracking] mode = "refuse"`) the stateful firewall refuses every fragment
/// before any decision (FIREWALL_FRAGMENT_UNSUPPORTED), so a received
/// fragment (also an overlong one) never reaches fragmentation; with the
/// table it does and is re-fragmented (crates/io-sim/tests/nat_frag.rs).
#[test]
fn received_fragments_are_refused_by_the_firewall_before_fragmentation() {
    let mut world = World::new(Setup {
        dmz_mtu: 576,
        ..Setup::default()
    });
    for word in [MF | 185, 185, MF | 8150] {
        let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, D, 0x5555, word, 64, UDP, &data(1200));
        let outcome = world.run(&[(LAN, sent)]);
        assert_eq!(outcome.drops, [DropReason::FirewallFragmentUnsupported]);
        assert!(outcome.tx.is_empty() && outcome.consumed.is_empty());
    }
    assert_eq!(world.counters(), Ipv4FragmentationCounters::default());
}

#[test]
fn nat_outbound_udp_tcp_and_icmp_are_fragmented_after_translation() {
    let mut world = World::new(Setup {
        wan_mtu: 1400,
        ..Setup::default()
    });
    // UDP: 1500 bytes, DF clear, through the NAT.
    let segment = udp_segment(H1, REMOTE, (P1, 53), 1472);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x1111, 0, 64, UDP, &segment),
    )]);
    let fragments = frames_to(&outcome, WAN);
    assert_fragment_set(&fragments, 1400);
    let id = id_of(&fragments[0]);
    let translated = udp_segment(PUBLIC, REMOTE, (P1, 53), 1472);
    let forwarded = ipv4_frame(
        (GW_MAC, WAN_MAC),
        PUBLIC,
        REMOTE,
        id,
        0,
        63,
        UDP,
        &translated,
    );
    assert_eq!(fragments, rfc791_fragments(&forwarded, 1400));
    assert_eq!(reassemble(&fragments), forwarded);
    assert_eq!(
        world.state()[..2],
        [1, 1],
        "mapping and peer committed once"
    );

    // TCP: a 1500-byte ACK segment of an established-looking flow (the
    // SYN first creates the session).
    let syn = tcp_segment(H1, REMOTE, (P1, 443), 0x02, 0);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, DF, 64, TCP, &syn),
    )]);
    assert_eq!(outcome.tx.len(), 1);
    let ack = tcp_segment(H1, REMOTE, (P1, 443), 0x10, 1460);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x2222, 0, 64, TCP, &ack),
    )]);
    let fragments = frames_to(&outcome, WAN);
    assert_fragment_set(&fragments, 1400);
    let tcp_id = id_of(&fragments[0]);
    let translated = tcp_segment(PUBLIC, REMOTE, (P1, 443), 0x10, 1460);
    let forwarded = ipv4_frame(
        (GW_MAC, WAN_MAC),
        PUBLIC,
        REMOTE,
        tcp_id,
        0,
        63,
        TCP,
        &translated,
    );
    assert_eq!(fragments, rfc791_fragments(&forwarded, 1400));

    // ICMP Echo Request: 1500 bytes, DF clear (Windows ping -l 1472).
    let request = echo_request(0x0101, 1472);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x3333, 0, 64, ICMP, &request),
    )]);
    let fragments = frames_to(&outcome, WAN);
    assert_fragment_set(&fragments, 1400);
    let whole = reassemble(&fragments);
    assert_eq!(
        &whole[26..34],
        &[PUBLIC.octets(), REMOTE.octets()].concat()[..]
    );
    assert_eq!(whole[34], 8);
    assert_eq!(
        sum16(&whole[34..]),
        0,
        "ICMP checksum of the translated query"
    );
    assert_eq!(&whole[42..], &data(1472)[..]);
    assert_eq!(world.state()[4], 1, "query mapping committed");
    assert_eq!(world.counters().fragmented, 3);
}

#[test]
fn nat_inbound_is_fragmented_toward_a_smaller_lan() {
    let mut world = World::new(Setup {
        lan_mtu: 1280,
        ..Setup::default()
    });
    let query = udp_segment(H1, REMOTE, (P1, 53), 8);
    world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, DF, 64, UDP, &query),
    )]);
    // A 1500-byte DF-clear reply to the public address.
    let reply = udp_segment(REMOTE, PUBLIC, (53, P1), 1472);
    let outcome = world.run(&[(
        WAN,
        ipv4_frame(
            (WAN_MAC, GW_MAC),
            REMOTE,
            PUBLIC,
            0x6666,
            0,
            64,
            UDP,
            &reply,
        ),
    )]);
    let fragments = frames_to(&outcome, LAN);
    assert_fragment_set(&fragments, 1280);
    // RFC 6864 §5.3.1: the translated datagram's ID is generated (inbound
    // array) and every fragment carries it.
    let id = id_of(&fragments[0]);
    let translated = udp_segment(REMOTE, H1, (53, P1), 1472);
    let forwarded = ipv4_frame((H1_MAC, LAN_MAC), REMOTE, H1, id, 0, 63, UDP, &translated);
    assert_eq!(fragments, rfc791_fragments(&forwarded, 1280));
    assert_eq!(reassemble(&fragments), forwarded);
    // The next inbound datagram of the tuple gets the next ID.
    let outcome = world.run(&[(
        WAN,
        ipv4_frame(
            (WAN_MAC, GW_MAC),
            REMOTE,
            PUBLIC,
            0x6666,
            0,
            64,
            UDP,
            &reply,
        ),
    )]);
    let again = frames_to(&outcome, LAN);
    assert!(again.iter().all(|f| id_of(f) == id.wrapping_add(1)));
}

#[test]
fn hairpin_is_fragmented_toward_the_inside_mtu() {
    let mut world = World::new(Setup {
        lan_mtu: 1000,
        ..Setup::default()
    });
    // H2's mapping PUBLIC:P2, then the hole punching exchange the firewall
    // needs (H1 -> H2 is refused until H2 has sent to H1's endpoint).
    let open = udp_segment(H2, REMOTE, (P2, 53), 8);
    world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H2_MAC), H2, REMOTE, 1, DF, 64, UDP, &open),
    )]);
    let punch = udp_segment(H1, PUBLIC, (P1, P2), 8);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, PUBLIC, 2, DF, 64, UDP, &punch),
    )]);
    assert_eq!(outcome.drops, [DropReason::FirewallDefaultDenied]);
    let reply = udp_segment(H2, PUBLIC, (P2, P1), 8);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H2_MAC), H2, PUBLIC, 3, DF, 64, UDP, &reply),
    )]);
    assert_eq!(frames_to(&outcome, LAN).len(), 1);
    let segment = udp_segment(H1, PUBLIC, (P1, P2), 1400);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, PUBLIC, 0x7777, 0, 64, UDP, &segment),
    )]);
    let fragments = frames_to(&outcome, LAN);
    assert_fragment_set(&fragments, 1000);
    let id = id_of(&fragments[0]);
    let translated = udp_segment(PUBLIC, H2, (P1, P2), 1400);
    let forwarded = ipv4_frame((H2_MAC, LAN_MAC), PUBLIC, H2, id, 0, 63, UDP, &translated);
    assert_eq!(fragments, rfc791_fragments(&forwarded, 1000));
}

#[test]
fn a_translated_icmp_error_above_the_lan_mtu_is_fragmented() {
    let mut world = World::new(Setup {
        lan_mtu: 576,
        ..Setup::default()
    });
    let query = udp_segment(H1, REMOTE, (P1, 53), 1000);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &query),
    )]);
    let out = frames_to(&outcome, WAN).remove(0);
    // A DF-clear Time Exceeded quoting 600 bytes of the translated datagram
    // (more than RFC 1812's 576 cap, as some routers send).
    let mut icmp = vec![11, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&out[14..14 + 600]);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let router = Ipv4Address::from_octets([198, 51, 100, 1]);
    let error = ipv4_frame(
        (WAN_MAC, GW_MAC),
        router,
        PUBLIC,
        0x7777,
        0,
        64,
        ICMP,
        &icmp,
    );
    let outcome = world.run(&[(WAN, error)]);
    let fragments = frames_to(&outcome, LAN);
    assert_fragment_set(&fragments, 576);
    let whole = reassemble(&fragments);
    assert_eq!(whole.len(), 14 + 20 + 608);
    assert_eq!(&whole[30..34], &H1.octets(), "outer destination translated");
    assert_eq!(
        sum16(&whole[34..]),
        0,
        "ICMP checksum over the whole message"
    );
    assert_eq!(
        &whole[42 + 12..42 + 16],
        &H1.octets(),
        "quoted source reverted"
    );
}

#[test]
fn the_bound_refuses_the_whole_datagram_and_commits_nothing() {
    let mut world = World::new(Setup {
        wan_mtu: 576,
        policy: Some(Ipv4FragmentationPolicy::new(true, 2).unwrap()),
        ..Setup::default()
    });
    let segment = udp_segment(H1, REMOTE, (P1, 53), 1472);
    let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &segment);
    let outcome = world.run(&[(LAN, sent)]);
    assert_eq!(
        outcome.drops,
        [DropReason::Ipv4FragmentationTooManyFragments]
    );
    assert!(outcome.tx.is_empty() && outcome.consumed.is_empty());
    assert_eq!(world.state(), [0; 6], "no mapping, peer, or firewall state");
    assert_eq!(world.counters(), Ipv4FragmentationCounters::default());
    // Exactly two fragments are within the bound.
    let fits = udp_segment(H1, REMOTE, (P1, 53), 1000);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &fits),
    )]);
    assert_eq!(frames_to(&outcome, WAN).len(), 2);
    // The refused datagram took no ID: the first sent one has the ID a
    // fresh world gives its first DF-clear datagram of the tuple.
    let mut fresh = World::new(Setup {
        wan_mtu: 576,
        ..Setup::default()
    });
    let fresh_out = fresh.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &fits),
    )]);
    assert_eq!(id_of(&outcome.tx[0].1), id_of(&fresh_out.tx[0].1));
}

#[test]
fn a_full_slot_table_refuses_the_whole_datagram_and_commits_nothing() {
    let mut world = World::new(Setup {
        wan_mtu: 576,
        datagrams: 1,
        ..Setup::default()
    });
    let first = udp_segment(H1, REMOTE, (P1, 53), 1000);
    let second = udp_segment(H2, REMOTE, (P2, 53), 1000);
    let outcome = world.run(&[
        (
            LAN,
            ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &first),
        ),
        (
            LAN,
            ipv4_frame((LAN_MAC, H2_MAC), H2, REMOTE, 2, 0, 64, UDP, &second),
        ),
    ]);
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentationQueueFull]);
    assert_eq!(outcome.consumed, [ConsumeReason::Ipv4Fragmented]);
    let fragments = frames_to(&outcome, WAN);
    assert_eq!(fragments.len(), 2);
    assert!(fragments.iter().all(|f| f[26..30] == PUBLIC.octets()));
    // Only H1's mapping, peer, and firewall state exist.
    assert_eq!(world.state(), [1, 1, 0, 0, 0, 1]);
    // The slot is free again in the next batch.
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H2_MAC), H2, REMOTE, 2, 0, 64, UDP, &second),
    )]);
    assert_eq!(frames_to(&outcome, WAN).len(), 2);
}

#[test]
fn a_datagram_longer_than_a_slot_is_refused_whole() {
    // Slots hold 1500-byte datagrams; the LAN device delivered 1600.
    let mut world = World::new(Setup {
        lan_mtu: 1600,
        wan_mtu: 576,
        ..Setup::default()
    });
    let segment = udp_segment(H1, REMOTE, (P1, 53), 1572);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &segment),
    )]);
    assert_eq!(
        outcome.drops,
        [DropReason::Ipv4FragmentationDatagramTooLarge]
    );
    assert_eq!(world.state(), [0; 6]);
}

#[test]
fn no_room_for_the_whole_set_sends_nothing() {
    let mut world = World::new(Setup {
        wan_mtu: 576,
        ..Setup::default()
    });
    world.io.set_generated_budget(2);
    let segment = udp_segment(H1, REMOTE, (P1, 53), 1472);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &segment),
    )]);
    assert_eq!(outcome.consumed, [ConsumeReason::Ipv4Fragmented]);
    assert_eq!(
        outcome.fragment_outcomes,
        [Ipv4FragmentOutcome::Refused(
            ruster_core::GeneratedAllocationError::Unavailable
        )]
    );
    assert!(outcome.tx.is_empty(), "no partial fragment set");
    assert_eq!(world.counters().dropped_unavailable, 1);
    // The TX accept budget is part of the room too.
    world.io.set_generated_budget(usize::MAX);
    world.io.set_generated_accept_budget(2);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 2, 0, 64, UDP, &segment),
    )]);
    assert!(outcome.tx.is_empty());
    assert_eq!(world.counters().dropped_unavailable, 2);
    world.io.set_generated_accept_budget(3);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 3, 0, 64, UDP, &segment),
    )]);
    assert_eq!(frames_to(&outcome, WAN).len(), 3);
}

#[test]
fn the_firewall_decides_first_and_a_refusal_commits_nothing() {
    let mut world = World::new(Setup {
        wan_mtu: 576,
        firewall: Some(true),
        ..Setup::default()
    });
    let segment = udp_segment(H1, REMOTE, (P1, 53), 1472);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &segment),
    )]);
    assert_eq!(outcome.drops.len(), 1);
    assert!(
        matches!(
            outcome.drops[0],
            DropReason::FirewallRuleDenied | DropReason::FirewallDefaultDenied
        ),
        "{:?}",
        outcome.drops
    );
    assert!(outcome.tx.is_empty() && outcome.consumed.is_empty());
    assert_eq!(world.state(), [0; 6]);
    assert_eq!(world.counters(), Ipv4FragmentationCounters::default());
}

#[test]
fn the_off_switch_keeps_fragmentation_required() {
    for policy in [
        Some(Ipv4FragmentationPolicy::new(false, 1365).unwrap()),
        None,
    ] {
        let mut world = World::new(Setup {
            wan_mtu: 576,
            policy,
            ..Setup::default()
        });
        let segment = udp_segment(H1, REMOTE, (P1, 53), 1472);
        let outcome = world.run(&[(
            LAN,
            ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, 0, 64, UDP, &segment),
        )]);
        assert_eq!(outcome.drops, [DropReason::Ipv4FragmentationRequired]);
        assert!(outcome.tx.is_empty());
        assert_eq!(world.state(), [0; 6]);
        // DF still yields Fragmentation Needed, never fragments.
        let outcome = world.run(&[(
            LAN,
            ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, DF, 64, UDP, &segment),
        )]);
        assert_eq!(outcome.drops, [DropReason::Ipv4FragmentationNeeded]);
    }
}

#[test]
fn df_datagrams_are_never_fragmented() {
    let mut world = World::new(Setup {
        wan_mtu: 576,
        ..Setup::default()
    });
    let segment = udp_segment(H1, REMOTE, (P1, 53), 1472);
    let outcome = world.run(&[(
        LAN,
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 1, DF, 64, UDP, &segment),
    )]);
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentationNeeded]);
    assert!(outcome.tx.is_empty() && outcome.consumed.is_empty());
    assert_eq!(world.counters().queued, 0);
}

/// SimIo's `check_capacity` (IO-014): room is the smaller of the session's
/// allocation budget and its accept budget left, lengths up to the maximum
/// frame, exactly at each bound.
#[test]
fn sim_check_capacity_is_exact_at_every_bound() {
    use ruster_core::{GeneratedAllocationError, GeneratedPacketBatch, GeneratedPacketIo};
    let mut io = SimIo::new();
    io.set_generated_max_frame(100);
    io.set_generated_budget(3);
    io.set_generated_accept_budget(4);
    let mut batch = io.begin_generated(WAN);
    assert_eq!(batch.check_capacity(0, 0), Ok(()));
    assert_eq!(
        batch.check_capacity(1, 0),
        Err(GeneratedAllocationError::ZeroLength)
    );
    assert_eq!(batch.check_capacity(3, 100), Ok(()));
    assert_eq!(
        batch.check_capacity(3, 101),
        Err(GeneratedAllocationError::FrameTooLarge)
    );
    assert_eq!(
        batch.check_capacity(4, 100),
        Err(GeneratedAllocationError::Unavailable),
        "allocation budget"
    );
    batch.allocate(60).unwrap().commit();
    assert_eq!(batch.check_capacity(2, 100), Ok(()));
    assert_eq!(
        batch.check_capacity(3, 100),
        Err(GeneratedAllocationError::Unavailable)
    );
    let completion = batch.finish();
    assert_eq!((completion.attempts, completion.accepted), (1, 1));
    // The accept budget binds when it is the smaller one.
    io.set_generated_budget(10);
    io.set_generated_accept_budget(2);
    let mut batch = io.begin_generated(WAN);
    assert_eq!(batch.check_capacity(2, 100), Ok(()));
    batch.allocate(60).unwrap().commit();
    assert_eq!(batch.check_capacity(1, 100), Ok(()));
    assert_eq!(
        batch.check_capacity(2, 100),
        Err(GeneratedAllocationError::Unavailable),
        "accept budget"
    );
    let _ = batch.finish();
}

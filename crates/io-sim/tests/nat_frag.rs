//! NAT-FRAG (RFC 4787 REQ-14, RFC 5382 §5, RFC 5508 §5, RFC 1858,
//! RFC 3128, RFC 6864 §5.3.1, RFC 791 §3.2): fragments of one datagram
//! through the stateful firewall and the NAT, in order and out of order.
//!
//! Every expected frame is built here, independently of the router: the
//! whole datagram as the router would forward it (RFC 791/768/793/792
//! layouts, checksums recomputed from scratch with the translated
//! addresses and ports), then cut by this file's own RFC 791 procedure at
//! the same boundaries the sender used. The generated NAT ID is read from
//! the transmitted fragments; every fragment of one datagram must carry
//! that one ID, and the reassembled output must equal the expected whole
//! datagram, which checks the incrementally updated transport checksum of
//! the first fragment.

mod support;

use ruster_core::{
    execute_one_ipv4_fragmentation,
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragment_tracking,
    ipv4_fragment_slot_bytes, ipv4_fragment_tracking_buckets, ipv4_fragment_tracking_tombstones,
    ConsumeReason, DirectoryBucket, DirectoryNode, DropReason, FirewallAction, FirewallConfig,
    FirewallHashKey, FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange,
    FirewallProtocol, FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot,
    ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime,
    Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, Ipv4FragmentEntrySlot,
    Ipv4FragmentHeldSlot, Ipv4FragmentHostSlot, Ipv4FragmentSlot, Ipv4FragmentTombstoneSlot,
    Ipv4FragmentTracker, Ipv4FragmentTrackingCounters, Ipv4FragmentTrackingPolicy,
    Ipv4FragmentTrackingStorage, Ipv4FragmentationPolicy, Ipv4FragmentationRuntime,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44Filtering, Nat44IcmpConfig,
    Nat44IcmpPolicy, Nat44IcmpRuntime, Nat44TcpConfig, Nat44TcpMappingSlot, Nat44TcpPolicy,
    Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpMappingSlot, Nat44UdpPeerSlot,
    Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, PacketIo, ResolutionActionSlot, ResolutionHashKey,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
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
const LAN_ADDRESS: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const H1: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const H2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
const D: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 50]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const P1: u16 = 40_000;
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const UDP: u8 = 17;
const TCP: u8 = 6;
const ICMP: u8 = 1;
const NOW: u64 = 1_000;

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

fn snapshot(wan_mtu: u16, dmz_mtu: u16) -> ForwardingSnapshot<'static> {
    let routes = leak([
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, DMZ, None).unwrap(),
        Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GW)).unwrap(),
    ]);
    let interfaces = leak([
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: 1500,
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
            address: LAN_ADDRESS,
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
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 8).unwrap(),
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap(),
        protocol,
        full,
        full,
        action,
    )
}

struct Setup {
    wan_mtu: u16,
    dmz_mtu: u16,
    deny_udp: bool,
    /// `None`: the `refuse` mode (no association table).
    tracking: Option<Ipv4FragmentTrackingPolicy>,
    entries: usize,
    held: usize,
    fragmentation_slots: usize,
    /// ICMP query NAT in the composition.
    icmp_nat: bool,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            wan_mtu: 1500,
            dmz_mtu: 1500,
            deny_udp: false,
            tracking: Some(Ipv4FragmentTrackingPolicy::new(5_000, 32, 16).unwrap()),
            entries: 16,
            held: 8,
            fragmentation_slots: 16,
            icmp_nat: true,
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
    resolution: ResolutionRuntime<'static>,
    errors: Icmpv4ErrorRuntime<'static>,
    fragmentation: Ipv4FragmentationRuntime<'static>,
    tracker: Option<Ipv4FragmentTracker<'static>>,
    icmp_nat: bool,
    io: SimIo,
    trace: VecTrace,
}

#[derive(Debug, Default)]
struct Outcome {
    tx: Vec<(IfId, Vec<u8>)>,
    drops: Vec<DropReason>,
    consumed: Vec<ConsumeReason>,
}

fn tracker(
    policy: Ipv4FragmentTrackingPolicy,
    entries: usize,
    held: usize,
) -> Ipv4FragmentTracker<'static> {
    let buckets = ipv4_fragment_tracking_buckets(entries);
    let tombstones = ipv4_fragment_tracking_tombstones(entries);
    Ipv4FragmentTracker::new(
        policy,
        Ipv4FragmentTrackingStorage {
            entries: Vec::leak(vec![Ipv4FragmentEntrySlot::EMPTY; entries]),
            entry_buckets: Vec::leak(vec![DirectoryBucket::default(); buckets]),
            entry_nodes: Vec::leak(vec![DirectoryNode::default(); entries]),
            hosts: Vec::leak(vec![Ipv4FragmentHostSlot::EMPTY; entries]),
            host_buckets: Vec::leak(vec![DirectoryBucket::default(); buckets]),
            host_nodes: Vec::leak(vec![DirectoryNode::default(); entries]),
            tombstones: Vec::leak(vec![Ipv4FragmentTombstoneSlot::EMPTY; tombstones]),
            tombstone_buckets: Vec::leak(vec![
                DirectoryBucket::default();
                ipv4_fragment_tracking_buckets(tombstones)
            ]),
            tombstone_nodes: Vec::leak(vec![DirectoryNode::default(); tombstones]),
            held: Vec::leak(vec![Ipv4FragmentHeldSlot::EMPTY; held]),
            held_bytes: Vec::leak(vec![0; held * ipv4_fragment_slot_bytes(1500)]),
        },
        ResolutionHashKey::new(0x1111, 0x2222).unwrap(),
    )
    .unwrap()
}

impl World {
    fn new(setup: Setup) -> Self {
        let snapshot = snapshot(setup.wan_mtu, setup.dmz_mtu);
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
            // Endpoint-independent, so an inside host can open a hairpinned
            // TCP connection to another's mapping.
            Nat44TcpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent),
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
        let udp_action = if setup.deny_udp {
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
        let slots = setup.fragmentation_slots;
        let fragmentation = Ipv4FragmentationRuntime::new(
            Ipv4FragmentationPolicy::DEFAULT,
            Vec::leak(vec![Ipv4FragmentSlot::EMPTY; slots]),
            Vec::leak(vec![0; slots * ipv4_fragment_slot_bytes(1500)]),
        )
        .unwrap();
        let mut io = SimIo::new();
        io.set_generated_max_frame(14 + 1500);
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
            resolution: ResolutionRuntime::new(
                ResolutionPolicy::new(1_000, 2_000).unwrap(),
                leak([ResolutionStateSlot::EMPTY; 2]),
                leak([ResolutionActionSlot::EMPTY; 2]),
            ),
            errors: Icmpv4ErrorRuntime::new(
                Icmpv4ErrorPolicy::default(),
                leak([Icmpv4ErrorStateSlot::EMPTY; 6]),
                leak([Icmpv4ErrorActionSlot::EMPTY; 6]),
            ),
            fragmentation,
            tracker: setup
                .tracking
                .map(|policy| tracker(policy, setup.entries, setup.held)),
            icmp_nat: setup.icmp_nat,
            io,
            trace: VecTrace::default(),
        }
    }

    /// Injects `frames` as one RX batch at `now`, then sends every staged
    /// datagram (re-fragmented or released) as the tick's generated
    /// fragment phase does.
    fn run_at(&mut self, now: u64, frames: &[(IfId, Vec<u8>)]) -> Outcome {
        for (ingress, frame) in frames {
            self.io.inject(*ingress, frame.clone());
        }
        let batch = self.io.receive(frames.len()).unwrap();
        let report =
            forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragment_tracking(
                batch,
                &self.snapshot,
                &mut self.resolution,
                &mut self.errors,
                &self.udp_config,
                Some(&mut self.udp),
                &self.tcp_config,
                Some(&mut self.tcp),
                self.icmp_nat
                    .then_some((&self.icmp_config, Some(&mut self.icmp))),
                &self.firewall_config,
                Some(&mut self.firewall),
                None,
                Some(&mut self.fragmentation),
                self.tracker.as_mut(),
                MonotonicMillis(now),
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
        while let Some(report) =
            execute_one_ipv4_fragmentation(&mut self.io, &mut self.fragmentation, &mut { 64 })
        {
            assert_eq!(report.outcome, ruster_core::Ipv4FragmentOutcome::Sent);
        }
        while let Some(tx) = self.io.pop_tx() {
            outcome.tx.push((tx.egress, tx.bytes));
        }
        outcome
    }

    fn run(&mut self, frames: &[(IfId, Vec<u8>)]) -> Outcome {
        self.run_at(NOW, frames)
    }

    fn counters(&self) -> Ipv4FragmentTrackingCounters {
        self.tracker.as_ref().unwrap().counters()
    }

    /// Live association entries and held fragments.
    fn occupancy(&self) -> (usize, usize) {
        let tracker = self.tracker.as_ref().unwrap();
        (tracker.entries(), tracker.held())
    }

    /// UDP mappings, TCP sessions, ICMP mappings, firewall states.
    fn state(&self) -> [usize; 4] {
        [
            self.udp.occupancy().mappings.occupied(),
            self.tcp.occupancy().sessions.occupied(),
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

/// A TCP segment with `options` (a multiple of 4 bytes) and `len` data
/// bytes.
fn tcp_segment(
    source: Ipv4Address,
    destination: Ipv4Address,
    ports: (u16, u16),
    flags: u8,
    options: usize,
    len: usize,
) -> Vec<u8> {
    let header = 20 + options;
    let mut segment = vec![0_u8; header];
    segment[0..2].copy_from_slice(&ports.0.to_be_bytes());
    segment[2..4].copy_from_slice(&ports.1.to_be_bytes());
    segment[4..8].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    segment[12] = u8::try_from(header / 4).unwrap() << 4;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&65_535_u16.to_be_bytes());
    // NOP options.
    segment[20..].fill(1);
    segment.extend_from_slice(&data(len));
    let checksum = pseudo_checksum(source, destination, TCP, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// An ICMP Echo message (RFC 792) with `len` data bytes.
fn echo(icmp_type: u8, identifier: u16, len: usize) -> Vec<u8> {
    let mut message = vec![icmp_type, 0, 0, 0];
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&data(len));
    let checksum = sum16(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

/// Cuts the whole datagram `whole` (20-byte header, MF clear, offset 0)
/// into fragments carrying `sizes` data bytes each, in order, as a sending
/// host does (RFC 791 §3.2): one ID, MF on all but the last, offsets in
/// 8-byte units, a fresh header checksum. `sizes` but the last are
/// multiples of 8 and sum to the datagram's data.
fn cut(whole: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let data_len = whole.len() - 34;
    assert_eq!(sizes.iter().sum::<usize>(), data_len);
    let word = u16::from_be_bytes([whole[20], whole[21]]);
    let mut start = 0;
    sizes
        .iter()
        .enumerate()
        .map(|(index, &len)| {
            let last = index + 1 == sizes.len();
            assert!(last || len % 8 == 0);
            let mut frame = whole[..34].to_vec();
            let more = if last { 0 } else { MF };
            let flags = (word & DF) | more | u16::try_from(start / 8).unwrap();
            frame[16..18].copy_from_slice(&u16::try_from(20 + len).unwrap().to_be_bytes());
            frame[20..22].copy_from_slice(&flags.to_be_bytes());
            frame[24..26].fill(0);
            let checksum = sum16(&frame[14..34]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            frame.extend_from_slice(&whole[34 + start..34 + start + len]);
            start += len;
            frame
        })
        .collect()
}

/// Reassembles fragments in any order into the whole frame (RFC 791 §3.2):
/// data by offset, the first fragment's header with MF and offset clear.
fn reassemble(fragments: &[Vec<u8>]) -> Vec<u8> {
    let offset = |frame: &Vec<u8>| u16::from_be_bytes([frame[20], frame[21]]) & 0x1fff;
    let mut sorted = fragments.to_vec();
    sorted.sort_by_key(offset);
    let mut whole = sorted[0][..34].to_vec();
    for fragment in &sorted {
        assert_eq!(
            34 + usize::from(offset(fragment)) * 8,
            whole.len(),
            "contiguous"
        );
        whole.extend_from_slice(&fragment[34..]);
    }
    let last = u16::from_be_bytes([sorted.last().unwrap()[20], sorted.last().unwrap()[21]]);
    assert_eq!(last & MF, 0, "the last fragment ends the datagram");
    let total = u16::try_from(whole.len() - 14).unwrap();
    whole[16..18].copy_from_slice(&total.to_be_bytes());
    let word = u16::from_be_bytes([whole[20], whole[21]]) & DF;
    whole[20..22].copy_from_slice(&word.to_be_bytes());
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

/// Every fragment carries one ID and a valid header checksum; returns it.
fn one_id(fragments: &[Vec<u8>]) -> u16 {
    let id = id_of(&fragments[0]);
    for fragment in fragments {
        assert_eq!(id_of(fragment), id, "one ID for the whole datagram");
        assert_eq!(sum16(&fragment[14..34]), 0, "header checksum");
    }
    id
}

fn sorted(mut frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    frames.sort();
    frames
}

/// A 3000-byte UDP datagram from H1 to REMOTE:53 as host fragments of
/// 1480 + 1480 + 20 data bytes (an Ethernet sender's cut).
const SIZES: [usize; 3] = [1480, 1480, 20];
const UDP_DATA: usize = 2980 - 8;

fn outbound_udp(id: u16) -> (Vec<Vec<u8>>, Vec<u8>) {
    let segment = udp_segment(H1, REMOTE, (P1, 53), UDP_DATA);
    let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, id, 0, 64, UDP, &segment);
    let translated = udp_segment(PUBLIC, REMOTE, (P1, 53), UDP_DATA);
    // The ID is a placeholder: the router generates one (NAT44-126).
    let forwarded = ipv4_frame(
        (GW_MAC, WAN_MAC),
        PUBLIC,
        REMOTE,
        0,
        0,
        63,
        UDP,
        &translated,
    );
    (cut(&sent, &SIZES), forwarded)
}

fn with_id(frame: &[u8], id: u16) -> Vec<u8> {
    let mut frame = frame.to_vec();
    frame[18..20].copy_from_slice(&id.to_be_bytes());
    frame[24..26].fill(0);
    let checksum = sum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn lan(frames: &[Vec<u8>]) -> Vec<(IfId, Vec<u8>)> {
    frames.iter().map(|frame| (LAN, frame.clone())).collect()
}

fn wan(frames: &[Vec<u8>]) -> Vec<(IfId, Vec<u8>)> {
    frames.iter().map(|frame| (WAN, frame.clone())).collect()
}

// -------------------------------------------------------------- tests ----

#[test]
fn nat_outbound_udp_fragments_in_order_get_one_translation_and_one_id() {
    let mut world = World::new(Setup::default());
    let (fragments, forwarded) = outbound_udp(0x4242);
    let outcome = world.run(&lan(&fragments));
    assert!(outcome.drops.is_empty() && outcome.consumed.is_empty());
    let out = frames_to(&outcome, WAN);
    assert_eq!(out.len(), 3);
    let id = one_id(&out);
    let expected = with_id(&forwarded, id);
    // Byte-exact: each forwarded fragment is the expected datagram cut at
    // the sender's boundaries (TTL 63, PUBLIC, the generated ID, the first
    // fragment's port and UDP checksum translated).
    assert_eq!(out, cut(&expected, &SIZES));
    assert_eq!(reassemble(&out), expected);
    assert_eq!(
        world.state(),
        [1, 0, 0, 1],
        "one mapping, one firewall state"
    );
    let counters = world.counters();
    assert_eq!(counters.first_allowed, 1);
    assert_eq!(counters.followed, 2);
    // Every byte up to the last fragment passed: the entry is freed early.
    assert_eq!(counters.entries_completed, 1);
    assert_eq!(world.occupancy(), (0, 0));

    // A second datagram with the same host ID gets the next generated ID.
    let outcome = world.run(&lan(&fragments));
    let out = frames_to(&outcome, WAN);
    assert_eq!(one_id(&out), id.wrapping_add(1));
}

#[test]
fn nat_outbound_udp_fragments_out_of_order_are_held_then_released() {
    let mut world = World::new(Setup::default());
    let (fragments, forwarded) = outbound_udp(0x4343);
    // The last, then the middle fragment, before the first: held.
    let outcome = world.run(&lan(&[fragments[2].clone(), fragments[1].clone()]));
    assert!(outcome.tx.is_empty() && outcome.drops.is_empty());
    assert_eq!(
        outcome.consumed,
        [
            ConsumeReason::Ipv4FragmentHeld,
            ConsumeReason::Ipv4FragmentHeld
        ]
    );
    assert_eq!(world.occupancy(), (1, 2));
    assert_eq!(
        world.state(),
        [0, 0, 0, 0],
        "no decision without the header"
    );
    // The first fragment decides; the held ones follow it.
    let outcome = world.run(&lan(&fragments[..1]));
    assert!(outcome.drops.is_empty() && outcome.consumed.is_empty());
    let out = frames_to(&outcome, WAN);
    assert_eq!(out.len(), 3);
    let id = one_id(&out);
    let expected = with_id(&forwarded, id);
    assert_eq!(sorted(out.clone()), sorted(cut(&expected, &SIZES)));
    assert_eq!(reassemble(&out), expected);
    let counters = world.counters();
    assert_eq!((counters.held, counters.released), (2, 2));
    assert_eq!(counters.entries_completed, 1);
    assert_eq!(world.occupancy(), (0, 0));
    assert_eq!(world.fragmentation.counters().whole, 2);

    // All three in one batch, first last.
    let outcome = world.run(&lan(&[
        fragments[1].clone(),
        fragments[2].clone(),
        fragments[0].clone(),
    ]));
    let out = frames_to(&outcome, WAN);
    let id = one_id(&out);
    assert_eq!(reassemble(&out), with_id(&forwarded, id));
}

#[test]
fn nat_inbound_udp_fragments_reach_the_inside_host_in_and_out_of_order() {
    let mut world = World::new(Setup::default());
    // The outbound mapping and firewall state first.
    let request = udp_segment(H1, REMOTE, (P1, 53), 32);
    let outcome = world.run(&lan(&[ipv4_frame(
        (LAN_MAC, H1_MAC),
        H1,
        REMOTE,
        1,
        DF,
        64,
        UDP,
        &request,
    )]));
    assert_eq!(outcome.tx.len(), 1);
    // A large DNS answer (EDNS) from REMOTE:53 to PUBLIC:P1, fragmented.
    let answer = udp_segment(REMOTE, PUBLIC, (53, P1), UDP_DATA);
    let sent = ipv4_frame(
        (WAN_MAC, GW_MAC),
        REMOTE,
        PUBLIC,
        0x7777,
        0,
        60,
        UDP,
        &answer,
    );
    let fragments = cut(&sent, &SIZES);
    let translated = udp_segment(REMOTE, H1, (53, P1), UDP_DATA);
    let forwarded = ipv4_frame((H1_MAC, LAN_MAC), REMOTE, H1, 0, 0, 59, UDP, &translated);
    for order in [[0, 1, 2], [2, 0, 1], [1, 2, 0]] {
        let batch: Vec<_> = order.iter().map(|&i| fragments[i].clone()).collect();
        let outcome = world.run(&wan(&batch));
        assert!(outcome.drops.is_empty(), "{order:?}: {:?}", outcome.drops);
        let out = frames_to(&outcome, LAN);
        assert_eq!(out.len(), 3);
        let id = one_id(&out);
        let expected = with_id(&forwarded, id);
        assert_eq!(sorted(out.clone()), sorted(cut(&expected, &SIZES)));
        assert_eq!(reassemble(&out), expected, "{order:?}");
    }
    assert_eq!(world.occupancy(), (0, 0));
}

/// The NAT public address is one of the router's own addresses: fragments
/// to it are associated whichever NAT protocols the composition has (here
/// without ICMP query NAT).
#[test]
fn fragments_to_the_public_address_are_associated_without_icmp_nat() {
    let mut world = World::new(Setup {
        icmp_nat: false,
        ..Setup::default()
    });
    let request = udp_segment(H1, REMOTE, (P1, 53), 32);
    let outcome = world.run(&lan(&[ipv4_frame(
        (LAN_MAC, H1_MAC),
        H1,
        REMOTE,
        1,
        DF,
        64,
        UDP,
        &request,
    )]));
    assert_eq!(outcome.tx.len(), 1);
    let answer = udp_segment(REMOTE, PUBLIC, (53, P1), UDP_DATA);
    let sent = ipv4_frame(
        (WAN_MAC, GW_MAC),
        REMOTE,
        PUBLIC,
        0x7878,
        0,
        60,
        UDP,
        &answer,
    );
    let outcome = world.run(&wan(&cut(&sent, &SIZES)));
    assert!(outcome.drops.is_empty(), "{:?}", outcome.drops);
    let out = frames_to(&outcome, LAN);
    let translated = udp_segment(REMOTE, H1, (53, P1), UDP_DATA);
    let expected = with_id(
        &ipv4_frame((H1_MAC, LAN_MAC), REMOTE, H1, 0, 0, 59, UDP, &translated),
        one_id(&out),
    );
    assert_eq!(out, cut(&expected, &SIZES));
}

#[test]
fn nat_tcp_fragments_follow_the_first_fragment_both_ways() {
    let mut world = World::new(Setup::default());
    let syn = tcp_segment(H1, REMOTE, (P1, 443), 0x02, 0, 0);
    let outcome = world.run(&lan(&[ipv4_frame(
        (LAN_MAC, H1_MAC),
        H1,
        REMOTE,
        1,
        DF,
        64,
        TCP,
        &syn,
    )]));
    assert_eq!(outcome.tx.len(), 1);
    let syn_ack = tcp_segment(REMOTE, PUBLIC, (443, P1), 0x12, 0, 0);
    let outcome = world.run(&wan(&[ipv4_frame(
        (WAN_MAC, GW_MAC),
        REMOTE,
        PUBLIC,
        2,
        DF,
        60,
        TCP,
        &syn_ack,
    )]));
    assert_eq!(outcome.tx.len(), 1);

    // Outbound: a fragmented ACK with 12 option bytes (a 32-byte header in
    // the first fragment), out of order.
    let segment = tcp_segment(H1, REMOTE, (P1, 443), 0x10, 12, 2000);
    let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x2222, 0, 64, TCP, &segment);
    let sizes = [1000, 1000, 32];
    let fragments = cut(&sent, &sizes);
    let outcome = world.run(&lan(&[fragments[2].clone(), fragments[0].clone()]));
    assert_eq!(outcome.consumed, [ConsumeReason::Ipv4FragmentHeld]);
    let outcome_tail = world.run(&lan(&fragments[1..2]));
    let mut out = frames_to(&outcome, WAN);
    out.extend(frames_to(&outcome_tail, WAN));
    let id = one_id(&out);
    let translated = tcp_segment(PUBLIC, REMOTE, (P1, 443), 0x10, 12, 2000);
    let expected = with_id(
        &ipv4_frame(
            (GW_MAC, WAN_MAC),
            PUBLIC,
            REMOTE,
            0,
            0,
            63,
            TCP,
            &translated,
        ),
        id,
    );
    assert_eq!(sorted(out.clone()), sorted(cut(&expected, &sizes)));
    assert_eq!(reassemble(&out), expected);

    // Inbound: the answer, fragmented.
    let segment = tcp_segment(REMOTE, PUBLIC, (443, P1), 0x10, 0, 1800);
    let sent = ipv4_frame(
        (WAN_MAC, GW_MAC),
        REMOTE,
        PUBLIC,
        0x3333,
        0,
        60,
        TCP,
        &segment,
    );
    let sizes = [1200, 620];
    let outcome = world.run(&wan(&cut(&sent, &sizes)));
    let out = frames_to(&outcome, LAN);
    let id = one_id(&out);
    let translated = tcp_segment(REMOTE, H1, (443, P1), 0x10, 0, 1800);
    let expected = with_id(
        &ipv4_frame((H1_MAC, LAN_MAC), REMOTE, H1, 0, 0, 59, TCP, &translated),
        id,
    );
    assert_eq!(out, cut(&expected, &sizes));
}

#[test]
fn nat_icmp_echo_fragments_are_translated_both_ways() {
    let mut world = World::new(Setup::default());
    // `ping -s 3000`: a fragmented Echo Request, then its fragmented Reply.
    let request = echo(8, 0x0bad, 3000);
    let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x1234, 0, 64, ICMP, &request);
    let sizes = [1480, 1480, 48];
    let outcome = world.run(&lan(&cut(&sent, &sizes)));
    let out = frames_to(&outcome, WAN);
    let id = one_id(&out);
    let whole = reassemble(&out);
    // The identifier is the mapping's (P1 here, the first of the pool's
    // identifiers); the ICMP checksum covers the whole message.
    let identifier = u16::from_be_bytes([whole[38], whole[39]]);
    let expected = with_id(
        &ipv4_frame(
            (GW_MAC, WAN_MAC),
            PUBLIC,
            REMOTE,
            0,
            0,
            63,
            ICMP,
            &echo(8, identifier, 3000),
        ),
        id,
    );
    assert_eq!(whole, expected);
    assert_eq!(out, cut(&expected, &sizes));

    let reply = echo(0, identifier, 3000);
    let sent = ipv4_frame(
        (WAN_MAC, GW_MAC),
        REMOTE,
        PUBLIC,
        0x5678,
        0,
        60,
        ICMP,
        &reply,
    );
    let fragments = cut(&sent, &sizes);
    let outcome = world.run(&wan(&[
        fragments[1].clone(),
        fragments[2].clone(),
        fragments[0].clone(),
    ]));
    let out = frames_to(&outcome, LAN);
    let id = one_id(&out);
    let expected = with_id(
        &ipv4_frame(
            (H1_MAC, LAN_MAC),
            REMOTE,
            H1,
            0,
            0,
            59,
            ICMP,
            &echo(0, 0x0bad, 3000),
        ),
        id,
    );
    assert_eq!(reassemble(&out), expected);
}

#[test]
fn plain_routing_under_the_firewall_forwards_fragments_with_their_own_id() {
    let mut world = World::new(Setup::default());
    let segment = udp_segment(H1, D, (5000, 9000), UDP_DATA);
    let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, D, 0x5151, 0, 64, UDP, &segment);
    let fragments = cut(&sent, &SIZES);
    let forwarded = ipv4_frame((D_MAC, DMZ_MAC), H1, D, 0x5151, 0, 63, UDP, &segment);
    let outcome = world.run(&lan(&fragments));
    // No NAT: the source's ID and addresses, TTL - 1, new MACs.
    assert_eq!(frames_to(&outcome, DMZ), cut(&forwarded, &SIZES));
    let outcome = world.run(&lan(&[
        fragments[2].clone(),
        fragments[1].clone(),
        fragments[0].clone(),
    ]));
    assert_eq!(
        sorted(frames_to(&outcome, DMZ)),
        sorted(cut(&forwarded, &SIZES))
    );
    assert_eq!(world.state()[0], 0, "no NAT mapping");
}

#[test]
fn a_refused_first_fragment_refuses_the_rest_of_its_datagram() {
    let mut world = World::new(Setup {
        deny_udp: true,
        ..Setup::default()
    });
    let (fragments, _) = outbound_udp(0x6060);
    // In order: the first is denied by rule, the later ones follow it.
    let outcome = world.run(&lan(&fragments));
    assert!(outcome.tx.is_empty());
    assert_eq!(
        outcome.drops,
        [
            DropReason::FirewallRuleDenied,
            DropReason::Ipv4FragmentFirstDenied,
            DropReason::Ipv4FragmentFirstDenied,
        ]
    );
    // Out of order: the held fragments are discarded with the refusal.
    let (fragments, _) = outbound_udp(0x6161);
    let outcome = world.run(&lan(&[fragments[1].clone(), fragments[2].clone()]));
    assert_eq!(outcome.consumed.len(), 2);
    let outcome = world.run(&lan(&fragments[..1]));
    assert_eq!(outcome.drops, [DropReason::FirewallRuleDenied]);
    assert!(outcome.tx.is_empty());
    let counters = world.counters();
    assert_eq!(counters.first_denied, 2);
    assert_eq!(counters.followed_denied, 2);
    assert_eq!(counters.held_denied, 2);
    assert_eq!(counters.released, 0);
    assert_eq!(world.state(), [0, 0, 0, 0], "nothing committed");
    // Both refused datagrams passed (refused) whole: their entries are done.
    assert_eq!(world.occupancy(), (0, 0));
    assert_eq!(counters.entries_completed, 2);

    // An inbound fragment toward the public address with no mapping: the
    // NAT refuses the first fragment, the rest follow.
    let answer = udp_segment(REMOTE, PUBLIC, (53, P1 + 3), UDP_DATA);
    let sent = ipv4_frame((WAN_MAC, GW_MAC), REMOTE, PUBLIC, 9, 0, 60, UDP, &answer);
    let outcome = world.run(&wan(&cut(&sent, &SIZES)));
    assert!(outcome.tx.is_empty());
    assert_eq!(outcome.drops.len(), 3);
    assert_eq!(
        &outcome.drops[1..],
        [DropReason::Ipv4FragmentFirstDenied; 2]
    );
}

#[test]
fn transport_header_overlap_tiny_and_malformed_fragments_are_refused() {
    let mut world = World::new(Setup::default());
    let syn = tcp_segment(H1, REMOTE, (P1, 443), 0x02, 0, 0);
    world.run(&lan(&[ipv4_frame(
        (LAN_MAC, H1_MAC),
        H1,
        REMOTE,
        1,
        DF,
        64,
        TCP,
        &syn,
    )]));
    let frag = |id: u16, word: u16, payload: &[u8]| {
        ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, id, word, 64, TCP, payload)
    };
    // RFC 1858 §3.2: a TCP fragment at offset 1 (8 bytes) or 2 (16 bytes)
    // starts inside any TCP header, before its first fragment is known.
    for offset in [1, 2] {
        let outcome = world.run(&lan(&[frag(0x10, offset, &data(16))]));
        assert_eq!(
            outcome.drops,
            [DropReason::Ipv4FragmentTransportHeaderOverlap]
        );
    }
    // A first fragment with a 32-byte header: a later fragment at offset
    // 24 would rewrite its options, one at 32 is data.
    let segment = tcp_segment(H1, REMOTE, (P1, 443), 0x10, 12, 64);
    let outcome = world.run(&lan(&[frag(0x11, MF, &segment[..40])]));
    assert_eq!(outcome.tx.len(), 1);
    let outcome = world.run(&lan(&[frag(0x11, MF | 3, &data(8))]));
    assert_eq!(
        outcome.drops,
        [DropReason::Ipv4FragmentTransportHeaderOverlap]
    );
    // A second first fragment of a decided datagram (RFC 1858 §4).
    let outcome = world.run(&lan(&[frag(0x11, MF, &segment[..40])]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentDuplicateFirst]);
    let outcome = world.run(&lan(&[frag(0x11, 5, &segment[40..])]));
    assert_eq!(outcome.tx.len(), 1);
    // A tiny first fragment that cuts the TCP header (RFC 1858 §3.1): the
    // firewall cannot read it, so the datagram is refused.
    let outcome = world.run(&lan(&[frag(0x12, MF, &segment[..16])]));
    assert_eq!(outcome.drops, [DropReason::FirewallTcpHeaderTruncated]);
    let outcome = world.run(&lan(&[frag(0x12, 2 | MF, &segment[16..24])]));
    assert_eq!(
        outcome.drops,
        [DropReason::Ipv4FragmentTransportHeaderOverlap]
    );
    let outcome = world.run(&lan(&[frag(0x12, 4, &segment[32..])]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentFirstDenied]);
    // A non-last fragment whose data is not a multiple of 8, a fragment
    // without data, data past 65515 bytes.
    for (word, len) in [(MF | 10, 12), (10, 0), (0x1fff, 16)] {
        let outcome = world.run(&lan(&[frag(0x13, word, &data(len))]));
        assert_eq!(
            outcome.drops,
            [DropReason::Ipv4FragmentMalformed],
            "{word:#x}"
        );
    }
    // Once every byte has passed the entry is gone; a late duplicate is a
    // new datagram (decided again on its own header).
    assert_eq!(world.counters().entries_completed, 1);
}

#[test]
fn associations_and_held_fragments_expire_after_the_timeout() {
    let mut world = World::new(Setup {
        tracking: Some(Ipv4FragmentTrackingPolicy::new(500, 32, 16).unwrap()),
        ..Setup::default()
    });
    let (fragments, forwarded) = outbound_udp(0x7070);
    // Held, then the first fragment comes too late: the held fragments
    // expired with their entry, and the first starts a new one.
    let outcome = world.run_at(NOW, &lan(&fragments[1..]));
    assert_eq!(outcome.consumed.len(), 2);
    let outcome = world.run_at(NOW + 500, &lan(&fragments[..1]));
    assert_eq!(frames_to(&outcome, WAN).len(), 1);
    let counters = world.counters();
    assert_eq!((counters.entries_expired, counters.held_expired), (1, 2));
    // Just before the timeout the late fragments still follow it; at the
    // timeout they are held as an unknown datagram again.
    let outcome = world.run_at(NOW + 999, &lan(&fragments[1..2]));
    assert_eq!(frames_to(&outcome, WAN).len(), 1);
    let outcome = world.run_at(NOW + 1000, &lan(&fragments[2..]));
    assert_eq!(outcome.consumed, [ConsumeReason::Ipv4FragmentHeld]);
    assert!(outcome.tx.is_empty());
    // In time, the whole datagram passes and is reassembled.
    let (fragments, _) = outbound_udp(0x7171);
    world.run_at(NOW + 2000, &lan(&fragments[2..]));
    let outcome = world.run_at(NOW + 2499, &lan(&fragments[..2]));
    let out = frames_to(&outcome, WAN);
    assert_eq!(reassemble(&out), with_id(&forwarded, one_id(&out)));
}

#[test]
fn per_host_and_global_caps_refuse_new_datagrams() {
    let mut world = World::new(Setup {
        // Without the ingress partition (every datagram is from the LAN).
        tracking: Some(
            Ipv4FragmentTrackingPolicy::new(5_000, 2, 1)
                .unwrap()
                .with_ingress_share_percent(100)
                .unwrap(),
        ),
        entries: 3,
        held: 2,
        ..Setup::default()
    });
    let first = |source: Ipv4Address, mac: MacAddress, id: u16| {
        let segment = udp_segment(source, D, (5000, 9000), UDP_DATA);
        cut(
            &ipv4_frame((LAN_MAC, mac), source, D, id, 0, 64, UDP, &segment),
            &SIZES,
        )
    };
    // H1: two datagrams in flight, a third is over its limit.
    let a = first(H1, H1_MAC, 1);
    let b = first(H1, H1_MAC, 2);
    let c = first(H1, H1_MAC, 3);
    assert_eq!(world.run(&lan(&a[..1])).tx.len(), 1);
    assert_eq!(world.run(&lan(&b[..1])).tx.len(), 1);
    let outcome = world.run(&lan(&c[..1]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentHostLimit]);
    assert!(outcome.tx.is_empty(), "refused before its decision");
    // Its later fragments cannot be held either (no entry for H1 left).
    let outcome = world.run(&lan(&c[1..2]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentHostLimit]);
    // H2 has its own limit; the table (3 entries) is then full.
    let d = first(H2, H2_MAC, 4);
    let e = first(H2, H2_MAC, 5);
    let outcome = world.run(&lan(&d[1..2]));
    assert_eq!(outcome.consumed, [ConsumeReason::Ipv4FragmentHeld]);
    // One held fragment per host.
    let outcome = world.run(&lan(&d[2..3]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentHostHoldLimit]);
    // The table is full: a new datagram evicts the oldest pending entry
    // (d, with its held fragment), never an allowing one.
    let outcome = world.run(&lan(&e[..1]));
    assert_eq!(outcome.tx.len(), 1);
    let counters = world.counters();
    assert_eq!((counters.entries_evicted, counters.held_evicted), (1, 1));
    assert_eq!(world.occupancy(), (3, 0));
    // Full of allowing entries, a new datagram is refused.
    let f = first(H2, H2_MAC, 6);
    let outcome = world.run(&lan(&f[..1]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentTableFull]);
    // Finishing H1's datagrams frees their entries early.
    world.run(&lan(&a[1..]));
    world.run(&lan(&b[1..]));
    assert_eq!(world.occupancy(), (1, 0));
    assert_eq!(world.run(&lan(&f[..1])).tx.len(), 1);
}

#[test]
fn forwarded_fragments_above_the_egress_mtu_are_refragmented_with_the_nat_id() {
    let mut world = World::new(Setup {
        wan_mtu: 1000,
        ..Setup::default()
    });
    let (fragments, forwarded) = outbound_udp(0x8080);
    // The middle fragment first (held, re-fragmented at release), then the
    // first (re-fragmented on arrival), then the last (within the MTU).
    world.run(&lan(&fragments[1..2]));
    let mut out = frames_to(&world.run(&lan(&fragments[..1])), WAN);
    out.extend(frames_to(&world.run(&lan(&fragments[2..])), WAN));
    // 1480-byte fragments cut at 976 bytes: 976 + 504, twice, then 20.
    assert_eq!(out.len(), 5);
    let id = one_id(&out);
    for frame in &out {
        assert!(frame.len() - 14 <= 1000);
    }
    let expected = with_id(&forwarded, id);
    assert_eq!(
        sorted(out.clone()),
        sorted(cut(&expected, &[976, 504, 976, 504, 20]))
    );
    assert_eq!(reassemble(&out), expected);
    assert_eq!(world.fragmentation.counters().fragmented, 2);
}

#[test]
fn the_refuse_mode_keeps_every_fragment_refused() {
    let mut world = World::new(Setup {
        tracking: None,
        ..Setup::default()
    });
    let (fragments, _) = outbound_udp(0x9090);
    let outcome = world.run(&lan(&fragments));
    assert!(outcome.tx.is_empty());
    assert_eq!(outcome.drops, [DropReason::FirewallFragmentUnsupported; 3]);
    assert_eq!(world.state(), [0, 0, 0, 0]);
}

#[test]
fn fragments_for_the_router_keep_the_local_path() {
    let mut world = World::new(Setup::default());
    // A fragmented Echo Request to the router's own LAN address: no
    // reassembly (ICMP4-006), so no association either.
    let request = echo(8, 7, 2000);
    let sent = ipv4_frame(
        (LAN_MAC, H1_MAC),
        H1,
        LAN_ADDRESS,
        0x4444,
        0,
        64,
        ICMP,
        &request,
    );
    let outcome = world.run(&lan(&cut(&sent, &[1480, 528])));
    assert!(outcome.tx.is_empty());
    assert_eq!(outcome.drops, [DropReason::Icmpv4FragmentUnsupported; 2]);
    assert_eq!(world.occupancy(), (0, 0));
    assert_eq!(world.counters(), Ipv4FragmentTrackingCounters::default());
}

#[test]
fn a_publication_flush_drops_every_association_and_held_fragment() {
    let mut world = World::new(Setup::default());
    let (fragments, _) = outbound_udp(0xa0a0);
    world.run(&lan(&fragments[..1]));
    let (held, _) = outbound_udp(0xa1a1);
    world.run(&lan(&held[1..]));
    assert_eq!(world.occupancy(), (2, 2));
    world
        .tracker
        .as_mut()
        .unwrap()
        .flush_with_key(ResolutionHashKey::new(3, 4).unwrap());
    assert_eq!(world.occupancy(), (0, 0));
    let counters = world.counters();
    assert_eq!((counters.entries_flushed, counters.held_flushed), (2, 2));
    // The later fragments of the flushed datagram are now unknown: held.
    let outcome = world.run(&lan(&fragments[1..2]));
    assert_eq!(outcome.consumed, [ConsumeReason::Ipv4FragmentHeld]);
}

/// xorshift64*: a fixed, dependency-free generator for the bounded
/// property run below.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, upper: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(upper).unwrap()).unwrap()
    }
}

/// A bounded property run: two hosts' datagrams of random lengths, cut at
/// random 8-byte boundaries, some fragments duplicated, interleaved in a
/// random order over random batches (out of order included), with random
/// later fragments of datagrams that were never sent mixed in. Every
/// datagram arrives whole (the forwarded pieces with its ID, duplicates
/// removed, reassemble to the independently built datagram), nothing
/// panics, the table never holds more than its capacity, and a bounded
/// sweep after the timeout leaves it empty.
#[test]
fn random_cuts_orders_and_garbage_keep_every_datagram_whole() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for case in 0..200 {
        // Room for every fragment of both datagrams to be held and released
        // in one batch (at most 22 fragments each, below): the property is
        // about association, not about the bounds (tested above).
        let mut world = World::new(Setup {
            tracking: Some(Ipv4FragmentTrackingPolicy::new(5_000, 32, 32).unwrap()),
            held: 64,
            fragmentation_slots: 64,
            ..Setup::default()
        });
        let mut expected = Vec::new();
        let mut injected = Vec::new();
        for (host, mac, port) in [(H1, H1_MAC, 5001_u16), (H2, H2_MAC, 5002)] {
            let len = 9 + rng.below(4000);
            let segment = udp_segment(host, D, (port, 9000), len);
            let id = u16::try_from(rng.below(60_000)).unwrap();
            let sent = ipv4_frame((LAN_MAC, mac), host, D, id, 0, 64, UDP, &segment);
            let mut sizes = Vec::new();
            let mut left = segment.len();
            while left > 0 {
                let block = 8 * (23 + rng.below(163));
                if block >= left {
                    sizes.push(left);
                    break;
                }
                sizes.push(block);
                left -= block;
            }
            let forwarded = ipv4_frame((D_MAC, DMZ_MAC), host, D, id, 0, 63, UDP, &segment);
            expected.push((id, forwarded));
            let fragments = cut(&sent, &sizes);
            if fragments.len() == 1 {
                // Not a fragment at all: skip, the property is about sets.
                expected.pop();
                continue;
            }
            // Duplicates (as a network may deliver them).
            for _ in 0..rng.below(3) {
                let copy = fragments[rng.below(fragments.len())].clone();
                injected.push(copy);
            }
            injected.extend(fragments);
        }
        // Garbage: random flags, offsets, and lengths from H1 with fresh
        // IDs; they may be held or refused, never forwarded whole as a
        // datagram that was not sent.
        for _ in 0..rng.below(4) {
            let word = u16::try_from(1 + rng.below(0x1ffe)).unwrap() | MF;
            let id = 60_000 + u16::try_from(rng.below(1000)).unwrap();
            injected.push(ipv4_frame(
                (LAN_MAC, H1_MAC),
                H1,
                D,
                id,
                word,
                64,
                UDP,
                &data(rng.below(64)),
            ));
        }
        for index in (1..injected.len()).rev() {
            injected.swap(index, rng.below(index + 1));
        }
        let mut out = Vec::new();
        let mut now = NOW;
        while !injected.is_empty() {
            let take = 1 + rng.below(injected.len());
            let batch: Vec<_> = injected.drain(..take).collect();
            let outcome = world.run_at(now, &lan(&batch));
            out.extend(frames_to(&outcome, DMZ));
            let (entries, held) = world.occupancy();
            assert!(entries <= 16 && held <= 64, "case {case}");
            now += 1;
        }
        for (id, forwarded) in &expected {
            let mut pieces: Vec<_> = out
                .iter()
                .filter(|frame| id_of(frame) == *id && frame[26..30] == forwarded[26..30])
                .cloned()
                .collect();
            pieces.sort();
            pieces.dedup();
            assert!(
                !pieces.is_empty(),
                "case {case}: datagram {id:#x} forwarded"
            );
            assert_eq!(&reassemble(&pieces), forwarded, "case {case}");
        }
        let tracker = world.tracker.as_mut().unwrap();
        tracker.sweep(now + 5_000, usize::MAX);
        assert_eq!(world.occupancy(), (0, 0), "case {case}");
    }
}

/// Counts the allocations of the measuring thread while it is armed (as in
/// the runtime's steady-allocation tests).
#[allow(unsafe_code)]
mod counting {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }

    fn note() {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
        }
    }

    pub struct Counting;

    // SAFETY: every method forwards the caller's arguments unchanged to
    // `System`; the const thread-local counters never allocate.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: `pointer` and `layout` came from this allocator.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    pub fn during(run: impl FnOnce()) -> usize {
        ARMED.with(|armed| armed.set(true));
        COUNT.with(|count| count.set(0));
        run();
        ARMED.with(|armed| armed.set(false));
        let count = COUNT.with(Cell::get);
        // The counter is live: an armed allocation counts.
        ARMED.with(|armed| armed.set(true));
        drop(std::hint::black_box(Box::new(0_u8)));
        ARMED.with(|armed| armed.set(false));
        assert_eq!(COUNT.with(Cell::get), count + 1, "the counter counts");
        count
    }
}

/// AGENTS.md: the fragment paths allocate nothing. The RX batch of a
/// warmed-up `SimIo` (whose queues already have their capacity) is
/// forwarded with first fragments, followed fragments, held fragments, and
/// releases into the fragmentation slots, and the forwarding call itself
/// allocates nothing (the simulator's own frame storage is outside it).
#[test]
fn the_fragment_paths_do_not_allocate() {
    let mut world = World::new(Setup::default());
    let forward = |world: &mut World, frames: &[(IfId, Vec<u8>)], measure: bool| {
        for (ingress, frame) in frames {
            world.io.inject(*ingress, frame.clone());
        }
        let mut allocations = 0;
        let mut call = || {
            let batch = world.io.receive(frames.len()).unwrap();
            let report =
                forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragment_tracking(
                    batch,
                    &world.snapshot,
                    &mut world.resolution,
                    &mut world.errors,
                    &world.udp_config,
                    Some(&mut world.udp),
                    &world.tcp_config,
                    Some(&mut world.tcp),
                    Some((&world.icmp_config, Some(&mut world.icmp))),
                    &world.firewall_config,
                    Some(&mut world.firewall),
                    None,
                    Some(&mut world.fragmentation),
                    world.tracker.as_mut(),
                    MonotonicMillis(NOW),
                    &mut ruster_core::NoTrace,
                );
            assert!(report.invariants_hold());
        };
        if measure {
            allocations = counting::during(call);
        } else {
            call();
        }
        while world.io.pop_recycled().is_some() {}
        while execute_one_ipv4_fragmentation(&mut world.io, &mut world.fragmentation, &mut { 64 })
            .is_some()
        {}
        while world.io.pop_tx().is_some() {}
        allocations
    };
    for measure in [false, true, true] {
        let (fragments, _) = outbound_udp(0x4000 + u16::from(measure));
        let in_order = lan(&fragments);
        let reversed = lan(&[
            fragments[2].clone(),
            fragments[1].clone(),
            fragments[0].clone(),
        ]);
        let mut batch = in_order;
        batch.extend(reversed);
        assert_eq!(
            forward(&mut world, &batch, measure),
            0,
            "measured: {measure}"
        );
    }
    assert_eq!(world.counters().released, 6);
}

// --------------------------------------------- review follow-ups (#337) ----

const P2: u16 = 40_001;

/// Review M-A (core): an ID reused after a lost fragment. Datagram A's
/// middle fragment is lost; datagram B then reuses A's (source,
/// destination, protocol, ID). B's first fragment poisons the entry, so
/// none of B's later fragments leaves under A's template and generated ID
/// (the receiver would misassemble A from them).
#[test]
fn a_reused_id_poisons_the_entry_instead_of_misassembling() {
    let mut world = World::new(Setup::default());
    let (a, _) = outbound_udp(0x0aaa);
    let outcome = world.run(&lan(&[a[0].clone(), a[2].clone()]));
    assert_eq!(frames_to(&outcome, WAN).len(), 2);
    let segment = udp_segment(H1, REMOTE, (P1, 53), UDP_DATA - 8);
    let b = cut(
        &ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x0aaa, 0, 64, UDP, &segment),
        &[1480, 1480, 12],
    );
    let outcome = world.run(&lan(&b));
    assert!(outcome.tx.is_empty(), "nothing of B leaves");
    assert_eq!(
        outcome.drops,
        [
            DropReason::Ipv4FragmentDuplicateFirst,
            DropReason::Ipv4FragmentFirstDenied,
            DropReason::Ipv4FragmentFirstDenied,
        ]
    );
    // A's lost middle fragment, retransmitted by nobody but arriving late,
    // is refused too: both datagrams fail closed.
    let outcome = world.run(&lan(&a[1..2]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentFirstDenied]);
    assert_eq!(world.counters().poisoned, 1);
    // A byte-identical duplicate of a first fragment is dropped alone.
    let (c, forwarded) = outbound_udp(0x0ccc);
    let outcome = world.run(&lan(&[
        c[0].clone(),
        c[0].clone(),
        c[1].clone(),
        c[2].clone(),
    ]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentDuplicateFirst]);
    let out = frames_to(&outcome, WAN);
    assert_eq!(reassemble(&out), with_id(&forwarded, one_id(&out)));
    assert_eq!(world.counters().duplicate_first, 1);
}

/// Review M-A (sec): the inbound key has no destination port. A server
/// answers H1 and H2 (behind one public address) with datagrams that share
/// an ID, interleaved: A0, B0, A1, B1, A2, B2. B0 poisons the entry, so no
/// fragment of B reaches H1 (and none of A after A0).
#[test]
fn colliding_inbound_ids_to_two_hosts_fail_closed() {
    let mut world = World::new(Setup::default());
    let mut public = Vec::new();
    for (host, mac, port) in [(H1, H1_MAC, 5001_u16), (H2, H2_MAC, 5002)] {
        let request = udp_segment(host, REMOTE, (port, 53), 8);
        let outcome = world.run(&lan(&[ipv4_frame(
            (LAN_MAC, mac),
            host,
            REMOTE,
            1,
            DF,
            64,
            UDP,
            &request,
        )]));
        let out = frames_to(&outcome, WAN);
        public.push(u16::from_be_bytes([out[0][34], out[0][35]]));
    }
    let answer = |port: u16, fill: usize| {
        let segment = udp_segment(REMOTE, PUBLIC, (53, port), UDP_DATA - fill);
        cut(
            &ipv4_frame(
                (WAN_MAC, GW_MAC),
                REMOTE,
                PUBLIC,
                0x5555,
                0,
                60,
                UDP,
                &segment,
            ),
            &[1480, 1480, 20 - fill],
        )
    };
    let a = answer(public[0], 0);
    let b = answer(public[1], 8);
    let outcome = world.run(&wan(&[
        a[0].clone(),
        b[0].clone(),
        a[1].clone(),
        b[1].clone(),
        a[2].clone(),
        b[2].clone(),
    ]));
    let out = frames_to(&outcome, LAN);
    assert_eq!(out.len(), 1, "only A0, to H1");
    assert_eq!(out[0][30..34], H1.octets());
    assert_eq!(
        outcome.drops,
        [
            DropReason::Ipv4FragmentDuplicateFirst,
            DropReason::Ipv4FragmentFirstDenied,
            DropReason::Ipv4FragmentFirstDenied,
            DropReason::Ipv4FragmentFirstDenied,
            DropReason::Ipv4FragmentFirstDenied,
        ]
    );
}

/// Review M-B: duplicates and overlaps do not declare a datagram complete
/// early (which freed the entry and lost the rest), and a forged last
/// fragment with another end poisons the entry instead of moving the end.
#[test]
fn duplicates_overlaps_and_forged_ends_do_not_complete_a_datagram() {
    let mut world = World::new(Setup::default());
    let segment = udp_segment(H1, REMOTE, (P1, 53), 4460 - 8);
    let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x0ddd, 0, 64, UDP, &segment);
    let sizes = [1480, 1480, 1480, 20];
    let fragments = cut(&sent, &sizes);
    // First, last, then the second three times: 1480 + 20 + 3 * 1480 bytes
    // would have counted past the 4460-byte end.
    let outcome = world.run(&lan(&[
        fragments[0].clone(),
        fragments[3].clone(),
        fragments[1].clone(),
        fragments[1].clone(),
        fragments[1].clone(),
    ]));
    assert_eq!(frames_to(&outcome, WAN).len(), 5);
    assert_eq!(world.occupancy(), (1, 0), "bytes 2960..4440 not seen");
    let outcome = world.run(&lan(&fragments[2..3]));
    assert_eq!(frames_to(&outcome, WAN).len(), 1, "the third still follows");
    assert_eq!(world.occupancy(), (0, 0));

    // A forged last fragment that ends before data already seen contradicts
    // the datagram: the entry is poisoned and refuses the rest.
    let fragments = cut(
        &ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x0eee, 0, 64, UDP, &segment),
        &sizes,
    );
    let mut forged = fragments[1][..34 + 8].to_vec();
    forged[16..18].copy_from_slice(&28_u16.to_be_bytes());
    forged[20..22].copy_from_slice(&185_u16.to_be_bytes());
    forged[24..26].fill(0);
    let checksum = sum16(&forged[14..34]);
    forged[24..26].copy_from_slice(&checksum.to_be_bytes());
    let outcome = world.run(&lan(&[fragments[0].clone(), fragments[2].clone(), forged]));
    assert_eq!(
        outcome.drops,
        [DropReason::Ipv4FragmentMalformed],
        "the forged end is before the third fragment's data"
    );
    let outcome = world.run(&lan(&[fragments[1].clone(), fragments[3].clone()]));
    assert_eq!(outcome.drops, [DropReason::Ipv4FragmentFirstDenied; 2]);
    assert_eq!(world.counters().poisoned, 1);
}

/// Review M-C (sec): 32 refused first fragments from a source used to fill
/// its per-host quota for the timeout, so the same source's legitimate
/// reply was refused. Refusing entries are evicted, oldest first.
#[test]
fn refused_first_fragments_cannot_hold_a_sources_quota() {
    let mut world = World::new(Setup {
        entries: 64,
        ..Setup::default()
    });
    let request = udp_segment(H1, REMOTE, (P1, 53), 8);
    world.run(&lan(&[ipv4_frame(
        (LAN_MAC, H1_MAC),
        H1,
        REMOTE,
        1,
        DF,
        64,
        UDP,
        &request,
    )]));
    // 32 first fragments from REMOTE to unmapped public ports: refused.
    let flood: Vec<_> = (0..32)
        .map(|index| {
            let segment = udp_segment(REMOTE, PUBLIC, (53, P1 + 8), UDP_DATA);
            let sent = ipv4_frame(
                (WAN_MAC, GW_MAC),
                REMOTE,
                PUBLIC,
                0x6000 + index,
                0,
                60,
                UDP,
                &segment,
            );
            cut(&sent, &SIZES).remove(0)
        })
        .collect();
    let outcome = world.run(&wan(&flood));
    assert_eq!(outcome.drops.len(), 32);
    assert!(outcome.tx.is_empty());
    let answer = udp_segment(REMOTE, PUBLIC, (53, P1), UDP_DATA);
    let sent = ipv4_frame(
        (WAN_MAC, GW_MAC),
        REMOTE,
        PUBLIC,
        0x7000,
        0,
        60,
        UDP,
        &answer,
    );
    let outcome = world.run(&wan(&cut(&sent, &SIZES)));
    assert!(outcome.drops.is_empty(), "{:?}", outcome.drops);
    assert_eq!(frames_to(&outcome, LAN).len(), 3);
    assert_eq!(world.counters().entries_evicted, 1);
}

/// Review M-C (sec): host accounting is per (ingress, source). Fragments
/// from the WAN that claim an inside host's address use their own quota,
/// not the inside host's.
#[test]
fn a_spoofed_inside_source_does_not_use_the_inside_hosts_quota() {
    let mut world = World::new(Setup {
        tracking: Some(Ipv4FragmentTrackingPolicy::new(5_000, 2, 16).unwrap()),
        entries: 16,
        ..Setup::default()
    });
    // Later fragments from the WAN claiming H1 as source, to D.
    for id in 0..4 {
        let spoofed = ipv4_frame(
            (WAN_MAC, GW_MAC),
            H1,
            D,
            0x6100 + id,
            100,
            64,
            UDP,
            &data(16),
        );
        let outcome = world.run(&wan(&[spoofed]));
        assert_eq!(outcome.consumed, [ConsumeReason::Ipv4FragmentHeld]);
    }
    // H1 from the LAN: two datagrams in flight, as its quota allows.
    for id in [0x6200, 0x6201] {
        let segment = udp_segment(H1, D, (5000, 9000), UDP_DATA);
        let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, D, id, 0, 64, UDP, &segment);
        let outcome = world.run(&lan(&cut(&sent, &SIZES)[..2]));
        assert_eq!(frames_to(&outcome, DMZ).len(), 2);
    }
    // The spoofed ones evicted only each other (two per host at a time).
    assert_eq!(world.counters().entries_evicted, 2);
}

/// Review L3: hairpinned fragments, UDP and TCP, in order and reversed,
/// byte for byte (both addresses translated, the inside MTU, one ID).
#[test]
fn hairpinned_fragments_are_translated_both_ways_in_any_order() {
    for reversed in [false, true] {
        let mut world = World::new(Setup::default());
        // UDP: H2's mapping PUBLIC:P2 and the hole punching exchange the
        // firewall needs (H1 -> H2 is refused until H2 has sent to H1).
        let open = udp_segment(H2, REMOTE, (P2, 53), 8);
        world.run(&lan(&[ipv4_frame(
            (LAN_MAC, H2_MAC),
            H2,
            REMOTE,
            1,
            DF,
            64,
            UDP,
            &open,
        )]));
        let punch = udp_segment(H1, PUBLIC, (P1, P2), 8);
        world.run(&lan(&[ipv4_frame(
            (LAN_MAC, H1_MAC),
            H1,
            PUBLIC,
            2,
            DF,
            64,
            UDP,
            &punch,
        )]));
        let reply = udp_segment(H2, PUBLIC, (P2, P1), 8);
        let outcome = world.run(&lan(&[ipv4_frame(
            (LAN_MAC, H2_MAC),
            H2,
            PUBLIC,
            3,
            DF,
            64,
            UDP,
            &reply,
        )]));
        assert_eq!(frames_to(&outcome, LAN).len(), 1);
        let segment = udp_segment(H1, PUBLIC, (P1, P2), UDP_DATA);
        let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, PUBLIC, 0x4848, 0, 64, UDP, &segment);
        let mut fragments = cut(&sent, &SIZES);
        if reversed {
            fragments.reverse();
        }
        let outcome = world.run(&lan(&fragments));
        assert!(outcome.drops.is_empty(), "UDP: {:?}", outcome.drops);
        let out = frames_to(&outcome, LAN);
        let translated = udp_segment(PUBLIC, H2, (P1, P2), UDP_DATA);
        let expected = with_id(
            &ipv4_frame((H2_MAC, LAN_MAC), PUBLIC, H2, 0, 0, 63, UDP, &translated),
            one_id(&out),
        );
        assert_eq!(sorted(out.clone()), sorted(cut(&expected, &SIZES)), "UDP");
        assert_eq!(reassemble(&out), expected);

        // TCP: H2's session to REMOTE gives it PUBLIC:P2. Hole punching
        // (RFC 5128 §3.4): H1's SYN to PUBLIC:P2 is refused by the firewall
        // but keeps its outbound half; H2's SYN to PUBLIC:P1 then passes.
        let syn = tcp_segment(H2, REMOTE, (P2, 443), 0x02, 0, 0);
        world.run(&lan(&[ipv4_frame(
            (LAN_MAC, H2_MAC),
            H2,
            REMOTE,
            4,
            DF,
            64,
            TCP,
            &syn,
        )]));
        let syn = tcp_segment(H1, PUBLIC, (P1, P2), 0x02, 0, 0);
        world.run(&lan(&[ipv4_frame(
            (LAN_MAC, H1_MAC),
            H1,
            PUBLIC,
            5,
            DF,
            64,
            TCP,
            &syn,
        )]));
        let syn = tcp_segment(H2, PUBLIC, (P2, P1), 0x02, 0, 0);
        let outcome = world.run(&lan(&[ipv4_frame(
            (LAN_MAC, H2_MAC),
            H2,
            PUBLIC,
            6,
            DF,
            64,
            TCP,
            &syn,
        )]));
        assert_eq!(frames_to(&outcome, LAN).len(), 1, "{:?}", outcome.drops);
        let segment = tcp_segment(H1, PUBLIC, (P1, P2), 0x10, 0, 2000);
        let sent = ipv4_frame((LAN_MAC, H1_MAC), H1, PUBLIC, 0x4949, 0, 64, TCP, &segment);
        let sizes = [1000, 1000, 20];
        let mut fragments = cut(&sent, &sizes);
        if reversed {
            fragments.reverse();
        }
        let outcome = world.run(&lan(&fragments));
        assert!(outcome.drops.is_empty(), "TCP: {:?}", outcome.drops);
        let out = frames_to(&outcome, LAN);
        let translated = tcp_segment(PUBLIC, H2, (P1, P2), 0x10, 0, 2000);
        let expected = with_id(
            &ipv4_frame((H2_MAC, LAN_MAC), PUBLIC, H2, 0, 0, 63, TCP, &translated),
            one_id(&out),
        );
        assert_eq!(sorted(out.clone()), sorted(cut(&expected, &sizes)), "TCP");
        assert_eq!(reassemble(&out), expected);
    }
}

// ------------------------------------------- re-review follow-ups (#337) ----

/// Re-review M-E: a fixed-length UDP tunnel with checksum 0 (VXLAN, RFC
/// 7348). After A's middle fragment is lost and the ID wraps, B's first
/// fragment has A's length and A's first 8 data bytes (the UDP header) but
/// other data: it poisons the entry (the fingerprint covers every data
/// byte), so B's middle fragment is not forwarded under A's template and
/// ID (A0 + B1 + A2 would reassemble with no checksum to catch it).
#[test]
fn a_checksum_zero_tunnel_reusing_an_id_poisons_instead_of_misassembling() {
    let mut world = World::new(Setup::default());
    let datagram = |flip: u8| {
        let mut segment = udp_segment(H1, REMOTE, (P1, 4789), UDP_DATA);
        segment[6..8].fill(0);
        for byte in &mut segment[8..] {
            *byte ^= flip;
        }
        cut(
            &ipv4_frame((LAN_MAC, H1_MAC), H1, REMOTE, 0x0bbb, 0, 64, UDP, &segment),
            &SIZES,
        )
    };
    let a = datagram(0);
    let b = datagram(0x55);
    assert_eq!(a[0][34..42], b[0][34..42], "same UDP header");
    let outcome = world.run(&lan(&[a[0].clone(), a[2].clone()]));
    assert_eq!(frames_to(&outcome, WAN).len(), 2);
    let outcome = world.run(&lan(&b));
    assert!(outcome.tx.is_empty(), "nothing of B leaves");
    assert_eq!(
        outcome.drops,
        [
            DropReason::Ipv4FragmentDuplicateFirst,
            DropReason::Ipv4FragmentFirstDenied,
            DropReason::Ipv4FragmentFirstDenied,
        ]
    );
    assert_eq!(world.counters().poisoned, 1);
}

/// Opens H1's NAT mapping and firewall state toward `remote`:53 from P1.
fn open_to(world: &mut World, remote: Ipv4Address) {
    let request = udp_segment(H1, remote, (P1, 53), 8);
    let outcome = world.run(&lan(&[ipv4_frame(
        (LAN_MAC, H1_MAC),
        H1,
        remote,
        1,
        DF,
        64,
        UDP,
        &request,
    )]));
    assert_eq!(outcome.tx.len(), 1);
}

/// A first fragment from `remote`:53 to PUBLIC:P1 (return traffic of H1's
/// mapping, so allowed) with `id`, whose later fragments never come.
fn spoofed_first(remote: Ipv4Address, id: u16) -> Vec<u8> {
    let answer = udp_segment(remote, PUBLIC, (53, P1), UDP_DATA);
    cut(
        &ipv4_frame((WAN_MAC, GW_MAC), remote, PUBLIC, id, 0, 60, UDP, &answer),
        &SIZES,
    )
    .remove(0)
}

/// Re-review M-D repro 1: spoofed first fragments from a peer that has a
/// mapping are allowed as return traffic, and their allowing entries used
/// to be unevictable: 32 of them at 6.4 pps filled the peer's quota and its
/// legitimate reply was IPV4_FRAGMENT_HOST_LIMIT. An allowing entry whose
/// datagram stalled for a fifth of the timeout is now evicted.
#[test]
fn stalled_allowing_entries_do_not_hold_a_peers_quota() {
    let mut world = World::new(Setup {
        entries: 64,
        ..Setup::default()
    });
    open_to(&mut world, REMOTE);
    for index in 0..32_u16 {
        let now = NOW + u64::from(index) * 150;
        world.run_at(now, &wan(&[spoofed_first(REMOTE, 0x7100 + index)]));
    }
    let answer = udp_segment(REMOTE, PUBLIC, (53, P1), UDP_DATA);
    let sent = ipv4_frame(
        (WAN_MAC, GW_MAC),
        REMOTE,
        PUBLIC,
        0x7200,
        0,
        60,
        UDP,
        &answer,
    );
    let outcome = world.run_at(NOW + 32 * 150, &wan(&cut(&sent, &SIZES)));
    assert!(outcome.drops.is_empty(), "{:?}", outcome.drops);
    assert_eq!(frames_to(&outcome, LAN).len(), 3);
    assert!(world.counters().entries_evicted >= 1);
}

/// Re-review M-D repro 2: four spoofed peers × 8 fresh allowing first
/// fragments filled the table and an unrelated LAN host's outbound
/// fragments were IPV4_FRAGMENT_TABLE_FULL. The WAN may now take only its
/// share (`ingress-share-percent`, 50 by default): the rest of its flood is
/// IPV4_FRAGMENT_INGRESS_LIMIT and the LAN keeps its half.
#[test]
fn one_ingress_cannot_take_another_ingresss_share() {
    let mut world = World::new(Setup {
        entries: 32,
        ..Setup::default()
    });
    let peers = [
        REMOTE,
        Ipv4Address::from_octets([198, 51, 100, 21]),
        Ipv4Address::from_octets([198, 51, 100, 22]),
        Ipv4Address::from_octets([198, 51, 100, 23]),
    ];
    for peer in peers {
        open_to(&mut world, peer);
    }
    let flood: Vec<_> = peers
        .iter()
        .flat_map(|peer| (0..8).map(move |index| spoofed_first(*peer, 0x7300 + index)))
        .collect();
    let outcome = world.run(&wan(&flood));
    assert_eq!(
        outcome.drops,
        [DropReason::Ipv4FragmentIngressLimit; 16],
        "the WAN's share is 16 of 32"
    );
    // An unrelated LAN host's datagram still gets an entry.
    let segment = udp_segment(H2, D, (5000, 9000), UDP_DATA);
    let sent = ipv4_frame((LAN_MAC, H2_MAC), H2, D, 0x7400, 0, 64, UDP, &segment);
    let outcome = world.run(&lan(&cut(&sent, &SIZES)));
    assert!(outcome.drops.is_empty(), "{:?}", outcome.drops);
    assert_eq!(frames_to(&outcome, DMZ).len(), 3);
}

/// Follow-up L1: thirty fresh allowing entries of a spoofed peer used to
/// shield its pending entries (held forged later fragments) from eviction,
/// since only the eight oldest entries of a scope were probed: the peer's
/// legitimate reply was IPV4_FRAGMENT_HOST_LIMIT. The scope's pending and
/// refusing entries are now on their own list and evicted in O(1).
#[test]
fn a_held_flood_behind_allowing_entries_is_still_evicted() {
    let mut world = World::new(Setup {
        entries: 64,
        ..Setup::default()
    });
    open_to(&mut world, REMOTE);
    let mut flood: Vec<_> = (0..30_u16)
        .map(|index| spoofed_first(REMOTE, 0x7500 + index))
        .collect();
    for index in 0..2_u16 {
        let answer = udp_segment(REMOTE, PUBLIC, (53, P1), UDP_DATA);
        let sent = ipv4_frame(
            (WAN_MAC, GW_MAC),
            REMOTE,
            PUBLIC,
            0x7600 + index,
            0,
            60,
            UDP,
            &answer,
        );
        flood.push(cut(&sent, &SIZES).remove(1));
    }
    let outcome = world.run(&wan(&flood));
    assert!(outcome.drops.is_empty(), "{:?}", outcome.drops);
    assert_eq!(world.occupancy(), (32, 2));
    let answer = udp_segment(REMOTE, PUBLIC, (53, P1), UDP_DATA);
    let sent = ipv4_frame(
        (WAN_MAC, GW_MAC),
        REMOTE,
        PUBLIC,
        0x7700,
        0,
        60,
        UDP,
        &answer,
    );
    let outcome = world.run(&wan(&cut(&sent, &SIZES)));
    assert!(outcome.drops.is_empty(), "{:?}", outcome.drops);
    assert_eq!(frames_to(&outcome, LAN).len(), 3);
    let counters = world.counters();
    assert_eq!((counters.entries_evicted, counters.held_evicted), (1, 1));
}

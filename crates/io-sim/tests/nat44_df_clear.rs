//! MTU2 part A (NAT44-008, NAT44-126): NAT44 translates whole DF-clear
//! datagrams (MF=0, offset 0) of UDP, TCP, ICMP queries and translated
//! ICMP errors, outbound, inbound and hairpinned, and gives each a generated
//! IPv4 ID (RFC 6864 §5.3.1). Fragments stay a typed drop (NAT-FRAG).
//!
//! Every expected frame is built here from the RFC 791/768/793 layouts with
//! fully recomputed checksums; the generated ID is taken from the
//! transmitted frame and the ID policy is checked as properties: atomic
//! datagrams keep their ID, consecutive DF-clear datagrams of one
//! translated (source, destination, protocol) tuple get consecutive IDs
//! whatever the hosts sent, and a datagram that is not sent consumes none.

mod support;

use ruster_core::{
    internet_checksum, ipv4_header_checksum, DropReason, FirewallAction, FirewallConfig,
    FirewallHashKey, FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange,
    FirewallProtocol, FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot,
    ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime,
    Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Nat44Filtering, Nat44IcmpConfig, Nat44IcmpPolicy, Nat44IcmpRuntime,
    Nat44TcpConfig, Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot,
    Nat44UdpConfig, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime,
    Neighbor, PacketIo, Route,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};
use support::UdpTestIndexes;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const H1_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 10]);
const H2_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 11]);
const GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const H1: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const H2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const ROUTER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
/// Inside ports in the pool: port preservation keeps them (NAT44-020).
const P1: u16 = 40_000;
const P2: u16 = 40_001;
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const UDP: u8 = 17;
const TCP: u8 = 6;
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

fn snapshot(wan_mtu: u16) -> ForwardingSnapshot<'static> {
    let routes = leak([
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
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
    ]);
    ForwardingSnapshot::new(&routes[..], &interfaces[..], &neighbors[..], &bindings[..]).unwrap()
}

fn outbound_rule(id: u32, protocol: FirewallProtocol) -> FirewallRule {
    let full = FirewallPortRange::new(0, u16::MAX).unwrap();
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(LAN),
        FirewallInterface::Interface(WAN),
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 8).unwrap(),
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap(),
        protocol,
        full,
        full,
        FirewallAction::AllowStateful,
    )
}

struct World {
    snapshot: ForwardingSnapshot<'static>,
    udp_config: Nat44UdpConfig,
    tcp_config: Nat44TcpConfig,
    icmp_config: Nat44IcmpConfig,
    udp: Nat44UdpRuntime<'static>,
    tcp: Nat44TcpRuntime<'static>,
    icmp: Nat44IcmpRuntime<'static>,
    firewall_config: Option<FirewallConfig<'static>>,
    firewall: Option<FirewallRuntime<'static>>,
    errors: Icmpv4ErrorRuntime<'static>,
    io: SimIo,
    trace: VecTrace,
}

impl World {
    fn new(firewall: bool, wan_mtu: u16) -> Self {
        Self::with_filtering(firewall, wan_mtu, Nat44Filtering::AddressDependent)
    }

    fn with_filtering(firewall: bool, wan_mtu: u16, filtering: Nat44Filtering) -> Self {
        let snapshot = snapshot(wan_mtu);
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            P1,
            P1 + 15,
            Nat44UdpPolicy::default().with_filtering(filtering),
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
        let (firewall_config, firewall) = if firewall {
            let config = FirewallConfig::new(
                &snapshot,
                Vec::leak(vec![
                    outbound_rule(20, FirewallProtocol::Udp),
                    outbound_rule(30, FirewallProtocol::Tcp),
                    outbound_rule(40, FirewallProtocol::Icmp),
                ]),
                FirewallPolicy::default(),
                1,
                FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
            )
            .unwrap();
            let runtime = FirewallRuntime::new(config, leak([FirewallStateSlot::default(); 16]));
            (Some(config), Some(runtime))
        } else {
            (None, None)
        };
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
                leak([Icmpv4ErrorStateSlot::EMPTY; 4]),
                leak([Icmpv4ErrorActionSlot::EMPTY; 4]),
            ),
            io: SimIo::new(),
            trace: VecTrace::default(),
        }
    }

    fn run(&mut self, ingress: IfId, frame: Vec<u8>) -> Result<(IfId, Vec<u8>), DropReason> {
        self.io.inject(ingress, frame.clone());
        let now = MonotonicMillis(1_000);
        let batch = self.io.receive(1).unwrap();
        let report = if let Some(firewall_config) = &self.firewall_config {
            support::forward(
                batch,
                &self.snapshot,
                now,
                ruster_core::Services {
                    icmpv4_errors: Some(&mut self.errors),
                    nat44_udp: (Some(&mut self.udp)).map(|runtime| (&self.udp_config, runtime)),
                    nat44_tcp: (Some(&mut self.tcp)).map(|runtime| (&self.tcp_config, runtime)),
                    nat44_icmp: (Some((&self.icmp_config, Some(&mut self.icmp))))
                        .and_then(|(config, runtime)| runtime.map(|runtime| (config, runtime))),
                    firewall: (self.firewall.as_mut()).map(|runtime| (firewall_config, runtime)),
                    firewall_audit: None,
                    ..ruster_core::Services::default()
                },
                &mut self.trace,
            )
        } else {
            support::forward(
                batch,
                &self.snapshot,
                now,
                ruster_core::Services {
                    icmpv4_errors: Some(&mut self.errors),
                    nat44_udp: (Some(&mut self.udp)).map(|runtime| (&self.udp_config, runtime)),
                    nat44_tcp: (Some(&mut self.tcp)).map(|runtime| (&self.tcp_config, runtime)),
                    nat44_icmp: (Some(&mut self.icmp)).map(|runtime| (&self.icmp_config, runtime)),
                    ..ruster_core::Services::default()
                },
                &mut self.trace,
            )
        };
        assert!(report.invariants_hold());
        if let Some(tx) = self.io.pop_tx() {
            return Ok((tx.egress, tx.bytes));
        }
        let recycled = self.io.pop_recycled().expect("dropped");
        assert_eq!(recycled.bytes, frame, "a drop leaves the frame unchanged");
        match recycled.cause {
            RecycleCause::Forwarding(reason) => Err(reason),
            other => panic!("unexpected recycle {other:?}"),
        }
    }

    /// Mapping, peer/session, and firewall state counts.
    fn state(&self) -> [usize; 6] {
        let udp = self.udp.occupancy();
        let tcp = self.tcp.occupancy();
        let icmp = self.icmp.occupancy();
        [
            udp.mappings.occupied(),
            udp.peers.occupied(),
            tcp.mappings.occupied(),
            tcp.sessions.occupied(),
            icmp.mappings.occupied(),
            self.firewall
                .as_ref()
                .map_or(0, |firewall| firewall.occupancy().occupied()),
        ]
    }
}

fn mac_pair(ingress: IfId, source: Ipv4Address) -> (MacAddress, MacAddress) {
    match ingress {
        LAN => (LAN_MAC, if source == H2 { H2_MAC } else { H1_MAC }),
        _ => (WAN_MAC, GW_MAC),
    }
}

/// RFC 791 header (IHL 5, TOS 0) with a recomputed checksum.
#[allow(clippy::too_many_arguments)]
fn ipv4_frame(
    destination_mac: MacAddress,
    source_mac: MacAddress,
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
    frame[0..6].copy_from_slice(&destination_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&id.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = ttl;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34..].copy_from_slice(payload);
    frame
}

/// RFC 768/793 pseudo-header checksum over `segment` (checksum field zero).
fn transport_checksum(
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
    internet_checksum(&bytes)
}

fn udp_segment(
    source: Ipv4Address,
    destination: Ipv4Address,
    sport: u16,
    dport: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut segment = vec![0_u8; 8 + data.len()];
    segment[0..2].copy_from_slice(&sport.to_be_bytes());
    segment[2..4].copy_from_slice(&dport.to_be_bytes());
    let length = u16::try_from(segment.len()).unwrap();
    segment[4..6].copy_from_slice(&length.to_be_bytes());
    segment[8..].copy_from_slice(data);
    let checksum = match transport_checksum(source, destination, UDP, &segment) {
        0 => 0xffff,
        checksum => checksum,
    };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    segment
}

fn tcp_segment(
    source: Ipv4Address,
    destination: Ipv4Address,
    sport: u16,
    dport: u16,
    flags: u8,
) -> Vec<u8> {
    let mut segment = vec![0_u8; 20];
    segment[0..2].copy_from_slice(&sport.to_be_bytes());
    segment[2..4].copy_from_slice(&dport.to_be_bytes());
    segment[4..8].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    if flags & 0x10 != 0 {
        segment[8..12].copy_from_slice(&0x0a0b_0c0d_u32.to_be_bytes());
    }
    segment[12] = 0x50;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&65_535_u16.to_be_bytes());
    let checksum = transport_checksum(source, destination, TCP, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// A UDP datagram as received on `ingress`.
fn udp(
    ingress: IfId,
    source: Ipv4Address,
    destination: Ipv4Address,
    sport: u16,
    dport: u16,
    id: u16,
    flags_fragment: u16,
) -> Vec<u8> {
    let (dst_mac, src_mac) = mac_pair(ingress, source);
    let segment = udp_segment(source, destination, sport, dport, b"df-clear");
    ipv4_frame(
        dst_mac,
        src_mac,
        source,
        destination,
        id,
        flags_fragment,
        64,
        UDP,
        &segment,
    )
}

/// The frame the router must send: built from scratch, TTL 63, with the
/// given ID.
#[allow(clippy::too_many_arguments)]
fn expected_udp(
    destination_mac: MacAddress,
    source_mac: MacAddress,
    source: Ipv4Address,
    destination: Ipv4Address,
    sport: u16,
    dport: u16,
    id: u16,
    flags_fragment: u16,
) -> Vec<u8> {
    let segment = udp_segment(source, destination, sport, dport, b"df-clear");
    ipv4_frame(
        destination_mac,
        source_mac,
        source,
        destination,
        id,
        flags_fragment,
        63,
        UDP,
        &segment,
    )
}

fn id_of(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[18], frame[19]])
}

#[test]
fn df_clear_udp_translates_both_ways_with_generated_ids() {
    for firewall in [false, true] {
        let mut world = World::new(firewall, 1500);
        // Outbound: H1 sends ID 0x1111 without DF.
        let (egress, out) = world
            .run(LAN, udp(LAN, H1, REMOTE, P1, 53, 0x1111, 0))
            .unwrap();
        assert_eq!(egress, WAN);
        let first = id_of(&out);
        assert_eq!(
            out,
            expected_udp(GW_MAC, WAN_MAC, PUBLIC, REMOTE, P1, 53, first, 0)
        );
        // The next DF-clear datagram of (PUBLIC, REMOTE, UDP) takes the next
        // ID, even though the host repeats its ID.
        let (_, again) = world
            .run(LAN, udp(LAN, H1, REMOTE, P1, 53, 0x1111, 0))
            .unwrap();
        assert_eq!(
            again,
            expected_udp(
                GW_MAC,
                WAN_MAC,
                PUBLIC,
                REMOTE,
                P1,
                53,
                first.wrapping_add(1),
                0
            )
        );
        // An atomic datagram keeps its ID and consumes none (RFC 6864 §4.1).
        let (_, atomic) = world
            .run(LAN, udp(LAN, H1, REMOTE, P1, 53, 0x2222, DF))
            .unwrap();
        assert_eq!(
            atomic,
            expected_udp(GW_MAC, WAN_MAC, PUBLIC, REMOTE, P1, 53, 0x2222, DF)
        );
        // The reserved flag is ignored and preserved (NAT44-008).
        let (_, reserved) = world
            .run(LAN, udp(LAN, H1, REMOTE, P1, 53, 0x1111, 0x8000))
            .unwrap();
        assert_eq!(
            reserved,
            expected_udp(
                GW_MAC,
                WAN_MAC,
                PUBLIC,
                REMOTE,
                P1,
                53,
                first.wrapping_add(2),
                0x8000
            )
        );
        // Inbound: the DF-clear answer reaches H1 with an ID of the
        // (REMOTE, H1, UDP) tuple.
        let (egress, back) = world
            .run(WAN, udp(WAN, REMOTE, PUBLIC, 53, P1, 0x3333, 0))
            .unwrap();
        assert_eq!(egress, LAN);
        let inbound = id_of(&back);
        assert_eq!(
            back,
            expected_udp(H1_MAC, LAN_MAC, REMOTE, H1, 53, P1, inbound, 0)
        );
        let (_, back_again) = world
            .run(WAN, udp(WAN, REMOTE, PUBLIC, 53, P1, 0x3333, 0))
            .unwrap();
        assert_eq!(id_of(&back_again), inbound.wrapping_add(1));
        assert_eq!(world.state()[0], 1, "one mapping");
    }
}

#[test]
fn two_inside_hosts_with_the_same_id_get_distinct_ids() {
    let mut world = World::new(false, 1500);
    let (_, from_h1) = world
        .run(LAN, udp(LAN, H1, REMOTE, P1, 53, 0x4242, 0))
        .unwrap();
    let (_, from_h2) = world
        .run(LAN, udp(LAN, H2, REMOTE, P2, 53, 0x4242, 0))
        .unwrap();
    // Same translated tuple (PUBLIC, REMOTE, UDP): consecutive, so a
    // downstream reassembly cannot merge their fragments.
    assert_eq!(id_of(&from_h2), id_of(&from_h1).wrapping_add(1));
    assert_eq!(
        from_h2,
        expected_udp(GW_MAC, WAN_MAC, PUBLIC, REMOTE, P2, 53, id_of(&from_h2), 0)
    );
    // With DF set both keep the colliding ID: atomic IDs have no meaning.
    let (_, a) = world
        .run(LAN, udp(LAN, H1, REMOTE, P1, 53, 0x4242, DF))
        .unwrap();
    let (_, b) = world
        .run(LAN, udp(LAN, H2, REMOTE, P2, 53, 0x4242, DF))
        .unwrap();
    assert_eq!((id_of(&a), id_of(&b)), (0x4242, 0x4242));
}

#[test]
fn df_clear_tcp_translates_both_ways_with_generated_ids() {
    for firewall in [false, true] {
        let mut world = World::new(firewall, 1500);
        let syn = tcp_segment(H1, REMOTE, P1, 443, SYN);
        let (egress, out) = world
            .run(
                LAN,
                ipv4_frame(LAN_MAC, H1_MAC, H1, REMOTE, 0x0101, 0, 64, TCP, &syn),
            )
            .unwrap();
        assert_eq!(egress, WAN);
        let expected = ipv4_frame(
            GW_MAC,
            WAN_MAC,
            PUBLIC,
            REMOTE,
            id_of(&out),
            0,
            63,
            TCP,
            &tcp_segment(PUBLIC, REMOTE, P1, 443, SYN),
        );
        assert_eq!(out, expected);
        let syn_ack = tcp_segment(REMOTE, PUBLIC, 443, P1, SYN_ACK);
        let (egress, back) = world
            .run(
                WAN,
                ipv4_frame(
                    WAN_MAC, GW_MAC, REMOTE, PUBLIC, 0x0202, 0, 64, TCP, &syn_ack,
                ),
            )
            .unwrap();
        assert_eq!(egress, LAN);
        let expected = ipv4_frame(
            H1_MAC,
            LAN_MAC,
            REMOTE,
            H1,
            id_of(&back),
            0,
            63,
            TCP,
            &tcp_segment(REMOTE, H1, 443, P1, SYN_ACK),
        );
        assert_eq!(back, expected);
        assert_eq!(world.state()[2..4], [1, 1], "mapping and session");
    }
}

#[test]
fn df_clear_hairpin_reaches_the_other_host_with_a_generated_id() {
    let mut world = World::with_filtering(false, 1500, Nat44Filtering::EndpointIndependent);
    // H2's mapping PUBLIC:P2 exists after it sends outward.
    world.run(LAN, udp(LAN, H2, REMOTE, P2, 53, 1, DF)).unwrap();
    let (egress, delivered) = world
        .run(LAN, udp(LAN, H1, PUBLIC, P1, P2, 0x5151, 0))
        .unwrap();
    assert_eq!(egress, LAN);
    let id = id_of(&delivered);
    assert_eq!(
        delivered,
        expected_udp(H2_MAC, LAN_MAC, PUBLIC, H2, P1, P2, id, 0)
    );
    let (_, again) = world
        .run(LAN, udp(LAN, H1, PUBLIC, P1, P2, 0x5151, 0))
        .unwrap();
    assert_eq!(id_of(&again), id.wrapping_add(1), "tuple (PUBLIC, H2, UDP)");
}

#[test]
fn df_clear_errors_quoting_df_clear_datagrams_are_translated() {
    let mut world = World::new(false, 1500);
    let (_, out) = world
        .run(LAN, udp(LAN, H1, REMOTE, P1, 53, 0x1111, 0))
        .unwrap();
    // A router on the path quotes the translated datagram in a DF-clear
    // Time Exceeded (Linux sends errors without DF).
    let quote = out[14..14 + 28].to_vec();
    let mut icmp = vec![11, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&quote);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let error = ipv4_frame(WAN_MAC, GW_MAC, ROUTER, PUBLIC, 0x7777, 0, 64, 1, &icmp);
    let (egress, delivered) = world.run(WAN, error).unwrap();
    assert_eq!(egress, LAN);
    // The quote is reverted to what H1 sent (addresses, port, checksums),
    // except its ID, which stays the generated one (no reverse ID state;
    // hosts match errors by addresses and ports).
    let mut reverted = quote.clone();
    reverted[12..16].copy_from_slice(&H1.octets());
    reverted[10..12].fill(0);
    let checksum = ipv4_header_checksum(&reverted[..20]);
    reverted[10..12].copy_from_slice(&checksum.to_be_bytes());
    let original = udp_segment(H1, REMOTE, P1, 53, b"df-clear");
    reverted[20..28].copy_from_slice(&original[..8]);
    let mut icmp = vec![11, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&reverted);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let expected = ipv4_frame(
        H1_MAC,
        LAN_MAC,
        ROUTER,
        H1,
        id_of(&delivered),
        0,
        63,
        1,
        &icmp,
    );
    assert_eq!(delivered, expected);
    // A quote that is a fragment stays refused.
    let mut fragment = quote;
    fragment[6..8].copy_from_slice(&MF.to_be_bytes());
    fragment[10..12].fill(0);
    let checksum = ipv4_header_checksum(&fragment[..20]);
    fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
    let mut icmp = vec![11, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&fragment);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    assert_eq!(
        world.run(
            WAN,
            ipv4_frame(WAN_MAC, GW_MAC, ROUTER, PUBLIC, 0x7777, 0, 64, 1, &icmp)
        ),
        Err(DropReason::Nat44Icmpv4QuotedFragmentUnsupported)
    );
}

#[test]
fn fragments_stay_a_typed_drop_without_state_or_id() {
    // The firewall validates first, so it names the drop when bound.
    for (firewall, udp_reason, tcp_reason) in [
        (
            false,
            DropReason::Nat44UdpNonAtomicIpv4Unsupported,
            DropReason::Nat44TcpNonAtomicIpv4Unsupported,
        ),
        (
            true,
            DropReason::FirewallFragmentUnsupported,
            DropReason::FirewallFragmentUnsupported,
        ),
    ] {
        let mut world = World::new(firewall, 1500);
        for flags in [MF, 1, MF | 1, DF | 1, 0x8000 | MF] {
            assert_eq!(
                world.run(LAN, udp(LAN, H1, REMOTE, P1, 53, 9, flags)),
                Err(udp_reason)
            );
            let syn = tcp_segment(H1, REMOTE, P1, 443, SYN);
            assert_eq!(
                world.run(
                    LAN,
                    ipv4_frame(LAN_MAC, H1_MAC, H1, REMOTE, 9, flags, 64, TCP, &syn)
                ),
                Err(tcp_reason)
            );
        }
        assert_eq!(world.state(), [0; 6]);
        // The first DF-clear datagram after them still takes the first ID
        // of its tuple: H1's next one is consecutive.
        let (_, a) = world.run(LAN, udp(LAN, H1, REMOTE, P1, 53, 9, 0)).unwrap();
        let (_, b) = world.run(LAN, udp(LAN, H1, REMOTE, P1, 53, 9, 0)).unwrap();
        assert_eq!(id_of(&b), id_of(&a).wrapping_add(1));
    }
}

/// The firewall decides before translation and before any ID is taken: a
/// refused DF-clear datagram commits no NAT or firewall state and consumes
/// no ID of its tuple. So does one refused by the egress MTU.
#[test]
fn refused_df_clear_datagrams_commit_nothing_and_take_no_id() {
    let mut world = World::new(true, 1500);
    world.run(LAN, udp(LAN, H1, REMOTE, P1, 53, 1, DF)).unwrap();
    let (_, reply) = world
        .run(WAN, udp(WAN, REMOTE, PUBLIC, 53, P1, 2, 0))
        .unwrap();
    let state = world.state();
    let udp_counters = world.udp.counters();
    // Same remote address, another port: the NAT (address-dependent
    // filtering) admits it, the stateful firewall has no state for it.
    let denied = world.run(WAN, udp(WAN, REMOTE, PUBLIC, 54, P1, 3, 0));
    assert!(
        matches!(denied, Err(DropReason::FirewallDefaultDenied)),
        "{denied:?}"
    );
    assert_eq!(world.state(), state);
    assert_eq!(world.udp.counters(), udp_counters);
    let (_, next) = world
        .run(WAN, udp(WAN, REMOTE, PUBLIC, 53, P1, 4, 0))
        .unwrap();
    assert_eq!(id_of(&next), id_of(&reply).wrapping_add(1));

    // WAN MTU 68: a 96-byte DF-clear datagram is refused by the MTU check
    // (until fragmentation, NAT44-019L) after the NAT admitted it.
    let mut world = World::new(true, 68);
    let small = udp_segment(H1, REMOTE, P1, 53, b"");
    let fits = ipv4_frame(LAN_MAC, H1_MAC, H1, REMOTE, 5, 0, 64, UDP, &small);
    let (_, first) = world.run(LAN, fits.clone()).unwrap();
    let state = world.state();
    let large = udp_segment(H1, REMOTE, P1, 53, &[0x5a; 68]);
    assert_eq!(
        world.run(
            LAN,
            ipv4_frame(LAN_MAC, H1_MAC, H1, REMOTE, 6, 0, 64, UDP, &large)
        ),
        Err(DropReason::Ipv4FragmentationRequired)
    );
    assert_eq!(world.state(), state);
    let (_, second) = world.run(LAN, fits).unwrap();
    assert_eq!(id_of(&second), id_of(&first).wrapping_add(1));
}

fn icmp_message(icmp_type: u8, code: u8, word: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut icmp = vec![icmp_type, code, 0, 0];
    icmp.extend_from_slice(&word);
    icmp.extend_from_slice(body);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    icmp
}

/// ICMP queries and translated ICMPv4 errors share protocol 1, so they share
/// one ID sequence per translated tuple: the ICMP query runtime's.
#[test]
fn queries_and_translated_errors_share_the_icmp_sequence() {
    let mut world = World::new(false, 1500);
    world.run(LAN, udp(LAN, H1, REMOTE, P1, 53, 1, DF)).unwrap();
    let (_, answer) = world
        .run(WAN, udp(WAN, REMOTE, PUBLIC, 53, P1, 2, DF))
        .unwrap();
    let echo = icmp_message(8, 0, [0x9c, 0x40, 0, 1], b"ping");
    let (egress, query) = world
        .run(
            LAN,
            ipv4_frame(LAN_MAC, H1_MAC, H1, REMOTE, 0x0808, 0, 64, 1, &echo),
        )
        .unwrap();
    assert_eq!(egress, WAN);
    let first = id_of(&query);
    assert_eq!(
        query,
        ipv4_frame(GW_MAC, WAN_MAC, PUBLIC, REMOTE, first, 0, 63, 1, &echo),
        "identifier 40000 is preserved"
    );
    // H1's DF-clear Port Unreachable about the answer leaves as
    // (PUBLIC, REMOTE, ICMP) too: the next ID of the same sequence.
    let unreachable = icmp_message(3, 3, [0; 4], &answer[14..42]);
    let (egress, error) = world
        .run(
            LAN,
            ipv4_frame(LAN_MAC, H1_MAC, H1, REMOTE, 0x0303, 0, 64, 1, &unreachable),
        )
        .unwrap();
    assert_eq!(egress, WAN);
    assert_eq!(id_of(&error), first.wrapping_add(1));
    assert_eq!(ipv4_header_checksum(&error[14..34]), 0);
    assert_eq!(&error[26..30], &PUBLIC.octets());
}

impl World {
    /// Runs one frame through the UDP-only (`udp_only`) or TCP-only NAT
    /// composition: no ICMP query runtime is bound.
    fn run_single(
        &mut self,
        udp_only: bool,
        ingress: IfId,
        frame: Vec<u8>,
    ) -> Result<(IfId, Vec<u8>), DropReason> {
        self.io.inject(ingress, frame);
        let now = MonotonicMillis(1_000);
        let report = if udp_only {
            self.io.run_nat44_udp_once(
                1,
                &self.snapshot,
                &self.udp_config,
                Some(&mut self.udp),
                now,
                &mut self.trace,
            )
        } else {
            self.io.run_nat44_tcp_once(
                1,
                &self.snapshot,
                &self.tcp_config,
                Some(&mut self.tcp),
                now,
                &mut self.trace,
            )
        }
        .unwrap();
        assert!(report.invariants_hold());
        if let Some(tx) = self.io.pop_tx() {
            return Ok((tx.egress, tx.bytes));
        }
        match self.io.pop_recycled().expect("dropped").cause {
            RecycleCause::Forwarding(reason) => Err(reason),
            other => panic!("unexpected recycle {other:?}"),
        }
    }
}

/// Review M1/L1: inbound translations count apart from outbound ones, so no
/// amount of outside DF-clear traffic toward the inside advances the ID
/// sequence of an outbound tuple. 32768 outside sources (each its own
/// inbound tuple, spread over the 4096 buckets, so that a shared array would
/// put one in the outbound tuple's bucket with probability about
/// 1 - e^-8) send DF-clear datagrams to
/// H1's mapping; H1's next outbound DF-clear datagram still takes the next
/// ID of (PUBLIC, REMOTE, UDP). With one shared array some of those inbound
/// tuples would share that tuple's bucket and skip its sequence.
#[test]
fn inbound_df_clear_volume_never_advances_an_outbound_sequence() {
    let mut world = World::with_filtering(false, 1500, Nat44Filtering::EndpointIndependent);
    let (_, first) = world.run(LAN, udp(LAN, H1, REMOTE, P1, 53, 1, 0)).unwrap();
    for n in 0..32_768_u16 {
        let [high, low] = n.to_be_bytes();
        let source = Ipv4Address::from_octets([198, 18, high, low | 1]);
        let (egress, _) = world
            .run(WAN, udp(WAN, source, PUBLIC, 53, P1, n, 0))
            .unwrap();
        assert_eq!(egress, LAN);
    }
    let (_, next) = world.run(LAN, udp(LAN, H1, REMOTE, P1, 53, 1, 0)).unwrap();
    assert_eq!(id_of(&next), id_of(&first).wrapping_add(1));
}

/// Review L2: without an ICMP query runtime, protocol 1 (translated errors)
/// takes its IDs from the UDP runtime, or the TCP one when it is alone; a
/// DF-clear error is translated with consecutive generated IDs, never
/// refused.
#[test]
fn translated_errors_without_the_icmp_runtime_get_generated_ids() {
    for udp_only in [true, false] {
        let mut world = World::new(false, 1500);
        let out = if udp_only {
            world
                .run_single(true, LAN, udp(LAN, H1, REMOTE, P1, 53, 1, 0))
                .unwrap()
                .1
        } else {
            let syn = tcp_segment(H1, REMOTE, P1, 443, SYN);
            world
                .run_single(
                    false,
                    LAN,
                    ipv4_frame(LAN_MAC, H1_MAC, H1, REMOTE, 1, 0, 64, TCP, &syn),
                )
                .unwrap()
                .1
        };
        let icmp = icmp_message(11, 0, [0; 4], &out[14..42]);
        let error = ipv4_frame(WAN_MAC, GW_MAC, ROUTER, PUBLIC, 0x7777, 0, 64, 1, &icmp);
        let (egress, a) = world.run_single(udp_only, WAN, error.clone()).unwrap();
        assert_eq!(egress, LAN);
        let (_, b) = world.run_single(udp_only, WAN, error).unwrap();
        assert_eq!(id_of(&b), id_of(&a).wrapping_add(1), "udp_only={udp_only}");
        assert_eq!(ipv4_header_checksum(&a[14..34]), 0);
        assert_eq!(&a[30..34], &H1.octets());
    }
}

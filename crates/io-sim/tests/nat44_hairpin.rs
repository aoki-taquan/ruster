//! NAT44 hairpinning (RFC 4787 §6 REQ-9, REQ-9 a; RFC 5382 §7.2 REQ-8)
//! through the full packet path, with and without the firewall.
//!
//! A hairpinned packet is two NAT traversals: the outbound half (the
//! sender's mapping and filter state, exactly as for an ordinary outbound
//! packet to the router's public address) and the inbound half (the
//! destination mapping's filtering and the firewall, exactly as for an
//! ordinary inbound packet from the sender's external endpoint). A refused
//! inbound half keeps the outbound half, which is what hole punching between
//! two hosts behind the same NAT relies on (RFC 5128 §3.3.2 for UDP, §3.4
//! for TCP simultaneous open).

mod support;

use ruster_core::{
    internet_checksum, ipv4_header_checksum, DropReason, FirewallAction, FirewallAuditBuffer,
    FirewallAuditRecord, FirewallConfig, FirewallConnectionClass, FirewallHashKey,
    FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange, FirewallProtocol,
    FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot, FirewallVerdict,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Nat44Filtering, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig, Nat44TcpMappingSlot,
    Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpMappingSlot,
    Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, NoTrace, ResolutionActionSlot,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
};
use ruster_io_sim::{RecycleCause, SimIo};
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
/// Inside host without a static neighbor (dynamic resolution only).
const H3: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 12]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const FIRST_PORT: u16 = 40_000;
const LAST_PORT: u16 = 40_015;
/// Internal ports outside the pool, so public ports are allocated, not
/// preserved, and the external source is distinguishable from the internal.
const P1: u16 = 5001;
const P2: u16 = 5002;
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const MODES: [Nat44Filtering; 3] = [
    Nat44Filtering::EndpointIndependent,
    Nat44Filtering::AddressDependent,
    Nat44Filtering::AddressAndPortDependent,
];

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

fn snapshot() -> ForwardingSnapshot<'static> {
    let routes = leak([
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GW)).unwrap(),
    ]);
    let interfaces = leak([
        Interface {
            id: LAN,
            mac: LAN_MAC,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
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

fn any() -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap()
}

fn lan_prefix() -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24).unwrap()
}

fn ports(first: u16, last: u16) -> FirewallPortRange {
    FirewallPortRange::new(first, last).unwrap()
}

fn rule(
    id: u32,
    protocol: FirewallProtocol,
    destination_ports: FirewallPortRange,
    action: FirewallAction,
) -> FirewallRule {
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(LAN),
        FirewallInterface::Interface(WAN),
        lan_prefix(),
        any(),
        protocol,
        ports(0, u16::MAX),
        destination_ports,
        action,
    )
}

/// The M1 shape: inside to outside UDP/TCP allowed statefully, nothing
/// admitted from outside to inside except established return traffic.
fn outbound_only_rules() -> Vec<FirewallRule> {
    vec![
        rule(
            20,
            FirewallProtocol::Udp,
            ports(1, u16::MAX),
            FirewallAction::AllowStateful,
        ),
        rule(
            30,
            FirewallProtocol::Tcp,
            ports(1, u16::MAX),
            FirewallAction::AllowStateful,
        ),
    ]
}

struct World {
    snapshot: ForwardingSnapshot<'static>,
    udp_config: Nat44UdpConfig,
    tcp_config: Nat44TcpConfig,
    udp: Nat44UdpRuntime<'static>,
    tcp: Nat44TcpRuntime<'static>,
    firewall_config: Option<FirewallConfig<'static>>,
    firewall: Option<FirewallRuntime<'static>>,
    resolution: ResolutionRuntime<'static>,
    io: SimIo,
    now: u64,
}

/// Knobs of one test world beyond filtering, the switch, and the rules.
#[derive(Clone, Copy)]
struct Shape {
    udp_peers: usize,
    tcp_sessions: usize,
    icmpv4_errors: Nat44Icmpv4ErrorPolicy,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            udp_peers: 8,
            tcp_sessions: 8,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Disabled,
        }
    }
}

impl World {
    fn new(filtering: Nat44Filtering, hairpinning: bool, rules: Option<Vec<FirewallRule>>) -> Self {
        Self::shaped(filtering, hairpinning, rules, Shape::default())
    }

    fn shaped(
        filtering: Nat44Filtering,
        hairpinning: bool,
        rules: Option<Vec<FirewallRule>>,
        shape: Shape,
    ) -> Self {
        let snapshot = snapshot();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            FIRST_PORT,
            LAST_PORT,
            Nat44UdpPolicy::default()
                .with_filtering(filtering)
                .with_hairpinning(hairpinning)
                .with_icmpv4_errors(shape.icmpv4_errors),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            FIRST_PORT,
            LAST_PORT,
            Nat44TcpPolicy::default()
                .with_filtering(filtering)
                .with_hairpinning(hairpinning)
                .with_icmpv4_errors(shape.icmpv4_errors),
        )
        .unwrap();
        let indexes = leak(UdpTestIndexes::new(udp_config, 4, shape.udp_peers));
        let udp = indexes.runtime(
            udp_config,
            leak([Nat44UdpMappingSlot::default(); 4]),
            Vec::leak(vec![Nat44UdpPeerSlot::default(); shape.udp_peers]),
        );
        let tcp = support::tcp_runtime(
            tcp_config,
            leak([Nat44TcpMappingSlot::default(); 4]),
            Vec::leak(vec![Nat44TcpSessionSlot::default(); shape.tcp_sessions]),
        );
        let (firewall_config, firewall) = match rules {
            Some(rules) => {
                let config = FirewallConfig::new(
                    &snapshot,
                    Vec::leak(rules),
                    FirewallPolicy::default(),
                    1,
                    FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
                )
                .unwrap();
                let runtime =
                    FirewallRuntime::new(config, leak([FirewallStateSlot::default(); 16]));
                (Some(config), Some(runtime))
            }
            None => (None, None),
        };
        let resolution = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            leak([ResolutionStateSlot::EMPTY; 2]),
            leak([ResolutionActionSlot::EMPTY; 2]),
        );
        Self {
            snapshot,
            udp_config,
            tcp_config,
            udp,
            tcp,
            firewall_config,
            firewall,
            resolution,
            io: SimIo::new(),
            now: 0,
        }
    }

    fn run(&mut self, ingress: IfId, packet: Vec<u8>) {
        self.io.inject(ingress, packet);
        let now = MonotonicMillis(self.now);
        self.now += 1;
        if let Some(firewall_config) = &self.firewall_config {
            self.io
                .run_nat44_udp_and_tcp_with_firewall_once(
                    1,
                    &self.snapshot,
                    &mut self.resolution,
                    &self.udp_config,
                    Some(&mut self.udp),
                    &self.tcp_config,
                    Some(&mut self.tcp),
                    firewall_config,
                    self.firewall.as_mut(),
                    now,
                    &mut NoTrace,
                )
                .unwrap();
        } else {
            self.io
                .run_nat44_udp_and_tcp_once(
                    1,
                    &self.snapshot,
                    &mut self.resolution,
                    &self.udp_config,
                    Some(&mut self.udp),
                    &self.tcp_config,
                    Some(&mut self.tcp),
                    now,
                    &mut NoTrace,
                )
                .unwrap();
        }
    }

    fn run_audited(&mut self, ingress: IfId, packet: Vec<u8>, audit: &mut FirewallAuditBuffer<'_>) {
        self.io.inject(ingress, packet);
        let now = MonotonicMillis(self.now);
        self.now += 1;
        self.io
            .run_nat44_udp_and_tcp_with_firewall_audited_once(
                1,
                &self.snapshot,
                &mut self.resolution,
                &self.udp_config,
                Some(&mut self.udp),
                &self.tcp_config,
                Some(&mut self.tcp),
                self.firewall_config.as_ref().unwrap(),
                self.firewall.as_mut(),
                audit,
                now,
                &mut NoTrace,
            )
            .unwrap();
    }

    /// Sends `host:port` to REMOTE and returns the allocated public port.
    fn establish(&mut self, host: Ipv4Address, port: u16, tcp: bool) -> u16 {
        let packet = if tcp {
            tcp_frame(host, REMOTE, port, 443, SYN)
        } else {
            udp_frame(host, REMOTE, port, 53)
        };
        self.run(LAN, packet);
        let tx = self.io.pop_tx().expect("outbound translation");
        assert_eq!(tx.egress, WAN);
        assert_eq!(&tx.bytes[26..30], &PUBLIC.octets());
        u16::from_be_bytes([tx.bytes[34], tx.bytes[35]])
    }

    fn state(&self) -> State {
        State {
            udp_mappings: self.udp.mappings().to_vec(),
            udp_peers: self.udp.peers().to_vec(),
            tcp_mappings: self.tcp.mappings().to_vec(),
            tcp_sessions: self.tcp.sessions().to_vec(),
            firewall: self
                .firewall
                .as_ref()
                .map(|firewall| firewall.states().to_vec())
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct State {
    udp_mappings: Vec<Nat44UdpMappingSlot>,
    udp_peers: Vec<Nat44UdpPeerSlot>,
    tcp_mappings: Vec<Nat44TcpMappingSlot>,
    tcp_sessions: Vec<Nat44TcpSessionSlot>,
    firewall: Vec<FirewallStateSlot>,
}

fn transport_checksum(
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let mut bytes = Vec::with_capacity(12 + segment.len());
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[0, protocol]);
    bytes.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(segment);
    let checksum = internet_checksum(&bytes);
    if protocol == 17 && checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

/// Atomic (DF=1) IPv4 frame from an inside host to the LAN interface MAC
/// (or from outside to the WAN MAC). `flags` is `None` for UDP.
fn frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags: Option<u8>,
) -> Vec<u8> {
    let transport_len = if flags.is_some() { 20 } else { 12 };
    let total_len = 20 + transport_len;
    let mut frame = vec![0_u8; 14 + total_len];
    let (ingress_mac, source_mac) = if source.octets()[0] == 10 {
        (LAN_MAC, if source == H2 { H2_MAC } else { H1_MAC })
    } else {
        (WAN_MAC, GW_MAC)
    };
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = if flags.is_some() { 6 } else { 17 };
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    if let Some(flags) = flags {
        frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
        frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
        frame[46] = 5 << 4;
        frame[47] = flags;
        frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
        let checksum = transport_checksum(source, destination, 6, &frame[34..54]);
        frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    } else {
        frame[38..40].copy_from_slice(&12_u16.to_be_bytes());
        frame[42..46].copy_from_slice(b"ping");
        let checksum = transport_checksum(source, destination, 17, &frame[34..46]);
        frame[40..42].copy_from_slice(&checksum.to_be_bytes());
    }
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn udp_frame(source: Ipv4Address, destination: Ipv4Address, sport: u16, dport: u16) -> Vec<u8> {
    frame(source, destination, sport, dport, None)
}

fn tcp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    sport: u16,
    dport: u16,
    flags: u8,
) -> Vec<u8> {
    frame(source, destination, sport, dport, Some(flags))
}

fn assert_drop(world: &mut World, reason: DropReason, original: &[u8]) {
    let recycled = world.io.pop_recycled().expect("dropped packet");
    assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
    assert_eq!(recycled.bytes, original, "drops are byte-unchanged");
    assert!(world.io.pop_tx().is_none());
}

/// Asserts one hairpinned TX back into the inside realm: Ethernet rewritten
/// toward `destination_mac`, TTL decremented once, the external source
/// tuple, the internal destination tuple, IP ID/payload preserved, and both
/// checksums valid (the incremental RFC 1624 result equals a full
/// recomputation).
fn assert_hairpin(
    world: &mut World,
    original: &[u8],
    destination_mac: MacAddress,
    (source, source_port): (Ipv4Address, u16),
    (destination, destination_port): (Ipv4Address, u16),
) {
    assert!(world.io.pop_recycled().is_none());
    let tx = world.io.pop_tx().expect("hairpinned packet");
    assert_eq!(tx.egress, LAN);
    let bytes = &tx.bytes;
    assert_eq!(bytes.len(), original.len());
    assert_eq!(&bytes[0..6], &destination_mac.0);
    assert_eq!(&bytes[6..12], &LAN_MAC.0);
    assert_eq!(bytes[22], original[22] - 1, "TTL");
    assert_eq!(&bytes[18..22], &original[18..22], "IP ID and flags");
    assert_eq!(&bytes[26..30], &source.octets());
    assert_eq!(&bytes[30..34], &destination.octets());
    assert_eq!(&bytes[34..36], &source_port.to_be_bytes());
    assert_eq!(&bytes[36..38], &destination_port.to_be_bytes());
    assert_eq!(ipv4_header_checksum(&bytes[14..34]), 0, "IPv4 checksum");
    let protocol = bytes[23];
    let mut recomputed = bytes[34..].to_vec();
    let checksum_offset = if protocol == 6 { 16 } else { 6 };
    recomputed[checksum_offset..checksum_offset + 2].fill(0);
    assert_eq!(
        transport_checksum(source, destination, protocol, &recomputed).to_be_bytes(),
        [bytes[34 + checksum_offset], bytes[35 + checksum_offset]],
        "transport checksum"
    );
    // Everything else (TCP sequence/flags/window, UDP length/payload) is
    // preserved.
    if protocol == 6 {
        assert_eq!(&bytes[38..50], &original[38..50]);
        assert_eq!(&bytes[52..], &original[52..]);
    } else {
        assert_eq!(&bytes[38..40], &original[38..40]);
        assert_eq!(&bytes[42..], &original[42..]);
    }
}

/// UDP hairpin between two inside hosts under endpoint-independent
/// filtering: the receiver sees the sender's external address and port
/// (REQ-9 a), and the outbound half reuses the sender's existing mapping.
#[test]
fn udp_hairpin_between_hosts_presents_the_external_source() {
    let mut world = World::new(Nat44Filtering::EndpointIndependent, true, None);
    let public1 = world.establish(H1, P1, false);
    let public2 = world.establish(H2, P2, false);
    let before = world.udp.counters();

    let packet = udp_frame(H1, PUBLIC, P1, public2);
    world.run(LAN, packet.clone());
    assert_hairpin(&mut world, &packet, H2_MAC, (PUBLIC, public1), (H2, P2));
    let after = world.udp.counters();
    assert_eq!(after.hairpin_translated, before.hairpin_translated + 1);
    // The hairpin is neither an outbound nor an inbound translation, and the
    // sender's mapping is reused (EIM), not duplicated.
    assert_eq!(after.outbound_translated, before.outbound_translated);
    assert_eq!(after.inbound_translated, before.inbound_translated);
    assert_eq!(after.mappings_created, before.mappings_created);
    assert_eq!(after.mappings_reused, before.mappings_reused + 1);
    assert_eq!(after.peers_created, before.peers_created + 1);

    // A sender without a mapping gets one per the normal outbound rules.
    let mut world = World::new(Nat44Filtering::EndpointIndependent, true, None);
    let public2 = world.establish(H2, P2, false);
    let packet = udp_frame(H1, PUBLIC, P1, public2);
    world.run(LAN, packet.clone());
    let tx = world.io.pop_tx().unwrap();
    let public1 = u16::from_be_bytes([tx.bytes[34], tx.bytes[35]]);
    assert_ne!(public1, public2);
    assert!((FIRST_PORT..=LAST_PORT).contains(&public1));
    assert_eq!(world.udp.counters().mappings_created, 2);
    // The new external mapping is H1's ordinary mapping: an outbound packet
    // to an external host now uses the same public port.
    assert_eq!(world.establish(H1, P1, false), public1);
}

/// UDP hole punching through the same NAT under address-dependent and
/// address-and-port-dependent filtering: the first packet is refused by the
/// destination mapping's filter but commits the sender's outbound half; the
/// reply then passes, and so does the next packet (RFC 5128 §3.3.2).
#[test]
fn udp_hairpin_hole_punching_under_dependent_filtering() {
    for filtering in [
        Nat44Filtering::AddressDependent,
        Nat44Filtering::AddressAndPortDependent,
    ] {
        let mut world = World::new(filtering, true, None);
        let public1 = world.establish(H1, P1, false);
        let public2 = world.establish(H2, P2, false);
        let before = world.udp.counters();

        let first = udp_frame(H1, PUBLIC, P1, public2);
        world.run(LAN, first.clone());
        assert_drop(&mut world, DropReason::Nat44UdpHairpinFiltered, &first);
        let after = world.udp.counters();
        assert_eq!(
            after.peers_created,
            before.peers_created + 1,
            "{filtering:?}"
        );
        assert_eq!(after.hairpin_inbound_refused, 1);
        assert_eq!(after.hairpin_translated, 0);
        // A hairpin refusal is not also an ordinary inbound filter denial.
        assert_eq!(after.filter_denied, before.filter_denied);

        let reply = udp_frame(H2, PUBLIC, P2, public1);
        world.run(LAN, reply.clone());
        assert_hairpin(&mut world, &reply, H1_MAC, (PUBLIC, public2), (H1, P1));

        world.run(LAN, first.clone());
        assert_hairpin(&mut world, &first, H2_MAC, (PUBLIC, public1), (H2, P2));
        assert_eq!(world.udp.counters().hairpin_translated, 2);
    }

    // Under endpoint-independent filtering the first packet already passes.
    let mut world = World::new(Nat44Filtering::EndpointIndependent, true, None);
    let public1 = world.establish(H1, P1, false);
    let public2 = world.establish(H2, P2, false);
    let first = udp_frame(H1, PUBLIC, P1, public2);
    world.run(LAN, first.clone());
    assert_hairpin(&mut world, &first, H2_MAC, (PUBLIC, public1), (H2, P2));
}

/// A host addressing its own public mapping gets the packet back with its
/// own external endpoint as source, in every filtering mode: the inbound
/// half is evaluated after the outbound half recorded the public address.
#[test]
fn udp_and_tcp_self_hairpin_works_in_every_mode() {
    for filtering in MODES {
        let mut world = World::new(filtering, true, None);
        let public1 = world.establish(H1, P1, false);
        let packet = udp_frame(H1, PUBLIC, P1, public1);
        world.run(LAN, packet.clone());
        assert_hairpin(&mut world, &packet, H1_MAC, (PUBLIC, public1), (H1, P1));

        let public1 = world.establish(H1, P1, true);
        let syn = tcp_frame(H1, PUBLIC, P1, public1, SYN);
        world.run(LAN, syn.clone());
        assert_hairpin(&mut world, &syn, H1_MAC, (PUBLIC, public1), (H1, P1));
        assert_eq!(world.tcp.counters().hairpin_translated, 1, "{filtering:?}");
    }
}

/// TCP hairpin (RFC 5382 REQ-8): under endpoint-independent filtering the
/// first SYN reaches the other host from the sender's external endpoint;
/// under the dependent modes the first SYN is refused but opens the
/// sender's session, and the peer's SYN then completes a simultaneous open.
#[test]
fn tcp_hairpin_between_hosts_and_hole_punching() {
    for filtering in MODES {
        let mut world = World::new(filtering, true, None);
        let public1 = world.establish(H1, P1, true);
        let public2 = world.establish(H2, P2, true);
        let syn1 = tcp_frame(H1, PUBLIC, P1, public2, SYN);
        world.run(LAN, syn1.clone());
        if filtering == Nat44Filtering::EndpointIndependent {
            assert_hairpin(&mut world, &syn1, H2_MAC, (PUBLIC, public1), (H2, P2));
            let syn_ack = tcp_frame(H2, PUBLIC, P2, public1, SYN_ACK);
            world.run(LAN, syn_ack.clone());
            assert_hairpin(&mut world, &syn_ack, H1_MAC, (PUBLIC, public2), (H1, P1));
        } else {
            assert_drop(&mut world, DropReason::Nat44TcpHairpinFiltered, &syn1);
            let counters = world.tcp.counters();
            assert_eq!(counters.hairpin_inbound_refused, 1);
            // The outbound half committed H1's session toward P:public2.
            assert_eq!(counters.sessions_created, 3, "{filtering:?}");
            assert_eq!(counters.session_misses, 0);

            let syn2 = tcp_frame(H2, PUBLIC, P2, public1, SYN);
            world.run(LAN, syn2.clone());
            assert_hairpin(&mut world, &syn2, H1_MAC, (PUBLIC, public2), (H1, P1));
            let syn_ack = tcp_frame(H1, PUBLIC, P1, public2, SYN_ACK);
            world.run(LAN, syn_ack.clone());
            assert_hairpin(&mut world, &syn_ack, H2_MAC, (PUBLIC, public1), (H2, P2));
        }
        let ack = tcp_frame(H1, PUBLIC, P1, public2, ACK);
        world.run(LAN, ack.clone());
        assert_hairpin(&mut world, &ack, H2_MAC, (PUBLIC, public1), (H2, P2));

        // Without a session, a non-SYN cannot open the outbound half.
        let stray = tcp_frame(H1, PUBLIC, P1 + 100, public2, ACK);
        let state = world.state();
        world.run(LAN, stray.clone());
        assert_drop(&mut world, DropReason::Nat44TcpInvalidInitialFlags, &stray);
        assert_eq!(world.state(), state);
    }
}

/// With the firewall bound, each half is evaluated as the ordinary traversal
/// it stands for: the outbound half as ingress LAN, egress WAN, pre-SNAT
/// X1:x1 -> P:x2'; the inbound half as ingress WAN, egress LAN, post-DNAT
/// P:x1' -> X2:x2. With an outbound-only policy (M1), the first packet is
/// refused by the firewall like any unsolicited inbound flow, but its
/// outbound half commits; the reply then matches that state as established.
#[test]
fn firewall_evaluates_each_half_like_the_ordinary_traversal() {
    let mut world = World::new(
        Nat44Filtering::EndpointIndependent,
        true,
        Some(outbound_only_rules()),
    );
    let public1 = world.establish(H1, P1, false);
    let public2 = world.establish(H2, P2, false);
    let firewall_before = world.firewall.as_ref().unwrap().counters();
    let storage = leak([FirewallAuditRecord::default(); 4]);
    let mut audit = FirewallAuditBuffer::new(storage);

    let first = udp_frame(H1, PUBLIC, P1, public2);
    world.run_audited(LAN, first.clone(), &mut audit);
    assert_drop(&mut world, DropReason::FirewallDefaultDenied, &first);
    let records = audit.records();
    assert_eq!(records.len(), 2);
    let outbound = records[0];
    assert_eq!((outbound.ingress, outbound.egress), (LAN, WAN));
    assert_eq!((outbound.source, outbound.source_port), (H1, P1));
    assert_eq!(
        (outbound.destination, outbound.destination_port),
        (PUBLIC, public2)
    );
    assert_eq!(outbound.disposition.verdict, FirewallVerdict::Allow);
    assert_eq!(outbound.disposition.class, FirewallConnectionClass::New);
    let inbound = records[1];
    assert_eq!((inbound.ingress, inbound.egress), (WAN, LAN));
    assert_eq!((inbound.source, inbound.source_port), (PUBLIC, public1));
    assert_eq!((inbound.destination, inbound.destination_port), (H2, P2));
    assert_eq!(inbound.disposition.verdict, FirewallVerdict::Drop);
    let firewall = world.firewall.as_ref().unwrap().counters();
    assert_eq!(firewall.allowed_new, firewall_before.allowed_new + 1);
    assert_eq!(firewall.denied_default, firewall_before.denied_default + 1);
    assert_eq!(world.udp.counters().hairpin_inbound_refused, 1);

    audit.clear();
    let reply = udp_frame(H2, PUBLIC, P2, public1);
    world.run_audited(LAN, reply.clone(), &mut audit);
    assert_hairpin(&mut world, &reply, H1_MAC, (PUBLIC, public2), (H1, P1));
    let records = audit.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].disposition.class, FirewallConnectionClass::New);
    assert_eq!(
        records[1].disposition.class,
        FirewallConnectionClass::Established
    );

    audit.clear();
    world.run_audited(LAN, first.clone(), &mut audit);
    assert_hairpin(&mut world, &first, H2_MAC, (PUBLIC, public1), (H2, P2));
    assert!(audit
        .records()
        .iter()
        .all(|record| record.disposition.class == FirewallConnectionClass::Established));
}

/// Under the default filtering and the M1 firewall, hole punching works for
/// UDP and for TCP simultaneous open: NAT filter and firewall each refuse
/// only what they would refuse from an external host at the sender's
/// external endpoint.
#[test]
fn default_filtering_and_m1_firewall_support_hole_punching() {
    let mut world = World::new(
        Nat44Filtering::AddressDependent,
        true,
        Some(outbound_only_rules()),
    );
    let public1 = world.establish(H1, P1, false);
    let public2 = world.establish(H2, P2, false);
    let first = udp_frame(H1, PUBLIC, P1, public2);
    let state = world.state();
    world.run(LAN, first.clone());
    assert_drop(&mut world, DropReason::Nat44UdpHairpinFiltered, &first);
    assert_ne!(world.state(), state, "the outbound half committed");
    let reply = udp_frame(H2, PUBLIC, P2, public1);
    world.run(LAN, reply.clone());
    assert_hairpin(&mut world, &reply, H1_MAC, (PUBLIC, public2), (H1, P1));
    world.run(LAN, first.clone());
    assert_hairpin(&mut world, &first, H2_MAC, (PUBLIC, public1), (H2, P2));

    let public1 = world.establish(H1, P1, true);
    let public2 = world.establish(H2, P2, true);
    let syn1 = tcp_frame(H1, PUBLIC, P1, public2, SYN);
    world.run(LAN, syn1.clone());
    assert_drop(&mut world, DropReason::Nat44TcpHairpinFiltered, &syn1);
    let syn2 = tcp_frame(H2, PUBLIC, P2, public1, SYN);
    world.run(LAN, syn2.clone());
    assert_hairpin(&mut world, &syn2, H1_MAC, (PUBLIC, public2), (H1, P1));
    let syn_ack = tcp_frame(H1, PUBLIC, P1, public2, SYN_ACK);
    world.run(LAN, syn_ack.clone());
    assert_hairpin(&mut world, &syn_ack, H2_MAC, (PUBLIC, public1), (H2, P2));
}

/// A firewall deny of the outbound half (a rule an ordinary outbound packet
/// to the public address would hit) commits nothing at all: hairpin is not a
/// way around the inside-to-outside policy.
#[test]
fn firewall_deny_of_the_outbound_half_commits_nothing() {
    for tcp in [false, true] {
        let mut rules = outbound_only_rules();
        let protocol = if tcp {
            FirewallProtocol::Tcp
        } else {
            FirewallProtocol::Udp
        };
        let mut world = World::new(Nat44Filtering::EndpointIndependent, true, None);
        let public2 = world.establish(H2, P2, tcp);
        rules.insert(
            0,
            rule(5, protocol, ports(public2, public2), FirewallAction::Deny),
        );
        // Rebuild with the firewall; H2's mapping must exist first.
        let mut world = World::new(Nat44Filtering::EndpointIndependent, true, Some(rules));
        assert_eq!(world.establish(H2, P2, tcp), public2);
        let state = world.state();
        let udp_before = world.udp.counters();
        let tcp_before = world.tcp.counters();
        let packet = if tcp {
            tcp_frame(H1, PUBLIC, P1, public2, SYN)
        } else {
            udp_frame(H1, PUBLIC, P1, public2)
        };
        world.run(LAN, packet.clone());
        assert_drop(&mut world, DropReason::FirewallRuleDenied, &packet);
        assert_eq!(world.state(), state);
        assert_eq!(
            world.udp.counters().mappings_created,
            udp_before.mappings_created
        );
        assert_eq!(
            world.tcp.counters().sessions_created,
            tcp_before.sessions_created
        );
        assert_eq!(world.udp.counters().hairpin_inbound_refused, 0);
        assert_eq!(world.tcp.counters().hairpin_inbound_refused, 0);
    }
}

/// Hairpinning off (an RFC 1812 §1.1.3 security option; the default is on):
/// a typed, byte-unchanged drop that commits no NAT, firewall, or
/// resolution state, counted per protocol.
#[test]
fn hairpinning_disabled_is_a_typed_drop_without_state() {
    for rules in [None, Some(outbound_only_rules())] {
        let with_firewall = rules.is_some();
        let mut world = World::new(Nat44Filtering::EndpointIndependent, false, rules);
        let public2 = world.establish(H2, P2, false);
        let tcp_public2 = world.establish(H2, P2, true);
        let state = world.state();
        let packet = udp_frame(H1, PUBLIC, P1, public2);
        world.run(LAN, packet.clone());
        assert_drop(&mut world, DropReason::Nat44UdpHairpinDisabled, &packet);
        let segment = tcp_frame(H1, PUBLIC, P1, tcp_public2, SYN);
        world.run(LAN, segment.clone());
        assert_drop(&mut world, DropReason::Nat44TcpHairpinDisabled, &segment);
        assert_eq!(world.state(), state, "firewall bound: {with_firewall}");
        assert_eq!(world.udp.counters().hairpin_disabled, 1);
        assert_eq!(world.tcp.counters().hairpin_disabled, 1);
        // Ordinary translation is unaffected by the switch.
        world.run(LAN, udp_frame(H1, REMOTE, P1, 53));
        assert_eq!(world.io.pop_tx().unwrap().egress, WAN);
    }
}

/// Unknown destination mappings and malformed packets keep the existing
/// fail-closed behavior and commit nothing, not even an outbound half.
#[test]
fn unknown_mapping_and_malformed_hairpin_packets_fail_closed() {
    for rules in [None, Some(outbound_only_rules())] {
        let mut world = World::new(Nat44Filtering::EndpointIndependent, true, rules);
        let public2 = world.establish(H2, P2, false);
        let tcp_public2 = world.establish(H2, P2, true);
        let unused = (FIRST_PORT..=LAST_PORT)
            .find(|port| *port != public2 && *port != tcp_public2)
            .unwrap();
        let mut short_udp = udp_frame(H1, PUBLIC, P1, public2);
        short_udp[38..40].copy_from_slice(&4_u16.to_be_bytes());
        let mut bad_tcp = tcp_frame(H1, PUBLIC, P1, tcp_public2, SYN);
        bad_tcp[51] ^= 0xff;
        let mut ttl_one = udp_frame(H1, PUBLIC, P1, public2);
        ttl_one[22] = 1;
        ttl_one[24..26].fill(0);
        let checksum = ipv4_header_checksum(&ttl_one[14..34]);
        ttl_one[24..26].copy_from_slice(&checksum.to_be_bytes());
        let mut zero_port = udp_frame(H1, PUBLIC, 0, public2);
        zero_port[40..42].fill(0);
        let cases = [
            (
                udp_frame(H1, PUBLIC, P1, unused),
                DropReason::Nat44UdpMappingMiss,
            ),
            (
                tcp_frame(H1, PUBLIC, P1, unused, SYN),
                DropReason::Nat44TcpMappingMiss,
            ),
            (ttl_one, DropReason::Ipv4TtlExpired),
            (zero_port, DropReason::Nat44UdpSourcePortZero),
        ];
        let firewall = world.firewall_config.is_some();
        for (packet, reason) in cases {
            let state = world.state();
            world.run(LAN, packet.clone());
            assert_drop(&mut world, reason, &packet);
            assert_eq!(world.state(), state, "{reason:?}");
        }
        // Malformed transport fails in the firewall preflight when one is
        // bound, otherwise in NAT validation; neither commits state.
        for (packet, nat_reason, firewall_reason) in [
            (
                short_udp,
                DropReason::Nat44UdpLengthTooSmall,
                DropReason::FirewallUdpLengthTooSmall,
            ),
            (
                bad_tcp,
                DropReason::Nat44TcpChecksumInvalid,
                DropReason::FirewallTcpChecksumInvalid,
            ),
        ] {
            let state = world.state();
            world.run(LAN, packet.clone());
            let reason = if firewall {
                firewall_reason
            } else {
                nat_reason
            };
            assert_drop(&mut world, reason, &packet);
            assert_eq!(world.state(), state, "{reason:?}");
        }
        assert_eq!(world.udp.counters().hairpin_translated, 0);
        assert_eq!(world.udp.counters().hairpin_inbound_refused, 0);
    }
}

/// The hairpin state names the router's own public address as the remote,
/// which common admission refuses as an external source: an outside host
/// spoofing P:x1' cannot use the state the hole punch created, and the
/// NAT44-021 direct outside-to-inside bypass stays closed.
#[test]
fn hairpin_state_is_not_reachable_from_outside() {
    let mut world = World::new(Nat44Filtering::AddressDependent, true, None);
    let public1 = world.establish(H1, P1, false);
    let public2 = world.establish(H2, P2, false);
    let reply = udp_frame(H2, PUBLIC, P2, public1);
    world.run(LAN, reply);
    assert_drop(
        &mut world,
        DropReason::Nat44UdpHairpinFiltered,
        &udp_frame(H2, PUBLIC, P2, public1),
    );
    // H2's mapping now records P as a peer; P:public1 from WAN is refused.
    let mut spoofed = udp_frame(REMOTE, PUBLIC, public1, public2);
    spoofed[26..30].copy_from_slice(&PUBLIC.octets());
    spoofed[24..26].fill(0);
    let checksum = ipv4_header_checksum(&spoofed[14..34]);
    spoofed[24..26].copy_from_slice(&checksum.to_be_bytes());
    let state = world.state();
    world.run(WAN, spoofed.clone());
    assert_drop(&mut world, DropReason::Ipv4SourceLocalAddress, &spoofed);
    assert_eq!(world.state(), state);

    let direct = udp_frame(REMOTE, H2, 53, P2);
    world.run(WAN, direct.clone());
    assert_drop(
        &mut world,
        DropReason::Nat44ExternalToInternalBypass,
        &direct,
    );
}

/// ICMPv4 error from an inside host about a hairpinned datagram: what X2
/// would send back to P about P:x1' -> X2:x2.
fn hairpinned_icmp_error(code: u8, quoted_source_port: u16) -> Vec<u8> {
    let quoted = udp_frame(PUBLIC, H2, quoted_source_port, P2);
    let quote = &quoted[14..14 + 28];
    let total_len = 20 + 8 + quote.len();
    let mut frame = vec![0_u8; 14 + total_len];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&H2_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&H2.octets());
    frame[30..34].copy_from_slice(&PUBLIC.octets());
    frame[34] = 3;
    frame[35] = code;
    frame[42..].copy_from_slice(quote);
    let checksum = internet_checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// RFC 5508 REQ-7 (hairpinned ICMP error traversal) is deferred: an ICMP
/// error an inside host sends to the public address about a hairpinned
/// datagram is not translated. It fails closed like any other
/// non-UDP/TCP inside-to-outside crossing, with no state change, whatever
/// the quoted tuple.
#[test]
fn hairpinned_icmp_errors_are_not_translated_and_fail_closed() {
    for rules in [None, Some(outbound_only_rules())] {
        let firewall = rules.is_some();
        let mut world = World::new(Nat44Filtering::EndpointIndependent, true, rules);
        let public1 = world.establish(H1, P1, false);
        let public2 = world.establish(H2, P2, false);
        let packet = udp_frame(H1, PUBLIC, P1, public2);
        world.run(LAN, packet.clone());
        if firewall {
            assert_drop(&mut world, DropReason::FirewallDefaultDenied, &packet);
        } else {
            assert_hairpin(&mut world, &packet, H2_MAC, (PUBLIC, public1), (H2, P2));
        }
        for code in [3, 4] {
            let error = hairpinned_icmp_error(code, public1);
            let state = world.state();
            world.run(LAN, error.clone());
            let reason = if firewall {
                DropReason::FirewallUnsupportedProtocol
            } else {
                DropReason::Nat44UdpUnsupportedTransport
            };
            assert_drop(&mut world, reason, &error);
            assert_eq!(world.state(), state);
        }
    }
}

/// Type 3/Code 4 from an outside router to P quoting `P:quoted_public ->
/// remote:remote_port` (UDP or TCP), as an outside host would forge to
/// reach hairpin state.
fn outside_frag_needed(
    quoted_public: u16,
    remote: Ipv4Address,
    remote_port: u16,
    tcp: bool,
) -> Vec<u8> {
    let quoted = if tcp {
        tcp_frame(PUBLIC, remote, quoted_public, remote_port, SYN)
    } else {
        udp_frame(PUBLIC, remote, quoted_public, remote_port)
    };
    let quote = &quoted[14..14 + 28];
    let total_len = 20 + 8 + quote.len();
    let mut frame = vec![0_u8; 14 + total_len];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&GW_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&REMOTE.octets());
    frame[30..34].copy_from_slice(&PUBLIC.octets());
    frame[34] = 3;
    frame[35] = 4;
    frame[40..42].copy_from_slice(&1280_u16.to_be_bytes());
    frame[42..].copy_from_slice(quote);
    let checksum = internet_checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// Review M-1 regression: hairpin state names P as its remote, so an
/// outside Fragmentation Needed quoting `P:x1' -> P:x2'` would otherwise
/// find it. Opt-in ICMP translation refuses any quoted remote that is a
/// router address, before any NAT lookup, with or without the firewall. A
/// quote of a real external peer is still translated.
#[test]
fn outside_icmp_errors_cannot_reach_hairpin_state() {
    for rules in [None, Some(outbound_only_rules())] {
        let firewall = rules.is_some();
        let mut world = World::shaped(
            Nat44Filtering::AddressAndPortDependent,
            true,
            rules,
            Shape {
                icmpv4_errors: Nat44Icmpv4ErrorPolicy::ExternalOnly,
                ..Shape::default()
            },
        );
        for tcp in [false, true] {
            let public1 = world.establish(H1, P1, tcp);
            let public2 = world.establish(H2, P2, tcp);
            // The hole punch is refused but commits H1's state toward P.
            let punch = if tcp {
                tcp_frame(H1, PUBLIC, P1, public2, SYN)
            } else {
                udp_frame(H1, PUBLIC, P1, public2)
            };
            world.run(LAN, punch.clone());
            let refused = if tcp {
                DropReason::Nat44TcpHairpinFiltered
            } else {
                DropReason::Nat44UdpHairpinFiltered
            };
            assert_drop(&mut world, refused, &punch);

            for local in [PUBLIC, Ipv4Address::from_octets([10, 0, 0, 1])] {
                let forged = outside_frag_needed(public1, local, public2, tcp);
                let state = world.state();
                world.run(WAN, forged.clone());
                assert_drop(
                    &mut world,
                    DropReason::Nat44Icmpv4QuotedRemoteLocal,
                    &forged,
                );
                assert_eq!(world.state(), state, "tcp {tcp} firewall {firewall}");
            }

            // Control: the real external peer of `establish` is still
            // translated toward H1.
            let remote_port = if tcp { 443 } else { 53 };
            let genuine = outside_frag_needed(public1, REMOTE, remote_port, tcp);
            world.run(WAN, genuine);
            let tx = world.io.pop_tx().expect("translated ICMP error");
            assert_eq!(tx.egress, LAN);
            assert_eq!(&tx.bytes[30..34], &H1.octets());
        }
    }
}

/// Review L-1: the outbound half admits only an inside host. A router
/// address as source is refused by common admission before NAT, and a
/// source whose reverse LPM selects the outside is refused by the
/// hairpin's own reverse-authority check; neither commits state.
#[test]
fn hairpin_sender_must_be_an_inside_host() {
    for rules in [None, Some(outbound_only_rules())] {
        let mut world = World::new(Nat44Filtering::EndpointIndependent, true, rules);
        let public2 = world.establish(H2, P2, false);
        let tcp_public2 = world.establish(H2, P2, true);
        for tcp in [false, true] {
            let port = if tcp { tcp_public2 } else { public2 };
            // Every case arrives on the LAN interface.
            let make = |source| {
                let mut frame = if tcp {
                    tcp_frame(source, PUBLIC, P1, port, SYN)
                } else {
                    udp_frame(source, PUBLIC, P1, port)
                };
                frame[0..6].copy_from_slice(&LAN_MAC.0);
                frame
            };
            let mut cases = vec![
                (make(PUBLIC), DropReason::Ipv4SourceLocalAddress),
                (
                    make(Ipv4Address::from_octets([10, 0, 0, 1])),
                    DropReason::Ipv4SourceLocalAddress,
                ),
            ];
            // An external source arriving on the LAN interface.
            cases.push((
                make(REMOTE),
                if tcp {
                    DropReason::Nat44TcpReverseAuthorityMismatch
                } else {
                    DropReason::Nat44UdpReverseAuthorityMismatch
                },
            ));
            for (packet, reason) in cases {
                let state = world.state();
                world.run(LAN, packet.clone());
                assert_drop(&mut world, reason, &packet);
                assert_eq!(world.state(), state, "{reason:?}");
            }
        }
    }
}

/// Review L-2: UDP checksum zero (no checksum) stays zero, and an
/// incremental result of arithmetic zero is sent as 0xffff (RFC 768).
#[test]
fn udp_hairpin_checksum_zero_and_arithmetic_zero_follow_rfc768() {
    let mut world = World::new(Nat44Filtering::EndpointIndependent, true, None);
    let public1 = world.establish(H1, P1, false);
    let public2 = world.establish(H2, P2, false);

    let mut zero = udp_frame(H1, PUBLIC, P1, public2);
    zero[40..42].fill(0);
    world.run(LAN, zero.clone());
    let tx = world.io.pop_tx().expect("hairpinned packet");
    assert_eq!(&tx.bytes[40..42], &[0, 0], "zero checksum preserved");
    assert_eq!(&tx.bytes[26..30], &PUBLIC.octets());
    assert_eq!(&tx.bytes[30..34], &H2.octets());

    // Choose the last payload word so that the translated datagram sums to
    // 0xffff, that is a computed checksum of zero.
    let word = (0..=u16::MAX)
        .find(|word| {
            let mut segment = udp_frame(PUBLIC, H2, public1, P2)[34..46].to_vec();
            segment[10..12].copy_from_slice(&word.to_be_bytes());
            segment[6..8].fill(0);
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&PUBLIC.octets());
            bytes.extend_from_slice(&H2.octets());
            bytes.extend_from_slice(&[0, 17, 0, 12]);
            bytes.extend_from_slice(&segment);
            internet_checksum(&bytes) == 0
        })
        .expect("some payload word yields an arithmetic zero");
    let mut packet = udp_frame(H1, PUBLIC, P1, public2);
    packet[44..46].copy_from_slice(&word.to_be_bytes());
    packet[40..42].fill(0);
    let checksum = transport_checksum(H1, PUBLIC, 17, &packet[34..46]);
    packet[40..42].copy_from_slice(&checksum.to_be_bytes());
    world.run(LAN, packet.clone());
    let tx = world.io.pop_tx().expect("hairpinned packet");
    assert_eq!(&tx.bytes[34..36], &public1.to_be_bytes());
    assert_eq!(&tx.bytes[36..38], &P2.to_be_bytes());
    assert_eq!(
        &tx.bytes[40..42],
        &[0xff, 0xff],
        "arithmetic zero is 0xffff"
    );
    assert_eq!(&tx.bytes[44..46], &word.to_be_bytes());
}

fn permissive_rules() -> Vec<FirewallRule> {
    let mut rules = outbound_only_rules();
    for (id, protocol) in [(40, FirewallProtocol::Udp), (50, FirewallProtocol::Tcp)] {
        rules.push(FirewallRule::new(
            FirewallRuleId(id),
            FirewallInterface::Interface(WAN),
            FirewallInterface::Interface(LAN),
            any(),
            lan_prefix(),
            protocol,
            ports(0, u16::MAX),
            ports(1, u16::MAX),
            FirewallAction::AllowStateful,
        ));
    }
    rules
}

fn occupied_firewall_states(world: &World) -> usize {
    world
        .firewall
        .as_ref()
        .unwrap()
        .states()
        .iter()
        .filter(|slot| slot.is_occupied())
        .count()
}

fn sessions_toward(world: &World, remote: Ipv4Address) -> usize {
    world
        .tcp
        .sessions()
        .iter()
        .filter(|slot| slot.is_occupied() && slot.remote_address() == remote)
        .count()
}

/// Review L-3: with the firewall bound, an inbound half refused after its
/// NAT and firewall plans (neighbor miss), by inbound session capacity, or
/// by the firewall itself keeps only the outbound half: one new firewall
/// state and one sender-side NAT entry, nothing on the destination side.
/// A capacity failure of the outbound half (UDP peer table) commits
/// nothing. (`WrongEgress` after DNAT needs a mapping whose internal
/// address no longer routes inside, which a fixed publication cannot
/// produce: mappings are created only for inside-routed sources and
/// reconcile flushes them.)
#[test]
fn refused_inbound_halves_keep_only_the_outbound_half() {
    // Neighbor miss after both plans: H3 has no static neighbor.
    for tcp in [false, true] {
        let mut world = World::new(
            Nat44Filtering::EndpointIndependent,
            true,
            Some(permissive_rules()),
        );
        let public3 = world.establish(H3, P2, tcp);
        let states = occupied_firewall_states(&world);
        let allowed = world.firewall.as_ref().unwrap().counters().allowed_new;
        let toward_public = sessions_toward(&world, PUBLIC);
        let packet = if tcp {
            tcp_frame(H1, PUBLIC, P1, public3, SYN)
        } else {
            udp_frame(H1, PUBLIC, P1, public3)
        };
        world.run(LAN, packet.clone());
        assert_drop(&mut world, DropReason::NeighborUnresolved, &packet);
        assert_eq!(occupied_firewall_states(&world), states + 1, "tcp {tcp}");
        assert_eq!(
            world.firewall.as_ref().unwrap().counters().allowed_new,
            allowed + 1
        );
        if tcp {
            // H1's outbound-half session only; none on H3's mapping.
            assert_eq!(sessions_toward(&world, PUBLIC), toward_public + 1);
            assert_eq!(world.tcp.counters().hairpin_inbound_refused, 1);
            assert_eq!(world.tcp.counters().inbound_sessions_created, 0);
        } else {
            assert_eq!(world.udp.counters().hairpin_inbound_refused, 1);
        }
    }

    // TCP inbound session table full (2 sessions: H2's and H1's outbound
    // half).
    let mut world = World::shaped(
        Nat44Filtering::EndpointIndependent,
        true,
        Some(permissive_rules()),
        Shape {
            tcp_sessions: 2,
            ..Shape::default()
        },
    );
    let public2 = world.establish(H2, P2, true);
    let states = occupied_firewall_states(&world);
    let syn = tcp_frame(H1, PUBLIC, P1, public2, SYN);
    world.run(LAN, syn.clone());
    assert_drop(&mut world, DropReason::Nat44TcpSessionTableFull, &syn);
    assert_eq!(occupied_firewall_states(&world), states + 1);
    assert_eq!(sessions_toward(&world, PUBLIC), 1);
    assert_eq!(world.tcp.counters().hairpin_inbound_refused, 1);

    // TCP inbound half denied by the firewall (M1 policy, EIF admits).
    let mut world = World::new(
        Nat44Filtering::EndpointIndependent,
        true,
        Some(outbound_only_rules()),
    );
    let public2 = world.establish(H2, P2, true);
    let states = occupied_firewall_states(&world);
    let syn = tcp_frame(H1, PUBLIC, P1, public2, SYN);
    world.run(LAN, syn.clone());
    assert_drop(&mut world, DropReason::FirewallDefaultDenied, &syn);
    assert_eq!(occupied_firewall_states(&world), states + 1);
    assert_eq!(sessions_toward(&world, PUBLIC), 1, "H1's session only");
    assert_eq!(world.tcp.counters().inbound_sessions_created, 0);
    assert_eq!(world.tcp.counters().hairpin_inbound_refused, 1);

    // UDP peer table full in the outbound half: nothing commits.
    let mut world = World::shaped(
        Nat44Filtering::EndpointIndependent,
        true,
        Some(permissive_rules()),
        Shape {
            udp_peers: 1,
            ..Shape::default()
        },
    );
    let public2 = world.establish(H2, P2, false);
    let state = world.state();
    let packet = udp_frame(H1, PUBLIC, P1, public2);
    world.run(LAN, packet.clone());
    assert_drop(&mut world, DropReason::Nat44UdpPeerTableFull, &packet);
    assert_eq!(world.state(), state);
    assert_eq!(world.udp.counters().hairpin_inbound_refused, 0);
}

//! RFC 5508 ICMPv4 error translation through the full packet path, with and
//! without the firewall: external errors toward the public address (REQ-4),
//! errors an inside host or router sends toward the external realm about a
//! packet it received (REQ-5), and hairpinned errors (REQ-7).
//!
//! Every translation is checked against a full recomputation. The reverted
//! quote must equal, byte for byte, the packet the error's recipient
//! originally sent (or received), apart from the TTL the router decremented
//! and that header's checksum. The outer IPv4 and ICMP checksums are
//! verified by summing the whole header and message.

mod support;

use ruster_core::{
    internet_checksum, ipv4_header_checksum, DropReason, FirewallAction, FirewallAuditBuffer,
    FirewallAuditRecord, FirewallConfig, FirewallConnectionClass, FirewallHashKey,
    FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange, FirewallProtocol,
    FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot, FirewallVerdict,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Nat44Filtering, Nat44Icmpv4Disposition, Nat44Icmpv4ErrorPolicy,
    Nat44TcpConfig, Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot,
    Nat44UdpConfig, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime,
    Neighbor, ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot,
    Route, TraceEvent,
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
const INNER_GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 12]);
const GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
/// A router address on a third interface, routed toward the outside.
const DMZ_LOCAL: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const H1: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const H2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
/// An inside router on the LAN that routes 10.1.0.0/16.
const INNER_GW: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 254]);
/// A host behind `INNER_GW`.
const H4: Ipv4Address = Ipv4Address::from_octets([10, 1, 0, 5]);
/// A host routed out of the DMZ through a next hop that is `INNER_GW`.
const H5: Ipv4Address = Ipv4Address::from_octets([10, 2, 0, 5]);
/// An off-path outside host that never spoofs its address.
const ATTACKER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 66]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const OTHER_REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 21]);
const ROUTER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const FIRST_PORT: u16 = 40_000;
const LAST_PORT: u16 = 40_015;
const P1: u16 = 5001;
const P2: u16 = 5002;
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;

/// Every (type, code) pair of the three error types, with whether NAT44
/// translates it.
fn error_matrix() -> Vec<(u8, u8, bool)> {
    let mut matrix = Vec::new();
    for code in 0..=16_u8 {
        matrix.push((3, code, !matches!(code, 5 | 8 | 16)));
    }
    for code in 0..=2_u8 {
        matrix.push((11, code, code == 0));
    }
    for code in 0..=3_u8 {
        matrix.push((12, code, code <= 2));
    }
    // Source Quench and Redirect are never translated.
    matrix.push((4, 0, false));
    matrix.push((5, 1, false));
    matrix
}

fn supported_errors() -> Vec<(u8, u8)> {
    error_matrix()
        .into_iter()
        .filter(|(_, _, supported)| *supported)
        .map(|(icmp_type, code, _)| (icmp_type, code))
        .collect()
}

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

fn snapshot() -> ForwardingSnapshot<'static> {
    let routes = leak([
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([10, 1, 0, 0]),
            16,
            LAN,
            Some(INNER_GW),
        )
        .unwrap(),
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, Some(GW)).unwrap(),
        Route::new(
            Ipv4Address::from_octets([10, 2, 0, 0]),
            16,
            DMZ,
            Some(INNER_GW),
        )
        .unwrap(),
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
        Interface {
            id: DMZ,
            mac: DMZ_MAC,
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
            interface: LAN,
            target: INNER_GW,
            mac: INNER_GW_MAC,
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
            address: LAN_LOCAL,
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
        LocalIpv4Binding {
            interface: DMZ,
            address: DMZ_LOCAL,
        },
    ]);
    ForwardingSnapshot::new(&routes[..], &interfaces[..], &neighbors[..], &bindings[..]).unwrap()
}

fn any() -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap()
}

fn inside_prefix() -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 8).unwrap()
}

/// The M1 shape: inside to outside UDP/TCP allowed statefully, nothing
/// admitted from outside to inside except established return traffic.
fn outbound_only_rules() -> Vec<FirewallRule> {
    [(20, FirewallProtocol::Udp), (30, FirewallProtocol::Tcp)]
        .into_iter()
        .map(|(id, protocol)| {
            FirewallRule::new(
                FirewallRuleId(id),
                FirewallInterface::Interface(LAN),
                FirewallInterface::Interface(WAN),
                inside_prefix(),
                any(),
                protocol,
                FirewallPortRange::new(0, u16::MAX).unwrap(),
                FirewallPortRange::new(1, u16::MAX).unwrap(),
                FirewallAction::AllowStateful,
            )
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Shape {
    filtering: Nat44Filtering,
    udp_errors: Nat44Icmpv4ErrorPolicy,
    tcp_errors: Nat44Icmpv4ErrorPolicy,
    hairpinning: bool,
    /// Adds a rule admitting new outside-to-inside UDP flows.
    inbound_udp_rule: bool,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            filtering: Nat44Filtering::AddressDependent,
            udp_errors: Nat44Icmpv4ErrorPolicy::default(),
            tcp_errors: Nat44Icmpv4ErrorPolicy::default(),
            hairpinning: true,
            inbound_udp_rule: false,
        }
    }
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
    trace: VecTrace,
    now: u64,
}

impl World {
    fn new(firewall: bool) -> Self {
        Self::shaped(firewall, Shape::default())
    }

    fn shaped(firewall: bool, shape: Shape) -> Self {
        let snapshot = snapshot();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            FIRST_PORT,
            LAST_PORT,
            Nat44UdpPolicy::default()
                .with_filtering(shape.filtering)
                .with_hairpinning(shape.hairpinning)
                .with_icmpv4_errors(shape.udp_errors),
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
                .with_filtering(shape.filtering)
                .with_hairpinning(shape.hairpinning)
                .with_icmpv4_errors(shape.tcp_errors),
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
        let (firewall_config, firewall) = if firewall {
            let config = FirewallConfig::new(
                &snapshot,
                Vec::leak({
                    let mut rules = outbound_only_rules();
                    if shape.inbound_udp_rule {
                        rules.push(FirewallRule::new(
                            FirewallRuleId(40),
                            FirewallInterface::Interface(WAN),
                            FirewallInterface::Interface(LAN),
                            any(),
                            inside_prefix(),
                            FirewallProtocol::Udp,
                            FirewallPortRange::new(1, u16::MAX).unwrap(),
                            FirewallPortRange::new(1, u16::MAX).unwrap(),
                            FirewallAction::AllowStateful,
                        ));
                    }
                    rules
                }),
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
            trace: VecTrace::default(),
            now: 0,
        }
    }

    fn run(&mut self, ingress: IfId, packet: Vec<u8>) {
        self.io.inject(ingress, packet);
        let now = MonotonicMillis(self.now);
        self.now += 1;
        self.trace.clear();
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
                    &mut self.trace,
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
                    &mut self.trace,
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
                &mut VecTrace::default(),
            )
            .unwrap();
    }

    /// Sends `host:port` to `REMOTE` (53 or 443) and returns the outbound
    /// wire packet.
    fn establish(&mut self, host: Ipv4Address, port: u16, tcp: bool) -> Vec<u8> {
        let packet = if tcp {
            tcp_frame(host, REMOTE, port, 443, SYN)
        } else {
            udp_frame(host, REMOTE, port, 53)
        };
        self.run(LAN, packet);
        let tx = self.io.pop_tx().expect("outbound translation");
        assert_eq!(tx.egress, WAN);
        tx.bytes
    }

    /// `REMOTE` replies to `public_port`; returns the reply as sent and as
    /// delivered inside.
    fn reply(&mut self, public_port: u16, tcp: bool) -> (Vec<u8>, Vec<u8>) {
        let packet = if tcp {
            tcp_frame(REMOTE, PUBLIC, 443, public_port, SYN_ACK)
        } else {
            udp_frame(REMOTE, PUBLIC, 53, public_port)
        };
        self.run(WAN, packet.clone());
        let tx = self.io.pop_tx().expect("inbound translation");
        assert_eq!(tx.egress, LAN);
        (packet, tx.bytes)
    }

    fn state(&self) -> State {
        State {
            udp_mappings: self.udp.mappings().to_vec(),
            udp_peers: self.udp.peers().to_vec(),
            tcp_mappings: self.tcp.mappings().to_vec(),
            tcp_sessions: self.tcp.sessions().to_vec(),
            udp_counters: format!("{:?}", self.udp.counters()),
            tcp_counters: format!("{:?}", self.tcp.counters()),
            firewall: self
                .firewall
                .as_ref()
                .map(|firewall| {
                    (
                        firewall.states().to_vec(),
                        format!("{:?}", firewall.counters()),
                    )
                })
                .unwrap_or_default(),
        }
    }

    fn assert_drop(&mut self, reason: DropReason, original: &[u8]) {
        let recycled = self.io.pop_recycled().expect("dropped packet");
        assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
        assert_eq!(recycled.bytes, original, "drops are byte-unchanged");
        assert!(self.io.pop_tx().is_none());
    }

    /// Runs `error` and asserts a byte-unchanged drop with no state change.
    fn assert_refused(&mut self, ingress: IfId, error: Vec<u8>, reason: DropReason) {
        let before = self.state();
        self.run(ingress, error.clone());
        self.assert_drop(reason, &error);
        assert_eq!(self.state(), before, "{reason:?}");
    }
}

#[derive(Debug, Eq, PartialEq)]
struct State {
    udp_mappings: Vec<Nat44UdpMappingSlot>,
    udp_peers: Vec<Nat44UdpPeerSlot>,
    tcp_mappings: Vec<Nat44TcpMappingSlot>,
    tcp_sessions: Vec<Nat44TcpSessionSlot>,
    udp_counters: String,
    tcp_counters: String,
    firewall: (Vec<FirewallStateSlot>, String),
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

fn source_mac(source: Ipv4Address) -> (MacAddress, MacAddress) {
    match source {
        H1 => (LAN_MAC, H1_MAC),
        H2 => (LAN_MAC, H2_MAC),
        source if source.octets()[0] == 10 => (LAN_MAC, INNER_GW_MAC),
        _ => (WAN_MAC, GW_MAC),
    }
}

/// Atomic (DF=1) UDP or TCP frame; `flags` is `None` for UDP.
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
    let (ingress_mac, sender_mac) = source_mac(source);
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&sender_mac.0);
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

fn public_source_port(outbound: &[u8]) -> u16 {
    u16::from_be_bytes([outbound[34], outbound[35]])
}

/// An ICMPv4 error from `source` to `destination` quoting the whole IPv4
/// datagram of `quoted` (an Ethernet frame). The ingress follows `source`.
fn icmp_error(
    source: Ipv4Address,
    destination: Ipv4Address,
    icmp_type: u8,
    code: u8,
    quoted: &[u8],
) -> Vec<u8> {
    let quote = &quoted[14..];
    let total_len = 20 + 8 + quote.len();
    let mut frame = vec![0_u8; 14 + total_len];
    let (ingress_mac, sender_mac) = source_mac(source);
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&sender_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0xc0;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x7777_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34] = icmp_type;
    frame[35] = code;
    // Unused / MTU / pointer word, preserved by translation.
    frame[38..42].copy_from_slice(&[0x14, 0, 0x05, 0x00]);
    frame[42..].copy_from_slice(quote);
    refresh_icmp(&mut frame);
    frame
}

fn refresh_icmp(frame: &mut [u8]) {
    frame[36..38].fill(0);
    let checksum = internet_checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

/// `packet` as it looks after one router hop: TTL - 1 and a recomputed
/// IPv4 checksum, everything else unchanged.
fn after_one_hop(packet: &[u8]) -> Vec<u8> {
    let mut ipv4 = packet[14..].to_vec();
    ipv4[8] -= 1;
    ipv4[10..12].fill(0);
    let checksum = ipv4_header_checksum(&ipv4[..20]);
    ipv4[10..12].copy_from_slice(&checksum.to_be_bytes());
    ipv4
}

/// Asserts one translated error: egress and Ethernet, TTL - 1, the outer
/// addresses, type/code/word preserved, the quote equal to `expected_quote`,
/// and every checksum valid by full recomputation.
#[allow(clippy::too_many_arguments)]
fn assert_translated(
    world: &mut World,
    error: &[u8],
    egress: IfId,
    destination_mac: MacAddress,
    outer_source: Ipv4Address,
    outer_destination: Ipv4Address,
    expected_quote: &[u8],
) {
    assert!(world.io.pop_recycled().is_none(), "no drop");
    let tx = world.io.pop_tx().expect("translated ICMP error");
    assert!(world.io.pop_tx().is_none());
    let bytes = &tx.bytes;
    assert_eq!(tx.egress, egress);
    assert_eq!(bytes.len(), error.len());
    assert_eq!(&bytes[0..6], &destination_mac.0);
    let egress_mac = if egress == LAN { LAN_MAC } else { WAN_MAC };
    assert_eq!(&bytes[6..12], &egress_mac.0);
    assert_eq!(&bytes[14..22], &error[14..22], "version..flags preserved");
    assert_eq!(bytes[22], error[22] - 1, "TTL");
    assert_eq!(bytes[23], 1);
    assert_eq!(&bytes[26..30], &outer_source.octets());
    assert_eq!(&bytes[30..34], &outer_destination.octets());
    assert_eq!(ipv4_header_checksum(&bytes[14..34]), 0, "outer checksum");
    assert_eq!(&bytes[34..36], &error[34..36], "type and code preserved");
    assert_eq!(&bytes[38..42], &error[38..42], "rest-of-header preserved");
    assert_eq!(internet_checksum(&bytes[34..]), 0, "ICMP checksum");
    assert_eq!(&bytes[42..], expected_quote, "reverted quote");
    let quote = &bytes[42..];
    assert_eq!(
        ipv4_header_checksum(&quote[..20]),
        0,
        "quoted IPv4 checksum"
    );
    // Full transport checksum of the reverted quote.
    let protocol = quote[9];
    let source = Ipv4Address::from_octets(quote[12..16].try_into().unwrap());
    let destination = Ipv4Address::from_octets(quote[16..20].try_into().unwrap());
    let mut segment = quote[20..].to_vec();
    let offset = if protocol == 6 { 16 } else { 6 };
    let carried = u16::from_be_bytes([segment[offset], segment[offset + 1]]);
    segment[offset..offset + 2].fill(0);
    assert_eq!(
        transport_checksum(source, destination, protocol, &segment),
        carried,
        "quoted transport checksum"
    );
}

/// REQ-5: an inside host's error about a reply it received from REMOTE is
/// sent to REMOTE from P, quoting the reply exactly as REMOTE sent it. Every
/// supported type and code, UDP and TCP, with and without the firewall. An
/// unsupported type or code is not a candidate and keeps the existing
/// fail-closed drop.
#[test]
fn inside_errors_of_every_supported_type_reach_the_sender_with_the_quote_reverted() {
    for firewall in [false, true] {
        for tcp in [false, true] {
            let mut world = World::new(firewall);
            let outbound = world.establish(H1, P1, tcp);
            let public = public_source_port(&outbound);
            let (sent, delivered) = world.reply(public, tcp);
            let expected_quote = after_one_hop(&sent);
            for (icmp_type, code, supported) in error_matrix() {
                let error = icmp_error(H1, REMOTE, icmp_type, code, &delivered);
                let before = world.state();
                world.run(LAN, error.clone());
                if supported {
                    assert_translated(
                        &mut world,
                        &error,
                        WAN,
                        GW_MAC,
                        PUBLIC,
                        REMOTE,
                        &expected_quote,
                    );
                    assert!(
                        world.trace.events().contains(&TraceEvent::Nat44Icmpv4 {
                            ingress: LAN,
                            disposition: Nat44Icmpv4Disposition::TranslatedFromInside {
                                quoted_protocol: if tcp { 6 } else { 17 },
                                internal_address: H1,
                                internal_port: P1,
                                public_port: public,
                            },
                        }),
                        "type {icmp_type} code {code}"
                    );
                } else {
                    let reason = if firewall {
                        DropReason::FirewallUnsupportedProtocol
                    } else {
                        DropReason::Nat44UdpUnsupportedTransport
                    };
                    world.assert_drop(reason, &error);
                    // The existing path is unchanged (with the firewall it
                    // counts an invalid packet).
                    continue;
                }
                // Read-only: no NAT or firewall slot, counter, or watermark.
                assert_eq!(world.state(), before, "type {icmp_type} code {code}");
            }
        }
    }
}

/// REQ-4 (NAT44-019J): an outside router's error about H1's outbound
/// packet reaches H1 for every supported type and code, quoting the packet
/// exactly as H1 sent it.
#[test]
fn external_errors_of_every_supported_type_reach_the_inside_host() {
    for firewall in [false, true] {
        for tcp in [false, true] {
            let mut world = World::new(firewall);
            let original = if tcp {
                tcp_frame(H1, REMOTE, P1, 443, SYN)
            } else {
                udp_frame(H1, REMOTE, P1, 53)
            };
            let outbound = world.establish(H1, P1, tcp);
            let expected_quote = after_one_hop(&original);
            for (icmp_type, code, supported) in error_matrix() {
                // Protocol/Port Unreachable come only from the end host.
                let end_host_only = icmp_type == 3 && matches!(code, 2 | 3);
                if end_host_only {
                    world.assert_refused(
                        WAN,
                        icmp_error(ROUTER, PUBLIC, icmp_type, code, &outbound),
                        DropReason::Nat44Icmpv4EndHostSourceMismatch,
                    );
                }
                let reporter = if end_host_only { REMOTE } else { ROUTER };
                let error = icmp_error(reporter, PUBLIC, icmp_type, code, &outbound);
                let before = world.state();
                world.run(WAN, error.clone());
                if supported {
                    assert_translated(
                        &mut world,
                        &error,
                        LAN,
                        H1_MAC,
                        reporter,
                        H1,
                        &expected_quote,
                    );
                } else {
                    let recycled = world.io.pop_recycled().unwrap();
                    assert_eq!(
                        recycled.cause,
                        RecycleCause::Consumed(ruster_core::ConsumeReason::Ipv4LocalUnsupported),
                        "type {icmp_type} code {code}"
                    );
                }
                assert_eq!(world.state(), before, "type {icmp_type} code {code}");
            }
        }
    }
}

/// REQ-5 c: an inside router reporting about a packet to a host behind it
/// is translated too; the outer source becomes P.
#[test]
fn inside_router_on_the_path_may_report_about_the_host_behind_it() {
    for tcp in [false, true] {
        let mut world = World::new(false);
        let outbound = world.establish(H4, P1, tcp);
        let public = public_source_port(&outbound);
        let (sent, delivered) = world.reply(public, tcp);
        for (icmp_type, code) in [(11, 0), (3, 1), (3, 4)] {
            let error = icmp_error(INNER_GW, REMOTE, icmp_type, code, &delivered);
            world.run(LAN, error.clone());
            assert_translated(
                &mut world,
                &error,
                WAN,
                GW_MAC,
                PUBLIC,
                REMOTE,
                &after_one_hop(&sent),
            );
        }
        // Protocol/Port Unreachable come only from the host itself.
        for code in [2, 3] {
            world.assert_refused(
                LAN,
                icmp_error(INNER_GW, REMOTE, 3, code, &delivered),
                DropReason::Nat44Icmpv4InsideSourceMismatch,
            );
        }
        // The host itself may report them.
        let error = icmp_error(H4, REMOTE, 3, 3, &delivered);
        world.run(LAN, error.clone());
        assert_translated(
            &mut world,
            &error,
            WAN,
            GW_MAC,
            PUBLIC,
            REMOTE,
            &after_one_hop(&sent),
        );
    }
}

/// Source authority, direction, and state checks of REQ-5. Each refusal is
/// a byte-unchanged drop that changes no state.
#[test]
fn inside_errors_without_authority_are_refused_atomically() {
    for firewall in [false, true] {
        for tcp in [false, true] {
            let mut world = World::new(firewall);
            let outbound = world.establish(H1, P1, tcp);
            let public = public_source_port(&outbound);
            let (_, delivered) = world.reply(public, tcp);
            let remote_port = if tcp { 443 } else { 53 };
            let quoted = |source, sport, destination, dport| {
                if tcp {
                    tcp_frame(source, destination, sport, dport, SYN_ACK)
                } else {
                    udp_frame(source, destination, sport, dport)
                }
            };
            let (mapping_miss, peer_miss) = if tcp {
                (
                    DropReason::Nat44TcpMappingMiss,
                    DropReason::Nat44TcpSessionMiss,
                )
            } else {
                (
                    DropReason::Nat44UdpMappingMiss,
                    DropReason::Nat44UdpFilterDenied,
                )
            };

            // Spoofing: H2 and the inside router report about H1's flow.
            for spoofer in [H2, INNER_GW] {
                world.assert_refused(
                    LAN,
                    icmp_error(spoofer, REMOTE, 3, 3, &delivered),
                    DropReason::Nat44Icmpv4InsideSourceMismatch,
                );
            }
            // An outside address on the LAN fails the strict reverse path.
            let mut outside_source = icmp_error(OTHER_REMOTE, REMOTE, 3, 3, &delivered);
            outside_source[0..6].copy_from_slice(&LAN_MAC.0);
            outside_source[6..12].copy_from_slice(&H1_MAC.0);
            world.assert_refused(LAN, outside_source, DropReason::Nat44Icmpv4SourceForbidden);
            // The error must go to the sender of the quoted packet.
            world.assert_refused(
                LAN,
                icmp_error(H1, OTHER_REMOTE, 3, 3, &delivered),
                DropReason::Nat44Icmpv4OuterDestinationMismatch,
            );
            // Wrong direction: a quote of H1's own outbound packet.
            world.assert_refused(
                LAN,
                icmp_error(H1, REMOTE, 3, 3, &quoted(H1, P1, REMOTE, remote_port)),
                DropReason::Nat44Icmpv4OuterDestinationMismatch,
            );
            // No mapping for the quoted internal endpoint.
            world.assert_refused(
                LAN,
                icmp_error(H1, REMOTE, 3, 3, &quoted(REMOTE, remote_port, H1, P2)),
                mapping_miss,
            );
            // H2 has no mapping, so it cannot report about itself either.
            world.assert_refused(
                LAN,
                icmp_error(H2, REMOTE, 3, 3, &quoted(REMOTE, remote_port, H2, P1)),
                mapping_miss,
            );
            // No peer/session with this remote: an inside host cannot reach
            // an external host its mapping never exchanged traffic with.
            world.assert_refused(
                LAN,
                icmp_error(
                    H1,
                    OTHER_REMOTE,
                    3,
                    3,
                    &quoted(OTHER_REMOTE, remote_port, H1, P1),
                ),
                peer_miss,
            );
            if tcp {
                // TCP sessions are exact in the remote port.
                world.assert_refused(
                    LAN,
                    icmp_error(H1, REMOTE, 3, 3, &quoted(REMOTE, 444, H1, P1)),
                    peer_miss,
                );
            } else if firewall {
                // The address-granular UDP peer admits another remote port,
                // but the firewall's exact flow does not.
                world.assert_refused(
                    LAN,
                    icmp_error(H1, REMOTE, 3, 3, &quoted(REMOTE, 54, H1, P1)),
                    DropReason::FirewallRelatedIcmpv4StateMiss,
                );
            }
            // A router address as the quoted remote never reaches NAT state.
            world.assert_refused(
                LAN,
                icmp_error(H1, DMZ_LOCAL, 3, 3, &quoted(DMZ_LOCAL, remote_port, H1, P1)),
                DropReason::Nat44Icmpv4QuotedRemoteLocal,
            );
        }
    }
}

/// RFC 5508 REQ-3: malformed, truncated, and fragmented errors and quotes
/// are refused with stable reasons before any lookup.
#[test]
fn malformed_inside_errors_are_refused_atomically() {
    let mut world = World::new(false);
    let outbound = world.establish(H1, P1, false);
    let (_, delivered) = world.reply(public_source_port(&outbound), false);
    let valid = icmp_error(H1, REMOTE, 3, 3, &delivered);

    let mut bad_icmp = valid.clone();
    bad_icmp[36] ^= 0xff;
    bad_icmp[24..26].fill(0);
    let checksum = ipv4_header_checksum(&bad_icmp[14..34]);
    bad_icmp[24..26].copy_from_slice(&checksum.to_be_bytes());
    world.assert_refused(LAN, bad_icmp, DropReason::Nat44Icmpv4ChecksumInvalid);

    let mut bad_inner = valid.clone();
    bad_inner[42 + 10] ^= 0xff;
    refresh_icmp(&mut bad_inner);
    world.assert_refused(LAN, bad_inner, DropReason::Nat44Icmpv4QuotedChecksumInvalid);

    let mut ttl_one = valid.clone();
    ttl_one[22] = 1;
    refresh_icmp(&mut ttl_one);
    world.assert_refused(LAN, ttl_one, DropReason::Nat44Icmpv4OuterTtlExpired);

    let mut fragment = delivered.clone();
    fragment[20..22].copy_from_slice(&0x2000_u16.to_be_bytes());
    fragment[24..26].fill(0);
    let checksum = ipv4_header_checksum(&fragment[14..34]);
    fragment[24..26].copy_from_slice(&checksum.to_be_bytes());
    world.assert_refused(
        LAN,
        icmp_error(H1, REMOTE, 3, 3, &fragment),
        DropReason::Nat44Icmpv4QuotedFragmentUnsupported,
    );

    // Quote cut to the IPv4 header plus 4 transport bytes.
    let mut truncated = icmp_error(H1, REMOTE, 3, 3, &delivered);
    let cut = 14 + 20 + 8 + 20 + 4;
    truncated.truncate(cut);
    let total = u16::try_from(cut - 14).unwrap();
    truncated[16..18].copy_from_slice(&total.to_be_bytes());
    refresh_icmp(&mut truncated);
    world.assert_refused(LAN, truncated, DropReason::Nat44Icmpv4QuoteTruncated);

    let mut icmp_quote = delivered.clone();
    icmp_quote[23] = 1;
    icmp_quote[24..26].fill(0);
    let checksum = ipv4_header_checksum(&icmp_quote[14..34]);
    icmp_quote[24..26].copy_from_slice(&checksum.to_be_bytes());
    world.assert_refused(
        LAN,
        icmp_error(H1, REMOTE, 3, 3, &icmp_quote),
        DropReason::Nat44Icmpv4QuotedProtocolUnsupported,
    );

    // The valid error still translates afterwards.
    world.run(LAN, valid);
    assert!(world.io.pop_tx().is_some());
}

/// REQ-7: X2's error about a hairpinned packet from X1 returns to X1 with
/// both halves reverted: the quote is exactly what X1 sent (UDP after a
/// hole punch under address-dependent filtering, TCP under
/// endpoint-independent filtering), with and without the firewall.
#[test]
fn hairpinned_errors_return_to_the_sender_with_both_halves_reverted() {
    for firewall in [false, true] {
        for tcp in [false, true] {
            let filtering = if tcp {
                Nat44Filtering::EndpointIndependent
            } else {
                Nat44Filtering::AddressDependent
            };
            if tcp && firewall {
                // The outbound-only firewall refuses an unsolicited
                // hairpinned SYN's inbound half; the TCP case is covered
                // without it and the UDP case with it.
                continue;
            }
            let mut world = World::shaped(
                firewall,
                Shape {
                    filtering,
                    ..Shape::default()
                },
            );
            let public1 = public_source_port(&world.establish(H1, P1, tcp));
            let public2 = public_source_port(&world.establish(H2, P2, tcp));
            let packet = |source, sport, dport| {
                if tcp {
                    tcp_frame(source, PUBLIC, sport, dport, SYN)
                } else {
                    udp_frame(source, PUBLIC, sport, dport)
                }
            };
            if !tcp {
                // Hole punch: H1 -> P:x2' is filtered but commits H1's
                // outbound half; H2 -> P:x1' then reaches H1.
                let punch = packet(H1, P1, public2);
                world.run(LAN, punch.clone());
                let refused = world.io.pop_recycled().expect("refused punch");
                assert!(matches!(
                    refused.cause,
                    RecycleCause::Forwarding(
                        DropReason::Nat44UdpHairpinFiltered | DropReason::FirewallDefaultDenied
                    )
                ));
                world.run(LAN, packet(H2, P2, public1));
                assert_eq!(world.io.pop_tx().unwrap().egress, LAN);
            }
            let sent = packet(H1, P1, public2);
            world.run(LAN, sent.clone());
            let delivered = world.io.pop_tx().expect("hairpinned packet").bytes;
            assert_eq!(&delivered[26..30], &PUBLIC.octets());
            assert_eq!(&delivered[30..34], &H2.octets());

            for (icmp_type, code) in supported_errors() {
                let error = icmp_error(H2, PUBLIC, icmp_type, code, &delivered);
                let before = world.state();
                world.run(LAN, error.clone());
                assert_translated(
                    &mut world,
                    &error,
                    LAN,
                    H1_MAC,
                    PUBLIC,
                    H1,
                    &after_one_hop(&sent),
                );
                assert!(world.trace.events().contains(&TraceEvent::Nat44Icmpv4 {
                    ingress: LAN,
                    disposition: Nat44Icmpv4Disposition::TranslatedHairpin {
                        quoted_protocol: if tcp { 6 } else { 17 },
                        internal_address: H1,
                        internal_port: P1,
                    },
                }));
                assert_eq!(world.state(), before);
            }

            // Spoofing X2 and a forged quote source are refused.
            world.assert_refused(
                LAN,
                icmp_error(H1, PUBLIC, 3, 3, &delivered),
                DropReason::Nat44Icmpv4InsideSourceMismatch,
            );
            let mut forged = delivered.clone();
            forged[26..30].copy_from_slice(&REMOTE.octets());
            forged[24..26].fill(0);
            let checksum = ipv4_header_checksum(&forged[14..34]);
            forged[24..26].copy_from_slice(&checksum.to_be_bytes());
            world.assert_refused(
                LAN,
                icmp_error(H2, PUBLIC, 3, 3, &forged),
                DropReason::Nat44Icmpv4QuotedPublicSourceMismatch,
            );
            // A quoted sender port with no outbound half toward P:x2'.
            let (mapping_miss, _) = if tcp {
                (DropReason::Nat44TcpMappingMiss, ())
            } else {
                (DropReason::Nat44UdpMappingMiss, ())
            };
            let unknown_sender = if tcp {
                tcp_frame(PUBLIC, H2, LAST_PORT, P2, SYN)
            } else {
                udp_frame(PUBLIC, H2, LAST_PORT, P2)
            };
            let mut unknown_sender = after_one_hop(&unknown_sender);
            let mut frame = vec![0_u8; 14];
            frame.append(&mut unknown_sender);
            let refused = if tcp {
                // X2 has no session with P:LAST_PORT.
                DropReason::Nat44TcpSessionMiss
            } else {
                // X2's address-granular peer P admits any port, but no
                // mapping owns P:LAST_PORT.
                mapping_miss
            };
            world.assert_refused(LAN, icmp_error(H2, PUBLIC, 3, 3, &frame), refused);
        }
    }
}

/// With the firewall, a hairpinned error needs both halves' flows. X2 can
/// make the NAT authority hold for a packet X1 never sent it: X1's peer `P`
/// is address-granular (from a punch toward another host), and X2's own
/// outbound half gives it the received-flow state. Only X1's missing
/// outbound flow `X1:x1 -> P:x2'` refuses the forged error.
///
/// Without the firewall the same forged error is delivered (review L1,
/// `poc_req7_adf_wildcard_fabricated_hairpin_flow`): UDP peers are
/// address-granular under address-dependent filtering, as REQ-9 a and ADF
/// require, so the NAT cannot tell which `P` port X1 sent to. The error
/// stays inside the inside realm, where X1's socket tuple match is the
/// final guard.
#[test]
fn firewall_requires_the_hairpin_senders_own_outbound_flow() {
    let mut world = World::new(false);
    let public1 = public_source_port(&world.establish(H1, P1, false));
    let public2 = public_source_port(&world.establish(H2, P2, false));
    let public4 = public_source_port(&world.establish(H4, P1, false));
    world.run(LAN, udp_frame(H1, PUBLIC, P1, public4));
    assert!(world.io.pop_recycled().is_some());
    world.run(LAN, udp_frame(H2, PUBLIC, P2, public1));
    assert_eq!(world.io.pop_tx().unwrap().egress, LAN);
    let mut never_sent = after_one_hop(&udp_frame(PUBLIC, H2, public1, P2));
    let mut frame = vec![0_u8; 14];
    frame.append(&mut never_sent);
    world.run(LAN, icmp_error(H2, PUBLIC, 3, 3, &frame));
    let delivered = world.io.pop_tx().expect("no firewall: delivered");
    assert_eq!(&delivered.bytes[30..34], &H1.octets());
    // The quote names `P:x2'`, a port X1 never sent to.
    assert_eq!(&delivered.bytes[64..66], &public2.to_be_bytes());

    let mut world = World::new(true);
    let public1 = public_source_port(&world.establish(H1, P1, false));
    let public2 = public_source_port(&world.establish(H2, P2, false));
    let public4 = public_source_port(&world.establish(H4, P1, false));
    // X1 punches toward H4 only, recording its address-granular peer P.
    world.run(LAN, udp_frame(H1, PUBLIC, P1, public4));
    assert!(world.io.pop_recycled().is_some());
    // X2 sends to P:x1'; the firewall refuses the inbound half (X1 never
    // sent to P:x2'), but X2's outbound half commits.
    let probe = udp_frame(H2, PUBLIC, P2, public1);
    world.run(LAN, probe.clone());
    world.assert_drop(DropReason::FirewallDefaultDenied, &probe);
    // X2 forges an error about a packet X1 never sent it.
    let mut never_sent = after_one_hop(&udp_frame(PUBLIC, H2, public1, P2));
    let mut frame = vec![0_u8; 14];
    frame.append(&mut never_sent);
    let mut records = [FirewallAuditRecord::default(); 4];
    let mut audit = FirewallAuditBuffer::new(&mut records);
    let error = icmp_error(H2, PUBLIC, 3, 3, &frame);
    let before = world.state();
    world.run_audited(LAN, error.clone(), &mut audit);
    world.assert_drop(DropReason::FirewallRelatedIcmpv4StateMiss, &error);
    assert_eq!(world.state(), before);
    let records = audit.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].disposition.verdict, FirewallVerdict::Allow);
    assert_eq!((records[1].source, records[1].destination), (H1, PUBLIC));
    assert_eq!(records[1].destination_port, public2);
    assert_eq!(records[1].disposition.verdict, FirewallVerdict::Drop);
    assert_eq!(
        records[1].disposition.class,
        FirewallConnectionClass::Related
    );
}

/// Under endpoint-independent UDP filtering a hairpinned datagram reaches
/// X2 without X2 ever sending to P, but the error authority still requires
/// X2's address-granular peer, so the error is refused (local policy, as for
/// REQ-5 and REQ-4).
#[test]
fn hairpinned_udp_errors_need_the_receivers_peer_even_under_eif() {
    let mut world = World::shaped(
        false,
        Shape {
            filtering: Nat44Filtering::EndpointIndependent,
            ..Shape::default()
        },
    );
    let public1 = public_source_port(&world.establish(H1, P1, false));
    let public2 = public_source_port(&world.establish(H2, P2, false));
    world.run(LAN, udp_frame(H1, PUBLIC, P1, public2));
    let delivered = world.io.pop_tx().unwrap().bytes;
    world.assert_refused(
        LAN,
        icmp_error(H2, PUBLIC, 3, 3, &delivered),
        DropReason::Nat44UdpFilterDenied,
    );
    // Once X2 has sent to P, the error translates.
    world.run(LAN, udp_frame(H2, PUBLIC, P2, public1));
    assert!(world.io.pop_tx().is_some());
    let error = icmp_error(H2, PUBLIC, 3, 3, &delivered);
    world.run(LAN, error);
    let tx = world.io.pop_tx().expect("translated");
    assert_eq!(&tx.bytes[30..34], &H1.octets());
}

/// The firewall view: the REQ-5 quote is the received packet `R:r -> X:x`
/// (ingress outside, egress inside), RELATED to the live flow in either
/// direction; the audit records it as RELATED from the flow's rule.
///
/// Without the firewall the other-remote-port quote is delivered (review
/// L2): under address-dependent filtering the UDP peer is address-granular,
/// so the quoted remote port is not NAT authority.
#[test]
fn firewall_records_inside_errors_as_related_to_the_reverse_flow() {
    let mut world = World::new(false);
    let outbound = world.establish(H1, P1, false);
    let (_, delivered) = world.reply(public_source_port(&outbound), false);
    let mut other_port = delivered.clone();
    other_port[34..36].copy_from_slice(&54_u16.to_be_bytes());
    world.run(LAN, icmp_error(H1, REMOTE, 3, 3, &other_port));
    let tx = world.io.pop_tx().expect("no firewall: delivered");
    assert_eq!(tx.egress, WAN);
    assert_eq!(&tx.bytes[62..64], &54_u16.to_be_bytes());

    let mut world = World::new(true);
    let outbound = world.establish(H1, P1, false);
    let (_, delivered) = world.reply(public_source_port(&outbound), false);
    let mut records = [FirewallAuditRecord::default(); 2];
    let mut audit = FirewallAuditBuffer::new(&mut records);
    world.run_audited(LAN, icmp_error(H1, REMOTE, 3, 3, &delivered), &mut audit);
    assert!(world.io.pop_tx().is_some());
    let records = audit.records();
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!((record.ingress, record.egress), (WAN, LAN));
    assert_eq!((record.source, record.source_port), (REMOTE, 53));
    assert_eq!((record.destination, record.destination_port), (H1, P1));
    assert_eq!(record.disposition.class, FirewallConnectionClass::Related);
    assert_eq!(record.disposition.verdict, FirewallVerdict::Allow);
    assert_eq!(
        record.disposition.source,
        ruster_core::FirewallPolicySource::Rule(FirewallRuleId(20))
    );

    // A quote of another remote port has NAT authority (address-granular
    // peer) but no firewall flow: audited as a RELATED drop.
    let mut other_port = delivered.clone();
    other_port[34..36].copy_from_slice(&54_u16.to_be_bytes());
    let mut records = [FirewallAuditRecord::default(); 2];
    let mut audit = FirewallAuditBuffer::new(&mut records);
    let error = icmp_error(H1, REMOTE, 3, 3, &other_port);
    world.run_audited(LAN, error.clone(), &mut audit);
    world.assert_drop(DropReason::FirewallRelatedIcmpv4StateMiss, &error);
    let record = audit.records()[0];
    assert_eq!(record.disposition.class, FirewallConnectionClass::Related);
    assert_eq!(record.disposition.verdict, FirewallVerdict::Drop);
}

/// The off switches: `external-only` and `disabled` keep inside errors on
/// the existing fail-closed path, per protocol, and `hairpinning = false`
/// refuses hairpinned errors.
#[test]
fn inside_translation_has_per_protocol_off_switches() {
    for firewall in [false, true] {
        for policy in [
            Nat44Icmpv4ErrorPolicy::ExternalOnly,
            Nat44Icmpv4ErrorPolicy::Disabled,
        ] {
            for tcp in [false, true] {
                let shape = if tcp {
                    Shape {
                        tcp_errors: policy,
                        ..Shape::default()
                    }
                } else {
                    Shape {
                        udp_errors: policy,
                        ..Shape::default()
                    }
                };
                let mut world = World::shaped(firewall, shape);
                let outbound = world.establish(H1, P1, tcp);
                let (_, delivered) = world.reply(public_source_port(&outbound), tcp);
                let reason = if firewall {
                    DropReason::FirewallUnsupportedProtocol
                } else {
                    DropReason::Nat44UdpUnsupportedTransport
                };
                // The existing fail-closed path (with the firewall it counts
                // an invalid packet; NAT state is untouched).
                let nat_before = (world.udp.mappings().to_vec(), world.udp.peers().to_vec());
                let error = icmp_error(H1, REMOTE, 3, 3, &delivered);
                world.run(LAN, error.clone());
                world.assert_drop(reason, &error);
                assert_eq!(
                    (world.udp.mappings().to_vec(), world.udp.peers().to_vec()),
                    nat_before
                );

                // The other protocol keeps the default and still translates.
                let other = !tcp;
                let outbound = world.establish(H2, P2, other);
                let (_, delivered) = world.reply(public_source_port(&outbound), other);
                world.run(LAN, icmp_error(H2, REMOTE, 3, 3, &delivered));
                assert_eq!(world.io.pop_tx().unwrap().egress, WAN);
            }
        }
    }

    // `hairpinning = false`: hairpinned errors are refused by the switch.
    for tcp in [false, true] {
        let mut world = World::shaped(
            false,
            Shape {
                filtering: Nat44Filtering::EndpointIndependent,
                hairpinning: false,
                ..Shape::default()
            },
        );
        let public1 = public_source_port(&world.establish(H1, P1, tcp));
        let quoted = if tcp {
            tcp_frame(PUBLIC, H2, public1, P2, SYN)
        } else {
            udp_frame(PUBLIC, H2, public1, P2)
        };
        let reason = if tcp {
            DropReason::Nat44TcpHairpinDisabled
        } else {
            DropReason::Nat44UdpHairpinDisabled
        };
        world.assert_refused(LAN, icmp_error(H2, PUBLIC, 3, 3, &quoted), reason);
    }

    // `external-only` keeps refusing an inside error addressed to P as a
    // wrong-ingress external candidate, as before.
    let mut world = World::shaped(
        false,
        Shape {
            udp_errors: Nat44Icmpv4ErrorPolicy::ExternalOnly,
            ..Shape::default()
        },
    );
    let public1 = public_source_port(&world.establish(H1, P1, false));
    world.assert_refused(
        LAN,
        icmp_error(H2, PUBLIC, 3, 3, &udp_frame(PUBLIC, H2, public1, P2)),
        DropReason::Nat44Icmpv4WrongIngress,
    );
}

/// Review M1 regression (`poc` sweep): an off-path outside host using its
/// own, unspoofed address sweeps every public port with errors quoting
/// `P:port -> REMOTE:53`. Protocol and Port Unreachable get no hit, because
/// only the quoted destination host may send them. The types an
/// intermediate router legitimately sends still hit the live mapping: that
/// is the residual trade-off of REQ-4 (no rate limit, NAT44-065).
#[test]
fn off_path_sweep_cannot_inject_end_host_errors() {
    for firewall in [false, true] {
        let mut world = World::new(firewall);
        let public = public_source_port(&world.establish(H1, P1, false));
        let mut hits = Vec::new();
        for (icmp_type, code) in [(3_u8, 2_u8), (3, 3), (3, 1), (11, 0), (12, 0), (3, 13)] {
            let mut count = 0;
            for port in FIRST_PORT..=LAST_PORT {
                let quoted = udp_frame(PUBLIC, REMOTE, port, 53);
                world.run(WAN, icmp_error(ATTACKER, PUBLIC, icmp_type, code, &quoted));
                if let Some(tx) = world.io.pop_tx() {
                    assert_eq!(port, public);
                    assert_eq!(tx.egress, LAN);
                    count += 1;
                } else {
                    world.io.pop_recycled().expect("refused");
                }
            }
            hits.push(((icmp_type, code), count));
        }
        assert_eq!(
            hits,
            [
                ((3, 2), 0),
                ((3, 3), 0),
                ((3, 1), 1),
                ((11, 0), 1),
                ((12, 0), 1),
                ((3, 13), 1),
            ],
            "firewall {firewall}"
        );
    }
}

/// Review RFC M-1: a TCP inside error needs a live session even while the
/// mapping stays live through another session.
#[test]
fn inside_tcp_error_about_an_expired_session_is_a_session_miss() {
    let mut world = World::new(false);
    let public = public_source_port(&world.establish(H1, P1, true));
    let (_, delivered) = world.reply(public, true);
    // A second session keeps the mapping live past the first's idle TTL.
    world.now = 7_000_000;
    world.run(LAN, tcp_frame(H1, REMOTE, P1, 444, SYN));
    assert_eq!(world.io.pop_tx().unwrap().egress, WAN);
    world.now = 7_440_010;
    world.assert_refused(
        LAN,
        icmp_error(H1, REMOTE, 3, 1, &delivered),
        DropReason::Nat44TcpSessionMiss,
    );
    // The live session still translates.
    let (_, live) = {
        let packet = tcp_frame(REMOTE, PUBLIC, 444, public, SYN_ACK);
        world.run(WAN, packet.clone());
        (packet, world.io.pop_tx().unwrap().bytes)
    };
    world.run(LAN, icmp_error(H1, REMOTE, 3, 1, &live));
    assert_eq!(world.io.pop_tx().unwrap().egress, WAN);
}

/// Review RFC L-1: the inside next hop counts only for a route whose egress
/// is the inside interface. A route out of another interface through the
/// same next-hop address gives that router no authority.
#[test]
fn next_hop_authority_requires_an_inside_egress_route() {
    let mut world = World::new(false);
    let quoted = udp_frame(REMOTE, H5, 53, P1);
    world.assert_refused(
        LAN,
        icmp_error(INNER_GW, REMOTE, 3, 1, &quoted),
        DropReason::Nat44Icmpv4InsideSourceMismatch,
    );
}

/// Review RFC L-3: REQ-4 matches the firewall flow by its origin only. An
/// outside error about H1's reply in an outside-initiated flow has NAT
/// authority but is refused, while REQ-5 accepts both directions.
#[test]
fn external_errors_match_the_firewall_origin_only() {
    let mut world = World::shaped(
        true,
        Shape {
            filtering: Nat44Filtering::EndpointIndependent,
            inbound_udp_rule: true,
            ..Shape::default()
        },
    );
    let public = public_source_port(&world.establish(H1, P1, false));
    // REMOTE:7000 opens a new inbound flow (origin outside).
    world.run(WAN, udp_frame(REMOTE, PUBLIC, 7000, public));
    let delivered = world.io.pop_tx().expect("inbound flow").bytes;
    // H1 replies; the reply leaves as P:x' -> REMOTE:7000.
    world.run(LAN, udp_frame(H1, REMOTE, P1, 7000));
    let reply = world.io.pop_tx().expect("reply").bytes;
    world.assert_refused(
        WAN,
        icmp_error(ROUTER, PUBLIC, 3, 1, &reply),
        DropReason::FirewallRelatedIcmpv4StateMiss,
    );
    // The inside error about the inbound packet is RELATED (origin match).
    world.run(LAN, icmp_error(H1, REMOTE, 3, 3, &delivered));
    assert_eq!(world.io.pop_tx().unwrap().egress, WAN);
}

/// Review Low-A: the UDP REQ-5 authority needs a live mapping. Past the
/// idle TTL the mapping slot still names H1:P1, but the error is refused.
#[test]
fn inside_udp_error_after_the_mapping_expired_is_a_mapping_miss() {
    let mut world = World::new(false);
    let outbound = world.establish(H1, P1, false);
    let (_, delivered) = world.reply(public_source_port(&outbound), false);
    world.now = 400_000;
    world.assert_refused(
        LAN,
        icmp_error(H1, REMOTE, 3, 3, &delivered),
        DropReason::Nat44UdpMappingMiss,
    );
}

//! INPUT-FW: the input (local-delivery) firewall `[firewall.input]` for
//! datagrams addressed to the router itself, through the validated config,
//! the publication, `run_tick`, and SimIo (fixtures/inputfw/router.toml:
//! LAN 192.168.1.1/24 with H 192.168.1.10, WAN 203.0.113.2/24 which is also
//! the NAT public address, a default route via the WAN gateway G
//! 203.0.113.1, UDP/TCP/ICMP NAPT, a stateful forward firewall).
//!
//! Every frame is built here from RFC 791/768/792 with this file's own
//! checksum, independently of the router.

use ruster_config::{parse, validate, ValidatedConfig, PRODUCTION_VALIDATION_LIMITS};
use ruster_control::{
    ActivePublication, FullServiceStorage, PublicationSequencer, SimDeterministicKeySource,
};
use ruster_core::{
    ConsumeReason, DropReason, FirewallInterface, FirewallIpv4Prefix, FirewallRuleId,
    ForwardingSnapshot, IfId, InputFirewallAction, InputFirewallError, InputFirewallProtocol,
    InputFirewallRule, Interface, Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis,
    SnapshotError, TraceEvent,
};
use ruster_io_sim::{SimIo, TxFrame, VecTrace};
use ruster_runtime::{run_tick, PublicationOutcome, TickBudgets, TickObserver};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const H_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const G_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const LAN_IP: [u8; 4] = [192, 168, 1, 1];
/// The WAN address, which is also the NAT public address.
const PUBLIC: [u8; 4] = [203, 0, 113, 2];
const H: [u8; 4] = [192, 168, 1, 10];
/// An Internet host: only the default route covers it.
const X: [u8; 4] = [192, 0, 2, 77];
/// A management host on the Internet (198.51.100.0/24).
const MGMT: [u8; 4] = [198, 51, 100, 7];
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const ROUTER: &str = include_str!("../../../fixtures/inputfw/router.toml");
const ACCEPT_TABLE: &str = "[firewall.input]\ndefault-action = \"accept\"\n";

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

fn ethernet(destination: [u8; 6], source: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// RFC 791 header with `options` (padded by the caller to 4 octets) and
/// `payload`.
#[allow(clippy::too_many_arguments)]
fn ipv4_with_options(
    source: [u8; 4],
    destination: [u8; 4],
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let header_len = 20 + options.len();
    let mut packet = vec![0x40 | u8::try_from(header_len / 4).unwrap(), 0];
    packet.extend_from_slice(
        &u16::try_from(header_len + payload.len())
            .unwrap()
            .to_be_bytes(),
    );
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&flags_fragment.to_be_bytes());
    packet.extend_from_slice(&[ttl, protocol, 0, 0]);
    packet.extend_from_slice(&source);
    packet.extend_from_slice(&destination);
    packet.extend_from_slice(options);
    let checksum = sum16(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn ipv4(
    source: [u8; 4],
    destination: [u8; 4],
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    ipv4_with_options(
        source,
        destination,
        id,
        flags_fragment,
        ttl,
        protocol,
        &[],
        payload,
    )
}

/// RFC 768 datagram with its checksum.
fn udp(source: [u8; 4], destination: [u8; 4], ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&ports.0.to_be_bytes());
    segment.extend_from_slice(&ports.1.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let checksum = match sum16(&pseudo) {
        0 => 0xffff,
        sum => sum,
    };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// RFC 792 Echo (type 8), Echo Reply (type 0), or any query-shaped `kind`.
fn icmp_echo(kind: u8, identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![kind, 0, 0, 0];
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(data);
    let checksum = sum16(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

/// An IPv4 frame received on the WAN from G's MAC with any `source`.
fn on_wan(source: [u8; 4], destination: [u8; 4], protocol: u8, l4: &[u8]) -> Vec<u8> {
    ethernet(
        WAN_MAC,
        G_MAC,
        0x0800,
        &ipv4(source, destination, 0x0505, DF, 64, protocol, l4),
    )
}

/// An IPv4 frame received on the LAN from H's MAC.
fn on_lan(destination: [u8; 4], flags_fragment: u16, protocol: u8, l4: &[u8]) -> Vec<u8> {
    ethernet(
        LAN_MAC,
        H_MAC,
        0x0800,
        &ipv4(H, destination, 0x0606, flags_fragment, 64, protocol, l4),
    )
}

/// The Echo Request `source` -> the router's WAN address, on the WAN.
fn ping_wan(source: [u8; 4]) -> Vec<u8> {
    on_wan(source, PUBLIC, 1, &icmp_echo(8, 0x77, 1, b"infw"))
}

/// The router's Echo Reply to `source` out of the WAN to G's MAC.
fn pong(source: [u8; 4]) -> Vec<u8> {
    ethernet(
        G_MAC,
        WAN_MAC,
        0x0800,
        &ipv4(
            PUBLIC,
            source,
            0,
            DF,
            64,
            1,
            &icmp_echo(0, 0x77, 1, b"infw"),
        ),
    )
}

/// H's Echo Request to the router's LAN address.
fn ping_lan() -> Vec<u8> {
    on_lan(LAN_IP, DF, 1, &icmp_echo(8, 0x42, 9, b"lan"))
}

/// UDP from H to the router's LAN address, port 53.
fn udp_lan() -> Vec<u8> {
    on_lan(LAN_IP, DF, 17, &udp(H, LAN_IP, (5000, 53), b"q"))
}

/// An unimplemented protocol (GRE, 47) from H to the router's LAN address.
fn gre_lan() -> Vec<u8> {
    on_lan(LAN_IP, DF, 47, &[0; 8])
}

/// H to the router's LAN address with a malformed Record Route option
/// (length 2 < 3): a Parameter Problem pointing at octet 21.
fn bad_options_lan() -> Vec<u8> {
    ethernet(
        LAN_MAC,
        H_MAC,
        0x0800,
        &ipv4_with_options(
            H,
            LAN_IP,
            0x0707,
            DF,
            64,
            1,
            &[7, 2, 0, 0],
            &icmp_echo(8, 1, 1, b""),
        ),
    )
}

/// H's Echo Request to the router's LAN address whose Total Length runs
/// four octets past the frame: a Parameter Problem pointing at 2.
fn truncated_lan() -> Vec<u8> {
    let mut frame = ping_lan();
    frame.truncate(frame.len() - 4);
    frame
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

/// The ICMP type and code of a router-originated frame (IHL 5).
fn icmp_kind(frame: &TxFrame) -> (u8, u8) {
    assert_eq!(u16_at(&frame.bytes, 12), 0x0800);
    assert_eq!(frame.bytes[23], 1, "an ICMP message");
    (frame.bytes[34], frame.bytes[35])
}

// --------------------------------------------------------------- world ----

/// The fixture with `table` in place of its `[firewall.input]` table.
fn router(table: &str) -> String {
    assert!(ROUTER.contains(ACCEPT_TABLE));
    ROUTER.replacen(ACCEPT_TABLE, table, 1)
}

/// `[firewall.input]` with `default` and the rule tables `rules`.
fn input(default: &str, rules: &str) -> String {
    router(&format!(
        "[firewall.input]\ndefault-action = \"{default}\"\n\n{rules}"
    ))
}

/// The recommended WAN stealth policy: everything from the LAN, Echo from
/// the management prefix on the WAN, nothing else.
const STEALTH: &str = "\
[[firewall.input.rules]]
id = 10
ingress = \"lan\"
action = \"accept\"

[[firewall.input.rules]]
id = 20
ingress = \"wan\"
source = \"198.51.100.0/24\"
protocol = \"icmp\"
icmp-type = 8
action = \"accept\"
";

fn validated(text: &str) -> ruster_config::ValidatedConfigV1 {
    let ValidatedConfig::V1(config) = validate(
        parse(text.as_bytes()).expect("parse"),
        PRODUCTION_VALIDATION_LIMITS,
    )
    .expect("valid") else {
        unreachable!("schema V1");
    };
    config
}

fn budgets() -> TickBudgets {
    TickBudgets {
        rx: 32,
        resolution_timer_scans: 16,
        failure_dispatch_scans: 16,
        generated_arp: 8,
        generated_icmpv4: 8,
        generated_fragments: 64,
    }
}

struct World {
    active: ActivePublication<'static, SimIo>,
    sequencer: PublicationSequencer<SimDeterministicKeySource>,
    io: SimIo,
    observer: TickObserver,
    now: u64,
}

impl World {
    fn new(text: &str) -> Self {
        let config = validated(text);
        let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(7));
        let candidate = sequencer.candidate(&config).expect("candidate");
        let storage = Box::leak(Box::new(
            FullServiceStorage::new(candidate.storage_shape()).expect("storage"),
        ));
        let active = ActivePublication::<SimIo>::new(storage, candidate).expect("activates");
        Self {
            active,
            sequencer,
            io: SimIo::new(),
            observer: TickObserver::default(),
            now: 0,
        }
    }

    /// Injects `frames` and runs one tick (plus one for generated ICMP) at
    /// `now`; returns the frames sent.
    fn tick(&mut self, now: u64, frames: &[(IfId, Vec<u8>)]) -> Vec<TxFrame> {
        self.now = now;
        for (ingress, frame) in frames {
            self.io.inject(*ingress, frame.clone());
        }
        let mut sent = Vec::new();
        for _ in 0..2 {
            let report = run_tick(
                &mut self.active,
                None,
                &mut self.io,
                MonotonicMillis(now),
                budgets(),
                &mut self.observer,
            );
            self.observer.observe_tick(
                MonotonicMillis(now),
                Some(self.active.generation()),
                &report,
            );
            while self.io.pop_recycled().is_some() {}
            sent.extend(std::iter::from_fn(|| self.io.pop_tx()));
        }
        sent
    }

    /// Applies `text` as a new generation (a reload) in a tick at `now`.
    fn apply(&mut self, now: u64, text: &str) {
        self.now = now;
        let candidate = self
            .sequencer
            .candidate(&validated(text))
            .expect("candidate");
        let report = run_tick(
            &mut self.active,
            Some(candidate),
            &mut self.io,
            MonotonicMillis(now),
            budgets(),
            &mut self.observer,
        );
        assert!(
            matches!(report.publication, PublicationOutcome::Applied),
            "{:?}",
            report.publication
        );
        self.observer.observe_tick(
            MonotonicMillis(now),
            Some(self.active.generation()),
            &report,
        );
    }

    fn drops(&self, reason: DropReason) -> u64 {
        self.observer
            .snapshot(MonotonicMillis(self.now))
            .drops
            .count(reason)
    }

    fn consumed(&self, reason: ConsumeReason) -> u64 {
        self.observer
            .snapshot(MonotonicMillis(self.now))
            .consumes
            .count(reason)
    }

    /// (rule denies, default denies).
    fn input_drops(&self) -> (u64, u64) {
        (
            self.drops(DropReason::Ipv4InputFirewallRuleDenied),
            self.drops(DropReason::Ipv4InputFirewallDefaultDenied),
        )
    }
}

fn bytes(frames: &[TxFrame]) -> Vec<(IfId, Vec<u8>)> {
    frames
        .iter()
        .map(|frame| (frame.egress, frame.bytes.clone()))
        .collect()
}

/// Every local probe, one per second (the class 0 limiter never refuses),
/// and what the router sent for each.
fn probe_all(world: &mut World, start: u64) -> Vec<Vec<TxFrame>> {
    [
        (WAN, ping_wan(X)),
        (LAN, ping_lan()),
        (LAN, udp_lan()),
        (LAN, gre_lan()),
        (LAN, bad_options_lan()),
        (LAN, truncated_lan()),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, frame)| world.tick(start + 1_000 * index as u64, &[frame]))
    .collect()
}

// --------------------------------------------------------------- tests ----

/// Absent, the explicit default, and `accept` with no rules are the RFC
/// behavior unchanged: Echo Reply, Port Unreachable, Protocol Unreachable,
/// and the two Parameter Problems.
#[test]
fn default_accept_is_the_rfc_behavior_unchanged() {
    let absent = router("");
    assert!(!absent.contains("\n[firewall.input]"));
    let config = validated(&absent);
    let firewall = config.firewall().expect("firewall");
    assert!(firewall.input_rules().is_empty());
    assert_eq!(firewall.input_default(), InputFirewallAction::Accept);

    let mut outputs = Vec::new();
    for text in [absent.as_str(), ROUTER, &input("accept", "")] {
        let mut world = World::new(text);
        let sent = probe_all(&mut world, 0);
        assert_eq!(bytes(&sent[0]), [(WAN, pong(X))]);
        assert_eq!(sent[1].len(), 1);
        assert_eq!(icmp_kind(&sent[1][0]), (0, 0), "Echo Reply");
        assert_eq!(icmp_kind(&sent[2][0]), (3, 3), "Port Unreachable");
        assert_eq!(icmp_kind(&sent[3][0]), (3, 2), "Protocol Unreachable");
        assert_eq!(icmp_kind(&sent[4][0]), (12, 0), "Parameter Problem");
        assert_eq!(sent[4][0].bytes[38], 21, "pointer at the option length");
        assert_eq!(icmp_kind(&sent[5][0]), (12, 0), "Parameter Problem");
        assert_eq!(sent[5][0].bytes[38], 2, "pointer at Total Length");
        assert_eq!(world.input_drops(), (0, 0));
        outputs.push(sent.iter().map(|frames| bytes(frames)).collect::<Vec<_>>());
    }
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(outputs[0], outputs[2]);
}

/// `default-action = "deny"` without rules: Echo, UDP, another protocol,
/// bad options, and a truncated datagram to any router address are all
/// silent, and a valid non-Echo ICMP message is dropped instead of
/// consumed.
#[test]
fn default_deny_drops_every_local_datagram_silently() {
    let mut world = World::new(&input("deny", ""));
    for (index, sent) in probe_all(&mut world, 0).into_iter().enumerate() {
        assert!(sent.is_empty(), "probe {index}: {sent:?}");
    }
    // The truncated datagram keeps its own drop reason; the five others
    // are default denies.
    assert_eq!(world.input_drops(), (0, 5));
    assert_eq!(world.drops(DropReason::Ipv4TotalLengthExceedsPacket), 1);
    for reason in [
        DropReason::Ipv4LocalUdpPortUnreachable,
        DropReason::Ipv4LocalProtocolUnreachable,
        DropReason::Ipv4OptionsUnsupported,
    ] {
        assert_eq!(world.drops(reason), 0, "{reason:?}");
    }

    let timestamp = on_lan(LAN_IP, DF, 1, &icmp_echo(13, 1, 1, &[0; 12]));
    assert!(world.tick(10_000, &[(LAN, timestamp)]).is_empty());
    assert_eq!(world.consumed(ConsumeReason::Ipv4LocalUnsupported), 0);
    assert_eq!(world.input_drops(), (0, 6));
}

/// RFC behavior for Echo from a management prefix only: an `accept` rule
/// for ICMP type 8 from 198.51.100.0/24 on the WAN admits that Echo; Echo
/// from another source, and any other datagram from the management host,
/// stay silent.
#[test]
fn an_allow_rule_admits_echo_from_a_prefix_only() {
    let mut world = World::new(&input("deny", STEALTH));
    assert_eq!(
        bytes(&world.tick(0, &[(WAN, ping_wan(MGMT))])),
        [(WAN, pong(MGMT))]
    );
    assert!(world.tick(1_000, &[(WAN, ping_wan(X))]).is_empty());
    let udp_from_mgmt = on_wan(MGMT, PUBLIC, 47, &[0; 8]);
    assert!(world.tick(2_000, &[(WAN, udp_from_mgmt)]).is_empty());
    let timestamp = on_wan(MGMT, PUBLIC, 1, &icmp_echo(13, 1, 1, &[0; 12]));
    assert!(world.tick(3_000, &[(WAN, timestamp)]).is_empty());
    assert_eq!(world.input_drops(), (0, 3));
}

/// Per-interface scoping (ICMP4-027): the stealth policy answers
/// everything on the LAN as before and nothing on the WAN; a `deny` rule
/// counts as a rule deny.
#[test]
fn ingress_rules_scope_the_policy_per_interface() {
    let mut world = World::new(&input("deny", STEALTH));
    let sent = probe_all(&mut world, 0);
    assert!(sent[0].is_empty(), "WAN Echo from X: {:?}", sent[0]);
    for (index, kind) in [
        (1, (0, 0)),
        (2, (3, 3)),
        (3, (3, 2)),
        (4, (12, 0)),
        (5, (12, 0)),
    ] {
        assert_eq!(sent[index].len(), 1, "probe {index}");
        assert_eq!(icmp_kind(&sent[index][0]), kind, "probe {index}");
        assert_eq!(sent[index][0].egress, LAN);
    }
    assert_eq!(world.input_drops(), (0, 1));

    // Accept by default with one deny rule for the WAN.
    let deny_wan = "\
[[firewall.input.rules]]
id = 7
ingress = \"wan\"
action = \"deny\"
";
    let mut world = World::new(&input("accept", deny_wan));
    assert!(world.tick(0, &[(WAN, ping_wan(MGMT))]).is_empty());
    assert_eq!(world.tick(1_000, &[(LAN, ping_lan())]).len(), 1);
    assert_eq!(world.input_drops(), (1, 0));
}

/// NAT traffic to the public address is not local delivery, even though
/// the public address is the WAN address: with everything denied on the
/// WAN, the answer to H's UDP query and the Echo Reply to H's ping are
/// still translated to H, and an unsolicited datagram to the public
/// address keeps its NAT drop reason.
#[test]
fn nat_traffic_to_the_public_address_stays_on_the_nat_path() {
    let mut world = World::new(&input("deny", STEALTH));
    let query = on_lan(X, DF, 17, &udp(H, X, (5000, 53), b"query"));
    let sent = world.tick(0, &[(LAN, query)]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].egress, WAN);
    let port = u16_at(&sent[0].bytes, 34);
    let answer = on_wan(X, PUBLIC, 17, &udp(X, PUBLIC, (53, port), b"answer"));
    let sent = world.tick(1_000, &[(WAN, answer)]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].egress, LAN);
    assert_eq!(&sent[0].bytes[0..6], &H_MAC);
    assert_eq!(u16_at(&sent[0].bytes, 36), 5000);

    let ping = on_lan(X, DF, 1, &icmp_echo(8, 0x99, 1, b"out"));
    let sent = world.tick(2_000, &[(LAN, ping)]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let identifier = u16_at(&sent[0].bytes, 38);
    let reply = on_wan(X, PUBLIC, 1, &icmp_echo(0, identifier, 1, b"out"));
    let sent = world.tick(3_000, &[(WAN, reply)]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].egress, LAN);
    assert_eq!(icmp_kind(&sent[0]), (0, 0));

    let unmapped = if port == 40_000 { 40_001 } else { 40_000 };
    let unsolicited = on_wan(X, PUBLIC, 17, &udp(X, PUBLIC, (53, unmapped), b"x"));
    let sent = world.tick(4_000, &[(WAN, unsolicited)]);
    assert!(sent.is_empty(), "{sent:?}");
    assert_eq!(world.drops(DropReason::Nat44UdpMappingMiss), 1);
    assert_eq!(world.input_drops(), (0, 0));
    assert_eq!(world.drops(DropReason::Ipv4LocalUdpPortUnreachable), 0);
}

/// Ordering: the martian and URPF checks run first and keep their reasons;
/// the input firewall never sees those datagrams.
#[test]
fn martian_and_urpf_checks_run_before_the_input_firewall() {
    let strict_wan = input("deny", STEALTH).replacen(
        "mac = \"02:00:00:00:00:02\"\nsource-validation = \"off\"\n",
        "mac = \"02:00:00:00:00:02\"\nsource-validation = \"strict\"\n",
        1,
    );
    let mut world = World::new(&strict_wan);
    // A spoofed inside source on the WAN fails strict before any rule.
    let spoofed = on_wan(H, PUBLIC, 1, &icmp_echo(8, 1, 1, b""));
    assert!(world.tick(0, &[(WAN, spoofed)]).is_empty());
    assert_eq!(world.drops(DropReason::Ipv4SourceValidationFailed), 1);
    // A loopback source is a martian.
    let martian = on_wan([127, 0, 0, 1], PUBLIC, 1, &icmp_echo(8, 1, 1, b""));
    assert!(world.tick(1_000, &[(WAN, martian)]).is_empty());
    assert_eq!(world.drops(DropReason::Ipv4SourceLoopback), 1);
    assert_eq!(world.input_drops(), (0, 0));
    // The management host passes URPF and its rule.
    assert_eq!(world.tick(2_000, &[(WAN, ping_wan(MGMT))]).len(), 1);
}

/// A reload changes the input policy in place: accept, deny, the stealth
/// rules, then accept again, with the same frames.
#[test]
fn a_reload_changes_the_input_policy_in_place() {
    let mut world = World::new(ROUTER);
    assert_eq!(world.tick(0, &[(WAN, ping_wan(X))]).len(), 1);
    world.apply(1_000, &input("deny", ""));
    assert!(world.tick(2_000, &[(WAN, ping_wan(MGMT))]).is_empty());
    assert_eq!(world.input_drops(), (0, 1));
    world.apply(3_000, &input("deny", STEALTH));
    assert_eq!(world.tick(4_000, &[(WAN, ping_wan(MGMT))]).len(), 1);
    assert!(world.tick(5_000, &[(WAN, ping_wan(X))]).is_empty());
    assert_eq!(world.input_drops(), (0, 2));
    world.apply(6_000, ROUTER);
    assert_eq!(world.tick(7_000, &[(WAN, ping_wan(X))]).len(), 1);
    assert_eq!(world.input_drops(), (0, 2));
}

/// Input deny wins over the per-kind `[icmpv4-errors.generate]` switches
/// and `[ipv4-origin] echo-reply`: with the switches off and the policy
/// accepting, the datagrams keep their disabled-switch reasons; denied,
/// they are input drops and never reach the switches.
#[test]
fn input_deny_wins_over_the_icmp_switches() {
    let switches_off = |text: String| {
        text.replacen(
            "host-unreachable = true\n",
            "host-unreachable = true\nprotocol-unreachable = false\nudp-port-unreachable = false\n",
            1,
        )
        .replacen("echo-reply = true", "echo-reply = false", 1)
    };
    let mut accepting = World::new(&switches_off(ROUTER.to_owned()));
    for (index, frame) in [ping_lan(), udp_lan(), gre_lan()].into_iter().enumerate() {
        assert!(accepting
            .tick(1_000 * index as u64, &[(LAN, frame)])
            .is_empty());
    }
    assert_eq!(accepting.drops(DropReason::Icmpv4EchoDisabled), 1);
    assert_eq!(accepting.drops(DropReason::Ipv4LocalUdpPortUnreachable), 1);
    assert_eq!(accepting.drops(DropReason::Ipv4LocalProtocolUnreachable), 1);

    let mut denying = World::new(&switches_off(input("deny", "")));
    for (index, frame) in [ping_lan(), udp_lan(), gre_lan()].into_iter().enumerate() {
        assert!(denying
            .tick(1_000 * index as u64, &[(LAN, frame)])
            .is_empty());
    }
    assert_eq!(denying.input_drops(), (0, 3));
    for reason in [
        DropReason::Icmpv4EchoDisabled,
        DropReason::Ipv4LocalUdpPortUnreachable,
        DropReason::Ipv4LocalProtocolUnreachable,
    ] {
        assert_eq!(denying.drops(reason), 0, "{reason:?}");
    }

    // The switches on and the rule accepting: the errors are generated.
    let mut stealth = World::new(&input("deny", STEALTH));
    assert_eq!(icmp_kind(&stealth.tick(0, &[(LAN, gre_lan())])[0]), (3, 2));
}

/// Fragments for the router are consumed without reassembly (ICMP4-006);
/// the policy judges each one. A first fragment has its transport header,
/// so an `accept` rule for UDP port 53 admits it; a later fragment has
/// none, so only the default (or a deny rule) decides it.
#[test]
fn fragments_for_the_router_are_judged_without_reassembly() {
    let first = on_lan(LAN_IP, MF, 17, &udp(H, LAN_IP, (5000, 53), &[0; 16])[..16]);
    let later = on_lan(LAN_IP, 2, 17, &[0; 16]);

    let mut accepting = World::new(ROUTER);
    assert!(accepting
        .tick(0, &[(LAN, first.clone()), (LAN, later.clone())])
        .is_empty());
    assert_eq!(accepting.consumed(ConsumeReason::Ipv4LocalUnsupported), 2);

    let dns = "\
[[firewall.input.rules]]
id = 53
protocol = \"udp\"
destination-ports = { first = 53, last = 53 }
action = \"accept\"
";
    let mut world = World::new(&input("deny", dns));
    assert!(world
        .tick(0, &[(LAN, first.clone()), (LAN, later.clone())])
        .is_empty());
    assert_eq!(world.consumed(ConsumeReason::Ipv4LocalUnsupported), 1);
    assert_eq!(world.input_drops(), (0, 1));

    // A deny rule for the port refuses the later fragment too (fail
    // closed), while the default would accept it.
    let deny_dns = dns.replace("action = \"accept\"", "action = \"deny\"");
    let mut world = World::new(&input("accept", &deny_dns));
    assert!(world.tick(0, &[(LAN, first), (LAN, later)]).is_empty());
    assert_eq!(world.input_drops(), (2, 0));
}

/// The datagram for another interface's address (ingress-scoped local
/// delivery, ICMP4-001) is not local and the input firewall does not see
/// it: Echo to the LAN address arriving on the WAN is not answered by the
/// input path either way.
#[test]
fn another_interfaces_address_is_not_local_delivery() {
    for text in [ROUTER.to_owned(), input("deny", "")] {
        let mut world = World::new(&text);
        let sent = world.tick(0, &[(WAN, on_wan(X, LAN_IP, 1, &icmp_echo(8, 1, 1, b"")))]);
        assert!(
            sent.iter().all(|frame| frame.bytes.get(34) != Some(&0)),
            "no Echo Reply: {sent:?}"
        );
        assert_eq!(world.input_drops(), (0, 0));
        // It is transit: the NAT refuses an outside-to-inside crossing.
        assert_eq!(world.drops(DropReason::Nat44ExternalToInternalBypass), 1);
    }
}

/// The snapshot API: a rule deny is traced with its rule id, a default
/// deny without one, and invalid rules are refused.
#[test]
fn snapshot_rules_trace_their_ids_and_are_validated() {
    let interfaces = [
        Interface {
            id: LAN,
            mac: MacAddress(LAN_MAC),
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: MacAddress(WAN_MAC),
            mtu: 1500,
        },
    ];
    let bindings = [
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets(LAN_IP),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: Ipv4Address::from_octets(PUBLIC),
        },
    ];
    let any = FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap();
    let rule = |id, ingress| {
        InputFirewallRule::new(
            FirewallRuleId(id),
            ingress,
            any,
            any,
            InputFirewallProtocol::Icmp { icmp_type: Some(8) },
            InputFirewallAction::Deny,
        )
    };
    let rules = [rule(7, FirewallInterface::Interface(WAN))];
    let base = ForwardingSnapshot::new(&[], &interfaces, &[], &bindings).unwrap();
    let snapshot = base
        .with_input_firewall(&rules, InputFirewallAction::Deny)
        .unwrap();
    assert_eq!(snapshot.input_firewall_rules(), rules);
    assert_eq!(snapshot.input_firewall_default(), InputFirewallAction::Deny);

    let mut io = SimIo::new();
    io.inject(WAN, ping_wan(X));
    io.inject(LAN, ping_lan());
    let mut trace = VecTrace::default();
    let report = io.run_once(2, &snapshot, &mut trace).unwrap();
    assert_eq!(report.dropped, 2);
    assert_eq!(report.tx_requested, 0);
    assert!(trace
        .events()
        .contains(&TraceEvent::Ipv4InputFirewallDenied {
            ingress: WAN,
            source: Ipv4Address::from_octets(X),
            rule: Some(FirewallRuleId(7)),
        }));
    assert!(trace
        .events()
        .contains(&TraceEvent::Ipv4InputFirewallDenied {
            ingress: LAN,
            source: Ipv4Address::from_octets(H),
            rule: None,
        }));
    for (reason, code, value) in [
        (
            DropReason::Ipv4InputFirewallRuleDenied,
            "IPV4_INPUT_FIREWALL_RULE_DENIED",
            210,
        ),
        (
            DropReason::Ipv4InputFirewallDefaultDenied,
            "IPV4_INPUT_FIREWALL_DEFAULT_DENIED",
            211,
        ),
    ] {
        assert_eq!(reason.code(), code);
        assert_eq!(reason as u16, value);
    }

    // Without rules and with accept, the router answers as before.
    let mut io = SimIo::new();
    io.inject(WAN, ping_wan(X));
    let report = io.run_once(1, &base, &mut VecTrace::default()).unwrap();
    assert_eq!(report.tx_requested, 1);

    for (rules, error) in [
        (
            vec![rule(0, FirewallInterface::Any)],
            InputFirewallError::RuleIdZero,
        ),
        (
            vec![
                rule(3, FirewallInterface::Any),
                rule(3, FirewallInterface::Any),
            ],
            InputFirewallError::DuplicateRuleId,
        ),
        (
            vec![rule(4, FirewallInterface::Interface(IfId(9)))],
            InputFirewallError::IngressInterfaceMissing,
        ),
    ] {
        assert_eq!(
            base.with_input_firewall(&rules, InputFirewallAction::Accept)
                .err(),
            Some(SnapshotError::InputFirewall(error))
        );
    }
}

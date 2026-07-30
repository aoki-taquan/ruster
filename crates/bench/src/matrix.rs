use std::convert::Infallible;
use std::hint::black_box;
use std::time::{Duration, Instant};

use ruster_core::{
    forward_batch, forward_batch_with_firewall, forward_batch_with_nat44_tcp,
    forward_batch_with_nat44_udp, forward_batch_with_nat44_udp_and_tcp_and_firewall,
    ipv4_header_checksum, validate_ipv4_frame, BatchReport, FirewallAction, FirewallConfig,
    FirewallHashKey, FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange,
    FirewallProtocol, FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Nat44TcpConfig, Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime,
    Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy,
    Nat44UdpRuntime, Neighbor, NoTrace, PacketIo, ResolutionActionSlot, ResolutionPolicy,
    ResolutionRuntime, ResolutionStateSlot, Route,
};

use crate::backend::BenchBatch;
use crate::runner::{
    ensure_no_allocations, subtract_setup_control, Measurement, MIN_AGGREGATE_REPETITIONS,
};
use crate::{
    allocation_count, BenchBackend, BenchCompletion, FrameSize, ResultRow, RunConfig, RunError,
    SampleStats,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 10]);
const GATEWAY_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 20]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const HOST_PORT: u16 = 40_000;
const REMOTE_PORT: u16 = 443;
const NOW: MonotonicMillis = MonotonicMillis(1_000);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Plain,
    Nat,
    Firewall,
    Combined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transport {
    UdpZero,
    UdpChecksum,
    Tcp,
}

impl Transport {
    const ALL: [Self; 3] = [Self::UdpZero, Self::UdpChecksum, Self::Tcp];

    const fn protocol(self) -> u8 {
        match self {
            Self::UdpZero | Self::UdpChecksum => 17,
            Self::Tcp => 6,
        }
    }

    const fn firewall_protocol(self) -> FirewallProtocol {
        match self {
            Self::UdpZero | Self::UdpChecksum => FirewallProtocol::Udp,
            Self::Tcp => FirewallProtocol::Tcp,
        }
    }

    const fn checksum_enabled(self) -> bool {
        !matches!(self, Self::UdpZero)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Outbound,
    Inbound,
}

impl Direction {
    const ALL: [Self; 2] = [Self::Outbound, Self::Inbound];

    const fn ingress(self) -> IfId {
        match self {
            Self::Outbound => LAN,
            Self::Inbound => WAN,
        }
    }

    const fn egress(self) -> IfId {
        match self {
            Self::Outbound => WAN,
            Self::Inbound => LAN,
        }
    }
}

#[derive(Clone, Copy)]
struct Case {
    profile: Profile,
    transport: Transport,
    direction: Direction,
}

impl Case {
    const fn label(self) -> &'static str {
        match (self.profile, self.transport, self.direction) {
            (Profile::Plain, Transport::UdpZero, Direction::Outbound) => "ctl-udp0-out",
            (Profile::Plain, Transport::UdpZero, Direction::Inbound) => "ctl-udp0-in",
            (Profile::Plain, Transport::UdpChecksum, Direction::Outbound) => "ctl-udpc-out",
            (Profile::Plain, Transport::UdpChecksum, Direction::Inbound) => "ctl-udpc-in",
            (Profile::Plain, Transport::Tcp, Direction::Outbound) => "ctl-tcp-out",
            (Profile::Plain, Transport::Tcp, Direction::Inbound) => "ctl-tcp-in",
            (Profile::Nat, Transport::UdpZero, Direction::Outbound) => "nat-udp0-out-est",
            (Profile::Nat, Transport::UdpZero, Direction::Inbound) => "nat-udp0-in-est",
            (Profile::Nat, Transport::UdpChecksum, Direction::Outbound) => "nat-udpc-out-est",
            (Profile::Nat, Transport::UdpChecksum, Direction::Inbound) => "nat-udpc-in-est",
            (Profile::Nat, Transport::Tcp, Direction::Outbound) => "nat-tcp-out-est",
            (Profile::Nat, Transport::Tcp, Direction::Inbound) => "nat-tcp-in-est",
            (Profile::Firewall, Transport::UdpZero, Direction::Outbound) => "fw-udp0-out-est",
            (Profile::Firewall, Transport::UdpZero, Direction::Inbound) => "fw-udp0-in-est",
            (Profile::Firewall, Transport::UdpChecksum, Direction::Outbound) => "fw-udpc-out-est",
            (Profile::Firewall, Transport::UdpChecksum, Direction::Inbound) => "fw-udpc-in-est",
            (Profile::Firewall, Transport::Tcp, Direction::Outbound) => "fw-tcp-out-est",
            (Profile::Firewall, Transport::Tcp, Direction::Inbound) => "fw-tcp-in-est",
            (Profile::Combined, Transport::UdpZero, Direction::Outbound) => "both-udp0-out-est",
            (Profile::Combined, Transport::UdpZero, Direction::Inbound) => "both-udp0-in-est",
            (Profile::Combined, Transport::UdpChecksum, Direction::Outbound) => "both-udpc-out-est",
            (Profile::Combined, Transport::UdpChecksum, Direction::Inbound) => "both-udpc-in-est",
            (Profile::Combined, Transport::Tcp, Direction::Outbound) => "both-tcp-out-est",
            (Profile::Combined, Transport::Tcp, Direction::Inbound) => "both-tcp-in-est",
        }
    }

    const fn checksum_passes(self) -> u8 {
        match (self.profile, self.transport) {
            (_, Transport::UdpZero)
            | (Profile::Plain, Transport::UdpChecksum | Transport::Tcp)
            | (Profile::Nat, Transport::UdpChecksum) => 0,
            (Profile::Nat, Transport::Tcp)
            | (Profile::Firewall, Transport::UdpChecksum | Transport::Tcp)
            | (Profile::Combined, Transport::UdpChecksum) => 1,
            (Profile::Combined, Transport::Tcp) => 2,
        }
    }
}

pub(crate) fn run_matrix(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
) -> Result<Vec<ResultRow>, RunError> {
    let mut rows = Vec::with_capacity(24);
    for transport in Transport::ALL {
        for direction in Direction::ALL {
            for profile in [
                Profile::Plain,
                Profile::Nat,
                Profile::Firewall,
                Profile::Combined,
            ] {
                let case = Case {
                    profile,
                    transport,
                    direction,
                };
                rows.push(match profile {
                    Profile::Plain => run_plain_control(config, size, batch_size, case)?,
                    Profile::Nat => run_nat_case(config, size, batch_size, case)?,
                    Profile::Firewall => run_firewall_case(config, size, batch_size, case)?,
                    Profile::Combined => run_combined_case(config, size, batch_size, case)?,
                });
            }
        }
    }
    Ok(rows)
}

fn run_plain_control(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
    case: Case,
) -> Result<ResultRow, RunError> {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let template = timed_fixture(size, config.seed, case, false);
    let mut backend = BenchBackend::new(batch_size, case.direction.ingress(), &template);
    let row = {
        let mut forward = |batch: BenchBatch<'_>| forward_batch(batch, &snapshot, &mut NoTrace);
        measure_case(
            config,
            size,
            batch_size,
            case,
            &template,
            &mut backend,
            &mut forward,
        )?
    };
    verify_case(&backend, &template, batch_size, case, false)?;
    Ok(row)
}

fn topology() -> (
    [Route; 2],
    [Interface; 2],
    [Neighbor; 2],
    [LocalIpv4Binding; 2],
) {
    (
        [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None)
                .expect("benchmark LAN route"),
            Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GATEWAY))
                .expect("benchmark default route"),
        ],
        [
            Interface {
                id: LAN,
                mac: LAN_MAC,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
            },
        ],
        [
            Neighbor {
                interface: LAN,
                target: HOST,
                mac: HOST_MAC,
            },
            Neighbor {
                interface: WAN,
                target: GATEWAY,
                mac: GATEWAY_MAC,
            },
        ],
        [
            LocalIpv4Binding {
                interface: LAN,
                address: LAN_LOCAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ],
    )
}

fn resolution<'a>(
    states: &'a mut [ResolutionStateSlot],
    actions: &'a mut [ResolutionActionSlot],
) -> ResolutionRuntime<'a> {
    ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 2_000).expect("benchmark resolution policy"),
        states,
        actions,
    )
}

fn nat_configs(snapshot: &ForwardingSnapshot<'_>) -> (Nat44UdpConfig, Nat44TcpConfig) {
    (
        Nat44UdpConfig::new(
            snapshot,
            LAN,
            WAN,
            PUBLIC,
            HOST_PORT,
            HOST_PORT,
            Nat44UdpPolicy::default(),
        )
        .expect("benchmark UDP NAT config"),
        Nat44TcpConfig::new(
            snapshot,
            LAN,
            WAN,
            PUBLIC,
            HOST_PORT,
            HOST_PORT,
            Nat44TcpPolicy::default(),
        )
        .expect("benchmark TCP NAT config"),
    )
}

fn firewall_rules() -> [FirewallRule; 2] {
    let source =
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24).expect("prefix");
    let any = FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).expect("prefix");
    let all_ports = FirewallPortRange::new(0, u16::MAX).expect("port range");
    [
        FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            source,
            any,
            FirewallProtocol::Udp,
            all_ports,
            all_ports,
            FirewallAction::AllowStateful,
        ),
        FirewallRule::new(
            FirewallRuleId(2),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            source,
            any,
            FirewallProtocol::Tcp,
            all_ports,
            all_ports,
            FirewallAction::AllowStateful,
        ),
    ]
}

fn firewall_config<'a>(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &'a [FirewallRule],
) -> FirewallConfig<'a> {
    FirewallConfig::new(
        snapshot,
        rules,
        FirewallPolicy::default(),
        1,
        FirewallHashKey::new(0x1357_9bdf_2468_ace0, 0xfdb9_7531_eca8_6420)
            .expect("benchmark hash key"),
    )
    .expect("benchmark firewall config")
}

fn run_nat_case(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
    case: Case,
) -> Result<ResultRow, RunError> {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let (udp_config, tcp_config) = nat_configs(&snapshot);
    let mut resolution_states: [ResolutionStateSlot; 0] = [];
    let mut resolution_actions: [ResolutionActionSlot; 0] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let template = timed_fixture(size, config.seed, case, true);
    let mut backend = BenchBackend::new(batch_size, case.direction.ingress(), &template);

    match case.transport {
        Transport::UdpZero | Transport::UdpChecksum => {
            let mut mappings = [Nat44UdpMappingSlot::default(); 4];
            let mut peers = [Nat44UdpPeerSlot::default(); 4];
            let mut runtime = Nat44UdpRuntime::new(udp_config, &mut mappings, &mut peers);
            establish_udp(
                case,
                |batch| {
                    forward_batch_with_nat44_udp(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &udp_config,
                        Some(&mut runtime),
                        NOW,
                        &mut NoTrace,
                    )
                },
                config.seed,
            )?;
            let row = {
                let mut forward = |batch: BenchBatch<'_>| {
                    forward_batch_with_nat44_udp(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &udp_config,
                        Some(&mut runtime),
                        NOW,
                        &mut NoTrace,
                    )
                };
                measure_case(
                    config,
                    size,
                    batch_size,
                    case,
                    &template,
                    &mut backend,
                    &mut forward,
                )?
            };
            if runtime
                .mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count()
                != 1
                || runtime
                    .peers()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count()
                    != 1
                || runtime.counters().mappings_created != 1
                || runtime.counters().peers_created != 1
            {
                return Err(RunError::ForwardingOracle);
            }
            verify_case(&backend, &template, batch_size, case, true)?;
            Ok(row)
        }
        Transport::Tcp => {
            let mut mappings = [Nat44TcpMappingSlot::default(); 4];
            let mut sessions = [Nat44TcpSessionSlot::default(); 4];
            let mut runtime = Nat44TcpRuntime::new(tcp_config, &mut mappings, &mut sessions);
            establish_tcp(
                case,
                |batch| {
                    forward_batch_with_nat44_tcp(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &tcp_config,
                        Some(&mut runtime),
                        NOW,
                        &mut NoTrace,
                    )
                },
                config.seed,
            )?;
            let row = {
                let mut forward = |batch: BenchBatch<'_>| {
                    forward_batch_with_nat44_tcp(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &tcp_config,
                        Some(&mut runtime),
                        NOW,
                        &mut NoTrace,
                    )
                };
                measure_case(
                    config,
                    size,
                    batch_size,
                    case,
                    &template,
                    &mut backend,
                    &mut forward,
                )?
            };
            if runtime
                .mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count()
                != 1
                || runtime
                    .sessions()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count()
                    != 1
                || runtime.counters().mappings_created != 1
                || runtime.counters().sessions_created != 1
            {
                return Err(RunError::ForwardingOracle);
            }
            verify_case(&backend, &template, batch_size, case, true)?;
            Ok(row)
        }
    }
}

fn run_firewall_case(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
    case: Case,
) -> Result<ResultRow, RunError> {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let rules = firewall_rules();
    let firewall_config = firewall_config(&snapshot, &rules);
    let mut firewall_states = [FirewallStateSlot::default(); 4];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_states);
    let mut resolution_states: [ResolutionStateSlot; 0] = [];
    let mut resolution_actions: [ResolutionActionSlot; 0] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let template = timed_fixture(size, config.seed, case, false);
    let mut backend = BenchBackend::new(batch_size, case.direction.ingress(), &template);

    if case.transport == Transport::Tcp {
        establish_tcp(
            case,
            |batch| {
                forward_batch_with_firewall(
                    batch,
                    &snapshot,
                    &mut resolution,
                    &firewall_config,
                    Some(&mut firewall),
                    NOW,
                    &mut NoTrace,
                )
            },
            config.seed,
        )?;
    } else {
        establish_udp(
            case,
            |batch| {
                forward_batch_with_firewall(
                    batch,
                    &snapshot,
                    &mut resolution,
                    &firewall_config,
                    Some(&mut firewall),
                    NOW,
                    &mut NoTrace,
                )
            },
            config.seed,
        )?;
    }
    let row = {
        let mut forward = |batch: BenchBatch<'_>| {
            forward_batch_with_firewall(
                batch,
                &snapshot,
                &mut resolution,
                &firewall_config,
                Some(&mut firewall),
                NOW,
                &mut NoTrace,
            )
        };
        measure_case(
            config,
            size,
            batch_size,
            case,
            &template,
            &mut backend,
            &mut forward,
        )?
    };
    let occupied = firewall
        .states()
        .iter()
        .filter(|slot| slot.is_occupied())
        .count();
    if occupied != 1
        || firewall
            .states()
            .iter()
            .find(|slot| slot.is_occupied())
            .map(|slot| slot.protocol())
            != Some(case.transport.firewall_protocol())
        || firewall.counters().allowed_new != 1
    {
        return Err(RunError::ForwardingOracle);
    }
    verify_case(&backend, &template, batch_size, case, false)?;
    Ok(row)
}

fn run_combined_case(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
    case: Case,
) -> Result<ResultRow, RunError> {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let (udp_config, tcp_config) = nat_configs(&snapshot);
    let rules = firewall_rules();
    let firewall_config = firewall_config(&snapshot, &rules);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 4];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 4];
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 4];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 4];
    let mut firewall_states = [FirewallStateSlot::default(); 4];
    let mut udp = Nat44UdpRuntime::new(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_states);
    let mut resolution_states: [ResolutionStateSlot; 0] = [];
    let mut resolution_actions: [ResolutionActionSlot; 0] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let template = timed_fixture(size, config.seed, case, true);
    let mut backend = BenchBackend::new(batch_size, case.direction.ingress(), &template);

    if case.transport == Transport::Tcp {
        establish_tcp(
            case,
            |batch| {
                forward_batch_with_nat44_udp_and_tcp_and_firewall(
                    batch,
                    &snapshot,
                    &mut resolution,
                    &udp_config,
                    Some(&mut udp),
                    &tcp_config,
                    Some(&mut tcp),
                    &firewall_config,
                    Some(&mut firewall),
                    NOW,
                    &mut NoTrace,
                )
            },
            config.seed,
        )?;
    } else {
        establish_udp(
            case,
            |batch| {
                forward_batch_with_nat44_udp_and_tcp_and_firewall(
                    batch,
                    &snapshot,
                    &mut resolution,
                    &udp_config,
                    Some(&mut udp),
                    &tcp_config,
                    Some(&mut tcp),
                    &firewall_config,
                    Some(&mut firewall),
                    NOW,
                    &mut NoTrace,
                )
            },
            config.seed,
        )?;
    }
    let row = {
        let mut forward = |batch: BenchBatch<'_>| {
            forward_batch_with_nat44_udp_and_tcp_and_firewall(
                batch,
                &snapshot,
                &mut resolution,
                &udp_config,
                Some(&mut udp),
                &tcp_config,
                Some(&mut tcp),
                &firewall_config,
                Some(&mut firewall),
                NOW,
                &mut NoTrace,
            )
        };
        measure_case(
            config,
            size,
            batch_size,
            case,
            &template,
            &mut backend,
            &mut forward,
        )?
    };
    let nat_state_ok = match case.transport {
        Transport::UdpZero | Transport::UdpChecksum => {
            udp.mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count()
                == 1
                && udp.peers().iter().filter(|slot| slot.is_occupied()).count() == 1
                && tcp.mappings().iter().all(|slot| !slot.is_occupied())
                && tcp.sessions().iter().all(|slot| !slot.is_occupied())
        }
        Transport::Tcp => {
            tcp.mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count()
                == 1
                && tcp
                    .sessions()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count()
                    == 1
                && udp.mappings().iter().all(|slot| !slot.is_occupied())
                && udp.peers().iter().all(|slot| !slot.is_occupied())
        }
    };
    if !nat_state_ok
        || firewall
            .states()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count()
            != 1
        || firewall.counters().allowed_new != 1
        || (matches!(case.transport, Transport::UdpZero | Transport::UdpChecksum)
            && (udp.counters().mappings_created != 1 || udp.counters().peers_created != 1))
        || (case.transport == Transport::Tcp
            && (tcp.counters().mappings_created != 1 || tcp.counters().sessions_created != 1))
    {
        return Err(RunError::ForwardingOracle);
    }
    verify_case(&backend, &template, batch_size, case, true)?;
    Ok(row)
}

fn establish_udp<F>(case: Case, mut forward: F, seed: u64) -> Result<(), RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let fixture = packet_fixture(
        FrameSize::Wire64,
        seed,
        case.transport,
        Direction::Outbound,
        false,
        case.profile == Profile::Nat || case.profile == Profile::Combined,
    );
    forward_setup(&fixture, LAN, &mut forward)
}

fn establish_tcp<F>(case: Case, mut forward: F, seed: u64) -> Result<(), RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let nat = case.profile == Profile::Nat || case.profile == Profile::Combined;
    let syn = tcp_fixture(FrameSize::Wire64, seed, Direction::Outbound, 0x02, nat);
    forward_setup(&syn, LAN, &mut forward)?;
    let syn_ack = tcp_fixture(FrameSize::Wire64, seed ^ 1, Direction::Inbound, 0x12, nat);
    forward_setup(&syn_ack, WAN, &mut forward)?;
    let ack = tcp_fixture(FrameSize::Wire64, seed ^ 2, Direction::Outbound, 0x10, nat);
    forward_setup(&ack, LAN, &mut forward)
}

fn forward_setup<F>(fixture: &[u8], ingress: IfId, forward: &mut F) -> Result<(), RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let mut backend = BenchBackend::new(1, ingress, fixture);
    let batch = backend.receive(1).expect("infallible backend");
    let report = forward(batch);
    verify_report(&report, 1)?;
    if backend.completion(0).is_none() {
        return Err(RunError::ForwardingOracle);
    }
    Ok(())
}

fn measure_case<F>(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
    case: Case,
    template: &[u8],
    backend: &mut BenchBackend,
    forward: &mut F,
) -> Result<ResultRow, RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    warm_case(
        case.label(),
        backend,
        template,
        batch_size,
        config.warmup_time,
        forward,
    )?;
    let repetitions = calibrate_case(
        case.label(),
        backend,
        template,
        batch_size,
        config.sample_time,
        forward,
    )?;
    let mut normalized = Vec::with_capacity(config.samples);
    let mut allocations = 0_u64;
    let mut digest = 0_u16;
    for _ in 0..config.samples {
        let measurement = measure_forward(backend, template, batch_size, repetitions, forward)?;
        allocations += measurement.allocations;
        digest = measurement.digest;
        let packets = repetitions
            .checked_mul(batch_size)
            .ok_or(RunError::RepetitionOverflow)?;
        normalized.push(measurement.elapsed.as_nanos() as f64 / packets as f64);
    }
    ensure_no_allocations(case.label(), allocations)?;
    Ok(ResultRow {
        case: case.label(),
        size,
        batch: batch_size,
        checksum_passes: case.checksum_passes(),
        seed: config.seed,
        repetitions_per_sample: repetitions,
        timed_allocations: allocations,
        stats: SampleStats::from_samples(&normalized).ok_or(RunError::InvalidStatistics)?,
        digest,
    })
}

fn warm_case<F>(
    label: &'static str,
    backend: &mut BenchBackend,
    template: &[u8],
    batch_size: usize,
    warmup: Duration,
    forward: &mut F,
) -> Result<(), RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let started = Instant::now();
    while started.elapsed() < warmup {
        match measure_forward(
            backend,
            template,
            batch_size,
            MIN_AGGREGATE_REPETITIONS,
            forward,
        ) {
            Ok(measurement) => {
                ensure_no_allocations(label, measurement.allocations)?;
                black_box(measurement);
            }
            Err(RunError::SetupControlExceededMeasured { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn calibrate_case<F>(
    label: &'static str,
    backend: &mut BenchBackend,
    template: &[u8],
    batch_size: usize,
    target: Duration,
    forward: &mut F,
) -> Result<usize, RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let mut repetitions = MIN_AGGREGATE_REPETITIONS;
    loop {
        let measurement = match measure_forward(backend, template, batch_size, repetitions, forward)
        {
            Ok(measurement) => measurement,
            Err(RunError::SetupControlExceededMeasured { .. }) => {
                repetitions = repetitions
                    .checked_mul(2)
                    .ok_or(RunError::RepetitionOverflow)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        ensure_no_allocations(label, measurement.allocations)?;
        if measurement.elapsed >= target {
            return Ok(repetitions);
        }
        repetitions = repetitions
            .checked_mul(2)
            .ok_or(RunError::RepetitionOverflow)?;
    }
}

fn measure_forward<F>(
    backend: &mut BenchBackend,
    template: &[u8],
    batch_size: usize,
    repetitions: usize,
    forward: &mut F,
) -> Result<Measurement, RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let setup_started = Instant::now();
    for _ in 0..repetitions {
        backend.reset(template);
        let batch = backend.receive(batch_size).expect("infallible backend");
        let _ = black_box(batch);
    }
    let setup_elapsed = setup_started.elapsed();

    let before_allocations = allocation_count();
    let measured_started = Instant::now();
    let mut last_report = None;
    for _ in 0..repetitions {
        backend.reset(template);
        let batch = backend.receive(batch_size).expect("infallible backend");
        last_report = Some(black_box(forward(batch)));
    }
    let measured_elapsed = measured_started.elapsed();
    let allocations = allocation_count() - before_allocations;
    let report = black_box(last_report).expect("repetitions are nonzero");
    verify_report(&report, batch_size)?;
    Ok(Measurement {
        elapsed: subtract_setup_control(setup_elapsed, measured_elapsed)?,
        allocations,
        digest: u16::try_from(report.tx_requested).unwrap_or(u16::MAX),
    })
}

fn verify_report(report: &BatchReport<Infallible>, batch_size: usize) -> Result<(), RunError> {
    if report.received != batch_size
        || report.tx_requested != batch_size
        || report.dropped != 0
        || report.consumed != 0
        || report.completion.tx_requested != batch_size
        || report.completion.tx_accepted != batch_size
        || report.completion.tx_rejected != 0
        || report.completion.recycled != 0
        || report.completion.error.is_some()
    {
        Err(RunError::UnexpectedBatchReport)
    } else {
        Ok(())
    }
}

fn timed_fixture(size: FrameSize, seed: u64, case: Case, nat: bool) -> Vec<u8> {
    packet_fixture(size, seed, case.transport, case.direction, false, nat)
}

fn packet_fixture(
    size: FrameSize,
    seed: u64,
    transport: Transport,
    direction: Direction,
    tcp_syn: bool,
    nat: bool,
) -> Vec<u8> {
    match transport {
        Transport::Tcp => tcp_fixture(
            size,
            seed,
            direction,
            if tcp_syn { 0x02 } else { 0x10 },
            nat,
        ),
        Transport::UdpZero | Transport::UdpChecksum => udp_fixture(
            size,
            seed,
            direction,
            transport == Transport::UdpChecksum,
            nat,
        ),
    }
}

fn endpoints(direction: Direction, nat: bool) -> (Ipv4Address, Ipv4Address, u16, u16) {
    match direction {
        Direction::Outbound => (HOST, REMOTE, HOST_PORT, REMOTE_PORT),
        Direction::Inbound => (
            REMOTE,
            if nat { PUBLIC } else { HOST },
            REMOTE_PORT,
            HOST_PORT,
        ),
    }
}

fn ethernet(direction: Direction) -> (MacAddress, MacAddress) {
    match direction {
        Direction::Outbound => (LAN_MAC, HOST_MAC),
        Direction::Inbound => (WAN_MAC, GATEWAY_MAC),
    }
}

fn base_frame(size: FrameSize, seed: u64, direction: Direction, protocol: u8) -> Vec<u8> {
    let mut frame = vec![0_u8; size.backend_bytes()];
    let (destination_mac, source_mac) = ethernet(direction);
    frame[0..6].copy_from_slice(&destination_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(
        &u16::try_from(size.ipv4_total_bytes())
            .expect("benchmark frame length")
            .to_be_bytes(),
    );
    frame[18..20].copy_from_slice(&(seed as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = protocol;
    frame
}

fn udp_fixture(
    size: FrameSize,
    seed: u64,
    direction: Direction,
    checksum: bool,
    nat: bool,
) -> Vec<u8> {
    let mut frame = base_frame(size, seed, direction, 17);
    let (source, destination, source_port, destination_port) = endpoints(direction, nat);
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    let udp_len = size.ipv4_total_bytes() - 20;
    frame[38..40].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("benchmark UDP length")
            .to_be_bytes(),
    );
    fill_payload(&mut frame[42..], seed);
    if checksum {
        let value = transport_checksum(source, destination, 17, &frame[34..]);
        frame[40..42].copy_from_slice(&value.to_be_bytes());
    }
    finish_ipv4_checksum(&mut frame);
    frame
}

fn tcp_fixture(size: FrameSize, seed: u64, direction: Direction, flags: u8, nat: bool) -> Vec<u8> {
    let mut frame = base_frame(size, seed, direction, 6);
    let (source, destination, source_port, destination_port) = endpoints(direction, nat);
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
    frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
    frame[46] = 5 << 4;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
    fill_payload(&mut frame[54..], seed);
    let value = transport_checksum(source, destination, 6, &frame[34..]);
    frame[50..52].copy_from_slice(&value.to_be_bytes());
    finish_ipv4_checksum(&mut frame);
    frame
}

fn fill_payload(payload: &mut [u8], seed: u64) {
    let mut state = seed.max(1);
    for byte in payload {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
}

fn finish_ipv4_checksum(frame: &mut [u8]) {
    frame[24..26].fill(0);
    let value = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&value.to_be_bytes());
}

fn transport_checksum(
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    fn add(sum: &mut u32, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            *sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            *sum += u32::from(last) << 8;
        }
    }

    let mut sum = 0_u32;
    add(&mut sum, &source.octets());
    add(&mut sum, &destination.octets());
    sum += u32::from(protocol);
    sum += u32::from(u16::try_from(segment.len()).expect("benchmark transport length"));
    add(&mut sum, segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let value = !(sum as u16);
    if protocol == 17 && value == 0 {
        0xffff
    } else {
        value
    }
}

fn transport_checksum_valid(
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: u8,
    segment: &[u8],
) -> bool {
    fn sum_words(bytes: &[u8]) -> u64 {
        let pairs = bytes
            .chunks_exact(2)
            .map(|pair| u64::from(u16::from_be_bytes([pair[0], pair[1]])))
            .sum::<u64>();
        pairs
            + bytes
                .chunks_exact(2)
                .remainder()
                .first()
                .map_or(0, |byte| u64::from(*byte) << 8)
    }

    let pseudo = sum_words(&source.octets())
        + sum_words(&destination.octets())
        + u64::from(protocol)
        + u64::try_from(segment.len()).expect("benchmark transport length")
        + sum_words(segment);
    let mut folded = pseudo;
    while folded >> 16 != 0 {
        folded = (folded & 0xffff) + (folded >> 16);
    }
    folded == 0xffff
}

fn verify_case(
    backend: &BenchBackend,
    template: &[u8],
    batch_size: usize,
    case: Case,
    nat: bool,
) -> Result<(), RunError> {
    let (source, destination, source_port, destination_port) = match (case.direction, nat) {
        (Direction::Outbound, true) => (PUBLIC, REMOTE, HOST_PORT, REMOTE_PORT),
        (Direction::Inbound, true) => (REMOTE, HOST, REMOTE_PORT, HOST_PORT),
        (Direction::Outbound, false) => (HOST, REMOTE, HOST_PORT, REMOTE_PORT),
        (Direction::Inbound, false) => (REMOTE, HOST, REMOTE_PORT, HOST_PORT),
    };
    let (destination_mac, source_mac) = match case.direction {
        Direction::Outbound => (GATEWAY_MAC, WAN_MAC),
        Direction::Inbound => (HOST_MAC, LAN_MAC),
    };
    let mut expected = template.to_vec();
    expected[0..6].copy_from_slice(&destination_mac.0);
    expected[6..12].copy_from_slice(&source_mac.0);
    expected[22] = 63;
    expected[26..30].copy_from_slice(&source.octets());
    expected[30..34].copy_from_slice(&destination.octets());
    expected[34..36].copy_from_slice(&source_port.to_be_bytes());
    expected[36..38].copy_from_slice(&destination_port.to_be_bytes());
    if case.transport.checksum_enabled() {
        let checksum_offset = if case.transport == Transport::Tcp {
            50
        } else {
            40
        };
        expected[checksum_offset..checksum_offset + 2].fill(0);
        let value = transport_checksum(
            source,
            destination,
            case.transport.protocol(),
            &expected[34..],
        );
        expected[checksum_offset..checksum_offset + 2].copy_from_slice(&value.to_be_bytes());
    }
    finish_ipv4_checksum(&mut expected);
    for index in 0..batch_size {
        if backend.completion(index) != Some(BenchCompletion::Transmitted(case.direction.egress()))
        {
            return Err(RunError::ForwardingOracle);
        }
        let bytes = backend.bytes(index).ok_or(RunError::ForwardingOracle)?;
        let ipv4 = validate_ipv4_frame(bytes).map_err(|_| RunError::ForwardingOracle)?;
        let actual_source_port = u16::from_be_bytes([bytes[34], bytes[35]]);
        let actual_destination_port = u16::from_be_bytes([bytes[36], bytes[37]]);
        if bytes[0..6] != destination_mac.0
            || bytes[6..12] != source_mac.0
            || ipv4.ttl != 63
            || ipv4.protocol != case.transport.protocol()
            || ipv4.source != source
            || ipv4.destination != destination
            || actual_source_port != source_port
            || actual_destination_port != destination_port
            || bytes != expected
        {
            return Err(RunError::ForwardingOracle);
        }
        let segment = &bytes[34..14 + ipv4.total_len];
        match case.transport {
            Transport::UdpZero if bytes[40..42] != [0, 0] => {
                return Err(RunError::ForwardingOracle);
            }
            Transport::UdpChecksum | Transport::Tcp
                if !transport_checksum_valid(source, destination, ipv4.protocol, segment) =>
            {
                return Err(RunError::ForwardingOracle);
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_fixtures_cover_sizes_directions_and_checksum_modes() {
        for size in FrameSize::ALL {
            for transport in Transport::ALL {
                for direction in Direction::ALL {
                    let frame = packet_fixture(size, 7, transport, direction, false, true);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    assert_eq!(frame.len(), size.backend_bytes());
                    assert_eq!(ipv4.total_len, size.ipv4_total_bytes());
                    let segment = &frame[34..14 + ipv4.total_len];
                    if transport == Transport::UdpZero {
                        assert_eq!(&frame[40..42], &[0, 0]);
                    } else {
                        assert!(transport_checksum_valid(
                            ipv4.source,
                            ipv4.destination,
                            ipv4.protocol,
                            segment
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn short_matrix_identifies_every_case() {
        let mut config = RunConfig::smoke();
        config.samples = 1;
        config.sample_time = Duration::from_micros(100);
        config.warmup_time = Duration::ZERO;
        for transport in Transport::ALL {
            for direction in Direction::ALL {
                for profile in [
                    Profile::Plain,
                    Profile::Nat,
                    Profile::Firewall,
                    Profile::Combined,
                ] {
                    let case = Case {
                        profile,
                        transport,
                        direction,
                    };
                    let result = match profile {
                        Profile::Plain => run_plain_control(&config, FrameSize::Wire64, 1, case),
                        Profile::Nat => run_nat_case(&config, FrameSize::Wire64, 1, case),
                        Profile::Firewall => run_firewall_case(&config, FrameSize::Wire64, 1, case),
                        Profile::Combined => run_combined_case(&config, FrameSize::Wire64, 1, case),
                    };
                    assert!(result.is_ok(), "{}: {result:?}", case.label());
                }
            }
        }
    }

    #[test]
    fn checksum_pass_metadata_matches_full_transport_scans() {
        let expectations = [
            (Profile::Plain, Transport::UdpZero, 0),
            (Profile::Plain, Transport::UdpChecksum, 0),
            (Profile::Plain, Transport::Tcp, 0),
            (Profile::Nat, Transport::UdpZero, 0),
            (Profile::Nat, Transport::UdpChecksum, 0),
            (Profile::Nat, Transport::Tcp, 1),
            (Profile::Firewall, Transport::UdpZero, 0),
            (Profile::Firewall, Transport::UdpChecksum, 1),
            (Profile::Firewall, Transport::Tcp, 1),
            (Profile::Combined, Transport::UdpZero, 0),
            (Profile::Combined, Transport::UdpChecksum, 1),
            (Profile::Combined, Transport::Tcp, 2),
        ];
        for (profile, transport, expected) in expectations {
            for direction in Direction::ALL {
                let case = Case {
                    profile,
                    transport,
                    direction,
                };
                assert_eq!(
                    case.checksum_passes(),
                    expected,
                    "{} metadata",
                    case.label()
                );
            }
        }
    }
}

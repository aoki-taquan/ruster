//! AFPKT-015: `ruster run` over the AF_PACKET backend, on the scripted
//! host. The startup has no session per port: every port is resolved and
//! checked first, then all are opened at once; the datapath owns the
//! sockets, and dropping it after the drain closes them.

use super::*;
use crate::run::checks::cap;

const PACKET_BACKEND: &str = r#"
[backend]
kind = "af-packet"

[backend.af-packet]
max-frame-len = 1514

[[backend.af-packet.ports]]
interface = "wan"
rx = { block-size = 65536, block-count = 4, retire-timeout-ms = 4 }
tx = { block-size = 65536, block-count = 2 }

[[backend.af-packet.ports]]
interface = "lan"
rx = { block-size = 65536, block-count = 4, retire-timeout-ms = 4 }
tx = { block-size = 65536, block-count = 2 }
"#;

/// `open_packet_ports` calls `stop()` once per port, `execute_packet`
/// once before the open, and `serve` once before activation: the first
/// loop check is call 5 with two ports.
const PACKET_FIRST_LOOP_CHECK: u32 = 5;

fn packet_config() -> ValidatedConfigV1 {
    config_with(PACKET_BACKEND)
}

fn run_packet(host: &FakeHost, policy: CheckPolicy, stop: &impl StopSignal) -> Outcome {
    run_packet_with(host, settings(policy, 0), stop)
}

fn run_packet_with(host: &FakeHost, settings: Settings, stop: &impl StopSignal) -> Outcome {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = execute_with(
        host,
        packet_config(),
        FakeSource::default(),
        settings,
        &mut FakeClock {
            step_us: 1_000,
            ..FakeClock::default()
        },
        stop,
        &mut out,
        &mut err,
    );
    Outcome {
        status,
        out: String::from_utf8(out).expect("utf-8"),
        err: String::from_utf8(err).expect("utf-8"),
    }
}

#[test]
fn af_packet_run_checks_every_port_then_opens_all_at_once_and_closes_by_drop() {
    let host = FakeHost::default();
    let outcome = run_packet(
        &host,
        CheckPolicy::default(),
        &FakeStop::after(PACKET_FIRST_LOOP_CHECK + 3),
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(
        host.events(),
        [
            Event::Preflight,
            // lan (if1) first although the config lists wan first; no
            // session, no attach.
            Event::Inspect(LAN),
            Event::Inspect(WAN),
            Event::OpenPacket([fake_ifindex(LAN), fake_ifindex(WAN)]),
            Event::Drain(DRAIN_ROUNDS),
            Event::ClosePacket,
        ]
    );
    host.assert_released();
    // The AF_PACKET preflight gets the drop policy too.
    assert_eq!(
        host.preflight_policies.borrow().as_slice(),
        [PrivilegePolicy::default()]
    );
    // The full lockdown ran after the open, before the first tick.
    let lockdowns = host.state.lockdowns.borrow();
    assert_eq!(lockdowns.len(), 1);
    assert_eq!(lockdowns[0].events_before, 4, "after the open");
    assert_eq!(lockdowns[0].ticks_before, 0);
    assert_eq!(host.state.confines.borrow().len(), 1);
    assert!(
        outcome.err.contains(&format!("{READY} 1 on 2 port(s)")),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains("stopped by signal; ") && outcome.err.contains("; closed 2 port(s)"),
        "{}",
        outcome.err
    );
    assert!(!outcome.err.contains("detached"), "{}", outcome.err);
    assert!(outcome.out.contains("fake.ports=2\n"), "{}", outcome.out);
    // Every health sample (here every tick) follows a backend refresh
    // (AF_PACKET folds PACKET_STATISTICS there).
    assert!(host.state.sampled.get() >= 3);
    assert_eq!(host.state.refreshes.get(), host.state.sampled.get());
    assert!(!host.state.unrefreshed_sample.get());
}

#[test]
fn af_packet_startup_refusals_open_nothing() {
    type Setup = fn(&mut FakeHost);
    let cases: [(Setup, &str, u8); 11] = [
        (
            |host| host.packet_offload = Some(Ok(Offload::Gro)),
            "stage=checks port=if1 code=RECEIVE_OFFLOAD feature=rx-gro",
            EXIT_RUNTIME,
        ),
        (
            |host| host.packet_offload = Some(Ok(Offload::GroHw)),
            "stage=checks port=if1 code=RECEIVE_OFFLOAD feature=rx-gro-hw",
            EXIT_RUNTIME,
        ),
        (
            |host| host.packet_offload = Some(Err(())),
            "stage=checks port=if1 code=UNVERIFIABLE probe=offloads",
            EXIT_RUNTIME,
        ),
        (
            |host| host.packet_mtu = Some(1_400),
            "stage=checks port=if1 code=MTU_BELOW_FRAME mtu=1400 required=1500",
            EXIT_RUNTIME,
        ),
        (
            |host| host.packet_mtu = Some(9_000),
            "stage=checks port=if1 code=MTU_ABOVE_FRAME mtu=9000 limit=1500",
            EXIT_RUNTIME,
        ),
        (
            |host| host.packet_master = Some(WAN),
            "stage=checks port=if2 code=KERNEL_UPPER_DEVICE",
            EXIT_RUNTIME,
        ),
        (
            |host| host.ipv4_routes = 1,
            "stage=checks port=if1 code=KERNEL_IPV4_ROUTES count=1",
            EXIT_RUNTIME,
        ),
        (
            |host| host.forwarding_on = true,
            "stage=checks port=if1 code=KERNEL_FORWARDING_ENABLED scope=global",
            EXIT_RUNTIME,
        ),
        (
            |host| host.weak_host = true,
            "stage=checks port=if1 code=KERNEL_IPV4_WEAK_HOST",
            EXIT_RUNTIME,
        ),
        (
            |host| host.renamed = Some(LAN),
            "stage=checks port=if1 code=UNVERIFIABLE probe=name",
            EXIT_RUNTIME,
        ),
        (
            |host| host.privilege = Some(PrivilegeFailure::MissingCapabilities(1 << cap::NET_RAW)),
            "stage=privileges code=MISSING_CAPABILITIES missing=CAP_NET_RAW",
            EXIT_PRIVILEGE,
        ),
    ];
    for (setup, line, status) in cases {
        let mut host = FakeHost::default();
        setup(&mut host);
        let outcome = run_packet(
            &host,
            CheckPolicy::default(),
            &FakeStop::after(PACKET_FIRST_LOOP_CHECK + 3),
        );
        assert_eq!(outcome.status, status, "{line}: {}", outcome.err);
        assert!(
            outcome
                .err
                .contains(&format!("ruster run: startup failed: {line}\n")),
            "{line}: {}",
            outcome.err
        );
        assert!(
            !host
                .events()
                .iter()
                .any(|event| matches!(event, Event::OpenPacket(_))),
            "{line}: opened"
        );
        host.assert_released();
        assert!(host.state.lockdowns.borrow().is_empty());
    }
    // The capability hint names only what AF_PACKET needs.
    let host = FakeHost {
        privilege: Some(PrivilegeFailure::MissingCapabilities(1 << cap::NET_RAW)),
        ..FakeHost::default()
    };
    let outcome = run_packet(
        &host,
        CheckPolicy::default(),
        &FakeStop::after(PACKET_FIRST_LOOP_CHECK + 3),
    );
    assert!(
        outcome
            .err
            .contains("ruster run: run as root or grant CAP_NET_RAW\n"),
        "{}",
        outcome.err
    );
    assert!(!outcome.err.contains("CAP_BPF"), "{}", outcome.err);
}

#[test]
fn af_packet_overrides_and_queue_counts_follow_the_af_xdp_rules() {
    // A multi-queue device needs no override (a packet socket receives
    // from every queue); kernel forwarding and the weak host are accepted
    // with their overrides, as for AF_XDP, with the same warnings.
    let host = FakeHost {
        multi_queue: Some(LAN),
        forwarding_on: true,
        weak_host: true,
        ..FakeHost::default()
    };
    let policy = CheckPolicy {
        allow_kernel_forwarding: true,
        allow_ipv4_weak_host: true,
        ..CheckPolicy::default()
    };
    let outcome = run_packet(&host, policy, &FakeStop::after(PACKET_FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    for line in [
        "ruster run: warning: port=if1 IPV4_FORWARDING_ENABLED scope=global\n",
        "ruster run: warning: port=if1 IPV4_WEAK_HOST_EXPOSURE\n",
    ] {
        assert!(outcome.err.contains(line), "{line}: {}", outcome.err);
    }
    assert!(!outcome.err.contains("MULTI_QUEUE"), "{}", outcome.err);
    host.assert_released();
}

#[test]
fn af_packet_open_failure_and_a_signal_roll_back_cleanly() {
    let host = FakeHost::failing(Stage::Open, None);
    let outcome = run_packet(
        &host,
        CheckPolicy::default(),
        &FakeStop::after(PACKET_FIRST_LOOP_CHECK + 3),
    );
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("ruster run: startup failed: stage=open code=PORTS\n"),
        "{}",
        outcome.err
    );
    host.assert_released();
    assert!(host.state.lockdowns.borrow().is_empty());
    // A stop request between the checks and the open: nothing opened.
    let host = FakeHost::default();
    let outcome = run_packet(&host, CheckPolicy::default(), &FakeStop::after(3));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(
        outcome.err.contains("startup cancelled by signal"),
        "{}",
        outcome.err
    );
    assert_eq!(
        host.events(),
        [Event::Preflight, Event::Inspect(LAN), Event::Inspect(WAN)]
    );
    host.assert_released();
}

fn sample(interface: u16, device_gone: bool) -> PortSample {
    PortSample {
        interface: IfId(interface),
        polls: 0,
        tx_inflight: 0,
        oldest_age_polls: 0,
        kick_errors: 0,
        kick_link_down: false,
        fill_starved: 0,
        fill_ring_occupancy: 0,
        rx_packets: 0,
        device_gone,
    }
}

#[test]
fn an_unbound_af_packet_port_is_fatal_device_removed() {
    let host = FakeHost::default();
    host.state.samples.borrow_mut().extend([
        vec![sample(LAN, false), sample(WAN, false)],
        vec![sample(LAN, true), sample(WAN, false)],
    ]);
    let outcome = run_packet(
        &host,
        CheckPolicy::default(),
        &FakeStop::after(PACKET_FIRST_LOOP_CHECK + 40),
    );
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("ruster run: fatal: port=if1 health=DEVICE_REMOVED\n"),
        "{}",
        outcome.err
    );
    assert!(
        outcome
            .err
            .contains("stopped after a fatal health event port=if1 code=DEVICE_REMOVED; ")
            && outcome.err.contains("; closed 2 port(s)"),
        "{}",
        outcome.err
    );
    // Drained, then the sockets closed with the datapath.
    let events = host.events();
    assert_eq!(
        &events[events.len() - 2..],
        [Event::Drain(DRAIN_ROUNDS), Event::ClosePacket]
    );
    host.assert_released();
}

#[test]
fn kernel_exposure_found_at_run_time_ends_an_af_packet_run() {
    // A kernel IPv4 address on the port while the router runs: the kernel
    // answers on it in parallel, so the run stops (fail closed).
    let host = FakeHost::default();
    host.state
        .addresses
        .borrow_mut()
        .push_back((IfId(LAN), Ok(1)));
    let outcome = run_packet(
        &host,
        CheckPolicy::default(),
        &FakeStop::after(PACKET_FIRST_LOOP_CHECK + 40),
    );
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("ruster run: warning: port=if1 health=KERNEL_IPV4_ADDRESSES\n")
            && outcome
                .err
                .contains("ruster run: fatal: port=if1 health=KERNEL_IPV4_ADDRESSES\n"),
        "{}",
        outcome.err
    );
    assert!(
        outcome
            .err
            .contains("stopped after a fatal health event port=if1 code=KERNEL_IPV4_ADDRESSES"),
        "{}",
        outcome.err
    );
    host.assert_released();

    // Accepted at startup through an override: only a warning at run time.
    let host = FakeHost::default();
    host.state.forwarding.borrow_mut().push_back((
        IfId(LAN),
        Ok(Forwarding {
            global: true,
            ..Forwarding::default()
        }),
    ));
    let policy = CheckPolicy {
        allow_kernel_forwarding: true,
        ..CheckPolicy::default()
    };
    let outcome = run_packet(&host, policy, &FakeStop::after(PACKET_FIRST_LOOP_CHECK + 6));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("ruster run: warning: port=if1 health=KERNEL_FORWARDING_ENABLED\n"),
        "{}",
        outcome.err
    );
    assert!(!outcome.err.contains("fatal"), "{}", outcome.err);

    // The same address on an AF_XDP port only warns (XDP takes the frames).
    let host = FakeHost::default();
    host.state
        .addresses
        .borrow_mut()
        .push_back((IfId(LAN), Ok(1)));
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 6));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("ruster run: warning: port=if1 health=KERNEL_IPV4_ADDRESSES\n"),
        "{}",
        outcome.err
    );
    assert!(!outcome.err.contains("fatal"), "{}", outcome.err);
}

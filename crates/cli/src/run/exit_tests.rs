//! OPS-EXIT: the opt-in exit protection (`[exit-protection]`) and the
//! user-namespace diagnostic of `ruster run`, on the scripted host.

use super::*;

const FORWARDING: &str = "\n[exit-protection]\nipv4-forwarding-off = true\n";
const BOTH: &str = "\n[exit-protection]\nipv4-forwarding-off = true\nlink-down = true\n";

fn protected(extra: &str) -> ValidatedConfigV1 {
    config_with(&format!("{BACKEND}{extra}"))
}

fn run_config(
    host: &FakeHost,
    config: ValidatedConfigV1,
    settings: Settings,
    stop: u32,
) -> Outcome {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = execute_with(
        host,
        config,
        FakeSource::default(),
        settings,
        &mut FakeClock {
            step_us: 1_000,
            ..FakeClock::default()
        },
        &FakeStop::after(stop),
        &mut out,
        &mut err,
    );
    let outcome = Outcome {
        status,
        out: String::from_utf8(out).expect("utf-8"),
        err: String::from_utf8(err).expect("utf-8"),
    };
    super::super::log::tests::assert_classified(&outcome.err);
    outcome
}

fn keep() -> Settings {
    let mut settings = settings(CheckPolicy::default(), 0);
    settings.privileges = PrivilegePolicy::Keep;
    settings
}

/// The exit actions run once, after the drain and before the first port
/// is detached; their resources were opened after the adapter (before the
/// filters); the armed line follows the filter and precedes readiness.
#[test]
fn the_exit_actions_run_after_the_drain_and_before_the_detach() {
    let host = FakeHost::default();
    let outcome = run_config(&host, protected(FORWARDING), keep(), FIRST_LOOP_CHECK + 2);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let events = host.events();
    let at = |wanted: Event| events.iter().position(|event| *event == wanted);
    let opened = at(Event::ExitOpen {
        link_down: false,
        forwarding_off: true,
    })
    .expect("opened");
    let applied = at(Event::ExitApplied).expect("applied");
    let adapter = at(Event::Adapter).expect("adapter");
    let last_drain = events
        .iter()
        .rposition(|event| matches!(event, Event::Drain(_)))
        .expect("drained");
    let first_close = events
        .iter()
        .position(|event| matches!(event, Event::Close { .. }))
        .expect("closed");
    assert!(adapter < opened && opened < last_drain, "{events:?}");
    assert!(last_drain < applied && applied < first_close, "{events:?}");
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::ExitApplied)
            .count(),
        1
    );
    // Armed after the syscall filter, before readiness.
    let seccomp = outcome
        .err
        .find("seccomp filter installed")
        .expect("filter");
    let armed = outcome
        .err
        .find(
            "ruster run: exit protection armed: ipv4-forwarding-off=true link-down=false ports=2\n",
        )
        .expect("armed line");
    assert!(seccomp < armed && armed < outcome.err.find(READY).expect("ready"));
    assert!(
        outcome.err.contains(
            "ruster run: exit protection applied: ipv4-forwarding-off=2 link-down=0 failed=0\n"
        ),
        "{}",
        outcome.err
    );
}

/// Off (the default): nothing is opened, armed, or applied.
#[test]
fn without_the_section_nothing_is_opened_or_applied() {
    let host = FakeHost::default();
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 2));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(!host
        .events()
        .iter()
        .any(|event| matches!(event, Event::ExitOpen { .. } | Event::ExitApplied)));
    assert!(!outcome.err.contains("exit protection"), "{}", outcome.err);
}

/// `link-down` needs `CAP_NET_ADMIN` at exit, which the default drop
/// removes: refused with exit 2 before any resource. With
/// `--keep-privileges` both actions run.
#[test]
fn link_down_needs_kept_privileges() {
    let host = FakeHost::default();
    let outcome = run_config(
        &host,
        protected(BOTH),
        settings(CheckPolicy::default(), 0),
        FIRST_LOOP_CHECK + 2,
    );
    assert_eq!(outcome.status, EXIT_INVALID, "{}", outcome.err);
    assert!(outcome.err.contains(
        "ruster run: invalid config: stage=exit-protection \
         code=EXIT_LINK_DOWN_NEEDS_PRIVILEGES path=exit-protection.link-down\n"
    ));
    assert!(outcome.err.contains("--keep-privileges"), "{}", outcome.err);
    assert!(host.events().is_empty(), "{:?}", host.events());

    let host = FakeHost::default();
    let outcome = run_config(&host, protected(BOTH), keep(), FIRST_LOOP_CHECK + 2);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome.err.contains(
        "ruster run: exit protection applied: ipv4-forwarding-off=2 link-down=2 failed=0\n"
    ));
}

/// `ipv4-forwarding-off` needs `CAP_NET_ADMIN` at exit too (Linux checks
/// it at every sysctl write): refused under the default drop and with
/// `--user`/`--group`.
#[test]
fn forwarding_off_needs_kept_privileges() {
    let mut switch = settings(CheckPolicy::default(), 0);
    switch.privileges = PrivilegePolicy::Drop {
        identity: Some(Identity {
            uid: 1000,
            gid: 1000,
        }),
    };
    for settings in [settings(CheckPolicy::default(), 0), switch] {
        let host = FakeHost::default();
        let outcome = run_config(&host, protected(FORWARDING), settings, FIRST_LOOP_CHECK + 2);
        assert_eq!(outcome.status, EXIT_INVALID, "{}", outcome.err);
        assert!(outcome.err.contains(
            "code=EXIT_FORWARDING_NEEDS_PRIVILEGES path=exit-protection.ipv4-forwarding-off"
        ));
        assert!(host.events().is_empty());
    }
}

/// A failed action is reported per port and action, the others still
/// run, and the exit status is 1; the ports are still detached.
#[test]
fn a_failed_exit_action_exits_1_and_still_detaches() {
    let host = FakeHost {
        exit_fails: Some(WAN),
        ..FakeHost::default()
    };
    let outcome = run_config(&host, protected(BOTH), keep(), FIRST_LOOP_CHECK + 2);
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    for action in ["ipv4-forwarding-off", "link-down"] {
        assert!(
            outcome.err.contains(&format!(
                "ruster run: exit protection failed: port=if{WAN} action={action} code=INJECTED\n"
            )),
            "{}",
            outcome.err
        );
    }
    assert!(outcome.err.contains(
        "ruster run: exit protection applied: ipv4-forwarding-off=1 link-down=1 failed=2\n"
    ));
    assert!(outcome.err.contains("detached and closed 2 port(s)"));
    host.assert_released();
}

/// A startup that fails after the resources were opened, or is
/// cancelled, never arms the actions: the ports keep the operator's
/// state.
#[test]
fn a_startup_that_never_served_applies_nothing() {
    let host = FakeHost::failing(Stage::Seccomp, None);
    let outcome = run_config(&host, protected(FORWARDING), keep(), FIRST_LOOP_CHECK + 2);
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(host
        .events()
        .iter()
        .any(|event| matches!(event, Event::ExitOpen { .. })));
    assert!(!host.events().contains(&Event::ExitApplied));
    assert!(!outcome.err.contains("exit protection"), "{}", outcome.err);
    host.assert_released();

    let host = FakeHost::default();
    let outcome = run_config(&host, protected(FORWARDING), keep(), 3);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(!host.events().contains(&Event::ExitApplied));
    host.assert_released();
}

/// The resources cannot be opened: a startup failure at
/// `stage=exit-protection` that rolls back every port.
#[test]
fn an_exit_resource_that_cannot_open_fails_the_startup() {
    let host = FakeHost::failing(Stage::ExitProtection, None);
    let outcome = run_config(&host, protected(FORWARDING), keep(), FIRST_LOOP_CHECK + 2);
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome.err.contains(&format!(
            "ruster run: startup failed: stage=exit-protection port=if{LAN} code=INJECTED"
        )),
        "{}",
        outcome.err
    );
    assert!(!outcome.err.contains(READY));
    assert!(host.state.confines.borrow().is_empty(), "before the filter");
    host.assert_released();
}

/// A fatal device event ends the run like a signal: the actions still
/// run before the detach (and the exit status stays 1).
#[test]
fn a_fatal_event_still_applies_the_exit_actions() {
    let host = FakeHost::default();
    host.state
        .links
        .borrow_mut()
        .push_back((IfId(WAN), Err(NetlinkError::Kernel(-19))));
    let outcome = run_config(&host, protected(FORWARDING), keep(), FIRST_LOOP_CHECK + 50);
    assert_eq!(outcome.status, EXIT_RUNTIME, "{}", outcome.err);
    assert!(
        outcome.err.contains("code=DEVICE_REMOVED"),
        "{}",
        outcome.err
    );
    assert!(host.events().contains(&Event::ExitApplied));
    assert!(outcome.err.contains("exit protection applied:"));
    host.assert_released();
}

/// Review M3 (interim posture): the kept privileges are refused without
/// the syscall filter or the filesystem confinement.
#[test]
fn exit_protection_needs_the_filters_on() {
    for (seccomp, fs, code) in [
        (
            SeccompMode::Off,
            FsConfineMode::Landlock,
            "EXIT_PROTECTION_NEEDS_SECCOMP",
        ),
        (
            SeccompMode::Kill,
            FsConfineMode::Off,
            "EXIT_PROTECTION_NEEDS_FS_CONFINE",
        ),
    ] {
        let host = FakeHost::default();
        let mut settings = keep();
        settings.seccomp = seccomp;
        settings.fs_confine = fs;
        let outcome = run_config(&host, protected(FORWARDING), settings, FIRST_LOOP_CHECK + 2);
        assert_eq!(outcome.status, EXIT_INVALID, "{}", outcome.err);
        assert!(
            outcome.err.contains(&format!(
                "invalid config: stage=exit-protection code={code} path=exit-protection\n"
            )),
            "{}",
            outcome.err
        );
        assert!(host.events().is_empty());
    }
    // `--seccomp log` keeps a filter and is accepted.
    let host = FakeHost::default();
    let mut settings = keep();
    settings.seccomp = SeccompMode::Log;
    let outcome = run_config(&host, protected(FORWARDING), settings, FIRST_LOOP_CHECK + 2);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
}

/// Review core L3: a panic after readiness (here in the drain) still runs
/// the exit actions, through the guard's `Drop`, before any port closes.
#[test]
fn a_panic_after_readiness_runs_the_exit_actions_before_the_close() {
    let host = FakeHost::default();
    host.state.panic_in_drain.set(true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_config(&host, protected(FORWARDING), keep(), FIRST_LOOP_CHECK + 2)
    }));
    assert!(result.is_err(), "the injected panic propagates");
    host.assert_released();
    let events = host.events();
    let applied = events
        .iter()
        .position(|event| *event == Event::ExitApplied)
        .expect("applied while unwinding");
    let first_close = events
        .iter()
        .position(|event| matches!(event, Event::Close { .. }))
        .expect("closed");
    assert!(applied < first_close, "{events:?}");
}

/// OPS-EXIT item 4: outside the initial user namespace the startup warns
/// once, value-free; inside it says nothing.
#[test]
fn a_non_initial_user_namespace_is_warned() {
    let host = FakeHost {
        user_namespace: true,
        ..FakeHost::default()
    };
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(
        outcome
            .err
            .matches("ruster run: warning: user namespace: code=USER_NAMESPACE_NOT_INITIAL")
            .count(),
        1,
        "{}",
        outcome.err
    );
    let host = FakeHost::default();
    let outcome = run(&host, &FakeStop::after(FIRST_LOOP_CHECK + 1));
    assert!(!outcome.err.contains("user namespace"), "{}", outcome.err);
}

/// Review core L2: once the exit actions closed an exposure, the exit
/// warning says so: forwarding off rewords the forwarding warning, every
/// link down drops the exposure warnings.
#[test]
fn exit_warnings_follow_what_the_exit_actions_closed() {
    let run_with_forwarding = |config: &str| {
        let host = FakeHost::default();
        // Forwarding seen on the WAN port in every link round.
        let on = Forwarding {
            global: true,
            device: false,
            force: false,
            multicast: false,
        };
        for _ in 0..1_000 {
            host.state
                .forwarding
                .borrow_mut()
                .push_back((IfId(WAN), Ok(on)));
        }
        run_config(&host, protected(config), keep(), FIRST_LOOP_CHECK + 20)
    };
    let plain = "kernel forwarding is enabled; detached ports may be forwarded by the kernel";
    let outcome = run_with_forwarding("");
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome.err.contains(plain), "{}", outcome.err);

    let outcome = run_with_forwarding(FORWARDING);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(!outcome.err.contains(plain), "{}", outcome.err);
    assert!(
        outcome
            .err
            .contains("the ports' forwarding was turned off at exit"),
        "{}",
        outcome.err
    );

    let outcome = run_with_forwarding(BOTH);
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(
        !outcome.err.contains("warning: kernel forwarding"),
        "{}",
        outcome.err
    );
}

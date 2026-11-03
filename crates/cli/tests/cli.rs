//! Process-level tests of the built `ruster` binary.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ruster");
/// Generous bound for CI; the happy path takes well under a second.
const TIMEOUT: Duration = Duration::from_secs(60);

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/m1")
}

fn ruster(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(BIN).args(args).output().expect("spawn ruster")
}

fn run(args: &[&str]) -> Output {
    let args: Vec<&std::ffi::OsStr> = args.iter().map(std::ffi::OsStr::new).collect();
    ruster(&args)
}

fn fixture(name: &str) -> String {
    fixtures()
        .join(name)
        .to_str()
        .expect("utf-8 path")
        .to_owned()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("utf-8 output")
}

/// A fresh directory under the cargo test tmpdir.
fn scratch() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn status(output: &Output) -> i32 {
    output.status.code().expect("exited normally")
}

#[test]
fn help_version_and_usage_errors_have_documented_statuses() {
    let help = run(&["--help"]);
    assert_eq!(status(&help), 0);
    assert!(text(&help.stdout).contains("ruster run-sim [--hold] --scenario"));
    let version = run(&["--version"]);
    assert_eq!(status(&version), 0);
    assert_eq!(
        text(&version.stdout),
        format!("ruster {}\n", env!("CARGO_PKG_VERSION"))
    );
    for args in [
        &[][..],
        &["frobnicate"][..],
        &["--verbose"][..],
        &["validate"][..],
        &["plan", "a.toml"][..],
        &["run-sim"][..],
        &["run-sim", "--scenario", "s.toml", "--fast"][..],
        &["run-sim", "--scenario", "--hold"][..],
        &["run"][..],
        &["run", "--config", "a.toml", "--hold"][..],
        &["run", "--config", "a.toml", "--stats-interval=x"][..],
    ] {
        let output = run(args);
        assert_eq!(status(&output), 2, "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(text(&output.stderr).contains("usage:"), "{args:?}");
    }
}

#[test]
fn validate_reports_summary_or_typed_diagnostics_with_exit_status() {
    let ok = run(&["validate", &fixture("router-v1.toml")]);
    assert_eq!(status(&ok), 0);
    assert_eq!(
        text(&ok.stdout),
        "valid: schema-version=1 interfaces=2 routes=3 neighbors=1 local-ipv4=2 \
         firewall-rules=3 services=resolution,icmpv4-errors,nat44-udp,nat44-tcp,firewall \
         storage-bytes=856800 backend=sim\n"
    );
    assert!(ok.stderr.is_empty());

    for (name, diagnostic) in [
        (
            "router-invalid.toml",
            "ruster: invalid config: stage=validate code=GATEWAY_NOT_ON_LINK path=routes[0].via\n",
        ),
        (
            "router-missing-nat.toml",
            "ruster: invalid config: stage=bridge code=MISSING_SERVICE_NAT44_UDP\n",
        ),
        (
            "scenario.toml",
            "ruster: invalid config: stage=parse code=MISSING_SCHEMA_VERSION path=schema-version\n",
        ),
    ] {
        let output = run(&["validate", &fixture(name)]);
        assert_eq!(status(&output), 2, "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        assert_eq!(text(&output.stderr), diagnostic, "{name}");
    }

    let missing = run(&["validate", &fixture("does-not-exist.toml")]);
    assert_eq!(status(&missing), 1);
    assert_eq!(
        text(&missing.stderr),
        "ruster: cannot read config: NOT_FOUND\n"
    );
}

#[test]
fn validate_never_prints_allocator_seeds() {
    let dir = scratch();
    let secret_udp = "8642097531864209";
    let secret_tcp = "1357924680135792";
    let source = fs::read_to_string(fixtures().join("router-v1.toml"))
        .unwrap()
        .replace(
            "allocator-seed = \"1\"",
            &format!("allocator-seed = \"{secret_udp}\""),
        )
        .replace(
            "allocator-seed = \"2\"",
            &format!("allocator-seed = \"{secret_tcp}\""),
        );
    let valid = dir.join("valid.toml");
    fs::write(&valid, &source).unwrap();
    let invalid = dir.join("invalid.toml");
    fs::write(
        &invalid,
        source.replace("via = \"203.0.113.1\"", "via = \"10.9.9.1\""),
    )
    .unwrap();
    let unknown = dir.join("unknown.toml");
    fs::write(
        &unknown,
        source.replace(
            "[nat44.udp]\n",
            &format!("[nat44.udp]\nx{secret_udp} = 1\n"),
        ),
    )
    .unwrap();

    let mut statuses = Vec::new();
    for path in [&valid, &invalid, &unknown] {
        let output = ruster(&["validate".as_ref(), path.as_os_str()]);
        statuses.push(status(&output));
        for stream in [&output.stdout, &output.stderr] {
            let stream = text(stream);
            assert!(!stream.contains(secret_udp), "{stream}");
            assert!(!stream.contains(secret_tcp), "{stream}");
        }
    }
    assert_eq!(statuses, [0, 2, 2]);
    let plan = ruster(&["plan".as_ref(), valid.as_os_str(), valid.as_os_str()]);
    assert_eq!(status(&plan), 0);
    assert!(!text(&plan.stdout).contains(secret_udp));
    assert!(!text(&plan.stdout).contains(secret_tcp));
}

const EXPECT_ALL: &str = "expected-flush:
  resolution_states all
  resolution_actions all
  dynamic_neighbors all
  failure_holds all
  icmpv4_error_states all
  icmpv4_error_actions all
  nat44_udp_mappings all
  nat44_udp_peers all
  nat44_tcp_mappings all
  nat44_tcp_sessions all
  nat44_icmp_mappings all
  nat44_icmp_peers all
  firewall_flows all
";

const FLUSHED: &str = "  arp flushed
  nat44-udp flushed
  nat44-tcp flushed
  firewall flushed
";

/// A restart-required plan: a restart flushes everything.
fn restart_all() -> String {
    format!("{EXPECT_ALL}state: restart\n{FLUSHED}")
}

/// A reloadable plan to a `[reload] state = "flush"` document.
fn flush_all() -> String {
    format!("{EXPECT_ALL}state: flush\n{FLUSHED}")
}

/// A reloadable plan that carries every family (RELOAD-CARRY, the default)
/// with unchanged rules: only learned neighbors the successor invalidates
/// drop, and pending resolution and ICMPv4 error work flushes.
const CARRY_ALL: &str = "expected-flush:
  resolution_states all
  resolution_actions all
  dynamic_neighbors invalidated
  failure_holds all
  icmpv4_error_states all
  icmpv4_error_actions all
  nat44_udp_mappings 0
  nat44_udp_peers 0
  nat44_tcp_mappings 0
  nat44_tcp_sessions 0
  nat44_icmp_mappings all
  nat44_icmp_peers all
  firewall_flows 0
state: carry
  arp carried
  nat44-udp carried
  nat44-tcp carried
  firewall carried
";

#[test]
fn plan_output_is_deterministic_and_reports_restart_reasons() {
    let cases = [
        (
            "router-v2.toml",
            "plan: reloadable\nrestart-required: none\nchanges: 3\n  \
             route + 192.0.2.0/24 dev if2 via 203.0.113.1\n  \
             firewall-rule + id 40 udp if1 -> any 192.168.1.0/24 -> 0.0.0.0/0 \
             sport 1-65535 dport 1-65535 allow-stateful\n  \
             reload-state ~ carry -> flush\n",
            flush_all(),
        ),
        (
            "router-capacity.toml",
            "plan: restart-required\nrestart-required: STORAGE_SHAPE\nchanges: 0\n",
            restart_all(),
        ),
        (
            "router-interface.toml",
            "plan: restart-required\nrestart-required: INTERFACES\nchanges: 1\n  \
             interface ~ if2 mac 02:00:00:00:00:02 mtu 1500 -> if2 mac 02:00:00:00:00:22 mtu 1500\n",
            restart_all(),
        ),
        (
            "router-relabel.toml",
            "plan: reloadable\nrestart-required: none\nchanges: 1\n  \
             interface-label ~ if2 name wan device sim1 -> name uplink device sim1\n",
            CARRY_ALL.to_owned(),
        ),
        (
            "router-v1.toml",
            "plan: reloadable\nrestart-required: none\nchanges: 0\n",
            CARRY_ALL.to_owned(),
        ),
    ];
    for (next, head, state) in cases {
        let first = run(&["plan", &fixture("router-v1.toml"), &fixture(next)]);
        assert_eq!(status(&first), 0, "{next}");
        assert_eq!(text(&first.stdout), format!("{head}{state}"), "{next}");
        assert!(first.stderr.is_empty(), "{next}");
        let second = run(&["plan", &fixture("router-v1.toml"), &fixture(next)]);
        assert_eq!(first.stdout, second.stdout, "{next}");
    }

    let reverse = run(&[
        "plan",
        &fixture("router-v2.toml"),
        &fixture("router-v1.toml"),
    ]);
    assert!(text(&reverse.stdout).contains("  route - 192.0.2.0/24 dev if2 via 203.0.113.1\n"));

    let invalid = run(&[
        "plan",
        &fixture("router-v1.toml"),
        &fixture("router-invalid.toml"),
    ]);
    assert_eq!(status(&invalid), 2);
    assert!(invalid.stdout.is_empty());
    assert_eq!(
        text(&invalid.stderr),
        "ruster: invalid next config: stage=validate code=GATEWAY_NOT_ON_LINK path=routes[0].via\n"
    );
    let missing = run(&[
        "plan",
        &fixture("router-missing-nat.toml"),
        &fixture("router-v1.toml"),
    ]);
    assert_eq!(status(&missing), 2);
    assert_eq!(
        text(&missing.stderr),
        "ruster: invalid current config: stage=bridge code=MISSING_SERVICE_NAT44_UDP\n"
    );
}

#[test]
fn run_sim_matches_the_golden_output_byte_for_byte_twice() {
    let expected = fs::read(fixtures().join("expected.jsonl")).unwrap();
    let mut outputs = Vec::new();
    for _ in 0..2 {
        let output = run(&["run-sim", "--scenario", &fixture("scenario.toml")]);
        assert_eq!(status(&output), 0, "{}", text(&output.stderr));
        assert!(
            output.stdout == expected,
            "stdout differs from expected.jsonl"
        );
        let stderr = text(&output.stderr);
        assert!(
            stderr.starts_with("ruster run-sim: finished at 4030 ms; generation 5,"),
            "{stderr}"
        );
        assert!(!stderr.contains("20261101"), "{stderr}");
        outputs.push((output.stdout, output.stderr));
    }
    assert_eq!(outputs[0], outputs[1]);
}

#[test]
fn run_sim_failures_map_to_exit_statuses() {
    let dir = scratch();
    fs::copy(
        fixtures().join("router-v1.toml"),
        dir.join("router-v1.toml"),
    )
    .unwrap();
    fs::copy(
        fixtures().join("router-invalid.toml"),
        dir.join("router-invalid.toml"),
    )
    .unwrap();
    let header = "schema = \"ruster-scenario/v1\"\nseed = 3\n";
    let write = |name: &str, body: &str| {
        let path = dir.join(name);
        fs::write(&path, format!("{header}{body}")).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let wrong = write(
        "wrong.toml",
        "config = \"router-v1.toml\"\n\n[[step]]\nkind = \"expect\"\ngeneration = 9\n",
    );
    let bad_config = write("bad-config.toml", "config = \"router-invalid.toml\"\n");
    let missing_config = write("missing-config.toml", "config = \"absent.toml\"\n");
    let unknown_field = write("unknown.toml", "config = \"router-v1.toml\"\nextra = 1\n");
    let unknown_interface = write(
        "unknown-if.toml",
        "config = \"router-v1.toml\"\n\n[[step]]\nkind = \"inject\"\ninterface = \"dmz\"\n\
         frame = { kind = \"raw\", hex = \"00\" }\n",
    );
    let absent = dir
        .join("absent-scenario.toml")
        .to_str()
        .unwrap()
        .to_owned();

    for (path, code, message) in [
        (
            &wrong,
            1,
            "expectation failed: step[0]: generation expected 9, observed 1",
        ),
        (&bad_config, 2, "invalid initial config"),
        (&missing_config, 1, "read failed: config file: NOT_FOUND"),
        (&unknown_field, 2, "invalid scenario"),
        (&unknown_interface, 2, "invalid scenario"),
        (&absent, 1, "read failed: scenario file: NOT_FOUND"),
    ] {
        let output = run(&["run-sim", "--scenario", path]);
        let stderr = text(&output.stderr);
        assert_eq!(status(&output), code, "{path}: {stderr}");
        assert!(stderr.contains(message), "{path}: {stderr}");
        assert!(
            !text(&output.stdout).contains("\"event\":\"final\""),
            "{path}"
        );
    }
}

/// A `run-sim --hold` child that is always killed and reaped, even when an
/// assertion panics, so no orphan outlives the test.
struct Held {
    child: Child,
    stdout: Option<thread::JoinHandle<String>>,
    stderr: Option<thread::JoinHandle<Vec<String>>>,
    idle: mpsc::Receiver<()>,
}

impl Drop for Held {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Held {
    /// Spawns `command` and returns once the readiness line is on stderr and
    /// the first idle tick is on stdout (hold mode flushes after every idle
    /// tick), so a signal provably interrupts the idle loop.
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ruster");
        let (idle_tx, idle) = mpsc::channel();
        let stdout_pipe = child.stdout.take().unwrap();
        let stderr_pipe = child.stderr.take().unwrap();
        let mut held = Self {
            child,
            stdout: None,
            stderr: None,
            idle,
        };
        held.stdout = Some(thread::spawn(move || {
            let mut text = String::new();
            for line in BufReader::new(stdout_pipe).lines() {
                let line = line.unwrap();
                if line.starts_with("{\"event\":\"tick\",\"step\":null,") {
                    let _ = idle_tx.send(());
                }
                text.push_str(&line);
                text.push('\n');
            }
            text
        }));
        let (ready_tx, ready) = mpsc::channel();
        held.stderr = Some(thread::spawn(move || {
            let mut lines = Vec::new();
            for line in BufReader::new(stderr_pipe).lines() {
                let line = line.unwrap();
                if line.starts_with("ruster run-sim: holding") {
                    let _ = ready_tx.send(());
                }
                lines.push(line);
            }
            lines
        }));
        ready.recv_timeout(TIMEOUT).expect("readiness line");
        held.next_idle_tick();
        held
    }

    fn next_idle_tick(&self) {
        self.idle.recv_timeout(TIMEOUT).expect("idle tick");
    }

    fn signal(&self, signal: &str) {
        let kill = Command::new("kill")
            .args(["-s", signal, &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(kill.success());
    }

    /// Waits (bounded) for exit and returns status, stdout, stderr lines.
    fn finish(mut self) -> (std::process::ExitStatus, String, Vec<String>) {
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("ruster did not exit after the signal");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = self.stdout.take().unwrap().join().unwrap();
        let stderr = self.stderr.take().unwrap().join().unwrap();
        (status, stdout, stderr)
    }
}

/// `run-sim --hold` with SIGINT reset to its default disposition.
///
/// `ruster` deliberately keeps an inherited-ignored SIGINT ignored (see
/// `inherited_ignored_sigint_stays_ignored_and_sigterm_still_stops`), and
/// SIG_IGN survives fork and exec. A test runner started as an asynchronous
/// list of a non-interactive shell (`cargo test &` in a script or a
/// background job without job control) inherits SIGINT ignored, so without
/// the reset every SIGINT test would wait out [`TIMEOUT`]. coreutils
/// `env --default-signal` (8.31+) restores SIG_DFL and execs in place, so
/// the child's pid is `ruster`'s.
fn hold_command() -> Command {
    let mut command = Command::new("env");
    command.args([
        "--default-signal=INT",
        BIN,
        "run-sim",
        "--hold",
        "--scenario",
        &fixture("scenario.toml"),
    ]);
    command
}

fn assert_stopped(signal: &str, held: Held) -> String {
    let (exit, stdout, stderr) = held.finish();
    assert_eq!(exit.code(), Some(0), "{signal}: {stderr:?}");
    assert!(
        stderr
            .last()
            .is_some_and(|line| line.starts_with("ruster run-sim: stopped by signal")),
        "{signal}: {stderr:?}"
    );
    stdout
}

fn hold_then_signal(signal: &str) {
    let held = Held::spawn(hold_command());
    held.signal(signal);
    let stdout = assert_stopped(signal, held);

    // The scenario part is the golden output without its final event, then
    // idle ticks, then exactly one final event.
    let expected = text(&fs::read(fixtures().join("expected.jsonl")).unwrap());
    let golden_prefix = &expected[..expected.rfind("{\"event\":\"final\"").unwrap()];
    assert!(stdout.starts_with(golden_prefix), "{signal}");
    let lines: Vec<&str> = stdout[golden_prefix.len()..].lines().collect();
    let (last, idle) = lines.split_last().expect("final event");
    assert!(!idle.is_empty(), "{signal}: at least one idle tick");
    assert!(last.starts_with("{\"event\":\"final\""), "{signal}: {last}");
    assert_eq!(stdout.matches("{\"event\":\"final\"").count(), 1);
    assert!(last.contains("\"generation\":5,"), "{last}");
    for quiet in [
        "\"backend.sim.rx_leases_live\":0,",
        "\"backend.sim.generated_leases_live\":0,",
        "\"backend.sim.pending_tx\":0,",
        "\"backend.sim.batch_open\":false",
    ] {
        assert!(last.contains(quiet), "{signal}: {quiet}");
    }
    // Idle ticks advance injected time by a fixed 100 ms step.
    let ticks: Vec<&&str> = idle
        .iter()
        .filter(|line| !line.starts_with("{\"event\":\"tx\",\"step\":null,"))
        .collect();
    for (index, line) in ticks.iter().enumerate() {
        let at = 4030 + 100 * (index + 1);
        assert!(
            line.starts_with(&format!(
                "{{\"event\":\"tick\",\"step\":null,\"at_ms\":{at},\"generation\":5,"
            )),
            "{signal}: {line}"
        );
    }
    let final_at = 4030 + 100 * ticks.len();
    assert!(last.contains(&format!("\"at_ms\":{final_at},")), "{last}");
}

#[test]
fn hold_mode_shuts_down_in_order_on_sigterm() {
    hold_then_signal("TERM");
}

#[test]
fn hold_mode_shuts_down_in_order_on_sigint() {
    hold_then_signal("INT");
}

#[test]
fn inherited_ignored_sigint_stays_ignored_and_sigterm_still_stops() {
    // `trap '' INT` sets SIG_IGN, which `exec` preserves (as for a
    // background job without job control).
    let mut command = Command::new("sh");
    command.args([
        "-c",
        "trap '' INT; exec \"$0\" run-sim --hold --scenario \"$1\"",
        BIN,
        &fixture("scenario.toml"),
    ]);
    let held = Held::spawn(command);
    held.signal("INT");
    // Count only ticks received after the send.
    while held.idle.try_recv().is_ok() {}
    // Still idling: had SIGINT been handled, at most one more idle tick
    // could follow and stdout would close.
    for _ in 0..3 {
        held.next_idle_tick();
    }
    held.signal("TERM");
    let stdout = assert_stopped("TERM", held);
    assert!(stdout
        .lines()
        .last()
        .is_some_and(|line| line.starts_with("{\"event\":\"final\"")));
}

#[test]
fn plan_classifies_icmpv4_switches_like_their_policy_tables() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let echo_off = dir.join("echo-off.toml");
    fs::write(
        &echo_off,
        source.replacen("echo-reply = true", "echo-reply = false", 1),
    )
    .unwrap();
    let ttl_off = dir.join("ttl-off.toml");
    fs::write(
        &ttl_off,
        source.replacen("time-exceeded = true", "time-exceeded = false", 1),
    )
    .unwrap();
    let current = fixtures().join("router-v1.toml");

    let validate = ruster(&["validate".as_ref(), ttl_off.as_os_str()]);
    assert_eq!(status(&validate), 0);

    // The Echo responder switch is a reloadable ipv4-origin change.
    let echo = ruster(&["plan".as_ref(), current.as_os_str(), echo_off.as_os_str()]);
    assert_eq!(status(&echo), 0);
    assert_eq!(
        text(&echo.stdout),
        format!(
            "plan: reloadable\nrestart-required: none\nchanges: 1\n  ipv4-origin ~ changed\n\
             {CARRY_ALL}"
        )
    );
    // An ICMPv4 error generation switch belongs to the restart-required
    // ICMPv4 error policy, like interval-ms and state-ttl-ms.
    let ttl = ruster(&["plan".as_ref(), current.as_os_str(), ttl_off.as_os_str()]);
    assert_eq!(status(&ttl), 0);
    assert_eq!(
        text(&ttl.stdout),
        format!(
            "plan: restart-required\nrestart-required: ICMPV4_ERROR_POLICY\nchanges: 0\n{}",
            restart_all()
        )
    );
}

/// NAT44-065: `[icmpv4-errors.translated]` belongs to the restart-required
/// ICMPv4 error policy; the defaults spelled out are no change, and 0 is a
/// value-free validation error at the table's path.
#[test]
fn plan_classifies_the_translated_icmpv4_limit_as_restart_required() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let current = fixtures().join("router-v1.toml");
    let with = |name: &str, table: &str| {
        let path = dir.join(name);
        fs::write(
            &path,
            source.replacen(
                "[icmpv4-errors.capacity]",
                &format!("[icmpv4-errors.translated]\n{table}\n\n[icmpv4-errors.capacity]"),
                1,
            ),
        )
        .unwrap();
        path
    };
    let defaults = with("defaults.toml", "rate-per-second = 100\nburst = 100");
    let slower = with("slower.toml", "rate-per-second = 10");
    let zero = with("zero.toml", "burst = 0");

    let plan = ruster(&["plan".as_ref(), current.as_os_str(), defaults.as_os_str()]);
    assert_eq!(status(&plan), 0);
    assert_eq!(
        text(&plan.stdout),
        format!("plan: reloadable\nrestart-required: none\nchanges: 0\n{CARRY_ALL}")
    );
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), slower.as_os_str()]);
    assert_eq!(status(&plan), 0);
    assert_eq!(
        text(&plan.stdout),
        format!(
            "plan: restart-required\nrestart-required: ICMPV4_ERROR_POLICY\nchanges: 0\n{}",
            restart_all()
        )
    );
    let invalid = ruster(&["validate".as_ref(), zero.as_os_str()]);
    assert_ne!(status(&invalid), 0);
    let stderr = text(&invalid.stderr);
    assert!(stderr.contains("ICMPV4_ERROR_POLICY"), "{stderr}");
    assert!(stderr.contains("icmpv4-errors.translated"), "{stderr}");
    assert!(!stderr.contains(" 0"), "value-free: {stderr}");
}

/// The ARP-031 opt-in (`[arp] require-on-link-sender`) is a reloadable
/// `arp` change; the RFC 826 default spelled out is no change.
#[test]
fn plan_prints_the_arp_policy_as_reloadable() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let current = fixtures().join("router-v1.toml");
    let with = |name: &str, value: &str| {
        let path = dir.join(name);
        fs::write(
            &path,
            source.replacen(
                "[resolution.policy]",
                &format!("[arp]\nrequire-on-link-sender = {value}\n\n[resolution.policy]"),
                1,
            ),
        )
        .unwrap();
        path
    };
    let hardened = with("arp-on.toml", "true");
    let explicit_default = with("arp-off.toml", "false");
    assert_eq!(
        status(&ruster(&["validate".as_ref(), hardened.as_os_str()])),
        0
    );

    let plan = ruster(&["plan".as_ref(), current.as_os_str(), hardened.as_os_str()]);
    assert_eq!(status(&plan), 0);
    assert_eq!(
        text(&plan.stdout),
        format!(
            "plan: reloadable\nrestart-required: none\nchanges: 1\n  arp ~ changed\n{CARRY_ALL}"
        )
    );
    let plan = ruster(&[
        "plan".as_ref(),
        current.as_os_str(),
        explicit_default.as_os_str(),
    ]);
    assert_eq!(status(&plan), 0);
    assert_eq!(
        text(&plan.stdout),
        format!("plan: reloadable\nrestart-required: none\nchanges: 0\n{CARRY_ALL}")
    );
}

/// URPF: `[[interfaces]] source-validation` is a reloadable per-interface
/// delta; `off` spelled out is no change, and allow-default without
/// `loose` is refused by `validate`.
#[test]
fn plan_prints_source_validation_as_a_reloadable_delta() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let current = fixtures().join("router-v1.toml");
    let with = |name: &str, keys: &str| {
        let path = dir.join(name);
        fs::write(
            &path,
            source.replacen(
                "mac = \"02:00:00:00:00:02\"\n",
                &format!("mac = \"02:00:00:00:00:02\"\n{keys}"),
                1,
            ),
        )
        .unwrap();
        path
    };
    let strict = with("urpf-strict.toml", "source-validation = \"strict\"\n");
    let loose = with(
        "urpf-loose.toml",
        "source-validation = \"loose\"\nsource-validation-allow-default = true\n",
    );
    let off = with("urpf-off.toml", "source-validation = \"off\"\n");
    let invalid = with(
        "urpf-invalid.toml",
        "source-validation = \"strict\"\nsource-validation-allow-default = true\n",
    );
    assert_eq!(
        status(&ruster(&["validate".as_ref(), strict.as_os_str()])),
        0
    );

    let plan = ruster(&["plan".as_ref(), current.as_os_str(), strict.as_os_str()]);
    assert_eq!(status(&plan), 0);
    assert_eq!(
        text(&plan.stdout),
        format!(
            "plan: reloadable\nrestart-required: none\nchanges: 1\n  \
             source-validation + if2 strict\n{CARRY_ALL}"
        )
    );
    let plan = ruster(&["plan".as_ref(), strict.as_os_str(), loose.as_os_str()]);
    assert_eq!(status(&plan), 0);
    assert!(
        text(&plan.stdout)
            .contains("  source-validation ~ if2 strict -> if2 loose-allow-default\n"),
        "{}",
        text(&plan.stdout)
    );
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), off.as_os_str()]);
    assert_eq!(status(&plan), 0);
    assert_eq!(
        text(&plan.stdout),
        format!("plan: reloadable\nrestart-required: none\nchanges: 0\n{CARRY_ALL}")
    );

    let rejected = ruster(&["validate".as_ref(), invalid.as_os_str()]);
    assert_ne!(status(&rejected), 0);
    let stderr = text(&rejected.stderr);
    assert!(
        stderr.contains("SOURCE_VALIDATION_ALLOW_DEFAULT_NOT_LOOSE"),
        "{stderr}"
    );
}

/// URPF sec L2: `validate` warns (value-free, exit 0) about `loose`
/// without allow-default on the egress of a `/0` route and about `strict`
/// on an interface no route leaves through; neither is refused, and a
/// sensible setting (strict on the WAN, loose with allow-default) is quiet.
#[test]
fn validate_warns_about_suspicious_source_validation() {
    let dir = scratch();
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/urpf/router.toml"),
    )
    .unwrap();
    let wan = "mac = \"02:00:00:00:00:02\"\nsource-validation = \"off\"\n";
    // A third interface with no address and no route.
    let spare = "[[interfaces]]\nid = 3\nname = \"spare\"\ndevice = \"sim2\"\n\
                 mac = \"02:00:00:00:00:03\"\nsource-validation = \"strict\"\n\n[[addresses]]";
    let write = |name: &str, text: String| {
        let path = dir.join(name);
        fs::write(&path, text).unwrap();
        path
    };
    let cases = [
        (
            "urpf-loose.toml",
            source.replacen(
                wan,
                "mac = \"02:00:00:00:00:02\"\nsource-validation = \"loose\"\n",
                1,
            ),
            vec!["ruster: warning: SOURCE_VALIDATION_DEFAULT_IGNORED interface=if2"],
        ),
        (
            "urpf-no-route.toml",
            source.replacen("[[addresses]]", spare, 1),
            vec!["ruster: warning: SOURCE_VALIDATION_NO_ROUTE interface=if3"],
        ),
        (
            "urpf-quiet.toml",
            source.replacen(
                wan,
                "mac = \"02:00:00:00:00:02\"\nsource-validation = \"strict\"\n",
                1,
            ),
            vec![],
        ),
        (
            "urpf-allowed.toml",
            source.replacen(
                wan,
                "mac = \"02:00:00:00:00:02\"\nsource-validation = \"loose\"\n\
                 source-validation-allow-default = true\n",
                1,
            ),
            vec![],
        ),
    ];
    for (name, document, expected) in cases {
        let path = write(name, document);
        let validated = ruster(&["validate".as_ref(), path.as_os_str()]);
        assert_eq!(status(&validated), 0, "{name}: {}", text(&validated.stderr));
        let warnings: Vec<String> = text(&validated.stderr)
            .lines()
            .filter(|line| line.contains("SOURCE_VALIDATION_"))
            .map(str::to_owned)
            .collect();
        assert_eq!(warnings, expected, "{name}");
    }
}

#[test]
fn plan_prints_nat_filtering_as_a_reloadable_typed_delta() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    // router-v1.toml spells the default out for UDP first, then TCP.
    assert_eq!(
        source.matches("filtering = \"address-dependent\"").count(),
        2
    );
    let edited = dir.join("filtering.toml");
    fs::write(
        &edited,
        source
            .replacen(
                "filtering = \"address-dependent\"",
                "filtering = \"endpoint-independent\"",
                1,
            )
            .replacen(
                "allocator-seed = \"2\"\nicmpv4-errors = \"disabled\"\n# RFC 5382 REQ-3 \"more \
                 stringent\" RECOMMENDED default.\nfiltering = \"address-dependent\"",
                "allocator-seed = \"2\"\nicmpv4-errors = \"disabled\"\n\
                 filtering = \"address-and-port-dependent\"",
                1,
            ),
    )
    .unwrap();
    let current = fixtures().join("router-v1.toml");
    let validate = ruster(&["validate".as_ref(), edited.as_os_str()]);
    assert_eq!(status(&validate), 0);
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), edited.as_os_str()]);
    assert_eq!(status(&plan), 0);
    assert_eq!(
        text(&plan.stdout),
        format!(
            "plan: reloadable\nrestart-required: none\nchanges: 2\n  \
             nat44-udp filtering ~ address-dependent -> endpoint-independent\n  \
             nat44-tcp filtering ~ address-dependent -> address-and-port-dependent\n\
             {}",
            CARRY_ALL
                .replace("nat44_udp_mappings 0", "nat44_udp_mappings all")
                .replace("nat44_udp_peers 0", "nat44_udp_peers all")
                .replace("nat44_tcp_mappings 0", "nat44_tcp_mappings all")
                .replace("nat44_tcp_sessions 0", "nat44_tcp_sessions all")
                .replace("nat44-udp carried", "nat44-udp flushed:filtering")
                .replace("nat44-tcp carried", "nat44-tcp flushed:filtering")
        )
    );
    // router-v2.toml omits the key: the absent default plans as no change.
    let v2 = fixtures().join("router-v2.toml");
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), v2.as_os_str()]);
    assert!(!text(&plan.stdout).contains("filtering"));
}

/// Every `Nat44Filtering` variant renders its config spelling on both sides
/// of a plan line, and that spelling is accepted by `validate`, so a new
/// variant cannot appear in plan text without a real, parseable name.
#[test]
fn plan_text_covers_every_nat_filtering_variant() {
    use ruster_core::Nat44Filtering;

    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let with_udp = |filtering: Nat44Filtering| {
        let path = dir.join(format!("udp-{}.toml", filtering.config_name()));
        fs::write(
            &path,
            source.replacen(
                "filtering = \"address-dependent\"",
                &format!("filtering = \"{}\"", filtering.config_name()),
                1,
            ),
        )
        .unwrap();
        path
    };
    for old in Nat44Filtering::ALL {
        for new in Nat44Filtering::ALL {
            let (current, next) = (with_udp(old), with_udp(new));
            assert_eq!(status(&ruster(&["validate".as_ref(), next.as_os_str()])), 0);
            let plan = ruster(&["plan".as_ref(), current.as_os_str(), next.as_os_str()]);
            assert_eq!(status(&plan), 0);
            let stdout = text(&plan.stdout);
            assert!(!stdout.contains("unknown"), "{stdout}");
            let line = format!(
                "  nat44-udp filtering ~ {} -> {}\n",
                old.config_name(),
                new.config_name()
            );
            assert_eq!(stdout.contains(&line), old != new, "{stdout}");
            assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
        }
    }
}

/// The hairpinning switch is a reloadable typed delta rendered as `on`/`off`
/// per protocol, and only the changed protocol gets a line.
#[test]
fn plan_text_renders_the_hairpinning_switch_as_a_reloadable_typed_delta() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let off = dir.join("tcp-hairpin-off.toml");
    fs::write(
        &off,
        source.replacen(
            "allocator-seed = \"2\"\n",
            "allocator-seed = \"2\"\nhairpinning = false\n",
            1,
        ),
    )
    .unwrap();
    let current = fixtures().join("router-v1.toml");
    assert_eq!(status(&ruster(&["validate".as_ref(), off.as_os_str()])), 0);
    for (from, to, line) in [
        (&current, &off, "  nat44-tcp hairpinning ~ on -> off\n"),
        (&off, &current, "  nat44-tcp hairpinning ~ off -> on\n"),
    ] {
        let plan = ruster(&["plan".as_ref(), from.as_os_str(), to.as_os_str()]);
        assert_eq!(status(&plan), 0);
        let stdout = text(&plan.stdout);
        assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
        assert!(stdout.contains(line), "{stdout}");
        assert!(!stdout.contains("nat44-udp hairpinning"), "{stdout}");
        assert!(!stdout.contains("policy ~ changed"), "{stdout}");
    }
}

/// N2: the port preservation switch is a reloadable typed delta rendered as
/// `on`/`off` per protocol, and only the changed protocol gets a line.
#[test]
fn plan_text_renders_the_port_preservation_switch_as_a_reloadable_typed_delta() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let off = dir.join("udp-preservation-off.toml");
    fs::write(
        &off,
        source.replacen(
            "allocator-seed = \"1\"\n",
            "allocator-seed = \"1\"\nport-preservation = false\n",
            1,
        ),
    )
    .unwrap();
    let current = fixtures().join("router-v1.toml");
    assert_eq!(status(&ruster(&["validate".as_ref(), off.as_os_str()])), 0);
    for (from, to, line) in [
        (
            &current,
            &off,
            "  nat44-udp port-preservation ~ on -> off\n",
        ),
        (
            &off,
            &current,
            "  nat44-udp port-preservation ~ off -> on\n",
        ),
    ] {
        let plan = ruster(&["plan".as_ref(), from.as_os_str(), to.as_os_str()]);
        assert_eq!(status(&plan), 0);
        let stdout = text(&plan.stdout);
        assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
        assert!(stdout.contains(line), "{stdout}");
        assert!(!stdout.contains("nat44-tcp port-preservation"), "{stdout}");
        assert!(!stdout.contains("policy ~ changed"), "{stdout}");
    }
}

/// N3: the per-host mapping limit is a typed delta rendered with `0` as
/// `unlimited`. Switching it on adds per-host storage, so that plan is
/// restart-required (storage shape); changing one limit to another is
/// reloadable.
#[test]
fn plan_text_renders_the_per_host_mapping_limit_and_its_storage_switch() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let with = |name: &str, value: u16| {
        let path = dir.join(name);
        fs::write(
            &path,
            source.replacen(
                "allocator-seed = \"1\"\n",
                &format!("allocator-seed = \"1\"\nmappings-per-host = {value}\n"),
                1,
            ),
        )
        .unwrap();
        path
    };
    let current = fixtures().join("router-v1.toml");
    let limited = with("udp-limit-64.toml", 64);
    let raised = with("udp-limit-128.toml", 128);
    assert_eq!(
        status(&ruster(&["validate".as_ref(), limited.as_os_str()])),
        0
    );
    let on = ruster(&["plan".as_ref(), current.as_os_str(), limited.as_os_str()]);
    assert_eq!(status(&on), 0);
    let stdout = text(&on.stdout);
    assert!(stdout.starts_with("plan: restart-required\n"), "{stdout}");
    assert!(
        stdout.contains("restart-required: STORAGE_SHAPE\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("  nat44-udp mappings-per-host ~ unlimited -> 64\n"),
        "{stdout}"
    );
    let change = ruster(&["plan".as_ref(), limited.as_os_str(), raised.as_os_str()]);
    assert_eq!(status(&change), 0);
    let stdout = text(&change.stdout);
    assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
    assert!(
        stdout.contains("  nat44-udp mappings-per-host ~ 64 -> 128\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("nat44-tcp mappings-per-host"), "{stdout}");
    assert!(!stdout.contains("policy ~ changed"), "{stdout}");
}

/// N6: the UDP peer and TCP session limits render as typed deltas; turning
/// the TCP session limit on adds per-session storage (restart-required),
/// changing it between two limits is reloadable.
#[test]
fn plan_text_renders_the_per_host_peer_and_session_limits() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let with = |name: &str, peers: u16, sessions: u16| {
        let path = dir.join(name);
        fs::write(
            &path,
            source
                .replacen(
                    "allocator-seed = \"1\"\n",
                    &format!("allocator-seed = \"1\"\npeers-per-host = {peers}\n"),
                    1,
                )
                .replacen(
                    "allocator-seed = \"2\"\n",
                    &format!("allocator-seed = \"2\"\nsessions-per-host = {sessions}\n"),
                    1,
                ),
        )
        .unwrap();
        path
    };
    let current = fixtures().join("router-v1.toml");
    let limited = with("limits-16-32.toml", 16, 32);
    let changed = with("limits-8-64.toml", 8, 64);
    assert_eq!(
        status(&ruster(&["validate".as_ref(), limited.as_os_str()])),
        0
    );
    let on = ruster(&["plan".as_ref(), current.as_os_str(), limited.as_os_str()]);
    assert_eq!(status(&on), 0);
    let stdout = text(&on.stdout);
    assert!(stdout.starts_with("plan: restart-required\n"), "{stdout}");
    assert!(
        stdout.contains("restart-required: STORAGE_SHAPE\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("  nat44-udp peers-per-host ~ unlimited -> 16\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("  nat44-tcp sessions-per-host ~ unlimited -> 32\n"),
        "{stdout}"
    );
    let change = ruster(&["plan".as_ref(), limited.as_os_str(), changed.as_os_str()]);
    assert_eq!(status(&change), 0);
    let stdout = text(&change.stdout);
    assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
    assert!(
        stdout.contains("  nat44-udp peers-per-host ~ 16 -> 8\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("  nat44-tcp sessions-per-host ~ 32 -> 64\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("policy ~ changed"), "{stdout}");
}

/// The TCP per-remote inbound session limit is a reloadable typed delta;
/// `0` renders as `unlimited`, and out-of-range values are rejected with a
/// value-free code and path.
#[test]
fn plan_text_renders_the_tcp_inbound_limit_as_a_reloadable_typed_delta() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let with = |name: &str, value: &str| {
        let path = dir.join(name);
        fs::write(
            &path,
            source.replacen(
                "allocator-seed = \"2\"\n",
                &format!("allocator-seed = \"2\"\ninbound-sessions-per-remote = {value}\n"),
                1,
            ),
        )
        .unwrap();
        path
    };
    let eight = with("tcp-eight.toml", "8");
    let four = with("tcp-four.toml", "4");
    let current = fixtures().join("router-v1.toml");
    for (from, to, line) in [
        (
            &current,
            &eight,
            "  nat44-tcp inbound-sessions-per-remote ~ unlimited -> 8\n",
        ),
        (
            &eight,
            &four,
            "  nat44-tcp inbound-sessions-per-remote ~ 8 -> 4\n",
        ),
        (
            &four,
            &current,
            "  nat44-tcp inbound-sessions-per-remote ~ 4 -> unlimited\n",
        ),
    ] {
        let plan = ruster(&["plan".as_ref(), from.as_os_str(), to.as_os_str()]);
        assert_eq!(status(&plan), 0);
        let stdout = text(&plan.stdout);
        assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
        assert!(stdout.contains(line), "{stdout}");
        assert!(!stdout.contains("policy ~ changed"), "{stdout}");
    }
    let invalid = with("tcp-too-large.toml", "17");
    let output = ruster(&["validate".as_ref(), invalid.as_os_str()]);
    assert_eq!(status(&output), 2);
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("code=NAT44_TCP_POLICY path=nat44.tcp.inbound-sessions-per-remote"),
        "{stderr}"
    );
    assert!(!stderr.contains("17"), "{stderr}");
}

/// N1: `inbound-rst` is a reloadable typed delta; the transitory timers
/// are opaque policy; an unknown `inbound-rst` value is a value-free type
/// error.
#[test]
fn plan_text_renders_the_tcp_inbound_rst_policy_and_timers() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let with = |name: &str, line: &str| {
        let path = dir.join(name);
        fs::write(
            &path,
            source.replacen(
                "allocator-seed = \"2\"\n",
                &format!("allocator-seed = \"2\"\n{line}\n"),
                1,
            ),
        )
        .unwrap();
        path
    };
    let current = fixtures().join("router-v1.toml");
    let strict = with("tcp-corroborate.toml", "inbound-rst = \"corroborate\"");
    for (from, to, line) in [
        (
            &current,
            &strict,
            "  nat44-tcp inbound-rst ~ closing -> corroborate\n",
        ),
        (
            &strict,
            &current,
            "  nat44-tcp inbound-rst ~ corroborate -> closing\n",
        ),
    ] {
        let plan = ruster(&["plan".as_ref(), from.as_os_str(), to.as_os_str()]);
        assert_eq!(status(&plan), 0);
        let stdout = text(&plan.stdout);
        assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
        assert!(stdout.contains(line), "{stdout}");
        assert!(!stdout.contains("policy ~ changed"), "{stdout}");
    }
    let timer = with("tcp-closing.toml", "closing-idle-ttl-ms = 300000");
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), timer.as_os_str()]);
    assert_eq!(status(&plan), 0);
    let stdout = text(&plan.stdout);
    assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
    assert!(
        stdout.contains("  nat44-tcp policy ~ changed\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("300000"), "{stdout}");
    for (name, line, path) in [
        (
            "tcp-bad-rst.toml",
            "inbound-rst = \"drop\"",
            "nat44.tcp.inbound-rst",
        ),
        (
            "tcp-short.toml",
            "opening-idle-ttl-ms = 239999",
            "nat44.tcp.opening-idle-ttl-ms",
        ),
    ] {
        let invalid = with(name, line);
        let output = ruster(&["validate".as_ref(), invalid.as_os_str()]);
        assert_eq!(status(&output), 2);
        let stderr = text(&output.stderr);
        assert!(stderr.contains(&format!("path={path}")), "{stderr}");
        assert!(
            !stderr.contains("drop") && !stderr.contains("239999"),
            "{stderr}"
        );
    }
}

/// B3: the RFC 5382 REQ-4 switch is a reloadable typed delta, and the hold
/// capacity is restart-required storage shape (value-free, like every
/// capacity).
#[test]
fn plan_text_renders_the_unsolicited_syn_switch_and_hold_capacity() {
    let on = fixtures().join("../b3/router.toml");
    let off = fixtures().join("../b3/router-off.toml");
    for (from, to, line) in [
        (&on, &off, "  nat44-tcp unsolicited-syn-icmp ~ on -> off\n"),
        (&off, &on, "  nat44-tcp unsolicited-syn-icmp ~ off -> on\n"),
    ] {
        let plan = ruster(&["plan".as_ref(), from.as_os_str(), to.as_os_str()]);
        assert_eq!(status(&plan), 0);
        let stdout = text(&plan.stdout);
        assert!(stdout.starts_with("plan: reloadable\n"), "{stdout}");
        assert!(stdout.contains(line), "{stdout}");
        assert!(!stdout.contains("policy ~ changed"), "{stdout}");
    }
    let dir = scratch();
    let more = dir.join("b3-more-holds.toml");
    fs::write(
        &more,
        fs::read_to_string(&on).unwrap().replacen(
            "unsolicited-syn-holds = 4\n",
            "unsolicited-syn-holds = 5\n",
            1,
        ),
    )
    .unwrap();
    let plan = ruster(&["plan".as_ref(), on.as_os_str(), more.as_os_str()]);
    assert_eq!(status(&plan), 0);
    let stdout = text(&plan.stdout);
    assert!(stdout.starts_with("plan: restart-required\n"), "{stdout}");
    assert!(stdout.contains("STORAGE_SHAPE"), "{stdout}");
}

/// An AF_XDP `[backend]` binding both M1 interfaces (lan listed second).
const AF_XDP_BACKEND: &str = r#"
[backend]
kind = "af-xdp"
existing-xdp-program = "refuse"

[[backend.ports]]
interface = "wan"
queue = 1
mode = "zero-copy"
xdp-attach = "native"
rings = { fill = 2048, rx = 2048, tx = 2048, completion = 2048 }
frame-size = 4096
frame-count = 4608
generated-frames = 512

[[backend.ports]]
interface = "lan"
queue = 0
mode = "copy"
xdp-attach = "generic"
rings = { fill = 256, rx = 256, tx = 256, completion = 512 }
frame-size = 2048
frame-count = 1024
generated-frames = 64
headroom = 32
"#;

/// `validate` and `plan` accept a valid AF_XDP backend; any backend change
/// is restart-required with typed per-port lines; `run-sim` refuses it.
#[test]
fn af_xdp_backend_validates_plans_as_restart_required_and_is_refused_by_run_sim() {
    let dir = scratch();
    let v1 = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let xdp = dir.join("router-af-xdp.toml");
    fs::write(&xdp, format!("{v1}{AF_XDP_BACKEND}")).unwrap();

    let ok = ruster(&["validate".as_ref(), xdp.as_os_str()]);
    assert_eq!(status(&ok), 0, "{}", text(&ok.stderr));
    assert_eq!(
        text(&ok.stdout),
        "valid: schema-version=1 interfaces=2 routes=3 neighbors=1 local-ipv4=2 \
         firewall-rules=3 services=resolution,icmpv4-errors,nat44-udp,nat44-tcp,firewall \
         storage-bytes=856800 backend=af-xdp ports=2 umem-bytes=20971520\n"
    );

    let current = fixtures().join("router-v1.toml");
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), xdp.as_os_str()]);
    assert_eq!(status(&plan), 0);
    let stdout = text(&plan.stdout);
    assert!(
        stdout.starts_with(
            "plan: restart-required\nrestart-required: BACKEND\nchanges: 3\n\
             \x20 backend ~ sim -> af-xdp\n\
             \x20 backend-port + if1 dev sim0 queue 0 copy generic rings 256/256/256/512 \
             frames 1024x2048 generated 64 headroom 32\n\
             \x20 backend-port + if2 dev sim1 queue 1 zero-copy native rings 2048/2048/2048/2048 \
             frames 4608x4096 generated 512 headroom 0\n\
             expected-flush:\n"
        ),
        "{stdout}"
    );

    // One port setting: a typed `~` line for that port only.
    let moved = dir.join("router-af-xdp-moved.toml");
    fs::write(
        &moved,
        format!(
            "{v1}{}",
            AF_XDP_BACKEND.replacen("queue = 1", "queue = 2", 1)
        ),
    )
    .unwrap();
    let plan = ruster(&["plan".as_ref(), xdp.as_os_str(), moved.as_os_str()]);
    assert_eq!(status(&plan), 0);
    let stdout = text(&plan.stdout);
    assert!(
        stdout.starts_with(
            "plan: restart-required\nrestart-required: BACKEND\nchanges: 1\n\
             \x20 backend-port ~ if2 dev sim1 queue 1 zero-copy native rings 2048/2048/2048/2048 \
             frames 4608x4096 generated 512 headroom 0 -> if2 dev sim1 queue 2 zero-copy native \
             rings 2048/2048/2048/2048 frames 4608x4096 generated 512 headroom 0\n"
        ),
        "{stdout}"
    );
    let same = ruster(&["plan".as_ref(), xdp.as_os_str(), xdp.as_os_str()]);
    assert!(
        text(&same.stdout).starts_with("plan: reloadable\nrestart-required: none\nchanges: 0\n")
    );

    // A rule violation is a value-free path.
    let bad = dir.join("router-af-xdp-bad.toml");
    fs::write(
        &bad,
        format!(
            "{v1}{}",
            AF_XDP_BACKEND.replacen("xdp-attach = \"native\"", "xdp-attach = \"generic\"", 1)
        ),
    )
    .unwrap();
    let output = ruster(&["validate".as_ref(), bad.as_os_str()]);
    assert_eq!(status(&output), 2);
    assert_eq!(
        text(&output.stderr),
        "ruster: invalid config: stage=validate code=BACKEND_MODE_REQUIRES_NATIVE_ATTACH \
         path=backend.ports[0].mode\n"
    );

    fs::write(
        dir.join("scenario.toml"),
        "schema = \"ruster-scenario/v1\"\nseed = 1\nconfig = \"router-af-xdp.toml\"\n",
    )
    .unwrap();
    let scenario = dir.join("scenario.toml");
    let output = ruster(&[
        "run-sim".as_ref(),
        "--scenario".as_ref(),
        scenario.as_os_str(),
    ]);
    assert_eq!(status(&output), 2);
    assert!(output.stdout.is_empty());
    assert_eq!(
        text(&output.stderr),
        "ruster run-sim: invalid initial config: initial config rejected at backend: \
         UNSUPPORTED_BACKEND\n"
    );
}

const AF_PACKET_BACKEND: &str = r#"
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
rx = { block-size = 131072, block-count = 2, retire-timeout-ms = 10 }
tx = { block-size = 65536, block-count = 2 }
"#;

/// AFPKT-015: `validate` and `plan` accept the AF_PACKET backend with the
/// production limits; a backend change is restart-required with typed
/// per-port lines; `run-sim` refuses it.
#[test]
fn af_packet_backend_validates_plans_as_restart_required_and_is_refused_by_run_sim() {
    let dir = scratch();
    let v1 = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let packet = dir.join("router-af-packet.toml");
    fs::write(&packet, format!("{v1}{AF_PACKET_BACKEND}")).unwrap();

    let ok = ruster(&["validate".as_ref(), packet.as_os_str()]);
    assert_eq!(status(&ok), 0, "{}", text(&ok.stderr));
    assert_eq!(
        text(&ok.stdout),
        "valid: schema-version=1 interfaces=2 routes=3 neighbors=1 local-ipv4=2 \
         firewall-rules=3 services=resolution,icmpv4-errors,nat44-udp,nat44-tcp,firewall \
         storage-bytes=856800 backend=af-packet ports=2 max-frame-len=1514 ring-bytes=786432\n"
    );

    let current = fixtures().join("router-v1.toml");
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), packet.as_os_str()]);
    assert_eq!(status(&plan), 0);
    let stdout = text(&plan.stdout);
    assert!(
        stdout.starts_with(
            "plan: restart-required\nrestart-required: BACKEND\nchanges: 4\n\
             \x20 backend ~ sim -> af-packet\n\
             \x20 backend af-packet max-frame-len ~ none -> 1514\n\
             \x20 backend-af-packet-port + if1 dev sim0 rx 2x131072 frame 2048 retire 10 ms \
             tx 2x65536 frame 2048\n\
             \x20 backend-af-packet-port + if2 dev sim1 rx 4x65536 frame 2048 retire 4 ms \
             tx 2x65536 frame 2048\n\
             expected-flush:\n"
        ),
        "{stdout}"
    );
    // One ring setting: a typed `~` line for that port only.
    let longer = dir.join("router-af-packet-longer.toml");
    fs::write(
        &longer,
        format!(
            "{v1}{}",
            AF_PACKET_BACKEND.replacen("retire-timeout-ms = 4", "retire-timeout-ms = 8", 1)
        ),
    )
    .unwrap();
    let plan = ruster(&["plan".as_ref(), packet.as_os_str(), longer.as_os_str()]);
    let stdout = text(&plan.stdout);
    assert!(
        stdout.starts_with(
            "plan: restart-required\nrestart-required: BACKEND\nchanges: 1\n\
             \x20 backend-af-packet-port ~ if2 dev sim1 rx 4x65536 frame 2048 retire 4 ms \
             tx 2x65536 frame 2048 -> if2 dev sim1 rx 4x65536 frame 2048 retire 8 ms \
             tx 2x65536 frame 2048\n"
        ),
        "{stdout}"
    );
    // AF_XDP to AF_PACKET: every port of each is removed or added.
    let xdp = dir.join("router-af-xdp.toml");
    fs::write(&xdp, format!("{v1}{AF_XDP_BACKEND}")).unwrap();
    let plan = ruster(&["plan".as_ref(), xdp.as_os_str(), packet.as_os_str()]);
    let stdout = text(&plan.stdout);
    assert!(
        stdout.starts_with("plan: restart-required\nrestart-required: BACKEND\nchanges: 6\n")
            && stdout.contains("  backend ~ af-xdp -> af-packet\n")
            && stdout.contains("  backend-port - if1 dev sim0 ")
            && stdout.contains("  backend-af-packet-port + if2 dev sim1 "),
        "{stdout}"
    );
    let same = ruster(&["plan".as_ref(), packet.as_os_str(), packet.as_os_str()]);
    assert!(
        text(&same.stdout).starts_with("plan: reloadable\nrestart-required: none\nchanges: 0\n")
    );

    // A rule violation is a value-free path.
    let bad = dir.join("router-af-packet-bad.toml");
    fs::write(
        &bad,
        format!(
            "{v1}{}",
            AF_PACKET_BACKEND.replacen("retire-timeout-ms = 4", "retire-timeout-ms = 0", 1)
        ),
    )
    .unwrap();
    let output = ruster(&["validate".as_ref(), bad.as_os_str()]);
    assert_eq!(status(&output), 2);
    assert_eq!(
        text(&output.stderr),
        "ruster: invalid config: stage=validate code=BACKEND_RETIRE_TIMEOUT_OUT_OF_RANGE \
         path=backend.af-packet.ports[0].rx.retire-timeout-ms limit=1 actual=0\n"
    );

    fs::write(
        dir.join("scenario.toml"),
        "schema = \"ruster-scenario/v1\"\nseed = 1\nconfig = \"router-af-packet.toml\"\n",
    )
    .unwrap();
    let scenario = dir.join("scenario.toml");
    let output = ruster(&[
        "run-sim".as_ref(),
        "--scenario".as_ref(),
        scenario.as_os_str(),
    ]);
    assert_eq!(status(&output), 2);
    assert_eq!(
        text(&output.stderr),
        "ruster run-sim: invalid initial config: initial config rejected at backend: \
         UNSUPPORTED_BACKEND\n"
    );
}

/// `ruster run` refuses the simulation backend (pointing to `run-sim`) and
/// an unreadable config with the documented statuses, before any signal
/// handler, key source, or socket.
#[test]
fn run_refuses_sim_backend_and_unreadable_config() {
    let sim = run(&["run", "--config", &fixture("router-v1.toml")]);
    assert_eq!(status(&sim), 2);
    assert!(sim.stdout.is_empty());
    let stderr = text(&sim.stderr);
    assert!(
        stderr.contains("stage=backend code=SIM_BACKEND") && stderr.contains("ruster run-sim"),
        "{stderr}"
    );
    let missing = run(&["run", "--config", "/nonexistent/ruster-run.toml"]);
    assert_eq!(status(&missing), 1);
    assert!(text(&missing.stderr).contains("cannot read config: NOT_FOUND"));
    let invalid = run(&["run", "--config", &fixture("router-invalid.toml")]);
    assert_eq!(status(&invalid), 2);
    assert!(text(&invalid.stderr).contains("stage=validate"));
}

/// Whether this test process holds `CAP_NET_ADMIN` (bit 12 of `CapEff`).
fn holds_net_admin() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let value = status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:"))?;
            u64::from_str_radix(value.trim(), 16).ok()
        })
        .is_some_and(|effective| effective & (1 << 12) != 0)
}

/// Without the documented capabilities `run` refuses before any resource
/// (exit 4). With `CAP_NET_ADMIN` (for example `cargo test` as root) the
/// test is skipped: a live startup must never run in the caller's network
/// namespace, even against device names that should not exist.
#[test]
fn run_without_privileges_or_devices_fails_closed() {
    if holds_net_admin() {
        eprintln!("skipped: CAP_NET_ADMIN held; refusing a live startup in this namespace");
        return;
    }
    let dir = scratch();
    let v1 = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let config = dir.join("router-af-xdp.toml");
    let text_config = format!("{v1}{AF_XDP_BACKEND}")
        .replace("device = \"sim0\"", "device = \"rusternodev0\"")
        .replace("device = \"sim1\"", "device = \"rusternodev1\"");
    fs::write(&config, text_config).unwrap();
    let output = ruster(&["run".as_ref(), "--config".as_ref(), config.as_os_str()]);
    let code = status(&output);
    let stderr = text(&output.stderr);
    assert_eq!(code, 4, "{stderr}");
    assert!(
        stderr.contains("startup failed: stage=privileges code=MISSING_CAPABILITIES"),
        "{stderr}"
    );
    assert!(!stderr.contains("running generation"), "{stderr}");
    // The output threads dropped their own privileges at spawn (open to
    // any user) before the refusal went through them.
    assert!(!stderr.contains("privilege-drop"), "{stderr}");
    assert!(output.stdout.is_empty());
    // With an identity switch the refusal comes before the output threads
    // (which switch at spawn) and names CAP_SETUID/CAP_SETGID too.
    let output = ruster(&[
        "run".as_ref(),
        "--user".as_ref(),
        "65534".as_ref(),
        "--group".as_ref(),
        "65534".as_ref(),
        "--config".as_ref(),
        config.as_os_str(),
    ]);
    let stderr = text(&output.stderr);
    assert_eq!(status(&output), 4, "{stderr}");
    assert!(
        stderr.contains("startup failed: stage=privileges code=MISSING_CAPABILITIES missing=")
            && stderr.contains("CAP_SETGID,CAP_SETUID,"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--user/--group also need CAP_SETUID and CAP_SETGID"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

/// `--keep-privileges` and `--user`/`--group` are usage errors together,
/// and `--user` needs `--group` (exit 2 before the config is read).
#[test]
fn run_privilege_options_are_usage_errors_when_combined_wrongly() {
    for args in [
        &[
            "run",
            "--keep-privileges",
            "--user=1",
            "--group=1",
            "--config",
            "a.toml",
        ][..],
        &["run", "--user=1", "--config", "a.toml"][..],
        &["run", "--group=1", "--config", "a.toml"][..],
        &["run", "--user=root", "--group=1", "--config", "a.toml"][..],
        &["run", "--user=0", "--group=0", "--config", "a.toml"][..],
    ] {
        let output = run(args);
        assert_eq!(status(&output), 2, "{args:?}");
        assert!(text(&output.stderr).contains("usage:"), "{args:?}");
    }
}

/// Waits at most `limit` for `child`, killing it on timeout.
fn exits_within(mut child: Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// `ruster run` exits in bounded time even when nobody ever reads its
/// stdout (#301 LN1): `main` does not flush stdout after `run`. Both the
/// sim refusal (before the output thread) and the privilege refusal
/// (through the output thread) are exercised with stdout on a pipe that
/// is never drained. Skipped with `CAP_NET_ADMIN`, like the test above.
#[test]
fn run_exits_in_bounded_time_with_an_undrained_stdout() {
    let sim = Command::new(BIN)
        .args(["run", "--config", &fixture("router-v1.toml")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert_eq!(exits_within(sim, Duration::from_secs(10)), Some(2));
    if holds_net_admin() {
        eprintln!("skipped the live part: CAP_NET_ADMIN held");
        return;
    }
    let dir = scratch();
    let v1 = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let config = dir.join("router-af-xdp.toml");
    fs::write(
        &config,
        format!("{v1}{AF_XDP_BACKEND}")
            .replace("device = \"sim0\"", "device = \"rusternodev0\"")
            .replace("device = \"sim1\"", "device = \"rusternodev1\""),
    )
    .unwrap();
    let live = Command::new(BIN)
        .arg("run")
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    assert_eq!(exits_within(live, Duration::from_secs(10)), Some(4));
}

/// H3: `validate` and `run` apply the production limits to an af-xdp
/// document: every table at its production limit is accepted; one slot
/// above (a quote table, the resolution failure holds, at 4097, which the simulator's limits
/// still accept as a sim document, and a firewall table at 65537) is exit 2
/// with a value-free code and path from both. `run` of the maximal document
/// gets past validation and storage allocation to the privilege preflight
/// (exit 4) when unprivileged; with `CAP_NET_ADMIN` that half is skipped
/// (no live startup in the caller's namespace).
#[test]
fn validate_and_run_apply_the_production_limits_to_af_xdp() {
    let dir = scratch();
    let maximal = fs::read_to_string(fixtures().join("../limits/router-production-max.toml"))
        .expect("fixture");
    let max = dir.join("router-production-max.toml");
    fs::write(&max, &maximal).unwrap();
    let ok = ruster(&["validate".as_ref(), max.as_os_str()]);
    assert_eq!(status(&ok), 0, "{}", text(&ok.stderr));
    assert!(
        text(&ok.stdout).contains(" storage-bytes=67050176 backend=af-xdp "),
        "{}",
        text(&ok.stdout)
    );

    let sim_backend = |document: &str| {
        let at = document.find("\n[backend]\n").expect("backend");
        document[..=at].to_owned()
    };
    for (from, to, path, limit) in [
        (
            "failure-holds = 4096\n",
            "failure-holds = 4097\n",
            "resolution.capacity.failure-holds",
            4096,
        ),
        (
            "[firewall.capacity]\nstates = 65536\n",
            "[firewall.capacity]\nstates = 65537\n",
            "firewall.capacity.states",
            65536,
        ),
    ] {
        assert!(maximal.contains(from), "{from}");
        let document = maximal.replacen(from, to, 1);
        let above = dir.join("router-production-above.toml");
        fs::write(&above, &document).unwrap();
        let expected = format!(
            "ruster: invalid config: stage=validate code=CAPACITY_LIMIT_EXCEEDED \
             path={path} limit={limit} actual={}\n",
            limit + 1
        );
        let refused = ruster(&["validate".as_ref(), above.as_os_str()]);
        assert_eq!(status(&refused), 2);
        assert_eq!(text(&refused.stderr), expected);
        let refused = ruster(&["run".as_ref(), "--config".as_ref(), above.as_os_str()]);
        assert_eq!(status(&refused), 2);
        assert_eq!(text(&refused.stderr), expected);
        assert!(refused.stdout.is_empty());
        let sim = dir.join("router-sim-above.toml");
        fs::write(&sim, sim_backend(&document)).unwrap();
        let as_sim = ruster(&["validate".as_ref(), sim.as_os_str()]);
        if limit == 4096 {
            assert_eq!(status(&as_sim), 0, "{}", text(&as_sim.stderr));
        } else {
            assert_eq!(text(&as_sim.stderr), expected);
        }
    }

    if holds_net_admin() {
        eprintln!("skipped run of the maximal config: CAP_NET_ADMIN held");
        return;
    }
    let output = ruster(&["run".as_ref(), "--config".as_ref(), max.as_os_str()]);
    let stderr = text(&output.stderr);
    assert_eq!(status(&output), 4, "{stderr}");
    assert!(
        stderr.contains("startup failed: stage=privileges code=MISSING_CAPABILITIES"),
        "{stderr}"
    );
}

/// H10: a `NOTIFY_SOCKET`/`WATCHDOG_*` environment that `sd_notify` would
/// not accept is refused first (exit 1 `stage=notify`, before signals,
/// capabilities, or ports); a valid one gets nothing before readiness, so
/// a refused startup (here: no capability) sends no `READY=1`.
#[test]
fn run_validates_the_systemd_notification_environment() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    if holds_net_admin() {
        eprintln!("skipped: CAP_NET_ADMIN held; refusing a live startup in this namespace");
        return;
    }
    let dir = scratch();
    let v1 = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let config = dir.join("router-af-xdp.toml");
    let text_config = format!("{v1}{AF_XDP_BACKEND}")
        .replace("device = \"sim0\"", "device = \"rusternodev0\"")
        .replace("device = \"sim1\"", "device = \"rusternodev1\"");
    fs::write(&config, text_config).unwrap();
    let start = |env: &[(&str, &str)]| {
        let mut command = Command::new(BIN);
        command
            .args(["run".as_ref(), "--config".as_ref(), config.as_os_str()])
            .env_remove("NOTIFY_SOCKET")
            .env_remove("WATCHDOG_USEC")
            .env_remove("WATCHDOG_PID");
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("spawn ruster")
    };
    for (env, code) in [
        (
            &[("NOTIFY_SOCKET", "relative/notify")][..],
            "NOTIFY_SOCKET_INVALID",
        ),
        (&[("NOTIFY_SOCKET", "")][..], "NOTIFY_SOCKET_INVALID"),
        (
            &[("NOTIFY_SOCKET", "vsock:2:9")][..],
            "NOTIFY_SOCKET_INVALID",
        ),
        (
            &[("NOTIFY_SOCKET", "/run/n"), ("WATCHDOG_USEC", "0")][..],
            "WATCHDOG_USEC_INVALID",
        ),
        (
            &[
                ("NOTIFY_SOCKET", "/run/n"),
                ("WATCHDOG_USEC", "5"),
                ("WATCHDOG_PID", "x"),
            ][..],
            "WATCHDOG_PID_INVALID",
        ),
    ] {
        let output = start(env);
        let stderr = text(&output.stderr);
        assert_eq!(status(&output), 1, "{env:?}: {stderr}");
        assert_eq!(
            stderr,
            format!("ruster run: startup failed: stage=notify code={code}\n"),
            "{env:?}"
        );
        assert!(output.stdout.is_empty());
    }
    // A valid abstract socket: the privilege refusal (exit 4) comes as
    // before and nothing is notified.
    let name = format!("ruster-cli-notify-{}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let listener = UnixDatagram::bind_addr(&address).unwrap();
    listener.set_nonblocking(true).unwrap();
    let output = start(&[
        ("NOTIFY_SOCKET", &format!("@{name}")),
        ("WATCHDOG_USEC", "1000000"),
    ]);
    let stderr = text(&output.stderr);
    assert_eq!(status(&output), 4, "{stderr}");
    assert!(stderr.contains("stage=privileges code=MISSING_CAPABILITIES"));
    let mut buffer = [0_u8; 256];
    assert!(
        listener.recv(&mut buffer).is_err(),
        "notified before readiness"
    );
}

/// Core L1: a firewall that flushes (a longer idle timeout) is not reported
/// as re-evaluated even when its rules and routes change too.
#[test]
fn plan_shows_a_flushed_firewall_without_reevaluate() {
    let dir = scratch();
    let source = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let current = fixtures().join("router-v1.toml");
    let next = dir.join("longer.toml");
    fs::write(
        &next,
        source
            .replacen("udp-idle-ttl-ms = 300000", "udp-idle-ttl-ms = 600000", 1)
            .replacen("first = 23\nlast = 23", "first = 25\nlast = 25", 1)
            + "\n[[routes]]\nprefix = \"192.0.2.0/24\"\negress = \"wan\"\nvia = \"203.0.113.1\"\n",
    )
    .unwrap();
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), next.as_os_str()]);
    assert_eq!(status(&plan), 0, "{}", text(&plan.stderr));
    let out = text(&plan.stdout);
    assert!(out.contains("  firewall flushed:timers\n"), "{out}");
    assert!(!out.contains("reevaluate"), "{out}");
    assert!(out.contains("  firewall_flows all\n"), "{out}");
    // Without the longer timeout the same changes re-evaluate.
    fs::write(
        &next,
        source.replacen("first = 23\nlast = 23", "first = 25\nlast = 25", 1)
            + "\n[[routes]]\nprefix = \"192.0.2.0/24\"\negress = \"wan\"\nvia = \"203.0.113.1\"\n",
    )
    .unwrap();
    let plan = ruster(&["plan".as_ref(), current.as_os_str(), next.as_os_str()]);
    let out = text(&plan.stdout);
    assert!(out.contains("  firewall carried reevaluate\n"), "{out}");
    assert!(out.contains("  firewall_flows invalidated\n"), "{out}");
}

/// OPS-LOG: `--log-format json` turns the refusals before startup into
/// one JSON line each (the `ruster-run-log/v1` schema; the in-process tests
/// parse every field), a `[health]` key out of range is a typed invalid
/// config, and a bad format value is a usage error.
#[test]
fn run_json_log_format_reports_refusals_as_json_lines() {
    let one_line = |output: &Output, event: &str, level: &str| {
        assert!(output.stdout.is_empty());
        let stderr = text(&output.stderr);
        assert!(stderr.is_ascii(), "{stderr}");
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(lines.len(), 1, "{stderr}");
        let line = lines[0];
        assert!(
            line.starts_with("{\"schema\":\"ruster-run-log/v1\",\"ts\":\""),
            "{line}"
        );
        assert!(
            line.contains(&format!(
                "\",\"level\":\"{level}\",\"event\":\"{event}\",\"msg\":"
            )),
            "{line}"
        );
        assert!(line.ends_with('}'), "{line}");
        line.to_owned()
    };
    let sim = run(&[
        "run",
        "--log-format",
        "json",
        "--config",
        &fixture("router-v1.toml"),
    ]);
    assert_eq!(status(&sim), 2);
    let line = one_line(&sim, "CONFIG_INVALID", "error");
    assert!(
        line.contains("\"fields\":{\"stage\":\"backend\",\"code\":\"SIM_BACKEND\"}"),
        "{line}"
    );
    let missing = run(&[
        "run",
        "--log-format=json",
        "--config",
        "/nonexistent/ruster-run.toml",
    ]);
    assert_eq!(status(&missing), 1);
    one_line(&missing, "CONFIG_UNREADABLE", "error");

    let dir = scratch();
    let v1 = fs::read_to_string(fixtures().join("router-v1.toml")).unwrap();
    let config = dir.join("health.toml");
    fs::write(&config, format!("{v1}\n[health]\ntx-stall-warn-ms = 5\n")).unwrap();
    let health = run(&[
        "run",
        "--log-format",
        "json",
        "--config",
        config.to_str().expect("utf-8"),
    ]);
    assert_eq!(status(&health), 2);
    let line = one_line(&health, "CONFIG_INVALID", "error");
    assert!(
        line.contains(
            "\"fields\":{\"stage\":\"validate\",\"code\":\"HEALTH_VALUE_OUT_OF_RANGE\",\
             \"path\":\"health.tx-stall-warn-ms\",\"limit\":100,\"actual\":5}"
        ),
        "{line}"
    );
    // The text default is unchanged.
    let text_run = run(&["run", "--config", config.to_str().expect("utf-8")]);
    assert_eq!(
        text(&text_run.stderr),
        "ruster: invalid config: stage=validate code=HEALTH_VALUE_OUT_OF_RANGE \
         path=health.tx-stall-warn-ms limit=100 actual=5\n"
    );
    // `validate` checks the same keys.
    let validate = ruster(&["validate".as_ref(), config.as_os_str()]);
    assert_eq!(status(&validate), 2);
    assert!(text(&validate.stderr).contains("code=HEALTH_VALUE_OUT_OF_RANGE"));

    let bad = run(&["run", "--log-format", "xml", "--config", "a.toml"]);
    assert_eq!(status(&bad), 2);
    assert!(text(&bad.stderr).contains("option --log-format needs text or json"));
}

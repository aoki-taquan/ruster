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
         storage-bytes=16192\n"
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

const FLUSH_ALL: &str = "expected-flush:
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
  firewall_flows all
";

#[test]
fn plan_output_is_deterministic_and_reports_restart_reasons() {
    let cases = [
        (
            "router-v2.toml",
            "plan: reloadable\nrestart-required: none\nchanges: 1\n  \
             route + 192.0.2.0/24 dev if2 via 203.0.113.1\n",
        ),
        (
            "router-capacity.toml",
            "plan: restart-required\nrestart-required: STORAGE_SHAPE\nchanges: 0\n",
        ),
        (
            "router-interface.toml",
            "plan: restart-required\nrestart-required: INTERFACES\nchanges: 1\n  \
             interface ~ if2 mac 02:00:00:00:00:02 -> if2 mac 02:00:00:00:00:22\n",
        ),
        (
            "router-relabel.toml",
            "plan: reloadable\nrestart-required: none\nchanges: 1\n  \
             interface-label ~ if2 name wan device sim1 -> name uplink device sim1\n",
        ),
        (
            "router-v1.toml",
            "plan: reloadable\nrestart-required: none\nchanges: 0\n",
        ),
    ];
    for (next, head) in cases {
        let first = run(&["plan", &fixture("router-v1.toml"), &fixture(next)]);
        assert_eq!(status(&first), 0, "{next}");
        assert_eq!(text(&first.stdout), format!("{head}{FLUSH_ALL}"), "{next}");
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

fn hold_command() -> Command {
    let mut command = Command::new(BIN);
    command.args(["run-sim", "--hold", "--scenario", &fixture("scenario.toml")]);
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

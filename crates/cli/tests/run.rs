#![cfg(target_os = "linux")]

use std::{
    env,
    ffi::CString,
    fs,
    os::raw::c_int,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use ruster_config::MAX_CONFIG_BYTES;

const SIGTERM: c_int = 15;
const E2E_STARTUP_WAIT: Duration = Duration::from_secs(2);

static NEXT_SIM_CONFIG_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn run_reports_missing_raw_capability_or_shuts_down_in_order() {
    let fixture = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../control/tests/full-service.toml"),
    )
    .expect("full-service fixture must be readable");
    let devices = resolvable_devices();
    if devices.len() < 2 {
        if env::var("RUSTER_PRIVILEGED_E2E").ok().as_deref() == Some("1") {
            panic!(
                "privileged E2E requested but fewer than two interfaces are resolvable: {devices:?}"
            );
        }
        println!(
            "ruster-cli run E2E skipped: fewer than two interfaces are resolvable: {devices:?}"
        );
        return;
    }
    // Substitute through sentinels: a direct sequential replace would rewrite a
    // device name that an earlier replacement had just written (for example
    // `eth1 -> eth0` followed by `eth0 -> lo` collapses both interfaces onto
    // `lo` and the config is rejected for a duplicate device name).
    let source = fixture
        .replace("device = \"eth0\"", "device = \"@@RUSTER_DEV0@@\"")
        .replace("device = \"eth1\"", "device = \"@@RUSTER_DEV1@@\"")
        .replace("@@RUSTER_DEV0@@", &devices[0])
        .replace("@@RUSTER_DEV1@@", &devices[1]);
    let runwork = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.reloadwork");
    fs::create_dir_all(&runwork).expect("runwork directory must be creatable");
    let config_path = runwork.join(format!("ruster-cli-run-{}.toml", std::process::id()));
    fs::write(&config_path, source).expect("temporary run config must be writable");

    let mut child = Command::new(env!("CARGO_BIN_EXE_ruster"))
        .arg("run")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ruster run must spawn");

    let deadline = Instant::now() + E2E_STARTUP_WAIT;
    let (status, output) = loop {
        if let Some(status) = child.try_wait().expect("child status must be readable") {
            let output = child
                .wait_with_output()
                .expect("completed child output must be readable");
            break (status, output);
        }
        if Instant::now() >= deadline {
            // SAFETY: `child.id()` identifies the live child we just spawned,
            // and SIGTERM is a valid signal whose handler only sets its stop flag.
            let result = unsafe { kill(child.id() as c_int, SIGTERM) };
            assert_eq!(result, 0, "SIGTERM must be delivered to ruster run");
            let output = child
                .wait_with_output()
                .expect("signalled child output must be readable");
            break (output.status, output);
        }
        thread::sleep(Duration::from_millis(10));
    };

    fs::remove_file(&config_path).expect("temporary run config must be removable");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if status.success() {
        assert!(
            stdout.contains("shutdown complete"),
            "successful shutdown must be reported on stdout; stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains("generation=1"),
            "startup generation must be reported; stdout={stdout:?}"
        );
        assert!(
            stdout.contains("bound interface"),
            "bound interfaces must be reported; stdout={stdout:?}"
        );
    } else {
        assert_ne!(
            env::var("RUSTER_PRIVILEGED_E2E").ok().as_deref(),
            Some("1"),
            "privileged E2E requested but ruster run failed: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stderr.contains("root or CAP_NET_RAW is required"),
            "non-privileged run must explain the raw-socket requirement; stdout={stdout:?} stderr={stderr:?}"
        );
    }
}

fn resolvable_devices() -> Vec<String> {
    ["lo", "eth0", "eth1"]
        .iter()
        .filter_map(|name| {
            let c_name = CString::new(*name).expect("test interface names contain no NUL");
            // SAFETY: `c_name` is a live, NUL-terminated interface name and
            // `if_nametoindex` only reads it.
            let index = unsafe { if_nametoindex(c_name.as_ptr()) };
            (index != 0).then(|| (*name).to_owned())
        })
        .collect()
}

fn write_sim_config(label: &str, source: &str) -> PathBuf {
    let work = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.reloadwork");
    fs::create_dir_all(&work).expect("simwork directory must be creatable");
    let id = NEXT_SIM_CONFIG_ID.fetch_add(1, Ordering::Relaxed);
    let path = work.join(format!(
        "ruster-cli-{label}-{}-{id}.toml",
        std::process::id()
    ));
    fs::write(&path, source).expect("run-sim config must be writable");
    path
}

fn full_service_sim_config() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../control/tests/full-service.toml"),
    )
    .expect("full-service fixture must be readable")
}

fn run_sim_process(config_path: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ruster"))
        .arg("run-sim")
        .arg(config_path)
        .arg("--ticks")
        .arg("4")
        .output()
        .expect("run-sim must spawn")
}

fn final_observability_line(stdout: &str) -> &str {
    stdout
        .lines()
        .rfind(|line| line.starts_with("record_type=observability "))
        .expect("run-sim must emit a final observability record")
}

fn observability_field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|field| {
            let (field_key, value) = field.split_once('=')?;
            (field_key == key).then_some(value)
        })
        .unwrap_or_else(|| panic!("observability field {key:?} is missing: {line:?}"))
}

#[test]
fn run_sim_valid_config_is_non_privileged_finite_and_forwards() {
    let config_path = write_sim_config("valid", &full_service_sim_config());
    let output = run_sim_process(&config_path);
    fs::remove_file(&config_path).expect("temporary run-sim config must be removable");

    assert!(
        output.status.success(),
        "valid run-sim config must exit 0; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = final_observability_line(&stdout);
    let forwarded = observability_field(line, "forwarded")
        .parse::<u64>()
        .expect("forwarded must be an unsigned counter");
    assert!(forwarded > 0, "run-sim must forward a real packet: {line}");
    assert_eq!(observability_field(line, "backend_mode"), "sim");
    assert!(stdout.contains("shutdown complete"), "stdout={stdout:?}");
}

#[test]
fn run_sim_invalid_config_exits_nonzero() {
    let config_path = write_sim_config("invalid", "schema-version = 1\n[[interfaces]]\n");
    let output = run_sim_process(&config_path);
    fs::remove_file(&config_path).expect("temporary run-sim config must be removable");

    assert!(!output.status.success(), "invalid config must exit nonzero");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("configuration"),
        "invalid config failure must be explained; stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn run_sim_same_config_produces_deterministic_stdout() {
    let config_path = write_sim_config("deterministic", &full_service_sim_config());
    let first = run_sim_process(&config_path);
    let second = run_sim_process(&config_path);
    fs::remove_file(&config_path).expect("temporary run-sim config must be removable");

    assert!(
        first.status.success(),
        "first run-sim invocation must exit 0; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "second run-sim invocation must exit 0; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        first.stdout, second.stdout,
        "run-sim stdout must be deterministic"
    );
    let stdout = String::from_utf8_lossy(&first.stdout);
    let forwarded = observability_field(final_observability_line(&stdout), "forwarded")
        .parse::<u64>()
        .expect("forwarded must be an unsigned counter");
    assert!(
        forwarded > 0,
        "deterministic scenario must forward: {stdout:?}"
    );
}

fn write_temp_config(label: &str, contents: &[u8]) -> PathBuf {
    let id = NEXT_SIM_CONFIG_ID.fetch_add(1, Ordering::Relaxed);
    let path = env::temp_dir().join(format!(
        "ruster-cli-defect-{label}-{}-{id}.toml",
        std::process::id()
    ));
    fs::write(&path, contents).expect("temporary defect config must be writable");
    path
}

fn run_limited_cli(args: &[&str]) -> (Output, bool) {
    let mut child = Command::new("sh")
        .args([
            "-c",
            "ulimit -v 65536; exec \"$@\"",
            "ruster-test-shell",
            env!("CARGO_BIN_EXE_ruster"),
        ])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ruster test process must spawn");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child
            .try_wait()
            .expect("ruster test process status must be readable")
            .is_some()
        {
            return (
                child
                    .wait_with_output()
                    .expect("completed ruster test output must be readable"),
                false,
            );
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .expect("timed-out ruster process must be killable");
            return (
                child
                    .wait_with_output()
                    .expect("killed ruster test output must be readable"),
                true,
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn config_commands_bound_an_infinite_device_source() {
    for command in ["validate", "plan", "run", "run-sim"] {
        let (output, timed_out) = run_limited_cli(&[command, "/dev/zero"]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !timed_out,
            "{command} must stop reading /dev/zero at the input limit; stderr={stderr:?}"
        );
        assert!(
            !output.status.success(),
            "{command} /dev/zero must reject the input; stdout={:?} stderr={stderr:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            stderr.contains("input exceeds"),
            "{command} must report the bounded input error; stderr={stderr:?}"
        );
    }
}

#[test]
fn config_reader_does_not_wait_for_a_fifo_writer() {
    let id = NEXT_SIM_CONFIG_ID.fetch_add(1, Ordering::Relaxed);
    let path = env::temp_dir().join(format!(
        "ruster-cli-defect-fifo-{}-{id}",
        std::process::id()
    ));
    let status = Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo must be available for the FIFO regression");
    assert!(status.success(), "mkfifo must create the test FIFO");

    let (output, timed_out) =
        run_limited_cli(&["validate", path.to_str().expect("UTF-8 FIFO path")]);
    fs::remove_file(&path).expect("test FIFO must be removable");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !timed_out,
        "validate must not wait for a FIFO writer; stderr={stderr:?}"
    );
    assert!(
        !output.status.success(),
        "an empty FIFO cannot be a valid configuration; stderr={stderr:?}"
    );
    assert!(
        !stderr.contains("out of memory"),
        "FIFO rejection must not be caused by unbounded allocation; stderr={stderr:?}"
    );
}

#[test]
fn config_errors_are_operator_readable_and_keep_path_and_reason() {
    let unknown_path = write_temp_config(
        "unknown-field",
        br#"schema-version = 1
[[interfaces]]
id = 1
name = "lan"
devicee = "eth0"
mac = "02:00:00:00:00:01"
"#,
    );
    let (unknown_output, unknown_timed_out) =
        run_limited_cli(&["validate", unknown_path.to_str().expect("UTF-8 temp path")]);
    fs::remove_file(&unknown_path).expect("unknown-field fixture must be removable");
    let unknown_stderr = String::from_utf8_lossy(&unknown_output.stderr);
    assert!(!unknown_timed_out, "unknown-field validation must finish");
    assert!(!unknown_output.status.success());
    assert!(
        unknown_stderr
            .contains("configuration invalid at interfaces[0]: unknown field \"devicee\""),
        "unknown field must name its path and key; stderr={unknown_stderr:?}"
    );
    assert!(
        !unknown_stderr.contains("Diagnostic {") && !unknown_stderr.contains("path:"),
        "unknown field must not use a Rust Debug dump; stderr={unknown_stderr:?}"
    );

    let invalid_frame_path = write_temp_config(
        "invalid-frame-size",
        br#"schema-version = 1
[[interfaces]]
id = 1
name = "lan"
device = "eth0"
mac = "02:00:00:00:00:01"
[[interfaces]]
id = 2
name = "wan"
device = "eth1"
mac = "02:00:00:00:00:02"

[backend]
kind = "af-xdp"
xskmap-max-entries = 1
bind-flags = 10
attach-mode = "skb"

[backend.umem]
frame-count = 4
frame-size = 2047
headroom = 0
rx-frames = 1
generated-frames = 3
raw-flags = 0

[backend.rings]
fill = 2
rx = 2
tx = 2
completion = 2

[[backend.resources]]
interface = "lan"
queue-id = 0

[[backend.resources]]
interface = "wan"
queue-id = 0
"#,
    );
    let (validation_output, validation_timed_out) = run_limited_cli(&[
        "validate",
        invalid_frame_path.to_str().expect("UTF-8 temp path"),
    ]);
    fs::remove_file(&invalid_frame_path).expect("invalid-frame fixture must be removable");
    let validation_stderr = String::from_utf8_lossy(&validation_output.stderr);
    assert!(
        !validation_timed_out,
        "invalid-frame validation must finish"
    );
    assert!(!validation_output.status.success());
    assert!(
        validation_stderr.contains(
            "configuration invalid at backend.umem.frame-size: frame size 2047 must be a power of two"
        ),
        "frame-size error must be readable; stderr={validation_stderr:?}"
    );
    assert!(
        !validation_stderr.contains("ValidationError {") && !validation_stderr.contains("path:"),
        "validation must not use a Rust Debug dump; stderr={validation_stderr:?}"
    );

    let oversized_path = write_temp_config("input-too-large", &vec![b' '; MAX_CONFIG_BYTES + 1]);
    let (oversized_output, oversized_timed_out) = run_limited_cli(&[
        "validate",
        oversized_path.to_str().expect("UTF-8 temp path"),
    ]);
    fs::remove_file(&oversized_path).expect("oversized fixture must be removable");
    let oversized_stderr = String::from_utf8_lossy(&oversized_output.stderr);
    assert!(!oversized_timed_out, "oversized validation must finish");
    assert!(!oversized_output.status.success());
    assert!(
        oversized_stderr.contains(
            "configuration invalid at <input>: input exceeds 1048576 bytes (read at least 1048577)"
        ),
        "input limit error must be readable; stderr={oversized_stderr:?}"
    );
    assert!(
        !oversized_stderr.contains("Diagnostic {") && !oversized_stderr.contains("path:"),
        "input limit must not use a Rust Debug dump; stderr={oversized_stderr:?}"
    );
}

unsafe extern "C" {
    fn if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
    fn kill(pid: c_int, signal: c_int) -> c_int;
}

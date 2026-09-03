//! Measurement-only support shared by the privileged throughput tests.
//!
//! This module is included by the integration-test crates with `#[path]`; it
//! is deliberately not part of a product packet path.  The ABI constants and
//! the `PerfEventAttr` layout below were checked with the C probe recorded in
//! `docs/throughput-measurement.md` against the installed Linux headers:
//! `__NR_perf_event_open=298` and `sizeof(struct perf_event_attr)=136` on the
//! x86_64 host.  The probe also recorded every offset used by this layout.

use std::{
    env,
    ffi::{c_char, c_int, c_long, c_ulong, c_void},
    fs,
    mem::{offset_of, size_of},
    os::fd::RawFd,
};

pub const LATENCY_CLOCK_NAME: &str = "CLOCK_MONOTONIC";
pub const LATENCY_CLOCK_DOMAIN: &str = "same_host_monotonic_clock";
pub const LATENCY_PERCENTILE_METHOD: &str = "nearest_rank";
pub const LATENCY_MAGIC: [u8; 8] = *b"RUSTLAT1";
pub const LATENCY_MAGIC_OFFSET: usize = 14;
pub const LATENCY_TIMESTAMP_OFFSET: usize = LATENCY_MAGIC_OFFSET + LATENCY_MAGIC.len();
pub const LATENCY_TIMESTAMP_LEN: usize = size_of::<u64>();
pub const LATENCY_PAYLOAD_END: usize = LATENCY_TIMESTAMP_OFFSET + LATENCY_TIMESTAMP_LEN;

pub const MIN_SAMPLES_P50: u64 = 2;
pub const MIN_SAMPLES_P90: u64 = 10;
pub const MIN_SAMPLES_P99: u64 = 100;
pub const MIN_SAMPLES_P99_9: u64 = 1_000;

const CLOCK_MONOTONIC: c_int = 1;
const EINVAL: i32 = 22;
const ENODEV: i32 = 19;
#[cfg(not(target_arch = "x86_64"))]
const ENOTSUP: i32 = 95;
const EIO: i32 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampError {
    FrameTooShort,
    Clock { errno: i32 },
    InvalidClockValue,
    ClockOverflow,
}

impl TimestampError {
    pub fn code(self) -> i32 {
        match self {
            Self::FrameTooShort => -EINVAL,
            Self::Clock { errno } => errno,
            Self::InvalidClockValue => -EINVAL,
            Self::ClockOverflow => -EOVERFLOW,
        }
    }
}

const EOVERFLOW: i32 = 75;

fn monotonic_now_ns() -> Result<u64, TimestampError> {
    let mut time = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is an initialized, writable `timespec` whose lifetime
    // covers the call; CLOCK_MONOTONIC does not read any other pointer.
    let result = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut time) };
    if result != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        return Err(TimestampError::Clock { errno });
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(TimestampError::InvalidClockValue);
    }
    let seconds = u64::try_from(time.tv_sec).map_err(|_| TimestampError::InvalidClockValue)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(u64::try_from(time.tv_nsec).ok()?))
        .ok_or(TimestampError::ClockOverflow)
}

/// Stamp a sender slot while guaranteeing a distinct timestamp for every
/// successful slot in one sender thread.  The value is derived from the
/// `CLOCK_MONOTONIC` reading; a one-nanosecond tie break only handles coarse
/// clock ticks and does not replace the monotonic clock as the time source.
pub fn stamp_frame_with_last(
    frame: &mut [u8],
    last_timestamp: &mut u64,
) -> Result<(), TimestampError> {
    if frame.len() < LATENCY_PAYLOAD_END {
        return Err(TimestampError::FrameTooShort);
    }
    let clock_timestamp = monotonic_now_ns()?;
    let timestamp = if clock_timestamp <= *last_timestamp {
        last_timestamp
            .checked_add(1)
            .ok_or(TimestampError::ClockOverflow)?
    } else {
        clock_timestamp
    };
    write_frame_timestamp(frame, timestamp);
    *last_timestamp = timestamp;
    Ok(())
}

fn write_frame_timestamp(frame: &mut [u8], timestamp: u64) {
    frame[LATENCY_MAGIC_OFFSET..LATENCY_PAYLOAD_END - LATENCY_TIMESTAMP_LEN]
        .copy_from_slice(&LATENCY_MAGIC);
    frame[LATENCY_TIMESTAMP_OFFSET..LATENCY_PAYLOAD_END].fill(0);
    frame[LATENCY_TIMESTAMP_OFFSET..LATENCY_PAYLOAD_END].copy_from_slice(&timestamp.to_be_bytes());
}

/// Make a failed sender timestamp unmatchable without allocating a new frame.
pub fn clear_frame_timestamp(frame: &mut [u8]) {
    if frame.len() >= LATENCY_PAYLOAD_END {
        frame[LATENCY_TIMESTAMP_OFFSET..LATENCY_PAYLOAD_END].fill(0);
    }
}

pub struct LatencyCollector {
    samples: Vec<u64>,
    unmatched_packets: u64,
    missing_timestamps: u64,
    backwards_timestamps: u64,
    clock_errors: u64,
    last_clock_error: Option<i32>,
}

impl LatencyCollector {
    pub fn new() -> Self {
        Self {
            samples: Vec::with_capacity(4_096),
            unmatched_packets: 0,
            missing_timestamps: 0,
            backwards_timestamps: 0,
            clock_errors: 0,
            last_clock_error: None,
        }
    }

    /// Read the sender timestamp and take the receive timestamp as close as
    /// possible to the borrowed packet access.  The vector is owned by the
    /// receiver test thread and is never shared with the product data path.
    pub fn record_received(&mut self, frame: &[u8]) {
        if frame.len() < LATENCY_PAYLOAD_END
            || frame[LATENCY_MAGIC_OFFSET..LATENCY_TIMESTAMP_OFFSET] != LATENCY_MAGIC
        {
            self.unmatched_packets = self
                .unmatched_packets
                .checked_add(1)
                .expect("latency unmatched counter overflowed");
            return;
        }
        let timestamp_bytes: [u8; LATENCY_TIMESTAMP_LEN] = frame
            [LATENCY_TIMESTAMP_OFFSET..LATENCY_PAYLOAD_END]
            .try_into()
            .expect("latency timestamp range has a fixed size");
        let sent_ns = u64::from_be_bytes(timestamp_bytes);
        if sent_ns == 0 {
            self.missing_timestamps = self
                .missing_timestamps
                .checked_add(1)
                .expect("latency missing counter overflowed");
            return;
        }
        let received_ns = match monotonic_now_ns() {
            Ok(value) => value,
            Err(error) => {
                self.clock_errors = self
                    .clock_errors
                    .checked_add(1)
                    .expect("latency clock error counter overflowed");
                self.last_clock_error = Some(error.code());
                return;
            }
        };
        let Some(latency_ns) = received_ns.checked_sub(sent_ns) else {
            self.backwards_timestamps = self
                .backwards_timestamps
                .checked_add(1)
                .expect("latency backwards counter overflowed");
            return;
        };
        self.samples.push(latency_ns);
    }

    pub fn finish(mut self) -> LatencySummary {
        self.samples.sort_unstable();
        let samples = u64::try_from(self.samples.len()).expect("latency sample count fits u64");
        let summary = LatencySummary {
            samples,
            p50_ns: nearest_rank(&self.samples, 1, 2, MIN_SAMPLES_P50),
            p90_ns: nearest_rank(&self.samples, 9, 10, MIN_SAMPLES_P90),
            p99_ns: nearest_rank(&self.samples, 99, 100, MIN_SAMPLES_P99),
            p99_9_ns: nearest_rank(&self.samples, 999, 1_000, MIN_SAMPLES_P99_9),
            min_ns: self.samples.first().copied(),
            max_ns: self.samples.last().copied(),
            unmatched_packets: self.unmatched_packets,
            missing_timestamps: self.missing_timestamps,
            backwards_timestamps: self.backwards_timestamps,
            clock_errors: self.clock_errors,
            last_clock_error: self.last_clock_error,
        };
        debug_assert_eq!(summary.samples, samples);
        summary
    }
}

impl Default for LatencyCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencySummary {
    pub samples: u64,
    pub p50_ns: Option<u64>,
    pub p90_ns: Option<u64>,
    pub p99_ns: Option<u64>,
    pub p99_9_ns: Option<u64>,
    pub min_ns: Option<u64>,
    pub max_ns: Option<u64>,
    pub unmatched_packets: u64,
    pub missing_timestamps: u64,
    pub backwards_timestamps: u64,
    pub clock_errors: u64,
    pub last_clock_error: Option<i32>,
}

impl LatencySummary {
    pub fn percentiles_complete(self) -> bool {
        self.p50_ns.is_some()
            && self.p90_ns.is_some()
            && self.p99_ns.is_some()
            && self.p99_9_ns.is_some()
    }
}

fn nearest_rank(
    sorted_samples: &[u64],
    numerator: u64,
    denominator: u64,
    minimum: u64,
) -> Option<u64> {
    let samples = u64::try_from(sorted_samples.len()).ok()?;
    if samples < minimum || samples == 0 {
        return None;
    }
    let rank = samples
        .checked_mul(numerator)?
        .checked_add(denominator - 1)?
        / denominator;
    let index = usize::try_from(rank.checked_sub(1)?).ok()?;
    sorted_samples.get(index).copied()
}

pub fn format_latency_value(value: Option<u64>) -> String {
    value.map_or_else(
        || "insufficient_samples".to_owned(),
        |value| value.to_string(),
    )
}

pub fn format_optional_i32(value: Option<i32>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}

pub fn format_optional_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}

/// Assert the whitespace-delimited record contract used by the measurement
/// harnesses.  These harnesses are the only callers; this is intentionally a
/// test-time guard around their stdout rather than a packet-path utility.
#[allow(dead_code)]
pub fn assert_machine_readable_record_line(line: &str) {
    assert!(!line.is_empty(), "record line must not be empty");
    assert!(
        !line.contains(['\n', '\r']),
        "record must be exactly one line: {line:?}"
    );
    for token in line.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .unwrap_or_else(|| panic!("record token is not key=value: {token:?}"));
        assert!(!key.is_empty(), "record token has an empty key: {token:?}");
        assert!(
            !value.chars().any(char::is_whitespace),
            "record value contains whitespace: {token:?}"
        );
    }
}

fn machine_readable_field_value<'a>(line: &'a str, field: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|token| {
            let (key, value) = token.split_once('=')?;
            (key == field).then_some(value)
        })
        .unwrap_or_else(|| panic!("record field is missing: {field} in {line:?}"))
}

fn is_stable_ascii_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Assert that a selected record field is a stable ASCII token or comma-list.
#[allow(dead_code)]
pub fn assert_machine_readable_ascii_field(line: &str, field: &str) {
    let value = machine_readable_field_value(line, field);
    assert!(
        value.split(',').all(is_stable_ascii_token),
        "record field is not a stable ASCII token/list: {field}={value}"
    );
}

/// Assert that a selected record field is exactly one stable ASCII token.
#[allow(dead_code)]
pub fn assert_machine_readable_ascii_token_field(line: &str, field: &str) {
    let value = machine_readable_field_value(line, field);
    assert!(
        is_stable_ascii_token(value),
        "record field is not a stable ASCII token: {field}={value}"
    );
}

/// Assert that a selected record field is a non-empty comma-separated list of
/// stable ASCII tokens.
#[allow(dead_code)]
pub fn assert_machine_readable_ascii_token_list_field(line: &str, field: &str) {
    let value = machine_readable_field_value(line, field);
    assert!(
        value.split(',').all(is_stable_ascii_token),
        "record field is not a comma-separated stable ASCII token list: {field}={value}"
    );
}

pub const MIN_HARDWARE_ACCEPTANCE_LINK_SPEED_MBPS: i64 = 10_000;

// Stable machine-readable acceptance tokens.  Keep this mapping backwards
// compatible because records are consumed by scripts and long-lived logs:
//
//   invalid interface       -> nic_interface_invalid
//   missing device          -> nic_device_missing
//   virtual driver          -> nic_driver_virtual
//   unknown driver          -> nic_driver_unknown
//   unreadable/invalid speed -> link_speed_read_error or link_speed_invalid
//   unknown/non-positive speed -> link_speed_unknown
//   positive speed below gate -> link_speed_below_threshold
//   physical gate fallback   -> nic_physical_gate_unmet
//   CPU affinity unverified  -> cpu_affinity_not_verified
//   IRQ affinity unverified  -> irq_affinity_not_verified
//   RSS queue unverified     -> rss_queue_not_verified
//   perf cycles unavailable   -> perf_cycles_not_measured
//   perf cache misses unavailable -> perf_cache_misses_not_measured
//   latency samples incomplete -> latency_samples_insufficient
//   measurement skipped      -> measurement_skipped
//   measurement status error -> measurement_error
//
// The physical-NIC `measurement_error` field uses `none` for success,
// `nic_physical_precondition_unmet` when the read-only NIC/speed gate skips
// traffic, and `measurement_failed` for an attempted measurement error.
const TOKEN_NIC_INTERFACE_INVALID: &str = "nic_interface_invalid";
const TOKEN_NIC_DEVICE_MISSING: &str = "nic_device_missing";
const TOKEN_NIC_DRIVER_VIRTUAL: &str = "nic_driver_virtual";
const TOKEN_NIC_DRIVER_UNKNOWN: &str = "nic_driver_unknown";
const TOKEN_LINK_SPEED_READ_ERROR: &str = "link_speed_read_error";
const TOKEN_LINK_SPEED_INVALID: &str = "link_speed_invalid";
const TOKEN_LINK_SPEED_UNKNOWN: &str = "link_speed_unknown";
const TOKEN_LINK_SPEED_BELOW_THRESHOLD: &str = "link_speed_below_threshold";
const TOKEN_NIC_PHYSICAL_GATE_UNMET: &str = "nic_physical_gate_unmet";
const TOKEN_CPU_AFFINITY_NOT_VERIFIED: &str = "cpu_affinity_not_verified";
const TOKEN_IRQ_AFFINITY_NOT_VERIFIED: &str = "irq_affinity_not_verified";
const TOKEN_RSS_QUEUE_NOT_VERIFIED: &str = "rss_queue_not_verified";
const TOKEN_PERF_CYCLES_NOT_MEASURED: &str = "perf_cycles_not_measured";
const TOKEN_PERF_CACHE_MISSES_NOT_MEASURED: &str = "perf_cache_misses_not_measured";
const TOKEN_LATENCY_SAMPLES_INSUFFICIENT: &str = "latency_samples_insufficient";
const TOKEN_MEASUREMENT_SKIPPED: &str = "measurement_skipped";
const TOKEN_MEASUREMENT_ERROR: &str = "measurement_error";
const TOKEN_NIC_PHYSICAL_PRECONDITION_UNMET: &str = "nic_physical_precondition_unmet";
const TOKEN_MEASUREMENT_FAILED: &str = "measurement_failed";

const IFNAMSIZ: usize = 16;
const AF_INET: c_int = 2;
const SOCK_DGRAM: c_int = 2;
const SOCK_CLOEXEC: c_int = 0x8_0000;
const SIOCETHTOOL: c_ulong = 0x8946;
const ETHTOOL_GRXFHINDIR: u32 = 0x0000_0038;
const MAX_RSS_INDIRECTION_ENTRIES: usize = 1_048_576;

#[allow(dead_code)]
const VIRTUAL_NIC_DRIVERS: &[&str] = &[
    "virtio_net",
    "veth",
    "loopback",
    "tun",
    "tap",
    "dummy",
    "bridge",
    "bonding",
    "team",
    "macvlan",
    "macvtap",
    "ipvlan",
    "ipvtap",
    "ifb",
    "wireguard",
    "vxlan",
    "geneve",
    "gre",
    "gretap",
    "ip6gre",
    "ip6tnl",
    "sit",
];

#[allow(dead_code)]
#[derive(Debug)]
pub struct NicInspection {
    pub device_present: bool,
    pub driver: Option<String>,
    pub driver_is_virtual: bool,
    pub link_speed_mbps: Option<i64>,
    pub link_speed_raw: String,
    pub physical_verdict: bool,
    pub blockers: Vec<String>,
}

impl NicInspection {
    pub fn link_speed_at_least_acceptance_threshold(&self) -> bool {
        self.link_speed_mbps
            .is_some_and(|speed| speed >= MIN_HARDWARE_ACCEPTANCE_LINK_SPEED_MBPS)
    }
}

/// Explain why a harness must not start packet traffic when the NIC identity
/// or speed prerequisite is already rejected.  This is separate from the
/// generic unmeasured perf/latency blockers so a skipped measurement remains
/// an explicit acceptance failure.
#[allow(dead_code)]
pub fn acceptance_measurement_skip_reason(nic: &NicInspection) -> Option<String> {
    let mut reasons = Vec::with_capacity(2);
    if !nic.physical_verdict {
        reasons.push(format!(
            "NIC physical 前提未達 (nic_physical_verdict=false device_present={} driver={})",
            nic.device_present,
            nic.driver.as_deref().unwrap_or("unknown")
        ));
    }
    if !nic.link_speed_at_least_acceptance_threshold() {
        let speed = nic
            .link_speed_mbps
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
        reasons.push(format!(
            "link speed 前提未達 (nic_link_speed_mbps={speed} required>={MIN_HARDWARE_ACCEPTANCE_LINK_SPEED_MBPS} Mbps)"
        ));
    }
    if reasons.is_empty() {
        None
    } else {
        Some(format!(
            "NIC の physical/speed 前提未達のため測定未実施: {}",
            reasons.join("; ")
        ))
    }
}

/// Return the stable machine-readable value for the physical-NIC error field.
/// The caller retains the supplied string as a human-readable stderr detail.
#[allow(dead_code)]
pub fn acceptance_measurement_error_token(
    nic: &NicInspection,
    measurement_error: Option<&str>,
) -> &'static str {
    match measurement_error {
        None => "none",
        Some(_) if acceptance_measurement_skip_reason(nic).is_some() => {
            TOKEN_NIC_PHYSICAL_PRECONDITION_UNMET
        }
        Some(_) => TOKEN_MEASUREMENT_FAILED,
    }
}

/// Inspect only immutable/read-only interface evidence needed for hardware
/// acceptance.  In particular, a `/device` symlink alone is not considered a
/// physical-NIC proof: the driver and a positive kernel-reported link speed
/// are required as well.
#[allow(dead_code)]
pub fn inspect_nic(interface: &str) -> NicInspection {
    let mut blockers = Vec::with_capacity(4);
    if !valid_interface_name(interface) {
        blockers.push("interface name が無効で sysfs を安全に検査できない".to_owned());
        return NicInspection {
            device_present: false,
            driver: None,
            driver_is_virtual: false,
            link_speed_mbps: None,
            link_speed_raw: "invalid_interface".to_owned(),
            physical_verdict: false,
            blockers,
        };
    }

    let device_path = format!("/sys/class/net/{interface}/device");
    let device_present = fs::metadata(&device_path).is_ok();
    if !device_present {
        blockers.push(format!("{interface} の sysfs device が存在しない"));
    }

    let driver = fs::read_link(format!("{device_path}/driver"))
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_owned()))
        .and_then(|name| name.into_string().ok());
    let driver_is_virtual = driver
        .as_deref()
        .is_some_and(|name| VIRTUAL_NIC_DRIVERS.contains(&name));
    match driver.as_deref() {
        Some(name) if driver_is_virtual => {
            blockers.push(format!("{name} は仮想ドライバ"));
        }
        Some(_) => {}
        None => blockers.push("NIC driver 名を sysfs から取得できない".to_owned()),
    }

    let (link_speed_mbps, link_speed_raw) =
        match fs::read_to_string(format!("/sys/class/net/{interface}/speed")) {
            Ok(value) => {
                let raw = value.trim().to_owned();
                let parsed = raw.parse::<i64>().ok();
                match parsed {
                    Some(speed) if speed > 0 => {}
                    Some(-1) => blockers.push("link speed 不明 (-1)".to_owned()),
                    Some(speed) => blockers.push(format!("link speed 不明 ({speed})")),
                    None => blockers.push(format!("link speed の値を解釈できない ({raw})")),
                }
                (parsed, raw)
            }
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(-1);
                blockers.push(format!("link speed を読み取れない (errno={errno})"));
                (None, "unknown".to_owned())
            }
        };

    let physical_verdict = device_present
        && driver.is_some()
        && !driver_is_virtual
        && link_speed_mbps.is_some_and(|speed| speed > 0);
    NicInspection {
        device_present,
        driver,
        driver_is_virtual,
        link_speed_mbps,
        link_speed_raw,
        physical_verdict,
        blockers,
    }
}

#[allow(dead_code)]
fn valid_interface_name(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() < IFNAMSIZ
        && interface.bytes().all(|byte| byte != 0 && byte != b'/')
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PerfFailureStage {
    Open,
    Reset,
    Enable,
    Disable,
    GroupRead,
    Close,
    #[cfg(not(target_arch = "x86_64"))]
    Unsupported,
}

impl PerfFailureStage {
    const fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reset => "reset",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::GroupRead => "group_read",
            Self::Close => "close",
            #[cfg(not(target_arch = "x86_64"))]
            Self::Unsupported => "unsupported_architecture",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfCounterResult {
    count: Option<u64>,
    errno: Option<i32>,
    failure: Option<PerfFailureStage>,
}

impl PerfCounterResult {
    const fn pending() -> Self {
        Self {
            count: None,
            errno: None,
            failure: None,
        }
    }

    const fn unavailable(stage: PerfFailureStage, errno: i32) -> Self {
        Self {
            count: None,
            errno: Some(errno),
            failure: Some(stage),
        }
    }

    pub fn count(self) -> Option<u64> {
        self.count
    }

    pub fn measured(self) -> bool {
        self.count.is_some()
    }

    pub fn value(self) -> String {
        self.count
            .map_or_else(|| "unmeasured".to_owned(), |value| value.to_string())
    }

    pub fn status(self) -> String {
        match (self.failure, self.errno) {
            (Some(stage), Some(errno)) => format!("unmeasured_{}_errno_{errno}", stage.name()),
            (Some(stage), None) => format!("unmeasured_{}", stage.name()),
            (None, None) if self.count.is_some() => "measured".to_owned(),
            (None, _) => "unmeasured_not_started".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfReport {
    pub cycles: PerfCounterResult,
    pub cache_references: PerfCounterResult,
    pub cache_misses: PerfCounterResult,
}

impl PerfReport {
    pub const fn not_measured() -> Self {
        Self {
            cycles: PerfCounterResult::pending(),
            cache_references: PerfCounterResult::pending(),
            cache_misses: PerfCounterResult::pending(),
        }
    }

    pub fn cycles_per_packet(self, packets: u64) -> Option<f64> {
        let cycles = self.cycles.count()?;
        if packets == 0 {
            None
        } else {
            Some(cycles as f64 / packets as f64)
        }
    }

    pub fn cache_miss_rate_percent(self) -> Option<f64> {
        let misses = self.cache_misses.count()?;
        let references = self.cache_references.count()?;
        if references == 0 {
            None
        } else {
            Some(misses as f64 * 100.0 / references as f64)
        }
    }
}

// The C probe in docs/throughput-measurement.md measured the x86_64 Linux
// UAPI layout.  The bitfield is represented by its ABI storage unit: the
// only flag used here is disabled (bit 0).
#[repr(C)]
#[derive(Clone, Copy)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    reserved2: u16,
    aux_sample_size: u32,
    reserved3: u32,
    sig_data: u64,
    config3: u64,
}

#[cfg(target_arch = "x86_64")]
const _: () = {
    assert!(size_of::<PerfEventAttr>() == 136);
    assert!(offset_of!(PerfEventAttr, type_) == 0);
    assert!(offset_of!(PerfEventAttr, size) == 4);
    assert!(offset_of!(PerfEventAttr, config) == 8);
    assert!(offset_of!(PerfEventAttr, sample_period) == 16);
    assert!(offset_of!(PerfEventAttr, sample_type) == 24);
    assert!(offset_of!(PerfEventAttr, read_format) == 32);
    assert!(offset_of!(PerfEventAttr, flags) == 40);
    assert!(offset_of!(PerfEventAttr, wakeup_events) == 48);
    assert!(offset_of!(PerfEventAttr, bp_type) == 52);
    assert!(offset_of!(PerfEventAttr, config1) == 56);
    assert!(offset_of!(PerfEventAttr, config2) == 64);
    assert!(offset_of!(PerfEventAttr, branch_sample_type) == 72);
    assert!(offset_of!(PerfEventAttr, sample_regs_user) == 80);
    assert!(offset_of!(PerfEventAttr, sample_stack_user) == 88);
    assert!(offset_of!(PerfEventAttr, clockid) == 92);
    assert!(offset_of!(PerfEventAttr, sample_regs_intr) == 96);
    assert!(offset_of!(PerfEventAttr, aux_watermark) == 104);
    assert!(offset_of!(PerfEventAttr, sample_max_stack) == 108);
    assert!(offset_of!(PerfEventAttr, aux_sample_size) == 112);
    assert!(offset_of!(PerfEventAttr, sig_data) == 120);
    assert!(offset_of!(PerfEventAttr, config3) == 128);
    assert!(PERF_FORMAT_TOTAL_TIME_ENABLED == 0x1);
    assert!(PERF_FORMAT_TOTAL_TIME_RUNNING == 0x2);
    assert!(PERF_FORMAT_GROUP == 0x8);
    assert!(PERF_EVENT_READ_FORMAT == 0xb);
    assert!(PERF_IOC_FLAG_GROUP == 0x1);
};

const PERF_TYPE_HARDWARE: u64 = 0;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const PERF_ATTR_DISABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
const PERF_FORMAT_GROUP: u64 = 1 << 3;
const PERF_EVENT_READ_FORMAT: u64 =
    PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
const PERF_IOC_FLAG_GROUP: c_ulong = 1;
const PERF_GROUP_READ_HEADER_WORDS: usize = 3;
const PERF_GROUP_READ_WORDS: usize = PERF_GROUP_READ_HEADER_WORDS + 3;

// The installed-header probe printed __NR_perf_event_open=298 for this
// x86_64 toolchain.  Other architectures are deliberately reported as
// unsupported instead of guessing an ABI number.
const PERF_EVENT_OPEN_SYSCALL_X86_64: c_long = 298;
const PERF_EVENT_IOC_ENABLE: c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: c_ulong = 0x2401;
const PERF_EVENT_IOC_RESET: c_ulong = 0x2403;

#[derive(Clone, Copy)]
struct PerfEventSlot {
    name: &'static str,
    config: u64,
    fd: RawFd,
    result: PerfCounterResult,
}

impl PerfEventSlot {
    const fn new(name: &'static str, config: u64) -> Self {
        Self {
            name,
            config,
            fd: -1,
            result: PerfCounterResult::pending(),
        }
    }
}

pub struct PerfEventSet {
    events: [PerfEventSlot; 3],
    group_indices: [usize; 3],
    group_len: usize,
}

impl PerfEventSet {
    pub fn open_current_thread() -> Self {
        let mut set = Self {
            events: [
                PerfEventSlot::new("cycles", PERF_COUNT_HW_CPU_CYCLES),
                PerfEventSlot::new("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
                PerfEventSlot::new("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
            ],
            group_indices: [0; 3],
            group_len: 0,
        };
        #[cfg(target_arch = "x86_64")]
        {
            match set.open_event(0, -1, true) {
                Ok(()) => {
                    set.group_indices[0] = 0;
                    set.group_len = 1;
                    let leader_fd = set.events[0].fd;
                    for index in 1..set.events.len() {
                        match set.open_event(index, leader_fd, false) {
                            Ok(()) => {
                                let group_index = set.group_len;
                                set.group_indices[group_index] = index;
                                set.group_len += 1;
                            }
                            Err(errno) => {
                                // Cache events are optional.  Keep the
                                // cycles-led group usable when one cannot be
                                // opened, while retaining this event as
                                // explicitly unmeasured.
                                set.mark_failure(index, PerfFailureStage::Open, errno);
                            }
                        }
                    }
                }
                Err(errno) => {
                    // The leader is required for all group measurements.  A
                    // failure here makes every requested perf result
                    // unavailable, and is reported for each output field.
                    for index in 0..set.events.len() {
                        set.mark_failure(index, PerfFailureStage::Open, errno);
                    }
                }
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            for event in &mut set.events {
                event.result =
                    PerfCounterResult::unavailable(PerfFailureStage::Unsupported, ENOTSUP);
                eprintln!(
                    "PERF_MEASUREMENT_FAILURE event={} stage=unsupported_architecture errno={ENOTSUP}",
                    event.name
                );
            }
        }
        set
    }

    #[cfg(target_arch = "x86_64")]
    fn open_event(&mut self, index: usize, group_fd: RawFd, leader: bool) -> Result<(), i32> {
        let event = self.events[index];
        // SAFETY: all fields are integer ABI fields and zero is valid for the
        // complete UAPI structure; the kernel only reads `attr` during this
        // synchronous raw syscall.
        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.type_ = PERF_TYPE_HARDWARE as u32;
        attr.size = u32::try_from(size_of::<PerfEventAttr>()).expect("perf attr size fits u32");
        attr.config = event.config;
        attr.read_format = PERF_EVENT_READ_FORMAT;
        attr.flags = if leader { PERF_ATTR_DISABLED } else { 0 };
        // SAFETY: `attr` is a live, fully initialized repr(C) UAPI object.
        // The raw syscall arguments follow perf_event_open(attr, pid, cpu,
        // group_fd, flags): pid=0 selects this receiving thread, cpu=-1 lets
        // it run on its selected CPU, group_fd is -1 for the leader or the
        // live leader fd for a member, and flags=0.  The syscall number is
        // the installed-header __NR_perf_event_open.
        let fd = unsafe {
            syscall(
                PERF_EVENT_OPEN_SYSCALL_X86_64,
                &attr as *const PerfEventAttr,
                0_i32,
                -1_i32,
                group_fd,
                0_u64,
            )
        };
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            Err(errno)
        } else {
            self.events[index].fd = i32::try_from(fd).map_err(|_| EOVERFLOW)?;
            Ok(())
        }
    }

    pub fn start(&mut self) {
        if self.group_len == 0 {
            return;
        }
        let leader_fd = self.events[0].fd;
        if leader_fd < 0 {
            return;
        }
        // SAFETY: the leader fd was returned by perf_event_open and remains
        // owned by this set; PERF_IOC_FLAG_GROUP applies the request to the
        // complete group and carries no pointer argument.
        let reset = unsafe { ioctl(leader_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) };
        if reset < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            self.fail_group(PerfFailureStage::Reset, errno);
            return;
        }
        // SAFETY: the same owned leader fd is synchronously enabled as a
        // group; the ioctl argument is an integer flag, not a pointer.
        let enabled = unsafe { ioctl(leader_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) };
        if enabled < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            self.fail_group(PerfFailureStage::Enable, errno);
        }
    }

    pub fn stop_and_read(mut self) -> PerfReport {
        if self.group_len == 0 || self.events[0].fd < 0 {
            return self.report();
        }
        let leader_fd = self.events[0].fd;
        // SAFETY: the leader fd is live and owned by this set; the group flag
        // applies the disable operation to every opened member.
        let disabled = unsafe { ioctl(leader_fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) };
        if disabled < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            self.fail_group(PerfFailureStage::Disable, errno);
            return self.report();
        }

        let mut group_read = [0_u64; PERF_GROUP_READ_WORDS];
        let read_words = PERF_GROUP_READ_HEADER_WORDS + self.group_len;
        let read_size = size_of::<u64>() * read_words;
        // SAFETY: `group_read` is a writable fixed-size array for exactly the
        // no-ID group layout requested below (nr, enabled, running, and the
        // opened group's values), and the live leader fd is the owner of this
        // group read.  The count is bounded by the array's six-u64 capacity.
        let bytes = unsafe {
            read(
                leader_fd,
                group_read.as_mut_ptr().cast::<c_void>(),
                read_size,
            )
        };
        let expected_bytes = isize::try_from(read_size).expect("group read size fits isize");
        if bytes != expected_bytes {
            let errno = if bytes < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            } else {
                EIO
            };
            self.fail_group(PerfFailureStage::GroupRead, errno);
            return self.report();
        }

        let group_count = usize::try_from(group_read[0]).unwrap_or(usize::MAX);
        if group_count != self.group_len {
            eprintln!(
                "PERF_MEASUREMENT_FAILURE stage=group_read reason=unexpected_nr expected={} observed={group_count}; result is unmeasured",
                self.group_len
            );
            self.fail_group(PerfFailureStage::GroupRead, EIO);
            return self.report();
        }
        let time_enabled = group_read[1];
        let time_running = group_read[2];
        if time_enabled == 0 || time_running == 0 || time_running > time_enabled {
            eprintln!(
                "PERF_MEASUREMENT_FAILURE stage=group_read reason=invalid_time_running time_enabled={time_enabled} time_running={time_running}; result is unmeasured"
            );
            self.fail_group(PerfFailureStage::GroupRead, EIO);
            return self.report();
        }

        for group_position in 0..self.group_len {
            let index = self.group_indices[group_position];
            let raw_count = group_read[PERF_GROUP_READ_HEADER_WORDS + group_position];
            let Some(count) = scale_perf_count(raw_count, time_enabled, time_running) else {
                eprintln!(
                    "PERF_MEASUREMENT_FAILURE event={} stage=group_read reason=count_scaling_overflow; result is unmeasured",
                    self.events[index].name
                );
                self.fail_group(PerfFailureStage::GroupRead, EOVERFLOW);
                return self.report();
            };
            self.events[index].result = PerfCounterResult {
                count: Some(count),
                errno: None,
                failure: None,
            };
        }
        for group_position in 0..self.group_len {
            self.close_event(self.group_indices[group_position]);
        }
        self.group_len = 0;
        self.report()
    }

    fn report(&self) -> PerfReport {
        PerfReport {
            cycles: self.events[0].result,
            cache_references: self.events[1].result,
            cache_misses: self.events[2].result,
        }
    }

    fn mark_failure(&mut self, index: usize, stage: PerfFailureStage, errno: i32) {
        self.events[index].result = PerfCounterResult::unavailable(stage, errno);
        eprintln!(
            "PERF_MEASUREMENT_FAILURE event={} stage={} errno={errno}; result is unmeasured",
            self.events[index].name,
            stage.name()
        );
    }

    fn fail_group(&mut self, stage: PerfFailureStage, errno: i32) {
        for group_position in 0..self.group_len {
            self.mark_failure(self.group_indices[group_position], stage, errno);
        }
        for group_position in 0..self.group_len {
            self.close_event(self.group_indices[group_position]);
        }
        self.group_len = 0;
    }

    fn close_event(&mut self, index: usize) {
        let fd = self.events[index].fd;
        if fd < 0 {
            return;
        }
        // SAFETY: this slot owns the fd and marks it closed before returning;
        // close is never retried because the numeric fd may be reused.
        let result = unsafe { close(fd) };
        self.events[index].fd = -1;
        if result != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            self.events[index].result =
                PerfCounterResult::unavailable(PerfFailureStage::Close, errno);
            eprintln!(
                "PERF_MEASUREMENT_FAILURE event={} stage=close errno={errno}; result is unmeasured",
                self.events[index].name,
            );
        }
    }

    pub fn syscall_number() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "298"
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            "not_applicable"
        }
    }

    pub fn attr_size() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "136"
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            "not_applicable"
        }
    }
}

impl Drop for PerfEventSet {
    fn drop(&mut self) {
        // Use the same one-shot close path so cleanup failures are loud and
        // every attempted fd is invalidated even while unwinding.
        for index in 0..self.events.len() {
            self.close_event(index);
        }
    }
}

fn scale_perf_count(raw_count: u64, time_enabled: u64, time_running: u64) -> Option<u64> {
    if time_enabled == 0 || time_running == 0 || time_running > time_enabled {
        return None;
    }
    let scaled = u128::from(raw_count)
        .checked_mul(u128::from(time_enabled))?
        .checked_div(u128::from(time_running))?;
    u64::try_from(scaled).ok()
}

pub fn format_cache_miss_rate(report: PerfReport) -> String {
    report
        .cache_miss_rate_percent()
        .map_or_else(|| "unmeasured".to_owned(), |value| format!("{value:.6}"))
}

pub fn format_cycles_per_packet(report: PerfReport, packets: u64) -> String {
    report
        .cycles_per_packet(packets)
        .map_or_else(|| "unmeasured".to_owned(), |value| format!("{value:.3}"))
}

const CPU_SET_WORDS: usize = 16;
const CPU_SET_BITS: usize = CPU_SET_WORDS * u64::BITS as usize;

#[repr(C)]
#[derive(Clone, Copy)]
struct CpuSet {
    bits: [u64; CPU_SET_WORDS],
}

impl Default for CpuSet {
    fn default() -> Self {
        Self {
            bits: [0; CPU_SET_WORDS],
        }
    }
}

impl CpuSet {
    fn set(&mut self, cpu: usize) {
        self.bits[cpu / 64] |= 1_u64 << (cpu % 64);
    }

    fn contains(&self, cpu: usize) -> bool {
        cpu < CPU_SET_BITS && self.bits[cpu / 64] & (1_u64 << (cpu % 64)) != 0
    }

    fn is_singleton(&self, cpu: usize) -> bool {
        self.contains(cpu) && self.bits.iter().map(|word| word.count_ones()).sum::<u32>() == 1
    }
}

#[derive(Debug)]
pub struct AffinityReport {
    pub selected_cpu: usize,
    pub selection_source: &'static str,
    pub set_ok: bool,
    pub get_ok: bool,
    pub verified: bool,
    pub current_cpu: Option<usize>,
    pub observed_mask: String,
    pub set_errno: Option<i32>,
    pub get_errno: Option<i32>,
}

pub fn configure_receiver_affinity() -> AffinityReport {
    let (selected_cpu, selection_source) = match env::var("RUSTER_THROUGHPUT_CPU") {
        Ok(value) => {
            let cpu = value.parse::<usize>().unwrap_or_else(|_| {
                panic!("RUSTER_THROUGHPUT_CPU must be an unsigned integer, got {value:?}")
            });
            (cpu, "environment")
        }
        Err(env::VarError::NotPresent) => match current_cpu() {
            Some(cpu) => (cpu, "current_cpu"),
            None => (0, "cpu_0_fallback"),
        },
        Err(env::VarError::NotUnicode(_)) => {
            panic!("RUSTER_THROUGHPUT_CPU is not valid UTF-8")
        }
    };

    let mut requested = CpuSet::default();
    let mut set_errno = None;
    let set_ok = if selected_cpu >= CPU_SET_BITS {
        set_errno = Some(EINVAL);
        false
    } else {
        requested.set(selected_cpu);
        // SAFETY: `requested` is an initialized Linux CPU mask with the exact
        // byte length passed to sched_setaffinity; pid 0 means this thread.
        let result =
            unsafe { sched_setaffinity(0, size_of::<CpuSet>(), &requested as *const CpuSet) };
        if result == 0 {
            true
        } else {
            set_errno = Some(last_errno());
            false
        }
    };
    if !set_ok {
        eprintln!(
            "MEASUREMENT_WARNING component=cpu_affinity stage=sched_setaffinity errno={}",
            set_errno.unwrap_or(-1)
        );
    }

    let mut observed = CpuSet::default();
    // SAFETY: `observed` is writable for exactly the CPU mask extent supplied
    // to sched_getaffinity, and pid 0 selects this receiver thread.
    let get_result =
        unsafe { sched_getaffinity(0, size_of::<CpuSet>(), &mut observed as *mut CpuSet) };
    let get_errno = if get_result == 0 {
        None
    } else {
        let errno = last_errno();
        eprintln!(
            "MEASUREMENT_WARNING component=cpu_affinity stage=sched_getaffinity errno={errno}"
        );
        Some(errno)
    };
    let get_ok = get_errno.is_none();
    let current_cpu = current_cpu();
    if current_cpu.is_none() {
        eprintln!(
            "MEASUREMENT_WARNING component=cpu_affinity stage=sched_getcpu errno={}",
            last_errno()
        );
    }
    let verified = set_ok && get_ok && observed.is_singleton(selected_cpu);
    if !verified {
        eprintln!(
            "MEASUREMENT_WARNING component=cpu_affinity status=unmeasured selected_cpu={selected_cpu}"
        );
    }
    AffinityReport {
        selected_cpu,
        selection_source,
        set_ok,
        get_ok,
        verified,
        current_cpu,
        observed_mask: if get_ok {
            format_cpu_mask(&observed)
        } else {
            "unknown".to_owned()
        },
        set_errno,
        get_errno,
    }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn current_cpu() -> Option<usize> {
    // SAFETY: sched_getcpu has no pointer arguments and only queries this
    // thread's current CPU.
    let cpu = unsafe { sched_getcpu() };
    if cpu < 0 {
        None
    } else {
        usize::try_from(cpu).ok()
    }
}

fn format_cpu_mask(mask: &CpuSet) -> String {
    let mut result = String::new();
    let mut range_start = None;
    let mut previous = 0_usize;
    for cpu in 0..CPU_SET_BITS {
        if mask.contains(cpu) {
            if range_start.is_none() {
                range_start = Some(cpu);
            }
            previous = cpu;
        } else if let Some(start) = range_start.take() {
            append_cpu_range(&mut result, start, previous);
        }
    }
    if let Some(start) = range_start {
        append_cpu_range(&mut result, start, previous);
    }
    if result.is_empty() {
        "empty".to_owned()
    } else {
        result
    }
}

fn append_cpu_range(result: &mut String, start: usize, end: usize) {
    if !result.is_empty() {
        result.push(',');
    }
    if start == end {
        result.push_str(&start.to_string());
    } else {
        result.push_str(&start.to_string());
        result.push('-');
        result.push_str(&end.to_string());
    }
}

#[derive(Debug)]
pub struct Observation {
    pub value: String,
    pub measured: bool,
    pub not_applicable: bool,
}

impl Observation {
    fn measured(value: String) -> Self {
        Self {
            value,
            measured: true,
            not_applicable: false,
        }
    }

    fn not_applicable() -> Self {
        Self {
            value: "not_applicable".to_owned(),
            measured: false,
            not_applicable: true,
        }
    }

    fn unmeasured_value(errno: i32) -> Self {
        Self {
            value: format!("unmeasured_errno_{errno}"),
            measured: false,
            not_applicable: false,
        }
    }

    pub fn status(&self) -> &'static str {
        if self.measured {
            "measured"
        } else if self.not_applicable {
            "not_applicable"
        } else {
            "unmeasured"
        }
    }

    pub fn is_unmeasured(&self) -> bool {
        !self.measured && !self.not_applicable
    }
}

#[derive(Debug)]
pub struct SystemConditions {
    pub affinity: AffinityReport,
    pub numa_node: Observation,
    pub irq_count: Observation,
    pub irq_affinity: Observation,
    pub irq_affinity_verified: bool,
    pub irq_affinity_verification: String,
    pub rss_queue_count: Observation,
    pub rss_queue_verified: bool,
    pub rss_queue_verification: String,
    #[allow(dead_code)]
    pub rss_indirection_table_size: Option<usize>,
}

pub fn read_system_conditions(interface: &str, affinity: AffinityReport) -> SystemConditions {
    let selected_cpu = affinity.selected_cpu;
    let (irq_count, irq_affinity) = read_irq_data(interface);
    let (irq_affinity_verified, irq_affinity_verification) =
        verify_irq_affinity(&irq_count, &irq_affinity);
    let rss_queue_count = read_rss_queue_count(interface);
    let (rss_queue_verified, rss_queue_verification, rss_indirection_table_size) =
        verify_rss_queues(interface, &rss_queue_count);
    SystemConditions {
        affinity,
        numa_node: read_numa_node(selected_cpu),
        irq_count,
        irq_affinity,
        irq_affinity_verified,
        irq_affinity_verification,
        rss_queue_count,
        rss_queue_verified,
        rss_queue_verification,
        rss_indirection_table_size,
    }
}

fn read_numa_node(cpu: usize) -> Observation {
    let entries = match fs::read_dir("/sys/devices/system/node") {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Observation::not_applicable();
        }
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(-1);
            eprintln!("MEASUREMENT_WARNING component=numa stage=read_node_directory errno={errno}");
            return Observation::unmeasured_value(errno);
        }
    };
    let mut node_count = 0_usize;
    let mut first_error = None;
    for entry in entries {
        let Ok(entry) = entry else {
            let errno = -EIO;
            first_error.get_or_insert(errno);
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(node_number) = name.strip_prefix("node") else {
            continue;
        };
        if node_number.is_empty() || !node_number.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        node_count += 1;
        let path = format!("/sys/devices/system/node/{name}/cpulist");
        match fs::read_to_string(path) {
            Ok(cpulist) if cpu_list_contains(&cpulist, cpu) => {
                return Observation::measured(node_number.to_owned());
            }
            Ok(_) => {}
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(-1);
                first_error.get_or_insert(errno);
            }
        }
    }
    if node_count == 0 {
        return Observation::not_applicable();
    }
    let errno = first_error.unwrap_or(ENODEV);
    eprintln!("MEASUREMENT_WARNING component=numa stage=cpu_node_lookup errno={errno} cpu={cpu}");
    Observation::unmeasured_value(errno)
}

fn cpu_list_contains(cpulist: &str, cpu: usize) -> bool {
    let Ok(cpu) = u64::try_from(cpu) else {
        return false;
    };
    for item in cpulist.trim().split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (start, end) = match item.split_once('-') {
            Some((start, end)) => {
                let Ok(start) = start.trim().parse::<u64>() else {
                    continue;
                };
                let Ok(end) = end.trim().parse::<u64>() else {
                    continue;
                };
                (start, end)
            }
            None => {
                let Ok(single) = item.parse::<u64>() else {
                    continue;
                };
                (single, single)
            }
        };
        if start <= cpu && cpu <= end {
            return true;
        }
    }
    false
}

fn read_irq_data(interface: &str) -> (Observation, Observation) {
    let mut irq_numbers = Vec::<u32>::new();
    let msi_path = format!("/sys/class/net/{interface}/device/msi_irqs");
    match fs::read_dir(&msi_path) {
        Ok(entries) => {
            for entry in entries {
                let Ok(entry) = entry else {
                    let observation = Observation::unmeasured_value(-EIO);
                    return (observation, Observation::unmeasured_value(-EIO));
                };
                if let Ok(irq) = entry.file_name().to_string_lossy().parse::<u32>() {
                    irq_numbers.push(irq);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(-1);
            eprintln!(
                "MEASUREMENT_WARNING component=irq stage=read_msi_irqs errno={errno} interface={interface}"
            );
            let observation = Observation::unmeasured_value(errno);
            return (observation, Observation::unmeasured_value(errno));
        }
    }
    if irq_numbers.is_empty() {
        match fs::read_to_string("/proc/interrupts") {
            Ok(interrupts) => {
                let interface_prefix = format!("{interface}-");
                for line in interrupts.lines() {
                    let mut fields = line.split_whitespace();
                    let Some(irq_field) = fields.next() else {
                        continue;
                    };
                    let Some(irq_text) = irq_field.strip_suffix(':') else {
                        continue;
                    };
                    let Ok(irq) = irq_text.parse::<u32>() else {
                        continue;
                    };
                    if fields
                        .any(|field| field == interface || field.starts_with(&interface_prefix))
                    {
                        irq_numbers.push(irq);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(-1);
                eprintln!(
                    "MEASUREMENT_WARNING component=irq stage=read_proc_interrupts errno={errno} interface={interface}"
                );
                let observation = Observation::unmeasured_value(errno);
                return (observation, Observation::unmeasured_value(errno));
            }
        }
    }
    irq_numbers.sort_unstable();
    irq_numbers.dedup();
    if irq_numbers.is_empty() {
        return (Observation::not_applicable(), Observation::not_applicable());
    }

    let mut affinities = Vec::with_capacity(irq_numbers.len());
    for irq in &irq_numbers {
        let path = format!("/proc/irq/{irq}/smp_affinity_list");
        match fs::read_to_string(path) {
            Ok(value) if !value.trim().is_empty() => {
                affinities.push(format!("{irq}:{}", value.trim()));
            }
            Ok(_) => {
                let observation = Observation::unmeasured_value(-EINVAL);
                return (observation, Observation::unmeasured_value(-EINVAL));
            }
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(-1);
                eprintln!(
                    "MEASUREMENT_WARNING component=irq stage=read_smp_affinity_list errno={errno} irq={irq}"
                );
                let observation = Observation::unmeasured_value(errno);
                return (observation, Observation::unmeasured_value(errno));
            }
        }
    }
    (
        Observation::measured(irq_numbers.len().to_string()),
        Observation::measured(affinities.join(";")),
    )
}

fn verify_irq_affinity(irq_count: &Observation, irq_affinity: &Observation) -> (bool, String) {
    if !irq_count.measured || !irq_affinity.measured {
        return (false, "irq_affinity_data_not_measured".to_owned());
    }
    let expected_count = match irq_count.value.parse::<usize>() {
        Ok(value) if value > 0 => value,
        _ => return (false, "irq_count_value_invalid".to_owned()),
    };
    let mut observed_count = 0_usize;
    for entry in irq_affinity.value.split(';') {
        let Some((irq, mask)) = entry.split_once(':') else {
            return (false, "irq_affinity_entry_malformed".to_owned());
        };
        if irq.parse::<u32>().is_err() || parse_singleton_cpu_mask(mask).is_none() {
            return (false, format!("irq_affinity_not_fixed_single_cpu:{entry}"));
        }
        observed_count = observed_count
            .checked_add(1)
            .expect("IRQ affinity entry counter overflowed");
    }
    if observed_count != expected_count {
        return (
            false,
            format!(
                "irq_affinity_entry_count_mismatch:expected={expected_count}:observed={observed_count}"
            ),
        );
    }
    (
        true,
        format!("all_{observed_count}_irq_masks_fixed_to_single_cpu"),
    )
}

fn parse_singleton_cpu_mask(mask: &str) -> Option<usize> {
    let mut selected = None;
    for part in mask.trim().split(',') {
        if part.is_empty() {
            continue;
        }
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => {
                let start = start.trim().parse::<usize>().ok()?;
                let end = end.trim().parse::<usize>().ok()?;
                (start, end)
            }
            None => {
                let cpu = part.trim().parse::<usize>().ok()?;
                (cpu, cpu)
            }
        };
        if start != end || selected.replace(start).is_some() {
            return None;
        }
    }
    selected
}

fn read_rss_queue_count(interface: &str) -> Observation {
    match read_rx_queue_indices(interface) {
        Ok(None) => {
            // Interfaces without a real device (for example loopback and
            // veth) must not turn their synthetic queue directory into
            // hardware RSS evidence.
            Observation::not_applicable()
        }
        Ok(Some(queues)) if queues.is_empty() => Observation::not_applicable(),
        Ok(Some(queues)) => Observation::measured(queues.len().to_string()),
        Err(errno) => {
            eprintln!(
                "MEASUREMENT_WARNING component=rss stage=read_queue_directory errno={errno} interface={interface}"
            );
            Observation::unmeasured_value(errno)
        }
    }
}

fn read_rx_queue_indices(interface: &str) -> Result<Option<Vec<usize>>, i32> {
    let device_path = format!("/sys/class/net/{interface}/device");
    match fs::metadata(&device_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.raw_os_error().unwrap_or(-1)),
    }
    let path = format!("/sys/class/net/{interface}/queues");
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.raw_os_error().unwrap_or(-1)),
    };
    let mut queues = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| -EIO)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(number) = name.strip_prefix("rx-") else {
            continue;
        };
        if !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()) {
            if let Ok(index) = number.parse::<usize>() {
                queues.push(index);
            }
        }
    }
    queues.sort_unstable();
    queues.dedup();
    Ok(Some(queues))
}

fn verify_rss_queues(interface: &str, queue_count: &Observation) -> (bool, String, Option<usize>) {
    if !queue_count.measured {
        return (false, "rss_rx_queue_count_not_measured".to_owned(), None);
    }
    let Ok(Some(queues)) = read_rx_queue_indices(interface) else {
        return (
            false,
            "rss_rx_queue_directory_not_readable".to_owned(),
            None,
        );
    };
    if queues.is_empty() {
        return (false, "rss_has_no_rx_queues".to_owned(), None);
    }
    let table = match read_ethtool_rss_indirection(interface) {
        Ok(table) => table,
        Err(errno) => {
            eprintln!(
                "MEASUREMENT_WARNING component=rss stage=read_indirection_table errno={errno} interface={interface}"
            );
            return (
                false,
                format!("ethtool_grxfhindir_failed_errno_{errno}"),
                None,
            );
        }
    };
    if table.is_empty() {
        return (false, "rss_indirection_table_is_empty".to_owned(), Some(0));
    }
    if table
        .iter()
        .any(|queue| !queues.binary_search(queue).is_ok())
    {
        return (
            false,
            "rss_indirection_table_points_to_unknown_rx_queue".to_owned(),
            Some(table.len()),
        );
    }
    (
        true,
        format!("ethtool_grxfhindir_verified_entries_{}", table.len()),
        Some(table.len()),
    )
}

#[repr(C)]
struct Ifreq {
    ifr_name: [c_char; IFNAMSIZ],
    ifr_data: *mut c_void,
    // `struct ifreq.ifr_ifru` is a 24-byte union on the Linux x86_64 ABI.
    // `ifr_data` is the only member used by the SIOCETHTOOL path; preserve the
    // rest of the union extent so the ioctl receives the complete object.
    _ifr_ifru_padding: [u8; 16],
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const _: () = {
    assert!(size_of::<Ifreq>() == 40);
    assert!(offset_of!(Ifreq, ifr_name) == 0);
    assert!(offset_of!(Ifreq, ifr_data) == 16);
    assert!(offset_of!(Ifreq, _ifr_ifru_padding) == 24);
};

fn read_ethtool_rss_indirection(interface: &str) -> Result<Vec<usize>, i32> {
    let fd = unsafe {
        // SAFETY: socket has no pointer arguments; the returned descriptor is
        // owned by this function and is closed before it returns.
        socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)
    };
    if fd < 0 {
        return Err(last_errno());
    }

    let mut query = [ETHTOOL_GRXFHINDIR, 0_u32];
    let query_result = ethtool_ioctl(interface, fd, query.as_mut_ptr().cast::<c_void>());
    query_result.inspect_err(|_| {
        // SAFETY: `fd` is the descriptor returned by the preceding socket
        // call and is owned exclusively here.
        let _ = unsafe { close(fd) };
    })?;
    let table_size = usize::try_from(query[1]).map_err(|_| EOVERFLOW)?;
    if table_size == 0 || table_size > MAX_RSS_INDIRECTION_ENTRIES {
        // SAFETY: `fd` is the descriptor returned by socket and is closed at
        // every return path after ownership was established.
        let _ = unsafe { close(fd) };
        return Err(EIO);
    }

    // `ethtool_rxfh_indir` has a two-word header followed by a flexible
    // array.  The kernel writes only within this fixed, pre-sized request.
    let mut request = vec![0_u32; table_size + 2];
    request[0] = ETHTOOL_GRXFHINDIR;
    request[1] = query[1];
    let request_result = ethtool_ioctl(interface, fd, request.as_mut_ptr().cast::<c_void>());
    // SAFETY: `fd` is the descriptor returned by socket and remains owned by
    // this function until this final close.
    let close_result = unsafe { close(fd) };
    request_result?;
    if close_result != 0 {
        return Err(last_errno());
    }
    let observed_size = usize::try_from(request[1]).map_err(|_| EOVERFLOW)?;
    if observed_size == 0 || observed_size > table_size {
        return Err(EIO);
    }
    Ok(request[2..2 + observed_size]
        .iter()
        .map(|value| usize::try_from(*value).expect("RSS queue index fits usize"))
        .collect())
}

fn ethtool_ioctl(interface: &str, fd: RawFd, data: *mut c_void) -> Result<(), i32> {
    let mut ifreq = Ifreq {
        ifr_name: [0; IFNAMSIZ],
        ifr_data: data,
        _ifr_ifru_padding: [0; 16],
    };
    for (slot, byte) in ifreq
        .ifr_name
        .iter_mut()
        .zip(interface.as_bytes().iter().copied())
    {
        *slot = byte as c_char;
    }
    // SAFETY: `ifreq` and the pointed-to ethtool request remain initialized
    // and live for the synchronous ioctl; the driver writes only the UAPI
    // response fields in that request.
    let result = unsafe { ioctl(fd, SIOCETHTOOL, &mut ifreq as *mut Ifreq) };
    if result < 0 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

pub fn read_perf_event_paranoid() -> String {
    fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .ok()
        .map_or_else(|| "unknown".to_owned(), |value| value.trim().to_owned())
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct HardwareAcceptanceReport {
    pub hardware_acceptance: bool,
    pub blockers: Vec<String>,
    pub blocker_tokens: Vec<&'static str>,
}

impl HardwareAcceptanceReport {
    #[allow(dead_code)]
    pub fn blockers_value(&self) -> String {
        if self.blockers.is_empty() {
            "none".to_owned()
        } else {
            self.blockers.join("; ")
        }
    }

    #[allow(dead_code)]
    pub fn blocker_tokens_value(&self) -> String {
        if self.blocker_tokens.is_empty() {
            "none".to_owned()
        } else {
            self.blocker_tokens.join(",")
        }
    }

    #[allow(dead_code)]
    pub fn blockers_detail(&self) -> String {
        self.blockers_value()
    }
}

fn nic_blocker_tokens(nic: &NicInspection) -> Vec<&'static str> {
    let mut tokens = Vec::with_capacity(nic.blockers.len() + 2);
    if nic.link_speed_raw == "invalid_interface" {
        push_unique_token(&mut tokens, TOKEN_NIC_INTERFACE_INVALID);
        return tokens;
    }
    if !nic.device_present {
        push_unique_token(&mut tokens, TOKEN_NIC_DEVICE_MISSING);
    }
    match nic.driver.as_deref() {
        Some(_) if nic.driver_is_virtual => {
            push_unique_token(&mut tokens, TOKEN_NIC_DRIVER_VIRTUAL);
        }
        Some(_) => {}
        None => push_unique_token(&mut tokens, TOKEN_NIC_DRIVER_UNKNOWN),
    }
    match nic.link_speed_mbps {
        Some(speed) if speed > 0 => {
            if speed < MIN_HARDWARE_ACCEPTANCE_LINK_SPEED_MBPS {
                push_unique_token(&mut tokens, TOKEN_LINK_SPEED_BELOW_THRESHOLD);
            }
        }
        Some(_) => push_unique_token(&mut tokens, TOKEN_LINK_SPEED_UNKNOWN),
        None if nic.link_speed_raw == "unknown" => {
            push_unique_token(&mut tokens, TOKEN_LINK_SPEED_READ_ERROR);
        }
        None => push_unique_token(&mut tokens, TOKEN_LINK_SPEED_INVALID),
    }
    tokens
}

fn push_unique_token(tokens: &mut Vec<&'static str>, token: &'static str) {
    if !tokens.contains(&token) {
        tokens.push(token);
    }
}

fn measurement_status_token(nic: &NicInspection) -> &'static str {
    if acceptance_measurement_skip_reason(nic).is_some() {
        TOKEN_MEASUREMENT_SKIPPED
    } else {
        TOKEN_MEASUREMENT_ERROR
    }
}

/// Apply the complete hardware-acceptance gate to read-only NIC evidence and
/// the measurements collected by a harness.  Every failed predicate adds an
/// explanatory blocker; the caller must not turn an unavailable value into a
/// silent skip.
pub fn evaluate_hardware_acceptance(
    nic: &NicInspection,
    latency: &LatencySummary,
    perf: PerfReport,
    conditions: &SystemConditions,
    measurement_status: Option<&str>,
) -> HardwareAcceptanceReport {
    let mut blockers = Vec::with_capacity(10);
    let mut blocker_tokens = nic_blocker_tokens(nic);
    for blocker in &nic.blockers {
        push_unique_blocker(&mut blockers, blocker.clone());
    }
    if !nic.physical_verdict && nic.blockers.is_empty() {
        push_unique_blocker(
            &mut blockers,
            "physical NIC の read-only 判定を完了できない".to_owned(),
        );
        push_unique_token(&mut blocker_tokens, TOKEN_NIC_PHYSICAL_GATE_UNMET);
    }
    if !nic.link_speed_at_least_acceptance_threshold()
        && nic.link_speed_mbps.is_some_and(|speed| speed > 0)
    {
        let speed = nic.link_speed_mbps.expect("positive speed was checked");
        push_unique_blocker(
            &mut blockers,
            format!(
                "link speed {speed} Mbps は基準 {MIN_HARDWARE_ACCEPTANCE_LINK_SPEED_MBPS} Mbps 未満"
            ),
        );
        push_unique_token(&mut blocker_tokens, TOKEN_LINK_SPEED_BELOW_THRESHOLD);
    }

    if !conditions.affinity.verified {
        push_unique_blocker(
            &mut blockers,
            format!(
                "CPU pinning が sched_getaffinity で検証されていない (set_ok={} get_ok={} mask={})",
                conditions.affinity.set_ok,
                conditions.affinity.get_ok,
                conditions.affinity.observed_mask
            ),
        );
        push_unique_token(&mut blocker_tokens, TOKEN_CPU_AFFINITY_NOT_VERIFIED);
    }
    if !conditions.irq_affinity_verified {
        push_unique_blocker(
            &mut blockers,
            format!(
                "IRQ affinity が固定・検証されていない ({})",
                conditions.irq_affinity_verification
            ),
        );
        push_unique_token(&mut blocker_tokens, TOKEN_IRQ_AFFINITY_NOT_VERIFIED);
    }
    if !conditions.rss_queue_verified {
        push_unique_blocker(
            &mut blockers,
            format!(
                "RSS queue が設定・検証されていない ({})",
                conditions.rss_queue_verification
            ),
        );
        push_unique_token(&mut blocker_tokens, TOKEN_RSS_QUEUE_NOT_VERIFIED);
    }
    if !perf.cycles.measured() {
        push_unique_blocker(
            &mut blockers,
            format!(
                "perf cycles が measured ではない ({})",
                perf.cycles.status()
            ),
        );
        push_unique_token(&mut blocker_tokens, TOKEN_PERF_CYCLES_NOT_MEASURED);
    }
    if !perf.cache_misses.measured() {
        push_unique_blocker(
            &mut blockers,
            format!(
                "perf cache misses が measured ではない ({})",
                perf.cache_misses.status()
            ),
        );
        push_unique_token(&mut blocker_tokens, TOKEN_PERF_CACHE_MISSES_NOT_MEASURED);
    }
    if latency.samples < MIN_SAMPLES_P99_9 || latency.p99_9_ns.is_none() {
        push_unique_blocker(
            &mut blockers,
            format!(
                "latency サンプル数不足: {} (p99.9 に必要な最小値 {})",
                latency.samples, MIN_SAMPLES_P99_9
            ),
        );
        push_unique_token(&mut blocker_tokens, TOKEN_LATENCY_SAMPLES_INSUFFICIENT);
    }
    if let Some(status) = measurement_status {
        push_unique_blocker(&mut blockers, format!("acceptance 測定状態: {status}"));
        push_unique_token(&mut blocker_tokens, measurement_status_token(nic));
    }

    HardwareAcceptanceReport {
        hardware_acceptance: blockers.is_empty(),
        blockers,
        blocker_tokens,
    }
}

fn push_unique_blocker(blockers: &mut Vec<String>, blocker: String) {
    if !blockers.iter().any(|existing| existing == &blocker) {
        blockers.push(blocker);
    }
}

pub fn unmeasured_fields(
    latency: &LatencySummary,
    perf: PerfReport,
    packets: u64,
    conditions: &SystemConditions,
) -> String {
    let mut fields = Vec::with_capacity(12);
    if !latency.percentiles_complete() {
        fields.push("latency_percentiles");
    }
    if perf.cycles_per_packet(packets).is_none() {
        fields.push("cycles_per_packet");
    }
    if !perf.cache_misses.measured() {
        fields.push("cache_misses");
    }
    if !perf.cache_references.measured() {
        fields.push("cache_references");
    }
    if perf.cache_miss_rate_percent().is_none() {
        fields.push("cache_miss_rate");
    }
    if !conditions.affinity.verified {
        fields.push("cpu_affinity");
    }
    if conditions.numa_node.is_unmeasured() {
        fields.push("numa_node");
    }
    if conditions.irq_count.is_unmeasured() {
        fields.push("irq_count");
    }
    if conditions.irq_affinity.is_unmeasured() {
        fields.push("irq_affinity");
    }
    if conditions.rss_queue_count.is_unmeasured() {
        fields.push("rss_queue_count");
    }
    // This test creates a veth pair and therefore can never be a physical-NIC
    // acceptance run, regardless of whether optional counters are available.
    fields.push("physical_NIC_acceptance");
    fields.join(",")
}

// SAFETY: each declaration below is a Linux/POSIX ABI boundary, and every
// call site supplies initialized pointers with a lifetime covering the call.
unsafe extern "C" {
    fn clock_gettime(clock_id: c_int, time: *mut Timespec) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn read(fd: c_int, buffer: *mut c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn sched_setaffinity(pid: c_int, cpusetsize: usize, mask: *const CpuSet) -> c_int;
    fn sched_getaffinity(pid: c_int, cpusetsize: usize, mask: *mut CpuSet) -> c_int;
    fn sched_getcpu() -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn siocethtool_ifreq_matches_linux_x86_64_abi_size() {
        assert_eq!(size_of::<Ifreq>(), 40);
    }

    #[test]
    fn generated_physical_and_veth_record_lines_are_machine_parseable() {
        let nic = NicInspection {
            device_present: true,
            driver: Some("virtio_net".to_owned()),
            driver_is_virtual: true,
            link_speed_mbps: Some(-1),
            link_speed_raw: "-1".to_owned(),
            physical_verdict: false,
            blockers: vec![
                "virtio_net は仮想ドライバ".to_owned(),
                "link speed 不明 (-1)".to_owned(),
            ],
        };
        let conditions = SystemConditions {
            affinity: AffinityReport {
                selected_cpu: 0,
                selection_source: "test",
                set_ok: false,
                get_ok: false,
                verified: false,
                current_cpu: None,
                observed_mask: "unknown".to_owned(),
                set_errno: Some(EINVAL),
                get_errno: Some(EINVAL),
            },
            numa_node: Observation::not_applicable(),
            irq_count: Observation::not_applicable(),
            irq_affinity: Observation::not_applicable(),
            irq_affinity_verified: false,
            irq_affinity_verification: "irq_affinity_data_not_measured".to_owned(),
            rss_queue_count: Observation::not_applicable(),
            rss_queue_verified: false,
            rss_queue_verification: "rss_rx_queue_count_not_measured".to_owned(),
            rss_indirection_table_size: None,
        };
        let measurement_error = acceptance_measurement_skip_reason(&nic);
        let acceptance = evaluate_hardware_acceptance(
            &nic,
            &LatencyCollector::new().finish(),
            PerfReport::not_measured(),
            &conditions,
            measurement_error.as_deref(),
        );
        let physical_measurement = format!(
            "measurement_kind=physical_nic_acceptance hardware_acceptance={} measurement_error={}",
            acceptance.hardware_acceptance,
            acceptance_measurement_error_token(&nic, measurement_error.as_deref()),
        );
        let physical_blockers = format!(
            "acceptance_blockers_count={} acceptance_blockers={}",
            acceptance.blockers.len(),
            acceptance.blocker_tokens_value()
        );
        for line in [physical_measurement.as_str(), physical_blockers.as_str()] {
            assert_machine_readable_record_line(line);
        }
        assert_machine_readable_ascii_token_field(&physical_measurement, "measurement_error");
        assert_machine_readable_ascii_token_list_field(&physical_blockers, "acceptance_blockers");
        assert_eq!(
            physical_measurement
                .split_whitespace()
                .find_map(|token| token.strip_prefix("measurement_error="))
                .expect("generated physical record has measurement_error"),
            "nic_physical_precondition_unmet"
        );
    }

    #[test]
    fn nearest_rank_uses_rank_ceiling_and_explicit_minimums() {
        let samples = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(nearest_rank(&samples, 9, 10, MIN_SAMPLES_P90), Some(90));
        assert_eq!(nearest_rank(&samples, 99, 100, MIN_SAMPLES_P99), None);
        assert_eq!(nearest_rank(&[7, 8], 1, 2, MIN_SAMPLES_P50), Some(7));
    }

    #[test]
    fn cpu_list_parser_handles_singletons_and_ranges() {
        assert!(cpu_list_contains("0-3,8,10-12\n", 0));
        assert!(cpu_list_contains("0-3,8,10-12\n", 11));
        assert!(!cpu_list_contains("0-3,8,10-12\n", 9));
    }

    #[test]
    fn perf_count_scaling_uses_checked_time_ratio() {
        assert_eq!(scale_perf_count(100, 3, 2), Some(150));
        assert_eq!(scale_perf_count(100, 1, 0), None);
        assert_eq!(scale_perf_count(100, 1, 2), None);
        assert_eq!(scale_perf_count(u64::MAX, u64::MAX, 1), None);
    }

    #[test]
    fn singleton_irq_masks_are_the_only_fixed_affinity_shape() {
        assert_eq!(parse_singleton_cpu_mask("7"), Some(7));
        assert_eq!(parse_singleton_cpu_mask("7\n"), Some(7));
        assert_eq!(parse_singleton_cpu_mask("7-7"), Some(7));
        assert_eq!(parse_singleton_cpu_mask("0-3"), None);
        assert_eq!(parse_singleton_cpu_mask("7,8"), None);
        assert_eq!(parse_singleton_cpu_mask(""), None);
    }

    #[test]
    fn acceptance_report_lists_each_missing_gate_with_a_reason() {
        let nic = NicInspection {
            device_present: true,
            driver: Some("virtio_net".to_owned()),
            driver_is_virtual: true,
            link_speed_mbps: Some(-1),
            link_speed_raw: "-1".to_owned(),
            physical_verdict: false,
            blockers: vec![
                "virtio_net は仮想ドライバ".to_owned(),
                "link speed 不明 (-1)".to_owned(),
            ],
        };
        let conditions = SystemConditions {
            affinity: AffinityReport {
                selected_cpu: 0,
                selection_source: "test",
                set_ok: false,
                get_ok: false,
                verified: false,
                current_cpu: None,
                observed_mask: "unknown".to_owned(),
                set_errno: Some(EINVAL),
                get_errno: Some(EINVAL),
            },
            numa_node: Observation::not_applicable(),
            irq_count: Observation::not_applicable(),
            irq_affinity: Observation::not_applicable(),
            irq_affinity_verified: false,
            irq_affinity_verification: "irq_affinity_data_not_measured".to_owned(),
            rss_queue_count: Observation::not_applicable(),
            rss_queue_verified: false,
            rss_queue_verification: "rss_rx_queue_count_not_measured".to_owned(),
            rss_indirection_table_size: None,
        };
        let report = evaluate_hardware_acceptance(
            &nic,
            &LatencyCollector::new().finish(),
            PerfReport::not_measured(),
            &conditions,
            acceptance_measurement_skip_reason(&nic).as_deref(),
        );
        assert!(!report.hardware_acceptance);
        for reason in [
            "virtio_net は仮想ドライバ",
            "link speed 不明 (-1)",
            "CPU pinning が sched_getaffinity で検証されていない",
            "IRQ affinity が固定・検証されていない",
            "RSS queue が設定・検証されていない",
            "perf cycles が measured ではない",
            "perf cache misses が measured ではない",
            "latency サンプル数不足",
            "NIC physical 前提未達",
            "link speed 前提未達",
            "測定未実施",
        ] {
            assert!(
                report
                    .blockers
                    .iter()
                    .any(|blocker| blocker.contains(reason)),
                "missing blocker reason: {reason}; actual={:?}",
                report.blockers
            );
        }
    }
}

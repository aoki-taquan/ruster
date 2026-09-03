use std::fmt;
use std::hint::black_box;
use std::time::{Duration, Instant};

use ruster_core::{
    forward_batch, internet_checksum, validate_ipv4_frame, ForwardingSnapshot, IfId, Interface,
    Ipv4Address, LocalIpv4Binding, MacAddress, Neighbor, NoTrace, PacketIo, Route,
};

use crate::{
    allocation_count, plain_ipv4_fixture, BenchBackend, BenchCompletion, FrameSize, ResultRow,
    SampleStats,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const GATEWAY_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 3]);
pub(crate) const MIN_AGGREGATE_REPETITIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suite {
    Smoke,
    Datapath,
    DeterministicSmoke,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunConfig {
    pub suite: Suite,
    pub seed: u64,
    pub samples: usize,
    pub sample_time: Duration,
    pub warmup_time: Duration,
    pub batches: Vec<usize>,
}

impl RunConfig {
    #[must_use]
    pub fn smoke() -> Self {
        Self {
            suite: Suite::Smoke,
            seed: 0x5eed_0200_0000_0001,
            samples: 5,
            sample_time: Duration::from_millis(5),
            warmup_time: Duration::from_millis(20),
            batches: vec![1, 32],
        }
    }

    #[must_use]
    pub fn datapath() -> Self {
        Self {
            suite: Suite::Datapath,
            seed: 0x5eed_0200_0000_0001,
            samples: 31,
            sample_time: Duration::from_millis(100),
            warmup_time: Duration::from_millis(250),
            batches: vec![1, 8, 32, 64, 256],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunError {
    NoSamples,
    ZeroSampleTime,
    ZeroBatch,
    RepetitionOverflow,
    SetupControlExceededMeasured { setup: Duration, measured: Duration },
    TimedAllocations { case: &'static str, count: u64 },
    AllocationInstrumentationUnavailable,
    InvalidDeterministicSeed { expected: u64, actual: u64 },
    UnexpectedBatchReport,
    ForwardingOracle,
    InvalidStatistics,
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSamples => formatter.write_str("sample count must be nonzero"),
            Self::ZeroSampleTime => formatter.write_str("sample time must be nonzero"),
            Self::ZeroBatch => formatter.write_str("batch sizes must be nonzero"),
            Self::RepetitionOverflow => formatter.write_str("adaptive repetition count overflowed"),
            Self::SetupControlExceededMeasured { setup, measured } => write!(
                formatter,
                "setup control ({setup:?}) exceeded measured interval ({measured:?})"
            ),
            Self::TimedAllocations { case, count } => {
                write!(formatter, "{case} allocated {count} times in timed regions")
            }
            Self::AllocationInstrumentationUnavailable => formatter.write_str(
                "allocation-free benchmark results require the ruster-bench counting allocator",
            ),
            Self::InvalidDeterministicSeed { expected, actual } => write!(
                formatter,
                "deterministic smoke seed must be {expected}, got {actual}"
            ),
            Self::UnexpectedBatchReport => {
                formatter.write_str("benchmark forwarding returned an unexpected batch report")
            }
            Self::ForwardingOracle => {
                formatter.write_str("benchmark forwarding output failed its untimed oracle")
            }
            Self::InvalidStatistics => formatter.write_str("sample statistics were invalid"),
        }
    }
}

impl std::error::Error for RunError {}

#[derive(Clone, Copy)]
pub(crate) struct Measurement {
    pub(crate) elapsed: Duration,
    pub(crate) allocations: u64,
    pub(crate) digest: u16,
}

/// Executes the selected NIC-free cases and returns structured result rows.
///
/// Formatting and artifact I/O are deliberately outside this function. The
/// timed and deterministic paths require the binary's [`crate::CountingAllocator`]
/// (or an equivalent process-wide installation) so an allocation-free result
/// cannot silently become a false zero in a downstream consumer.
pub fn run(config: &RunConfig) -> Result<Vec<ResultRow>, RunError> {
    if config.suite == Suite::DeterministicSmoke {
        require_allocation_instrumentation()?;
        if config.seed != crate::R17_DETERMINISTIC_SMOKE_SEED {
            return Err(RunError::InvalidDeterministicSeed {
                expected: crate::R17_DETERMINISTIC_SMOKE_SEED,
                actual: config.seed,
            });
        }
        return crate::matrix::run_deterministic_matrix(config);
    }
    require_allocation_instrumentation()?;
    validate_config(config)?;
    let rows_per_size = config
        .batches
        .len()
        .checked_mul(25)
        .and_then(|count| count.checked_add(2))
        .ok_or(RunError::RepetitionOverflow)?;
    let mut rows = Vec::with_capacity(
        FrameSize::ALL
            .len()
            .checked_mul(rows_per_size)
            .ok_or(RunError::RepetitionOverflow)?,
    );
    for size in FrameSize::ALL {
        for &batch in &config.batches {
            rows.push(run_plain_case(config, size, batch)?);
            rows.extend(crate::matrix::run_matrix(config, size, batch)?);
        }
        rows.push(run_checksum_case(config, size, 1)?);
        rows.push(run_checksum_case(config, size, 2)?);
    }
    Ok(rows)
}

fn validate_config(config: &RunConfig) -> Result<(), RunError> {
    if config.samples == 0 {
        return Err(RunError::NoSamples);
    }
    if config.sample_time.is_zero() {
        return Err(RunError::ZeroSampleTime);
    }
    if config.batches.contains(&0) {
        return Err(RunError::ZeroBatch);
    }
    Ok(())
}

fn run_plain_case(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
) -> Result<ResultRow, RunError> {
    let template = plain_ipv4_fixture(size, config.seed);
    let mut backend = BenchBackend::new(batch_size, LAN, &template);
    let routes = [Route::new(
        Ipv4Address::from_octets([0, 0, 0, 0]),
        0,
        WAN,
        Some(Ipv4Address::from_octets([203, 0, 113, 1])),
    )
    .expect("benchmark route is valid")];
    let interfaces = [
        Interface {
            id: LAN,
            mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
        },
    ];
    let neighbors = [Neighbor {
        interface: WAN,
        target: Ipv4Address::from_octets([203, 0, 113, 1]),
        mac: GATEWAY_MAC,
    }];
    let bindings = [LocalIpv4Binding {
        interface: LAN,
        address: Ipv4Address::from_octets([192, 0, 2, 1]),
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot is valid");

    warm_plain(
        &mut backend,
        &template,
        &snapshot,
        batch_size,
        config.warmup_time,
    )?;
    let repetitions = calibrate_plain(
        &mut backend,
        &template,
        &snapshot,
        batch_size,
        config.sample_time,
    )?;
    let mut normalized = Vec::with_capacity(config.samples);
    let mut allocations = 0;
    let mut digest = 0;
    for _ in 0..config.samples {
        let measurement =
            measure_plain(&mut backend, &template, &snapshot, batch_size, repetitions)?;
        allocations += measurement.allocations;
        digest = measurement.digest;
        let packets = repetitions
            .checked_mul(batch_size)
            .ok_or(RunError::RepetitionOverflow)?;
        normalized.push(measurement.elapsed.as_nanos() as f64 / packets as f64);
    }
    if allocations != 0 {
        return Err(RunError::TimedAllocations {
            case: "plain-ipv4",
            count: allocations,
        });
    }
    verify_forwarded(&backend, &template, batch_size)?;
    Ok(ResultRow {
        case: "plain-ipv4",
        size,
        batch: batch_size,
        checksum_passes: 0,
        seed: config.seed,
        repetitions_per_sample: repetitions,
        timed_allocations: allocations,
        stats: SampleStats::from_samples(&normalized).ok_or(RunError::InvalidStatistics)?,
        digest,
    })
}

fn warm_plain(
    backend: &mut BenchBackend,
    template: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    batch_size: usize,
    warmup_time: Duration,
) -> Result<(), RunError> {
    let started = Instant::now();
    while started.elapsed() < warmup_time {
        match measure_plain(
            backend,
            template,
            snapshot,
            batch_size,
            MIN_AGGREGATE_REPETITIONS,
        ) {
            Ok(measurement) => {
                ensure_no_allocations("plain-ipv4", measurement.allocations)?;
                black_box(measurement);
            }
            Err(RunError::SetupControlExceededMeasured { .. }) => {
                // A discarded warmup probe can be shorter than scheduler and
                // cache noise. Formal samples still propagate this typed
                // error rather than substituting zero.
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn calibrate_plain(
    backend: &mut BenchBackend,
    template: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    batch_size: usize,
    target: Duration,
) -> Result<usize, RunError> {
    let mut repetitions = MIN_AGGREGATE_REPETITIONS;
    loop {
        let measurement = match measure_plain(backend, template, snapshot, batch_size, repetitions)
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
        ensure_no_allocations("plain-ipv4", measurement.allocations)?;
        if measurement.elapsed >= target {
            return Ok(repetitions);
        }
        repetitions = repetitions
            .checked_mul(2)
            .ok_or(RunError::RepetitionOverflow)?;
    }
}

fn measure_plain(
    backend: &mut BenchBackend,
    template: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    batch_size: usize,
    repetitions: usize,
) -> Result<Measurement, RunError> {
    let setup_started = Instant::now();
    for _ in 0..repetitions {
        backend.reset(template);
        let batch = backend.receive(batch_size).expect("infallible backend");
        let _ = black_box(batch);
    }
    let setup_elapsed = setup_started.elapsed();

    let mut trace = NoTrace;
    let before_allocations = allocation_count();
    let measured_started = Instant::now();
    let mut last_report = None;
    for _ in 0..repetitions {
        backend.reset(template);
        let batch = backend.receive(batch_size).expect("infallible backend");
        last_report = Some(black_box(forward_batch(batch, snapshot, &mut trace)));
    }
    let measured_elapsed = measured_started.elapsed();
    let allocations = allocation_count() - before_allocations;
    let report = black_box(last_report).expect("repetitions are nonzero");
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
        return Err(RunError::UnexpectedBatchReport);
    }
    Ok(Measurement {
        elapsed: subtract_setup_control(setup_elapsed, measured_elapsed)?,
        allocations,
        digest: u16::try_from(report.tx_requested).unwrap_or(u16::MAX),
    })
}

pub(crate) fn subtract_setup_control(
    setup: Duration,
    measured: Duration,
) -> Result<Duration, RunError> {
    measured
        .checked_sub(setup)
        .ok_or(RunError::SetupControlExceededMeasured { setup, measured })
}

fn verify_forwarded(
    backend: &BenchBackend,
    template: &[u8],
    batch_size: usize,
) -> Result<(), RunError> {
    for index in 0..batch_size {
        if backend.completion(index) != Some(BenchCompletion::Transmitted(WAN)) {
            return Err(RunError::ForwardingOracle);
        }
        let bytes = backend.bytes(index).ok_or(RunError::ForwardingOracle)?;
        let ipv4 = validate_ipv4_frame(bytes).map_err(|_| RunError::ForwardingOracle)?;
        if bytes[0..6] != GATEWAY_MAC.0
            || bytes[6..12] != WAN_MAC.0
            || ipv4.ttl != 63
            || ipv4.source != Ipv4Address::from_octets([192, 0, 2, 10])
            || ipv4.destination != Ipv4Address::from_octets([198, 51, 100, 10])
            || bytes[34..] != template[34..]
        {
            return Err(RunError::ForwardingOracle);
        }
    }
    Ok(())
}

fn run_checksum_case(
    config: &RunConfig,
    size: FrameSize,
    passes: u8,
) -> Result<ResultRow, RunError> {
    let bytes = plain_ipv4_fixture(size, config.seed);
    warm_checksum(&bytes, passes, config.warmup_time)?;
    let repetitions = calibrate_checksum(&bytes, passes, config.sample_time)?;
    let mut normalized = Vec::with_capacity(config.samples);
    let mut allocations = 0;
    let mut digest = 0;
    for _ in 0..config.samples {
        let measurement = measure_checksum(&bytes, passes, repetitions);
        allocations += measurement.allocations;
        digest = measurement.digest;
        normalized.push(measurement.elapsed.as_nanos() as f64 / repetitions as f64);
    }
    let case = if passes == 1 {
        "checksum-once"
    } else {
        "checksum-twice"
    };
    if allocations != 0 {
        return Err(RunError::TimedAllocations {
            case,
            count: allocations,
        });
    }
    Ok(ResultRow {
        case,
        size,
        batch: 1,
        checksum_passes: passes,
        seed: config.seed,
        repetitions_per_sample: repetitions,
        timed_allocations: allocations,
        stats: SampleStats::from_samples(&normalized).ok_or(RunError::InvalidStatistics)?,
        digest,
    })
}

fn warm_checksum(bytes: &[u8], passes: u8, warmup_time: Duration) -> Result<(), RunError> {
    let started = Instant::now();
    while started.elapsed() < warmup_time {
        let measurement = measure_checksum(bytes, passes, 1);
        ensure_no_allocations("checksum-control", measurement.allocations)?;
        black_box(measurement);
    }
    Ok(())
}

fn calibrate_checksum(bytes: &[u8], passes: u8, target: Duration) -> Result<usize, RunError> {
    let mut repetitions = 1_usize;
    loop {
        let measurement = measure_checksum(bytes, passes, repetitions);
        ensure_no_allocations("checksum-control", measurement.allocations)?;
        if measurement.elapsed >= target {
            return Ok(repetitions);
        }
        repetitions = repetitions
            .checked_mul(2)
            .ok_or(RunError::RepetitionOverflow)?;
    }
}

pub(crate) fn ensure_no_allocations(case: &'static str, count: u64) -> Result<(), RunError> {
    if count == 0 {
        Ok(())
    } else {
        Err(RunError::TimedAllocations { case, count })
    }
}

pub(crate) fn require_allocation_instrumentation() -> Result<(), RunError> {
    if crate::allocation::allocation_instrumentation_available() {
        Ok(())
    } else {
        Err(RunError::AllocationInstrumentationUnavailable)
    }
}

fn measure_checksum(bytes: &[u8], passes: u8, repetitions: usize) -> Measurement {
    let before_allocations = allocation_count();
    let started = Instant::now();
    let mut digest = 0_u16;
    for _ in 0..repetitions {
        for _ in 0..passes {
            digest = black_box(internet_checksum(black_box(bytes)));
        }
    }
    let elapsed = started.elapsed();
    let allocations = allocation_count() - before_allocations;
    Measurement {
        elapsed,
        allocations,
        digest: black_box(digest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_configs_are_rejected_before_setup() {
        let mut config = RunConfig::smoke();
        config.samples = 0;
        assert_eq!(run(&config), Err(RunError::NoSamples));
        config.samples = 1;
        config.sample_time = Duration::ZERO;
        assert_eq!(run(&config), Err(RunError::ZeroSampleTime));
        config.sample_time = Duration::from_nanos(1);
        config.batches = vec![0];
        assert_eq!(run(&config), Err(RunError::ZeroBatch));
    }

    #[test]
    fn one_plain_iteration_passes_the_untimed_wire_oracle() {
        let mut config = RunConfig::smoke();
        config.samples = 1;
        config.sample_time = Duration::from_micros(100);
        config.warmup_time = Duration::ZERO;
        config.batches = vec![1];
        let rows = run(&config).unwrap();
        assert_eq!(rows.len(), 54);
        assert!(rows.iter().all(|row| row.timed_allocations == 0));
        assert!(rows.iter().any(|row| {
            row.case == "plain-ipv4" && row.size == FrameSize::Wire64 && row.stats.samples == 1
        }));
    }

    #[test]
    fn checksum_control_matches_an_independent_known_answer() {
        // RFC 1071-style four-word example:
        // 0001 + f203 + f4f5 + f6f7 = ddf2 after carry folding.
        let bytes = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let once = measure_checksum(&bytes, 1, 3);
        let twice = measure_checksum(&bytes, 2, 3);
        assert_eq!(once.digest, 0x220d);
        assert_eq!(twice.digest, once.digest);
        assert_eq!(internet_checksum(&bytes), 0x220d);
    }

    #[test]
    fn setup_control_subtraction_never_silently_saturates() {
        assert_eq!(
            subtract_setup_control(Duration::from_nanos(3), Duration::from_nanos(8)),
            Ok(Duration::from_nanos(5))
        );
        assert_eq!(
            subtract_setup_control(Duration::from_nanos(8), Duration::from_nanos(3)),
            Err(RunError::SetupControlExceededMeasured {
                setup: Duration::from_nanos(8),
                measured: Duration::from_nanos(3),
            })
        );
    }

    #[test]
    fn forwarding_errors_describe_all_benchmark_profiles() {
        assert_eq!(
            RunError::UnexpectedBatchReport.to_string(),
            "benchmark forwarding returned an unexpected batch report"
        );
        assert_eq!(
            RunError::ForwardingOracle.to_string(),
            "benchmark forwarding output failed its untimed oracle"
        );
    }
}

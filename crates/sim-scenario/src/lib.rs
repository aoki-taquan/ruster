#![forbid(unsafe_code)]
//! Bounded, versioned `ruster-scenario/v1` model for deterministic simulation.
//!
//! A scenario is a separate TOML file holding a seed for the simulation-only
//! hash-key source, the initial configuration path, and an ordered list of
//! `inject`, `tick`, `apply`, `expect`, and final `hold` steps. Frames are
//! described with typed cold-side builders or raw hex and are built to exact
//! bytes while parsing, so the same input always yields the same model.
//!
//! Notes on the format:
//!
//! - `seed` is a TOML integer, so its range is `0..=i64::MAX`.
//! - IPv4 `df` defaults to `true`; `ttl` to 64; other header fields to 0.
//! - Hex strings may contain ASCII whitespace only between whole octets.
//! - Config paths are relative to the scenario directory; `.` segments are
//!   stripped and root, `..`, `\`, and `:` are rejected.
//! - Typed frames accept `pad-to-min = true` for zero padding to 60 bytes.
//! - `expect.tx` matches bytes exactly; see [`Expectation::tx`].
//!
//! [`parse_scenario`] only parses and validates: it opens no file, reads no
//! clock, and executes nothing. The driver ([`SimSession`], [`SimRun`],
//! [`run_scenario_file`]) reads the scenario and configuration files, runs
//! the scenario through the public full-service composition on `SimIo` with
//! injected time only, evaluates `expect` steps, and writes canonical
//! `ruster-run-sim/v1` JSON lines.
//!
//! # `ruster-run-sim/v1` output
//!
//! One JSON object per line, fields in a fixed order, the first field always
//! `event`. No wall clock, map iteration, hash key, or seed is ever written.
//! Steps are zero-based indices into the scenario `step` list.
//!
//! - `start`: `schema`, backend name and mode, initial config path,
//!   generation, start time, step count, interfaces, storage capacities,
//!   tick budgets.
//! - `inject`: step, interface, length, frame hex.
//! - `tick`: one line per worker tick with its publication outcome and RX,
//!   forwarded, drop, consume, and generated counts.
//! - `tx`: every completed TX frame with egress interface, origin
//!   (`forwarded`/`generated`), and hex, in backend FIFO order.
//! - `apply`: outcome (`applied`/`rejected`), reason (`restart-required`/
//!   `invalid`), stage and code, the generation the sequencer consumed (if
//!   any), the active generation, and the committed flush counts.
//! - `expect`: `pass` or `fail` with the mismatch kind; the typed
//!   [`DriverError::Expect`] carries the precise difference.
//! - `final`: the R15 [`ruster_runtime::ObservabilitySnapshot`] (counters,
//!   health, generation, last apply), per-service counters, and backend
//!   stats, each rendered through `ObservableFields` as flat
//!   `"section.key"` members.
//!
//! Field names are part of the schema; renaming or reordering requires a new
//! schema version. Rendered typed codes (`code` of an `apply` line) use the
//! stable variant names of the config/control error enums.
//!
//! ```
//! use std::path::Path;
//! use ruster_sim_scenario::{parse_scenario, Step};
//!
//! let source = br#"
//! schema = "ruster-scenario/v1"
//! seed = 7
//! config = "router.toml"
//!
//! [[step]]
//! kind = "inject"
//! interface = "lan"
//! frame = { kind = "raw", hex = "ffffffffffff 020000000001 0806" }
//!
//! [[step]]
//! kind = "tick"
//! advance-ms = 10
//! "#;
//! let scenario = parse_scenario(source, Path::new("fixtures")).unwrap();
//! assert_eq!(scenario.config.resolved(), Path::new("fixtures/router.toml"));
//! assert!(matches!(scenario.steps[1], Step::Tick { at_ms: 10, ticks: 1 }));
//! ```

mod driver;
mod error;
mod frame;
mod model;
mod output;
mod parse;

pub use driver::{
    run_scenario_file, ApplyClass, ConfigRejection, DriverError, ExpectMismatch, FileRole,
    Progress, RunSummary, SimRun, SimSession, TxRecord, RUN_SIM_SCHEMA_V1, SIM_VALIDATION_LIMITS,
};

pub use error::{PathSegment, ScenarioError, ScenarioErrorCode};
pub use frame::{
    ArpOperation, ArpSpec, EthernetSpec, Frame, FrameBuildError, FrameKind, FrameSpec,
    IcmpEchoKind, Ipv4Spec, TcpFlags, ETHERNET_MIN_FRAME_LEN, MAX_FRAGMENT_OFFSET, MAX_FRAME_LEN,
};
pub use model::{
    ApplyOutcome, Expectation, ExpectedTx, InterfaceName, RejectReason, Scenario, ScenarioPath,
    ScenarioSeed, Step,
};
pub use parse::{
    parse_scenario, MAX_EXPECTED_TX, MAX_INTERFACE_NAME_BYTES, MAX_PATH_BYTES, MAX_SCENARIO_BYTES,
    MAX_STEPS, MAX_TICKS_PER_STEP, MAX_TOTAL_TICKS, SCENARIO_SCHEMA_V1,
};

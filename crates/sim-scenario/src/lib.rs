#![forbid(unsafe_code)]
//! Bounded, versioned `ruster-scenario/v1` model for deterministic simulation.
//!
//! A scenario is a separate TOML file holding a seed for the simulation-only
//! hash-key source, the initial configuration path, and an ordered list of
//! `inject`, `tick`, `apply`, `expect`, and final `hold` steps. Frames are
//! described with typed cold-side builders or raw hex and are built to exact
//! bytes while parsing, so the same input always yields the same model.
//!
//! This crate only parses and validates. It opens no file, reads no clock,
//! and executes nothing; the driver evaluates the model.
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

mod error;
mod frame;
mod model;
mod parse;

pub use error::{PathSegment, ScenarioError, ScenarioErrorCode};
pub use frame::{
    ArpOperation, ArpSpec, EthernetSpec, Frame, FrameBuildError, FrameKind, FrameSpec,
    IcmpEchoKind, Ipv4Spec, TcpFlags, MAX_FRAGMENT_OFFSET, MAX_FRAME_LEN,
};
pub use model::{
    ApplyOutcome, Expectation, ExpectedTx, InterfaceName, Scenario, ScenarioPath, ScenarioSeed,
    Step,
};
pub use parse::{
    parse_scenario, MAX_EXPECTED_TX, MAX_INTERFACE_NAME_BYTES, MAX_PATH_BYTES, MAX_SCENARIO_BYTES,
    MAX_STEPS, MAX_TICKS_PER_STEP, MAX_TOTAL_TICKS, SCENARIO_SCHEMA_V1,
};

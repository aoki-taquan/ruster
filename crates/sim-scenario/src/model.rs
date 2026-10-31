use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use ruster_core::{ConsumeReason, DropReason};

use crate::Frame;

/// A parsed, validated `ruster-scenario/v1` document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scenario {
    /// Seed for the simulation-only deterministic hash-key source.
    pub seed: ScenarioSeed,
    /// Injected monotonic time before the first step, in milliseconds.
    pub start_ms: u64,
    /// Initial configuration file.
    pub config: ScenarioPath,
    pub steps: Vec<Step>,
}

impl Scenario {
    /// Whether the scenario ends with a [`Step::Hold`] marker.
    #[must_use]
    pub fn holds(&self) -> bool {
        matches!(self.steps.last(), Some(Step::Hold))
    }
}

/// A scenario seed. `Debug` never shows the value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ScenarioSeed(u64);

impl ScenarioSeed {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for ScenarioSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScenarioSeed([REDACTED])")
    }
}

/// A configuration file reference confined to the scenario directory.
///
/// `relative` is the scenario text with `.` segments stripped; it never has a
/// root, a `..` segment, `\\`, or `:`. `resolved` is `base_dir.join(relative)`. The file is not opened or canonicalized here,
/// so symlinks are not inspected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioPath {
    relative: PathBuf,
    resolved: PathBuf,
}

impl ScenarioPath {
    pub(crate) fn new(relative: PathBuf, base_dir: &Path) -> Self {
        let resolved = base_dir.join(&relative);
        Self { relative, resolved }
    }

    #[must_use]
    pub fn relative(&self) -> &Path {
        &self.relative
    }

    #[must_use]
    pub fn resolved(&self) -> &Path {
        &self.resolved
    }
}

/// A bounded configuration interface name, resolved by the driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceName(pub(crate) String);

impl InterfaceName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One ordered scenario step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// Queue one frame on an ingress interface.
    Inject {
        interface: InterfaceName,
        frame: Frame,
    },
    /// Set injected monotonic time to `at_ms` (never earlier than the
    /// previous time) and run `ticks` worker ticks at that time.
    Tick {
        at_ms: u64,
        ticks: u32,
    },
    /// Validate and publish `config` as a new generation. Rollback is an
    /// apply of an older file.
    Apply {
        config: ScenarioPath,
        outcome: ApplyOutcome,
    },
    Expect(Expectation),
    /// Marker for CLI hold mode. Only valid as the final step.
    Hold,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplyOutcome {
    Applied,
    /// The apply must fail and leave the active generation unchanged.
    /// `None` accepts any rejection class.
    Rejected {
        reason: Option<RejectReason>,
    },
}

/// Expected rejection class; the driver maps it to control's typed errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RejectReason {
    /// Valid config whose change requires a process restart.
    RestartRequired,
    /// Config that fails parsing or validation.
    Invalid,
}

/// Assertions the driver evaluates at this point.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Expectation {
    /// When present, the exact ordered TX frames since the previous expect
    /// step (or scenario start). An empty list asserts no TX. Matching is
    /// byte-exact only: allocator-chosen NAT ports or ICMP identifiers are
    /// deterministic per seed, but fixtures must be regenerated whenever the
    /// allocator changes.
    pub tx: Option<Vec<ExpectedTx>>,
    /// Cumulative drop counts, in file order; each reason at most once.
    pub drops: Vec<(DropReason, u64)>,
    /// Cumulative consume counts, in file order; each reason at most once.
    pub consumes: Vec<(ConsumeReason, u64)>,
    /// Active publication generation.
    pub generation: Option<NonZeroU64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedTx {
    pub interface: InterfaceName,
    pub frame: Frame,
}

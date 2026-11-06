//! The "task and runner" shape from `docs/design/fe-internals.md`.
//!
//! Every role (an FE worker, the FE control role, a CE process) is a task: something
//! that can be moved forward a bounded amount without waiting. A runner is a thread
//! that steps a list of tasks; it does not know what they do. Tests run several tasks,
//! even several processes' worth, on one runner in a fixed order, so a run is
//! repeatable.

/// What one step did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// The task did something and may have more to do right away.
    pub busy: bool,
    /// The latest time (milliseconds) at which the task wants to be stepped again
    /// even if nothing arrives.
    pub wake_at: Option<u64>,
}

impl Progress {
    pub const IDLE: Self = Self {
        busy: false,
        wake_at: None,
    };

    pub fn busy(busy: bool) -> Self {
        Self {
            busy,
            wake_at: None,
        }
    }

    /// Combines the progress of two steps.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        Self {
            busy: self.busy || other.busy,
            wake_at: match (self.wake_at, other.wake_at) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
        }
    }
}

/// A role that can be stepped without blocking. One step does a bounded amount of work.
pub trait Task {
    fn step(&mut self, now_ms: u64) -> Progress;
}

/// Steps every task in order until none is busy, at most `max_rounds` rounds.
///
/// Returns the number of rounds it took, or `None` if the tasks were still busy after
/// `max_rounds` (which a test should treat as a livelock).
pub fn run_until_idle(
    tasks: &mut [&mut dyn Task],
    now_ms: u64,
    max_rounds: usize,
) -> Option<usize> {
    for round in 1..=max_rounds {
        let mut busy = false;
        for task in tasks.iter_mut() {
            busy |= task.step(now_ms).busy;
        }
        if !busy {
            return Some(round);
        }
    }
    None
}

#![doc = "Dependency-free, NIC-free benchmark support for `ruster-core`."]

mod allocation;
mod backend;
mod fixture;
mod matrix;
mod output;
mod runner;
mod stats;

pub use allocation::allocation_count;
pub use backend::{BenchBackend, BenchCompletion};
pub use fixture::{plain_ipv4_fixture, FrameSize};
pub use output::{OutputFormat, ResultRow};
pub use runner::{run, RunConfig, RunError, Suite};
pub use stats::SampleStats;

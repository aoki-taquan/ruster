use std::{fmt, num::NonZeroU64};

use crate::{MonotonicMillis, Scenario, ScenarioError};

/// Maximum number of logical ticks accepted by one scenario descriptor.
pub const MAX_SCENARIO_TICKS: usize = 64;

/// Maximum number of bounded reload or rollback events accepted by one
/// scenario descriptor.
pub const MAX_SCENARIO_PUBLICATION_EVENTS: usize = 16;

/// The public, value-only kind of a finite scenario publication event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioPublicationKind {
    /// Publish a separately compiled config authority at a fresh generation.
    Reload,
    /// Publish the config content recorded at one earlier generation with a
    /// fresh identity and a higher target generation.
    Rollback { source_generation: NonZeroU64 },
}

impl fmt::Display for ScenarioPublicationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reload => formatter.write_str("Reload"),
            Self::Rollback { source_generation } => write!(
                formatter,
                "Rollback(source_generation={})",
                source_generation
            ),
        }
    }
}

/// Value-free structural validation failures for a finite scenario
/// descriptor. No variant stores config text, seeds, derived keys, or caller
/// supplied names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioDescriptorError {
    TooManyTicks,
    TooManyPublicationEvents,
    TickTimeNotStrictlyIncreasing,
    PublicationEventTimeNotStrictlyIncreasing,
    PublicationEventNotOnTick,
    MoreThanOnePublicationAtTick,
    InitialGenerationZero,
    GenerationZero,
    GenerationExhausted,
    GenerationNotIncreasing,
    IdentityReused,
    RollbackSourceMissing,
    RollbackSourceNotEarlier,
}

impl fmt::Display for ScenarioDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TooManyTicks => "scenario tick limit exceeded",
            Self::TooManyPublicationEvents => "scenario publication event limit exceeded",
            Self::TickTimeNotStrictlyIncreasing => {
                "scenario tick logical time is not strictly increasing"
            }
            Self::PublicationEventTimeNotStrictlyIncreasing => {
                "scenario publication time is not strictly increasing"
            }
            Self::PublicationEventNotOnTick => "scenario publication is not bound to a tick",
            Self::MoreThanOnePublicationAtTick => {
                "scenario has more than one publication at a tick"
            }
            Self::InitialGenerationZero => "scenario initial generation is zero",
            Self::GenerationZero => "scenario publication generation is zero",
            Self::GenerationExhausted => "scenario publication generation is exhausted",
            Self::GenerationNotIncreasing => "scenario publication generation is not increasing",
            Self::IdentityReused => "scenario publication identity is reused",
            Self::RollbackSourceMissing => "scenario rollback source is missing",
            Self::RollbackSourceNotEarlier => "scenario rollback source is not earlier",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ScenarioDescriptorError {}

/// A value-free error returned by exact catalog lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioLookupError {
    UnknownName,
}

impl fmt::Display for ScenarioLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownName => formatter.write_str("unknown named scenario"),
        }
    }
}

impl std::error::Error for ScenarioLookupError {}

/// A typed failure from the high-level named-scenario runner.
#[derive(Debug, Eq, PartialEq)]
pub enum RunNamedScenarioError {
    Lookup(ScenarioLookupError),
    Descriptor(ScenarioDescriptorError),
    Scenario(ScenarioError),
}

impl fmt::Display for RunNamedScenarioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(error) => error.fmt(formatter),
            Self::Descriptor(_) => formatter.write_str("named scenario descriptor is invalid"),
            Self::Scenario(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RunNamedScenarioError {}

#[derive(Clone)]
enum EventAuthority {
    Reload {
        config_toml: &'static str,
        seed: u64,
    },
    Rollback {
        seed: u64,
    },
}

/// One finite logical-time publication event.
///
/// The public accessors expose only logical time, event kind, and target
/// generation. Config text and identity inputs remain private and are used
/// only when the runner materializes a candidate at the event boundary.
#[derive(Clone)]
pub struct ScenarioPublicationEvent {
    at: MonotonicMillis,
    generation: NonZeroU64,
    kind: ScenarioPublicationKind,
    authority: EventAuthority,
}

impl ScenarioPublicationEvent {
    /// Constructs a reload event. The config is required to have static
    /// lifetime so this API cannot become a filesystem or runtime fixture
    /// loader.
    pub fn reload(
        at: MonotonicMillis,
        generation: u64,
        config_toml: &'static str,
        seed: u64,
    ) -> Result<Self, ScenarioDescriptorError> {
        let generation =
            NonZeroU64::new(generation).ok_or(ScenarioDescriptorError::GenerationZero)?;
        Ok(Self {
            at,
            generation,
            kind: ScenarioPublicationKind::Reload,
            authority: EventAuthority::Reload { config_toml, seed },
        })
    }

    /// Alias for [`Self::reload`] using the conventional fallible-constructor
    /// spelling.
    pub fn try_reload(
        at: MonotonicMillis,
        generation: u64,
        config_toml: &'static str,
        seed: u64,
    ) -> Result<Self, ScenarioDescriptorError> {
        Self::reload(at, generation, config_toml, seed)
    }

    /// Constructs a rollback event. The source config is resolved from the
    /// descriptor's earlier revision history; it is not duplicated in this
    /// event. The seed is retained privately for fresh candidate identity.
    pub fn rollback(
        at: MonotonicMillis,
        generation: u64,
        source_generation: u64,
        seed: u64,
    ) -> Result<Self, ScenarioDescriptorError> {
        let generation =
            NonZeroU64::new(generation).ok_or(ScenarioDescriptorError::GenerationZero)?;
        let source_generation = NonZeroU64::new(source_generation)
            .ok_or(ScenarioDescriptorError::RollbackSourceMissing)?;
        Ok(Self {
            at,
            generation,
            kind: ScenarioPublicationKind::Rollback { source_generation },
            authority: EventAuthority::Rollback { seed },
        })
    }

    /// Alias for [`Self::rollback`] using the conventional fallible-constructor
    /// spelling.
    pub fn try_rollback(
        at: MonotonicMillis,
        generation: u64,
        source_generation: u64,
        seed: u64,
    ) -> Result<Self, ScenarioDescriptorError> {
        Self::rollback(at, generation, source_generation, seed)
    }

    /// Returns the event's logical tick time.
    #[must_use]
    pub const fn at(&self) -> MonotonicMillis {
        self.at
    }

    /// Returns the fresh target generation.
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    /// Returns the value-only public event kind.
    #[must_use]
    pub const fn kind(&self) -> ScenarioPublicationKind {
        self.kind
    }

    pub(crate) fn seed(&self) -> u64 {
        match self.authority {
            EventAuthority::Reload { seed, .. } | EventAuthority::Rollback { seed } => seed,
        }
    }

    pub(crate) fn config_for_history(&self, history: &[ScenarioRevision]) -> Option<&'static str> {
        match self.authority {
            EventAuthority::Reload { config_toml, .. } => Some(config_toml),
            EventAuthority::Rollback { .. } => {
                let ScenarioPublicationKind::Rollback { source_generation } = self.kind else {
                    unreachable!("reload authority cannot carry rollback kind");
                };
                history
                    .iter()
                    .rev()
                    .find(|revision| revision.generation == source_generation)
                    .map(|revision| revision.config_toml)
            }
        }
    }
}

impl fmt::Debug for ScenarioPublicationEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScenarioPublicationEvent")
            .field("at", &self.at)
            .field("generation", &self.generation)
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for ScenarioPublicationEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ScenarioPublicationEvent(at={:?}, generation={}, kind={})",
            self.at, self.generation, self.kind
        )
    }
}

/// A structurally validated initial scenario plus a bounded ordered event
/// stream. Construction performs all value-only checks before the runner can
/// parse config, plan a candidate, allocate storage, activate runtimes, or
/// bind a backend.
#[derive(Clone)]
pub struct ScenarioDescriptor {
    initial: Scenario,
    publications: Vec<ScenarioPublicationEvent>,
}

/// Private revision-history entry used only to resolve rollback config content
/// and never exposed as a candidate or authority.
pub(crate) struct ScenarioRevision {
    pub(crate) generation: NonZeroU64,
    pub(crate) config_toml: &'static str,
}

impl ScenarioDescriptor {
    /// Validates and constructs a descriptor from an initial scenario and an
    /// ordered finite publication list.
    pub fn new(
        initial: Scenario,
        publications: Vec<ScenarioPublicationEvent>,
    ) -> Result<Self, ScenarioDescriptorError> {
        let descriptor = Self {
            initial,
            publications,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Alias for [`Self::new`].
    pub fn try_new(
        initial: Scenario,
        publications: Vec<ScenarioPublicationEvent>,
    ) -> Result<Self, ScenarioDescriptorError> {
        Self::new(initial, publications)
    }

    /// Re-runs the value-only structural validation without parsing or
    /// materializing any config authority.
    pub fn validate(&self) -> Result<(), ScenarioDescriptorError> {
        if self.initial.ticks.len() > MAX_SCENARIO_TICKS {
            return Err(ScenarioDescriptorError::TooManyTicks);
        }
        if self.publications.len() > MAX_SCENARIO_PUBLICATION_EVENTS {
            return Err(ScenarioDescriptorError::TooManyPublicationEvents);
        }
        if self.initial.generation == 0 {
            return Err(ScenarioDescriptorError::InitialGenerationZero);
        }

        let mut previous_tick = None;
        for tick in &self.initial.ticks {
            if previous_tick.is_some_and(|previous| tick.now <= previous) {
                return Err(ScenarioDescriptorError::TickTimeNotStrictlyIncreasing);
            }
            previous_tick = Some(tick.now);
        }

        let initial_generation = NonZeroU64::new(self.initial.generation)
            .ok_or(ScenarioDescriptorError::InitialGenerationZero)?;
        let mut history = Vec::with_capacity(self.publications.len() + 1);
        history.push(ScenarioRevision {
            generation: initial_generation,
            config_toml: self.initial.config_toml,
        });
        // `plan_candidate` derives the three key pairs as
        // `(seed, seed + 1)`, `(seed + 2, seed + 3)`, and
        // `(seed + 4, seed + 5)` with wrapping arithmetic. For each key
        // family the fixed offset is a bijection over `u64`, and the first
        // component therefore preserves seed identity. Rejecting a seed
        // against the complete bounded history is sufficient to reject key
        // reuse, including non-adjacent revisions, without retaining keys in
        // this offline descriptor.
        let mut seeds = Vec::with_capacity(self.publications.len() + 1);
        seeds.push(self.initial.seed);
        let mut previous_event_at = None;

        for event in &self.publications {
            if let Some(previous) = previous_event_at {
                if event.at == previous {
                    return Err(ScenarioDescriptorError::MoreThanOnePublicationAtTick);
                }
                if event.at < previous {
                    return Err(ScenarioDescriptorError::PublicationEventTimeNotStrictlyIncreasing);
                }
            }
            previous_event_at = Some(event.at);

            if !self.initial.ticks.iter().any(|tick| tick.now == event.at) {
                return Err(ScenarioDescriptorError::PublicationEventNotOnTick);
            }

            let previous_generation = history
                .last()
                .map(|revision| revision.generation)
                .ok_or(ScenarioDescriptorError::InitialGenerationZero)?;
            if previous_generation.get() == u64::MAX {
                return Err(ScenarioDescriptorError::GenerationExhausted);
            }
            if event.generation <= previous_generation {
                return Err(ScenarioDescriptorError::GenerationNotIncreasing);
            }
            if seeds.iter().any(|seed| *seed == event.seed()) {
                return Err(ScenarioDescriptorError::IdentityReused);
            }

            if let ScenarioPublicationKind::Rollback { source_generation } = event.kind {
                if source_generation >= event.generation {
                    return Err(ScenarioDescriptorError::RollbackSourceNotEarlier);
                }
                if !history
                    .iter()
                    .any(|revision| revision.generation == source_generation)
                {
                    return Err(ScenarioDescriptorError::RollbackSourceMissing);
                }
            }

            let config_toml = event
                .config_for_history(&history)
                .ok_or(ScenarioDescriptorError::RollbackSourceMissing)?;
            history.push(ScenarioRevision {
                generation: event.generation,
                config_toml,
            });
            seeds.push(event.seed());
        }

        Ok(())
    }

    /// Returns the ordered public publication events without exposing their
    /// private config or identity authority.
    #[must_use]
    pub fn publication_events(&self) -> &[ScenarioPublicationEvent] {
        &self.publications
    }

    /// Returns the number of publication events.
    #[must_use]
    pub const fn publication_count(&self) -> usize {
        self.publications.len()
    }

    pub(crate) fn initial_scenario(&self) -> &Scenario {
        &self.initial
    }

    /// Runs this descriptor through the high-level deterministic composition
    /// path.
    pub fn run(&self) -> Result<Vec<crate::TickOutcome>, ScenarioError> {
        crate::run_descriptor(self)
    }
}

impl fmt::Debug for ScenarioDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScenarioDescriptor")
            .field("initial", &self.initial)
            .field("publications", &self.publications)
            .finish()
    }
}

impl fmt::Display for ScenarioDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ScenarioDescriptor(name={}, ticks={}, publications={})",
            self.initial.name,
            self.initial.ticks.len(),
            self.publications.len()
        )
    }
}

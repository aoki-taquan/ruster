//! How runtime state crosses a committed publication (RELOAD-CARRY).
//!
//! Every stateful runtime either flushes its publication-bound state on a
//! new generation, as it always did, or carries it into the successor when
//! the successor does not change what that state means. Carrying keeps the
//! runtime's secret hash key and every index as they are, so a carry is
//! O(1) for NAT44 and bounded for resolution and the firewall; see each
//! runtime's `preflight_*_carrying` method.

/// What a committed publication did with one runtime's state.
///
/// Value-free: it never names an address, port, or key.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateCarryOutcome {
    /// Flushed because the publication asked for a flush (the plain
    /// `reconcile`/`commit` APIs, or `[reload] state = "flush"`). The hash
    /// key rotated.
    #[default]
    FlushRequested,
    /// Flushed although a carry was asked for, because the successor
    /// changes what the state means. The hash key rotated.
    FlushIncompatible(StateCarryConflict),
    /// Carried: the state and its hash key were kept, and only the entries
    /// the successor invalidates were dropped.
    Carried,
}

/// Why a successor cannot carry one runtime's state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateCarryConflict {
    /// NAT44: the inside or outside interface changed.
    Interfaces,
    /// NAT44: the public address changed.
    PublicAddress,
    /// NAT44: the public port (or ICMP identifier) pool changed.
    PortRange,
    /// NAT44: the inbound filtering mode changed, which changes the key of
    /// every filter peer.
    Filtering,
    /// NAT44 TCP: an idle timeout of a session phase changed. TCP mappings
    /// keep absolute expiry deadlines in deadline-ordered lists, so they
    /// cannot take a new timeout in place; or a UDP/ICMP query idle timeout
    /// or a firewall idle timeout grew, which would make state that already
    /// expired under the old timeout live again.
    Timers,
    /// NAT44: a per-host limit was lowered or added; a host above it would
    /// never come down to it, because its expired slots are taken over one
    /// for one.
    Quota,
    /// Firewall: re-evaluating every carried flow against changed rules
    /// would exceed [`crate::FIREWALL_CARRY_REEVALUATION_BUDGET`] rule
    /// evaluations, so the apply flushes instead of stalling the worker.
    ReevaluationBudget,
}

impl StateCarryOutcome {
    /// Whether the state was carried.
    #[must_use]
    pub const fn carried(self) -> bool {
        matches!(self, Self::Carried)
    }

    /// Stable kebab-case label for machine-readable output.
    ///
    /// Exhaustive, so a new variant fails to compile until it has a label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FlushRequested => "flushed",
            Self::Carried => "carried",
            Self::FlushIncompatible(conflict) => match conflict {
                StateCarryConflict::Interfaces => "flushed:interfaces",
                StateCarryConflict::PublicAddress => "flushed:public-address",
                StateCarryConflict::PortRange => "flushed:port-range",
                StateCarryConflict::Filtering => "flushed:filtering",
                StateCarryConflict::Timers => "flushed:timers",
                StateCarryConflict::Quota => "flushed:quota",
                StateCarryConflict::ReevaluationBudget => "flushed:reevaluation-budget",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{StateCarryConflict, StateCarryOutcome};

    #[test]
    fn labels_are_stable_and_distinct() {
        let all = [
            StateCarryOutcome::FlushRequested,
            StateCarryOutcome::Carried,
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::Interfaces),
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::PublicAddress),
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::PortRange),
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::Filtering),
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::ReevaluationBudget),
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::Timers),
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::Quota),
        ];
        let labels = all.map(StateCarryOutcome::label);
        assert_eq!(
            labels,
            [
                "flushed",
                "carried",
                "flushed:interfaces",
                "flushed:public-address",
                "flushed:port-range",
                "flushed:filtering",
                "flushed:reevaluation-budget",
                "flushed:timers",
                "flushed:quota",
            ]
        );
        assert_eq!(
            StateCarryOutcome::default(),
            StateCarryOutcome::FlushRequested
        );
        assert!(StateCarryOutcome::Carried.carried());
        assert!(!StateCarryOutcome::FlushRequested.carried());
        assert!(!all[2].carried());
    }
}

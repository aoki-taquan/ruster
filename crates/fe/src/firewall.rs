//! The default VRF's forward firewall, from the tables' firewall rules, and its flow
//! states.
//!
//! Every accepted table change makes a new firewall publication for the new tables,
//! even with no rules, so the flow states can carry across it: core keeps the flows
//! the new rules and routes still allow and drops the others (see
//! `FirewallRuntime::preflight_reconcile_carrying`). The states are allocated once,
//! when the first rule arrives, and kept for the life of the process.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

use ruster_core::{
    FirewallConfig, FirewallHashKey, FirewallPolicy, FirewallRule, FirewallRuntime,
    FirewallStateSlot, ForwardingSnapshot, ValidatedFirewallOwner,
};

/// Flow states: about three quarters of them can be live at once.
const STATES: usize = 1 << 14;

/// A firewall publication made for one set of tables.
pub(crate) struct Publication {
    owner: ValidatedFirewallOwner,
    /// Whether it has any rule. With none, no firewall is applied.
    rules: bool,
}

impl Publication {
    /// The publication of `rules` for tables whose default VRF is `snapshot` (the
    /// snapshot of a `ValidatedForwardingOwner`). `generation` grows with each one.
    pub(crate) fn new(
        snapshot: &ForwardingSnapshot<'_>,
        rules: &[FirewallRule],
        generation: u64,
    ) -> Result<Self, String> {
        let owner = ValidatedFirewallOwner::new(
            snapshot,
            rules.into(),
            FirewallPolicy::default(),
            generation,
            hash_key(),
        )
        .map_err(|error| format!("firewall: {error:?}"))?;
        Ok(Self {
            owner,
            rules: !rules.is_empty(),
        })
    }
}

/// The firewall in use and its flow states.
pub(crate) struct Firewall {
    current: Publication,
    runtime: FirewallRuntime<'static>,
}

impl Firewall {
    /// Moves `firewall` to `next`, made for the tables whose default VRF is
    /// `next_snapshot`; `current_snapshot` is that of the tables in use. Nothing is
    /// allocated until a publication has rules.
    pub(crate) fn publish(
        firewall: &mut Option<Self>,
        next: Publication,
        current_snapshot: ForwardingSnapshot<'_>,
        next_snapshot: ForwardingSnapshot<'_>,
    ) -> Result<(), String> {
        let Some(this) = firewall else {
            if next.rules {
                let states =
                    Box::leak(vec![FirewallStateSlot::default(); STATES].into_boxed_slice());
                let runtime = FirewallRuntime::new(next.owner.config(), states);
                *firewall = Some(Self {
                    current: next,
                    runtime,
                });
            }
            return Ok(());
        };
        this.runtime
            .preflight_reconcile_carrying(
                this.current.owner.config(),
                next.owner.config(),
                current_snapshot,
                next_snapshot,
            )
            .map_err(|error| format!("firewall: {error:?}"))?
            .commit();
        this.current = next;
        Ok(())
    }

    /// The configuration and runtime to forward with, or `None` with no rules.
    pub(crate) fn service(
        &mut self,
    ) -> Option<(FirewallConfig<'_>, &mut FirewallRuntime<'static>)> {
        self.current
            .rules
            .then(|| (self.current.owner.config(), &mut self.runtime))
    }
}

/// A key for the flow table, different for every publication. The standard
/// library's `RandomState` is seeded from the operating system.
fn hash_key() -> FirewallHashKey {
    loop {
        let state = RandomState::new();
        if let Ok(key) = FirewallHashKey::new(state.hash_one(1_u8), state.hash_one(2_u8)) {
            return key;
        }
    }
}

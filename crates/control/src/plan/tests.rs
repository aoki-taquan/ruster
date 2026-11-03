use std::num::NonZeroU64;

use ruster_config::{
    parse, validate, AfXdpModeV1, BackendKindV1, ValidatedConfig, ValidatedConfigV1,
};
use ruster_core::{
    FirewallAction, IfId, Ipv4Address, MacAddress, StateCarryConflict, StateCarryOutcome,
};

use super::{
    ApplyPlan, Change, Delta, FlushCount, NatPortRange, NatRealm, PlanError, PlanSide,
    PublicationSequencer, SequencerError, StateFlush,
};
use crate::{
    activation::tests::{config_text, LIMITS, SEED, V1},
    ConfigBridgeError, KeySourceError, KeySourceKind, PublicationKeySource, PublicationKeys,
    ReloadState, RestartRequired, RuntimeService, SimDeterministicKeySource, ValidatedCandidate,
};

/// The S2 fixture document with exact textual replacements applied.
pub(crate) fn edited(edits: &[(&str, &str)]) -> String {
    let mut text = config_text(&V1);
    for (from, to) in edits {
        assert_eq!(text.matches(from).count(), 1, "edit anchor {from:?}");
        text = text.replacen(from, to, 1);
    }
    text
}

pub(crate) fn document(text: &str) -> ValidatedConfigV1 {
    match validate(parse(text.as_bytes()).expect("syntax"), LIMITS).expect("semantics") {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("fixture selects schema V1"),
    }
}

pub(crate) fn config(edits: &[(&str, &str)]) -> ValidatedConfigV1 {
    document(&edited(edits))
}

pub(crate) const ROUTE_CHANGE: (&str, &str) = ("via = \"198.51.100.1\"", "via = \"198.51.100.2\"");
pub(crate) const SHAPE_CHANGE: (&str, &str) = (
    "[firewall.capacity]\nstates = 16",
    "[firewall.capacity]\nstates = 32",
);
pub(crate) const RESOLUTION_POLICY_CHANGE: (&str, &str) =
    ("interval-ms = 1000", "interval-ms = 2000");
pub(crate) const ICMPV4_POLICY_CHANGE: (&str, &str) = (
    "interval-ms = 100\nstate-ttl-ms = 60000",
    "interval-ms = 200\nstate-ttl-ms = 60000",
);
/// An ICMPv4 error generation switch is part of the restart-required policy.
pub(crate) const ICMPV4_GENERATION_CHANGE: (&str, &str) = (
    "[icmpv4-errors.capacity]",
    "[icmpv4-errors.generate]\ntime-exceeded = false\n\n[icmpv4-errors.capacity]",
);
/// The Echo responder switch lives in the reloadable `ipv4-origin` policy
/// (the default TTL is unchanged).
pub(crate) const ECHO_REPLY_CHANGE: (&str, &str) = (
    "[resolution.policy]",
    "[ipv4-origin]\ndefault-ttl = 64\necho-reply = false\n\n[resolution.policy]",
);
/// The ARP-031 on-link sender opt-in lives in the reloadable `arp` policy.
pub(crate) const ARP_ON_LINK_CHANGE: (&str, &str) = (
    "[resolution.policy]",
    "[arp]\nrequire-on-link-sender = true\n\n[resolution.policy]",
);
/// NAT filtering modes are reloadable (the storage shape does not depend on
/// them); this edit loosens UDP and tightens TCP.
pub(crate) const NAT_FILTERING_CHANGE: [(&str, &str); 2] = [
    (
        "icmpv4-errors = \"external-only\"\n",
        "icmpv4-errors = \"external-only\"\nfiltering = \"endpoint-independent\"\n",
    ),
    (
        "allocator-seed = \"11\"\n",
        "allocator-seed = \"11\"\nfiltering = \"address-and-port-dependent\"\n",
    ),
];
/// The TCP per-remote inbound session limit is reloadable (the storage
/// shape does not depend on it); this edit opts into the recommended 8.
pub(crate) const TCP_INBOUND_LIMIT_CHANGE: (&str, &str) = (
    "allocator-seed = \"11\"\n",
    "allocator-seed = \"11\"\ninbound-sessions-per-remote = 8\n",
);
pub(crate) const INTERFACE_CHANGE: (&str, &str) =
    ("mac = \"02:00:00:00:00:02\"", "mac = \"02:00:00:00:00:22\"");
pub(crate) const PORT_CHANGE: (&str, &str) = ("last = 40015", "last = 40031");
/// Same pool size, shifted range: reloadable.
pub(crate) const PORT_SHIFT: (&str, &str) =
    ("first = 40000\nlast = 40015", "first = 40016\nlast = 40031");

fn plan(edits: &[(&str, &str)]) -> ApplyPlan {
    ApplyPlan::between(&config(&[]), &config(edits)).expect("plan")
}

fn ip(octets: [u8; 4]) -> Ipv4Address {
    Ipv4Address::from_octets(octets)
}

/// Asserts that only the listed aspects of `plan` are non-empty.
fn only(plan: &ApplyPlan, aspects: &[&str]) {
    let present = [
        ("routes", !plan.routes().is_empty()),
        ("neighbors", !plan.neighbors().is_empty()),
        ("local_ipv4", !plan.local_ipv4().is_empty()),
        ("interfaces", !plan.interfaces().is_empty()),
        ("interface_labels", !plan.interface_labels().is_empty()),
        ("firewall_rules", !plan.firewall_rules().is_empty()),
        ("firewall_order", plan.firewall_rule_order_changed()),
        ("firewall_policy", plan.firewall_policy_changed()),
        ("ipv4_origin", plan.ipv4_origin_changed()),
        ("arp", plan.arp_policy_changed()),
        ("nat44_udp", !plan.nat44_udp().is_empty()),
        ("nat44_tcp", !plan.nat44_tcp().is_empty()),
        ("backend", !plan.backend().is_empty()),
        ("restart", plan.requires_restart()),
    ];
    for (name, is_present) in present {
        assert_eq!(is_present, aspects.contains(&name), "aspect {name}");
    }
    // Pending resolution and ICMPv4 error work always flushes; the other
    // families follow the plan's carry expectation.
    let flush = plan.flush();
    for pending in [
        flush.resolution_states,
        flush.resolution_actions,
        flush.failure_holds,
        flush.icmpv4_error_states,
        flush.icmpv4_error_actions,
    ] {
        assert_eq!(pending, FlushCount::All);
    }
    if plan.carry().mode == ReloadState::Flush {
        assert_eq!(flush, StateFlush::ALL);
    }
    assert_eq!(plan.dry_run(), None);
}

/// `[reload] state = "flush"` appended to a document.
pub(crate) const FLUSH_MODE: (&str, &str) = (
    "[resolution.policy]",
    "[reload]\nstate = \"flush\"\n\n[resolution.policy]",
);

#[test]
fn identical_documents_plan_no_change_and_carry_every_family() {
    let plan = plan(&[]);
    only(&plan, &[]);
    let carry = plan.carry();
    assert_eq!(carry.mode, ReloadState::Carry);
    for outcome in [
        carry.resolution,
        carry.nat44_udp,
        carry.nat44_tcp,
        carry.firewall,
    ] {
        assert_eq!(outcome, StateCarryOutcome::Carried);
    }
    assert_eq!(carry.nat44_icmp, None);
    assert!(!carry.firewall_reevaluated);
    let flush = plan.flush();
    assert_eq!(flush.nat44_udp_mappings, FlushCount::Exact(0));
    assert_eq!(flush.nat44_tcp_sessions, FlushCount::Exact(0));
    assert_eq!(flush.firewall_flows, FlushCount::Exact(0));
    assert_eq!(flush.dynamic_neighbors, FlushCount::Invalidated);
}

#[test]
fn flush_mode_plans_a_full_flush_and_carry_mode_names_each_conflict() {
    // The successor's mode decides, so switching it is itself reloadable.
    let flush = ApplyPlan::between(&config(&[]), &config(&[FLUSH_MODE])).expect("plan");
    only(&flush, &[]);
    assert_eq!(flush.flush(), StateFlush::ALL);
    assert_eq!(flush.carry(), crate::StateCarry::flush(false));
    let back = ApplyPlan::between(&config(&[FLUSH_MODE]), &config(&[])).expect("plan");
    assert_eq!(back.carry().mode, ReloadState::Carry);

    // A same-size port shift flushes NAT with the pool as the reason; a
    // filtering change flushes with filtering; a rule change keeps the
    // firewall but re-evaluates it.
    let shift = plan(&[PORT_SHIFT]);
    let conflict = |reason| StateCarryOutcome::FlushIncompatible(reason);
    assert_eq!(
        shift.carry().nat44_udp,
        conflict(StateCarryConflict::PortRange)
    );
    assert_eq!(shift.flush().nat44_udp_mappings, FlushCount::All);
    let filtering = plan(&NAT_FILTERING_CHANGE);
    assert_eq!(
        (filtering.carry().nat44_udp, filtering.carry().nat44_tcp),
        (
            conflict(StateCarryConflict::Filtering),
            conflict(StateCarryConflict::Filtering)
        )
    );
    let rules = plan(&[(
        "destination = \"192.0.2.0/24\"",
        "destination = \"192.0.2.0/25\"",
    )]);
    assert_eq!(rules.carry().firewall, StateCarryOutcome::Carried);
    assert!(rules.carry().firewall_reevaluated);
    assert_eq!(rules.flush().firewall_flows, FlushCount::Invalidated);
    // A timer or quota change carries everything.
    let ttl = plan(&[TCP_INBOUND_LIMIT_CHANGE]);
    assert_eq!(ttl.carry().nat44_tcp, StateCarryOutcome::Carried);
}

#[test]
fn plan_reports_route_and_neighbor_changes_in_key_order() {
    let plan = plan(&[
        ROUTE_CHANGE,
        (
            "[[neighbors]]\ninterface = \"wan\"\naddress = \"198.51.100.2\"\nmac = \"02:00:00:00:00:04\"\n",
            "",
        ),
        ("mac = \"02:00:00:00:00:32\"", "mac = \"02:00:00:00:00:33\""),
    ]);
    only(&plan, &["routes", "neighbors"]);
    let [Change::Changed(Delta { old, new })] = plan.routes() else {
        panic!("one changed default route: {:?}", plan.routes());
    };
    assert_eq!(
        (old.prefix_len(), old.next_hop()),
        (0, Some(ip([198, 51, 100, 1])))
    );
    assert_eq!(new.next_hop(), Some(ip([198, 51, 100, 2])));
    let [Change::Changed(changed), Change::Removed(removed)] = plan.neighbors() else {
        panic!(
            "LAN neighbor change, then WAN removal: {:?}",
            plan.neighbors()
        );
    };
    assert_eq!(
        (changed.old.interface, changed.new.mac),
        (IfId(1), MacAddress([2, 0, 0, 0, 0, 0x33]))
    );
    assert_eq!(
        (removed.interface, removed.target),
        (IfId(2), ip([198, 51, 100, 2]))
    );
}

#[test]
fn plan_reports_firewall_rule_policy_and_order_changes() {
    let deny = plan(&[(
        "destination = \"192.0.2.0/24\"\nprotocol = \"udp\"\naction = \"allow-stateful\"",
        "destination = \"192.0.2.0/24\"\nprotocol = \"udp\"\naction = \"deny\"",
    )]);
    only(&deny, &["firewall_rules"]);
    let [Change::Changed(Delta { old, new })] = deny.firewall_rules() else {
        panic!("rule 3 changed: {:?}", deny.firewall_rules());
    };
    assert_eq!(
        (old.id().0, old.action(), new.action()),
        (3, FirewallAction::AllowStateful, FirewallAction::Deny)
    );

    let rule = |id: u32| format!("[[firewall.rules]]\nid = {id}\n");
    let swapped = plan(&[
        (&rule(1), &rule(9)),
        (&rule(2), &rule(1)),
        (&rule(9), &rule(2)),
    ]);
    only(&swapped, &["firewall_rules", "firewall_order"]);
    assert_eq!(swapped.firewall_rules().len(), 2);

    let renumbered = plan(&[(&rule(3), &rule(4))]);
    only(&renumbered, &["firewall_rules"]);
    assert!(matches!(
        renumbered.firewall_rules(),
        [Change::Removed(removed), Change::Added(added)] if removed.id().0 == 3 && added.id().0 == 4
    ));

    let policy = plan(&[("udp-idle-ttl-ms = 300000", "udp-idle-ttl-ms = 360000")]);
    only(&policy, &["firewall_policy"]);
}

#[test]
fn plan_reports_nat_realm_ports_and_policy_changes() {
    let realm = plan(&[
        ("ipv4 = \"198.51.100.10/24\"", "ipv4 = \"198.51.100.11/24\""),
        (
            "public-address = \"198.51.100.10\"",
            "public-address = \"198.51.100.11\"",
        ),
    ]);
    only(&realm, &["local_ipv4", "nat44_udp", "nat44_tcp"]);
    let expected = |last| NatRealm {
        inside: IfId(1),
        outside: IfId(2),
        public_address: ip([198, 51, 100, last]),
    };
    for nat in [realm.nat44_udp(), realm.nat44_tcp()] {
        assert_eq!(
            nat.realm,
            Some(Delta {
                old: expected(10),
                new: expected(11)
            })
        );
        assert_eq!((nat.ports, nat.policy_changed), (None, false));
    }

    // The port-owner table has one slot per pool port, so a pool size change
    // is also a storage shape change.
    let ports = plan(&[PORT_CHANGE]);
    only(&ports, &["nat44_udp", "nat44_tcp", "restart"]);
    assert_eq!(
        ports.nat44_udp().ports,
        Some(Delta {
            old: NatPortRange {
                first: 40000,
                last: 40015
            },
            new: NatPortRange {
                first: 40000,
                last: 40031
            },
        })
    );
    assert_eq!(ports.restart_required(), [RestartRequired::StorageShape]);

    // A same-size shift keeps the shape and is reloadable.
    let shift = plan(&[PORT_SHIFT]);
    only(&shift, &["nat44_udp", "nat44_tcp"]);
    assert_eq!(
        shift.nat44_tcp().ports.map(|ports| ports.new),
        Some(NatPortRange {
            first: 40016,
            last: 40031
        })
    );

    let policy = plan(&[("allocator-seed = \"7\"", "allocator-seed = \"8\"")]);
    only(&policy, &["nat44_udp"]);
    assert!(policy.nat44_udp().policy_changed);
    assert_eq!(policy.nat44_udp().filtering, None);
}

#[test]
fn nat_filtering_is_a_reloadable_typed_delta_separate_from_the_policy_flag() {
    use ruster_core::Nat44Filtering;

    const UDP: &str = "icmpv4-errors = \"external-only\"\n";
    const TCP: &str = "allocator-seed = \"11\"\n";
    // Spelling out the default is no change.
    only(
        &plan(&[
            (
                UDP,
                "icmpv4-errors = \"external-only\"\nfiltering = \"address-dependent\"\n",
            ),
            (
                TCP,
                "allocator-seed = \"11\"\nfiltering = \"address-dependent\"\n",
            ),
        ]),
        &[],
    );

    let udp = plan(&[(
        UDP,
        "icmpv4-errors = \"external-only\"\nfiltering = \"endpoint-independent\"\n",
    )]);
    only(&udp, &["nat44_udp"]);
    assert_eq!(
        udp.nat44_udp().filtering,
        Some(Delta {
            old: Nat44Filtering::AddressDependent,
            new: Nat44Filtering::EndpointIndependent,
        })
    );
    // A filtering-only change does not set the opaque policy flag, and it is
    // not restart-required: storage does not depend on the mode.
    assert!(!udp.nat44_udp().policy_changed);
    assert!(udp.restart_required().is_empty());

    let tcp = plan(&[(
        TCP,
        "allocator-seed = \"12\"\nfiltering = \"address-and-port-dependent\"\n",
    )]);
    only(&tcp, &["nat44_tcp"]);
    assert_eq!(
        tcp.nat44_tcp().filtering,
        Some(Delta {
            old: Nat44Filtering::AddressDependent,
            new: Nat44Filtering::AddressAndPortDependent,
        })
    );
    // Another policy change alongside still raises the opaque flag.
    assert!(tcp.nat44_tcp().policy_changed);
    assert!(tcp.restart_required().is_empty());
    assert_eq!(config(&[]).storage_shape(), {
        let edited = config(&[(
            TCP,
            "allocator-seed = \"11\"\nfiltering = \"endpoint-independent\"\n",
        )]);
        edited.storage_shape()
    });
}

#[test]
fn nat_hairpinning_is_a_reloadable_typed_delta_separate_from_the_policy_flag() {
    const UDP: &str = "icmpv4-errors = \"external-only\"\n";
    const TCP: &str = "allocator-seed = \"11\"\n";
    // Spelling out the default (on) is no change.
    only(
        &plan(&[
            (
                UDP,
                "icmpv4-errors = \"external-only\"\nhairpinning = true\n",
            ),
            (TCP, "allocator-seed = \"11\"\nhairpinning = true\n"),
        ]),
        &[],
    );

    let udp = plan(&[(
        UDP,
        "icmpv4-errors = \"external-only\"\nhairpinning = false\n",
    )]);
    only(&udp, &["nat44_udp"]);
    assert_eq!(
        udp.nat44_udp().hairpinning,
        Some(Delta {
            old: true,
            new: false
        })
    );
    assert_eq!(udp.nat44_udp().filtering, None);
    // A switch-only change does not set the opaque policy flag and is not
    // restart-required: storage does not depend on it.
    assert!(!udp.nat44_udp().policy_changed);
    assert!(udp.restart_required().is_empty());
    assert_eq!(udp.nat44_tcp().hairpinning, None);

    let tcp = plan(&[(TCP, "allocator-seed = \"12\"\nhairpinning = false\n")]);
    only(&tcp, &["nat44_tcp"]);
    assert_eq!(
        tcp.nat44_tcp().hairpinning,
        Some(Delta {
            old: true,
            new: false
        })
    );
    // Another policy change alongside still raises the opaque flag.
    assert!(tcp.nat44_tcp().policy_changed);
    assert!(tcp.restart_required().is_empty());
    assert_eq!(
        config(&[]).storage_shape(),
        config(&[(TCP, "allocator-seed = \"11\"\nhairpinning = false\n")]).storage_shape()
    );
}

/// N2: `port-preservation` is a non-secret, reloadable typed delta per
/// protocol (the apply flushes the NAT state like every NAT change), never
/// restart-required, and does not raise the opaque policy flag alone.
#[test]
fn nat_port_preservation_is_a_reloadable_typed_delta_separate_from_the_policy_flag() {
    const UDP: &str = "icmpv4-errors = \"external-only\"\n";
    const TCP: &str = "allocator-seed = \"11\"\n";
    // Spelling out the default (on) is no change.
    only(
        &plan(&[
            (
                UDP,
                "icmpv4-errors = \"external-only\"\nport-preservation = true\n",
            ),
            (TCP, "allocator-seed = \"11\"\nport-preservation = true\n"),
        ]),
        &[],
    );

    let udp = plan(&[(
        UDP,
        "icmpv4-errors = \"external-only\"\nport-preservation = false\n",
    )]);
    only(&udp, &["nat44_udp"]);
    assert_eq!(
        udp.nat44_udp().port_preservation,
        Some(Delta {
            old: true,
            new: false
        })
    );
    assert_eq!(udp.nat44_udp().hairpinning, None);
    assert!(!udp.nat44_udp().policy_changed);
    assert!(udp.restart_required().is_empty());
    assert_eq!(udp.nat44_tcp().port_preservation, None);

    let tcp = plan(&[(TCP, "allocator-seed = \"11\"\nport-preservation = false\n")]);
    only(&tcp, &["nat44_tcp"]);
    assert_eq!(
        tcp.nat44_tcp().port_preservation,
        Some(Delta {
            old: true,
            new: false
        })
    );
    assert!(!tcp.nat44_tcp().policy_changed);
    assert!(tcp.restart_required().is_empty());
    assert_eq!(tcp.nat44_udp().port_preservation, None);
    assert_eq!(
        config(&[]).storage_shape(),
        config(&[(TCP, "allocator-seed = \"11\"\nport-preservation = false\n")]).storage_shape()
    );
}

/// N3: `mappings-per-host` is a non-secret typed delta per protocol that
/// does not raise the opaque policy flag. Switching between `0` and a
/// limit adds or drops the per-host storage, so it is restart-required as a
/// storage-shape change; changing one limit to another is reloadable (the
/// apply flushes the NAT state like every NAT change).
#[test]
fn nat_mappings_per_host_is_a_typed_delta_and_only_switching_it_on_or_off_is_a_shape_change() {
    const UDP: &str = "icmpv4-errors = \"external-only\"\n";
    const TCP: &str = "allocator-seed = \"11\"\n";
    let udp_limit = |limit: u16| {
        (
            UDP,
            format!("icmpv4-errors = \"external-only\"\nmappings-per-host = {limit}\n"),
        )
    };
    let tcp_limit = |limit: u16| {
        (
            TCP,
            format!("allocator-seed = \"11\"\nmappings-per-host = {limit}\n"),
        )
    };
    let edits = |edits: &[(&'static str, String)]| -> ValidatedConfigV1 {
        let borrowed: Vec<(&str, &str)> = edits
            .iter()
            .map(|(anchor, text)| (*anchor, text.as_str()))
            .collect();
        config(&borrowed)
    };
    // Spelling out the default (0, no limit) is no change.
    only(
        &ApplyPlan::between(&config(&[]), &edits(&[udp_limit(0), tcp_limit(0)])).unwrap(),
        &[],
    );

    let on = ApplyPlan::between(&config(&[]), &edits(&[udp_limit(64)])).unwrap();
    only(&on, &["nat44_udp", "restart"]);
    assert_eq!(on.restart_required(), [RestartRequired::StorageShape]);
    assert_eq!(
        on.nat44_udp().mappings_per_host,
        Some(Delta { old: 0, new: 64 })
    );
    assert!(!on.nat44_udp().policy_changed);
    assert_eq!(on.nat44_tcp().mappings_per_host, None);

    let off = ApplyPlan::between(&edits(&[tcp_limit(8)]), &config(&[])).unwrap();
    only(&off, &["nat44_tcp", "restart"]);
    assert_eq!(off.restart_required(), [RestartRequired::StorageShape]);
    assert_eq!(
        off.nat44_tcp().mappings_per_host,
        Some(Delta { old: 8, new: 0 })
    );

    let change = ApplyPlan::between(
        &edits(&[udp_limit(64), tcp_limit(8)]),
        &edits(&[udp_limit(128), tcp_limit(16)]),
    )
    .unwrap();
    only(&change, &["nat44_udp", "nat44_tcp"]);
    assert!(change.restart_required().is_empty());
    assert_eq!(
        change.nat44_udp().mappings_per_host,
        Some(Delta { old: 64, new: 128 })
    );
    assert_eq!(
        change.nat44_tcp().mappings_per_host,
        Some(Delta { old: 8, new: 16 })
    );
    assert!(!change.nat44_udp().policy_changed && !change.nat44_tcp().policy_changed);
    assert_eq!(
        edits(&[udp_limit(64), tcp_limit(8)]).storage_shape(),
        edits(&[udp_limit(1), tcp_limit(65_535)]).storage_shape()
    );
}

/// N6: `peers-per-host` (UDP) and `sessions-per-host` (TCP) are typed
/// deltas, never the opaque policy flag. Switching the TCP session limit
/// between `0` and a limit is a storage-shape change; so is switching the
/// UDP peer limit on or off when no UDP mapping limit already provides the
/// per-host storage, and not when one does. Changing one nonzero limit to
/// another is reloadable.
#[test]
fn nat_peer_and_session_limits_are_typed_deltas_and_only_storage_switches_restart() {
    const UDP: &str = "icmpv4-errors = \"external-only\"\n";
    const TCP: &str = "allocator-seed = \"11\"\n";
    let udp = |text: &str| (UDP, format!("icmpv4-errors = \"external-only\"\n{text}"));
    let tcp = |text: &str| (TCP, format!("allocator-seed = \"11\"\n{text}"));
    let edits = |edits: &[(&'static str, String)]| -> ValidatedConfigV1 {
        let borrowed: Vec<(&str, &str)> = edits
            .iter()
            .map(|(anchor, text)| (*anchor, text.as_str()))
            .collect();
        config(&borrowed)
    };
    only(
        &ApplyPlan::between(
            &config(&[]),
            &edits(&[udp("peers-per-host = 0\n"), tcp("sessions-per-host = 0\n")]),
        )
        .unwrap(),
        &[],
    );

    let on = ApplyPlan::between(&config(&[]), &edits(&[tcp("sessions-per-host = 32\n")])).unwrap();
    only(&on, &["nat44_tcp", "restart"]);
    assert_eq!(on.restart_required(), [RestartRequired::StorageShape]);
    assert_eq!(
        on.nat44_tcp().sessions_per_host,
        Some(Delta { old: 0, new: 32 })
    );
    assert_eq!(on.nat44_tcp().peers_per_host, None);
    assert!(!on.nat44_tcp().policy_changed);

    let udp_on = ApplyPlan::between(&config(&[]), &edits(&[udp("peers-per-host = 16\n")])).unwrap();
    only(&udp_on, &["nat44_udp", "restart"]);
    assert_eq!(udp_on.restart_required(), [RestartRequired::StorageShape]);
    assert_eq!(
        udp_on.nat44_udp().peers_per_host,
        Some(Delta { old: 0, new: 16 })
    );
    assert_eq!(udp_on.nat44_udp().sessions_per_host, None);

    // With a mapping limit the storage exists: the peer limit reloads.
    let shared = ApplyPlan::between(
        &edits(&[udp("mappings-per-host = 8\n")]),
        &edits(&[udp("mappings-per-host = 8\npeers-per-host = 16\n")]),
    )
    .unwrap();
    only(&shared, &["nat44_udp"]);
    assert!(shared.restart_required().is_empty());

    let change = ApplyPlan::between(
        &edits(&[
            udp("peers-per-host = 16\n"),
            tcp("sessions-per-host = 32\n"),
        ]),
        &edits(&[udp("peers-per-host = 64\n"), tcp("sessions-per-host = 8\n")]),
    )
    .unwrap();
    only(&change, &["nat44_udp", "nat44_tcp"]);
    assert!(change.restart_required().is_empty());
    assert_eq!(
        change.nat44_udp().peers_per_host,
        Some(Delta { old: 16, new: 64 })
    );
    assert_eq!(
        change.nat44_tcp().sessions_per_host,
        Some(Delta { old: 32, new: 8 })
    );
    assert!(!change.nat44_udp().policy_changed && !change.nat44_tcp().policy_changed);
}

#[test]
fn tcp_inbound_limit_is_a_reloadable_typed_delta_separate_from_the_policy_flag() {
    const TCP: &str = "allocator-seed = \"11\"\n";
    // Spelling out the default (0, no limit) is no change.
    only(
        &plan(&[(
            TCP,
            "allocator-seed = \"11\"\ninbound-sessions-per-remote = 0\n",
        )]),
        &[],
    );

    let tcp = plan(&[TCP_INBOUND_LIMIT_CHANGE]);
    only(&tcp, &["nat44_tcp"]);
    assert_eq!(
        tcp.nat44_tcp().inbound_sessions_per_remote,
        Some(Delta { old: 0, new: 8 })
    );
    assert_eq!(tcp.nat44_tcp().filtering, None);
    assert_eq!(tcp.nat44_tcp().hairpinning, None);
    // A limit-only change does not set the opaque policy flag and is not
    // restart-required: storage does not depend on it.
    assert!(!tcp.nat44_tcp().policy_changed);
    assert!(tcp.restart_required().is_empty());
    assert_eq!(tcp.nat44_udp().inbound_sessions_per_remote, None);
    assert_eq!(
        config(&[]).storage_shape(),
        config(&[TCP_INBOUND_LIMIT_CHANGE]).storage_shape()
    );

    // Another policy change alongside still raises the opaque flag.
    let both = plan(&[(
        TCP,
        "allocator-seed = \"12\"\ninbound-sessions-per-remote = 3\n",
    )]);
    assert_eq!(
        both.nat44_tcp().inbound_sessions_per_remote,
        Some(Delta { old: 0, new: 3 })
    );
    assert!(both.nat44_tcp().policy_changed);
    assert!(both.restart_required().is_empty());
}

/// N1: the opening and closing idle timeouts are TCP policy, like the
/// established `idle-ttl-ms`: a change is reloadable (no storage shape
/// change, so no restart reason) and raises only the opaque policy flag;
/// apply flushes the NAT state as for every policy change.
#[test]
fn tcp_transitory_idle_ttls_are_reloadable_policy_changes() {
    const TCP: &str = "allocator-seed = \"11\"\n";
    // Spelling out the defaults is no change.
    only(
        &plan(&[(
            TCP,
            "allocator-seed = \"11\"\nopening-idle-ttl-ms = 240000\nclosing-idle-ttl-ms = 240000\n",
        )]),
        &[],
    );
    for key in ["opening-idle-ttl-ms", "closing-idle-ttl-ms"] {
        let change = format!("allocator-seed = \"11\"\n{key} = 300000\n");
        let tcp = plan(&[(TCP, change.as_str())]);
        only(&tcp, &["nat44_tcp"]);
        assert!(tcp.nat44_tcp().policy_changed, "{key}");
        assert_eq!(tcp.nat44_tcp().filtering, None);
        assert_eq!(tcp.nat44_tcp().inbound_sessions_per_remote, None);
        assert!(tcp.restart_required().is_empty(), "{key}");
        assert!(!tcp.nat44_udp().policy_changed);
        assert_eq!(
            config(&[]).storage_shape(),
            config(&[(TCP, change.as_str())]).storage_shape()
        );
    }
}

/// N1: `inbound-rst` is a reloadable typed TCP delta outside the opaque
/// policy flag; spelling out the default is no change.
#[test]
fn tcp_inbound_rst_is_a_reloadable_typed_delta() {
    use ruster_core::Nat44TcpInboundRst;
    const TCP: &str = "allocator-seed = \"11\"\n";
    only(
        &plan(&[(TCP, "allocator-seed = \"11\"\ninbound-rst = \"closing\"\n")]),
        &[],
    );
    let strict = plan(&[(
        TCP,
        "allocator-seed = \"11\"\ninbound-rst = \"corroborate\"\n",
    )]);
    only(&strict, &["nat44_tcp"]);
    assert_eq!(
        strict.nat44_tcp().inbound_rst,
        Some(Delta {
            old: Nat44TcpInboundRst::Closing,
            new: Nat44TcpInboundRst::Corroborate
        })
    );
    assert!(!strict.nat44_tcp().policy_changed);
    assert!(strict.restart_required().is_empty());
    assert_eq!(strict.nat44_udp().inbound_rst, None);
}

/// B3: the RFC 5382 REQ-4 switch is a reloadable typed TCP delta outside
/// the opaque policy flag; the hold capacity is storage shape.
#[test]
fn unsolicited_syn_switch_is_reloadable_and_hold_capacity_is_storage_shape() {
    const TCP: &str = "allocator-seed = \"11\"\n";
    const CAPACITY: &str = "[nat44.tcp.capacity]\nmappings = 4\n";
    // Spelling out the defaults is no change.
    only(
        &plan(&[
            (
                TCP,
                "allocator-seed = \"11\"\nunsolicited-syn-icmp = true\n",
            ),
            (
                CAPACITY,
                "[nat44.tcp.capacity]\nunsolicited-syn-holds = 64\nmappings = 4\n",
            ),
        ]),
        &[],
    );

    let off = plan(&[(
        TCP,
        "allocator-seed = \"11\"\nunsolicited-syn-icmp = false\n",
    )]);
    only(&off, &["nat44_tcp"]);
    assert_eq!(
        off.nat44_tcp().unsolicited_syn_icmp,
        Some(Delta {
            old: true,
            new: false
        })
    );
    assert!(!off.nat44_tcp().policy_changed);
    assert!(off.restart_required().is_empty());
    assert_eq!(off.nat44_udp().unsolicited_syn_icmp, None);

    let holds = plan(&[(
        CAPACITY,
        "[nat44.tcp.capacity]\nunsolicited-syn-holds = 65\nmappings = 4\n",
    )]);
    only(&holds, &["restart"]);
    assert_eq!(holds.restart_required(), [RestartRequired::StorageShape]);
}

#[test]
fn plan_classifies_interface_shape_and_policy_changes_as_restart_required() {
    let interface = plan(&[INTERFACE_CHANGE]);
    only(&interface, &["interfaces", "restart"]);
    assert!(matches!(
        interface.interfaces(),
        [Change::Changed(Delta { old, new })] if old.id == IfId(2) && new.mac == MacAddress([2, 0, 0, 0, 0, 0x22])
    ));
    assert_eq!(interface.restart_required(), [RestartRequired::Interfaces]);

    // MTU1: the interface MTU is part of the interface identity the running
    // backend was checked against (`ruster run` refuses a configured MTU
    // above the device's), so a change is restart-required.
    let mtu = plan(&[(
        "mac = \"02:00:00:00:00:02\"",
        "mac = \"02:00:00:00:00:02\"\nmtu = 1400",
    )]);
    only(&mtu, &["interfaces", "restart"]);
    assert!(matches!(
        mtu.interfaces(),
        [Change::Changed(Delta { old, new })]
            if old.id == IfId(2) && old.mtu == 1500 && new.mtu == 1400 && old.mac == new.mac
    ));
    assert_eq!(mtu.restart_required(), [RestartRequired::Interfaces]);

    // Name/device are control-plane labels: informational, reloadable.
    // Every reference is by name, so rename all of them.
    let renamed =
        edited(&[("device = \"eth1\"", "device = \"eth9\"")]).replace("\"wan\"", "\"uplink\"");
    let labels = ApplyPlan::between(&config(&[]), &document(&renamed)).unwrap();
    only(&labels, &["interface_labels"]);
    let [change] = labels.interface_labels() else {
        panic!("one label change: {:?}", labels.interface_labels());
    };
    assert_eq!(change.old.id, IfId(2));
    assert_eq!((&*change.old.name, &*change.old.device), ("wan", "eth1"));
    assert_eq!((&*change.new.name, &*change.new.device), ("uplink", "eth9"));

    for (edit, reason) in [
        (SHAPE_CHANGE, RestartRequired::StorageShape),
        (RESOLUTION_POLICY_CHANGE, RestartRequired::ResolutionPolicy),
        (ICMPV4_POLICY_CHANGE, RestartRequired::Icmpv4ErrorPolicy),
        (ICMPV4_GENERATION_CHANGE, RestartRequired::Icmpv4ErrorPolicy),
        // MTU2 part B: the fragmentation policy and slots are part of the
        // storage shape, so every `[fragmentation]` change restarts.
        (
            (
                "[resolution.policy]",
                "[fragmentation]\nenabled = false\n\n[resolution.policy]",
            ),
            RestartRequired::StorageShape,
        ),
        (
            (
                "[resolution.policy]",
                "[fragmentation]\nmax-fragments-per-datagram = 8\n\n[resolution.policy]",
            ),
            RestartRequired::StorageShape,
        ),
        (
            (
                "[resolution.policy]",
                "[fragmentation]\ndatagrams = 8\n\n[resolution.policy]",
            ),
            RestartRequired::StorageShape,
        ),
        // NAT-FRAG: the association policy and tables are part of the
        // storage shape too.
        (
            (
                "[resolution.policy]",
                "[fragment-tracking]\nmode = \"refuse\"\n\n[resolution.policy]",
            ),
            RestartRequired::StorageShape,
        ),
        (
            (
                "[resolution.policy]",
                "[fragment-tracking]\ntimeout-ms = 2000\n\n[resolution.policy]",
            ),
            RestartRequired::StorageShape,
        ),
        (
            (
                "[resolution.policy]",
                "[fragment-tracking]\nheld-fragments = 8\n\n[resolution.policy]",
            ),
            RestartRequired::StorageShape,
        ),
    ] {
        let plan = plan(&[edit]);
        only(&plan, &["restart"]);
        assert_eq!(plan.restart_required(), [reason]);
    }

    // The Echo responder switch is a reloadable ipv4-origin change, and
    // spelling out every default switch is no change at all.
    only(&plan(&[ECHO_REPLY_CHANGE]), &["ipv4_origin"]);
    // The ARP-031 opt-in is a reloadable arp change (in both directions),
    // and spelling out the RFC 826 default is no change at all.
    only(&plan(&[ARP_ON_LINK_CHANGE]), &["arp"]);
    only(
        &ApplyPlan::between(&config(&[ARP_ON_LINK_CHANGE]), &config(&[])).expect("plan"),
        &["arp"],
    );
    only(
        &plan(&[(
            "[resolution.policy]",
            "[arp]\nrequire-on-link-sender = false\n\n[resolution.policy]",
        )]),
        &[],
    );
    only(
        &plan(&[("[resolution.policy]", "[arp]\n\n[resolution.policy]")]),
        &[],
    );
    only(
        &plan(&[
            (
                "[icmpv4-errors.capacity]",
                "[icmpv4-errors.generate]\ntime-exceeded = true\nnet-unreachable = true\n\
                 host-unreachable = true\n\n[icmpv4-errors.capacity]",
            ),
            (
                "[resolution.policy]",
                "[ipv4-origin]\ndefault-ttl = 64\necho-reply = true\n\n[resolution.policy]",
            ),
        ]),
        &[],
    );

    // Every reason is listed, in successor validation order.
    let all = plan(&[
        INTERFACE_CHANGE,
        ICMPV4_POLICY_CHANGE,
        RESOLUTION_POLICY_CHANGE,
        SHAPE_CHANGE,
    ]);
    assert_eq!(
        all.restart_required(),
        [
            RestartRequired::StorageShape,
            RestartRequired::ResolutionPolicy,
            RestartRequired::Icmpv4ErrorPolicy,
            RestartRequired::Interfaces,
        ]
    );
}

/// The fixture document with an AF_XDP `[backend]` binding lan and wan,
/// wan on `wan_queue` with `wan_mode`.
pub(crate) fn af_xdp(edits: &[(&str, &str)], wan_queue: u32, wan_mode: &str) -> ValidatedConfigV1 {
    document(&af_xdp_text(edits, wan_queue, wan_mode))
}

fn af_xdp_text(edits: &[(&str, &str)], wan_queue: u32, wan_mode: &str) -> String {
    let port = |interface: &str, queue: u32, mode: &str| {
        format!(
            "\n[[backend.ports]]\ninterface = \"{interface}\"\nqueue = {queue}\n\
             mode = \"{mode}\"\nxdp-attach = \"native\"\n\
             rings = {{ fill = 256, rx = 256, tx = 256, completion = 256 }}\n\
             frame-size = 2048\nframe-count = 1024\ngenerated-frames = 64\n"
        )
    };
    format!(
        "{}\n[backend]\nkind = \"af-xdp\"\n{}{}",
        edited(edits),
        port("wan", wan_queue, wan_mode),
        port("lan", 0, "copy"),
    )
}

/// The fixture document with an AF_PACKET `[backend]` binding lan and wan,
/// with the given `max-frame-len` and wan RX retire timeout.
fn af_packet(max_frame_len: u32, wan_retire_ms: u32) -> ValidatedConfigV1 {
    let port = |interface: &str, retire: u32| {
        format!(
            "\n[[backend.af-packet.ports]]\ninterface = \"{interface}\"\n\
             rx = {{ block-size = 65536, block-count = 4, retire-timeout-ms = {retire} }}\n\
             tx = {{ block-size = 65536, block-count = 2 }}\n"
        )
    };
    document(&format!(
        "{}\n[backend]\nkind = \"af-packet\"\n\n[backend.af-packet]\nmax-frame-len = {max_frame_len}\n{}{}",
        edited(&[]),
        port("wan", wan_retire_ms),
        port("lan", 4),
    ))
}

/// AFPKT-015: every AF_PACKET backend difference (kind, maximum frame, a
/// port's ring) is restart-required and typed; the same backend is not.
#[test]
fn af_packet_backend_changes_are_restart_required_and_typed() {
    let sim = config(&[]);
    let packet = af_packet(1_514, 4);
    let up = ApplyPlan::between(&sim, &packet).unwrap();
    only(&up, &["backend", "restart"]);
    assert_eq!(up.restart_required(), [RestartRequired::Backend]);
    assert_eq!(
        up.backend().kind,
        Some(Delta {
            old: BackendKindV1::Sim,
            new: BackendKindV1::AfPacket,
        })
    );
    assert_eq!(
        up.backend().af_packet_max_frame_len,
        Some(Delta {
            old: None,
            new: Some(1_514),
        })
    );
    assert!(up.backend().ports.is_empty());
    assert!(matches!(
        &*up.backend().af_packet_ports,
        [Change::Added(lan), Change::Added(wan)]
            if lan.interface() == IfId(1) && wan.interface() == IfId(2)
    ));
    only(
        &ApplyPlan::between(&packet, &af_packet(1_514, 4)).unwrap(),
        &[],
    );
    let frame = ApplyPlan::between(&packet, &af_packet(1_518, 4)).unwrap();
    only(&frame, &["backend", "restart"]);
    assert!(frame.backend().af_packet_ports.is_empty());
    assert!(frame.backend().af_packet_max_frame_len.is_some());
    let retire = ApplyPlan::between(&packet, &af_packet(1_514, 8)).unwrap();
    only(&retire, &["backend", "restart"]);
    let [Change::Changed(Delta { old, new })] = &*retire.backend().af_packet_ports else {
        panic!(
            "one wan port change: {:?}",
            retire.backend().af_packet_ports
        );
    };
    assert_eq!((old.interface(), new.interface()), (IfId(2), IfId(2)));
    assert_eq!(
        (old.rx().retire_timeout_ms(), new.rx().retire_timeout_ms()),
        (4, 8)
    );
    // AF_XDP to AF_PACKET removes every AF_XDP port and adds every
    // AF_PACKET one.
    let across = ApplyPlan::between(&af_xdp(&[], 0, "copy"), &packet).unwrap();
    only(&across, &["backend", "restart"]);
    assert_eq!(across.backend().ports.len(), 2);
    assert_eq!(across.backend().af_packet_ports.len(), 2);
}

#[test]
fn backend_changes_are_restart_required_typed_and_listed_last() {
    let sim = config(&[]);
    // An explicit `sim` backend is the same as an absent section.
    let explicit = document(&format!("{}\n[backend]\nkind = \"sim\"\n", edited(&[])));
    only(&ApplyPlan::between(&sim, &explicit).unwrap(), &[]);

    let xdp = af_xdp(&[], 0, "copy");
    let up = ApplyPlan::between(&sim, &xdp).unwrap();
    only(&up, &["backend", "restart"]);
    assert_eq!(up.restart_required(), [RestartRequired::Backend]);
    assert_eq!(
        up.backend().kind,
        Some(Delta {
            old: BackendKindV1::Sim,
            new: BackendKindV1::AfXdp,
        })
    );
    assert_eq!(up.backend().existing_xdp_program, None);
    // Ports appear in IfId order although the document lists wan first.
    assert!(matches!(
        &*up.backend().ports,
        [Change::Added(lan), Change::Added(wan)]
            if lan.interface() == IfId(1) && wan.interface() == IfId(2)
    ));

    let down = ApplyPlan::between(&xdp, &sim).unwrap();
    only(&down, &["backend", "restart"]);
    assert!(matches!(
        &*down.backend().ports,
        [Change::Removed(_), Change::Removed(_)]
    ));

    // Same backend: nothing to restart, even with other reloadable changes.
    only(
        &ApplyPlan::between(&xdp, &af_xdp(&[], 0, "copy")).unwrap(),
        &[],
    );
    only(
        &ApplyPlan::between(&xdp, &af_xdp(&[ROUTE_CHANGE], 0, "copy")).unwrap(),
        &["routes"],
    );

    // Any one port setting is a typed per-port change.
    for next in [af_xdp(&[], 1, "copy"), af_xdp(&[], 0, "auto")] {
        let plan = ApplyPlan::between(&xdp, &next).unwrap();
        only(&plan, &["backend", "restart"]);
        assert_eq!(plan.restart_required(), [RestartRequired::Backend]);
        assert_eq!(plan.backend().kind, None);
        let [Change::Changed(Delta { old, new })] = &*plan.backend().ports else {
            panic!("one wan port change: {:?}", plan.backend().ports);
        };
        assert_eq!((old.interface(), new.interface()), (IfId(2), IfId(2)));
        assert!(old.queue() != new.queue() || old.mode() != new.mode());
        assert_eq!(old.mode(), AfXdpModeV1::Copy);
    }

    // Under af-xdp a port owns its device: moving an interface to another
    // device is restart-required (a label change alone is reloadable only
    // under sim), and so is swapping the devices of two interfaces.
    let moved = ApplyPlan::between(
        &xdp,
        &af_xdp(&[("device = \"eth1\"", "device = \"eth2\"")], 0, "copy"),
    )
    .unwrap();
    only(&moved, &["interface_labels", "backend", "restart"]);
    assert_eq!(moved.restart_required(), [RestartRequired::Backend]);
    let [Change::Changed(Delta { old, new })] = &*moved.backend().ports else {
        panic!("one wan port change: {:?}", moved.backend().ports);
    };
    assert_eq!((old.interface(), old.device()), (IfId(2), "eth1"));
    assert_eq!((new.interface(), new.device()), (IfId(2), "eth2"));
    let swapped = ApplyPlan::between(
        &xdp,
        &af_xdp(
            &[
                ("device = \"eth0\"", "device = \"swap\""),
                ("device = \"eth1\"", "device = \"eth0\""),
                ("device = \"swap\"", "device = \"eth1\""),
            ],
            0,
            "copy",
        ),
    )
    .unwrap();
    only(&swapped, &["interface_labels", "backend", "restart"]);
    assert_eq!(swapped.restart_required(), [RestartRequired::Backend]);
    assert!(matches!(
        &*swapped.backend().ports,
        [Change::Changed(lan), Change::Changed(wan)]
            if (lan.old.device(), lan.new.device()) == ("eth0", "eth1")
                && (wan.old.device(), wan.new.device()) == ("eth1", "eth0")
    ));
    // The same device under a new interface name is still the same port.
    let renamed = document(&af_xdp_text(&[], 0, "copy").replace("\"wan\"", "\"uplink\""));
    only(
        &ApplyPlan::between(&xdp, &renamed).unwrap(),
        &["interface_labels"],
    );

    // Backend is always the last reason.
    let both =
        ApplyPlan::between(&sim, &af_xdp(&[SHAPE_CHANGE, INTERFACE_CHANGE], 0, "copy")).unwrap();
    assert_eq!(
        both.restart_required(),
        [
            RestartRequired::StorageShape,
            RestartRequired::Interfaces,
            RestartRequired::Backend,
        ]
    );
    assert_eq!(RestartRequired::Backend.code(), "BACKEND");
}

#[test]
fn plan_ordering_is_deterministic_and_independent_of_document_order() {
    let first = "[[routes]]\nprefix = \"10.1.0.0/16\"\negress = \"lan\"\nvia = \"192.0.2.50\"\n";
    let second = "[[routes]]\nprefix = \"10.0.0.0/16\"\negress = \"lan\"\nvia = \"192.0.2.50\"\n";
    let anchor = "[[neighbors]]\ninterface = \"wan\"\naddress = \"198.51.100.1\"";
    let forward = format!("{first}\n{second}\n{anchor}");
    let reverse = format!("{second}\n{first}\n{anchor}");
    let current = config(&[]);
    let a = ApplyPlan::between(&current, &config(&[(anchor, &forward), ROUTE_CHANGE])).unwrap();
    let b = ApplyPlan::between(&current, &config(&[(anchor, &reverse), ROUTE_CHANGE])).unwrap();
    assert_eq!(a, b);
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
    let keys: Vec<_> = a
        .routes()
        .iter()
        .map(|change| match change {
            Change::Added(route)
            | Change::Removed(route)
            | Change::Changed(Delta { new: route, .. }) => (route.prefix(), route.prefix_len()),
        })
        .collect();
    assert_eq!(
        keys,
        [
            (ip([0, 0, 0, 0]), 0),
            (ip([10, 0, 0, 0]), 16),
            (ip([10, 1, 0, 0]), 16)
        ]
    );
    // Removing the routes again is the mirror image.
    let back = ApplyPlan::between(&config(&[(anchor, &forward)]), &current).unwrap();
    assert!(matches!(
        back.routes(),
        [Change::Removed(_), Change::Removed(_)]
    ));
}

#[test]
fn plan_rejects_missing_services_with_side() {
    let without_firewall = {
        let text = config_text(&V1);
        let cut = text.find("[firewall.policy]").unwrap();
        document(&text[..cut])
    };
    let full = config(&[]);
    assert_eq!(
        ApplyPlan::between(&without_firewall, &full),
        Err(PlanError::MissingService {
            side: PlanSide::Current,
            service: RuntimeService::Firewall
        })
    );
    assert_eq!(
        ApplyPlan::between(&full, &without_firewall),
        Err(PlanError::MissingService {
            side: PlanSide::Next,
            service: RuntimeService::Firewall
        })
    );
}

fn keys_of(
    candidate: &ValidatedCandidate,
) -> (
    ruster_core::Nat44UdpHashKey,
    ruster_core::Nat44TcpHashKey,
    ruster_core::FirewallHashKey,
) {
    let authority = candidate.authority();
    (
        authority.nat44_udp_hash_key(),
        authority.nat44_tcp_hash_key(),
        authority.firewall_config().hash_key(),
    )
}

#[test]
fn sequencer_issues_monotonic_generations_and_rollback_gets_new_keys() {
    let a = config(&[]);
    let b = config(&[ROUTE_CHANGE]);
    let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(SEED));
    assert_eq!(sequencer.last_issued(), None);
    assert_eq!(sequencer.next_generation(), Ok(NonZeroU64::MIN));
    let issued: Vec<_> = [&a, &b, &a]
        .into_iter()
        .map(|config| sequencer.candidate(config).expect("candidate"))
        .collect();
    let generations: Vec<_> = issued
        .iter()
        .map(|candidate| candidate.generation().get())
        .collect();
    assert_eq!(generations, [1, 2, 3]);
    let keys: Vec<_> = issued.iter().map(keys_of).collect();
    for (index, left) in keys.iter().enumerate() {
        for right in &keys[index + 1..] {
            assert!(left.0 != right.0 && left.1 != right.1 && left.2 != right.2);
        }
    }
    // The rollback candidate is a valid successor of B and of A's original
    // generation alike: new generation, new keys, same document.
    issued[1].validate_successor(&issued[2]).unwrap();
    issued[0].validate_successor(&issued[2]).unwrap();

    // A failed build consumes its generation; it is never reissued.
    let text = config_text(&V1);
    let without_firewall = document(&text[..text.find("[firewall.policy]").unwrap()]);
    assert_eq!(
        sequencer.candidate(&without_firewall).err(),
        Some(SequencerError::Bridge(ConfigBridgeError::MissingService(
            RuntimeService::Firewall
        )))
    );
    assert_eq!(sequencer.last_issued().map(NonZeroU64::get), Some(4));
    assert_eq!(sequencer.candidate(&a).unwrap().generation().get(), 5);

    sequencer.last_issued = NonZeroU64::new(u64::MAX);
    assert_eq!(
        sequencer.next_generation(),
        Err(SequencerError::GenerationExhausted)
    );
    assert_eq!(
        sequencer.candidate(&a).err(),
        Some(SequencerError::GenerationExhausted)
    );
}

/// A misbehaving source: A→B→A reissues the first generation's keys.
struct Replaying {
    calls: u64,
    replay: [u64; 3],
}

impl PublicationKeySource for Replaying {
    const KIND: KeySourceKind = KeySourceKind::DeterministicSimulation;

    fn publication_keys(&mut self, _: NonZeroU64) -> Result<PublicationKeys, KeySourceError> {
        let generation = self.replay[usize::try_from(self.calls).unwrap()];
        self.calls += 1;
        SimDeterministicKeySource::new(SEED).publication_keys(NonZeroU64::new(generation).unwrap())
    }
}

#[test]
fn sequencer_rejects_key_reuse_even_from_a_misbehaving_source() {
    let a = config(&[]);
    let b = config(&[ROUTE_CHANGE]);
    let mut sequencer = PublicationSequencer::new(Replaying {
        calls: 0,
        replay: [1, 2, 1],
    });
    let first = sequencer.candidate(&a).unwrap();
    sequencer.candidate(&b).unwrap();
    assert_eq!(
        sequencer.candidate(&a).err(),
        Some(SequencerError::KeyReused(RuntimeService::Nat44Udp))
    );
    assert_eq!(sequencer.last_issued().map(NonZeroU64::get), Some(3));
    assert_eq!(first.generation().get(), 1);
}

/// Fresh NAT44 and firewall keys, but the resolution key of generation 1
/// every time.
struct ResolutionReplaying;

impl PublicationKeySource for ResolutionReplaying {
    const KIND: KeySourceKind = KeySourceKind::DeterministicSimulation;

    fn publication_keys(
        &mut self,
        generation: NonZeroU64,
    ) -> Result<PublicationKeys, KeySourceError> {
        let fresh = SimDeterministicKeySource::new(SEED).publication_keys(generation)?;
        let first = SimDeterministicKeySource::new(SEED).publication_keys(NonZeroU64::MIN)?;
        Ok(PublicationKeys::new(
            fresh.nat44_udp(),
            fresh.nat44_tcp(),
            fresh.firewall(),
            first.resolution(),
            fresh.nat44_icmp(),
        ))
    }
}

#[test]
fn sequencer_rejects_a_reused_resolution_key() {
    let mut sequencer = PublicationSequencer::new(ResolutionReplaying);
    sequencer.candidate(&config(&[])).unwrap();
    assert_eq!(
        sequencer.candidate(&config(&[ROUTE_CHANGE])).err(),
        Some(SequencerError::KeyReused(RuntimeService::Resolution))
    );
}

#[test]
fn plan_and_sequencer_debug_never_show_keys_or_seeds() {
    let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(SEED));
    sequencer.candidate(&config(&[])).unwrap();
    let debug = format!("{sequencer:?}");
    assert_eq!(
        debug,
        "PublicationSequencer { last_issued: Some(1), issued_key_sets: 1, .. }"
    );
    let plan = plan(&[
        ("allocator-seed = \"7\"", "allocator-seed = \"8\""),
        ROUTE_CHANGE,
    ]);
    let debug = format!("{plan:?}");
    for secret in [
        "seed",
        "Seed",
        "key",
        "Key",
        &format!("{SEED}"),
        &format!("{SEED:x}"),
    ] {
        assert!(!debug.contains(secret), "{secret} in plan Debug");
    }
}

/// OPS-LOG: `[health]` and `[watch]` are `ruster run` watch settings, not
/// publication state: changing, adding, or removing them is no plan aspect
/// at all and never restart-required (the run applies them with the
/// reload, from the next health sample).
#[test]
fn health_and_watch_changes_are_reloadable_and_no_plan_aspect() {
    const OPS: (&str, &str) = (
        "[resolution.policy]",
        "[health]\ntx-stall-warn-ms = 2000\ntx-stall-fatal-ms = 0\n\
         frames-quarantined-fatal = 1\n\n[watch]\nhealth-interval-ms = 100\n\
         link-interval-ms = 500\nlink-stale-ms = 9000\n\n[resolution.policy]",
    );
    only(&plan(&[OPS]), &[]);
    only(
        &ApplyPlan::between(&config(&[OPS]), &config(&[])).expect("plan"),
        &[],
    );
    assert!(!plan(&[OPS]).requires_restart());
}

use std::num::NonZeroU64;

use ruster_config::{parse, validate, ValidatedConfig, ValidatedConfigV1};
use ruster_core::{FirewallAction, IfId, Ipv4Address, MacAddress};

use super::{
    ApplyPlan, Change, Delta, FlushCount, NatPortRange, NatRealm, PlanError, PlanSide,
    PublicationSequencer, SequencerError, StateFlush,
};
use crate::{
    activation::tests::{config_text, LIMITS, SEED, V1},
    ConfigBridgeError, KeySourceError, KeySourceKind, PublicationKeySource, PublicationKeys,
    RestartRequired, RuntimeService, SimDeterministicKeySource, ValidatedCandidate,
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
        ("nat44_udp", !plan.nat44_udp().is_empty()),
        ("nat44_tcp", !plan.nat44_tcp().is_empty()),
        ("restart", plan.requires_restart()),
    ];
    for (name, is_present) in present {
        assert_eq!(is_present, aspects.contains(&name), "aspect {name}");
    }
    assert_eq!(plan.flush(), StateFlush::ALL);
    assert_eq!(plan.dry_run(), None);
}

#[test]
fn identical_documents_plan_no_change_but_still_flush_everything() {
    let plan = plan(&[]);
    only(&plan, &[]);
    assert_eq!(plan.flush().nat44_udp_mappings, FlushCount::All);
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

#[test]
fn plan_classifies_interface_shape_and_policy_changes_as_restart_required() {
    let interface = plan(&[INTERFACE_CHANGE]);
    only(&interface, &["interfaces", "restart"]);
    assert!(matches!(
        interface.interfaces(),
        [Change::Changed(Delta { old, new })] if old.id == IfId(2) && new.mac == MacAddress([2, 0, 0, 0, 0, 0x22])
    ));
    assert_eq!(interface.restart_required(), [RestartRequired::Interfaces]);

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
    ] {
        let plan = plan(&[edit]);
        only(&plan, &["restart"]);
        assert_eq!(plan.restart_required(), [reason]);
    }

    // The Echo responder switch is a reloadable ipv4-origin change, and
    // spelling out every default switch is no change at all.
    only(&plan(&[ECHO_REPLY_CHANGE]), &["ipv4_origin"]);
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

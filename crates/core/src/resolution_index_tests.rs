//! H4b (PERF-001): the indexed resolution runtime against the pre-H4b
//! runtime, index invariants, and per-packet cost at the production limits.

use super::*;
use crate::{
    resolution_reference::{
        self as reference, RefAction, RefDynamic, RefHold, RefRuntime, RefState,
    },
    ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorStateSlot, Interface,
    LocalIpv4Binding, Neighbor, Route,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);

/// SplitMix64: deterministic and dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

fn host(egress: IfId, last: u8) -> Ipv4Address {
    Ipv4Address::from_octets([10, 0, egress.0 as u8, last])
}

fn local(egress: IfId) -> Ipv4Address {
    host(egress, 254)
}

fn mac_of(egress: IfId) -> MacAddress {
    if egress == LAN {
        LAN_MAC
    } else {
        WAN_MAC
    }
}

fn arp_action(egress: IfId, target: Ipv4Address) -> ArpRequestAction {
    ArpRequestAction {
        egress,
        source_mac: mac_of(egress),
        source_ip: local(egress),
        target_ip: target,
    }
}

fn connected(prefix: [u8; 4], len: u8, egress: IfId) -> Route {
    Route::new(Ipv4Address::from_octets(prefix), len, egress, None).unwrap()
}

fn routes() -> [Route; 2] {
    [
        connected([10, 0, 1, 0], 24, LAN),
        connected([10, 0, 2, 0], 24, WAN),
    ]
}
const INTERFACES: [Interface; 2] = [
    Interface {
        id: LAN,
        mac: LAN_MAC,
        mtu: 1500,
    },
    Interface {
        id: WAN,
        mac: WAN_MAC,
        mtu: 1500,
    },
];
const BINDINGS: [LocalIpv4Binding; 2] = [
    LocalIpv4Binding {
        interface: LAN,
        address: Ipv4Address::from_octets([10, 0, 1, 254]),
    },
    LocalIpv4Binding {
        interface: WAN,
        address: Ipv4Address::from_octets([10, 0, 2, 254]),
    },
];

/// Every observable piece of state of the indexed runtime equals the
/// pre-H4b runtime: each slot (so the same slot was chosen), the queue
/// order, cursors, counters; and the indexes match the slots.
fn assert_same(new: &ResolutionRuntime<'_>, old: &RefRuntime<'_>, step: usize) {
    for (index, (slot, old)) in new.states.iter().zip(old.states.iter()).enumerate() {
        let entry = slot.entry;
        assert_eq!(
            (
                entry.occupied,
                entry.key.egress,
                entry.key.target,
                entry.action,
                entry.generation,
                entry.attempts,
                entry.accepted_attempts,
                entry.requested_at,
                entry.failed_at,
                entry.phase,
                entry.failure_notified,
            ),
            (
                old.occupied,
                old.key.egress,
                old.key.target,
                old.action,
                old.generation,
                old.attempts,
                old.accepted_attempts,
                old.requested_at,
                old.failed_at,
                old.phase,
                old.failure_notified,
            ),
            "state slot {index} at step {step}"
        );
    }
    for (index, (slot, old)) in new
        .dynamic_neighbors
        .iter()
        .zip(old.dynamic_neighbors.iter())
        .enumerate()
    {
        let entry = slot.entry;
        assert_eq!(
            (
                entry.occupied,
                entry.interface,
                entry.target,
                entry.mac,
                entry.refreshed_at
            ),
            (
                old.occupied,
                old.interface,
                old.target,
                old.mac,
                old.refreshed_at
            ),
            "dynamic slot {index} at step {step}"
        );
    }
    for (index, (hold, old)) in new
        .failure_holds
        .iter()
        .zip(old.failure_holds.iter())
        .enumerate()
    {
        assert_eq!(hold.phase, old.phase, "hold {index} at step {step}");
        if hold.phase != ResolutionFailureHoldPhase::Empty {
            assert_eq!(
                (
                    hold.forward,
                    hold.original_source,
                    hold.original_destination,
                    hold.forward_source_mac,
                    hold.forward_source_ip,
                    hold.forward_prefix,
                    hold.forward_prefix_len,
                    hold.original_tos,
                    &hold.quote[..],
                ),
                (
                    old.forward,
                    old.original_source,
                    old.original_destination,
                    old.forward_source_mac,
                    old.forward_source_ip,
                    old.forward_prefix,
                    old.forward_prefix_len,
                    old.original_tos,
                    &old.quote[..],
                ),
                "hold {index} at step {step}"
            );
        }
        if hold.phase == ResolutionFailureHoldPhase::WaitingReverse {
            assert_eq!(hold.reverse, old.reverse, "hold {index} at step {step}");
        }
    }
    let mut queue = Vec::new();
    assert!(new.action_queue.validate(new.actions, |index| {
        queue.push(new.actions[index].queued.unwrap());
        true
    }));
    let old_queue: Vec<_> = (0..old.len)
        .map(|offset| {
            old.actions[(old.head + offset) % old.actions.len()]
                .0
                .unwrap()
        })
        .map(|queued| (queued.action, queued.generation))
        .collect();
    let queue: Vec<_> = queue
        .iter()
        .map(|queued| (queued.action, queued.generation))
        .collect();
    assert_eq!(queue, old_queue, "action queue at step {step}");
    assert_eq!(new.counters, old.counters, "counters at step {step}");
    assert_eq!(new.failure_counters, old.failure_counters, "step {step}");
    assert_eq!(
        (
            new.pending_state_count,
            new.pending_failure_hold_count,
            new.poll_cursor,
            new.failure_cursor,
            new.last_now,
            new.dynamic_neighbor_count(),
            new.cooldown_count(),
        ),
        (
            old.pending_state_count,
            old.pending_failure_hold_count,
            old.poll_cursor,
            old.failure_cursor,
            old.last_now,
            old.dynamic_neighbor_count(),
            old.cooldown_count(),
        ),
        "accounting at step {step}"
    );
    assert!(new.indexes_valid(), "indexes at step {step}");
    assert_eq!(new.index_counters, ResolutionIndexCounters::default());
}

#[derive(Default)]
struct Timers(Vec<ResolutionTimerTrace>);

impl ResolutionTimerTraceSink for Timers {
    fn record_resolution_timer(&mut self, event: ResolutionTimerTrace) {
        self.0.push(event);
    }
}

#[derive(Default)]
struct Failures(Vec<ResolutionFailureTrace>);

impl ResolutionFailureTraceSink for Failures {
    fn record_resolution_failure(&mut self, event: ResolutionFailureTrace) {
        self.0.push(event);
    }
}

struct Sizes {
    states: usize,
    actions: usize,
    dynamic: usize,
    holds: usize,
}

/// Seeded churn of every per-packet and timer operation, applied to the
/// indexed runtime and to the pre-H4b runtime (`resolution_reference`, the
/// old code path itself), comparing each result, trace, and slot.
fn churn_matches_pre_h4b_runtime(
    seed: u64,
    sizes: &Sizes,
    steps: usize,
    seen: &mut std::collections::BTreeSet<String>,
) {
    let mut rng = Rng(seed);
    let interval = 1_000;
    let failed_hold = 1_000 + rng.below(3) * 500;
    let attempts = 1 + rng.below(3) as u16;
    let dynamic_ttl = 500 + rng.below(4) * 700;
    let policy = ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(
        interval,
        failed_hold,
        attempts,
        dynamic_ttl,
    )
    .unwrap();
    let mut states = vec![ResolutionStateSlot::EMPTY; sizes.states];
    let mut actions = vec![ResolutionActionSlot::EMPTY; sizes.actions];
    let mut dynamic = vec![DynamicNeighborSlot::EMPTY; sizes.dynamic];
    let mut holds = vec![ResolutionFailureHoldSlot::EMPTY; sizes.holds];
    let key = ResolutionHashKey::new(seed | 1, seed.rotate_left(17)).unwrap();
    let mut new = ResolutionRuntime::with_hash_key(
        policy,
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut holds,
        key,
    );
    let mut old_states = vec![RefState::EMPTY; sizes.states];
    let mut old_actions = vec![RefAction::EMPTY; sizes.actions];
    let mut old_dynamic = vec![RefDynamic::EMPTY; sizes.dynamic];
    let mut old_holds = vec![RefHold::EMPTY; sizes.holds];
    let mut old = RefRuntime::with_dynamic_neighbors_and_failure_holds(
        policy,
        &mut old_states,
        &mut old_actions,
        &mut old_dynamic,
        &mut old_holds,
    );
    let icmp_policy = Icmpv4ErrorPolicy::new(1_000, 2_000).unwrap();
    let mut new_icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 4];
    let mut new_icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 4];
    let mut new_icmp =
        Icmpv4ErrorRuntime::new(icmp_policy, &mut new_icmp_states, &mut new_icmp_actions);
    let mut old_icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 4];
    let mut old_icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 4];
    let mut old_icmp =
        Icmpv4ErrorRuntime::new(icmp_policy, &mut old_icmp_states, &mut old_icmp_actions);
    let routes = routes();
    let snapshot = ForwardingSnapshot::new(&routes, &INTERFACES, &[], &BINDINGS).unwrap();
    // A few more hosts than slots, so tables fill and refuse.
    let hosts = (sizes.states.max(sizes.dynamic) as u64 + 3).min(200);
    let pick = |rng: &mut Rng| {
        let egress = if rng.chance(50) { LAN } else { WAN };
        (egress, host(egress, 1 + rng.below(hosts) as u8))
    };
    let mut now = 0u64;
    for step in 0..steps {
        if rng.chance(30) {
            let jump = if rng.chance(10) { 4_000 } else { 400 };
            now += rng.below(jump);
        }
        let at = MonotonicMillis(now);
        match rng.below(100) {
            0..=24 => {
                let (egress, target) = pick(&mut rng);
                let forbidden = rng.chance(3);
                let action = arp_action(egress, target);
                let result = new.schedule(action, at, forbidden);
                assert_eq!(
                    result,
                    old.schedule(action, at, forbidden),
                    "schedule at step {step}"
                );
                seen.insert(variant("schedule", &result));
            }
            25..=39 => {
                let front = new.front();
                assert_eq!(
                    front.map(|queued| (queued.action, queued.generation)),
                    old.front().map(|queued| (queued.action, queued.generation)),
                    "front at step {step}"
                );
                if let (Some(front), Some(old_front)) = (front, old.front()) {
                    let valid = new.execution_time_valid(at);
                    assert_eq!(valid, old.execution_time_valid(at));
                    if valid {
                        new.committed(front, at);
                        old.committed(old_front, at);
                        let accepted = usize::from(rng.chance(70));
                        new.accepted(front, accepted);
                        old.accepted(old_front, accepted);
                    }
                }
            }
            40..=49 => {
                let budget = 1 + rng.below(sizes.states as u64 + 2) as usize;
                let mut new_trace = Timers::default();
                let mut old_trace = Timers::default();
                assert_eq!(
                    poll_resolution_timers(&mut new, at, budget, &mut new_trace),
                    reference::ref_poll_resolution_timers(&mut old, at, budget, &mut old_trace),
                    "poll at step {step}"
                );
                assert_eq!(new_trace.0, old_trace.0, "timer trace at step {step}");
                for event in &new_trace.0 {
                    seen.insert(variant("timer", event));
                }
            }
            50..=59 => {
                let (egress, target) = pick(&mut rng);
                let result = new.lookup_dynamic(egress, target, at);
                assert_eq!(
                    result,
                    old.lookup_dynamic(egress, target, at),
                    "lookup at step {step}"
                );
                seen.insert(variant("lookup", &result));
            }
            60..=74 => {
                let (egress, target) = pick(&mut rng);
                let mac = MacAddress([2, 1, 0, 0, egress.0 as u8, rng.below(4) as u8]);
                let allow = rng.chance(70);
                let static_key = rng.chance(4);
                let result = new.merge_dynamic(egress, target, mac, allow, static_key, at);
                assert_eq!(
                    result,
                    old.merge_dynamic(egress, target, mac, allow, static_key, at),
                    "merge at step {step}"
                );
                seen.insert(variant("merge", &result));
            }
            75..=84 => {
                let (egress, target) = pick(&mut rng);
                let other = if egress == LAN { WAN } else { LAN };
                // Mostly an on-link source on the other side; sometimes a
                // source without a route, or on the same link.
                let source = match rng.below(10) {
                    0 => Ipv4Address::from_octets([192, 0, 2, 1]),
                    1 => host(egress, 1 + rng.below(hosts) as u8),
                    _ => host(other, 1 + rng.below(4) as u8),
                };
                let quote = [rng.below(256) as u8; 28];
                let prefix = Ipv4Address::from_octets([10, 0, egress.0 as u8, 0]);
                let capture = |runtime: &mut ResolutionRuntime<'_>| {
                    runtime.capture_failure_candidate(
                        egress,
                        target,
                        source,
                        target,
                        mac_of(egress),
                        local(egress),
                        prefix,
                        24,
                        0,
                        &quote,
                    )
                };
                let captured = capture(&mut new);
                assert_eq!(
                    captured,
                    old.capture_failure_candidate(
                        egress,
                        target,
                        source,
                        target,
                        mac_of(egress),
                        local(egress),
                        prefix,
                        24,
                        0,
                        &quote,
                    ),
                    "capture at step {step}"
                );
                seen.insert(variant("capture", &captured));
            }
            85..=93 => {
                let budget = 1 + rng.below(sizes.holds as u64 + 2) as usize;
                let mut new_trace = Failures::default();
                let mut old_trace = Failures::default();
                assert_eq!(
                    dispatch_host_unreachable_failures(
                        &mut new,
                        &mut new_icmp,
                        &snapshot,
                        at,
                        budget,
                        &mut new_trace
                    ),
                    reference::ref_dispatch_host_unreachable_failures(
                        &mut old,
                        &mut old_icmp,
                        &snapshot,
                        at,
                        budget,
                        &mut old_trace
                    ),
                    "dispatch at step {step}"
                );
                assert_eq!(new_trace.0, old_trace.0, "failure trace at step {step}");
                for event in &new_trace.0 {
                    seen.insert(variant("failure", event));
                }
                assert_eq!(new_icmp.counters(), old_icmp.counters());
                assert_eq!(new_icmp.pending_actions(), old_icmp.pending_actions());
            }
            94..=96 => {
                let mut neighbors: Vec<Neighbor> = Vec::new();
                for _ in 0..rng.below(4) {
                    let (interface, target) = pick(&mut rng);
                    if !neighbors.iter().any(|neighbor| {
                        neighbor.interface == interface && neighbor.target == target
                    }) {
                        neighbors.push(Neighbor {
                            interface,
                            target,
                            mac: MacAddress([2, 9, 9, 9, 9, 9]),
                        });
                    }
                }
                if rng.chance(50) {
                    assert_eq!(
                        new.reconcile_static(&neighbors),
                        old.reconcile_static(&neighbors),
                        "reconcile_static at step {step}"
                    );
                    seen.insert("reconcile:static".to_owned());
                } else {
                    let published =
                        ForwardingSnapshot::new(&routes, &INTERFACES, &neighbors, &BINDINGS)
                            .unwrap();
                    assert_eq!(
                        new.reconcile_publication(&published),
                        old.reconcile_publication(&published),
                        "reconcile_publication at step {step}"
                    );
                    seen.insert("reconcile:publication".to_owned());
                }
            }
            _ => {
                // A clock regression is refused by every entry point.
                let back = MonotonicMillis(now.saturating_sub(1 + rng.below(3)));
                let (egress, target) = pick(&mut rng);
                let result = new.schedule(arp_action(egress, target), back, false);
                assert_eq!(
                    result,
                    old.schedule(arp_action(egress, target), back, false)
                );
                seen.insert(variant("schedule", &result));
            }
        }
        assert_same(&new, &old, step);
        if new.cooldown_count() != 0 {
            seen.insert("state:cooldown".to_owned());
        }
        for _ in 0..2 {
            let (egress, target) = pick(&mut rng);
            assert_eq!(
                new.status(egress, target),
                old.status(egress, target),
                "status at step {step}"
            );
        }
    }
}

#[test]
fn seeded_churn_matches_the_pre_h4b_runtime_slot_for_slot() {
    let shapes = [
        Sizes {
            states: 1,
            actions: 1,
            dynamic: 1,
            holds: 1,
        },
        Sizes {
            states: 4,
            actions: 2,
            dynamic: 3,
            holds: 2,
        },
        Sizes {
            states: 8,
            actions: 8,
            dynamic: 8,
            holds: 8,
        },
        Sizes {
            states: 65,
            actions: 16,
            dynamic: 70,
            holds: 33,
        },
        Sizes {
            states: 130,
            actions: 130,
            dynamic: 130,
            holds: 64,
        },
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (shape_index, sizes) in shapes.iter().enumerate() {
        for seed in 0..10u64 {
            churn_matches_pre_h4b_runtime(
                0x4834_6200_0000_0000 ^ (shape_index as u64) << 32 ^ seed,
                sizes,
                2_000,
                &mut seen,
            );
        }
    }
    // The churn reaches every outcome the indexes decide.
    for expected in [
        "schedule:Queued",
        "schedule:RetryQueued",
        "schedule:Suppressed",
        "schedule:TimedOut",
        "schedule:Failed",
        "schedule:StateFull",
        "schedule:ActionFull",
        "schedule:ClockRegression",
        "schedule:ForbiddenTarget",
        "lookup:Hit",
        "lookup:Miss",
        "merge:Inserted",
        "merge:Updated",
        "merge:Ignored",
        "merge:StaticPreserved",
        "merge:CacheFull",
        "capture:Captured",
        "capture:Existing",
        "capture:Inactive",
        "capture:CapacityFull",
        "timer:RetryQueued",
        "timer:TimedOut",
        "timer:NoAcceptedArpRequest",
        "timer:FailureExpired",
        "timer:ActionFull",
        "failure:Queued",
        "failure:ReverseArpScheduled",
        "failure:ReverseArpPending",
        "failure:Retained",
        "failure:ReverseResolutionFailed",
        "failure:SameFailedKey",
        "failure:ForwardAuthorityLost",
        "reconcile:static",
        "reconcile:publication",
        "state:cooldown",
    ] {
        assert!(
            seen.contains(expected),
            "churn never reached {expected}: {seen:?}"
        );
    }
    // Zero-capacity tables.
    churn_matches_pre_h4b_runtime(
        7,
        &Sizes {
            states: 0,
            actions: 0,
            dynamic: 0,
            holds: 0,
        },
        500,
        &mut std::collections::BTreeSet::new(),
    );
}

/// `tag:Variant` of a value's `Debug` form.
fn variant(tag: &str, value: &impl std::fmt::Debug) -> String {
    let text = format!("{value:?}");
    let end = text.find([' ', '(', '{']).unwrap_or(text.len());
    format!("{tag}:{}", &text[..end])
}

/// Production-limit tables for the cost tests.
struct Tables {
    states: Vec<ResolutionStateSlot>,
    actions: Vec<ResolutionActionSlot>,
    dynamic: Vec<DynamicNeighborSlot>,
    holds: Vec<ResolutionFailureHoldSlot>,
}

impl Tables {
    fn new(states: usize, actions: usize, dynamic: usize, holds: usize) -> Self {
        Self {
            states: vec![ResolutionStateSlot::EMPTY; states],
            actions: vec![ResolutionActionSlot::EMPTY; actions],
            dynamic: vec![DynamicNeighborSlot::EMPTY; dynamic],
            holds: vec![ResolutionFailureHoldSlot::EMPTY; holds],
        }
    }

    fn runtime(&mut self, policy: ResolutionPolicy) -> ResolutionRuntime<'_> {
        ResolutionRuntime::with_hash_key(
            policy,
            &mut self.states,
            &mut self.actions,
            &mut self.dynamic,
            &mut self.holds,
            ResolutionHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
        )
    }
}

/// A distinct on-link address per index (10.0/16 on the WAN interface).
fn spread(index: usize) -> Ipv4Address {
    let index = index as u32 + 1;
    Ipv4Address::from_octets([
        10,
        (index >> 16) as u8 + 64,
        (index >> 8) as u8,
        index as u8,
    ])
}

/// Index slots one packet may visit: two key chains (lookup plus the chain
/// the operation touches), one list head, the reusable bitmap at 65536
/// slots (16 summary words and a leaf), plus a few bucket heads.
const PER_PACKET_VISITS: u64 = 2 * RESOLUTION_INDEX_CHAIN_LIMIT as u64 + 1 + 17 + 8;

const PRODUCTION_SLOTS: usize = 1 << 16;
const PRODUCTION_QUOTE_SLOTS: usize = 1 << 12;

#[test]
fn arp_flood_from_distinct_senders_costs_a_constant_per_packet_at_65536() {
    let policy = ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 1_000, 60_000).unwrap();
    let mut tables = Tables::new(16, 16, PRODUCTION_SLOTS, 16);
    let mut runtime = tables.runtime(policy);
    let mac = MacAddress([2, 3, 4, 5, 6, 7]);
    let mut worst = 0;
    // Learn until full: every insert is constant work.
    for index in 0..PRODUCTION_SLOTS {
        runtime.take_visits();
        assert_eq!(
            runtime.merge_dynamic(WAN, spread(index), mac, true, false, MonotonicMillis(0)),
            ControlDisposition::Inserted
        );
        worst = worst.max(runtime.take_visits());
    }
    // A flood of new senders against a full table of live entries.
    for index in PRODUCTION_SLOTS..PRODUCTION_SLOTS + 50_000 {
        runtime.take_visits();
        assert_eq!(
            runtime.merge_dynamic(WAN, spread(index), mac, true, false, MonotonicMillis(1)),
            ControlDisposition::CacheFull
        );
        worst = worst.max(runtime.take_visits());
    }
    // Refreshes and forwarding lookups (hits and misses).
    for index in (0..PRODUCTION_SLOTS).step_by(7) {
        runtime.take_visits();
        assert_eq!(
            runtime.merge_dynamic(WAN, spread(index), mac, false, false, MonotonicMillis(2)),
            ControlDisposition::Updated
        );
        assert_eq!(
            runtime.lookup_dynamic(WAN, spread(index), MonotonicMillis(2)),
            DynamicLookup::Hit(mac)
        );
        assert_eq!(
            runtime.lookup_dynamic(WAN, spread(index + PRODUCTION_SLOTS), MonotonicMillis(2)),
            DynamicLookup::Miss
        );
        worst = worst.max(runtime.take_visits());
    }
    assert!(
        worst <= PER_PACKET_VISITS,
        "worst {worst} visits per packet"
    );
    // Once every entry expired, the next inserts reuse expired slots. The
    // refresh order is drained once (one visit per learned entry), so the
    // cost is amortized constant.
    runtime.take_visits();
    let inserts = PRODUCTION_SLOTS;
    for index in 0..inserts {
        assert_eq!(
            runtime.merge_dynamic(
                WAN,
                spread(index + 2 * PRODUCTION_SLOTS),
                mac,
                true,
                false,
                MonotonicMillis(70_000)
            ),
            ControlDisposition::Inserted
        );
    }
    let average = runtime.take_visits() / inserts as u64;
    assert!(average <= PER_PACKET_VISITS + 2, "average {average}");
    assert_eq!(runtime.dynamic_neighbor_count(), PRODUCTION_SLOTS);
    assert_eq!(runtime.index_counters(), ResolutionIndexCounters::default());
    assert!(runtime.indexes_valid());
}

#[test]
fn packets_to_many_unused_addresses_cost_a_constant_per_packet_at_65536() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut tables = Tables::new(
        PRODUCTION_SLOTS,
        PRODUCTION_SLOTS,
        PRODUCTION_SLOTS,
        PRODUCTION_QUOTE_SLOTS,
    );
    let mut runtime = tables.runtime(policy);
    let worst = Cell::new(0);
    let packet = |runtime: &mut ResolutionRuntime<'_>, index: usize, now: u64| {
        // What forwarding does for a packet to an unresolved next hop: a
        // dynamic-neighbor miss, then scheduling, then failure capture.
        runtime.take_visits();
        let target = spread(index);
        assert_eq!(
            runtime.lookup_dynamic(WAN, target, MonotonicMillis(now)),
            DynamicLookup::Miss
        );
        let result = runtime.schedule(arp_action(WAN, target), MonotonicMillis(now), false);
        let _ = runtime.capture_failure_candidate(
            WAN,
            target,
            Ipv4Address::from_octets([10, 0, 1, 1]),
            target,
            WAN_MAC,
            local(WAN),
            Ipv4Address::from_octets([10, 0, 0, 0]),
            8,
            0,
            &[0x45; 28],
        );
        worst.set(worst.get().max(runtime.take_visits()));
        result
    };
    for index in 0..PRODUCTION_SLOTS {
        assert_eq!(packet(&mut runtime, index, 0), ResolutionResult::Queued);
    }
    for index in PRODUCTION_SLOTS..PRODUCTION_SLOTS + 50_000 {
        assert_eq!(packet(&mut runtime, index, 1), ResolutionResult::StateFull);
    }
    // Repeats of pending targets are suppressed.
    for index in (0..PRODUCTION_SLOTS).step_by(5) {
        assert_eq!(packet(&mut runtime, index, 2), ResolutionResult::Suppressed);
    }
    let worst = worst.get();
    assert!(
        worst <= PER_PACKET_VISITS,
        "worst {worst} visits per packet"
    );
    assert_eq!(runtime.pending_failure_holds(), PRODUCTION_QUOTE_SLOTS);
    // Committing every request and cancelling them all (as ARP replies
    // would) leaves cooldowns, which become reusable an interval after
    // their request; new targets then reuse them at amortized constant cost.
    while let Some(front) = runtime.front() {
        runtime.committed(front, MonotonicMillis(3));
    }
    for index in 0..PRODUCTION_SLOTS {
        runtime.clear_resolution(WAN, spread(index));
    }
    assert_eq!(runtime.cooldown_count(), PRODUCTION_SLOTS);
    for index in PRODUCTION_SLOTS..PRODUCTION_SLOTS + 1_000 {
        assert_eq!(packet(&mut runtime, index, 4), ResolutionResult::StateFull);
    }
    runtime.take_visits();
    for index in 0..PRODUCTION_SLOTS {
        assert_eq!(
            runtime.schedule(
                arp_action(WAN, spread(index + 3 * PRODUCTION_SLOTS)),
                MonotonicMillis(1_003),
                false
            ),
            ResolutionResult::Queued
        );
        let front = runtime.front().unwrap();
        runtime.committed(front, MonotonicMillis(1_003));
    }
    let average = runtime.take_visits() / PRODUCTION_SLOTS as u64;
    assert!(average <= PER_PACKET_VISITS + 2, "average {average}");
    assert_eq!(runtime.cooldown_count(), 0);
    assert_eq!(runtime.index_counters(), ResolutionIndexCounters::default());
    assert!(runtime.indexes_valid());
}

#[test]
fn failure_hold_churn_costs_amortized_constant_at_the_production_limit() {
    let policy = ResolutionPolicy::with_retry(1_000, 10_000, 1).unwrap();
    let holds = PRODUCTION_QUOTE_SLOTS;
    let mut tables = Tables::new(PRODUCTION_SLOTS, PRODUCTION_SLOTS, 16, holds);
    let mut runtime = tables.runtime(policy);
    // One spoofed source: every hold ends up waiting for the same reverse
    // resolution, the longest reverse chain an attacker can build.
    let spoofed = Ipv4Address::from_octets([10, 0, 1, 77]);
    let capture = |runtime: &mut ResolutionRuntime<'_>, target| {
        runtime.capture_failure_candidate(
            WAN,
            target,
            spoofed,
            target,
            WAN_MAC,
            local(WAN),
            Ipv4Address::from_octets([10, 0, 0, 0]),
            8,
            0,
            &[0x45; 28],
        )
    };
    let mut worst = 0;
    for index in 0..holds + 2_000 {
        let target = spread(index);
        runtime.schedule(arp_action(WAN, target), MonotonicMillis(0), false);
        runtime.take_visits();
        let captured = capture(&mut runtime, target);
        worst = worst.max(runtime.take_visits());
        if index < holds {
            assert!(matches!(captured, ResolutionFailureCapture::Captured(_)));
        } else {
            // A full hold table refuses captures at constant cost.
            assert_eq!(captured, ResolutionFailureCapture::CapacityFull);
        }
    }
    assert!(worst <= PER_PACKET_VISITS, "capture {worst}");
    while let Some(front) = runtime.front() {
        runtime.committed(front, MonotonicMillis(0));
        runtime.accepted(front, 1);
    }
    // Every forward resolution times out; each hold becomes ready.
    let timed_out = poll_resolution_timers(
        &mut runtime,
        MonotonicMillis(1_000),
        usize::MAX,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    assert_eq!(timed_out.timed_out, holds + 2_000);
    // Dispatch moves every hold to wait for the one reverse resolution.
    let routes = [
        connected([10, 0, 1, 0], 24, LAN),
        connected([10, 0, 0, 0], 8, WAN),
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &INTERFACES, &[], &BINDINGS).unwrap();
    let mut icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 2];
    let mut icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
    let mut icmp = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut icmp_states,
        &mut icmp_actions,
    );
    runtime.take_visits();
    let report = dispatch_host_unreachable_failures(
        &mut runtime,
        &mut icmp,
        &snapshot,
        MonotonicMillis(1_000),
        usize::MAX,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!(
        (report.reverse_arp_scheduled, report.reverse_arp_pending),
        (1, holds - 1)
    );
    let average = runtime.take_visits() / holds as u64;
    assert!(average <= PER_PACKET_VISITS, "wait reverse {average}");
    // The reverse resolution fails: dispatch retires every waiting hold.
    let reverse = runtime.front().unwrap();
    runtime.committed(reverse, MonotonicMillis(1_000));
    runtime.accepted(reverse, 1);
    poll_resolution_timers(
        &mut runtime,
        MonotonicMillis(2_000),
        usize::MAX,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    runtime.take_visits();
    let report = dispatch_host_unreachable_failures(
        &mut runtime,
        &mut icmp,
        &snapshot,
        MonotonicMillis(2_000),
        usize::MAX,
        &mut NoResolutionFailureTrace,
    )
    .unwrap();
    assert_eq!(report.retired, holds);
    let average = runtime.take_visits() / holds as u64;
    assert!(average <= PER_PACKET_VISITS, "reverse failed {average}");
    assert_eq!(runtime.pending_failure_holds(), 0);
    assert!(runtime.indexes_valid());
}

#[test]
fn expiry_clears_every_reverse_waiter_at_one_visit_each() {
    let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
    let holds = PRODUCTION_QUOTE_SLOTS;
    let mut tables = Tables::new(16, 16, 16, holds);
    let mut runtime = tables.runtime(policy);
    let reverse_target = Ipv4Address::from_octets([10, 0, 1, 77]);
    runtime.schedule(arp_action(LAN, reverse_target), MonotonicMillis(0), false);
    let front = runtime.front().unwrap();
    runtime.committed(front, MonotonicMillis(0));
    poll_resolution_timers(
        &mut runtime,
        MonotonicMillis(1_000),
        usize::MAX,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    let reverse = ResolutionGenerationToken {
        egress: LAN,
        target: reverse_target,
        generation: runtime.status(LAN, reverse_target).unwrap().generation,
    };
    // Every hold waits for that failed reverse resolution.
    for index in 0..holds {
        runtime.install_hold_for_test(
            index,
            ResolutionFailureHoldPhase::WaitingReverse,
            ResolutionGenerationToken {
                egress: WAN,
                target: spread(index),
                generation: 1,
            },
            reverse,
        );
    }
    assert!(runtime.indexes_valid());
    runtime.take_visits();
    let expired = poll_resolution_timers(
        &mut runtime,
        MonotonicMillis(2_000),
        usize::MAX,
        &mut NoResolutionTimerTrace,
    )
    .unwrap();
    assert_eq!(expired.failures_expired, 1);
    assert_eq!(runtime.pending_failure_holds(), 0);
    assert_eq!(runtime.failure_counters().cancelled, holds);
    // One visit per cleared hold, plus the bucket heads.
    let visits = runtime.take_visits();
    assert!(visits <= holds as u64 + 4, "{visits} visits");
    assert!(runtime.indexes_valid());
}

#[test]
fn a_full_key_chain_fails_closed_and_counts() {
    // A one-bucket view: with two slots every key lands in bucket 0 or 1,
    // so filling chain 0 to the limit needs keys that collide. Use a
    // table larger than the limit and search keys for one bucket.
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let slots = 64;
    let mut tables = Tables::new(slots, slots, slots, slots);
    let mut runtime = tables.runtime(policy);
    let bucket = runtime
        .state_bucket(ResolutionKey {
            egress: WAN,
            target: spread(0),
        })
        .unwrap();
    let colliding: Vec<Ipv4Address> = (0..100_000)
        .map(spread)
        .filter(|target| {
            runtime.state_bucket(ResolutionKey {
                egress: WAN,
                target: *target,
            }) == Some(bucket)
        })
        .take(RESOLUTION_INDEX_CHAIN_LIMIT + 1)
        .collect();
    assert_eq!(colliding.len(), RESOLUTION_INDEX_CHAIN_LIMIT + 1);
    for target in &colliding[..RESOLUTION_INDEX_CHAIN_LIMIT] {
        assert_eq!(
            runtime.schedule(arp_action(WAN, *target), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
    }
    let before = runtime.counters();
    assert_eq!(
        runtime.schedule(
            arp_action(WAN, colliding[RESOLUTION_INDEX_CHAIN_LIMIT]),
            MonotonicMillis(0),
            false
        ),
        ResolutionResult::StateFull
    );
    assert_eq!(runtime.counters().state_full, before.state_full + 1);
    assert_eq!(runtime.index_counters().state_probe_exhausted, 1);
    // Other buckets still work, and the chain admits again once a state of
    // it is gone.
    let elsewhere = (0..100_000)
        .map(spread)
        .find(|target| {
            runtime.state_bucket(ResolutionKey {
                egress: WAN,
                target: *target,
            }) != Some(bucket)
        })
        .unwrap();
    assert_eq!(
        runtime.schedule(arp_action(WAN, elsewhere), MonotonicMillis(0), false),
        ResolutionResult::Queued
    );
    runtime.clear_resolution(WAN, colliding[0]);
    assert_eq!(
        runtime.schedule(
            arp_action(WAN, colliding[RESOLUTION_INDEX_CHAIN_LIMIT]),
            MonotonicMillis(0),
            false
        ),
        ResolutionResult::Queued
    );
    assert!(runtime.indexes_valid());

    // The same for the dynamic neighbor cache.
    let colliding: Vec<Ipv4Address> = (0..100_000)
        .map(spread)
        .filter(|target| {
            runtime.dynamic_bucket(ResolutionKey {
                egress: LAN,
                target: *target,
            }) == Some(0)
        })
        .take(RESOLUTION_INDEX_CHAIN_LIMIT + 1)
        .collect();
    let mac = MacAddress([2, 5, 5, 5, 5, 5]);
    for target in &colliding[..RESOLUTION_INDEX_CHAIN_LIMIT] {
        assert_eq!(
            runtime.merge_dynamic(LAN, *target, mac, true, false, MonotonicMillis(0)),
            ControlDisposition::Inserted
        );
    }
    assert_eq!(
        runtime.merge_dynamic(
            LAN,
            colliding[RESOLUTION_INDEX_CHAIN_LIMIT],
            mac,
            true,
            false,
            MonotonicMillis(0)
        ),
        ControlDisposition::CacheFull
    );
    assert_eq!(runtime.index_counters().dynamic_probe_exhausted, 1);
    assert!(runtime.indexes_valid());
}

/// Targets whose key lands in the same bucket of `bucket_of`, at least
/// `count` of them.
fn colliding(count: usize, bucket_of: impl Fn(Ipv4Address) -> Option<usize>) -> Vec<Ipv4Address> {
    let first = bucket_of(spread(0));
    let targets: Vec<_> = (0..200_000)
        .map(spread)
        .filter(|target| bucket_of(*target) == first)
        .take(count)
        .collect();
    assert_eq!(targets.len(), count);
    targets
}

#[test]
fn a_full_chain_still_admits_a_key_that_reuses_a_slot_of_that_chain() {
    // States: a full chain whose oldest member is an elapsed cooldown. A
    // new colliding key reuses that very slot, so the chain does not grow.
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut tables = Tables::new(
        RESOLUTION_INDEX_CHAIN_LIMIT,
        RESOLUTION_INDEX_CHAIN_LIMIT,
        RESOLUTION_INDEX_CHAIN_LIMIT,
        1,
    );
    let mut runtime = tables.runtime(policy);
    let targets = colliding(RESOLUTION_INDEX_CHAIN_LIMIT + 1, |target| {
        runtime.state_bucket(ResolutionKey {
            egress: WAN,
            target,
        })
    });
    for target in &targets[..RESOLUTION_INDEX_CHAIN_LIMIT] {
        assert_eq!(
            runtime.schedule(arp_action(WAN, *target), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        let front = runtime.front().unwrap();
        runtime.committed(front, MonotonicMillis(0));
    }
    runtime.clear_resolution(WAN, targets[0]);
    assert_eq!(runtime.cooldown_count(), 1);
    assert_eq!(
        runtime.schedule(
            arp_action(WAN, targets[RESOLUTION_INDEX_CHAIN_LIMIT]),
            MonotonicMillis(1_000),
            false
        ),
        ResolutionResult::Queued
    );
    assert_eq!(runtime.index_counters(), ResolutionIndexCounters::default());
    assert!(runtime.indexes_valid());

    // Dynamic neighbors: a full chain whose oldest member expired.
    let policy = ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 1_000, 100).unwrap();
    let mut tables = Tables::new(1, 1, RESOLUTION_INDEX_CHAIN_LIMIT, 1);
    let mut runtime = tables.runtime(policy);
    let targets = colliding(RESOLUTION_INDEX_CHAIN_LIMIT + 1, |target| {
        runtime.dynamic_bucket(ResolutionKey {
            egress: LAN,
            target,
        })
    });
    let mac = MacAddress([2, 6, 6, 6, 6, 6]);
    for (index, target) in targets[..RESOLUTION_INDEX_CHAIN_LIMIT].iter().enumerate() {
        assert_eq!(
            runtime.merge_dynamic(
                LAN,
                *target,
                mac,
                true,
                false,
                MonotonicMillis(index as u64)
            ),
            ControlDisposition::Inserted
        );
    }
    assert_eq!(
        runtime.merge_dynamic(
            LAN,
            targets[RESOLUTION_INDEX_CHAIN_LIMIT],
            mac,
            true,
            false,
            MonotonicMillis(100)
        ),
        ControlDisposition::Inserted
    );
    assert_eq!(runtime.index_counters(), ResolutionIndexCounters::default());
    assert!(runtime.indexes_valid());
}

#[test]
fn a_full_forward_hold_chain_refuses_capture_and_counts() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut tables = Tables::new(256, 256, 1, 64);
    let mut runtime = tables.runtime(policy);
    let targets = colliding(RESOLUTION_INDEX_CHAIN_LIMIT + 1, |target| {
        runtime.forward_bucket(WAN, target)
    });
    let capture = |runtime: &mut ResolutionRuntime<'_>, target| {
        runtime.capture_failure_candidate(
            WAN,
            target,
            Ipv4Address::from_octets([10, 0, 1, 1]),
            target,
            WAN_MAC,
            local(WAN),
            Ipv4Address::from_octets([10, 0, 0, 0]),
            8,
            0,
            &[0x45; 28],
        )
    };
    for target in &targets {
        assert_eq!(
            runtime.schedule(arp_action(WAN, *target), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
    }
    for target in &targets[..RESOLUTION_INDEX_CHAIN_LIMIT] {
        assert!(matches!(
            capture(&mut runtime, *target),
            ResolutionFailureCapture::Captured(_)
        ));
    }
    let full = runtime.failure_counters().capture_full;
    assert_eq!(
        capture(&mut runtime, targets[RESOLUTION_INDEX_CHAIN_LIMIT]),
        ResolutionFailureCapture::CapacityFull
    );
    assert_eq!(runtime.failure_counters().capture_full, full + 1);
    assert_eq!(runtime.index_counters().failure_hold_probe_exhausted, 1);
    assert!(runtime.indexes_valid());
}

/// H4b review L1: other tokens that hash into the bucket of a token that
/// thousands of holds wait on (one spoofed source) pay only for the
/// distinct tokens on the reverse chain, not for those holds. Adapted from
/// the reviewer's `rev310_reverse_chain_miss_walk`; the key is the fixed
/// test key, so the collisions are found by search.
#[test]
fn reverse_chain_walks_skip_holds_of_a_colliding_token() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let holds = PRODUCTION_QUOTE_SLOTS;
    let mut tables = Tables::new(PRODUCTION_SLOTS, PRODUCTION_SLOTS, 16, holds);
    let mut runtime = tables.runtime(policy);
    let reverse = ResolutionGenerationToken {
        egress: LAN,
        target: Ipv4Address::from_octets([10, 0, 1, 77]),
        generation: 1,
    };
    for index in 0..holds {
        runtime.install_hold_for_test(
            index,
            ResolutionFailureHoldPhase::WaitingReverse,
            ResolutionGenerationToken {
                egress: WAN,
                target: spread(index),
                generation: 1,
            },
            reverse,
        );
    }
    let bucket = runtime.reverse_bucket(reverse).unwrap();
    let colliding: Vec<Ipv4Address> = (10_000..2_000_000)
        .map(spread)
        .filter(|target| {
            runtime.reverse_bucket(ResolutionGenerationToken {
                egress: WAN,
                target: *target,
                generation: 1,
            }) == Some(bucket)
        })
        .take(200)
        .collect();
    assert_eq!(colliding.len(), 200);
    runtime.take_visits();
    for target in &colliding {
        let token = ResolutionGenerationToken {
            egress: WAN,
            target: *target,
            generation: 1,
        };
        // The alias check of a new generation, then a new state whose
        // first generation (1) collides with the crowded bucket.
        assert!(!runtime.token_in_use(token));
        assert!(runtime.take_visits() <= PER_PACKET_VISITS);
        assert_eq!(
            runtime.schedule(arp_action(WAN, *target), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        assert!(runtime.take_visits() <= PER_PACKET_VISITS);
        // Expiry of a colliding token clears nothing and stays cheap.
        runtime.cancel_holds_of_token(token);
        assert!(runtime.take_visits() <= PER_PACKET_VISITS);
    }
    assert_eq!(runtime.pending_failure_holds(), holds);
    assert!(runtime.token_in_use(reverse));
    // The crowded token itself is cleared at one visit per hold.
    runtime.take_visits();
    runtime.cancel_holds_of_token(reverse);
    assert_eq!(runtime.pending_failure_holds(), 0);
    assert!(runtime.take_visits() <= holds as u64 + 4);
    assert!(runtime.indexes_valid());
}

/// Group bookkeeping: a leader hands its place to the next hold of its
/// token, members leave from the middle, and a hold moving to another
/// reverse token changes group.
#[test]
fn reverse_groups_survive_leaders_and_members_leaving() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut tables = Tables::new(4, 4, 1, 8);
    let mut runtime = tables.runtime(policy);
    let token = |last: u8| ResolutionGenerationToken {
        egress: LAN,
        target: Ipv4Address::from_octets([10, 0, 1, last]),
        generation: 1,
    };
    for index in 0..6 {
        runtime.install_hold_for_test(
            index,
            ResolutionFailureHoldPhase::WaitingReverse,
            ResolutionGenerationToken {
                egress: WAN,
                target: spread(index),
                generation: 1,
            },
            token(if index < 4 { 7 } else { 8 }),
        );
        assert!(runtime.indexes_valid());
    }
    // A middle member, then the leader, then a move to the other token.
    runtime.clear_failure_hold(2);
    assert!(runtime.indexes_valid());
    runtime.clear_failure_hold(0);
    assert!(runtime.indexes_valid());
    runtime.wait_reverse(1, token(8));
    assert!(runtime.indexes_valid());
    runtime.wait_reverse(4, token(9));
    assert!(runtime.indexes_valid());
    assert!(runtime.token_in_use(token(7)));
    runtime.cancel_holds_of_token(token(7));
    assert!(!runtime.token_in_use(token(7)));
    runtime.cancel_holds_of_token(token(8));
    runtime.cancel_holds_of_token(token(9));
    assert_eq!(runtime.pending_failure_holds(), 0);
    assert!(runtime.indexes_valid());
    assert!(runtime
        .failure_holds
        .iter()
        .all(|hold| *hold == ResolutionFailureHoldSlot::EMPTY));
}

/// H4b review core L2: the timer poll drains expired entries off the
/// time-ordered lists a scan budget at a time, so the insert after a quiet
/// period does not pay for every entry that expired meanwhile.
#[test]
fn timer_polls_drain_expired_entries_in_the_background() {
    let policy = ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 1_000, 100).unwrap();
    let slots = PRODUCTION_QUOTE_SLOTS;
    let mut tables = Tables::new(slots, slots, slots, 1);
    let mut runtime = tables.runtime(policy);
    let mac = MacAddress([2, 7, 7, 7, 7, 7]);
    for index in 0..slots {
        runtime.merge_dynamic(WAN, spread(index), mac, true, false, MonotonicMillis(0));
        runtime.schedule(arp_action(LAN, spread(index)), MonotonicMillis(0), false);
        let front = runtime.front().unwrap();
        runtime.committed(front, MonotonicMillis(0));
        runtime.clear_resolution(LAN, spread(index));
    }
    assert_eq!(runtime.cooldown_count(), slots);
    let budget = 64;
    for _ in 0..slots / budget {
        runtime.take_visits();
        poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(1_000),
            budget,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        // Each list at most one budget plus the head that stops it.
        assert!(runtime.take_visits() <= 2 * (budget as u64 + 1));
    }
    assert_eq!(runtime.dynamic_order, SlotList::EMPTY);
    assert_eq!(runtime.request_order, SlotList::EMPTY);
    runtime.take_visits();
    assert_eq!(
        runtime.merge_dynamic(WAN, spread(slots), mac, true, false, MonotonicMillis(1_000)),
        ControlDisposition::Inserted
    );
    assert_eq!(
        runtime.schedule(
            arp_action(LAN, spread(slots)),
            MonotonicMillis(1_000),
            false
        ),
        ResolutionResult::Queued
    );
    assert!(runtime.take_visits() <= 2 * PER_PACKET_VISITS);
    assert!(runtime.indexes_valid());
}

#[test]
fn a_new_generation_skips_a_live_reverse_token() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut tables = Tables::new(1, 1, 1, 2);
    let mut runtime = tables.runtime(policy);
    runtime.states[0].entry.generation = 5;
    let key_target = Ipv4Address::from_octets([10, 0, 2, 9]);
    // A hold elsewhere waits for reverse resolution (WAN, key_target) at
    // generation 6, the generation the slot would hand out next.
    runtime.install_hold_for_test(
        0,
        ResolutionFailureHoldPhase::WaitingReverse,
        ResolutionGenerationToken {
            egress: LAN,
            target: Ipv4Address::from_octets([10, 0, 1, 9]),
            generation: 1,
        },
        ResolutionGenerationToken {
            egress: WAN,
            target: key_target,
            generation: 6,
        },
    );
    assert_eq!(
        runtime.schedule(arp_action(WAN, key_target), MonotonicMillis(0), false),
        ResolutionResult::Queued
    );
    assert_eq!(runtime.status(WAN, key_target).unwrap().generation, 7);
    assert!(runtime.indexes_valid());
}

#[test]
fn corrupt_indexes_fail_closed_on_the_packet_path() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut tables = Tables::new(8, 8, 8, 8);
    let mut runtime = tables.runtime(policy);
    assert_eq!(
        runtime.schedule(arp_action(WAN, spread(1)), MonotonicMillis(0), false),
        ResolutionResult::Queued
    );
    let bucket = runtime
        .state_bucket(ResolutionKey {
            egress: WAN,
            target: spread(1),
        })
        .unwrap();
    // A bucket head pointing outside the table.
    runtime.states[bucket].bucket_head = 1_000;
    let before: Vec<_> = runtime.states.iter().map(|slot| slot.entry).collect();
    assert_eq!(
        runtime.schedule(arp_action(WAN, spread(1)), MonotonicMillis(0), false),
        ResolutionResult::StateFull
    );
    assert_eq!(runtime.index_counters().index_corrupt, 1);
    let after: Vec<_> = runtime.states.iter().map(|slot| slot.entry).collect();
    assert_eq!(before, after, "nothing changed");
    assert_eq!(
        runtime.preflight_publication().err(),
        Some(ResolutionPublicationError::IndexCorrupt)
    );
}

/// Before/after timing in a release build (`cargo test --release -p
/// ruster-core --lib -- --ignored --nocapture timing`). "before" is the
/// pre-H4b runtime (`resolution_reference`), "after" the indexed one, on
/// the same operations with tables at the given capacity.
#[test]
#[ignore = "release timing report; run explicitly"]
fn timing_report_before_and_after_h4b() {
    use std::time::Instant;
    for slots in [4_096usize, 65_536] {
        let policy = ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 1_000, 600_000).unwrap();
        let mac = MacAddress([2, 3, 4, 5, 6, 7]);
        let rounds = if slots > 10_000 { 2_000 } else { 20_000 };
        let mut tables = Tables::new(slots, slots, slots, PRODUCTION_QUOTE_SLOTS);
        let mut new = tables.runtime(policy);
        let mut old_states = vec![RefState::EMPTY; slots];
        let mut old_actions = vec![RefAction::EMPTY; slots];
        let mut old_dynamic = vec![RefDynamic::EMPTY; slots];
        let mut old_holds = vec![RefHold::EMPTY; PRODUCTION_QUOTE_SLOTS];
        let mut old = RefRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut old_states,
            &mut old_actions,
            &mut old_dynamic,
            &mut old_holds,
        );
        for index in 0..slots {
            new.merge_dynamic(LAN, spread(index), mac, true, false, MonotonicMillis(0));
            old.merge_dynamic(LAN, spread(index), mac, true, false, MonotonicMillis(0));
            new.schedule(arp_action(WAN, spread(index)), MonotonicMillis(0), false);
            old.schedule(arp_action(WAN, spread(index)), MonotonicMillis(0), false);
        }
        macro_rules! time {
            ($label:expr, $runtime:ident, $op:expr) => {{
                let start = Instant::now();
                for index in 0..rounds {
                    let $runtime = &mut $runtime;
                    std::hint::black_box($op(&mut *$runtime, index));
                }
                let ns = start.elapsed().as_nanos() / rounds as u128;
                eprintln!("H4B_TIMING slots={slots} {} {ns} ns/op", $label);
            }};
        }
        time!(
            "before dynamic-miss lookup",
            old,
            |runtime: &mut RefRuntime<'_>, index| runtime.lookup_dynamic(
                WAN,
                spread(index),
                MonotonicMillis(1)
            )
        );
        time!(
            "after  dynamic-miss lookup",
            new,
            |runtime: &mut ResolutionRuntime<'_>, index| runtime.lookup_dynamic(
                WAN,
                spread(index),
                MonotonicMillis(1)
            )
        );
        time!(
            "before arp-flood merge (cache full)",
            old,
            |runtime: &mut RefRuntime<'_>, index| runtime.merge_dynamic(
                WAN,
                spread(index),
                mac,
                true,
                false,
                MonotonicMillis(1)
            )
        );
        time!(
            "after  arp-flood merge (cache full)",
            new,
            |runtime: &mut ResolutionRuntime<'_>, index| runtime.merge_dynamic(
                WAN,
                spread(index),
                mac,
                true,
                false,
                MonotonicMillis(1)
            )
        );
        time!(
            "before schedule new target (states full)",
            old,
            |runtime: &mut RefRuntime<'_>, index| runtime.schedule(
                arp_action(LAN, spread(index)),
                MonotonicMillis(1),
                false
            )
        );
        time!(
            "after  schedule new target (states full)",
            new,
            |runtime: &mut ResolutionRuntime<'_>, index| runtime.schedule(
                arp_action(LAN, spread(index)),
                MonotonicMillis(1),
                false
            )
        );
        time!(
            "before arp update of a pending target",
            old,
            |runtime: &mut RefRuntime<'_>, index| runtime.merge_dynamic(
                LAN,
                spread(index % slots),
                mac,
                false,
                false,
                MonotonicMillis(1)
            )
        );
        time!(
            "after  arp update of a pending target",
            new,
            |runtime: &mut ResolutionRuntime<'_>, index| runtime.merge_dynamic(
                LAN,
                spread(index % slots),
                mac,
                false,
                false,
                MonotonicMillis(1)
            )
        );
        // The one-off maturation pass: the first insert after every learned
        // entry expired takes all of them off the refresh order at once.
        let start = Instant::now();
        assert_eq!(
            new.merge_dynamic(
                WAN,
                spread(3 * slots),
                mac,
                true,
                false,
                MonotonicMillis(600_001)
            ),
            ControlDisposition::Inserted
        );
        eprintln!(
            "H4B_TIMING slots={slots} after  first insert after all entries expired {} ns",
            start.elapsed().as_nanos()
        );
    }
}

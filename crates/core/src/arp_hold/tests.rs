//! Unit tests of the ARP hold table (ARP-HOLD): bounds, latest-datagram
//! replacement, the age and free lists, readiness, expiry, the replay batch,
//! and staging. The end-to-end behaviour (forwarding, the tick, NAT,
//! firewall, fragments) is in `crates/io-sim/tests/arp_hold.rs`.

use super::{
    ArpHoldFragmentHook, ArpHoldMiss, ArpHoldNextHop, ArpHoldPolicy, ArpHoldPolicyError,
    ArpHoldRuntime, ArpHoldSlot, ArpHoldStorageError, HoldState, ARP_HOLD_MAX_PACKETS,
    ARP_HOLD_MAX_PER_NEIGHBOR, NONE,
};
use crate::{
    ipv4_fragment_slot_bytes, ConsumeReason, DropReason, ForwardingSnapshot, IfId, Interface,
    Ipv4Address, Ipv4FragmentSlot, Ipv4FragmentationPolicy, Ipv4FragmentationRuntime,
    LocalIpv4Binding, MacAddress, PacketBatch, Route,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const OTHER: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 50]);
const SLOT: usize = ipv4_fragment_slot_bytes(1500);

/// An Ethernet + IPv4 frame from `source` of `len` bytes; byte 42 carries
/// `tag` so a frame can be told apart after a replay.
fn frame(source: [u8; 4], len: usize, tag: u8) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    bytes[12..14].copy_from_slice(&[0x08, 0x00]);
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&u16::try_from(len - 14).unwrap().to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&source);
    bytes[30..34].copy_from_slice(&[198, 51, 100, 20]);
    if len > 42 {
        bytes[42] = tag;
    }
    bytes
}

fn miss(target: Ipv4Address, deadline_ms: u64) -> ArpHoldMiss {
    ArpHoldMiss {
        egress: WAN,
        target,
        deadline_ms,
    }
}

struct Table {
    slots: Vec<ArpHoldSlot>,
    bytes: Vec<u8>,
}

impl Table {
    fn new(slots: usize) -> Self {
        Self {
            slots: vec![ArpHoldSlot::EMPTY; slots],
            bytes: vec![0xaa; slots * SLOT],
        }
    }

    fn runtime(&mut self, per_neighbor: u16, per_host: u16) -> ArpHoldRuntime<'_> {
        ArpHoldRuntime::new(
            ArpHoldPolicy::new(per_neighbor, per_host).unwrap(),
            &mut self.slots,
            &mut self.bytes,
        )
        .unwrap()
    }
}

/// The held frames' tags, oldest first, walking the age list both ways.
fn tags(runtime: &ArpHoldRuntime<'_>) -> Vec<u8> {
    let mut forward = Vec::new();
    let mut cursor = runtime.oldest;
    let mut last = NONE;
    while cursor != NONE {
        let slot = runtime.slots[cursor as usize];
        assert_eq!(slot.older, last, "the age list links back");
        assert_ne!(slot.state, HoldState::Free);
        forward.push(runtime.bytes[cursor as usize * runtime.slot_bytes + 42]);
        last = cursor;
        cursor = slot.newer;
    }
    assert_eq!(runtime.newest, last);
    assert_eq!(forward.len(), runtime.live());
    // Every other slot is on the free list exactly once.
    let mut free = 0;
    let mut cursor = runtime.free;
    while cursor != NONE {
        assert_eq!(runtime.slots[cursor as usize].state, HoldState::Free);
        free += 1;
        cursor = runtime.slots[cursor as usize].newer;
    }
    assert_eq!(free + runtime.live(), runtime.slot_capacity());
    forward
}

fn snapshot() -> ForwardingSnapshot<'static> {
    let routes = Box::leak(Box::new([
        Route::new(Ipv4Address::from_octets([192, 168, 1, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GW)).unwrap(),
        Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, WAN, None).unwrap(),
    ]));
    let interfaces = Box::leak(Box::new([
        Interface {
            id: LAN,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: 576,
        },
    ]));
    let bindings = Box::leak(Box::new([
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([192, 168, 1, 1]),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: Ipv4Address::from_octets([203, 0, 113, 2]),
        },
    ]));
    ForwardingSnapshot::new(&routes[..], &interfaces[..], &[], &bindings[..]).unwrap()
}

#[test]
fn policy_and_storage_bounds_fail_closed() {
    assert_eq!(
        ArpHoldPolicy::new(0, 1),
        Err(ArpHoldPolicyError::PerNeighbor)
    );
    assert_eq!(
        ArpHoldPolicy::new(ARP_HOLD_MAX_PER_NEIGHBOR + 1, 1),
        Err(ArpHoldPolicyError::PerNeighbor)
    );
    assert_eq!(ArpHoldPolicy::new(1, 0), Err(ArpHoldPolicyError::PerHost));
    let edge = ArpHoldPolicy::new(ARP_HOLD_MAX_PER_NEIGHBOR, 1).unwrap();
    assert_eq!(
        (edge.per_neighbor(), edge.per_host()),
        (ARP_HOLD_MAX_PER_NEIGHBOR, 1)
    );
    assert_eq!(ArpHoldPolicy::default(), ArpHoldPolicy::DEFAULT);
    assert_eq!(
        (
            ArpHoldPolicy::DEFAULT.per_neighbor(),
            ArpHoldPolicy::DEFAULT.per_host()
        ),
        (3, 16)
    );

    let policy = ArpHoldPolicy::DEFAULT;
    let mut slots = vec![ArpHoldSlot::EMPTY; 2];
    // Not whole slots, too small a slot, too large a slot.
    for len in [2 * SLOT + 1, 2 * (14 + 67), 2 * (14 + 65_536)] {
        let mut bytes = vec![0; len];
        assert_eq!(
            ArpHoldRuntime::new(policy, &mut slots, &mut bytes).err(),
            Some(ArpHoldStorageError::SlotBytes),
            "{len}"
        );
    }
    // The smallest and the largest valid slot.
    for len in [2 * (14 + 68), 2 * (14 + 65_535)] {
        let mut bytes = vec![0; len];
        assert!(ArpHoldRuntime::new(policy, &mut slots, &mut bytes).is_ok());
    }
    let mut none: [ArpHoldSlot; 0] = [];
    assert_eq!(
        ArpHoldRuntime::new(policy, &mut none, &mut [0]).err(),
        Some(ArpHoldStorageError::SlotBytes)
    );
    let mut too_many = vec![ArpHoldSlot::EMPTY; ARP_HOLD_MAX_PACKETS as usize + 1];
    let mut bytes = vec![0; too_many.len() * (14 + 68)];
    assert_eq!(
        ArpHoldRuntime::new(policy, &mut too_many, &mut bytes).err(),
        Some(ArpHoldStorageError::TooManySlots)
    );
    let mut max = vec![ArpHoldSlot::EMPTY; ARP_HOLD_MAX_PACKETS as usize];
    let mut bytes = vec![0; max.len() * (14 + 68)];
    assert!(ArpHoldRuntime::new(policy, &mut max, &mut bytes).is_ok());
}

#[test]
fn a_new_table_is_empty_and_zeroed() {
    let mut table = Table::new(3);
    let runtime = table.runtime(3, 16);
    assert_eq!(runtime.live(), 0);
    assert_eq!(runtime.slot_capacity(), 3);
    assert_eq!(runtime.slot_bytes(), SLOT);
    assert_eq!(runtime.policy(), ArpHoldPolicy::new(3, 16).unwrap());
    assert!(tags(&runtime).is_empty());
    assert!(runtime.bytes.iter().all(|byte| *byte == 0));
}

#[test]
fn holds_copy_the_frame_and_record_the_next_hop() {
    let mut table = Table::new(4);
    let mut runtime = table.runtime(3, 16);
    let held = frame([192, 168, 1, 10], 60, 7);
    runtime
        .hold(&held, LAN, miss(GW, 3_000), |_, _, _, _| {})
        .unwrap();
    assert_eq!(runtime.live(), 1);
    let slot = runtime.slots[runtime.oldest as usize];
    assert_eq!(
        (
            slot.state,
            slot.ingress,
            slot.egress,
            slot.target,
            slot.source,
            slot.deadline_ms,
            slot.frame_len
        ),
        (
            HoldState::Held,
            LAN,
            WAN,
            GW,
            Ipv4Address::from_octets([192, 168, 1, 10]),
            3_000,
            60
        )
    );
    let range = runtime.range(runtime.oldest as usize);
    assert_eq!(&runtime.bytes[range], &held[..]);
    assert_eq!(runtime.counters().held, 1);
}

#[test]
fn the_latest_datagrams_per_next_hop_are_kept() {
    let mut table = Table::new(8);
    let mut runtime = table.runtime(3, 16);
    for tag in 1..=5 {
        runtime
            .hold(
                &frame([192, 168, 1, 10], 60, tag),
                LAN,
                miss(GW, 3_000),
                |_, _, _, _| {},
            )
            .unwrap();
    }
    // Another next hop is not touched by GW's replacements.
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 9),
            LAN,
            miss(OTHER, 3_000),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 6),
            LAN,
            miss(GW, 3_000),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(tags(&runtime), [4, 5, 9, 6]);
    let counters = runtime.counters();
    assert_eq!((counters.held, counters.replaced), (7, 3));
}

#[test]
fn one_per_next_hop_keeps_only_the_latest() {
    let mut table = Table::new(2);
    let mut runtime = table.runtime(1, 16);
    for tag in 1..=3 {
        runtime
            .hold(
                &frame([192, 168, 1, 10], 60, tag),
                LAN,
                miss(GW, 3_000),
                |_, _, _, _| {},
            )
            .unwrap();
        assert_eq!(tags(&runtime), [tag]);
    }
}

#[test]
fn the_per_host_bound_is_per_ingress_and_source() {
    let mut table = Table::new(8);
    let mut runtime = table.runtime(8, 2);
    let host = [192, 168, 1, 10];
    runtime
        .hold(&frame(host, 60, 1), LAN, miss(GW, 3_000), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(
            &frame(host, 60, 2),
            LAN,
            miss(OTHER, 3_000),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(
        runtime.hold(&frame(host, 60, 3), LAN, miss(GW, 3_000), |_, _, _, _| {}),
        Err(DropReason::ArpHoldHostLimit)
    );
    // The same source on another ingress, and another source, are other
    // hosts.
    runtime
        .hold(&frame(host, 60, 4), WAN, miss(GW, 3_000), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(
            &frame([192, 168, 1, 11], 60, 5),
            LAN,
            miss(GW, 3_000),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(tags(&runtime), [1, 2, 4, 5]);
    let counters = runtime.counters();
    assert_eq!((counters.held, counters.refused_host_limit), (4, 1));
}

#[test]
fn a_replacement_from_the_same_host_does_not_count_against_it() {
    let mut table = Table::new(4);
    let mut runtime = table.runtime(1, 1);
    let host = [192, 168, 1, 10];
    runtime
        .hold(&frame(host, 60, 1), LAN, miss(GW, 3_000), |_, _, _, _| {})
        .unwrap();
    // At its host bound, H may still replace its own datagram to GW...
    runtime
        .hold(&frame(host, 60, 2), LAN, miss(GW, 3_000), |_, _, _, _| {})
        .unwrap();
    assert_eq!(tags(&runtime), [2]);
    // ...but not hold one for another next hop.
    assert_eq!(
        runtime.hold(
            &frame(host, 60, 3),
            LAN,
            miss(OTHER, 3_000),
            |_, _, _, _| {}
        ),
        Err(DropReason::ArpHoldHostLimit)
    );
    // And another host at its own bound cannot evict H's datagram through
    // the next-hop bound unless it has room itself.
    let mut table = Table::new(4);
    let mut runtime = table.runtime(1, 1);
    let other = [192, 168, 1, 11];
    runtime
        .hold(&frame(host, 60, 1), LAN, miss(GW, 3_000), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(
            &frame(other, 60, 2),
            LAN,
            miss(OTHER, 3_000),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(
        runtime.hold(&frame(other, 60, 3), LAN, miss(GW, 3_000), |_, _, _, _| {}),
        Err(DropReason::ArpHoldHostLimit)
    );
    assert_eq!(tags(&runtime), [1, 2]);
}

#[test]
fn a_full_table_refuses_and_a_long_frame_is_refused() {
    let mut table = Table::new(2);
    let mut runtime = table.runtime(3, 16);
    let targets = [GW, OTHER, Ipv4Address::from_octets([203, 0, 113, 51])];
    for (tag, target) in (1..).zip(&targets[..2]) {
        runtime
            .hold(
                &frame([192, 168, 1, tag], 60, tag),
                LAN,
                miss(*target, 1),
                |_, _, _, _| {},
            )
            .unwrap();
    }
    assert_eq!(
        runtime.hold(
            &frame([192, 168, 1, 3], 60, 3),
            LAN,
            miss(targets[2], 1),
            |_, _, _, _| {}
        ),
        Err(DropReason::ArpHoldFull)
    );
    // A next hop at its bound still replaces in a full table.
    let mut table = Table::new(2);
    let mut runtime = table.runtime(1, 16);
    runtime
        .hold(
            &frame([192, 168, 1, 1], 60, 1),
            LAN,
            miss(GW, 1),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime
        .hold(
            &frame([192, 168, 1, 2], 60, 2),
            LAN,
            miss(OTHER, 1),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime
        .hold(
            &frame([192, 168, 1, 3], 60, 3),
            LAN,
            miss(GW, 1),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(tags(&runtime), [2, 3]);

    let mut table = Table::new(2);
    let mut runtime = table.runtime(3, 16);
    // Exactly a slot is held; one byte more is refused.
    runtime
        .hold(
            &frame([192, 168, 1, 1], SLOT, 1),
            LAN,
            miss(GW, 1),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(
        runtime.hold(
            &frame([192, 168, 1, 1], SLOT + 1, 2),
            LAN,
            miss(GW, 1),
            |_, _, _, _| {}
        ),
        Err(DropReason::ArpHoldTooLarge)
    );
    let counters = runtime.counters();
    assert_eq!((counters.held, counters.refused_too_large), (1, 1));

    // No slot at all: every hold is refused as full.
    let mut none: [ArpHoldSlot; 0] = [];
    let mut runtime = ArpHoldRuntime::new(ArpHoldPolicy::DEFAULT, &mut none, &mut []).unwrap();
    assert_eq!(
        runtime.hold(
            &frame([192, 168, 1, 1], 60, 1),
            LAN,
            miss(GW, 1),
            |_, _, _, _| {}
        ),
        Err(DropReason::ArpHoldFull)
    );
    assert_eq!(runtime.counters().refused_full, 1);
}

#[test]
fn a_short_frame_without_a_source_is_held_under_the_zero_source() {
    let mut table = Table::new(2);
    let mut runtime = table.runtime(3, 1);
    runtime
        .hold(&[0; 20], LAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    assert_eq!(
        runtime.slots[runtime.oldest as usize].source,
        Ipv4Address::from_octets([0; 4])
    );
    assert_eq!(
        runtime.hold(&[0; 20], LAN, miss(OTHER, 1), |_, _, _, _| {}),
        Err(DropReason::ArpHoldHostLimit)
    );
}

#[test]
fn releasing_any_slot_keeps_both_lists() {
    for victim in 0..4_u8 {
        let mut table = Table::new(4);
        let mut runtime = table.runtime(3, 16);
        for tag in 0..4_u8 {
            runtime
                .hold(
                    &frame([192, 168, 1, tag], 60, tag),
                    LAN,
                    miss(Ipv4Address::from_octets([203, 0, 113, 10 + tag]), 1),
                    |_, _, _, _| {},
                )
                .unwrap();
        }
        let index = (0..4)
            .find(|index| runtime.bytes[index * SLOT + 42] == victim)
            .unwrap();
        runtime.release(index);
        let expected: Vec<u8> = (0..4).filter(|tag| *tag != victim).collect();
        assert_eq!(tags(&runtime), expected, "victim {victim}");
        // The freed slot is reused first.
        runtime
            .hold(
                &frame([10, 0, 0, 1], 60, 9),
                LAN,
                miss(GW, 1),
                |_, _, _, _| {},
            )
            .unwrap();
        assert_eq!(runtime.newest as usize, index);
        assert_eq!(tags(&runtime).last(), Some(&9));
    }
}

fn occupancy(runtime: &ArpHoldRuntime<'_>) -> (usize, usize, usize) {
    let occupancy = runtime.occupancy();
    assert_eq!(occupancy.occupied(), runtime.live());
    (
        occupancy.occupied(),
        occupancy.high_water(),
        occupancy.capacity(),
    )
}

/// OBS-017: the held-datagram high-water mark follows each hold, stays
/// through a replacement at the per-neighbor limit, and keeps the peak
/// after a slot is freed.
#[test]
fn held_high_water_follows_holds_and_survives_releases() {
    let mut table = Table::new(3);
    let mut runtime = table.runtime(2, 16);
    assert_eq!(occupancy(&runtime), (0, 0, 3));
    for tag in 1..=2 {
        runtime
            .hold(
                &frame([192, 168, 1, 10], 60, tag),
                LAN,
                miss(GW, 1),
                |_, _, _, _| {},
            )
            .unwrap();
    }
    assert_eq!(occupancy(&runtime), (2, 2, 3));
    // The per-neighbor limit replaces the oldest: the count is unchanged.
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 3),
            LAN,
            miss(GW, 1),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(occupancy(&runtime), (2, 2, 3));
    runtime
        .hold(
            &frame([192, 168, 1, 11], 60, 4),
            LAN,
            miss(OTHER, 1),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(occupancy(&runtime), (3, 3, 3));
    let oldest = runtime.oldest as usize;
    runtime.release(oldest);
    assert_eq!(occupancy(&runtime), (2, 3, 3));
}

#[test]
fn flush_frees_everything_and_counts_it() {
    let mut table = Table::new(3);
    let mut runtime = table.runtime(3, 16);
    for tag in 1..=2 {
        runtime
            .hold(
                &frame([192, 168, 1, 10], 60, tag),
                LAN,
                miss(GW, 1),
                |_, _, _, _| {},
            )
            .unwrap();
    }
    assert_eq!(occupancy(&runtime), (2, 2, 3));
    assert_eq!(runtime.flush(), 2);
    assert_eq!(occupancy(&runtime), (0, 0, 3), "a flush restarts the mark");
    assert_eq!(runtime.live(), 0);
    assert!(tags(&runtime).is_empty());
    assert_eq!(runtime.counters().flushed, 2);
    assert_eq!(runtime.flush(), 0);
    assert_eq!(runtime.counters().flushed, 2);
    // Usable again with all three slots.
    for tag in 1..=3 {
        runtime
            .hold(
                &frame([192, 168, 1, tag], 60, tag),
                LAN,
                miss(Ipv4Address::from_octets([203, 0, 113, tag]), 1),
                |_, _, _, _| {},
            )
            .unwrap();
    }
    assert_eq!(tags(&runtime), [1, 2, 3]);
}

#[test]
fn mark_ready_replays_known_next_hops_within_room_and_frees_the_rest() {
    let mut table = Table::new(8);
    let mut runtime = table.runtime(8, 16);
    let resolving = Ipv4Address::from_octets([203, 0, 113, 60]);
    let over = Ipv4Address::from_octets([203, 0, 113, 61]);
    let holds = [
        (1, GW, 5_000),
        (2, resolving, 5_000),
        (3, GW, 5_000),
        (4, over, 5_000),
        (5, resolving, 1_000),
        (6, GW, 1_000),
        (7, GW, 5_000),
    ];
    for (tag, target, deadline) in holds {
        runtime
            .hold(
                &frame([192, 168, 1, tag], 60, tag),
                LAN,
                miss(target, deadline),
                |_, _, _, _| {},
            )
            .unwrap();
    }
    let probe = |_: IfId, target: Ipv4Address| match target {
        GW => ArpHoldNextHop::Known,
        t if t == resolving => ArpHoldNextHop::Resolving,
        _ => ArpHoldNextHop::Failed,
    };
    // Room for two at 1_000: 1 and 3 are ready; 6 is known but has no room
    // and its deadline passed; 7 is deferred; 5 expired; 4 failed; 2 waits.
    assert_eq!(runtime.mark_ready(1_000, 2, probe, |_| 0), 2);
    let states: Vec<(u8, HoldState)> = {
        let mut out = Vec::new();
        let mut cursor = runtime.oldest;
        while cursor != NONE {
            let slot = runtime.slots[cursor as usize];
            out.push((runtime.bytes[cursor as usize * SLOT + 42], slot.state));
            cursor = slot.newer;
        }
        out
    };
    assert_eq!(
        states,
        [
            (1, HoldState::Ready),
            (2, HoldState::Held),
            (3, HoldState::Ready),
            (7, HoldState::Held),
        ]
    );
    let counters = runtime.counters();
    assert_eq!(
        (counters.expired, counters.failed, counters.deferred),
        (2, 1, 1)
    );
    // A second pass skips the ready ones; one deadline exactly reached.
    assert_eq!(runtime.mark_ready(4_999, 0, probe, |_| 0), 0);
    assert_eq!(runtime.counters().deferred, 2);
    assert_eq!(runtime.mark_ready(5_000, 0, probe, |_| 0), 0);
    assert_eq!(tags(&runtime), [1, 3]);
    assert_eq!(runtime.counters().expired, 4);
}

#[test]
fn the_replay_batch_lends_ready_datagrams_and_settles_each_completion() {
    let mut table = Table::new(6);
    let mut runtime = table.runtime(8, 16);
    for tag in 1..=5 {
        runtime
            .hold(
                &frame([192, 168, 1, 10], 60, tag),
                LAN,
                miss(GW, 9_000),
                |_, _, _, _| {},
            )
            .unwrap();
    }
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 6),
            WAN,
            miss(OTHER, 9_000),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(
        runtime.mark_ready(
            0,
            5,
            |_, target| if target == GW {
                ArpHoldNextHop::Known
            } else {
                ArpHoldNextHop::Resolving
            },
            |_| 0
        ),
        5
    );
    let mut batch = runtime.replay_batch();
    let mut seen = Vec::new();
    fn tag_of<S: crate::PacketSlot>(lease: &mut crate::PacketLease<S>) -> u8 {
        let bytes: &mut [u8] = lease.bytes_mut();
        assert_eq!(bytes.len(), 60);
        bytes[42]
    }
    let mut first = batch.next_packet().unwrap();
    assert_eq!(first.ingress(), LAN);
    seen.push(tag_of(&mut first));
    // The replay rewrites the frame in place, then commits it.
    first.bytes_mut()[43] = 0xee;
    first.commit(LAN);
    let mut second = batch.next_packet().unwrap();
    seen.push(tag_of(&mut second));
    second.consume(ConsumeReason::Ipv4Fragmented);
    let mut third = batch.next_packet().unwrap();
    seen.push(tag_of(&mut third));
    third.recycle(DropReason::FirewallRuleDenied);
    let mut fourth = batch.next_packet().unwrap();
    seen.push(tag_of(&mut fourth));
    fourth.consume(ConsumeReason::ArpControl);
    let mut fifth = batch.next_packet().unwrap();
    seen.push(tag_of(&mut fifth));
    drop(fifth);
    assert!(batch.next_packet().is_none());
    let completion = batch.finish();
    assert_eq!(seen, [1, 2, 3, 4, 5]);
    assert_eq!(
        (
            completion.tx_requested,
            completion.tx_accepted,
            completion.tx_rejected,
            completion.recycled,
            completion.error
        ),
        (1, 1, 0, 4, None)
    );
    assert!(completion.invariants_hold());
    let counters = runtime.counters();
    assert_eq!(
        (
            counters.replayed,
            counters.replay_fragmented,
            counters.replay_dropped
        ),
        (5, 1, 3)
    );
    // The committed one waits for staging on the egress it was given; the
    // one that was not ready is untouched.
    assert_eq!(tags(&runtime), [1, 6]);
    let committed = runtime.slots[runtime.oldest as usize];
    assert_eq!(
        (committed.state, committed.egress),
        (HoldState::Committed, LAN)
    );
}

#[test]
fn staging_sends_committed_datagrams_whole_and_returns_unreached_ones() {
    let snapshot = snapshot();
    let mut fragment_slots = vec![Ipv4FragmentSlot::EMPTY; 2];
    let mut fragment_bytes = vec![0; 2 * SLOT];
    let mut fragmentation = Ipv4FragmentationRuntime::new(
        Ipv4FragmentationPolicy::DEFAULT,
        &mut fragment_slots,
        &mut fragment_bytes,
    )
    .unwrap();
    assert_eq!(fragmentation.free_slots(), 2);
    let mut table = Table::new(4);
    let mut runtime = table.runtime(8, 16);
    // Padded to 64 bytes: the datagram is 46 bytes.
    let mut padded = frame([192, 168, 1, 10], 60, 1);
    padded[16..18].copy_from_slice(&46_u16.to_be_bytes());
    padded.extend_from_slice(&[0; 4]);
    runtime
        .hold(&padded, LAN, miss(GW, 9_000), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 2),
            LAN,
            miss(GW, 9_000),
            |_, _, _, _| {},
        )
        .unwrap();
    // DF set, so it cannot be cut either.
    let mut long = frame([192, 168, 1, 10], 600, 3);
    long[20] = 0x40;
    runtime
        .hold(&long, LAN, miss(GW, 9_000), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 4),
            LAN,
            miss(OTHER, 9_000),
            |_, _, _, _| {},
        )
        .unwrap();
    // Mark three ready (4's next hop resolves only later).
    runtime.mark_ready(
        0,
        3,
        |_, target| {
            if target == GW {
                ArpHoldNextHop::Known
            } else {
                ArpHoldNextHop::Resolving
            }
        },
        |_| 0,
    );
    {
        let mut batch = runtime.replay_batch();
        // 1 is committed on the WAN (MTU 576): staged whole without padding.
        batch.next_packet().unwrap().commit(WAN);
        // 2 is committed on an egress the snapshot does not know.
        batch.next_packet().unwrap().commit(IfId(9));
        // 3 (600 bytes with DF, above the WAN MTU) is committed: not
        // stageable.
        batch.next_packet().unwrap().commit(WAN);
    }
    runtime.stage_committed(&snapshot, &mut fragmentation);
    assert_eq!(tags(&runtime), [4]);
    assert_eq!(
        runtime.slots[runtime.oldest as usize].state,
        HoldState::Held
    );
    let counters = runtime.counters();
    assert_eq!((counters.replay_sent, counters.replay_unstaged), (1, 2));
    assert_eq!(fragmentation.pending(), 1);
    assert_eq!(fragmentation.free_slots(), 1, "one of two slots taken");
    assert_eq!(fragmentation.counters().queued, 1);

    // A ready datagram the replay did not reach goes back to waiting.
    let mut table = Table::new(2);
    let mut runtime = table.runtime(8, 16);
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 1),
            LAN,
            miss(GW, 9_000),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime.mark_ready(0, 1, |_, _| ArpHoldNextHop::Known, |_| 0);
    runtime.stage_committed(&snapshot, &mut fragmentation);
    assert_eq!(
        runtime.slots[runtime.oldest as usize].state,
        HoldState::Held
    );
    assert_eq!(runtime.counters().replay_sent, 0);
}

#[test]
fn the_per_ingress_bound_refuses_and_a_full_table_is_full_first() {
    assert_eq!(
        ArpHoldPolicy::DEFAULT.with_per_ingress(0),
        Err(ArpHoldPolicyError::PerIngress)
    );
    assert_eq!(ArpHoldPolicy::DEFAULT.per_ingress(), 32);
    let policy = ArpHoldPolicy::new(1, 16)
        .unwrap()
        .with_per_ingress(2)
        .unwrap();
    assert_eq!(policy.per_ingress(), 2);
    let mut table = Table::new(4);
    let mut runtime = ArpHoldRuntime::new(policy, &mut table.slots, &mut table.bytes).unwrap();
    let target = |last: u8| Ipv4Address::from_octets([203, 0, 113, last]);
    // Two spoofed sources on the WAN take the ingress share.
    runtime
        .hold(
            &frame([198, 51, 100, 1], 60, 1),
            WAN,
            miss(target(10), 1),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime
        .hold(
            &frame([198, 51, 100, 2], 60, 2),
            WAN,
            miss(target(11), 1),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(
        runtime.hold(
            &frame([198, 51, 100, 3], 60, 3),
            WAN,
            miss(target(12), 1),
            |_, _, _, _| {}
        ),
        Err(DropReason::ArpHoldIngressLimit)
    );
    // Replacing one of its own (same next hop) needs no more share.
    runtime
        .hold(
            &frame([198, 51, 100, 3], 60, 4),
            WAN,
            miss(target(11), 1),
            |_, _, _, _| {},
        )
        .unwrap();
    // The LAN still finds room.
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 5),
            LAN,
            miss(target(13), 1),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime
        .hold(
            &frame([192, 168, 1, 11], 60, 6),
            LAN,
            miss(target(14), 1),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(tags(&runtime), [1, 4, 5, 6]);
    // Full now: refused as full before the ingress share.
    assert_eq!(
        runtime.hold(
            &frame([192, 168, 1, 12], 60, 7),
            LAN,
            miss(target(15), 1),
            |_, _, _, _| {}
        ),
        Err(DropReason::ArpHoldFull)
    );
    let counters = runtime.counters();
    assert_eq!(
        (counters.refused_ingress_limit, counters.refused_full),
        (1, 1)
    );
}

#[test]
fn a_replacement_prefers_the_senders_own_datagram() {
    let mut table = Table::new(4);
    let mut runtime = table.runtime(2, 16);
    let a = [192, 168, 1, 10];
    let b = [192, 168, 1, 11];
    runtime
        .hold(&frame(b, 60, 1), LAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(&frame(a, 60, 2), LAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    // A's new datagram replaces A's own, not B's older one.
    runtime
        .hold(&frame(a, 60, 3), LAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    assert_eq!(tags(&runtime), [1, 3]);
    // C has none there: the oldest goes.
    runtime
        .hold(
            &frame([192, 168, 1, 12], 60, 4),
            LAN,
            miss(GW, 1),
            |_, _, _, _| {},
        )
        .unwrap();
    assert_eq!(tags(&runtime), [3, 4]);
}

#[test]
fn a_cancelled_resolution_is_counted_apart_from_a_failed_one() {
    let mut table = Table::new(4);
    let mut runtime = table.runtime(8, 16);
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 1),
            LAN,
            miss(GW, 9_000),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 2),
            LAN,
            miss(OTHER, 9_000),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime.mark_ready(
        0,
        4,
        |_, target| {
            if target == GW {
                ArpHoldNextHop::Gone
            } else {
                ArpHoldNextHop::Failed
            }
        },
        |_| 0,
    );
    let counters = runtime.counters();
    assert_eq!(
        (counters.cancelled, counters.failed, runtime.live()),
        (1, 1, 0)
    );
}

#[test]
fn a_first_fragment_needs_room_for_the_held_fragments() {
    let mut table = Table::new(4);
    let mut runtime = table.runtime(8, 16);
    let mut first = frame([192, 168, 1, 10], 60, 1);
    first[20] = 0x20; // MF, offset 0
    let mut later = frame([192, 168, 1, 10], 60, 2);
    later[20..22].copy_from_slice(&[0x20, 0x10]); // MF, offset 16
    runtime
        .hold(&first, LAN, miss(GW, 9_000), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(&later, LAN, miss(GW, 9_000), |_, _, _, _| {})
        .unwrap();
    let known = |_: IfId, _: Ipv4Address| ArpHoldNextHop::Known;
    // A first fragment costs 1 + 2 reserved: with 2 slots only the later
    // fragment (cost 1) is ready.
    assert_eq!(runtime.mark_ready(0, 2, known, |_| 2), 1);
    assert_eq!(runtime.counters().deferred, 1);
    runtime.stage_committed(&snapshot(), &mut {
        // Nothing committed: everything goes back to waiting.
        let slots = Box::leak(Box::new([Ipv4FragmentSlot::EMPTY; 1]));
        let bytes = Box::leak(vec![0_u8; SLOT].into_boxed_slice());
        Ipv4FragmentationRuntime::new(Ipv4FragmentationPolicy::DEFAULT, slots, bytes).unwrap()
    });
    assert_eq!(runtime.mark_ready(0, 4, known, |_| 2), 2);
}

#[test]
fn a_replacement_takes_from_the_sender_then_the_ingress_then_the_busiest_ingress() {
    let lan_a = [192, 168, 1, 10];
    let lan_b = [192, 168, 1, 11];
    let wan = [198, 51, 100, 1];
    // The sender's own first, then the same ingress's, even if a datagram
    // of another ingress is older.
    let mut table = Table::new(8);
    let mut runtime = table.runtime(2, 16);
    runtime
        .hold(&frame(wan, 60, 1), WAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(&frame(lan_a, 60, 2), LAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(&frame(lan_b, 60, 3), LAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    assert_eq!(tags(&runtime), [1, 3]);
    runtime
        .hold(&frame(lan_b, 60, 4), LAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    assert_eq!(tags(&runtime), [1, 4]);

    // Only another ingress's datagram there: the new datagram's ingress
    // holds fewer (0 against 2), so it may take it.
    let mut table = Table::new(8);
    let mut runtime = table.runtime(1, 16);
    runtime
        .hold(&frame(lan_a, 60, 1), LAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(&frame(lan_a, 60, 2), LAN, miss(OTHER, 1), |_, _, _, _| {})
        .unwrap();
    runtime
        .hold(&frame(wan, 60, 3), WAN, miss(GW, 1), |_, _, _, _| {})
        .unwrap();
    assert_eq!(tags(&runtime), [2, 3]);

    // Several other ingresses at this next hop: the oldest of the one
    // holding the most there goes, even when another one's is older; the
    // new ingress's datagrams elsewhere do not matter.
    let dmz = IfId(3);
    let mut table = Table::new(8);
    let mut runtime = table.runtime(3, 16);
    fn hold(
        runtime: &mut ArpHoldRuntime<'_>,
        tag: u8,
        source: [u8; 4],
        ingress: IfId,
        target: Ipv4Address,
    ) {
        runtime
            .hold(
                &frame(source, 60, tag),
                ingress,
                miss(target, 1),
                |_, _, _, _| {},
            )
            .unwrap();
    }
    hold(&mut runtime, 1, [10, 0, 0, 1], dmz, GW);
    hold(&mut runtime, 2, wan, WAN, GW);
    hold(&mut runtime, 3, [198, 51, 100, 2], WAN, GW);
    hold(&mut runtime, 4, lan_a, LAN, OTHER);
    hold(&mut runtime, 5, lan_b, LAN, GW);
    assert_eq!(tags(&runtime), [1, 3, 4, 5]);
    // A tie (DMZ 1, WAN 1, LAN 1 now): the oldest of the tied, DMZ's.
    hold(&mut runtime, 6, [10, 1, 0, 1], IfId(4), GW);
    assert_eq!(tags(&runtime), [3, 4, 5, 6]);
    assert_eq!(runtime.counters().replaced, 2);
}

#[test]
fn a_parked_replay_is_counted_apart_and_dropped_first_fragments_are_reported() {
    let mut table = Table::new(4);
    let mut runtime = table.runtime(8, 16);
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 1),
            LAN,
            miss(GW, 9_000),
            |_, _, _, _| {},
        )
        .unwrap();
    runtime.mark_ready(0, 1, |_, _| ArpHoldNextHop::Known, |_| 0);
    {
        let mut batch = runtime.replay_batch();
        batch
            .next_packet()
            .unwrap()
            .consume(ConsumeReason::Ipv4FragmentHeld);
    }
    let counters = runtime.counters();
    assert_eq!((counters.replay_parked, counters.replay_dropped), (1, 0));

    // A first fragment freed (expired here) with an association reports
    // it; a datagram without one does not.
    let mut first = frame([192, 168, 1, 10], 60, 2);
    first[20] = 0x20;
    runtime
        .hold(&first, WAN, miss(GW, 10), |_, _, _, _| {})
        .unwrap();
    runtime.set_newest_association((7, 3));
    runtime
        .hold(
            &frame([192, 168, 1, 10], 60, 3),
            LAN,
            miss(OTHER, 10),
            |_, _, _, _| {},
        )
        .unwrap();
    let mut reported = Vec::new();
    runtime.mark_ready(
        10,
        0,
        |_, _| ArpHoldNextHop::Resolving,
        |hook| {
            if let ArpHoldFragmentHook::Dropped {
                association,
                generation,
                ..
            } = hook
            {
                reported.push((association, generation));
            }
            0
        },
    );
    assert_eq!(reported, [(7, 3)]);
    assert_eq!(runtime.live(), 0);
}

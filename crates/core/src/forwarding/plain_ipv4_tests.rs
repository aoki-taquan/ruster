//! The short way (`plain_ipv4`) against the full way: on random tables and
//! frames, each batch is forwarded twice, once with the short way off, and
//! the frames as they leave, how each ended, the counts and the trace must be
//! the same.

use super::lookup_tests::{
    bits, interface_ids, ip, owner, probe_addresses, random_tables, Rng, Tables,
};
use super::*;
use crate::{
    FirewallPolicy, FirewallRule, Ipv4Address, MacAddress, PacketLease, PacketSlot, SlotCompletion,
};

const NO_NAT: plain_ipv4::Nat<'static> = plain_ipv4::Nat {
    udp: None,
    tcp: None,
    icmp: None,
};

struct Item {
    ingress: IfId,
    frame: Vec<u8>,
    ended: Option<SlotCompletion>,
}

struct ItemSlot<'a>(&'a mut Item);

impl PacketSlot for ItemSlot<'_> {
    fn ingress(&self) -> IfId {
        self.0.ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0.frame
    }

    fn complete(self, completion: SlotCompletion) {
        assert_eq!(self.0.ended.replace(completion), None);
    }
}

struct Items<'a> {
    items: &'a mut [Item],
    next: usize,
}

impl PacketBatch for Items<'_> {
    type Error = ();
    type Slot<'a>
        = ItemSlot<'a>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        let item = self.items.get_mut(self.next)?;
        self.next += 1;
        Some(PacketLease::new(ItemSlot(item)))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        let sent = self
            .items
            .iter()
            .filter(|item| matches!(item.ended, Some(SlotCompletion::Transmit(_))))
            .count();
        BatchCompletion {
            tx_requested: sent,
            tx_accepted: sent,
            tx_rejected: 0,
            recycled: self.items.len() - sent,
            error: None,
        }
    }
}

#[derive(Default)]
struct Recorded(Vec<TraceEvent>);

impl TraceSink for Recorded {
    fn record(&mut self, event: TraceEvent) {
        self.0.push(event);
    }
}

/// Neighbors for route next hops and destinations, so that many packets can
/// be forwarded.
fn with_reachable_neighbors(rng: &mut Rng, tables: &mut Tables) {
    for route in tables.routes.clone() {
        if rng.below(3) == 0 {
            continue;
        }
        let target = route.next_hop().unwrap_or_else(|| {
            let host = rng.address() & (u32::MAX >> route.prefix_len().min(31));
            ip(bits(route.prefix()) | host)
        });
        let interface = route.egress();
        if !tables
            .neighbors
            .iter()
            .any(|neighbor| neighbor.interface == interface && neighbor.target == target)
        {
            let n = tables.neighbors.len();
            tables.neighbors.push(Neighbor {
                interface,
                target,
                mac: MacAddress([2, 2, 0, 0, (n >> 8) as u8, n as u8]),
            });
        }
    }
}

fn random_mac(rng: &mut Rng) -> [u8; 6] {
    let mut mac = rng.next().to_be_bytes();
    mac[0] &= 0xfe;
    [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]
}

/// An Ethernet frame with an IPv4 header, mostly valid and mostly to be
/// forwarded, with every field the short way looks at sometimes off.
fn random_frame(rng: &mut Rng, tables: &Tables, ids: &[IfId], addresses: &[Ipv4Address]) -> Item {
    let ingress = match tables.interfaces.len() as u64 {
        n if n > 0 && rng.below(4) != 0 => tables.interfaces[rng.below(n) as usize].id,
        _ => ids[rng.below(ids.len() as u64) as usize],
    };
    let pick = |rng: &mut Rng| addresses[rng.below(addresses.len() as u64) as usize];
    let options = if rng.below(16) == 0 { 4 } else { 0 };
    let payload = match rng.below(8) {
        0 => 1400 + rng.below(200) as usize,
        _ => rng.below(64) as usize,
    };
    let total = 20 + options + payload;
    let mut frame = vec![0_u8; 14 + total];
    let destination_mac = match (
        rng.below(12),
        tables.interfaces.iter().find(|i| i.id == ingress),
    ) {
        (0, _) | (_, None) => random_mac(rng),
        (1, _) => [0xff; 6],
        (2, _) => [1, 0, 0x5e, 0, 0, 1],
        (_, Some(interface)) => interface.mac.0,
    };
    frame[0..6].copy_from_slice(&destination_mac);
    let source_mac = match rng.below(24) {
        0 => [0; 6],
        1 => [0xff; 6],
        2 => [3, 0, 0, 0, 0, 1],
        _ => random_mac(rng),
    };
    frame[6..12].copy_from_slice(&source_mac);
    let ether_type: u16 = match rng.below(32) {
        0 => 0x0806,
        1 => 0x86dd,
        _ => 0x0800,
    };
    frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
    frame[14] = if rng.below(32) == 0 {
        0x65
    } else {
        0x45 + (options / 4) as u8
    };
    frame[16..18].copy_from_slice(&(total as u16).to_be_bytes());
    let flags: u16 = match rng.below(16) {
        0 => 0x2000,
        1 => 0x0010,
        2..=7 => 0x4000,
        _ => 0,
    };
    frame[20..22].copy_from_slice(&flags.to_be_bytes());
    frame[22] = match rng.below(8) {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 64,
    };
    frame[23] = [1, 6, 17, 47][rng.below(4) as usize];
    frame[26..30].copy_from_slice(&pick(rng).octets());
    let destination = match tables.neighbors.len() as u64 {
        0 => pick(rng),
        n if rng.below(2) == 0 => tables.neighbors[rng.below(n) as usize].target,
        _ => pick(rng),
    };
    frame[30..34].copy_from_slice(&destination.octets());
    for byte in &mut frame[34..] {
        *byte = rng.next() as u8;
    }
    write_transport(rng, &mut frame, 14 + 20 + options);
    transport_checksum(&mut frame);
    if rng.below(32) == 0 {
        if let Some(byte) = frame.last_mut() {
            *byte ^= 0x40;
        }
    }
    let header_end = 14 + 20 + options;
    let checksum = crate::ipv4_header_checksum(&frame[14..header_end]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    if rng.below(32) == 0 {
        frame[24] ^= 1;
    }
    match rng.below(32) {
        // Bytes after Total Length.
        0 => frame.extend((0..rng.below(64)).map(|_| 0)),
        // Shorter than Total Length.
        1 => frame.truncate(14 + 20 + options),
        _ => {}
    }
    Item {
        ingress,
        frame,
        ended: None,
    }
}

/// A transport header the firewall can read, most of the time: UDP with its
/// length, TCP with a header length and SYN or ACK, ICMP Echo or an error.
fn write_transport(rng: &mut Rng, frame: &mut [u8], at: usize) {
    let len = frame.len().saturating_sub(at);
    match frame[23] {
        17 if len >= 8 && rng.below(16) != 0 => {
            frame[at + 4..at + 6].copy_from_slice(&(len as u16).to_be_bytes());
            frame[at + 6..at + 8].copy_from_slice(&[0, 0]);
        }
        6 if len >= 20 && rng.below(16) != 0 => {
            frame[at + 12] = 0x50;
            frame[at + 13] = [0x02, 0x10, 0x12, 0x18][rng.below(4) as usize];
        }
        1 if len >= 8 => {
            frame[at] = [8, 0, 3, 11][rng.below(4) as usize];
            frame[at + 1] = 0;
        }
        _ => {}
    }
}

/// Sets the TCP or ICMP checksum of a whole IPv4 frame (not a fragment).
fn transport_checksum(frame: &mut [u8]) {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    let at = 14 + header_len;
    let end = 14 + usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    if end > frame.len() || at > end {
        return;
    }
    match frame[23] {
        6 if end - at >= 20 => {
            frame[at + 16..at + 18].copy_from_slice(&[0, 0]);
            let mut pseudo = Vec::with_capacity(12 + end - at);
            pseudo.extend_from_slice(&frame[26..34]);
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&((end - at) as u16).to_be_bytes());
            pseudo.extend_from_slice(&frame[at..end]);
            let checksum = crate::internet_checksum(&pseudo);
            frame[at + 16..at + 18].copy_from_slice(&checksum.to_be_bytes());
        }
        1 if end - at >= 8 => {
            frame[at + 2..at + 4].copy_from_slice(&[0, 0]);
            let checksum = crate::internet_checksum(&frame[at..end]);
            frame[at + 2..at + 4].copy_from_slice(&checksum.to_be_bytes());
        }
        _ => {}
    }
}

/// The reply to a frame that left through `egress`: addresses and ports
/// swapped, in from `egress`, to its MAC.
fn reply(frame: &[u8], egress: IfId, tables: &Tables) -> Item {
    let mut frame = frame.to_vec();
    if let Some(interface) = tables.interfaces.iter().find(|i| i.id == egress) {
        frame[0..6].copy_from_slice(&interface.mac.0);
    }
    frame[6..12].copy_from_slice(&[2, 9, 9, 9, 9, 9]);
    let (source, destination) = (frame[26..30].to_vec(), frame[30..34].to_vec());
    frame[26..30].copy_from_slice(&destination);
    frame[30..34].copy_from_slice(&source);
    frame[22] = 64;
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    let at = 14 + header_len;
    if matches!(frame[23], 6 | 17) && frame.len() >= at + 4 {
        let (from, to) = (frame[at..at + 2].to_vec(), frame[at + 2..at + 4].to_vec());
        frame[at..at + 2].copy_from_slice(&to);
        frame[at + 2..at + 4].copy_from_slice(&from);
        if frame[23] == 6 && frame.len() > at + 13 && frame[at + 13] == 0x02 {
            frame[at + 13] = 0x12;
        }
    }
    if frame[23] == 1 && frame.len() > at && frame[at] == 8 {
        frame[at] = 0;
    }
    transport_checksum(&mut frame);
    frame[24..26].copy_from_slice(&[0, 0]);
    let checksum = crate::ipv4_header_checksum(&frame[14..14 + header_len]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    Item {
        ingress: egress,
        frame,
        ended: None,
    }
}

fn random_prefix(rng: &mut Rng, addresses: &[Ipv4Address]) -> crate::FirewallPrefix {
    let len = [0, 0, 0, 0, 8, 16, 24, 32][rng.below(8) as usize];
    let address = bits(addresses[rng.below(addresses.len() as u64) as usize]);
    let masked = if len == 0 {
        0
    } else {
        address & (u32::MAX << (32 - len))
    };
    crate::FirewallIpv4Prefix::new(ip(masked), len as u8)
        .expect("a masked prefix")
        .into()
}

fn random_rules(rng: &mut Rng, ids: &[IfId], addresses: &[Ipv4Address]) -> Vec<FirewallRule> {
    let interface = |rng: &mut Rng| match rng.below(3) {
        0 | 1 => crate::FirewallInterface::Any,
        _ => crate::FirewallInterface::Interface(ids[rng.below(ids.len() as u64) as usize]),
    };
    let all = crate::FirewallPortRange::new(0, u16::MAX).expect("all ports");
    let mut rules: Vec<FirewallRule> = (0..1 + rng.below(5))
        .map(|id| {
            FirewallRule::new(
                crate::FirewallRuleId(id as u32 + 1),
                interface(rng),
                interface(rng),
                random_prefix(rng, addresses),
                random_prefix(rng, addresses),
                [
                    FirewallProtocol::Udp,
                    FirewallProtocol::Tcp,
                    FirewallProtocol::Icmp,
                ][rng.below(3) as usize],
                all,
                all,
                if rng.below(6) == 0 {
                    crate::FirewallAction::Deny
                } else {
                    crate::FirewallAction::AllowStateful
                },
            )
        })
        .collect();
    // Often everything else is let through, so that flows are opened and
    // their replies come back.
    if rng.below(2) == 0 {
        let any = crate::FirewallIpv4Prefix::new(ip(0), 0).expect("/0").into();
        for (at, protocol) in [
            FirewallProtocol::Udp,
            FirewallProtocol::Tcp,
            FirewallProtocol::Icmp,
        ]
        .into_iter()
        .enumerate()
        {
            rules.push(FirewallRule::new(
                crate::FirewallRuleId(100 + at as u32),
                crate::FirewallInterface::Any,
                crate::FirewallInterface::Any,
                any,
                any,
                protocol,
                all,
                all,
                crate::FirewallAction::AllowStateful,
            ));
        }
    }
    rules
}

/// A forward firewall and what it keeps, for one way of forwarding.
struct Guarded {
    states: Vec<crate::FirewallStateSlot>,
    audit: Vec<crate::FirewallAuditRecord>,
    errors: Vec<crate::Icmpv4ErrorStateSlot>,
    actions: Vec<crate::Icmpv4ErrorActionSlot>,
}

impl Guarded {
    fn new() -> Self {
        Self {
            states: vec![crate::FirewallStateSlot::default(); 64],
            audit: vec![crate::FirewallAuditRecord::default(); 512],
            errors: vec![crate::Icmpv4ErrorStateSlot::EMPTY; 16],
            actions: vec![crate::Icmpv4ErrorActionSlot::EMPTY; 16],
        }
    }
}

type Outcome = (Vec<Item>, Vec<TraceEvent>, (usize, usize, usize, usize));

/// `batches` forwarded in turn with the firewall, one way: what each ended
/// as, and the firewall's counters, states and audit records after.
fn forward_guarded(
    snapshot: &ForwardingSnapshot<'_>,
    config: &FirewallConfig<'_>,
    batches: &[&[Item]],
    short_way: bool,
    guarded: &mut Guarded,
) -> (
    Vec<Outcome>,
    crate::FirewallCounters,
    Vec<crate::FirewallAuditRecord>,
) {
    let policy = crate::Icmpv4ErrorPolicy::default().with_generation(
        crate::Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited,
        true,
    );
    let mut errors =
        crate::Icmpv4ErrorRuntime::new(policy, &mut guarded.errors, &mut guarded.actions);
    let mut runtime = FirewallRuntime::new(*config, &mut guarded.states);
    let mut audit = crate::FirewallAuditBuffer::new(&mut guarded.audit);
    let mut control = crate::ControlQueue::new(16);
    let mut outcomes = Vec::new();
    plain_ipv4::OFF.with(|off| off.set(!short_way));
    for (at, frames) in batches.iter().enumerate() {
        let mut items: Vec<Item> = frames
            .iter()
            .map(|item| Item {
                ingress: item.ingress,
                frame: item.frame.clone(),
                ended: None,
            })
            .collect();
        let mut trace = Recorded::default();
        let snapshot = snapshot.with_now(MonotonicMillis(1_000 + at as u64 * 10));
        let report = forward_batch_with_control(
            Items {
                items: &mut items,
                next: 0,
            },
            &snapshot,
            &mut control,
            Services {
                icmpv4_errors: Some(&mut errors),
                firewall: Some((config, &mut runtime)),
                firewall_audit: Some(&mut audit),
                ..Services::default()
            },
            &mut trace,
        );
        let counts = (
            report.received,
            report.tx_requested,
            report.dropped,
            report.consumed,
        );
        outcomes.push((items, trace.0, counts));
    }
    plain_ipv4::OFF.with(|off| off.set(false));
    (outcomes, runtime.counters(), audit.records().to_vec())
}

fn forward(
    snapshot: &ForwardingSnapshot<'_>,
    frames: &[Item],
    short_way: bool,
) -> (Vec<Item>, Vec<TraceEvent>, (usize, usize, usize, usize)) {
    let mut items: Vec<Item> = frames
        .iter()
        .map(|item| Item {
            ingress: item.ingress,
            frame: item.frame.clone(),
            ended: None,
        })
        .collect();
    let mut trace = Recorded::default();
    plain_ipv4::OFF.with(|off| off.set(!short_way));
    let report = forward_batch(
        Items {
            items: &mut items,
            next: 0,
        },
        snapshot,
        &mut trace,
    );
    plain_ipv4::OFF.with(|off| off.set(false));
    let counts = (
        report.received,
        report.tx_requested,
        report.dropped,
        report.consumed,
    );
    (items, trace.0, counts)
}

#[test]
fn the_short_way_ends_every_packet_as_the_full_way_does() {
    let mut rng = Rng(0x5eed_0f9a_7e00);
    let mut short = 0;
    let mut sent = 0;
    for round in 0..1_000 {
        let mut tables = random_tables(&mut rng, 40);
        with_reachable_neighbors(&mut rng, &mut tables);
        for interface in &mut tables.interfaces {
            interface.mtu = [576, 1500, 1500, 9000][rng.below(4) as usize];
        }
        let mut owner = owner(&tables);
        if round % 3 == 0 {
            let mut bindings: Vec<SourceValidationBinding> = Vec::new();
            for interface in &tables.interfaces {
                if rng.below(2) == 0 {
                    continue;
                }
                bindings.push(SourceValidationBinding {
                    interface: interface.id,
                    mode: [
                        SourceValidation::Loose,
                        SourceValidation::LooseAllowDefault,
                        SourceValidation::Strict,
                    ][rng.below(3) as usize],
                });
            }
            owner = owner.with_source_validation(&bindings).unwrap();
        }
        let kernel = [tables.interfaces[0].id];
        let snapshot = owner.snapshot();
        let snapshot = if round % 4 == 0 {
            snapshot.with_kernel_ingress(&kernel)
        } else {
            snapshot
        };
        let ids = interface_ids(&tables);
        let addresses = probe_addresses(&mut rng, &tables);
        let frames: Vec<Item> = (0..64)
            .map(|_| random_frame(&mut rng, &tables, &ids, &addresses))
            .collect();
        short += frames
            .iter()
            .filter(|item| {
                plain_ipv4::decide(
                    &item.frame,
                    snapshot.for_ingress(item.ingress),
                    &snapshot,
                    item.ingress,
                    None,
                    false,
                    NO_NAT,
                )
                .is_some()
            })
            .count();
        let (fast, fast_trace, fast_counts) = forward(&snapshot, &frames, true);
        let (full, full_trace, full_counts) = forward(&snapshot, &frames, false);
        assert_eq!(fast_counts, full_counts, "round {round}");
        assert_eq!(fast_trace, full_trace, "round {round}");
        for (index, (fast, full)) in fast.iter().zip(&full).enumerate() {
            assert_eq!(fast.ended, full.ended, "round {round} frame {index}");
            assert_eq!(fast.frame, full.frame, "round {round} frame {index}");
        }
        sent += full_counts.1;
    }
    // Both ways are exercised: many packets go the short way, and some
    // that are sent do not.
    assert!(short > 1_000, "short way taken {short} times");
    assert!(sent > short, "sent {sent}, short way {short}");
}

#[test]
fn with_a_firewall_the_short_way_ends_every_packet_as_the_full_way_does() {
    let mut rng = Rng(0xf1fe_0a11_5eed_0001);
    let mut short = 0;
    let mut replies_sent = 0;
    let mut states = 0;
    for round in 0..600 {
        let mut tables = random_tables(&mut rng, 24);
        with_reachable_neighbors(&mut rng, &mut tables);
        // Every other round, a second VRF (its own owner, so another
        // authority) holds some of the interfaces: the firewall is the
        // default VRF's, and that VRF's datagrams go the full way.
        let default_vrf = owner(&tables);
        let second_vrf = owner(&tables);
        let vrfs = [default_vrf.snapshot(), second_vrf.snapshot()];
        let by_ingress: Vec<u16> =
            (0..=tables.interfaces.iter().map(|i| i.id.0).max().unwrap_or(0))
                .map(|_| u16::from(round % 2 == 1 && rng.below(2) == 0))
                .collect();
        let snapshot = vrfs[0].with_vrfs(&vrfs, &by_ingress);
        let ids = interface_ids(&tables);
        let addresses = probe_addresses(&mut rng, &tables);
        let interfaces: Vec<IfId> = tables.interfaces.iter().map(|i| i.id).collect();
        let rules = random_rules(&mut rng, &interfaces, &addresses);
        let config = FirewallConfig::new(
            &snapshot,
            &rules,
            FirewallPolicy::default(),
            1,
            crate::FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210)
                .expect("a key"),
        )
        .expect("a firewall");
        let first: Vec<Item> = (0..48)
            .map(|_| random_frame(&mut rng, &tables, &ids, &addresses))
            .collect();
        short += first
            .iter()
            .filter(|item| {
                plain_ipv4::decide(
                    &item.frame,
                    snapshot.for_ingress(item.ingress),
                    &snapshot,
                    item.ingress,
                    None,
                    true,
                    NO_NAT,
                )
                .is_some()
            })
            .count();
        // The replies to what the full way sent, and the first batch again.
        let (sent, _, _) =
            forward_guarded(&snapshot, &config, &[&first], false, &mut Guarded::new());
        let mut second: Vec<Item> = sent[0]
            .0
            .iter()
            .filter_map(|item| match item.ended {
                Some(SlotCompletion::Transmit(egress)) => Some(reply(&item.frame, egress, &tables)),
                _ => None,
            })
            .collect();
        second.extend(first.iter().map(|item| Item {
            ingress: item.ingress,
            frame: item.frame.clone(),
            ended: None,
        }));
        let batches: [&[Item]; 2] = [&first, &second];
        let mut fast_kept = Guarded::new();
        let mut full_kept = Guarded::new();
        let (fast, fast_counters, fast_audit) =
            forward_guarded(&snapshot, &config, &batches, true, &mut fast_kept);
        let (full, full_counters, full_audit) =
            forward_guarded(&snapshot, &config, &batches, false, &mut full_kept);
        for (batch, (fast, full)) in fast.iter().zip(&full).enumerate() {
            assert_eq!(fast.2, full.2, "round {round} batch {batch}");
            assert_eq!(fast.1, full.1, "round {round} batch {batch}");
            for (index, (fast, full)) in fast.0.iter().zip(&full.0).enumerate() {
                assert_eq!(
                    fast.ended, full.ended,
                    "round {round} batch {batch} frame {index}"
                );
                assert_eq!(
                    fast.frame, full.frame,
                    "round {round} batch {batch} frame {index}"
                );
            }
        }
        assert_eq!(fast_counters, full_counters, "round {round}");
        assert_eq!(fast_kept.states, full_kept.states, "round {round}");
        assert_eq!(fast_audit, full_audit, "round {round}");
        assert_eq!(fast_kept.errors, full_kept.errors, "round {round}");
        assert_eq!(fast_kept.actions, full_kept.actions, "round {round}");
        replies_sent += full[1].2 .1;
        states += full_kept
            .states
            .iter()
            .filter(|slot| **slot != crate::FirewallStateSlot::default())
            .count();
    }
    assert!(short > 1_000, "short way taken {short} times");
    assert!(states > 200, "{states} flows opened");
    assert!(
        replies_sent > 300,
        "{replies_sent} sent in the second batches"
    );
}

fn leak<T: Clone>(len: usize, value: T) -> &'static mut [T] {
    Box::leak(vec![value; len].into_boxed_slice())
}

fn buckets(count: usize) -> &'static mut [crate::DirectoryBucket] {
    leak(count.next_power_of_two(), crate::DirectoryBucket::default())
}

const NAT_SLOTS: usize = 16;
const NAT_PORTS: u16 = 8;

fn udp_runtime(config: Nat44UdpConfig) -> Nat44UdpRuntime<'static> {
    let ports = usize::from(NAT_PORTS);
    Nat44UdpRuntime::new(
        config,
        leak(NAT_SLOTS, crate::Nat44UdpMappingSlot::default()),
        leak(NAT_SLOTS, crate::Nat44UdpPeerSlot::default()),
        crate::Nat44UdpIndexStorage::new(
            buckets(NAT_SLOTS),
            leak(NAT_SLOTS, crate::DirectoryNode::default()),
            buckets(NAT_SLOTS),
            leak(NAT_SLOTS, crate::DirectoryNode::default()),
            leak(ports, crate::PortOwnerSlot::default()),
            leak(crate::port_free_bitmap_words(ports), 0_u64),
            crate::Nat44HostStorage::disabled(),
        ),
        crate::Nat44UdpHashKey::new(0x1357_9bdf_2468_ace0, 0xfdb9_7531_eca8_6420).expect("a key"),
    )
    .expect("a UDP runtime")
}

fn tcp_runtime(config: Nat44TcpConfig) -> Nat44TcpRuntime<'static> {
    let ports = usize::from(NAT_PORTS);
    Nat44TcpRuntime::new(
        config,
        leak(NAT_SLOTS, crate::Nat44TcpMappingSlot::default()),
        leak(NAT_SLOTS, crate::Nat44TcpSessionSlot::default()),
        crate::Nat44TcpIndexStorage::new(
            buckets(NAT_SLOTS),
            leak(NAT_SLOTS, crate::DirectoryNode::default()),
            buckets(NAT_SLOTS),
            leak(NAT_SLOTS, crate::DirectoryNode::default()),
            buckets(NAT_SLOTS),
            leak(NAT_SLOTS, crate::DirectoryNode::default()),
            leak(ports, crate::PortOwnerSlot::default()),
            leak(crate::port_free_bitmap_words(ports), 0_u64),
            crate::Nat44HostStorage::disabled(),
        ),
        crate::Nat44TcpHashKey::new(0xc001_d00d_f00d_beef, 0x1234_5678_9abc_def0).expect("a key"),
    )
    .expect("a TCP runtime")
}

/// `batches` forwarded in turn with NAT, one way: what each ended as, and
/// NAT's counters and tables after.
fn forward_translated(
    snapshot: &ForwardingSnapshot<'_>,
    udp_config: Option<&Nat44UdpConfig>,
    tcp_config: Option<&Nat44TcpConfig>,
    batches: &[&[Item]],
    times: &[u64],
    short_way: bool,
) -> (Vec<Outcome>, impl PartialEq + std::fmt::Debug, NatTables) {
    let mut udp = udp_config.map(|config| udp_runtime(*config));
    let mut tcp = tcp_config.map(|config| tcp_runtime(*config));
    let mut control = crate::ControlQueue::new(16);
    let mut outcomes = Vec::new();
    plain_ipv4::OFF.with(|off| off.set(!short_way));
    for (at, frames) in batches.iter().enumerate() {
        let mut items: Vec<Item> = frames
            .iter()
            .map(|item| Item {
                ingress: item.ingress,
                frame: item.frame.clone(),
                ended: None,
            })
            .collect();
        let mut trace = Recorded::default();
        let snapshot = snapshot.with_now(MonotonicMillis(times[at]));
        let report = forward_batch_with_control(
            Items {
                items: &mut items,
                next: 0,
            },
            &snapshot,
            &mut control,
            Services {
                nat44_udp: udp_config.zip(udp.as_mut()),
                nat44_tcp: tcp_config.zip(tcp.as_mut()),
                ..Services::default()
            },
            &mut trace,
        );
        let counts = (
            report.received,
            report.tx_requested,
            report.dropped,
            report.consumed,
        );
        outcomes.push((items, trace.0, counts));
    }
    plain_ipv4::OFF.with(|off| off.set(false));
    let counters = (
        udp.as_ref().map(Nat44UdpRuntime::counters),
        tcp.as_ref().map(Nat44TcpRuntime::counters),
    );
    let state = (
        udp.as_ref().map(|udp| {
            (
                udp.mappings()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count(),
                udp.peers().iter().filter(|slot| slot.is_occupied()).count(),
            )
        }),
        tcp.as_ref().map(|tcp| {
            (
                tcp.mappings()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count(),
                tcp.sessions()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count(),
            )
        }),
    );
    let tables: NatTables = (
        udp.as_ref()
            .map(|u| u.mappings().to_vec())
            .unwrap_or_default(),
        udp.as_ref().map(|u| u.peers().to_vec()).unwrap_or_default(),
        tcp.as_ref()
            .map(|t| t.mappings().to_vec())
            .unwrap_or_default(),
        tcp.as_ref()
            .map(|t| t.sessions().to_vec())
            .unwrap_or_default(),
    );
    (outcomes, (counters, state), tables)
}

/// NAT's tables after a run: UDP mappings and peers, TCP mappings and
/// sessions.
type NatTables = (
    Vec<crate::Nat44UdpMappingSlot>,
    Vec<crate::Nat44UdpPeerSlot>,
    Vec<crate::Nat44TcpMappingSlot>,
    Vec<crate::Nat44TcpSessionSlot>,
);

#[test]
fn with_nat_the_short_way_ends_every_packet_as_the_full_way_does() {
    let mut rng = Rng(0x0a7a_5eed_0000_0001);
    let mut short = 0;
    let mut translated = 0;
    let mut rounds = 0;
    for round in 0..600 {
        let mut tables = random_tables(&mut rng, 16);
        if tables.interfaces.len() < 2 {
            continue;
        }
        // The outside has an address (the public one); the inside a network
        // behind it, and the outside a way to everywhere.
        let outside_at = rng.below(tables.interfaces.len() as u64) as usize;
        let outside = tables.interfaces[outside_at].id;
        let inside = tables.interfaces[(outside_at + 1) % tables.interfaces.len()].id;
        let public = ip(0xc633_6401 + rng.below(200) as u32);
        tables
            .local_ipv4
            .retain(|binding| binding.interface != outside);
        tables.local_ipv4.push(LocalIpv4Binding {
            interface: outside,
            address: public,
        });
        let network = 0x0ac8_0000 | (rng.below(256) as u32) << 8;
        tables
            .routes
            .retain(|route| route.prefix_len() != 0 && route.prefix() != ip(network));
        tables
            .routes
            .push(Route::new(ip(network), 24, inside, None).expect("inside network"));
        let gateway = ip(0xc633_6301);
        tables
            .routes
            .push(Route::new(ip(0), 0, outside, Some(gateway)).expect("default route"));
        with_reachable_neighbors(&mut rng, &mut tables);
        for (interface, target) in [(outside, gateway), (inside, ip(network | 7))] {
            if !tables
                .neighbors
                .iter()
                .any(|n| n.interface == interface && n.target == target)
            {
                tables.neighbors.push(Neighbor {
                    interface,
                    target,
                    mac: MacAddress([2, 3, 0, 0, 0, tables.neighbors.len() as u8]),
                });
            }
        }
        let Ok(owner) = std::panic::catch_unwind(|| owner(&tables)) else {
            continue;
        };
        let snapshot = owner.snapshot();
        let port = 40_000 + rng.below(1_000) as u16;
        let udp_config = (rng.below(4) != 0).then(|| {
            Nat44UdpConfig::new(
                &snapshot,
                inside,
                outside,
                public,
                port,
                port + NAT_PORTS - 1,
                crate::Nat44UdpPolicy::default(),
            )
            .expect("a UDP NAT")
        });
        // Now and then TCP NAT has another inside: the realms disagree.
        let tcp_inside = match tables.interfaces.len() {
            n if n > 2 && rng.below(4) == 0 => tables.interfaces[(outside_at + 2) % n].id,
            _ => inside,
        };
        let tcp_config = (rng.below(4) != 0).then(|| {
            Nat44TcpConfig::new(
                &snapshot,
                tcp_inside,
                outside,
                public,
                port,
                port + NAT_PORTS - 1,
                crate::Nat44TcpPolicy::default(),
            )
            .expect("a TCP NAT")
        });
        if udp_config.is_none() && tcp_config.is_none() {
            continue;
        }
        rounds += 1;
        let ids = interface_ids(&tables);
        let mut addresses = probe_addresses(&mut rng, &tables);
        addresses.extend((0..16).map(|host| ip(network | host)));
        addresses.push(public);
        let first: Vec<Item> = (0..48)
            .map(|_| {
                let mut item = random_frame(&mut rng, &tables, &ids, &addresses);
                // Mostly from a host on the inside.
                if rng.below(3) != 0 && item.frame.len() >= 34 && item.frame[12..14] == [8, 0] {
                    item.ingress = inside;
                    let mac = tables
                        .interfaces
                        .iter()
                        .find(|i| i.id == inside)
                        .unwrap()
                        .mac;
                    item.frame[0..6].copy_from_slice(&mac.0);
                    item.frame[26..30]
                        .copy_from_slice(&ip(network | (1 + rng.below(6) as u32)).octets());
                    if item.frame[14] == 0x45 {
                        transport_checksum(&mut item.frame);
                        item.frame[24..26].copy_from_slice(&[0, 0]);
                        let checksum = crate::ipv4_header_checksum(&item.frame[14..34]);
                        item.frame[24..26].copy_from_slice(&checksum.to_be_bytes());
                    }
                }
                item
            })
            .collect();
        let nat = plain_ipv4::Nat {
            udp: udp_config.as_ref(),
            tcp: tcp_config.as_ref(),
            icmp: None,
        };
        short += first
            .iter()
            .filter(|item| {
                plain_ipv4::decide(
                    &item.frame,
                    snapshot.for_ingress(item.ingress),
                    &snapshot,
                    item.ingress,
                    None,
                    false,
                    nat,
                )
                .is_some()
            })
            .count();
        let (sent, _, _) = forward_translated(
            &snapshot,
            udp_config.as_ref(),
            tcp_config.as_ref(),
            &[&first],
            &[1_000],
            false,
        );
        let mut second: Vec<Item> = sent[0]
            .0
            .iter()
            .filter_map(|item| match item.ended {
                Some(SlotCompletion::Transmit(egress)) => Some(reply(&item.frame, egress, &tables)),
                _ => None,
            })
            .collect();
        second.extend(first.iter().map(|item| Item {
            ingress: item.ingress,
            frame: item.frame.clone(),
            ended: None,
        }));
        let batches: [&[Item]; 2] = [&first, &second];
        // Now and then the clock goes back, which NAT refuses.
        let times = [1_000, if round % 5 == 0 { 990 } else { 1_010 }];
        let (fast, fast_state, fast_tables) = forward_translated(
            &snapshot,
            udp_config.as_ref(),
            tcp_config.as_ref(),
            &batches,
            &times,
            true,
        );
        let (full, full_state, full_tables) = forward_translated(
            &snapshot,
            udp_config.as_ref(),
            tcp_config.as_ref(),
            &batches,
            &times,
            false,
        );
        for (batch, (fast, full)) in fast.iter().zip(&full).enumerate() {
            assert_eq!(fast.2, full.2, "round {round} batch {batch}");
            assert_eq!(fast.1, full.1, "round {round} batch {batch}");
            for (index, (fast, full)) in fast.0.iter().zip(&full.0).enumerate() {
                assert_eq!(
                    fast.ended, full.ended,
                    "round {round} batch {batch} frame {index}"
                );
                assert_eq!(
                    fast.frame, full.frame,
                    "round {round} batch {batch} frame {index}"
                );
            }
        }
        assert_eq!(fast_state, full_state, "round {round}");
        assert!(
            fast_tables == full_tables,
            "round {round}: the NAT tables differ"
        );
        translated += full[0]
            .1
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    TraceEvent::Nat44Udp { .. } | TraceEvent::Nat44Tcp { .. }
                )
            })
            .count();
    }
    assert!(rounds > 200, "{rounds} rounds with NAT");
    assert!(short > 1_000, "short way taken {short} times");
    assert!(translated > 500, "{translated} translated");
}

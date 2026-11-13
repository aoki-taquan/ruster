//! The short way (`plain_ipv4`) against the full way: on random tables and
//! frames, each batch is forwarded twice, once with the short way off, and
//! the frames as they leave, how each ended, the counts and the trace must be
//! the same.

use super::lookup_tests::{
    bits, interface_ids, ip, owner, probe_addresses, random_tables, Rng, Tables,
};
use super::*;
use crate::{Ipv4Address, MacAddress, PacketLease, PacketSlot, SlotCompletion};

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
    let ingress = ids[rng.below(ids.len() as u64) as usize];
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

//! The punt table (`ruster-punt`): which class traffic to the router or to the
//! control side belongs to, where each class goes and how fast.
//!
//! Some classes are there without any table entry and cannot be removed: `arp` and
//! `nd` to the neighbor process, and the kinds of the kernel's traffic
//! (`icmp-error`, `icmp`, `tcp-syn`, `tcp`, `udp`, `other`). An entry with one of
//! their names changes their rate and burst (and, for a kernel kind, may drop it);
//! deleting it brings back the default. Other entries match an IP protocol and,
//! for TCP and UDP, a range of destination ports, on one interface or on any.
//! Packets to the router are first matched against those entries, then fall into
//! the kernel kind they are of. Two entries that could match the same packet are
//! refused, so the order of the entries does not matter.
//!
//! Each class has its own token bucket; a class to the kernel has one per VRF, so
//! that a flood in one VRF does not crowd out another's. Each class counts what it
//! handed over and what it dropped.
//!
//! # Standards
//!
//! - RFC 6192 section 3 (Informational): traffic to the router is sorted into
//!   classes, each with its own rate limit, set by the deployment (section 3.2).
//!
//! Deviations: classes have no priority among themselves; each has its own limit
//! instead, so one that overflows does not take another's place. An entry with
//! ports matches neither an IPv4 fragment (not even the first) nor an IPv6 packet
//! whose transport header follows an extension header; those fall into a kernel
//! kind.

use ruster_core::IfId;
use ruster_proto::session::Store;
use ruster_proto::table::{Key, PuntClass, PuntDestination, PuntKind, PuntMatch, Value};

use crate::local::{self, Bucket};

/// The most entries the table may hold besides the built-in classes.
pub(crate) const ENTRIES_MAX: usize = 64;
/// The rate and burst of a built-in class when no entry sets them: 2 000 packets
/// per second, 200 at once.
pub(crate) const DEFAULT_RATE: u32 = 2_000;
pub(crate) const DEFAULT_BURST: u32 = 200;
/// The control process ARP and Neighbor Discovery go to.
pub(crate) const NEIGHBOR_PROCESS: &str = "neighd";

/// The built-in classes, in the order of their index.
const BUILT_IN: [PuntKind; 8] = [
    PuntKind::Arp,
    PuntKind::Nd,
    PuntKind::IcmpError,
    PuntKind::Icmp,
    PuntKind::TcpSyn,
    PuntKind::Tcp,
    PuntKind::Udp,
    PuntKind::Other,
];

/// The index of built-in class `kind`.
pub(crate) fn built_in(kind: PuntKind) -> usize {
    BUILT_IN
        .iter()
        .position(|&k| k == kind)
        .expect("a built-in kind")
}

/// Where a class goes, its interface resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Class {
    pub(crate) name: String,
    pub(crate) matches: PuntMatch,
    /// `None` for any interface.
    pub(crate) interface: Option<IfId>,
    pub(crate) destination: PuntDestination,
    pub(crate) rate: u32,
    pub(crate) burst: u32,
}

/// What a class handed over and dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PuntCounters {
    pub handed: u64,
    pub dropped: u64,
}

/// The classes of the current tables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Classes {
    /// The built-in classes in the order of [`BUILT_IN`], then the entries'.
    classes: Vec<Class>,
}

impl Classes {
    /// The classes of `store`. `interface` gives the id of an enabled interface; an
    /// entry naming another matches nothing and is left out.
    pub(crate) fn build(
        store: &Store,
        interface: impl Fn(&str) -> Option<IfId>,
    ) -> Result<Self, String> {
        let mut classes: Vec<Class> = BUILT_IN
            .iter()
            .map(|&kind| Class {
                name: kind.name().to_owned(),
                matches: PuntMatch::Kind(kind),
                interface: None,
                destination: if kind.is_frame() {
                    PuntDestination::Control(NEIGHBOR_PROCESS.to_owned())
                } else {
                    PuntDestination::Kernel
                },
                rate: DEFAULT_RATE,
                burst: DEFAULT_BURST,
            })
            .collect();
        let mut entries: Vec<(&str, &PuntClass)> = Vec::new();
        for (key, value) in store.iter() {
            if let (Key::Punt { class }, Value::Punt(entry)) = (key, value) {
                entries.push((class, entry));
            }
        }
        if entries.len() > ENTRIES_MAX {
            return Err(format!("more than {ENTRIES_MAX} punt classes"));
        }
        for (at, &(name, entry)) in entries.iter().enumerate() {
            if let Some(index) = BUILT_IN.iter().position(|kind| kind.name() == name) {
                let built = &mut classes[index];
                let same_destination = entry.destination == built.destination
                    || (built.destination == PuntDestination::Kernel
                        && entry.destination == PuntDestination::Drop);
                if entry.matches != built.matches || entry.interface.is_some() || !same_destination
                {
                    return Err(format!(
                        "punt class {name}: a built-in class changes only its rate and burst \
                         (a kernel kind may also be dropped)"
                    ));
                }
                built.destination.clone_from(&entry.destination);
                built.rate = entry.rate;
                built.burst = entry.burst;
                continue;
            }
            let PuntMatch::Ip { protocol, ports } = entry.matches else {
                return Err(format!(
                    "punt class {name}: a fixed kind is matched only by its built-in class"
                ));
            };
            if matches!(entry.destination, PuntDestination::Control(_)) {
                return Err(format!(
                    "punt class {name}: a control process as the destination is not supported yet"
                ));
            }
            for &(other, earlier) in &entries[..at] {
                let PuntMatch::Ip {
                    protocol: other_protocol,
                    ports: other_ports,
                } = earlier.matches
                else {
                    continue;
                };
                let interfaces = match (&entry.interface, &earlier.interface) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                };
                let ports = match (ports, other_ports) {
                    (Some((a, b)), Some((c, d))) => a <= d && c <= b,
                    _ => true,
                };
                if protocol == other_protocol && interfaces && ports {
                    return Err(format!(
                        "punt classes {other} and {name} can match the same packet"
                    ));
                }
            }
            let resolved = match &entry.interface {
                Some(named) => match interface(named) {
                    Some(id) => Some(id),
                    None => continue,
                },
                None => None,
            };
            classes.push(Class {
                name: name.to_owned(),
                matches: entry.matches,
                interface: resolved,
                destination: entry.destination.clone(),
                rate: entry.rate,
                burst: entry.burst,
            });
        }
        Ok(Self { classes })
    }

    pub(crate) fn get(&self, index: usize) -> &Class {
        &self.classes[index]
    }

    pub(crate) fn len(&self) -> usize {
        self.classes.len()
    }

    /// The class of an IP packet to the router (`packet` starts at the IP header)
    /// that came in on `ingress`.
    pub(crate) fn of_local(&self, ingress: IfId, packet: &[u8]) -> usize {
        let transport = transport(packet);
        let entry = self.classes[BUILT_IN.len()..].iter().position(|class| {
            let PuntMatch::Ip { protocol, ports } = class.matches else {
                return false;
            };
            class.interface.is_none_or(|id| id == ingress)
                && match (transport, ports) {
                    (Some((p, _)), None) => p == protocol,
                    (Some((p, Some(port))), Some((first, last))) => {
                        p == protocol && (first..=last).contains(&port)
                    }
                    _ => false,
                }
        });
        match entry {
            Some(at) => BUILT_IN.len() + at,
            None => built_in(local::kind(packet)),
        }
    }
}

/// The IP protocol of `packet` and, for TCP and UDP that is not a fragment, its
/// destination port. `None` for a packet whose protocol is not at a fixed place
/// (an IPv4 fragment after the first, an IPv6 extension header).
fn transport(packet: &[u8]) -> Option<(u8, Option<u16>)> {
    let (protocol, header, fragment) = match packet.first()? >> 4 {
        4 => {
            let flags = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
            if flags & 0x1fff != 0 {
                return None;
            }
            (
                *packet.get(9)?,
                usize::from(packet[0] & 0x0f) * 4,
                flags & 0x2000 != 0,
            )
        }
        6 => (*packet.get(6)?, 40, false),
        _ => return None,
    };
    if matches!(protocol, 0 | 43 | 44 | 60) && packet[0] >> 4 == 6 {
        return None;
    }
    let port = match protocol {
        6 | 17 if !fragment => packet
            .get(header + 2..header + 4)
            .map(|p| u16::from_be_bytes([p[0], p[1]])),
        _ => None,
    };
    Some((protocol, port))
}

/// The buckets and counters of the classes, kept across table changes for the
/// classes that stay (by name).
#[derive(Debug)]
pub(crate) struct Limits {
    names: Vec<String>,
    /// One bucket per class, for classes not to the kernel.
    buckets: Vec<Bucket>,
    /// Per VRF, one bucket per class, for classes to the kernel.
    kernel: Vec<Vec<Bucket>>,
    counters: Vec<PuntCounters>,
}

impl Limits {
    pub(crate) fn new(classes: &Classes, vrfs: usize) -> Self {
        let mut limits = Self {
            names: Vec::new(),
            buckets: Vec::new(),
            kernel: Vec::new(),
            counters: Vec::new(),
        };
        limits.update(classes, vrfs);
        limits
    }

    /// Follows the classes of new tables with `vrfs` VRFs. A class keeps its tokens
    /// and counters by name; the per-VRF buckets start again when the VRFs change.
    pub(crate) fn update(&mut self, classes: &Classes, vrfs: usize) {
        let old = |name: &str| self.names.iter().position(|n| n == name);
        let mut buckets = Vec::with_capacity(classes.len());
        let mut counters = Vec::with_capacity(classes.len());
        for class in &classes.classes {
            let at = old(&class.name);
            let bucket = at.map_or_else(
                || Bucket::new(class.rate, class.burst),
                |at| self.buckets[at].with_limits(class.rate, class.burst),
            );
            buckets.push(bucket);
            counters.push(at.map_or_else(PuntCounters::default, |at| self.counters[at]));
        }
        let kernel = if self.kernel.len() == vrfs {
            self.kernel
                .iter()
                .map(|per_vrf| {
                    classes
                        .classes
                        .iter()
                        .map(|class| {
                            old(&class.name).map_or_else(
                                || Bucket::new(class.rate, class.burst),
                                |at| per_vrf[at].with_limits(class.rate, class.burst),
                            )
                        })
                        .collect()
                })
                .collect()
        } else {
            let fresh: Vec<Bucket> = classes
                .classes
                .iter()
                .map(|class| Bucket::new(class.rate, class.burst))
                .collect();
            vec![fresh; vrfs]
        };
        self.names = classes.classes.iter().map(|c| c.name.clone()).collect();
        self.buckets = buckets;
        self.kernel = kernel;
        self.counters = counters;
    }

    /// Whether one more packet of class `index` may go now; for the kernel of the
    /// VRF at `vrf`. Counts a refused one as dropped.
    pub(crate) fn admit(&mut self, index: usize, vrf: Option<usize>, now_ms: u64) -> bool {
        let bucket = match vrf {
            Some(vrf) => self.kernel.get_mut(vrf).and_then(|b| b.get_mut(index)),
            None => self.buckets.get_mut(index),
        };
        let admitted = bucket.is_some_and(|bucket| bucket.take(now_ms));
        if !admitted {
            self.dropped(index);
        }
        admitted
    }

    pub(crate) fn handed(&mut self, index: usize) {
        if let Some(counters) = self.counters.get_mut(index) {
            counters.handed += 1;
        }
    }

    pub(crate) fn dropped(&mut self, index: usize) {
        if let Some(counters) = self.counters.get_mut(index) {
            counters.dropped += 1;
        }
    }

    /// Every class's name and counters.
    pub(crate) fn counters(&self) -> Vec<(String, PuntCounters)> {
        self.names
            .iter()
            .cloned()
            .zip(self.counters.iter().copied())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8, port: u16, flags: u16) -> Vec<u8> {
        let mut p = vec![0_u8; 28];
        p[0] = 0x45;
        p[6..8].copy_from_slice(&flags.to_be_bytes());
        p[9] = protocol;
        p[22..24].copy_from_slice(&port.to_be_bytes());
        p
    }

    #[test]
    fn the_transport_is_read_only_where_it_is() {
        assert_eq!(transport(&ipv4(17, 67, 0)), Some((17, Some(67))));
        assert_eq!(transport(&ipv4(17, 67, 0x2000)), Some((17, None)), "MF");
        assert_eq!(transport(&ipv4(17, 67, 1)), None, "a later fragment");
        assert_eq!(transport(&ipv4(89, 0, 0)), Some((89, None)));
        let mut v6 = vec![0_u8; 48];
        v6[0] = 0x60;
        v6[6] = 17;
        v6[42..44].copy_from_slice(&547_u16.to_be_bytes());
        assert_eq!(transport(&v6), Some((17, Some(547))));
        v6[6] = 0;
        assert_eq!(transport(&v6), None, "behind an extension header");
        assert_eq!(transport(&[0x45, 0]), None, "too short");
    }
}

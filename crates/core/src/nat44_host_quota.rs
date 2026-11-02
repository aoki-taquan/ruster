//! Per-internal-host accounting of NAT44 mappings (N3, NAT44-092).
//!
//! RFC 6888 REQ-4 asks a NAT to support limiting the external ports assigned
//! per subscriber. A NAT44 runtime whose per-host mapping limit is set keeps,
//! for every internal IPv4 address that holds a public port, a host slot with
//! intrusive lists of exactly those mappings. The number of public ports an
//! internal host holds is then a list length read in O(1), and its mapping
//! that expires first is a list head.
//!
//! A mapping *counts* toward its internal address exactly while it is
//! occupied and owns its public port (`occupied && port_owned`): from the
//! commit that creates it until the commit that reclaims its slot for a new
//! mapping, retires it (another mapping takes its port), or a reconcile
//! flush. Expiry is lazy, so an expired mapping still counts until one of
//! those commits; the runtime's quota check therefore looks at the host's
//! list heads and reclaims an expired mapping before it refuses (see the
//! runtimes). Each host list mirrors one of the runtime's reuse lists of
//! port-owning mappings: every append to that list's tail is an append to
//! the host list's tail and every removal is a removal, so a host list is
//! its host's sublist of a list in expiry order, and is in expiry order too.
//!
//! The per-mapping links live in a caller-backed array parallel to the
//! mapping slots, so a runtime without a limit carries no host storage and
//! does no host work at all. Host slots are found through a keyed
//! [`FixedDirectory`] with its own hash domain. A host whose last mapping
//! stops counting keeps its slot and directory entry on an *empty* list until
//! a new internal address needs a slot, so a commit never unlinks a
//! directory node and links or relinks at most one, which the plan prepares
//! like the other directory mutations. There are as many host slots as
//! mapping slots, so a slot is always available (see
//! [`HostTable::plan_assignment`]).

use crate::{
    fixed_directory::{DirectoryHashDomain, DirectoryHashKey, FixedDirectory},
    slot_list::{Linked, SlotLinks, SlotList, LINK_NONE},
    DirectoryBucket, DirectoryNode, Ipv4Address,
};

/// Caller-backed membership of one mapping slot on its internal host's list
/// (N3). A runtime with per-host accounting has one per mapping slot.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44HostLink {
    links: SlotLinks,
    /// `host * LISTS + list`, or `LINK_NONE` while the mapping does not
    /// count.
    tag: u32,
}

impl Nat44HostLink {
    /// Not on any host list.
    pub const EMPTY: Self = Self {
        links: SlotLinks::UNLINKED,
        tag: LINK_NONE,
    };
}

impl Default for Nat44HostLink {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl std::fmt::Debug for Nat44HostLink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Nat44HostLink([REDACTED])")
    }
}

impl Linked for Nat44HostLink {
    fn links(&self) -> SlotLinks {
        self.links
    }

    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.links
    }
}

/// Caller-backed slot of one internal host (N3), with `LISTS` mapping lists:
/// one for UDP ([`Nat44UdpHostSlot`]), one per mapping activity list for TCP
/// ([`Nat44TcpHostSlot`]). Allocated slots are exactly those below the
/// table's fresh boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44HostSlot<const LISTS: usize> {
    address: Ipv4Address,
    mappings: [SlotList; LISTS],
    /// On the empty-host list while allocated with no counted mapping.
    links: SlotLinks,
}

/// Host slot of the UDP per-host mapping accounting (one activity list).
pub type Nat44UdpHostSlot = Nat44HostSlot<1>;
/// Host slot of the TCP per-host mapping accounting (established and
/// transitory lists).
pub type Nat44TcpHostSlot = Nat44HostSlot<2>;

impl<const LISTS: usize> Nat44HostSlot<LISTS> {
    /// An unused slot.
    pub const EMPTY: Self = Self {
        address: Ipv4Address::from_octets([0; 4]),
        mappings: [SlotList::EMPTY; LISTS],
        links: SlotLinks::UNLINKED,
    };

    fn count(&self) -> usize {
        self.mappings.iter().map(|list| list.len()).sum()
    }
}

impl<const LISTS: usize> Default for Nat44HostSlot<LISTS> {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl<const LISTS: usize> std::fmt::Debug for Nat44HostSlot<LISTS> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Nat44HostSlot([REDACTED])")
    }
}

impl<const LISTS: usize> Linked for Nat44HostSlot<LISTS> {
    fn links(&self) -> SlotLinks {
        self.links
    }

    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.links
    }
}

/// Caller-owned storage of a NAT44 runtime's per-host mapping accounting
/// (N3): either all four arrays empty (no accounting; the runtime's per-host
/// limit must then be `0`), or one [`Nat44HostLink`], one host slot, and one
/// host directory node per mapping slot, with as many directory buckets as
/// the mapping directory.
pub struct Nat44HostStorage<'a, const LISTS: usize> {
    pub(crate) links: &'a mut [Nat44HostLink],
    pub(crate) hosts: &'a mut [Nat44HostSlot<LISTS>],
    pub(crate) buckets: &'a mut [DirectoryBucket],
    pub(crate) nodes: &'a mut [DirectoryNode],
}

impl<'a, const LISTS: usize> Nat44HostStorage<'a, LISTS> {
    pub fn new(
        links: &'a mut [Nat44HostLink],
        hosts: &'a mut [Nat44HostSlot<LISTS>],
        buckets: &'a mut [DirectoryBucket],
        nodes: &'a mut [DirectoryNode],
    ) -> Self {
        Self {
            links,
            hosts,
            buckets,
            nodes,
        }
    }

    /// No per-host accounting: a runtime whose per-host limit is `0`.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            links: &mut [],
            hosts: &mut [],
            buckets: &mut [],
            nodes: &mut [],
        }
    }
}

/// How a new mapping's internal address gets its host slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostAssignmentKind {
    /// The address already has a host slot (possibly with no mapping).
    Existing,
    /// The lowest never-used host slot, linked into the directory.
    Fresh,
    /// A host slot with no counted mapping when the commit assigns it,
    /// relinked under the new address.
    Recycle,
}

/// Which host slot a new mapping's internal address gets, decided at plan
/// time. The plan carries the directory hash of the address rather than a
/// prepared link (16 bytes instead of 32, keeping the plan within its
/// cache-line budget); the commit's revalidation proves the link or relink
/// can be prepared, so the commit prepares and applies it without failing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostAssignment {
    hash: u64,
    host: u32,
    kind: HostAssignmentKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostTableCorrupt;

/// Per-host mapping lists of one NAT44 runtime; see the module docs. With
/// no storage every operation is a no-op and no address has a host slot.
pub(crate) struct HostTable<'a, const LISTS: usize> {
    links: &'a mut [Nat44HostLink],
    hosts: &'a mut [Nat44HostSlot<LISTS>],
    directory: FixedDirectory<'a>,
    domain: DirectoryHashDomain,
    /// Host slots at and after this index have never been used since the
    /// last flush; those before it are allocated.
    next_fresh: usize,
    /// Allocated host slots with no counted mapping, oldest first.
    empty: SlotList,
    #[cfg(test)]
    lookup_probes: std::cell::Cell<usize>,
}

impl<'a, const LISTS: usize> HostTable<'a, LISTS> {
    /// Checks the caller-backed dimensions: no storage at all, or one link,
    /// one host slot, and one directory node per mapping slot and a valid
    /// directory.
    pub(crate) fn validate_config(
        storage: &Nat44HostStorage<'_, LISTS>,
        mappings: usize,
    ) -> Result<(), HostTableCorrupt> {
        let lengths = [
            storage.links.len(),
            storage.hosts.len(),
            storage.buckets.len(),
            storage.nodes.len(),
        ];
        if lengths == [0; 4] {
            return Ok(());
        }
        if lengths[0] != mappings || lengths[1] != mappings || lengths[3] != mappings {
            return Err(HostTableCorrupt);
        }
        FixedDirectory::validate_config(lengths[2], lengths[3]).map_err(|_| HostTableCorrupt)
    }

    pub(crate) fn new(
        storage: Nat44HostStorage<'a, LISTS>,
        key: DirectoryHashKey,
        domain: DirectoryHashDomain,
    ) -> Result<Self, HostTableCorrupt> {
        let directory = FixedDirectory::new(storage.buckets, storage.nodes, key)
            .map_err(|_| HostTableCorrupt)?;
        storage.links.fill(Nat44HostLink::EMPTY);
        storage.hosts.fill(Nat44HostSlot::EMPTY);
        Ok(Self {
            links: storage.links,
            hosts: storage.hosts,
            directory,
            domain,
            next_fresh: 0,
            empty: SlotList::EMPTY,
            #[cfg(test)]
            lookup_probes: std::cell::Cell::new(0),
        })
    }

    /// Whether this runtime keeps per-host accounting.
    pub(crate) fn enabled(&self) -> bool {
        !self.hosts.is_empty()
    }

    /// Forgets every host (reconcile flush) and rekeys the directory.
    pub(crate) fn clear_with_key(&mut self, key: DirectoryHashKey) {
        self.links.fill(Nat44HostLink::EMPTY);
        self.hosts.fill(Nat44HostSlot::EMPTY);
        self.directory.clear_with_key(key);
        self.next_fresh = 0;
        self.empty = SlotList::EMPTY;
    }

    pub(crate) const fn slot_count(&self) -> usize {
        self.hosts.len()
    }

    pub(crate) const fn bucket_count(&self) -> usize {
        self.directory.bucket_count()
    }

    pub(crate) const fn node_capacity(&self) -> usize {
        self.directory.node_capacity()
    }

    fn words(address: Ipv4Address) -> [u64; 1] {
        [u64::from(u32::from_be_bytes(address.octets()))]
    }

    fn tag(host: usize, list: usize) -> u32 {
        u32::try_from(host * LISTS + list).expect("validated host slot index fits u32")
    }

    /// The host slot of `address`, if it has one: one keyed directory
    /// lookup (none without accounting).
    pub(crate) fn find(&self, address: Ipv4Address) -> Result<Option<usize>, HostTableCorrupt> {
        let probe = self
            .directory
            .lookup(self.domain, &Self::words(address), |index| {
                index < self.next_fresh && self.hosts[index].address == address
            })
            .map_err(|_| HostTableCorrupt)?;
        #[cfg(test)]
        self.lookup_probes
            .set(self.lookup_probes.get().saturating_add(probe.probes));
        Ok(probe.state_index)
    }

    /// Host directory nodes visited by lookups since the last call (cost
    /// tests).
    #[cfg(test)]
    pub(crate) fn take_lookup_probes(&self) -> usize {
        self.lookup_probes.replace(0)
    }

    /// Mappings counted toward host slot `host` (O(1)).
    pub(crate) fn count(&self, host: usize) -> usize {
        self.hosts[host].count()
    }

    /// Head of list `list` of host slot `host`: of the host's mappings on
    /// that list, the one that expires first.
    pub(crate) fn head(&self, host: usize, list: usize) -> Option<usize> {
        self.hosts[host].mappings[list].head()
    }

    /// The host slot mapping `index` counts toward, if it counts.
    pub(crate) fn mapping_host(&self, index: usize) -> Option<usize> {
        let tag = self.links.get(index)?.tag;
        (tag != LINK_NONE).then_some(tag as usize / LISTS)
    }

    /// The host slot that loses its last counted mapping when the mapping
    /// in slot `index` is reclaimed or retired, if any.
    pub(crate) fn releasing_host(&self, index: usize) -> Option<usize> {
        self.mapping_host(index)
            .filter(|host| self.hosts[*host].count() == 1)
    }

    /// Prepares the host slot of a new mapping for `address` (`found` is the
    /// result of [`Self::find`]); `None` without accounting. `releasing` is
    /// the host slot that the commit leaves with no counted mapping before
    /// it assigns this one ([`Self::releasing_host`] of the reclaimed
    /// mapping slot).
    ///
    /// A slot is always available: allocated hosts with a counted mapping
    /// number at most the counted mappings, which is at most the mapping
    /// capacity, the host slot count. If no slot is fresh or empty, every
    /// mapping slot counts toward a different host, so the reclaimed mapping
    /// slot is the last of its host, which is `releasing`.
    pub(crate) fn plan_assignment(
        &self,
        address: Ipv4Address,
        found: Option<usize>,
        releasing: Option<usize>,
    ) -> Result<Option<HostAssignment>, HostTableCorrupt> {
        if !self.enabled() {
            return Ok(None);
        }
        let (host, kind) = if let Some(host) = found {
            (host, HostAssignmentKind::Existing)
        } else if let Some(host) = self.empty.head().or(releasing) {
            (host, HostAssignmentKind::Recycle)
        } else if self.next_fresh < self.hosts.len() {
            (self.next_fresh, HostAssignmentKind::Fresh)
        } else {
            return Err(HostTableCorrupt);
        };
        let assignment = HostAssignment {
            hash: self
                .directory
                .hash_words(self.domain, &Self::words(address)),
            host: encode(host)?,
            kind,
        };
        if self.assignment_matches(Some(assignment), address, releasing) {
            Ok(Some(assignment))
        } else {
            Err(HostTableCorrupt)
        }
    }

    /// Whether the planned assignment of a new mapping still applies to
    /// the current state, for a commit whose reclaimed mapping slot leaves
    /// host slot `releasing` empty. Read-only; the commit then applies it
    /// infallibly.
    pub(crate) fn assignment_matches(
        &self,
        assignment: Option<HostAssignment>,
        address: Ipv4Address,
        releasing: Option<usize>,
    ) -> bool {
        let Some(assignment) = assignment else {
            return !self.enabled();
        };
        let host = assignment.host as usize;
        match assignment.kind {
            HostAssignmentKind::Existing => {
                host < self.next_fresh && self.hosts[host].address == address
            }
            HostAssignmentKind::Fresh => {
                host == self.next_fresh
                    && host < self.hosts.len()
                    && self
                        .directory
                        .prepare_link_hashed(host, assignment.hash)
                        .is_ok()
            }
            HostAssignmentKind::Recycle => {
                host < self.next_fresh
                    && self.hosts[host].address != address
                    && (self.hosts[host].count() == 0 || releasing == Some(host))
                    && self
                        .directory
                        .prepare_relink_hashed(host, assignment.hash)
                        .is_ok()
            }
        }
    }

    /// Takes mapping `index` off its host's list, if it counts; a host left
    /// without a counted mapping joins the empty list. O(1).
    pub(crate) fn detach(&mut self, index: usize) {
        let Some(link) = self.links.get(index).copied() else {
            return;
        };
        if link.tag == LINK_NONE {
            return;
        }
        let (host, list) = (link.tag as usize / LISTS, link.tag as usize % LISTS);
        self.hosts[host].mappings[list].unlink(self.links, index);
        self.links[index].tag = LINK_NONE;
        if self.hosts[host].count() == 0 {
            self.empty.push_back(self.hosts, host);
        }
    }

    /// Applies the planned assignment of the new mapping in slot `index`
    /// for `address` (which counts toward no host) and appends the mapping
    /// to the tail of the host's list `list`. O(1); no-op without
    /// accounting.
    pub(crate) fn attach_new(
        &mut self,
        index: usize,
        assignment: Option<HostAssignment>,
        address: Ipv4Address,
        list: usize,
    ) {
        let Some(assignment) = assignment else {
            return;
        };
        let host = assignment.host as usize;
        match assignment.kind {
            HostAssignmentKind::Existing => {}
            HostAssignmentKind::Fresh => {
                debug_assert!(host == self.next_fresh);
                let link = self
                    .directory
                    .prepare_link_hashed(host, assignment.hash)
                    .expect("revalidated host directory link");
                self.directory.apply_prepared_link(link);
                self.next_fresh += 1;
                self.hosts[host] = Nat44HostSlot {
                    address,
                    ..Nat44HostSlot::EMPTY
                };
                // Allocated with no mapping: on the empty list until the
                // mapping below takes it off.
                self.empty.push_back(self.hosts, host);
            }
            HostAssignmentKind::Recycle => {
                debug_assert!(self.hosts[host].count() == 0);
                let relink = self
                    .directory
                    .prepare_relink_hashed(host, assignment.hash)
                    .expect("revalidated host directory relink");
                self.directory.apply_prepared_relink(relink);
                self.hosts[host].address = address;
            }
        }
        debug_assert!(self.links[index] == Nat44HostLink::EMPTY);
        if self.hosts[host].count() == 0 {
            self.empty.unlink(self.hosts, host);
        }
        self.links[index].tag = Self::tag(host, list);
        self.hosts[host].mappings[list].push_back(self.links, index);
    }

    /// Moves counted mapping `index` to the tail of its host's list `list`
    /// (it was just appended to the matching reuse list); no-op for a
    /// mapping that does not count. O(1).
    pub(crate) fn relist(&mut self, index: usize, list: usize) {
        let Some(link) = self.links.get(index).copied() else {
            return;
        };
        if link.tag == LINK_NONE {
            return;
        }
        let (host, old) = (link.tag as usize / LISTS, link.tag as usize % LISTS);
        self.hosts[host].mappings[old].unlink(self.links, index);
        self.links[index].tag = Self::tag(host, list);
        self.hosts[host].mappings[list].push_back(self.links, index);
    }

    /// Exact full check against the mapping slots (validation only, at
    /// worst quadratic in the host count). `counted(index)` is the
    /// address, host list, and expiry order key of mapping slot `index` if
    /// it counts. Without accounting the check is that there is no storage.
    /// Otherwise: allocated host slots are below the fresh boundary with
    /// distinct addresses and keyed directory entries, fresh ones are
    /// default; every counted mapping is on exactly the list `counted`
    /// names of the host slot of its address, each list in nondecreasing
    /// order key; a mapping that does not count is on none; and the empty
    /// list holds exactly the allocated hosts with no counted mapping.
    pub(crate) fn validate(
        &self,
        key: DirectoryHashKey,
        mappings: usize,
        counted: impl Fn(usize) -> Option<(Ipv4Address, usize, u64)>,
    ) -> bool {
        if !self.enabled() {
            return self.links.is_empty() && self.directory.node_capacity() == 0;
        }
        if self.links.len() != mappings {
            return false;
        }
        let Some(fresh) = self.hosts.get(self.next_fresh..) else {
            return false;
        };
        if fresh.iter().any(|host| *host != Nat44HostSlot::EMPTY) {
            return false;
        }
        let allocated = &self.hosts[..self.next_fresh];
        for (index, host) in allocated.iter().enumerate() {
            if allocated[..index]
                .iter()
                .any(|other| other.address == host.address)
            {
                return false;
            }
        }
        if self
            .directory
            .validate_semantics(|index| {
                (index < self.next_fresh)
                    .then(|| key.hash_words(self.domain, &Self::words(self.hosts[index].address)))
            })
            .is_err()
        {
            return false;
        }
        let mut listed = 0_usize;
        for (host_index, host) in allocated.iter().enumerate() {
            for (list, header) in host.mappings.iter().enumerate() {
                let mut previous = 0_u64;
                let consistent = header.validate(self.links, |index| {
                    listed += 1;
                    let expected = Some((host.address, list));
                    let Some((address, mapping_list, order)) = counted(index) else {
                        return false;
                    };
                    let ordered = previous <= order;
                    previous = order;
                    ordered
                        && Some((address, mapping_list)) == expected
                        && self.links[index].tag == Self::tag(host_index, list)
                });
                if !consistent {
                    return false;
                }
            }
        }
        let counted_slots = (0..mappings)
            .filter(|index| counted(*index).is_some())
            .count();
        if listed != counted_slots
            || (0..mappings)
                .any(|index| counted(index).is_none() && self.links[index] != Nat44HostLink::EMPTY)
        {
            return false;
        }
        let empty_hosts = allocated.iter().filter(|host| host.count() == 0).count();
        empty_hosts == self.empty.len()
            && self
                .empty
                .validate(self.hosts, |index| self.hosts[index].count() == 0)
    }

    /// Allocated host slots and those with a counted mapping (tests).
    #[cfg(test)]
    pub(crate) fn host_counts(&self) -> (usize, usize) {
        let allocated = &self.hosts[..self.next_fresh];
        let with_mappings = allocated.iter().filter(|host| host.count() > 0).count();
        (self.next_fresh, with_mappings)
    }
}

/// Leaked host storage for `mappings` mapping slots (tests).
#[cfg(test)]
pub(crate) fn leaked_host_storage<const LISTS: usize>(
    mappings: usize,
) -> Nat44HostStorage<'static, LISTS> {
    let buckets = if mappings == 0 {
        0
    } else {
        mappings.next_power_of_two()
    };
    Nat44HostStorage::new(
        Box::leak(vec![Nat44HostLink::EMPTY; mappings].into_boxed_slice()),
        Box::leak(vec![Nat44HostSlot::EMPTY; mappings].into_boxed_slice()),
        Box::leak(vec![DirectoryBucket::default(); buckets].into_boxed_slice()),
        Box::leak(vec![DirectoryNode::default(); mappings].into_boxed_slice()),
    )
}

fn encode(index: usize) -> Result<u32, HostTableCorrupt> {
    u32::try_from(index)
        .ok()
        .filter(|link| *link != LINK_NONE)
        .ok_or(HostTableCorrupt)
}

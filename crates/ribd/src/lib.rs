#![forbid(unsafe_code)]
//! The route selection process (`docs/design/ce-processes.md`, "ruster-ribd").
//!
//! Each route source (confd for static and connected routes; later DHCP, PPPoE and
//! routing daemons) writes its candidate routes to its own table server inside ribd.
//! For every VRF and prefix ribd picks the route of the source with the lowest
//! preference and writes the result to the FE's route table, sending only what changed.
//!
//! When ribd starts it does not know what the FE holds. It marks the FE's routes
//! (resync-begin), keeps sending what it selects, and deletes the rest (resync-end)
//! only after every source said it has sent everything (`sync-done`) or its hold time
//! ran out. Forwarding keeps the old routes in the meantime.
//!
//! A source given a drop time ([`SourceSpec::drop_after_ms`]) that has had no
//! connection for that long loses its routes; others keep theirs until they connect
//! again or ribd restarts.
//!
//! A selected route whose next hops are only gateway addresses is resolved through
//! the other selected routes of its VRF before it goes to the FE ([`resolve`]).
//!
//! Skeleton limits: no route leaking between VRFs, no metric or ECMP across sources.
//!
//! # Standards
//!
//! - RFC 8349 (`ietf-routing`): routes per VRF and prefix, chosen by route preference
//!   (lower is preferred) between sources.
//! - RFC 4271 sections 5.1.3 and 9.1.2.1: gateways are resolved recursively (see
//!   [`resolve`]).
//!
//! Deviations: a preference is set per source, not per route. ribd does not know
//! the interfaces, so a route out of a disabled interface may be chosen over a
//! usable one (RFC 8349 chooses among usable routes), and the FE leaves it out;
//! confd offers none of its own static routes out of one.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Client, Event, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{network, Change, Key, RouteAction, Value};
use ruster_proto::task::{Progress, Task};

pub mod resolve;

/// A route source and how much it is preferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSpec {
    pub name: String,
    /// Lower wins, like an administrative distance.
    pub preference: u32,
    /// After ribd starts, how long to wait for this source's `sync-done`.
    pub hold_ms: u64,
    /// When set, the source's routes go once it has had no connection for this
    /// long. When not, they stay until it connects again or ribd restarts.
    pub drop_after_ms: Option<u64>,
}

/// How ribd works, apart from its sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Gateways may be resolved through the default route ([`resolve`]).
    pub resolve_via_default: bool,
    /// The most changes one patch to the FE carries. More go in several patches, one
    /// after the other's answer, so that no message passes the connection's size
    /// limit (a full table after the FE restarted, or a table arriving faster than
    /// the FE takes it).
    pub changes_per_patch: usize,
}

/// A route with 16 next hops on long interface names takes about 1 KiB, so 8,192 of
/// them stay well below the 16 MiB a message may have.
pub const CHANGES_PER_PATCH: usize = 8_192;

impl Default for Options {
    fn default() -> Self {
        Self {
            resolve_via_default: false,
            changes_per_patch: CHANGES_PER_PATCH,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RibdCounters {
    pub patches_sent: u64,
    pub patches_refused: u64,
    /// Sources whose routes went because they stayed away.
    pub sources_dropped: u64,
}

struct Source {
    spec: SourceSpec,
    server: Server,
    /// How many of its routes give their next hops as gateways only.
    gateways: usize,
    /// The gateway addresses of those routes, by VRF, and how many routes give each.
    gateway_addresses: BTreeMap<(String, IpAddr), usize>,
    /// Since when it has had no connection, while it has routes.
    gone_since: Option<u64>,
}

fn is_gateways(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Route(RouteAction::Gateways(_))))
}

/// The VRF and gateway addresses of a gateway route.
fn gateways_of<'a>(key: &'a Key, value: Option<&'a Value>) -> Option<(&'a str, &'a [IpAddr])> {
    match (key, value) {
        (Key::Route { vrf, .. }, Some(Value::Route(RouteAction::Gateways(gateways)))) => {
            Some((vrf.as_str(), gateways.as_slice()))
        }
        _ => None,
    }
}

fn count_gateways(
    addresses: &mut BTreeMap<(String, IpAddr), usize>,
    key: &Key,
    value: Option<&Value>,
    add: bool,
) {
    let Some((vrf, gateways)) = gateways_of(key, value) else {
        return;
    };
    for &gateway in gateways {
        let entry = (vrf.to_owned(), gateway);
        if add {
            *addresses.entry(entry).or_default() += 1;
        } else if let Some(count) = addresses.get_mut(&entry) {
            *count -= 1;
            if *count == 0 {
                addresses.remove(&entry);
            }
        }
    }
}

/// The last address of a prefix.
fn last_address(prefix: IpAddr, len: u8) -> IpAddr {
    match network(prefix, len) {
        IpAddr::V4(a) => {
            IpAddr::V4((u32::from(a) | u32::MAX.checked_shr(u32::from(len)).unwrap_or(0)).into())
        }
        IpAddr::V6(a) => {
            IpAddr::V6((u128::from(a) | u128::MAX.checked_shr(u32::from(len)).unwrap_or(0)).into())
        }
    }
}

/// Notes what changed in a source's table.
struct Changed<'a> {
    /// Whether anything did.
    any: bool,
    /// Whether it changed in a way that does not say which entries (the end of a
    /// resync).
    whole: bool,
    /// The entries its patches touched are added here.
    touched: &'a mut BTreeSet<Key>,
    gateways: &'a mut usize,
    gateway_addresses: &'a mut BTreeMap<(String, IpAddr), usize>,
}

impl Hook for Changed<'_> {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        self.whole = true;
        *self.gateways = next
            .iter()
            .filter(|(_, value)| is_gateways(Some(value)))
            .count();
        self.gateway_addresses.clear();
        for (key, value) in next.iter() {
            count_gateways(self.gateway_addresses, key, Some(value), true);
        }
        Ok(())
    }

    fn check_patch(
        &mut self,
        next: &Store,
        changed: &[(&Key, Option<&Value>)],
    ) -> Result<(), String> {
        for (key, before) in changed {
            if is_gateways(*before) {
                *self.gateways -= 1;
            }
            if is_gateways(next.get(key)) {
                *self.gateways += 1;
            }
            count_gateways(self.gateway_addresses, key, *before, false);
            count_gateways(self.gateway_addresses, key, next.get(key), true);
            self.touched.insert((*key).clone());
        }
        Ok(())
    }

    fn committed(&mut self, _store: &Store) {
        self.any = true;
    }
}

pub struct Ribd {
    sources: Vec<Source>,
    options: Options,
    fe: Client,
    /// What the FE was sent since ribd started.
    sent: BTreeMap<Key, Value>,
    /// When ribd started waiting, set on the first step; `None` again once the FE's
    /// unrefreshed routes were deleted.
    waiting_since: Option<Option<u64>>,
    dirty: bool,
    /// The next patch is made by going through every route, not only those in
    /// `touched`: at the start, after a source's resync, and whenever what the FE
    /// holds is unclear.
    whole: bool,
    /// The routes the sources' patches touched since the last patch to the FE was
    /// made.
    touched: BTreeSet<Key>,
    /// The patches made each way.
    #[cfg(test)]
    made: (usize, usize),
    /// resync-begin was sent; resync-end follows once the FE accepted the full send.
    resync_pending: bool,
    /// The patch waiting for the FE's answer, and its changes: once accepted, the FE
    /// holds what it held before with them.
    in_flight: Option<(u32, Vec<Change>)>,
    /// Changes made but not sent yet, because a patch carries at most
    /// [`Options::changes_per_patch`]. None of their keys is in the patch in flight.
    queued: BTreeMap<Key, Change>,
    /// The resync-end waiting for the FE's answer.
    resync_end: Option<u32>,
    /// The FE refused resync-end: what it holds stays marked stale, and resync-end
    /// goes again after the next change from a source (not every step), or
    /// [`RESYNC_END_RETRY_MS`] after the refusal was seen (what the FE refused for
    /// may have gone).
    resync_end_refused: bool,
    refused_at: Option<u64>,
    /// The FE refused a patch: everything goes again with the next change from a
    /// source, or [`RESYNC_END_RETRY_MS`] after the refusal was seen.
    patch_refused: Option<Option<u64>>,
    counters: RibdCounters,
}

/// A refused resync-end is sent again at least this often.
pub const RESYNC_END_RETRY_MS: u64 = 10_000;

impl std::fmt::Debug for Ribd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ribd")
            .field("sources", &self.sources.len())
            .field("sent", &self.sent.len())
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl Ribd {
    /// `fe` is a connection to the FE allowed to write the route table.
    pub fn new(fe: UnixStream, sources: Vec<SourceSpec>) -> io::Result<Self> {
        Self::with_options(fe, sources, Options::default())
    }

    pub fn with_options(
        fe: UnixStream,
        sources: Vec<SourceSpec>,
        options: Options,
    ) -> io::Result<Self> {
        let mut fe = Client::new(fe)?;
        fe.resync_begin();
        Ok(Self {
            sources: sources
                .into_iter()
                .map(|spec| Source {
                    spec,
                    server: Server::new(),
                    gateways: 0,
                    gateway_addresses: BTreeMap::new(),
                    gone_since: None,
                })
                .collect(),
            options,
            fe,
            sent: BTreeMap::new(),
            waiting_since: Some(None),
            dirty: false,
            whole: true,
            touched: BTreeSet::new(),
            #[cfg(test)]
            made: (0, 0),
            resync_pending: false,
            in_flight: None,
            queued: BTreeMap::new(),
            resync_end: None,
            resync_end_refused: false,
            refused_at: None,
            patch_refused: None,
            counters: RibdCounters::default(),
        })
    }

    /// Accepts the connection of the source `name`. A new connection for the same
    /// source replaces the old one.
    pub fn attach_source(&mut self, name: &str, stream: UnixStream) -> io::Result<()> {
        let source = self
            .sources
            .iter_mut()
            .find(|s| s.spec.name == name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown route source"))?;
        source.server.attach(stream, &[sid::ROUTE])
    }

    /// True once the FE connection closed (the FE stopped or restarted).
    pub fn fe_closed(&self) -> bool {
        self.fe.is_closed()
    }

    /// Replaces a closed FE connection and sends the FE every selected route again.
    /// Routes the FE holds that are no longer selected are deleted, unless ribd is
    /// still waiting for its sources after start-up.
    pub fn reconnect_fe(&mut self, stream: UnixStream) -> io::Result<()> {
        let mut fe = Client::new(stream)?;
        fe.resync_begin();
        self.fe = fe;
        self.sent.clear();
        self.in_flight = None;
        self.queued.clear();
        self.resync_end = None;
        self.resync_end_refused = false;
        self.refused_at = None;
        self.patch_refused = None;
        self.dirty = true;
        self.whole = true;
        self.resync_pending = self.waiting_since.is_none();
        Ok(())
    }

    pub fn counters(&self) -> RibdCounters {
        self.counters
    }

    /// True once the FE's routes not sent again since start were deleted.
    pub fn synced(&self) -> bool {
        self.waiting_since.is_none()
    }

    /// The selected route for every VRF and prefix, with gateways resolved: what the
    /// FE should hold.
    fn selected(&self) -> BTreeMap<Key, Value> {
        let mut order: Vec<&Source> = self.sources.iter().collect();
        order.sort_by_key(|s| s.spec.preference);
        let mut selected = BTreeMap::new();
        for source in order {
            for (key, value) in source.server.store().iter() {
                if matches!(key, Key::Route { .. }) {
                    selected.entry(key.clone()).or_insert_with(|| value.clone());
                }
            }
        }
        resolve::resolve(&mut selected, self.options.resolve_via_default);
        selected
    }

    /// Sends the FE what changed since what it accepted. One patch at a time: what
    /// the FE holds is only known once it answered. A patch carries at most
    /// [`Options::changes_per_patch`] changes; the rest wait in `queued` for the next.
    /// Returns whether a patch was sent.
    fn push(&mut self) -> bool {
        if self.in_flight.is_some() {
            // Sent after the answer; the answer wakes the next step.
            self.dirty = true;
            return false;
        }
        let touched = std::mem::take(&mut self.touched);
        // A route given by its gateways is resolved through the other routes. When a
        // touched route may be what a gateway matches, or a touched gateway route
        // matches another gateway route, every route is gone through.
        let mut whole = self.whole || self.gateways_reached(&touched);
        self.whole = false;
        let mut changes = Vec::new();
        if !whole {
            match self.changes_of(&touched) {
                Some(of) => changes = of,
                None => whole = true,
            }
        }
        if whole {
            let selected = self.selected();
            self.queued.clear();
            for (key, value) in &selected {
                if self.sent.get(key) != Some(value) {
                    self.queued
                        .insert(key.clone(), Change::set(key.clone(), value.clone()));
                }
            }
            for key in self.sent.keys() {
                if !selected.contains_key(key) {
                    self.queued.insert(key.clone(), Change::delete(key.clone()));
                }
            }
        } else {
            // A queued change of a route touched again may be out of date.
            for key in &touched {
                self.queued.remove(key);
            }
            for change in changes {
                self.queued.insert(change.key.clone(), change);
            }
        }
        if self.queued.is_empty() {
            return false;
        }
        let mut changes = Vec::new();
        while changes.len() < self.options.changes_per_patch.max(1) {
            let Some((_, change)) = self.queued.pop_first() else {
                break;
            };
            changes.push(change);
        }
        match self.fe.patch(&changes) {
            Ok(token) => {
                self.counters.patches_sent += 1;
                #[cfg(test)]
                if whole {
                    self.made.0 += 1;
                } else {
                    self.made.1 += 1;
                }
                // The rest goes after the answer (`step`).
                self.in_flight = Some((token, changes));
                true
            }
            Err(_) => {
                // Not sent: what it would have changed is looked at again.
                self.whole = true;
                false
            }
        }
    }

    /// Whether a touched route's prefix holds a gateway address of a gateway route:
    /// its change may change what that route resolves to.
    fn gateways_reached(&self, touched: &BTreeSet<Key>) -> bool {
        if self.sources.iter().all(|source| source.gateways == 0) {
            return false;
        }
        touched.iter().any(|key| {
            let Key::Route { vrf, prefix, len } = key else {
                return false;
            };
            let first = (vrf.clone(), network(*prefix, *len));
            let last = (vrf.clone(), last_address(*prefix, *len));
            self.sources.iter().any(|source| {
                source
                    .gateway_addresses
                    .range(first.clone()..=last.clone())
                    .next()
                    .is_some()
            })
        })
    }

    /// The selected route of `key`, as its best source gives it.
    fn selected_of(&self, key: &Key) -> Option<&Value> {
        self.sources
            .iter()
            .filter_map(|source| Some((source.spec.preference, source.server.store().get(key)?)))
            .min_by_key(|(preference, _)| *preference)
            .map(|(_, value)| value)
    }

    /// What the FE must be sent for the routes `touched`, when no gateway route
    /// resolves through them ([`Self::gateways_reached`]): for each, the route of the
    /// best source that has it, resolved if it is a gateway route, if that is not
    /// what the FE was sent. `None` when a touched gateway route matches another
    /// gateway route, which only resolving every route works out.
    fn changes_of(&self, touched: &BTreeSet<Key>) -> Option<Vec<Change>> {
        let mut changes = Vec::new();
        for key in touched {
            if !matches!(key, Key::Route { .. }) {
                continue;
            }
            let selected = match self.selected_of(key) {
                Some(Value::Route(RouteAction::Gateways(gateways))) => {
                    let hops = resolve::resolve_one(
                        key,
                        gateways,
                        self.options.resolve_via_default,
                        |at| self.selected_of(at),
                    )?;
                    (!hops.is_empty()).then_some(Value::Route(RouteAction::Forward(hops)))
                }
                other => other.cloned(),
            };
            match (selected, self.sent.get(key)) {
                (Some(value), sent) if sent != Some(&value) => {
                    changes.push(Change::set(key.clone(), value));
                }
                (None, Some(_)) => changes.push(Change::delete(key.clone())),
                _ => {}
            }
        }
        Some(changes)
    }

    /// resync-end deletes what the FE holds from ribd but was not sent again, so it
    /// goes only after the full send was accepted.
    ///
    /// `sent` is cleared at resync-begin and holds only what the FE accepted since, so
    /// once it equals the selection the FE holds everything ribd wants.
    fn finish_resync(&mut self) -> bool {
        if self.resync_pending
            && !self.resync_end_refused
            && self.resync_end.is_none()
            && self.in_flight.is_none()
            && !self.dirty
            && self.queued.is_empty()
            && self.sent == self.selected()
        {
            self.resync_end = Some(self.fe.resync_end());
            self.resync_pending = false;
            return true;
        }
        false
    }

    fn ready_to_sweep(&self, now_ms: u64, since: u64) -> bool {
        self.sources
            .iter()
            .all(|s| s.server.sync_done() || now_ms >= since.saturating_add(s.spec.hold_ms))
    }
}

impl Task for Ribd {
    fn step(&mut self, now_ms: u64) -> Progress {
        let mut progress = Progress::IDLE;
        for source in &mut self.sources {
            let mut changed = Changed {
                any: false,
                whole: false,
                touched: &mut self.touched,
                gateways: &mut source.gateways,
                gateway_addresses: &mut source.gateway_addresses,
            };
            progress = progress.and(source.server.step(&mut changed));
            // A source that went away for longer than it may: its routes go.
            if let Some(after) = source.spec.drop_after_ms {
                if source.server.peers() > 0 || source.server.store().is_empty() {
                    source.gone_since = None;
                } else {
                    let since = *source.gone_since.get_or_insert(now_ms);
                    let at = since.saturating_add(after);
                    if now_ms >= at {
                        source.gone_since = None;
                        if source.server.drop_tables(&[sid::ROUTE], &mut changed) {
                            self.counters.sources_dropped += 1;
                            eprintln!(
                                "ruster-ribd: source {} has been away {after} ms; its routes go",
                                source.spec.name
                            );
                        }
                    } else {
                        progress = progress.and(Progress {
                            busy: false,
                            wake_at: Some(at),
                        });
                    }
                }
            }
            self.dirty |= changed.any;
            self.whole |= changed.whole;
            self.resync_end_refused &= !changed.any;
        }
        let (fe, events) = self.fe.poll();
        progress = progress.and(fe);
        self.answers(&events);
        if let Some(waiting) = &mut self.waiting_since {
            let since = *waiting.get_or_insert(now_ms);
            if self.ready_to_sweep(now_ms, since) {
                self.waiting_since = None;
                self.resync_pending = true;
                self.dirty = true;
                self.whole = true;
            } else {
                let deadline = self
                    .sources
                    .iter()
                    .filter(|s| !s.server.sync_done())
                    .map(|s| since.saturating_add(s.spec.hold_ms))
                    .min();
                progress = progress.and(Progress {
                    busy: false,
                    wake_at: deadline,
                });
            }
        }
        // Queued changes go once the patch before them was answered. A refusal
        // empties the queue, so a refused patch is not sent again at once.
        let queued = !self.queued.is_empty() && self.in_flight.is_none();
        if (std::mem::take(&mut self.dirty) || queued) && self.push() {
            progress.busy = true;
        }
        if let Some(seen) = self.patch_refused.as_mut() {
            let at = *seen.get_or_insert(now_ms);
            let retry_at = at.saturating_add(RESYNC_END_RETRY_MS);
            if now_ms >= retry_at && self.in_flight.is_none() {
                self.patch_refused = None;
                self.dirty = true;
                self.whole = true;
                progress.busy = true;
            } else if now_ms < retry_at {
                progress = progress.and(Progress {
                    busy: false,
                    wake_at: Some(retry_at),
                });
            }
        }
        if self.resync_end_refused {
            let at = *self.refused_at.get_or_insert(now_ms);
            let retry_at = at.saturating_add(RESYNC_END_RETRY_MS);
            if now_ms >= retry_at {
                self.resync_end_refused = false;
            } else {
                progress = progress.and(Progress {
                    busy: false,
                    wake_at: Some(retry_at),
                });
            }
        }
        if !self.resync_end_refused {
            self.refused_at = None;
        }
        if self.finish_resync() {
            progress.busy = true;
        }
        let (flushed, events) = self.fe.poll();
        self.answers(&events);
        // An answer just read lets the queued changes go on the next step.
        progress.busy |= !self.queued.is_empty() && self.in_flight.is_none();
        progress.and(flushed)
    }
}

impl Ribd {
    /// Handles the FE's answers. An accepted patch makes its routes what the FE holds;
    /// a refused one starts a resync, so routes the FE already has are kept until a
    /// later full send is accepted. The refused routes go again with the next change, or after RESYNC_END_RETRY_MS.
    fn answers(&mut self, events: &[Event]) {
        for event in events {
            let Event::Response { token, code, .. } = event else {
                continue;
            };
            let refused = code.class() != 2;
            if refused {
                self.counters.patches_refused += 1;
            }
            if self.resync_end == Some(*token) {
                self.resync_end = None;
                if refused {
                    self.resync_pending = true;
                    // A change from a source in this same step, or a patch on its
                    // way, already counts as the next change: resync-end goes
                    // again after it.
                    self.resync_end_refused = !self.dirty && self.in_flight.is_none();
                }
            }
            if self.in_flight.as_ref().is_some_and(|(t, _)| t == token) {
                let (_, changes) = self.in_flight.take().expect("checked");
                if refused {
                    // What the FE holds from ribd is now unclear: start a resync, so
                    // the next accepted full send is followed by resync-end. Routes
                    // the FE holds stay until then.
                    self.fe.resync_begin();
                    self.sent.clear();
                    self.queued.clear();
                    self.whole = true;
                    self.patch_refused.get_or_insert(None);
                    if self.waiting_since.is_none() {
                        self.resync_pending = true;
                    }
                } else {
                    for change in changes {
                        match change.value {
                            Some(value) => self.sent.insert(change.key, value),
                            None => self.sent.remove(&change.key),
                        };
                    }
                    self.patch_refused = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ruster_proto::table::NextHop;

    use super::*;

    /// The FE: refuses tables with a route out of "bad".
    struct Fe;

    impl Hook for Fe {
        fn check(&mut self, next: &Store) -> Result<(), String> {
            let bad = next.iter().any(|(_, value)| {
                matches!(value, Value::Route(RouteAction::Forward(hops))
                    if hops.iter().any(|hop| hop.interface == "bad"))
            });
            if bad {
                Err("refused".into())
            } else {
                Ok(())
            }
        }

        fn committed(&mut self, _store: &Store) {}
    }

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, bound: u64) -> u64 {
            // SplitMix64.
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (value ^ (value >> 31)) % bound
        }
    }

    /// A change of one of few routes: removed, out of an interface, or (with
    /// `gateways`) through a gateway that the other routes may or may not reach.
    fn change(rng: &mut Rng, gateways: bool, bad: bool) -> Change {
        let prefixes: [(&str, u8); 6] = [
            ("0.0.0.0", 0),
            ("10.0.0.0", 8),
            ("10.1.0.0", 16),
            ("10.1.2.0", 24),
            ("192.0.2.0", 24),
            ("198.51.100.0", 24),
        ];
        let (prefix, len) = prefixes[rng.below(6) as usize];
        let key = Key::Route {
            vrf: ["default", "red"][rng.below(2) as usize].into(),
            prefix: prefix.parse().unwrap(),
            len,
        };
        let action = match rng.below(10) {
            0..=2 => return Change::delete(key),
            3 if gateways => {
                let gateway: IpAddr = ["10.1.2.3", "192.0.2.9", "203.0.113.1"]
                    [rng.below(3) as usize]
                    .parse()
                    .unwrap();
                RouteAction::Gateways(vec![gateway])
            }
            4 if bad => RouteAction::Forward(vec![NextHop {
                interface: "bad".into(),
                address: None,
            }]),
            _ => RouteAction::Forward(vec![NextHop {
                interface: ["a", "b", "c"][rng.below(3) as usize].into(),
                address: None,
            }]),
        };
        Change::set(key, Value::Route(action))
    }

    /// Runs changes from three sources against an FE and, whenever all is quiet and
    /// the FE refused nothing, has what the FE holds be the selection made by going
    /// through every route. Returns the patches made each way.
    fn run(seed: u64, rounds: usize, gateways: bool, per_patch: usize) -> (usize, usize) {
        let mut rng = Rng(seed);
        let mut fe = Server::new();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::ROUTE]).unwrap();
        let specs =
            [("static", 1), ("ospf", 20), ("bgp", 50)].map(|(name, preference)| SourceSpec {
                name: name.into(),
                preference,
                hold_ms: 0,
                drop_after_ms: None,
            });
        let options = Options {
            changes_per_patch: per_patch,
            ..Options::default()
        };
        let mut ribd = Ribd::with_options(b, specs.to_vec(), options).unwrap();
        let mut sources: Vec<Client> = specs
            .iter()
            .map(|spec| {
                let (a, b) = UnixStream::pair().unwrap();
                ribd.attach_source(&spec.name, a).unwrap();
                let mut client = Client::new(b).unwrap();
                client.sync_done();
                client
            })
            .collect();
        let mut now = 0;
        let mut checked = 0;
        // Steps with a patch on its way while a source has changed again.
        let mut overtaken = 0;
        for _ in 0..rounds {
            let source = &mut sources[rng.below(3) as usize];
            let bad = rng.below(12) == 0;
            match rng.below(12) {
                0 => {
                    source.resync_begin();
                    let again: Vec<Change> = (0..rng.below(4))
                        .map(|_| change(&mut rng, gateways, false))
                        .filter(|change| change.value.is_some())
                        .collect();
                    source.patch(&again).unwrap();
                    source.resync_end();
                }
                _ => {
                    let changes: Vec<Change> = (0..1 + rng.below(3))
                        .map(|_| change(&mut rng, gateways, bad))
                        .collect();
                    source.patch(&changes).unwrap();
                }
            }
            // Time passes, so that what the FE refused is tried again.
            now += RESYNC_END_RETRY_MS / 3;
            // At times the next change comes before the FE answered this one: ribd
            // takes the change and sends its patch, and the FE is not stepped.
            if rng.below(3) == 0 {
                for _ in 0..2 {
                    for source in &mut sources {
                        source.poll();
                    }
                    ribd.step(now);
                    overtaken += usize::from(ribd.in_flight.is_some() && !ribd.touched.is_empty());
                }
                continue;
            }
            let mut quiet = false;
            for _ in 0..1_000 {
                let mut busy = fe.step(&mut Fe).busy;
                busy |= ribd.step(now).busy;
                for source in &mut sources {
                    busy |= source.poll().0.busy;
                }
                if !busy {
                    quiet = true;
                    break;
                }
            }
            assert!(quiet, "never settled");
            let selected = ribd.selected();
            // What the FE refuses.
            let refused = selected.values().any(|value| {
                matches!(value, Value::Route(RouteAction::Forward(hops))
                    if hops.iter().any(|hop| hop.interface == "bad"))
            });
            if refused {
                continue;
            }
            // What the FE refused before may still be waiting for its next try.
            if ribd.patch_refused.is_some() || ribd.resync_pending || ribd.resync_end_refused {
                continue;
            }
            let held: BTreeMap<Key, Value> = fe
                .store()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            assert_eq!(ribd.sent, selected, "seed {seed}");
            assert_eq!(held, selected, "seed {seed}");
            checked += 1;
        }
        assert!(checked > rounds / 3, "{checked} of {rounds}");
        if !gateways {
            assert!(overtaken > 0, "no change came while a patch was on its way");
        }
        ribd.made
    }

    #[test]
    fn going_through_the_touched_routes_gives_what_going_through_every_route_gives() {
        let mut whole = 0;
        let mut touched = 0;
        for seed in 0..2 {
            let made = run(0x7269_6264 + seed, 100, false, CHANGES_PER_PATCH);
            whole += made.0;
            touched += made.1;
        }
        // Mostly the touched routes alone; every route after a resync or a refusal.
        assert!(touched > 60, "{touched}");
        assert!(whole > 10, "{whole}");
    }

    #[test]
    fn with_routes_given_by_their_gateways_the_touched_routes_mostly_do() {
        let mut whole = 0;
        let mut touched = 0;
        for seed in 0..1 {
            let made = run(0x6761_7465 + seed, 120, true, CHANGES_PER_PATCH);
            whole += made.0;
            touched += made.1;
        }
        // A touched route that holds a gateway, or a gateway route through another,
        // makes every route be gone through; otherwise the touched routes alone are.
        assert!(whole > 30, "{whole}");
        assert!(touched > 10, "{touched}");
    }

    #[test]
    fn patches_of_a_few_changes_each_give_the_same() {
        for (seed, gateways) in [(0x7370_6c69, false), (0x7370_6c6a, true)] {
            for per_patch in [1, 2] {
                run(seed, 80, gateways, per_patch);
            }
        }
    }

    /// The FE: records how many changes each patch had.
    #[derive(Default)]
    struct Sizes(Vec<usize>);

    impl Hook for Sizes {
        fn check(&mut self, _next: &Store) -> Result<(), String> {
            Ok(())
        }

        fn check_patch(
            &mut self,
            _next: &Store,
            changed: &[(&Key, Option<&Value>)],
        ) -> Result<(), String> {
            self.0.push(changed.len());
            Ok(())
        }

        fn committed(&mut self, _store: &Store) {}
    }

    #[test]
    fn many_routes_go_in_patches_of_at_most_the_limit() {
        let mut fe = Server::new();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::ROUTE]).unwrap();
        let spec = SourceSpec {
            name: "bgp".into(),
            preference: 50,
            hold_ms: 0,
            drop_after_ms: None,
        };
        let options = Options {
            changes_per_patch: 7,
            ..Options::default()
        };
        let mut ribd = Ribd::with_options(b, vec![spec], options).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        ribd.attach_source("bgp", a).unwrap();
        let mut source = Client::new(b).unwrap();
        let route = |i: u32, interface: &str| {
            let key = Key::Route {
                vrf: "default".into(),
                prefix: std::net::Ipv4Addr::from(0x0a00_0000 + (i << 8)).into(),
                len: 24,
            };
            let hop = NextHop {
                interface: interface.into(),
                address: None,
            };
            Change::set(key, Value::Route(RouteAction::Forward(vec![hop])))
        };
        let mut sizes = Sizes::default();
        let mut settle = |ribd: &mut Ribd, source: &mut Client, sizes: &mut Sizes| {
            for _ in 0..10_000 {
                let mut busy = fe.step(sizes).busy;
                busy |= ribd.step(0).busy;
                busy |= source.poll().0.busy;
                if !busy {
                    return fe.store().iter().count();
                }
            }
            panic!("never settled");
        };
        source.sync_done();
        source
            .patch(&(0..100).map(|i| route(i, "a")).collect::<Vec<_>>())
            .unwrap();
        assert_eq!(settle(&mut ribd, &mut source, &mut sizes), 100);
        // Changes that come while the first patches are on their way.
        source
            .patch(&(50..150).map(|i| route(i, "b")).collect::<Vec<_>>())
            .unwrap();
        assert_eq!(settle(&mut ribd, &mut source, &mut sizes), 150);
        assert!(sizes.0.iter().all(|&n| n <= 7), "{:?}", sizes.0);
        assert!(sizes.0.len() >= 150 / 7, "{:?}", sizes.0);
        let held: BTreeMap<Key, Value> = fe
            .store()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(held, ribd.selected());
    }

    /// A BGP table: many routes through two gateways on a connected route.
    #[test]
    fn changing_gateway_routes_goes_through_only_them() {
        let mut fe = Server::new();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::ROUTE]).unwrap();
        let specs = [("confd", 1), ("bgp", 50)].map(|(name, preference)| SourceSpec {
            name: name.into(),
            preference,
            hold_ms: 0,
            drop_after_ms: None,
        });
        let mut ribd = Ribd::new(b, specs.to_vec()).unwrap();
        let mut sources: Vec<Client> = specs
            .iter()
            .map(|spec| {
                let (a, b) = UnixStream::pair().unwrap();
                ribd.attach_source(&spec.name, a).unwrap();
                let mut client = Client::new(b).unwrap();
                client.sync_done();
                client
            })
            .collect();
        let key = |text: &str| {
            let (prefix, len) = text.split_once('/').unwrap();
            Key::Route {
                vrf: "default".into(),
                prefix: prefix.parse().unwrap(),
                len: len.parse().unwrap(),
            }
        };
        let connected = |interface: &str| {
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: interface.into(),
                address: None,
            }]))
        };
        let via =
            |gateway: &str| Value::Route(RouteAction::Gateways(vec![gateway.parse().unwrap()]));
        let bgp = |i: u32, gateway: &str| {
            let prefix = std::net::Ipv4Addr::from(0x6400_0000 + (i << 8));
            Change::set(key(&format!("{prefix}/24")), via(gateway))
        };
        let mut settle = |ribd: &mut Ribd, sources: &mut Vec<Client>| {
            for _ in 0..10_000 {
                let mut busy = fe.step(&mut Fe).busy;
                busy |= ribd.step(0).busy;
                for source in sources.iter_mut() {
                    busy |= source.poll().0.busy;
                }
                if !busy {
                    let held: BTreeMap<Key, Value> = fe
                        .store()
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect();
                    assert_eq!(held, ribd.selected());
                    return held;
                }
            }
            panic!("never settled");
        };
        sources[0]
            .patch(&[Change::set(key("198.51.100.0/24"), connected("wan"))])
            .unwrap();
        sources[1]
            .patch(&(0..200).map(|i| bgp(i, "198.51.100.1")).collect::<Vec<_>>())
            .unwrap();
        let held = settle(&mut ribd, &mut sources);
        assert_eq!(held.len(), 201);
        let whole = ribd.made.0;
        // Changes of the BGP routes alone: no route is gone through again.
        for round in 0..20 {
            let gateway = ["198.51.100.1", "198.51.100.2"][round % 2];
            sources[1]
                .patch(
                    &(round as u32 * 10..round as u32 * 10 + 10)
                        .map(|i| bgp(i, gateway))
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            settle(&mut ribd, &mut sources);
        }
        // A gateway that matches nothing: the route goes.
        sources[1].patch(&[bgp(0, "203.0.113.1")]).unwrap();
        assert_eq!(settle(&mut ribd, &mut sources).len(), 200);
        assert_eq!(ribd.made.0, whole);
        // The connected route the gateways match changes: every route goes again.
        sources[0]
            .patch(&[Change::set(key("198.51.100.0/24"), connected("wan2"))])
            .unwrap();
        let held = settle(&mut ribd, &mut sources);
        assert!(ribd.made.0 > whole);
        assert!(held.values().all(|value| match value {
            Value::Route(RouteAction::Forward(hops)) => hops[0].interface == "wan2",
            _ => false,
        }));
    }

    /// Two sources with the same routes' kind: `kept` keeps its routes when it goes
    /// away, `dropped` loses them after 1 s without a connection.
    #[test]
    fn a_source_away_longer_than_it_may_loses_its_routes() {
        let mut fe = Server::new();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::ROUTE]).unwrap();
        let specs = [("kept", 20, None), ("dropped", 50, Some(1_000))].map(
            |(name, preference, drop_after_ms)| SourceSpec {
                name: name.into(),
                preference,
                hold_ms: 0,
                drop_after_ms,
            },
        );
        let mut ribd = Ribd::new(b, specs.to_vec()).unwrap();
        let route = |third: u8| {
            let key = Key::Route {
                vrf: "default".into(),
                prefix: std::net::Ipv4Addr::new(10, 0, third, 0).into(),
                len: 24,
            };
            let hop = NextHop {
                interface: "a".into(),
                address: None,
            };
            Change::set(key, Value::Route(RouteAction::Forward(vec![hop])))
        };
        let connect = |ribd: &mut Ribd, name: &str, third: u8| {
            let (a, b) = UnixStream::pair().unwrap();
            ribd.attach_source(name, a).unwrap();
            let mut client = Client::new(b).unwrap();
            client.patch(&[route(third)]).unwrap();
            client.sync_done();
            client
        };
        let mut kept = Some(connect(&mut ribd, "kept", 1));
        let mut dropped = Some(connect(&mut ribd, "dropped", 2));
        // How many routes the FE holds once all is quiet at `now`.
        let mut settle = |ribd: &mut Ribd, now: u64| {
            for _ in 0..1_000 {
                let busy = fe.step(&mut Fe).busy | ribd.step(now).busy;
                if !busy {
                    break;
                }
            }
            fe.store().len()
        };
        for client in [&mut kept, &mut dropped].into_iter().flatten() {
            client.poll();
        }
        assert_eq!(settle(&mut ribd, 0), 2);
        // Both go away.
        drop(kept.take());
        drop(dropped.take());
        assert_eq!(settle(&mut ribd, 10), 2);
        assert_eq!(settle(&mut ribd, 1_009), 2);
        assert_eq!(settle(&mut ribd, 1_010), 1);
        assert_eq!(ribd.counters().sources_dropped, 1);
        // Back, and away again: a connection before the time keeps the routes.
        dropped = Some(connect(&mut ribd, "dropped", 2));
        dropped.as_mut().unwrap().poll();
        assert_eq!(settle(&mut ribd, 2_000), 2);
        drop(dropped.take());
        assert_eq!(settle(&mut ribd, 2_500), 2);
        dropped = Some(connect(&mut ribd, "dropped", 2));
        dropped.as_mut().unwrap().poll();
        assert_eq!(settle(&mut ribd, 3_400), 2);
        assert_eq!(settle(&mut ribd, 9_000), 2);
        assert_eq!(ribd.counters().sources_dropped, 1);
    }
}

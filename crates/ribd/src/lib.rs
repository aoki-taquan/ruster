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
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Client, Event, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, RouteAction, Value};
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
}

/// How ribd works, apart from its sources.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Gateways may be resolved through the default route ([`resolve`]).
    pub resolve_via_default: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RibdCounters {
    pub patches_sent: u64,
    pub patches_refused: u64,
}

struct Source {
    spec: SourceSpec,
    server: Server,
    /// How many of its routes give their next hops as gateways only.
    gateways: usize,
}

fn is_gateways(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Route(RouteAction::Gateways(_))))
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
}

impl Hook for Changed<'_> {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        self.whole = true;
        *self.gateways = next
            .iter()
            .filter(|(_, value)| is_gateways(Some(value)))
            .count();
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
            self.touched.insert((*key).clone());
        }
        Ok(())
    }

    fn committed(&mut self, _store: &Store) {
        self.any = true;
    }
}

/// A patch on its way to the FE: what the FE holds once it accepts it.
enum InFlight {
    /// Every route in it.
    All(BTreeMap<Key, Value>),
    /// What it held before, with these changes.
    Changes(Vec<Change>),
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
    /// The patch waiting for the FE's answer, and the routes it would make the FE hold.
    in_flight: Option<(u32, InFlight)>,
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
    /// the FE holds is only known once it answered.
    /// Returns whether a patch was sent.
    fn push(&mut self) -> bool {
        if self.in_flight.is_some() {
            // Sent after the answer; the answer wakes the next step.
            self.dirty = true;
            return false;
        }
        // A route given by its gateways is resolved through the other routes, so a
        // change of any route may change it: with one, every route is gone through.
        let whole = self.whole || self.sources.iter().any(|source| source.gateways > 0);
        let touched = std::mem::take(&mut self.touched);
        self.whole = false;
        let (changes, holds) = if whole {
            let selected = self.selected();
            let mut changes = Vec::new();
            for (key, value) in &selected {
                if self.sent.get(key) != Some(value) {
                    changes.push(Change::set(key.clone(), value.clone()));
                }
            }
            for key in self.sent.keys() {
                if !selected.contains_key(key) {
                    changes.push(Change::delete(key.clone()));
                }
            }
            (changes, InFlight::All(selected))
        } else {
            let changes = self.changes_of(touched);
            (changes.clone(), InFlight::Changes(changes))
        };
        if changes.is_empty() {
            return false;
        }
        match self.fe.patch(&changes) {
            Ok(token) => {
                self.counters.patches_sent += 1;
                #[cfg(test)]
                match holds {
                    InFlight::All(_) => self.made.0 += 1,
                    InFlight::Changes(_) => self.made.1 += 1,
                }
                self.in_flight = Some((token, holds));
                true
            }
            Err(_) => {
                // Not sent: what it would have changed is looked at again.
                self.whole = true;
                false
            }
        }
    }

    /// What the FE must be sent for the routes `touched`, when no route is given by
    /// its gateways (the selected route is then what the FE holds, as it is): for
    /// each, the route of the best source that has it, if that is not what the FE
    /// was sent.
    fn changes_of(&self, touched: BTreeSet<Key>) -> Vec<Change> {
        let mut order: Vec<&Source> = self.sources.iter().collect();
        order.sort_by_key(|s| s.spec.preference);
        let mut changes = Vec::new();
        for key in touched {
            if !matches!(key, Key::Route { .. }) {
                continue;
            }
            let selected = order
                .iter()
                .find_map(|source| source.server.store().get(&key));
            match (selected, self.sent.get(&key)) {
                (Some(value), sent) if sent != Some(value) => {
                    changes.push(Change::set(key, value.clone()));
                }
                (None, Some(_)) => changes.push(Change::delete(key)),
                _ => {}
            }
        }
        changes
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
            };
            progress = progress.and(source.server.step(&mut changed));
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
        if std::mem::take(&mut self.dirty) && self.push() {
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
                let (_, holds) = self.in_flight.take().expect("checked");
                if refused {
                    // What the FE holds from ribd is now unclear: start a resync, so
                    // the next accepted full send is followed by resync-end. Routes
                    // the FE holds stay until then.
                    self.fe.resync_begin();
                    self.sent.clear();
                    self.whole = true;
                    self.patch_refused.get_or_insert(None);
                    if self.waiting_since.is_none() {
                        self.resync_pending = true;
                    }
                } else {
                    match holds {
                        InFlight::All(selected) => self.sent = selected,
                        InFlight::Changes(changes) => {
                            for change in changes {
                                match change.value {
                                    Some(value) => self.sent.insert(change.key, value),
                                    None => self.sent.remove(&change.key),
                                };
                            }
                        }
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
    fn run(seed: u64, rounds: usize, gateways: bool) -> (usize, usize) {
        let mut rng = Rng(seed);
        let mut fe = Server::new();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::ROUTE]).unwrap();
        let specs =
            [("static", 1), ("ospf", 20), ("bgp", 50)].map(|(name, preference)| SourceSpec {
                name: name.into(),
                preference,
                hold_ms: 0,
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
        let mut now = 0;
        let mut checked = 0;
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
        assert!(checked > rounds / 2, "{checked} of {rounds}");
        ribd.made
    }

    #[test]
    fn going_through_the_touched_routes_gives_what_going_through_every_route_gives() {
        let mut whole = 0;
        let mut touched = 0;
        for seed in 0..2 {
            let made = run(0x7269_6264 + seed, 100, false);
            whole += made.0;
            touched += made.1;
        }
        // Mostly the touched routes alone; every route after a resync or a refusal.
        assert!(touched > 60, "{touched}");
        assert!(whole > 10, "{whole}");
    }

    #[test]
    fn with_a_route_given_by_its_gateways_every_route_is_gone_through() {
        let mut whole = 0;
        let mut touched = 0;
        for seed in 0..1 {
            let made = run(0x6761_7465 + seed, 120, true);
            whole += made.0;
            touched += made.1;
        }
        // Now and then no route is given by its gateways, and the touched routes
        // alone are gone through.
        assert!(whole > 30, "{whole}");
        assert!(touched > 0, "{touched}");
    }
}

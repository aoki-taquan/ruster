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
//! Skeleton limits: next hops are passed through as given (no recursive resolution),
//! no route leaking between VRFs, no metric or ECMP across sources.
//!
//! # Standards
//!
//! - RFC 8349 (`ietf-routing`): routes per VRF and prefix, chosen by route preference
//!   (lower is preferred) between sources.
//!
//! Deviations: a preference is set per source, not per route.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Client, Event, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, Value};
use ruster_proto::task::{Progress, Task};

/// A route source and how much it is preferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSpec {
    pub name: String,
    /// Lower wins, like an administrative distance.
    pub preference: u32,
    /// After ribd starts, how long to wait for this source's `sync-done`.
    pub hold_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RibdCounters {
    pub patches_sent: u64,
    pub patches_refused: u64,
}

struct Source {
    spec: SourceSpec,
    server: Server,
}

/// Notes that a source's table changed.
#[derive(Default)]
struct Changed(bool);

impl Hook for Changed {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }

    fn committed(&mut self, _store: &Store) {
        self.0 = true;
    }
}

pub struct Ribd {
    sources: Vec<Source>,
    fe: Client,
    /// What the FE was sent since ribd started.
    sent: BTreeMap<Key, Value>,
    /// When ribd started waiting, set on the first step; `None` again once the FE's
    /// unrefreshed routes were deleted.
    waiting_since: Option<Option<u64>>,
    dirty: bool,
    /// resync-begin was sent; resync-end follows once the FE accepted the full send.
    resync_pending: bool,
    /// The patch waiting for the FE's answer, and the routes it would make the FE hold.
    in_flight: Option<(u32, BTreeMap<Key, Value>)>,
    counters: RibdCounters,
}

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
        let mut fe = Client::new(fe)?;
        fe.resync_begin();
        Ok(Self {
            sources: sources
                .into_iter()
                .map(|spec| Source {
                    spec,
                    server: Server::new(),
                })
                .collect(),
            fe,
            sent: BTreeMap::new(),
            waiting_since: Some(None),
            dirty: false,
            resync_pending: false,
            in_flight: None,
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
        self.dirty = true;
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

    /// The selected route for every VRF and prefix.
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
        if changes.is_empty() {
            return false;
        }
        match self.fe.patch(&changes) {
            Ok(token) => {
                self.counters.patches_sent += 1;
                self.in_flight = Some((token, selected));
                true
            }
            Err(_) => false,
        }
    }

    /// resync-end deletes what the FE holds from ribd but was not sent again, so it
    /// goes only after the full send was accepted.
    ///
    /// `sent` is cleared at resync-begin and holds only what the FE accepted since, so
    /// once it equals the selection the FE holds everything ribd wants.
    fn finish_resync(&mut self) -> bool {
        if self.resync_pending
            && self.in_flight.is_none()
            && !self.dirty
            && self.sent == self.selected()
        {
            self.fe.resync_end();
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
            let mut changed = Changed::default();
            progress = progress.and(source.server.step(&mut changed));
            self.dirty |= changed.0;
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
    /// later full send is accepted. The refused routes go again with the next change.
    fn answers(&mut self, events: &[Event]) {
        for event in events {
            let Event::Response { token, code, .. } = event else {
                continue;
            };
            let refused = code.class() != 2;
            if refused {
                self.counters.patches_refused += 1;
            }
            if self.in_flight.as_ref().is_some_and(|(t, _)| t == token) {
                let (_, selected) = self.in_flight.take().expect("checked");
                if refused {
                    // What the FE holds from ribd is now unclear: start a resync, so
                    // the next accepted full send is followed by resync-end. Routes
                    // the FE holds stay until then.
                    self.fe.resync_begin();
                    self.sent.clear();
                    if self.waiting_since.is_none() {
                        self.resync_pending = true;
                    }
                } else {
                    self.sent = selected;
                }
            }
        }
    }
}

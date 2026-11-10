//! A writer of table entries to a table server that keeps what the server should
//! hold and writes it again after each (re)connection: what a daemon uses for its
//! confd source (`confd/source/<name>/source.sock`) and its ribd route source
//! (`docs/design/ce-processes.md`, "送り手").
//!
//! Whenever a [`Writer`] connects (again) it sends resync-begin, everything it
//! holds, resync-end and sync-done ("送り終わった"), so the receiver drops what an
//! earlier run left. A change goes as one iPATCH. With a refresh interval it sends
//! everything again that often, so values with a lifetime last while the daemon
//! runs.
//!
//! # Standards
//!
//! - draft-ietf-core-comi-21 and RFC 8132: the entries are written with iPATCH on
//!   `c`.
//!
//! Deviations: resync-begin, resync-end and sync-done are ruster's own.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::daemon;
use crate::session::{Client, Event};
use crate::table::{Change, Key, Value};

/// One receiver (confd's socket for a source, or ribd's for a route source) and
/// what it should hold.
#[derive(Debug)]
pub struct Writer {
    path: PathBuf,
    client: Option<Client>,
    held: BTreeMap<Key, Value>,
    /// Send everything again this often; `None` for never.
    refresh_ms: Option<u64>,
    sent_at: u64,
    retry: daemon::Retry,
    /// The receiver's last refusal, to report once.
    pub refused: Option<String>,
}

impl Writer {
    pub fn new(path: PathBuf, refresh_ms: Option<u64>) -> Self {
        Self {
            path,
            client: None,
            held: BTreeMap::new(),
            refresh_ms,
            sent_at: 0,
            retry: daemon::Retry::default(),
            refused: None,
        }
    }

    pub fn connected(&self) -> bool {
        self.client.as_ref().is_some_and(|c| !c.is_closed())
    }

    /// What the receiver should hold now.
    pub fn held(&self) -> &BTreeMap<Key, Value> {
        &self.held
    }

    /// Takes changes and writes those that change what is held.
    pub fn set(&mut self, changes: Vec<Change>) {
        let changes: Vec<Change> = changes
            .into_iter()
            .filter(|c| self.held.get(&c.key) != c.value.as_ref())
            .collect();
        if changes.is_empty() {
            return;
        }
        for change in &changes {
            match &change.value {
                Some(value) => self.held.insert(change.key.clone(), value.clone()),
                None => self.held.remove(&change.key),
            };
        }
        if let Some(client) = self.client.as_mut().filter(|c| !c.is_closed()) {
            let _ = client.patch(&changes);
        }
    }

    /// Takes a connection to the receiver and sends everything.
    pub fn attach(&mut self, client: Client, now_ms: u64) {
        let mut client = client;
        client.resync_begin();
        let all: Vec<Change> = self
            .held
            .iter()
            .map(|(k, v)| Change::set(k.clone(), v.clone()))
            .collect();
        if !all.is_empty() {
            let _ = client.patch(&all);
        }
        client.resync_end();
        client.sync_done();
        self.client = Some(client);
        self.sent_at = now_ms;
    }

    /// Connects again when the connection is gone, sends everything again when it is
    /// time, and reads the answers. Returns whether anything moved, and when to come
    /// back.
    pub fn step(&mut self, now_ms: u64) -> (bool, Option<u64>) {
        if !self.connected() && self.retry.due(now_ms) {
            if let Some(stream) = daemon::try_connect(&self.path) {
                if let Ok(client) = Client::new(stream) {
                    self.attach(client, now_ms);
                }
            }
        }
        let mut wake = None;
        if let Some(every) = self.refresh_ms {
            let due = self.sent_at.saturating_add(every);
            if self.connected() && now_ms >= due {
                self.sent_at = now_ms;
                let all: Vec<Change> = self
                    .held
                    .iter()
                    .map(|(k, v)| Change::set(k.clone(), v.clone()))
                    .collect();
                if let (false, Some(client)) = (all.is_empty(), self.client.as_mut()) {
                    let _ = client.patch(&all);
                }
            }
            wake = Some(self.sent_at.saturating_add(every));
        }
        let mut busy = false;
        if let Some(client) = &mut self.client {
            let (progress, events) = client.poll();
            busy = progress.busy;
            for event in events {
                if let Event::Response { code, payload, .. } = event {
                    if code.class() != 2 {
                        self.refused = Some(String::from_utf8_lossy(&payload).into_owned());
                    }
                }
            }
        }
        if !self.connected() {
            let next = now_ms.saturating_add(daemon::RECONNECT_EVERY_MS);
            wake = Some(wake.map_or(next, |w: u64| w.min(next)));
        }
        (busy, wake)
    }
}

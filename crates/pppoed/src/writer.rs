//! Where the client's sessions go: each session's values to its confd source
//! (`confd/source/<name>.sock`), and the default routes to ribd as the route source
//! `pppoed` (`docs/design/ce-processes.md`, "送り手").
//!
//! A [`Writer`] keeps what its receiver should hold and writes it there. Whenever it
//! connects (again) it sends resync-begin, everything it holds, resync-end and
//! sync-done ("送り終わった"), so the receiver drops what an earlier run left. A
//! change goes as one iPATCH. For confd it sends everything again every
//! [`REFRESH_MS`], well within [`LIFETIME`], so the values last while the client
//! runs and run out about a minute after it stops.
//!
//! # Standards
//!
//! - draft-ietf-core-comi-21 and RFC 8132: the values and routes are written with
//!   iPATCH on `c`.
//! - RFC 8349: a default route is 0.0.0.0/0 out of the session interface, on-link
//!   (the session is point-to-point, RFC 1661).
//!
//! Deviations: resync-begin, resync-end, sync-done and the lifetimes are ruster's own.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use ruster_proto::daemon;
use ruster_proto::session::{Client, Event};
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};

use crate::session::SessionUp;

/// How long a value sent to confd lasts, in seconds.
pub const LIFETIME: u32 = 60;
/// How often the values are sent to confd again.
pub const REFRESH_MS: u64 = 20_000;

/// A session's values for its source: set while it is up, deleted when not.
pub fn source_values(source: &str, up: Option<&SessionUp>) -> Vec<Change> {
    let session = Key::SourcePppoe {
        source: source.to_owned(),
    };
    let address = Key::SourceIpv4 {
        source: source.to_owned(),
    };
    let Some(up) = up else {
        return vec![Change::delete(session), Change::delete(address)];
    };
    let mut out = vec![Change::set(
        session,
        Value::SourcePppoe {
            session: up.session_id,
            peer: up.ac,
            mtu: up.mtu,
            lifetime: LIFETIME,
        },
    )];
    out.push(match up.ipv4 {
        Some(ipv4) => Change::set(
            address,
            Value::SourceIpv4 {
                address: ipv4,
                prefix_len: 32,
                lifetime: LIFETIME,
            },
        ),
        None => Change::delete(address),
    });
    out
}

/// The IPv4 default route of `vrf` out of the session `interface`: set while the
/// session is up with an address, deleted when not.
pub fn default_route(vrf: &str, interface: &str, up: Option<&SessionUp>) -> Change {
    let key = Key::Route {
        vrf: vrf.to_owned(),
        prefix: Ipv4Addr::UNSPECIFIED.into(),
        len: 0,
    };
    if up.is_some_and(|up| up.ipv4.is_some()) {
        Change::set(
            key,
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: interface.to_owned(),
                address: None,
            }])),
        )
    } else {
        Change::delete(key)
    }
}

/// One receiver (confd's socket for a source, or ribd's for `pppoed`) and what it
/// should hold.
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

//! A table server and its client, as described in `docs/design/control-protocol.md`.
//!
//! The server keeps a [`Store`] of entries and accepts connections, each allowed to
//! write some tables (one writer per table). On a connection it answers:
//!
//! | Request | Meaning |
//! |---|---|
//! | iPATCH `c` | apply the changes in the payload, all or none |
//! | GET `c` | the entries of the tables this connection writes (all tables if it writes none) |
//! | POST `c/resync-begin` | mark this writer's entries as not yet sent again |
//! | POST `c/resync-end` | delete this writer's entries that were not sent again |
//! | POST `c/sync-done` | the writer has sent everything it has (see [`Server::sync_done`]) |
//! | GET `s` with Observe 0 | send notifications to this connection from now on |
//!
//! The owner of the server decides whether a new set of tables is acceptable through
//! [`Hook::check`], and learns about each accepted set through [`Hook::committed`].
//! A request that fails changes nothing.
//!
//! The store is copied for each change. That is fine for the skeleton's small tables;
//! large tables (a full BGP table) need a structure that shares unchanged parts.
//!
//! # Standards
//!
//! - draft-ietf-core-comi-21: the CORECONF operations (iPATCH to change, GET to read, GET
//!   with Observe for notifications) on the datastore resource `c` and the stream `s`.
//! - RFC 8132: iPATCH. RFC 7641: Observe.
//!
//! Deviations: `c/resync-begin`, `c/resync-end` and `c/sync-done` are ruster's own (a
//! writer resending everything after a restart). GET `c` answers only the tables the
//! connection writes.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;

use crate::cbor::{Decoder, Encoder};
use crate::coap::Code;
use crate::conn::{ConnError, Connection, Incoming, Outgoing, DEFAULT_LIMIT};
use crate::table::{Change, Key, ModelError, Value};
use crate::task::Progress;

/// At most this many requests are handled per connection in one step.
const REQUESTS_PER_STEP: usize = 64;

/// The tables of a server, keyed by entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Store {
    entries: BTreeMap<Key, Slot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Slot {
    value: Value,
    /// Marked by resync-begin, cleared when the writer sends the entry again.
    stale: bool,
}

impl Store {
    pub fn get(&self, key: &Key) -> Option<&Value> {
        self.entries.get(key).map(|slot| &slot.value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Key, &Value)> {
        self.entries.iter().map(|(key, slot)| (key, &slot.value))
    }

    /// Whether `key` is an entry its writer has not sent again since a resync began:
    /// it goes when the resync ends.
    pub fn is_stale(&self, key: &Key) -> bool {
        self.entries.get(key).is_some_and(|slot| slot.stale)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn with_changes(&self, changes: &[Change]) -> Self {
        let mut next = self.clone();
        for change in changes {
            match &change.value {
                Some(value) => {
                    next.entries.insert(
                        change.key.clone(),
                        Slot {
                            value: value.clone(),
                            stale: false,
                        },
                    );
                }
                None => {
                    next.entries.remove(&change.key);
                }
            }
        }
        next
    }

    fn mark_stale(&mut self, tables: &[u64]) {
        for (key, slot) in &mut self.entries {
            if tables.contains(&key.table()) {
                slot.stale = true;
            }
        }
    }

    fn without_stale(&self, tables: &[u64]) -> Self {
        let mut next = self.clone();
        next.entries
            .retain(|key, slot| !(slot.stale && tables.contains(&key.table())));
        next
    }
}

/// Encodes changes as an iPATCH payload (a CBOR sequence).
pub fn encode_changes(changes: &[Change]) -> Result<Vec<u8>, ModelError> {
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    for change in changes {
        change.encode(&mut e)?;
    }
    Ok(out)
}

/// Decodes an iPATCH payload.
pub fn decode_changes(payload: &[u8]) -> Result<Vec<Change>, ModelError> {
    let mut d = Decoder::new(payload);
    let mut changes = Vec::new();
    while !d.is_empty() {
        changes.push(Change::decode(&mut d)?);
    }
    Ok(changes)
}

/// What the owner of a [`Server`] decides and hears.
pub trait Hook {
    /// Whether `next` may become the current tables. The error text goes back to the
    /// writer.
    fn check(&mut self, next: &Store) -> Result<(), String>;

    /// `store` is now the current tables.
    fn committed(&mut self, store: &Store);

    /// An iPATCH was taken (after [`Hook::committed`]): its changes, including
    /// entries set again to the value they had. A receiver that keeps a lifetime per
    /// entry starts it again here.
    fn patched(&mut self, _changes: &[Change]) {}
}

struct Peer {
    conn: Connection,
    writes: Vec<u64>,
    observe_token: Option<Vec<u8>>,
    observe_seq: u32,
}

#[derive(Default)]
pub struct Server {
    store: Store,
    peers: Vec<Peer>,
    sync_done: bool,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("entries", &self.store.len())
            .field("peers", &self.peers.len())
            .finish()
    }
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn peers(&self) -> usize {
        self.peers.len()
    }

    /// True once a writer said it has sent everything it has (`POST c/sync-done`).
    /// A receiver that restarted waits for this before deleting what was not sent
    /// again (docs/design/ce-processes.md, "起動し直したとき").
    pub fn sync_done(&self) -> bool {
        self.sync_done
    }

    /// The largest number of bytes queued for any one connection.
    pub fn max_backlog(&self) -> usize {
        self.peers
            .iter()
            .map(|peer| peer.conn.backlog())
            .max()
            .unwrap_or(0)
    }

    /// Accepts a connection that may write `writes` (table SIDs). An empty list makes
    /// it read-only.
    ///
    /// A table has one writer. An older connection that writes any of the same tables
    /// is closed, because a new connection for them means the writer restarted.
    pub fn attach(&mut self, stream: UnixStream, writes: &[u64]) -> io::Result<()> {
        for peer in &mut self.peers {
            if peer.writes.iter().any(|table| writes.contains(table)) {
                peer.conn.close();
            }
        }
        self.peers.push(Peer {
            conn: Connection::new(stream, DEFAULT_LIMIT)?,
            writes: writes.to_vec(),
            observe_token: None,
            observe_seq: 0,
        });
        Ok(())
    }

    /// Queues a notification for every connection that observes `s`.
    ///
    /// An observer that has fallen a whole message limit behind is closed rather than
    /// queued for without bound.
    pub fn notify(&mut self, payload: &[u8]) {
        for peer in &mut self.peers {
            let Some(token) = peer.observe_token.clone() else {
                continue;
            };
            if peer.conn.backlog() >= peer.conn.limit() {
                peer.conn.close();
                continue;
            }
            // Observe numbers are 24 bits; 0 is the registration, so wrap to 1.
            peer.observe_seq = if peer.observe_seq >= 0x00ff_ffff {
                1
            } else {
                peer.observe_seq + 1
            };
            let _ = peer.conn.send(&Outgoing {
                code: Some(Code::CONTENT),
                token: &token,
                observe: Some(peer.observe_seq),
                payload,
                ..Outgoing::default()
            });
        }
    }

    /// Moves bytes, handles requests and drops closed connections.
    pub fn step(&mut self, hook: &mut dyn Hook) -> Progress {
        let mut busy = false;
        let mut index = 0;
        while index < self.peers.len() {
            busy |= self.peers[index].conn.pump().unwrap_or(false);
            for _ in 0..REQUESTS_PER_STEP {
                // Backpressure: a peer that does not read its replies gets no more
                // handled until it does.
                if self.peers[index].conn.backlog() >= self.peers[index].conn.limit() {
                    break;
                }
                match self.peers[index].conn.next_message() {
                    Ok(Some(request)) => {
                        busy = true;
                        self.handle(index, &request, hook);
                    }
                    Ok(None) | Err(ConnError::Frame(_) | ConnError::Io(_)) => break,
                }
            }
            busy |= self.peers[index].conn.pump().unwrap_or(false);
            busy |= self.peers[index].conn.take_more();
            if self.peers[index].conn.is_closed() {
                self.peers.swap_remove(index);
            } else {
                index += 1;
            }
        }
        Progress::busy(busy)
    }

    fn handle(&mut self, index: usize, request: &Incoming, hook: &mut dyn Hook) {
        let path: Vec<&str> = request.path.iter().map(String::as_str).collect();
        let writes = self.peers[index].writes.clone();
        let (code, payload): (Code, Vec<u8>) = match (request.code, path.as_slice()) {
            (Code::IPATCH, ["c"]) if writes.is_empty() => {
                (Code::FORBIDDEN, b"read-only connection".to_vec())
            }
            (Code::IPATCH, ["c"]) => match decode_changes(&request.payload) {
                Err(error) => (Code::BAD_REQUEST, error.to_string().into_bytes()),
                Ok(changes) => {
                    if changes.iter().any(|c| !writes.contains(&c.key.table())) {
                        (Code::FORBIDDEN, b"table not writable here".to_vec())
                    } else {
                        let next = self.store.with_changes(&changes);
                        let answer = self.commit(next, hook);
                        if answer.0 == Code::CHANGED {
                            hook.patched(&changes);
                        }
                        answer
                    }
                }
            },
            (Code::GET, ["c"]) => {
                let changes: Vec<Change> = self
                    .store
                    .iter()
                    .filter(|(key, _)| writes.is_empty() || writes.contains(&key.table()))
                    .map(|(key, value)| Change::set(key.clone(), value.clone()))
                    .collect();
                let limit = self.peers[index].conn.peer_limit().unwrap_or(DEFAULT_LIMIT);
                match encode_changes(&changes) {
                    // Leave room for the header and token.
                    Ok(payload) if payload.len() + 64 > limit => (
                        Code::REQUEST_ENTITY_TOO_LARGE,
                        b"tables larger than the peer's message limit".to_vec(),
                    ),
                    Ok(payload) => (Code::CONTENT, payload),
                    Err(error) => (Code::INTERNAL_SERVER_ERROR, error.to_string().into_bytes()),
                }
            }
            (Code::POST, ["c", "resync-begin"]) if !writes.is_empty() => {
                self.store.mark_stale(&writes);
                (Code::CHANGED, Vec::new())
            }
            (Code::POST, ["c", "sync-done"]) if !writes.is_empty() => {
                self.sync_done = true;
                (Code::CHANGED, Vec::new())
            }
            (Code::POST, ["c", "resync-end"]) if !writes.is_empty() => {
                let next = self.store.without_stale(&writes);
                self.commit(next, hook)
            }
            (Code::GET, ["s"]) if request.observe == Some(0) => {
                let peer = &mut self.peers[index];
                peer.observe_token = Some(request.token.clone());
                peer.observe_seq = 0;
                let _ = peer.conn.send(&Outgoing {
                    code: Some(Code::CONTENT),
                    token: &request.token,
                    observe: Some(0),
                    ..Outgoing::default()
                });
                return;
            }
            (Code::GET | Code::POST | Code::IPATCH | Code::FETCH | Code::PUT | Code::DELETE, _) => {
                (Code::NOT_FOUND, Vec::new())
            }
            _ => return,
        };
        let _ = self.peers[index].conn.send(&Outgoing {
            code: Some(code),
            token: &request.token,
            payload: &payload,
            ..Outgoing::default()
        });
    }

    fn commit(&mut self, next: Store, hook: &mut dyn Hook) -> (Code, Vec<u8>) {
        match hook.check(&next) {
            Err(reason) => (Code::BAD_REQUEST, reason.into_bytes()),
            Ok(()) => {
                self.store = next;
                hook.committed(&self.store);
                (Code::CHANGED, Vec::new())
            }
        }
    }
}

/// What a [`Client`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Response {
        token: u32,
        code: Code,
        payload: Vec<u8>,
    },
    Notification {
        payload: Vec<u8>,
    },
}

/// The writer side of a connection to a [`Server`].
#[derive(Debug)]
pub struct Client {
    conn: Connection,
    next_token: u32,
    observe_token: Option<u32>,
}

impl Client {
    pub fn new(stream: UnixStream) -> io::Result<Self> {
        Ok(Self {
            conn: Connection::new(stream, DEFAULT_LIMIT)?,
            next_token: 1,
            observe_token: None,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    fn request(&mut self, code: Code, path: &[&str], observe: Option<u32>, payload: &[u8]) -> u32 {
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        let _ = self.conn.send(&Outgoing {
            code: Some(code),
            token: &token.to_be_bytes(),
            path,
            observe,
            payload,
        });
        token
    }

    /// Sends changes. Returns the token of the request.
    pub fn patch(&mut self, changes: &[Change]) -> Result<u32, ModelError> {
        let payload = encode_changes(changes)?;
        Ok(self.request(Code::IPATCH, &["c"], None, &payload))
    }

    pub fn get_all(&mut self) -> u32 {
        self.request(Code::GET, &["c"], None, &[])
    }

    pub fn resync_begin(&mut self) -> u32 {
        self.request(Code::POST, &["c", "resync-begin"], None, &[])
    }

    pub fn resync_end(&mut self) -> u32 {
        self.request(Code::POST, &["c", "resync-end"], None, &[])
    }

    /// Tells the server this writer has sent everything it has.
    pub fn sync_done(&mut self) -> u32 {
        self.request(Code::POST, &["c", "sync-done"], None, &[])
    }

    /// Sends POST to `path` with `payload`, for a resource outside the tables (confd's
    /// `config`). Returns the token of the request.
    pub fn post(&mut self, path: &[&str], payload: &[u8]) -> u32 {
        self.request(Code::POST, path, None, payload)
    }

    /// Sends GET to `path`, for a resource outside the tables (confd's `versions`).
    /// Returns the token of the request.
    pub fn get(&mut self, path: &[&str]) -> u32 {
        self.request(Code::GET, path, None, &[])
    }

    /// Asks for notifications. They arrive as [`Event::Notification`].
    pub fn observe(&mut self) -> u32 {
        let token = self.request(Code::GET, &["s"], Some(0), &[]);
        self.observe_token = Some(token);
        token
    }

    /// Moves bytes and returns what arrived.
    pub fn poll(&mut self) -> (Progress, Vec<Event>) {
        let mut busy = self.conn.pump().unwrap_or(false);
        let mut events = Vec::new();
        while let Ok(Some(message)) = self.conn.next_message() {
            busy = true;
            let token = message
                .token
                .as_slice()
                .try_into()
                .map(u32::from_be_bytes)
                .unwrap_or(0);
            let observing = Some(token) == self.observe_token;
            if observing && message.observe.is_some_and(|n| n > 0) {
                events.push(Event::Notification {
                    payload: message.payload,
                });
            } else if !(observing && message.observe == Some(0)) {
                // Ordinary responses, and an error answer to the registration.
                events.push(Event::Response {
                    token,
                    code: message.code,
                    payload: message.payload,
                });
            }
        }
        busy |= self.conn.take_more();
        busy |= self.conn.pump().unwrap_or(false);
        (Progress::busy(busy), events)
    }
}

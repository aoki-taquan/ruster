//! The sources: daemons that send confd values found at run time
//! (`docs/design/ce-processes.md`, "送り手").
//!
//! The configuration declares each source with a name and a kind. confd listens on
//! `confd/source/<name>.sock` for each, and the daemon writes its values there as
//! table entries ([`ruster_proto::session`]), keyed by the source's name:
//!
//! | Kind | What it may write |
//! |---|---|
//! | `pppoe` | [`Key::SourcePppoe`] (the session ID, the access concentrator's MAC, the MTU) and [`Key::SourceIpv4`] (the address IPCP gave) |
//!
//! A write to another table, or under another source's name, is refused. So is an
//! IPv4 address that is not a unicast address.
//!
//! Every value carries a lifetime in seconds. confd counts it from when the value
//! arrives, and from each time it arrives again: the daemon sends its values again
//! before they run out, and a value not sent again in time is dropped, so the
//! values of a daemon that stopped go when their lifetime ends. A source deletes a
//! value it no longer has. confd keeps values only in memory: when confd starts
//! again, it has none until the sources send them again.
//!
//! When a daemon connects (again), it sends `c/resync-begin`, every value it has,
//! `c/resync-end` (which drops the values it did not send again) and then
//! `c/sync-done` ("送り終わった"). After confd starts, it keeps what the FE, ribd and
//! neighd hold from before (it holds back resync-end and ribd's sync-done) until
//! every source declared said `sync-done`, or until the source's `sync-wait` passed
//! for those that did not (docs/design/ce-processes.md, "起動し直したとき").
//!
//! A newer connection for a source closes the older one; its values stay.
//!
//! # Standards
//!
//! - draft-ietf-core-comi-21 and RFC 8132: the values are written with iPATCH on `c`,
//!   as on every table server ([`ruster_proto::session`]).
//!
//! Deviations: the tables, the lifetimes and the resync and sync-done requests are
//! ruster's own.

use std::collections::BTreeMap;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, Value};
use ruster_proto::task::Progress;

/// The longest `sync-wait`, in seconds.
pub const SYNC_WAIT_MAX: u32 = 600;
/// The most sources: each has a socket.
pub const SOURCES_MAX: usize = 32;
/// The longest source name, so that `<name>.sock` is a short path component.
pub const NAME_MAX: usize = 32;

/// What a source is, and so what it may write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `ruster-pppoed`: one PPPoE session.
    Pppoe,
}

impl Kind {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "pppoe" => Some(Self::Pppoe),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pppoe => "pppoe",
        }
    }

    /// The tables (SIDs) a source of this kind writes.
    pub fn tables(self) -> &'static [u64] {
        match self {
            Self::Pppoe => &[sid::SOURCE_PPPOE, sid::SOURCE_IPV4],
        }
    }
}

/// A source as the configuration declares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub name: String,
    pub kind: Kind,
    /// After confd starts, the most it waits for the source's `sync-done`.
    pub sync_wait_ms: u64,
}

/// Whether `name` can name a source: 1 to [`NAME_MAX`] lower-case letters, digits
/// and `-`, from a letter.
pub fn is_name(name: &str) -> bool {
    name.len() <= NAME_MAX
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Checks the lock form's sources.
pub fn specs(sources: Vec<ruster_config::Source>) -> Result<Vec<Spec>, String> {
    if sources.len() > SOURCES_MAX {
        return Err(format!("give at most {SOURCES_MAX} sources"));
    }
    let mut out: Vec<Spec> = Vec::with_capacity(sources.len());
    for source in sources {
        let at = format!("source {:?}", source.name);
        if !is_name(&source.name) {
            return Err(format!(
                "{at}: a name is 1 to {NAME_MAX} lower-case letters, digits and -, from a letter"
            ));
        }
        if out.iter().any(|s| s.name == source.name) {
            return Err(format!("{at}: given twice"));
        }
        let kind = Kind::from_name(&source.kind)
            .ok_or_else(|| format!("{at}: kind {:?} is not \"pppoe\"", source.kind))?;
        if source.sync_wait > SYNC_WAIT_MAX {
            return Err(format!("{at}: sync-wait must be at most {SYNC_WAIT_MAX}"));
        }
        out.push(Spec {
            name: source.name,
            kind,
            sync_wait_ms: u64::from(source.sync_wait) * 1_000,
        });
    }
    Ok(out)
}

struct Source {
    spec: Spec,
    server: Server,
    /// When each value runs out. A value of the server's store without one has run
    /// out and is not used.
    until: BTreeMap<Key, u64>,
}

/// The table server's hook for one source.
struct Taking<'a> {
    name: &'a str,
    now: u64,
    until: &'a mut BTreeMap<Key, u64>,
    changed: bool,
}

impl Hook for Taking<'_> {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        for (key, value) in next.iter() {
            let source = match key {
                Key::SourcePppoe { source } | Key::SourceIpv4 { source } => source,
                _ => return Err("not a source's value".into()),
            };
            if source != self.name {
                return Err(format!("this is the socket of source {}", self.name));
            }
            if let Value::SourceIpv4 { address, .. } = value {
                if !unicast(*address) {
                    return Err(format!("{address} is not a unicast address"));
                }
            }
        }
        Ok(())
    }

    fn committed(&mut self, store: &Store) {
        // resync-end dropped what was not sent again.
        self.until.retain(|key, _| store.get(key).is_some());
        self.changed = true;
    }

    fn patched(&mut self, changes: &[Change]) {
        for change in changes {
            let lifetime = match &change.value {
                Some(Value::SourcePppoe { lifetime, .. } | Value::SourceIpv4 { lifetime, .. }) => {
                    *lifetime
                }
                _ => {
                    self.until.remove(&change.key);
                    continue;
                }
            };
            let until = self.now.saturating_add(u64::from(lifetime) * 1_000);
            self.until.insert(change.key.clone(), until);
        }
        self.changed = true;
    }
}

/// An address a host may have (RFC 6890, RFC 1122 section 3.2.1.3).
fn unicast(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    first != 0 && first != 127 && first < 224
}

/// confd's sources and the values they sent.
#[derive(Default)]
pub(crate) struct Sources {
    sources: Vec<Source>,
    /// Since confd started, waiting for the sources' `sync-done`: when it started
    /// waiting, set on the first step. `None` once done.
    waiting_since: Option<Option<u64>>,
}

impl Sources {
    pub(crate) fn new(specs: &[Spec]) -> Self {
        let mut sources = Self {
            sources: Vec::new(),
            waiting_since: (!specs.is_empty()).then_some(None),
        };
        sources.set_specs(specs);
        sources
    }

    /// Takes a new configuration's sources. A source kept with the same kind keeps
    /// its connection and values; the values of the others are dropped.
    pub(crate) fn set_specs(&mut self, specs: &[Spec]) {
        let mut old = std::mem::take(&mut self.sources);
        for spec in specs {
            let kept = old
                .iter()
                .position(|s| s.spec.name == spec.name && s.spec.kind == spec.kind)
                .map(|at| old.swap_remove(at));
            self.sources.push(match kept {
                Some(mut source) => {
                    source.spec = spec.clone();
                    source
                }
                None => Source {
                    spec: spec.clone(),
                    server: Server::new(),
                    until: BTreeMap::new(),
                },
            });
        }
    }

    pub(crate) fn names(&self) -> Vec<String> {
        self.sources.iter().map(|s| s.spec.name.clone()).collect()
    }

    /// Takes a connection on the source's socket.
    pub(crate) fn attach(&mut self, name: &str, stream: UnixStream) -> io::Result<()> {
        let source = self
            .sources
            .iter_mut()
            .find(|s| s.spec.name == name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such source"))?;
        source.server.attach(stream, source.spec.kind.tables())
    }

    /// True while confd waits for the sources after it started.
    pub(crate) fn waiting(&self) -> bool {
        self.waiting_since.is_some()
    }

    /// Handles what the sources sent and drops values that ran out. Returns the
    /// progress and whether any value changed.
    pub(crate) fn step(&mut self, now: u64) -> (Progress, bool) {
        let mut progress = Progress::IDLE;
        let mut changed = false;
        for source in &mut self.sources {
            let mut hook = Taking {
                name: &source.spec.name,
                now,
                until: &mut source.until,
                changed: false,
            };
            progress = progress.and(source.server.step(&mut hook));
            changed |= hook.changed;
            let before = source.until.len();
            source.until.retain(|_, until| *until > now);
            changed |= source.until.len() != before;
            if let Some(next) = source.until.values().min() {
                progress = progress.and(Progress {
                    busy: false,
                    wake_at: Some(*next),
                });
            }
        }
        if let Some(waiting) = &mut self.waiting_since {
            let since = *waiting.get_or_insert(now);
            let left: Vec<u64> = self
                .sources
                .iter()
                .filter(|s| !s.server.sync_done())
                .map(|s| since.saturating_add(s.spec.sync_wait_ms))
                .collect();
            if left.iter().all(|&at| now >= at) {
                self.waiting_since = None;
                progress.busy = true;
            } else {
                progress = progress.and(Progress {
                    busy: false,
                    wake_at: left.into_iter().filter(|&at| at > now).min(),
                });
            }
        }
        (progress, changed)
    }

    fn value(&self, name: &str, key: &Key) -> Option<&Value> {
        let source = self.sources.iter().find(|s| s.spec.name == name)?;
        source.until.get(key)?;
        source.server.store().get(key)
    }

    /// The session the source `name` has now: its ID, the AC's MAC and the MTU.
    pub(crate) fn pppoe(&self, name: &str) -> Option<(u16, [u8; 6], u16)> {
        let key = Key::SourcePppoe {
            source: name.to_owned(),
        };
        match self.value(name, &key)? {
            Value::SourcePppoe {
                session, peer, mtu, ..
            } => Some((*session, *peer, *mtu)),
            _ => None,
        }
    }

    /// The IPv4 address and prefix length the source `name` has now.
    pub(crate) fn ipv4(&self, name: &str) -> Option<(Ipv4Addr, u8)> {
        let key = Key::SourceIpv4 {
            source: name.to_owned(),
        };
        match self.value(name, &key)? {
            Value::SourceIpv4 {
                address,
                prefix_len,
                ..
            } => Some((*address, *prefix_len)),
            _ => None,
        }
    }
}

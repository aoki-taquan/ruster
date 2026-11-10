//! The socket through which the CLI gives confd a new configuration, lists the versions
//! and goes back to one (`docs/design/router-box.md`, "反映の流れ").
//!
//! | Request | What |
//! |---|---|
//! | POST `config`, the file's text | put it in use (below) |
//! | POST `rollback/<N>` | put version N's configuration in use, the same way |
//! | GET `versions` | 2.05 Content: the versions kept, a line each, newest first ([`Versions::listing`]) |
//!
//! Requests are framed like the other sockets. For POST `config`, confd reads the text as
//! it reads its file at start-up; for `rollback/<N>`, version N's lock form (4.04 Not
//! Found when it is not kept). Then it sends what changed to
//! the FE, ribd and neighd, and the parts that changed to the processes that take them
//! ([`crate::part`]), and answers once each of them has answered. Once every process
//! has taken it, confd keeps it as the next version ([`crate::versions`]); the answer
//! says which.
//!
//! | Answer | Meaning |
//! |---|---|
//! | 2.04 Changed | every connected process answered yes, and the configuration was kept as a version |
//! | 2.05 Content | the answer to GET `versions` |
//! | 4.00 Bad Request | the file or the version does not read, `<N>` is not a number, or a process refused the change; in the last case confd puts the configuration it had before back |
//! | 4.04 Not Found | version N is not kept, or the resource is not one of the above |
//! | 5.00 Internal Server Error | the configuration is in use, but writing the version failed |
//! | 5.03 Service Unavailable | an earlier new configuration is still waiting for answers |
//! | 5.04 Gateway Timeout | a process has not answered in time |
//!
//! After 5.04 confd keeps waiting: if the answer is a refusal, it puts the configuration
//! before back then, and if it is yes, it keeps the version then. A process that
//! disconnects meanwhile (one already disconnected when the file came is not waited
//! for) is waited for too: confd sends it everything when it connects again, and its
//! answer counts. confd stops waiting after [`GIVE_UP_MS`], logs it, and keeps the
//! configuration as a version, since it is the one in use. A new file is taken only
//! when every process has answered everything sent to it; until then it gets 5.03.
//!
//! The payload of an answer is text for a person: the error, or what the answer needs
//! to add (a process that is not connected gets the configuration when it connects
//! again; errors setting up the kernel side; the version number).
//!
//! Limits:
//! - Static routes go through ribd, which takes any route; a route the FE then refuses
//!   is not seen here.
//! - A new configuration is sent to the processes and taken in one step: there is no
//!   preview of the changes and no confirm-or-revert yet.
//!
//! # Standards
//!
//! - RFC 7252 sections 5.8.1 (GET), 5.8.2 (POST) and 5.9 (the response codes above),
//!   over the stream framing of RFC 8323 like the table sockets.
//!
//! Deviations: the resources and their text payloads are ruster's own; they are not a
//! CORECONF datastore.

use std::os::unix::net::UnixStream;

use ruster_proto::coap::Code;
use ruster_proto::conn::{Connection, Incoming, Outgoing};
use ruster_proto::task::Progress;

use crate::versions::Versions;
use crate::{file, Confd, Config, PeerKind};

/// The largest configuration file accepted.
const LIMIT: usize = 1 << 20;

/// How long a new configuration waits for the processes' answers before 5.04.
pub const ANSWER_WAIT_MS: u64 = 3_000;

/// How long confd waits at most for the answers to one new configuration.
pub const GIVE_UP_MS: u64 = 30_000;

/// At most this many connections at once; more are closed straight away.
pub const MAX_CONNECTIONS: usize = 8;

/// At most this many requests are handled per connection in one step.
const REQUESTS_PER_STEP: usize = 16;

/// The connections of `ruster apply`, the one change being applied and the versions.
#[derive(Default)]
pub struct Apply {
    conns: Vec<(u64, Connection)>,
    next_id: u64,
    pending: Option<Pending>,
    counters: ApplyCounters,
    versions: Versions,
    log: Vec<String>,
}

/// What happened after an answer had gone out, for the log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyCounters {
    /// A refusal came after 5.04 and the configuration before was put back.
    pub late_rollbacks: u64,
    /// confd stopped waiting after [`GIVE_UP_MS`].
    pub gave_up: u64,
}

impl std::fmt::Debug for Apply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Apply")
            .field("connections", &self.conns.len())
            .field("pending", &self.pending.is_some())
            .field("versions", &self.versions.list().len())
            .finish()
    }
}

/// A new configuration sent to the processes and waiting for their answers.
struct Pending {
    conn: u64,
    token: Vec<u8>,
    previous: Config,
    /// [`Confd::generation`] of the new configuration.
    generation: u64,
    started_ms: u64,
    /// Processes not connected when the file came: like absent ones, not waited for.
    closed_at_start: Vec<PeerKind>,
    notes: Vec<String>,
    /// 5.04 went out; the answer still decides whether to go back.
    timed_out: bool,
    /// What to keep as a version once it is taken.
    keep: Keep,
}

/// A version to keep: how it came, the lock form and the `ruster.toml` text.
struct Keep {
    how: String,
    lock: String,
    toml: Option<String>,
}

impl Apply {
    /// With the versions so far; the latest is the configuration confd has.
    pub fn new(versions: Versions) -> Self {
        Self {
            versions,
            ..Self::default()
        }
    }

    pub fn counters(&self) -> ApplyCounters {
        self.counters
    }

    pub fn versions(&self) -> &Versions {
        &self.versions
    }

    /// Lines for confd's log since the last call.
    pub fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    /// Takes a connection, or closes it if [`MAX_CONNECTIONS`] are open.
    pub fn attach(&mut self, stream: UnixStream) -> std::io::Result<()> {
        if self.conns.len() >= MAX_CONNECTIONS {
            return Err(std::io::Error::other("too many connections"));
        }
        self.conns
            .push((self.next_id, Connection::new(stream, LIMIT)?));
        self.next_id += 1;
        Ok(())
    }

    /// Handles requests and answers a change once the processes have answered.
    ///
    /// `prepare` runs before confd sends a configuration (the new one, or the one put
    /// back) and returns notes for the answer; confd's `--kernel` uses it.
    pub fn step(
        &mut self,
        confd: &mut Confd,
        now_ms: u64,
        prepare: &mut dyn FnMut(&Config) -> Vec<String>,
    ) -> Progress {
        let mut busy = self.finish(confd, now_ms, prepare);
        let mut index = 0;
        while index < self.conns.len() {
            let id = self.conns[index].0;
            busy |= self.conns[index].1.pump().unwrap_or(false);
            for _ in 0..REQUESTS_PER_STEP {
                let conn = &mut self.conns[index].1;
                // A client that does not read its answers gets no more handled.
                if conn.backlog() >= conn.limit() {
                    break;
                }
                let Ok(Some(request)) = conn.next_message() else {
                    break;
                };
                busy = true;
                let answer = self.handle(confd, id, &request, now_ms, prepare);
                if let Some((code, text)) = answer {
                    send(&mut self.conns[index].1, &request.token, code, &text);
                }
            }
            let conn = &mut self.conns[index].1;
            busy |= conn.pump().unwrap_or(false);
            busy |= conn.take_more();
            if conn.is_closed() {
                self.conns.swap_remove(index);
            } else {
                index += 1;
            }
        }
        busy |= self.finish(confd, now_ms, prepare);
        Progress::busy(busy)
    }

    /// Handles one request of connection `id`. `None` when the answer comes later
    /// (from [`Apply::finish`]) or there is none.
    fn handle(
        &mut self,
        confd: &mut Confd,
        id: u64,
        request: &Incoming,
        now_ms: u64,
        prepare: &mut dyn FnMut(&Config) -> Vec<String>,
    ) -> Option<(Code, String)> {
        let path: Vec<&str> = request.path.iter().map(String::as_str).collect();
        let busy = self.pending.is_some() || !confd.settled();
        let candidate = match (request.code, path.as_slice()) {
            (Code::GET, ["versions"]) => return Some((Code::CONTENT, self.versions.listing())),
            (Code::POST, ["config"] | ["rollback", _]) if busy => {
                return Some((
                    Code::SERVICE_UNAVAILABLE,
                    "an earlier configuration is still waiting for answers".to_owned(),
                ))
            }
            (Code::POST, ["config"]) => std::str::from_utf8(&request.payload)
                .map_err(|_| "the file is not UTF-8".to_owned())
                .and_then(file::candidate)
                .map(|candidate| {
                    let keep = Keep {
                        how: "apply".into(),
                        lock: candidate.lock,
                        toml: candidate.toml,
                    };
                    (candidate.config, keep)
                }),
            (Code::POST, ["rollback", number]) => {
                let Some(number) = number
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| number.parse::<u64>().ok())
                    .flatten()
                else {
                    return Some((Code::BAD_REQUEST, format!("{number}: not a version number")));
                };
                let Some(version) = self.versions.get(number) else {
                    return Some((Code::NOT_FOUND, "it is not kept".to_owned()));
                };
                // A version from before an update may be one this confd cannot read.
                let hint = if version.toml.is_some() {
                    "; its ruster.toml is kept: `ruster apply` of it resolves it with this \
                     ruster's defaults"
                } else {
                    ""
                };
                file::parse(&version.lock)
                    .map_err(|error| format!("version {number}: {error}{hint}"))
                    .map(|config| {
                        let keep = Keep {
                            how: format!("rollback to {number}"),
                            lock: version.lock.clone(),
                            toml: version.toml.clone(),
                        };
                        (config, keep)
                    })
            }
            (code, _) if code.class() == 0 => return Some((Code::NOT_FOUND, String::new())),
            _ => return None,
        };
        match candidate {
            Err(error) => Some((Code::BAD_REQUEST, error)),
            Ok((config, keep)) => {
                self.start(confd, config, keep, (id, &request.token), now_ms, prepare);
                None
            }
        }
    }

    /// Sends a new configuration to the processes; [`Apply::finish`] answers
    /// `(connection, token)` once they have answered.
    fn start(
        &mut self,
        confd: &mut Confd,
        config: Config,
        keep: Keep,
        (conn, token): (u64, &[u8]),
        now_ms: u64,
        prepare: &mut dyn FnMut(&Config) -> Vec<String>,
    ) {
        let notes = prepare(&confd.with_values_of(&config));
        let previous = confd.config().clone();
        confd.set_config(config);
        self.pending = Some(Pending {
            conn,
            token: token.to_vec(),
            previous,
            generation: confd.generation(),
            started_ms: now_ms,
            closed_at_start: confd.closed(),
            notes,
            timed_out: false,
            keep,
        });
    }

    /// Answers the pending change if the processes have answered or the wait is over,
    /// and goes back if one refused it.
    fn finish(
        &mut self,
        confd: &mut Confd,
        now_ms: u64,
        prepare: &mut dyn FnMut(&Config) -> Vec<String>,
    ) -> bool {
        let Some(pending) = &mut self.pending else {
            return false;
        };
        let refusal = confd
            .refused_since(pending.generation)
            .map(|(kind, reason)| format!("{kind} refused it: {reason}"));
        let waited = now_ms.saturating_sub(pending.started_ms);
        let answered = confd.settled()
            && confd
                .closed()
                .iter()
                .all(|kind| pending.closed_at_start.contains(kind));
        if refusal.is_none() && !answered && waited >= GIVE_UP_MS && pending.timed_out {
            // The configuration stays, so it is the latest version.
            if let Some(pending) = self.pending.take() {
                let _ = self.keep(pending.keep);
            }
            self.counters.gave_up += 1;
            return true;
        }
        if refusal.is_none() && !answered {
            if waited < ANSWER_WAIT_MS || pending.timed_out {
                return false;
            }
            pending.timed_out = true;
            let (conn, token) = (pending.conn, pending.token.clone());
            let lines = vec![
                "a process has not answered in time; confd keeps waiting up to 30 s and \
                 goes back to the configuration before if it is refused"
                    .to_owned(),
            ];
            self.reply(conn, &token, Code::GATEWAY_TIMEOUT, absent(confd, lines));
            return true;
        }
        let Some(pending) = self.pending.take() else {
            return false;
        };
        let (code, lines) = match refusal {
            Some(why) => {
                if pending.timed_out {
                    self.counters.late_rollbacks += 1;
                }
                let mut lines = vec![
                    why,
                    "the configuration before it is being sent again".into(),
                ];
                lines.extend(prepare(&confd.with_values_of(&pending.previous)));
                confd.set_config(pending.previous);
                (Code::BAD_REQUEST, lines)
            }
            None => {
                let mut lines = pending.notes;
                let (code, line) = match self.keep(pending.keep) {
                    Ok(line) => (Code::CHANGED, line),
                    Err(line) => (Code::INTERNAL_SERVER_ERROR, line),
                };
                lines.push(line);
                (code, lines)
            }
        };
        // After 5.04 the answer went out already.
        if !pending.timed_out {
            self.reply(pending.conn, &pending.token, code, absent(confd, lines));
        }
        true
    }

    /// Keeps the configuration taken as the next version, and says so in the log and
    /// in the line returned for the answer.
    fn keep(&mut self, keep: Keep) -> Result<String, String> {
        let before = self.versions.latest().map(|v| v.number);
        let kept = self
            .versions
            .commit(&keep.how, &keep.lock, keep.toml.as_deref());
        let line = match &kept {
            Ok(number) => format!("kept as version {number} ({})", keep.how),
            Err(error) => {
                let back = before.map_or("the file it was started with".into(), |n| {
                    format!("version {n}")
                });
                format!(
                    "the configuration is in use but was not kept as a version ({error}); \
                     confd started again would go back to {back}"
                )
            }
        };
        self.log.push(line.clone());
        kept.map(|_| line.clone()).map_err(|_| line)
    }

    fn reply(&mut self, conn: u64, token: &[u8], code: Code, lines: Vec<String>) {
        if let Some((_, conn)) = self.conns.iter_mut().find(|(id, _)| *id == conn) {
            send(conn, token, code, &lines.join("\n"));
        }
    }
}

/// `lines`, and a line for each process that is not connected.
fn absent(confd: &Confd, mut lines: Vec<String>) -> Vec<String> {
    for kind in confd.absent() {
        lines.push(format!(
            "{kind} is not connected; it gets the configuration when it connects"
        ));
    }
    lines
}

fn send(conn: &mut Connection, token: &[u8], code: Code, text: &str) {
    let _ = conn.send(&Outgoing {
        code: Some(code),
        token,
        payload: text.as_bytes(),
        ..Outgoing::default()
    });
}

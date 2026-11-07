//! The socket through which `ruster apply` gives confd a new configuration file
//! (`docs/design/ce-processes.md`, "反映の流れ").
//!
//! A request is POST `config` with the file's text as its payload, framed like the other
//! sockets. confd reads the text as it reads its file at start-up, sends what changed to
//! the FE, ribd and neighd, and answers once each of them has answered:
//!
//! | Answer | Meaning |
//! |---|---|
//! | 2.04 Changed | every connected process answered yes |
//! | 4.00 Bad Request | the file has an error, or a process refused the change; in the second case confd puts the configuration it had before back |
//! | 5.03 Service Unavailable | an earlier new configuration is still waiting for answers |
//! | 5.04 Gateway Timeout | a process has not answered in time |
//!
//! After 5.04 confd keeps waiting: if the answer is a refusal, it puts the configuration
//! before back then, and until the answer comes another file gets 5.03. So a refusal
//! always ends with every process on the configuration before.
//!
//! The payload of an answer is text for a person: the error, or what the answer needs
//! to add (a process that is not connected gets the configuration when it connects
//! again; errors setting up the kernel side).
//!
//! Limits:
//! - Static routes go through ribd, which takes any route; a route the FE then refuses
//!   is not seen here.
//! - The new configuration lives only in confd's memory, so confd started again reads
//!   its file.
//! - There is no preview of the changes, no confirm-or-revert and no list of earlier
//!   versions yet.
//!
//! # Standards
//!
//! - RFC 7252 section 5.8.2 (POST) and 5.9 (the response codes above), over the stream
//!   framing of RFC 8323 like the table sockets.
//!
//! Deviations: the resource `config` and its TOML payload are ruster's own; they are not a
//! CORECONF datastore.

use std::os::unix::net::UnixStream;

use ruster_proto::coap::Code;
use ruster_proto::conn::{Connection, Outgoing};
use ruster_proto::task::Progress;

use crate::{file, Confd, Config};

/// The largest configuration file accepted.
const LIMIT: usize = 1 << 20;

/// How long a new configuration waits for the processes' answers before 5.04.
pub const ANSWER_WAIT_MS: u64 = 3_000;

/// At most this many connections at once; more are closed straight away.
pub const MAX_CONNECTIONS: usize = 8;

/// At most this many requests are handled per connection in one step.
const REQUESTS_PER_STEP: usize = 16;

/// The connections of `ruster apply` and the one change being applied.
#[derive(Default)]
pub struct Apply {
    conns: Vec<(u64, Connection)>,
    next_id: u64,
    pending: Option<Pending>,
}

impl std::fmt::Debug for Apply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Apply")
            .field("connections", &self.conns.len())
            .field("pending", &self.pending.is_some())
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
    deadline_ms: u64,
    notes: Vec<String>,
    /// 5.04 went out; the answer still decides whether to go back.
    timed_out: bool,
}

impl Apply {
    pub fn new() -> Self {
        Self::default()
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
                let path: Vec<&str> = request.path.iter().map(String::as_str).collect();
                let answer = match (request.code, path.as_slice()) {
                    (Code::POST, ["config"]) if self.pending.is_some() => Some((
                        Code::SERVICE_UNAVAILABLE,
                        "an earlier configuration is still waiting for answers".to_owned(),
                    )),
                    (Code::POST, ["config"]) => match std::str::from_utf8(&request.payload)
                        .map_err(|_| "the file is not UTF-8".to_owned())
                        .and_then(file::parse)
                    {
                        Err(error) => Some((Code::BAD_REQUEST, error)),
                        Ok(config) => {
                            let notes = prepare(&config);
                            let previous = confd.config().clone();
                            confd.set_config(config);
                            self.pending = Some(Pending {
                                conn: id,
                                token: request.token.clone(),
                                previous,
                                generation: confd.generation(),
                                deadline_ms: now_ms.saturating_add(ANSWER_WAIT_MS),
                                notes,
                                timed_out: false,
                            });
                            None
                        }
                    },
                    (code, _) if code.class() == 0 => Some((Code::NOT_FOUND, String::new())),
                    _ => None,
                };
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
        if refusal.is_none() && !confd.settled() {
            if now_ms < pending.deadline_ms || pending.timed_out {
                return false;
            }
            pending.timed_out = true;
            let (conn, token) = (pending.conn, pending.token.clone());
            let lines = vec![
                "a process has not answered in time; confd keeps waiting and goes back to \
                 the configuration before if it is refused"
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
                let mut lines = vec![why, "the configuration before it is applied again".into()];
                lines.extend(prepare(&pending.previous));
                confd.set_config(pending.previous);
                (Code::BAD_REQUEST, lines)
            }
            None => (Code::CHANGED, pending.notes),
        };
        // After 5.04 the answer went out already.
        if !pending.timed_out {
            self.reply(pending.conn, &pending.token, code, absent(confd, lines));
        }
        true
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

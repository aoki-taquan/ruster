//! The socket through which `ruster apply` gives confd a new configuration file
//! (`docs/design/ce-processes.md`, "反映の流れ").
//!
//! A request is POST `config` with the file's text as its payload, framed like the other
//! sockets. confd reads the text as it reads its file at start-up, sends what changed to
//! the FE, ribd and neighd, and answers once each of them has answered:
//!
//! | Answer | Meaning |
//! |---|---|
//! | 2.04 Changed | every connected process took the new configuration |
//! | 4.00 Bad Request | the file has an error, or a process refused the change; in the second case confd puts the configuration it had before back |
//! | 5.03 Service Unavailable | another new configuration is still being applied |
//! | 5.04 Gateway Timeout | a process did not answer in time; confd keeps the new configuration |
//!
//! The payload of an answer is text for a person: the error, or what the answer needs
//! to add (a process that is not connected gets the configuration when it connects
//! again).
//!
//! Limits: the new configuration lives only in confd's memory, so confd started again
//! reads its file. There is no preview of the changes, no confirm-or-revert and no list
//! of earlier versions yet.
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

/// How long a new configuration waits for the processes' answers.
pub const ANSWER_WAIT_MS: u64 = 3_000;

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
    refused: u64,
    deadline_ms: u64,
    notes: Vec<String>,
}

impl Apply {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attach(&mut self, stream: UnixStream) -> std::io::Result<()> {
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
            busy |= self.conns[index].1.pump().unwrap_or(false);
            while let Ok(Some(request)) = self.conns[index].1.next_message() {
                busy = true;
                let path: Vec<&str> = request.path.iter().map(String::as_str).collect();
                let answer = match (request.code, path.as_slice()) {
                    (Code::POST, ["config"]) if self.pending.is_some() => Some((
                        Code::SERVICE_UNAVAILABLE,
                        "another configuration is being applied".to_owned(),
                    )),
                    (Code::POST, ["config"]) => match std::str::from_utf8(&request.payload)
                        .map_err(|_| "the file is not UTF-8".to_owned())
                        .and_then(file::parse)
                    {
                        Err(error) => Some((Code::BAD_REQUEST, error)),
                        Ok(config) => {
                            let notes = prepare(&config);
                            self.pending = Some(Pending {
                                conn: self.conns[index].0,
                                token: request.token.clone(),
                                previous: confd.config().clone(),
                                refused: confd.counters().patches_refused,
                                deadline_ms: now_ms.saturating_add(ANSWER_WAIT_MS),
                                notes,
                            });
                            confd.set_config(config);
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
            busy |= self.conns[index].1.pump().unwrap_or(false);
            busy |= self.conns[index].1.take_more();
            if self.conns[index].1.is_closed() {
                self.conns.swap_remove(index);
            } else {
                index += 1;
            }
        }
        busy |= self.finish(confd, now_ms, prepare);
        Progress::busy(busy)
    }

    /// Answers the pending change if the processes have answered or the wait is over.
    fn finish(
        &mut self,
        confd: &mut Confd,
        now_ms: u64,
        prepare: &mut dyn FnMut(&Config) -> Vec<String>,
    ) -> bool {
        let Some(pending) = &self.pending else {
            return false;
        };
        let refused = confd.counters().patches_refused != pending.refused;
        if !refused && !confd.settled() && now_ms < pending.deadline_ms {
            return false;
        }
        let Some(mut pending) = self.pending.take() else {
            return false;
        };
        let (code, mut lines) = if refused {
            let why = confd.last_refusal().map_or_else(
                || "a process refused it".to_owned(),
                |(kind, reason)| format!("{kind} refused it: {reason}"),
            );
            let notes = prepare(&pending.previous);
            confd.set_config(pending.previous);
            let mut lines = vec![why, "the configuration before it is applied again".into()];
            lines.extend(notes);
            (Code::BAD_REQUEST, lines)
        } else if confd.settled() {
            (Code::CHANGED, Vec::new())
        } else {
            (
                Code::GATEWAY_TIMEOUT,
                vec!["a process did not answer in time; the new configuration stays".into()],
            )
        };
        lines.append(&mut pending.notes);
        for kind in confd.absent() {
            lines.push(format!(
                "{kind} is not connected; it gets the configuration when it connects"
            ));
        }
        if let Some((_, conn)) = self.conns.iter_mut().find(|(id, _)| *id == pending.conn) {
            send(conn, &pending.token, code, &lines.join("\n"));
        }
        true
    }
}

fn send(conn: &mut Connection, token: &[u8], code: Code, text: &str) {
    let _ = conn.send(&Outgoing {
        code: Some(code),
        token,
        payload: text.as_bytes(),
        ..Outgoing::default()
    });
}

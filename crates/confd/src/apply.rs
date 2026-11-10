//! The socket through which the CLI changes confd's configuration
//! (`docs/design/router-box.md`, "反映の流れ").
//!
//! | Request | CLI | What |
//! |---|---|---|
//! | POST `diff`, the file's text | `ruster diff` | what putting it in use would change, putting it in use nowhere ([`crate::diff`]) |
//! | POST `config`, the file's text | `ruster apply` | put it in use, and keep it as a version |
//! | POST `config/confirm-within/<M>`, the file's text | `ruster apply --confirm-within M` | the same, and go back unless confirmed within M minutes (below) |
//! | POST `confirm` | `ruster confirm` | the version waiting for confirmation stays |
//! | POST `rollback/<N>` | `ruster rollback N` | put version N's configuration in use again, as a new version |
//! | GET `versions` | `ruster versions` | the versions kept, a line each, newest first ([`Versions::listing`]) |
//!
//! # Putting a configuration in use
//!
//! For `config`, confd reads the text as it reads its file at start-up; for
//! `rollback/<N>`, it takes version N's lock form. Then it goes in two steps, the
//! candidate and the commit of `docs/design/router-box.md`, "反映の流れ":
//!
//! 1. Candidate: each process that takes a part checks its part of the
//!    configuration without taking it ([`crate::part`]). If one refuses it, confd
//!    answers 4.00 with each refusal and sends nothing to anyone. A process that is
//!    not connected is not asked; one that has not answered after [`ANSWER_WAIT_MS`]
//!    is not waited for, and the answer says so. `diff` stops here and answers with
//!    what each process said ([`crate::diff`]).
//! 2. Commit: confd sends what changed to the FE, ribd and neighd, and the parts that
//!    changed to the processes that take them. Once each of them has said yes, confd
//!    keeps the configuration as the next version ([`crate::versions`]) and answers,
//!    naming the version. If one refuses, confd sends the configuration before back
//!    to all of them. This catches what the check cannot: the FE, ribd and neighd
//!    are not asked first, and the software a bridge drives may refuse the file only
//!    when it reads it.
//!
//! The processes check one candidate at a time: requests that come meanwhile wait,
//! in order, until its answers are in.
//!
//! After 5.04 confd keeps waiting: a later refusal still puts the configuration before
//! back, and a later yes keeps the version. A process that disconnects meanwhile (one
//! already disconnected when the file came is not waited for) is waited for too: it
//! gets everything when it connects again, and its answer counts. After [`GIVE_UP_MS`]
//! confd stops waiting, logs it, and keeps the configuration as a version, since it
//! is the one in use. Only one change is applied at a time.
//!
//! # Confirming
//!
//! With `confirm-within`, the version kept waits M minutes (1 to
//! [`MAX_CONFIRM_MINUTES`]) for `confirm`. Without it in time, confd puts the version
//! before back the same way as a rollback, as a new version ("back to N: version V was
//! not confirmed"). This is for a change that could cut off the operator: confd holds
//! the timer, so it goes back even when no CLI is left to ask.
//!
//! - The deadline (version, version to go back to, time) is written to the state
//!   directory before the version is, so confd started again during the wait goes on
//!   waiting for the time left. Started after the deadline, confd sends the latest
//!   version as at any start, and starts going back in its first step. A deadline
//!   more than M minutes away at a start means the clock went back; confd then goes
//!   back at once too.
//! - Going back does not wait for the processes to finish what they were sent
//!   before, and does not ask them to check it first: a process that never answers
//!   or refuses must not keep the version in use. It is given up on like any change,
//!   after [`GIVE_UP_MS`].
//! - If the deadline or the version cannot be written, confd goes back at once and
//!   answers 5.00.
//! - While a version waits, `config`, `confirm-within` and `rollback` are refused with
//!   5.03; `diff` and `versions` are answered (the listing names the deadline).
//! - If a process refuses the version before, the waiting version stays in use and
//!   confd tries again after [`GO_BACK_RETRY_MS`]. A `confirm` that comes while it is
//!   going back is refused with 5.03.
//!
//! # Answers
//!
//! | Answer | Meaning |
//! |---|---|
//! | 2.04 Changed | every connected process said yes and the version was kept; or, for `confirm`, the version stays |
//! | 2.05 Content | the answer to `diff` and `versions` |
//! | 4.00 Bad Request | the file or the version does not read, `<N>` or `<M>` is not one that is allowed, nothing waits for `confirm`, a process refused the candidate (nothing was sent), or a process refused the change (and confd puts the configuration before back) |
//! | 4.04 Not Found | version N is not kept, or the resource is not one of the above |
//! | 5.00 Internal Server Error | the configuration is in use, but the version or the deadline could not be written (with `confirm-within`, confd goes back at once) |
//! | 5.03 Service Unavailable | another change is waiting for answers (for `diff` too, since what is in use is not yet a version; for `config` and `rollback`, also while a change of a source's values is), or a version waits for `confirm` |
//! | 5.04 Gateway Timeout | a process has not answered in time |
//!
//! The payload of an answer is text for a person: the error, or what the answer needs
//! to add (a process that is not connected gets the configuration when it connects
//! again; errors setting up the kernel side; the version number and any deadline).
//!
//! Limits:
//! - Static routes go through ribd, which takes any route; a route the FE then refuses
//!   is not seen here.
//! - The FE, ribd and neighd do not take part in the candidate step: confd works out
//!   their tables itself, and they check them only when they are sent.
//!
//! # Standards
//!
//! - RFC 7252 sections 5.8.1 (GET), 5.8.2 (POST) and 5.9 (the response codes above),
//!   over the stream framing of RFC 8323 like the table sockets.
//! - RFC 6241 section 8.4 (the confirmed commit of NETCONF), for `confirm-within`
//!   and `confirm`: without a confirming commit before the timeout, the configuration
//!   before goes back.
//!
//! Deviations: the resources and their text payloads are ruster's own; they are not a
//! CORECONF datastore. Of RFC 6241 8.4: the timeout is in minutes (1 to 1440), not
//! seconds, and counts from when the version is kept; there is no `persist-id` (the
//! wait outlives the connection, and confd itself) and no `cancel-commit` (wait or
//! confirm); a new commit during the wait is refused rather than confirming it.

use std::os::unix::net::UnixStream;

use ruster_proto::coap::Code;
use ruster_proto::conn::{Connection, Incoming, Outgoing};
use ruster_proto::task::Progress;

use crate::part::{Checked, Module};
use crate::versions::{unix_now, utc, Versions, Waiting};
use crate::{diff, file, Confd, Config, PeerKind};

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
    /// A candidate whose parts the processes are checking.
    checking: Option<Checking>,
    counters: ApplyCounters,
    versions: Versions,
    /// The latest version waits for `ruster confirm`.
    confirm: Option<Confirm>,
    log: Vec<String>,
}

/// A version waiting for `ruster confirm`, and when confd goes back.
#[derive(Clone, Copy, Debug)]
struct Confirm {
    waiting: Waiting,
    due: Due,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Due {
    /// This long after the first step (after a start-up).
    In(u64),
    /// At this time of the steps' clock.
    At(u64),
    /// The version before is being sent again.
    GoingBack,
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

/// A candidate the processes are checking ([`crate::part`]), and what then.
struct Checking {
    conn: u64,
    token: Vec<u8>,
    started_ms: u64,
    then: Then,
}

enum Then {
    /// Answer `diff` with confd's own part of it and the processes' answers.
    Diff(String),
    /// Put it in use unless a process refuses it.
    Apply(Box<Config>, Keep),
}

/// A version to keep: how it came, the lock form and the `ruster.toml` text.
struct Keep {
    how: String,
    lock: String,
    toml: Option<String>,
    /// It waits this many minutes for `ruster confirm`.
    confirm: Option<u32>,
    /// It is the version before one that was not confirmed.
    going_back: bool,
}

impl Keep {
    fn new(how: String, lock: String, toml: Option<String>) -> Self {
        Self {
            how,
            lock,
            toml,
            confirm: None,
            going_back: false,
        }
    }
}

/// The longest wait for `ruster confirm`: a day.
pub const MAX_CONFIRM_MINUTES: u32 = 24 * 60;

/// How long confd waits before it tries again to go back, after a process refused
/// the version before.
pub const GO_BACK_RETRY_MS: u64 = 60_000;

/// The connection of the answer to a change confd makes by itself.
const NO_CONNECTION: u64 = u64::MAX;

impl Apply {
    /// With the versions so far; the latest is the configuration confd has. If it
    /// waits for `ruster confirm`, the time left is counted from the first step.
    pub fn new(versions: Versions) -> Self {
        let mut apply = Self {
            versions,
            ..Self::default()
        };
        if let Some(waiting) = apply.versions.waiting() {
            // A deadline further away than the wait given means the clock went back
            // (a box with no clock kept across a restart): it cannot be trusted, and
            // waiting again each start could put going back off for ever.
            let left_s = waiting.deadline.saturating_sub(unix_now());
            let left_s = if left_s > u64::from(waiting.minutes) * 60 {
                0
            } else {
                left_s
            };
            apply.confirm = Some(Confirm {
                waiting,
                due: Due::In(left_s * 1_000),
            });
            apply.log.push(format!(
                "version {} waits for `ruster confirm`; it goes back to version {} in {left_s} s",
                waiting.version, waiting.back_to
            ));
        }
        apply
    }

    /// The version waiting for `ruster confirm`, if one is.
    pub fn waiting(&self) -> Option<Waiting> {
        self.confirm.map(|c| c.waiting)
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
        busy |= self.finish_check(confd, now_ms, prepare);
        busy |= self.go_back_when_due(confd, now_ms, prepare);
        let mut index = 0;
        while index < self.conns.len() {
            let id = self.conns[index].0;
            busy |= self.conns[index].1.pump().unwrap_or(false);
            for _ in 0..REQUESTS_PER_STEP {
                // The processes check one candidate at a time: the requests after it
                // wait for its answers, in order.
                if self.checking.is_some() {
                    break;
                }
                let conn = &mut self.conns[index].1;
                // A client that does not read its answers gets no more handled.
                if conn.backlog() >= conn.limit() {
                    break;
                }
                let Ok(Some(request)) = conn.next_message() else {
                    break;
                };
                busy = true;
                let answer = self.handle(confd, id, &request, now_ms);
                if let Some((code, text)) = answer {
                    send(&mut self.conns[index].1, &request.token, code, &text);
                }
                // With no process to ask, a check is answered at once.
                self.finish_check(confd, now_ms, prepare);
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
        busy |= self.finish_check(confd, now_ms, prepare);
        Progress::busy(busy)
    }

    /// Handles one request of connection `id`. `None` when the answer comes later
    /// (from [`Apply::finish_check`] and [`Apply::finish`]) or there is none.
    fn handle(
        &mut self,
        confd: &mut Confd,
        id: u64,
        request: &Incoming,
        now_ms: u64,
    ) -> Option<(Code, String)> {
        let path: Vec<&str> = request.path.iter().map(String::as_str).collect();
        let busy = self.pending.is_some() || !confd.settled();
        let mut confirm = None;
        let candidate = match (request.code, path.as_slice()) {
            (Code::GET, ["versions"]) => return Some((Code::CONTENT, self.versions.listing())),
            (Code::POST, ["confirm"]) => return Some(self.confirmed()),
            (Code::POST, ["config"] | ["config", "confirm-within", _] | ["rollback", _])
                if busy =>
            {
                return Some((
                    Code::SERVICE_UNAVAILABLE,
                    "an earlier configuration is still waiting for answers".to_owned(),
                ))
            }
            // Only reads; but what is in use is not yet a version.
            (Code::POST, ["diff"]) if self.pending.is_some() => {
                return Some((
                    Code::SERVICE_UNAVAILABLE,
                    "an earlier configuration is still waiting for answers".to_owned(),
                ))
            }
            (Code::POST, ["config"] | ["config", "confirm-within", _] | ["rollback", _])
                if self.confirm.is_some() =>
            {
                let waiting = self.confirm.map(|c| c.waiting)?;
                return Some((
                    Code::SERVICE_UNAVAILABLE,
                    format!(
                        "version {} waits for `ruster confirm` (else it goes back to version {} \
                         at {}); confirm it, or let it go back, first",
                        waiting.version,
                        waiting.back_to,
                        utc(waiting.deadline)
                    ),
                ));
            }
            (Code::POST, ["config", "confirm-within", minutes]) => {
                match minutes
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| minutes.parse::<u32>().ok())
                    .flatten()
                    .filter(|m| (1..=MAX_CONFIRM_MINUTES).contains(m))
                {
                    // Never without a version to go back to (confd always has one).
                    Some(_) if self.versions.latest().is_none() => {
                        return Some((
                            Code::BAD_REQUEST,
                            "there is no version to go back to".to_owned(),
                        ))
                    }
                    Some(minutes) => confirm = Some(minutes),
                    None => {
                        return Some((
                            Code::BAD_REQUEST,
                            format!("{minutes}: minutes from 1 to {MAX_CONFIRM_MINUTES}"),
                        ))
                    }
                }
                std::str::from_utf8(&request.payload)
                    .map_err(|_| "the file is not UTF-8".to_owned())
                    .and_then(file::candidate)
                    .map(|candidate| {
                        let keep = Keep::new("apply".into(), candidate.lock, candidate.toml);
                        (candidate.config, keep)
                    })
            }
            (Code::POST, ["diff"]) => {
                return match std::str::from_utf8(&request.payload)
                    .map_err(|_| "the file is not UTF-8".to_owned())
                    .and_then(file::candidate)
                {
                    Err(error) => Some((Code::BAD_REQUEST, error)),
                    Ok(candidate) => {
                        let own = self.diff(confd, &candidate);
                        self.check(
                            confd,
                            &candidate.config,
                            Then::Diff(own),
                            id,
                            request,
                            now_ms,
                        );
                        None
                    }
                };
            }
            (Code::POST, ["config"]) => std::str::from_utf8(&request.payload)
                .map_err(|_| "the file is not UTF-8".to_owned())
                .and_then(file::candidate)
                .map(|candidate| {
                    let keep = Keep::new("apply".into(), candidate.lock, candidate.toml);
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
                        let keep = Keep::new(
                            format!("rollback to {number}"),
                            version.lock.clone(),
                            version.toml.clone(),
                        );
                        (config, keep)
                    })
            }
            (code, _) if code.class() == 0 => return Some((Code::NOT_FOUND, String::new())),
            _ => return None,
        };
        match candidate {
            Err(error) => Some((Code::BAD_REQUEST, error)),
            Ok((config, mut keep)) => {
                keep.confirm = confirm;
                let candidate = config.clone();
                self.check(
                    confd,
                    &candidate,
                    Then::Apply(Box::new(config), keep),
                    id,
                    request,
                    now_ms,
                );
                None
            }
        }
    }

    /// Answers `ruster confirm`: the waiting version stays.
    fn confirmed(&mut self) -> (Code, String) {
        let Some(confirm) = self.confirm else {
            return (
                Code::BAD_REQUEST,
                "nothing waits for confirmation".to_owned(),
            );
        };
        let (version, back_to) = (confirm.waiting.version, confirm.waiting.back_to);
        if confirm.due == Due::GoingBack {
            return (
                Code::SERVICE_UNAVAILABLE,
                format!("too late: version {back_to} is being sent again"),
            );
        }
        self.confirm = None;
        let answer = match self.versions.set_waiting(None) {
            Ok(()) => (Code::CHANGED, format!("version {version} confirmed")),
            Err(error) => (
                Code::INTERNAL_SERVER_ERROR,
                format!(
                    "version {version} confirmed, but {error}: confd started again would \
                     still go back to version {back_to}"
                ),
            ),
        };
        self.log.push(answer.1.clone());
        answer
    }

    /// Goes back to the version before one not confirmed in time, once nothing else
    /// is being applied.
    fn go_back_when_due(
        &mut self,
        confd: &mut Confd,
        now_ms: u64,
        prepare: &mut dyn FnMut(&Config) -> Vec<String>,
    ) -> bool {
        let Some(confirm) = &mut self.confirm else {
            return false;
        };
        if let Due::In(left_ms) = confirm.due {
            confirm.due = Due::At(now_ms + left_ms);
        }
        let Due::At(at) = confirm.due else {
            return false;
        };
        // Not waiting for the processes to settle: one that never answers must not
        // keep the version in use. Going back has its own wait and give-up.
        if now_ms < at || self.pending.is_some() {
            return false;
        }
        let Waiting {
            version, back_to, ..
        } = confirm.waiting;
        // A lock form from before an update may not read; its ruster.toml is then
        // resolved again, as at start-up.
        let config = match self.versions.get(back_to) {
            None => Err("it is not kept".to_owned()),
            Some(before) => match file::parse(&before.lock) {
                Ok(config) => Ok((config, before.lock.clone(), before.toml.clone())),
                Err(error) => match before.toml.as_deref().map(file::candidate) {
                    Some(Ok(c)) => Ok((c.config, c.lock, before.toml.clone())),
                    _ => Err(error),
                },
            },
        };
        match config {
            Ok((config, lock, toml)) => {
                let how = if self.versions.get(version).is_some() {
                    format!("back to {back_to}: version {version} was not confirmed")
                } else {
                    format!("back to {back_to}: the configuration after it was not kept")
                };
                let mut keep = Keep::new(how, lock, toml);
                keep.going_back = true;
                confirm.due = Due::GoingBack;
                self.log.push(format!(
                    "version {version} was not confirmed in time; going back to version {back_to}"
                ));
                self.start(confd, config, keep, (NO_CONNECTION, &[]), now_ms, prepare);
            }
            Err(error) => {
                // Nothing to go back to: what is in use stays.
                self.confirm = None;
                let _ = self.versions.set_waiting(None);
                self.log.push(format!(
                    "version {version} was not confirmed in time, but version {back_to} \
                     cannot be put back ({error}); version {version} stays"
                ));
            }
        }
        true
    }

    /// What `candidate` would change, as text for a person ([`crate::diff`]).
    fn diff(&self, confd: &mut Confd, candidate: &file::Candidate) -> String {
        let (name, lock) = match self.versions.latest() {
            Some(latest) => (format!("version {}", latest.number), latest.lock.as_str()),
            None => ("nothing".to_owned(), ""),
        };
        let none = |text: String| {
            if text.is_empty() {
                "no change\n".into()
            } else {
                text
            }
        };
        let [[fe_now, fe_then], [routes_now, routes_then]] =
            confd.tables_now_and_with(&candidate.config);
        format!(
            "lock form:\n{}\nFE tables (with the values the sources have now):\n{}\n\
             routes offered to ribd:\n{}",
            none(diff::lines(lock, &candidate.lock, (&name, "new"))),
            none(diff::tables(&fe_now, &fe_then)),
            none(diff::tables(&routes_now, &routes_then)),
        )
    }

    /// Asks the processes to check their parts of `candidate`;
    /// [`Apply::finish_check`] goes on once they have answered.
    fn check(
        &mut self,
        confd: &mut Confd,
        candidate: &Config,
        then: Then,
        conn: u64,
        request: &Incoming,
        now_ms: u64,
    ) {
        confd.check_parts(candidate);
        self.checking = Some(Checking {
            conn,
            token: request.token.clone(),
            started_ms: now_ms,
            then,
        });
    }

    /// Once every process asked has answered the check, or [`ANSWER_WAIT_MS`] has
    /// passed: answers `diff`, or refuses the candidate if a process refused it, or
    /// sends it.
    fn finish_check(
        &mut self,
        confd: &mut Confd,
        now_ms: u64,
        prepare: &mut dyn FnMut(&Config) -> Vec<String>,
    ) -> bool {
        let Some(checking) = &self.checking else {
            return false;
        };
        let checks = confd.part_checks();
        let answered = !checks.values().any(|c| *c == Checked::NoAnswer);
        if !answered && now_ms.saturating_sub(checking.started_ms) < ANSWER_WAIT_MS {
            return false;
        }
        let Some(checking) = self.checking.take() else {
            return false;
        };
        let checks = checks.clone();
        match checking.then {
            Then::Diff(own) => {
                let text = format!("{own}\n{}", part_sections(&checks));
                self.reply(checking.conn, &checking.token, Code::CONTENT, vec![text]);
            }
            Then::Apply(config, keep) => {
                let refusals: Vec<String> = checks
                    .iter()
                    .filter_map(|(module, checked)| match checked {
                        Checked::Refused(reason) => {
                            Some(format!("{} refuses it: {reason}", name(*module)))
                        }
                        _ => None,
                    })
                    .collect();
                if refusals.is_empty() && !confd.settled() {
                    // Something changed while the processes checked (a source's
                    // values, a process that connected again).
                    let line = "an earlier configuration is still waiting for answers";
                    self.reply(
                        checking.conn,
                        &checking.token,
                        Code::SERVICE_UNAVAILABLE,
                        vec![line.into()],
                    );
                } else if refusals.is_empty() {
                    let late = checks.iter().filter(|(_, c)| **c == Checked::NoAnswer).map(
                        |(module, _)| format!("{} did not answer the check in time", name(*module)),
                    );
                    let late: Vec<String> = late.collect();
                    let to = (checking.conn, checking.token.as_slice());
                    self.start(confd, *config, keep, to, now_ms, prepare);
                    if let Some(pending) = &mut self.pending {
                        pending.notes.splice(0..0, late);
                    }
                } else {
                    let mut lines = refusals;
                    lines.push("nothing was sent; the configuration in use stays".into());
                    self.log.push(lines.join("; "));
                    self.reply(checking.conn, &checking.token, Code::BAD_REQUEST, lines);
                }
            }
        }
        true
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
                let _ = self.keep(pending.keep, now_ms);
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
            let mut lines = vec![
                "a process has not answered in time; confd keeps waiting up to 30 s and \
                 goes back to the configuration before if it is refused"
                    .to_owned(),
            ];
            if let Some(minutes) = pending.keep.confirm {
                lines.push(format!(
                    "if it is kept, it then waits {minutes} min for `ruster confirm`; \
                     see `ruster versions`"
                ));
            }
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
                if pending.keep.going_back {
                    // The version not confirmed stays for now; confd tries again.
                    if let Some(confirm) = &mut self.confirm {
                        confirm.due = Due::At(now_ms + GO_BACK_RETRY_MS);
                    }
                    self.log.push(format!(
                        "going back was refused ({}); trying again in {} s",
                        lines[0],
                        GO_BACK_RETRY_MS / 1_000
                    ));
                }
                (Code::BAD_REQUEST, lines)
            }
            None => {
                let mut lines = pending.notes;
                let (code, line) = match self.keep(pending.keep, now_ms) {
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
    ///
    /// For one that waits for `ruster confirm`, the deadline is written before the
    /// version, so that confd stopped in between and started again still goes back.
    /// If either cannot be written, confd goes back at once.
    fn keep(&mut self, keep: Keep, now_ms: u64) -> Result<String, String> {
        let before = self.versions.latest().map(|v| v.number);
        let mut kept = Err(String::new());
        if let (Some(minutes), Some(back_to)) = (keep.confirm, before) {
            let waiting = Waiting {
                version: back_to + 1,
                back_to,
                deadline: unix_now() + u64::from(minutes) * 60,
                minutes,
            };
            self.confirm = Some(Confirm {
                waiting,
                due: Due::At(now_ms + u64::from(minutes) * 60_000),
            });
            kept = self.versions.set_waiting(Some(waiting)).map(|()| 0);
        }
        if keep.confirm.is_none() || kept.is_ok() {
            kept = self
                .versions
                .commit(&keep.how, &keep.lock, keep.toml.as_deref());
        }
        let line = match (&kept, self.confirm) {
            (Ok(number), Some(confirm)) if keep.confirm.is_some() => format!(
                "kept as version {number} ({}); it goes back to version {} at {} unless \
                 `ruster confirm` comes first",
                keep.how,
                confirm.waiting.back_to,
                utc(confirm.waiting.deadline)
            ),
            (Ok(number), _) => format!("kept as version {number} ({})", keep.how),
            (Err(error), Some(confirm)) if keep.confirm.is_some() => {
                self.confirm = Some(Confirm {
                    due: Due::At(now_ms),
                    ..confirm
                });
                let _ = self.versions.set_waiting(None);
                format!(
                    "the configuration is in use but was not kept as a version ({error}); \
                     going back to version {} now",
                    confirm.waiting.back_to
                )
            }
            (Err(error), _) => {
                let back = before.map_or("the file it was started with".into(), |n| {
                    format!("version {n}")
                });
                format!(
                    "the configuration is in use but was not kept as a version ({error}); \
                     confd started again would go back to {back}"
                )
            }
        };
        // Once the version before is back in use, nothing waits any more. If it was not
        // kept, the deadline stays on disk, so confd started again goes back too.
        if keep.going_back {
            self.confirm = None;
            if kept.is_ok() {
                if let Err(error) = self.versions.set_waiting(None) {
                    self.log.push(error);
                }
            }
        }
        self.log.push(line.clone());
        kept.map(|_| line.clone()).map_err(|_| line)
    }

    fn reply(&mut self, conn: u64, token: &[u8], code: Code, lines: Vec<String>) {
        if let Some((_, conn)) = self.conns.iter_mut().find(|(id, _)| *id == conn) {
            send(conn, token, code, &lines.join("\n"));
        }
    }
}

/// A process that takes a module's part, for a person.
fn name(module: Module) -> String {
    format!("{} ({module})", module.process())
}

/// What each process said to a check, a section each, for `ruster diff`.
fn part_sections(checks: &std::collections::BTreeMap<Module, Checked>) -> String {
    let mut out = String::new();
    for (module, checked) in checks {
        out.push_str(&format!("{}:\n", name(*module)));
        match checked {
            Checked::Changes(text) if text.is_empty() => out.push_str("no change\n"),
            Checked::Changes(text) => {
                out.push_str(text);
                if !text.ends_with('\n') {
                    out.push('\n');
                }
            }
            Checked::Refused(reason) => out.push_str(&format!("refuses it: {reason}\n")),
            Checked::NotConnected => {
                out.push_str("not connected; it gets the configuration when it connects\n");
            }
            Checked::NoAnswer => out.push_str("did not answer in time\n"),
        }
        out.push('\n');
    }
    out
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

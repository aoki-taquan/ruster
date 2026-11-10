//! The sockets where each process takes its part of the configuration
//! (`docs/design/router-box.md`, "設定の三段").
//!
//! Each module has its own socket, `confd/part/<module>/part.sock`, in a directory of
//! its own, so that file permissions can let only the module's process open it
//! (`docs/design/ce-processes.md`, "socketの権限"): the `pppoe` part holds the PPPoE
//! passwords. A process (such as `ruster-unbound`) connects to its module's socket,
//! names the module, and from then on confd puts that module's part to it, in the
//! lock form, and the process answers whether it took it:
//!
//! | From | Request | Answer |
//! |---|---|---|
//! | process | POST `<module>`, no payload | 2.04 Changed; 4.04 Not Found for a module other than the socket's; 4.00 Bad Request for a second module on one connection |
//! | confd | PUT `<module>`, the part as TOML text | 2.04 Changed when the process took it; any other code refuses it, with the reason as text |
//! | confd | POST `<module>/check`, a candidate part as TOML text | 2.05 Content with what taking it would change, as text for a person (empty when nothing would); 4.00 Bad Request with the reason when the process would refuse it |
//!
//! confd puts the part right after the 2.04, and again whenever a new configuration
//! changes it. A part is the whole of the module, so each PUT replaces the last one.
//! A refused PUT is handled like a refusal from the FE, ribd or neighd: if it is for
//! a new configuration from `ruster apply`, confd puts the configuration before back
//! ([`crate::apply`]), which for the refusing process is the part it already holds.
//!
//! A check is the candidate step of `docs/design/router-box.md`, "反映の流れ": the
//! process works out what the part would change against what it holds now (its
//! files, its sessions), and takes nothing. A process whose part would not change
//! is not asked: that part is not sent either. `ruster diff` shows the answers, and
//! `ruster apply` sends nothing to anyone when one refuses ([`crate::apply`]). An
//! answer too long for one message is cut, saying so. A check cannot foresee
//! everything: the software a bridge drives may still refuse the file when it reads
//! it, which the answer to the PUT then says.
//! A process gets only its own module's part, never the rest of the configuration.
//!
//! One connection takes one module, and one connection holds each module: a newer one
//! for the same module closes the older one, since it means the process started
//! again. While the process is away, `ruster apply` waits for it as for the FE.
//!
//! The modules and their parts:
//!
//! | Module | Process | Part |
//! |---|---|---|
//! | `dns` | `ruster-unbound` | [`ruster_config::dns_part_with`]: with the DNS servers the sources of `upstream-from` have now (`upstream-found`) |
//! | `dhcp` | `ruster-kea` | [`ruster_config::dhcp_part`] |
//! | `ra` | `ruster-neighd` | [`ruster_config::ra_part`] |
//! | `pppoe` | `ruster-pppoed` | [`ruster_config::pppoe_part`] |
//! | `dhcpc` | `ruster-dhcpc` | [`ruster_config::dhcp_client_part`] |
//! | `frr` | `ruster-frr` | [`ruster_config::frr_part`], with the prefixes of the default VRF's interfaces ([`crate::bgp::connected`]) |
//!
//! [`Client`] is the process's side, and [`changes`] the text a process that runs
//! one thing per entry answers a check with.
//!
//! # Standards
//!
//! - RFC 7252 sections 5.8.2 (POST), 5.8.3 (PUT) and 5.9 (the response codes), over
//!   the stream framing of RFC 8323 like the table sockets. Either side sends
//!   requests on the one connection, as RFC 8323 allows.
//!
//! Deviations: the resources and their TOML payloads are ruster's own, not a
//! CORECONF datastore.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;

use ruster_proto::coap::Code;
use ruster_proto::conn::{Connection, Incoming, Outgoing};
use ruster_proto::task::Progress;

use crate::Config;

/// The largest message on this socket.
const LIMIT: usize = 1 << 20;

/// At most this many connections per socket that have not named a module yet.
pub const MAX_UNNAMED: usize = 8;

/// At most this many messages are handled per connection in one step.
const MESSAGES_PER_STEP: usize = 16;

/// A part of the configuration that one process takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Module {
    Dns,
    Dhcp,
    Ra,
    Pppoe,
    Dhcpc,
    Frr,
}

impl Module {
    pub const ALL: [Module; 6] = [
        Module::Dns,
        Module::Dhcp,
        Module::Ra,
        Module::Pppoe,
        Module::Dhcpc,
        Module::Frr,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Dhcp => "dhcp",
            Self::Ra => "ra",
            Self::Pppoe => "pppoe",
            Self::Dhcpc => "dhcpc",
            Self::Frr => "frr",
        }
    }

    /// The process that takes the module.
    pub fn process(self) -> &'static str {
        match self {
            Self::Dns => "ruster-unbound",
            Self::Dhcp => "ruster-kea",
            Self::Ra => "ruster-neighd",
            Self::Pppoe => "ruster-pppoed",
            Self::Dhcpc => "ruster-dhcpc",
            Self::Frr => "ruster-frr",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == name)
    }

    /// The module's part of `config`.
    pub fn part(self, config: &Config) -> String {
        match self {
            Self::Dns => ruster_config::dns_part_with(config.dns.as_ref(), &config.dns_found),
            Self::Dhcp => ruster_config::dhcp_part(&config.dhcp, &config.dhcp6),
            Self::Ra => ruster_config::ra_part(&config.ra),
            Self::Pppoe => ruster_config::pppoe_part(&config.pppoe),
            Self::Dhcpc => ruster_config::dhcp_client_part(&config.dhcp_client),
            Self::Frr => ruster_config::frr_part(
                config.bgp.as_ref(),
                &crate::bgp::connected(&config.interfaces),
            ),
        }
    }

    /// Whether `config` has anything for the module.
    pub fn configured(self, config: &Config) -> bool {
        match self {
            Self::Dns => config.dns.is_some(),
            Self::Dhcp => !config.dhcp.is_empty() || !config.dhcp6.is_empty(),
            Self::Ra => !config.ra.is_empty(),
            Self::Pppoe => !config.pppoe.is_empty(),
            Self::Dhcpc => !config.dhcp_client.is_empty(),
            Self::Frr => config.bgp.is_some(),
        }
    }
}

impl std::fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The process that took a module.
struct Taker {
    conn: Connection,
    next_token: u32,
    /// The part it took last.
    held: Option<String>,
    /// PUTs waiting for an answer: token, configuration generation, part.
    in_flight: Vec<(u32, u64, String)>,
    /// The token of the check waiting for an answer, if one is.
    checking: Option<u32>,
}

impl Taker {
    /// The part it will hold once every PUT in flight is taken.
    fn expected(&self) -> Option<&String> {
        self.in_flight
            .last()
            .map(|(_, _, part)| part)
            .or(self.held.as_ref())
    }

    fn token(&mut self) -> u32 {
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        token
    }

    fn put(&mut self, module: Module, part: String, generation: u64) {
        let token = self.token();
        let sent = self.conn.send(&Outgoing {
            code: Some(Code::PUT),
            token: &token.to_be_bytes(),
            path: &[module.name()],
            payload: part.as_bytes(),
            ..Outgoing::default()
        });
        if sent.is_ok() {
            self.in_flight.push((token, generation, part));
        }
    }

    fn check(&mut self, module: Module, part: &str) -> bool {
        let token = self.token();
        let sent = self.conn.send(&Outgoing {
            code: Some(Code::POST),
            token: &token.to_be_bytes(),
            path: &[module.name(), "check"],
            payload: part.as_bytes(),
            ..Outgoing::default()
        });
        self.checking = sent.is_ok().then_some(token);
        sent.is_ok()
    }
}

/// A process's answer to a check of a candidate part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Checked {
    /// It would take the part; what that would change (empty: nothing).
    Changes(String),
    /// It would refuse the part, for this reason.
    Refused(String),
    /// No process takes the module now.
    NotConnected,
    /// It has not answered (yet).
    NoAnswer,
}

/// confd's side: the connections, and the process holding each module.
#[derive(Default)]
pub(crate) struct Parts {
    /// Connections that have not named a module yet, with the module of their socket.
    unnamed: Vec<(Module, Connection)>,
    takers: BTreeMap<Module, Taker>,
    /// The answers to the last check, by module.
    checked: BTreeMap<Module, Checked>,
}

/// A process refused a part: the module, its reason, and the generation of the part.
pub(crate) type Refusal = (Module, String, u64);

impl Parts {
    /// Takes a connection on `module`'s socket.
    pub(crate) fn attach(&mut self, module: Module, stream: UnixStream) -> io::Result<()> {
        // Counted per socket, so that a process that may open one socket cannot keep
        // the others' processes out.
        if self.unnamed.iter().filter(|(m, _)| *m == module).count() >= MAX_UNNAMED {
            return Err(io::Error::other("too many connections"));
        }
        self.unnamed.push((module, Connection::new(stream, LIMIT)?));
        Ok(())
    }

    /// Puts each module's part where it differs from what its process holds.
    pub(crate) fn send(&mut self, config: &Config, generation: u64) {
        for (module, taker) in &mut self.takers {
            let part = module.part(config);
            if !taker.conn.is_closed() && taker.expected() != Some(&part) {
                taker.put(*module, part, generation);
            }
        }
    }

    /// Asks every connected process whose part `candidate` changes to check it (one
    /// whose part stays has no change), and notes the modules `candidate` has that no
    /// process takes now. The answers of an earlier
    /// check are dropped.
    pub(crate) fn check(&mut self, candidate: &Config) {
        self.checked.clear();
        for module in Module::ALL {
            let part = module.part(candidate);
            let asked = match self.takers.get_mut(&module) {
                // A part that would not change is not sent, so nothing can refuse it.
                Some(taker) if !taker.conn.is_closed() && taker.expected() == Some(&part) => {
                    self.checked.insert(module, Checked::Changes(String::new()));
                    continue;
                }
                Some(taker) if !taker.conn.is_closed() => taker.check(module, &part),
                _ => false,
            };
            if asked {
                self.checked.insert(module, Checked::NoAnswer);
            } else if module.configured(candidate) {
                self.checked.insert(module, Checked::NotConnected);
            }
        }
    }

    /// The answers to the last check so far, by module.
    pub(crate) fn checked(&self) -> &BTreeMap<Module, Checked> {
        &self.checked
    }

    /// True when every connected process has answered every PUT.
    pub(crate) fn settled(&self) -> bool {
        self.takers
            .values()
            .all(|t| t.conn.is_closed() || t.in_flight.is_empty())
    }

    /// The modules whose process was connected and went away.
    pub(crate) fn closed(&self) -> Vec<Module> {
        self.takers
            .iter()
            .filter(|(_, t)| t.conn.is_closed())
            .map(|(m, _)| *m)
            .collect()
    }

    /// Whether a process holds `module` now.
    pub(crate) fn connected(&self, module: Module) -> bool {
        self.takers
            .get(&module)
            .is_some_and(|t| !t.conn.is_closed())
    }

    pub(crate) fn step(&mut self, config: &Config, generation: u64) -> (Progress, Vec<Refusal>) {
        let mut busy = false;
        let mut named = Vec::new();
        let mut index = 0;
        while index < self.unnamed.len() {
            let (socket, conn) = &mut self.unnamed[index];
            busy |= conn.pump().unwrap_or(false);
            let mut module = None;
            if conn.backlog() >= conn.limit() {
                conn.close();
            } else if let Ok(Some(request)) = conn.next_message() {
                busy = true;
                module = name(conn, &request, *socket);
            }
            busy |= conn.pump().unwrap_or(false);
            if let Some(module) = module {
                named.push((module, self.unnamed.swap_remove(index).1));
            } else if self.unnamed[index].1.is_closed() {
                self.unnamed.swap_remove(index);
            } else {
                index += 1;
            }
        }
        for (module, conn) in named {
            let mut taker = Taker {
                conn,
                next_token: 1,
                held: None,
                in_flight: Vec::new(),
                checking: None,
            };
            // A process that started again does not answer the older one's check.
            if self.checked.get(&module) == Some(&Checked::NoAnswer) {
                self.checked.insert(module, Checked::NotConnected);
            }
            taker.put(module, module.part(config), generation);
            // The older connection for the module, if any, is closed by the drop.
            self.takers.insert(module, taker);
        }
        let mut refusals = Vec::new();
        for (module, taker) in &mut self.takers {
            busy |= taker.conn.pump().unwrap_or(false);
            for _ in 0..MESSAGES_PER_STEP {
                // A process that does not read its answers gets no more handled.
                if taker.conn.backlog() >= taker.conn.limit() {
                    break;
                }
                let Ok(Some(message)) = taker.conn.next_message() else {
                    break;
                };
                busy = true;
                if message.code.class() == 0 {
                    // The module is named already; nothing else is asked of confd.
                    reply(
                        &mut taker.conn,
                        &message.token,
                        Code::BAD_REQUEST,
                        "one module per connection",
                    );
                    continue;
                }
                let token = message
                    .token
                    .as_slice()
                    .try_into()
                    .map(u32::from_be_bytes)
                    .unwrap_or(0);
                if taker.checking == Some(token) {
                    taker.checking = None;
                    let text = String::from_utf8_lossy(&message.payload).into_owned();
                    let answer = if message.code.class() == 2 {
                        Checked::Changes(text)
                    } else {
                        Checked::Refused(text)
                    };
                    self.checked.insert(*module, answer);
                    continue;
                }
                let Some(at) = taker.in_flight.iter().position(|(t, _, _)| *t == token) else {
                    continue;
                };
                let (_, generation, part) = taker.in_flight.remove(at);
                if message.code.class() == 2 {
                    taker.held = Some(part);
                } else {
                    let reason = String::from_utf8_lossy(&message.payload).into_owned();
                    refusals.push((*module, reason, generation));
                }
            }
            busy |= taker.conn.take_more();
            busy |= taker.conn.pump().unwrap_or(false);
            if taker.conn.is_closed() && taker.checking.take().is_some() {
                self.checked.insert(*module, Checked::NotConnected);
            }
        }
        (Progress::busy(busy), refusals)
    }
}

/// Answers a connection's first request on `socket`'s socket; the module it names,
/// if it is that one.
fn name(conn: &mut Connection, request: &Incoming, socket: Module) -> Option<Module> {
    let path: Vec<&str> = request.path.iter().map(String::as_str).collect();
    let module = match (request.code, path.as_slice()) {
        (Code::POST, [name]) => Module::from_name(name).filter(|m| *m == socket),
        (code, _) if code.class() != 0 => return None,
        _ => None,
    };
    match module {
        Some(_) => reply(conn, &request.token, Code::CHANGED, ""),
        None => reply(conn, &request.token, Code::NOT_FOUND, "no such module"),
    }
    module
}

fn reply(conn: &mut Connection, token: &[u8], code: Code, text: &str) {
    let _ = conn.send(&Outgoing {
        code: Some(code),
        token,
        payload: text.as_bytes(),
        ..Outgoing::default()
    });
}

/// What confd asks of a process ([`Client::poll`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asked<'a> {
    /// Take this part. `Ok` takes it (its text is not used); `Err` refuses it, with
    /// the reason.
    Take(&'a str),
    /// Check this candidate part without taking it. `Ok` says what taking it would
    /// change, as text for a person (empty when nothing would); `Err` says why it
    /// would be refused.
    Check(&'a str),
}

/// The answer to a check for a process that runs one thing per entry of its part
/// (`ruster-pppoed`, `ruster-dhcpc`, neighd's RA): the line diff of the part from
/// `before` to `after`, written by `part`, and then a line for each entry that would
/// start, change or stop, named by `key`, with the words of `verbs` (in that order).
/// Empty when the entries are the same. Entries whose content should not be shown
/// (passwords) are hidden by the caller before.
pub fn changes<T: PartialEq>(
    before: &[T],
    after: &[T],
    key: impl Fn(&T) -> &str,
    part: impl Fn(&[T]) -> String,
    verbs: [&str; 3],
) -> String {
    let mut out = crate::diff::lines(&part(before), &part(after), ("in use", "candidate"));
    for entry in after {
        let same_key = before.iter().find(|b| key(b) == key(entry));
        let verb = match same_key {
            None => verbs[0],
            Some(old) if old != entry => verbs[1],
            Some(_) => continue,
        };
        out.push_str(&format!("{}: {verb}\n", key(entry)));
    }
    for entry in before {
        if !after.iter().any(|a| key(a) == key(entry)) {
            out.push_str(&format!("{}: {}\n", key(entry), verbs[2]));
        }
    }
    out
}

/// The process's side: names its module, then takes each part confd puts.
#[derive(Debug)]
pub struct Client {
    conn: Connection,
    module: Module,
    named: bool,
}

impl Client {
    /// Takes over a connection to `confd/part/<module>/part.sock` and names `module`.
    pub fn new(stream: UnixStream, module: Module) -> io::Result<Self> {
        let mut conn = Connection::new(stream, LIMIT)?;
        let _ = conn.send(&Outgoing {
            code: Some(Code::POST),
            token: &[0],
            path: &[module.name()],
            ..Outgoing::default()
        });
        Ok(Self {
            conn,
            module,
            named: false,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// True once confd took the module's name.
    pub fn named(&self) -> bool {
        self.named
    }

    /// Hands each part confd put, and each candidate part it asks to check, to
    /// `answer` and answers confd with what it returns ([`Asked`]). An error from
    /// confd to the module's name is returned.
    pub fn poll(
        &mut self,
        answer: &mut dyn FnMut(Asked<'_>) -> Result<String, String>,
    ) -> Result<Progress, String> {
        let mut busy = self.conn.pump().unwrap_or(false);
        while let Ok(Some(message)) = self.conn.next_message() {
            busy = true;
            if message.code.class() != 0 {
                if message.code != Code::CHANGED {
                    let reason = String::from_utf8_lossy(&message.payload);
                    return Err(format!("confd refused module {}: {reason}", self.module));
                }
                self.named = true;
                continue;
            }
            let path: Vec<&str> = message.path.iter().map(String::as_str).collect();
            let text = std::str::from_utf8(&message.payload)
                .map_err(|_| "the part is not UTF-8".to_owned());
            let (code, text) = match (message.code, path.as_slice()) {
                (Code::PUT, [name]) if *name == self.module.name() => {
                    match text.and_then(|part| answer(Asked::Take(part))) {
                        Ok(_) => (Code::CHANGED, String::new()),
                        Err(reason) => (Code::BAD_REQUEST, reason),
                    }
                }
                (Code::POST, [name, "check"]) if *name == self.module.name() => {
                    let limit = self.conn.peer_limit().unwrap_or(LIMIT);
                    match text.and_then(|part| answer(Asked::Check(part))) {
                        Ok(changes) => (Code::CONTENT, cut(changes, limit)),
                        Err(reason) => (Code::BAD_REQUEST, cut(reason, limit)),
                    }
                }
                _ => (Code::NOT_FOUND, String::new()),
            };
            reply(&mut self.conn, &message.token, code, &text);
        }
        busy |= self.conn.take_more();
        busy |= self.conn.pump().unwrap_or(false);
        Ok(Progress::busy(busy))
    }
}

/// `text` cut to fit a message confd takes (`limit` bytes, less room for the
/// header), saying how much was left out.
fn cut(mut text: String, limit: usize) -> String {
    let room = limit.saturating_sub(1_024);
    if text.len() <= room {
        return text;
    }
    let mut at = room.saturating_sub(64);
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    let left = text.len() - at;
    text.truncate(at);
    text.push_str(&format!("\n(cut: {left} more bytes)\n"));
    text
}

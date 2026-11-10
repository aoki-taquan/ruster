//! The socket where each process takes its part of the configuration
//! (`docs/design/router-box.md`, "設定の三段").
//!
//! A process (such as `ruster-unbound`) connects to `confd/part.sock`, names the one
//! module it is responsible for, and from then on confd puts that module's part to it,
//! in the lock form, and the process answers whether it took it:
//!
//! | From | Request | Answer |
//! |---|---|---|
//! | process | POST `<module>`, no payload | 2.04 Changed; 4.04 Not Found for a module confd does not know; 4.00 Bad Request for a second module on one connection |
//! | confd | PUT `<module>`, the part as TOML text | 2.04 Changed when the process took it; any other code refuses it, with the reason as text |
//!
//! confd puts the part right after the 2.04, and again whenever a new configuration
//! changes it. A part is the whole of the module, so each PUT replaces the last one.
//! A refusal is handled like one from the FE, ribd or neighd: if it is for a new
//! configuration from `ruster apply`, confd puts the configuration before back
//! ([`crate::apply`]), which for the refusing process is the part it already holds.
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
//! | `dns` | `ruster-unbound` | [`ruster_config::dns_part`] |
//! | `dhcp` | `ruster-kea` | [`ruster_config::dhcp_part`] |
//!
//! [`Client`] is the process's side.
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

/// At most this many connections that have not named a module yet.
pub const MAX_UNNAMED: usize = 8;

/// At most this many messages are handled per connection in one step.
const MESSAGES_PER_STEP: usize = 16;

/// A part of the configuration that one process takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Module {
    Dns,
    Dhcp,
}

impl Module {
    pub const ALL: [Module; 2] = [Module::Dns, Module::Dhcp];

    pub fn name(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Dhcp => "dhcp",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == name)
    }

    /// The module's part of `config`.
    pub fn part(self, config: &Config) -> String {
        match self {
            Self::Dns => ruster_config::dns_part(config.dns.as_ref()),
            Self::Dhcp => ruster_config::dhcp_part(&config.dhcp),
        }
    }

    /// Whether `config` has anything for the module.
    pub fn configured(self, config: &Config) -> bool {
        match self {
            Self::Dns => config.dns.is_some(),
            Self::Dhcp => !config.dhcp.is_empty(),
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
}

impl Taker {
    /// The part it will hold once every PUT in flight is taken.
    fn expected(&self) -> Option<&String> {
        self.in_flight
            .last()
            .map(|(_, _, part)| part)
            .or(self.held.as_ref())
    }

    fn put(&mut self, module: Module, part: String, generation: u64) {
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
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
}

/// confd's side: the connections, and the process holding each module.
#[derive(Default)]
pub(crate) struct Parts {
    unnamed: Vec<Connection>,
    takers: BTreeMap<Module, Taker>,
}

/// A process refused a part: the module, its reason, and the generation of the part.
pub(crate) type Refusal = (Module, String, u64);

impl Parts {
    pub(crate) fn attach(&mut self, stream: UnixStream) -> io::Result<()> {
        if self.unnamed.len() >= MAX_UNNAMED {
            return Err(io::Error::other("too many connections"));
        }
        self.unnamed.push(Connection::new(stream, LIMIT)?);
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
            let conn = &mut self.unnamed[index];
            busy |= conn.pump().unwrap_or(false);
            let mut module = None;
            if conn.backlog() >= conn.limit() {
                conn.close();
            } else if let Ok(Some(request)) = conn.next_message() {
                busy = true;
                module = name(conn, &request);
            }
            busy |= conn.pump().unwrap_or(false);
            if let Some(module) = module {
                named.push((module, self.unnamed.swap_remove(index)));
            } else if self.unnamed[index].is_closed() {
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
            };
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
                    answer(
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
        }
        (Progress::busy(busy), refusals)
    }
}

/// Answers a connection's first request; the module it names, if it is one.
fn name(conn: &mut Connection, request: &Incoming) -> Option<Module> {
    let path: Vec<&str> = request.path.iter().map(String::as_str).collect();
    let module = match (request.code, path.as_slice()) {
        (Code::POST, [name]) => Module::from_name(name),
        (code, _) if code.class() != 0 => return None,
        _ => None,
    };
    match module {
        Some(_) => answer(conn, &request.token, Code::CHANGED, ""),
        None => answer(conn, &request.token, Code::NOT_FOUND, "no such module"),
    }
    module
}

fn answer(conn: &mut Connection, token: &[u8], code: Code, text: &str) {
    let _ = conn.send(&Outgoing {
        code: Some(code),
        token,
        payload: text.as_bytes(),
        ..Outgoing::default()
    });
}

/// The process's side: names its module, then takes each part confd puts.
#[derive(Debug)]
pub struct Client {
    conn: Connection,
    module: Module,
    named: bool,
}

impl Client {
    /// Takes over a connection to `confd/part.sock` and names `module`.
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

    /// Hands each part confd put to `take` and answers with what it returns: `Ok`
    /// takes the part, `Err` refuses it with the reason. An error from confd to the
    /// module's name is returned.
    pub fn poll(
        &mut self,
        take: &mut dyn FnMut(&str) -> Result<(), String>,
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
            let (code, text) = match (message.code, path.as_slice()) {
                (Code::PUT, [name]) if *name == self.module.name() => {
                    match std::str::from_utf8(&message.payload)
                        .map_err(|_| "the part is not UTF-8".to_owned())
                        .and_then(&mut *take)
                    {
                        Ok(()) => (Code::CHANGED, String::new()),
                        Err(reason) => (Code::BAD_REQUEST, reason),
                    }
                }
                _ => (Code::NOT_FOUND, String::new()),
            };
            answer(&mut self.conn, &message.token, code, &text);
        }
        busy |= self.conn.take_more();
        busy |= self.conn.pump().unwrap_or(false);
        Ok(Progress::busy(busy))
    }
}

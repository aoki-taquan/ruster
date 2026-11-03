//! Machine-readable output of `ruster run` (`--log-format json`, OPS-LOG).
//!
//! The default (`text`) output is unchanged. With `json` every line the
//! run writes becomes one JSON object per line (JSON Lines), on the same
//! stream: events on stderr, stats blocks on stdout. The translation
//! happens in [`JsonLines`], a `Write` adapter over the stream that the
//! output writer threads own ([`super::output::ColdOutput`]), so the
//! router thread formats and queues exactly the text it always did and
//! does nothing more per line; the bounded queues and the dropped-output
//! counter (`output.dropped`) are the same in both formats. Lines written
//! before those threads exist (a config that does not load, a failed
//! startup step) go through the same adapter on the main thread.
//!
//! # Schema `ruster-run-log/v1`
//!
//! Every object has, in this order:
//!
//! | key | type | meaning |
//! |---|---|---|
//! | `schema` | string | always `ruster-run-log/v1` |
//! | `ts` | string | UTC wall clock when the writer thread wrote the line, RFC 3339 with milliseconds (`2026-11-03T12:34:56.789Z`) |
//! | `level` | string | `info`, `warn`, or `error` |
//! | `event` | string | a stable code ([`EVENTS`]); `STATS` for a stats block, `UNCLASSIFIED` for a line no rule matches (a bug: every line the run writes has a code) |
//! | `msg` | string | the text line, without the `ruster run: ` prefix |
//! | `fields` | object | every `key=value` token of `msg`: a whole number is a JSON number, `true`/`false` a boolean, anything else a string; in a `;`-separated clause that starts with one bare word (`flushed`, `carried`, `state`, `drain`) the keys get that word and a dot as prefix; the first of two equal keys wins. Health and check warnings also get `code` (the condition) |
//! | `truncated` | boolean | only when `msg` was cut at [`MAX_MSG_BYTES`] or a stats block at [`MAX_BLOCK_LINES`] |
//! | `stats` | object | `STATS` only: every `section.key=value` line of the block (key exactly as in the text block, `none` as `null`) |
//!
//! Strings are escaped per RFC 8259 and the output is pure ASCII: `"`,
//! `\`, every control character, DEL, and every non-ASCII character are
//! escaped (`\uXXXX`, surrogate pairs above the BMP), invalid UTF-8
//! becomes U+FFFD. A value can therefore never end the line or forge
//! another event (log injection). The messages are value-free by design
//! anyway: interface ids, codes, counts, and fixed names; no device name,
//! address, or path from the config or the command line (the one directory
//! named, in `FS_CONFINE_WARNING`, is one of the fixed
//! [`super::fs_confine::BROAD_DIRECTORIES`], a `&'static str` by type).
//!
//! Numbers are unsigned 64-bit counters written exactly; a consumer that
//! parses JSON numbers as IEEE doubles (JavaScript, `jq` before 1.7) loses
//! precision above 2^53 (a counter that large takes years at line rate).

use std::collections::HashSet;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// The `schema` value of every object.
pub const SCHEMA: &str = "ruster-run-log/v1";
/// Longest `msg` in bytes; longer lines are cut (`truncated`).
pub const MAX_MSG_BYTES: usize = 16 * 1024;
/// Most lines of one stats block; the rest of the block is dropped
/// (`truncated`).
pub const MAX_BLOCK_LINES: usize = 64 * 1024;

/// `--log-format`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LogFormat {
    /// The human-readable lines (the default, unchanged).
    #[default]
    Text,
    /// One JSON object per line ([`SCHEMA`]).
    Json,
}

impl LogFormat {
    /// Parses an option value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// Severity of an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// How a rule matches the message (after the `ruster run: ` prefix).
#[derive(Clone, Copy, Debug)]
enum Match {
    Prefix(&'static str),
    /// A prefix and a substring after it.
    PrefixWith(&'static str, &'static str),
    Suffix(&'static str),
}

/// One classification rule: the first that matches names the event.
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    matches: Match,
    /// The `event` code.
    pub code: &'static str,
    level: Level,
    /// The level when the message starts with this text instead (a
    /// shutdown by signal is `info`, any other `error`).
    calm: Option<&'static str>,
    /// A SCREAMING_SNAKE token of the message becomes `fields.code`.
    condition: bool,
}

const fn rule(matches: Match, code: &'static str, level: Level) -> Rule {
    Rule {
        matches,
        code,
        level,
        calm: None,
        condition: false,
    }
}

const fn with_condition(mut rule: Rule) -> Rule {
    rule.condition = true;
    rule
}

const fn calm_when(mut rule: Rule, prefix: &'static str) -> Rule {
    rule.calm = Some(prefix);
    rule
}

use Level::{Error, Info, Warn};
use Match::{Prefix, PrefixWith, Suffix};

/// Every event code with the messages it covers, first match wins. The
/// codes are stable: new messages get new codes, existing ones keep
/// theirs.
pub static EVENTS: &[Rule] = &[
    rule(Prefix("running generation "), "READY", Info),
    rule(Prefix("reload requested"), "RELOAD_REQUESTED", Info),
    rule(Prefix("reload checked:"), "RELOAD_CHECKED", Info),
    rule(Prefix("reload applied:"), "RELOAD_APPLIED", Info),
    rule(Prefix("reload refused:"), "RELOAD_REFUSED", Warn),
    rule(Prefix("reload failed:"), "RELOAD_FAILED", Warn),
    rule(
        Prefix("watch settings applied:"),
        "WATCH_SETTINGS_APPLIED",
        Info,
    ),
    with_condition(rule(
        PrefixWith("warning: port=", " health="),
        "HEALTH_WARNING",
        Warn,
    )),
    with_condition(rule(Prefix("recovered: port="), "HEALTH_RECOVERED", Info)),
    with_condition(rule(Prefix("fatal: port="), "HEALTH_FATAL", Error)),
    with_condition(rule(Prefix("warning: port="), "CHECK_WARNING", Warn)),
    with_condition(rule(
        Prefix("warning: RESOLUTION_SWEEP_SLOW"),
        "SWEEP_SLOW",
        Warn,
    )),
    with_condition(rule(
        Prefix("warning: FRAGMENT_INGRESS_SHARE_OVERCOMMITTED"),
        "FRAGMENT_SHARE_OVERCOMMITTED",
        Warn,
    )),
    rule(
        Prefix("warning: reload preparation running"),
        "RELOAD_PREPARE_SLOW",
        Warn,
    ),
    rule(
        Prefix("warning: idle poll failed"),
        "IDLE_POLL_FAILED",
        Warn,
    ),
    rule(
        PrefixWith("warning: the ", " thread did not end"),
        "WORKER_ABANDONED",
        Warn,
    ),
    rule(Prefix("warning: kernel "), "KERNEL_EXPOSURE_AT_EXIT", Warn),
    rule(Prefix("warning: privileges kept"), "PRIVILEGES_KEPT", Warn),
    rule(Prefix("privileges dropped:"), "PRIVILEGES_DROPPED", Info),
    rule(Prefix("filesystem confined:"), "FS_CONFINED", Info),
    rule(Prefix("warning: fs-confine=off"), "FS_CONFINE_OFF", Warn),
    rule(
        Prefix("warning: fs-confine code="),
        "FS_CONFINE_WARNING",
        Warn,
    ),
    rule(
        Prefix("seccomp filter installed:"),
        "SECCOMP_INSTALLED",
        Info,
    ),
    rule(Prefix("warning: seccomp=log"), "SECCOMP_LOG", Warn),
    rule(Prefix("warning: seccomp=off"), "SECCOMP_OFF", Warn),
    rule(
        PrefixWith("warning: --", " is overridden by "),
        "FLAG_OVERRIDDEN",
        Warn,
    ),
    rule(Prefix("startup attempt "), "STARTUP_RETRY", Warn),
    rule(
        Prefix("startup cancelled by signal"),
        "STARTUP_CANCELLED",
        Info,
    ),
    rule(Prefix("startup failed:"), "STARTUP_FAILED", Error),
    rule(Prefix("run as root or grant "), "STARTUP_HINT", Info),
    rule(Prefix("--user/--group also need"), "STARTUP_HINT", Info),
    rule(Prefix("before Linux 6.5 "), "STARTUP_HINT", Info),
    rule(Prefix("--fs-confine landlock needs"), "STARTUP_HINT", Info),
    rule(
        Prefix("the Landlock calls were refused"),
        "STARTUP_HINT",
        Info,
    ),
    rule(Prefix("the config's directory is /"), "STARTUP_HINT", Info),
    rule(Prefix("cannot install "), "SIGNAL_INSTALL_FAILED", Error),
    rule(
        Prefix("cannot start the output thread"),
        "OUTPUT_THREAD_FAILED",
        Error,
    ),
    rule(
        Prefix("unsupported platform"),
        "UNSUPPORTED_PLATFORM",
        Error,
    ),
    rule(Prefix("invalid config:"), "CONFIG_INVALID", Error),
    rule(Prefix("cannot read config:"), "CONFIG_UNREADABLE", Error),
    rule(Prefix("refused config:"), "CONFIG_REFUSED", Error),
    calm_when(
        rule(Suffix("; draining"), "SHUTDOWN_DRAINING", Error),
        "stop requested",
    ),
    rule(Prefix("drain failed:"), "DRAIN_FAILED", Error),
    rule(Prefix("close failed:"), "CLOSE_FAILED", Error),
    calm_when(
        rule(Prefix("stopped "), "SHUTDOWN_SUMMARY", Error),
        "stopped by signal",
    ),
    rule(Prefix("warning: "), "WARNING", Warn),
];

/// The `event` of a line no rule matches.
pub const UNCLASSIFIED: &str = "UNCLASSIFIED";

/// The prefixes the run's lines start with.
const PREFIXES: [&str; 2] = ["ruster run: ", "ruster: "];

/// The event code and level of one text line (without its newline).
pub fn classify(line: &str) -> (&'static str, Level, Option<&'static Rule>) {
    let Some(body) = PREFIXES.iter().find_map(|prefix| line.strip_prefix(prefix)) else {
        return (UNCLASSIFIED, Level::Info, None);
    };
    for rule in EVENTS {
        let hit = match rule.matches {
            Prefix(prefix) => body.starts_with(prefix),
            PrefixWith(prefix, inner) => body
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.contains(inner)),
            Suffix(suffix) => body.ends_with(suffix),
        };
        if hit {
            let level = match rule.calm {
                Some(calm) if body.starts_with(calm) => Level::Info,
                _ => rule.level,
            };
            return (rule.code, level, Some(rule));
        }
    }
    (UNCLASSIFIED, Level::Info, None)
}

/// Appends `text` as a JSON string (with quotes), pure ASCII.
pub fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(character),
            other => {
                let mut units = [0_u16; 2];
                for unit in other.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// A typed JSON value of one `key=value` token.
fn push_value(out: &mut String, value: &str, none_is_null: bool) {
    let number = !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value.parse::<u64>().is_ok();
    if number || value == "true" || value == "false" {
        out.push_str(value);
    } else if none_is_null && value == "none" {
        out.push_str("null");
    } else {
        push_json_string(out, value);
    }
}

fn is_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn is_word(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_lowercase())
}

/// A SCREAMING_SNAKE condition token (`TX_STALL`, `MULTI_QUEUE_ALLOWED`).
fn is_condition(token: &str) -> bool {
    token.len() >= 3
        && token.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The `fields` object of a message (see the module documentation).
fn push_fields(out: &mut String, body: &str, condition: bool) {
    let mut keys: Vec<String> = Vec::new();
    let mut pairs: Vec<(String, &str)> = Vec::new();
    let mut code = None;
    for clause in body.split(';') {
        let tokens: Vec<&str> = clause.split_whitespace().collect();
        let prefix = match tokens.as_slice() {
            [word, next, ..] if is_word(word) && next.contains('=') => Some(*word),
            _ => None,
        };
        for token in &tokens {
            let token = token.trim_end_matches([',', ':', ')']);
            let Some((key, value)) = token.split_once('=') else {
                if condition && code.is_none() && is_condition(token) {
                    code = Some(token);
                }
                continue;
            };
            if !is_key(key) {
                continue;
            }
            let key = match prefix {
                Some(word) => format!("{word}.{key}"),
                None => key.to_owned(),
            };
            if keys.contains(&key) {
                continue;
            }
            if condition && code.is_none() && key == "health" && is_condition(value) {
                code = Some(value);
            }
            keys.push(key.clone());
            pairs.push((key, value));
        }
    }
    out.push('{');
    let mut first = true;
    let mut separator = |out: &mut String| {
        if !std::mem::take(&mut first) {
            out.push(',');
        }
    };
    if let Some(code) = code.filter(|_| !keys.iter().any(|key| key == "code")) {
        separator(out);
        out.push_str("\"code\":");
        push_json_string(out, code);
    }
    for (key, value) in pairs {
        separator(out);
        push_json_string(out, &key);
        out.push(':');
        push_value(out, value, false);
    }
    out.push('}');
}

/// RFC 3339 UTC with milliseconds of `millis` since the Unix epoch.
pub fn rfc3339(millis: u64) -> String {
    let days = millis / 86_400_000;
    let rest = millis % 86_400_000;
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = i64::try_from(days).unwrap_or(i64::MAX / 2) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3_600_000,
        rest / 60_000 % 60,
        rest / 1_000 % 60,
        rest % 1_000
    )
}

/// The wall clock in milliseconds since the Unix epoch (0 before it).
pub fn wall_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

fn head(out: &mut String, millis: u64, level: Level, event: &str) {
    out.push_str("{\"schema\":\"");
    out.push_str(SCHEMA);
    out.push_str("\",\"ts\":\"");
    out.push_str(&rfc3339(millis));
    out.push_str("\",\"level\":\"");
    out.push_str(level.label());
    out.push_str("\",\"event\":");
    push_json_string(out, event);
}

/// Cuts `text` to at most `max` bytes at a character boundary.
fn cut(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// The JSON object of one event line (without the newline).
pub fn event_object(line: &str, millis: u64) -> String {
    let (line, truncated) = cut(line, MAX_MSG_BYTES);
    let (event, level, rule) = classify(line);
    let body = PREFIXES
        .iter()
        .find_map(|prefix| line.strip_prefix(prefix))
        .unwrap_or(line);
    let mut out = String::with_capacity(body.len() * 2 + 128);
    head(&mut out, millis, level, event);
    out.push_str(",\"msg\":");
    push_json_string(&mut out, body);
    out.push_str(",\"fields\":");
    push_fields(&mut out, body, rule.is_some_and(|rule| rule.condition));
    if truncated {
        out.push_str(",\"truncated\":true");
    }
    out.push('}');
    out
}

/// The JSON object of one stats block: its header line and its
/// `section.key=value` lines (without `end`).
pub fn stats_object(header: &str, lines: &[String], truncated: bool, millis: u64) -> String {
    let mut out = String::with_capacity(lines.len() * 48 + 256);
    head(&mut out, millis, Level::Info, "STATS");
    out.push_str(",\"msg\":");
    push_json_string(&mut out, header);
    out.push_str(",\"fields\":");
    push_fields(&mut out, header, false);
    if truncated {
        out.push_str(",\"truncated\":true");
    }
    out.push_str(",\"stats\":{");
    // Linear in the block (a 256-port block has about 28k lines): the keys
    // are unique by construction, the set only keeps a duplicate from
    // making invalid JSON.
    let mut seen: HashSet<&str> = HashSet::with_capacity(lines.len());
    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !is_key(key) || seen.contains(key) {
            continue;
        }
        if !seen.is_empty() {
            out.push(',');
        }
        seen.insert(key);
        push_json_string(&mut out, key);
        out.push(':');
        push_value(&mut out, value, true);
    }
    out.push_str("}}");
    out
}

/// The header of a stats block.
const STATS_HEADER: &str = "ruster-run-stats ";

/// A stats block being collected.
struct Block {
    header: String,
    lines: Vec<String>,
    truncated: bool,
}

/// A `Write` adapter that turns the run's text lines into JSON lines
/// (module documentation). Complete lines are translated as they arrive;
/// `flush` also translates a partial last line. A stats block (header to
/// `end`) becomes one object.
pub struct JsonLines<W: Write> {
    inner: W,
    pending: Vec<u8>,
    block: Option<Block>,
    clock: fn() -> u64,
}

impl<W: Write> JsonLines<W> {
    pub fn new(inner: W) -> Self {
        Self::with_clock(inner, wall_millis)
    }

    /// With a fixed clock (tests).
    pub fn with_clock(inner: W, clock: fn() -> u64) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            block: None,
            clock,
        }
    }

    /// The inner writer (tests).
    #[cfg(test)]
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// The inner writer, borrowed (tests).
    #[cfg(test)]
    pub fn inner_ref(&self) -> &W {
        &self.inner
    }

    fn emit(&mut self, object: &str) -> io::Result<()> {
        let mut line = Vec::with_capacity(object.len() + 1);
        line.extend_from_slice(object.as_bytes());
        line.push(b'\n');
        self.inner.write_all(&line)
    }

    fn line(&mut self, bytes: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(bytes);
        let text = text.strip_suffix('\r').unwrap_or(&text);
        if let Some(block) = self.block.as_mut() {
            if text == "end" {
                let block = self.block.take().expect("collecting");
                let object =
                    stats_object(&block.header, &block.lines, block.truncated, (self.clock)());
                return self.emit(&object);
            }
            if !text.starts_with(STATS_HEADER) {
                if block.lines.len() < MAX_BLOCK_LINES {
                    block.lines.push(text.to_owned());
                } else {
                    block.truncated = true;
                }
                return Ok(());
            }
            // A new header before `end`: the previous block was cut.
            let block = self.block.take().expect("collecting");
            let object = stats_object(&block.header, &block.lines, true, (self.clock)());
            self.emit(&object)?;
        }
        if text.starts_with(STATS_HEADER) {
            self.block = Some(Block {
                header: text.to_owned(),
                lines: Vec::new(),
                truncated: false,
            });
            return Ok(());
        }
        if text.is_empty() {
            return Ok(());
        }
        let object = event_object(text, (self.clock)());
        self.emit(&object)
    }
}

impl<W: Write> Write for JsonLines<W> {
    /// Linear in the bytes written: one scan with a cursor over the
    /// pending bytes, one drain of the translated lines at the end.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        let pending = std::mem::take(&mut self.pending);
        let mut start = 0;
        let mut result = Ok(());
        while let Some(end) = pending[start..].iter().position(|byte| *byte == b'\n') {
            let line = &pending[start..start + end];
            start += end + 1;
            if let Err(error) = self.line(line) {
                result = Err(error);
                break;
            }
        }
        self.pending = pending;
        self.pending.drain(..start);
        result?;
        // A runaway partial line is translated in pieces (bounded).
        if self.pending.len() > MAX_MSG_BYTES {
            let line = std::mem::take(&mut self.pending);
            self.line(&line)?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.line(&line)?;
        }
        self.inner.flush()
    }
}

/// The text or JSON form of one output stream.
pub enum Sink<W: Write> {
    Text(W),
    Json(JsonLines<W>),
}

impl<W: Write> Sink<W> {
    pub fn new(inner: W, format: LogFormat) -> Self {
        match format {
            LogFormat::Text => Self::Text(inner),
            LogFormat::Json => Self::Json(JsonLines::new(inner)),
        }
    }
}

impl<W: Write> Write for Sink<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Text(inner) => inner.write(bytes),
            Self::Json(json) => json.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Text(inner) => inner.flush(),
            Self::Json(json) => json.flush(),
        }
    }
}

#[cfg(test)]
#[path = "log_tests.rs"]
pub mod tests;

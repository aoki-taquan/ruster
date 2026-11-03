//! `--log-format json` (OPS-LOG): schema, escaping, every event code, and
//! the stats object, checked with a small strict JSON parser.

use std::io::Write;

use super::*;

/// A parsed JSON value (tests only).
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// The number's text.
    Number(String),
    String(String),
    Array(Vec<Json>),
    /// Members in order; a duplicate key is a parse error.
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Self::String(text)) => Some(text),
            _ => None,
        }
    }

    pub fn keys(&self) -> Vec<&str> {
        match self {
            Self::Object(members) => members.iter().map(|(name, _)| name.as_str()).collect(),
            _ => Vec::new(),
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at {}", byte as char, self.at))
        }
    }

    fn literal(&mut self, text: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.at..].starts_with(text.as_bytes()) {
            self.at += text.len();
            Ok(value)
        } else {
            Err(format!("bad literal at {}", self.at))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_space();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::String),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(format!("unexpected byte at {}", self.at)),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut members: Vec<(String, Json)> = Vec::new();
        let mut names = std::collections::HashSet::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_space();
            let key = self.string()?;
            if !names.insert(key.clone()) {
                return Err(format!("duplicate key {key:?}"));
            }
            self.skip_space();
            self.expect(b':')?;
            let value = self.value()?;
            members.push((key, value));
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(members));
                }
                _ => return Err(format!("bad object at {}", self.at)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(format!("bad array at {}", self.at)),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .ok_or("short \\u escape")?;
        let value = u32::from_str_radix(digits, 16).map_err(|_| "bad \\u escape")?;
        self.at += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut text = String::new();
        loop {
            let byte = self.peek().ok_or("unterminated string")?;
            self.at += 1;
            match byte {
                b'"' => return Ok(text),
                b'\\' => {
                    let escape = self.peek().ok_or("bad escape")?;
                    self.at += 1;
                    match escape {
                        b'"' => text.push('"'),
                        b'\\' => text.push('\\'),
                        b'/' => text.push('/'),
                        b'b' => text.push('\u{8}'),
                        b'f' => text.push('\u{c}'),
                        b'n' => text.push('\n'),
                        b'r' => text.push('\r'),
                        b't' => text.push('\t'),
                        b'u' => {
                            let high = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&high) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let low = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err("lone surrogate".into());
                                }
                                0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                            } else {
                                high
                            };
                            text.push(char::from_u32(code).ok_or("bad code point")?);
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                0..=0x1f => return Err(format!("raw control byte at {}", self.at - 1)),
                0x20..=0x7f => text.push(char::from(byte)),
                _ => {
                    // Copy one UTF-8 character (at most 4 bytes; checking
                    // the whole rest would make the parser quadratic).
                    let start = self.at - 1;
                    let end = (start + 4).min(self.bytes.len());
                    let rest = match std::str::from_utf8(&self.bytes[start..end]) {
                        Ok(rest) => rest,
                        Err(error) if error.valid_up_to() > 0 => {
                            std::str::from_utf8(&self.bytes[start..start + error.valid_up_to()])
                                .map_err(|_| "invalid UTF-8")?
                        }
                        Err(_) => return Err("invalid UTF-8".into()),
                    };
                    let character = rest.chars().next().ok_or("empty")?;
                    self.at = start + character.len_utf8();
                    text.push(character);
                }
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let digits = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        if self.at == digits || (self.bytes[digits] == b'0' && self.at - digits > 1) {
            return Err(format!("bad number at {start}"));
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        Ok(Json::Number(
            String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned(),
        ))
    }
}

/// Parses one complete JSON text strictly (RFC 8259; duplicate keys
/// refused).
pub fn parse_json(text: &str) -> Result<Json, String> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = parser.value()?;
    parser.skip_space();
    if parser.at != text.len() {
        return Err(format!("trailing bytes at {}", parser.at));
    }
    Ok(value)
}

/// Parses every line of JSON Lines output and checks the common schema.
pub fn parse_lines(bytes: &[u8]) -> Vec<Json> {
    let text = std::str::from_utf8(bytes).expect("utf-8");
    assert!(text.is_ascii(), "non-ASCII output: {text}");
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "unterminated: {text}"
    );
    text.lines()
        .map(|line| {
            let object = parse_json(line).unwrap_or_else(|error| panic!("{error}: {line}"));
            let keys = object.keys();
            assert_eq!(
                keys[..6],
                ["schema", "ts", "level", "event", "msg", "fields"],
                "{line}"
            );
            assert_eq!(object.str("schema"), Some(SCHEMA));
            let ts = object.str("ts").expect("ts");
            assert_eq!(ts.len(), 24, "{ts}");
            assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T', "{ts}");
            assert!(matches!(
                object.str("level"),
                Some("info" | "warn" | "error")
            ));
            assert!(matches!(object.get("fields"), Some(Json::Object(_))));
            object
        })
        .collect()
}

/// Every line of a text-mode stderr has an event code, and its JSON form
/// parses (the coverage hook of the `ruster run` tests: every message the
/// run writes in any test is classified).
pub fn assert_classified(text: &str) {
    for line in text.lines() {
        let (code, _, _) = classify(line);
        assert_ne!(code, UNCLASSIFIED, "no event code for {line:?}");
        let object = event_object(line, 0);
        parse_json(&object).unwrap_or_else(|error| panic!("{error}: {object}"));
    }
}

/// Every stats block of a text-mode stdout becomes one valid `STATS`
/// object.
pub fn assert_stats_translate(text: &str) {
    let mut json = JsonLines::with_clock(Vec::new(), || 0);
    json.write_all(text.as_bytes()).expect("vec");
    json.flush().expect("vec");
    let blocks = text.matches("ruster-run-stats ").count();
    let objects = parse_lines(&json.into_inner());
    assert_eq!(objects.len(), blocks, "{text}");
    for object in &objects {
        assert_eq!(object.str("event"), Some("STATS"));
        assert!(object.get("truncated").is_none());
        assert!(matches!(object.get("stats"), Some(Json::Object(_))));
    }
}

fn translate(text: &str) -> Vec<Json> {
    let mut json = JsonLines::with_clock(Vec::new(), || 1_793_708_096_789);
    json.write_all(text.as_bytes()).expect("vec");
    json.flush().expect("vec");
    parse_lines(&json.into_inner())
}

/// One sample line per rule of [`EVENTS`], with its code and level.
const SAMPLES: &[(&str, &str, &str)] = &[
    (
        "ruster run: running generation 1 on 2 port(s); send SIGINT or SIGTERM to stop, SIGHUP to reload",
        "READY",
        "info",
    ),
    ("ruster run: reload requested (generation 1)", "RELOAD_REQUESTED", "info"),
    (
        "ruster run: reload checked: generation 1 keeps running until the switch; would carry dynamic-neighbors=0 nat44-udp-mappings=0 nat44-tcp-sessions=0 nat44-icmp-mappings=0 firewall-flows<=7",
        "RELOAD_CHECKED",
        "info",
    ),
    (
        "ruster run: reload applied: generation=2 previous=1; interfaces=2 addresses=2 routes=3 neighbors=1 firewall-rules=3 nat44-ports=16; flushed dynamic-neighbors=0 resolution-states=0 nat44-udp-mappings=0 nat44-tcp-sessions=0 firewall-flows=0; carried dynamic-neighbors=4 nat44-udp-mappings=1 nat44-tcp-sessions=0 nat44-icmp-mappings=0 firewall-flows=2 firewall-revoked=0; state arp=carried nat44-udp=carried nat44-tcp=carried nat44-icmp=none firewall=carried",
        "RELOAD_APPLIED",
        "info",
    ),
    (
        "ruster run: reload refused: code=RESTART_REQUIRED reasons=BACKEND,INTERFACES; generation 1 keeps running",
        "RELOAD_REFUSED",
        "warn",
    ),
    (
        "ruster run: reload failed: stage=validate code=UNKNOWN_FIELD path=health; generation 1 keeps running",
        "RELOAD_FAILED",
        "warn",
    ),
    (
        "ruster run: watch settings applied: tx-stall-warn-ms=1000 tx-stall-fatal-ms=0",
        "WATCH_SETTINGS_APPLIED",
        "info",
    ),
    ("ruster run: warning: port=if2 health=TX_STALL", "HEALTH_WARNING", "warn"),
    ("ruster run: recovered: port=if2 health=TX_STALL", "HEALTH_RECOVERED", "info"),
    ("ruster run: fatal: port=if2 health=FRAMES_QUARANTINED", "HEALTH_FATAL", "error"),
    (
        "ruster run: warning: port=if1 MULTI_QUEUE_ALLOWED rx-queues=4",
        "CHECK_WARNING",
        "warn",
    ),
    (
        "ruster run: warning: RESOLUTION_SWEEP_SLOW table=states ticks=2048",
        "SWEEP_SLOW",
        "warn",
    ),
    (
        "ruster run: warning: FRAGMENT_INGRESS_SHARE_OVERCOMMITTED share-percent=50 interfaces=3",
        "FRAGMENT_SHARE_OVERCOMMITTED",
        "warn",
    ),
    (
        "ruster run: warning: reload preparation running for 10 s; later SIGHUPs are held",
        "RELOAD_PREPARE_SLOW",
        "warn",
    ),
    (
        "ruster run: warning: idle poll failed code=ERRNO_22; sleeping at most 1 ms between idle ticks instead",
        "IDLE_POLL_FAILED",
        "warn",
    ),
    (
        "ruster run: warning: the link watcher thread did not end within 500 ms after the loop; abandoned",
        "WORKER_ABANDONED",
        "warn",
    ),
    (
        "ruster run: warning: kernel forwarding is enabled; detached ports may be forwarded by the kernel",
        "KERNEL_EXPOSURE_AT_EXIT",
        "warn",
    ),
    (
        "ruster run: warning: privileges kept (--keep-privileges): every capability stays for the whole run",
        "PRIVILEGES_KEPT",
        "warn",
    ),
    (
        "ruster run: privileges dropped: threads=4 capabilities=none bounding-set=cleared no-new-privs=1 identity=unchanged",
        "PRIVILEGES_DROPPED",
        "info",
    ),
    (
        "ruster run: filesystem confined: mode=landlock abi=5 rules=4 threads=5",
        "FS_CONFINED",
        "info",
    ),
    (
        "ruster run: warning: fs-confine=off (--fs-confine off): no filesystem confinement",
        "FS_CONFINE_OFF",
        "warn",
    ),
    (
        "ruster run: warning: fs-confine code=CONFIG_DIRECTORY_BROAD directory=/etc: every file",
        "FS_CONFINE_WARNING",
        "warn",
    ),
    (
        "ruster run: seccomp filter installed: mode=kill threads=5 syscalls=60 arch=x86_64",
        "SECCOMP_INSTALLED",
        "info",
    ),
    (
        "ruster run: warning: seccomp=log (--seccomp log): a syscall outside the allowlist is logged by the kernel and allowed",
        "SECCOMP_LOG",
        "warn",
    ),
    (
        "ruster run: warning: seccomp=off (--seccomp off): no syscall filter",
        "SECCOMP_OFF",
        "warn",
    ),
    (
        "ruster run: warning: --tx-stall-warn-secs is overridden by [health] tx-stall-warn-ms of the config",
        "FLAG_OVERRIDDEN",
        "warn",
    ),
    (
        "ruster run: startup attempt 1 of 3 failed: stage=open port=if2 code=BIND/BUSY; rolled back 1 port(s), retrying in 250 ms",
        "STARTUP_RETRY",
        "warn",
    ),
    (
        "ruster run: startup cancelled by signal; rolled back 2 port(s)",
        "STARTUP_CANCELLED",
        "info",
    ),
    (
        "ruster run: startup failed: stage=checks port=if1 code=MULTI_QUEUE_DEVICE rx-queues=4",
        "STARTUP_FAILED",
        "error",
    ),
    (
        "ruster run: run as root or grant CAP_NET_RAW",
        "STARTUP_HINT",
        "info",
    ),
    (
        "ruster run: --user/--group also need CAP_SETUID and CAP_SETGID at startup",
        "STARTUP_HINT",
        "info",
    ),
    (
        "ruster run: before Linux 6.5 with kernel.unprivileged_bpf_disabled set, detaching needs CAP_BPF",
        "STARTUP_HINT",
        "info",
    ),
    (
        "ruster run: --fs-confine landlock needs Landlock (Linux 5.13 or newer)",
        "STARTUP_HINT",
        "info",
    ),
    (
        "ruster run: the Landlock calls were refused (EPERM)",
        "STARTUP_HINT",
        "info",
    ),
    (
        "ruster run: the config's directory is /, which would leave every file readable",
        "STARTUP_HINT",
        "info",
    ),
    (
        "ruster run: cannot install SIGHUP handler",
        "SIGNAL_INSTALL_FAILED",
        "error",
    ),
    (
        "ruster run: cannot start the output thread",
        "OUTPUT_THREAD_FAILED",
        "error",
    ),
    (
        "ruster run: unsupported platform: `ruster run` needs x86_64 Linux",
        "UNSUPPORTED_PLATFORM",
        "error",
    ),
    (
        "ruster run: invalid config: stage=backend code=SIM_BACKEND",
        "CONFIG_INVALID",
        "error",
    ),
    (
        "ruster: cannot read config: NOT_FOUND",
        "CONFIG_UNREADABLE",
        "error",
    ),
    (
        "ruster: refused config: stage=permissions code=GROUP_WRITABLE",
        "CONFIG_REFUSED",
        "error",
    ),
    (
        "ruster run: fatal health event port=if1 code=TX_STALL; draining",
        "SHUTDOWN_DRAINING",
        "error",
    ),
    ("ruster run: drain failed: code=RING", "DRAIN_FAILED", "error"),
    (
        "ruster run: close failed: port=if1 code=DETACH",
        "CLOSE_FAILED",
        "error",
    ),
    (
        "ruster run: stopped by signal; drain calls=1 completed=0 rx-released=0 tx-in-flight=0 tx-handoffs=0 fill-in-kernel=0 forced=false timed-out=false last-kick-error=none; detached and closed 2 port(s)",
        "SHUTDOWN_SUMMARY",
        "info",
    ),
    (
        "ruster run: warning: something new",
        "WARNING",
        "warn",
    ),
];

/// Every rule of [`EVENTS`] has a sample, every sample gets its code and
/// level, and the codes are stable SCREAMING_SNAKE names.
#[test]
fn every_event_code_has_a_sample_and_classifies() {
    let mut hit = vec![false; EVENTS.len()];
    for (line, code, level) in SAMPLES {
        let (event, got, rule) = classify(line);
        assert_eq!((event, got.label()), (*code, *level), "{line}");
        let index = EVENTS
            .iter()
            .position(|candidate| rule.is_some_and(|rule| std::ptr::eq(candidate, rule)))
            .expect("a rule");
        hit[index] = true;
        let object = parse_json(&event_object(line, 0)).expect("valid");
        assert_eq!(object.str("event"), Some(*code));
    }
    for (rule, hit) in EVENTS.iter().zip(&hit) {
        assert!(hit, "no sample for {}", rule.code);
        assert!(
            rule.code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_'),
            "{}",
            rule.code
        );
    }
    // Calmer variants of the shutdown lines.
    for (line, level) in [
        ("ruster run: stop requested; draining", "info"),
        (
            "ruster run: backend stopped after a fault; draining",
            "error",
        ),
        (
            "ruster run: stopped after a fatal health event port=if1 code=TX_STALL; drain calls=1",
            "error",
        ),
    ] {
        assert_eq!(classify(line).1.label(), level, "{line}");
    }
    // Lines of no known form.
    for line in ["ruster run: hello", "something else", ""] {
        assert_eq!(classify(line).0, UNCLASSIFIED);
    }
    // The code list is part of the schema: renaming one is a breaking
    // change (add a new code instead).
    let codes: Vec<&str> = EVENTS.iter().map(|rule| rule.code).collect();
    assert_eq!(
        codes.join(" "),
        "READY RELOAD_REQUESTED RELOAD_CHECKED RELOAD_APPLIED RELOAD_REFUSED RELOAD_FAILED \
         WATCH_SETTINGS_APPLIED HEALTH_WARNING HEALTH_RECOVERED HEALTH_FATAL CHECK_WARNING \
         SWEEP_SLOW FRAGMENT_SHARE_OVERCOMMITTED RELOAD_PREPARE_SLOW IDLE_POLL_FAILED \
         WORKER_ABANDONED \
         KERNEL_EXPOSURE_AT_EXIT PRIVILEGES_KEPT PRIVILEGES_DROPPED FS_CONFINED FS_CONFINE_OFF \
         FS_CONFINE_WARNING SECCOMP_INSTALLED SECCOMP_LOG SECCOMP_OFF FLAG_OVERRIDDEN \
         STARTUP_RETRY STARTUP_CANCELLED STARTUP_FAILED STARTUP_HINT STARTUP_HINT STARTUP_HINT \
         STARTUP_HINT STARTUP_HINT STARTUP_HINT SIGNAL_INSTALL_FAILED OUTPUT_THREAD_FAILED \
         UNSUPPORTED_PLATFORM CONFIG_INVALID CONFIG_UNREADABLE CONFIG_REFUSED SHUTDOWN_DRAINING \
         DRAIN_FAILED CLOSE_FAILED SHUTDOWN_SUMMARY WARNING"
    );
}

/// The object of one event: key order, typed fields, clause prefixes,
/// first-key-wins, and the health condition code.
#[test]
fn an_event_object_has_the_schema_and_typed_fields() {
    let text = format!("{}\n", SAMPLES[3].0);
    let objects = translate(&text);
    let [applied] = objects.as_slice() else {
        panic!("{objects:?}");
    };
    assert_eq!(
        applied.keys(),
        ["schema", "ts", "level", "event", "msg", "fields"]
    );
    assert_eq!(applied.str("ts"), Some("2026-11-03T12:14:56.789Z"));
    assert_eq!(
        applied.str("msg"),
        SAMPLES[3].0.strip_prefix("ruster run: ")
    );
    let fields = applied.get("fields").expect("fields");
    let number = |key: &str| match fields.get(key) {
        Some(Json::Number(text)) => text.clone(),
        other => panic!("{key}: {other:?}"),
    };
    assert_eq!(number("generation"), "2");
    assert_eq!(number("previous"), "1");
    assert_eq!(number("routes"), "3");
    assert_eq!(number("flushed.dynamic-neighbors"), "0");
    assert_eq!(number("carried.dynamic-neighbors"), "4");
    assert_eq!(fields.str("state.arp"), Some("carried"));
    assert_eq!(fields.str("state.nat44-icmp"), Some("none"));

    let objects = translate(
        "ruster run: warning: port=if2 health=TX_STALL\n\
         ruster run: stopped by signal; drain calls=1 forced=false last-kick-error=if1:NETWORK_DOWN\n\
         ruster run: reload refused: code=RESTART_REQUIRED reasons=BACKEND,INTERFACES; generation 1 keeps running\n\
         ruster run: warning: port=if1 MTU_BELOW_DEVICE mtu=9000 config=1500\n\
         ruster run: startup failed: stage=open port=if1 code=A code=B\n",
    );
    let fields: Vec<&Json> = objects
        .iter()
        .map(|object| object.get("fields").expect("fields"))
        .collect();
    assert_eq!(fields[0].str("code"), Some("TX_STALL"));
    assert_eq!(fields[0].str("port"), Some("if2"));
    assert_eq!(fields[0].str("health"), Some("TX_STALL"));
    assert_eq!(fields[1].get("drain.forced"), Some(&Json::Bool(false)));
    assert_eq!(
        fields[1].str("drain.last-kick-error"),
        Some("if1:NETWORK_DOWN")
    );
    assert_eq!(fields[2].str("reasons"), Some("BACKEND,INTERFACES"));
    assert_eq!(objects[2].str("level"), Some("warn"));
    assert_eq!(fields[3].str("code"), Some("MTU_BELOW_DEVICE"));
    assert_eq!(fields[3].get("mtu"), Some(&Json::Number("9000".into())));
    // The first of two equal keys wins.
    assert_eq!(fields[4].str("code"), Some("A"));
}

/// Strings are escaped per RFC 8259 into pure ASCII: a value can never
/// end the line or break out of its string (log injection).
#[test]
fn strings_are_escaped_and_cannot_inject_events() {
    let mut out = String::new();
    push_json_string(&mut out, "a\"b\\c\nd\re\tf\u{1}\u{1f}\u{7f}é\u{2028}😀/");
    assert_eq!(
        out,
        "\"a\\\"b\\\\c\\nd\\re\\tf\\u0001\\u001f\\u007f\\u00e9\\u2028\\ud83d\\ude00/\""
    );
    assert!(out.is_ascii());
    assert_eq!(
        parse_json(&out),
        Ok(Json::String(
            "a\"b\\c\nd\re\tf\u{1}\u{1f}\u{7f}é\u{2028}😀/".into()
        ))
    );

    // A value that tries to close the string and add keys stays a value.
    let hostile = "ruster run: warning: port=if1\",\"event\":\"READY health=X\u{1b}[2J";
    let object = parse_json(&event_object(hostile, 0)).expect("valid");
    assert_eq!(object.str("event"), Some("HEALTH_WARNING"));
    assert_eq!(object.str("msg"), hostile.strip_prefix("ruster run: "));
    assert_eq!(
        object.keys(),
        ["schema", "ts", "level", "event", "msg", "fields"]
    );
    // An embedded newline splits lines exactly as the text format does;
    // both halves are complete objects and the second is unclassified.
    let objects = translate("ruster run: warning: port=if1 health=X\nforged\n");
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[1].str("event"), Some(UNCLASSIFIED));
    // Invalid UTF-8 becomes U+FFFD.
    let mut json = JsonLines::with_clock(Vec::new(), || 0);
    json.write_all(b"ruster run: warning: \xff\xfe\n")
        .expect("vec");
    let objects = parse_lines(&json.into_inner());
    assert_eq!(objects[0].str("msg"), Some("warning: \u{fffd}\u{fffd}"));
}

/// A stats block becomes one `STATS` object with typed values.
#[test]
fn a_stats_block_is_one_object() {
    let block = "ruster-run-stats kind=periodic uptime-ms=60000\n\
                 observer.taken_at=60000\n\
                 observer.state=healthy\n\
                 observer.generation=1\n\
                 observer.last_apply=none\n\
                 if1.watch.link_up=true\n\
                 if1.watch.link_up=false\n\
                 output.dropped=0\n\
                 end\n";
    let objects = translate(block);
    let [stats] = objects.as_slice() else {
        panic!("{objects:?}");
    };
    assert_eq!(stats.str("event"), Some("STATS"));
    assert_eq!(
        stats.keys(),
        ["schema", "ts", "level", "event", "msg", "fields", "stats"]
    );
    let fields = stats.get("fields").expect("fields");
    assert_eq!(fields.str("kind"), Some("periodic"));
    assert_eq!(fields.get("uptime-ms"), Some(&Json::Number("60000".into())));
    let values = stats.get("stats").expect("stats");
    assert_eq!(
        values.keys(),
        [
            "observer.taken_at",
            "observer.state",
            "observer.generation",
            "observer.last_apply",
            "if1.watch.link_up",
            "output.dropped"
        ]
    );
    assert_eq!(values.str("observer.state"), Some("healthy"));
    assert_eq!(values.get("observer.last_apply"), Some(&Json::Null));
    assert_eq!(values.get("if1.watch.link_up"), Some(&Json::Bool(true)));

    // A block cut short by the next header is marked truncated; events
    // around blocks stay events.
    let objects = translate(
        "ruster run: reload requested (generation 1)\n\
         ruster-run-stats kind=on-demand uptime-ms=5\nrx.received=1\n\
         ruster-run-stats kind=final uptime-ms=6\nrx.received=2\nend\n",
    );
    let events: Vec<_> = objects.iter().map(|object| object.str("event")).collect();
    assert_eq!(
        events,
        [Some("RELOAD_REQUESTED"), Some("STATS"), Some("STATS")]
    );
    assert_eq!(objects[1].get("truncated"), Some(&Json::Bool(true)));
    assert!(objects[2].get("truncated").is_none());
}

/// Lines split across writes, a partial last line at `flush`, a too-long
/// line, and empty lines.
#[test]
fn lines_are_translated_across_writes_and_bounded() {
    let mut json = JsonLines::with_clock(Vec::new(), || 0);
    for byte in
        b"ruster run: reload requested (generation 1)\n\nruster run: stop requested; draining"
    {
        json.write_all(&[*byte]).expect("vec");
    }
    let written = parse_lines(json.inner_ref());
    assert_eq!(written.len(), 1);
    json.flush().expect("vec");
    let objects = parse_lines(&json.into_inner());
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[1].str("event"), Some("SHUTDOWN_DRAINING"));
    assert_eq!(objects[1].str("level"), Some("info"));

    let long = format!("ruster run: warning: {}\n", "x".repeat(MAX_MSG_BYTES * 2));
    let objects = translate(&long);
    assert!(!objects.is_empty());
    assert_eq!(objects[0].get("truncated"), Some(&Json::Bool(true)));
    assert!(objects.iter().all(|object| object
        .str("msg")
        .is_some_and(|msg| msg.len() <= MAX_MSG_BYTES)));
}

#[test]
fn timestamps_are_rfc3339_utc_milliseconds() {
    assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00.000Z");
    assert_eq!(rfc3339(1_793_708_096_789), "2026-11-03T12:14:56.789Z");
    assert_eq!(rfc3339(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    assert!(wall_millis() > 1_700_000_000_000);
}

/// The strict parser refuses what is not JSON (so the checks above mean
/// something).
#[test]
fn the_test_parser_is_strict() {
    for bad in [
        "{\"a\":1,\"a\":2}",
        "{\"a\":\"\n\"}",
        "{\"a\":01}",
        "{\"a\":1} x",
        "{\"a\":\"\\ud800\"}",
        "{a:1}",
    ] {
        assert!(parse_json(bad).is_err(), "{bad}");
    }
    assert!(parse_json("{\"a\":[1,-2.5e3,true,null,{}]}").is_ok());
}

/// M1 (PR #339 review): the translation is linear in the block size. A
/// block of 30000 lines (a 256-port run has about 28k), in one write and
/// again line by line, becomes one object well within a generous budget
/// (the quadratic version took about 2.6 s for 28k lines; this takes
/// milliseconds). Before the fix the output thread fell behind and the
/// final block could miss the 1 s exit wait.
#[test]
fn a_large_stats_block_translates_in_linear_time() {
    let mut block = String::from("ruster-run-stats kind=final uptime-ms=1\n");
    for index in 0..30_000 {
        block.push_str(&format!(
            "if{}.watch.counter_{index}={index}\n",
            index % 256
        ));
    }
    block.push_str("end\n");
    let started = std::time::Instant::now();
    let mut whole = JsonLines::with_clock(Vec::new(), || 0);
    whole.write_all(block.as_bytes()).expect("vec");
    whole.flush().expect("vec");
    let mut chunked = JsonLines::with_clock(Vec::new(), || 0);
    for line in block.split_inclusive('\n') {
        chunked.write_all(line.as_bytes()).expect("vec");
    }
    chunked.flush().expect("vec");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "30000-line block took {elapsed:?}"
    );
    for bytes in [whole.into_inner(), chunked.into_inner()] {
        let objects = parse_lines(&bytes);
        let [stats] = objects.as_slice() else {
            panic!("{} objects", objects.len());
        };
        assert_eq!(stats.get("stats").expect("stats").keys().len(), 30_000);
        assert!(stats.get("truncated").is_none());
    }
}

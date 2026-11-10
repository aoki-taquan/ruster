#![forbid(unsafe_code)]
//! The bridge between confd and Unbound (`docs/design/router-box.md`, "Unbound").
//!
//! `ruster-unbound` takes the `dns` part of the configuration from confd
//! ([`ruster_confd::part`]), turns it into Unbound settings ([`settings`]) and writes
//! them to one file, which the operator's `unbound.conf` includes as a whole file
//! (`include-toplevel:`; Debian's `unbound.conf` includes every file in
//! `/etc/unbound/unbound.conf.d/`). Then it runs a command that has Unbound read its
//! settings again: `systemctl restart unbound` unless told otherwise.
//! `unbound-control reload` is not enough, because a reload does not open the
//! sockets of new `interface:` addresses. Everything else about Unbound (its user, its remote
//! control, `local-data`, ...) stays in the operator's files, which ruster-unbound
//! neither reads nor changes; it does not start Unbound itself (systemd does).
//!
//! The file holds a `server:` clause with an `interface:` for each listen address and
//! an `access-control: <prefix> allow` for each allowed prefix, and `ip-freebind: yes`
//! so that Unbound can start before confd has put the addresses on the kernel's TUN
//! device. With upstream servers it also holds a `forward-zone:` for `.` that
//! forwards every query to them; without, Unbound resolves from the root itself.
//! With no `dns` in the configuration, the `server:` clause is empty: Unbound answers
//! on its defaults (localhost) only.
//!
//! Taking a part ([`Bridge::take`]): the file is replaced (written next to it, then
//! renamed), and the command is run. When it fails, or takes longer than
//! [`COMMAND_LIMIT`], the file before is put back, the command is run once more, and
//! the part is refused, so confd puts the configuration before back. A part that
//! gives the file it already holds changes nothing and runs nothing, except the first
//! part after ruster-unbound starts, which always runs the command. ruster-unbound
//! tells systemd it is ready once the first file is written, before that command, so
//! Unbound's unit can be ordered after it (`systemctl restart unbound` then starts
//! Unbound). While the command runs, ruster-unbound answers nothing else.
//!
//! The upstream servers that a WAN DHCP client or PPPoE finds at run time are not
//! used yet (the lock form's `upstream-from`).
//!
//! # Standards
//!
//! - RFC 5358 section 4: the recursive server answers only the clients it is meant
//!   for; `access-control` allows the prefixes of the listen interfaces and Unbound
//!   refuses the rest (its default).
//!
//! Deviations: none of DNS itself is here; Unbound implements it.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ruster_config::Dns;

/// The first line of the file.
pub const HEADER: &str =
    "# Written by ruster-unbound from confd's dns part; it is replaced on each change.";

/// The Unbound settings for `dns`, the text of the included file. Each value is read
/// as an address or prefix again, so nothing else reaches the file.
pub fn settings(dns: Option<&Dns>) -> Result<String, String> {
    let mut out = format!("{HEADER}\nserver:\n");
    let Some(dns) = dns else {
        return Ok(out);
    };
    let address = |text: &str, what: &str| {
        text.parse::<IpAddr>()
            .map_err(|_| format!("{what} {text:?} is not an address"))
    };
    for text in &dns.listen {
        let _ = writeln!(out, "    interface: {}", address(text, "listen")?);
    }
    if !dns.listen.is_empty() {
        out.push_str("    ip-freebind: yes\n");
    }
    for text in &dns.allow {
        let (prefix, len) = text
            .split_once('/')
            .ok_or_else(|| format!("allow {text:?} is not a prefix"))?;
        let prefix = address(prefix, "allow")?;
        let max = if prefix.is_ipv4() { 32 } else { 128 };
        let len: u8 = len
            .parse()
            .ok()
            .filter(|len| *len <= max)
            .ok_or_else(|| format!("allow {text:?} has no usable prefix length"))?;
        let _ = writeln!(out, "    access-control: {prefix}/{len} allow");
    }
    if !dns.upstream.is_empty() {
        out.push_str("forward-zone:\n    name: \".\"\n");
        for text in &dns.upstream {
            let _ = writeln!(out, "    forward-addr: {}", address(text, "upstream")?);
        }
    }
    Ok(out)
}

/// How long the command may take; it is stopped after this and counts as failed.
/// The command and the run that puts the file before back fit together before confd
/// stops waiting for an answer (30 s).
pub const COMMAND_LIMIT: Duration = Duration::from_secs(12);

/// Writes the file and runs the command that has Unbound read it.
#[derive(Debug)]
pub struct Bridge {
    path: PathBuf,
    reload: Vec<String>,
    /// Whether a part was taken since ruster-unbound started.
    took: bool,
}

impl Bridge {
    /// For the file at `path`; `reload` is the program and its arguments.
    pub fn new(path: PathBuf, reload: Vec<String>) -> Self {
        Self {
            path,
            reload,
            took: false,
        }
    }

    /// Takes a `dns` part ([`ruster_config::dns_part`]), or refuses it with the reason.
    /// `written` runs once the file holds the part, before the command.
    pub fn take(&mut self, part: &str, written: &mut dyn FnMut()) -> Result<(), String> {
        let dns = ruster_config::parse_dns_part(part)?;
        let text = settings(dns.as_ref())?;
        let before = match std::fs::read_to_string(&self.path) {
            Ok(before) => Some(before),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("{}: {error}", self.path.display())),
        };
        // After a start, the command runs even for the file it finds: Unbound may not
        // have read it (ruster-unbound may have stopped between the two).
        if self.took && before.as_deref() == Some(text.as_str()) {
            return Ok(());
        }
        if before.as_deref() != Some(text.as_str()) {
            self.write(&text)?;
        }
        written();
        if let Err(error) = self.run_reload() {
            let put_back = match &before {
                Some(before) => self.write(before),
                None => std::fs::remove_file(&self.path).map_err(|e| e.to_string()),
            };
            if let Err(again) = put_back.and_then(|()| self.run_reload()) {
                eprintln!("ruster-unbound: putting the file before back: {again}");
            }
            return Err(error);
        }
        self.took = true;
        Ok(())
    }

    fn write(&self, text: &str) -> Result<(), String> {
        let mut next = self.path.clone().into_os_string();
        next.push(".next");
        let at = |e: std::io::Error| format!("{}: {e}", self.path.display());
        std::fs::write(&next, text).map_err(at)?;
        std::fs::rename(&next, &self.path).map_err(at)
    }

    fn run_reload(&self) -> Result<(), String> {
        let Some((program, args)) = self.reload.split_first() else {
            return Ok(());
        };
        let command = self.reload.join(" ");
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() < COMMAND_LIMIT => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{command} took longer than {COMMAND_LIMIT:?}"));
                }
                Err(error) => return Err(format!("{command}: {error}")),
            }
        };
        if status.success() {
            return Ok(());
        }
        let mut said = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut stderr, &mut said);
        }
        Err(format!("{command} failed ({status}): {}", said.trim()))
    }
}

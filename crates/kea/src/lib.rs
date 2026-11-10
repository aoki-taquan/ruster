#![forbid(unsafe_code)]
//! The bridge between confd and Kea (`docs/design/router-box.md`, "Kea").
//!
//! The LAN ports belong to the FE, so Kea, which runs in the router's kernel
//! network namespace, never sees a client's broadcast. `ruster-kea` stands between
//! them as a DHCP relay agent: the FE hands it the clients' requests (the punt
//! classes confd writes for each `[[dhcp]]` and `[[dhcp6]]` interface), it relays
//! them to Kea over UDP, and it turns Kea's replies back into frames that the FE
//! sends out of the interface ([`relay`] for DHCPv4, [`relay6`] for DHCPv6,
//! [`agent`]).
//!
//! It takes the `dhcp` part of the configuration from confd
//! ([`ruster_confd::part`]), writes Kea's subnets for it to one file per server
//! (DHCPv4 [`settings`], DHCPv6 [`settings6`]) and has each Kea read its
//! configuration again (`config-reload` on its control socket). When a Kea refuses
//! its file, both files before are put back and read again, and the part is
//! refused, so confd puts the configuration before back. When a Kea is not running
//! the part is taken: Kea reads the file when it starts. ruster-kea does not start
//! Kea (systemd does).
//!
//! # Standards
//!
//! See [`relay`], [`relay6`], [`settings`] and [`settings6`].

pub mod agent;
pub mod relay;
pub mod relay6;
pub mod settings;
pub mod settings6;

use std::path::PathBuf;

use settings::{Listen, Served};
use settings6::{Listen6, Served6};

/// One of Kea's servers: the file ruster-kea writes for it, and its control socket
/// (none: Kea is not asked to read it again).
#[derive(Debug)]
pub struct Server {
    pub path: PathBuf,
    pub control: Option<PathBuf>,
}

impl Server {
    fn reload(&self) -> Result<(), String> {
        let Some(control) = &self.control else {
            return Ok(());
        };
        if !settings::reload(control)? {
            eprintln!(
                "ruster-kea: Kea is not running ({}); it reads the file when it starts",
                control.display()
            );
        }
        Ok(())
    }

    fn read(&self) -> Result<Option<String>, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(before) => Ok(Some(before)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", self.path.display())),
        }
    }

    fn write(&self, text: &str) -> Result<(), String> {
        let mut next = self.path.clone().into_os_string();
        next.push(".next");
        let at = |e: std::io::Error| format!("{}: {e}", self.path.display());
        std::fs::write(&next, text).map_err(at)?;
        std::fs::rename(&next, &self.path).map_err(at)
    }
}

/// The files a part makes, each with its text, and what to serve.
type Files<'a> = (Vec<(&'a Server, String)>, Vec<Served>, Vec<Served6>);

/// Writes Kea's settings files and has Kea read them.
#[derive(Debug)]
pub struct Bridge {
    v4: Server,
    listen: Listen,
    /// The DHCPv6 server, when ruster-kea is given one.
    v6: Option<(Server, Listen6)>,
}

impl Bridge {
    /// For the DHCPv4 file at `path`, Kea's control socket at `control` (none: Kea
    /// is not asked to read it again), and Kea listening at `listen`.
    pub fn new(path: PathBuf, control: Option<PathBuf>, listen: Listen) -> Self {
        Self {
            v4: Server { path, control },
            listen,
            v6: None,
        }
    }

    /// Also writes the DHCPv6 file for `server`, Kea's DHCPv6 listening at `listen`.
    pub fn with_dhcp6(mut self, server: Server, listen: Listen6) -> Self {
        self.v6 = Some((server, listen));
        self
    }

    /// What taking a `dhcp` part would change: the line diff of each file, or the
    /// reason it would be refused. Nothing is written.
    pub fn check(&self, part: &str) -> Result<String, String> {
        let mut out = String::new();
        for (server, text) in self.files(part)?.0 {
            let before = server.read()?.unwrap_or_default();
            let name = server.path.display().to_string();
            out.push_str(&ruster_confd::diff::lines(
                &before,
                &text,
                (&name, "candidate"),
            ));
        }
        Ok(out)
    }

    /// The files a `dhcp` part makes, each with its text, and what to serve.
    fn files(&self, part: &str) -> Result<Files<'_>, String> {
        let (dhcp, dhcp6) = ruster_config::parse_dhcp_part(part)?;
        let served = settings::read(&dhcp)?;
        let served6 = settings6::read(&dhcp6)?;
        if !served6.is_empty() && self.v6.is_none() {
            return Err("dhcp6 is given, but ruster-kea has no DHCPv6 file (--dhcp6)".into());
        }
        let mut files = vec![(&self.v4, settings::settings(&self.listen, &served))];
        if let Some((server, listen)) = &self.v6 {
            files.push((server, settings6::settings(listen, &served6)));
        }
        Ok((files, served, served6))
    }

    /// Takes a `dhcp` part ([`ruster_config::dhcp_part`]) and gives what to serve,
    /// or refuses it with the reason. `written` runs once the files hold the part,
    /// before Kea is asked to read them.
    pub fn take(
        &mut self,
        part: &str,
        written: &mut dyn FnMut(),
    ) -> Result<(Vec<Served>, Vec<Served6>), String> {
        let (files, served, served6) = self.files(part)?;
        let mut before = Vec::with_capacity(files.len());
        for (server, _) in &files {
            before.push(server.read()?);
        }
        let wrote = files
            .iter()
            .zip(&before)
            .try_for_each(|((server, text), before)| {
                if before.as_deref() == Some(text.as_str()) {
                    return Ok(());
                }
                server.write(text)
            });
        if wrote.is_ok() {
            written();
        }
        // Asked even when a file is the same: Kea may not have read it yet.
        let reloaded =
            wrote.and_then(|()| files.iter().try_for_each(|(server, _)| server.reload()));
        // A file that could not be written, or that a Kea refused: every file before
        // is put back.
        if let Err(error) = reloaded {
            // With no file a Kea could not start: one with no subnets instead.
            let empty = [
                settings::settings(&self.listen, &[]),
                self.v6
                    .as_ref()
                    .map(|(_, listen)| settings6::settings(listen, &[]))
                    .unwrap_or_default(),
            ];
            for (((server, _), before), empty) in files.iter().zip(&before).zip(&empty) {
                let put_back = server.write(before.as_deref().unwrap_or(empty));
                if let Err(again) = put_back.and_then(|()| server.reload()) {
                    eprintln!("ruster-kea: putting the file before back: {again}");
                }
            }
            return Err(error);
        }
        Ok((served, served6))
    }
}

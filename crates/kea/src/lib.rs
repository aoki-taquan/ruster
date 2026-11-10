#![forbid(unsafe_code)]
//! The bridge between confd and Kea (`docs/design/router-box.md`, "Kea").
//!
//! The LAN ports belong to the FE, so Kea, which runs in the router's kernel
//! network namespace, never sees a client's broadcast. `ruster-kea` stands between
//! them as a DHCP relay agent: the FE hands it the clients' requests (the punt
//! classes confd writes for each `[[dhcp]]` interface), it relays them to Kea over
//! UDP, and it turns Kea's replies back into frames that the FE sends out of the
//! interface ([`relay`]).
//!
//! It takes the `dhcp` part of the configuration from confd
//! ([`ruster_confd::part`]), writes Kea's subnets for it to one file
//! ([`settings`]) and has Kea read its configuration again (`config-reload` on
//! Kea's control socket). When Kea refuses the file, the file before is put back
//! and read again, and the part is refused, so confd puts the configuration before
//! back. When Kea is not running the part is taken: Kea reads the file when it
//! starts. ruster-kea does not start Kea (systemd does).
//!
//! # Standards
//!
//! See [`relay`] and [`settings`].

pub mod relay;
pub mod settings;

use std::path::PathBuf;

use settings::{Listen, Served};

/// Writes Kea's settings file and has Kea read it.
#[derive(Debug)]
pub struct Bridge {
    path: PathBuf,
    control: Option<PathBuf>,
    listen: Listen,
}

impl Bridge {
    /// For the file at `path`, Kea's control socket at `control` (none: Kea is not
    /// asked to read it again), and Kea listening at `listen`.
    pub fn new(path: PathBuf, control: Option<PathBuf>, listen: Listen) -> Self {
        Self {
            path,
            control,
            listen,
        }
    }

    /// Takes a `dhcp` part ([`ruster_config::dhcp_part`]) and gives what to serve,
    /// or refuses it with the reason. `written` runs once the file holds the part,
    /// before Kea is asked to read it.
    pub fn take(&mut self, part: &str, written: &mut dyn FnMut()) -> Result<Vec<Served>, String> {
        let served = settings::read(&ruster_config::parse_dhcp_part(part)?)?;
        let text = settings::settings(&self.listen, &served);
        let before = match std::fs::read_to_string(&self.path) {
            Ok(before) => Some(before),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("{}: {error}", self.path.display())),
        };
        if before.as_deref() != Some(text.as_str()) {
            self.write(&text)?;
        }
        written();
        // Asked even when the file is the same: Kea may not have read it yet.
        if let Err(error) = self.reload() {
            let put_back = match &before {
                Some(before) => self.write(before),
                None => std::fs::remove_file(&self.path).map_err(|e| e.to_string()),
            };
            if let Err(again) = put_back.and_then(|()| self.reload()) {
                eprintln!("ruster-kea: putting the file before back: {again}");
            }
            return Err(error);
        }
        Ok(served)
    }

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

    fn write(&self, text: &str) -> Result<(), String> {
        let mut next = self.path.clone().into_os_string();
        next.push(".next");
        let at = |e: std::io::Error| format!("{}: {e}", self.path.display());
        std::fs::write(&next, text).map_err(at)?;
        std::fs::rename(&next, &self.path).map_err(at)
    }
}

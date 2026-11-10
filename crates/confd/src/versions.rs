//! The configurations confd has committed, kept as numbered versions
//! (`docs/design/router-box.md`, "反映の流れ").
//!
//! A version is committed when every process has taken a new configuration (see
//! [`crate::apply`]), with two exceptions: the file confd starts with, which is kept
//! before it is sent, and a configuration whose answers confd stopped waiting for,
//! which stays in use. Each version keeps the lock form, the `ruster.toml` text when
//! the configuration came as one, the time and how it came. Numbers go up by one from
//! the latest kept; the last [`KEEP`] versions are kept and older ones are deleted.
//!
//! With `--state-dir DIR`, the versions are files, so they outlive confd:
//!
//! ```text
//! DIR/versions/000001.toml   version 1: time, how, lock, toml
//! DIR/versions/000002.toml
//! DIR/versions/confirm.toml  only while the latest waits for `ruster confirm`:
//!                            version, back-to, deadline, minutes ([`Waiting`])
//! ```
//!
//! A `confirm.toml` for a version that is not the latest is from a crash between
//! writing it and writing the version, and is removed at start-up.
//!
//! The directory is made with mode 0700 and the files with 0600, since the lock form
//! can hold PPPoE passwords. Each file is written to a temporary file, synced, renamed
//! into place, and then the directory is synced, so a crash leaves either the whole
//! version or none of it. Without `--state-dir` the versions are only in memory.
//!
//! At start-up confd uses the latest version ([`Versions::starting_config`]). The file
//! given on its command line is read only when there is no version yet, and then it
//! becomes version 1: it is the first configuration, not the one confd goes back to
//! each time it starts. To start over from the file, empty the directory (numbering
//! then starts again from 1).
//!
//! An update of ruster can change the lock form, so the latest version's lock form
//! may not read. `ruster_config::VERSION` changes when an older lock form no longer
//! reads, and a test in ruster-config fails when the lock form changes without it.
//! At start-up confd tries, in order:
//!
//! 1. The latest version's lock form.
//! 2. Its `ruster.toml` text, if it has one, resolved again with this ruster's
//!    defaults. The result is kept as a new version (and still waits for
//!    `ruster confirm` if the latest did).
//! 3. The newest older version that reads in either way. It is kept as a new version,
//!    a wait for `ruster confirm` is dropped, and confd writes a warning to the log:
//!    the router keeps running, on an older configuration, rather than not start.
//!
//! Step 3 can go back far: older versions kept only as a lock form usually do not read
//! either, so it is often the newest one with a `ruster.toml`. The warning is written
//! once; the version list shows how the new version came. Going back to the earlier
//! ruster then starts with the version kept in step 3, not the one that did not read
//! (`ruster rollback` reaches it).
//!
//! If none reads, confd does not start. A version file that does not read at all is
//! left out with a line in the log. If the start-up file cannot be kept (a full disk, a
//! directory confd cannot write), confd does not start either.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{file, Config};

/// How many versions are kept.
pub const KEEP: usize = 50;

/// One committed configuration. Its `Debug` does not show the texts, which may hold
/// PPPoE passwords.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    #[serde(skip)]
    pub number: u64,
    /// Seconds since 1970-01-01 UTC.
    pub time: u64,
    /// How it came, for a person: `apply`, `rollback to 3` and so on.
    pub how: String,
    /// The configuration in the lock form.
    pub lock: String,
    /// The `ruster.toml` text, when the configuration came as one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toml: Option<String>,
}

impl std::fmt::Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            number,
            time,
            how,
            lock: _,
            toml,
        } = self;
        f.debug_struct("Version")
            .field("number", number)
            .field("time", time)
            .field("how", how)
            .field("lock", &ruster_config::HIDDEN)
            .field("toml", &toml.as_ref().map(|_| ruster_config::HIDDEN))
            .finish()
    }
}

/// The versions, oldest first.
#[derive(Debug, Default)]
pub struct Versions {
    dir: Option<PathBuf>,
    list: Vec<Version>,
    waiting: Option<Waiting>,
}

/// The latest version waits for `ruster confirm` ([`crate::apply`]); without it in
/// time, confd goes back to `back_to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Waiting {
    pub version: u64,
    pub back_to: u64,
    /// When it goes back, in seconds since 1970-01-01 UTC.
    pub deadline: u64,
    /// How long it was given; a start-up waits at most this long, should the clock
    /// have gone back.
    pub minutes: u32,
}

/// The name of the file that holds [`Waiting`], beside the versions.
const WAITING: &str = "confirm.toml";

impl Versions {
    /// Versions only in memory.
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Opens (or makes) the state directory and reads the versions in it.
    pub fn open(state_dir: &Path) -> Result<Self, String> {
        let dir = state_dir.join("versions");
        let at = |e: io::Error| format!("{}: {e}", dir.display());
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(at)?;
        let mut found = Vec::new();
        for entry in fs::read_dir(&dir).map_err(at)? {
            let entry = entry.map_err(at)?;
            let name = entry.file_name();
            // Exactly the names confd writes; a temporary file left by a crash, or
            // anything else, is not a version.
            let Some(number) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".toml"))
                .filter(|n| n.len() == 6 && n.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|n| n.parse::<u64>().ok())
            else {
                continue;
            };
            found.push((number, entry.path()));
        }
        found.sort();
        let mut list = Vec::new();
        let latest = found.last().map(|(n, _)| *n);
        for (number, path) in found {
            let read = fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|text| {
                    toml::from_str::<Version>(&text)
                        .map_err(|e| ruster_config::toml_error(&text, &e))
                });
            match read {
                Ok(mut version) => {
                    version.number = number;
                    list.push(version);
                }
                // Only the latest version decides how confd starts.
                Err(error) if Some(number) == latest => {
                    return Err(format!("{}: {error}", path.display()));
                }
                Err(error) => eprintln!(
                    "ruster-confd: {}: {error}; this older version is left out",
                    path.display()
                ),
            }
        }
        let mut versions = Self {
            dir: Some(dir),
            list,
            waiting: None,
        };
        versions.read_waiting()?;
        Ok(versions)
    }

    /// Reads [`WAITING`]. One for a version that is not the latest is from before a
    /// crash (the version was not written, or a newer one was) and is removed.
    fn read_waiting(&mut self) -> Result<(), String> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        let path = dir.join(WAITING);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let waiting: Waiting = toml::from_str(&text).map_err(|e| {
            format!(
                "{}: {}",
                path.display(),
                ruster_config::toml_error(&text, &e)
            )
        })?;
        let latest = self.latest().map(|v| v.number);
        if Some(waiting.version) == latest && self.get(waiting.back_to).is_some() {
            self.waiting = Some(waiting);
            return Ok(());
        }
        eprintln!(
            "ruster-confd: {}: version {} is not the latest, or version {} is not kept; \
             nothing waits for confirmation",
            path.display(),
            waiting.version,
            waiting.back_to
        );
        self.set_waiting(None)
    }

    /// The version waiting for `ruster confirm`, if one is.
    pub fn waiting(&self) -> Option<Waiting> {
        self.waiting
    }

    /// Keeps (or with `None`, drops) what waits for confirmation, in the state
    /// directory too. On an error writing, nothing is kept; on an error removing, it
    /// is dropped in memory only.
    pub fn set_waiting(&mut self, waiting: Option<Waiting>) -> Result<(), String> {
        let written = match (&self.dir, &waiting) {
            (None, _) => Ok(()),
            (Some(dir), Some(waiting)) => {
                let text = toml::to_string(waiting).map_err(|e| e.to_string())?;
                write_atomically(dir, WAITING, text.as_bytes())
            }
            (Some(dir), None) => match fs::remove_file(dir.join(WAITING)) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
                _ => fs::File::open(dir).and_then(|d| d.sync_all()),
            },
        };
        let written = written.map_err(|e| format!("{WAITING}: {e}"));
        if written.is_ok() || waiting.is_none() {
            self.waiting = waiting;
        }
        written
    }

    /// The versions kept, oldest first.
    pub fn list(&self) -> &[Version] {
        &self.list
    }

    pub fn latest(&self) -> Option<&Version> {
        self.list.last()
    }

    pub fn get(&self, number: u64) -> Option<&Version> {
        self.list.iter().find(|v| v.number == number)
    }

    /// Keeps a new version and returns its number. On an error nothing is kept.
    pub fn commit(&mut self, how: &str, lock: &str, toml: Option<&str>) -> Result<u64, String> {
        let number = self.latest().map_or(1, |v| v.number + 1);
        let version = Version {
            number,
            time: unix_now(),
            how: how.to_owned(),
            lock: lock.to_owned(),
            toml: toml.map(str::to_owned),
        };
        if let Some(dir) = &self.dir {
            let text = toml::to_string(&version).map_err(|e| e.to_string())?;
            write_atomically(dir, &file_name(number), text.as_bytes())
                .map_err(|e| format!("{}: {e}", dir.join(file_name(number)).display()))?;
        }
        self.list.push(version);
        while self.list.len() > KEEP {
            let old = self.list.remove(0);
            if let Some(dir) = &self.dir {
                // One left behind is deleted with the next.
                let _ = fs::remove_file(dir.join(file_name(old.number)));
            }
        }
        Ok(number)
    }

    /// The configuration confd starts with: the latest version, or else the file at
    /// `path`, which is then kept as version 1. When the latest version does not read
    /// (see the module documentation), the newest older one that does is used.
    pub fn starting_config(&mut self, path: &str) -> Result<Start, String> {
        let Some(latest) = self.latest() else {
            let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let candidate = file::candidate(&text).map_err(|e| format!("{path}: {e}"))?;
            self.commit(
                &format!("start-up file {path}"),
                &candidate.lock,
                candidate.toml.as_deref(),
            )?;
            return Ok(Start {
                config: candidate.config,
                from: path.to_owned(),
                warning: None,
            });
        };
        let number = latest.number;
        let latest_error = match read(latest) {
            Ok((config, None)) => {
                return Ok(Start {
                    config,
                    from: format!("version {number}"),
                    warning: None,
                })
            }
            Ok((config, Some(candidate))) => {
                let how = format!("ruster.toml of version {number} resolved again at start-up");
                // The deadline moves to the new version first: it is the same
                // configuration, still waiting for `ruster confirm`.
                if let Some(waiting) = self.waiting.filter(|w| w.version == number) {
                    self.set_waiting(Some(Waiting {
                        version: number + 1,
                        ..waiting
                    }))?;
                }
                let new = self.commit(&how, &candidate.lock, candidate.toml.as_deref())?;
                return Ok(Start {
                    config,
                    from: format!("version {new} ({how})"),
                    warning: None,
                });
            }
            Err(error) => format!("version {number}: {error}"),
        };
        // The newest older version that reads, so that a router keeps running after an
        // update; the person is told loudly to check it.
        let older = self.list.iter().rev().skip(1).find_map(|version| {
            read(version)
                .ok()
                .map(|(config, candidate)| (version.clone(), config, candidate))
        });
        let Some((older, config, candidate)) = older else {
            return Err(latest_error);
        };
        let how = format!(
            "version {} again at start-up: version {number} does not read",
            older.number
        );
        // The version that waited for `ruster confirm` is not the one running.
        self.set_waiting(None)?;
        let (lock, toml) = match &candidate {
            Some(candidate) => (candidate.lock.as_str(), candidate.toml.as_deref()),
            None => (older.lock.as_str(), older.toml.as_deref()),
        };
        let new = self.commit(&how, lock, toml)?;
        Ok(Start {
            config,
            from: format!("version {new} ({how})"),
            warning: Some(format!(
                "{latest_error}; started with version {} instead (kept as version {new}). \
                 Check the configuration and apply it again",
                older.number
            )),
        })
    }

    /// One line per version, newest first: number, time (UTC) and how it came.
    pub fn listing(&self) -> String {
        let mut out = String::new();
        for version in self.list.iter().rev() {
            let waits = match self.waiting {
                Some(w) if w.version == version.number => format!(
                    " (waits for `ruster confirm`; goes back to version {} at {})",
                    w.back_to,
                    utc(w.deadline)
                ),
                _ => String::new(),
            };
            let _ = writeln!(
                out,
                "{:>6}  {}  {}{waits}",
                version.number,
                utc(version.time),
                version.how
            );
        }
        out
    }
}

/// What [`Versions::starting_config`] found.
#[derive(Debug)]
pub struct Start {
    pub config: Config,
    /// Where the configuration came from, for the log.
    pub from: String,
    /// Set when the latest version did not read and an older one is used.
    pub warning: Option<String>,
}

/// Reads a kept version: its lock form, or else its `ruster.toml` resolved again with
/// this ruster's defaults (then with the new lock form).
fn read(version: &Version) -> Result<(Config, Option<file::Candidate>), String> {
    let lock_error = match file::parse(&version.lock) {
        Ok(config) => return Ok((config, None)),
        Err(error) => error,
    };
    let Some(toml) = &version.toml else {
        return Err(lock_error);
    };
    match file::candidate(toml) {
        Ok(candidate) => Ok((candidate.config.clone(), Some(candidate))),
        Err(error) => Err(format!(
            "{lock_error}; its ruster.toml does not read either: {error}"
        )),
    }
}

/// Seconds since 1970-01-01 UTC now.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn file_name(number: u64) -> String {
    format!("{number:06}.toml")
}

/// Writes `dir/name` so that it is either the old file or the whole new one: a
/// temporary file, synced, renamed, and the directory synced.
pub fn write_atomically(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!(".{name}.tmp"));
    // One left by a crash is made again, so that it gets mode 0600.
    match fs::remove_file(&temp) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, dir.join(name))?;
    fs::File::open(dir)?.sync_all()
}

/// Seconds since 1970 as `YYYY-MM-DD hh:mm:ss UTC` (the civil calendar of the
/// proleptic Gregorian calendar).
pub fn utc(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rest = seconds % 86_400;
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rest / 3_600,
        rest / 60 % 60,
        rest % 60
    )
}

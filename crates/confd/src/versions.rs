//! The configurations confd has committed, kept as numbered versions
//! (`docs/design/router-box.md`, "反映の流れ").
//!
//! A version is committed when every process has taken a new configuration (see
//! [`crate::apply`]). Each one keeps the lock form, the `ruster.toml` text when the
//! configuration came as one, the time and how it came. Numbers go up by one and are
//! never used again; the last [`KEEP`] versions are kept and older ones are deleted.
//!
//! With `--state-dir DIR`, the versions are files, so they outlive confd:
//!
//! ```text
//! DIR/versions/000001.toml   version 1: time, how, lock, toml
//! DIR/versions/000002.toml
//! ```
//!
//! The directory is made with mode 0700 and the files with 0600, since the lock form
//! can hold PPPoE passwords. Each file is written to a temporary file, synced, renamed
//! into place, and then the directory is synced, so a crash leaves either the whole
//! version or none of it. Without `--state-dir` the versions are only in memory.
//!
//! At start-up confd uses the latest version ([`Versions::starting_config`]). The file
//! given on its command line is read only when there is no version yet, and then it
//! becomes version 1: it is the first configuration, not the one confd goes back to
//! each time it starts. To start over from the file, empty the directory. If the
//! latest version cannot be read (for example, after an update that reads another
//! lock form version), confd does not start, rather than run an older configuration.

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

/// One committed configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// The versions, oldest first.
#[derive(Debug, Default)]
pub struct Versions {
    dir: Option<PathBuf>,
    list: Vec<Version>,
}

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
        let mut list = Vec::new();
        for entry in fs::read_dir(&dir).map_err(at)? {
            let entry = entry.map_err(at)?;
            let name = entry.file_name();
            let Some(number) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".toml"))
                .and_then(|n| n.parse::<u64>().ok())
            else {
                // A temporary file left by a crash, or something else.
                continue;
            };
            let path = entry.path();
            let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut version: Version =
                toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            version.number = number;
            list.push(version);
        }
        list.sort_by_key(|v| v.number);
        Ok(Self {
            dir: Some(dir),
            list,
        })
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
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
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

    /// The configuration confd starts with, and where it came from: the latest
    /// version, or else the file at `path`, which is then kept as version 1.
    pub fn starting_config(&mut self, path: &str) -> Result<(Config, String), String> {
        if let Some(latest) = self.latest() {
            let at = format!("version {}", latest.number);
            let config = file::parse(&latest.lock).map_err(|e| format!("{at}: {e}"))?;
            return Ok((config, at));
        }
        let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let candidate = file::candidate(&text).map_err(|e| format!("{path}: {e}"))?;
        self.commit(
            &format!("start-up file {path}"),
            &candidate.lock,
            candidate.toml.as_deref(),
        )?;
        Ok((candidate.config, path.to_owned()))
    }

    /// One line per version, newest first: number, time (UTC) and how it came.
    pub fn listing(&self) -> String {
        let mut out = String::new();
        for version in self.list.iter().rev() {
            let _ = writeln!(
                out,
                "{:>6}  {}  {}",
                version.number,
                utc(version.time),
                version.how
            );
        }
        out
    }
}

fn file_name(number: u64) -> String {
    format!("{number:06}.toml")
}

/// Writes `dir/name` so that it is either the old file or the whole new one: a
/// temporary file, synced, renamed, and the directory synced.
pub fn write_atomically(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!(".{name}.tmp"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
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

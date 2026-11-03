//! Filesystem confinement of `ruster run` after startup (H11, CLI-122 to
//! CLI-127).
//!
//! The privilege drop ([`super::privileges`]) and the syscall filter
//! ([`super::seccomp`]) still let the process open, read-only, every file
//! its user may read: uid 0 without `--user` owns every root file
//! (`/etc/shadow`, keys), and a compromised router could send such a file
//! out over the network or its output. So every thread is confined to the
//! files the run reads with one Landlock ruleset (`--fs-confine landlock`,
//! the default; `off` opts out):
//!
//! | grant | access | why |
//! |---|---|---|
//! | the config file's directory, as given, and (if different) the directory of the file it resolves to | read files | the SIGHUP reload reads the config again, also after an atomic replace (a new inode in the same directory) |
//! | `/proc/<pid>` (this process) | read files, list directories | `/proc/self/task/*/status` and `/proc/thread-self/status` (the drop and filter verifications), `/proc/self/status` (the effective uid of `--strict-config-perms`) |
//! | `/proc/sys/net` | read files | the link watch's forwarding, `rp_filter`, and IPv6 sysctls |
//! | the executable | read files | symbolizing a panic backtrace (skipped when the binary cannot be opened) |
//!
//! Nothing else can be opened, listed, executed, written, created,
//! removed, linked, or renamed by path (truncation by path is a Landlock
//! right from ABI 3; before it, the syscall filter's `openat` rule without
//! `O_TRUNC` and the missing `truncate` keep it out, so not under
//! `--seccomp log|off`). On ABI 4 and newer TCP `bind` and `connect` are
//! refused too (no rule grants a port; the run uses no TCP). What does not go
//! through a path stays: the fds opened before (the ports, the netlink and
//! notification sockets, `/dev/urandom`, stdout/stderr), and metadata
//! (`stat`, `readlink`; the `--strict-config-perms` walk to `/` and the
//! `/proc/self/fd/N` link). Landlock checks the path an open resolves to,
//! so `/proc/<pid>/root/...`, `/proc/self/cwd/...`, or a symlink that
//! leads out of a granted directory is refused, as is every other
//! process's `/proc/<pid>`.
//!
//! # Why Landlock (and not a mount namespace)
//!
//! A mount namespace with `pivot_root` needs `CAP_SYS_ADMIN` (the
//! startup preflight accepts `CAP_BPF` + `CAP_PERFMON` instead), changes
//! only the calling thread's namespace (the output threads exist before
//! startup), and must rebuild a minimal tree with procfs that reflects the
//! right network namespace. Landlock needs no privilege, composes with the
//! drop and the filter, is per thread like the drop (so each thread
//! confines itself in the same prologue), and keeps the paths unchanged.
//!
//! # When, per thread
//!
//! A config directory of `/` would grant reading the whole filesystem: it
//! is refused (`code=CONFIG_DIRECTORY_ROOT`), and a broad one (`/etc`,
//! `/home`, `/root`, `/usr`, `/var`) is warned (see [`classify_directory`]).
//!
//! Landlock confines the calling thread (and the threads it starts later).
//! [`linux::prepare_process`] builds the ruleset first thing, on the only
//! thread, before any other thread exists; each thread then confines
//! itself after its privilege drop: the output threads at spawn, the link
//! watcher and the reload worker at spawn after activation, and the router
//! thread right after its drop and before the syscall filter
//! ([`linux::restrict_process`]). Every confinement is checked by the thread
//! itself: listing `/` must fail with `EACCES`, and records its thread id.
//! The router thread finally requires the recorded ids to be exactly the
//! ids `/proc/self/task` lists. Any
//! failure aborts startup with the full rollback (exit 1,
//! `stage=fs-confine`).
//!
//! The rules hold inodes, not paths: the `/proc/<pid>` and `/proc/sys/net`
//! directories are procfs entries whose inodes are made again when their
//! dentries are reclaimed, so their `O_PATH` fds stay open for the whole
//! run (a held dentry is never reclaimed, so every lookup finds the same
//! inode). The `landlock_*` and `prctl` calls happen before the syscall
//! filter is installed; the allowlist has none of them.
//!
//! # Kernel
//!
//! Landlock ABI 1 (Linux 5.13) or newer, enabled (`landlock` in
//! `/sys/kernel/security/lsm`). The ruleset handles the filesystem rights
//! of the running ABI up to ABI 5 ([`handled_access`]; refer from ABI 2,
//! truncate from ABI 3, device ioctl from ABI 5), never a right defined
//! later: an unhandled right is allowed, so a later kernel restricts
//! nothing new (such as connecting to the notification socket by path).
//! Without Landlock the default refuses to start
//! (`code=LANDLOCK_UNSUPPORTED`, `LANDLOCK_DISABLED`, or `LANDLOCK_BLOCKED`
//! when a supervisor's syscall filter refuses the calls with `EPERM`);
//! `--fs-confine off` runs without it.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use ruster_core::{FieldValue, FieldVisitor, ObservableFields};

pub use crate::args::FsConfineMode;

// Landlock filesystem access rights (`linux/landlock.h`).
pub const ACCESS_EXECUTE: u64 = 1 << 0;
pub const ACCESS_WRITE_FILE: u64 = 1 << 1;
pub const ACCESS_READ_FILE: u64 = 1 << 2;
pub const ACCESS_READ_DIR: u64 = 1 << 3;
pub const ACCESS_REMOVE_DIR: u64 = 1 << 4;
pub const ACCESS_REMOVE_FILE: u64 = 1 << 5;
pub const ACCESS_MAKE_CHAR: u64 = 1 << 6;
pub const ACCESS_MAKE_DIR: u64 = 1 << 7;
pub const ACCESS_MAKE_REG: u64 = 1 << 8;
pub const ACCESS_MAKE_SOCK: u64 = 1 << 9;
pub const ACCESS_MAKE_FIFO: u64 = 1 << 10;
pub const ACCESS_MAKE_BLOCK: u64 = 1 << 11;
pub const ACCESS_MAKE_SYM: u64 = 1 << 12;
/// ABI 2 (Linux 5.19).
pub const ACCESS_REFER: u64 = 1 << 13;
/// ABI 3 (Linux 6.2).
pub const ACCESS_TRUNCATE: u64 = 1 << 14;
/// ABI 5 (Linux 6.10).
pub const ACCESS_IOCTL_DEV: u64 = 1 << 15;

/// The rights of ABI 1.
const ABI1_ACCESS: u64 = ACCESS_EXECUTE
    | ACCESS_WRITE_FILE
    | ACCESS_READ_FILE
    | ACCESS_READ_DIR
    | ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SOCK
    | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK
    | ACCESS_MAKE_SYM;

/// The filesystem rights the ruleset handles (denies unless granted) on a
/// kernel of Landlock ABI `abi`: every right that ABI knows, up to ABI 5.
/// Rights of later ABIs are never handled (they stay allowed), so a newer
/// kernel cannot make a call the run needs fail; 0 for ABI 0.
pub const fn handled_access(abi: u32) -> u64 {
    match abi {
        0 => 0,
        1 => ABI1_ACCESS,
        2 => ABI1_ACCESS | ACCESS_REFER,
        3 | 4 => ABI1_ACCESS | ACCESS_REFER | ACCESS_TRUNCATE,
        _ => ABI1_ACCESS | ACCESS_REFER | ACCESS_TRUNCATE | ACCESS_IOCTL_DEV,
    }
}

/// `LANDLOCK_ACCESS_NET_BIND_TCP` (ABI 4, Linux 6.7).
pub const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
/// `LANDLOCK_ACCESS_NET_CONNECT_TCP` (ABI 4).
pub const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

/// The network rights the ruleset handles on ABI `abi`: TCP bind and
/// connect from ABI 4, with no rule granting any port (the run uses
/// AF_XDP, netlink, and a Unix datagram socket, never TCP). Defence in
/// depth for `--seccomp log|off`, under which `socket` is not limited.
pub const fn handled_net_access(abi: u32) -> u64 {
    if abi >= 4 {
        ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
    } else {
        0
    }
}

/// How broad a config directory is (by its canonical path).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryScope {
    /// `/`: granting it would let the router read every file its user may
    /// read; refused.
    Root,
    /// A well-known shared directory: allowed, with a warning naming it.
    Broad(&'static str),
    /// Anything else (the recommended `/etc/ruster`).
    Dedicated,
}

/// Directories warned as broad: they hold many unrelated files (`/etc`
/// holds `/etc/shadow`).
pub const BROAD_DIRECTORIES: [&str; 5] = ["/etc", "/home", "/root", "/usr", "/var"];

/// The scope of a config directory from its canonical (absolute, resolved)
/// path.
pub fn classify_directory(canonical: &Path) -> DirectoryScope {
    if canonical == Path::new("/") {
        return DirectoryScope::Root;
    }
    BROAD_DIRECTORIES
        .iter()
        .find(|broad| canonical == Path::new(broad))
        .map_or(DirectoryScope::Dedicated, |broad| {
            DirectoryScope::Broad(broad)
        })
}

/// The startup warning for a broad config directory: a fixed name of
/// [`BROAD_DIRECTORIES`] (`'static` by type, never the operator's path, so
/// the line stays value-free and its `directory=` field cannot carry
/// operator text into the JSON log).
pub fn broad_warning(directory: &'static str) -> String {
    format!(
        "warning: fs-confine code=CONFIG_DIRECTORY_BROAD directory={directory}: every file \
         beneath it that the process's user may read stays readable; keep the config in a \
         directory of its own (such as /etc/ruster)"
    )
}

/// One rule of the ruleset: what it grants beneath.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Grant {
    /// The config file's directory, as the path names it.
    ConfigDirectory,
    /// The directory of the file the config path resolves to, when it is
    /// another directory (a symlinked config).
    ConfigTarget,
    /// `/proc/<pid>` of this process.
    Process,
    /// `/proc/sys/net`.
    NetSysctls,
    /// The executable (backtrace symbols).
    Executable,
}

impl Grant {
    /// The rights granted beneath it: reading files, and for the process
    /// directory also listing (`/proc/self/task`).
    pub const fn access(self) -> u64 {
        match self {
            Self::Process => ACCESS_READ_FILE | ACCESS_READ_DIR,
            Self::ConfigDirectory | Self::ConfigTarget | Self::NetSysctls | Self::Executable => {
                ACCESS_READ_FILE
            }
        }
    }
}

/// The directory of the config file as `path` names it: its parent, or
/// `.` for a bare file name (the run never changes its working
/// directory).
pub fn config_directory(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The step of the confinement that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsStep {
    /// `landlock_create_ruleset` with `LANDLOCK_CREATE_RULESET_VERSION`.
    Abi,
    /// `landlock_create_ruleset` of the ruleset.
    Ruleset,
    /// Opening (`O_PATH`) the path of a grant.
    Open(Grant),
    /// `landlock_add_rule` of a grant.
    AddRule(Grant),
    /// `PR_SET_NO_NEW_PRIVS` 1 (Landlock needs it without
    /// `CAP_SYS_ADMIN`).
    NoNewPrivs,
    /// `landlock_restrict_self`.
    Restrict,
    /// The self-check (listing `/`) failed otherwise than with `EACCES`.
    Probe,
}

/// What showed that a thread is not confined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unconfined {
    /// The thread could list `/` after its confinement.
    Probe,
    /// The threads that confined themselves are not exactly the threads
    /// of the process.
    Threads,
}

/// Why the confinement failed. Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsFailure {
    /// The kernel has no Landlock (`ENOSYS`: before Linux 5.13 or built
    /// without it).
    Unsupported,
    /// Landlock is built in but not enabled (`EOPNOTSUPP`: not in the
    /// boot `lsm=` list).
    Disabled,
    /// The Landlock calls are refused with `EPERM` (a supervisor's syscall
    /// filter, a container runtime).
    Blocked,
    /// The config directory (as named or as resolved) is `/`.
    ConfigDirectoryRoot,
    /// A step failed with this errno.
    Syscall { step: FsStep, errno: i32 },
    /// The router thread found no prepared ruleset.
    NotPrepared,
    /// A thread is not confined.
    NotConfined(Unconfined),
    /// `/proc/self/task` could not be listed.
    Unreadable,
    /// A failure injected by a test host.
    #[cfg(test)]
    Injected,
}

impl FsFailure {
    /// The advice printed after the failure line, if any.
    pub const fn hint(self) -> Option<&'static str> {
        match self {
            Self::Unsupported | Self::Disabled => Some(
                "--fs-confine landlock needs Landlock (Linux 5.13 or newer with landlock in \
                 /sys/kernel/security/lsm); --fs-confine off runs without filesystem \
                 confinement",
            ),
            Self::Blocked => Some(
                "the Landlock calls were refused (EPERM): allow landlock_create_ruleset, \
                 landlock_add_rule, and landlock_restrict_self in the supervisor's syscall \
                 filter, or --fs-confine off runs without filesystem confinement",
            ),
            Self::ConfigDirectoryRoot => Some(
                "the config's directory is /, which would leave every file readable: keep the \
                 config in a directory of its own (such as /etc/ruster), or --fs-confine off \
                 runs without filesystem confinement",
            ),
            _ => None,
        }
    }
}

impl fmt::Display for FsFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use super::startup::token;
        match self {
            Self::Unsupported => formatter.write_str("code=LANDLOCK_UNSUPPORTED"),
            Self::Disabled => formatter.write_str("code=LANDLOCK_DISABLED"),
            Self::Blocked => formatter.write_str("code=LANDLOCK_BLOCKED"),
            Self::ConfigDirectoryRoot => formatter.write_str("code=CONFIG_DIRECTORY_ROOT"),
            Self::Syscall { step, errno } => {
                write!(formatter, "code={}/ERRNO_{errno}", token(step))
            }
            Self::NotPrepared => formatter.write_str("code=NOT_PREPARED"),
            Self::NotConfined(what) => write!(formatter, "code=NOT_CONFINED/{}", token(what)),
            Self::Unreadable => formatter.write_str("code=STATUS_UNREADABLE"),
            #[cfg(test)]
            Self::Injected => formatter.write_str("code=INJECTED"),
        }
    }
}

/// The process-wide check after the router thread confined itself: the
/// ids of the threads that confined themselves (`confined`) must be
/// exactly the ids `/proc/self/task` lists (`tasks`, not empty).
pub fn check_threads(confined: &BTreeSet<u32>, tasks: &BTreeSet<u32>) -> Result<(), FsFailure> {
    if tasks.is_empty() {
        return Err(FsFailure::Unreadable);
    }
    if confined != tasks {
        return Err(FsFailure::NotConfined(Unconfined::Threads));
    }
    Ok(())
}

/// The outcome of a successful confinement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsReport {
    /// The kernel's Landlock ABI.
    pub abi: u32,
    /// Rules of the ruleset.
    pub rules: u32,
    /// Threads confined (every thread of the process).
    pub threads: u32,
}

/// The filesystem confinement of the running router, for the startup line
/// and the stats blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsState {
    Confined(FsReport),
    /// `--fs-confine off`.
    Off,
}

impl FsState {
    /// The value-free startup line.
    pub fn line(self) -> String {
        match self {
            Self::Confined(report) => format!(
                "filesystem confined: mode=landlock abi={} rules={} threads={}",
                report.abi, report.rules, report.threads
            ),
            Self::Off => "warning: fs-confine=off (--fs-confine off): no filesystem \
                          confinement; every file the process's user may read stays readable"
                .to_owned(),
        }
    }
}

impl ObservableFields for FsState {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "fs";
        let (mode, report) = match self {
            Self::Confined(report) => (FsConfineMode::Landlock, *report),
            Self::Off => (
                FsConfineMode::Off,
                FsReport {
                    abi: 0,
                    rules: 0,
                    threads: 0,
                },
            ),
        };
        visitor.field(SECTION, "confine", FieldValue::Label(mode.label()));
        visitor.field(SECTION, "abi", FieldValue::Count(u64::from(report.abi)));
        visitor.field(SECTION, "rules", FieldValue::Count(u64::from(report.rules)));
        visitor.field(
            SECTION,
            "threads",
            FieldValue::Count(u64::from(report.threads)),
        );
    }
}

/// The live confinement: x86_64 Linux only (x86_64 syscall numbers).
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub mod linux {
    use std::collections::BTreeSet;
    use std::fs::{self, File, OpenOptions};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    use super::{
        check_threads, classify_directory, config_directory, handled_access, handled_net_access,
        DirectoryScope, FsFailure, FsReport, FsStep, Grant, Unconfined,
    };

    /// `O_PATH` (x86_64): a handle on the path only, no read access.
    const O_PATH: i32 = 0o10_000_000;
    /// `O_DIRECTORY`.
    const O_DIRECTORY: i32 = 0o200_000;
    const EACCES: i32 = 13;
    const EEXIST: i32 = 17;

    /// The ruleset of the process, built once before any other thread.
    static PREPARED: OnceLock<Prepared> = OnceLock::new();
    /// Ids of the threads that confined themselves with it (startup only;
    /// never touched by the run loop).
    static CONFINED: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

    /// A built ruleset and the `O_PATH` fds of its rules, which stay open
    /// as long as it does (see the module documentation: a held procfs
    /// dentry keeps its inode).
    pub struct Prepared {
        ruleset: OwnedFd,
        _pins: Vec<OwnedFd>,
        abi: u32,
        rules: u32,
        broad: Option<&'static str>,
    }

    fn open_path(grant: Grant, path: &Path, directory: bool) -> Result<OwnedFd, FsFailure> {
        let flags = if directory {
            O_PATH | O_DIRECTORY
        } else {
            O_PATH
        };
        OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .map(OwnedFd::from)
            .map_err(|error| FsFailure::Syscall {
                step: FsStep::Open(grant),
                errno: error.raw_os_error().unwrap_or(0),
            })
    }

    /// The scope of a config directory, refusing `/`. An unresolvable
    /// directory is the open failure of `grant`.
    fn scope(grant: Grant, directory: &Path) -> Result<Option<&'static str>, FsFailure> {
        let canonical = fs::canonicalize(directory).map_err(|error| FsFailure::Syscall {
            step: FsStep::Open(grant),
            errno: error.raw_os_error().unwrap_or(0),
        })?;
        match classify_directory(&canonical) {
            DirectoryScope::Root => Err(FsFailure::ConfigDirectoryRoot),
            DirectoryScope::Broad(name) => Ok(Some(name)),
            DirectoryScope::Dedicated => Ok(None),
        }
    }

    /// The id of the calling thread (`/proc/thread-self` links to
    /// `<pid>/task/<tid>`; reading a link is not a Landlock access).
    fn own_tid() -> Result<u32, FsFailure> {
        fs::read_link("/proc/thread-self")
            .ok()
            .and_then(|link| link.file_name()?.to_str()?.parse().ok())
            .ok_or(FsFailure::Unreadable)
    }

    /// `(device, inode)` of an `O_PATH` fd.
    fn identity(fd: &OwnedFd) -> Option<(u64, u64)> {
        let file = File::from(fd.try_clone().ok()?);
        let metadata = file.metadata().ok()?;
        Some((metadata.dev(), metadata.ino()))
    }

    impl Prepared {
        /// Builds the ruleset for the config at `config` (as given on the
        /// command line). Fails with [`FsFailure::Unsupported`] or
        /// [`FsFailure::Disabled`] without Landlock.
        pub fn new(config: &Path) -> Result<Self, FsFailure> {
            // `/` first: refused whatever the kernel offers.
            let named_scope = scope(Grant::ConfigDirectory, &config_directory(config))?;
            let resolved = fs::canonicalize(config).map_err(|error| FsFailure::Syscall {
                step: FsStep::Open(Grant::ConfigTarget),
                errno: error.raw_os_error().unwrap_or(0),
            })?;
            let target_scope = scope(Grant::ConfigTarget, &config_directory(&resolved))?;
            let abi = match sys::abi() {
                Ok(abi) if abi >= 1 => abi,
                Ok(_) | Err(sys::ENOSYS) => return Err(FsFailure::Unsupported),
                Err(sys::EOPNOTSUPP) => return Err(FsFailure::Disabled),
                Err(sys::EPERM) => return Err(FsFailure::Blocked),
                Err(errno) => {
                    return Err(FsFailure::Syscall {
                        step: FsStep::Abi,
                        errno,
                    })
                }
            };
            let handled = handled_access(abi);
            let ruleset =
                sys::create_ruleset(handled, handled_net_access(abi)).map_err(|errno| {
                    FsFailure::Syscall {
                        step: FsStep::Ruleset,
                        errno,
                    }
                })?;
            let mut prepared = Self {
                ruleset,
                _pins: Vec::new(),
                abi,
                rules: 0,
                broad: named_scope.or(target_scope),
            };
            let directory = open_path(Grant::ConfigDirectory, &config_directory(config), true)?;
            let named = identity(&directory);
            prepared.add(Grant::ConfigDirectory, directory, handled)?;
            let target = open_path(Grant::ConfigTarget, &config_directory(&resolved), true)?;
            if named.is_none() || identity(&target) != named {
                prepared.add(Grant::ConfigTarget, target, handled)?;
            }
            // `/proc/self` resolves to `/proc/<pid>` of this process.
            let process = open_path(Grant::Process, Path::new("/proc/self"), true)?;
            prepared.add(Grant::Process, process, handled)?;
            let sysctls = open_path(Grant::NetSysctls, Path::new("/proc/sys/net"), true)?;
            prepared.add(Grant::NetSysctls, sysctls, handled)?;
            // Optional: without it a panic backtrace has no symbols.
            if let Some(executable) = std::env::current_exe()
                .ok()
                .and_then(|path| open_path(Grant::Executable, &path, false).ok())
            {
                prepared.add(Grant::Executable, executable, handled)?;
            }
            Ok(prepared)
        }

        fn add(&mut self, grant: Grant, fd: OwnedFd, handled: u64) -> Result<(), FsFailure> {
            sys::add_path_rule(self.ruleset.as_fd(), fd.as_fd(), grant.access() & handled)
                .map_err(|errno| FsFailure::Syscall {
                    step: FsStep::AddRule(grant),
                    errno,
                })?;
            self._pins.push(fd);
            self.rules += 1;
            Ok(())
        }

        /// The kernel's Landlock ABI.
        pub const fn abi(&self) -> u32 {
            self.abi
        }

        /// Rules of the ruleset.
        pub const fn rules(&self) -> u32 {
            self.rules
        }

        /// The broad config directory ([`DirectoryScope::Broad`]) to warn
        /// about, if any.
        pub const fn broad(&self) -> Option<&'static str> {
            self.broad
        }

        /// Confines the calling thread (only) with the ruleset, then checks
        /// it: listing `/` must now fail with `EACCES`. Sets
        /// `no_new_privs` first (Landlock needs it without
        /// `CAP_SYS_ADMIN`; the drop has set it already, and the syscall
        /// filter sets it anyway).
        pub fn restrict_thread(&self) -> Result<(), FsFailure> {
            sys::set_no_new_privs().map_err(|errno| FsFailure::Syscall {
                step: FsStep::NoNewPrivs,
                errno,
            })?;
            sys::restrict_self(self.ruleset.as_fd()).map_err(|errno| FsFailure::Syscall {
                step: FsStep::Restrict,
                errno,
            })?;
            probe()
        }
    }

    /// Listing `/` needs the read-dir right, which no rule grants there.
    pub(super) fn probe() -> Result<(), FsFailure> {
        match fs::read_dir("/") {
            Ok(_) => Err(FsFailure::NotConfined(Unconfined::Probe)),
            Err(error) if error.raw_os_error() == Some(EACCES) => Ok(()),
            Err(error) => Err(FsFailure::Syscall {
                step: FsStep::Probe,
                errno: error.raw_os_error().unwrap_or(0),
            }),
        }
    }

    /// Builds the process's ruleset for the config at `config` and returns
    /// the broad config directory to warn about, if any. Call it once, on
    /// the only thread, before any thread runs [`restrict_thread`].
    pub fn prepare_process(config: &Path) -> Result<Option<&'static str>, FsFailure> {
        let prepared = Prepared::new(config)?;
        let broad = prepared.broad();
        // A second ruleset would be refused like an existing file.
        PREPARED.set(prepared).map_err(|_| FsFailure::Syscall {
            step: FsStep::Ruleset,
            errno: EEXIST,
        })?;
        Ok(broad)
    }

    /// Records the calling (confined) thread's id.
    fn record() -> Result<(), FsFailure> {
        let tid = own_tid()?;
        CONFINED
            .lock()
            .map_err(|_| FsFailure::Unreadable)?
            .insert(tid);
        Ok(())
    }

    /// The prologue step of a thread: confines the calling thread with the
    /// process's ruleset, if [`prepare_process`] built one (nothing with
    /// `--fs-confine off`), and counts it.
    pub fn restrict_thread() -> Result<(), FsFailure> {
        let Some(prepared) = PREPARED.get() else {
            return Ok(());
        };
        prepared.restrict_thread()?;
        record()
    }

    /// The router thread's step after its privilege drop: confines itself,
    /// then requires every thread of the process (`/proc/self/task`) to
    /// have confined itself.
    pub fn restrict_process() -> Result<FsReport, FsFailure> {
        let prepared = PREPARED.get().ok_or(FsFailure::NotPrepared)?;
        prepared.restrict_thread()?;
        record()?;
        let mut tasks = BTreeSet::new();
        for task in fs::read_dir("/proc/self/task").map_err(|_| FsFailure::Unreadable)? {
            let task = task.map_err(|_| FsFailure::Unreadable)?;
            let tid = task
                .file_name()
                .to_str()
                .and_then(|name| name.parse().ok())
                .ok_or(FsFailure::Unreadable)?;
            tasks.insert(tid);
        }
        let confined = CONFINED.lock().map_err(|_| FsFailure::Unreadable)?.clone();
        check_threads(&confined, &tasks)?;
        let threads = u32::try_from(tasks.len()).unwrap_or(u32::MAX);
        Ok(FsReport {
            abi: prepared.abi(),
            rules: prepared.rules(),
            threads,
        })
    }

    /// Raw Landlock and `prctl` syscalls (x86_64 numbers; the C library
    /// has no Landlock wrappers).
    #[allow(unsafe_code)]
    pub(super) mod sys {
        use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
        use std::os::raw::c_long;

        const SYS_PRCTL: c_long = 157;
        const SYS_LANDLOCK_CREATE_RULESET: c_long = 444;
        const SYS_LANDLOCK_ADD_RULE: c_long = 445;
        const SYS_LANDLOCK_RESTRICT_SELF: c_long = 446;
        const PR_SET_NO_NEW_PRIVS: c_long = 38;
        const LANDLOCK_CREATE_RULESET_VERSION: c_long = 1;
        const LANDLOCK_RULE_PATH_BENEATH: c_long = 1;
        pub const ENOSYS: i32 = 38;
        pub const EOPNOTSUPP: i32 = 95;
        pub const EPERM: i32 = 1;

        /// `struct landlock_ruleset_attr` up to `handled_access_net` (the
        /// kernel accepts a prefix of the struct; nothing scope related is
        /// handled). Only the first field is passed before ABI 4.
        #[repr(C)]
        struct RulesetAttr {
            handled_access_fs: u64,
            handled_access_net: u64,
        }

        /// `struct landlock_path_beneath_attr` (packed: 12 bytes).
        #[repr(C, packed)]
        struct PathBeneathAttr {
            allowed_access: u64,
            parent_fd: i32,
        }

        const _: () = assert!(std::mem::size_of::<RulesetAttr>() == 16);
        const _: () = assert!(std::mem::size_of::<PathBeneathAttr>() == 12);

        extern "C" {
            // `long syscall(long number, ...)` from the C library std
            // already links (glibc or musl); it passes up to six
            // `long`-sized arguments to the kernel and returns -1 with
            // `errno` set on failure.
            fn syscall(number: c_long, ...) -> c_long;
        }

        fn errno() -> i32 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        }

        fn checked(value: c_long) -> Result<c_long, i32> {
            if value == -1 {
                Err(errno())
            } else {
                Ok(value)
            }
        }

        /// The kernel's Landlock ABI version.
        pub fn abi() -> Result<u32, i32> {
            // SAFETY: with `LANDLOCK_CREATE_RULESET_VERSION` the kernel
            // requires a null attribute pointer and size 0 and reads no
            // memory; it returns the ABI version.
            let value = checked(unsafe {
                syscall(
                    SYS_LANDLOCK_CREATE_RULESET,
                    std::ptr::null::<u8>(),
                    0_i64,
                    LANDLOCK_CREATE_RULESET_VERSION,
                )
            })?;
            Ok(u32::try_from(value).unwrap_or(0))
        }

        /// A new ruleset handling `handled` filesystem and `net` network
        /// rights (close-on-exec fd).
        pub fn create_ruleset(handled: u64, net: u64) -> Result<OwnedFd, i32> {
            let attr = RulesetAttr {
                handled_access_fs: handled,
                handled_access_net: net,
            };
            // A kernel before ABI 4 refuses a nonzero byte past the struct
            // it knows: pass only the filesystem field then.
            let size = if net == 0 {
                std::mem::size_of::<u64>()
            } else {
                std::mem::size_of::<RulesetAttr>()
            };
            // SAFETY: `attr` is a live, initialized `repr(C)` struct at least
            // `size` bytes long; the kernel only reads those bytes during
            // the call.
            let fd = checked(unsafe {
                syscall(
                    SYS_LANDLOCK_CREATE_RULESET,
                    (&raw const attr).cast::<u8>(),
                    size as c_long,
                    0_i64,
                )
            })?;
            let fd = i32::try_from(fd).map_err(|_| 9)?;
            // SAFETY: the kernel returned a new fd that nothing else owns;
            // ownership moves into the `OwnedFd` (closed on drop).
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }

        /// Adds a path-beneath rule granting `access` beneath `parent`.
        pub fn add_path_rule(
            ruleset: BorrowedFd<'_>,
            parent: BorrowedFd<'_>,
            access: u64,
        ) -> Result<(), i32> {
            let attr = PathBeneathAttr {
                allowed_access: access,
                parent_fd: parent.as_raw_fd(),
            };
            // SAFETY: `attr` is a live, initialized packed `repr(C)` struct
            // (the kernel's layout, 12 bytes) that the kernel only reads
            // during the call; both fds are borrowed, open for the call.
            checked(unsafe {
                syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    c_long::from(ruleset.as_raw_fd()),
                    LANDLOCK_RULE_PATH_BENEATH,
                    (&raw const attr).cast::<u8>(),
                    0_i64,
                )
            })
            .map(drop)
        }

        /// `PR_SET_NO_NEW_PRIVS` 1 on the calling thread.
        pub fn set_no_new_privs() -> Result<(), i32> {
            // SAFETY: `prctl` with this option reads only its integer
            // arguments (the unused ones are passed as 0, as the kernel
            // requires); no memory is passed.
            checked(unsafe { syscall(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1_i64, 0_i64, 0_i64, 0_i64) })
                .map(drop)
        }

        /// Confines the calling thread with `ruleset`.
        pub fn restrict_self(ruleset: BorrowedFd<'_>) -> Result<(), i32> {
            // SAFETY: integer arguments only (a borrowed, open fd and flags
            // 0); no memory is passed.
            checked(unsafe {
                syscall(
                    SYS_LANDLOCK_RESTRICT_SELF,
                    c_long::from(ruleset.as_raw_fd()),
                    0_i64,
                )
            })
            .map(drop)
        }
    }
}

#[cfg(test)]
#[path = "fs_confine_tests.rs"]
mod tests;

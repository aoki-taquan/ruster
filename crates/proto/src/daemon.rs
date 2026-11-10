//! What each process's `main` shares: where the sockets are, listening and connecting,
//! the clock, and waiting while idle.
//!
//! Every socket lives under one directory (`/run/ruster` by default), at the paths in
//! [`socket`] (`docs/design/control-protocol.md`). The process that serves a table
//! listens; the processes that write or read it connect. A listener creates the
//! directories it needs and removes a socket file left behind by an earlier run before
//! it binds. Next to each socket it holds a lock on `<socket>.lock` until it exits;
//! when another process holds that lock, the same process is already running, and the
//! listener stops instead of taking the path over.
//!
//! Whoever may open these sockets may change the tables or read the configuration
//! (PPPoE passwords included), so only the router's processes may reach them. File
//! permissions do this, whatever the umask:
//!
//! - A directory the listener creates gets mode 0750 ([`DIR_MODE`]): the owner and the
//!   group may enter, others may not.
//! - Each socket gets mode 0660 ([`SOCKET_MODE`]): the owner and the group may connect
//!   (connecting needs write permission on the socket file), others may not.
//! - The group is the one Linux gives a new file: the group of its directory when that
//!   directory has the set-group-ID bit, otherwise the process's group. A directory the
//!   listener creates inside a set-group-ID directory keeps that bit, so one group
//!   set on the top directory reaches every socket under it.
//!
//! When every process runs as root (as in the netns scripts), the group is root's and
//! nothing else is needed. When they run as different users, the top directory is made
//! beforehand with the set-group-ID bit and a group shared by the router's processes
//! (`docs/design/ce-processes.md`, "socketの権限").

use std::io::{self, ErrorKind};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::task::Progress;

/// The socket directory when none is given.
pub const DEFAULT_RUN_DIR: &str = "/run/ruster";

/// The mode of a directory a listener creates: the owner and the group may enter.
pub const DIR_MODE: u32 = 0o750;

/// The mode of each socket file: the owner and the group may connect.
pub const SOCKET_MODE: u32 = 0o660;

/// Socket file names inside the socket directory.
pub mod socket {
    /// The FE's table server for interfaces and addresses (written by confd).
    pub const FE_CONFIG: &str = "fe/config.sock";
    /// The FE's table server for routes (written by ribd).
    pub const FE_ROUTE: &str = "fe/route.sock";
    /// The FE's table server for neighbors (written by neighd).
    pub const FE_NEIGHBOR: &str = "fe/neigh.sock";
    /// The FE's read-only socket: every table, and notifications.
    pub const FE_STATE: &str = "fe/state.sock";
    /// The FE's datagram socket for frames to and from the CE.
    pub const FE_PUNT: &str = "fe/punt/arp-nd.sock";
    /// neighd's datagram socket for frames from the FE.
    pub const NEIGHD_PUNT: &str = "neighd/punt.sock";
    /// neighd's table server for interfaces and addresses (written by confd).
    pub const NEIGHD_CONFIG: &str = "neighd/config.sock";
    /// confd's socket for a new configuration file (from `ruster apply`).
    pub const CONFD_CONFIG: &str = "confd/config.sock";
    /// confd's socket where each process takes its part of the configuration.
    pub const CONFD_PART: &str = "confd/part.sock";

    /// The FE's datagram socket for frames to and from the control process `name`
    /// of a punt class (other than neighd).
    pub fn fe_punt(name: &str) -> String {
        format!("fe/punt/{name}.sock")
    }

    /// The datagram socket the control process `name` takes frames from the FE on.
    pub fn control_punt(name: &str) -> String {
        format!("{name}/punt.sock")
    }

    /// confd's table server for the source `name` (values found at run time).
    pub fn confd_source(name: &str) -> String {
        format!("confd/source/{name}.sock")
    }

    /// ribd's table server for the route source `name`.
    pub fn ribd_source(name: &str) -> String {
        format!("ribd/source/{name}.sock")
    }
}

/// Milliseconds since the process started.
#[derive(Debug)]
pub struct Clock(Instant);

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    pub fn new() -> Self {
        Self(Instant::now())
    }

    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Creates the directories above `path` and removes a socket file left by an earlier
/// run. Anything else at `path` is an error.
fn remove_stale(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    if let Some(parent) = path.parent() {
        create_dirs(parent)?;
    }
    take_lock(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!("{} exists and is not a socket", path.display()),
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Creates `dir` and the directories above it that are missing, each with
/// [`DIR_MODE`] whatever the umask. A directory that is already there is left as it is.
fn create_dirs(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_dirs(parent)?;
    }
    match std::fs::DirBuilder::new().mode(DIR_MODE).create(dir) {
        Ok(()) => {}
        // Another process made it in the meantime.
        Err(error) if error.kind() == ErrorKind::AlreadyExists && dir.is_dir() => return Ok(()),
        Err(error) => return Err(error),
    }
    // The umask may have taken bits away. The set-group-ID bit Linux copies from the
    // parent stays.
    let mode = std::fs::metadata(dir)?.permissions().mode();
    let wanted = (mode & 0o7000) | DIR_MODE;
    if mode & 0o7777 != wanted {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(wanted))?;
    }
    Ok(())
}

/// Gives the socket at `path` [`SOCKET_MODE`], whatever the umask.
fn set_socket_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
}

/// The locks this process holds, one per socket path, kept until it exits.
static LOCKS: Mutex<Vec<(PathBuf, std::fs::File)>> = Mutex::new(Vec::new());

/// Locks `<path>.lock`, once per process. Binding the same path again later (for
/// example after a peer restarted) keeps the lock already held.
fn take_lock(path: &Path) -> io::Result<()> {
    let mut locks = LOCKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if locks.iter().any(|(held, _)| held == path) {
        return Ok(());
    }
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .mode(0o600)
        .create(true)
        .truncate(false)
        .write(true)
        .open(&name)?;
    match file.try_lock() {
        Ok(()) => {
            locks.push((path.to_path_buf(), file));
            Ok(())
        }
        Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
            ErrorKind::AddrInUse,
            format!(
                "{} is in use; is the process already running?",
                path.display()
            ),
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

/// A non-blocking listening stream socket at `path`.
pub fn listen(path: &Path) -> io::Result<UnixListener> {
    remove_stale(path)?;
    let listener = UnixListener::bind(path)?;
    set_socket_mode(path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// A non-blocking datagram socket bound at `path`.
pub fn bind_datagram(path: &Path) -> io::Result<UnixDatagram> {
    remove_stale(path)?;
    let socket = UnixDatagram::bind(path)?;
    set_socket_mode(path)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Every connection waiting on `listener`. An error (for example too many open files)
/// ends this round; the listener is tried again on the next one. The error is
/// written to standard error once, until it changes or accepting works again.
pub fn accept(listener: &UnixListener) -> Vec<UnixStream> {
    let mut streams = Vec::new();
    loop {
        match listener.accept() {
            Ok((stream, _)) => streams.push(stream),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                *LAST_ACCEPT_ERROR
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                return streams;
            }
            Err(error) => {
                // Written once until it changes or an accept works again, not every
                // round.
                let mut last = LAST_ACCEPT_ERROR
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if *last != Some(error.kind()) {
                    eprintln!("accepting a connection: {error}; tried again next round");
                    *last = Some(error.kind());
                }
                return streams;
            }
        }
    }
}

/// The kind of the last accept error written, so that it is written once.
static LAST_ACCEPT_ERROR: Mutex<Option<ErrorKind>> = Mutex::new(None);

/// How often a connection to a process that is not up yet is tried again.
const RETRY: Duration = Duration::from_millis(50);

fn not_up_yet(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::NotFound | ErrorKind::ConnectionRefused
    )
}

/// Connects to `path`, trying again while the listener is not up yet, for at most `wait`.
pub fn connect(path: &Path, wait: Duration) -> io::Result<UnixStream> {
    let start = Instant::now();
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error) if not_up_yet(&error) && start.elapsed() < wait => thread::sleep(RETRY),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{}: {error}", path.display()),
                ))
            }
        }
    }
}

/// Connects the datagram `socket` to `path`, trying again like [`connect`].
pub fn connect_datagram(socket: &UnixDatagram, path: &Path, wait: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        match socket.connect(path) {
            Ok(()) => return Ok(()),
            Err(error) if not_up_yet(&error) && start.elapsed() < wait => thread::sleep(RETRY),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{}: {error}", path.display()),
                ))
            }
        }
    }
}

/// Tells systemd (a `Type=notify` service) that the process is ready, or is stopping:
/// one datagram to `$NOTIFY_SOCKET` (sd_notify(3)). Without that variable it does
/// nothing. An address starting with `@` is in the abstract namespace.
pub fn notify(state: &str) {
    let Some(address) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let Ok(socket) = UnixDatagram::unbound() else {
        return;
    };
    let bytes = address.as_encoded_bytes();
    let _ = if let Some(name) = bytes.strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt;
        std::os::unix::net::SocketAddr::from_abstract_name(name)
            .and_then(|to| socket.send_to_addr(state.as_bytes(), &to))
    } else {
        socket.send_to(state.as_bytes(), Path::new(&address))
    };
}

/// How often a closed connection is tried again.
pub const RECONNECT_EVERY_MS: u64 = 1_000;

/// Paces attempts to connect again after a connection closed.
#[derive(Debug, Default)]
pub struct Retry {
    next_at: u64,
}

impl Retry {
    /// True when an attempt is due at `now_ms`; the next one is then a second later.
    pub fn due(&mut self, now_ms: u64) -> bool {
        if now_ms < self.next_at {
            return false;
        }
        self.next_at = now_ms.saturating_add(RECONNECT_EVERY_MS);
        true
    }
}

/// One attempt to connect to `path`, without waiting.
pub fn try_connect(path: &Path) -> Option<UnixStream> {
    UnixStream::connect(path).ok()
}

/// How long the FE waits for frames while idle, so that new connections and socket
/// input are noticed soon. The control-plane processes use [`Idle`].
pub const IDLE_MAX: Duration = Duration::from_millis(IDLE_MAX_MS as u64);
/// [`IDLE_MAX`] in milliseconds.
pub const IDLE_MAX_MS: u32 = 1;

/// How long a process waits between steps while it has nothing to do: not at all
/// after a step with work, then 1 ms, doubling while it stays idle up to a limit. A
/// process that waits for nothing does not wake a thousand times a second.
#[derive(Debug)]
pub struct Idle {
    next_ms: u32,
    longest_ms: u32,
}

impl Default for Idle {
    fn default() -> Self {
        Self::new()
    }
}

impl Idle {
    /// For a control-plane process: up to 8 ms.
    pub fn new() -> Self {
        Self::up_to(8)
    }

    /// Up to `longest_ms` (at least 1).
    pub fn up_to(longest_ms: u32) -> Self {
        Self {
            next_ms: 0,
            longest_ms: longest_ms.max(1),
        }
    }

    /// How long to wait after a step, in milliseconds; `None` after a busy one.
    pub fn after(&mut self, busy: bool) -> Option<u32> {
        if busy {
            self.next_ms = 0;
            return None;
        }
        self.next_ms = self.next_ms();
        Some(self.next_ms)
    }

    /// Sleeps when `progress` found nothing to do.
    pub fn wait(&mut self, progress: Progress) {
        if let Some(ms) = self.after(progress.busy) {
            thread::sleep(Duration::from_millis(u64::from(ms)));
        }
    }

    /// The wait the next idle step takes, in milliseconds.
    pub fn next_ms(&self) -> u32 {
        self.next_ms.saturating_mul(2).clamp(1, self.longest_ms)
    }
}

/// Reads `--run-dir DIR` (and the other arguments a process takes) from the command
/// line. Returns the socket directory and the remaining arguments in order.
pub fn run_dir_and_rest(
    args: impl IntoIterator<Item = String>,
) -> Result<(PathBuf, Vec<String>), String> {
    let mut run_dir = PathBuf::from(DEFAULT_RUN_DIR);
    let mut rest = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--run-dir" {
            run_dir = args
                .next()
                .ok_or_else(|| "--run-dir needs a directory".to_owned())?
                .into();
        } else {
            rest.push(arg);
        }
    }
    Ok((run_dir, rest))
}

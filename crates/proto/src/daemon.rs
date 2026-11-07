//! What each process's `main` shares: where the sockets are, listening and connecting,
//! the clock, and waiting while idle.
//!
//! Every socket lives under one directory (`/run/ruster` by default), at the paths in
//! [`socket`] (`docs/design/control-protocol.md`). The process that serves a table
//! listens; the processes that write or read it connect. A listener creates the
//! directories it needs (readable by the owner only) and removes a socket file left behind by an earlier run before
//! it binds. Whoever may open these sockets may change the tables, so the directory
//! must be reachable only by the router's processes.

use std::io::{self, ErrorKind};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::task::Progress;

/// The socket directory when none is given.
pub const DEFAULT_RUN_DIR: &str = "/run/ruster";

/// Socket file names inside the socket directory.
pub mod socket {
    /// The FE's table server for interfaces and addresses (written by confd).
    pub const FE_CONFIG: &str = "fe/config.sock";
    /// The FE's table server for routes (written by ribd).
    pub const FE_ROUTE: &str = "fe/route.sock";
    /// The FE's table server for neighbors (written by neighd).
    pub const FE_NEIGHBOR: &str = "fe/neigh.sock";
    /// The FE's datagram socket for frames to and from the CE.
    pub const FE_PUNT: &str = "fe/punt/arp-nd.sock";
    /// neighd's datagram socket for frames from the FE.
    pub const NEIGHD_PUNT: &str = "neighd/punt.sock";
    /// neighd's table server for interfaces and addresses (written by confd).
    pub const NEIGHD_CONFIG: &str = "neighd/config.sock";

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
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
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

/// A non-blocking listening stream socket at `path`.
pub fn listen(path: &Path) -> io::Result<UnixListener> {
    remove_stale(path)?;
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// A non-blocking datagram socket bound at `path`.
pub fn bind_datagram(path: &Path) -> io::Result<UnixDatagram> {
    remove_stale(path)?;
    let socket = UnixDatagram::bind(path)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Every connection waiting on `listener`. An error (for example too many open files)
/// ends this round; the listener is tried again on the next one.
pub fn accept(listener: &UnixListener) -> Vec<UnixStream> {
    let mut streams = Vec::new();
    loop {
        match listener.accept() {
            Ok((stream, _)) => streams.push(stream),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return streams,
        }
    }
}

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

/// The longest a process sleeps while idle, so that new connections and socket input
/// are noticed soon.
pub const IDLE_MAX: Duration = Duration::from_millis(IDLE_MAX_MS as u64);
/// [`IDLE_MAX`] in milliseconds.
pub const IDLE_MAX_MS: u32 = 1;

/// Sleeps [`IDLE_MAX`] when the last step found nothing to do.
pub fn idle(progress: Progress) {
    if !progress.busy {
        thread::sleep(IDLE_MAX);
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

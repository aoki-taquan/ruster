//! systemd service notification of `ruster run` (`sd_notify` protocol,
//! H10, CLI-117 to CLI-121).
//!
//! Only when the service manager set `NOTIFY_SOCKET`. At the very start of
//! `ruster run`, before any thread exists, [`Notifier::from_process_env`]
//! reads `NOTIFY_SOCKET`, `WATCHDOG_USEC`, and `WATCHDOG_PID`, removes them
//! from the environment (setting the environment is not thread safe, and
//! nothing later should see them), validates them ([`parse`]), and opens
//! one unbound, non-blocking, close-on-exec `AF_UNIX` datagram socket. So
//! every later notification is a single `sendto` on that existing fd: the
//! syscall filter of section 5 (seccomp) already allows `sendto`, and no
//! socket is created after startup. A notification never blocks the
//! router: a full receive queue (`EAGAIN`) or a missing listener only
//! counts in `notify.failed`.
//!
//! | when | message |
//! |---|---|
//! | generation 1 active, privileges dropped, seccomp installed (the stderr readiness line) | `READY=1`, `STATUS=running generation N` |
//! | a SIGHUP reload starts | `RELOADING=1`, `MONOTONIC_USEC=<CLOCK_MONOTONIC>` (omitted if the clock cannot be read), `STATUS=reloading (generation N)` |
//! | it ends (applied, refused, failed, abandoned) | `READY=1`, `STATUS=running generation N` |
//! | the run loop ends (signal, fatal event, backend stop) | `STOPPING=1`, `STATUS=stopping: <reason>` |
//! | `WATCHDOG_USEC` set (and `WATCHDOG_PID` unset or this process) | `WATCHDOG=1` every half of it, from the router loop |
//!
//! `MONOTONIC_USEC` lets systemd 253 and newer (`Type=notify-reload`) tell
//! this reload from an earlier one. The watchdog ping is sent by the
//! router thread between ticks, at the same cold point as the health
//! watch, so a router stuck inside a tick (or anywhere else) stops
//! pinging and systemd's watchdog acts. The status texts are value-free:
//! generation numbers, port labels, and fixed codes only.
//!
//! Every message is composed in a stack buffer: no allocation, also not
//! for the watchdog ping on the tick loop's cold path.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

use ruster_core::{FieldValue, FieldVisitor, MonotonicMillis, ObservableFields};

/// Longest `sun_path` (108 bytes with the terminating NUL; an abstract
/// name has no NUL but its leading zero byte).
const SUN_PATH_MAX: usize = 107;
/// Bytes of the stack buffer of one message.
const MESSAGE_MAX: usize = 192;

/// Why the notification environment is refused at startup. Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyError {
    /// `NOTIFY_SOCKET` is not an absolute path or an abstract name
    /// (`@name`), or too long for a `sockaddr_un`.
    InvalidSocket,
    /// `WATCHDOG_USEC` is not a positive decimal number.
    InvalidWatchdog,
    /// `WATCHDOG_PID` is not a positive decimal number.
    InvalidWatchdogPid,
    /// The socket could not be created or set non-blocking.
    Socket,
}

impl NotifyError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSocket => "NOTIFY_SOCKET_INVALID",
            Self::InvalidWatchdog => "WATCHDOG_USEC_INVALID",
            Self::InvalidWatchdogPid => "WATCHDOG_PID_INVALID",
            Self::Socket => "NOTIFY_SOCKET_OPEN",
        }
    }
}

impl fmt::Display for NotifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Where the notifications go.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotifyAddress {
    /// A path socket (`/run/systemd/notify`).
    Path(Vec<u8>),
    /// A Linux abstract socket (`@name` in the variable; the name bytes
    /// here, without the `@`).
    Abstract(Vec<u8>),
}

/// The validated notification environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyConfig {
    pub address: NotifyAddress,
    /// The watchdog ping interval: half of `WATCHDOG_USEC`, at least
    /// 1 ms; `None` without a watchdog for this process.
    pub watchdog_ms: Option<u64>,
}

/// A positive decimal number of at most 20 digits.
fn decimal(value: &OsStr) -> Option<u64> {
    let bytes = value.as_encoded_bytes();
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()?
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
}

/// Validates the notification environment as `sd_notify` and
/// `sd_watchdog_enabled` read it. `Ok(None)` without `NOTIFY_SOCKET` (the
/// watchdog variables are then ignored: nothing could be sent).
///
/// `NOTIFY_SOCKET` must be `@name` (abstract) or an absolute path, at most
/// 107 bytes; anything else (empty, relative, `vsock:`) is refused rather
/// than silently not notifying. `WATCHDOG_USEC` must be a positive
/// decimal; `WATCHDOG_PID`, if set, a positive decimal, and the watchdog
/// is this process's only if it equals `pid` (systemd sets it to the main
/// process).
pub fn parse(
    socket: Option<&OsStr>,
    watchdog_usec: Option<&OsStr>,
    watchdog_pid: Option<&OsStr>,
    pid: u32,
) -> Result<Option<NotifyConfig>, NotifyError> {
    let Some(socket) = socket else {
        return Ok(None);
    };
    let bytes = socket.as_encoded_bytes();
    let address = match bytes.first() {
        Some(b'@') if bytes.len() > 1 => NotifyAddress::Abstract(bytes[1..].to_vec()),
        Some(b'/') => NotifyAddress::Path(bytes.to_vec()),
        _ => return Err(NotifyError::InvalidSocket),
    };
    if bytes.len() > SUN_PATH_MAX || bytes.contains(&0) {
        return Err(NotifyError::InvalidSocket);
    }
    let ours = match watchdog_pid {
        None => true,
        Some(value) => {
            let owner = decimal(value).ok_or(NotifyError::InvalidWatchdogPid)?;
            owner == u64::from(pid)
        }
    };
    let watchdog_ms = match watchdog_usec {
        None => None,
        Some(value) => {
            let usec = decimal(value).ok_or(NotifyError::InvalidWatchdog)?;
            ours.then_some((usec / 2_000).max(1))
        }
    };
    Ok(Some(NotifyConfig {
        address,
        watchdog_ms,
    }))
}

/// Counters of the notifications (`notify.*` in the stats blocks).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NotifyCounters {
    /// `NOTIFY_SOCKET` was set.
    pub enabled: bool,
    /// The watchdog ping interval (0: no watchdog).
    pub watchdog_interval_ms: u64,
    /// Messages sent.
    pub sent: u64,
    /// ... of them watchdog pings.
    pub watchdog_pings: u64,
    /// Messages that could not be sent (no listener, a full queue).
    pub failed: u64,
}

impl ObservableFields for NotifyCounters {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "notify";
        visitor.field(SECTION, "enabled", FieldValue::Flag(self.enabled));
        visitor.field(
            SECTION,
            "watchdog_interval_ms",
            FieldValue::Count(self.watchdog_interval_ms),
        );
        visitor.field(SECTION, "sent", FieldValue::Count(self.sent));
        visitor.field(
            SECTION,
            "watchdog_pings",
            FieldValue::Count(self.watchdog_pings),
        );
        visitor.field(SECTION, "failed", FieldValue::Count(self.failed));
    }
}

struct Target {
    socket: UnixDatagram,
    address: SocketAddr,
}

/// The service notifier: a no-op without `NOTIFY_SOCKET`.
pub struct Notifier {
    target: Option<Target>,
    watchdog_ms: Option<u64>,
    last_ping: Option<MonotonicMillis>,
    /// A `RELOADING=1` was sent and its `READY=1` not yet.
    reloading: bool,
    counters: NotifyCounters,
}

impl Notifier {
    /// Notifies nothing.
    pub const fn disabled() -> Self {
        Self {
            target: None,
            watchdog_ms: None,
            last_ping: None,
            reloading: false,
            counters: NotifyCounters {
                enabled: false,
                watchdog_interval_ms: 0,
                sent: 0,
                watchdog_pings: 0,
                failed: 0,
            },
        }
    }

    /// Reads, removes, and validates the notification variables of the
    /// process environment and opens the socket.
    ///
    /// Must run before any other thread exists: removing a variable while
    /// another thread reads the environment is undefined behaviour in the
    /// C library. `ruster run` calls it first thing, on the main thread.
    #[cfg(target_os = "linux")]
    pub fn from_process_env() -> Result<Self, NotifyError> {
        const NAMES: [&str; 3] = ["NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"];
        let [socket, usec, pid] = NAMES.map(std::env::var_os);
        for name in NAMES {
            // Single threaded here (see above); ruster never starts a
            // process, so this only keeps the values out of later reads.
            std::env::remove_var(name);
        }
        match parse(
            socket.as_deref(),
            usec.as_deref(),
            pid.as_deref(),
            std::process::id(),
        )? {
            None => Ok(Self::disabled()),
            Some(config) => Self::open(&config),
        }
    }

    /// Opens the socket for `config`.
    pub fn open(config: &NotifyConfig) -> Result<Self, NotifyError> {
        let address = match &config.address {
            NotifyAddress::Path(path) => {
                SocketAddr::from_pathname(<OsStr as OsStrExt>::from_bytes(path))
            }
            NotifyAddress::Abstract(name) => abstract_address(name),
        }
        .map_err(|_| NotifyError::InvalidSocket)?;
        Self::to(address, config.watchdog_ms).map_err(|_| NotifyError::Socket)
    }

    /// Notifies `address` from a new unbound non-blocking datagram socket,
    /// pinging the watchdog every `watchdog_ms` if given.
    pub fn to(address: SocketAddr, watchdog_ms: Option<u64>) -> io::Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            target: Some(Target { socket, address }),
            watchdog_ms,
            last_ping: None,
            reloading: false,
            counters: NotifyCounters {
                enabled: true,
                watchdog_interval_ms: watchdog_ms.unwrap_or(0),
                ..NotifyCounters::default()
            },
        })
    }

    pub const fn counters(&self) -> NotifyCounters {
        self.counters
    }

    /// `READY=1` with the running generation (startup, and the end of a
    /// reload).
    pub fn ready(&mut self, generation: u64) {
        self.reloading = false;
        self.send(false, |out| {
            write!(out, "READY=1\nSTATUS=running generation {generation}\n")
        });
    }

    /// `RELOADING=1` with `MONOTONIC_USEC` (a SIGHUP reload starts).
    pub fn reloading(&mut self, generation: u64) {
        if self.target.is_none() {
            return;
        }
        self.reloading = true;
        let usec = sys::monotonic_usec();
        self.send(false, |out| {
            out.write_all(b"RELOADING=1\n")?;
            // Omitted rather than wrong when the clock cannot be read.
            if let Some(usec) = usec {
                writeln!(out, "MONOTONIC_USEC={usec}")?;
            }
            writeln!(out, "STATUS=reloading (generation {generation})")
        });
    }

    /// The `READY=1` that ends a reload, once no reload is `busy`.
    pub fn reload_settled(&mut self, busy: bool, generation: u64) {
        if self.reloading && !busy {
            self.ready(generation);
        }
    }

    /// `STOPPING=1` with the reason (`status` writes it).
    pub fn stopping(&mut self, status: impl FnOnce(&mut &mut [u8]) -> io::Result<()>) {
        self.send(false, |out| {
            out.write_all(b"STOPPING=1\nSTATUS=stopping: ")?;
            status(out)?;
            out.write_all(b"\n")
        });
    }

    /// When the next watchdog ping is due (`None` without a watchdog).
    pub fn watchdog_due(&self) -> Option<MonotonicMillis> {
        let interval = self.watchdog_ms?;
        self.target.as_ref()?;
        Some(self.last_ping.map_or(MonotonicMillis(0), |last| {
            MonotonicMillis(last.0.saturating_add(interval))
        }))
    }

    /// Pings the watchdog if it is due at `now` (cold point of the router
    /// loop). No allocation.
    pub fn watchdog(&mut self, now: MonotonicMillis) {
        if self.watchdog_due().is_some_and(|due| now >= due) {
            self.last_ping = Some(now);
            self.send(true, |out| out.write_all(b"WATCHDOG=1\n"));
        }
    }

    fn send(&mut self, ping: bool, compose: impl FnOnce(&mut &mut [u8]) -> io::Result<()>) {
        let Some(target) = &self.target else {
            return;
        };
        let mut buffer = [0_u8; MESSAGE_MAX];
        let composed = {
            let mut rest = &mut buffer[..];
            compose(&mut rest).map(|()| MESSAGE_MAX - rest.len())
        };
        let sent =
            composed.and_then(|len| target.socket.send_to_addr(&buffer[..len], &target.address));
        let counters = &mut self.counters;
        if sent.is_ok() {
            counters.sent = counters.sent.saturating_add(1);
            if ping {
                counters.watchdog_pings = counters.watchdog_pings.saturating_add(1);
            }
        } else {
            counters.failed = counters.failed.saturating_add(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn abstract_address(name: &[u8]) -> io::Result<SocketAddr> {
    use std::os::linux::net::SocketAddrExt;
    SocketAddr::from_abstract_name(name)
}

#[cfg(not(target_os = "linux"))]
fn abstract_address(_: &[u8]) -> io::Result<SocketAddr> {
    Err(io::ErrorKind::Unsupported.into())
}

/// `clock_gettime(CLOCK_MONOTONIC)` for `MONOTONIC_USEC`: the clock
/// systemd compares it with (std's `Instant` does not expose its value).
/// Only where `struct timespec` is two 64-bit fields: x86_64 Linux, the
/// platform `ruster run` serves (the same gate as `live`).
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
#[allow(unsafe_code)]
mod sys {
    use std::os::raw::c_int;

    const CLOCK_MONOTONIC: c_int = 1;

    /// `struct timespec` of x86_64 Linux (`time_t` and `long`, both
    /// 64-bit; glibc and musl alike).
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanos: i64,
    }

    const _: () = assert!(std::mem::size_of::<Timespec>() == 16);

    extern "C" {
        // `int clock_gettime(clockid_t, struct timespec *)` from the C
        // library std links (a vDSO call; the syscall without a vDSO is
        // on the seccomp allowlist).
        fn clock_gettime(clock: c_int, time: *mut Timespec) -> c_int;
    }

    /// Microseconds of `CLOCK_MONOTONIC`; `None` if it cannot be read.
    pub fn monotonic_usec() -> Option<u64> {
        let mut time = Timespec {
            seconds: 0,
            nanos: 0,
        };
        // SAFETY: `clock_gettime` has the declared C ABI; `time` is a
        // valid, writable, properly aligned `struct timespec` of this
        // target's layout (checked by the gate and the size assertion)
        // that lives across the call and is only written by it.
        let status = unsafe { clock_gettime(CLOCK_MONOTONIC, &raw mut time) };
        if status != 0 {
            return None;
        }
        let seconds = u64::try_from(time.seconds).ok()?;
        let micros = u64::try_from(time.nanos / 1_000).ok()?;
        Some(seconds.saturating_mul(1_000_000).saturating_add(micros))
    }
}

/// Elsewhere no clock is read and `MONOTONIC_USEC` is omitted.
#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
mod sys {
    pub fn monotonic_usec() -> Option<u64> {
        None
    }
}

#[cfg(test)]
#[path = "notify_tests.rs"]
pub(crate) mod tests;

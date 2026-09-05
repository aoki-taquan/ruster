//! Minimal Linux implementation of systemd's `sd_notify` datagram protocol.
//!
//! The protocol is intentionally kept local to the CLI. It only needs a
//! datagram socket and a newline-separated sequence of `KEY=VALUE` fields;
//! pulling in libsystemd or a third-party crate would add a dependency for a
//! very small interface.

use std::{
    ffi::{c_int, c_void},
    os::unix::ffi::OsStrExt,
    process,
    time::{Duration, Instant},
};

const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";
const WATCHDOG_USEC_ENV: &str = "WATCHDOG_USEC";
const WATCHDOG_PID_ENV: &str = "WATCHDOG_PID";

// Linux defines AF_UNIX as 1, SOCK_DGRAM as 2, and sockaddr_un::sun_path as
// 108 bytes. These values are part of the Linux socket ABI, so no libc crate
// is needed for this small protocol implementation.
const AF_UNIX: c_int = 1;
const SOCK_DGRAM: c_int = 2;
const SOCK_NONBLOCK: c_int = 0x800;
const NOTIFY_SOCKET_TYPE: c_int = SOCK_DGRAM | SOCK_NONBLOCK;
const MSG_DONTWAIT: c_int = 0x40;
const EAGAIN: i32 = 11;
#[cfg(test)]
const SOL_SOCKET: c_int = 1;
#[cfg(test)]
const SO_RCVBUF: c_int = 8;
const SUN_PATH_LEN: usize = 108;
const SUN_PATH_OFFSET: usize = std::mem::size_of::<u16>();

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrUn {
    sun_family: u16,
    sun_path: [u8; SUN_PATH_LEN],
}

#[derive(Clone, Copy)]
struct NotifyAddress {
    sockaddr: SockAddrUn,
    length: u32,
}

impl NotifyAddress {
    fn from_env() -> Option<Self> {
        let value = crate::test_env::var_os(NOTIFY_SOCKET_ENV)?;
        Self::from_bytes(value.as_os_str().as_bytes())
    }

    fn from_bytes(value: &[u8]) -> Option<Self> {
        if value.is_empty() {
            return None;
        }

        let mut sockaddr = SockAddrUn {
            sun_family: AF_UNIX as u16,
            sun_path: [0; SUN_PATH_LEN],
        };

        if let Some(name) = value.strip_prefix(b"@") {
            // systemd's `@name` spelling denotes the Linux abstract
            // namespace. The leading `@` is not part of the socket name;
            // sun_path[0] must be the NUL byte that selects that namespace.
            if name.is_empty() || name.len() >= SUN_PATH_LEN || name.contains(&0) {
                return None;
            }
            sockaddr.sun_path[0] = 0;
            sockaddr.sun_path[1..name.len() + 1].copy_from_slice(name);
            let length = SUN_PATH_OFFSET + name.len() + 1;
            return Some(Self {
                sockaddr,
                length: u32::try_from(length).ok()?,
            });
        }

        // A pathname address includes its terminating NUL in the sockaddr
        // length. Keep the final byte available for that terminator.
        if value.len() >= SUN_PATH_LEN || value.contains(&0) {
            return None;
        }
        sockaddr.sun_path[..value.len()].copy_from_slice(value);
        sockaddr.sun_path[value.len()] = 0;
        let length = SUN_PATH_OFFSET + value.len() + 1;
        Some(Self {
            sockaddr,
            length: u32::try_from(length).ok()?,
        })
    }
}

/// Best-effort systemd notification state for one daemon invocation.
pub(crate) struct Notifier {
    address: Option<NotifyAddress>,
    watchdog_interval: Option<Duration>,
    next_watchdog: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NotifySendResult {
    Disabled,
    Sent,
    WouldBlock,
    Failed { errno: i32 },
}

impl Notifier {
    pub(crate) fn from_env() -> Self {
        let address = NotifyAddress::from_env();
        let watchdog_interval = watchdog_interval_from_env();
        let next_watchdog =
            watchdog_interval.and_then(|interval| Instant::now().checked_add(interval));
        Self {
            address,
            watchdog_interval,
            next_watchdog,
        }
    }

    pub(crate) fn ready(&self) -> NotifySendResult {
        self.send_fields(&[("READY", "1")])
    }

    pub(crate) fn stopping(&self) -> NotifySendResult {
        self.send_fields(&[("STOPPING", "1")])
    }

    pub(crate) fn watchdog_after_tick(
        &mut self,
        completed_at: Instant,
    ) -> Option<NotifySendResult> {
        let interval = self.watchdog_interval?;
        let next_watchdog = self.next_watchdog?;
        if completed_at < next_watchdog {
            return None;
        }

        let result = self.send_fields(&[("WATCHDOG", "1")]);
        if matches!(result, NotifySendResult::Sent | NotifySendResult::Disabled) {
            // Schedule from the completed tick rather than trying to catch up
            // in a burst. A delayed tick has already used up its watchdog
            // budget; sending several stale datagrams would not make the loop
            // healthy. A failed nonblocking send deliberately leaves the old
            // deadline in place so the next completed tick retries it.
            self.next_watchdog = completed_at.checked_add(interval);
        }
        Some(result)
    }

    /// Chooses a bounded wait for an idle daemon tick.
    ///
    /// `watchdog_interval` is the half-`WATCHDOG_USEC` heartbeat cadence used
    /// by [`Self::watchdog_after_tick`]. Limiting the wait to one quarter of
    /// that cadence leaves several opportunities to complete a heartbeat
    /// before systemd's deadline. The observability bound keeps an idle wait
    /// from delaying the next scheduled output. Keep the resulting wait at
    /// least one millisecond, which is the smallest useful blocking timeout
    /// for the backend poll boundary.
    pub(crate) fn idle_wait_timeout(
        &self,
        observability_interval: Duration,
        maximum: Duration,
    ) -> Duration {
        let bounded = maximum.min(observability_interval / 4);
        self.watchdog_interval
            .map_or(bounded, |interval| bounded.min(interval / 4))
            .max(Duration::from_millis(1))
    }

    fn send_fields(&self, fields: &[(&str, &str)]) -> NotifySendResult {
        let Some(address) = self.address else {
            return NotifySendResult::Disabled;
        };
        let message = format_message(fields);
        // SAFETY: `socket` has no borrowed pointer arguments; the constants
        // select a Linux AF_UNIX datagram socket with nonblocking file status.
        let fd = unsafe { socket(AF_UNIX, NOTIFY_SOCKET_TYPE, 0) };
        if fd < 0 {
            return NotifySendResult::Failed {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(5),
            };
        }

        // `SOCK_NONBLOCK` bounds the descriptor operation, and
        // `MSG_DONTWAIT` keeps this individual send nonblocking even if a
        // future socket construction change drops the file status flag.
        // SAFETY: `message` and `address` remain live for the call; their
        // pointers describe initialized bytes and a valid sockaddr length.
        let sent = unsafe {
            sendto(
                fd,
                message.as_ptr().cast::<c_void>(),
                message.len(),
                MSG_DONTWAIT,
                &address.sockaddr,
                address.length,
            )
        };
        let result = if sent >= 0 {
            NotifySendResult::Sent
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(5);
            classify_send_errno(errno)
        };
        // SAFETY: `fd` is the exact descriptor returned by `socket` and is no
        // longer used after this close. Closing is not part of the bounded
        // send operation and its result cannot change the send outcome.
        let _ = unsafe { close(fd) };
        result
    }
}

fn classify_send_errno(errno: i32) -> NotifySendResult {
    if errno == EAGAIN {
        NotifySendResult::WouldBlock
    } else {
        NotifySendResult::Failed { errno }
    }
}

fn watchdog_interval_from_env() -> Option<Duration> {
    let usec = crate::test_env::var_os(WATCHDOG_USEC_ENV)?
        .to_str()?
        .parse::<u64>()
        .ok()?;
    let half_usec = usec / 2;
    if half_usec == 0 || !watchdog_pid_matches() {
        return None;
    }
    Some(Duration::from_micros(half_usec))
}

fn watchdog_pid_matches() -> bool {
    // An absent variable means systemd did not scope the watchdog to a PID.
    // A non-Unicode value is not a PID, so it can never match this process.
    match crate::test_env::var_os(WATCHDOG_PID_ENV) {
        None => true,
        Some(value) => value
            .to_str()
            .is_some_and(|value| value.parse::<u32>().ok() == Some(process::id())),
    }
}

fn format_message(fields: &[(&str, &str)]) -> String {
    let mut message = String::new();
    for (index, (key, value)) in fields.iter().enumerate() {
        if index != 0 {
            message.push('\n');
        }
        message.push_str(key);
        message.push('=');
        message.push_str(value);
    }
    message
}

unsafe extern "C" {
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn sendto(
        socket: c_int,
        message: *const c_void,
        length: usize,
        flags: c_int,
        destination: *const SockAddrUn,
        destination_length: u32,
    ) -> isize;
    fn close(fd: c_int) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        ffi::OsStr,
        fs,
        path::{Path, PathBuf},
        sync::atomic::AtomicU64,
    };

    const POLLIN: i16 = 0x0001;
    static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);

    /// Gives one test its own view of the three systemd variables.
    ///
    /// The override is per thread, so tests need no shared lock and one
    /// failing test cannot poison another. See `test_env` for why the process
    /// environment must not be written from a test.
    struct NotifyEnv {
        _overrides: [crate::test_env::EnvOverrideGuard; 3],
    }

    impl NotifyEnv {
        fn new(
            notify_socket: Option<&str>,
            watchdog_usec: Option<&str>,
            watchdog_pid: Option<&str>,
        ) -> Self {
            Self {
                _overrides: [
                    crate::test_env::override_for_thread(
                        NOTIFY_SOCKET_ENV,
                        notify_socket.map(OsStr::new),
                    ),
                    crate::test_env::override_for_thread(
                        WATCHDOG_USEC_ENV,
                        watchdog_usec.map(OsStr::new),
                    ),
                    crate::test_env::override_for_thread(
                        WATCHDOG_PID_ENV,
                        watchdog_pid.map(OsStr::new),
                    ),
                ],
            }
        }
    }

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    struct TestReceiver {
        fd: c_int,
        path: Option<PathBuf>,
    }

    impl TestReceiver {
        fn bind(value: &str) -> Result<Self, std::io::Error> {
            let address = NotifyAddress::from_bytes(value.as_bytes())
                .expect("test notify socket address must be valid");
            // SAFETY: `socket(2)` receives only scalar ABI arguments; the
            // constants select an AF_UNIX datagram socket and the returned fd
            // is owned by this test receiver.
            let fd = unsafe { socket(AF_UNIX, SOCK_DGRAM, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `address.sockaddr` is initialized and remains live for
            // this call; `address.length` is its validated ABI length, and
            // `fd` is the socket descriptor owned by this receiver.
            let result = unsafe { bind(fd, &address.sockaddr, address.length) };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                // SAFETY: `fd` is the descriptor returned above and is owned
                // by this receiver after the failed bind.
                let _ = unsafe { close(fd) };
                return Err(error);
            }
            Ok(Self {
                fd,
                path: (!value.starts_with('@')).then(|| PathBuf::from(value)),
            })
        }

        fn receive(&self) -> Option<String> {
            let mut poll_fd = PollFd {
                fd: self.fd,
                events: POLLIN,
                revents: 0,
            };
            // SAFETY: `poll_fd` points to one initialized pollfd that remains
            // live for the call, and poll does not retain the pointer.
            let ready = unsafe { poll(&mut poll_fd, 1, 1_000) };
            assert!(ready >= 0, "test receiver poll must succeed");
            if ready == 0 {
                return None;
            }
            let mut buffer = [0_u8; 256];
            // SAFETY: `self.fd` is a live receiver-owned datagram descriptor;
            // `buffer` is writable for its full length and remains live for
            // the call.
            let length = unsafe { recv(self.fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
            assert!(length >= 0, "test receiver recv must succeed");
            Some(
                String::from_utf8(buffer[..length as usize].to_vec())
                    .expect("sd_notify test message must be UTF-8"),
            )
        }
    }

    impl Drop for TestReceiver {
        fn drop(&mut self) {
            // SAFETY: `self.fd` is the descriptor created and owned by this
            // receiver, and Drop closes it exactly once.
            let _ = unsafe { close(self.fd) };
            if let Some(path) = &self.path {
                let _ = fs::remove_file(path);
            }
        }
    }

    fn unique_path() -> PathBuf {
        let root = env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.reloadwork"));
        fs::create_dir_all(&root).expect("sd_notify test temporary directory must exist");
        let id = NEXT_SOCKET_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        root.join(format!("ruster-sd-notify-{}-{id}.sock", process::id()))
    }

    fn unique_abstract_name() -> String {
        let id = NEXT_SOCKET_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("@ruster-sd-notify-{}-{id}", process::id())
    }

    fn receiver_or_skip(value: &str) -> Option<TestReceiver> {
        match TestReceiver::bind(value) {
            Ok(receiver) => Some(receiver),
            Err(error) if matches!(error.raw_os_error(), Some(1) | Some(13)) => {
                if env::var("RUSTER_PRIVILEGED_E2E").ok().as_deref() == Some("1") {
                    panic!(
                        "privileged sd_notify socket test requested but AF_UNIX bind is unavailable: {error}"
                    );
                }
                println!("sd_notify socket test skipped: AF_UNIX bind is unavailable: {error}");
                None
            }
            Err(error) => panic!("test receiver socket must be bound: {error}"),
        }
    }

    const MAX_DGRAM_QLEN_PATH: &str = "/proc/sys/net/unix/max_dgram_qlen";
    const FALLBACK_MAX_FILL_ATTEMPTS: usize = 8_192;
    const FALLBACK_MAX_FILLERS: usize = 8_192;

    #[derive(Clone, Copy)]
    struct QueueFillLimits {
        max_attempts: usize,
        max_fillers: usize,
        max_dgram_qlen: Option<usize>,
    }

    struct FillerSockets {
        fds: Vec<c_int>,
    }

    impl FillerSockets {
        fn new() -> Self {
            Self { fds: Vec::new() }
        }

        fn push(&mut self, fd: c_int) {
            self.fds.push(fd);
        }
    }

    impl Drop for FillerSockets {
        fn drop(&mut self) {
            for &fd in &self.fds {
                // SAFETY: Every descriptor in `fds` was returned by
                // `socket` and remains owned by this guard until this close.
                let _ = unsafe { close(fd) };
            }
        }
    }

    fn queue_fill_limits(effective_receive_buffer: usize, payload_len: usize) -> QueueFillLimits {
        assert!(payload_len > 0, "queue filler payload must not be empty");

        // SO_RCVBUF is a byte limit, so this is a conservative packet-count
        // bound for kernels that enforce that limit before the datagram-count
        // limit. The extra attempt is needed to observe EAGAIN rather than
        // merely stopping after the last successful send.
        let receive_buffer_bound = effective_receive_buffer
            .saturating_add(payload_len - 1)
            .checked_div(payload_len)
            .unwrap_or(0)
            .saturating_add(1);

        let max_dgram_qlen = fs::read_to_string(MAX_DGRAM_QLEN_PATH)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok());

        let (max_attempts, max_fillers) = match max_dgram_qlen {
            Some(max_datagrams) => {
                // In the worst case every filler contributes one successful
                // datagram and then EAGAIN, followed by one fresh filler that
                // immediately reports EAGAIN. That requires Q successes plus
                // Q+1 EAGAIN observations, or 2*Q+1 attempts in total.
                let queue_attempt_bound = max_datagrams
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(1));
                let queue_filler_bound = max_datagrams.checked_add(1);

                // Keep overflow a bounded diagnostic failure instead of
                // turning a saturated limit into an impractically long test.
                match (
                    queue_attempt_bound.and_then(|value| receive_buffer_bound.checked_add(value)),
                    queue_filler_bound,
                ) {
                    (Some(max_attempts), Some(max_fillers)) => (max_attempts, max_fillers),
                    _ => (FALLBACK_MAX_FILL_ATTEMPTS, FALLBACK_MAX_FILLERS),
                }
            }
            None => {
                // /proc is not guaranteed to be mounted in a test sandbox.
                // Retain the existing bounded fallback and allow for one
                // per-filler EAGAIN observation in the multi-filler loop.
                let fallback_attempts = receive_buffer_bound
                    .checked_mul(2)
                    .map_or(FALLBACK_MAX_FILL_ATTEMPTS, |bound| {
                        FALLBACK_MAX_FILL_ATTEMPTS.max(bound)
                    });
                (fallback_attempts, FALLBACK_MAX_FILLERS)
            }
        };

        // Keep a procfs value from turning this test into an unbounded amount
        // of work. These fixed fallback values are also the hard caps; if a
        // larger queue cannot be filled within them, the assertion below
        // reports the observed attempts, fillers, and queue parameters.
        let max_attempts = max_attempts.min(FALLBACK_MAX_FILL_ATTEMPTS);
        let max_fillers = max_fillers.min(FALLBACK_MAX_FILLERS);

        println!(
            concat!(
                "sd_notify queue-fill limits: attempts={}, fillers={}, ",
                "effective SO_RCVBUF={} bytes, max_dgram_qlen={}"
            ),
            max_attempts,
            max_fillers,
            effective_receive_buffer,
            max_dgram_qlen.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
        );
        QueueFillLimits {
            max_attempts,
            max_fillers,
            max_dgram_qlen,
        }
    }

    #[test]
    fn message_fields_are_newline_separated() {
        assert_eq!(
            format_message(&[("READY", "1"), ("STATUS", "interfaces=2")]),
            "READY=1\nSTATUS=interfaces=2"
        );
    }

    #[test]
    fn notify_socket_type_keeps_both_socket_flags() {
        // Protects the contract that notification sockets are both datagram
        // sockets and nonblocking; XOR would silently drop that combination.
        assert_eq!(NOTIFY_SOCKET_TYPE, SOCK_DGRAM | SOCK_NONBLOCK);
    }

    #[test]
    fn abstract_address_rejects_an_empty_name() {
        // Protects the validation that `@` without a namespace name is not a
        // usable abstract AF_UNIX destination.
        assert!(NotifyAddress::from_bytes(b"@").is_none());
    }

    #[test]
    fn abstract_address_rejects_an_embedded_nul() {
        // Protects the validation that an abstract socket name cannot contain
        // a NUL byte, which would truncate the kernel-visible name.
        assert!(NotifyAddress::from_bytes(b"@name\0suffix").is_none());
    }

    #[test]
    fn abstract_address_rejects_a_name_that_fills_sun_path() {
        let mut value = vec![b'@'];
        value.extend([b'x'; SUN_PATH_LEN]);

        // Protects the strict abstract-name size boundary required to leave
        // room for the namespace marker in sun_path.
        assert!(NotifyAddress::from_bytes(&value).is_none());
    }

    #[test]
    fn abstract_address_has_the_expected_layout_and_length() {
        let address = NotifyAddress::from_bytes(b"@abc").expect("abstract address must parse");

        // Protects the abstract namespace marker, copied name, and sockaddr
        // length arithmetic; each byte and the trailing length are ABI data.
        assert_eq!(address.sockaddr.sun_family, AF_UNIX as u16);
        assert_eq!(&address.sockaddr.sun_path[..5], b"\0abc\0");
        assert_eq!(address.length, (SUN_PATH_OFFSET + 3 + 1) as u32);
    }

    #[test]
    fn pathname_address_rejects_an_embedded_nul() {
        // Protects the pathname validation that rejects embedded NUL bytes
        // instead of allowing the kernel to see a shorter path.
        assert!(NotifyAddress::from_bytes(b"/tmp\0notify.sock").is_none());
    }

    #[test]
    fn pathname_address_rejects_a_path_that_fills_sun_path() {
        // Protects the strict pathname size boundary needed for its trailing
        // NUL terminator.
        assert!(NotifyAddress::from_bytes(&[b'x'; SUN_PATH_LEN]).is_none());
    }

    #[test]
    fn pathname_address_has_the_expected_layout_and_length() {
        let address = NotifyAddress::from_bytes(b"abc").expect("pathname address must parse");

        // Protects pathname copying, its terminator, and sockaddr length
        // arithmetic used by sendto and bind.
        assert_eq!(address.sockaddr.sun_family, AF_UNIX as u16);
        assert_eq!(&address.sockaddr.sun_path[..4], b"abc\0");
        assert_eq!(address.length, (SUN_PATH_OFFSET + 3 + 1) as u32);
    }

    #[test]
    fn ready_is_received_on_path_socket() {
        let path = unique_path();
        let path_string = path.to_str().expect("test path must be UTF-8");
        let Some(receiver) = receiver_or_skip(path_string) else {
            return;
        };
        let _environment = NotifyEnv::new(Some(path_string), None, None);

        Notifier::from_env().ready();

        assert_eq!(receiver.receive().as_deref(), Some("READY=1"));
    }

    #[test]
    fn ready_is_received_on_abstract_socket() {
        let abstract_name = unique_abstract_name();
        let Some(receiver) = receiver_or_skip(&abstract_name) else {
            return;
        };
        let _environment = NotifyEnv::new(Some(&abstract_name), None, None);

        Notifier::from_env().ready();

        assert_eq!(receiver.receive().as_deref(), Some("READY=1"));
    }

    #[test]
    fn missing_notify_socket_is_a_no_op() {
        let _environment = NotifyEnv::new(None, None, None);
        let mut notifier = Notifier::from_env();

        notifier.ready();
        notifier.stopping();
        notifier.watchdog_after_tick(Instant::now() + Duration::from_secs(1));
    }

    #[test]
    fn watchdog_for_another_pid_does_not_send() {
        let path = unique_path();
        let path_string = path.to_str().expect("test path must be UTF-8");
        let Some(receiver) = receiver_or_skip(path_string) else {
            return;
        };
        let other_pid = process::id().saturating_add(1).to_string();
        let _environment = NotifyEnv::new(Some(path_string), Some("2"), Some(&other_pid));

        let mut notifier = Notifier::from_env();
        notifier.watchdog_after_tick(Instant::now() + Duration::from_secs(1));

        assert!(
            receiver.receive().is_none(),
            "watchdog must not notify on behalf of another PID"
        );
    }

    #[test]
    fn notify_socket_is_nonblocking_for_bounded_send() {
        assert_eq!(
            NOTIFY_SOCKET_TYPE & SOCK_NONBLOCK,
            SOCK_NONBLOCK,
            "notify socket must use SOCK_NONBLOCK so a full receiver queue cannot block"
        );
    }

    #[test]
    fn notify_send_failure_is_reported_and_watchdog_retries() {
        let path = unique_path();
        let path_string = path.to_str().expect("test path must be UTF-8");
        let _environment = NotifyEnv::new(Some(path_string), Some("200000"), None);
        let mut notifier = Notifier::from_env();
        let deadline = notifier
            .next_watchdog
            .expect("watchdog deadline must be configured");

        assert!(matches!(
            notifier.ready(),
            NotifySendResult::Failed { errno } if matches!(errno, 1 | 2 | 13)
        ));
        assert!(matches!(
            notifier.stopping(),
            NotifySendResult::Failed { errno } if matches!(errno, 1 | 2 | 13)
        ));
        assert!(matches!(
            notifier.watchdog_after_tick(deadline),
            Some(NotifySendResult::Failed { errno }) if matches!(errno, 1 | 2 | 13)
        ));
        assert_eq!(notifier.next_watchdog, Some(deadline));
    }

    #[test]
    fn watchdog_sends_at_the_deadline_but_not_before_it() {
        let _environment = NotifyEnv::new(None, Some("200000"), None);
        let mut notifier = Notifier::from_env();
        let deadline = notifier
            .next_watchdog
            .expect("watchdog deadline must be configured");

        // Protects the strict pre-deadline check: a completed tick before the
        // deadline must not emit a heartbeat.
        assert_eq!(
            notifier.watchdog_after_tick(deadline - Duration::from_nanos(1)),
            None
        );
        // Protects the inclusive deadline boundary: the tick exactly at the
        // deadline must be processed and schedule the next interval.
        assert_eq!(
            notifier.watchdog_after_tick(deadline),
            Some(NotifySendResult::Disabled)
        );
        assert_eq!(
            notifier.next_watchdog,
            deadline.checked_add(Duration::from_micros(100_000))
        );
    }

    #[test]
    fn eagain_is_reported_as_a_visible_would_block_result() {
        assert_eq!(classify_send_errno(EAGAIN), NotifySendResult::WouldBlock);
        assert_eq!(
            classify_send_errno(111),
            NotifySendResult::Failed { errno: 111 }
        );
    }

    #[test]
    fn full_notify_queue_does_not_block_ready_notification() {
        let path = unique_path();
        let path_string = path.to_str().expect("test path must be UTF-8");
        let Some(receiver) = receiver_or_skip(path_string) else {
            return;
        };
        let address = NotifyAddress::from_bytes(path_string.as_bytes())
            .expect("test notify socket address must be valid");
        let requested_receive_buffer = 2_304;
        // SAFETY: `receiver.fd` is a live AF_UNIX datagram socket owned by the
        // test, and the kernel copies this initialized integer option value.
        let result = unsafe {
            setsockopt(
                receiver.fd,
                SOL_SOCKET,
                SO_RCVBUF,
                (&requested_receive_buffer as *const c_int).cast(),
                std::mem::size_of::<c_int>() as u32,
            )
        };
        assert_eq!(result, 0, "test receiver SO_RCVBUF must be set");

        let mut effective_receive_buffer: c_int = 0;
        let mut effective_receive_buffer_length = std::mem::size_of::<c_int>() as u32;
        // SAFETY: `receiver.fd` is a live AF_UNIX datagram socket, and both
        // output pointers refer to writable storage that remains live for the
        // call.
        let result = unsafe {
            getsockopt(
                receiver.fd,
                SOL_SOCKET,
                SO_RCVBUF,
                (&mut effective_receive_buffer as *mut c_int).cast(),
                &mut effective_receive_buffer_length,
            )
        };
        assert_eq!(result, 0, "test receiver SO_RCVBUF must be readable");
        assert_eq!(
            effective_receive_buffer_length as usize,
            std::mem::size_of::<c_int>(),
            "test receiver SO_RCVBUF must return an integer"
        );
        let effective_receive_buffer = usize::try_from(effective_receive_buffer)
            .expect("test receiver SO_RCVBUF must be positive");

        // Fill the peer queue through nonblocking helpers so the reproduction
        // itself cannot wait. An EAGAIN after a successful send only means
        // that this helper's send buffer is full; a fresh helper gets another
        // chance to put a datagram into the receiver queue.
        let payload = [0_u8; 128];
        let limits = queue_fill_limits(effective_receive_buffer, payload.len());
        let max_dgram_qlen = limits
            .max_dgram_qlen
            .map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
        let mut filler_sockets = FillerSockets::new();
        let mut fill_attempts = 0;
        let mut queue_full = false;
        'fill_queue: for _ in 0..limits.max_fillers {
            if fill_attempts >= limits.max_attempts {
                break;
            }

            // SAFETY: `socket` has no borrowed pointer arguments and the
            // flags are valid Linux AF_UNIX datagram flags.
            let filler = unsafe { socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0) };
            assert!(
                filler >= 0,
                "queue filler socket could not be created: attempts={}, fillers={}, effective SO_RCVBUF={} bytes, max_dgram_qlen={}",
                fill_attempts,
                filler_sockets.fds.len(),
                effective_receive_buffer,
                max_dgram_qlen
            );
            filler_sockets.push(filler);

            let mut sent_on_filler = false;
            while fill_attempts < limits.max_attempts {
                fill_attempts += 1;
                // SAFETY: `payload` and `address` remain live for the call;
                // both pointers describe initialized datagram data and
                // sockaddr bytes.
                let sent = unsafe {
                    sendto(
                        filler,
                        payload.as_ptr().cast(),
                        payload.len(),
                        0,
                        &address.sockaddr,
                        address.length,
                    )
                };
                if sent >= 0 {
                    sent_on_filler = true;
                    continue;
                }

                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(5);
                if errno != EAGAIN {
                    panic!(
                        "queue filler send failed with errno {errno}: attempts={}, fillers={}, effective SO_RCVBUF={} bytes, max_dgram_qlen={}",
                        fill_attempts,
                        filler_sockets.fds.len(),
                        effective_receive_buffer,
                        max_dgram_qlen
                    );
                }
                if !sent_on_filler {
                    queue_full = true;
                    break 'fill_queue;
                }
                break;
            }
        }

        assert!(
            queue_full,
            "notify receiver queue must become full within fill limits: attempts={}, fillers={}, effective SO_RCVBUF={} bytes, max_dgram_qlen={}",
            fill_attempts,
            filler_sockets.fds.len(),
            effective_receive_buffer,
            max_dgram_qlen
        );

        let _environment = NotifyEnv::new(Some(path_string), None, None);
        // The notifier is built here rather than inside the worker: the test
        // environment override is scoped to this thread, and the property
        // under test is that the *send* does not block, not where the address
        // is read.
        let notifier = Notifier::from_env();
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let _worker = std::thread::spawn(move || {
            let _ = done_sender.send(notifier.ready());
        });
        let result = done_receiver
            .recv_timeout(Duration::from_millis(100))
            .expect("READY notification must return after the notify receiver queue filled");
        // Keep all filler descriptors open until the READY send has completed;
        // closing them earlier could drain the condition being tested. The
        // guard also closes every descriptor if setup or the bounded fill
        // fails before this point.
        drop(filler_sockets);
        assert_eq!(
            result,
            NotifySendResult::WouldBlock,
            "a full notify queue must be reported as a dropped advisory notification"
        );
    }

    #[test]
    fn idle_wait_clamps_to_watchdog_quarter_and_has_millisecond_floor() {
        {
            let _environment = NotifyEnv::new(None, Some("400000"), None);
            let notifier = Notifier::from_env();
            assert_eq!(
                notifier.idle_wait_timeout(Duration::from_secs(10), Duration::from_secs(1)),
                Duration::from_millis(50)
            );
        }

        {
            let _environment = NotifyEnv::new(None, Some("4"), None);
            let notifier = Notifier::from_env();
            assert_eq!(
                notifier.idle_wait_timeout(Duration::from_secs(10), Duration::from_secs(1)),
                Duration::from_millis(1)
            );
        }
    }

    #[test]
    fn idle_wait_clamps_observability_interval_to_one_quarter() {
        let _environment = NotifyEnv::new(None, None, None);
        let notifier = Notifier::from_env();

        // Protects the observability cadence bound: without a watchdog, the
        // wait is one quarter of observability_interval when that is tighter.
        assert_eq!(
            notifier.idle_wait_timeout(Duration::from_secs(8), Duration::from_secs(10)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn watchdog_idle_wait_has_a_millisecond_floor() {
        let _environment = NotifyEnv::new(None, Some("4"), None);
        let notifier = Notifier::from_env();
        assert_eq!(
            notifier.idle_wait_timeout(Duration::from_secs(10), Duration::from_secs(1)),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn watchdog_usec_four_quarter_is_floored_for_idle_poll() {
        let _environment = NotifyEnv::new(None, Some("4"), None);
        let notifier = Notifier::from_env();
        let raw_watchdog_quarter = Duration::from_micros(2) / 4;

        assert_eq!(raw_watchdog_quarter, Duration::from_nanos(500));
        assert_eq!(
            notifier.idle_wait_timeout(Duration::from_secs(10), Duration::from_secs(1)),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn send_fields_accepts_a_zero_socket_descriptor() {
        const CHILD_ENV: &str = "RUSTER_SD_NOTIFY_FD_ZERO_CHILD";

        if env::var(CHILD_ENV).ok().as_deref() == Some("1") {
            let path = unique_path();
            let path_string = path.to_str().expect("test path must be UTF-8");
            assert!(!path.exists(), "fd-zero notify path must not exist");
            let address =
                NotifyAddress::from_bytes(path_string.as_bytes()).expect("pathname must parse");
            let notifier = Notifier {
                address: Some(address),
                watchdog_interval: None,
                next_watchdog: None,
            };

            // Protects the socket error boundary in an isolated child: fd 0
            // is valid and must proceed to sendto rather than be rejected;
            // sendto then reports an error for this deliberately absent path.
            // Setting EBADF before and after close(0) makes the <=0/==0
            // mutants observably return before sendto, with errno 9.
            let _ = unsafe { close(-1) };
            assert_eq!(unsafe { close(0) }, 0, "child standard input must close");
            let _ = unsafe { close(-1) };
            match notifier.ready() {
                NotifySendResult::Failed { errno } => {
                    assert_ne!(errno, 9, "sendto must run with valid fd 0");
                }
                other => panic!("missing pathname must fail to send: {other:?}"),
            }
            return;
        }

        let executable = env::current_exe().expect("sd_notify test executable must be found");
        let status = process::Command::new(executable)
            .arg("--exact")
            .arg("sd_notify::tests::send_fields_accepts_a_zero_socket_descriptor")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .status()
            .expect("fd-zero sd_notify child must start");

        // Protects the fd-zero path without changing any descriptor in the
        // parent test process; only the child performs the socket operation.
        assert!(status.success(), "fd-zero sd_notify child must succeed");
    }

    mod mutation_sd_notify_line_26 {
        use super::*;

        #[test]
        fn notify_socket_type_has_the_complete_socket_abi_flags() {
            // The datagram and nonblocking flags are both required by the
            // notification socket ABI. Their disjoint bit patterns also make
            // `|` and `^` semantically equivalent for this constant.
            assert_eq!(SOCK_DGRAM, 2);
            assert_eq!(SOCK_NONBLOCK, 0x800);
            assert_eq!(NOTIFY_SOCKET_TYPE, 0x802);
            assert_eq!(NOTIFY_SOCKET_TYPE & SOCK_DGRAM, SOCK_DGRAM);
            assert_eq!(NOTIFY_SOCKET_TYPE & SOCK_NONBLOCK, SOCK_NONBLOCK);
        }
    }

    unsafe extern "C" {
        fn bind(socket: c_int, address: *const SockAddrUn, address_length: u32) -> c_int;
        fn setsockopt(
            socket: c_int,
            level: c_int,
            option_name: c_int,
            option_value: *const c_void,
            option_length: u32,
        ) -> c_int;
        fn getsockopt(
            socket: c_int,
            level: c_int,
            option_name: c_int,
            option_value: *mut c_void,
            option_length: *mut u32,
        ) -> c_int;
        fn poll(fds: *mut PollFd, count: usize, timeout_ms: c_int) -> c_int;
        fn recv(socket: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
    }
}

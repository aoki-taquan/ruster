//! The `sd_notify` environment and messages (H10).

use std::ffi::OsStr;
use std::os::linux::net::SocketAddrExt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::*;

const PID: u32 = 4242;

fn os(text: &str) -> &OsStr {
    OsStr::new(text)
}

#[test]
fn the_environment_is_validated_like_sd_notify() {
    // Unset: nothing, whatever the watchdog says.
    assert_eq!(parse(None, Some(os("100")), None, PID), Ok(None));
    let config = |socket: &str, usec: Option<&str>, pid: Option<&str>| {
        parse(Some(os(socket)), usec.map(os), pid.map(os), PID)
    };
    assert_eq!(
        config("/run/systemd/notify", None, None),
        Ok(Some(NotifyConfig {
            address: NotifyAddress::Path(b"/run/systemd/notify".to_vec()),
            watchdog_ms: None,
        }))
    );
    assert_eq!(
        config("@ruster/notify", None, None).map(|c| c.map(|c| c.address)),
        Ok(Some(NotifyAddress::Abstract(b"ruster/notify".to_vec())))
    );
    // Refused rather than silently not notifying.
    let long = format!("/{}", "a".repeat(107));
    for bad in ["", "@", "relative/notify", "vsock:2:1234", long.as_str()] {
        assert_eq!(
            config(bad, None, None),
            Err(NotifyError::InvalidSocket),
            "{bad:?}"
        );
    }
    assert!(config(&long[..107], None, None).is_ok(), "107 bytes fit");
    // The watchdog: half of WATCHDOG_USEC, at least 1 ms.
    let watchdog = |usec, pid| config("/n", Some(usec), pid).map(|c| c.and_then(|c| c.watchdog_ms));
    assert_eq!(watchdog("10000000", None), Ok(Some(5_000)));
    assert_eq!(watchdog("3000", None), Ok(Some(1)));
    assert_eq!(watchdog("1", None), Ok(Some(1)));
    assert_eq!(watchdog("10000000", Some("4242")), Ok(Some(5_000)));
    assert_eq!(
        watchdog("10000000", Some("4243")),
        Ok(None),
        "another pid's"
    );
    for bad in ["", "0", "-1", "+5", "1e6", " 5", "99999999999999999999999"] {
        assert_eq!(
            watchdog(bad, None),
            Err(NotifyError::InvalidWatchdog),
            "{bad:?}"
        );
    }
    for bad in ["", "0", "x", "-4242"] {
        assert_eq!(
            watchdog("1000000", Some(bad)),
            Err(NotifyError::InvalidWatchdogPid),
            "{bad:?}"
        );
    }
    assert_eq!(NotifyError::InvalidSocket.code(), "NOTIFY_SOCKET_INVALID");
}

/// A bound abstract datagram socket that receives what a notifier sends.
pub(crate) struct Listener {
    socket: UnixDatagram,
    pub(crate) name: Vec<u8>,
}

impl Listener {
    pub(crate) fn bind() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "ruster-notify-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .into_bytes();
        let address = SocketAddr::from_abstract_name(&name).expect("address");
        let socket = UnixDatagram::bind_addr(&address).expect("bind");
        socket.set_nonblocking(true).expect("nonblocking");
        Self { socket, name }
    }

    pub(crate) fn notifier(&self, watchdog_ms: Option<u64>) -> Notifier {
        Notifier::open(&NotifyConfig {
            address: NotifyAddress::Abstract(self.name.clone()),
            watchdog_ms,
        })
        .expect("notifier")
    }

    /// Every message received so far.
    pub(crate) fn messages(&self) -> Vec<String> {
        let mut messages = Vec::new();
        let mut buffer = [0_u8; 512];
        while let Ok(len) = self.socket.recv(&mut buffer) {
            messages.push(String::from_utf8(buffer[..len].to_vec()).expect("utf-8"));
        }
        messages
    }
}

#[test]
fn messages_follow_the_protocol() {
    let listener = Listener::bind();
    let mut notifier = listener.notifier(None);
    notifier.ready(1);
    notifier.reload_settled(false, 1);
    notifier.reloading(1);
    notifier.reload_settled(true, 1);
    notifier.reload_settled(false, 2);
    notifier.reload_settled(false, 2);
    notifier.stopping(|text| text.write_all(b"stop requested"));
    let messages = listener.messages();
    assert_eq!(messages.len(), 4, "{messages:?}");
    assert_eq!(messages[0], "READY=1\nSTATUS=running generation 1\n");
    let reloading: Vec<&str> = messages[1].lines().collect();
    assert_eq!(reloading[0], "RELOADING=1");
    let usec = reloading[1]
        .strip_prefix("MONOTONIC_USEC=")
        .and_then(|usec| usec.parse::<u64>().ok())
        .expect("MONOTONIC_USEC");
    assert!(usec > 0);
    assert_eq!(reloading[2], "STATUS=reloading (generation 1)");
    assert_eq!(messages[2], "READY=1\nSTATUS=running generation 2\n");
    assert_eq!(messages[3], "STOPPING=1\nSTATUS=stopping: stop requested\n");
    let counters = notifier.counters();
    assert!(counters.enabled);
    assert_eq!((counters.sent, counters.failed), (4, 0));
    // A status that does not fit the stack buffer is not sent, not cut.
    notifier.stopping(|text| text.write_all(&[b'x'; 400]));
    assert!(listener.messages().is_empty());
    assert_eq!(notifier.counters().failed, 1);
}

#[test]
fn the_watchdog_pings_every_interval_and_never_blocks() {
    let listener = Listener::bind();
    let mut notifier = listener.notifier(Some(500));
    let at = MonotonicMillis;
    assert_eq!(notifier.watchdog_due(), Some(at(0)), "due at once");
    notifier.watchdog(at(10));
    notifier.watchdog(at(509));
    assert_eq!(notifier.watchdog_due(), Some(at(510)));
    notifier.watchdog(at(510));
    notifier.watchdog(at(2_000));
    assert_eq!(listener.messages(), ["WATCHDOG=1\n"; 3]);
    let counters = notifier.counters();
    assert_eq!(
        (
            counters.watchdog_interval_ms,
            counters.watchdog_pings,
            counters.sent
        ),
        (500, 3, 3)
    );
    // Nobody reads: the receive queue fills, and the sender neither
    // blocks nor stops counting.
    let started = std::time::Instant::now();
    for step in 0..2_000_u64 {
        notifier.watchdog(at(3_000 + step * 500));
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    let counters = notifier.counters();
    assert!(counters.failed > 0, "{counters:?}");
    assert_eq!(counters.sent + counters.failed, 2_003);
    // No listener at all.
    drop(listener);
    notifier.ready(1);
    assert_eq!(notifier.counters().failed, counters.failed + 1);
}

#[test]
fn a_disabled_notifier_sends_nothing() {
    let mut notifier = Notifier::disabled();
    notifier.ready(1);
    notifier.reloading(1);
    notifier.watchdog(MonotonicMillis(0));
    assert_eq!(notifier.watchdog_due(), None);
    assert_eq!(notifier.counters(), NotifyCounters::default());
    // The stats fields.
    let mut text = String::new();
    crate::run::stats::write_fields(&mut text, None, &notifier.counters());
    assert_eq!(
        text,
        "notify.enabled=false\nnotify.watchdog_interval_ms=0\nnotify.sent=0\n\
         notify.watchdog_pings=0\nnotify.failed=0\n"
    );
}

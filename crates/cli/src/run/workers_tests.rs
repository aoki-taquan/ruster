//! The worker threads and the link round handoff (H7).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ruster_core::IfId;

use super::*;
use crate::run::tests::counting;

const TARGETS: [LinkTarget; 2] = [
    LinkTarget {
        watch_uppers: false,
        interface: IfId(1),
        ifindex: 11,
        name: crate::run::netlink::IfName::literal(b"veth0"),
        mtu: 1500,
        frame_capacity: 1792,
    },
    LinkTarget {
        watch_uppers: false,
        interface: IfId(2),
        ifindex: 12,
        name: crate::run::netlink::IfName::literal(b"veth0"),
        mtu: 1500,
        frame_capacity: 1792,
    },
];

/// A `Send` link monitor: answers every query, records the calls and the
/// thread they ran on, and blocks in `query` while `closed` (a `send`
/// waiting for the RTNL lock).
#[derive(Clone, Default)]
struct Monitor {
    calls: Arc<Mutex<Vec<(&'static str, u32)>>>,
    threads: Arc<Mutex<Vec<Option<String>>>>,
    closed: Arc<AtomicBool>,
    blocked: Arc<AtomicU32>,
    /// `query` of this ifindex fails.
    failing: Option<u32>,
    /// `query` panics (a dead watcher).
    panics: bool,
}

impl Monitor {
    fn record(&self, call: &'static str, target: &LinkTarget) {
        self.calls.lock().unwrap().push((call, target.ifindex));
    }
}

impl LinkMonitor for Monitor {
    fn stacked_links(&mut self, _: &[u32], counts: &mut [u32]) -> Result<(), NetlinkError> {
        counts.iter_mut().for_each(|count| *count = 0);
        Ok(())
    }

    fn query(&mut self, target: &LinkTarget) -> Result<LinkFacts, NetlinkError> {
        assert!(!self.panics, "watcher dies");
        self.threads
            .lock()
            .unwrap()
            .push(thread::current().name().map(str::to_owned));
        if self.closed.load(Ordering::SeqCst) {
            self.blocked.fetch_add(1, Ordering::SeqCst);
            while self.closed.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
        }
        self.record("link", target);
        if self.failing == Some(target.ifindex) {
            return Err(NetlinkError::Errno(110));
        }
        Ok(LinkFacts {
            name: target.name,
            mtu: target.mtu + 1,
            rx_queues: Some(1),
            admin_up: true,
            lower_up: true,
            master: None,
        })
    }

    fn ipv4_addresses(&mut self, target: &LinkTarget) -> Result<u32, NetlinkError> {
        self.record("addresses", target);
        Ok(target.ifindex)
    }

    fn ipv4_routes(&mut self, target: &LinkTarget) -> Result<u32, NetlinkError> {
        self.record("routes", target);
        Ok(target.ifindex + 100)
    }

    fn ipv6(&mut self, target: &LinkTarget) -> Ipv6Sample {
        self.record("ipv6", target);
        Ipv6Sample::DISABLED
    }

    fn forwarding(&mut self, target: &LinkTarget) -> Result<Forwarding, ()> {
        self.record("forwarding", target);
        Ok(Forwarding::default())
    }

    fn ipv4_weak_host(&mut self, target: &LinkTarget) -> Option<bool> {
        self.record("weak-host", target);
        Some(false)
    }
}

fn no_prologue() -> Result<(), DropFailure> {
    Ok(())
}

/// Polls until the round is back (bounded).
fn wait_round(watcher: &mut LinkWatcher) -> Vec<PortRound> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(round) = watcher.poll() {
            return round.ports().to_vec();
        }
        assert!(Instant::now() < deadline, "the round never came back");
        thread::sleep(Duration::from_millis(1));
    }
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_round_runs_every_query_in_order_on_the_watcher_thread() {
    let monitor = Monitor {
        failing: Some(12),
        ..Monitor::default()
    };
    let mut watcher = LinkWatcher::spawn(monitor.clone(), &TARGETS, no_prologue).expect("spawned");
    assert_eq!(watcher.running_since(), None);
    assert!(watcher.request(MonotonicMillis(7)));
    let ports = wait_round(&mut watcher);
    assert_eq!(watcher.running_since(), None);
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0].link.map(|facts| facts.mtu), Ok(1501));
    assert_eq!(ports[0].addresses, Some(Ok(11)));
    assert_eq!(ports[0].routes, Some(Ok(111)));
    assert_eq!(ports[0].ipv6, Some(Ipv6Sample::DISABLED));
    // A failed link query skips the dumps of that port, as before H7.
    assert_eq!(ports[1].link, Err(NetlinkError::Errno(110)));
    assert_eq!(
        (ports[1].addresses, ports[1].routes, ports[1].ipv6),
        (None, None, None)
    );
    assert_eq!(ports[1].forwarding, Ok(Forwarding::default()));
    assert_eq!(ports[1].weak_host, Some(false));
    assert_eq!(
        *monitor.calls.lock().unwrap(),
        [
            ("link", 11),
            ("addresses", 11),
            ("routes", 11),
            ("forwarding", 11),
            ("weak-host", 11),
            ("ipv6", 11),
            ("link", 12),
            ("forwarding", 12),
            ("weak-host", 12),
        ]
    );
    let threads = monitor.threads.lock().unwrap().clone();
    assert!(
        threads
            .iter()
            .all(|name| name.as_deref() == Some("ruster-watch")),
        "{threads:?}"
    );
    // The buffer is lent again for the next round.
    assert!(watcher.request(MonotonicMillis(8)));
    assert_eq!(wait_round(&mut watcher).len(), 2);
    let worker = watcher.stop().expect("worker");
    assert!(worker.finish(Instant::now() + Duration::from_secs(30)));
}

/// At most one round is outstanding: while the watcher is stuck (a `send`
/// waiting for the RTNL lock) the router sees it running since its
/// request and requests nothing more; nothing is lost when it returns.
#[test]
fn a_stuck_watcher_keeps_one_round_outstanding_and_never_blocks_the_caller() {
    let monitor = Monitor::default();
    monitor.closed.store(true, Ordering::SeqCst);
    let mut watcher = LinkWatcher::spawn(monitor.clone(), &TARGETS, no_prologue).expect("spawned");
    assert!(watcher.request(MonotonicMillis(100)));
    wait_until("the watcher blocks", || {
        monitor.blocked.load(Ordering::SeqCst) == 1
    });
    let started = Instant::now();
    for now in 101..2_000 {
        assert!(!watcher.request(MonotonicMillis(now)));
        assert!(watcher.poll().is_none());
        assert_eq!(watcher.running_since(), Some(MonotonicMillis(100)));
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "requests and polls returned at once"
    );
    monitor.closed.store(false, Ordering::SeqCst);
    assert_eq!(wait_round(&mut watcher).len(), 2);
    assert_eq!(watcher.running_since(), None);
    assert!(watcher.request(MonotonicMillis(2_000)));
    wait_round(&mut watcher);
}

/// The router thread's side of the handoff allocates nothing: requests,
/// polls of a running round, and taking finished rounds back.
#[test]
fn the_handoff_does_not_allocate_on_the_router_thread() {
    let mut watcher =
        LinkWatcher::spawn(Monitor::default(), &TARGETS, no_prologue).expect("spawned");
    // Warm up (first use of the channels).
    assert!(watcher.request(MonotonicMillis(0)));
    wait_round(&mut watcher);
    let before = counting::count();
    counting::arm(true);
    let mut rounds = 0;
    for now in 1..200 {
        assert!(watcher.request(MonotonicMillis(now)));
        loop {
            if watcher.poll().is_some() {
                rounds += 1;
                break;
            }
            let _ = watcher.request(MonotonicMillis(now));
            thread::yield_now();
        }
    }
    counting::arm(false);
    assert_eq!(rounds, 199);
    assert_eq!(counting::count() - before, 0, "allocation in the handoff");
}

/// Shutdown: an idle watcher ends at once; one stuck in a round is
/// abandoned at the deadline, so the caller waits at most until then.
#[test]
fn a_stopped_watcher_ends_or_is_abandoned_at_the_deadline() {
    let watcher = LinkWatcher::spawn(Monitor::default(), &TARGETS, no_prologue).expect("spawned");
    let worker = watcher.stop().expect("worker");
    assert!(worker.finish(Instant::now() + Duration::from_secs(30)));

    let monitor = Monitor::default();
    monitor.closed.store(true, Ordering::SeqCst);
    let mut watcher = LinkWatcher::spawn(monitor.clone(), &TARGETS, no_prologue).expect("spawned");
    assert!(watcher.request(MonotonicMillis(0)));
    wait_until("the watcher blocks", || {
        monitor.blocked.load(Ordering::SeqCst) == 1
    });
    let worker = watcher.stop().expect("worker");
    let started = Instant::now();
    assert!(!worker.finish(Instant::now() + Duration::from_millis(100)));
    let waited = started.elapsed();
    assert!(
        (Duration::from_millis(90)..Duration::from_secs(5)).contains(&waited),
        "{waited:?}"
    );
    // Let the abandoned thread go.
    monitor.closed.store(false, Ordering::SeqCst);
}

/// A watcher that died keeps its round outstanding forever, so the watch
/// turns it into stale rounds (fail closed) instead of a silent stop.
#[test]
fn a_dead_watcher_stays_outstanding() {
    let monitor = Monitor {
        panics: true,
        ..Monitor::default()
    };
    let mut watcher = LinkWatcher::spawn(monitor, &TARGETS, no_prologue).expect("spawned");
    assert!(watcher.request(MonotonicMillis(5)));
    thread::sleep(Duration::from_millis(50));
    for now in 6..100 {
        assert!(watcher.poll().is_none());
        assert!(!watcher.request(MonotonicMillis(now)));
        assert_eq!(watcher.running_since(), Some(MonotonicMillis(5)));
    }
    let worker = watcher.stop().expect("worker");
    assert!(worker.finish(Instant::now() + Duration::from_secs(30)));
}

/// A failing prologue (the privilege drop) fails the spawn, and the body
/// never runs: the monitor is never queried.
#[test]
fn a_failed_prologue_fails_the_spawn_before_any_round() {
    let monitor = Monitor::default();
    let result = LinkWatcher::spawn(monitor.clone(), &TARGETS, || Err(DropFailure::Injected));
    assert!(matches!(
        result,
        Err(SpawnError::Prologue(DropFailure::Injected))
    ));
    assert!(monitor.calls.lock().unwrap().is_empty());
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let prologue_thread = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&prologue_thread);
    let worker = spawn(
        "ruster-reload",
        move || {
            *seen.lock().unwrap() = thread::current().name().map(str::to_owned);
            Ok(())
        },
        move || flag.store(true, Ordering::SeqCst),
    )
    .expect("spawned");
    assert!(worker.finish(Instant::now() + Duration::from_secs(30)));
    assert!(ran.load(Ordering::SeqCst));
    // The prologue runs on the worker thread itself.
    assert_eq!(
        prologue_thread.lock().unwrap().as_deref(),
        Some("ruster-reload")
    );
}

/// The live prologue: a worker spawned with the per-thread drop holds no
/// capability and has `NoNewPrivs` 1 before its body runs, while the
/// spawning thread keeps what it had (so `drop_process` later finds every
/// worker already dropped).
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
#[test]
fn a_worker_with_the_live_prologue_runs_dropped() {
    use super::super::privileges::{self, parse_status, PrivilegePolicy};

    let status = || {
        parse_status(&std::fs::read_to_string("/proc/thread-self/status").expect("status"))
            .expect("parse")
    };
    let parent = status();
    let seen = Arc::new(Mutex::new(None));
    let record = Arc::clone(&seen);
    let worker = spawn(
        "ruster-watch",
        || privileges::linux::drop_thread(PrivilegePolicy::Drop { identity: None }).map(drop),
        move || *record.lock().unwrap() = Some(status()),
    )
    .expect("spawned");
    assert!(worker.finish(Instant::now() + Duration::from_secs(30)));
    let dropped = seen.lock().unwrap().expect("body ran");
    assert_eq!(
        (
            dropped.inheritable,
            dropped.permitted,
            dropped.effective,
            dropped.ambient
        ),
        (0, 0, 0, 0)
    );
    assert!(dropped.no_new_privs);
    assert_eq!(status(), parent, "the drop leaked to the spawning thread");
}

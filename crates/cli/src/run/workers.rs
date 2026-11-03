//! Cold-path worker threads of `ruster run` (H7): the link watcher and
//! the reload preparer ([`super::reload`]).
//!
//! # Threads
//!
//! | thread | name | runs |
//! |---|---|---|
//! | router | `ruster` | the run loop: ticks, health samples, watch decisions, reload publication |
//! | link watcher | `ruster-watch` | one rtnetlink and sysctl round per request ([`LinkWatcher`]) |
//! | reload preparer | `ruster-reload` | read, validate, candidate, document plan ([`super::reload::ReloadWorker`]) |
//! | output | `ruster-stdout`, `ruster-stderr` | the stdout and stderr lines ([`super::output`]) |
//!
//! Each worker is spawned with [`spawn`] after activation and before the
//! router thread drops its own privileges, and runs the per-thread
//! privilege drop ([`super::privileges`]) as its prologue before it takes
//! anything; the spawn waits for the outcome and fails startup if it
//! fails. The router thread's process-wide verification then reads every
//! thread, the workers included.
//!
//! # Handoff
//!
//! Message passing only: each worker owns what it works on (the watcher
//! the rtnetlink socket and sysctl paths, the preparer the production
//! sequencer and the documents), and the router thread talks to it over
//! two bounded `std::sync::mpsc` channels that it only touches with
//! `try_send` and `try_recv`, at most once per loop iteration and only
//! while a request is outstanding, between ticks. The router thread never
//! blocks on a worker and never takes an application lock (the channels'
//! internal waker lock is taken only to wake a worker that sleeps in
//! `recv`, i.e. at most once per request, never per packet).
//!
//! The link round travels as one preallocated buffer ([`LinkRound`],
//! sized once at startup): the router thread lends it with the request
//! and gets it back filled, so no round allocates on either side.
//!
//! # Shutdown
//!
//! At the end of the run the router thread drops its channel ends; a
//! worker waiting for a request ends at once, one in the middle of a round
//! or a preparation ends when that returns. [`Worker::finish`] waits for
//! that at most until a deadline ([`WORKER_STOP_MS`] after the loop ended,
//! overlapping the drain) and then abandons the thread, which dies with the
//! process: a watcher stuck in a `send` while another process holds the
//! RTNL lock delays the detach and the exit by at most that bound. (The
//! XDP detach itself needs RTNL too, so while another process holds it the
//! exit waits for the kernel anyway, as before H7.)

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use ruster_config::MAX_BACKEND_PORTS;
use ruster_core::MonotonicMillis;

use super::engine::LinkMonitor;
use super::netlink::{LinkFacts, NetlinkError};
use super::output::SpawnError;
use super::privileges::DropFailure;
use super::watch::{Forwarding, Ipv6Sample, LinkTarget};

/// How long the shutdown waits for the workers to end after the loop
/// ended (counted from then, so it overlaps the drain) before it abandons
/// them.
pub const WORKER_STOP_MS: u64 = 500;

/// One spawned worker thread.
pub struct Worker {
    done: Receiver<()>,
    handle: Option<JoinHandle<()>>,
}

/// Spawns a worker thread named `name` that runs `prologue` (the
/// per-thread privilege drop) and, only if it succeeds, `body`. Waits for
/// the prologue's outcome; on an error the thread has already ended
/// without running `body` (which is dropped on that thread).
pub fn spawn<P, B>(name: &str, prologue: P, body: B) -> Result<Worker, SpawnError<DropFailure>>
where
    P: FnOnce() -> Result<(), DropFailure> + Send + 'static,
    B: FnOnce() + Send + 'static,
{
    let (finished, done) = mpsc::sync_channel(1);
    let (started, outcome) = mpsc::sync_channel(1);
    let handle = thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let ready = prologue();
            let ok = ready.is_ok();
            let _ = started.send(ready);
            if ok {
                body();
            } else {
                drop(body);
            }
            // A panic in `body` drops `finished` unsent, which `finish`
            // also reads as ended.
            let _ = finished.send(());
        })
        .map_err(|_| SpawnError::Io)?;
    match outcome.recv() {
        Ok(Ok(())) => Ok(Worker {
            done,
            handle: Some(handle),
        }),
        Ok(Err(error)) => {
            let _ = handle.join();
            Err(SpawnError::Prologue(error))
        }
        Err(_) => Err(SpawnError::Io),
    }
}

impl Worker {
    /// Waits until `deadline` for the thread to end (the caller has
    /// dropped its channel ends) and joins it; returns `false` and
    /// abandons (detaches) a thread that is still running then.
    pub fn finish(mut self, deadline: Instant) -> bool {
        let wait = deadline.saturating_duration_since(Instant::now());
        match self.done.recv_timeout(wait) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
        }
    }
}

/// What one link round read for one port. `addresses`, `routes`, and
/// `ipv6` are read only after a successful link query of the same round
/// (`None` otherwise), as before H7.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortRound {
    pub link: Result<LinkFacts, NetlinkError>,
    pub addresses: Option<Result<u32, NetlinkError>>,
    pub routes: Option<Result<u32, NetlinkError>>,
    pub forwarding: Result<Forwarding, ()>,
    pub weak_host: Option<bool>,
    pub ipv6: Option<Ipv6Sample>,
    /// AF_PACKET ports: devices stacked on the port (one bounded link
    /// dump into the probe's reused buffer, no allocation).
    pub uppers: Option<Result<u32, NetlinkError>>,
}

impl PortRound {
    /// A slot that no round has filled yet.
    const EMPTY: Self = Self {
        link: Err(NetlinkError::EndOfStream),
        addresses: None,
        routes: None,
        forwarding: Err(()),
        weak_host: None,
        ipv6: None,
        uppers: None,
    };
}

/// One link round of every port, in `IfId` order: a buffer allocated once
/// at startup and lent to the watcher with each request.
#[derive(Debug)]
pub struct LinkRound {
    ports: Box<[PortRound]>,
}

impl LinkRound {
    pub fn new(ports: usize) -> Self {
        Self {
            ports: vec![PortRound::EMPTY; ports].into_boxed_slice(),
        }
    }

    /// The ports' results, in `IfId` order.
    pub fn ports(&self) -> &[PortRound] {
        &self.ports
    }
}

/// Runs one link round over `targets` into `round` (the queries and their
/// order of the pre-H7 router-thread round). No allocation.
pub fn probe_round<L: LinkMonitor>(links: &mut L, targets: &[LinkTarget], round: &mut LinkRound) {
    for (target, port) in targets.iter().zip(round.ports.iter_mut()) {
        let link = links.query(target);
        let linked = link.is_ok();
        port.link = link;
        port.addresses = linked.then(|| links.ipv4_addresses(target));
        port.routes = linked.then(|| links.ipv4_routes(target));
        port.forwarding = links.forwarding(target);
        port.weak_host = links.ipv4_weak_host(target);
        port.ipv6 = linked.then(|| links.ipv6(target));
        port.uppers = None;
    }
    stacked_round(links, targets, round);
}

/// The stacked-device check of the round: one link dump for every
/// AF_PACKET port whose link query succeeded (the dump reads every link
/// of the namespace, so its cost does not grow with the port count), into
/// fixed arrays of [`MAX_BACKEND_PORTS`] (no allocation).
fn stacked_round<L: LinkMonitor>(links: &mut L, targets: &[LinkTarget], round: &mut LinkRound) {
    let mut ifindexes = [0_u32; MAX_BACKEND_PORTS];
    let mut counts = [0_u32; MAX_BACKEND_PORTS];
    let mut watched = 0;
    for (target, port) in targets.iter().zip(round.ports.iter()) {
        if target.watch_uppers && port.link.is_ok() && watched < MAX_BACKEND_PORTS {
            ifindexes[watched] = target.ifindex;
            watched += 1;
        }
    }
    // Validation bounds the ports by MAX_BACKEND_PORTS, so every watched
    // port fits; one that did not would get a failed query below (fail
    // closed), never no answer.
    debug_assert!(targets.len() <= MAX_BACKEND_PORTS);
    if watched == 0 {
        return;
    }
    let result = links.stacked_links(&ifindexes[..watched], &mut counts[..watched]);
    let mut at = 0;
    for (target, port) in targets.iter().zip(round.ports.iter_mut()) {
        if target.watch_uppers && port.link.is_ok() {
            port.uppers = Some(if at < watched {
                result.map(|()| counts[at])
            } else {
                Err(NetlinkError::Truncated)
            });
            at += 1;
        }
    }
}

/// The router thread's end of the link watcher.
///
/// [`Self::request`] lends the round buffer to the watcher thread, which
/// runs [`probe_round`] and sends it back; [`Self::poll`] takes it back
/// once it is done. At most one round is outstanding, so a watcher that
/// is stuck (a `send` waiting for the RTNL lock) is visible as a round
/// running since [`Self::running_since`], which the watch turns into a
/// stale round ([`super::watch::Watch::on_late_round`]).
pub struct LinkWatcher {
    requests: SyncSender<Box<LinkRound>>,
    replies: Receiver<Box<LinkRound>>,
    /// The buffer while no round runs.
    idle: Option<Box<LinkRound>>,
    /// A reply taken early by a lockstep request (tests).
    #[cfg(test)]
    early: Option<Box<LinkRound>>,
    /// When the outstanding round was requested (or the watcher was found
    /// gone).
    since: Option<MonotonicMillis>,
    worker: Option<Worker>,
    /// Tests: every request waits for its reply (see [`lockstep_wait`]).
    #[cfg(test)]
    lockstep: bool,
}

impl LinkWatcher {
    /// Spawns the watcher thread `ruster-watch` over `links` and
    /// `targets`; it runs `prologue` first.
    pub fn spawn<L, P>(
        mut links: L,
        targets: &[LinkTarget],
        prologue: P,
    ) -> Result<Self, SpawnError<DropFailure>>
    where
        L: LinkMonitor + Send + 'static,
        P: FnOnce() -> Result<(), DropFailure> + Send + 'static,
    {
        let (requests, jobs) = mpsc::sync_channel::<Box<LinkRound>>(1);
        let (done, replies) = mpsc::sync_channel::<Box<LinkRound>>(1);
        let owned: Box<[LinkTarget]> = targets.into();
        let worker = spawn("ruster-watch", prologue, move || {
            for mut round in jobs {
                probe_round(&mut links, &owned, &mut round);
                if done.send(round).is_err() {
                    return;
                }
            }
        })?;
        Ok(Self {
            requests,
            replies,
            idle: Some(Box::new(LinkRound::new(targets.len()))),
            #[cfg(test)]
            early: None,
            since: None,
            worker: Some(worker),
            #[cfg(test)]
            lockstep: false,
        })
    }

    /// Tests: makes every request wait (bounded) for its reply, so a round
    /// completes within the loop iteration that requested it, as before
    /// H7.
    #[cfg(test)]
    #[must_use]
    pub fn lockstep(mut self, on: bool) -> Self {
        self.lockstep = on;
        self
    }

    /// Requests a round at `now`. `false` if one is still outstanding (or
    /// the watcher is gone: its round never completes). Never blocks
    /// (except in test lockstep) and never allocates.
    pub fn request(&mut self, now: MonotonicMillis) -> bool {
        let Some(round) = self.idle.take() else {
            return false;
        };
        self.since = Some(now);
        match self.requests.try_send(round) {
            Ok(()) => {
                #[cfg(test)]
                if self.lockstep {
                    self.early = lockstep_wait(&self.replies);
                }
                true
            }
            // Only one buffer exists and it is lent only while idle, so the
            // queue is never full.
            Err(TrySendError::Full(round)) => {
                debug_assert!(false, "the link request queue is never full");
                self.idle = Some(round);
                self.since = None;
                false
            }
            // A gone watcher: the buffer is dropped on purpose, so `idle`
            // stays empty and the round stays outstanding since `now`
            // forever, which the watch turns into stale rounds (fail
            // closed). Nothing is allocated or freed per round otherwise.
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// The outstanding round, once the watcher has finished it. Never
    /// blocks and never allocates.
    pub fn poll(&mut self) -> Option<&LinkRound> {
        if self.idle.is_some() || self.since.is_none() {
            return None;
        }
        #[cfg(test)]
        let early = self.early.take();
        #[cfg(not(test))]
        let early = None;
        let round = match early {
            Some(round) => round,
            None => match self.replies.try_recv() {
                Ok(round) => round,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return None,
            },
        };
        self.since = None;
        self.idle = Some(round);
        self.idle.as_deref()
    }

    /// Since when the outstanding round runs, if one does.
    pub const fn running_since(&self) -> Option<MonotonicMillis> {
        match self.idle {
            Some(_) => None,
            None => self.since,
        }
    }

    /// Ends the watcher: drops the router thread's channel ends (a waiting
    /// watcher ends at once, a running round first returns) and hands back
    /// the thread for a bounded [`Worker::finish`].
    pub fn stop(mut self) -> Option<Worker> {
        self.worker.take()
    }
}

/// Tests only (`lockstep`): waits up to 30 s of wall time for a reply,
/// spinning on `try_recv` with short sleeps (no allocation, no blocking
/// `recv`).
#[cfg(test)]
pub fn lockstep_wait<T>(replies: &Receiver<T>) -> Option<T> {
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match replies.try_recv() {
            Ok(reply) => return Some(reply),
            Err(TryRecvError::Disconnected) => return None,
            Err(TryRecvError::Empty) if Instant::now() >= deadline => return None,
            Err(TryRecvError::Empty) => thread::sleep(std::time::Duration::from_micros(50)),
        }
    }
}

#[cfg(test)]
#[path = "workers_tests.rs"]
mod tests;

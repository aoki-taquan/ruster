//! The FPM end that zebra connects to: a TCP listener on the loopback address of
//! the router's kernel namespace, one connection at a time.
//!
//! - A new connection replaces the one before (zebra connected again). The routes
//!   held are marked stale; zebra sends all of its routes again, and once it has
//!   been quiet for [`QUIET_MS`] the routes it did not send again are removed.
//!   zebra marks no end of its sending, so quiet is the sign; at the latest the
//!   routes are swept [`RESYNC_MAX_MS`] after it connected. A zebra that started
//!   again connects before bgpd has its routes, so its routes come back as bgpd
//!   learns them again.
//! - While no connection is up, the routes are kept for [`HOLD_MS`], then removed.
//! - A frame that is not FPM version 1 netlink ends the connection; a message that
//!   cannot be read is counted and passed over, and the first reason of each
//!   connection is logged.
//! - With an owner given ([`Fpm::bind`]), a connection is taken only from a socket of
//!   that user, as `/proc/net/tcp` shows it: anyone on the router may connect to a
//!   TCP port, and zebra runs as `frr`. `ruster-frr` gives the `frr` user's ID
//!   unless told otherwise.
//!
//! [`Fpm::ready`] says when what ruster-frr holds is worth giving to ribd: after
//! zebra's first sending went quiet, or after [`HOLD_MS`] without zebra.
//!
//! # Standards
//!
//! - FRR's FPM (`dplane_fpm_nl`): TCP, zebra connects, frames as in [`crate::fpm`].
//!
//! Deviations: no authentication beyond the owner check; IPv4 loopback only.

use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};

use ruster_config::Connected;
use ruster_proto::table::Change;

use crate::fpm::{self, Message};
use crate::routes::Routes;

/// How long zebra is quiet after connecting before the routes it did not send again
/// are removed, in milliseconds.
pub const QUIET_MS: u64 = 3_000;
/// How long the routes are kept while zebra is not connected, in milliseconds.
pub const HOLD_MS: u64 = 30_000;
/// The longest a resync waits for zebra to be quiet, in milliseconds.
pub const RESYNC_MAX_MS: u64 = 30_000;
/// The most connections taken per step, so a flood of them does not hold the loop.
const ACCEPTS_PER_STEP: usize = 8;
/// The most bytes read per step, so a fast sender does not hold the loop.
const READ_PER_STEP: usize = 1 << 20;

struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
    /// Messages passed over on this connection.
    bad: u64,
}

pub struct Fpm {
    listener: TcpListener,
    owner: Option<u32>,
    conn: Option<Conn>,
    routes: Routes,
    /// When the routes start being swept after a connection: the last message's time.
    resync_since: Option<u64>,
    /// When the connection being resynced came.
    connected_at: u64,
    /// When the connection went away.
    lost_at: Option<u64>,
    started_at: Option<u64>,
    ready: bool,
}

impl std::fmt::Debug for Fpm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fpm")
            .field("connected", &self.conn.is_some())
            .field("routes", &self.routes.len())
            .finish_non_exhaustive()
    }
}

impl Fpm {
    /// Listens on 127.0.0.1:`port` (0 for any free port). With `owner`, only
    /// connections from sockets of that user ID are taken.
    pub fn bind(port: u16, owner: Option<u32>) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            owner,
            conn: None,
            routes: Routes::new(),
            resync_since: None,
            connected_at: 0,
            lost_at: None,
            started_at: None,
            ready: false,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn connected(&self) -> bool {
        self.conn.is_some()
    }

    /// Whether what is held should go to ribd now.
    pub fn ready(&self) -> bool {
        self.ready
    }

    pub fn routes(&self) -> &Routes {
        &self.routes
    }

    /// Takes the TAP devices' indexes ([`crate::routes::tap_indexes`]); the
    /// changes for ribd.
    pub fn set_taps(&mut self, taps: std::collections::BTreeMap<u32, String>) -> Vec<Change> {
        self.routes.set_taps(taps)
    }

    /// Takes the interfaces' prefixes from confd's part; the changes for ribd.
    pub fn set_connected(&mut self, connected: &[Connected]) -> Vec<Change> {
        self.routes.set_connected(connected)
    }

    /// Takes connections and frames, and keeps the timers. Returns the changes for
    /// ribd, whether anything moved, and when to come back.
    pub fn step(&mut self, now: u64) -> (Vec<Change>, bool, Option<u64>) {
        let started = *self.started_at.get_or_insert(now);
        let mut changes = Vec::new();
        let mut busy = self.accept(now);
        if let Some(conn) = &mut self.conn {
            match read(conn, &mut self.routes, &mut changes) {
                Ok(moved) => {
                    if moved {
                        busy = true;
                        self.resync_since = self.resync_since.map(|_| now);
                    }
                }
                Err(reason) => {
                    eprintln!("ruster-frr: FPM connection ended: {reason}");
                    self.conn = None;
                    self.lost_at = Some(now);
                    busy = true;
                }
            }
        }
        let mut wake = None;
        if let (Some(_), None) = (self.resync_since, &self.conn) {
            // zebra went away while sending: the routes stay stale and held until
            // the next connection or the hold time.
            self.resync_since = None;
        }
        if let Some(since) = self.resync_since {
            // Quiet, or at the latest RESYNC_MAX_MS after it connected: zebra may
            // never be quiet while routes keep changing.
            let at = since
                .saturating_add(QUIET_MS)
                .min(self.connected_at.saturating_add(RESYNC_MAX_MS));
            if now >= at {
                changes.extend(self.routes.sweep());
                self.resync_since = None;
                self.ready = true;
                busy = true;
            } else {
                wake = Some(at);
            }
        }
        if let (None, Some(lost)) = (&self.conn, self.lost_at) {
            if now >= lost.saturating_add(HOLD_MS) {
                changes.extend(self.routes.clear());
                self.lost_at = None;
                busy = true;
            } else {
                wake = Some(lost.saturating_add(HOLD_MS));
            }
        }
        if !self.ready && self.conn.is_none() && self.resync_since.is_none() {
            if now >= started.saturating_add(HOLD_MS) {
                self.ready = true;
            } else {
                let at = started.saturating_add(HOLD_MS);
                wake = Some(wake.map_or(at, |w: u64| w.min(at)));
            }
        }
        (changes, busy, wake)
    }

    fn accept(&mut self, now: u64) -> bool {
        let mut busy = false;
        for _ in 0..ACCEPTS_PER_STEP {
            let (stream, peer) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return busy,
                Err(error) => {
                    eprintln!("ruster-frr: FPM accept: {error}");
                    return busy;
                }
            };
            busy = true;
            if let Some(owner) = self.owner {
                let local = stream.local_addr().ok();
                let uid = local.and_then(|local| socket_owner(peer, local));
                if uid != Some(owner) {
                    eprintln!(
                        "ruster-frr: FPM connection from {peer} refused: its owner is {uid:?}, not {owner}"
                    );
                    continue;
                }
            }
            if stream.set_nonblocking(true).is_err() {
                continue;
            }
            eprintln!("ruster-frr: FPM connected from {peer}");
            self.conn = Some(Conn {
                stream,
                buf: Vec::new(),
                bad: 0,
            });
            self.lost_at = None;
            self.routes.mark_stale();
            self.resync_since = Some(now);
            self.connected_at = now;
        }
        busy
    }
}

/// Reads what is there and takes the whole frames. `Ok(true)` when anything was
/// read; `Err` when the connection is over.
fn read(conn: &mut Conn, routes: &mut Routes, changes: &mut Vec<Change>) -> Result<bool, String> {
    let mut chunk = [0u8; 64 * 1_024];
    let mut total = 0;
    let mut moved = false;
    while total < READ_PER_STEP {
        match conn.stream.read(&mut chunk) {
            Ok(0) => return Err("closed by zebra".into()),
            Ok(n) => {
                total += n;
                moved = true;
                conn.buf.extend_from_slice(&chunk[..n]);
                frames(conn, routes, changes)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(moved)
}

/// Takes every whole frame in the buffer; at most one frame (64 KiB) stays.
fn frames(conn: &mut Conn, routes: &mut Routes, changes: &mut Vec<Change>) -> Result<(), String> {
    let mut at = 0;
    while let Some((body, used)) = fpm::next_frame(&conn.buf[at..]).map_err(|e| e.to_string())? {
        let mut taken = Vec::new();
        for message in fpm::messages(body) {
            match message {
                Ok(Message::Route(route)) => taken.push(route),
                Ok(Message::Ignored) => {}
                Err(reason) => {
                    if conn.bad == 0 {
                        eprintln!("ruster-frr: an FPM message passed over: {reason}");
                    }
                    conn.bad += 1;
                }
            }
        }
        changes.extend(routes.take_frame(&taken));
        at += used;
    }
    conn.buf.drain(..at);
    Ok(())
}

/// The user ID that owns the TCP socket at `peer` connected to `local`, from
/// `/proc/net/tcp` (the namespace's IPv4 sockets): the line whose local address is
/// `peer` and whose remote address is `local`.
pub fn socket_owner(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let table = std::fs::read_to_string("/proc/net/tcp").ok()?;
    owner_in(&table, peer, local)
}

/// [`socket_owner`] on the text of `/proc/net/tcp`.
pub fn owner_in(table: &str, peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let hex = |a: SocketAddr| match a {
        SocketAddr::V4(a) => Some(format!(
            "{:08X}:{:04X}",
            u32::from_ne_bytes(a.ip().octets()),
            a.port()
        )),
        SocketAddr::V6(_) => None,
    };
    let (peer, local) = (hex(peer)?, hex(local)?);
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.get(1) == Some(&peer.as_str()) && fields.get(2) == Some(&local.as_str()))
            .then(|| fields.get(7)?.parse().ok())
            .flatten()
    })
}

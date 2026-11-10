//! The DHCPv4 client of one interface, without I/O.
//!
//! A [`Client`] is driven by the caller: [`Client::receive`] with each DHCP reply
//! that came to the interface, [`Client::timeout`] when [`Client::next_timer`]
//! comes. Each fills an [`Output`] with the messages to send ([`Send`]) and what
//! changed ([`Event`]): [`Event::Bound`] with the whole lease each time it is taken
//! or renewed, [`Event::Lost`] when the address may no longer be used. Times are in
//! milliseconds from any fixed start.
//!
//! # Standards
//!
//! - RFC 2131 section 4.4 (figure 5): the states INIT, SELECTING, REQUESTING,
//!   BOUND, RENEWING and REBINDING. Section 4.4.1: the first DHCPDISCOVER goes
//!   after a random wait of 1 to 10 s. The first offer is taken. Section 4.4.5: T1
//!   and T2 are 0.5 and 0.875 of the lease time unless the server gives them; in
//!   RENEWING the DHCPREQUEST goes to the server, in REBINDING it is broadcast,
//!   each sent again after half the time left until T2 (or the lease's end), at
//!   least 60 s; at the end of the lease the address is given up. A DHCPNAK sends
//!   the client back to INIT.
//! - RFC 2131 section 4.1: messages are sent again after 4 s, doubling up to 64 s,
//!   each wait randomized by -1 to +1 s; a DHCPREQUEST in REQUESTING is sent
//!   [`REQUEST_TRIES`] times before going back to INIT (section 3.1, step 5).
//! - RFC 2131 section 3.1, step 5, and section 4.4.4: a leased address that cannot
//!   be used is declined with DHCPDECLINE, and the client waits 10 s before INIT.
//!   Section 4.4.6: [`Client::release`] gives the address back with DHCPRELEASE.
//!
//! Deviations: no ARP check of the leased address before using it (RFC 2131 section
//! 2.2 says the client SHOULD probe): only an address that cannot be a host's (not
//! unicast, or its subnet's network or broadcast address) is declined. No
//! INIT-REBOOT: a client that starts again begins with DHCPDISCOVER. An ACK
//! without a subnet mask is taken with the address's class mask (RFC 791), and one
//! without a lease time is ignored. T1 and T2 that are not below the lease time (T1
//! below T2) are replaced by the defaults. A lease shorter than 20 s is taken as
//! 20 s, and going back to INIT (after a DHCPNAK or the end of a lease) waits 1 to
//! 10 s as at the start. The lease is timed from when the DHCPACK arrives, not from
//! when the request was sent (section 4.4.1). An ACK to a renewal may give another
//! address; [`Event::Bound`] then carries it, and the old one is no longer held.
//! The BROADCAST flag is set in RENEWING and REBINDING too, as in the other states
//! ([`crate::dhcp4`]).

use std::net::Ipv4Addr;

use crate::dhcp4::{self, kind, Reply, Request};
use crate::Rng;

/// How many times a DHCPREQUEST is sent in REQUESTING.
pub const REQUEST_TRIES: u32 = 4;
/// The least wait between retransmissions in RENEWING and REBINDING.
const LEAST_RENEW_WAIT_MS: u64 = 60_000;
/// The wait after a DHCPDECLINE.
const DECLINE_WAIT_MS: u64 = 10_000;
/// The shortest lease taken, in seconds.
const LEAST_LEASE: u32 = 20;
/// A lease time of all ones is infinite.
const INFINITE: u32 = u32::MAX;

/// What the client holds while it has an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// The server identifier.
    pub server: Ipv4Addr,
    /// In seconds; [`u32::MAX`] is infinite.
    pub lease_time: u32,
    pub t1: u32,
    pub t2: u32,
}

/// The state of RFC 2131 figure 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    /// Released, or waiting after a DHCPDECLINE.
    Stopped,
}

/// Where a message goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum To {
    /// To 255.255.255.255 and the broadcast MAC address.
    Broadcast,
    /// To the server's address.
    Server(Ipv4Addr),
}

/// A message to send from port 68 to port 67.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Send {
    pub to: To,
    /// The source address: the client's, or 0.0.0.0 while it has none.
    pub from: Ipv4Addr,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Bound(Lease),
    Lost,
}

#[derive(Debug, Default)]
pub struct Output {
    pub sends: Vec<Send>,
    pub events: Vec<Event>,
}

#[derive(Debug)]
pub struct Client {
    mac: [u8; 6],
    rng: Rng,
    state: State,
    xid: u32,
    /// When the exchange began, for `secs`.
    started_at: u64,
    /// The offered address and its server, in REQUESTING.
    offer: Option<(Ipv4Addr, Ipv4Addr)>,
    lease: Option<Lease>,
    bound_at: u64,
    timer: Option<u64>,
    tries: u32,
    /// The wait before the next retransmission (before randomizing).
    wait_ms: u64,
}

impl Client {
    /// A client that sends its first DHCPDISCOVER 1 to 10 s after `now`.
    pub fn new(mac: [u8; 6], seed: u64, now: u64) -> Self {
        let mut rng = Rng::new(seed);
        let first = now + 1_000 + rng.below(9_001);
        Self {
            mac,
            rng,
            state: State::Init,
            xid: 0,
            started_at: now,
            offer: None,
            lease: None,
            bound_at: 0,
            timer: Some(first),
            tries: 0,
            wait_ms: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    pub fn next_timer(&self) -> Option<u64> {
        self.timer
    }

    fn request(&self, now: u64, kind: u8) -> Request {
        Request {
            kind,
            xid: self.xid,
            secs: u16::try_from(now.saturating_sub(self.started_at) / 1_000).unwrap_or(u16::MAX),
            mac: self.mac,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested: None,
            server: None,
        }
    }

    /// A new exchange: a new transaction ID, `secs` from now, the first wait.
    fn begin(&mut self, now: u64) {
        self.xid = self.rng.next_u64() as u32;
        self.started_at = now;
        self.tries = 0;
        self.wait_ms = 4_000;
    }

    /// The next retransmission: the wait randomized by -1 to +1 s, then doubled up
    /// to 64 s.
    fn backoff(&mut self, now: u64) {
        let wait = self.wait_ms - 1_000 + self.rng.below(2_001);
        self.timer = Some(now + wait);
        self.wait_ms = (self.wait_ms * 2).min(64_000);
        self.tries += 1;
    }

    fn discover(&mut self, now: u64, out: &mut Output) {
        let payload = self.request(now, kind::DISCOVER).encode();
        out.sends.push(Send {
            to: To::Broadcast,
            from: Ipv4Addr::UNSPECIFIED,
            payload,
        });
        self.backoff(now);
    }

    fn select(&mut self, now: u64, out: &mut Output) {
        let (address, server) = self.offer.expect("an offer in REQUESTING");
        let payload = Request {
            requested: Some(address),
            server: Some(server),
            ..self.request(now, kind::REQUEST)
        }
        .encode();
        out.sends.push(Send {
            to: To::Broadcast,
            from: Ipv4Addr::UNSPECIFIED,
            payload,
        });
        self.backoff(now);
    }

    /// A DHCPREQUEST of RENEWING (to the server) or REBINDING (broadcast), sent
    /// again after half the time left until `until`, at least 60 s.
    fn extend(&mut self, now: u64, until: u64, out: &mut Output) {
        let lease = self.lease.as_ref().expect("a lease");
        let to = match self.state {
            State::Renewing => To::Server(lease.server),
            _ => To::Broadcast,
        };
        let payload = Request {
            ciaddr: lease.address,
            ..self.request(now, kind::REQUEST)
        }
        .encode();
        out.sends.push(Send {
            to,
            from: lease.address,
            payload,
        });
        let half = until.saturating_sub(now) / 2;
        self.timer = Some(until.min(now + half.max(LEAST_RENEW_WAIT_MS)));
    }

    /// When the lease reaches `seconds` after it was bound; `None` for never.
    fn at(&self, seconds: u32) -> Option<u64> {
        let lease = self.lease.as_ref()?;
        (lease.lease_time != INFINITE).then(|| self.bound_at + u64::from(seconds) * 1_000)
    }

    fn lose(&mut self, now: u64, out: &mut Output) {
        if self.lease.take().is_some() {
            out.events.push(Event::Lost);
        }
        self.restart(now);
    }

    /// Back to INIT, with the same 1 to 10 s wait as at the start, so that a server
    /// that keeps refusing does not make the client send without pause.
    fn restart(&mut self, now: u64) {
        self.offer = None;
        self.state = State::Init;
        self.timer = Some(now + 1_000 + self.rng.below(9_001));
    }

    pub fn timeout(&mut self, now: u64, out: &mut Output) {
        if self.timer.is_none_or(|at| at > now) {
            return;
        }
        self.timer = None;
        match self.state {
            State::Init | State::Stopped => {
                self.state = State::Selecting;
                self.begin(now);
                self.discover(now, out);
            }
            State::Selecting => self.discover(now, out),
            State::Requesting if self.tries >= REQUEST_TRIES => self.restart(now),
            State::Requesting => self.select(now, out),
            State::Bound | State::Renewing | State::Rebinding => self.lease_timer(now, out),
        }
    }

    fn lease_timer(&mut self, now: u64, out: &mut Output) {
        let lease = self.lease.as_ref().expect("a lease while bound");
        let (t2, end) = (lease.t2, lease.lease_time);
        let (Some(t2), Some(end)) = (self.at(t2), self.at(end)) else {
            return;
        };
        if now >= end {
            return self.lose(now, out);
        }
        if now >= t2 {
            if self.state != State::Rebinding {
                self.state = State::Rebinding;
                self.begin(now);
            }
            return self.extend(now, end, out);
        }
        if self.state == State::Bound {
            self.state = State::Renewing;
            self.begin(now);
        }
        self.extend(now, t2, out);
    }

    /// Takes a DHCP message that came to port 68 of the interface.
    pub fn receive(&mut self, now: u64, payload: &[u8], out: &mut Output) {
        let Some(reply) = Reply::parse(payload) else {
            return;
        };
        if reply.xid != self.xid || reply.chaddr != self.mac {
            return;
        }
        match (self.state, reply.kind) {
            (State::Selecting, kind::OFFER) => {
                let Some(server) = reply.server else { return };
                if !host(reply.yiaddr) {
                    return;
                }
                self.offer = Some((reply.yiaddr, server));
                self.state = State::Requesting;
                self.tries = 0;
                self.wait_ms = 4_000;
                self.select(now, out);
            }
            (State::Requesting, kind::ACK) => {
                let Some((address, server)) = self.offer else {
                    return;
                };
                if reply.server.is_some_and(|s| s != server) {
                    return;
                }
                let Some(lease) = lease(&reply, server) else {
                    return;
                };
                if lease.address != address || !usable(&lease) {
                    self.decline(now, &lease, out);
                    return;
                }
                self.bind(now, lease, out);
            }
            (State::Renewing | State::Rebinding, kind::ACK) => {
                let held = self.lease.as_ref().expect("a lease");
                let Some(lease) = lease(&reply, reply.server.unwrap_or(held.server)) else {
                    return;
                };
                if !usable(&lease) {
                    // Keep the address until its lease ends; the server may answer
                    // better to the next request.
                    return;
                }
                self.bind(now, lease, out);
            }
            (State::Requesting, kind::NAK) => self.restart(now),
            (State::Renewing | State::Rebinding, kind::NAK) => self.lose(now, out),
            _ => {}
        }
    }

    fn bind(&mut self, now: u64, lease: Lease, out: &mut Output) {
        self.state = State::Bound;
        self.offer = None;
        self.bound_at = now;
        out.events.push(Event::Bound(lease.clone()));
        self.lease = Some(lease);
        self.timer = self.at(self.lease.as_ref().map_or(0, |l| l.t1));
    }

    fn decline(&mut self, now: u64, lease: &Lease, out: &mut Output) {
        let payload = Request {
            requested: Some(lease.address),
            server: Some(lease.server),
            secs: 0,
            ..self.request(now, kind::DECLINE)
        }
        .encode();
        out.sends.push(Send {
            to: To::Broadcast,
            from: Ipv4Addr::UNSPECIFIED,
            payload,
        });
        self.offer = None;
        self.state = State::Stopped;
        self.timer = Some(now + DECLINE_WAIT_MS);
    }

    /// Gives the address back to the server (DHCPRELEASE) and stops: no timer runs
    /// until the client is made again.
    pub fn release(&mut self, now: u64, out: &mut Output) {
        if let Some(lease) = self.lease.take() {
            self.xid = self.rng.next_u64() as u32;
            let payload = Request {
                ciaddr: lease.address,
                server: Some(lease.server),
                secs: 0,
                ..self.request(now, kind::RELEASE)
            }
            .encode();
            out.sends.push(Send {
                to: To::Server(lease.server),
                from: lease.address,
                payload,
            });
            out.events.push(Event::Lost);
        }
        self.offer = None;
        self.state = State::Stopped;
        self.timer = None;
    }
}

/// The lease an ACK gives, if it has a lease time.
fn lease(reply: &Reply, server: Ipv4Addr) -> Option<Lease> {
    // A lease shorter than this is taken as this long, so that a server giving
    // 0 s does not make the client bind and lose the address without pause.
    let lease_time = reply.lease_time?.max(LEAST_LEASE);
    let prefix_len = reply
        .subnet_mask
        .and_then(dhcp4::mask_len)
        .filter(|len| (1..=32).contains(len))
        .unwrap_or_else(|| class_len(reply.yiaddr));
    let (mut t1, mut t2) = (lease_time / 2, (u64::from(lease_time) * 7 / 8) as u32);
    if let (Some(a), Some(b)) = (reply.t1, reply.t2) {
        if a < b && b < lease_time {
            (t1, t2) = (a, b);
        }
    }
    Some(Lease {
        address: reply.yiaddr,
        prefix_len,
        routers: reply.routers.clone(),
        dns: reply.dns.clone(),
        server,
        lease_time,
        t1,
        t2,
    })
}

/// The prefix length of an address's class (RFC 791): A /8, B /16, C /24.
fn class_len(address: Ipv4Addr) -> u8 {
    match address.octets()[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    }
}

/// An address a host may have (RFC 1122 section 3.2.1.3).
fn host(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    first != 0 && first != 127 && first < 224
}

/// A lease whose address a host may have, and that is not its subnet's network or
/// broadcast address (RFC 919, RFC 922; /31 and /32 have neither).
fn usable(lease: &Lease) -> bool {
    let host_bits = u32::MAX
        .checked_shr(u32::from(lease.prefix_len))
        .unwrap_or(0);
    let part = u32::from(lease.address) & host_bits;
    host(lease.address) && (lease.prefix_len > 30 || (part != 0 && part != host_bits))
}

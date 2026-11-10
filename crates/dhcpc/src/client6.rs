//! The DHCPv6 client of one interface, without I/O: a delegated prefix (IA_PD),
//! and an address (IA_NA) when asked for.
//!
//! Driven like [`crate::client4::Client`]: [`Client::receive`] with each DHCPv6
//! message that came to port 546, [`Client::timeout`] at [`Client::next_timer`].
//! Every message goes to ff02::1:2 port 547. [`Event::Bound`] carries the whole
//! lease each time it is taken or extended; [`Event::Lost`] says it may no longer
//! be used.
//!
//! # Standards
//!
//! - RFC 8415 section 18.2: Solicit, then Request to the server of the Advertise
//!   taken, Renew to it at T1, Rebind to any server at T2; the lease ends when the
//!   valid lifetimes of what it holds end. Section 18.2.1: the first Solicit goes
//!   after a random wait of up to 1 s (SOL_MAX_DELAY). Section 18.2.6: Release.
//! - RFC 8415 section 15: retransmission. RT starts at IRT randomized by -0.1 to
//!   +0.1 (only upward for the first Solicit), doubles with the same randomizing up
//!   to MRT. Solicit: IRT 1 s, MRT 3600 s. Request: IRT 1 s, MRT 30 s, MRC 10, after
//!   which the client solicits again. Renew and Rebind: IRT 10 s, MRT 600 s, until
//!   T2 and the end of the lease. Section 21.24: a SOL_MAX_RT option of 60 to
//!   86400 s in an Advertise or Reply becomes Solicit's MRT.
//! - RFC 8415 section 14.2 and 21.4: T1 and T2 of 0 from the server leave them to
//!   the client: 0.5 and 0.8 of the shortest preferred lifetime.
//! - RFC 8415 section 18.2.10: a Reply's IA with status NoBinding to a Renew or
//!   Rebind is asked for again with a Request; an IA without what the client wants
//!   ends the lease.
//!
//! Deviations: the first acceptable Advertise is taken without waiting for others
//! (section 18.2.1 waits the first RT for more unless the preference is 255); it
//! must hold a prefix, and an address only when one is asked for and given. A
//! Release is sent once, not retransmitted, as the client is stopping. No Confirm
//! or Information-request, no Reconfigure, no Rapid Commit. The lease ends with the
//! shortest valid lifetime of what it holds. T1 is at least 10 s and T2 at least
//! T1; T1 above T2 from the server is replaced by the client's own (section 21.4
//! drops such an IA). A failed Request goes back to Solicit, after a wait that
//! doubles with each failure in a row (1 s to an hour), also on a top-level error
//! status (section 18.2.10 sends the Request again for some).

use std::net::Ipv6Addr;

use crate::dhcp6::{self, kind, status, IaAddress, IaPrefix, Reply, Request};
use crate::Rng;

/// The most Requests before soliciting again (REQ_MAX_RC).
pub const REQUEST_TRIES: u32 = 10;
/// Infinite lifetime.
const INFINITE: u32 = u32::MAX;
/// The shortest T1, in seconds.
const LEAST_T1: u32 = 10;

/// What the client asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Want {
    pub address: bool,
    pub prefix: bool,
}

/// What the client holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: Option<IaAddress>,
    /// The delegated prefix, with no bits set after its length.
    pub prefix: Option<IaPrefix>,
    pub dns: Vec<Ipv6Addr>,
    pub server_id: Vec<u8>,
    /// Seconds after the lease was taken.
    pub t1: u32,
    pub t2: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Init,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Bound(Lease),
    Lost,
}

#[derive(Debug, Default)]
pub struct Output {
    /// Payloads to send to ff02::1:2 port 547.
    pub sends: Vec<Vec<u8>>,
    pub events: Vec<Event>,
}

#[derive(Debug)]
pub struct Client {
    duid: Vec<u8>,
    want: Want,
    rng: Rng,
    state: State,
    xid: u32,
    started_at: u64,
    /// The Advertise taken, in REQUESTING.
    offer: Option<Lease>,
    lease: Option<Lease>,
    bound_at: u64,
    timer: Option<u64>,
    tries: u32,
    /// The retransmission timeout now, in ms.
    rt: u64,
    /// Exchanges that failed in a row, for the wait before soliciting again.
    failures: u32,
    /// The MRT of Solicit in ms: SOL_MAX_RT, or what a server's SOL_MAX_RT option
    /// gave.
    sol_max_rt: u64,
}

/// Retransmission parameters: IRT and MRT, in ms.
const SOLICIT: (u64, u64) = (1_000, 3_600_000);
const REQUEST: (u64, u64) = (1_000, 30_000);
const RENEW: (u64, u64) = (10_000, 600_000);

impl Client {
    /// A client that sends its first Solicit within 1 s of `now`.
    pub fn new(mac: [u8; 6], want: Want, seed: u64, now: u64) -> Self {
        let mut rng = Rng::new(seed);
        let first = now + rng.below(1_001);
        Self {
            duid: dhcp6::duid(mac),
            want,
            rng,
            state: State::Init,
            xid: 0,
            started_at: now,
            offer: None,
            lease: None,
            bound_at: 0,
            timer: Some(first),
            tries: 0,
            rt: 0,
            failures: 0,
            sol_max_rt: SOLICIT.1,
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

    /// `rt` randomized by -0.1 to +0.1 of it (above 0 to +0.1 when `up`: section
    /// 15 wants RAND strictly greater than 0 for the first Solicit).
    fn randomize(&mut self, rt: u64, up: bool) -> u64 {
        let tenth = rt / 10;
        let low = if up { rt + 1 } else { rt - tenth };
        low + self.rng.below(rt + tenth - low + 1)
    }

    fn begin(&mut self, now: u64, (irt, _): (u64, u64), up: bool) {
        self.xid = (self.rng.next_u64() & 0x00ff_ffff) as u32;
        self.started_at = now;
        self.tries = 0;
        self.rt = self.randomize(irt, up);
    }

    /// Sends the message of the state now, and sets the next retransmission no
    /// later than `until`.
    fn send(&mut self, now: u64, (_, mrt): (u64, u64), until: Option<u64>, out: &mut Output) {
        let elapsed = (now.saturating_sub(self.started_at) / 10).min(0xffff) as u16;
        let (message, held) = match self.state {
            State::Soliciting => (kind::SOLICIT, None),
            State::Requesting => (kind::REQUEST, self.offer.as_ref()),
            State::Renewing => (kind::RENEW, self.lease.as_ref()),
            _ => (kind::REBIND, self.lease.as_ref()),
        };
        let server_id = match message {
            kind::REQUEST | kind::RENEW => held.map(|l| l.server_id.as_slice()),
            _ => None,
        };
        let payload = Request {
            kind: message,
            xid: self.xid,
            elapsed,
            client_id: &self.duid,
            server_id,
            ia_na: self.want.address.then(|| held.and_then(|l| l.address)),
            ia_pd: self.want.prefix.then(|| held.and_then(|l| l.prefix)),
        }
        .encode();
        out.sends.push(payload);
        self.tries += 1;
        let next = now + self.rt;
        self.timer = Some(until.map_or(next, |u| next.min(u)));
        // RT = 2 RTprev + RAND RTprev; past MRT, RT = MRT + RAND MRT.
        let tenth = self.rt / 10;
        let doubled = self.rt * 2 - tenth + self.rng.below(2 * tenth + 1);
        self.rt = if doubled > mrt {
            self.randomize(mrt, false)
        } else {
            doubled
        };
    }

    /// When the lease reaches `seconds` after it was taken; `None` for never.
    fn at(&self, seconds: u32) -> Option<u64> {
        (seconds != INFINITE).then(|| self.bound_at + u64::from(seconds) * 1_000)
    }

    /// When the lease ends: the shortest valid lifetime of what it holds.
    fn end(&self) -> Option<u64> {
        let lease = self.lease.as_ref()?;
        let valid = [
            lease.address.map(|a| a.valid),
            lease.prefix.map(|p| p.valid),
        ];
        self.at(valid.into_iter().flatten().min()?)
    }

    /// Back to soliciting, giving up the lease if one is held, after a wait that
    /// doubles with each failure in a row from 1 s up to an hour (section 14.1:
    /// a server that keeps failing the client gets no flood).
    fn solicit_again(&mut self, now: u64, out: &mut Output) {
        if self.lease.take().is_some() {
            out.events.push(Event::Lost);
        }
        self.offer = None;
        self.state = State::Init;
        let wait = SOLICIT.0 << self.failures.min(12);
        self.failures += 1;
        self.timer = Some(now + self.randomize(wait.min(SOLICIT.1), false));
    }

    fn lose(&mut self, now: u64, out: &mut Output) {
        self.solicit_again(now, out);
    }

    pub fn timeout(&mut self, now: u64, out: &mut Output) {
        if self.timer.is_none_or(|at| at > now) {
            return;
        }
        self.timer = None;
        match self.state {
            State::Init => {
                self.state = State::Soliciting;
                self.begin(now, SOLICIT, true);
                self.send(now, (SOLICIT.0, self.sol_max_rt), None, out);
            }
            State::Soliciting => self.send(now, (SOLICIT.0, self.sol_max_rt), None, out),
            State::Requesting if self.tries >= REQUEST_TRIES => self.solicit_again(now, out),
            // After NoBinding the lease held still ends on time.
            State::Requesting if self.end().is_some_and(|end| now >= end) => self.lose(now, out),
            State::Requesting => {
                let end = self.end();
                self.send(now, REQUEST, end, out)
            }
            State::Bound | State::Renewing | State::Rebinding => {
                let lease = self.lease.as_ref().expect("a lease");
                let t2 = self.at(lease.t2);
                let end = self.end();
                if end.is_some_and(|end| now >= end) {
                    return self.lose(now, out);
                }
                if t2.is_some_and(|t2| now >= t2) {
                    if self.state != State::Rebinding {
                        self.state = State::Rebinding;
                        self.begin(now, RENEW, false);
                    }
                    return self.send(now, RENEW, end, out);
                }
                if self.state == State::Bound {
                    self.state = State::Renewing;
                    self.begin(now, RENEW, false);
                }
                let until = [t2, end].into_iter().flatten().min();
                self.send(now, RENEW, until, out);
            }
            State::Stopped => {}
        }
    }

    /// The lease an Advertise or Reply gives, if it holds what the client wants.
    fn lease_of(&self, reply: &Reply) -> Option<Lease> {
        let server_id = reply.server_id.clone()?;
        let address = reply
            .ia_na
            .as_ref()
            .filter(|ia| ia.status == status::SUCCESS)
            .and_then(|ia| ia.lease)
            .filter(|a| a.valid > 0 && a.preferred <= a.valid);
        let prefix = reply
            .ia_pd
            .as_ref()
            .filter(|ia| ia.status == status::SUCCESS)
            .and_then(|ia| ia.lease)
            .filter(|p| p.valid > 0 && p.preferred <= p.valid && (1..=128).contains(&p.len))
            .map(|p| IaPrefix {
                prefix: network(p.prefix, p.len),
                ..p
            });
        // The prefix is what the client is for; an address only when it asks for
        // nothing else.
        let wanted = if self.want.prefix {
            prefix.is_some()
        } else {
            address.is_some()
        };
        if !wanted {
            return None;
        }
        let shortest = [address.map(|a| a.preferred), prefix.map(|p| p.preferred)]
            .into_iter()
            .flatten()
            .min()?;
        // The IAs' own T1 and T2, the smallest that are set.
        let times: Vec<(u32, u32)> = [
            reply
                .ia_na
                .as_ref()
                .filter(|_| address.is_some())
                .map(|ia| (ia.t1, ia.t2)),
            reply
                .ia_pd
                .as_ref()
                .filter(|_| prefix.is_some())
                .map(|ia| (ia.t1, ia.t2)),
        ]
        .into_iter()
        .flatten()
        .collect();
        let given = |pick: fn(&(u32, u32)) -> u32| times.iter().map(pick).filter(|t| *t > 0).min();
        let (mut t1, mut t2) = (given(|t| t.0), given(|t| t.1));
        if t1.is_none_or(|t1| t2.is_none_or(|t2| t1 > t2)) {
            if shortest == INFINITE {
                (t1, t2) = (Some(INFINITE), Some(INFINITE));
            } else {
                (t1, t2) = (
                    Some(shortest / 2),
                    Some((u64::from(shortest) * 4 / 5) as u32),
                );
            }
        }
        // At least LEAST_T1 s, so that a lifetime of 0 or 1 s does not make the
        // client renew without pause.
        let t1 = t1.unwrap_or(INFINITE).max(LEAST_T1);
        let t2 = t2.unwrap_or(INFINITE).max(t1);
        Some(Lease {
            address,
            prefix,
            dns: reply.dns.clone(),
            server_id,
            t1,
            t2,
        })
    }

    /// Takes a DHCPv6 message that came to port 546.
    pub fn receive(&mut self, now: u64, payload: &[u8], out: &mut Output) {
        let Some(reply) = Reply::parse(payload) else {
            return;
        };
        if reply.xid != self.xid || reply.client_id.as_deref() != Some(self.duid.as_slice()) {
            return;
        }
        // Sections 18.2.9 and 18.2.10: taken even from a message that is then
        // dropped for its status.
        if let Some(seconds) = reply.sol_max_rt {
            self.sol_max_rt = u64::from(seconds) * 1_000;
        }
        match (self.state, reply.kind) {
            (State::Soliciting, kind::ADVERTISE) => {
                if reply.status != status::SUCCESS {
                    return;
                }
                let Some(offer) = self.lease_of(&reply) else {
                    return;
                };
                self.offer = Some(offer);
                self.state = State::Requesting;
                self.begin(now, REQUEST, false);
                self.send(now, REQUEST, None, out);
            }
            (State::Requesting, kind::REPLY) => {
                let server = self.offer.as_ref().map(|o| o.server_id.clone());
                if reply.server_id != server {
                    return;
                }
                match self.lease_of(&reply) {
                    Some(lease) if reply.status == status::SUCCESS => self.bind(now, lease, out),
                    _ => self.solicit_again(now, out),
                }
            }
            (State::Renewing | State::Rebinding, kind::REPLY) => {
                if reply.status != status::SUCCESS {
                    return;
                }
                let no_binding = [
                    reply.ia_na.as_ref().map(|ia| ia.status),
                    reply.ia_pd.as_ref().map(|ia| ia.status),
                ]
                .contains(&Some(status::NO_BINDING));
                // A reply without the IA asked for is no answer about it
                // (section 18.2.10.1): keep the lease and keep asking.
                let missing = if self.want.prefix {
                    reply.ia_pd.is_none()
                } else {
                    reply.ia_na.is_none()
                };
                match self.lease_of(&reply) {
                    Some(lease) => self.bind(now, lease, out),
                    None if missing => {}
                    None if no_binding => {
                        let held = self.lease.clone().expect("a lease");
                        self.offer = Some(Lease {
                            server_id: reply.server_id.clone().unwrap_or(held.server_id.clone()),
                            ..held
                        });
                        self.state = State::Requesting;
                        self.begin(now, REQUEST, false);
                        self.send(now, REQUEST, None, out);
                    }
                    // What the client wants is gone (lifetimes 0, or not given).
                    None => self.lose(now, out),
                }
            }
            _ => {}
        }
    }

    fn bind(&mut self, now: u64, lease: Lease, out: &mut Output) {
        self.failures = 0;
        self.state = State::Bound;
        self.offer = None;
        self.bound_at = now;
        out.events.push(Event::Bound(lease.clone()));
        let t1 = lease.t1;
        self.lease = Some(lease);
        // T1, or the end of the lease if that comes first.
        self.timer = [self.at(t1), self.end()].into_iter().flatten().min();
    }

    /// Gives the lease back (Release, sent once) and stops.
    pub fn release(&mut self, now: u64, out: &mut Output) {
        if let Some(lease) = self.lease.take() {
            self.xid = (self.rng.next_u64() & 0x00ff_ffff) as u32;
            self.started_at = now;
            out.sends.push(
                Request {
                    kind: kind::RELEASE,
                    xid: self.xid,
                    elapsed: 0,
                    client_id: &self.duid,
                    server_id: Some(&lease.server_id),
                    ia_na: lease.address.map(Some),
                    ia_pd: lease.prefix.map(Some),
                }
                .encode(),
            );
            out.events.push(Event::Lost);
        }
        self.offer = None;
        self.state = State::Stopped;
        self.timer = None;
    }
}

/// `address` with the bits after `len` cleared.
fn network(address: Ipv6Addr, len: u8) -> Ipv6Addr {
    let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
    Ipv6Addr::from(u128::from(address) & mask)
}

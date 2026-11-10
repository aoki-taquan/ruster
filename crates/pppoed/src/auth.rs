//! Authenticating ourselves to the peer with PAP or CHAP (MD5), whichever the peer
//! asked for in LCP.
//!
//! With PAP the host sends its name and password and sends them again until the
//! peer answers. With CHAP it answers each Challenge with the MD5 hash of the
//! identifier, the password and the challenge. The peer's Ack or Success ends the
//! phase well, its Nak or Failure badly. A CHAP peer may challenge again later; a
//! Failure then also ends the link.
//!
//! # Standards
//!
//! - RFC 1334 section 2.2: the PAP Authenticate-Request (Peer-ID and Password, each
//!   with a one-octet length) is sent again after the restart timer, with a new
//!   identifier each time, until an Authenticate-Ack or -Nak with that identifier
//!   comes; Msg-Length must fit the packet.
//! - RFC 1994 section 4.1: a Response carries the Challenge's identifier and
//!   MD5(identifier, secret, challenge value), with our name. Section 4.2: Success
//!   and Failure count only with the identifier of our last Response. A Challenge
//!   with a value size of 0 or past the packet is invalid.
//!
//! Deviations: a PAP Ack or Nak without Msg-Length is taken (as pppd does). The
//! number of PAP tries is the RFC 1661 Max-Configure (10), as
//! RFC 1334 leaves it to the implementation. The authentication phase also ends
//! badly when it does not end in time ([`crate::session::AUTH_TIMEOUT_MS`]).

use md5::{Digest, Md5};

use crate::lcp::Auth;
use crate::ppp::{self, protocol};

/// PAP codes.
pub mod pap {
    pub const REQUEST: u8 = 1;
    pub const ACK: u8 = 2;
    pub const NAK: u8 = 3;
}

/// CHAP codes.
pub mod chap {
    pub const CHALLENGE: u8 = 1;
    pub const RESPONSE: u8 = 2;
    pub const SUCCESS: u8 = 3;
    pub const FAILURE: u8 = 4;
}

/// How long to wait for a PAP answer before sending again.
pub const PAP_RESTART_MS: u64 = 3_000;
/// How many PAP requests are sent.
pub const PAP_TRIES: u32 = 10;

/// The end of the authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
}

/// The authentication of one session. Its `Debug` does not show the password.
#[derive(Clone)]
pub struct Client {
    method: Auth,
    user: Vec<u8>,
    password: Vec<u8>,
    /// The identifier of our last PAP request or CHAP response.
    id: Option<u8>,
    next_id: u8,
    tries: u32,
    timer: Option<u64>,
    succeeded: bool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every field by name, so that a new one is not missed.
        let Self {
            method,
            user,
            password: _,
            id,
            next_id,
            tries,
            timer,
            succeeded,
        } = self;
        f.debug_struct("Client")
            .field("method", method)
            .field("user", user)
            .field("password", &ruster_config::HIDDEN)
            .field("id", id)
            .field("next_id", next_id)
            .field("tries", tries)
            .field("timer", timer)
            .field("succeeded", succeeded)
            .finish()
    }
}

impl Client {
    /// `user` and `password` must be at most 255 octets.
    pub fn new(method: Auth, user: &[u8], password: &[u8]) -> Self {
        Self {
            method,
            user: user.to_vec(),
            password: password.to_vec(),
            id: None,
            next_id: 1,
            tries: 0,
            timer: None,
            succeeded: false,
        }
    }

    /// The PPP protocol this client speaks.
    pub fn protocol(&self) -> u16 {
        match self.method {
            Auth::Pap => protocol::PAP,
            Auth::ChapMd5 => protocol::CHAP,
        }
    }

    pub fn next_timer(&self) -> Option<u64> {
        self.timer
    }

    /// Begins: PAP sends its request; CHAP waits for the Challenge.
    pub fn start(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        if self.method == Auth::Pap {
            self.tries = 0;
            self.send_pap(now, out);
        }
    }

    /// Sends the PAP request again when it is due; fails after [`PAP_TRIES`].
    pub fn timeout(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Option<Outcome> {
        if self.timer.is_none_or(|at| now < at) {
            return None;
        }
        if self.tries >= PAP_TRIES {
            self.timer = None;
            return Some(Outcome::Failure);
        }
        self.send_pap(now, out);
        None
    }

    /// A received packet of [`Client::protocol`] (the whole information field).
    pub fn receive(&mut self, information: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Outcome> {
        let packet = ppp::Packet::parse(information)?;
        match (self.method, packet.code) {
            (Auth::Pap, pap::ACK | pap::NAK) if Some(packet.id) == self.id => {
                // Some peers leave out Msg-Length; that is a message of 0.
                let length = packet.data.first().map_or(0, |&l| usize::from(l));
                if (!packet.data.is_empty() && packet.data.len() < 1 + length) || self.succeeded {
                    return None;
                }
                self.timer = None;
                self.id = None;
                if packet.code == pap::ACK {
                    self.succeeded = true;
                    Some(Outcome::Success)
                } else {
                    Some(Outcome::Failure)
                }
            }
            (Auth::ChapMd5, chap::CHALLENGE) => {
                let size = usize::from(*packet.data.first()?);
                let value = packet.data.get(1..1 + size).filter(|v| !v.is_empty())?;
                let mut hash = Md5::new();
                hash.update([packet.id]);
                hash.update(&self.password);
                hash.update(value);
                let mut data = vec![16];
                data.extend_from_slice(&hash.finalize());
                data.extend_from_slice(&self.user);
                out.push(ppp::packet(chap::RESPONSE, packet.id, &data));
                self.id = Some(packet.id);
                None
            }
            (Auth::ChapMd5, chap::SUCCESS) if Some(packet.id) == self.id => {
                self.id = None;
                (!std::mem::replace(&mut self.succeeded, true)).then_some(Outcome::Success)
            }
            (Auth::ChapMd5, chap::FAILURE) if Some(packet.id) == self.id => {
                self.id = None;
                self.succeeded = false;
                Some(Outcome::Failure)
            }
            _ => None,
        }
    }

    fn send_pap(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut data = Vec::with_capacity(2 + self.user.len() + self.password.len());
        data.push(u8::try_from(self.user.len()).unwrap_or(u8::MAX));
        data.extend_from_slice(&self.user);
        data.push(u8::try_from(self.password.len()).unwrap_or(u8::MAX));
        data.extend_from_slice(&self.password);
        out.push(ppp::packet(pap::REQUEST, id, &data));
        self.id = Some(id);
        self.tries += 1;
        self.timer = Some(now + PAP_RESTART_MS);
    }
}

//! The IPv6CP options: agree on the interface identifiers of both ends, from which
//! each side forms its link-local address.
//!
//! The host asks for a random identifier. It takes the peer's when it is neither
//! 0 nor ours, and otherwise suggests another one.
//!
//! # Standards
//!
//! - RFC 5072 section 4.1: Interface-Identifier. A received identifier is compared
//!   with the one we last asked for: different and not 0 is acknowledged; 0 (and
//!   ours not 0) or equal to ours is Nak'd with a different identifier that is not
//!   0; both 0 is rejected. A Nak of ours gives the identifier to use, unless it
//!   is 0 or the peer's. Section 4.1 also allows a random identifier when there is
//!   no stable one; its "u" bit is 0, in ours and in those we suggest.
//! - RFC 1661 section 5.4: other options are rejected.
//!
//! Deviations: IPv6-Compression-Protocol (RFC 5072 section 4.2) is rejected and
//! never asked for. The identifiers are negotiated and reported, but no link-local
//! address is formed from them (RFC 5072 section 5): IPv6 over the session is not
//! used yet, so the session interface carries no IPv6 address.

use crate::fsm::{Negotiation, Reply};
use crate::ppp::{push_option, Opt};
use crate::Rng;

/// The IPv6CP option types.
pub mod option {
    pub const INTERFACE_IDENTIFIER: u8 = 1;
}

const ZERO: [u8; 8] = [0; 8];

/// The IPv6CP options of both sides.
#[derive(Clone, Debug)]
pub struct Ipv6cpOptions {
    rng: Rng,
    /// The identifier we ask for.
    pub local: [u8; 8],
    ask: bool,
    /// The peer's identifier, once acknowledged.
    pub peer: Option<[u8; 8]>,
}

impl Ipv6cpOptions {
    pub fn new(mut rng: Rng) -> Self {
        let local = Self::random(&mut rng, ZERO);
        Self {
            rng,
            local,
            ask: true,
            peer: None,
        }
    }

    /// Our identifier, if the peer did not reject the option.
    pub fn local(&self) -> Option<[u8; 8]> {
        self.ask.then_some(self.local)
    }

    /// An identifier that is neither 0 nor `not`.
    fn random(rng: &mut Rng, not: [u8; 8]) -> [u8; 8] {
        loop {
            let mut id = rng.next_u64().to_be_bytes();
            // A random identifier has the "u" bit 0 (RFC 5072 section 4.1).
            id[0] &= !0x02;
            if id != ZERO && id != not {
                return id;
            }
        }
    }
}

impl Negotiation for Ipv6cpOptions {
    fn request(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.ask {
            push_option(&mut out, option::INTERFACE_IDENTIFIER, &self.local);
        }
        out
    }

    fn check(&mut self, options: &[Opt<'_>], nak: bool) -> Reply {
        let mut naks = Vec::new();
        let mut rejects = Vec::new();
        let mut peer = None;
        let ours = if self.ask { self.local } else { ZERO };
        for &(kind, value) in options {
            let id = <[u8; 8]>::try_from(value).ok();
            match (kind, id) {
                (option::INTERFACE_IDENTIFIER, Some(id)) if id != ZERO && id != ours => {
                    peer = Some(id);
                }
                (option::INTERFACE_IDENTIFIER, Some(id)) if id != ZERO || ours != ZERO => {
                    if nak {
                        let suggestion = Self::random(&mut self.rng, ours);
                        push_option(&mut naks, kind, &suggestion);
                    } else {
                        push_option(&mut rejects, kind, value);
                    }
                }
                _ => push_option(&mut rejects, kind, value),
            }
        }
        if !rejects.is_empty() {
            Reply::Reject(rejects)
        } else if !naks.is_empty() {
            Reply::Nak(naks)
        } else {
            self.peer = peer;
            Reply::Ack
        }
    }

    fn naked(&mut self, options: &[Opt<'_>]) {
        for &(kind, value) in options {
            if kind != option::INTERFACE_IDENTIFIER {
                continue;
            }
            let peer = self.peer.unwrap_or(ZERO);
            self.local = match <[u8; 8]>::try_from(value) {
                Ok(id) if id != ZERO && id != peer => id,
                _ => Self::random(&mut self.rng, peer),
            };
        }
    }

    fn rejected(&mut self, options: &[Opt<'_>]) {
        if options
            .iter()
            .any(|&(k, _)| k == option::INTERFACE_IDENTIFIER)
        {
            self.ask = false;
        }
    }
}

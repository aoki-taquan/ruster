//! The IPCP options for the host: get our IPv4 address and the DNS servers from
//! the peer.
//!
//! The host asks for address 0.0.0.0 and DNS servers 0.0.0.0; the peer Naks with
//! the values to use, and the host asks again with them. Of the peer's options it
//! takes only IP-Address (the peer's own address, if not 0).
//!
//! # Standards
//!
//! - RFC 1332 section 3.3: IP-Address; 0.0.0.0 asks the peer to give one.
//! - RFC 1877 section 1.1 and 1.3: Primary-DNS-Server-Address (129) and
//!   Secondary-DNS-Server-Address (131), asked for the same way; one the peer
//!   rejects is not asked for again.
//! - RFC 1661 section 5.4: options the host does not take are rejected.
//!
//! Deviations: IP-Compression-Protocol (Van Jacobson) and the old IP-Addresses
//! option are rejected and never asked for. A peer that asks for 0.0.0.0 is
//! rejected, since the host has no address to give it. NBNS servers (RFC 1877) are
//! not asked for.

use std::net::Ipv4Addr;

use crate::fsm::{Negotiation, Reply};
use crate::ppp::{push_option, Opt};

/// The IPCP option types.
pub mod option {
    pub const IP_ADDRESS: u8 = 3;
    pub const PRIMARY_DNS: u8 = 129;
    pub const SECONDARY_DNS: u8 = 131;
}

const ASKED: [u8; 3] = [
    option::IP_ADDRESS,
    option::PRIMARY_DNS,
    option::SECONDARY_DNS,
];

/// The IPCP options of both sides.
#[derive(Clone, Debug)]
pub struct IpcpOptions {
    /// Our address, then the primary and secondary DNS servers: the values asked
    /// for (0.0.0.0 until the peer gives them).
    pub values: [Ipv4Addr; 3],
    /// Whether each is still asked for.
    ask: [bool; 3],
    /// The peer's address, if it gave one.
    pub peer: Option<Ipv4Addr>,
}

impl Default for IpcpOptions {
    fn default() -> Self {
        Self {
            values: [Ipv4Addr::UNSPECIFIED; 3],
            ask: [true; 3],
            peer: None,
        }
    }
}

impl IpcpOptions {
    /// Our address, once the peer gave one.
    pub fn address(&self) -> Option<Ipv4Addr> {
        Some(self.values[0]).filter(|a| self.ask[0] && !a.is_unspecified())
    }

    /// The DNS servers the peer gave.
    pub fn dns(&self) -> Vec<Ipv4Addr> {
        (1..3)
            .filter(|&i| self.ask[i] && !self.values[i].is_unspecified())
            .map(|i| self.values[i])
            .collect()
    }
}

fn address(value: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(value).ok().map(Ipv4Addr::from)
}

impl Negotiation for IpcpOptions {
    fn request(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, kind) in ASKED.into_iter().enumerate() {
            if self.ask[i] {
                push_option(&mut out, kind, &self.values[i].octets());
            }
        }
        out
    }

    fn check(&mut self, options: &[Opt<'_>], _nak: bool) -> Reply {
        let mut rejects = Vec::new();
        let mut peer = None;
        for &(kind, value) in options {
            match (kind, address(value)) {
                (option::IP_ADDRESS, Some(a)) if !a.is_unspecified() => peer = Some(a),
                _ => push_option(&mut rejects, kind, value),
            }
        }
        if rejects.is_empty() {
            self.peer = peer;
            Reply::Ack
        } else {
            Reply::Reject(rejects)
        }
    }

    fn naked(&mut self, options: &[Opt<'_>]) {
        for &(kind, value) in options {
            if let (Some(i), Some(a)) = (ASKED.iter().position(|&k| k == kind), address(value)) {
                if self.ask[i] {
                    self.values[i] = a;
                }
            }
        }
    }

    fn rejected(&mut self, options: &[Opt<'_>]) {
        for &(kind, _) in options {
            if let Some(i) = ASKED.iter().position(|&k| k == kind) {
                self.ask[i] = false;
            }
        }
    }
}

#![forbid(unsafe_code)]
//! The PPPoE client (`ruster-pppoed`): the host side of PPPoE sessions
//! (`docs/design/router-box.md`, "自作の制御").
//!
//! The protocol code does no I/O. Each part takes a received frame and the time in
//! milliseconds, and gives back the frames to send and what happened; timers are
//! deadlines the caller asks for and passes back when they are due. The daemon
//! moves frames between these parts and the FE's punt socket.
//!
//! - [`discovery`]: PPPoE Discovery (RFC 2516 section 5).
//! - [`ppp`]: session frames and control packets.
//! - [`fsm`]: the option negotiation automaton (RFC 1661 section 4).
//! - [`lcp`]: LCP options, echo keepalive (RFC 1661, RFC 2516 section 7).
//! - [`auth`]: PAP (RFC 1334) and CHAP with MD5 (RFC 1994).
//! - [`ipcp`]: IPv4 address and DNS servers (RFC 1332, RFC 1877).
//! - [`ipv6cp`]: IPv6 interface identifiers (RFC 5072).
//!
//! # Standards
//!
//! Each module lists the sections it follows and where it deviates.

pub mod auth;
pub mod discovery;
pub mod fsm;
pub mod ipcp;
pub mod ipv6cp;
pub mod lcp;
pub mod ppp;

/// An Ethernet MAC address.
pub type Mac = [u8; 6];

/// A small pseudo-random generator (SplitMix64) for Host-Uniq values, magic
/// numbers and interface identifiers. These must differ between sessions and
/// restarts, not be secret: the daemon seeds it from the system's random source.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value that is not zero.
    pub fn non_zero_u32(&mut self) -> u32 {
        loop {
            let value = self.next_u64() as u32;
            if value != 0 {
                return value;
            }
        }
    }
}

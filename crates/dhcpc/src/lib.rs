#![forbid(unsafe_code)]
//! The WAN side's DHCP client (`docs/design/router-box.md`, "自作の制御").
//!
//! The protocol is here without I/O: DHCPv4 messages ([`dhcp4`]) and the client
//! of one interface ([`client4`]), DHCPv6 messages ([`dhcp6`]) and the client of
//! one interface with prefix delegation ([`client6`]).

pub mod client4;
pub mod client6;
pub mod dhcp4;
pub mod dhcp6;

/// A small pseudo-random generator (xorshift64*) for transaction IDs and the
/// randomized waits. They must differ between clients and restarts, not be secret:
/// the daemon seeds it from the system's random source.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Zero would stay zero.
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `0..bound`; 0 when `bound` is 0.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

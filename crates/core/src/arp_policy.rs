//! The ARP policy a forwarding snapshot carries: RFC 5227 announcement timing and
//! per-interface overrides. Announcements themselves are no longer sent by core
//! (neighd owns ARP); the policy stays part of the snapshot's configuration.

use std::num::NonZeroU8;

use crate::IfId;

/// RFC 5227 §1.1 ANNOUNCE_NUM: Announcements per sequence.
pub const ARP_ANNOUNCE_NUM: u8 = 2;
/// RFC 5227 §1.1 ANNOUNCE_INTERVAL: time between Announcements.
pub const ARP_ANNOUNCE_INTERVAL_MS: u64 = 2_000;
/// RFC 5227 §1.1 DEFEND_INTERVAL: minimum interval between defensive
/// Announcements of one address.
pub const ARP_DEFEND_INTERVAL_MS: u64 = 10_000;
/// Default minimum interval between two announcement sequences on one
/// interface (local flap bound, ARP-035). It reuses DEFEND_INTERVAL, the
/// RFC's own floor for repeated broadcasts about one address.
pub const ARP_ANNOUNCE_DEFAULT_MIN_INTERVAL_MS: u64 = ARP_DEFEND_INTERVAL_MS;
/// Largest `count` [`ArpAnnouncePolicy::new`] accepts.
pub const ARP_ANNOUNCE_MAX_COUNT: u8 = 10;
/// Smallest `interval_ms` [`ArpAnnouncePolicy::new`] accepts.
pub const ARP_ANNOUNCE_MIN_INTERVAL_MS: u64 = 1_000;
/// Largest `interval_ms` and `min_interval_ms` [`ArpAnnouncePolicy::new`]
/// accepts (one hour).
pub const ARP_ANNOUNCE_MAX_INTERVAL_MS: u64 = 3_600_000;

/// Why [`ArpAnnouncePolicy::new`] refused its values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpAnnouncePolicyError {
    /// `count` is 0 or above [`ARP_ANNOUNCE_MAX_COUNT`].
    CountOutOfRange,
    /// `interval_ms` is below [`ARP_ANNOUNCE_MIN_INTERVAL_MS`] or above
    /// [`ARP_ANNOUNCE_MAX_INTERVAL_MS`].
    IntervalOutOfRange,
    /// `min_interval_ms` is above [`ARP_ANNOUNCE_MAX_INTERVAL_MS`] or
    /// shorter than one whole sequence (`interval_ms * (count - 1)`, and
    /// at least [`ARP_ANNOUNCE_MIN_INTERVAL_MS`]).
    MinIntervalOutOfRange,
}

/// How the router announces its own addresses (RFC 5227 §2.3).
///
/// 12 bytes (an `Option` of it too): it rides in the by-value forwarding
/// snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpAnnouncePolicy {
    count: NonZeroU8,
    interval_ms: u32,
    min_interval_ms: u32,
}

impl ArpAnnouncePolicy {
    /// RFC 5227 §1.1 values: ANNOUNCE_NUM 2, ANNOUNCE_INTERVAL 2 s, and
    /// the local minimum interval [`ARP_ANNOUNCE_DEFAULT_MIN_INTERVAL_MS`].
    pub const RFC5227: Self = Self {
        count: NonZeroU8::new(ARP_ANNOUNCE_NUM).expect("ANNOUNCE_NUM is nonzero"),
        interval_ms: ARP_ANNOUNCE_INTERVAL_MS as u32,
        min_interval_ms: ARP_ANNOUNCE_DEFAULT_MIN_INTERVAL_MS as u32,
    };

    /// A policy of `count` Announcements `interval_ms` apart, with
    /// sequences on one interface starting at least `min_interval_ms`
    /// apart.
    pub const fn new(
        count: u8,
        interval_ms: u64,
        min_interval_ms: u64,
    ) -> Result<Self, ArpAnnouncePolicyError> {
        let Some(nonzero) = NonZeroU8::new(count) else {
            return Err(ArpAnnouncePolicyError::CountOutOfRange);
        };
        if count > ARP_ANNOUNCE_MAX_COUNT {
            return Err(ArpAnnouncePolicyError::CountOutOfRange);
        }
        if interval_ms < ARP_ANNOUNCE_MIN_INTERVAL_MS || interval_ms > ARP_ANNOUNCE_MAX_INTERVAL_MS
        {
            return Err(ArpAnnouncePolicyError::IntervalOutOfRange);
        }
        let sequence = interval_ms * (count as u64 - 1);
        if min_interval_ms > ARP_ANNOUNCE_MAX_INTERVAL_MS
            || min_interval_ms < sequence
            || min_interval_ms < ARP_ANNOUNCE_MIN_INTERVAL_MS
        {
            return Err(ArpAnnouncePolicyError::MinIntervalOutOfRange);
        }
        // Both are at most ARP_ANNOUNCE_MAX_INTERVAL_MS, which fits u32.
        Ok(Self {
            count: nonzero,
            interval_ms: interval_ms as u32,
            min_interval_ms: min_interval_ms as u32,
        })
    }

    pub(crate) const fn interval_ms_u32(self) -> u32 {
        self.interval_ms
    }

    pub(crate) const fn min_interval_ms_u32(self) -> u32 {
        self.min_interval_ms
    }

    /// The policy stored as parts by [`crate::ArpPolicy`] (`count` 0:
    /// none). The parts come from a validated policy.
    pub(crate) const fn from_parts(
        count: u8,
        interval_ms: u32,
        min_interval_ms: u32,
    ) -> Option<Self> {
        match NonZeroU8::new(count) {
            Some(count) => Some(Self {
                count,
                interval_ms,
                min_interval_ms,
            }),
            None => None,
        }
    }

    #[must_use]
    pub const fn count(self) -> u8 {
        self.count.get()
    }

    #[must_use]
    pub const fn interval_ms(self) -> u64 {
        self.interval_ms as u64
    }

    #[must_use]
    pub const fn min_interval_ms(self) -> u64 {
        self.min_interval_ms as u64
    }
}

/// Per-interface overrides of the router-wide `[arp] announce` and
/// `[arp] conflict-defense` switches (ARP-040, `[[interfaces]]
/// arp-announce` and `arp-conflict-defense`). `None` inherits the
/// router-wide switch. Conflict detection and counting stay on either way.
///
/// 4 bytes; the forwarding snapshot borrows a sorted slice of them
/// ([`ForwardingSnapshot::with_arp_interfaces`]), not the runtime slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpInterfacePolicy {
    pub interface: IfId,
    /// RFC 5227 §2.3 Announcements on this interface.
    pub announce: Option<bool>,
    /// The RFC 5227 §2.4 (c) defense on this interface. `Some(false)` is
    /// an operator-selected §2.4 deviation (ARP-038).
    pub conflict_defense: Option<bool>,
}

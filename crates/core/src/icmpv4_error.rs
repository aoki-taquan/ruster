//! ICMPv4 errors the router generates about the datagrams it forwards or refuses.
//!
//! # Standards
//!
//! - RFC 1812 section 4.3.2: Time Exceeded, Destination Unreachable (Network,
//!   Port, Protocol, Fragmentation Needed with the Next-Hop MTU of RFC 1191,
//!   Administratively Prohibited when enabled), Parameter Problem and Redirect;
//!   none about an ICMP error, a non-initial fragment, a broadcast or multicast,
//!   or a source that is not a host (section 4.3.2.7); the quote at most 576 bytes
//!   in all and cut to the egress MTU (section 4.3.2.3); precedence 6 (section
//!   4.3.2.5); a rate limit per kind and egress (section 4.3.2.8).
//!
//! Deviations: no Destination Unreachable (Host) for an unresolved neighbor (the
//! packet is dropped silently, RFC 1812 section 5.2.7.1 says SHOULD); no Source
//! Quench (RFC 6633 deprecates it).

use std::{marker::PhantomData, rc::Rc};

use crate::icmpv4_translated_limit::{
    TranslatedIcmpv4Limiter, ICMPV4_DEFAULT_TRANSLATED_BURST,
    ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND, ICMPV4_MAX_TRANSLATED_LIMIT,
};
use crate::{
    internet_checksum, ipv4_header_checksum, GeneratedAllocationError, GeneratedBatchCompletion,
    GeneratedPacketBatch, GeneratedPacketIo, HighWaterMark, IfId, Ipv4Address, MacAddress,
    MonotonicMillis, OccupancyCounter, TableOccupancy, IPV4_ETHERTYPE,
};

pub const ICMPV4_ERROR_MAX_QUOTE_LEN: usize = 548;
pub const ICMPV4_ERROR_MAX_FRAME_LEN: usize = 590;
pub const ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN: usize = ICMPV4_ERROR_MAX_QUOTE_LEN;
pub const ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN: usize = ICMPV4_ERROR_MAX_FRAME_LEN;
const ETHERNET_MIN_FRAME_LEN: usize = 60;
/// The limiter class of [`Icmpv4ErrorKind::RedirectHost`] (ICMP-REDIRECT).
const REDIRECT_LIMITER_CLASS: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4ErrorKind {
    TimeExceededTtl,
    DestinationUnreachableNetwork,
    DestinationUnreachableHost,
    /// Destination Unreachable, Port Unreachable (Type 3, Code 3): the
    /// delayed answer of the TCP NAT to an unsolicited inbound SYN
    /// (RFC 5382 REQ-4). Its on/off switch is the NAT's
    /// [`crate::Nat44TcpPolicy::with_unsolicited_syn_icmp`]. It shares the
    /// action queue with every other kind but has its own per-egress
    /// limiter class and interval
    /// ([`Icmpv4ErrorPolicy::with_port_unreachable_interval_ms`]), so a SYN
    /// flood cannot use up the limiter of the other kinds.
    DestinationUnreachablePort,
    /// Destination Unreachable, Fragmentation Needed and DF Set (Type 3,
    /// Code 4): a forwarded datagram with DF set is longer than the MTU of
    /// its egress interface (RFC 1812 §§4.2.2.7, 5.2.7.1; RFC 792). The
    /// action carries the egress MTU as the Next-Hop MTU in the low-order
    /// 16 bits of the second ICMP header word (RFC 1191 §4). It has its own
    /// per-egress limiter class and interval
    /// ([`Icmpv4ErrorPolicy::with_fragmentation_needed_interval_ms`]), so a
    /// flood of other errors (a TTL sweep) never starves Path MTU Discovery.
    DestinationUnreachableFragmentationNeeded,
    /// Destination Unreachable, Protocol Unreachable (Type 3, Code 2): a
    /// datagram addressed to the router carries an IP protocol the router
    /// does not implement (RFC 1812 §5.2.7.1, RFC 1122 §3.2.2.1). Shares
    /// limiter class 0.
    DestinationUnreachableProtocol,
    /// Destination Unreachable, Port Unreachable (Type 3, Code 3) about a
    /// UDP datagram addressed to the router: no UDP port is open on the
    /// router (RFC 1812 §5.2.7.1, RFC 1122 §§3.2.2.1, 4.1.3.1). Separate
    /// from [`Self::DestinationUnreachablePort`] (the TCP NAT's delayed
    /// answer), so each has its own switch and counters. Shares limiter
    /// class 0.
    DestinationUnreachableLocalPort,
    /// Parameter Problem, pointer indicates the error (Type 12, Code 0): a
    /// datagram whose IPv4 header the router cannot process (RFC 1812
    /// §§4.3.3.5, 5.2.2, 5.2.4.1). The action carries the pointer to the
    /// offending octet in the first octet of the second ICMP header word
    /// (RFC 792). Shares limiter class 0.
    ParameterProblem,
    /// Destination Unreachable, Communication Administratively Prohibited
    /// (Type 3, Code 13): the forward firewall denied the datagram (RFC
    /// 1812 §5.2.7.1). Off by default (RFC 1812 §5.2.7.1 allows the option
    /// that suppresses it; owner decision). Shares limiter class 0.
    DestinationUnreachableAdministrativelyProhibited,
    /// Redirect for Host (Type 5, Code 1): a forwarded datagram left
    /// through the interface it arrived on, and its source and the chosen
    /// next hop are on that interface's connected subnet, so the source has
    /// a better first hop (RFC 1812 §§4.3.3.2, 5.2.7.2; RFC 792). Routers
    /// MUST NOT send the Network Redirects (codes 0 and 2) and MUST be able
    /// to send this one. The action carries the gateway (the next hop) as
    /// the whole second ICMP header word. The datagram is still forwarded.
    /// Has its own limiter class 3 (interval `interval-ms`), so a host that
    /// ignores Redirects never starves the class 0 errors of its egress
    /// (ICMP4-033).
    RedirectHost,
}

impl Icmpv4ErrorKind {
    const fn icmp_type(self) -> u8 {
        match self {
            Self::TimeExceededTtl => 11,
            Self::ParameterProblem => 12,
            Self::RedirectHost => 5,
            Self::DestinationUnreachableNetwork
            | Self::DestinationUnreachableHost
            | Self::DestinationUnreachablePort
            | Self::DestinationUnreachableFragmentationNeeded
            | Self::DestinationUnreachableProtocol
            | Self::DestinationUnreachableLocalPort
            | Self::DestinationUnreachableAdministrativelyProhibited => 3,
        }
    }

    const fn icmp_code(self) -> u8 {
        match self {
            Self::DestinationUnreachableHost | Self::RedirectHost => 1,
            Self::DestinationUnreachableProtocol => 2,
            Self::DestinationUnreachablePort | Self::DestinationUnreachableLocalPort => 3,
            Self::DestinationUnreachableFragmentationNeeded => 4,
            Self::DestinationUnreachableAdministrativelyProhibited => 13,
            Self::TimeExceededTtl
            | Self::DestinationUnreachableNetwork
            | Self::ParameterProblem => 0,
        }
    }

    /// The limiter class: a limiter state is keyed by egress and class.
    /// Port Unreachable (1), Fragmentation Needed (2), and Redirect (3)
    /// have their own classes; every other kind shares class 0 (so the
    /// ICMP-ERR kinds add no limiter state and no `states` capacity
    /// requirement).
    pub(crate) const fn limiter_class(self) -> u8 {
        match self {
            Self::DestinationUnreachablePort => 1,
            Self::DestinationUnreachableFragmentationNeeded => 2,
            Self::RedirectHost => REDIRECT_LIMITER_CLASS,
            Self::TimeExceededTtl
            | Self::DestinationUnreachableNetwork
            | Self::DestinationUnreachableHost
            | Self::DestinationUnreachableProtocol
            | Self::DestinationUnreachableLocalPort
            | Self::ParameterProblem
            | Self::DestinationUnreachableAdministrativelyProhibited => 0,
        }
    }

    const fn generation_bit(self) -> u16 {
        match self {
            Self::TimeExceededTtl => 1,
            Self::DestinationUnreachableNetwork => 1 << 1,
            Self::DestinationUnreachableHost => 1 << 2,
            Self::DestinationUnreachablePort => 1 << 3,
            Self::DestinationUnreachableFragmentationNeeded => 1 << 4,
            Self::DestinationUnreachableProtocol => 1 << 5,
            Self::DestinationUnreachableLocalPort => 1 << 6,
            Self::ParameterProblem => 1 << 7,
            Self::DestinationUnreachableAdministrativelyProhibited => 1 << 8,
            Self::RedirectHost => 1 << 9,
        }
    }
}

/// Kinds a default policy does not generate: only Communication
/// Administratively Prohibited (RFC 1812 §5.2.7.1 allows an option that
/// suppresses it; a firewall deny stays a silent drop unless the operator
/// opts in).
const DEFAULT_DISABLED: u16 =
    Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited.generation_bit();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4ErrorPolicyError {
    IntervalZero,
    StateTtlTooShort,
    /// A translated error rate or burst is 0 or above
    /// [`crate::ICMPV4_MAX_TRANSLATED_LIMIT`].
    TranslatedLimitOutOfRange,
}

/// Rate-limit policy and per-kind generation switches for router-originated
/// ICMPv4 errors.
///
/// Every kind except Communication Administratively Prohibited is generated
/// by default, which is the RFC 1812 behavior (§5.3.1 Time Exceeded and
/// §5.2.7.1 Destination Unreachable are MUSTs; §5.2.7.1 explicitly allows
/// the option that suppresses Code 13, which is the default here).
/// RFC 1812 §1.1.3 allows an operator option that violates a MUST only when
/// its default conforms, so [`Self::with_generation`] can turn one kind off
/// for security reasons. A disabled kind is suppressed before the limiter,
/// the reverse route, and any reverse ARP, and is counted separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorPolicy {
    interval_ms: u64,
    port_unreachable_interval_ms: u64,
    fragmentation_needed_interval_ms: u64,
    state_ttl_ms: u64,
    disabled: u16,
    translated_rate_per_second: u32,
    translated_burst: u32,
}

/// Default minimum interval between two ICMP Port Unreachable errors on one
/// egress ([`Icmpv4ErrorPolicy::port_unreachable_interval_ms`]).
pub const ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS: u64 = 1_000;

/// Default minimum interval between two ICMP Fragmentation Needed errors on
/// one egress ([`Icmpv4ErrorPolicy::fragmentation_needed_interval_ms`]):
/// 10 ms, ten times shorter than the other errors' 100 ms. PMTUD depends on
/// every sender getting the error (Linux does not rate limit it at all by
/// default); the error is never larger than the datagram that triggered it
/// (at most 576 bytes against at least MTU + 1), so it cannot amplify.
pub const ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS: u64 = 10;

impl Icmpv4ErrorPolicy {
    pub const fn new(interval_ms: u64, state_ttl_ms: u64) -> Result<Self, Icmpv4ErrorPolicyError> {
        if interval_ms == 0 {
            return Err(Icmpv4ErrorPolicyError::IntervalZero);
        }
        if state_ttl_ms < interval_ms {
            return Err(Icmpv4ErrorPolicyError::StateTtlTooShort);
        }
        Ok(Self {
            interval_ms,
            port_unreachable_interval_ms: ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS,
            fragmentation_needed_interval_ms: ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS,
            state_ttl_ms,
            disabled: DEFAULT_DISABLED,
            translated_rate_per_second: ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND,
            translated_burst: ICMPV4_DEFAULT_TRANSLATED_BURST,
        })
    }

    /// Returns this policy with the rate limit of external ICMPv4 errors
    /// that NAT44 translates toward an inside host (RFC 5508 REQ-10 f, RFC
    /// 1812 §4.3.2.8; NAT44-065): at most `burst` errors at one instant
    /// and `rate_per_second` sustained, per path (inside host and quoted
    /// remote address).
    ///
    /// Errors offered at one clock reading pass at most `burst` at a time,
    /// so the sustained rate is also capped at `burst` per millisecond.
    /// Both at the maximum is the effectively-off setting. The
    /// defaults are [`crate::ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND`]
    /// and [`crate::ICMPV4_DEFAULT_TRANSLATED_BURST`].
    ///
    /// # Errors
    ///
    /// [`Icmpv4ErrorPolicyError::TranslatedLimitOutOfRange`] when either is
    /// 0 or above [`crate::ICMPV4_MAX_TRANSLATED_LIMIT`]. There is no
    /// unlimited setting: the limit fails closed.
    pub const fn with_translated_limit(
        self,
        rate_per_second: u32,
        burst: u32,
    ) -> Result<Self, Icmpv4ErrorPolicyError> {
        if rate_per_second == 0
            || burst == 0
            || rate_per_second > ICMPV4_MAX_TRANSLATED_LIMIT
            || burst > ICMPV4_MAX_TRANSLATED_LIMIT
        {
            return Err(Icmpv4ErrorPolicyError::TranslatedLimitOutOfRange);
        }
        Ok(Self {
            translated_rate_per_second: rate_per_second,
            translated_burst: burst,
            ..self
        })
    }

    /// Sustained translated ICMPv4 errors per second per (inside host,
    /// quoted remote address).
    #[must_use]
    pub const fn translated_rate_per_second(self) -> u32 {
        self.translated_rate_per_second
    }

    /// Translated ICMPv4 errors one (inside host, quoted remote address)
    /// can receive at one instant.
    #[must_use]
    pub const fn translated_burst(self) -> u32 {
        self.translated_burst
    }

    /// Returns this policy with `interval_ms` as the minimum interval
    /// between two Port Unreachable errors (RFC 5382 REQ-4, from the TCP
    /// NAT) on one egress. Port Unreachable is limited separately from the
    /// other kinds (its own limiter state per egress), so a flood of
    /// unsolicited SYNs never delays a Time Exceeded or another Destination
    /// Unreachable. The default is
    /// [`ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS`].
    ///
    /// # Errors
    ///
    /// [`Icmpv4ErrorPolicyError::IntervalZero`] for 0.
    pub const fn with_port_unreachable_interval_ms(
        self,
        interval_ms: u64,
    ) -> Result<Self, Icmpv4ErrorPolicyError> {
        if interval_ms == 0 {
            return Err(Icmpv4ErrorPolicyError::IntervalZero);
        }
        Ok(Self {
            port_unreachable_interval_ms: interval_ms,
            ..self
        })
    }

    #[must_use]
    pub const fn port_unreachable_interval_ms(self) -> u64 {
        self.port_unreachable_interval_ms
    }

    /// Returns this policy with `interval_ms` as the minimum interval
    /// between two Fragmentation Needed errors (MTU1) on one egress.
    /// Fragmentation Needed has its own limiter state per egress, so a flood
    /// of Time Exceeded or other errors toward the same egress never starves
    /// Path MTU Discovery. The default is
    /// [`ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS`].
    ///
    /// # Errors
    ///
    /// [`Icmpv4ErrorPolicyError::IntervalZero`] for 0 (there is no unlimited
    /// setting: the limit fails closed).
    pub const fn with_fragmentation_needed_interval_ms(
        self,
        interval_ms: u64,
    ) -> Result<Self, Icmpv4ErrorPolicyError> {
        if interval_ms == 0 {
            return Err(Icmpv4ErrorPolicyError::IntervalZero);
        }
        Ok(Self {
            fragmentation_needed_interval_ms: interval_ms,
            ..self
        })
    }

    #[must_use]
    pub const fn fragmentation_needed_interval_ms(self) -> u64 {
        self.fragmentation_needed_interval_ms
    }

    const fn class_interval_ms(self, class: u8) -> u64 {
        match class {
            1 => self.port_unreachable_interval_ms,
            2 => self.fragmentation_needed_interval_ms,
            // Class 0 and the Redirect class 3 share the interval value,
            // not the state.
            _ => self.interval_ms,
        }
    }

    /// An idle limiter state is reclaimed only once both the state TTL and
    /// its class interval have passed, so reclaiming never shortens the
    /// interval.
    const fn class_reclaim_ms(self, class: u8) -> u64 {
        let interval = self.class_interval_ms(class);
        if interval > self.state_ttl_ms {
            interval
        } else {
            self.state_ttl_ms
        }
    }

    /// Returns this policy with generation of `kind` enabled or disabled.
    #[must_use]
    pub const fn with_generation(self, kind: Icmpv4ErrorKind, enabled: bool) -> Self {
        let bit = kind.generation_bit();
        Self {
            disabled: if enabled {
                self.disabled & !bit
            } else {
                self.disabled | bit
            },
            ..self
        }
    }

    /// Whether errors of `kind` are generated (default: every kind but
    /// [`Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited`]).
    #[must_use]
    pub const fn generates(self, kind: Icmpv4ErrorKind) -> bool {
        self.disabled & kind.generation_bit() == 0
    }

    #[must_use]
    pub const fn interval_ms(self) -> u64 {
        self.interval_ms
    }

    #[must_use]
    pub const fn state_ttl_ms(self) -> u64 {
        self.state_ttl_ms
    }
}

impl Default for Icmpv4ErrorPolicy {
    fn default() -> Self {
        Self {
            interval_ms: 100,
            port_unreachable_interval_ms: ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS,
            fragmentation_needed_interval_ms: ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS,
            state_ttl_ms: 60_000,
            disabled: DEFAULT_DISABLED,
            translated_rate_per_second: ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND,
            translated_burst: ICMPV4_DEFAULT_TRANSLATED_BURST,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorAction {
    pub kind: Icmpv4ErrorKind,
    pub egress: IfId,
    pub source_mac: MacAddress,
    pub destination_mac: MacAddress,
    pub source_ip: Ipv4Address,
    pub destination_ip: Ipv4Address,
    pub outer_tos: u8,
    pub outer_ttl: u8,
    /// The kind-specific value of the second ICMP header word: the Next-Hop
    /// MTU (RFC 1191 §4, bytes 6..8) of
    /// [`Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded`], the
    /// pointer (RFC 792, byte 4) of [`Icmpv4ErrorKind::ParameterProblem`],
    /// the gateway address (RFC 792, bytes 4..8) of
    /// [`Icmpv4ErrorKind::RedirectHost`]; 0 (the RFC 792 unused field) for
    /// every other kind. One field for all three keeps the action slot size
    /// unchanged (the 32-bit word fits the padding the slot already had).
    header_value: u32,
    /// [`Self::fit_egress_mtu`] could not keep the RFC 792 minimum quote
    /// (the original IPv4 header and 8 data bytes); the runtime suppresses
    /// the action ([`Icmpv4ErrorDisposition::QuoteBelowMinimum`]).
    quote_below_minimum: bool,
    quote_len: u16,
    quote: [u8; ICMPV4_ERROR_MAX_QUOTE_LEN],
}

impl Icmpv4ErrorAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        egress: IfId,
        source_mac: MacAddress,
        destination_mac: MacAddress,
        source_ip: Ipv4Address,
        destination_ip: Ipv4Address,
        original_tos: u8,
        outer_ttl: u8,
        original_ipv4: &[u8],
    ) -> Self {
        Self::new_with_kind(
            Icmpv4ErrorKind::TimeExceededTtl,
            egress,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            original_tos,
            outer_ttl,
            original_ipv4,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_kind(
        kind: Icmpv4ErrorKind,
        egress: IfId,
        source_mac: MacAddress,
        destination_mac: MacAddress,
        source_ip: Ipv4Address,
        destination_ip: Ipv4Address,
        original_tos: u8,
        outer_ttl: u8,
        original_ipv4: &[u8],
    ) -> Self {
        let quote_len = original_ipv4.len().min(ICMPV4_ERROR_MAX_QUOTE_LEN);
        let mut quote = [0; ICMPV4_ERROR_MAX_QUOTE_LEN];
        quote[..quote_len].copy_from_slice(&original_ipv4[..quote_len]);
        Self {
            kind,
            egress,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            outer_tos: (original_tos & 0x1e) | 0xc0,
            outer_ttl,
            header_value: 0,
            quote_below_minimum: false,
            quote_len: quote_len as u16,
            quote,
        }
    }

    /// Returns this action with `mtu` as the Next-Hop MTU (RFC 1191 §4).
    /// Only [`Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded`]
    /// carries one; for every other kind the field stays 0 (unused).
    #[must_use]
    pub const fn with_next_hop_mtu(mut self, mtu: u16) -> Self {
        if matches!(
            self.kind,
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded
        ) {
            self.header_value = mtu as u32;
        }
        self
    }

    /// The Next-Hop MTU written to the ICMP header (0 for kinds other than
    /// Fragmentation Needed).
    #[must_use]
    pub const fn next_hop_mtu(&self) -> u16 {
        if matches!(
            self.kind,
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded
        ) {
            self.header_value as u16
        } else {
            0
        }
    }

    /// Returns this action with `pointer` (the offset of the offending
    /// octet in the quoted IPv4 header, RFC 792) as the Parameter Problem
    /// pointer. Only [`Icmpv4ErrorKind::ParameterProblem`] carries one; for
    /// every other kind it is ignored.
    #[must_use]
    pub const fn with_pointer(mut self, pointer: u8) -> Self {
        if matches!(self.kind, Icmpv4ErrorKind::ParameterProblem) {
            self.header_value = pointer as u32;
        }
        self
    }

    /// The Parameter Problem pointer written to the ICMP header (0 for
    /// other kinds).
    #[must_use]
    pub const fn pointer(&self) -> u8 {
        if matches!(self.kind, Icmpv4ErrorKind::ParameterProblem) {
            self.header_value as u8
        } else {
            0
        }
    }

    /// Returns this action with `gateway` (the better first hop, RFC 792)
    /// as the Redirect gateway address. Only
    /// [`Icmpv4ErrorKind::RedirectHost`] carries one; for every other kind
    /// it is ignored.
    #[must_use]
    pub const fn with_gateway(mut self, gateway: Ipv4Address) -> Self {
        if matches!(self.kind, Icmpv4ErrorKind::RedirectHost) {
            self.header_value = u32::from_be_bytes(gateway.octets());
        }
        self
    }

    /// The Redirect gateway address written to the ICMP header
    /// (`0.0.0.0` for other kinds).
    #[must_use]
    pub const fn gateway(&self) -> Ipv4Address {
        if matches!(self.kind, Icmpv4ErrorKind::RedirectHost) {
            Ipv4Address::from_octets(self.header_value.to_be_bytes())
        } else {
            Ipv4Address::from_octets([0; 4])
        }
    }

    /// Returns this action with the quote shortened so that the generated
    /// IPv4 datagram (20-byte header, 8-byte ICMP header, quote) is at most
    /// `egress_mtu` bytes: an error never needs fragmentation on the
    /// interface it leaves (RFC 1812 §4.3.2.3 asks for as much of the
    /// original as fits without exceeding 576 bytes, which
    /// [`ICMPV4_ERROR_MAX_QUOTE_LEN`] already bounds). The cut bytes are
    /// zeroed so equal actions stay equal. An MTU of at least
    /// [`crate::IPV4_MIN_MTU`] keeps at least 40 quoted bytes, enough for an
    /// option-free header (20 bytes) plus the 8 data bytes RFC 792 requires,
    /// but not for a header with options (up to 60 bytes). When the room is
    /// below the quoted IHL * 4 + 8 (or the whole original datagram, if that
    /// is shorter) the action is marked and the runtime suppresses it as
    /// [`Icmpv4ErrorDisposition::QuoteBelowMinimum`] instead of sending a
    /// quote the receiver cannot match.
    #[must_use]
    pub fn fit_egress_mtu(mut self, egress_mtu: u16) -> Self {
        let room = usize::from(egress_mtu).saturating_sub(28);
        let quote_len = usize::from(self.quote_len);
        let minimum = self
            .quote
            .first()
            .map_or(0, |first| usize::from(first & 0x0f) * 4 + 8)
            .min(quote_len);
        if room < minimum {
            self.quote_below_minimum = true;
        }
        if quote_len > room {
            self.quote[room..quote_len].fill(0);
            self.quote_len = room as u16;
        }
        self
    }

    /// Whether [`Self::fit_egress_mtu`] cut the quote below the RFC 792
    /// minimum (the action will be suppressed).
    #[must_use]
    pub const fn quote_below_minimum(&self) -> bool {
        self.quote_below_minimum
    }

    #[must_use]
    pub fn quote(&self) -> &[u8] {
        &self.quote[..usize::from(self.quote_len)]
    }

    #[must_use]
    pub const fn quote_len(&self) -> usize {
        self.quote_len as usize
    }

    #[must_use]
    pub const fn frame_len(&self) -> usize {
        let visible = 14 + 28 + self.quote_len as usize;
        if visible < ETHERNET_MIN_FRAME_LEN {
            ETHERNET_MIN_FRAME_LEN
        } else {
            visible
        }
    }
}

pub type Icmpv4TimeExceededAction = Icmpv4ErrorAction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorActionSlot(Option<QueuedAction>);

impl Icmpv4ErrorActionSlot {
    pub const EMPTY: Self = Self(None);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4ErrorStateSlot {
    egress: IfId,
    /// Limiter class (`Icmpv4ErrorKind::limiter_class`): a state is keyed by
    /// egress and class.
    class: u8,
    generation: u64,
    requested_at: MonotonicMillis,
    occupied: bool,
    action_queued: bool,
    has_requested: bool,
}

impl Icmpv4ErrorStateSlot {
    pub const EMPTY: Self = Self {
        egress: IfId(0),
        class: 0,
        generation: 0,
        requested_at: MonotonicMillis(0),
        occupied: false,
        action_queued: false,
        has_requested: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueuedAction {
    action: Icmpv4ErrorAction,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Icmpv4ErrorDisposition {
    Queued {
        egress: IfId,
        quote_len: usize,
    },
    DestinationUnreachableQueued {
        egress: IfId,
        quote_len: usize,
    },
    HostUnreachableQueued {
        egress: IfId,
        quote_len: usize,
    },
    PortUnreachableQueued {
        egress: IfId,
        quote_len: usize,
    },
    /// A Fragmentation Needed error (Type 3, Code 4) was queued.
    FragmentationNeededQueued {
        egress: IfId,
        quote_len: usize,
        next_hop_mtu: u16,
    },
    /// A Protocol Unreachable error (Type 3, Code 2) was queued.
    ProtocolUnreachableQueued {
        egress: IfId,
        quote_len: usize,
    },
    /// A Port Unreachable error (Type 3, Code 3) about a UDP datagram
    /// addressed to the router was queued.
    LocalPortUnreachableQueued {
        egress: IfId,
        quote_len: usize,
    },
    /// A Parameter Problem error (Type 12, Code 0) was queued.
    ParameterProblemQueued {
        egress: IfId,
        quote_len: usize,
        pointer: u8,
    },
    /// A Communication Administratively Prohibited error (Type 3, Code 13)
    /// was queued.
    AdministrativelyProhibitedQueued {
        egress: IfId,
        quote_len: usize,
    },
    /// A Redirect for Host (Type 5, Code 1) naming `gateway` was queued.
    RedirectQueued {
        egress: IfId,
        quote_len: usize,
        gateway: Ipv4Address,
    },
    Pending {
        egress: IfId,
    },
    RateLimited {
        egress: IfId,
    },
    /// The policy disables generation of `kind`; nothing was queued.
    GenerationDisabled {
        kind: Icmpv4ErrorKind,
    },
    /// The MTU of the reverse egress leaves less room than the RFC 792
    /// minimum quote (the original header with its options and 8 data
    /// bytes); nothing was queued.
    QuoteBelowMinimum {
        egress: IfId,
    },
    StateFull,
    ActionFull,
    ClockRegression,
    SourceNotUnicast,
    SourceIsLocal,
    DestinationMulticast,
    DestinationLimitedBroadcast,
    DestinationNetworkAddress,
    DestinationDirectedBroadcast,
    EthernetDestinationGroup,
    NonInitialFragment,
    IcmpErrorMessage,
    IcmpTypeMissing,
    ReverseRouteMiss,
    ReverseInterfaceMiss {
        egress: IfId,
    },
    ReverseBindingMiss {
        egress: IfId,
    },
    ReverseTargetForbidden {
        egress: IfId,
        target: Ipv4Address,
    },
    ReverseNeighborUnresolved {
        egress: IfId,
        target: Ipv4Address,
    },
}

pub type Icmpv4TimeExceededDisposition = Icmpv4ErrorDisposition;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Icmpv4ErrorCounters {
    pub queued: usize,
    pub queued_time_exceeded: usize,
    pub queued_destination_unreachable: usize,
    pub queued_host_unreachable: usize,
    pub queued_port_unreachable: usize,
    pub queued_fragmentation_needed: usize,
    pub pending: usize,
    pub rate_limited: usize,
    pub disabled_time_exceeded: usize,
    pub disabled_destination_unreachable: usize,
    pub disabled_host_unreachable: usize,
    pub disabled_port_unreachable: usize,
    pub disabled_fragmentation_needed: usize,
    pub quote_below_minimum: usize,
    pub state_full: usize,
    pub action_full: usize,
    pub clock_regressions: usize,
    pub source_not_unicast: usize,
    pub source_is_local: usize,
    pub destination_multicast: usize,
    pub destination_limited_broadcast: usize,
    pub destination_network_address: usize,
    pub destination_directed_broadcast: usize,
    pub ethernet_destination_group: usize,
    pub noninitial_fragment: usize,
    pub icmp_error_message: usize,
    pub icmp_type_missing: usize,
    pub reverse_route_miss: usize,
    pub reverse_interface_miss: usize,
    pub reverse_binding_miss: usize,
    pub reverse_target_forbidden: usize,
    pub reverse_neighbor_unresolved: usize,
    pub dequeued: usize,
    pub dequeued_time_exceeded: usize,
    pub dequeued_destination_unreachable: usize,
    pub dequeued_host_unreachable: usize,
    pub dequeued_port_unreachable: usize,
    pub dequeued_fragmentation_needed: usize,
    // ICMP-ERR: appended so the earlier fields keep their order.
    pub queued_protocol_unreachable: usize,
    pub queued_udp_port_unreachable: usize,
    pub queued_parameter_problem: usize,
    pub queued_admin_prohibited: usize,
    pub disabled_protocol_unreachable: usize,
    pub disabled_udp_port_unreachable: usize,
    pub disabled_parameter_problem: usize,
    pub disabled_admin_prohibited: usize,
    pub dequeued_protocol_unreachable: usize,
    pub dequeued_udp_port_unreachable: usize,
    pub dequeued_parameter_problem: usize,
    pub dequeued_admin_prohibited: usize,
    // ICMP-REDIRECT: appended so the earlier fields keep their order.
    pub queued_redirect: usize,
    pub disabled_redirect: usize,
    pub dequeued_redirect: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Icmpv4ErrorPublicationReport {
    pub states_flushed: usize,
    pub actions_flushed: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Icmpv4ErrorPublicationError {
    ActionQueueCapacity,
    ActionQueueHead,
    ActionQueueWindow,
    QueuedStateMismatch,
    RuntimeEpochExhausted,
    /// The occupied limiter states are not exactly a prefix of the table.
    OccupiedPrefix,
}

/// Exclusive proof that old generated-ICMP authority can be flushed totally.
///
/// ```compile_fail
/// use ruster_core::Icmpv4ErrorRuntime;
///
/// fn reborrow<'storage>(runtime: &mut Icmpv4ErrorRuntime<'storage>) {
///     let permit = runtime.preflight_publication().unwrap();
///     let _ = runtime.pending_actions();
///     permit.commit();
/// }
/// ```
#[must_use]
pub struct Icmpv4ErrorPublicationPermit<'runtime, 'storage> {
    runtime: &'runtime mut Icmpv4ErrorRuntime<'storage>,
    next_runtime_epoch: u128,
    report: Icmpv4ErrorPublicationReport,
}

/// Caller-backed, worker-local ICMP error queue and per-egress limiter.
///
/// The runtime deliberately has no shared state and cannot cross worker
/// boundaries.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::Icmpv4ErrorRuntime<'static>>();
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<ruster_core::Icmpv4ErrorRuntime<'static>>();
/// ```
pub struct Icmpv4ErrorRuntime<'a> {
    policy: Icmpv4ErrorPolicy,
    states: &'a mut [Icmpv4ErrorStateSlot],
    actions: &'a mut [Icmpv4ErrorActionSlot],
    head: usize,
    len: usize,
    /// Occupied limiter states are exactly `states[..occupied_prefix]`: a
    /// state is only ever created in the lowest free slot and only a
    /// publication flush frees one. Every occupied state has its own egress
    /// interface and limiter class (at most three per egress: Port
    /// Unreachable and Fragmentation Needed have their own), so per-packet
    /// searches read at most three slots per egress interface in use (H4b,
    /// PERF-001), not the whole capacity.
    occupied_prefix: usize,
    last_now: Option<MonotonicMillis>,
    runtime_epoch: u128,
    counters: Icmpv4ErrorCounters,
    /// Allocated limiter state slots; see [`Icmpv4ErrorRuntime::state_occupancy`].
    state_occupancy: OccupancyCounter,
    /// Largest queued action count; see [`Icmpv4ErrorRuntime::action_occupancy`].
    action_high_water: HighWaterMark,
    /// Limiter of translated NAT44 errors per (inside host, quoted remote)
    /// (NAT44-065). A publication that installs the same key keeps it (the
    /// policy cannot change without a restart); a new key empties it.
    translated: TranslatedIcmpv4Limiter,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> Icmpv4ErrorRuntime<'a> {
    #[must_use]
    pub fn new(
        policy: Icmpv4ErrorPolicy,
        states: &'a mut [Icmpv4ErrorStateSlot],
        actions: &'a mut [Icmpv4ErrorActionSlot],
    ) -> Self {
        states.fill(Icmpv4ErrorStateSlot::EMPTY);
        actions.fill(Icmpv4ErrorActionSlot::EMPTY);
        Self {
            policy,
            states,
            actions,
            head: 0,
            len: 0,
            occupied_prefix: 0,
            last_now: None,
            runtime_epoch: 1,
            counters: Icmpv4ErrorCounters::default(),
            state_occupancy: OccupancyCounter::default(),
            action_high_water: HighWaterMark::default(),
            translated: TranslatedIcmpv4Limiter::EMPTY,
            _worker_local: PhantomData,
        }
    }

    /// Returns this runtime with `key` (a publication's secret resolution
    /// key, used in its own hash domain) choosing the buckets of the
    /// translated error limiter (NAT44-065). Without it the runtime uses a
    /// public fixed key, whose bucket collisions anyone can compute; every
    /// production activation and publication supplies the secret.
    #[must_use]
    pub fn with_translated_limit_key(mut self, key: crate::ResolutionHashKey) -> Self {
        self.translated.rekey(key.directory_key());
        self
    }

    /// Whether the translated error limiter hashes with `key` (a
    /// publication's binding check; reveals nothing without the key).
    #[must_use]
    pub fn translated_limit_key_matches(&self, key: crate::ResolutionHashKey) -> bool {
        self.translated.key_matches(key.directory_key())
    }

    /// Admits one external ICMPv4 error that NAT44 translates toward the
    /// inside host `host` about its flow with `remote`, or refuses it under
    /// the policy's translated limit (NAT44-065). O(1): one keyed hash and
    /// one fixed bucket, no allocation or scan; a refusal changes nothing.
    pub(crate) fn admit_translated(
        &mut self,
        host: Ipv4Address,
        remote: Ipv4Address,
        now: MonotonicMillis,
    ) -> bool {
        self.translated.admit(
            host,
            remote,
            now,
            self.policy.translated_rate_per_second,
            self.policy.translated_burst,
        )
    }

    #[must_use]
    pub const fn pending_actions(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn counters(&self) -> Icmpv4ErrorCounters {
        self.counters
    }

    #[must_use]
    pub const fn policy(&self) -> Icmpv4ErrorPolicy {
        self.policy
    }

    #[must_use]
    pub const fn state_capacity(&self) -> usize {
        self.states.len()
    }

    #[must_use]
    pub const fn action_capacity(&self) -> usize {
        self.actions.len()
    }

    /// Exact allocated per-egress limiter state slots and their high-water
    /// mark since construction or the last publication flush, in O(1).
    ///
    /// A slot counts from the first queued error for its egress until a
    /// publication flush. A state past its TTL is reclaimed in place by the
    /// next new egress, so expired states still count until reused.
    #[must_use]
    pub const fn state_occupancy(&self) -> TableOccupancy {
        self.state_occupancy.snapshot(self.states.len())
    }

    /// The generated error action queue (pending errors) and its high-water
    /// mark since construction or the last publication commit, which empties
    /// the queue (OBS-017). O(1).
    #[must_use]
    pub const fn action_occupancy(&self) -> TableOccupancy {
        self.action_high_water
            .snapshot(self.len, self.actions.len())
    }

    /// Returns whether this runtime is still in its exact constructor state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.states
            .iter()
            .all(|slot| *slot == Icmpv4ErrorStateSlot::EMPTY)
            && self
                .actions
                .iter()
                .all(|slot| *slot == Icmpv4ErrorActionSlot::EMPTY)
            && self.head == 0
            && self.len == 0
            && self.occupied_prefix == 0
            && self.last_now.is_none()
            && self.runtime_epoch == 1
            && self.counters == Icmpv4ErrorCounters::default()
            && self.state_occupancy == OccupancyCounter::default()
            && self.action_high_water == HighWaterMark::default()
            && self.translated.is_pristine()
    }

    /// Validates the generated-action queue without changing runtime state.
    ///
    /// Successful commit clears all limiter and action state because queued
    /// actions contain publication-specific egress, MAC, and IPv4 authority.
    /// Cumulative operational counters are deliberately preserved.
    pub fn preflight_publication<'runtime>(
        &'runtime mut self,
    ) -> Result<Icmpv4ErrorPublicationPermit<'runtime, 'a>, Icmpv4ErrorPublicationError> {
        if self.len > self.actions.len() {
            return Err(Icmpv4ErrorPublicationError::ActionQueueCapacity);
        }
        if self.actions.is_empty() {
            if self.head != 0 || self.len != 0 {
                return Err(Icmpv4ErrorPublicationError::ActionQueueHead);
            }
        } else if self.head >= self.actions.len() {
            return Err(Icmpv4ErrorPublicationError::ActionQueueHead);
        }
        for index in 0..self.actions.len() {
            let distance = (index + self.actions.len() - self.head) % self.actions.len();
            if self.actions[index].0.is_some() != (distance < self.len) {
                return Err(Icmpv4ErrorPublicationError::ActionQueueWindow);
            }
        }
        if self
            .states
            .iter()
            .any(|state| state.action_queued && !state.occupied)
        {
            return Err(Icmpv4ErrorPublicationError::QueuedStateMismatch);
        }
        if self.occupied_prefix > self.states.len()
            || self
                .states
                .iter()
                .enumerate()
                .any(|(index, state)| state.occupied != (index < self.occupied_prefix))
        {
            return Err(Icmpv4ErrorPublicationError::OccupiedPrefix);
        }
        let queued_states = self
            .states
            .iter()
            .filter(|state| state.occupied && state.action_queued)
            .count();
        if queued_states != self.len {
            return Err(Icmpv4ErrorPublicationError::QueuedStateMismatch);
        }
        for offset in 0..self.len {
            let index = (self.head + offset) % self.actions.len();
            let Some(queued) = self.actions[index].0 else {
                return Err(Icmpv4ErrorPublicationError::ActionQueueWindow);
            };
            if (0..offset).any(|previous_offset| {
                let previous_index = (self.head + previous_offset) % self.actions.len();
                self.actions[previous_index].0.is_some_and(|previous| {
                    previous.action.egress == queued.action.egress
                        && previous.action.kind.limiter_class()
                            == queued.action.kind.limiter_class()
                        && previous.generation == queued.generation
                })
            }) {
                return Err(Icmpv4ErrorPublicationError::QueuedStateMismatch);
            }
            if !self.states.iter().any(|state| {
                state.occupied
                    && state.action_queued
                    && state.egress == queued.action.egress
                    && state.class == queued.action.kind.limiter_class()
                    && state.generation == queued.generation
            }) {
                return Err(Icmpv4ErrorPublicationError::QueuedStateMismatch);
            }
        }
        let next_runtime_epoch = self
            .runtime_epoch
            .checked_add(1)
            .ok_or(Icmpv4ErrorPublicationError::RuntimeEpochExhausted)?;
        let report = Icmpv4ErrorPublicationReport {
            states_flushed: self.states.iter().filter(|state| state.occupied).count(),
            actions_flushed: self.len,
        };
        Ok(Icmpv4ErrorPublicationPermit {
            runtime: self,
            next_runtime_epoch,
            report,
        })
    }

    pub(crate) fn record_suppression(
        &mut self,
        disposition: Icmpv4ErrorDisposition,
    ) -> Icmpv4ErrorDisposition {
        match disposition {
            Icmpv4ErrorDisposition::Queued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_time_exceeded += 1;
            }
            Icmpv4ErrorDisposition::DestinationUnreachableQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_destination_unreachable += 1;
            }
            Icmpv4ErrorDisposition::HostUnreachableQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_host_unreachable += 1;
            }
            Icmpv4ErrorDisposition::PortUnreachableQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_port_unreachable += 1;
            }
            Icmpv4ErrorDisposition::FragmentationNeededQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_fragmentation_needed += 1;
            }
            Icmpv4ErrorDisposition::ProtocolUnreachableQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_protocol_unreachable += 1;
            }
            Icmpv4ErrorDisposition::LocalPortUnreachableQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_udp_port_unreachable += 1;
            }
            Icmpv4ErrorDisposition::ParameterProblemQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_parameter_problem += 1;
            }
            Icmpv4ErrorDisposition::AdministrativelyProhibitedQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_admin_prohibited += 1;
            }
            Icmpv4ErrorDisposition::RedirectQueued { .. } => {
                self.counters.queued += 1;
                self.counters.queued_redirect += 1;
            }
            Icmpv4ErrorDisposition::Pending { .. } => self.counters.pending += 1,
            Icmpv4ErrorDisposition::RateLimited { .. } => {
                self.counters.rate_limited += 1;
            }
            Icmpv4ErrorDisposition::GenerationDisabled { kind } => match kind {
                Icmpv4ErrorKind::TimeExceededTtl => self.counters.disabled_time_exceeded += 1,
                Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                    self.counters.disabled_destination_unreachable += 1;
                }
                Icmpv4ErrorKind::DestinationUnreachableHost => {
                    self.counters.disabled_host_unreachable += 1;
                }
                Icmpv4ErrorKind::DestinationUnreachablePort => {
                    self.counters.disabled_port_unreachable += 1;
                }
                Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded => {
                    self.counters.disabled_fragmentation_needed += 1;
                }
                Icmpv4ErrorKind::DestinationUnreachableProtocol => {
                    self.counters.disabled_protocol_unreachable += 1;
                }
                Icmpv4ErrorKind::DestinationUnreachableLocalPort => {
                    self.counters.disabled_udp_port_unreachable += 1;
                }
                Icmpv4ErrorKind::ParameterProblem => {
                    self.counters.disabled_parameter_problem += 1;
                }
                Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited => {
                    self.counters.disabled_admin_prohibited += 1;
                }
                Icmpv4ErrorKind::RedirectHost => self.counters.disabled_redirect += 1,
            },
            Icmpv4ErrorDisposition::QuoteBelowMinimum { .. } => {
                self.counters.quote_below_minimum += 1;
            }
            Icmpv4ErrorDisposition::StateFull => self.counters.state_full += 1,
            Icmpv4ErrorDisposition::ActionFull => self.counters.action_full += 1,
            Icmpv4ErrorDisposition::ClockRegression => {
                self.counters.clock_regressions += 1;
            }
            Icmpv4ErrorDisposition::SourceNotUnicast => {
                self.counters.source_not_unicast += 1;
            }
            Icmpv4ErrorDisposition::SourceIsLocal => self.counters.source_is_local += 1,
            Icmpv4ErrorDisposition::DestinationMulticast => {
                self.counters.destination_multicast += 1;
            }
            Icmpv4ErrorDisposition::DestinationLimitedBroadcast => {
                self.counters.destination_limited_broadcast += 1;
            }
            Icmpv4ErrorDisposition::DestinationNetworkAddress => {
                self.counters.destination_network_address += 1;
            }
            Icmpv4ErrorDisposition::DestinationDirectedBroadcast => {
                self.counters.destination_directed_broadcast += 1;
            }
            Icmpv4ErrorDisposition::EthernetDestinationGroup => {
                self.counters.ethernet_destination_group += 1;
            }
            Icmpv4ErrorDisposition::NonInitialFragment => {
                self.counters.noninitial_fragment += 1;
            }
            Icmpv4ErrorDisposition::IcmpErrorMessage => {
                self.counters.icmp_error_message += 1;
            }
            Icmpv4ErrorDisposition::IcmpTypeMissing => {
                self.counters.icmp_type_missing += 1;
            }
            Icmpv4ErrorDisposition::ReverseRouteMiss => {
                self.counters.reverse_route_miss += 1;
            }
            Icmpv4ErrorDisposition::ReverseInterfaceMiss { .. } => {
                self.counters.reverse_interface_miss += 1;
            }
            Icmpv4ErrorDisposition::ReverseBindingMiss { .. } => {
                self.counters.reverse_binding_miss += 1;
            }
            Icmpv4ErrorDisposition::ReverseTargetForbidden { .. } => {
                self.counters.reverse_target_forbidden += 1;
            }
            Icmpv4ErrorDisposition::ReverseNeighborUnresolved { .. } => {
                self.counters.reverse_neighbor_unresolved += 1;
            }
        }
        disposition
    }

    pub(crate) fn schedule(
        &mut self,
        action: Icmpv4ErrorAction,
        now: MonotonicMillis,
    ) -> Icmpv4ErrorDisposition {
        if !self.policy.generates(action.kind) {
            return self.record_suppression(Icmpv4ErrorDisposition::GenerationDisabled {
                kind: action.kind,
            });
        }
        if action.quote_below_minimum {
            return self.record_suppression(Icmpv4ErrorDisposition::QuoteBelowMinimum {
                egress: action.egress,
            });
        }
        if !self.observe_now(now) {
            return self.record_suppression(Icmpv4TimeExceededDisposition::ClockRegression);
        }
        let class = action.kind.limiter_class();
        let occupied = &self.states[..self.occupied_prefix];
        if let Some(index) = occupied.iter().position(|state| {
            state.occupied && state.egress == action.egress && state.class == class
        }) {
            let state = self.states[index];
            if state.action_queued {
                return self.record_suppression(Icmpv4TimeExceededDisposition::Pending {
                    egress: action.egress,
                });
            }
            if state.has_requested
                && now.0.saturating_sub(state.requested_at.0) < self.policy.class_interval_ms(class)
            {
                return self.record_suppression(Icmpv4TimeExceededDisposition::RateLimited {
                    egress: action.egress,
                });
            }
            return self.enqueue(index, action);
        }

        // The lowest occupied state past its TTL, else the first free slot,
        // which is the slot right after the occupied prefix.
        let Some(index) = self.states[..self.occupied_prefix]
            .iter()
            .position(|state| {
                !state.action_queued
                    && state.has_requested
                    && now.0.saturating_sub(state.requested_at.0)
                        >= self.policy.class_reclaim_ms(state.class)
            })
            .or((self.occupied_prefix < self.states.len()).then_some(self.occupied_prefix))
        else {
            return self.record_suppression(Icmpv4TimeExceededDisposition::StateFull);
        };
        if self.len == self.actions.len() {
            return self.record_suppression(Icmpv4TimeExceededDisposition::ActionFull);
        }
        let reclaimed = self.states[index].occupied;
        if !reclaimed {
            debug_assert_eq!(index, self.occupied_prefix);
            self.occupied_prefix += 1;
        }
        self.states[index] = Icmpv4ErrorStateSlot {
            egress: action.egress,
            class,
            generation: self.states[index].generation.wrapping_add(1),
            requested_at: MonotonicMillis(0),
            occupied: true,
            action_queued: false,
            has_requested: false,
        };
        self.state_occupancy.transition(reclaimed, true);
        self.enqueue(index, action)
    }

    fn enqueue(&mut self, state_index: usize, action: Icmpv4ErrorAction) -> Icmpv4ErrorDisposition {
        if self.len == self.actions.len() {
            return self.record_suppression(Icmpv4TimeExceededDisposition::ActionFull);
        }
        let generation = self.states[state_index].generation.wrapping_add(1);
        let tail = (self.head + self.len) % self.actions.len();
        self.actions[tail].0 = Some(QueuedAction { action, generation });
        self.states[state_index].generation = generation;
        self.states[state_index].action_queued = true;
        self.len += 1;
        self.action_high_water.observe(self.len);
        let disposition = match action.kind {
            Icmpv4ErrorKind::TimeExceededTtl => Icmpv4ErrorDisposition::Queued {
                egress: action.egress,
                quote_len: action.quote_len(),
            },
            Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                Icmpv4ErrorDisposition::DestinationUnreachableQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                }
            }
            Icmpv4ErrorKind::DestinationUnreachableHost => {
                Icmpv4ErrorDisposition::HostUnreachableQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                }
            }
            Icmpv4ErrorKind::DestinationUnreachablePort => {
                Icmpv4ErrorDisposition::PortUnreachableQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                }
            }
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded => {
                Icmpv4ErrorDisposition::FragmentationNeededQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                    next_hop_mtu: action.next_hop_mtu(),
                }
            }
            Icmpv4ErrorKind::DestinationUnreachableProtocol => {
                Icmpv4ErrorDisposition::ProtocolUnreachableQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                }
            }
            Icmpv4ErrorKind::DestinationUnreachableLocalPort => {
                Icmpv4ErrorDisposition::LocalPortUnreachableQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                }
            }
            Icmpv4ErrorKind::ParameterProblem => Icmpv4ErrorDisposition::ParameterProblemQueued {
                egress: action.egress,
                quote_len: action.quote_len(),
                pointer: action.pointer(),
            },
            Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited => {
                Icmpv4ErrorDisposition::AdministrativelyProhibitedQueued {
                    egress: action.egress,
                    quote_len: action.quote_len(),
                }
            }
            Icmpv4ErrorKind::RedirectHost => Icmpv4ErrorDisposition::RedirectQueued {
                egress: action.egress,
                quote_len: action.quote_len(),
                gateway: action.gateway(),
            },
        };
        self.record_suppression(disposition)
    }

    /// The limiter refusal (`Pending` or `RateLimited`) an error of `kind`
    /// out of `egress` would get now, read without touching any state, so
    /// a caller can stop before reverse route and neighbor work
    /// (ICMP-REDIRECT). `None` when the limiter would admit it (or has no
    /// state for it yet).
    pub(crate) fn limiter_refusal(
        &self,
        kind: Icmpv4ErrorKind,
        egress: IfId,
        now: MonotonicMillis,
    ) -> Option<Icmpv4ErrorDisposition> {
        let class = kind.limiter_class();
        let state = self.states[..self.occupied_prefix]
            .iter()
            .find(|state| state.occupied && state.egress == egress && state.class == class)?;
        if state.action_queued {
            return Some(Icmpv4ErrorDisposition::Pending { egress });
        }
        (state.has_requested
            && now.0.saturating_sub(state.requested_at.0) < self.policy.class_interval_ms(class))
        .then_some(Icmpv4ErrorDisposition::RateLimited { egress })
    }

    pub(crate) fn observe_decision(&mut self, now: MonotonicMillis) -> bool {
        self.observe_now(now)
    }

    fn observe_now(&mut self, now: MonotonicMillis) -> bool {
        if self.last_now.is_some_and(|last| now < last) {
            return false;
        }
        self.last_now = Some(now);
        true
    }

    /// Drops the error at the front of the queue without sending it, for one the
    /// caller cannot send (its egress is no port of the backend). Returns whether
    /// there was one.
    pub fn discard_front(&mut self) -> bool {
        let Some(slot) = self.actions.get_mut(self.head) else {
            return false;
        };
        let Some(queued) = slot.0.take() else {
            return false;
        };
        self.head = (self.head + 1) % self.actions.len();
        self.len -= 1;
        self.counters.dequeued += 1;
        // Its limiter state no longer waits for it: later errors of its kind out of
        // its egress may be queued again (none was sent, so the interval does not
        // start).
        if let Some(state) = self.states[..self.occupied_prefix]
            .iter_mut()
            .find(|state| {
                state.occupied
                    && state.egress == queued.action.egress
                    && state.class == queued.action.kind.limiter_class()
                    && state.generation == queued.generation
            })
        {
            state.action_queued = false;
        }
        true
    }

    fn front(&self) -> Option<QueuedAction> {
        self.actions.get(self.head).and_then(|slot| slot.0)
    }

    fn execution_time_valid(&mut self, now: MonotonicMillis) -> bool {
        if self.observe_now(now) {
            true
        } else {
            self.counters.clock_regressions += 1;
            false
        }
    }

    fn committed(&mut self, queued: QueuedAction, now: MonotonicMillis) {
        let actual = self.actions[self.head]
            .0
            .take()
            .expect("committed ICMP action is queue front");
        debug_assert_eq!(actual, queued);
        self.head = (self.head + 1) % self.actions.len();
        self.len -= 1;
        self.counters.dequeued += 1;
        match queued.action.kind {
            Icmpv4ErrorKind::TimeExceededTtl => self.counters.dequeued_time_exceeded += 1,
            Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                self.counters.dequeued_destination_unreachable += 1;
            }
            Icmpv4ErrorKind::DestinationUnreachableHost => {
                self.counters.dequeued_host_unreachable += 1;
            }
            Icmpv4ErrorKind::DestinationUnreachablePort => {
                self.counters.dequeued_port_unreachable += 1;
            }
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded => {
                self.counters.dequeued_fragmentation_needed += 1;
            }
            Icmpv4ErrorKind::DestinationUnreachableProtocol => {
                self.counters.dequeued_protocol_unreachable += 1;
            }
            Icmpv4ErrorKind::DestinationUnreachableLocalPort => {
                self.counters.dequeued_udp_port_unreachable += 1;
            }
            Icmpv4ErrorKind::ParameterProblem => self.counters.dequeued_parameter_problem += 1,
            Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited => {
                self.counters.dequeued_admin_prohibited += 1;
            }
            Icmpv4ErrorKind::RedirectHost => self.counters.dequeued_redirect += 1,
        }
        if let Some(state) = self.states[..self.occupied_prefix]
            .iter_mut()
            .find(|state| {
                state.occupied
                    && state.egress == queued.action.egress
                    && state.class == queued.action.kind.limiter_class()
                    && state.generation == queued.generation
            })
        {
            state.action_queued = false;
            state.has_requested = true;
            state.requested_at = now;
        }
    }
}

impl Icmpv4ErrorPublicationPermit<'_, '_> {
    /// [`Self::commit`] that also installs the successor's secret key for
    /// the translated error limiter (NAT44-065). A different key empties
    /// the limiter, whose buckets the old key chose.
    pub fn commit_with_translated_limit_key(
        self,
        key: crate::ResolutionHashKey,
    ) -> Icmpv4ErrorPublicationReport {
        self.runtime.translated.rekey(key.directory_key());
        self.commit()
    }

    /// Flushes old publication authority without failure.
    pub fn commit(self) -> Icmpv4ErrorPublicationReport {
        self.runtime.states.fill(Icmpv4ErrorStateSlot::EMPTY);
        self.runtime.actions.fill(Icmpv4ErrorActionSlot::EMPTY);
        self.runtime.head = 0;
        self.runtime.len = 0;
        self.runtime.occupied_prefix = 0;
        self.runtime.last_now = None;
        self.runtime.runtime_epoch = self.next_runtime_epoch;
        self.runtime.state_occupancy.flush();
        self.runtime.action_high_water.reset(0);
        self.report
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4ErrorBuildError {
    ExactLengthRequired,
}

pub type Icmpv4TimeExceededBuildError = Icmpv4ErrorBuildError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecuteIcmpv4Error {
    ClockRegression,
}

pub type ExecuteIcmpv4TimeExceededError = ExecuteIcmpv4Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedIcmpv4Trace {
    AllocationFailed(GeneratedAllocationError),
    BuildFailed(Icmpv4ErrorBuildError),
    DestinationUnreachableAllocationFailed(GeneratedAllocationError),
    DestinationUnreachableBuildFailed(Icmpv4ErrorBuildError),
    HostUnreachableAllocationFailed(GeneratedAllocationError),
    HostUnreachableBuildFailed(Icmpv4ErrorBuildError),
    PortUnreachableAllocationFailed(GeneratedAllocationError),
    PortUnreachableBuildFailed(Icmpv4ErrorBuildError),
    FragmentationNeededAllocationFailed(GeneratedAllocationError),
    FragmentationNeededBuildFailed(Icmpv4ErrorBuildError),
    ClockRegression,
    DestinationUnreachableClockRegression,
    HostUnreachableClockRegression,
    PortUnreachableClockRegression,
    FragmentationNeededClockRegression,
    TxRequested {
        egress: IfId,
        destination: Ipv4Address,
    },
    DestinationUnreachableTxRequested {
        egress: IfId,
        destination: Ipv4Address,
    },
    HostUnreachableTxRequested {
        egress: IfId,
        destination: Ipv4Address,
    },
    PortUnreachableTxRequested {
        egress: IfId,
        destination: Ipv4Address,
    },
    FragmentationNeededTxRequested {
        egress: IfId,
        destination: Ipv4Address,
        next_hop_mtu: u16,
    },
    BatchCompleted {
        accepted: usize,
        rejected: usize,
    },
    DestinationUnreachableBatchCompleted {
        accepted: usize,
        rejected: usize,
    },
    HostUnreachableBatchCompleted {
        accepted: usize,
        rejected: usize,
    },
    PortUnreachableBatchCompleted {
        accepted: usize,
        rejected: usize,
    },
    FragmentationNeededBatchCompleted {
        accepted: usize,
        rejected: usize,
    },
    /// The events of the ICMP-ERR kinds (Protocol Unreachable, the router's
    /// own UDP Port Unreachable, Parameter Problem, Communication
    /// Administratively Prohibited) carry their kind.
    KindAllocationFailed {
        kind: Icmpv4ErrorKind,
        error: GeneratedAllocationError,
    },
    KindBuildFailed {
        kind: Icmpv4ErrorKind,
        error: Icmpv4ErrorBuildError,
    },
    KindClockRegression {
        kind: Icmpv4ErrorKind,
    },
    KindTxRequested {
        kind: Icmpv4ErrorKind,
        egress: IfId,
        destination: Ipv4Address,
    },
    KindBatchCompleted {
        kind: Icmpv4ErrorKind,
        accepted: usize,
        rejected: usize,
    },
}

pub trait GeneratedIcmpv4TraceSink {
    fn record_generated_icmpv4(&mut self, event: GeneratedIcmpv4Trace);
}

#[derive(Default)]
pub struct NoGeneratedIcmpv4Trace;

impl GeneratedIcmpv4TraceSink for NoGeneratedIcmpv4Trace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedIcmpv4Report<E> {
    pub action: Icmpv4ErrorAction,
    pub allocation_error: Option<GeneratedAllocationError>,
    pub build_error: Option<Icmpv4ErrorBuildError>,
    pub completion: GeneratedBatchCompletion<E>,
}

pub fn execute_one_icmpv4_time_exceeded<I, T>(
    io: &mut I,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<Option<GeneratedIcmpv4Report<I::Error>>, ExecuteIcmpv4TimeExceededError>
where
    I: GeneratedPacketIo,
    T: GeneratedIcmpv4TraceSink,
{
    execute_one_icmpv4_error(io, runtime, now, trace)
}

pub fn execute_one_icmpv4_error<I, T>(
    io: &mut I,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<Option<GeneratedIcmpv4Report<I::Error>>, ExecuteIcmpv4Error>
where
    I: GeneratedPacketIo,
    T: GeneratedIcmpv4TraceSink,
{
    let Some(queued) = runtime.front() else {
        return Ok(None);
    };
    if !runtime.execution_time_valid(now) {
        let event = match queued.action.kind {
            Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::ClockRegression,
            Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                GeneratedIcmpv4Trace::DestinationUnreachableClockRegression
            }
            Icmpv4ErrorKind::DestinationUnreachableHost => {
                GeneratedIcmpv4Trace::HostUnreachableClockRegression
            }
            Icmpv4ErrorKind::DestinationUnreachablePort => {
                GeneratedIcmpv4Trace::PortUnreachableClockRegression
            }
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded => {
                GeneratedIcmpv4Trace::FragmentationNeededClockRegression
            }
            kind => GeneratedIcmpv4Trace::KindClockRegression { kind },
        };
        trace.record_generated_icmpv4(event);
        return Err(ExecuteIcmpv4TimeExceededError::ClockRegression);
    }
    let mut batch = io.begin_generated(queued.action.egress);
    let (allocation_error, build_error) = match allocate_icmpv4_error(&mut batch, &queued.action) {
        Ok(()) => {
            runtime.committed(queued, now);
            let event = match queued.action.kind {
                Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::TxRequested {
                    egress: queued.action.egress,
                    destination: queued.action.destination_ip,
                },
                Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                    GeneratedIcmpv4Trace::DestinationUnreachableTxRequested {
                        egress: queued.action.egress,
                        destination: queued.action.destination_ip,
                    }
                }
                Icmpv4ErrorKind::DestinationUnreachableHost => {
                    GeneratedIcmpv4Trace::HostUnreachableTxRequested {
                        egress: queued.action.egress,
                        destination: queued.action.destination_ip,
                    }
                }
                Icmpv4ErrorKind::DestinationUnreachablePort => {
                    GeneratedIcmpv4Trace::PortUnreachableTxRequested {
                        egress: queued.action.egress,
                        destination: queued.action.destination_ip,
                    }
                }
                Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded => {
                    GeneratedIcmpv4Trace::FragmentationNeededTxRequested {
                        egress: queued.action.egress,
                        destination: queued.action.destination_ip,
                        next_hop_mtu: queued.action.next_hop_mtu(),
                    }
                }
                kind => GeneratedIcmpv4Trace::KindTxRequested {
                    kind,
                    egress: queued.action.egress,
                    destination: queued.action.destination_ip,
                },
            };
            trace.record_generated_icmpv4(event);
            (None, None)
        }
        Err(GenerationError::Allocation(error)) => {
            let event = match queued.action.kind {
                Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::AllocationFailed(error),
                Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                    GeneratedIcmpv4Trace::DestinationUnreachableAllocationFailed(error)
                }
                Icmpv4ErrorKind::DestinationUnreachableHost => {
                    GeneratedIcmpv4Trace::HostUnreachableAllocationFailed(error)
                }
                Icmpv4ErrorKind::DestinationUnreachablePort => {
                    GeneratedIcmpv4Trace::PortUnreachableAllocationFailed(error)
                }
                Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded => {
                    GeneratedIcmpv4Trace::FragmentationNeededAllocationFailed(error)
                }
                kind => GeneratedIcmpv4Trace::KindAllocationFailed { kind, error },
            };
            trace.record_generated_icmpv4(event);
            (Some(error), None)
        }
        Err(GenerationError::Build(error)) => {
            let event = match queued.action.kind {
                Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::BuildFailed(error),
                Icmpv4ErrorKind::DestinationUnreachableNetwork => {
                    GeneratedIcmpv4Trace::DestinationUnreachableBuildFailed(error)
                }
                Icmpv4ErrorKind::DestinationUnreachableHost => {
                    GeneratedIcmpv4Trace::HostUnreachableBuildFailed(error)
                }
                Icmpv4ErrorKind::DestinationUnreachablePort => {
                    GeneratedIcmpv4Trace::PortUnreachableBuildFailed(error)
                }
                Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded => {
                    GeneratedIcmpv4Trace::FragmentationNeededBuildFailed(error)
                }
                kind => GeneratedIcmpv4Trace::KindBuildFailed { kind, error },
            };
            trace.record_generated_icmpv4(event);
            (None, Some(error))
        }
    };
    let completion = batch.finish();
    let event = match queued.action.kind {
        Icmpv4ErrorKind::TimeExceededTtl => GeneratedIcmpv4Trace::BatchCompleted {
            accepted: completion.accepted,
            rejected: completion.rejected,
        },
        Icmpv4ErrorKind::DestinationUnreachableNetwork => {
            GeneratedIcmpv4Trace::DestinationUnreachableBatchCompleted {
                accepted: completion.accepted,
                rejected: completion.rejected,
            }
        }
        Icmpv4ErrorKind::DestinationUnreachableHost => {
            GeneratedIcmpv4Trace::HostUnreachableBatchCompleted {
                accepted: completion.accepted,
                rejected: completion.rejected,
            }
        }
        Icmpv4ErrorKind::DestinationUnreachablePort => {
            GeneratedIcmpv4Trace::PortUnreachableBatchCompleted {
                accepted: completion.accepted,
                rejected: completion.rejected,
            }
        }
        Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded => {
            GeneratedIcmpv4Trace::FragmentationNeededBatchCompleted {
                accepted: completion.accepted,
                rejected: completion.rejected,
            }
        }
        kind => GeneratedIcmpv4Trace::KindBatchCompleted {
            kind,
            accepted: completion.accepted,
            rejected: completion.rejected,
        },
    };
    trace.record_generated_icmpv4(event);
    Ok(Some(GeneratedIcmpv4Report {
        action: queued.action,
        allocation_error,
        build_error,
        completion,
    }))
}

enum GenerationError {
    Allocation(GeneratedAllocationError),
    Build(Icmpv4ErrorBuildError),
}

fn allocate_icmpv4_error<B: GeneratedPacketBatch>(
    batch: &mut B,
    action: &Icmpv4ErrorAction,
) -> Result<(), GenerationError> {
    let frame_len = action.frame_len();
    let mut lease = batch
        .allocate(frame_len)
        .map_err(GenerationError::Allocation)?;
    if lease.bytes_mut().len() != frame_len {
        lease.cancel();
        return Err(GenerationError::Build(
            Icmpv4TimeExceededBuildError::ExactLengthRequired,
        ));
    }
    build_icmpv4_error(lease.bytes_mut(), action);
    lease.commit();
    Ok(())
}

fn build_icmpv4_error(frame: &mut [u8], action: &Icmpv4ErrorAction) {
    debug_assert_eq!(frame.len(), action.frame_len());
    let quote_len = action.quote_len();
    let ipv4_total_len = 28 + quote_len;
    let icmp_end = 42 + quote_len;
    frame.fill(0);
    frame[0..6].copy_from_slice(&action.destination_mac.0);
    frame[6..12].copy_from_slice(&action.source_mac.0);
    frame[12..14].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = action.outer_tos;
    frame[16..18].copy_from_slice(&(ipv4_total_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = action.outer_ttl;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&action.source_ip.octets());
    frame[30..34].copy_from_slice(&action.destination_ip.octets());
    let header_checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&header_checksum.to_be_bytes());
    frame[34] = action.kind.icmp_type();
    frame[35] = action.kind.icmp_code();
    // Second ICMP header word: the Parameter Problem pointer in its first
    // octet (RFC 792), the Next-Hop MTU in its low-order 16 bits (RFC 1191
    // §4), the whole word the Redirect gateway address (RFC 792), zero
    // otherwise.
    if matches!(action.kind, Icmpv4ErrorKind::RedirectHost) {
        frame[38..42].copy_from_slice(&action.gateway().octets());
    } else {
        frame[38] = action.pointer();
        frame[40..42].copy_from_slice(&action.next_hop_mtu().to_be_bytes());
    }
    frame[42..icmp_end].copy_from_slice(action.quote());
    let icmp_checksum = internet_checksum(&frame[34..icmp_end]);
    frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct RuntimeImage {
        policy: Icmpv4ErrorPolicy,
        states: Vec<Icmpv4ErrorStateSlot>,
        actions: Vec<Icmpv4ErrorActionSlot>,
        head: usize,
        len: usize,
        last_now: Option<MonotonicMillis>,
        runtime_epoch: u128,
        counters: Icmpv4ErrorCounters,
        state_occupancy: OccupancyCounter,
        action_high_water: HighWaterMark,
    }

    fn runtime_image(runtime: &Icmpv4ErrorRuntime<'_>) -> RuntimeImage {
        RuntimeImage {
            policy: runtime.policy,
            states: runtime.states.to_vec(),
            actions: runtime.actions.to_vec(),
            head: runtime.head,
            len: runtime.len,
            last_now: runtime.last_now,
            runtime_epoch: runtime.runtime_epoch,
            counters: runtime.counters,
            state_occupancy: runtime.state_occupancy,
            action_high_water: runtime.action_high_water,
        }
    }

    fn assert_publication_error_is_atomic(
        runtime: &mut Icmpv4ErrorRuntime<'_>,
        expected: Icmpv4ErrorPublicationError,
    ) {
        let before = runtime_image(runtime);
        assert_eq!(runtime.preflight_publication().err(), Some(expected));
        assert_eq!(runtime_image(runtime), before);
    }

    fn action(egress: u16, quote_len: usize) -> Icmpv4TimeExceededAction {
        let original = [0xa5; ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN];
        Icmpv4TimeExceededAction::new(
            IfId(egress),
            MacAddress([2, 0, 0, 0, 0, 1]),
            MacAddress([2, 0, 0, 0, 0, 2]),
            Ipv4Address::from_octets([192, 0, 2, 1]),
            Ipv4Address::from_octets([198, 51, 100, 1]),
            0x2f,
            64,
            &original[..quote_len],
        )
    }

    fn action_kind(kind: Icmpv4ErrorKind, egress: u16, quote_len: usize) -> Icmpv4ErrorAction {
        let original = [0x5a; ICMPV4_ERROR_MAX_QUOTE_LEN];
        Icmpv4ErrorAction::new_with_kind(
            kind,
            IfId(egress),
            MacAddress([2, 0, 0, 0, 0, 1]),
            MacAddress([2, 0, 0, 0, 0, 2]),
            Ipv4Address::from_octets([192, 0, 2, 1]),
            Ipv4Address::from_octets([198, 51, 100, 1]),
            0,
            64,
            &original[..quote_len],
        )
    }

    #[test]
    fn policy_validates_and_defaults_to_ten_per_second() {
        assert_eq!(
            Icmpv4ErrorPolicy::new(0, 100),
            Err(Icmpv4ErrorPolicyError::IntervalZero)
        );
        assert_eq!(
            Icmpv4ErrorPolicy::new(100, 99),
            Err(Icmpv4ErrorPolicyError::StateTtlTooShort)
        );
        assert_eq!(Icmpv4ErrorPolicy::default().interval_ms(), 100);
    }

    #[test]
    fn disabled_kind_is_suppressed_before_clock_limiter_and_queue() {
        let policy = Icmpv4ErrorPolicy::new(100, 1_000)
            .unwrap()
            .with_generation(Icmpv4ErrorKind::TimeExceededTtl, false);
        assert!(!policy.generates(Icmpv4ErrorKind::TimeExceededTtl));
        assert!(policy.generates(Icmpv4ErrorKind::DestinationUnreachableNetwork));
        assert_ne!(policy, Icmpv4ErrorPolicy::new(100, 1_000).unwrap());
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime = Icmpv4ErrorRuntime::new(policy, &mut states, &mut actions);
        let mut before = runtime_image(&runtime);
        assert_eq!(
            runtime.schedule(action(2, 28), MonotonicMillis(50)),
            Icmpv4ErrorDisposition::GenerationDisabled {
                kind: Icmpv4ErrorKind::TimeExceededTtl
            }
        );
        before.counters.disabled_time_exceeded = 1;
        assert_eq!(runtime_image(&runtime), before, "only the counter moves");
        // An earlier timestamp is not a clock regression: the disabled
        // attempt observed no time.
        assert_eq!(
            runtime.schedule(
                action_kind(Icmpv4ErrorKind::DestinationUnreachableNetwork, 2, 28),
                MonotonicMillis(10),
            ),
            Icmpv4ErrorDisposition::DestinationUnreachableQueued {
                egress: IfId(2),
                quote_len: 28
            }
        );
    }

    #[test]
    fn publication_preflight_errors_leave_runtime_exactly_unchanged() {
        let mut states = [];
        let mut actions = [];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.len = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::ActionQueueCapacity,
        );

        let mut states = [];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.head = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::ActionQueueHead,
        );

        let mut states = [];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.len = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::ActionQueueWindow,
        );

        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        assert!(matches!(
            runtime.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        runtime.states[0].action_queued = false;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::QueuedStateMismatch,
        );

        let mut states = [];
        let mut actions = [];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.runtime_epoch = u128::MAX;
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::RuntimeEpochExhausted,
        );
    }

    #[test]
    fn publication_preflight_rejects_duplicate_action_authority() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        assert!(matches!(
            runtime.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        assert!(matches!(
            runtime.schedule(action(2, 20), MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        runtime.actions[1] = runtime.actions[0];
        assert_publication_error_is_atomic(
            &mut runtime,
            Icmpv4ErrorPublicationError::QueuedStateMismatch,
        );
    }

    #[test]
    fn publication_permit_drop_and_commit_cover_wrapped_fifo_and_counter_policy() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(1, 2).unwrap(),
            &mut states,
            &mut actions,
        );
        runtime.schedule(action(1, 20), MonotonicMillis(0));
        runtime.schedule(action(2, 20), MonotonicMillis(0));
        let first = runtime.front().unwrap();
        runtime.committed(first, MonotonicMillis(0));
        runtime.schedule(action(1, 20), MonotonicMillis(1));
        runtime.counters.queued = usize::MAX;

        let before = runtime_image(&runtime);
        let permit = runtime.preflight_publication().unwrap();
        assert_eq!(
            permit.report,
            Icmpv4ErrorPublicationReport {
                states_flushed: 2,
                actions_flushed: 2,
            }
        );
        drop(permit);
        assert_eq!(runtime_image(&runtime), before);

        let counters = runtime.counters;
        let report = runtime.preflight_publication().unwrap().commit();
        assert_eq!(
            report,
            Icmpv4ErrorPublicationReport {
                states_flushed: 2,
                actions_flushed: 2,
            }
        );
        assert!(runtime
            .states
            .iter()
            .all(|slot| *slot == Icmpv4ErrorStateSlot::EMPTY));
        assert!(runtime
            .actions
            .iter()
            .all(|slot| *slot == Icmpv4ErrorActionSlot::EMPTY));
        assert_eq!((runtime.head, runtime.len), (0, 0));
        assert_eq!(runtime.last_now, None);
        assert_eq!(runtime.runtime_epoch, 2);
        assert_eq!(runtime.counters, counters);
    }

    #[test]
    fn publication_zero_capacity_is_total_and_pristine_is_exact() {
        let mut states = [];
        let mut actions = [];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        assert!(runtime.is_pristine());
        assert_eq!(
            runtime.preflight_publication().unwrap().commit(),
            Icmpv4ErrorPublicationReport::default()
        );
        assert!(!runtime.is_pristine());

        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut actions = [];
        let runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        runtime.states[0].egress = IfId(9);
        assert!(!runtime.is_pristine());
    }

    /// NAT44-065: the translated limiter is part of the exact constructor
    /// state (a keyed runtime is pristine too). A publication that installs
    /// the same key keeps the buckets; a new key empties them.
    #[test]
    fn translated_limiter_is_pristine_state_and_follows_the_publication_key() {
        let policy = Icmpv4ErrorPolicy::default()
            .with_translated_limit(1, 1)
            .unwrap();
        let host = Ipv4Address::from_octets([10, 0, 0, 10]);
        let remote = Ipv4Address::from_octets([198, 51, 100, 20]);
        let first = crate::ResolutionHashKey::new(1, 2).unwrap();
        let second = crate::ResolutionHashKey::new(3, 4).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut runtime = Icmpv4ErrorRuntime::new(policy, &mut states, &mut actions)
            .with_translated_limit_key(first);
        assert!(runtime.is_pristine());
        assert!(runtime.admit_translated(host, remote, MonotonicMillis(1_000)));
        assert!(!runtime.is_pristine());
        assert_eq!(runtime.counters(), Icmpv4ErrorCounters::default());
        runtime.preflight_publication().unwrap().commit();
        assert!(!runtime.admit_translated(host, remote, MonotonicMillis(1_999)));
        runtime
            .preflight_publication()
            .unwrap()
            .commit_with_translated_limit_key(first);
        assert!(!runtime.admit_translated(host, remote, MonotonicMillis(1_999)));
        runtime
            .preflight_publication()
            .unwrap()
            .commit_with_translated_limit_key(second);
        assert!(runtime.admit_translated(host, remote, MonotonicMillis(1_999)));
        assert!(!runtime.admit_translated(host, remote, MonotonicMillis(1_999)));
        assert!(runtime.admit_translated(host, remote, MonotonicMillis(2_999)));
    }

    #[test]
    fn translated_limit_policy_bounds_are_exact() {
        use crate::{
            ICMPV4_DEFAULT_TRANSLATED_BURST, ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND,
            ICMPV4_MAX_TRANSLATED_LIMIT,
        };
        let policy = Icmpv4ErrorPolicy::default();
        assert_eq!(
            (
                policy.translated_rate_per_second(),
                policy.translated_burst()
            ),
            (
                ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND,
                ICMPV4_DEFAULT_TRANSLATED_BURST
            )
        );
        assert_eq!(policy, Icmpv4ErrorPolicy::new(100, 60_000).unwrap());
        let max = ICMPV4_MAX_TRANSLATED_LIMIT;
        for (rate, burst) in [(0, 1), (1, 0), (max + 1, 1), (1, max + 1)] {
            assert_eq!(
                policy.with_translated_limit(rate, burst),
                Err(Icmpv4ErrorPolicyError::TranslatedLimitOutOfRange)
            );
        }
        let edge = policy.with_translated_limit(max, 1).unwrap();
        assert_eq!(
            (edge.translated_rate_per_second(), edge.translated_burst()),
            (max, 1)
        );
        assert_eq!(edge.interval_ms(), policy.interval_ms());
    }

    #[test]
    fn action_bounds_quote_and_frame_and_zeroes_unused_storage() {
        let short = action(1, 20);
        assert_eq!(short.quote_len(), 20);
        assert_eq!(short.frame_len(), 62);
        assert!(short.quote[20..].iter().all(|byte| *byte == 0));
        let long = action(1, 548);
        assert_eq!(long.frame_len(), ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN);
        assert_eq!(long.outer_tos, 0xce, "RFC 1812 reserved TOS bit is cleared");
    }

    #[test]
    fn host_unreachable_code_and_maximum_odd_quote_wire_are_exact() {
        let action = action_kind(
            Icmpv4ErrorKind::DestinationUnreachableHost,
            1,
            ICMPV4_ERROR_MAX_QUOTE_LEN,
        );
        let mut frame = [0xa5; ICMPV4_ERROR_MAX_FRAME_LEN];
        build_icmpv4_error(&mut frame, &action);
        assert_eq!(&frame[34..36], &[3, 1]);
        assert_eq!(&frame[38..42], &[0; 4]);
        assert_eq!(
            u16::from_be_bytes([frame[16], frame[17]]),
            576,
            "outer IPv4 remains within the RFC 1812 quote ceiling"
        );
        assert_eq!(ipv4_header_checksum(&frame[14..34]), 0);
        assert_eq!(internet_checksum(&frame[34..]), 0);

        let odd = action_kind(Icmpv4ErrorKind::DestinationUnreachableHost, 1, 21);
        let mut odd_frame = [0; 63];
        build_icmpv4_error(&mut odd_frame, &odd);
        assert_eq!(internet_checksum(&odd_frame[34..63]), 0);
    }

    #[test]
    fn fragmentation_needed_carries_the_next_hop_mtu_and_only_it_does() {
        let action = action_kind(
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded,
            1,
            40,
        )
        .with_next_hop_mtu(1400);
        assert_eq!(action.next_hop_mtu(), 1400);
        let mut frame = [0xa5; 82];
        build_icmpv4_error(&mut frame, &action);
        assert_eq!(&frame[34..36], &[3, 4]);
        // RFC 1191 §4: high-order 16 bits unused (zero), low-order the MTU.
        assert_eq!(&frame[38..42], &[0, 0, 0x05, 0x78]);
        assert_eq!(internet_checksum(&frame[34..]), 0);
        for kind in [
            Icmpv4ErrorKind::TimeExceededTtl,
            Icmpv4ErrorKind::DestinationUnreachableNetwork,
            Icmpv4ErrorKind::DestinationUnreachableHost,
            Icmpv4ErrorKind::DestinationUnreachablePort,
        ] {
            let action = action_kind(kind, 1, 40).with_next_hop_mtu(1400);
            assert_eq!(action.next_hop_mtu(), 0, "{kind:?}");
            build_icmpv4_error(&mut frame, &action);
            assert_eq!(&frame[38..42], &[0; 4], "{kind:?}");
        }
    }

    const ALL_KINDS: [Icmpv4ErrorKind; 10] = [
        Icmpv4ErrorKind::TimeExceededTtl,
        Icmpv4ErrorKind::DestinationUnreachableNetwork,
        Icmpv4ErrorKind::DestinationUnreachableHost,
        Icmpv4ErrorKind::DestinationUnreachablePort,
        Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded,
        Icmpv4ErrorKind::DestinationUnreachableProtocol,
        Icmpv4ErrorKind::DestinationUnreachableLocalPort,
        Icmpv4ErrorKind::ParameterProblem,
        Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited,
        Icmpv4ErrorKind::RedirectHost,
    ];

    #[test]
    fn every_kind_has_its_own_generation_switch() {
        let all_on = Icmpv4ErrorPolicy::default().with_generation(
            Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited,
            true,
        );
        for off in ALL_KINDS {
            let policy = all_on.with_generation(off, false);
            for kind in ALL_KINDS {
                assert_eq!(policy.generates(kind), kind != off, "{off:?} off, {kind:?}");
            }
        }
        let default = Icmpv4ErrorPolicy::default();
        for kind in ALL_KINDS {
            assert_eq!(
                default.generates(kind),
                kind != Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn icmp_err_kinds_have_their_type_code_and_header_word() {
        let mut frame = [0xa5; 82];
        for (kind, type_code) in [
            (Icmpv4ErrorKind::DestinationUnreachableProtocol, [3, 2]),
            (Icmpv4ErrorKind::DestinationUnreachableLocalPort, [3, 3]),
            (Icmpv4ErrorKind::ParameterProblem, [12, 0]),
            (
                Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited,
                [3, 13],
            ),
        ] {
            assert_eq!(kind.limiter_class(), 0, "{kind:?}");
            let action = action_kind(kind, 1, 40)
                .with_pointer(21)
                .with_next_hop_mtu(1400);
            build_icmpv4_error(&mut frame, &action);
            assert_eq!(&frame[34..36], &type_code, "{kind:?}");
            // RFC 792: the Parameter Problem pointer is the first octet of
            // the second word, the rest unused; zero for the others.
            let word = if kind == Icmpv4ErrorKind::ParameterProblem {
                [21, 0, 0, 0]
            } else {
                [0; 4]
            };
            assert_eq!(&frame[38..42], &word, "{kind:?}");
            assert_eq!(action.next_hop_mtu(), 0, "{kind:?}");
            assert_eq!(internet_checksum(&frame[34..]), 0);
        }
        // Only Parameter Problem takes a pointer.
        let mtu = action_kind(
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded,
            1,
            40,
        )
        .with_next_hop_mtu(1400)
        .with_pointer(21);
        assert_eq!((mtu.next_hop_mtu(), mtu.pointer()), (1400, 0));
    }

    /// ICMP-REDIRECT: Redirect for Host is type 5, code 1, limiter class 3,
    /// on by default, and carries the gateway as the whole second word
    /// (RFC 792). No other kind takes a gateway, and the gateway does not
    /// leak into the pointer or Next-Hop MTU.
    #[test]
    fn redirect_has_type_five_code_one_and_the_gateway_word() {
        let kind = Icmpv4ErrorKind::RedirectHost;
        assert_eq!((kind.icmp_type(), kind.icmp_code()), (5, 1));
        assert_eq!(kind.limiter_class(), 3);
        assert!(Icmpv4ErrorPolicy::default().generates(kind));
        let gateway = Ipv4Address::from_octets([192, 0, 2, 254]);
        let action = action_kind(kind, 1, 40)
            .with_gateway(gateway)
            .with_pointer(21)
            .with_next_hop_mtu(1400);
        assert_eq!(action.gateway(), gateway);
        assert_eq!((action.pointer(), action.next_hop_mtu()), (0, 0));
        let mut frame = [0xa5; 82];
        build_icmpv4_error(&mut frame, &action);
        assert_eq!(&frame[34..36], &[5, 1]);
        assert_eq!(&frame[38..42], &[192, 0, 2, 254]);
        assert_eq!(internet_checksum(&frame[34..]), 0);
        for other in ALL_KINDS {
            if other == kind {
                continue;
            }
            let action = action_kind(other, 1, 40).with_gateway(gateway);
            assert_eq!(action.gateway(), Ipv4Address::from_octets([0; 4]));
        }
        let mtu = action_kind(
            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded,
            1,
            40,
        )
        .with_next_hop_mtu(1400)
        .with_gateway(gateway);
        build_icmpv4_error(&mut frame, &mtu);
        assert_eq!(&frame[38..42], &[0, 0, 0x05, 0x78]);
    }

    #[test]
    fn the_action_slot_size_is_unchanged() {
        // ICMP-ERR keeps the pointer in the Next-Hop MTU field, and
        // ICMP-REDIRECT widens that field to the 32-bit gateway inside the
        // padding the slot already had: the slot stays 592 bytes (storage
        // bound, CLI-083/CLI-086).
        assert_eq!(std::mem::size_of::<Icmpv4ErrorActionSlot>(), 592);
        assert_eq!(std::mem::size_of::<Icmpv4ErrorAction>(), 580);
    }

    #[test]
    fn fit_egress_mtu_cuts_and_zeroes_the_quote_only_when_needed() {
        // An option-free quoted IPv4 header (IHL 5).
        let quoted = |len: usize, first: u8| {
            let mut original = [0x5a; ICMPV4_ERROR_MAX_QUOTE_LEN];
            original[0] = first;
            Icmpv4ErrorAction::new_with_kind(
                Icmpv4ErrorKind::TimeExceededTtl,
                IfId(1),
                MacAddress([2, 0, 0, 0, 0, 1]),
                MacAddress([2, 0, 0, 0, 0, 2]),
                Ipv4Address::from_octets([192, 0, 2, 1]),
                Ipv4Address::from_octets([198, 51, 100, 1]),
                0,
                64,
                &original[..len],
            )
        };
        let full = quoted(ICMPV4_ERROR_MAX_QUOTE_LEN, 0x45);
        assert_eq!(full.fit_egress_mtu(576), full);
        assert_eq!(full.fit_egress_mtu(1500), full);
        let cut = full.fit_egress_mtu(575);
        assert_eq!(cut.quote_len(), 547);
        assert_eq!(cut.frame_len(), 14 + 575);
        let minimal = full.fit_egress_mtu(crate::IPV4_MIN_MTU);
        assert_eq!(minimal.quote_len(), 40);
        assert!(!minimal.quote_below_minimum());
        assert_eq!(minimal, quoted(40, 0x45));
        let short = quoted(28, 0x45);
        assert_eq!(short.fit_egress_mtu(crate::IPV4_MIN_MTU), short);

        // RFC 792 minimum: the header with its options and 8 data bytes.
        // IHL 8 (32-byte header) needs 40: exactly fits MTU 68.
        let options = quoted(ICMPV4_ERROR_MAX_QUOTE_LEN, 0x48);
        assert!(!options.fit_egress_mtu(68).quote_below_minimum());
        // IHL 9 needs 44: below the room of MTU 68 (40), fits MTU 72.
        let options = quoted(ICMPV4_ERROR_MAX_QUOTE_LEN, 0x49);
        assert!(options.fit_egress_mtu(71).quote_below_minimum());
        assert!(!options.fit_egress_mtu(72).quote_below_minimum());
        // A datagram shorter than IHL * 4 + 8 needs only itself.
        let tiny = quoted(30, 0x4f);
        assert!(!tiny.fit_egress_mtu(68).quote_below_minimum());

        // The runtime suppresses a marked action before clock and limiter.
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut actions);
        assert_eq!(
            runtime.schedule(options.fit_egress_mtu(68), MonotonicMillis(5)),
            Icmpv4ErrorDisposition::QuoteBelowMinimum { egress: IfId(1) }
        );
        assert_eq!(runtime.counters().quote_below_minimum, 1);
        assert_eq!(runtime.pending_actions(), 0);
        assert_eq!(runtime.last_now, None);
    }

    #[test]
    fn limiter_is_per_egress_and_exact_boundary_is_allowed() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(100, 1_000).unwrap(),
            &mut states,
            &mut slots,
        );
        assert!(matches!(
            runtime.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
        assert_eq!(
            runtime.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::Pending { egress: IfId(1) }
        );
        assert!(matches!(
            runtime.schedule(action(2, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
        let first = runtime.front().unwrap();
        runtime.committed(first, MonotonicMillis(0));
        assert_eq!(
            runtime.schedule(action(1, 20), MonotonicMillis(99)),
            Icmpv4TimeExceededDisposition::RateLimited { egress: IfId(1) }
        );
        assert!(matches!(
            runtime.schedule(action(1, 20), MonotonicMillis(100)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
    }

    /// A discarded error frees its egress for the next one, and the runtime still
    /// moves to a new publication.
    #[test]
    fn a_discarded_error_does_not_keep_its_egress_waiting() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(100, 1_000).unwrap(),
            &mut states,
            &mut slots,
        );
        let time = action_kind(Icmpv4ErrorKind::TimeExceededTtl, 1, 20);
        assert!(matches!(
            runtime.schedule(time, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        assert!(runtime.discard_front());
        assert!(!runtime.discard_front());
        assert!(matches!(
            runtime.schedule(time, MonotonicMillis(1)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        assert!(runtime.discard_front());
        assert!(runtime.preflight_publication().is_ok());
    }

    #[test]
    fn mixed_kinds_share_fifo_pending_and_exact_rate_boundary() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(100, 1_000).unwrap(),
            &mut states,
            &mut slots,
        );
        let time = action_kind(Icmpv4ErrorKind::TimeExceededTtl, 1, 20);
        let unreachable = action_kind(Icmpv4ErrorKind::DestinationUnreachableNetwork, 1, 21);
        assert!(matches!(
            runtime.schedule(time, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        assert_eq!(
            runtime.schedule(unreachable, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Pending { egress: IfId(1) }
        );
        let queued = runtime.front().unwrap();
        assert_eq!(queued.action.kind, Icmpv4ErrorKind::TimeExceededTtl);
        runtime.committed(queued, MonotonicMillis(0));
        assert_eq!(
            runtime.schedule(unreachable, MonotonicMillis(99)),
            Icmpv4ErrorDisposition::RateLimited { egress: IfId(1) }
        );
        assert!(matches!(
            runtime.schedule(unreachable, MonotonicMillis(100)),
            Icmpv4ErrorDisposition::DestinationUnreachableQueued { .. }
        ));
        let queued = runtime.front().unwrap();
        assert_eq!(
            queued.action.kind,
            Icmpv4ErrorKind::DestinationUnreachableNetwork
        );
        runtime.committed(queued, MonotonicMillis(100));
        assert_eq!(
            runtime.counters(),
            Icmpv4ErrorCounters {
                queued: 2,
                queued_time_exceeded: 1,
                queued_destination_unreachable: 1,
                pending: 1,
                rate_limited: 1,
                dequeued: 2,
                dequeued_time_exceeded: 1,
                dequeued_destination_unreachable: 1,
                ..Icmpv4ErrorCounters::default()
            }
        );
    }

    /// Port Unreachable (RFC 5382 REQ-4) has its own limiter class per
    /// egress with its own interval: a burst of it is neither held back by
    /// nor holds back Time Exceeded or another Destination Unreachable on
    /// the same egress, and it is limited to one per
    /// `port_unreachable_interval_ms`.
    #[test]
    fn port_unreachable_has_its_own_limiter_class_per_egress() {
        assert_eq!(
            Icmpv4ErrorPolicy::default().port_unreachable_interval_ms(),
            ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS
        );
        assert_eq!(
            Icmpv4ErrorPolicy::default().with_port_unreachable_interval_ms(0),
            Err(Icmpv4ErrorPolicyError::IntervalZero)
        );
        let policy = Icmpv4ErrorPolicy::new(100, 1_000)
            .unwrap()
            .with_port_unreachable_interval_ms(500)
            .unwrap();
        assert_ne!(policy, Icmpv4ErrorPolicy::new(100, 1_000).unwrap());
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 3];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 4];
        let mut runtime = Icmpv4ErrorRuntime::new(policy, &mut states, &mut slots);
        let port = action_kind(Icmpv4ErrorKind::DestinationUnreachablePort, 1, 40);
        let time = action_kind(Icmpv4ErrorKind::TimeExceededTtl, 1, 20);
        assert!(matches!(
            runtime.schedule(port, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::PortUnreachableQueued { .. }
        ));
        // A queued Port Unreachable does not make other kinds pending.
        assert!(matches!(
            runtime.schedule(time, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        assert_eq!(
            runtime.schedule(port, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::Pending { egress: IfId(1) }
        );
        assert_eq!(runtime.occupied_prefix, 2, "one state per egress and class");
        for _ in 0..2 {
            let queued = runtime.front().unwrap();
            runtime.committed(queued, MonotonicMillis(0));
        }
        // Each class runs its own interval from its own last error.
        assert!(matches!(
            runtime.schedule(time, MonotonicMillis(100)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        let queued = runtime.front().unwrap();
        runtime.committed(queued, MonotonicMillis(100));
        assert_eq!(
            runtime.schedule(port, MonotonicMillis(150)),
            Icmpv4ErrorDisposition::RateLimited { egress: IfId(1) }
        );
        assert!(matches!(
            runtime.schedule(time, MonotonicMillis(200)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
        let queued = runtime.front().unwrap();
        runtime.committed(queued, MonotonicMillis(200));
        assert_eq!(
            runtime.schedule(port, MonotonicMillis(499)),
            Icmpv4ErrorDisposition::RateLimited { egress: IfId(1) }
        );
        assert!(matches!(
            runtime.schedule(port, MonotonicMillis(500)),
            Icmpv4ErrorDisposition::PortUnreachableQueued { .. }
        ));
        let queued = runtime.front().unwrap();
        runtime.committed(queued, MonotonicMillis(500));
        assert!(runtime.preflight_publication().is_ok());
    }

    /// An idle state is reclaimed only after both its TTL and its class
    /// interval, so a Port Unreachable interval longer than the state TTL is
    /// never cut short by reclaiming its state.
    #[test]
    fn reclaiming_a_state_never_shortens_its_class_interval() {
        let policy = Icmpv4ErrorPolicy::new(100, 1_000)
            .unwrap()
            .with_port_unreachable_interval_ms(5_000)
            .unwrap();
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut runtime = Icmpv4ErrorRuntime::new(policy, &mut states, &mut slots);
        let port = action_kind(Icmpv4ErrorKind::DestinationUnreachablePort, 1, 40);
        let other_egress = action_kind(Icmpv4ErrorKind::TimeExceededTtl, 2, 20);
        assert!(matches!(
            runtime.schedule(port, MonotonicMillis(0)),
            Icmpv4ErrorDisposition::PortUnreachableQueued { .. }
        ));
        let queued = runtime.front().unwrap();
        runtime.committed(queued, MonotonicMillis(0));
        // Past the state TTL but within the class interval: not reclaimed.
        assert_eq!(
            runtime.schedule(other_egress, MonotonicMillis(4_999)),
            Icmpv4ErrorDisposition::StateFull
        );
        assert!(matches!(
            runtime.schedule(other_egress, MonotonicMillis(5_000)),
            Icmpv4ErrorDisposition::Queued { .. }
        ));
    }

    #[test]
    fn mixed_kind_fifo_is_ordered_across_egresses_and_clock_failure_is_atomic() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut slots);
        let time = action_kind(Icmpv4ErrorKind::TimeExceededTtl, 1, 20);
        let unreachable = action_kind(Icmpv4ErrorKind::DestinationUnreachableNetwork, 2, 20);
        runtime.schedule(time, MonotonicMillis(10));
        runtime.schedule(unreachable, MonotonicMillis(10));
        assert_eq!(runtime.pending_actions(), 2);
        let first = runtime.front().unwrap();
        assert_eq!(first.action.kind, Icmpv4ErrorKind::TimeExceededTtl);
        runtime.committed(first, MonotonicMillis(10));
        let second = runtime.front().unwrap();
        assert_eq!(
            second.action.kind,
            Icmpv4ErrorKind::DestinationUnreachableNetwork
        );
        assert_eq!(
            runtime.schedule(time, MonotonicMillis(9)),
            Icmpv4ErrorDisposition::ClockRegression
        );
        assert_eq!(runtime.front(), Some(second));
        assert_eq!(runtime.pending_actions(), 1);
    }

    #[test]
    fn zero_capacity_and_clock_regression_do_not_create_phantom_actions() {
        let mut states = [];
        let mut slots = [];
        let mut runtime =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut slots);
        assert_eq!(
            runtime.schedule(action(1, 20), MonotonicMillis(10)),
            Icmpv4TimeExceededDisposition::StateFull
        );
        assert_eq!(
            runtime.schedule(action(1, 20), MonotonicMillis(9)),
            Icmpv4TimeExceededDisposition::ClockRegression
        );
        assert_eq!(runtime.pending_actions(), 0);
    }

    #[test]
    fn action_and_state_full_are_atomic_and_runtime_recreation_clears_storage() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut no_actions = [];
        let mut action_full =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut no_actions);
        assert_eq!(
            action_full.schedule(action(1, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::ActionFull
        );
        assert_eq!(action_full.pending_actions(), 0);

        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        {
            let mut runtime =
                Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut slots);
            runtime.schedule(action(1, 20), MonotonicMillis(0));
            assert_eq!(
                runtime.schedule(action(2, 20), MonotonicMillis(0)),
                Icmpv4TimeExceededDisposition::StateFull
            );
            assert_eq!(runtime.pending_actions(), 1);
        }
        let recreated =
            Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut states, &mut slots);
        assert_eq!(recreated.pending_actions(), 0);
    }

    #[test]
    fn wrapped_fifo_reuses_only_expired_idle_state() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(1, 2).unwrap(),
            &mut states,
            &mut slots,
        );
        runtime.schedule(action(1, 20), MonotonicMillis(0));
        runtime.schedule(action(2, 20), MonotonicMillis(0));
        let first = runtime.front().unwrap();
        runtime.committed(first, MonotonicMillis(0));
        runtime.schedule(action(1, 20), MonotonicMillis(1));
        let second = runtime.front().unwrap();
        assert_eq!(second.action.egress, IfId(2));
        runtime.committed(second, MonotonicMillis(1));
        let third = runtime.front().unwrap();
        assert_eq!(third.action.egress, IfId(1));
        runtime.committed(third, MonotonicMillis(1));
        assert!(matches!(
            runtime.schedule(action(3, 20), MonotonicMillis(3)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
    }

    /// `(occupied, high_water, capacity)`, checked against a full scan.
    fn exact_state_occupancy(runtime: &Icmpv4ErrorRuntime<'_>) -> (usize, usize, usize) {
        let occupancy = runtime.state_occupancy();
        let scanned = runtime.states.iter().filter(|state| state.occupied).count();
        assert_eq!(occupancy.occupied(), scanned);
        (
            occupancy.occupied(),
            occupancy.high_water(),
            occupancy.capacity(),
        )
    }

    #[test]
    fn limiter_state_occupancy_is_exact_across_insert_reuse_and_flush() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 4];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(1, 2).unwrap(),
            &mut states,
            &mut slots,
        );
        assert_eq!(exact_state_occupancy(&runtime), (0, 0, 2));
        // Insert one state per egress.
        runtime.schedule(action(1, 20), MonotonicMillis(0));
        assert_eq!(exact_state_occupancy(&runtime), (1, 1, 2));
        runtime.schedule(action(2, 20), MonotonicMillis(0));
        assert_eq!(exact_state_occupancy(&runtime), (2, 2, 2));
        for _ in 0..2 {
            let front = runtime.front().unwrap();
            runtime.committed(front, MonotonicMillis(0));
        }
        // An existing egress state is reused; a third egress finds no
        // reclaimable state and is refused without a count change.
        runtime.schedule(action(1, 20), MonotonicMillis(1));
        assert!(matches!(
            runtime.schedule(action(3, 20), MonotonicMillis(1)),
            Icmpv4TimeExceededDisposition::StateFull
        ));
        assert_eq!(exact_state_occupancy(&runtime), (2, 2, 2));
        let front = runtime.front().unwrap();
        runtime.committed(front, MonotonicMillis(1));
        // Expiry is lazy: egress 2's idle state passed its TTL at 2 and stays
        // counted until egress 3 reclaims it in place.
        assert_eq!(exact_state_occupancy(&runtime), (2, 2, 2));
        assert!(matches!(
            runtime.schedule(action(3, 20), MonotonicMillis(3)),
            Icmpv4TimeExceededDisposition::Queued { .. }
        ));
        assert_eq!(exact_state_occupancy(&runtime), (2, 2, 2));
        // A dropped permit changes nothing; a committed flush resets the
        // count and the high-water mark.
        drop(runtime.preflight_publication().unwrap());
        assert_eq!(exact_state_occupancy(&runtime), (2, 2, 2));
        runtime.preflight_publication().unwrap().commit();
        assert_eq!(exact_state_occupancy(&runtime), (0, 0, 2));
        runtime.schedule(action(2, 20), MonotonicMillis(0));
        assert_eq!(exact_state_occupancy(&runtime), (1, 1, 2));
    }

    fn action_queue(runtime: &Icmpv4ErrorRuntime<'_>) -> (usize, usize, usize) {
        let occupancy = runtime.action_occupancy();
        assert_eq!(occupancy.occupied(), runtime.pending_actions());
        (
            occupancy.occupied(),
            occupancy.high_water(),
            occupancy.capacity(),
        )
    }

    /// OBS-017: the action queue's high-water mark follows enqueues, stays
    /// through dequeues and a refused enqueue, and restarts at a commit.
    #[test]
    fn action_queue_high_water_survives_dequeue_and_restarts_at_commit() {
        let mut states = [Icmpv4ErrorStateSlot::EMPTY; 4];
        let mut slots = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut runtime = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::new(1, 2).unwrap(),
            &mut states,
            &mut slots,
        );
        assert_eq!(action_queue(&runtime), (0, 0, 2));
        runtime.schedule(action(1, 20), MonotonicMillis(0));
        runtime.schedule(action(2, 20), MonotonicMillis(0));
        assert_eq!(action_queue(&runtime), (2, 2, 2));
        assert!(matches!(
            runtime.schedule(action(3, 20), MonotonicMillis(0)),
            Icmpv4TimeExceededDisposition::ActionFull
        ));
        assert_eq!(action_queue(&runtime), (2, 2, 2));
        let front = runtime.front().unwrap();
        runtime.committed(front, MonotonicMillis(0));
        assert_eq!(action_queue(&runtime), (1, 2, 2));
        drop(runtime.preflight_publication().unwrap());
        assert_eq!(action_queue(&runtime), (1, 2, 2), "a dropped permit");
        runtime.preflight_publication().unwrap().commit();
        assert_eq!(action_queue(&runtime), (0, 0, 2));
        runtime.schedule(action(2, 20), MonotonicMillis(0));
        assert_eq!(action_queue(&runtime), (1, 1, 2));
    }

    /// H4b: occupied limiter states stay a prefix of the table, so a new
    /// egress reads only the occupied states (at most one per egress
    /// interface), however large the capacity is; a broken prefix is
    /// refused by the publication preflight.
    #[test]
    fn occupied_states_are_a_prefix_and_searches_stay_inside_it() {
        let policy = Icmpv4ErrorPolicy::new(1, 2).unwrap();
        let mut states = vec![Icmpv4ErrorStateSlot::EMPTY; 1 << 16];
        let mut actions = [Icmpv4ErrorActionSlot::EMPTY; 8];
        let mut runtime = Icmpv4ErrorRuntime::new(policy, &mut states, &mut actions);
        for egress in 1..=3 {
            runtime.schedule(action(egress, 20), MonotonicMillis(0));
            assert_eq!(runtime.occupied_prefix, usize::from(egress));
        }
        // An existing egress and a reclaim reuse the prefix in place.
        while let Some(front) = runtime.front() {
            runtime.committed(front, MonotonicMillis(0));
        }
        runtime.schedule(action(2, 20), MonotonicMillis(5));
        runtime.schedule(action(9, 20), MonotonicMillis(5));
        assert_eq!(runtime.occupied_prefix, 3);
        assert!(runtime.states[..3].iter().all(|state| state.occupied));
        assert!(runtime.states[3..].iter().all(|state| !state.occupied));
        assert!(runtime.preflight_publication().is_ok());
        runtime.states[7].occupied = true;
        assert_eq!(
            runtime.preflight_publication().err(),
            Some(Icmpv4ErrorPublicationError::OccupiedPrefix)
        );
        runtime.states[7].occupied = false;
        runtime.preflight_publication().unwrap().commit();
        assert_eq!(runtime.occupied_prefix, 0);
        assert!(runtime.states.iter().all(|state| !state.occupied));
    }
}

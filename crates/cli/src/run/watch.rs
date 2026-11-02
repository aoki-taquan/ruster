//! Cold-path health and link watch of `ruster run` (OBS-018, M2 S10b).
//!
//! Between ticks, at most every [`HEALTH_INTERVAL_MS`], the loop samples
//! each port's backend counters ([`PortSample`]), and at most every
//! [`LINK_INTERVAL_MS`] it queries each port's link over rtnetlink
//! ([`super::netlink::LinkProbe`]). Both are pure decisions over those
//! samples here, so every threshold is tested without a kernel. Nothing in
//! this module allocates: per-port state is fixed at startup, and events
//! are handed to a callback (which formats a line only when something
//! happened).
//!
//! # Health conditions (per port)
//!
//! | condition | detected when | warning after | fatal after |
//! |---|---|---|---|
//! | `TX_STALL` | TX is in flight and the oldest in-flight frame stays the same (no completion of it), while the link is up | [`Thresholds::tx_stall_warn_ms`] (default 1 s) | [`Thresholds::tx_stall_fatal_ms`] (default 10 s, `None`: never) |
//! | `FILL_STARVED` | Fill holds no frame in the kernel, no RX arrived, and the engine found its free list empty (`fill_starved` grew) since the last sample | [`FILL_STARVED_WARN_MS`] | never (a symptom; the frames are held by TX, which `TX_STALL` covers) |
//! | `KICK_ERRORS` | `kick_errors` (kick failures other than `ENETDOWN`) grew in every sample | first growth | [`Thresholds::kick_errors_fatal_ms`] (default 5 s, `None`: never) of growth in every sample |
//!
//! The thresholds come from `--tx-stall-warn-secs`, `--tx-stall-fatal-secs`,
//! and `--kick-errors-fatal-secs` (0 disables a fatal exit). A TX stall can
//! be caused from the wire (802.3x PAUSE frames from an on-segment host
//! stop a NIC's TX), so its fatal exit is a denial-of-service lever; it
//! stays on by default because the router fails closed (startup refuses
//! kernel forwarding and kernel L3 on the ports, so nothing is forwarded
//! while it is down, and a supervisor restarts it), and an operator who
//! prefers availability over a restart can turn it into a warning.
//!
//! A busy healthy link never trips them: completions retire the oldest
//! frame (a new oldest, or none, every sample), RX keeps arriving, and
//! kicks succeed. A link that is down (rtnetlink, or the adapter's last
//! kick saw `ENETDOWN`) holds its TX by design, so `TX_STALL` is not timed
//! while it is down.
//!
//! # Link and device events (per port)
//!
//! | event | outcome |
//! |---|---|
//! | the interface index is gone (`ENODEV`) | fatal `DEVICE_REMOVED` |
//! | MTU below the startup MTU (TX is bounded by the startup MTU, so longer frames than the device now carries could be published and stranded) | fatal `MTU_DECREASED` |
//! | MTU above what a UMEM frame holds ([`super::checks::mtu_limit`]) | fatal `MTU_ABOVE_FRAME` |
//! | MTU raised within the frame bound | warning `MTU_RAISED` (TX stays bounded by the startup MTU until a restart); recovered when it returns |
//! | link down (`IFF_UP` or `IFF_LOWER_UP` clear) | warning `LINK_DOWN`, counted; the router keeps running and owed TX kicks resume when the link returns (recovered `LINK_DOWN`) |
//! | the link query fails | warning `LINK_PROBE`; fatal `LINK_UNVERIFIABLE` after [`LINK_PROBE_FAILURES_FATAL`] failures in a row |
//! | a kernel IPv4 address appears on the port (rtnetlink `RTM_GETADDR`, same round) | fatal `KERNEL_IPV4_ADDRESSES`, as the startup check refuses it; a failed address dump counts as a failed query |
//! | `net.ipv4.ip_forward` or `conf/<dev>/forwarding` turns on (procfs, same round) | fatal `KERNEL_FORWARDING_ENABLED`, as at startup; with `--allow-kernel-forwarding` a warning `KERNEL_FORWARDING` |
//! | a forwarding sysctl is unreadable | a failed query (fatal after [`LINK_PROBE_FAILURES_FATAL`] in a row); with the override a warning |
//!
//! The link query, the address dump, and the forwarding read each count
//! their own consecutive failures, so one query that succeeds every round
//! cannot keep another that fails every round from becoming fatal.
//!
//! A fatal event ends the run loop; the shutdown then drains, detaches,
//! closes, and exits 1 (no silent continuation).

use std::fmt;

use ruster_core::{FieldValue, FieldVisitor, IfId, MonotonicMillis, ObservableFields};

use super::checks::mtu_limit;
use super::netlink::{LinkFacts, NetlinkError};

/// Minimum interval between backend health samples.
pub const HEALTH_INTERVAL_MS: u64 = 500;
/// Minimum interval between rtnetlink link queries.
pub const LINK_INTERVAL_MS: u64 = 1_000;
/// Fill starved this long: warning.
pub const FILL_STARVED_WARN_MS: u64 = 1_000;

/// Operator-set health thresholds (milliseconds).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Thresholds {
    /// The oldest in-flight frame unchanged this long: warning.
    pub tx_stall_warn_ms: u64,
    /// ... this long: fatal; `None` never (warn only).
    pub tx_stall_fatal_ms: Option<u64>,
    /// Kick errors in every sample this long: fatal; `None` never.
    pub kick_errors_fatal_ms: Option<u64>,
}

impl Default for Thresholds {
    /// 1 s warning, 10 s fatal TX stall; 5 s fatal kick errors.
    fn default() -> Self {
        Self {
            tx_stall_warn_ms: 1_000,
            tx_stall_fatal_ms: Some(10_000),
            kick_errors_fatal_ms: Some(5_000),
        }
    }
}

impl Thresholds {
    /// From whole seconds, 0 fatal meaning never.
    pub fn from_secs(warn: u64, fatal: u64, kicks: u64) -> Self {
        let ms = |secs: u64| secs.saturating_mul(1_000);
        Self {
            tx_stall_warn_ms: ms(warn),
            tx_stall_fatal_ms: (fatal != 0).then(|| ms(fatal)),
            kick_errors_fatal_ms: (kicks != 0).then(|| ms(kicks)),
        }
    }
}
/// Link queries failing in a row before the link counts as unverifiable.
pub const LINK_PROBE_FAILURES_FATAL: u32 = 3;

/// One port's backend counters at one instant (cold path).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortSample {
    pub interface: IfId,
    /// Engine polls so far.
    pub polls: u64,
    /// TX frames published and not completed.
    pub tx_inflight: u64,
    /// Polls since the oldest in-flight frame was submitted (0 with
    /// nothing in flight).
    pub oldest_age_polls: u64,
    /// Kick failures other than `ENETDOWN` so far.
    pub kick_errors: u64,
    /// The last TX kick saw `ENETDOWN`.
    pub kick_link_down: bool,
    /// Refills that found the free list empty so far.
    pub fill_starved: u64,
    /// Fill entries the kernel holds right now.
    pub fill_ring_occupancy: u64,
    /// Valid RX frames so far.
    pub rx_packets: u64,
}

/// The queries of one link round, each with its own failure count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Query {
    Link = 0,
    Addresses = 1,
    Forwarding = 2,
}

impl Query {
    const COUNT: usize = 3;
}

/// The two kernel IPv4 forwarding sysctls of one port.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Forwarding {
    /// `net.ipv4.ip_forward`.
    pub global: bool,
    /// `net.ipv4.conf.<dev>.forwarding`.
    pub device: bool,
}

/// What the link watch checks one port against (fixed at startup).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkTarget {
    pub interface: IfId,
    pub ifindex: u32,
    /// The MTU at startup, which bounds the adapter's TX.
    pub mtu: u32,
    /// The longest frame a UMEM frame holds.
    pub frame_capacity: u32,
}

/// A non-fatal condition (warning and recovery lines).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Condition {
    TxStall,
    FillStarved,
    KickErrors,
    LinkDown,
    MtuRaised,
    LinkProbe,
    /// Kernel IPv4 forwarding is on (or unreadable) under
    /// `--allow-kernel-forwarding`.
    KernelForwarding,
}

impl Condition {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TxStall => "TX_STALL",
            Self::FillStarved => "FILL_STARVED",
            Self::KickErrors => "KICK_ERRORS",
            Self::LinkDown => "LINK_DOWN",
            Self::MtuRaised => "MTU_RAISED",
            Self::LinkProbe => "LINK_PROBE",
            Self::KernelForwarding => "KERNEL_FORWARDING",
        }
    }
}

/// Why the watch ends the run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fatal {
    TxStall,
    KickErrors,
    DeviceRemoved,
    MtuDecreased,
    MtuAboveFrame,
    LinkUnverifiable,
    KernelIpv4Addresses,
    KernelForwardingEnabled,
}

impl Fatal {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TxStall => "TX_STALL",
            Self::KickErrors => "KICK_ERRORS",
            Self::DeviceRemoved => "DEVICE_REMOVED",
            Self::MtuDecreased => "MTU_DECREASED",
            Self::MtuAboveFrame => "MTU_ABOVE_FRAME",
            Self::LinkUnverifiable => "LINK_UNVERIFIABLE",
            Self::KernelIpv4Addresses => "KERNEL_IPV4_ADDRESSES",
            Self::KernelForwardingEnabled => "KERNEL_FORWARDING_ENABLED",
        }
    }
}

/// One watch event of one port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchEvent {
    Warning { port: IfId, condition: Condition },
    Recovered { port: IfId, condition: Condition },
    Fatal { port: IfId, cause: Fatal },
}

impl fmt::Display for WatchEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning { port, condition } => write!(
                formatter,
                "warning: port=if{} health={}",
                port.0,
                condition.code()
            ),
            Self::Recovered { port, condition } => write!(
                formatter,
                "recovered: port=if{} health={}",
                port.0,
                condition.code()
            ),
            Self::Fatal { port, cause } => write!(
                formatter,
                "fatal: port=if{} health={}",
                port.0,
                cause.code()
            ),
        }
    }
}

/// A timed condition: when it started and whether its warning was given.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Timed {
    since: Option<MonotonicMillis>,
    warned: bool,
}

impl Timed {
    /// Advances the condition; returns the elapsed time while it holds.
    fn hold(&mut self, now: MonotonicMillis) -> u64 {
        let since = *self.since.get_or_insert(now);
        now.0.saturating_sub(since.0)
    }

    /// Clears the condition; returns whether a warning was given.
    fn clear(&mut self) -> bool {
        self.since = None;
        std::mem::take(&mut self.warned)
    }
}

/// Watch state of one port.
#[derive(Clone, Copy, Debug)]
struct PortWatch {
    target: LinkTarget,
    last: Option<PortSample>,
    /// The submit poll of the oldest in-flight frame last seen.
    oldest_stamp: Option<u64>,
    stall: Timed,
    starved: Timed,
    kicks: Timed,
    link_up: bool,
    mtu: u32,
    mtu_warned: bool,
    /// Consecutive failures per [`Query`] kind.
    probe_failures: [u32; Query::COUNT],
    probe_warned: bool,
    forwarding_warned: bool,
    counters: PortHealth,
}

/// Cold-path health fields of one port (`if<id>.watch.*`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PortHealth {
    pub tx_stall: bool,
    /// How long the oldest in-flight frame has been unchanged.
    pub tx_stall_ms: u64,
    pub fill_starved: bool,
    pub kick_errors_persistent: bool,
    pub link_up: bool,
    pub link_down_events: u64,
    pub link_up_events: u64,
    pub mtu: u32,
    pub link_probe_errors: u64,
    /// Kernel IPv4 addresses seen on the port by the last nonzero dump.
    pub kernel_ipv4_addresses: u32,
    /// A kernel forwarding sysctl read 1 in the last round.
    pub kernel_forwarding: bool,
    pub warnings: u64,
}

impl ObservableFields for PortHealth {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "watch";
        visitor.field(SECTION, "tx_stall", FieldValue::Flag(self.tx_stall));
        visitor.field(SECTION, "tx_stall_ms", FieldValue::Count(self.tx_stall_ms));
        visitor.field(SECTION, "fill_starved", FieldValue::Flag(self.fill_starved));
        visitor.field(
            SECTION,
            "kick_errors_persistent",
            FieldValue::Flag(self.kick_errors_persistent),
        );
        visitor.field(SECTION, "link_up", FieldValue::Flag(self.link_up));
        visitor.field(
            SECTION,
            "link_down_events",
            FieldValue::Count(self.link_down_events),
        );
        visitor.field(
            SECTION,
            "link_up_events",
            FieldValue::Count(self.link_up_events),
        );
        visitor.field(SECTION, "mtu", FieldValue::Count(u64::from(self.mtu)));
        visitor.field(
            SECTION,
            "link_probe_errors",
            FieldValue::Count(self.link_probe_errors),
        );
        visitor.field(
            SECTION,
            "kernel_ipv4_addresses",
            FieldValue::Count(u64::from(self.kernel_ipv4_addresses)),
        );
        visitor.field(
            SECTION,
            "kernel_forwarding",
            FieldValue::Flag(self.kernel_forwarding),
        );
        visitor.field(SECTION, "warnings", FieldValue::Count(self.warnings));
    }
}

/// Health and link watch of every port, in `IfId` order.
pub struct Watch {
    ports: Box<[PortWatch]>,
    thresholds: Thresholds,
    /// `--allow-kernel-forwarding`: forwarding at run time only warns.
    allow_kernel_forwarding: bool,
    last_health: Option<MonotonicMillis>,
    last_link: Option<MonotonicMillis>,
}

impl Watch {
    /// One allocation of the port state (cold).
    pub fn new(targets: &[LinkTarget], thresholds: Thresholds) -> Self {
        Self {
            ports: targets
                .iter()
                .map(|target| PortWatch {
                    target: *target,
                    last: None,
                    oldest_stamp: None,
                    stall: Timed::default(),
                    starved: Timed::default(),
                    kicks: Timed::default(),
                    link_up: true,
                    mtu: target.mtu,
                    mtu_warned: false,
                    probe_failures: [0; Query::COUNT],
                    probe_warned: false,
                    forwarding_warned: false,
                    counters: PortHealth {
                        link_up: true,
                        mtu: target.mtu,
                        ..PortHealth::default()
                    },
                })
                .collect(),
            thresholds,
            allow_kernel_forwarding: false,
            last_health: None,
            last_link: None,
        }
    }

    /// Kernel forwarding found at run time warns instead of being fatal
    /// (`--allow-kernel-forwarding`).
    #[must_use]
    pub const fn allowing_kernel_forwarding(mut self, allowed: bool) -> Self {
        self.allow_kernel_forwarding = allowed;
        self
    }

    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// The link target of port `index`, in `IfId` order.
    pub fn target(&self, index: usize) -> Option<LinkTarget> {
        self.ports.get(index).map(|port| port.target)
    }

    /// Whether a health sample is due at `now` (and marks it taken).
    pub fn health_due(&mut self, now: MonotonicMillis, interval_ms: u64) -> bool {
        due(&mut self.last_health, now, interval_ms)
    }

    /// Whether a link query round is due at `now` (and marks it taken).
    pub fn link_due(&mut self, now: MonotonicMillis, interval_ms: u64) -> bool {
        due(&mut self.last_link, now, interval_ms)
    }

    /// Whether any port currently has a warning condition.
    pub fn warning(&self) -> bool {
        self.ports.iter().any(|port| {
            port.stall.warned
                || port.starved.warned
                || port.kicks.warned
                || !port.link_up
                || port.mtu_warned
                || port.probe_warned
                || port.forwarding_warned
        })
    }

    /// Health fields of each port, in `IfId` order.
    pub fn health(&self) -> impl Iterator<Item = (IfId, PortHealth)> + '_ {
        self.ports
            .iter()
            .map(|port| (port.target.interface, port.counters))
    }

    /// Folds one backend sample of `sample.interface` into its port and
    /// reports the resulting events.
    pub fn on_sample(
        &mut self,
        now: MonotonicMillis,
        sample: PortSample,
        emit: &mut impl FnMut(WatchEvent),
    ) {
        let Some(port) = self
            .ports
            .iter_mut()
            .find(|port| port.target.interface == sample.interface)
        else {
            return;
        };
        port.sample(now, sample, self.thresholds, emit);
    }

    /// Folds one link query result of port `index` (in [`Self::target`]
    /// order) and reports the resulting events.
    pub fn on_link(
        &mut self,
        index: usize,
        result: Result<LinkFacts, NetlinkError>,
        emit: &mut impl FnMut(WatchEvent),
    ) {
        if let Some(port) = self.ports.get_mut(index) {
            port.link(result, emit);
        }
    }

    /// Folds the kernel IPv4 address count of port `index` (rtnetlink
    /// `RTM_GETADDR`, queried after a successful link query of the same
    /// round): any address is fatal, a failed dump is a failed query.
    pub fn on_addresses(
        &mut self,
        index: usize,
        result: Result<u32, NetlinkError>,
        emit: &mut impl FnMut(WatchEvent),
    ) {
        if let Some(port) = self.ports.get_mut(index) {
            port.addresses(result, emit);
        }
    }

    /// Folds the kernel forwarding sysctls read for port `index` in this
    /// round: on is fatal `KERNEL_FORWARDING_ENABLED` unless allowed (then
    /// a warning); unreadable is a failed query unless allowed (then a
    /// warning), as at startup.
    pub fn on_forwarding(
        &mut self,
        index: usize,
        result: Result<Forwarding, ()>,
        emit: &mut impl FnMut(WatchEvent),
    ) {
        let allowed = self.allow_kernel_forwarding;
        if let Some(port) = self.ports.get_mut(index) {
            port.forwarding(result, allowed, emit);
        }
    }
}

/// `watch.state` (`ok` or `warning`) and the warnings given so far.
impl ObservableFields for Watch {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "watch";
        visitor.field(
            SECTION,
            "state",
            FieldValue::Label(if self.warning() { "warning" } else { "ok" }),
        );
        let warnings = self.ports.iter().fold(0_u64, |sum, port| {
            sum.saturating_add(port.counters.warnings)
        });
        visitor.field(SECTION, "warnings", FieldValue::Count(warnings));
    }
}

fn due(last: &mut Option<MonotonicMillis>, now: MonotonicMillis, interval_ms: u64) -> bool {
    let ready = last.is_none_or(|last| now.0.saturating_sub(last.0) >= interval_ms);
    if ready {
        *last = Some(now);
    }
    ready
}

impl PortWatch {
    fn warn(&mut self, condition: Condition, emit: &mut impl FnMut(WatchEvent)) {
        self.counters.warnings = self.counters.warnings.saturating_add(1);
        emit(WatchEvent::Warning {
            port: self.target.interface,
            condition,
        });
    }

    fn recover(&mut self, condition: Condition, emit: &mut impl FnMut(WatchEvent)) {
        emit(WatchEvent::Recovered {
            port: self.target.interface,
            condition,
        });
    }

    fn fatal(&self, cause: Fatal, emit: &mut impl FnMut(WatchEvent)) {
        emit(WatchEvent::Fatal {
            port: self.target.interface,
            cause,
        });
    }

    fn sample(
        &mut self,
        now: MonotonicMillis,
        sample: PortSample,
        thresholds: Thresholds,
        emit: &mut impl FnMut(WatchEvent),
    ) {
        let last = self.last.replace(sample);
        // TX stall: the same oldest frame in flight, with the link up.
        let stamp =
            (sample.tx_inflight != 0).then(|| sample.polls.saturating_sub(sample.oldest_age_polls));
        let link_down = sample.kick_link_down || !self.link_up;
        let same_oldest = stamp.is_some() && stamp == self.oldest_stamp;
        self.oldest_stamp = stamp;
        if same_oldest && !link_down {
            let held = self.stall.hold(now);
            self.counters.tx_stall_ms = held;
            if thresholds
                .tx_stall_fatal_ms
                .is_some_and(|fatal| held >= fatal)
            {
                self.fatal(Fatal::TxStall, emit);
            } else if held >= thresholds.tx_stall_warn_ms && !self.stall.warned {
                self.stall.warned = true;
                self.counters.tx_stall = true;
                self.warn(Condition::TxStall, emit);
            }
        } else {
            // Nothing in flight, the link is down, or a new oldest frame
            // (which starts its own clock now).
            self.counters.tx_stall = false;
            self.counters.tx_stall_ms = 0;
            if self.stall.clear() {
                self.recover(Condition::TxStall, emit);
            }
            if stamp.is_some() && !link_down {
                self.stall.since = Some(now);
            }
        }
        let Some(last) = last else {
            return;
        };
        // Fill starvation: no Fill frame in the kernel, no RX, and the
        // free list ran dry again.
        let starving = sample.fill_ring_occupancy == 0
            && sample.rx_packets == last.rx_packets
            && sample.fill_starved > last.fill_starved;
        if starving {
            if self.starved.hold(now) >= FILL_STARVED_WARN_MS && !self.starved.warned {
                self.starved.warned = true;
                self.counters.fill_starved = true;
                self.warn(Condition::FillStarved, emit);
            }
        } else {
            self.counters.fill_starved = false;
            if self.starved.clear() {
                self.recover(Condition::FillStarved, emit);
            }
        }
        // Kick errors in every sample.
        if sample.kick_errors > last.kick_errors {
            let held = self.kicks.hold(now);
            if !self.kicks.warned {
                self.kicks.warned = true;
                self.counters.kick_errors_persistent = true;
                self.warn(Condition::KickErrors, emit);
            }
            if thresholds
                .kick_errors_fatal_ms
                .is_some_and(|fatal| held >= fatal)
            {
                self.fatal(Fatal::KickErrors, emit);
            }
        } else {
            self.counters.kick_errors_persistent = false;
            if self.kicks.clear() {
                self.recover(Condition::KickErrors, emit);
            }
        }
    }

    /// One failed query of this round. Each query kind counts its own
    /// consecutive failures, so one that always fails cannot be reset by
    /// another that succeeds in the same round.
    fn probe_failed(&mut self, query: Query, emit: &mut impl FnMut(WatchEvent)) {
        self.counters.link_probe_errors = self.counters.link_probe_errors.saturating_add(1);
        let failures = &mut self.probe_failures[query as usize];
        *failures = failures.saturating_add(1);
        if *failures >= LINK_PROBE_FAILURES_FATAL {
            self.fatal(Fatal::LinkUnverifiable, emit);
        } else if !self.probe_warned {
            self.probe_warned = true;
            self.warn(Condition::LinkProbe, emit);
        }
    }

    /// One successful query: its count restarts, and the warning recovers
    /// once no query kind is failing.
    fn probe_ok(&mut self, query: Query, emit: &mut impl FnMut(WatchEvent)) {
        self.probe_failures[query as usize] = 0;
        if self.probe_failures.iter().all(|failures| *failures == 0)
            && std::mem::take(&mut self.probe_warned)
        {
            self.recover(Condition::LinkProbe, emit);
        }
    }

    fn addresses(&mut self, result: Result<u32, NetlinkError>, emit: &mut impl FnMut(WatchEvent)) {
        match result {
            Ok(count) => {
                self.probe_ok(Query::Addresses, emit);
                if count != 0 {
                    self.counters.kernel_ipv4_addresses = count;
                    self.fatal(Fatal::KernelIpv4Addresses, emit);
                }
            }
            Err(_) => self.probe_failed(Query::Addresses, emit),
        }
    }

    fn forwarding(
        &mut self,
        result: Result<Forwarding, ()>,
        allowed: bool,
        emit: &mut impl FnMut(WatchEvent),
    ) {
        match result {
            Ok(forwarding) => {
                self.probe_ok(Query::Forwarding, emit);
                let on = forwarding.global || forwarding.device;
                self.counters.kernel_forwarding = on;
                if on && !allowed {
                    self.fatal(Fatal::KernelForwardingEnabled, emit);
                } else if on && !self.forwarding_warned {
                    self.forwarding_warned = true;
                    self.warn(Condition::KernelForwarding, emit);
                } else if !on && std::mem::take(&mut self.forwarding_warned) {
                    self.recover(Condition::KernelForwarding, emit);
                }
            }
            // With the override an unreadable sysctl only warns, as at
            // startup.
            Err(()) if allowed => {
                if !self.forwarding_warned {
                    self.forwarding_warned = true;
                    self.warn(Condition::KernelForwarding, emit);
                }
            }
            Err(()) => self.probe_failed(Query::Forwarding, emit),
        }
    }

    fn link(&mut self, result: Result<LinkFacts, NetlinkError>, emit: &mut impl FnMut(WatchEvent)) {
        let facts = match result {
            Ok(facts) => facts,
            Err(error) if error.is_no_device() => {
                self.fatal(Fatal::DeviceRemoved, emit);
                return;
            }
            Err(_) => {
                self.probe_failed(Query::Link, emit);
                return;
            }
        };
        self.probe_ok(Query::Link, emit);
        self.counters.mtu = facts.mtu;
        if facts.mtu < self.target.mtu {
            self.fatal(Fatal::MtuDecreased, emit);
            return;
        }
        if facts.mtu > mtu_limit(self.target.frame_capacity) {
            self.fatal(Fatal::MtuAboveFrame, emit);
            return;
        }
        if facts.mtu != self.mtu {
            self.mtu = facts.mtu;
            if facts.mtu > self.target.mtu {
                // Once per new value.
                self.mtu_warned = true;
                self.warn(Condition::MtuRaised, emit);
            } else if std::mem::take(&mut self.mtu_warned) {
                self.recover(Condition::MtuRaised, emit);
            }
        }
        let up = facts.is_up();
        if up != self.link_up {
            self.link_up = up;
            self.counters.link_up = up;
            if up {
                self.counters.link_up_events = self.counters.link_up_events.saturating_add(1);
                self.recover(Condition::LinkDown, emit);
            } else {
                self.counters.link_down_events = self.counters.link_down_events.saturating_add(1);
                self.warn(Condition::LinkDown, emit);
            }
        }
    }
}

#[cfg(test)]
#[path = "watch_tests.rs"]
mod tests;

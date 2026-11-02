//! The live x86_64 Linux host of `ruster run`: native AF_XDP sessions,
//! engines, and the core adapter of `ruster-io-xdp-native`.

use std::num::{NonZeroU128, NonZeroU32};

use ruster_config::{ValidatedAfXdpPortV1, ValidatedAfXdpV1, XdpAttachModeV1};
use ruster_core::{BackendStats, IfId, MonotonicMillis};
use ruster_io_xdp_native::{
    NativeSession, RxFillConfig, RxFillEngine, SessionConfig, UmemDomainId, XdpAttachMode,
    XdpCounters, XdpIoError, XdpPacketIo, XdpPacketIoSetupError, XdpPort, XdpPortConfig,
};

use super::checks::linux::PortSysctls;
use super::checks::{self, CheckFailure, DeviceFacts, PrivilegeFailure};
use super::engine::{ClockedIo, Datapath, DrainProgress, LinkMonitor};
use super::netlink::{Dump, Family, LinkFacts, LinkProbe, NetlinkError};
use super::startup::{CloseFailure, Failure, OpenPort, PortHost, Stage, StartupError};
use super::stats::write_fields;
use super::watch::{Forwarding, Ipv6Sample, LinkTarget, PortSample};

/// High bits of every engine's UMEM domain id (`"rstr"`); the low bits are
/// the port's `IfId`, so domains are distinct per port.
const DOMAIN_TAG: u128 = 0x7273_7472 << 64;

/// Native AF_XDP host.
pub struct LinuxHost;

impl PortHost for LinuxHost {
    type Session = NativeSession;
    type Datapath<'s> = XdpDatapath<'s>;
    type Links = NetlinkLinks;

    fn links(&self, devices: &[(IfId, &str)]) -> Result<NetlinkLinks, Failure> {
        let probe = LinkProbe::open().map_err(Failure::Links)?;
        // Device names were accepted by `SessionConfig::new` (one path
        // component).
        let sysctls = devices
            .iter()
            .map(|(interface, device)| (*interface, PortSysctls::new(device)))
            .collect();
        Ok(NetlinkLinks { probe, sysctls })
    }

    fn preflight(&self, backend: &ValidatedAfXdpV1) -> Result<(), PrivilegeFailure> {
        checks::linux::check_privileges(checks::required_memlock(backend))
    }

    fn open(&self, port: &ValidatedAfXdpPortV1) -> Result<NativeSession, Failure> {
        let config = SessionConfig::new(
            port.device(),
            port.queue(),
            port.bind_flags(),
            port.rings(),
            port.umem(),
        )
        .map_err(Failure::SessionConfig)?;
        NativeSession::open(&config).map_err(Failure::Session)
    }

    fn inspect(
        &self,
        port: &ValidatedAfXdpPortV1,
        session: &NativeSession,
    ) -> Result<DeviceFacts, CheckFailure> {
        let facts = checks::linux::SessionFacts {
            ifindex: session.ifindex(),
            mtu: session.mtu(),
            frame_capacity: port.umem().visible_capacity(),
        };
        let mut probe = LinkProbe::open().ok();
        let sysctls = PortSysctls::new(port.device());
        checks::linux::device_facts(&sysctls, facts, probe.as_mut())
    }

    fn attach(&self, session: &mut NativeSession, mode: XdpAttachModeV1) -> Result<(), Failure> {
        let mode = match mode {
            XdpAttachModeV1::Native => XdpAttachMode::Native,
            XdpAttachModeV1::Generic => XdpAttachMode::Generic,
        };
        session.attach_xdp(mode).map_err(Failure::Attach)
    }

    fn build<'s>(
        &self,
        ports: &'s mut [OpenPort<NativeSession>],
    ) -> Result<XdpDatapath<'s>, StartupError>
    where
        Self: 's,
    {
        let mut built = Vec::with_capacity(ports.len());
        for port in ports.iter_mut() {
            let interface = port.interface;
            let fail = |stage, failure| StartupError::new(stage, Some(interface), failure);
            let session: &'s mut NativeSession = &mut port.session;
            let config = XdpPortConfig::from_session(interface, session);
            let datapath = session
                .take_datapath()
                .map_err(|error| fail(Stage::Datapath, Failure::Datapath(error)))?;
            let fill_batch = datapath.capacities()[0];
            let engine = RxFillEngine::new(
                datapath,
                domain(interface),
                RxFillConfig::new(NonZeroU32::new(fill_batch).unwrap_or(NonZeroU32::MIN)),
            )
            .map_err(|error| fail(Stage::Engine, Failure::Engine(error)))?;
            built.push(XdpPort::new(config, engine));
        }
        let io = XdpPacketIo::new(built).map_err(|error| {
            StartupError::new(Stage::Adapter, adapter_port(error), Failure::Adapter(error))
        })?;
        Ok(XdpDatapath { io })
    }

    fn close(&self, session: NativeSession) -> Result<(), CloseFailure> {
        session.close().map_err(CloseFailure::Cleanup)
    }
}

/// The interface an adapter setup error names, if any.
fn adapter_port(error: XdpPacketIoSetupError) -> Option<IfId> {
    match error {
        XdpPacketIoSetupError::NoPorts => None,
        XdpPacketIoSetupError::DuplicateInterface(interface)
        | XdpPacketIoSetupError::EngineDraining(interface)
        | XdpPacketIoSetupError::ZeroMtu(interface)
        | XdpPacketIoSetupError::SessionMismatch(interface)
        | XdpPacketIoSetupError::GeneratedPoolTooSmall { interface, .. } => Some(interface),
    }
}

/// UMEM domain of `interface`'s engine.
fn domain(interface: IfId) -> UmemDomainId {
    let id = DOMAIN_TAG | u128::from(interface.0);
    UmemDomainId::new(NonZeroU128::new(id).unwrap_or(NonZeroU128::MIN))
}

/// The run-time link watch: one reused rtnetlink socket and buffer, and
/// the sysctl paths built once at startup.
pub struct NetlinkLinks {
    probe: LinkProbe,
    sysctls: Vec<(IfId, PortSysctls)>,
}

impl NetlinkLinks {
    fn sysctls(&self, target: &LinkTarget) -> Option<&PortSysctls> {
        self.sysctls
            .iter()
            .find(|(interface, _)| *interface == target.interface)
            .map(|(_, sysctls)| sysctls)
    }
}

impl LinkMonitor for NetlinkLinks {
    fn query(&mut self, target: &LinkTarget) -> Result<LinkFacts, NetlinkError> {
        self.probe.query(target.ifindex)
    }

    fn ipv4_addresses(&mut self, target: &LinkTarget) -> Result<u32, NetlinkError> {
        self.probe.ipv4_addresses(target.ifindex)
    }

    fn ipv4_routes(&mut self, target: &LinkTarget) -> Result<u32, NetlinkError> {
        self.probe.count(Dump::Routes(Family::Ipv4), target.ifindex)
    }

    fn forwarding(&mut self, target: &LinkTarget) -> Result<Forwarding, ()> {
        let ipv4 = self.sysctls(target).ok_or(())?.ipv4();
        Ok(Forwarding {
            global: ipv4.forwarding_global.ok_or(())?,
            device: ipv4.forwarding_device.ok_or(())?,
            force: false,
            multicast: ipv4.forwarding_multicast.ok_or(())?,
        })
    }

    fn ipv4_weak_host(&mut self, target: &LinkTarget) -> Option<bool> {
        self.sysctls(target)?.ipv4().weak_host
    }

    /// `disable_ipv6` first: when set (or without IPv6 in the namespace)
    /// nothing else is read; otherwise both IPv6 dumps and every IPv6
    /// forwarding sysctl (also when the flag was unreadable: fail
    /// closed). No allocation.
    fn ipv6(&mut self, target: &LinkTarget) -> Ipv6Sample {
        let Some(sysctls) = self.sysctls(target) else {
            return Ipv6Sample {
                disabled: Err(()),
                addresses: Err(NetlinkError::UnexpectedLink),
                routes: Err(NetlinkError::UnexpectedLink),
                forwarding: Err(()),
            };
        };
        let disabled = sysctls.ipv6_disabled().ok_or(());
        if disabled == Ok(true) {
            return Ipv6Sample::DISABLED;
        }
        let ipv6 = sysctls.ipv6_forwarding();
        let forwarding = match (ipv6.global, ipv6.device, ipv6.force, ipv6.multicast) {
            (Some(global), Some(device), Some(force), Some(multicast)) => Ok(Forwarding {
                global,
                device,
                force,
                multicast,
            }),
            _ => Err(()),
        };
        Ipv6Sample {
            disabled,
            addresses: self
                .probe
                .count(Dump::Addresses(Family::Ipv6), target.ifindex),
            routes: self.probe.count(Dump::Routes(Family::Ipv6), target.ifindex),
            forwarding,
        }
    }
}

impl ClockedIo for XdpPacketIo<'_> {
    fn set_clock(&mut self, now: MonotonicMillis) {
        XdpPacketIo::set_clock(self, now);
    }
}

/// The adapter over every port's engine.
pub struct XdpDatapath<'s> {
    io: XdpPacketIo<'s>,
}

impl<'s> Datapath for XdpDatapath<'s> {
    type Io = XdpPacketIo<'s>;

    fn io(&mut self) -> &mut XdpPacketIo<'s> {
        &mut self.io
    }

    fn drain(&mut self, rounds: u32) -> Result<DrainProgress, XdpIoError> {
        self.io.drain(rounds).map(|report| DrainProgress {
            completed: report.completed,
            rx_pending_released: report.rx_pending_released,
            tx_in_flight: report.tx_in_flight,
            fill_in_kernel: report.fill_in_kernel,
            tx_handoffs: report.tx_handoffs_outstanding,
            last_kick_error: report.last_kick_error,
        })
    }

    fn sample_ports(&self, visit: &mut impl FnMut(PortSample)) {
        for interface in self.io.interfaces() {
            // One getsockopt(XDP_STATISTICS) per port; no allocation.
            if let Some(stats) = self.io.port_stats(interface) {
                let counters = stats.counters;
                visit(PortSample {
                    interface,
                    polls: counters.polls,
                    tx_inflight: counters.tx_inflight,
                    oldest_age_polls: counters.completion_lag_oldest_polls,
                    kick_errors: watched_kick_errors(&counters),
                    kick_link_down: stats.link_down,
                    fill_starved: counters.fill_starved,
                    fill_ring_occupancy: counters.fill_ring_occupancy,
                    rx_packets: counters.rx_packets,
                });
            }
        }
    }

    fn write_stats(&self, out: &mut String) {
        write_fields(out, None, &self.io.backend_stats());
        let interfaces: Vec<IfId> = self.io.interfaces().collect();
        for interface in interfaces {
            if let Some(stats) = self.io.port_stats(interface) {
                write_fields(out, Some(interface), &stats);
            }
        }
    }

    fn port_count(&self) -> usize {
        self.io.port_count()
    }
}

/// The kick failures the health watch times as `KICK_ERRORS`: the
/// engine's `kick_errors` counts every failed kick, `ENETDOWN` included,
/// while the adapter counts the `ENETDOWN` ones separately
/// (`kicks_link_down`). A port whose link is down keeps its TX kick owed
/// and retries it (rate-limited: 1 ms doubling to 64 ms), so without the
/// subtraction a down link with TX in flight would turn into a fatal
/// `KICK_ERRORS` instead of staying `LINK_DOWN`. A retry the adapter
/// skipped because it was not due (`kick_retries_suppressed`) made no
/// syscall and is in neither counter.
fn watched_kick_errors(counters: &XdpCounters) -> u64 {
    counters
        .kick_errors
        .saturating_sub(counters.kicks_link_down)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enetdown_kicks_are_not_kick_errors_for_the_watch() {
        let mut counters = XdpCounters::default();
        counters.kick_errors = 47_307;
        counters.kicks_link_down = 47_307;
        assert_eq!(watched_kick_errors(&counters), 0);
        counters.kick_errors = 47_310;
        assert_eq!(watched_kick_errors(&counters), 3);
        // Suppressed link-down retries are not kicks at all.
        counters.kick_retries_suppressed = 1_000_000;
        assert_eq!(watched_kick_errors(&counters), 3);
        // Never wraps (the adapter counts ENETDOWN only after the engine
        // counted the failed kick, so this cannot happen, but stays 0).
        counters.kick_errors = 1;
        counters.kicks_link_down = 2;
        assert_eq!(watched_kick_errors(&counters), 0);
    }
}

//! The live x86_64 Linux host of `ruster run`: native AF_XDP sessions,
//! engines, and the core adapter of `ruster-io-xdp-native`; and the
//! AF_PACKET adapter of `ruster-io-afpacket` (AFPKT-015).

use std::num::{NonZeroU128, NonZeroU32};

use ruster_config::{
    AfPacketRingV1, ExitProtectionV1, ValidatedAfPacketPortV1, ValidatedAfPacketV1,
    ValidatedAfXdpPortV1, ValidatedAfXdpV1, XdpAttachModeV1,
};
use ruster_core::{BackendStats, IfId, MonotonicMillis};
use ruster_io_afpacket::{
    AfPacketIo, AfPacketPlatform, PlatformError, PortConfig, RingGeometry, RxWait as PacketRxWait,
    ValidatedConfig as PacketConfig,
};
use ruster_io_xdp_native::{
    NativeSession, RxFillConfig, RxFillEngine, RxWait, RxWaitError, SessionConfig, UmemDomainId,
    XdpAttachMode, XdpCounters, XdpIoError, XdpPacketIo, XdpPacketIoSetupError, XdpPort,
    XdpPortConfig,
};

use super::checks::linux::PortSysctls;
use super::checks::{self, CheckFailure, DeviceFacts, PrivilegeFailure, Probe};
use super::engine::HealthSample;
use super::engine::{ClockedIo, Datapath, DrainProgress, IdleWake, LinkMonitor, WaitError};
use super::exit_guard::{ExitAction, ExitActions, ExitError, ExitReport};
use super::fs_confine::{self, FsFailure, FsReport};
use super::netlink::{Dump, Family, IfName, LinkFacts, LinkProbe, NetlinkError};
use super::offload;
use super::privileges::{self, DropFailure, DropReport, Identity, PrivilegePolicy};
use super::seccomp::{self, ConfineFailure, ConfineReport, SeccompMode};
use super::startup::{
    CloseFailure, Failure, OpenPort, PacketFacts, PacketOpenError, PortHost, Stage, StartupError,
};
use super::stats::write_fields;
use super::watch::{Forwarding, IntegritySample, Ipv6Sample, LinkTarget, PortSample};

/// High bits of every engine's UMEM domain id (`"rstr"`); the low bits are
/// the port's `IfId`, so domains are distinct per port.
const DOMAIN_TAG: u128 = 0x7273_7472 << 64;

/// Native AF_XDP host.
pub struct LinuxHost;

impl PortHost for LinuxHost {
    type Session = NativeSession;
    type Datapath<'s> = XdpDatapath<'s>;
    type Packet = PacketDatapath;
    type Links = NetlinkLinks;
    type Exit = LinuxExit;

    fn initial_user_namespace(&self) -> Option<bool> {
        std::fs::read_to_string("/proc/self/uid_map")
            .ok()
            .map(|map| is_initial_uid_map(&map))
    }

    fn exit_actions(
        &self,
        protection: ExitProtectionV1,
        targets: &[LinkTarget],
    ) -> Result<LinuxExit, (Option<IfId>, ExitError)> {
        LinuxExit::open(protection, targets)
    }

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

    fn preflight(
        &self,
        backend: &ValidatedAfXdpV1,
        policy: PrivilegePolicy,
    ) -> Result<(), PrivilegeFailure> {
        checks::linux::check_privileges(checks::required_memlock(backend), policy)
    }

    fn lockdown(&self, identity: Option<Identity>) -> Result<DropReport, DropFailure> {
        privileges::linux::drop_process(identity)
    }

    fn thread_prologue(&self) -> fn(PrivilegePolicy) -> Result<(), DropFailure> {
        thread_lockdown
    }

    fn fs_confine(&self) -> Result<FsReport, FsFailure> {
        fs_confine::linux::restrict_process()
    }

    fn confine(&self, mode: SeccompMode) -> Result<ConfineReport, ConfineFailure> {
        seccomp::linux::confine(mode)
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

    fn preflight_packet(&self, policy: PrivilegePolicy) -> Result<(), PrivilegeFailure> {
        checks::linux::check_packet_privileges(policy)
    }

    /// One rtnetlink socket per port: the name lookup, then the same facts
    /// as an AF_XDP port of that index; then the receive offloads.
    fn inspect_packet(
        &self,
        port: &ValidatedAfPacketPortV1,
        max_frame_len: u32,
    ) -> Result<PacketFacts, CheckFailure> {
        let name =
            IfName::new(port.device().as_bytes()).ok_or(CheckFailure::Unverifiable(Probe::Name))?;
        let mut probe = LinkProbe::open().map_err(|_| CheckFailure::Unverifiable(Probe::Link))?;
        let (ifindex, link) = probe
            .resolve(name)
            .map_err(|_| CheckFailure::Unverifiable(Probe::Link))?;
        // The offload probe names the device (`SIOCETHTOOL` takes a name),
        // so it runs between the name -> index lookup above and the index
        // query of `device_facts`, whose name the startup then compares
        // with the configured one (H10): a rename or a replacement of the
        // device in between is refused (`probe=name`), so the offloads read
        // are those of the index that is bound.
        let offload = offload::linux::active_receive_offload(name).map_err(|_| ());
        let facts = checks::linux::SessionFacts {
            ifindex,
            mtu: link.mtu,
            frame_capacity: max_frame_len,
        };
        let sysctls = PortSysctls::new(port.device());
        let mut device = checks::linux::device_facts(&sysctls, facts, Some(&mut probe))?;
        let mut stacked = [0_u32];
        device.stacked = probe
            .count_stacked(&[ifindex], &mut stacked)
            .ok()
            .map(|()| stacked[0]);
        Ok(PacketFacts { device, offload })
    }

    fn open_packet(
        &self,
        backend: &ValidatedAfPacketV1,
        targets: &[LinkTarget],
    ) -> Result<PacketDatapath, Failure> {
        let fail = |error| Failure::Packet(error);
        if targets.len() != backend.ports().len() {
            return Err(fail(PacketOpenError::Ports));
        }
        let mut ports = Vec::with_capacity(targets.len());
        for (port, target) in backend.ports().iter().zip(targets) {
            if port.interface() != target.interface {
                return Err(fail(PacketOpenError::Ports));
            }
            ports.push(PortConfig {
                interface: port.interface(),
                if_index: target.ifindex,
                rx: geometry(port.rx()),
                tx: geometry(port.tx()),
            });
        }
        let page = AfPacketPlatform::page_size()
            .map_err(|error| fail(PacketOpenError::Platform(error)))?;
        let max_frame = usize::try_from(backend.max_frame_len()).unwrap_or(usize::MAX);
        let config = PacketConfig::new(&ports, page, max_frame)
            .map_err(|error| fail(PacketOpenError::Config(error)))?;
        let io =
            AfPacketIo::open(config).map_err(|error| fail(PacketOpenError::Platform(error)))?;
        Ok(PacketDatapath { io })
    }
}

/// The backend ring geometry of a validated AF_PACKET ring.
fn geometry(ring: AfPacketRingV1) -> RingGeometry {
    RingGeometry {
        block_size: ring.block_size(),
        block_count: ring.block_count(),
        frame_size: ring.frame_size(),
        frame_count: ring.frame_count(),
        retire_timeout_ms: ring.retire_timeout_ms(),
        private_size: 0,
        feature_flags: 0,
    }
}

/// The prologue of every thread but the router thread (the output threads
/// and the workers): drops the calling thread's privileges (nothing with
/// [`PrivilegePolicy::Keep`]), then confines its filesystem view (nothing
/// with `--fs-confine off`, which prepares no ruleset).
pub fn thread_lockdown(policy: PrivilegePolicy) -> Result<(), DropFailure> {
    privileges::linux::drop_thread(policy)?;
    fs_confine::linux::restrict_thread().map_err(DropFailure::Filesystem)
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

    fn stacked_links(&mut self, ifindexes: &[u32], counts: &mut [u32]) -> Result<(), NetlinkError> {
        self.probe.count_stacked(ifindexes, counts)
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
        self.sample(&mut |sample| {
            if let HealthSample::Port(sample) = sample {
                visit(sample);
            }
        });
    }

    /// Both samples of each port, the health counters and the integrity
    /// counters (quarantined frames and the kernel's `tx_invalid_descs`,
    /// OPS-LOG), from ONE `getsockopt(XDP_STATISTICS)` per port; no
    /// allocation.
    fn sample(&self, visit: &mut impl FnMut(HealthSample)) {
        for interface in self.io.interfaces() {
            if let Some(stats) = self.io.port_stats(interface) {
                let counters = stats.counters;
                visit(HealthSample::Port(PortSample {
                    interface,
                    polls: counters.polls,
                    tx_inflight: counters.tx_inflight,
                    oldest_age_polls: counters.completion_lag_oldest_polls,
                    kick_errors: watched_kick_errors(&counters),
                    kick_link_down: stats.link_down,
                    fill_starved: counters.fill_starved,
                    fill_ring_occupancy: counters.fill_ring_occupancy,
                    rx_packets: counters.rx_packets,
                    device_gone: false,
                }));
                visit(HealthSample::Integrity(IntegritySample {
                    interface,
                    frames_quarantined: counters.frames_quarantined,
                    tx_invalid_descs: counters.kernel_tx_invalid_descs,
                }));
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

    /// One `poll(2)` over every port's AF_XDP socket (`POLLIN`), or none
    /// while a port already has RX work (H9).
    fn wait_rx(&mut self, timeout_ms: u32) -> Result<IdleWake, WaitError> {
        match self.io.wait_rx(timeout_ms) {
            Ok(RxWait::Ready) => Ok(IdleWake::Ready),
            Ok(RxWait::TimedOut) => Ok(IdleWake::TimedOut),
            Ok(RxWait::Interrupted) => Ok(IdleWake::Interrupted),
            Err(RxWaitError::Errno(errno)) => Err(WaitError::Errno(errno)),
            Err(RxWaitError::Unsupported) => Err(WaitError::Unsupported),
        }
    }

    fn tx_outstanding(&self) -> bool {
        self.io.tx_outstanding()
    }
}

impl ClockedIo for AfPacketIo {
    fn set_clock(&mut self, now: MonotonicMillis) {
        AfPacketIo::set_clock(self, now);
    }
}

/// The AF_PACKET adapter over every port's socket (AFPKT-015). It owns the
/// sockets and rings: dropping it unmaps and closes each port once.
pub struct PacketDatapath {
    io: AfPacketIo,
}

impl Datapath for PacketDatapath {
    type Io = AfPacketIo;

    fn io(&mut self) -> &mut AfPacketIo {
        &mut self.io
    }

    /// `AfPacketIo::drain`: the first call stops RX and new TX for good,
    /// every call kicks owed ports without backoff and reaps at most
    /// `rounds` times. It cannot fail; frames the kernel still holds are
    /// `tx_in_flight` (and the kernel frees them with the socket). There is
    /// no Fill ring, no staged handoff, and no unlent RX frame to release
    /// (an unreturned RX block goes back with the socket).
    fn drain(&mut self, rounds: u32) -> Result<DrainProgress, XdpIoError> {
        let before = self.io.backend_stats().counters.tx_completed;
        let report = self.io.drain(rounds);
        let completed = self
            .io
            .backend_stats()
            .counters
            .tx_completed
            .saturating_sub(before);
        Ok(DrainProgress {
            completed: u32::try_from(completed).unwrap_or(u32::MAX),
            rx_pending_released: 0,
            tx_in_flight: u32::try_from(report.tx_in_flight).unwrap_or(u32::MAX),
            fill_in_kernel: 0,
            tx_handoffs: 0,
            last_kick_error: None,
        })
    }

    /// Per port: `polls` is the port's completed TX frames, so the TX stall
    /// watch ([`super::watch`]) times frames in flight while no completion
    /// arrives at all (`oldest_age_polls` 0: the stamp is the completion
    /// count). There is no Fill ring to starve. `kick_errors` excludes
    /// `ENETDOWN` already (the adapter counts it as `kicks_link_down`
    /// only), and an `ENXIO` kick (the bound device unregistered) makes the
    /// port `unbound`: `device_gone`, fatal `DEVICE_REMOVED`.
    fn sample_ports(&self, visit: &mut impl FnMut(PortSample)) {
        for stats in self.io.ports() {
            let counters = stats.counters;
            visit(PortSample {
                interface: stats.interface,
                polls: counters.tx_completed,
                tx_inflight: u64::from(stats.tx_inflight),
                oldest_age_polls: 0,
                kick_errors: counters.kick_errors,
                kick_link_down: stats.link_down,
                fill_starved: 0,
                fill_ring_occupancy: 0,
                rx_packets: counters.rx_packets,
                device_gone: stats.unbound,
            });
        }
    }

    /// Folds the kernel's `PACKET_STATISTICS` (32-bit, reset on every read)
    /// into the adapter's 64-bit counters at every health sample (500 ms),
    /// so they never wrap; a failed read is counted
    /// (`kernel_stats_errors`).
    fn refresh(&mut self) {
        let _ = self.io.refresh_kernel_stats();
    }

    fn write_stats(&self, out: &mut String) {
        write_fields(out, None, &self.io.backend_stats());
        for stats in self.io.ports() {
            write_fields(out, Some(stats.interface), &stats);
        }
    }

    fn port_count(&self) -> usize {
        self.io.port_count()
    }

    /// One `poll(2)` over every port's packet socket (`POLLIN`), or none
    /// while a port has RX work; a pending socket error is cleared there.
    fn wait_rx(&mut self, timeout_ms: u32) -> Result<IdleWake, WaitError> {
        match self.io.wait_rx(timeout_ms) {
            Ok(PacketRxWait::Ready) => Ok(IdleWake::Ready),
            Ok(PacketRxWait::TimedOut) => Ok(IdleWake::TimedOut),
            Ok(PacketRxWait::Interrupted) => Ok(IdleWake::Interrupted),
            Err(PlatformError::Syscall { errno, .. }) => Err(WaitError::Errno(
                u16::try_from(errno.get()).unwrap_or(u16::MAX),
            )),
            Err(_) => Err(WaitError::Unsupported),
        }
    }

    fn tx_outstanding(&self) -> bool {
        self.io.tx_outstanding()
    }
}

/// Whether `/proc/self/uid_map` is the initial user namespace's: one
/// extent mapping every uid onto itself (`0 0 4294967295`).
fn is_initial_uid_map(map: &str) -> bool {
    let mut lines = map.lines();
    let first = lines
        .next()
        .map(|line| line.split_whitespace().collect::<Vec<_>>());
    lines.next().is_none() && first.as_deref() == Some(&["0", "0", "4294967295"][..])
}

/// The live exit actions (OPS-EXIT, [`super::exit_guard`]): the ports'
/// IPv4 forwarding sysctl files opened write-only and an rtnetlink socket,
/// all opened before the privilege drop and any confinement.
pub struct LinuxExit {
    forwarding: Vec<(IfId, std::fs::File)>,
    links: Option<(LinkProbe, Vec<(IfId, u32)>)>,
}

impl LinuxExit {
    fn open(
        protection: ExitProtectionV1,
        targets: &[LinkTarget],
    ) -> Result<Self, (Option<IfId>, ExitError)> {
        let mut forwarding = Vec::new();
        if protection.ipv4_forwarding_off {
            for target in targets {
                let fail = |error| (Some(target.interface), error);
                // The configured device name (an ASCII path component,
                // checked by the config and `IfName`).
                let device = std::str::from_utf8(target.name.as_bytes())
                    .map_err(|_| fail(ExitError::Errno(EINVAL)))?;
                let path = format!("/proc/sys/net/ipv4/conf/{device}/forwarding");
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(|error| fail(io_error(&error)))?;
                forwarding.push((target.interface, file));
            }
        }
        let links = if protection.link_down {
            let probe = LinkProbe::open().map_err(|error| (None, ExitError::Netlink(error)))?;
            let ports = targets
                .iter()
                .map(|target| (target.interface, target.ifindex))
                .collect();
            Some((probe, ports))
        } else {
            None
        };
        Ok(Self { forwarding, links })
    }
}

/// `EINVAL`.
const EINVAL: i32 = 22;

fn io_error(error: &std::io::Error) -> ExitError {
    ExitError::Errno(error.raw_os_error().unwrap_or(0))
}

impl ExitActions for LinuxExit {
    /// Forwarding first (it only narrows what the kernel does), then the
    /// links. Each sysctl file is written once at offset 0 (never written
    /// before), as `0` and a newline.
    fn apply(&mut self, report: &mut ExitReport) {
        use std::io::Write as _;
        for (interface, file) in &mut self.forwarding {
            let result = match file.write(b"0\n") {
                Ok(2) => Ok(()),
                Ok(_) => Err(ExitError::ShortWrite),
                Err(error) => Err(io_error(&error)),
            };
            report.record(*interface, ExitAction::Ipv4ForwardingOff, result);
        }
        if let Some((probe, ports)) = &mut self.links {
            for (interface, ifindex) in ports.iter() {
                let result = probe.set_down(*ifindex).map_err(ExitError::Netlink);
                report.record(*interface, ExitAction::LinkDown, result);
            }
        }
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
    fn only_the_identity_uid_map_is_the_initial_user_namespace() {
        assert!(is_initial_uid_map("         0          0 4294967295\n"));
        assert!(!is_initial_uid_map("         0       1000          1\n"));
        assert!(!is_initial_uid_map("0 0 4294967295\n1 1 1\n"));
        assert!(!is_initial_uid_map("0 0 65536\n"));
        assert!(!is_initial_uid_map(""));
    }

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

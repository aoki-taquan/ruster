//! The live x86_64 Linux host of `ruster run`: native AF_XDP sessions,
//! engines, and the core adapter of `ruster-io-xdp-native`.

use std::num::{NonZeroU128, NonZeroU32};

use ruster_config::{ValidatedAfXdpPortV1, ValidatedAfXdpV1, XdpAttachModeV1};
use ruster_core::{BackendStats, IfId};
use ruster_io_xdp_native::{
    NativeSession, RxFillConfig, RxFillEngine, SessionConfig, UmemDomainId, XdpAttachMode,
    XdpIoError, XdpPacketIo, XdpPacketIoSetupError, XdpPort, XdpPortConfig,
};

use super::checks::{self, CheckFailure, DeviceFacts, PrivilegeFailure};
use super::engine::{Datapath, DrainProgress};
use super::netlink;
use super::startup::{CloseFailure, Failure, OpenPort, PortHost, Stage, StartupError};
use super::stats::write_fields;

/// High bits of every engine's UMEM domain id (`"rstr"`); the low bits are
/// the port's `IfId`, so domains are distinct per port.
const DOMAIN_TAG: u128 = 0x7273_7472 << 64;

/// Native AF_XDP host.
pub struct LinuxHost;

impl PortHost for LinuxHost {
    type Session = NativeSession;
    type Datapath<'s> = XdpDatapath<'s>;

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
        checks::linux::device_facts(port.device(), session.ifindex(), |ifindex| {
            netlink::ipv4_address_count(ifindex).ok()
        })
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
            last_kick_error: report.last_kick_error,
        })
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

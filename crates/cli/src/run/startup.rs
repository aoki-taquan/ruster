//! Failure-atomic port startup of `ruster run`, generic over the host so
//! every stage can be failed by a scripted fake.
//!
//! Per port, in `IfId` order: open the session, run the XDP-063 device
//! checks, attach XDP. Then, over all opened sessions: take each datapath,
//! build each engine, build the adapter. Every opened session is owned by
//! [`OpenedPorts`]; a failure at any stage (or a stop request between
//! stages) closes every session opened so far in reverse order, and
//! closing a session detaches its XDP program first, so no program stays
//! attached and every socket, UMEM, and ring mapping is released.
//!
//! The datapath is built after all sessions are attached because each
//! engine borrows its session mutably for its whole life, and attach also
//! needs `&mut` session: an engine can only exist once its session is
//! final. Taking the datapath and building engines acquires no kernel
//! resource; the XDP program redirects frames to a socket whose Fill ring
//! is still empty until then, which the kernel counts as
//! `rx_fill_ring_empty_descs` drops (the same as an engine that falls
//! behind), never as frames reaching the kernel stack.

use std::fmt;

use ruster_config::{ValidatedAfXdpPortV1, ValidatedAfXdpV1, XdpAttachModeV1};
use ruster_control::{ActivationError, SequencerError, StorageAllocationError};
use ruster_core::IfId;
use ruster_io_xdp_native::{
    AttachError, CleanupError, DatapathError, RxFillSetupError, SessionConfigError, SessionError,
    XdpPacketIoSetupError,
};

use super::checks::{
    evaluate_device, CheckFailure, CheckPolicy, DeviceFacts, PrivilegeFailure, Warnings,
};
use super::engine::{port_label, Datapath, StopSignal};

/// Startup stage, in execution order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Production candidate (bridge and key draw).
    Candidate,
    /// Runtime storage allocation.
    Storage,
    /// Capability and memlock preflight.
    Privileges,
    /// `NativeSession::open` (with its TX-queue and MTU checks).
    Open,
    /// XDP-063 device checks.
    Checks,
    /// `NativeSession::attach_xdp`.
    Attach,
    /// `NativeSession::take_datapath`.
    Datapath,
    /// `RxFillEngine::new`.
    Engine,
    /// `XdpPacketIo::new`.
    Adapter,
    /// `ActivePublication::new` of generation 1.
    Activate,
}

impl Stage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Storage => "storage",
            Self::Privileges => "privileges",
            Self::Open => "open",
            Self::Checks => "checks",
            Self::Attach => "attach",
            Self::Datapath => "datapath",
            Self::Engine => "engine",
            Self::Adapter => "adapter",
            Self::Activate => "activate",
        }
    }
}

/// Value-free cause of a startup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Sequencer(SequencerError),
    Storage(StorageAllocationError),
    Privileges(PrivilegeFailure),
    SessionConfig(SessionConfigError),
    Session(SessionError),
    Check(CheckFailure),
    Attach(AttachError),
    Datapath(DatapathError),
    Engine(RxFillSetupError),
    Adapter(XdpPacketIoSetupError),
    Activation(ActivationError),
    /// A failure injected by a test host.
    #[cfg(test)]
    Injected,
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequencer(SequencerError::Bridge(error)) => {
                write!(formatter, "code={}", error.code())
            }
            Self::Sequencer(error) => write!(formatter, "code={error:?}"),
            Self::Storage(error) => write!(formatter, "code={error:?}"),
            Self::Privileges(error) => write!(formatter, "code={error}"),
            Self::SessionConfig(error) => write!(formatter, "code={error:?}"),
            Self::Session(error) => {
                write!(formatter, "code={:?}/{:?}", error.stage(), error.failure())
            }
            Self::Check(error) => write!(formatter, "code={error}"),
            Self::Attach(error) => {
                write!(formatter, "code={:?}/{:?}", error.stage(), error.failure())?;
                if let Some(log) = error.verifier_log() {
                    write!(
                        formatter,
                        " verifier-log-bytes={} truncated={}",
                        log.bytes(),
                        log.truncated()
                    )?;
                }
                Ok(())
            }
            Self::Datapath(error) => write!(formatter, "code={error:?}"),
            Self::Engine(error) => write!(formatter, "code={error:?}"),
            Self::Adapter(error) => write!(formatter, "code={error:?}"),
            Self::Activation(error) => write!(formatter, "code={error:?}"),
            #[cfg(test)]
            Self::Injected => formatter.write_str("code=INJECTED"),
        }
    }
}

/// A stage that failed, the port it failed on, and why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupError {
    pub stage: Stage,
    pub port: Option<IfId>,
    pub failure: Failure,
}

impl StartupError {
    pub const fn new(stage: Stage, port: Option<IfId>, failure: Failure) -> Self {
        Self {
            stage,
            port,
            failure,
        }
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "stage={}", self.stage.label())?;
        if let Some(port) = self.port {
            write!(formatter, " port={}", port_label(port))?;
        }
        write!(formatter, " {}", self.failure)
    }
}

/// Why closing a session reported an error (the rest of it was still
/// released).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseFailure {
    Cleanup(CleanupError),
    #[cfg(test)]
    Injected,
}

impl fmt::Display for CloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cleanup(error) => match error.errno() {
                Some(errno) => write!(formatter, "code={:?} errno={errno}", error.stage()),
                None => write!(formatter, "code={:?}", error.stage()),
            },
            #[cfg(test)]
            Self::Injected => formatter.write_str("code=INJECTED"),
        }
    }
}

/// One opened session and its interface.
pub struct OpenPort<S> {
    pub interface: IfId,
    pub session: S,
}

/// The operations startup and teardown need from the platform.
pub trait PortHost {
    type Session;
    type Datapath<'s>: Datapath
    where
        Self: 's;

    /// Capabilities and memlock for `backend`, before any resource.
    fn preflight(&self, backend: &ValidatedAfXdpV1) -> Result<(), PrivilegeFailure>;

    /// Opens one session (no XDP attached yet).
    fn open(&self, port: &ValidatedAfXdpPortV1) -> Result<Self::Session, Failure>;

    /// Reads the device facts of an opened session.
    fn inspect(
        &self,
        port: &ValidatedAfXdpPortV1,
        session: &Self::Session,
    ) -> Result<DeviceFacts, CheckFailure>;

    /// Attaches the redirect program (existing programs are refused).
    fn attach(&self, session: &mut Self::Session, mode: XdpAttachModeV1) -> Result<(), Failure>;

    /// Takes every session's datapath, builds the engines and the adapter.
    /// On error everything built so far is dropped (no session is closed:
    /// the caller owns them).
    fn build<'s>(
        &self,
        ports: &'s mut [OpenPort<Self::Session>],
    ) -> Result<Self::Datapath<'s>, StartupError>
    where
        Self: 's;

    /// Detaches (if attached) and closes one session, releasing every
    /// resource even when a step reports an error.
    fn close(&self, session: Self::Session) -> Result<(), CloseFailure>;
}

/// Sessions opened so far, closed in reverse order by [`Self::close_all`]
/// or, if that never runs (a panic), by `Drop`.
pub struct OpenedPorts<'h, H: PortHost> {
    host: &'h H,
    ports: Vec<OpenPort<H::Session>>,
}

impl<'h, H: PortHost> OpenedPorts<'h, H> {
    pub fn new(host: &'h H, capacity: usize) -> Self {
        Self {
            host,
            ports: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.ports.len()
    }

    pub fn ports_mut(&mut self) -> &mut [OpenPort<H::Session>] {
        &mut self.ports
    }

    /// Closes every session, last opened first, and returns the ports whose
    /// close reported an error.
    pub fn close_all(mut self) -> Vec<(IfId, CloseFailure)> {
        let mut failures = Vec::new();
        while let Some(port) = self.ports.pop() {
            if let Err(error) = self.host.close(port.session) {
                failures.push((port.interface, error));
            }
        }
        failures
    }
}

impl<H: PortHost> Drop for OpenedPorts<'_, H> {
    fn drop(&mut self) {
        while let Some(port) = self.ports.pop() {
            let _ = self.host.close(port.session);
        }
    }
}

/// Why [`open_ports`] stopped early.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interrupt {
    Failed(StartupError),
    /// A stop request arrived between stages.
    Signalled,
}

/// Opens, checks, and attaches every port of `backend` in `IfId` order
/// into `opened`. On `Err` the caller must [`OpenedPorts::close_all`].
/// `warn` receives each port's non-fatal check findings.
pub fn open_ports<H: PortHost, S: StopSignal>(
    opened: &mut OpenedPorts<'_, H>,
    backend: &ValidatedAfXdpV1,
    policy: CheckPolicy,
    stop: &S,
    mut warn: impl FnMut(IfId, &Warnings),
) -> Result<(), Interrupt> {
    let host = opened.host;
    for port in backend.ports() {
        let interface = port.interface();
        let fail =
            |stage, failure| Interrupt::Failed(StartupError::new(stage, Some(interface), failure));
        if stop.stop() {
            return Err(Interrupt::Signalled);
        }
        let session = host
            .open(port)
            .map_err(|failure| fail(Stage::Open, failure))?;
        opened.ports.push(OpenPort { interface, session });
        let Some(entry) = opened.ports.last_mut() else {
            unreachable!("a port was just pushed");
        };
        let facts = host
            .inspect(port, &entry.session)
            .map_err(|failure| fail(Stage::Checks, Failure::Check(failure)))?;
        let warnings = evaluate_device(&facts, policy)
            .map_err(|failure| fail(Stage::Checks, Failure::Check(failure)))?;
        warn(interface, &warnings);
        if stop.stop() {
            return Err(Interrupt::Signalled);
        }
        host.attach(&mut entry.session, port.attach())
            .map_err(|failure| fail(Stage::Attach, failure))?;
    }
    Ok(())
}

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
            Self::Sequencer(error) => write!(formatter, "code={}", token(error)),
            Self::Storage(error) => write!(formatter, "code={}", token(error)),
            Self::Privileges(error) => write!(formatter, "code={error}"),
            Self::SessionConfig(error) => write!(formatter, "code={}", token(error)),
            Self::Session(error) => write!(
                formatter,
                "code={}/{}",
                token(&error.stage()),
                token(&error.failure())
            ),
            Self::Check(error) => write!(formatter, "code={error}"),
            Self::Attach(error) => {
                write!(
                    formatter,
                    "code={}/{}",
                    token(&error.stage()),
                    token(&error.failure())
                )?;
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
            Self::Datapath(error) => write!(formatter, "code={}", token(error)),
            Self::Engine(error) => write!(formatter, "code={}", token(error)),
            Self::Adapter(error) => write!(formatter, "code={}", token(error)),
            Self::Activation(error) => write!(formatter, "code={}", token(error)),
            #[cfg(test)]
            Self::Injected => formatter.write_str("code=INJECTED"),
        }
    }
}

/// Stable, value-free `SCREAMING_SNAKE` token of a typed error, derived
/// from its variant path: `Bind` / `Busy` -> `BIND` / `BUSY`,
/// `Layout(ZeroFrames)` -> `LAYOUT.ZERO_FRAMES`, `Errno(105)` ->
/// `ERRNO_105`. Struct fields (after `{`) and `IfId(..)` payloads are left
/// out (the port is reported as `port=if<id>`), so no field value and no
/// `Debug` struct syntax reaches the output.
pub fn token(value: &impl fmt::Debug) -> String {
    let text = format!("{value:?}");
    let text = text.split('{').next().unwrap_or_default();
    let mut parts: Vec<String> = Vec::new();
    let mut skip_number = false;
    let mut chars = text.chars().peekable();
    while let Some(&first) = chars.peek() {
        if first.is_ascii_alphabetic() {
            let mut word = String::new();
            while let Some(&c) = chars.peek().filter(|c| c.is_ascii_alphanumeric()) {
                word.push(c);
                chars.next();
            }
            if word == "IfId" {
                skip_number = true;
            } else {
                parts.push(screaming(&word));
            }
        } else if first.is_ascii_digit() {
            let mut number = String::new();
            while let Some(&c) = chars.peek().filter(|c| c.is_ascii_digit()) {
                number.push(c);
                chars.next();
            }
            if !std::mem::take(&mut skip_number) {
                match parts.last_mut() {
                    Some(last) => {
                        last.push('_');
                        last.push_str(&number);
                    }
                    None => parts.push(number),
                }
            }
        } else {
            chars.next();
        }
    }
    if parts.is_empty() {
        return "UNKNOWN".to_owned();
    }
    parts.join(".")
}

fn screaming(word: &str) -> String {
    let chars: Vec<char> = word.chars().collect();
    let mut out = String::new();
    for (index, c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() && index > 0 {
            let previous = chars[index - 1];
            let next_lower = chars.get(index + 1).is_some_and(char::is_ascii_lowercase);
            if previous.is_ascii_lowercase()
                || previous.is_ascii_digit()
                || (previous.is_ascii_uppercase() && next_lower)
            {
                out.push('_');
            }
        }
        out.push(c.to_ascii_uppercase());
    }
    out
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
                Some(errno) => {
                    write!(formatter, "code={} errno={errno}", token(&error.stage()))
                }
                None => write!(formatter, "code={}", token(&error.stage())),
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

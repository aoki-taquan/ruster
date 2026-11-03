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
//!
//! # AF_PACKET (AFPKT-015)
//!
//! An AF_PACKET backend has no per-port session to attach: per port, in
//! `IfId` order, [`open_packet_ports`] resolves the configured device by
//! name in the router's namespace, reads its facts, and runs the AF_PACKET
//! device checks ([`evaluate_packet_device`]); only then does
//! [`PortHost::open_packet`] open every packet socket at once, a
//! failure-atomic transaction of `ruster-io-afpacket` that releases
//! whatever it acquired. The opened datapath owns the sockets and rings;
//! dropping it (after the drain) unmaps and closes them, so there is
//! nothing to close port by port and nothing that can stay attached.

use std::fmt;

use ruster_config::{
    InterfaceBindingV1, ValidatedAfPacketPortV1, ValidatedAfPacketV1, ValidatedAfXdpPortV1,
    ValidatedAfXdpV1, XdpAttachModeV1,
};
use ruster_control::{ActivationError, SequencerError, StorageAllocationError};
use ruster_core::IfId;
use ruster_io_afpacket::{ConfigError as PacketConfigError, PlatformError};
use ruster_io_xdp_native::{
    AttachError, CleanupError, DatapathError, RxFillSetupError, SessionConfigError, SessionError,
    SessionFailure, SessionStage, XdpPacketIoSetupError,
};

use super::checks::{
    evaluate_config_mtu, evaluate_device, evaluate_packet_device, CheckFailure, CheckPolicy,
    DeviceFacts, PrivilegeFailure, Probe, Warnings,
};
use super::engine::{port_label, Datapath, LinkMonitor, StopSignal};
use super::exit_guard::{ExitActions, ExitError};
use super::fs_confine::{FsFailure, FsReport};
use super::netlink::{IfName, NetlinkError};
use super::offload::Offload;
use super::privileges::{DropFailure, DropReport, Identity, PrivilegePolicy};
use super::seccomp::{ConfineFailure, ConfineReport, SeccompMode};
use super::watch::LinkTarget;

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
    /// The rtnetlink socket of the run-time link watch.
    Watch,
    /// `NativeSession::take_datapath`.
    Datapath,
    /// `RxFillEngine::new`.
    Engine,
    /// `XdpPacketIo::new`.
    Adapter,
    /// `ActivePublication::new` of generation 1.
    Activate,
    /// The link watcher and reload worker threads (H7).
    Workers,
    /// The privilege drop after activation (or of an output thread at
    /// spawn).
    PrivilegeDrop,
    /// The filesystem confinement after the privilege drop (H11; or of a
    /// thread in its prologue, or the ruleset before any thread).
    FsConfine,
    /// The syscall filter after the privilege drop (H8).
    Seccomp,
    /// The resources of the exit actions (`[exit-protection]`, OPS-EXIT),
    /// opened after activation and before the privilege drop.
    ExitProtection,
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
            Self::Watch => "watch",
            Self::Datapath => "datapath",
            Self::Engine => "engine",
            Self::Adapter => "adapter",
            Self::Activate => "activate",
            Self::Workers => "workers",
            Self::PrivilegeDrop => "privilege-drop",
            Self::FsConfine => "fs-confine",
            Self::Seccomp => "seccomp",
            Self::ExitProtection => "exit-protection",
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
    /// The link watch's rtnetlink socket could not be opened.
    Links(NetlinkError),
    /// The privilege drop after activation failed.
    PrivilegeDrop(DropFailure),
    /// The filesystem confinement failed.
    FsConfine(FsFailure),
    /// The syscall filter could not be installed or verified.
    Seccomp(ConfineFailure),
    /// A worker thread could not be spawned.
    Spawn,
    /// The AF_PACKET backend could not be opened (AFPKT-015).
    Packet(PacketOpenError),
    /// A resource of the exit actions could not be opened (OPS-EXIT).
    ExitProtection(ExitError),
    /// A failure injected by a test host.
    #[cfg(test)]
    Injected,
    /// A transient failure injected by a test host (retried like
    /// `BIND/BUSY`).
    #[cfg(test)]
    InjectedTransient,
}

impl Failure {
    /// Whether a startup that failed with this may succeed when retried
    /// after a full rollback (XDP-045): the kernel releases a closed
    /// socket's queue registration and UMEM accounting from deferred work,
    /// so right after a previous run (or a crash) a port can be briefly
    /// `BIND/BUSY` or `REGISTER_UMEM/MEMLOCK_LIMIT` (`ENOMEM` there too),
    /// and any session stage can report `EAGAIN`. Everything else is a
    /// configuration, privilege, or device problem and is never retried.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Session(error) => transient_open(error.stage(), error.failure()),
            #[cfg(test)]
            Self::InjectedTransient => true,
            _ => false,
        }
    }
}

/// `EAGAIN`.
const EAGAIN: u16 = 11;

/// The transient session failures of [`Failure::is_transient`].
pub const fn transient_open(stage: SessionStage, failure: SessionFailure) -> bool {
    matches!(
        (stage, failure),
        (SessionStage::Bind, SessionFailure::Busy)
            | (
                SessionStage::RegisterUmem,
                SessionFailure::MemlockLimit | SessionFailure::OutOfMemory
            )
            | (_, SessionFailure::Errno(EAGAIN))
    )
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequencer(SequencerError::Bridge(error)) => {
                write!(formatter, "code={}", error.code())
            }
            Self::Sequencer(error) => write!(formatter, "code={}", token(error)),
            Self::Storage(error) => write!(formatter, "code=ALLOCATION.{}", token(&error.service)),
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
            Self::Links(error) => write!(formatter, "code={}", token(error)),
            Self::PrivilegeDrop(error) => write!(formatter, "{error}"),
            Self::FsConfine(error) => write!(formatter, "{error}"),
            Self::Seccomp(error) => write!(formatter, "{error}"),
            Self::Spawn => formatter.write_str("code=THREAD_SPAWN"),
            Self::Packet(error) => write!(formatter, "code={error}"),
            Self::ExitProtection(error) => write!(formatter, "code={error}"),
            #[cfg(test)]
            Self::Injected => formatter.write_str("code=INJECTED"),
            #[cfg(test)]
            Self::InjectedTransient => formatter.write_str("code=INJECTED_TRANSIENT"),
        }
    }
}

/// Why the AF_PACKET backend could not be opened. Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketOpenError {
    /// The page size could not be read, or the compiled TPACKET_V3 layout
    /// is not the kernel's ([`PlatformError`]).
    Platform(PlatformError),
    /// The backend refused the configured geometry at this page size (or
    /// an interface index) before acquiring anything.
    Config(PacketConfigError),
    /// The resolved ports do not match the configuration (internal).
    Ports,
}

impl fmt::Display for PacketOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(PlatformError::Syscall { stage, errno }) => {
                write!(formatter, "{}/ERRNO_{}", token(stage), errno.get())
            }
            Self::Platform(error) => formatter.write_str(&token(error)),
            Self::Config(error) => write!(formatter, "CONFIG.{}", token(error)),
            Self::Ports => formatter.write_str("PORTS"),
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
    /// What the link watch checks this port against (from the checked
    /// device facts).
    pub link: LinkTarget,
}

/// What [`PortHost::inspect_packet`] reads of one AF_PACKET port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketFacts {
    /// The device facts of the index the name resolved to (`session_mtu`
    /// is the MTU of that answer, `frame_capacity` the configured
    /// `max-frame-len`).
    pub device: DeviceFacts,
    /// The first active merging receive offload, `None` if all are off;
    /// `Err` if unreadable.
    pub offload: Result<Option<Offload>, ()>,
}

/// The operations startup and teardown need from the platform.
pub trait PortHost {
    type Session;
    type Datapath<'s>: Datapath
    where
        Self: 's;
    /// The AF_PACKET datapath (AFPKT-015): owns its sockets and rings.
    type Packet: Datapath;
    /// Moved to the link watcher thread (H7), hence `Send`.
    type Links: LinkMonitor + Send + 'static;
    /// The exit actions of `[exit-protection]` (OPS-EXIT).
    type Exit: ExitActions;

    /// Whether the process runs in the initial user namespace; `None` if
    /// that cannot be read.
    fn initial_user_namespace(&self) -> Option<bool>;

    /// Opens what the exit actions of `protection` need for every port of
    /// `targets` (after activation, before the privilege drop and any
    /// confinement): the forwarding sysctl files write-only, the rtnetlink
    /// socket. On error nothing stays open; the error names the port.
    fn exit_actions(
        &self,
        protection: ruster_config::ExitProtectionV1,
        targets: &[LinkTarget],
    ) -> Result<Self::Exit, (Option<IfId>, ExitError)>;

    /// Opens the run-time link watch (before the datapath is built).
    /// `devices` are the ports' interfaces and kernel device names, in
    /// `IfId` order (for the forwarding sysctls).
    fn links(&self, devices: &[(IfId, &str)]) -> Result<Self::Links, Failure>;

    /// The per-thread privilege drop each worker thread runs first (the
    /// live one drops the calling thread's privileges, see
    /// [`super::privileges::linux::drop_thread`], and then confines its
    /// filesystem view, see [`super::fs_confine`]).
    fn thread_prologue(&self) -> fn(PrivilegePolicy) -> Result<(), DropFailure>;

    /// Capabilities and memlock for `backend`, and the preconditions of
    /// the privilege drop of `policy`, before any resource.
    fn preflight(
        &self,
        backend: &ValidatedAfXdpV1,
        policy: PrivilegePolicy,
    ) -> Result<(), PrivilegeFailure>;

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

    /// Drops every privilege of the process after startup (and switches to
    /// `identity`), irreversibly, and verifies every thread.
    fn lockdown(&self, identity: Option<Identity>) -> Result<DropReport, DropFailure>;

    /// Confines the calling (router) thread's filesystem view after the
    /// privilege drop and requires every thread of the process to be
    /// confined (the others confined themselves in their prologue, see
    /// [`super::fs_confine`]).
    fn fs_confine(&self) -> Result<FsReport, FsFailure>;

    /// Installs the syscall filter of `mode` (never `Off`) on every thread
    /// of the process after the privilege drop, and verifies every thread.
    fn confine(&self, mode: SeccompMode) -> Result<ConfineReport, ConfineFailure>;

    /// Detaches (if attached) and closes one session, releasing every
    /// resource even when a step reports an error.
    fn close(&self, session: Self::Session) -> Result<(), CloseFailure>;

    /// AF_PACKET: `CAP_NET_RAW` and the preconditions of the privilege
    /// drop of `policy`, before any resource.
    fn preflight_packet(&self, policy: PrivilegePolicy) -> Result<(), PrivilegeFailure>;

    /// AF_PACKET: resolves `port`'s device by name in the router's network
    /// namespace and reads its facts (`frame_capacity` is
    /// `max_frame_len`) and receive offloads. Acquires nothing that
    /// outlives the call.
    fn inspect_packet(
        &self,
        port: &ValidatedAfPacketPortV1,
        max_frame_len: u32,
    ) -> Result<PacketFacts, CheckFailure>;

    /// AF_PACKET: opens every port of `backend` at once, each bound to the
    /// interface index of its checked target (`targets` in `IfId` order,
    /// one per port). Failure atomic: on error nothing stays open.
    fn open_packet(
        &self,
        backend: &ValidatedAfPacketV1,
        targets: &[LinkTarget],
    ) -> Result<Self::Packet, Failure>;
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

/// The link watch target of a port whose device facts passed the checks.
pub const fn link_target(interface: IfId, facts: &DeviceFacts) -> LinkTarget {
    LinkTarget {
        watch_uppers: false,
        interface,
        ifindex: facts.ifindex,
        name: facts.link_name,
        mtu: facts.session_mtu,
        frame_capacity: facts.frame_capacity,
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
/// `warn` receives each port's non-fatal check findings. `interfaces` are
/// the configured interfaces, whose `mtu` the device must carry
/// ([`evaluate_config_mtu`]).
pub fn open_ports<H: PortHost, S: StopSignal>(
    opened: &mut OpenedPorts<'_, H>,
    backend: &ValidatedAfXdpV1,
    interfaces: &[InterfaceBindingV1],
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
        opened.ports.push(OpenPort {
            interface,
            session,
            link: LinkTarget {
                interface,
                ifindex: 0,
                name: IfName::DEFAULT,
                mtu: 0,
                frame_capacity: 0,
                watch_uppers: false,
            },
        });
        let Some(entry) = opened.ports.last_mut() else {
            unreachable!("a port was just pushed");
        };
        let facts = host
            .inspect(port, &entry.session)
            .map_err(|failure| fail(Stage::Checks, Failure::Check(failure)))?;
        // The session's index must still carry the configured name: the
        // sysctl paths of the checks and of the link watch name the
        // device (H10; the watch then compares it every round).
        if IfName::new(port.device().as_bytes()) != Some(facts.link_name) {
            return Err(fail(
                Stage::Checks,
                Failure::Check(CheckFailure::Unverifiable(Probe::Name)),
            ));
        }
        let mut warnings = evaluate_device(&facts, policy)
            .map_err(|failure| fail(Stage::Checks, Failure::Check(failure)))?;
        // Validation binds every port to a configured interface; a miss
        // fails closed.
        let config_mtu = interfaces
            .iter()
            .find(|binding| binding.id() == interface)
            .map(InterfaceBindingV1::mtu)
            .ok_or_else(|| {
                fail(
                    Stage::Checks,
                    Failure::Check(CheckFailure::Unverifiable(Probe::Mtu)),
                )
            })?;
        warnings.mtu_below_device = evaluate_config_mtu(config_mtu, &facts)
            .map_err(|failure| fail(Stage::Checks, Failure::Check(failure)))?;
        entry.link = link_target(interface, &facts);
        warn(interface, &warnings);
        if stop.stop() {
            return Err(Interrupt::Signalled);
        }
        host.attach(&mut entry.session, port.attach())
            .map_err(|failure| fail(Stage::Attach, failure))?;
    }
    Ok(())
}

/// Resolves and checks every AF_PACKET port of `backend` in `IfId` order
/// ([`evaluate_packet_device`], with the device name check of H10, then
/// the configured interface MTU of MTU1, [`evaluate_config_mtu`]: above
/// the device MTU refused `MTU_BELOW_CONFIG`, below it the warning
/// `MTU_BELOW_DEVICE`) and returns their link watch targets. Nothing is
/// opened: on `Err` there is nothing to roll back. `warn` receives each
/// port's non-fatal findings.
pub fn open_packet_ports<H: PortHost, S: StopSignal>(
    host: &H,
    backend: &ValidatedAfPacketV1,
    interfaces: &[InterfaceBindingV1],
    policy: CheckPolicy,
    stop: &S,
    mut warn: impl FnMut(IfId, &Warnings),
) -> Result<Vec<LinkTarget>, Interrupt> {
    let mut targets = Vec::with_capacity(backend.ports().len());
    for port in backend.ports() {
        let interface = port.interface();
        let fail = |failure| {
            Interrupt::Failed(StartupError::new(
                Stage::Checks,
                Some(interface),
                Failure::Check(failure),
            ))
        };
        if stop.stop() {
            return Err(Interrupt::Signalled);
        }
        let facts = host
            .inspect_packet(port, backend.max_frame_len())
            .map_err(fail)?;
        // The resolved index must carry the configured name: the sysctl
        // paths of the checks and of the link watch name the device (H10).
        if IfName::new(port.device().as_bytes()) != Some(facts.device.link_name) {
            return Err(fail(CheckFailure::Unverifiable(Probe::Name)));
        }
        let mut warnings =
            evaluate_packet_device(&facts.device, facts.offload, policy).map_err(fail)?;
        // Validation binds every port to a configured interface; a miss
        // fails closed.
        let config_mtu = interfaces
            .iter()
            .find(|binding| binding.id() == interface)
            .map(InterfaceBindingV1::mtu)
            .ok_or_else(|| fail(CheckFailure::Unverifiable(Probe::Mtu)))?;
        warnings.mtu_below_device = evaluate_config_mtu(config_mtu, &facts.device).map_err(fail)?;
        targets.push(LinkTarget {
            watch_uppers: true,
            ..link_target(interface, &facts.device)
        });
        warn(interface, &warnings);
    }
    Ok(targets)
}

//! Cold-path XDP interface attachment through Linux rtnetlink.
//!
//! The wire layout in this module is pinned to the reviewed Linux headers:
//! `/usr/src/linux-headers-6.8.0-137/include/uapi/linux/netlink.h:9,37-58,62-79,98-125` defines
//! `NETLINK_ROUTE`, `sockaddr_nl`, `struct nlmsghdr`, request/ACK flags,
//! `NLMSG_ALIGN`, and `struct nlmsgerr`; `/usr/src/linux-headers-6.8.0-137/include/uapi/linux/rtnetlink.h:24-35`
//! defines `RTM_SETLINK`, `:211-226` defines `struct rtattr` and `RTA_ALIGN`,
//! and `:561-568` defines `struct ifinfomsg`; `/usr/src/linux-headers-6.8.0-137/include/uapi/linux/if_link.h:350`
//! defines `IFLA_XDP`, while `:1870-1879` defines the XDP flags and
//! `:1891-1903` defines the nested XDP attribute numbers.  A direct compile
//! against the installed `<linux/if_link.h>` measured
//! `IFLA_XDP_EXPECTED_FD = 8` and `__IFLA_XDP_MAX = 9`; the latter is the enum
//! sentinel, not an attribute type.  `XDP_FLAGS_REPLACE` is bit 4.
//! The installed libbpf `bpf_xdp_detach` implementation was also checked: it
//! sends fd `-1`, adds `XDP_FLAGS_REPLACE`, and forwards `old_prog_fd` as the
//! expected-fd attribute.  This module follows that identity-guarded detach
//! contract while retaining `XDP_FLAGS_UPDATE_IF_NOEXIST` for attach.
//!
//! The outer `IFLA_XDP` container uses the legacy `rtattr` representation used
//! by rtnetlink. Its `rta_len` includes every inner attribute header, payload,
//! and alignment padding. Every request in this profile is four-byte aligned,
//! so `nlmsg_len` equals the actual byte extent passed to the socket.

use crate::{
    ensure_native_syscall_supported, XdpAttachConfigError, XdpAttachError, XdpAttachOperation,
};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
use crate::NativeSyscallPlatformError;

/// `RTM_SETLINK` from `linux/rtnetlink.h:24-35`.
pub const RTM_SETLINK: u16 = 19;
/// `NLM_F_REQUEST` from `linux/netlink.h:62-67`.
pub const NLM_F_REQUEST: u16 = 0x01;
/// `NLM_F_ACK` from `linux/netlink.h:62-67`.
pub const NLM_F_ACK: u16 = 0x04;
/// `IFLA_XDP` from the link-attribute enum at `linux/if_link.h:350`.
pub const IFLA_XDP: u16 = 43;
/// `IFLA_XDP_FD` from `linux/if_link.h:1891-1894`.
pub const IFLA_XDP_FD: u16 = 1;
/// `IFLA_XDP_FLAGS` from `linux/if_link.h:1891-1894`.
pub const IFLA_XDP_FLAGS: u16 = 3;
/// `IFLA_XDP_EXPECTED_FD` from `linux/if_link.h:1891-1903`.
///
/// A direct compile against the installed Linux header measured this enum
/// value as 8. The following `__IFLA_XDP_MAX` value, 9, is only the enum
/// sentinel and must not be sent as an attribute type.
pub const IFLA_XDP_EXPECTED_FD: u16 = 8;
/// `XDP_FLAGS_UPDATE_IF_NOEXIST` from `linux/if_link.h:1870-1879`.
pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
/// `XDP_FLAGS_SKB_MODE` from `linux/if_link.h:1870-1879`.
pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
/// `XDP_FLAGS_DRV_MODE` from `linux/if_link.h:1870-1879`.
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
/// `XDP_FLAGS_REPLACE` from `linux/if_link.h:1870-1879`.
///
/// This is used only for detach requests carrying
/// [`IFLA_XDP_EXPECTED_FD`]. It is intentionally not accepted by
/// [`ValidatedXdpAttachFlags`] for attach, where the no-replace policy remains
/// [`XDP_FLAGS_UPDATE_IF_NOEXIST`].
pub const XDP_FLAGS_REPLACE: u32 = 1 << 4;

const SUPPORTED_ATTACH_FLAGS: u32 =
    XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE;
const XDP_MODE_FLAGS: u32 = XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE;

/// XDP execution mode selected for an interface attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpAttachMode {
    /// Generic SKB mode, which is available for veth and does not require a
    /// driver-specific zero-copy XDP hook.
    Skb,
    /// Native driver mode, which depends on the selected NIC driver.
    Drv,
}

impl XdpAttachMode {
    const fn flag(self) -> u32 {
        match self {
            Self::Skb => XDP_FLAGS_SKB_MODE,
            Self::Drv => XDP_FLAGS_DRV_MODE,
        }
    }
}

/// A validated XDP attach flag word.
///
/// The value always contains exactly one of SKB/DRV and
/// `XDP_FLAGS_UPDATE_IF_NOEXIST`. The latter is an intentional safety
/// invariant: an existing interface program is never silently overwritten.
/// `XDP_FLAGS_REPLACE` and HW mode are not admitted by this initial profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedXdpAttachFlags {
    raw: u32,
    mode: XdpAttachMode,
}

impl ValidatedXdpAttachFlags {
    /// Validates raw Linux XDP attach flags.
    ///
    /// Both SKB and DRV together are rejected. A mode and
    /// `XDP_FLAGS_UPDATE_IF_NOEXIST` are required so that the default and all
    /// raw-flag construction paths preserve the no-silent-replacement policy.
    pub const fn new(raw: u32) -> Result<Self, XdpAttachConfigError> {
        let unsupported = raw & !SUPPORTED_ATTACH_FLAGS;
        if unsupported != 0 {
            return Err(XdpAttachConfigError::UnsupportedFlags(unsupported));
        }
        if raw & XDP_MODE_FLAGS == XDP_MODE_FLAGS {
            return Err(XdpAttachConfigError::ConflictingModes);
        }
        let mode = if raw & XDP_FLAGS_SKB_MODE != 0 {
            XdpAttachMode::Skb
        } else if raw & XDP_FLAGS_DRV_MODE != 0 {
            XdpAttachMode::Drv
        } else {
            return Err(XdpAttachConfigError::MissingMode);
        };
        if raw & XDP_FLAGS_UPDATE_IF_NOEXIST == 0 {
            return Err(XdpAttachConfigError::UpdateIfNoExistRequired);
        }
        Ok(Self { raw, mode })
    }

    /// Creates the safe no-replace flag word for one supported mode.
    #[must_use]
    pub const fn for_mode(mode: XdpAttachMode) -> Self {
        Self {
            raw: XDP_FLAGS_UPDATE_IF_NOEXIST | mode.flag(),
            mode,
        }
    }

    /// Returns the exact Linux flag word sent in `IFLA_XDP_FLAGS`.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.raw
    }

    /// Returns the selected XDP execution mode.
    #[must_use]
    pub const fn mode(self) -> XdpAttachMode {
        self.mode
    }
}

impl Default for ValidatedXdpAttachFlags {
    /// Uses SKB mode because it works for veth while DRV mode is NIC-driver
    /// dependent. Existing programs are protected by UPDATE_IF_NOEXIST.
    fn default() -> Self {
        Self::for_mode(XdpAttachMode::Skb)
    }
}

impl TryFrom<u32> for ValidatedXdpAttachFlags {
    type Error = XdpAttachConfigError;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        Self::new(raw)
    }
}

/// Short name for [`ValidatedXdpAttachFlags`].
pub type XdpAttachFlags = ValidatedXdpAttachFlags;

/// Option-oriented alias for [`ValidatedXdpAttachFlags`].
pub type XdpAttachOptions = ValidatedXdpAttachFlags;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use std::os::fd::RawFd;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use std::io::Write;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use crate::native_unsafe::syscall::{LinuxSyscalls, NetlinkSyscalls, RecvMessage};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
static NETLINK_SYSCALLS: LinuxSyscalls = LinuxSyscalls;

/// An active XDP interface attachment.
///
/// The attachment owns its netlink socket and a duplicate of the loaded
/// program fd. It sends `IFLA_XDP_FD = -1`, `XDP_FLAGS_REPLACE`, and that
/// duplicate as `IFLA_XDP_EXPECTED_FD` during [`Self::detach`] or `Drop`.
/// Consequently a program installed by another process is not removed when
/// the expected identity no longer matches.
pub struct XdpAttachment {
    ifindex: u32,
    mode: XdpAttachMode,
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    inner: NetlinkAttachment<'static, LinuxSyscalls>,
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )))]
    _unsupported: (),
}

impl XdpAttachment {
    /// Returns the interface index targeted by this attachment.
    #[must_use]
    pub const fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Returns the mode used by the attach request.
    #[must_use]
    pub const fn mode(&self) -> XdpAttachMode {
        self.mode
    }

    /// Reports whether the kernel attachment is still considered active by
    /// this owner.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        ))]
        {
            self.inner.active
        }
        #[cfg(not(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        )))]
        {
            false
        }
    }

    /// Detaches the program and returns the netlink/kernel error, if any.
    ///
    /// The active marker is cleared only after an ACK with
    /// `nlmsgerr.error == 0`. If an explicit detach fails, `Drop` retains one
    /// best-effort attempt so a transient failure does not silently leave the
    /// program attached without another opportunity to remove it.
    pub fn detach(&mut self) -> Result<(), XdpAttachError> {
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        ))]
        {
            self.inner.detach()
        }
        #[cfg(not(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        )))]
        {
            Err(XdpAttachError::Platform(unsupported_platform_error()))
        }
    }
}

impl Drop for XdpAttachment {
    fn drop(&mut self) {
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        ))]
        {
            // The inner owner performs the best-effort detach in its Drop
            // implementation. Drop cannot return that error; callers that
            // need a reported failure must call detach().
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub(crate) fn attach_program(
    program_fd: RawFd,
    ifindex: u32,
    flags: ValidatedXdpAttachFlags,
) -> Result<XdpAttachment, XdpAttachError> {
    let inner = attach_with_syscalls(&NETLINK_SYSCALLS, program_fd, ifindex, flags)?;
    Ok(XdpAttachment {
        ifindex,
        mode: flags.mode(),
        inner,
    })
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
struct NetlinkAttachment<'syscalls, S: NetlinkSyscalls> {
    socket: OwnedNetlinkSocket<'syscalls, S>,
    ifindex: u32,
    mode: XdpAttachMode,
    expected_program_fd: Option<RawFd>,
    active: bool,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
enum AttachTransactionResult {
    /// The request was completely acknowledged by the kernel.
    Success,
    /// `sendto(2)` returned an errno, so no rollback is warranted.
    NotSubmitted(XdpAttachError),
    /// A complete `NLMSG_ERROR` carried a negative errno from the kernel.
    /// The request was explicitly rejected and must not trigger detach.
    KernelRejected(XdpAttachError),
    /// The request was accepted by `sendto(2)`, but its final disposition is
    /// unknown because the response transport or protocol was unusable.
    StateUnknown(XdpAttachError),
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
/// A provisional owner held from attach submission until its ACK is known.
///
/// An accepted `sendto(2)` does not by itself prove that the kernel applied
/// the request. Therefore this owner arms a single best-effort detach whenever
/// the subsequent response is not a clear ACK or a clear kernel rejection.
/// Keeping the socket here is important: rollback must happen before the fd
/// is closed, and the `Option` transfer makes the close owner unambiguous.
struct PendingNetlinkAttachment<'syscalls, S: NetlinkSyscalls> {
    socket: Option<OwnedNetlinkSocket<'syscalls, S>>,
    ifindex: u32,
    mode: XdpAttachMode,
    expected_program_fd: Option<RawFd>,
    rollback_needed: bool,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<'syscalls, S: NetlinkSyscalls> NetlinkAttachment<'syscalls, S> {
    fn detach(&mut self) -> Result<(), XdpAttachError> {
        if !self.active {
            return Ok(());
        }
        let sequence = self.socket.next_sequence();
        let expected_program_fd = self
            .expected_program_fd
            .expect("active XDP attachment owns expected program fd");
        let request = encode_detach_message(
            self.ifindex,
            self.mode,
            expected_program_fd,
            sequence,
            self.socket.portid,
        );
        self.socket
            .transact(&request, sequence, XdpAttachOperation::Detach)?;
        self.active = false;
        self.close_expected_program_fd()
    }

    fn close_expected_program_fd(&mut self) -> Result<(), XdpAttachError> {
        let Some(fd) = self.expected_program_fd.take() else {
            return Ok(());
        };
        self.socket
            .syscalls
            .close(fd)
            .map_err(|errno| map_syscall_error(XdpAttachOperation::CloseExpectedProgramFd, errno))
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<'syscalls, S: NetlinkSyscalls> PendingNetlinkAttachment<'syscalls, S> {
    fn new(
        socket: OwnedNetlinkSocket<'syscalls, S>,
        ifindex: u32,
        mode: XdpAttachMode,
        expected_program_fd: RawFd,
    ) -> Self {
        Self {
            socket: Some(socket),
            ifindex,
            mode,
            expected_program_fd: Some(expected_program_fd),
            rollback_needed: false,
        }
    }

    fn socket(&self) -> &OwnedNetlinkSocket<'syscalls, S> {
        self.socket
            .as_ref()
            .expect("pending netlink attachment owns its socket")
    }

    fn socket_mut(&mut self) -> &mut OwnedNetlinkSocket<'syscalls, S> {
        self.socket
            .as_mut()
            .expect("pending netlink attachment owns its socket")
    }

    fn transact_attach(&mut self, request: &[u8], sequence: u32) -> AttachTransactionResult {
        let outcome = self.socket().transact_attach(request, sequence);
        if matches!(outcome, AttachTransactionResult::StateUnknown(_)) {
            // `transact_attach` only returns StateUnknown after sendto(2)
            // accepted the request. Arm the guard before returning the error
            // so an unwind in the caller cannot lose the rollback opportunity.
            self.rollback_needed = true;
        }
        outcome
    }

    fn activate(mut self) -> NetlinkAttachment<'syscalls, S> {
        self.rollback_needed = false;
        NetlinkAttachment {
            socket: self
                .socket
                .take()
                .expect("pending netlink attachment owns its socket"),
            ifindex: self.ifindex,
            mode: self.mode,
            expected_program_fd: Some(
                self.expected_program_fd
                    .take()
                    .expect("pending XDP attachment owns expected program fd"),
            ),
            active: true,
        }
    }

    fn rollback(&mut self) -> Result<(), XdpAttachError> {
        if !self.rollback_needed {
            return Ok(());
        }

        let socket = self
            .socket
            .as_mut()
            .expect("pending netlink attachment owns its socket");
        let expected_program_fd = self
            .expected_program_fd
            .expect("pending XDP attachment owns expected program fd");
        let sequence = socket.next_sequence();
        let request = encode_detach_message(
            self.ifindex,
            self.mode,
            expected_program_fd,
            sequence,
            socket.portid,
        );
        socket.transact(&request, sequence, XdpAttachOperation::Detach)?;
        // Keep the guard armed when the detach fails so Drop gets one bounded
        // retry. Clear it only after a successful detach ACK; Drop calls this
        // method at most once and therefore cannot loop indefinitely.
        self.rollback_needed = false;
        let fd = self
            .expected_program_fd
            .take()
            .expect("pending XDP attachment owns expected program fd");
        socket
            .syscalls
            .close(fd)
            .map_err(|errno| map_syscall_error(XdpAttachOperation::CloseExpectedProgramFd, errno))
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<S: NetlinkSyscalls> Drop for PendingNetlinkAttachment<'_, S> {
    fn drop(&mut self) {
        if self.rollback_needed {
            // Drop cannot return an error. This fallback preserves the
            // best-effort rollback if an attach path unwinds before it can
            // report the original state-unknown error. The failure is still
            // emitted so an operator can detect a potentially orphaned XDP
            // program instead of mistaking the unwind for a clean rollback.
            if let Err(error) = self.rollback() {
                report_drop_error("AF_XDP attach rollback", &error);
            }
        }
        if let Some(fd) = self.expected_program_fd.take() {
            if let Some(socket) = self.socket.as_ref() {
                // The explicit rollback path returns close failures. This is
                // only the unavoidable best-effort path during unwinding.
                if let Err(errno) = socket.syscalls.close(fd) {
                    let error =
                        map_syscall_error(XdpAttachOperation::CloseExpectedProgramFd, errno);
                    report_drop_error("AF_XDP rollback identity-fd close", &error);
                }
            }
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<S: NetlinkSyscalls> Drop for NetlinkAttachment<'_, S> {
    fn drop(&mut self) {
        // Drop cannot return an error. This is deliberately best effort so an
        // attached program gets one teardown attempt during unwinding; callers
        // that need an observable error must call XdpAttachment::detach().
        if let Err(error) = self.detach() {
            report_drop_error("AF_XDP detach during Drop", &error);
        }
        if let Some(fd) = self.expected_program_fd.take() {
            if let Err(errno) = self.socket.syscalls.close(fd) {
                let error = map_syscall_error(XdpAttachOperation::CloseExpectedProgramFd, errno);
                report_drop_error("AF_XDP expected-program fd close during Drop", &error);
            }
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn attach_with_syscalls<'syscalls, S: NetlinkSyscalls>(
    syscalls: &'syscalls S,
    program_fd: RawFd,
    ifindex: u32,
    flags: ValidatedXdpAttachFlags,
) -> Result<NetlinkAttachment<'syscalls, S>, XdpAttachError> {
    validate_ifindex(ifindex)?;
    if program_fd < 0 {
        return Err(XdpAttachError::InvalidProgramFileDescriptor { fd: program_fd });
    }

    let socket = OwnedNetlinkSocket::open(syscalls)?;
    let expected_program_fd = syscalls
        .dup_cloexec(program_fd)
        .map_err(|errno| map_syscall_error(XdpAttachOperation::DuplicateProgramFd, errno))?;
    if expected_program_fd < 0 {
        return Err(XdpAttachError::InvalidProgramFileDescriptor {
            fd: expected_program_fd,
        });
    }
    let mut pending =
        PendingNetlinkAttachment::new(socket, ifindex, flags.mode(), expected_program_fd);
    let sequence = pending.socket_mut().next_sequence();
    let request = encode_attach_message(
        ifindex,
        program_fd,
        flags.raw(),
        sequence,
        pending.socket().portid,
    );
    match pending.transact_attach(&request, sequence) {
        AttachTransactionResult::Success => Ok(pending.activate()),
        AttachTransactionResult::NotSubmitted(error)
        | AttachTransactionResult::KernelRejected(error) => Err(error),
        AttachTransactionResult::StateUnknown(error) => {
            // The request was submitted but its attach result is unknowable.
            // Attempt rollback while the provisional owner still holds the
            // socket. Preserve both the original uncertainty and a rollback
            // failure in the API result so an orphaned program cannot be
            // mistaken for an ordinary attach error.
            //
            // `UPDATE_IF_NOEXIST` protects the normal request from replacing
            // an existing program, and a complete negative NLMSG_ERROR is
            // handled above without rollback. A lost or malformed response
            // cannot, however, distinguish an applied attach from an
            // existing-program rejection; the Linux detach form has no
            // program identity and could remove whichever program is then
            // installed. That is an unavoidable residual ambiguity of this
            // raw UAPI transaction, retained here only for the required
            // best-effort cleanup of a possibly applied attach.
            match pending.rollback() {
                Ok(()) => Err(error),
                Err(rollback) => Err(XdpAttachError::StateUnknownRollback {
                    original: Box::new(error),
                    rollback: Box::new(rollback),
                }),
            }
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
struct OwnedNetlinkSocket<'syscalls, S: NetlinkSyscalls> {
    syscalls: &'syscalls S,
    fd: Option<RawFd>,
    portid: u32,
    next_sequence: u32,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<'syscalls, S: NetlinkSyscalls> OwnedNetlinkSocket<'syscalls, S> {
    fn open(syscalls: &'syscalls S) -> Result<Self, XdpAttachError> {
        ensure_native_syscall_supported().map_err(XdpAttachError::Platform)?;
        let fd = syscalls
            .socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)
            .map_err(|errno| map_syscall_error(XdpAttachOperation::OpenSocket, errno))?;
        if fd < 0 {
            return Err(XdpAttachError::InvalidSocketFileDescriptor { fd });
        }
        let mut socket = Self {
            syscalls,
            fd: Some(fd),
            portid: 0,
            next_sequence: 1,
        };

        // Bind with nl_pid=0 so the kernel allocates a unique port ID, then
        // read that ID back below. Keeping it explicit in nlmsg_pid makes the
        // request identity auditable and avoids relying on implicit kernel
        // filling when matching the ACK sequence.
        let local = encode_sockaddr_nl(0, 0);
        socket
            .syscalls
            .bind(socket.raw(), &local, SOCKADDR_NL_LEN as u32)
            .map_err(|errno| map_syscall_error(XdpAttachOperation::BindSocket, errno))?;

        let mut address = [0_u8; SOCKADDR_NL_LEN];
        let mut address_len = SOCKADDR_NL_LEN as u32;
        socket
            .syscalls
            .getsockname(socket.raw(), &mut address, &mut address_len)
            .map_err(|errno| map_syscall_error(XdpAttachOperation::GetPortId, errno))?;
        let actual = address_len as usize;
        if actual > address.len() {
            return Err(XdpAttachError::PortIdResponseTooLong {
                actual,
                capacity: address.len(),
            });
        }
        if actual < SOCKADDR_NL_LEN {
            return Err(XdpAttachError::PortIdResponseTooShort {
                actual,
                minimum: SOCKADDR_NL_LEN,
            });
        }
        let family = read_u16(&address, 0);
        if family != AF_NETLINK as u16 {
            return Err(XdpAttachError::UnexpectedPortIdFamily { family });
        }
        socket.portid = read_u32(&address, 4);
        Ok(socket)
    }

    fn raw(&self) -> RawFd {
        self.fd.expect("owned netlink fd is active")
    }

    fn next_sequence(&mut self) -> u32 {
        let sequence = self.next_sequence;
        self.next_sequence = if sequence == u32::MAX {
            1
        } else {
            sequence + 1
        };
        sequence
    }

    fn transact(
        &self,
        request: &[u8],
        sequence: u32,
        operation: XdpAttachOperation,
    ) -> Result<(), XdpAttachError> {
        let sent = self.send_request(request)?;
        if sent != request.len() {
            return Err(XdpAttachError::ShortSend {
                expected: request.len(),
                actual: sent,
            });
        }
        self.receive_ack(sequence, operation)
    }

    fn transact_attach(&self, request: &[u8], sequence: u32) -> AttachTransactionResult {
        let sent = match self.send_request(request) {
            Ok(sent) => sent,
            Err(error) => return AttachTransactionResult::NotSubmitted(error),
        };
        if sent != request.len() {
            return AttachTransactionResult::StateUnknown(XdpAttachError::ShortSend {
                expected: request.len(),
                actual: sent,
            });
        }

        match self.receive_ack(sequence, XdpAttachOperation::Attach) {
            Ok(()) => AttachTransactionResult::Success,
            Err(error) => match error {
                XdpAttachError::KernelRejected {
                    operation: XdpAttachOperation::Attach,
                    ..
                }
                | XdpAttachError::PermissionDenied {
                    operation: XdpAttachOperation::Attach,
                } => AttachTransactionResult::KernelRejected(error),
                error => AttachTransactionResult::StateUnknown(error),
            },
        }
    }

    fn send_request(&self, request: &[u8]) -> Result<usize, XdpAttachError> {
        let destination = encode_sockaddr_nl(0, 0);
        self.syscalls
            .send_netlink(self.raw(), request, &destination)
            .map_err(|errno| map_syscall_error(XdpAttachOperation::SendMessage, errno))
    }

    fn receive_ack(
        &self,
        sequence: u32,
        operation: XdpAttachOperation,
    ) -> Result<(), XdpAttachError> {
        let mut response = [0_u8; NETLINK_RESPONSE_CAPACITY];
        let received = self
            .syscalls
            .recvmsg(self.raw(), &mut response)
            .map_err(|errno| map_syscall_error(XdpAttachOperation::ReceiveMessage, errno))?;
        inspect_ack(&response, received, sequence, operation)
    }

    fn close_once(&mut self) -> Result<(), XdpAttachError> {
        let Some(fd) = self.fd.take() else {
            return Ok(());
        };
        self.syscalls
            .close(fd)
            .map_err(|errno| map_syscall_error(XdpAttachOperation::CloseSocket, errno))
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<S: NetlinkSyscalls> Drop for OwnedNetlinkSocket<'_, S> {
    fn drop(&mut self) {
        // Socket close is best effort during ownership unwinding; explicit
        // attach/detach errors are returned by their public methods. A close
        // failure is nevertheless reported because it identifies a resource
        // leak in the cold control plane.
        if let Err(error) = self.close_once() {
            report_drop_error("AF_XDP netlink socket close during Drop", &error);
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn map_syscall_error(
    operation: XdpAttachOperation,
    errno: crate::native_unsafe::syscall::Errno,
) -> XdpAttachError {
    if errno.raw() == Some(1) {
        XdpAttachError::PermissionDenied { operation }
    } else {
        XdpAttachError::Syscall {
            operation,
            errno: errno.raw(),
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn report_drop_error(context: &str, error: &XdpAttachError) {
    // `Drop` cannot return an error, and it may run while another panic is
    // unwinding. Use a fallible write rather than `eprintln!` so reporting a
    // closed stderr never causes a second panic that would abort the process.
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "ruster: {context} failed: {error}");
}

fn validate_ifindex(ifindex: u32) -> Result<(), XdpAttachError> {
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        Err(XdpAttachError::InvalidInterfaceIndex { ifindex })
    } else {
        Ok(())
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const AF_NETLINK: i32 = 16;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const NETLINK_ROUTE: i32 = 0;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
// AF_NETLINK is PF_NETLINK=16 at bits/socket.h:59 and aliases it at
// bits/socket.h:111. SOCK_RAW=3 is bits/socket_type.h:23-33.
const SOCK_RAW: i32 = 3;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
// SOCK_CLOEXEC=02000000 (0x80000) is bits/socket_type.h:46-51.
const SOCK_CLOEXEC: i32 = 0x8_0000;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
// MSG_TRUNC=0x20 is bits/socket.h:218-224.
const MSG_TRUNC: i32 = 0x20;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const NLMSG_HDRLEN: usize = 16;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const IFINFOMSG_LEN: usize = 16;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const RTATTR_HDRLEN: usize = 4;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const SOCKADDR_NL_LEN: usize = 12;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const NLMSGERR_LEN: usize = 20;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const NLMSG_ERROR_MESSAGE_LEN: usize = NLMSG_HDRLEN + NLMSGERR_LEN;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const NETLINK_RESPONSE_CAPACITY: usize = 4096;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn align4(length: usize) -> usize {
    (length + 3) & !3
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("checked u16 extent"),
    )
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked u32 extent"),
    )
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_ne_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked i32 extent"),
    )
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn append_rtattr(container: &mut Vec<u8>, attribute_type: u16, payload: &[u8]) {
    let length = RTATTR_HDRLEN + payload.len();
    let space = align4(length);
    let start = container.len();
    container.resize(start + space, 0);
    write_u16(
        container,
        start,
        u16::try_from(length).expect("fixed XDP rtattr fits u16"),
    );
    write_u16(container, start + 2, attribute_type);
    container[start + RTATTR_HDRLEN..start + length].copy_from_slice(payload);
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn encode_sockaddr_nl(portid: u32, groups: u32) -> [u8; SOCKADDR_NL_LEN] {
    let mut bytes = [0_u8; SOCKADDR_NL_LEN];
    // `sockaddr_nl` is `family`, `pad`, `nl_pid`, and `nl_groups` at
    // linux/netlink.h:37-42. A zero port ID in the destination means kernel.
    write_u16(&mut bytes, 0, AF_NETLINK as u16);
    write_u32(&mut bytes, 4, portid);
    write_u32(&mut bytes, 8, groups);
    bytes
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn encode_message(
    ifindex: u32,
    fd: i32,
    flags: Option<u32>,
    expected_fd: Option<i32>,
    sequence: u32,
    portid: u32,
) -> Vec<u8> {
    let mut link = [0_u8; IFINFOMSG_LEN];
    // `ifinfomsg` is family/pad/type/index/flags/change at
    // rtnetlink.h:561-568. RTM_SETLINK needs only the signed index here.
    write_i32(
        &mut link,
        4,
        i32::try_from(ifindex).expect("validated ifindex fits i32"),
    );

    let mut nested = Vec::with_capacity(16);
    append_rtattr(&mut nested, IFLA_XDP_FD, &fd.to_ne_bytes());
    if let Some(flags) = flags {
        append_rtattr(&mut nested, IFLA_XDP_FLAGS, &flags.to_ne_bytes());
    }
    if let Some(expected_fd) = expected_fd {
        append_rtattr(
            &mut nested,
            IFLA_XDP_EXPECTED_FD,
            &expected_fd.to_ne_bytes(),
        );
    }

    let mut body = Vec::with_capacity(IFINFOMSG_LEN + RTATTR_HDRLEN + nested.len());
    body.extend_from_slice(&link);
    append_rtattr(&mut body, IFLA_XDP, &nested);

    let nlmsg_len = NLMSG_HDRLEN + body.len();
    let mut message = vec![0_u8; align4(nlmsg_len)];
    write_u32(
        &mut message,
        0,
        u32::try_from(nlmsg_len).expect("fixed XDP netlink request fits u32"),
    );
    write_u16(&mut message, 4, RTM_SETLINK);
    write_u16(&mut message, 6, NLM_F_REQUEST | NLM_F_ACK);
    write_u32(&mut message, 8, sequence);
    write_u32(&mut message, 12, portid);
    message[NLMSG_HDRLEN..NLMSG_HDRLEN + body.len()].copy_from_slice(&body);
    message
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn encode_attach_message(
    ifindex: u32,
    program_fd: i32,
    flags: u32,
    sequence: u32,
    portid: u32,
) -> Vec<u8> {
    encode_message(ifindex, program_fd, Some(flags), None, sequence, portid)
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn encode_detach_message(
    ifindex: u32,
    mode: XdpAttachMode,
    expected_fd: i32,
    sequence: u32,
    portid: u32,
) -> Vec<u8> {
    encode_message(
        ifindex,
        -1,
        Some(XDP_FLAGS_REPLACE | mode.flag()),
        Some(expected_fd),
        sequence,
        portid,
    )
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn inspect_ack(
    response: &[u8],
    received: RecvMessage,
    expected_sequence: u32,
    operation: XdpAttachOperation,
) -> Result<(), XdpAttachError> {
    if received.flags & MSG_TRUNC != 0 {
        return Err(XdpAttachError::ResponseTruncated);
    }
    if received.byte_len > response.len() {
        return Err(XdpAttachError::ResponseLengthMismatch {
            declared: response.len(),
            actual: received.byte_len,
        });
    }
    if received.byte_len < NLMSG_HDRLEN {
        return Err(XdpAttachError::ResponseTooShort {
            actual: received.byte_len,
            minimum: NLMSG_HDRLEN,
        });
    }

    let bytes = &response[..received.byte_len];
    let declared = read_u32(bytes, 0) as usize;
    if declared < NLMSG_ERROR_MESSAGE_LEN {
        return Err(XdpAttachError::ResponseTooShort {
            actual: declared,
            minimum: NLMSG_ERROR_MESSAGE_LEN,
        });
    }
    let aligned = align4(declared);
    if aligned > received.byte_len {
        return Err(XdpAttachError::ResponseTooShort {
            actual: received.byte_len,
            minimum: aligned,
        });
    }
    if aligned != received.byte_len {
        return Err(XdpAttachError::ResponseLengthMismatch {
            declared,
            actual: received.byte_len,
        });
    }
    if read_u16(bytes, 4) != 2 {
        return Err(XdpAttachError::UnexpectedMessageType {
            message_type: read_u16(bytes, 4),
        });
    }
    let actual_sequence = read_u32(bytes, 8);
    if actual_sequence != expected_sequence {
        return Err(XdpAttachError::UnexpectedSequence {
            expected: expected_sequence,
            actual: actual_sequence,
        });
    }

    let error = read_i32(bytes, NLMSG_HDRLEN);
    if error == 0 {
        return Ok(());
    }
    if error > 0 {
        return Err(XdpAttachError::InvalidErrorCode { code: error });
    }
    let errno = error.checked_neg().and_then(|value| {
        if (1..=4_095).contains(&value) {
            Some(value as u16)
        } else {
            None
        }
    });
    if errno == Some(1) {
        Err(XdpAttachError::PermissionDenied { operation })
    } else {
        Err(XdpAttachError::KernelRejected { operation, errno })
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
fn unsupported_platform_error() -> NativeSyscallPlatformError {
    match ensure_native_syscall_supported() {
        Ok(()) => unreachable!("unsupported netlink path on a supported target"),
        Err(error) => error,
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod tests {
    use std::{cell::RefCell, os::fd::RawFd};

    use super::*;
    use crate::native_unsafe::syscall::{sealed, Errno};

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Socket {
            domain: i32,
            kind: i32,
            protocol: i32,
        },
        Bind(Vec<u8>),
        GetSocketName,
        Duplicate {
            fd: RawFd,
        },
        Send(Vec<u8>),
        Receive,
        Close {
            fd: RawFd,
        },
    }

    #[derive(Clone)]
    struct FakeResponse {
        bytes: Vec<u8>,
        byte_len: usize,
        flags: i32,
    }

    #[derive(Clone)]
    enum FakeReceive {
        Response(FakeResponse),
        Error(Errno),
    }

    struct FakeNetlinkSyscalls {
        calls: RefCell<Vec<Call>>,
        responses: RefCell<Vec<FakeReceive>>,
        portid: u32,
    }

    impl FakeNetlinkSyscalls {
        fn new(responses: Vec<FakeResponse>) -> Self {
            Self::with_transcript(responses.into_iter().map(FakeReceive::Response).collect())
        }

        fn with_transcript(responses: Vec<FakeReceive>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                responses: RefCell::new(responses),
                portid: 0x1122_3344,
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }
    }

    impl sealed::Sealed for FakeNetlinkSyscalls {}

    impl NetlinkSyscalls for FakeNetlinkSyscalls {
        fn socket(&self, domain: i32, kind: i32, protocol: i32) -> Result<RawFd, Errno> {
            self.calls.borrow_mut().push(Call::Socket {
                domain,
                kind,
                protocol,
            });
            Ok(77)
        }

        fn bind(&self, _fd: RawFd, address: &[u8], _length: u32) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::Bind(address.to_vec()));
            Ok(())
        }

        fn getsockname(
            &self,
            _fd: RawFd,
            address: &mut [u8],
            length: &mut u32,
        ) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::GetSocketName);
            address.fill(0);
            write_u16(address, 0, AF_NETLINK as u16);
            write_u32(address, 4, self.portid);
            *length = SOCKADDR_NL_LEN as u32;
            Ok(())
        }

        fn dup_cloexec(&self, fd: RawFd) -> Result<RawFd, Errno> {
            self.calls.borrow_mut().push(Call::Duplicate { fd });
            Ok(88)
        }

        fn send_netlink(
            &self,
            _fd: RawFd,
            message: &[u8],
            _destination: &[u8],
        ) -> Result<usize, Errno> {
            self.calls.borrow_mut().push(Call::Send(message.to_vec()));
            Ok(message.len())
        }

        fn recvmsg(&self, _fd: RawFd, buffer: &mut [u8]) -> Result<RecvMessage, Errno> {
            self.calls.borrow_mut().push(Call::Receive);
            let response = self.responses.borrow_mut().remove(0);
            match response {
                FakeReceive::Error(error) => Err(error),
                FakeReceive::Response(response) => {
                    let copy_len = response.bytes.len().min(buffer.len());
                    buffer[..copy_len].copy_from_slice(&response.bytes[..copy_len]);
                    Ok(RecvMessage {
                        byte_len: response.byte_len,
                        flags: response.flags,
                    })
                }
            }
        }

        fn close(&self, fd: RawFd) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::Close { fd });
            Ok(())
        }
    }

    struct ConfigurableNetlinkSyscalls {
        calls: RefCell<Vec<Call>>,
        responses: RefCell<Vec<FakeReceive>>,
        portid: u32,
        socket_fd: RawFd,
        duplicate_fd: RawFd,
        address_length: u32,
        close_error: Option<Errno>,
    }

    impl ConfigurableNetlinkSyscalls {
        fn new(responses: Vec<FakeResponse>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                responses: RefCell::new(responses.into_iter().map(FakeReceive::Response).collect()),
                portid: 0x1122_3344,
                socket_fd: 77,
                duplicate_fd: 88,
                address_length: SOCKADDR_NL_LEN as u32,
                close_error: None,
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }

        fn with_socket_fd(mut self, socket_fd: RawFd) -> Self {
            self.socket_fd = socket_fd;
            self
        }

        fn with_duplicate_fd(mut self, duplicate_fd: RawFd) -> Self {
            self.duplicate_fd = duplicate_fd;
            self
        }

        fn with_address_length(mut self, address_length: u32) -> Self {
            self.address_length = address_length;
            self
        }

        fn with_close_error(mut self, close_error: Errno) -> Self {
            self.close_error = Some(close_error);
            self
        }
    }

    impl sealed::Sealed for ConfigurableNetlinkSyscalls {}

    impl NetlinkSyscalls for ConfigurableNetlinkSyscalls {
        fn socket(&self, domain: i32, kind: i32, protocol: i32) -> Result<RawFd, Errno> {
            self.calls.borrow_mut().push(Call::Socket {
                domain,
                kind,
                protocol,
            });
            Ok(self.socket_fd)
        }

        fn bind(&self, _fd: RawFd, address: &[u8], _length: u32) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::Bind(address.to_vec()));
            Ok(())
        }

        fn getsockname(
            &self,
            _fd: RawFd,
            address: &mut [u8],
            length: &mut u32,
        ) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::GetSocketName);
            address.fill(0);
            write_u16(address, 0, AF_NETLINK as u16);
            write_u32(address, 4, self.portid);
            *length = self.address_length;
            Ok(())
        }

        fn dup_cloexec(&self, fd: RawFd) -> Result<RawFd, Errno> {
            self.calls.borrow_mut().push(Call::Duplicate { fd });
            Ok(self.duplicate_fd)
        }

        fn send_netlink(
            &self,
            _fd: RawFd,
            message: &[u8],
            _destination: &[u8],
        ) -> Result<usize, Errno> {
            self.calls.borrow_mut().push(Call::Send(message.to_vec()));
            Ok(message.len())
        }

        fn recvmsg(&self, _fd: RawFd, buffer: &mut [u8]) -> Result<RecvMessage, Errno> {
            self.calls.borrow_mut().push(Call::Receive);
            let response = self.responses.borrow_mut().remove(0);
            match response {
                FakeReceive::Error(error) => Err(error),
                FakeReceive::Response(response) => {
                    let copy_len = response.bytes.len().min(buffer.len());
                    buffer[..copy_len].copy_from_slice(&response.bytes[..copy_len]);
                    Ok(RecvMessage {
                        byte_len: response.byte_len,
                        flags: response.flags,
                    })
                }
            }
        }

        fn close(&self, fd: RawFd) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::Close { fd });
            match self.close_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    fn ack(sequence: u32, error: i32) -> FakeResponse {
        let mut bytes = vec![0_u8; NLMSG_ERROR_MESSAGE_LEN];
        write_u32(&mut bytes, 0, NLMSG_ERROR_MESSAGE_LEN as u32);
        write_u16(&mut bytes, 4, 2);
        write_u32(&mut bytes, 8, sequence);
        write_i32(&mut bytes, NLMSG_HDRLEN, error);
        FakeResponse {
            byte_len: bytes.len(),
            bytes,
            flags: 0,
        }
    }

    fn sent_messages(fake: &FakeNetlinkSyscalls) -> Vec<Vec<u8>> {
        fake.calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Send(message) => Some(message),
                _ => None,
            })
            .collect()
    }

    fn close_count(fake: &FakeNetlinkSyscalls) -> usize {
        fake.calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Close { .. }))
            .count()
    }

    fn public_attachment(ifindex: u32, active: bool) -> XdpAttachment {
        let mode = XdpAttachMode::Skb;
        XdpAttachment {
            ifindex,
            mode,
            inner: NetlinkAttachment {
                socket: OwnedNetlinkSocket {
                    syscalls: &NETLINK_SYSCALLS,
                    fd: None,
                    portid: 0,
                    next_sequence: 1,
                },
                ifindex,
                mode,
                expected_program_fd: None,
                active,
            },
        }
    }

    #[test]
    fn default_and_driver_flags_are_exact_and_raw_both_modes_are_rejected() {
        assert_eq!(ValidatedXdpAttachFlags::default().raw(), 3);
        assert_eq!(
            ValidatedXdpAttachFlags::for_mode(XdpAttachMode::Drv).raw(),
            XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE
        );
        assert_eq!(
            ValidatedXdpAttachFlags::new(
                XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE
            ),
            Err(XdpAttachConfigError::ConflictingModes)
        );
    }

    #[test]
    fn attach_message_is_exactly_aligned_and_contains_nested_fd_and_flags() {
        let message = encode_attach_message(7, 23, 3, 1, 0x1122_3344);
        assert_eq!(message.len(), 52);
        assert_eq!(
            message,
            vec![
                0x34, 0x00, 0x00, 0x00, 0x13, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x44, 0x33,
                0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x2b, 0x00, 0x08, 0x00, 0x01, 0x00, 0x17, 0x00,
                0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            u32::from_ne_bytes(message[0..4].try_into().unwrap()),
            message.len() as u32
        );
        assert_eq!(u16::from_ne_bytes(message[32..34].try_into().unwrap()), 20);
        assert_eq!(u16::from_ne_bytes(message[36..38].try_into().unwrap()), 8);
        assert_eq!(u16::from_ne_bytes(message[44..46].try_into().unwrap()), 8);
    }

    #[test]
    fn detach_message_uses_expected_fd_attribute_type_eight() {
        let message = encode_detach_message(7, XdpAttachMode::Skb, 2, 2, 0x1122_3344);
        assert_eq!(message.len(), 60);
        assert_eq!(u16::from_ne_bytes(message[54..56].try_into().unwrap()), 8);
        assert_eq!(
            message,
            vec![
                0x3c, 0x00, 0x00, 0x00, 0x13, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x44, 0x33,
                0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x2b, 0x00, 0x08, 0x00, 0x01, 0x00, 0xff, 0xff,
                0xff, 0xff, 0x08, 0x00, 0x03, 0x00, 0x12, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
                0x02, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            u32::from_ne_bytes(message[0..4].try_into().unwrap()),
            message.len() as u32
        );
        assert_eq!(u16::from_ne_bytes(message[32..34].try_into().unwrap()), 28);
        assert_eq!(
            u32::from_ne_bytes(message[48..52].try_into().unwrap()),
            XDP_FLAGS_REPLACE | XDP_FLAGS_SKB_MODE
        );
        assert_eq!(u16::from_ne_bytes(message[52..54].try_into().unwrap()), 8);
        assert_eq!(u16::from_ne_bytes(message[54..56].try_into().unwrap()), 8);
        assert_eq!(i32::from_ne_bytes(message[56..60].try_into().unwrap()), 2);
    }

    #[test]
    fn fake_transcript_uses_cloexec_socket_and_drop_attempts_detach() {
        let fake = FakeNetlinkSyscalls::new(vec![ack(1, 0), ack(2, 0)]);
        let flags = ValidatedXdpAttachFlags::for_mode(XdpAttachMode::Drv);
        {
            let attachment = attach_with_syscalls(&fake, 23, 7, flags).expect("fake attach ACK");
            assert!(attachment.active);
        }
        let sends: Vec<Vec<u8>> = fake
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Send(message) => Some(message),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 2);
        assert_eq!(
            sends[0],
            encode_attach_message(7, 23, flags.raw(), 1, 0x1122_3344)
        );
        assert_eq!(
            sends[1],
            encode_detach_message(7, XdpAttachMode::Drv, 88, 2, 0x1122_3344)
        );
        assert!(fake.calls().contains(&Call::Socket {
            domain: AF_NETLINK,
            kind: SOCK_RAW | SOCK_CLOEXEC,
            protocol: NETLINK_ROUTE,
        }));
        assert!(fake.calls().contains(&Call::Close { fd: 88 }));
    }

    #[test]
    fn explicit_detach_is_acknowledged_once() {
        let fake = FakeNetlinkSyscalls::new(vec![ack(1, 0), ack(2, 0)]);
        let mut attachment = attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default())
            .expect("fake attach ACK");
        attachment.detach().expect("fake detach ACK");
        assert!(!attachment.active);
        assert_eq!(
            sent_messages(&fake),
            vec![
                encode_attach_message(7, 23, 3, 1, 0x1122_3344),
                encode_detach_message(7, XdpAttachMode::Skb, 88, 2, 0x1122_3344),
            ]
        );
        drop(attachment);
        let sends = fake
            .calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Send(_)))
            .count();
        assert_eq!(sends, 2);
    }

    #[test]
    fn negative_nlmsgerr_is_typed_and_eperm_is_permission_denied() {
        let fake = FakeNetlinkSyscalls::new(vec![ack(1, -22)]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("negative netlink errno was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            XdpAttachError::KernelRejected {
                operation: XdpAttachOperation::Attach,
                errno: Some(22),
            }
        );
        assert_eq!(sent_messages(&fake).len(), 1);
        assert_eq!(close_count(&fake), 2);

        let fake = FakeNetlinkSyscalls::new(vec![ack(1, -1)]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("permission netlink errno was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            XdpAttachError::PermissionDenied {
                operation: XdpAttachOperation::Attach,
            }
        );
        assert!(error.is_permission_denied());
        assert_eq!(sent_messages(&fake).len(), 1);
        assert_eq!(close_count(&fake), 2);
    }

    #[test]
    fn short_and_truncated_responses_are_rejected() {
        let mut short_bytes = vec![0_u8; NLMSG_HDRLEN];
        write_u32(&mut short_bytes, 0, NLMSG_HDRLEN as u32);
        let short = FakeResponse {
            bytes: short_bytes,
            byte_len: NLMSG_HDRLEN,
            flags: 0,
        };
        let fake = FakeNetlinkSyscalls::new(vec![short, ack(2, 0)]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("short netlink response was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            XdpAttachError::ResponseTooShort {
                actual: NLMSG_HDRLEN,
                minimum: NLMSG_ERROR_MESSAGE_LEN,
            }
        );
        assert_eq!(sent_messages(&fake).len(), 2);
        assert_eq!(close_count(&fake), 2);

        let mut truncated = ack(1, 0);
        truncated.flags = MSG_TRUNC;
        let fake = FakeNetlinkSyscalls::new(vec![truncated, ack(2, 0)]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("truncated netlink response was accepted"),
            Err(error) => error,
        };
        assert_eq!(error, XdpAttachError::ResponseTruncated);
        assert_eq!(sent_messages(&fake).len(), 2);
        assert_eq!(close_count(&fake), 2);
    }

    #[test]
    fn receive_errno_after_submit_rolls_back_and_preserves_attach_error() {
        let fake = FakeNetlinkSyscalls::with_transcript(vec![
            FakeReceive::Error(Errno::Linux(11)),
            FakeReceive::Response(ack(2, 0)),
        ]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("recvmsg errno was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            XdpAttachError::Syscall {
                operation: XdpAttachOperation::ReceiveMessage,
                errno: Some(11),
            }
        );
        assert_eq!(
            sent_messages(&fake),
            vec![
                encode_attach_message(7, 23, 3, 1, 0x1122_3344),
                encode_detach_message(7, XdpAttachMode::Skb, 88, 2, 0x1122_3344),
            ]
        );
        assert_eq!(close_count(&fake), 2);
    }

    #[test]
    fn positive_nlmsgerr_is_malformed_and_rolls_back() {
        let fake = FakeNetlinkSyscalls::new(vec![ack(1, 7), ack(2, 0)]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("positive netlink error was accepted"),
            Err(error) => error,
        };
        assert_eq!(error, XdpAttachError::InvalidErrorCode { code: 7 });
        assert_eq!(sent_messages(&fake).len(), 2);
        assert_eq!(close_count(&fake), 2);
    }

    #[test]
    fn sequence_mismatch_is_state_unknown_and_rolls_back() {
        let fake = FakeNetlinkSyscalls::new(vec![ack(99, 0), ack(2, 0)]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("sequence mismatch was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            XdpAttachError::UnexpectedSequence {
                expected: 1,
                actual: 99,
            }
        );
        assert_eq!(sent_messages(&fake).len(), 2);
        assert_eq!(close_count(&fake), 2);
    }

    #[test]
    fn rollback_failure_does_not_replace_original_attach_error() {
        let fake = FakeNetlinkSyscalls::new(vec![ack(1, 7), ack(2, -16), ack(3, -16)]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("malformed netlink error was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            &error,
            XdpAttachError::StateUnknownRollback { original, rollback }
                if original.as_ref() == &(XdpAttachError::InvalidErrorCode { code: 7 })
                    && rollback.as_ref()
                        == &(XdpAttachError::KernelRejected {
                            operation: XdpAttachOperation::Detach,
                            errno: Some(16),
                        })
        ));
        assert_eq!(sent_messages(&fake).len(), 3);
        assert_eq!(close_count(&fake), 2);
    }

    #[test]
    fn rollback_detach_failure_is_retried_by_pending_drop() {
        let fake = FakeNetlinkSyscalls::new(vec![ack(1, 7), ack(2, -16), ack(3, 0)]);
        let error = match attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default()) {
            Ok(_) => panic!("malformed netlink error was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            &error,
            XdpAttachError::StateUnknownRollback { original, rollback }
                if original.as_ref() == &(XdpAttachError::InvalidErrorCode { code: 7 })
                    && rollback.as_ref()
                        == &(XdpAttachError::KernelRejected {
                            operation: XdpAttachOperation::Detach,
                            errno: Some(16),
                        })
        ));
        assert_eq!(
            sent_messages(&fake),
            vec![
                encode_attach_message(7, 23, 3, 1, 0x1122_3344),
                encode_detach_message(7, XdpAttachMode::Skb, 88, 2, 0x1122_3344),
                encode_detach_message(7, XdpAttachMode::Skb, 88, 3, 0x1122_3344),
            ]
        );
        assert_eq!(close_count(&fake), 2);
    }

    #[test]
    fn pending_guard_drop_rolls_back_once_when_unwinding_before_explicit_cleanup() {
        let fake = FakeNetlinkSyscalls::new(vec![ack(1, 7), ack(2, 0)]);
        let socket = OwnedNetlinkSocket::open(&fake).expect("fake socket open");
        let mut pending = PendingNetlinkAttachment::new(socket, 7, XdpAttachMode::Skb, 2);
        let sequence = pending.socket_mut().next_sequence();
        let request = encode_attach_message(7, 23, 3, sequence, 0x1122_3344);
        assert!(matches!(
            pending.transact_attach(&request, sequence),
            AttachTransactionResult::StateUnknown(XdpAttachError::InvalidErrorCode { code: 7 })
        ));
        drop(pending);
        assert_eq!(sent_messages(&fake).len(), 2);
        assert_eq!(close_count(&fake), 2);
    }

    #[test]
    fn attach_flags_reject_every_missing_or_unsafe_mode_combination() {
        // Protects the no-replace invariant and the rejection of unknown or
        // conflicting XDP modes, including the TryFrom forwarding path.
        assert_eq!(
            ValidatedXdpAttachFlags::try_from(XDP_FLAGS_UPDATE_IF_NOEXIST),
            Err(XdpAttachConfigError::MissingMode)
        );
        assert_eq!(
            ValidatedXdpAttachFlags::try_from(XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_REPLACE),
            Err(XdpAttachConfigError::UnsupportedFlags(XDP_FLAGS_REPLACE))
        );
        assert_eq!(
            ValidatedXdpAttachFlags::try_from(
                XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE
            ),
            Err(XdpAttachConfigError::ConflictingModes)
        );
        assert_eq!(
            ValidatedXdpAttachFlags::try_from(XDP_FLAGS_SKB_MODE),
            Err(XdpAttachConfigError::UpdateIfNoExistRequired)
        );
    }

    #[test]
    fn ifindex_validation_rejects_zero_and_signed_index_overflow_only() {
        // Protects the rtnetlink ifinfomsg signed-index boundary before any
        // socket or duplicate-program-fd side effect occurs.
        assert_eq!(
            validate_ifindex(0),
            Err(XdpAttachError::InvalidInterfaceIndex { ifindex: 0 })
        );
        assert_eq!(validate_ifindex(i32::MAX as u32), Ok(()));
        assert_eq!(
            validate_ifindex(i32::MAX as u32 + 1),
            Err(XdpAttachError::InvalidInterfaceIndex {
                ifindex: i32::MAX as u32 + 1,
            })
        );
    }

    #[test]
    fn detach_message_preserves_driver_mode_and_expected_fd_identity() {
        // Protects the ABI detach contract: fd -1, REPLACE plus the selected
        // mode, and IFLA_XDP_EXPECTED_FD type 8 with the owner fd value.
        let message = encode_detach_message(9, XdpAttachMode::Drv, 91, 7, 0x5566_7788);
        assert_eq!(message.len(), 60);
        assert_eq!(i32::from_ne_bytes(message[40..44].try_into().unwrap()), -1);
        assert_eq!(
            u32::from_ne_bytes(message[48..52].try_into().unwrap()),
            XDP_FLAGS_REPLACE | XDP_FLAGS_DRV_MODE
        );
        assert_eq!(u16::from_ne_bytes(message[52..54].try_into().unwrap()), 8);
        assert_eq!(
            u16::from_ne_bytes(message[54..56].try_into().unwrap()),
            IFLA_XDP_EXPECTED_FD
        );
        assert_eq!(i32::from_ne_bytes(message[56..60].try_into().unwrap()), 91);
    }

    #[test]
    fn inspect_ack_rejects_transport_and_protocol_length_boundaries() {
        // Protects fail-closed ACK parsing for short receives, declared
        // extents that need padding, and receives longer than the buffer.
        let response = ack(4, 0);
        assert_eq!(
            inspect_ack(
                &response.bytes,
                RecvMessage {
                    byte_len: NLMSG_HDRLEN - 1,
                    flags: 0,
                },
                4,
                XdpAttachOperation::Attach,
            ),
            Err(XdpAttachError::ResponseTooShort {
                actual: NLMSG_HDRLEN - 1,
                minimum: NLMSG_HDRLEN,
            })
        );
        assert_eq!(
            inspect_ack(
                &response.bytes,
                RecvMessage {
                    byte_len: response.bytes.len() + 1,
                    flags: 0,
                },
                4,
                XdpAttachOperation::Attach,
            ),
            Err(XdpAttachError::ResponseLengthMismatch {
                declared: response.bytes.len(),
                actual: response.bytes.len() + 1,
            })
        );

        let mut unaligned = response.bytes.clone();
        write_u32(&mut unaligned, 0, (NLMSG_ERROR_MESSAGE_LEN + 1) as u32);
        assert_eq!(
            inspect_ack(
                &unaligned,
                RecvMessage {
                    byte_len: NLMSG_ERROR_MESSAGE_LEN,
                    flags: 0,
                },
                4,
                XdpAttachOperation::Attach,
            ),
            Err(XdpAttachError::ResponseTooShort {
                actual: NLMSG_ERROR_MESSAGE_LEN,
                minimum: align4(NLMSG_ERROR_MESSAGE_LEN + 1),
            })
        );

        let mut extra = response.bytes.clone();
        extra.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            inspect_ack(
                &extra,
                RecvMessage {
                    byte_len: extra.len(),
                    flags: 0,
                },
                4,
                XdpAttachOperation::Attach,
            ),
            Err(XdpAttachError::ResponseLengthMismatch {
                declared: NLMSG_ERROR_MESSAGE_LEN,
                actual: NLMSG_ERROR_MESSAGE_LEN + 4,
            })
        );
    }

    #[test]
    fn inspect_ack_requires_error_message_type_and_exact_sequence() {
        // Protects ACK identity checks so an unrelated netlink message cannot
        // be mistaken for a successful attach/detach transaction.
        let mut wrong_type = ack(4, 0).bytes;
        write_u16(&mut wrong_type, 4, 3);
        assert_eq!(
            inspect_ack(
                &wrong_type,
                RecvMessage {
                    byte_len: wrong_type.len(),
                    flags: 0,
                },
                4,
                XdpAttachOperation::Attach,
            ),
            Err(XdpAttachError::UnexpectedMessageType { message_type: 3 })
        );

        let response = ack(5, 0);
        assert_eq!(
            inspect_ack(
                &response.bytes,
                RecvMessage {
                    byte_len: response.bytes.len(),
                    flags: 0,
                },
                4,
                XdpAttachOperation::Attach,
            ),
            Err(XdpAttachError::UnexpectedSequence {
                expected: 4,
                actual: 5,
            })
        );
    }

    #[test]
    fn attach_rejects_negative_program_fd_before_opening_netlink_socket() {
        // Protects the raw-fd validation boundary and ensures invalid input
        // has no observable syscall side effect.
        let fake = FakeNetlinkSyscalls::new(Vec::new());
        assert!(matches!(
            attach_with_syscalls(&fake, -1, 7, ValidatedXdpAttachFlags::default()),
            Err(XdpAttachError::InvalidProgramFileDescriptor { fd: -1 })
        ));
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn netlink_open_binds_kernel_allocated_port_before_reading_portid() {
        // Protects the control-plane socket initialization: the bind syscall
        // must be issued with nl_pid zero before getsockname supplies portid.
        let fake = FakeNetlinkSyscalls::new(Vec::new());
        let socket = OwnedNetlinkSocket::open(&fake).expect("fake netlink socket");
        let calls = fake.calls();
        let bind_index = calls
            .iter()
            .position(|call| matches!(call, Call::Bind(_)))
            .expect("bind transcript entry");
        let getsockname_index = calls
            .iter()
            .position(|call| matches!(call, Call::GetSocketName))
            .expect("getsockname transcript entry");
        assert!(bind_index < getsockname_index);
        assert!(calls.contains(&Call::Bind(encode_sockaddr_nl(0, 0).to_vec())));
        drop(socket);
    }

    #[test]
    fn sockaddr_nl_encoder_preserves_fixed_family_portid_and_groups_fields() {
        // Protects sockaddr_nl ABI encoding independently of the encoder's
        // implementation: family, port ID, groups, and zero padding are all
        // checked against fixed little-endian bytes.
        let encoded = encode_sockaddr_nl(0x1122_3344, 0x5566_7788);
        assert_eq!(
            encoded,
            [0x10, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55,]
        );
        assert_eq!(
            u16::from_ne_bytes(encoded[0..2].try_into().unwrap()),
            AF_NETLINK as u16
        );
        assert_eq!(
            u32::from_ne_bytes(encoded[4..8].try_into().unwrap()),
            0x1122_3344
        );
        assert_eq!(
            u32::from_ne_bytes(encoded[8..12].try_into().unwrap()),
            0x5566_7788
        );
    }

    #[test]
    fn public_attachment_accessors_preserve_identity_and_active_state() {
        let mut attachment = public_attachment(37, true);
        assert_eq!(attachment.ifindex(), 37);
        let was_active = attachment.is_attached();

        // Make the test-owned value safe to drop without issuing a real
        // detach request after both active states have been observed.
        attachment.inner.active = false;
        assert!(was_active);
        assert!(!attachment.is_attached());
    }

    #[test]
    fn public_detach_propagates_send_failure_and_retains_active_state() {
        let mode = XdpAttachMode::Skb;
        let mut attachment = XdpAttachment {
            ifindex: 1,
            mode,
            inner: NetlinkAttachment {
                socket: OwnedNetlinkSocket {
                    syscalls: &NETLINK_SYSCALLS,
                    fd: Some(-1),
                    portid: 0,
                    next_sequence: 1,
                },
                ifindex: 1,
                mode,
                expected_program_fd: Some(-1),
                active: true,
            },
        };

        let result = attachment.detach();
        assert!(matches!(
            result,
            Err(XdpAttachError::Syscall {
                operation: XdpAttachOperation::SendMessage,
                ..
            }) | Err(XdpAttachError::PermissionDenied {
                operation: XdpAttachOperation::SendMessage,
            })
        ));
        assert!(attachment.is_attached());

        attachment.inner.active = false;
        attachment.inner.expected_program_fd = None;
        attachment.inner.socket.fd = None;
    }

    #[test]
    fn close_expected_program_fd_reports_close_failure_after_ack() {
        let fake =
            ConfigurableNetlinkSyscalls::new(vec![ack(1, 0)]).with_close_error(Errno::Linux(9));
        let mut attachment = NetlinkAttachment {
            socket: OwnedNetlinkSocket {
                syscalls: &fake,
                fd: Some(77),
                portid: 0x1122_3344,
                next_sequence: 1,
            },
            ifindex: 7,
            mode: XdpAttachMode::Skb,
            expected_program_fd: Some(88),
            active: true,
        };

        let result = attachment.detach();
        assert_eq!(
            result,
            Err(XdpAttachError::Syscall {
                operation: XdpAttachOperation::CloseExpectedProgramFd,
                errno: Some(9),
            })
        );
        assert!(!attachment.active);
        assert_eq!(attachment.expected_program_fd, None);

        // Avoid a second best-effort close from this test's owner drop.
        attachment.socket.fd = None;
    }

    #[test]
    fn attach_accepts_zero_program_fd_at_signed_boundary() {
        let fake = ConfigurableNetlinkSyscalls::new(vec![ack(1, 0), ack(2, 0)]);
        let mut attachment = attach_with_syscalls(&fake, 0, 7, ValidatedXdpAttachFlags::default())
            .expect("fd zero is a valid nonnegative input");

        attachment.detach().expect("fake detach ACK");
    }

    #[test]
    fn attach_accepts_zero_duplicate_fd_as_an_owned_identity() {
        let fake =
            ConfigurableNetlinkSyscalls::new(vec![ack(1, 0), ack(2, 0)]).with_duplicate_fd(0);
        let mut attachment = attach_with_syscalls(&fake, 23, 7, ValidatedXdpAttachFlags::default())
            .expect("duplicate fd zero is accepted by the nonnegative contract");

        assert_eq!(attachment.expected_program_fd, Some(0));
        attachment.detach().expect("fake detach ACK");
        assert!(fake.calls().contains(&Call::Close { fd: 0 }));
    }

    #[test]
    fn socket_open_accepts_zero_fd_and_raw_returns_the_owned_value() {
        let fake = ConfigurableNetlinkSyscalls::new(Vec::new()).with_socket_fd(0);
        let socket = OwnedNetlinkSocket::open(&fake).expect("fd zero is a valid socket value");
        assert_eq!(socket.raw(), 0);
        drop(socket);

        let fake = ConfigurableNetlinkSyscalls::new(Vec::new()).with_socket_fd(123);
        let socket = OwnedNetlinkSocket::open(&fake).expect("fake socket open");
        assert_eq!(socket.raw(), 123);
        drop(socket);
    }

    #[test]
    fn socket_open_rejects_address_lengths_outside_the_checked_buffer() {
        let too_long = ConfigurableNetlinkSyscalls::new(Vec::new())
            .with_address_length((SOCKADDR_NL_LEN + 1) as u32);
        assert!(matches!(
            OwnedNetlinkSocket::open(&too_long),
            Err(XdpAttachError::PortIdResponseTooLong { .. })
        ));

        let too_short = ConfigurableNetlinkSyscalls::new(Vec::new())
            .with_address_length((SOCKADDR_NL_LEN - 1) as u32);
        assert!(matches!(
            OwnedNetlinkSocket::open(&too_short),
            Err(XdpAttachError::PortIdResponseTooShort { .. })
        ));
    }

    #[test]
    fn netlink_error_message_extent_is_the_fixed_header_plus_error_size() {
        assert_eq!(NLMSG_HDRLEN, 16);
        assert_eq!(NLMSGERR_LEN, 20);
        assert_eq!(NLMSG_ERROR_MESSAGE_LEN, 36);
        assert_eq!(ack(1, 0).bytes.len(), 36);
    }

    #[test]
    fn inspect_ack_accepts_zero_but_rejects_positive_error_codes() {
        let success = ack(11, 0);
        assert_eq!(
            inspect_ack(
                &success.bytes,
                RecvMessage {
                    byte_len: success.byte_len,
                    flags: success.flags,
                },
                11,
                XdpAttachOperation::Attach,
            ),
            Ok(())
        );

        let malformed = ack(12, 1);
        assert_eq!(
            inspect_ack(
                &malformed.bytes,
                RecvMessage {
                    byte_len: malformed.byte_len,
                    flags: malformed.flags,
                },
                12,
                XdpAttachOperation::Attach,
            ),
            Err(XdpAttachError::InvalidErrorCode { code: 1 })
        );
    }

    #[test]
    fn report_drop_error_writes_context_and_error_to_stderr() {
        const CHILD_ENV: &str = "RUSTER_NETLINK_REPORT_DROP_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            report_drop_error(
                "netlink-drop-test",
                &XdpAttachError::Syscall {
                    operation: XdpAttachOperation::CloseSocket,
                    errno: Some(9),
                },
            );
            return;
        }

        let output = std::process::Command::new(
            std::env::current_exe().expect("the unit-test executable is available"),
        )
        .arg("report_drop_error_writes_context_and_error_to_stderr")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn report child");
        assert!(output.status.success(), "child failed: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("netlink-drop-test"), "stderr: {stderr}");
        assert!(stderr.contains("errno 9"), "stderr: {stderr}");
    }
}

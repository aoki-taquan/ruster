//! Checked XSKMAP creation and AF_XDP socket registration.
//!
//! The public API deliberately accepts [`XdpResource`] rather than a raw file
//! descriptor. `XdpResource` is returned only after the AF_XDP setup
//! transaction has completed its successful `bind(2)`, so an unbound socket
//! cannot reach the map-update operation through this API.

use crate::{XdpProgramError, XdpRedirectProgram, XdpResource, XskMapError};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
use crate::{ensure_native_syscall_supported, NativeSyscallPlatformError};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use crate::native_unsafe::syscall::{
    BpfArgumentError, BpfResourceError, LinuxSyscalls, OwnedBpfMap,
};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
static XSKMAP_SYSCALLS: LinuxSyscalls = LinuxSyscalls;

/// An owned Linux XSKMAP.
///
/// The map stores `u32 queue_id -> u32 AF_XDP socket fd` entries. Its
/// descriptor is closed exactly once by the inner RAII owner when this value
/// is explicitly closed or dropped. Map creation and update are cold-path
/// operations; no packet-path lock, allocation, or dynamic dispatch is
/// introduced here.
pub struct XskMap {
    max_entries: u32,
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    inner: OwnedBpfMap<'static, LinuxSyscalls>,
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )))]
    _unsupported: (),
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl XskMap {
    /// Creates an XSKMAP with one slot for each queue id in `0..max_entries`.
    ///
    /// Linux checks `CAP_BPF` (or root-equivalent privilege) for this
    /// operation. An `EPERM` response is returned as
    /// [`XskMapError::PermissionDenied`] with a message that names the
    /// required privilege; it is never silently skipped.
    pub fn new(max_entries: u32) -> Result<Self, XskMapError> {
        let inner = OwnedBpfMap::create(&XSKMAP_SYSCALLS, max_entries).map_err(map_bpf_error)?;
        Ok(Self {
            max_entries: inner.max_entries(),
            inner,
        })
    }

    /// Registers the bound AF_XDP socket for its configured hardware queue.
    ///
    /// The resource argument is the proof that setup reached successful
    /// `bind(2)`: its socket fd is private and cannot be supplied by an
    /// arbitrary caller. The queue id is taken from that same resource, and
    /// is checked against this map's `max_entries` before `bpf(2)` is entered.
    pub fn register(&self, resource: &XdpResource<'_>) -> Result<(), XskMapError> {
        self.inner
            .update_xsk(resource.queue_id(), resource.bound_socket())
            .map_err(map_bpf_error)
    }

    /// Loads the minimum XDP redirect program for this map.
    ///
    /// The returned program keeps its own kernel reference to the map after
    /// loading and owns its program fd independently. This method only loads
    /// bytecode; call [`XdpRedirectProgram::attach`] on the returned program
    /// to perform the separate rtnetlink interface transaction.
    pub fn load_redirect_program(&self) -> Result<XdpRedirectProgram, XdpProgramError> {
        XdpRedirectProgram::load(self)
    }

    /// Returns the checked maximum queue-id range of this map.
    #[must_use]
    pub const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn raw_fd(&self) -> i32 {
        self.inner.raw()
    }

    /// Explicitly closes the map descriptor and observes a close failure.
    ///
    /// The consuming operation removes the descriptor from the RAII owner
    /// before calling `close(2)`, so dropping after an error cannot retry a
    /// possibly released or reused descriptor.
    pub fn close(self) -> Result<(), XskMapError> {
        self.inner.close().map_err(map_bpf_error)
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
impl XskMap {
    /// Rejects creation because the reviewed native bpf profile is unavailable.
    pub fn new(max_entries: u32) -> Result<Self, XskMapError> {
        if max_entries == 0 {
            return Err(XskMapError::InvalidMaxEntries { max_entries });
        }
        Err(XskMapError::Platform(unsupported_platform_error()))
    }

    /// Rejects registration because the reviewed native bpf profile is
    /// unavailable on this target.
    pub fn register(&self, _resource: &XdpResource<'_>) -> Result<(), XskMapError> {
        Err(XskMapError::Platform(unsupported_platform_error()))
    }

    /// Rejects program loading because the reviewed native bpf profile is
    /// unavailable on this target.
    pub fn load_redirect_program(&self) -> Result<XdpRedirectProgram, XdpProgramError> {
        XdpRedirectProgram::load(self)
    }

    /// Returns the value retained by this portable placeholder.
    #[must_use]
    pub const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    /// Unsupported targets never acquire a map descriptor.
    pub fn close(self) -> Result<(), XskMapError> {
        let _ = self;
        Ok(())
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn map_bpf_error(error: BpfResourceError) -> XskMapError {
    match error {
        BpfResourceError::Platform(error) => XskMapError::Platform(error),
        BpfResourceError::Argument(error) => match error {
            BpfArgumentError::InvalidMaxEntries { max_entries } => {
                XskMapError::InvalidMaxEntries { max_entries }
            }
            BpfArgumentError::QueueIdOutOfRange {
                queue_id,
                max_entries,
            } => XskMapError::QueueIdOutOfRange {
                queue_id,
                max_entries,
            },
            BpfArgumentError::InvalidFileDescriptor { operation } => {
                XskMapError::InvalidFileDescriptor { operation }
            }
        },
        BpfResourceError::Syscall { operation, errno } => {
            if errno.raw() == Some(1) {
                XskMapError::PermissionDenied { operation }
            } else {
                XskMapError::Syscall {
                    operation,
                    errno: errno.raw(),
                }
            }
        }
        BpfResourceError::UnexpectedReturn { operation, value } => {
            XskMapError::UnexpectedReturn { operation, value }
        }
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
fn unsupported_platform_error() -> NativeSyscallPlatformError {
    match ensure_native_syscall_supported() {
        Ok(()) => unreachable!("unsupported XSKMAP path on a supported target"),
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
    use super::*;
    use crate::native_unsafe::syscall::{BpfResourceError, Errno};
    use crate::XskMapOperation;

    #[test]
    fn eperm_maps_to_explicit_cap_bpf_or_root_error() {
        let error = map_bpf_error(BpfResourceError::Syscall {
            operation: XskMapOperation::Create,
            errno: Errno::Linux(1),
        });
        assert_eq!(
            error,
            XskMapError::PermissionDenied {
                operation: XskMapOperation::Create,
            }
        );
        assert!(error.is_permission_denied());
        assert!(error.to_string().contains("CAP_BPF or root is required"));
    }

    #[test]
    fn public_constructor_rejects_zero_max_entries_without_bpf_call() {
        assert!(matches!(
            XskMap::new(0),
            Err(XskMapError::InvalidMaxEntries { max_entries: 0 })
        ));
    }
}

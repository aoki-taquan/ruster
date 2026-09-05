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
    use std::{
        ffi::{c_int, c_long, c_void},
        mem::ManuallyDrop,
        os::fd::RawFd,
    };

    use super::*;
    use crate::native_unsafe::syscall::{
        BpfResourceError, Errno, MapRequest, PollDescriptor, Syscalls,
    };
    use crate::XskMapOperation;

    struct BpfOnlySyscalls {
        bpf_return: c_long,
    }

    impl BpfOnlySyscalls {
        fn new(bpf_return: c_long) -> Self {
            Self { bpf_return }
        }
    }

    impl crate::native_unsafe::syscall::sealed::Sealed for BpfOnlySyscalls {}

    impl Syscalls for BpfOnlySyscalls {
        fn socket(&self, _domain: c_int, _kind: c_int, _protocol: c_int) -> Result<RawFd, Errno> {
            Err(Errno::Linux(38))
        }

        fn set_socket_option(
            &self,
            _fd: RawFd,
            _level: c_int,
            _name: c_int,
            _value: &[u8],
            _length: u32,
        ) -> Result<(), Errno> {
            Err(Errno::Linux(38))
        }

        fn get_socket_option(
            &self,
            _fd: RawFd,
            _level: c_int,
            _name: c_int,
            _value: &mut [u8],
            _length: &mut u32,
        ) -> Result<(), Errno> {
            Err(Errno::Linux(38))
        }

        fn mmap(&self, _request: MapRequest) -> Result<*mut c_void, Errno> {
            Err(Errno::Linux(38))
        }

        fn munmap(&self, _address: *mut c_void, _byte_len: usize) -> Result<(), Errno> {
            Err(Errno::Linux(38))
        }

        fn bind(&self, _fd: RawFd, _address: &[u8], _length: u32) -> Result<(), Errno> {
            Err(Errno::Linux(38))
        }

        fn poll(
            &self,
            _descriptor: &mut PollDescriptor,
            _timeout_millis: c_int,
        ) -> Result<u32, Errno> {
            Err(Errno::Linux(38))
        }

        fn send_to_wakeup(&self, _fd: RawFd) -> Result<(), Errno> {
            Err(Errno::Linux(38))
        }

        fn bpf(&self, _command: u32, _attr: &mut [u8]) -> Result<c_long, Errno> {
            Ok(self.bpf_return)
        }

        fn close(&self, _fd: RawFd) -> Result<(), Errno> {
            Err(Errno::Linux(38))
        }
    }

    struct SetupSyscalls;

    impl crate::native_unsafe::syscall::sealed::Sealed for SetupSyscalls {}

    impl Syscalls for SetupSyscalls {
        fn socket(&self, _domain: c_int, _kind: c_int, _protocol: c_int) -> Result<RawFd, Errno> {
            Ok(17)
        }

        fn set_socket_option(
            &self,
            _fd: RawFd,
            _level: c_int,
            _name: c_int,
            _value: &[u8],
            _length: u32,
        ) -> Result<(), Errno> {
            Ok(())
        }

        fn get_socket_option(
            &self,
            _fd: RawFd,
            _level: c_int,
            _name: c_int,
            value: &mut [u8],
            length: &mut u32,
        ) -> Result<(), Errno> {
            let ring = crate::abi::XdpRingOffset {
                producer: 0,
                consumer: 64,
                flags: 128,
                descriptors: 192,
            };
            let bytes = crate::abi::encode_xdp_mmap_offsets(crate::abi::XdpMmapOffsets {
                rx: ring,
                tx: ring,
                fill: ring,
                completion: ring,
            });
            value[..bytes.len()].copy_from_slice(&bytes);
            *length = u32::try_from(bytes.len()).expect("offset extent fits socklen");
            Ok(())
        }

        fn mmap(&self, _request: MapRequest) -> Result<*mut c_void, Errno> {
            let memory = Box::leak(vec![0_u8; 4_096].into_boxed_slice());
            Ok(memory.as_mut_ptr().cast())
        }

        fn munmap(&self, _address: *mut c_void, _byte_len: usize) -> Result<(), Errno> {
            Ok(())
        }

        fn bind(&self, _fd: RawFd, _address: &[u8], _length: u32) -> Result<(), Errno> {
            Ok(())
        }

        fn poll(
            &self,
            _descriptor: &mut PollDescriptor,
            _timeout_millis: c_int,
        ) -> Result<u32, Errno> {
            Ok(0)
        }

        fn send_to_wakeup(&self, _fd: RawFd) -> Result<(), Errno> {
            Ok(())
        }

        fn bpf(&self, _command: u32, _attr: &mut [u8]) -> Result<c_long, Errno> {
            Ok(0)
        }

        fn close(&self, _fd: RawFd) -> Result<(), Errno> {
            Ok(())
        }
    }

    #[allow(unsafe_code)]
    fn map_for_observation(fd: c_long, max_entries: u32) -> ManuallyDrop<XskMap> {
        let syscalls: &'static BpfOnlySyscalls = Box::leak(Box::new(BpfOnlySyscalls::new(fd)));
        let inner = OwnedBpfMap::create(syscalls, max_entries).expect("fake XSKMAP");
        let inner = unsafe {
            std::mem::transmute::<
                OwnedBpfMap<'static, BpfOnlySyscalls>,
                OwnedBpfMap<'static, LinuxSyscalls>,
            >(inner)
        };
        ManuallyDrop::new(XskMap { max_entries, inner })
    }

    #[allow(unsafe_code)]
    fn resource_for_register(queue_id: u32) -> ManuallyDrop<XdpResource<'static>> {
        let umem = crate::UmemConfig::new(2, 2_048, 256, 1, 1, 0).expect("UMEM config");
        let rings = crate::RingConfig::new(4, 4, 4, 4).expect("ring config");
        let builder =
            crate::XdpResourceBuilder::new(umem, rings, 7, queue_id).expect("resource builder");
        let syscalls: &'static SetupSyscalls = Box::leak(Box::new(SetupSyscalls));
        let memory: &'static mut [u8] =
            Box::leak(vec![0_u8; umem.byte_len() as usize].into_boxed_slice());
        let owner = builder
            .build_with_syscalls(memory, syscalls)
            .expect("fake bound resource");

        // SAFETY: `XdpResource` is a single `ResourceOwner` field and the
        // syscall parameter only appears in references inside the owner. The
        // value is retained in ManuallyDrop because its fake syscall owner
        // must not be dropped through the retyped Linux implementation.
        ManuallyDrop::new(unsafe {
            std::mem::transmute::<
                crate::setup::ResourceOwner<'static, 'static, SetupSyscalls>,
                XdpResource<'static>,
            >(owner)
        })
    }

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
    fn non_eperm_map_failure_remains_a_regular_syscall_error() {
        // Protects the permission boundary: only EPERM is privileged denial;
        // another errno must remain observable as the original syscall error.
        let error = map_bpf_error(BpfResourceError::Syscall {
            operation: XskMapOperation::UpdateElem,
            errno: Errno::Linux(5),
        });
        assert_eq!(
            error,
            XskMapError::Syscall {
                operation: XskMapOperation::UpdateElem,
                errno: Some(5),
            }
        );
        assert!(!error.is_permission_denied());
    }

    #[test]
    fn public_constructor_rejects_zero_max_entries_without_bpf_call() {
        assert!(matches!(
            XskMap::new(0),
            Err(XskMapError::InvalidMaxEntries { max_entries: 0 })
        ));
    }

    #[test]
    fn register_rejects_queue_at_max_entries_before_entering_bpf() {
        let map = map_for_observation(-1, 8);
        let resource = resource_for_register(8);
        assert_eq!(
            map.register(&resource),
            Err(XskMapError::QueueIdOutOfRange {
                queue_id: 8,
                max_entries: 8,
            })
        );
    }

    #[test]
    fn max_entries_accessor_returns_the_checked_map_capacity() {
        let map = map_for_observation(-1, 37);
        assert_eq!(map.max_entries(), 37);
    }

    #[test]
    fn raw_fd_accessor_returns_the_owned_map_descriptor() {
        let map = map_for_observation(-7, 1);
        assert_eq!(map.raw_fd(), -7);
    }

    #[test]
    fn close_propagates_a_real_close_failure() {
        let map = ManuallyDrop::into_inner(map_for_observation(-1, 1));
        assert_eq!(
            map.close(),
            Err(XskMapError::Syscall {
                operation: XskMapOperation::Close,
                errno: Some(9),
            })
        );
    }

    #[test]
    fn load_redirect_program_rejects_a_negative_map_descriptor() {
        let map = map_for_observation(-1, 1);
        let error = map
            .load_redirect_program()
            .err()
            .expect("negative map fd must be rejected before program load");
        assert_eq!(error, XdpProgramError::InvalidMapFileDescriptor { fd: -1 });
    }

    #[test]
    fn map_error_mapping_preserves_each_argument_and_unexpected_return() {
        let platform = map_bpf_error(BpfResourceError::Platform(
            crate::NativeSyscallPlatformError::UnsupportedArchitecture,
        ));
        assert_eq!(
            platform,
            XskMapError::Platform(crate::NativeSyscallPlatformError::UnsupportedArchitecture)
        );

        let invalid_max = map_bpf_error(BpfResourceError::Argument(
            BpfArgumentError::InvalidMaxEntries { max_entries: 0 },
        ));
        assert_eq!(
            invalid_max,
            XskMapError::InvalidMaxEntries { max_entries: 0 }
        );

        let out_of_range = map_bpf_error(BpfResourceError::Argument(
            BpfArgumentError::QueueIdOutOfRange {
                queue_id: 8,
                max_entries: 8,
            },
        ));
        assert_eq!(
            out_of_range,
            XskMapError::QueueIdOutOfRange {
                queue_id: 8,
                max_entries: 8,
            }
        );

        let invalid_fd = map_bpf_error(BpfResourceError::Argument(
            BpfArgumentError::InvalidFileDescriptor {
                operation: XskMapOperation::UpdateElem,
            },
        ));
        assert_eq!(
            invalid_fd,
            XskMapError::InvalidFileDescriptor {
                operation: XskMapOperation::UpdateElem,
            }
        );

        let invalid_errno = map_bpf_error(BpfResourceError::Syscall {
            operation: XskMapOperation::Close,
            errno: Errno::InvalidCapture,
        });
        assert_eq!(
            invalid_errno,
            XskMapError::Syscall {
                operation: XskMapOperation::Close,
                errno: None,
            }
        );

        let unexpected = map_bpf_error(BpfResourceError::UnexpectedReturn {
            operation: XskMapOperation::UpdateElem,
            value: -1,
        });
        assert_eq!(
            unexpected,
            XskMapError::UnexpectedReturn {
                operation: XskMapOperation::UpdateElem,
                value: -1,
            }
        );
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
#[cfg(test)]
mod unsupported_tests {
    use super::*;

    fn unsupported_error() -> crate::NativeSyscallPlatformError {
        crate::ensure_native_syscall_supported()
            .expect_err("this test only runs on an unsupported native target")
    }

    #[test]
    fn unsupported_constructor_and_loader_remain_platform_errors() {
        let expected = unsupported_error();
        let constructor_error = XskMap::new(1)
            .err()
            .expect("unsupported constructor must fail");
        assert_eq!(constructor_error, XskMapError::Platform(expected));

        let map = XskMap {
            max_entries: 7,
            _unsupported: (),
        };
        let load_error = map
            .load_redirect_program()
            .err()
            .expect("unsupported loader must fail");
        assert_eq!(load_error, XdpProgramError::Platform(expected));
    }

    #[test]
    fn unsupported_map_accessors_keep_state_and_close_is_explicitly_noop() {
        let map = XskMap {
            max_entries: 7,
            _unsupported: (),
        };
        assert_eq!(map.max_entries(), 7);
        assert_eq!(map.close(), Ok(()));
    }

    #[test]
    fn unsupported_register_remains_a_platform_error() {
        let expected = unsupported_error();
        let map = XskMap {
            max_entries: 7,
            _unsupported: (),
        };
        let resource = crate::XdpResource::test_placeholder();

        assert_eq!(
            map.register(&resource),
            Err(XskMapError::Platform(expected))
        );
    }
}

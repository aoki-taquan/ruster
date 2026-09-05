use crate::{NativeSyscallPlatformError, PlatformError};

/// Rejects unsupported targets before any future native resource acquisition.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub const fn ensure_supported() -> Result<(), PlatformError> {
    Ok(())
}

/// Rejects unsupported targets before any future native resource acquisition.
#[cfg(not(target_os = "linux"))]
pub const fn ensure_supported() -> Result<(), PlatformError> {
    Err(PlatformError::UnsupportedOperatingSystem)
}

/// Rejects unsupported targets before any future native resource acquisition.
#[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
pub const fn ensure_supported() -> Result<(), PlatformError> {
    Err(PlatformError::UnsupportedPointerWidth)
}

/// Checks the narrower platform contract of the private C2A syscall seam.
///
/// C0/C1 layout validation and borrowed ring access retain their reviewed
/// 64-bit Linux boundary. The dependency-free syscall constants are audited
/// only for x86_64 Linux, so every future resource builder must call this
/// separate check before opening a file descriptor.
pub const fn ensure_native_syscall_supported() -> Result<(), NativeSyscallPlatformError> {
    native_syscall_support(
        cfg!(target_os = "linux"),
        cfg!(target_pointer_width = "64"),
        cfg!(target_arch = "x86_64"),
    )
}

const fn native_syscall_support(
    is_linux: bool,
    is_64_bit: bool,
    is_x86_64: bool,
) -> Result<(), NativeSyscallPlatformError> {
    if !is_linux {
        Err(NativeSyscallPlatformError::UnsupportedOperatingSystem)
    } else if !is_64_bit {
        Err(NativeSyscallPlatformError::UnsupportedPointerWidth)
    } else if !is_x86_64 {
        Err(NativeSyscallPlatformError::UnsupportedArchitecture)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_platform_gate_matches_the_compiled_target_contract() {
        // Protects the target-specific ensure_supported branches: unsupported
        // operating systems and pointer widths must fail before acquisition.
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        assert_eq!(ensure_supported(), Ok(()));

        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            ensure_supported(),
            Err(PlatformError::UnsupportedOperatingSystem)
        );

        #[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
        assert_eq!(
            ensure_supported(),
            Err(PlatformError::UnsupportedPointerWidth)
        );
    }

    #[test]
    fn native_syscall_platform_profile_is_exact_and_typed() {
        assert_eq!(
            native_syscall_support(false, true, true),
            Err(NativeSyscallPlatformError::UnsupportedOperatingSystem)
        );
        assert_eq!(
            native_syscall_support(true, false, true),
            Err(NativeSyscallPlatformError::UnsupportedPointerWidth)
        );
        assert_eq!(
            native_syscall_support(true, true, false),
            Err(NativeSyscallPlatformError::UnsupportedArchitecture)
        );
        assert_eq!(native_syscall_support(true, true, true), Ok(()));

        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        ))]
        assert_eq!(ensure_native_syscall_supported(), Ok(()));

        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            ensure_native_syscall_supported(),
            Err(NativeSyscallPlatformError::UnsupportedOperatingSystem)
        );

        #[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
        assert_eq!(
            ensure_native_syscall_supported(),
            Err(NativeSyscallPlatformError::UnsupportedPointerWidth)
        );

        #[cfg(all(
            target_os = "linux",
            target_pointer_width = "64",
            not(target_arch = "x86_64")
        ))]
        assert_eq!(
            ensure_native_syscall_supported(),
            Err(NativeSyscallPlatformError::UnsupportedArchitecture)
        );
    }

    #[test]
    fn native_syscall_gate_uses_the_compiled_target_dimensions() {
        assert_eq!(
            ensure_native_syscall_supported(),
            native_syscall_support(
                cfg!(target_os = "linux"),
                cfg!(target_pointer_width = "64"),
                cfg!(target_arch = "x86_64"),
            )
        );
    }
}

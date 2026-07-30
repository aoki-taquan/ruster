use crate::PlatformError;

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

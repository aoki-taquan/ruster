use crate::error::PlatformError;

pub struct DpdkPlatform;

impl DpdkPlatform {
    /// True only when this crate was built with the `dpdk` feature *and*
    /// `build.rs` actually found a usable `libdpdk` and compiler. Neither
    /// condition alone is enough: the feature can be on with DPDK absent
    /// (host build with the flag flipped), in which case this still reports
    /// `false` and the crate stays a stub.
    #[must_use]
    pub const fn is_supported() -> bool {
        cfg!(dpdk_available)
    }

    pub fn ensure_supported() -> Result<(), PlatformError> {
        if Self::is_supported() {
            Ok(())
        } else {
            Err(PlatformError::Unavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DpdkPlatform;

    #[test]
    fn reports_supported_iff_dpdk_available_cfg_is_set() {
        assert_eq!(DpdkPlatform::is_supported(), cfg!(dpdk_available));
        assert_eq!(
            DpdkPlatform::ensure_supported().is_ok(),
            cfg!(dpdk_available)
        );
    }
}

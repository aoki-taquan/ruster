use crate::PlatformError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UapiLayout {
    pub tpacket3_header: usize,
    pub tpacket3_status_offset: usize,
    pub tpacket3_mac_offset: usize,
    pub tpacket_block_descriptor: usize,
    pub tpacket_block_alignment: usize,
    pub block_status_offset: usize,
    pub block_sequence_offset: usize,
    pub tpacket_request3: usize,
    pub sockaddr_ll: usize,
    pub tpacket3_hdrlen: usize,
    pub ethernet_mac_offset: usize,
}

pub struct AfPacketPlatform;

impl AfPacketPlatform {
    #[must_use]
    pub const fn is_supported() -> bool {
        cfg!(target_os = "linux")
    }

    pub fn ensure_supported() -> Result<UapiLayout, PlatformError> {
        platform_uapi_layout()
    }
}

#[cfg(target_os = "linux")]
fn platform_uapi_layout() -> Result<UapiLayout, PlatformError> {
    crate::sys::validated_uapi_layout()
}

#[cfg(not(target_os = "linux"))]
fn platform_uapi_layout() -> Result<UapiLayout, PlatformError> {
    Err(PlatformError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::{AfPacketPlatform, UapiLayout};

    #[test]
    fn platform_is_supported_matches_build_target() {
        if cfg!(target_os = "linux") {
            assert!(AfPacketPlatform::is_supported());
        } else {
            assert!(!AfPacketPlatform::is_supported());
        }
    }

    #[test]
    fn ensure_supported_returns_expected_layout_fields() {
        let layout = AfPacketPlatform::ensure_supported()
            .expect("uapi layout should be available on supported platforms");

        let expected = UapiLayout {
            tpacket3_header: 48,
            tpacket3_status_offset: 20,
            tpacket3_mac_offset: 24,
            tpacket_block_descriptor: 48,
            tpacket_block_alignment: 8,
            block_status_offset: 8,
            block_sequence_offset: 24,
            tpacket_request3: 28,
            sockaddr_ll: 20,
            tpacket3_hdrlen: 68,
            ethernet_mac_offset: 82,
        };

        assert_eq!(layout, expected);
    }
}

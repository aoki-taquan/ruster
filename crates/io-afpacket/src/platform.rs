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

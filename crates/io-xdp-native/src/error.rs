use std::{error::Error, fmt};

use crate::RingName;

/// A named field within one kernel-reported ring mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingField {
    /// Producer cursor.
    Producer,
    /// Consumer cursor.
    Consumer,
    /// Need-wakeup flags word.
    Flags,
    /// Descriptor array.
    Descriptors,
}

/// Cold configuration validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// At least one UMEM frame is required.
    ZeroFrameCount,
    /// Aligned chunks require a nonzero power-of-two size.
    InvalidFrameSize(u32),
    /// Headroom must leave at least one visible byte.
    HeadroomConsumesFrame {
        /// Requested headroom.
        headroom: u32,
        /// Configured frame size.
        frame_size: u32,
    },
    /// The initial profile does not accept these UMEM flags.
    UnsupportedUmemFlags(u32),
    /// At least one frame must be reserved for RX/FILL.
    ZeroRxFrames,
    /// At least one frame must be reserved for generated packets.
    ZeroGeneratedFrames,
    /// The two frame-pool counts overflowed.
    FramePartitionOverflow,
    /// RX and generated pools did not partition the UMEM exactly.
    FramePartitionMismatch {
        /// Total configured frames.
        frame_count: u32,
        /// RX/FILL frame count.
        rx_frames: u32,
        /// Generated frame count.
        generated_frames: u32,
    },
    /// A ring capacity was zero or not a power of two.
    InvalidRingEntries {
        /// Ring whose capacity was rejected.
        ring: RingName,
        /// Rejected capacity.
        entries: u32,
    },
    /// Bind flags included unsupported or unknown bits.
    UnsupportedBindFlags(u16),
    /// The initial profile always requires `XDP_USE_NEED_WAKEUP`.
    NeedWakeupRequired,
    /// Copy and zero-copy were both required.
    ConflictingBindModes,
    /// Single-buffer descriptors require an option word of zero.
    UnsupportedDescriptorOptions(u32),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ConfigError {}

/// Failure while validating kernel-reported ring mapping offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiLayoutError {
    /// A field offset does not meet its C ABI alignment.
    MisalignedOffset {
        /// Misaligned field.
        field: RingField,
        /// Kernel-reported offset.
        offset: u64,
        /// Required alignment.
        alignment: usize,
    },
    /// A field extent overflowed `u64`.
    ExtentOverflow {
        /// Field whose extent overflowed.
        field: RingField,
    },
    /// The mapping extent cannot be represented by this process.
    ExtentDoesNotFitUsize,
    /// Two independently accessed mapping fields overlap.
    OverlappingFields {
        /// First overlapping field.
        first: RingField,
        /// Second overlapping field.
        second: RingField,
    },
}

impl fmt::Display for AbiLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for AbiLayoutError {}

/// Native platform support failure detected before any syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    /// AF_XDP native access is available only on Linux.
    UnsupportedOperatingSystem,
    /// The first reviewed ABI profile supports only 64-bit processes.
    UnsupportedPointerWidth,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PlatformError {}

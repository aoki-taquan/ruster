use std::{error::Error, fmt};

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

/// Failure while binding a checked ring layout to caller-owned mapped bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingMapError {
    /// The kernel-reported layout was invalid.
    Layout(AbiLayoutError),
    /// The borrowed mapping does not cover every checked field.
    MappingTooShort {
        /// Minimum byte length computed from the checked layout.
        required: usize,
        /// Actual borrowed byte length.
        actual: usize,
    },
    /// A field address is misaligned even though its relative offset is aligned.
    MisalignedFieldAddress {
        /// Misaligned field.
        field: RingField,
        /// Required alignment.
        alignment: usize,
    },
    /// Adding a checked field offset to the mapping base address overflowed.
    FieldAddressOverflow {
        /// Field whose process address overflowed.
        field: RingField,
    },
}

impl From<AbiLayoutError> for RingMapError {
    fn from(value: AbiLayoutError) -> Self {
        Self::Layout(value)
    }
}

impl fmt::Display for RingMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RingMapError {}

/// Native SPSC ring operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRingError {
    /// A reservation or acquisition must contain at least one entry.
    ZeroLength,
    /// The requested range exceeds the configured ring capacity.
    LengthExceedsCapacity,
    /// The producer has insufficient free entries.
    RingFull,
    /// The consumer has insufficient published entries.
    RingEmpty,
    /// Published cursor distance exceeds the configured capacity.
    CorruptCursor {
        /// Producer cursor observed from shared memory.
        producer: u32,
        /// Consumer cursor observed from shared memory.
        consumer: u32,
        /// Checked ring capacity.
        capacity: u32,
    },
    /// The reservation was submitted before every descriptor was written.
    IncompleteReservation {
        /// Reserved entry count.
        reserved: u32,
        /// Entries written before submission.
        written: u32,
    },
    /// The acquisition was consumed before every descriptor was read.
    IncompleteAcquisition {
        /// Acquired entry count.
        acquired: u32,
        /// Entries read before consumption.
        read: u32,
    },
    /// The caller attempted to write or read beyond its fixed range.
    RangeExhausted,
    /// The kernel exposed ring flag bits outside the reviewed v6.8 profile.
    UnsupportedRingFlags(u32),
}

impl fmt::Display for NativeRingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for NativeRingError {}

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

/// Narrow platform failure for the architecture-dependent native syscall seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSyscallPlatformError {
    /// Native syscalls are available only on Linux.
    UnsupportedOperatingSystem,
    /// The reviewed syscall ABI uses 64-bit pointer-sized C types.
    UnsupportedPointerWidth,
    /// Numeric syscall flags are audited only for x86_64.
    UnsupportedArchitecture,
}

impl fmt::Display for NativeSyscallPlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for NativeSyscallPlatformError {}

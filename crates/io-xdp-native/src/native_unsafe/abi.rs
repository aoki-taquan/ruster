//! Linux AF_XDP UAPI facts and checked ring-map layout arithmetic.
//!
//! Values and C layouts are pinned to Linux v6.8
//! `include/uapi/linux/if_xdp.h`. This module deliberately performs no FFI,
//! pointer access, socket operation, or memory mapping and therefore contains
//! no unsafe code.

use std::mem::{align_of, size_of};

use crate::{AbiLayoutError, RingEntries, RingField};

/// Pinned source of the C ABI facts in this module.
pub const ABI_HEADER_PROFILE: &str = "Linux v6.8 include/uapi/linux/if_xdp.h";

/// AF_XDP protocol family.
pub const AF_XDP: i32 = 44;
/// AF_XDP socket option level.
pub const SOL_XDP: i32 = 283;

/// Share an existing UMEM.
pub const XDP_SHARED_UMEM: u16 = 1 << 0;
/// Require copy mode.
pub const XDP_COPY: u16 = 1 << 1;
/// Require zero-copy mode.
pub const XDP_ZEROCOPY: u16 = 1 << 2;
/// Enable conditional producer wakeups.
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
/// Enable scatter/gather packets; deferred by the initial profile.
pub const XDP_USE_SG: u16 = 1 << 4;
/// Bind flags accepted by the initial profile.
pub const XDP_SUPPORTED_BIND_FLAGS: u16 =
    XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP;

/// Use unaligned UMEM chunks.
pub const XDP_UMEM_UNALIGNED_CHUNK_FLAG: u32 = 1 << 0;
/// Force software TX checksum in copy mode.
pub const XDP_UMEM_TX_SW_CSUM: u32 = 1 << 1;

/// Producer needs an explicit wakeup.
pub const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

/// Retrieve kernel ring offsets.
pub const XDP_MMAP_OFFSETS: i32 = 1;
/// Configure the RX ring.
pub const XDP_RX_RING: i32 = 2;
/// Configure the TX ring.
pub const XDP_TX_RING: i32 = 3;
/// Register UMEM.
pub const XDP_UMEM_REG: i32 = 4;
/// Configure the UMEM Fill ring.
pub const XDP_UMEM_FILL_RING: i32 = 5;
/// Configure the UMEM Completion ring.
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;
/// Retrieve socket statistics.
pub const XDP_STATISTICS: i32 = 7;
/// Retrieve negotiated socket options.
pub const XDP_OPTIONS: i32 = 8;
/// Negotiated zero-copy option bit.
pub const XDP_OPTIONS_ZEROCOPY: u32 = 1 << 0;

/// RX ring mmap offset.
pub const XDP_PGOFF_RX_RING: u64 = 0;
/// TX ring mmap offset.
pub const XDP_PGOFF_TX_RING: u64 = 0x8000_0000;
/// UMEM Fill ring mmap offset.
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x1_0000_0000;
/// UMEM Completion ring mmap offset.
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x1_8000_0000;

/// A packet continues in the next descriptor; unsupported initially.
pub const XDP_PKT_CONTD: u32 = 1 << 0;
/// A TX packet carries metadata; unsupported initially.
pub const XDP_TX_METADATA: u32 = 1 << 1;

/// Linux `struct sockaddr_xdp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SockAddrXdp {
    /// Protocol family; must be [`AF_XDP`].
    pub family: u16,
    /// `XDP_*` bind flags.
    pub flags: u16,
    /// Linux interface index.
    pub ifindex: u32,
    /// Hardware queue identifier.
    pub queue_id: u32,
    /// Owner socket fd when sharing UMEM.
    pub shared_umem_fd: u32,
}

/// Linux `struct xdp_ring_offset`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpRingOffset {
    /// Producer cursor byte offset.
    pub producer: u64,
    /// Consumer cursor byte offset.
    pub consumer: u64,
    /// Descriptor-array byte offset.
    pub descriptors: u64,
    /// Ring-flags byte offset.
    pub flags: u64,
}

/// Linux `struct xdp_mmap_offsets`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpMmapOffsets {
    /// RX ring offsets.
    pub rx: XdpRingOffset,
    /// TX ring offsets.
    pub tx: XdpRingOffset,
    /// Fill ring offsets.
    pub fill: XdpRingOffset,
    /// Completion ring offsets.
    pub completion: XdpRingOffset,
}

/// Linux `struct xdp_umem_reg`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpUmemReg {
    /// Start of the packet data area.
    pub address: u64,
    /// Packet data area length.
    pub len: u64,
    /// Fixed chunk size.
    pub chunk_size: u32,
    /// Kernel-reserved headroom.
    pub headroom: u32,
    /// UMEM option flags.
    pub flags: u32,
    /// Per-chunk TX metadata length.
    pub tx_metadata_len: u32,
}

/// Linux `struct xdp_statistics`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpStatistics {
    /// Packets dropped for reasons other than invalid descriptors.
    pub rx_dropped: u64,
    /// Invalid RX descriptors.
    pub rx_invalid_descriptors: u64,
    /// Invalid TX descriptors.
    pub tx_invalid_descriptors: u64,
    /// Packets dropped because the RX ring was full.
    pub rx_ring_full: u64,
    /// Failed Fill-ring descriptor retrievals.
    pub rx_fill_ring_empty_descriptors: u64,
    /// Failed TX-ring descriptor retrievals.
    pub tx_ring_empty_descriptors: u64,
}

/// Linux `struct xdp_options`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpOptions {
    /// Negotiated option bits.
    pub flags: u32,
}

/// Linux `struct xdp_desc`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpDescriptor {
    /// UMEM-relative packet address.
    pub address: u64,
    /// Visible packet length.
    pub len: u32,
    /// Descriptor option bits.
    pub options: u32,
}

/// Descriptor element stored by one native ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingElement {
    /// Fill and Completion rings contain one UMEM address.
    UmemAddress,
    /// RX and TX rings contain one [`XdpDescriptor`].
    PacketDescriptor,
}

impl RingElement {
    const fn size(self) -> usize {
        match self {
            Self::UmemAddress => size_of::<u64>(),
            Self::PacketDescriptor => size_of::<XdpDescriptor>(),
        }
    }

    const fn alignment(self) -> usize {
        match self {
            Self::UmemAddress => align_of::<u64>(),
            Self::PacketDescriptor => align_of::<XdpDescriptor>(),
        }
    }
}

/// Checked process-relative offsets and required mmap byte length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingMmapLayout {
    producer: usize,
    consumer: usize,
    flags: usize,
    descriptors: usize,
    byte_len: usize,
}

impl RingMmapLayout {
    /// Validates kernel-reported offsets before any future mmap pointer access.
    pub fn new(
        raw: XdpRingOffset,
        entries: RingEntries,
        element: RingElement,
    ) -> Result<Self, AbiLayoutError> {
        let fields = [
            checked_extent(
                RingField::Producer,
                raw.producer,
                size_of::<u32>(),
                align_of::<u32>(),
            )?,
            checked_extent(
                RingField::Consumer,
                raw.consumer,
                size_of::<u32>(),
                align_of::<u32>(),
            )?,
            checked_extent(
                RingField::Flags,
                raw.flags,
                size_of::<u32>(),
                align_of::<u32>(),
            )?,
            checked_extent(
                RingField::Descriptors,
                raw.descriptors,
                element.size().checked_mul(entries.get() as usize).ok_or(
                    AbiLayoutError::ExtentOverflow {
                        field: RingField::Descriptors,
                    },
                )?,
                element.alignment(),
            )?,
        ];

        for (index, first) in fields.iter().enumerate() {
            for second in &fields[index + 1..] {
                if first.start < second.end && second.start < first.end {
                    return Err(AbiLayoutError::OverlappingFields {
                        first: first.field,
                        second: second.field,
                    });
                }
            }
        }

        let byte_len = fields
            .iter()
            .map(|extent| extent.end)
            .max()
            .expect("four ring fields");
        Ok(Self {
            producer: usize::try_from(raw.producer)
                .map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
            consumer: usize::try_from(raw.consumer)
                .map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
            flags: usize::try_from(raw.flags).map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
            descriptors: usize::try_from(raw.descriptors)
                .map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
            byte_len: usize::try_from(byte_len)
                .map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
        })
    }

    /// Returns the producer cursor offset.
    #[must_use]
    pub const fn producer(self) -> usize {
        self.producer
    }

    /// Returns the consumer cursor offset.
    #[must_use]
    pub const fn consumer(self) -> usize {
        self.consumer
    }

    /// Returns the flags-word offset.
    #[must_use]
    pub const fn flags(self) -> usize {
        self.flags
    }

    /// Returns the descriptor-array offset.
    #[must_use]
    pub const fn descriptors(self) -> usize {
        self.descriptors
    }

    /// Returns the minimum required mmap byte length.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        self.byte_len
    }
}

#[derive(Clone, Copy)]
struct Extent {
    field: RingField,
    start: u64,
    end: u64,
}

fn checked_extent(
    field: RingField,
    offset: u64,
    len: usize,
    alignment: usize,
) -> Result<Extent, AbiLayoutError> {
    if !offset.is_multiple_of(alignment as u64) {
        return Err(AbiLayoutError::MisalignedOffset {
            field,
            offset,
            alignment,
        });
    }
    let len = u64::try_from(len).map_err(|_| AbiLayoutError::ExtentOverflow { field })?;
    let end = offset
        .checked_add(len)
        .ok_or(AbiLayoutError::ExtentOverflow { field })?;
    Ok(Extent {
        field,
        start: offset,
        end,
    })
}

use crate::{domain::DomainIdentity, FrameId};

/// Untrusted descriptor fields read from, or intended for, an AF_XDP ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawDescriptor {
    /// UMEM-relative start address of packet bytes.
    pub addr: u64,
    /// Number of visible packet bytes.
    pub len: u32,
    /// Descriptor option bits.
    pub options: u32,
}

/// Descriptor fields after validation against one [`crate::UmemLayout`].
///
/// The value is `Copy`, but its hidden domain binding remains unchanged.
/// Copying it cannot make it valid for another UMEM or ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDescriptor {
    domain: DomainIdentity,
    frame: FrameId,
    frame_base: u64,
    data_offset: u32,
    len: u32,
}

impl ValidatedDescriptor {
    pub(crate) const fn new(
        domain: DomainIdentity,
        frame: FrameId,
        frame_base: u64,
        data_offset: u32,
        len: u32,
    ) -> Self {
        Self {
            domain,
            frame,
            frame_base,
            data_offset,
            len,
        }
    }

    /// Returns the canonical frame containing all visible bytes.
    #[must_use]
    pub const fn frame(self) -> FrameId {
        self.frame
    }

    /// Returns the UMEM-relative base address of the containing frame.
    #[must_use]
    pub const fn frame_base(self) -> u64 {
        self.frame_base
    }

    /// Returns the byte offset of packet data within the frame.
    #[must_use]
    pub const fn data_offset(self) -> u32 {
        self.data_offset
    }

    /// Returns the checked visible packet length.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.len
    }

    /// Reports whether the descriptor has no visible packet bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// The same frame's bytes with the start moved: a positive `delta` drops that
    /// many bytes from the front, a negative one takes that many more before it.
    /// `None` when the result would leave the frame of `frame_size` bytes.
    #[must_use]
    pub fn moved_front(self, delta: i64, frame_size: u64) -> Option<Self> {
        let offset = i64::from(self.data_offset).checked_add(delta)?;
        let len = i64::from(self.len).checked_sub(delta)?;
        let offset = u32::try_from(offset).ok()?;
        let len = u32::try_from(len).ok()?;
        if u64::from(offset) + u64::from(len) > frame_size {
            return None;
        }
        Some(Self {
            data_offset: offset,
            len,
            ..self
        })
    }

    pub(crate) fn belongs_to(self, domain: DomainIdentity) -> bool {
        self.domain == domain
    }
}

/// Reason an untrusted descriptor cannot designate one packet in one frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    /// The start address lies outside the configured UMEM extent.
    AddressOutsideUmem,
    /// The packet begins before the reserved per-frame headroom.
    DataBeforeHeadroom,
    /// A packet descriptor must expose at least one byte.
    EmptyPacket,
    /// Address plus length overflowed its integer representation.
    AddressLengthOverflow,
    /// The visible byte range crosses the containing frame boundary.
    CrossesFrameBoundary,
    /// This model supports only a single-buffer descriptor with no option bits.
    UnsupportedOptions(u32),
}

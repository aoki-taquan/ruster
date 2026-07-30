use crate::{
    domain::DomainIdentity, DescriptorError, FrameId, RawDescriptor, UmemDomainId,
    ValidatedDescriptor,
};

/// Checked fixed-frame UMEM geometry.
#[derive(Debug, Eq, PartialEq)]
pub struct UmemLayout {
    domain: DomainIdentity,
    frame_count: u32,
    frame_size: u32,
    headroom: u32,
    byte_len: u64,
}

impl UmemLayout {
    /// Creates an aligned-chunk layout.
    ///
    /// Frame size must be a power of two and headroom must leave at least one
    /// visible byte in every frame.
    pub fn new(
        domain: UmemDomainId,
        frame_count: u32,
        frame_size: u32,
        headroom: u32,
    ) -> Result<Self, LayoutError> {
        if frame_count == 0 {
            return Err(LayoutError::ZeroFrameCount);
        }
        if !frame_size.is_power_of_two() {
            return Err(LayoutError::FrameSizeNotPowerOfTwo);
        }
        if headroom >= frame_size {
            return Err(LayoutError::HeadroomConsumesFrame);
        }
        let byte_len = u64::from(frame_count)
            .checked_mul(u64::from(frame_size))
            .ok_or(LayoutError::ByteLengthOverflow)?;

        Ok(Self {
            domain: domain.into_inner(),
            frame_count,
            frame_size,
            headroom,
            byte_len,
        })
    }

    /// Returns the number of frames.
    #[must_use]
    pub const fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Returns the fixed frame size in bytes.
    #[must_use]
    pub const fn frame_size(&self) -> u32 {
        self.frame_size
    }

    /// Returns the reserved prefix in every frame.
    #[must_use]
    pub const fn headroom(&self) -> u32 {
        self.headroom
    }

    /// Returns the total UMEM extent in bytes.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Resolves a frame index into its canonical identity.
    pub fn frame_id(&self, index: u32) -> Result<FrameId, LayoutError> {
        if index >= self.frame_count {
            return Err(LayoutError::FrameIndexOutsideUmem);
        }
        Ok(FrameId::from_index(index))
    }

    /// Validates that one descriptor exposes bytes wholly within one frame.
    pub fn validate_descriptor(
        &self,
        descriptor: RawDescriptor,
    ) -> Result<ValidatedDescriptor, DescriptorError> {
        if descriptor.options != 0 {
            return Err(DescriptorError::UnsupportedOptions(descriptor.options));
        }
        if descriptor.len == 0 {
            return Err(DescriptorError::EmptyPacket);
        }
        if descriptor.addr >= self.byte_len {
            return Err(DescriptorError::AddressOutsideUmem);
        }

        let frame_size = u64::from(self.frame_size);
        let index = descriptor.addr / frame_size;
        let frame_base = index * frame_size;
        let data_offset =
            u32::try_from(descriptor.addr - frame_base).expect("offset is smaller than u32 frame");
        if data_offset < self.headroom {
            return Err(DescriptorError::DataBeforeHeadroom);
        }

        let end = descriptor
            .addr
            .checked_add(u64::from(descriptor.len))
            .ok_or(DescriptorError::AddressLengthOverflow)?;
        let frame_end = frame_base + frame_size;
        if end > frame_end {
            return Err(DescriptorError::CrossesFrameBoundary);
        }

        let frame_index = u32::try_from(index).map_err(|_| DescriptorError::AddressOutsideUmem)?;
        Ok(ValidatedDescriptor::new(
            self.domain,
            FrameId::from_index(frame_index),
            frame_base,
            data_offset,
            descriptor.len,
        ))
    }

    pub(crate) const fn domain(&self) -> DomainIdentity {
        self.domain
    }
}

/// Reason fixed-frame UMEM geometry is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    /// At least one frame is required.
    ZeroFrameCount,
    /// Aligned-chunk canonicalization requires a nonzero power-of-two size.
    FrameSizeNotPowerOfTwo,
    /// Headroom must leave at least one usable byte.
    HeadroomConsumesFrame,
    /// The total byte extent cannot be represented.
    ByteLengthOverflow,
    /// The requested frame index is outside the UMEM extent.
    FrameIndexOutsideUmem,
}

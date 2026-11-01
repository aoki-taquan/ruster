//! Borrowed ring-mapping validation.
//!
//! This private module never owns or creates an operating-system mapping. It
//! binds a checked C0 layout to borrowed bytes and retains the exclusive
//! borrow for the complete native ring-view lifetime. The bytes come either
//! from a caller-owned `&mut [u8]` or, for a live session, from an exclusive
//! borrow of an owned kernel ring mapping (`MappedRegion::borrow_mapping`).

use std::{marker::PhantomData, mem::align_of, ptr::NonNull};

use crate::{abi::RingMmapLayout, RingField, RingMapError};

pub(crate) struct BorrowedMmap<'memory> {
    base: NonNull<u8>,
    len: usize,
    _borrow: PhantomData<&'memory mut [u8]>,
}

impl<'memory> BorrowedMmap<'memory> {
    pub(super) fn new(
        memory: &'memory mut [u8],
        layout: RingMmapLayout,
    ) -> Result<Self, RingMapError> {
        let mapping = Self {
            base: NonNull::new(memory.as_mut_ptr()).expect("slice pointers are non-null"),
            len: memory.len(),
            _borrow: PhantomData,
        };
        mapping.validate(layout)?;
        Ok(mapping)
    }

    /// Wraps `len` bytes at `base` as an exclusive borrow for `'memory`.
    ///
    /// # Safety
    ///
    /// For all of `'memory`, `base..base + len` must be one live readable and
    /// writable mapping that no Rust reference aliases, and nothing may unmap
    /// it. Concurrent writes by the kernel are permitted because every access
    /// through the result is atomic or volatile and never forms a reference to
    /// descriptor memory.
    #[cfg_attr(
        not(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        )),
        allow(dead_code)
    )]
    #[allow(unsafe_code)]
    pub(super) unsafe fn from_raw_parts(base: NonNull<u8>, len: usize) -> Self {
        Self {
            base,
            len,
            _borrow: PhantomData,
        }
    }

    /// Releases the base and length to a sibling owner that keeps the same
    /// exclusive-borrow and no-reference contract for `'memory`.
    #[cfg_attr(
        not(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        )),
        allow(dead_code)
    )]
    pub(super) fn into_parts(self) -> (NonNull<u8>, usize) {
        (self.base, self.len)
    }

    /// Checks the minimum extent and the actual cursor-field address alignment.
    pub(super) fn validate(&self, layout: RingMmapLayout) -> Result<(), RingMapError> {
        if self.len < layout.byte_len() {
            return Err(RingMapError::MappingTooShort {
                required: layout.byte_len(),
                actual: self.len,
            });
        }
        self.validate_field::<u32>(RingField::Producer, layout.producer())?;
        self.validate_field::<u32>(RingField::Consumer, layout.consumer())?;
        self.validate_field::<u32>(RingField::Flags, layout.flags())?;
        Ok(())
    }

    pub(super) fn field<T>(
        &self,
        field: RingField,
        offset: usize,
    ) -> Result<NonNull<T>, RingMapError> {
        self.validate_field::<T>(field, offset)?;
        let pointer = self.base.as_ptr().wrapping_add(offset).cast::<T>();
        NonNull::new(pointer).ok_or(RingMapError::FieldAddressOverflow { field })
    }

    fn validate_field<T>(&self, field: RingField, offset: usize) -> Result<(), RingMapError> {
        let address = self
            .base
            .as_ptr()
            .addr()
            .checked_add(offset)
            .ok_or(RingMapError::FieldAddressOverflow { field })?;
        let alignment = align_of::<T>();
        if !address.is_multiple_of(alignment) {
            return Err(RingMapError::MisalignedFieldAddress { field, alignment });
        }
        Ok(())
    }
}

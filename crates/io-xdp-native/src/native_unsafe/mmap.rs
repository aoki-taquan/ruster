//! Borrowed ring-mapping validation.
//!
//! This private module never owns or creates an operating-system mapping. It
//! binds a checked C0 layout to caller-owned bytes and retains the exclusive
//! borrow for the complete native ring-view lifetime.

use std::{marker::PhantomData, mem::align_of, ptr::NonNull};

use crate::{abi::RingMmapLayout, RingField, RingMapError};

pub(super) struct BorrowedMmap<'memory> {
    base: NonNull<u8>,
    _borrow: PhantomData<&'memory mut [u8]>,
}

impl<'memory> BorrowedMmap<'memory> {
    pub(super) fn new(
        memory: &'memory mut [u8],
        layout: RingMmapLayout,
    ) -> Result<Self, RingMapError> {
        if memory.len() < layout.byte_len() {
            return Err(RingMapError::MappingTooShort {
                required: layout.byte_len(),
                actual: memory.len(),
            });
        }

        let mapping = Self {
            base: NonNull::new(memory.as_mut_ptr()).expect("slice pointers are non-null"),
            _borrow: PhantomData,
        };
        mapping.validate_field::<u32>(RingField::Producer, layout.producer())?;
        mapping.validate_field::<u32>(RingField::Consumer, layout.consumer())?;
        mapping.validate_field::<u32>(RingField::Flags, layout.flags())?;
        Ok(mapping)
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

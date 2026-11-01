#![allow(unsafe_code)]
//! Ledger-gated byte access to one borrowed UMEM mapping.
//!
//! The kernel owns, and may write at any time, every frame that the
//! application published to the Fill ring (and reads every frame published
//! to the TX ring). Rust references into UMEM are therefore formed only for
//! one frame at a time, only while the paired [`FrameLedger`] records that
//! frame as `Leased` (owned by user space), and only for the exact visible
//! byte range of the descriptor the kernel returned. The reference borrows
//! [`UmemFrames`], so no ledger transition, and in particular no recycle to
//! the Fill ring, can happen while it is alive.
//!
//! Soundness of the lease check relies on one crate-private protocol, kept
//! by the RX/Fill engine (`rx_fill.rs`), the only ledger mutator: a frame
//! enters `Leased` either from `Free` without ever being published to the
//! kernel, or from `FillOwnedByKernel` only after the kernel returned that
//! exact frame on the RX ring (`receive` then `lease_rx`). A kernel that
//! keeps writing a frame after returning it violates the AF_XDP contract.

use std::{fmt, marker::PhantomData, ptr::NonNull};

use ruster_io_xdp::{FrameLedger, FrameStateKind, FrameToken, ValidatedDescriptor};

use super::mmap::BorrowedMmap;

/// Exclusive borrow of the complete UMEM byte range, without any reference.
pub(crate) struct UmemMapping<'memory> {
    base: NonNull<u8>,
    len: usize,
    _borrow: PhantomData<&'memory mut [u8]>,
}

impl<'memory> UmemMapping<'memory> {
    /// Borrows caller-owned process memory (tests and heap-backed callers).
    pub(crate) fn from_slice(memory: &'memory mut [u8]) -> Self {
        Self {
            base: NonNull::new(memory.as_mut_ptr()).expect("slice pointers are non-null"),
            len: memory.len(),
            _borrow: PhantomData,
        }
    }

    /// Takes over an exclusive borrow of a live session UMEM mapping.
    #[cfg_attr(
        not(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        )),
        allow(dead_code)
    )]
    pub(crate) fn from_mapping(mapping: BorrowedMmap<'memory>) -> Self {
        let (base, len) = mapping.into_parts();
        Self {
            base,
            len,
            _borrow: PhantomData,
        }
    }

    /// Wraps `len` bytes at `base`.
    ///
    /// # Safety
    ///
    /// For all of `'memory`, `base..base + len` must be one live readable and
    /// writable allocation or mapping that nothing unmaps or frees. Other
    /// parties (the kernel, or a test's scripted kernel) may access it only
    /// through raw pointers and only outside the frames that the paired
    /// ledger records as `Leased`.
    #[cfg(test)]
    pub(super) unsafe fn from_raw_parts(base: NonNull<u8>, len: usize) -> Self {
        Self {
            base,
            len,
            _borrow: PhantomData,
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }
}

impl fmt::Debug for UmemMapping<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UmemMapping")
            .field("base", &"<redacted>")
            .field("len", &self.len)
            .finish()
    }
}

/// Failure pairing a UMEM mapping with its ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UmemPairingError {
    /// The mapping is shorter than the ledger layout.
    MappingTooShort,
    /// The ledger already tracks ownership that this engine did not create.
    LedgerNotFresh,
}

/// One UMEM mapping and the authoritative ledger of its frames.
pub(crate) struct UmemFrames<'memory> {
    mapping: UmemMapping<'memory>,
    ledger: FrameLedger,
    frame_size: u64,
}

impl<'memory> UmemFrames<'memory> {
    /// Pairs a mapping with a fresh ledger whose layout fits inside it.
    pub(crate) fn new(
        mapping: UmemMapping<'memory>,
        ledger: FrameLedger,
    ) -> Result<Self, UmemPairingError> {
        let layout = ledger.layout();
        let fits = usize::try_from(layout.byte_len()).is_ok_and(|len| len <= mapping.len());
        if !fits {
            return Err(UmemPairingError::MappingTooShort);
        }
        if ledger.counts().get(FrameStateKind::Free) != ledger.frame_count()
            || ledger.deep_audit().is_err()
        {
            return Err(UmemPairingError::LedgerNotFresh);
        }
        let frame_size = u64::from(layout.frame_size());
        Ok(Self {
            mapping,
            ledger,
            frame_size,
        })
    }

    pub(crate) const fn ledger(&self) -> &FrameLedger {
        &self.ledger
    }

    /// Mutable ledger access for the engine protocol described above.
    pub(crate) fn ledger_mut(&mut self) -> &mut FrameLedger {
        &mut self.ledger
    }

    /// Returns `(offset, len)` of the visible bytes when `token` is the live
    /// `Leased` owner of the descriptor's frame and the range lies inside
    /// that frame and the mapping.
    fn leased_range(
        &self,
        token: FrameToken,
        descriptor: ValidatedDescriptor,
    ) -> Option<(usize, usize)> {
        let frame = descriptor.frame();
        if token.frame() != frame {
            return None;
        }
        let state = self.ledger.state(frame.index()).ok()?;
        if state.kind() != FrameStateKind::Leased || state.token() != Some(token) {
            return None;
        }
        // Recompute containment from this ledger's own geometry instead of
        // trusting the descriptor's origin.
        let base = u64::from(frame.index()).checked_mul(self.frame_size)?;
        if descriptor.frame_base() != base {
            return None;
        }
        let end_in_frame =
            u64::from(descriptor.data_offset()).checked_add(u64::from(descriptor.len()))?;
        if end_in_frame > self.frame_size {
            return None;
        }
        let start = base.checked_add(u64::from(descriptor.data_offset()))?;
        let end = base.checked_add(end_in_frame)?;
        let end = usize::try_from(end).ok()?;
        if end > self.mapping.len {
            return None;
        }
        let start = usize::try_from(start).ok()?;
        Some((start, end - start))
    }

    /// Shared view of a leased frame's visible bytes.
    pub(crate) fn leased_bytes(
        &self,
        token: FrameToken,
        descriptor: ValidatedDescriptor,
    ) -> Option<&[u8]> {
        let (start, len) = self.leased_range(token, descriptor)?;
        let pointer = self.mapping.base.as_ptr().wrapping_add(start);
        // SAFETY: `leased_range` proved `start..start + len` lies inside the
        // borrowed mapping and inside one frame that the ledger records as
        // `Leased` by `token`. By the module protocol the kernel neither
        // owns nor writes a `Leased` frame, and every other party accesses
        // UMEM only through raw pointers outside leased frames. The returned
        // reference borrows `self`, so the ledger cannot leave `Leased`
        // (which needs `&mut self`) while it lives. Any byte pattern is a
        // valid `u8`.
        Some(unsafe { std::slice::from_raw_parts(pointer, len) })
    }

    /// Exclusive view of a leased frame's visible bytes.
    pub(crate) fn leased_bytes_mut(
        &mut self,
        token: FrameToken,
        descriptor: ValidatedDescriptor,
    ) -> Option<&mut [u8]> {
        let (start, len) = self.leased_range(token, descriptor)?;
        let pointer = self.mapping.base.as_ptr().wrapping_add(start);
        // SAFETY: the extent, ownership, and kernel-exclusion arguments of
        // `leased_bytes` apply. The reference borrows `self` mutably, so no
        // other reference into this mapping created through `UmemFrames`
        // coexists with it, and the ledger cannot change until it ends.
        Some(unsafe { std::slice::from_raw_parts_mut(pointer, len) })
    }
}

impl fmt::Debug for UmemFrames<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UmemFrames")
            .field("mapping", &self.mapping)
            .field("counts", &self.ledger.counts())
            .finish_non_exhaustive()
    }
}

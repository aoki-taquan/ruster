//! Cold ownership storage and checked combined-ring extent foundations.
//!
//! AP1-0 does not perform packet I/O. It fixes the disjoint RX/TX mapping
//! boundary and allocates the metadata backing that later RX/TX state machines
//! will reuse without allocating in steady operation.

use crate::{
    MappingAccessError, PlatformError, RingKind, TxFrameModel, ValidatedPort, TPACKET_ALIGNMENT,
    TPACKET_V3_HEADER_LEN,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RingExtent {
    start: usize,
    end: usize,
}

impl RingExtent {
    pub(crate) const fn start(self) -> usize {
        self.start
    }

    pub(crate) const fn len(self) -> usize {
        self.end - self.start
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CombinedRingExtents {
    rx: RingExtent,
    tx: RingExtent,
    combined_len: usize,
}

impl CombinedRingExtents {
    pub(crate) fn for_port(port: ValidatedPort) -> Result<Self, MappingAccessError> {
        Self::validate(
            port.rx().map_len(),
            port.tx_map_offset(),
            port.tx().map_len(),
            port.combined_map_len(),
        )
    }

    fn validate(
        rx_len: usize,
        tx_offset: usize,
        tx_len: usize,
        combined_len: usize,
    ) -> Result<Self, MappingAccessError> {
        if tx_offset < rx_len {
            return Err(MappingAccessError::RingExtentsOverlap {
                rx_end: rx_len,
                tx_start: tx_offset,
            });
        }
        if tx_offset > rx_len {
            return Err(MappingAccessError::RingExtentGap {
                rx_end: rx_len,
                tx_start: tx_offset,
            });
        }
        if !tx_offset.is_multiple_of(TPACKET_ALIGNMENT) {
            return Err(MappingAccessError::RingExtentMisaligned {
                kind: RingKind::Tx,
                offset: tx_offset,
                alignment: TPACKET_ALIGNMENT,
            });
        }
        let tx_end = tx_offset
            .checked_add(tx_len)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        if tx_end != combined_len {
            return Err(MappingAccessError::CombinedLengthMismatch {
                expected: tx_end,
                actual: combined_len,
            });
        }
        Ok(Self {
            rx: RingExtent {
                start: 0,
                end: rx_len,
            },
            tx: RingExtent {
                start: tx_offset,
                end: tx_end,
            },
            combined_len,
        })
    }

    pub(crate) const fn rx(self) -> RingExtent {
        self.rx
    }

    pub(crate) const fn tx(self) -> RingExtent {
        self.tx
    }

    pub(crate) const fn combined_len(self) -> usize {
        self.combined_len
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct RxPacketMetadata {
    pub(crate) data_offset: usize,
    pub(crate) data_len: usize,
    pub(crate) next_offset: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct TxFrameMetadata {
    pub(crate) generation: u64,
    pub(crate) ownership: TxFrameModel,
}

#[allow(dead_code)]
pub(crate) struct ColdRingMetadata {
    rx_packets: Box<[RxPacketMetadata]>,
    tx_frames: Box<[TxFrameMetadata]>,
}

#[allow(dead_code)]
impl ColdRingMetadata {
    pub(crate) fn for_port(port: ValidatedPort) -> Result<Self, PlatformError> {
        let rx = port.rx();
        let rx_packets = (rx.block_size() - rx.block_plus_private()) / TPACKET_V3_HEADER_LEN;
        let tx = port.tx();
        let tx_frames = tx.map_len() / tx.frame_size();
        Ok(Self {
            rx_packets: fixed_storage(RingKind::Rx, rx_packets, RxPacketMetadata::default())?,
            tx_frames: fixed_storage(RingKind::Tx, tx_frames, TxFrameMetadata::default())?,
        })
    }

    pub(crate) fn rx_packets(&self) -> &[RxPacketMetadata] {
        &self.rx_packets
    }

    pub(crate) fn rx_packets_mut(&mut self) -> &mut [RxPacketMetadata] {
        &mut self.rx_packets
    }

    pub(crate) fn tx_frames(&self) -> &[TxFrameMetadata] {
        &self.tx_frames
    }

    pub(crate) fn tx_frames_mut(&mut self) -> &mut [TxFrameMetadata] {
        &mut self.tx_frames
    }
}

fn fixed_storage<T: Copy>(
    kind: RingKind,
    entries: usize,
    value: T,
) -> Result<Box<[T]>, PlatformError> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(entries)
        .map_err(|_| PlatformError::MetadataAllocationFailed { kind, entries })?;
    storage.resize(entries, value);
    Ok(storage.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::CombinedRingExtents;
    use crate::{MappingAccessError, RingKind, TPACKET_ALIGNMENT};

    #[test]
    fn combined_ring_extents_reject_overlap_gap_alignment_overflow_and_wrong_length() {
        let valid =
            CombinedRingExtents::validate(4_096, 4_096, 4_096, 8_192).expect("adjacent extents");
        assert_eq!((valid.rx().start(), valid.rx().len()), (0, 4_096));
        assert_eq!((valid.tx().start(), valid.tx().len()), (4_096, 4_096));
        assert_eq!(valid.combined_len(), 8_192);

        assert_eq!(
            CombinedRingExtents::validate(4_096, 2_048, 4_096, 6_144),
            Err(MappingAccessError::RingExtentsOverlap {
                rx_end: 4_096,
                tx_start: 2_048,
            })
        );
        assert_eq!(
            CombinedRingExtents::validate(4_096, 8_192, 4_096, 12_288),
            Err(MappingAccessError::RingExtentGap {
                rx_end: 4_096,
                tx_start: 8_192,
            })
        );
        assert_eq!(
            CombinedRingExtents::validate(4_097, 4_097, 4_096, 8_193),
            Err(MappingAccessError::RingExtentMisaligned {
                kind: RingKind::Tx,
                offset: 4_097,
                alignment: TPACKET_ALIGNMENT,
            })
        );
        assert_eq!(
            CombinedRingExtents::validate(usize::MAX - 15, usize::MAX - 15, 16, 0),
            Err(MappingAccessError::ArithmeticOverflow)
        );
        assert_eq!(
            CombinedRingExtents::validate(4_096, 4_096, 4_096, 8_191),
            Err(MappingAccessError::CombinedLengthMismatch {
                expected: 8_192,
                actual: 8_191,
            })
        );
    }
}

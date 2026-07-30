use std::ops::Range;

use crate::{
    error::TxOperation, GeometryError, OwnershipError, RingLayout, TPACKET_ALIGNMENT,
    TPACKET_BLOCK_HEADER_LEN, TPACKET_V3_HEADER_LEN,
};

pub const TP_STATUS_KERNEL: u32 = 0;
pub const TP_STATUS_USER: u32 = 1;
pub const TP_STATUS_AVAILABLE: u32 = 0;
pub const TP_STATUS_SEND_REQUEST: u32 = 1;
pub const TP_STATUS_SENDING: u32 = 2;
pub const TP_STATUS_WRONG_FORMAT: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockDescriptor {
    pub block_len: usize,
    pub packet_count: u32,
    pub first_packet_offset: usize,
}

impl BlockDescriptor {
    pub fn validate(self, layout: RingLayout) -> Result<(), GeometryError> {
        if self.packet_count == 0 {
            return Err(GeometryError::PacketCountZero);
        }
        if self.block_len < TPACKET_BLOCK_HEADER_LEN || self.block_len > layout.block_size() {
            return Err(GeometryError::FirstPacketOffsetInvalid {
                offset: self.first_packet_offset,
            });
        }
        let first_packet_minimum = TPACKET_BLOCK_HEADER_LEN
            .checked_add(
                usize::try_from(layout.geometry().private_size)
                    .map_err(|_| GeometryError::ArithmeticOverflow)?,
            )
            .ok_or(GeometryError::ArithmeticOverflow)?;
        if self.first_packet_offset < first_packet_minimum
            || !self.first_packet_offset.is_multiple_of(TPACKET_ALIGNMENT)
        {
            return Err(GeometryError::FirstPacketOffsetInvalid {
                offset: self.first_packet_offset,
            });
        }
        let first_header_end = self
            .first_packet_offset
            .checked_add(TPACKET_V3_HEADER_LEN)
            .ok_or(GeometryError::ArithmeticOverflow)?;
        if first_header_end > self.block_len {
            return Err(GeometryError::PacketHeaderOutOfBounds {
                offset: self.first_packet_offset,
            });
        }
        let maximum = (self.block_len - self.first_packet_offset) / TPACKET_V3_HEADER_LEN;
        if usize::try_from(self.packet_count)
            .ok()
            .is_none_or(|count| count > maximum)
        {
            return Err(GeometryError::PacketCountExceedsBlock {
                packet_count: self.packet_count,
                maximum,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketDescriptor {
    pub packet_offset: usize,
    pub next_offset: usize,
    pub mac_offset: usize,
    pub snap_len: usize,
    pub wire_len: usize,
    pub is_last: bool,
}

impl PacketDescriptor {
    pub fn validate(self, block_len: usize) -> Result<ValidatedPacket, GeometryError> {
        if !self.packet_offset.is_multiple_of(TPACKET_ALIGNMENT) {
            return Err(GeometryError::PacketOffsetNotAligned {
                offset: self.packet_offset,
            });
        }
        if self.packet_offset < TPACKET_BLOCK_HEADER_LEN {
            return Err(GeometryError::PacketHeaderOutOfBounds {
                offset: self.packet_offset,
            });
        }
        let header_end = self
            .packet_offset
            .checked_add(TPACKET_V3_HEADER_LEN)
            .ok_or(GeometryError::ArithmeticOverflow)?;
        if header_end > block_len {
            return Err(GeometryError::PacketHeaderOutOfBounds {
                offset: self.packet_offset,
            });
        }
        if self.mac_offset < TPACKET_V3_HEADER_LEN {
            return Err(GeometryError::MacOffsetBeforeHeader {
                mac_offset: self.mac_offset,
            });
        }
        if self.snap_len > self.wire_len {
            return Err(GeometryError::SnapshotExceedsWireLength {
                snap_len: self.snap_len,
                wire_len: self.wire_len,
            });
        }
        let data_start = self
            .packet_offset
            .checked_add(self.mac_offset)
            .ok_or(GeometryError::ArithmeticOverflow)?;
        let data_end = data_start
            .checked_add(self.snap_len)
            .ok_or(GeometryError::ArithmeticOverflow)?;
        if data_end > block_len {
            return Err(GeometryError::PacketDataOutOfBounds {
                offset: data_start,
                length: self.snap_len,
            });
        }

        let next_packet_offset = if self.next_offset == 0 {
            if self.is_last {
                None
            } else {
                return Err(GeometryError::MissingNextPacketOffset);
            }
        } else {
            if !self.next_offset.is_multiple_of(TPACKET_ALIGNMENT) {
                return Err(GeometryError::NextPacketOffsetNotAligned {
                    offset: self.next_offset,
                });
            }
            if self.next_offset < TPACKET_V3_HEADER_LEN {
                return Err(GeometryError::NextPacketOffsetTooSmall {
                    offset: self.next_offset,
                });
            }
            let next = self
                .packet_offset
                .checked_add(self.next_offset)
                .ok_or(GeometryError::ArithmeticOverflow)?;
            let next_header_end = next
                .checked_add(TPACKET_V3_HEADER_LEN)
                .ok_or(GeometryError::ArithmeticOverflow)?;
            if next_header_end > block_len {
                return Err(GeometryError::PacketHeaderOutOfBounds { offset: next });
            }
            if data_end > next {
                return Err(GeometryError::PacketCrossesNextOffset);
            }
            Some(next)
        };

        Ok(ValidatedPacket {
            header: self.packet_offset..header_end,
            data: data_start..data_end,
            next_packet_offset,
            truncated: self.snap_len < self.wire_len,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPacket {
    header: Range<usize>,
    data: Range<usize>,
    next_packet_offset: Option<usize>,
    truncated: bool,
}

impl ValidatedPacket {
    #[must_use]
    pub fn header(&self) -> Range<usize> {
        self.header.start..self.header.end
    }

    #[must_use]
    pub fn data(&self) -> Range<usize> {
        self.data.start..self.data.end
    }

    #[must_use]
    pub const fn next_packet_offset(&self) -> Option<usize> {
        self.next_packet_offset
    }

    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxOwnership {
    Kernel,
    User,
}

impl RxOwnership {
    pub fn from_status(status: u32) -> Result<Self, GeometryError> {
        if status == TP_STATUS_KERNEL {
            Ok(Self::Kernel)
        } else if status & TP_STATUS_USER != 0 {
            Ok(Self::User)
        } else {
            Err(GeometryError::InvalidRxStatus { status })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxBlockModel {
    owner: RxOwnership,
    packets: u32,
    completed: u32,
}

impl Default for RxBlockModel {
    fn default() -> Self {
        Self::new()
    }
}

impl RxBlockModel {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner: RxOwnership::Kernel,
            packets: 0,
            completed: 0,
        }
    }

    #[must_use]
    pub const fn owner(self) -> RxOwnership {
        self.owner
    }

    #[must_use]
    pub const fn remaining(self) -> u32 {
        self.packets - self.completed
    }

    pub fn acquire(&mut self, packets: u32) -> Result<(), OwnershipError> {
        if self.owner != RxOwnership::Kernel {
            return Err(OwnershipError::RxAcquireWhileOwned { owner: self.owner });
        }
        if packets == 0 {
            return Err(OwnershipError::RxPacketCountZero);
        }
        self.owner = RxOwnership::User;
        self.packets = packets;
        self.completed = 0;
        Ok(())
    }

    pub fn complete_packet(&mut self) -> Result<(), OwnershipError> {
        if self.owner == RxOwnership::Kernel {
            return Err(OwnershipError::RxReleaseWhileKernelOwned);
        }
        if self.completed == self.packets {
            return Err(OwnershipError::RxTooManyCompletions {
                packets: self.packets,
            });
        }
        self.completed += 1;
        Ok(())
    }

    pub fn release(&mut self) -> Result<(), OwnershipError> {
        if self.owner == RxOwnership::Kernel {
            return Err(OwnershipError::RxReleaseWhileKernelOwned);
        }
        let remaining = self.remaining();
        if remaining != 0 {
            return Err(OwnershipError::RxPacketsOutstanding { remaining });
        }
        self.owner = RxOwnership::Kernel;
        self.packets = 0;
        self.completed = 0;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxOwnership {
    Available,
    Prepared,
    SendRequest,
    Sending,
    WrongFormat,
}

impl TxOwnership {
    pub fn from_status(status: u32) -> Result<Self, GeometryError> {
        match status {
            TP_STATUS_AVAILABLE => Ok(Self::Available),
            TP_STATUS_SEND_REQUEST => Ok(Self::SendRequest),
            TP_STATUS_SENDING => Ok(Self::Sending),
            TP_STATUS_WRONG_FORMAT => Ok(Self::WrongFormat),
            _ => Err(GeometryError::InvalidTxStatus { status }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxFrameModel {
    owner: TxOwnership,
}

impl Default for TxFrameModel {
    fn default() -> Self {
        Self::new()
    }
}

impl TxFrameModel {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner: TxOwnership::Available,
        }
    }

    #[must_use]
    pub const fn owner(self) -> TxOwnership {
        self.owner
    }

    pub fn prepare(&mut self) -> Result<(), OwnershipError> {
        self.transition(
            TxOwnership::Available,
            TxOwnership::Prepared,
            TxOperation::Prepare,
        )
    }

    pub fn cancel_prepared(&mut self) -> Result<(), OwnershipError> {
        self.transition(
            TxOwnership::Prepared,
            TxOwnership::Available,
            TxOperation::CancelPrepared,
        )
    }

    pub fn publish(&mut self) -> Result<(), OwnershipError> {
        self.transition(
            TxOwnership::Prepared,
            TxOwnership::SendRequest,
            TxOperation::Publish,
        )
    }

    pub fn kernel_accept(&mut self) -> Result<(), OwnershipError> {
        self.transition(
            TxOwnership::SendRequest,
            TxOwnership::Sending,
            TxOperation::KernelAccept,
        )
    }

    pub fn kernel_complete(&mut self) -> Result<(), OwnershipError> {
        self.transition(
            TxOwnership::Sending,
            TxOwnership::Available,
            TxOperation::KernelComplete,
        )
    }

    pub fn kernel_reject_format(&mut self) -> Result<(), OwnershipError> {
        self.transition(
            TxOwnership::SendRequest,
            TxOwnership::WrongFormat,
            TxOperation::KernelRejectFormat,
        )
    }

    pub fn reclaim_unconsumed(&mut self) -> Result<(), OwnershipError> {
        self.transition(
            TxOwnership::SendRequest,
            TxOwnership::Available,
            TxOperation::ReclaimUnconsumed,
        )
    }

    pub fn recycle_wrong_format(&mut self) -> Result<(), OwnershipError> {
        self.transition(
            TxOwnership::WrongFormat,
            TxOwnership::Available,
            TxOperation::RecycleWrongFormat,
        )
    }

    fn transition(
        &mut self,
        from: TxOwnership,
        to: TxOwnership,
        operation: TxOperation,
    ) -> Result<(), OwnershipError> {
        if self.owner != from {
            return Err(OwnershipError::TxInvalidTransition {
                from: self.owner,
                operation,
            });
        }
        self.owner = to;
        Ok(())
    }
}

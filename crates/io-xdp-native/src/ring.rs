//! Safe, role-typed views over borrowed AF_XDP ring memory.
//!
//! The four public roles expose only the cursor operations owned by the
//! application. Reservations and acquisitions borrow their role exclusively,
//! allocate no memory, and publish only complete ranges.

use crate::{
    abi::{XdpDescriptor, XdpRingOffset},
    native_unsafe::ring_mem::{RingMemory, RingValue},
    NativeRingError, RingEntries, RingMapError,
};

/// Checked need-wakeup observation taken after producer publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeedWakeup {
    /// The kernel currently requests an explicit kick.
    Required,
    /// The kernel does not currently request an explicit kick.
    NotRequired,
}

/// Result of a complete producer publication.
///
/// Publication has already succeeded even when [`Self::need_wakeup`] reports
/// unsupported kernel flag bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "the post-publication need-wakeup observation must be handled"]
pub struct ProducerPublication {
    need_wakeup: Result<NeedWakeup, NativeRingError>,
}

impl ProducerPublication {
    /// Returns the checked flag observation taken after the Release publish.
    pub const fn need_wakeup(self) -> Result<NeedWakeup, NativeRingError> {
        self.need_wakeup
    }
}

struct ProducerRing<'memory, T: RingValue> {
    memory: RingMemory<'memory, T>,
}

impl<'memory, T: RingValue> ProducerRing<'memory, T> {
    fn new(
        memory: &'memory mut [u8],
        offsets: XdpRingOffset,
        entries: RingEntries,
    ) -> Result<Self, RingMapError> {
        Ok(Self {
            memory: RingMemory::new(memory, offsets, entries)?,
        })
    }

    const fn capacity(&self) -> u32 {
        self.memory.capacity()
    }

    fn need_wakeup(&self) -> Result<NeedWakeup, NativeRingError> {
        self.memory.need_wakeup().map(|required| {
            if required {
                NeedWakeup::Required
            } else {
                NeedWakeup::NotRequired
            }
        })
    }

    fn reserve(
        &mut self,
        len: u32,
    ) -> Result<ProducerReservation<'_, 'memory, T>, NativeRingError> {
        validate_len(len, self.capacity())?;
        let producer = self.memory.producer_relaxed();
        let consumer = self.memory.consumer_acquire();
        let occupied = occupied(producer, consumer, self.capacity())?;
        if len > self.capacity() - occupied {
            return Err(NativeRingError::RingFull);
        }
        Ok(ProducerReservation {
            ring: self,
            start: producer,
            len,
            written: 0,
        })
    }
}

struct ProducerReservation<'ring, 'memory, T: RingValue> {
    ring: &'ring mut ProducerRing<'memory, T>,
    start: u32,
    len: u32,
    written: u32,
}

impl<T: RingValue> ProducerReservation<'_, '_, T> {
    fn write(&mut self, value: T) -> Result<(), NativeRingError> {
        if self.written == self.len {
            return Err(NativeRingError::RangeExhausted);
        }
        self.ring
            .memory
            .write(self.start.wrapping_add(self.written), value);
        self.written += 1;
        Ok(())
    }

    fn release_submit(self) -> Result<ProducerPublication, NativeRingError> {
        if self.written != self.len {
            return Err(NativeRingError::IncompleteReservation {
                reserved: self.len,
                written: self.written,
            });
        }
        self.ring
            .memory
            .publish_producer(self.start.wrapping_add(self.len));
        let need_wakeup = self.ring.need_wakeup();
        Ok(ProducerPublication { need_wakeup })
    }

    fn release_cancel(self) {}
}

struct ConsumerRing<'memory, T: RingValue> {
    memory: RingMemory<'memory, T>,
}

impl<'memory, T: RingValue> ConsumerRing<'memory, T> {
    fn new(
        memory: &'memory mut [u8],
        offsets: XdpRingOffset,
        entries: RingEntries,
    ) -> Result<Self, RingMapError> {
        Ok(Self {
            memory: RingMemory::new(memory, offsets, entries)?,
        })
    }

    const fn capacity(&self) -> u32 {
        self.memory.capacity()
    }

    fn acquire(
        &mut self,
        len: u32,
    ) -> Result<ConsumerAcquisition<'_, 'memory, T>, NativeRingError> {
        validate_len(len, self.capacity())?;
        // This Acquire must occur before any descriptor read in the returned
        // acquisition.
        let producer = self.memory.producer_acquire();
        let consumer = self.memory.consumer_relaxed();
        let available = occupied(producer, consumer, self.capacity())?;
        if len > available {
            return Err(NativeRingError::RingEmpty);
        }
        Ok(ConsumerAcquisition {
            ring: self,
            start: consumer,
            len,
            read: 0,
        })
    }
}

struct ConsumerAcquisition<'ring, 'memory, T: RingValue> {
    ring: &'ring mut ConsumerRing<'memory, T>,
    start: u32,
    len: u32,
    read: u32,
}

impl<T: RingValue> ConsumerAcquisition<'_, '_, T> {
    fn read(&mut self) -> Result<T, NativeRingError> {
        if self.read == self.len {
            return Err(NativeRingError::RangeExhausted);
        }
        let value = self.ring.memory.read(self.start.wrapping_add(self.read));
        self.read += 1;
        Ok(value)
    }

    fn release_consume(self) -> Result<(), NativeRingError> {
        if self.read != self.len {
            return Err(NativeRingError::IncompleteAcquisition {
                acquired: self.len,
                read: self.read,
            });
        }
        self.ring
            .memory
            .publish_consumer(self.start.wrapping_add(self.len));
        Ok(())
    }

    fn release_cancel(self) {}
}

fn validate_len(len: u32, capacity: u32) -> Result<(), NativeRingError> {
    if len == 0 {
        Err(NativeRingError::ZeroLength)
    } else if len > capacity {
        Err(NativeRingError::LengthExceedsCapacity)
    } else {
        Ok(())
    }
}

fn occupied(producer: u32, consumer: u32, capacity: u32) -> Result<u32, NativeRingError> {
    let occupied = producer.wrapping_sub(consumer);
    if occupied > capacity {
        Err(NativeRingError::CorruptCursor {
            producer,
            consumer,
            capacity,
        })
    } else {
        Ok(occupied)
    }
}

/// Application producer for the UMEM Fill ring.
pub struct FillProducer<'memory> {
    inner: ProducerRing<'memory, u64>,
}

impl<'memory> FillProducer<'memory> {
    /// Binds a Fill producer to checked caller-owned mapped bytes.
    pub fn new(
        memory: &'memory mut [u8],
        offsets: XdpRingOffset,
        entries: RingEntries,
    ) -> Result<Self, RingMapError> {
        Ok(Self {
            inner: ProducerRing::new(memory, offsets, entries)?,
        })
    }

    /// Returns the checked fixed capacity.
    pub const fn capacity(&self) -> u32 {
        self.inner.capacity()
    }

    /// Reads the kernel-owned need-wakeup flag without issuing a wakeup.
    pub fn need_wakeup(&self) -> Result<NeedWakeup, NativeRingError> {
        self.inner.need_wakeup()
    }

    /// Reserves an unpublished range of UMEM addresses.
    pub fn reserve(&mut self, len: u32) -> Result<FillReservation<'_, 'memory>, NativeRingError> {
        Ok(FillReservation {
            inner: self.inner.reserve(len)?,
        })
    }
}

/// Unpublished Fill range.
pub struct FillReservation<'ring, 'memory> {
    inner: ProducerReservation<'ring, 'memory, u64>,
}

impl FillReservation<'_, '_> {
    /// Writes the next UMEM address.
    ///
    /// ```compile_fail
    /// use ruster_io_xdp_native::{abi::XdpDescriptor, FillReservation};
    /// fn foreign_role(reservation: &mut FillReservation<'_, '_>, descriptor: XdpDescriptor) {
    ///     reservation.write(descriptor);
    /// }
    /// ```
    pub fn write(&mut self, address: u64) -> Result<(), NativeRingError> {
        self.inner.write(address)
    }

    /// Release-publishes the complete range and then observes need-wakeup.
    pub fn release_submit(self) -> Result<ProducerPublication, NativeRingError> {
        self.inner.release_submit()
    }

    /// Cancels without changing the published producer cursor.
    pub fn release_cancel(self) {
        self.inner.release_cancel();
    }
}

/// Application producer for the packet-descriptor TX ring.
pub struct TxProducer<'memory> {
    inner: ProducerRing<'memory, XdpDescriptor>,
}

impl<'memory> TxProducer<'memory> {
    /// Binds a TX producer to checked caller-owned mapped bytes.
    pub fn new(
        memory: &'memory mut [u8],
        offsets: XdpRingOffset,
        entries: RingEntries,
    ) -> Result<Self, RingMapError> {
        Ok(Self {
            inner: ProducerRing::new(memory, offsets, entries)?,
        })
    }

    /// Returns the checked fixed capacity.
    pub const fn capacity(&self) -> u32 {
        self.inner.capacity()
    }

    /// Reads the kernel-owned need-wakeup flag without issuing a wakeup.
    pub fn need_wakeup(&self) -> Result<NeedWakeup, NativeRingError> {
        self.inner.need_wakeup()
    }

    /// Reserves an unpublished descriptor range.
    pub fn reserve(&mut self, len: u32) -> Result<TxReservation<'_, 'memory>, NativeRingError> {
        Ok(TxReservation {
            inner: self.inner.reserve(len)?,
        })
    }
}

/// Unpublished TX descriptor range.
pub struct TxReservation<'ring, 'memory> {
    inner: ProducerReservation<'ring, 'memory, XdpDescriptor>,
}

impl TxReservation<'_, '_> {
    /// Writes the next packet descriptor.
    pub fn write(&mut self, descriptor: XdpDescriptor) -> Result<(), NativeRingError> {
        self.inner.write(descriptor)
    }

    /// Release-publishes the complete range and then observes need-wakeup.
    pub fn release_submit(self) -> Result<ProducerPublication, NativeRingError> {
        self.inner.release_submit()
    }

    /// Cancels without changing the published producer cursor.
    pub fn release_cancel(self) {
        self.inner.release_cancel();
    }
}

/// Application consumer for the packet-descriptor RX ring.
pub struct RxConsumer<'memory> {
    inner: ConsumerRing<'memory, XdpDescriptor>,
}

impl<'memory> RxConsumer<'memory> {
    /// Binds an RX consumer to checked caller-owned mapped bytes.
    pub fn new(
        memory: &'memory mut [u8],
        offsets: XdpRingOffset,
        entries: RingEntries,
    ) -> Result<Self, RingMapError> {
        Ok(Self {
            inner: ConsumerRing::new(memory, offsets, entries)?,
        })
    }

    /// Returns the checked fixed capacity.
    pub const fn capacity(&self) -> u32 {
        self.inner.capacity()
    }

    /// Acquire-loads the producer cursor and acquires a published range.
    pub fn acquire(&mut self, len: u32) -> Result<RxAcquisition<'_, 'memory>, NativeRingError> {
        Ok(RxAcquisition {
            inner: self.inner.acquire(len)?,
        })
    }
}

/// Acquired RX descriptor range.
pub struct RxAcquisition<'ring, 'memory> {
    inner: ConsumerAcquisition<'ring, 'memory, XdpDescriptor>,
}

impl RxAcquisition<'_, '_> {
    /// Reads the next descriptor after producer Acquire.
    pub fn read(&mut self) -> Result<XdpDescriptor, NativeRingError> {
        self.inner.read()
    }

    /// Release-publishes consumption after every descriptor was read.
    pub fn release_consume(self) -> Result<(), NativeRingError> {
        self.inner.release_consume()
    }

    /// Cancels without changing the published consumer cursor.
    pub fn release_cancel(self) {
        self.inner.release_cancel();
    }
}

/// Application consumer for the UMEM-address Completion ring.
pub struct CompletionConsumer<'memory> {
    inner: ConsumerRing<'memory, u64>,
}

impl<'memory> CompletionConsumer<'memory> {
    /// Binds a Completion consumer to checked caller-owned mapped bytes.
    pub fn new(
        memory: &'memory mut [u8],
        offsets: XdpRingOffset,
        entries: RingEntries,
    ) -> Result<Self, RingMapError> {
        Ok(Self {
            inner: ConsumerRing::new(memory, offsets, entries)?,
        })
    }

    /// Returns the checked fixed capacity.
    pub const fn capacity(&self) -> u32 {
        self.inner.capacity()
    }

    /// Acquire-loads the producer cursor and acquires a published range.
    pub fn acquire(
        &mut self,
        len: u32,
    ) -> Result<CompletionAcquisition<'_, 'memory>, NativeRingError> {
        Ok(CompletionAcquisition {
            inner: self.inner.acquire(len)?,
        })
    }
}

/// Acquired Completion address range.
pub struct CompletionAcquisition<'ring, 'memory> {
    inner: ConsumerAcquisition<'ring, 'memory, u64>,
}

impl CompletionAcquisition<'_, '_> {
    /// Reads the next completed UMEM address.
    pub fn read(&mut self) -> Result<u64, NativeRingError> {
        self.inner.read()
    }

    /// Release-publishes consumption after every address was read.
    pub fn release_consume(self) -> Result<(), NativeRingError> {
        self.inner.release_consume()
    }

    /// Cancels without changing the published consumer cursor.
    pub fn release_cancel(self) {
        self.inner.release_cancel();
    }
}

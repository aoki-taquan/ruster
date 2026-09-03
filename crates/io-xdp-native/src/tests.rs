use std::mem::{align_of, offset_of, size_of};

use crate::{
    abi::{
        RingElement, RingMmapLayout, SockAddrXdp, XdpDescriptor, XdpMmapOffsets, XdpOptions,
        XdpRingOffset, XdpStatistics, XdpUmemReg, ABI_HEADER_PROFILE, AF_XDP, SOL_XDP, XDP_COPY,
        XDP_MMAP_OFFSETS, XDP_OPTIONS, XDP_OPTIONS_ZEROCOPY, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING,
        XDP_PKT_CONTD, XDP_RING_NEED_WAKEUP, XDP_RX_RING, XDP_SHARED_UMEM, XDP_STATISTICS,
        XDP_TX_METADATA, XDP_TX_RING, XDP_UMEM_COMPLETION_RING, XDP_UMEM_FILL_RING,
        XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_PGOFF_FILL_RING, XDP_UMEM_REG,
        XDP_UMEM_TX_SW_CSUM, XDP_UMEM_UNALIGNED_CHUNK_FLAG, XDP_USE_NEED_WAKEUP, XDP_USE_SG,
        XDP_ZEROCOPY,
    },
    ensure_supported, validate_descriptor_options, AbiLayoutError, BindMode, CompletionConsumer,
    ConfigError, FillProducer, NativeRingError, NeedWakeup, RingConfig, RingEntries, RingField,
    RingMapError, RingName, RxConsumer, TxProducer, UmemConfig, ValidatedBindFlags, MAX_UMEM_BYTES,
    MAX_UMEM_FRAME_COUNT, MIN_VISIBLE_FRAME_CAPACITY, SUPPORTED_ALIGNED_CHUNK_SIZES,
    XDP_PACKET_HEADROOM,
};

const TEST_RING_OFFSETS: XdpRingOffset = XdpRingOffset {
    producer: 0,
    consumer: 64,
    flags: 128,
    descriptors: 192,
};

#[repr(align(64))]
struct AlignedRingMemory([u8; 256]);

impl AlignedRingMemory {
    const fn zeroed() -> Self {
        Self([0; 256])
    }
}

fn write_u32(memory: &mut [u8], offset: usize, value: u32) {
    memory[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_ne_bytes());
}

fn read_u32(memory: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        memory[offset..offset + size_of::<u32>()]
            .try_into()
            .expect("four bytes"),
    )
}

#[test]
fn native_abi_matches_linux_v6_8_uapi_layout() {
    assert_eq!(ABI_HEADER_PROFILE, "Linux v6.8 include/uapi/linux/if_xdp.h");
    assert_eq!((AF_XDP, SOL_XDP), (44, 283));
    assert_eq!(
        (
            XDP_SHARED_UMEM,
            XDP_COPY,
            XDP_ZEROCOPY,
            XDP_USE_NEED_WAKEUP,
            XDP_USE_SG,
        ),
        (1, 2, 4, 8, 16)
    );
    assert_eq!((XDP_UMEM_UNALIGNED_CHUNK_FLAG, XDP_UMEM_TX_SW_CSUM), (1, 2));
    assert_eq!(XDP_RING_NEED_WAKEUP, 1);
    assert_eq!(
        (
            XDP_MMAP_OFFSETS,
            XDP_RX_RING,
            XDP_TX_RING,
            XDP_UMEM_REG,
            XDP_UMEM_FILL_RING,
            XDP_UMEM_COMPLETION_RING,
            XDP_STATISTICS,
            XDP_OPTIONS,
        ),
        (1, 2, 3, 4, 5, 6, 7, 8)
    );
    assert_eq!(
        (
            XDP_PGOFF_RX_RING,
            XDP_PGOFF_TX_RING,
            XDP_UMEM_PGOFF_FILL_RING,
            XDP_UMEM_PGOFF_COMPLETION_RING,
        ),
        (0, 0x8000_0000, 0x1_0000_0000, 0x1_8000_0000)
    );
    assert_eq!(XDP_OPTIONS_ZEROCOPY, 1);
    assert_eq!((XDP_PKT_CONTD, XDP_TX_METADATA), (1, 2));

    assert_eq!(
        (size_of::<SockAddrXdp>(), align_of::<SockAddrXdp>()),
        (16, 4)
    );
    assert_eq!(offset_of!(SockAddrXdp, family), 0);
    assert_eq!(offset_of!(SockAddrXdp, flags), 2);
    assert_eq!(offset_of!(SockAddrXdp, ifindex), 4);
    assert_eq!(offset_of!(SockAddrXdp, queue_id), 8);
    assert_eq!(offset_of!(SockAddrXdp, shared_umem_fd), 12);

    assert_eq!(
        (size_of::<XdpRingOffset>(), align_of::<XdpRingOffset>()),
        (32, 8)
    );
    assert_eq!(offset_of!(XdpRingOffset, producer), 0);
    assert_eq!(offset_of!(XdpRingOffset, consumer), 8);
    assert_eq!(offset_of!(XdpRingOffset, descriptors), 16);
    assert_eq!(offset_of!(XdpRingOffset, flags), 24);
    assert_eq!(
        (size_of::<XdpMmapOffsets>(), align_of::<XdpMmapOffsets>()),
        (128, 8)
    );
    assert_eq!(offset_of!(XdpMmapOffsets, rx), 0);
    assert_eq!(offset_of!(XdpMmapOffsets, tx), 32);
    assert_eq!(offset_of!(XdpMmapOffsets, fill), 64);
    assert_eq!(offset_of!(XdpMmapOffsets, completion), 96);

    assert_eq!((size_of::<XdpUmemReg>(), align_of::<XdpUmemReg>()), (32, 8));
    assert_eq!(offset_of!(XdpUmemReg, address), 0);
    assert_eq!(offset_of!(XdpUmemReg, len), 8);
    assert_eq!(offset_of!(XdpUmemReg, chunk_size), 16);
    assert_eq!(offset_of!(XdpUmemReg, headroom), 20);
    assert_eq!(offset_of!(XdpUmemReg, flags), 24);
    assert_eq!(offset_of!(XdpUmemReg, tx_metadata_len), 28);

    assert_eq!(
        (size_of::<XdpStatistics>(), align_of::<XdpStatistics>()),
        (48, 8)
    );
    assert_eq!((size_of::<XdpOptions>(), align_of::<XdpOptions>()), (4, 4));
    assert_eq!(
        (size_of::<XdpDescriptor>(), align_of::<XdpDescriptor>()),
        (16, 8)
    );
    assert_eq!(offset_of!(XdpDescriptor, address), 0);
    assert_eq!(offset_of!(XdpDescriptor, len), 8);
    assert_eq!(offset_of!(XdpDescriptor, options), 12);
}

#[test]
fn native_ring_offsets_validate_bounds_alignment_and_overflow() {
    let entries = RingEntries::new(RingName::Rx, 64).expect("valid capacity");
    let raw = XdpRingOffset {
        producer: 0,
        consumer: 64,
        flags: 128,
        descriptors: 192,
    };
    let layout =
        RingMmapLayout::new(raw, entries, RingElement::PacketDescriptor).expect("valid layout");
    assert_eq!(
        (
            layout.producer(),
            layout.consumer(),
            layout.flags(),
            layout.descriptors(),
            layout.byte_len(),
        ),
        (0, 64, 128, 192, 1_216)
    );

    assert_eq!(
        RingMmapLayout::new(
            XdpRingOffset { producer: 2, ..raw },
            entries,
            RingElement::PacketDescriptor,
        ),
        Err(AbiLayoutError::MisalignedOffset {
            field: RingField::Producer,
            offset: 2,
            alignment: 4,
        })
    );
    assert_eq!(
        RingMmapLayout::new(
            XdpRingOffset { consumer: 0, ..raw },
            entries,
            RingElement::PacketDescriptor,
        ),
        Err(AbiLayoutError::OverlappingFields {
            first: RingField::Producer,
            second: RingField::Consumer,
        })
    );
    assert_eq!(
        RingMmapLayout::new(
            XdpRingOffset {
                descriptors: u64::MAX - 7,
                ..raw
            },
            entries,
            RingElement::UmemAddress,
        ),
        Err(AbiLayoutError::ExtentOverflow {
            field: RingField::Descriptors,
        })
    );
}

#[test]
fn native_config_rejects_invalid_geometry_and_flags() {
    let umem = UmemConfig::new(4_096, 2_048, 256, 3_584, 512, 0).expect("valid UMEM");
    assert_eq!(
        (
            umem.frame_count(),
            umem.frame_size(),
            umem.headroom(),
            umem.visible_capacity(),
            umem.rx_frames(),
            umem.generated_frames(),
            umem.byte_len(),
        ),
        (4_096, 2_048, 256, 1_536, 3_584, 512, 8_388_608)
    );
    assert_eq!(
        UmemConfig::new(0, 2_048, 256, 1, 1, 0),
        Err(ConfigError::ZeroFrameCount)
    );
    assert_eq!(
        UmemConfig::new(2, 1, 0, 1, 1, 0),
        Err(ConfigError::InvalidFrameSize(1))
    );
    assert_eq!(
        UmemConfig::new(2, 1_024, 0, 1, 1, 0),
        Err(ConfigError::InvalidFrameSize(1_024))
    );
    assert_eq!(
        UmemConfig::new(2, 1_500, 0, 1, 1, 0),
        Err(ConfigError::InvalidFrameSize(1_500))
    );
    assert_eq!(
        UmemConfig::new(2, 8_192, 0, 1, 1, 0),
        Err(ConfigError::InvalidFrameSize(8_192))
    );
    assert_eq!(
        UmemConfig::new(2, 2_048, 0, 1, 1, 1),
        Err(ConfigError::UnsupportedUmemFlags(1))
    );
    assert_eq!(
        UmemConfig::new(4, 2_048, 0, u32::MAX, 1, 0),
        Err(ConfigError::FramePartitionOverflow)
    );
    assert_eq!(
        UmemConfig::new(2, 2_048, 0, 0, 2, 0),
        Err(ConfigError::ZeroRxFrames)
    );
    assert_eq!(
        UmemConfig::new(2, 2_048, 0, 2, 0, 0),
        Err(ConfigError::ZeroGeneratedFrames)
    );
    assert_eq!(
        UmemConfig::new(4, 2_048, 0, 2, 1, 0),
        Err(ConfigError::FramePartitionMismatch {
            frame_count: 4,
            rx_frames: 2,
            generated_frames: 1,
        })
    );

    let rings = RingConfig::new(2_048, 2_048, 1_024, 1_024).expect("valid rings");
    assert_eq!((rings.fill().get(), rings.rx().get()), (2_048, 2_048));
    assert_eq!((rings.tx().get(), rings.completion().get()), (1_024, 1_024));
    assert_eq!(
        RingConfig::new(3, 2, 2, 2),
        Err(ConfigError::InvalidRingEntries {
            ring: RingName::Fill,
            entries: 3,
        })
    );

    let automatic =
        ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP).expect("automatic need-wakeup profile");
    assert_eq!(automatic.mode(), BindMode::Automatic);
    assert_eq!(automatic.raw(), XDP_USE_NEED_WAKEUP);
    assert!(!automatic.shared_umem());
    let shared_copy = ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | XDP_SHARED_UMEM | XDP_COPY)
        .expect("shared copy profile");
    assert_eq!(shared_copy.mode(), BindMode::CopyRequired);
    assert!(shared_copy.shared_umem());
    assert_eq!(
        ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | XDP_COPY | XDP_ZEROCOPY),
        Err(ConfigError::ConflictingBindModes)
    );
    assert_eq!(
        ValidatedBindFlags::new(XDP_USE_SG | XDP_USE_NEED_WAKEUP),
        Err(ConfigError::UnsupportedBindFlags(XDP_USE_SG))
    );
    assert_eq!(
        ValidatedBindFlags::new(0),
        Err(ConfigError::NeedWakeupRequired)
    );
    assert_eq!(
        validate_descriptor_options(XDP_TX_METADATA),
        Err(ConfigError::UnsupportedDescriptorOptions(XDP_TX_METADATA))
    );
}

#[test]
fn native_umem_capacity_accounts_fixed_kernel_headroom() {
    assert_eq!(XDP_PACKET_HEADROOM, 256);
    assert_eq!(MIN_VISIBLE_FRAME_CAPACITY, 1);
    assert_eq!(SUPPORTED_ALIGNED_CHUNK_SIZES, [2_048, 4_096]);

    let smallest_2k =
        UmemConfig::new(2, 2_048, 1_791, 1, 1, 0).expect("one visible byte in 2K chunk");
    assert_eq!(smallest_2k.visible_capacity(), 1);
    assert_eq!(
        UmemConfig::new(2, 2_048, 1_792, 1, 1, 0),
        Err(ConfigError::InsufficientVisibleCapacity {
            headroom: 1_792,
            frame_size: 2_048,
            kernel_headroom: 256,
            minimum_visible: 1,
        })
    );

    let smallest_4k =
        UmemConfig::new(2, 4_096, 3_839, 1, 1, 0).expect("one visible byte in 4K chunk");
    assert_eq!(smallest_4k.visible_capacity(), 1);
    assert_eq!(
        UmemConfig::new(2, 4_096, 3_840, 1, 1, 0),
        Err(ConfigError::InsufficientVisibleCapacity {
            headroom: 3_840,
            frame_size: 4_096,
            kernel_headroom: 256,
            minimum_visible: 1,
        })
    );

    assert_eq!(
        UmemConfig::new(2, 2_048, u32::MAX, 1, 1, 0),
        Err(ConfigError::HeadroomCapacityOverflow { headroom: u32::MAX })
    );
    assert_eq!(
        UmemConfig::new(2, 2_048, u32::MAX - 256, 1, 1, 0),
        Err(ConfigError::HeadroomCapacityOverflow {
            headroom: u32::MAX - 256,
        })
    );
}

#[test]
fn native_umem_capacity_bounds_mapping_and_ledger_before_allocation() {
    assert_eq!(MAX_UMEM_BYTES, 1 << 30);
    assert_eq!(MAX_UMEM_FRAME_COUNT, 1 << 20);

    let exact_byte_frame_count =
        u32::try_from(MAX_UMEM_BYTES / 2_048).expect("exact byte-bound frame count fits u32");
    let exact = UmemConfig::new(
        exact_byte_frame_count,
        2_048,
        0,
        1,
        exact_byte_frame_count - 1,
        0,
    )
    .expect("the exact byte bound remains valid");
    assert_eq!(exact.byte_len(), MAX_UMEM_BYTES);

    let over_bytes = exact_byte_frame_count + 1;
    assert_eq!(
        UmemConfig::new(over_bytes, 2_048, 0, 1, over_bytes - 1, 0),
        Err(ConfigError::UmemByteLengthExceedsLimit {
            byte_len: MAX_UMEM_BYTES + 2_048,
            limit: MAX_UMEM_BYTES,
        })
    );

    let over_frames = MAX_UMEM_FRAME_COUNT + 1;
    assert_eq!(
        UmemConfig::new(over_frames, 2_048, 0, 1, over_frames - 1, 0),
        Err(ConfigError::UmemFrameCountExceedsLimit {
            frame_count: over_frames,
            limit: MAX_UMEM_FRAME_COUNT,
        })
    );
}

#[test]
fn native_platform_support_is_typed() {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    assert_eq!(ensure_supported(), Ok(()));

    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        ensure_supported(),
        Err(crate::PlatformError::UnsupportedOperatingSystem)
    );

    #[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
    assert_eq!(
        ensure_supported(),
        Err(crate::PlatformError::UnsupportedPointerWidth)
    );
}

#[test]
fn native_ring_mapping_rejects_invalid_borrowed_memory() {
    let entries = RingEntries::new(RingName::Fill, 4).expect("capacity");
    let mut short = AlignedRingMemory::zeroed();
    assert!(matches!(
        FillProducer::new(&mut short.0[..223], TEST_RING_OFFSETS, entries),
        Err(RingMapError::MappingTooShort {
            required: 224,
            actual: 223,
        })
    ));

    let mut shifted = AlignedRingMemory::zeroed();
    assert!(matches!(
        FillProducer::new(&mut shifted.0[1..], TEST_RING_OFFSETS, entries),
        Err(RingMapError::MisalignedFieldAddress {
            field: RingField::Producer,
            alignment: 4,
            ..
        })
    ));

    let mut corrupt = AlignedRingMemory::zeroed();
    assert_eq!(
        FillProducer::new(
            &mut corrupt.0,
            XdpRingOffset {
                consumer: 0,
                ..TEST_RING_OFFSETS
            },
            entries,
        )
        .err(),
        Some(RingMapError::Layout(AbiLayoutError::OverlappingFields {
            first: RingField::Producer,
            second: RingField::Consumer,
        }))
    );
    assert_eq!(
        FillProducer::new(
            &mut corrupt.0,
            XdpRingOffset {
                producer: 2,
                ..TEST_RING_OFFSETS
            },
            entries,
        )
        .err(),
        Some(RingMapError::Layout(AbiLayoutError::MisalignedOffset {
            field: RingField::Producer,
            offset: 2,
            alignment: 4,
        }))
    );

    let descriptors_past_mapping = XdpRingOffset {
        descriptors: 248,
        ..TEST_RING_OFFSETS
    };
    assert_eq!(
        FillProducer::new(&mut corrupt.0, descriptors_past_mapping, entries).err(),
        Some(RingMapError::MappingTooShort {
            required: 280,
            actual: 256,
        })
    );
}

#[test]
fn native_u64_roles_wrap_and_enforce_full_empty() {
    let entries = RingEntries::new(RingName::Fill, 4).expect("capacity");
    let mut memory = AlignedRingMemory::zeroed();
    write_u32(&mut memory.0, 0, u32::MAX - 1);
    write_u32(&mut memory.0, 64, u32::MAX - 1);
    write_u32(&mut memory.0, 128, XDP_RING_NEED_WAKEUP);

    {
        let mut fill =
            FillProducer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("Fill view");
        assert_eq!(fill.capacity(), 4);
        let mut reservation = fill.reserve(4).expect("whole ring");
        for address in [10, 11, 12, 13] {
            reservation.write(address).expect("sequential address");
        }
        let publication = reservation.release_submit().expect("complete publish");
        assert_eq!(publication.need_wakeup(), Ok(NeedWakeup::Required));
    }
    assert_eq!(read_u32(&memory.0, 0), 2);

    {
        let mut fill =
            FillProducer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("Fill view");
        assert_eq!(fill.reserve(1).err(), Some(NativeRingError::RingFull));
    }
    {
        let mut completion =
            CompletionConsumer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("CQ view");
        assert_eq!(completion.capacity(), 4);
        let mut acquisition = completion.acquire(4).expect("wrapped entries");
        assert_eq!(acquisition.read(), Ok(10));
        assert_eq!(acquisition.read(), Ok(11));
        assert_eq!(acquisition.read(), Ok(12));
        assert_eq!(acquisition.read(), Ok(13));
        assert_eq!(acquisition.read(), Err(NativeRingError::RangeExhausted));
        acquisition.release_consume().expect("complete consume");
    }
    assert_eq!(read_u32(&memory.0, 64), 2);
    let mut completion =
        CompletionConsumer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("CQ view");
    assert_eq!(
        completion.acquire(1).err(),
        Some(NativeRingError::RingEmpty)
    );
}

#[test]
fn native_reservation_cancel_and_incomplete_submit_are_invisible() {
    let entries = RingEntries::new(RingName::Fill, 4).expect("capacity");
    let mut memory = AlignedRingMemory::zeroed();
    {
        let mut fill =
            FillProducer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("Fill view");
        let mut incomplete = fill.reserve(2).expect("reserve two");
        incomplete.write(41).expect("first only");
        assert_eq!(
            incomplete.release_submit(),
            Err(NativeRingError::IncompleteReservation {
                reserved: 2,
                written: 1,
            })
        );

        let mut cancelled = fill.reserve(2).expect("same unpublished range");
        cancelled.write(42).expect("first");
        cancelled.write(43).expect("second");
        cancelled.release_cancel();
    }
    assert_eq!(read_u32(&memory.0, 0), 0);

    let mut completion =
        CompletionConsumer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("CQ view");
    assert_eq!(
        completion.acquire(1).err(),
        Some(NativeRingError::RingEmpty)
    );
}

#[test]
fn native_descriptor_memory_order_visibility_is_exact() {
    let entries = RingEntries::new(RingName::Tx, 4).expect("capacity");
    let first = XdpDescriptor {
        address: 2_304,
        len: 64,
        options: 0,
    };
    let second = XdpDescriptor {
        address: 4_352,
        len: 128,
        options: 0,
    };
    let mut memory = AlignedRingMemory::zeroed();

    {
        let mut tx = TxProducer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("TX view");
        let mut reservation = tx.reserve(2).expect("reserve");
        reservation.write(first).expect("first");
        reservation.write(second).expect("second");
        let publication = reservation.release_submit().expect("Release producer");
        assert_eq!(publication.need_wakeup(), Ok(NeedWakeup::NotRequired));
    }
    assert_eq!(read_u32(&memory.0, 0), 2);

    {
        let mut rx = RxConsumer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("RX view");
        let mut incomplete = rx.acquire(2).expect("Acquire producer");
        assert_eq!(incomplete.read(), Ok(first));
        assert_eq!(
            incomplete.release_consume(),
            Err(NativeRingError::IncompleteAcquisition {
                acquired: 2,
                read: 1,
            })
        );
    }
    assert_eq!(read_u32(&memory.0, 64), 0);

    {
        let mut rx = RxConsumer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("RX view");
        assert_eq!(rx.capacity(), 4);
        let mut acquisition = rx.acquire(2).expect("reacquire");
        assert_eq!(acquisition.read(), Ok(first));
        assert_eq!(acquisition.read(), Ok(second));
        acquisition.release_consume().expect("Release consumer");
    }
    assert_eq!(read_u32(&memory.0, 64), 2);
}

#[test]
fn native_need_wakeup_is_checked_after_release_publication() {
    let entries = RingEntries::new(RingName::Fill, 4).expect("capacity");
    let mut memory = AlignedRingMemory::zeroed();
    write_u32(&mut memory.0, 128, XDP_RING_NEED_WAKEUP | 2);

    let observation = {
        let mut fill =
            FillProducer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("Fill view");
        let mut reservation = fill.reserve(1).expect("reserve");
        reservation.write(99).expect("descriptor first");
        reservation.release_submit().expect("producer publication")
    };
    assert_eq!(read_u32(&memory.0, 0), 1);
    assert_eq!(
        observation.need_wakeup(),
        Err(NativeRingError::UnsupportedRingFlags(2))
    );
}

#[test]
fn native_corrupt_cursor_is_typed_and_atomic() {
    let entries = RingEntries::new(RingName::Fill, 4).expect("capacity");
    let mut memory = AlignedRingMemory::zeroed();
    write_u32(&mut memory.0, 0, 5);
    {
        let mut fill =
            FillProducer::new(&mut memory.0, TEST_RING_OFFSETS, entries).expect("Fill view");
        assert_eq!(
            fill.reserve(1).err(),
            Some(NativeRingError::CorruptCursor {
                producer: 5,
                consumer: 0,
                capacity: 4,
            })
        );
    }
    assert_eq!(read_u32(&memory.0, 0), 5);
    assert_eq!(read_u32(&memory.0, 64), 0);
}

#[test]
fn xdp_run_e2e_disables_veth_tx_checksum_offload() {
    // Generic XDP executes before the skb transmit checksum helper can make a
    // TCP checksum field wire-valid.  Keep the TCP fixture at the same
    // byte-level contract as a physical wire or a real NIC RX path.  Linux
    // v6.8's bpf/test_xdp_features.sh applies this exact setting to both
    // ends of its veth/XDP test.
    let script = include_str!("../../../scripts/run-netns-xdp-run-e2e.sh");
    for command in [
        "ip netns exec \"$sender_ns\" ethtool -K \"$sender_if\" tx-checksumming off",
        "ip netns exec \"$daemon_ns\" ethtool -K \"$lan_if\" tx-checksumming off",
        "ip netns exec \"$daemon_ns\" ethtool -K \"$wan_if\" tx-checksumming off",
        "ip netns exec \"$receiver_ns\" ethtool -K \"$receiver_if\" tx-checksumming off",
    ] {
        assert!(
            script.contains(command),
            "AF_XDP daemon E2E must disable veth TX checksum offload: {command}"
        );
    }
}

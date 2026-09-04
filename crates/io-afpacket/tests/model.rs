use ruster_core::IfId;
use ruster_io_afpacket::{
    validate_v3_block_chain, AfPacketPlatform, BackendStat, BackendStats, BlockDescriptor,
    ConfigError, GeometryError, OwnershipError, PacketDescriptor, PlatformError, PortConfig,
    RingGeometry, RingKind, RxBlockModel, RxOwnership, SyscallStage, TxFrameModel, TxOwnership,
    ValidatedConfig,
};

fn geometry() -> RingGeometry {
    RingGeometry {
        block_size: 4_096,
        block_count: 2,
        frame_size: 2_048,
        frame_count: 4,
        retire_timeout_ms: 10,
        private_size: 16,
        feature_flags: 1,
    }
}

fn port(interface: u16, if_index: u32) -> PortConfig {
    let mut tx = geometry();
    tx.retire_timeout_ms = 0;
    tx.private_size = 0;
    tx.feature_flags = 0;
    PortConfig {
        interface: IfId(interface),
        if_index,
        rx: geometry(),
        tx,
    }
}

#[test]
fn af_packet_v3_ring_model_validates_geometry_and_ownership() {
    let ports = [port(7, 3), port(u16::MAX, 4)];
    let config =
        ValidatedConfig::new(&ports, 4_096, 1_514).expect("valid TPACKET_V3 configuration");
    assert_eq!(config.ports().len(), 2);
    assert_eq!(config.port(IfId(7)).expect("mapped port").if_index(), 3);
    assert_eq!(
        config
            .port(IfId(u16::MAX))
            .expect("full IfId range")
            .if_index(),
        4
    );
    assert!(config.port(IfId(8)).is_none());
    let first = config.ports()[0];
    assert_eq!(first.rx().map_len(), 8_192);
    assert_eq!(first.rx().block_plus_private(), 64);
    assert_eq!(first.tx_map_offset(), 8_192);
    assert_eq!(first.combined_map_len(), 16_384);
    assert_eq!(first.rx().block_range(1), Ok(4_096..8_192));

    let block = BlockDescriptor {
        version: 2,
        offset_to_private: 48,
        block_len: 4_096,
        packet_count: 2,
        first_packet_offset: 64,
    };
    block.validate(first.rx()).expect("bounded block");
    let first_descriptor = PacketDescriptor {
        packet_offset: 64,
        next_offset: 1_568,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 1_472,
        wire_len: 1_500,
        is_last: false,
    };
    let packet = first_descriptor.validate(4_096).expect("bounded packet");
    assert_eq!(packet.header(), 64..112);
    assert_eq!(packet.data(), 146..1_618);
    assert_eq!(packet.next_packet_offset(), Some(1_632));
    assert!(packet.is_truncated());
    let terminal = PacketDescriptor {
        packet_offset: 1_632,
        next_offset: 0,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 60,
        wire_len: 60,
        is_last: true,
    };
    validate_v3_block_chain(block, &[first_descriptor, terminal], first.rx())
        .expect("complete terminal chain");

    let mut rx = RxBlockModel::new();
    rx.acquire(2).expect("kernel transfers block");
    rx.complete_packet().expect("first packet terminal");
    assert_eq!(
        rx.release(),
        Err(OwnershipError::RxPacketsOutstanding { remaining: 1 })
    );
    rx.complete_packet().expect("second packet terminal");
    rx.release().expect("whole block returns to kernel");
    assert_eq!(rx.owner(), RxOwnership::Kernel);

    let mut tx = TxFrameModel::new();
    tx.prepare().expect("userspace reserves");
    tx.publish().expect("userspace publishes");
    tx.kernel_accept().expect("kernel consumes");
    tx.kernel_complete().expect("kernel releases");
    assert_eq!(tx.owner(), TxOwnership::Available);
}

#[test]
fn geometry_descriptor_and_status_fail_closed_on_checked_boundaries() {
    assert_eq!(
        geometry().validate_rx(4_096, 0),
        Err(GeometryError::ZeroMaxFrameLength)
    );
    let compact_tx = RingGeometry {
        block_size: 4_096,
        block_count: 1,
        frame_size: 256,
        frame_count: 16,
        retire_timeout_ms: 0,
        private_size: 0,
        feature_flags: 0,
    };
    assert!(compact_tx.validate_tx(4_096, 190).is_ok());
    assert_eq!(
        compact_tx.validate_rx(4_096, 190),
        Err(GeometryError::FrameTooSmall {
            frame_size: 256,
            minimum: 272,
        })
    );
    let mut invalid = geometry();
    invalid.block_size = 4_095;
    assert_eq!(
        invalid.validate_rx(4_096, 1_514),
        Err(GeometryError::BlockSizeNotPageAligned {
            block_size: 4_095,
            page_size: 4_096,
        })
    );
    invalid = geometry();
    invalid.frame_count = 3;
    assert_eq!(
        invalid.validate_rx(4_096, 1_514),
        Err(GeometryError::FrameCountMismatch {
            configured: 3,
            expected: 4,
        })
    );
    invalid = geometry();
    invalid.block_size = i32::MAX as u32 + 1;
    assert_eq!(
        invalid.validate_rx(4_096, 1_514),
        Err(GeometryError::BlockSizeExceedsKernelLimit {
            block_size: i32::MAX as u32 + 1,
        })
    );
    invalid = geometry();
    invalid.feature_flags = 2;
    assert_eq!(
        invalid.validate_rx(4_096, 1_514),
        Err(GeometryError::UnknownFeatureFlags { feature_flags: 2 })
    );
    invalid = geometry();
    invalid.private_size = 4_048;
    assert_eq!(
        invalid.validate_rx(4_096, 1_514),
        Err(GeometryError::RxBlockBelowKernelMinimum {
            block_plus_private: 4_096,
            header_len: 68,
            block_size: 4_096,
        })
    );
    invalid = geometry();
    invalid.private_size = 2_496;
    assert_eq!(
        invalid.validate_rx(4_096, 1_514),
        Err(GeometryError::RxBlockWouldTruncateMaxFrame {
            block_plus_private: 2_544,
            mac_offset: 82,
            max_frame_len: 1_514,
            block_size: 4_096,
        })
    );
    let layout = geometry().validate_rx(4_096, 1_514).expect("layout");
    assert_eq!(
        BlockDescriptor {
            version: 1,
            offset_to_private: 48,
            block_len: 4_096,
            packet_count: 1,
            first_packet_offset: 64,
        }
        .validate(layout),
        Err(GeometryError::UnsupportedBlockVersion { version: 1 })
    );
    assert_eq!(
        BlockDescriptor {
            version: 2,
            offset_to_private: 64,
            block_len: 4_096,
            packet_count: 1,
            first_packet_offset: 80,
        }
        .validate(layout),
        Err(GeometryError::PrivateOffsetInvalid { offset: 64 })
    );
    assert_eq!(
        BlockDescriptor {
            version: 2,
            offset_to_private: 48,
            block_len: 4_096,
            packet_count: 1,
            first_packet_offset: 80,
        }
        .validate(layout),
        Err(GeometryError::FirstPacketOffsetMismatch {
            configured: 80,
            expected: 64,
        })
    );
    let mut eight_aligned_private = geometry();
    eight_aligned_private.private_size = 17;
    let eight_aligned_layout = eight_aligned_private
        .validate_rx(4_096, 1_514)
        .expect("private size is rounded up to eight bytes");
    assert_eq!(eight_aligned_layout.block_plus_private(), 72);
    BlockDescriptor {
        version: 2,
        offset_to_private: 48,
        block_len: 4_096,
        packet_count: 1,
        first_packet_offset: 72,
    }
    .validate(eight_aligned_layout)
    .expect("kernel first-packet offset may be eight-byte aligned");
    PacketDescriptor {
        packet_offset: 72,
        next_offset: 0,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 60,
        wire_len: 60,
        is_last: true,
    }
    .validate(4_096)
    .expect("V3 packet descriptors use the kernel's eight-byte alignment");
    assert_eq!(
        geometry()
            .validate_rx(4_096, 1_514)
            .expect("layout")
            .block_range(2),
        Err(GeometryError::BlockIndexOutOfRange { block_index: 2 })
    );
    assert_eq!(
        BlockDescriptor {
            version: 2,
            offset_to_private: 48,
            block_len: 128,
            packet_count: 2,
            first_packet_offset: 64,
        }
        .validate(geometry().validate_rx(4_096, 1_514).expect("layout")),
        Err(GeometryError::PacketCountExceedsBlock {
            packet_count: 2,
            maximum: 1,
        })
    );

    let crossing = PacketDescriptor {
        packet_offset: 48,
        next_offset: 64,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 60,
        wire_len: 60,
        is_last: false,
    };
    assert_eq!(
        crossing.validate(4_096),
        Err(GeometryError::PacketCrossesNextOffset)
    );
    let overflow = PacketDescriptor {
        packet_offset: usize::MAX - 15,
        next_offset: 0,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 60,
        wire_len: 60,
        is_last: true,
    };
    assert_eq!(
        overflow.validate(4_096),
        Err(GeometryError::ArithmeticOverflow)
    );
    assert_eq!(RxOwnership::from_status(0), Ok(RxOwnership::Kernel));
    assert_eq!(RxOwnership::from_status(1 | 4), Ok(RxOwnership::User));
    assert_eq!(
        RxOwnership::from_status(4),
        Err(GeometryError::InvalidRxStatus { status: 4 })
    );
    assert_eq!(
        TxOwnership::from_status(3),
        Err(GeometryError::InvalidTxStatus { status: 3 })
    );
}

#[test]
fn config_rejects_ambiguous_interface_mappings() {
    assert_eq!(
        ValidatedConfig::new(&[], 4_096, 1_514),
        Err(ConfigError::NoPorts)
    );
    assert_eq!(
        ValidatedConfig::new(&[port(1, 3), port(1, 4)], 4_096, 1_514),
        Err(ConfigError::DuplicateInterface { interface: IfId(1) })
    );
    assert_eq!(
        ValidatedConfig::new(&[port(1, 3), port(2, 3)], 4_096, 1_514),
        Err(ConfigError::DuplicateIfIndex { if_index: 3 })
    );
    assert_eq!(
        ValidatedConfig::new(&[port(1, 0)], 4_096, 1_514),
        Err(ConfigError::ZeroIfIndex { interface: IfId(1) })
    );
    assert_eq!(
        ValidatedConfig::new(&[port(1, u32::MAX)], 4_096, 1_514),
        Err(ConfigError::IfIndexOutOfRange {
            interface: IfId(1),
            if_index: u32::MAX,
        })
    );

    let mut bad_rx = port(1, 3);
    bad_rx.rx.frame_size = 64;
    assert!(matches!(
        ValidatedConfig::new(&[bad_rx], 4_096, 1_514),
        Err(ConfigError::Ring {
            interface: IfId(1),
            kind: RingKind::Rx,
            source: GeometryError::FrameTooSmall { .. },
        })
    ));

    let mut bad_tx = port(1, 3);
    bad_tx.tx.feature_flags = 1;
    assert_eq!(
        ValidatedConfig::new(&[bad_tx], 4_096, 1_514),
        Err(ConfigError::Ring {
            interface: IfId(1),
            kind: RingKind::Tx,
            source: GeometryError::FeatureFlagsUnsupportedForTx { feature_flags: 1 },
        })
    );
    let mut bad_tx = port(1, 3);
    bad_tx.tx.retire_timeout_ms = 1;
    assert_eq!(
        ValidatedConfig::new(&[bad_tx], 4_096, 1_514),
        Err(ConfigError::Ring {
            interface: IfId(1),
            kind: RingKind::Tx,
            source: GeometryError::RetireTimeoutUnsupportedForTx {
                retire_timeout_ms: 1,
            },
        })
    );
    let mut bad_tx = port(1, 3);
    bad_tx.tx.private_size = 16;
    assert_eq!(
        ValidatedConfig::new(&[bad_tx], 4_096, 1_514),
        Err(ConfigError::Ring {
            interface: IfId(1),
            kind: RingKind::Tx,
            source: GeometryError::PrivateAreaUnsupportedForTx { private_size: 16 },
        })
    );

    #[cfg(target_pointer_width = "64")]
    {
        let huge = RingGeometry {
            block_size: 2_147_479_552,
            block_count: u32::MAX,
            frame_size: 2_147_479_552,
            frame_count: u32::MAX,
            retire_timeout_ms: 0,
            private_size: 0,
            feature_flags: 0,
        };
        assert_eq!(
            ValidatedConfig::new(
                &[PortConfig {
                    interface: IfId(9),
                    if_index: 9,
                    rx: huge,
                    tx: huge,
                }],
                4_096,
                1_514,
            ),
            Err(ConfigError::CombinedMapExceedsAddressSpace {
                interface: IfId(9),
                map_len: 18_446_708_885_042_503_680,
            })
        );
    }
}

#[test]
fn ownership_model_rejects_early_reclaim_and_invalid_transitions() {
    let mut rx = RxBlockModel::new();
    assert_eq!(rx.release(), Err(OwnershipError::RxReleaseWhileKernelOwned));
    assert_eq!(rx.acquire(0), Err(OwnershipError::RxPacketCountZero));
    rx.acquire(1).expect("acquire once");
    assert_eq!(
        rx.acquire(1),
        Err(OwnershipError::RxAcquireWhileOwned {
            owner: RxOwnership::User
        })
    );

    let mut tx = TxFrameModel::new();
    assert!(matches!(
        tx.publish(),
        Err(OwnershipError::TxInvalidTransition {
            from: TxOwnership::Available,
            ..
        })
    ));
    tx.prepare().expect("prepare");
    tx.publish().expect("publish");
    tx.reclaim_unconsumed().expect("EAGAIN suffix reclaim");
    assert_eq!(tx.owner(), TxOwnership::Available);

    tx.prepare().expect("prepare again");
    tx.publish().expect("publish again");
    tx.kernel_reject_format().expect("kernel format rejection");
    assert_eq!(tx.owner(), TxOwnership::WrongFormat);
    tx.recycle_wrong_format().expect("poisoned slot recycle");
    assert_eq!(tx.owner(), TxOwnership::Available);
}

#[test]
fn stats_are_fixed_saturating_counters_and_platform_is_explicit() {
    let mut stats = BackendStats::new();
    stats.record(BackendStat::GeometryRejected);
    stats.record(BackendStat::DescriptorRejected);
    stats.record(BackendStat::StatusRejected);
    stats.record(BackendStat::OwnershipRejected);
    stats.record(BackendStat::SyscallError);
    stats.record(BackendStat::MmapError);
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.geometry_rejected, 1);
    assert_eq!(snapshot.descriptor_rejected, 1);
    assert_eq!(snapshot.status_rejected, 1);
    assert_eq!(snapshot.ownership_rejected, 1);
    assert_eq!(snapshot.syscall_errors, 1);
    assert_eq!(snapshot.mmap_errors, 1);
    assert_eq!(
        PlatformError::Syscall {
            stage: SyscallStage::Mmap,
            errno: ruster_io_afpacket::Errno::new(12),
        }
        .to_string(),
        "Mmap failed with errno 12"
    );

    assert_eq!(AfPacketPlatform::is_supported(), cfg!(target_os = "linux"));
    #[cfg(target_os = "linux")]
    {
        let layout = AfPacketPlatform::ensure_supported().expect("Linux UAPI");
        assert_eq!(layout.tpacket3_header, 48);
        assert_eq!(layout.tpacket3_status_offset, 20);
        assert_eq!(layout.tpacket3_mac_offset, 24);
        assert_eq!(layout.tpacket_block_alignment, 8);
        assert_eq!(layout.block_status_offset, 8);
        assert_eq!(layout.block_sequence_offset, 24);
        assert_eq!(layout.tpacket3_hdrlen, 68);
        assert_eq!(layout.ethernet_mac_offset, 82);
    }
}

#[test]
fn block_validation_accepts_exact_header_and_packet_count_boundaries() {
    let layout = geometry().validate_rx(4_096, 1_514).expect("layout");
    let block = BlockDescriptor {
        version: 2,
        offset_to_private: 48,
        block_len: 112,
        packet_count: 1,
        first_packet_offset: 64,
    };

    // Protect strict `>` checks: an exactly fitting first header and packet count are valid.
    block
        .validate(layout)
        .expect("one packet header exactly ends at the block boundary");
}

#[test]
fn block_layout_rejects_short_blocks_and_preserves_the_header_lower_bound() {
    let layout = geometry().validate_rx(4_096, 1_514).expect("layout");
    let short = BlockDescriptor {
        version: 2,
        offset_to_private: 48,
        block_len: 47,
        packet_count: 1,
        first_packet_offset: 64,
    };
    assert_eq!(
        short.validate(layout),
        Err(GeometryError::FirstPacketOffsetInvalid { offset: 64 })
    );

    let layout_without_private = RingGeometry {
        private_size: 0,
        ..geometry()
    }
    .validate_rx(4_096, 1_514)
    .expect("layout without private bytes");
    let header_sized = BlockDescriptor {
        version: 2,
        offset_to_private: 48,
        block_len: 48,
        packet_count: 1,
        first_packet_offset: 48,
    };

    // Protect the strict block-header lower bound: 48 bytes reaches the next validation stage.
    assert_eq!(
        header_sized.validate(layout_without_private),
        Err(GeometryError::PacketHeaderOutOfBounds { offset: 48 })
    );
}

#[test]
fn rx_geometry_accepts_exact_strict_frame_capacity() {
    let exact = RingGeometry {
        block_size: 4_096,
        block_count: 1,
        frame_size: 4_096,
        frame_count: 1,
        ..geometry()
    };

    // Protect the RX truncation guard: the maximum frame ending exactly at block_size is valid.
    exact
        .validate_rx(4_096, 3_950)
        .expect("exact RX frame capacity");
}

#[test]
fn geometry_rejects_non_power_of_two_pages_before_alignment_checks() {
    let exact_multiple = RingGeometry {
        block_size: 4_800,
        block_count: 1,
        frame_size: 1_600,
        frame_count: 3,
        ..geometry()
    };

    // Protect the page-size disjunction: a nonzero non-power-of-two page is rejected on its own.
    assert_eq!(
        exact_multiple.validate_rx(3, 1_514),
        Err(GeometryError::PageSizeNotPowerOfTwo { page_size: 3 })
    );
}

#[test]
fn exact_kernel_limit_uses_the_following_alignment_error() {
    let exact_limit = RingGeometry {
        block_size: i32::MAX as u32,
        ..geometry()
    };

    // Protect the strict kernel limit: equality is not that error, and reaches page alignment.
    assert_eq!(
        exact_limit.validate_rx(4_096, 1_514),
        Err(GeometryError::BlockSizeNotPageAligned {
            block_size: i32::MAX as u32,
            page_size: 4_096,
        })
    );
}

#[cfg(target_pointer_width = "32")]
#[test]
fn ring_geometry_rejects_map_length_above_isize_max_directly() {
    let geometry = RingGeometry {
        block_size: 1_073_741_824,
        block_count: 3,
        frame_size: 1_073_741_824,
        frame_count: 3,
        retire_timeout_ms: 0,
        private_size: 0,
        feature_flags: 0,
    };

    // Protect the direct ring map-length guard before ValidatedConfig's combined-map check.
    assert_eq!(
        geometry.validate_rx(4_096, 1_514),
        Err(GeometryError::MapLengthExceedsAddressSpace {
            map_len: 3_221_225_472,
        })
    );
}

#[test]
fn frame_size_accepts_the_exact_aligned_minimum() {
    let exact = RingGeometry {
        block_size: 4_096,
        block_count: 1,
        frame_size: 256,
        frame_count: 16,
        retire_timeout_ms: 0,
        private_size: 0,
        feature_flags: 0,
    };

    // Protect the strict frame-size minimum: an exactly aligned frame is large enough.
    exact
        .validate_tx(4_096, 193)
        .expect("exact TX frame minimum");
}

#[test]
fn validated_config_preserves_frame_limit_and_layout_counts() {
    let config = ValidatedConfig::new(&[port(7, 3)], 4_096, 1_514).expect("configuration");
    let validated = config.ports()[0];

    // Protect cold-path accessors used by the TX size check and ring traversal.
    assert_eq!(config.max_frame_len(), 1_514);
    assert_eq!(validated.rx().frames_per_block(), 2);
}

#[test]
fn packet_validation_distinguishes_header_and_data_end_boundaries() {
    let header_boundary = PacketDescriptor {
        packet_offset: 64,
        next_offset: 0,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 0,
        wire_len: 0,
        is_last: true,
    };
    assert_eq!(
        header_boundary.validate(112),
        Err(GeometryError::PacketDataOutOfBounds {
            offset: 146,
            length: 0,
        })
    );

    let data_boundary = PacketDescriptor {
        packet_offset: 64,
        next_offset: 0,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 110,
        wire_len: 110,
        is_last: true,
    };

    // Protect strict packet bounds and equality-based non-truncation at the block end.
    let validated = data_boundary
        .validate(256)
        .expect("packet data exactly ends at block_size");
    assert_eq!(validated.data(), 146..256);
    assert!(!validated.is_truncated());
}

#[test]
fn packet_validation_rejects_mac_offset_at_the_header_limit() {
    let descriptor = PacketDescriptor {
        packet_offset: 64,
        next_offset: 0,
        mac_offset: 68,
        net_offset: 96,
        snap_len: 0,
        wire_len: 0,
        is_last: true,
    };

    // Protect the strict MAC header lower bound: equality is checked by the Ethernet offset rule.
    assert_eq!(
        descriptor.validate(200),
        Err(GeometryError::EthernetMacOffsetInvalid { mac_offset: 68 })
    );
}

#[test]
fn packet_validation_rejects_a_next_offset_at_the_header_limit() {
    let descriptor = PacketDescriptor {
        packet_offset: 64,
        next_offset: 48,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 0,
        wire_len: 0,
        is_last: false,
    };

    // Protect the strict next-offset lower bound before the cross-packet check.
    assert_eq!(
        descriptor.validate(160),
        Err(GeometryError::PacketCrossesNextOffset)
    );
}

#[test]
fn packet_chain_accepts_exact_next_header_and_data_boundaries() {
    let descriptor = PacketDescriptor {
        packet_offset: 64,
        next_offset: 88,
        mac_offset: 82,
        net_offset: 96,
        snap_len: 6,
        wire_len: 6,
        is_last: false,
    };

    // Protect exact `>` checks for the next header/data and preserve non-truncated packets.
    let validated = descriptor
        .validate(200)
        .expect("next header and data end exactly at their boundaries");
    assert_eq!(validated.next_packet_offset(), Some(152));
    assert_eq!(validated.data(), 146..152);
    assert!(!validated.is_truncated());
}

#[test]
fn block_chain_rejects_descriptor_count_mismatch() {
    let layout = geometry().validate_rx(4_096, 1_514).expect("layout");
    let block = BlockDescriptor {
        version: 2,
        offset_to_private: 48,
        block_len: 4_096,
        packet_count: 1,
        first_packet_offset: 64,
    };

    // Protect the chain validator from accepting a block whose descriptor count disagrees.
    assert_eq!(
        validate_v3_block_chain(block, &[], layout),
        Err(GeometryError::PacketDescriptorCountMismatch {
            packet_count: 1,
            descriptors: 0,
        })
    );
}

#[test]
fn tx_status_mapping_keeps_sending_and_wrong_format_states() {
    // Protect both explicit TX status arms used by completion and retry handling.
    assert_eq!(
        TxOwnership::from_status(ruster_io_afpacket::TP_STATUS_SENDING),
        Ok(TxOwnership::Sending)
    );
    assert_eq!(
        TxOwnership::from_status(ruster_io_afpacket::TP_STATUS_WRONG_FORMAT),
        Ok(TxOwnership::WrongFormat)
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_af_packet_is_explicitly_unsupported() {
    // Protect the target-specific support gate and its non-Linux error path.
    assert!(!AfPacketPlatform::is_supported());
    assert_eq!(
        AfPacketPlatform::ensure_supported(),
        Err(PlatformError::UnsupportedPlatform)
    );
}

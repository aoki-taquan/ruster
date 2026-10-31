use std::{ffi::c_int, mem::ManuallyDrop, os::fd::RawFd, ptr::NonNull};

use ruster_core::IfId;

use super::{
    Completion, RxBatchReport, RxBlockReturn, RxBlockToken, RxBudget, RxFault, RxNext, RxPacket,
    RxPacketToken, RxReleaseError, RxStop,
};
use crate::{
    boundary::RxPacketFault,
    sys::{tests::allocation_count, PacketOps, PacketRingResources, SockaddrLl},
    GeometryError, MappingAccessError, OwnershipError, PlatformError, PortConfig, RingGeometry,
    RingKind, RxBlockModel, RxOwnership, SyscallStage, ValidatedConfig, TP_STATUS_KERNEL,
    TP_STATUS_USER,
};

const BLOCK_SIZE: usize = 4_096;
const BLOCKS: usize = 4;
const RX_LEN: usize = BLOCK_SIZE * BLOCKS;
const COMBINED_LEN: usize = RX_LEN + 4_096;
const FIRST_PACKET: usize = 64;
const MAX_FRAME: usize = 1_514;
const UNLIMITED: RxBudget = RxBudget {
    packets: usize::MAX,
    block_status_reads: usize::MAX,
    descriptor_visits: usize::MAX,
};

// Accessed only through raw pointers derived from Box::into_raw.
#[repr(align(4_096))]
struct Backing(#[allow(dead_code)] [u8; COMBINED_LEN]);

#[derive(Clone)]
struct FixtureOps {
    base: NonNull<u8>,
}

impl PacketOps for FixtureOps {
    fn open_socket(&mut self) -> Result<RawFd, PlatformError> {
        Ok(75)
    }

    fn set_socket_option<T>(
        &mut self,
        _fd: RawFd,
        _option: c_int,
        _value: &T,
        _stage: SyscallStage,
    ) -> Result<(), PlatformError> {
        Ok(())
    }

    fn bind(&mut self, _fd: RawFd, _address: &SockaddrLl) -> Result<(), PlatformError> {
        Ok(())
    }

    fn map(&mut self, _fd: RawFd, len: usize) -> Result<NonNull<u8>, PlatformError> {
        assert_eq!(len, COMBINED_LEN);
        Ok(self.base)
    }

    fn kick(&mut self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }

    fn unmap(&mut self, _base: NonNull<u8>, _len: usize) {}

    fn close(&mut self, _fd: RawFd) {}
}

/// Kernel stand-in that writes TPACKET_V3 RX blocks into a fake mapping.
struct Fixture {
    port: ManuallyDrop<PacketRingResources<FixtureOps>>,
    base: NonNull<u8>,
}

impl Fixture {
    fn new() -> Self {
        let rx = RingGeometry {
            block_size: 4_096,
            block_count: 4,
            frame_size: 2_048,
            frame_count: 8,
            retire_timeout_ms: 10,
            private_size: 16,
            feature_flags: 1,
        };
        let tx = RingGeometry {
            block_size: 4_096,
            block_count: 1,
            frame_size: 2_048,
            frame_count: 2,
            retire_timeout_ms: 0,
            private_size: 0,
            feature_flags: 0,
        };
        let config = ValidatedConfig::new(
            &[PortConfig {
                interface: IfId(7),
                if_index: 9,
                rx,
                tx,
            }],
            4_096,
            MAX_FRAME,
        )
        .expect("fixture config");
        let port = config.ports()[0];
        assert_eq!(port.rx().block_plus_private(), FIRST_PACKET);
        assert_eq!(port.combined_map_len(), COMBINED_LEN);
        let base = NonNull::new(Box::into_raw(Box::new(Backing([0; COMBINED_LEN]))))
            .expect("boxed backing")
            .cast::<u8>();
        let port = PacketRingResources::open_with_ops(port, FixtureOps { base })
            .expect("fixture resources");
        Self {
            port: ManuallyDrop::new(port),
            base,
        }
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) {
        self.port.mapping.write_for_test(offset, bytes);
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.write(offset, &value.to_ne_bytes());
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        self.write(offset, &value.to_ne_bytes());
    }

    fn status(&self, block: usize) -> u32 {
        raw_u32(self.base, block * BLOCK_SIZE + 8)
    }

    fn set_status(&mut self, block: usize, status: u32) {
        self.write_u32(block * BLOCK_SIZE + 8, status);
    }

    /// Lays out packets exactly as the kernel does: each header is followed
    /// by `tp_mac` bytes of headroom and the payload, aligned to eight bytes;
    /// the terminal packet has `tp_next_offset == 0`. The block status is
    /// written last.
    fn write_block(&mut self, block: usize, packets: &[Packet<'_>]) {
        let start = block * BLOCK_SIZE;
        let mut offset = FIRST_PACKET;
        for (index, packet) in packets.iter().enumerate() {
            let total = (82 + packet.payload.len()).next_multiple_of(8);
            let next = if index + 1 == packets.len() {
                0
            } else {
                u32::try_from(total).expect("small offset")
            };
            let header = start + offset;
            let snap = packet
                .snap_len
                .unwrap_or(u32::try_from(packet.payload.len()).expect("small payload"));
            self.write_u32(header, packet.next_offset.unwrap_or(next));
            self.write_u32(header + 12, snap);
            self.write_u32(header + 16, packet.wire_len.unwrap_or(snap));
            self.write_u32(header + 20, packet.status);
            self.write_u16(header + 24, packet.mac_offset);
            self.write_u16(header + 26, 96);
            self.write(header + 82, packet.payload);
            offset += total;
        }
        self.write_u32(start, 2);
        self.write_u32(start + 4, 48);
        self.write_u32(
            start + 12,
            u32::try_from(packets.len()).expect("small count"),
        );
        self.write_u32(start + 16, u32::try_from(FIRST_PACKET).expect("offset"));
        self.write_u32(start + 20, u32::try_from(offset).expect("block length"));
        self.set_status(block, TP_STATUS_USER);
    }

    fn data_address(&self, block: usize, packet_offset: usize) -> usize {
        self.base.as_ptr() as usize + block * BLOCK_SIZE + packet_offset + 82
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: the engine is dropped exactly once, here, before the
        // backing it points into is freed. The fake ops never unmap.
        unsafe { ManuallyDrop::drop(&mut self.port) };
        // SAFETY: `base` came from Box::into_raw of a `Backing` in `new` and
        // is freed only here, after its only user was dropped above.
        drop(unsafe { Box::from_raw(self.base.as_ptr().cast::<Backing>()) });
    }
}

fn raw_u32(base: NonNull<u8>, offset: usize) -> u32 {
    assert!(offset + 4 <= COMBINED_LEN && offset.is_multiple_of(4));
    // SAFETY: the bounds and alignment are asserted inside the live boxed
    // backing. This volatile read observes memory without creating a Rust
    // reference, so it does not conflict with a live engine borrow.
    unsafe { std::ptr::read_volatile(base.as_ptr().add(offset).cast::<u32>()) }
}

fn raw_u8(base: NonNull<u8>, offset: usize) -> u8 {
    assert!(offset < COMBINED_LEN);
    // SAFETY: as in `raw_u32`.
    unsafe { std::ptr::read_volatile(base.as_ptr().add(offset)) }
}

#[derive(Clone, Copy)]
struct Packet<'p> {
    payload: &'p [u8],
    snap_len: Option<u32>,
    wire_len: Option<u32>,
    mac_offset: u16,
    next_offset: Option<u32>,
    status: u32,
}

const fn packet(payload: &[u8]) -> Packet<'_> {
    Packet {
        payload,
        snap_len: None,
        wire_len: None,
        mac_offset: 82,
        next_offset: None,
        status: TP_STATUS_USER,
    }
}

fn token(block_index: usize, generation: u64, packet_index: u32) -> RxPacketToken {
    RxPacketToken {
        block: RxBlockToken {
            block_index,
            generation,
        },
        packet_index,
    }
}

fn expect_packet<'b>(next: Option<RxNext<'b, FixtureOps>>) -> RxPacket<'b, FixtureOps> {
    match next {
        Some(RxNext::Packet(packet)) => packet,
        Some(RxNext::Fault(fault)) => panic!("unexpected RX fault {fault:?}"),
        None => panic!("RX batch ended early"),
    }
}

fn expect_fault(next: Option<RxNext<'_, FixtureOps>>) -> RxFault {
    match next {
        Some(RxNext::Fault(fault)) => fault,
        Some(RxNext::Packet(packet)) => panic!("unexpected RX packet {:?}", packet.token()),
        None => panic!("RX batch ended early"),
    }
}

fn budget(packets: usize, block_status_reads: usize, descriptor_visits: usize) -> RxBudget {
    RxBudget {
        packets,
        block_status_reads,
        descriptor_visits,
    }
}

#[test]
fn rx_budget_resumes_saved_cursor_without_rescan_or_early_return() {
    let mut fixture = Fixture::new();
    fixture.write_block(0, &[packet(&[1; 60]), packet(&[2; 61]), packet(&[3; 62])]);
    let mut reports = Vec::new();
    for index in 0_u32..3 {
        let mut batch = fixture.port.begin_rx(budget(1, usize::MAX, usize::MAX));
        let packet = expect_packet(batch.next());
        assert_eq!(packet.token(), token(0, 1, index));
        assert_eq!(packet.ingress(), IfId(7));
        assert_eq!(packet.len(), 60 + index as usize);
        assert!(packet
            .bytes()
            .iter()
            .all(|byte| *byte == u8::try_from(index + 1).expect("marker")));
        let returned = packet.release().expect("release");
        if index < 2 {
            assert_eq!(returned, None, "block returned before its last packet");
        } else {
            assert_eq!(
                returned,
                Some(RxBlockReturn {
                    block: RxBlockToken {
                        block_index: 0,
                        generation: 1,
                    },
                    packet_count: 3,
                })
            );
        }
        assert!(batch.next().is_none());
        reports.push(batch.finish());
        let expected_status = if index < 2 {
            TP_STATUS_USER
        } else {
            TP_STATUS_KERNEL
        };
        assert_eq!(fixture.status(0), expected_status);
    }
    assert_eq!(
        reports[0],
        RxBatchReport {
            status_reads: 1,
            descriptor_visits: 3,
            blocks_acquired: 1,
            leased: 1,
            released: 1,
            stop: Some(RxStop::PacketBudget),
            ..RxBatchReport::default()
        }
    );
    assert_eq!(
        reports[1],
        RxBatchReport {
            leased: 1,
            released: 1,
            stop: Some(RxStop::PacketBudget),
            ..RxBatchReport::default()
        }
    );
    assert_eq!(
        reports[2],
        RxBatchReport {
            leased: 1,
            released: 1,
            blocks_returned: 1,
            stop: Some(RxStop::PacketBudget),
            ..RxBatchReport::default()
        }
    );

    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert!(batch.next().is_none());
    assert!(batch.next().is_none(), "a stopped batch rereads nothing");
    assert_eq!(
        batch.finish(),
        RxBatchReport {
            status_reads: 1,
            stop: Some(RxStop::RingEmpty),
            ..RxBatchReport::default()
        }
    );
}

#[test]
fn rx_validation_budget_persists_progress_and_zero_budgets_do_not_scan() {
    let mut fixture = Fixture::new();
    fixture.write_block(0, &[packet(&[1; 60]), packet(&[2; 60]), packet(&[3; 60])]);

    for (zero, stop) in [
        (budget(0, usize::MAX, usize::MAX), RxStop::PacketBudget),
        (budget(usize::MAX, 0, usize::MAX), RxStop::StatusBudget),
        (budget(usize::MAX, usize::MAX, 0), RxStop::DescriptorBudget),
    ] {
        let mut batch = fixture.port.begin_rx(zero);
        assert!(batch.next().is_none());
        assert_eq!(
            batch.finish(),
            RxBatchReport {
                stop: Some(stop),
                ..RxBatchReport::default()
            }
        );
    }

    let mut reports = Vec::new();
    for _ in 0..2 {
        let mut batch = fixture.port.begin_rx(budget(usize::MAX, usize::MAX, 1));
        assert!(batch.next().is_none(), "packet exposed before full chain");
        reports.push(batch.finish());
    }
    assert_eq!(
        reports,
        [
            RxBatchReport {
                status_reads: 1,
                descriptor_visits: 1,
                blocks_acquired: 1,
                stop: Some(RxStop::DescriptorBudget),
                ..RxBatchReport::default()
            },
            RxBatchReport {
                descriptor_visits: 1,
                stop: Some(RxStop::DescriptorBudget),
                ..RxBatchReport::default()
            },
        ]
    );
    let mut batch = fixture.port.begin_rx(budget(usize::MAX, usize::MAX, 1));
    let mut markers = Vec::new();
    while let Some(next) = batch.next() {
        let packet = expect_packet(Some(next));
        markers.push(packet.bytes()[0]);
        drop(packet);
    }
    assert_eq!(markers, [1, 2, 3]);
    let report = batch.finish();
    assert_eq!(
        report.status_reads, 0,
        "exhausted descriptor budget observed a block"
    );
    assert_eq!(report.descriptor_visits, 1);
    assert_eq!(report.leased, 3);
    assert_eq!(report.dropped, 3);
    assert_eq!(report.released, 0);
    assert_eq!(report.blocks_returned, 1);
    assert_eq!(report.stop, Some(RxStop::DescriptorBudget));
    assert_eq!(fixture.port.metadata.rx_blocks()[1].generation, 0);
}

#[test]
fn rx_ring_wraps_in_ring_order_and_reuse_advances_generation() {
    let mut fixture = Fixture::new();
    for block in 0..BLOCKS {
        fixture.write_block(
            block,
            &[packet(&[u8::try_from(block).expect("marker"); 60])],
        );
    }
    let mut first_cycle = Vec::new();
    {
        let mut batch = fixture.port.begin_rx(UNLIMITED);
        while let Some(next) = batch.next() {
            let packet = expect_packet(Some(next));
            first_cycle.push((packet.token(), packet.bytes()[0]));
            assert!(packet.release().expect("release").is_some());
        }
        assert_eq!(batch.finish().stop, Some(RxStop::RingEmpty));
    }
    assert_eq!(
        first_cycle,
        (0..BLOCKS)
            .map(|block| (token(block, 1, 0), u8::try_from(block).expect("marker")))
            .collect::<Vec<_>>()
    );
    for block in 0..BLOCKS {
        assert_eq!(fixture.status(block), TP_STATUS_KERNEL);
    }

    // The cursor wrapped to block zero; a USER block further ahead is never
    // taken out of ring order.
    fixture.write_block(2, &[packet(&[0x22; 60])]);
    {
        let mut batch = fixture.port.begin_rx(UNLIMITED);
        assert!(batch.next().is_none());
        assert_eq!(batch.finish().stop, Some(RxStop::RingEmpty));
    }
    assert_eq!(fixture.status(2), TP_STATUS_USER);

    fixture.write_block(0, &[packet(&[0x99; 60])]);
    fixture.write_block(1, &[packet(&[0x11; 60])]);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    let reused = expect_packet(batch.next());
    assert_eq!(reused.token(), token(0, 2, 0));
    assert_ne!(
        reused.token(),
        first_cycle[0].0,
        "reused block kept its identity"
    );
    assert_eq!(reused.bytes()[0], 0x99);
    drop(reused);
    assert_eq!(expect_packet(batch.next()).token(), token(1, 2, 0));
    assert_eq!(expect_packet(batch.next()).token(), token(2, 2, 0));
    assert!(batch.next().is_none());
}

#[test]
fn rx_live_lease_blocks_return_until_release_and_returns_exactly_once() {
    let mut fixture = Fixture::new();
    fixture.write_block(0, &[packet(&[0xa5; 60]), packet(&[0x5a; 60])]);
    let base = fixture.base;
    let expected_data = fixture.data_address(0, FIRST_PACKET);
    {
        let mut batch = fixture.port.begin_rx(UNLIMITED);
        let mut first = expect_packet(batch.next());
        assert_eq!(first.bytes().as_ptr() as usize, expected_data, "copied");
        first.bytes_mut()[0] = 0xee;
        // While the lease is live the port is exclusively borrowed; the
        // kernel-visible status is still USER.
        assert_eq!(raw_u32(base, 8), TP_STATUS_USER);
        drop(first);
        assert_eq!(raw_u32(base, 8), TP_STATUS_USER, "one sibling outstanding");

        let second = expect_packet(batch.next());
        assert_eq!(raw_u32(base, 8), TP_STATUS_USER);
        assert!(second.release().expect("final release").is_some());
        assert_eq!(raw_u32(base, 8), TP_STATUS_KERNEL);
        assert!(batch.next().is_none());
        let report = batch.finish();
        assert_eq!(report.leased, 2);
        assert_eq!(report.released, 1);
        assert_eq!(report.dropped, 1);
        assert_eq!(report.abandoned_leaks, 0);
        assert_eq!(report.blocks_returned, 1);
    }
    assert_eq!(raw_u8(base, FIRST_PACKET + 82), 0xee, "zero-copy mutation");

    // The returned packet's token is stale: no second completion or return.
    let mut report = RxBatchReport::default();
    assert_eq!(
        fixture
            .port
            .rx_complete(token(0, 1, 1), Completion::Released, &mut report),
        Err(RxReleaseError::Stale(token(0, 1, 1)))
    );
    assert_eq!(report, RxBatchReport::default());

    // A forgotten lease is completed as abandoned on the next cursor step.
    fixture.write_block(1, &[packet(&[1; 60]), packet(&[2; 60])]);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    std::mem::forget(expect_packet(batch.next()));
    assert_eq!(raw_u32(base, BLOCK_SIZE + 8), TP_STATUS_USER);
    let second = expect_packet(batch.next());
    assert_eq!(second.token(), token(1, 1, 1));
    assert!(second.release().expect("release").is_some());
    let report = batch.finish();
    assert_eq!(report.leased, 2);
    assert_eq!(report.abandoned_leaks, 1);
    assert_eq!(report.released, 1, "abandoned completion double-counted");
    assert_eq!(report.dropped, 0);
    assert_eq!(report.blocks_returned, 1);
    assert_eq!(fixture.status(1), TP_STATUS_KERNEL);
}

#[test]
fn rx_unsafe_chain_returns_whole_block_without_exposing_or_walking_suffix() {
    let mut fixture = Fixture::new();
    // Packet 1 has a misaligned next link while the header claims the
    // maximum count; nothing after it may be visited.
    let mut packets = [packet(&[1; 60]); 3];
    packets[1].next_offset = Some(148);
    fixture.write_block(0, &packets);
    fixture.write_u32(12, 84);
    fixture.write_u32(20, 4_096);
    fixture.write_block(1, &[packet(&[0x77; 60])]);
    let base = fixture.base;
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert_eq!(
        expect_fault(batch.next()),
        RxFault::Block {
            block: RxBlockToken {
                block_index: 0,
                generation: 1,
            },
            packet_index: Some(1),
            error: MappingAccessError::Geometry(GeometryError::NextPacketOffsetNotAligned {
                offset: 148,
            }),
            return_error: None,
        }
    );
    assert_eq!(raw_u32(base, 8), TP_STATUS_KERNEL);
    let next = expect_packet(batch.next());
    assert_eq!(next.token(), token(1, 1, 0));
    assert_eq!(next.bytes()[0], 0x77);
    drop(next);
    let report = batch.finish();
    assert_eq!(
        report.descriptor_visits, 3,
        "two in block 0, one in block 1"
    );
    assert_eq!(report.block_faults, 1);
    assert_eq!(report.blocks_returned, 2);
    assert_eq!(report.leased, 1);
    assert_eq!(fixture.status(0), TP_STATUS_KERNEL);
    assert_eq!(fixture.port.rx_stats().geometry_rejected, 1);

    // A terminal packet that still names a successor is an unsafe chain.
    let mut terminal = packet(&[3; 60]);
    terminal.next_offset = Some(48);
    fixture.write_block(2, &[terminal]);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert!(matches!(
        expect_fault(batch.next()),
        RxFault::Block {
            packet_index: Some(0),
            error: MappingAccessError::Geometry(GeometryError::TerminalPacketHasNextOffset {
                offset: 48
            }),
            return_error: None,
            ..
        }
    ));
    assert!(batch.next().is_none());
    assert_eq!(fixture.status(2), TP_STATUS_KERNEL);
}

#[test]
fn rx_malformed_block_header_is_returned_without_reading_descriptors() {
    let cases: [(usize, u32, GeometryError); 6] = [
        (0, 1, GeometryError::UnsupportedBlockVersion { version: 1 }),
        (4, 0, GeometryError::PrivateOffsetInvalid { offset: 0 }),
        (12, 0, GeometryError::PacketCountZero),
        (
            16,
            72,
            GeometryError::FirstPacketOffsetMismatch {
                configured: 72,
                expected: 64,
            },
        ),
        (
            20,
            4_097,
            GeometryError::FirstPacketOffsetInvalid { offset: 64 },
        ),
        (
            12,
            85,
            GeometryError::PacketCountExceedsBlock {
                packet_count: 85,
                maximum: 84,
            },
        ),
    ];
    for (field, value, expected) in cases {
        let mut fixture = Fixture::new();
        fixture.write_block(0, &[packet(&[1; 60])]);
        fixture.write_u32(field, value);
        if field == 12 && value == 85 {
            fixture.write_u32(20, 4_096);
        }
        fixture.write_block(1, &[packet(&[2; 60])]);
        let mut batch = fixture.port.begin_rx(UNLIMITED);
        assert_eq!(
            expect_fault(batch.next()),
            RxFault::Block {
                block: RxBlockToken {
                    block_index: 0,
                    generation: 1,
                },
                packet_index: None,
                error: MappingAccessError::Geometry(expected),
                return_error: None,
            }
        );
        let report = batch.report();
        assert_eq!(
            report.descriptor_visits, 0,
            "descriptor read after bad header"
        );
        assert_eq!(expect_packet(batch.next()).bytes()[0], 2);
        drop(batch);
        assert_eq!(fixture.status(0), TP_STATUS_KERNEL);
        assert_eq!(fixture.status(1), TP_STATUS_KERNEL);
        assert_eq!(fixture.port.rx_stats().geometry_rejected, 1);
    }
}

#[test]
fn rx_local_packet_faults_are_terminal_once_and_siblings_are_delivered() {
    let mut fixture = Fixture::new();
    let mut snap_over_wire = packet(&[2; 60]);
    snap_over_wire.wire_len = Some(59);
    let mut truncated = packet(&[3; 60]);
    truncated.wire_len = Some(1_500);
    let mut bad_mac = packet(&[4; 60]);
    bad_mac.mac_offset = 80;
    let oversize = packet(&[5; 1_515]);
    let maximum = [6; 1_514];
    let at_maximum = packet(&maximum);
    let mut out_of_block = packet(&[7; 60]);
    out_of_block.snap_len = Some(4_000);
    out_of_block.wire_len = Some(4_000);
    let packets = [
        packet(&[1; 60]),
        snap_over_wire,
        truncated,
        bad_mac,
        oversize,
        at_maximum,
        out_of_block,
    ];
    fixture.write_block(0, &packets);
    let block_len = raw_u32(fixture.base, 20) as usize;

    let mut events = Vec::new();
    let mut batch = fixture.port.begin_rx(budget(2, usize::MAX, usize::MAX));
    while let Some(next) = batch.next() {
        events.push(match next {
            RxNext::Packet(packet) => {
                let event = (packet.token().packet_index, None, packet.len());
                drop(packet);
                event
            }
            RxNext::Fault(RxFault::Packet { token, fault, .. }) => {
                (token.packet_index, Some(fault), 0)
            }
            RxNext::Fault(fault) => panic!("unexpected block fault {fault:?}"),
        });
    }
    assert_eq!(batch.finish().stop, Some(RxStop::PacketBudget));
    assert_eq!(fixture.status(0), TP_STATUS_USER);

    let mut batch = fixture.port.begin_rx(UNLIMITED);
    let mut returned = Vec::new();
    while let Some(next) = batch.next() {
        events.push(match next {
            RxNext::Packet(packet) => {
                let event = (packet.token().packet_index, None, packet.len());
                drop(packet);
                event
            }
            RxNext::Fault(RxFault::Packet {
                token,
                fault,
                returned: block,
            }) => {
                returned.extend(block);
                (token.packet_index, Some(fault), 0)
            }
            RxNext::Fault(fault) => panic!("unexpected block fault {fault:?}"),
        });
    }
    let report = batch.finish();
    let last_offset = FIRST_PACKET
        + 144 * 4
        + (82_usize + 1_515).next_multiple_of(8)
        + (82_usize + 1_514).next_multiple_of(8);
    assert_eq!(
        events,
        [
            (0, None, 60),
            (
                1,
                Some(RxPacketFault::Descriptor(
                    GeometryError::SnapshotExceedsWireLength {
                        snap_len: 60,
                        wire_len: 59,
                    }
                )),
                0
            ),
            (
                2,
                Some(RxPacketFault::Truncated {
                    snap_len: 60,
                    wire_len: 1_500,
                }),
                0
            ),
            (
                3,
                Some(RxPacketFault::Descriptor(
                    GeometryError::EthernetMacOffsetInvalid { mac_offset: 80 }
                )),
                0
            ),
            (
                4,
                Some(RxPacketFault::Oversize {
                    length: 1_515,
                    maximum: MAX_FRAME,
                }),
                0
            ),
            (5, None, MAX_FRAME),
            (
                6,
                Some(RxPacketFault::Descriptor(
                    GeometryError::PacketDataOutOfBounds {
                        offset: last_offset + 82,
                        length: 4_000,
                    }
                )),
                0
            ),
        ]
    );
    assert!(last_offset + 82 + 4_000 > block_len);
    assert_eq!(
        returned,
        [RxBlockReturn {
            block: RxBlockToken {
                block_index: 0,
                generation: 1,
            },
            packet_count: 7,
        }]
    );
    assert_eq!(report.blocks_returned, 1);
    assert_eq!(fixture.status(0), TP_STATUS_KERNEL);

    // An offloaded VLAN tag would make a tagged frame look untagged.
    let mut vlan = packet(&[8; 60]);
    vlan.status = TP_STATUS_USER | 0x10 | 0x40;
    fixture.write_block(1, &[vlan, packet(&[9; 60])]);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert_eq!(
        expect_fault(batch.next()),
        RxFault::Packet {
            token: token(1, 1, 0),
            fault: RxPacketFault::VlanOffloaded {
                status: TP_STATUS_USER | 0x50,
            },
            returned: None,
        }
    );
    assert_eq!(expect_packet(batch.next()).bytes()[0], 9);
    drop(batch);
    assert_eq!(fixture.status(1), TP_STATUS_KERNEL);
    let stats = fixture.port.rx_stats();
    assert_eq!(stats.descriptor_rejected, 6);
    assert_eq!(stats.geometry_rejected, 0);
}

#[test]
fn rx_invalid_status_and_generation_exhaustion_fail_closed_without_touching_block() {
    let mut fixture = Fixture::new();
    fixture.write_block(0, &[packet(&[1; 60])]);
    fixture.set_status(0, 0x2);
    for _ in 0..3 {
        let mut batch = fixture.port.begin_rx(UNLIMITED);
        assert_eq!(
            expect_fault(batch.next()),
            RxFault::Status {
                block_index: 0,
                status: 0x2,
            }
        );
        assert!(batch.next().is_none());
        let report = batch.finish();
        assert_eq!(report.status_reads, 1);
        assert_eq!(report.stop, Some(RxStop::Halted));
        assert_eq!(fixture.status(0), 0x2, "unowned block was written");
    }
    // A persistent halt is one event, not one per poll; a different unknown
    // status is a new event.
    assert_eq!(fixture.port.rx_stats().status_rejected, 1);
    fixture.set_status(0, 0x4);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert_eq!(
        expect_fault(batch.next()),
        RxFault::Status {
            block_index: 0,
            status: 0x4,
        }
    );
    drop(batch);
    assert_eq!(fixture.port.rx_stats().status_rejected, 2);
    assert_eq!(fixture.port.metadata.rx_blocks()[0].generation, 0);

    fixture.set_status(0, TP_STATUS_USER);
    fixture.port.metadata.rx_blocks_mut()[0].generation = u64::MAX;
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert_eq!(
        expect_fault(batch.next()),
        RxFault::GenerationExhausted { block_index: 0 }
    );
    assert!(batch.next().is_none());
    drop(batch);
    assert_eq!(
        fixture.status(0),
        TP_STATUS_USER,
        "exhausted block was returned"
    );
    assert_eq!(fixture.port.rx_stats().ownership_rejected, 1);

    fixture.port.metadata.rx_blocks_mut()[0].generation = u64::MAX - 1;
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert_eq!(expect_packet(batch.next()).token(), token(0, u64::MAX, 0));
    assert!(batch.next().is_none());
    drop(batch);
    assert_eq!(fixture.status(0), TP_STATUS_KERNEL);
}

#[test]
fn rx_steady_receive_release_has_zero_allocations() {
    let mut fixture = Fixture::new();
    let payload = [0x42; 128];
    let packets = [packet(&payload), packet(&payload)];
    let mut truncated = packet(&payload);
    truncated.wire_len = Some(1_500);
    let faulted = [truncated, packet(&payload)];
    let before = allocation_count();
    let mut digest = 0_usize;
    for iteration in 0..10_000 {
        let block = iteration % BLOCKS;
        match iteration % 3 {
            0 => {
                fixture.write_block(block, &packets);
                let mut batch = fixture.port.begin_rx(UNLIMITED);
                let first = expect_packet(batch.next());
                digest ^= usize::from(first.bytes()[0]);
                assert_eq!(first.release().expect("first"), None);
                let second = expect_packet(batch.next());
                digest ^= second.len();
                assert!(second.release().expect("second").is_some());
                assert!(batch.next().is_none());
                assert_eq!(batch.finish().blocks_returned, 1);
            }
            1 => {
                fixture.write_block(block, &faulted);
                let mut batch = fixture.port.begin_rx(UNLIMITED);
                assert!(matches!(
                    expect_fault(batch.next()),
                    RxFault::Packet { returned: None, .. }
                ));
                drop(expect_packet(batch.next()));
                assert!(batch.next().is_none());
                assert_eq!(batch.finish().blocks_returned, 1);
            }
            _ => {
                fixture.write_block(block, &packets);
                fixture.write_u32(block * BLOCK_SIZE, 1);
                let mut batch = fixture.port.begin_rx(UNLIMITED);
                assert!(matches!(
                    expect_fault(batch.next()),
                    RxFault::Block {
                        return_error: None,
                        ..
                    }
                ));
                assert!(batch.next().is_none());
                assert_eq!(batch.finish().blocks_returned, 1);
            }
        }
    }
    std::hint::black_box(digest);
    assert_eq!(allocation_count(), before);
}

#[test]
fn rx_old_generation_token_is_stale_while_reused_block_is_delivering() {
    let mut fixture = Fixture::new();
    for block in 0..BLOCKS {
        fixture.write_block(block, &[packet(&[1; 60]), packet(&[2; 60])]);
    }
    {
        let mut batch = fixture.port.begin_rx(UNLIMITED);
        while let Some(next) = batch.next() {
            drop(expect_packet(Some(next)));
        }
        assert_eq!(batch.finish().blocks_returned, BLOCKS);
    }
    fixture.write_block(0, &[packet(&[3; 60]), packet(&[4; 60])]);
    {
        let mut batch = fixture.port.begin_rx(budget(1, usize::MAX, usize::MAX));
        let first = expect_packet(batch.next());
        assert_eq!(first.token(), token(0, 2, 0));
        assert_eq!(first.release().expect("first"), None);
    }
    let mut report = RxBatchReport::default();
    for (stale, kind) in [
        (token(0, 1, 1), Completion::Fault),
        (token(0, 1, 1), Completion::Released),
        (token(0, 1, 0), Completion::Fault),
        (token(0, 2, 0), Completion::Fault),
    ] {
        assert_eq!(
            fixture.port.rx_complete(stale, kind, &mut report),
            Err(RxReleaseError::Stale(stale))
        );
    }
    {
        // Lent packet of the new generation: an old-generation release of
        // the same index is still stale.
        let mut batch = fixture.port.begin_rx(budget(1, usize::MAX, usize::MAX));
        std::mem::forget(expect_packet(batch.next()));
    }
    for kind in [
        Completion::Released,
        Completion::Dropped,
        Completion::Abandoned,
    ] {
        assert_eq!(
            fixture.port.rx_complete(token(0, 1, 1), kind, &mut report),
            Err(RxReleaseError::Stale(token(0, 1, 1)))
        );
    }
    assert_eq!(report, RxBatchReport::default());
    assert_eq!(fixture.status(0), TP_STATUS_USER);
    assert_eq!(
        fixture.port.metadata.rx_blocks()[0].ownership.remaining(),
        1
    );
    assert_eq!(
        fixture
            .port
            .rx_complete(token(0, 2, 1), Completion::Abandoned, &mut report),
        Ok(Some(RxBlockReturn {
            block: RxBlockToken {
                block_index: 0,
                generation: 2,
            },
            packet_count: 2,
        }))
    );
    assert_eq!(fixture.status(0), TP_STATUS_KERNEL);
}

#[test]
fn rx_forgotten_leases_finalize_in_a_later_batch_with_packet_budget() {
    let mut fixture = Fixture::new();
    fixture.write_block(0, &[packet(&[1; 60]), packet(&[2; 60])]);
    let one = budget(1, usize::MAX, usize::MAX);
    let mut batch = fixture.port.begin_rx(one);
    std::mem::forget(expect_packet(batch.next()));
    assert!(batch.next().is_none());
    let first = batch.finish();
    assert_eq!((first.leased, first.abandoned_leaks), (1, 0));
    assert_eq!(first.stop, Some(RxStop::PacketBudget));

    // A zero packet budget neither scans nor finalizes the leaked lease.
    let mut batch = fixture.port.begin_rx(budget(0, usize::MAX, usize::MAX));
    assert!(batch.next().is_none());
    assert_eq!(batch.finish().abandoned_leaks, 0);
    assert_eq!(fixture.status(0), TP_STATUS_USER);

    let mut batch = fixture.port.begin_rx(one);
    let last = expect_packet(batch.next());
    assert_eq!(last.token(), token(0, 1, 1));
    std::mem::forget(last);
    assert!(batch.next().is_none());
    let second = batch.finish();
    assert_eq!(
        (
            second.leased,
            second.abandoned_leaks,
            second.blocks_returned
        ),
        (1, 1, 0)
    );
    assert_eq!(
        fixture.status(0),
        TP_STATUS_USER,
        "forgotten last packet returned"
    );

    let mut batch = fixture.port.begin_rx(budget(0, usize::MAX, usize::MAX));
    assert!(batch.next().is_none());
    drop(batch);
    assert_eq!(fixture.status(0), TP_STATUS_USER);

    let mut batch = fixture.port.begin_rx(one);
    assert!(batch.next().is_none());
    let third = batch.finish();
    assert_eq!(
        third,
        RxBatchReport {
            status_reads: 1,
            abandoned_leaks: 1,
            blocks_returned: 1,
            stop: Some(RxStop::RingEmpty),
            ..RxBatchReport::default()
        }
    );
    assert_eq!(fixture.status(0), TP_STATUS_KERNEL);
}

#[test]
fn rx_lease_dropped_during_unwind_completes_once() {
    let mut fixture = Fixture::new();
    fixture.write_block(0, &[packet(&[1; 60])]);
    let base = fixture.base;
    let port = &mut *fixture.port;
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut batch = port.begin_rx(UNLIMITED);
        let packet = expect_packet(batch.next());
        assert_eq!(raw_u32(base, 8), TP_STATUS_USER);
        std::hint::black_box(&packet);
        std::panic::resume_unwind(Box::new("unwind with a live lease"));
    }));
    assert!(unwound.is_err());
    assert_eq!(fixture.status(0), TP_STATUS_KERNEL);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert!(batch.next().is_none());
    assert_eq!(
        batch.finish(),
        RxBatchReport {
            status_reads: 1,
            stop: Some(RxStop::RingEmpty),
            ..RxBatchReport::default()
        }
    );
    assert_eq!(
        fixture.port.metadata.rx_blocks()[0].ownership.owner(),
        RxOwnership::Kernel
    );
    assert_eq!(fixture.port.rx_stats().ownership_rejected, 0);
}

#[test]
fn rx_acquire_invariant_failure_halts_without_returning_block() {
    let mut fixture = Fixture::new();
    fixture.write_block(0, &[packet(&[1; 60]), packet(&[2; 60])]);
    fixture.port.metadata.rx_blocks_mut()[0]
        .ownership
        .acquire(1)
        .expect("desynchronize model");
    let expected = RxFault::Acquire {
        block: RxBlockToken {
            block_index: 0,
            generation: 1,
        },
        error: OwnershipError::RxAcquireWhileOwned {
            owner: RxOwnership::User,
        },
    };
    let mut reports = Vec::new();
    for _ in 0..2 {
        let mut batch = fixture.port.begin_rx(UNLIMITED);
        assert_eq!(expect_fault(batch.next()), expected);
        assert!(batch.next().is_none());
        reports.push(batch.finish());
        assert_eq!(
            fixture.status(0),
            TP_STATUS_USER,
            "block returned on invariant failure"
        );
    }
    assert_eq!(reports[0].descriptor_visits, 2);
    assert_eq!(
        reports[1].descriptor_visits, 1,
        "only the final descriptor is retried"
    );
    assert_eq!(reports[1].status_reads, 0);
    let stats = fixture.port.rx_stats();
    assert_eq!(stats.ownership_rejected, 1);
    assert_eq!(stats.geometry_rejected, 0);

    fixture.port.metadata.rx_blocks_mut()[0].ownership = RxBlockModel::new();
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert_eq!(expect_packet(batch.next()).token(), token(0, 1, 0));
    assert_eq!(expect_packet(batch.next()).token(), token(0, 1, 1));
    assert!(batch.next().is_none());
    drop(batch);
    assert_eq!(fixture.status(0), TP_STATUS_KERNEL);
}

fn injected(offset: usize, length: usize) -> MappingAccessError {
    MappingAccessError::RingOffsetOutOfBounds {
        kind: RingKind::Rx,
        offset,
        length,
    }
}

#[test]
fn rx_injected_mapping_failures_halt_retry_and_count_once() {
    // Head status load failure: halts untouched, counted once per event.
    let mut fixture = Fixture::new();
    fixture.write_block(0, &[packet(&[1; 60])]);
    fixture.port.rx_injection.status_loads = 2;
    for _ in 0..2 {
        let mut batch = fixture.port.begin_rx(UNLIMITED);
        assert_eq!(
            expect_fault(batch.next()),
            RxFault::Mapping {
                block_index: 0,
                error: injected(8, 4),
            }
        );
        assert!(batch.next().is_none());
    }
    assert_eq!(fixture.port.rx_stats().mmap_errors, 1);
    assert_eq!(fixture.port.metadata.rx_blocks()[0].generation, 0);

    // Data address failure: only that packet faults.
    fixture.write_block(0, &[packet(&[1; 60]), packet(&[2; 60])]);
    fixture.port.rx_injection.data_addresses = 1;
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert_eq!(
        expect_fault(batch.next()),
        RxFault::Packet {
            token: token(0, 1, 0),
            fault: RxPacketFault::Mapping(injected(FIRST_PACKET + 82, 60)),
            returned: None,
        }
    );
    assert_eq!(expect_packet(batch.next()).bytes()[0], 2);
    assert!(batch.next().is_none());
    drop(batch);
    assert_eq!(fixture.status(0), TP_STATUS_KERNEL);
    assert_eq!(fixture.port.rx_stats().descriptor_rejected, 1);

    // Return-store failure: the release reports it, every packet stays
    // terminal, the next step retries and halts while it keeps failing, and
    // the block returns exactly once when the store succeeds.
    fixture.write_block(1, &[packet(&[3; 60])]);
    fixture.port.rx_injection.status_stores = 2;
    let store_error = injected(BLOCK_SIZE + 8, 4);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    let packet_lease = expect_packet(batch.next());
    assert_eq!(
        packet_lease.release(),
        Err(RxReleaseError::Mapping(store_error))
    );
    assert_eq!(
        expect_fault(batch.next()),
        RxFault::Release(RxReleaseError::Mapping(store_error))
    );
    assert!(batch.next().is_none());
    let report = batch.finish();
    assert_eq!((report.released, report.blocks_returned), (1, 0));
    assert_eq!(fixture.status(1), TP_STATUS_USER);
    assert_eq!(fixture.port.rx_stats().mmap_errors, 2);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert!(batch.next().is_none());
    let report = batch.finish();
    assert_eq!(
        (report.blocks_returned, report.released, report.stop),
        (1, 0, Some(RxStop::RingEmpty))
    );
    assert_eq!(fixture.status(1), TP_STATUS_KERNEL);
    assert_eq!(fixture.port.rx_stats().mmap_errors, 2);

    // Reject-store failure: the malformed block is not advanced past; the
    // next observation (new generation) returns it.
    fixture.write_block(2, &[packet(&[4; 60])]);
    fixture.write_u32(2 * BLOCK_SIZE, 1);
    fixture.port.rx_injection.status_stores = 1;
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert_eq!(
        expect_fault(batch.next()),
        RxFault::Block {
            block: RxBlockToken {
                block_index: 2,
                generation: 1,
            },
            packet_index: None,
            error: MappingAccessError::Geometry(GeometryError::UnsupportedBlockVersion {
                version: 1
            }),
            return_error: Some(injected(2 * BLOCK_SIZE + 8, 4)),
        }
    );
    assert!(batch.next().is_none());
    drop(batch);
    assert_eq!(fixture.status(2), TP_STATUS_USER);
    let mut batch = fixture.port.begin_rx(UNLIMITED);
    assert!(matches!(
        expect_fault(batch.next()),
        RxFault::Block {
            block: RxBlockToken {
                block_index: 2,
                generation: 2,
            },
            return_error: None,
            ..
        }
    ));
    drop(batch);
    assert_eq!(fixture.status(2), TP_STATUS_KERNEL);
    let stats = fixture.port.rx_stats();
    assert_eq!(stats.mmap_errors, 3);
    assert_eq!(stats.geometry_rejected, 2);
    assert_eq!(stats.ownership_rejected, 0);
}

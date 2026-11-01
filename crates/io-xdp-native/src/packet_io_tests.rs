//! Core adapter tests over two scripted heap kernels (M2 S6, X04a).

// `drop(batch)` marks where a batch borrow ends; it is deliberate.
#![allow(clippy::drop_non_drop)]

use std::num::{NonZeroU128, NonZeroU32};

use ruster_core::{
    forward_batch, ipv4_header_checksum, BackendMode, BackendStats, FieldValue, FieldVisitor,
    ForwardingSnapshot, GeneratedAllocationError, GeneratedPacketBatch, GeneratedPacketIo, IfId,
    Interface, Ipv4Address, MacAddress, Neighbor, NoTrace, ObservableFields, PacketBatch, PacketIo,
    PublicationQuiescence, PublicationQuiescenceDisposition, Route,
};

use crate::{
    abi::XdpStatistics,
    abi::{XdpDescriptor, XDP_RING_NEED_WAKEUP},
    native_unsafe::{
        heap_kernel::{allocation_count, ScriptedKernel},
        kick::KickRing,
    },
    packet_io::{generated_reserve, KICK_SLACK, KICK_TX_BATCH},
    KickError, NegotiatedMode, RingEntries, RingName, RxFillConfig, RxFillEngine, TxRejection,
    UmemConfig, UmemDomainId, XdpIoError, XdpPacketIo, XdpPacketIoSetupError, XdpPort,
    XdpPortConfig, XdpQuiescenceError, XDP_PACKET_HEADROOM,
};

pub(crate) const FRAME_SIZE: u32 = 2_048;
pub(crate) const FRAMES: u32 = 32;
pub(crate) const RX_FRAMES: u32 = 16;
pub(crate) const RING: u32 = 8;
pub(crate) const HEADROOM: u64 = XDP_PACKET_HEADROOM as u64;
pub(crate) const MTU: u32 = 1_500;

pub(crate) const LAN: IfId = IfId(1);
pub(crate) const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x01]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x02]);
const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x10];
const SERVER_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x20]);
const HOST_IP: [u8; 4] = [192, 0, 2, 10];
const SERVER_IP: [u8; 4] = [198, 51, 100, 20];

fn entries(ring: RingName, value: u32) -> RingEntries {
    RingEntries::new(ring, value).expect("ring entries")
}

pub(crate) fn kernel() -> ScriptedKernel {
    kernel_with(RX_FRAMES, FRAMES - RX_FRAMES)
}

pub(crate) fn kernel_with(rx_frames: u32, generated: u32) -> ScriptedKernel {
    ScriptedKernel::with_tx(
        entries(RingName::Fill, RING),
        entries(RingName::Rx, RING),
        entries(RingName::Tx, RING),
        entries(RingName::Completion, RING),
        UmemConfig::new(
            rx_frames + generated,
            FRAME_SIZE,
            0,
            rx_frames,
            generated,
            0,
        )
        .expect("UMEM"),
    )
}

pub(crate) fn engine(kernel: &ScriptedKernel, domain: u128) -> RxFillEngine<'_> {
    RxFillEngine::new(
        kernel.take_datapath().expect("first take"),
        UmemDomainId::new(NonZeroU128::new(domain).expect("nonzero")),
        RxFillConfig::new(NonZeroU32::new(RING).expect("nonzero")),
    )
    .expect("engine")
}

pub(crate) fn port(kernel: &ScriptedKernel, interface: IfId, queue: u32, mtu: u32) -> XdpPort<'_> {
    XdpPort::new(
        XdpPortConfig::for_test(interface, queue, NegotiatedMode::Copy, mtu, kernel.origin()),
        engine(kernel, 0x5600 + u128::from(interface.0)),
    )
}

/// LAN on `lan`, WAN on `wan`, both with [`MTU`].
fn adapter<'k>(lan: &'k ScriptedKernel, wan: &'k ScriptedKernel) -> XdpPacketIo<'k> {
    XdpPacketIo::new([port(wan, WAN, 0, MTU), port(lan, LAN, 0, MTU)]).expect("adapter")
}

pub(crate) fn frame_of(address: u64) -> u32 {
    u32::try_from(address / u64::from(FRAME_SIZE)).expect("frame")
}

/// Kernel-receives `bytes` into the oldest Fill frame; returns its address.
pub(crate) fn deliver(kernel: &ScriptedKernel, bytes: &[u8]) -> u64 {
    let base = kernel.consume_fill().expect("a published Fill frame");
    let address = base + HEADROOM;
    kernel.write_umem(address, bytes);
    assert!(kernel.produce_rx(XdpDescriptor {
        address,
        len: u32::try_from(bytes.len()).expect("short"),
        options: 0,
    }));
    address
}

/// Kernel-transmits and completes everything in TX.
fn transmit_all(kernel: &ScriptedKernel) -> Vec<(XdpDescriptor, Vec<u8>)> {
    let mut sent = Vec::new();
    while let Some(descriptor) = kernel.consume_tx() {
        let mut bytes = vec![0; descriptor.len as usize];
        kernel.read_umem(descriptor.address, &mut bytes);
        assert!(kernel.produce_completion(descriptor.address));
        sent.push((descriptor, bytes));
    }
    sent
}

fn audit(io: &XdpPacketIo<'_>) {
    for interface in [LAN, WAN] {
        if let Some(engine) = io.engine(interface) {
            engine.audit().expect("engine audit");
        }
    }
}

/// An IPv4/UDP frame from the LAN host to the WAN server, `len` bytes.
fn ipv4_frame(len: usize, ttl: u8) -> Vec<u8> {
    assert!(len >= 42);
    let mut bytes = vec![0_u8; len];
    bytes[0..6].copy_from_slice(&LAN_MAC.0);
    bytes[6..12].copy_from_slice(&HOST_MAC);
    bytes[12..14].copy_from_slice(&[0x08, 0x00]);
    let total = u16::try_from(len - 14).expect("short");
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&total.to_be_bytes());
    bytes[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    bytes[22] = ttl;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&HOST_IP);
    bytes[30..34].copy_from_slice(&SERVER_IP);
    let checksum = ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&9_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&(total - 20).to_be_bytes());
    bytes
}

struct Topology {
    routes: [Route; 2],
    interfaces: [Interface; 2],
    neighbors: [Neighbor; 1],
}

fn topology() -> Topology {
    let ip = Ipv4Address::from_octets;
    Topology {
        routes: [
            Route::new(ip([192, 0, 2, 0]), 24, LAN, None).expect("route"),
            Route::new(ip([198, 51, 100, 0]), 24, WAN, None).expect("route"),
        ],
        interfaces: [
            Interface {
                id: LAN,
                mac: LAN_MAC,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
            },
        ],
        neighbors: [Neighbor {
            interface: WAN,
            target: ip(SERVER_IP),
            mac: SERVER_MAC,
        }],
    }
}

fn snapshot(topology: &Topology) -> ForwardingSnapshot<'_> {
    ForwardingSnapshot::new(
        &topology.routes,
        &topology.interfaces,
        &topology.neighbors,
        &[],
    )
    .expect("snapshot")
}

/// Leases every frame of one batch and commits each to `egress`.
fn commit_all(io: &mut XdpPacketIo<'_>, budget: usize, egress: IfId) -> (usize, usize, usize) {
    let mut batch = io.receive(budget).expect("receive");
    while let Some(packet) = batch.next_packet() {
        packet.commit(egress);
    }
    let completion = batch.finish();
    assert!(completion.invariants_hold());
    assert_eq!(completion.error, None);
    (
        completion.tx_requested,
        completion.tx_accepted,
        completion.tx_rejected,
    )
}

#[test]
fn adapter_fixes_the_ifid_mapping_and_refuses_bad_port_sets() {
    let empty: [XdpPort<'_>; 0] = [];
    assert_eq!(
        XdpPacketIo::new(empty).map(|_| ()),
        Err(XdpPacketIoSetupError::NoPorts)
    );
    let (first, second) = (kernel(), kernel());
    assert_eq!(
        XdpPacketIo::new([port(&first, LAN, 0, MTU), port(&second, LAN, 1, MTU)]).map(|_| ()),
        Err(XdpPacketIoSetupError::DuplicateInterface(LAN))
    );
    let zero = kernel();
    assert_eq!(
        XdpPacketIo::new([port(&zero, WAN, 0, 0)]).map(|_| ()),
        Err(XdpPacketIoSetupError::ZeroMtu(WAN))
    );
    let draining = kernel();
    let mut engine = engine(&draining, 0x5698);
    let _ = engine.drain(0).expect("drain");
    let config = XdpPortConfig::for_test(LAN, 0, NegotiatedMode::Copy, MTU, draining.origin());
    assert_eq!(
        XdpPacketIo::new([XdpPort::new(config, engine)]).map(|_| ()),
        Err(XdpPacketIoSetupError::EngineDraining(LAN))
    );

    // Given out of order, kept sorted by IfId; lookups by IfId only.
    let (lan, wan) = (kernel(), kernel());
    let io =
        XdpPacketIo::new([port(&wan, WAN, 7, 9_000), port(&lan, LAN, 3, MTU)]).expect("adapter");
    assert_eq!(io.port_count(), 2);
    assert_eq!(io.interfaces().collect::<Vec<_>>(), [LAN, WAN]);
    let wan_config = io.port_config(WAN).expect("WAN");
    assert_eq!((wan_config.queue(), wan_config.mtu()), (7, 9_000));
    assert_eq!(wan_config.max_frame_len(), 9_014);
    // The enforced bound is capped by the frame capacity.
    let stats = io.port_stats(WAN).expect("WAN stats");
    assert_eq!(stats.max_frame, FRAME_SIZE - HEADROOM as u32);
    assert_eq!(io.port_stats(LAN).expect("LAN").max_frame, MTU + 14);
    assert_eq!(io.port_config(IfId(9)), None);
    assert!(io.engine(IfId(9)).is_none());
}

#[test]
fn cross_port_forward_copies_into_the_egress_generated_pool() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    let topology = topology();
    let snapshot = snapshot(&topology);
    let original = ipv4_frame(98, 64);
    let rx_address = deliver(&lan, &original);

    let report = forward_batch(io.receive(8).expect("receive"), &snapshot, &mut NoTrace);
    assert!(report.invariants_hold(), "{report:?}");
    assert_eq!(report.received, 1);
    assert_eq!(report.completion.tx_accepted, 1);
    assert_eq!(report.completion.error, None);

    // Nothing left the ingress port; the RX frame is free again.
    assert_eq!(lan.tx_pending(), 0);
    let lan_engine = io.engine(LAN).expect("LAN");
    assert_eq!(lan_engine.counters().rx_recycled, 1);
    assert_eq!(lan_engine.frame_accounting().leased, 0);
    assert_eq!(lan_engine.tx_inflight(), 0);
    // The egress transmits a generated-pool frame of its own UMEM.
    let sent = transmit_all(&wan);
    assert_eq!(sent.len(), 1);
    let (descriptor, bytes) = &sent[0];
    assert!(frame_of(descriptor.address) >= RX_FRAMES, "generated pool");
    assert_eq!(descriptor.address % u64::from(FRAME_SIZE), HEADROOM);
    assert_eq!(descriptor.len as usize, original.len());
    assert_eq!(&bytes[0..6], &SERVER_MAC.0, "next-hop MAC");
    assert_eq!(&bytes[6..12], &WAN_MAC.0, "egress MAC");
    assert_eq!(bytes[22], 63, "TTL decremented");
    assert_eq!(&bytes[34..], &original[34..], "payload copied exactly");
    let _ = rx_address;

    let stats = io.port_stats(WAN).expect("WAN").counters;
    assert_eq!(stats.cross_port_copies, 1);
    assert_eq!(stats.generated_committed, 1);
    assert_eq!(stats.forwarded_in_place, 0);
    assert_eq!(io.service().expect("service"), 1);
    let wan_engine = io.engine(WAN).expect("WAN");
    assert_eq!(wan_engine.generated_free_frames(), FRAMES - RX_FRAMES);
    assert_eq!(wan_engine.generated_counters().generated_completed, 1);
    audit(&io);
    assert!(io.try_publication_quiescence().is_ok());
}

#[test]
fn same_port_forward_transmits_the_received_frame_in_place() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    let address = deliver(&lan, &ipv4_frame(60, 9));
    {
        let mut batch = io.receive(1).expect("receive");
        let mut packet = batch.next_packet().expect("lease");
        assert_eq!(packet.ingress(), LAN);
        packet.bytes_mut()[0] = 0xee;
        packet.commit(LAN);
        let completion = batch.finish();
        assert_eq!((completion.tx_accepted, completion.recycled), (1, 0));
    }
    let sent = transmit_all(&lan);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0.address, address, "the same UMEM frame");
    assert_eq!(sent[0].1[0], 0xee, "rewritten in place");
    assert_eq!(wan.tx_pending(), 0);
    let counters = io.port_stats(LAN).expect("LAN").counters;
    assert_eq!(
        (counters.forwarded_in_place, counters.cross_port_copies),
        (1, 0)
    );
    io.service().expect("service");
    audit(&io);
}

#[test]
fn rx_merges_ports_with_a_rotating_start_under_one_budget() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    for marker in 1..=3_u8 {
        let mut bytes = ipv4_frame(60, 64);
        bytes[59] = marker;
        deliver(&lan, &bytes);
        bytes[59] = 0x10 + marker;
        deliver(&wan, &bytes);
    }
    let order = |io: &mut XdpPacketIo<'_>, budget| {
        let mut batch = io.receive(budget).expect("receive");
        let mut seen = Vec::new();
        while let Some(mut packet) = batch.next_packet() {
            seen.push((packet.ingress(), packet.bytes_mut()[59]));
            drop(packet);
        }
        assert_eq!(batch.finish().recycled, seen.len());
        seen
    };
    // First batch starts at LAN (sorted first) and stops at the budget.
    assert_eq!(
        order(&mut io, 4),
        [(LAN, 1), (LAN, 2), (LAN, 3), (WAN, 0x11)]
    );
    // The next batch starts at WAN, so LAN's new frame comes last.
    let mut bytes = ipv4_frame(60, 64);
    bytes[59] = 4;
    deliver(&lan, &bytes);
    assert_eq!(order(&mut io, 8), [(WAN, 0x12), (WAN, 0x13), (LAN, 4)]);
    assert!(order(&mut io, 8).is_empty());
    audit(&io);
}

#[test]
fn tx_back_pressure_is_a_rejection_without_an_error() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    // Eight in-place frames fill LAN's TX in-flight bound (the TX capacity).
    for _ in 0..RING {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    assert_eq!(commit_all(&mut io, 8, LAN), (8, 8, 0));
    let lan_free = io.engine(LAN).expect("LAN").frame_accounting().free;
    // Two more are refused as back-pressure and recycled at once.
    io.service().expect("service");
    for _ in 0..2 {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    assert_eq!(commit_all(&mut io, 8, LAN), (2, 0, 2));
    let lan_stats = io.port_stats(LAN).expect("LAN").counters;
    assert_eq!(lan_stats.tx_blocked, 2);
    assert!(lan_stats.tx_ring_full + lan_stats.tx_inflight_limited >= 2);
    let accounting = io.engine(LAN).expect("LAN").frame_accounting();
    assert_eq!(accounting.tx_handoffs, 0);
    assert_eq!(accounting.leased, 0);
    assert!(accounting.free + accounting.fill_in_kernel >= lan_free);

    // Cross-port into a full WAN ring: the copy is cancelled back to the
    // WAN generated pool and the LAN source frame is recycled.
    {
        let mut batch = io.begin_generated(WAN);
        for _ in 0..RING {
            batch.allocate(60).expect("generated").commit();
        }
        assert_eq!(batch.finish().accepted, 8);
    }
    let generated_free = io.engine(WAN).expect("WAN").generated_free_frames();
    deliver(&lan, &ipv4_frame(60, 64));
    assert_eq!(commit_all(&mut io, 8, WAN), (1, 0, 1));
    let wan_engine = io.engine(WAN).expect("WAN");
    assert_eq!(wan_engine.generated_free_frames(), generated_free);
    assert_eq!(wan_engine.tx_handoffs_outstanding(), 0);
    assert_eq!(io.port_stats(WAN).expect("WAN").counters.tx_blocked, 1);

    // A generated commit into the full ring is rejected, not an error.
    let completion = {
        let mut batch = io.begin_generated(WAN);
        batch.allocate(60).expect("generated").commit();
        batch.finish()
    };
    assert!(completion.invariants_hold());
    assert_eq!((completion.accepted, completion.rejected), (0, 1));
    assert_eq!(completion.error, None);
    assert_eq!(
        io.port_stats(WAN)
            .expect("WAN")
            .counters
            .generated_tx_blocked,
        1
    );
    // Draining the kernel side lets everything through again.
    transmit_all(&lan);
    transmit_all(&wan);
    io.service().expect("service");
    audit(&io);
    assert!(io.try_publication_quiescence().is_ok());
}

#[test]
fn tx_longer_than_mtu_plus_ethernet_header_is_refused_before_any_descriptor() {
    let (lan, wan) = (kernel(), kernel());
    let mut io =
        XdpPacketIo::new([port(&lan, LAN, 0, MTU), port(&wan, WAN, 0, 100)]).expect("adapter");
    // In place on WAN: 114 bytes fit, 115 do not.
    deliver(&wan, &ipv4_frame(114, 64));
    deliver(&wan, &ipv4_frame(115, 64));
    assert_eq!(commit_all(&mut io, 8, WAN), (2, 1, 1));
    // Cross-port LAN → WAN: the same bound, checked before any allocation.
    deliver(&lan, &ipv4_frame(115, 64));
    deliver(&lan, &ipv4_frame(114, 64));
    assert_eq!(commit_all(&mut io, 8, WAN), (2, 1, 1));
    let sent = transmit_all(&wan);
    assert_eq!(
        sent.iter().map(|(d, _)| d.len).collect::<Vec<_>>(),
        [114, 114]
    );
    let counters = io.port_stats(WAN).expect("WAN").counters;
    assert_eq!(counters.tx_over_mtu, 2);
    assert_eq!(counters.generated_allocated, 1, "only the fitting copy");
    // Generated: the bound maps to FrameTooLarge.
    {
        let mut batch = io.begin_generated(WAN);
        assert!(matches!(
            batch.allocate(115),
            Err(GeneratedAllocationError::FrameTooLarge)
        ));
        batch.allocate(114).expect("fits").cancel();
        let completion = batch.finish();
        assert!(completion.invariants_hold());
        assert_eq!((completion.failed, completion.cancelled), (1, 1));
    }
    assert_eq!(
        io.port_stats(WAN).expect("WAN").counters.generated_over_mtu,
        1
    );
    io.service().expect("service");
    audit(&io);
}

#[test]
fn generated_refusals_map_to_core_allocation_errors() {
    // A generated pool smaller than the TX in-flight bound can run dry.
    let generated = 4;
    let (lan, wan) = (kernel(), kernel_with(RX_FRAMES, generated));
    let mut io = adapter(&lan, &wan);
    let completion = {
        let mut batch = io.begin_generated(WAN);
        assert!(matches!(
            batch.allocate(0),
            Err(GeneratedAllocationError::ZeroLength)
        ));
        // Below an Ethernet header: the nearest core variant.
        assert!(matches!(
            batch.allocate(13),
            Err(GeneratedAllocationError::FrameTooLarge)
        ));
        assert!(matches!(
            batch.allocate(1_515),
            Err(GeneratedAllocationError::FrameTooLarge)
        ));
        for _ in 0..generated {
            batch.allocate(42).expect("generated").commit();
        }
        assert!(matches!(
            batch.allocate(42),
            Err(GeneratedAllocationError::Unavailable)
        ));
        batch.finish()
    };
    assert!(completion.invariants_hold(), "{completion:?}");
    assert_eq!(completion.failed, 4);
    assert_eq!(completion.accepted, generated as usize);
    assert_eq!(completion.rejected, 0);
    assert_eq!(completion.error, None);
    let engine = io.engine(WAN).expect("WAN").generated_counters();
    assert_eq!(engine.generated_rejected_total(), 2, "zero and runt");

    // An unknown egress allocates nothing and reports the IfId.
    let completion = {
        let mut batch = io.begin_generated(IfId(42));
        assert!(matches!(
            batch.allocate(42),
            Err(GeneratedAllocationError::Unavailable)
        ));
        batch.finish()
    };
    assert!(completion.invariants_hold());
    assert_eq!(completion.error, None, "not a backend fault");
    assert_eq!(io.backend_stats().generated_unknown_egress, 1);
    transmit_all(&wan);
    io.service().expect("service");
    audit(&io);
}

#[test]
fn quiescence_reaps_first_and_defers_only_on_in_flight_tx() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    assert!(io.try_publication_quiescence().is_ok(), "fresh adapter");
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    // Unlent RX frames carry no publication authority.
    deliver(&lan, &ipv4_frame(60, 64));
    drop(io.receive(0).expect("zero budget"));
    assert!(io.try_publication_quiescence().is_ok());

    // One in place, one copied from WAN: both in flight on LAN.
    deliver(&wan, &ipv4_frame(60, 64));
    assert_eq!(commit_all(&mut io, 8, LAN), (2, 2, 0));
    let Err(error) = io.try_publication_quiescence() else {
        panic!("in-flight TX must defer the publication");
    };
    assert_eq!(
        error,
        XdpQuiescenceError::TxInFlight {
            interface: LAN,
            frames: 2
        }
    );
    assert_eq!(
        XdpPacketIo::quiescence_error_disposition(&error),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    // The kernel completes; the quiescence check itself reaps it.
    transmit_all(&lan);
    assert!(io.try_publication_quiescence().is_ok());
    assert_eq!(io.engine(LAN).expect("LAN").tx_inflight(), 0);

    // A drain stops the adapter for good.
    deliver(&lan, &ipv4_frame(60, 64));
    assert_eq!(commit_all(&mut io, 8, LAN), (1, 1, 0));
    let report = io.drain(1).expect("drain");
    assert_eq!(report.tx_in_flight, 1);
    assert!(!report.is_drained());
    transmit_all(&lan);
    let report = io.drain(1).expect("drain");
    assert!(report.is_drained(), "{report:?}");
    assert_eq!(report.completed, 1);
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::Stop
    );
    let Err(error) = io.try_publication_quiescence() else {
        panic!("a drained adapter is stopped");
    };
    assert_eq!(error, XdpQuiescenceError::Stopped);
    assert_eq!(
        XdpPacketIo::quiescence_error_disposition(&error),
        PublicationQuiescenceDisposition::Stop
    );
    assert!(matches!(io.receive(8), Err(XdpIoError::Stopped)));
    let completion = {
        let mut batch = io.begin_generated(LAN);
        assert!(batch.allocate(60).is_err());
        batch.finish()
    };
    assert_eq!(completion.error, Some(XdpIoError::Stopped));
    assert!(io.backend_stats().stopped);
    audit(&io);
}

#[test]
fn forgotten_leases_are_reclaimed_by_their_batch() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    deliver(&lan, &ipv4_frame(60, 64));
    deliver(&lan, &ipv4_frame(60, 64));
    {
        let mut batch = io.receive(8).expect("receive");
        std::mem::forget(batch.next_packet().expect("first"));
        // The next lend reclaims the forgotten one first.
        batch
            .next_packet()
            .expect("second")
            .recycle(ruster_core::DropReason::RouteMiss);
        let completion = batch.finish();
        assert_eq!(completion.recycled, 1, "a reclaimed lease is not recycled");
    }
    deliver(&lan, &ipv4_frame(60, 64));
    {
        let mut batch = io.receive(8).expect("receive");
        std::mem::forget(batch.next_packet().expect("lease"));
        drop(batch);
    }
    {
        let mut batch = io.begin_generated(WAN);
        std::mem::forget(batch.allocate(60).expect("generated"));
        let completion = batch.finish();
        assert!(completion.invariants_hold(), "{completion:?}");
        assert_eq!(completion.abandoned, 1);
    }
    assert_eq!(
        io.port_stats(LAN).expect("LAN").counters.leases_reclaimed,
        2
    );
    assert_eq!(
        io.port_stats(WAN).expect("WAN").counters.leases_reclaimed,
        1
    );
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    assert!(io.try_publication_quiescence().is_ok());
    audit(&io);
}

#[test]
fn kick_policy_settles_owed_tx_and_reports_only_genuine_failures() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    // Need-wakeup clear (a zero-copy driver that consumes by itself): TX in
    // flight is owed but never kicked.
    for _ in 0..3 {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    assert_eq!(commit_all(&mut io, 8, LAN), (3, 3, 0));
    assert_eq!(lan.kicks(KickRing::Tx), 0, "NotRequired: no kick");
    let stats = io.port_stats(LAN).expect("LAN");
    assert!(stats.kick_owed);
    assert_eq!(io.backend_stats().kick_owed_ports, 1);
    // The kernel asks: the next settle kicks within its budget,
    // ceil(3 / 32) + 2 = 3 kicks, while nothing is consumed.
    lan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    io.service().expect("service");
    assert_eq!(lan.kicks(KickRing::Tx), 3);
    let counters = io.port_stats(LAN).expect("LAN").counters;
    assert_eq!(counters.kick_budget_exhausted, 1);
    assert_eq!(counters.tx_kicks, 3);
    // Nothing published on WAN: never kicked.
    assert_eq!(wan.kicks(KickRing::Tx), 0);
    // Once the kernel completes, the next settle clears the debt.
    transmit_all(&lan);
    io.service().expect("service");
    assert!(!io.port_stats(LAN).expect("LAN").kick_owed);
    let kicks = lan.kicks(KickRing::Tx);
    io.service().expect("service");
    assert_eq!(lan.kicks(KickRing::Tx), kicks, "no debt, no kick");

    // A genuine failure (EINVAL) is the batch error; the frame stays in
    // flight and the kick stays owed.
    deliver(&lan, &ipv4_frame(60, 64));
    lan.fail_next_kick(Some(22));
    {
        let mut batch = io.receive(8).expect("receive");
        batch.next_packet().expect("lease").commit(LAN);
        let completion = batch.finish();
        assert!(completion.invariants_hold());
        assert_eq!(completion.tx_accepted, 1);
        assert!(matches!(
            completion.error,
            Some(XdpIoError::Kick {
                interface: LAN,
                error: KickError::Errno(22),
            })
        ));
    }
    assert_eq!(io.engine(LAN).expect("LAN").tx_inflight(), 1);
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo,
        "not sticky"
    );
    // A generated session kicks its egress the same way.
    wan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    {
        let mut batch = io.begin_generated(WAN);
        batch.allocate(42).expect("generated").commit();
        assert_eq!(batch.finish().error, None);
    }
    assert!(wan.kicks(KickRing::Tx) >= 1);
    // A finished batch is settled once: a kernel that consumes nothing
    // gets exactly one settle's budget of kicks, not a second from the
    // batch's drop.
    transmit_all(&wan);
    io.service().expect("service");
    deliver(&wan, &ipv4_frame(60, 64));
    let before = wan.kicks(KickRing::Tx);
    assert_eq!(commit_all(&mut io, 8, WAN), (1, 1, 0));
    assert_eq!(
        wan.kicks(KickRing::Tx) - before,
        1_u32.div_ceil(KICK_TX_BATCH) + KICK_SLACK
    );
    // Fill wakeup requests are answered by receive.
    lan.set_fill_flags(XDP_RING_NEED_WAKEUP);
    drop(io.receive(8).expect("receive"));
    assert!(lan.kicks(KickRing::Fill) >= 1);
    transmit_all(&lan);
    transmit_all(&wan);
    io.service().expect("service");
    audit(&io);
}

/// A port whose rings hold 64 entries and whose RX pool can fill them.
fn big_kernel() -> ScriptedKernel {
    ScriptedKernel::with_tx(
        entries(RingName::Fill, 64),
        entries(RingName::Rx, 64),
        entries(RingName::Tx, 64),
        entries(RingName::Completion, 64),
        UmemConfig::new(144, FRAME_SIZE, 0, 128, 16, 0).expect("UMEM"),
    )
}

fn big_port(kernel: &ScriptedKernel, interface: IfId) -> XdpPort<'_> {
    let engine = RxFillEngine::new(
        kernel.take_datapath().expect("first take"),
        UmemDomainId::new(NonZeroU128::new(0x5700 + u128::from(interface.0)).expect("nonzero")),
        RxFillConfig::new(NonZeroU32::new(64).expect("nonzero")),
    )
    .expect("engine");
    XdpPort::new(
        XdpPortConfig::for_test(interface, 0, NegotiatedMode::Copy, MTU, kernel.origin()),
        engine,
    )
}

#[test]
fn copy_mode_batch_above_tx_batch_size_completes_without_more_traffic() {
    let (lan, wan) = (big_kernel(), kernel());
    let mut io = XdpPacketIo::new([big_port(&lan, LAN), port(&wan, WAN, 0, MTU)]).expect("adapter");
    // Linux v6.8 copy mode: at most 32 descriptors per sendto, EAGAIN while
    // more remain; the flag stays set.
    lan.set_copy_transmit(Some(KICK_TX_BATCH));
    lan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    for _ in 0..60 {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    assert_eq!(commit_all(&mut io, 64, LAN), (60, 60, 0));
    // The finish alone pushed all 60 out: two kicks, nothing in flight.
    assert_eq!(lan.transmitted(), 60);
    assert_eq!(lan.kicks(KickRing::Tx), 2);
    let stats = io.port_stats(LAN).expect("LAN");
    assert_eq!(stats.counters.tx_inflight, 0);
    assert_eq!(stats.counters.tx_completed, 60);
    assert_eq!(stats.counters.kicks_deferred, 1, "the EAGAIN round");
    assert!(!stats.kick_owed);
    assert!(io.try_publication_quiescence().is_ok());
    audit(&io);
}

#[test]
fn link_flap_recovers_without_new_traffic() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    for kernel in [&lan, &wan] {
        kernel.set_copy_transmit(Some(KICK_TX_BATCH));
        kernel.set_tx_flags(XDP_RING_NEED_WAKEUP);
    }
    wan.set_link_down(true);
    // A forwarded copy and a generated ARP frame while WAN is down.
    deliver(&lan, &ipv4_frame(60, 64));
    {
        let mut batch = io.receive(8).expect("receive");
        batch.next_packet().expect("lease").commit(WAN);
        let completion = batch.finish();
        assert_eq!(completion.tx_accepted, 1);
        assert_eq!(completion.error, None, "link down is not an error");
    }
    {
        let mut batch = io.begin_generated(WAN);
        batch.allocate(42).expect("generated").commit();
        assert_eq!(batch.finish().error, None);
    }
    let stats = io.port_stats(WAN).expect("WAN");
    assert!(stats.link_down && stats.kick_owed, "{stats:?}");
    assert_eq!(stats.counters.tx_inflight, 2);
    assert!(stats.counters.kicks_link_down >= 2);
    assert_eq!(io.backend_stats().link_down_ports, 1);
    assert!(matches!(
        io.try_publication_quiescence(),
        Err(XdpQuiescenceError::TxInFlight {
            interface: WAN,
            frames: 2
        })
    ));
    // The link returns; no new traffic. The quiescence check itself
    // settles the owed kick and becomes ready.
    wan.set_link_down(false);
    assert!(io.try_publication_quiescence().is_ok());
    assert_eq!(wan.transmitted(), 2);
    let stats = io.port_stats(WAN).expect("WAN");
    assert!(!stats.link_down && !stats.kick_owed);
    assert_eq!(
        stats.counters.generated_completed, 2,
        "both pool frames back"
    );
    // The same recovery through idle receives, with the debt kept across
    // a batch that ran while the link was still down.
    wan.set_link_down(true);
    {
        let mut batch = io.begin_generated(WAN);
        batch.allocate(42).expect("generated").commit();
        let _ = batch.finish();
    }
    drop(io.receive(0).expect("idle receive while down"));
    assert!(io.port_stats(WAN).expect("WAN").kick_owed);
    wan.set_link_down(false);
    drop(io.receive(0).expect("idle receive"));
    assert_eq!(wan.transmitted(), 3);
    assert_eq!(io.engine(WAN).expect("WAN").tx_inflight(), 0);
    audit(&io);
}

#[test]
fn generated_reserve_keeps_router_frames_from_cross_port_copies() {
    assert_eq!(generated_reserve(1), 1);
    assert_eq!(generated_reserve(2), 2);
    assert_eq!(generated_reserve(16), 2);
    assert_eq!(generated_reserve(64), 8);
    assert_eq!(generated_reserve(512), 64);
    let (lan, wan) = (big_kernel(), big_kernel());
    let mut io = XdpPacketIo::new([big_port(&lan, LAN), big_port(&wan, WAN)]).expect("adapter");
    assert_eq!(io.port_stats(WAN).expect("WAN").copy_reserve, 2);
    // Sixteen cross-port copies with WAN's kernel not transmitting: the
    // first fourteen take generated frames, the last two are refused.
    for _ in 0..16 {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    assert_eq!(commit_all(&mut io, 64, WAN), (16, 14, 2));
    let wan_engine = io.engine(WAN).expect("WAN");
    assert_eq!(wan_engine.generated_free_frames(), 2);
    let counters = io.port_stats(WAN).expect("WAN").counters;
    assert_eq!(counters.cross_port_copies, 14);
    assert_eq!(counters.cross_port_copy_reserved, 2);
    // Router generation still gets the reserve.
    {
        let mut batch = io.begin_generated(WAN);
        batch.allocate(42).expect("reserved frame").commit();
        batch.allocate(42).expect("reserved frame").commit();
        assert!(matches!(
            batch.allocate(42),
            Err(GeneratedAllocationError::Unavailable)
        ));
        assert_eq!(batch.finish().accepted, 2);
    }
    // begin_generated reaps first: once WAN's kernel completes, the pool
    // is back for the next generated session without any other call.
    while let Some(descriptor) = wan.consume_tx() {
        assert!(wan.produce_completion(descriptor.address));
    }
    {
        let mut batch = io.begin_generated(WAN);
        for _ in 0..3 {
            batch
                .allocate(42)
                .expect("completions reaped by begin_generated")
                .cancel();
        }
        let _ = batch.finish();
    }
    // A pool of 0 to 2 frames is all reserve: refused with several ports.
    // An empty pool would be refused too (its reserve is 0), but
    // `UmemConfig` already refuses zero generated frames.
    assert_eq!(generated_reserve(0), 0);
    assert!(UmemConfig::new(RX_FRAMES, FRAME_SIZE, 0, RX_FRAMES, 0, 0).is_err());
    for frames in [1, 2] {
        let (lan, wan) = (kernel(), kernel_with(RX_FRAMES, frames));
        assert_eq!(
            XdpPacketIo::new([port(&lan, LAN, 0, MTU), port(&wan, WAN, 0, MTU)]).map(|_| ()),
            Err(XdpPacketIoSetupError::GeneratedPoolTooSmall {
                interface: WAN,
                generated_frames: frames,
            })
        );
    }
    // A single port never copies, so its small pool is accepted.
    let alone = kernel_with(RX_FRAMES, 1);
    assert!(XdpPacketIo::new([port(&alone, WAN, 0, MTU)]).is_ok());
    // An empty pool counts as unavailable.
    let (lan, wan) = (kernel(), kernel_with(RX_FRAMES, 3));
    let mut io = adapter(&lan, &wan);
    {
        let mut batch = io.begin_generated(WAN);
        for _ in 0..3 {
            batch.allocate(42).expect("generated").commit();
        }
        let _ = batch.finish();
    }
    deliver(&lan, &ipv4_frame(60, 64));
    assert_eq!(commit_all(&mut io, 8, WAN), (1, 0, 1));
    assert_eq!(
        io.port_stats(WAN)
            .expect("WAN")
            .counters
            .cross_port_copy_unavailable,
        1
    );
    transmit_all(&wan);
    io.service().expect("service");
    audit(&io);
}

#[test]
fn leaked_batches_are_reclaimed_and_keep_their_kick_debt() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    lan.set_copy_transmit(Some(KICK_TX_BATCH));
    lan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    deliver(&lan, &ipv4_frame(60, 64));
    deliver(&lan, &ipv4_frame(60, 64));
    // A whole batch leaked with one frame committed and one still lent.
    {
        let mut batch = io.receive(8).expect("receive");
        batch.next_packet().expect("first").commit(LAN);
        let lent = batch.next_packet().expect("second");
        std::mem::forget(lent);
        std::mem::forget(batch);
    }
    // The leaked lease is reclaimable, so I/O is not skipped.
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    assert!(io.port_stats(LAN).expect("LAN").kick_owed);
    assert_eq!(lan.transmitted(), 0, "no finish ran");
    // The next receive reclaims the lease and pays the kick debt before
    // it lends anything.
    let batch = io.receive(8).expect("receive");
    assert_eq!(lan.transmitted(), 1);
    drop(batch);
    let counters = io.port_stats(LAN).expect("LAN").counters;
    assert_eq!(counters.leases_reclaimed, 1);
    assert_eq!(counters.tx_inflight, 0);
    // A leaked generated batch is reclaimed by the next begin_generated.
    {
        let mut batch = io.begin_generated(WAN);
        std::mem::forget(batch.allocate(42).expect("generated"));
        std::mem::forget(batch);
    }
    let _ = io.begin_generated(LAN).finish();
    assert_eq!(
        io.port_stats(WAN).expect("WAN").counters.leases_reclaimed,
        1
    );
    assert!(io.try_publication_quiescence().is_ok());
    audit(&io);
}

#[test]
fn stranded_engine_leases_and_handoffs_skip_io() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    deliver(&lan, &ipv4_frame(60, 64));
    deliver(&lan, &ipv4_frame(60, 64));
    // Engine-level leaks no adapter path produces: a handoff and a frame.
    {
        let engine = io.engine_mut_for_test(LAN);
        let mut batch = engine.poll(8).expect("poll");
        let handoff = batch.next_frame().expect("first").stage_tx();
        std::mem::forget(handoff);
    }
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::SkipIo
    );
    let error = io
        .try_publication_quiescence()
        .map(|_| ())
        .expect_err("stranded");
    assert_eq!(
        error,
        XdpQuiescenceError::HandoffOutstanding {
            interface: LAN,
            frames: 1
        }
    );
    assert_eq!(
        XdpPacketIo::quiescence_error_disposition(&error),
        PublicationQuiescenceDisposition::SkipIo
    );
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    deliver(&wan, &ipv4_frame(60, 64));
    {
        let engine = io.engine_mut_for_test(WAN);
        let mut batch = engine.poll(8).expect("poll");
        std::mem::forget(batch.next_frame().expect("frame"));
    }
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::SkipIo
    );
    let error = io
        .try_publication_quiescence()
        .map(|_| ())
        .expect_err("stranded");
    assert_eq!(
        error,
        XdpQuiescenceError::LeaseOutstanding {
            interface: WAN,
            frames: 1
        }
    );
    assert_eq!(
        XdpPacketIo::quiescence_error_disposition(&error),
        PublicationQuiescenceDisposition::SkipIo
    );
}

#[test]
fn budget_zero_ports_still_reap_and_refill() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    // WAN: a frame in flight committed at engine level (no kick debt), then
    // completed by the kernel, and three Fill frames taken by the kernel.
    {
        let engine = io.engine_mut_for_test(WAN);
        let report = engine.allocate_generated(42).expect("generated").commit();
        assert_eq!(report.map(|report| report.submitted()).ok(), Some(1));
    }
    transmit_all(&wan);
    for _ in 0..3 {
        let _ = wan.consume_fill();
    }
    let published = io.port_stats(WAN).expect("WAN").counters.fill_published;
    // LAN (first this batch) uses the whole budget of one.
    deliver(&lan, &ipv4_frame(60, 64));
    deliver(&lan, &ipv4_frame(60, 64));
    {
        let mut batch = io.receive(1).expect("receive");
        batch
            .next_packet()
            .expect("lease")
            .recycle(ruster_core::DropReason::RouteMiss);
        assert!(batch.next_packet().is_none(), "budget spent");
        let _ = batch.finish();
    }
    let wan_stats = io.port_stats(WAN).expect("WAN").counters;
    assert_eq!(wan_stats.tx_inflight, 0, "reaped by the budget-0 poll");
    assert_eq!(wan_stats.tx_completed, 1);
    assert_eq!(wan_stats.fill_published, published + 3, "refilled");
    audit(&io);
}

#[test]
fn cross_port_submit_fault_stops_the_adapter() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    wan.set_tx_consumer(wan.tx_producer().wrapping_add(RING + 1));
    deliver(&lan, &ipv4_frame(60, 64));
    let completion = {
        let mut batch = io.receive(8).expect("receive");
        batch.next_packet().expect("lease").commit(WAN);
        batch.finish()
    };
    assert!(completion.invariants_hold());
    assert_eq!((completion.tx_accepted, completion.tx_rejected), (0, 1));
    assert!(matches!(
        completion.error,
        Some(XdpIoError::Submit {
            interface: WAN,
            rejection: TxRejection::Ring(_),
        })
    ));
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::Stop
    );
    assert!(matches!(io.receive(8), Err(XdpIoError::Stopped)));
    // Both frames went back to their pools before the stop.
    assert_eq!(io.engine(LAN).expect("LAN").frame_accounting().leased, 0);
    let wan_engine = io.engine(WAN).expect("WAN");
    assert_eq!(wan_engine.generated_free_frames(), FRAMES - RX_FRAMES);
    assert_eq!(wan_engine.tx_handoffs_outstanding(), 0);
}

#[test]
fn unknown_egress_and_high_water_are_counted_exactly() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    deliver(&lan, &ipv4_frame(60, 64));
    assert_eq!(commit_all(&mut io, 8, IfId(77)), (1, 0, 1));
    assert_eq!(
        io.port_stats(LAN).expect("LAN").counters.tx_unknown_egress,
        1
    );
    // High-water is a maximum over ports, not a sum: LAN 3, WAN 1.
    for _ in 0..3 {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    assert_eq!(commit_all(&mut io, 8, LAN), (3, 3, 0));
    deliver(&wan, &ipv4_frame(60, 64));
    assert_eq!(commit_all(&mut io, 8, WAN), (1, 1, 0));
    let stats = io.backend_stats().counters;
    assert_eq!(stats.tx_inflight_highwater, 3);
    assert_eq!(stats.tx_inflight, 4, "the gauge is a sum");
    transmit_all(&lan);
    transmit_all(&wan);
    io.service().expect("service");
    audit(&io);
}

#[test]
fn kernel_statistics_and_ring_gauges_reach_the_stats() {
    let (lan, wan) = (kernel(), kernel());
    let io = adapter(&lan, &wan);
    lan.set_statistics(Some(XdpStatistics {
        rx_dropped: 1,
        rx_invalid_descriptors: 2,
        tx_invalid_descriptors: 3,
        rx_ring_full: 4,
        rx_fill_ring_empty_descriptors: 5,
        tx_ring_empty_descriptors: 6,
    }));
    deliver(&wan, &ipv4_frame(60, 64));
    let lan_stats = io.port_stats(LAN).expect("LAN");
    assert_eq!(lan_stats.kernel.map(|k| k.tx_invalid_descriptors), Some(3));
    assert_eq!(io.port_stats(WAN).expect("WAN").kernel, None);
    let stats = io.backend_stats();
    assert_eq!(stats.kernel_stats_ports, 1);
    let counters = stats.counters;
    assert_eq!(
        [
            counters.kernel_rx_dropped,
            counters.kernel_rx_invalid_descs,
            counters.kernel_tx_invalid_descs,
            counters.kernel_rx_ring_full,
            counters.kernel_rx_fill_ring_empty_descs,
            counters.kernel_tx_ring_empty_descs,
        ],
        [1, 2, 3, 4, 5, 6]
    );
    // Fill: 8 published per port, one taken by WAN's kernel; RX: one
    // descriptor WAN's engine has not read.
    assert_eq!(counters.fill_ring_occupancy, 15);
    assert_eq!(counters.rx_ring_occupancy, 1);
    assert_eq!(counters.tx_ring_unconsumed, 0);
}

#[test]
fn a_port_config_of_another_session_is_refused() {
    let (first, second) = (kernel(), kernel());
    let engine = engine(&second, 0x5690);
    let config = XdpPortConfig::for_test(LAN, 0, NegotiatedMode::Copy, MTU, first.origin());
    assert_eq!(
        XdpPacketIo::new([XdpPort::new(config, engine)]).map(|_| ()),
        Err(XdpPacketIoSetupError::SessionMismatch(LAN))
    );
}

#[test]
#[should_panic(expected = "a raw lease is used only on the engine that issued it")]
fn a_raw_lease_of_another_engine_is_refused() {
    let (first, second) = (kernel(), kernel());
    // The same domain on both: identical tokens, only the engine differs.
    let mut mine = engine(&first, 0x5691);
    let mut other = engine(&second, 0x5691);
    deliver(&second, &ipv4_frame(60, 64));
    drop(other.poll(8).expect("poll"));
    let lease = other.lease_pending().expect("lease");
    assert_ne!(lease.engine(), 0);
    let _ = mine.lease_bytes_mut(&lease);
}

#[test]
fn completion_lag_after_consumption_does_not_burn_kicks() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    // Copy-mode transmit that consumes at once but completes late (TX
    // interrupt coalescing on a NIC, or zero copy).
    lan.set_copy_transmit(Some(KICK_TX_BATCH));
    lan.set_defer_completions(true);
    lan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    for _ in 0..RING {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    assert_eq!(commit_all(&mut io, 8, LAN), (8, 8, 0));
    // One kick consumed all eight; nothing more is kicked while only the
    // completions lag, across the finish, the drop, and later settles.
    assert_eq!(lan.kicks(KickRing::Tx), 1);
    for _ in 0..4 {
        io.service().expect("service");
        drop(io.receive(8).expect("receive"));
    }
    assert_eq!(lan.kicks(KickRing::Tx), 1);
    let stats = io.port_stats(LAN).expect("LAN");
    assert_eq!(stats.counters.kick_budget_exhausted, 0);
    assert_eq!(stats.counters.tx_inflight, 8);
    assert!(stats.kick_owed, "owed until the completions arrive");
    // Blocked submissions while the in-flight bound is full relieve at most
    // once per batch and do not kick either.
    for _ in 0..4 {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    assert_eq!(commit_all(&mut io, 8, LAN), (4, 0, 4));
    assert_eq!(lan.kicks(KickRing::Tx), 1);
    assert_eq!(
        io.port_stats(LAN)
            .expect("LAN")
            .counters
            .kick_budget_exhausted,
        0
    );
    // The completions arrive; the next settle reaps them all.
    assert_eq!(lan.release_deferred_completions(), 8);
    io.service().expect("service");
    let stats = io.port_stats(LAN).expect("LAN");
    assert_eq!(stats.counters.tx_inflight, 0);
    assert!(!stats.kick_owed);
    audit(&io);
}

#[test]
fn a_blocked_port_is_relieved_once_per_batch() {
    // TX ring of 4 and copy-mode transmit: the first refusal kicks and
    // reaps, freeing the ring for the next four commits; the second
    // refusal of the same batch is left to the finish.
    let make = || {
        ScriptedKernel::with_tx(
            entries(RingName::Fill, 16),
            entries(RingName::Rx, 16),
            entries(RingName::Tx, 4),
            entries(RingName::Completion, 4),
            UmemConfig::new(40, FRAME_SIZE, 0, 24, 16, 0).expect("UMEM"),
        )
    };
    let (lan, wan) = (make(), kernel());
    let engine = RxFillEngine::new(
        lan.take_datapath().expect("first take"),
        UmemDomainId::new(NonZeroU128::new(0x5781).expect("nonzero")),
        RxFillConfig::new(NonZeroU32::new(16).expect("nonzero")),
    )
    .expect("engine");
    let mut io = XdpPacketIo::new([
        XdpPort::new(
            XdpPortConfig::for_test(LAN, 0, NegotiatedMode::Copy, MTU, lan.origin()),
            engine,
        ),
        port(&wan, WAN, 0, MTU),
    ])
    .expect("adapter");
    lan.set_copy_transmit(Some(KICK_TX_BATCH));
    lan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    for _ in 0..12 {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    // 4 accepted, 1 refused (relieve: kick + reap), 4 accepted, 3 refused.
    assert_eq!(commit_all(&mut io, 16, LAN), (12, 8, 4));
    assert_eq!(lan.transmitted(), 8);
    assert_eq!(lan.kicks(KickRing::Tx), 2, "one relieve, one finish");
    let counters = io.port_stats(LAN).expect("LAN").counters;
    assert_eq!(counters.tx_blocked, 4);
    assert_eq!(counters.kick_budget_exhausted, 0);
    assert_eq!(counters.tx_inflight, 0);
    audit(&io);
}

/// #300 follow-up: the once-per-batch relieve is re-armed by every
/// `receive` and every `begin_generated`, so a later batch that hits the
/// same full ring relieves it again instead of refusing everything after
/// the first four commits.
#[test]
fn relieve_is_rearmed_for_every_rx_and_generated_batch() {
    let lan = ScriptedKernel::with_tx(
        entries(RingName::Fill, 16),
        entries(RingName::Rx, 16),
        entries(RingName::Tx, 4),
        entries(RingName::Completion, 4),
        UmemConfig::new(40, FRAME_SIZE, 0, 24, 16, 0).expect("UMEM"),
    );
    let wan = kernel();
    let engine = RxFillEngine::new(
        lan.take_datapath().expect("first take"),
        UmemDomainId::new(NonZeroU128::new(0x5782).expect("nonzero")),
        RxFillConfig::new(NonZeroU32::new(16).expect("nonzero")),
    )
    .expect("engine");
    let mut io = XdpPacketIo::new([
        XdpPort::new(
            XdpPortConfig::for_test(LAN, 0, NegotiatedMode::Copy, MTU, lan.origin()),
            engine,
        ),
        port(&wan, WAN, 0, MTU),
    ])
    .expect("adapter");
    lan.set_copy_transmit(Some(KICK_TX_BATCH));
    lan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    for round in 1..=2_u32 {
        for _ in 0..12 {
            deliver(&lan, &ipv4_frame(60, 64));
        }
        // 4 accepted, 1 refused (relieve), 4 accepted, 3 refused: one
        // relieve kick and one finish kick per batch.
        assert_eq!(commit_all(&mut io, 16, LAN), (12, 8, 4), "batch {round}");
        assert_eq!(lan.kicks(KickRing::Tx), 2 * round, "batch {round}");
    }
    // A generated session on the same port, right after an RX batch that
    // relieved: its first blocked commit relieves again.
    {
        let mut batch = io.begin_generated(LAN);
        for _ in 0..12 {
            batch.allocate(42).expect("generated").commit();
        }
        let completion = batch.finish();
        assert_eq!(
            (completion.accepted, completion.rejected),
            (8, 4),
            "{completion:?}"
        );
        assert_eq!(completion.error, None);
    }
    assert_eq!(lan.kicks(KickRing::Tx), 6, "one relieve, one finish");
    let counters = io.port_stats(LAN).expect("LAN").counters;
    assert_eq!(counters.tx_blocked, 8);
    assert_eq!(counters.generated_tx_blocked, 4);
    assert_eq!(counters.tx_inflight, 0);
    audit(&io);
}

/// #300 follow-up: `finish` consumes the generated batch, whose `Drop`
/// then runs; it must not settle a second time. A batch dropped without
/// `finish` settles exactly once from `Drop`.
#[test]
fn a_generated_batch_is_settled_once_by_finish_or_by_drop() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    // The kernel asks for kicks and consumes nothing, so every settle
    // spends its whole budget: ceil(in_flight / 32) + 2 kicks.
    wan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    let budget = |in_flight: u32| in_flight.div_ceil(KICK_TX_BATCH) + KICK_SLACK;
    {
        let mut batch = io.begin_generated(WAN);
        for _ in 0..2 {
            batch.allocate(42).expect("generated").commit();
        }
        assert_eq!(batch.finish().accepted, 2);
    }
    assert_eq!(wan.kicks(KickRing::Tx), budget(2), "finish only");
    assert_eq!(
        io.port_stats(WAN)
            .expect("WAN")
            .counters
            .kick_budget_exhausted,
        1
    );
    let before = wan.kicks(KickRing::Tx);
    {
        let mut batch = io.begin_generated(WAN);
        batch.allocate(42).expect("generated").commit();
        // Dropped without finish. `begin_generated` already settled the
        // two earlier frames once (their debt is owed across batches).
    }
    let after_begin_and_drop = wan.kicks(KickRing::Tx) - before;
    assert_eq!(after_begin_and_drop, budget(2) + budget(3));
    assert_eq!(
        io.port_stats(WAN)
            .expect("WAN")
            .counters
            .kick_budget_exhausted,
        3
    );
    transmit_all(&wan);
    io.service().expect("service");
    audit(&io);
}

#[test]
fn a_panic_with_a_leaked_lease_only_stops_and_drain_reclaims() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    deliver(&lan, &ipv4_frame(60, 64));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut batch = io.receive(8).expect("receive");
        std::mem::forget(batch.next_packet().expect("lease"));
        panic!("core failed after leaking a lease");
    }));
    assert!(result.is_err());
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::Stop
    );
    // Nothing was reclaimed during the unwind.
    assert_eq!(io.engine(LAN).expect("LAN").frame_accounting().leased, 1);
    let report = io.drain(1).expect("drain");
    assert!(report.is_drained());
    assert_eq!(io.engine(LAN).expect("LAN").frame_accounting().leased, 0);
    assert_eq!(
        io.port_stats(LAN).expect("LAN").counters.leases_reclaimed,
        1
    );
    audit(&io);
}

#[test]
fn a_panic_inside_a_batch_stops_the_adapter() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    deliver(&lan, &ipv4_frame(60, 64));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut batch = io.receive(8).expect("receive");
        let _lease = batch.next_packet().expect("lease");
        panic!("core failed while a frame was lent");
    }));
    assert!(result.is_err());
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::Stop
    );
    // Fail closed, but no frame leaked: the lease was reclaimed.
    assert_eq!(io.engine(LAN).expect("LAN").frame_accounting().leased, 0);
    audit(&io);
}

#[derive(Default)]
struct Fields(Vec<(&'static str, &'static str, FieldValue)>);

impl FieldVisitor for Fields {
    fn field(&mut self, section: &'static str, key: &'static str, value: FieldValue) {
        self.0.push((section, key, value));
    }
}

fn field(fields: &Fields, key: &str) -> FieldValue {
    fields
        .0
        .iter()
        .find(|(_, name, _)| *name == key)
        .map(|(_, _, value)| *value)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

#[test]
fn backend_stats_sum_ports_with_a_fixed_shape_and_allocate_nothing() {
    assert_eq!(<XdpPacketIo<'_> as BackendStats>::NAME, "af_xdp");
    assert_eq!(<XdpPacketIo<'_> as BackendStats>::MODE, BackendMode::Copy);
    let (lan, wan) = (kernel(), kernel());
    let mut io = XdpPacketIo::new([
        port(&lan, LAN, 0, MTU),
        XdpPort::new(
            XdpPortConfig::for_test(WAN, 0, NegotiatedMode::ZeroCopy, MTU, wan.origin()),
            engine(&wan, 0x5699),
        ),
    ])
    .expect("adapter");
    let topology = topology();
    let snapshot = snapshot(&topology);
    deliver(&lan, &ipv4_frame(60, 64));
    deliver(&lan, &ipv4_frame(60, 64));
    // A runt and an out-of-UMEM descriptor are counted by reason.
    deliver(&lan, &[0; 10]);
    assert!(lan.produce_rx(XdpDescriptor {
        address: u64::from(FRAMES * FRAME_SIZE) + 64,
        len: 60,
        options: 0,
    }));
    let report = forward_batch(io.receive(8).expect("receive"), &snapshot, &mut NoTrace);
    assert_eq!(report.completion.tx_accepted, 2);
    wan.set_tx_flags(XDP_RING_NEED_WAKEUP);

    let before = allocation_count();
    let stats = io.backend_stats();
    let wan_stats = io.port_stats(WAN).expect("WAN");
    assert_eq!(allocation_count(), before, "stats allocate nothing");

    assert_eq!(
        (stats.ports, stats.copy_ports, stats.zero_copy_ports),
        (2, 1, 1)
    );
    assert_eq!(stats.mode_label(), "mixed");
    assert_eq!(stats.tx_need_wakeup_ports, 1);
    assert!(wan_stats.tx_need_wakeup);
    let counters = stats.counters;
    assert_eq!(counters.cross_port_copies, 2);
    assert_eq!(counters.rx_packets, 2);
    assert_eq!(counters.rx_invalid, 2);
    assert_eq!(counters.rx_invalid_by_reason[0], 1, "outside UMEM");
    assert_eq!(counters.rx_invalid_by_reason[4], 1, "runt");
    assert_eq!(counters.tx_inflight, 2);
    assert_eq!(counters.generated_inflight, 2);
    assert_eq!(counters.tx_submitted, 2);
    assert_eq!(counters.polls, 2, "one poll per port");
    // The initial refills, then the three Fill frames the kernel used
    // (two packets and the runt) republished by the poll.
    assert_eq!(counters.fill_published, u64::from(2 * RING + 3));

    let mut fields = Fields::default();
    stats.visit_fields(&mut fields);
    let mut again = Fields::default();
    stats.visit_fields(&mut again);
    assert_eq!(fields.0, again.0, "fixed order");
    assert!(fields.0.iter().all(|(section, _, _)| *section == "af_xdp"));
    let mut keys: Vec<_> = fields.0.iter().map(|(_, key, _)| *key).collect();
    let count = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), count, "unique keys");
    assert_eq!(field(&fields, "mode"), FieldValue::Label("mixed"));
    assert_eq!(field(&fields, "cross_port_copies"), FieldValue::Count(2));
    assert_eq!(
        field(&fields, "rx_invalid_exceeds_frame"),
        FieldValue::Count(0)
    );
    assert_eq!(field(&fields, "stopped"), FieldValue::Flag(false));

    let mut port_fields = Fields::default();
    wan_stats.visit_fields(&mut port_fields);
    assert_eq!(field(&port_fields, "mode"), FieldValue::Label("zero_copy"));
    assert_eq!(field(&port_fields, "interface"), FieldValue::Count(2));
    assert_eq!(field(&port_fields, "max_frame"), FieldValue::Count(1_514));
    assert_eq!(
        field(&port_fields, "tx_need_wakeup_now"),
        FieldValue::Flag(true)
    );
    // Shared counter keys: per-port rows carry eight leading facts.
    assert_eq!(port_fields.0.len(), fields.0.len() + 1);

    // Quarantine of a generated frame after TX is counted on its own and
    // in the both-pool total.
    let sent = {
        let mut sent = Vec::new();
        while let Some(descriptor) = wan.consume_tx() {
            sent.push(descriptor);
        }
        sent
    };
    assert!(wan.produce_completion(sent[0].address + 1));
    assert!(wan.produce_completion(sent[1].address));
    io.service().expect("service");
    let counters = io.port_stats(WAN).expect("WAN").counters;
    assert_eq!(counters.generated_quarantined_after_tx, 1);
    assert_eq!(counters.generated_quarantined, 1);
    assert_eq!(counters.frames_quarantined, 1);
    assert_eq!(
        counters.generated_committed,
        counters.generated_completed
            + counters.generated_inflight
            + counters.generated_quarantined_after_tx
    );
    audit(&io);
}

#[test]
fn steady_state_forwarding_and_generation_allocate_nothing() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    let topology = topology();
    let snapshot = snapshot(&topology);
    let frame = ipv4_frame(98, 64);
    let mut hairpin = frame.clone();
    hairpin[0..6].copy_from_slice(&WAN_MAC.0);
    lan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    wan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    let round = |io: &mut XdpPacketIo<'_>| {
        // Two cross-port forwards through core, one in-place commit, one
        // generated frame; then the kernels transmit and complete.
        deliver(&lan, &frame);
        deliver(&lan, &frame);
        let report = forward_batch(io.receive(8).expect("receive"), &snapshot, &mut NoTrace);
        assert_eq!(report.completion.tx_accepted, 2);
        deliver(&wan, &hairpin);
        {
            let mut batch = io.receive(8).expect("receive");
            batch.next_packet().expect("lease").commit(WAN);
            assert_eq!(batch.finish().tx_accepted, 1);
        }
        {
            let mut batch = io.begin_generated(LAN);
            batch.allocate(42).expect("generated").commit();
            assert_eq!(batch.finish().accepted, 1);
        }
        for kernel in [&lan, &wan] {
            while let Some(descriptor) = kernel.consume_tx() {
                assert!(kernel.produce_completion(descriptor.address));
            }
        }
        io.service().expect("service");
        let _ = io.backend_stats();
    };
    for _ in 0..4 {
        round(&mut io);
    }
    let before = allocation_count();
    for _ in 0..32 {
        round(&mut io);
    }
    assert_eq!(allocation_count(), before, "steady state allocates nothing");
    audit(&io);
    assert!(io.try_publication_quiescence().is_ok());
}

#[test]
fn ring_corruption_stops_the_adapter_for_good() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    lan.set_rx_producer(lan.rx_consumer().wrapping_add(RING + 1));
    assert!(matches!(
        io.receive(8),
        Err(XdpIoError::Datapath { interface: LAN, .. })
    ));
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::Stop
    );
    lan.set_rx_producer(lan.rx_consumer());
    assert!(matches!(io.receive(8), Err(XdpIoError::Stopped)));
    assert!(matches!(io.service(), Err(XdpIoError::Stopped)));
}

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
    abi::{XdpDescriptor, XDP_RING_NEED_WAKEUP},
    native_unsafe::{
        heap_kernel::{allocation_count, ScriptedKernel},
        kick::KickRing,
    },
    NegotiatedMode, RingEntries, RingName, RxFillConfig, RxFillEngine, UmemConfig, UmemDomainId,
    XdpIoError, XdpPacketIo, XdpPacketIoSetupError, XdpPort, XdpPortConfig, XdpQuiescenceError,
    XDP_PACKET_HEADROOM,
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
        XdpPortConfig::new(interface, queue, NegotiatedMode::Copy, mtu),
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
    let config = XdpPortConfig::new(LAN, 0, NegotiatedMode::Copy, MTU);
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
    assert_eq!(completion.error, Some(XdpIoError::UnknownEgress(IfId(42))));
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
fn kicks_once_per_published_port_and_reports_a_failed_kick() {
    let (lan, wan) = (kernel(), kernel());
    let mut io = adapter(&lan, &wan);
    lan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    wan.set_tx_flags(XDP_RING_NEED_WAKEUP);
    for _ in 0..3 {
        deliver(&lan, &ipv4_frame(60, 64));
    }
    {
        let mut batch = io.receive(8).expect("receive");
        let mut index = 0;
        while let Some(packet) = batch.next_packet() {
            packet.commit(if index == 0 { WAN } else { LAN });
            index += 1;
        }
        let completion = batch.finish();
        assert_eq!((completion.tx_accepted, completion.error), (3, None));
    }
    assert_eq!(lan.kicks(KickRing::Tx), 1);
    assert_eq!(wan.kicks(KickRing::Tx), 1);
    // Nothing published: no kick.
    drop(io.receive(8).expect("receive"));
    assert_eq!(lan.kicks(KickRing::Tx), 1);
    // A failed kick is the batch error; the frame stays in flight.
    transmit_all(&lan);
    io.service().expect("service");
    deliver(&lan, &ipv4_frame(60, 64));
    lan.fail_next_kick(Some(100)); // ENETDOWN
    {
        let mut batch = io.receive(8).expect("receive");
        batch.next_packet().expect("lease").commit(LAN);
        let completion = batch.finish();
        assert!(completion.invariants_hold());
        assert_eq!(completion.tx_accepted, 1);
        assert!(matches!(
            completion.error,
            Some(XdpIoError::Kick { interface: LAN, .. })
        ));
    }
    assert_eq!(io.engine(LAN).expect("LAN").tx_inflight(), 1);
    // Not sticky: I/O continues.
    assert_eq!(
        io.current_io_disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    // A generated session kicks its egress the same way.
    {
        let mut batch = io.begin_generated(WAN);
        batch.allocate(42).expect("generated").commit();
        assert_eq!(batch.finish().error, None);
    }
    assert_eq!(wan.kicks(KickRing::Tx), 2);
    // Fill wakeup requests are answered by receive.
    lan.set_fill_flags(XDP_RING_NEED_WAKEUP);
    drop(io.receive(8).expect("receive"));
    assert!(lan.kicks(KickRing::Fill) >= 1);
    transmit_all(&lan);
    transmit_all(&wan);
    io.service().expect("service");
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
            XdpPortConfig::new(WAN, 0, NegotiatedMode::ZeroCopy, MTU),
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

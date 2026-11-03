//! AGENTS.md: the ARP-HOLD paths allocate nothing. A warmed-up world holds
//! a datagram to an unresolved gateway, learns the gateway from its ARP
//! Reply, and replays the datagram into a fragmentation slot; the
//! forwarding calls and the replay allocate nothing (the simulator's own
//! frame storage is outside them).

mod support;

use ruster_core::{
    execute_one_ipv4_fragmentation,
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragment_tracking_and_arp_hold,
    internet_checksum, ipv4_fragment_slot_bytes, replay_arp_holds, ArpHoldPolicy, ArpHoldRuntime,
    ArpHoldSlot, DynamicNeighborSlot, FirewallAction, FirewallConfig, FirewallHashKey,
    FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange, FirewallProtocol,
    FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot, ForwardingSnapshot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId,
    Interface, Ipv4Address, Ipv4FragmentSlot, Ipv4FragmentationPolicy, Ipv4FragmentationRuntime,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44TcpConfig, Nat44TcpMappingSlot,
    Nat44TcpPolicy, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpMappingSlot, Nat44UdpPeerSlot,
    Nat44UdpPolicy, NoTrace, PacketIo, ResolutionActionSlot, ResolutionFailureHoldSlot,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
};
use ruster_io_sim::SimIo;
use support::UdpTestIndexes;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const G_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const PUBLIC: [u8; 4] = [203, 0, 113, 2];
const G: [u8; 4] = [203, 0, 113, 1];

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

/// Counts the allocations of the measuring thread while it is armed (as in
/// the runtime's steady-allocation tests).
#[allow(unsafe_code)]
mod counting {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }

    fn note() {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
        }
    }

    pub struct Counting;

    // SAFETY: every method forwards the caller's arguments unchanged to
    // `System`; the const thread-local counters never allocate.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: `pointer` and `layout` came from this allocator.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    pub fn during(run: impl FnOnce()) -> usize {
        ARMED.with(|armed| armed.set(true));
        COUNT.with(|count| count.set(0));
        run();
        ARMED.with(|armed| armed.set(false));
        let count = COUNT.with(Cell::get);
        // The counter is live: an armed allocation counts.
        ARMED.with(|armed| armed.set(true));
        drop(std::hint::black_box(Box::new(0_u8)));
        ARMED.with(|armed| armed.set(false));
        assert_eq!(COUNT.with(Cell::get), count + 1, "the counter counts");
        count
    }
}

fn snapshot() -> ForwardingSnapshot<'static> {
    let routes = leak([
        Route::new(Ipv4Address::from_octets([192, 168, 1, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, WAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([198, 51, 100, 0]),
            24,
            WAN,
            Some(Ipv4Address::from_octets(G)),
        )
        .unwrap(),
    ]);
    let interfaces = leak([
        Interface {
            id: LAN,
            mac: MacAddress(LAN_MAC),
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: MacAddress(WAN_MAC),
            mtu: 1500,
        },
    ]);
    let bindings = leak([
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([192, 168, 1, 1]),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: Ipv4Address::from_octets(PUBLIC),
        },
    ]);
    ForwardingSnapshot::new(&routes[..], &interfaces[..], &[], &bindings[..]).unwrap()
}

/// An unchecked-payload UDP datagram from 192.168.1.10:`port` to
/// 198.51.100.20:53 (UDP checksum 0: none), DF set.
fn datagram(port: u16) -> Vec<u8> {
    let mut frame = LAN_MAC.to_vec();
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 0x10, 0x08, 0x00]);
    let mut header = vec![0x45, 0, 0, 30, 0, 1, 0x40, 0, 64, 17, 0, 0];
    header.extend_from_slice(&[192, 168, 1, 10, 198, 51, 100, 20]);
    let sum = internet_checksum(&header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(&[0, 53, 0, 10, 0, 0, 0x71, 0x31]);
    frame
}

/// G's ARP Reply to the router's WAN address, padded to 60 bytes.
fn g_reply() -> Vec<u8> {
    let mut frame = WAN_MAC.to_vec();
    frame.extend_from_slice(&G_MAC);
    frame.extend_from_slice(&[0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 2]);
    frame.extend_from_slice(&G_MAC);
    frame.extend_from_slice(&G);
    frame.extend_from_slice(&WAN_MAC);
    frame.extend_from_slice(&PUBLIC);
    frame.resize(60, 0);
    frame
}

#[test]
fn the_hold_and_replay_paths_do_not_allocate() {
    let snapshot = snapshot();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        Ipv4Address::from_octets(PUBLIC),
        40_000,
        40_015,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = Nat44TcpConfig::new(
        &snapshot,
        LAN,
        WAN,
        Ipv4Address::from_octets(PUBLIC),
        40_000,
        40_015,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
    let indexes = leak(UdpTestIndexes::new(udp_config, 8, 16));
    let mut udp = indexes.runtime(
        udp_config,
        leak([Nat44UdpMappingSlot::default(); 8]),
        leak([Nat44UdpPeerSlot::default(); 16]),
    );
    let mut tcp = support::tcp_runtime(
        tcp_config,
        leak([Nat44TcpMappingSlot::default(); 4]),
        leak([Nat44TcpSessionSlot::default(); 8]),
    );
    let any = FirewallPortRange::new(0, u16::MAX).unwrap();
    let firewall_config = FirewallConfig::new(
        &snapshot,
        Vec::leak(vec![FirewallRule::new(
            FirewallRuleId(20),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Any,
            FirewallIpv4Prefix::new(Ipv4Address::from_octets([192, 168, 1, 0]), 24).unwrap(),
            FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap(),
            FirewallProtocol::Udp,
            any,
            any,
            FirewallAction::AllowStateful,
        )]),
        FirewallPolicy::default(),
        1,
        FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
    )
    .unwrap();
    let mut firewall =
        FirewallRuntime::new(firewall_config, leak([FirewallStateSlot::default(); 16]));
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        leak([ResolutionStateSlot::EMPTY; 4]),
        leak([ResolutionActionSlot::EMPTY; 4]),
        leak([DynamicNeighborSlot::EMPTY; 4]),
        leak([ResolutionFailureHoldSlot::EMPTY; 4]),
    );
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        leak([Icmpv4ErrorStateSlot::EMPTY; 4]),
        leak([Icmpv4ErrorActionSlot::EMPTY; 4]),
    );
    let slot = ipv4_fragment_slot_bytes(1500);
    let mut fragmentation = Ipv4FragmentationRuntime::new(
        Ipv4FragmentationPolicy::DEFAULT,
        Vec::leak(vec![Ipv4FragmentSlot::EMPTY; 4]),
        Vec::leak(vec![0; 4 * slot]),
    )
    .unwrap();
    let mut hold = ArpHoldRuntime::new(
        ArpHoldPolicy::DEFAULT,
        Vec::leak(vec![ArpHoldSlot::EMPTY; 4]),
        Vec::leak(vec![0; 4 * slot]),
    )
    .unwrap();
    let mut io = SimIo::new();

    // Each round: the dynamic neighbor (60 s TTL) has expired, so the
    // datagram is held again; G's reply resolves it; the replay stages it.
    for (round, measure) in [false, true, true].into_iter().enumerate() {
        let now = MonotonicMillis(100_000 * (round as u64 + 1));
        let mut forward = |io: &mut SimIo, frame: Vec<u8>, hold: &mut ArpHoldRuntime<'_>| {
            io.inject(
                if frame[12] == 0x08 && frame[13] == 0x06 {
                    WAN
                } else {
                    LAN
                },
                frame,
            );
            let mut call = || {
                let batch = io.receive(1).unwrap();
                let report =
                    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragment_tracking_and_arp_hold(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &mut errors,
                        &udp_config,
                        Some(&mut udp),
                        &tcp_config,
                        Some(&mut tcp),
                        None,
                        &firewall_config,
                        Some(&mut firewall),
                        None,
                        Some(&mut fragmentation),
                        None,
                        Some(&mut *hold),
                        now,
                        &mut NoTrace,
                    );
                assert!(report.invariants_hold());
            };
            let allocations = if measure {
                counting::during(call)
            } else {
                call();
                0
            };
            while io.pop_recycled().is_some() {}
            allocations
        };
        assert_eq!(forward(&mut io, datagram(5000), &mut hold), 0, "hold");
        assert_eq!(hold.live(), 1, "round {round}");
        assert_eq!(forward(&mut io, g_reply(), &mut hold), 0, "learn");
        let mut replay = || {
            replay_arp_holds(
                &mut hold,
                &snapshot,
                &mut resolution,
                &mut errors,
                &udp_config,
                Some(&mut udp),
                &tcp_config,
                Some(&mut tcp),
                None,
                &firewall_config,
                Some(&mut firewall),
                &mut fragmentation,
                None,
                now,
                &mut NoTrace,
            )
        };
        let mut replayed = 0;
        let allocations = if measure {
            counting::during(|| replayed = replay())
        } else {
            replayed = replay();
            0
        };
        assert_eq!((allocations, replayed), (0, 1), "replay, round {round}");
        assert_eq!(hold.live(), 0);
        while execute_one_ipv4_fragmentation(&mut io, &mut fragmentation, &mut { 64 }).is_some() {}
        let sent = io.pop_tx().expect("the replayed datagram");
        assert_eq!(&sent.bytes[..6], &G_MAC);
        while io.pop_tx().is_some() {}
    }
    assert_eq!(hold.counters().replay_sent, 3);
}
